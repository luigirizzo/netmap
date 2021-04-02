#include <stdio.h>
#include <limits.h>
#include <malloc.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include "dedup.h"

#include "mark-adler-hash.c"

static int dedup_sse42;

static inline int
dedup_can_hold(struct dedup *d)
{
	return d->fifo_slot == d->out_slot;
}

static void
dedup_ptr_init(struct dedup *d, struct dedup_ptr *p, unsigned long v)
{
	p->r = v;
	p->o = v % d->out_ring->num_slots;
	p->f = v % d->fifo_size;
}


int
dedup_init(struct dedup *d, unsigned int fifo_size, struct netmap_ring *in, struct netmap_ring *out)
{
	unsigned int sh;

	if (fifo_size == 0)
		return -1;

	d->fifo = calloc(fifo_size, sizeof(d->fifo[0]));
	if (d->fifo == NULL)
		return -1;

	sh = (unsigned int)(sizeof(fifo_size) * CHAR_BIT - __builtin_clz(fifo_size - 1)) + 1;
	D("sh %u size %lu", sh, 1UL << sh);
	if (sh > sizeof(unsigned short) * CHAR_BIT - 1)
		goto err;
	d->hashmap = calloc(1UL << sh, sizeof(struct dedup_hashmap_entry));
	if (d->hashmap == NULL)
		goto err;
	d->hashmap_mask = (1UL << sh) - 1;
	d->fifo_size = fifo_size;
	d->in_ring = in;
	d->in_slot = in->slot;
	d->out_ring = out;
	d->out_slot = out->slot;
	dedup_ptr_init(d, &d->fifo_out, out->head);
	dedup_ptr_init(d, &d->fifo_in, out->head);
	SSE42(dedup_sse42);
	return 0;
err:
	free(d->fifo);
	d->fifo = NULL;
	return -1;
}

uint32_t
dedup_set_fifo_buffers(struct dedup *d, struct netmap_ring *ring, uint32_t buf_head)
{
	uint32_t scan;
	struct netmap_slot *s;
	struct netmap_ring *r = ring ? ring : d->in_ring;

	if (buf_head == 0) {
		d->fifo_ring = d->out_ring;
		d->fifo_slot = d->out_slot;
		d->next_to_send = &d->fifo_out;
		return 0;
	}
	d->fifo_slot = calloc(d->fifo_size, sizeof(struct netmap_slot));
	if (d->fifo_slot == NULL)
		return buf_head;
	for (scan = buf_head, s = d->fifo_slot;
	     scan != 0 && s != d->fifo_slot + d->fifo_size;
	     scan = *(uint32_t *)NETMAP_BUF(r, scan), s++) {
		s->len = r->nr_buf_size;
		s->buf_idx = scan;
	}
	if (s != d->fifo_slot + d->fifo_size) {
		free(d->fifo_slot);
		d->fifo_slot = NULL;
		return buf_head;
	}
	d->fifo_ring = d->in_ring;
	d->next_to_send = &d->fifo_in;
	return scan;
}

void
dedup_get_fifo_buffers(struct dedup *d, struct netmap_ring *ring, uint32_t *buf_head)
{
	struct netmap_ring *r = ring ? ring : d->in_ring;
	unsigned int i;

	if (d->fifo_slot == NULL || dedup_can_hold(d))
		return;

	for (i = 0; i < d->fifo_size; i++) {
		struct netmap_slot *s = d->fifo_slot + i;
		uint32_t *new_head = (uint32_t *)NETMAP_BUF(r, s->buf_idx);

		*new_head = *buf_head;
		*buf_head = s->buf_idx;
	}
	free(d->fifo_slot);
	d->fifo_slot = NULL;
}

void
dedup_fini(struct dedup *d)
{
	if (d->fifo != NULL) {
		free(d->fifo);
		d->fifo = NULL;
	}
	if (d->fifo_slot != NULL && d->fifo_slot != d->out_slot) {
		free(d->fifo_slot);
		d->fifo_slot = NULL;
	}
	if (d->hashmap != NULL) {
		free(d->hashmap);
		d->hashmap = NULL;
	}
}

static int
dedup_fifo_full(const struct dedup *d)
{
	return (d->fifo_in.r - d->fifo_out.r >= d->fifo_size);
}

static int
dedup_fifo_empty(const struct dedup *d)
{
	return (d->fifo_in.r == d->fifo_out.r);
}

static inline uint32_t
dedup_hash(const char *data)
{
	return dedup_sse42 ? crc32c_hw(0, data, 64) : crc32c_sw(0, data, 64);
}

static void
dedup_hashmap_insert(struct dedup *d, unsigned short h)
{
	struct dedup_hashmap_entry *he = d->hashmap + h;
	struct dedup_fifo_entry *fe = d->fifo + d->fifo_in.f;
	fe->bucket_next = (he->valid ? d->fifo_in.r - he->bucket_head : 0);
	fe->hashmap_entry = h;
	he->bucket_head = d->fifo_in.r;
	he->valid = 1;
#ifdef DEDUP_HASH_STAT
	he->bucket_size++;
#endif
}

static void
dedup_hashmap_remove(struct dedup *d)
{
	struct dedup_fifo_entry *fe = d->fifo + d->fifo_out.f;
	struct dedup_hashmap_entry *he = d->hashmap + fe->hashmap_entry;

	ND("h %u bucket_head %lu fifo_out.r %lu fifo_out.f %u",
			fe->hashmap_entry, he->bucket_head,
			d->fifo_out.r, d->fifo_out.f);
	if (he->bucket_head == d->fifo_out.r)
		he->valid = 0;
	fe->hashmap_entry = 0;
	fe->bucket_next = 0;
#ifdef DEDUP_HASH_STAT
	he->bucket_size--;
#endif
}

static long
dedup_fresh_packet(struct dedup *d, const struct netmap_slot *s)
{
	const void *buf = NETMAP_BUF(d->in_ring, s->buf_idx);
	unsigned int h = dedup_hash(buf);
	unsigned short i = h & d->hashmap_mask;
	struct dedup_hashmap_entry *he = d->hashmap + i;
	unsigned long fi = he->bucket_head;
	unsigned long fifo_win = d->fifo_in.r - d->fifo_out.r;

	if (!he->valid)
		return i;

	while (d->fifo_in.r - fi > 0 && d->fifo_in.r - fi <= fifo_win) {
		struct netmap_slot *fs;
		const void *fbuf;
		unsigned long rfi = fi - d->fifo_out.r + d->fifo_out.f;
		unsigned int delta;

		if (rfi >= d->fifo_size)
			rfi -= d->fifo_size;

		fs = d->fifo_slot + rfi;
		ND("checking %lu %lu: lengths %u %u buf %d", fi, rfi, fs->len, s->len,
				fs->buf_idx);

		if (fs->len != s->len)
			goto next;
		fbuf = NETMAP_BUF(d->fifo_ring, fs->buf_idx);
		if (memcmp(buf, fbuf, s->len))
			goto next;
		return -1;
	next:
		delta = d->fifo[rfi].bucket_next;
		if (delta == 0)
			break;
		fi -= delta;
	}
	return i;
}

static inline void
dedup_transfer_pkt(struct dedup *d,
	struct netmap_ring *src_ring,
	struct netmap_slot *src_slot,
	struct netmap_ring *dst_ring,
	struct netmap_slot *dst_slot,
	int zcopy)
{
	(void)d;

	if (zcopy) {
		struct netmap_slot w = *dst_slot;
		__builtin_prefetch(dst_slot + 1);
		*dst_slot = *src_slot;
		dst_slot->flags |= NS_BUF_CHANGED;
		*src_slot = w;
		src_slot->flags |= NS_BUF_CHANGED;
	} else {
		char *rxbuf = NETMAP_BUF(src_ring, src_slot->buf_idx);
		char *txbuf = NETMAP_BUF(dst_ring, dst_slot->buf_idx);
		nm_pkt_copy(rxbuf, txbuf, src_slot->len);
		dst_slot->len = src_slot->len;
		dst_slot->ptr = src_slot->ptr;
	}
}

static void
dedup_fifo_slide_win(struct dedup *d, const struct timeval* now)
{
	struct timeval winstart;

	timersub(now, &d->win_size, &winstart);

	while (!dedup_fifo_empty(d)) {
		struct dedup_fifo_entry *e = &d->fifo[d->fifo_out.f];

		ND("fifo %u: arrival %llu.%llu winstart %llu.%llu",
				d->fifo_out.f,
				(unsigned long long)e->arrival.tv_sec,
				(unsigned long long)e->arrival.tv_usec,
				(unsigned long long)winstart.tv_sec,
				(unsigned long long)winstart.tv_usec);

		if (timercmp(&winstart, &e->arrival, <=))
			break;

		ND("fifo %u: pushing out", d->fifo_out.f);
		dedup_hashmap_remove(d);
		dedup_ptr_inc(d, &d->fifo_out);
	}
}

int
dedup_push_in(struct dedup *d, const struct timeval *now)
{
	struct netmap_ring *ri = d->in_ring, *ro = d->out_ring;
	uint32_t head;
	int n, out_space;

	dedup_fifo_slide_win(d, now);

	/* packets to input */
	n = ri->tail - ri->head;
	if (n < 0)
		n += ri->num_slots;
	/* available space on the output ring */
	out_space = nm_ring_space(ro);

	for (head = ri->head; n; head = nm_ring_next(ri, head), n--) {
		struct netmap_slot *src_slot, *dst_slot;
		long h;

		src_slot = d->in_slot + head;

		h = dedup_fresh_packet(d, src_slot);
		if (h < 0) { /* duplicate */
			ND("dropping %u", head);
			continue;
		}

		if (out_space == 0)
			break;

		/* if the FIFO is full, remove and possibly send
		 * the oldest packet
		 */
		if (dedup_fifo_full(d)) {
			dedup_hashmap_remove(d);
			dedup_ptr_inc(d, &d->fifo_out);
		}

		/* move the new packet to out ring */
		dst_slot = d->out_slot + d->fifo_in.o;
		dedup_transfer_pkt(d,
			d->in_ring,
			src_slot,
			d->out_ring,
			dst_slot,
			d->in_memid == d->out_memid);

		/* hold/copy/swap the packet in the FIFO ring */
		d->fifo[d->fifo_in.f].arrival = d->in_ring->ts;

		if (!dedup_can_hold(d)) {
			dedup_transfer_pkt(d,
				(d->in_memid == d->out_memid ? d->out_ring : d->in_ring),
				(d->in_memid == d->out_memid ? dst_slot : src_slot),
				d->fifo_ring,
				d->fifo_slot + d->fifo_in.f,
				(d->in_memid != d->out_memid &&
				 d->in_memid == d->fifo_memid));
		}

		dedup_hashmap_insert(d, h);
		dedup_ptr_inc(d, &d->fifo_in);
		out_space--;
	}
	ri->head = head;
	ri->cur = ri->tail;
	ro->head = d->next_to_send->o;
	ro->cur = dedup_can_hold(d) ? d->fifo_in.o : ro->head;
	return n;
}
