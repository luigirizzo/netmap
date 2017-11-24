#include <stdio.h>
#include <malloc.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include "dedup.h"

static void
dedup_ptr_init(struct dedup *d, struct dedup_ptr *p, unsigned long v)
{
	p->r = v;
	p->o = v % d->out_ring->num_slots;
}


int
dedup_init(struct dedup *d, unsigned int fifo_size, struct netmap_ring *in, struct netmap_ring *out)
{
	d->fifo = calloc(fifo_size, sizeof(d->fifo[0]));
	if (d->fifo == NULL)
		return -1;
	d->fifo_size = fifo_size;
	d->in_ring = in;
	d->in_slot = in->slot;
	d->out_ring = out;
	d->out_slot = out->slot;
	dedup_ptr_init(d, &d->fifo_out, out->head);
	dedup_ptr_init(d, &d->fifo_in, out->head);
	return 0;
}

int
dedup_set_hold_packets(struct dedup *d, int hold)
{
	if (hold) {
		d->fifo_slot = d->out_slot;
		d->next_to_send = &d->fifo_out;
	} else {
		d->fifo_slot = calloc(d->fifo_size, sizeof(struct netmap_slot));
		if (d->fifo_slot == NULL)
			return -1;
		d->next_to_send = &d->fifo_in;
	}
	return 0;
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

static void
dedup_hash_remove(struct dedup *d, struct netmap_slot *s)
{
	(void)d;
	(void)s;
}

static void
dedup_hash_insert(struct dedup *d, struct netmap_slot *s)
{
	(void)d;
	(void)s;
}

static int
dedup_duplicate(struct dedup *d, const struct netmap_slot *s)
{
	(void)d;
	(void)s;
	return 0;
}

static void
_transfer_pkt(struct dedup *d, struct netmap_slot *src, struct netmap_slot *dst,
		int zcopy)
{
	if (zcopy) {
		struct netmap_slot w = *dst;
		*dst = *src;
		*src = w;
		src->flags |= NS_BUF_CHANGED;
		dst->flags |= NS_BUF_CHANGED;
	} else {
		char *rxbuf = NETMAP_BUF(d->in_ring, src->buf_idx);
		char *txbuf = NETMAP_BUF(d->out_ring, dst->buf_idx);
		nm_pkt_copy(rxbuf, txbuf, src->len);
		dst->len = src->len;
		dst->ptr = src->ptr;
	}
}

static void
_dedup_fifo_push_out(struct dedup *d)
{
	dedup_hash_remove(d, &d->out_slot[d->fifo_out.o]);
	dedup_ptr_inc(d, &d->fifo_out);
}

static void
_dedup_fifo_slide_win(struct dedup *d, const struct timeval* now)
{
	struct timeval winstart;

	timersub(now, &d->win_size, &winstart);

	while (!dedup_fifo_empty(d)) {
		struct dedup_fifo_entry *e = &d->fifo[d->fifo_out.f];

		if (timercmp(&e->arrival, &winstart, <))
			break;

		_dedup_fifo_push_out(d);
	}
}

static inline int
dedup_can_hold(struct dedup *d)
{
	return d->fifo_slot == d->out_slot;
}

int
dedup_push_in(struct dedup *d, const struct timeval *now)
{
	struct netmap_ring *ri = d->in_ring, *ro = d->out_ring;
	uint32_t head;
	int n, out_space;

	_dedup_fifo_slide_win(d, now);

	/* packets to input */
	n = ri->tail - ri->head;
	if (n < 0)
		n += ri->num_slots;
	/* available space on the output ring */
	out_space = nm_ring_space(ro);

	for (head = ri->head; n; head = nm_ring_next(ri, head), n--) {
		struct netmap_slot *src_slot, *dst_slot;

		src_slot = d->in_slot + head;

		if (dedup_duplicate(d, src_slot))
			continue;

		if (out_space == 0)
			break;

		/* if the FIFO is full, remove and possibily send
		 * the oldest packet
		 */
		if (dedup_fifo_full(d))
			_dedup_fifo_push_out(d);

		/* move the new packet to the FIFO */
		dst_slot = d->fifo_slot + d->fifo_in.o;
		_transfer_pkt(d, src_slot, dst_slot, d->in_memid == d->fifo_memid);
		d->fifo[d->fifo_in.f].arrival = d->in_ring->ts;
		dedup_ptr_inc(d, &d->fifo_in);
		dedup_hash_insert(d, dst_slot);

		/* 
		 * if we cannot hold packets, we need
		 * to copy the outgoing packet to the out queue
		 */
		if (!dedup_can_hold(d)) {
			_transfer_pkt(d,
				d->fifo_slot + d->next_to_send->f,
				d->out_slot + d->next_to_send->o,
				0 /* force copy */);
		}

		out_space--;
	}
	ri->head = head;
	ri->cur = ri->tail;
	ro->head = d->next_to_send->o;
	ro->cur = dedup_can_hold(d) ? d->fifo_in.o : ro->head;
	return n;
}

#if 0
int
dedup_push_in(struct dedup *d)
{
	struct netmap_ring *ri = d->in_ring, *ro = d->out_ring;
	uint32_t head;
	int n, out_space;
	struct timeval now;
	struct dedup_ptr *dst = &(d->can_hold ? 
			d->fifo_in : d->next_to_send);

	gettimeofday(&now, NULL);

	_dedup_fifo_slide_win(d, &now);

	/* packets to input */
	n = ri->tail - ri->head;
	if (n < 0)
		n += ri->num_slots;
	/* available space on the output ring */
	out_space = ro->tail - d->next_to_send.o;
	if (out_space < 0)
		out_space += ro->num_slots;

	for (head = ri->head; n; head = nm_ring_next(ri, head), n--) {
		struct netmap_slot *src_slot, *dst_slot;

		src_slot = d->in_slot + head;

		if (dedup_duplicate(d, src_slot))
			continue;

		/* if the FIFO is full, send the oldest packet */
		if (dedup_fifo_full(d))
			_dedup_fifo_drop(d);

		/* send the new packet */
		dst_slot = d->out_slot + d->next_to_send.o;
		dedup_move_in_out(d, src_slot, dst_slot);
		/* copy or move into the FIFO */
		d->fifo[d->fifo_in.f].arrival = d->in_ring->ts;
		dedup_ptr_inc(d, &d->fifo_in);
		out_space--;
		dedup_hash_insert(d, dst_slot);
	}
	ri->head = head;
	ro->head = d->next_to_send.o;
	return n;
}

/* dedup_push_in: push new packets through the deduplicator.
 *
 * - duplicated packets are dropped
 * - fresh packets always go into the FIFO first. If they cannot be hold, they
 *   are also copied to the out ring; if we can hold packets, an incoming fresh
 *   packet may still cause another packet to be pushed to the out ring, if the
 *   FIFO is full; if these operations cannot be completed for lack of space,
 *   the processing stops and the fresh packet is not removed from the input
 *   queue (XXX this means that it will be checked for duplication again next
 *   time: we may optmize this by playing with head and cur)
 */
int
dedup_push_in(struct dedup *d)
{
	struct nemap_ring *ri = d->in_ring, *ro = d->out_ring;
	uint32_t cur;
	int n

	/* packets to input */
	n = ri->tail - ri->cur;
	if (n < 0)
		n += ri->num_slots;
	/* available space on the output ring
	 * (note that can_hold == 0 implies prefetch == 0 )
	 */
	out_space = ro->tail - (ro->head + d->prefetch);
	if (out_space < 0)
		out_space += ro->num_slots;

	for (cur = ri->cur; n; cur = nm_ring_next(ri, cur), n--) {
		unsigned long next_to_send = d->next_to_send.r;
		struct netmap_slot *src_slot, *dst_slot;

		src_slot = d->in_slot + cur;

		if (dedup_duplicate(d, src_slot))
			continue;

		/* if the FIFO is full, remove the oldest */
		if (dedup_fifo_full(d)) {
			struct netmap_slot *rem_slot;

			/* we can only send out the packet if it is
			 * already prefeteched or we have a free slot
			 * in the output queue
			 */
			if (d->prefetch == 0 && out_space == 0)
				break;
			dedup_ptr_inc(&d->next_to_send);

			rem_slot = (d->prefetched > 0) ?
				d->out_slot + d->fifo_out.o :
				d->spill_slot d->fifo_out.f;
			dedup_hash_remove(d, rem_slot);
			dedup_ptr_inc(d, &d->fifo_out);
		}

		/* move the new packet to the FIFO */
		if (out_space > 0) {
			/* put the new packet directly into the output ring */
			dst_slot = d->out_slot + d->fifo_in.o;
			d->prefetched++;
		} else {
			/* the packet goes into the spill queue.
			 * It is guaranteed to there be room there, since we have
			 * removed the oldest packet from the FIFO above
			 */
			dst_slot = d->spill + d->fifo_in.f;
		}
		// XXX copy-or-swap from src_slot to dst_slot
		dedup_ptr_inc(d, &d->fifo_in);
		dedup_hash_insert(d, dst_slot);
		/* the next packet to send always comes from the FIFO,
		 * at next_to_send position. If hold > 0 the packet already
		 * is in the out_ring, otherwise it must be obtained
		 * from the spill_ring. 
		 * If hold cannot be increased, we also need to copy the
		 * packet, whatever the value of the swap-or-copy flag for
		 * the direction.
		 */
		if (d->hold == 0) {
			if (d->max_hold == 0) {
				// XXX copy from spill[d->spill_head] to
				// out_ring[d->out_head]
			} else {
				// XXX copy-or-swap from spill[d->spill_head]
				// to out_ring[d->out_head]
				d->hold++;
			}
		} else {
			d->hold--;
		}
		dedup_ptr_inc(d, &d->next_to_send);
	}
	ro->head = ro->cur = d->next_to_send.o;
	return n;
}
#endif

