#ifndef DEDUP_H_
#define DEDUP_H_

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <time.h>
#include <limits.h>

struct dedup_ptr {
	unsigned long r; /* free running, wraps naturally */
	unsigned short o;  /* wraps at out_ring-size */
	unsigned short f;  /* wraps at fifo_size */
};

struct dedup_fifo_entry {
	struct timeval arrival;
	unsigned short hashmap_entry;
	unsigned int bucket_next; /* collision chain */
};

struct dedup_hashmap_entry {
	int valid;
#ifdef DEDUP_HASH_STAT
	unsigned int bucket_size;
#endif
	unsigned long bucket_head;
};

struct dedup {
	/* input ring */
	struct netmap_ring *in_ring;
	struct netmap_slot *in_slot;
	int in_memid;

	/* output ring */
	struct netmap_ring *out_ring;
	struct netmap_slot *out_slot;
	int out_memid;

	/* fifo */
	struct dedup_fifo_entry *fifo;
	struct netmap_ring *fifo_ring;
	struct netmap_slot *fifo_slot;
	int fifo_memid;

	/* pointers */
	struct dedup_ptr *next_to_send;
	struct dedup_ptr fifo_in;
	struct dedup_ptr fifo_out;

	/* hash map */
	struct dedup_hashmap_entry *hashmap;
	unsigned int hashmap_mask;

	/* configuration */ 
	unsigned int fifo_size;
	struct timeval win_size;
	int zcopy_in_out;
};

int dedup_init(struct dedup *d, unsigned int fifo_size, struct netmap_ring *in,
		struct netmap_ring *out);
uint32_t dedup_set_fifo_buffers(struct dedup *d, struct netmap_ring *ring, uint32_t buf_head);
void dedup_get_fifo_buffers(struct dedup *d, struct netmap_ring *ring, uint32_t *buf_head);

static inline void dedup_ptr_inc(struct dedup *d, struct dedup_ptr *p)
{
	p->r++;
	p->o++;
	if (unlikely(p->o >= d->out_ring->num_slots))
			p->o = 0;
	p->f++;
	if (unlikely(p->f >= d->fifo_size))
			p->f = 0;
}

int dedup_push_in(struct dedup *d, const struct timeval *now);

void dedup_fini(struct dedup *d);

#endif
