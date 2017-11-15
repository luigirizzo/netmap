#ifndef DEDUP_H_
#define DEDUP_H_

#define _BSD_SOURCE
#include <time.h>

struct dedup_ptr {
	unsigned long r; /* free running, wraps naturally */
	unsigned int o;  /* wraps at out_ring-size */
	unsigned int f;  /* wraps at fifo_size */
};

struct dedup_fifo_entry {
	struct timeval arrival;
};

struct dedup {
	/* input ring */
	struct netmap_ring *in_ring;
	struct netmap_slot *in_slot;

	/* output ring */
	struct netmap_ring *out_ring;
	struct netmap_slot *out_slot;

	/* fifo */
	struct dedup_fifo_entry *fifo;

	/* pointers */
	struct dedup_ptr next_to_send;
	struct dedup_ptr fifo_in;
	struct dedup_ptr fifo_out;

	/* configuration */ 
	unsigned int fifo_size;
	struct timeval win_size;
	int	zcopy_in_out;
};

int dedup_init(struct dedup *d, unsigned int fifo_size, struct netmap_ring *in,
		struct netmap_ring *out);

void dedup_ptr_init(struct dedup *d, struct dedup_ptr *p, unsigned long v);

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

int dedup_hold_push_in(struct dedup *d);

#endif
