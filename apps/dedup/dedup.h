#ifndef DEDUP_H_
#define DEDUP_H_

struct dedup_ptr {
	unsigned long r; /* free running, wraps naturally */
	unsigned int o;  /* wraps at out_ring-size */
	unsigned int s;  /* wraps at spill-size */
};

struct dedup {
	/* input ring */
	struct netmap_ring *in_ring;
	struct netmap_slot *in_slot;

	/* output ring */
	struct netmap_ring *out_ring;
	struct netmap_slot *out_slot;

	/* pointers */
	struct dedup_ptr next_to_send;
	struct dedup_ptr fifo_in;
	struct dedup_ptr fifo_out;

	/* how many slots of the FIFO are already in the out_ring,
	 * starting at next_to_send
	 */
	unsigned int prefetched;

	/* configuration */ 
	unsigned int fifo_size;
	int	zcopy_in_out;
};

void dedup_ptr_init(struct dedup *d, struct dedup_ptr *p, unsigned long v);

static inline void dedup_ptr_inc(struct dedup *d, struct dedup_ptr *p)
{
	p->r++;
	p->o++;
	if (unlikely(p->o >= d->out_ring->num_slots))
			p->o = 0;
#if 0
	p->f++;
	if (unlikely(p->f > d->spill_size))
			p->f = 0;
#endif

}

int dedup_hold_push_in(struct dedup *d);

#endif
