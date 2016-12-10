/*
 * Copyright (C) 2016 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if 0 /* COMMENT */

This program implements TLEM, a bandwidth and delay emulator between two
netmap ports. It is meant to be run from the command line and
implemented with a main control thread, plus a couple of threads
for each direction of the communication.

The control thread parses command line arguments and then sits
in a loop where it periodically reads traffic statistics from
the other threads and prints them out on the console.

The packet transfer in each direction is implemented by a "producer"
thread prod() which reads from the input netmap port and puts packets
into a queue (struct _qs) with appropriate metatada on when packets
are due for release, and a "consumer" thread cons() which reads
from the queue and transmits packets on the output port when their
time has come.

     netmap    thread      struct _qs     thread   netmap
      port                                          port
     {input}-->(prod)-->--[  queue  ]-->--(cons)-->{output}

The producer can either wait for traffic using a blocking poll(),
or periodically check the input around short usleep().
The latter mechanism is the preferred one as it allows a controlled
latency with a low interrupt load and a modest system load.

The queue is sized so that overflows can occur only if the consumer
is severely backlogged, hence the only appropriate option is drop
traffic rather than wait for space.  The case of an empty queue is
managed by having the consumer probe the queue around short usleep()
calls. This mechanism gives controlled latency with moderate system
load, so it is not worthwhile to optimize the CPU usage.

In order to get good and predictable performance, it is important
that threads are pinned to a single core, and it is preferable that
prod() and cons() for each direction share the cache as much as possible.
Putting them on two hyperthreads of the same core seems to give
good results but that shoud be investigated further.

It also seems useful to use a scheduler (SCHED_FIFO or SCHED_RR)
that gives more predictable cycles to the CPU, as well as try
to keep other system tasks away from the CPUs used for the four
main threads.
The program does CPU pinning and sets the scheduler and priority
for the prod and cons threads. Externally one should do the
assignment of other threads (e.g. interrupt handlers) and
make sure that network interfaces are configured properly.

--- Main functions of the program ---
within each function, q is used as a pointer to the queue holding
packets and parameters.

prod()

    waits for packets using the wait_for_packet() function.
    After that, for each packet, the following information may
    be of use:
    	q->cur_pkt	points to the buffer containing the packet
	q->cur_len	packet length, excluding CRC
	q->prod_now	time at which the packet was received,
			in nanoseconds. A batch of packets may
			have the same value q->prod_now

    Four functions are then called in sequence:

    q->c_loss (set with the -L command line option) decides
    	whether the packet should be dropped before even queuing.
	This is generally useful to emulate random loss.
	The function is supposed to set q->c_drop = 1 if the
	packet should be dropped, or leave it to 0 otherwise.

    no_room (not configurable) checks whether there is space
    	in the queue, enforcing both the queue size set with -Q
	and the space allocated for the delay line.
	In case of no space the packet is dropped.

    q->c_bw (set with the -B command line option) is used to
        enforce bandwidth limitation. The function must store
	in q->cur_tt the transmission time (in nanoseconds) of
	the packet, which is typically proportional to the length
	of the packet, i.e. q->cur_tt = q->cur_len / <bandwidth>
	Variants are possible, eg. to account for constant framing
	bits as on the ethernet, or variable channel acquisition times,
	etc.
	This mechanism can also be used to simulate variable queueing
	delay e.g. due to the presence of cross traffic.

    q->c_delay (set with the -D option) implements delay emulation.
	The function should set q->cur_delay to the additional
	delay the packet is subject to. The framework will take care of
	computing the actual exit time of a packet so that there is no
	reordering.



#endif /* COMMENT */

// debugging macros
#define NED(_fmt, ...)	do {} while (0)
#define ED(_fmt, ...)						\
	do {							\
		struct timeval _t0;				\
		gettimeofday(&_t0, NULL);			\
		fprintf(stderr, "%03d.%03d [%5d] \t" _fmt "\n", \
		(int)(_t0.tv_sec % 1000), (int)_t0.tv_usec/1000, \
		__LINE__, ##__VA_ARGS__);     \
	} while (0)

#define _GNU_SOURCE	// for CPU_SET() etc
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>


int verbose = 0;

static int do_abort = 0;

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>

#include <sys/resource.h> // setpriority

#ifdef __FreeBSD__
#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#endif /* __FreeBSD__ */

#ifdef linux
#define cpuset_t        cpu_set_t
#endif

#ifdef __APPLE__
#define cpuset_t        uint64_t        // XXX
static inline void CPU_ZERO(cpuset_t *p)
{
        *p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p)
{
        *p |= 1<< (i & 0x3f);
}

#define pthread_setaffinity_np(a, b, c) ((void)a, 0)
#define sched_setscheduler(a, b, c)	(1) /* error */
#define clock_gettime(a,b)      \
        do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)

#define	_P64	unsigned long
#endif

#ifndef _P64

/* we use uint64_t widely, but printf gives trouble on different
 * platforms so we use _P64 as a cast
 */
#define	_P64	uint64_t
#endif /* print stuff */


struct _qs;	/* forward */
/*
 * descriptor of a configuration entry.
 * Each handler has a parse function which takes ac/av[] and returns
 * true if successful. Any allocated space is stored into struct _cfg *
 * that is passed as argument.
 * arg and arg_len are included for convenience.
 */
struct _cfg {
    int (*parse)(struct _qs *, struct _cfg *, int ac, char *av[]);  /* 0 ok, 1 on error */
    int (*run)(struct _qs *, struct _cfg *arg);         /* 0 Ok, 1 on error */
    // int close(struct _qs *, void *arg);              /* 0 Ok, 1 on error */

    const char *optarg;	/* command line argument. Initial value is the error message */
    /* placeholders for common values */
    void *arg;		/* allocated memory if any */
    int arg_len;	/* size of *arg in case a realloc is needed */
    uint64_t d[16];	/* static storage for simple cases */
};

/*
 *
A packet in the queue is q_pkt plus the payload.

For the packet descriptor we need the following:

    -	position of next packet in the queue (can go backwards).
	We can reduce to 32 bits if we consider alignments,
	or we just store the length to be added to the current
	value and assume 0 as a special index.
    -	actual packet length (16 bits may be ok)
    -	queue output time, in nanoseconds (64 bits)
    -	delay line output time, in nanoseconds
	One of the two can be packed to a 32bit value

A convenient coding uses 32 bytes per packet.
Even if we use a compact encoding it is difficult to go below 18 bytes

 */

struct q_pkt {
	uint64_t	next;		/* buffer index for next packet */
	uint64_t	pktlen;		/* actual packet len */
	uint64_t	pt_qout;	/* time of output from queue */
	uint64_t	pt_tx;		/* transmit time */
};


/*
 * communication occurs through this data structure, with fields
 * cache-aligned according to who are the readers/writers.
 *

The queue is an array of memory  (buf) of size buflen (does not change).

The producer uses 'tail' as an index in the queue to indicate
the first empty location (ie. after the last byte of data),
the consumer uses head to indicate the next byte to consume.

For best performance we should align buffers and packets
to multiples of cacheline, but this would explode memory too much.
Worst case memory explosion is with 65 byte packets.
Memory usage as shown below:

		qpkt-pad
	size	32-16	32-32	32-64	64-64

	64	96	96	96	128
	65	112	128	160	192


An empty queue has head == tail, a full queue will have free space
below a threshold.  In our case the queue is large enough and we
are non blocking so we can simply drop traffic when the queue
approaches a full state.

To simulate bandwidth limitations efficiently, the producer has a second
pointer, prod_tail_1, used to check for expired packets. This is done lazily.

 */
/*
 * When sizing the buffer, we must assume some value for the bandwidth.
 * INFINITE_BW is supposed to be faster than what we support
 */
#define INFINITE_BW	(200ULL*1000000*1000)
#define	MY_CACHELINE	(128ULL)
#define PKT_PAD		(32)	/* padding on packets */
#define MAX_PKT		(9200)	/* max packet size */

#define ALIGN_CACHE	__attribute__ ((aligned (MY_CACHELINE)))

struct _qs { /* shared queue */
	uint64_t	t0;	/* start of times */

	uint64_t 	buflen;	/* queue length */
	char *buf;

	/* the queue has at least 1 empty position */
	uint64_t	max_bps;	/* bits per second */
	uint64_t	max_delay;	/* nanoseconds */
	uint64_t	qsize;	/* queue size in bytes */

	/* handlers for various options */
	struct _cfg	c_delay;
	struct _cfg	c_bw;
	struct _cfg	c_loss;

	/* producer's fields */
	uint64_t	tx ALIGN_CACHE;	/* tx counter */
	uint64_t	prod_tail_1;	/* head of queue */
	uint64_t	prod_queued;	/* queued bytes */
	uint64_t	prod_head;	/* cached copy */
	uint64_t	prod_tail;	/* cached copy */
	uint64_t	prod_now;	/* most recent producer timestamp */
	uint64_t	prod_drop;	/* drop packet count */
	uint64_t	prod_max_gap;	/* rx round duration */

	/* parameters for reading from the netmap port */
	struct nm_desc *src_port;		/* netmap descriptor */
	const char *	prod_ifname;	/* interface name */
	struct netmap_ring *rxring;	/* current ring being handled */
	uint32_t	si;		/* ring index */
	int		burst;
	uint32_t	rx_qmax;	/* stats on max queued */

	uint64_t	qt_qout;	/* queue exit time for last packet */
		/*
		 * when doing shaping, the software computes and stores here
		 * the time when the most recently queued packet will exit from
		 * the queue.
		 */

	uint64_t	qt_tx;		/* delay line exit time for last packet */
		/*
		 * The software computes the time at which the most recently
		 * queued packet exits from the queue.
		 * To avoid reordering, the next packet should exit at least
		 * at qt_tx + cur_tt
		 */

	/* producer's fields controlling the queueing */
	char *		cur_pkt;	/* current packet being analysed */
	uint32_t	cur_len;	/* length of current packet */

	int		cur_drop;	/* 1 if current  packet should be dropped. */
		/*
		 * cur_drop can be set as a result of the loss emulation,
		 * and may need to use the packet size, current time, etc.
		 */

	uint64_t	cur_tt;		/* transmission time (ns) for current packet */
		/*
		 * The transmission time is how much link time the packet will consume.
		 * should be set by the function that does the bandwidth emulation,
		 * but could also be the result of a function that emulates the
		 * presence of competing traffic, MAC protocols etc.
		 * cur_tt is 0 for links with infinite bandwidth.
		 */

	uint64_t	cur_delay;	/* delay (ns) for current packet from c_delay.run() */
		/*
		 * this should be set by the function that computes the extra delay
		 * applied to the packet.
		 * The code makes sure that there is no reordering and possibly
		 * bumps the output time as needed.
		 */


	/* consumer's fields */
	const char *		cons_ifname;
	uint64_t rx ALIGN_CACHE;	/* rx counter */
//	uint64_t	cons_head;	/* cached copy */
//	uint64_t	cons_tail;	/* cached copy */
	uint64_t	cons_now;	/* most recent producer timestamp */
	uint64_t	cons_lag;	/* tail - head */
	uint64_t	rx_wait;	/* stats */

	/* shared fields */
	volatile uint64_t tail ALIGN_CACHE ;	/* producer writes here */
	volatile uint64_t head ALIGN_CACHE ;	/* consumer reads from here */
};

struct pipe_args {
	int		zerocopy;
	int		wait_link;

	pthread_t	cons_tid;	/* main thread */
	pthread_t	prod_tid;	/* producer thread */

	/* Affinity: */
	int		cons_core;	/* core for cons() */
	int		prod_core;	/* core for prod() */

	struct nm_desc *pa;		/* netmap descriptor */
	struct nm_desc *pb;

	struct _qs	q;
};

#define NS_IN_S	(1000000000ULL)	// nanoseconds
#define TIME_UNITS	NS_IN_S

/* set the thread affinity. */
static int
setaffinity(int i)
{
        cpuset_t cpumask;
	struct sched_param p;

        if (i == -1)
                return 0;

        /* Set thread affinity affinity.*/
        CPU_ZERO(&cpumask);
        CPU_SET(i, &cpumask);

        if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpumask) != 0) {
                ED("Unable to set affinity: %s", strerror(errno));
        }
	if (setpriority(PRIO_PROCESS, 0, -10)) {; // XXX not meaningful
                ED("Unable to set priority: %s", strerror(errno));
	}
	bzero(&p, sizeof(p));
	p.sched_priority = 10; // 99 on linux ?
	// use SCHED_RR or SCHED_FIFO
	if (sched_setscheduler(0, SCHED_RR, &p)) {
                ED("Unable to set scheduler: %s", strerror(errno));
	}
        return 0;
}


static inline void
set_tns_now(uint64_t *now, uint64_t t0)
{
    struct timespec t;

    clock_gettime(CLOCK_REALTIME, &t); // XXX precise on FreeBSD ?
    *now = (uint64_t)(t.tv_nsec + NS_IN_S * t.tv_sec);
    *now -= t0;
}


static inline int pad(int x)
{
	return ((x) + PKT_PAD - 1) & ~(PKT_PAD - 1) ;
}

/* compare two timestamps */
static inline int64_t
ts_cmp(uint64_t a, uint64_t b)
{
	return (int64_t)(a - b);
}

/* create a packet descriptor */
static inline struct q_pkt *
pkt_at(struct _qs *q, uint64_t ofs)
{
    return (struct q_pkt *)(q->buf + ofs);
}

/*
 * q_reclaim() accounts for packets whose output time has expired,
 * return 1 if any has been reclaimed.
 * XXX if bw = 0, prod_queued does not need to be updated or prod_tail_1 handled
 */
static int
q_reclaim(struct _qs *q)
{
	struct q_pkt *p0, *p;

	p = p0 = pkt_at(q, q->prod_tail_1);
	/* always reclaim queued packets */
	while (ts_cmp(p->pt_qout, q->prod_now) <= 0 && q->prod_queued > 0) {
	    ND(1, "reclaim pkt at %ld len %d left %ld", q->prod_tail_1, p->pktlen, q->prod_queued);
	    q->prod_queued -= p->pktlen;
	    q->prod_tail_1 = p->next;
	    p = pkt_at(q, q->prod_tail_1);
	}
	return p != p0;
}

/*
 * no_room() checks for room in the queue and delay line.
 *
 * For the queue, we check that the amount of queued bytes does
 * not exceed the space. We reclaim expired packets if needed.
 *
 * For the delay line and buffer, we make sure that a packet is never
 * split across a boundary. "need" is the amount of space we allocate,
 * padding as needed, so that new_t will become 0 if needed,
 * new_t > 0 if there is room in the remaining part of the buffer.
 *
 * enqueue a packet. Two cases:
 * A:	[     h......t    ]
 *	because of the padding, overflow if (h <= t && new_t == 0 && h == 0)
 *
 * B:	[...t     h ......]
 *	overflow if (h > t && (new_t == 0 || new_t >= h)
 *
 * Conditions to have space:
 * A
 * for another one, wrap tail to 0 to ease checks.
 */
static int
no_room(struct _qs *q)
{
    uint64_t h = q->prod_head;	/* shorthand */
    uint64_t t = q->prod_tail;	/* shorthand */
    struct q_pkt *p = pkt_at(q, t);
    uint64_t need = pad(q->cur_len) + sizeof(*p); /* space for a packet */
    uint64_t new_t = t + need;

    if (q->buflen - new_t < MAX_PKT + sizeof(*p))
	new_t = 0; /* further padding */

    /* XXX let the queue overflow once, otherwise it is complex
     * to deal with 0-sized queues
     */
    if (q->prod_queued > q->qsize) {
	q_reclaim(q);
	if (q->prod_queued > q->qsize) {
	    q->prod_drop++;
	    RD(1, "too many bytes queued %lu, drop %lu",
		(_P64)q->prod_queued, (_P64)q->prod_drop);
	    return 1;
	}
    }

    if ((h <= t && new_t == 0 && h == 0) || (h > t && (new_t == 0 || new_t >= h)) ) {
	h = q->prod_head = q->head; /* re-read head, just in case */
	/* repeat the test */
	if ((h <= t && new_t == 0 && h == 0) || (h > t && (new_t == 0 || new_t >= h)) ) {
	    ND(1, "no room for insert h %ld t %ld new_t %ld",
		(_P64)h, (_P64)t, (_P64)new_t);
	    return 1; /* no room for insert */
	}
    }
    p->next = new_t; /* prepare for queueing */
    p->pktlen = 0;
    return 0;
}


/*
 * we have already checked for room and prepared p->next
 */
static inline int
enq(struct _qs *q)
{
    struct q_pkt *p = pkt_at(q, q->prod_tail);

    /* hopefully prefetch has been done ahead */
    nm_pkt_copy(q->cur_pkt, (char *)(p+1), q->cur_len);
    p->pktlen = q->cur_len;
    p->pt_qout = q->qt_qout;
    p->pt_tx = q->qt_tx;
    ND(1, "enqueue len %d at %d new tail %ld qout %ld tx %ld",
	q->cur_len, (int)q->prod_tail, p->next,
	p->pt_qout, p->pt_tx);
    q->prod_tail = p->next;
    q->tx++;
    if (q->max_bps)
	q->prod_queued += p->pktlen;
    /* XXX update timestamps ? */
    return 0;
}


int
rx_queued(struct nm_desc *d)
{
    u_int tot = 0, i;
    for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
	struct netmap_ring *rxr = NETMAP_RXRING(d->nifp, i);

	ND(5, "ring %d h %d cur %d tail %d", i,
		rxr->head, rxr->cur, rxr->tail);
	tot += nm_ring_space(rxr);
    }
    return tot;
}

/*
 * wait for packets, then compute a timestamp in 64-bit ns
 */
static void
wait_for_packets(struct _qs *q)
{
    int n0;
    uint64_t prev = q->prod_now;

    ioctl(q->src_port->fd, NIOCRXSYNC, 0); /* forced */
    while (!do_abort) {

	n0 = rx_queued(q->src_port);
	if (n0 > (int)q->rx_qmax) {
	    q->rx_qmax = n0;
	}
	if (n0)
	    break;
	prev = 0; /* we slept */
	if (1) {
	    usleep(5);
	    ioctl(q->src_port->fd, NIOCRXSYNC, 0);
	} else {
	    struct pollfd pfd;
	    struct netmap_ring *rx;
	    int ret;

	    pfd.fd = q->src_port->fd;
	    pfd.revents = 0;
	    pfd.events = POLLIN;
	    ND(1, "prepare for poll on %s", q->prod_ifname);
	    ret = poll(&pfd, 1, 10000);
	    if (ret <= 0 || verbose) {
		D("poll %s ev %x %x rx %d@%d",
		    ret <= 0 ? "timeout" : "ok",
		    pfd.events,
		    pfd.revents,
		    rx_queued(q->src_port),
		    NETMAP_RXRING(q->src_port->nifp, q->src_port->first_rx_ring)->cur
		);
	    }
	    if (pfd.revents & POLLERR) {
		rx = NETMAP_RXRING(q->src_port->nifp, q->src_port->first_rx_ring);
		D("error on fd0, rx [%d,%d,%d)",
		    rx->head, rx->cur, rx->tail);
		sleep(1);
	    }
	}
    }
    set_tns_now(&q->prod_now, q->t0);
    if (ts_cmp(q->qt_qout, q->prod_now) < 0) {
	q->qt_qout = q->prod_now;
    }
    if (prev > 0 && (prev = q->prod_now - prev) > q->prod_max_gap) {
	q->prod_max_gap = prev;
    }
    ND(10, "%s %d queued packets at %ld ms",
	q->prod_ifname, n0, (q->prod_now/1000000) % 10000);
}

/*
 * prefetch a packet 'pos' slots ahead of cur.
 * not very useful though
 */
void
prefetch_packet(struct netmap_ring *rxr, int pos)
{
    struct netmap_slot *rs;
    uint32_t ofs = rxr->cur + pos;
    uint32_t i, l;
    const char *buf;

    if (ofs >= rxr->num_slots)
	return;
    rs = &rxr->slot[ofs];
    buf = NETMAP_BUF(rxr, rs->buf_idx);
    l = rs->len;
    for (i = 0; i < l; i += 64)
	__builtin_prefetch(buf + i);
}

/*
 * initialize state variables to the first or next packet
 */
static void
scan_ring(struct _qs *q, int next /* bool */)
{
    struct netmap_slot *rs;
    struct netmap_ring *rxr = q->rxring; /* invalid if next == 0 */
    struct nm_desc *pa = q->src_port;

    /* fast path for the first two */
    if (likely(next != 0)) { /* current ring */
	ND(10, "scan next");
	/* advance */
	rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
	if (!nm_ring_empty(rxr)) /* good one */
	    goto got_one;
	q->si++;	/* otherwise update and fallthrough */
    } else { /* scan from beginning */
	q->si = pa->first_rx_ring;
	ND(10, "scanning first ring %d", q->si);
    }
    while (q->si <= pa->last_rx_ring) {
	q->rxring = rxr = NETMAP_RXRING(pa->nifp, q->si);
	if (!nm_ring_empty(rxr))
	    break;
	q->si++;
	continue;
    }
    if (q->si > pa->last_rx_ring) { /* no data, cur == tail */
        ND(5, "no more pkts on %s", q->prod_ifname);
	return;
    }
got_one:
    rs = &rxr->slot[rxr->cur];
    if (unlikely(rs->buf_idx < 2)) {
	D("wrong index rx[%d] = %d", rxr->cur, rs->buf_idx);
	sleep(2);
    }
    if (unlikely(rs->len > MAX_PKT)) { // XXX
	D("wrong len rx[%d] len %d", rxr->cur, rs->len);
	rs->len = 0;
    }
    q->cur_pkt = NETMAP_BUF(rxr, rs->buf_idx);
    q->cur_len = rs->len;
    //prefetch_packet(rxr, 1); not much better than prefetching q->cur_pkt, one line
    __builtin_prefetch(q->cur_pkt);
    __builtin_prefetch(rs+1); /* one row ahead ? */
    ND(10, "-------- slot %d tail %d len %d buf %p", rxr->cur, rxr->tail, q->cur_len, q->cur_pkt);
}

/*
 * simple handler for parameters not supplied
 */
static int
null_run_fn(struct _qs *q, struct _cfg *cfg)
{
    (void)q;
    (void)cfg;
    return 0;
}


static int
drop_after(struct _qs *q)
{
	(void)q; // XXX
	return 0;
}


static void *
prod(void *_pa)
{
    struct pipe_args *pa = _pa;
    struct _qs *q = &pa->q;

    setaffinity(pa->prod_core);
    set_tns_now(&q->prod_now, q->t0);
    q->qt_qout = q->qt_tx = q->prod_now;
    ND("start times %ld", q->prod_now);
    while (!do_abort) { /* producer, infinite */
	int count;

	wait_for_packets(q);	/* also updates prod_now */
	// XXX optimize to flush frequently
	for (count = 0, scan_ring(q, 0); count < q->burst && !nm_ring_empty(q->rxring);
		count++, scan_ring(q, 1)) {
	    // transmission time
	    uint64_t t_tx, tt;	/* output and transmission time */

	    if (q->cur_len < 60) {
		RD(5, "short packet len %d", q->cur_len);
		continue; // short frame
	    }
	    q->c_loss.run(q, &q->c_loss);
	    if (q->cur_drop)
		continue;
	    if (no_room(q)) {
		q->tail = q->prod_tail; /* notify */
		usleep(1); // XXX give cons a chance to run ?
		if (no_room(q)) /* try to run drop-free once */
		    continue;
	    }
	    // XXX possibly implement c_tt for transmission time emulation
	    q->c_bw.run(q, &q->c_bw);
	    tt = q->cur_tt;
	    q->qt_qout += tt;
	    if (drop_after(q))
		continue;
	    q->c_delay.run(q, &q->c_delay); /* compute delay */
	    t_tx = q->qt_qout + q->cur_delay;
	    ND(5, "tt %ld qout %ld tx %ld qt_tx %ld", tt, q->qt_qout, t_tx, q->qt_tx);
	    /* insure no reordering and spacing by transmission time */
	    q->qt_tx = (t_tx >= q->qt_tx + tt) ? t_tx : q->qt_tx + tt;
	    enq(q);
	}
	q->tail = q->prod_tail; /* notify */
    }
    D("exiting on abort");
    return NULL;
}


/*
 * the consumer reads from the queue using head,
 * advances it every now and then.
 */
static void *
cons(void *_pa)
{
    struct pipe_args *pa = _pa;
    struct _qs *q = &pa->q;
    int cycles = 0;
    int pending = 0;
    const char *pre_start, *pre_end; /* prefetch limits */

    /*
     * prefetch about 2k ahead of the current pointer
     */
    pre_start = q->buf + q->head;
    pre_end = pre_start + 2048;

    (void)cycles; // XXX disable warning
    set_tns_now(&q->cons_now, q->t0);
    while (!do_abort) { /* consumer, infinite */
	struct q_pkt *p = (struct q_pkt *)(q->buf + q->head);
	if (p->next < q->head) { /* wrap around prefetch */
	    pre_start = q->buf + p->next;
	}
	pre_end = q->buf + p->next + 2048;
#if 1
	/* prefetch the first line saves 4ns */
        (void)pre_end;//   __builtin_prefetch(pre_end - 2048);
#else
	/* prefetch, ideally up to a full packet not just one line.
	 * this does not seem to have a huge effect.
	 * 4ns out of 198 on 1500 byte packets
	 */
	for (; pre_start < pre_end; pre_start += 64)
	    __builtin_prefetch(pre_start);
#endif

	if (q->head == q->tail || ts_cmp(p->pt_tx, q->cons_now) > 0) {
	    ND(4, "                 >>>> TXSYNC, pkt not ready yet h %ld t %ld now %ld tx %ld",
		q->head, q->tail, q->cons_now, p->pt_tx);
	    q->rx_wait++;
	    ioctl(pa->pb->fd, NIOCTXSYNC, 0); // XXX just in case
	    pending = 0;
	    usleep(5);
	    set_tns_now(&q->cons_now, q->t0);
	    continue;
	}
	ND(5, "drain len %ld now %ld tx %ld h %ld t %ld next %ld",
		p->pktlen, q->cons_now, p->pt_tx, q->head, q->tail, p->next);
	/* XXX inefficient but simple */
	pending++;
	if (nm_inject(pa->pb, (char *)(p + 1), p->pktlen) == 0 ||
		pending > q->burst) {
	    ND(5, "inject failed len %d now %ld tx %ld h %ld t %ld next %ld",
		(int)p->pktlen, q->cons_now, p->pt_tx, q->head, q->tail, p->next);
	    ioctl(pa->pb->fd, NIOCTXSYNC, 0);
	    pending = 0;
	    continue;
	}

	q->head = p->next;
	/* drain packets from the queue */
	q->rx++;
	// XXX barrier
    }
    D("exiting on abort");
    return NULL;
}


/*
 * main thread for each direction.
 * Allocates memory for the queues, creates the prod() thread,
 * then acts as a cons().
 */
static void *
tlem_main(void *_a)
{
    struct pipe_args *a = _a;
    struct _qs *q = &a->q;
    uint64_t need;

    setaffinity(a->cons_core);
    set_tns_now(&q->t0, 0); /* starting reference */

    a->pa = nm_open(q->prod_ifname, NULL, NETMAP_NO_TX_POLL, NULL);
    if (a->pa == NULL) {
	ED("cannot open %s", q->prod_ifname);
	return NULL;
    }
    // XXX use a single mmap ?
    a->pb = nm_open(q->cons_ifname, NULL, NM_OPEN_NO_MMAP, a->pa);
    if (a->pb == NULL) {
	ED("cannot open %s", q->cons_ifname);
	nm_close(a->pa);
	return NULL;
    }
    a->zerocopy = a->zerocopy && (a->pa->mem == a->pb->mem);
    ND("------- zerocopy %ssupported", a->zerocopy ? "" : "NOT ");
    /* allocate space for the queue:
     * compute required bw*delay (adding 1ms for good measure),
     * then add the queue size i bytes, then multiply by three due
     * to the packet expansion for padding
     */

    need = q->max_bps ? q->max_bps : INFINITE_BW;
    need *= q->max_delay + 1000000;	/* delay is in nanoseconds */
    need /= TIME_UNITS; /* total bits */
    need /= 8; /* in bytes */
    need += q->qsize; /* in bytes */
    need += 3 * MAX_PKT; // safety

    /*
     * This is the memory strictly for packets.
     * The size can increase a lot if we account for descriptors and
     * rounding.
     * In fact, the expansion factor can be up to a factor of 3
     * for particularly bad situations (65-byte packets)
     */
    need *= 3; /* room for descriptors and padding */

    q->buf = calloc(1, need);
    if (q->buf == NULL) {
	ED("alloc %ld bytes for queue failed, exiting", (_P64)need);
	nm_close(a->pa);
	nm_close(a->pb);
	return(NULL);
    }
    q->buflen = need;
    ED("----\n\t%s -> %s :  bps %ld delay %s loss %s queue %ld bytes"
	"\n\tbuffer %lu bytes",
	q->prod_ifname, q->cons_ifname,
	(_P64)q->max_bps, q->c_delay.optarg, q->c_loss.optarg, (_P64)q->qsize,
	(_P64)q->buflen);

    q->src_port = a->pa;

    pthread_create(&a->prod_tid, NULL, prod, (void*)a);
    /* continue as cons() */
    cons((void*)a);
    D("exiting on abort");
    return NULL;
}



static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}



static void
usage(void)
{
	fprintf(stderr,
	    "usage: tlem [-v] [-D delay] [-B bps] [-L loss] [-Q qsize] \n"
	    "\t[-b burst] [-w wait_time] -i ifa -i ifb\n");
	exit(1);
}


/*---- configuration handling ---- */
/*
 * support routine: split argument, returns ac and *av.
 * av contains two extra entries, a NULL and a pointer
 * to the entire string.
 */
static char **
split_arg(const char *src, int *_ac)
{
    char *my = NULL, **av = NULL, *seps = " \t\r\n,";
    int l, i, ac; /* number of entries */

    if (!src)
	return NULL;
    l = strlen(src);
    /* in the first pass we count fields, in the second pass
     * we allocate the av[] array and a copy of the string
     * and fill av[]. av[ac] = NULL, av[ac+1]
     */
    for (;;) {
	i = ac = 0;
	ND("start pass %d: <%s>", av ? 1 : 0, my);
	while (i < l) {
	    /* trim leading separator */
	    while (i <l && strchr(seps, src[i]))
		i++;
	    if (i >= l)
		break;
	    ND("   pass %d arg %d: <%s>", av ? 1 : 0, ac, src+i);
	    if (av) /* in the second pass, set the result */
		av[ac] = my+i;
	    ac++;
	    /* skip string */
	    while (i <l && !strchr(seps, src[i])) i++;
	    if (av)
		my[i] = '\0'; /* write marker */
	}
	if (!av) { /* end of first pass */
	    ND("ac is %d", ac);
	    av = calloc(1, (l+1) + (ac + 2)*sizeof(char *));
	    my = (char *)&(av[ac+2]);
	    strcpy(my, src);
	} else {
	    break;
	}
    }
    for (i = 0; i < ac; i++) fprintf(stderr, "%d: <%s>\n", i, av[i]);
    av[i++] = NULL;
    av[i++] = my;
    *_ac = ac;
    return av;
}


/*
 * apply a command against a set of functions,
 * install a handler in *dst
 */
static int
cmd_apply(const struct _cfg *a, const char *arg, struct _qs *q, struct _cfg *dst)
{
	int ac = 0;
	char **av;
	int i;

	if (arg == NULL || *arg == '\0')
		return 1; /* no argument may be ok */
	if (a == NULL || dst == NULL) {
		ED("program error - invalid arguments");
		exit(1);
	}
	av = split_arg(arg, &ac);
	if (av == NULL)
		return 1; /* error */
	for (i = 0; a[i].parse; i++) {
		struct _cfg x = a[i];
		const char *errmsg = x.optarg;
		int ret;

		x.arg = NULL;
		x.arg_len = 0;
		bzero(&x.d, sizeof(x.d));
		ret = x.parse(q, &x, ac, av);
		if (ret == 2) /* not recognised */
			continue;
		if (ret == 1) {
			ED("invalid arguments: need '%s' have '%s'",
				errmsg, arg);
			break;
		}
		x.optarg = arg;
		*dst = x;
		return 0;
	}
	ED("arguments %s not recognised", arg);
	free(av);
	return 1;
}

static struct _cfg delay_cfg[];
static struct _cfg bw_cfg[];
static struct _cfg loss_cfg[];

static uint64_t parse_bw(const char *arg);
static uint64_t parse_qsize(const char *arg);

/*
 * tlem [options]
 * accept separate sets of arguments for the two directions
 *
 */

static void
add_to(const char ** v, int l, const char *arg, const char *msg)
{
	for (; l > 0 && *v != NULL ; l--, v++);
	if (l == 0) {
		ED("%s %s", msg, arg);
		exit(1);
	}
	*v = arg;
}

int
main(int argc, char **argv)
{
	int ch, i, err=0;

#define	N_OPTS	2
	struct pipe_args bp[N_OPTS];
	const char *d[N_OPTS], *b[N_OPTS], *l[N_OPTS], *q[N_OPTS], *ifname[N_OPTS];
	int cores[4] = { 2, 8, 4, 10 }; /* default values */

	bzero(d, sizeof(d));
	bzero(b, sizeof(b));
	bzero(l, sizeof(l));
	bzero(q, sizeof(q));
	bzero(ifname, sizeof(ifname));

	fprintf(stderr, "%s built %s %s\n", argv[0], __DATE__, __TIME__);

	bzero(&bp, sizeof(bp));	/* all data initially go here */

	for (i = 0; i < N_OPTS; i++) {
	    struct _qs *q = &bp[i].q;
	    q->c_delay.optarg = "0";
	    q->c_delay.run = null_run_fn;
	    q->c_loss.optarg = "0";
	    q->c_loss.run = null_run_fn;
	    q->c_bw.optarg = "0";
	    q->c_bw.run = null_run_fn;
	}

	// Options:
	// B	bandwidth in bps
	// D	delay in seconds
	// Q	qsize in bytes
	// L	loss probability
	// i	interface name (two mandatory)
	// v	verbose
	// b	batch size

	while ( (ch = getopt(argc, argv, "B:C:D:L:Q:b:ci:vw:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;

		case 'C': /* CPU placement, up to 4 arguments */
			{
				int ac = 0;
				char **av = split_arg(optarg, &ac);
				if (ac == 1) { /* sequential after the first */
					cores[0] = atoi(av[0]);
					cores[1] = cores[0] + 1;
					cores[2] = cores[1] + 1;
					cores[3] = cores[2] + 1;
				} else if (ac == 2) { /* two sequential pairs */
					cores[0] = atoi(av[0]);
					cores[1] = cores[0] + 1;
					cores[2] = atoi(av[1]);
					cores[3] = cores[2] + 1;
				} else if (ac == 4) { /* four values */
					cores[0] = atoi(av[0]);
					cores[1] = atoi(av[1]);
					cores[2] = atoi(av[2]);
					cores[3] = atoi(av[3]);
				} else {
					ED(" -C accepts 1, 2 or 4 comma separated arguments");
					usage();
				}
				if (av)
					free(av);
			}
			break;

		case 'B': /* bandwidth in bps */
			add_to(b, N_OPTS, optarg, "-B too many times");
			break;

		case 'D': /* delay in seconds (float) */
			add_to(d, N_OPTS, optarg, "-D too many times");
			break;

		case 'Q': /* qsize in bytes */
			add_to(q, N_OPTS, optarg, "-Q too many times");
			break;

		case 'L': /* loss probability */
			add_to(l, N_OPTS, optarg, "-L too many times");
			break;

		case 'b':	/* burst */
			bp[0].q.burst = atoi(optarg);
			break;

		case 'i':	/* interface */
			add_to(ifname, N_OPTS, optarg, "-i too many times");
			break;
		case 'c':
			bp[0].zerocopy = 0; /* do not zerocopy */
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			bp[0].wait_link = atoi(optarg);
			break;
		}

	}

	argc -= optind;
	argv += optind;

	/*
	 * consistency checks for common arguments
	 */
	if (!ifname[0] || !ifname[0]) {
		ED("missing interface(s)");
		usage();
	}
	if (strcmp(ifname[0], ifname[1]) == 0) {
		ED("must specify two different interfaces %s %s", ifname[0], ifname[1]);
		usage();
	}
	if (bp[0].q.burst < 1 || bp[0].q.burst > 8192) {
		ED("invalid burst %d, set to 1024", bp[0].q.burst);
		bp[0].q.burst = 1024; // XXX 128 is probably better
	}
	if (bp[0].wait_link > 100) {
		ED("invalid wait_link %d, set to 4", bp[0].wait_link);
		bp[0].wait_link = 4;
	}

	bp[1] = bp[0]; /* copy parameters, but swap interfaces */
	bp[0].q.prod_ifname = bp[1].q.cons_ifname = ifname[0];
	bp[1].q.prod_ifname = bp[0].q.cons_ifname = ifname[1];

	/* assign cores. prod and cons work better if on the same HT */
	bp[0].cons_core = cores[0];
	bp[0].prod_core = cores[1];
	bp[1].cons_core = cores[2];
	bp[1].prod_core = cores[3];
	ED("running on cores %d %d %d %d", cores[0], cores[1], cores[2], cores[3]);

	/* use same parameters for both directions if needed */
	if (d[1] == NULL)
		d[1] = d[0];
	if (b[1] == NULL)
		b[1] = b[0];
	if (l[1] == NULL)
		l[1] = l[0];

	/* apply commands */
	for (i = 0; i < N_OPTS; i++) { /* once per queue */
		struct _qs *q = &bp[i].q;
		err += cmd_apply(delay_cfg, d[i], q, &q->c_delay);
		err += cmd_apply(bw_cfg, b[i], q, &q->c_bw);
		err += cmd_apply(loss_cfg, l[i], q, &q->c_loss);
	}

	if (q[0] == NULL)
		q[0] = "0";
	if (q[1] == NULL)
		q[1] = q[0];
	bp[0].q.qsize = parse_qsize(q[0]);
	bp[1].q.qsize = parse_qsize(q[1]);

	if (bp[0].q.qsize == 0) {
		ED("qsize= 0 is not valid, set to 50k");
		bp[0].q.qsize = 50000;
	}
	if (bp[1].q.qsize == 0) {
		ED("qsize= 0 is not valid, set to 50k");
		bp[1].q.qsize = 50000;
	}

	pthread_create(&bp[0].cons_tid, NULL, tlem_main, (void*)&bp[0]);
	pthread_create(&bp[1].cons_tid, NULL, tlem_main, (void*)&bp[1]);

	signal(SIGINT, sigint_h);
	sleep(1);
	while (!do_abort) {
	    struct _qs olda = bp[0].q, oldb = bp[1].q;
	    struct _qs *q0 = &bp[0].q, *q1 = &bp[1].q;

	    sleep(1);
	    ED("%ld -> %ld maxq %d round %ld, %ld <- %ld maxq %d round %ld",
		(_P64)(q0->rx - olda.rx), (_P64)(q0->tx - olda.tx),
		q0->rx_qmax, (_P64)q0->prod_max_gap,
		(_P64)(q1->rx - oldb.rx), (_P64)(q1->tx - oldb.tx),
		q1->rx_qmax, (_P64)q1->prod_max_gap
		);
	    ED("plr nominal %le actual %le",
		(double)(q0->c_loss.d[0])/(1<<24),
		q0->c_loss.d[1] == 0 ? 0 :
		(double)(q0->c_loss.d[2])/q0->c_loss.d[1]);
	    bp[0].q.rx_qmax = (bp[0].q.rx_qmax * 7)/8; // ewma
	    bp[0].q.prod_max_gap = (bp[0].q.prod_max_gap * 7)/8; // ewma
	    bp[1].q.rx_qmax = (bp[1].q.rx_qmax * 7)/8; // ewma
	    bp[1].q.prod_max_gap = (bp[1].q.prod_max_gap * 7)/8; // ewma
	}
	D("exiting on abort");
	sleep(1);

	return (0);
}

/* conversion factor for numbers.
 * Each entry has a set of characters and conversion factor,
 * the first entry should have an empty string and default factor,
 * the final entry has s = NULL.
 */
struct _sm {	/* string and multiplier */
	char *s;
	double m;
};

/*
 * parse a generic value
 */
static double
parse_gen(const char *arg, const struct _sm *conv, int *err)
{
	double d;
	char *ep;
	int dummy;

	if (err == NULL)
		err = &dummy;
	*err = 0;
	if (arg == NULL)
		goto error;
	d = strtod(arg, &ep);
	if (ep == arg) { /* no value */
		ED("bad argument %s", arg);
		goto error;
	}
	/* special case, no conversion */
	if (conv == NULL && *ep == '\0')
		goto done;
	ND("checking %s [%s]", arg, ep);
	for (;conv->s; conv++) {
		if (strchr(conv->s, *ep))
			goto done;
	}
error:
	*err = 1;	/* unrecognised */
	return 0;

done:
	if (conv) {
		ND("scale is %s %lf", conv->s, conv->m);
		d *= conv->m; /* apply default conversion */
	}
	ND("returning %lf", d);
	return d;
}

#define U_PARSE_ERR ~(0ULL)

/* returns a value in nanoseconds */
static uint64_t
parse_time(const char *arg)
{
    struct _sm a[] = {
	{"", 1000000000 /* seconds */},
	{"n", 1 /* nanoseconds */}, {"u", 1000 /* microseconds */},
	{"m", 1000000 /* milliseconds */}, {"s", 1000000000 /* seconds */},
	{NULL, 0 /* seconds */}
    };
    int err;
    uint64_t ret = (uint64_t)parse_gen(arg, a, &err);
    return err ? U_PARSE_ERR : ret;
}


/*
 * parse a bandwidth, returns value in bps or U_PARSE_ERR if error.
 */
static uint64_t
parse_bw(const char *arg)
{
    struct _sm a[] = {
	{"", 1}, {"kK", 1000}, {"mM", 1000000}, {"gG", 1000000000}, {NULL, 0}
    };
    int err;
    uint64_t ret = (uint64_t)parse_gen(arg, a, &err);
    return err ? U_PARSE_ERR : ret;
}

/*
 * parse a queue size, returns value in bytes or U_PARSE_ERR if error.
 */
static uint64_t
parse_qsize(const char *arg)
{
    struct _sm a[] = {
	{"", 1}, {"kK", 1024}, {"mM", 1024*1024}, {"gG", 1024*1024*1024}, {NULL, 0}
    };
    int err;
    uint64_t ret = (uint64_t)parse_gen(arg, a, &err);
    return err ? U_PARSE_ERR : ret;
}

/*
 * For some function we need random bits.
 * This is a wrapper to whatever function you want that returns
 * 24 useful random bits.
 */

#include <math.h> /* log, exp etc. */
static inline uint64_t
my_random24(void)	/* 24 useful bits */
{
	return random() & ((1<<24) - 1);
}


/*-------------- user-configuration -----------------*/

#if 0 /* start of comment block */

Here we place the functions to implement the various features
of the system. For each feature one should define a struct _cfg
(see at the beginning for definition) that refers a *_parse() function
to extract values from the command line, and a *_run() function
that is invoked on each packet to implement the desired function.

Examples of the two functions are below. In general:

- the *_parse() function takes argc/argv[], matches the function
  name in argv[0], extracts the operating parameters, allocates memory
  if needed, and stores them in the struct _cfg.
  Return value is 2 if argv[0] is not recosnised, 1 if there is an
  error in the arguments, 0 if all ok.

  On the command line, argv[] is a single, comma separated argument
  that follow the specific option eg -D constant,20ms

  struct _cfg has some preallocated space (e.g an array of uint64_t) so simple
  function can use that without having to allocate memory.

- the *_run() function takes struct _q *q and struct _cfg *cfg as arguments.
  *q contains all the informatio that may be possibly needed, including
  those on the packet currently under processing.
  The basic values are the following:

	char *	 cur_pkt 	points to the current packet (linear buffer)
	uint32_t cur_len;	length of the current packet
		the functions are not supposed to modify these values

	int	 cur_drop;	true if current packet must be dropped.
		Must be set to non-zero by the loss emulation function

	uint64_t cur_delay;	delay in nanoseconds for the current packet
		Must be set by the delay emulation function

   More sophisticated functions may need to access other fields in *q,
   see the structure description for that.

When implementing a new function for a feature (e.g. for delay,
bandwidth, loss...) the struct _cfg should be added to the array
that contains all possible options.

		--- Specific notes ---

DELAY emulation		-D option_arguments

    NOTE: The config function should store, in q->max_delay,
    a reasonable estimate of the maximum delay applied to the packets
    as this is needed to size the memory buffer used to store packets.

    If the option is not supplied, the system applies 0 extra delay

    The resolution for times is 1ns, the precision is load dependent and
    generally in the order of 20-50us.
    Times are in nanoseconds, can be followed by a character specifying
    a different unit e.g.

	n	nanoseconds
	u	microseconds
	m	milliseconds
	s	seconds

    Currently implemented options:

    constant,t		constant delay equal to t

    uniform,tmin,tmax	uniform delay between tmin and tmax

    exp,tavg,tmin	exponential distribution with average tavg
			and minimum tmin (corresponds to an exponential
			distribution with argument 1/(tavg-tmin) )


LOSS emulation		-L option_arguments

    Loss is expressed as packet or bit error rate, which is an absolute
    number between 0 and 1 (typically small).

    Currently implemented options

    plr,p		uniform packet loss rate p, independent
			of packet size

    burst,p,lmin,lmax 	burst loss with burst probability p and
			burst length uniformly distributed between
			lmin and lmax

    ber,p		uniformly distributed bit error rate p,
			so actual loss prob. depends on size.

BANDWIDTH emulation	-B option_arguments

    Bandwidths are expressed in bits per second, can be followed by a
    character specifying a different unit e.g.

	b/B	bits per second
	k/K	kbits/s (10^3 bits/s)
	m/M	mbits/s (10^6 bits/s)
	g/G	gbits/s (10^9 bits/s)

    The config function should store in q->max_bps the maximum
    available bandwidth, which is used to determine how much space
    is needed in the queue.

    Currently implemented options

    const,b		constant bw, excluding mac framing
    ether,b		constant bw, including ethernet framing
			(20 bytes framing + 4 bytes crc)

#endif /* end of comment block */

/*
 * Configuration options for delay
 *
 * Must store a reasonable estimate of the max_delay in q->max_delay
 * as this is used to size the queue.
 */

/* constant delay, also accepts just a number */
static int
const_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	uint64_t delay;

	if (strncmp(av[0], "const", 5) != 0 && ac > 1)
		return 2; /* unrecognised */
	if (ac > 2)
		return 1; /* error */
	delay = parse_time(av[ac - 1]);
	if (delay == U_PARSE_ERR)
		return 1; /* error */
	dst->d[0] = delay;
	q->max_delay = delay;
	return 0;	/* success */
}

/* runtime function, store the delay into q->cur_delay */
static int
const_delay_run(struct _qs *q, struct _cfg *arg)
{
	q->cur_delay = arg->d[0]; /* the delay */
	return 0;
}

static int
uniform_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	uint64_t dmin, dmax;

	(void)q;
	if (strcmp(av[0], "uniform") != 0)
		return 2; /* not recognised */
	if (ac != 3)
		return 1; /* error */
	dmin = parse_time(av[1]);
	dmax = parse_time(av[2]);
	if (dmin == U_PARSE_ERR || dmax == U_PARSE_ERR || dmin > dmax)
		return 1;
	D("dmin %ld dmax %ld", (_P64)dmin, (_P64)dmax);
	dst->d[0] = dmin;
	dst->d[1] = dmax;
	dst->d[2] = dmax - dmin;
	q->max_delay = dmax;
	return 0;
}

static int
uniform_delay_run(struct _qs *q, struct _cfg *arg)
{
	uint64_t x = my_random24();
	q->cur_delay = arg->d[0] + ((arg->d[2] * x) >> 24);
#if 0 /* COMPUTE_STATS */
#endif /* COMPUTE_STATS */
	return 0;
}

/*
 * exponential delay: Prob(delay = x) = exp(-x/d_av)
 * gives a delay between 0 and infinity with average d_av
 * The cumulative function is 1 - d_av exp(-x/d_av)
 *
 * The inverse function generates a uniform random number p in 0..1
 * and generates delay = (d_av-d_min) * -ln(1-p) + d_min
 *
 * To speed up behaviour at runtime we tabulate the values
 */

static int
exp_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
#define	PTS_D_EXP	512
	uint64_t i, d_av, d_min, *t; /*table of values */

        (void)q;
        if (strcmp(av[0], "exp") != 0)
		return 2; /* not recognised */
        if (ac != 3)
                return 1; /* error */
        d_av = parse_time(av[1]);
        d_min = parse_time(av[2]);
        if (d_av == U_PARSE_ERR || d_min == U_PARSE_ERR || d_av < d_min)
                return 1; /* error */
	d_av -= d_min;
	dst->arg_len = PTS_D_EXP * sizeof(uint64_t);
	dst->arg = calloc(1, dst->arg_len);
	if (dst->arg == NULL)
		return 1; /* no memory */
	t = (uint64_t *)dst->arg;
        q->max_delay = d_av * 4 + d_min; /* exp(-4) */
	/* tabulate -ln(1-n)*delay  for n in 0..1 */
	for (i = 0; i < PTS_D_EXP; i++) {
		double d = -log2 ((double)(PTS_D_EXP - i) / PTS_D_EXP) * d_av + d_min;
		t[i] = (uint64_t)d;
		ND(5, "%ld: %le", i, d);
	}
        return 0;
}

static int
exp_delay_run(struct _qs *q, struct _cfg *arg)
{
	uint64_t *t = (uint64_t *)arg->arg;
        q->cur_delay = t[my_random24() & (PTS_D_EXP - 1)];
	RD(5, "delay %lu", (_P64)q->cur_delay);
        return 0;
}


#define TLEM_CFG_END	NULL, 0, {0}

static struct _cfg delay_cfg[] = {
	{ const_delay_parse, const_delay_run,
		"constant,delay", TLEM_CFG_END },
	{ uniform_delay_parse, uniform_delay_run,
		"uniform,dmin,dmax # dmin <= dmax", TLEM_CFG_END },
	{ exp_delay_parse, exp_delay_run,
		"exp,dmin,davg # dmin <= davg", TLEM_CFG_END },
	{ NULL, NULL, NULL, TLEM_CFG_END }
};

/* standard bandwidth, also accepts just a number */
static int
const_bw_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	uint64_t bw;

	(void)q;
	if (strncmp(av[0], "const", 5) != 0)
		return 2; /* unrecognised */
	if (ac > 2)
		return 1; /* error */
	bw = parse_bw(av[ac - 1]);
	if (bw == U_PARSE_ERR) {
		return (ac == 2) ? 1 /* error */ : 2 /* unrecognised */;
	}
	dst->d[0] = bw;
	q->max_bps = bw;	/* bw used to determine queue size */
	return 0;	/* success */
}


/* runtime function, store the delay into q->cur_delay */
static int
const_bw_run(struct _qs *q, struct _cfg *arg)
{
	uint64_t bps = arg->d[0];
	q->cur_tt = bps ? 8ULL* TIME_UNITS * q->cur_len / bps : 0 ;
	return 0;
}

/* ethernet bandwidth, add 672 bits per packet */
static int
ether_bw_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	uint64_t bw;

	(void)q;
	if (strcmp(av[0], "ether") != 0)
		return 2; /* unrecognised */
	if (ac != 2)
		return 1; /* error */
	bw = parse_bw(av[ac - 1]);
	if (bw == U_PARSE_ERR)
		return 1; /* error */
	dst->d[0] = bw;
	q->max_bps = bw;	/* bw used to determine queue size */
	return 0;	/* success */
}


/* runtime function, add 20 bytes (framing) + 4 bytes (crc) */
static int
ether_bw_run(struct _qs *q, struct _cfg *arg)
{
	uint64_t bps = arg->d[0];
	q->cur_tt = bps ? 8ULL * TIME_UNITS * (q->cur_len + 24) / bps : 0 ;
	return 0;
}

static struct _cfg bw_cfg[] = {
	{ const_bw_parse, const_bw_run,
		"constant,bps", TLEM_CFG_END },
	{ ether_bw_parse, ether_bw_run,
		"ether,bps", TLEM_CFG_END },
	{ NULL, NULL, NULL, TLEM_CFG_END }
};

/*
 * loss patterns
 */
static int
const_plr_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	double plr;
	int err;

	(void)q;
	if (strcmp(av[0], "plr") != 0 && ac > 1)
		return 2; /* unrecognised */
	if (ac > 2)
		return 1; /* error */
	// XXX to be completed
	plr = parse_gen(av[ac-1], NULL, &err);
	if (err || plr < 0 || plr > 1)
		return 1;
	dst->d[0] = plr * (1<<24); /* scale is 16m */
	if (plr != 0 && dst->d[0] == 0)
		ED("WWW warning,  rounding %le down to 0", plr);
	return 0;	/* success */
}

static int
const_plr_run(struct _qs *q, struct _cfg *arg)
{
	(void)arg;
	uint64_t r = my_random24();
	q->cur_drop = r < arg->d[0];
#if 1	/* keep stats */
	arg->d[1]++;
	arg->d[2] += q->cur_drop;
#endif
	return 0;
}


/*
 * For BER the loss is 1- (1-ber)**bit_len
 * The linear approximation is only good for small values, so we
 * tabulate (1-ber)**len for various sizes in bytes
 */
static int
const_ber_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
	double ber, ber8, cur;
	int i, err;
	uint32_t *plr;
	const uint32_t mask = (1<<24) - 1;

	(void)q;
	if (strcmp(av[0], "ber") != 0)
		return 2; /* unrecognised */
	if (ac != 2)
		return 1; /* error */
	ber = parse_gen(av[ac-1], NULL, &err);
	if (err || ber < 0 || ber > 1)
		return 1;
	dst->arg_len = MAX_PKT * sizeof(uint32_t);
	plr = calloc(1, dst->arg_len);
	if (plr == NULL)
		return 1; /* no memory */
	dst->arg = plr;
	ber8 = 1 - ber;
	ber8 *= ber8; /* **2 */
	ber8 *= ber8; /* **4 */
	ber8 *= ber8; /* **8 */
	cur = 1;
	for (i=0; i < MAX_PKT; i++, cur *= ber8) {
		plr[i] = (mask + 1)*(1 - cur);
		if (plr[i] > mask)
			plr[i] = mask;
#if 0
		if (i>= 60) //  && plr[i] < mask/2)
			RD(50,"%4d: %le %ld", i, 1.0 - cur, (_P64)plr[i]);
#endif
	}
	dst->d[0] = ber * (mask + 1);
	return 0;	/* success */
}

static int
const_ber_run(struct _qs *q, struct _cfg *arg)
{
	int l = q->cur_len;
	uint64_t r = my_random24();
	uint32_t *plr = arg->arg;

	if (l >= MAX_PKT) {
		RD(5, "pkt len %d too large, trim to %d", l, MAX_PKT-1);
		l = MAX_PKT-1;
	}
	q->cur_drop = r < plr[l];
#if 1	/* keep stats */
	arg->d[1] += l * 8;
	arg->d[2] += q->cur_drop;
#endif
	return 0;
}

static struct _cfg loss_cfg[] = {
	{ const_plr_parse, const_plr_run,
		"plr,prob # 0 <= prob <= 1", TLEM_CFG_END },
	{ const_ber_parse, const_ber_run,
		"ber,prob # 0 <= prob <= 1", TLEM_CFG_END },
	{ NULL, NULL, NULL, TLEM_CFG_END }
};
