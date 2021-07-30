/* vim: set shiftwidth=4 softtabstop=4 :*/
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

#define WITH_MAX_LAG

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
/
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
good results but that should be investigated further.

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

    Five functions are then called in sequence:

    q->c_loss (set with the -L command line option) decides
    	whether the packet should be dropped before even queuing.
	This is generally useful to emulate random loss.
	The function is supposed to set q->c_drop = 1 if the
	packet should be dropped, or leave it to 0 otherwise.

    q-c_reorder (set with the -R command line option) decides
        whether the packet should be temporary hold to emulate
	packet reordering. To hold a packet, it should set
	q->cur_hold_delay to a non-zero value. The packet will
	reenter the stream once the cur_hold_delay has expired.

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
	   if (verbose > 0) {					\
		struct timeval _t0;				\
		gettimeofday(&_t0, NULL);			\
		fprintf(stderr, "%03d.%03d [%5d] \t" _fmt "\n", \
		(int)(_t0.tv_sec % 1000), (int)_t0.tv_usec/1000, \
		__LINE__, ##__VA_ARGS__);     \
	   }							\
	} while (0)

#define _GNU_SOURCE	// for CPU_SET() etc
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libnetmap.h>


int verbose = 1;

static int do_abort = 0;

#ifdef linux
static int latency_fd = -1;
static void latency_reduction_start(void)
{
    uint32_t target = 0;

    if (latency_fd >= 0)
        return;
    latency_fd = open("/dev/cpu_dma_latency", O_RDWR);
    if (latency_fd < 0) {
        ED("WARNING: failed to setup low latency: %s", strerror(errno));
        return;
    }
    if (write(latency_fd, &target, sizeof(target)) < 0) {
        ED("WARNING: failed to setup low latency: %s", strerror(errno));
    }
    ED("latency reduction started");
}
static void latency_reduction_stop(void)
{
    if (latency_fd >= 0)
        close(latency_fd);
}
#else
#define latency_reduction_start()
#define latency_reduction_stop()
#endif /* linux */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/time.h>

// for route-mode
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <sys/resource.h> // setpriority

#ifdef __FreeBSD__
#include <net/if_dl.h>	/* sokcaddr_dl */
#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#define MAP_HUGETLB 0	/* not supported */
#endif /* __FreeBSD__ */

#ifdef linux
#define cpuset_t        cpu_set_t
#include <sys/mman.h>
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#endif

#include "ctrs.h"	/* norm() */

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

#define	MY_CACHELINE	(128ULL)
#define ALIGN_CACHE	__attribute__ ((aligned (MY_CACHELINE)))

struct stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	drop_packets;
	uint64_t	drop_bytes;
	uint64_t	reorder_packets;
	uint64_t	reorder_bytes;
} ALIGN_CACHE;

/* external configuration for each impairment (bw, delay, loss, reorder, ...) */
struct _ec {
        uint8_t         ec_valid;       /* 1 iff the other fields are valid */
        uint8_t         ec_index;       /* impairment sub-type */
        uint16_t        ec_datasz;      /* size of the parameters */
        uint32_t        ec_dataoff;     /* offset of the parameters */
};

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
    void *arg;		/* allocated memory */
    struct _ec *ec;     /* external configuration */
    uint64_t def_qsize; /* default qsize (for bw configs) */
};

/* impairments */
enum {
	I_DELAY = 0,
	I_BW,
	I_LOSS,
	I_REORDER,
	I_NUM
};

/* configuration instance. There may be one or more of these
 * for direction. One of them is the active one, currently
 * used by the server. Clients prepare an instance not in use,
 * then make it active when ready.
 */
struct _eci {
        struct _ec      ec_imp[I_NUM];
	uint64_t	ec_delay_offset;
	int		ec_allow_drop;
	uint32_t	ec_qsize;
#define EC_DATASZ       (1U << 17)
        char            ec_data[EC_DATASZ];
};

/* set of configuration instances. One set per direction */
struct _ecs {
        /* fields only written by the server */
	uint64_t	max_bps;	/* bits per second */
	uint64_t	max_delay;	/* nanoseconds */
	uint64_t	max_hold_delay; /* nanoseconds */
        /* fields written by the server on startup, and then by
         * the clients in mutual exclusion among themselves.
         * The communication among the clients and the server
         * is lockless, and based on ordered updates to the
         * active field.
         */
        volatile uint64_t active; /* active configuration instance */
#define EC_NINST      2
        struct _eci    instances[EC_NINST];
};

/* contents of the external configuration */
struct _ecf {
#define EC_NOPTS      2
	struct stats	stats[2 * EC_NOPTS];
        uint32_t        version;
#define EC_VERSION    1
        struct _ecs     sets[EC_NOPTS];
};
#define EC_HDRSZ (offsetof(struct _ecf, sets))

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

/* for packets hold for reorderind we only record their size and
 * hold time.
 */
struct h_pkt {
	uint64_t	pktlen;
	uint64_t	releasetime;
};

/*
 * When sizing the buffer, we must assume some value for the bandwidth.
 * INFINITE_BW is supposed to be faster than what we support
 */
#define INFINITE_BW	(200ULL*1000000*1000)
#define PKT_PAD		(8)	/* padding on packets */
#define MAX_PKT		(9200)	/* max packet size */
#define MAX_FRAGS       (1000)  /* max number of fragments */

struct _frag {
       char           *buf;
       unsigned int    len;
};

struct _qs { /* shared queue */
	uint64_t	t0;	/* start of times */

	uint64_t 	buflen;	/* queue length */
	char *buf;

        struct _ecs    *ec;             /* external configuration set */
        uint32_t        ec_active;      /* active instance in the set */
        size_t          ec_nta[EC_NINST]; /* allocated byes in each instance */
	/* the queue has at least 1 empty position */
	uint64_t	qsize;	/* queue size in bytes */

	/* handlers for various options */
	struct _cfg	c_imp[I_NUM];

	/* producer's fields */
	uint64_t	prod_tail_1 ALIGN_CACHE; /* head of queue */
	uint64_t	prod_queued;	/* queued bytes */
	uint64_t	prod_head;	/* cached copy */
	uint64_t	prod_tail;	/* cached copy */
	uint64_t	prod_now;	/* most recent producer timestamp */
	uint64_t	prod_max_gap;	/* rx round duration */
	unsigned short	prod_seed[3];
	struct stats	*txstats;

	/* parameters for reading from the netmap port */
	struct nmport_d *src_port;		/* netmap descriptor */
	const char *	prod_ifname;	/* interface name */
	struct netmap_ring *rxring;	/* source netmap ring */
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
        struct _frag    cur_frags[MAX_FRAGS];
        int             cur_nfrags;

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
	int		allow_drop;	/* improve delay accuracy by dropping packets */
		/*
		 * by default, TLEM adjusts the cur_delay of each packet to
		 * avoid reordering, thus sacrificing the delay emulation
		 * accuracy.  In 'allow_drop' mode we try to improve the
		 * accuracy by dropping the packets that should be reordered,
		 * instead of queueing them.
		 */
	int		reuse_delay;	/* reuse the last computed delay */
		/*
		 * In 'allow_drop' mode we reuse the last computed delay until
		 * we find a packet that can be sent in order. If we kept
		 * recomputing the delay, instead, we would skew the
		 * distribution towards larger values.
		 */
	uint64_t	delay_offset;	/* to be subtracted from cur_delay */

	/* producers's fields for reordering */
	uint64_t	cur_hold_delay; /* reordering delay (ns) from c_reorder.run() */
	uint64_t	hold_tail, hold_head; /* pointers in the reorder queue */
	char	       *hold_buf;	/* the reorder queue */
	uint64_t	hold_buflen;	/* and its size */
	uint64_t	hold_next_rt;	/* release time of the first hold packet */
	uint64_t	hold_tail_rt;	/* release time of the last hold packet */
	int		hold_release;   /* there are packets ready to be released */


	/* consumer's fields */
//	uint64_t	cons_head;	/* cached copy */
//	uint64_t	cons_tail;	/* cached copy */
	uint64_t	cons_now ALIGN_CACHE;	/* most recent producer timestamp */
	uint64_t	cons_lag;	/* tail - head */
	uint64_t	rx_wait;	/* stats */
	const char *	cons_ifname;
	struct stats	*rxstats;

	/* shared fields */
	volatile uint64_t tail ALIGN_CACHE ;	/* producer writes here */
	volatile uint64_t head ALIGN_CACHE ;	/* consumer reads from here */
};

static int
ec_next(int i)
{
    return (i + 1) % EC_NINST;
}

/* if fname is NULL tlem will run standalone, i.e., in server mode
 * with no possibility for clients to change the configuration.
 * Otherwise, the first tlem instance that successfully locks the
 * first four bytes of the configuration file becomes the server.
 * Clients write-lock the rest of the file, to guarantee mutual
 * exclusive configuration updates among them.
 */
static int ecf_fd = -1;
static struct _ecf *
ec_map(const char *fname, int *server)
{
    size_t sz;
    struct _ecf *ecf;
    int mmap_flags;

    sz = sizeof(struct _ecf);
    if (fname) {
        ecf_fd = open(fname, O_RDWR | O_CREAT, 0664);
        if (ecf_fd < 0) {
            ED("cannot open %s: %s", fname, strerror(errno));
            return NULL;
        }
        if (ftruncate(ecf_fd, sz) < 0) {
            ED("cannot truncate(%s, %zu): %s",
                    fname, sz, strerror(errno));
            return NULL;
        }
        mmap_flags = MAP_SHARED;

        /* try to lock the entire file.
         * If we succeed, we are the server.
         */
        if (lockf(ecf_fd, F_TLOCK, 0) == 0) {
            *server = 1;
            /* we will release the non-header part when
             * we are done with the initial configuration
             */
        } else {
            if (errno != EACCES && errno != EAGAIN) {
                ED("failed to lock %s: %s", fname, strerror(errno));
                return NULL;
            }
            /* we are a client. Skip the header and wait
             * for exclusive access to the rest.
             */
            *server = 0;
            if (lseek(ecf_fd, EC_HDRSZ, SEEK_SET) < 0) {
                ED("failed to skip the header of %s: %s",
                        fname, strerror(errno));
                return NULL;
            }
            if (lockf(ecf_fd, F_LOCK, 0) < 0) {
                ED("failed to lock the client area of %s: %s",
                        fname, strerror(errno));
                return NULL;
            }
        }
    } else {
        mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE;
    }
    ecf = mmap(NULL, sz,
            PROT_READ | PROT_WRITE,
            mmap_flags, ecf_fd, 0);
    /* errors are all fatal. Locks will be released on exit */
    if (ecf == MAP_FAILED) {
        D("cannot mmap %s: %s", fname, strerror(errno));
        return NULL;
    }
    if (*server) {
        memset(ecf, 0, sz);
        ecf->version = EC_VERSION;
    } else {
        if (ecf->version != EC_VERSION) {
            ED("Expected version %d, got %d",
                    EC_VERSION, ecf->version);
            return NULL;
        }
    }
    return ecf;
}

static int
ec_waitterminate()
{
    if (ecf_fd < 0)
        return 0;
    if (lseek(ecf_fd, 0, SEEK_SET) < 0) {
        ED("failed to rewind the session file: %s",
                strerror(errno));
        return 1;
    }
    if (lockf(ecf_fd, F_LOCK, 0) < 0) {
        ED("failed to lock the session file %s",
                strerror(errno));
        return 1;
    }
    return 0;
}

static int
ec_allowclients()
{
    if (ecf_fd < 0) {
        /* OK, standalone mode */
        return 0;
    }
    if (lseek(ecf_fd, EC_HDRSZ, SEEK_SET) < 0) {
        ED("failed to skip the header: %s",
                strerror(errno));
        return 1;
    }
    if (lockf(ecf_fd, F_ULOCK, 0) < 0) {
        ED("failed to unlock the client area: %s",
                strerror(errno));
        return 1;
    }
    return 0;
}

static void ec_activate(struct _qs *q); // forward
static int
ec_init(struct _qs *q, struct _ecs *ec, int server)
{
    int i;
    struct _eci *ci;

    q->ec = ec;
    for (i = 0; i < EC_NINST; i++)
	q->ec_nta[i] = 0;
    q->ec_active = server ? 0 : ec_next(q->ec->active);
    ci = &q->ec->instances[q->ec_active];
    for (i = 0; i < I_NUM; i++) {
	ci->ec_imp[i].ec_valid = 0;
	q->c_imp[i].ec = &ci->ec_imp[i];
    }
    return 0;
}

static void
ec_terminate(struct _ecs *ec)
{
    ec->active = EC_NINST;
}

/* allocate sz bytes in the non-active config instance */
static void *
ec_alloc(struct _qs *q, struct _ec *ec, size_t sz)
{
    int i = q->ec_active;
    struct _eci *a = &q->ec->instances[i];
    size_t nta = q->ec_nta[i];

    if (sz + nta >= EC_DATASZ) {
        ED("no room for %zu bytes in external config instance %d", sz, i);
        return NULL;
    }
    q->ec_nta[i] += sz;
    ec->ec_dataoff = nta;
    ec->ec_datasz = sz;
    return &a->ec_data[nta];
}

static inline void
ec_checkactive(struct _qs *q)
{
    uint64_t i = q->ec->active;
    if (unlikely(i >= EC_NINST)) {
        /* setting ec_active to an out-of-bounds value is
         * interpreted as an exit request
         */
        do_abort = 1;
        return;
    }
    if (i != q->ec_active) {
        asm volatile("" ::: "memory");
        __sync_synchronize();
        ND("switching to configuration %i", i);
        q->ec_active = i;
        ec_activate(q);
    }
}

static void
ec_switchactive(struct _qs *q)
{
    if (q->ec_active != q->ec->active) {
        asm volatile("" ::: "memory");
        __sync_synchronize();
        ND("switching to configuration %i", q->ec_active);
        q->ec->active = q->ec_active;
    }
}

/* route-mode data structures and helper functions
 *
 * In route-mode TLEM acts as a router between the two subnets at its ends.
 * This is implemented as follows:
 * - there are two arp tables, one for each subnet
 * - arp tables are private to the cons() process
 * - the prod() processes extract the relevant info from any received ARP
 *   message and pass them down to the cons() process insisting on the same
 *   port, as illustrated in the following diagram:
 *
 *         |---> prod1 --------------------------> cons1 --->|
 *         |       |                                 ^       |
 *         | ARP req/repl info                       |       |
 *         |       |                                 |       |
 * port1<->+       |                                 |       +<->port2
 *         |       |                                 |       |
 *         |       |                       ARP req/repl info |
 *         |       V                                 |       |
 *         |<--- cons2 <-------------------------- prod2 <---|
 *
 * - the cons() processes react to these infos by sending ARP replies/
 *   updating their private ARP table as needed
 * - the cons() processes change the outgoing packets destination addresses
 *   before injecting them, sending ARP requests when needed.
 * - TTL decrement is not implemented, for performance reasons.
 *
 * Delegating all the heavy work to the cons() has the advantage that the only
 * new inter-thread interactions are prod1->cons1 and prod2->cons2; these can
 * be implemented by lockless and barrier-less mailboxes. Since writes into the
 * mailbox are rare, the consumer can bring it into its local cache and poll it
 * as often as needed, without incurring too much of a performance hit.
 *
 */

/* the arp table is implemented as a sparse array indexed by
 * the host part of the ip address.
 *
 * The array is in virtual memory (mmap) and is left uninitialized, so that the
 * kernel will allocate and zero-fill pages on demand.  The ether_addr is
 * stored in negated form and therefore it is always valid: uninitialized
 * entries will give the broadcast address.  A new arp request will be sent
 * when 'now' is after 'next_req'. The initial zero value of 'next_req' will
 * trigger an arp request the first time the entry is read.
 */
struct arp_table_entry {
	uint64_t	next_req;	/* when to send next arp request */
	union {
		uint8_t		ether_addr[6 + 2]; /* size + padding */
		struct {
			uint32_t eth1;
			uint16_t eth2;
			uint16_t pad;
		};
	};
} __attribute__((packed));

void
arp_table_entry_dump(int idx, struct arp_table_entry *e)
{
    ED("%d: next %" PRIu64 " addr %02x:%02x:%02x:%02x:%02x:%02x",
            idx, e->next_req,
            (uint8_t)~e->ether_addr[0],
            (uint8_t)~e->ether_addr[1],
            (uint8_t)~e->ether_addr[2],
            (uint8_t)~e->ether_addr[3],
            (uint8_t)~e->ether_addr[4],
            (uint8_t)~e->ether_addr[5]);
}

struct arp_table_entry *
arp_table_new(in_addr_t mask)
{
    // XXX this only works if mask is in CIDR form */
    size_t s = (~ntohl(mask) + 1) * sizeof(struct arp_table_entry);
    struct arp_table_entry *e;
    ED("allocating %zu bytes for arp table", s);
    e = mmap(NULL, s, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (e == MAP_FAILED)
        return NULL;
    return e;
}

static inline int
arp_idx(in_addr_t addr, in_addr_t mask)
{
    return ntohl(addr & ~mask);
}


/* arp commands are sent by the producer to the consumer that insists on
 * the same port. The commands are sent when the producer receives an ARP
 * message, as follows:
 * - when an ARP request is received, ask the consumer to send an ARP
 *   reply
 * - when an ARP reply is received, ask the consumer to update its
 *   ARP table
 * The commands also contain the ethernet and IP address of the sender
 * of the received ARP message.
 */
struct arp_cmd {
	union {
		uint8_t		ether_addr[6];
		struct {
			uint32_t eth1;
			uint16_t eth2;
		};
	};
	uint8_t		valid; /* 0: empty, 1: new, 2: seen */
	uint8_t		cmd;   /* ARPOP_REQUEST or ARPOP_REPLY */
	in_addr_t	ip_addr;
	uint8_t		pad[4];
} __attribute__((packed));

/* the commands are sent in a small mailbox shared between the producer and the
 * consumer. The head and tail pointers are not shared, and the synchronization
 * is enforced by the 'valid' fields inside the commands themselves.  This
 * saves some cache misses and eliminates the need for memory barriers.
 */
#define ARP_CMD_QSIZE 16
struct arp_cmd_q {
	struct arp_cmd	q[ARP_CMD_QSIZE] ALIGN_CACHE;
	uint64_t	head ALIGN_CACHE; /* private to the consumer */
	uint64_t	toclean;	  /* private to the consumer */
	uint64_t	tail ALIGN_CACHE; /* private to the producer */
};

/* consumer: extract a new command.  The command slot is not immediately
 * released, so that at most ARP_CMD_QSIZE messages are read for each
 * cons() loop.
 */
static inline struct arp_cmd *
arpq_get_cmd(struct arp_cmd_q *a)
{
    int h = a->head & (ARP_CMD_QSIZE - 1);
    if (unlikely(a->q[h].valid == 1)) {
        a->q[h].valid = 2; /* mark as seen */
        a->head++;
        return &a->q[h];
    }
    return NULL;
}

/* consumer: release all seen slots */
static inline void
arpq_release(struct arp_cmd_q *a)
{
    int c = a->toclean & (ARP_CMD_QSIZE - 1);
    if (likely(a->q[c].valid != 2))
        return;
    while (a->q[c].valid == 2) {
        a->q[c].valid = 0;
        a->toclean++;
	c = a->toclean & (ARP_CMD_QSIZE - 1);
    }
}

struct arp_cmd *
arpq_new_cmd(struct arp_cmd_q *a)
{
    int t = a->tail & (ARP_CMD_QSIZE - 1);
    struct arp_cmd *c = &a->q[t];

    return (c->valid ? NULL : c);
}

void
arpq_push(struct arp_cmd_q *a, struct arp_cmd *c)
{
    c->valid = 1;
    a->tail++;
}

static inline int
is_arp(const void *pkt)
{
    const struct ether_header *h = pkt;
    return h->ether_type == htons(ETHERTYPE_ARP);
}

struct arp_cmd_q arpq[2];

/* IPv4 info for a port. Shared between the producer and the consumer that
 * insist on the same port
 */
struct ipv4_info {
	char		name[IFNAMSIZ + 1];
	in_addr_t	ip_addr;
	in_addr_t	ip_mask;
	in_addr_t	ip_subnet;
	in_addr_t	ip_bcast;
	in_addr_t	ip_gw;
	union {
		struct {
		    uint8_t  pad1[2];
		    uint8_t  ether_addr[6];
		};
		struct {
		    uint16_t pad2;
		    uint16_t eth1;
		    uint32_t eth2;
		};
	};
	/* pre-formatted arp messages */
	union {
		uint8_t pkt[60];
		struct {
			struct ether_header eh;
			struct ether_arp    ah;
		} arp __attribute__((packed));
	} arp_reply, arp_request;

	struct arp_table_entry *arp_table;
};

void
ipv4_dump(const struct ipv4_info *i)
{
    const uint8_t *ipa = (uint8_t *)&i->ip_addr,
          *ipm = (uint8_t *)&i->ip_mask,
          *ipb = (uint8_t *)&i->ip_bcast,
          *ipc = (uint8_t *)&i->ip_gw,
          *ea = i->ether_addr;

    ED("%s: ip %u.%u.%u.%u/%u.%u.%u.%u bcast %u.%u.%u.%u gw %u.%u.%u.%u mac %02x:%02x:%02x:%02x:%02x:%02x",
            i->name,
            ipa[0], ipa[1], ipa[2], ipa[3],
            ipm[0], ipm[1], ipm[2], ipm[3],
            ipb[0], ipb[1], ipb[2], ipb[3],
            ipc[0], ipc[1], ipc[2], ipc[3],
            ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);
}

struct ipv4_info ipv4[2];

static void usage();
void
route_mode_init(const char *ifname[], const char *gateways[])
{
    int fd, i;
    struct ifreq ifr;
#ifdef __FreeBSD__
    struct ifaddrs *ifap, *p;

    if (getifaddrs(&ifap) < 0) {
	ED("failed to get interface list: %s", strerror(errno));
	usage();
    }
#endif /* __FreeBSD__ */

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0) {
	ED("failed to open SOCK_DGRAM socket: %s", strerror(errno));
	usage();
    }

    for (i = 0; i < 2; i++) {
	struct ipv4_info *ip = &ipv4[i];
	char *dst = ip->name;
	const char *scan;
	struct ether_header *eh;
	struct ether_arp *ah;
	void *hwaddr = NULL;

	/* try to extract the port name */
	if (!strncmp("vale", ifname[i], 4)) {
	    ED("route mode not supported for VALE port %s", ifname[i]);
	    usage();
	}
	if (strncmp("netmap:", ifname[i], 7)) {
	    ED("missing netmap: prefix in %s", ifname[i]);
	    usage();
	}
	scan = ifname[i] + 7;
	if (strlen(scan) >= IFNAMSIZ) {
	    ED("name too long: %s", scan);
	    usage();
	}
	while (*scan && isalnum(*scan))
	    *dst++ = *scan++;
	*dst = '\0';
	ED("trying to get configuration for %s", ip->name);

	/* MAC address */
#ifdef linux
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ip->name);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0) {
	    hwaddr = ifr.ifr_addr.sa_data;
	}
#elif defined (__FreeBSD__)
	errno = ENOENT;
	for (p = ifap; p; p = p->ifa_next) {

	    if (!strcmp(p->ifa_name, ip->name) &&
		    p->ifa_addr != NULL &&
		    p->ifa_addr->sa_family == AF_LINK)
	    {
		struct sockaddr_dl *sdp =
		    (struct sockaddr_dl *)p->ifa_addr;
		hwaddr = sdp->sdl_data + sdp->sdl_nlen;
		break;
	    }
	}
#endif /* __FreeBSD__ */
	if (hwaddr == NULL) {
	    ED("failed to get MAC address for %s: %s",
		    ip->name, strerror(errno));
	    usage();
	}
	memcpy(ip->ether_addr, hwaddr, 6);

#define get_ip_info(_c, _f, _m) 						\
	memset(&ifr, 0, sizeof(ifr));						\
	strcpy(ifr.ifr_name, ip->name);						\
	ifr.ifr_addr.sa_family = AF_INET;					\
	if (ioctl(fd, _c, &ifr) < 0) {						\
	    ED("failed to get IPv4 " _m " for %s: %s",				\
		    ip->name, strerror(errno));					\
	    usage();								\
	}									\
	memcpy(&ip->_f, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);	\


	/* IP address */
	get_ip_info(SIOCGIFADDR, ip_addr, "address");
	/* netmask */
	get_ip_info(SIOCGIFNETMASK, ip_mask, "netmask");
	/* broadcast */
	get_ip_info(SIOCGIFBRDADDR, ip_bcast, "broadcast");
#undef get_ip_info

	/* do we have an IP address? */
	if (ip->ip_addr == 0) {
	    ED("no IPv4 address found for %s", ip->name);
	    usage();
	}

	/* cache the subnet */
	ip->ip_subnet = ip->ip_addr & ip->ip_mask;

	/* default gateway, if any */
	if (gateways[i]) {
	    const char *gw = gateways[i];
	    struct ipv4_info *ip = &ipv4[i];
	    struct in_addr a;
	    if (!inet_aton(gw, &a)) {
		ED("not a valid IP address: %s", gw);
		usage();
	    }
	    if ((a.s_addr & ip->ip_mask) != ip->ip_subnet) {
		ED("gateway %s unreachable", gw);
		usage();
	    }
	    ip->ip_gw = a.s_addr;
	}

	ipv4_dump(ip);

	/* precompute the arp reply for this interface */
	eh = &ip->arp_reply.arp.eh;
	ah = &ip->arp_reply.arp.ah;
	memset(&ip->arp_reply, 0, sizeof(ip->arp_reply));
	memcpy(eh->ether_shost, ip->ether_addr, 6);
	eh->ether_type = htons(ETHERTYPE_ARP);
	ah->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	ah->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	ah->ea_hdr.ar_hln = 6;
	ah->ea_hdr.ar_pln = 4;
	ah->ea_hdr.ar_op = htons(ARPOP_REPLY);
	memcpy(ah->arp_sha, ip->ether_addr, 6);
	memcpy(ah->arp_spa, &ip->ip_addr, 4);

	/* precompute the arp request for this interface */
	eh = &ip->arp_request.arp.eh;
	ah = &ip->arp_request.arp.ah;
	memcpy(&ip->arp_request, &ip->arp_reply,
		sizeof(ip->arp_reply));
	memset(eh->ether_dhost, 0xff, 6);
	ah->ea_hdr.ar_op = htons(ARPOP_REQUEST);

	/* allocate the arp table */
	ip->arp_table = arp_table_new(ip->ip_mask);
	if (ip->arp_table == NULL) {
	    ED("failed to allocate the arp table for %s: %s", ip->name,
		    strerror(errno));
	    usage();
	}
    }

    close(fd);
#ifdef __FreeBSD__
    freeifaddrs(ifap);
#endif /* __FreeBSD__ */
}

struct pipe_args {
	int		zerocopy;
	int		wait_link;
	int		route_mode;
	int		hugepages;

	pthread_t	cons_tid;	/* main thread */
	pthread_t	prod_tid;	/* producer thread */

	/* Affinity: */
	int		cons_core;	/* core for cons() */
	int		prod_core;	/* core for prod() */

	struct nmport_d *pa;		/* netmap descriptor */
	struct nmport_d *pb;

	/* route-mode */
	struct arp_cmd_q *cons_arpq;	/* out mailbox for cons */
	struct arp_cmd_q *prod_arpq;	/* in mailbox for prod */
	struct ipv4_info *cons_ipv4;	/* mac addr etc. */
	struct ipv4_info *prod_ipv4;	/* mac addr etc. */

	/* raw stats */
	struct stats	*stats;

#ifdef WITH_MAX_LAG
	/* max delay before the consumer starts dropping packets */
	int64_t		max_lag;
#endif /* WITH_MAX_LAG */

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
    int error;
    int maxprio;

    if (i == -1)
        return 0;

    /* Set thread affinity affinity.*/
    CPU_ZERO(&cpumask);
    CPU_SET(i, &cpumask);

    if ( (error = pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpumask)) != 0) {
        ED("Unable to set affinity to cpu %d: %s", i, strerror(error));
    }
    if (setpriority(PRIO_PROCESS, 0, -10)) {; // XXX not meaningful
        ED("Unable to set priority: %s", strerror(errno));
    }
    maxprio = sched_get_priority_max(SCHED_RR);
    if (maxprio < 0) {
        ED("Unable to retrieve max RR priority, using 10");
        maxprio = 10;
    }
    bzero(&p, sizeof(p));
    p.sched_priority = maxprio;
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
            RD(1, "too many bytes queued %llu, drop %llu",
                    (unsigned long long)q->prod_queued, (unsigned long long)q->txstats->drop_packets);
            return 1;
        }
    }

    if ((h <= t && new_t == 0 && h == 0) || (h > t && (new_t == 0 || new_t >= h)) ) {
        h = q->prod_head = q->head; /* re-read head, just in case */
        /* repeat the test */
        if ((h <= t && new_t == 0 && h == 0) || (h > t && (new_t == 0 || new_t >= h)) ) {
            ND(1, "no room for insert h %lld t %lld new_t %lld",
                    (long long)h, (long long)t, (long long)new_t);
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
    char *dst = (char *)(p + 1);
    unsigned int len = q->cur_frags[0].len;
    int i;

    /* hopefully prefetch has been done ahead */
    nm_pkt_copy(q->cur_pkt, dst, len);
    /* copy the fragments, if any */
    for (i = 1; i < q->cur_nfrags; i++) {
        dst += len;
        len = q->cur_frags[i].len;
        /* we cannot use nm_pkt_copy, since dst may be unaligned */
        memcpy(dst, q->cur_frags[i].buf, len);
    }
    p->pktlen = q->cur_len;
    p->pt_qout = q->qt_qout;
    p->pt_tx = q->qt_tx - q->cur_tt;
    ND(1, "enqueue len %d at %d new tail %ld qout %ld tx %ld",
            q->cur_len, (int)q->prod_tail, p->next,
            p->pt_qout, p->pt_tx);
    q->prod_tail = p->next;
    if (q->qsize)
        q->prod_queued += p->pktlen;
    /* XXX update timestamps ? */
    return 0;
}


static inline int
hold_update_release(struct _qs *q)
{
    if (q->hold_release)
        return 1;
    if (q->hold_next_rt && ts_cmp(q->hold_next_rt, q->prod_now) <= 0) {
        q->hold_release = 1;
        return 1;
    }
    return 0;
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
    ec_checkactive(q);
    while (!do_abort) {
        if (hold_update_release(q))
            break;
        n0 = nm_ring_space(q->rxring);
        if (n0 > (int)q->rx_qmax) {
            q->rx_qmax = n0;
        }
        if (n0)
            break;
        prev = 0; /* we slept */
        usleep(5);
        ioctl(q->src_port->fd, NIOCRXSYNC, 0);
        ec_checkactive(q);
        set_tns_now(&q->prod_now, q->t0);
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
    struct netmap_ring *rxr = q->rxring;
    int nfrags;

    if (likely(next != 0)) {
        /* advance */
        rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
        if (nm_ring_empty(rxr)) /* no more packets */
            return;
    }
    rs = &rxr->slot[rxr->cur];
    /* netmap makes sure that we do not receive incomplete packets */
    nfrags = 0;
    q->cur_len = 0;
    do {
        struct _frag *f = &q->cur_frags[nfrags];
        f->buf = NETMAP_BUF(rxr, rs->buf_idx);
        f->len = rs->len;
        q->cur_len += f->len;
        nfrags++;
        if (!(rs->flags & NS_MOREFRAG))
            break;
        rxr->cur = nm_ring_next(rxr, rxr->cur);
        rs = &rxr->slot[rxr->cur];
    } while (nfrags < MAX_FRAGS);
    q->cur_pkt = q->cur_frags[0].buf;
    q->cur_nfrags = nfrags;
    rxr->head = rxr->cur;
    //prefetch_packet(rxr, 1); not much better than prefetching q->cur_pkt, one line
    __builtin_prefetch(q->cur_pkt);
    __builtin_prefetch(rs+1); /* one row ahead ? */
    ND(10, "-------- slot %d tail %d len %d buf %p", rxr->cur, rxr->tail, q->cur_len, q->cur_pkt);
}

/*
 * Packet reordering.
 *
 * Packets subject to reordering are hold in a separate FIFO queue,
 * local to the producer thread. Note that cur_hold_delay may then be
 * increased to make sure that no further reording is necessary
 * in the FIFO.
 *
 * Once out of the queue, the hold packets reenter the stream
 * and go through the normal processing.
 */

static inline void
reorder_hold(struct _qs *q)
{
    struct h_pkt *nh;

    nh = (struct h_pkt *)(q->hold_buf + q->hold_tail);
    nm_pkt_copy(q->cur_pkt, (char *)(nh + 1), q->cur_len);
    nh->pktlen = q->cur_len;
    nh->releasetime = q->cur_hold_delay;
    if (!q->hold_next_rt) {
        q->hold_next_rt = nh->releasetime;
    } else {
        /* not empty, prevent further reordering */
        if (nh->releasetime < q->hold_tail_rt)
            nh->releasetime = q->hold_tail_rt;
    }
    q->hold_tail_rt = nh->releasetime;
    q->hold_tail += sizeof(*nh) + nh->pktlen;
    if (unlikely(q->hold_tail >= q->hold_buflen))
        q->hold_tail = 0;
}

static int
reorder_release(struct _qs *q)
{
    struct h_pkt *h;
    if (!q->hold_release)
        return 0;
    h = (struct h_pkt *)(q->hold_buf + q->hold_head);
    q->cur_pkt = q->hold_buf + q->hold_head + sizeof(*h);
    q->cur_len = h->pktlen;
    q->cur_frags[0].buf = q->cur_pkt;
    q->cur_frags[0].len = q->cur_len;
    q->cur_nfrags = 1;
    q->hold_head += sizeof(*h) + q->cur_len;
    if (unlikely(q->hold_head >= q->hold_buflen))
        q->hold_head = 0;
    q->hold_release = 0;
    if (q->hold_head != q->hold_tail) {
        h = (struct h_pkt *)(q->hold_buf + q->hold_head);
        q->hold_next_rt = h->releasetime;
        if (ts_cmp(q->hold_next_rt, q->prod_now) < 0)
            q->hold_release = 1;
    } else {
        q->hold_next_rt = 0;
    }
    return 1;
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
    int drop = q->cur_drop;
    q->cur_drop = 0;
    return drop;
}

/* poducer: send the proper command depending on the contents of the received
 * ARP message in pkt
 */
void
prod_push_arp(const struct pipe_args *pa, const void *pkt)
{
    const struct ether_header *eh = pkt;
    const struct ether_arp *arp = (const struct ether_arp *)(eh + 1);
    const struct ipv4_info *ip = pa->prod_ipv4;
    struct arp_cmd_q *a = pa->prod_arpq;
    struct arp_cmd *c;
    in_addr_t ip_saddr, ip_taddr;
    uint16_t arpop = ntohs(arp->ea_hdr.ar_op);

    memcpy(&ip_saddr, arp->arp_spa, 4);
    memcpy(&ip_taddr, arp->arp_tpa, 4);
    if (ip_taddr != ip->ip_addr ||
            ((ip_saddr & ip->ip_mask) != ip->ip_subnet) ||
            (arpop != ARPOP_REQUEST && arpop != ARPOP_REPLY)) {
        /* not for us, drop */
        return;
    }
    c = arpq_new_cmd(a);
    if (c == NULL) {
        /* no space left in the mailbox */
        return;
    }
    c->cmd = arpop; /* just the low byte */
    memcpy(c->ether_addr, arp->arp_sha, 6);
    c->ip_addr = ip_saddr;
    arpq_push(a, c);
}

static void
prod_procpkt(struct _qs *q)
{
    uint64_t t_tx, tt;	/* output and transmission time */

    q->c_imp[I_LOSS].run(q, &q->c_imp[I_LOSS]);
    if (q->cur_drop) {
        q->txstats->drop_packets++;
        q->txstats->drop_bytes += q->cur_len;
        return;
    }
    if (no_room(q)) {
        q->tail = q->prod_tail; /* notify */
        usleep(1); // XXX give cons a chance to run ?
        set_tns_now(&q->prod_now, q->t0);
        if (no_room(q)) {/* try to run drop-free once */
            q->txstats->drop_packets++;
            q->txstats->drop_bytes += q->cur_len;
            return;
        }
    }
    // XXX possibly implement c_tt for transmission time emulation
    q->c_imp[I_BW].run(q, &q->c_imp[I_BW]);
    tt = q->cur_tt;
    q->qt_qout += tt;
    if (drop_after(q)) {
	q->qt_qout -= tt;
        q->txstats->drop_packets++;
        q->txstats->drop_bytes += q->cur_len;
        return;
    }
    if (!q->reuse_delay) {
        q->c_imp[I_DELAY].run(q, &q->c_imp[I_DELAY]); /* compute delay */
        if (q->delay_offset > q->cur_delay) {
            q->cur_delay = 0;
        } else {
            q->cur_delay -= q->delay_offset;
        }
    }
    t_tx = q->qt_qout + q->cur_delay;
    ND(5, "tt %ld qout %ld tx %ld qt_tx %ld", tt, q->qt_qout, t_tx, q->qt_tx);
    /* insure no reordering and spacing by transmission time */
    if (t_tx < q->qt_tx + tt) {
        q->reuse_delay = 1;
        if (q->allow_drop) {
            q->qt_qout -= tt;
            q->txstats->drop_packets++;
            q->txstats->drop_bytes += q->cur_len;
            return;
        }
        t_tx = q->qt_tx + tt;
    } else {
        q->reuse_delay = 0;
    }
    q->qt_tx = t_tx;
    enq(q);
    q->txstats->packets++;
    q->txstats->bytes += q->cur_len;
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

        for (count = 0; count < q->burst && reorder_release(q); count++) {
            prod_procpkt(q);
        }
        // XXX optimize to flush frequently
        for (scan_ring(q, 0); count < q->burst && !nm_ring_empty(q->rxring);
                count++, scan_ring(q, 1)) {
            if (q->cur_len < 60) {
                RD(5, "short packet len %d", q->cur_len);
                continue; // short frame
            }
            if (pa->route_mode && unlikely(is_arp(q->cur_pkt))) {
                /* pass it to the consumer in the other direction */
                prod_push_arp(pa, q->cur_pkt);
                continue;
            }
            q->c_imp[I_REORDER].run(q, &q->c_imp[I_REORDER]);
            if (q->cur_hold_delay) {
                q->cur_hold_delay += q->prod_now;
                q->txstats->reorder_packets++;
                q->txstats->reorder_bytes += q->cur_len;
                reorder_hold(q);
                continue;
            }
            prod_procpkt(q);
        }
        q->tail = q->prod_tail; /* notify */
    }
    D("exiting on abort");
    return NULL;
}

/* react to a command sent by the producer in the other direction.
 * returns the number of packets injected.
 */
int
cons_handle_arp(struct pipe_args *pa, struct arp_cmd *c)
{
    struct ipv4_info *ip = pa->cons_ipv4;
    struct ether_header *eh = &ip->arp_reply.arp.eh;
    struct ether_arp *ah = &ip->arp_reply.arp.ah;
    struct arp_table_entry *e;
    int rv = 0;

    switch (c->cmd) {
        case ARPOP_REQUEST:
            /* send reply */
            memcpy(eh->ether_dhost, c->ether_addr, 6);
            memcpy(ah->arp_tha, c->ether_addr, 6);
            memcpy(ah->arp_tpa, &c->ip_addr, 4);
            if (nmport_inject(pa->pb, eh, sizeof(ip->arp_reply)) == 0) {
                RD(1, "failed to inject arp reply");
                break;
            }
            /* force the reply out */
            rv = pa->q.burst;
            break;
        case ARPOP_REPLY:
            e = ip->arp_table + arp_idx(c->ip_addr, ip->ip_mask);
            set_tns_now(&e->next_req, pa->q.cons_now);
            e->next_req += 5000000000;
            e->eth1 = ~c->eth1;
            e->eth2 = ~c->eth2;
            break;
        default:
            /* we don't handle these ones */
            RD(1, "unknown/unsupported ARP operation: %x", c->cmd);
            break;
    }
    return rv;
}

/* change the ethernet target address according to the local ARP table
 * and set the source address to the local MAC.
 * may send an ARP request.
 * returns the number of packets injected, or < 0 if the packet
 * needs to be dropped
 */
static inline int
cons_update_macs(struct pipe_args *pa, void *pkt)
{
    struct ether_header *eh = pkt;
    struct ip *iph = (struct ip *)(eh + 1);
    in_addr_t dst = iph->ip_dst.s_addr;
    struct arp_table_entry *e;
    struct ipv4_info *ipv4 = pa->cons_ipv4;
    int idx;
    int injected = 0;
    //uint8_t *d = (uint8_t *)&dst;

    ND("dst %u.%u.%u.%u", d[0], d[1], d[2], d[3]);
    if (unlikely((ntohs(eh->ether_type) < 0x600)))
	return -2; /* ignore 802.3 packets */
    if (unlikely(!(ntohs(eh->ether_type) == ETHERTYPE_IP)))
        return -1; /* drop */
    if (unlikely(dst == ipv4->ip_bcast || dst == 0xffffffff))
        return -1; /* drop */
    if ((dst & ipv4->ip_mask) != ipv4->ip_subnet) {
        if (ipv4->ip_gw) {
            /* send to the default gateway */
            dst = ipv4->ip_gw;
        } else {
            return -1; /* drop */
        }
    }
    idx = arp_idx(dst, ipv4->ip_mask);
    e = ipv4->arp_table + idx;
    ND("idx %d e %p", idx, e);
    //arp_table_entry_dump(idx, e);
    if (unlikely(ts_cmp(pa->q.cons_now, e->next_req) > 0)) {
        /* send arp request for this client */
        struct ether_arp *ah = &ipv4->arp_request.arp.ah;
        ND("sending arp request");
        memcpy(ah->arp_tpa, &dst, 4);
        set_tns_now(&e->next_req, pa->q.cons_now);
        e->next_req += 5000000000; /* 5s */
        if (nmport_inject(pa->pb, &ipv4->arp_request,
                    sizeof(ipv4->arp_request)) == 0) {
            RD(1, "failed to inject arp request");
        } else {
            injected = 1;
        }
    }
    /* copy negated dst into eh (either broadcast or unicast) */
    *(uint32_t *)eh = ~e->eth1;
    *(uint16_t *)((char *)eh + 4) = ~e->eth2;
    /* copy local MAC address into source */
    *(uint16_t *)((char *)eh + 6) = ipv4->eth1;
    *(uint32_t *)((char *)eh + 8) = ipv4->eth2;
    return injected;
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
    int pending = 0, retrying = 0;
#if 0
    int cycles = 0;
    const char *pre_start, *pre_end; /* prefetch limits */

    /*
     * prefetch about 2k ahead of the current pointer
     */
    pre_start = q->buf + q->head;
    pre_end = pre_start + 2048;
    (void)cycles; // XXX disable warning
#endif

    set_tns_now(&q->cons_now, q->t0);
    while (!do_abort) { /* consumer, infinite */
        uint64_t h = q->head; /* read only once */
        uint64_t t = q->tail; /* read only once */
        struct q_pkt *p = (struct q_pkt *)(q->buf + h);
        struct arp_cmd *arpc;
        int64_t delta;
#if 0
        struct q_pkt *p = (struct q_pkt *)(q->buf + q->head);
        if (p->next < q->head) { /* wrap around prefetch */
            pre_start = q->buf + p->next;
        }
        pre_end = q->buf + p->next + 2048;
        //#if 1
        /* prefetch the first line saves 4ns */
        (void)pre_end;//   __builtin_prefetch(pre_end - 2048);
        //#else
        /* prefetch, ideally up to a full packet not just one line.
         * this does not seem to have a huge effect.
         * 4ns out of 198 on 1500 byte packets
         */
        for (; pre_start < pre_end; pre_start += 64)
            __builtin_prefetch(pre_start);
#endif
        if (pa->route_mode) {
            while (unlikely(arpc = arpq_get_cmd(pa->cons_arpq))) {
                // uint8_t *ip_addr = (uint8_t *)&arpc->ip_addr;
                ND("arp %x ether %02x:%02x:%02x:%02x:%02x:%02x ip %u.%u.%u.%u",
                        arpc->cmd,
                        arpc->ether_addr[0],
                        arpc->ether_addr[1],
                        arpc->ether_addr[2],
                        arpc->ether_addr[3],
                        arpc->ether_addr[4],
                        arpc->ether_addr[5],
                        ip_addr[0],
                        ip_addr[1],
                        ip_addr[2],
                        ip_addr[3]);
                pending += cons_handle_arp(pa, arpc);
            }
            arpq_release(pa->cons_arpq);
        }
        if ( h == t || (delta = ts_cmp(p->pt_tx, q->cons_now) ) > 0) {
            ND(4, "                 >>>> TXSYNC, pkt not ready yet h %ld t %ld now %ld tx %ld",
                    h, t, q->cons_now, p->pt_tx);
            q->rx_wait++;
            if (pending > 0) {
                /* this also sends any pending arp messages from this or
                 * previous loop iterations
                 */
                ioctl(pa->pb->fd, NIOCTXSYNC, 0);
                pending = 0;
            } else {
                usleep(5);
            }
            set_tns_now(&q->cons_now, q->t0);
            continue;
        }
#ifdef WITH_MAX_LAG
        if (delta < -pa->max_lag) {
            q->rxstats->drop_packets++;
            q->rxstats->drop_bytes += p->pktlen;
            goto next;
        }
#endif /* WITH_MAX_LAG */
        ND(5, "drain len %ld now %ld tx %ld h %ld t %ld next %ld",
                p->pktlen, q->cons_now, p->pt_tx, h, t, p->next);
        if (pa->route_mode && !retrying) {
            int injected = cons_update_macs(pa, p + 1);
            if (unlikely(injected < 0)) {
                /* drop this packet. Any pending arp message
                 * will be sent in the next iteration
                 */
		if (injected == -1) {
		    q->rxstats->drop_packets++;
		    q->rxstats->drop_bytes += p->pktlen;
		}
                goto next;
            }
            pending += injected;
        }
        /* XXX inefficient but simple */
        if (nmport_inject(pa->pb, (char *)(p + 1), p->pktlen) == 0) {
            ND(5, "inject failed len %d now %ld tx %ld h %ld t %ld next %ld",
                    (int)p->pktlen, q->cons_now, p->pt_tx, h, t, p->next);
            ioctl(pa->pb->fd, NIOCTXSYNC, 0);
            set_tns_now(&q->cons_now, q->t0);
            pending = 0;
            retrying = 1;
            continue;
        }
        retrying = 0;
        pending++;
        if (pending > q->burst) {
            ioctl(pa->pb->fd, NIOCTXSYNC, 0);
            pending = 0;
        }

        q->rxstats->packets++;
        q->rxstats->bytes += p->pktlen;
next:
        q->head = p->next;
        /* drain packets from the queue */
        // XXX barrier
    }
    D("exiting on abort");
    return NULL;
}

static uint64_t get_bufsize(uint64_t max_bps, uint64_t max_delay, uint64_t qsize, size_t hdrsz)
{
    double need;

    /* allocate space for the queue:
     * compute required bw*delay (adding 1ms for good measure),
     * then add the queue size in bytes, then account for the headers
     * and the packet expansion for padding
     */

    need = max_bps ? max_bps : INFINITE_BW;
    need *= max_delay + 1000000;	/* delay is in nanoseconds */
    need /= TIME_UNITS; /* total bits */
    need /= 8; /* in bytes */
    need += qsize; /* in bytes */
    need += 3 * MAX_PKT; // safety
    need *= (1 + 1.0 * (hdrsz + PKT_PAD) / 64);
    return need;
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
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    char b1[40], b2[40] = "0";

    setaffinity(a->cons_core);
    set_tns_now(&q->t0, 0); /* starting reference */

    if (a->hugepages) {
        mmap_flags |= MAP_HUGETLB;
    }

    a->zerocopy = a->zerocopy && (a->pa->mem == a->pb->mem);
    ND("------- zerocopy %ssupported", a->zerocopy ? "" : "NOT ");

    need = get_bufsize(q->ec->max_bps, q->ec->max_delay,
            q->qsize, sizeof(struct q_pkt));
    norm(b1, need, 1);

retry:
    q->buf = mmap(0, need, PROT_WRITE | PROT_READ, mmap_flags, -1, 0);
    if (q->buf == MAP_FAILED) {
        ED("alloc %s bytes for queue failed, exiting", b1);
        if (mmap_flags & MAP_HUGETLB && a->hugepages < 2) {
            ED("trying again without hugepages");
            mmap_flags &= ~MAP_HUGETLB;
            goto retry;
        }
        nmport_close(a->pa);
        nmport_close(a->pb);
        do_abort = 1;
        return(NULL);
    }
    if (mlock(q->buf, need) < 0) {
        ED("(not fatal) failed to pin buffer memory: %s", strerror(errno));
    }
    q->buflen = need;

    if (q->ec->max_hold_delay) {
        need = get_bufsize(q->ec->max_bps, q->ec->max_hold_delay,
                0, sizeof(struct h_pkt));
        norm(b2, need, 1);

retry2:
        q->hold_buf = mmap(0, need, PROT_WRITE | PROT_READ, mmap_flags, -1, 0);
        if (q->hold_buf == MAP_FAILED) {
            ED("alloc %s bytes for hold-buf failed, exiting", b2);
            if (mmap_flags & MAP_HUGETLB) {
                ED("trying again without hugepages");
                mmap_flags &= ~MAP_HUGETLB;
                goto retry2;
            }
            nmport_close(a->pa);
            nmport_close(a->pb);
            do_abort = 1;
            return(NULL);
        }
        if (mlock(q->hold_buf, need) < 0) {
            ED("(not fatal) failed to pin hold buffer memory: %s", strerror(errno));
        }
        q->hold_buflen = need - (sizeof(struct h_pkt) + MAX_PKT);
    }

    ED("----\n\t%s -> %s :  bps %lld delay %s loss %s reorder %s queue %lld bytes"
            "\n\tbuffer   %s bytes\n\thold-buf %s bytes",
            q->prod_ifname, q->cons_ifname,
            (long long)q->ec->max_bps, q->c_imp[I_DELAY].optarg, q->c_imp[I_LOSS].optarg,
	    q->c_imp[I_REORDER].optarg,
            (long long)q->qsize, b1,
            b2);


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
            "\t[-b burst] [-w wait_time] [-G gateway] -i ifa -i ifb\n");
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
    if (verbose > 2)
        for (i = 0; i < ac; i++) fprintf(stderr, "%d: <%s>\n", i, av[i]);
    av[ac] = NULL;
    av[ac+1] = my;
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
        return 0; /* no argument may be ok */
    if (a == NULL || dst == NULL) {
        ED("program error - invalid arguments");
        exit(1);
    }
    if (!strcmp(arg, "none")) {
        dst->ec->ec_valid = 0; /* use default */
        return 0;
    }
    av = split_arg(arg, &ac);
    if (av == NULL)
        goto out; /* error */
    for (i = 0; a[i].parse; i++) {
        struct _cfg x = a[i];
        const char *errmsg = x.optarg;
        int ret;

        x.arg = NULL;
        x.ec = dst->ec;
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
        dst->ec->ec_index = i;
        dst->ec->ec_valid = 1;
        return 0;
    }
    ED("arguments %s not recognised", arg);
    free(av);
out:
    dst->ec->ec_valid = 0;
    return 1;
}

static struct _cfg delay_cfg[];
static struct _cfg bw_cfg[];
static struct _cfg loss_cfg[];
static struct _cfg reorder_cfg[];

static uint64_t parse_bw(const char *arg);
static uint64_t parse_qsize(const char *arg);

/*
 * tlem [options]
 * accept separate sets of arguments for the two directions
 *
 */

static void
add_to(const char ** v, int l, const char *arg, char opt)
{
    for (; l > 0 && *v != NULL ; l--, v++);
    if (l == 0) {
        ED("-%c too many times: %s", opt, arg);
        exit(1);
    }
    *v = arg;
}

#define U_PARSE_ERR ~(0ULL)

static uint64_t parse_time(const char *arg); // forward

/* set the maximum values for delay, bw and hold-time */
static int
set_max(const char *arg, struct _qs *q)
{
    int ac = 0;
    char **av;
    uint64_t delay = 0, bps = 0, hold = 0;

    if (arg == NULL)
        return 0;

    av = split_arg(arg, &ac);
    if (av == NULL || ac < 1 || ac > 3) {
        ND("arg %p av %p ac %d", arg, av, ac);
        ED("invalid parameters for -M: need max-delay[,max-bps[,max-hold-time]]]");
        return 1;
    }
    /* first argument: max delay */
    delay = parse_time(av[0]);
    if (delay == U_PARSE_ERR) {
        ED("invalid max-delay: %s", av[0]);
        return 1;
    }
    if (ac > 1) {
        /* second argument: max bw */
        bps = parse_bw(av[1]);
        if (bps == U_PARSE_ERR) {
            ED("invalid max-bps: %s", av[1]);
            return 1;
        }
	/* if we did not get any bw limitation from -B, use this one */
	if (q->c_imp[I_BW].run == null_run_fn) {
	    if (cmd_apply(bw_cfg, av[1], q, &q->c_imp[I_BW])) {
		ED("warning: failed to set default bandwidth limitation to %s", av[1]);
	    } else {
		ED("set maximum bandwidth to %s", av[1]);
	    }
	}
    }
    if (ac > 2) {
        /* third argument: max hold time */
        hold = parse_time(av[2]);
        if (hold == U_PARSE_ERR) {
            ED("invalid max-hold-time: %s", av[2]);
            return 1;
        }
    }
    if (delay > q->ec->max_delay)
        q->ec->max_delay = delay;
    if (bps > q->ec->max_bps)
        q->ec->max_bps = bps;
    if (hold > q->ec->max_hold_delay)
        q->ec->max_hold_delay = hold;
    return 0;
}

/* options that can be specified for each direction */
struct dir_opt {
    char opt;
    int  flags;
#define DOPT_CLONE  1	/* clone if only one is given */
#define DOPT_IGNOR  2	/* ignore the option */
    const char *arg[EC_NOPTS];
};
#define MAXOPTS 1024
#define DOPT(a, f)  { .opt = a, .flags = f, .arg = { NULL, NULL } }

/* mapping between options and configurations */
struct cfg_opt {
    int opt;
    struct _cfg *c;
};

struct cfg_opt all_cfgs[] = {
    [I_DELAY]	= { 'D', delay_cfg },
    [I_BW]    	= { 'B', bw_cfg },
    [I_LOSS]  	= { 'L', loss_cfg },
    [I_REORDER]	= { 'R', reorder_cfg },
};

int
main(int argc, char **argv)
{
    int ch, i, j, err=0;

    struct pipe_args bp[EC_NOPTS];
    struct dir_opt dopt[] = {
        DOPT('B', DOPT_CLONE), /* bandwidth in bps */
        DOPT('D', DOPT_CLONE), /* delay in seconds (float) */
        DOPT('Q', DOPT_CLONE), /* qsize in bytes */
        DOPT('L', DOPT_CLONE), /* loss probability */
        DOPT('R', DOPT_CLONE), /* reordering */
        DOPT('G', 0),	       /* default gateway */
        DOPT('M', DOPT_CLONE), /* max bw, delay and hold-time */
        DOPT('P', DOPT_CLONE), /* allow dropping to obtain precise delay */
        DOPT('i', 0),	       /* interface */
        DOPT('O', DOPT_CLONE), /* delay offset */
#ifdef WITH_MAX_LAG
        DOPT('d', DOPT_CLONE),
#else
        DOPT('d', DOPT_IGNOR),
#endif /* WITH_MAX_LAG */
        DOPT(0, 0)  /* end of options */
    };
    struct dir_opt *invdopt[256], *scandopt;
    int ncpus;
    int cores[4];
    int hugepages = 0;
    char *sfname = NULL; /* session file name */
    int server = 1, terminate = 0;
    struct _ecf *ecf;
    char doptstr[MAXOPTS], *strp = doptstr;
    const char **ifname;

    nmctx_set_threadsafe();

    bzero(invdopt, sizeof(invdopt));
    for (scandopt = dopt; scandopt->opt; scandopt++) {
        bzero(scandopt->arg, sizeof(scandopt->arg));
        invdopt[(unsigned int)scandopt->opt] = scandopt;
        *strp++ = scandopt->opt;
        *strp++ = ':';
    }
    *strp = '\0';
    ifname = invdopt['i']->arg;

    fprintf(stderr, "%s built %s %s\n", argv[0], __DATE__, __TIME__);

    bzero(&bp, sizeof(bp));	/* all data initially go here */

    for (i = 0; i < EC_NOPTS; i++) {
        struct _qs *q = &bp[i].q;
        uint64_t seed = time(0);
	int j;

        memcpy(q->prod_seed, &seed, sizeof(q->prod_seed));
	for (j = 0; j < I_NUM; j++) {
	    q->c_imp[j].optarg = "0";
	    q->c_imp[j].run = null_run_fn;
	}
    }

    ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus <= 0) {
        ED("failed to get the number of online CPUs: %s",
                strerror(errno));
        cores[0] = cores[1] = cores[2] = cores[3] = 0;
    } else {
        /* try to put prod/cons on two HT of the same core */
        int h = ncpus / 2;
        cores[0] = h / 3;
        cores[1] = cores[0] + h;
        cores[2] = (2 * h) / 3;
        cores[3] = cores[2] + h;
    }

    // Options:
    // B	bandwidth in bps
    // D	delay in seconds
    // Q	qsize in bytes
    // L	loss probability
    // R	reordering probability and delay min/max
    // i	interface name (two mandatory)
    // v	verbose
    // b	batch size
    // r	route mode
    // d	max consumer delay

    strcat(doptstr, "C:b:cvw:rHs:qa");
    while ( (ch = getopt(argc, argv, doptstr)) != -1) {
        switch (ch) {
            case '?':
                ED("unknown option '-%c'", optopt);
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

            case 'b':	/* burst */
                bp[0].q.burst = atoi(optarg);
                break;

            case 'c':
                bp[0].zerocopy = 0; /* do not zerocopy */
                break;
            case 'v':
                verbose++;
                break;
            case 'q':
                if (verbose > 0)
                    verbose--;
                break;
            case 'w':
                bp[0].wait_link = atoi(optarg);
                break;
            case 'r':
                bp[0].route_mode = 1;
                break;
            case 'H':
                hugepages++;
                break;
            case 's':
                if (sfname != NULL) {
                    D("option 's' duplicated");
                    usage();
                }
                sfname = optarg;
                break;
            case 'a':
                terminate = 1;
                break;
            default:
                if (invdopt[ch]) {
                    struct dir_opt *o = invdopt[ch];
                    if (!(o->flags & DOPT_IGNOR)) {
                        add_to(o->arg, EC_NOPTS, optarg, o->opt);
                    } else {
                        ED("option '-%c' ignored", o->opt);
                    }
                } else {
                    ED("unknown option '-%c'", ch);
                }
        }
    }

    argc -= optind;
    argv += optind;

    /* map the session area and auto-detect whether we are server or client */
    ecf = ec_map(sfname, &server);
    if (ecf == NULL)
        exit(1);

    if (terminate)
        goto skip_args;

    /*
     * consistency checks for common arguments
     */
    if (server) {
        if (!ifname[0] || !ifname[1]) {
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

        if (bp[0].route_mode) {
	    const char *gateways[] = { invdopt['G']->arg[0], invdopt['G']->arg[1] };
	    route_mode_init(ifname, gateways);
        }

        bp[1] = bp[0]; /* copy parameters, but swap interfaces */
        bp[0].q.prod_ifname = bp[1].q.cons_ifname = ifname[0];
        bp[1].q.prod_ifname = bp[0].q.cons_ifname = ifname[1];
        bp[0].prod_ipv4 = bp[1].cons_ipv4 = &ipv4[0];
        bp[0].cons_ipv4 = bp[1].prod_ipv4 = &ipv4[1];


        /* assign cores. prod and cons work better if on the same HT */
        bp[0].cons_core = cores[0];
        bp[0].prod_core = cores[1];
        bp[1].cons_core = cores[2];
        bp[1].prod_core = cores[3];
        ED("running on cores %d->%d %d->%d", cores[1], cores[0], cores[3], cores[2]);

    }

    /* use same parameters for both directions if needed */
    for (scandopt = dopt; scandopt->opt; scandopt++) {
        if (!(scandopt->flags & DOPT_CLONE))
            continue;
        if (scandopt->arg[1] == NULL)
            scandopt->arg[1] = scandopt->arg[0];
    }

skip_args:
    /* apply commands */
    j = 0;
    for (i = 0; i < EC_NOPTS; i++) { /* once per queue */
        struct _qs *q = &bp[i].q;
        struct _eci *a;
	int k;

        if (ec_init(q, &ecf->sets[i], server))
            exit(1);
        if (terminate) {
            ec_terminate(&ecf->sets[i]);
            continue;
        }
        a = &q->ec->instances[q->ec_active];
	for (k = 0; k < I_NUM; k++) {
	    err += cmd_apply(all_cfgs[k].c, invdopt[all_cfgs[k].opt]->arg[i], q, &q->c_imp[k]);
	}
#ifdef WITH_MAX_LAG
        if (invdopt['d']->arg[i] != NULL) {
            uint64_t max_lag = parse_time(invdopt[(int)'d']->arg[i]);
            if (max_lag == U_PARSE_ERR) {
                err++;
            } else {
                bp[i].max_lag = max_lag;
            }
        }
#endif /* WITH_MAX_LAG */
        if (invdopt['P']->arg[i] != NULL) {
            const char *p = invdopt['P']->arg[i];
            if (!strcmp(p, "0") || !strcmp(p, "1")) {
                a->ec_allow_drop = atoi(p);
                q->allow_drop = a->ec_allow_drop;
            } else {
                ED("-P expects either 0 or 1");
                err++;
            }
        }
        if (invdopt['O']->arg[i] != NULL) {
            a->ec_delay_offset = parse_time(invdopt['O']->arg[i]);
            q->delay_offset = a->ec_delay_offset;
        }
	if (invdopt['Q']->arg[i] != NULL) {
            a->ec_qsize = parse_qsize(invdopt['Q']->arg[0]);
            q->qsize = a->ec_qsize;
	} else if (invdopt['B']->arg[i] != NULL) {
	    /* we need e small finite queue for bandwidth emulation,
	     * otherwise delay is unbounded
	     */
	    ED("setting qsize to %lluB", (unsigned long long)q->c_imp[I_BW].def_qsize);
	    a->ec_qsize = q->c_imp[I_BW].def_qsize;
	    q->qsize = q->c_imp[I_BW].def_qsize;
	} else {
	    ED("using unlimited qsize");
	    a->ec_qsize = 0;
	    q->qsize = 0; /* infinite */
	}
        bp[i].q.txstats = &ecf->stats[j++];
        bp[i].q.rxstats = &ecf->stats[j++];
    }

    if (terminate) {
        int rv = 0;
        ED("exiting due to -a");
        if (!server)
            rv = ec_waitterminate();
        exit(rv);
    }

    if (err) {
        ED("exiting due to %d error(s)", err);
        exit(1);
    }

    if (server) {
	/* lock everything in core */
	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
	    ED("failed to lock memory: %s", strerror(errno));
	}
        /* set the maximum values */
        for (i = 0; i < EC_NOPTS; i++) {
            if (set_max(invdopt['M']->arg[i], &bp[i].q))
                exit(1);
        }
        /* now the clients may send new configurations */
        if (ec_allowclients())
            exit(1);
    } else {
        for (i = 0; i < EC_NOPTS; i++)
            ec_switchactive(&bp[i].q);
        exit(0);
    }

#ifdef WITH_MAX_LAG
    for (i = 0; i < EC_NOPTS; i++) {
        if (bp[i].max_lag == 0) {
            bp[i].max_lag = 100000; /* 100 us */
        }
    }
#endif /* WITH_MAX_LAG */

    /* assign arp command queues for route mode */
    bp[0].prod_arpq = &arpq[0];
    bp[0].cons_arpq = &arpq[1];
    bp[1].prod_arpq = &arpq[1];
    bp[1].cons_arpq = &arpq[0];

    /* hugepages */
    if (hugepages) {
#ifdef MAP_HUGETLB
        ED("using hugepages");
        bp[0].hugepages = bp[1].hugepages = hugepages;
#else /* !MAP_HUGETLB */
        ED("WARNING: hugepages not supported");
        hugepages = 0;
#endif /* MAP_HUGETLB */
    }

    for (i = 0; i < 2; i++) {
        struct pipe_args *a = &bp[i];

        a->pa = nmport_prepare(a->q.prod_ifname);
        if (a->pa == NULL) {
            D("cannot open %s", a->q.prod_ifname);
            exit(1);
        }
        a->pa->reg.nr_flags |= NETMAP_NO_TX_POLL;
        if (nmport_open_desc(a->pa) < 0) {
            D("cannot open %s", a->q.prod_ifname);
	    exit(1);
        }
	if (a->pa->first_rx_ring != a->pa->last_rx_ring) {
	    D("WARNING: %s has more than one rx ring; only ring %d will be used",
			    a->q.prod_ifname, a->pa->first_rx_ring);
	}
	a->q.rxring = NETMAP_RXRING(a->pa->nifp, a->pa->first_rx_ring);
        a->pb = nmport_open(a->q.cons_ifname);
        if (a->pb == NULL) {
            D("cannot open %s", a->q.cons_ifname);
            exit(1);
        }

    }
    sleep(bp[0].wait_link);

    latency_reduction_start();

    pthread_create(&bp[0].cons_tid, NULL, tlem_main, (void*)&bp[0]);
    pthread_create(&bp[1].cons_tid, NULL, tlem_main, (void*)&bp[1]);

    signal(SIGINT, sigint_h);
    sleep(1);
    while (!do_abort) {
        struct stats old0tx = *bp[0].q.txstats,
                     old0rx = *bp[0].q.rxstats,
                     old1tx = *bp[1].q.txstats,
                     old1rx = *bp[1].q.rxstats;
        struct _qs *q0 = &bp[0].q, *q1 = &bp[1].q;

        sleep(1);
        ED("%lld -> %lld maxq %d round %lld drop %lld/%lld, %lld <- %lld maxq %d round %lld drop %lld/%lld",
                (long long)(q0->rxstats->packets - old0rx.packets),
                (long long)(q0->txstats->packets - old0tx.packets),
                q0->rx_qmax, (long long)q0->prod_max_gap,
                (long long)(q0->txstats->drop_packets - old0tx.drop_packets),
                (long long)(q0->rxstats->drop_packets - old0rx.drop_packets),
                (long long)(q1->rxstats->packets - old1rx.packets),
                (long long)(q1->txstats->packets - old1tx.packets),
                q1->rx_qmax, (long long)q1->prod_max_gap,
                (long long)(q1->txstats->drop_packets - old1tx.drop_packets),
                (long long)(q1->rxstats->drop_packets - old1rx.drop_packets)
          );
        ND("plr nominal %le actual %le",
                (double)(q0->c_loss.d[0])/(1<<24),
                q0->c_loss.d[1] == 0 ? 0 :
                (double)(q0->c_loss.d[2])/q0->c_loss.d[1]);
        bp[0].q.rx_qmax = 0;
        bp[0].q.prod_max_gap = 0;
        bp[1].q.rx_qmax = 0;
        bp[1].q.prod_max_gap = 0;
    }
    ED("exiting on abort");
    sleep(1);

    latency_reduction_stop();

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
    if (conv == NULL) {
        if (*ep == '\0') /* special case, no conversion */
            goto done;
        ED("bad suffix %s", ep);
        goto error;
    }
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
my_random24(struct _qs *q)	/* 24 useful bits */
{
    return nrand48(q->prod_seed) & ((1<<24) - 1);
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

REORDERING emulation 	-R option_arguments

    NOTE: The config function should store, in q->max_hold_delay,
    a reasonable estimate of the maximum hold delay applied to the packets
    as this is needed to size the memory buffer used to hold reordered
    packets.

    If the option is not supplied, the system does not reorder packets.

    Currently implemented options

    const,p,t		hold packets for t ns, with probability t


#endif /* end of comment block */

/*
 * Configuration options for delay
 *
 * Must store a reasonable estimate of the max_delay in q->max_delay
 * as this is used to size the queue.
 */

static int
update_max_delay(struct _qs *q, uint64_t delay)
{
    if (q->ec->max_delay) {
        if (q->ec->max_delay < delay) {
            ED("invalid new delay %lld (max %lld)",
                    (long long)delay, (long long)q->ec->max_delay);
            return 1;
        }
    } else {
        q->ec->max_delay = delay;
    }
    return 0;
}

/* constant delay, also accepts just a number */
static int
const_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    uint64_t delay, *d;

    if (strncmp(av[0], "const", 5) != 0 && ac > 1)
        return 2; /* unrecognised */
    if (ac > 2)
        return 1; /* error */
    delay = parse_time(av[ac - 1]);
    if (delay == U_PARSE_ERR)
        return 1; /* error */
    if (update_max_delay(q, delay))
        return 1;
    dst->arg = ec_alloc(q, dst->ec, sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    d[0] = delay;
    return 0;	/* success */
}

/* runtime function, store the delay into q->cur_delay */
static int
const_delay_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t *d = arg->arg;
    q->cur_delay = d[0]; /* the delay */
    return 0;
}

static int
uniform_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    uint64_t dmin, dmax, *d;

    if (strcmp(av[0], "uniform") != 0)
        return 2; /* not recognised */
    if (ac != 3)
        return 1; /* error */
    dmin = parse_time(av[1]);
    dmax = parse_time(av[2]);
    if (dmin == U_PARSE_ERR || dmax == U_PARSE_ERR || dmin > dmax)
        return 1;
    ED("dmin %lld dmax %lld", (long long)dmin, (long long)dmax);
    if (update_max_delay(q, dmax))
        return 1;
    dst->arg = ec_alloc(q, dst->ec, 3 * sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    d[0] = dmin;
    d[1] = dmax;
    d[2] = dmax - dmin;
    return 0;
}

static int
uniform_delay_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t x = my_random24(q), *d = arg->arg;
    q->cur_delay = d[0] + ((d[2] * x) >> 24);
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
    uint64_t i, d_av, d_min, d_max, *t; /*table of values */

    if (strcmp(av[0], "exp") != 0)
        return 2; /* not recognised */
    if (ac != 3)
        return 1; /* error */
    d_min = parse_time(av[1]);
    d_av = parse_time(av[2]);
    if (d_av == U_PARSE_ERR || d_min == U_PARSE_ERR || d_av < d_min)
        return 1; /* error */
    d_max = d_av * 4 + d_min; /* exp(-4) */
    if (update_max_delay(q, d_max))
        return 1;
    d_av -= d_min;
    dst->arg = ec_alloc(q, dst->ec, PTS_D_EXP * sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1; /* no memory */
    t = (uint64_t *)dst->arg;
    /* tabulate -ln(1-n)*delay  for n in 0..1 */
    for (i = 0; i < PTS_D_EXP; i++) {
        double d = -log ((double)(PTS_D_EXP - i) / PTS_D_EXP) * d_av + d_min;
        t[i] = (uint64_t)d;
        ND(5, "%ld: %le", i, d);
    }
    return 0;
}

static int
exp_delay_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t *t = (uint64_t *)arg->arg;
    q->cur_delay = t[my_random24(q) & (PTS_D_EXP - 1)];
    ND(5, "delay %llu", (unsigned long long)q->cur_delay);
    return 0;
}

static int
interpacket_delay_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    uint64_t delay, gmin, gmax, *d;
    if (strcmp(av[0], "inter-packet") != 0)
        return 2; /* not recognized */
    if (ac != 4)
        return 1; /* error */
    gmin = parse_time(av[1]);
    gmax = parse_time(av[2]);
    delay = parse_time(av[3]);
    if (gmin == U_PARSE_ERR || gmax == U_PARSE_ERR || delay == U_PARSE_ERR
            || gmin > gmax)
        return 1;
    ED("min-gap %lld max-gap %lld delay %lld",
            (long long)gmin, (long long)gmax, (long long)delay);
    if (update_max_delay(q, delay))
        return 1;
    dst->arg = ec_alloc(q, dst->ec, 4 * sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    d[0] = gmin;
    d[1] = gmax;
    d[2] = gmax - gmin;
    d[3] = delay;
    return 0;
}

static int
interpacket_delay_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t x = my_random24(q), *d = arg->arg;
    uint64_t gap = d[0] + ((d[2] * x) >> 24);
    uint64_t base = q->qt_tx;
    if (base < q->prod_now) {
        base = q->prod_now;
        gap = d[3];
    }
    q->cur_delay = (base - q->prod_now) + gap;
    return 0;
}

#define TLEM_CFG_END	NULL, NULL, 0

static struct _cfg delay_cfg[] = {
	{ const_delay_parse, const_delay_run,
		"constant,delay", TLEM_CFG_END },
	{ uniform_delay_parse, uniform_delay_run,
		"uniform,dmin,dmax # dmin <= dmax", TLEM_CFG_END },
	{ exp_delay_parse, exp_delay_run,
		"exp,dmin,davg # dmin <= davg", TLEM_CFG_END },
	{ interpacket_delay_parse, interpacket_delay_run,
	        "inter-packet,min-gap,max-gap,delay # min-gap <= max-gap", TLEM_CFG_END },
	{ NULL, NULL, NULL, TLEM_CFG_END }
};

static int
update_max_bw(struct _qs *q, uint64_t bw)
{
    if (q->ec->max_bps) {
        if (q->ec->max_bps < bw) {
            ED("invalid new bandwidth %lld (max %lld)",
                    (long long)bw, (long long)q->ec->max_bps);
            return 1;
        }
    } else {
        q->ec->max_bps = bw;	/* bw used to determine queue size */
    }
    return 0;
}

/* standard bandwidth, also accepts just a number */
static int
const_bw_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    uint64_t bw;
    uint32_t *d;
    int i;

    if (strncmp(av[0], "const", 5) != 0 && ac > 1)
        return 2; /* unrecognised */
    if (ac > 2)
        return 1; /* error */
    bw = parse_bw(av[ac - 1]);
    if (bw == U_PARSE_ERR) {
        return (ac == 2) ? 1 /* error */ : 2 /* unrecognised */;
    }
    dst->arg = ec_alloc(q, dst->ec, MAX_PKT * sizeof(uint32_t));
    if (dst->arg == NULL)
        return 1;
    if (update_max_bw(q, bw))
        return 1;
    d = dst->arg;
    for (i = 0; i < MAX_PKT; i++) {
        d[i] = bw ? 8ULL * TIME_UNITS * i / bw : 0;
    }
    dst->def_qsize = 50000;
    return 0;	/* success */
}


/* runtime function, store the delay into q->cur_delay */
static int
const_bw_run(struct _qs *q, struct _cfg *arg)
{
    uint32_t *d = arg->arg;
    q->cur_tt = d[q->cur_len];
    q->cur_drop = 0;
    return 0;
}

/* ethernet bandwidth, add 672 bits per packet */
static int
ether_bw_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    uint64_t bw;
    uint32_t *d;
    int i;

    if (strcmp(av[0], "ether") != 0)
        return 2; /* unrecognised */
    if (ac != 2)
        return 1; /* error */
    bw = parse_bw(av[ac - 1]);
    if (bw == U_PARSE_ERR)
        return 1; /* error */
    if (update_max_bw(q, bw))
        return 1;
    dst->arg = ec_alloc(q, dst->ec, MAX_PKT * sizeof(uint32_t));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    for (i = 0; i < MAX_PKT; i++) {
        d[i] = bw ? 8ULL * TIME_UNITS * (i + 24) / bw : 0;
    }
    dst->def_qsize = 50000;
    return 0;	/* success */
}


/* runtime function, add 20 bytes (framing) + 4 bytes (crc) */
static int
ether_bw_run(struct _qs *q, struct _cfg *arg)
{
    uint32_t *d = arg->arg;
    q->cur_tt = d[q->cur_len];
    q->cur_drop = 0;
    return 0;
}

/* token bucket. We don't limit the transmission time of
 * each packet, but non-conforming packets are dropped
 */
#define WSHIFT 20
struct avgbw_arg {
    uint64_t token;
    uint64_t bucket;
    uint64_t depth;
    uint64_t last_token;
};
static int
avg_bw_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    double bw, token;
    struct avgbw_arg *d;

    if (strcmp(av[0], "avg") != 0)
        return 2; /* unrecognised */
    if (ac != 2)
        return 1; /* error */
    bw = parse_bw(av[ac - 1]);
    if (bw == U_PARSE_ERR)
        return 1; /* error */
    if (update_max_bw(q, bw))
        return 1;
    token = (bw / 8) * (1UL << WSHIFT) / 1e9;
    dst->arg = ec_alloc(q, dst->ec, sizeof(*d));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    d->token = token;
    d->bucket = 0;
    d->depth = 4 * token;
    if (d->depth < 2*MAX_PKT)
	d->depth = 2*MAX_PKT;
    d->last_token = 0;
    dst->def_qsize = 0; /* skip the queue emulation */
    D("token %lluB/%.2fms depth %llu",
	    (unsigned long long)d->token, (1UL << WSHIFT)/1e6,
	    (unsigned long long)d->depth);
    return 0;	/* success */

}

static int
avg_bw_run(struct _qs *q, struct _cfg *arg)
{
    struct avgbw_arg *d = arg->arg;
    uint64_t now = (q->prod_now >> WSHIFT);
    uint64_t sz = q->cur_len + 24;
    uint64_t tokens;

    /* insert all the necessary tokens */
    tokens = (now - d->last_token) * d->token;
    d->last_token = now;
    d->bucket += tokens;
    if (d->bucket > d->depth)
	d->bucket = d->depth;
    ND(1, "%llu: now %llu last %llu tokens %llu bucket %llu",
		(unsigned long long)q->prod_now,
		(unsigned long long)now,
		(unsigned long long)d->last_token,
		(unsigned long long)tokens,
		(unsigned long long)d->bucket);
    q->cur_tt = 0;
    q->cur_drop = sz > d->bucket;
    if (!q->cur_drop)
	d->bucket -= sz;
    //printf("%llu %llu\n", (unsigned long long)q->prod_now, (unsigned long long)d->bucket);
    return 0;
}

static struct _cfg bw_cfg[] = {
	{ const_bw_parse, const_bw_run,
		"constant,bps", TLEM_CFG_END },
	{ ether_bw_parse, ether_bw_run,
		"ether,bps", TLEM_CFG_END },
	{ avg_bw_parse, avg_bw_run, "avg,bps", TLEM_CFG_END },
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
    uint64_t *d;

    (void)q;
    if (strcmp(av[0], "plr") != 0 && ac > 1)
        return 2; /* unrecognised */
    if (ac > 2)
        return 1; /* error */
    // XXX to be completed
    plr = parse_gen(av[ac-1], NULL, &err);
    if (err || plr < 0 || plr > 1)
        return 1;
    dst->arg = ec_alloc(q, dst->ec, 3 * sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1;
    d = dst->arg;
    d[0] = plr * (1<<24); /* scale is 16m */
    if (plr != 0 && d[0] == 0)
        ED("WWW warning,  rounding %le down to 0", plr);
    return 0;	/* success */
}

static int
const_plr_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t *d = arg->arg, r = my_random24(q);
    q->cur_drop = r < d[0];
#if 1	/* keep stats */
    d[1]++;
    d[2] += q->cur_drop;
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
    uint64_t *d;
    const uint32_t mask = (1<<24) - 1;

    (void)q;
    if (strcmp(av[0], "ber") != 0)
        return 2; /* unrecognised */
    if (ac != 2)
        return 1; /* error */
    ber = parse_gen(av[ac-1], NULL, &err);
    if (err || ber < 0 || ber > 1)
        return 1;
    dst->arg = ec_alloc(q, dst->ec,
            3 * sizeof(uint64_t) + MAX_PKT * sizeof(uint32_t));
    if (dst->arg == NULL)
        return 1; /* no memory */
    d = dst->arg;
    plr = (uint32_t *)(d + 3);
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
    d[0] = ber * (mask + 1);
    return 0;	/* success */
}

static int
const_ber_run(struct _qs *q, struct _cfg *arg)
{
    int l = q->cur_len;
    uint64_t r = my_random24(q), *d = arg->arg;
    uint32_t *plr = (uint32_t *)(d + 3);

    if (l >= MAX_PKT) {
        RD(5, "pkt len %d too large, trim to %d", l, MAX_PKT-1);
        l = MAX_PKT-1;
    }
    q->cur_drop = r < plr[l];
#if 1	/* keep stats */
    d[1] += l * 8;
    d[2] += q->cur_drop;
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


/*
 * reordering
 */

static int
update_max_hold_delay(struct _qs *q, uint64_t delay)
{
    if (q->ec->max_hold_delay) {
        if (q->ec->max_hold_delay < delay) {
            ED("invalid new hold delay %lld (max %lld)",
                    (long long)delay,
                    (long long)q->ec->max_hold_delay);
            return 1;
        }
    } else {
        q->ec->max_hold_delay = delay;
    }
    return 0;
}

static int
const_reorder_parse(struct _qs *q, struct _cfg *dst, int ac, char *av[])
{
    double prob;
    uint64_t delay, *d;
    int err;

    if (strcmp(av[0], "const") != 0 && ac != 2)
        return 2; /* not recognized */
    if (ac > 3)
        return 1; /* error */
    dst->arg = ec_alloc(q, dst->ec, 2 * sizeof(uint64_t));
    if (dst->arg == NULL)
        return 1; /* no memory */
    prob = parse_gen(av[ac - 2], NULL, &err);
    if (err || prob < 0 || prob > 1)
        return 1;
    d = dst->arg;
    d[0] = prob * (1<<24);
    if (prob != 0 && d[0] == 0)
        ED("WWW warning,  rounding %le down to 0", prob);
    delay = parse_time(av[ac - 1]);
    if (delay == U_PARSE_ERR)
        return 1;
    if (update_max_hold_delay(q, delay))
        return 1;
    d[1] = delay;
    return 0;
}

static int
const_reorder_run(struct _qs *q, struct _cfg *arg)
{
    uint64_t r = my_random24(q), *d = arg->arg;
    q->cur_hold_delay = (r < d[0] ? d[1] : 0);
    return 0;
}

static struct _cfg reorder_cfg[] = {
	{ const_reorder_parse, const_reorder_run,
		"const,prob,delay # 0 <= prob <= 1", TLEM_CFG_END },
	{ NULL, NULL, NULL, TLEM_CFG_END }
};

void
ec_activate(struct _qs *q)
{
    int i = q->ec_active, j;
    struct _eci *a = &q->ec->instances[i];

    for (j = 0; j < I_NUM; j++) {
	if (a->ec_imp[j].ec_valid) {
	    q->c_imp[j] = all_cfgs[j].c[a->ec_imp[j].ec_index];
	    q->c_imp[j].arg = &a->ec_data[a->ec_imp[j].ec_dataoff];
	} else {
	    switch (j) {
	    case I_DELAY:
	        q->cur_delay = 0;
	        break;
	    case I_BW:
		q->cur_tt = 0;
	        break;
	    case I_LOSS:
		q->cur_drop = 0;
	        break;
	    case I_REORDER:
		q->cur_hold_delay = 0;
	        break;
	    }
	    q->c_imp[j].run = null_run_fn;
	}
	q->c_imp[j].ec = &a->ec_imp[j];
    }
    q->allow_drop = a->ec_allow_drop;
    q->delay_offset = a->ec_delay_offset;
    q->qsize = a->ec_qsize;
}
