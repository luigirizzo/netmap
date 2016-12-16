/*
 * Copyright (C) 2012-2014 Luigi Rizzo. All rights reserved.
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

/*
 * $Id$
 *
 * Test program to study various ops and concurrency issues.
 * Create multiple threads, possibly bind to cpus, and run a workload.
 *
 * cc -O2 -Werror -Wall testlock.c -o testlock -lpthread
 *	you might need -lrt
 */

#define _GNU_SOURCE	// setaffinity ?

#include <inttypes.h>
#include <sys/types.h>
#include <pthread.h>	/* pthread_* */

#if defined(__APPLE__)

#include <net/if_var.h>
#include <libkern/OSAtomic.h>
#define atomic_add_int(p, n) OSAtomicAdd32(n, (int *)p)
#define	atomic_cmpset_32(p, o, n)	OSAtomicCompareAndSwap32(o, n, (int *)p)

#elif defined(linux)

#define atomic_cmpset_32(p, o, n) __sync_bool_compare_and_swap(p, o, n)
#include <sched.h>	// affinity
#define HAVE_AFFINITY	1
#define	cpuset_t	cpu_set_t

#if defined(HAVE_GCC_ATOMICS)
int atomic_add_int(volatile int *p, int v)
{
        return __sync_fetch_and_add(p, v);
}
#else
inline
uint32_t atomic_add_int(uint32_t *p, int v)
{
        __asm __volatile (
        "       lock   xaddl   %0, %1 ;        "
        : "+r" (v),                     /* 0 (result) */
          "=m" (*p)                     /* 1 */
        : "m" (*p));                    /* 2 */
        return (v);
}
#endif

#else /* FreeBSD */
#include <sys/param.h>
#include <machine/atomic.h>
#include <pthread_np.h>	/* pthread w/ affinity */

#if __FreeBSD_version > 500000
#include <sys/cpuset.h>	/* cpu_set */
#if __FreeBSD_version > 800000
#define HAVE_AFFINITY
#endif


#else /* FreeBSD 4.x */
int atomic_cmpset_32(volatile uint32_t *p, uint32_t old, uint32_t new)
{
	int ret = *p == old;
	*p = new;
	return ret;
}

#define PRIu64	"llu"
#endif /* FreeBSD 4.x */

#endif /* FreeBSD */

#include <signal.h>	/* signal */
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <inttypes.h>	/* PRI* macros */
#include <string.h>	/* strcmp */
#include <fcntl.h>	/* open */
#include <unistd.h>	/* getopt */


#include <sys/sysctl.h>	/* sysctl */
#include <sys/time.h>	/* timersub */

#define CE(a, b)	(((a)+(b)-1)/(b))

#define ONE_MILLION	1000000
#define _1K		(1000)
#define _100K		(100*_1K)
#define	_1M		(_1K*_1K)
#define	_10M		(10*_1M)
#define	_100M		(100*_1M)
/* debug support */
#define ND(format, ...)
#define D(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n",	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)

int verbose = 0;

#if 1//def MY_RDTSC
/* Wrapper around `rdtsc' to take reliable timestamps flushing the pipeline */
#define my_rdtsc(t)				\
	do {					\
		u_int __regs[4];		\
						\
		do_cpuid(0, __regs);		\
		(t) = rdtsc();			\
	} while (0)

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax) );
}

static __inline uint64_t
rdtsc(void)
{
	uint64_t rv;

	// XXX does not work on linux-64 bit
	__asm __volatile("rdtscp" : "=A" (rv) : : "%rax");
	return (rv);
}
#endif /* 1 */

struct targ;

/*** global arguments for all threads ***/
struct glob_arg {
	struct  {
		uint32_t	ctr[1024];
	} v __attribute__ ((aligned(256) ));
	int64_t m_cycles;	/* total cycles */
	int nthreads;
	int cpus;
	int privs;	// 1 if has IO privileges
	int arg;	// microseconds in usleep
	int nullfd;	// open(/dev/null)
	char *test_name;
	pthread_mutex_t mtx;
	void (*fn)(struct targ *);
	uint64_t scale;	// scaling factor
	char *scale_name;	// scaling factor
	struct targ *ta;	// per cpu/thread argument
};

/*
 * Arguments for a new thread.
 */
struct targ {
	struct glob_arg *g;
	int		completed;
	u_int		*glob_ctr;
	uint64_t volatile count;
	struct timeval	tic, toc;
	int		me;
	pthread_t	thread;
	int		affinity;
	pthread_mutex_t	mtx;
} __attribute__ ((aligned(64) ));


static struct targ *ta;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	for (i = 0; i < global_nthreads; i++) {
		/* cancel active threads. */
		if (ta[i].completed)
			continue;
		D("Cancelling thread #%d\n", i);
		pthread_cancel(ta[i].thread);
		ta[i].completed = 0;
	}
	signal(SIGINT, SIG_DFL);
}


/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
#ifdef linux
	return sysconf(_SC_NPROCESSORS_ONLN);
#else
	int mib[2] = { CTL_HW, HW_NCPU}, ncpus;
	size_t len = sizeof(mib);
	sysctl(mib, len / sizeof(mib[0]), &ncpus, &len, NULL, 0);
	D("system had %d cpus", ncpus);

	return (ncpus);
#endif
}

/*
 * try to get I/O privileges so we can execute cli/sti etc.
 */
int
getprivs(void)
{
	int fd = open("/dev/io", O_RDWR);
	if (fd < 0) {
		D("cannot open /dev/io, fd %d", fd);
		return 0;
	}
	return 1;
}

/* set the thread affinity. */
/* ARGSUSED */
#ifdef HAVE_AFFINITY
static int
setaffinity(pthread_t me, int i)
{
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity");
		return 1;
	}
	return 0;
}
#endif


static void *
td_body(void *data)
{
	struct targ *t = (struct targ *) data;

#ifdef HAVE_AFFINITY
	if (0 == setaffinity(t->thread, t->affinity))
#endif
	{
		/* main loop.*/
		D("testing %"PRIu64" cycles arg %d",
			t->g->m_cycles, t->g->arg);
		gettimeofday(&t->tic, NULL);
		t->g->fn(t);
		gettimeofday(&t->toc, NULL);
	}
	t->completed = 1;
	return (NULL);
}

#include <sys/wait.h>

void
test_fork(struct targ *t)
{
	int arg = t->g->arg;
	int m;
	struct timeval tot = {0, 0};
	struct timeval ta, tb;
	char *p = NULL;
	int sum = 0;
	long int i;
	int np=arg*1000000/4096;
	p = malloc(arg*1000000);

	D("memsize is %d MB", arg);

	if (arg > 0) {
		if (p == NULL)
			D("malloc failed");
		D("pages %d %s %s", np, arg & 1 ? "READ" : "",
			arg & 2 ? "WRITE" : "");
	}
	for (m = 0; m < t->g->m_cycles; m++) {
		int pid;
		int st = 0;
		if (arg & 1) for (i = 0; i < arg*1000000; i += 4096) {
			sum += p[i];
		}
		if (arg & 2) for (i = 0; i < arg*1000000; i += 4096) {
			p[i] = 3;
		}
		ta.tv_sec = sum;
		gettimeofday(&ta, NULL);
		pid = fork();
		if (pid == 0)
			exit(0);
		gettimeofday(&tb, NULL);
		if (waitpid(-1, &st, WNOHANG) > 0) // another try
			waitpid(-1, &st, WNOHANG);

		tot.tv_sec += (tb.tv_sec - ta.tv_sec);
		tot.tv_usec += (tb.tv_usec - ta.tv_usec);
		if (tot.tv_usec < 0) {
			tot.tv_sec--;
			tot.tv_usec += ONE_MILLION;
		} else if (tot.tv_usec >= ONE_MILLION) {
			tot.tv_sec++;
			tot.tv_usec -= ONE_MILLION;
		}
		t->count++;
	}
	D("avg is %lu ns", (unsigned long)
		((tot.tv_sec * ONE_MILLION + tot.tv_usec)*1000/t->count));
	if (p)
		free(p);
}

/*
 * select and poll:
 *	arg	fd	timeout
 *	>0	block	>0
 *	 0	block	0
 *		block	NULL (not implemented)
 *	< -2	ready	-arg
 *	-1	ready	0
 *	-2	ready	NULL / <0 for poll
 *
 * arg = -1 -> NULL timeout (select)
 */
void
test_select(struct targ *t)
{
	int arg = t->g->arg;
	// stdin is blocking on reads /dev/null or /dev/zero are not
	int fd = (arg < 0) ? t->g->nullfd : 0;
	fd_set r;
	struct timeval t0 = { 0, arg};
	struct timeval tcur, *tp = (arg == -2) ? NULL : &tcur;
	int64_t m;

	if (arg == -1)
		t0.tv_usec = 0;
	else if (arg < -2)
		t0.tv_usec = -arg;

	D("tp %p mode %s timeout %d", tp, arg < 0 ? "ready" : "block",
		(int)t0.tv_usec);
	for (m = 0; m < t->g->m_cycles; m++) {
		int ret;
		tcur = t0;
		FD_ZERO(&r);
		FD_SET(fd, &r);
		ret = select(fd+1, &r, NULL, NULL, tp);
		(void)ret;
		ND("ret %d r %d w %d", ret,
			FD_ISSET(fd, &r),
			FD_ISSET(fd, &w));
		t->count++;
	}
}

void
test_poll(struct targ *t)
{
	int arg = t->g->arg;
	// stdin is blocking on reads /dev/null is not
	int fd = (arg < 0) ? t->g->nullfd : 0;
	int64_t m;
	int ms;

	if (arg == -1)
		ms = 0;
	else if (arg == -2)
		ms = -1; /* blocking */
	else if (arg < 0)
		ms = -arg/1000;
	else
		ms = arg/1000;

	D("mode %s timeout %d", arg < 0 ? "ready" : "block", ms);
	for (m = 0; m < t->g->m_cycles; m++) {
		struct pollfd x;
		x.fd = fd;
		x.events = POLLIN;
		poll(&x, 1, ms);
		t->count++;
	}
}

void
test_usleep(struct targ *t)
{
	int64_t m;
	for (m = 0; m < t->g->m_cycles; m++) {
		usleep(t->g->arg);
		t->count++;
	}
}

/* X86 only support for reading the current cpu */
static inline void do_cpuid2(uint32_t code, uint32_t* regs)
{
	asm volatile ( "cpuid" : "=a"(regs[0]), "=b"(regs[1]),
		"=c"(regs[2]), "=d"(regs[3]) : "a"(code));
}


void
test_cpuid(struct targ *t)
{
	int64_t m, i;
	uint32_t old, curcpu, tmp, regs[4], migrate=0;
	do_cpuid2(0xb, regs);
	D("cpuid() returns %x %x %x %x",
	regs[0], regs[1], regs[2], regs[3]);
	old = regs[3];

	for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < _1K; i++) {
			asm volatile("cpuid" : "=d"(curcpu), "=a"(tmp), "=b"(tmp), "=c"(tmp) : "a"(0xb) );
			//do_cpuid2(0xb, regs); curcpu = regs[3];
			if (old != curcpu)
				migrate++;
			old = curcpu;
			t->count++;
		}
	}
	D("migrated %d times out of %ld", migrate, m*i);
}

void
test_cli(struct targ *t)
{
        int64_t m, i;
	if (!t->g->privs) {
		D("%s", "privileged instructions not available");
		return;
	}
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
			__asm __volatile("cli;");
			__asm __volatile("and %eax, %eax;");
			__asm __volatile("sti;");
			t->count++;
		}
        }
}

void
test_nop(struct targ *t)
{
        int64_t m, i;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
			__asm __volatile("nop;");
			__asm __volatile("nop; nop; nop; nop; nop;");
			//__asm __volatile("nop; nop; nop; nop; nop;");
			t->count++;
		}
	}
}

void
test_rdtsc1(struct targ *t)
{
        int64_t m, i;
	uint64_t v;
	(void)v;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
                	my_rdtsc(v);
			t->count++;
		}
        }
}

void
test_rdtsc(struct targ *t)
{
        int64_t m, i;
	volatile uint64_t v;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
                	v = rdtsc();
			t->count++;
		}
        }
	(void)v;
}

void
test_add(struct targ *t)
{
        int64_t m, i;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
                	t->glob_ctr[0] ++;
			t->count++;
		}
        }
}

void
test_atomic_add(struct targ *t)
{
        int64_t m, i;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
                	atomic_add_int(t->glob_ctr, 1);
			t->count++;
		}
        }
}

void
test_atomic_cmpset(struct targ *t)
{
        int64_t m, i;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
		        atomic_cmpset_32(t->glob_ctr, m, i);
			t->count++;
		}
        }
}

void
test_pthread_mutex(struct targ *t)
{
        int64_t m, i, lim = CE(t->g->m_cycles, ONE_MILLION);
	pthread_mutex_t *mtx = &t->g->mtx;
        for (m = 0; m < lim; m++) {
		for (i = 0; i < ONE_MILLION; i++) {
		        pthread_mutex_lock(mtx);
			t->count++;
		        pthread_mutex_unlock(mtx);
		}
        }
}

volatile int foo;

void
test_spinlock(struct targ *t)
{
        int64_t m, i;
//	uint64_t min = 1000000, minp=1000000, max=0, maxp = 0, cur=0;
        for (m = 0; m < t->g->m_cycles; m++) {
		for (i = 0; i < 100*ONE_MILLION; i++) {
		        while (!atomic_cmpset_32(t->glob_ctr, 0, 1)) {
			}
			t->count++;
		        atomic_cmpset_32(t->glob_ctr, 1, 0);
		}
        }
}

void
test_time(struct targ *t)
{
        int64_t m;
        for (m = 0; m < t->g->m_cycles; m++) {
#ifndef __APPLE__
		struct timespec ts;
		clock_gettime(t->g->arg, &ts);
#endif
		t->count++;
        }
}

void
test_gettimeofday(struct targ *t)
{
        int64_t m;
	struct timeval ts;
        for (m = 0; m < t->g->m_cycles; m++) {
		gettimeofday(&ts, NULL);
		t->count++;
        }
}

/*
 * getppid is the simplest system call (getpid is cached by glibc
 * so it would not be a good test)
 */
void
test_getpid(struct targ *t)
{
        int64_t m;
        for (m = 0; m < t->g->m_cycles; m++) {
		getppid();
		t->count++;
        }
}


#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

static void
fast_bcopy(void *_src, void *_dst, int l)
{
	uint64_t *src = _src;
	uint64_t *dst = _dst;
	if (unlikely(l >= 1024)) {
		bcopy(src, dst, l);
		return;
	}
	for (; likely(l > 0); l-=64) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}

static inline void
asmcopy(void *dst, void *src, uint64_t l)
{
	(void)dst;
	(void)src;
	asm(
	"\n\t"
	"movq %0, %%rcx\n\t"
	"addq $7, %%rcx\n\t"
	"shrq $03, %%rcx\n\t"
	"cld\n\t"
	"movq %1, %%rdi\n\t"
	"movq %2, %%rsi\n\t"
	"repe movsq\n\t"
/*	"movq %0, %%rcx\n\t"
	"andq $0x7, %%rcx\n\t"
	"repe movsb\n\t"
*/
	: /* out */
	: "r" (l), "r" (dst), "r" (src) /* in */
	: "%rcx", "%rsi", "%rdi" /* clobbered */
	);

}
// XXX if you want to make sure there is no inlining...
// static void (*fp)(void *_src, void *_dst, int l) = fast_bcopy;

#define HU	0x3ffff
static struct glob_arg huge[HU+1];

void
test_fastcopy(struct targ *t)
{
        int64_t m;
	int len = t->g->arg;

	if (len > (int)sizeof(struct glob_arg))
		len = sizeof(struct glob_arg);
	D("fast copying %d bytes", len);
        for (m = 0; m < t->g->m_cycles; m++) {
		fast_bcopy(t->g, (void *)&huge[m & HU], len);
		t->count+=1;
        }
}

void
test_asmcopy(struct targ *t)
{
        int64_t m;
	int len = t->g->arg;

	if (len > (int)sizeof(struct glob_arg))
		len = sizeof(struct glob_arg);
	D("fast copying %d bytes", len);
        for (m = 0; m < t->g->m_cycles; m++) {
		asmcopy((void *)&huge[m & HU], t->g, len);
		t->count+=1;
        }
}

void
test_bcopy(struct targ *t)
{
        int64_t m;
	int len = t->g->arg;

	if (len > (int)sizeof(struct glob_arg))
		len = sizeof(struct glob_arg);
	D("bcopying %d bytes", len);
        for (m = 0; m < t->g->m_cycles; m++) {
		bcopy(t->g, (void *)&huge[m & HU], len);
		t->count+=1;
        }
}

void
test_builtin_memcpy(struct targ *t)
{
        int64_t m;
	int len = t->g->arg;

	if (len > (int)sizeof(struct glob_arg))
		len = sizeof(struct glob_arg);
	D("bcopying %d bytes", len);
        for (m = 0; m < t->g->m_cycles; m++) {
		__builtin_memcpy((void *)&huge[m & HU], t->g, len);
		t->count+=1;
        }
}

void
test_memcpy(struct targ *t)
{
        int64_t m;
	int len = t->g->arg;

	if (len > (int)sizeof(struct glob_arg))
		len = sizeof(struct glob_arg);
	D("memcopying %d bytes", len);
        for (m = 0; m < t->g->m_cycles; m++) {
		memcpy((void *)&huge[m & HU], t->g, len);
		t->count+=1;
        }
}

#include <sys/ioctl.h>
#include <sys/socket.h>	// OSX
#include <net/if.h>
#include <net/netmap.h>
void
test_netmap(struct targ *t)
{
	struct nmreq nmr;
	int fd;
        int64_t m, scale;

	scale = t->g->m_cycles / 100;
	fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D("fail to open netmap, exit");
		return;
	}
	bzero(&nmr, sizeof(nmr));
        for (m = 0; m < t->g->m_cycles; m += scale) {
		nmr.nr_version = 666;
		nmr.nr_cmd = t->g->arg;
		nmr.nr_offset = (uint32_t)scale;
		ioctl(fd, NIOCGINFO, &nmr);
		t->count += scale;
        }
	return;
}

struct entry {
	void (*fn)(struct targ *);
	char *name;
	uint64_t scale;
	uint64_t m_cycles;
};
#define EE(a, b, c)	{ test_ ## a, #a, b, c }
struct entry tests[] = {
	EE(fork, 1, _1K),
	EE(select, 1, _1K),
	EE(poll, 1, _1K),
	EE(usleep, 1, _1K),
	EE(cpuid, _1K, _100K),
	EE(time, 1, _1K),
	EE(gettimeofday, 1, _1M),
	EE(getpid, 1, _1M),
	EE(bcopy, _1K, _100M),
	EE(builtin_memcpy, _1K, _100M),
	EE(memcpy, _1K, _100M),
	EE(fastcopy, _1K, _100M),
	EE(asmcopy, _1K, _100M),
	EE(add, _1M, _100M),
	EE(nop, _1M, _100M),
	EE(atomic_add, _1M, _100M),
	EE(cli, _1M, _100M),
	EE(rdtsc, _1M, _100M),	// unserialized
	EE(rdtsc1, _1M, _100M),	// serialized
	EE(atomic_cmpset, _1M, _100M),
	EE(netmap, _1K, _100M),
	EE(pthread_mutex, _1K, _100M),
	EE(spinlock, _1K, _100M),
	{ NULL, NULL, 0, 0 }
};

static void
usage(void)
{
	const char *cmd = "test";
	int i;

	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-m name		test name\n"
		"\t-n cycles		(millions) of cycles\n"
		"\t-l arg		bytes, usec, ... \n"
		"\t-t threads		total threads\n"
		"\t-c cores		cores to use\n"
		"\t-a n			force affinity every n cores\n"
		"\t-A n			cache contention every n bytes\n"
		"\t-w report_ms		milliseconds between reports\n"
		"",
		cmd);
	fprintf(stderr, "Available tests:\n");
	for (i = 0; tests[i].name; i++) {
		fprintf(stderr, "%12s\n", tests[i].name);
	}

	exit(0);
}

static int64_t
getnum(const char *s)
{
	int64_t n;
	char *e;

	n = strtol(s, &e, 0);
	switch (e ? *e : '\0')  {
	case 'k':
	case 'K':
		return n*1000;
	case 'm':
	case 'M':
		return n*1000*1000;
	case 'g':
	case 'G':
		return n*1000*1000*1000;
	case 't':
	case 'T':
		return n*1000*1000*1000*1000;
	default:
		return n;
	}
}

struct glob_arg g;
int
main(int argc, char **argv)
{
	int i, ch, report_interval, affinity, align;

	ND("g has size %d", (int)sizeof(g));
	report_interval = 250;	/* ms */
	affinity = 0;		/* no affinity */
	align = 0;		/* global variable */

	bzero(&g, sizeof(g));

	g.privs = getprivs();
	pthread_mutex_init(&g.mtx, NULL);
	g.nthreads = 1;
	g.cpus = 1;
	g.m_cycles = 0;
	g.nullfd = open("/dev/zero", O_RDWR);
	D("nullfd is %d", g.nullfd);

	while ( (ch = getopt(argc, argv, "A:a:m:n:w:c:t:vl:")) != -1) {
		switch(ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'A':	/* align */
			align = atoi(optarg);
			break;
		case 'a':	/* force affinity */
			affinity = atoi(optarg);
			break;
		case 'n':	/* cycles */
			g.m_cycles = getnum(optarg);
			break;
		case 'w':	/* report interval */
			report_interval = atoi(optarg);
			break;
		case 'c':
			g.cpus = atoi(optarg);
			break;
		case 't':
			g.nthreads = atoi(optarg);
			break;
		case 'm':
			g.test_name = optarg;
			break;
		case 'l':
			g.arg = getnum(optarg);
			break;

		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (!g.test_name && argc > 0)
		g.test_name = argv[0];

	if (g.test_name) {
		for (i = 0; tests[i].name; i++) {
			if (!strcmp(g.test_name, tests[i].name)) {
				g.fn = tests[i].fn;
				g.scale = tests[i].scale;
				if (g.m_cycles == 0)
					g.m_cycles = tests[i].m_cycles;
				if (g.scale == ONE_MILLION)
					g.scale_name = "M";
				else if (g.scale == 1000)
					g.scale_name = "K";
				else {
					g.scale = 1;
					g.scale_name = "";
				}
				break;
			}
		}
	}
	if (!g.fn) {
		D("%s", "missing/unknown test name");
		usage();
	}
	i = system_ncpus();
	if (g.cpus < 0 || g.cpus > i) {
		D("%d cpus is too high, have only %d cpus", g.cpus, i);
		usage();
	}
	if (g.cpus == 0)
		g.cpus = i;
	if (g.nthreads < 1) {
		D("bad nthreads %d, using 1", g.nthreads);
		g.nthreads = 1;
	}
	i = sizeof(g.v.ctr) / g.nthreads*sizeof(g.v.ctr[0]);
	if (align < 0 || align > i) {
		D("bad align %d, max is %d", align, i);
		align = i;
	}

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);
    {
	int sz = g.nthreads;
	if (sz < g.cpus)
		sz = g.cpus;

	ta = calloc(sz, sizeof(*ta));
	g.ta = ta;
    }
	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
 	 */
	D("start %d threads on %d cores", g.nthreads, g.cpus);
	for (i = 0; i < g.nthreads; i++) {
		struct targ *t = &ta[i];
		bzero(t, sizeof(*t));
		t->g = &g;
		t->me = i;
		t->glob_ctr = &g.v.ctr[(i*align)/sizeof(g.v.ctr[0])];
		D("thread %d ptr %p", i, t->glob_ctr);
		t->affinity = affinity ? (affinity*i) % g.cpus : -1;
		if (pthread_create(&t->thread, NULL, td_body, t) == -1) {
			D("Unable to create thread %d", i);
			t->completed = 1;
		}
	}
	/* the main loop */

    {
	uint64_t my_count = 0, prev = 0;
	uint64_t count = 0;
	double delta_t;
	struct timeval tic, toc;

	gettimeofday(&toc, NULL);
	for (;;) {
		struct timeval now, delta;
		uint64_t pps;
		int done = 0;

		delta.tv_sec = report_interval/1000;
		delta.tv_usec = (report_interval%1000)*1000;
		select(0, NULL, NULL, NULL, &delta);
		gettimeofday(&now, NULL);
		timersub(&now, &toc, &toc);
		my_count = 0;
		for (i = 0; i < g.nthreads; i++) {
			my_count += ta[i].count;
			if (ta[i].completed)
				done++;
		}
		pps = toc.tv_sec* ONE_MILLION + toc.tv_usec;
		if (pps < 10000)
			continue;
		pps = (my_count - prev)*ONE_MILLION / pps;
		D("%" PRIu64 " %scycles/s scale %" PRIu64 " in %dus", pps/g.scale,
			g.scale_name, g.scale, (int)(toc.tv_sec* ONE_MILLION + toc.tv_usec));
		prev = my_count;
		toc = now;
		if (done == g.nthreads)
			break;
	}
	D("total %" PRIu64 " cycles", prev);

	timerclear(&tic);
	timerclear(&toc);
	for (i = 0; i < g.nthreads; i++) {
		pthread_join(ta[i].thread, NULL);

		if (ta[i].completed == 0)
			continue;

		/*
		 * Collect threads o1utput and extract information about
		 * how log it took to send all the packets.
		 */
		count += ta[i].count;
		if (!timerisset(&tic) || timercmp(&ta[i].tic, &tic, <))
			tic = ta[i].tic;
		if (!timerisset(&toc) || timercmp(&ta[i].toc, &toc, >))
			toc = ta[i].toc;
	}

	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	D("total %8.6f seconds", delta_t);
    }

	return (0);
}
/* end of file */
