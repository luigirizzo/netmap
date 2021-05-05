#ifndef _NMLIB_H_
#define _NMLIB_H_
#include <math.h>
#ifdef __FreeBSD__
#include<sys/cpuset.h>
#include <pthread_np.h> /* pthread w/ affinity */
#include<sys/sysctl.h>	/* sysctl */
#endif
#include <x86intrin.h>
#include<net/netmap.h>
#include<net/netmap_user.h>
#include<net/netmap_paste.h>
#include<ctrs.h>
#include<pthread.h>
#include <netinet/tcp.h>	/* SOL_TCP */
#include <sys/poll.h>
#ifdef __linux__
#include <linux/sysctl.h>	/* sysctl */
#include <netinet/tcp.h>	/* SOL_TCP */
#include <sys/epoll.h>
#include <bsd/string.h>
#endif /* __linux__ */

#ifdef __cplusplus
extern "C" {
#include <libnetmap.h>
}
#else
#include <libnetmap.h>
#endif /* __cplusplus */

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

int normalize = 1;

#define EPOLLEVENTS 2048
#define DEBUG_SOCKET	1
#ifndef linux
#define SOL_TCP	SOL_SOCKET
#define fallocate(a, b, c, d)	posix_fallocate(a, c, d)
#endif

#ifdef __FreeBSD__
static inline void *
mempcpy(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n) + n;
}
#endif /* __FreeBSD__ */

enum dev_type { DEV_NONE, DEV_NETMAP, DEV_SOCKET };
enum { TD_TYPE_SENDER = 1, TD_TYPE_RECEIVER, TD_TYPE_OTHER, TD_TYPE_DUMMY };

#ifdef linux
#define cpuset_t        cpu_set_t
#endif
/* set the thread affinity. */
static inline int
setaffinity(pthread_t me, int i)
{
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity: %s", strerror(errno));
		return 1;
	}
	return 0;
}

static void
tx_output(struct my_ctrs *cur, double delta, const char *msg)
{
	double bw, raw_bw, pps, abs;
	char b1[40], b2[80], b3[80];
	u_int size;

	if (cur->pkts == 0) {
		printf("%s nothing.\n", msg);
		return;
	}

	size = (cur->bytes / cur->pkts);

	printf("%s %llu packets %llu bytes %llu events %d bytes each in %.2f seconds.\n",
		msg,
		(unsigned long long)cur->pkts,
		(unsigned long long)cur->bytes,
		(unsigned long long)cur->events, size, delta);
	if (delta == 0)
		delta = 1e-6;
	if (size < 60)		/* correct for min packet size */
		size = 60;
	pps = cur->pkts / delta;
	bw = (8.0 * cur->bytes) / delta;
	/* raw packets have4 bytes crc + 20 bytes framing */
	raw_bw = (8.0 * (cur->pkts * 24 + cur->bytes)) / delta;
	abs = cur->pkts / (double)(cur->events);

	printf("Speed: %spps Bandwidth: %sbps (raw %sbps). Average batch: %.2f pkts\n",
		norm(b1, pps, normalize), norm(b2, bw, normalize), norm(b3, raw_bw, normalize), abs);
}

struct nm_msg {
	struct netmap_ring *rxring;
	struct netmap_ring *txring;
	struct netmap_slot *slot;
	struct nm_targ *targ;
	int fd;
};

struct nm_garg {
	char ifname[NETMAP_REQ_IFNAMSIZ*2]; // must be here
	struct nmport_d *nmd;
	void *(*td_body)(void *);
	int nthreads;
	int affinity;
	int dev_type;
	int td_type;
	int main_fd;
	int system_cpus;
	int cpus;
	uint32_t extra_bufs;		/* goes in nr_arg3 */
	uint64_t extmem_siz;
	u_int ring_objsize;
	int extra_pipes;	/* goes in nr_arg1 */
	char *nmr_config;
	char *extmem;		/* goes to nr_arg1+ */
#define	STATS_WIN	15
	int win_idx;
	int64_t win[STATS_WIN];
	int wait_link;
	int polltimeo;
#ifdef __FreeBSD__
	struct timespec *polltimeo_ts;
#endif
	int verbose;
	int report_interval;
#define OPT_PPS_STATS   2048
	int options;
	int targ_opaque_len; // passed down to targ

	struct nmreq_header nm_hdr; // cache decoded
	int (*data)(struct nm_msg *);
	void (*connection)(struct nm_msg *);
	int (*read)(struct nm_msg *);
	int (*thread)(struct nm_targ *);
	int *fds;
	u_int fdnum;
	int emu_delay;
	void *garg_private;
	char ifname2[NETMAP_REQ_IFNAMSIZ];
};

struct nm_targ {
	struct nm_garg *g;
	struct nmport_d *nmd;
	/* these ought to be volatile, but they are
	 * only sampled and errors should not accumulate
	 */
	struct my_ctrs ctr;

	struct timespec tic, toc;
	int used;
	int completed;
	int cancel;
	int fd;
	int me;
	int affinity;
	pthread_t thread;
#ifdef NMLIB_EXTRA_SLOT
	struct netmap_slot *extra;
#else
	uint32_t *extra;
#endif
	uint32_t extra_cur;
	uint32_t extra_num;
	int *fdtable;
	int fdtable_siz;
#ifdef linux
	struct epoll_event evts[EPOLLEVENTS];
#else
	struct kevent	evts[EPOLLEVENTS];
#endif /* linux */
	void *opaque;
};

static inline void
nm_update_ctr(struct nm_targ *targ, int npkts, int nbytes)
{
	targ->ctr.pkts += npkts;
	targ->ctr.bytes += nbytes;
}

static struct nm_targ *targs;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(int sig)
{
	int i;

	(void)sig;	/* UNUSED */
	D("received control-C on thread %p", (void *)pthread_self());
	for (i = 0; i < global_nthreads; i++) {
		D("canceling targs[i] %p", &targs[i]);
		targs[i].cancel = 1;
	}
}


/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
	int ncpus;
#if defined (__FreeBSD__)
	int mib[2] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);
#elif defined(linux)
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_WIN32)
	{
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		ncpus = sysinfo.dwNumberOfProcessors;
	}
#else /* others */
	ncpus = 1;
#endif /* others */
	return (ncpus);
}

static void *
nm_thread(void *data)
{
	struct nm_targ *targ = (struct nm_targ *) data;
	struct nm_garg *g = targ->g;

	D("start, fd %d main_fd %d affinity %d",
			targ->fd, targ->g->main_fd, targ->affinity);
	if (setaffinity(targ->thread, targ->affinity))
		goto quit;
	g->td_body(data);

quit:
	targ->used = 0;
	return (NULL);
}

static int
nm_start_threads(struct nm_garg *g)
{
	int i;
	struct nm_targ *t;

	targs = (struct nm_targ *)calloc(g->nthreads, sizeof(*targs));
	if (!targs) {
		return -ENOMEM;
	}
	for (i = 0; i < g->nthreads; i++) {
		t = &targs[i];

		bzero(t, sizeof(*t));
		t->fd = -1;
		t->g = g;
		t->opaque = calloc(g->targ_opaque_len, 1);
		if (t->opaque == NULL) {
			continue;
		}

		if (g->dev_type == DEV_NETMAP) {
			t->nmd = nmport_clone(g->nmd);
			if (i > 0) {
				/* register one NIC only */
				char name[NETMAP_REQ_IFNAMSIZ], *suff;
				size_t nl = strlen(t->nmd->hdr.nr_name);

				if (asprintf(&suff, "-%d", i) < 0) {
					perror("asprintf");
					continue;
				}
				if (sizeof(name) < nl + strlen(suff) + 1) {
					D("no space %s", t->nmd->hdr.nr_name);
					continue;
				}
				/* let nmport_parse() handle errors */
				strlcpy((char *)mempcpy(name, t->nmd->hdr.nr_name, nl),
						suff, sizeof(name) - nl);
				free(suff);
				if (nmport_parse(t->nmd, name)) {
					D("failed in nmport_parse %s", name);
					continue;
				}
				if (nmport_open_desc(t->nmd)) {
					D("Unable to open %s: %s", t->g->ifname,
						strerror(errno));
					continue;
				}
				D("thread %d %u extra bufs at %u", i,
				    t->nmd->reg.nr_extra_bufs,
				    t->nmd->nifp->ni_bufs_head);
			} else {
				t->nmd = g->nmd;
			}
			t->fd = t->nmd->fd;

		}
		t->used = 1;
		t->me = i;
		if (g->affinity >= 0) {
			t->affinity = (g->affinity + i) % g->system_cpus;
		} else {
			t->affinity = -1;
		}
	}
	/* Wait for PHY reset. */
	D("Wait %d secs for phy reset", g->wait_link);
	sleep(g->wait_link);
	D("Ready...");

	D("nthreads %d", g->nthreads);
	for (i = 0; i < g->nthreads; i++) {
		t = &targs[i];
		if (pthread_create(&t->thread, NULL, &nm_thread, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
	return 0;
}

static void
nm_main_thread(struct nm_garg *g)
{
	int i;

	struct my_ctrs prev, cur;
	double delta_t;
	struct timeval tic, toc;

	prev.pkts = prev.bytes = prev.events = 0;
	gettimeofday(&prev.t, NULL);
	for (;;) {
		char b1[40], b2[40], b3[40], b4[100];
		uint64_t pps, usec;
		struct my_ctrs x;
		double abs;
		int done = 0;

		usec = wait_for_next_report(&prev.t, &cur.t,
				g->report_interval);

		cur.pkts = cur.bytes = cur.events = 0;
		cur.min_space = 0;
		if (usec < 10000) /* too short to be meaningful */
			continue;
		/* accumulate counts for all threads */
		for (i = 0; i < g->nthreads; i++) {
			cur.pkts += targs[i].ctr.pkts;
			cur.bytes += targs[i].ctr.bytes;
			cur.events += targs[i].ctr.events;
			cur.min_space += targs[i].ctr.min_space;
			targs[i].ctr.min_space = 99999;
			if (targs[i].used == 0) {
				done++;
			}
		}
		x.pkts = cur.pkts - prev.pkts;
		x.bytes = cur.bytes - prev.bytes;
		x.events = cur.events - prev.events;
		pps = (x.pkts*1000000 + usec/2) / usec;
		abs = (x.events > 0) ? (x.pkts / (double) x.events) : 0;

		if (!(g->options & OPT_PPS_STATS)) {
			strcpy(b4, "");
		} else {
			/* Compute some pps stats using a sliding window. */
			double ppsavg = 0.0, ppsdev = 0.0;
			int nsamples = 0;

			g->win[g->win_idx] = pps;
			g->win_idx = (g->win_idx + 1) % STATS_WIN;

			for (i = 0; i < STATS_WIN; i++) {
				ppsavg += g->win[i];
				if (g->win[i]) {
					nsamples ++;
				}
			}
			ppsavg /= nsamples;

			for (i = 0; i < STATS_WIN; i++) {
				if (g->win[i] == 0) {
					continue;
				}
				ppsdev += (g->win[i] - ppsavg) * (g->win[i] - ppsavg);
			}
			ppsdev /= nsamples;
			ppsdev = sqrt(ppsdev);

			snprintf(b4, sizeof(b4), "[avg/std %s/%s pps]",
				 norm(b1, ppsavg, normalize), norm(b2, ppsdev, normalize));
		}

		D("%spps %s(%spkts %sbps in %llu usec) %.2f avg_batch %d min_space",
			norm(b1, pps, normalize), b4,
			norm(b2, (double)x.pkts, normalize),
			norm(b3, (double)x.bytes*8, normalize),
			(unsigned long long)usec,
			abs, (int)cur.min_space);
		prev = cur;

		if (done == g->nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	cur.pkts = cur.bytes = cur.events = 0;
	/* final round */
	for (i = 0; i < g->nthreads; i++) {
		struct timespec t_tic, t_toc;
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		if (targs[i].used)
			pthread_join(targs[i].thread, NULL); /* blocking */
		if (g->dev_type == DEV_NETMAP) {
			nmport_close(targs[i].nmd);
			targs[i].nmd = NULL;
		} else if (targs[i].fd > 2) {
			close(targs[i].fd);
		}
		if (targs[i].completed == 0)
			D("ouch, thread %d exited with error", i);
		/*
		 * Collect threads output and extract information about
		 * how long it took to send all the packets.
		 */
		cur.pkts += targs[i].ctr.pkts;
		cur.bytes += targs[i].ctr.bytes;
		cur.events += targs[i].ctr.events;
		/* collect the largest start (tic) and end (toc) times,
		 * XXX maybe we should do the earliest tic, or do a weighted
		 * average ?
		 */
		t_tic = timeval2spec(&tic);
		t_toc = timeval2spec(&toc);
		if (!timerisset(&tic) || timespec_ge(&targs[i].tic, &t_tic))
			tic = timespec2val(&targs[i].tic);
		if (!timerisset(&toc) || timespec_ge(&targs[i].toc, &t_toc))
			toc = timespec2val(&targs[i].toc);

	}
	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
	if (g->td_type == TD_TYPE_SENDER)
		tx_output(&cur, delta_t, "Sent");
	else if (g->td_type == TD_TYPE_RECEIVER)
		tx_output(&cur, delta_t, "Received");
}

#define IF_OBJTOTAL	100
#define RING_OBJSIZE	33024
#define RING_OBJTOTAL	(IF_OBJTOTAL * 4)

static int
nm_start(struct nm_garg *g)
{
	int i, devqueues = 0;
	struct sigaction sa;
	sigset_t ss;
	int error;

	g->main_fd = -1;
	g->wait_link = 3;
	g->report_interval = 2000;
	g->cpus = g->system_cpus = i = system_ncpus();
	if (g->nthreads == 0)
		g->nthreads = 1;
	if (g->cpus < 0 || g->cpus > i) {
		D("%d cpus is too high, have only %d cpus", g->cpus, i);
		return -EINVAL;
	}
	D("running on %d cpus (have %d)", g->cpus, i);
	if (g->cpus == 0)
		g->cpus = i;

	if (g->dev_type != DEV_NETMAP)
		goto nonetmap;

	if (g->nthreads > 1) {
		/* register only one ring */
		if (strlen(g->ifname) + 2 > sizeof(g->ifname) - 1) {
			D("no space in g->ifname");
			return -EINVAL;
		}
		strlcat(g->ifname, "-0", sizeof(g->ifname));
	}

	if (g->nthreads > 1) {
		char conf[32];
		/* create multiple rings */
		snprintf(conf, sizeof(conf), "@conf:rings=%d", g->nthreads);
		strlcat(g->ifname, conf, sizeof(g->ifname));
	}
	if (g->extmem) {
		int i;
		size_t need_rings, need_rings_space, need_ifs, need_ifs_space,
		       buf_space, need_rings_bufs, buf_avail;
		char extm[128], kv[32];
		char *prms[4] = {(char *)",if-num=%u",
			(char *)",ring-num=%u", (char *)",ring-size=%u",
			(char *)",buf-num=%u"};
		u_int32_t prmvals[4];

		//= {IF_OBJTOTAL, RING_OBJTOTAL,
		//	RING_OBJSIZE, (uint32_t)g->extra_bufs + 320000};
		need_rings = 12 * g->nthreads;
		need_rings_space = (g->ring_objsize+64) * need_rings;
		need_rings_bufs = (g->ring_objsize+64)/sizeof(struct netmap_slot);
		need_ifs = g->nthreads * 2;
		need_ifs_space = (sizeof(struct netmap_if)+64) * need_ifs;
		buf_space = g->extmem_siz - need_rings_space - need_ifs_space;
		buf_avail = buf_space / 2048;
		buf_avail = (buf_avail/10) * 10;
		if (buf_avail < need_rings * need_rings_bufs) {
			D("only %lu bufs available", buf_avail);
			return -EINVAL;
		}
		g->extra_bufs = buf_avail - need_rings * need_rings_bufs;
		D("extmem_siz %lu need_ifs %lu need_rings %lu buf_avail %lu need_ring_bufs %lu extra_bufs %u",
				g->extmem_siz,
				need_ifs, need_rings, buf_avail,
				need_rings_bufs,
				g->extra_bufs
				);
		prmvals[0] = need_ifs;
		prmvals[1] = need_rings;
		prmvals[2] = g->ring_objsize;
		prmvals[3] = buf_avail;

		snprintf(extm, sizeof(extm), "@extmem:file=%s", g->extmem);
		for (i = 0; i < 4; i++) {
			snprintf(kv, sizeof(kv), prms[i], prmvals[i]);
			if (strlcat(extm, kv, sizeof(extm)) >= sizeof(extm)) {
				D("no space for %s", kv);
				return -EINVAL;
			}
		}
		if (strlcat(g->ifname, extm, sizeof(g->ifname)) >=
		    sizeof(g->ifname)) {
			D("no space for %s", extm);
			return -EINVAL;
		}
	}
	/* internally nmport_parse() */
	D("now nmport_open %s", g->ifname);
	//g->nmd = nmport_open(g->ifname);
	if (nmport_enable_option("offset"))
		goto out;
	g->nmd = nmport_prepare(g->ifname);
	if (g->nmd == NULL) {
		D("Unable to prepare %s: %s", g->ifname, strerror(errno));
		goto out;
	}
	if (g->extra_bufs) {
		g->nmd->reg.nr_extra_bufs = g->extra_bufs / g->nthreads;
	}
	error = nmport_open_desc(g->nmd);
	if (error) {
		D("Unable to open_desc %s: %s", g->ifname, strerror(errno));
		goto out;
	}
	D("got %u extra bufs at %u", g->nmd->reg.nr_extra_bufs,
			g->nmd->nifp->ni_bufs_head);

	g->main_fd = g->nmd->fd;
	D("mapped %lu at %p", (unsigned long)g->nmd->reg.nr_memsize>>10, g->nmd->mem);

	/* get num of queues in tx or rx */
	if (g->td_type == TD_TYPE_SENDER)
		devqueues = g->nmd->reg.nr_tx_rings;
	else
		devqueues = g->nmd->reg.nr_rx_rings;

	/* validate provided nthreads. */
	if (g->nthreads < 1 || g->nthreads > devqueues) {
		D("bad nthreads %d, have %d queues", g->nthreads, devqueues);
		// continue, fail later
	}

	if (g->verbose) {
		struct netmap_if *nifp = g->nmd->nifp;
		struct nmreq_register *reg = &g->nmd->reg;

		D("nifp at offset %lu, %d tx %d rx region %d",
		    reg->nr_offset, reg->nr_tx_rings, reg->nr_rx_rings,
		    reg->nr_mem_id);
		for (i = 0; i <= reg->nr_tx_rings; i++) {
			struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
			D("   TX%d at 0x%p slots %d", i,
			    (void *)((char *)ring - (char *)nifp), ring->num_slots);
		}
		for (i = 0; i <= reg->nr_rx_rings; i++) {
			struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
			D("   RX%d at 0x%p slots %d", i,
			    (void *)((char *)ring - (char *)nifp), ring->num_slots);
		}
	}

	if (g->ifname2[0] != '\0') {
		struct nmreq_header hdr;
		struct nmreq_vale_attach reg;
		int error;
		size_t l = strlen("pst:") + strlen(g->ifname2);

		if (l + 1 > sizeof(hdr.nr_name)) {
			g->main_fd = -1;
			nmport_close(g->nmd);
			goto nonetmap;
		}
		bzero(&hdr, sizeof(hdr));
		memcpy(hdr.nr_name, "pst:", strlen("pst:"));
		memcpy(hdr.nr_name + strlen(hdr.nr_name), g->ifname2,
		       strlen(g->ifname2));
		hdr.nr_name[l] = '\0';
		hdr.nr_version = NETMAP_API;
		hdr.nr_reqtype = NETMAP_REQ_PST_ATTACH;
		hdr.nr_body = (uintptr_t)&reg;

		bzero(&reg, sizeof(reg));
		reg.reg.nr_mem_id = g->nmd->reg.nr_mem_id;
		reg.reg.nr_mode = NR_REG_NIC_SW;
		error = ioctl(g->main_fd, NIOCCTRL, &hdr);
		if (error < 0) {
			perror("ioctl");
			D("failed in attach ioctl");
			nmport_close(g->nmd);
			g->main_fd = -1;
		}
	}

nonetmap:
	/* Print some debug information. */
	fprintf(stdout,
		"%s %s: %d queues, %d threads and %d cpus.\n", "Working on",
		g->ifname,
		devqueues,
		g->nthreads,
		g->cpus);
out:
	/* return -1 if something went wrong. */
	if (g->dev_type == DEV_NETMAP && g->main_fd < 0) {
		D("aborting");
		return -1;
	} else if (g->td_type == TD_TYPE_DUMMY) {
		D("this is dummy, %s and returning",
				g->main_fd < 0 ? "failed" : "success");
		return 0;
	}

	/* Install ^C handler. */
	global_nthreads = g->nthreads;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	/* block SIGINT now, so that all created threads will inherit the mask */
	if (pthread_sigmask(SIG_BLOCK, &ss, NULL) < 0) {
		D("failed to block SIGINT: %s", strerror(errno));
	}
	nm_start_threads(g);

	/* Install the handler and re-enable SIGINT for the main thread */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_h;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		D("failed to install ^C handler: %s", strerror(errno));
	}

	if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) < 0) {
		D("failed to re-enable SIGINT: %s", strerror(errno));
	}

	nm_main_thread(g);

	for (i = 0; i < g->nthreads; i++) {
		if (targs[i].opaque)
			free(targs[i].opaque);
	}
	free(targs);
	return 0;
}


#define IPV4TCP_HDRLEN	66
static inline int
netmap_sendmsg (struct nm_msg *msgp, void *data, size_t len)
{
	struct netmap_ring *ring = (struct netmap_ring *) msgp->txring;
	u_int cur = ring->cur;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF_OFFSET(ring, slot) + IPV4TCP_HDRLEN;

	memcpy (p, data, len);
	slot->len = IPV4TCP_HDRLEN + len;
	nm_pst_setfd(slot, nm_pst_getfd(msgp->slot));
	nm_pst_setdoff(slot, IPV4TCP_HDRLEN);
	ND("slot->buf_idx %u slot->len %u slot->fd %u", slot->buf_idx, slot->len, nm_pst_getfd(slot));
	ring->cur = ring->head = nm_ring_next(ring, cur);
	return len;
}

#define NM_NOEXTRA	(~0U)
/* curp is reset when it wraps */
static inline uint32_t
netmap_extra_next(struct nm_targ *t, size_t *curp, int wrap)
{
	uint32_t ret = t->extra_cur;

	if (unlikely(ret == t->extra_num)) {
		if (!wrap) {
			return NM_NOEXTRA;
		}
		ret = t->extra_cur = 0;
		if (curp) {
			*curp = 0;
		}
	}
	t->extra_cur++;
	return ret;
}

#ifdef NMLIB_EXTRA_SLOT
static int inline
netmap_copy_out(struct nm_msg *nmsg)
{
	struct netmap_ring *ring = nmsg->rxring;
	struct netmap_slot *slot = nmsg->slot;
	struct nm_targ *t = nmsg->targ;
	char *p, *ep;
	uint32_t i = slot->buf_idx;
	uint32_t extra_i = netmap_extra_next(t, (size_t *)&t->extra_cur, 0);
	u_int off = nm_pst_getdoff(slot);
	u_int len = slot->len;
	struct netmap_slot tmp = {.buf_idx = extra_i};

	if (extra_i == NM_NOEXTRA)
		return -1;
	NETMAP_WOFFSET(ring, &tmp, NETMAP_ROFFSET(ring, slot));
	p = NETMAP_BUF_OFFSET(ring, slot) + off;
	ep = NETMAP_BUF_OFFSET(ring, &tmp) + off;
	memcpy(ep, p, len - off);
	for (i = 0; i < len - off; i += 64) {
		_mm_clflush(ep + i);
	}
	return 0;
}

/* XXX should we update nmsg->slot to new one? */
static int inline
netmap_swap_out(struct nm_msg *nmsg)
{
	struct netmap_slot *slot = nmsg->slot, *extra, tmp;
	struct nm_targ *t = nmsg->targ;
	uint32_t extra_i = netmap_extra_next(t, (size_t *)&t->extra_cur, 0);

	if (extra_i == NM_NOEXTRA)
		return -1;
	tmp = *slot;
	extra = &t->extra[extra_i];
	ND("%u is swaped with extra[%d] %u", i, extra_i, extra->buf_idx);
	slot->buf_idx = extra->buf_idx;
	slot->flags |= NS_BUF_CHANGED;
	*extra = tmp;
	return 0;
}
#endif /* NMLIB_EXTRA_SLOT */

static inline void
free_if_exist(void *p)
{
	if (p != NULL)
		free(p);
}

static int fdtable_expand(struct nm_targ *t)
{
	int *newfds, fdsiz = sizeof(*t->fdtable);
	int nfds = t->fdtable_siz;

	newfds = (int *)calloc(fdsiz, nfds * 2);
	if (!newfds) {
		perror("calloc");
		return ENOMEM;
	}
	memcpy(newfds, t->fdtable, fdsiz * nfds);
	free(t->fdtable);
	//mm_mfence(); // XXX
	t->fdtable = newfds;
	t->fdtable_siz = nfds * 2;
	return 0;
}

#ifdef WITH_CLFLUSHOPT
static inline void
wait_ns(long ns)
{
	struct timespec cur, w;

	if (unlikely(ns > 10000 || ns < 100)) {
		RD(1, "ns %ld may not be apprepriate", ns);
	}
	clock_gettime(CLOCK_REALTIME, &cur);
	for (;;) {
		clock_gettime(CLOCK_REALTIME, &w);
		w = timespec_sub(w, cur);
		if (unlikely(w.tv_sec < 0)) // maybe too short interval
			continue;
		else if (w.tv_nsec >= ns || w.tv_sec > 0)
			break;
	}
}
#endif /* WITH_CLFLUSHOPT */

static void
do_nm_ring(struct nm_targ *t, int ring_nr)
{
	struct netmap_ring *rxr = NETMAP_RXRING(t->nmd->nifp, ring_nr);
	struct netmap_ring *txr = NETMAP_TXRING(t->nmd->nifp, ring_nr);
	u_int const rxtail = rxr->tail;
	u_int rxcur = rxr->cur;

	for (; rxcur != rxtail; rxcur = nm_ring_next(rxr, rxcur)) {
		struct netmap_slot *rxs = &rxr->slot[rxcur];
		struct nm_msg m = {.rxring = rxr, .txring = txr, .slot = rxs, .targ = t, .fd = nm_pst_getfd(rxs)} ;

		t->g->data(&m);
		nm_update_ctr(t, 1, rxs->len - nm_pst_getdoff(rxs));
	}
	rxr->head = rxr->cur = rxcur;
#ifdef WITH_CLFLUSHOPT
	_mm_mfence();
	if (t->g->emu_delay) {
		wait_ns(t->g->emu_delay);
	}
#endif /* WITH_CLFLUSHOPT */
}

static int inline
soopton(int fd, int level, int type)
{
	const int on = 1;

	if (setsockopt(fd, level, type, &on, sizeof(int)) < 0) {
		perror("setsockopt");
		return 1;
	}
	return 0;
}

static int inline
do_setsockopt(int fd)
{
	const int on = 1;
	struct linger sl = {.l_onoff = 1, .l_linger = 0};

	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)))
		return -EFAULT;
	if (soopton(fd, SOL_SOCKET, SO_REUSEADDR) ||
	    soopton(fd, SOL_SOCKET, SO_REUSEPORT) ||
#ifdef __FreeBSD__
	    //soopton(fd, SOL_SOCKET, SO_REUSEPORT_LB) ||
#endif /* __FreeBSD__ */
	    soopton(fd, SOL_TCP, TCP_NODELAY))
		return -EFAULT;
	if (ioctl(fd, FIONBIO, &on) < 0) {
		perror("ioctl");
		return -EFAULT;
	}
	return 0;
}

static int do_accept(struct nm_targ *t, int fd, int epfd)
{
#ifdef linux
	struct epoll_event ev;
#else
	struct kevent ev;
#endif
	struct sockaddr_in sin;
	socklen_t addrlen;
	int newfd;
	//int val = 1;
	while ((newfd = accept(fd, (struct sockaddr *)&sin, &addrlen)) != -1) {
		//if (ioctl(fd, FIONBIO, &(int){1}) < 0) {
		//	perror("ioctl");
		//}
		//int yes = 1;
		//setsockopt(newfd, SOL_SOCKET, SO_BUSY_POLL, &yes, sizeof(yes));
		if (newfd >= t->fdtable_siz) {
			if (fdtable_expand(t)) {
				close(newfd);
				break;
			}
		}
		memset(&ev, 0, sizeof(ev));
#ifdef linux
		ev.events = POLLIN;
		ev.data.fd = newfd;
		epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &ev);
#else
		EV_SET(&ev, newfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		kevent(epfd, &ev, 1, NULL, 0, NULL);
#endif
	}
	return 0;
}

#define DEFAULT_NFDS	65535
#define ARRAYSIZ(a)	(sizeof(a) / sizeof(a[0]))
static void *
netmap_worker(void *data)
{
	struct nm_targ *t = (struct nm_targ *) data;
	struct nm_garg *g = t->g;
	struct nmport_d *nmd = t->nmd;
	struct pollfd pfd[2] = {{ .fd = t->fd }}; // XXX make variable size
	struct nmreq_header hdr = g->nm_hdr;
#if DEBUG_SOCKET
	int acceptfds[DEFAULT_NFDS];

	bzero(acceptfds, sizeof(acceptfds));
#endif /* DEBUG_SOCKET */

	if (g->thread) {
		int error = g->thread(t);
		if (error) {
			D("error on t->thread");
			goto quit;
		}
	}

	/* allocate fd table */
	t->fdtable = (int *)calloc(sizeof(*t->fdtable), DEFAULT_NFDS);
	if (!t->fdtable) {
		perror("calloc");
		goto quit;
	}
	t->fdtable_siz = DEFAULT_NFDS;

	/* import extra buffers */
	if (g->dev_type == DEV_NETMAP) {
		const struct nmreq_register *reg = &nmd->reg;
		const struct netmap_if *nifp = nmd->nifp;
		//const struct netmap_ring *any_ring = nmd->some_ring;
		const struct netmap_ring *any_ring = NETMAP_TXRING(nmd->nifp, nmd->first_tx_ring);
		uint32_t next = nifp->ni_bufs_head;
		const u_int n = reg->nr_extra_bufs;
		uint32_t i;

		D("have %u extra buffers from %u ring %p", n, next, any_ring);
#ifdef NMLIB_EXTRA_SLOT
		t->extra = (struct netmap_slot *)calloc(sizeof(*t->extra), n);
#else
		t->extra = (uint32_t *)calloc(sizeof(*t->extra), n);
#endif
		if (!t->extra) {
			perror("calloc");
			goto quit;
		}
		for (i = 0; i < n && next; i++) {
			char *p;
			struct netmap_slot tmp = any_ring->slot[0];
			tmp.ptr = 0; // XXX
#ifdef NMLIB_EXTRA_SLOT
			t->extra[i].buf_idx = next;
#else
			t->extra[i] = next;
#endif
			tmp.buf_idx = next;
			p = NETMAP_BUF_OFFSET(any_ring, &tmp);
			next = *(uint32_t *)p;
		}
		t->extra_num = i;
		D("imported %u extra buffers", i);
	} else if (g->dev_type == DEV_SOCKET) {
#ifdef linux
		struct epoll_event ev;

		t->fd = epoll_create1(EPOLL_CLOEXEC);
		if (t->fd < 0) {
			perror("epoll_create1");
			t->cancel = 1;
			goto quit;
		}

		/* XXX make variable ev num. */
		bzero(&ev, sizeof(ev));
		ev.events = POLLIN;
		ev.data.fd = g->fds[0];
		if (epoll_ctl(t->fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
			perror("epoll_ctl");
			t->cancel = 1;
			goto quit;
		}
#else /* !linux */
		struct kevent ev;

		t->fd = kqueue();
		if (t->fd < 0) {
			perror("kqueue");
			t->cancel = 1;
			goto quit;
		}
		EV_SET(&ev, g->fds[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(t->fd, &ev, 1, NULL, 0, NULL)) {
			perror("kevent");
			t->cancel = 1;
			goto quit;
		}
#endif /* linux */
	}

	while (!t->cancel) {
		struct nm_msg msg;

		if (g->dev_type == DEV_NETMAP) {
			u_int first_ring = nmd->first_rx_ring;
			u_int last_ring = nmd->last_rx_ring;
			u_int i;
			struct netmap_slot slot;
			int n;

			pfd[0].fd = t->fd;
			pfd[0].events = POLLIN;
			/* XXX make safer... */
			for (i = 0; i < t->g->fdnum; i++) {
				pfd[i+1].fd = t->g->fds[i];
				pfd[i+1].events = POLLIN;
			}
			n = poll(pfd, i+1, t->g->polltimeo);
			if (n < 0) {
				perror("poll");
				goto quit;
			}
			/*
			 * check listen sockets
			 */
			for (i = 1; i <= t->g->fdnum; i++) {
				struct sockaddr_storage tmp;
				struct sockaddr *sa = (struct sockaddr *)&tmp;
				int newfd;
				socklen_t len = sizeof(tmp);
				int e;
				struct nmreq_pst_fd_reg fdr;

				if (!(pfd[i].revents & POLLIN))
					continue;
				newfd = accept(pfd[i].fd, sa, &len);
				if (newfd < 0) {
					RD(1, "accept error");
					/* ignore this socket */
					continue;
				}

				fdr.fd = newfd;
				hdr.nr_body = (uintptr_t)&fdr;
				e = ioctl(t->fd, NIOCCTRL, &hdr);
				if (e) {
					perror("ioctl");
					if (errno == ENOTCONN) {
						D("ENOTCONN closing newfd %d", newfd);
						close(newfd);
					} else if (errno == ENOMEM) {
						D("ENOMEM closing newfd %d", newfd);
						close(newfd);
close_pfds:
						for (i = 1; i < g->fdnum; i++) {
							close(pfd[i].fd);
						}
						goto quit;
					} else {
						D("undefined error %d", errno);
					}
				}
				if (unlikely(newfd >= t->fdtable_siz)) {
					if (fdtable_expand(t)) {
						goto close_pfds;
					}
				}
				nm_pst_setfd(&slot, newfd);
				msg.slot = &slot;
				if (g->connection)
					g->connection(&msg);
#if DEBUG_SOCKET
				acceptfds[newfd] = newfd;
#endif
			}

			/* check the netmap fd */
			if (!(pfd[0].revents & POLLIN)) {
				continue;
			}

			for (i = first_ring; i <= last_ring; i++) {
				do_nm_ring(t, i);
			}
		} else if (g->dev_type == DEV_SOCKET) {
			int i, nfd, epfd = t->fd;
			int nevts = ARRAYSIZ(t->evts);
#ifdef linux
			struct epoll_event *evts = t->evts;

			nfd = epoll_wait(epfd, evts, nevts, g->polltimeo);
			if (nfd < 0) {
				perror("epoll_wait");
				goto quit;
			}
#else
			struct kevent *evts = t->evts;

			nfd = kevent(epfd, NULL, 0, evts, nevts, g->polltimeo_ts);
#endif
			for (i = 0; i < nfd; i++) {
				u_int j;
#ifdef linux
				int fd = evts[i].data.fd;
#else
				int fd = evts[i].ident;
#endif

				for (j = 0; j < t->g->fdnum; j++) {
					if (fd != t->g->fds[j]) {
						continue;
					}
					do_accept(t, fd, epfd);
					break;
				}
				if (j != t->g->fdnum)
					continue;
				msg.fd = fd;
				msg.targ = t;
				g->read(&msg);
			}
		}
	}
#if DEBUG_SOCKET
	if (t->cancel) {
		int i;
		D("canceled, closing sockets");
		for (i = 0; i < DEFAULT_NFDS; i++) {
			close(acceptfds[i]);
		}
	}
#endif /* DEBUG_SOCKET */
quit:
	free_if_exist(t->extra);
	free_if_exist(t->fdtable);
	return (NULL);
}

// XXX inline just to scilence compiler
static inline void *
do_mmap(int fd, size_t len)
{
	void *p;

	if (lseek(fd, len -1, SEEK_SET) < 0) {
		perror("lseek");
		return NULL;
	}
	if (write(fd, "", 1) != 1) {
		perror("write");
		return NULL;
	}
	p = mmap(0, len, PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	return p;
}


struct netmap_events {
	int (*data)(struct nm_msg *);
	int (*read)(struct nm_msg *);
	void (*connection)(struct nm_msg *);
	int (*thread)(struct nm_targ *targ);
};

/*
 * Highest level abstraction mainly for PASTE
 *
 * ifname: netmap port name with prefix (e.g., pst:)
 *         and suffix (e.g., @/mnt/pm/x).
 * ret: pointer to nm_garg allocated
 * error: error value
 * fds: array of listening file descriptors monitored by poll().
 * fdnum: number of file descriptors in fds.
 */
static void
netmap_eventloop(const char *name, char *ifname, void **ret, int *error, int *fds, int fdnum,
	struct netmap_events *e, struct nm_garg *args, void *garg_private)
{
	struct nm_garg *g = (struct nm_garg *)calloc(1, sizeof(*g));
	int i;
	struct nmreq_header hdr;
	struct nmctx ctx;
	const char *namep = name;

	*error = 0;
	if (!g) {
		perror("calloc");
		*error = -ENOMEM;
		return;
	}

#define B(a, v, l, h, d) \
		(!(a) ? d : (((a)->v >= l && (a)->v <= h) ? (a)->v : d))
	g->polltimeo = B(args, polltimeo, 0, 2000, 1000);
	g->dev_type = B(args, dev_type, 0, DEV_SOCKET, DEV_SOCKET);
	g->nthreads = B(args, nthreads, 1, 128, 1);
	g->affinity = B(args, affinity, -1, 128, -1);
	g->extmem_siz = B(args, extmem_siz, 0, 8192000000000UL, 0);
	g->extra_bufs = B(args, extra_bufs, 0, 4096000000UL, 0);
	g->ring_objsize = B(args, ring_objsize, RING_OBJSIZE/4,
				RING_OBJSIZE*2, RING_OBJSIZE);
#undef B
	g->targ_opaque_len = args ? args->targ_opaque_len : 0;
	g->nmr_config = args ? args->nmr_config : NULL;
	g->extmem = args->extmem;
	g->td_body = netmap_worker;
	g->connection = e->connection;
	g->data = e->data;
	g->read = e->read;
	g->thread = e->thread;
	g->fds = fds;
	g->fdnum = fdnum;
#ifdef __FreeBSD__
	g->polltimeo_ts = args->polltimeo_ts;
#endif /* FreeBSD */
#ifdef WITH_CLFLUSHOPT
	g->emu_delay = args->emu_delay;
#endif /* WITH_CLFLUSHOPT */
	*ret = g;

	for (i = 0; i < fdnum; i++) {
		if (do_setsockopt(fds[i]) < 0) {
			perror("setsockopt");
			*error = -EFAULT;
			return;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	/* Ensure correct name. Suffix may be added in nm_start() later */
	bzero(&ctx, sizeof(ctx));
	if (nmreq_header_decode(&namep, &hdr, &ctx) < 0) {
		*error = -EINVAL;
		return;
	}

	strncpy(g->ifname, name, sizeof(g->ifname) - 1);
	D("name %s g->ifname %s ifname %s", name, g->ifname, ifname);
	if (ifname && strlen(ifname)) {
		struct nmreq_header *h = &g->nm_hdr;

		strncpy(g->ifname2, ifname, sizeof(g->ifname2));
		/* pre-initialize ifreq for accept() */
		bzero(h, sizeof(*h));
		memcpy(h->nr_name, hdr.nr_name, sizeof(h->nr_name));
		h->nr_version = NETMAP_API;
		h->nr_reqtype = NETMAP_REQ_PST_FD_REG;
		// nr_body is per thread
	}
	g->garg_private = garg_private;
	*error = nm_start(g);
}

/*
 * General routine to write data to netmap buffer(s).
 * Data is written after `off` except for the first chunk, which
 * is written after `off0` bytes. This is useful when the caller writes
 * an app-level header beforehand
 */
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
const u_int DEFAULT_MTU = 1420; // maximum option space
static int
nm_write(struct netmap_ring *ring, const char *data,
		size_t len, int off0, int fd)
{
	u_int const tail = ring->tail;
	u_int cur = ring->cur;
	size_t copied = 0;
	const u_int space = nm_ring_space(ring);
	size_t space_bytes;
	const int off = IPV4TCP_HDRLEN;

	//if (unlikely(off + off0 > DEFAULT_MTU)) {
	//	D("total offset must be < %u", DEFAULT_MTU);
	//} else if (unlikely(off > DEFAULT_MTU)) {
	//	D("offset must be < %u", DEFAULT_MTU);
	//}

	space_bytes = (DEFAULT_MTU - off) * space - off0;
	if (unlikely(!space || space_bytes < len)) {
		RD(1, "no space (%d slots)", space);
		return -1;
	}

	while (likely(cur != tail) && copied < len) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF_OFFSET(ring, slot) + off + off0;
		int l = min(DEFAULT_MTU - off0, len - copied);

		if (data) {
			nm_pkt_copy(data + copied, p, l);
		}
		slot->len = off + off0 + l;
		nm_pst_setdoff(slot, off);
		nm_pst_setfd(slot, fd);
		copied += l;
		off0 = 0;
		cur = nm_ring_next(ring, cur);
	}
	ring->cur = ring->head = cur;
	return len;
}

static inline struct netmap_slot *
nm_zcopy(struct netmap_ring *txr, struct netmap_slot *slot)
{
	struct netmap_slot tmp, *txs = NULL;

	if (unlikely(nm_ring_space(txr) == 0)) {
		return NULL;
	}
	txs = &txr->slot[txr->cur];
	if (likely(slot != txs)) {
		tmp = *txs;
		*txs = *slot;
		txs->flags |= NS_BUF_CHANGED;
		*slot = tmp;
		slot->flags |= NS_BUF_CHANGED; // might be on-ring
	}
	txr->cur = txr->head = nm_ring_next(txr, txr->cur);
	return txs;
}
#endif /* _NMLIB_H_ */
