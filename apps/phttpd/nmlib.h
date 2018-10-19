#ifndef _NMLIB_H_
#define _NMLIB_H_
#include <math.h>
#ifdef __FreeBSD__
#include<sys/cpuset.h>
#include <pthread_np.h> /* pthread w/ affinity */
#endif
#include <x86intrin.h>
#include<net/netmap.h>
#include<net/netmap_user.h>
#include<ctrs.h>
#include<pthread.h>
#include<sys/sysctl.h>	/* sysctl */
#include <netinet/tcp.h>	/* SOL_TCP */
#include <sys/poll.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif /* __linux__ */

/* prototypes for libnetmap/nmreq.c */
const char *nmreq_header_decode(const char *, struct nmreq_header *);
struct nm_desc * nmreq_open(const char *, uint64_t, const struct nm_desc *);
int nmreq_close(struct nm_desc *);

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

int normalize = 1;

#define VIRT_HDR_1	10	/* length of a base vnet-hdr */
#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
#define EPOLLEVENTS 2048
#define DEBUG_SOCKET	1
#ifndef linux
#define SOL_TCP	SOL_SOCKET
#define fallocate(a, b, c, d)	posix_fallocate(a, c, d)
#endif

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
	int size;

	if (cur->pkts == 0) {
		printf("%s nothing.\n", msg);
		return;
	}

	size = (int)(cur->bytes / cur->pkts);

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
};

struct nm_garg {
	char ifname[NETMAP_REQ_IFNAMSIZ]; // must be here
	struct nm_desc *nmd;
	void *(*td_body)(void *);
	int nthreads;
	int affinity;
	int dev_type;
	int td_type;
	int main_fd;
	int system_cpus;
	int cpus;
	int virt_header;	/* send also the virt_header */
	int extra_bufs;		/* goes in nr_arg3 */
	uint64_t extmem_siz;
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

	struct nm_ifreq ifreq;
	void (*data)(struct nm_msg *);
	void (*connection)(struct nm_msg *);
	int (*read)(int, struct nm_targ *);
	int (*thread)(struct nm_targ *);
	int *fds;
	int fdnum;
	int emu_delay;
	void *garg_private;
	char ifname2[NETMAP_REQ_IFNAMSIZ];
};

struct nm_targ {
	struct nm_garg *g;
	struct nm_desc *nmd;
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
	struct nm_ifreq ifreq;
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

static int
nm_parse_nmr_config(const char* conf, struct nmreq_register *reg)
{
	char *w, *tok;
	int i, v;

	reg->nr_tx_rings = reg->nr_rx_rings = 0;
	reg->nr_tx_slots = reg->nr_rx_slots = 0;
	if (conf == NULL || ! *conf)
		return 0;
	w = strdup(conf);
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			reg->nr_tx_slots = reg->nr_rx_slots = v;
			break;
		case 1:
			reg->nr_rx_slots = v;
			break;
		case 2:
			reg->nr_tx_rings = reg->nr_rx_rings = v;
			break;
		case 3:
			reg->nr_rx_rings = v;
			break;
		default:
			D("ignored config: %s", tok);
			break;
		}
	}
	D("txr %d txd %d rxr %d rxd %d",
			reg->nr_tx_rings, reg->nr_tx_slots,
			reg->nr_rx_rings, reg->nr_rx_slots);
	free(w);
	return (reg->nr_tx_rings || reg->nr_tx_slots ||
                        reg->nr_rx_rings || reg->nr_rx_slots) ?
		NM_OPEN_RING_CFG : 0;
}

static void
get_vnet_hdr_len(struct nm_garg *g)
{
	struct nmreq_header hdr;
	struct nmreq_port_hdr req = {0};
	int err;

	bzero(&hdr, sizeof(hdr));
	hdr.nr_body = (uintptr_t)&req;
	strncpy(hdr.nr_name, g->nmd->nr.hdr.nr_name, sizeof(hdr.nr_name));
	hdr.nr_version = NETMAP_API;
	hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_GET;

	err = ioctl(g->main_fd, NIOCCTRL, &hdr);
	if (err) {
		D("Unable to get virtio-net header length");
		return;
	}
	g->virt_header = req.nr_hdr_len;
	if (g->virt_header) {
		D("Port requires virtio-net header, length = %d",
		  g->virt_header);
	}
}

static void
set_vnet_hdr_len(struct nm_garg *g)
{
	struct nmreq_header hdr;
	struct nmreq_port_hdr req = {0};
	int err, l = g->virt_header;

	if (l == 0)
		return;
	bzero(&hdr, sizeof(hdr));
	hdr.nr_body = (uintptr_t)&req;
	strncpy(hdr.nr_name, g->nmd->nr.hdr.nr_name, sizeof(hdr.nr_name));
	hdr.nr_version = NETMAP_API;
	hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;

	err = ioctl(g->main_fd, NIOCCTRL, &hdr);
	if (err) {
		D("Unable to set virtio-net header length %d", l);
	}
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

	targs = calloc(g->nthreads, sizeof(*targs));
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
			/* copy, we overwrite ringid */
			struct nm_desc nmd = *g->nmd;
			uint64_t nmd_flags = 0;
			nmd.self = &nmd;

			if (i > 0) {
				/* the first thread uses the fd opened by the
				 * main thread, the other threads re-open
				 * /dev/netmap
				 */
				if (g->nthreads > 1) {
					nmd.nr.reg.nr_flags =
					    g->nmd->nr.reg.nr_flags & ~NR_REG_MASK;
					nmd.nr.reg.nr_mode = NR_REG_ONE_NIC;
					nmd.nr.reg.nr_ringid = i;
					if (nmd.nr.reg.nr_extra_bufs) {
						D("setting nmd_flags NM_OPEN_EXTRA for %u", nmd.nr.reg.nr_extra_bufs);
						nmd_flags |= NM_OPEN_EXTRA;
					}
				}
				/* Only touch one of the rings
				 * (rx is already ok)
				 */
				if (g->td_type == TD_TYPE_RECEIVER)
					nmd_flags |= NETMAP_NO_TX_POLL;

				/* register interface. Override ifname and ringid etc. */
				t->nmd = nmreq_open(t->g->ifname, nmd_flags
						| NM_OPEN_IFNAME
						| NM_OPEN_NO_DECODE
						| NM_OPEN_NO_MMAP, &nmd);
				if (t->nmd == NULL) {
					D("Unable to open %s: %s", t->g->ifname,
						       	strerror(errno));
					continue;
				}
				D("got %u extra bufs at %u",
				    t->nmd->nr.reg.nr_extra_bufs,
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
		char b1[40], b2[40], b3[40], b4[70];
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
			nmreq_close(targs[i].nmd);
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
	struct nm_desc base_nmd;
	struct sigaction sa;
	sigset_t ss;
	u_int flags;

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

	if (g->virt_header != 0 && g->virt_header != VIRT_HDR_1
			&& g->virt_header != VIRT_HDR_2) {
		D("bad virtio-net-header length");
		return -EINVAL;
	}

	bzero(&base_nmd, sizeof(base_nmd));

	nm_parse_nmr_config(g->nmr_config, &base_nmd.nr.reg);
	if (g->extra_bufs) {
		base_nmd.nr.reg.nr_extra_bufs = g->extra_bufs / g->nthreads;
	}
	base_nmd.nr.reg.nr_flags |= NR_ACCEPT_VNET_HDR;
	/* NM_OPEN_IFNAME overrides nmreq_register_decode() result */
	base_nmd.nr.reg.nr_mode = NR_REG_ALL_NIC;

	/*
	 * Open the netmap device using nmreq_open().
	 *
	 * protocol stack and may cause a reset of the card,
	 * which in turn may take some time for the PHY to
	 * reconfigure. We do the open here to have time to reset.
	 */
	flags = NM_OPEN_IFNAME | NM_OPEN_RING_CFG;
	flags |= NM_OPEN_ARG1 | NM_OPEN_MEMID | NM_OPEN_EXTRA;
	if (g->nthreads > 1) {
		base_nmd.nr.reg.nr_flags &= ~NR_REG_MASK;
		base_nmd.nr.reg.nr_mode = NR_REG_ONE_NIC;
		base_nmd.nr.reg.nr_ringid = 0;
	}

	base_nmd.self = &base_nmd;
	memcpy(base_nmd.nr.hdr.nr_name, g->ifname,
			sizeof(base_nmd.nr.hdr.nr_name));
	if (g->extmem) {
		struct nmreq_pools_info *pi = &base_nmd.nr.ext.nro_info;

		pi->nr_memsize = g->extmem_siz;
		pi->nr_if_pool_objtotal = IF_OBJTOTAL;
		pi->nr_ring_pool_objtotal = RING_OBJTOTAL;
		pi->nr_ring_pool_objsize = RING_OBJSIZE;
		pi->nr_buf_pool_objtotal = g->extra_bufs + 320000;
		strncat(g->ifname, "@", 1);
		strncat(g->ifname, g->extmem, strlen(g->extmem));
		D("requesting buf_pool_objtotal %u (extra %u)",
				pi->nr_buf_pool_objtotal, g->extra_bufs);
	}

	g->nmd = nmreq_open(g->ifname, flags, &base_nmd);
	if (g->nmd == NULL) {
		D("Unable to open %s: %s", g->ifname, strerror(errno));
		goto out;
	}
	ND("got %u extra bufs at %u", g->nmd->nr.reg.nr_extra_bufs,
			g->nmd->nifp->ni_bufs_head);

	g->main_fd = g->nmd->fd;
	D("mapped %lu at %p", (unsigned long)g->nmd->nr.reg.nr_memsize>>10, g->nmd->mem);

	if (g->virt_header) {
		/* Set the virtio-net header length, since the user asked
		 * for it explicitely. */
		set_vnet_hdr_len(g);
	} else {
		/* Check whether the netmap port we opened requires us to send
		 * and receive frames with virtio-net header. */
		get_vnet_hdr_len(g);
	}

	/* get num of queues in tx or rx */
	if (g->td_type == TD_TYPE_SENDER)
		devqueues = g->nmd->nr.reg.nr_tx_rings;
	else
		devqueues = g->nmd->nr.reg.nr_rx_rings;

	/* validate provided nthreads. */
	if (g->nthreads < 1 || g->nthreads > devqueues) {
		D("bad nthreads %d, have %d queues", g->nthreads, devqueues);
		// continue, fail later
	}

	if (g->verbose) {
		struct netmap_if *nifp = g->nmd->nifp;
		struct nmreq_register *reg = &g->nmd->nr.reg;

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

		bzero(&hdr, sizeof(hdr));
		strncpy(hdr.nr_name, "stack:", sizeof(hdr.nr_name));
		strncat(hdr.nr_name, g->ifname2,
			sizeof(hdr.nr_name) - strlen("stack:"));
		hdr.nr_version = NETMAP_API;
		hdr.nr_reqtype = NETMAP_REQ_VALE_ATTACH;
		hdr.nr_body = (uintptr_t)&reg;

		bzero(&reg, sizeof(reg));
		reg.reg.nr_mem_id = g->nmd->nr.reg.nr_mem_id;
		reg.reg.nr_mode = NR_REG_NIC_SW;
		error = ioctl(g->main_fd, NIOCCTRL, &hdr);
		if (error < 0) {
			perror("ioctl");
			D("failed in attach ioctl");
			nmreq_close(g->nmd);
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
	struct nm_targ *t = msgp->targ;
	struct netmap_ring *ring = (struct netmap_ring *) msgp->txring;
	u_int cur = ring->cur;
	int virt_header = t->g->virt_header;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF(ring, slot->buf_idx) + virt_header + IPV4TCP_HDRLEN;

	memcpy (p, data, len);
	slot->len = virt_header + IPV4TCP_HDRLEN + len;
    	slot->fd = msgp->slot->fd;
    	slot->offset = IPV4TCP_HDRLEN;
	ND("slot->buf_idx %u slot->len %u slot->fd %u", slot->buf_idx, slot->len, slot->fd);
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
	u_int off = t->g->virt_header + slot->offset;
	u_int len = slot->len - off;

	if (extra_i == NM_NOEXTRA)
		return -1;
	p = NETMAP_BUF(ring, i) + off;
	ep = NETMAP_BUF(ring, extra_i) + off;
	memcpy(ep, p, len);
	for (i = 0; i < len; i += 64) {
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

	newfds = calloc(fdsiz, nfds * 2);
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
		struct nm_msg m = {.rxring = rxr, .txring = txr, .slot = rxs, .targ = t} ;

		/*
		bzero(&m, sizeof(m));
		m.rxring = rxr;
		m.txring = txr;
		m.slot = rxs;
		m.targ = t;
		*/
		t->g->data(&m);
		nm_update_ctr(t, 1, rxs->len - t->g->virt_header - rxs->offset);
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
	if (setsockopt(fd, level, type, &(int){1}, sizeof(int)) < 0) {
		perror("setsockopt");
		return 1;
	}
	return 0;
}

static int inline
do_setsockopt(int fd)
{
	if (soopton(fd, SOL_SOCKET, SO_REUSEADDR) ||
	    soopton(fd, SOL_SOCKET, SO_REUSEPORT) ||
#ifdef __FreeBSD__
	    //soopton(fd, SOL_SOCKET, SO_REUSEPORT_LB) ||
#endif /* __FreeBSD__ */
	    soopton(fd, SOL_TCP, TCP_NODELAY))
		return -EFAULT;
	if (ioctl(fd, FIONBIO, &(int){1}) < 0) {
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
	struct nm_desc *nmd = t->nmd;
	struct pollfd pfd[2] = {{ .fd = t->fd }}; // XXX make variable size
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
	t->fdtable = calloc(sizeof(*t->fdtable), DEFAULT_NFDS);
	if (!t->fdtable) {
		perror("calloc");
		goto quit;
	}
	t->fdtable_siz = DEFAULT_NFDS;

	/* import extra buffers */
	if (g->dev_type == DEV_NETMAP) {
		const struct nmreq_register *reg = &nmd->nr.reg;
		const struct netmap_if *nifp = nmd->nifp;
		const struct netmap_ring *any_ring = nmd->some_ring;
		uint32_t next = nifp->ni_bufs_head;
		const u_int n = reg->nr_extra_bufs;
		uint32_t i;

		D("have %u extra buffers from %u ring %p", n, next, any_ring);
		t->extra = calloc(sizeof(*t->extra), n);
		if (!t->extra) {
			perror("calloc");
			goto quit;
		}
		for (i = 0; i < n && next; i++) {
			char *p;
#ifdef NMLIB_EXTRA_SLOT
			t->extra[i].buf_idx = next;
#else
			t->extra[i] = next;
#endif
			p = NETMAP_BUF(any_ring, next);
			next = *(uint32_t *)p;
		}
		t->extra_num = i;
		D("imported %u extra buffers", i);
		t->ifreq = g->ifreq;
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
		if (g->dev_type == DEV_NETMAP) {
			u_int first_ring = nmd->first_rx_ring;
			u_int last_ring = nmd->last_rx_ring;
			u_int i;
			struct nm_msg msg;
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
				struct nm_ifreq *ifreq = &g->ifreq;
				int newfd;
				socklen_t len = sizeof(tmp);

				if (!(pfd[i].revents & POLLIN))
					continue;
				newfd = accept(pfd[i].fd, sa, &len);
				if (newfd < 0) {
					RD(1, "accept error");
					/* ignore this socket */
					continue;
				}
				memcpy(ifreq->data, &newfd, sizeof(newfd));
				if (ioctl(t->fd, NIOCCONFIG, ifreq)) {
					if (errno == ENOTCONN) {
						perror("ioctl");
						close(newfd);
					} else if (errno == ENOMEM) {
						perror("ioctl");
						close(newfd);
close_pfds:
						for (i = 1; i < g->fdnum; i++) {
							close(pfd[i].fd);
						}
						goto quit;
					}
				}
				if (unlikely(newfd >= t->fdtable_siz)) {
					if (fdtable_expand(t)) {
						goto close_pfds;
					}
				}
				slot.fd = newfd;
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
				int j;
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
				g->read(fd, t);
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
static inline char *
do_mmap(int fd, size_t len)
{
	char *p;

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
	void (*data)(struct nm_msg *);
	int (*read)(int, struct nm_targ *);
	void (*connection)(struct nm_msg *);
	int (*thread)(struct nm_targ *targ);
};

/*
 * Highest level abstraction mainly for PASTE
 *
 * ifname: netmap port name with prefix (e.g., stack:)
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
	struct nm_garg *g = calloc(1, sizeof(*g));
	int i;
	struct nmreq_header hdr;

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
	if (nmreq_header_decode(name, &hdr) == NULL) {
		*error = -EINVAL;
		return;
	}
	strncpy(g->ifname, name, sizeof(g->ifname));

	if (ifname && strlen(ifname)) {
		struct nm_ifreq *r = &g->ifreq;

		strncpy(g->ifname2, ifname, sizeof(g->ifname2));
		/* pre-initialize ifreq for accept() */
		bzero(r, sizeof(*r));
		strncpy(r->nifr_name, hdr.nr_name, sizeof(r->nifr_name));
	}
	g->garg_private = garg_private;
	*error = nm_start(g);
}
#endif /* _NMLIB_H_ */
