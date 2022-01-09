/*
 * Copyright (C) 2018 Michio Honda
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
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

#if defined(__FreeBSD__)
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/socketvar.h>	/* struct socket */
#include <sys/socket.h> /* sockaddrs */
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>	/* struct ether_header */
#include <netinet/in.h>		/* IPPROTO_UDP */
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/kthread.h>	/* kthread_add() */

#elif defined(linux)
#include "bsd_glue.h"
#define ENOTSUP ENOTSUPP
#else
#error Unsupported platform
#endif /* unsupported */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>

#ifdef WITH_PASTE
#include <net/netmap_paste.h>

int paste_host_batch = 1;
static int paste_extra = 2048;
int paste_usrrcv = 0;
int paste_optim_sendpage = 0;
SYSBEGIN(vars_paste);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_host_batch, CTLFLAG_RW, &paste_host_batch, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_extra, CTLFLAG_RW, &paste_extra, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_usrrcv, CTLFLAG_RW, &paste_usrrcv, 1 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_optim_sendpage, CTLFLAG_RW, &paste_optim_sendpage, 1 , "");
SYSEND;

static int netmap_pst_bwrap_intr_notify(struct netmap_kring *kring, int flags);
static inline void
pst_swap(struct netmap_slot *s, struct netmap_slot *d)
{
	struct netmap_slot tmp = *d;
	*d = *s;
	*s = tmp;
	s->flags |= NS_BUF_CHANGED;
	d->flags |= NS_BUF_CHANGED;
}

static inline u_int
rollup(struct netmap_kring *kring, u_int from, u_int to, u_int *n)
{
	u_int i, m = 0, lim = kring->nkr_num_slots - 1;

	for (i = from; i != to; m++) {
		struct netmap_slot *slot = &kring->ring->slot[i];
		struct nmcb *cb = NMCB_SLT(kring->na, slot);

		i = nm_next(i, lim);
		if (nmcb_valid(cb) && nmcb_rstate(cb) != MB_NOREF) {
			i = nm_prev(i, lim);
			break;
		}
	}
	if (n)
		*n = m;
	return i;
}

static inline struct netmap_pst_adapter *
topna(struct netmap_adapter *na)
{
	return (struct netmap_pst_adapter *)na;
}

static inline struct netmap_vp_adapter *
tovpna(struct netmap_adapter *na)
{
	return (struct netmap_vp_adapter *)na;
}

struct netmap_adapter *
pst_na(const struct netmap_adapter *port)
{
	const struct netmap_vp_adapter *vpna =
		(const struct netmap_vp_adapter *)port;
	return likely(vpna) ? &vpna->na_bdg->bdg_ports[0]->up : NULL;
}

static inline int
is_host(struct netmap_adapter *na)
{
	return na->nm_register == NULL;
}

#define for_bdg_ports(i, b) \
	        for ((i) = 0; (i) < (b)->bdg_active_ports; (i)++)

#define NM_PST_MAXRINGS	64
#define NM_PST_RINGSIZE	1024
#define NM_PST_MAXSLOTS	2048
#define NM_PST_FD_MAX	65535
#define NM_PST_BATCH_MAX	2048

/* Buffers sorted by file descriptors */
struct pst_fdt_q {
	uint32_t fq_head;
	uint32_t fq_tail;
};

struct pst_fdt {
	uint16_t nfds;
	uint16_t npkts;
	struct pst_fdt_q fde[NM_PST_FD_MAX];
	uint32_t tmp[NM_PST_BATCH_MAX];
	uint32_t fds[NM_PST_BATCH_MAX * 4];
};
#define NM_FDT_NULL 0	// invalid buf index

struct pst_extra_slot {
	struct netmap_slot slot;
	uint16_t prev;
	uint16_t next;
};

struct pst_extra_pool {
	u_int num;
	struct pst_extra_slot *slots;
	uint32_t free;
	uint32_t free_tail;
	uint32_t busy;
	uint32_t busy_tail;
	u_int refcount;
};

void
pst_get_extra_ref(struct netmap_kring *kring)
{
	kring->extra->refcount++;
}

void
pst_put_extra_ref(struct netmap_kring *kring)
{
	kring->extra->refcount--;
}

u_int
pst_peek_extra_ref(struct netmap_kring *kring)
{
	return kring->extra->refcount;
}

static int
pst_extra_noref(struct netmap_adapter *na)
{
	struct netmap_adapter *port;
	struct nm_bridge *b = tovpna(na)->na_bdg;
	int i, j;

	for_bdg_ports(i, b) {
		port = &b->bdg_ports[i]->up;
		if (is_host(port))
			continue;
		for (j = 0; j < nma_get_nrings(port, NR_TX); j++) {
			struct netmap_kring *kr = NMR(port, NR_TX)[j];

			if (pst_peek_extra_ref(kr) > 0) {
				struct pst_extra_pool *p;
				u_int k, n = 0;

				p = kr->extra;
				for (k = p->busy; k != p->busy_tail;) {
					k = p->slots[k].next;
					n++;
				}
				PST_DBG("%s ref %d busy slots %d",
				  kr->name, pst_peek_extra_ref(kr), n);

				return 0;
			}
		}
	}
	return 1;
}

#define NM_EXT_NULL	((uint16_t)~0)
#define EXTRA_APPEND(name, pool, xtra, slots) \
	do {							\
		u_int pos = xtra - slots;			\
		xtra->next = NM_EXT_NULL;			\
		if (pool->name == NM_EXT_NULL)			\
			pool->name = pos;			\
		else						\
			slots[pool->name##_tail].next = pos;	\
		xtra->prev = pool->name##_tail;			\
		pool->name##_tail = pos;			\
	} while (0)						\

#define BETWEEN(x, l, h) \
	((uintptr_t)(x) >= (uintptr_t)(l) && (uintptr_t)(x) < (uintptr_t)(l+h))
void
pst_extra_deq(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct pst_extra_pool *pool;
	struct pst_extra_slot *slots, *xtra;

	/* XXX raising mbuf might have been orphaned */
	if (netmap_debug) {
		if (kring == NULL || kring->nr_mode != NKR_NETMAP_ON)
			panic("kring NULL or off");
	}
	pool = kring->extra;
	slots = pool->slots;
	/* nothing to do if I am on the ring */
	if (unlikely(!(BETWEEN(slot, slots, pool->num)))) {
		PST_DBG_LIM("%s kring %u buf_idx %u not in the extra pool",
				kring->na->name, kring->ring_id, slot->buf_idx);
		return;
	}

	xtra = (struct pst_extra_slot *)slot;
	/* remove from busy list */
	if (xtra->next == NM_EXT_NULL)
		pool->busy_tail = xtra->prev; // might be NM_EXT_NULL
	else
		slots[xtra->next].prev = xtra->prev; // might be NM_EXT_NULL
	if (xtra->prev == NM_EXT_NULL)
		pool->busy = xtra->next; // might be NM_EXT_NULL
	else
		slots[xtra->prev].next = xtra->next; // might be NM_EXT_NULL
	/* append to free list */
	EXTRA_APPEND(free, pool, xtra, slots);
}
#undef BETWEEN

int
pst_extra_enq(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct pst_extra_pool *pool = kring->extra;
	struct pst_extra_slot *slots = pool->slots, *xtra;
	struct nmcb *cb;

	if (unlikely(pool->free_tail == NM_EXT_NULL))
		return EBUSY;

	xtra = &slots[pool->free_tail];
	/* remove from free list */
	pool->free_tail = xtra->prev;
	if (unlikely(pool->free_tail == NM_EXT_NULL)) // I'm the last one
		pool->free = NM_EXT_NULL;
	else
		slots[xtra->prev].next = NM_EXT_NULL;
	/* append to busy list */
	EXTRA_APPEND(busy, pool, xtra, slots);

	cb = NMCB_SLT(na, slot);
	pst_swap(slot, &xtra->slot);
	if (netmap_debug) {
		if (nmcb_kring(cb) != kring)
			panic(" ");
	}
	nmcbw(cb, nmcb_kring(cb), &xtra->slot);
	return 0;
}
#undef EXTRA_APPEND

static inline struct pst_fdt *
pst_get_fdt(struct netmap_kring *kring)
{
	return (struct pst_fdt *)kring->nkr_ft;
}

static void
pst_fdt_free(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < netmap_real_rings(na, NR_TX); i++) {
		struct netmap_kring *kring = NMR(na, NR_TX)[i];
		if (kring->nkr_ft) {
			nm_os_free(kring->nkr_ft);
			kring->nkr_ft = NULL;
		}
	}
}

static int
pst_fdt_alloc(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < netmap_real_rings(na, NR_TX); i++) {
		struct pst_fdt *ft = nm_os_malloc(sizeof(struct pst_fdt));
		if (!ft) {
			pst_fdt_free(na);
			return ENOMEM;
		}
		NMR(na, NR_TX)[i]->nkr_ft = (struct nm_bdg_fwd *)ft;
	}
	return 0;
}

void
pst_fdt_add(struct nmcb *cb, struct netmap_kring *kring)
{
	struct netmap_slot *slot = nmcb_slot(cb);
	struct pst_fdt *ft = pst_get_fdt(kring);
	struct pst_fdt_q *fde;

	fde = ft->fde + nm_pst_getfd(slot);

	cb->next = NM_FDT_NULL;
	if (fde->fq_head == NM_FDT_NULL) {
		fde->fq_head = fde->fq_tail = slot->buf_idx;
		ft->fds[ft->nfds++] = nm_pst_getfd(slot);
	} else {
		struct netmap_slot tmp = { fde->fq_tail };
		struct nmcb *prev = NMCB_SLT(kring->na, &tmp);
		prev->next = fde->fq_tail = slot->buf_idx;
	}
	ft->npkts++;
}

/* XXX should go away */
static void
pst_fdt_may_reset(struct netmap_kring *kring)
{
	struct pst_fdt *ft = pst_get_fdt(kring);

	if (likely(ft->nfds == 0 && ft->npkts == 0))
		return;
	PST_DBG("kring %d fds %d pkts %d", kring->ring_id, ft->nfds, ft->npkts);
	if (ft->nfds > 0 && ft->npkts == 0) {
		ft->nfds = 0;
	} else if (ft->nfds == 0 && ft->npkts > 0) {
		int i;
		for (i = 0; i < NM_PST_FD_MAX; i++) {
			struct pst_fdt_q *fde = ft->fde + i;
			if (unlikely(fde->fq_head != NM_FDT_NULL)) {
				fde->fq_head = fde->fq_tail = NM_FDT_NULL;
				if (--ft->npkts == 0)
					break;
			}
		}
		ft->npkts = 0;
	}
}

struct pst_so_adapter *
pst_soa_from_fd(struct netmap_adapter *na, int fd)
{
	struct netmap_pst_adapter *pna = topna(na);

	if (unlikely(fd >= pna->so_adapters_max))
		return NULL;
	return pna->so_adapters[fd];
}

/* Differ from nm_kr_space() due to different meaning of the lease */
static inline uint32_t
pst_kr_rxspace(struct netmap_kring *k)
{
	int busy = k->nr_hwtail - k->nkr_hwlease;

	if (busy < 0)
		busy += k->nkr_num_slots;
	return k->nkr_num_slots - 1 - busy;
}

static void
pst_poststack(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na, *rxna;
	struct nm_bridge *b = tovpna(na)->na_bdg;
	struct pst_fdt *ft = pst_get_fdt(kring);
	uint32_t *nonfree = ft->tmp;
	u_int lim_rx, howmany, nrings;
	struct netmap_kring *rxr;
	int j, want, sent = 0, nonfree_num = 0;

	if (!BDG_RTRYLOCK(b)) {
		return;
	}

	if (is_host(na)) {
		want = kring->rhead - kring->nr_hwcur;
		if (want < 0)
			want += kring->nkr_num_slots;
	} else {
		want = ft->npkts;
	}

	/* Now, we know how many packets go to the receiver */
	if (na == pst_na(na) || is_host(na)) {
		if (unlikely(b->bdg_ports[1] == NULL))
			goto runlock;
		rxna = &b->bdg_ports[1]->up; /* XXX */
	} else {
		rxna = pst_na(na);
	}

	/* XXX Ugly but we cannot use ring_id on host rings */
	nrings = nma_get_nrings(rxna, NR_RX);
	rxr = NMR(rxna, NR_RX)[(kring - NMR(na, NR_TX)[0]) % nrings];
	lim_rx = rxr->nkr_num_slots - 1;
	j = rxr->nr_hwtail;

	/* under lock */
	mtx_lock(&rxr->q_lock);
	/* no need to check rxr->nkr_stopped */

	howmany = pst_kr_rxspace(rxr);
	if (howmany < want) { // try to reclaim completed buffers
		u_int n = 0;
		rxr->nkr_hwlease =
			rollup(rxr, rxr->nkr_hwlease, rxr->nr_hwtail, &n);
		howmany += n;
	} else if (likely(want < howmany)) {
		howmany = want;
	}
	if (unlikely(howmany == 0)) {
		goto unlock_kring;
	}

	if (is_host(na)) { // don't touch buffers, slightly faster
		u_int k = kring->nr_hwcur, lim_tx = kring->nkr_num_slots - 1;
		while (howmany--) {
			struct netmap_slot *rs, *ts = &kring->ring->slot[k];
			rs = &rxr->ring->slot[j];
			pst_swap(ts, rs);
			k = nm_next(k, lim_tx);
			j = nm_next(j, lim_rx);
			sent++;
		}
	} else {
		int n = 0;
		while (n < ft->nfds && likely(howmany)) {
			int fd = ft->fds[n];
			struct pst_fdt_q *fq = ft->fde + fd;
			uint32_t next = fq->fq_head;
			while (next != NM_FDT_NULL && likely(howmany)) {
				struct netmap_slot tmp = { next };
				struct netmap_slot *ts, *rs;
				struct nmcb *cb;

				rs = &rxr->ring->slot[j];
				cb = NMCB_SLT(na, &tmp);
				if (likely(nmcb_valid(cb))) {
					next = cb->next;
					cb->next = NM_FDT_NULL;
				} else {
					next = NM_FDT_NULL;
					goto skip;
				}
				ts = nmcb_slot(cb);
				if (unlikely(ts == NULL)) {
					PST_DBG("null ts nxt %u fd %d bufi "
					    "%u valid %d cb %p ft %d",
					    next, fd, tmp.buf_idx,
					    nmcb_valid(cb), cb,
					    nmcb_rstate(cb) == MB_FTREF);
					goto skip;
				} else if (unlikely(cb != NMB(na, ts))) {
					PST_DBG("fd %d cb %p != nmb %p "
					    "len %d state %d", fd, cb,
					    NMB(na, nmcb_slot(cb)), ts->len,
					    nmcb_rstate(cb) == MB_FTREF);
				}

				if (nmcb_rstate(cb) == MB_TXREF) {
					nonfree[nonfree_num++] = j;
				}
				pst_swap(ts, rs);
				if (nmcb_rstate(cb) == MB_FTREF) {
					nmcb_wstate(cb, MB_NOREF);
					pst_extra_deq(nmcb_kring(cb), ts);
				}
				nmcbw(cb, nmcb_kring(cb), rs);// needed?
skip:
				j = nm_next(j, lim_rx);
				sent++;
				howmany--;
			}
			if (next == NM_FDT_NULL) {
				n++;
				fq->fq_tail = NM_FDT_NULL;
			}
			fq->fq_head = next; // no NULL if howmany has run out
		}
		ft->nfds -= n;
		ft->npkts -= sent;
		memmove(ft->fds, ft->fds + n, sizeof(ft->fds[0]) * ft->nfds);
		pst_fdt_may_reset(kring);
	}

	rxr->nr_hwtail = j; // no update if !sent
unlock_kring:
	mtx_unlock(&rxr->q_lock);

	if (likely(sent))
		rxr->nm_notify(rxr, 0);
	rxr->nkr_hwlease = rxr->nr_hwcur;

	/* swap out packets still referred by the stack */
	for (j = 0; j < nonfree_num; j++) {
		struct netmap_slot *slot = &rxr->ring->slot[nonfree[j]];
		struct nmcb *cb = NMCB_SLT(rxna, slot);
		if (unlikely(pst_extra_enq(nmcb_kring(cb), slot))) {
			/* Don't reclaim on/after this positon */
			rxr->nkr_hwlease = slot - rxr->ring->slot;
			if (netmap_debug) {
				if (rxr->nkr_hwlease > rxr->nkr_num_slots)
					panic(" ");
			}
			break;
		}
	}
runlock:
	BDG_RUNLOCK(b);
	return;
}

/* Form fdtable to be flushed */
static int
pst_prestack(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	int k = kring->nr_hwcur;
	const u_int lim_tx = kring->nkr_num_slots - 1;
	const int rhead = kring->rhead;
	const bool tx = na == pst_na(na) ? 1 : 0;
	struct pst_fdt *ft = pst_get_fdt(kring);

	if (!tx && is_host(na))
		kring->nkr_hwlease = rhead; // skip loop below
	for (k = kring->nkr_hwlease; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		int err;
		if (unlikely(slot->len == 0)) {
			continue;
		}
		nmcbw(NMCB_SLT(na, slot), kring, slot);
		if (tx) {
			const u_int offset = nm_get_offset(kring, slot);
			const u_int pst_offset = nm_pst_getdoff(slot);
			/* XXX how to inform -EINVAL */
			if (unlikely(slot->len <  pst_offset)) {
				if (netmap_verbose)
					nm_prinf("data offset %u too large",
						 offset);
				break;
			} else if (unlikely(offset < sizeof(struct nmcb))) {
				if (netmap_verbose)
					nm_prinf("offset must be at least %lu",
						 sizeof(struct nmcb));
				break;
			}
			err = nm_os_pst_tx(kring, slot);
		} else {
			err = nm_os_pst_rx(kring, slot);
		}
		if (unlikely(err)) {
			/*
			 * EBUSY advances the cursor as the stack has consumed
			 * data (see nm_os_pst_tx()). EINVAL stops that as the
			 * client is likely misbehaving.
			 */
			if (err == -EBUSY) {
				k = nm_next(k, lim_tx);
			}
			break;
		}
	}
	kring->nkr_hwlease = k; // next position to process in the stack
	pst_poststack(kring);
	if (ft->npkts) { // we have leftover, cannot report k
		k = rollup(kring, kring->nr_hwcur, k, NULL);
	}
	return k;
}

static int
nombq(struct netmap_adapter *na, struct mbuf *m)
{
	struct netmap_kring *kring;
	struct netmap_slot *hs;
	u_int head, nm_i, lim, len = MBUF_LEN(m);

	/* host ring */
	nm_i = curcpu % nma_get_host_nrings(na, NR_RX);
	kring = NMR(na, NR_RX)[nma_get_nrings(na, NR_RX) + nm_i];
	head = kring->rhead;
	lim = kring->nkr_num_slots - 1;
	nm_i = kring->nr_hwtail;
	/* check space */
	if (unlikely(nm_i == nm_prev(kring->nr_hwcur, lim))) {
		netmap_bwrap_intr_notify(kring, 0);
		if (kring->nr_hwtail == nm_prev(kring->nr_hwcur, lim)) {
			m_freem(m);
			return EBUSY;
		}
	} else if (unlikely(!nm_netmap_on(na))) {
		m_freem(m);
		return ENXIO;
	}
	hs = &kring->ring->slot[nm_i];
	m_copydata(m, 0, len, (char *)NMB(na, hs) + nm_get_offset(kring, hs));
	hs->len = len;
	kring->nr_hwtail = nm_next(nm_i, lim);

	nm_i = kring->nr_hwcur;
	if (likely(nm_i != head)) {
		kring->nr_hwcur = head;
	}
	if (!paste_host_batch) {
		netmap_bwrap_intr_notify(kring, 0);
	}
	/* as if netmap_transmit + rxsync_from_host done */
	m_freem(m);
	return 0;
}

#ifdef __FreeBSD__
/* FreeBSD doesn't have protocol header offsets filled */
static inline void
mbuf_proto_headers(struct mbuf *m)
{
	uint16_t ethertype;

	ethertype = ntohs(*(uint16_t *)(m->m_data + 12));
	if (MBUF_L3_OFST(m) > 0)
		return;
	m->m_pkthdr.l2hlen = sizeof(struct ether_header);
	m->m_pkthdr.l3hlen = sizeof(struct nm_iphdr);
}
#else
#define mbuf_proto_headers(m)
#endif /* !FreeBSD */

static void
csum_transmit(struct netmap_adapter *na, struct mbuf *m)
{
	if (nm_os_mbuf_has_csum_offld(m)) {
		struct nm_iphdr *iph;
		char *th;
		uint16_t *check;
		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)MBUF_L3_HEADER(m);
		th = MBUF_L4_HEADER(m);
		if (iph->protocol == IPPROTO_UDP)
			check = &((struct nm_udphdr *)th)->check;
		else if (likely(iph->protocol == IPPROTO_TCP))
			check = &((struct nm_tcphdr *)th)->check;
		else
			panic("bad proto %u w/ offld", iph->protocol);
		/* With ethtool -K eth1 tx-checksum-ip-generic on, we
		 * see HWCSUM/IP6CSUM in dev and ip_sum PARTIAL on m.
		 */
		*check = 0;
		nm_os_csum_tcpudp_ipv4(iph, th,
			MBUF_LEN(m) - MBUF_L4_OFST(m), check);
		//m->ip_summed = 0;
		//m->m_pkthdr.csum_flags = CSUM_TSO; // XXX
	}
	nombq(na, m);
}

int
netmap_pst_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct nmcb *cb = NULL;
	struct netmap_kring *kring;
	struct netmap_slot *slot;
	char *nmb;
	int hole;
	const u_int bufsize = NETMAP_BUF_SIZE(na);
	u_int poff, doff, mlen;

#ifdef __FreeBSD__
	/* M_EXT or multiple mbufs (i.e., chain) */
	if ((m->m_flags & M_EXT)) // not TCP case
		cb = NMCB_EXT(m, 0, bufsize);
	if (!(cb && nmcb_valid(cb))) { // TCP case
		if (MBUF_HASNEXT(m) && (m->m_next->m_flags & M_EXT)) {
			(void)bufsize;
			cb = NMCB_EXT(m->m_next, 0, bufsize);
		}
	}
#elif defined(linux)
	/* txsync-ing TX packets are always frags */
	if (!MBUF_HASNEXT(m)) {
		csum_transmit(na, m);
		return 0;
	}

	cb = NMCB_EXT(m, 0, bufsize);
#endif /* __FreeBSD__ */
	/*
	 * FreeBSD pushes down the same cb multiple times for different slots
	 */
	if (unlikely(!(cb && nmcb_valid(cb)))) {
		csum_transmit(na, m);
		return 0;
	}
	kring = nmcb_kring(cb);
	/*
	 * Linux pushes down the same cb multiple times for a slot whose
	 * len > MTU, but the first one clears the MB_STACK state.
	 */
	if (unlikely(nmcb_rstate(cb) != MB_STACK)
#ifdef __FreeBSD__
	    /* FreeBSD ARP reply recycles the request mbuf */
	    || unlikely(kring && kring->na->na_private == na->na_private)
#endif /* __FreeBSD__ */
	    ) {
		PST_DBG_LIM("cb %p %s len %u", cb,
		    nmcb_rstate(cb) == MB_QUEUED ? "MB_QUEUED" : "!MB_STACK",
		    MBUF_LEN(m));
#ifdef linux
		if (unlikely(nmcb_rstate(cb) == MB_QUEUED)) {
			nmcb_wstate(NMCB_EXT(m, 0, bufsize), MB_NOREF);
			pst_extra_deq(kring, nmcb_slot(cb));
		}
#endif
		MBUF_FLATTEN(m); // XXX
		csum_transmit(na, m);
		return 0;
	}

	/* Valid cb, txsync-ing packet. */

	slot = nmcb_slot(cb);
	nmb = NMB(na, slot);
	if (unlikely((struct nmcb *)nmb != cb)) {
		panic("nmb %p cb %p", nmb, cb);
	}
	mlen = m_length(m, NULL);
	poff = nm_get_offset(kring, slot);
	doff = nm_pst_getdoff(slot);
	hole = (int)doff - MBUF_HDRLEN(m);

	if (!hole) {
		/* bring headers in */
		memcpy(nmb + poff, MBUF_DATA(m), doff);
		if (netmap_verbose)
			nm_prlim(1,"zerocopy: off %u len %u",
			    poff + doff, slot->len);
	} else {
		caddr_t p = nmb + poff + doff;
		if (netmap_verbose)
			nm_prlim(1, "hole %d poff %u doff %u hlen %u mlen %u "
			    "mclen %u slen %u",
			    hole, poff, doff, MBUF_HDRLEN(m), MBUF_LEN(m),
			    mlen, slot->len);
		// buffers can overlap
		memcpy(p - hole, p, MBUF_LEN(m) - MBUF_HDRLEN(m));
		nm_os_pst_mbuf_extadj(m, 0, -hole);
		memcpy(nmb + poff, MBUF_DATA(m), MBUF_HDRLEN(m));
		slot->len -= hole;
		nm_pst_setdoff(slot, doff - hole); // inform user
	}
	if (unlikely(slot->len > mlen)) {
		slot->len = mlen;
	}

	if (nm_os_mbuf_has_csum_offld(m)) {
		struct nm_iphdr *iph;
		struct nm_tcphdr *tcph;
		uint16_t *check;
		int len;
		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)(nmb + poff + MBUF_L3_OFST(m));
		tcph = (struct nm_tcphdr *)(nmb + poff + MBUF_L4_OFST(m));
		MBUF_CSUM_DONE(m);
		check = &tcph->check;
		*check = 0;
		len = slot->len - MBUF_L4_OFST(m);
		nm_os_csum_tcpudp_ipv4(iph, tcph, len, check);
	}
	pst_fdt_add(cb, kring);

	/* the stack might hold reference via clone, so let's see */
	nmcb_wstate(cb, MB_TXREF);
#ifdef linux
	/* in FreeBSD mbuf comes from our code */
	pst_get_extra_ref(kring);
	nm_os_set_mbuf_data_destructor(m, &cb->ui, nm_os_pst_mbuf_data_dtor);
#endif /* linux */
	m_freem(m);
	return 0;
}

static void
pst_extra_free_kring(struct netmap_kring *kring)
{
	struct pst_extra_pool *extra;

	/* kring->nr_mode is NKR_NEMAP_OFF on do_unregif() after reg failure
	 * (e.g., for allocating some netmap object)
	 */
	if (!kring->extra) {
		PST_DBG("%s kr %u no extra", kring->na->name, kring->ring_id);
		return;
	}
	extra = kring->extra;
	if (extra->busy != NM_EXT_NULL) {
		PST_DBG("%s kr %u busy %u",
			kring->na->name, kring->ring_id, extra->busy);
	}
	kring->extra = NULL;
	extra->num = 0;
	if (extra->slots)
		nm_os_free(extra->slots);
	nm_os_free(extra);
}

static void
pst_extra_free(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		pst_extra_free_kring(NMR(na, NR_TX)[i]);
	}
}

static int
pst_extra_alloc_kring(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	struct pst_extra_pool *pool;
	struct pst_extra_slot *extra_slots = NULL;
	u_int want = paste_extra, n, j, next;

	pool = nm_os_malloc(sizeof(*pool));
	if (!pool)
		return ENOMEM;
	kring->extra = pool; // make extra_free_kring()-able

	n = netmap_extra_alloc(na, &next, want);
	if (n == 0) {
		return ENOMEM;
	} else if (n < want) {
		if (netmap_verbose)
			nm_prinf("allocated only %u bufs", n);
	}
	kring->extra->num = n;
	if (n) {
		extra_slots = nm_os_malloc(sizeof(*extra_slots) * n);
		if (!extra_slots)
			return ENOMEM;
	}

	for (j = 0; j < n; j++) {
		struct pst_extra_slot *exs;
		struct netmap_slot tmp = {.buf_idx = next};

		exs = &extra_slots[j];
		exs->slot.buf_idx = next;
		exs->slot.len = 0;
		exs->slot.ptr = (exs->slot.ptr & ~kring->offset_mask) |
				(sizeof(struct nmcb) & kring->offset_mask);
		exs->prev = j == 0 ? NM_EXT_NULL : j - 1;
		exs->next = j + 1 == n ? NM_EXT_NULL : j + 1;
		next = *(uint32_t *)NMB(na, &tmp);
	}
	pool->free = 0;
	pool->free_tail = n - 1;
	pool->busy = pool->busy_tail = NM_EXT_NULL;
	pool->slots = extra_slots;
	return 0;
}

static int
pst_extra_alloc(struct netmap_adapter *na)
{
	int i;

	/* we don't need extra on host rings */
	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		if (pst_extra_alloc_kring(NMR(na, NR_TX)[i])) {
			pst_extra_free(na);
			return ENOMEM;
		}
	}
	return 0;
}

static void
pst_mbufpool_free(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		struct netmap_kring *kring = NMR(na, NR_TX)[i];
		if (kring->tx_pool == NULL)
			continue;
		if (kring->tx_pool[1]) {
			m_freem((struct mbuf *)kring->tx_pool[1]);
			kring->tx_pool[1] = NULL;
		}
		if (kring->tx_pool[0]) {
			nm_os_free(kring->tx_pool[0]);
			kring->tx_pool[0] = NULL;
		}
		nm_os_free(kring->tx_pool);
		kring->tx_pool = NULL;
	}
}

/* Create extra buffers and mbuf pool */
static int
pst_mbufpool_alloc(struct netmap_adapter *na)
{
	struct netmap_kring *kring;
	int i, error = 0;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		kring = NMR(na, NR_TX)[i];
		kring->tx_pool = nm_os_malloc(2 * sizeof(struct mbuf *));
		if (!kring->tx_pool) {
			PST_DBG("tx_pool allocation failed");
			error = ENOMEM;
			break;
		}
		kring->tx_pool[0] = nm_os_malloc(sizeof(struct mbuf));
		if (!kring->tx_pool[0]) {
			error = ENOMEM;
			break;
		}
	}
	if (error) {
		pst_mbufpool_free(na);
	}
	return error;
}

static int
pst_kwait(void *data)
{
	struct netmap_pst_adapter *pna = (struct netmap_pst_adapter *)data;
	struct netmap_priv_d *kpriv = pna->kpriv;
	int lim = 20;
	bool s = false;

	for (; lim > 0; s = 0) {
		if (pna->num_so_adapters > 0) {
			if (netmap_verbose)
				nm_prinf("waiting for %d sockets to go",
					pna->num_so_adapters);
			s = true;
		}
		if (!pst_extra_noref(&pna->up.up)) {
			if (netmap_verbose)
				nm_prinf("waiting for mbufs to go");
			if (s == false)
				lim--;
			s = true;
		}
		if (!s)
			break;
		pause("netmap-pst-kwait-pause", 2000);
	}
	if (netmap_verbose)
		nm_prinf("%s deleting priv", pna->up.up.name);
	NMG_LOCK();
	pna->kpriv = NULL;
	/* we don't clear pna->kwaittdp to indicate my run */
	netmap_priv_delete(kpriv);
	NMG_UNLOCK();
#ifdef __FreeBSD__
	kthread_exit();
#endif /* __FreeBSD__ */
	return 0;
}

static void
pst_write_offset(struct netmap_adapter *na, bool noring)
{
	enum txrx t;
	u_int i, j;
	const u_int offset = sizeof(struct nmcb);
	const u_int mask = 0xff;

	for_rx_tx(t) {
		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = NMR(na, t)[i];
			struct netmap_ring *ring = kring->ring;

			kring->offset_max = mask;
			kring->offset_mask = mask;
			/* Since app threads individually register port/rings,
			 * there exist rings not enabled yet.
			 *
			 * We cannot use nm_kring_pending_on(). Unlike main
			 * rings, host rings have both mode and pending_mode
			 * turned on already by netmap_update_hostrings_mode().
			 */
			if (noring) {
				continue;
			} else if (kring->nr_pending_mode != NKR_NETMAP_ON) {
				PST_DBG("%s %s %d not ready", na->name,
					t == NR_TX ? "tx" : "rx", i);
				continue;
			}
			*(uint64_t *)(uintptr_t)&ring->offset_mask = mask;
			for (j = 0; j < kring->nkr_num_slots; j++) {
				nm_write_offset(kring, ring->slot + j, offset);
			}
		}
	}
}

static int
netmap_pst_bwrap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_bwrap_adapter *bna = (struct netmap_bwrap_adapter *)na;
	struct netmap_adapter *hwna = bna->hwna;
#ifdef linux
	struct netmap_hw_adapter *hw = (struct netmap_hw_adapter *)hwna;
#endif

	if (onoff) {
		int i, error;

		if (na->nm_mem != pst_na(na)->nm_mem) {
			PST_DBG("mem mismatch %s nm_mem %p %s nm_mem %p",
				na->name, na->nm_mem,
				pst_na(na)->name, pst_na(na)->nm_mem);
			return EINVAL;
		}
		if (bna->up.na_bdg->bdg_active_ports > 3) {
			PST_DBG("%s: only one NIC is supported", na->name);
			return ENOTSUP;
		}
		/* netmap_do_regif just created rings. As we cannot rely on
		 * netmap_offsets_init, we set offsets here.
		 */
		pst_write_offset(na, 0);
		pst_write_offset(hwna, 1);

		error = netmap_bwrap_reg(na, onoff);
		if (error)
			return error;
		if (pst_extra_alloc(na)) {
			PST_DBG("extra_alloc failed for bwrap");
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}
		if (pst_mbufpool_alloc(na)) {
			PST_DBG("mbufpool_alloc failed for bwrap");
			pst_extra_free(na);
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}

		/* na->if_transmit already has backup */
#ifdef linux
		hw->nm_ndo.ndo_start_xmit = linux_pst_start_xmit;
		/* re-overwrite */
		hwna->ifp->netdev_ops = &hw->nm_ndo;
#elif defined (__FreeBSD__)
		hwna->ifp->if_transmit = netmap_pst_transmit;
#endif /* linux */

		/* set void callback on host rings */
		for (i = nma_get_nrings(hwna, NR_RX);
		     i < netmap_real_rings(hwna, NR_RX); i++) {
			NMR(hwna, NR_RX)[i]->nm_sync = netmap_vp_rxsync_locked;
		}
	} else {
#ifdef linux
		/* restore default start_xmit for future register */
		((struct netmap_hw_adapter *)hwna)->nm_ndo.ndo_start_xmit =
			linux_netmap_start_xmit;
#else
		hwna->ifp->if_transmit = hwna->if_transmit;
#endif
		pst_mbufpool_free(na);
		pst_extra_free(na);
		return netmap_bwrap_reg(na, onoff);
	}
	return 0;
}

static int
netmap_pst_bwrap_intr_notify(struct netmap_kring *kring, int flags) {
	struct netmap_adapter *hwna = kring->na, *vpna, *mna;
	enum txrx t = kring->tx ? NR_TX : NR_RX;

	vpna = (struct netmap_adapter *)hwna->na_private;
	if (unlikely(!vpna))
		return NM_IRQ_COMPLETED;

	/* just wakeup the client on the master */
	mna = pst_na(vpna);
	if (likely(mna)) {
		//u_int me = kring - NMR(hwna, t), last;
		u_int me = kring->ring_id, last;
		struct netmap_kring *mk;
		last = nma_get_nrings(mna, t);
		mk = NMR(mna, t)[last > me ? me : me % last];
		mk->nm_notify(mk, 0);
	}
	return NM_IRQ_COMPLETED;
}

static void
pst_unregister_socket(struct pst_so_adapter *soa)
{
	NM_SOCK_T *so = soa->so;
	struct netmap_pst_adapter *pna = topna(soa->na);

	mtx_lock(&pna->so_adapters_lock);
	if (soa->fd >= pna->so_adapters_max)
		panic("non-registered or invalid fd %d", soa->fd);
	pna->so_adapters[soa->fd] = NULL;
	pna->num_so_adapters--;
	SOCKBUF_LOCK(&so->so_rcv);
	RESTORE_SOUPCALL(so, soa);
	RESTORE_SODTOR(so, soa);
	SOCKBUF_UNLOCK(&so->so_rcv);
	pst_wso(NULL, so);
	wmb();
	bzero(soa, sizeof(*soa));
	nm_os_free(soa);
	mtx_unlock(&pna->so_adapters_lock);
}

static void
pst_sodtor(NM_SOCK_T *so)
{
	if (pst_so(so))
		pst_unregister_socket(pst_so(so));
	if (so->so_dtor) {
		so->so_dtor(so);
	}
}

void
pst_mbuf_data_dtor(struct nmcb *cb)
{
	if (unlikely(!nmcb_valid(cb))) {
		PST_DBG("invalid cb %p", cb);
		return;
	} else if (unlikely(nmcb_kring(cb) == NULL)) {
		PST_DBG("no kring in cb %p", cb);
		return;
	}
	pst_put_extra_ref(nmcb_kring(cb));
	if (nmcb_rstate(cb) != MB_FTREF) {
		pst_extra_deq(nmcb_kring(cb), nmcb_slot(cb));
		nmcb_wstate(cb, MB_NOREF);
	}
}

/* Under NMG_LOCK() */
static void
netmap_pst_bdg_dtor(const struct netmap_vp_adapter *vpna)
{
	struct netmap_pst_adapter *pna;

	if (&vpna->up != pst_na(&vpna->up))
		return;

	pna = (struct netmap_pst_adapter *)(void *)(uintptr_t)vpna;
	mtx_lock(&pna->so_adapters_lock);
	bzero(pna->so_adapters, sizeof(uintptr_t) * pna->so_adapters_max);
	pna->so_adapters_max = 0;
	nm_os_free(pna->so_adapters);
	pna->so_adapters = NULL;
	mtx_unlock(&pna->so_adapters_lock);
	mtx_destroy(&pna->so_adapters_lock);
	wmb();
	if (netmap_verbose)
		nm_prinf("destroyed everything");
}

/* not NMG_LOCK held */
int
netmap_pst_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *so;
	void *file;
	struct pst_so_adapter *soa;
	struct netmap_pst_adapter *pna = topna(na);
	int error = 0;

	if (unlikely(fd > NM_PST_FD_MAX)) {
		PST_DBG("fd %d too high", fd);
		return ENOMEM;
	}
	if (unlikely(fd < 3)) {
		PST_DBG("bad fd %d", fd);
		return EINVAL;
	}
	so = nm_os_sock_fget(fd, &file);
	if (!so)
		return EINVAL;
	if (!nm_os_so_connected(so)) {
		nm_os_sock_fput(so, file);
		return EINVAL;
	}

	so_lock(so);
	/* [Linux] It is possible that socket is disconnected but dead */
	if (nm_os_sock_dead(so)) {
		PST_DBG("so %p SOCK_DEAD", so);
		so_unlock(so);
		nm_os_sock_fput(so, file);
		return EINVAL;
	}
	if (pst_so(so)) {
		PST_DBG("already registered %d", fd);
		so_unlock(so);
		nm_os_sock_fput(so, file);
		return EBUSY;
	}

	/*serialize simultaneous accept/config */
	mtx_lock(&pna->so_adapters_lock);
	/* first check table size */
	if (fd >= pna->so_adapters_max) {
		struct pst_so_adapter **old = pna->so_adapters, **new;
		const int oldsize = pna->so_adapters_max;
		const int newsize = oldsize ? oldsize * 2 : DEFAULT_SK_ADAPTERS;

		new = nm_os_malloc(sizeof(new) * newsize);
		if (!new) {
			PST_DBG("failed to extend fdtable");
			error = ENOMEM;
			goto unlock_return;
		}
		if (old) {
			memcpy(new, old, sizeof(old) * oldsize);
			bzero(old, sizeof(old) * oldsize);
			nm_os_free(old);
		}
		pna->so_adapters = new;
		pna->so_adapters_max = newsize;
	}

	soa = nm_os_malloc(sizeof(*soa));
	if (!soa) {
		error = ENOMEM;
		goto unlock_return;
	}
	SOCKBUF_LOCK(&so->so_rcv);
	SAVE_SOUPCALL(so, soa);
	SAVE_SODTOR(so, soa);
	soa->na = na;
	soa->so = so;
	soa->fd = fd;
	pst_wso(soa, so);
	SET_SOUPCALL(so, nm_os_pst_upcall);
	SET_SODTOR(so, pst_sodtor);
	pna->so_adapters[fd] = soa;
	pna->num_so_adapters++;
	nm_os_sock_set_nocoalesce(&so->so_rcv);
	wmb();
	SOCKBUF_UNLOCK(&so->so_rcv);

	SOCKBUF_LOCK(&so->so_snd);
	nm_os_sock_set_nocoalesce(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);

#ifdef linux
	nm_os_set_nodelay(so); // within the same socket lock.
#endif
unlock_return:
	if (!error) {
		error = nm_os_pst_sbdrain(na, so);
	}
	mtx_unlock(&pna->so_adapters_lock);
	so_unlock(so);
#ifdef __FreeBSD__
	if (!error) {
		nm_os_set_nodelay(so); // inp must be locked outside our lock
	}
#endif
	nm_os_sock_fput(so, file);
	return error;
}

static int
netmap_pst_reg(struct netmap_adapter *na, int onoff)
{
	int err;

	if (onoff) {
		pst_write_offset(na, 0);
		if (na->active_fds > 0) {
			goto vp_reg;
		}
		err = pst_extra_alloc(na);
		if (err)
			return err;
	}
	if (!onoff) {
		struct nm_bridge *b = tovpna(na)->na_bdg;
		int i;
		struct netmap_pst_adapter *pna;

		if (na->active_fds > 0)
			goto vp_reg;

	       	pna = (struct netmap_pst_adapter *)na;
		if (netmap_verbose)
			nm_prinf("%s active_fds %d num_so_adapters %d",
				na->name, na->active_fds, pna->num_so_adapters);
		if (!pna->kwaittdp &&
		    (pna->num_so_adapters > 0 || !pst_extra_noref(na))) {
			struct netmap_if *nifp;
			enum txrx t;
			struct netmap_priv_d *kpriv = netmap_priv_new();
			kpriv->np_na = na;
			/* revert krings_put() - this also survives
			 * mem_rings_delete */
			for_rx_tx(t) {
				kpriv->np_qfirst[t] = 0;
				kpriv->np_qlast[t] = nma_get_nrings(na, t);
				for (i = 0; i < nma_get_nrings(na, t); i++) {
					NMR(na, t)[i]->users++;
					NMR(na, t)[i]->nr_pending_mode =
						NKR_NETMAP_ON;
				}
			}
			err = netmap_mem_finalize(na->nm_mem, na);
			if (err)
				goto del_kpriv;
			/* we don't need rings_create() */
			nifp = netmap_mem_if_new(na, kpriv);
			if (nifp == NULL) {
				err = ENOMEM;
del_kpriv:
				netmap_priv_delete(kpriv);
				pst_extra_free(na);
				return err;
			}
			kpriv->np_nifp = nifp;
			na->active_fds++;

			pna->kpriv = kpriv;
			netmap_adapter_get(na);
			/* we cannot die, create another and return */

			if (netmap_verbose)
				nm_prinf("spawning kwait");
			nm_os_kthread_add(pst_kwait, (void *)pna, NULL,
				    &pna->kwaittdp, 0, 0, "netmap-pst-kwait");
			return EBUSY; // XXX the caller doesn't care
		}

		for_bdg_ports(i, b) {
			struct netmap_vp_adapter *s;
			struct netmap_adapter *bna;
			struct nmreq_header hdr;
			struct nmreq_port_hdr req;
			int err;
			if (i == 0)
				continue;
			s = b->bdg_ports[i];
			bzero(&hdr, sizeof(hdr));
			strncpy(hdr.nr_name, s->up.name, sizeof(hdr.nr_name));
			hdr.nr_reqtype = NETMAP_REQ_PST_DETACH;
			hdr.nr_version = NETMAP_API;
			hdr.nr_body = (uintptr_t)&req;
			bna = &s->up;
			netmap_adapter_get(bna);
			if (bna->nm_bdg_ctl) {
				err = bna->nm_bdg_ctl(&hdr, bna);
			}
			netmap_adapter_put(bna);
		}
		pst_extra_free(na);
	}
vp_reg:
	err = netmap_vp_reg(na, onoff);
	return err;
}

static inline int
pst_bdg_valid(struct netmap_adapter *na)
{
	struct nm_bridge *b = tovpna(na)->na_bdg;

	if (unlikely(b == NULL)) {
		return 0;
	} else if (unlikely(b->bdg_active_ports < 3)) {
		if (netmap_verbose)
			nm_prinf("active ports %d", b->bdg_active_ports);
		return 0;
	}
	return 1;
}

static int
netmap_pst_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	u_int const head = kring->rhead;
	u_int done;

	if (unlikely(!pst_bdg_valid(na))) {
		done = head;
		return 0;
	} else if (unlikely(kring->nr_mode == NKR_NETMAP_OFF)) {
		PST_DBG("na %s kring %d OFF", na->name, kring->ring_id);
		return 0;
	}
	done = pst_prestack(kring);

	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

static int
netmap_pst_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_pst_adapter *pna = topna(kring->na);
	struct nm_bridge *b = pna->up.na_bdg;
	int i, err;
	u_int intr;

	if (unlikely(!pst_bdg_valid(kring->na))) {
		return 0;
	}
	err = netmap_vp_rxsync_locked(kring, flags); // reclaim buffers
	if (err)
		return err;

	intr = intr_disable(); // emulate software interrupt context

	for_bdg_ports(i, b) {
		struct netmap_vp_adapter *vpna = b->bdg_ports[i];
		struct netmap_adapter *na = &vpna->up;
		struct netmap_adapter *hwna;
		u_int first, last, j, hostnr;

		if (netmap_bdg_idx(vpna) == netmap_bdg_idx(&pna->up))
			continue;
		else if (is_host(na))
			continue;
		hwna = ((struct netmap_bwrap_adapter *)vpna)->hwna;
		hostnr = nma_get_host_nrings(hwna, NR_RX);

		first = kring->na->num_rx_rings > 1 ? kring->ring_id : 0;
		last = na->num_rx_rings;
		for (j = first; j < last; j += kring->na->num_rx_rings) {
			struct netmap_kring *hwk, *bk, *hk;
			hwk = NMR(hwna, NR_RX)[j];
			bk = NMR(na, NR_TX)[j];
			hk = NMR(hwna, NR_RX)[last + (j % hostnr)];
			/*
			 * the nm_os_pst_drain() context may have linked
			 * buffer(s) to the fdtable.
			 */
			if (pst_get_fdt(bk)->npkts > 0) {
				pst_poststack(bk);
			} else {
				netmap_bwrap_intr_notify(hwk, 0);
				if (paste_host_batch) {
					netmap_bwrap_intr_notify(hk, 0);
				}
			}
		}
	}
	intr_restore(intr);
	return netmap_vp_rxsync_locked(kring, flags);
}

static void
netmap_pst_dtor(struct netmap_adapter *na)
{
	struct nm_bridge *b = tovpna(na)->na_bdg;

	if (b) {
		netmap_bdg_detach_common(b, tovpna(na)->bdg_port, -1);
	}
	if (na->ifp != NULL && !nm_iszombie(na)) {
		NM_DETACH_NA(na->ifp);
	}
}

static void
netmap_pst_krings_delete(struct netmap_adapter *na)
{
	pst_fdt_free(na);
	netmap_krings_delete(na);
}

static int
netmap_pst_krings_create(struct netmap_adapter *na)
{
	int error = netmap_krings_create(na, 0);

	if (error)
		return error;
	error = pst_fdt_alloc(na);
	if (error)
		netmap_krings_delete(na);
	return error;
}

static void
netmap_pst_bwrap_krings_delete(struct netmap_adapter *na)
{
	netmap_bwrap_krings_delete_common(na);
	netmap_pst_krings_delete(na);
}

static int
netmap_pst_bwrap_krings_create(struct netmap_adapter *na)
{
	int error = netmap_pst_krings_create(na);

	if (error)
		return error;
	error = netmap_bwrap_krings_create_common(na);
	if (error) {
		netmap_pst_krings_delete(na);
	}
	return error;
}

static int
netmap_pst_vp_create(struct nmreq_header *hdr, struct ifnet *ifp,
		struct netmap_mem_d *nmd, struct netmap_vp_adapter **ret)
{
	struct nmreq_register *req =
		(struct nmreq_register *)(uintptr_t)hdr->nr_body;
	struct netmap_pst_adapter *pna;
	struct netmap_vp_adapter *vpna;
	struct netmap_adapter *na;
	int error = 0;
	u_int npipes = 0;

	if (hdr->nr_reqtype != NETMAP_REQ_REGISTER) {
		return EINVAL;
	}

	pna = nm_os_malloc(sizeof(*pna));
	if (pna == NULL)
		return ENOMEM;
	mtx_init(&pna->so_adapters_lock, "so_adapters_lock", NULL, MTX_DEF);
	vpna = &pna->up;
	na = &vpna->up;

	na->ifp = ifp;
	strncpy(na->name, hdr->nr_name, sizeof(na->name));
	na->num_tx_rings = req->nr_tx_rings;
	nm_bound_var(&na->num_tx_rings, 1, 1, NM_PST_MAXRINGS, NULL);
	req->nr_tx_rings = na->num_tx_rings; /* write back */
	na->num_rx_rings = req->nr_rx_rings;
	nm_bound_var(&na->num_rx_rings, 1, 1, NM_PST_MAXRINGS, NULL);
	req->nr_rx_rings = na->num_rx_rings; /* write back */
	nm_bound_var(&req->nr_tx_slots, NM_PST_RINGSIZE,
			1, NM_PST_MAXSLOTS, NULL);
	na->num_tx_desc = req->nr_tx_slots;
	nm_bound_var(&req->nr_rx_slots, NM_PST_RINGSIZE,
			1, NM_PST_MAXSLOTS, NULL);
	nm_bound_var(&npipes, 2, 1, NM_MAXPIPES, NULL); /* do we need this? */

	/* XXX should we check extra bufs? */
	na->num_rx_desc = req->nr_rx_slots;
	if (ifp)
		na->na_flags |= NAF_NATIVE;
	na->nm_txsync = netmap_pst_txsync;
	na->nm_rxsync = netmap_pst_rxsync;
	na->nm_register = netmap_pst_reg;
	na->nm_krings_create = netmap_pst_krings_create;
	na->nm_krings_delete = netmap_pst_krings_delete;
	na->nm_dtor = netmap_pst_dtor;
	na->nm_mem = nmd ?
		netmap_mem_get(nmd):
		netmap_mem_private_new(
			na->num_tx_rings, na->num_tx_desc,
			na->num_rx_rings, na->num_rx_desc,
			req->nr_extra_bufs, npipes, &error);
	if (na->nm_mem == NULL)
		goto err;
	error = netmap_attach_common(na);
	if (error)
		goto err;
	*ret = vpna;
	return 0;

err:
	if (na->nm_mem != NULL)
		netmap_mem_put(na->nm_mem);
	nm_os_free(pna);
	return error;
}

static int
netmap_pst_bwrap_attach(const char *nr_name, struct netmap_adapter *hwna)
{
	struct netmap_bwrap_adapter *bna;
	struct netmap_adapter *na = NULL;
	struct netmap_adapter *hostna = NULL;
	int error;

	if (!nm_os_hwcsum_ok(hwna)) {
#ifdef __FreeBSD__
		nm_prinf("paste needs checksum offload disabled");
#else
		nm_prinf("paste needs checksum offload enabled");
#endif /* __FreeBSD__ */
		return ENOTSUP;
	}

	bna = nm_os_malloc(sizeof(*bna));
	if (bna == NULL) {
		return ENOMEM;
	}
	na = &bna->up.up;
	strncpy(na->name, nr_name, sizeof(na->name));
	na->nm_register = netmap_pst_bwrap_reg;
	na->nm_txsync = netmap_pst_txsync;
	na->nm_krings_create = netmap_pst_bwrap_krings_create;
	na->nm_krings_delete = netmap_pst_bwrap_krings_delete;
	na->nm_notify = netmap_bwrap_notify;
	na->na_flags |= NAF_MOREFRAG; // survive netmap_buf_size_validate()
	na->na_flags |= NAF_HOST_ALL;

	bna->nm_intr_notify = netmap_pst_bwrap_intr_notify;

	if (hwna->na_flags & NAF_HOST_RINGS) {
		hostna = &bna->host.up;
		hostna->nm_notify = netmap_bwrap_notify;
	}

	error = netmap_bwrap_attach_common(na, hwna);
	if (error) {
		nm_os_free(bna);
	}
	return error;
}

struct netmap_bdg_ops pst_bdg_ops = {
	.lookup = NULL,
	.dtor = netmap_pst_bdg_dtor,
	.vp_create = netmap_pst_vp_create,
	.bwrap_attach = netmap_pst_bwrap_attach,
	.name = NM_PST_NAME,
};


int
netmap_get_pst_na(struct nmreq_header *hdr, struct netmap_adapter **na,
		struct netmap_mem_d *nmd, int create)
{
	return netmap_get_bdg_na(hdr, na, nmd, create, &pst_bdg_ops);
}
#endif /* WITH_PASTE */
