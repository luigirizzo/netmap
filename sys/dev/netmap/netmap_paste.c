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
SYSBEGIN(vars_paste);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_host_batch, CTLFLAG_RW, &paste_host_batch, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_extra, CTLFLAG_RW, &paste_extra, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, paste_usrrcv, CTLFLAG_RW, &paste_usrrcv, 1 , "");
SYSEND;

static int netmap_pst_bwrap_intr_notify(struct netmap_kring *kring, int flags);
static inline void
nm_swap(struct netmap_slot *s, struct netmap_slot *d)
{
	struct netmap_slot tmp = *d;
	*d = *s;
	*s = tmp;
	s->flags |= NS_BUF_CHANGED;
	d->flags |= NS_BUF_CHANGED;
}

static inline void
nm_swap_reset(struct netmap_slot *s, struct netmap_slot *d)
{
	nm_swap(s, d);
	s->len = 0;
	nm_pst_reset_fduoff(s);
}

static inline u_int
rollup(struct netmap_kring *kring, u_int from, u_int to, u_int *n)
{
	u_int i, m = 0, lim = kring->nkr_num_slots - 1;

	for (i = from; i != to; i = nm_next(i, lim), m++) {
		struct netmap_slot *slot = &kring->ring->slot[i];
		struct nmcb *cb;

		if (unlikely(!slot->len))
			continue;
		cb = NMCB_SLT(kring->na, slot);
		if (nmcb_valid(cb) && nmcb_rstate(cb) != MB_NOREF)
			break;
	}
	if (n)
		*n = m;
	return i;
}

struct netmap_adapter *
stna(const struct netmap_adapter *slave)
{
	const struct netmap_vp_adapter *vpna =
		(const struct netmap_vp_adapter *)slave;

	return likely(vpna) ? &vpna->na_bdg->bdg_ports[0]->up : NULL;
}

static inline struct netmap_pst_adapter *
tosna(struct netmap_adapter *na)
{
	return (struct netmap_pst_adapter *)na;
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

struct pst_fdtable {
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
};

#define NM_EXT_NULL	((uint16_t)~0)
#define EXTRA_APPEND(name, pool, xtra, slots, pos) \
	do {							\
		xtra->next = NM_EXT_NULL;			\
		if (pool->name == NM_EXT_NULL)			\
			pool->name = pos;			\
		else						\
			slots[pool->name##_tail].next = pos;	\
		xtra->prev = pool->name##_tail;			\
		pool->name##_tail = pos;			\
	} while (0)						\

#define BETWEEN(x, l, h) \
	((uintptr_t)(x) >= (uintptr_t)(l) && (uintptr_t)(x) < (uintptr_t)(h))

void
pst_extra_deq(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_ring *ring;
	struct pst_extra_pool *pool;
	struct pst_extra_slot *slots, *xtra;
	u_int pos;

	/* XXX raising mbuf might have been orphaned */
	if (unlikely(kring == NULL))
		return;
	if (unlikely(kring->nr_mode != NKR_NETMAP_ON))
		return;
	pool = kring->extra;
	if (unlikely(!pool))
		return;
	if (unlikely(!pool->num))
		return;

	slots = pool->slots;
	ring = kring->ring;
	/* nothing to do if I am on the ring */
	if (BETWEEN(slot, ring->slot, ring->slot + kring->nkr_num_slots)) {
		return;
	} else if (!(likely(BETWEEN(slot, slots, slots + pool->num)))) {
		PST_ASSERT("cannot dequeue slot not in the extra pool");
		return;
	}

	xtra = (struct pst_extra_slot *)slot;
	pos = xtra - slots;

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
	EXTRA_APPEND(free, pool, xtra, slots, pos);
}
#undef BETWEEN

int
pst_extra_enq(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct pst_extra_pool *pool = kring->extra;
	struct pst_extra_slot *slots = pool->slots, *xtra;
	u_int pos;
	struct nmcb *cb;

	if (unlikely(pool->free_tail == NM_EXT_NULL))
		return EBUSY;

	pos = pool->free_tail;
	xtra = &slots[pos];

	/* remove from free list */
	pool->free_tail = xtra->prev;
	if (unlikely(pool->free_tail == NM_EXT_NULL)) // I'm the last one
		pool->free = NM_EXT_NULL;
	else
		slots[xtra->prev].next = NM_EXT_NULL;
	/* append to busy list */
	EXTRA_APPEND(busy, pool, xtra, slots, pos);

	cb = NMCB_SLT(na, slot);
	nm_swap_reset(slot, &xtra->slot);
	nmcbw(cb, kring, &xtra->slot);

	return 0;
}
#undef EXTRA_APPEND

static inline struct pst_fdtable *
pst_fdt(struct netmap_kring *kring)
{
	return (struct pst_fdtable *)kring->nkr_ft;
}

static void
pst_fdtable_free(struct netmap_adapter *na)
{
	int i;

	NMG_LOCK_ASSERT();
	for (i = 0; i < netmap_real_rings(na, NR_TX); i++) {
		struct netmap_kring *kring = NMR(na, NR_TX)[i];
		if (kring->nkr_ft) {
			nm_os_free(kring->nkr_ft);
			kring->nkr_ft = NULL;
		}
	}
}

static int
pst_fdtable_alloc(struct netmap_adapter *na)
{
	int i;

	NMG_LOCK_ASSERT();
	for (i = 0; i < netmap_real_rings(na, NR_TX); i++) {
		struct pst_fdtable *ft = nm_os_malloc(sizeof(struct pst_fdtable));
		if (!ft) {
			pst_fdtable_free(na);
			return ENOMEM;
		}
		NMR(na, NR_TX)[i]->nkr_ft = (struct nm_bdg_fwd *)ft;
	}
	return 0;
}

void
pst_fdtable_add(struct nmcb *cb, struct netmap_kring *kring)
{
	struct netmap_slot *slot = nmcb_slot(cb);
	struct pst_fdtable *ft = pst_fdt(kring);
	struct pst_fdt_q *fde;

	fde = ft->fde + nm_pst_getfd(slot);

	cb->next = NM_FDT_NULL;
	nm_prdis("kring %p ft %p fde %p fd %d", kring, ft, fde, nm_pst_getfd(slot));
	if (fde->fq_head == NM_FDT_NULL) {
		fde->fq_head = fde->fq_tail = slot->buf_idx;
		ft->fds[ft->nfds++] = nm_pst_getfd(slot);
	} else {
		struct netmap_slot tmp = { fde->fq_tail };
		struct nmcb *prev = NMCB_SLT(kring->na, &tmp);

		/* invalid prev is not seen */
		prev->next = fde->fq_tail = slot->buf_idx;
	}
	ft->npkts++;
}

/* XXX should go away */
static void
pst_fdtable_may_reset(struct netmap_kring *kring)
{
	struct pst_fdtable *ft = pst_fdt(kring);

	if (unlikely(ft->nfds > 0 && ft->npkts == 0)) {
		ft->nfds = 0;
	} else if (unlikely(ft->nfds == 0 && ft->npkts > 0)) {
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


/* TX:
 * We overwrite ptr field (8 byte width) of netmap slot to store a
 * socket (4 byte), next buf index (2 byte).
 * The rest of 2 bytes may be used to store the number of frags
 * (1 byte) and destination port (1 byte).
 * We do not support INDIRECT as packet movement is done by swapping
 */

struct pst_so_adapter *
pst_soa_from_fd(struct netmap_adapter *na, int fd)
{
	struct netmap_pst_adapter *sna = tosna(na);

	if (unlikely(fd >= sna->so_adapters_max))
		return NULL;
	return sna->so_adapters[fd];
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
	struct nm_bridge *b = ((struct netmap_vp_adapter *)na)->na_bdg;
	struct pst_fdtable *ft = pst_fdt(kring);
	uint32_t *nonfree = ft->tmp;
	u_int lim_rx, howmany, nrings;
	struct netmap_kring *rxr;
	int j, want, sent = 0, nonfree_num = 0;

	if (na->na_flags & NAF_BDG_MAYSLEEP)
		BDG_RLOCK(b);
	else if (!BDG_RTRYLOCK(b))
		return;

	if (is_host(na)) {
		want = kring->rhead - kring->nr_hwcur;
		if (want < 0)
			want += kring->nkr_num_slots;
	} else {
		want = ft->npkts;
	}

	/* XXX perhaps this is handled later? */
	if (unlikely(b->bdg_active_ports < 3)) {
		PST_ASSERT("active ports %d", b->bdg_active_ports);
		goto runlock;
	}
	/* Now, we know how many packets go to the receiver */
	if (na == stna(na) || is_host(na))
		rxna = &b->bdg_ports[1]->up; /* XXX */
	else
		rxna = stna(na);

	if (unlikely(!nm_netmap_on(rxna)))
		panic("receiver na off");
	/* XXX Ugly but we cannot use ring_id on host rings */
	nrings = nma_get_nrings(rxna, NR_RX);
	rxr = NMR(rxna, NR_RX)[(kring - NMR(na, NR_TX)[0]) % nrings];
	lim_rx = rxr->nkr_num_slots - 1;
	j = rxr->nr_hwtail;

	/* under lock */
	mtx_lock(&rxr->q_lock);

	if (unlikely(rxr->nkr_stopped)) {
		mtx_unlock(&rxr->q_lock);
		goto runlock;
	}
	howmany = pst_kr_rxspace(rxr);
	if (unlikely(howmany < want)) { // try to reclaim completed buffers
		u_int n = 0;
		rxr->nkr_hwlease =
			rollup(rxr, rxr->nkr_hwlease, rxr->nr_hwtail, &n);
		howmany += n;
	} else if (likely(want < howmany)) {
		howmany = want;
	}

	if (is_host(na)) { // don't touch buffers, slightly faster
		u_int k = kring->nr_hwcur, lim_tx = kring->nkr_num_slots - 1;

		while (howmany--) {
			struct netmap_slot *rs, *ts = &kring->ring->slot[k];

			__builtin_prefetch(ts);
			rs = &rxr->ring->slot[j];
			__builtin_prefetch(rs);
			nm_swap(ts, rs);
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
				__builtin_prefetch(rs);
				cb = NMCB_SLT(na, &tmp);
				next = unlikely(!nmcb_valid(cb)) ?
					NM_FDT_NULL : cb->next;
				ts = nmcb_slot(cb);
				if (unlikely(ts == NULL)) {
					PST_ASSERT("null ts nxt %u", next);
					goto skip;
				}
				if (nmcb_rstate(cb) == MB_TXREF)
					nonfree[nonfree_num++] = j;
				nmcbw(cb, rxr, rs);
				nm_swap_reset(ts, rs);
skip:
				j = nm_next(j, lim_rx);
				sent++;
				howmany--;
			}
			if (likely(next == NM_FDT_NULL))
				n++;
			fq->fq_head = next; // no NULL if howmany has run out
		}
		ft->nfds -= n;
		ft->npkts -= sent;
		memmove(ft->fds, ft->fds + n, sizeof(ft->fds[0]) * ft->nfds);
		pst_fdtable_may_reset(kring);
	}

	rxr->nr_hwtail = j; // no update if !sent
	mtx_unlock(&rxr->q_lock);

	if (likely(sent))
		rxr->nm_notify(rxr, 0);
	rxr->nkr_hwlease = rxr->nr_hwcur;

	/* swap out packets still referred by the stack */
	for (j = 0; likely(j < nonfree_num); j++) {
		struct netmap_slot *slot = &rxr->ring->slot[nonfree[j]];

		if (unlikely(pst_extra_enq(rxr, slot))) {
			/* Don't reclaim on/after this positon */
			u_long nm_i = slot - rxr->ring->slot;
			rxr->nkr_hwlease = nm_i;
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
	u_int lim_tx = kring->nkr_num_slots - 1;
	const int rhead = kring->rhead;
	//int tx = 0;
	const bool tx = na == stna(na) ? 1 : 0;
	struct pst_fdtable *ft = pst_fdt(kring);

	//if (na == stna(na))
	//	tx = 1;
	//else if (is_host(na))
	//	kring->nkr_hwlease = rhead; // skip loop below
	if (!tx && is_host(na))
		kring->nkr_hwlease = rhead; // skip loop below
	for (k = kring->nkr_hwlease; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		char *nmb = NMB(na, slot);
		int err;

		__builtin_prefetch(nmb);
		if (unlikely(slot->len == 0))
			continue;
		/* validate user-supplied data */
		if (tx) {
			if (unlikely(slot->len < nm_pst_getuoff(slot))) {
				continue;
			}
			if (unlikely(nm_get_offset(kring, slot) !=
				     sizeof(struct nmcb))) {
				PST_DBG_LIM("bad offset %lu",
					    nm_get_offset(kring, slot));
				continue;
			}

		}
		nmcbw(NMCB_BUF(nmb), kring, slot);
		err = tx ? nm_os_pst_tx(kring, slot) :
			   nm_os_pst_rx(kring, slot);
		if (unlikely(err)) {
			/*
			 * EBUSY advances the pointer as the stack has consumed
			 * data (see nm_os_pst_tx()). Other errors stops it as
			 * the client is likely misbehaving.
			 */
			if (err == -EBUSY)
				k = nm_next(k, lim_tx);
			break;
		}
	}
	kring->nkr_hwlease = k; // next position to process in the stack
	pst_poststack(kring);
	if (ft->npkts) // we have leftover, cannot report k
		k = rollup(kring, kring->nr_hwcur, k, NULL);
	return k;
}

static int
nombq(struct netmap_adapter *na, struct mbuf *m)
{
	struct netmap_kring *kring;
	struct netmap_slot *hslot;
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
	hslot = &kring->ring->slot[nm_i];
	m_copydata(m, 0, len,
		   (char *)NMB(na, hslot) + nm_get_offset(kring, hslot));
	hslot->len = len;
	kring->nr_hwtail = nm_next(nm_i, lim);

	nm_i = kring->nr_hwcur;
	if (likely(nm_i != head))
		kring->nr_hwcur = head;
	if (!paste_host_batch)
		netmap_bwrap_intr_notify(kring, 0);
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
	if (MBUF_NETWORK_OFFSET(m) > 0)
		return;
	m->m_pkthdr.l2hlen = sizeof(struct ether_header);
	m->m_pkthdr.l3hlen = sizeof(struct nm_iphdr);
}
#else
#define mbuf_proto_headers(m)

#define I40E_TXD_QW1_CMD_SHIFT	4
#define I40E_TXD_QW1_CMD_MASK	(0x3FFUL << I40E_TXD_QW1_CMD_SHIFT)

enum i40e_tx_desc_cmd_bits {
	I40E_TX_DESC_CMD_EOP			= 0x0001,
	I40E_TX_DESC_CMD_RS			= 0x0002,
	I40E_TX_DESC_CMD_ICRC			= 0x0004,
	I40E_TX_DESC_CMD_IL2TAG1		= 0x0008,
	I40E_TX_DESC_CMD_DUMMY			= 0x0010,
	I40E_TX_DESC_CMD_IIPT_NONIP		= 0x0000, /* 2 BITS */
	I40E_TX_DESC_CMD_IIPT_IPV6		= 0x0020, /* 2 BITS */
	I40E_TX_DESC_CMD_IIPT_IPV4		= 0x0040, /* 2 BITS */
	I40E_TX_DESC_CMD_IIPT_IPV4_CSUM		= 0x0060, /* 2 BITS */
	I40E_TX_DESC_CMD_FCOET			= 0x0080,
	I40E_TX_DESC_CMD_L4T_EOFT_UNK		= 0x0000, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_TCP		= 0x0100, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_SCTP		= 0x0200, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_UDP		= 0x0300, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_N		= 0x0000, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_T		= 0x0100, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_NI	= 0x0200, /* 2 BITS */
	I40E_TX_DESC_CMD_L4T_EOFT_EOF_A		= 0x0300, /* 2 BITS */
};

#define I40E_TXD_QW1_OFFSET_SHIFT	16
#define I40E_TXD_QW1_OFFSET_MASK	(0x3FFFFULL << \
					 I40E_TXD_QW1_OFFSET_SHIFT)

enum i40e_tx_desc_length_fields {
	/* Note: These are predefined bit offsets */
	I40E_TX_DESC_LENGTH_MACLEN_SHIFT	= 0, /* 7 BITS */
	I40E_TX_DESC_LENGTH_IPLEN_SHIFT		= 7, /* 7 BITS */
	I40E_TX_DESC_LENGTH_L4_FC_LEN_SHIFT	= 14 /* 4 BITS */
};

static inline int
csum_ctx(uint32_t *cmd, uint32_t *off,
		struct nm_iphdr *iph, struct nm_tcphdr *th)
{
	if (unlikely(iph->protocol != IPPROTO_TCP))
		return -1;
	*cmd = *off = 0;
	*cmd |= I40E_TX_DESC_CMD_IIPT_IPV4; /* no tso */
	*off |= (ETH_HDR_LEN >> 1) << I40E_TX_DESC_LENGTH_MACLEN_SHIFT;
	*off |= ((4 * (iph->version_ihl & 0x0F)) >> 2)
		<< I40E_TX_DESC_LENGTH_IPLEN_SHIFT;

	*cmd |= I40E_TX_DESC_CMD_L4T_EOFT_TCP;
	*off |= ((4 * (th->doff >> 4)) >> 2) << I40E_TX_DESC_LENGTH_L4_FC_LEN_SHIFT;
	return 0;
}
#endif /* !FreeBSD */

static void
csum_transmit(struct netmap_adapter *na, struct mbuf *m)
{
	if (nm_os_mbuf_has_csum_offld(m)) {
		struct nm_iphdr *iph;
		char *th;
		uint16_t *check;

		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)MBUF_NETWORK_HEADER(m);
		th = MBUF_TRANSPORT_HEADER(m);
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
			MBUF_LEN(m) - MBUF_TRANSPORT_OFFSET(m), check);
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
	int mismatch;
	const u_int bufsize = NETMAP_BUF_SIZE(na);

#ifdef __FreeBSD__
	struct mbuf *md = m;

	/* M_EXT or multiple mbufs (i.e., chain) */
	if ((m->m_flags & M_EXT)) // not TCP case
		cb = NMCB_EXT(m, 0, bufsize);
	if (!(cb && nmcb_valid(cb))) { // TCP case
		if (MBUF_NONLINEAR(m) && (m->m_next->m_flags & M_EXT)) {
			(void)bufsize;
			cb = NMCB_EXT(m->m_next, 0, bufsize);
		}
		md = m->m_next;
	}
#elif defined(linux)
	/* txsync-ing TX packets are always frags */
	if (!MBUF_NONLINEAR(m)) {
		csum_transmit(na, m);
		return 0;
	}

	cb = NMCB_EXT(m, 0, bufsize);
#endif /* __FreeBSD__ */
	if (!(cb && nmcb_valid(cb))) {
		csum_transmit(na, m);
		return 0;
	}
	kring = nmcb_kring(cb);
	if (unlikely(nmcb_rstate(cb) != MB_STACK) ||
	    /* FreeBSD ARP reply recycles the request mbuf */
	    unlikely(kring && kring->na->na_private == na->na_private)) {
		MBUF_LINEARIZE(m); // XXX
		csum_transmit(na, m);
		return 0;
	}
	/* Valid cb, txsync-ing packet. */
	slot = nmcb_slot(cb);
	if (unlikely(nmcb_rstate(cb) == MB_QUEUED)) {
		/* originated by netmap but has been queued in either extra
		 * or txring slot. The backend might drop this packet.
		 */
#ifdef linux
		int i, n = MBUF_CLUSTERS(m);

		for (i = 0; i < n; i++)
			nmcb_wstate(NMCB_EXT(m, i, bufsize), MB_NOREF);
#else
		/* To be done */
#endif /* linux */
		MBUF_LINEARIZE(m);
		csum_transmit(na, m);
		return 0;
	}

	nmb = NMB(na, slot);
	/* bring protocol headers in */
	mismatch = MBUF_HEADLEN(m) - (int)nm_pst_getuoff(slot);
	if (!mismatch) {
		/* Length has already been validated */
		memcpy(nmb + nm_get_offset(kring, slot), MBUF_DATA(m),
		       nm_pst_getuoff(slot));
		PST_DBG_LIM("zero copy tx uoff %u roff %u", nm_pst_getuoff(slot), (u_int)(slot->ptr & kring->offset_mask));
	} else {
		m_copydata(m, 0, MBUF_LEN(m), nmb + nm_get_offset(kring, slot));
		slot->len += mismatch;
		PST_DBG_LIM("copy tx");
	}

	if (nm_os_mbuf_has_csum_offld(m)) {
		struct nm_iphdr *iph;
		struct nm_tcphdr *tcph;
		uint16_t *check;
		int len, v = nm_get_offset(kring, slot);

		mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)(nmb + v + MBUF_NETWORK_OFFSET(m));
		tcph = (struct nm_tcphdr *)(nmb + v + MBUF_TRANSPORT_OFFSET(m));
#ifdef linux
		if (na->na_flags & NAF_CSUM) {
			if (likely(!csum_ctx(&cb->cmd, &cb->off, iph, tcph))) {
				slot->flags |= NS_CSUM;
				goto csum_done;
			}
		}
		m->ip_summed = CHECKSUM_COMPLETE;
#endif
		check = &tcph->check;
		*check = 0;
		len = slot->len - MBUF_TRANSPORT_OFFSET(m);
		nm_os_csum_tcpudp_ipv4(iph, tcph, len, check);
	}
#ifdef linux
csum_done:
#endif
	if (cb == NULL) {
		nm_prinf("WARNING: NULL cb (na %s)", na->name);
	}
	pst_fdtable_add(cb, kring);

	/* the stack might hold reference via clone, so let's see */
	if (cb == NULL) {
		PST_ASSERT("na %s kring %p cb NULL", na->name, kring);
	}
	nmcb_wstate(cb, MB_TXREF);
#ifdef linux
	/* for FreeBSD mbuf comes from our code */
	nm_os_set_mbuf_data_destructor(m, &cb->ui,
			nm_os_pst_mbuf_data_dtor);
#endif /* linux */
	m_freem(m);
	return 0;
}

static void
pst_extra_free_kring(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	struct netmap_ring *ring = kring->ring;
	struct pst_extra_pool *extra;
	uint32_t j;

	/* True on do_unregif() after reg failure
	 * (e.g., for allocating some netmap object
	 */
	if (kring->nr_mode == NKR_NETMAP_OFF || !kring->extra)
		return;
	extra = kring->extra;

	j = extra->busy;
	while (j != NM_EXT_NULL) {
		struct pst_extra_slot *e = &extra->slots[j];
		struct nmcb *cb = NMCB_SLT(na, &e->slot);
		nmcb_set_gone(cb);
		j = e->next;
	}
	kring->extra = NULL;
	extra->num = 0;
	if (extra->slots)
		nm_os_free(extra->slots);
	nm_os_free(extra);

	/* also mark on-ring bufs */
	for (j = 0; j < kring->nkr_num_slots; j++) {
		struct nmcb *cb;

		cb = NMCB_SLT(na, &ring->slot[j]);
		if (nmcb_valid(cb)) {
			nmcb_set_gone(cb);
		}
	}
}

static void
pst_extra_free(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		for (i = 0; i < netmap_real_rings(na, t); i++) {
			pst_extra_free_kring(NMR(na, t)[i]);
		}
	}
}

static int
pst_extra_alloc_kring(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	struct pst_extra_pool *pool;
	struct pst_extra_slot *extra_slots = NULL;
	u_int want = paste_extra, n, j, next;

	pool = nm_os_malloc(sizeof(*kring->extra));
	if (!pool)
		return ENOMEM;
	kring->extra = pool;

	n = netmap_extra_alloc(na, &next, want);
	if (n < want) {
		PST_ASSERT("allocated only %u bufs", n);
	}
	kring->extra->num = n;
	if (n) {
		extra_slots = nm_os_malloc(sizeof(*extra_slots)
				* n);
		if (!extra_slots)
			return ENOMEM;
	}

	for (j = 0; j < n; j++) {
		struct pst_extra_slot *exs;
		struct netmap_slot tmp = {.buf_idx = next};

		exs = &extra_slots[j];
		exs->slot.buf_idx = next;
		exs->slot.len = 0;
		exs->slot.ptr =
		  (exs->slot.ptr & ~kring->offset_mask) |
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
	enum txrx t;
	int error = 0;

	for_rx_tx(t) {
		int i;

		if (error)
			break;
		/* XXX probably we don't need extra on host rings */
		for (i = 0; i < netmap_real_rings(na, t); i++) {
			if (pst_extra_alloc_kring(NMR(na, t)[i])) {
				error = ENOMEM;
				break;
			}
		}
	}
	if (error)
		pst_extra_free(na);
	return error;
}

/* Create extra buffers and mbuf pool */
static int
pst_mbufpool_alloc(struct netmap_adapter *na)
{
	struct netmap_kring *kring;
	int i, error = 0;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		kring = NMR(na, NR_TX)[i];
		kring->tx_pool =
			nm_os_malloc(na->num_tx_desc * sizeof(struct mbuf *));
		if (!kring->tx_pool) {
			PST_ASSERT("tx_pool allocation failed");
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
		for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
			kring = NMR(na, NR_TX)[i];
			if (kring->tx_pool == NULL)
				break; // further allocation has never happened
			if (kring->tx_pool[0])
				nm_os_free(kring->tx_pool[0]);
			nm_os_free(kring->tx_pool);
			kring->tx_pool = NULL;
		}
	}
	return error;
}

static void
pst_mbufpool_free(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < nma_get_nrings(na, NR_TX); i++) {
		struct netmap_kring *kring = NMR(na, NR_TX)[i];

		if (kring->tx_pool == NULL)
			continue;
		if (kring->tx_pool[0])
			nm_os_free(kring->tx_pool[0]);
		nm_os_free(kring->tx_pool);
		kring->tx_pool = NULL;
	}
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

			kring->offset_max = offset;
			kring->offset_mask = mask;
			if (!noring && !nm_kring_pending_on(kring))
				continue; // ring is not ready
			if (noring)
				continue;
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

		if (bna->up.na_bdg->bdg_active_ports > 3) {
			PST_ASSERT("%s: only one NIC is supported", na->name);
			return ENOTSUP;
		}
		if (hwna->na_flags & NAF_CSUM) {
			struct netmap_adapter *mna = stna(na);
			if (!mna)
				panic("x");
			mna->na_flags |= NAF_CSUM;
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
			PST_ASSERT("extra_alloc failed for slave");
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}
		if (pst_mbufpool_alloc(na)) {
			PST_ASSERT("mbufpool_alloc failed for slave");
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
	mna = stna(vpna);
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

/*
 * When stack dies first, it simply restores all the socket
 * information on dtor().
 * Otherwise our sk->sk_destructor will cleanup stack states
 */
static void
pst_unregister_socket(struct pst_so_adapter *soa)
{
	NM_SOCK_T *so = soa->so;
	struct netmap_pst_adapter *sna = tosna(soa->na);

	nm_prdis("so %p soa %p fd %d", so, soa, soa->fd);
	if (!sna) {
		PST_DBG("no sna");
		//nm_os_free(soa);
		return;
	}
	if (!soa) {
		PST_DBG("no soa");
		return;
	}
	mtx_lock(&sna->so_adapters_lock);
	if (soa->fd >= sna->so_adapters_max) {
		PST_DBG("non-registered or invalid fd %d", soa->fd);
	} else {
		sna->so_adapters[soa->fd] = NULL;
		NM_SOCK_LOCK(so);
		/* socket is dying, no need to lock sockbuf */
		RESTORE_SOUPCALL(so, soa);
		RESTORE_SODTOR(so, soa);
		pst_wso(NULL, so);
		NM_SOCK_UNLOCK(so);
	}
	nm_os_free(soa);
	mtx_unlock(&sna->so_adapters_lock);
}

static void
pst_sodtor(NM_SOCK_T *so)
{
	struct pst_so_adapter *soa = pst_so(so);

	if (soa->so != so) {
		pst_wso(NULL, so);
		return;
	}
	pst_unregister_socket(soa);
	if (so->so_dtor) {
		so->so_dtor(so);
	}
}

/* Under NMG_LOCK() */
static void
netmap_pst_bdg_dtor(const struct netmap_vp_adapter *vpna)
{
	struct netmap_pst_adapter *sna;
	int i;

	if (&vpna->up != stna(&vpna->up))
		return;

	sna = (struct netmap_pst_adapter *)(void *)(uintptr_t)vpna;
	for (i = 0; i < sna->so_adapters_max; i++) {
		struct pst_so_adapter *soa = sna->so_adapters[i];
		if (soa)
			pst_unregister_socket(soa);
	}
	bzero(sna->so_adapters, sizeof(uintptr_t) * sna->so_adapters_max);
	sna->so_adapters_max = 0;
	sna->so_adapters = NULL;
	nm_os_free(sna->so_adapters);
	mtx_destroy(&sna->so_adapters_lock);
}

static int
pst_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *so;
	void *file;
	struct pst_so_adapter *soa;
	struct netmap_pst_adapter *sna = tosna(na);
	int error = 0;

	if (unlikely(fd > NM_PST_FD_MAX)) {
		return ENOMEM;
	}
	NMG_LOCK();
	mtx_lock(&sna->so_adapters_lock);
	/* first check table size */
	if (fd >= sna->so_adapters_max) {
		struct pst_so_adapter **old = sna->so_adapters, **new;
		int oldsize = sna->so_adapters_max;
		int newsize = oldsize ? oldsize * 2 : DEFAULT_SK_ADAPTERS;

		new = nm_os_malloc(sizeof(new) * newsize);
		if (!new) {
			PST_ASSERT("failed to extend fdtable");
			mtx_unlock(&sna->so_adapters_lock);
			NMG_UNLOCK();
			return ENOMEM;
		}
		if (old) {
			memcpy(new, old, sizeof(old) * oldsize);
			nm_os_free(old);
		}
		sna->so_adapters = new;
		sna->so_adapters_max = newsize;
	}
	mtx_unlock(&sna->so_adapters_lock);
	NMG_UNLOCK();

	so = nm_os_sock_fget(fd, &file);
	if (!so)
		return EINVAL;
	if (nm_os_set_nodelay(so) < 0) {
		PST_DBG_LIM("failed to set TCP_NODELAY");
	}
	/*serialize simultaneous accept/config */
	NM_SOCK_LOCK(so); // sosetopt() internally locks socket
	if (pst_so(so)) {
		error = EBUSY;
		goto unlock_return;
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
	SET_SOUPCALL(so, nm_os_pst_upcall);
	SET_SODTOR(so, pst_sodtor);
	pst_wso(soa, so);
	sna->so_adapters[fd] = soa;
	SOCKBUF_UNLOCK(&so->so_rcv);
unlock_return:
	NM_SOCK_UNLOCK(so);
	if (!error) {
		error = nm_os_pst_sbdrain(na, so);
	}
	nm_os_sock_fput(so, file);
	return error;
}

static int
netmap_pst_bdg_config(struct nm_ifreq *ifr)
{
	struct netmap_adapter *na;
	int fd = *(int *)ifr->data;
	struct nmreq_header hdr;
	int error;

	strncpy(hdr.nr_name, ifr->nifr_name, sizeof(hdr.nr_name));
	NMG_LOCK();
	error = netmap_get_pst_na(&hdr, &na, NULL, 0);
	NMG_UNLOCK();
	if (!error && na != NULL) {
		error = pst_register_fd(na, fd);
	}
	if (na) {
		NMG_LOCK();
		netmap_adapter_put(na);
		NMG_UNLOCK();
	}
	return error;
}

static int
netmap_pst_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_vp_adapter *vpna = (struct netmap_vp_adapter *)na;
	int err;

	if (onoff) {
		pst_write_offset(na, 0);
		if (na->active_fds > 0) {
			return 0;
		}
		err = pst_extra_alloc(na);
		if (err)
			return err;
	}
	if (!onoff) {
		struct nm_bridge *b = vpna->na_bdg;
		int i;

		for_bdg_ports(i, b) {
			struct netmap_vp_adapter *s;
			struct netmap_adapter *slvna;
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
			slvna = &s->up;
			netmap_adapter_get(slvna);
			if (slvna->nm_bdg_ctl) {
				err = slvna->nm_bdg_ctl(&hdr, slvna);
			}
			netmap_adapter_put(slvna);
		}
		pst_extra_free(na);
	}
	err = netmap_vp_reg(na, onoff);
	return err;
}

static inline int
pst_bdg_valid(struct netmap_adapter *na)
{
	struct nm_bridge *b = ((struct netmap_vp_adapter *)na)->na_bdg;

	if (unlikely(b == NULL)) {
		return 0;
	} else if (unlikely(b->bdg_active_ports < 3)) {
		PST_ASSERT("active ports %d", b->bdg_active_ports);
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
	}
	done = pst_prestack(kring);

	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

/* We can call rxsync without locks because of run-to-completion */
static int
netmap_pst_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_pst_adapter *sna = tosna(kring->na);
	struct nm_bridge *b = sna->up.na_bdg;
	int i, err;
	register_t	intr;

	if (unlikely(!pst_bdg_valid(kring->na))) {
		return 0;
	}
	/* TODO scan only necessary ports */
	err = netmap_vp_rxsync_locked(kring, flags); // reclaim buffers
	if (err)
		return err;

	intr = intr_disable(); // emulate software interrupt context

	for_bdg_ports(i, b) {
		struct netmap_vp_adapter *vpna = b->bdg_ports[i];
		struct netmap_adapter *na = &vpna->up;
		struct netmap_adapter *hwna;
		u_int first, last, j;
	
		if (netmap_bdg_idx(vpna) == netmap_bdg_idx(&sna->up))
			continue;
		else if (is_host(na))
			continue;
		hwna = ((struct netmap_bwrap_adapter *)vpna)->hwna;

		/* hw ring(s) to scan */
		first = kring->na->num_rx_rings > 1 ? kring->ring_id : 0;
		last = na->num_rx_rings;
		for (j = first; j < last; j += kring->na->num_rx_rings) {
			struct netmap_kring *hwk, *bk, *hk;
		       
			hwk = NMR(hwna, NR_RX)[j];
			bk = NMR(na, NR_TX)[j];
			hk = NMR(hwna, NR_RX)[last +
				(j % nma_get_host_nrings(hwna, NR_RX))];
			/*
			 * st_fromstack has been put off because we do not want
			 * it to run in bdg_config context with bridge lock
			 * held. Thus, if we have some packets originated by
			 * this NIC ring, just drain it without NIC's rxsync.
			 */
			if (pst_fdt(bk)->npkts > 0) {
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
	struct netmap_vp_adapter *vpna = (struct netmap_vp_adapter*)na;
	struct nm_bridge *b = vpna->na_bdg;

	if (b) {
		netmap_bdg_detach_common(b, vpna->bdg_port, -1);
	}
	if (na->ifp != NULL && !nm_iszombie(na)) {
		NM_DETACH_NA(na->ifp);
	}
}

static void
netmap_pst_krings_delete(struct netmap_adapter *na)
{
	pst_fdtable_free(na);
	netmap_krings_delete(na);
}

static int
netmap_pst_krings_create(struct netmap_adapter *na)
{
	int error = netmap_krings_create(na, 0);

	if (error)
		return error;
	error = pst_fdtable_alloc(na);
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
	struct netmap_pst_adapter *sna;
	struct netmap_vp_adapter *vpna;
	struct netmap_adapter *na;
	int error = 0;
	u_int npipes = 0;

	if (hdr->nr_reqtype != NETMAP_REQ_REGISTER) {
		return EINVAL;
	}

	sna = nm_os_malloc(sizeof(*sna));
	if (sna == NULL)
		return ENOMEM;
	mtx_init(&sna->so_adapters_lock, "so_adapters_lock", NULL, MTX_DEF);
	vpna = &sna->up;
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
	na->na_flags |= NAF_BDG_MAYSLEEP;
	/*
	 * persistent VALE ports look like hw devices
	 * with a native netmap adapter
	 */
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
	/* We have no na->nm_bdg_attach */
	/* other nmd fields are set in the common routine */
	error = netmap_attach_common(na);
	if (error)
		goto err;
	*ret = vpna;
	return 0;

err:
	if (na->nm_mem != NULL)
		netmap_mem_put(na->nm_mem);
	nm_os_free(sna);
	return error;
}

static int
netmap_pst_bwrap_attach(const char *nr_name, struct netmap_adapter *hwna)
{
	struct netmap_bwrap_adapter *bna;
	struct netmap_adapter *na = NULL;
	struct netmap_adapter *hostna = NULL;
	int error;

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
	/* Set the mfs, needed on the VALE mismatch datapath. */
	bna->up.mfs = NM_BDG_MFS_DEFAULT;

	if (hwna->na_flags & NAF_HOST_RINGS) {
		hostna = &bna->host.up;
		hostna->nm_notify = netmap_bwrap_notify;
		bna->host.mfs = NM_BDG_MFS_DEFAULT;
	}

	error = netmap_bwrap_attach_common(na, hwna);
	if (error) {
		nm_os_free(bna);
	}
	return error;
}

struct netmap_bdg_ops pst_bdg_ops = {
	.lookup = NULL,
	.config = netmap_pst_bdg_config,
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
