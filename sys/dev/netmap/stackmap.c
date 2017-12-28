/*
 * Copyright (C) 2017 NetApp. Inc.
 * Copyright (C) 2017 NEC Europe Ltd.
 * Copyright (C) 2017 Michio Honda
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

/*
 * common headers
 */
#if defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct, UID, GID */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <net/ethernet.h>	/* struct ether_header */
#include <netinet/in.h>		/* IPPROTO_UDP */
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/endian.h>
#include <sys/refcount.h>

#elif defined(linux)
#include <bsd_glue.h>
#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>

#ifdef WITH_STACK
int stackmap_no_runtocomp = 0;
int stackmap_host_batch = 1;
int stackmap_verbose = 0;
#ifdef linux
EXPORT_SYMBOL(stackmap_verbose);
#endif
static int stackmap_extra = 2048;
SYSBEGIN(vars_stack);
SYSCTL_DECL(_dev_netmap);
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_no_runtocomp, CTLFLAG_RW, &stackmap_no_runtocomp, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_host_batch, CTLFLAG_RW, &stackmap_host_batch, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_verbose, CTLFLAG_RW, &stackmap_verbose, 0 , "");
SYSCTL_INT(_dev_netmap, OID_AUTO, stackmap_extra, CTLFLAG_RW, &stackmap_extra, 0 , "");
SYSEND;

static inline struct netmap_adapter *
stmp_na(const struct netmap_adapter *slave)
{
	const struct netmap_vp_adapter *vpna;

	if (unlikely(!slave))
		return NULL;
	vpna = (const struct netmap_vp_adapter *)slave;
	return &netmap_bdg_port(vpna->na_bdg, 0)->up;
}

static inline int
stmp_is_host(struct netmap_adapter *na)
{
	return na->nm_register == NULL;
}

/* nm_notify() for NIC RX.
 * Deliver interrupts to the same ring index of master if possible
 */
static int
stmp_intr_notify(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *hwna = kring->na, *vpna, *mna;
	enum txrx t = kring->tx ? NR_TX : NR_RX;

	vpna = (struct netmap_adapter *)hwna->na_private;
	if (unlikely(!vpna))
		return NM_IRQ_COMPLETED;

	/* just wakeup the client on the master */
	mna = stmp_na(vpna);
	if (likely(mna)) {
		u_int me = kring - NMR(hwna, t), last;
		struct netmap_kring *mk;

		if (stackmap_no_runtocomp)
			return netmap_bwrap_intr_notify(kring, flags);
		last = nma_get_nrings(mna, t);
		mk = &NMR(mna, t)[last > me ? me : me % last];
		mk->nm_notify(mk, 0);
	}
	return NM_IRQ_COMPLETED;
}

/*
 * We need to form lists using scb and buf_idx, because they
 * can be very long due to ofo packets that have been queued
 */
#define STACKMAP_FD_HOST	(NM_BDG_MAXPORTS*NM_BDG_MAXRINGS-1)

struct stmp_bdg_q {
	uint32_t bq_head;
	uint32_t bq_tail;
};

struct stmp_fwd {
	uint16_t nfds;
	uint16_t npkts;
	struct stmp_bdg_q fde[NM_BDG_MAXPORTS * NM_BDG_MAXRINGS
	       	+ NM_BDG_BATCH_MAX]; /* XXX */
	uint32_t tmp[NM_BDG_BATCH_MAX];
	uint32_t fds[NM_BDG_BATCH_MAX/2]; // max fd index
};
#define STACKMAP_FT_NULL 0	// invalid buf index

struct stmp_extra_slot {
	struct netmap_slot slot;
	uint16_t prev;
	uint16_t next;
};

struct stmp_extra_pool {
	u_int num;
	struct stmp_extra_slot *slots;
	uint32_t free;
	uint32_t free_tail;
	uint32_t busy;
	uint32_t busy_tail;
};
#define NM_EXT_NULL	((uint16_t)~0)
void
stmp_extra_dequeue(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_ring *ring = kring->ring;
	struct stmp_extra_pool *pool = kring->extra;
	struct stmp_extra_slot *slots, *extra;
	u_int pos;

	if (unlikely(!pool)) {
		RD(1, "kring->extra has gone");
		return;
	} else if (unlikely(!pool->num)) {
		RD(1, "extra slots have gone");
		return;
	}
	slots = pool->slots;
	/* nothing to do if I am on the ring */
	if ((uintptr_t)slot >= (uintptr_t)ring->slot &&
	    (uintptr_t)slot < (uintptr_t)(ring->slot + kring->nkr_num_slots)) {
		return;
	} else if (!(likely((uintptr_t)slot >= (uintptr_t)slots) &&
	      likely((uintptr_t)slot < (uintptr_t)(slots + pool->num)))) {
		D("WARNING: invalid slot");
		return;
	}

	extra = (struct stmp_extra_slot *)slot;
	pos = extra - slots;

	/* remove from busy list (offset has been modified to indicate prev) */
	if (extra->next == NM_EXT_NULL)
		pool->busy_tail = extra->prev; // might be NM_EXT_NULL
	else
		slots[extra->next].prev = extra->prev; // might be NM_EXT_NULL
	if (extra->prev == NM_EXT_NULL)
		pool->busy = extra->next; // might be NM_EXT_NULL
	else
		slots[extra->prev].next = extra->next; // might be NM_EXT_NULL

	/* append to free list */
	extra->next = NM_EXT_NULL;
	if (unlikely(pool->free == NM_EXT_NULL))
		pool->free = pos;
	else
		slots[pool->free_tail].next = pos;
	extra->prev = pool->free_tail; // can be NM_EXT_NULL
	pool->free_tail = pos;
}

int
stmp_extra_enqueue(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct stmp_extra_pool *pool = kring->extra;
	struct stmp_extra_slot *slots = pool->slots, *extra;
	uint32_t tmp;
	u_int pos;
	struct stmp_cb *scb;

	if (pool->free_tail == NM_EXT_NULL)
		return EBUSY;

	pos = pool->free_tail;
	extra = &slots[pos];

	/* remove from free list */
	pool->free_tail = extra->prev;
	if (unlikely(pool->free_tail == NM_EXT_NULL)) // I was the last one
		pool->free = NM_EXT_NULL;
	else // not the last one
		slots[extra->prev].next = NM_EXT_NULL;

	/* apend to busy list */
	extra->next = NM_EXT_NULL;
	if (pool->busy == NM_EXT_NULL) {
		pool->busy = pos;
	} else
		slots[pool->busy_tail].next = pos;
	extra->prev = pool->busy_tail;
	pool->busy_tail = pos;

	scb = NMCB_BUF(NMB(na, slot));
	tmp = extra->slot.buf_idx; // backup
	extra->slot = *slot;
	slot->buf_idx = tmp;
	slot->flags |= NS_BUF_CHANGED;
	slot->len = slot->offset = slot->next = 0;
	slot->fd = 0;

	scbw(scb, kring, &extra->slot);

	return 0;
}

static inline struct stmp_fwd *
stmp_get_fwd(struct netmap_kring *kring)
{
	return (struct stmp_fwd *)kring->nkr_ft;
}

void
stmp_add_fdtable(struct stmp_cb *scb, struct netmap_kring *kring)
{
	struct netmap_slot *slot = scb_slot(scb);
	struct stmp_fwd *ft;
	uint32_t fd = slot->fd;
	struct stmp_bdg_q *fde;
	int i;

	ft = stmp_get_fwd(kring);
	i = slot->buf_idx;
	scb->next = STACKMAP_FT_NULL;
	fde = ft->fde + fd;
	if (fde->bq_head == STACKMAP_FT_NULL) {
		fde->bq_head = fde->bq_tail = i;
		ft->fds[ft->nfds++] = fd;
	} else {
		struct netmap_slot s = { fde->bq_tail };
		struct stmp_cb *prev = NMCB_BUF(NMB(kring->na, &s));
		prev->next = fde->bq_tail = i;
	}
	ft->npkts++;
}

/* TX:
 * 1. sort packets by socket with forming send buffer (in-order iteration)
 * 2. do tcp processing on each socket (out-of-order iteration)
 * We must take into account MOREFRAGS.
 * We do not support INDIRECT as packet movement is done by swapping
 * We thus overwrite ptr field (8 byte width) in a slot to store a 
 * socket (4 byte), next buf index (2 byte).
 * The rest of 2 bytes may be used to store the number of frags 
 * (1 byte) and destination port (1 byte).
 */

struct stmp_sk_adapter *
stmp_ska_from_fd(struct netmap_adapter *na, int fd)
{
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;

	if (unlikely(fd >= sna->sk_adapters_max))
		return NULL;
	return sna->sk_adapters[fd];
}

/* Differ from nm_kr_space() due to different meaning of the lease */
static inline uint32_t
stmp_kr_rxspace(struct netmap_kring *k)
{
	int busy = k->nr_hwtail - k->nkr_hwlease;

	if (busy < 0)
		busy += k->nkr_num_slots;
	return k->nkr_num_slots - 1 - busy;
}

/* bdg_{r,w}lock() must be held */
static void
stmp_bdg_flush(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na, *rxna;
	struct nm_bridge *b = ((struct netmap_vp_adapter *)na)->na_bdg;
	struct stmp_fwd *ft;
	u_int lim_rx, howmany;
	u_int dst_nr, nrings;
	struct netmap_kring *rxkring;
	int j, want, nonfree_num = 0;
	uint32_t *nonfree;

	if (netmap_bdg_rlock(b, na)){
		return;
	}

	ft = stmp_get_fwd(kring);
	nonfree = ft->tmp;
	if (stmp_is_host(na)) {
		want = kring->rhead - kring->nr_hwcur;
		if (want < 0)
			want += kring->nkr_num_slots;
	} else {
		want = ft->npkts;
	}

	/* XXX perhaps this is handled later? */
	if (unlikely(netmap_bdg_active_ports(b) < 3)) {
		RD(1, "only 1 or 2 active ports");
		goto runlock;
	}
	/* Now, we know how many packets go to the receiver */

	if (na == stmp_na(na) || stmp_is_host(na)) {
		rxna = &netmap_bdg_port(b, 1)->up; /* XXX */
	} else {
		rxna = stmp_na(na);
	}

	if (unlikely(!nm_netmap_on(rxna))) {
		panic("receiver na off");
	}
	dst_nr = kring - NMR(kring->na, NR_TX); // XXX cannot rely on ring_id
	nrings = nma_get_nrings(rxna, NR_RX);
	if (dst_nr >= nrings)
		dst_nr = dst_nr % nrings;
	rxkring = NMR(rxna, NR_RX) + dst_nr;
	lim_rx = rxkring->nkr_num_slots - 1;
	j = rxkring->nr_hwtail;

	/* under lock */

	mtx_lock(&rxkring->q_lock);
	if (unlikely(rxkring->nkr_stopped)) {
		mtx_unlock(&rxkring->q_lock);
		goto runlock;
	}
	howmany = stmp_kr_rxspace(rxkring);
	if (howmany < want) { // try to reclaim completed buffers
		u_int i = rxkring->nkr_hwlease, n = 0;

		for (; i != rxkring->nr_hwtail; i = nm_next(i, lim_rx), n++) {
			struct netmap_slot *slot = &rxkring->ring->slot[i];
			struct stmp_cb *scb = NMCB_BUF(NMB(rxna, slot));

			if (stmp_cb_valid(scb) &&
			    stmp_cb_rstate(scb) != SCB_M_NOREF)
				break;
		}
		howmany += n;
		rxkring->nkr_hwlease = i;
	} else if (likely(want < howmany)) {
		howmany = want;
	}

	if (stmp_is_host(na)) { // don't touch buffers
		u_int k = kring->nr_hwcur, lim_tx = kring->nkr_num_slots - 1;

		while (howmany--) {
			struct netmap_slot *ts, *rs, tmp;

			ts = &kring->ring->slot[k];
			__builtin_prefetch(ts);
			rs = &rxkring->ring->slot[j];
			__builtin_prefetch(rs);
			tmp = *rs;
			*rs = *ts;
			*ts = tmp;
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			k = nm_next(k, lim_tx);
			j = nm_next(j, lim_rx);
		}
	} else {
		int n, sent = 0;
		for (n = 0; n < ft->nfds && howmany;) {
			int fd = ft->fds[n];
			struct stmp_bdg_q *bq = ft->fde + fd;
			uint32_t next = bq->bq_head;
			do {
				struct netmap_slot tmp, *ts, *rs;
				struct stmp_cb *scb;

				rs = &rxkring->ring->slot[j];
				__builtin_prefetch(rs);
				tmp.buf_idx = next;
				scb = NMCB_BUF(NMB(na, &tmp));
				next = scb->next;
				ts = scb_slot(scb);
				if (stmp_cb_rstate(scb) == SCB_M_TXREF) {
					nonfree[nonfree_num++] = j;
				}
				scbw(scb, rxkring, rs);
				tmp = *rs;
				*rs = *ts;
				*ts = tmp;
				ts->len = ts->offset = 0;
				ts->fd = 0;
				ts->flags |= NS_BUF_CHANGED;
				rs->flags |= NS_BUF_CHANGED;
				j = nm_next(j, lim_rx);
				sent++;
			} while (next != STACKMAP_FT_NULL && --howmany);
			if (likely(next == STACKMAP_FT_NULL))
				n++;
			bq->bq_head = next; // no NULL if howmany has run out
		}
		ft->nfds -= n;
		ft->npkts -= sent;
		memmove(ft->fds, ft->fds + n, sizeof(ft->fds[0]) * ft->nfds);
	}

	rxkring->nr_hwtail = j;
	mtx_unlock(&rxkring->q_lock);

	rxkring->nm_notify(rxkring, 0);
	rxkring->nkr_hwlease = rxkring->nr_hwcur;

	/* swap out packets still referred by the stack */
	for (j = 0; j < nonfree_num; j++) {
		struct netmap_slot *slot = &rxkring->ring->slot[nonfree[j]];

		if (unlikely(stmp_extra_enqueue(rxkring, slot))) {
			/* Don't reclaim on/after this postion */
			u_long nm_i = slot - rxkring->ring->slot;
			rxkring->nkr_hwlease = nm_i;
			break;
		}
	}
runlock:
	netmap_bdg_runlock(b);
	return;
}

/* Form fdtable to be flushed */
static int
stmp_bdg_preflush(struct netmap_kring *kring)
{
	struct netmap_adapter *na = kring->na;
	int k = kring->nr_hwcur;
	u_int lim_tx = kring->nkr_num_slots - 1;
	const int rhead = kring->rhead;
	int tx = 0;
	struct stmp_fwd *ft = stmp_get_fwd(kring);

	if (na == stmp_na(na))
		tx = 1;
	else if (stmp_is_host(na))
		kring->nkr_hwlease = rhead; // skip loop below
	//if (ft->npkts) {
		//stmp_bdg_flush(kring);	
	//}
	for (k = kring->nkr_hwlease; k != rhead; k = nm_next(k, lim_tx)) {
		struct netmap_slot *slot = &kring->ring->slot[k];
		struct stmp_cb *scb;
		char *nmb = NMB(na, slot);
		int error;

		__builtin_prefetch(nmb);
		if (unlikely(slot->len == 0)) {
			continue;
		}
		scb = NMCB_BUF(nmb);
		scbw(scb, kring, slot);
		error = tx ? nm_os_stmp_send(kring, slot) :
			     nm_os_stmp_recv(kring, slot);
		if (unlikely(error)) {
			/* We stop processing on -EAGAIN(TX) which occurs due
			 * to misbehaviong user e.g., invalid fd.
			 */
			if (error == -EBUSY)
				k = nm_next(k, lim_tx);
			break;
		}
	}
	kring->nkr_hwlease = k; // next position to throw into the stack
	stmp_bdg_flush(kring);
	if (ft->npkts) { // we have leftover, cannot report k
		int j;

		/* try to reclaim buffers on txring */
		for (j = kring->nr_hwcur; j != k; j = nm_next(j, lim_tx)) {
			struct netmap_slot *slot = &kring->ring->slot[j];
			struct stmp_cb *scb;
		       
			if (unlikely(!slot->len))
				continue;
			scb = NMCB_BUF(NMB(na, slot));
			/* scb can be invalid due to new buffer swap-ed in */
			if (stmp_cb_valid(scb) &&
			    stmp_cb_rstate(scb) != SCB_M_NOREF)
				break;
		}
		k = j;
	}
	return k;
}

static int
stmp_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_stack_adapter *sna =
		(struct netmap_stack_adapter *)kring->na;
	struct nm_bridge *b = sna->up.na_bdg;
	int i, err;
	register_t	intr;

	/* TODO scan only necessary ports */
	err = netmap_vp_rxsync(kring, flags); // reclaim buffers released
	if (err)
		return err;
	if (stackmap_no_runtocomp)
		return 0;

	intr = intr_disable(); // emulate software interrupt context

	for_bdg_ports(i, b) {
		struct netmap_vp_adapter *vpna = netmap_bdg_port(b, i);
		struct netmap_adapter *na = &vpna->up;
		struct netmap_adapter *hwna;
		u_int first, stride, last, i;
	
		if (netmap_bdg_idx(vpna) == netmap_bdg_idx(&sna->up))
			continue;
		else if (stmp_is_host(na))
			continue;

		/* We assume the same number of hwna with vpna
		 * (see netmap_bwrap_attach()) */
		hwna = ((struct netmap_bwrap_adapter *)vpna)->hwna;

		/* hw ring(s) to scan */
		first = kring->na->num_rx_rings > 1 ? kring->ring_id : 0;
		stride = kring->na->num_rx_rings;
		last = na->num_rx_rings;
		for (i = first; i < last; i += stride) {
			struct netmap_kring *hwk, *bk, *hk;
		       
			hwk = &NMR(hwna, NR_RX)[i];
			bk = &NMR(na, NR_TX)[i];
			hk = &NMR(hwna, NR_RX)[last];
			if (hwna->na_flags & NAF_HOST_MQ)
				hk += i;
			/*
			 * bdg_flush has been put off because we do not want
			 * it to run in bdg_config context with bridge wlock
			 * held. Thus, if we have some packets originated by
			 * this NIC ring, just drain it without NIC's rxsync.
			 */
			if (stmp_get_fwd(bk)->npkts > 0) {
				stmp_bdg_flush(bk);
			} else {
				netmap_bwrap_intr_notify(hwk, 0);
				if (stackmap_host_batch) {
					netmap_bwrap_intr_notify(hk, 0);
				}
			}
		}
	}
	intr_restore(intr);
	return netmap_vp_rxsync(kring, flags);
}


static int
stmp_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	u_int const head = kring->rhead;
	u_int done;

	if (unlikely(((struct netmap_vp_adapter *)na)->na_bdg == NULL)) {
		done = head;
		return 0;
	}
	done = stmp_bdg_preflush(kring);

	kring->nr_hwcur = done;
	kring->nr_hwtail = nm_prev(done, kring->nkr_num_slots - 1);
	return 0;
}

static int
nombq_rxsync(struct netmap_kring *kring, int flags)
{
	(void)kring;
	(void)flags;
	return 0;
}

static int
nombq(struct netmap_adapter *na, struct mbuf *m)
{
	struct netmap_kring *kring;
	struct netmap_slot *hslot;
	u_int head, nm_i, lim, len = MBUF_LEN(m);

	/* host ring */
	nm_i = curcpu % nm_num_host_rings(na, NR_RX);
	kring = &NMR(na, NR_RX)[nma_get_nrings(na, NR_RX) + nm_i];
	head = kring->rhead;
	lim = kring->nkr_num_slots - 1;
	nm_i = kring->nr_hwtail;
	/* check space */
	if (unlikely(nm_i == nm_prev(kring->nr_hwcur, lim))) {
		RD(1, "kring full");
		m_freem(m);
		return EBUSY;
	} else if (unlikely(!nm_netmap_on(na))) {
		m_freem(m);
		return ENXIO;
	}
	hslot = &kring->ring->slot[nm_i];
	m_copydata(m, 0, len, (char *)NMB(na, hslot) + na->virt_hdr_len);
	hslot->len = len;
	kring->nr_hwtail = nm_next(nm_i, lim);

	nm_i = kring->nr_hwcur;
	if (likely(nm_i != head)) {
		kring->nr_hwcur = head;
	}
	if (!stackmap_host_batch) {
		netmap_bwrap_intr_notify(kring, 0);
	}
	/* as if netmap_transmit + rxsync_from_host done */
	m_freem(m);
	return 0;
}

#ifdef __FreeBSD__
/* FreeBSD doesn't have protocol header offsets filled */
static inline void
__mbuf_proto_headers(struct mbuf *m)
{
	uint16_t ethertype;

	ethertype = ntohs(*(uint16_t *)(m->m_data + 12));
	if (MBUF_NETWORK_OFFSET(m) > 0)
		return;
	m->m_pkthdr.l2hlen = sizeof(struct ether_header);
	m->m_pkthdr.l3hlen = sizeof(struct nm_iphdr);
}
#else
#define __mbuf_proto_headers(m)
#endif /* __FreeBSD__ */

static void
csum_transmit(struct netmap_adapter *na, struct mbuf *m)
{
	if (nm_os_mbuf_has_offld(m)) {
		struct nm_iphdr *iph;
		char *th;
		uint16_t *check;

		__mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)MBUF_NETWORK_HEADER(m);
		KASSERT(iph != NULL, ("NULL iph"));
		th = MBUF_TRANSPORT_HEADER(m);
		KASSERT(th != NULL, ("NULL th"));
		th = MBUF_TRANSPORT_HEADER(m);
		if (iph->protocol == IPPROTO_UDP) {
			check = &((struct nm_udphdr *)th)->check;
		} else if (likely(iph->protocol == IPPROTO_TCP)) {
			check = &((struct nm_tcphdr *)th)->check;
		} else {
			panic("bad proto %u w/ offld", iph->protocol);
		}
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
stmp_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	struct stmp_cb *scb = NULL;
	struct netmap_slot *slot;
	char *nmb;
	int mismatch;
	struct mbuf *md = m;

#ifdef linux
	/* txsync-ing TX packets are always frags */
	if (!MBUF_NONLINEAR(m)) {
		csum_transmit(na, m);
		return 0;
	}

	scb = NMCB_EXT(m, 0, NETMAP_BUF_SIZE(na));
#else
	/* M_EXT or multiple mbufs (i.e., chain) */
	if ((m->m_flags & M_EXT)) { // not TCP case
		scb = NMCB_EXT(m, 0, NETMAP_BUF_SIZE(na));
	}
	if (!scb || !stmp_cb_valid(scb)) { // TCP case
		if (MBUF_NONLINEAR(m) && (m->m_next->m_flags & M_EXT)) {
			scb = NMCB_EXT(m->m_next, 0, NETMAP_BUF_SIZE(na));
		}
		md = m->m_next;
	}
	if (!scb || !stmp_cb_valid(scb)) {
		csum_transmit(na, m);
		return 0;
	}
#endif /* linux */

	if (unlikely(stmp_cb_rstate(scb) != SCB_M_STACK) ||
	    /* FreeBSD ARP reply recycles the request mbuf */
	    unlikely(scb_kring(scb) &&
	    scb_kring(scb)->na->na_private == na->na_private)) {
		MBUF_LINEARIZE(m); // XXX
		csum_transmit(na, m);
		return 0;
	}
	/* Valid scb, txsync-ing packet. */
	slot = scb_slot(scb);
	if (unlikely(stmp_cb_rstate(scb) == SCB_M_QUEUED)) {
	       	/* originated by netmap but has been queued in either extra
		 * or txring slot. The backend might drop this packet.
		 */
#ifdef linux
		struct stmp_cb *scb2;
		int i, n = MBUF_CLUSTERS(m);

		for (i = 0; i < n; i++) {
			scb2 = NMCB_EXT(m, i, NETMAP_BUF_SIZE(na));
			stmp_cb_wstate(scb2, SCB_M_NOREF);
		}
#else
		/* To be done */
#endif /* linux */
		slot->len = 0; // XXX
		MBUF_LINEARIZE(m);
		csum_transmit(na, m);
		return 0;
	}

	nmb = NMB(na, slot);

	/* bring protocol headers in */
	mismatch = MBUF_HEADLEN(m) - (int)slot->offset;

	ND("MBUF_HEADLEN(m) %d MBUF_HEADLEN(nd) %d m->m_len %d"
	   "m->m_pkthdr.len %d m->m_pkthdr.l2hlen %d "
	   "m->m_pkthdr.l3hlen %d m->m_pkthdr.l4hlen %d ethtype 0x%x "
	   "slot->len %u slot->offset %u virt %u offld %d mismatch %d",
	   MBUF_HEADLEN(m), MBUF_HEADLEN(md), m->m_len, m->m_pkthdr.len,
	   m->m_pkthdr.l2hlen, m->m_pkthdr.l3hlen, m->m_pkthdr.l4hlen,
	   ntohs(*(uint16_t *)(m->m_data + 12)), slot->len, slot->offset,
	   na->virt_hdr_len, nm_os_mbuf_has_offld(m), mismatch);
	if (!mismatch) {
		/* Length has already been validated */
		memcpy(nmb + na->virt_hdr_len, MBUF_DATA(m), slot->offset);
	} else {
		m_copydata(m, 0, MBUF_LEN(m), nmb + na->virt_hdr_len);
		slot->len += mismatch;
	}

	if (nm_os_mbuf_has_offld(m)) {
		struct nm_iphdr *iph;
		struct nm_tcphdr *tcph;
		uint16_t *check;
		int len, v = na->virt_hdr_len;

		__mbuf_proto_headers(m);
		iph = (struct nm_iphdr *)(nmb + v + MBUF_NETWORK_OFFSET(m));
		tcph = (struct nm_tcphdr *)(nmb + v + MBUF_TRANSPORT_OFFSET(m));
		check = &tcph->check;
		*check = 0;
		len = slot->len - v - MBUF_TRANSPORT_OFFSET(m);
		nm_os_csum_tcpudp_ipv4(iph, tcph, len, check);
	}

	stmp_add_fdtable(scb, scb_kring(scb));

	/* We don't know when the stack actually releases the data;
	 * it might holds reference via clone.
	 */
	stmp_cb_wstate(scb, SCB_M_TXREF);
#ifdef linux
	/* for FreeBSD mbuf comes from our code */
	nm_set_mbuf_data_destructor(m, &scb->ui,
			nm_os_stmp_mbuf_data_destructor);

#endif /* linux */
	m_freem(m);
	return 0;
}

static void
stmp_extra_free(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			struct stmp_extra_pool *extra;

			if (!kring->extra)
				continue;
			extra = kring->extra;
			kring->extra = NULL;
			extra->num = 0;
			if (extra->slots)
				nm_os_free(extra->slots);
			nm_os_free(extra);
		}
	}
}

static int
stmp_extra_alloc(struct netmap_adapter *na)
{
	enum txrx t;

	for_rx_tx(t) {
		int i;

		/* XXX probably we don't need extra on host rings */
		for (i = 0; i < netmap_real_rings(na, t); i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			struct stmp_extra_pool *pool;
			struct stmp_extra_slot *extra_slots = NULL;
			u_int want = stackmap_extra, n, j, next;

			pool = nm_os_malloc(sizeof(*kring->extra));
			if (!pool)
				break;
			kring->extra = pool;

			n = netmap_extra_alloc(na, &next, want);
			if (n < want)
				D("allocated only %u bufs", n);
			kring->extra->num = n;

			if (n) {
				extra_slots = nm_os_malloc(sizeof(*extra_slots)
						* n);
				if (!extra_slots)
					break;
			}

			for (j = 0; j < n; j++) {
				struct stmp_extra_slot *exs;
				struct netmap_slot tmp = {.buf_idx = next};

				exs = &extra_slots[j];
				exs->slot.buf_idx = next;
				exs->slot.len = 0;
				exs->prev = j == 0 ? NM_EXT_NULL : j - 1;
				exs->next = j + 1 == n ? NM_EXT_NULL : j + 1;
				next = *(uint32_t *)NMB(na, &tmp);
			}
			pool->free = 0;
			pool->free_tail = n - 1;
			pool->busy = pool->busy_tail = NM_EXT_NULL;
			pool->slots = extra_slots;
		}
		/* rollaback on error */
		if (i < netmap_real_rings(na, t)) {
			stmp_extra_free(na);
			return ENOMEM;
		}
	}
	return 0;
}

/* Create extra buffers and mbuf pool */

#define for_each_kring_n(_i, _k, _karr, _n) \
	for (_k=_karr, _i = 0; _i < _n; (_k)++, (_i)++)
#define for_each_tx_kring(_i, _k, _na) \
	for_each_kring_n(_i, _k, (_na)->tx_rings, (_na)->num_tx_rings)

static int
stmp_mbufpool_alloc(struct netmap_adapter *na)
{
	struct netmap_kring *kring;
	int r, error = 0;

	for_each_tx_kring(r, kring, na) {
		kring->tx_pool = NULL;
	}
	for_each_tx_kring(r, kring, na) {
		kring->tx_pool =
			nm_os_malloc(na->num_tx_desc *
				sizeof(struct mbuf *));
		if (!kring->tx_pool) {
			D("tx_pool allocation failed");
			error = ENOMEM;
			break;
		}
		bzero(kring->tx_pool, na->num_tx_desc * sizeof(struct mbuf *));
		kring->tx_pool[0] = nm_os_malloc(sizeof(struct mbuf));
		if (!kring->tx_pool[0]) {
			error = ENOMEM;
			break;
		}
		bzero(kring->tx_pool[0], sizeof(struct mbuf));
	}
	if (error) {
		for_each_tx_kring(r, kring, na) {
			if (kring->tx_pool == NULL)
				continue;
			if (kring->tx_pool[0])
				nm_os_free(kring->tx_pool[0]);
			nm_os_free(kring->tx_pool);
			kring->tx_pool = NULL;
		}
	}
	return error;
}

static void
stmp_mbufpool_free(struct netmap_adapter *na)
{
	struct netmap_kring *kring;
	int r;

	for_each_tx_kring(r, kring, na) {
		if (kring->tx_pool == NULL)
			continue;
		if (kring->tx_pool[0])
			nm_os_free(kring->tx_pool[0]);
		nm_os_free(kring->tx_pool);
		kring->tx_pool = NULL;
	}
}

/* Stackmap extends default bwrap_reg() and bwrap_attach() */
static int
stmp_bwrap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_bwrap_adapter *bna = (struct netmap_bwrap_adapter *)na;
	struct netmap_adapter *hwna = bna->hwna;
#ifdef linux
	struct netmap_hw_adapter *hw = (struct netmap_hw_adapter *)hwna;
#endif
	int error;

	error = netmap_bwrap_reg(na, onoff);
	if (error)
		return error;

	if (onoff) {
		int i;

		if (stmp_extra_alloc(na)) {
			D("extra_alloc failed for slave");
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}
		if (stmp_mbufpool_alloc(na)) {
			D("mbufpool_alloc failed for slave");
			stmp_extra_free(na);
			netmap_bwrap_reg(na, 0);
			return ENOMEM;
		}

		/* na->if_transmit already has backup */
#ifdef linux
		hw->nm_ndo.ndo_start_xmit = linux_stmp_start_xmit;
		/* re-overwrite */
		hwna->ifp->netdev_ops = &hw->nm_ndo;
#elif defined (__FreeBSD__)
		hwna->ifp->if_transmit = stmp_transmit;
#endif /* linux */

		/* set void callback on host rings */
		for (i = nma_get_nrings(hwna, NR_RX);
		     i < netmap_real_rings(hwna, NR_RX); i++) {
			NMR(hwna, NR_RX)[i].nm_sync = nombq_rxsync;
		}
	} else {
#ifdef linux
		/* restore default start_xmit for future register */
		((struct netmap_hw_adapter *)hwna)->nm_ndo.ndo_start_xmit =
			linux_netmap_start_xmit;
#else
		hwna->ifp->if_transmit = hwna->if_transmit;
#endif
		stmp_mbufpool_free(na);
		stmp_extra_free(na);
	}
	return error;
}

static int
stmp_bwrap_attach(struct netmap_adapter *na)
{
	struct netmap_bwrap_adapter *bna = (struct netmap_bwrap_adapter *)na;
	struct netmap_adapter *hwna = bna->hwna;

	hwna->virt_hdr_len = na->virt_hdr_len;
	if (hwna->na_flags & NAF_HOST_RINGS)
		bna->host.up.virt_hdr_len = na->virt_hdr_len;
	na->nm_register = stmp_bwrap_reg;
	na->nm_txsync = stmp_txsync;
	if (!stackmap_no_runtocomp) {
		na->nm_intr_notify = stmp_intr_notify;
	}
	return 0;
}


/* XXX Ugly to separate from reg_slaves(), but we cannot detach
 * slaves by name as get_bnsbridges() fails due to lack of current.
 */
static void
stmp_unreg_slaves(struct netmap_adapter *na) {
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;
	struct nm_bridge *b = sna->up.na_bdg;
	int i, me = netmap_bdg_idx(&sna->up);

	for_bdg_ports(i, b) {
		struct netmap_adapter *slave = &netmap_bdg_port(b, i)->up;
		struct netmap_adapter *hwna;
		struct lut_entry *lut;

		if (i == me)
			continue;
		hwna = ((struct netmap_bwrap_adapter *)slave)->hwna;
		lut = hwna->na_lut.lut;
		netmap_adapter_get(slave);
		slave->nm_bdg_ctl(slave, NULL, 0);
		netmap_adapter_put(slave);
	}
}

static int
stmp_reg_slaves(struct netmap_adapter *na)
{
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;
	char *tok, *s, *s_orig;
	int error = 0;
	struct nmreq nmr;
	char *p = nmr.nr_name;

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	nmr.nr_cmd = NETMAP_BDG_ATTACH;
	/* Regular host stack port for indirect packets */
	nmr.nr_arg1 = NETMAP_BDG_HOST;
	p += strlcat(p, ":", sizeof(nmr.nr_name) - 
		strlcpy(p, netmap_bdg_name(&sna->up), sizeof(nmr.nr_name)));
	if (!strlen(sna->suffix))
		return 0;

	s = strdup(sna->suffix, M_DEVBUF);
	if (!s)
		return ENOMEM;
	s_orig = s;
	while ((tok = strsep(&s, "+")) != NULL &&
	    strncmp(tok, p, strlen(tok))) {
		struct netmap_adapter *slave = NULL;

		strlcpy(p, tok, strlen(tok) + 1);
		error = netmap_get_bdg_na(&nmr, &slave, na->nm_mem, 1);
		if (error)
			continue;
		if (!slave || !nm_is_bwrap(slave) /* XXX ugly */) {
			D("no error on get_bdg_na() but no valid adapter");
			netmap_adapter_put(slave);
			continue;
		}

		/* install reg/intr_notify/txsync callbacks */
		slave->virt_hdr_len = na->virt_hdr_len;
		stmp_bwrap_attach(slave);

		error = slave->nm_bdg_ctl(slave, &nmr, 1);
		if (error) {
			netmap_adapter_put(slave);
			continue;
		}
		{
			struct netmap_bwrap_adapter *bna =
				(struct netmap_bwrap_adapter *)slave;
			struct netmap_adapter *tmp[3] =
				{&bna->up.up, bna->hwna, &bna->host.up};
			int i;

			for (i = 0; i < 3; i++) {
				struct netmap_adapter *a = tmp[i];
				D("%s rings %d %d real %d %d", a->name,
					nma_get_nrings(a, NR_TX),
					nma_get_nrings(a, NR_RX),
					netmap_real_rings(a, NR_TX),
					netmap_real_rings(a, NR_RX));
			}
		}
	}
	nm_os_free(s_orig);
	return error;
}

/*
 * When stackmap dies first, it simply restores all the socket
 * information on dtor().
 * Otherwise our sk->sk_destructor will cleanup stackmap states
 */
static void
stmp_unregister_socket(struct stmp_sk_adapter *ska)
{
	NM_SOCK_T *sk = ska->sk;
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)ska->na;

	if (ska->fd >= sna->sk_adapters_max) {
		D("WARNING: non-registered or invalid fd %d", ska->fd);
	} else {
		sna->sk_adapters[ska->fd] = NULL;
		NM_SOCK_LOCK(sk);
		SOCKBUF_LOCK(&sk->so_rcv);
		RESTORE_DATA_READY(sk, ska);
		RESTORE_DESTRUCTOR(sk, ska);
		stmp_wsk(NULL, sk);
		SOCKBUF_UNLOCK(&sk->so_rcv);
		NM_SOCK_UNLOCK(sk);
	}
	nm_os_free(ska);
}

static void
stmp_sk_destruct(NM_SOCK_T *sk)
{
	struct stmp_sk_adapter *ska;
	struct netmap_stack_adapter *sna;

	ska = stmp_sk(sk);
	if (ska->save_sk_destruct) {
		ska->save_sk_destruct(sk);
	}
	sna = (struct netmap_stack_adapter *)ska->na;
	netmap_bdg_wlock(sna->up.na_bdg);
	stmp_unregister_socket(ska);
	netmap_bdg_wunlock(sna->up.na_bdg);
}

static void
stmp_bdg_dtor(const struct netmap_vp_adapter *vpna)
{
	struct netmap_stack_adapter *sna;
	int i;

	if (&vpna->up != stmp_na(&vpna->up))
		return;

	//sna = (struct netmap_stack_adapter *)vpna;
	sna = (struct netmap_stack_adapter *)(void *)(uintptr_t)vpna;
	for (i = 0; i < sna->sk_adapters_max; i++) {
		struct stmp_sk_adapter *ska = sna->sk_adapters[i];
		if (ska)
			stmp_unregister_socket(ska);
	}
	nm_os_free(sna->sk_adapters);
	sna->sk_adapters_max = 0;
}

static int
stmp_register_fd(struct netmap_adapter *na, int fd)
{
	NM_SOCK_T *sk;
	void *file;
	struct stmp_sk_adapter *ska;
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;
	int on = 1;
	struct sockopt sopt;

	/* first check table size */
	if (fd >= sna->sk_adapters_max) {
		struct stmp_sk_adapter **old = sna->sk_adapters, **new;
		int oldsize = sna->sk_adapters_max;
		int newsize = oldsize ? oldsize * 2 : DEFAULT_SK_ADAPTERS;

		new = nm_os_malloc(sizeof(new) * newsize);
		if (!new) {
			D("failed to extend fd->sk_adapter table");
			return ENOMEM;
		}
		if (old) {
			memcpy(new, old, sizeof(old) * oldsize);
			nm_os_free(old);
		}
		sna->sk_adapters = new;
		sna->sk_adapters_max = newsize;
	}

	sk = nm_os_sock_fget(fd, &file);
	if (!sk)
		return EINVAL;
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = TCP_NODELAY;
	sopt.sopt_val = &on;
	sopt.sopt_valsize = sizeof(on);
	if (sosetopt(sk, &sopt) < 0) {
		RD(1, "WARNING: failed sosetopt(TCP_NODELAY)");
	}
	NM_SOCK_LOCK(sk); // kernel_setsockopt() above internally takes this lock
	/* This validation under lock is needed to handle
	 * simultaneous accept/config
	 */
	if (stmp_sk(sk)) {
		NM_SOCK_UNLOCK(sk);
		nm_os_sock_fput(sk, file);
		D("ska already allocated");
		return EBUSY;
	}
	ska = nm_os_malloc(sizeof(*ska));
	if (!ska) {
		NM_SOCK_UNLOCK(sk);
		nm_os_sock_fput(sk, file);
		return ENOMEM;
	}
	SOCKBUF_LOCK(&sk->so_rcv);
	SAVE_DATA_READY(sk, ska);
	SAVE_DESTRUCTOR(sk, ska);
	ska->na = na;
	ska->sk = sk;
	ska->fd = fd;
	SET_DATA_READY(sk, nm_os_stmp_data_ready);
	SET_DESTRUCTOR(sk, stmp_sk_destruct);
	stmp_wsk(ska, sk);
	sna->sk_adapters[fd] = ska;
	SOCKBUF_UNLOCK(&sk->so_rcv);
	nm_os_stmp_sb_drain(na, sk);
	NM_SOCK_UNLOCK(sk);
	nm_os_sock_fput(sk, file);
	return 0;
}
static int
stmp_bdg_config(struct nm_ifreq *ifr,
			struct netmap_vp_adapter *vpna)
{
	int fd = *(int *)ifr->data;
	struct netmap_adapter *na = &vpna->up;

	return stmp_register_fd(na, fd);
}

static int
stmp_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_stack_adapter *sna = (struct netmap_stack_adapter *)na;
	int err;

	D("%s (%p) onoff %d suffix: %s rings %d %d",
		na->name, sna, onoff, sna->suffix[0] ? sna->suffix : "none",
		na->num_tx_rings, na->num_rx_rings);
	err = sna->save_reg(na, onoff);
	if (err)
		return err;
	if (onoff) {
		struct netmap_bdg_ops ops
			= {NULL, stmp_bdg_config, stmp_bdg_dtor};
		if (na->active_fds > 0) {
			return 0;
		}

		if (stmp_extra_alloc(na))
			return err;
		/* install config handler */
		netmap_bdg_set_ops(sna->up.na_bdg, &ops);
		na->virt_hdr_len = sizeof(struct stmp_cb);
#ifdef NETMAP_MEM_MAPPING
		//netmap_mem_set_buf_offset(na->nm_mem, na->virt_hdr_len);
#endif /* NETMAP_MEM_MAPPING */

		return stmp_reg_slaves(na);
	}
	stmp_unreg_slaves(na);
	return 0;
}

/* allocating skb is postponed until krings are created on register */
static int
stmp_attach(struct netmap_adapter *arg, struct netmap_adapter **ret,
		const char *suffix)
{
	struct netmap_vp_adapter *vparg = (struct netmap_vp_adapter *)arg;
	struct nm_bridge *b = vparg->na_bdg;
	struct netmap_stack_adapter *sna;
	struct netmap_vp_adapter *vpna;
	struct netmap_adapter *na;


	sna = nm_os_malloc(sizeof(*sna));
	if (sna == NULL)
		return ENOMEM;
	vpna = &sna->up;
	/* copy everything and replace references from hwna and bridge */
	*vpna = *((struct netmap_vp_adapter *)arg);
	vpna->up.na_vp = vpna;
	netmap_bdg_wlock(b);
	netmap_set_bdg_port(b, vpna->bdg_port, vpna);
	nm_os_free(arg);

	na = &vpna->up;
	sna->save_reg = na->nm_register;
	na->nm_register = stmp_reg;
	na->nm_txsync = stmp_txsync;
	na->nm_rxsync = stmp_rxsync;
	strncpy(sna->suffix, suffix, sizeof(sna->suffix));
	netmap_bdg_wunlock(b);
	*ret = na;
	return 0;
}

int
netmap_get_stack_na(struct nmreq *nmr, struct netmap_mem_d *nmd, struct netmap_adapter **ret,
	       	int create)
{
	struct netmap_adapter *na;
	int error;

	*ret = NULL;
	if (strncmp(nmr->nr_name, NM_STACK_NAME, strlen(NM_STACK_NAME)))
		return 0;

	/* XXX always a new, private allocator */
	error = netmap_get_bdg_na(nmr, &na, nmd, create);
	if (error) {
		D("error in get_bdg_na");
		return error;
	}
	/* only master port is extended */
	if (!nm_is_bwrap(na) && na->na_refcount == 1 /* just created */) {
		/* extend the original adapter */
		error = stmp_attach(na, ret, nmr->nr_extname);
	} else {
		*ret = na;
	}
	return error;
}
#endif /* WITH_STACK */
