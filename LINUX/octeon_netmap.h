/*
 * Copyright 2017, Allied Telesis Labs New Zealand, Ltd
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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
#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

/* Private adapter storage */
struct oct_nm_adapter {
	struct netmap_hw_adapter up;
	int base;		/* Group base */
	int fau;		/* Fetch and Add register to keep track of transmitted packet */
};

/* Bitmap used to keep track of available groups */
static unsigned long netmap_receive_groups = 0;

static void
octeon_netmap_irq_enable(struct netmap_adapter *na, int queue, int onoff)
{
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	struct netmap_kring *kring = NMR(na, NR_RX)[0];
	union cvmx_pow_wq_int wq_int;
	union cvmx_pow_wq_int_thrx int_thr;
	int group = ona->base + queue;

	nm_prdis("%s: IRQ %s", na->name, onoff ? "ON" : "OFF");

	mtx_lock(&kring->q_lock);
	if (onoff) {
		/* Enable */
		int_thr.u64 = 0;
		int_thr.s.iq_thr = 1;
		cvmx_write_csr(CVMX_POW_WQ_INT_THRX(group), int_thr.u64);
	} else {
		/* Disable */
		int_thr.u64 = 0;
		int_thr.s.iq_thr = 0;
		cvmx_write_csr(CVMX_POW_WQ_INT_THRX(group), int_thr.u64);
		/* Clear */
		wq_int.u64 = 0;
		wq_int.s.wq_int = 1 << group;
		cvmx_write_csr(CVMX_POW_WQ_INT, wq_int.u64);
	}
	mtx_unlock(&kring->q_lock);
}

static irqreturn_t octeon_netmap_do_interrupt(int cpl, void *data)
{
	struct netmap_adapter *na = (struct netmap_adapter *)data;
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	int queue = cpl - OCTEON_IRQ_WORKQ0 - ona->base;
	int work_done = 0;

	octeon_netmap_irq_enable(na, queue, 0);
	return netmap_rx_irq(na->ifp, queue, &work_done) ==
	    NM_IRQ_COMPLETED ? IRQ_HANDLED : IRQ_NONE;
}

static void octeon_netmap_submit_kernel(struct cvmx_wqe *work)
{
	uint16_t hash = work->word1.tag & 0xFFFF;
	uint64_t group = hash % hweight_long(pow_receive_groups);

	cvmx_pow_work_submit(work, work->word1.tag, work->word1.tag_type,
			     cvmx_wqe_get_qos(work), group);
}

static int octeon_netmap_enable_port(struct netmap_adapter *na)
{
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	struct ifnet *ifp = na->ifp;
	struct octeon_ethernet *priv = netdev_priv(ifp);
	union cvmx_pip_prt_tagx pip_prt_tagx;
	union cvmx_pip_prt_cfgx pip_prt_cfgx;
	int port = priv->port;
	int tag_mask = ((1 << get_count_order(na->num_rx_rings)) - 1) ? : 1;
	int i;

	nm_prdis("%s: Enable Port %d", ifp->name, port);

	/* Select a contiguous block of groups for the rings */
	ona->base = -1;
	for (i = 0; i < 16; i++) {
		if ((netmap_receive_groups & (tag_mask << i)) == 0) {
			ona->base = i;
			break;
		}
	}
	if (ona->base == -1) {
		pr_err("%s: Couldn't find a contiguous block of free groups\n",
		       ifp->name);
		return -1;
	}

	/* Choose a FAU for packet transmission tracking
	 * Avoid space used by default driver:
	 * TO_CLEAN = CVMX_FAU_REG_END - sizeof(u32)
	 * TO_FREE = TO_CLEAN - sizeof(u32)
	 * PORT0 = TO_FREE - sizeof(u32)
	 * PORT16 = PORT0 - sizeof(u32)
	 * PORT24 = PORT16 - sizeof(u32)
	 */
	ona->fau = priv->fau - (3 * sizeof(u32));
	nm_prdis("%s: FAU Default:0x%0x Netmap:0x%0x\n", ifp->name, priv->fau,
		 ona->fau);
	cvmx_fau_atomic_write32(ona->fau, 0);

	/* Register an IRQ handler for each group interrupts */
	for (i = 0; i < na->num_rx_rings; i++) {
		struct netmap_kring *kring = na->rx_rings[i];
		int group = ona->base + i;

		/* Request the interrupt */
		if (request_irq(OCTEON_IRQ_WORKQ0 + group,
				octeon_netmap_do_interrupt, 0, kring->name,
				na)) {
			panic("Could not acquire Ethernet IRQ %d\n",
			      OCTEON_IRQ_WORKQ0 + group);
			return -1;
		}
		/* Pin the IRQ to the core with the same number */
		irq_set_affinity_hint(OCTEON_IRQ_WORKQ0 + group, cpumask_of(i));

		/* Enable POW interrupt when our port has at least one packet */
		octeon_netmap_irq_enable(na, i, 1);

		/* Mark the group as used */
		set_bit(group, &netmap_receive_groups);
	}

	/* Configure port to use netmap receive group(s) */
	pip_prt_tagx.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
	pip_prt_tagx.s.grptagbase = ona->base;
	pip_prt_tagx.s.grptagmask = ~tag_mask;
	pip_prt_tagx.s.grp = ona->base;
	cvmx_write_csr(CVMX_PIP_PRT_TAGX(port), pip_prt_tagx.u64);

	/* Set the default QOS level for the port */
	pip_prt_cfgx.u64 = cvmx_read_csr(CVMX_PIP_PRT_CFGX(port));
	pip_prt_cfgx.s.qos = 1;
	cvmx_write_csr(CVMX_PIP_PRT_CFGX(port), pip_prt_cfgx.u64);

	return 0;
}

static int octeon_netmap_disable_port(struct netmap_adapter *na)
{
	const int coreid = cvmx_get_core_num();
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	struct ifnet *ifp = na->ifp;
	struct octeon_ethernet *priv = netdev_priv(ifp);
	union cvmx_pip_prt_tagx pip_prt_tagx;
	int port = priv->port;
	int i;

	nm_prdis("%s: Disable Port %d", ifp->name, port);

	/* Configure port to use default receive group(s) */
	pip_prt_tagx.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(port));
	pip_prt_tagx.s.grptagbase = 0;
	pip_prt_tagx.s.grptagmask = ~((1 << receive_group_order) - 1);
	if (receive_group_order)
		pip_prt_tagx.s.grp = 0;
	else
		pip_prt_tagx.s.grp = pow_receive_group;
	cvmx_write_csr(CVMX_PIP_PRT_TAGX(port), pip_prt_tagx.u64);

	/* Pass all queued packets to the default work queue */
	for (i = 0; i < na->num_rx_rings; i++) {
		while (1) {
			u64 old_group_mask;
			struct cvmx_wqe *work;
			int group = ona->base + i;

			old_group_mask =
			    cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreid));
			cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreid),
				       (old_group_mask & ~0xFFFFull) | 1 <<
				       group);
			work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
			cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreid),
				       old_group_mask);
			if (!work)
				break;
			octeon_netmap_submit_kernel(work);
		}
	}

	/* Free the interrupt handlers */
	for (i = 0; i < na->num_rx_rings; i++) {
		int group = ona->base + i;

		/* Disable interrupt and free the handler */
		octeon_netmap_irq_enable(na, i, 0);
		irq_set_affinity_hint(OCTEON_IRQ_WORKQ0 + group, NULL);
		free_irq(OCTEON_IRQ_WORKQ0 + group, na);
		clear_bit(group, &netmap_receive_groups);
	}

	return 0;
}

/*
 * Register/unregister. We are already under netmap lock.
 */
static int octeon_netmap_reg(struct netmap_adapter *na, int onoff)
{
	int r;

	nm_prdis("%s: %s", na->ifp->name, onoff ? "ON" : "OFF");

	/* Enable or disable */
	if (onoff) {
		if (na->active_fds == 0) {
			octeon_netmap_enable_port(na);
		}
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
		if (na->active_fds == 0) {
			octeon_netmap_disable_port(na);
		}
	}
	for (r = 0; r < na->num_rx_rings; r++) {
		(void)netmap_reset(na, NR_RX, r, 0);
	}
	for (r = 0; r < na->num_tx_rings; r++) {
		(void)netmap_reset(na, NR_TX, r, 0);
	}

	return 0;
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int octeon_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = (struct netmap_adapter *)kring->na;
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	struct ifnet *ifp = na->ifp;
	struct octeon_ethernet *priv = netdev_priv(ifp);
	struct netmap_ring *ring = kring->ring;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int qos = 0;
	u_int nm_i;
	u_int n;

	if (!netif_carrier_ok(ifp)) {
		return 0;
	}

	/* First part: process new packets to send */
	nm_i = kring->nr_hwcur;
	for (n = 0; nm_i != head; n++) {
		struct netmap_slot *slot = &ring->slot[nm_i];
		union cvmx_pko_command_word0 pko_command;
		union cvmx_buf_ptr hw_buffer;
		uint64_t offset = nm_get_offset(kring, slot);
		void *buffer = NMB(na, slot);
		u_int len = slot->len;

		NM_CHECK_ADDR_LEN_OFF(na, len, offset);

		nm_prdis("%s: TX %d bytes @ %p (index %d)",
			 kring->name, len, buffer, nm_i);

		/* The Netmap allocated buffers are fine
		 * for transmission via the PKO. We just
		 * have to make sure we do not let the PKO
		 * free the buffer as it would put it back
		 * in the FPA - not what we want.
		 */
		pko_command.u64 = 0;
#ifdef __LITTLE_ENDIAN
		pko_command.s.le = 1;
#endif
		pko_command.s.n2 = 1;
		pko_command.s.segs = 1;
		pko_command.s.total_bytes = len;
		pko_command.s.size0 = CVMX_FAU_OP_SIZE_32;
		pko_command.s.subone0 = 1;
		pko_command.s.dontfree = 1;
		pko_command.s.reg0 = ona->fau;

		hw_buffer.u64 = 0;
		hw_buffer.s.addr = XKPHYS_TO_PHYS((u64)buffer + offset);
		hw_buffer.s.pool = 0;
		hw_buffer.s.size = len;

		cvmx_pko_send_packet_prepare(priv->port,
					     priv->queue + qos,
					     CVMX_PKO_LOCK_NONE);
		if (unlikely
		    (cvmx_pko_send_packet_finish
		     (priv->port, priv->queue + qos, pko_command, hw_buffer,
		      CVMX_PKO_LOCK_NONE))) {
			printk_ratelimited("%s: Failed to send the packet\n",
					   kring->name);
		}

		slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
		nm_i = nm_next(nm_i, lim);
	}
	kring->nr_hwcur = head;

	/* Second part: reclaim buffers for completed transmissions */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		int32_t transmitted;

		/* The PKO decrements the counter stored in the FAU
		 * for each buffer it transmits. This allows us to
		 * shift the tail and hence free up the TX ring.
		 */
		transmitted = -(cvmx_fau_fetch_and_add32(ona->fau, 0));
		cvmx_fau_atomic_add32(ona->fau, transmitted);

		nm_prdis("%s: Free %d TX buffers", kring->name, transmitted);

		nm_i = kring->nr_hwtail + transmitted;
		if (nm_i >= kring->nkr_num_slots) {
			nm_i -= kring->nkr_num_slots;
		}
		kring->nr_hwtail = nm_i;
	}

	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 */
static int octeon_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	const int coreid = cvmx_get_core_num();
	struct netmap_adapter *na = (struct netmap_adapter *)kring->na;
	struct oct_nm_adapter *ona = (struct oct_nm_adapter *)na;
	struct ifnet *ifp = na->ifp;
	int group = ona->base + kring->ring_id;
	struct netmap_ring *ring = kring->ring;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	u_int nm_i;
	u_int n;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	/* First part: import newly received packets */
	if (netmap_no_pendintr ||
	    flags & NAF_FORCE_READ || kring->nr_kflags & NKR_PENDINTR) {
		uint32_t hwtail_lim = nm_prev(kring->nr_hwcur, lim);
		void *addr = NULL;
		int length = 0;

		nm_i = kring->nr_hwtail;
		while (nm_i != hwtail_lim) {
			u64 old_group_mask;
			struct cvmx_wqe *work;
			uint64_t offset =
			    nm_get_offset(kring, &ring->slot[nm_i]);

			old_group_mask =
			    cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreid));
			cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreid),
				       (old_group_mask & ~0xFFFFull) | 1 <<
				       group);
			work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
			cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreid),
				       old_group_mask);
			if (!work)
				break;

			if (unlikely(work->word2.snoip.rcv_error ||
				     cvmx_wqe_get_grp(work) != group)) {
				octeon_netmap_submit_kernel(work);
				continue;
			}

			/* Currently we copy into the netmap allocated buffer
			 * as Octeon buffers are shared for all interfaces
			 * and hence we cannot force a single interface to
			 * use only Netmap buffers allocated for its ring.
			 * Potentially we could teach Netmap to use the FPA
			 * buffer pool for all Netmap rings and hence avoid
			 * this copy.
			 */
			addr = NMB(na, &ring->slot[nm_i]);
			length = work->word1.len;
			memcpy(addr + offset,
			       cvmx_phys_to_ptr(work->packet_ptr.s.addr),
			       length);

			cvm_oct_free_work(work);

			nm_prdis("%s: RX %d bytes @ %p (index %d)",
				 kring->name, length, addr + offset, nm_i);

			ring->slot[nm_i].len = length;
			ring->slot[nm_i].flags = 0;

			nm_i = kring->nr_hwtail = nm_next(nm_i, lim);
		}
		if (nm_i != hwtail_lim) {
			kring->nr_kflags &= ~NKR_PENDINTR;
			octeon_netmap_irq_enable(na, kring->ring_id, 1);
		}
	}

	/* Second part: skip past packets that userspace has released */
	nm_i = kring->nr_hwcur;
	for (n = 0; nm_i != head; n++) {
		struct netmap_slot *slot = &ring->slot[nm_i];
		uint64_t offset = nm_get_offset(kring, slot);
		void *addr = NMB(na, slot);

		/* We currently do not do anything here. But if we
		 * decide to use FPA buffers for the Netmap ring,
		 * then this code would need to free the buffer
		 * back to the FPA pool.
		 */
		nm_prdis("%s: Free RX buffer @ %p (index %d)",
			 kring->name, addr + offset, nm_i);

		if (addr == NETMAP_BUF_BASE(na))	/* bad buf */
			goto ring_reset;
		slot->flags &= ~NS_BUF_CHANGED;
		nm_i = nm_next(nm_i, lim);
	}
	kring->nr_hwcur = head;

	return 0;
ring_reset:
	return netmap_ring_reinit(kring);
}

static void octeon_netmap_attach(struct octeon_ethernet *priv)
{
	struct netmap_adapter na;
	int rx_rings = bitmap_weight(((const unsigned long *)
				      &pow_receive_groups), BITS_PER_LONG);

	/* Avoid kernel configured groups
	 *  16 groups available
	 *  most likely scenario is the kernel is either;
	 *    a) using only group 15
	 *    b) using groups 0-3 on 4-core (0-1 on 2-core)
	 *  pow_receive_groups = bitmask of which groups are in use
	 */
	netmap_receive_groups = (unsigned long)pow_receive_groups;

	bzero(&na, sizeof(na));
	na.na_flags = NAF_OFFSETS;
	na.ifp = priv->netdev;
	na.num_tx_desc = 128 * rx_rings;
	na.num_rx_desc = 128;
	na.nm_register = octeon_netmap_reg;
	na.nm_txsync = octeon_netmap_txsync;
	na.nm_rxsync = octeon_netmap_rxsync;
	na.num_tx_rings = 1;
	na.num_rx_rings = rx_rings;
	netmap_attach_ext(&na, sizeof(struct oct_nm_adapter), 0);
}

static void octeon_netmap_detach(struct octeon_ethernet *priv)
{
	netmap_detach(priv->netdev);
}
