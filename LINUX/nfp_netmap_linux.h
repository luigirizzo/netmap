/*
 * Copyright (C) 2023, Giuseppe Lettieri. All rights reserved.
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
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

#ifdef NETMAP_NFP_NET
/* prevent name clash */
#undef cdev
#endif /* NETMAP_NFP_NET */

#ifdef NETMAP_NFP_NFD3_DP

static int
nfp_netmap_configure_rx_ring(struct nfp_net_dp *dp, struct nfp_net_rx_ring *rx_ring)
{
	struct netmap_adapter *na;
	struct netmap_slot *slot;
	struct netmap_kring *kring;
	int lim, i, ring_nr;

	if (!dp->netdev || !NM_NA_VALID(dp->netdev))
		return 0;

	na = NA(dp->netdev);
	ring_nr = rx_ring->idx;

	slot = netmap_reset(na, NR_RX, ring_nr, 0);
	if (!slot)
		return 0;	// not in netmap mode

	kring = na->rx_rings[ring_nr];
	lim = na->num_rx_desc - 1 - nm_kr_rxspace(kring);

	nm_prinf("rx ring %d filling %d slots rx_offset %x", ring_nr, lim, dp->rx_offset);
	for (i = 0; i < lim; i++) {
		int si = netmap_idx_n2k(kring, i);
		uint64_t paddr;
		PNMB_O(kring, slot + si, &paddr);

		if (i % 32 == 0)
			nm_prdis("%s: si %d addr %llx", kring->name, si, (unsigned long long)paddr);
		rx_ring->rxds[i].fld.reserved = 0;
		rx_ring->rxds[i].fld.meta_len_dd = 0;
		nfp_desc_set_dma_addr_48b(&rx_ring->rxds[i].fld, paddr);
	}
	wmb();
	nfp_qcp_wr_ptr_add(rx_ring->qcp_fl, lim);

	return 1;
}

#endif

#ifdef NETMAP_NFP_DP

static int
nfp_netmap_configure_tx_ring(struct nfp_net *nn, struct nfp_net_tx_ring *tx_ring)
{
	(void)nn;
	nm_prdis("idx %d", tx_ring->idx);
	return 0;
}

#endif /* NETMAP_NFP_DP */

#ifdef NETMAP_NFP_MAIN

static int
nfp_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct nfp_net *nn = netdev_priv(ifp);
	struct nfp_net_dp *dp;

	dp = nfp_net_clone_dp(nn);
	if (!dp)
		return 1;

	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	return nfp_net_ring_reconfig(nn, dp, NULL);
}

static int
nfp_netmap_txsync(struct netmap_kring *kring, int flags)
{
	(void)kring;
	(void)flags;
	return 0;
}

static int
nfp_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device specific */
	struct nfp_net *nn = netdev_priv(ifp);
	struct nfp_net_rx_ring *rxr;

	if (!netif_running(ifp))
		return 0;

	rxr = nn->r_vecs[kring->ring_id].rx_ring;
	if (unlikely(!rxr || !rxr->rxds)) {
		nm_prlim(1, "ring %s is missing (rxr=%p)", kring->name, rxr);
		return ENXIO;
	}

	if (head > lim)
		return netmap_ring_reinit(kring);

	if (netmap_no_pendintr || force_update) {
		unsigned int meta_len, data_len, pkt_len;

		nm_i = kring->nr_hwtail;
		nic_i = netmap_idx_k2n(kring, nm_i);

		for (n = 0; ; n++) {
			struct nfp_net_rx_desc *curr = &rxr->rxds[nic_i];
			struct netmap_slot *slot;
			uint64_t paddr;

			if (!(curr->rxd.meta_len_dd & PCIE_DESC_RX_DD))
				break;
			dma_rmb();
			meta_len = curr->rxd.meta_len_dd & PCIE_DESC_RX_META_LEN_MASK;
			data_len = le16_to_cpu(curr->rxd.data_len);
			pkt_len = data_len - meta_len;
			slot = ring->slot + nm_i;
			slot->len = pkt_len;
			PNMB(na, slot, &paddr);
			nm_write_offset(kring, slot, meta_len);
			nm_prdis("%s: rd_p %u nic_i %d addr %llx", kring->name, rxr->rd_p, nic_i, (unsigned long long)paddr);
			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, data_len, NR_RX);

			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nm_i, rxr->cnt - 1);
		}
		if (n) {
			kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
			uint64_t offset = nm_get_offset(kring, slot);

			struct nfp_net_rx_desc *curr = &rxr->rxds[nic_i];

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				//netmap_reload_map(na, rxr->ptag, rxbuf->pmap, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->fld.reserved = 0;
			curr->fld.meta_len_dd = 0;
			nfp_desc_set_dma_addr_48b(&curr->fld, paddr + offset);
			nm_prdis("%s: nic_i %d addr %llx", kring->name, nic_i, (unsigned long long)paddr + offset);
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
					&paddr, NETMAP_BUF_SIZE(na), NR_RX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, rxr->cnt - 1);
		}
		kring->nr_hwcur = head;

		wmb();
		nfp_qcp_wr_ptr_add(rxr->qcp_fl, n);
	}
	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}

static int
nfp_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

	return 0;
}

static int
nfp_netmap_krings_create(struct netmap_adapter *na)
{
	int error, i;

	error = netmap_hw_krings_create(na);
	if (error)
		return error;

	for (i = 0; i < nma_get_nrings(na, NR_RX); i++) {
		struct netmap_kring *kring = NMR(na, NR_RX)[i];

		kring->nr_kflags |= NKR_NEEDRING;
	}

	error = netmap_mem_rings_create(na);
	if (error) {
		goto err_del_krings;
	}

	/* set the offset on all the RX rings */
	for (i = 0; i < nma_get_nrings(na, NR_RX); i++) {
		struct netmap_kring *kring = NMR(na, NR_RX)[i];

		kring->offset_mask = 0xFFFFFFFFFFFFFFFF;
		kring->offset_max = NFP_NET_MAX_PREPEND;
		*(uint64_t *)(uintptr_t)&kring->ring->offset_mask = kring->offset_mask;
	}


	return 0;

err_del_krings:
	netmap_hw_krings_delete(na);
	return error;
}

static void
nfp_netmap_krings_delete(struct netmap_adapter *na)
{
	int i;

	for (i = 0; i < nma_get_nrings(na, NR_RX); i++) {
		struct netmap_kring *kring = NMR(na, NR_RX)[i];

		kring->nr_kflags &= ~NKR_NEEDRING;
	}

	netmap_mem_rings_delete(na);
	netmap_hw_krings_delete(na);
}

static int
nfp_netmap_bufcfg(struct netmap_kring *kring, uint64_t target)
{
	(void)kring;
	(void)target;
	nm_prinf("called target %llx", target);
	return 0;
}

static void
nfp_netmap_attach(struct nfp_net *nn)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = nn->dp.netdev;
	na.pdev = &nn->pdev->dev;
	na.na_flags = NAF_OFFSETS;
	na.num_tx_desc = nn->dp.txd_cnt;
	na.num_rx_desc = nn->dp.rxd_cnt;
	na.num_tx_rings = nn->dp.num_tx_rings;
	na.num_rx_rings = nn->dp.num_rx_rings;
	na.rx_buf_maxsize = 4096;
	na.nm_txsync = nfp_netmap_txsync;
	na.nm_rxsync = nfp_netmap_rxsync;
	na.nm_krings_create = nfp_netmap_krings_create;
	na.nm_krings_delete = nfp_netmap_krings_delete;
	na.nm_register = nfp_netmap_reg;
	na.nm_config = nfp_netmap_config;
	na.nm_bufcfg = nfp_netmap_bufcfg;
	netmap_attach(&na);
}
#endif /* NETMAP_NFP_MAIN */
