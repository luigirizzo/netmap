/*
 * Copyright (C) 2012-2014 Gaetano Catalli, Luigi Rizzo. All rights reserved.
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

/*
 * $Id: if_e1000e_netmap.h 10670 2012-02-27 21:15:38Z luigi $
 *
 * netmap support for: e1000e (linux version)
 * For details on netmap support please see ixgbe_netmap.h
 * The driver supports 1 TX and 1 RX ring. Single lock.
 * tx buffer address only written on change.
 * Apparently the driver uses extended descriptors on rx from 3.2.32
 * Rx Crc stripping ?
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

#define SOFTC_T	e1000_adapter

#define e1000e_driver_name netmap_e1000e_driver_name
char netmap_e1000e_driver_name[] = "e1000e" NETMAP_LINUX_DRIVER_SUFFIX;

/*
 * Adaptation to different versions of the driver.
 */
#ifdef NETMAP_LINUX_HAVE_E1000E_EXT_RXDESC
//#warning this driver uses extended descriptors
#define NM_E1K_RX_DESC_T	union e1000_rx_desc_extended
#define	NM_E1R_RX_STATUS	wb.upper.status_error
#define	NM_E1R_RX_LENGTH	wb.upper.length
#define	NM_E1R_RX_BUFADDR	read.buffer_addr
#else
//#warning this driver uses regular descriptors
#define E1000_RX_DESC_EXT	E1000_RX_DESC	// XXX workaround
#define NM_E1K_RX_DESC_T	struct e1000_rx_desc
#define	NM_E1R_RX_STATUS	status
#define	NM_E1R_RX_BUFADDR	buffer_addr
#define	NM_E1R_RX_LENGTH	length
#endif /* up to 3.2.x */

/* Macros to write to the head and tail registers of TX and RX rings. */
#ifndef NETMAP_LINUX_HAVE_E1000E_HWADDR
#define NM_WR_TX_TAIL(_x)	writel(_x, txr->tail)
#define	NM_WR_RX_TAIL(_x)	writel(_x, rxr->tail)
#define	NM_RD_TX_HEAD()		readl(txr->head)
#else
#define NM_WR_TX_TAIL(_x)	writel(_x, adapter->hw.hw_addr + txr->tail)
#define	NM_WR_RX_TAIL(_x)	writel(_x, adapter->hw.hw_addr + rxr->tail)
#define	NM_RD_TX_HEAD()		readl(adapter->hw.hw_addr + txr->head)
#endif

#ifdef NETMAP_LINUX_HAVE_E1000E_DOWN2
#define nm_e1000e_down(_a)	e1000e_down(_a, true)
#else
#define nm_e1000e_down(_a)	e1000e_down(_a)
#endif


/*
 * Register/unregister. We are already under netmap lock.
 */
static int
e1000_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);

	/* protect against other reinit */
	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (netif_running(adapter->netdev))
		nm_e1000e_down(adapter);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	if (netif_running(adapter->netdev))
		e1000e_up(adapter);
	else
		e1000e_reset(adapter);	// XXX is it needed ?

	clear_bit(__E1000_RESETTING, &adapter->state);
	return (0);
}

struct e1000e_netmap_szdesc {
	uint32_t bufsize;
	uint32_t rctl;
};

#define E1000_NETMAP_RCTL_MASK	0x7A030000
static struct e1000e_netmap_szdesc e1000e_netmap_bufsize[] = {
	{ 16384,	0x02010000},
	{ 8192,		0x02020000},
	{ 4096,		0x02030000},
	{ 2048,		0x00000000},
	{ 1024,		0x00010000},
	{ 512,		0x00020000},
	{ 256,		0x00030000},
	{ 0,		0},
};

static uint32_t
e1000e_netmap_get_rctl(uint32_t bufsize)
{
	struct e1000e_netmap_szdesc *sz;

	for (sz = e1000e_netmap_bufsize; sz->bufsize; sz++)
		if (bufsize == sz->bufsize)
			return sz->rctl;

	return ((bufsize >> 10) & 0xF) << 27;
}

static int
e1000e_netmap_bufcfg(struct netmap_kring *kring, uint64_t target)
{
	uint64_t bufsz;
	struct e1000e_netmap_szdesc *sz;

	if (kring->tx == NR_TX) {
		kring->hwbuf_len = target;
		return 0;
	}

	bufsz = 0;
	for (sz = e1000e_netmap_bufsize; sz->bufsize; sz++)
		if (sz->bufsize <= target) {
			bufsz = sz->bufsize;
			break;
		}
	if (!bufsz)
		return EINVAL;
	/* check if we can find a better size using 1K increments */
	target >>= 10;
	if (target >= 1 && target <= 15) {
		target <<= 10;
		if (target > bufsz)
			bufsz = target;
	}
	kring->hwbuf_len = bufsz;
	kring->buf_align = 0; /* no alignment */
	nm_prinf("%s: hwbuf_len %llu", kring->name, kring->hwbuf_len);
	return 0;
}

/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
e1000_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_ring* txr = &adapter->tx_ring[ring_nr];

	rmb();
	/*
	 * First part: process new packets to send.
	 */

	if (!netif_carrier_ok(ifp)) {
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			uint64_t offset = nm_get_offset(kring, slot);

			/* device-specific */
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, nic_i);
			int hw_flags = E1000_TXD_CMD_IFCS;

			PNMB(na, slot, &paddr);
			NM_CHECK_ADDR_LEN_OFF(na, len, offset);

			if (!(slot->flags & NS_MOREFRAG)) {
				hw_flags |= adapter->txd_cmd;
				/* For now E1000_TXD_CMD_RS is always set.
				 * We may set it only if NS_REPORT is set or
				 * at least once every half ring. */
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED | NS_MOREFRAG);
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev, &paddr, len, NR_TX);

			/* Fill the slot in the NIC ring. */
			curr->buffer_addr = htole64(paddr + offset);
			curr->upper.data = 0;
			curr->lower.data = htole32(len | hw_flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;

		wmb();	/* synchronize writes to the NIC ring */

		txr->next_to_use = nic_i; /* for consistency */
		NM_WR_TX_TAIL(nic_i);
		wmb(); /* needed after writing to TX ring tail */
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || nm_kr_txempty(kring)) {
		u_int tosync;

		/* Record completed transmissions using TDH.
		 * Alternative approach would be to scan descriptors and read
		 * the DD bit until we found one that is not set. */
		nic_i = NM_RD_TX_HEAD();
		if (unlikely(nic_i >= kring->nkr_num_slots)) {
			/* This should never happen. */
			nm_prerr("TDH wrap at idx %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		nm_i = netmap_idx_n2k(kring, nic_i);
		txr->next_to_clean = nic_i;
		tosync = nm_next(kring->nr_hwtail, lim);
		/* sync all buffers that we are returning to userspace */
		for ( ; tosync != nm_i; tosync = nm_next(tosync, lim)) {
			struct netmap_slot *slot = &ring->slot[tosync];
			uint64_t paddr;
			(void)PNMB_O(kring, slot, &paddr);

			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev,
					&paddr, slot->len, NR_TX);
		}
		kring->nr_hwtail = nm_prev(nm_i, lim);
	}
out:

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
e1000_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* device-specific */
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_ring *rxr = &adapter->rx_ring[ring_nr];

	if (!netif_carrier_ok(ifp))
		return 0;

	if (head > lim)
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: import newly received packets.
	 */
	if (netmap_no_pendintr || force_update) {
		int strip_crc = (adapter->flags2 & FLAG2_CRC_STRIPPING) ? 0 : 4;

		nic_i = rxr->next_to_clean;
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = 0; ; n++) {
			NM_E1K_RX_DESC_T *curr = E1000_RX_DESC_EXT(*rxr, nic_i);
			uint32_t staterr = le32toh(curr->NM_E1R_RX_STATUS);
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			dma_rmb();  /* read descriptor after status DD */
			PNMB_O(kring, slot, &paddr);
			slot->len = le16toh(curr->NM_E1R_RX_LENGTH) - strip_crc;
			slot->flags = (!(staterr & E1000_RXD_STAT_EOP) ? NS_MOREFRAG : 0);
			netmap_sync_map_cpu(na, (bus_dma_tag_t) na->pdev, &paddr,
					slot->len, NR_RX);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = nic_i;
			kring->nr_hwtail = nm_i;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
			NM_E1K_RX_DESC_T *curr = E1000_RX_DESC_EXT(*rxr, nic_i);

			if (addr == NETMAP_BUF_BASE(na)) /* bad buf */
				goto ring_reset;
			netmap_sync_map_dev(na, (bus_dma_tag_t) na->pdev,
					&paddr, NETMAP_BUF_SIZE(na), NR_RX);
			curr->NM_E1R_RX_BUFADDR = htole64(paddr); /* reload ext.desc. addr. */
			if (slot->flags & NS_BUF_CHANGED) {
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->NM_E1R_RX_STATUS = 0;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = head;
		rxr->next_to_use = nic_i; /* for consistency */
		wmb();
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move nic_i back by one unit
		 */
		nic_i = nm_prev(nic_i, lim);
		NM_WR_RX_TAIL(nic_i);
	}


	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/* diagnostic routine to catch errors */
static void e1000e_no_rx_alloc(struct SOFTC_T *a, int n)
{
	nm_prerr("alloc_rx_buf() should not be called");
}


/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int e1000e_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_kring *kring;
	struct netmap_slot* slot;
	struct e1000_ring *rxr = adapter->rx_ring;
	int i, si, n;
	uint64_t paddr;
	uint32_t rctl;

	if (!nm_native_on(na))
		return 0;

	slot = netmap_reset(na, NR_RX, 0, 0);
	if (slot) {
		kring = na->rx_rings[0];
		/* initialize the RX ring for netmap mode */
		adapter->alloc_rx_buf = (void*)e1000e_no_rx_alloc;
		/* preserve buffers already made available to clients */
		n = rxr->count - 1 - nm_kr_rxspace(kring);
		for (i = 0; i < n; i++) {
			struct e1000_buffer *bi = &rxr->buffer_info[i];
			si = netmap_idx_n2k(kring, i);
			PNMB_O(kring, slot + si, &paddr);
			if (bi->skb)
				nm_prerr("Warning: rx skb still set on slot #%d", i);
			E1000_RX_DESC_EXT(*rxr, i)->NM_E1R_RX_BUFADDR = htole64(paddr);
		}
		rxr->next_to_use = 0;

		/* program the RCTL */
		rctl = er32(RCTL);
		rctl = (rctl & ~E1000_NETMAP_RCTL_MASK) |
			e1000e_netmap_get_rctl(kring->hwbuf_len);
		ew32(RCTL, rctl);

		wmb();	/* Force memory writes to complete */
		NM_WR_RX_TAIL(n);
	}

	netmap_reset(na, NR_TX, 0, 0);

	/* no need to fill the tx ring, since txsync will always
	 * overwrite the tx slots
	 */

	return 1;
}

static int
e1000e_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	struct SOFTC_T *adapter = netdev_priv(na->ifp);
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = adapter->rx_buffer_len;

	return 0;
}


static void
e1000_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.pdev = &adapter->pdev->dev;
	na.na_flags = NAF_MOREFRAG | NAF_OFFSETS;
	na.num_tx_desc = adapter->tx_ring->count;
	na.num_rx_desc = adapter->rx_ring->count;
	na.num_tx_rings = na.num_rx_rings = 1;
	na.rx_buf_maxsize = adapter->rx_buffer_len;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	na.nm_config = e1000e_netmap_config;
	na.nm_bufcfg = e1000e_netmap_bufcfg;
	netmap_attach(&na);
}

/* end of file */
