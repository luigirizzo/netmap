/*
 * netmap support for Mellanox mlx5 Ethernet driver on Linux
 *
 * Copyright (C) 2015-2018 British Broadcasting Corporation. All rights reserved.
 *
 * Author: Stuart Grace, BBC Research & Development
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *   SUCH DAMAGE.
 *
 * Some portions are:
 *
 *   Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *   SUCH DAMAGE.
 *
 * Some portions are:
 *
 *   Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
 *
 *       Redistribution and use in source and binary forms, with or
 *       without modification, are permitted provided that the following
 *       conditions are met:
 *
 *        - Redistributions of source code must retain the above
 *          copyright notice, this list of conditions and the following
 *          disclaimer.
 *
 *        - Redistributions in binary form must reproduce the above
 *          copyright notice, this list of conditions and the following
 *          disclaimer in the documentation and/or other materials
 *          provided with the distribution.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.
 */

#ifndef __MLX5_NETMAP_LINUX_H__
#define __MLX5_NETMAP_LINUX_H__

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

#ifdef NETMAP_MLX5_MAIN

#define NM_MLX5E_ADAPTER mlx5e_priv

/* This function is in en_rx.c but needed here to
 * deal with compressed CQEs
 */
u32 mlx5e_decompress_cqes_start(struct mlx5e_rq *rq,
                          struct mlx5e_cq *cq,
                          int budget_rem);


/*
 * Register/unregister. We are already under netmap lock.
 * Only called on the first register or the last unregister.
 */
int mlx5e_netmap_reg(struct netmap_adapter *na, int onoff) {
  struct ifnet *ifp = na->ifp;
  struct NM_MLX5E_ADAPTER *adapter = netdev_priv(ifp);
  int err = 0;
  int was_opened;

  nm_prinf("mlx5e switching %s native netmap mode", onoff ? "into" : "out of");

  /* Should we check and wait for any reset in progress to complete? */
  mutex_lock(&adapter->state_lock);
  was_opened = test_bit(MLX5E_STATE_OPENED, &adapter->state);

  if (was_opened) {
    mlx5e_close_locked(adapter->netdev);
  }

  /* enable or disable flags and callbacks in na and ifp */
  if (onoff) {
    nm_set_native_flags(na);
  } else {
    nm_clear_native_flags(na);
  }

  if (was_opened)
    err = mlx5e_open_locked(adapter->netdev);

  if (err)
    netdev_err(adapter->netdev,
               "mlx5e_netmap_reg: mlx5e_open_locked returned err code %d\n",
               err);

  mutex_unlock(&adapter->state_lock);

  return err;
}

#define MLX5E_SQ_NOPS_ROOM  MLX5_SEND_WQE_MAX_WQEBBS
#define MLX5E_SQ_STOP_ROOM (MLX5_SEND_WQE_MAX_WQEBBS +\
                MLX5E_SQ_NOPS_ROOM)

/*
 * Reconcile kernel and user view of the transmit ring.
 *
 * Userspace wants to send packets up to the one before ring->head,
 * kernel knows kring->nr_hwcur is the first unsent packet.
 *
 * Here we push packets out (as many as possible), and possibly
 * reclaim buffers from previously completed transmission.
 *
 * ring->tail is updated on return.
 * ring->head is never used here.
 *
 * The caller (netmap) guarantees that there is only one instance
 * running at any time. Any interference with other driver
 * methods should be handled by the individual drivers.
 */
int mlx5e_netmap_txsync(struct netmap_kring *kring, int flags) {
  struct netmap_adapter *na = kring->na;
  struct ifnet *ifp = na->ifp;
  struct netmap_ring *ring = kring->ring;
  u32 ring_nr = kring->ring_id;
  u32 nm_i; /* index into the netmap ring */
  u32 n;
  u32 const lim = kring->nkr_num_slots - 1;
  u32 const head = kring->rhead;

  /* device-specific */
  struct NM_MLX5E_ADAPTER *priv = netdev_priv(ifp);

  struct mlx5e_txqsq *sq = priv->txq2sq[ring_nr];
  struct mlx5_wq_cyc *wq = &sq->wq;
  struct mlx5e_cq *cq = &(sq->cq);
  struct mlx5e_tx_wqe *wqe = NULL;
  struct mlx5_cqe64 *cqe = NULL;
  struct mlx5_wqe_ctrl_seg *cseg;
  struct mlx5_wqe_eth_seg *eseg;
  struct mlx5_wqe_data_seg *dseg;
  u16 sqcc;
  int cqe_found = 0;

  /*
   * If we have packets to send (kring->nr_hwcur != ring->cur)
   * iterate over the netmap ring, fetch buffer address and length
   * and create a suitable WQE for each packet to send.
   *
   * Only the last WQE requests a CQE is created to report
   * completion.
   */

  if (!netif_carrier_ok(ifp)) {
    goto out;
  }

  nm_i = kring->nr_hwcur;

  if (nm_i != head) { /* we have new packets to send */

    /* nm_prinf("TX ring %u sending slots %u to %u",
     *            ring_nr, nm_i, nm_prev(head, lim));
     */

    for (n = 0; nm_i != head; n++) {
      if (unlikely(!mlx5e_wqc_has_room_for(wq, sq->cc, sq->pc, MLX5E_SQ_STOP_ROOM))) {
          break;
      }

      struct netmap_slot *slot = &ring->slot[nm_i];
      u_int len = slot->len;
      uint64_t paddr; /* physical address for DMA */
      void *addr = PNMB(na, slot, &paddr);

      /* Code below based on mlx5e_sq_xmit() in en_tx.c */

      u16 pi = sq->pc & wq->fbc.sz_m1; /* producer index */

      u8 opcode = MLX5_OPCODE_SEND;
      u16 ds_cnt;
      u16 ihs; /* inline hdr size */
      u8 num_wqebbs = 0;

      wqe = mlx5_wq_cyc_get_wqe(wq, pi);
      cseg = &wqe->ctrl; /* ctrl seg */
      eseg = &wqe->eth;  /* ethernet seg */
      ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;

      NM_CHECK_ADDR_LEN(na, addr, len); /* limit len to buf size */

      slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);

      memset(wqe, 0, sizeof(*wqe));

      /* request checksum generation in hw */
      eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;

      /* Use minimum inline header to minimise data copying */
      ihs = ETH_HLEN;

      if (unlikely(ihs > len))
        ihs = len; /* whole packet fits inline */

      memcpy(eseg->inline_hdr.start, addr, ihs);
      eseg->inline_hdr.sz = cpu_to_be16(ihs);

      ds_cnt +=
          DIV_ROUND_UP(ihs - sizeof(eseg->inline_hdr.start), MLX5_SEND_WQE_DS);

      dseg = (struct mlx5_wqe_data_seg *)cseg + ds_cnt;

      /* Put all rest of packet into a single data segment */
      /* excluding bytes in the inline header */
      if (likely(len > ihs)) {

        dseg->addr = cpu_to_be64(paddr + ihs); /* phys addr */
        dseg->lkey = sq->mkey_be;
        dseg->byte_count = cpu_to_be32(len - ihs);
        ds_cnt++;
      }

      cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | opcode);
      cseg->qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_cnt);

      num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS);
      sq->pc += num_wqebbs;

      /* Instead of storing pointer to a skb in sq->skb[pi], we use
       * it to store info we will need at completion:
       *   - number of wqebbs in this wqe (shifted up by 24 bits)
       *   - slot number in the netmap kring that this wqe is sending
       *           (in bottom 24 bits)
       */
      sq->db.wqe_info[pi].skb = (void *)(uintptr_t)(nm_i & 0x00FFFFFF);
      sq->db.wqe_info[pi].num_wqebbs = num_wqebbs;

      mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, cseg);

      sq->stats->packets++;

      /* next netmap slot */
      nm_i = nm_next(nm_i, lim);
    } /* next packet */

    kring->nr_hwcur = nm_i;
  }

  /*
   * Second part: reclaim buffers from completed transmissions.
   * We find these by looking for CQEs in the CQ.
   *
   * Code below based on mlx5e_poll_tx_cq() in en_tx.c
   */

  /* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
   * otherwise a cq overrun may occur */
  sqcc = sq->cc;

  cqe = mlx5_cqwq_get_cqe(&cq->wq);

  while (cqe) {
    u16 wqe_counter;
    bool last_wqe;

    cqe_found = 1;
    mlx5_cqwq_pop(&cq->wq);

    /* this cqe could relate to many wqes */
    wqe_counter = be16_to_cpu(cqe->wqe_counter);

    do {
      u16 ci = sqcc & sq->wq.fbc.sz_m1;
      void *skb = sq->db.wqe_info[ci].skb;
      u8 num_wqebbs = sq->db.wqe_info[ci].num_wqebbs;
      u32 nm_i_done;

      last_wqe = (sqcc == wqe_counter);

      if (unlikely(!skb)) { /* nop */
        sq->stats->nop++;
        sqcc++;
        continue;
      }

      /* unpack slot number from skb pointer */
      nm_i_done = (u32)((uintptr_t)skb & 0x00FFFFFF);

      sqcc += num_wqebbs;
      kring->nr_hwtail = nm_prev(nm_i_done, lim);

    } while (!last_wqe);

    cqe = mlx5_cqwq_get_cqe(&cq->wq);
  }

  if (cqe_found) {

    mlx5_cqwq_update_db_record(&cq->wq);

    /* ensure cq space is freed before enabling more cqes */
    wmb();
    sq->cc = sqcc;
  }

  mlx5e_cq_arm(cq); /* allow interrupts from this CQ */

out:
  return 0;
}

/*
 * Reconcile kernel and user view of the receive ring.
 * Same as for the txsync, this routine must be efficient.
 * The caller guarantees a single invocations, but races against
 * the rest of the driver should be handled here.
 *
 * When called, userspace has released buffers up to ring->head
 * (last one excluded).
 *
 * If (flags & NAF_FORCE_READ) also check for incoming packets irrespective
 * of whether or not we received an interrupt.
 */
int mlx5e_netmap_rxsync(struct netmap_kring *kring, int flags) {
  struct netmap_adapter *na = kring->na;
  struct ifnet *ifp = na->ifp;
  struct netmap_ring *ring = kring->ring;
  u_int ring_nr = kring->ring_id;
  u_int nm_i = 0; /* index into the netmap ring */
  u_int const lim = kring->nkr_num_slots - 1;
  u_int const head = kring->rhead;
  u_int const stop_i = nm_prev(head, lim); /* stop reclaiming here */
  uint16_t slot_flags = 0;

  /* device-specific */
  struct NM_MLX5E_ADAPTER *priv = netdev_priv(ifp);
  struct mlx5e_rq *rq = &(priv->channels.c[ring_nr]->rq);
  struct mlx5e_cq *cq = &(rq->cq);
  struct mlx5_cqe64 *cqe = NULL;
  int cqe_found = 0;
/*
  if (unlikely(rq->rq_type == RQ_TYPE_STRIDE)) {
    netdev_err(ifp,
               "RQ type is STRIDING - this is not supported in netmap mode\n");
    return 0;
  }
*/
  if (!netif_carrier_ok(ifp))
    return 0;

  if (unlikely(head > lim)) {
    return netmap_ring_reinit(kring);
  }

  rmb();

  /*
   * first part: reclaim buffers that userspace has released:
   *  (from kring->nr_hwcur to second last [*] slot before ring->head)
   * and make the buffers available for reception.
   * As usual nm_i is the index in the netmap ring.
   * [*] IMPORTANT: we must leave one free slot in the ring
   * to avoid ring empty/full confusion in userspace.
   */
  nm_i = kring->nr_hwcur;

  if (nm_i != stop_i) {
    struct mlx5_wq_cyc *wq = &rq->wqe.wq;
    struct mlx5e_rx_wqe_cyc *wqe = mlx5_wq_cyc_get_wqe(wq, mlx5_wq_cyc_get_head(wq));
    struct netmap_slot *slot;
    uint64_t paddr;
    void *addr;

    while (nm_i != stop_i && !mlx5_wq_cyc_is_full(wq)) {

      slot = &ring->slot[nm_i];
      addr = PNMB(na, slot, &paddr); /* find phys address */

      if (unlikely(addr == NETMAP_BUF_BASE(na))) { /* bad buf */
        netdev_warn(ifp, "Resetting RX ring %u in mlx5e_netmap_rxsync\n",
                    ring_nr);
        goto ring_reset;
      }

      if (slot->flags & NS_BUF_CHANGED) {
        slot->flags &= ~NS_BUF_CHANGED;
      }

      wqe = mlx5_wq_cyc_get_wqe(wq, mlx5_wq_cyc_get_head(wq));
      wqe->data->addr = cpu_to_be64(paddr);

      mlx5_wq_cyc_push(wq);

      nm_i = nm_next(nm_i, lim);
    }

    kring->nr_hwcur = nm_i;

    /* ensure wqes are visible to device before updating doorbell record */
    wmb();
    mlx5_wq_cyc_update_db_record(wq);
  }

  /*
   * Second part: import newly received packets.
   * We are told about received packets by CQEs in the CQ.
   *
   * nm_i is the index of the next free slot in the netmap ring:
   */
  nm_i = kring->nr_hwtail;

  cqe = mlx5_cqwq_get_cqe(&cq->wq);

  while (cqe) {
    struct mlx5e_rx_wqe_cyc *wqe;
    u16 bytes_recv = 0;
    __be16 wqe_id_be;
    u16 wqe_counter;

    cqe_found = 1;
    if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED)
        mlx5e_decompress_cqes_start(rq, &rq->cq, 1024);

    mlx5_cqwq_pop(&cq->wq);

    wqe_id_be = cqe->wqe_counter;
    wqe_counter = be16_to_cpu(wqe_id_be);
    wqe = mlx5_wq_cyc_get_wqe( &rq->wqe.wq, wqe_counter);
    bytes_recv = be32_to_cpu(cqe->byte_cnt);

    if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
      rq->stats->wqe_err++;
      netdev_warn(ifp, "Bad response found in CQE for RQ %u\n", ring_nr);
      goto wq_cyc_pop;
    }

    rq->stats->packets++;
    if (cqe->hds_ip_ext & CQE_L4_OK)
      rq->stats->csum_unnecessary++;

    /* could analyse checksums more thoroughly using flags in
     * l4_hdr_type_etc that us which checksums are applicable
     */
    /* Following is useful during debugging:
     *   printk(KERN_ERR "** Received %u bytes for ring %u slot %u with
     *                    L2CSUM %s, L3CSUM %s, L4CSUM %s\n",
     *   be32_to_cpu(cqe->byte_cnt), ring_nr, nm_i,
     *   (cqe->hds_ip_ext & CQE_L2_OK)? "good" : "*BAD*",
     *   (cqe->hds_ip_ext & CQE_L3_OK)? "good" : "bad or not IP",
     *   (cqe->hds_ip_ext & CQE_L4_OK)? "good" : "bad or not TCP/UDP");
     */

    ring->slot[nm_i].len = bytes_recv;
    ring->slot[nm_i].flags = slot_flags;
    nm_i = nm_next(nm_i, lim);

  wq_cyc_pop:
    cqe = mlx5_cqwq_get_cqe(&cq->wq);
    mlx5_wq_cyc_pop(&rq->wqe.wq);
  }

  if (cqe_found) {
    kring->nr_hwtail = nm_i;
    mlx5_cqwq_update_db_record(&cq->wq);

    /* ensure cq space is freed before enabling more cqes */
    wmb();

    /* update the kring state */
    kring->nr_kflags &= ~NKR_PENDINTR;
  }

  mlx5e_cq_arm(cq); /* allow interrupts from this CQ */

  return 0;

ring_reset:
  return netmap_ring_reinit(kring);
}

/*
 * Acknowledge and clear all CQEs when TX queue is closing down
 */
int mlx5e_netmap_tx_flush(struct mlx5e_txqsq *sq) {
  struct mlx5e_cq *cq = &(sq->cq);
  struct mlx5_cqe64 *cqe;
  u16 sqcc;

  rmb();

  /* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
   * otherwise a cq overrun may occur */
  sqcc = sq->cc;

  /* Any completed jobs in the CQ? */
  cqe = mlx5_cqwq_get_cqe(&cq->wq);

  while (cqe) {
    u16 wqe_counter;
    bool last_wqe;

    mlx5_cqwq_pop(&cq->wq);

    /* this cqe could relate to many wqes */
    wqe_counter = be16_to_cpu(cqe->wqe_counter);

    do {
      u16 ci = sqcc & sq->wq.fbc.sz_m1;
      void *skb = sq->db.wqe_info[ci].skb;
      u8 num_wqebbs = sq->db.wqe_info[ci].num_wqebbs;

      last_wqe = (sqcc == wqe_counter);

      if (unlikely(!skb)) { /* nop */
        sq->stats->nop++;
        sqcc++;
        continue;
      }

      sqcc += num_wqebbs;

    } while (!last_wqe);

    cqe = mlx5_cqwq_get_cqe(&cq->wq);
  }

  mlx5_cqwq_update_db_record(&cq->wq);

  /* ensure cq space is freed before enabling more cqes */
  wmb();
  sq->cc = sqcc;

  return 0;
}

/*
 * Acknowledge and clear all CQEs when RX queue is closing down
 */
int mlx5e_netmap_rx_flush(struct mlx5e_rq *rq) {
  struct mlx5e_cq *cq = &(rq->cq);
  struct mlx5_cqe64 *cqe;

  rmb();

  cqe = mlx5_cqwq_get_cqe(&cq->wq);

  while (cqe) {
    struct mlx5e_rx_wqe_cyc *wqe;
    __be16 wqe_id_be;
    u16 wqe_counter;

    if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED)
        mlx5e_decompress_cqes_start(rq, &rq->cq, 1024);

    mlx5_cqwq_pop(&cq->wq);

    wqe_id_be = cqe->wqe_counter;
    wqe_counter = be16_to_cpu(wqe_id_be);
    wqe = mlx5_wq_cyc_get_wqe(&rq->wqe.wq, wqe_counter);

    cqe = mlx5_cqwq_get_cqe(&cq->wq);
    mlx5_wq_cyc_pop(&rq->wqe.wq);
  }

  mlx5_cqwq_update_db_record(&cq->wq);

  /* ensure cq space is freed before enabling more cqes */
  wmb();

  mlx5e_cq_arm(cq); /* allow interrupts from this CQ */

  return 0;
}

/*
 * if in netmap mode, attach the netmap buffers to the ring and return true.
 * Otherwise return false.
 */
int mlx5e_netmap_configure_tx_ring(struct NM_MLX5E_ADAPTER *adapter,
                                   int ring_nr) {
  struct netmap_adapter *na = NA(adapter->netdev);
  struct netmap_slot *slot;

  slot = netmap_reset(na, NR_TX, ring_nr, 0);
  if (!slot)
    return 0; /* not in native netmap mode */

  /*
   * On some cards we would set up the slot addresses now.
   * But on mlx5e, the address will be written to the WQ when
   * each packet arrives in mlx5e_netmap_txsync
   */

  return 1;
}

int mlx5e_netmap_configure_rx_ring(struct mlx5e_rq *rq, int ring_nr) {
  /*
   * In netmap mode, we must preserve the buffers made
   * available to userspace before the if_init()
   * (this is true by default on the TX side, because
   * init makes all buffers available to userspace).
   */
  struct netmap_adapter *na = NA(rq->netdev);
  struct netmap_slot *slot;
  int lim; /* number of WQEs to prepare */
  int count = 0;

  struct mlx5_wq_cyc *wq = &rq->wqe.wq;

  slot = netmap_reset(na, NR_RX, ring_nr, 0);
  if (!slot)
    return 0; /* not in native netmap mode */

  lim = na->num_rx_desc - 1 - nm_kr_rxspace(na->rx_rings[ring_nr]);

  while (!mlx5_wq_cyc_is_full(wq) && (count < lim)) {

    struct mlx5e_rx_wqe_cyc *wqe = mlx5_wq_cyc_get_wqe(wq, mlx5_wq_cyc_get_head(wq));

    uint64_t paddr;
    PNMB(na, slot + count, &paddr);

    wqe->data->addr = cpu_to_be64(paddr);

    mlx5_wq_cyc_push(wq);
    count++;
  }

  nm_prinf("populated %d WQEs in ring %d", count, ring_nr);

  /* tell netmap how many buffers we have prepared */
  na->rx_rings[ring_nr]->nr_hwcur = count;

  /* ensure wqes are visible to device before updating doorbell record */
  wmb();
  mlx5_wq_cyc_update_db_record(wq);

  return 1;
}

int mlx5e_netmap_config(struct netmap_adapter *na, struct nm_config_info *info) {
  int ret = netmap_rings_config_get(na, info);

  if (ret) {
    return ret;
  }

  info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

  return 0;
}

/*
 * The attach routine, called at the end of mlx5e_create_netdev(),
 * fills the parameters for netmap_attach() and calls it.
 * It cannot fail, in the worst case (such as no memory)
 * netmap mode will be disabled and the driver will only
 * operate in standard mode.
 */
void mlx5e_netmap_attach(struct NM_MLX5E_ADAPTER *adapter) {
  struct netmap_adapter na;
  bzero(&na, sizeof(na));

  na.ifp = adapter->netdev;
  na.pdev = &adapter->mdev->pdev->dev;
  na.num_tx_desc = (1 << adapter->channels.params.log_sq_size);
  na.num_rx_desc = (1 << adapter->channels.params.log_rq_mtu_frames);
  na.nm_txsync = mlx5e_netmap_txsync;
  na.nm_rxsync = mlx5e_netmap_rxsync;
  na.nm_register = mlx5e_netmap_reg;
  na.nm_config = mlx5e_netmap_config;

  /* each channel has 1 rx ring and a tx for each tc */
  na.num_tx_rings = adapter->channels.params.num_channels * adapter->channels.params.num_tc;
  na.num_rx_rings = adapter->channels.params.num_channels;
  na.rx_buf_maxsize = 1500; /* will be overwritten by nm_config */
  netmap_attach(&na);
}

#endif /* NETMAP_MLX5_MAIN */

#endif /* __MLX5_NETMAP_LINUX_H__ */

/* end of file */
