/*
 * Copyright (C) 2014-2016 Vincenzo Maffione. All rights reserved.
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
#include <dev/netmap/netmap_mem2.h>

#ifndef WITH_PIPES
#error "netmap pipes are required by veth native adapter"
#endif /* WITH_PIPES */

static int veth_open(struct ifnet *ifp);
static int veth_close(struct ifnet *ifp);

struct netmap_veth_adapter {
	struct netmap_hw_adapter up;
	struct netmap_veth_adapter *peer;
	int peer_ref;
};

/* To be called under RCU read lock. This also sets peer_ref in the
 * same way netmap_get_pipe_na() does. */
static struct netmap_adapter *
veth_get_peer_na(struct netmap_adapter *na)
{
	struct ifnet *ifp = na->ifp;
	struct veth_priv *priv = netdev_priv(ifp);
	struct ifnet *peer_ifp;
	struct netmap_veth_adapter *vna =
		(struct netmap_veth_adapter *)na;

	if (vna->peer == NULL) {
		/* Only one of the two endpoint enters here,
		 * and only once. */
		peer_ifp = rcu_dereference(priv->peer);
		if (!peer_ifp) {
			return NULL;
		}
		/* Cross link the peer netmap adapters. Note that we
		 * can retrieve the peer to do our clean-up even if
		 * the peer_ifp is detached from us. */
		vna->peer = (struct netmap_veth_adapter *)NA(peer_ifp);
		vna->peer->peer = vna;

		/* Get a reference to the other endpoint. */
		netmap_adapter_get(&vna->peer->up.up);
		vna->peer_ref = 1;
	}

	return &vna->peer->up.up;
}

static void
veth_netmap_dtor(struct netmap_adapter *na)
{
	struct netmap_veth_adapter *vna =
		(struct netmap_veth_adapter *)na;
	if (vna->peer_ref) {
		vna->peer_ref = 0;
		netmap_adapter_put(&vna->peer->up.up);
	}
}

/*
 * Register/unregister. We are already under RCU lock.
 * This register function is similar to the one used by
 * pipes; in addition to the regular tasks (commit the rings
 * in/out netmap node and call nm_(set|clear)_native_flags),
 * we also mark the peer rings as needed by us and possibly
 * create/destroy some netmap rings.
 */
static int
veth_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_veth_adapter *vna =
		(struct netmap_veth_adapter *)na;
	struct netmap_adapter *peer_na;
	struct ifnet *ifp = na->ifp;
	bool was_up;
	enum txrx t;
	int error;
	int i;

	peer_na = veth_get_peer_na(na);
	if (!peer_na) {
		return EINVAL;
	}

	was_up = netif_running(ifp);
	if (na->active_fds == 0 && was_up) {
		/* The interface is up. Close it while (un)registering. */
		veth_close(ifp);
	}

	/* Enable or disable flags and callbacks in na and ifp. */
	if (onoff) {
		for_rx_tx(t) {
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_on(kring)) {
					/* mark the peer ring as needed */
					kring->pipe->nr_kflags |= NKR_NEEDRING;
				}
			}
		}

		/* create all missing needed rings on the other end.
		 * They have all been marked as fake in the krings_create
		 * above, so the will not be filled with buffers
		 */

		error = netmap_mem_rings_create(peer_na);
		if (error) {
			return error;
		}

		/* In case of no error we put our rings in netmap mode */
		for_rx_tx(t) {
			for (i = 0; i < nma_get_nrings(na, t) + 1; i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_on(kring)) {
					struct netmap_kring *sring, *dring;

					/* copy the buffers from the non-fake ring */
					if (kring->nr_kflags & NKR_FAKERING) {
						sring = kring->pipe;
						dring = kring;
					} else {
						sring = kring;
						dring = kring->pipe;
					}
					memcpy(dring->ring->slot,
					       sring->ring->slot,
					       sizeof(struct netmap_slot) *
							sring->nkr_num_slots);
					/* mark both rings as fake and needed,
					 * so that buffers will not be
					 * deleted by the standard machinery
					 * (we will delete them by ourselves in
					 * veth_netmap_krings_delete)
					 */
					sring->nr_kflags |=
						(NKR_FAKERING | NKR_NEEDRING);
					dring->nr_kflags |=
						(NKR_FAKERING | NKR_NEEDRING);
					kring->nr_mode = NKR_NETMAP_ON;
				}
			}
		}
		nm_set_native_flags(na);
		if (netmap_verbose) {
			D("registered veth %s", na->name);
		}
	} else {
		nm_clear_native_flags(na);

		for_rx_tx(t) {
			for (i = 0; i < nma_get_nrings(na, t) + 1; i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_off(kring)) {
					kring->nr_mode = NKR_NETMAP_OFF;
				}
			}
		}
		if (netmap_verbose) {
			D("unregistered veth %s", na->name);
		}
	}

	if (na->active_fds == 0 && was_up) {
		veth_open(ifp);
	}

	if (vna->peer_ref) {
		return 0;
	}
	if (onoff) {
		vna->peer->peer_ref = 0;
		netmap_adapter_put(na);
	} else {
		netmap_adapter_get(na);
		vna->peer->peer_ref = 1;
	}

	return 0;
}

/* See netmap_pipe_krings_create(). */
static int
veth_netmap_krings_create(struct netmap_adapter *na)
{
	struct netmap_veth_adapter *vna = (struct netmap_veth_adapter *)na;
	struct netmap_adapter *peer_na;
	int error = 0;
	enum txrx t;

	/* The nm_krings_create callback is called first in netmap_do_regif(),
	 * so the the cross linking happens now (if this is the first endpoint
	 * to register). */
	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	rcu_read_unlock();
	if (!peer_na) {
		D("veth peer not found");
		return ENXIO;
	}

	if (vna->peer_ref) {

		/* create my krings */
		error = netmap_krings_create(na, 0);
		if (error)
			return error;

		/* create the krings of the other end */
		error = netmap_krings_create(peer_na, 0);
		if (error)
			goto del_krings1;

		/* cross link the krings (only the hw ones, not
		 * the host krings) */
		for_rx_tx(t) {
			enum txrx r = nm_txrx_swap(t); /* swap NR_TX <-> NR_RX */
			int i;

			for (i = 0; i < nma_get_nrings(na, t); i++) {
				NMR(na, t)[i]->pipe = NMR(peer_na, r)[i];
				NMR(peer_na, r)[i]->pipe = NMR(na, t)[i];
				/* mark all peer-adapter rings as fake */
				NMR(peer_na, r)[i]->nr_kflags |= NKR_FAKERING;
			}
		}

		if (netmap_verbose) {
			D("created krings for %s and its peer", na->name);
		}
	}

	return 0;

del_krings1:
	netmap_krings_delete(na);
	return error;
}

/* See netmap_pipe_krings_delete(). */
static void
veth_netmap_krings_delete(struct netmap_adapter *na)
{
	struct netmap_veth_adapter *vna = (struct netmap_veth_adapter *)na;
	struct netmap_adapter *peer_na, *sna;
	enum txrx t;
	int i;

	if (!vna->peer_ref) {
		return;
	}

	if (netmap_verbose) {
		D("Delete krings for %s and its peer", na->name);
	}

	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	rcu_read_unlock();
	if (!peer_na) {
		D("veth peer not found");
		return;
	}

	sna = na;
cleanup:
	for_rx_tx(t) {
		for (i = 0; i < nma_get_nrings(sna, t) + 1; i++) {
			struct netmap_kring *kring = NMR(sna, t)[i];
			struct netmap_ring *ring = kring->ring;
			uint32_t j, lim = kring->nkr_num_slots - 1;

			ND("%s ring %p hwtail %u hwcur %u",
				kring->name, ring, kring->nr_hwtail, kring->nr_hwcur);

			if (ring == NULL)
				continue;

			if (kring->nr_hwtail == kring->nr_hwcur)
				ring->slot[kring->nr_hwtail].buf_idx = 0;

			for (j = nm_next(kring->nr_hwtail, lim);
			     j != kring->nr_hwcur;
			     j = nm_next(j, lim))
			{
				ND("%s[%d] %u", kring->name, j, ring->slot[j].buf_idx);
				ring->slot[j].buf_idx = 0;
			}
			kring->nr_kflags &= ~(NKR_FAKERING | NKR_NEEDRING);
		}

	}
	if (sna != peer_na && peer_na->tx_rings) {
		sna = peer_na;
		goto cleanup;
	}

	netmap_mem_rings_delete(na);
	netmap_krings_delete(na); /* also zeroes tx_rings etc. */

	if (peer_na->tx_rings == NULL) {
		/* already deleted, we must be on an
		 * cleanup-after-error path */
		return;
	}
	netmap_mem_rings_delete(peer_na);
	netmap_krings_delete(peer_na);
}

static void
veth_netmap_attach(struct ifnet *ifp)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = ifp;
	na.pdev = NULL;
	na.num_tx_desc = 1024;
	na.num_rx_desc = 1024;
	na.nm_register = veth_netmap_reg;
	na.nm_txsync = netmap_pipe_txsync;
	na.nm_rxsync = netmap_pipe_rxsync;
	na.nm_krings_create = veth_netmap_krings_create;
	na.nm_krings_delete = veth_netmap_krings_delete;
	na.nm_dtor = veth_netmap_dtor;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach_ext(&na, sizeof(struct netmap_veth_adapter),
			0 /* do not ovveride reg */);
}

/* end of file */
