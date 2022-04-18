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
		vna->peer->peer = NULL;
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
	int error;

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
		enum txrx t;

		error = netmap_pipe_reg_both(na, peer_na);
		if (error) {
			return error;
		}
		for_rx_tx(t) {
			int i;

			for (i = nma_get_nrings(na, t);
			    i < netmap_real_rings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_on(kring)) {
					/* mark the peer ring as needed */
					kring->nr_mode |= NKR_NETMAP_ON	;
				}
			}
		}
		nm_set_native_flags(na);
		if (netmap_verbose) {
			nm_prinf("registered veth %s", na->name);
		}
	} else {
		nm_clear_native_flags(na);
		netmap_krings_mode_commit(na, onoff);
		if (netmap_verbose) {
			nm_prinf("unregistered veth %s", na->name);
		}
	}

	if (na->active_fds == 0 && was_up) {
		veth_open(ifp);
	}

	if (vna->peer_ref) {
		return 0;
	}
	if (onoff) {
		if (vna->peer->peer_ref) {
			vna->peer->peer_ref = 0;
			netmap_adapter_put(na);
		}
	} else {
		if (!vna->peer->peer_ref) {
			netmap_adapter_get(na);
			vna->peer->peer_ref = 1;
		}
	}

	return 0;
}

static int
veth_netmap_krings_create(struct netmap_adapter *na)
{
	struct netmap_veth_adapter *vna = (struct netmap_veth_adapter *)na;
	struct netmap_adapter *peer_na;

	/* The nm_krings_create callback is called first in netmap_do_regif(),
	 * so the the cross linking happens now (if this is the first endpoint
	 * to register). */
	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	rcu_read_unlock();
	if (!peer_na) {
		nm_prerr("veth peer not found for %s", na->name);
		return ENXIO;
	}

	if (vna->peer_ref)
		return netmap_pipe_krings_create_both(na, peer_na);

	return 0;
}

static void
veth_netmap_krings_delete(struct netmap_adapter *na)
{
	struct netmap_veth_adapter *vna = (struct netmap_veth_adapter *)na;
	struct netmap_adapter *peer_na;

	if (!vna->peer_ref) {
		return;
	}

	if (netmap_verbose) {
		nm_prinf("Delete krings for %s and its peer", na->name);
	}

	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	rcu_read_unlock();
	if (!peer_na) {
		nm_prinf("veth peer not found");
		return;
	}

	netmap_pipe_krings_delete_both(na, peer_na);

	netmap_adapter_put(&vna->peer->up.up);
	vna->peer_ref = 0;
	vna->peer->peer = NULL;
	vna->peer = NULL;
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
			0 /* do not override reg */);
}

/* end of file */
