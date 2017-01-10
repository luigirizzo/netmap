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

/* To be called under RCU read lock */
static struct netmap_adapter *
veth_get_peer_na(struct netmap_adapter *na)
{
	struct ifnet *ifp = na->ifp;
	struct veth_priv *priv = netdev_priv(ifp);
	struct ifnet *peer_ifp;

	peer_ifp = rcu_dereference(priv->peer);
	if (!peer_ifp) {
		return NULL;
	}

	return NA(peer_ifp);
}

/*
 * Returns true if our krings needed by the other peer, false
 * if they are not, or they do not exist.
 */
static bool
krings_needed(struct netmap_adapter *na)
{
	enum txrx t;
	int i;

	if (na->tx_rings == NULL) {
		return false;
	}

	for_rx_tx(t) {
		for (i = 0; i < nma_get_nrings(na, t) + 1; i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];

			if (kring->nr_kflags & NKR_NEEDRING) {
				return true;
			}
		}
	}

	return false;
}

/*
 * Register/unregister. We are already under netmap lock.
 * This register function is similar to the one used by
 * pipes; in addition to the regular tasks (commit the rings
 * in/out netmap node and call nm_(set|clear)_native_flags),
 * we also mark the peer rings as needed by us and possibly
 * create/destroy some netmap rings.
 */
static int
veth_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_adapter *peer_na;
	struct ifnet *ifp = na->ifp;
	bool was_up;
	enum txrx t;
	int error;
	int i;

	rcu_read_lock();

	peer_na = veth_get_peer_na(na);
	if (!peer_na) {
		rcu_read_unlock();
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
				struct netmap_kring *kring = &NMR(na, t)[i];

				if (nm_kring_pending_on(kring)) {
					/* mark the peer ring as needed */
					kring->pipe->nr_kflags |= NKR_NEEDRING;
				}
			}
		}

		/* create all missing needed rings on the other end */
		error = netmap_mem_rings_create(peer_na);
		if (error) {
			rcu_read_unlock();
			return error;
		}

		/* In case of no error we put our rings in netmap mode */
		for_rx_tx(t) {
			for (i = 0; i < nma_get_nrings(na, t) + 1; i++) {
				struct netmap_kring *kring = &NMR(na, t)[i];

				if (nm_kring_pending_on(kring)) {
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
				struct netmap_kring *kring = &NMR(na, t)[i];

				if (nm_kring_pending_off(kring)) {
					kring->nr_mode = NKR_NETMAP_OFF;
					/* If hw kring, mark the peer kring
					 * as no longer needed by us (it may
					 * still be kept if sombody else is
					 * using it).
					 */
					if (kring->pipe) {
						kring->pipe->nr_kflags &=
								~NKR_NEEDRING;
					}
				}
			}
		}
		/* delete all the peer rings that are no longer needed */
		netmap_mem_rings_delete(peer_na);
		if (netmap_verbose) {
			D("unregistered veth %s", na->name);
		}
	}

	rcu_read_unlock();

	if (na->active_fds == 0 && was_up) {
		veth_open(ifp);
	}

	return error;
}

static int
veth_netmap_krings_create(struct netmap_adapter *na)
{
	struct netmap_adapter *peer_na;
	int error = 0;
	enum txrx t;

	if (krings_needed(na)) {
		/* Our krings are already needed by our peer, which
		 * means they were already created. */
		if (netmap_verbose) {
			D("krings already created for %s, nothing to do",
			  na->name);
		}
		return 0;
	}

	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	if (!peer_na) {
		rcu_read_unlock();
		D("veth peer not found");
		return ENXIO;
	}

	/* create my krings */
	error = netmap_krings_create(na, 0);
	if (error)
		goto err;

	/* create the krings of the other end */
	error = netmap_krings_create(peer_na, 0);
	if (error)
		goto del_krings1;

	/* cross link the krings (only the hw ones, not the host krings) */
	for_rx_tx(t) {
		enum txrx r = nm_txrx_swap(t); /* swap NR_TX <-> NR_RX */
		int i;

		for (i = 0; i < nma_get_nrings(na, t); i++) {
			NMR(na, t)[i].pipe = NMR(peer_na, r) + i;
			NMR(peer_na, r)[i].pipe = NMR(na, t) + i;
		}
	}

	rcu_read_unlock();

	if (netmap_verbose) {
		D("created krings for %s and its peer", na->name);
	}

	return 0;

del_krings1:
	netmap_krings_delete(na);
err:
	rcu_read_unlock();
	return error;
}

static void
veth_netmap_krings_delete(struct netmap_adapter *na)
{
	struct netmap_adapter *peer_na;

	if (krings_needed(na)) {
		/* Our krings are needed by the other peer, so we
		 * do nothing here, and let the peer destroy also
		 * our krings when it needs to destroy its krings. */
		if (netmap_verbose) {
			D("krings for %s are still needed by its peer",
			  na->name);
		}
		return;
	}

	if (netmap_verbose) {
		D("Delete krings for %s and its peer", na->name);
	}

	/* Destroy my krings. */
	netmap_krings_delete(na);

	/* Destroy the krings of our peer. */
	rcu_read_lock();
	peer_na = veth_get_peer_na(na);
	if (!peer_na) {
		rcu_read_unlock();
		D("veth peer not found");
		return;
	}

	netmap_krings_delete(peer_na);
	rcu_read_unlock();
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
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
