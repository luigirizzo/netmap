/*
 * Copyright (C) 2014 Luigi Rizzo. All rights reserved.
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
 * $FreeBSD$
 *
 * netmap modifications for cxgbe

20120120
t4_sge seems to be the main file for processing.

the device has several queues
	iq	ingress queue (messages posted ?)
	fl	freelist queue

buffers are in sd->cl

interrupts are serviced by t4_intr*() which does a atomic_cmpset_int()
to run only one instance of the driver (service_iq()) and
then clears the flag at the end.
The dispatches in there makes a list (iql) of postponed work.

Handlers are cpl_handler[] per packet type.
	received packets are t4_eth_rx()

the main transmit routine is t4_main.c :: cxgbe_transmit()
	which ends into t4_sge.c :: t4_eth_tx()
	and eventually write_txpkt_wr()

refill_fl() is called under lock
X_RSPD_TYPE_FLBUF	is a data packet, perhaps
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
// #include <vm/vm.h>
// #include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>

static int	cxgbe_netmap_reg(struct ifnet *, int onoff);
static int	cxgbe_netmap_txsync(void *, u_int, int);
static int	cxgbe_netmap_rxsync(void *, u_int, int);
static void	cxgbe_netmap_lock_wrapper(void *, int, u_int);


SYSCTL_NODE(_dev, OID_AUTO, cxgbe, CTLFLAG_RW, 0, "cxgbe card");

static void
cxgbe_netmap_attach(struct port_info *pi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = pi->ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = 0; // qsize pi->num_tx_desc;
	na.num_rx_desc = 0; // XXX qsize  pi->num_rx_desc;
	na.nm_txsync = cxgbe_netmap_txsync;
	na.nm_rxsync = cxgbe_netmap_rxsync;
	na.nm_register = cxgbe_netmap_reg;
	/*
	 * adapter->rx_mbuf_sz is set by SIOCSETMTU, but in netmap mode
	 * we allocate the buffers on the first register. So we must
	 * disallow a SIOCSETMTU in netmap mode
	 */
	na.num_tx_rings = na->num_rx_rings = pi->ntxq;
	na.buff_size = NETMAP_BUF_SIZE;
	netmap_attach(&na);
}


/*
 * support for netmap register/unregisted. We are already under core lock.
 * only called on the first init or the last unregister.
 */
static int
cxgbe_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;

#if 0
	cxgbe_disable_intr(adapter);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}
	cxgbe_init_locked(adapter);	/* also enables intr */
#endif
	return (ifp->if_drv_flags & IFF_DRV_RUNNING ? 0 : 1);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
cxgbe_netmap_txsync(struct netmap_kring *kring, int flags)
{
#if 0
	// see ixgbe_netmap.h
#endif
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
cxgbe_netmap_rxsync(struct netmap_kring *kring, int flags)
{
#if 0
	// see ixgbe_netmap.h
#endif
	return 0;
}
