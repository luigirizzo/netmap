/*
 * Copyright (C) 2015 Stefano Garzarella
 * Copyright (C) 2016 Vincenzo Maffione
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
 *
 * $FreeBSD$
 */

/*
 * common headers
 */
#if defined(__FreeBSD__)
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/selinfo.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>

#elif defined(linux)
#include <bsd_glue.h>
#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <net/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>

#ifdef WITH_PTNETMAP_GUEST
/*
 * Guest ptnetmap txsync()/rxsync() routines, used in ptnet device drivers.
 * These routines are reused across the different operating systems supported
 * by netmap.
 */

/*
 * Reconcile host and guest views of the transmit ring.
 *
 * Guest user wants to transmit packets up to the one before ring->head,
 * and guest kernel knows tx_ring->hwcur is the first packet unsent
 * by the host kernel.
 *
 * We push out as many packets as possible, and possibly
 * reclaim buffers from previously completed transmission.
 *
 * Notifications from the host are enabled only if the user guest would
 * block (no space in the ring).
 */
bool
netmap_pt_guest_txsync(struct ptnet_csb_gh *ptgh, struct ptnet_csb_hg *pthg,
			struct netmap_kring *kring, int flags)
{
	bool notify = false;

	/* Disable notifications */
	ptgh->guest_need_kick = 0;

	/*
	 * First part: tell the host (updating the CSB) to process the new
	 * packets.
	 */
	kring->nr_hwcur = pthg->hwcur;
	ptnetmap_guest_write_kring_csb(ptgh, kring->rcur, kring->rhead);

        /* Ask for a kick from a guest to the host if needed. */
	if (((kring->rhead != kring->nr_hwcur || nm_kr_txempty(kring))
		&& NM_ACCESS_ONCE(pthg->host_need_kick)) ||
			(flags & NAF_FORCE_RECLAIM)) {
		ptgh->sync_flags = flags;
		notify = true;
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (nm_kr_txempty(kring) || (flags & NAF_FORCE_RECLAIM)) {
                ptnetmap_guest_read_kring_csb(pthg, kring);
	}

        /*
         * No more room in the ring for new transmissions. The user thread will
	 * go to sleep and we need to be notified by the host when more free
	 * space is available.
         */
	if (nm_kr_txempty(kring) && !(kring->nr_kflags & NKR_NOINTR)) {
		/* Reenable notifications. */
		ptgh->guest_need_kick = 1;
                /* Double check */
                ptnetmap_guest_read_kring_csb(pthg, kring);
                /* If there is new free space, disable notifications */
		if (unlikely(!nm_kr_txempty(kring))) {
			ptgh->guest_need_kick = 0;
		}
	}

	ND(1, "%s CSB(head:%u cur:%u hwtail:%u) KRING(head:%u cur:%u tail:%u)",
		kring->name, ptgh->head, ptgh->cur, pthg->hwtail,
		kring->rhead, kring->rcur, kring->nr_hwtail);

	return notify;
}

/*
 * Reconcile host and guest view of the receive ring.
 *
 * Update hwcur/hwtail from host (reading from CSB).
 *
 * If guest user has released buffers up to the one before ring->head, we
 * also give them to the host.
 *
 * Notifications from the host are enabled only if the user guest would
 * block (no more completed slots in the ring).
 */
bool
netmap_pt_guest_rxsync(struct ptnet_csb_gh *ptgh, struct ptnet_csb_hg *pthg,
			struct netmap_kring *kring, int flags)
{
	bool notify = false;

        /* Disable notifications */
	ptgh->guest_need_kick = 0;

	/*
	 * First part: import newly received packets, by updating the kring
	 * hwtail to the hwtail known from the host (read from the CSB).
	 * This also updates the kring hwcur.
	 */
        ptnetmap_guest_read_kring_csb(pthg, kring);
	kring->nr_kflags &= ~NKR_PENDINTR;

	/*
	 * Second part: tell the host about the slots that guest user has
	 * released, by updating cur and head in the CSB.
	 */
	if (kring->rhead != kring->nr_hwcur) {
		ptnetmap_guest_write_kring_csb(ptgh, kring->rcur,
					       kring->rhead);
                /* Ask for a kick from the guest to the host if needed. */
		if (NM_ACCESS_ONCE(pthg->host_need_kick)) {
			ptgh->sync_flags = flags;
			notify = true;
		}
	}

        /*
         * No more completed RX slots. The user thread will go to sleep and
	 * we need to be notified by the host when more RX slots have been
	 * completed.
         */
	if (nm_kr_rxempty(kring) && !(kring->nr_kflags & NKR_NOINTR)) {
		/* Reenable notifications. */
                ptgh->guest_need_kick = 1;
                /* Double check */
                ptnetmap_guest_read_kring_csb(pthg, kring);
                /* If there are new slots, disable notifications. */
		if (!nm_kr_rxempty(kring)) {
                        ptgh->guest_need_kick = 0;
                }
        }

	ND(1, "%s CSB(head:%u cur:%u hwtail:%u) KRING(head:%u cur:%u tail:%u)",
		kring->name, ptgh->head, ptgh->cur, pthg->hwtail,
		kring->rhead, kring->rcur, kring->nr_hwtail);

	return notify;
}

/*
 * Callbacks for ptnet drivers: nm_krings_create, nm_krings_delete, nm_dtor.
 */
int
ptnet_nm_krings_create(struct netmap_adapter *na)
{
	struct netmap_pt_guest_adapter *ptna =
			(struct netmap_pt_guest_adapter *)na; /* Upcast. */
	struct netmap_adapter *na_nm = &ptna->hwup.up;
	struct netmap_adapter *na_dr = &ptna->dr.up;
	int ret;

	if (ptna->backend_regifs) {
		return 0;
	}

	/* Create krings on the public netmap adapter. */
	ret = netmap_hw_krings_create(na_nm);
	if (ret) {
		return ret;
	}

	/* Copy krings into the netmap adapter private to the driver. */
	na_dr->tx_rings = na_nm->tx_rings;
	na_dr->rx_rings = na_nm->rx_rings;

	return 0;
}

void
ptnet_nm_krings_delete(struct netmap_adapter *na)
{
	struct netmap_pt_guest_adapter *ptna =
			(struct netmap_pt_guest_adapter *)na; /* Upcast. */
	struct netmap_adapter *na_nm = &ptna->hwup.up;
	struct netmap_adapter *na_dr = &ptna->dr.up;

	if (ptna->backend_regifs) {
		return;
	}

	na_dr->tx_rings = NULL;
	na_dr->rx_rings = NULL;

	netmap_hw_krings_delete(na_nm);
}

void
ptnet_nm_dtor(struct netmap_adapter *na)
{
	struct netmap_pt_guest_adapter *ptna =
			(struct netmap_pt_guest_adapter *)na;

	netmap_mem_put(ptna->dr.up.nm_mem);
	memset(&ptna->dr, 0, sizeof(ptna->dr));
	netmap_mem_pt_guest_ifp_del(na->nm_mem, na->ifp);
}

int
netmap_pt_guest_attach(struct netmap_adapter *arg,
		       unsigned int nifp_offset, unsigned int memid)
{
	struct netmap_pt_guest_adapter *ptna;
	struct ifnet *ifp = arg ? arg->ifp : NULL;
	int error;

	/* get allocator */
	arg->nm_mem = netmap_mem_pt_guest_new(ifp, nifp_offset, memid);
	if (arg->nm_mem == NULL)
		return ENOMEM;
	arg->na_flags |= NAF_MEM_OWNER;
	error = netmap_attach_ext(arg, sizeof(struct netmap_pt_guest_adapter), 1);
	if (error)
		return error;

	/* get the netmap_pt_guest_adapter */
	ptna = (struct netmap_pt_guest_adapter *) NA(ifp);

	/* Initialize a separate pass-through netmap adapter that is going to
	 * be used by the ptnet driver only, and so never exposed to netmap
         * applications. We only need a subset of the available fields. */
	memset(&ptna->dr, 0, sizeof(ptna->dr));
	ptna->dr.up.ifp = ifp;
	ptna->dr.up.nm_mem = netmap_mem_get(ptna->hwup.up.nm_mem);
        ptna->dr.up.nm_config = ptna->hwup.up.nm_config;

	ptna->backend_regifs = 0;

	return 0;
}

#endif /* WITH_PTNETMAP_GUEST */
