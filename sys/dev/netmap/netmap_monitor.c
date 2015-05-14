/*
 * Copyright (C) 2014 Giuseppe Lettieri. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/netmap_zmon.c 270063 2014-08-16 15:00:01Z luigi $
 *
 * Monitors
 *
 * netmap monitors can be used to do zero-copy monitoring of network traffic
 * on another adapter, when the latter adapter is working in netmap mode.
 *
 * Monitors offer to userspace the same interface as any other netmap port,
 * with as many pairs of netmap rings as the monitored adapter.
 * However, only the rx rings are actually used. Each monitor rx ring receives
 * the traffic transiting on both the tx and rx corresponding rings in the
 * monitored adapter. During registration, the user can choose if she wants
 * to intercept tx only, rx only, or both tx and rx traffic.
 *
 * The monitor only sees the frames after they have been consumed in the
 * monitored adapter:
 *
 *  - For tx traffic, this is after the slots containing the frames have been
 *    marked as free. Note that this may happen at a considerably delay after
 *    frame transmission, since freeing of slots is often done lazily.
 *
 *  - For rx traffic, this is after the consumer on the monitored adapter
 *    has released them. In most cases, the consumer is a userspace
 *    application which may have modified the frame contents.
 *
 * If the monitor is not able to cope with the stream of frames, excess traffic
 * will be dropped.
 *
 * Each ring can be monitored by at most one monitor. This may change in the
 * future, if we implement monitor chaining.
 *
 */


#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/socket.h> /* sockaddrs */
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/refcount.h>


#elif defined(linux)

#include "bsd_glue.h"

#elif defined(__APPLE__)

#warning OSX support is only partial
#include "osx_glue.h"

#else

#error	Unsupported platform

#endif /* unsupported */

/*
 * common headers
 */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

#ifdef WITH_MONITOR

#define NM_MONITOR_MAXSLOTS 4096

/* monitor works by replacing the nm_sync callbacks in the monitored rings.
 * The actions to be performed are the same on both tx and rx rings, so we
 * have collected them here
 */
static int
netmap_zmon_parent_sync(struct netmap_kring *kring, int flags, enum txrx tx)
{
	struct netmap_kring *mkring = kring->next_monitor[tx];
	struct netmap_ring *ring = kring->ring, *mring;
	int error = 0;
	int rel_slots, free_slots, busy, sent = 0;
	u_int beg, end, i;
	u_int lim = kring->nkr_num_slots - 1,
	      mlim; // = mkring->nkr_num_slots - 1;

	if (mkring == NULL) {
		RD(5, "NULL monitor on %s", kring->name);
		return 0;
	}
	mring = mkring->ring;
	mlim = mkring->nkr_num_slots - 1;

	/* get the relased slots (rel_slots) */
	if (tx == NR_TX) {
		beg = kring->nr_hwtail;
		error = kring->mon_sync(kring, flags);
		if (error)
			return error;
		end = kring->nr_hwtail;
	} else { /* NR_RX */
		beg = kring->nr_hwcur;
		end = kring->rhead;
	}

	rel_slots = end - beg;
	if (rel_slots < 0)
		rel_slots += kring->nkr_num_slots;

	if (!rel_slots) {
		/* no released slots, but we still need
		 * to call rxsync if this is a rx ring
		 */
		goto out_rxsync;
	}

	/* we need to lock the monitor receive ring, since it
	 * is the target of bot tx and rx traffic from the monitored
	 * adapter
	 */
	mtx_lock(&mkring->q_lock);
	/* get the free slots available on the monitor ring */
	i = mkring->nr_hwtail;
	busy = i - mkring->nr_hwcur;
	if (busy < 0)
		busy += mkring->nkr_num_slots;
	free_slots = mlim - busy;

	if (!free_slots)
		goto out;

	/* swap min(free_slots, rel_slots) slots */
	if (free_slots < rel_slots) {
		beg += (rel_slots - free_slots);
		if (beg >= kring->nkr_num_slots)
			beg -= kring->nkr_num_slots;
		rel_slots = free_slots;
	}

	sent = rel_slots;
	for ( ; rel_slots; rel_slots--) {
		struct netmap_slot *s = &ring->slot[beg];
		struct netmap_slot *ms = &mring->slot[i];
		uint32_t tmp;

		tmp = ms->buf_idx;
		ms->buf_idx = s->buf_idx;
		s->buf_idx = tmp;
		ND(5, "beg %d buf_idx %d", beg, tmp);

		tmp = ms->len;
		ms->len = s->len;
		s->len = tmp;

		s->flags |= NS_BUF_CHANGED;

		beg = nm_next(beg, lim);
		i = nm_next(i, mlim);

	}
	mb();
	mkring->nr_hwtail = i;

out:
	mtx_unlock(&mkring->q_lock);

	if (sent) {
		/* notify the new frames to the monitor */
		mkring->nm_notify(mkring, 0);
	}

out_rxsync:
	if (tx == NR_RX)
		error = kring->mon_sync(kring, flags);

	return error;
}

/* callback used to replace the nm_sync callback in the monitored tx rings */
static int
netmap_zmon_parent_txsync(struct netmap_kring *kring, int flags)
{
        ND("%s %x", kring->name, flags);
        return netmap_zmon_parent_sync(kring, flags, NR_TX);
}

/* callback used to replace the nm_sync callback in the monitored rx rings */
static int
netmap_zmon_parent_rxsync(struct netmap_kring *kring, int flags)
{
        ND("%s %x", kring->name, flags);
        return netmap_zmon_parent_sync(kring, flags, NR_RX);
}

/* nm_sync callback for the monitor's own tx rings.
 * This makes no sense and always returns error
 */
static int
netmap_monitor_txsync(struct netmap_kring *kring, int flags)
{
        RD(1, "%s %x", kring->name, flags);
	return EIO;
}

/* nm_sync callback for the monitor's own rx rings.
 * Note that the lock in netmap_zmon_parent_sync only protects
 * writers among themselves. Synchronization between writers
 * (i.e., netmap_zmon_parent_txsync and netmap_zmon_parent_rxsync)
 * and readers (i.e., netmap_zmon_rxsync) relies on memory barriers.
 */
static int
netmap_monitor_rxsync(struct netmap_kring *kring, int flags)
{
        ND("%s %x", kring->name, flags);
	kring->nr_hwcur = kring->rcur;
	mb();
        return 0;
}

/* nm_krings_create callbacks for monitors.
 * We could use the default netmap_hw_krings_zmon, but
 * we don't need the mbq.
 */
static int
netmap_monitor_krings_create(struct netmap_adapter *na)
{
	return netmap_krings_create(na, 0);
}

static u_int
nm_txrx2flag(enum txrx t)
{
	return (t == NR_RX ? NR_MONITOR_RX : NR_MONITOR_TX);
}


/* nm_register callback for monitors.
 *
 * On registration, replace the nm_sync callbacks in the monitored
 * rings with our own, saving the previous ones in the monitored
 * rings themselves, where they are used by netmap_zmon_parent_sync.
 *
 * On de-registration, restore the original callbacks. We need to
 * stop traffic while we are doing this, since the monitored adapter may
 * have already started executing a netmap_zmon_parent_sync
 * and may not like the kring->mon_sync pointer to become NULL.
 */
static int
netmap_zmon_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_monitor_adapter *mna =
		(struct netmap_monitor_adapter *)na;
	struct netmap_priv_d *priv = &mna->priv;
	struct netmap_adapter *pna = priv->np_na;
	struct netmap_kring *kring;
	int i;
	enum txrx t;

	ND("%p: onoff %d", na, onoff);
	if (onoff) {
		if (!nm_netmap_on(pna)) {
			/* parent left netmap mode, fatal */
			return ENXIO;
		}
		for_rx_tx(t) {
			if (mna->flags & nm_txrx2flag(t)) {
				for (i = priv->np_qfirst[t]; i < priv->np_qlast[t]; i++) {
					kring = &NMR(pna, t)[i];
					kring->next_monitor[t] = &na->rx_rings[i];
					kring->prev_monitor[t] = NULL;
					kring->mon_sync = kring->nm_sync;
					kring->nm_sync = (t == NR_RX ? 
							netmap_zmon_parent_rxsync :
							netmap_zmon_parent_txsync);
				}
			}
		}
		na->na_flags |= NAF_NETMAP_ON;
	} else {
		if (!nm_netmap_on(pna)) {
			/* parent left netmap mode, nothing to restore */
			return 0;
		}
		na->na_flags &= ~NAF_NETMAP_ON;
		for_rx_tx(t) {
			if (mna->flags & nm_txrx2flag(t)) {
				for (i = priv->np_qfirst[t]; i < priv->np_qlast[t]; i++) {
					netmap_set_ring(pna, i, t, 1 /* stopped */);
					kring = &NMR(pna, t)[i];
					kring->nm_sync = kring->mon_sync;
					kring->mon_sync = NULL;
					kring->next_monitor[t] = NULL;
					netmap_set_ring(pna, i, t, 0 /* enabled */);
				}
			}
		}
	}
	return 0;
}
/* nm_krings_delete callback for monitors */
static void
netmap_monitor_krings_delete(struct netmap_adapter *na)
{
	netmap_krings_delete(na);
}


/* nm_dtor callback for monitors */
static void
netmap_zmon_dtor(struct netmap_adapter *na)
{
	struct netmap_monitor_adapter *mna =
		(struct netmap_monitor_adapter *)na;
	struct netmap_priv_d *priv = &mna->priv;
	struct netmap_adapter *pna = priv->np_na;

	netmap_adapter_put(pna);
}

static void
netmap_monitor_parent_sync(struct netmap_kring *kring, u_int first_new, int new_slots)
{
	struct netmap_kring *mkring;
	enum txrx t = kring->tx;

	for (mkring = kring->next_monitor[t]; mkring; mkring = mkring->next_monitor[t]) {
		u_int i, mlim, beg;
		int free_slots, busy, sent = 0, m;
		u_int lim = kring->nkr_num_slots - 1;
		struct netmap_ring *ring = kring->ring, *mring = mkring->ring;
		u_int max_len = NETMAP_BUF_SIZE(mkring->na);

		mlim = mkring->nkr_num_slots - 1;

		/* we need to lock the monitor receive ring, since it
		 * is the target of bot tx and rx traffic from the monitored
		 * adapter
		 */
		mtx_lock(&mkring->q_lock);
		/* get the free slots available on the monitor ring */
		i = mkring->nr_hwtail;
		busy = i - mkring->nr_hwcur;
		if (busy < 0)
			busy += mkring->nkr_num_slots;
		free_slots = mlim - busy;

		if (!free_slots)
			goto out;

		/* copy min(free_slots, new_slots) slots */
		m = new_slots;
		beg = first_new;
		if (free_slots < m) {
			beg += (m - free_slots);
			if (beg >= kring->nkr_num_slots)
				beg -= kring->nkr_num_slots;
			m = free_slots;
		}

		for ( ; m; m--) {
			struct netmap_slot *s = &ring->slot[beg];
			struct netmap_slot *ms = &mring->slot[i];
			u_int copy_len = s->len;
			char *src = NMB(kring->na, s),
			     *dst = NMB(mkring->na, ms);

			if (unlikely(copy_len > max_len)) {
				RD(5, "%s->%s: truncating %d to %d", kring->name,
						mkring->name, copy_len, max_len);
				copy_len = max_len;
			}

			memcpy(dst, src, copy_len);
			ms->len = copy_len;
			sent++;

			beg = nm_next(beg, lim);
			i = nm_next(i, mlim);
		}
		mb();
		mkring->nr_hwtail = i;
	out:
		mtx_unlock(&mkring->q_lock);

		if (sent) {
			/* notify the new frames to the monitor */
			mkring->nm_notify(mkring, 0);
		}
	}
}

/* callback used to replace the nm_sync callback in the monitored tx rings */
static int
netmap_monitor_parent_txsync(struct netmap_kring *kring, int flags)
{
	u_int first_new;
	int new_slots;

	/* get the new slots */
	first_new = kring->nr_hwcur;
        new_slots = kring->rhead - first_new;
        if (new_slots < 0)
                new_slots += kring->nkr_num_slots;
	if (new_slots)
		netmap_monitor_parent_sync(kring, first_new, new_slots);
	return kring->mon_sync(kring, flags);
}

/* callback used to replace the nm_sync callback in the monitored rx rings */
static int
netmap_monitor_parent_rxsync(struct netmap_kring *kring, int flags)
{
	u_int first_new;
	int new_slots, error;

	/* get the new slots */
	error =  kring->mon_sync(kring, flags);
	if (error)
		return error;
	first_new = kring->mon_tail;
        new_slots = kring->nr_hwtail - first_new;
        if (new_slots < 0)
                new_slots += kring->nkr_num_slots;
	if (new_slots)
		netmap_monitor_parent_sync(kring, first_new, new_slots);
	kring->mon_tail = kring->nr_hwtail;
	return 0;
}

static int
netmap_monitor_parent_notify(struct netmap_kring *kring, int flags)
{
	RD(5, "%s %x", kring->name, flags);
	if (nm_kr_tryget(kring))
		goto out;
	netmap_monitor_parent_rxsync(kring, NAF_FORCE_READ);
	nm_kr_put(kring);
out:
        return kring->mon_notify(kring, flags);
}


static void
netmap_monitor_add(struct netmap_adapter *na, struct netmap_kring *kring)
{
	u_int ring_n = kring->ring_id;
	struct netmap_kring *mkring = &na->rx_rings[ring_n];
	enum txrx t = kring->tx;

	nm_kr_get(kring);
	if (kring->next_monitor[t] == NULL) {
		/* this is the first monitor, intercept callbacks */
		D("%s: intercept callbacks", na->name);
		kring->mon_sync = kring->nm_sync;
		if (t == NR_TX) {
			kring->nm_sync = netmap_monitor_parent_txsync;
		} else {
			kring->nm_sync = netmap_monitor_parent_rxsync;
			/* also intercept notify */
			kring->mon_notify = kring->nm_notify;
			kring->nm_notify = netmap_monitor_parent_notify;
			kring->mon_tail = kring->nr_hwtail;
		}
	}
	/* front insert */
	mkring->prev_monitor[t] = kring;
	mkring->next_monitor[t] = kring->next_monitor[t];
	kring->next_monitor[t] = mkring;
	if (mkring->next_monitor[t])
		mkring->next_monitor[t]->prev_monitor[t] = mkring;
	nm_kr_put(kring);
}

static void
netmap_monitor_del(struct netmap_adapter *na, struct netmap_kring *kring)
{
	u_int ring_n = kring->ring_id;
	struct netmap_kring *mkring = &na->rx_rings[ring_n];
	enum txrx t = kring->tx;

	nm_kr_get(kring);
	/* remove from list */
	mkring->prev_monitor[t]->next_monitor[t] = mkring->next_monitor[t];
	if (mkring->next_monitor[t])
		mkring->next_monitor[t]->prev_monitor[t] = mkring->prev_monitor[t];
	if (kring->next_monitor[t] == NULL) {
		/* this was the last monitor, restore callbacks */
		D("restoring sync %p", kring->mon_sync);
		kring->nm_sync = kring->mon_sync;
		kring->mon_sync = NULL;
		if (kring->tx == NR_RX) {
			D("restoring notify %p", kring->mon_notify);
			kring->nm_notify = kring->mon_notify;
			kring->mon_notify = NULL;
		}
	}
	/* for safety */
	mkring->next_monitor[t] = NULL;
	mkring->prev_monitor[t] = NULL;
	nm_kr_put(kring);
}

static int
netmap_monitor_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_monitor_adapter *mna =
		(struct netmap_monitor_adapter *)na;
	struct netmap_priv_d *priv = &mna->priv;
	struct netmap_adapter *pna = priv->np_na;
	struct netmap_kring *kring;
	int i;
	enum txrx t;

	D("%p: onoff %d", na, onoff);
	for_rx_tx(t) {
		if (! (mna->flags & nm_txrx2flag(t)))
			continue;
		for (i = priv->np_qfirst[t]; i < priv->np_qlast[t]; i++) {
			kring = &NMR(pna, t)[i];
			if (onoff)
				netmap_monitor_add(na, kring);
			else
				netmap_monitor_del(na, kring);
		}
	}
	if (onoff)
		na->na_flags |= NAF_NETMAP_ON;
	else
		na->na_flags &= ~NAF_NETMAP_ON;	
	return 0;
}

static void
netmap_monitor_dtor(struct netmap_adapter *na)
{
	struct netmap_monitor_adapter *mna =
		(struct netmap_monitor_adapter *)na;
	struct netmap_priv_d *priv = &mna->priv;
	struct netmap_adapter *pna = priv->np_na;

	netmap_adapter_put(pna);
}


/* check if nmr is a request for a monitor adapter that we can satisfy */
int
netmap_get_monitor_na(struct nmreq *nmr, struct netmap_adapter **na, int create)
{
	struct nmreq pnmr;
	struct netmap_adapter *pna; /* parent adapter */
	struct netmap_monitor_adapter *mna;
	int i, error;
	enum txrx t;
	int zcopy = (nmr->nr_flags & NR_ZCOPY_MON);

	if ((nmr->nr_flags & (NR_MONITOR_TX | NR_MONITOR_RX)) == 0) {
		ND("not a monitor");
		return 0;
	}
	/* this is a request for a monitor adapter */

	D("flags %x", nmr->nr_flags);

	mna = malloc(sizeof(*mna), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (mna == NULL) {
		D("memory error");
		return ENOMEM;
	}

	/* first, try to find the adapter that we want to monitor
	 * We use the same nmr, after we have turned off the monitor flags.
	 * In this way we can potentially monitor everything netmap understands,
	 * except other monitors.
	 */
	memcpy(&pnmr, nmr, sizeof(pnmr));
	pnmr.nr_flags &= ~(NR_MONITOR_TX | NR_MONITOR_RX);
	error = netmap_get_na(&pnmr, &pna, create);
	if (error) {
		D("parent lookup failed: %d", error);
		return error;
	}
	D("found parent: %s", pna->name);

	if (!nm_netmap_on(pna)) {
		/* parent not in netmap mode */
		/* XXX we can wait for the parent to enter netmap mode,
		 * by intercepting its nm_register callback (2014-03-16)
		 */
		D("%s not in netmap mode", pna->name);
		error = EINVAL;
		goto put_out;
	}

	/* grab all the rings we need in the parent */
	mna->priv.np_na = pna;
	error = netmap_interp_ringid(&mna->priv, nmr->nr_ringid, nmr->nr_flags);
	if (error) {
		D("ringid error");
		goto put_out;
	}
	snprintf(mna->up.name, sizeof(mna->up.name), "mon:%s", pna->name);

	if (zcopy) {
		/* zero copy monitors need exclusive access to the monitored rings */
		for_rx_tx(t) {
			if (! (nmr->nr_flags & nm_txrx2flag(t)))
				continue;
			for (i = mna->priv.np_qfirst[t]; i < mna->priv.np_qlast[t]; i++) {
				struct netmap_kring *kring = &NMR(pna, t)[i];
				if (kring->next_monitor) {
					error = EBUSY;
					D("ring busy");
					goto put_out;
				}
			}
		}
		mna->up.nm_register = netmap_zmon_reg;
		mna->up.nm_dtor = netmap_zmon_dtor;
		/* to have zero copy, we need to use the same memory allocator
		 * as the monitored port
		 */
		mna->up.nm_mem = pna->nm_mem;
		mna->up.na_lut = pna->na_lut;
		mna->up.na_lut_objtotal = pna->na_lut_objtotal;
		mna->up.na_lut_objsize = pna->na_lut_objsize;
	} else {
		/* normal monitors are incompatible with zero copy ones */
		for_rx_tx(t) {
			if (! (nmr->nr_flags & nm_txrx2flag(t)))
				continue;
			for (i = mna->priv.np_qfirst[t]; i < mna->priv.np_qlast[t]; i++) {
				struct netmap_kring *kring = &NMR(pna, t)[i];
				if (kring->next_monitor[t] &&
				    kring->next_monitor[t]->na->nm_register == netmap_zmon_reg)
				{
					error = EBUSY;
					D("ring busy");
					goto put_out;
				}
			}
		}
		mna->up.nm_rxsync = netmap_monitor_rxsync;
		mna->up.nm_register = netmap_monitor_reg;
		mna->up.nm_dtor = netmap_monitor_dtor;
	}

	/* the monitor supports the host rings iff the parent does */
	mna->up.na_flags = (pna->na_flags & NAF_HOST_RINGS);
	/* a do-nothing txsync: monitors cannot be used to inject packets */
	mna->up.nm_txsync = netmap_monitor_txsync;
	mna->up.nm_rxsync = netmap_monitor_rxsync;
	mna->up.nm_krings_create = netmap_monitor_krings_create;
	mna->up.nm_krings_delete = netmap_monitor_krings_delete;
	mna->up.num_tx_rings = 1; // XXX we don't need it, but field can't be zero
	/* we set the number of our rx_rings to be max(num_rx_rings, num_rx_rings)
	 * in the parent
	 */
	mna->up.num_rx_rings = pna->num_rx_rings;
	if (pna->num_tx_rings > pna->num_rx_rings)
		mna->up.num_rx_rings = pna->num_tx_rings;
	/* by default, the number of slots is the same as in
	 * the parent rings, but the user may ask for a different
	 * number
	 */
	mna->up.num_tx_desc = nmr->nr_tx_slots;
	nm_bound_var(&mna->up.num_tx_desc, pna->num_tx_desc,
			1, NM_MONITOR_MAXSLOTS, NULL);
	mna->up.num_rx_desc = nmr->nr_rx_slots;
	nm_bound_var(&mna->up.num_rx_desc, pna->num_rx_desc,
			1, NM_MONITOR_MAXSLOTS, NULL);
	error = netmap_attach_common(&mna->up);
	if (error) {
		D("attach_common error");
		goto put_out;
	}

	/* remember the traffic directions we have to monitor */
	mna->flags = (nmr->nr_flags & (NR_MONITOR_TX | NR_MONITOR_RX));

	*na = &mna->up;
	netmap_adapter_get(*na);

	/* write the configuration back */
	nmr->nr_tx_rings = mna->up.num_tx_rings;
	nmr->nr_rx_rings = mna->up.num_rx_rings;
	nmr->nr_tx_slots = mna->up.num_tx_desc;
	nmr->nr_rx_slots = mna->up.num_rx_desc;

	/* keep the reference to the parent */
	D("monitor ok");

	return 0;

put_out:
	netmap_adapter_put(pna);
	free(mna, M_DEVBUF);
	return error;
}


#endif /* WITH_MONITOR */
