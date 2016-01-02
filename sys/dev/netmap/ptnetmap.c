/*
 * Copyright (C) 2015 Stefano Garzarella (stefano.garzarella@gmail.com)
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

//#define usleep_range(_1, _2)
#define usleep_range(_1, _2) \
	pause_sbt("ptnetmap-sleep", SBT_1US * _1, SBT_1US * 1, C_ABSOLUTE)

#elif defined(linux)
#include <bsd_glue.h>
#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>

#ifdef WITH_PTNETMAP_HOST

/* RX cycle without receive any packets */
#define PTN_RX_NOWORK_CYCLE	10
/* Limit Batch TX to half ring */
#define PTN_TX_BATCH_LIM(_n)	((_n >> 1))

/* XXX: avoid nm_*sync_prologue(). XXX-vin: this should go away,
 *      we should never trust the guest. */
#define PTN_AVOID_NM_PROLOGUE
//#define BUSY_WAIT

#define DEBUG  /* Enables communication debugging. */
#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif


#undef RATE
//#define RATE  /* Enables communication statistics. */
#ifdef RATE
#define IFRATE(x) x
struct rate_batch_info {
    uint64_t events;
    uint64_t zero_events;
    uint64_t slots;
};

struct rate_stats {
    unsigned long gtxk;     /* Guest --> Host Tx kicks. */
    unsigned long grxk;     /* Guest --> Host Rx kicks. */
    unsigned long htxk;     /* Host --> Guest Tx kicks. */
    unsigned long hrxk;     /* Host --> Guest Rx Kicks. */
    unsigned long btxwu;    /* Backend Tx wake-up. */
    unsigned long brxwu;    /* Backend Rx wake-up. */
    struct rate_batch_info bf_tx;
    struct rate_batch_info bf_rx;
};

struct rate_context {
    struct timer_list timer;
    struct rate_stats new;
    struct rate_stats old;
};

#define RATE_PERIOD  2
static void
rate_callback(unsigned long arg)
{
    struct rate_context * ctx = (struct rate_context *)arg;
    struct rate_stats cur = ctx->new;
    struct rate_batch_info *bf_tx = &cur.bf_tx;
    struct rate_batch_info *bf_rx = &cur.bf_rx;
    struct rate_batch_info *bf_tx_old = &ctx->old.bf_tx;
    struct rate_batch_info *bf_rx_old = &ctx->old.bf_rx;
    uint64_t tx_batch, rx_batch;
    unsigned long txpkts, rxpkts;
    int r;

    txpkts = bf_tx->slots - bf_tx_old->slots;
    rxpkts = bf_rx->slots - bf_rx_old->slots;

    tx_batch = ((bf_tx->events - bf_tx_old->events) > 0) ?
	       txpkts / (bf_tx->events - bf_tx_old->events): 0;
    rx_batch = ((bf_rx->events - bf_rx_old->events) > 0) ?
	       rxpkts / (bf_rx->events - bf_rx_old->events): 0;

    /* Fix-up gtxk and grxk estimate. */
    cur.gtxk -= cur.btxwu - ctx->old.btxwu;
    cur.grxk -= cur.brxwu - ctx->old.brxwu;

    printk("txpkts  = %lu Hz\n", txpkts/RATE_PERIOD);
    printk("gtxk    = %lu Hz\n", (cur.gtxk - ctx->old.gtxk)/RATE_PERIOD);
    printk("htxk    = %lu Hz\n", (cur.htxk - ctx->old.htxk)/RATE_PERIOD);
    printk("btxw    = %lu Hz\n", (cur.btxwu - ctx->old.btxwu)/RATE_PERIOD);
    printk("rxpkts  = %lu Hz\n", rxpkts/RATE_PERIOD);
    printk("grxk    = %lu Hz\n", (cur.grxk - ctx->old.grxk)/RATE_PERIOD);
    printk("hrxk    = %lu Hz\n", (cur.hrxk - ctx->old.hrxk)/RATE_PERIOD);
    printk("brxw    = %lu Hz\n", (cur.brxwu - ctx->old.brxwu)/RATE_PERIOD);
    printk("txbatch = %llu avg\n", tx_batch);
    printk("rxbatch = %llu avg\n", rx_batch);
    printk("\n");

    ctx->old = cur;
    r = mod_timer(&ctx->timer, jiffies +
            msecs_to_jiffies(RATE_PERIOD * 1000));
    if (unlikely(r))
        D("[ptnetmap] Error: mod_timer()\n");
}

static void
rate_batch_info_update(struct rate_batch_info *bf, uint32_t pre_tail,
		       uint32_t act_tail, uint32_t lim)
{
    int n_slots;

    n_slots = (int)act_tail - pre_tail;
    if (n_slots) {
        if (n_slots < 0)
            n_slots += lim;

        bf->events++;
        bf->slots += (uint64_t) n_slots;
    } else {
        bf->zero_events++;
    }
}

#else /* !RATE */
#define IFRATE(x)
#endif /* RATE */

struct ptnetmap_state {
    struct nm_kthread *ptk_tx, *ptk_rx;		/* kthreads pointers */

    struct ptnetmap_cfg config;                 /* rings configuration */
    struct paravirt_csb __user *csb;		/* shared page with the guest */

    bool stopped;

    struct netmap_pt_host_adapter *pth_na;	/* backend netmap adapter */

    IFRATE(struct rate_context rate_ctx;)
};

static inline void
ptnetmap_kring_dump(const char *title, const struct netmap_kring *kring)
{
    RD(1, "%s - name: %s hwcur: %d hwtail: %d rhead: %d rcur: %d \
    		    rtail: %d head: %d cur: %d tail: %d",
            title, kring->name, kring->nr_hwcur,
            kring->nr_hwtail, kring->rhead, kring->rcur, kring->rtail,
            kring->ring->head, kring->ring->cur, kring->ring->tail);
}

#if 0
static inline void
ptnetmap_ring_reinit(struct netmap_kring *kring, uint32_t g_head, uint32_t g_cur)
{
    struct netmap_ring *ring = kring->ring;

    //XXX: trust guest?
    ring->head = g_head;
    ring->cur = g_cur;
    ring->tail = NM_ACCESS_ONCE(kring->nr_hwtail);

    netmap_ring_reinit(kring);
    ptnetmap_kring_dump("kring reinit", kring);
}
#endif

/*
 * TX functions to set/get and to handle host/guest kick.
 */


/* Enable or disable TX kick to the host */
static inline void
ptnetmap_tx_set_hostkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, host_need_txkick, val);
}

/* Check if TX kick to the guest is enable or disable */
static inline uint32_t
ptnetmap_tx_get_guestkick(struct paravirt_csb __user *csb)
{
    uint32_t v;

    CSB_READ(csb, guest_need_txkick, v);

    return v;
}

/* Enable or disable TX kick to the guest */
static inline void
ptnetmap_tx_set_guestkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, guest_need_txkick, val);
}

/* Handle TX events: from the guest or from the backend */
static void
ptnetmap_tx_handler(void *data)
{
    struct ptnetmap_state *pts = (struct ptnetmap_state *) data;
    struct netmap_kring *kring;
    struct paravirt_csb __user *csb = NULL;
    struct pt_ring __user *csb_ring;
    struct netmap_ring g_ring;	/* guest ring pointer, copied from CSB */
    uint32_t num_slots;
    bool more_txspace = false;
    int batch;
    IFRATE(uint32_t pre_tail;)

    if (unlikely(!pts || !pts->pth_na)) {
        D("ERROR ptnetmap state %p, ptnetmap host adapter %p", pts,
	   pts ? pts->pth_na : NULL);
        return;
    }

    if (unlikely(pts->stopped)) {
        RD(1, "backend netmap is being stopped");
        return;
    }

    kring = &pts->pth_na->parent->tx_rings[0];

    if (unlikely(nm_kr_tryget(kring, 1, NULL))) {
        D("ERROR nm_kr_tryget()");
        return;
    }

    /* This is a guess, to be fixed in the rate callback. */
    IFRATE(pts->rate_ctx.new.gtxk++);

    csb = pts->csb;
    csb_ring = &csb->tx_ring; /* netmap TX kring pointers in CSB */
    num_slots = kring->nkr_num_slots;

    g_ring.head = kring->rhead;
    g_ring.cur = kring->rcur;

    /* Disable notifications. */
    ptnetmap_tx_set_hostkick(csb, 0);
    /* Copy the guest kring pointers from the CSB */
    ptnetmap_host_read_kring_csb(csb_ring, &g_ring, num_slots);

    for (;;) {
	/* If guest moves ahead too fast, let's cut the move so
	 * that we don't exceed our batch limit. */
        batch = g_ring.head - kring->nr_hwcur;
        if (batch < 0)
            batch += num_slots;

        if (batch > PTN_TX_BATCH_LIM(num_slots)) {
            uint32_t head_lim = kring->nr_hwcur + PTN_TX_BATCH_LIM(num_slots);

            if (head_lim >= num_slots)
                head_lim -= num_slots;
            ND(1, "batch: %d head: %d head_lim: %d", batch, g_ring.head,
						     head_lim);
            g_ring.head = head_lim;
	    batch = PTN_TX_BATCH_LIM(num_slots);
        }

        if (nm_kr_txspace(kring) <= (num_slots >> 1)) {
            g_ring.flags |= NAF_FORCE_RECLAIM;
        }
#ifndef PTN_AVOID_NM_PROLOGUE
        /* Netmap prologue */
        if (unlikely(nm_txsync_prologue(kring, &g_ring) >= num_slots)) {
            ptnetmap_ring_reinit(kring, g_ring.head, g_ring.cur);
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            break;
        }
#else /* PTN_AVOID_NM_PROLOGUE */
        kring->rhead = g_ring.head;
        kring->rcur = g_ring.cur;
#endif /* !PTN_AVOID_NM_PROLOGUE */
        if (unlikely(netmap_verbose & NM_VERB_TXSYNC)) {
            ptnetmap_kring_dump("pre txsync", kring);
	}

        IFRATE(pre_tail = kring->rtail);
        if (unlikely(kring->nm_sync(kring, g_ring.flags))) {
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            D("ERROR txsync");
            goto leave;
        }

        /*
         * Finalize
         * Copy host hwcur and hwtail into the CSB for the guest sync(), and
	 * do the nm_sync_finalize.
         */
        ptnetmap_host_write_kring_csb(csb_ring, kring->nr_hwcur,
				      kring->nr_hwtail);
        if (kring->rtail != kring->nr_hwtail) {
	    /* Some more room available in the parent adapter. */
	    kring->rtail = kring->nr_hwtail;
	    more_txspace = true;
        }

        IFRATE(rate_batch_info_update(&pts->rate_ctx.new.bf_tx, pre_tail,
				      kring->rtail, num_slots));

        if (unlikely(netmap_verbose & NM_VERB_TXSYNC)) {
            ptnetmap_kring_dump("post txsync", kring);
	}

#ifndef BUSY_WAIT
        /* Interrupt the guest if needed. */
        if (more_txspace && ptnetmap_tx_get_guestkick(csb)) {
            /* Disable guest kick to avoid sending unnecessary kicks */
            ptnetmap_tx_set_guestkick(csb, 0);
            nm_os_kthread_send_irq(pts->ptk_tx);
            IFRATE(pts->rate_ctx.new.htxk++);
            more_txspace = false;
        }
#endif
        /* Read CSB to see if there is more work to do. */
        ptnetmap_host_read_kring_csb(csb_ring, &g_ring, num_slots);
#ifndef BUSY_WAIT
        if (g_ring.head == kring->rhead) {
            /*
             * No more packets to transmit. We enable notifications and
             * go to sleep, waiting for a kick from the guest when new
             * new slots are ready for transmission.
             */
            usleep_range(1,1);
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            /* Doublecheck. */
            ptnetmap_host_read_kring_csb(csb_ring, &g_ring, num_slots);
            if (g_ring.head != kring->rhead) {
		/* We won the race condition, disable notification and
		 * redo the cycle again. */
		ptnetmap_tx_set_hostkick(csb, 0);
		continue;
	    }
	    break;
        }

	if (nm_kr_txempty(kring)) {
	    /* No more available TX slots. We stop waiting for a notification
	     * from the backend (netmap_tx_irq). */
            ND(1, "TX ring");
            break;
        }
#endif
        if (unlikely(pts->stopped)) {
            D("backend netmap is being stopped");
            break;
        }
    }

leave:
    nm_kr_put(kring);

    if (more_txspace && ptnetmap_tx_get_guestkick(csb)) {
        ptnetmap_tx_set_guestkick(csb, 0);
        nm_os_kthread_send_irq(pts->ptk_tx);
        IFRATE(pts->rate_ctx.new.htxk++);
    }
}


/*
 * RX functions to set/get and to handle host/guest kick.
 */


/* Enable or disable RX kick to the host */
static inline void
ptnetmap_rx_set_hostkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, host_need_rxkick, val);
}

/* Check if RX kick to the guest is enable or disable */
static inline uint32_t
ptnetmap_rx_get_guestkick(struct paravirt_csb __user *csb)
{
    uint32_t v;

    CSB_READ(csb, guest_need_rxkick, v);

    return v;
}

/* Enable or disable RX kick to the guest */
static inline void
ptnetmap_rx_set_guestkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, guest_need_rxkick, val);
}

/*
 * We need kicks from the guest when:
 *
 * - RX: tail == head - 1
 *       ring is full
 *       We need to wait that the guest gets some packets from the ring and
 *       then it notifies us.
 */
#ifndef BUSY_WAIT
static inline int
ptnetmap_kr_rxfull(struct netmap_kring *kring, uint32_t g_head)
{
    return (NM_ACCESS_ONCE(kring->nr_hwtail) == nm_prev(g_head,
    			    kring->nkr_num_slots - 1));
}
#endif /* !BUSY_WAIT */

/* Handle RX events: from the guest or from the backend */
static void
ptnetmap_rx_handler(void *data)
{
    struct ptnetmap_state *pts = (struct ptnetmap_state *) data;
    struct netmap_kring *kring;
    struct paravirt_csb __user *csb = NULL;
    struct pt_ring __user *csb_ring;
    struct netmap_ring g_ring;	/* guest ring pointer, copied from CSB */
    uint32_t nkr_num_slots;
    int cicle_nowork = 0;
    bool work = false;
    IFRATE(uint32_t pre_tail);

    if (unlikely(!pts || !pts->pth_na)) {
        D("ERROR ptnetmap state %p, ptnetmap host adapter %p", pts,
	  pts ? pts->pth_na : NULL);
        return;
    }

    if (unlikely(pts->stopped)) {
        RD(1, "backend netmap is being stopped");
        goto leave;
    }

    kring = &pts->pth_na->parent->rx_rings[0];

    if (unlikely(nm_kr_tryget(kring, 1, NULL))) {
        D("ERROR nm_kr_tryget()");
        goto leave;
    }

    /* This is a guess, to be fixed in the rate callback. */
    IFRATE(pts->rate_ctx.new.grxk++);

    csb = pts->csb;
    csb_ring = &csb->rx_ring; /* netmap RX kring pointers in CSB */
    nkr_num_slots = kring->nkr_num_slots;

    g_ring.head = kring->rhead;
    g_ring.cur = kring->rcur;

    /* Disable notifications. */
    ptnetmap_rx_set_hostkick(csb, 0);
    /* Copy the guest kring pointers from the CSB */
    ptnetmap_host_read_kring_csb(csb_ring, &g_ring, nkr_num_slots);

    for (;;) {
#ifndef PTN_AVOID_NM_PROLOGUE
        /* Netmap prologue */
        if (unlikely(nm_rxsync_prologue(kring, &g_ring) >= nkr_num_slots)) {
            ptnetmap_ring_reinit(kring, g_ring.head, g_ring.cur);
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            break;
        }
#else /* PTN_AVOID_NM_PROLOGUE */
        kring->rhead = g_ring.head;
        kring->rcur = g_ring.cur;
#endif /* !PTN_AVOID_NM_PROLOGUE */

        if (unlikely(netmap_verbose & NM_VERB_RXSYNC))
            ptnetmap_kring_dump("pre rxsync", kring);

        IFRATE(pre_tail = kring->rtail);

        if (likely(kring->nm_sync(kring, g_ring.flags) == 0)) {
            /*
             * Finalize
             * Copy host hwcur and hwtail into the CSB for the guest sync()
             */
            ptnetmap_host_write_kring_csb(csb_ring, kring->nr_hwcur,
            		    NM_ACCESS_ONCE(kring->nr_hwtail));
            if (kring->rtail != NM_ACCESS_ONCE(kring->nr_hwtail)) {
                kring->rtail = NM_ACCESS_ONCE(kring->nr_hwtail);
                work = true;
                cicle_nowork = 0;
            } else {
                cicle_nowork++;
            }
        } else {
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            D("ERROR rxsync()");
            goto leave_kr_put;
        }

        IFRATE(rate_batch_info_update(&pts->rate_ctx.new.bf_rx, pre_tail,
	                              kring->rtail, kring->nkr_num_slots));

        if (unlikely(netmap_verbose & NM_VERB_RXSYNC))
            ptnetmap_kring_dump("post rxsync", kring);

#ifndef BUSY_WAIT
        /* Send kick to the guest if it needs them */
        if (work && ptnetmap_rx_get_guestkick(csb)) {
            /* Disable guest kick to avoid sending unnecessary kicks */
            ptnetmap_rx_set_guestkick(csb, 0);
            nm_os_kthread_send_irq(pts->ptk_rx);
            IFRATE(pts->rate_ctx.new.hrxk++);
            work = false;
        }
#endif
        /* We read the CSB before deciding to continue or stop. */
        ptnetmap_host_read_kring_csb(csb_ring, &g_ring, nkr_num_slots);
#ifndef BUSY_WAIT
        /*
         * Ring full. No space to receive. We enable notification and
         * go to sleep. We need a notification when the guest has
         * new free slots.
         */
        if (ptnetmap_kr_rxfull(kring, g_ring.head)) {
            usleep_range(1,1);
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            /* Doublecheck. */
            ptnetmap_host_read_kring_csb(csb_ring, &g_ring, nkr_num_slots);
            /* If there are new free slots, disable notifications and redo new sync() */
            if (!ptnetmap_kr_rxfull(kring, g_ring.head)) {
                ptnetmap_rx_set_hostkick(csb, 0);
                continue;
            } else
                break;
        }

        /*
         * Ring empty. We stop without reenable notification
         * because we await the BE.
         */
        if (unlikely(NM_ACCESS_ONCE(kring->nr_hwtail) == kring->rhead
                    || cicle_nowork >= PTN_RX_NOWORK_CYCLE)) {
            ND(1, "nr_hwtail: %d rhead: %d cicle_nowork: %d",
            	NM_ACCESS_ONCE(kring->nr_hwtail), kring->rhead, cicle_nowork);
            break;
        }
#endif
        if (unlikely(pts->stopped)) {
            D("backend netmap is being stopped");
            break;
        }
    }

leave_kr_put:
    nm_kr_put(kring);

leave:
    /* Send kick to the guest if it needs them */
    if (csb && work && ptnetmap_rx_get_guestkick(csb)) {
        ptnetmap_rx_set_guestkick(csb, 0);
        nm_os_kthread_send_irq(pts->ptk_rx);
        IFRATE(pts->rate_ctx.new.hrxk++);
    }
}

#ifdef DEBUG
static void
ptnetmap_print_configuration(struct ptnetmap_state *pts)
{
    struct ptnetmap_cfg *cfg = &pts->config;

    D("[PTN] configuration:");
    D("TX: iofd=%llu, irqfd=%llu",
            (unsigned long long) cfg->tx_ring.ioeventfd,
            (unsigned long long)cfg->tx_ring.irqfd);
    D("RX: iofd=%llu, irqfd=%llu",
            (unsigned long long) cfg->rx_ring.ioeventfd,
            (unsigned long long) cfg->rx_ring.irqfd);
    D("CSB: csb_addr=%p", cfg->csb);

}
#endif

/* Copy actual state of the host ring into the CSB for the guest init */
static int
ptnetmap_kring_snapshot(struct netmap_kring *kring, struct pt_ring __user *ptr)
{
    if(CSB_WRITE(ptr, head, kring->rhead))
        goto err;
    if(CSB_WRITE(ptr, cur, kring->rcur))
        goto err;

    if(CSB_WRITE(ptr, hwcur, kring->nr_hwcur))
        goto err;
    if(CSB_WRITE(ptr, hwtail, NM_ACCESS_ONCE(kring->nr_hwtail)))
        goto err;

    DBG(ptnetmap_kring_dump("ptnetmap_kring_snapshot", kring);)

    return 0;
err:
    return EFAULT;
}

static int
ptnetmap_krings_snapshot(struct ptnetmap_state *pts,
		struct netmap_pt_host_adapter *pth_na)
{
    struct netmap_kring *kring;
    int error = 0;

    kring = &pth_na->parent->tx_rings[0];
    if((error = ptnetmap_kring_snapshot(kring, &pts->csb->tx_ring)))
        goto err;

    kring = &pth_na->parent->rx_rings[0];
    error = ptnetmap_kring_snapshot(kring, &pts->csb->rx_ring);

err:
    return error;
}

/*
 * Functions to create, start and stop the kthreads
 */

static int
ptnetmap_create_kthreads(struct ptnetmap_state *pts)
{
    struct nm_kthread_cfg nmk_cfg;

    nmk_cfg.worker_private = pts;

    /* TX kthread */
    nmk_cfg.type = PTK_TX;
    nmk_cfg.event = pts->config.tx_ring;
    nmk_cfg.worker_fn = ptnetmap_tx_handler;
    nmk_cfg.attach_user = 1; /* attach kthread to user process */
    pts->ptk_tx = nm_os_kthread_create(&nmk_cfg);
    if (pts->ptk_tx == NULL) {
        goto err;
    }

    /* RX kthread */
    nmk_cfg.type = PTK_RX;
    nmk_cfg.event = pts->config.rx_ring;
    nmk_cfg.worker_fn = ptnetmap_rx_handler;
    nmk_cfg.attach_user = 1; /* attach kthread to user process */
    pts->ptk_rx = nm_os_kthread_create(&nmk_cfg);
    if (pts->ptk_rx == NULL) {
        goto err;
    }

    return 0;
err:
    if (pts->ptk_tx) {
        nm_os_kthread_delete(pts->ptk_tx);
        pts->ptk_tx = NULL;
    }
    return EFAULT;
}

static int
ptnetmap_start_kthreads(struct ptnetmap_state *pts)
{
    int error;

    if (!pts) {
        D("BUG pts is NULL");
        return EFAULT;
    }

    pts->stopped = false;

    /* TX kthread */
    //nm_os_kthread_set_affinity(pts->ptk_tx, 2);
    error = nm_os_kthread_start(pts->ptk_tx);
    if (error) {
        return error;
    }
    /* RX kthread */
    //nm_os_kthread_set_affinity(pts->ptk_tx, 3);
    error = nm_os_kthread_start(pts->ptk_rx);
    if (error) {
        nm_os_kthread_stop(pts->ptk_tx);
        return error;
    }

    return 0;
}

static void
ptnetmap_stop_kthreads(struct ptnetmap_state *pts)
{
    if (!pts) {
	/* Nothing to do. */
        return;
    }

    pts->stopped = true;

    /* TX kthread */
    nm_os_kthread_stop(pts->ptk_tx);
    /* RX kthread */
    nm_os_kthread_stop(pts->ptk_rx);
}

static int nm_unused_notify(struct netmap_kring *, int);
static int nm_pt_host_notify(struct netmap_kring *, int);

/* Create ptnetmap state and switch parent adapter to ptnetmap mode. */
static int
ptnetmap_create(struct netmap_pt_host_adapter *pth_na,
		struct ptnetmap_cfg *cfg)
{
    struct ptnetmap_state *pts;
    int ret, i;
    unsigned ft_mask = (PTNETMAP_CFG_FEAT_CSB | PTNETMAP_CFG_FEAT_EVENTFD);

    /* Check if ptnetmap state is already there. */
    if (pth_na->ptn_state) {
        D("ERROR adapter %p already in ptnetmap mode", pth_na->parent);
        return EINVAL;
    }

    if ((cfg->features & ft_mask) != ft_mask) {
        D("ERROR ptnetmap_cfg(%x) does not contain CSB and EVENTFD",
	  cfg->features);
        return EINVAL;
    }

    pts = malloc(sizeof(*pts), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!pts)
        return ENOMEM;

    pts->stopped = true;

    /* Store the ptnetmap configuration provided by the hypervisor. */
    memcpy(&pts->config, cfg, sizeof(struct ptnetmap_cfg));
    pts->csb = pts->config.csb;
    DBG(ptnetmap_print_configuration(pts);)

    /* Create kthreads */
    if ((ret = ptnetmap_create_kthreads(pts))) {
        D("ERROR ptnetmap_create_kthreads()");
        goto err;
    }
    /* Copy krings state into the CSB for the guest initialization */
    if ((ret = ptnetmap_krings_snapshot(pts, pth_na))) {
        D("ERROR ptnetmap_krings_snapshot()");
        goto err;
    }

    pth_na->ptn_state = pts;
    pts->pth_na = pth_na;

    /* Overwrite parent nm_notify krings callback. */
    pth_na->parent->na_private = pth_na;
    pth_na->parent_nm_notify = pth_na->parent->nm_notify;
    pth_na->parent->nm_notify = nm_unused_notify;

    for (i = 0; i < pth_na->parent->num_rx_rings; i++) {
        pth_na->parent->rx_rings[i].save_notify =
        	pth_na->parent->rx_rings[i].nm_notify;
        pth_na->parent->rx_rings[i].nm_notify = nm_pt_host_notify;
    }
    for (i = 0; i < pth_na->parent->num_tx_rings; i++) {
        pth_na->parent->tx_rings[i].save_notify =
        	pth_na->parent->tx_rings[i].nm_notify;
        pth_na->parent->tx_rings[i].nm_notify = nm_pt_host_notify;
    }

#ifdef RATE
    memset(&pts->rate_ctx, 0, sizeof(pts->rate_ctx));
    setup_timer(&pts->rate_ctx.timer, &rate_callback,
            (unsigned long)&pts->rate_ctx);
    if (mod_timer(&pts->rate_ctx.timer, jiffies + msecs_to_jiffies(1500)))
        D("[ptn] Error: mod_timer()\n");
#endif

    DBG(D("[%s] ptnetmap configuration DONE", pth_na->up.name));

    return 0;

err:
    free(pts, M_DEVBUF);
    return ret;
}

/* Switch parent adapter back to normal mode and destroy
 * ptnetmap state. */
static void
ptnetmap_delete(struct netmap_pt_host_adapter *pth_na)
{
    struct ptnetmap_state *pts = pth_na->ptn_state;
    int i;

    if (!pts) {
	/* Nothing to do. */
        return;
    }

    /* restore parent adapter callbacks */
    pth_na->parent->nm_notify = pth_na->parent_nm_notify;
    pth_na->parent->na_private = NULL;

    for (i = 0; i < pth_na->parent->num_rx_rings; i++) {
        pth_na->parent->rx_rings[i].nm_notify =
        	pth_na->parent->rx_rings[i].save_notify;
        pth_na->parent->rx_rings[i].save_notify = NULL;
    }
    for (i = 0; i < pth_na->parent->num_tx_rings; i++) {
        pth_na->parent->tx_rings[i].nm_notify =
        	pth_na->parent->tx_rings[i].save_notify;
        pth_na->parent->tx_rings[i].save_notify = NULL;
    }

    /* delete kthreads */
    nm_os_kthread_delete(pts->ptk_tx);
    nm_os_kthread_delete(pts->ptk_rx);

    IFRATE(del_timer(&pts->rate_ctx.timer));

    free(pts, M_DEVBUF);

    pth_na->ptn_state = NULL;

    DBG(D("[%s] ptnetmap deleted", pth_na->up.name));
}

/*
 * Called by netmap_ioctl().
 * Operation is indicated in nmr->nr_cmd.
 *
 * Called without NMG_LOCK.
 */
int
ptnetmap_ctl(struct nmreq *nmr, struct netmap_adapter *na)
{
    struct netmap_pt_host_adapter *pth_na;
    struct ptnetmap_cfg cfg;
    char *name;
    int cmd, error = 0;

    name = nmr->nr_name;
    cmd = nmr->nr_cmd;

    DBG(D("name: %s", name);)

    if (!nm_ptnetmap_host_on(na)) {
        D("ERROR Netmap adapter %p is not a ptnetmap host adapter", na);
        error = ENXIO;
        goto done;
    }
    pth_na = (struct netmap_pt_host_adapter *)na;

    NMG_LOCK();
    switch (cmd) {
    case NETMAP_PT_HOST_CREATE:
	/* Read hypervisor configuration from userspace. */
        error = ptnetmap_read_cfg(nmr, &cfg);
        if (error)
            break;
        /* Create ptnetmap state (kthreads, ...) and switch parent
	 * adapter to ptnetmap mode. */
        error = ptnetmap_create(pth_na, &cfg);
        if (error)
            break;
        /* start kthreads */
        error = ptnetmap_start_kthreads(pth_na->ptn_state);
        if (error)
            ptnetmap_delete(pth_na);
        break;

    case NETMAP_PT_HOST_DELETE:
        /* stop kthreads */
        ptnetmap_stop_kthreads(pth_na->ptn_state);
        /* Switch parent adapter back to normal mode and destroy
	 * ptnetmap state (kthreads, ...). */
        ptnetmap_delete(pth_na);
        break;

    default:
        D("ERROR invalid cmd (nmr->nr_cmd) (0x%x)", cmd);
        error = EINVAL;
        break;
    }
    NMG_UNLOCK();

done:
    return error;
}

/* nm_notify callbacks for ptnetmap */
static int
nm_pt_host_notify(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct netmap_pt_host_adapter *pth_na =
		(struct netmap_pt_host_adapter *)na->na_private;
	struct ptnetmap_state *pts;

	if (unlikely(!pth_na)) {
		return 0;
	}

	pts = pth_na->ptn_state;
	if (unlikely(!pts)) {
		return 0;
	}

	/* Notify kthreads (wake up if needed) */
	if (kring->tx == NR_TX) {
		ND(1, "TX backend irq");
		nm_os_kthread_wakeup_worker(pts->ptk_tx);
		IFRATE(pts->rate_ctx.new.btxwu++);

	} else {
		ND(1, "RX backend irq");
		nm_os_kthread_wakeup_worker(pts->ptk_rx);
		IFRATE(pts->rate_ctx.new.brxwu++);
	}

	return 0;
}

static int
nm_unused_notify(struct netmap_kring *kring, int flags)
{
    D("BUG this should never be called");
    return -1;
}

/* nm_config callback for bwrap */
static int
nm_pt_host_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
        u_int *rxr, u_int *rxd)
{
    struct netmap_pt_host_adapter *pth_na =
        (struct netmap_pt_host_adapter *)na;
    struct netmap_adapter *parent = pth_na->parent;
    int error;

    //XXX: maybe call parent->nm_config is better

    /* forward the request */
    error = netmap_update_config(parent);

    *rxr = na->num_rx_rings = parent->num_rx_rings;
    *txr = na->num_tx_rings = parent->num_tx_rings;
    *txd = na->num_tx_desc = parent->num_tx_desc;
    *rxd = na->num_rx_desc = parent->num_rx_desc;

    DBG(D("rxr: %d txr: %d txd: %d rxd: %d", *rxr, *txr, *txd, *rxd);)

    return error;
}

/* nm_krings_create callback for ptnetmap */
static int
nm_pt_host_krings_create(struct netmap_adapter *na)
{
    struct netmap_pt_host_adapter *pth_na =
        (struct netmap_pt_host_adapter *)na;
    struct netmap_adapter *parent = pth_na->parent;
    int error;

    DBG(D("%s", pth_na->up.name);)

    /* create the parent krings */
    error = parent->nm_krings_create(parent);
    if (error) {
        return error;
    }

    /* A ptnetmap host adapter points the very same krings
     * as its parent adapter. However, these pointers are
     * currently never used. */
    na->tx_rings = parent->tx_rings;
    na->rx_rings = parent->rx_rings;
    na->tailroom = parent->tailroom; //XXX

    return 0;
}

/* nm_krings_delete callback for ptnetmap */
static void
nm_pt_host_krings_delete(struct netmap_adapter *na)
{
    struct netmap_pt_host_adapter *pth_na =
        (struct netmap_pt_host_adapter *)na;
    struct netmap_adapter *parent = pth_na->parent;

    DBG(D("%s", pth_na->up.name);)

    parent->nm_krings_delete(parent);

    na->tx_rings = na->rx_rings = na->tailroom = NULL;
}

/* nm_register callback */
static int
nm_pt_host_register(struct netmap_adapter *na, int onoff)
{
    struct netmap_pt_host_adapter *pth_na =
        (struct netmap_pt_host_adapter *)na;
    struct netmap_adapter *parent = pth_na->parent;
    int error;
    DBG(D("%s onoff %d", pth_na->up.name, onoff);)

    if (onoff) {
        /* netmap_do_regif has been called on the ptnetmap na.
         * We need to pass the information about the
         * memory allocator to the parent before
         * putting it in netmap mode
         */
        parent->na_lut = na->na_lut;
    }

    /* forward the request to the parent */
    error = parent->nm_register(parent, onoff);
    if (error)
        return error;


    if (onoff) {
        na->na_flags |= NAF_NETMAP_ON | NAF_PTNETMAP_HOST;
    } else {
        ptnetmap_delete(pth_na);
        na->na_flags &= ~(NAF_NETMAP_ON | NAF_PTNETMAP_HOST);
    }

    return 0;
}

/* nm_dtor callback */
static void
nm_pt_host_dtor(struct netmap_adapter *na)
{
    struct netmap_pt_host_adapter *pth_na =
        (struct netmap_pt_host_adapter *)na;
    struct netmap_adapter *parent = pth_na->parent;

    DBG(D("%s", pth_na->up.name);)

    parent->na_flags &= ~NAF_BUSY;

    netmap_adapter_put(pth_na->parent);
    pth_na->parent = NULL;
}

/* check if nmr is a request for a ptnetmap adapter that we can satisfy */
int
netmap_get_pt_host_na(struct nmreq *nmr, struct netmap_adapter **na, int create)
{
    struct nmreq parent_nmr;
    struct netmap_adapter *parent; /* target adapter */
    struct netmap_pt_host_adapter *pth_na;
    struct ifnet *ifp = NULL;
    int error;

    /* Check if it is a request for a ptnetmap adapter */
    if ((nmr->nr_flags & (NR_PTNETMAP_HOST)) == 0) {
        return 0;
    }

    D("Requesting a ptnetmap host adapter");

    pth_na = malloc(sizeof(*pth_na), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (pth_na == NULL) {
        D("ERROR malloc");
        return ENOMEM;
    }

    /* first, try to find the adapter that we want to passthrough
     * We use the same nmr, after we have turned off the ptnetmap flag.
     * In this way we can potentially passthrough everything netmap understands.
     */
    memcpy(&parent_nmr, nmr, sizeof(parent_nmr));
    parent_nmr.nr_flags &= ~(NR_PTNETMAP_HOST);
    error = netmap_get_na(&parent_nmr, &parent, &ifp, create);
    if (error) {
        D("parent lookup failed: %d", error);
        goto put_out_noputparent;
    }
    DBG(D("found parent: %s", parent->name);)

    /* make sure the interface is not already in use */
    if (NETMAP_OWNED_BY_ANY(parent)) {
        D("NIC %s busy, cannot ptnetmap", parent->name);
        error = EBUSY;
        goto put_out;
    }

    pth_na->parent = parent;

    /* Follow netmap_attach()-like operations for the host
     * ptnetmap adapter. */

    //XXX pth_na->up.na_flags = parent->na_flags;
    pth_na->up.num_rx_rings = parent->num_rx_rings;
    pth_na->up.num_tx_rings = parent->num_tx_rings;
    pth_na->up.num_tx_desc = parent->num_tx_desc;
    pth_na->up.num_rx_desc = parent->num_rx_desc;

    pth_na->up.nm_dtor = nm_pt_host_dtor;
    pth_na->up.nm_register = nm_pt_host_register;

    /* Reuse parent's adapter txsync and rxsync methods. */
    pth_na->up.nm_txsync = parent->nm_txsync;
    pth_na->up.nm_rxsync = parent->nm_rxsync;

    pth_na->up.nm_krings_create = nm_pt_host_krings_create;
    pth_na->up.nm_krings_delete = nm_pt_host_krings_delete;
    pth_na->up.nm_config = nm_pt_host_config;

    /* Set the notify method only or convenience, it will never
     * be used, since - differently from default krings_create - we
     * ptnetmap krings_create callback inits kring->nm_notify
     * directly. */
    pth_na->up.nm_notify = nm_unused_notify;

    pth_na->up.nm_mem = parent->nm_mem;
    error = netmap_attach_common(&pth_na->up);
    if (error) {
        D("ERROR netmap_attach_common()");
        goto put_out;
    }

    *na = &pth_na->up;
    netmap_adapter_get(*na);

    /* set parent busy, because attached for ptnetmap */
    parent->na_flags |= NAF_BUSY;

    strncpy(pth_na->up.name, parent->name, sizeof(pth_na->up.name));
    strcat(pth_na->up.name, "-PTN");

    DBG(D("%s ptnetmap request DONE", pth_na->up.name);)

    /* drop the reference to the ifp, if any */
    if (ifp)
        if_rele(ifp);

    return 0;

put_out:
    netmap_adapter_put(parent);
    if (ifp)
	if_rele(ifp);
put_out_noputparent:
    free(pth_na, M_DEVBUF);
    return error;
}
#endif /* WITH_PTNETMAP_HOST */

#ifdef WITH_PTNETMAP_GUEST
/*
 * GUEST ptnetmap generic txsync()/rxsync() used in e1000/virtio-net device
 * driver notify is set when we need to send notification to the host
 * (driver-specific)
 */

/*
 * Reconcile host and guest views of the transmit ring.
 *
 * Guest user wants to transmit packets up to the one before ring->head,
 * and guest kernel knows csb->tx_ring.hwcur is the first packet unsent
 * by the host kernel.
 *
 * We push out as many packets as possible, and possibly
 * reclaim buffers from previously completed transmission.
 *
 * Notifications from the host are enabled only if the user guest would
 * block (no space in the ring).
 */
bool
netmap_pt_guest_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct netmap_pt_guest_adapter *ptna =
		(struct netmap_pt_guest_adapter *)na;
	struct paravirt_csb *csb = ptna->csb;
	bool notify = false;

	/* Disable notifications */
	csb->guest_need_txkick = 0;

	/*
	 * First part: tell the host (updating the CSB) to process the new
	 * packets.
	 */
	kring->nr_hwcur = csb->tx_ring.hwcur;
	ptnetmap_guest_write_kring_csb(&csb->tx_ring, kring->rcur, kring->rhead);

        /* Ask for a kick from a guest to the host if needed. */
	if ((kring->rhead != kring->nr_hwcur &&
		NM_ACCESS_ONCE(csb->host_need_txkick)) ||
			(flags & NAF_FORCE_RECLAIM)) {
		csb->tx_ring.sync_flags = flags;
		notify = true;
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (nm_kr_txempty(kring) || (flags & NAF_FORCE_RECLAIM)) {
                ptnetmap_guest_read_kring_csb(&csb->tx_ring, &kring->nr_hwcur,
				&kring->nr_hwtail, kring->nkr_num_slots);
	}

        /*
         * No more room in the ring for new transmissions. The user thread will
	 * go to sleep and we need to be notified by the host when more free
	 * space is available.
         */
	if (nm_kr_txempty(kring)) {
		/* Reenable notifications. */
		csb->guest_need_txkick = 1;
                /* Double check */
                ptnetmap_guest_read_kring_csb(&csb->tx_ring, &kring->nr_hwcur,
                		&kring->nr_hwtail, kring->nkr_num_slots);
                /* If there is new free space, disable notifications */
		if (unlikely(!nm_kr_txempty(kring))) {
			csb->guest_need_txkick = 0;
		}
	}

	ND(1,"TX - CSB: head:%u cur:%u hwtail:%u - KRING: head:%u cur:%u tail: %u",
			csb->tx_ring.head, csb->tx_ring.cur, csb->tx_ring.hwtail,
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
netmap_pt_guest_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct netmap_pt_guest_adapter *ptna =
		(struct netmap_pt_guest_adapter *)na;
	struct paravirt_csb *csb = ptna->csb;

	uint32_t h_hwcur = kring->nr_hwcur, h_hwtail = kring->nr_hwtail;
	bool notify = false;

        /* Disable notifications */
	csb->guest_need_rxkick = 0;

	/* Fetch the hwcur/hwtail known from the host. */
        ptnetmap_guest_read_kring_csb(&csb->rx_ring, &h_hwcur, &h_hwtail,
				      kring->nkr_num_slots);

	/*
	 * First part: import newly received packets, by updating the kring
	 * hwtail to the hwtail known from the host (read from the CSB)
	 */
	kring->nr_hwtail = h_hwtail;
	kring->nr_kflags &= ~NKR_PENDINTR;

	/*
	 * Second part: tell the host about the slots that guest user has
	 * released, by updating cur and head in the CSB.
	 */
	kring->nr_hwcur = h_hwcur;
	if (kring->rhead != kring->nr_hwcur) {
		ptnetmap_guest_write_kring_csb(&csb->rx_ring, kring->rcur,
					       kring->rhead);
                /* Ask for a kick from the guest to the host if needed. */
		if (NM_ACCESS_ONCE(csb->host_need_rxkick)) {
			csb->rx_ring.sync_flags = flags;
			notify = true;
		}
	}

        /*
         * No more completed RX slots. The user thread will go to sleep and
	 * we need to be notified by the host when more RX slots have been
	 * completed.
         */
	if (nm_kr_rxempty(kring)) {
		/* Reenable notifications. */
                csb->guest_need_rxkick = 1;
                /* Double check */
                ptnetmap_guest_read_kring_csb(&csb->rx_ring, &kring->nr_hwcur,
					      &kring->nr_hwtail, kring->nkr_num_slots);
                /* If there are new slots, disable notifications. */
		if (!nm_kr_rxempty(kring)) {
                        csb->guest_need_rxkick = 0;
                }
        }

	ND("RX - CSB: head:%u cur:%u hwtail:%u - KRING: head:%u cur:%u",
			csb->rx_ring.head, csb->rx_ring.cur, csb->rx_ring.hwtail,
			kring->rhead, kring->rcur);

	return notify;
}
#endif /* WITH_PTNETMAP_GUEST */
