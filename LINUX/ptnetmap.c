/*
 * common headers
 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/paravirt.h>

#include "ptnetmap.h"

#ifdef WITH_PASSTHROUGH

#define PTN_RX_NOWORK_CYCLE   10                               /* RX cycle without receive any packets */
#define PTN_TX_BATCH_LIM      ((kring->nkr_num_slots >> 1))     /* Limit Batch TX to half ring */

//#define DEBUG  /* Enables communication debugging. */
#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif


#undef RATE
//#define RATE  /* Enables communication statistics. */
#ifdef RATE
#define IFRATE(x) x
struct batch_info {
    uint64_t events;
    uint64_t zero_events;
    uint64_t slots;
};


static void batch_info_update(struct batch_info *bf, uint32_t pre_tail, uint32_t act_tail, uint32_t lim)
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

struct rate_stats {
    unsigned long gtxk;     /* Guest --> Host Tx kicks. */
    unsigned long grxk;     /* Guest --> Host Rx kicks. */
    unsigned long htxk;     /* Host --> Guest Tx kicks. */
    unsigned long hrxk;     /* Host --> Guest Rx Kicks. */
    unsigned long btxwu;    /* Backend Tx wake-up. */
    unsigned long brxwu;    /* Backend Rx wake-up. */
    unsigned long txpkts;   /* Transmitted packets. */
    unsigned long rxpkts;   /* Received packets. */
    unsigned long txfl;     /* TX flushes requests. */
    struct batch_info bf_tx;
    struct batch_info bf_rx;
};

struct rate_context {
    struct timer_list timer;
    struct rate_stats new;
    struct rate_stats old;
};

#define RATE_PERIOD  2
static void rate_callback(unsigned long arg)
{
    struct rate_context * ctx = (struct rate_context *)arg;
    struct rate_stats cur = ctx->new;
    struct batch_info *bf_tx = &cur.bf_tx;
    struct batch_info *bf_rx = &cur.bf_rx;
    struct batch_info *bf_tx_old = &ctx->old.bf_tx;
    struct batch_info *bf_rx_old = &ctx->old.bf_rx;
    uint64_t tx_batch, rx_batch;
    int r;

    tx_batch = ((bf_tx->events - bf_tx_old->events) > 0) ?
        (bf_tx->slots - bf_tx_old->slots) / (bf_tx->events - bf_tx_old->events): 0;
    rx_batch = ((bf_rx->events - bf_rx_old->events) > 0) ?
        (bf_rx->slots - bf_rx_old->slots) / (bf_rx->events - bf_rx_old->events): 0;

    printk("txp  = %lu Hz\n", (cur.txpkts - ctx->old.txpkts)/RATE_PERIOD);
    printk("gtxk = %lu Hz\n", (cur.gtxk - ctx->old.gtxk)/RATE_PERIOD);
    printk("htxk = %lu Hz\n", (cur.htxk - ctx->old.htxk)/RATE_PERIOD);
    printk("btxw = %lu Hz\n", (cur.btxwu - ctx->old.btxwu)/RATE_PERIOD);
    printk("rxp  = %lu Hz\n", (cur.rxpkts - ctx->old.rxpkts)/RATE_PERIOD);
    printk("grxk = %lu Hz\n", (cur.grxk - ctx->old.grxk)/RATE_PERIOD);
    printk("hrxk = %lu Hz\n", (cur.hrxk - ctx->old.hrxk)/RATE_PERIOD);
    printk("brxw = %lu Hz\n", (cur.brxwu - ctx->old.brxwu)/RATE_PERIOD);
    printk("txfl = %lu Hz\n", (cur.txfl - ctx->old.txfl)/RATE_PERIOD);
    printk("tx_batch = %llu avg\n", tx_batch);
    printk("rx_batch = %llu avg\n", rx_batch);
    printk("\n");

    ctx->old = cur;
    r = mod_timer(&ctx->timer, jiffies +
            msecs_to_jiffies(RATE_PERIOD * 1000));
    if (unlikely(r))
        D("[ptnetmap] Error: mod_timer()\n");
}

#else /* !RATE */
#define IFRATE(x)
#endif /* RATE */

struct ptnetmap_state {
    struct ptn_kthread *ptk_tx, *ptk_rx;

    struct ptn_cfg config;
    bool configured;
    struct paravirt_csb __user *csb;
    bool stopped;

    struct netmap_passthrough_adapter *pt_na;

    IFRATE(struct rate_context rate_ctx);
};

#define CSB_READ(csb, field, r) (get_user(r, &csb->field))
#define CSB_WRITE(csb, field, v) (put_user(v, &csb->field))

static inline void
ptnetmap_read_kring_csb(struct pt_ring __user *ptr, uint32_t *g_head,
        uint32_t *g_cur, uint32_t *g_flags)
{
    CSB_READ(ptr, head, *g_head);

    smp_mb();

    CSB_READ(ptr, cur, *g_cur);
    CSB_READ(ptr, sync_flags, *g_flags);
}

static inline void
ptnetmap_write_kring_csb(struct pt_ring __user *ptr, uint32_t hwcur,
        uint32_t hwtail)
{
    CSB_WRITE(ptr, hwcur, hwcur);

    smp_mb();

    CSB_WRITE(ptr, hwtail, hwtail);
}

static inline void
ptnetmap_kring_dump(const char *title, const struct netmap_kring *kring)
{
    D("%s - name: %s hwcur: %d hwtail: %d rhead: %d rcur: %d rtail: %d head: %d cur: %d tail: %d",
            title, kring->name, kring->nr_hwcur,
            kring->nr_hwtail, kring->rhead, kring->rcur, kring->rtail,
            kring->ring->head, kring->ring->cur, kring->ring->tail);
}

static inline void
ptnetmap_ring_reinit(struct netmap_kring *kring, uint32_t g_head, uint32_t g_cur)
{
    struct netmap_ring *ring = kring->ring;

    // XXX trust guest?
    ring->head = g_head;
    ring->cur = g_cur;
    ring->tail = kring->nr_hwtail;

    netmap_ring_reinit(kring);
    ptnetmap_kring_dump("kring reinit", kring);
}

static inline void ptnetmap_tx_set_hostkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, host_need_txkick, val);
}

static inline uint32_t ptnetmap_tx_get_guestkick(struct paravirt_csb __user *csb)
{
    uint32_t v;

    CSB_READ(csb, guest_need_txkick, v);

    return v;
}
static inline void ptnetmap_tx_set_guestkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, guest_need_txkick, val);
}

/*
 * Handle tx events: from the guest or from the backend
 */
static void ptnetmap_tx_handler(void *data)
{
    struct ptnetmap_state *pts = (struct ptnetmap_state *) data;
    struct netmap_kring *kring;
    struct paravirt_csb __user *csb;
    struct pt_ring __user *csb_ring;
    uint32_t g_cur = 0, g_head = 0, g_flags = 0; /* guest variables; init for compiler */
    bool work = false;
    int batch;
    IFRATE(uint32_t pre_tail;)

    if (unlikely(!pts)) {
        D("backend netmap is not configured");
        return;
    }

    if (unlikely(!pts->pt_na || pts->stopped || !pts->configured)) {
        D("backend netmap is not configured");
        goto leave;
    }

    kring = &pts->pt_na->parent->tx_rings[0];

    if (nm_kr_tryget(kring)) {
        D("error nm_kr_tryget()");
        goto leave_kr_put;
    }

    csb = pts->csb;
    csb_ring = &csb->tx_ring; /* netmap TX pointers in CSB */

    /* Disable notifications. */
    ptnetmap_tx_set_hostkick(csb, 0);

    ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);

    for (;;) {
#ifdef PTN_TX_BATCH_LIM
        batch = g_head - kring->nr_hwcur;

        if (batch < 0)
            batch += kring->nkr_num_slots;

        if (batch > PTN_TX_BATCH_LIM) {
            uint32_t new_head = kring->nr_hwcur + PTN_TX_BATCH_LIM;
            if (new_head >= kring->nkr_num_slots)
                new_head -= kring->nkr_num_slots;
            ND(1, "batch: %d old_head: %d new_head: %d", batch, g_head, new_head);
            g_head = new_head;
        }
#endif /* PTN_TX_BATCH_LIM */

        if (nm_kr_txspace(kring) <= (kring->nkr_num_slots >> 1)) {
            g_flags |= NAF_FORCE_RECLAIM;
        }

        if (nm_txsync_prologue(kring, g_head, g_cur, NULL)
                >= kring->nkr_num_slots) {
            ptnetmap_ring_reinit(kring, g_head, g_cur);
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            break;
        }

        if (netmap_verbose & NM_VERB_TXSYNC)
            ptnetmap_kring_dump("pre txsync", kring);

        IFRATE(pre_tail = kring->rtail;)

        if (likely(kring->nm_sync(kring, g_flags) == 0)) {
            /* finalize */
            ptnetmap_write_kring_csb(csb_ring, kring->nr_hwcur, kring->nr_hwtail);
            if (kring->rtail != kring->nr_hwtail) {
                kring->rtail = kring->nr_hwtail;
                work = true;
            }
        } else {
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            D("nm_sync error");
            goto leave_kr_put;
        }

        IFRATE(batch_info_update(&pts->rate_ctx.new.bf_tx, pre_tail, kring->rtail, kring->nkr_num_slots);)

        if (netmap_verbose & NM_VERB_TXSYNC)
            ptnetmap_kring_dump("post txsync", kring);

//#define BUSY_WAIT
#ifndef BUSY_WAIT
        if (work && ptnetmap_tx_get_guestkick(csb)) {
            ptnetmap_tx_set_guestkick(csb, 0);
            ptn_kthread_send_irq(pts->ptk_tx);
            IFRATE(pts->rate_ctx.new.htxk++);
            work = false;
        }
#endif
        ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);
#ifndef BUSY_WAIT
        /* Nothing to transmit */
        if (g_head == kring->rhead) {
            usleep_range(1,1);
            /* Reenable notifications. */
            ptnetmap_tx_set_hostkick(csb, 1);
            /* Doublecheck. */
            ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);
            if (unlikely(g_head != kring->rhead)) {
                ptnetmap_tx_set_hostkick(csb, 0);
                continue;
            } else
                break;
        }

        /* ring full */
        if (kring->nr_hwtail == kring->rhead) {
            RD(1, "TX ring FULL");
            break;
        }
#endif
        if (unlikely(pts->stopped || !pts->configured)) {
            D("stopped or not configured");
            break;
        }
    }

leave_kr_put:
    nm_kr_put(kring);

leave:
    if (work && ptnetmap_tx_get_guestkick(csb)) {
        ptnetmap_tx_set_guestkick(csb, 0);
        ptn_kthread_send_irq(pts->ptk_tx);
        IFRATE(pts->rate_ctx.new.htxk++);
    }

    return;
}

static inline void ptnetmap_rx_set_hostkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, host_need_rxkick, val);
}

static inline uint32_t ptnetmap_rx_get_guestkick(struct paravirt_csb __user *csb)
{
    uint32_t v;

    CSB_READ(csb, guest_need_rxkick, v);

    return v;
}
static inline void ptnetmap_rx_set_guestkick(struct paravirt_csb __user *csb, uint32_t val)
{
    CSB_WRITE(csb, guest_need_rxkick, val);
}

/*
 * We needs kick from the guest when:
 *
 * - RX: tail == head - 1
 *       ring is full
 *       We need to wait that the guest gets some packets from the ring and then it notifies us.
 */
static inline int
nm_kr_rxfull(struct netmap_kring *kring, uint32_t g_head)
{
    return (ACCESS_ONCE(kring->nr_hwtail) == nm_prev(g_head, kring->nkr_num_slots - 1));
}

/*
 * Handle rx events: from the guest or from the backend
 */
static void ptnetmap_rx_handler(void *data)
{
    struct ptnetmap_state *pts = (struct ptnetmap_state *) data;
    struct netmap_kring *kring;
    struct paravirt_csb __user *csb;
    struct pt_ring __user *csb_ring;
    uint32_t g_cur = 0, g_head = 0, g_flags = 0; /* guest variables; init for compiler */
    int cicle_nowork = 0;
    bool work = false;
    IFRATE(uint32_t pre_tail;)

    if (unlikely(!pts)) {
        D("backend netmap is not configured");
        return;
    }

    if (unlikely(!pts->pt_na || pts->stopped || !pts->configured)) {
        D("backend netmap is not configured");
        goto leave;
    }

    kring = &pts->pt_na->parent->rx_rings[0];

    if (nm_kr_tryget(kring)) {
        D("error nm_kr_tryget()");
        goto leave;
    }

    csb = pts->csb;
    csb_ring = &csb->rx_ring; /* netmap RX pointers in CSB */

    /* Disable notifications. */
    ptnetmap_rx_set_hostkick(csb, 0);

    ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);

    for (;;) {

        if (nm_rxsync_prologue(kring, g_head, g_cur, NULL)
                >= kring->nkr_num_slots) {
            ptnetmap_ring_reinit(kring, g_head, g_cur);
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            break;
        }

        if (netmap_verbose & NM_VERB_RXSYNC)
            ptnetmap_kring_dump("pre rxsync", kring);

        IFRATE(pre_tail = kring->rtail;)

        if (kring->nm_sync(kring, g_flags) == 0) {
            /* finalize */
            ptnetmap_write_kring_csb(csb_ring, kring->nr_hwcur, kring->nr_hwtail);
            if (kring->rtail != kring->nr_hwtail) {
                kring->rtail = kring->nr_hwtail;
                work = true;
                cicle_nowork = 0;
            } else {
                cicle_nowork++;
            }
        } else {
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            D("nm_sync error");
            goto leave_kr_put;
        }

        IFRATE(batch_info_update(&pts->rate_ctx.new.bf_rx, pre_tail, kring->rtail, kring->nkr_num_slots);)

        if (netmap_verbose & NM_VERB_RXSYNC)
            ptnetmap_kring_dump("post rxsync", kring);

#ifndef BUSY_WAIT
        if (work && ptnetmap_rx_get_guestkick(csb)) {
            ptnetmap_rx_set_guestkick(csb, 0);
            ptn_kthread_send_irq(pts->ptk_rx);
            IFRATE(pts->rate_ctx.new.hrxk++);
            work = false;
        }
#endif
        ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);
#ifndef BUSY_WAIT
        /* No space to receive */
        if (nm_kr_rxfull(kring, g_head)) {
            usleep_range(1,1);
            /* Reenable notifications. */
            ptnetmap_rx_set_hostkick(csb, 1);
            /* Doublecheck. */
            ptnetmap_read_kring_csb(csb_ring, &g_head, &g_cur, &g_flags);
            if (unlikely(!nm_kr_rxfull(kring, g_head))) {
                ptnetmap_rx_set_hostkick(csb, 0);
                continue;
            } else
                break;
        }

        /* ring empty */
        if (kring->nr_hwtail == kring->rhead || cicle_nowork >= PTN_RX_NOWORK_CYCLE) {
            RD(1, "nr_hwtail: %d rhead: %d cicle_nowork: %d", kring->nr_hwtail, kring->rhead, cicle_nowork);
            break;
        }
#endif
        if (unlikely(pts->stopped || !pts->configured)) {
            D("stopped or not configured");
            break;
        }
    }

leave_kr_put:
    nm_kr_put(kring);

leave:
    if (work && ptnetmap_rx_get_guestkick(csb)) {
        ptnetmap_rx_set_guestkick(csb, 0);
        ptn_kthread_send_irq(pts->ptk_rx);
        IFRATE(pts->rate_ctx.new.hrxk++);
    }
}

static void inline
ptnetmap_tx_notify(struct ptnetmap_state *pts) {
    ptn_kthread_wakeup_worker(pts->ptk_tx);
    IFRATE(pts->rate_ctx.new.btxwu++);
}

static void inline
ptnetmap_rx_notify(struct ptnetmap_state *pts) {
    ptn_kthread_wakeup_worker(pts->ptk_rx);
    IFRATE(pts->rate_ctx.new.brxwu++);
}

static void ptnetmap_print_configuration(struct ptnetmap_state *pts)
{
    struct ptn_cfg *cfg = &pts->config;

    D("[ptn] configuration:");
    D("TX: iofd=%u, irqfd=%u",
            cfg->tx_ring.ioeventfd, cfg->tx_ring.irqfd);
    D("RX: iofd=%u, irqfd=%u",
            cfg->rx_ring.ioeventfd, cfg->rx_ring.irqfd);
    D("CSB: csb_addr=%p", cfg->csb);

}

static int
ptnetmap_create_kthreads(struct ptnetmap_state *pts)
{
    struct ptn_kthread_cfg ptk_cfg;

    ptk_cfg.worker_private = pts;

    /* TX kthread */
    ptk_cfg.type = PTK_TX;
    ptk_cfg.ring = pts->config.tx_ring;
    ptk_cfg.worker_fn = ptnetmap_tx_handler;
    pts->ptk_tx = ptn_kthread_create(&ptk_cfg);
    if (pts->ptk_tx == NULL) {
        goto err;
    }

    /* RX kthread */
    ptk_cfg.type = PTK_RX;
    ptk_cfg.ring = pts->config.rx_ring;
    ptk_cfg.worker_fn = ptnetmap_rx_handler;
    pts->ptk_rx = ptn_kthread_create(&ptk_cfg);
    if (pts->ptk_rx == NULL) {
        goto err;
    }

    return 0;
err:
    if (pts->ptk_tx) {
        ptn_kthread_delete(pts->ptk_tx);
        pts->ptk_tx = NULL;
    }
    return EFAULT;
}

static int
ptnetmap_kring_snapshot(struct netmap_kring *kring, struct pt_ring __user *ptr)
{
    if(CSB_WRITE(ptr, head, kring->rhead))
        goto err;
    if(CSB_WRITE(ptr, cur, kring->rcur))
        goto err;

    if(CSB_WRITE(ptr, hwcur, kring->nr_hwcur))
        goto err;
    if(CSB_WRITE(ptr, hwtail, kring->nr_hwtail))
        goto err;

    ptnetmap_kring_dump("ptnetmap_kring_snapshot", kring);

    return 0;
err:
    return EFAULT;
}

static int
ptnetmap_krings_snapshot(struct ptnetmap_state *pts, struct netmap_passthrough_adapter *pt_na)
{
    struct netmap_kring *kring;
    int error = 0;

    kring = &pt_na->parent->tx_rings[0];
    if((error = ptnetmap_kring_snapshot(kring, &pts->csb->tx_ring)))
        goto err;

    kring = &pt_na->parent->rx_rings[0];
    error = ptnetmap_kring_snapshot(kring, &pts->csb->rx_ring);

err:
    return error;
}

static int ptnetmap_notify(struct netmap_adapter *, u_int, enum txrx, int);

static int
ptnetmap_create(struct netmap_passthrough_adapter *pt_na, const void __user *buf, uint16_t buf_len)
{
    struct ptnetmap_state *pts;
    int ret;

    /* XXX check if already attached */

    D("");
    pts = kzalloc(sizeof *pts, GFP_KERNEL);
    if (!pts)
        return ENOMEM;
    pts->configured = false;
    pts->stopped = true;

    if (buf_len != sizeof(struct ptn_cfg)) {
        D("buf_len ERROR! - buf_len %d, expected %d", (int)buf_len, (int)sizeof(struct ptn_cfg));
        ret = EINVAL;
        goto err;
    }

    /* Read the configuration from userspace. */
    if (copy_from_user(&pts->config, buf, sizeof(struct ptn_cfg))) {
        D("copy_from_user() ERROR!");
        ret = EFAULT;
        goto err;
    }

    pts->csb = pts->config.csb;
    D("configuration read");
    ptnetmap_print_configuration(pts);

    if ((ret = ptnetmap_create_kthreads(pts))) {
        D("ptnetmap error creation kthreads");
        goto err;
    }

    if ((ret = ptnetmap_krings_snapshot(pts, pt_na))) {
        D("ptnetmap_krings_snapshot error");
        goto err;
    }

    D("configuration OK");

    pts->configured = true;
    pt_na->ptn_state = pts;
    pts->pt_na = pt_na;

    pt_na->parent_nm_notify = pt_na->parent->nm_notify;
    pt_na->parent->nm_notify = ptnetmap_notify;
    pt_na->parent->na_private = pt_na;

#ifdef RATE
    memset(&pts->rate_ctx, 0, sizeof(pts->rate_ctx));
    setup_timer(&pts->rate_ctx.timer, &rate_callback,
            (unsigned long)&pts->rate_ctx);
    if (mod_timer(&pts->rate_ctx.timer, jiffies + msecs_to_jiffies(1500)))
        D("[ptn] Error: mod_timer()\n");
#endif

    return 0;

err:
    kfree(pts);
    return ret;
}

static int
ptnetmap_start_kthreads(struct ptnetmap_state *pts)
{
    int error;

    /* check if ptnetmap is configured */
    if (!pts) {
        D("ptnetmap not configured");
        return EFAULT;
    }

    pts->stopped = false;

    /* TX kthread */
    error = ptn_kthread_start(pts->ptk_tx);
    if (error) {
        return error;
    }
    /* RX kthread */
    error = ptn_kthread_start(pts->ptk_rx);
    if (error) {
        ptn_kthread_stop(pts->ptk_tx);
        return error;
    }

    return 0;
}

static void
ptnetmap_stop_kthreads(struct ptnetmap_state *pts)
{
    /* check if it is configured */
    if (!pts)
        return;

    pts->stopped = true;

    /* TX kthread */
    ptn_kthread_stop(pts->ptk_tx);
    /* RX kthread */
    ptn_kthread_stop(pts->ptk_rx);
}

static void
ptnetmap_delete(struct netmap_passthrough_adapter *pt_na)
{
    struct ptnetmap_state *pts = pt_na->ptn_state;

    D("");

    /* check if ptnetmap is configured */
    if (!pts)
        return;

    pts->configured = false;

    /* delete kthreads */
    ptn_kthread_delete(pts->ptk_tx);
    ptn_kthread_delete(pts->ptk_rx);

    pt_na->parent->nm_notify = pt_na->parent_nm_notify;
    pt_na->parent->na_private = NULL;

    IFRATE(del_timer(&pts->rate_ctx.timer));

    kfree(pts);

    pt_na->ptn_state = NULL;

}


int
ptnetmap_ctl(struct nmreq *nmr, struct netmap_adapter *na)
{
    struct netmap_passthrough_adapter *pt_na;
    char *name;
    int cmd, error = 0;
    void __user *buf;
    uint16_t buf_len;

    name = nmr->nr_name;
    cmd = nmr->nr_cmd;

    D("name: %s", name);

    if (!nm_passthrough_on(na)) {
        D("Internal error: interface not in netmap passthrough mode. na = %p", na);
        error = ENXIO;
        goto done;
    }
    pt_na = (struct netmap_passthrough_adapter *)na;

    switch (cmd) {
        case NETMAP_PT_CREATE:
            nmr_read_buf(nmr, &buf, &buf_len);

            /* create kthreads */
            error = ptnetmap_create(pt_na, buf, buf_len);
            if (error)
                break;
            /* start kthreads */
            error = ptnetmap_start_kthreads(pt_na->ptn_state);
            if (error)
                ptnetmap_delete(pt_na);

            break;
        case NETMAP_PT_DELETE:
            /* stop kthreads */
            ptnetmap_stop_kthreads(pt_na->ptn_state);
            /* delete kthreads */
            ptnetmap_delete(pt_na);
            break;
        default:
            D("invalid cmd (nmr->nr_cmd) (0x%x)", cmd);
            error = EINVAL;
            break;
    }

done:
    return error;
}

static int
ptnetmap_notify(struct netmap_adapter *na, u_int n_ring,
        enum txrx tx, int flags)
{
    struct netmap_passthrough_adapter *pt_na = na->na_private;
    struct ptnetmap_state *pts = pt_na->ptn_state;

    if (tx == NR_TX) {
        ptnetmap_tx_notify(pts);
        /* optimization: avoid a wake up on the global
         * queue if nobody has registered for more
         * than one ring
         */
        if (na->tx_si_users > 0)
            OS_selwakeup(&na->tx_si, PI_NET);
    } else {
        ptnetmap_rx_notify(pts);
        /* optimization: same as above */
        if (na->rx_si_users > 0)
            OS_selwakeup(&na->rx_si, PI_NET);
    }
    return 0;
}

//XXX maybe is unnecessary redefine the *xsync
/* nm_txsync callback for passthrough */
static int
ptnetmap_txsync(struct netmap_kring *kring, int flags)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)kring->na;
    struct netmap_adapter *parent = pt_na->parent;
    int n;

    D("");
    n = parent->nm_txsync(kring, flags);

    return n;
}

/* nm_rxsync callback for passthrough */
    static int
ptnetmap_rxsync(struct netmap_kring *kring, int flags)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)kring->na;
    struct netmap_adapter *parent = pt_na->parent;
    int n;

    D("");
    n = parent->nm_rxsync(kring, flags);

    return n;
}

/* nm_config callback for bwrap */
static int
ptnetmap_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
        u_int *rxr, u_int *rxd)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;
    struct netmap_adapter *parent = pt_na->parent;
    int error;

    //XXX: maybe call parent->nm_config is better

    /* forward the request */
    error = netmap_update_config(parent);

    *rxr = na->num_rx_rings = parent->num_rx_rings;
    *txr = na->num_tx_rings = parent->num_tx_rings;
    *txd = na->num_tx_desc = parent->num_tx_desc;
    *rxd = na->num_rx_desc = parent->num_rx_desc;

    D("rxr: %d txr: %d txd: %d rxd: %d", *rxr, *txr, *txd, *rxd);

    return error;
}

/* nm_krings_create callback for passthrough */
static int
ptnetmap_krings_create(struct netmap_adapter *na)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;
    struct netmap_adapter *parent = pt_na->parent;
    int error;

    D("%s", na->name);

    /* create the parent krings */
    error = parent->nm_krings_create(parent);
    if (error) {
        return error;
    }

    na->tx_rings = parent->tx_rings;
    na->rx_rings = parent->rx_rings;
    na->tailroom = parent->tailroom; //XXX

    return 0;
}

/* nm_krings_delete callback for passthrough */
static void
ptnetmap_krings_delete(struct netmap_adapter *na)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;
    struct netmap_adapter *parent = pt_na->parent;

    D("%s", na->name);

    parent->nm_krings_delete(parent);

    na->tx_rings = na->rx_rings = na->tailroom = NULL;
}

/* nm_register callback */
static int
ptnetmap_register(struct netmap_adapter *na, int onoff)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;
    struct netmap_adapter *parent = pt_na->parent;
    int error;
    D("%p: onoff %d", na, onoff);

    if (onoff) {
        /* netmap_do_regif has been called on the
         * passthrough na.
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
        na->na_flags |= NAF_NETMAP_ON | NAF_PASSTHROUGH_FULL;
    } else {
        ptnetmap_delete(pt_na);
        na->na_flags &= ~(NAF_NETMAP_ON | NAF_PASSTHROUGH_FULL);
    }

    return 0;
}

/* nm_dtor callback */
static void
ptnetmap_dtor(struct netmap_adapter *na)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;
    struct netmap_adapter *parent = pt_na->parent;

    D("%p", na);

    parent->na_flags &= ~NAF_BUSY;

    netmap_adapter_put(pt_na->parent);
    pt_na->parent = NULL;
}

/* check if nmr is a request for a passthrough adapter that we can satisfy */
int
netmap_get_passthrough_na(struct nmreq *nmr, struct netmap_adapter **na, int create)
{
    struct nmreq parent_nmr;
    struct netmap_adapter *parent; /* target adapter */
    struct netmap_passthrough_adapter *pt_na;
    int error;

    if ((nmr->nr_flags & (NR_PASSTHROUGH_FULL)) == 0) {
        D("not a passthrough");
        return 0;
    }
    /* this is a request for a passthrough adapter */
    D("flags %x", nmr->nr_flags);

    pt_na = malloc(sizeof(*pt_na), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (pt_na == NULL) {
        D("memory error");
        return ENOMEM;
    }

    /* first, try to find the adapter that we want to passthrough
     * We use the same nmr, after we have turned off the passthrough flag.
     * In this way we can potentially passthrough everything netmap understands.
     */
    memcpy(&parent_nmr, nmr, sizeof(parent_nmr));
    parent_nmr.nr_flags &= ~(NR_PASSTHROUGH_FULL);
    error = netmap_get_na(&parent_nmr, &parent, create);
    if (error) {
        D("parent lookup failed: %d", error);
        goto put_out_noputparent;
    }
    D("found parent: %s", parent->name);

    /* make sure the NIC is not already in use */
    if (NETMAP_OWNED_BY_ANY(parent)) {
        D("NIC %s busy, cannot passthrough", parent->name);
        error = EBUSY;
        goto put_out;
    }

    pt_na->parent = parent;

    //XXX pt_na->up.na_flags = parent->na_flags;
    pt_na->up.num_rx_rings = parent->num_rx_rings;
    pt_na->up.num_tx_rings = parent->num_tx_rings;
    pt_na->up.num_tx_desc = parent->num_tx_desc;
    pt_na->up.num_rx_desc = parent->num_rx_desc;

    pt_na->up.nm_dtor = ptnetmap_dtor;
    pt_na->up.nm_register = ptnetmap_register;

    //XXX maybe is unnecessary redefine the *xsync
    pt_na->up.nm_txsync = ptnetmap_txsync;
    pt_na->up.nm_rxsync = ptnetmap_rxsync;

    pt_na->up.nm_krings_create = ptnetmap_krings_create;
    pt_na->up.nm_krings_delete = ptnetmap_krings_delete;
    pt_na->up.nm_config = ptnetmap_config;
    pt_na->up.nm_notify = ptnetmap_notify;


    //XXX needed?
    //pt_na->up.nm_bdg_attach = ptnetmap_bdg_attach;
    //pt_na->up.nm_bdg_ctl = ptnetmap_bdg_ctl;

    pt_na->up.nm_mem = parent->nm_mem;
    error = netmap_attach_common(&pt_na->up);
    if (error) {
        D("attach_common error");
        goto put_out;
    }

    *na = &pt_na->up;
    netmap_adapter_get(*na);

    /* write the configuration back */
    nmr->nr_tx_rings = pt_na->up.num_tx_rings;
    nmr->nr_rx_rings = pt_na->up.num_rx_rings;
    nmr->nr_tx_slots = pt_na->up.num_tx_desc;
    nmr->nr_rx_slots = pt_na->up.num_rx_desc;

    parent->na_flags |= NAF_BUSY;

    strncpy(pt_na->up.name, parent->name, sizeof(pt_na->up.name));
    strcat(pt_na->up.name, "-PT");
    D("passthrough full ok");
    return 0;

put_out:
    netmap_adapter_put(parent);
put_out_noputparent:
    free(pt_na, M_DEVBUF);
    return error;
}
#endif /* WITH_PASSTHROUGH */
