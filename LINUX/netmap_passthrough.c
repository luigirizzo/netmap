/*
 * common headers
 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

#include "vhost-netmap-pt/paravirt.h"
#include "vhost-netmap-pt/vhost_netmap_pt.h"

#ifdef WITH_PASSTHROUGH

#define NM_PT_RX_NOWORK_CYCLE   2                               /* RX cycle without receive any packets */
#define NM_PT_TX_BATCH_LIM      ((kring->nkr_num_slots >> 1))     /* Limit Batch TX to half ring */

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
        printk("[vPT] Error: mod_timer()\n");
}

#else /* !RATE */
#define IFRATE(x)
#endif /* RATE */

struct vPT_net {
    struct vPT_dev dev_tx, dev_rx;
    struct vPT_ring tx_ring, rx_ring;
    struct vPT_poll tx_poll, rx_poll;

    struct vPT_Config config;
    bool configured;
    struct paravirt_csb __user * csb;
    bool broken;

    struct file *nm_f;
    int nm_fput_needed;
    struct netmap_passthrough_adapter *pt_na;

    IFRATE(struct rate_context rate_ctx);
};



#define CSB_READ(csb, field, r) \
    do { \
        if (get_user(r, &csb->field)) { \
            D("get_user ERROR"); \
            r = -EFAULT; \
        } \
    } while (0)

#define CSB_WRITE(csb, field, v) \
    do { \
        if (put_user(v, &csb->field)) { \
            D("put_user ERROR"); \
            v = -EFAULT; \
        } \
    } while (0)

static inline void
nm_kring_dump(const char *title, const struct netmap_kring *kring)
{
    D("%s - name: %s hwcur: %d hwtail: %d rhead: %d rcur: %d rtail: %d head: %d cur: %d tail: %d",
            title, kring->name, kring->nr_hwcur,
            kring->nr_hwtail, kring->rhead, kring->rcur, kring->rtail,
            kring->ring->head, kring->ring->cur, kring->ring->tail);
}

static inline void
nm_pt_ring_reinit(struct netmap_kring *kring, uint32_t g_head, uint32_t g_cur)
{
    struct netmap_ring *ring = kring->ring;

    // XXX trust guest?
    ring->head = g_head;
    ring->cur = g_cur;
    ring->tail = kring->nr_hwtail;

    //ring->head = kring->rhead = kring->nr_hwcur;
    //ring->cur = kring->rcur = kring->nr_hwcur;
    //ring->tail = kring->rtail = kring->nr_hwtail;

    netmap_ring_reinit(kring);
    nm_kring_dump("post reinit", kring);
}

static inline void vPT_set_txkick(struct vPT_net *net, bool enable)
{
    uint32_t v = enable ? 1 : 0;

    CSB_WRITE(net->csb, host_need_txkick, v);
}

static inline bool vPT_tx_interrupts_enabled(struct vPT_net * net)
{
    uint32_t v;

    CSB_READ(net->csb, guest_need_txkick, v);

    return v;
}
static inline void vPT_disable_guest_txkick(struct vPT_net *net)
{
    uint32_t v = 0;

    CSB_WRITE(net->csb, guest_need_txkick, v);
}

/*
 * We needs kick from the guest when:
 * - TX: tail == head - 1
 *       ring is empty
 *       We need to wait that the guest puts some packets in the ring and then it notifies us.
 *
 * - RX: tail == head - 1
 *       ring is full
 *       We need to wait that the guest gets some packets from the ring and then it notifies us.
 */
static inline int
nm_kring_need_kick(struct netmap_kring *kring, uint32_t g_head)
{
    return (ACCESS_ONCE(kring->nr_hwtail) == nm_prev(g_head, kring->nkr_num_slots - 1));
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_tx(struct vPT_net *net)
{
    struct vPT_ring *vr;
    struct netmap_kring *kring;
    uint32_t g_cur, g_head, g_flags; /* guest variables */
    int error = 0;
    bool work = false;
    int batch;
    IFRATE(uint32_t pre_tail;)

    if (unlikely(!net)) {
        D("backend netmap is not configured");
        return;
    }

    vr = &net->tx_ring;
    mutex_lock(&vr->mutex);

    if (unlikely(!net->pt_na || net->broken || !net->configured)) {
        D("backend netmap is not configured");
        goto leave;
    }

    kring = &net->pt_na->parent->tx_rings[0];

    if (nm_kr_tryget(kring)) {
        error = EBUSY;
        D("error: %d", error);
        goto leave_kr_put;
    }

    /* Disable notifications. */
    vPT_set_txkick(net, false);

    // prologue
    CSB_READ(net->csb, tx_ring.head, g_head);
    CSB_READ(net->csb, tx_ring.cur, g_cur);
    CSB_READ(net->csb, tx_ring.sync_flags, g_flags);
    mb(); //XXX: or smp_mb() ?

    for (;;) {
#ifdef NM_PT_TX_BATCH_LIM
        batch = g_head - kring->nr_hwcur;

        if (batch < 0)
            batch += kring->nkr_num_slots;

        if (batch > NM_PT_TX_BATCH_LIM) {
            uint32_t new_head = kring->nr_hwcur + NM_PT_TX_BATCH_LIM;
            if (new_head >= kring->nkr_num_slots)
                new_head -= kring->nkr_num_slots;
            ND(1, "batch: %d old_head: %d new_head: %d", batch, g_head, new_head);
            g_head = new_head;
        }
#endif /* NM_PT_TX_BATCH_LIM */

        if (nm_kr_txspace(kring) <= (kring->nkr_num_slots >> 1)) {
            g_flags |= NAF_FORCE_RECLAIM;
        }

        if (nm_txsync_prologue(kring, g_head, g_cur, NULL)
                >= kring->nkr_num_slots) {
            nm_pt_ring_reinit(kring, g_head, g_cur);
            /* Reenable notifications. */
            vPT_set_txkick(net, true);
            break;
        }

        if (netmap_verbose & NM_VERB_TXSYNC)
            nm_kring_dump("pre txsync", kring);

        IFRATE(pre_tail = kring->rtail;)

        if (likely(kring->nm_sync(kring, g_flags) == 0)) {
            /* finalize */
            //nm_txsync_finalize(kring);
            mb();
            CSB_WRITE(net->csb, tx_ring.hwcur, kring->nr_hwcur);
            CSB_WRITE(net->csb, tx_ring.hwtail, ACCESS_ONCE(kring->nr_hwtail));
            if (kring->rtail != kring->nr_hwtail) {
                kring->rtail = kring->nr_hwtail;
                work = true;
            }
        } else {
            /* Reenable notifications. */
            vPT_set_txkick(net, true);
            D("nm_sync error");
            goto leave_kr_put;
        }

        IFRATE(batch_info_update(&net->rate_ctx.new.bf_tx, pre_tail, kring->rtail, kring->nkr_num_slots);)

        if (netmap_verbose & NM_VERB_TXSYNC)
            nm_kring_dump("post txsync", kring);

        if (work && vPT_tx_interrupts_enabled(net)) {
            vPT_disable_guest_txkick(net);
            eventfd_signal(vr->call_ctx, 1);
            IFRATE(net->rate_ctx.new.htxk++);
            work = false;
        }

        // prologue
        CSB_READ(net->csb, tx_ring.head, g_head);
        CSB_READ(net->csb, tx_ring.cur, g_cur);
        CSB_READ(net->csb, tx_ring.sync_flags, g_flags);
//#define INFINITE_WORK
#ifndef INFINITE_WORK
        /* Nothing to transmit */
        if (g_head == kring->rhead) {
            usleep_range(1,1);
            /* Reenable notifications. */
            vPT_set_txkick(net, true);
            /* Doublecheck. */
            CSB_READ(net->csb, tx_ring.head, g_head);
            CSB_READ(net->csb, tx_ring.cur, g_cur);
            if (unlikely(g_head != kring->rhead)) {
                vPT_set_txkick(net, false);
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
        if (unlikely(net->broken || !net->configured)) {
            D("net broken");
            break;
        }
    }

leave_kr_put:
    nm_kr_put(kring);

leave:
    if (work && vPT_tx_interrupts_enabled(net)) {
        vPT_disable_guest_txkick(net);
        eventfd_signal(vr->call_ctx, 1);
        IFRATE(net->rate_ctx.new.htxk++);
    }
    mutex_unlock(&vr->mutex);

    return;
}

static inline void vPT_set_rxkick(struct vPT_net *net, bool enable)
{
    uint32_t v = enable ? 1 : 0;

    CSB_WRITE(net->csb, host_need_rxkick, v);
}

static inline bool vPT_rx_interrupts_enabled(struct vPT_net * net)
{
    uint32_t v;

    CSB_READ(net->csb, guest_need_rxkick, v);

    return v;
}
static inline void vPT_disable_guest_rxkick(struct vPT_net *net)
{
    uint32_t v = 0;

    CSB_WRITE(net->csb, guest_need_rxkick, v);
}


/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_rx(struct vPT_net *net)
{
    struct vPT_ring *vr;
    struct netmap_kring *kring;
    uint32_t g_cur, g_head, g_flags; /* guest variables */
    int error = 0;
    int cicle_nowork = 0;
    bool work = false;
    IFRATE(uint32_t pre_tail;)

    if (unlikely(!net)) {
        D("backend netmap is not configured");
        return;
    }

    vr = &net->rx_ring;

    mutex_lock(&vr->mutex);

    if (unlikely(!net->pt_na || net->broken || !net->configured)) {
        D("backend netmap is not configured");
        goto leave;
    }

    kring = &net->pt_na->parent->rx_rings[0];

    if (nm_kr_tryget(kring)) {
        error = EBUSY;
        D("error: %d", error);
        goto leave;
    }

    /* Disable notifications. */
    vPT_set_rxkick(net, false);

    // prologue
    mb();
    CSB_READ(net->csb, rx_ring.head, g_head);
    CSB_READ(net->csb, rx_ring.cur, g_cur);
    CSB_READ(net->csb, rx_ring.sync_flags, g_flags);

    for (;;) {

        if (nm_rxsync_prologue(kring, g_head, g_cur, NULL)
                >= kring->nkr_num_slots) {
            nm_pt_ring_reinit(kring, g_head, g_cur);
            /* Reenable notifications. */
            vPT_set_rxkick(net, true);
            break;
        }

        if (netmap_verbose & NM_VERB_RXSYNC)
            nm_kring_dump("pre rxsync", kring);

        IFRATE(pre_tail = kring->rtail;)

        if (kring->nm_sync(kring, g_flags) == 0) {
            //nm_rxsync_finalize(kring);
            //finalize
            CSB_WRITE(net->csb, rx_ring.hwcur, kring->nr_hwcur);
            CSB_WRITE(net->csb, rx_ring.hwtail, ACCESS_ONCE(kring->nr_hwtail));
            mb();
            if (kring->rtail != kring->nr_hwtail) {
                kring->rtail = kring->nr_hwtail;
                work = true;
                cicle_nowork = 0;
            } else {
                cicle_nowork++;
            }
        } else {
            /* Reenable notifications. */
            vPT_set_rxkick(net, true);
            D("nm_sync error");
            goto leave_kr_put;
        }

        IFRATE(batch_info_update(&net->rate_ctx.new.bf_rx, pre_tail, kring->rtail, kring->nkr_num_slots);)

        if (netmap_verbose & NM_VERB_RXSYNC)
            nm_kring_dump("post rxsync", kring);

        if (work && vPT_rx_interrupts_enabled(net)) {
            vPT_disable_guest_rxkick(net);
            eventfd_signal(vr->call_ctx, 1);
            IFRATE(net->rate_ctx.new.hrxk++);
            work = false;
        }

        // prologue
        mb();
        CSB_READ(net->csb, rx_ring.head, g_head);
        CSB_READ(net->csb, rx_ring.cur, g_cur);
        CSB_READ(net->csb, rx_ring.sync_flags, g_flags);
#ifndef INFINITE_WORK
        /* No space to receive */
        if (nm_kring_need_kick(kring, g_head)) {
            usleep_range(1,1);
            /* Reenable notifications. */
            vPT_set_rxkick(net, true);
            /* Doublecheck. */
            CSB_READ(net->csb, rx_ring.head, g_head);
            CSB_READ(net->csb, rx_ring.cur, g_cur);
            mb();
            if (unlikely(!nm_kring_need_kick(kring, g_head))) {
                vPT_set_rxkick(net, false);
                continue;
            } else
                break;
        }

        /* ring empty */
        if (kring->nr_hwtail == kring->rhead || cicle_nowork >= NM_PT_RX_NOWORK_CYCLE) {
            RD(1, "nr_hwtail: %d rhead: %d cicle_nowork: %d", kring->nr_hwtail, kring->rhead, cicle_nowork);
            break;
        }
#endif
        if (unlikely(net->broken || !net->configured)) {
            D("net broken");
            break;
        }
    }

leave_kr_put:
    nm_kr_put(kring);

leave:
    if (work && vPT_rx_interrupts_enabled(net)) {
        vPT_disable_guest_rxkick(net);
        eventfd_signal(vr->call_ctx, 1);
        IFRATE(net->rate_ctx.new.hrxk++);
    }
    mutex_unlock(&vr->mutex);
   // DBG(printk("rxintr=%d\n", vPT_rx_interrupts_enabled(net)));
}

static void handle_tx_kick(struct vPT_work *work)
{
    struct vPT_ring *vr = container_of(work, struct vPT_ring,
            poll.work);
    struct vPT_net *net = container_of(vr->dev, struct vPT_net, dev_tx);

    IFRATE(net->rate_ctx.new.gtxk++);
    handle_tx(net);
}

static void handle_rx_kick(struct vPT_work *work)
{
    struct vPT_ring *vr = container_of(work, struct vPT_ring,
            poll.work);
    struct vPT_net *net = container_of(vr->dev, struct vPT_net, dev_rx);

    IFRATE(net->rate_ctx.new.grxk++);
    handle_rx(net);
}

static void handle_tx_net(struct vPT_work *work)
{
    struct vPT_net *net = container_of(work, struct vPT_net,
            tx_poll.work);

    IFRATE(net->rate_ctx.new.btxwu++);
    handle_tx(net);
}

static void handle_rx_net(struct vPT_work *work)
{
    struct vPT_net *net = container_of(work, struct vPT_net,
            rx_poll.work);

    IFRATE(net->rate_ctx.new.brxwu++);
    handle_rx(net);
}

static int vPT_set_eventfds_ring(struct vPT_ring * vr, struct vPT_RingConfig * vrc)
{
    vr->kick = eventfd_fget(vrc->ioeventfd);
    if (IS_ERR(vr->kick))
        return PTR_ERR(vr->kick);

    vr->call = eventfd_fget(vrc->irqfd);
    if (IS_ERR(vr->call))
        return PTR_ERR(vr->call);
    vr->call_ctx = eventfd_ctx_fileget(vr->call);

    if (vrc->resamplefd != ~0U) {
        vr->resample = eventfd_fget(vrc->resamplefd);
        if (IS_ERR(vr->resample))
            return PTR_ERR(vr->resample);
        vr->resample_ctx = eventfd_ctx_fileget(vr->resample);
    } else {
        vr->resample = NULL;
        vr->resample_ctx = NULL;
    }

    return 0;
}

static int vPT_set_eventfds(struct vPT_net * net)
{
    int r;

    if ((r = vPT_set_eventfds_ring(&net->tx_ring, &net->config.tx_ring)))
        return r;
    if ((r = vPT_set_eventfds_ring(&net->rx_ring, &net->config.rx_ring)))
        return r;

    return 0;
}

static int vPT_set_backend(struct vPT_net * net)
{
    //net->nm_f = fget_light(net->config.netmap_fd, &net->nm_fput_needed);
    net->nm_f = fget(net->config.netmap_fd);
    if (IS_ERR(net->nm_f))
        return PTR_ERR(net->nm_f);
    //D("fget_light - fput_neede=%d", net->nm_fput_needed);
    D("netmap_fd:%u f_count:%d", net->config.netmap_fd, (int)net->nm_f->f_count.counter);

    return 0;
}

static void vPT_print_configuration(struct vPT_net * net)
{
    struct vPT_Config *cfg = &net->config;

    printk("[vPT] configuration:\n");
    printk("TX: iofd=%u, irqfd=%u, resfd=%d\n",
            cfg->tx_ring.ioeventfd, cfg->tx_ring.irqfd, cfg->tx_ring.resamplefd);
    printk("RX: iofd=%u, irqfd=%u, resfd=%d\n",
            cfg->rx_ring.ioeventfd, cfg->rx_ring.irqfd, cfg->rx_ring.resamplefd);
    printk("Backend: netmapfd=%u\n", cfg->netmap_fd);
    printk("CSB: csb_addr=%p\n", cfg->csb);

}

int vPT_netmap_poll_start(struct vPT_net *net, struct file *file,
        struct netmap_passthrough_adapter *pt_na)
{
    int ret = 0;

    if (!net->tx_poll.wqh) {
        poll_wait(file, &pt_na->parent->tx_rings[0].si, &net->tx_poll.table);
        vPT_poll_queue(&net->tx_poll);
        printk("%p.poll_start()\n", &net->tx_poll);
    }

    if (!net->rx_poll.wqh) {
        poll_wait(file, &pt_na->parent->rx_rings[0].si, &net->rx_poll.table);
        vPT_poll_queue(&net->rx_poll);
        printk("%p.poll_start()\n", &net->rx_poll);
    }

    return ret;
}

static int vPT_configure(struct vPT_net * net, struct netmap_passthrough_adapter *pt_na)
{
    int r;

    /* Configure. */
    if ((r = vPT_dev_set_owner(&net->dev_tx)))
        return r;
    if ((r = vPT_dev_set_owner(&net->dev_rx)))
        return r;
    if ((r = vPT_set_eventfds(net)))
        return r;
    if ((r = vPT_set_backend(net)))
        return r;
    ///XXX function ???
    net->csb = net->config.csb;

    vPT_print_configuration(net);

    /* Start polling. */
    if (net->tx_ring.handle_kick && (r = vPT_poll_start(&net->tx_ring.poll, net->tx_ring.kick)))
        return r;
    if (net->rx_ring.handle_kick && (r = vPT_poll_start(&net->rx_ring.poll, net->rx_ring.kick)))
        return r;
    if (net->nm_f && (r = vPT_netmap_poll_start(net, net->nm_f, pt_na)))
        return r;

    return 0;
}

static int
netmap_pt_kring_snapshot(struct netmap_kring *kring, struct pt_ring __user *pt_ring)
{
    if(put_user(kring->rhead, &pt_ring->head))
        goto err;
    if(put_user(kring->rcur, &pt_ring->cur))
        goto err;

    if(put_user(kring->nr_hwcur, &pt_ring->hwcur))
        goto err;
    if(put_user(kring->nr_hwtail, &pt_ring->hwtail))
        goto err;

    nm_kring_dump("", kring);

    return 0;
err:
    return -EFAULT;
}

static int
netmap_pt_krings_snapshot(struct netmap_passthrough_adapter *pt_na, struct vPT_net * net)
{
    struct netmap_kring *kring;
    int error = 0;

    kring = &pt_na->parent->tx_rings[0];
    if((error = netmap_pt_kring_snapshot(kring, &net->csb->tx_ring)))
        goto err;

    kring = &pt_na->parent->rx_rings[0];
    error = netmap_pt_kring_snapshot(kring, &net->csb->rx_ring);

err:
    return error;
}

static int
netmap_pt_create(struct netmap_passthrough_adapter *pt_na, const void __user *buf, uint16_t buf_len)
{
    struct vPT_net *net = kmalloc(sizeof *net, GFP_KERNEL);
    struct vPT_dev *dev_tx, *dev_rx;
    int ret;

    /* XXX check if already attached */

    D("");
    printk("%p.OPEN()\n", net);
    if (!net)
        return ENOMEM;
    net->configured = net->broken = false;

    dev_tx = &net->dev_tx;
    dev_rx = &net->dev_rx;
    net->tx_ring.handle_kick = handle_tx_kick;
    net->rx_ring.handle_kick = handle_rx_kick;

    ret = vPT_dev_init(dev_tx, &net->tx_ring, NULL);
    if (ret < 0) {
        kfree(net);
        return ret;
    }
    ret = vPT_dev_init(dev_rx, NULL, &net->rx_ring);
    if (ret < 0) {
        kfree(net);
        return ret;
    }

    vPT_poll_init(&net->tx_poll, handle_tx_net, POLLOUT, dev_tx);
    vPT_poll_init(&net->rx_poll, handle_rx_net, POLLIN, dev_rx);

#ifdef RATE
    memset(&net->rate_ctx, 0, sizeof(net->rate_ctx));
    setup_timer(&net->rate_ctx.timer, &rate_callback,
            (unsigned long)&net->rate_ctx);
    if (mod_timer(&net->rate_ctx.timer, jiffies + msecs_to_jiffies(1500)))
        printk("[vPT] Error: mod_timer()\n");
#endif

    printk("%p.OPEN_END()\n", net);

    mutex_lock(&net->dev_tx.mutex);
    mutex_lock(&net->dev_rx.mutex);

    if (buf_len != sizeof(struct vPT_Config)) {
        D("buf_len error buf_len %d, expected %d", (int)buf_len, (int)sizeof(struct vPT_Config));
        ret = EINVAL;
        goto err;
    }

    /* Read the configuration from userspace. */
    if (copy_from_user(&net->config, buf, sizeof(struct vPT_Config))) {
        printk(KERN_ALERT "vPT_first_write(): copy_from_user()\n");
        ret = EFAULT;
        goto err;
    }

    printk("[vPT] configuration read\n");
    if ((ret = vPT_configure(net, pt_na))) {
        D("vPT_configure error");
        goto err;
    }

    if ((ret = netmap_pt_krings_snapshot(pt_na, net))) {
        D("netmap_pt_krings_snapshot error");
        goto err;
    }

    printk("[vPT] configuration OK\n");

    net->configured = true;
    pt_na->private = net;
    net->pt_na = pt_na;

    mutex_unlock(&net->dev_rx.mutex);
    mutex_unlock(&net->dev_tx.mutex);

    return 0;

err:
    mutex_unlock(&net->dev_rx.mutex);
    mutex_unlock(&net->dev_tx.mutex);
    kfree(net);
    return ret;
}

static void vPT_net_stop_vr(struct vPT_net *net,
        struct vPT_ring *vr)
{
    mutex_lock(&vr->mutex);
    if (vr == &net->tx_ring)
        vPT_poll_stop(&net->tx_poll);
    else
        vPT_poll_stop(&net->rx_poll);
    mutex_unlock(&vr->mutex);
}

static void vPT_net_stop(struct vPT_net *net)
{
    vPT_net_stop_vr(net, &net->tx_ring);
    vPT_net_stop_vr(net, &net->rx_ring);
}

static void vPT_net_flush(struct vPT_net *n)
{
    vPT_poll_flush(&n->rx_poll);
    vPT_poll_flush(&n->dev_rx.rx_ring->poll);
    vPT_poll_flush(&n->tx_poll);
    vPT_poll_flush(&n->dev_tx.tx_ring->poll);
}

static int
netmap_pt_delete(struct netmap_passthrough_adapter *pt_na)
{
    struct vPT_net *net = pt_na->private;

    D("");
    printk("%p.RELEASE()\n", net);

    //XXX check if is configured
    if (!net)
        return EFAULT;

    net->configured = false;

    vPT_net_stop(net);
    vPT_net_flush(net);
    vPT_dev_stop(&net->dev_tx);
    vPT_dev_stop(&net->dev_rx);
    vPT_dev_cleanup(&net->dev_tx);
    vPT_dev_cleanup(&net->dev_rx);
    if (net->nm_f)
        fput(net->nm_f);
    /* We do an extra flush before freeing memory,
     * since jobs can re-queue themselves. */
    vPT_net_flush(net);

    IFRATE(del_timer(&net->rate_ctx.timer));
    kfree(net);

    pt_na->private = NULL;

    printk("%p.RELEASE_END()\n", net);
    return 0;
}


int
netmap_pt_ctl(struct nmreq *nmr, struct netmap_adapter *na)
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
            error = netmap_pt_create(pt_na, buf, buf_len);
            break;
        case NETMAP_PT_DELETE:
            error = netmap_pt_delete(pt_na);
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
netmap_pt_notify(struct netmap_adapter *na, u_int n_ring,
        enum txrx tx, int flags)
{
    struct netmap_kring *kring;

    if (tx == NR_TX) {
        kring = na->tx_rings + n_ring;
        mb();
        //wake_up(&kring->si);
        wake_up_interruptible_poll(&kring->si, POLLOUT |
                POLLWRNORM | POLLWRBAND);
        /* optimization: avoid a wake up on the global
         * queue if nobody has registered for more
         * than one ring
         */
        if (na->tx_si_users > 0)
            OS_selwakeup(&na->tx_si, PI_NET);
    } else {
        kring = na->rx_rings + n_ring;
        mb();
        //wake_up(&kring->si);
        wake_up_interruptible_poll(&kring->si, POLLIN |
                POLLRDNORM | POLLRDBAND);
        /* optimization: same as above */
        if (na->rx_si_users > 0)
            OS_selwakeup(&na->rx_si, PI_NET);
    }
    return 0;
}

//XXX maybe is unnecessary redefine the *xsync
/* nm_txsync callback for passthrough */
static int
netmap_pt_txsync(struct netmap_kring *kring, int flags)
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
netmap_pt_rxsync(struct netmap_kring *kring, int flags)
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
netmap_pt_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
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
netmap_pt_krings_create(struct netmap_adapter *na)
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
netmap_pt_krings_delete(struct netmap_adapter *na)
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
netmap_pt_register(struct netmap_adapter *na, int onoff)
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
        //TODO: creare il kthread
    } else {
        netmap_pt_delete(pt_na);
        na->na_flags &= ~(NAF_NETMAP_ON | NAF_PASSTHROUGH_FULL);
        //TODO: uccidere il kthread
    }

    return 0;
}

/* nm_dtor callback */
static void
netmap_pt_dtor(struct netmap_adapter *na)
{
    struct netmap_passthrough_adapter *pt_na =
        (struct netmap_passthrough_adapter *)na;

    D("%p", na);

    pt_na->parent->na_flags &= ~NAF_BUSY;
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

    pt_na->up.nm_dtor = netmap_pt_dtor;
    pt_na->up.nm_register = netmap_pt_register;

    //XXX maybe is unnecessary redefine the *xsync
    pt_na->up.nm_txsync = netmap_pt_txsync;
    pt_na->up.nm_rxsync = netmap_pt_rxsync;

    pt_na->up.nm_krings_create = netmap_pt_krings_create;
    pt_na->up.nm_krings_delete = netmap_pt_krings_delete;
    pt_na->up.nm_config = netmap_pt_config;

    pt_na->up.nm_notify = netmap_pt_notify;
    //XXX restore
    parent->nm_notify = netmap_pt_notify;

    //XXX needed?
    //pt_na->up.nm_bdg_attach = netmap_pt_bdg_attach;
    //pt_na->up.nm_bdg_ctl = netmap_pt_bdg_ctl;


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

    pt_na->up.nm_mem = parent->nm_mem;
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
