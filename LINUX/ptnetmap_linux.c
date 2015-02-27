#include <linux/eventfd.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include <linux/file.h>

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/paravirt.h>

struct ptn_kthread_ctx {
    /* files to echange notifications */
    struct file *ioevent_file;          /* notification from guest */
    struct file *irq_file;              /* notification to guest (interrupt) */
    struct eventfd_ctx  *irq_ctx;

    /* poll ioeventfd to receive notification from the guest */
    poll_table poll_table;
    wait_queue_head_t *waitq_head;
    wait_queue_t waitq;

    /* worker function and parameter */
    ptn_kthread_worker_fn_t worker_fn;
    void *worker_private;

    struct ptn_kthread *ptk;

    /* worker type RX or TX */
    enum ptn_kthread_t type;
};

struct ptn_kthread {
    struct mm_struct *mm;
    struct task_struct *worker;

    spinlock_t worker_lock;     /* XXX: unused */
    uint64_t scheduled;         /* pending wake_up request */

    struct ptn_kthread_ctx worker_ctx;
};

void inline
ptn_kthread_wakeup_worker(struct ptn_kthread *ptk)
{
    //unsigned long flags;

    //spin_lock_irqsave(&ptk->worker_lock, flags);
    /*
     * There may be a race between FE and BE,
     * which call both this function, and worker kthread,
     * that reads ptk->scheduled.
     *
     * For us it is not important the counter value,
     * but simply that it has changed since the last
     * time the kthread saw it.
     */
    ptk->scheduled++;
    wake_up_process(ptk->worker);
    //spin_unlock_irqrestore(&ptk->worker_lock, flags);
}


static void
ptn_kthread_poll_fn(struct file *file, wait_queue_head_t *wq_head, poll_table *pt)
{
    struct ptn_kthread_ctx *ctx;

    ctx = container_of(pt, struct ptn_kthread_ctx, poll_table);
    ctx->waitq_head = wq_head;
    add_wait_queue(wq_head, &ctx->waitq);
}

static int
ptn_kthread_poll_wakeup(wait_queue_t *wq, unsigned mode, int sync, void *key)
{
    struct ptn_kthread_ctx *ctx;

    ctx = container_of(wq, struct ptn_kthread_ctx, waitq);

    ptn_kthread_wakeup_worker(ctx->ptk);
    return 0;
}

static int
ptn_kthread_worker(void *data)
{
    struct ptn_kthread *ptk = data;
    struct ptn_kthread_ctx *ctx = &ptk->worker_ctx;
    uint64_t old_scheduled = 0, new_scheduled = 0;
    mm_segment_t oldfs = get_fs();

    set_fs(USER_DS);
    use_mm(ptk->mm);

    while (!kthread_should_stop()) {
        /*
         * Set INTERRUPTIBLE state before to check if there is work.
         * if wake_up() is called, although we have not seen the new
         * counter value, the kthread state is set to RUNNING and
         * after schedule() it is not moved off run queue.
         */
        set_current_state(TASK_INTERRUPTIBLE);

        //spin_lock_irq(&ptk->worker_lock);
        new_scheduled = ptk->scheduled;
        //spin_unlock_irq(&ptk->worker_lock);

        /* checks if there is a pending notification */
        if (new_scheduled != old_scheduled) {
            old_scheduled = new_scheduled;
            __set_current_state(TASK_RUNNING);
            ctx->worker_fn(ctx->worker_private); /* worker body */
            if (need_resched())
                schedule();
        } else {
            schedule();
        }
    }

    __set_current_state(TASK_RUNNING);

    unuse_mm(ptk->mm);
    set_fs(oldfs);
    return 0;
}

void inline
ptn_kthread_send_irq(struct ptn_kthread *ptk)
{
    eventfd_signal(ptk->worker_ctx.irq_ctx, 1);
}

static int
ptn_kthread_open_files(struct ptn_kthread *ptk, struct ptn_cfg_ring *ring_cfg)
{
    struct file *file;
    struct ptn_kthread_ctx *wctx = &ptk->worker_ctx;

    file = eventfd_fget(ring_cfg->ioeventfd);
    if (IS_ERR(file))
        return -PTR_ERR(file);
    wctx->ioevent_file = file;

    file = eventfd_fget(ring_cfg->irqfd);
    if (IS_ERR(file))
        goto err;
    wctx->irq_file = file;
    wctx->irq_ctx = eventfd_ctx_fileget(file);


    return 0;
err:
    if (wctx->ioevent_file) {
        fput(wctx->ioevent_file);
        wctx->ioevent_file = NULL;
    }

    return -PTR_ERR(file);
}

static void
ptn_kthread_close_files(struct ptn_kthread *ptk)
{
    struct ptn_kthread_ctx *wctx = &ptk->worker_ctx;

    if (wctx->ioevent_file) {
        fput(wctx->ioevent_file);
        wctx->ioevent_file = NULL;
    }

    if (wctx->irq_file) {
        fput(wctx->irq_file);
        wctx->irq_file = NULL;
        eventfd_ctx_put(wctx->irq_ctx);
        wctx->irq_ctx = NULL;
    }
}

static void
ptn_kthread_init_poll(struct ptn_kthread *ptk, struct ptn_kthread_ctx *ctx)
{
    init_waitqueue_func_entry(&ctx->waitq, ptn_kthread_poll_wakeup);
    init_poll_funcptr(&ctx->poll_table, ptn_kthread_poll_fn);
    ctx->ptk = ptk;
}

static int
ptn_kthread_start_poll(struct ptn_kthread_ctx *ctx, struct file *file)
{
    unsigned long mask;
    int ret = 0;

    if (ctx->waitq_head)
        return 0;
    mask = file->f_op->poll(file, &ctx->poll_table);
    if (mask)
        ptn_kthread_poll_wakeup(&ctx->waitq, 0, 0, (void *)mask);
    if (mask & POLLERR) {
        if (ctx->waitq_head)
            remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ret = EINVAL;
    }
    return ret;
}

static void
ptn_kthread_stop_poll(struct ptn_kthread_ctx *ctx)
{
    if (ctx->waitq_head) {
        remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ctx->waitq_head = NULL;
    }
}

struct ptn_kthread *
ptn_kthread_create(struct ptn_kthread_cfg *cfg)
{
    struct ptn_kthread *ptk = NULL;
    int error;

    ptk = kzalloc(sizeof *ptk, GFP_KERNEL);
    if (!ptk)
        return NULL;

    spin_lock_init(&ptk->worker_lock);
    ptk->worker_ctx.worker_fn = cfg->worker_fn;
    ptk->worker_ctx.worker_private = cfg->worker_private;
    ptk->worker_ctx.type = cfg->type;

    /* open event fd */
    error = ptn_kthread_open_files(ptk, &cfg->ring);
    if (error)
        goto err;

    ptn_kthread_init_poll(ptk, &ptk->worker_ctx);

    return ptk;
err:
    //XXX: set errno?
    kfree(ptk);
    return NULL;
}

int
ptn_kthread_start(struct ptn_kthread *ptk)
{
    int error = 0;

    if (ptk->worker) {
        return EBUSY;
    }

    ptk->mm = get_task_mm(current);
    ptk->worker = kthread_run(ptn_kthread_worker, ptk, "ptn_kthread-%s-%d",
            ptk->worker_ctx.type == PTK_RX ? "RX" : "TX", current->pid);
    if (IS_ERR(ptk->worker)) {
	error = -PTR_ERR(ptk->worker);
	goto err;
    }

    error = ptn_kthread_start_poll(&ptk->worker_ctx, ptk->worker_ctx.ioevent_file);
    if (error) {
        goto err_kstop;
    }

    return 0;
err_kstop:
    kthread_stop(ptk->worker);
err:
    ptk->worker = NULL;
    if (ptk->mm)
        mmput(ptk->mm);
    ptk->mm = NULL;
    return error;
}

void
ptn_kthread_stop(struct ptn_kthread *ptk)
{
    if (!ptk->worker) {
        return;
    }

    ptn_kthread_stop_poll(&ptk->worker_ctx);

    if (ptk->worker) {
        kthread_stop(ptk->worker);
        ptk->worker = NULL;
    }

    if (ptk->mm) {
        mmput(ptk->mm);
        ptk->mm = NULL;
    }
}

void
ptn_kthread_delete(struct ptn_kthread *ptk)
{
    if (!ptk)
        return;

    if (ptk->worker) {
        ptn_kthread_stop(ptk);
    }

    ptn_kthread_close_files(ptk);

    kfree(ptk);
}
