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
        if (likely(new_scheduled != old_scheduled)) {
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

/* ptnetmap mem device
 *
 * Used to expose host memory to the guest
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

/* XXX: move */
#define PTN_MEMDEV_NAME "ptnetmap-memdev"

/* XXX: move to pci_ids.h */
#define PCI_VENDOR_ID_PTNETMAP  0x3333
#define PCI_DEVICE_ID_PTNETMAP  0x0001

/* XXX: move */
#define PTNETMAP_IO_PCI_BAR         0
#define PTNETMAP_MEM_PCI_BAR        1

/* register XXX: move */

/* 32 bit r/o */
#define PTNETMAP_IO_PCI_FEATURES        0

/* 32 bit r/o */
#define PTNETMAP_IO_PCI_MEMSIZE         4

/* 16 bit r/o */
#define PTNETMAP_IO_PCI_HOSTID          8

#define PTNEMTAP_IO_SIZE                10

/*
 * PCI Device ID Table
 * list of (VendorID,DeviceID) supported by this driver
 */
static struct pci_device_id ptn_memdev_ids[] = {
    { PCI_DEVICE(PCI_VENDOR_ID_PTNETMAP, PCI_DEVICE_ID_PTNETMAP), },
    { 0, }
};

MODULE_DEVICE_TABLE(pci, ptn_memdev_ids);

/*
 * ptnetmap_memdev private data structure
 */
struct ptnetmap_memdev
{
    struct pci_dev *pdev;
    void __iomem *io_addr;
    void __iomem *mem_addr;
    struct netmap_mem_d *nm_mem;
    int bars;
};

/*
 * map netmap allocator through PCI-BAR in the guest OS
 */
int
netmap_pt_memdev_iomap(struct ptnetmap_memdev *ptn_dev, vm_paddr_t *nm_paddr, void **nm_addr)
{
    struct pci_dev *pdev = ptn_dev->pdev;
    uint32_t mem_size;
    phys_addr_t mem_paddr;
    int err = 0;

    mem_size = ioread32(ptn_dev->io_addr + PTNETMAP_IO_PCI_MEMSIZE);

    D("=== BAR %d start %llx len %llx mem_size %x ===",
            PTNETMAP_MEM_PCI_BAR,
            pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
            pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR),
            mem_size);

    /* map memory allocator */
    mem_paddr = pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR);
    ptn_dev->mem_addr = *nm_addr = ioremap_cache(mem_paddr, mem_size);
    if (ptn_dev->mem_addr == NULL) {
        err = -ENOMEM;
    }
    *nm_paddr = mem_paddr;

    return err;
}

/*
 * unmap PCI-BAR
 */
void
netmap_pt_memdev_iounmap(struct ptnetmap_memdev *ptn_dev)
{
    if (ptn_dev->mem_addr) {
        iounmap(ptn_dev->mem_addr);
        ptn_dev->mem_addr = NULL;
    }
}

/*
 * Device Initialization Routine
 *
 * Returns 0 on success, negative on failure
 */
static int
ptn_memdev_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct ptnetmap_memdev *ptn_dev;
    int bars, err;
    uint16_t mem_id;

    ND("ptn_memdev_driver probe");

    /* allocate our structure and fill it out */
    ptn_dev = kzalloc(sizeof(*ptn_dev), GFP_KERNEL);
    if (ptn_dev == NULL)
        return -ENOMEM;

    ptn_dev->pdev = pdev;
    bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
    /* enable the device */
    err = pci_enable_device(pdev); /* XXX-ste: device_mem() */
    if (err)
        goto err;

    err = pci_request_selected_regions(pdev, bars, PTN_MEMDEV_NAME);
    if (err)
        goto err_pci_reg;

    ptn_dev->io_addr = pci_iomap(pdev, PTNETMAP_IO_PCI_BAR, 0);
    if (ptn_dev->io_addr == NULL) {
        err = -ENOMEM;
        goto err_iomap;
    }
    pci_set_drvdata(pdev, ptn_dev);
    pci_set_master(pdev); /* XXX-ste: is needed??? */

    ptn_dev->bars = bars;
    mem_id = ioread16(ptn_dev->io_addr + PTNETMAP_IO_PCI_HOSTID);

    /* Create guest allocator */
    ptn_dev->nm_mem = netmap_mem_pt_guest_create(ptn_dev, mem_id);
    if (ptn_dev->nm_mem == NULL) {
        err = -ENOMEM;
        goto err_nmd_create;
    }
    netmap_mem_get(ptn_dev->nm_mem);

    ND("ptn_memdev_driver probe OK");

    return 0;

err_nmd_create:
    pci_set_drvdata(pdev, NULL);
    iounmap(ptn_dev->io_addr);
err_iomap:
    pci_release_selected_regions(pdev, bars);
err_pci_reg:
    pci_disable_device(pdev);
err:
    kfree(ptn_dev);
    return err;
}

/*
 * Device Removal Routine
 */
static void
ptn_memdev_remove(struct pci_dev *pdev)
{
    struct ptnetmap_memdev *ptn_dev = pci_get_drvdata(pdev);

    ND("ptn_memdev_driver remove");
    if (ptn_dev->nm_mem) {
        netmap_mem_put(ptn_dev->nm_mem);
    }
    if (ptn_dev->mem_addr) {
        iounmap(ptn_dev->mem_addr);
    }
    pci_set_drvdata(pdev, NULL);
    iounmap(ptn_dev->io_addr);
    pci_release_selected_regions(pdev, ptn_dev->bars);
    pci_disable_device(pdev);
    kfree(ptn_dev);
}

/*
 * pci driver information
 */
static struct pci_driver ptn_memdev_driver = {
    .name       = PTN_MEMDEV_NAME,
    .id_table   = ptn_memdev_ids,
    .probe      = ptn_memdev_probe,
    .remove     = ptn_memdev_remove,
};

/*
 * Driver Registration Routine
 *
 * Returns 0 on success, negative on failure
 */
int
netmap_pt_memdev_init(void)
{
    int ret;

    /* register pci driver */
    ret = pci_register_driver(&ptn_memdev_driver);
    if (ret < 0) {
        D("ptn-driver register error");
        return ret;
    }
    return 0;
}

/*
 * Driver Exit Cleanup Routine
 */
void
netmap_pt_memdev_uninit(void)
{
    /* unregister pci driver */
    pci_unregister_driver(&ptn_memdev_driver);

    D("ptn_memdev_driver exit");
}
