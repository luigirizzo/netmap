/* Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2006 Rusty Russell IBM Corporation
 *
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * Inspiration, some code, and most witty comments come from
 * Documentation/virtual/lguest/lguest.c, by Rusty Russell
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Generic code for virtio server in host kernel.
 */

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/cgroup.h>

#include "vhost_netmap_pt.h"


static void vPT_poll_func(struct file *file, wait_queue_head_t *wqh,
	poll_table *pt)
{
    struct vPT_poll *poll;

    poll = container_of(pt, struct vPT_poll, table);
    poll->wqh = wqh;
    add_wait_queue(wqh, &poll->wait);
}

static int vPT_poll_wakeup(wait_queue_t *wait, unsigned mode, int sync,
	void *key)
{
    struct vPT_poll *poll = container_of(wait, struct vPT_poll, wait);

    //printk("%p.vPT_poll_wakeup(), %lu, %lu\n",poll,(unsigned long)key, poll->mask);
    if (!((unsigned long)key & poll->mask))
	return 0;

    vPT_poll_queue(poll);
    return 0;
}

void vPT_work_init(struct vPT_work *work, vPT_work_fn_t fn)
{
    INIT_LIST_HEAD(&work->node);
    work->fn = fn;
    init_waitqueue_head(&work->done);
    work->flushing = 0;
    work->queue_seq = work->done_seq = 0;
}

/* Init poll structure */
void vPT_poll_init(struct vPT_poll *poll, vPT_work_fn_t fn,
	unsigned long mask, struct vPT_dev *dev)
{
    init_waitqueue_func_entry(&poll->wait, vPT_poll_wakeup);
    init_poll_funcptr(&poll->table, vPT_poll_func);
    poll->mask = mask;
    poll->dev = dev;
    poll->wqh = NULL;

    vPT_work_init(&poll->work, fn);
}

/* Start polling a file. We add ourselves to file's wait queue. The caller must
 * keep a reference to a file until after vPT_poll_stop is called. */
int vPT_poll_start(struct vPT_poll *poll, struct file *file)
{
    unsigned long mask;
    int ret = 0;

    if (poll->wqh)
        return 0;
    mask = file->f_op->poll(file, &poll->table);
    if (mask)
	vPT_poll_wakeup(&poll->wait, 0, 0, (void *)mask);
    if (mask & POLLERR) {
	if (poll->wqh)
	    remove_wait_queue(poll->wqh, &poll->wait);
	ret = -EINVAL;
    }
    printk("%p.poll_start()\n", poll);
    return ret;
}

/* Stop polling a file. After this function returns, it becomes safe to drop the
 * file reference. You must also flush afterwards. */
void vPT_poll_stop(struct vPT_poll *poll)
{
    if (poll->wqh) {
	remove_wait_queue(poll->wqh, &poll->wait);
	poll->wqh = NULL;
    }
    printk("%p.poll_stop()\n", poll);
}

static bool vPT_work_seq_done(struct vPT_dev *dev, struct vPT_work *work,
	unsigned seq)
{
    int left;

    spin_lock_irq(&dev->work_lock);
    left = seq - work->done_seq;
    spin_unlock_irq(&dev->work_lock);
    return left <= 0;
}

static void vPT_work_flush(struct vPT_dev *dev, struct vPT_work *work)
{
    unsigned seq;
    int flushing;

    spin_lock_irq(&dev->work_lock);
    seq = work->queue_seq;
    work->flushing++;
    spin_unlock_irq(&dev->work_lock);
    wait_event(work->done, vPT_work_seq_done(dev, work, seq));
    spin_lock_irq(&dev->work_lock);
    flushing = --work->flushing;
    spin_unlock_irq(&dev->work_lock);
    BUG_ON(flushing < 0);
}

/* Flush any work that has been scheduled. When calling this, don't hold any
 * locks that are also used by the callback. */
void vPT_poll_flush(struct vPT_poll *poll)
{
    vPT_work_flush(poll->dev, &poll->work);
}

void vPT_work_queue(struct vPT_dev *dev, struct vPT_work *work)
{
    unsigned long flags;

    spin_lock_irqsave(&dev->work_lock, flags);
    if (list_empty(&work->node)) {
	list_add_tail(&work->node, &dev->work_list);
	work->queue_seq++;
	wake_up_process(dev->worker);
    }
    spin_unlock_irqrestore(&dev->work_lock, flags);
}

void vPT_poll_queue(struct vPT_poll *poll)
{
    vPT_work_queue(poll->dev, &poll->work);
}

static void vPT_vr_reset(struct vPT_dev *dev,
	struct vPT_ring *vr)
{
    vr->private_data = NULL;
    vr->kick = NULL;
    vr->call_ctx = NULL;
    vr->call = NULL;
}

static int vPT_worker(void *data)
{
    struct vPT_dev *dev = data;
    struct vPT_work *work = NULL;
    unsigned uninitialized_var(seq);
    mm_segment_t oldfs = get_fs();

    set_fs(USER_DS);
    use_mm(dev->mm);

    for (;;) {
	/* mb paired w/ kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_irq(&dev->work_lock);
	if (work) {
	    work->done_seq = seq;
	    if (work->flushing)
		wake_up_all(&work->done);
	}

	if (kthread_should_stop()) {
	    spin_unlock_irq(&dev->work_lock);
	    __set_current_state(TASK_RUNNING);
	    break;
	}
	if (!list_empty(&dev->work_list)) {
	    work = list_first_entry(&dev->work_list,
		    struct vPT_work, node);
	    list_del_init(&work->node);
	    seq = work->queue_seq;
	} else
	    work = NULL;
	spin_unlock_irq(&dev->work_lock);

	if (work) {
	    __set_current_state(TASK_RUNNING);
	    work->fn(work);
	    if (need_resched())
		schedule();
	} else
	    schedule();

    }
    unuse_mm(dev->mm);
    set_fs(oldfs);
    return 0;
}

long vPT_dev_init(struct vPT_dev * dev, struct vPT_ring * tx_ring,
	struct vPT_ring * rx_ring)
{
    int i;

    dev->rings[0] = dev->tx_ring = tx_ring;
    dev->rings[1] = dev->rx_ring = rx_ring;

    mutex_init(&dev->mutex);
    dev->mm = NULL;
    spin_lock_init(&dev->work_lock);
    INIT_LIST_HEAD(&dev->work_list);
    dev->worker = NULL;

    for (i=0; i<2; i++) {
        if (!(dev->rings[i]))
            continue;

	dev->rings[i]->dev = dev;
	mutex_init(&dev->rings[i]->mutex);
	vPT_vr_reset(dev, dev->rings[i]);
	if (dev->rings[i]->handle_kick)
	    vPT_poll_init(&dev->rings[i]->poll,
		dev->rings[i]->handle_kick, POLLIN, dev);
    }

    return 0;
}

/* Caller should have device mutex */
long vPT_dev_check_owner(struct vPT_dev *dev)
{
    /* Are you the owner? If not, I don't think you mean to do that */
    return dev->mm == current->mm ? 0 : -EPERM;
}

/* Caller should have device mutex */
long vPT_dev_set_owner(struct vPT_dev *dev)
{
    struct task_struct *worker;
    int err;

    /* Is there an owner already? */
    if (dev->mm) {
	err = -EBUSY;
	goto err_mm;
    }

    /* No owner, become one */
    dev->mm = get_task_mm(current);
    if (dev->tx_ring)
        worker = kthread_create(vPT_worker, dev, "vPT-TX-%d", current->pid);
    else if (dev->rx_ring)
        worker = kthread_create(vPT_worker, dev, "vPT-RX-%d", current->pid);

    if (IS_ERR(worker)) {
	err = PTR_ERR(worker);
	goto err_worker;
    }

    dev->worker = worker;
    wake_up_process(worker);	/* avoid contributing to loadavg */


    return 0;
err_worker:
    if (dev->mm)
	mmput(dev->mm);
    dev->mm = NULL;
err_mm:
    return err;
}

void vPT_dev_stop(struct vPT_dev *dev)
{
    int i;

    for (i = 0; i<2; i++) {
	if (dev->rings[i] && dev->rings[i]->kick && dev->rings[i]->handle_kick) {
	    vPT_poll_stop(&dev->rings[i]->poll);
	    vPT_poll_flush(&dev->rings[i]->poll);
	}
    }
}

/* Caller should have device mutex if and only if locked is set */
void vPT_dev_cleanup(struct vPT_dev *dev)
{
    int i;

    for (i = 0; i<2; i++) {
        if (!(dev->rings[i]))
            continue;
	if (dev->rings[i]->kick)
	    fput(dev->rings[i]->kick);
	if (dev->rings[i]->call_ctx)
	    eventfd_ctx_put(dev->rings[i]->call_ctx);
	if (dev->rings[i]->call)
	    fput(dev->rings[i]->call);
	vPT_vr_reset(dev, dev->rings[i]);
    }
    WARN_ON(!list_empty(&dev->work_list));
    if (dev->worker) {
	kthread_stop(dev->worker);
	dev->worker = NULL;
    }
    if (dev->mm)
	mmput(dev->mm);
    dev->mm = NULL;
}

/* This actually signals the guest, using eventfd. */
void vhost_signal(struct vPT_dev *dev, struct vPT_ring *vr)
{
    /* Signal the Guest tell them we used something up. */
    if (vr->call_ctx)
	eventfd_signal(vr->call_ctx, 1);
}

