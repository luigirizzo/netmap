#ifndef __VPT_H
#define __VPT_H

#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/atomic.h>

struct vPT_work;
typedef void (*vPT_work_fn_t)(struct vPT_work *work);

struct vPT_work {
    struct list_head    node;
    vPT_work_fn_t       fn;
    wait_queue_head_t   done;
    int                 flushing;
    unsigned            queue_seq;
    unsigned            done_seq;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct vPT_poll {
    poll_table          table;
    wait_queue_head_t   *wqh;
    wait_queue_t        wait;
    struct vPT_work     work;
    unsigned long       mask;
    struct vPT_dev      *dev;
};


void vPT_work_init(struct vPT_work *work, vPT_work_fn_t fn);
void vPT_work_queue(struct vPT_dev *dev, struct vPT_work *work);

void vPT_poll_init(struct vPT_poll *poll, vPT_work_fn_t fn,
        unsigned long mask, struct vPT_dev *dev);
int vPT_poll_start(struct vPT_poll *poll, struct file *file);
void vPT_poll_stop(struct vPT_poll *poll);
void vPT_poll_flush(struct vPT_poll *poll);
void vPT_poll_queue(struct vPT_poll *poll);

struct writeback_info {
    uint8_t *addr;
    uint8_t value;
};

struct vPT_ring;

/* The vPT_ring structure describes a queue attached to a device. */
struct vPT_ring {
    struct vPT_dev      *dev;

    struct mutex        mutex;
    struct file         *kick;
    struct file         *call;
    struct eventfd_ctx  *call_ctx;
    struct file         *resample;
    struct eventfd_ctx  *resample_ctx;

    struct vPT_poll     poll;

    /* The routine to call when the Guest pings us, or timeout. */
    vPT_work_fn_t       handle_kick;

    /* Protected by virtual ring mutex. */
    void        *private_data;
};

struct vPT_dev {
    struct mm_struct *mm;
    struct mutex mutex;
    struct vPT_ring * tx_ring;
    struct vPT_ring * rx_ring;
    struct vPT_ring * rings[2];
    spinlock_t work_lock;
    struct list_head work_list;
    struct task_struct *worker;
};

long vPT_dev_init(struct vPT_dev *, struct vPT_ring *, struct vPT_ring *);
void vPT_dev_cleanup(struct vPT_dev *);
void vPT_dev_stop(struct vPT_dev *);
int vPT_vr_access_ok(struct vPT_ring *vr);
long vPT_dev_set_owner(struct vPT_dev *dev);


#include "vhost_netmap_pt_user.h"


#endif /* __VPT_H */
