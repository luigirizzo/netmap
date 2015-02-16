#ifndef __PTNETMAP_VHOST_H
#define __PTNETMAP_VHOST_H

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

struct ptn_vhost_work;
typedef void (*ptn_vhost_work_fn_t)(struct ptn_vhost_work *work);

struct ptn_vhost_work {
    struct list_head    node;
    ptn_vhost_work_fn_t       fn;
    wait_queue_head_t   done;
    int                 flushing;
    unsigned            queue_seq;
    unsigned            done_seq;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct ptn_vhost_poll {
    poll_table          table;
    wait_queue_head_t   *wqh;
    wait_queue_t        wait;
    struct ptn_vhost_work     work;
    unsigned long       mask;
    struct ptn_vhost_dev      *dev;
};


void ptn_vhost_work_init(struct ptn_vhost_work *work, ptn_vhost_work_fn_t fn);
void ptn_vhost_work_queue(struct ptn_vhost_dev *dev, struct ptn_vhost_work *work);

void ptn_vhost_poll_init(struct ptn_vhost_poll *poll, ptn_vhost_work_fn_t fn,
        unsigned long mask, struct ptn_vhost_dev *dev);
int ptn_vhost_poll_start(struct ptn_vhost_poll *poll, struct file *file);
void ptn_vhost_poll_stop(struct ptn_vhost_poll *poll);
void ptn_vhost_poll_flush(struct ptn_vhost_poll *poll);
void ptn_vhost_poll_queue(struct ptn_vhost_poll *poll);

struct writeback_info {
    uint8_t *addr;
    uint8_t value;
};

struct ptn_vhost_ring;

/* The ptn_vhost_ring structure describes a queue attached to a device. */
struct ptn_vhost_ring {
    struct ptn_vhost_dev      *dev;

    struct mutex        mutex;
    struct file         *kick;
    struct file         *call;
    struct eventfd_ctx  *call_ctx;
    struct file         *resample;
    struct eventfd_ctx  *resample_ctx;

    struct ptn_vhost_poll     poll;

    /* The routine to call when the Guest pings us, or timeout. */
    ptn_vhost_work_fn_t       handle_kick;

    /* Protected by virtual ring mutex. */
    void        *private_data;
};

struct ptn_vhost_dev {
    struct mm_struct *mm;
    struct mutex mutex;
    struct ptn_vhost_ring * tx_ring;
    struct ptn_vhost_ring * rx_ring;
    struct ptn_vhost_ring * rings[2];
    spinlock_t work_lock;
    struct list_head work_list;
    struct task_struct *worker;
};

long ptn_vhost_dev_init(struct ptn_vhost_dev *, struct ptn_vhost_ring *, struct ptn_vhost_ring *);
void ptn_vhost_dev_cleanup(struct ptn_vhost_dev *);
void ptn_vhost_dev_stop(struct ptn_vhost_dev *);
int ptn_vhost_vr_access_ok(struct ptn_vhost_ring *vr);
long ptn_vhost_dev_set_owner(struct ptn_vhost_dev *dev);

#endif /* __PTNETMAP_VHOST_H */
