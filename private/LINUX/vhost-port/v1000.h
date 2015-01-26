#ifndef _VHOST_H
#define _VHOST_H

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


struct v1000_work;
typedef void (*v1000_work_fn_t)(struct v1000_work *work);

struct v1000_work {
    struct list_head	  node;
    v1000_work_fn_t		  fn;
    wait_queue_head_t	  done;
    int			  flushing;
    unsigned		  queue_seq;
    unsigned		  done_seq;
};

/* Poll a file (eventfd or socket) */
/* Note: there's nothing vhost specific about this structure. */
struct v1000_poll {
    poll_table                table;
    wait_queue_head_t        *wqh;
    wait_queue_t              wait;
    struct v1000_work	  work;
    unsigned long		  mask;
    struct v1000_dev	 *dev;
};

void v1000_work_init(struct v1000_work *work, v1000_work_fn_t fn);
void v1000_work_queue(struct v1000_dev *dev, struct v1000_work *work);

void v1000_poll_init(struct v1000_poll *poll, v1000_work_fn_t fn,
	unsigned long mask, struct v1000_dev *dev);
int v1000_poll_start(struct v1000_poll *poll, struct file *file);
void v1000_poll_stop(struct v1000_poll *poll);
void v1000_poll_flush(struct v1000_poll *poll);
void v1000_poll_queue(struct v1000_poll *poll);

struct writeback_info {
    uint8_t * addr;
    uint8_t value;
};

struct v1000_ring;

/* The v1000_ring structure describes a queue attached to a device. */
struct v1000_ring {
    struct v1000_dev *dev;

    struct mutex mutex;
    struct file *kick;
    struct file *call;
    struct eventfd_ctx *call_ctx;
    struct file *resample;
    struct eventfd_ctx *resample_ctx;

    struct v1000_poll poll;

    /* The routine to call when the Guest pings us, or timeout. */
    v1000_work_fn_t handle_kick;

    struct iovec iov[UIO_MAXIOV];

    struct writeback_info wb[UIO_MAXIOV];

    /* Protected by virtual ring mutex. */
    void *private_data;
};

struct v1000_dev {
    /* Readers use RCU to access memory table pointer
     * log base pointer and features.
     * Writers use mutex below.*/
    struct V1000Translation __rcu *memory;
    struct mm_struct *mm;
    struct mutex mutex;
    struct v1000_ring * tx_ring;
    struct v1000_ring * rx_ring;
    struct v1000_ring * rings[2];
    spinlock_t work_lock;
    struct list_head work_list;
    struct task_struct *worker;
};

long v1000_dev_init(struct v1000_dev *, struct v1000_ring *, struct v1000_ring *);
void v1000_dev_cleanup(struct v1000_dev *);
void v1000_dev_stop(struct v1000_dev *);
int v1000_vr_access_ok(struct v1000_ring *vr);
long v1000_dev_set_owner(struct v1000_dev *dev);


#include "v1000_user.h"

#endif
