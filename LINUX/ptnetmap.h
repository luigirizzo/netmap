/*
 * XXX: this header must be included in netmap_kern.h
 */
#ifndef __PTNETMAP_H
#define __PTNETMAP_H

/* ptnetmap kthread type */
enum ptn_kthread_t { PTK_RX = 0, PTK_TX = 1 };

/* ptnetmap kthread - opaque */
struct ptn_kthread;

typedef void (*ptn_kthread_worker_fn_t)(void *data);

/* ptnetmap kthread configuration */
struct ptn_kthread_cfg {
    enum ptn_kthread_t type;            /* kthread TX or RX */
    struct ptn_cfg_ring ring;           /* ring event fd */
    ptn_kthread_worker_fn_t worker_fn;  /* worker function */
    void *worker_private;               /* worker parameter */
};

struct ptn_kthread *ptn_kthread_create(struct ptn_kthread_cfg *);
int ptn_kthread_start(struct ptn_kthread *);
void ptn_kthread_stop(struct ptn_kthread *);
void ptn_kthread_delete(struct ptn_kthread *);

void ptn_kthread_wakeup_worker(struct ptn_kthread *ptk);
void ptn_kthread_send_irq(struct ptn_kthread *);

#endif /* __PTNETMAP_H */
