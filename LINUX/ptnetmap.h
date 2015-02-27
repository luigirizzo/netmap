/*
 * XXX: this header must be included in netmap_kern.h
 */
#ifndef __PTNETMAP_H
#define __PTNETMAP_H

#include <dev/netmap/paravirt.h>

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

/* Functions to read and write CSB fields */
#define CSB_READ(csb, field, r) (get_user(r, &csb->field))
#define CSB_WRITE(csb, field, v) (put_user(v, &csb->field))

static inline uint32_t
nm_sub(uint32_t l_elem, uint32_t r_elem, uint32_t num_slots)
{
    int64_t res;

    res = (int64_t)(l_elem) - r_elem;

    return (res < 0) ? res + num_slots : res;
}

/*
 * HOST read/write kring pointers from/in CSB
 */

/* Host: Read kring pointers (head, cur, sync_flags) from CSB */
static inline void
ptnetmap_host_read_kring_csb(struct pt_ring __user *ptr, uint32_t *g_head,
        uint32_t *g_cur, uint32_t *g_flags, uint32_t num_slots)
{
    uint32_t old_head = *g_head, old_cur = *g_cur;
    uint32_t d, inc_h, inc_c;

    //mb(); /* Force memory complete before read CSB */

    /*
     * We must first read head and then cur with a barrier in the
     * middle, because cur can exceed head, but not vice versa.
     * The guest must first write cur and then head with a barrier.
     *
     * head <= cur
     *
     *          guest           host
     *
     *          STORE(cur)      LOAD(head)
     *            mb() ----------- mb()
     *          STORE(head)     LOAD(cur)
     *
     * This approach ensures that every head that we read is
     * associated with the correct cur. In this way head can not exceed cur.
     */
    CSB_READ(ptr, head, *g_head);
    mb();
    CSB_READ(ptr, cur, *g_cur);
    CSB_READ(ptr, sync_flags, *g_flags);
    /*
     * The previous barrier does not avoid to read an update cur and an old
     * head. For this reason, we have to check that the new cur not overtaking head.
     */
    d = nm_sub(old_cur, old_head, num_slots);     /* previous distance */
    inc_c = nm_sub(*g_cur, old_cur, num_slots);   /* increase of cur */
    inc_h = nm_sub(*g_head, old_head, num_slots); /* increase of head */

    if (unlikely(inc_c > num_slots - d + inc_h)) { /* cur overtakes head */
        ND(1,"ERROR cur overtakes head - old_cur: %u cur: %u old_head: %u head: %u",
                old_cur, *g_cur, old_head, *g_head);
        *g_cur = nm_prev(*g_head, num_slots - 1);
        //*g_cur = *g_head;
    }
}

/* Host: Write kring pointers (hwcur, hwtail) into the CSB */
static inline void
ptnetmap_host_write_kring_csb(struct pt_ring __user *ptr, uint32_t hwcur,
        uint32_t hwtail)
{
    /* We must write hwtail before hwcur for sync reason. */
    CSB_WRITE(ptr, hwtail, hwtail);
    mb();
    CSB_WRITE(ptr, hwcur, hwcur);

    //mb(); /* Force memory complete before send notification */
}

/*
 * GUEST read/write kring pointers from/in CSB.
 * To use into device driver.
 */

/* Guest: Write kring pointers (cur, head) into the CSB */
static inline void
ptnetmap_guest_write_kring_csb(struct pt_ring *ptr, uint32_t cur,
        uint32_t head)
{
    /* We must write cur before head for sync reason (ref. ptnetmap.c) */
    ptr->cur = cur;
    mb();
    ptr->head = head;

    //mb(); /* Force memory complete before send notification */
}

/* Guest: Read kring pointers (hwcur, hwtail) from CSB */
static inline void
ptnetmap_guest_read_kring_csb(struct pt_ring *ptr, uint32_t *h_hwcur,
        uint32_t *h_hwtail, uint32_t num_slots)
{
    uint32_t old_hwcur = *h_hwcur, old_hwtail = *h_hwtail;
    uint32_t d, inc_hc, inc_ht;

    //mb(); /* Force memory complete before read CSB */

    /*
     * We must first read hwcur and then hwtail with a barrier in the
     * middle, because hwtail can exceed hwcur, but not vice versa.
     * The host must first write hwtail and then hwcur with a barrier.
     *
     * hwcur <= hwtail
     *
     *          host            guest
     *
     *          STORE(hwtail)   LOAD(hwcur)
     *            mb()  ---------  mb()
     *          STORE(hwcur)    LOAD(hwtail)
     *
     * This approach ensures that every hwcur that the guest reads is
     * associated with the correct hwtail. In this way hwcur can not exceed hwtail.
     */
    *h_hwcur = ptr->hwcur;
    mb();
    *h_hwtail = ptr->hwtail;

    /*
     * The previous barrier does not avoid to read an update hwtail and an old
     * hwcur. For this reason, we have to check that the new hwtail not overtaking hwcur.
     */
    d = nm_sub(old_hwtail, old_hwcur, num_slots);       /* previous distance */
    inc_ht = nm_sub(*h_hwtail, old_hwtail, num_slots);  /* increase of hwtail */
    inc_hc = nm_sub(*h_hwcur, old_hwcur, num_slots);    /* increase of hwcur */

    if (unlikely(inc_ht > num_slots - d + inc_hc)) {
        ND(1, "ERROR hwtail overtakes hwcur - old_hwtail: %u hwtail: %u old_hwcur: %u hwcur: %u",
                old_hwtail, *h_hwtail, old_hwcur, *h_hwcur);
        *h_hwtail = nm_prev(*h_hwcur, num_slots - 1);
        //*h_hwtail = *h_hwcur;
    }
}
#endif /* __PTNETMAP_H */
