/*
 * Copyright (C) 2013 Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 Support for virtio-like communication between host (H) and guest (G) NICs.

 The guest allocates the shared Communication Status Block (csb) and
 write its physical address at CSBAL and CSBAH (data is little endian).
 csb->csb_on enables the mode. If disabled, the device acts a regular one.

 Notifications for tx and rx are exchanged without vm exits
 if possible. In particular (only mentioning csb mode below),
 the following actions are performed. In the description below,
 "double check" means verifying again the condition that caused
 the previous action, and reverting the action if the condition has
 changed. The condition typically depends on a variable set by the
 other party, and the double check is done to avoid races. E.g.

	// start with A=0
    again:
	// do something
	if ( cond(C) ) { // C is written by the other side
	    A = 1;
	    // barrier
	    if ( !cond(C) ) {
		A = 0;
		goto again;
	    }
	}

 TX: start from idle:
    H starts with host_need_txkick=1 when the I/O thread bh is idle. Upon new
    transmissions, G always updates guest_tdt.  If host_need_txkick == 1,
    G also writes to the TDT, which acts as a kick to H (so pending
    writes are always dispatched to H as soon as possible.)

 TX: active state:
    On the kick (TDT write) H sets host_need_txkick == 0 (if not
    done already by G), and starts an I/O thread trying to consume
    packets from TDH to guest_tdt, periodically refreshing host_tdh
    and TDH.  When host_tdh == guest_tdt, H sets host_need_txkick=1,
    and then does the "double check" for race avoidance.

 TX: G runs out of buffers
    XXX there are two mechanisms, one boolean (using guest_need_txkick)
    and one with a threshold (using guest_txkick_at). They are mutually
    exclusive.
    BOOLEAN: when G has no space, it sets guest_need_txkick=1 and does
        the double check. If H finds guest_need_txkick== 1 on a write
        to TDH, it also generates an interrupt.
    THRESHOLD: G sets guest_txkick_at to the TDH value for which it
	wants to receive an interrupt. When H detects that TDH moves
	across guest_txkick_at, it generates an interrupt.
	This second mechanism reduces the number of interrupts and
	TDT writes on the transmit side when the host is too slow.

 RX: start from idle
    G starts with guest_need_rxkick = 1 when the receive ring is empty.
    As packets arrive, H updates host_rdh (and RDH) and also generates an
    interrupt when guest_need_rxkick == 1 (so incoming packets are
    always reported to G as soon as possible, apart from interrupt
    moderation delays). It also tracks guest_rdt for new buffers.

 RX: active state
    As the interrupt arrives, G sets guest_need_rxkick = 0 and starts
    draining packets from the receive ring, while updating guest_rdt
    When G runs out of packets it sets guest_need_rxkick=1 and does the
    double check.

 RX: H runs out of buffers
    XXX there are two mechanisms, one boolean (using host_need_rxkick)
    and one with a threshold (using host_xxkick_at). They are mutually
    exclusive.
    BOOLEAN: when H has no space, it sets host_need_rxkick=1 and does the
	double check. If G finds host_need_rxkick==1 on updating guest_rdt,
        it also writes to RDT causing a kick to H.
    THRESHOLD: H sets host_rxkick_at to the RDT value for which it wants
	to receive a kick. When G detects that guest_rdt moves across
	host_rxkick_at, it writes to RDT thus generates a kick.
	This second mechanism reduces the number of kicks and
        RDT writes on the receive side when the guest is too slow and
	would free only a few buffers at a time.

 */

#if !defined(NETMAP_VIRT_CSB) /*&& !defined(NET_PARAVIRT_CSB_SIZE) XXX: NET_PARAVIRT_CSB_SIZE to avoid oldest CSB */
#define NETMAP_VIRT_CSB

struct pt_ring {
    uint32_t head;
    uint32_t cur;
    uint32_t hwcur;
    uint32_t hwtail;
    uint32_t sync_flags;
};

struct paravirt_csb {
    /* XXX revise the layout to minimize cache bounces.
     * Usage is described as follows:
     * 	[GH][RW][+-0]	guest/host reads/writes frequently/rarely/almost never
     */
    /* these are (mostly) written by the guest */
    uint32_t guest_tdt;            /* GW+ HR+ pkt to transmit */
    uint32_t guest_need_txkick;    /* GW- HR+ G ran out of tx bufs, request kick */
    uint32_t guest_need_rxkick;    /* GW- HR+ G ran out of rx pkts, request kick  */
    uint32_t guest_csb_on;         /* GW- HR+ enable paravirtual mode */
    uint32_t guest_rdt;            /* GW+ HR+ rx buffers available */
    uint32_t guest_txkick_at;      /* GW- HR+ tx ring pos. where G expects an intr */
    uint32_t guest_use_msix;        /* GW0 HR0 guest uses MSI-X interrupts. */
    uint32_t pad[9];

    /* these are (mostly) written by the host */
    uint32_t host_tdh;             /* GR0 HW- shadow register, mostly unused */
    uint32_t host_need_txkick;     /* GR+ HW- start the iothread */
    uint32_t host_txcycles_lim;    /* GW- HR- how much to spin before  sleep.
				    * set by the guest */
    uint32_t host_txcycles;        /* GR0 HW- counter, but no need to be exported */
    uint32_t host_rdh;             /* GR0 HW- shadow register, mostly unused */
    uint32_t host_need_rxkick;     /* GR+ HW- flush rx queued packets */
    uint32_t host_isr;             /* GR* HW* shadow copy of ISR */
    uint32_t host_rxkick_at;       /* GR+ HW- rx ring pos where H expects a kick */
    uint32_t vnet_ring_high;	/* Vnet ring physical address high. */
    uint32_t vnet_ring_low;	/* Vnet ring physical address low. */

    /* passthrough */
    uint32_t nifp_offset;          /* offset of the netmap_if in the shared memory */
    /* uint16_t host_mem_id; */
    uint16_t num_tx_rings;
    uint16_t num_rx_rings;
    uint16_t num_tx_slots;
    uint16_t num_rx_slots;

    struct pt_ring tx_ring;
    struct pt_ring rx_ring;
};

#define NET_PARAVIRT_CSB_SIZE   4096
#define NET_PARAVIRT_NONE   (~((uint32_t)0))

#define NET_PTN_FEATURES_BASE            1
#define NET_PTN_FEATURES_FULL            2

/* passthrough commands */
#define NET_PARAVIRT_PTCTL_CONFIG	1
#define NET_PARAVIRT_PTCTL_FINALIZE	2
#define NET_PARAVIRT_PTCTL_IFNEW	3
#define NET_PARAVIRT_PTCTL_IFDELETE	4
#define NET_PARAVIRT_PTCTL_RINGSCREATE	5
#define NET_PARAVIRT_PTCTL_RINGSDELETE	6
#define NET_PARAVIRT_PTCTL_DEREF	7
#define NET_PARAVIRT_PTCTL_TXSYNC	8
#define NET_PARAVIRT_PTCTL_RXSYNC	9
#define NET_PARAVIRT_PTCTL_REGIF        10
#define NET_PARAVIRT_PTCTL_UNREGIF      11
#define NET_PARAVIRT_PTCTL_HOSTMEMID	12

/*
 * Structures used for ptnetmap configuration
 */
struct ptnetmap_cfg_ring {
	uint32_t ioeventfd;
	uint32_t irqfd;
};

/*
 * struct ptnetmap_cfg overlaps struct nmreq
 * from nr_offset field, but nr_cmd is required in netmap_ioctl()
 * For this reason this condition must be true:
 * offsetof(struct ptnetmap_cfg, nr_cmd) ==
 * (offsetof(struct nmreq, nr_cmd) - offsetof(struct nmreq , nr_offset))
 */
struct ptnetmap_cfg {
        uint32_t features;
#define PTNETMAP_CFG_FEAT_CSB           0x0001
#define PTNETMAP_CFG_FEAT_EVENTFD       0x0002
	struct ptnetmap_cfg_ring tx_ring;
	struct ptnetmap_cfg_ring rx_ring;
	uint8_t pad[2];                 /* padding to overlap strct nmreq */
	uint16_t nr_cmd;                /* needed in netmap_ioctl() */
        void *csb;   /* CSB */
};

#ifdef	QEMU_PCI_H

/*
 * API functions only available within QEMU
 */

void paravirt_configure_csb(struct paravirt_csb** csb, uint32_t csbbal,
			uint32_t csbbah, QEMUBH* tx_bh, AddressSpace *as);

#endif /* QEMU_PCI_H */

#endif /* NETMAP_VIRT_CSB */

#if defined(NETMAP_API) && !defined(NETMAP_VIRT_PTNETMAP)
#define NETMAP_VIRT_PTNETMAP

#ifndef CTASSERT
#ifndef BUILD_BUG_ON_ZERO
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#endif /* BUILD_BUG_ON_ZERO */
#define CTASSERT(e) ((void)BUILD_BUG_ON_ZERO(!(e)))
#endif /* CTASSERT */

/*
 * Functions used to read/write ptnetmap_cfg in the nmreq,
 * between the fields nm_offset and nr_cmd.
 */
static inline void
ptnetmap_write_cfg(struct nmreq *nmr, struct ptnetmap_cfg *cfg)
{
#ifdef CTASSERT
CTASSERT(offsetof(struct ptnetmap_cfg, nr_cmd) == (offsetof(struct nmreq, nr_cmd) - offsetof(struct nmreq , nr_offset)));
CTASSERT(sizeof(struct ptnetmap_cfg) <= sizeof(struct nmreq) - offsetof(struct nmreq , nr_offset));
#endif
    memcpy(&nmr->nr_offset, cfg, sizeof(*cfg));
}

static inline void
ptnetmap_read_cfg(struct nmreq *nmr, struct ptnetmap_cfg *cfg)
{
    memcpy(cfg, &nmr->nr_offset, sizeof(*cfg));
}

#if defined (WITH_PTNETMAP_HOST) || defined (WITH_PTNETMAP_GUEST)
static inline uint32_t
ptn_sub(uint32_t l_elem, uint32_t r_elem, uint32_t num_slots)
{
    int64_t res;

    res = (int64_t)(l_elem) - r_elem;

    return (res < 0) ? res + num_slots : res;
}
#endif /* WITH_PTNETMAP_HOST || WITH_PTNETMAP_GUEST */

#ifdef WITH_PTNETMAP_HOST
/* ptnetmap kernel thread routines */
enum ptn_kthread_t { PTK_RX = 0, PTK_TX = 1 }; /* kthread type */
struct ptn_kthread; /* ptnetmap kthread - opaque */
typedef void (*ptn_kthread_worker_fn_t)(void *data);
/* ptnetmap kthread configuration */
struct ptn_kthread_cfg {
    enum ptn_kthread_t type;            /* kthread TX or RX */
    struct ptnetmap_cfg_ring ring;      /* ring event fd */
    ptn_kthread_worker_fn_t worker_fn;  /* worker function */
    void *worker_private;               /* worker parameter */
};
struct ptn_kthread *ptn_kthread_create(struct ptn_kthread_cfg *);
int ptn_kthread_start(struct ptn_kthread *);
void ptn_kthread_stop(struct ptn_kthread *);
void ptn_kthread_delete(struct ptn_kthread *);
void ptn_kthread_wakeup_worker(struct ptn_kthread *ptk);
void ptn_kthread_send_irq(struct ptn_kthread *);

/* Functions to read and write CSB fields in the host */
#if defined (linux)
#define CSB_READ(csb, field, r) (get_user(r, &csb->field))
#define CSB_WRITE(csb, field, v) (put_user(v, &csb->field))
#else /* not linux */
#define CSB_READ(csb, field, r) (r = fuword32(&csb->field))
#define CSB_WRITE(csb, field, v) (suword32(&csb->field, v))
#endif /* linux */

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
    d = ptn_sub(old_cur, old_head, num_slots);     /* previous distance */
    inc_c = ptn_sub(*g_cur, old_cur, num_slots);   /* increase of cur */
    inc_h = ptn_sub(*g_head, old_head, num_slots); /* increase of head */

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

#endif /* WITH_PTNETMAP_HOST */

#ifdef WITH_PTNETMAP_GUEST
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
    d = ptn_sub(old_hwtail, old_hwcur, num_slots);       /* previous distance */
    inc_ht = ptn_sub(*h_hwtail, old_hwtail, num_slots);  /* increase of hwtail */
    inc_hc = ptn_sub(*h_hwcur, old_hwcur, num_slots);    /* increase of hwcur */

    if (unlikely(inc_ht > num_slots - d + inc_hc)) {
        ND(1, "ERROR hwtail overtakes hwcur - old_hwtail: %u hwtail: %u old_hwcur: %u hwcur: %u",
                old_hwtail, *h_hwtail, old_hwcur, *h_hwcur);
        *h_hwtail = nm_prev(*h_hwcur, num_slots - 1);
        //*h_hwtail = *h_hwcur;
    }
}

/* ptnetmap memdev routines */
struct ptnetmap_memdev;
int netmap_pt_memdev_init(void);
void netmap_pt_memdev_uninit(void);
int netmap_pt_memdev_iomap(struct ptnetmap_memdev *, vm_paddr_t *, void **);
void netmap_pt_memdev_iounmap(struct ptnetmap_memdev *);


/* ptnetmap memdev PCI-ID and PCI-BARS */
#define PTN_MEMDEV_NAME                 "ptnetmap-memdev"
#define PTNETMAP_PCI_VENDOR_ID          0x3333  /* XXX-ste: set vendor_id */
#define PTNETMAP_PCI_DEVICE_ID          0x0001
#define PTNETMAP_IO_PCI_BAR             0
#define PTNETMAP_MEM_PCI_BAR            1

/* ptnetmap memdev register */
/* 32 bit r/o */
#define PTNETMAP_IO_PCI_FEATURES        0
/* 32 bit r/o */
#define PTNETMAP_IO_PCI_MEMSIZE         4
/* 16 bit r/o */
#define PTNETMAP_IO_PCI_HOSTID          8
#define PTNEMTAP_IO_SIZE                10
#endif /* WITH_PTNETMAP_GUEST */

#endif /* NETMAP_VIRT_PTNETMAP */
