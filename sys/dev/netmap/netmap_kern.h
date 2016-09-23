/*
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/netmap_kern.h 238985 2012-08-02 11:59:43Z luigi $
 *
 * The header contains the definitions of constants and function
 * prototypes used only in kernelspace.
 */

#ifndef _NET_NETMAP_KERN_H_
#define _NET_NETMAP_KERN_H_

#if defined(linux)

#if  defined(CONFIG_NETMAP_VALE)
#define WITH_VALE
#endif
#if defined(CONFIG_NETMAP_PIPE)
#define WITH_PIPES
#endif
#if defined(CONFIG_NETMAP_MONITOR)
#define WITH_MONITOR
#endif
#if defined(CONFIG_NETMAP_GENERIC)
#define WITH_GENERIC
#endif
#if defined(CONFIG_NETMAP_PTNETMAP_GUEST)
#define WITH_PTNETMAP_GUEST
#endif
#if defined(CONFIG_NETMAP_PTNETMAP_HOST)
#define WITH_PTNETMAP_HOST
#endif

#elif defined (_WIN32)
#define WITH_VALE	// comment out to disable VALE support
#define WITH_PIPES
#define WITH_MONITOR
#define WITH_GENERIC

#else	/* neither linux nor windows */
#define WITH_VALE	// comment out to disable VALE support
#define WITH_PIPES
#define WITH_MONITOR
#define WITH_GENERIC
#define WITH_PTNETMAP_HOST	/* ptnetmap host support */
#define WITH_PTNETMAP_GUEST	/* ptnetmap guest support */

#endif

#if defined(__FreeBSD__)

#define likely(x)	__builtin_expect((long)!!(x), 1L)
#define unlikely(x)	__builtin_expect((long)!!(x), 0L)
#define __user

#define	NM_LOCK_T	struct mtx	/* low level spinlock, used to protect queues */

#define NM_MTX_T	struct sx	/* OS-specific mutex (sleepable) */
#define NM_MTX_INIT(m)		sx_init(&(m), #m)
#define NM_MTX_DESTROY(m)	sx_destroy(&(m))
#define NM_MTX_LOCK(m)		sx_xlock(&(m))
#define NM_MTX_UNLOCK(m)	sx_xunlock(&(m))
#define NM_MTX_ASSERT(m)	sx_assert(&(m), SA_XLOCKED)

#define	NM_SELINFO_T	struct nm_selinfo
#define NM_SELRECORD_T	struct thread
#define	MBUF_LEN(m)	((m)->m_pkthdr.len)
#define MBUF_TXQ(m)	((m)->m_pkthdr.flowid)
#define MBUF_TRANSMIT(na, ifp, m)	((na)->if_transmit(ifp, m))
#define	GEN_TX_MBUF_IFP(m)	((m)->m_pkthdr.rcvif)

#define NM_ATOMIC_T	volatile int	// XXX ?
/* atomic operations */
#include <machine/atomic.h>
#define NM_ATOMIC_TEST_AND_SET(p)       (!atomic_cmpset_acq_int((p), 0, 1))
#define NM_ATOMIC_CLEAR(p)              atomic_store_rel_int((p), 0)

#if __FreeBSD_version >= 1100030
#define	WNA(_ifp)	(_ifp)->if_netmap
#else /* older FreeBSD */
#define	WNA(_ifp)	(_ifp)->if_pspare[0]
#endif /* older FreeBSD */

#if __FreeBSD_version >= 1100005
struct netmap_adapter *netmap_getna(if_t ifp);
#endif

#if __FreeBSD_version >= 1100027
#define MBUF_REFCNT(m)		((m)->m_ext.ext_cnt ? *((m)->m_ext.ext_cnt) : -1)
#define SET_MBUF_REFCNT(m, x)   *((m)->m_ext.ext_cnt) = x
#define PNT_MBUF_REFCNT(m)      ((m)->m_ext.ext_cnt)
#else
#define MBUF_REFCNT(m)		((m)->m_ext.ref_cnt ? *((m)->m_ext.ref_cnt) : -1)
#define SET_MBUF_REFCNT(m, x)   *((m)->m_ext.ref_cnt) = x
#define PNT_MBUF_REFCNT(m)      ((m)->m_ext.ref_cnt)
#endif

#define MBUF_QUEUED(m)		1

struct nm_selinfo {
	struct selinfo si;
	struct mtx m;
};


// XXX linux struct, not used in FreeBSD
struct net_device_ops {
};
struct ethtool_ops {
};
struct hrtimer {
};
#define NM_BNS_GET(b)
#define NM_BNS_PUT(b)

#elif defined (linux)

#define	NM_LOCK_T	safe_spinlock_t	// see bsd_glue.h
#define	NM_SELINFO_T	wait_queue_head_t
#define	MBUF_LEN(m)	((m)->len)
#define MBUF_TRANSMIT(na, ifp, m)							\
	({										\
		/* Avoid infinite recursion with generic. */				\
		m->priority = NM_MAGIC_PRIORITY_TX;					\
		(((struct net_device_ops *)(na)->if_transmit)->ndo_start_xmit(m, ifp));	\
		0;									\
	})

/* See explanation in nm_os_generic_xmit_frame. */
#define	GEN_TX_MBUF_IFP(m)	((struct ifnet *)skb_shinfo(m)->destructor_arg)

#define NM_ATOMIC_T	volatile long unsigned int

#define NM_MTX_T	struct mutex	/* OS-specific sleepable lock */
#define NM_MTX_INIT(m)	mutex_init(&(m))
#define NM_MTX_DESTROY(m)	do { (void)(m); } while (0)
#define NM_MTX_LOCK(m)		mutex_lock(&(m))
#define NM_MTX_UNLOCK(m)	mutex_unlock(&(m))
#define NM_MTX_ASSERT(m)	mutex_is_locked(&(m))

#ifndef DEV_NETMAP
#define DEV_NETMAP
#endif /* DEV_NETMAP */

#elif defined (__APPLE__)

#warning apple support is incomplete.
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define	NM_LOCK_T	IOLock *
#define	NM_SELINFO_T	struct selinfo
#define	MBUF_LEN(m)	((m)->m_pkthdr.len)

#elif defined (_WIN32)
#include "../../../WINDOWS/win_glue.h"

#define NM_SELRECORD_T		IO_STACK_LOCATION
#define NM_SELINFO_T		win_SELINFO		// see win_glue.h
#define NM_LOCK_T		win_spinlock_t	// see win_glue.h
#define NM_MTX_T		KGUARDED_MUTEX	/* OS-specific mutex (sleepable) */

#define NM_MTX_INIT(m)		KeInitializeGuardedMutex(&m);
#define NM_MTX_DESTROY(m)	do { (void)(m); } while (0)
#define NM_MTX_LOCK(m)		KeAcquireGuardedMutex(&(m))
#define NM_MTX_UNLOCK(m)	KeReleaseGuardedMutex(&(m))
#define NM_MTX_ASSERT(m)	assert(&m.Count>0)

//These linknames are for the NDIS driver
#define NETMAP_NDIS_LINKNAME_STRING             L"\\DosDevices\\NMAPNDIS"
#define NETMAP_NDIS_NTDEVICE_STRING             L"\\Device\\NMAPNDIS"

//Definition of internal driver-to-driver ioctl codes
#define NETMAP_KERNEL_XCHANGE_POINTERS		_IO('i', 180)
#define NETMAP_KERNEL_SEND_SHUTDOWN_SIGNAL	_IO_direct('i', 195)

//Empty data structures are not permitted by MSVC compiler
//XXX_ale, try to solve this problem
struct net_device_ops{
	char data[1];
};
typedef struct ethtool_ops{
	char data[1];
};
typedef struct hrtimer{
	KTIMER timer;
	BOOLEAN active;
	KDPC deferred_proc;
};

/* MSVC does not have likely/unlikely support */
#ifdef _MSC_VER
#define likely(x)	(x)
#define unlikely(x)	(x)
#else
#define likely(x)	__builtin_expect((long)!!(x), 1L)
#define unlikely(x)	__builtin_expect((long)!!(x), 0L)
#endif //_MSC_VER

#else

#error unsupported platform

#endif /* end - platform-specific code */

#ifndef _WIN32 /* support for emulated sysctl */
#define SYSBEGIN(x)
#define SYSEND
#endif /* _WIN32 */

#define NM_ACCESS_ONCE(x)	(*(volatile __typeof__(x) *)&(x))

#define	NMG_LOCK_T		NM_MTX_T
#define	NMG_LOCK_INIT()		NM_MTX_INIT(netmap_global_lock)
#define	NMG_LOCK_DESTROY()	NM_MTX_DESTROY(netmap_global_lock)
#define	NMG_LOCK()		NM_MTX_LOCK(netmap_global_lock)
#define	NMG_UNLOCK()		NM_MTX_UNLOCK(netmap_global_lock)
#define	NMG_LOCK_ASSERT()	NM_MTX_ASSERT(netmap_global_lock)

#define ND(format, ...)
#define D(format, ...)						\
	do {							\
		struct timeval __xxts;				\
		microtime(&__xxts);				\
		printf("%03d.%06d [%4d] %-25s " format "\n",	\
		(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec,	\
		__LINE__, __FUNCTION__, ##__VA_ARGS__);		\
	} while (0)

/* rate limited, lps indicates how many per second */
#define RD(lps, format, ...)					\
	do {							\
		static int t0, __cnt;				\
		if (t0 != time_second) {			\
			t0 = time_second;			\
			__cnt = 0;				\
		}						\
		if (__cnt++ < lps)				\
			D(format, ##__VA_ARGS__);		\
	} while (0)

struct netmap_adapter;
struct nm_bdg_fwd;
struct nm_bridge;
struct netmap_priv_d;

/* os-specific NM_SELINFO_T initialzation/destruction functions */
void nm_os_selinfo_init(NM_SELINFO_T *);
void nm_os_selinfo_uninit(NM_SELINFO_T *);

const char *nm_dump_buf(char *p, int len, int lim, char *dst);

void nm_os_selwakeup(NM_SELINFO_T *si);
void nm_os_selrecord(NM_SELRECORD_T *sr, NM_SELINFO_T *si);

int nm_os_ifnet_init(void);
void nm_os_ifnet_fini(void);
void nm_os_ifnet_lock(void);
void nm_os_ifnet_unlock(void);

void nm_os_get_module(void);
void nm_os_put_module(void);

void netmap_make_zombie(struct ifnet *);
void netmap_undo_zombie(struct ifnet *);

/* passes a packet up to the host stack.
 * If the packet is sent (or dropped) immediately it returns NULL,
 * otherwise it links the packet to prev and returns m.
 * In this case, a final call with m=NULL and prev != NULL will send up
 * the entire chain to the host stack.
 */
void *nm_os_send_up(struct ifnet *, struct mbuf *m, struct mbuf *prev);

int nm_os_mbuf_has_offld(struct mbuf *m);

#include "netmap_mbq.h"

extern NMG_LOCK_T	netmap_global_lock;

enum txrx { NR_RX = 0, NR_TX = 1, NR_TXRX };

static __inline const char*
nm_txrx2str(enum txrx t)
{
	return (t== NR_RX ? "RX" : "TX");
}

static __inline enum txrx
nm_txrx_swap(enum txrx t)
{
	return (t== NR_RX ? NR_TX : NR_RX);
}

#define for_rx_tx(t)	for ((t) = 0; (t) < NR_TXRX; (t)++)


/*
 * private, kernel view of a ring. Keeps track of the status of
 * a ring across system calls.
 *
 *	nr_hwcur	index of the next buffer to refill.
 *			It corresponds to ring->head
 *			at the time the system call returns.
 *
 *	nr_hwtail	index of the first buffer owned by the kernel.
 *			On RX, hwcur->hwtail are receive buffers
 *			not yet released. hwcur is advanced following
 *			ring->head, hwtail is advanced on incoming packets,
 *			and a wakeup is generated when hwtail passes ring->cur
 *			    On TX, hwcur->rcur have been filled by the sender
 *			but not sent yet to the NIC; rcur->hwtail are available
 *			for new transmissions, and hwtail->hwcur-1 are pending
 *			transmissions not yet acknowledged.
 *
 * The indexes in the NIC and netmap rings are offset by nkr_hwofs slots.
 * This is so that, on a reset, buffers owned by userspace are not
 * modified by the kernel. In particular:
 * RX rings: the next empty buffer (hwtail + hwofs) coincides with
 * 	the next empty buffer as known by the hardware (next_to_check or so).
 * TX rings: hwcur + hwofs coincides with next_to_send
 *
 * For received packets, slot->flags is set to nkr_slot_flags
 * so we can provide a proper initial value (e.g. set NS_FORWARD
 * when operating in 'transparent' mode).
 *
 * The following fields are used to implement lock-free copy of packets
 * from input to output ports in VALE switch:
 *	nkr_hwlease	buffer after the last one being copied.
 *			A writer in nm_bdg_flush reserves N buffers
 *			from nr_hwlease, advances it, then does the
 *			copy outside the lock.
 *			In RX rings (used for VALE ports),
 *			nkr_hwtail <= nkr_hwlease < nkr_hwcur+N-1
 *			In TX rings (used for NIC or host stack ports)
 *			nkr_hwcur <= nkr_hwlease < nkr_hwtail
 *	nkr_leases	array of nkr_num_slots where writers can report
 *			completion of their block. NR_NOSLOT (~0) indicates
 *			that the writer has not finished yet
 *	nkr_lease_idx	index of next free slot in nr_leases, to be assigned
 *
 * The kring is manipulated by txsync/rxsync and generic netmap function.
 *
 * Concurrent rxsync or txsync on the same ring are prevented through
 * by nm_kr_(try)lock() which in turn uses nr_busy. This is all we need
 * for NIC rings, and for TX rings attached to the host stack.
 *
 * RX rings attached to the host stack use an mbq (rx_queue) on both
 * rxsync_from_host() and netmap_transmit(). The mbq is protected
 * by its internal lock.
 *
 * RX rings attached to the VALE switch are accessed by both senders
 * and receiver. They are protected through the q_lock on the RX ring.
 */
struct netmap_kring {
	struct netmap_ring	*ring;

	uint32_t	nr_hwcur;
	uint32_t	nr_hwtail;

	/*
	 * Copies of values in user rings, so we do not need to look
	 * at the ring (which could be modified). These are set in the
	 * *sync_prologue()/finalize() routines.
	 */
	uint32_t	rhead;
	uint32_t	rcur;
	uint32_t	rtail;

	uint32_t	nr_kflags;	/* private driver flags */
#define NKR_PENDINTR	0x1		// Pending interrupt.
#define NKR_EXCLUSIVE	0x2		/* exclusive binding */
#define NKR_FORWARD	0x4		/* (host ring only) there are
					   packets to forward
					 */
#define NKR_NEEDRING	0x8		/* ring needed even if users==0
					 * (used internally by pipes and
					 *  by ptnetmap host ports)
					 */

	uint32_t	nr_mode;
	uint32_t	nr_pending_mode;
#define NKR_NETMAP_OFF	0x0
#define NKR_NETMAP_ON	0x1

	uint32_t	nkr_num_slots;

	/*
	 * On a NIC reset, the NIC ring indexes may be reset but the
	 * indexes in the netmap rings remain the same. nkr_hwofs
	 * keeps track of the offset between the two.
	 */
	int32_t		nkr_hwofs;

	uint16_t	nkr_slot_flags;	/* initial value for flags */

	/* last_reclaim is opaque marker to help reduce the frequency
	 * of operations such as reclaiming tx buffers. A possible use
	 * is set it to ticks and do the reclaim only once per tick.
	 */
	uint64_t	last_reclaim;


	NM_SELINFO_T	si;		/* poll/select wait queue */
	NM_LOCK_T	q_lock;		/* protects kring and ring. */
	NM_ATOMIC_T	nr_busy;	/* prevent concurrent syscalls */

	struct netmap_adapter *na;

	/* The following fields are for VALE switch support */
	struct nm_bdg_fwd *nkr_ft;
	uint32_t	*nkr_leases;
#define NR_NOSLOT	((uint32_t)~0)	/* used in nkr_*lease* */
	uint32_t	nkr_hwlease;
	uint32_t	nkr_lease_idx;

	/* while nkr_stopped is set, no new [tr]xsync operations can
	 * be started on this kring.
	 * This is used by netmap_disable_all_rings()
	 * to find a synchronization point where critical data
	 * structures pointed to by the kring can be added or removed
	 */
	volatile int nkr_stopped;

	/* Support for adapters without native netmap support.
	 * On tx rings we preallocate an array of tx buffers
	 * (same size as the netmap ring), on rx rings we
	 * store incoming mbufs in a queue that is drained by
	 * a rxsync.
	 */
	struct mbuf	**tx_pool;
	struct mbuf	*tx_event;	/* TX event used as a notification */
	NM_LOCK_T	tx_event_lock;	/* protects the tx_event mbuf */
	struct mbq	rx_queue;       /* intercepted rx mbufs. */

	uint32_t	users;		/* existing bindings for this ring */

	uint32_t	ring_id;	/* kring identifier */
	enum txrx	tx;		/* kind of ring (tx or rx) */
	char name[64];			/* diagnostic */

	/* [tx]sync callback for this kring.
	 * The default nm_kring_create callback (netmap_krings_create)
	 * sets the nm_sync callback of each hardware tx(rx) kring to
	 * the corresponding nm_txsync(nm_rxsync) taken from the
	 * netmap_adapter; moreover, it sets the sync callback
	 * of the host tx(rx) ring to netmap_txsync_to_host
	 * (netmap_rxsync_from_host).
	 *
	 * Overrides: the above configuration is not changed by
	 * any of the nm_krings_create callbacks.
	 */
	int (*nm_sync)(struct netmap_kring *kring, int flags);
	int (*nm_notify)(struct netmap_kring *kring, int flags);

#ifdef WITH_PIPES
	struct netmap_kring *pipe;	/* if this is a pipe ring,
					 * pointer to the other end
					 */
#endif /* WITH_PIPES */

#ifdef WITH_VALE
	int (*save_notify)(struct netmap_kring *kring, int flags);
#endif

#ifdef WITH_MONITOR
	/* array of krings that are monitoring this kring */
	struct netmap_kring **monitors;
	uint32_t max_monitors; /* current size of the monitors array */
	uint32_t n_monitors;	/* next unused entry in the monitor array */
	/*
	 * Monitors work by intercepting the sync and notify callbacks of the
	 * monitored krings. This is implemented by replacing the pointers
	 * above and saving the previous ones in mon_* pointers below
	 */
	int (*mon_sync)(struct netmap_kring *kring, int flags);
	int (*mon_notify)(struct netmap_kring *kring, int flags);

	uint32_t mon_tail;  /* last seen slot on rx */
	uint32_t mon_pos;   /* index of this ring in the monitored ring array */
#endif
}
#ifdef _WIN32
__declspec(align(64));
#else
__attribute__((__aligned__(64)));
#endif

/* return 1 iff the kring needs to be turned on */
static inline int
nm_kring_pending_on(struct netmap_kring *kring)
{
	return kring->nr_pending_mode == NKR_NETMAP_ON &&
	       kring->nr_mode == NKR_NETMAP_OFF;
}

/* return 1 iff the kring needs to be turned off */
static inline int
nm_kring_pending_off(struct netmap_kring *kring)
{
	return kring->nr_pending_mode == NKR_NETMAP_OFF &&
	       kring->nr_mode == NKR_NETMAP_ON;
}

/* return the next index, with wraparound */
static inline uint32_t
nm_next(uint32_t i, uint32_t lim)
{
	return unlikely (i == lim) ? 0 : i + 1;
}


/* return the previous index, with wraparound */
static inline uint32_t
nm_prev(uint32_t i, uint32_t lim)
{
	return unlikely (i == 0) ? lim : i - 1;
}


/*
 *
 * Here is the layout for the Rx and Tx rings.

       RxRING                            TxRING

      +-----------------+            +-----------------+
      |                 |            |                 |
      |XXX free slot XXX|            |XXX free slot XXX|
      +-----------------+            +-----------------+
head->| owned by user   |<-hwcur     | not sent to nic |<-hwcur
      |                 |            | yet             |
      +-----------------+            |                 |
 cur->| available to    |            |                 |
      | user, not read  |            +-----------------+
      | yet             |       cur->| (being          |
      |                 |            |  prepared)      |
      |                 |            |                 |
      +-----------------+            +     ------      +
tail->|                 |<-hwtail    |                 |<-hwlease
      | (being          | ...        |                 | ...
      |  prepared)      | ...        |                 | ...
      +-----------------+ ...        |                 | ...
      |                 |<-hwlease   +-----------------+
      |                 |      tail->|                 |<-hwtail
      |                 |            |                 |
      |                 |            |                 |
      |                 |            |                 |
      +-----------------+            +-----------------+

 * The cur/tail (user view) and hwcur/hwtail (kernel view)
 * are used in the normal operation of the card.
 *
 * When a ring is the output of a switch port (Rx ring for
 * a VALE port, Tx ring for the host stack or NIC), slots
 * are reserved in blocks through 'hwlease' which points
 * to the next unused slot.
 * On an Rx ring, hwlease is always after hwtail,
 * and completions cause hwtail to advance.
 * On a Tx ring, hwlease is always between cur and hwtail,
 * and completions cause cur to advance.
 *
 * nm_kr_space() returns the maximum number of slots that
 * can be assigned.
 * nm_kr_lease() reserves the required number of buffers,
 *    advances nkr_hwlease and also returns an entry in
 *    a circular array where completions should be reported.
 */


struct netmap_lut {
	struct lut_entry *lut;
	uint32_t objtotal;	/* max buffer index */
	uint32_t objsize;	/* buffer size */
};

struct netmap_vp_adapter; // forward

/*
 * The "struct netmap_adapter" extends the "struct adapter"
 * (or equivalent) device descriptor.
 * It contains all base fields needed to support netmap operation.
 * There are in fact different types of netmap adapters
 * (native, generic, VALE switch...) so a netmap_adapter is
 * just the first field in the derived type.
 */
struct netmap_adapter {
	/*
	 * On linux we do not have a good way to tell if an interface
	 * is netmap-capable. So we always use the following trick:
	 * NA(ifp) points here, and the first entry (which hopefully
	 * always exists and is at least 32 bits) contains a magic
	 * value which we can use to detect that the interface is good.
	 */
	uint32_t magic;
	uint32_t na_flags;	/* enabled, and other flags */
#define NAF_SKIP_INTR	1	/* use the regular interrupt handler.
				 * useful during initialization
				 */
#define NAF_SW_ONLY	2	/* forward packets only to sw adapter */
#define NAF_BDG_MAYSLEEP 4	/* the bridge is allowed to sleep when
				 * forwarding packets coming from this
				 * interface
				 */
#define NAF_MEM_OWNER	8	/* the adapter uses its own memory area
				 * that cannot be changed
				 */
#define NAF_NATIVE      16      /* the adapter is native.
				 * Virtual ports (non persistent vale ports,
				 * pipes, monitors...) should never use
				 * this flag.
				 */
#define	NAF_NETMAP_ON	32	/* netmap is active (either native or
				 * emulated). Where possible (e.g. FreeBSD)
				 * IFCAP_NETMAP also mirrors this flag.
				 */
#define NAF_HOST_RINGS  64	/* the adapter supports the host rings */
#define NAF_FORCE_NATIVE 128	/* the adapter is always NATIVE */
#define NAF_PTNETMAP_HOST 256	/* the adapter supports ptnetmap in the host */
#define NAF_ZOMBIE	(1U<<30) /* the nic driver has been unloaded */
#define	NAF_BUSY	(1U<<31) /* the adapter is used internally and
				  * cannot be registered from userspace
				  */
	int active_fds; /* number of user-space descriptors using this
			 interface, which is equal to the number of
			 struct netmap_if objs in the mapped region. */

	u_int num_rx_rings; /* number of adapter receive rings */
	u_int num_tx_rings; /* number of adapter transmit rings */

	u_int num_tx_desc;  /* number of descriptor in each queue */
	u_int num_rx_desc;

	/* tx_rings and rx_rings are private but allocated
	 * as a contiguous chunk of memory. Each array has
	 * N+1 entries, for the adapter queues and for the host queue.
	 */
	struct netmap_kring *tx_rings; /* array of TX rings. */
	struct netmap_kring *rx_rings; /* array of RX rings. */

	void *tailroom;		       /* space below the rings array */
				       /* (used for leases) */


	NM_SELINFO_T si[NR_TXRX];	/* global wait queues */

	/* count users of the global wait queues */
	int si_users[NR_TXRX];

	void *pdev; /* used to store pci device */

	/* copy of if_qflush and if_transmit pointers, to intercept
	 * packets from the network stack when netmap is active.
	 */
	int     (*if_transmit)(struct ifnet *, struct mbuf *);

	/* copy of if_input for netmap_send_up() */
	void     (*if_input)(struct ifnet *, struct mbuf *);

	/* references to the ifnet and device routines, used by
	 * the generic netmap functions.
	 */
	struct ifnet *ifp; /* adapter is ifp->if_softc */

	/*---- callbacks for this netmap adapter -----*/
	/*
	 * nm_dtor() is the cleanup routine called when destroying
	 *	the adapter.
	 *	Called with NMG_LOCK held.
	 *
	 * nm_register() is called on NIOCREGIF and close() to enter
	 *	or exit netmap mode on the NIC
	 *	Called with NNG_LOCK held.
	 *
	 * nm_txsync() pushes packets to the underlying hw/switch
	 *
	 * nm_rxsync() collects packets from the underlying hw/switch
	 *
	 * nm_config() returns configuration information from the OS
	 *	Called with NMG_LOCK held.
	 *
	 * nm_krings_create() create and init the tx_rings and
	 * 	rx_rings arrays of kring structures. In particular,
	 * 	set the nm_sync callbacks for each ring.
	 * 	There is no need to also allocate the corresponding
	 * 	netmap_rings, since netmap_mem_rings_create() will always
	 * 	be called to provide the missing ones.
	 *	Called with NNG_LOCK held.
	 *
	 * nm_krings_delete() cleanup and delete the tx_rings and rx_rings
	 * 	arrays
	 *	Called with NMG_LOCK held.
	 *
	 * nm_notify() is used to act after data have become available
	 * 	(or the stopped state of the ring has changed)
	 *	For hw devices this is typically a selwakeup(),
	 *	but for NIC/host ports attached to a switch (or vice-versa)
	 *	we also need to invoke the 'txsync' code downstream.
	 *      This callback pointer is actually used only to initialize
	 *      kring->nm_notify.
	 *      Return values are the same as for netmap_rx_irq().
	 */
	void (*nm_dtor)(struct netmap_adapter *);

	int (*nm_register)(struct netmap_adapter *, int onoff);
	void (*nm_intr)(struct netmap_adapter *, int onoff);

	int (*nm_txsync)(struct netmap_kring *kring, int flags);
	int (*nm_rxsync)(struct netmap_kring *kring, int flags);
	int (*nm_notify)(struct netmap_kring *kring, int flags);
#define NAF_FORCE_READ    1
#define NAF_FORCE_RECLAIM 2
	/* return configuration information */
	int (*nm_config)(struct netmap_adapter *,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd);
	int (*nm_krings_create)(struct netmap_adapter *);
	void (*nm_krings_delete)(struct netmap_adapter *);
#ifdef WITH_VALE
	/*
	 * nm_bdg_attach() initializes the na_vp field to point
	 *      to an adapter that can be attached to a VALE switch. If the
	 *      current adapter is already a VALE port, na_vp is simply a cast;
	 *      otherwise, na_vp points to a netmap_bwrap_adapter.
	 *      If applicable, this callback also initializes na_hostvp,
	 *      that can be used to connect the adapter host rings to the
	 *      switch.
	 *      Called with NMG_LOCK held.
	 *
	 * nm_bdg_ctl() is called on the actual attach/detach to/from
	 *      to/from the switch, to perform adapter-specific
	 *      initializations
	 *      Called with NMG_LOCK held.
	 */
	int (*nm_bdg_attach)(const char *bdg_name, struct netmap_adapter *);
	int (*nm_bdg_ctl)(struct netmap_adapter *, struct nmreq *, int);

	/* adapter used to attach this adapter to a VALE switch (if any) */
	struct netmap_vp_adapter *na_vp;
	/* adapter used to attach the host rings of this adapter
	 * to a VALE switch (if any) */
	struct netmap_vp_adapter *na_hostvp;
#endif

	/* standard refcount to control the lifetime of the adapter
	 * (it should be equal to the lifetime of the corresponding ifp)
	 */
	int na_refcount;

	/* memory allocator (opaque)
	 * We also cache a pointer to the lut_entry for translating
	 * buffer addresses, the total number of buffers and the buffer size.
	 */
 	struct netmap_mem_d *nm_mem;
	struct netmap_lut na_lut;

	/* additional information attached to this adapter
	 * by other netmap subsystems. Currently used by
	 * bwrap, LINUX/v1000 and ptnetmap
	 */
	void *na_private;

	/* array of pipes that have this adapter as a parent */
	struct netmap_pipe_adapter **na_pipes;
	int na_next_pipe;	/* next free slot in the array */
	int na_max_pipes;	/* size of the array */

	/* Offset of ethernet header for each packet. */
	u_int virt_hdr_len;

	char name[64];
};

static __inline u_int
nma_get_ndesc(struct netmap_adapter *na, enum txrx t)
{
	return (t == NR_TX ? na->num_tx_desc : na->num_rx_desc);
}

static __inline void
nma_set_ndesc(struct netmap_adapter *na, enum txrx t, u_int v)
{
	if (t == NR_TX)
		na->num_tx_desc = v;
	else
		na->num_rx_desc = v;
}

static __inline u_int
nma_get_nrings(struct netmap_adapter *na, enum txrx t)
{
	return (t == NR_TX ? na->num_tx_rings : na->num_rx_rings);
}

static __inline void
nma_set_nrings(struct netmap_adapter *na, enum txrx t, u_int v)
{
	if (t == NR_TX)
		na->num_tx_rings = v;
	else
		na->num_rx_rings = v;
}

static __inline struct netmap_kring*
NMR(struct netmap_adapter *na, enum txrx t)
{
	return (t == NR_TX ? na->tx_rings : na->rx_rings);
}

/*
 * If the NIC is owned by the kernel
 * (i.e., bridge), neither another bridge nor user can use it;
 * if the NIC is owned by a user, only users can share it.
 * Evaluation must be done under NMG_LOCK().
 */
#define NETMAP_OWNED_BY_KERN(na)	((na)->na_flags & NAF_BUSY)
#define NETMAP_OWNED_BY_ANY(na) \
	(NETMAP_OWNED_BY_KERN(na) || ((na)->active_fds > 0))

/*
 * derived netmap adapters for various types of ports
 */
struct netmap_vp_adapter {	/* VALE software port */
	struct netmap_adapter up;

	/*
	 * Bridge support:
	 *
	 * bdg_port is the port number used in the bridge;
	 * na_bdg points to the bridge this NA is attached to.
	 */
	int bdg_port;
	struct nm_bridge *na_bdg;
	int retry;

	/* Maximum Frame Size, used in bdg_mismatch_datapath() */
	u_int mfs;
	/* Last source MAC on this port */
	uint64_t last_smac;
};


struct netmap_hw_adapter {	/* physical device */
	struct netmap_adapter up;

	struct net_device_ops nm_ndo;	// XXX linux only
	struct ethtool_ops    nm_eto;	// XXX linux only
	const struct ethtool_ops*   save_ethtool;

	int (*nm_hw_register)(struct netmap_adapter *, int onoff);
};

#ifdef WITH_GENERIC
/* Mitigation support. */
struct nm_generic_mit {
	struct hrtimer mit_timer;
	int mit_pending;
	int mit_ring_idx;  /* index of the ring being mitigated */
	struct netmap_adapter *mit_na;  /* backpointer */
};

struct netmap_generic_adapter {	/* emulated device */
	struct netmap_hw_adapter up;

	/* Pointer to a previously used netmap adapter. */
	struct netmap_adapter *prev;

	/* generic netmap adapters support:
	 * a net_device_ops struct overrides ndo_select_queue(),
	 * save_if_input saves the if_input hook (FreeBSD),
	 * mit implements rx interrupt mitigation,
	 */
	struct net_device_ops generic_ndo;
	void (*save_if_input)(struct ifnet *, struct mbuf *);

	struct nm_generic_mit *mit;
#ifdef linux
        netdev_tx_t (*save_start_xmit)(struct mbuf *, struct ifnet *);
#endif
	/* Is the adapter able to use multiple RX slots to scatter
	 * each packet pushed up by the driver? */
	int rxsg;

	/* Is the transmission path controlled by a netmap-aware
	 * device queue (i.e. qdisc on linux)? */
	int txqdisc;
};
#endif  /* WITH_GENERIC */

static __inline int
netmap_real_rings(struct netmap_adapter *na, enum txrx t)
{
	return nma_get_nrings(na, t) + !!(na->na_flags & NAF_HOST_RINGS);
}

#ifdef WITH_VALE
struct nm_bdg_polling_state;
/*
 * Bridge wrapper for non VALE ports attached to a VALE switch.
 *
 * The real device must already have its own netmap adapter (hwna).
 * The bridge wrapper and the hwna adapter share the same set of
 * netmap rings and buffers, but they have two separate sets of
 * krings descriptors, with tx/rx meanings swapped:
 *
 *                                  netmap
 *           bwrap     krings       rings      krings      hwna
 *         +------+   +------+     +-----+    +------+   +------+
 *         |tx_rings->|      |\   /|     |----|      |<-tx_rings|
 *         |      |   +------+ \ / +-----+    +------+   |      |
 *         |      |             X                        |      |
 *         |      |            / \                       |      |
 *         |      |   +------+/   \+-----+    +------+   |      |
 *         |rx_rings->|      |     |     |----|      |<-rx_rings|
 *         |      |   +------+     +-----+    +------+   |      |
 *         +------+                                      +------+
 *
 * - packets coming from the bridge go to the brwap rx rings,
 *   which are also the hwna tx rings.  The bwrap notify callback
 *   will then complete the hwna tx (see netmap_bwrap_notify).
 *
 * - packets coming from the outside go to the hwna rx rings,
 *   which are also the bwrap tx rings.  The (overwritten) hwna
 *   notify method will then complete the bridge tx
 *   (see netmap_bwrap_intr_notify).
 *
 *   The bridge wrapper may optionally connect the hwna 'host' rings
 *   to the bridge. This is done by using a second port in the
 *   bridge and connecting it to the 'host' netmap_vp_adapter
 *   contained in the netmap_bwrap_adapter. The brwap host adapter
 *   cross-links the hwna host rings in the same way as shown above.
 *
 * - packets coming from the bridge and directed to the host stack
 *   are handled by the bwrap host notify callback
 *   (see netmap_bwrap_host_notify)
 *
 * - packets coming from the host stack are still handled by the
 *   overwritten hwna notify callback (netmap_bwrap_intr_notify),
 *   but are diverted to the host adapter depending on the ring number.
 *
 */
struct netmap_bwrap_adapter {
	struct netmap_vp_adapter up;
	struct netmap_vp_adapter host;  /* for host rings */
	struct netmap_adapter *hwna;	/* the underlying device */

	/*
	 * When we attach a physical interface to the bridge, we
	 * allow the controlling process to terminate, so we need
	 * a place to store the n_detmap_priv_d data structure.
	 * This is only done when physical interfaces
	 * are attached to a bridge.
	 */
	struct netmap_priv_d *na_kpriv;
	struct nm_bdg_polling_state *na_polling_state;
};
int netmap_bwrap_attach(const char *name, struct netmap_adapter *);

#endif /* WITH_VALE */

#ifdef WITH_PIPES

#define NM_MAXPIPES 	64	/* max number of pipes per adapter */

struct netmap_pipe_adapter {
	struct netmap_adapter up;

	u_int id; 	/* pipe identifier */
	int role;	/* either NR_REG_PIPE_MASTER or NR_REG_PIPE_SLAVE */

	struct netmap_adapter *parent; /* adapter that owns the memory */
	struct netmap_pipe_adapter *peer; /* the other end of the pipe */
	int peer_ref;		/* 1 iff we are holding a ref to the peer */

	u_int parent_slot; /* index in the parent pipe array */
};

#endif /* WITH_PIPES */


/* return slots reserved to rx clients; used in drivers */
static inline uint32_t
nm_kr_rxspace(struct netmap_kring *k)
{
	int space = k->nr_hwtail - k->nr_hwcur;
	if (space < 0)
		space += k->nkr_num_slots;
	ND("preserving %d rx slots %d -> %d", space, k->nr_hwcur, k->nr_hwtail);

	return space;
}

/* return slots reserved to tx clients */
#define nm_kr_txspace(_k) nm_kr_rxspace(_k)


/* True if no space in the tx ring, only valid after txsync_prologue */
static inline int
nm_kr_txempty(struct netmap_kring *kring)
{
	return kring->rcur == kring->nr_hwtail;
}

/* True if no more completed slots in the rx ring, only valid after
 * rxsync_prologue */
#define nm_kr_rxempty(_k)	nm_kr_txempty(_k)

/*
 * protect against multiple threads using the same ring.
 * also check that the ring has not been stopped or locked
 */
#define NM_KR_BUSY	1	/* some other thread is syncing the ring */
#define NM_KR_STOPPED	2	/* unbounded stop (ifconfig down or driver unload) */
#define NM_KR_LOCKED	3	/* bounded, brief stop for mutual exclusion */


/* release the previously acquired right to use the *sync() methods of the ring */
static __inline void nm_kr_put(struct netmap_kring *kr)
{
	NM_ATOMIC_CLEAR(&kr->nr_busy);
}


/* true if the ifp that backed the adapter has disappeared (e.g., the
 * driver has been unloaded)
 */
static inline int nm_iszombie(struct netmap_adapter *na);

/* try to obtain exclusive right to issue the *sync() operations on the ring.
 * The right is obtained and must be later relinquished via nm_kr_put() if and
 * only if nm_kr_tryget() returns 0.
 * If can_sleep is 1 there are only two other possible outcomes:
 * - the function returns NM_KR_BUSY
 * - the function returns NM_KR_STOPPED and sets the POLLERR bit in *perr
 *   (if non-null)
 * In both cases the caller will typically skip the ring, possibly collecting
 * errors along the way.
 * If the calling context does not allow sleeping, the caller must pass 0 in can_sleep.
 * In the latter case, the function may also return NM_KR_LOCKED and leave *perr
 * untouched: ideally, the caller should try again at a later time.
 */
static __inline int nm_kr_tryget(struct netmap_kring *kr, int can_sleep, int *perr)
{
	int busy = 1, stopped;
	/* check a first time without taking the lock
	 * to avoid starvation for nm_kr_get()
	 */
retry:
	stopped = kr->nkr_stopped;
	if (unlikely(stopped)) {
		goto stop;
	}
	busy = NM_ATOMIC_TEST_AND_SET(&kr->nr_busy);
	/* we should not return NM_KR_BUSY if the ring was
	 * actually stopped, so check another time after
	 * the barrier provided by the atomic operation
	 */
	stopped = kr->nkr_stopped;
	if (unlikely(stopped)) {
		goto stop;
	}

	if (unlikely(nm_iszombie(kr->na))) {
		stopped = NM_KR_STOPPED;
		goto stop;
	}

	return unlikely(busy) ? NM_KR_BUSY : 0;

stop:
	if (!busy)
		nm_kr_put(kr);
	if (stopped == NM_KR_STOPPED) {
/* if POLLERR is defined we want to use it to simplify netmap_poll().
 * Otherwise, any non-zero value will do.
 */
#ifdef POLLERR
#define NM_POLLERR POLLERR
#else
#define NM_POLLERR 1
#endif /* POLLERR */
		if (perr)
			*perr |= NM_POLLERR;
#undef NM_POLLERR
	} else if (can_sleep) {
		tsleep(kr, 0, "NM_KR_TRYGET", 4);
		goto retry;
	}
	return stopped;
}

/* put the ring in the 'stopped' state and wait for the current user (if any) to
 * notice. stopped must be either NM_KR_STOPPED or NM_KR_LOCKED
 */
static __inline void nm_kr_stop(struct netmap_kring *kr, int stopped)
{
	kr->nkr_stopped = stopped;
	while (NM_ATOMIC_TEST_AND_SET(&kr->nr_busy))
		tsleep(kr, 0, "NM_KR_GET", 4);
}

/* restart a ring after a stop */
static __inline void nm_kr_start(struct netmap_kring *kr)
{
	kr->nkr_stopped = 0;
	nm_kr_put(kr);
}


/*
 * The following functions are used by individual drivers to
 * support netmap operation.
 *
 * netmap_attach() initializes a struct netmap_adapter, allocating the
 * 	struct netmap_ring's and the struct selinfo.
 *
 * netmap_detach() frees the memory allocated by netmap_attach().
 *
 * netmap_transmit() replaces the if_transmit routine of the interface,
 *	and is used to intercept packets coming from the stack.
 *
 * netmap_load_map/netmap_reload_map are helper routines to set/reset
 *	the dmamap for a packet buffer
 *
 * netmap_reset() is a helper routine to be called in the hw driver
 *	when reinitializing a ring. It should not be called by
 *	virtual ports (vale, pipes, monitor)
 */
int netmap_attach(struct netmap_adapter *);
void netmap_detach(struct ifnet *);
int netmap_transmit(struct ifnet *, struct mbuf *);
struct netmap_slot *netmap_reset(struct netmap_adapter *na,
	enum txrx tx, u_int n, u_int new_cur);
int netmap_ring_reinit(struct netmap_kring *);

/* Return codes for netmap_*x_irq. */
enum {
	/* Driver should do normal interrupt processing, e.g. because
	 * the interface is not in netmap mode. */
	NM_IRQ_PASS = 0,
	/* Port is in netmap mode, and the interrupt work has been
	 * completed. The driver does not have to notify netmap
	 * again before the next interrupt. */
	NM_IRQ_COMPLETED = -1,
	/* Port is in netmap mode, but the interrupt work has not been
	 * completed. The driver has to make sure netmap will be
	 * notified again soon, even if no more interrupts come (e.g.
	 * on Linux the driver should not call napi_complete()). */
	NM_IRQ_RESCHED = -2,
};

/* default functions to handle rx/tx interrupts */
int netmap_rx_irq(struct ifnet *, u_int, u_int *);
#define netmap_tx_irq(_n, _q) netmap_rx_irq(_n, _q, NULL)
int netmap_common_irq(struct netmap_adapter *, u_int, u_int *work_done);


#ifdef WITH_VALE
/* functions used by external modules to interface with VALE */
#define netmap_vp_to_ifp(_vp)	((_vp)->up.ifp)
#define netmap_ifp_to_vp(_ifp)	(NA(_ifp)->na_vp)
#define netmap_ifp_to_host_vp(_ifp) (NA(_ifp)->na_hostvp)
#define netmap_bdg_idx(_vp)	((_vp)->bdg_port)
const char *netmap_bdg_name(struct netmap_vp_adapter *);
#else /* !WITH_VALE */
#define netmap_vp_to_ifp(_vp)	NULL
#define netmap_ifp_to_vp(_ifp)	NULL
#define netmap_ifp_to_host_vp(_ifp) NULL
#define netmap_bdg_idx(_vp)	-1
#define netmap_bdg_name(_vp)	NULL
#endif /* WITH_VALE */

static inline int
nm_netmap_on(struct netmap_adapter *na)
{
	return na && na->na_flags & NAF_NETMAP_ON;
}

static inline int
nm_native_on(struct netmap_adapter *na)
{
	return nm_netmap_on(na) && (na->na_flags & NAF_NATIVE);
}

static inline int
nm_iszombie(struct netmap_adapter *na)
{
	return na == NULL || (na->na_flags & NAF_ZOMBIE);
}

static inline void
nm_update_hostrings_mode(struct netmap_adapter *na)
{
	/* Process nr_mode and nr_pending_mode for host rings. */
	na->tx_rings[na->num_tx_rings].nr_mode =
		na->tx_rings[na->num_tx_rings].nr_pending_mode;
	na->rx_rings[na->num_rx_rings].nr_mode =
		na->rx_rings[na->num_rx_rings].nr_pending_mode;
}

/* set/clear native flags and if_transmit/netdev_ops */
static inline void
nm_set_native_flags(struct netmap_adapter *na)
{
	struct ifnet *ifp = na->ifp;

	/* We do the setup for intercepting packets only if we are the
	 * first user of this adapapter. */
	if (na->active_fds > 0) {
		return;
	}

	na->na_flags |= NAF_NETMAP_ON;
#ifdef IFCAP_NETMAP /* or FreeBSD ? */
	ifp->if_capenable |= IFCAP_NETMAP;
#endif
#if defined (__FreeBSD__)
	na->if_transmit = ifp->if_transmit;
	ifp->if_transmit = netmap_transmit;
#elif defined (_WIN32)
	(void)ifp; /* prevent a warning */
	//XXX_ale can we just comment those?
	//na->if_transmit = ifp->if_transmit;
	//ifp->if_transmit = netmap_transmit;
#else
	na->if_transmit = (void *)ifp->netdev_ops;
	ifp->netdev_ops = &((struct netmap_hw_adapter *)na)->nm_ndo;
	((struct netmap_hw_adapter *)na)->save_ethtool = ifp->ethtool_ops;
	ifp->ethtool_ops = &((struct netmap_hw_adapter*)na)->nm_eto;
#endif
	nm_update_hostrings_mode(na);
}

static inline void
nm_clear_native_flags(struct netmap_adapter *na)
{
	struct ifnet *ifp = na->ifp;

	/* We undo the setup for intercepting packets only if we are the
	 * last user of this adapapter. */
	if (na->active_fds > 0) {
		return;
	}

	nm_update_hostrings_mode(na);

#if defined(__FreeBSD__)
	ifp->if_transmit = na->if_transmit;
#elif defined(_WIN32)
	(void)ifp; /* prevent a warning */
	//XXX_ale can we just comment those?
	//ifp->if_transmit = na->if_transmit;
#else
	ifp->netdev_ops = (void *)na->if_transmit;
	ifp->ethtool_ops = ((struct netmap_hw_adapter*)na)->save_ethtool;
#endif
	na->na_flags &= ~NAF_NETMAP_ON;
#ifdef IFCAP_NETMAP /* or FreeBSD ? */
	ifp->if_capenable &= ~IFCAP_NETMAP;
#endif
}

/*
 * nm_*sync_prologue() functions are used in ioctl/poll and ptnetmap
 * kthreads.
 * We need netmap_ring* parameter, because in ptnetmap it is decoupled
 * from host kring.
 * The user-space ring pointers (head/cur/tail) are shared through
 * CSB between host and guest.
 */

/*
 * validates parameters in the ring/kring, returns a value for head
 * If any error, returns ring_size to force a reinit.
 */
uint32_t nm_txsync_prologue(struct netmap_kring *, struct netmap_ring *);


/*
 * validates parameters in the ring/kring, returns a value for head
 * If any error, returns ring_size lim to force a reinit.
 */
uint32_t nm_rxsync_prologue(struct netmap_kring *, struct netmap_ring *);


/* check/fix address and len in tx rings */
#if 1 /* debug version */
#define	NM_CHECK_ADDR_LEN(_na, _a, _l)	do {				\
	if (_a == NETMAP_BUF_BASE(_na) || _l > NETMAP_BUF_SIZE(_na)) {	\
		RD(5, "bad addr/len ring %d slot %d idx %d len %d",	\
			kring->ring_id, nm_i, slot->buf_idx, len);	\
		if (_l > NETMAP_BUF_SIZE(_na))				\
			_l = NETMAP_BUF_SIZE(_na);			\
	} } while (0)
#else /* no debug version */
#define	NM_CHECK_ADDR_LEN(_na, _a, _l)	do {				\
		if (_l > NETMAP_BUF_SIZE(_na))				\
			_l = NETMAP_BUF_SIZE(_na);			\
	} while (0)
#endif


/*---------------------------------------------------------------*/
/*
 * Support routines used by netmap subsystems
 * (native drivers, VALE, generic, pipes, monitors, ...)
 */


/* common routine for all functions that create a netmap adapter. It performs
 * two main tasks:
 * - if the na points to an ifp, mark the ifp as netmap capable
 *   using na as its native adapter;
 * - provide defaults for the setup callbacks and the memory allocator
 */
int netmap_attach_common(struct netmap_adapter *);
/* common actions to be performed on netmap adapter destruction */
void netmap_detach_common(struct netmap_adapter *);
/* fill priv->np_[tr]xq{first,last} using the ringid and flags information
 * coming from a struct nmreq
 */
int netmap_interp_ringid(struct netmap_priv_d *priv, uint16_t ringid, uint32_t flags);
/* update the ring parameters (number and size of tx and rx rings).
 * It calls the nm_config callback, if available.
 */
int netmap_update_config(struct netmap_adapter *na);
/* create and initialize the common fields of the krings array.
 * using the information that must be already available in the na.
 * tailroom can be used to request the allocation of additional
 * tailroom bytes after the krings array. This is used by
 * netmap_vp_adapter's (i.e., VALE ports) to make room for
 * leasing-related data structures
 */
int netmap_krings_create(struct netmap_adapter *na, u_int tailroom);
/* deletes the kring array of the adapter. The array must have
 * been created using netmap_krings_create
 */
void netmap_krings_delete(struct netmap_adapter *na);

int netmap_hw_krings_create(struct netmap_adapter *na);
void netmap_hw_krings_delete(struct netmap_adapter *na);

/* set the stopped/enabled status of ring
 * When stopping, they also wait for all current activity on the ring to
 * terminate. The status change is then notified using the na nm_notify
 * callback.
 */
void netmap_set_ring(struct netmap_adapter *, u_int ring_id, enum txrx, int stopped);
/* set the stopped/enabled status of all rings of the adapter. */
void netmap_set_all_rings(struct netmap_adapter *, int stopped);
/* convenience wrappers for netmap_set_all_rings */
void netmap_disable_all_rings(struct ifnet *);
void netmap_enable_all_rings(struct ifnet *);

int netmap_do_regif(struct netmap_priv_d *priv, struct netmap_adapter *na,
	uint16_t ringid, uint32_t flags);
void netmap_do_unregif(struct netmap_priv_d *priv);

u_int nm_bound_var(u_int *v, u_int dflt, u_int lo, u_int hi, const char *msg);
int netmap_get_na(struct nmreq *nmr, struct netmap_adapter **na,
		  struct ifnet **ifp, int create);
void netmap_unget_na(struct netmap_adapter *na, struct ifnet *ifp);
int netmap_get_hw_na(struct ifnet *ifp, struct netmap_adapter **na);


#ifdef WITH_VALE
/*
 * The following bridge-related functions are used by other
 * kernel modules.
 *
 * VALE only supports unicast or broadcast. The lookup
 * function can return 0 .. NM_BDG_MAXPORTS-1 for regular ports,
 * NM_BDG_MAXPORTS for broadcast, NM_BDG_MAXPORTS+1 for unknown.
 * XXX in practice "unknown" might be handled same as broadcast.
 */
typedef u_int (*bdg_lookup_fn_t)(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
		struct netmap_vp_adapter *);
typedef int (*bdg_config_fn_t)(struct nm_ifreq *);
typedef void (*bdg_dtor_fn_t)(const struct netmap_vp_adapter *);
struct netmap_bdg_ops {
	bdg_lookup_fn_t lookup;
	bdg_config_fn_t config;
	bdg_dtor_fn_t	dtor;
};

u_int netmap_bdg_learning(struct nm_bdg_fwd *ft, uint8_t *dst_ring,
		struct netmap_vp_adapter *);

#define	NM_BRIDGES		8	/* number of bridges */
#define	NM_BDG_MAXPORTS		254	/* up to 254 */
#define	NM_BDG_BROADCAST	NM_BDG_MAXPORTS
#define	NM_BDG_NOPORT		(NM_BDG_MAXPORTS+1)

#define	NM_NAME			"vale"	/* prefix for bridge port name */

/* these are redefined in case of no VALE support */
int netmap_get_bdg_na(struct nmreq *nmr, struct netmap_adapter **na, int create);
struct nm_bridge *netmap_init_bridges2(u_int);
void netmap_uninit_bridges2(struct nm_bridge *, u_int);
int netmap_init_bridges(void);
void netmap_uninit_bridges(void);
int netmap_bdg_ctl(struct nmreq *nmr, struct netmap_bdg_ops *bdg_ops);
int netmap_bdg_config(struct nmreq *nmr);

#else /* !WITH_VALE */
#define	netmap_get_bdg_na(_1, _2, _3)	0
#define netmap_init_bridges(_1) 0
#define netmap_uninit_bridges()
#define	netmap_bdg_ctl(_1, _2)	EINVAL
#endif /* !WITH_VALE */

#ifdef WITH_PIPES
/* max number of pipes per device */
#define NM_MAXPIPES	64	/* XXX how many? */
void netmap_pipe_dealloc(struct netmap_adapter *);
int netmap_get_pipe_na(struct nmreq *nmr, struct netmap_adapter **na, int create);
#else /* !WITH_PIPES */
#define NM_MAXPIPES	0
#define netmap_pipe_alloc(_1, _2) 	0
#define netmap_pipe_dealloc(_1)
#define netmap_get_pipe_na(nmr, _2, _3)	\
	({ int role__ = (nmr)->nr_flags & NR_REG_MASK; \
	   (role__ == NR_REG_PIPE_MASTER || 	       \
	    role__ == NR_REG_PIPE_SLAVE) ? EOPNOTSUPP : 0; })
#endif

#ifdef WITH_MONITOR
int netmap_get_monitor_na(struct nmreq *nmr, struct netmap_adapter **na, int create);
void netmap_monitor_stop(struct netmap_adapter *na);
#else
#define netmap_get_monitor_na(nmr, _2, _3) \
	((nmr)->nr_flags & (NR_MONITOR_TX | NR_MONITOR_RX) ? EOPNOTSUPP : 0)
#endif

#ifdef CONFIG_NET_NS
struct net *netmap_bns_get(void);
void netmap_bns_put(struct net *);
void netmap_bns_getbridges(struct nm_bridge **, u_int *);
#else
#define netmap_bns_get()
#define netmap_bns_put(_1)
#define netmap_bns_getbridges(b, n) \
	do { *b = nm_bridges; *n = NM_BRIDGES; } while (0)
#endif

/* Various prototypes */
int netmap_poll(struct netmap_priv_d *, int events, NM_SELRECORD_T *td);
int netmap_init(void);
void netmap_fini(void);
int netmap_get_memory(struct netmap_priv_d* p);
void netmap_dtor(void *data);

int netmap_ioctl(struct netmap_priv_d *priv, u_long cmd, caddr_t data, struct thread *);

/* netmap_adapter creation/destruction */

// #define NM_DEBUG_PUTGET 1

#ifdef NM_DEBUG_PUTGET

#define NM_DBG(f) __##f

void __netmap_adapter_get(struct netmap_adapter *na);

#define netmap_adapter_get(na) 				\
	do {						\
		struct netmap_adapter *__na = na;	\
		D("getting %p:%s (%d)", __na, (__na)->name, (__na)->na_refcount);	\
		__netmap_adapter_get(__na);		\
	} while (0)

int __netmap_adapter_put(struct netmap_adapter *na);

#define netmap_adapter_put(na)				\
	({						\
		struct netmap_adapter *__na = na;	\
		D("putting %p:%s (%d)", __na, (__na)->name, (__na)->na_refcount);	\
		__netmap_adapter_put(__na);		\
	})

#else /* !NM_DEBUG_PUTGET */

#define NM_DBG(f) f
void netmap_adapter_get(struct netmap_adapter *na);
int netmap_adapter_put(struct netmap_adapter *na);

#endif /* !NM_DEBUG_PUTGET */


/*
 * module variables
 */
#define NETMAP_BUF_BASE(_na)	((_na)->na_lut.lut[0].vaddr)
#define NETMAP_BUF_SIZE(_na)	((_na)->na_lut.objsize)
extern int netmap_mitigate;	// XXX not really used
extern int netmap_no_pendintr;
extern int netmap_verbose;	// XXX debugging
enum {                                  /* verbose flags */
	NM_VERB_ON = 1,                 /* generic verbose */
	NM_VERB_HOST = 0x2,             /* verbose host stack */
	NM_VERB_RXSYNC = 0x10,          /* verbose on rxsync/txsync */
	NM_VERB_TXSYNC = 0x20,
	NM_VERB_RXINTR = 0x100,         /* verbose on rx/tx intr (driver) */
	NM_VERB_TXINTR = 0x200,
	NM_VERB_NIC_RXSYNC = 0x1000,    /* verbose on rx/tx intr (driver) */
	NM_VERB_NIC_TXSYNC = 0x2000,
};

extern int netmap_txsync_retry;
extern int netmap_adaptive_io;
extern int netmap_flags;
extern int netmap_generic_mit;
extern int netmap_generic_ringsize;
extern int netmap_generic_rings;
extern int netmap_generic_txqdisc;

/*
 * NA returns a pointer to the struct netmap adapter from the ifp,
 * WNA is used to write it.
 */
#define	NA(_ifp)	((struct netmap_adapter *)WNA(_ifp))

/*
 * On old versions of FreeBSD, NA(ifp) is a pspare. On linux we
 * overload another pointer in the netdev.
 *
 * We check if NA(ifp) is set and its first element has a related
 * magic value. The capenable is within the struct netmap_adapter.
 */
#define	NETMAP_MAGIC	0x52697a7a

#define NM_NA_VALID(ifp)	(NA(ifp) &&		\
	((uint32_t)(uintptr_t)NA(ifp) ^ NA(ifp)->magic) == NETMAP_MAGIC )

#define	NM_ATTACH_NA(ifp, na) do {					\
	WNA(ifp) = na;							\
	if (NA(ifp))							\
		NA(ifp)->magic = 					\
			((uint32_t)(uintptr_t)NA(ifp)) ^ NETMAP_MAGIC;	\
} while(0)

#define NM_IS_NATIVE(ifp)	(NM_NA_VALID(ifp) && NA(ifp)->nm_dtor == netmap_hw_dtor)

#if defined(__FreeBSD__)

/* Assigns the device IOMMU domain to an allocator.
 * Returns -ENOMEM in case the domain is different */
#define nm_iommu_group_id(dev) (0)

/* Callback invoked by the dma machinery after a successful dmamap_load */
static void netmap_dmamap_cb(__unused void *arg,
    __unused bus_dma_segment_t * segs, __unused int nseg, __unused int error)
{
}

/* bus_dmamap_load wrapper: call aforementioned function if map != NULL.
 * XXX can we do it without a callback ?
 */
static inline void
netmap_load_map(struct netmap_adapter *na,
	bus_dma_tag_t tag, bus_dmamap_t map, void *buf)
{
	if (map)
		bus_dmamap_load(tag, map, buf, NETMAP_BUF_SIZE(na),
		    netmap_dmamap_cb, NULL, BUS_DMA_NOWAIT);
}

static inline void
netmap_unload_map(struct netmap_adapter *na,
        bus_dma_tag_t tag, bus_dmamap_t map)
{
	if (map)
		bus_dmamap_unload(tag, map);
}

/* update the map when a buffer changes. */
static inline void
netmap_reload_map(struct netmap_adapter *na,
	bus_dma_tag_t tag, bus_dmamap_t map, void *buf)
{
	if (map) {
		bus_dmamap_unload(tag, map);
		bus_dmamap_load(tag, map, buf, NETMAP_BUF_SIZE(na),
		    netmap_dmamap_cb, NULL, BUS_DMA_NOWAIT);
	}
}

#elif defined(_WIN32)

#else /* linux */

int nm_iommu_group_id(bus_dma_tag_t dev);
#include <linux/dma-mapping.h>

static inline void
netmap_load_map(struct netmap_adapter *na,
	bus_dma_tag_t tag, bus_dmamap_t map, void *buf)
{
	if (0 && map) {
		*map = dma_map_single(na->pdev, buf, NETMAP_BUF_SIZE(na),
				      DMA_BIDIRECTIONAL);
	}
}

static inline void
netmap_unload_map(struct netmap_adapter *na,
	bus_dma_tag_t tag, bus_dmamap_t map)
{
	u_int sz = NETMAP_BUF_SIZE(na);

	if (*map) {
		dma_unmap_single(na->pdev, *map, sz,
				 DMA_BIDIRECTIONAL);
	}
}

static inline void
netmap_reload_map(struct netmap_adapter *na,
	bus_dma_tag_t tag, bus_dmamap_t map, void *buf)
{
	u_int sz = NETMAP_BUF_SIZE(na);

	if (*map) {
		dma_unmap_single(na->pdev, *map, sz,
				DMA_BIDIRECTIONAL);
	}

	*map = dma_map_single(na->pdev, buf, sz,
				DMA_BIDIRECTIONAL);
}

/*
 * XXX How do we redefine these functions:
 *
 * on linux we need
 *	dma_map_single(&pdev->dev, virt_addr, len, direction)
 *	dma_unmap_single(&adapter->pdev->dev, phys_addr, len, direction
 * The len can be implicit (on netmap it is NETMAP_BUF_SIZE)
 * unfortunately the direction is not, so we need to change
 * something to have a cross API
 */

#if 0
	struct e1000_buffer *buffer_info =  &tx_ring->buffer_info[l];
	/* set time_stamp *before* dma to help avoid a possible race */
	buffer_info->time_stamp = jiffies;
	buffer_info->mapped_as_page = false;
	buffer_info->length = len;
	//buffer_info->next_to_watch = l;
	/* reload dma map */
	dma_unmap_single(&adapter->pdev->dev, buffer_info->dma,
			NETMAP_BUF_SIZE, DMA_TO_DEVICE);
	buffer_info->dma = dma_map_single(&adapter->pdev->dev,
			addr, NETMAP_BUF_SIZE, DMA_TO_DEVICE);

	if (dma_mapping_error(&adapter->pdev->dev, buffer_info->dma)) {
		D("dma mapping error");
		/* goto dma_error; See e1000_put_txbuf() */
		/* XXX reset */
	}
	tx_desc->buffer_addr = htole64(buffer_info->dma); //XXX

#endif

/*
 * The bus_dmamap_sync() can be one of wmb() or rmb() depending on direction.
 */
#define bus_dmamap_sync(_a, _b, _c)

#endif /* linux */


/*
 * functions to map NIC to KRING indexes (n2k) and vice versa (k2n)
 */
static inline int
netmap_idx_n2k(struct netmap_kring *kr, int idx)
{
	int n = kr->nkr_num_slots;
	idx += kr->nkr_hwofs;
	if (idx < 0)
		return idx + n;
	else if (idx < n)
		return idx;
	else
		return idx - n;
}


static inline int
netmap_idx_k2n(struct netmap_kring *kr, int idx)
{
	int n = kr->nkr_num_slots;
	idx -= kr->nkr_hwofs;
	if (idx < 0)
		return idx + n;
	else if (idx < n)
		return idx;
	else
		return idx - n;
}


/* Entries of the look-up table. */
struct lut_entry {
	void *vaddr;		/* virtual address. */
	vm_paddr_t paddr;	/* physical address. */
};

struct netmap_obj_pool;

/*
 * NMB return the virtual address of a buffer (buffer 0 on bad index)
 * PNMB also fills the physical address
 */
static inline void *
NMB(struct netmap_adapter *na, struct netmap_slot *slot)
{
	struct lut_entry *lut = na->na_lut.lut;
	uint32_t i = slot->buf_idx;
	return (unlikely(i >= na->na_lut.objtotal)) ?
		lut[0].vaddr : lut[i].vaddr;
}

static inline void *
PNMB(struct netmap_adapter *na, struct netmap_slot *slot, uint64_t *pp)
{
	uint32_t i = slot->buf_idx;
	struct lut_entry *lut = na->na_lut.lut;
	void *ret = (i >= na->na_lut.objtotal) ? lut[0].vaddr : lut[i].vaddr;

#ifndef _WIN32
	*pp = (i >= na->na_lut.objtotal) ? lut[0].paddr : lut[i].paddr;
#else
	*pp = (i >= na->na_lut.objtotal) ? (uint64_t)lut[0].paddr.QuadPart : (uint64_t)lut[i].paddr.QuadPart;
#endif
	return ret;
}


/*
 * Structure associated to each netmap file descriptor.
 * It is created on open and left unbound (np_nifp == NULL).
 * A successful NIOCREGIF will set np_nifp and the first few fields;
 * this is protected by a global lock (NMG_LOCK) due to low contention.
 *
 * np_refs counts the number of references to the structure: one for the fd,
 * plus (on FreeBSD) one for each active mmap which we track ourselves
 * (linux automatically tracks them, but FreeBSD does not).
 * np_refs is protected by NMG_LOCK.
 *
 * Read access to the structure is lock free, because ni_nifp once set
 * can only go to 0 when nobody is using the entry anymore. Readers
 * must check that np_nifp != NULL before using the other fields.
 */
struct netmap_priv_d {
	struct netmap_if * volatile np_nifp;	/* netmap if descriptor. */

	struct netmap_adapter	*np_na;
	struct ifnet	*np_ifp;
	uint32_t	np_flags;	/* from the ioctl */
	u_int		np_qfirst[NR_TXRX],
			np_qlast[NR_TXRX]; /* range of tx/rx rings to scan */
	uint16_t	np_txpoll;	/* XXX and also np_rxpoll ? */

	int		np_refs;	/* use with NMG_LOCK held */

	/* pointers to the selinfo to be used for selrecord.
	 * Either the local or the global one depending on the
	 * number of rings.
	 */
	NM_SELINFO_T *np_si[NR_TXRX];
	struct thread	*np_td;		/* kqueue, just debugging */
};

struct netmap_priv_d *netmap_priv_new(void);
void netmap_priv_delete(struct netmap_priv_d *);

static inline int nm_kring_pending(struct netmap_priv_d *np)
{
	struct netmap_adapter *na = np->np_na;
	enum txrx t;
	int i;

	for_rx_tx(t) {
		for (i = np->np_qfirst[t]; i < np->np_qlast[t]; i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			if (kring->nr_mode != kring->nr_pending_mode) {
				return 1;
			}
		}
	}
	return 0;
}

#ifdef WITH_MONITOR

struct netmap_monitor_adapter {
	struct netmap_adapter up;

	struct netmap_priv_d priv;
	uint32_t flags;
};

#endif /* WITH_MONITOR */


#ifdef WITH_GENERIC
/*
 * generic netmap emulation for devices that do not have
 * native netmap support.
 */
int generic_netmap_attach(struct ifnet *ifp);
int generic_rx_handler(struct ifnet *ifp, struct mbuf *m);;

int nm_os_catch_rx(struct netmap_generic_adapter *gna, int intercept);
int nm_os_catch_tx(struct netmap_generic_adapter *gna, int intercept);

/*
 * the generic transmit routine is passed a structure to optionally
 * build a queue of descriptors, in an OS-specific way.
 * The payload is at addr, if non-null, and the routine should send or queue
 * the packet, returning 0 if successful, 1 on failure.
 *
 * At the end, if head is non-null, there will be an additional call
 * to the function with addr = NULL; this should tell the OS-specific
 * routine to send the queue and free any resources. Failure is ignored.
 */
struct nm_os_gen_arg {
	struct ifnet *ifp;
	void *m;	/* os-specific mbuf-like object */
	void *head, *tail; /* tailq, if the OS-specific routine needs to build one */
	void *addr;	/* payload of current packet */
	u_int len;	/* packet length */
	u_int ring_nr;	/* packet length */
	u_int qevent;   /* in txqdisc mode, place an event on this mbuf */
};

int nm_os_generic_xmit_frame(struct nm_os_gen_arg *);
int nm_os_generic_find_num_desc(struct ifnet *ifp, u_int *tx, u_int *rx);
void nm_os_generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq);
void nm_os_generic_set_features(struct netmap_generic_adapter *gna);

static inline struct ifnet*
netmap_generic_getifp(struct netmap_generic_adapter *gna)
{
        if (gna->prev)
            return gna->prev->ifp;

        return gna->up.up.ifp;
}

void netmap_generic_irq(struct netmap_adapter *na, u_int q, u_int *work_done);

//#define RATE_GENERIC  /* Enables communication statistics for generic. */
#ifdef RATE_GENERIC
void generic_rate(int txp, int txs, int txi, int rxp, int rxs, int rxi);
#else
#define generic_rate(txp, txs, txi, rxp, rxs, rxi)
#endif

/*
 * netmap_mitigation API. This is used by the generic adapter
 * to reduce the number of interrupt requests/selwakeup
 * to clients on incoming packets.
 */
void nm_os_mitigation_init(struct nm_generic_mit *mit, int idx,
                                struct netmap_adapter *na);
void nm_os_mitigation_start(struct nm_generic_mit *mit);
void nm_os_mitigation_restart(struct nm_generic_mit *mit);
int nm_os_mitigation_active(struct nm_generic_mit *mit);
void nm_os_mitigation_cleanup(struct nm_generic_mit *mit);
#else /* !WITH_GENERIC */
#define generic_netmap_attach(ifp)	(EOPNOTSUPP)
#endif /* WITH_GENERIC */

/* Shared declarations for the VALE switch. */

/*
 * Each transmit queue accumulates a batch of packets into
 * a structure before forwarding. Packets to the same
 * destination are put in a list using ft_next as a link field.
 * ft_frags and ft_next are valid only on the first fragment.
 */
struct nm_bdg_fwd {	/* forwarding entry for a bridge */
	void *ft_buf;		/* netmap or indirect buffer */
	uint8_t ft_frags;	/* how many fragments (only on 1st frag) */
	uint8_t _ft_port;	/* dst port (unused) */
	uint16_t ft_flags;	/* flags, e.g. indirect */
	uint16_t ft_len;	/* src fragment len */
	uint16_t ft_next;	/* next packet to same destination */
};

/* struct 'virtio_net_hdr' from linux. */
struct nm_vnet_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1	/* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID    2	/* Csum is valid */
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE         0       /* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4        1       /* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP          3       /* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6        4       /* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN          0x80    /* TCP has ECN set */
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};

#define WORST_CASE_GSO_HEADER	(14+40+60)  /* IPv6 + TCP */

/* Private definitions for IPv4, IPv6, UDP and TCP headers. */

struct nm_iphdr {
	uint8_t		version_ihl;
	uint8_t		tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
};

struct nm_tcphdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint8_t		doff;  /* Data offset + Reserved */
	uint8_t		flags;
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
};

struct nm_udphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
};

struct nm_ipv6hdr {
	uint8_t		priority_version;
	uint8_t		flow_lbl[3];

	uint16_t	payload_len;
	uint8_t		nexthdr;
	uint8_t		hop_limit;

	uint8_t		saddr[16];
	uint8_t		daddr[16];
};

/* Type used to store a checksum (in host byte order) that hasn't been
 * folded yet.
 */
#define rawsum_t uint32_t

rawsum_t nm_os_csum_raw(uint8_t *data, size_t len, rawsum_t cur_sum);
uint16_t nm_os_csum_ipv4(struct nm_iphdr *iph);
void nm_os_csum_tcpudp_ipv4(struct nm_iphdr *iph, void *data,
		      size_t datalen, uint16_t *check);
void nm_os_csum_tcpudp_ipv6(struct nm_ipv6hdr *ip6h, void *data,
		      size_t datalen, uint16_t *check);
uint16_t nm_os_csum_fold(rawsum_t cur_sum);

void bdg_mismatch_datapath(struct netmap_vp_adapter *na,
			   struct netmap_vp_adapter *dst_na,
			   const struct nm_bdg_fwd *ft_p,
			   struct netmap_ring *dst_ring,
			   u_int *j, u_int lim, u_int *howmany);

/* persistent virtual port routines */
int nm_os_vi_persist(const char *, struct ifnet **);
void nm_os_vi_detach(struct ifnet *);
void nm_os_vi_init_index(void);

/*
 * kernel thread routines
 */
struct nm_kthread; /* OS-specific kthread - opaque */
typedef void (*nm_kthread_worker_fn_t)(void *data);

/* kthread configuration */
struct nm_kthread_cfg {
	long				type;		/* kthread type/identifier */
	struct ptnet_ring_cfg		event;		/* event/ioctl fd */
	nm_kthread_worker_fn_t		worker_fn;	/* worker function */
	void				*worker_private;/* worker parameter */
	int				attach_user;	/* attach kthread to user process */
};
/* kthread configuration */
struct nm_kthread *nm_os_kthread_create(struct nm_kthread_cfg *cfg);
int nm_os_kthread_start(struct nm_kthread *);
void nm_os_kthread_stop(struct nm_kthread *);
void nm_os_kthread_delete(struct nm_kthread *);
void nm_os_kthread_wakeup_worker(struct nm_kthread *nmk);
void nm_os_kthread_send_irq(struct nm_kthread *);
void nm_os_kthread_set_affinity(struct nm_kthread *, int);
u_int nm_os_ncpus(void);

#ifdef WITH_PTNETMAP_HOST
/*
 * netmap adapter for host ptnetmap ports
 */
struct netmap_pt_host_adapter {
	struct netmap_adapter up;

	struct netmap_adapter *parent;
	int (*parent_nm_notify)(struct netmap_kring *kring, int flags);
	void *ptns;
};
/* ptnetmap HOST routines */
int netmap_get_pt_host_na(struct nmreq *nmr, struct netmap_adapter **na, int create);
int ptnetmap_ctl(struct nmreq *nmr, struct netmap_adapter *na);
static inline int
nm_ptnetmap_host_on(struct netmap_adapter *na)
{
	return na && na->na_flags & NAF_PTNETMAP_HOST;
}
#else /* !WITH_PTNETMAP_HOST */
#define netmap_get_pt_host_na(nmr, _2, _3) \
	((nmr)->nr_flags & (NR_PTNETMAP_HOST) ? EOPNOTSUPP : 0)
#define ptnetmap_ctl(_1, _2)   EINVAL
#define nm_ptnetmap_host_on(_1)   EINVAL
#endif /* !WITH_PTNETMAP_HOST */

#ifdef WITH_PTNETMAP_GUEST
/* ptnetmap GUEST routines */

typedef uint32_t (*nm_pt_guest_ptctl_t)(struct ifnet *, uint32_t);

/*
 * netmap adapter for guest ptnetmap ports
 */
struct netmap_pt_guest_adapter {
        /* The netmap adapter to be used by netmap applications.
	 * This field must be the first, to allow upcast. */
	struct netmap_hw_adapter hwup;

        /* The netmap adapter to be used by the driver. */
        struct netmap_hw_adapter dr;

	void *csb;

	/* Reference counter to track users of backend netmap port: the
	 * network stack and netmap clients.
	 * Used to decide when we need (de)allocate krings/rings and
	 * start (stop) ptnetmap kthreads. */
	int backend_regifs;

};

int netmap_pt_guest_attach(struct netmap_adapter *, void *,
			   unsigned int, nm_pt_guest_ptctl_t);
struct ptnet_ring;
bool netmap_pt_guest_txsync(struct ptnet_ring *ptring, struct netmap_kring *kring,
			    int flags);
bool netmap_pt_guest_rxsync(struct ptnet_ring *ptring, struct netmap_kring *kring,
			    int flags);
int ptnet_nm_krings_create(struct netmap_adapter *na);
void ptnet_nm_krings_delete(struct netmap_adapter *na);
void ptnet_nm_dtor(struct netmap_adapter *na);
#endif /* WITH_PTNETMAP_GUEST */

#endif /* _NET_NETMAP_KERN_H_ */
