/*
 * Copyright (C) 2012-2014 Luigi Rizzo - Universita` di Pisa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
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
 * glue code to build the netmap bsd code under linux.
 * Some of these tweaks are generic, some are specific for
 * character device drivers and network code/device drivers.
 */

#ifndef NETMAP_BSD_GLUE_H
#define NETMAP_BSD_GLUE_H

/* a set of headers used in netmap */
#include <linux/version.h>

#include <linux/if.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>	// eth_type_trans
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/virtio.h>	// virt_to_phys
#include <net/sock.h>
#include <linux/delay.h>	// msleep
#include <linux/skbuff.h>		// skb_copy_to_linear_data_offset
#include <linux/vmalloc.h>

#include <linux/io.h>	// virt_to_phys
#include <linux/hrtimer.h>
#include <linux/highmem.h> // kmap

#define KASSERT(a, b)		BUG_ON(!(a))

/*----- support for compiling on older versions of linux -----*/
#include "netmap_linux_config.h"

#ifndef dma_rmb
#define dma_rmb() rmb()
#endif /* dma_rmb */

#ifdef NETMAP_LINUX_HAVE_PAGE_REF
#include <linux/page_ref.h>
#endif /* NETMAP_LINUX_HAVE_PAGE_REF */

#ifndef NETMAP_LINUX_HAVE_HRTIMER_MODE_REL
#define HRTIMER_MODE_REL	HRTIMER_REL
#endif

#ifndef NETMAP_LINUX_HAVE_SKB_COPY_LINEAR
#define skb_copy_from_linear_data_offset(skb, offset, to, copy)	\
	memcpy(to, (skb)->data + offset, copy)

#define skb_copy_to_linear_data_offset(skb, offset, from, copy)	\
	memcpy((skb)->data + offset, from, copy)

#define skb_copy_to_linear_data(skb, from, copy)		\
	memcpy((skb)->data, from, copy)
#endif /* HAVE_SKB_COPY_LINEAR */

#ifndef NETMAP_LINUX_HAVE_UINTPTR
#define uintptr_t	unsigned long
#endif

#ifdef NETMAP_LINUX_HAVE_WAIT_QUEUE_ENTRY_T
#define wait_queue_t	wait_queue_entry_t
#endif

#ifndef NETMAP_LINUX_HAVE_QUEUE_MAPPING
#define skb_get_queue_mapping(m)	(0)
#define skb_set_queue_mapping(a, b)	do { (void)(a); (void)(b); } while (0)
#endif

#ifndef NETMAP_LINUX_HAVE_HRTIMER_FORWARD_NOW
/* Forward a hrtimer so it expires after the hrtimer's current now */
static inline u64 hrtimer_forward_now(struct hrtimer *timer,
					ktime_t interval)
{
	return hrtimer_forward(timer, timer->base->get_time(), interval);
}
#endif

#ifndef NETMAP_LINUX_HAVE_PHYS_ADDR_T
typedef unsigned long phys_addr_t;
#endif

#ifndef NETMAP_LINUX_HAVE_INIT_NET
extern struct net init_net;
#endif

#ifndef NETMAP_LINUX_HAVE_NETDEV_OPS
#define netdev_ops	hard_start_xmit
struct net_device_ops {
	int (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
	int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);
};
#endif /* !NETDEV_OPS */

#ifndef NETMAP_LINUX_HAVE_NETDEV_TX_T
#define netdev_tx_t	int
#endif

#if !defined(NETMAP_LINUX_HAVE_USLEEP_RANGE) && !defined(usleep_range)
#define usleep_range(a, b)	msleep((a)+(b)+999)
#endif

#ifdef NETMAP_LINUX_HAVE_PAGE_REF
#define NM_SET_PAGE_COUNT(page, v)	set_page_count(page, v)
#else
#define NM_SET_PAGE_COUNT(page, v)	atomic_set(&((page)->NETMAP_LINUX_PAGE_COUNT), (v))
#endif

#ifndef NETMAP_LINUX_HAVE_SPLIT_PAGE
#define split_page(page, order) 			  \
	do {						  \
		int i_;					  \
		for (i_ = 1; i_ < (1 << (order)); i_++)	  \
			NM_SET_PAGE_COUNT(&(page)[i_], 1);\
	} while (0)
#endif /* HAVE_SPLIT_PAGE */

#if !defined(NETMAP_LINUX_HAVE_NNITD) && !defined(netdev_notifier_info_to_dev)
#define netdev_notifier_info_to_dev(ptr)	(ptr)
#endif /* HAVE_NNITD */

#if !defined(NETMAP_LINUX_HAVE_SKB_FRAG_SIZE) && !defined(skb_frag_size)
static inline unsigned int skb_frag_size(const skb_frag_t *frag) {
	return frag->size;
}
#endif
#if !defined(NETMAP_LINUX_HAVE_SKB_FRAG_ADDRESS) && !defined(skb_frag_address)
static inline void *skb_frag_address(const skb_frag_t *frag) {
	return page_address(frag->page) + frag->page_offset;
}
#endif
#if !defined(NETMAP_LINUX_HAVE_SKB_CHECKSUM_START_OFFSET) && !defined(skb_checksum_start_offset)
static inline int skb_checksum_start_offset(const struct sk_buff *skb) {
	return skb->csum_start - skb_headroom(skb);
}
#endif

#ifdef NETMAP_LINUX_HAVE_NUM_RX_QUEUES
#define DEV_NUM_RX_QUEUES(_netdev) (_netdev)->num_rx_queues
#else
#define	DEV_NUM_RX_QUEUES(_netdev) 1
#endif

#ifdef NETMAP_LINUX_HAVE_REG_NOTIF_RH
#define NM_REG_NETDEV_NOTIF(nb)		register_netdevice_notifier_rh(nb)
#define NM_UNREG_NETDEV_NOTIF(nb)	unregister_netdevice_notifier_rh(nb)
#else
#define NM_REG_NETDEV_NOTIF(nb)		register_netdevice_notifier(nb)
#define NM_UNREG_NETDEV_NOTIF(nb)	unregister_netdevice_notifier(nb)
#endif /* NETMAP_LINUX_HAVE_REG_NOTIF_RH */

#ifndef NETMAP_LINUX_HAVE_PAGE_TO_VIRT
#define page_to_virt(p) 		phys_to_virt(page_to_phys(p))
#endif /* NETMAP_LINUX_HAVE_PAGE_TO_VIRT */

/*----------- end of LINUX_VERSION_CODE dependencies ----------*/

/* Type redefinitions. XXX check them */
#define bus_dma_tag_t 		struct device *
#define bus_dmamap_t 		phys_addr_t*

typedef	int			bus_size_t;
typedef	int			bus_dma_segment_t;
typedef void *			bus_addr_t;
#define vm_paddr_t		phys_addr_t
/* the 'off_t' on Linux corresponds to a 'long' */
#define vm_offset_t		uint32_t
#define vm_ooffset_t		unsigned long
struct thread;

/* endianness macros/functions */
#define le16toh			le16_to_cpu
#define le32toh			le32_to_cpu
#define le64toh			le64_to_cpu
#define be16toh			be16_to_cpu
#define be32toh			be32_to_cpu
#define be64toh			be64_to_cpu
#define htole32			cpu_to_le32
#define htole64			cpu_to_le64
#define htobe16			cpu_to_be16
#define htobe32			cpu_to_be32

#include <linux/jiffies.h>
#define	time_second	(jiffies_to_msecs(jiffies) / 1000U )

#define bzero(a, len)		memset(a, 0, len)

/* Atomic variables. */
#define NM_ATOMIC_TEST_AND_SET(p)	test_and_set_bit(0, (p))
#define NM_ATOMIC_CLEAR(p)		clear_bit(0, (p))

#define NM_ATOMIC_SET(p, v)             atomic_set(p, v)
#define NM_ATOMIC_INC(p)                atomic_inc(p)
#define NM_ATOMIC_READ_AND_CLEAR(p)     atomic_xchg(p, 0)
#define NM_ATOMIC_READ(p)               atomic_read(p)


// XXX maybe implement it as a proper function somewhere
// it is important to set s->len before the copy.
#define	m_devget(_buf, _len, _ofs, _dev, _fn)	( {		\
	struct sk_buff *s = netdev_alloc_skb(_dev, _len);	\
	if (s) {						\
		skb_put(s, _len);					\
		skb_copy_to_linear_data_offset(s, _ofs, _buf, _len);	\
		s->protocol = eth_type_trans(s, _dev);		\
	}							\
	s; } )

#define	mbuf			sk_buff
#define	m_nextpkt		next			// chain of mbufs
#define m_freem(m)		dev_kfree_skb_any(m)	// free a sk_buff

#ifdef NETMAP_LINUX_HAVE_REFCOUNT_T
#define MBUF_REFCNT(m)			refcount_read(&((m)->users))
#else  /* !NETMAP_LINUX_HAVE_REFCOUNT_T */
#define MBUF_REFCNT(m)			NM_ATOMIC_READ(&((m)->users))
#endif /* !NETMAP_LINUX_HAVE_REFCOUNT_T */
/*
 * on tx we force skb->queue_mapping = ring_nr,
 * but on rx it is the driver that sets the value,
 * and it is 0 for no setting, ring_nr+1 otherwise.
 */
#define MBUF_TXQ(m)		skb_get_queue_mapping(m)
#define MBUF_RXQ(m)		(skb_rx_queue_recorded(m) ? skb_get_rx_queue(m) : 0)
#define SET_MBUF_DESTRUCTOR(m, f) m->destructor = (void *)f

/* Magic number for sk_buff.priority field, used to take decisions in
 * generic_ndo_start_xmit(), linux_generic_rx_handler() and
 * generic_qdisc_dequeue().
 */
#define NM_MAGIC_PRIORITY_TX	0xad86d310U
#define NM_MAGIC_PRIORITY_TXQE	0xad86d311U
#define NM_MAGIC_PRIORITY_RX	0xad86d30fU

#define MBUF_QUEUED(m)		((m->priority & (~0x1)) == NM_MAGIC_PRIORITY_TX)

/*
 * m_copydata() copies from mbuf to buffer following the mbuf chain.
 * skb_copy_bits() copies the skb headlen and all the fragments.
 */

#define m_copydata(m, o, l, b)          skb_copy_bits(m, o, b, l)

#define copyin(_from, _to, _len)	(copy_from_user(_to, _from, _len) ? EFAULT : 0)
#define copyout(_from, _to, _len)	(copy_to_user(_to, _from, _len) ? EFAULT : 0)

/* na attach/detach routines */
#ifdef NETMAP_LINUX_HAVE_AX25PTR
/*
 * struct ifnet is remapped into struct net_device on linux.
 * ifnet has an if_softc field pointing to the device-specific struct
 * (adapter).
 * On linux the ifnet/net_device is at the beginning of the device-specific
 * structure, so a pointer to the first field of the ifnet works.
 * We don't use this in netmap, though.
 *
 *	if_xname	name		device name
 *		we would use "features" but it is all taken.
 *
 * In netmap we use if_pspare[0] to point to the netmap_adapter,
 * in linux we have no spares so we overload ax25_ptr, and the detection
 * for netmap-capable is some magic in the area pointed by that.
 */
#define WNA(_ifp)		(_ifp)->ax25_ptr
/* use the default NM_ATTACH_NA/NM_DETACH_NA defined in netmap_kernel.h */
#else /* !NETMAP_LINUX_HAVE_AX25PTR */
/*
 * We hide behind the ethtool_ops
 */
int linux_netmap_set_ringparam(struct net_device *, struct ethtool_ringparam *);
struct netmap_linux_magic {
	struct ethtool_ops eto;
	const struct ethtool_ops *save_eto;
};
#define NM_OS_MAGIC	struct netmap_linux_magic
#define WNA(ifp)	(ifp->ethtool_ops)
#define NM_DETACH_NA(ifp)  do {						\
	(ifp)->ethtool_ops = NA(ifp)->magic.save_eto;			\
} while (0)
#define NM_ATTACH_NA(ifp, na) do {					\
	if ((ifp)->ethtool_ops) {					\
		(na)->magic.eto = *(ifp)->ethtool_ops;			\
		(na)->magic.save_eto = (ifp)->ethtool_ops;		\
	} else {							\
		memset(&(na)->magic, 0, sizeof((na)->magic));		\
	}								\
	(na)->magic.eto.set_ringparam = linux_netmap_set_ringparam;	\
	(ifp)->ethtool_ops = &(na)->magic.eto;				\
} while (0)
#define NM_RESTORE_NA(ifp, na) do {					\
	if (na == NULL) {						\
		NM_DETACH_NA(ifp);					\
	} else {							\
		(ifp)->ethtool_ops = &(na)->magic.eto;			\
	}								\
} while (0)
#define NM_NA_VALID(ifp)						\
	(NA(ifp) && NA(ifp)->magic.eto.set_ringparam == 		\
		linux_netmap_set_ringparam)
#define NM_NA_CLASH(ifp)	(0)	// XXX
#endif /* NETAP_LINUX_HAVE_AX25PTR */

#define ifnet           	net_device      /* remap */
#define	if_xname		name		/* field ifnet-> net_device */

/* some other FreeBSD APIs */
struct net_device* ifunit_ref(const char *name);
void if_ref(struct net_device *ifp);
void if_rele(struct net_device *ifp);

/* hook to send from user space */
netdev_tx_t linux_netmap_start_xmit(struct sk_buff *, struct net_device *);

/* prevent MTU changes while in netmap mode */
int linux_netmap_change_mtu(struct net_device *dev, int new_mtu);

/* prevent ring params change while in netmap mode */
int linux_netmap_set_ringparam(struct net_device *, struct ethtool_ringparam *);
#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
int linux_netmap_set_channels(struct net_device *, struct ethtool_channels *);
#endif

#define refcount_acquire(_a)    atomic_add(1, (atomic_t *)_a)
#define refcount_release(_a)    atomic_dec_and_test((atomic_t *)_a)


/*
 * We use spin_lock_irqsave() because we use the lock in the
 * (hard) interrupt context.
 */
typedef struct {
	spinlock_t      sl;
	ulong           flags;
} safe_spinlock_t;

static inline void mtx_lock(safe_spinlock_t *m)
{
	spin_lock_irqsave(&(m->sl), m->flags);
}

static inline void mtx_unlock(safe_spinlock_t *m)
{
	ulong flags = *(volatile ulong *)&m->flags;
	spin_unlock_irqrestore(&(m->sl), flags);
}

#define mtx_init(a, b, c, d)	spin_lock_init(&((a)->sl))
#define mtx_destroy(a)

#define mtx_lock_spin(a)	mtx_lock(a)
#define mtx_unlock_spin(a)	mtx_unlock(a)

/*
 * XXX these must be changed, as we cannot sleep within the RCU.
 * Must change to proper rwlock, and then can move the definitions
 * into the main netmap.c file.
 */
#define BDG_RWLOCK_T		struct rw_semaphore
#define BDG_RWINIT(b)		init_rwsem(&(b)->bdg_lock)
#define BDG_RWDESTROY(b)
#define BDG_WLOCK(b)		down_write(&(b)->bdg_lock)
#define BDG_WUNLOCK(b)		up_write(&(b)->bdg_lock)
#define BDG_RLOCK(b)		down_read(&(b)->bdg_lock)
#define BDG_RUNLOCK(b)		up_read(&(b)->bdg_lock)
#define BDG_RTRYLOCK(b)		down_read_trylock(&(b)->bdg_lock)
#define BDG_SET_VAR(lval, p)	((lval) = (p))
#define BDG_GET_VAR(lval)	(lval)

#ifndef ilog2 /* not in 2.6.18 */
static inline int ilog2(uint64_t n)
{
	uint64_t k = 1ULL<<63;
	int i;
	for (i = 63; i >= 0 && !(n &k); i--, k >>=1)
		;
	return i;
}
#endif /* ilog2 */

/* XXX do we need GFP_DMA for slots ?
 * Documentation/DMA-API.txt */

#define contigmalloc(sz, ty, flags, a, b, pgsz, c) ({		\
	unsigned int order_ =					\
		ilog2(roundup_pow_of_two(sz)/PAGE_SIZE);	\
	struct page *p_ = alloc_pages(GFP_ATOMIC | __GFP_ZERO,  \
		order_);					\
	if (p_ != NULL) 					\
		split_page(p_, order_);				\
	(p_ != NULL ? (char*)page_address(p_) : NULL); })

#define contigfree(va, sz, ty)					\
	do {							\
		unsigned int npages_ =				\
			roundup_pow_of_two(sz)/PAGE_SIZE;	\
		for (; npages_; npages_--, va += PAGE_SIZE)	\
			free_page((unsigned long)va);		\
	} while (0)

#define vtophys		virt_to_phys

/*--- selrecord and friends ---*/
struct nm_linux_selrecord_t;
#define NM_SELRECORD_T	struct nm_linux_selrecord_t

#define netmap_knlist_destroy(x)	// TODO

#define	tsleep(a, b, c, t)	msleep(10)

#define microtime		do_gettimeofday		/* debugging */


/*
 * The following trick is to map a struct cdev into a struct miscdevice
 * On FreeBSD cdev and cdevsw are two different objects.
 */
#define	cdev			miscdevice
#define	cdevsw			miscdevice

/*
 * make_dev_credf() will set an error and return the first argument.
 * This relies on the availability of the 'error' local variable.
 * For old linux systems that do not have devfs, generate a
 * message in syslog so the sysadmin knows which command to run
 * in order to create the /dev/netmap entry
 */
#define make_dev_credf(_flags, _cdev, _zero, _cred, _uid, _gid, _perm, _name)	\
	({error = misc_register(_cdev);				\
	D("run mknod /dev/%s c %d %d # returned %d",		\
	    (_cdev)->name, MISC_MAJOR, (_cdev)->minor, error);	\
	 _cdev; } )
#define destroy_dev(_cdev)	misc_deregister(_cdev)

/*--- sysctl API ----*/
/*
 * linux: sysctl are mapped into /sys/module/ipfw_mod parameters
 * windows: they are emulated via get/setsockopt
 */
#define CTLFLAG_RD              1
#define CTLFLAG_RW              2

struct sysctl_oid;
struct sysctl_req;


#define SYSCTL_DECL(_1)
#define SYSCTL_OID(_1, _2, _3, _4, _5, _6, _7, _8)
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define _SYSCTL_BASE(_name, _var, _ty, _perm)			\
		module_param_named(_name, *(_var), _ty,         \
			( (_perm) == CTLFLAG_RD) ? 0444: 0644 )

/* XXX should implement this */
extern struct kernel_param_ops generic_sysctl_ops;

#define SYSCTL_PROC(_base, _oid, _name, _mode, _var, _val, _fn, _ty, _desc) \
		module_param_cb(_name, &generic_sysctl_ops, _fn,	\
			( (_mode) & CTLFLAG_WR) ? 0644: 0444 )


/* for a string, _var is a preallocated buffer of size _varlen */
#define SYSCTL_STRING(_base, _oid, _name, _mode, _var, _varlen, _desc)	\
		module_param_string(_name, _var, _varlen,		\
			((_mode) == CTLFLAG_RD) ? 0444: 0644 )

#define SYSCTL_INT(_base, _oid, _name, _mode, _var, _val, _desc)        \
	_SYSCTL_BASE(_name, _var, int, _mode)

#define SYSCTL_LONG(_base, _oid, _name, _mode, _var, _val, _desc)       \
	_SYSCTL_BASE(_name, _var, long, _mode)

#define SYSCTL_ULONG(_base, _oid, _name, _mode, _var, _val, _desc)      \
	_SYSCTL_BASE(_name, _var, ulong, _mode)

#define SYSCTL_UINT(_base, _oid, _name, _mode, _var, _val, _desc)       \
	_SYSCTL_BASE(_name, _var, uint, _mode)

// #define TUNABLE_INT(_name, _ptr)

#define SYSCTL_VNET_PROC                SYSCTL_PROC
#define SYSCTL_VNET_INT                 SYSCTL_INT

#define SYSCTL_HANDLER_ARGS             \
	struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);

#define MALLOC_DECLARE(a)
#define MALLOC_DEFINE(a, b, c)

/* ---- namespaces ------ */
#ifdef CONFIG_NET_NS
int netmap_bns_register(void);
void netmap_bns_unregister(void);
#define NM_BNS_GET(b)	(b)->ns = netmap_bns_get()
#define NM_BNS_PUT(b)	netmap_bns_put(b->ns)
#else
#define NM_BNS_GET(b)	do { (void)(b); } while (0)
#define NM_BNS_PUT(b)   do { (void)(b); } while (0)
#endif

#define if_printf(ifp, fmt, ...)  dev_info(&(ifp)->dev, fmt, ##__VA_ARGS__)

#ifndef BIT_ULL
#define BIT_ULL(nr)	(1ULL << (nr))
#endif /* !BIT_ULL */

#endif /* NETMAP_BSD_GLUE_H */
