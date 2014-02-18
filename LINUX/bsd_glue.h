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

#ifndef _BSD_GLUE_H
#define _BSD_GLUE_H

/* a set of headers used in netmap */
#include <linux/version.h>
#include <linux/compiler.h>	// ACCESS_ONCE()

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

#include <linux/io.h>	// virt_to_phys
#include <linux/hrtimer.h>

#define printf(fmt, arg...)	printk(KERN_ERR fmt, ##arg)
#define KASSERT(a, b)		BUG_ON(!(a))

/*----- support for compiling on older versions of linux -----*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
#define HRTIMER_MODE_REL	HRTIMER_REL
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#define skb_copy_from_linear_data_offset(skb, offset, to, copy)	\
	memcpy(to, (skb)->data + offset, copy)

#define skb_copy_to_linear_data_offset(skb, offset, from, copy)	\
	memcpy((skb)->data + offset, from, copy)

#define skb_copy_to_linear_data(skb, from, copy)		\
	memcpy((skb)->data, from, copy)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#define ACCESS_ONCE(x)	(x)
#define uintptr_t	unsigned long
#define skb_get_queue_mapping(m)	(0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
/* Forward a hrtimer so it expires after the hrtimer's current now */
static inline u64 hrtimer_forward_now(struct hrtimer *timer,
                                      ktime_t interval)
{
        return hrtimer_forward(timer, timer->base->get_time(), interval);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
typedef unsigned long phys_addr_t;
extern struct net init_net;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28) // XXX
#define netdev_ops	hard_start_xmit
struct net_device_ops {
	int (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32) // XXX 31
#define netdev_tx_t	int
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
#define usleep_range(a, b)	msleep((a)+(b)+999)
#endif /* up to 2.6.35 */

/*----------- end of LINUX_VERSION_CODE dependencies ----------*/

/* Type redefinitions. XXX check them */
typedef	void *			bus_dma_tag_t;
typedef	void *			bus_dmamap_t;
typedef	int			bus_size_t;
typedef	int			bus_dma_segment_t;
typedef void *			bus_addr_t;
#define vm_paddr_t		phys_addr_t
/* XXX the 'off_t' on Linux corresponds to a 'long' */
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

#define GET_MBUF_REFCNT(m)	NM_ATOMIC_READ(&((m)->users))
#define netmap_get_mbuf(size)	alloc_skb(size, GFP_ATOMIC)
/*
 * on tx we force skb->queue_mapping = ring_nr,
 * but on rx it is the driver that sets the value,
 * and it is 0 for no setting, ring_nr+1 otherwise.
 */
#define MBUF_TXQ(m)		skb_get_queue_mapping(m)
#define MBUF_RXQ(m)		(skb_rx_queue_recorded(m) ? skb_get_rx_queue(m) : 0)
#define SET_MBUF_DESTRUCTOR(m, f) m->destructor = (void *)&f

/* Magic number for sk_buff.priority field, used to take decisions in
 * generic_ndo_start_xmit() and in linux_generic_rx_handler().
 */
#define NM_MAGIC_PRIORITY_TX 0xad86d310U
#define NM_MAGIC_PRIORITY_RX 0xad86d311U

/*
 * m_copydata() copies from mbuf to buffer following the mbuf chain.
 * skb_copy_bits() copies the skb headlen and all the fragments.
 */

#define m_copydata(m, o, l, b)          skb_copy_bits(m, o, b, l)

#define copyin(_from, _to, _len)	copy_from_user(_to, _from, _len)

/*
 * struct ifnet is remapped into struct net_device on linux.
 * ifnet has an if_softc field pointing to the device-specific struct
 * (adapter).
 * On linux the ifnet/net_device is at the beginning of the device-specific
 * structure, so a pointer to the first field of the ifnet works.
 * We don't use this in netmap, though.
 *
 *	if_xname	name		device name
 *	if_capenable	priv_flags
 *		we would use "features" but it is all taken.
 *		XXX check for conflict in flags use.
 *
 * In netmap we use if_pspare[0] to point to the netmap_adapter,
 * in linux we have no spares so we overload ax25_ptr, and the detection
 * for netmap-capable is some magic in the area pointed by that.
 */
#define WNA(_ifp)		(_ifp)->ax25_ptr

#define ifnet           	net_device      /* remap */
#define	if_xname		name		/* field ifnet-> net_device */
#define	if_capenable		priv_flags	/* IFCAP_NETMAP */

/* some other FreeBSD APIs */
struct net_device* ifunit_ref(const char *name);
void if_rele(struct net_device *ifp);

/* hook to send from user space */
netdev_tx_t linux_netmap_start_xmit(struct sk_buff *, struct net_device *);

/* prevent ring params change while in netmap mode */
int linux_netmap_set_ringparam(struct net_device *, struct ethtool_ringparam *);
#ifdef ETHTOOL_SCHANNELS
int linux_netmap_set_channels(struct net_device *, struct ethtool_channels *);
#endif

#define CURVNET_SET(x)
#define CURVNET_RESTORE(x)

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
	ulong flags = ACCESS_ONCE(m->flags);
        spin_unlock_irqrestore(&(m->sl), flags);
}

#define mtx_init(a, b, c, d)	spin_lock_init(&((a)->sl))
#define mtx_destroy(a)		// XXX spin_lock_destroy(a)

/*
 * XXX these must be changed, as we cannot sleep within the RCU.
 * Must change to proper rwlock, and then can move the definitions
 * into the main netmap.c file.
 */
#define BDG_RWLOCK_T		struct rw_semaphore
#define BDG_RWINIT(b)		init_rwsem(&(b)->bdg_lock)
#define BDG_WLOCK(b)		down_write(&(b)->bdg_lock)
#define BDG_WUNLOCK(b)		up_write(&(b)->bdg_lock)
#define BDG_RLOCK(b)		down_read(&(b)->bdg_lock)
#define BDG_RUNLOCK(b)		up_read(&(b)->bdg_lock)
#define BDG_RTRYLOCK(b)		down_read_trylock(&(b)->bdg_lock)
#define BDG_SET_VAR(lval, p)	((lval) = (p))
#define BDG_GET_VAR(lval)	(lval)
#define BDG_FREE(p)		kfree(p)

/* use volatile to fix a probable compiler error on 2.6.25 */
#define malloc(_size, type, flags)                      \
        ({ volatile int _v = _size; kmalloc(_v, GFP_ATOMIC | __GFP_ZERO); })

#define free(a, t)	kfree(a)

// XXX do we need GPF_ZERO ?
// XXX do we need GFP_DMA for slots ?
// http://www.mjmwired.net/kernel/Documentation/DMA-API.txt

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

#define contigmalloc(sz, ty, flags, a, b, pgsz, c)		\
	(char *) __get_free_pages(GFP_ATOMIC |  __GFP_ZERO,	\
		    ilog2(roundup_pow_of_two((sz)/PAGE_SIZE)))
#define contigfree(va, sz, ty)	free_pages((unsigned long)va,	\
		    ilog2(roundup_pow_of_two(sz)/PAGE_SIZE))

#define vtophys		virt_to_phys

/*--- selrecord and friends ---*/
/* wake_up() or wake_up_interruptible() ? */
#define	OS_selwakeup(sw, pri)	wake_up(sw)
#define selrecord(x, y)		poll_wait((struct file *)x, y, pwait)

// #define knlist_destroy(x)	// XXX todo

#define	tsleep(a, b, c, t)	msleep(10)
// #define	wakeup(sw)				// XXX double check

#define microtime		do_gettimeofday		// debugging


/*
 * The following trick is to map a struct cdev into a struct miscdevice
 * On FreeBSD cdev and cdevsw are two different objects.
 */
#define	cdev			miscdevice
#define	cdevsw			miscdevice


/*
 * XXX to complete - the dmamap interface
 */
#define	BUS_DMA_NOWAIT	0
#define	bus_dmamap_load(_1, _2, _3, _4, _5, _6, _7)
#define	bus_dmamap_unload(_1, _2)

typedef int (d_mmap_t)(struct file *f, struct vm_area_struct *vma);
typedef unsigned int (d_poll_t)(struct file * file, struct poll_table_struct *pwait);

/*
 * make_dev will set an error and return the first argument.
 * This relies on the availability of the 'error' local variable.
 * For old linux systems that do not have devfs, generate a
 * message in syslog so the sysadmin knows which command to run
 * in order to create the /dev/netmap entry
 */
#define make_dev(_cdev, _zero, _uid, _gid, _perm, _name)	\
	({error = misc_register(_cdev);				\
	D("run mknod /dev/%s c %d %d # error %d",		\
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

#define devfs_get_cdevpriv(pp)				\
	({ *(struct netmap_priv_d **)pp = ((struct file *)td)->private_data; 	\
		(*pp ? 0 : ENOENT); })

/* devfs_set_cdevpriv cannot fail on linux */
#define devfs_set_cdevpriv(p, fn)				\
	({ ((struct file *)td)->private_data = p; (p ? 0 : EINVAL); })


#define devfs_clear_cdevpriv()	do {				\
		netmap_dtor(priv); ((struct file *)td)->private_data = 0;	\
	} while (0)

#endif /* _BSD_GLUE_H */
