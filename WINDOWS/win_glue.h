/*
 * Copyright (C) 2015 Universita` di Pisa. All rights reserved.
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
 
#ifndef _WIN_GLUE_H_
#define _WIN_GLUE_H_

#ifdef __CYGWIN__
#define _WIN32
#endif //__CYGWIN__
//Disabling unuseful warnings
#pragma warning(disable:4018)	//wrong corrispondence between signed and unsigned
#pragma warning(disable:4047)	//!= <type> differs from <2nd type> in the levels of indirect reference
#pragma warning(disable:4098)	//void function returns a value
#pragma warning(disable:4118)	//error in between signed and unsigned
#pragma warning(disable:4100)	//formal parameter without references
#pragma warning(disable:4101)	//local variable without references
#pragma warning(disable:4115)	//definition of type between parenthesis
#pragma warning(disable:4127)	//constant conditional expression
#pragma warning(disable:4133)	//warning: uncompatible types: From <1> to <2>
#pragma warning(disable:4142)	//benign type redefinition
#pragma warning(disable:4189)	//local variable initialized but without references
#pragma warning(disable:4200)	//non-standard extension: matrix of zero dimension in struct/union
#pragma warning(disable:4201)	//nameless structure
#pragma warning(disable:4242)	//possible loss of data in conversion
#pragma warning(disable:4244)	//possible loss of data in conversion
#pragma warning(disable:4245)	//conversion from int to uint_32t: corrispondence error between signed and unsigned
#pragma warning(disable:4389)	//wrong corrispondence between signed and unsigned

#pragma warning(disable:4267)	//

/*#define FILTER_MAJOR_NDIS_VERSION   NDIS_SUPPORT_NDIS6
#define FILTER_MINOR_NDIS_VERSION   NDIS_SUPPORT_NDIS6
#define NDIS_SUPPORT_NDIS6			1	//gives support for NDIS NET_BUFFERs*/

#define WIN32_LEAN_AND_MEAN 1

#include <ndis.h>
#include <string.h>
#include <WinDef.h>
//#include <Iptypes.h>		// definition of IP_ADAPTER_INFO
#include <netioapi.h>		// definition of IF_NAMESIZE
#include <ntddk.h>          // various NT definitions
#include <errno.h>
#include <intrin.h>			//machine specific code (for example le64toh)
#include <Ntstrsafe.h>

#define PRIV_MEMORY_POOL_TAG				'memP'
#define PIPES_POOL_TAG						'epiP'
#define RINGS_POOL_TAG						'gniR'

//Originally defined in LINUX\IF.H
#define	IFNAMSIZ 44//IF_NAMESIZE //defined in netioapi.h, is 256
//XXX_ale	must set the same here and in userspace somehow

/*********************************************************
*   REDEFINITION OF UNCOMMON STRUCTURES FOR WINDOWS		 *
**********************************************************/

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef SSIZE_T ssize_t;
typedef uint32_t u_int;
typedef ULONG u_long;
typedef struct timeval {
  LONGLONG tv_sec;
  LONGLONG tv_usec;
} timeval;
typedef char* caddr_t;

typedef PHYSICAL_ADDRESS 	vm_paddr_t;
typedef uint32_t			vm_offset_t;
typedef ULONG 				vm_ooffset_t; 

#define thread PIO_STACK_LOCATION
//--------------------------------------------------------

/*********************************************************
*      		  	ERRNO->NTSTATUS TRANSLATION				 *  
**********************************************************/
#define ENOBUFS		STATUS_DEVICE_INSUFFICIENT_RESOURCES	
#define EOPNOTSUPP	STATUS_INVALID_DEVICE_REQUEST
/*********************************************************
*        		  	NO USE IN WINDOWS CODE         		 *
**********************************************************/
#define destroy_dev(a)
#define CURVNET_SET(x)
#define CURVNET_RESTORE()
#define __user
#define	nm_iommu_group_id(dev)	0
/*********************************************************
* TRANSLATION OF GCC COMPILER ATTRIBUTES TO MSVC COMPILER*
**********************************************************/

#ifdef _MSC_VER
#define inline __inline
#define	__builtin_prefetch(x)	_mm_prefetch(x,_MM_HINT_T2)
#endif //_MSC_VER

static void panic(const char *fmt, ...)
{
	NT_ASSERT(1);
}
#define __assert	NT_ASSERT
#define assert	NT_ASSERT


/*********************************************************
*        			SPINLOCKS DEFINITION        		 *  
**********************************************************/
typedef struct {
        KSPIN_LOCK      sl;
        KIRQL          irql;
} win_spinlock_t;

static inline void spin_lock_init(win_spinlock_t *m)
{
	KeInitializeSpinLock(&(m->sl));
}

//Acquires the spinlock and saves the current IRQL level
static inline void mtx_lock(win_spinlock_t *m)
{
    KeAcquireSpinLock(&(m->sl), &(m->irql));
}

//Release the spinlock and restore the old IRQL level
static inline void mtx_unlock(win_spinlock_t *m)
{
    KeReleaseSpinLock(&(m->sl), (m->irql));
}

#define mtx_init(a, b, c, d)	spin_lock_init(a)
#define mtx_destroy(a)		// XXX spin_lock_destroy(a)

#define mtx_lock_spin(a)	mtx_lock(a)
#define mtx_unlock_spin(a)	mtx_unlock(a)
//--------------------------------------------------------

/*********************************************************
*        		READ/WRITE LOCKS DEFINITION        		 *
**********************************************************/

#define BDG_RWLOCK_T			ERESOURCE
#define BDG_RWINIT(b)			ExInitializeResourceLite(b.bdg_lock)
#define BDG_RWDESTROY(b)		ExDeleteResourceLite(b.bdg_lock)
#define BDG_WLOCK(b)			ExAcquireResourceExclusiveLite(&b->bdg_lock, TRUE)
#define BDG_WUNLOCK(b)			ExReleaseResourceLite(&b->bdg_lock)
#define BDG_RLOCK(b)			ExAcquireResourceSharedLite(&b->bdg_lock,TRUE)
#define BDG_RUNLOCK(b)			ExReleaseResourceLite(&b->bdg_lock)
#define BDG_RTRYLOCK(b)			ExAcquireResourceExclusiveLite(&b->bdg_lock, FALSE)
#define BDG_SET_VAR(lval, p)	((lval) = (p))
#define BDG_GET_VAR(lval)		(lval)
#define BDG_FREE(p)				free(p)
//--------------------------------------------------------

/*********************************************************
*        			SLEEP/WAKEUP THREADS        		 *
**********************************************************/
static void win_selrecord(PIO_STACK_LOCATION irpSp, PKEVENT ev)
{
	irpSp->FileObject->FsContext2 = ev;
	KeClearEvent(ev);
}

#define PI_NET								16
#define init_waitqueue_head(x)				KeInitializeEvent(x, NotificationEvent, TRUE);
#define netmap_knlist_destroy(x)
#define OS_selwakeup(queue, priority)		KeSetEvent(queue, priority, FALSE);			
#pragma warning(disable:4702)	//
#define OS_selrecord(thread, queue)		    win_selrecord(thread, queue)
#define tsleep(ident, priority, wmesg, time)	KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)time)	
//--------------------------------------------------------

#define mb									KeMemoryBarrier
#define rmb									KeMemoryBarrier //XXX_ale: doesn't seems to exist just a read barrier

/*********************************************************
*        			TIME FUNCTIONS		        		 *
**********************************************************/
void do_gettimeofday(struct timeval *tv);
static int time_uptime_w32()
{
	int ret;
	LARGE_INTEGER tm;
	KeQuerySystemTime(&tm);
	ret = (int)(tm.QuadPart / (LONGLONG)1000000);
	return ret;
}

#define microtime		do_gettimeofday
#define time_second		time_uptime_w32
//--------------------------------------------------------

#define snprintf 							_snprintf
#define printf								DbgPrint

#define copyin(src, dst, copy_len)					RtlCopyBytes(&dst, src, copy_len)

static NTSTATUS SafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size)
{
	ASSERT(result != NULL);
	if (result == NULL || size == 0)
		return STATUS_INVALID_PARAMETER;

	result->Buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'rtsM');
	result->Length = 0;
	result->MaximumLength = size;

	if (result->Buffer)
		RtlZeroMemory(result->Buffer, size);
	else
		return STATUS_NO_MEMORY;

	return STATUS_SUCCESS;
}

/*********************************************************
*        		GENERIC/HW SPECIFIC STRUCTURES     		 *
**********************************************************/

typedef struct _FUNCTION_POINTER_XCHANGE
{
	PVOID(*pingPacketInsertionTest)(void);			//test function
	struct NET_BUFFER*(*netmap_catch_rx)(struct net_device*, uint32_t length, const char* data);
	NDIS_HANDLE(*get_device_handle_by_ifindex)(int ifIndex, PNDIS_HANDLE UserSendNetBufferListPool); //UserSendNetBufferListPool is returned from the call
	void(*set_ifp_in_device_handle)(struct net_device*, BOOLEAN);
	NTSTATUS(*injectPacket)(NDIS_HANDLE device, NDIS_HANDLE UserSendNetBufferListPool, PVOID data, uint32_t length, BOOLEAN sendToMiniport);
} FUNCTION_POINTER_XCHANGE, *PFUNCTION_POINTER_XCHANGE;

//XXX_ale: I'm sure that somewhere in windows definitions there's a structure like the original
struct netmap_adapter;
#if 0
struct ifnet {
	char    if_xname[IFNAMSIZ];     		/* external name (name + unit) */
	//        struct ifaltq if_snd;         /* output queue (includes altq) */
	struct netmap_adapter* na;

	int* netmap_generic_rx_handler;
};
#endif
struct net_device {
	char					if_xname[IFNAMSIZ];			// external name (name + unit) 
	//        struct ifaltq if_snd;         /* output queue (includes altq) */
	struct netmap_adapter*	na;
	NDIS_HANDLE				deviceHandle;
	NDIS_HANDLE				UserSendNetBufferListPool;
	int						ifIndex;
};

#define ifnet		net_device
struct mbuf {
	struct mbuf			*m_next;
	struct mbuf			*m_nextpkt;
	uint32_t			m_len;
	struct net_device	*dev;
	//PNET_BUFFER			pkt;
	PVOID				pkt;
	void*(*netmap_default_mbuf_destructor)(struct mbuf *m);
};

//XXX_ale To be correctly redefined
#define GET_MBUF_REFCNT(a)				1
#define	SET_MBUF_DESTRUCTOR(a,b)		
#define MBUF_IFP(m)						m->dev	

static void
generic_timer_handler(struct hrtimer *t)
{
#if 0
	struct nm_generic_mit *mit =
		container_of(t, struct nm_generic_mit, mit_timer);
	u_int work_done;

	if (!mit->mit_pending) {
		return HRTIMER_NORESTART;
	}

	/* Some work arrived while the timer was counting down:
	* Reset the pending work flag, restart the timer and send
	* a notification.
	*/
	mit->mit_pending = 0;
	/* below is a variation of netmap_generic_irq  XXX revise */
	if (nm_netmap_on(mit->mit_na)) {
		netmap_common_irq(mit->mit_na->ifp, mit->mit_ring_idx, &work_done);
		generic_rate(0, 0, 0, 0, 0, 1);
	}
	netmap_mitigation_restart(mit);
	return HRTIMER_RESTART;
#endif
	return 0;
}

static void netmap_mitigation_init(struct nm_generic_mit *mit, int idx,
struct netmap_adapter *na)
{
	/*hrtimer_init(&mit->mit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mit->mit_timer.function = &generic_timer_handler;
	mit->mit_pending = 0;
	mit->mit_ring_idx = idx;
	mit->mit_na = na;*/
}

static void netmap_mitigation_start(struct nm_generic_mit *mit)
{
	//hrtimer_start(&mit->mit_timer, ktime_set(0, netmap_generic_mit), HRTIMER_MODE_REL);
}

static void netmap_mitigation_restart(struct nm_generic_mit *mit)
{
	//hrtimer_forward_now(&mit->mit_timer, ktime_set(0, netmap_generic_mit));
}

static int netmap_mitigation_active(struct nm_generic_mit *mit)
{
	return 1;
	//return hrtimer_active(&mit->mit_timer);
}

static void netmap_mitigation_cleanup(struct nm_generic_mit *mit)
{
	//hrtimer_cancel(&mit->mit_timer);
}

static void
netmap_default_mbuf_destructor(struct mbuf *m)
{
	if (m->pkt != NULL)
	{
		ExFreePoolWithTag(m->pkt, 'pBUF');
		m->pkt = NULL;
	}
	ExFreePoolWithTag(m, 'MBUF');
	m = NULL;
}

static struct mbuf* netmap_get_mbuf(uint32_t buf_size)
{
	struct mbuf *m;
	m = ExAllocatePoolWithTag(NonPagedPool, buf_size, 'MBUF');
	if (m) {
		RtlZeroMemory(m, buf_size);
		m->netmap_default_mbuf_destructor = &netmap_default_mbuf_destructor;
		//ND(5, "create m %p refcnt %d", m, GET_MBUF_REFCNT(m));
	}
	return m;
}

static inline void win32_ndis_packet_freem(struct mbuf* m)
{
	if (m->pkt != NULL)
	{
		ExFreePoolWithTag(m->pkt, 'pubm');
		m->pkt = NULL;
	}
	if (m != NULL)
	{
		ExFreePoolWithTag(m, 'fubm');
		m = NULL;
	}	
}

#define	MBUF_LEN(m)											m->m_len
#define m_devget(slot_addr, slot_len, offset, dev, fn)		NULL
#define m_freem(mbuf)										win32_ndis_packet_freem(mbuf);
#define m_copydata(source, offset, length, dst)				RtlCopyMemory(dst, source->pkt, length)


#define le64toh(x)		_byteswap_uint64(x)	//defined in intrin.h

struct net_device* ifunit_ref(const char *name);
void if_rele(struct net_device *ifp);

#define WNA(_ifp)		_ifp->na
#define NM_BNS_GET(b)	do { (void)(b); } while (0)
#define NM_BNS_PUT(b)   do { (void)(b); } while (0)
#define NM_SEND_UP

/*********************************************************
*                   ATOMIC OPERATIONS     		         *  
**********************************************************/
#define NM_ATOMIC_T 					volatile long
#define atomic_t						NM_ATOMIC_T
#define NM_ATOMIC_TEST_AND_SET(p)       (!InterlockedBitTestAndSet(p,0))
#define NM_ATOMIC_CLEAR(p)              InterlockedBitTestAndReset(p,0)
#define refcount_acquire(_a)    		InterlockedExchangeAdd((atomic_t *)_a, 1)
#define refcount_release(_a)    		(InterlockedDecrement((atomic_t *)_a) < 0)
#define NM_ATOMIC_SET(p, v)             InterlockedExchange(p, v)
#define NM_ATOMIC_INC(p)                InterlockedIncrement(p)
#define NM_ATOMIC_READ_AND_CLEAR(p)     InterlockedExchange(p, 0)
#define NM_ATOMIC_READ(p)               InterlockedExchangeAdd(p, 0)
//--------------------------------------------------------
/*********************************************************
*                   KERNEL MEMORY ALLOCATION	         *  
**********************************************************/

int win32_devfs_get_cdevpriv(struct netmap_priv_d **mem, PIO_STACK_LOCATION td);
static inline int ilog2(uint64_t n);
static inline int roundup_pow_of_two(int sz);
char* win_contigMalloc(int sz, int page_size);
void win_ContigFree(void* virtualAddress);

#define bcopy(_s, _d, _l)					RtlCopyMemory(_d, _s, _l)
#define bzero(addr, size)					RtlZeroMemory(addr, size)
#define malloc(size, structType, flags)		win_kernel_malloc(size)
#define free(addr, structType)				ExFreePoolWithTag(addr, RINGS_POOL_TAG)
#define realloc(src, len, old_len)			win_reallocate(src, len, old_len)

static inline PVOID win_reallocate(void* src, size_t size, size_t oldSize)
{
	//DbgPrint("Netmap.sys: win_reallocate(%p, %i, %i)", src, size, oldSize);
	PVOID newBuff = NULL;
	if (src == NULL)
	{
		if (size == 0)
		{
			return NULL;
		}
		else{
			newBuff = ExAllocatePoolWithTag(NonPagedPool, size, PIPES_POOL_TAG);
			if (newBuff == NULL)
			{
				return NULL;
			}
			RtlZeroMemory(newBuff, size);
		}
	}
	else{
		if (size == 0)
		{
			ExFreePoolWithTag(src, PIPES_POOL_TAG);
		}
		else{
			if (size != oldSize)
			{
				newBuff = ExAllocatePoolWithTag(NonPagedPool, size, PIPES_POOL_TAG);
				if (newBuff == NULL)
				{
					return NULL;
				}
				RtlZeroMemory(newBuff, size);
				if (size > oldSize)
				{
					RtlCopyMemory(newBuff, src, oldSize);
				}
				else
				{
					RtlCopyMemory(newBuff, src, size);
				}
				ExFreePoolWithTag(src, PIPES_POOL_TAG);
			}
			else
			{
				newBuff = src;
			}
		}
	}
	return newBuff;
}

static void* win_kernel_malloc(size_t size)
{
	void* mem = ExAllocatePoolWithTag(NonPagedPool, size, RINGS_POOL_TAG);
	if (mem != NULL)
	{
		RtlZeroMemory(mem, size);
	}
	return mem;
}

#define contigmalloc(sz, ty, flags, a, b, pgsz, c)  win_contigMalloc(sz,pgsz)					
#define contigfree(va, sz, ty)						win_ContigFree(va)	

#define vtophys										MmGetPhysicalAddress
#define devfs_get_cdevpriv(mem)						win32_devfs_get_cdevpriv(mem, td)
#define MALLOC_DEFINE(a,b,c)
//--------------------------------------------------------
/*********************************************************
* SYSCTL emulation (copied from dummynet\glue.h)		 *
**********************************************************/
int do_netmap_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len);
int do_netmap_get_ctl(struct sock *sk, int cmd, void __user *user, int *len);

enum sopt_dir { SOPT_GET, SOPT_SET };

struct  sockopt {
	enum    sopt_dir sopt_dir; /* is this a get or a set? */
	int     sopt_level;     /* second arg of [gs]etsockopt */
	int     sopt_name;      /* third arg of [gs]etsockopt */
#ifdef _X64EMU
	void* pad1;
	void* pad2;
#endif
	void   *sopt_val;       /* fourth arg of [gs]etsockopt */
	size_t  sopt_valsize;   /* (almost) fifth arg of [gs]etsockopt */
#ifdef _X64EMU
	void* pad3;
	void* pad4;
#endif
	struct  thread *sopt_td; /* calling thread or null if kernel */
};

#define STRINGIFY(x) #x

enum {
	SYSCTLTYPE_INT = 0,
	SYSCTLTYPE_UINT = 1,
	SYSCTLTYPE_SHORT = 2,
	SYSCTLTYPE_USHORT = 3,
	SYSCTLTYPE_LONG = 4,
	SYSCTLTYPE_ULONG = 5,
	SYSCTLTYPE_STRING = 6,

	/* the following are SYSCTL_PROC equivalents of the above,
	* where the SYSCTLTYPE is shifted 2 bits,
	* and SYSCTLTYPE_PROC is set
	*/
	SYSCTLTYPE_PROC = 0x100,
	CTLTYPE_INT = (0x100 | (0 << 2)),
	CTLTYPE_UINT = (0x100 | (1 << 2))
};

struct sysctlhead {
	uint32_t blocklen; //total size of the entry
	uint32_t namelen; //strlen(name) + '\0'
	uint32_t flags; //type and access
	uint32_t datalen;
};

#ifdef SYSCTL_NODE
#undef SYSCTL_NODE
#endif
#define SYSCTL_NODE(a,b,c,d,e,f)
#define SYSCTL_DECL(a)
#define SYSCTL_VNET_PROC(a,b,c,d,e,f,g,h,i)
#define GST_HARD_LIMIT 100

/* In the module, GST is implemented as an array of
* sysctlentry, but while passing data to the userland
* pointers are useless, the buffer is actually made of:
* - sysctlhead (fixed size, containing lengths)
* - data (typically 32 bit)
* - name (zero-terminated and padded to mod4)
*/

struct sysctlentry {
	struct sysctlhead head;
	char* name;
	void* data;
};

struct sysctltable {
	int count; //number of valid tables
	int totalsize; //total size of valid entries of al the valid tables
	void* namebuffer; //a buffer for all chained names
	struct sysctlentry entry[GST_HARD_LIMIT];
};

#ifdef SYSBEGIN
#undef SYSBEGIN
#endif
#define SYSBEGIN(x) void sysctl_addgroup_##x() {
#ifdef SYSEND
#undef SYSEND
#endif
#define SYSEND }

#define CTLFLAG_RD		1
#define CTLFLAG_RDTUN	1
#define CTLFLAG_RW		2
#define CTLFLAG_SECURE3	0 // unsupported
#define CTLFLAG_VNET    0	/* unsupported */

/* XXX remove duplication */
#define SYSCTL_INT(a,b,c,d,e,f,g) 				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_INT << 2), sizeof(*e), e)

#define SYSCTL_VNET_INT(a,b,c,d,e,f,g)				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_INT << 2), sizeof(*e), e)

#define SYSCTL_UINT(a,b,c,d,e,f,g)				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_UINT << 2), sizeof(*e), e)

#define SYSCTL_VNET_UINT(a,b,c,d,e,f,g)				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_UINT << 2), sizeof(*e), e)

#define SYSCTL_LONG(a,b,c,d,e,f,g)				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_LONG << 2), sizeof(*e), e)

#define SYSCTL_ULONG(a,b,c,d,e,f,g)				\
	sysctl_pushback(STRINGIFY(a) "." STRINGIFY(c) + 1,	\
		(d) | (SYSCTLTYPE_ULONG << 2), sizeof(*e), e)

#define TUNABLE_INT(a,b)

void keinit_GST(void);
void keexit_GST(void);
int kesysctl_emu_set(void* p, int l);
int kesysctl_emu_get(struct sockopt* sopt);
void sysctl_pushback(char* name, int flags, int datalen, void* data);
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

int do_cmd(int optname, void *optval, uintptr_t optlen);

//--------------------------------------------------------

/*********************************************************
*			POLL VALUES DEFINITIONS						 *
**********************************************************/
#ifndef POLLRDNORM
#define POLLRDNORM  0x0040
#endif
#ifndef POLLRDBAND
#define POLLRDBAND  0x0080
#endif
#ifndef POLLIN
#define POLLIN		0x0001
#endif
#ifndef POLLPRI
#define POLLPRI     0x0002
#endif

#ifndef POLLWRNORM
#define POLLWRNORM  0x0100
#endif
#ifndef POLLOUT
#define POLLOUT		0x0004
#endif
#ifndef POLLWRBAND
#define POLLWRBAND  0x0200
#endif

#ifndef POLLERR
#define POLLERR     0x0008
#endif
#ifndef POLLHUP
#define POLLHUP     0x0010
#endif
#ifndef POLLNVAL
#define POLLNVAL    0x0020
#endif


#endif //_WIN_GLUE_H