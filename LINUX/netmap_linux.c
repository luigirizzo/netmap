/*
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

#include "bsd_glue.h"
#include <linux/file.h>   /* fget(int fd) */

#include <asm/types.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <net/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/netmap_bdg.h>
#include <net/ip6_checksum.h>
#include <linux/rtnetlink.h>
#include <linux/nsproxy.h>
#include <linux/ip.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/sock.h>
#ifdef NETMAP_LINUX_HAVE_SCHED_MM
#include <linux/sched/mm.h>
#endif /* NETMAP_LINUX_HAVE_SCHED_MM */
#ifdef WITH_PASTE
#include <linux/file.h> // sockfd_put()/fput()
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h> // sock_owned_by_user
#include <net/netmap_paste.h>
#endif /* WITH_PASTE */

#include "netmap_linux_config.h"

void *
nm_os_malloc(size_t size)
{
	void *rv = kmalloc(size, GFP_ATOMIC | __GFP_ZERO);
	if (IS_ERR(rv))
		return NULL;
	return rv;
}

void *
nm_os_vmalloc(size_t size)
{
	void *rv = vmalloc(size);
	if (IS_ERR(rv))
		return NULL;
	return rv;
}

void *
nm_os_realloc(void *addr, size_t new_size, size_t old_size)
{
	void *rv;
	(void)old_size;
	rv = krealloc(addr, new_size, GFP_ATOMIC | __GFP_ZERO);
	if (IS_ERR(rv))
		return NULL;
	return rv;
}

void
nm_os_free(void *addr){
	kfree(addr);
}

void
nm_os_vfree(void *addr){
	vfree(addr);
}

int
nm_os_selinfo_init(NM_SELINFO_T *si, const char *name)
{
	init_waitqueue_head(si);
	return 0;
}

void
nm_os_selinfo_uninit(NM_SELINFO_T *si)
{
}

void
nm_os_ifnet_lock(void)
{
	rtnl_lock();
}

void
nm_os_ifnet_unlock(void)
{
	rtnl_unlock();
}

void
nm_os_get_module(void)
{
	__module_get(THIS_MODULE);
}

void
nm_os_put_module(void)
{
	module_put(THIS_MODULE);
}

/* Register for a notification on device removal */
static int
linux_netmap_notifier_cb(struct notifier_block *b,
		unsigned long val, void *v)
{
	struct ifnet *ifp = netdev_notifier_info_to_dev(v);

	/* linux calls us while holding rtnl_lock() */
	switch (val) {
	case NETDEV_REGISTER:
		netmap_undo_zombie(ifp);
		break;
	case NETDEV_UNREGISTER:
		netmap_make_zombie(ifp);
		break;
	case NETDEV_GOING_DOWN:
		netmap_disable_all_rings(ifp);
		break;
	case NETDEV_UP:
		netmap_enable_all_rings(ifp);
		break;
	default:
		/* we don't care */
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block linux_netmap_netdev_notifier = {
	.notifier_call = linux_netmap_notifier_cb,
};

static int nm_os_ifnet_registered;

int
nm_os_ifnet_init(void)
{
	int error = NM_REG_NETDEV_NOTIF(&linux_netmap_netdev_notifier);
	if (!error)
		nm_os_ifnet_registered = 1;
	return error;
}

void
nm_os_ifnet_fini(void)
{
	if (nm_os_ifnet_registered) {
		NM_UNREG_NETDEV_NOTIF(&linux_netmap_netdev_notifier);
		nm_os_ifnet_registered = 0;
	}
}

unsigned
nm_os_ifnet_mtu(struct ifnet *ifp)
{
	return ifp->mtu;
}

#ifdef WITH_EXTMEM
struct nm_os_extmem {
	struct page **pages;
	int nr_pages;
	int mapped;
};

void
nm_os_extmem_delete(struct nm_os_extmem *e)
{
	int i;
	for (i = 0; i < e->nr_pages; i++) {
		if (i < e->mapped)
			kunmap(e->pages[i]);
#ifdef NETMAP_LINUX_HAVE_PIN_PAGES
		unpin_user_page(e->pages[i]);
#else
		put_page(e->pages[i]);
#endif
	}
	if (e->pages)
		nm_os_vfree(e->pages);
	nm_os_free(e);
}

char *
nm_os_extmem_nextpage(struct nm_os_extmem *e)
{
	if (e->mapped >= e->nr_pages)
		return NULL;
	return kmap(e->pages[e->mapped++]);
}

int
nm_os_extmem_isequal(struct nm_os_extmem *e1, struct nm_os_extmem *e2)
{
	int i;

	if (e1->nr_pages != e2->nr_pages)
		return 0;

	for (i = 0; i < e1->nr_pages; i++)
		if (e1->pages[i] != e2->pages[i])
			return 0;

	return 1;
}

int
nm_os_extmem_nr_pages(struct nm_os_extmem *e)
{
	return e->nr_pages;
}


struct nm_os_extmem *
nm_os_extmem_create(unsigned long p, struct nmreq_pools_info *pi, int *perror)
{
	unsigned long end, start;
	int nr_pages, res;
	struct nm_os_extmem *e = NULL;
	int err;
	struct page **pages;

	end = (p + pi->nr_memsize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	start = p >> PAGE_SHIFT;
	nr_pages = end - start;

	e = nm_os_malloc(sizeof(*e));
	if (e == NULL) {
		nm_prerr("failed to allocate os_extmem");
		err = ENOMEM;
		goto out;
	}

	pages = nm_os_vmalloc(nr_pages * sizeof(*pages));
	if (pages == NULL) {
		nm_prerr("failed to allocate pages array (nr_pages %d)", nr_pages);
		err = ENOMEM;
		goto out;
	}

	e->pages = pages;

#ifdef NETMAP_LINUX_HAVE_PIN_PAGES
	res = pin_user_pages_unlocked(
			p,
			nr_pages,
			pages,
			FOLL_WRITE | FOLL_SPLIT | FOLL_POPULATE);
#elif defined(NETMAP_LINUX_HAVE_GUP_4ARGS)
	res = get_user_pages_unlocked(
			p,
			nr_pages,
			pages,
			FOLL_WRITE | FOLL_GET | FOLL_SPLIT | FOLL_POPULATE); // XXX check other flags
#elif defined(NETMAP_LINUX_HAVE_GUP_5ARGS)
	res = get_user_pages_unlocked(
			p,
			nr_pages,
			1, /* write */
			0, /* don't force */
			pages);
#elif defined(NETMAP_LINUX_HAVE_GUP_7ARGS)
	res = get_user_pages_unlocked(
			current,
			current->mm,
			p,
			nr_pages,
			1, /* write */
			0, /* don't force */
			pages);
#else
	down_read(&current->mm->mmap_sem);
	res = get_user_pages(
			current,
			current->mm,
			p,
			nr_pages,
			1, /* write */
			0, /* don't force */
			pages,
			NULL);
	up_read(&current->mm->mmap_sem);
#endif	/* NETMAP_LINUX_GUP */

	e->nr_pages = res;

	if (res < nr_pages) {
		nm_prerr("failed to get user pages: res %d nr_pages %d", res, nr_pages);
		err = EFAULT;
		goto out;
	}

	return e;

out:
	if (e)
		nm_os_extmem_delete(e);
	if (perror)
		*perror = err;
	return NULL;
}
#endif /* WITH_EXTMEM */

#ifdef NETMAP_LINUX_HAVE_IOMMU
#include <linux/iommu.h>

/* #################### IOMMU ################## */
/*
 * Returns the IOMMU domain id that the device belongs to.
 */
int nm_iommu_group_id(struct device *dev)
{
	struct iommu_group *grp;
	int id;

	if (!dev)
		return -1;

	grp = iommu_group_get(dev);
	if (!grp)
		return -1;

	id = iommu_group_id(grp);

	iommu_group_put(grp);

	return id;
}
#else /* ! HAVE_IOMMU */
int nm_iommu_group_id(struct device *dev)
{
	return 0;
}
#endif /* HAVE_IOMMU */

/* #################### VALE OFFLOADINGS SUPPORT ################## */

/* Compute and return a raw checksum over (data, len), using 'cur_sum'
 * as initial value. Both 'cur_sum' and the return value are in host
 * byte order.
 */
rawsum_t
nm_os_csum_raw(uint8_t *data, size_t len, rawsum_t cur_sum)
{
	return csum_partial(data, len, cur_sum);
}

/* Compute an IPv4 header checksum, where 'data' points to the IPv4 header,
 * and 'len' is the IPv4 header length. Return value is in network byte
 * order.
 */
uint16_t
nm_os_csum_ipv4(struct nm_iphdr *iph)
{
	return ip_compute_csum((void*)iph, sizeof(struct nm_iphdr));
}

/* Compute and insert a TCP/UDP checksum over IPv4: 'iph' points to the IPv4
 * header, 'data' points to the TCP/UDP header, 'datalen' is the length of
 * TCP/UDP header + payload.
 */
void
nm_os_csum_tcpudp_ipv4(struct nm_iphdr *iph, void *data,
		      size_t datalen, uint16_t *check)
{
	*check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				datalen, iph->protocol,
				csum_partial(data, datalen, 0));
}

/* Compute and insert a TCP/UDP checksum over IPv6: 'ip6h' points to the IPv6
 * header, 'data' points to the TCP/UDP header, 'datalen' is the length of
 * TCP/UDP header + payload.
 */
void
nm_os_csum_tcpudp_ipv6(struct nm_ipv6hdr *ip6h, void *data,
		      size_t datalen, uint16_t *check)
{
	*check = csum_ipv6_magic((void *)&ip6h->saddr, (void*)&ip6h->daddr,
				datalen, ip6h->nexthdr,
				csum_partial(data, datalen, 0));
}

uint16_t
nm_os_csum_fold(rawsum_t cur_sum)
{
	return csum_fold(cur_sum);
}

/* on linux we send up one packet at a time */
void *
nm_os_send_up(struct ifnet *ifp, struct mbuf *m, struct mbuf *prev)
{
	(void)ifp;
	(void)prev;
	m->priority = NM_MAGIC_PRIORITY_RX; /* do not reinject to netmap */
	netif_rx(m);
	return NULL;
}

int
nm_os_mbuf_has_csum_offld(struct mbuf *m)
{
	return m->ip_summed == CHECKSUM_PARTIAL;
}

int
nm_os_mbuf_has_seg_offld(struct mbuf *m)
{
	return skb_is_gso(m);
}

#ifdef WITH_GENERIC
/* ####################### MITIGATION SUPPORT ###################### */

/*
 * The generic driver calls netmap once per received packet.
 * This is inefficient so we implement a mitigation mechanism,
 * as follows:
 * - the first packet on an idle receiver triggers a notification
 *   and starts a timer;
 * - subsequent incoming packets do not cause a notification
 *   until the timer expires;
 * - when the timer expires and there are pending packets,
 *   a notification is sent up and the timer is restarted.
 */
static NETMAP_LINUX_TIMER_RTYPE
generic_timer_handler(struct hrtimer *t)
{
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
		netmap_common_irq(mit->mit_na, mit->mit_ring_idx, &work_done);
		generic_rate(0, 0, 0, 0, 0, 1);
	}
	nm_os_mitigation_restart(mit);

	return HRTIMER_RESTART;
}


void
nm_os_mitigation_init(struct nm_generic_mit *mit, int idx,
			struct netmap_adapter *na)
{
	hrtimer_init(&mit->mit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mit->mit_timer.function = &generic_timer_handler;
	mit->mit_pending = 0;
	mit->mit_ring_idx = idx;
	mit->mit_na = na;
}


void
nm_os_mitigation_start(struct nm_generic_mit *mit)
{
	hrtimer_start(&mit->mit_timer, ktime_set(0, netmap_generic_mit), HRTIMER_MODE_REL);
}

void
nm_os_mitigation_restart(struct nm_generic_mit *mit)
{
	hrtimer_forward_now(&mit->mit_timer, ktime_set(0, netmap_generic_mit));
}

int
nm_os_mitigation_active(struct nm_generic_mit *mit)
{
	return hrtimer_active(&mit->mit_timer);
}

void
nm_os_mitigation_cleanup(struct nm_generic_mit *mit)
{
	hrtimer_cancel(&mit->mit_timer);
}



/* #################### GENERIC ADAPTER SUPPORT ################### */

/*
 * This handler is registered within the attached net_device
 * in the Linux RX subsystem, so that every mbuf passed up by
 * the driver can be stolen to the network stack.
 * Stolen packets are put in a queue where the
 * generic_netmap_rxsync() callback can extract them.
 * Packets that comes from netmap_txsync_to_host() are not
 * stolen.
 */
#ifdef NETMAP_LINUX_HAVE_RX_REGISTER
enum {
	NM_RX_HANDLER_STOLEN,
	NM_RX_HANDLER_PASS,
};

static inline int
linux_generic_rx_handler_common(struct mbuf *m)
{
	int stolen;

	/* If we were called by NM_SEND_UP(), we want to pass the mbuf
	   to network stack. We detect this situation looking at the
	   priority field. */
	if (m->priority == NM_MAGIC_PRIORITY_RX) {
		return NM_RX_HANDLER_PASS;
	}

	/* When we intercept a sk_buff coming from the driver, it happens that
	   skb->data points to the IP header, e.g. the ethernet header has
	   already been pulled. Since we want the netmap rings to contain the
	   full ethernet header, we push it back, so that the RX ring reader
	   can see it. */
	skb_push(m, ETH_HLEN);

	/* Possibly steal the mbuf and notify the pollers for a new RX
	 * packet. */
	stolen = generic_rx_handler(m->dev, m);
	if (stolen) {
		return NM_RX_HANDLER_STOLEN;
	}

	skb_pull(m, ETH_HLEN);

	return NM_RX_HANDLER_PASS;
}

#ifdef NETMAP_LINUX_HAVE_RX_HANDLER_RESULT
static rx_handler_result_t
linux_generic_rx_handler(struct mbuf **pm)
{
	int ret = linux_generic_rx_handler_common(*pm);

	return likely(ret == NM_RX_HANDLER_STOLEN) ? RX_HANDLER_CONSUMED :
						     RX_HANDLER_PASS;
}
#else /* ! HAVE_RX_HANDLER_RESULT */
static struct sk_buff *
linux_generic_rx_handler(struct mbuf *m)
{
	int ret = linux_generic_rx_handler_common(m);

	return likely(ret == NM_RX_HANDLER_STOLEN) ? NULL : m;
}
#endif /* HAVE_RX_HANDLER_RESULT */
#endif /* HAVE_RX_REGISTER */

/* Ask the Linux RX subsystem to intercept (or stop intercepting)
 * the packets incoming from the interface attached to 'na'.
 */
int
nm_os_catch_rx(struct netmap_generic_adapter *gna, int intercept)
{
#ifndef NETMAP_LINUX_HAVE_RX_REGISTER
#warning "Packet reception with emulated (generic) mode not supported for this kernel version"
	return 0;
#else /* HAVE_RX_REGISTER */
	struct netmap_adapter *na = &gna->up.up;
	struct ifnet *ifp = netmap_generic_getifp(gna);
	int ret = 0;

	if (!ifp) {
		nm_prerr("Failed to get ifp");
		return -EBUSY;
	}

	nm_os_ifnet_lock();
	if (intercept) {
		ret = -netdev_rx_handler_register(ifp,
				&linux_generic_rx_handler, na);
	} else {
		netdev_rx_handler_unregister(ifp);
	}
	nm_os_ifnet_unlock();
	return ret;
#endif /* HAVE_RX_REGISTER */
}

#ifndef NETMAP_LINUX_SELECT_QUEUE_PARM3
#define NETMAP_LINUX_SELECT_QUEUE_PARM3 void*
#endif /*! NETMAP_LINUX_SELECT_QUEUE_PARM3 */

#ifdef NETMAP_LINUX_SELECT_QUEUE
static u16
generic_ndo_select_queue(struct ifnet *ifp, struct mbuf *m
#if NETMAP_LINUX_SELECT_QUEUE >= 3
			, NETMAP_LINUX_SELECT_QUEUE_PARM3 accel_priv
#if NETMAP_LINUX_SELECT_QUEUE >= 4
				, select_queue_fallback_t fallback
#endif /* >= 4 */
#endif /* >= 3 */
		)
{
	return skb_get_queue_mapping(m); // actually 0 on 2.6.23 and before
}
#endif /* SELECT_QUEUE */

/* Replacement for the driver ndo_start_xmit() method.
 * When this function is invoked because of the dev_queue_xmit() call
 * in generic_xmit_frame() (e.g. because of a txsync on the NIC), we have
 * to call the original ndo_start_xmit() method.
 * In all the other cases (e.g. when the TX request comes from the network
 * stack) we intercept the packet and put it into the RX ring associated
 * to the host stack.
 */
static netdev_tx_t
generic_ndo_start_xmit(struct mbuf *m, struct ifnet *ifp)
{
	struct netmap_generic_adapter *gna =
		(struct netmap_generic_adapter *)NA(ifp);

	if (likely(m->priority == NM_MAGIC_PRIORITY_TX)) {
		netdev_tx_t ret;

		/* Reset priority, so that generic_netmap_tx_clean()
		 * knows that it can reclaim this mbuf. */
		m->priority = 0;
		ret = gna->save_start_xmit(m, ifp); /* To the driver. */
		if (unlikely(ret == NETDEV_TX_BUSY)) {
			/* The driver is busy, so the packet has not
			 * been consumed and will be resubmitted
			 * later. Set the priority again to our
			 * magic value, so that it hits again
			 * this code path. */
			m->priority = NM_MAGIC_PRIORITY_TX;
		}
		return ret;
	}

	/* To a netmap RX ring. */
	return linux_netmap_start_xmit(m, ifp);
}

struct nm_generic_qdisc {
	unsigned int limit;
};

static int
generic_qdisc_init(struct Qdisc *qdisc, struct nlattr *opt
#ifdef NETMAP_LINUX_HAVE_QDISC_EXTACK
		, struct netlink_ext_ack *extack
#endif /* NETMAP_LINUX_HAVE_QDISC_EXTACK */
	)
{
	struct nm_generic_qdisc *priv = NULL;

	/* Kernel < 2.6.39, do not have qdisc->limit, so we will
	 * always use our priv->limit, for simplicity. */

	priv = qdisc_priv(qdisc);
	priv->limit = 1024; /* This is going to be overridden. */

	if (opt) {
		uint32_t *limit = nla_data(opt);

		if (nla_len(opt) < sizeof(*limit) || *limit <= 0) {
#ifdef NETMAP_LINUX_HAVE_QDISC_EXTACK
			NL_SET_ERR_MSG(extack, "Invalid netlink attribute");
#else
			nm_prerr("Invalid netlink attribute");
#endif /* NETMAP_LINUX_HAVE_QDISC_EXTACK */
			return -EINVAL;
		}
		priv->limit = *limit;
	}

	/* Qdisc bypassing is not an option for now.
	qdisc->flags |= TCQ_F_CAN_BYPASS; */

	return 0;
}

static int
generic_qdisc_enqueue(struct mbuf *m, struct Qdisc *qdisc
#ifdef NETMAP_LINUX_HAVE_QDISC_ENQUEUE_TOFREE
		      , struct mbuf **to_free
#endif
)
{
	struct nm_generic_qdisc *priv = qdisc_priv(qdisc);

	if (unlikely(qdisc_qlen(qdisc) >= priv->limit)) {
		nm_prlim(5, "dropping mbuf");

		return qdisc_drop(m, qdisc
#ifdef NETMAP_LINUX_HAVE_QDISC_ENQUEUE_TOFREE
		       , to_free
#endif
			);
		/* or qdisc_reshape_fail() ? */
	}

	nm_prdis(5, "Enqueuing mbuf, len %u", qdisc_qlen(qdisc));

	return qdisc_enqueue_tail(m, qdisc);
}

static struct mbuf *
generic_qdisc_dequeue(struct Qdisc *qdisc)
{
	struct mbuf *m = qdisc_dequeue_head(qdisc);

	if (!m) {
		return NULL;
	}

	if (unlikely(m->priority == NM_MAGIC_PRIORITY_TXQE)) {
		/* nm_os_generic_xmit_frame() asked us an event on this mbuf.
		 * We have to set the priority to the normal TX token, so that
		 * generic_ndo_start_xmit can pass it to the driver. */
		m->priority = NM_MAGIC_PRIORITY_TX;
		nm_prdis(5, "Event met, notify %p", m);
		netmap_generic_irq(NA(qdisc_dev(qdisc)),
				skb_get_queue_mapping(m), NULL);
	}

	nm_prdis(5, "Dequeuing mbuf, len %u", qdisc_qlen(qdisc));

	return m;
}

static struct mbuf *
generic_qdisc_peek(struct Qdisc *qdisc)
{
	return qdisc_peek_head(qdisc);
}

static struct Qdisc_ops
generic_qdisc_ops __read_mostly = {
	.id		= "netmapemu",
	.priv_size	= sizeof(struct nm_generic_qdisc),
	.enqueue	= generic_qdisc_enqueue,
	.dequeue	= generic_qdisc_dequeue,
	.peek		= generic_qdisc_peek,
	.init		= generic_qdisc_init,
	.reset		= qdisc_reset_queue,
	.change		= generic_qdisc_init,
	.dump		= NULL,
	.owner		= THIS_MODULE,
};

static int
tc_configure(struct ifnet *ifp, const char *qdisc_name,
		uint32_t parent, uint32_t handle, uint32_t limit)
{
	struct sockaddr_nl saddr = {
		.nl_family = AF_NETLINK,
		.nl_groups = 0,
		.nl_pid = 0,
	};
	struct msghdr msg = {
		.msg_name = (struct sockaddr *)&saddr,
		.msg_namelen = sizeof(saddr),
		.msg_flags = /* MSG_DONTWAIT */0,
	};
	struct {
		struct nlmsghdr hdr;
		struct tcmsg tcmsg;
		char buf[100];
	} nlreq = {
		.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.hdr.nlmsg_type = RTM_NEWQDISC,
		.hdr.nlmsg_flags = NLM_F_REQUEST|/*NLM_F_ACK|*/NLM_F_REPLACE|NLM_F_CREATE,
		.hdr.nlmsg_seq = 1,
		.hdr.nlmsg_pid = 0,
		.tcmsg.tcm_family = AF_UNSPEC,
		.tcmsg.tcm_ifindex = ifp->ifindex,
		.tcmsg.tcm_handle = handle,
		.tcmsg.tcm_parent = parent,
		.tcmsg.tcm_info = 0,
	};
	struct socket *sock = NULL;
	struct nlattr *attr_kind;
	struct nlattr *attr_opt;
	struct iovec iov;
	int ret;

	ret = sock_create_kern(
#ifdef NETMAP_LINUX_SOCK_CREATE_KERN_NETNS
				current->nsproxy ?
					current->nsproxy->net_ns : &init_net,
#endif /* NETMAP_LINUX_SOCK_CREATE_KERN_NETNS  */
				AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, &sock);
	if (ret) {
		nm_prerr("Failed to create netlink socket (err=%d)", ret);
		return -ret;
	}


	ret = kernel_bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret) {
		nm_prerr("Failed to bind() netlink socket (err=%d)", ret);
		goto release;
	}

	/* Push TCA_KIND attr. */
	attr_kind = (struct nlattr *)(((void *)&nlreq.hdr) +
				 NLMSG_ALIGN(nlreq.hdr.nlmsg_len));
	attr_kind->nla_len = NLA_HDRLEN + strlen(qdisc_name) + 1;
	attr_kind->nla_type = TCA_KIND;
	strcpy(((void *)attr_kind) + NLA_HDRLEN, qdisc_name);
	nlreq.hdr.nlmsg_len = NLMSG_ALIGN(nlreq.hdr.nlmsg_len) +
				NLA_ALIGN(attr_kind->nla_len);

	if (limit > 0) {
		/* Push TCA_OPTIONS attr. */
		attr_opt = (struct nlattr *)(((void *)&nlreq.hdr) +
					 NLMSG_ALIGN(nlreq.hdr.nlmsg_len));
		attr_opt->nla_len = NLA_HDRLEN + sizeof(uint32_t);
		attr_opt->nla_type = TCA_OPTIONS;
		*((uint32_t *)(((void *)attr_opt) + NLA_HDRLEN)) = limit;
		nlreq.hdr.nlmsg_len = NLMSG_ALIGN(nlreq.hdr.nlmsg_len) +
					NLA_ALIGN(attr_opt->nla_len);
	}

	iov.iov_base = (void *)&nlreq;
	iov.iov_len = nlreq.hdr.nlmsg_len;
	ret = kernel_sendmsg(sock, &msg, (struct kvec *)&iov, 1,
				iov.iov_len);
	if (ret != nlreq.hdr.nlmsg_len) {
		nm_prerr("Failed to sendmsg to netlink socket (err=%d)", ret);
		ret = -EINVAL;
		goto release;
	}
	ret = 0;

	nm_prinf("ifp %s qdisc %s parent %u handle %u", ifp->name, qdisc_name, parent, handle);

release:
	sock_release(sock);

	return ret;
}

static int
nm_os_catch_qdisc(struct netmap_generic_adapter *gna, int intercept)
{
	struct ifnet *ifp = netmap_generic_getifp(gna);
	struct netmap_adapter *na = &gna->up.up;
	bool multiqueue = (na->num_tx_rings > 1);
	static uint32_t root_handle_cnt = 18;
	uint32_t root_handle = multiqueue ? root_handle_cnt++ : 0;
	uint32_t limit = (!multiqueue && intercept) ? na->num_tx_desc : 0;
	const char *qdisc_name;
	int ret = 0;

	if (!gna->txqdisc) {
		return 0;
	}

	qdisc_name = multiqueue ? "mq" :
			(intercept ? generic_qdisc_ops.id : "pfifo");
	/* Configure root qdisc.
	 * sudo tc qdisc replace dev ifp->name root handle @root_handle: qdisc_name */
	ret = tc_configure(ifp, qdisc_name, /*parent=*/TC_H_ROOT,
				/*handle=*/root_handle << 16, limit);
	if (ret) {
		return -ret;
	}
	if (intercept && multiqueue) {
		/* Configure per-queue qdisc. */
		int i;
		qdisc_name = (intercept ? generic_qdisc_ops.id : "pfifo");
		limit = na->num_tx_desc;
		for (i = 0; i < na->num_tx_rings; i++) {
			tc_configure(ifp, qdisc_name,
				/*parent=*/(root_handle << 16) | (i+1),
				/*handle=*/0, limit);
		}
	}
	return 0;
}

/* Must be called under rtnl. */
int
nm_os_catch_tx(struct netmap_generic_adapter *gna, int intercept)
{
	struct netmap_adapter *na = &gna->up.up;
	struct ifnet *ifp = netmap_generic_getifp(gna);
	int err;

	if (!ifp) {
		nm_prerr("Failed to get ifp");
		return -1;
	}

	err = nm_os_catch_qdisc(gna, intercept);
	if (err) {
		return err;
	}

	nm_os_ifnet_lock();

	if (intercept) {
		/*
		 * Save the old pointer to the netdev_ops,
		 * create an updated netdev ops replacing the
		 * ndo_select_queue() and ndo_start_xmit() methods
		 * with our custom ones, and make the driver use it.
		 */
		na->if_transmit = (void *)ifp->netdev_ops;
		/* Save a redundant copy of ndo_start_xmit(). */
		gna->save_start_xmit = ifp->netdev_ops->ndo_start_xmit;

		gna->up.nm_ndo = *ifp->netdev_ops; /* copy all, replace some */
		gna->up.nm_ndo.ndo_start_xmit = &generic_ndo_start_xmit;
#ifndef NETMAP_LINUX_SELECT_QUEUE
		nm_prerr("No packet steering support");
#else
		gna->up.nm_ndo.ndo_select_queue = &generic_ndo_select_queue;
#endif
		ifp->netdev_ops = &gna->up.nm_ndo;

	} else {
		/* Restore the original netdev_ops. */
		ifp->netdev_ops = (void *)na->if_transmit;
	}

	nm_os_ifnet_unlock();

	return 0;
}

/* Used to cover cases where ETH_P_802_3_MIN is undefined */
#define NM_ETH_P_802_3_MIN 0x0600

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
   and -1 on error (which may be packet drops or other errors). */
int
nm_os_generic_xmit_frame(struct nm_os_gen_arg *a)
{
	struct mbuf *m = a->m;
	struct ifnet *ifp = a->ifp;
	u_int len = a->len;
	netdev_tx_t ret;
	uint16_t ethertype;

	/* We know that the driver needs to prepend LL_RESERVED_SPACE(ifp) bytes
	 * to each packet to be transmitted. We then reset the mbuf pointers
	 * to the correct initial state:
	 *    ___________________________________________
	 *    ^           ^                             ^
	 *    |           |                             |
	 *   head        data                          end
	 *               tail
	 *
	 * which correspond to an empty buffer with exactly
	 * LL_RESERVED_SPACE(ifp) bytes between head and data.
	 */
	m->len = 0;
	m->data = m->head + LL_RESERVED_SPACE(ifp);
	skb_reset_tail_pointer(m);
	skb_reset_mac_header(m);

	/* Copy a netmap buffer into the mbuf.
	 * TODO Support the slot flags (NS_MOREFRAG, NS_INDIRECT). */
	skb_copy_to_linear_data(m, a->addr, len); // skb_store_bits(m, 0, addr, len);
	skb_put(m, len);

	/* Initialize the header pointers assuming this is an IP packet.
	 * This is useful to make netmap interact well with TC when
	 * netmap_generic_txqdisc == 0.  */
	skb_set_network_header(m, ETH_HLEN);
	ethertype = *((uint16_t*)(m->data + ETH_ALEN * 2));
	m->protocol = ntohs(ethertype) >= NM_ETH_P_802_3_MIN ? ethertype : htons(ETH_P_802_3);
	m->pkt_type = PACKET_HOST;
	m->ip_summed = CHECKSUM_NONE;

	if (m->protocol == htons(ETH_P_IPV6)) {
		skb_set_transport_header(m, ETH_HLEN + sizeof(struct nm_ipv6hdr));
	} else if (m->protocol == htons(ETH_P_IP)) {
		skb_set_transport_header(m, ETH_HLEN + sizeof(struct nm_iphdr));
	} else {
		skb_reset_transport_header(m);
	}

	/* Hold a reference on this, we are going to recycle mbufs as
	 * much as possible. */
	skb_get(m);

	/* On linux m->dev is not reliable, since it can be changed by the
	 * ndo_start_xmit() callback. This happens, for instance, with veth
	 * and bridge drivers. For this reason, the nm_os_generic_xmit_frame()
	 * implementation for linux stores a copy of m->dev into the
	 * destructor_arg field. */
	m->dev = ifp;
	skb_shinfo(m)->destructor_arg = m->dev;

	/* Tell the NIC to compute checksums for outgoing TCP and UDP packets */
	if (netmap_generic_hwcsum) {
		uint8_t transport_proto = IPPROTO_IP;

		if (m->protocol == htons(ETH_P_IPV6)) {
			transport_proto = ((struct nm_ipv6hdr*)ip_hdr(m))->nexthdr;
		} else if (m->protocol == htons(ETH_P_IP)) {
			transport_proto = ((struct nm_iphdr*)ip_hdr(m))->protocol;
		}

		if (transport_proto == IPPROTO_TCP) {
			m->ip_summed = CHECKSUM_PARTIAL;
			m->csum_start = m->transport_header;
			m->csum_offset = 16; /* offset to TCP checksum within TCP header */
		} else if (transport_proto == IPPROTO_UDP) {
			m->ip_summed = CHECKSUM_PARTIAL;
			m->csum_start = m->transport_header;
			m->csum_offset = 6; /* offset to UDP checksum within UDP header */
		}
	}

	/* Tell generic_ndo_start_xmit() to pass this mbuf to the driver. */
	skb_set_queue_mapping(m, a->ring_nr);
	m->priority = a->qevent ? NM_MAGIC_PRIORITY_TXQE : NM_MAGIC_PRIORITY_TX;

	if (unlikely(m->next)) {
		nm_prlim(1, "Warning: resetting skb->next as it is not NULL\n");
		m->next = NULL;
	}

	ret = dev_queue_xmit(m);

	if (unlikely(ret != NET_XMIT_SUCCESS)) {
		/* Reset priority, so that generic_netmap_tx_clean() can
		 * reclaim this mbuf. */
		m->priority = 0;

		/* Qdisc queue is full (this cannot happen with
		 * the netmap-aware qdisc, see exaplanation in
		 * netmap_generic_txsync), or qdisc is being
		 * deactivated. In the latter case dev_queue_xmit()
		 * does not call the enqueue method and returns
		 * NET_XMIT_DROP.
		 * If there is no carrier, the generic qdisc is
		 * not yet active (is pending in the qdisc_sleeping
		 * field), and so the temporary noop qdisc enqueue
		 * method will drop the packet and return NET_XMIT_CN.
		 */
		nm_prlim(3, "Warning: dev_queue_xmit() is dropping [%d]", ret);
		return -1;
	}

	return 0;
}

void
nm_os_generic_set_features(struct netmap_generic_adapter *gna)
{
	gna->rxsg = 1; /* Supported through skb_copy_bits(). */
	gna->txqdisc = netmap_generic_txqdisc;
}
#endif /* WITH_GENERIC */

#ifdef WITH_PASTE

netdev_tx_t
linux_pst_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	netmap_pst_transmit(dev, skb);
	return (NETDEV_TX_OK);
}

/* We have no way to track subsequent fragments, but such fragments
 * are always sent after queueing.
 * XXX !zerocopy_success might need to be handled explicitly
 * zerocopy_success is false when MB_TXREF and the slot is not on-ring.
 */
void
nm_os_pst_mbuf_data_dtor(struct ubuf_info *uarg,
	bool zerocopy_success)
{
	struct nmcb *cb;
	struct nm_ubuf_info *u = (struct nm_ubuf_info *)uarg;

	cb = container_of(u, struct nmcb, ui);
	if (unlikely(!nmcb_valid(cb))) {
		PST_DBG("invalid cb %p", cb);
		return;
	} else if (unlikely(nmcb_kring(cb) == NULL)) {
		PST_DBG("no kring in cb %p", cb);
		return;
	}
	pst_put_extra_ref(nmcb_kring(cb));
	if (nmcb_rstate(cb) != MB_FTREF) {
		pst_extra_deq(nmcb_kring(cb), nmcb_slot(cb));
		nmcb_wstate(cb, MB_NOREF);
	}
}

static void
nm_os_pst_mbuf_destructor(struct sk_buff *skb)
{
	struct nmcb *cb = NMCB(skb);

	if (likely(nmcb_valid(cb)))
		nm_os_set_mbuf_data_destructor(skb, &cb->ui,
				nm_os_pst_mbuf_data_dtor);
	else
		panic("invalid cb in our mbuf destructor");
}

void
nm_os_set_mbuf_data_destructor(struct mbuf *m,
	struct nm_ubuf_info *ui, void *cb)
{
	ui->ubuf.callback = cb;
	if (cb != NULL) {
#ifdef NETMAP_LINUX_SKB_ZCOPY_SET_3ARGS
		bool ref = true;
		skb_zcopy_set(m, (struct ubuf_info *)ui, &ref);
#else
		skb_zcopy_set(m, (struct ubuf_info *)ui);
#endif
	} else {
		skb_zcopy_clear(m, 1);
	}
}

/*
 * The socket is locked when it is detached from us.
 */
void
nm_os_pst_upcall(NM_SOCK_T *sk)
{
	struct sk_buff_head *queue = &sk->sk_receive_queue;
	struct sk_buff *m;
	struct netmap_kring *kring = NULL;

	rcu_read_lock();
	if (unlikely(pst_so(sk) == NULL))
		panic(" ");
	/* OOO segment(s) might have been enqueued in the same rxsync round */
	while ((m = skb_peek(queue)) != NULL) {
		struct nmcb *cb = NMCB(m);
		struct netmap_slot *slot;
		int queued = 0;

		if (unlikely(!nmcb_valid(cb))) {
			panic("invalid cb");
		}
		if (!kring) {
			kring = nmcb_kring(cb);
			/* XXX this happens when stack goes away.
			 * We need better workaround */
			if (unlikely(!kring)) {
				PST_DBG("WARNING: no kring");
				SET_MBUF_DESTRUCTOR(m, NULL);
				nm_os_set_mbuf_data_destructor(m, &cb->ui, NULL);
				__skb_unlink(m, queue);
				__kfree_skb(m);
				continue;
			}
			mtx_lock(&kring->q_lock);
		} else if (unlikely(nmcb_kring(cb) != kring)) {
			panic("different krings");
		}
		/* append this buffer to the scratchpad */
		slot = nmcb_slot(cb);
		if (unlikely(slot == NULL)) {
			PST_DBG("m %p no slot", m);
			continue;
		}
		/* too expensive */
#if 0
		if (!pst_slot_in_extra(slot, kring) &&
		    !pst_slot_in_kring(slot, kring)) {
			PST_DBG("invalid slot");
			continue;
		}
#endif /* 0 */
		if (unlikely(m->sk == NULL || pst_so(m->sk) == NULL)) {
			PST_DBG("m->sk %p soa %p",
					m->sk, m->sk ? pst_so(m->sk) : NULL);
			continue;
		}
		nm_pst_setfd(slot, pst_so(sk)->fd);
		nm_pst_setdoff(slot, (uint16_t)
			       skb_headroom(m) - nm_get_offset(kring, slot));
		slot->len = skb_headlen(m) + nm_pst_getdoff(slot);
		/*
		 * We might have leftover for the previous connection with
		 * the same fd value. Overwrite it if this is new connection.
		 */
		pst_fdtable_add(cb, kring);
		/* see comment in pst_transmit() */
#ifdef PST_MB_RECYCLE
		if (unlikely(nmcb_rstate(cb) == MB_QUEUED)) {
			queued = 1;
		}
#endif

		nmcb_wstate(cb, MB_FTREF);

		/* XXX use new sk_eat_skb() > 5.1 */
		__skb_unlink(m, queue);
#ifdef PST_MB_RECYCLE
		if (likely(!queued)) {
			skb_orphan(m);
		} else
#endif
			__kfree_skb(m);
	}
	if (kring)
		mtx_unlock(&kring->q_lock);
	rcu_read_unlock();
}

NM_SOCK_T *
nm_os_sock_fget(int fd, void **f)
{
	int err;
	struct socket *sock = sockfd_lookup(fd, &err);

	return sock ? sock->sk : NULL;
}

void
nm_os_sock_fput(NM_SOCK_T *sk, void *dummy)
{
	sockfd_put(sk->sk_socket);
}

int
nm_os_pst_sbdrain(struct netmap_adapter *na, NM_SOCK_T *sk)
{
	struct mbuf *m;

	/* XXX All the packets must be originated from netmap */
	m = skb_peek(&sk->sk_receive_queue);
	if (!m) {
		return 0;
	}
	else if (!nmcb_valid(NMCB(m))) {
		return 0;
	}
	/* No need for BDG_RLOCK() - we don't move packets to pst na */
	nm_os_pst_upcall(sk);
	return 0;
}

static inline int
nm_os_mbuf_valid(struct mbuf *m)
{
	return likely(*(int *)(&m->users) != 0);
}

static struct mbuf *
nm_os_build_mbuf(struct netmap_kring *kring, char *buf, u_int len)
{
	struct netmap_adapter *na = kring->na;
	struct mbuf *m;
	struct page *page;
	const int alen = NETMAP_BUF_SIZE(na) - sizeof(struct nmcb);
	const u_int offset = nm_get_offset(kring, nmcb_slot(NMCB_BUF(buf)));

#ifdef PST_MB_RECYCLE
	m = kring->tx_pool[1];
	if (m) {
		struct skb_shared_info *shinfo;

		/* XXX maybe build_skb_around with some overheads */
		*m = *kring->tx_pool[0];
		m->head = m->data = buf;
		skb_reset_tail_pointer(m);
		shinfo = skb_shinfo(m);
		bzero(shinfo, offsetof(struct skb_shared_info, dataref));
		*(int *)(&shinfo->dataref) = 1;
		//shinfo->tx_flags |= SKBTX_DEV_ZEROCOPY;
	} else
#endif
	{
		m = build_skb(buf, alen);
		m->dev = na->ifp;
	}
	if (unlikely(!m))
		return NULL;
#ifdef PST_MB_RECYCLE
	else if (unlikely(!nm_os_mbuf_valid(kring->tx_pool[0]))) {
		*kring->tx_pool[0] = *m;
	}
#endif
	page = virt_to_page(buf);
	page_ref_add(page, 1); // survive __kfree_skb()
	skb_reserve(m, offset); // m->data and tail
	skb_put(m, len - offset); // advance m->tail and m->len
	return m;
}

int
nm_os_pst_rx(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	char *p = NMB(na, slot);
	struct nmcb *cb = NMCB_BUF(p);
	struct mbuf *m;
	int ret = 0;

	m = nm_os_build_mbuf(kring, p, nm_get_offset(kring, slot) + slot->len);
	if (unlikely(!m))
		return 0; // drop and skip

	pst_get_extra_ref(nmcb_kring(cb));

	nmcb_wstate(cb, MB_STACK);
	nm_pst_setfd(slot, 0);
	if (slot->flags & NS_CSUM) {
		m->ip_summed = CHECKSUM_UNNECESSARY;
		slot->flags &= ~NS_CSUM;
	}
	m->protocol = eth_type_trans(m, m->dev);
	/* have orphan() set data_destructor */
	SET_MBUF_DESTRUCTOR(m, nm_os_pst_mbuf_destructor);
	netif_receive_skb_core(m);

	/* setting data destructor is safe only after skb_orphan_frag()
	 * in __netif_receive_skb_core().
	 */
	if (unlikely(nmcb_rstate(cb) == MB_STACK)) {
		nmcb_wstate(cb, MB_QUEUED);
		if (pst_extra_enq(kring, slot)) {
			ret = -EBUSY;
		}
	}
#ifdef PST_MB_RECYCLE
	/* XXX avoid refcount_read... */
	if (nmcb_rstate(cb) == MB_FTREF && likely(!skb_shared(m))) {
		/* we can recycle this mbuf (see nm_os_pst_data_ready) */
		struct ubuf_info *uarg = skb_shinfo(m)->destructor_arg;

		if (likely(uarg->callback)) {
			uarg->callback(uarg, true);
		}
		kring->tx_pool[1] = m;
	} else {
		kring->tx_pool[1] = NULL;
	}
#endif
	return ret;
}

int
nm_os_pst_tx(struct netmap_kring *kring, struct netmap_slot *slot)
{
	struct netmap_adapter *na = kring->na;
	struct pst_so_adapter *soa;
	struct nmcb *cb;
	struct page *page;
	u_int poff, len;
	NM_SOCK_T *sk;
	void *nmb;
	int err, pageref = 0;
	const u_int offset = nm_get_offset(kring, slot);
	const u_int pst_offset = nm_pst_getdoff(slot);

	if (unlikely(slot->len <  pst_offset)) {
		return -EINVAL;
	} else if (unlikely(offset != sizeof(*cb))) {
		PST_DBG("bad offset %u", offset);
		return -EINVAL;
	}

	nmb = NMB(na, slot);
	soa = pst_soa_from_fd(na, nm_pst_getfd(slot));
	if (unlikely(!soa)) {
		PST_DBG("no soa of fd %d", nm_pst_getfd(slot));
		return 0;
	}
	sk = soa->so;

	page = virt_to_page(nmb);
	get_page(page); // survive __kfree_skb()
	pageref = page_ref_count(page);
	cb = NMCB_BUF(nmb);
	poff = nmb - page_to_virt(page) + offset + pst_offset;
	len = slot->len - pst_offset;
	nmcb_wstate(cb, MB_STACK);

	if (unlikely(!sk)) {
		PST_DBG("NULL sk");
		nmcb_invalidate(cb);
		return 0;
	} else if (unlikely(!sk->sk_socket)) {
		PST_DBG("NULL sk->sk_socket");
		nmcb_invalidate(cb);
		return 0;
	}

#ifdef NETMAP_LINUX_HAVE_KERNEL_SENDPAGE_LOCKED
	/*
	 * We don't really own lock. But since we only actively receive packets,
	 * the RX path never tries to lock the socket.
	 * If the kernel is configured to detect incorrect locking, disable
	 * paste_optim_sendpage.
	 */
	if (paste_optim_sendpage) {
		err = kernel_sendpage_locked(sk, page, poff, len, MSG_DONTWAIT);
	} else
#endif /* NETMAP_LINUX_HAVE_KERNEL_SENDPAGE_LOCKED */
		err = kernel_sendpage(sk->sk_socket, page, poff, len,
					MSG_DONTWAIT);
	if (unlikely(err < 0)) {
		/* XXX check if it is enough to assume EAGAIN only */
		PST_DBG("error %d in sendpage() slot %ld",
				err, slot - kring->ring->slot);
		nmcb_invalidate(cb);
		return -EAGAIN;
	}

	if (unlikely(nmcb_rstate(cb) == MB_STACK)) {
		/* The stack might have just dropped a page reference (e.g.,
		 * linearized in skb_checksum_help() in __dev_queue_xmit().
		 */
		if (unlikely(pageref == page_ref_count(page))) {
			PST_DBG("dropped frag ref (fd %d)", nm_pst_getfd(slot));
			nmcb_invalidate(cb);
			return 0;
		}
		nmcb_wstate(cb, MB_QUEUED);

		if (likely(pst_extra_enq(kring, slot))) {
			return -EBUSY;
		}
	} /* usually MB_TXREF (TCP) or MB_NOREF (UDP) */
	return 0;
}

/* Since tcp_sock_set_nodelay locks socket by itself. Since we don't
 * need push_pending_frames, just set the flag manually.
 */
int
nm_os_set_nodelay(NM_SOCK_T *so)
{
	tcp_sk(so)->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
	return 0; // FreeBSD returns status
}

int
nm_os_kthread_add(void *f, void *arg, void *proc, struct thread **tdptr,
		int flags, int pages, const char *fmt)
{
	*tdptr = (struct thread *)kthread_create(f, arg, "netmap-pst-kwait");
	wake_up_process((struct task_struct *)*tdptr);
	return 0;
}

int
nm_os_hwcsum_ok(struct netmap_adapter *na)
{
	return na->ifp->features & NETIF_F_CSUM_MASK;
}
#endif /* WITH_PASTE */

/* Use ethtool to find the current NIC rings lengths, so that the netmap
   rings can have the same lengths. */
int
nm_os_generic_find_num_desc(struct ifnet *ifp, unsigned int *tx, unsigned int *rx)
{
	int error = EOPNOTSUPP;
#ifdef NETMAP_LINUX_HAVE_GET_RINGPARAM
	struct ethtool_ringparam rp;

	if (ifp->ethtool_ops && ifp->ethtool_ops->get_ringparam) {
		ifp->ethtool_ops->get_ringparam(ifp, &rp);
		*tx = rp.tx_pending ? rp.tx_pending : rp.tx_max_pending;
		*rx = rp.rx_pending ? rp.rx_pending : rp.rx_max_pending;
		if (*rx < 3) {
			nm_prerr("Invalid RX ring size %u, using default", *rx);
			*rx = netmap_generic_ringsize;
		}
		if (*tx < 3) {
			nm_prerr("Invalid TX ring size %u, using default", *tx);
			*tx = netmap_generic_ringsize;
		}
		error = 0;
	}
#endif /* HAVE_GET_RINGPARAM */
	return error;
}

/* Fills in the output arguments with the number of hardware TX/RX queues. */
void
nm_os_generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
	struct ethtool_channels ch;
	memset(&ch, 0, sizeof(ch));
	if (ifp->ethtool_ops && ifp->ethtool_ops->get_channels) {
		ifp->ethtool_ops->get_channels(ifp, &ch);
		*txq = ch.tx_count ? ch.tx_count : ch.combined_count;
		*rxq = ch.rx_count ? ch.rx_count : ch.combined_count;
	} else
#endif /* HAVE_SET_CHANNELS */
	{
		*txq = ifp->real_num_tx_queues;
#if defined(NETMAP_LINUX_HAVE_REAL_NUM_RX_QUEUES)
		*rxq = ifp->real_num_rx_queues;
#else
		*rxq = 1;
		nm_prinf("WARNING: netmap will use only the first "
			 "RX queue of %s", ifp->name);
#endif /* HAVE_REAL_NUM_RX_QUEUES */
	}
}

int
netmap_rings_config_get(struct netmap_adapter *na, struct nm_config_info *info)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	rtnl_lock();

	if (ifp == NULL) {
		nm_prerr("zombie adapter");
		error = ENXIO;
		goto out;
	}
	error = nm_os_generic_find_num_desc(ifp, &info->num_tx_descs,
						&info->num_rx_descs);
	if (error)
		goto out;
	nm_os_generic_find_num_queues(ifp, &info->num_tx_rings,
					&info->num_rx_rings);

out:
	rtnl_unlock();

	return error;
}
EXPORT_SYMBOL(netmap_rings_config_get);

/* Default nm_config implementation for netmap_hw_adapter on Linux. */
static int
netmap_linux_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	/* Take whatever we had at init time. */
	info->rx_buf_maxsize = na->rx_buf_maxsize;

	return 0;
}

/* ######################## FILE OPERATIONS ####################### */

struct net_device *
ifunit_ref(const char *name)
{
#ifndef NETMAP_LINUX_HAVE_INIT_NET
	return dev_get_by_name(name);
#else
	void *ns = &init_net;
#ifdef CONFIG_NET_NS
	ns = current->nsproxy->net_ns;
#endif
	return dev_get_by_name(ns, name);
#endif
}

void if_ref(struct net_device *ifp)
{
	dev_hold(ifp);
}

void if_rele(struct net_device *ifp)
{
	dev_put(ifp);
}

struct nm_linux_selrecord_t {
	struct file *file;
	struct poll_table_struct *pwait;
};

/*
 * Remap linux arguments into the FreeBSD call.
 * - pwait is the poll table, passed as 'dev';
 *   If pwait == NULL someone else already woke up before. We can report
 *   events but they are filtered upstream.
 *   If pwait != NULL, then pwait->key contains the list of events.
 * - events is computed from pwait as above.
 * - file is passed as 'td';
 */
static u_int
linux_netmap_poll(struct file *file, struct poll_table_struct *pwait)
{
#ifdef NETMAP_LINUX_PWAIT_KEY
	int events = pwait ? pwait->NETMAP_LINUX_PWAIT_KEY : \
		     POLLIN | POLLOUT | POLLERR;
#else
	int events = POLLIN | POLLOUT | POLLERR;
#endif /* PWAIT_KEY */
	struct nm_linux_selrecord_t sr = {
		.file = file,
		.pwait = pwait
	};
	struct netmap_priv_d *priv = file->private_data;
	return netmap_poll(priv, events, &sr);
}

#ifdef NETMAP_LINUX_HAVE_VMFAULT_T
static vm_fault_t
#else
static int
#endif /* NETMAP_LINUX_HAVE_VMFAULT_T */
#ifdef NETMAP_LINUX_HAVE_FAULT_VMA_ARG
linux_netmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#else
linux_netmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#endif /* NETMAP_LINUX_HAVE_FAULT_VMA_ARG */
	struct netmap_priv_d *priv = vma->vm_private_data;
	struct netmap_adapter *na = priv->np_na;
	struct page *page;
	unsigned long off = vmf->pgoff << PAGE_SHIFT;
	unsigned long pa, pfn;

	pa = netmap_mem_ofstophys(na->nm_mem, off);
	nm_prdis("fault off %lx -> phys addr %lx", off, pa);
	if (pa == 0)
		return VM_FAULT_SIGBUS;
	pfn = pa >> PAGE_SHIFT;
	if (!pfn_valid(pfn))
		return VM_FAULT_SIGBUS;
	page = pfn_to_page(pfn);
	SetPageSwapBacked(page);
	get_page(page);
	vmf->page = page;
	return 0;
}

static struct vm_operations_struct linux_netmap_mmap_ops = {
	.fault = linux_netmap_fault,
};

static int
linux_netmap_mmap(struct file *f, struct vm_area_struct *vma)
{
	int error = 0;
	uint64_t off;
	unsigned int memflags;
	uint64_t memsize;
	struct netmap_priv_d *priv = f->private_data;
	struct netmap_adapter *na = priv->np_na;
	/*
	 * vma->vm_start: start of mapping user address space
	 * vma->vm_end: end of the mapping user address space
	 * vma->vm_pfoff: offset of first page in the device
	 */

	if (priv->np_nifp == NULL) {
		return -EINVAL;
	}
	mb();

	/* check that [off, off + vsize) is within our memory */
	error = netmap_mem_get_info(na->nm_mem, &memsize, &memflags, NULL);
	nm_prdis("get_info returned %d", error);
	if (error)
		return -error;
	off = vma->vm_pgoff << PAGE_SHIFT;
	nm_prdis("off %lx size %lx memsize %x", off,
			(vma->vm_end - vma->vm_start), memsize);
	if (off + (vma->vm_end - vma->vm_start) > memsize)
		return -EINVAL;
	if (memflags & NETMAP_MEM_IO) {
		vm_ooffset_t pa;

		/* the underlying memory is contiguous */
		pa = netmap_mem_ofstophys(na->nm_mem, 0);
		if (pa == 0)
			return -EINVAL;
		return remap_pfn_range(vma, vma->vm_start,
				pa >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
	} else {
		/* non contiguous memory, we serve
		 * page faults as they come
		 */
		vma->vm_private_data = priv;
		vma->vm_ops = &linux_netmap_mmap_ops;
	}
	return 0;
}


/*
 * This one is probably already protected by the netif lock XXX
 */
netdev_tx_t
linux_netmap_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	netmap_transmit(dev, skb);
	return (NETDEV_TX_OK);
}

#define native_change_mtu(na, dev, mtu)					\
	(((struct net_device_ops *)(na)->if_transmit)->NETMAP_LINUX_CHANGE_MTU(dev, mtu))

int
linux_netmap_change_mtu(struct net_device *dev, int new_mtu)
{
	struct netmap_adapter *na = NA(dev);

	if (netmap_buf_size_validate(na, new_mtu))
		return -EINVAL;
	return native_change_mtu(na, dev, new_mtu);
}


/* while in netmap mode, we cannot tolerate any change in the
 * number of rx/tx rings and descriptors
 *
 * Linux calls this while holding the rtnl_lock().
 */
int
linux_netmap_set_ringparam(struct net_device *dev,
	struct ethtool_ringparam *e)
{
#ifdef NETMAP_LINUX_HAVE_AX25PTR
	return -EBUSY;
#else /* !NETMAP_LINUX_HAVE_AX25PTR */
	struct netmap_adapter *na = NA(dev);

	if (nm_netmap_on(na))
		return -EBUSY;
	if (na->magic.save_eto->set_ringparam)
		return na->magic.save_eto->set_ringparam(dev, e);
	return -EOPNOTSUPP;
#endif /* NETMAP_LINUX_HAVE_AX25PTR */
}

#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
int
linux_netmap_set_channels(struct net_device *dev,
	struct ethtool_channels *e)
{
#ifdef NETMAP_LINUX_HAVE_AX25PTR
	return -EBUSY;
#else /* !NETMAP_LINUX_HAVE_AX25PTR */
	struct netmap_adapter *na = NA(dev);

	if (nm_netmap_on(na))
		return -EBUSY;
	if (na->magic.save_eto->set_channels)
		return na->magic.save_eto->set_channels(dev, e);
	return -EOPNOTSUPP;
#endif /* NETMAP_LINUX_HAVE_AX25PTR */
}
#endif

#ifndef NETMAP_LINUX_HAVE_UNLOCKED_IOCTL
#define LIN_IOCTL_NAME	.ioctl
static int
linux_netmap_ioctl(struct inode *inode, struct file *file, u_int cmd, u_long data /* arg */)
#else
#define LIN_IOCTL_NAME	.unlocked_ioctl
static long
linux_netmap_ioctl(struct file *file, u_int cmd, u_long data /* arg */)
#endif
{
	struct netmap_priv_d *priv = file->private_data;
	int ret = 0;
	union {
		struct nm_ifreq ifr;
		struct nmreq nmr;
		struct nmreq_header hdr;
	} arg;
	size_t argsize = 0;

	switch (cmd) {
	case NIOCTXSYNC:
	case NIOCRXSYNC:
		break;
	case NIOCCONFIG:
		argsize = sizeof(arg.ifr);
		break;
	case NIOCREGIF:
	case NIOCGINFO:
		argsize = sizeof(arg.nmr);
		break;
	case NIOCCTRL: {
		argsize = sizeof(arg.hdr);
		break;
	}
	}
	if (argsize) {
		if (!data)
			return -EINVAL;
		bzero(&arg, argsize);
		if (copy_from_user(&arg, (void *)data, argsize) != 0)
			return -EFAULT;
	}
	ret = netmap_ioctl(priv, cmd, (caddr_t)&arg, NULL,
			   /*nr_body_is_user=*/1);
	if (data && copy_to_user((void*)data, &arg, argsize) != 0)
		return -EFAULT;
	return -ret;
}

#ifdef CONFIG_COMPAT
#include <asm/compat.h>

static long
linux_netmap_compat_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	return linux_netmap_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static int
linux_netmap_release(struct inode *inode, struct file *file)
{
	(void)inode;	/* UNUSED */
	if (file->private_data)
		netmap_dtor(file->private_data);
	return (0);
}


static int
linux_netmap_open(struct inode *inode, struct file *file)
{
	struct netmap_priv_d *priv;
	int error;
	(void)inode;	/* UNUSED */

	NMG_LOCK();
	priv = netmap_priv_new();
	if (priv == NULL) {
		error = -ENOMEM;
		goto out;
	}
	priv->np_filp = file;
	file->private_data = priv;
out:
	NMG_UNLOCK();

	return (0);
}


static struct file_operations netmap_fops = {
	.owner = THIS_MODULE,
	.open = linux_netmap_open,
	.mmap = linux_netmap_mmap,
	LIN_IOCTL_NAME = linux_netmap_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = linux_netmap_compat_ioctl,
#endif
	.poll = linux_netmap_poll,
	.release = linux_netmap_release,
};


#ifdef CONFIG_NET_NS
#include <net/netns/generic.h>

int netmap_bns_id;

struct netmap_bns {
	struct net *net;
	struct nm_bridge *bridges;
	u_int num_bridges;
};

#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
static int
nm_bns_create(struct net *net, struct netmap_bns **ns)
{
	*ns = net_generic(net, netmap_bns_id);
	return 0;
}
#define nm_bns_destroy(_1, _2)
#else
static int
nm_bns_create(struct net *net, struct netmap_bns **ns)
{
	int error = 0;

	*ns = kmalloc(sizeof(*ns), GFP_KERNEL);
	if (!*ns)
		return -ENOMEM;

	error = net_assign_generic(net, netmap_bns_id, *ns);
	if (error) {
		kfree(*ns);
		*ns = NULL;
	}
	return error;
}

void
nm_bns_destroy(struct net *net, struct netmap_bns *ns)
{
	kfree(ns);
	net_assign_generic(net, netmap_bns_id, NULL);
}
#endif

struct net*
netmap_bns_get(void)
{
	return get_net(current->nsproxy->net_ns);
}

void
netmap_bns_put(struct net *net_ns)
{
	put_net(net_ns);
}

void
netmap_bns_getbridges(struct nm_bridge **b, u_int *n)
{
	struct net *net_ns = current->nsproxy->net_ns;
	struct netmap_bns *ns = net_generic(net_ns, netmap_bns_id);

	*b = ns->bridges;
	*n = ns->num_bridges;
}

static int __net_init
netmap_pernet_init(struct net *net)
{
	struct netmap_bns *ns;
	int error = 0;

	error = nm_bns_create(net, &ns);
	if (error)
		return error;

	ns->net = net;
	ns->num_bridges = NM_BRIDGES;
	ns->bridges = netmap_init_bridges2(ns->num_bridges);
	if (ns->bridges == NULL) {
		nm_bns_destroy(net, ns);
		return -ENOMEM;
	}

	return 0;
}

static void __net_init
netmap_pernet_exit(struct net *net)
{
	struct netmap_bns *ns = net_generic(net, netmap_bns_id);

	netmap_uninit_bridges2(ns->bridges, ns->num_bridges);
	ns->bridges = NULL;

	nm_bns_destroy(net, ns);
}

static struct pernet_operations netmap_pernet_ops = {
	.init = netmap_pernet_init,
	.exit = netmap_pernet_exit,
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	.id = &netmap_bns_id,
	.size = sizeof(struct netmap_bns),
#endif
};

static int netmap_bns_registered = 0;
int
netmap_bns_register(void)
{
	int rv;
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	rv = register_pernet_subsys(&netmap_pernet_ops);
#else
	rv = register_pernet_gen_subsys(&netmap_bns_id,
			&netmap_pernet_ops);
#endif
	netmap_bns_registered = !rv;
	return -rv;
}

void
netmap_bns_unregister(void)
{
	if (!netmap_bns_registered)
		return;
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	unregister_pernet_subsys(&netmap_pernet_ops);
#else
	unregister_pernet_gen_subsys(netmap_bns_id,
			&netmap_pernet_ops);
#endif
}
#endif /* CONFIG_NET_NS */

/* ##################### kthread wrapper ##################### */
#include <linux/eventfd.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include <linux/cpumask.h> /* nr_cpu_ids */

u_int
nm_os_ncpus(void)
{
	return nr_cpu_ids;
}

struct nm_kctx {
	struct mm_struct *mm;       /* to access guest memory */
	struct task_struct *worker; /* the kernel thread */
	int attach_user;            /* kthread attached to user_process */
	int affinity;

	/* worker function and parameter */
	nm_kctx_worker_fn_t worker_fn;
	void *worker_private;

	/* integer to manage multiple worker contexts */
	long type;
};

static int
nm_kctx_worker(void *data)
{
	struct nm_kctx *nmk = data;
#ifndef NETMAP_LINUX_HAVE_KTHREAD_USE_MM
	mm_segment_t oldfs = get_fs();
#endif /* NETMAP_LINUX_HAVE_KTHREAD_USE_MM */

	if (nmk->mm) {
#ifndef NETMAP_LINUX_HAVE_KTHREAD_USE_MM
		set_fs(USER_DS);
		use_mm(nmk->mm);
#else
		kthread_use_mm(nmk->mm);
#endif /* NETMAP_LINUX_HAVE_KTHREAD_USE_MM */
	}

	while (!kthread_should_stop()) {
		nmk->worker_fn(nmk->worker_private); /* work */
		if (need_resched())
			schedule();
	}

	if (nmk->mm) {
#ifndef NETMAP_LINUX_HAVE_KTHREAD_USE_MM
		unuse_mm(nmk->mm);
#else
		kthread_unuse_mm(nmk->mm);
#endif /* NETMAP_LINUX_HAVE_KTHREAD_USE_MM */
	}

#ifndef NETMAP_LINUX_HAVE_KTHREAD_USE_MM
	set_fs(oldfs);
#endif /* NETMAP_LINUX_HAVE_KTHREAD_USE_MM */
	return 0;
}

void
nm_os_kctx_worker_setaff(struct nm_kctx *nmk, int affinity)
{
	nmk->affinity = affinity;
}

struct nm_kctx *
nm_os_kctx_create(struct nm_kctx_cfg *cfg, void *opaque)
{
	struct nm_kctx *nmk = NULL;

	nmk = kzalloc(sizeof *nmk, GFP_KERNEL);
	if (!nmk)
		return NULL;

	nmk->worker_fn = cfg->worker_fn;
	nmk->worker_private = cfg->worker_private;
	nmk->type = cfg->type;
	nmk->attach_user = cfg->attach_user;
	nmk->affinity = -1;  /* unspecified */

	return nmk;
}

int
nm_os_kctx_worker_start(struct nm_kctx *nmk)
{
	char name[16];
	int error = 0;

	if (nmk->worker) {
		return EBUSY;
	}

	/* Get caller's memory mapping if needed. */
	if (nmk->attach_user) {
		nmk->mm = get_task_mm(current);
	}

	/* Run the context in a kernel thread. */
	snprintf(name, sizeof(name), "nmkth:%d:%ld", current->pid,
							nmk->type);
	nmk->worker = kthread_create(nm_kctx_worker, nmk, name);
	if (IS_ERR(nmk->worker)) {
		error = -PTR_ERR(nmk->worker);
		goto err;
	}

	if (nmk->affinity >= 0) {
		kthread_bind(nmk->worker, nmk->affinity);
	}
	wake_up_process(nmk->worker);

	return 0;

err:
	if (nmk->worker) {
		kthread_stop(nmk->worker);
		nmk->worker = NULL;
	}
	if (nmk->mm) {
		mmput(nmk->mm);
		nmk->mm = NULL;
	}
	return error;
}

void
nm_os_kctx_worker_stop(struct nm_kctx *nmk)
{
	if (nmk->worker) {
		kthread_stop(nmk->worker);
		nmk->worker = NULL;
	}

	if (nmk->mm) {
		mmput(nmk->mm);
		nmk->mm = NULL;
	}
}

void
nm_os_kctx_destroy(struct nm_kctx *nmk)
{
	if (!nmk)
		return;

	if (nmk->worker) {
		nm_os_kctx_worker_stop(nmk);
	}

	kfree(nmk);
}

/* ################## PTNETMAP GUEST SUPPORT ################## */
#ifdef WITH_PTNETMAP
/*
 * ptnetmap memory device (memdev) for linux guest
 * Used to expose host memory to the guest through PCI-BAR
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

int ptnet_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ptnet_remove(struct pci_dev *pdev);
void ptnet_shutdown(struct pci_dev *pdev);

/*
 * PCI Device ID Table
 * list of (VendorID,DeviceID) supported by this driver
 */
static struct pci_device_id ptnetmap_guest_device_table[] = {
	{ PCI_DEVICE(PTNETMAP_PCI_VENDOR_ID, PTNETMAP_PCI_DEVICE_ID), },
	{ PCI_DEVICE(PTNETMAP_PCI_VENDOR_ID, PTNETMAP_PCI_NETIF_ID), },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, ptnetmap_guest_device_table);

/*
 * ptnetmap memdev private data structure
 */
struct ptnetmap_memdev
{
	struct pci_dev *pdev;
	void __iomem *pci_io;
	void __iomem *pci_mem;
	struct netmap_mem_d *nm_mem;
	int bars;
};

/*
 * map host netmap memory through PCI-BAR in the guest OS
 *
 * return physical (nm_paddr) and virtual (nm_addr) addresses
 * of the netmap memory mapped in the guest.
 */
int
nm_os_pt_memdev_iomap(struct ptnetmap_memdev *ptn_dev, vm_paddr_t *nm_paddr,
			void **nm_addr, uint64_t *mem_size)
{
	struct pci_dev *pdev = ptn_dev->pdev;
	phys_addr_t mem_paddr;
	int err = 0;

	*mem_size = ioread32(ptn_dev->pci_io + PTNET_MDEV_IO_MEMSIZE_HI);
	*mem_size = ioread32(ptn_dev->pci_io + PTNET_MDEV_IO_MEMSIZE_LO) |
		(*mem_size << 32);

	nm_prinf("=== BAR %d start %llx len %llx mem_size %lx ===",
	    PTNETMAP_MEM_PCI_BAR,
	    (unsigned long long)pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
	    (unsigned long long)pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR),
	    (unsigned long)(*mem_size));

	/* map memory allocator */
	mem_paddr = pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR);
	ptn_dev->pci_mem = *nm_addr = ioremap_cache(mem_paddr, *mem_size);
	if (ptn_dev->pci_mem == NULL) {
		err = -ENOMEM;
	}
	*nm_paddr = mem_paddr;

	return err;
}

uint32_t
nm_os_pt_memdev_ioread(struct ptnetmap_memdev *ptn_dev, unsigned int reg)
{
	return ioread32(ptn_dev->pci_io + reg);
}

/*
 * unmap PCI-BAR
 */
void
nm_os_pt_memdev_iounmap(struct ptnetmap_memdev *ptn_dev)
{
	if (ptn_dev->pci_mem) {
		iounmap(ptn_dev->pci_mem);
		ptn_dev->pci_mem = NULL;
	}
}

/*
 * Device initialization routine
 *
 * Returns 0 on success, negative on failure
 */
static int
ptnetmap_guest_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ptnetmap_memdev *ptn_dev;
	int bars, err;
	uint16_t mem_id;

	if (id->device == PTNETMAP_PCI_NETIF_ID) {
		/* Probe the ptnet device. */
		return ptnet_probe(pdev, id);
	}

	/* Probe the memdev device. */
	ptn_dev = kzalloc(sizeof(*ptn_dev), GFP_KERNEL);
	if (ptn_dev == NULL)
		return -ENOMEM;

	ptn_dev->pdev = pdev;
	bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
	/* enable the device */
	err = pci_enable_device(pdev);
	if (err)
		goto err;

	err = pci_request_selected_regions(pdev, bars, PTNETMAP_MEMDEV_NAME);
	if (err)
		goto err_pci_reg;

	ptn_dev->pci_io = pci_iomap(pdev, PTNETMAP_IO_PCI_BAR, 0);
	if (ptn_dev->pci_io == NULL) {
		err = -ENOMEM;
		goto err_iomap;
	}
	pci_set_drvdata(pdev, ptn_dev);
	pci_set_master(pdev); /* XXX probably not needed */

	ptn_dev->bars = bars;
	mem_id = ioread32(ptn_dev->pci_io + PTNET_MDEV_IO_MEMID);

	/* create guest allocator */
	ptn_dev->nm_mem = netmap_mem_pt_guest_attach(ptn_dev, mem_id);
	if (ptn_dev->nm_mem == NULL) {
		err = -ENOMEM;
		goto err_nmd_attach;
	}
	netmap_mem_get(ptn_dev->nm_mem);

	return 0;

err_nmd_attach:
	pci_set_drvdata(pdev, NULL);
	iounmap(ptn_dev->pci_io);
err_iomap:
	pci_release_selected_regions(pdev, bars);
err_pci_reg:
	pci_disable_device(pdev);
err:
	kfree(ptn_dev);
	return err;
}

/*
 * Device removal routine.
 */
static void
ptnetmap_guest_remove(struct pci_dev *pdev)
{
	struct ptnetmap_memdev *ptn_dev = pci_get_drvdata(pdev);

	if (pdev->device == PTNETMAP_PCI_NETIF_ID) {
		/* Remove the ptnet device. */
		return ptnet_remove(pdev);
	}

	/* Remove the memdev device. */

	if (ptn_dev->nm_mem) {
		netmap_mem_put(ptn_dev->nm_mem);
		ptn_dev->nm_mem = NULL;
	}
	nm_os_pt_memdev_iounmap(ptn_dev);
	pci_set_drvdata(pdev, NULL);
	iounmap(ptn_dev->pci_io);
	pci_release_selected_regions(pdev, ptn_dev->bars);
	pci_disable_device(pdev);
	kfree(ptn_dev);
}

/*
 * Device shutdown routine, called when the system is going to power
 * off or reboot.
 */
static void
ptnetmap_guest_shutdown(struct pci_dev *pdev)
{
	if (pdev->device == PTNETMAP_PCI_NETIF_ID) {
		/* Shutdown the ptnet device. */
		ptnet_shutdown(pdev);
	} else if (pdev->device == PTNETMAP_PCI_DEVICE_ID) {
		/* Shutdown the memdev device. */
		pci_disable_device(pdev);
	}
}

/*
 * pci driver information
 */
static struct pci_driver ptnetmap_guest_drivers = {
	.name       = "ptnetmap-guest-drivers",
	.id_table   = ptnetmap_guest_device_table,
	.probe      = ptnetmap_guest_probe,
	.remove     = ptnetmap_guest_remove,
	.shutdown   = ptnetmap_guest_shutdown,
};

/*
 * Driver Registration Routine
 *
 * Returns 0 on success, negative on failure
 */
static int
ptnetmap_guest_init(void)
{
	int ret;

	/* register pci driver */
	ret = pci_register_driver(&ptnetmap_guest_drivers);
	if (ret < 0) {
		nm_prerr("Failed to register drivers");
		return ret;
	}

	return 0;
}

/*
 * Driver Exit Cleanup Routine
 */
void
ptnetmap_guest_fini(void)
{
	/* unregister pci driver */
	pci_unregister_driver(&ptnetmap_guest_drivers);
}

#else /* !WITH_PTNETMAP */
#define ptnetmap_guest_init()		0
#define ptnetmap_guest_fini()
#endif /* WITH_PTNETMAP */

#ifdef WITH_SINK

/*
 * An emulated netmap-enabled device acting as a packet sink, useful for
 * performance tests of netmap applications or other netmap subsystems
 * (i.e. VALE, ptnetmap).
 *
 * The sink_delay_ns parameter is used to tune the speed of the packet sink
 * device. The absolute value of the parameter is interpreted as the number
 * of nanoseconds that are required to send a packet into the sink.
 * For positive values, the sink device emulates a NIC transmitting packets
 * asynchronously with respect to the txsync() caller, similarly to what
 * happens with real NICs.
 * For negative values, the sink device emulates a packet consumer,
 * transmitting packets synchronously with respect to the txsync() caller.
 */
static int sink_delay_ns = 100;
module_param(sink_delay_ns, int, 0644);
static struct net_device *nm_sink_netdev = NULL; /* global sink netdev */
s64 nm_sink_next_link_idle; /* for link emulation */

#define NM_SINK_SLOTS	1024
#define NM_SINK_DELAY_NS \
	((unsigned int)(sink_delay_ns > 0 ? sink_delay_ns : -sink_delay_ns))

static int
nm_sink_register(struct netmap_adapter *na, int onoff)
{
	if (onoff)
		nm_set_native_flags(na);
	else
		nm_clear_native_flags(na);

	nm_sink_next_link_idle = ktime_get_ns();

	return 0;
}

static inline void
nm_sink_emu(unsigned int n)
{
	u64 wait_until = nm_sink_next_link_idle;
	u64 now = ktime_get_ns();

	if (sink_delay_ns < 0 || nm_sink_next_link_idle < now) {
		/* If we are emulating packet consumer mode or the link went
		 * idle some time ago, we need to update the link emulation
		 * variable, because we don't want the caller to accumulate
		 * credit. */
		nm_sink_next_link_idle = now;
	}
	/* Schedule new transmissions. */
	nm_sink_next_link_idle += n * NM_SINK_DELAY_NS;
	if (sink_delay_ns < 0) {
		/* In packet consumer mode we emulate synchronous
		 * transmission, so we have to wait right now for the link
		 * to become idle. */
		wait_until = nm_sink_next_link_idle;
	}
	while (ktime_get_ns() < wait_until) ;
}

static int
nm_sink_txsync(struct netmap_kring *kring, int flags)
{
	unsigned int const lim = kring->nkr_num_slots - 1;
	unsigned int const head = kring->rhead;
	unsigned int n; /* num of packets to be transmitted */

	n = kring->nkr_num_slots + head - kring->nr_hwcur;
	if (n >= kring->nkr_num_slots) {
		n -= kring->nkr_num_slots;
	}
	kring->nr_hwcur = head;
	kring->nr_hwtail = nm_prev(kring->nr_hwcur, lim);

	nm_sink_emu(n);

	return 0;
}

static int
nm_sink_rxsync(struct netmap_kring *kring, int flags)
{
	u_int const head = kring->rhead;

	/* First part: nothing received for now. */
	/* Second part: skip past packets that userspace has released */
	kring->nr_hwcur = head;

	return 0;
}

static int nm_sink_open(struct net_device *netdev) { return 0; }
static int nm_sink_close(struct net_device *netdev) { return 0; }

static netdev_tx_t
nm_sink_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	kfree_skb(skb);
	nm_sink_emu(1);
	return NETDEV_TX_OK;
}

static const struct net_device_ops nm_sink_netdev_ops = {
	.ndo_open = nm_sink_open,
	.ndo_stop = nm_sink_close,
	.ndo_start_xmit = nm_sink_start_xmit,
};

int
netmap_sink_init(void)
{
	struct netmap_adapter na;
	struct net_device *netdev;
	int err;

	netdev = alloc_etherdev(0);
	if (!netdev) {
		return -ENOMEM;
	}
	netdev->netdev_ops = &nm_sink_netdev_ops ;
	strlcpy(netdev->name, "nmsink", sizeof(netdev->name));
	netdev->features = NETIF_F_HIGHDMA;
	strcpy(netdev->name, "nmsink%d");
	err = register_netdev(netdev);
	if (err) {
		free_netdev(netdev);
	}

	bzero(&na, sizeof(na));
	na.ifp = netdev;
	na.num_tx_desc = NM_SINK_SLOTS;
	na.num_rx_desc = NM_SINK_SLOTS;
	na.nm_register = nm_sink_register;
	na.nm_txsync = nm_sink_txsync;
	na.nm_rxsync = nm_sink_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);

	netif_carrier_on(netdev);
	nm_sink_netdev = netdev;

	return 0;
}

void
netmap_sink_fini(void)
{
	struct net_device *netdev = nm_sink_netdev;

	nm_sink_netdev = NULL;
	unregister_netdev(netdev);
	netmap_detach(netdev);
	free_netdev(netdev);
}
#endif  /* WITH_SINK */


/* ########################## MODULE INIT ######################### */

struct miscdevice netmap_cdevsw = { /* same name as FreeBSD */
	MISC_DYNAMIC_MINOR,
	"netmap",
	&netmap_fops,
};


static int linux_netmap_init(void)
{
	int err;
	/* Errors have negative values on linux. */
	err = -netmap_init();
	if (err) {
		return err;
	}

	err = ptnetmap_guest_init();
	if (err) {
		goto netmap_fini;
	}
#ifdef WITH_SINK
	err = netmap_sink_init();
	if (err) {
		nm_prerr("Error: could not init netmap sink interface");
		goto ptnetmap_fini;
	}
#endif /* WITH_SINK */
#ifdef WITH_GENERIC
	err = register_qdisc(&generic_qdisc_ops);
	if (err) {
		nm_prerr("Error: failed to register qdisc for emulated netmap (err=%d)", err);
		goto sink_fini;
	}
#endif /* WITH_GENERIC */
	return 0;

#ifdef WITH_GENERIC
sink_fini:
#endif /* WITH_GENERIC */
#ifdef WITH_SINK
	netmap_sink_fini();
ptnetmap_fini:
#endif /* WITH_SINK */
	ptnetmap_guest_fini();
netmap_fini:
	netmap_fini();
	return err;
}


static void linux_netmap_fini(void)
{
#ifdef WITH_GENERIC
	unregister_qdisc(&generic_qdisc_ops);
#endif /* WITH_GENERIC */
#ifdef WITH_SINK
	netmap_sink_fini();
#endif /* WITH_SINK */
	ptnetmap_guest_fini();
	netmap_fini();
}

#ifndef NETMAP_LINUX_HAVE_LIVE_ADDR_CHANGE
#define IFF_LIVE_ADDR_CHANGE 0
#endif

#ifndef NETMAP_LINUX_HAVE_TX_SKB_SHARING
#define IFF_TX_SKB_SHARING 0
#endif

static struct device_driver linux_dummy_drv = {.owner = THIS_MODULE};

static int linux_nm_vi_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int linux_nm_vi_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}
static int linux_nm_vi_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	if (skb != NULL)
		kfree_skb(skb);
	return 0;
}

#ifdef NETMAP_LINUX_HAVE_GET_STATS64
static
#ifdef NETMAP_LINUX_HAVE_NONVOID_GET_STATS64
struct rtnl_link_stats64 *
#else /* !VOID */
void
#endif /* NETMAP_LINUX_HAVE_NONVOID_GET_STATS64 */
linux_nm_vi_get_stats(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
#ifdef NETMAP_LINUX_HAVE_NONVOID_GET_STATS64
	return stats;
#endif /* !NETMAP_LINUX_HAVE_VOID_GET_STATS64 */
}
#endif /* NETMAP_LINUX_HAVE_GET_STATS64 */

static int linux_nm_vi_change_mtu(struct net_device *netdev, int new_mtu)
{
	return 0;
}
#ifdef NETMAP_LINUX_HAVE_NETDEV_DTOR
static void linux_nm_vi_destructor(struct net_device *netdev)
{
//	netmap_detach(netdev);
	free_netdev(netdev);
}
#endif
static const struct net_device_ops nm_vi_ops = {
	.ndo_open = linux_nm_vi_open,
	.ndo_stop = linux_nm_vi_stop,
	.ndo_start_xmit = linux_nm_vi_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.NETMAP_LINUX_CHANGE_MTU = linux_nm_vi_change_mtu,
#ifdef NETMAP_LINUX_HAVE_GET_STATS64
	.ndo_get_stats64 = linux_nm_vi_get_stats,
#endif
};
/* dev->name is not initialized yet */
static void
linux_nm_vi_setup(struct ifnet *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &nm_vi_ops;
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
#ifdef NETMAP_LINUX_HAVE_NETDEV_DTOR
	dev->destructor = linux_nm_vi_destructor;
#else
	dev->needs_free_netdev = 1;
#endif
	dev->tx_queue_len = 0;
	/* XXX */
	dev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
		NETIF_F_HIGHDMA | NETIF_F_HW_CSUM | NETIF_F_TSO;
#ifdef NETMAP_LINUX_HAVE_HW_FEATURES
	dev->hw_features = dev->features & ~NETIF_F_LLTX;
#endif
#ifdef NETMAP_LINUX_HAVE_ADDR_RANDOM
	eth_hw_addr_random(dev);
#endif
}

int
nm_os_vi_persist(const char *name, struct ifnet **ret)
{
	struct ifnet *ifp;
	int error;

	if (!try_module_get(linux_dummy_drv.owner))
		return EFAULT;
#ifdef NETMAP_LINUX_ALLOC_NETDEV_4ARGS
	ifp = alloc_netdev(0, name, NET_NAME_UNKNOWN, linux_nm_vi_setup);
#else
	ifp = alloc_netdev(0, name, linux_nm_vi_setup);
#endif
	if (!ifp) {
		error = ENOMEM;
		goto err_put;
	}
#ifdef CONFIG_NET_NS
	dev_net_set(ifp, current->nsproxy->net_ns);
#endif
	ifp->dev.driver = &linux_dummy_drv;
	error = register_netdev(ifp);
	if (error < 0) {
		nm_prerr("error %d", error);
		error = -error;
		goto err_free;
	}
	netif_start_queue(ifp);
	*ret = ifp;
	return 0;

err_free:
	free_netdev(ifp);
err_put:
	module_put(linux_dummy_drv.owner);
	return error;
}

void
nm_os_vi_detach(struct ifnet *ifp)
{
	netif_stop_queue(ifp);
	unregister_netdev(ifp);
	module_put(linux_dummy_drv.owner);
}

void
nm_os_selwakeup(NM_SELINFO_T *si)
{
	/* We use wake_up_interruptible() since select() and poll()
	 * sleep in an interruptbile way. */
	wake_up_interruptible(si);
}

void
nm_os_selrecord(NM_SELRECORD_T *sr, NM_SELINFO_T *si)
{
	poll_wait(sr->file, si, sr->pwait);
}

void
nm_os_onattach(struct ifnet *ifp)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter *)na;

#ifdef NETMAP_LINUX_HAVE_NETDEV_OPS
	if (ifp->netdev_ops) {
		/* prepare a clone of the netdev ops */
		hwna->nm_ndo = *ifp->netdev_ops;
	}
#endif /* NETMAP_LINUX_HAVE_NETDEV_OPS */
	hwna->nm_ndo.ndo_start_xmit = linux_netmap_start_xmit;
	hwna->nm_ndo.NETMAP_LINUX_CHANGE_MTU = linux_netmap_change_mtu;
#ifdef NETMAP_LINUX_HAVE_AX25PTR
	if (ifp->ethtool_ops) {
		hwna->nm_eto = *ifp->ethtool_ops;
	}
	hwna->nm_eto.set_ringparam = linux_netmap_set_ringparam;
#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
	hwna->nm_eto.set_channels = linux_netmap_set_channels;
#endif /* NETMAP_LINUX_HAVE_SET_CHANNELS */
#else /* !NETMAP_LINUX_HAVE_AX25PTR */
#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
	na->magic.eto.set_channels = linux_netmap_set_channels;
#endif /* NETMAP_LINUX_HAVE_SET_CHANNELS */
#endif /* NETMAP_LINUX_HAVE_AX25PTR */
	if (na->nm_config == NULL) {
		hwna->up.nm_config = netmap_linux_config;
	}
}

void
nm_os_onenter(struct ifnet *ifp)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter *)na;

	na->if_transmit = (void *)ifp->netdev_ops;
	ifp->netdev_ops = &hwna->nm_ndo;
#ifdef NETMAP_LINUX_HAVE_AX25PTR
	hwna->save_ethtool = ifp->ethtool_ops;
	ifp->ethtool_ops = &hwna->nm_eto;
#else /* NETMAP_LINUX_HAVE_AX25PTR */
	(void)hwna;
#endif /* NETMAP_LINUX_HAVE_AX25PTR */
}

void
nm_os_onexit(struct ifnet *ifp)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter *)na;

	ifp->netdev_ops = (void *)na->if_transmit;
#ifdef NETMAP_LINUX_HAVE_AX25PTR
	ifp->ethtool_ops = hwna->save_ethtool;
#else /* NETMAP_LINUX_HAVE_AX25PTR */
	(void)hwna;
#endif /* NETMAP_LINUX_HAVE_AX25PTR */
}

module_init(linux_netmap_init);
module_exit(linux_netmap_fini);

/* export certain symbols to other modules */
EXPORT_SYMBOL(netmap_attach);		/* driver attach routines */
EXPORT_SYMBOL(netmap_attach_ext);
#ifdef NM_DEBUG_PUTGET
EXPORT_SYMBOL(__netmap_adapter_get);
EXPORT_SYMBOL(__netmap_adapter_put);
#else
EXPORT_SYMBOL(netmap_adapter_get);
EXPORT_SYMBOL(netmap_adapter_put);
#endif /* NM_DEBUG_PUTGET */
#ifdef WITH_PTNETMAP
EXPORT_SYMBOL(netmap_pt_guest_attach);	/* ptnetmap driver attach routine */
EXPORT_SYMBOL(netmap_pt_guest_rxsync);	/* ptnetmap generic rxsync */
EXPORT_SYMBOL(netmap_pt_guest_txsync);	/* ptnetmap generic txsync */
EXPORT_SYMBOL(netmap_mem_pt_guest_ifp_del); /* unlink passthrough interface */
#endif /* WITH_PTNETMAP */
EXPORT_SYMBOL(netmap_detach);		/* driver detach routines */
EXPORT_SYMBOL(netmap_ring_reinit);	/* ring init on error */
EXPORT_SYMBOL(netmap_reset);		/* ring init routines */
EXPORT_SYMBOL(netmap_rx_irq);	        /* default irq handler */
EXPORT_SYMBOL(netmap_no_pendintr);	/* XXX mitigation - should go away */
EXPORT_SYMBOL(netmap_krings_mode_commit);
#ifdef WITH_VALE
EXPORT_SYMBOL(netmap_bdg_regops);	/* bridge configuration routine */
EXPORT_SYMBOL(netmap_bdg_name);		/* the bridge the vp is attached to */
EXPORT_SYMBOL(netmap_bdg_update_private_data);
EXPORT_SYMBOL(netmap_vale_create);
EXPORT_SYMBOL(netmap_vale_destroy);
EXPORT_SYMBOL(netmap_bdg_attach);
EXPORT_SYMBOL(netmap_bdg_detach);
EXPORT_SYMBOL(nm_vi_create);
EXPORT_SYMBOL(nm_vi_destroy);
#endif /* WITH_VALE */
EXPORT_SYMBOL(netmap_disable_all_rings);
EXPORT_SYMBOL(netmap_enable_all_rings);
EXPORT_SYMBOL(netmap_krings_create);
EXPORT_SYMBOL(netmap_krings_delete);	/* used by veth module */
EXPORT_SYMBOL(netmap_hw_krings_create);
EXPORT_SYMBOL(netmap_hw_krings_delete);
EXPORT_SYMBOL(netmap_mem_rings_create);	/* used by veth module */
EXPORT_SYMBOL(netmap_mem_rings_delete);	/* used by veth module */
#ifdef WITH_PIPES
EXPORT_SYMBOL(netmap_pipe_txsync);	/* used by veth module */
EXPORT_SYMBOL(netmap_pipe_rxsync);	/* used by veth module */
EXPORT_SYMBOL(netmap_pipe_krings_create_both);
EXPORT_SYMBOL(netmap_pipe_krings_delete_both);
EXPORT_SYMBOL(netmap_pipe_reg_both);
#endif /* WITH_PIPES */
EXPORT_SYMBOL(netmap_verbose);
EXPORT_SYMBOL(nm_set_native_flags);
EXPORT_SYMBOL(nm_clear_native_flags);
#ifndef NETMAP_LINUX_HAVE_AX25PTR
EXPORT_SYMBOL(linux_netmap_set_ringparam);
#endif /* NETMAP_LINUX_HAVE_AX25PTR */

MODULE_AUTHOR("http://info.iet.unipi.it/~luigi/netmap/");
MODULE_DESCRIPTION("The netmap packet I/O framework");
MODULE_LICENSE("Dual BSD/GPL"); /* the code here is all BSD. */
