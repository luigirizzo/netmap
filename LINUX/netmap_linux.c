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

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <net/netmap_virt.h>
#include <dev/netmap/netmap_mem2.h>
#include <linux/rtnetlink.h>
#include <linux/nsproxy.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>

#include "netmap_linux_config.h"

void *
nm_os_malloc(size_t size)
{
	return kmalloc(size, GFP_ATOMIC | __GFP_ZERO);
}

void *
nm_os_realloc(void *addr, size_t new_size, size_t old_size)
{
	(void)old_size;

	return krealloc(addr, new_size, GFP_ATOMIC | __GFP_ZERO);
}

void
nm_os_free(void *addr){
	kfree(addr);
}

void
nm_os_selinfo_init(NM_SELINFO_T *si)
{
	init_waitqueue_head(si);
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
		return 0;

	grp = iommu_group_get(dev);
	if (!grp)
		return 0;

	id = iommu_group_id(grp);
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
 * header, 'data' points to the TCP/UDP header, 'datalen' is the lenght of
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
 * header, 'data' points to the TCP/UDP header, 'datalen' is the lenght of
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
nm_os_mbuf_has_offld(struct mbuf *m)
{
	return m->ip_summed == CHECKSUM_PARTIAL || skb_is_gso(m);
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

    if (intercept) {
        return -netdev_rx_handler_register(ifp,
                &linux_generic_rx_handler, na);
    } else {
        netdev_rx_handler_unregister(ifp);
        return 0;
    }
#endif /* HAVE_RX_REGISTER */
}

#ifdef NETMAP_LINUX_SELECT_QUEUE
static u16
generic_ndo_select_queue(struct ifnet *ifp, struct mbuf *m
#if NETMAP_LINUX_SELECT_QUEUE >= 3
                                , void *accel_priv
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
		/* Reset priority, so that generic_netmap_tx_clean()
		 * knows that it can reclaim this mbuf. */
		m->priority = 0;
		return gna->save_start_xmit(m, ifp); /* To the driver. */
	}

	/* To a netmap RX ring. */
	return linux_netmap_start_xmit(m, ifp);
}

struct nm_generic_qdisc {
	unsigned int qidx;
	unsigned int limit;
};

static int
generic_qdisc_init(struct Qdisc *qdisc, struct nlattr *opt)
{
	struct nm_generic_qdisc *priv = NULL;

	/* Kernel < 2.6.39, do not have qdisc->limit, so we will
	 * always use our priv->limit, for simplicity. */

	priv = qdisc_priv(qdisc);
	priv->qidx = 0;
	priv->limit = 1024; /* This is going to be overridden. */

	if (opt) {
		struct nm_generic_qdisc *qdiscopt = nla_data(opt);

		if (nla_len(opt) < sizeof(*qdiscopt)) {
			D("Invalid netlink attribute");
			return EINVAL;
		}

		priv->qidx = qdiscopt->qidx;
		priv->limit = qdiscopt->limit;
		D("Qdisc #%d initialized with max_len = %u", priv->qidx,
				                             priv->limit);
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
		RD(5, "dropping mbuf");

		return qdisc_drop(m, qdisc
#ifdef NETMAP_LINUX_HAVE_QDISC_ENQUEUE_TOFREE
		       , to_free
#endif
			);
		/* or qdisc_reshape_fail() ? */
	}

	ND(5, "Enqueuing mbuf, len %u", qdisc_qlen(qdisc));

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
            ND(5, "Event met, notify %p", m);
            netmap_generic_irq(NA(qdisc_dev(qdisc)),
                               skb_get_queue_mapping(m), NULL);
        }

	ND(5, "Dequeuing mbuf, len %u", qdisc_qlen(qdisc));

	return m;
}

static struct Qdisc_ops
generic_qdisc_ops __read_mostly = {
	.id		= "netmap_generic",
	.priv_size	= sizeof(struct nm_generic_qdisc),
	.init		= generic_qdisc_init,
	.reset		= qdisc_reset_queue,
	.change		= generic_qdisc_init,
	.enqueue	= generic_qdisc_enqueue,
	.dequeue	= generic_qdisc_dequeue,
	.dump		= NULL,
	.owner		= THIS_MODULE,
};

static int
nm_os_catch_qdisc(struct netmap_generic_adapter *gna, int intercept)
{
	struct netmap_adapter *na = &gna->up.up;
	struct ifnet *ifp = netmap_generic_getifp(gna);
	struct nm_generic_qdisc *qdiscopt = NULL;
	struct Qdisc *fqdisc = NULL;
	struct nlattr *nla = NULL;
	struct netdev_queue *txq;
	unsigned int i;

	if (!gna->txqdisc) {
		return 0;
	}

	if (intercept) {
		nla = kmalloc(nla_attr_size(sizeof(*qdiscopt)),
				GFP_KERNEL);
		if (!nla) {
			D("Failed to allocate netlink attribute");
			return ENOMEM;
		}
		nla->nla_type = RTM_NEWQDISC;
		nla->nla_len = nla_attr_size(sizeof(*qdiscopt));
		qdiscopt = (struct nm_generic_qdisc *)nla_data(nla);
		memset(qdiscopt, 0, sizeof(*qdiscopt));
		qdiscopt->limit = na->num_tx_desc;
	}

	if (ifp->flags & IFF_UP) {
		dev_deactivate(ifp);
	}

	/* Replace the current qdiscs with our own. */
	for (i = 0; i < ifp->real_num_tx_queues; i++) {
		struct Qdisc *nqdisc = NULL;
		struct Qdisc *oqdisc;
		int err;

		txq = netdev_get_tx_queue(ifp, i);

		if (intercept) {
			/* This takes a refcount to netmap module, alloc the
			 * qdisc and calls the init() op with NULL netlink
			 * attribute. */
			nqdisc = qdisc_create_dflt(
#ifndef NETMAP_LINUX_QDISC_CREATE_DFLT_3ARGS
					ifp,
#endif  /* NETMAP_LINUX_QDISC_CREATE_DFLT_3ARGS */
					txq, &generic_qdisc_ops,
					TC_H_UNSPEC);
			if (!nqdisc) {
				D("Failed to create qdisc");
				goto qdisc_create;
			}
			fqdisc = fqdisc ?: nqdisc;

			/* Call the change() op passing a valid netlink
			 * attribute. This is used to set the queue idx. */
			qdiscopt->qidx = i;
			err = nqdisc->ops->change(nqdisc, nla);
			if (err) {
				D("Failed to init qdisc");
				goto qdisc_create;
			}
		}

		oqdisc = dev_graft_qdisc(txq, nqdisc);
		/* We can call this also with
		 * odisc == &noop_qdisc, since the noop
		 * qdisc has the TCQ_F_BUILTIN flag set,
		 * and so qdisc_destroy will skip it. */
		qdisc_destroy(oqdisc);
	}

	kfree(nla);

	if (ifp->qdisc) {
		qdisc_destroy(ifp->qdisc);
	}
	if (intercept) {
		atomic_inc(&fqdisc->refcnt);
		ifp->qdisc = fqdisc;
	} else {
		ifp->qdisc = &noop_qdisc;
	}

	if (ifp->flags & IFF_UP) {
		dev_activate(ifp);
	}

	return 0;

qdisc_create:
	if (nla) {
		kfree(nla);
	}

	nm_os_catch_qdisc(gna, 0);

	return -1;
}

/* Must be called under rtnl. */
int
nm_os_catch_tx(struct netmap_generic_adapter *gna, int intercept)
{
	struct netmap_adapter *na = &gna->up.up;
	struct ifnet *ifp = netmap_generic_getifp(gna);
	int err;

	err = nm_os_catch_qdisc(gna, intercept);
	if (err) {
		return err;
	}

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

		gna->generic_ndo = *ifp->netdev_ops;  /* Copy all */
		gna->generic_ndo.ndo_start_xmit = &generic_ndo_start_xmit;
#ifndef NETMAP_LINUX_SELECT_QUEUE
		D("No packet steering support");
#else
		gna->generic_ndo.ndo_select_queue = &generic_ndo_select_queue;
#endif

		ifp->netdev_ops = &gna->generic_ndo;

	} else {
		/* Restore the original netdev_ops. */
		ifp->netdev_ops = (void *)na->if_transmit;
	}

	return 0;
}

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
   and -1 on error (which may be packet drops or other errors). */
int
nm_os_generic_xmit_frame(struct nm_os_gen_arg *a)
{
	struct mbuf *m = a->m;
	struct ifnet *ifp = a->ifp;
	u_int len = a->len;
	netdev_tx_t ret;

	/* We know that the driver needs to prepend ifp->needed_headroom bytes
	 * to each packet to be transmitted. We then reset the mbuf pointers
	 * to the correct initial state:
	 *    ___________________________________________
	 *    ^           ^                             ^
	 *    |           |                             |
	 *   head        data                          end
	 *               tail
	 *
	 * which correspond to an empty buffer with exactly
	 * ifp->needed_headroom bytes between head and data.
	 */
	m->len = 0;
	m->data = m->head + ifp->needed_headroom;
	skb_reset_tail_pointer(m);
	skb_reset_mac_header(m);

        /* Initialize the header pointers assuming this is an IPv4 packet.
         * This is useful to make netmap interact well with TC when
         * netmap_generic_txqdisc == 0.  */
	skb_set_network_header(m, 14);
	skb_set_transport_header(m, 34);
	m->protocol = htons(ETH_P_IP);
	m->pkt_type = PACKET_HOST;

	/* Copy a netmap buffer into the mbuf.
	 * TODO Support the slot flags (NS_MOREFRAG, NS_INDIRECT). */
	skb_copy_to_linear_data(m, a->addr, len); // skb_store_bits(m, 0, addr, len);
	skb_put(m, len);

	/* Hold a reference on this, we are going to recycle mbufs as
	 * much as possible. */
	NM_ATOMIC_INC(&m->users);

	/* On linux m->dev is not reliable, since it can be changed by the
	 * ndo_start_xmit() callback. This happens, for instance, with veth
	 * and bridge drivers. For this reason, the nm_os_generic_xmit_frame()
	 * implementation for linux stores a copy of m->dev into the
	 * destructor_arg field. */
	m->dev = ifp;
	skb_shinfo(m)->destructor_arg = m->dev;

	/* Tell generic_ndo_start_xmit() to pass this mbuf to the driver. */
	skb_set_queue_mapping(m, a->ring_nr);
	m->priority = a->qevent ? NM_MAGIC_PRIORITY_TXQE : NM_MAGIC_PRIORITY_TX;

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
		RD(3, "Warning: dev_queue_xmit() is dropping [%d]", ret);
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
			D("Invalid RX ring size %u, using default", *rx);
			*rx = netmap_generic_ringsize;
		}
		if (*tx < 3) {
			D("Invalid TX ring size %u, using default", *tx);
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
#endif /* HAVE_REAL_NUM_RX_QUEUES */
	}
}

int
netmap_linux_config(struct netmap_adapter *na,
		u_int *txr, u_int *txd, u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	rtnl_lock();

	if (ifp == NULL) {
		D("zombie adapter");
		error = ENXIO;
		goto out;
	}
	error = nm_os_generic_find_num_desc(ifp, txd, rxd);
	if (error)
		goto out;
	nm_os_generic_find_num_queues(ifp, txr, rxr);

out:
	rtnl_unlock();

	return error;
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
linux_netmap_poll(struct file * file, struct poll_table_struct *pwait)
{
#ifdef NETMAP_LINUX_PWAIT_KEY
	int events = pwait ? pwait->NETMAP_LINUX_PWAIT_KEY : \
		     POLLIN | POLLOUT | POLLERR;
#else
	int events = POLLIN | POLLOUT; /* XXX maybe... */
#endif /* PWAIT_KEY */
	struct nm_linux_selrecord_t sr = {
		.file = file,
		.pwait = pwait
	};
	struct netmap_priv_d *priv = file->private_data;
	return netmap_poll(priv, events, &sr);
}

static int
linux_netmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct netmap_priv_d *priv = vma->vm_private_data;
	struct netmap_adapter *na = priv->np_na;
	struct page *page;
	unsigned long off = (vma->vm_pgoff + vmf->pgoff) << PAGE_SHIFT;
	unsigned long pa, pfn;

	pa = netmap_mem_ofstophys(na->nm_mem, off);
	ND("fault off %lx -> phys addr %lx", off, pa);
	if (pa == 0)
		return VM_FAULT_SIGBUS;
	pfn = pa >> PAGE_SHIFT;
	if (!pfn_valid(pfn))
		return VM_FAULT_SIGBUS;
	page = pfn_to_page(pfn);
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
	unsigned long off;
	u_int memsize, memflags;
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
	ND("get_info returned %d", error);
	if (error)
		return -error;
	off = vma->vm_pgoff << PAGE_SHIFT;
	ND("off %lx size %lx memsize %x", off,
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

/* while in netmap mode, we cannot tolerate any change in the
 * number of rx/tx rings and descriptors
 */
int
linux_netmap_set_ringparam(struct net_device *dev,
	struct ethtool_ringparam *e)
{
	return -EBUSY;
}

#ifdef NETMAP_LINUX_HAVE_SET_CHANNELS
int
linux_netmap_set_channels(struct net_device *dev,
	struct ethtool_channels *e)
{
	return -EBUSY;
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
	} arg;
	size_t argsize = 0;

	switch (cmd) {
	case NIOCTXSYNC:
	case NIOCRXSYNC:
		break;
	case NIOCCONFIG:
		argsize = sizeof(arg.ifr);
		break;
	default:
		argsize = sizeof(arg.nmr);
		break;
	}
	if (argsize) {
		if (!data)
			return -EINVAL;
		bzero(&arg, argsize);
		if (copy_from_user(&arg, (void *)data, argsize) != 0)
			return -EFAULT;
	}
	ret = netmap_ioctl(priv, cmd, (caddr_t)&arg, NULL);
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


#ifdef WITH_VALE
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

int
netmap_bns_register(void)
{
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	return -register_pernet_subsys(&netmap_pernet_ops);
#else
	return -register_pernet_gen_subsys(&netmap_bns_id,
			&netmap_pernet_ops);
#endif
}

void
netmap_bns_unregister(void)
{
#ifdef NETMAP_LINUX_HAVE_PERNET_OPS_ID
	unregister_pernet_subsys(&netmap_pernet_ops);
#else
	unregister_pernet_gen_subsys(netmap_bns_id,
			&netmap_pernet_ops);
#endif
}
#endif /* CONFIG_NET_NS */
#endif /* WITH_VALE */

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

/* kthread context */
struct nm_kthread_ctx {
    /* files to exchange notifications */
    struct file *ioevent_file;          /* notification from guest */
    struct file *irq_file;              /* notification to guest (interrupt) */
    struct eventfd_ctx *irq_ctx;

    /* poll ioeventfd to receive notification from the guest */
    poll_table poll_table;
    wait_queue_head_t *waitq_head;
    wait_queue_t waitq;

    /* worker function and parameter */
    nm_kthread_worker_fn_t worker_fn;
    void *worker_private;

    /* integer to manage multiple worker contexts */
    long type;
};

struct nm_kthread {
    struct mm_struct *mm;
    struct task_struct *worker;

    atomic_t scheduled;         /* pending wake_up request */
    int attach_user;            /* kthread attached to user_process */

    struct nm_kthread_ctx worker_ctx;
    int affinity;
};

void inline
nm_os_kthread_wakeup_worker(struct nm_kthread *nmk)
{
    /*
     * There may be a race between FE and BE,
     * which call both this function, and worker kthread,
     * that reads ptk->scheduled.
     *
     * For us it is not important the counter value,
     * but simply that it has changed since the last
     * time the kthread saw it.
     */
    atomic_inc(&nmk->scheduled);
    wake_up_process(nmk->worker);
}


static void
nm_kthread_poll_fn(struct file *file, wait_queue_head_t *wq_head, poll_table *pt)
{
    struct nm_kthread_ctx *ctx;

    ctx = container_of(pt, struct nm_kthread_ctx, poll_table);
    ctx->waitq_head = wq_head;
    add_wait_queue(wq_head, &ctx->waitq);
}

static int
nm_kthread_poll_wakeup(wait_queue_t *wq, unsigned mode, int sync, void *key)
{
    struct nm_kthread_ctx *ctx;
    struct nm_kthread *nmk;

    ctx = container_of(wq, struct nm_kthread_ctx, waitq);
    nmk = container_of(ctx, struct nm_kthread, worker_ctx);
    nm_os_kthread_wakeup_worker(nmk);

    return 0;
}

static void inline
nm_kthread_worker_fn(struct nm_kthread_ctx *ctx)
{
    __set_current_state(TASK_RUNNING);
    ctx->worker_fn(ctx->worker_private); /* run payload */
    if (need_resched())
        schedule();
}

static int
nm_kthread_worker(void *data)
{
    struct nm_kthread *nmk = data;
    struct nm_kthread_ctx *ctx = &nmk->worker_ctx;
    int old_scheduled = atomic_read(&nmk->scheduled);
    int new_scheduled = old_scheduled;
    mm_segment_t oldfs = get_fs();

    if (nmk->mm) {
        set_fs(USER_DS);
        use_mm(nmk->mm);
    }

    while (!kthread_should_stop()) {
        if (!ctx->ioevent_file) {
	    /*
             * if ioevent_file is not defined, we don't have notification
	     * mechanism and we continually execute worker_fn()
	     */
            nm_kthread_worker_fn(ctx);

        } else {
            /*
             * Set INTERRUPTIBLE state before to check if there is work.
             * if wake_up() is called, although we have not seen the new
             * counter value, the kthread state is set to RUNNING and
             * after schedule() it is not moved off run queue.
             */
            set_current_state(TASK_INTERRUPTIBLE);

            new_scheduled = atomic_read(&nmk->scheduled);

            /* check if there is a pending notification */
            if (likely(new_scheduled != old_scheduled)) {
                old_scheduled = new_scheduled;
                nm_kthread_worker_fn(ctx);
            } else {
                schedule();
            }
        }
    }

    __set_current_state(TASK_RUNNING);

    if (nmk->mm) {
        unuse_mm(nmk->mm);
    }

    set_fs(oldfs);
    return 0;
}

void inline
nm_os_kthread_send_irq(struct nm_kthread *nmk)
{
    if (nmk->worker_ctx.irq_ctx)
        eventfd_signal(nmk->worker_ctx.irq_ctx, 1);
}

static void
nm_kthread_close_files(struct nm_kthread *nmk)
{
    struct nm_kthread_ctx *wctx = &nmk->worker_ctx;

    if (wctx->ioevent_file) {
        fput(wctx->ioevent_file);
        wctx->ioevent_file = NULL;
    }

    if (wctx->irq_file) {
        fput(wctx->irq_file);
        wctx->irq_file = NULL;
        eventfd_ctx_put(wctx->irq_ctx);
        wctx->irq_ctx = NULL;
    }
}

static int
nm_kthread_open_files(struct nm_kthread *nmk, void *opaque)
{
    struct file *file;
    struct nm_kthread_ctx *wctx = &nmk->worker_ctx;
    struct ptnetmap_cfgentry_qemu *ring_cfg = opaque;

    wctx->ioevent_file = NULL;
    wctx->irq_file = NULL;

    if (!opaque) {
	return 0;
    }

    if (ring_cfg->ioeventfd) {
	file = eventfd_fget(ring_cfg->ioeventfd);
	if (IS_ERR(file))
	    goto err;
	wctx->ioevent_file = file;
    }

    if (ring_cfg->irqfd) {
	file = eventfd_fget(ring_cfg->irqfd);
	if (IS_ERR(file))
            goto err;
	wctx->irq_file = file;
	wctx->irq_ctx = eventfd_ctx_fileget(file);
    }

    return 0;

err:
    nm_kthread_close_files(nmk);
    return -PTR_ERR(file);
}

static void
nm_kthread_init_poll(struct nm_kthread *nmk, struct nm_kthread_ctx *ctx)
{
    init_waitqueue_func_entry(&ctx->waitq, nm_kthread_poll_wakeup);
    init_poll_funcptr(&ctx->poll_table, nm_kthread_poll_fn);
}

static int
nm_kthread_start_poll(struct nm_kthread_ctx *ctx, struct file *file)
{
    unsigned long mask;
    int ret = 0;

    if (ctx->waitq_head)
        return 0;
    mask = file->f_op->poll(file, &ctx->poll_table);
    if (mask)
        nm_kthread_poll_wakeup(&ctx->waitq, 0, 0, (void *)mask);
    if (mask & POLLERR) {
        if (ctx->waitq_head)
            remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ret = EINVAL;
    }
    return ret;
}

static void
nm_kthread_stop_poll(struct nm_kthread_ctx *ctx)
{
    if (ctx->waitq_head) {
        remove_wait_queue(ctx->waitq_head, &ctx->waitq);
        ctx->waitq_head = NULL;
    }
}

void
nm_os_kthread_set_affinity(struct nm_kthread *nmk, int affinity)
{
	nmk->affinity = affinity;
}

struct nm_kthread *
nm_os_kthread_create(struct nm_kthread_cfg *cfg, unsigned int cfgtype,
		     void *opaque)
{
    struct nm_kthread *nmk = NULL;
    int error;

    if (cfgtype != PTNETMAP_CFGTYPE_QEMU) {
	D("Unsupported cfgtype %u", cfgtype);
	return NULL;
    }

    nmk = kzalloc(sizeof *nmk, GFP_KERNEL);
    if (!nmk)
        return NULL;

    nmk->worker_ctx.worker_fn = cfg->worker_fn;
    nmk->worker_ctx.worker_private = cfg->worker_private;
    nmk->worker_ctx.type = cfg->type;
    atomic_set(&nmk->scheduled, 0);

    /* attach kthread to user process (ptnetmap) */
    nmk->attach_user = cfg->attach_user;

    /* open event fds */
    error = nm_kthread_open_files(nmk, opaque);
    if (error)
        goto err;

    nm_kthread_init_poll(nmk, &nmk->worker_ctx);

    return nmk;
err:
    //XXX: set errno?
    kfree(nmk);
    return NULL;
}

int
nm_os_kthread_start(struct nm_kthread *nmk)
{
    int error = 0;
    char name[16];

    if (nmk->worker) {
        return EBUSY;
    }

    /* check if we want to attach kthread to user process */
    if (nmk->attach_user) {
        nmk->mm = get_task_mm(current);
    }

    /* ToDo Make this able to pass arbitrary string (e.g., for 'nm_') from nmk */
    snprintf(name, sizeof(name), "nmkth:%d:%ld", current->pid,
	     nmk->worker_ctx.type);
    nmk->worker = kthread_create(nm_kthread_worker, nmk, name);
    if (IS_ERR(nmk->worker)) {
	error = -PTR_ERR(nmk->worker);
	goto err;
    }

    kthread_bind(nmk->worker, nmk->affinity);
    wake_up_process(nmk->worker);

    if (nmk->worker_ctx.ioevent_file) {
	error = nm_kthread_start_poll(&nmk->worker_ctx,
				      nmk->worker_ctx.ioevent_file);
	if (error) {
            goto err_kstop;
	}
    }

    return 0;
err_kstop:
    kthread_stop(nmk->worker);
err:
    nmk->worker = NULL;
    if (nmk->mm)
        mmput(nmk->mm);
    nmk->mm = NULL;
    return error;
}

void
nm_os_kthread_stop(struct nm_kthread *nmk)
{
    if (!nmk->worker) {
        return;
    }

    nm_kthread_stop_poll(&nmk->worker_ctx);

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
nm_os_kthread_delete(struct nm_kthread *nmk)
{
    if (!nmk)
        return;

    if (nmk->worker) {
        nm_os_kthread_stop(nmk);
    }

    nm_kthread_close_files(nmk);

    kfree(nmk);
}

/* ##################### PTNETMAP SUPPORT ##################### */
#ifdef WITH_PTNETMAP_GUEST
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

    D("=== BAR %d start %llx len %llx mem_size %lx ===",
            PTNETMAP_MEM_PCI_BAR,
            pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
            pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR),
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
 * Device Initialization Routine
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
    err = pci_enable_device(pdev); /* XXX-ste: device_mem() */
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
    pci_set_master(pdev); /* XXX-ste: is needed??? */

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
 * Device Removal Routine
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
 * pci driver information
 */
static struct pci_driver ptnetmap_guest_drivers = {
    .name       = "ptnetmap-guest-drivers",
    .id_table   = ptnetmap_guest_device_table,
    .probe      = ptnetmap_guest_probe,
    .remove     = ptnetmap_guest_remove,
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
        D("Failed to register drivers");
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

#else /* !WITH_PTNETMAP_GUEST */
#define ptnetmap_guest_init()		0
#define ptnetmap_guest_fini()
#endif /* WITH_PTNETMAP_GUEST */

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
		return ENOMEM;
	}
	netdev->netdev_ops = &nm_sink_netdev_ops ;
	strncpy(netdev->name, "nmsink", sizeof(netdev->name) - 1);
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
		return err;
	}
#ifdef WITH_SINK
	err = netmap_sink_init();
	if (err) {
		D("Warning: could not init netmap sink interface");
	}
#endif /* WITH_SINK */
	return 0;
}


static void linux_netmap_fini(void)
{
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
static struct rtnl_link_stats64 *linux_nm_vi_get_stats(
		struct net_device *netdev,
		struct rtnl_link_stats64 *stats)
{
	return stats;
}
#endif

static int linux_nm_vi_change_mtu(struct net_device *netdev, int new_mtu)
{
	return 0;
}
static void linux_nm_vi_destructor(struct net_device *netdev)
{
//	netmap_detach(netdev);
	free_netdev(netdev);
}
static const struct net_device_ops nm_vi_ops = {
	.ndo_open = linux_nm_vi_open,
	.ndo_stop = linux_nm_vi_stop,
	.ndo_start_xmit = linux_nm_vi_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu = linux_nm_vi_change_mtu,
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
	dev->destructor = linux_nm_vi_destructor;
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

	if (!try_module_get(linux_dummy_drv.owner))
		return EFAULT;
#ifdef NETMAP_LINUX_ALLOC_NETDEV_4ARGS
	ifp = alloc_netdev(0, name, NET_NAME_UNKNOWN, linux_nm_vi_setup);
#else
	ifp = alloc_netdev(0, name, linux_nm_vi_setup);
#endif
	if (!ifp) {
		module_put(linux_dummy_drv.owner);
		return ENOMEM;
	}
	dev_net_set(ifp, &init_net);
	ifp->features |= NETIF_F_NETNS_LOCAL; /* just for safety */
	register_netdev(ifp);
	ifp->dev.driver = &linux_dummy_drv;
	netif_start_queue(ifp);
	*ret = ifp;
	return 0;
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

module_init(linux_netmap_init);
module_exit(linux_netmap_fini);

/* export certain symbols to other modules */
EXPORT_SYMBOL(netmap_attach);		/* driver attach routines */
#ifdef WITH_PTNETMAP_GUEST
EXPORT_SYMBOL(netmap_pt_guest_attach);	/* ptnetmap driver attach routine */
EXPORT_SYMBOL(netmap_pt_guest_rxsync);	/* ptnetmap generic rxsync */
EXPORT_SYMBOL(netmap_pt_guest_txsync);	/* ptnetmap generic txsync */
EXPORT_SYMBOL(netmap_mem_pt_guest_ifp_del); /* unlink passthrough interface */
#endif /* WITH_PTNETMAP_GUEST */
EXPORT_SYMBOL(netmap_detach);		/* driver detach routines */
EXPORT_SYMBOL(netmap_ring_reinit);	/* ring init on error */
EXPORT_SYMBOL(netmap_reset);		/* ring init routines */
EXPORT_SYMBOL(netmap_rx_irq);	        /* default irq handler */
EXPORT_SYMBOL(netmap_no_pendintr);	/* XXX mitigation - should go away */
#ifdef WITH_VALE
EXPORT_SYMBOL(netmap_bdg_ctl);		/* bridge configuration routine */
EXPORT_SYMBOL(netmap_bdg_learning);	/* the default lookup function */
EXPORT_SYMBOL(netmap_bdg_name);		/* the bridge the vp is attached to */
#endif /* WITH_VALE */
EXPORT_SYMBOL(netmap_disable_all_rings);
EXPORT_SYMBOL(netmap_enable_all_rings);
EXPORT_SYMBOL(netmap_krings_create);
EXPORT_SYMBOL(netmap_krings_delete);	/* used by veth module */
EXPORT_SYMBOL(netmap_mem_rings_create);	/* used by veth module */
EXPORT_SYMBOL(netmap_mem_rings_delete);	/* used by veth module */
#ifdef WITH_PIPES
EXPORT_SYMBOL(netmap_pipe_txsync);	/* used by veth module */
EXPORT_SYMBOL(netmap_pipe_rxsync);	/* used by veth module */
#endif /* WITH_PIPES */
EXPORT_SYMBOL(netmap_verbose);

MODULE_AUTHOR("http://info.iet.unipi.it/~luigi/netmap/");
MODULE_DESCRIPTION("The netmap packet I/O framework");
MODULE_LICENSE("Dual BSD/GPL"); /* the code here is all BSD. */
