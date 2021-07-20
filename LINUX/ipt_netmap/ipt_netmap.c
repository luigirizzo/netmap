/**
 * @file    ipt_netmap.c
 * @author  Sheena Mira-ato
 * @date    12 January 2018
 * @version 1
 * @brief  A loadable kernel module (LKM) that adds an NMRING target for iptables
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/dst_metadata.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#include <net/xfrm.h>
#include <linux/list.h>
#include <net/icmp.h>
#include "ipt_netmap.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sheena Mira-ato");
MODULE_DESCRIPTION("A loadable kernel module that adds an NMRING target for iptables");
MODULE_VERSION("1");

#define NF_INET_UNSET	NF_INET_NUMHOOKS

struct ipt_netmap_priv {
	struct netmap_priv_d *netmap_priv;
	char name[IFNAMSIZ + 1];
	struct net *net;
	int hooknum;
	int __percpu *percpu_recursion;
	struct list_head list;
};

static struct ipt_netmap_priv ipt_netmap_pipes = { 0 };
static unsigned ipt_netmap_net_id __read_mostly;

static struct ipt_netmap_priv *find_ifc_pipe(const char pipe[])
{
	struct list_head *node;
	struct ipt_netmap_priv *entry = NULL;
	list_for_each(node, &ipt_netmap_pipes.list) {
		entry = list_entry(node, struct ipt_netmap_priv, list);
		if (strcmp(pipe, entry->name) == 0
#ifdef CONFIG_NET_NS
			&& entry->net == current->nsproxy->net_ns
#endif
		)
			return entry;
	}
	return NULL;
}

static struct ipt_netmap_priv *find_priv_from_na(struct netmap_adapter *na)
{
	struct list_head *node;
	struct ipt_netmap_priv *entry = NULL;

	list_for_each(node, &ipt_netmap_pipes.list) {
		entry = list_entry(node, struct ipt_netmap_priv, list);
		if (entry->netmap_priv->np_na == na)
			return entry;
	}
	return NULL;
}

static bool ipt_ipv4_route(struct net *net, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	struct flowi4 fl4;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = iph->daddr;
	fl4.saddr = iph->saddr;
	fl4.flowi4_tos = RT_TOS(iph->tos);
	fl4.flowi4_mark = skb->mark;
	fl4.flowi4_oif = skb->skb_iif;
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	fl4.flowi4_flags = FLOWI_FLAG_KNOWN_NH | FLOWI_FLAG_ANYSRC;
	fl4.flowi4_proto = iph->protocol;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return false;

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	if (skb_dst(skb)->error)
		return false;

#ifdef CONFIG_XFRM
	if (!(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
	    xfrm_decode_session(skb, flowi4_to_flowi(&fl4), AF_INET) == 0) {
		struct dst_entry *dst = skb_dst(skb);
		skb_dst_set(skb, NULL);
		dst = xfrm_lookup(net, dst, flowi4_to_flowi(&fl4), skb->sk, 0);
		if (IS_ERR(dst))
			return false;
		skb_dst_set(skb, dst);
	}
#endif

	skb->dev = rt->dst.dev;
	return true;
}

static bool ipt_ipv6_route(struct net *net, struct sk_buff *skb)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct dst_entry *dst;
	struct flowi6 fl6;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = iph->daddr;
	fl6.saddr = iph->saddr;
	fl6.flowlabel = ip6_flowinfo(iph);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = iph->nexthdr;
	fl6.flowi6_oif = skb->skb_iif;
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst->error) {
		dst_release(dst);
		return false;
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);

#ifdef CONFIG_XFRM
	if (!(IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) &&
	    xfrm_decode_session(skb, flowi6_to_flowi(&fl6), AF_INET6) == 0) {
		skb_dst_set(skb, NULL);
		dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), skb->sk, 0);
		if (IS_ERR(dst))
			return false;
		skb_dst_set(skb, dst);
	}
#endif

	/* Avoid looping back ndisc messages by ensuring they use the
	 * correct sk, which has mc_loop set to 0 */
	if (iph->nexthdr == IPPROTO_ICMPV6 &&
		ipv6_addr_is_multicast(&iph->daddr)) {
		struct icmp6hdr *hdr = (struct icmp6hdr *)(skb_network_header(skb) +
				skb_network_header_len(skb));
		switch (hdr->icmp6_type) {
		case NDISC_ROUTER_SOLICITATION:
		case NDISC_ROUTER_ADVERTISEMENT:
		case NDISC_NEIGHBOUR_SOLICITATION:
		case NDISC_NEIGHBOUR_ADVERTISEMENT:
		case NDISC_REDIRECT:
			skb_set_owner_w(skb, dev_net(dst->dev)->ipv6.ndisc_sk);
			break;
		default:
			break;
		}
	}

	/* Set the output device */
	skb->dev = dst->dev;
	return true;
}

static void ipt_output_repeat (struct ipt_netmap_priv *priv, struct mbuf *skb)
{
	int pf = (skb->protocol == htons(ETH_P_IP)) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	int err;

	nm_prdis("sending out pkt:%p size:%d proto:0x%0x\n",
			skb, MBUF_LEN(skb), skb->protocol);

	/* Need a dst */
	if (skb->protocol == htons(ETH_P_IP)) {
		ipt_ipv4_route(priv->net, skb);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ipt_ipv6_route(priv->net, skb);
	}
	if (!skb_dst(skb)) {
		if (printk_ratelimit())
			pr_debug("NMRING: No route for processed output packet\n");
		kfree_skb(skb);
		return;
	}

	/* SoftIRQs going off during this processing can cause soft lockups */
	local_bh_disable();

	/* Repeat OUTPUT chain avoiding re-entry */
	this_cpu_inc(*priv->percpu_recursion);
	err = nf_hook(pf, NF_INET_LOCAL_OUT,
		dev_net(skb_dst(skb)->dev), skb->sk, skb,
		NULL, skb_dst(skb)->dev,
		dst_output);
	this_cpu_dec(*priv->percpu_recursion);
	if (likely(err == 1)) {
		dst_output(priv->net, skb->sk, skb);
	}

	/* It's now safe to reenable softirqs */
	local_bh_enable();
}

static inline int ipt_prerouting_finish(struct net *net, struct sock *sk,
					 struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	if (skb->protocol == htons(ETH_P_IP)) {
		const struct iphdr *iph = ip_hdr(skb);
		skb = l3mdev_ip_rcv(skb);
		if (!skb)
			return NET_RX_SUCCESS;
		if (!skb_valid_dst(skb) &&
			ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, dev)) {
			if (printk_ratelimit())
				pr_debug("NMRING: No route for processed prerouting packet\n");
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);
		skb = l3mdev_ip6_rcv(skb);
		if (!skb)
			return NET_RX_SUCCESS;
		if (!skb_valid_dst(skb)) {
			int flags = RT6_LOOKUP_F_HAS_SADDR;
			struct flowi6 fl6 = {
				.flowi6_iif = dev->ifindex,
				.daddr = iph->daddr,
				.saddr = iph->saddr,
				.flowlabel = ip6_flowinfo(iph),
				.flowi6_mark = skb->mark,
				.flowi6_proto = iph->nexthdr,
			};
			skb_dst_drop(skb);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
			skb_dst_set(skb, ip6_route_input_lookup(net, dev, &fl6, flags));
#else
			skb_dst_set(skb, ip6_route_input_lookup(net, dev, &fl6, skb, flags));
#endif
		}
	}
	return dst_input(skb);
}

static void ipt_prerouting_repeat (struct ipt_netmap_priv *priv, struct mbuf *skb)
{
	int pf = (skb->protocol == htons(ETH_P_IP)) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	int err;

	nm_prdis("receiving pkt:%p size:%d proto:0x%0x\n",
			skb, MBUF_LEN(skb), skb->protocol);

	/* Find the interface this packet came in on */
	rcu_read_lock();
	skb->dev = dev_get_by_index_rcu(priv->net, skb->skb_iif);
	rcu_read_unlock();
	if (!skb->dev) {
		pr_err("NMRING: No iif for processed prerouting packet\n");
		kfree_skb(skb);
		return;
	}
	__net_timestamp(skb);

	/* SoftIRQs going off during this processing can cause soft lockups */
	local_bh_disable();

	/* Repeat PREROUTING chain avoiding re-entry */
	this_cpu_inc(*priv->percpu_recursion);
	err = nf_hook(pf, NF_INET_PRE_ROUTING,
		dev_net(skb->dev), NULL, skb,
		skb->dev, NULL,
		ipt_prerouting_finish);
	this_cpu_dec(*priv->percpu_recursion);
	if (likely(err == 1)) {
		ipt_prerouting_finish(priv->net, NULL, skb);
	}

	/* It's now safe to reenable softirqs */
	local_bh_enable();
}

static int ipt_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ipt_netmap_priv *priv = find_priv_from_na(kring->pipe->na);
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	u_int n;

	if (!priv) {
		pr_err("NMRING(TX): no priv\n");
		return 0;
	}

	for (n = kring->nr_hwcur; n != head; n = nm_next(n, lim)) {
		struct mbuf *skb;
		struct netmap_slot *slot = &kring->ring->slot[n];
		char *buffer = NMB(na, slot);
		unsigned short proto = ((struct ethhdr *) buffer)->h_proto;
		int len = slot->len;

		/* Sanity check buffer */
		if (len < 14 || len > NETMAP_BUF_SIZE(na)) {
			pr_err("NMRING: bad pkt at %d len %d\n", n, len);
			continue;
		}

		/* Copy into a fresh new skbuff */
		skb = m_devget(buffer, len, 0, NULL, NULL, slot->mark,
					   slot->hash, slot->iif);
		if (skb == NULL)
			continue;
		skb_pull(skb, ETH_HLEN);
		skb_set_network_header(skb, 0);
		if (proto == htons(ETH_P_IP)) {
			skb_set_transport_header(skb, sizeof(struct iphdr));
			IPCB(skb)->iif = skb->skb_iif;
		}
		else if (proto == htons(ETH_P_IPV6)) {
			skb_set_transport_header(skb, sizeof(struct ipv6hdr));
			IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);
			IP6CB(skb)->iif = skb->skb_iif;
		}
		skb->protocol = proto;

		if (priv->hooknum == NF_INET_PRE_ROUTING) {
			ipt_prerouting_repeat(priv, skb);
		}
		else if (priv->hooknum == NF_INET_LOCAL_OUT) {
			ipt_output_repeat(priv, skb);
		}
		else {
			pr_warn("NMRING: processed packet with no hooknum set\n");
			kfree_skb(skb);
		}
	}
	kring->nr_hwcur = head;
	kring->nr_hwtail = nm_prev(kring->nr_hwcur, lim);
	/* We do not use this - but netmap_pipe_krings_delete does */
	kring->pipe_tail = kring->nr_hwtail;
	return 0;
}

static int
ipt_rxsync(struct netmap_kring *kring, int flags)
{
	struct ipt_netmap_priv *priv = find_priv_from_na(kring->pipe->na);
	struct netmap_ring *ring = kring->ring;
	struct netmap_adapter *na = kring->na;
	u_int nm_i;	/* index into the netmap ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	/* Adapter-specific variables. */
	u_int nm_buf_len = NETMAP_BUF_SIZE(na);
	struct mbq tmpq;
	struct mbuf *m;
	int avail; /* in bytes */
	int mlen;
	int copy;

	if (!priv) {
		return 0;
	}

	if (head > lim)
		return netmap_ring_reinit(kring);

	/*
	 * First part: skip past packets that userspace has released.
	 * This can possibly make room for the second part.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != head) {
		/* Userspace has released some packets. */
		for (n = 0; nm_i != head; n++) {
			struct netmap_slot *rs = &kring->ring->slot[nm_i];
			struct netmap_slot *ts = &kring->pipe->ring->slot[nm_i];
			rs->flags &= ~NS_BUF_CHANGED;
			/* Keep the TX ring synced even though we do not use it
			   as it avoids double freeing buffers during cleanup */
			*ts = *rs;
			nm_i = nm_next(nm_i, lim);
		}
		kring->nr_hwcur = head;
	}
	/* We do not use this - but netmap_pipe_krings_delete does */
	kring->pipe_tail = kring->nr_hwcur;

	/*
	 * Second part: import newly received packets.
	 */
	if (!netmap_no_pendintr && !force_update) {
		return 0;
	}

	nm_i = kring->nr_hwtail; /* First empty slot in the receive ring. */

	/* Compute the available space (in bytes) in this netmap ring.
	 * The first slot that is not considered in is the one before
	 * nr_hwcur. */

	avail = nm_prev(kring->nr_hwcur, lim) - nm_i;
	if (avail < 0)
		avail += lim + 1;
	avail *= nm_buf_len;

	/* First pass: While holding the lock on the RX mbuf queue,
	 * extract as many mbufs as they fit the available space,
	 * and put them in a temporary queue.
	 * To avoid performing a per-mbuf division (mlen / nm_buf_len) to
	 * to update avail, we do the update in a while loop that we
	 * also use to set the RX slots, but without performing the copy. */
	mbq_init(&tmpq);
	mbq_lock(&kring->rx_queue);
	for (n = 0;; n++) {
		m = mbq_peek(&kring->rx_queue);
		if (!m) {
			/* No more packets from the driver. */
			break;
		}

		mlen = MBUF_LEN(m);
		if (mlen > avail) {
			/* No more space in the ring. */
			break;
		}

		mbq_dequeue(&kring->rx_queue);

		while (mlen) {
			copy = nm_buf_len;
			if (mlen < copy) {
				copy = mlen;
			}
			mlen -= copy;
			avail -= nm_buf_len;

			ring->slot[nm_i].len = copy;
			ring->slot[nm_i].flags = mlen ? NS_MOREFRAG : 0;
			nm_i = nm_next(nm_i, lim);
		}

		mbq_enqueue(&tmpq, m);
	}
	mbq_unlock(&kring->rx_queue);

	/* Second pass: Drain the temporary queue, going over the used RX slots,
	 * and perform the copy out of the RX queue lock. */
	nm_i = kring->nr_hwtail;

	for (;;) {
		void *nmaddr;
		struct ethhdr *eth_hdr = NULL;

		m = mbq_dequeue(&tmpq);
		if (!m)	{
			break;
		}

		ring->slot[nm_i].mark = m->mark;
		ring->slot[nm_i].hash = 0; /* Can't trust pkt hash from iptables */
		ring->slot[nm_i].ll_ofs = NETMAP_SLOT_HEADROOM;
		if (priv->hooknum == NF_INET_PRE_ROUTING) {
			ring->slot[nm_i].iif = m->skb_iif;
		}
		else if (priv->hooknum == NF_INET_LOCAL_OUT &&
		         skb_dst(m) && skb_dst(m)->dev) {
			ring->slot[nm_i].iif = skb_dst(m)->dev->ifindex;
		}
		else
		{
			ring->slot[nm_i].iif = 0;
		}

		nmaddr = NMB(na, &ring->slot[nm_i]);

		if (nmaddr == NETMAP_BUF_BASE(na)) { /* Bad buffer */
			m_freem(m);
			mbq_purge(&tmpq);
			mbq_fini(&tmpq);
			return netmap_ring_reinit(kring);
		}

		eth_hdr = (struct ethhdr *) nmaddr;
		eth_hdr->h_proto = m->protocol;

		copy = ring->slot[nm_i].len;
		ring->slot[nm_i].len += ETH_HLEN;
		m_copydata(m, 0, copy, nmaddr + ETH_HLEN);
		nm_i = nm_next(nm_i, lim);

		m_freem(m);
	}

	mbq_fini(&tmpq);

	if (n) {
		kring->nr_hwtail = nm_i;
	}
	kring->nr_kflags &= ~NKR_PENDINTR;

	return 0;
}

static int create_ifc_pipe(struct xt_nmring_info *info,
		struct net *net, unsigned int hooknum)
{
	int error = 0;
	struct nmreq *nmr = NULL;
	struct netmap_adapter *na = NULL;
	struct netmap_kring *rx_kring = NULL;
	struct netmap_kring *tx_kring = NULL;
	struct ipt_netmap_priv *priv;
	char *pipe = info->ifc_pipe;

	/**
	 * The ipv4 and ipv6 refer to the same priv and na. Just increment
	 * priv->np_refs if there's already a reference to na.
	 *
	 * If this rule already exists and iptables create other rules, iptables
	 * will also create and destroy this rule each time.  Increment
	 * priv->np_refs on create when na_refcount is 1, so that when destroy
	 * decrements priv->np_refs, it won't be decremented to zero until the
	 * final destroy call.
	 */

	/* See if this netmap pipe already exists */
	priv = find_ifc_pipe(pipe);
	/* Can go to/from unset to/from prerouting/output
	 * but not from prerouting to output or output to prerouting */
	if (priv &&
		priv->hooknum != hooknum &&
		priv->hooknum != NF_INET_UNSET &&
		hooknum != NF_INET_UNSET) {
		pr_err("%s: pipe cannot be assigned to both OUTPUT and PREROUTING\n", pipe);
		return -EBUSY;
	}

	NMG_LOCK();
	if (priv && (priv->netmap_priv->np_refs > 0)) {
		na = priv->netmap_priv->np_na;
		if (na && na->na_refcount == 1) {
			nm_prdis("Increment pipe %s hooknum:0x%x\n", pipe, hooknum);
			priv->netmap_priv->np_refs++;
			priv->hooknum = hooknum;
			NMG_UNLOCK();
			info->priv = priv;
			return 0;
		}
	}
	nm_prdis("Create pipe %s hooknum:0x%x\n", pipe, hooknum);

	priv = nm_os_malloc(sizeof(struct ipt_netmap_priv));
	if (!priv) {
		NMG_UNLOCK();
		return -ENOMEM;
	}

	/* NETMAP OPEN */
	priv->netmap_priv = netmap_priv_new();
	if (!priv->netmap_priv) {
		nm_os_free(priv);
		NMG_UNLOCK();
		return -ENOMEM;
	}
	NMG_UNLOCK();
	info->priv = priv;
	priv->net = net;
	priv->hooknum = hooknum;
	priv->percpu_recursion = alloc_percpu(int);
	strncpy(priv->name, pipe, IFNAMSIZ);
	INIT_LIST_HEAD(&priv->list);
	list_add(&priv->list, &ipt_netmap_pipes.list);

	/* Register the pipe */
	nmr = nm_os_malloc(sizeof(struct nmreq));
	nmr->nr_version = NETMAP_API;
	strncpy(nmr->nr_name, pipe, sizeof(nmr->nr_name) - 1);
	nmr->nr_name[sizeof(nmr->nr_name) - 1] = '\0';
	nmr->nr_version = NETMAP_API;
	nmr->nr_flags = NR_REG_PIPE_MASTER;
	nmr->nr_arg1 = 1;
	nmr->nr_ringid = 0;
	nmr->nr_cmd = 0;
	nmr->nr_tx_rings = nmr->nr_rx_rings = 1;
	nmr->nr_tx_slots = nmr->nr_rx_slots = netmap_generic_ringsize;
	nmr->nr_arg2 = 1; /* Use the global namespace */
	error = netmap_ioctl_legacy(priv->netmap_priv, NIOCREGIF, (caddr_t) nmr, NULL);
	if (!priv->netmap_priv->np_nifp) {
		nm_os_free(nmr);
		return -ENOMEM;
	}
	nm_os_free(nmr);

	/* Hook rxsync and txsync */
	na = priv->netmap_priv->np_na;
	rx_kring = na->rx_rings[priv->netmap_priv->np_qfirst[NR_RX]];
	tx_kring = rx_kring->pipe;
	tx_kring->nm_sync = ipt_txsync;
	tx_kring = na->tx_rings[priv->netmap_priv->np_qfirst[NR_TX]];
	rx_kring = tx_kring->pipe;
	rx_kring->nm_sync = ipt_rxsync;
	mbq_safe_init(&rx_kring->rx_queue);

	return error;
}

static int copy_pkt_to_queue(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct ipt_netmap_priv *priv = (struct ipt_netmap_priv *)skb_get_priv(skb);
	struct netmap_adapter *na = priv->netmap_priv->np_na;
	struct netmap_kring *tx_kring = na->tx_rings[priv->netmap_priv->np_qfirst[NR_TX]];
	struct netmap_kring *rx_kring = tx_kring->pipe;

	/* Calculate full checksum before we ship it off */
	if (priv->hooknum == NF_INET_LOCAL_OUT &&
		skb->ip_summed == CHECKSUM_PARTIAL &&
		skb_checksum_help(skb)) {
		pr_err("NMRING: calculate checksum failed\n");
		return -EFAULT;
	}

	/* We need to make sure we hold a reference to the dest */
	if (skb_dst_is_noref(skb))
		skb_dst_force(skb);

	mbq_safe_enqueue(&rx_kring->rx_queue, skb);
	rx_kring->nm_notify(rx_kring, 0);
	return 0;
}

static unsigned int nmring_tg4(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_nmring_info *info = par->targinfo;
	const struct ipt_netmap_priv *priv = info->priv;
	struct netmap_kring *tx_kring = NULL;
	struct netmap_kring *rx_kring = NULL;
	struct netmap_adapter *na = NULL;
	struct iphdr *iph = ip_hdr(skb);
	unsigned int mtu;
	unsigned int rc = NF_STOLEN;
	const struct icmphdr *icmph;

	if (!priv || priv->hooknum == NF_INET_UNSET ||
			!priv->netmap_priv || !priv->netmap_priv->np_na) {
		net_warn_ratelimited("NMRING: packet with no context\n");
		return XT_CONTINUE;
	}

	/* Avoid coming in again (i.e. from txsync) */
	if (__this_cpu_read(*priv->percpu_recursion) > 0) {
		return XT_CONTINUE;
	}

	/* Skip our own ICMP errors */
	if (iph->protocol == IPPROTO_ICMP && priv->hooknum == NF_INET_LOCAL_OUT) {
		icmph = icmp_hdr(skb);
		if (icmph && icmph->type == ICMP_DEST_UNREACH) {
			return XT_CONTINUE;
		}
	}

	na = priv->netmap_priv->np_na;
	tx_kring = na->tx_rings[priv->netmap_priv->np_qfirst[NR_TX]];
	rx_kring = tx_kring->pipe;

	if (unlikely(mbq_len(&rx_kring->rx_queue) > netdev_max_backlog)) {
		net_dbg_ratelimited("NMRING[%s]: queue full\n", priv->name);
		rx_kring->ring->drops++;
		return NF_DROP;
	}

	if (skb_dst(skb) && skb_dst(skb)->dev) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
		mtu = ip_skb_dst_mtu(skb);
#else
		mtu = ip_skb_dst_mtu(skb->sk, skb);
#endif
		mtu = min(mtu, NETMAP_BUF_SIZE(na));
	}
	else {
		mtu = min_not_zero((unsigned int)skb_pagelen(skb), NETMAP_BUF_SIZE(na));
	}

	skb->protocol = htons(ETH_P_IP);
	skb_set_priv(skb, priv);

	if (skb_is_gso(skb) && priv->hooknum == NF_INET_LOCAL_OUT) {
		/* We need to hand the GSO segmentation ourselves. */
		struct sk_buff *next;
		struct sk_buff *segments = skb_gso_segment(skb, 0);
		m_freem(skb);
		if (!IS_ERR(segments) && segments)
		{
			skb_list_walk_safe(segments, skb, next) {
				/* This no longer needs GSO */
				skb_mark_not_on_list(skb);
				copy_pkt_to_queue(priv->net, skb->sk, skb);
			}
		}
		return NF_STOLEN;
	}
	else if (skb->len > mtu) {
		if ((iph->frag_off & htons(IP_DF)) == 0) {
			ip_do_fragment(priv->net, NULL, skb, copy_pkt_to_queue);
		}
		else if (unlikely(!skb->ignore_df ||
				(IPCB(skb)->frag_max_size &&
						IPCB(skb)->frag_max_size > mtu))) {
			IP_INC_STATS(priv->net, IPSTATS_MIB_FRAGFAILS);
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				  htonl(mtu));
			return NF_DROP;
		}
		else {
			ip_do_fragment(priv->net, NULL, skb, copy_pkt_to_queue);
		}
		return NF_STOLEN;
	}
	else {
		if (copy_pkt_to_queue(NULL, NULL, skb) != 0) {
			rc = NF_DROP;
		}
		return rc;
	}
}

static unsigned int nmring_tg6(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_nmring_info *info = par->targinfo;
	const struct ipt_netmap_priv *priv = info->priv;
	struct netmap_kring *tx_kring = NULL;
	struct netmap_kring *rx_kring = NULL;
	struct netmap_adapter *na = NULL;
	unsigned int mtu;
	unsigned int rc = NF_STOLEN;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	const struct icmp6hdr *icmp6h = NULL;

	if (!priv || priv->hooknum == NF_INET_UNSET ||
			!priv->netmap_priv || !priv->netmap_priv->np_na) {
		pr_warn("NMRING: packet with no context\n");
		return XT_CONTINUE;
	}

	/* Avoid coming in again (i.e. from txsync) */
	if (__this_cpu_read(*priv->percpu_recursion) > 0) {
		return XT_CONTINUE;
	}

	/* Skip our own ICMPv6 errors */
	if (ip6h->nexthdr == NEXTHDR_ICMP && priv->hooknum == NF_INET_LOCAL_OUT) {
		icmp6h = icmp6_hdr(skb);
		if (icmp6h && (icmp6h->icmp6_type == ICMPV6_DEST_UNREACH ||
			       icmp6h->icmp6_type == ICMPV6_PKT_TOOBIG ||
			       icmp6h->icmp6_type == ICMPV6_TIME_EXCEED ||
			       icmp6h->icmp6_type == ICMPV6_PARAMPROB)) {
			return XT_CONTINUE;
		}
	}

	na = priv->netmap_priv->np_na;
	tx_kring = na->tx_rings[priv->netmap_priv->np_qfirst[NR_TX]];
	rx_kring = tx_kring->pipe;

	if (unlikely(mbq_len(&rx_kring->rx_queue) > netdev_max_backlog)) {
		net_dbg_ratelimited("NMRING[%s]: queue full\n", priv->name);
		rx_kring->ring->drops++;
		return NF_DROP;
	}

	if (skb_dst(skb)) {
		mtu = ip6_skb_dst_mtu(skb);
		mtu = min(mtu, NETMAP_BUF_SIZE(na));
	}
	else {
		mtu = min_not_zero((unsigned int)skb_pagelen(skb), NETMAP_BUF_SIZE(na));
	}

	skb->protocol = htons(ETH_P_IPV6);
	skb_set_priv(skb, priv);

	if ((skb->len > mtu)||
			(skb_dst(skb) && dst_allfrag(skb_dst(skb))) ||
			(IP6CB(skb)->frag_max_size &&
					skb->len > IP6CB(skb)->frag_max_size)) {
		ip6_fragment(priv->net, NULL, skb, copy_pkt_to_queue);
		return NF_STOLEN;
	}
	else {
		if (copy_pkt_to_queue(NULL, NULL, skb) != 0) {
			rc = NF_DROP;
		}
		return rc;
	}
}

static int nmring_tg_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_nmring_info *info = (struct xt_nmring_info *)par->targinfo;
	if (!info->ifc_pipe || info->ifc_pipe[0] == '\0') {
		pr_err("Invalid pipe name\n");
		return -EINVAL;
	}
	if (par->hook_mask == (1 << NF_INET_PRE_ROUTING)) {
		return create_ifc_pipe(info, par->net, NF_INET_PRE_ROUTING);
	}
	else if (par->hook_mask == (1 << NF_INET_LOCAL_OUT)) {
		return create_ifc_pipe(info, par->net, NF_INET_LOCAL_OUT);
	}
	else if (par->hook_mask == 0){
		return create_ifc_pipe(info, par->net, NF_INET_NUMHOOKS);
	}
	pr_err("%s: pipe can only be assigned to PREROUTING or OUTPUT\n", info->ifc_pipe);
	return -EINVAL;
}

static void
ipt_netmap_release_ring (struct ipt_netmap_priv *priv)
{
	bool freed = false;
	struct netmap_adapter *na;
	struct netmap_kring *kring;

	NMG_LOCK();
	if (priv) {
		if (priv->netmap_priv->np_refs == 1) {
			nm_prdis("Destroy pipe %s hooknum:0x%x\n", info->ifc_pipe, priv->hooknum);
			na = priv->netmap_priv->np_na;
			kring = na->tx_rings[priv->netmap_priv->np_qfirst[NR_TX]];
			mbq_safe_purge(&kring->pipe->rx_queue);
			freed = true;
		}
		else {
			nm_prdis("Decrement pipe %s hooknum:0x%x\n", info->ifc_pipe, priv->hooknum);
		}
		netmap_priv_delete(priv->netmap_priv);
		if (freed) {
			list_del(&priv->list);
			free_percpu(priv->percpu_recursion);
			kfree(priv);
		}
	}
	NMG_UNLOCK();
}

static void nmring_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_nmring_info *info = par->targinfo;
	struct ipt_netmap_priv *priv = find_ifc_pipe(info->ifc_pipe);

	ipt_netmap_release_ring (priv);
}

static struct xt_target nmring_tg_reg[] __read_mostly = {
	{
	 .name = "NMRING",
	 .family = NFPROTO_IPV6,
	 .revision = 0,
	 .target = nmring_tg6,
	 .targetsize = sizeof(struct xt_nmring_info),
	 .hooks = (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_PRE_ROUTING),
	 .checkentry = nmring_tg_checkentry,
	 .destroy = nmring_tg_destroy,
	 .me = THIS_MODULE,
	 },
	{
	 .name = "NMRING",
	 .family = NFPROTO_IPV4,
	 .revision = 0,
	 .target = nmring_tg4,
	 .targetsize = sizeof(struct xt_nmring_info),
	 .hooks = (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_PRE_ROUTING),
	 .checkentry = nmring_tg_checkentry,
	 .destroy = nmring_tg_destroy,
	 .me = THIS_MODULE,
	 },
};

static void __net_exit ipt_netmap_net_exit(struct net *net)
{
#ifdef CONFIG_NET_NS
	struct list_head *node, *next;
	struct ipt_netmap_priv *entry = NULL;

	list_for_each_safe(node, next, &ipt_netmap_pipes.list) {
		entry = list_entry(node, struct ipt_netmap_priv, list);
		if (entry->net == net) {
			ipt_netmap_release_ring (entry);
		}
	}
#endif
	return NULL;
}

static struct pernet_operations ipt_netmap_net_ops = {
	.pre_exit	= ipt_netmap_net_exit,
	.id	= &ipt_netmap_net_id,
	.size	= 0,
};

static int __init nmring_tg_init(void)
{
	INIT_LIST_HEAD(&ipt_netmap_pipes.list);
	register_pernet_subsys(&ipt_netmap_net_ops);
	return xt_register_targets(nmring_tg_reg, ARRAY_SIZE(nmring_tg_reg));
}

static void __exit nmring_tg_exit(void)
{
	unregister_pernet_subsys(&ipt_netmap_net_ops);
	xt_unregister_targets(nmring_tg_reg, ARRAY_SIZE(nmring_tg_reg));
}

module_init(nmring_tg_init);
module_exit(nmring_tg_exit);
