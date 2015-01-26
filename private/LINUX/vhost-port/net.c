/* Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * Based on the vhost/vhost-net work.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * e1000-paravirt server in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/virtio_net.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/cdev.h>

#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>

#include <net/sock.h>

#include "paravirt.h"
#include "v1000.h"


//#define DEBUG  /* Enables communication debugging. */
#ifdef DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

//#define RATE  /* Enables communication statistics. */
#ifdef RATE
#define IFRATE(x) x
struct rate_stats {
    unsigned long gtxk;     /* Guest --> Host Tx kicks. */
    unsigned long grxk;     /* Guest --> Host Rx kicks. */
    unsigned long htxk;     /* Host --> Guest Tx kicks. */
    unsigned long hrxk;     /* Host --> Guest Rx Kicks. */
    unsigned long btxwu;    /* Backend Tx wake-up. */
    unsigned long brxwu;    /* Backend Rx wake-up. */
    unsigned long txpkts;   /* Transmitted packets. */
    unsigned long rxpkts;   /* Received packets. */
    unsigned long txfl;     /* TX flushes requests. */
};

struct rate_context {
    struct timer_list timer;
    struct rate_stats new;
    struct rate_stats old;
};

#define RATE_PERIOD  2
static void rate_callback(unsigned long arg)
{
    struct rate_context * ctx = (struct rate_context *)arg;
    struct rate_stats cur = ctx->new;
    int r;

    printk("txp  = %lu Hz\n", (cur.txpkts - ctx->old.txpkts)/RATE_PERIOD);
    printk("gtxk = %lu Hz\n", (cur.gtxk - ctx->old.gtxk)/RATE_PERIOD);
    printk("htxk = %lu Hz\n", (cur.htxk - ctx->old.htxk)/RATE_PERIOD);
    printk("btxw = %lu Hz\n", (cur.btxwu - ctx->old.btxwu)/RATE_PERIOD);
    printk("rxp  = %lu Hz\n", (cur.rxpkts - ctx->old.rxpkts)/RATE_PERIOD);
    printk("grxk = %lu Hz\n", (cur.grxk - ctx->old.grxk)/RATE_PERIOD);
    printk("hrxk = %lu Hz\n", (cur.hrxk - ctx->old.hrxk)/RATE_PERIOD);
    printk("brxw = %lu Hz\n", (cur.brxwu - ctx->old.brxwu)/RATE_PERIOD);
    printk("txfl = %lu Hz\n", (cur.txfl - ctx->old.txfl)/RATE_PERIOD);
    printk("\n");

    ctx->old = cur;
    r = mod_timer(&ctx->timer, jiffies +
                                msecs_to_jiffies(RATE_PERIOD * 1000));
    if (unlikely(r))
        printk("[v1000] Error: mod_timer()\n");
}
#else
#define IFRATE(x)
#endif


struct e1000_tx_context {
    bool vlan_needed;
    uint8_t ipcss;
    uint8_t ipcso;
    uint16_t ipcse;
    uint32_t paylen;
    bool tcp;
};

struct e1000_state {
    uint32_t tdt;
    uint32_t tdh;
    uint32_t rdt;
    uint32_t rdh;
    struct e1000_tx_context txc;
    uint32_t txnum;	/* Number of TX descriptors. */
    uint32_t rxnum;	/* Number of RX descriptors. */
};

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define V1000_NET_WEIGHT 0x80000

/* A set of callbacks through wich the v1000 frontend interacts
   with a backend (socket or netmap). */
struct v1000_backend {
    /* Get the file struct attached to the backend. */
    struct file *(*get_file)(void *opaque);
    /* Send a packet to the backend. */
    int (*sendmsg)(void *opaque, struct msghdr *msg, size_t iovlen, unsigned flags);
    /* Get the length of the next rx buffer ready into the backend. */
    int (*peek_head_len)(void *opaque);
    /* Receive a packet from the backend. */
    int (*recvmsg)(void *opaque, struct msghdr *msg, size_t len);
};

struct v1000_net {
    struct v1000_dev dev;
    struct v1000_ring tx_ring, rx_ring;
    struct v1000_poll tx_poll, rx_poll;

    struct V1000Config config;
    bool configured;
    struct e1000_tx_desc __user * tx_desc;
    struct e1000_rx_desc __user * rx_desc;
    struct paravirt_csb __user * csb;
    struct virtio_net_hdr __user * tx_hdr;
    struct virtio_net_hdr __user * rx_hdr;
    struct e1000_state state;
    bool broken;
    struct v1000_backend backend;
    IFRATE(struct rate_context rate_ctx);
};

/* #################### SOCKET BACKEND CALLBACKS ################### */
static struct file *socket_backend_get_file(void *opaque)
{
    struct socket *sock = (struct socket *)opaque;

    return sock->file;
}

static int socket_backend_sendmsg(void *opaque, struct msghdr *msg,
                                   size_t iovlen, unsigned flags)
{
    struct socket *sock = (struct socket *)opaque;

    return sock->ops->sendmsg(NULL, sock, msg, iovlen);
}

static int socket_backend_peek_head_len(void *opaque)
{
    struct socket *sock = (struct socket *)opaque;
    struct sock *sk = sock->sk;
    struct sk_buff *head;
    int len = 0;
    unsigned long flags;

    spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
    head = skb_peek(&sk->sk_receive_queue);
    if (likely(head)) {
	len = head->len;
	if (vlan_tx_tag_present(head))
	    len += VLAN_HLEN;
    }

    spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
    return len;
}

static int socket_backend_recvmsg(void *opaque, struct msghdr *msg,
                                  size_t len)
{
    struct socket *sock = (struct socket *)opaque;

    return sock->ops->recvmsg(NULL, sock, msg, len,
                              MSG_DONTWAIT | MSG_TRUNC);
}

#ifdef DEBUG
/* Print the translation table. */
static void print_translations(struct v1000_net * net)
{
    struct V1000Translation * tr = &net->config.tr;
    int i;

    printk("Translation table.%p: (#%u)\n", net, tr->num);
    for (i=0; i<tr->num; i++) {
	printk("    idx=%d, pa=%llu, l=%llu, va=%p\n", i,
			tr->table[i].phy,
			tr->table[i].length,
			tr->table[i].virt);
    }
    printk("\n");
}
#endif

static void * lookup_translation(struct v1000_net * net, uint64_t address, uint64_t length)
{
    struct V1000Translation * tr = &net->config.tr;
    int i;

    for (i=0; i<tr->num; i++) {
        /*    printk("(%llu,%llu) against (%llu,%llu,%p)\n", address, length,
                tr->table[i].phy, tr->table[i].length, tr->table[i].virt); */
	if (address >= tr->table[i].phy && address + length <=
		tr->table[i].phy + tr->table[i].length) {
	    /* The requested address range is completely included
	       in this traslated memory chunk. We have a (complete)
	       hit. */
	    return (void *)(((uint64_t)tr->table[i].virt + address) - tr->table[i].phy);
	}
    }

    return NULL;
}

#define CSB_READ(csb, field, r) \
    do { \
	if (get_user(r, &csb->field)) { \
	    r = -EFAULT; \
	} \
    } while (0)

#define CSB_WRITE(csb, field, v) \
    do { \
	if (put_user(v, &csb->field)) { \
	    v = -EFAULT; \
	} \
    } while (0)

static inline void v1000_set_txkick(struct v1000_net *net, bool enable)
{
    uint32_t v = enable ? 1 : 0;

    CSB_WRITE(net->csb, host_need_txkick, v);
}

static inline bool v1000_tx_interrupts_enabled(struct v1000_net * net)
{
    uint32_t v;

    CSB_READ(net->csb, guest_need_txkick, v);

    return v;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_tx(struct v1000_net *net)
{
    struct v1000_ring *vr = &net->tx_ring;
    struct msghdr msg = {
	.msg_name = NULL,
	.msg_namelen = 0,
	.msg_control = NULL,
	.msg_controllen = 0,
	.msg_iov = vr->iov,
	.msg_flags = MSG_DONTWAIT,
    };
    struct virtio_net_hdr hdr;
    size_t iovlen, total_len = 0;
    int err;
    void *opaque;
    struct e1000_state * st = &net->state;
    struct e1000_tx_desc desc;
    struct e1000_context_desc * ctxdp =
                                (struct e1000_context_desc *)&desc;
    void __user * va;
    unsigned iovcnt, wbcnt, i;
    bool work = false;
    uint16_t len;
    uint32_t desc_type;
    bool eop;
    uint32_t next_tdh;

    mutex_lock(&vr->mutex);
    opaque = vr->private_data;
    if (unlikely(!opaque || net->broken)) {
	printk("[v1000] Broken device\n");
	goto leave;
    }

    /* Disable notifications. */
    v1000_set_txkick(net, false);

    next_tdh = st->tdh + 1;
    if (unlikely(next_tdh == st->txnum)) {
        next_tdh = 0;
    }

    smp_mb();
    CSB_READ(net->csb, guest_tdt, st->tdt);
    if (unlikely(st->tdt >= st->txnum)) {
        net->broken = true;
        goto leave;
    }
    for (;;) {
	/* Nothing new?  Wait for eventfd to tell us they refilled. */
	if (st->tdt == st->tdh) {
	    /* Reenable notifications. */
	    v1000_set_txkick(net, true);
	    /* Doublecheck. */
	    smp_mb();
	    CSB_READ(net->csb, guest_tdt, st->tdt);
            if (unlikely(st->tdt >= st->txnum)) {
                net->broken = true;
                goto leave;
            }
	    if (unlikely(st->tdt != st->tdh)) {
		v1000_set_txkick(net, false);
		continue;
	    }
	    break;
	}

	/* Use the first iovec slot for the virtio-net header. */
	vr->iov[0].iov_base = net->tx_hdr + st->tdh;
	vr->iov[0].iov_len = sizeof(struct virtio_net_hdr);
        memset(&hdr, 0, sizeof(struct virtio_net_hdr));
#if VIRTIO_NET_HDR_GSO_NONE
        hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
#endif
	/* TODO refer to a global zero (null) vnet-hdr to avoid the
	   copy_to_user when the header is zero. */

	/* Collect the TX descriptors. */
	iovcnt = 1;
	wbcnt = 0;
        eop = false;
	do {
	    if (unlikely(st->tdh == st->tdt)) {
		printk("[v1000] Broken TX descriptor chain: expected EOP\n");
		break;
	    }

	    /* Read a descriptor. */
	    if (unlikely(copy_from_user(&desc, net->tx_desc + st->tdh,
                            sizeof(struct e1000_tx_desc)))) {
		printk("copy_from_user(txdesc) FAILED!!!\n");
		net->broken = true;
		goto leave;
	    }

	    /* Process the descriptor. */
            if (desc.lower.data & E1000_TXD_CMD_RS) {
                /* Register a writeback operation. */
                vr->wb[wbcnt].addr = (uint8_t *)&net->tx_desc[st->tdh].upper.data;
                vr->wb[wbcnt].value = E1000_TXD_STAT_DD;
                wbcnt++;
            }
            desc_type = desc.lower.data & (E1000_TXD_CMD_DEXT
                            | E1000_TXD_DTYP_D);
            if (desc_type == E1000_TXD_CMD_DEXT) { /* Context descriptor. */
                if (unlikely(iovcnt != 1)) {
                    printk("[v1000] Warning: TX context descriptor in the"
                            "middle of a packet. Discarding %d data"
                            "descriptors\n", iovcnt - 1);
                    eop = true;
                }
                st->txc.ipcss = ctxdp->lower_setup.ip_fields.ipcss;
                st->txc.ipcso = ctxdp->lower_setup.ip_fields.ipcso;
                st->txc.ipcse = ctxdp->lower_setup.ip_fields.ipcse;
                st->txc.paylen = ctxdp->cmd_and_length & 0xfffff;
                st->txc.tcp = ((ctxdp->cmd_and_length &
                                E1000_TXD_CMD_TCP) != 0);

                if ((ctxdp->cmd_and_length & E1000_TXD_CMD_TSE)) {
                    hdr.gso_type = (ctxdp->cmd_and_length &
                            E1000_TXD_CMD_IP) ? VIRTIO_NET_HDR_GSO_TCPV4:
                        VIRTIO_NET_HDR_GSO_TCPV6;
                    hdr.gso_size = ctxdp->tcp_seg_setup.fields.mss;
                    hdr.hdr_len = ctxdp->tcp_seg_setup.fields.hdr_len;
                }

                hdr.csum_start = ctxdp->upper_setup.tcp_fields.tucss;
                hdr.csum_offset = ctxdp->upper_setup.tcp_fields.tucso - ctxdp->upper_setup.tcp_fields.tucss;
                if (unlikely(ctxdp->upper_setup.tcp_fields.tucse)) {
                    printk("[v1000] Warning: Checksum on partial payload\n");
                }
            } else { /* Data descriptor. */
                if (desc_type == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
                    /* Extended descriptor. */
                    if (iovcnt == 1) {
                        if (desc.upper.data & (E1000_TXD_POPTS_TXSM << 8))
                            hdr.flags |= VIRTIO_NET_HDR_F_NEEDS_CSUM;
                        /* Don't check for IP checksumming, it's already computed
                           by the guest kernel.
                        if (desc.upper.data & (E1000_TXD_POPTS_IXSM << 8)) {
                        } */
                    }
                    if (unlikely(hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE &&
                            !(desc.lower.data & E1000_TXD_CMD_TSE))) {
                        printk("[v1000] TCP segmentation error\n");
                        goto next;
                    }
                } else {
                    /* Legacy descriptor. */
                }

                len = desc.lower.data & 0xffff;
                va = lookup_translation(net, desc.buffer_addr, len);
                if (unlikely(!va)) {
                    printk("Address translation FAILED: tdh=%u, phy=%llu, len=%u\n", st->tdh, desc.buffer_addr, len);
                    net->broken = true;
                    goto leave;
                }
                DBG(printk("tx: phy=%llu,len=%u,virt=%p,TDH=%u,TDT=%u\n", desc.buffer_addr, len, va, st->tdh, st->tdt));
                vr->iov[iovcnt].iov_base = va;
                vr->iov[iovcnt].iov_len = len;
                iovcnt++;

                if (desc.lower.data & E1000_TXD_CMD_EOP) {
                    eop = true;
                    /* Insert virtio-net header. */
                    DBG(printk("hdr: flags=%X, cs=%u, co=%u, gso_t=%u, gso_s=%u, hlen=%u\n", hdr.flags, hdr.csum_start, hdr.csum_offset, hdr.gso_type, hdr.gso_size, hdr.hdr_len));
                    if (unlikely(copy_to_user(vr->iov->iov_base, &hdr, sizeof(hdr)))) {
                        printk("copy_to_user(vnet_hdr)\n");
                        net->broken = true;
                        break;
                    }

                    /* Reset the TX context. */
                    st->txc.vlan_needed = 0;

                    /* Once we have collected all the frame fragments,
                       we can send it through the backend. */
                    msg.msg_iovlen = iovcnt;
                    /* TODO compute iovlen during the cycle */
                    iovlen = iov_length(vr->iov, iovcnt);
                    err = net->backend.sendmsg(opaque, &msg, iovlen,
                                st->tdt == next_tdh ? 0 : MSG_MORE);
                    IFRATE(if (st->tdt == next_tdh) net->rate_ctx.new.txfl++);
                    if (unlikely(err < 0)) {
                        printk("sendmsg() err!!\n");
                        goto leave; // XXX
                    }
                    if (unlikely(err != iovlen))
                        pr_debug("Truncated TX packet\n");
                    total_len += iovlen;
                    IFRATE(net->rate_ctx.new.txpkts++);

                    smp_wmb();
                    for (i=0; i<wbcnt; i++) {
                        /* Writeback the used TX descriptor. */
                        if (unlikely(put_user(vr->wb[i].value,
                                        vr->wb[i].addr))) {
                            printk("copy_to_user(tx writeback)\n");
                            net->broken = true;
                            goto leave;
                        }
                    }
                    work = true;
                }
            }

next:
            st->tdh = next_tdh;
	    if (unlikely(++next_tdh == st->txnum))
		next_tdh = 0;
	} while (!eop);

	if (unlikely(total_len >= V1000_NET_WEIGHT)) {
	    v1000_poll_queue(&vr->poll);
	    break;
	}

	if (st->tdt == st->tdh) {
	    /* Reload 'tdt' only when necessary. */
	    smp_mb();
	    CSB_READ(net->csb, guest_tdt, st->tdt);
            if (unlikely(st->tdt >= st->txnum)) {
                net->broken = true;
                goto leave;
            }
	}
    }

leave:
    if (work && v1000_tx_interrupts_enabled(net)) {
	eventfd_signal(vr->call_ctx, 1);
        IFRATE(net->rate_ctx.new.htxk++);
    }
    mutex_unlock(&vr->mutex);

    return;
}

static inline uint32_t v1000_avail_rx(struct v1000_net * net)
{
    return ((net->state.rxnum  + net->state.rdt) - net->state.rdh) % net->state.rxnum;
}

static uint32_t v1000_avail_rx_bytes(struct v1000_net * net)
{
    return v1000_avail_rx(net) * net->config.rxbuf_size;
}

static inline void v1000_set_rxkick(struct v1000_net *net, bool enable)
{
    uint32_t v;

    if (enable) {
	v = (net->state.rdt + 1 + (net->state.rxnum - v1000_avail_rx(net) - 1) * 3/4) % net->state.rxnum;
    } else
	v = NET_PARAVIRT_NONE;
    CSB_WRITE(net->csb, host_rxkick_at, v);
}

static inline bool v1000_rx_interrupts_enabled(struct v1000_net * net)
{
    uint32_t v;

    CSB_READ(net->csb, guest_need_rxkick, v);

    return v;
}

#if 0
long lj = 0;
long cj;
int c = 0;
#endif

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_rx(struct v1000_net *net)
{
    struct v1000_ring *vr = &net->rx_ring;
    struct msghdr msg = {
	.msg_name = NULL,
	.msg_namelen = 0,
	.msg_control = NULL, /* FIXME: get and handle RX aux data. */
	.msg_controllen = 0,
	.msg_iov = vr->iov,
	.msg_flags = MSG_DONTWAIT,
    };
    size_t total_len = 0;
    int err;
    size_t sock_len;
    void *opaque;
    struct e1000_state * st = &net->state;
    struct e1000_rx_desc desc;
    void __user * va;
    uint32_t avail_bytes;
    unsigned fill;
    uint16_t wblen;
    uint32_t rdh;
    unsigned iovcnt, i;

    DBG(printk("handle_rx()\n"));

    mutex_lock(&vr->mutex);
    opaque = vr->private_data;
    if (unlikely(!opaque || net->broken)) {
	printk("[v1000] Broken device\n");
	goto leave;
    }

    /* XXX Disable notification only when NOT using host_rxkick_at. */
    v1000_set_rxkick(net, false);
    CSB_READ(net->csb, guest_rdt, st->rdt);

    while ((sock_len = net->backend.peek_head_len(opaque))) {
	fill = sock_len;
	sock_len += sizeof(struct virtio_net_hdr);
	avail_bytes = v1000_avail_rx_bytes(net);
	if (avail_bytes < sock_len) {
	    /* Reload rdt only when necessary. */
	    CSB_READ(net->csb, guest_rdt, st->rdt);
	    avail_bytes = v1000_avail_rx_bytes(net);
	    if (avail_bytes < sock_len) {
		/* If not enough space, reenable notifications. */
		v1000_set_rxkick(net, true);
		smp_mb();
		/* Doublecheck. */
		CSB_READ(net->csb, guest_rdt, st->rdt);
		avail_bytes = v1000_avail_rx_bytes(net);
		if (avail_bytes < sock_len)
		    break;
		v1000_set_rxkick(net, false);
	    }
	}

        rdh = st->rdh;
	/* The first slot of the iovec into which receive a new frame
	   will be used for the virtio-net header. */
	vr->iov[0].iov_base = net->rx_hdr + rdh;
	vr->iov[0].iov_len = sizeof(struct virtio_net_hdr);

	/* Use RX descriptors to fill the remainder of vr->iov. */
	iovcnt = 1;
	while (fill) {
	    /* Read the address into the descriptor. */
	    if (unlikely(get_user(desc.buffer_addr,
		    (uint64_t *)(net->rx_desc + rdh)))) {
		printk("copy_from_user(rxdesc) FAILED!!!\n");
		net->broken = true;
		goto leave;
	    }

	    /* Process the descriptor. */
	    va = lookup_translation(net, desc.buffer_addr,
				    net->config.rxbuf_size);
	    if (unlikely(!va)) {
		printk("Address translation FAILED: rdh=%u, phy=%llu, len=%u\n", rdh, desc.buffer_addr, net->config.rxbuf_size);
		net->broken = true;
		goto leave;
	    }
	    wblen = desc.length = net->config.rxbuf_size;
	    if (fill <= net->config.rxbuf_size) {
                /* Last fragment. */
		desc.length = fill;
                wblen = fill + 4;  /* FCS aka Ethernet CRC. */
            }

	    vr->iov[iovcnt].iov_base = va;
	    vr->iov[iovcnt].iov_len = desc.length;
	    vr->wb[iovcnt-1].addr = &net->rx_desc[rdh].status;
	    vr->wb[iovcnt-1].value = E1000_RXD_STAT_DD;
	    iovcnt++;

	    /* Length writeback. */
	    if (unlikely(put_user(wblen, &net->rx_desc[rdh].length))) {
		printk("copy_to_user(rx len writeback)\n");
		net->broken = true;
		goto leave;
	    }

	    if (unlikely(++rdh == st->rxnum))
		rdh = 0;
	    fill -= desc.length;
	}
	vr->wb[iovcnt-2].value |= E1000_RXD_STAT_EOP;
	msg.msg_iovlen = iovcnt;

        err = net->backend.recvmsg(opaque, &msg, sock_len);
	/* Userspace might have consumed the packet meanwhile:
	 * it's not supposed to do this usually, but might be hard
	 * to prevent. Discard data we got (if any) and keep going. */
	if (unlikely(err != sock_len)) {
	    printk("Discarded rx packet: "
		    " len %d, expected %zd\n", err, sock_len);
            /* Recover the RX descriptors. */
	    continue;
	}

	smp_mb();

	/* Descriptors writeback. */
	for (i=0; i<iovcnt-1; i++) {
	    /* Writeback the used RX descriptor. */
	    if (unlikely(put_user(vr->wb[i].value, vr->wb[i].addr))) {
		printk("copy_to_user(rx writeback)\n");
		net->broken = true;
		goto leave;
	    }
	}

        st->rdh = rdh;
        IFRATE(net->rate_ctx.new.rxpkts++);

	DBG(printk("received packet [len=%u,iovcnt=%u,rdh=%u,rdt=%u,avail=%u]\n", (unsigned)sock_len, iovcnt, st->rdh, st->rdt, avail_bytes));
#if 0
	if (++c == 100000) {
	    cj = jiffies;
	    if (cj != lj)
		printk("%lu pps\n", 300 * c / (cj - lj));
	    c = 0;
	    lj = jiffies;
	}
#endif

	total_len += sock_len;
	if (unlikely(total_len >= V1000_NET_WEIGHT)) {
	    v1000_poll_queue(&vr->poll);
	    break;
	}
    }

leave:
    if (v1000_rx_interrupts_enabled(net)) {
	eventfd_signal(vr->call_ctx, 1);
        IFRATE(net->rate_ctx.new.hrxk++);
    }
    mutex_unlock(&vr->mutex);
    DBG(printk("rxintr=%d\n", v1000_rx_interrupts_enabled(net)));
}

static void handle_tx_kick(struct v1000_work *work)
{
    struct v1000_ring *vr = container_of(work, struct v1000_ring,
	    poll.work);
    struct v1000_net *net = container_of(vr->dev, struct v1000_net, dev);

    IFRATE(net->rate_ctx.new.gtxk++);
    handle_tx(net);
}

static void handle_rx_kick(struct v1000_work *work)
{
    struct v1000_ring *vr = container_of(work, struct v1000_ring,
	    poll.work);
    struct v1000_net *net = container_of(vr->dev, struct v1000_net, dev);

    IFRATE(net->rate_ctx.new.grxk++);
    handle_rx(net);
}

static void handle_tx_net(struct v1000_work *work)
{
    struct v1000_net *net = container_of(work, struct v1000_net,
	    tx_poll.work);

    IFRATE(net->rate_ctx.new.btxwu++);
    handle_tx(net);
}

static void handle_rx_net(struct v1000_work *work)
{
    struct v1000_net *net = container_of(work, struct v1000_net,
	    rx_poll.work);

    IFRATE(net->rate_ctx.new.brxwu++);
    handle_rx(net);
}

static int v1000_open(struct inode *inode, struct file *f)
{
    struct v1000_net *n = kmalloc(sizeof *n, GFP_KERNEL);
    struct v1000_dev *dev;
    int r;

    printk("%p.OPEN()\n", n);
    if (!n)
	return -ENOMEM;
    n->configured = n->broken = false;
    memset(&n->state, 0, sizeof(struct e1000_state));

    dev = &n->dev;
    n->tx_ring.handle_kick = handle_tx_kick;
    n->rx_ring.handle_kick = handle_rx_kick;
    r = v1000_dev_init(dev, &n->tx_ring, &n->rx_ring);
    if (r < 0) {
	kfree(n);
	return r;
    }

    v1000_poll_init(&n->tx_poll, handle_tx_net, POLLOUT, dev);
    v1000_poll_init(&n->rx_poll, handle_rx_net, POLLIN, dev);

    f->private_data = n;

#ifdef RATE
    memset(&n->rate_ctx, 0, sizeof(n->rate_ctx));
    setup_timer(&n->rate_ctx.timer, &rate_callback,
                                (unsigned long)&n->rate_ctx);
    r = mod_timer(&n->rate_ctx.timer, jiffies + msecs_to_jiffies(1500));
    if (r)
        printk("[v1000] Error: mod_timer()\n");
#endif

    printk("%p.OPEN_END()\n", n);

    return 0;
}

static void v1000_net_disable_vr(struct v1000_net *n,
	struct v1000_ring *vr)
{
    if (!vr->private_data)
	return;
    if (vr == &n->tx_ring)
	v1000_poll_stop(&n->tx_poll);
    else
	v1000_poll_stop(&n->rx_poll);
}

static int v1000_net_enable_vr(struct v1000_net *n,
	struct v1000_ring *vr)
{
    void *opaque;
    int ret;

    opaque = vr->private_data;
    if (!opaque)
	return 0;
    if (vr == &n->tx_ring) {
	ret = v1000_poll_start(&n->tx_poll, n->backend.get_file(opaque));
    } else
	ret = v1000_poll_start(&n->rx_poll, n->backend.get_file(opaque));

    return ret;
}

static void *v1000_net_stop_vr(struct v1000_net *n,
	struct v1000_ring *vr)
{
    void *opaque;

    mutex_lock(&vr->mutex);
    opaque = vr->private_data;
    v1000_net_disable_vr(n, vr);
    vr->private_data = NULL;
    mutex_unlock(&vr->mutex);
    return opaque;
}

static void v1000_net_stop(struct v1000_net *n, void **tx_opaque,
	void **rx_opaque)
{
    *tx_opaque = v1000_net_stop_vr(n, &n->tx_ring);
    *rx_opaque = v1000_net_stop_vr(n, &n->rx_ring);
}

static void v1000_net_flush(struct v1000_net *n)
{
    v1000_poll_flush(&n->rx_poll);
    v1000_poll_flush(&n->dev.rx_ring->poll);
    v1000_poll_flush(&n->tx_poll);
    v1000_poll_flush(&n->dev.tx_ring->poll);
}

static int v1000_release(struct inode *inode, struct file *f)
{
    struct v1000_net *n = f->private_data;
    void *tx_opaque;
    void *rx_opaque;

    printk("%p.RELEASE()\n", n);
    v1000_net_stop(n, &tx_opaque, &rx_opaque);
    v1000_net_flush(n);
    v1000_dev_stop(&n->dev);
    v1000_dev_cleanup(&n->dev);
    if (tx_opaque)
	fput(n->backend.get_file(tx_opaque));
    if (rx_opaque)
	fput(n->backend.get_file(rx_opaque));
    /* We do an extra flush before freeing memory,
     * since jobs can re-queue themselves. */
    v1000_net_flush(n);

    IFRATE(del_timer(&n->rate_ctx.timer));
    kfree(n);
    printk("%p.RELEASE_END()\n", n);

    return 0;
}

static struct socket *get_raw_socket(int fd)
{
    struct {
	struct sockaddr_ll sa;
	char  buf[MAX_ADDR_LEN];
    } uaddr;
    int uaddr_len = sizeof uaddr, r;
    struct socket *sock = sockfd_lookup(fd, &r);

    if (!sock)
	return ERR_PTR(-ENOTSOCK);

    /* Parameter checking */
    if (sock->sk->sk_type != SOCK_RAW) {
	r = -ESOCKTNOSUPPORT;
	goto err;
    }

    r = sock->ops->getname(sock, (struct sockaddr *)&uaddr.sa,
	    &uaddr_len, 0);
    if (r)
	goto err;

    if (uaddr.sa.sll_family != AF_PACKET) {
	r = -EPFNOSUPPORT;
	goto err;
    }
    return sock;
err:
    fput(sock->file);
    return ERR_PTR(r);
}

static struct socket *get_tap_socket(int fd)
{
    struct file *file = fget(fd);
    struct socket *sock;

    if (!file)
	return ERR_PTR(-EBADF);
    sock = tun_get_socket(file);
    if (!IS_ERR(sock))
	return sock;
    sock = macvtap_get_socket(file);
    if (IS_ERR(sock))
	fput(file);
    return sock;
}

struct socket *get_netmap_socket(int fd);
void *netmap_get_backend(int fd);
struct file *netmap_backend_get_file(void *opaque);
int netmap_backend_sendmsg(void *opaque, struct msghdr *m, size_t len,
                           unsigned flags);
int netmap_backend_peek_head_len(void *opaque);
int netmap_backend_recvmsg(void *opaque, struct msghdr *m, size_t len);

static struct socket *get_socket(int fd)
{
    struct socket *sock;

    /* special case to disable backend */
    if (fd == -1)
	return NULL;
    sock = get_raw_socket(fd);
    if (!IS_ERR(sock))
	return sock;
    sock = get_tap_socket(fd);
    if (!IS_ERR(sock))
	return sock;
    sock = get_netmap_socket(fd);
    if (!IS_ERR(sock))
	return sock;
    return ERR_PTR(-ENOTSOCK);
}

static void *get_backend(struct v1000_net *n, int fd)
{
    /* Probe for the netmap backend first. */
    void *ret = netmap_get_backend(fd);

    if (!IS_ERR(ret)) {
        /* Set the netmap backend ops. */
        n->backend.get_file = &netmap_backend_get_file;
        n->backend.sendmsg = &netmap_backend_sendmsg;
        n->backend.peek_head_len = &netmap_backend_peek_head_len;
        n->backend.recvmsg = &netmap_backend_recvmsg;
        printk("[v1000] netmap backend selected\n");
        return ret;
    }

    /* Probe for a socket backend. */
    ret = get_socket(fd);
    if (!IS_ERR(ret)) {
        /* Set the socket backend ops. */
        n->backend.get_file = &socket_backend_get_file;
        n->backend.sendmsg = &socket_backend_sendmsg;
        n->backend.peek_head_len = &socket_backend_peek_head_len;
        n->backend.recvmsg = &socket_backend_recvmsg;
        printk("[v1000] socket backend selected\n");
    } else {
        printk("[v1000] no backend found\n");
    }

    return ret;
}

static long v1000_net_set_backend(struct v1000_net *n, struct v1000_ring *vr, int fd)
{
    void *opaque;
    int r = 0;

    mutex_lock(&vr->mutex);

    opaque = get_backend(n, fd);
    if (IS_ERR(opaque)) {
	r = PTR_ERR(opaque);
	goto err_vr;
    }

    /* start polling new backend */
    //v1000_net_disable_vr(n, vr);
    vr->private_data = opaque;
    if (r)
	goto err_used;
    //r = v1000_net_enable_vr(n, vr);
    if (r)
	goto err_used;

    mutex_unlock(&vr->mutex);

    return 0;

err_used:
    v1000_net_enable_vr(n, vr);
    fput(n->backend.get_file(opaque));
err_vr:
    mutex_unlock(&vr->mutex);
    return r;
}

static ssize_t v1000_read(struct file* file_ptr, char __user * buffer,
					size_t n, loff_t * offset_ptr)
{
    n = 0;
    *offset_ptr += n;

    return n;
}

static int v1000_set_memory(struct v1000_net * net)
{
    struct V1000Translation *newmem, *oldmem;

    /* Use the new table to translate rings and csb memory. */
    if (!(net->tx_desc = lookup_translation(net, net->config.tx_ring.phy,
		net->config.tx_ring.num * sizeof(struct e1000_tx_desc))))
	return -EFAULT;
    if (!(net->rx_desc = lookup_translation(net, net->config.rx_ring.phy,
		net->config.rx_ring.num * sizeof(struct e1000_rx_desc))))
	return -EFAULT;
    net->tx_hdr = net->config.tx_ring.hdr.virt;
    net->rx_hdr = lookup_translation(net, net->config.rx_ring.hdr.phy,
		net->config.rx_ring.num * sizeof(struct virtio_net_hdr));
    if (!net->rx_hdr)
	return -EFAULT;
    if (!(net->csb = lookup_translation(net, net->config.csb_phy,
				    sizeof(struct paravirt_csb))))
	return -EFAULT;

   printk("[v1000] virtuals: tx=%p, rx=%p, tx_hdr=%p, rx_hdr=%p, csb=%p\n",
            net->tx_desc, net->rx_desc, net->tx_hdr, net->rx_hdr, net->csb);

    newmem = kmalloc(sizeof(struct V1000Translation), GFP_KERNEL);
    if (!newmem)
	return -ENOMEM;

    memcpy(newmem, &net->config.tr, sizeof(struct V1000Translation));

    oldmem = rcu_dereference_protected(net->dev.memory,
	    lockdep_is_held(&net->dev->mutex));
    rcu_assign_pointer(net->dev.memory, newmem);
    synchronize_rcu();
    kfree(oldmem);

    return 0;
}

static int v1000_set_eventfds_ring(struct v1000_ring * vr, struct V1000RingConfig * vrc)
{
    vr->kick = eventfd_fget(vrc->ioeventfd);
    if (IS_ERR(vr->kick))
	return PTR_ERR(vr->kick);

    vr->call = eventfd_fget(vrc->irqfd);
    if (IS_ERR(vr->call))
	return PTR_ERR(vr->call);
    vr->call_ctx = eventfd_ctx_fileget(vr->call);

    if (vrc->resamplefd != ~0U) {
        vr->resample = eventfd_fget(vrc->resamplefd);
        if (IS_ERR(vr->resample))
            return PTR_ERR(vr->resample);
        vr->resample_ctx = eventfd_ctx_fileget(vr->resample);
    } else {
        vr->resample = NULL;
        vr->resample_ctx = NULL;
    }

    return 0;
}

static int v1000_set_eventfds(struct v1000_net * net)
{
    int r;

    if ((r = v1000_set_eventfds_ring(&net->tx_ring, &net->config.tx_ring)))
	return r;
    if ((r = v1000_set_eventfds_ring(&net->rx_ring, &net->config.rx_ring)))
	return r;

    return 0;
}

static void v1000_print_configuration(struct v1000_net * net)
{
    int i;
    struct V1000Config * cfg = &net->config;

    printk("[v1000] configuration:\n");
    printk("TX: phy=%llu, num=%u, hdr.virt=%p, io=%u, irq=%u, resample=%u\n",
            cfg->tx_ring.phy, cfg->tx_ring.num,
            cfg->tx_ring.hdr.virt, cfg->tx_ring.ioeventfd,
            cfg->tx_ring.irqfd, cfg->tx_ring.resamplefd);
    printk("RX: phy=%llu, num=%u, hdr.phy=%llu, io=%u, irq=%u, resample=%u\n",
            cfg->rx_ring.phy, cfg->rx_ring.num,
            cfg->rx_ring.hdr.phy, cfg->rx_ring.ioeventfd,
	    cfg->rx_ring.irqfd, cfg->rx_ring.resamplefd);
    printk("rxbuf_size=%u, csb_phy=%llu, tapfd=%d\n",
            cfg->rxbuf_size, cfg->csb_phy, cfg->tapfd);
    for (i=0; i<net->config.tr.num; i++) {
	printk("    pa=%llu, len=%llu, va=%p\n", net->config.tr.table[i].phy,
	    net->config.tr.table[i].length, net->config.tr.table[i].virt);
    }
}

static int v1000_configure(struct v1000_net * net)
{
    int r;

    /* Configure. */
    if ((r = v1000_dev_set_owner(&net->dev)))
	    return r;
    if ((r = v1000_set_memory(net)))
	    return r;
    if ((r = v1000_set_eventfds(net)))
	return r;
    if ((r = v1000_net_set_backend(net, &net->rx_ring, net->config.tapfd)))
	return r;
    if ((r = v1000_net_set_backend(net, &net->tx_ring, net->config.tapfd)))
	return r;
    net->state.txnum = net->config.tx_ring.num;
    net->state.rxnum = net->config.rx_ring.num;

    v1000_print_configuration(net);

    /* Start polling. */
    if (net->tx_ring.handle_kick && (r = v1000_poll_start(&net->tx_ring.poll, net->tx_ring.kick)))
	return r;
    if (net->rx_ring.handle_kick && (r = v1000_poll_start(&net->rx_ring.poll, net->rx_ring.kick)))
	return r;
    if ((r = v1000_net_enable_vr(net, &net->tx_ring)))
	return r;
    if ((r = v1000_net_enable_vr(net, &net->rx_ring)))
	return r;

    return 0;
}

static int v1000_access_ok(struct v1000_net * net)
{
    struct V1000Translation * tr = &net->config.tr;
    int i;

    for (i=0; i<tr->num; i++) {
        if (!access_ok(VERIFY_WRITE, tr->table[i].virt, tr->table[i].length))
            return -1;
    }

    return !(access_ok(VERIFY_WRITE, net->tx_desc,
                    net->config.tx_ring.num * sizeof(struct e1000_tx_desc))
        && access_ok(VERIFY_WRITE, net->rx_desc,
                    net->config.rx_ring.num * sizeof(struct e1000_rx_desc))
        && access_ok(VERIFY_READ, net->tx_hdr,
                    net->config.tx_ring.num * sizeof(struct virtio_net_hdr))
        && access_ok(VERIFY_WRITE, net->rx_hdr,
                    net->config.rx_ring.num * sizeof(struct virtio_net_hdr))
        && access_ok(VERIFY_WRITE, net->csb, sizeof(struct paravirt_csb))
            );
}

static ssize_t v1000_write(struct file * file_ptr, const char __user * buffer, size_t n, loff_t * offset_ptr)
{
    struct v1000_net * net = (struct v1000_net *)file_ptr->private_data;
    int res;

    /* TODO if n->configured?? */

    mutex_lock(&net->dev.mutex);

    if (n != sizeof(struct V1000Config)) {
	n = -EINVAL;
	goto leave;
    }

    /* Read the configuration from userspace. */
    if (copy_from_user(&net->config, buffer, sizeof(struct V1000Config))) {
	printk(KERN_ALERT "v1000_first_write(): copy_from_user()\n");
	n = -EFAULT;
	goto leave;
    }

    //printk("[v1000] configuration read\n");
    if ((res = v1000_configure(net))) {
	n = res;
	goto leave;
    }

    if ((res = v1000_access_ok(net))) {
        n = res;
        goto leave;
    }
    //printk("[v1000] configuration OK\n");
    net->configured = true;

    *offset_ptr += n;

leave:
    mutex_unlock(&net->dev.mutex);

    return n;
}

static const struct file_operations v1000_fops = {
    .owner          = THIS_MODULE,
    .release        = v1000_release,
    .open           = v1000_open,
    .write	    = v1000_write,
    .read	    = v1000_read,
    .llseek	    = noop_llseek,
};


/* Device number associated to the v1000 char device. */
static dev_t device_number;
static struct cdev v1000_cdev;
static struct class *cl;

static int __init v1000_init(void)
{
    int ret;

    printk(KERN_ALERT "[v1000] Module loaded\n");

    /* Dynamic allocation of a device number */
    if ((ret = alloc_chrdev_region(&device_number, 0, 1, "v1000")) < 0) {
	printk(KERN_ALERT "alloc_chrdev_region() failed");
	goto exit_after_error;
    }
    printk(KERN_INFO "[v1000] Device number allocated = (%d,%d)\n", MAJOR(device_number), MINOR(device_number));
    if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL) {
	printk(KERN_ALERT "class_create() failed");
	unregister_chrdev_region(device_number, 1);
	goto exit_after_error;
    }
    if (device_create(cl, NULL, device_number, NULL, "v1000") == NULL) {
	printk(KERN_ALERT "device_create() failed");
	class_destroy(cl);
	unregister_chrdev_region(device_number, 1);
	goto exit_after_error;
    }

    /* Registering a char device into the kernel */
    cdev_init(&(v1000_cdev), &v1000_fops);
    v1000_cdev.owner = THIS_MODULE;
    v1000_cdev.ops = &v1000_fops;
    if ((ret = cdev_add(&v1000_cdev, device_number, 1))) {
    	device_destroy(cl, device_number);
	class_destroy(cl);
	unregister_chrdev_region(device_number, 1);
	printk(KERN_ALERT "cdev_add() failed[%d]!\n", ret);
	goto exit_after_error;
    }
    printk(KERN_INFO "[v1000] Char device added into the kernel\n");

    return 0;

exit_after_error:
    printk(KERN_ALERT "[v1000] Module loading failed!\n" );
    return ret;
}

static void v1000_exit(void) // __exit
{
    cdev_del(&v1000_cdev);
    device_destroy(cl, device_number);
    class_destroy(cl);
    unregister_chrdev_region(device_number, 1);
    printk(KERN_INFO "[v1000] module unloaded\n");
}

module_init(v1000_init);
module_exit(v1000_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Vincenzo Maffione");
MODULE_DESCRIPTION("Host kernel accelerator for e1000-paravirt");
//MODULE_ALIAS_MISCDEV(VHOST_NET_MINOR);
MODULE_ALIAS("devname:v1000");
