/*
 * Netmap passthrough interface driver for Linux
 * Copyright(c) 2015 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>

#define WITH_PTNETMAP_GUEST
#include "../bsd_glue.h"
#include "net/netmap.h"
#include "dev/netmap/netmap_kern.h"
#include "dev/netmap/netmap_virt.h"


#define DRV_NAME "ptnet"
#define DRV_VERSION "0.1"

struct ptnet_info {
	struct net_device *netdev;
	struct pci_dev *pdev;

	uint32_t ptfeatures;

	int bars;
	u8* __iomem ioaddr;
	u8* __iomem csbaddr;
	volatile struct paravirt_csb *csb;

	struct napi_struct napi;
};

/*
 * ptnet_irq_disable - Mask off interrupt generation on the NIC
 * @pi: NIC private structure
 */
static void
ptnet_irq_disable(struct ptnet_info *pi)
{
	synchronize_irq(pi->pdev->irq);
}

/*
 * ptnet_irq_enable - Enable default interrupt generation settings
 * @pi: NIC private structure
 */
static void
ptnet_irq_enable(struct ptnet_info *pi)
{
}

static netdev_tx_t
ptnet_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/*
 * ptnet_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 */
static struct net_device_stats *
ptnet_get_stats(struct net_device *netdev)
{
	return &netdev->stats;
}

/*
 * ptnet_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int
ptnet_change_mtu(struct net_device *netdev, int new_mtu)
{
	pr_info("%s changing MTU from %d to %d\n",
		netdev->name, netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	return 0;
}

/*
 * ptnet_intr - Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 */
static irqreturn_t
ptnet_intr(int irq, void *data)
{
	struct net_device *netdev = data;
	struct ptnet_info *pi = netdev_priv(netdev);

	if (likely(napi_schedule_prep(&pi->napi))) {
		__napi_schedule(&pi->napi);
	} else {
		/* This should not happen, probably. */
		ptnet_irq_enable(pi);
	}

	return IRQ_HANDLED;
}

/*
 * ptnet_clean - NAPI Rx polling callback
 * @pi: NIC private structure
 */
static int
ptnet_clean(struct napi_struct *napi, int budget)
{
	struct ptnet_info *pi = container_of(napi, struct ptnet_info,
						     napi);
	int work_done = 0;

	/* Clean TX. */
	pi->netdev->stats.tx_bytes += 0;
	pi->netdev->stats.tx_packets += 0;

	/* Clean RX. */
	pi->netdev->stats.rx_bytes += 0;
	pi->netdev->stats.rx_packets += 0;

	/* If budget not fully consumed, exit the polling mode */
	if (work_done < budget) {
		napi_complete(napi);
		ptnet_irq_enable(pi);
	}

	return work_done;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/* Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void
ptnet_netpoll(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);

	disable_irq(pi->pdev->irq);
	ptnet_intr(pi->pdev->irq, netdev);
	enable_irq(pi->pdev->irq);
}
#endif

static int
ptnet_request_irq(struct ptnet_info *pi)
{
	struct net_device *netdev = pi->netdev;
	irq_handler_t handler = ptnet_intr;
	int irq_flags = IRQF_SHARED;
	int err;

	err = request_irq(pi->pdev->irq, handler, irq_flags, netdev->name,
	                  netdev);
	if (err) {
		pr_err( "Unable to allocate interrupt Error: %d\n", err);
	}

	return err;
}

static void
ptnet_free_irq(struct ptnet_info *pi)
{
	struct net_device *netdev = pi->netdev;

	free_irq(pi->pdev->irq, netdev);
}

static void
ptnet_ioregs_dump(struct ptnet_info *pi)
{
	char *regnames[PTNET_IO_END >> 2] = {
		"PTFEAT",
		"PTCTL",
		"PTSTS",
		"TXKICK",
		"RXKICK",
	}; // remove this ; to drive the compiler crazy !
	uint32_t val;
	int i;

	for (i=0; i<PTNET_IO_END; i+=4) {
		val = ioread32(pi->ioaddr + i);
		pr_info("PTNET_IO_%s = %u\n", regnames[i >> 2], val);
	}
}

/*
 * ptnet_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog task is started,
 * and the stack is notified that the interface is ready.
 */
static int
ptnet_open(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	int err;

	netif_carrier_off(netdev);

	err = ptnet_request_irq(pi);
	if (err) {
		return err;
	}

	napi_enable(&pi->napi);
	ptnet_irq_enable(pi);
	netif_start_queue(netdev);

	pr_info("%s: %p\n", __func__, pi);

	ptnet_ioregs_dump(pi);

	pi->csb->guest_csb_on = 1;

	return 0;
}

/*
 * ptnet_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 */
static int
ptnet_close(struct net_device *netdev)
{
	struct ptnet_info *pi = netdev_priv(netdev);

	pi->csb->guest_csb_on = 0;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	napi_disable(&pi->napi);
	ptnet_irq_disable(pi);
	ptnet_free_irq(pi);

	pr_info("%s: %p\n", __func__, pi);

	return 0;
}

static const struct net_device_ops ptnet_netdev_ops = {
	.ndo_open		= ptnet_open,
	.ndo_stop		= ptnet_close,
	.ndo_start_xmit		= ptnet_xmit_frame,
	.ndo_get_stats		= ptnet_get_stats,
	.ndo_change_mtu		= ptnet_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= ptnet_netpoll,
#endif
};

static uint32_t
ptnet_nm_ptctl(struct net_device *netdev, uint32_t cmd)
{
	struct ptnet_info *pi = netdev_priv(netdev);
	int ret;

	iowrite32(cmd, pi->ioaddr + PTNET_IO_PTCTL);
	ret = ioread32(pi->ioaddr + PTNET_IO_PTSTS);
	pr_info("PTCTL %u, ret %u\n", cmd, ret);

	return ret;
}

static struct netmap_pt_guest_ops ptnet_nm_pt_guest_ops = {
	.nm_ptctl = ptnet_nm_ptctl,
};

static int
ptnet_nm_register(struct netmap_adapter *na, int onoff)
{
	struct netmap_pt_guest_adapter *ptna =
			(struct netmap_pt_guest_adapter *)na;

	/* device-specific */
	struct net_device *netdev = na->ifp;
	struct paravirt_csb *csb = ptna->csb;
	bool was_up = false;
	enum txrx t;
	int ret = 0;
	int i;

	if (na->active_fds > 0) {
		/* Nothing to do. */
		return 0;
	}

	if (netif_running(netdev)) {
		was_up = true;
		ptnet_close(netdev);
	}

	if (onoff) {
		ret = ptnet_nm_ptctl(netdev, NET_PARAVIRT_PTCTL_REGIF);
		if (ret) {
			goto out;
		}

		for_rx_tx(t) {
			for (i=0; i<nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = &NMR(na, t)[i];
				struct pt_ring *ptring;

				if (!nm_kring_pending_on(kring)) {
					continue;
				}

				ptring = (t == NR_TX ? &csb->tx_ring : &csb->rx_ring);
				kring->rhead = kring->ring->head = ptring->head;
				kring->rcur = kring->ring->cur = ptring->cur;
				kring->nr_hwcur = ptring->hwcur;
				kring->nr_hwtail = kring->rtail =
					kring->ring->tail = ptring->hwtail;
				kring->nr_mode = NKR_NETMAP_ON;
			}
		}

		if (1) {
			nm_set_native_flags(na);
		} else {
			na->na_flags |= NAF_NETMAP_ON;
		}
	} else {
		if (1) {
			nm_clear_native_flags(na);
		} else {
			na->na_flags &= NAF_NETMAP_ON;
		}

		for_rx_tx(t) {
			for (i=0; i<nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = &NMR(na, t)[i];

				if (!nm_kring_pending_off(kring)) {
					continue;
				}

				kring->nr_mode = NKR_NETMAP_OFF;
			}
		}

		ret = ptnet_nm_ptctl(netdev, NET_PARAVIRT_PTCTL_UNREGIF);
	}
out:
	if (was_up) {
		ptnet_open(netdev);
	}

	return ret;
}

static int
ptnet_nm_config(struct netmap_adapter *na, unsigned *txr, unsigned *txd,
		unsigned *rxr, unsigned *rxd)
{
	struct netmap_pt_guest_adapter *ptna =
		(struct netmap_pt_guest_adapter *)na;
	int ret;

	if (ptna->csb == NULL) {
		pr_err("%s: NULL CSB pointer\n", __func__);
		return EINVAL;
	}

	ret = ptnet_nm_ptctl(na->ifp, NET_PARAVIRT_PTCTL_CONFIG);
	if (ret) {
		return ret;
	}

	*txr = ptna->csb->num_tx_rings;
	*rxr = ptna->csb->num_rx_rings;
#if 1
	*txr = 1;
	*rxr = 1;
#endif
	*txd = ptna->csb->num_tx_slots;
	*rxd = ptna->csb->num_rx_slots;

	pr_info("txr %u, rxr %u, txd %u, rxd %u\n",
		*txr, *rxr, *txd, *rxd);

	return 0;
}

static int
ptnet_nm_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct net_device *netdev = na->ifp;
	struct ptnet_info *pi = netdev_priv(netdev);
	bool notify;

	notify = netmap_pt_guest_txsync(kring, flags);
	if (notify) {
		iowrite32(0, pi->ioaddr + PTNET_IO_TXKICK);
	}

	return 0;
}

static int
ptnet_nm_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct net_device *netdev = na->ifp;
	struct ptnet_info *pi = netdev_priv(netdev);
	bool notify;

	notify = netmap_pt_guest_rxsync(kring, flags);
	if (notify) {
		iowrite32(0, pi->ioaddr + PTNET_IO_RXKICK);
	}

	return 0;
}

static struct netmap_adapter ptnet_nm_ops = {
	.num_tx_desc = 1024,
	.num_rx_desc = 1024,
	.num_tx_rings = 1,
	.num_rx_rings = 1,
	.nm_register = ptnet_nm_register,
	.nm_config = ptnet_nm_config,
	.nm_txsync = ptnet_nm_txsync,
	.nm_rxsync = ptnet_nm_rxsync,
};

/*
 * ptnet_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ptnet_pci_table
 *
 * Returns 0 on success, negative on failure
 *
 * ptnet_probe initializes an pi identified by a pci_dev structure.
 * The OS initialization, configuring of the pi private structure,
 * and a hardware reset occur.
 */
static int
ptnet_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct netmap_adapter na_arg;
	struct ptnet_info *pi;
	int bars;
	int err;

	bars = pci_select_bars(pdev, IORESOURCE_MEM | IORESOURCE_IO);
	err = pci_enable_device(pdev);
	if (err) {
		return err;
	}

	err = pci_request_selected_regions(pdev, bars, DRV_NAME);
	if (err) {
		goto err_pci_reg;
	}

	pci_set_master(pdev);
	err = pci_save_state(pdev);
	if (err) {
		goto err_alloc_etherdev;
	}

	err = -ENOMEM;
	netdev = alloc_etherdev(sizeof(struct ptnet_info));
	if (!netdev) {
		goto err_alloc_etherdev;
	}

	/* Cross-link data structures. */
	SET_NETDEV_DEV(netdev, &pdev->dev);
	pci_set_drvdata(pdev, netdev);
	pi = netdev_priv(netdev);
	pi->netdev = netdev;
	pi->pdev = pdev;
	pi->bars = bars;

	err = -EIO;
	pr_info("IO BAR (registers): start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_len(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_flags(pdev, PTNETMAP_IO_PCI_BAR));

	pi->ioaddr = pci_iomap(pdev, PTNETMAP_IO_PCI_BAR, 0);
	if (!pi->ioaddr) {
		goto err_dma;
	}

	/* Check if we are supported by the hypervisor. If not,
	 * bail out immediately. */
	iowrite32(NET_PTN_FEATURES_BASE, pi->ioaddr + PTNET_IO_PTFEAT);
	pi->ptfeatures = ioread32(pi->ioaddr + PTNET_IO_PTFEAT);
	if (!(pi->ptfeatures & NET_PTN_FEATURES_BASE)) {
		pr_err("Hypervisor doesn't support netmap passthrough\n");
		goto err_ptfeat;
	}

	/* Map the CSB memory exposed by the device. We don't use
	 * pci_ioremap_bar(), since we want the ioremap_cache() function
	 * to be called internally, rather than ioremap_nocache(). */
	pr_info("MEMORY BAR (CSB): start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
		pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR),
		pci_resource_flags(pdev, PTNETMAP_MEM_PCI_BAR));
	pi->csbaddr = ioremap_cache(pci_resource_start(pdev, PTNETMAP_MEM_PCI_BAR),
				    pci_resource_len(pdev, PTNETMAP_MEM_PCI_BAR));
	if (!pi->csbaddr)
		goto err_ptfeat;

	pi->csb = (struct paravirt_csb *)pi->csbaddr;

	/* useless, to be removed */
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		goto err_dma;
	}

	netdev->netdev_ops = &ptnet_netdev_ops;
	netif_napi_add(netdev, &pi->napi, ptnet_clean, 64);

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	synchronize_irq(pi->pdev->irq);

	netdev->hw_features = NETIF_F_SG |
			      NETIF_F_HW_CSUM |
			      NETIF_F_TSO |
			      NETIF_F_RXCSUM |
			      NETIF_F_RXALL |
			      NETIF_F_RXFCS |
			      NETIF_F_HIGHDMA;

	device_set_wakeup_enable(&pi->pdev->dev, 0);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_dma;

	netif_carrier_off(netdev);

	/* Attach a guest pass-through netmap adapter to this device. */
	na_arg = ptnet_nm_ops;
	na_arg.ifp = pi->netdev;
	netmap_pt_guest_attach(&na_arg, &ptnet_nm_pt_guest_ops);
	/* Now a netmap adapter for this device has been allocated, and it
	 * can be accessed through NA(ifp). We have to initialize the CSB
	 * pointer. */
	((struct netmap_pt_guest_adapter *)NA(pi->netdev))->csb =
			(struct paravirt_csb *)pi->csbaddr;

	pr_info("%s: %p\n", __func__, pi);

	return 0;

	pr_info("%s: failed\n", __func__);
err_dma:
	iounmap(pi->csbaddr);
err_ptfeat:
	iounmap(pi->ioaddr);
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_selected_regions(pdev, bars);
err_pci_reg:
	pci_disable_device(pdev);
	return err;
}

/*
 * ptnet_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ptnet_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 */
static void
ptnet_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ptnet_info *pi = netdev_priv(netdev);

	unregister_netdev(netdev);
	iounmap(pi->ioaddr);
	iounmap(pi->csbaddr);
	pci_release_selected_regions(pdev, pi->bars);
	free_netdev(netdev);
	pci_disable_device(pdev);

	pr_info("%s: %p\n", __func__, pi);
}

static void
ptnet_shutdown(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		ptnet_close(netdev);
	}

	pci_disable_device(pdev);
}

/* PCI Device ID Table */
static const struct pci_device_id ptnet_pci_table[] = {
        {PCI_DEVICE(PTNETMAP_PCI_VENDOR_ID, PTNETMAP_PCI_NETIF_ID), 0, 0, 0},
	/* required last entry */
	{0,}
};

MODULE_DEVICE_TABLE(pci, ptnet_pci_table);

static struct pci_driver ptnet_driver = {
	.name     = DRV_NAME,
	.id_table = ptnet_pci_table,
	.probe    = ptnet_probe,
	.remove   = ptnet_remove,
	.shutdown = ptnet_shutdown,
};

/*
 * ptnet_init_module - Driver Registration Routine
 *
 * ptnet_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 */
static int __init
ptnet_init_module(void)
{
	pr_info("%s - version %s\n", "Passthrough netmap interface driver",
		DRV_VERSION);
	pr_info("%s\n", "Copyright (c) 2015 Vincenzo Maffione");

	return pci_register_driver(&ptnet_driver);
}

/*
 * ptnet_exit_module - Driver Exit Cleanup Routine
 *
 * ptnet_exit_module is called just before the driver is removed
 * from memory.
 */
static void __exit
ptnet_exit_module(void)
{
	pci_unregister_driver(&ptnet_driver);
}

module_init(ptnet_init_module);
module_exit(ptnet_exit_module);

MODULE_AUTHOR("Vincenzo Maffione, <v.maffione@gmail.com>");
MODULE_DESCRIPTION("Passthrough netmap interface driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
