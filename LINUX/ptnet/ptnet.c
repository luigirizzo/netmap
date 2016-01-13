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

#include "../bsd_glue.h"
#include "net/netmap.h"
#include "dev/netmap/netmap_kern.h"
#include "dev/netmap/netmap_virt.h"


#define DRV_NAME "ptnet"
#define DRV_VERSION "0.1"

struct ptnet_info {
	struct net_device *netdev;
	struct pci_dev *pdev;

	int bars;
	u8* __iomem ioaddr;
	u8* __iomem csb_hwaddr;

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
	uint32_t x, y, z;

	x = ioread32(pi->ioaddr + 0);
	y = ioread32(pi->ioaddr + 4);
	z = ioread32(pi->ioaddr + 8);

	pr_info("x=%u y=%u x=%u\n", x, y, z);
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

	iowrite32(18, pi->ioaddr + 0);
	ptnet_ioregs_dump(pi);

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
	pr_info("IO BAR: start 0x%llx, len %llu, flags 0x%lx\n",
		pci_resource_start(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_len(pdev, PTNETMAP_IO_PCI_BAR),
		pci_resource_flags(pdev, PTNETMAP_IO_PCI_BAR));

	pi->ioaddr = pci_iomap(pdev, PTNETMAP_IO_PCI_BAR, 0);
	if (!pi->ioaddr) {
		goto err_dma;
	}

	pi->csb_hwaddr = pci_ioremap_bar(pdev, PTNETMAP_MEM_PCI_BAR);
	if (!pi->csb_hwaddr)
		goto err_ioremap;

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

	pr_info("%s: %p\n", __func__, pi);

	return 0;

	pr_info("%s: failed\n", __func__);
err_dma:
	iounmap(pi->csb_hwaddr);
err_ioremap:
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
	iounmap(pi->csb_hwaddr);
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
