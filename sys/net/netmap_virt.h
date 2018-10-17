/*
 * Copyright (C) 2013-2016 Luigi Rizzo
 * Copyright (C) 2013-2016 Giuseppe Lettieri
 * Copyright (C) 2013-2016 Vincenzo Maffione
 * Copyright (C) 2015 Stefano Garzarella
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef NETMAP_VIRT_H
#define NETMAP_VIRT_H

/*
 * ptnetmap_memdev: device used to expose memory into the guest VM
 *
 * These macros are used in the hypervisor frontend (QEMU, bhyve) and in the
 * guest device driver.
 */

/* PCI identifiers and PCI BARs for the ptnetmap memdev
 * and ptnetmap network interface. */
#define PTNETMAP_MEMDEV_NAME            "ptnetmap-memdev"
#define PTNETMAP_PCI_VENDOR_ID          0x1b36  /* QEMU virtual devices */
#define PTNETMAP_PCI_DEVICE_ID          0x000c  /* memory device */
#define PTNETMAP_PCI_NETIF_ID           0x000d  /* ptnet network interface */
#define PTNETMAP_IO_PCI_BAR             0
#define PTNETMAP_MEM_PCI_BAR            1
#define PTNETMAP_MSIX_PCI_BAR           2

/* Registers for the ptnetmap memdev */
#define PTNET_MDEV_IO_MEMSIZE_LO	0	/* netmap memory size (low) */
#define PTNET_MDEV_IO_MEMSIZE_HI	4	/* netmap_memory_size (high) */
#define PTNET_MDEV_IO_MEMID		8	/* memory allocator ID in the host */
#define PTNET_MDEV_IO_IF_POOL_OFS	64
#define PTNET_MDEV_IO_IF_POOL_OBJNUM	68
#define PTNET_MDEV_IO_IF_POOL_OBJSZ	72
#define PTNET_MDEV_IO_RING_POOL_OFS	76
#define PTNET_MDEV_IO_RING_POOL_OBJNUM	80
#define PTNET_MDEV_IO_RING_POOL_OBJSZ	84
#define PTNET_MDEV_IO_BUF_POOL_OFS	88
#define PTNET_MDEV_IO_BUF_POOL_OBJNUM	92
#define PTNET_MDEV_IO_BUF_POOL_OBJSZ	96
#define PTNET_MDEV_IO_END		100

/* ptnetmap features */
#define PTNETMAP_F_VNET_HDR        1

/* I/O registers for the ptnet device. */
#define PTNET_IO_PTFEAT		0
#define PTNET_IO_PTCTL		4
#define PTNET_IO_MAC_LO		8
#define PTNET_IO_MAC_HI		12
#define PTNET_IO_CSBBAH		16 /* deprecated */
#define PTNET_IO_CSBBAL		20 /* deprecated */
#define PTNET_IO_NIFP_OFS	24
#define PTNET_IO_NUM_TX_RINGS	28
#define PTNET_IO_NUM_RX_RINGS	32
#define PTNET_IO_NUM_TX_SLOTS	36
#define PTNET_IO_NUM_RX_SLOTS	40
#define PTNET_IO_VNET_HDR_LEN	44
#define PTNET_IO_HOSTMEMID	48
#define PTNET_IO_CSB_GH_BAH     52
#define PTNET_IO_CSB_GH_BAL     56
#define PTNET_IO_CSB_HG_BAH     60
#define PTNET_IO_CSB_HG_BAL     64
#define PTNET_IO_END		68
#define PTNET_IO_KICK_BASE	128
#define PTNET_IO_MASK		0xff

/* ptnetmap control commands (values for PTCTL register) */
#define PTNETMAP_PTCTL_CREATE		1
#define PTNETMAP_PTCTL_DELETE		2

#ifdef WITH_PTNETMAP

/* ptnetmap_memdev routines used to talk with ptnetmap_memdev device driver */
struct ptnetmap_memdev;
int nm_os_pt_memdev_iomap(struct ptnetmap_memdev *, vm_paddr_t *, void **,
                          uint64_t *);
void nm_os_pt_memdev_iounmap(struct ptnetmap_memdev *);
uint32_t nm_os_pt_memdev_ioread(struct ptnetmap_memdev *, unsigned int);

/* Guest driver: Write kring pointers (cur, head) to the CSB.
 * This routine is coupled with ptnetmap_host_read_kring_csb(). */
static inline void
ptnetmap_guest_write_kring_csb(struct nm_csb_atok *atok, uint32_t cur,
			       uint32_t head)
{
    /*
     * We need to write cur and head to the CSB but we cannot do it atomically.
     * There is no way we can prevent the host from reading the updated value
     * of one of the two and the old value of the other. However, if we make
     * sure that the host never reads a value of head more recent than the
     * value of cur we are safe. We can allow the host to read a value of cur
     * more recent than the value of head, since in the netmap ring cur can be
     * ahead of head and cur cannot wrap around head because it must be behind
     * tail. Inverting the order of writes below could instead result into the
     * host to think head went ahead of cur, which would cause the sync
     * prologue to fail.
     *
     * The following memory barrier scheme is used to make this happen:
     *
     *          Guest              Host
     *
     *          STORE(cur)         LOAD(head)
     *          mb() <-----------> mb()
     *          STORE(head)        LOAD(cur)
     */
    atok->cur = cur;
    mb();
    atok->head = head;
}

/* Guest driver: Read kring pointers (hwcur, hwtail) from the CSB.
 * This routine is coupled with ptnetmap_host_write_kring_csb(). */
static inline void
ptnetmap_guest_read_kring_csb(struct nm_csb_ktoa *ktoa,
                              struct netmap_kring *kring)
{
    /*
     * We place a memory barrier to make sure that the update of hwtail never
     * overtakes the update of hwcur.
     * (see explanation in ptnetmap_host_write_kring_csb).
     */
    kring->nr_hwtail = ktoa->hwtail;
    mb();
    kring->nr_hwcur = ktoa->hwcur;
}

#endif /* WITH_PTNETMAP */

#endif /* NETMAP_VIRT_H */
