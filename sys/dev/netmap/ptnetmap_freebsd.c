#include <sys/cdefs.h> /* prerequisite */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/socketvar.h>      /* struct socket */
#include <sys/socket.h> /* sockaddrs */
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <machine/bus.h>        /* bus_dmamap_* */
#include <machine/resource.h>
#include <net/if.h>
#include <net/if_var.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include <dev/netmap/paravirt.h>

#ifdef WITH_PTNETMAP_GUEST
/*
 * ptnetmap memory device (memdev) for freebsd guest
 * Used to expose host memory to the guest through PCI-BAR
 */

/*
 * ptnetmap memdev private data structure
 */
struct ptnetmap_memdev
{
	device_t dev;
	struct resource *pci_io;
	struct resource *pci_mem;
	struct netmap_mem_d *nm_mem;
};

static int	ptn_memdev_probe(device_t);
static int	ptn_memdev_attach(device_t);
static int	ptn_memdev_detach(device_t);
static int	ptn_memdev_shutdown(device_t);

static device_method_t ptn_memdev_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, ptn_memdev_probe),
	DEVMETHOD(device_attach, ptn_memdev_attach),
	DEVMETHOD(device_detach, ptn_memdev_detach),
	DEVMETHOD(device_shutdown, ptn_memdev_shutdown),
	DEVMETHOD_END
};

static driver_t ptn_memdev_driver = {
	PTN_MEMDEV_NAME, ptn_memdev_methods, sizeof(struct ptnetmap_memdev),
};

devclass_t ptnetmap_devclass;
DRIVER_MODULE(netmap, pci, ptn_memdev_driver, ptnetmap_devclass, 0, 0);

MODULE_DEPEND(netmap, pci, 1, 1, 1);

/*
 * I/O port read/write wrappers.
 */
#define ptn_ioread8(ptn_dev, reg)		bus_read_1((ptn_dev)->pci_io, (reg))
#define ptn_ioread16(ptn_dev, reg)		bus_read_2((ptn_dev)->pci_io, (reg))
#define ptn_ioread32(ptn_dev, reg)		bus_read_4((ptn_dev)->pci_io, (reg))
#define ptn_iowrite8(ptn_dev, reg, val)		bus_write_1((ptn_dev)->pci_io, (reg), (val))
#define ptn_iowrite16(ptn_dev, reg, val)	bus_write_2((ptn_dev)->pci_io, (reg), (val))
#define ptn_iowrite32(ptn_dev, reg, val)	bus_write_4((ptn_dev)->pci_io, (reg), (val))

/*
 * map host netmap memory through PCI-BAR in the guest OS
 *
 * return physical (nm_paddr) and virtual (nm_addr) addresses
 * of the netmap memory mapped in the guest.
 */
int
netmap_pt_memdev_iomap(struct ptnetmap_memdev *ptn_dev, vm_paddr_t *nm_paddr, void **nm_addr)
{
	uint32_t mem_size;
       	int rid;

	D("ptn_memdev_driver iomap");

	rid = PCIR_BAR(PTNETMAP_MEM_PCI_BAR);
	mem_size = ptn_ioread32(ptn_dev, PTNETMAP_IO_PCI_MEMSIZE);

	/* map memory allocator */
	ptn_dev->pci_mem = bus_alloc_resource(ptn_dev->dev, SYS_RES_MEMORY,
			&rid, 0, ~0, mem_size, RF_ACTIVE);
	if (ptn_dev->pci_mem == NULL) {
		*nm_paddr = 0;
		*nm_addr = 0;
		return ENOMEM;
	}

	*nm_paddr = rman_get_start(ptn_dev->pci_mem);
	*nm_addr = rman_get_virtual(ptn_dev->pci_mem);

	D("=== BAR %d start %llx len %llx mem_size %x ===",
			PTNETMAP_MEM_PCI_BAR,
			*nm_paddr,
			rman_get_size(ptn_dev->pci_mem),
			mem_size);
	return (0);
}

/*
 * unmap PCI-BAR
 */
void
netmap_pt_memdev_iounmap(struct ptnetmap_memdev *ptn_dev)
{
	D("ptn_memdev_driver iounmap");

	if (ptn_dev->pci_mem) {
		bus_release_resource(ptn_dev->dev, SYS_RES_MEMORY,
			PCIR_BAR(PTNETMAP_MEM_PCI_BAR), ptn_dev->pci_mem);
		ptn_dev->pci_mem = NULL;
	}
}

/*********************************************************************
 *  Device identification routine
 *
 *  ixgbe_probe determines if the driver should be loaded on
 *  adapter based on PCI vendor/device id of the adapter.
 *
 *  return BUS_PROBE_DEFAULT on success, positive on failure
 *********************************************************************/
static int
ptn_memdev_probe(device_t dev)
{
	char desc[256];

	if (pci_get_vendor(dev) != PTNETMAP_PCI_VENDOR_ID)
                return (ENXIO);
	if (pci_get_device(dev) != PTNETMAP_PCI_DEVICE_ID)
                return (ENXIO);

	D("ptn_memdev_driver probe");
        snprintf(desc, sizeof(desc), "%s PCI adapter",
        		PTN_MEMDEV_NAME);
        device_set_desc_copy(dev, desc);

	return (BUS_PROBE_DEFAULT);
}

/*********************************************************************
 *  Device initialization routine
 *
 *  The attach entry point is called when the driver is being loaded.
 *  This routine identifies the type of hardware, allocates all resources
 *  and initializes the hardware.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/
static int
ptn_memdev_attach(device_t dev)
{
	struct ptnetmap_memdev *ptn_dev;
	int rid;
	uint16_t mem_id;

	D("ptn_memdev_driver attach");

	ptn_dev = device_get_softc(dev);
	ptn_dev->dev = dev;

	pci_enable_busmaster(dev);

	rid = PCIR_BAR(PTNETMAP_IO_PCI_BAR);
	ptn_dev->pci_io = bus_alloc_resource_any(dev, SYS_RES_IOPORT, &rid,
			RF_ACTIVE);
	if (ptn_dev->pci_io == NULL) {
	        device_printf(dev, "cannot map I/O space\n");
	        return (ENXIO);
	}

	mem_id = ptn_ioread16(ptn_dev, PTNETMAP_IO_PCI_HOSTID);

	/* create guest allocator */
	ptn_dev->nm_mem = netmap_mem_pt_guest_create(ptn_dev, mem_id);
	if (ptn_dev->nm_mem == NULL) {
		ptn_memdev_detach(dev);
	        return (ENOMEM);
	}
	netmap_mem_get(ptn_dev->nm_mem);

	D("ptn_memdev_driver probe OK - host_id: %d", mem_id);

	return (0);
}

/*********************************************************************
 *  Device removal routine
 *
 *  The detach entry point is called when the driver is being removed.
 *  This routine stops the adapter and deallocates all the resources
 *  that were allocated for driver operation.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/
static int
ptn_memdev_detach(device_t dev)
{
	struct ptnetmap_memdev *ptn_dev;

	D("ptn_memdev_driver detach");
	ptn_dev = device_get_softc(dev);

	if (ptn_dev->nm_mem) {
		netmap_mem_put(ptn_dev->nm_mem);
		ptn_dev->nm_mem = NULL;
	}
	if (ptn_dev->pci_mem) {
		bus_release_resource(dev, SYS_RES_MEMORY,
			PCIR_BAR(PTNETMAP_MEM_PCI_BAR), ptn_dev->pci_mem);
		ptn_dev->pci_mem = NULL;
	}
	if (ptn_dev->pci_io) {
		bus_release_resource(dev, SYS_RES_IOPORT,
			PCIR_BAR(PTNETMAP_IO_PCI_BAR), ptn_dev->pci_io);
		ptn_dev->pci_io = NULL;
	}

	return (0);
}

/*********************************************************************
 *
 *  Shutdown entry point
 *
 **********************************************************************/
static int
ptn_memdev_shutdown(device_t dev)
{
	D("ptn_memdev_driver shutsown");
	return bus_generic_shutdown(dev);
}

int
netmap_pt_memdev_init(void)
{
	return 0;
}

void
netmap_pt_memdev_uninit(void)
{

}
#endif /* WITH_PTNETMAP_GUEST */
