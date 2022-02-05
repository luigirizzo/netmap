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

#include "win_glue.h"

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

//--------------------------------BEGIN Device driver routines

DRIVER_INITIALIZE DriverEntry;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH ioctlCreate;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH ioctlClose;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH ioctlDeviceControl;

__drv_dispatchType(IRP_MJ_INTERNAL_DEVICE_CONTROL)
DRIVER_DISPATCH ioctlInternalDeviceControl;


DRIVER_UNLOAD ioctlUnloadDriver;


//--------------------------------END Device driver routines

static NTSTATUS windows_netmap_mmap(PIRP Irp);
NTSTATUS copy_from_user(PVOID dst, PVOID src, size_t len, PIRP Irp);
NTSTATUS copy_to_user(PVOID dst, PVOID src, size_t len, PIRP Irp);
static FUNCTION_POINTER_XCHANGE ndis_hooks;

// Allocate the pageable routines and the init routine
// These routines will be unloaded from the memory as soon as
// they've returned
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry)
#endif // ALLOC_PRAGMA

/*
 * XXX this is the open call for the device
 */
NTSTATUS
ioctlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    // As stated in https://support.microsoft.com/en-us/kb/120170
    // irpSp->FileObject is the same for every call from a certain
    // handle so we can use it
    // We can use the structure itself to keep the data
    // [EXTRACT] { Because I/O requests with the same handle have the same file object, 
    // a driver can use the file-object pointer to identify the I/O operations that belong 
    // to one open instantiation of a device or file. }

    struct netmap_priv_d *priv;
    PIO_STACK_LOCATION  irpSp;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    NMG_LOCK();
    priv = irpSp->FileObject->FsContext;
    if (priv == NULL) {
	priv = nm_os_malloc(sizeof (*priv)); // could wait
	if (priv == NULL) {
	    status = STATUS_INSUFFICIENT_RESOURCES;
	} else {
	    priv->np_refs = 1;
	    nm_prinf("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refs);
	    irpSp->FileObject->FsContext = priv;
	}
    } else {
	priv->np_refs += 1;
	nm_prinf("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refs);
    }
    NMG_UNLOCK();

    //--------------------------------------------------------
    //nm_prinf("Netmap.sys: Pid %i attached: memory allocated @%p", currentProcId, priv);

    Irp->IoStatus.Status = status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Irp->IoStatus.Status;	
}


NTSTATUS
ioctlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    struct netmap_priv_d *priv = NULL;
    PIO_STACK_LOCATION  irpSp;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    priv = irpSp->FileObject->FsContext;
    if (priv != NULL) {
	netmap_dtor(priv);
    }	

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Irp->IoStatus.Status;	
}


VOID
ioctlUnloadDriver(__in PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    UNICODE_STRING uniWin32NameString;
    UNREFERENCED_PARAMETER(deviceObject);

    netmap_fini();
    keexit_GST();

    RtlInitUnicodeString(&uniWin32NameString, NETMAP_DOS_DEVICE_NAME);

    // Delete the link from our device name to a name in the Win32 namespace.
    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL) {
	IoDeleteDevice(deviceObject);
    }	
    return;
}


/* #################### GENERIC ADAPTER SUPPORT ################### */
/*XXX: use NETMAP_BUF_SIZE(ifp->na), for virtual interfaces gives BSOD
 * remember to set the same value in filter.c :: FilterAttach() when 
 *  doing ExInitializeNPagedLookasideList()
*/
void win32_init_lookaside_buffers(struct net_device *ifp){
	if (!ifp->lookasideListsAlreadyAllocated) {
		ifp->lookasideListsAlreadyAllocated = TRUE;
		ExInitializeNPagedLookasideList(&ifp->mbuf_pool, NULL, NULL, 0, sizeof(struct mbuf), M_DEVBUF, 0);
		ExInitializeNPagedLookasideList(&ifp->mbuf_packets_pool, NULL, NULL, 0, 2048, M_DEVBUF, 0);
	}
}

void win32_clear_lookaside_buffers(struct net_device *ifp){
	if (ifp->lookasideListsAlreadyAllocated) {
		ifp->lookasideListsAlreadyAllocated = FALSE;
		ExDeleteNPagedLookasideList(&ifp->mbuf_packets_pool);
		ExDeleteNPagedLookasideList(&ifp->mbuf_pool);
	}
}

/*
 * For packets coming from the generic adapter, netmap expects
 * an mbuf with a persistent copy of the data.
 * For the time being we construct a brand new mbuf and
 * pass it to the handler.
 * We use this routine also in a way similar to m_getcl(),
 * passing a NULL pointer does not initialize the buffer (we need the length).
 * We have two pools, one for the mbuf and one for the cluster.
 * XXX we could do with a single allocation.
 */
struct mbuf *
win_make_mbuf(struct net_device *ifp, uint32_t length, const char *data)
{
	struct mbuf *m = ExAllocateFromNPagedLookasideList(&ifp->mbuf_pool);
	//DbgPrint("win_make_mbuf - Data: %p - length: %i", data, length);
	if (m == NULL) {
		DbgPrint("Netmap.sys: Failed to allocate memory from the mbuf!!!");
		return NULL;
	}
	m->m_len = length;
	m->pkt = ExAllocateFromNPagedLookasideList(&ifp->mbuf_packets_pool);
	if (m->pkt == NULL) {
		DbgPrint("Netmap.sys: Failed to allocate memory from the mbuf packet!!!");
		ExFreeToNPagedLookasideList(&ifp->mbuf_pool, m);
		return NULL;
	}
	m->dev = ifp;
	if (data) // XXX otherwise zero memory ?
		RtlCopyMemory(m->pkt, data, length);
	return m;
}

/*
 * windows_handle_rx is called by the nm-ndis module on an incoming packet
 * from the NIC (miniport driver). After encapsulating into a buffer,
 * we pass it to the generic rx handler in netmap_generic.c to be queued
 * on the NIC rx ring.
 * XXX in the future we could avoid the allocation by passing up the NDIS
 * packet, and setting a callback to generate the notification when the
 * netmap receiver eventually calls rxsync. However the savings from the
 * extra allocation and copy are probably modest at least until we
 * have a relatively slow NIC.
 */
struct NET_BUFFER *
windows_handle_rx(struct net_device *ifp, uint32_t length, const char *data)
{
	struct mbuf *m = win_make_mbuf(ifp, length, data);

	if (m) {
		int stolen = generic_rx_handler(ifp, m);

		if (!stolen) {
			m_freem(m);
			/* XXX Should we return m instead of freeing it? */
		}
	}

	return NULL;
}

/*
 * Same as above for packets coming from the host stack and passed to the
 * host rx ring of netmap.
 */
struct NET_BUFFER *
windows_handle_tx(struct net_device *ifp, uint32_t length, const char *data)
{
	struct mbuf *m = win_make_mbuf(ifp, length, data);

	if (m)
		netmap_transmit(ifp, m);
	return NULL;
}

/*
 * we default to always allocating and zeroing
 */
void *
nm_os_malloc(size_t size)
{
    void* mem = ExAllocatePoolWithTag(NonPagedPool, size, /* M_DEVBUF */ 2);

    if (mem != NULL) {
        RtlZeroMemory(mem, size);
    }
    return mem;
}

void
nm_os_free(void *addr)
{
    ExFreePoolWithTag(addr, /* M_DEVBUF */ 2);
}

void *
nm_os_realloc(void *src, size_t size, size_t oldSize)
{
    //DbgPrint("Netmap.sys: win_reallocate(%p, %i, %i)", src, size, oldSize);
    PVOID newBuff = NULL; /* default return value */

    if (src == NULL) { /* if size > 0, this is a malloc */
        if (size > 0) {
            newBuff = nm_os_malloc(size);
        }
    } else if (size == 0) {
        nm_os_free(src);
    } else if (size == oldSize) {
        newBuff = src;
    } else { /* realloc -- XXX later maybe ignore shrink ? */
        newBuff = nm_os_malloc(size);
        if (newBuff != NULL) {
            if (size <= oldSize) { /* shrink, just copy back part of the data */
                RtlCopyMemory(newBuff, src, size);
            } else {
                RtlCopyMemory(newBuff, src, oldSize);
            }
        }
    }
    return newBuff;
}

int
nm_os_catch_rx(struct netmap_generic_adapter *gna, int intercept)
{
    struct netmap_adapter *na = &gna->up.up;
    int *p = na->ifp->intercept;

    if (p != NULL) {
	*p = intercept ? (*p | NM_WIN_CATCH_RX) : (*p & ~NM_WIN_CATCH_RX);
	return STATUS_SUCCESS;
    }
    return STATUS_DEVICE_NOT_CONNECTED;
}


int
nm_os_catch_tx(struct netmap_generic_adapter *gna, int intercept)
{
    struct netmap_adapter *na = &gna->up.up;
    int *p = na->ifp->intercept;

    if (p != NULL) {
	*p = intercept ? (*p | NM_WIN_CATCH_TX) : (*p & ~NM_WIN_CATCH_TX);
    }

    return 0;
}

/*
 * XXX the mbuf must be consumed
 * this is NM_SEND_UP which builds a batch of packets and then
 * sends them up on the last call with a NULL data.
 * XXX at the moment packets are copied from the netmap buffer into mbufs
 * and then again into NDIS packets. We could save one allocation and one
 * copy, eventually.
 */
void *
nm_os_send_up(struct ifnet *ifp, struct mbuf *m, struct mbuf *prev)
{
	void *head = NULL;
	if (ndis_hooks.injectPacket != NULL) {
		//DbgPrint("send_up_to_stack!");
		if (m != NULL) {
			head = ndis_hooks.injectPacket(ifp->pfilter, m->pkt, m->m_len, FALSE, prev);
			m_freem(m);
		} else {
			ndis_hooks.injectPacket(ifp->pfilter, NULL, 0, FALSE, prev);
		}
	} else { /* we should not get here */
		if (m != NULL)
			m_freem(m);
	}
	return head;
}

int
MBUF_TRANSMIT(struct netmap_adapter *na, struct ifnet *ifp, struct mbuf *m)
{
	if (ndis_hooks.injectPacket == NULL) {
		return 0;
	}
	if (ndis_hooks.injectPacket(ifp->pfilter, NULL, 0, TRUE, m)) {
                return 0;
        }
        return -1;
}

/*
 * Transmit routine used by generic_netmap_txsync(). Returns 0 on success
 * and <> 0 on error (which may be packet drops or other errors).
*/
int
nm_os_generic_xmit_frame(struct nm_os_gen_arg *a)
{
	void *cur;
	PVOID toSend = (a->addr == NULL) ? a->head : a->tail;
	if (ndis_hooks.injectPacket == NULL) { /* silently drop ? */
		return 0;
	}
	cur = ndis_hooks.injectPacket(a->ifp->pfilter, a->addr, a->len, TRUE, toSend);
	if (cur) {
		a->tail = cur;
		if (a->head == NULL)
			a->head = cur;
		return 0;
	}

	/* NDIS_STATUS_BUFFER_OVERFLOW */
	return -1;
}

/*
 * XXX We do not know how many descriptors and rings we have yet
 */
int
nm_os_generic_find_num_desc(struct ifnet *ifp, u_int *tx, u_int *rx)
{
    //XXX_ale: find where the rings are descripted (OID query probably)
    *tx = 1024;
    *rx = 1024;
    return 0;
}

void
nm_os_generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
    //XXX_ale: for a generic device is enough? need to find where this info is
    *txq = 1;
    *rxq = 1;
}

void
nm_os_generic_set_features(struct netmap_generic_adapter *gna)
{
	/* No support for now. */
	gna->rxsg = 0;
	gna->txqdisc = 0;
}
//

NTSTATUS
ioctlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	NTSTATUS            NtStatus = STATUS_SUCCESS;
	int ret = 0;
	union {
		struct nm_ifreq ifr;
		struct nmreq nmr;
	} arg;


	size_t	argsize = 0;
	PVOID	data;
	struct sockopt	*sopt;
	int	space, len = 0;

	(void)DeviceObject; // XXX

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	argsize = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	data = Irp->AssociatedIrp.SystemBuffer;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
	case NIOCGINFO:
		DbgPrint("Netmap.sys: NIOCGINFO");
		argsize = sizeof(arg.nmr);
		break;

	case NIOCREGIF:
		DbgPrint("Netmap.sys: NIOCREGIF");
		argsize = sizeof(arg.nmr);
#if 0
		struct nmreq* test = (struct nmreq*) Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("IFNAMSIZ: %i , sizeof(nmreq): %i\n", IFNAMSIZ, sizeof(struct nmreq));
		DbgPrint("nr_version: %i , nr_ringid: %i\n", test->nr_version, test->nr_ringid);
		DbgPrint("nr_cmd: %i , nr_name: %s\n", test->nr_cmd, test->nr_name);
		DbgPrint("nr_tx_rings: %i , nr_tx_slots: %i\n", test->nr_tx_rings, test->nr_tx_slots);
		DbgPrint("nr_offset: %i , nr_flags: %s\n", test->nr_offset, test->nr_flags);
#endif
		break;

	case NIOCTXSYNC:
		//DbgPrint("Netmap.sys: NIOCTXSYNC");
		break;

	case NIOCRXSYNC:
		//DbgPrint("Netmap.sys: NIOCRXSYNC");
		break;

	case NIOCCONFIG:
		DbgPrint("Netmap.sys: NIOCCONFIG");
		argsize = sizeof(arg.ifr);
		break;

	case NETMAP_MMAP:
		DbgPrint("Netmap.sys: NETMAP_MMAP");
		NtStatus = windows_netmap_mmap(Irp);
		Irp->IoStatus.Status = NtStatus;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return NtStatus;

	case NETMAP_GETSOCKOPT:
	case NETMAP_SETSOCKOPT:
		DbgPrint("Netmap.sys: NETMAP_SET/GET-SOCKOPT (Common code)");
		if (argsize < sizeof(struct sockopt)) {
			NtStatus = STATUS_BAD_DATA;
			Irp->IoStatus.Status = NtStatus;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return NtStatus;
		}
		sopt = Irp->AssociatedIrp.SystemBuffer;
		len = sopt->sopt_valsize;
		if (irpSp->Parameters.DeviceIoControl.IoControlCode == NETMAP_SETSOCKOPT) {
			DbgPrint("Netmap.sys: NETMAP_SETSOCKOPT");
			NtStatus = do_netmap_set_ctl(NULL, sopt->sopt_name, sopt + 1, len);
			Irp->IoStatus.Information = 0;
		} else {
			DbgPrint("Netmap.sys: NETMAP_GETSOCKOPT");
			NtStatus = do_netmap_get_ctl(NULL, sopt->sopt_name, sopt + 1, &len);
			sopt->sopt_valsize = len;
			// XXX should we use OutputBufferLength ?
			space = irpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (len + sizeof(struct sockopt) <= space) {
				Irp->IoStatus.Information = len + sizeof(struct sockopt);
			} else {
				Irp->IoStatus.Information = space;
			}
		}
		Irp->IoStatus.Status = NtStatus;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return NtStatus;

	case NETMAP_POLL:
		{
			//DbgPrint("%i: Requested call to POLL \n", PsGetCurrentThreadId());
			POLL_REQUEST_DATA *pollData = data;
			LARGE_INTEGER tout;
			tout.QuadPart = -(int)(pollData->timeout) * 1000 * 10;
			struct netmap_priv_d *priv = irpSp->FileObject->FsContext;

			if (priv == NULL) {
				NtStatus = STATUS_DEVICE_DATA_ERROR;
				goto done;
			}

			irpSp->FileObject->FsContext2 = NULL;
			pollData->revents = netmap_poll(priv, pollData->events, irpSp);
			while ((irpSp->FileObject->FsContext2 != NULL) && (pollData->revents == 0)) {
				NTSTATUS waitResult = KeWaitForSingleObject(&((win_SELINFO*)irpSp->FileObject->FsContext2)->queue,
								UserRequest, KernelMode, 
								FALSE, &tout);
				if (waitResult == STATUS_TIMEOUT) {
					DbgPrint("%i: Timeout on 0x%p \n", PsGetCurrentThreadId(), irpSp->FileObject->FsContext2);
					pollData->revents = STATUS_TIMEOUT;
					NtStatus = STATUS_TIMEOUT;
					break;
				}
				pollData->revents = netmap_poll(priv, pollData->events, irpSp);
			}	
			irpSp->FileObject->FsContext2 = NULL;
			copy_to_user((void*)data, &arg, sizeof(POLL_REQUEST_DATA), Irp);
		}
		Irp->IoStatus.Status = NtStatus;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return NtStatus;

	default:
		//bail out if unknown request issued
		DbgPrint("Netmap.sys: wrong request issued! (%i)", irpSp->Parameters.DeviceIoControl.IoControlCode);
		NtStatus = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return NtStatus;
	}

	if (argsize) {
		if (!data) {
			NtStatus = STATUS_DATA_ERROR;
		} else {
			bzero(&arg, argsize);
			if (!NT_SUCCESS(copy_from_user(&arg, (void *)data, argsize, Irp))) {
				NtStatus = STATUS_DATA_ERROR;
			}	
		}	
	}

	if (NT_SUCCESS(NtStatus)) {
		struct netmap_priv_d *priv = irpSp->FileObject->FsContext;

		if (priv == NULL) {
			NtStatus = STATUS_DEVICE_DATA_ERROR;
			goto done;
		}

		ret = netmap_ioctl(priv, irpSp->Parameters.DeviceIoControl.IoControlCode,
			(caddr_t)&arg, NULL, 1);
		if (NT_SUCCESS(ret)) {
			if (data && !NT_SUCCESS(copy_to_user((void*)data, &arg, argsize, Irp))) {
				DbgPrint("Netmap.sys: ioctl failure/cannot copy data to user");
				NtStatus = STATUS_DATA_ERROR;
			}
		} else {
			DbgPrint("Netmap.sys: ioctl failure (%i)", ret);
			NtStatus = STATUS_BAD_DATA;
		}
	}

done:
	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return NtStatus;
}

/* basically atoi() -- the name is confusing */
int
getDeviceIfIndex(const char* name)
{
    int i, result = 0;

    for (i = 0; i < 6 && name[i] >= '0' && name[i] <='9'; i++) {
	result = result * 10;
	result += (name[i] - '0');
    }
    if (i == 0 || i >= 6) {
	result = -1;
    }
    DbgPrint("Netmap.sys: Requested interface ifIndex: %i", result);
    return result;
}

/*
 * grab a reference to the device, and all pointers
 * we need to operate on it.
 */
struct net_device *
ifunit_ref(const char* name)
{
    int			deviceIfIndex = -1;
    struct net_device *	ifp = NULL;

    if (strlen(name) < 4 || _strnicmp(name, "eth", 3) != 0) {
	nm_prerr("not a NIC");
	return NULL;
    }
	if (ndis_hooks.ndis_regif == NULL)
	return NULL; /* function not available yet */

    deviceIfIndex = getDeviceIfIndex(name+3);
    if (deviceIfIndex < 0)
	return NULL;
    ifp = nm_os_malloc(sizeof(struct net_device));
    if (ifp == NULL)
	return NULL;

    win32_init_lookaside_buffers(ifp);

    RtlCopyMemory(ifp->if_xname, name, IFNAMSIZ);
    ifp->ifIndex = deviceIfIndex;

	win32_init_lookaside_buffers(ifp);

	if (ndis_hooks.ndis_regif(ifp) != STATUS_SUCCESS) {
	nm_os_free(ifp);
	win32_clear_lookaside_buffers(ifp);
	return NULL; /* not found */
    }
    return ifp;
}

NTSTATUS
ioctlInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    FUNCTION_POINTER_XCHANGE *data;

    (void)DeviceObject; // XXX

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case NETMAP_KERNEL_XCHANGE_POINTERS: /* the NDIS module registers with us */
	data = Irp->AssociatedIrp.SystemBuffer;
	/* tell ndis whom to call when a packet arrives */
	data->handle_rx = &windows_handle_rx;
	data->handle_tx = &windows_handle_tx;

	/* function(s) to access interface parameters */
	ndis_hooks.ndis_regif = data->ndis_regif;

	ndis_hooks.ndis_rele = data->ndis_rele;

	/* function to inject packets into the nic or the stack */
	ndis_hooks.injectPacket = data->injectPacket;

	/* copy back the results. XXX why do we need to do that ? */
	//RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, data, sizeof(FUNCTION_POINTER_XCHANGE));
	Irp->IoStatus.Information = sizeof(FUNCTION_POINTER_XCHANGE);
#if 0
	DbgPrint("Netmap.sys: NETMAP_KERNEL_XCHANGE_POINTERS - Internal device control called successfully (0x%p)\n", &testCallFunctionFromRemote);
	DbgPrint("Netmap.sys: Data->pRxPointer (0x%p) &(0x%p)\n", data->pRxPointer, &data->pRxPointer);
#endif
	break;

    default:
	DbgPrint("Netmap.sys: wrong request issued! (%i)", irpSp->Parameters.DeviceIoControl.IoControlCode);
	NtStatus = STATUS_INVALID_DEVICE_REQUEST;
    }	
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return NtStatus;
}

static NTSTATUS
windows_netmap_mmap(PIRP Irp)
{
	PIO_STACK_LOCATION	irpSp;
	struct netmap_priv_d	*priv;
	struct netmap_adapter	*na;
	PMDL mdl;
	NTSTATUS		ret = STATUS_SUCCESS;

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	priv = irpSp->FileObject->FsContext;

	if (priv == NULL) {
		nm_prerr("no priv");
		return STATUS_DEVICE_DATA_ERROR;
	}
	na = priv->np_na;
	if (na == NULL) {
		nm_prerr("na not attached");
		return STATUS_DEVICE_DATA_ERROR;
	}
	mb(); /* XXX really ? */

	mdl = win32_build_user_vm_map(na->nm_mem);
	if (mdl == NULL) {
		nm_prerr("failed building memory map");
		return STATUS_DEVICE_DATA_ERROR;
	}

	try { // XXX see if we can do without exceptions
		void *UserVirtualAddress;
		PVOID buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

		if (buffer == NULL) {
			Irp->IoStatus.Information = 0;
			DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
			return STATUS_DEVICE_DATA_ERROR;
		}

		UserVirtualAddress = MmMapLockedPagesSpecifyCache(
			mdl,
			UserMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (UserVirtualAddress != NULL) {
			MEMORY_ENTRY		returnedValue;

			returnedValue.pUsermodeVirtualAddress = UserVirtualAddress;
			RtlCopyMemory(buffer, &returnedValue, sizeof(PVOID));
			Irp->IoStatus.Information = sizeof(void*);
			DbgPrint("Netmap.sys: Memory allocated to user process");
		} else {
			Irp->IoStatus.Information = 0;
			DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
			// XXX do we need to free the mdl ?
			ret = STATUS_INSUFFICIENT_RESOURCES;
		}
	} except(EXCEPTION_EXECUTE_HANDLER) {
		Irp->IoStatus.Information = 0;
		DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
		ret = STATUS_INSUFFICIENT_RESOURCES;
	}
	IoFreeMdl(mdl);
	return ret;
}

int
copy_from_user(PVOID dst, PVOID src, size_t len, PIRP Irp)
{
	// XXX should we use Irp to check for the length ?
	RtlCopyMemory(dst, src, len);
	return STATUS_SUCCESS;
}

int
copy_to_user(PVOID dst, PVOID src, size_t len, PIRP Irp)
{
    ULONG		outBufLength = 0;
    PIO_STACK_LOCATION  irpSp;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outBufLength >= len) {
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, src, len);
	Irp->IoStatus.Information = len;
	return STATUS_SUCCESS;
    } else {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
}

 /*
 * Kernel driver entry point.
 *
 * Initialize/finalize the module and return.
 *
 * Return STATUS_SUCCESS on success, errno on failure.
 */

NTSTATUS
DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS        		ntStatus;
    UNICODE_STRING  		ntUnicodeString;    
    UNICODE_STRING  		ntWin32NameString;    
    PDEVICE_OBJECT  		deviceObject = NULL;    // pointer to the instanced device object
    // PDEVICE_DESCRIPTION 	devDes;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(deviceObject);
		
    RtlInitUnicodeString(&ntUnicodeString, NETMAP_NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,                   // The Driver Object
        0,                              // DeviceExtensionSize 
        &ntUnicodeString,               // DeviceName 
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     	// Device characteristics
        FALSE,                          // Not exclusive
        &deviceObject );                // Returned pointer to the device

    if ( !NT_SUCCESS( ntStatus ) ) {
        DbgPrint("NETMAP.SYS: Couldn't create the device object\n");
        return ntStatus;
    }
    DbgPrint("NETMAP.SYS: Driver loaded at address 0x%p \n",&deviceObject);
	
    // Init function pointers to major driver functions
    DriverObject->MajorFunction[IRP_MJ_CREATE] = ioctlCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ioctlClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctlDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = ioctlInternalDeviceControl;
    //DriverObject->MajorFunction[IRP_MJ_READ] = ReadSync;
    //DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteSync;
    DriverObject->DriverUnload = ioctlUnloadDriver;

    // Initialize a Unicode String containing the Win32 name
    // for our device.
    RtlInitUnicodeString(&ntWin32NameString, NETMAP_DOS_DEVICE_NAME);

    // Symlink creation
    ntStatus = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString );
    if (netmap_init() != 0) {
	DbgPrint("NETMAP.SYS: Netmap init FAILED!!!\n");
	ntStatus = STATUS_DEVICE_INSUFFICIENT_RESOURCES;
    }
    if ( !NT_SUCCESS( ntStatus ) ) {
	//Clear all in case of not success
        DbgPrint("NETMAP.SYS: Couldn't create driver\n");
        IoDeleteDevice( deviceObject );
    } else {
	keinit_GST();
	deviceObject->Flags |= DO_DIRECT_IO;
    }
    return ntStatus;
}

void
nm_os_vi_detach(struct ifnet *ifp)
{
    DbgPrint("nm_vi_detach unimplemented!!!\n");
}

//nm_os_selrecord(NM_SELRECORD_T *sr, NM_SELINFO_T *si)
void
nm_os_selrecord(IO_STACK_LOCATION *irpSp, win_SELINFO *ev)
{
	if (irpSp->FileObject->FsContext2 == NULL) {
		//DbgPrint("%i: nm_selrecord on 0x%p", PsGetCurrentThreadId(), &ev->queue);
		KeAcquireGuardedMutex(&ev->mutex);
		irpSp->FileObject->FsContext2 = ev;
		KeClearEvent(&ev->queue);
		KeReleaseGuardedMutex(&ev->mutex);
	}
}

void
nm_os_selwakeup(NM_SELINFO_T *queue)
{
	//DbgPrint("%i: nm_selwakeup on 0x%p",PsGetCurrentThreadId(), &queue->queue);
	KeAcquireGuardedMutex(&queue->mutex);
	KeSetEvent(&queue->queue, PI_NET, FALSE);
	KeReleaseGuardedMutex(&queue->mutex);
}

int
nm_os_vi_persist(const char *name, struct ifnet **ret)
{
    DbgPrint("nm_vi_persist unimplemented!!!\n");
    return ENOMEM;
}

void
bdg_mismatch_datapath(struct netmap_vp_adapter *na,
	struct netmap_vp_adapter *dst_na,
	const struct nm_bdg_fwd *ft_p, struct netmap_ring *dst_ring,
	u_int *j, u_int lim, u_int *howmany)
{
    DbgPrint("bdg_mismatch_datapath unimplemented!!!\n");
}

void if_ref(struct net_device *ifp)
{
	/*
	* XXX This is just to shut up the compiler.
	* I wouldn't know what to out in here yet...
	*/
	DbgPrint("unimplemented if_ref!!!\n");
/* 	dev_hold(ifp); */
}

void
if_rele(struct net_device *ifp)
{
	win32_clear_lookaside_buffers(ifp);

	if (ndis_hooks.ndis_rele != NULL)
	{
		ndis_hooks.ndis_rele(ifp);
	}
}

void 
nm_os_ifnet_unlock(void){
};

void 
nm_os_ifnet_lock(void){

};

int
nm_os_ifnet_init(void)
{
	return 0;
}

void
nm_os_ifnet_fini(void)
{

}

unsigned
nm_os_ifnet_mtu(struct ifnet *ifp)
{
       return 1500; /* XXX hardwired */
}

/*
 * Mitigation support
 */

void
generic_timer_handler(struct hrtimer *t)
{
	DbgPrint("unimplemented generic_timer_handler\n", t);
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
		netmap_common_irq(mit->mit_na, mit->mit_ring_idx, &work_done);
		generic_rate(0, 0, 0, 0, 0, 1);
	}
	nm_os_mitigation_restart(mit);
	return HRTIMER_RESTART;
#endif
}

void nm_os_mitigation_init(struct nm_generic_mit *mit, int idx,
struct netmap_adapter *na)
{
	DbgPrint("unimplemented generic_timer_handler\n");
	//KeInitializeDpc(&mit->mit_timer.deferred_proc, &generic_timer_handler, NULL);
	//KeInitializeTimer(&mit->mit_timer.timer);
	//hrtimer_init(&mit->mit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	//mit->mit_timer.function = &generic_timer_handler;
	//mit->mit_pending = 0;
	//mit->mit_ring_idx = idx;
	//mit->mit_na = na;
}

void nm_os_mitigation_start(struct nm_generic_mit *mit)
{
	DbgPrint("unimplemented generic_timer_handler\n");
	//LARGE_INTEGER test;
	//KeSetTimerEx(&mit->mit_timer.timer, test, 1000, &mit->mit_timer.deferred_proc);
	//mit->mit_timer.active = TRUE;
	//hrtimer_start(&mit->mit_timer, ktime_set(0, netmap_generic_mit), HRTIMER_MODE_REL);
	
}

void nm_os_mitigation_restart(struct nm_generic_mit *mit)
{
	DbgPrint("unimplemented nm_os_mitigation_start\n");
	//hrtimer_forward_now(&mit->mit_timer, ktime_set(0, netmap_generic_mit));
}

int nm_os_mitigation_active(struct nm_generic_mit *mit)
{
	DbgPrint("unimplemented nm_os_mitigation_active\n");
	return 0;
	//return mit->mit_timer.active;
	//return hrtimer_active(&mit->mit_timer);
}

void nm_os_mitigation_cleanup(struct nm_generic_mit *mit)
{
	DbgPrint("unimplemented nm_os_mitigation_cleanup\n");
	//mit->mit_timer.active = FALSE;
	//KeCancelTimer(&mit->mit_timer.timer);
	//hrtimer_cancel(&mit->mit_timer);
}

u_int
nm_os_ncpus(void)
{
	return 1;  // TODO
}

int
nm_os_mbuf_has_csum_offld(struct mbuf *m)
{
	return 0;  // TODO
}

int
nm_os_mbuf_has_seg_offld(struct mbuf *m)
{
	return 0;  // TODO
}

void
nm_os_get_module(void)
{
	// TODO
}

void
nm_os_put_module(void)
{
	// TODO
}


struct nm_kctx {
    int unused; /* To avoid compiler barfs */
};

void
nm_os_kctx_worker_setaff(struct nm_kctx *nmk, int affinity)
{
	// TODO
}

struct nm_kctx *
nm_os_kctx_create(struct nm_kctx_cfg *cfg, void *opaque)
{
	// TODO
	return NULL;
}

int
nm_os_kctx_worker_start(struct nm_kctx *nmk)
{
	// TODO
	return -1;
}

void
nm_os_kctx_worker_stop(struct nm_kctx *nmk)
{
	// TODO
}


void
nm_os_kctx_destroy(struct nm_kctx *nmk)
{
	// TODO
}

