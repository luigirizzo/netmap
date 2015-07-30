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
FUNCTION_POINTER_XCHANGE g_functionAddresses;

//Allocate the pageable routines and the init routine
//These routines will be unloaded from the memory as soon as
//they've returned
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry)
#endif // ALLOC_PRAGMA

/*
 * XXX this is the open call for the device
 */
NTSTATUS ioctlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
    if (priv == NULL)
    {
	priv = ExAllocatePoolWithTag(NonPagedPool,
		    sizeof(struct netmap_priv_d), PRIV_MEMORY_POOL_TAG);
	if (priv == NULL)
	{
	    status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
	    RtlZeroMemory(priv, sizeof(struct netmap_priv_d));
	    priv->np_refs = 1;
	    D("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refs);
	    irpSp->FileObject->FsContext = priv;
	}
    }
    else
    {
	priv->np_refs += 1;
	D("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refs);
    }
    NMG_UNLOCK();

    //--------------------------------------------------------
    //D("Netmap.sys: Pid %i attached: memory allocated @%p", currentProcId, priv);

    Irp->IoStatus.Status = status;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Irp->IoStatus.Status;	
}


NTSTATUS ioctlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    struct netmap_priv_d *priv = NULL;
    PIO_STACK_LOCATION  irpSp;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    priv = irpSp->FileObject->FsContext;
    if (priv != NULL)
    {
	netmap_dtor(priv);
    }	

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Irp->IoStatus.Status;	
}


VOID ioctlUnloadDriver(__in PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;

    UNICODE_STRING uniWin32NameString;
    UNREFERENCED_PARAMETER(deviceObject);

    netmap_fini();
    keexit_GST();

    RtlInitUnicodeString(&uniWin32NameString, NETMAP_DOS_DEVICE_NAME);

    // Delete the link from our device name to a name in the Win32 namespace.
    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL)
    {
	IoDeleteDevice(deviceObject);
    }	
    return;
}


/* #################### GENERIC ADAPTER SUPPORT ################### */

/*
 * called to enable/disable intercepting packets with netmap
 */
int netdev_rx_handler_register(struct net_device *ifp, BOOLEAN amIRegisteringTheInterface)
{
	if (ifp->ndis_pFilter_readyToUse != NULL)
	{
		*ifp->ndis_pFilter_readyToUse = amIRegisteringTheInterface;
		return STATUS_SUCCESS;
	}
    return STATUS_DEVICE_NOT_CONNECTED;
}

/*
 * intercept packet coming from down,
 * and pass them to netmap
 */
struct NET_BUFFER* windows_generic_rx_handler(struct net_device* nd, uint32_t length, const char* data)
{
    // XXX see if we can do a single allocation
    struct mbuf *m = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct mbuf), 'fubm');

    RtlZeroMemory(m, sizeof(struct mbuf));
    m->m_len = length;
    m->pkt = ExAllocatePoolWithTag(NonPagedPool,  length, 'pubm');// m + sizeof(struct mbuf);
    // RtlZeroMemory(m->pkt, length); // XXX not needed, we copy everything
    m->dev = nd;
    RtlCopyMemory(m->pkt, data, length);
    generic_rx_handler(nd, m);
    return NULL;
}

/*
* intercept packet coming from up,
* and pass them to netmap
*/
struct NET_BUFFER* windows_generic_tx_handler(struct net_device* nd, uint32_t length, const char* data)
{
	// XXX see if we can do a single allocation
	struct mbuf *m = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct mbuf), 'fubm');

	RtlZeroMemory(m, sizeof(struct mbuf));
	m->m_len = length;
	m->pkt = ExAllocatePoolWithTag(NonPagedPool, length, 'pubm');// m + sizeof(struct mbuf);
	// RtlZeroMemory(m->pkt, length); // XXX not needed, we copy everything
	m->dev = nd;
	RtlCopyMemory(m->pkt, data, length);
	netmap_transmit(nd, m);
	return NULL;
}

int netmap_catch_rx(struct netmap_generic_adapter *gna, int intercept)
{
    struct netmap_adapter *na = &gna->up.up;

    return netdev_rx_handler_register(na->ifp, intercept ? TRUE : FALSE);
}

/* We don't need to do anything here */
void netmap_catch_tx(struct netmap_generic_adapter *gna, int enable)
{
    if (enable) {
	    
    }
    else {
		
    }
}

int send_up_to_stack(struct ifnet *ifp, struct mbuf *m)
{
    NTSTATUS status;

    if (g_functionAddresses.injectPacket != NULL)
    {
	status = g_functionAddresses.injectPacket(ifp ->ndis_pFilter_reference, m->pkt, m->m_len, FALSE);
	return status;
    }
    return STATUS_DEVICE_NOT_CONNECTED;
}

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
and <> 0 on error (which may be packet drops or other errors). */
int generic_xmit_frame(struct ifnet *ifp, struct mbuf *m,
	void *addr, u_int len, u_int ring_nr)
{
    NTSTATUS status;
    if (g_functionAddresses.injectPacket != NULL)
    {
	status = g_functionAddresses.injectPacket(ifp->ndis_pFilter_reference, addr, len, TRUE);
	return status;
    }
    return STATUS_DEVICE_NOT_CONNECTED;
}

/*
 * XXX We do not know how many descriptors and rings we have yet
 */
int generic_find_num_desc(struct ifnet *ifp, u_int *tx, u_int *rx)
{
    //XXX_ale: find where the rings are descripted (OID query probably)
    *tx = 1024;
    *rx = 1024;
    return 0;
}

void generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
    //XXX_ale: for a generic device is enough? need to find where this info is
    *txq = 1;
    *rxq = 1;
}
//

NTSTATUS ioctlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	NTSTATUS            NtStatus = STATUS_SUCCESS;
	int ret = 0;
	union {
		struct nm_ifreq ifr;
		struct nmreq nmr;
	} arg;
	size_t			argsize = 0;
	PVOID			data;
	struct sockopt	*sopt;
	int				len = 0;

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	argsize = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	data = Irp->AssociatedIrp.SystemBuffer;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
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
		if (argsize < sizeof(struct sockopt))
		{
			NtStatus = STATUS_BAD_DATA;
			Irp->IoStatus.Status = NtStatus;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return NtStatus;
		}
		sopt = Irp->AssociatedIrp.SystemBuffer;
		len = sopt->sopt_valsize;
		if (irpSp->Parameters.DeviceIoControl.IoControlCode == NETMAP_SETSOCKOPT)
		{
			DbgPrint("Netmap.sys: NETMAP_SETSOCKOPT");
			NtStatus = do_netmap_set_ctl(NULL, sopt->sopt_name, sopt + 1, len);
			Irp->IoStatus.Information = 0;
		}
		else{
			DbgPrint("Netmap.sys: NETMAP_GETSOCKOPT");
			NtStatus = do_netmap_get_ctl(NULL, sopt->sopt_name, sopt + 1, &len);
			sopt->sopt_valsize = len;
			//sanity check on len
			if (len + sizeof(struct sockopt) <= irpSp->Parameters.DeviceIoControl.InputBufferLength)
			{
				Irp->IoStatus.Information = len + sizeof(struct sockopt);
			}
			else
			{
				Irp->IoStatus.Information = irpSp->Parameters.DeviceIoControl.InputBufferLength;
			}
		}
		Irp->IoStatus.Status = NtStatus;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return NtStatus;
	case NETMAP_POLL:
		{
			POLL_REQUEST_DATA *pollData = data;
			LARGE_INTEGER tout;
			long requiredTimeOut = -(int)(pollData->timeout) * 1000 * 10;
			tout = RtlConvertLongToLargeInteger(requiredTimeOut);
			irpSp->FileObject->FsContext2 = NULL;
			pollData->revents = netmap_poll(NULL, pollData->events, irpSp);
			while ((irpSp->FileObject->FsContext2 != NULL) && (pollData->revents == 0))
			{
				NTSTATUS waitResult = KeWaitForSingleObject(irpSp->FileObject->FsContext2, 
															UserRequest, 
															KernelMode, 
															FALSE, 
															&tout);
				if (waitResult == STATUS_TIMEOUT)
				{
					pollData->revents = STATUS_TIMEOUT;
					NtStatus = STATUS_TIMEOUT;
					break;
				}
				pollData->revents = netmap_poll(NULL, pollData->events, irpSp);
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
		if (!data)
		{
			NtStatus = STATUS_DATA_ERROR;
		}
		else{
			bzero(&arg, argsize);
			if (!NT_SUCCESS(copy_from_user(&arg, (void *)data, argsize, Irp)))
			{
				NtStatus = STATUS_DATA_ERROR;
			}	
		}	
	}

	if (NT_SUCCESS(NtStatus))
	{
		ret = netmap_ioctl(NULL, irpSp->Parameters.DeviceIoControl.IoControlCode,
			(caddr_t)&arg, 0, irpSp);
		if (NT_SUCCESS(ret))
		{
			if (data && !NT_SUCCESS(copy_to_user((void*)data, &arg, argsize, Irp)))
			{
				DbgPrint("Netmap.sys: ioctl failure/cannot copy data to user");
				NtStatus = STATUS_DATA_ERROR;
			}
		}else{
			DbgPrint("Netmap.sys: ioctl failure (%i)", ret);
			NtStatus = STATUS_BAD_DATA;
		}
	}

	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return NtStatus;
}

/* basically atoi() -- the name is confusing */
int getDeviceIfIndex(const char* name)
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
struct net_device* ifunit_ref(const char* name)
{
    int			deviceIfIndex = -1;
    NDIS_HANDLE		UserSendNetBufferListPool = NULL;
    struct net_device*	nd = NULL;


    if (g_functionAddresses.get_device_handle_by_ifindex == NULL)
	return NULL; /* function not available yet */

    deviceIfIndex = getDeviceIfIndex(name);
    if (deviceIfIndex < 0)
	return NULL;
    nd = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct net_device), 'NDEV');
    if (nd == NULL)
	return NULL;

    RtlZeroMemory(nd, sizeof(struct net_device));
    RtlCopyMemory(nd->if_xname, name, IFNAMSIZ);
    nd->ifIndex = deviceIfIndex;

    // XXX pass nd to get_device* so it stores all results there
	if (g_functionAddresses.get_device_handle_by_ifindex(deviceIfIndex, nd) != STATUS_SUCCESS)
	{
	ExFreePoolWithTag(nd, 'NDEV');
	return NULL; /* not found */
    }

    return nd;
}

NTSTATUS ioctlInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    FUNCTION_POINTER_XCHANGE *data;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
	case NETMAP_KERNEL_XCHANGE_POINTERS: /* the NDIS module registers with us */
	    data = Irp->AssociatedIrp.SystemBuffer;
	    /* tell ndis whom to call when a packet arrives */
	    data->netmap_catch_rx = &windows_generic_rx_handler;
	    data->netmap_catch_tx = &windows_generic_tx_handler;

	    /* function(s) to access interface parameters */
	    g_functionAddresses.get_device_handle_by_ifindex = data->get_device_handle_by_ifindex;

	    /* function to inject packets into the nic or the stack */
	    g_functionAddresses.injectPacket = data->injectPacket;

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

static NTSTATUS windows_netmap_mmap(PIRP Irp)
{
	PVOID       		buffer = NULL;
	MEMORY_ENTRY		returnedValue;
	void* 				UserVirtualAddress = NULL;
	PMDL 				mdl = NULL;

	PIO_STACK_LOCATION  irpSp;
	int error = 0;
	unsigned long off;
	u_int memsize, memflags;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	struct netmap_priv_d *priv = irpSp->FileObject->FsContext;
	if (priv == NULL)
	{
		DbgPrint("Netmap.sys: priv!!!!!");
		return STATUS_DEVICE_DATA_ERROR;
	}
	struct netmap_adapter *na = priv->np_na;
	if (priv->np_nifp == NULL) {
		DbgPrint("Netmap.sys: priv->np_nifp!!!!!");
		return STATUS_DEVICE_DATA_ERROR;
	}
	mb();

	error = netmap_mem_get_info(na->nm_mem, &memsize, &memflags, NULL);

#ifdef _WIN32_ALLOCATE_ONE_CONTIGUOUS_CLUSTER
	void* addressToShare;
	addressToShare = win32_netmap_mem_getVirtualAddress(na->nm_mem, 0);
	if (addressToShare == NULL)
	{
		return STATUS_DEVICE_DATA_ERROR;
	}
	vm_paddr_t temp;
	temp = vtophys(priv->np_nifp);
	if (temp.QuadPart == NULL)
	{
		return STATUS_DEVICE_DATA_ERROR;
	}
#endif
	try
	{
		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (buffer == NULL)
		{
			Irp->IoStatus.Information = 0;
			DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
			return STATUS_DEVICE_DATA_ERROR;
		}
#ifdef _WIN32_ALLOCATE_ONE_CONTIGUOUS_CLUSTER
		mdl = IoAllocateMdl(addressToShare,
			memsize,
			FALSE,
			FALSE,
			NULL);
		MmBuildMdlForNonPagedPool(mdl);
#else
		mdl = IoAllocateMdl(NULL,
			memsize,
			FALSE,
			FALSE,
			NULL);
		win32_build_virtual_memory_for_userspace(mdl, na->nm_mem);
#endif	//_WIN32_ALLOCATE_ONE_CONTIGUOUS_CLUSTER
		UserVirtualAddress = MmMapLockedPagesSpecifyCache(
			mdl,
			UserMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);
		if (UserVirtualAddress != NULL)
		{
			returnedValue.pUsermodeVirtualAddress = UserVirtualAddress;
			RtlCopyMemory(buffer,
				&returnedValue,
				sizeof(PVOID));
			IoFreeMdl(mdl);
			Irp->IoStatus.Information = sizeof(void*);
			DbgPrint("Netmap.sys: Memory allocated to user process");
			return STATUS_SUCCESS;
		}
		else{
			Irp->IoStatus.Information = 0;
			DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}except(EXCEPTION_EXECUTE_HANDLER)
	{
		Irp->IoStatus.Information = 0;
		DbgPrint("Netmap.sys: Failed to allocate memory!!!!!");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
}

int copy_from_user(PVOID dst, PVOID src, size_t len, PIRP Irp)
{
	RtlCopyMemory(dst, src, len);
	return STATUS_SUCCESS;
}

int copy_to_user(PVOID dst, PVOID src, size_t len, PIRP Irp)
{
    PVOID       buffer = NULL;
    ULONG		outBufLength = 0;
    PIO_STACK_LOCATION  irpSp;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outBufLength >= len)
    {
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, src, len);
	Irp->IoStatus.Information = len;
	return STATUS_SUCCESS;
    }
    else
    {
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

NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS        		ntStatus;
    UNICODE_STRING  		ntUnicodeString;    
    UNICODE_STRING  		ntWin32NameString;    
    PDEVICE_OBJECT  		deviceObject = NULL;    // pointer to the instanced device object
	PDEVICE_DESCRIPTION 	devDes;

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

    if ( !NT_SUCCESS( ntStatus ) )
    {
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
	if (netmap_init() != 0)
	{
		DbgPrint("NETMAP.SYS: Netmap init FAILED!!!\n");
		ntStatus = STATUS_DEVICE_INSUFFICIENT_RESOURCES;
	}
    if ( !NT_SUCCESS( ntStatus ) )
    {
		//Clear all in case of not success
        DbgPrint("NETMAP.SYS: Couldn't create driver\n");
        IoDeleteDevice( deviceObject );
	}else{
		keinit_GST();
		deviceObject->Flags |= DO_DIRECT_IO;
	}
    return ntStatus;
}

void nm_vi_detach(struct ifnet *ifp)
{
    DbgPrint("nm_vi_detach unimplemented!!!\n");
}

int nm_vi_persist(const char *name, struct ifnet **ret)
{
    DbgPrint("nm_vi_persist unimplemented!!!\n");
    return ENOMEM;
}

void bdg_mismatch_datapath(struct netmap_vp_adapter *na,
	struct netmap_vp_adapter *dst_na,
	struct nm_bdg_fwd *ft_p, struct netmap_ring *ring,
	u_int *j, u_int lim, u_int *howmany)
{
    DbgPrint("bdg_mismatch_datapath unimplemented!!!\n");
}

void if_rele(struct net_device *ifp)
{
    DbgPrint("if_rele unimplemented!!!\n");
    // XXX release the reference we got with ifunit_ref
}
