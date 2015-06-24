/*
 * Copyright (C) 2013-2015 Universita` di Pisa. All rights reserved.
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
#include "Ntstrsafe.h"

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

DRIVER_UNLOAD ioctlUnloadDriver;

//--------------------------------END Device driver routines
static NTSTATUS windows_netmap_mmap(HANDLE pid, PIRP Irp);
NTSTATUS copy_from_user(PVOID dst, PVOID src, size_t len, PIRP Irp);
NTSTATUS copy_to_user(PVOID dst, PVOID src, size_t len, PIRP Irp);

//Allocate the pageable routines and the init routine
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry)
#endif // ALLOC_PRAGMA

struct events_notifications *notes = NULL;

NTSTATUS ioctlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	//As stated in https://support.microsoft.com/en-us/kb/120170
	//irpSp->FileObject is the same for every call from a certain
	//handle so we can use it
	//We can use the structure itself to keep the data
	//[EXTRACT] { Because I/O requests with the same handle have the same file object, 
	//a driver can use the file-object pointer to identify the I/O operations that belong 
	//to one open instantiation of a device or file. }
	struct netmap_priv_d *priv;
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	NMG_LOCK();
	priv = irpSp->FileObject->FsContext;
	if (priv == NULL)
	{
		priv = ExAllocatePoolWithTag(NonPagedPool,
									sizeof(struct netmap_priv_d),
									PRIV_MEMORY_POOL_TAG);
		if (priv == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		else{
			RtlZeroMemory(priv, sizeof(struct netmap_priv_d));
			priv->np_refcount = 1;
			D("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refcount);
			irpSp->FileObject->FsContext = priv;
		}
	}else{
		priv->np_refcount += 1;
		D("Netmap.sys: ioctlCreate::priv->np_refcount = %i", priv->np_refcount);
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
	//Remove the private memory from the dictionary and free the memory
	//that was previously allocated from the structure itself	
	struct netmap_priv_d *priv = NULL;
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	priv = irpSp->FileObject->FsContext;
	if (priv != NULL)
	{
		netmap_dtor(priv);
	}	
	//--------------------------------------------------------
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

	RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);

	// Delete the link from our device name to a name in the Win32 namespace.
	IoDeleteSymbolicLink(&uniWin32NameString);

	if (deviceObject != NULL)
	{
		IoDeleteDevice(deviceObject);
	}	
	return;
}
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
		struct nmreq* test = (struct nmreq*) Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("IFNAMSIZ: %i , sizeof(nmreq): %i\n", IFNAMSIZ, sizeof(struct nmreq));
		DbgPrint("nr_version: %i , nr_ringid: %i\n", test->nr_version, test->nr_ringid);
		DbgPrint("nr_cmd: %i , nr_name: %s\n", test->nr_cmd, test->nr_name);
		DbgPrint("nr_tx_rings: %i , nr_tx_slots: %i\n", test->nr_tx_rings, test->nr_tx_slots);
		DbgPrint("nr_offset: %i , nr_flags: %s\n", test->nr_offset, test->nr_flags);
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
		HANDLE deviceUid = (void*)irpSp->FileObject;
		NtStatus = windows_netmap_mmap(deviceUid, Irp);
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
			//irpSp->FileObject->FsContext2 = pollData->timeout;
			irpSp->FileObject->FsContext2 = NULL;
			pollData->revents = netmap_poll(NULL, pollData->events, irpSp);
			while ((irpSp->FileObject->FsContext2 != NULL) && (pollData->revents == 0))
			{
				NTSTATUS waitResult = KeWaitForSingleObject((irpSp->FileObject->FsContext2), UserRequest, KernelMode, FALSE, &tout);
				if (waitResult == STATUS_TIMEOUT)
					break;
				pollData->revents = netmap_poll(NULL, pollData->events, irpSp);
			}	
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

static NTSTATUS windows_netmap_mmap(HANDLE pid, PIRP Irp)
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
		returnedValue.pUsermodeVirtualAddress = UserVirtualAddress;
		RtlCopyMemory(buffer,
			&returnedValue,
			sizeof(PVOID));
		IoFreeMdl(mdl);
		Irp->IoStatus.Information = sizeof(void*);
		DbgPrint("Netmap.sys: Memory allocated to user process");
		return STATUS_SUCCESS;
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


NTSTATUS ReadSync(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	KPRIORITY increment = 0;
	int events = POLLIN;
	//KeResetEvent(notes->RX_EVENT);
	irpSp = IoGetCurrentIrpStackLocation(Irp); 
	//struct events_notifications *notes = irpSp->FileObject->FsContext2;
	netmap_poll(NULL, events, irpSp);
	/*{
		KeSetEvent(notes->TX_EVENT, increment, FALSE);	
	}*/
	

	//DbgPrint("Netmap.sys: ReadSync invoked\n");
	NTSTATUS NtStatus = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}
NTSTATUS WriteSync(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	KPRIORITY increment = 0;
	//KeResetEvent(notes->TX_EVENT);
	int events = POLLOUT;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	//struct events_notifications *notes = irpSp->FileObject->FsContext2;
	netmap_poll(NULL, events, irpSp);
	/*{
		KeSetEvent(notes->RX_EVENT, increment, FALSE);	
	}*/
	

	//DbgPrint("Netmap.sys: WriteSync invoked\n");
	NTSTATUS NtStatus = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
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
		
    RtlInitUnicodeString( &ntUnicodeString, NT_DEVICE_NAME );

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
	DriverObject->MajorFunction[IRP_MJ_READ] = ReadSync;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteSync;
    DriverObject->DriverUnload = ioctlUnloadDriver;

    // Initialize a Unicode String containing the Win32 name
    // for our device.
    RtlInitUnicodeString( &ntWin32NameString, DOS_DEVICE_NAME );

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

}

int nm_vi_persist(const char *name, struct ifnet **ret)
{
	return ENOMEM;
}

void bdg_mismatch_datapath(struct netmap_vp_adapter *na,
							struct netmap_vp_adapter *dst_na,
							struct nm_bdg_fwd *ft_p, struct netmap_ring *ring,
							u_int *j, u_int lim, u_int *howmany)
{

}

struct net_device * ifunit_ref(const char *name)
{
	return NULL;
	/*
#ifndef NETMAP_LINUX_HAVE_INIT_NET
	return dev_get_by_name(name);
#else
	void *ns = &init_net;
#ifdef CONFIG_NET_NS
	ns = current->nsproxy->net_ns;
#endif
	return dev_get_by_name(ns, name);
#endif
	*/
}

void if_rele(struct net_device *ifp)
{

}
