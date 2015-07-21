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

//PFILE_OBJECT		pNdisFileObject = NULL;
//PDEVICE_OBJECT		pNdisDeviceObj = NULL;

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
		}else{
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

/* #################### GENERIC ADAPTER SUPPORT ################### */

/*NTSTATUS SetNDISDeviceReferences()
{
	OBJECT_ATTRIBUTES   objectAttributes;
	UNICODE_STRING      ObjectName;
	NTSTATUS			NtStatus;
	KIRQL Irql = KeGetCurrentIrql();
	ASSERT(Irql == PASSIVE_LEVEL);

	if (pNdisDeviceObj == NULL)
	{
		RtlInitUnicodeString(&ObjectName, NETMAP_NDIS_LINKNAME_STRING);
		InitializeObjectAttributes(&objectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		return IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &pNdisFileObject, &pNdisDeviceObj);
	}
	else{
		return STATUS_SUCCESS;
	}
}*/

int netdev_rx_handler_register(struct net_device *ifp, BOOLEAN amIRegisteringTheInterface)
{
	if (g_functionAddresses.set_ifp_in_device_handle != NULL)
	{
		g_functionAddresses.set_ifp_in_device_handle(ifp, amIRegisteringTheInterface);
		return STATUS_SUCCESS;
	}else{
		return STATUS_DEVICE_NOT_CONNECTED;
	}
#if 0		
	OBJECT_ATTRIBUTES   objectAttributes;
	UNICODE_STRING      ObjectName;
	IO_STATUS_BLOCK		iosb;
	PFILE_OBJECT		pFileObject = NULL;
	PDEVICE_OBJECT		pNdisObj;
	NTSTATUS			NtStatus;
	KIRQL FirstIrql = KeGetCurrentIrql();

	RtlInitUnicodeString(&ObjectName, NETMAP_NDIS_LINKNAME_STRING);
	InitializeObjectAttributes(&objectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	if (FirstIrql > PASSIVE_LEVEL)
	{
		KeLowerIrql(PASSIVE_LEVEL);
	}
	NtStatus = IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &pFileObject, &pNdisObj);
	if (KeGetCurrentIrql() != FirstIrql)
	{
		KeRaiseIrql(FirstIrql, &FirstIrql);
	}

	//NtStatus = SetNDISDeviceReferences();
	if (NT_SUCCESS(NtStatus))
	{
		PMEMORY_ENTRY memEntry;
		memEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(MEMORY_ENTRY), 'MENT');
		memEntry->pUsermodeVirtualAddress = ifp;
		//ULONG ctlCode = NETMAP_KERNEL_TEST_INJECT_PING;
		/*ULONG ctlCode = NETMAP_KERNEL_DEVICE_RX_REGISTER;
		if (!amIRegisteringTheInterface)
		{
			ctlCode = NETMAP_KERNEL_DEVICE_RX_UNREGISTER;
		}*/
		PIRP pIrp = IoBuildDeviceIoControlRequest(NETMAP_KERNEL_TEST_INJECT_PING,
				pNdisObj, //pNdisObj,
				NULL,
				0,
				NULL,
				0,
				TRUE,
				NULL,
				&iosb);
		
		/*PIRP pIrp = IoBuildDeviceIoControlRequest(ctlCode,
			pNdisObj,
			memEntry,
			sizeof(MEMORY_ENTRY),
			NULL,
			0,
			TRUE,
			NULL,
			&iosb);*/
		FirstIrql = KeGetCurrentIrql();
		if (FirstIrql > PASSIVE_LEVEL)
		{
			KeLowerIrql(PASSIVE_LEVEL);
		}
		NtStatus = IoCallDriver(pNdisObj, pIrp);	
		if (KeGetCurrentIrql() != FirstIrql)
		{
			KeRaiseIrql(FirstIrql, &FirstIrql);
		}
		
		ExFreePoolWithTag(memEntry, 'MENT');
		//ObDereferenceObject(pNdisObj);
		ObDereferenceObject(pFileObject);
		if NT_SUCCESS(NtStatus)
		{
			return STATUS_SUCCESS;
		}
	}
	return NtStatus;
#endif
}

struct NET_BUFFER* windows_generic_rx_handler(struct net_device* nd, uint32_t length, const char* data)
{
	struct mbuf m;	
	m.m_len = length;
	m.pkt = NULL; //ExAllocatePoolWithTag(NonPagedPool, length, 'test');
	m.dev = nd;
	//RtlCopyBytes(m.pkt, data, length);
	generic_rx_handler(nd, &m);
	return NULL;
}

int netmap_catch_rx(struct netmap_adapter *na, int intercept)
{
	if (intercept) {
		return netdev_rx_handler_register(na->ifp, TRUE);
	}
	else {
		netdev_rx_handler_register(na->ifp, FALSE);
		return 0;
	}
	return 0;
}

/* We don't need to do anything here */
void netmap_catch_tx(struct netmap_generic_adapter *gna, int enable)
{
	if (enable) {
		
	}
	else {
		
	}
}

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
and -1 on error (which may be packet drops or other errors). */
int generic_xmit_frame(struct ifnet *ifp, struct mbuf *m,
	void *addr, u_int len, u_int ring_nr)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;

	if (NT_SUCCESS(NtStatus)) {
		return 0;
	}else{
		/* If something goes wrong in the TX path, there is nothing
		intelligent we can do (for now) apart from error reporting. */
		return -1;
	}
}

int generic_find_num_desc(struct ifnet *ifp, u_int *tx, u_int *rx)
{
	//XXX_ale: find where the rings are descripted (OID query)
	*tx = 256;
	*rx = 256;
	return 0;
}
void generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
	//XXX_ale: for a generic device is enough? need to find where this info is
	*txq = 1;
	*rxq = 1;
}
//

void sendPingInternal()
{
#if 0
	OBJECT_ATTRIBUTES   objectAttributes;
	UNICODE_STRING      ObjectName;
	IO_STATUS_BLOCK		iosb;
	PFILE_OBJECT		pFileObject = NULL;
	PDEVICE_OBJECT		pNdisObj;
	NTSTATUS Status;
	RtlInitUnicodeString(&ObjectName, NETMAP_NDIS_LINKNAME_STRING);
	InitializeObjectAttributes(&objectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &pFileObject, &pNdisObj);
	if (NT_SUCCESS(Status))
	{
		PIRP pIrp = NULL;
		pIrp = IoBuildDeviceIoControlRequest(NETMAP_KERNEL_TEST_INJECT_PING,
			pNdisObj,
			NULL,
			0,
			NULL,
			0,
			TRUE,
			NULL,
			&iosb);
		IoCallDriver(pNdisObj, pIrp);
		ObDereferenceObject(pFileObject);
		//ObDereferenceObject(pNdisObj);
	}
#endif
	g_functionAddresses.pingPacketInsertionTest();
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
	case NETMAP_KERNEL_TEST_INJECT_PING:
		//DbgPrint("Netmap.sys: NETMAP_KERNEL_TEST_INJECT_PING\n");
		sendPingInternal();
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

int getDeviceIfIndex(const char* name)
{
	int found = FALSE;
	int result = 0;
	int i = 0;
	while (name[i] != '\0' && name[i]!=' ')
	{
		if (name[i] >= '0' && name[i] <= '9')
		{
			found = TRUE;
			result = result * 10;
			result += (name[i] - '0');
		}
		i++;
	}
	if (!found)
	{
		result = -1;
	}
	DbgPrint("Netmap.sys: Requested interface ifIndex: %i", result);
	return result;
}

struct net_device* dev_get_by_name(const char* name)
{
	NDIS_INTERNAL_DEVICE_HANDLER	exchangeBuffer;
	NDIS_HANDLE						temp = NULL;
	struct net_device*				nd = NULL;
	exchangeBuffer.deviceHandle = NULL;
	exchangeBuffer.deviceIfIndex = getDeviceIfIndex(name);

	if (g_functionAddresses.get_device_handle_by_ifindex != NULL)
	{
		temp = g_functionAddresses.get_device_handle_by_ifindex(&exchangeBuffer);
		if (temp != NULL)
		{
			nd = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct net_device), 'NDEV');
			RtlZeroMemory(nd, sizeof(struct net_device));
			RtlCopyMemory(nd->if_xname, name, IFNAMSIZ);
			nd->deviceHandle = temp; // exchangeBuffer.deviceHandle;
			nd->ifIndex = exchangeBuffer.deviceIfIndex;
			return nd;
		}else{
			return NULL;
		}
		
	}
	else{
		return NULL;
	}
#if 0
	OBJECT_ATTRIBUTES				objectAttributes;
	UNICODE_STRING					ObjectName;
	IO_STATUS_BLOCK					iosb;
	PFILE_OBJECT					pFileObject = NULL;
	PDEVICE_OBJECT					pNdisObj	= NULL;
	NTSTATUS						Status;
	

	KIRQL FirstIrql = KeGetCurrentIrql();
	
		
	exchangeBuffer.deviceHandle = NULL;
	exchangeBuffer.deviceIfIndex = getDeviceIfIndex(name);

	if (exchangeBuffer.deviceIfIndex > -1)
	{	
		RtlInitUnicodeString(&ObjectName, NETMAP_NDIS_LINKNAME_STRING);
		InitializeObjectAttributes(&objectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (FirstIrql > PASSIVE_LEVEL)
		{
			KeLowerIrql(PASSIVE_LEVEL);
		}
		Status = IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &pFileObject, &pNdisObj);
		if (KeGetCurrentIrql() != FirstIrql)
		{
			KeRaiseIrql(FirstIrql, &FirstIrql);
		}
		//Status = SetNDISDeviceReferences();
		if (NT_SUCCESS(Status))
		{
			PIRP pIrp = IoBuildDeviceIoControlRequest(NETMAP_KERNEL_GET_DEV_BY_NAME,
				pNdisObj,
				&exchangeBuffer,
				sizeof(NDIS_INTERNAL_DEVICE_HANDLER),
				&exchangeBuffer,
				sizeof(NDIS_INTERNAL_DEVICE_HANDLER),
				TRUE,
				NULL,
				&iosb);
			FirstIrql = KeGetCurrentIrql();
			if (FirstIrql > PASSIVE_LEVEL)
			{
				KeLowerIrql(PASSIVE_LEVEL);
			}
			Status = IoCallDriver(pNdisObj, pIrp);
			if (KeGetCurrentIrql() != FirstIrql)
			{
				KeRaiseIrql(FirstIrql, &FirstIrql);
			}

			ObDereferenceObject(pFileObject);

			//ObDereferenceObject(pFileObject);
			//ObDereferenceObject(pNdisObj);
			if (NT_SUCCESS(Status))
			{
				nd = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct net_device), 'NDEV');
				if (nd != NULL)
				{
					RtlZeroMemory(nd, sizeof(struct net_device));
					RtlCopyMemory(nd->if_xname, name, IFNAMSIZ);
					nd->deviceHandle = exchangeBuffer.deviceHandle;
					nd->ifIndex = exchangeBuffer.deviceIfIndex;
					return nd;
				}			
			}
		}
	}		
	return NULL;
#endif
}

NTSTATUS ioctlInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	FUNCTION_POINTER_XCHANGE *data;
	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		case NETMAP_KERNEL_XCHANGE_POINTERS:
			data = Irp->AssociatedIrp.SystemBuffer;
			data->windows_generic_rx_handler = &windows_generic_rx_handler;

			g_functionAddresses.pingPacketInsertionTest = data->pingPacketInsertionTest;
			g_functionAddresses.get_device_handle_by_ifindex = data->get_device_handle_by_ifindex;
			g_functionAddresses.set_ifp_in_device_handle = data->set_ifp_in_device_handle;

			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, data, sizeof(FUNCTION_POINTER_XCHANGE));
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

#if 0
NTSTATUS ReadSync(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("Netmap.sys: ReadSync invoked\n");
	NTSTATUS NtStatus = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}
NTSTATUS WriteSync(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DbgPrint("Netmap.sys: WriteSync invoked\n");
	NTSTATUS NtStatus = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}
#endif
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
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = ioctlInternalDeviceControl;
	//DriverObject->MajorFunction[IRP_MJ_READ] = ReadSync;
	//DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteSync;
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
#ifdef _WIN32
	return dev_get_by_name(name);
#else
#ifndef NETMAP_LINUX_HAVE_INIT_NET
	return dev_get_by_name(name);
#else
	void *ns = &init_net;
#ifdef CONFIG_NET_NS
	ns = current->nsproxy->net_ns;
#endif
	return dev_get_by_name(ns, name);
#endif
#endif //_WIN32
}

void if_rele(struct net_device *ifp)
{

}
