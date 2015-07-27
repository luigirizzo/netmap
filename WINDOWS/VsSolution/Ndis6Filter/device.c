/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"


#pragma NDIS_INIT_FUNCTION(FilterRegisterDevice)


_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
FilterRegisterDevice(
    VOID
    )
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;

    DEBUGP(DL_TRACE, "==>FilterRegisterDevice\n");

    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));

    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;
    DispatchTable[IRP_MJ_INTERNAL_DEVICE_CONTROL] = FilterInternalDeviceIoControl;

    NdisInitUnicodeString(&DeviceName, NETMAP_NDIS_NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, NETMAP_NDIS_LINKNAME_STRING);

    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);

    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &DeviceObject,
                &NdisFilterDeviceHandle
                );


    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);

        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;
    }


    DEBUGP(DL_TRACE, "<==FilterRegisterDevice: %x\n", Status);

    return (Status);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FilterDeregisterDevice(
    VOID
    )

{
    DbgPrint("NmNDIS.sys: FilterDeregisterDevice\n");
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
FilterDispatch(
    PDEVICE_OBJECT       DeviceObject,
    PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
FilterInternalDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
	PIO_STACK_LOCATION				IrpSp;
	NTSTATUS						NtStatus = STATUS_SUCCESS;
	PVOID							pOutBuff = NULL;
	MEMORY_ENTRY					*memEntry = NULL;
	struct net_device				*ifp = NULL;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
		default:
			DbgPrint("Netmap.sys: wrong request issued! (%i)", IrpSp->Parameters.DeviceIoControl.IoControlCode);
			NtStatus = STATUS_INVALID_DEVICE_REQUEST;
	}
	Irp->IoStatus.Status = NtStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return NtStatus;
}

_Use_decl_annotations_
NTSTATUS
FilterDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;


    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("------------------FilterDeviceIoControl!\n");

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');

    Irp->IoStatus.Information = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {

        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {

                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:

            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;


            pInfo = OutputBuffer;

            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

            Link = FilterModuleList.Flink;

            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);


                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));

                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT),
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);

                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }

                Link = Link->Flink;
            }

            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {

                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;


        default:
	    DbgPrint("WRONG request received!\n");
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;


}


_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
    _In_reads_bytes_(BufferLength)
         PUCHAR                   Buffer,
    _In_ ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;

   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

   Link = FilterModuleList.Flink;

   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }

       Link = Link->Flink;
   }

   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}



/*********************************************************
*        	FUNCTIONS CALLED BY NETMAP DRIVER   		 *
**********************************************************/

void DumpPayload(char* p, uint32_t len)
{
	char buf[128];
	int i ,j,i0;
	DbgPrint("p: 0x%p - len: %i", p, len);
	for (i = 0; i < len;) {
		memset(buf, sizeof(buf), ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf + 7 + j * 3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf + 7 + j + 48, "%c", (p[i] >= 32 && p[i]<=127) ? p[i] : '.');
		DbgPrint("%s\n", buf);
	}
}

unsigned char ethPingPacket[74] =
{ 0x00, 0x1b, 0x21, 0x44, 0x25, 0x34, 0x00, 0x15,
0x5d, 0xc4, 0x37, 0x00, 0x08, 0x00, 0x45, 0x00,
0x00, 0x3c, 0x0d, 0x48, 0x00, 0x00, 0x80, 0x01,
0x00, 0x00, 0x0a, 0xd8, 0x01, 0x9a, 0x0a, 0xd8,
0x01, 0x68, 0x08, 0x00, 0x4d, 0x46, 0x00, 0x01,
0x00, 0x15, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
0x68, 0x69 };
PMS_FILTER              pFilterPing = NULL;

void pingPacketInsertionTest()
{
	int counter = 0;
	PLIST_ENTRY             Link = NULL;
	//PMS_FILTER              pFilter = NULL;
	NDIS_HANDLE				moduleHandle = NULL;

	NDIS_HANDLE				pool;

	PVOID					buffer = NULL;
	PMDL					pMdl = NULL;
	PNET_BUFFER_LIST		pBufList = NULL;
	PNET_BUFFER				pFirst = NULL;
	PVOID					pNdisPacketMemory = NULL;
	int						txSize = 74;

	if (pFilterPing == NULL)
	{
		FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
		Link = FilterModuleList.Flink;
		while (Link != NULL && counter<FilterModulesCount)
		{
			pFilterPing = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
			//DbgPrint("IfIndex: %i, NDIS_HANDLE: %p\n", pFilter->MiniportIfIndex, pFilter->FilterHandle);
			Link = Link->Flink;
			counter += 1;
			moduleHandle = pFilterPing->FilterHandle;
			break;
		}
		FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
	}
	else
	{
		moduleHandle = pFilterPing->FilterHandle;
	}

	buffer = ExAllocatePoolWithTag(NonPagedPool, txSize, 'NDIS');
	if (buffer == NULL)
	{
		DbgPrint("Error allocating buffer!\n");
		return;
	}
	RtlZeroMemory(buffer, txSize);
	pMdl = NdisAllocateMdl(FilterDriverHandle, buffer, txSize);
	if (pMdl == NULL)
	{
		DbgPrint("Error allocating MDL!\n");
		return;
	}
	pMdl->Next = NULL;

	pBufList = NdisAllocateNetBufferAndNetBufferList(pFilterPing->UserSendNetBufferListPool,
		0, 0,
		pMdl, 0,
		txSize);
	if (pBufList == NULL)
	{
		DbgPrint("Error allocating NdisAllocateNetBufferAndNetBufferList!\n");
		return;
	}
	pFirst = NET_BUFFER_LIST_FIRST_NB(pBufList);
	pNdisPacketMemory = NdisGetDataBuffer(pFirst, txSize, NULL, sizeof(UINT8), 0);
	if (pNdisPacketMemory == NULL)
	{
		DbgPrint("Error allocating pNdisPacketMemory!\n");
		return;
	}

	NdisMoveMemory(pNdisPacketMemory, ethPingPacket, txSize);

	pBufList->SourceHandle = pFilterPing->FilterHandle;
	//This send down to the miniport
	NdisFSendNetBufferLists(moduleHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 0); // Send Flags );

	//This one send up to the OS
	//NdisFIndicateReceiveNetBufferLists(moduleHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 1, 0); // Send Flags );

	//NdisFreeMdl(pMdl);
	//NdisFreeMemoryWithTagPriority(FilterDriverHandle, buffer, 'TAGT');
	ExFreePoolWithTag(buffer, 'NDIS');
}

/*get_device_handle_by_ifindex - get the necessary structures to catch/inject packets from/into a generic interface

Return:	NDIS_HANDLE									//handle of the required network adapter

_IN_	int deviceIfIndex							//ifIndex of the network adapter (visible with Get-NetAdapter under powershell)
_OUT_	PNDIS_HANDLE	UserSendNetBufferListPool	//handle of the transmission pool
*/
NDIS_HANDLE get_device_handle_by_ifindex(int deviceIfIndex, PNDIS_HANDLE UserSendNetBufferListPool)
{
	NTSTATUS				NtStatus = STATUS_SUCCESS;
	PLIST_ENTRY             Link = NULL;
	PMS_FILTER              pFilter = NULL;
	int						counter = 0;

	FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
	Link = FilterModuleList.Flink;
	while (Link != NULL && counter<FilterModulesCount)
	{
		pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
		//DbgPrint("IfIndex: %i, NDIS_HANDLE: %p\n", pFilter->MiniportIfIndex, pFilter->FilterHandle);
		if (pFilter->MiniportIfIndex == deviceIfIndex)
		{
			FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
			*UserSendNetBufferListPool = pFilter->UserSendNetBufferListPool;
			return pFilter->FilterHandle;
		}
		else{
			Link = Link->Flink;
			counter += 1;
		}
	}
	FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
	return NULL;
}

/*set_ifp_in_device_handle - called from Netmap driver to start to intercept 
							packets and detach a network adapter from the network stack

Return:	nothing

_IN_	net_device *ifp						//pointer to the descriptor of the network adapter
_IN_	BOOLEAN amISettingTheHandler		//TRUE start to catch packets, FALSE stops

*/
void set_ifp_in_device_handle(struct net_device *ifp, BOOLEAN amISettingTheHandler)
{
	NTSTATUS				NtStatus = STATUS_SUCCESS;
	PLIST_ENTRY             Link = NULL;
	PMS_FILTER              pFilter = NULL;
	int						counter = 0;

	FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
	Link = FilterModuleList.Flink;
	while (Link != NULL && counter<FilterModulesCount)
	{
		pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
		if (pFilter->MiniportIfIndex == ifp->ifIndex)
		{
			if (amISettingTheHandler)
			{
				pFilter->ifp = ifp;
				pFilter->readyToUse = TRUE;
			}
			else{
				pFilter->readyToUse = FALSE;
				pFilter->ifp = NULL;
			}
			break;
		}
		else{
			Link = Link->Flink;
			counter += 1;
		}
	}
	FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
}

/*injectPacket - called from Netmap driver to inject a packet

Return: NTSTATUS - STATUS_SUCCESS packet injected, other value error

_IN_ NDIS_HANDLE deviceHandle,					//handle of the network adapter
_IN_ NDIS_HANDLE UserSendNetBufferListPool,		//handle of the transmission pool
_IN_ PVOID data,								//data to be injected
_IN_ uint32_t length							//length of the data to be injected
_IN_ BOOLEAN sendToMiniport						//TRUE send to miniport driver, FALSE send to OS stack (protocol driver)
*/
NTSTATUS injectPacket(NDIS_HANDLE deviceHandle, NDIS_HANDLE UserSendNetBufferListPool, PVOID data, uint32_t length, BOOLEAN sendToMiniport)
{
	PVOID					buffer = NULL;
	PMDL					pMdl = NULL;
	PNET_BUFFER_LIST		pBufList = NULL;
	PNET_BUFFER				pFirst = NULL;
	PVOID					pNdisPacketMemory = NULL;
	NTSTATUS				status = STATUS_SUCCESS;

	do
	{
		buffer = ExAllocatePoolWithTag(NonPagedPool, length, 'NDIS');
		if (buffer == NULL)
		{
			DbgPrint("Error allocating buffer!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(buffer, length);
		pMdl = NdisAllocateMdl(deviceHandle, buffer, length);
		if (pMdl == NULL)
		{
			DbgPrint("nmNdis.sys: Error allocating MDL!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		pMdl->Next = NULL;

		pBufList = NdisAllocateNetBufferAndNetBufferList(UserSendNetBufferListPool,
			0, 0,
			pMdl, 0,
			length);
		if (pBufList == NULL)
		{
			NdisFreeMdl(pMdl);
			DbgPrint("nmNdis.sys: Error allocating NdisAllocateNetBufferAndNetBufferList!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		pFirst = NET_BUFFER_LIST_FIRST_NB(pBufList);
		pNdisPacketMemory = NdisGetDataBuffer(pFirst, length, NULL, sizeof(UINT8), 0);
		if (pNdisPacketMemory == NULL)
		{
			NdisFreeNetBufferList(pBufList);
			NdisFreeMdl(pMdl);
			DbgPrint("nmNdis.sys: Error allocating pNdisPacketMemory!\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		NdisMoveMemory(pNdisPacketMemory, data, length);
#if 0
		DumpPayload(pNdisPacketMemory, length);
#endif
		pBufList->SourceHandle = deviceHandle;
		if (sendToMiniport)
		{
			//This send down to the miniport
			NdisFSendNetBufferLists(deviceHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 0);
		}
		else
		{
			//This one send up to the OS
			NdisFIndicateReceiveNetBufferLists(deviceHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 1, 0);
		}	
	} while (FALSE);
	if (buffer != NULL)
	{
		ExFreePoolWithTag(buffer, 'NDIS');
	}
	return status;
}
