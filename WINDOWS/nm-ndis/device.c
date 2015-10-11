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


/*
 * We use an internal ioctl to make modules communicate with each other
 * within the kernel.
 * At the moment we do not have any supported function
 */
_Use_decl_annotations_
NTSTATUS
FilterInternalDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
    PIO_STACK_LOCATION		IrpSp;
    NTSTATUS			NtStatus = STATUS_SUCCESS;

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



/*
 *  FUNCTIONS CALLED BY NETMAP DRIVER
 *
 * These are written using the netmap code style
 */


/*
 * helper function mostly used for debugging, hexump of a block of memory
 */
void 
DumpPayload(const char* p, uint32_t len)
{
    char buf[128];
    int i ,j,i0;

    DbgPrint("p: 0x%p - len: %i", p, len);

    for (i = 0; i < len;) {
	memset(buf, ' ', sizeof(buf));
	sprintf(buf, "%5d: ", i);
	i0 = i; /* save source offset */
	for (j = 0; j < 16 && i < len; i++, j++)
	    sprintf(buf + 7 + j * 3, "%02x ", (uint8_t)(p[i]));
	i = i0; /* restore source offset */
	for (j = 0; j < 16 && i < len; i++, j++)
	    sprintf(buf + 7 + j + 48, "%c", (p[i] >= 32 && p[i]<=127) ? p[i] : '.');
	DbgPrint("%s\n", buf);
    }
}


/*
 * ndis_regif
 *
 * In netmap we identify interfaces by ifindex, this function writes
 * in the ifp the pointers to the filter and to the variable
 * used to enable/disable the filter.
 * It does not matter if the call is expensive, it is only done when
 * during a NIOCREGIF
 *
 * Returns: NTSTATUS - STATUS_SUCCESS interface found, other value error
 */
NTSTATUS 
ndis_regif(struct net_device *ifp)
{
    PLIST_ENTRY         Link;
    NTSTATUS	status = STATUS_DEVICE_DOES_NOT_EXIST; // default return value

    /* the list is bidirectional and circular */

    FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
    for (Link = FilterModuleList.Flink; Link != &FilterModuleList; Link = Link->Flink) {
	PMS_FILTER pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

	//DbgPrint("IfIndex: %i, NDIS_HANDLE: %p\n", pFilter->MiniportIfIndex, pFilter->FilterHandle);
	if (pFilter->MiniportIfIndex == ifp->ifIndex) {
	    pFilter->RefCount++;
	    DbgPrint("pfilter %p refcount %d\n", pFilter, pFilter->RefCount);
	    ifp->pfilter = pFilter;  
	    ifp->intercept = &pFilter->intercept;
	    pFilter->ifp = ifp;
	    status = STATUS_SUCCESS;
	    break;
	}
    }
    FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
    return status;
}

NTSTATUS
ndis_rele(struct net_device *ifp)
{
	PMS_FILTER pFilter = ifp->pfilter;
	FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
	pFilter->RefCount--;
	DbgPrint("pfilter %p refcount %d\n", pFilter, pFilter->RefCount);
	FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
	return STATUS_SUCCESS;
}

/*
 * injectPacket - called from Netmap driver to inject a packet
 *
 * Return: NTSTATUS - STATUS_SUCCESS packet injected, other value error
 *
 * _IN_ PVOID _pfilter			pointer to the MS_FILTER structure of the network adapter
 * _IN_ PVOID data,			data to be injected
 * _IN_ uint32_t length			length of the data to be injected
 * _IN_ BOOLEAN sendToMiniport		TRUE send to miniport driver, FALSE send to OS stack (protocol driver)
 *
 * XXX TODO
 * if data == NULL prev indicates the list of packets to send out
 *		returns prev on success, NULL on failure
 *
 * if data != NULL creates a packet, appends to prev,
 *		returns packet on success, NULL on failure
 */
PVOID 
injectPacket(PVOID _pfilter, PVOID data, uint32_t length, BOOLEAN sendToMiniport, PNET_BUFFER_LIST prev)
{
    PVOID			buffer = NULL;
    PMDL			pMdl = NULL;
    PNET_BUFFER_LIST		pBufList = NULL;
    PNET_BUFFER			pFirst = NULL;
    PVOID			pNdisPacketMemory = NULL;
    NTSTATUS			status = STATUS_SUCCESS;
    PMS_FILTER			pfilter = (PMS_FILTER)_pfilter;

	if (sendToMiniport && (pfilter->current_tx_pending_packets_to_miniport > 1024))
	{
		return NULL;
	}
    do {
		if (data == NULL && prev != NULL) {
			pBufList = prev;
			goto sendOut;
		}
		if (data == NULL)
			return NULL;
	/*
	 * we construct a pool+packet+mdl from the data we receive from above
	 */
	buffer = ExAllocateFromNPagedLookasideList(&pfilter->netmap_injected_packets_pool);
	if (buffer == NULL) {
		DbgPrint("Error allocating buffer!\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		break;
	}

	// RtlZeroMemory(buffer, length); // we copy data, anyways
	/* attach the buffer to a newly allocated mdl */
	pMdl = NdisAllocateMdl(pfilter->FilterHandle, buffer, length);
	if (pMdl == NULL) {
	    DbgPrint("nmNdis.sys: Error allocating MDL!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	pMdl->Next = NULL;

	/* allocate a buffer list */
	pBufList = NdisAllocateNetBufferAndNetBufferList(pfilter->netmap_pool,
		    0, 0,
		    pMdl, 0,
		    length);
	if (pBufList == NULL) {
	    DbgPrint("nmNdis.sys: Error allocating NdisAllocateNetBufferAndNetBufferList!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	pFirst = NET_BUFFER_LIST_FIRST_NB(pBufList);
	pNdisPacketMemory = NdisGetDataBuffer(pFirst, length, NULL, sizeof(UINT8), 0);
	// pNdisPacketMemory is the same as buffer
	if (pNdisPacketMemory == NULL) {
	    DbgPrint("nmNdis.sys: weird, bad pNdisPacketMemory!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	NdisMoveMemory(pNdisPacketMemory, data, length);
#if 0
	DumpPayload(pNdisPacketMemory, length);
#endif
	pBufList->SourceHandle = pfilter->FilterHandle;
	if (prev != NULL) {
		prev->Next = pBufList;
	}
	return pBufList;

sendOut:
	{
		int nblNumber = 1; /*keep this for future differences between nbl number and packet number*/
		int pckCount = 1;
		{
			PNET_BUFFER_LIST temp = prev;
			while (temp->Next != NULL) {
				temp = temp->Next;
				nblNumber++;
				pckCount++;
			}
		}
		if (sendToMiniport) {
			// This send down to the NIC (miniport)
			// eventually triggering the callback FilterSendNetBufferListsComplete()
			// XXX check ownership of the packet. By default the packet stays alive until
			// we receive the callback
			NdisFSendNetBufferLists(pfilter->FilterHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 0);
			InterlockedAdd(&pfilter->current_tx_pending_packets_to_miniport, pckCount);
		}
		else {
			// This one sends up to the OS, again eventually triggering
			// FilterReturnNetBufferLists()
			NdisFIndicateReceiveNetBufferLists(pfilter->FilterHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, nblNumber, 0);
		}
	}
    } while (FALSE);
    if (status != STATUS_SUCCESS) {
	if (pBufList)
	    NdisFreeNetBufferList(pBufList);
	if (pMdl)
	    NdisFreeMdl(pMdl);
	if (buffer)
		ExFreeToNPagedLookasideList(&pfilter->netmap_injected_packets_pool, buffer);
	return NULL;
    }

	return pBufList;
}
