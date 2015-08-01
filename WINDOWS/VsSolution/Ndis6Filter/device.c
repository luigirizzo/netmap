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
    PVOID			pOutBuff = NULL;
    MEMORY_ENTRY		*memEntry = NULL;
    struct net_device		*ifp = NULL;

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
	memset(buf, sizeof(buf), ' ');
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
 * ndis_update_ifp
 *
 * In netmap we identify interfaces by ifindex, this function translates
 * it to the parameter required by NDIS calls and the buffer pool to
 * be used for transmissions XXX
 *
 * XXX change as follows:
 the function receives the net_device pointer,
 looks up the device (by index/string/whatever)
 grabs a reference
 stores in ifp the following fields:
	- pFilter
	- &pFilter->readyToUse so we can enable/disable it while keeping pfilter opaque

 * It does not matter if the call is expensive, it is only done when
 * during a NIOCREGIF
 *
 * Returns: NTSTATUS - STATUS_SUCCESS interface found, other value error
 *
 * _IN_	int	deviceIfIndex	ifIndex of the network adapter (visible with Get-NetAdapter under powershell)
 * _OUT_ net_device* 	ifp	netmap structure referring the adapter
 */
NTSTATUS 
ndis_update_ifp(int deviceIfIndex, struct net_device *ifp)
{
    PLIST_ENTRY         Link;
    int			counter = 0;
    NTSTATUS	status = STATUS_DEVICE_DOES_NOT_EXIST; // default return value

    // XXX check whether we need counter. If the list is bidirectional
    // but not circular we should not need it.

    FILTER_ACQUIRE_LOCK(&FilterListLock, FALSE);
    for (Link = FilterModuleList.Flink; (Link != NULL && counter < FilterModulesCount);
	    counter++, Link = Link->Flink) {
	PMS_FILTER pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

	//DbgPrint("IfIndex: %i, NDIS_HANDLE: %p\n", pFilter->MiniportIfIndex, pFilter->FilterHandle);
	if (pFilter->MiniportIfIndex == deviceIfIndex) {
	    // XXX should increment pFilter->RefCount before release
	    // and decrement on release
	    ifp->pfilter = pFilter;  
	    ifp->pfilter_ready = &pFilter->readyToUse;
	    pFilter->ifp = ifp;
	    status = STATUS_SUCCESS;
	    break;
	}
    }
    FILTER_RELEASE_LOCK(&FilterListLock, FALSE);
    return status;
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
 */
NTSTATUS 
injectPacket(PVOID _pfilter, PVOID data, uint32_t length, BOOLEAN sendToMiniport)
{
    PVOID			buffer = NULL;
    PMDL			pMdl = NULL;
    PNET_BUFFER_LIST		pBufList = NULL;
    PNET_BUFFER			pFirst = NULL;
    PVOID			pNdisPacketMemory = NULL;
    NTSTATUS			status = STATUS_SUCCESS;
    PMS_FILTER			pfilter = (PMS_FILTER)_pfilter;

    do {
	buffer = ExAllocatePoolWithTag(NonPagedPool, length, 'NDIS');
	if (buffer == NULL) {
	    DbgPrint("Error allocating buffer!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}
	RtlZeroMemory(buffer, length);
	pMdl = NdisAllocateMdl(pfilter->FilterHandle, buffer, length);
	if (pMdl == NULL) {
	    DbgPrint("nmNdis.sys: Error allocating MDL!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	pMdl->Next = NULL;

	pBufList = NdisAllocateNetBufferAndNetBufferList(pfilter->UserSendNetBufferListPool,
		    0, 0,
		    pMdl, 0,
		    length);
	if (pBufList == NULL) {
	    NdisFreeMdl(pMdl);
	    DbgPrint("nmNdis.sys: Error allocating NdisAllocateNetBufferAndNetBufferList!\n");
	    status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}
	pFirst = NET_BUFFER_LIST_FIRST_NB(pBufList);
	pNdisPacketMemory = NdisGetDataBuffer(pFirst, length, NULL, sizeof(UINT8), 0);
	// XXX is this the same as buffer ?
	if (pNdisPacketMemory == NULL) {
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
	pBufList->SourceHandle = pfilter->FilterHandle;
	if (sendToMiniport) {
	    //This send down to the miniport
	    NdisFSendNetBufferLists(pfilter->FilterHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 0);
	} else {
	    //This one send up to the OS
	    NdisFIndicateReceiveNetBufferLists(pfilter->FilterHandle, pBufList, NDIS_DEFAULT_PORT_NUMBER, 1, 0);
	}	
    } while (FALSE);

    // XXX not sure if we can free the buffer with regular returns.
    // if so, what is the buffer for ?
#if 1
    if (buffer != NULL) {
	ExFreePoolWithTag(buffer, 'NDIS');
    }
#endif
    return status;
}
