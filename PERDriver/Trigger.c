#include "Trigger.h"         // Include the trigger header file

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
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    // Packet parsing logic goes here...
    KdPrint(("[PER Driver] Received a packet!\n"));
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