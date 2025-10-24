#include <ntddk.h>

#include "Trigger.h"

NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);

    Cleanup();
    KdPrint(("[PER driver] Unloaded\n"));

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    
    KdPrint(("[PER driver] Loaded\n"));
    driverObject->DriverUnload = DriverUnload;

    NTSTATUS status = WfpInit(driverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[PER Driver] Failed to init WFP\n"));
        return status;
    }

    return STATUS_SUCCESS;
}