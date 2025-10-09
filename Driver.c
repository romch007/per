#include <ntddk.h>

NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);

    KdPrint(("Goodbye World!\n"));
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    
    KdPrint(("Hello World!\n"));
    driverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}