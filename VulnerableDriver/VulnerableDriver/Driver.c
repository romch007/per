#include <ntddk.h>
#include <wdf.h>

#include "IOCTL.h"

const char* PONG = "PONG";

VOID VulnDriverIoDeviceControl(
    WDFQUEUE queue,
    WDFREQUEST request,
    size_t outputBufferLength,
    size_t inputBufferLength,
    ULONG ioControlCode
) {
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(outputBufferLength);
    UNREFERENCED_PARAMETER(inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;

    switch (ioControlCode) {
    case IOCTL_PING: {
        PUINT32 inValue = NULL;
        PUINT32 outValue = NULL;
        SIZE_T inSize = 0;
        SIZE_T outSize = 0;

        status = WdfRequestRetrieveInputBuffer(request, sizeof(UINT32), (PVOID*)&inValue, &inSize);
        if (!NT_SUCCESS(status))
            break;

        status = WdfRequestRetrieveOutputBuffer(request, sizeof(UINT32), (PVOID*)&outValue, &outSize);
        if (!NT_SUCCESS(status))
            break;

        *outValue = *inValue + 1;

        WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(UINT32));
        return;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestComplete(request, status);
}

NTSTATUS VulnDriverCreateDevice(WDFDRIVER driver, PWDFDEVICE_INIT deviceInit) {
    UNREFERENCED_PARAMETER(driver);

    NTSTATUS status;
	WDFDEVICE device;
	WDF_IO_QUEUE_CONFIG queueConfig;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\VulnDriver");

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status))
        return status;

	status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\VulnDriver");

    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status))
        return status;

	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);

    queueConfig.EvtIoDeviceControl = VulnDriverIoDeviceControl;

	return WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
}


NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
	UNREFERENCED_PARAMETER(driverObject);

	KdPrint(("[Vulnerable Driver] Unloaded"));

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);

	KdPrint(("[Vulnerable Driver] Loaded"));
	driverObject->DriverUnload = DriverUnload;

	WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, VulnDriverCreateDevice);

	NTSTATUS ret = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	return ret;
}