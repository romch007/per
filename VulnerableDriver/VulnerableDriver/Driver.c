#include <ntddk.h>
#include <wdf.h>

#include "IOCTL.h"

const char* PONG = "PONG";

VOID VulnDriverIoDeviceControl(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _In_ size_t inputBufferLength,
    _In_ ULONG ioControlCode
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

WDFDEVICE gControlDevice;

NTSTATUS VulnDriverCreateDevice(_In_ WDFDRIVER wdfDriver) {
    NTSTATUS status;
	WDFDEVICE device;
	WDF_IO_QUEUE_CONFIG queueConfig;

    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(wdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\VulnDriver");

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: WdfDeviceInitAssignName failed: 0x%x\n", status));
        return status;
    }

	status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: WdfDeviceCreate failed: 0x%x\n", status));
        return status;
    }
    
    KdPrint(("[Vulnerable Driver] WDF device created\n"));

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\VulnDriver");

    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: WdfDeviceCreateSymbolicLink failed: 0x%x\n", status));
        return status;
    }

    KdPrint(("[Vulnerable Driver] WDF symlink created\n"));

	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);

    queueConfig.EvtIoDeviceControl = VulnDriverIoDeviceControl;

	status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: WdfIoQueueCreate failed: 0x%x\n", status));
        return status;
    }

    WdfControlFinishInitializing(device);
    
    gControlDevice = device;

    KdPrint(("[Vulnerable Driver] Control device created"));

    return STATUS_SUCCESS;
}


NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
	UNREFERENCED_PARAMETER(driverObject);

	KdPrint(("[Vulnerable Driver] Unloaded\n"));

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);

	KdPrint(("[Vulnerable Driver] Loaded\n"));
	driverObject->DriverUnload = DriverUnload;

	WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    WDFDRIVER wdfDriver;

	NTSTATUS status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &wdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: WdfDriverCreated failed: 0x%x\n", status));
        return status;
    }

	KdPrint(("[Vulnerable Driver] WDF driver created\n"));

    status = VulnDriverCreateDevice(wdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Vulnerable Driver] Error: VulnDriverCreateDevice failed: 0x%x\n", status));
        return status;
    }

	return STATUS_SUCCESS;
}