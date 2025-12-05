#include <ntddk.h>
#include <wdf.h>

#include "IOCTL.h"

const char* PONG = "PONG";

NTSTATUS ReadMemory(PHYSICAL_ADDRESS* systemBuffer, UINT32 inputBufferSize, VOID* outputBuffer, UINT32 outputBufferSize, VOID* unused) {
    UNREFERENCED_PARAMETER(unused);

    if (inputBufferSize != 16)
        return STATUS_INVALID_PARAMETER;

    UINT32 numberOfBytes = systemBuffer[1].HighPart * systemBuffer[1].LowPart;

    if (outputBufferSize < numberOfBytes)
        return STATUS_INVALID_PARAMETER;

    UINT32* baseAddress = MmMapIoSpace(*systemBuffer, numberOfBytes, MmNonCached);

    RtlCopyMemory(outputBuffer, baseAddress, systemBuffer[1].HighPart);

    MmUnmapIoSpace(baseAddress, numberOfBytes);

    return STATUS_SUCCESS;
}

NTSTATUS WriteMemory(PHYSICAL_ADDRESS* inputBuffer, UINT32 inputBufferSize, VOID* unused1, VOID* unused2, VOID* unused3) {
    UNREFERENCED_PARAMETER(unused1);
    UNREFERENCED_PARAMETER(unused2);
    UNREFERENCED_PARAMETER(unused3);

    if (inputBufferSize < 16)
        return STATUS_INVALID_PARAMETER;

    UINT32 numberOfBytes = inputBuffer[1].HighPart * inputBuffer[1].LowPart;

    if (inputBufferSize < numberOfBytes + 16)
        return STATUS_INVALID_PARAMETER;

    UINT32* baseAddress = MmMapIoSpace(*inputBuffer, numberOfBytes, MmNonCached);

    RtlCopyMemory(baseAddress, &inputBuffer[2], inputBuffer[1].HighPart);

    MmUnmapIoSpace(baseAddress, numberOfBytes);

    return STATUS_SUCCESS;
}

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

    IRP* irp = WdfRequestWdmGetIrp(request);
    UINT32* stack = (UINT32*)irp->Tail.Overlay.CurrentStackLocation;

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
    case IOCTL_READ_MEMORY: {
        // Arguments are extracted from IDA
        status = ReadMemory(
            irp->AssociatedIrp.MasterIrp,
            *((UINT32*)stack + 4),
            irp->AssociatedIrp.MasterIrp,
            *((UINT32*)stack + 2),
            &irp->IoStatus.Information
        );
        if (!NT_SUCCESS(status))
            break;
    }
    case IOCTL_WRITE_MEMORY: {
        // Arguments are extracted from IDA
        status = WriteMemory(
            irp->AssociatedIrp.MasterIrp,
            *((UINT32*)stack + 4),
            irp->AssociatedIrp.MasterIrp,
            *((UINT32*)stack + 2),
            &irp->IoStatus.Information
        );
        if (!NT_SUCCESS(status))
            break;
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

    // Everyone can open the device
    UNICODE_STRING permissions;
    RtlInitUnicodeString(&permissions, L"D:(A;;GA;;;WD)");

    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(wdfDriver, &permissions);

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