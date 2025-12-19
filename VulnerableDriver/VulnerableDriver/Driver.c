#include <ntddk.h>
#include <wdf.h>

#include "IOCTL.h"

NTSTATUS ReadMemory(PHYSICAL_ADDRESS* addr, UINT32 size, VOID* outputBuffer, UINT32 outputBufferSize, LONG* written) {
    UINT32 numberOfBytes = addr[1].HighPart * addr[1].LowPart;

    if (outputBufferSize < numberOfBytes)
        return STATUS_INVALID_PARAMETER;

    UINT32* baseAddress = MmMapIoSpace(*addr, numberOfBytes, MmNonCached);

    RtlCopyMemory(outputBuffer, baseAddress, addr[1].HighPart);

    MmUnmapIoSpace(baseAddress, numberOfBytes);

    *written = addr[1].HighPart;

    return STATUS_SUCCESS;
}

NTSTATUS WriteMemory(PHYSICAL_ADDRESS* addr, UINT32 size, BYTE* userBuffer) {
    UINT32 numberOfBytes = addr[1].HighPart * addr[1].LowPart;

    if (size < numberOfBytes + 16)
        return STATUS_INVALID_PARAMETER;

    UINT32* baseAddress = MmMapIoSpace(*addr, numberOfBytes, MmNonCached);

    RtlCopyMemory(baseAddress, userBuffer, addr[1].HighPart);

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

    NTSTATUS status = STATUS_SUCCESS;

    KdPrint(("[Vulnerable Driver] IOCTL code is 0%x\n", ioControlCode));

    switch (ioControlCode) {
    case IOCTL_PING: {
        UINT32* inValue = NULL;
        UINT32* outValue = NULL;
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
        if (inputBufferLength < sizeof(READ_MEMORY_INPUT_BUFFER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        READ_MEMORY_INPUT_BUFFER* inputBuffer = NULL;

        status = WdfRequestRetrieveInputBuffer(request, sizeof(READ_MEMORY_INPUT_BUFFER), (PVOID*)&inputBuffer, NULL);
        if (!NT_SUCCESS(status))
            break;

        VOID* outBuf = NULL;

        status = WdfRequestRetrieveOutputBuffer(request, outputBufferLength, &outBuf, NULL);
        if (!NT_SUCCESS(status))
            break;

        LONG written = 0;

        status = ReadMemory(&inputBuffer->physicalAddress, inputBuffer->size, outBuf, outputBufferLength, &written);
        if (!NT_SUCCESS(status))
            break;
        
        WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, written);
        return;
    }
    case IOCTL_WRITE_MEMORY: {
        if (inputBufferLength < sizeof(WRITE_MEMORY_INPUT_BUFFER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        WRITE_MEMORY_INPUT_BUFFER* inputBuffer = NULL;

        status = WdfRequestRetrieveInputBuffer(request, sizeof(WRITE_MEMORY_INPUT_BUFFER), (PVOID*)&inputBuffer, NULL);
        if (!NT_SUCCESS(status))
            break;

        status = WriteMemory(&inputBuffer->physicalAddress, inputBuffer->size, inputBuffer->data);
        if (!NT_SUCCESS(status))
            break;

        WdfRequestComplete(request, STATUS_SUCCESS);
        return;
    }
    case IOCTL_READ_MSR: {
        // 32bit integer for the register number
        // and 64bit integer for the MSR register value
        if (inputBufferLength < sizeof(UINT32) || outputBufferLength < sizeof(UINT64)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        UINT32* msrNumber = NULL;

        status = WdfRequestRetrieveInputBuffer(request, sizeof(UINT32), (PVOID*)&msrNumber, NULL);
        if (!NT_SUCCESS(status))
            break;

        UINT64* outBuf = NULL;
        SIZE_T actualLen = 0;

        status = WdfRequestRetrieveOutputBuffer(request, sizeof(UINT64), (PVOID*)&outBuf, &actualLen);
        if (!NT_SUCCESS(status))
            break;

        *outBuf = __readmsr(*msrNumber);

        WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(UINT64));
        return;
    }
    case IOCTL_WRITE_MSR: {
        if (inputBufferLength < sizeof(WRITE_MSR_INPUT_BUFFER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        WRITE_MSR_INPUT_BUFFER* inputBuffer = NULL;

        status = WdfRequestRetrieveInputBuffer(request, sizeof(WRITE_MSR_INPUT_BUFFER), (PVOID*)&inputBuffer, NULL);
        if (!NT_SUCCESS(status))
            break;

        __writemsr(inputBuffer->reg, inputBuffer->value);

        WdfRequestComplete(request, STATUS_SUCCESS);
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