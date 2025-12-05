#pragma once

#define IOCTL_PING CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x800, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_READ_MEMORY CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x801, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _READ_MEMORY_INPUT_BUFFER {
    LARGE_INTEGER physicalAddress;
    UINT32 size;
} READ_MEMORY_INPUT_BUFFER;
#pragma pack(pop)

#define IOCTL_WRITE_MEMORY CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x802, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _WRITE_MEMORY_INPUT_BUFFER {
    LARGE_INTEGER physicalAddress;
    UINT32 size;
    BYTE data[1];
} WRITE_MEMORY_INPUT_BUFFER;
#pragma pack(pop)

#define IOCTL_READ_MSR CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x803, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)


#define IOCTL_WRITE_MSR CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x804, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _WRITE_MSR_INPUT_BUFFER {
    UINT32 reg;
    UINT64 value;
} WRITE_MSR_INPUT_BUFFER;
#pragma pack(pop)
