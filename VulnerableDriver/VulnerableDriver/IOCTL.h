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

#define IOCTL_WRITE_MEMORY CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x802, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)
