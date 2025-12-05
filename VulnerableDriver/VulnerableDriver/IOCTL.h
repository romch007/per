#pragma once

#define IOCTL_PING CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x800, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)
