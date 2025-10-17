#pragma once

BYTE PASSWORD[4] = { 0x71, 0x72, 0x73, 0x74 }; // Password used for the network trigger (needs to be EXACTLY 4 bytes)

#pragma warning(disable: 4996)                 // Ignore deprecated function calls - used for ExAllocatePoolWithTag
#define ALLOC_TAG_NAME (ULONG)'TG_1'           // Tag to identify the memory pool  - used for ExAllocatePoolWithTag#pragma once
