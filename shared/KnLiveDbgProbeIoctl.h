#pragma once

typedef unsigned __int32 KNDBG_PROBE_UINT32;
typedef unsigned __int64 KNDBG_PROBE_UINT64;

#define KNDBG_PROBE_DEVICE_NAME L"\\Device\\KnLiveDbgProbe"
#define KNDBG_PROBE_DOS_DEVICE_NAME L"\\DosDevices\\KnLiveDbgProbe"
#define KNDBG_PROBE_USER_DEVICE_NAME L"\\\\.\\KnLiveDbgProbe"
#define KNDBG_PROBE_SERVICE_NAME L"KnLiveDbgProbe"
#define KNDBG_PROBE_DISPLAY_NAME L"Kn Live Debug Probe Driver"

#define KNDBG_PROBE_ABI_VERSION 1u
#define KNDBG_PROBE_BUFFER_LENGTH 0x1000u
#define KNDBG_PROBE_PATTERN_SEED 0x5Au

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x0001
#endif

#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA 0x0002
#endif

#define IOCTL_KNDBG_PROBE_GET_INFO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_KNDBG_PROBE_RESET_PATTERN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(push, 8)

typedef struct _KNDBG_PROBE_INFO_RESPONSE
{
    KNDBG_PROBE_UINT32 Size;
    KNDBG_PROBE_UINT32 AbiVersion;
    KNDBG_PROBE_UINT32 BufferLength;
    KNDBG_PROBE_UINT32 PatternSeed;
    KNDBG_PROBE_UINT64 BufferVirtualAddress;
    KNDBG_PROBE_UINT64 BufferPhysicalAddress;
} KNDBG_PROBE_INFO_RESPONSE;

#pragma pack(pop)
