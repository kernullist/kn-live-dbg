#include <ntddk.h>
#include <wdmsec.h>
#include "../shared/KnLiveDbgProbeIoctl.h"

static DRIVER_UNLOAD KnDbgProbeUnload;
static DRIVER_DISPATCH KnDbgProbeCreateClose;
static DRIVER_DISPATCH KnDbgProbeDeviceControl;
static DRIVER_DISPATCH KnDbgProbeNotSupportedDispatch;

#ifndef SystemRegisterFirmwareTableInformationHandler
#define SystemRegisterFirmwareTableInformationHandler 0x4B
#endif

typedef NTSTATUS(NTAPI* KNDBG_PROBE_ZW_SET_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _In_reads_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength);

static PVOID g_KnDbgProbeBuffer = nullptr;
static PDRIVER_OBJECT g_KnDbgProbeDriverObject = nullptr;
static BOOLEAN g_KnDbgProbeFirmwareProviderRegistered = FALSE;
static NTSTATUS g_KnDbgProbeFirmwareProviderRegisterStatus = STATUS_NOT_FOUND;
static NTSTATUS g_KnDbgProbeFirmwareProviderUnregisterStatus = STATUS_SUCCESS;
static const GUID KNDBG_PROBE_DEVICE_CLASS_GUID =
{
    0x8f5f4de1,
    0x583e,
    0x46cf,
    {0x9c, 0x80, 0x3d, 0xb4, 0x7f, 0x31, 0x66, 0x29}
};

static NTSTATUS KnDbgProbeCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS __cdecl KnDbgProbeFirmwareTableHandler(
    _Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    do
    {
        if (SystemFirmwareTableInfo == nullptr)
        {
            break;
        }

        if (SystemFirmwareTableInfo->ProviderSignature != KNDBG_PROBE_FIRMWARE_PROVIDER_SIGNATURE)
        {
            break;
        }

        if (SystemFirmwareTableInfo->Action == SystemFirmwareTable_Enumerate)
        {
            SystemFirmwareTableInfo->TableBufferLength = 0;
            status = STATUS_SUCCESS;
            break;
        }

        if (SystemFirmwareTableInfo->Action == SystemFirmwareTable_Get)
        {
            SystemFirmwareTableInfo->TableBufferLength = 0;
            status = STATUS_NOT_FOUND;
            break;
        }
    } while (false);

    return status;
}

static NTSTATUS KnDbgProbeSetFirmwareTableProvider(BOOLEAN Register)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        if (g_KnDbgProbeDriverObject == nullptr)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwSetSystemInformation");
        KNDBG_PROBE_ZW_SET_SYSTEM_INFORMATION zwSetSystemInformation =
            reinterpret_cast<KNDBG_PROBE_ZW_SET_SYSTEM_INFORMATION>(
                MmGetSystemRoutineAddress(&routineName));
        if (zwSetSystemInformation == nullptr)
        {
            status = STATUS_PROCEDURE_NOT_FOUND;
            break;
        }

        SYSTEM_FIRMWARE_TABLE_HANDLER tableHandler = {};
        tableHandler.ProviderSignature = KNDBG_PROBE_FIRMWARE_PROVIDER_SIGNATURE;
        tableHandler.Register = Register;
        tableHandler.FirmwareTableHandler = KnDbgProbeFirmwareTableHandler;
        tableHandler.DriverObject = g_KnDbgProbeDriverObject;

        status = zwSetSystemInformation(
            SystemRegisterFirmwareTableInformationHandler,
            &tableHandler,
            sizeof(tableHandler));
    } while (false);

    return status;
}

static void KnDbgProbeRegisterFirmwareTableProvider()
{
    do
    {
        if (g_KnDbgProbeFirmwareProviderRegistered)
        {
            break;
        }

        g_KnDbgProbeFirmwareProviderRegisterStatus = KnDbgProbeSetFirmwareTableProvider(TRUE);
        if (NT_SUCCESS(g_KnDbgProbeFirmwareProviderRegisterStatus))
        {
            g_KnDbgProbeFirmwareProviderRegistered = TRUE;
        }
    } while (false);
}

static void KnDbgProbeUnregisterFirmwareTableProvider()
{
    do
    {
        if (!g_KnDbgProbeFirmwareProviderRegistered)
        {
            break;
        }

        g_KnDbgProbeFirmwareProviderUnregisterStatus = KnDbgProbeSetFirmwareTableProvider(FALSE);
        if (NT_SUCCESS(g_KnDbgProbeFirmwareProviderUnregisterStatus))
        {
            g_KnDbgProbeFirmwareProviderRegistered = FALSE;
        }
    } while (false);
}

static void KnDbgProbeFillPattern()
{
    do
    {
        if (g_KnDbgProbeBuffer == nullptr)
        {
            break;
        }

        PUCHAR bytes = reinterpret_cast<PUCHAR>(g_KnDbgProbeBuffer);
        for (ULONG index = 0; index < KNDBG_PROBE_BUFFER_LENGTH; ++index)
        {
            bytes[index] = static_cast<UCHAR>((index * 13u + KNDBG_PROBE_PATTERN_SEED) & 0xffu);
        }
    } while (false);
}

static NTSTATUS KnDbgProbeHandleGetInfo(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        if (Buffer == nullptr || Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KNDBG_PROBE_INFO_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (g_KnDbgProbeBuffer == nullptr)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        RtlZeroMemory(Buffer, Stack->Parameters.DeviceIoControl.OutputBufferLength);

        KNDBG_PROBE_INFO_RESPONSE* response = reinterpret_cast<KNDBG_PROBE_INFO_RESPONSE*>(Buffer);
        PHYSICAL_ADDRESS physical = MmGetPhysicalAddress(g_KnDbgProbeBuffer);
        response->Size = sizeof(KNDBG_PROBE_INFO_RESPONSE);
        response->AbiVersion = KNDBG_PROBE_ABI_VERSION;
        response->BufferLength = KNDBG_PROBE_BUFFER_LENGTH;
        response->PatternSeed = KNDBG_PROBE_PATTERN_SEED;
        response->BufferVirtualAddress = reinterpret_cast<KNDBG_PROBE_UINT64>(g_KnDbgProbeBuffer);
        response->BufferPhysicalAddress = static_cast<KNDBG_PROBE_UINT64>(physical.QuadPart);
        response->FirmwareProviderSignature = KNDBG_PROBE_FIRMWARE_PROVIDER_SIGNATURE;
        response->FirmwareProviderRegistered = g_KnDbgProbeFirmwareProviderRegistered ? 1u : 0u;
        response->FirmwareProviderRegisterStatus =
            static_cast<KNDBG_PROBE_UINT32>(g_KnDbgProbeFirmwareProviderRegisterStatus);
        response->FirmwareProviderUnregisterStatus =
            static_cast<KNDBG_PROBE_UINT32>(g_KnDbgProbeFirmwareProviderUnregisterStatus);
        response->FirmwareTableHandlerAddress =
            reinterpret_cast<KNDBG_PROBE_UINT64>(&KnDbgProbeFirmwareTableHandler);

        information = sizeof(KNDBG_PROBE_INFO_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgProbeCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgProbeHandleResetPattern(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    UNREFERENCED_PARAMETER(Buffer);

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KnDbgProbeFillPattern();
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgProbeCompleteIrp(Irp, status, 0);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(KNDBG_PROBE_DEVICE_NAME);
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KNDBG_PROBE_DOS_DEVICE_NAME);
    UNICODE_STRING defaultSddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT deviceObject = nullptr;
    bool symbolicLinkCreated = false;

    do
    {
        g_KnDbgProbeDriverObject = DriverObject;

        for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index)
        {
            DriverObject->MajorFunction[index] = KnDbgProbeNotSupportedDispatch;
        }

        DriverObject->MajorFunction[IRP_MJ_CREATE] = KnDbgProbeCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = KnDbgProbeCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KnDbgProbeDeviceControl;
        DriverObject->DriverUnload = KnDbgProbeUnload;

        PHYSICAL_ADDRESS lowestAddress = {};
        PHYSICAL_ADDRESS highestAddress = {};
        PHYSICAL_ADDRESS boundaryAddress = {};
        highestAddress.QuadPart = MAXLONGLONG;

        g_KnDbgProbeBuffer = MmAllocateContiguousMemorySpecifyCache(
            KNDBG_PROBE_BUFFER_LENGTH,
            lowestAddress,
            highestAddress,
            boundaryAddress,
            MmCached);
        if (g_KnDbgProbeBuffer == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        KnDbgProbeFillPattern();

        status = IoCreateDeviceSecure(
            DriverObject,
            0,
            &deviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &defaultSddl,
            &KNDBG_PROBE_DEVICE_CLASS_GUID,
            &deviceObject);

        if (!NT_SUCCESS(status))
        {
            break;
        }

        deviceObject->Flags |= DO_BUFFERED_IO;

        status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        symbolicLinkCreated = true;
        deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        KnDbgProbeRegisterFirmwareTableProvider();
        status = STATUS_SUCCESS;
    } while (false);

    if (!NT_SUCCESS(status))
    {
        KnDbgProbeUnregisterFirmwareTableProvider();

        if (symbolicLinkCreated)
        {
            IoDeleteSymbolicLink(&symbolicLinkName);
        }

        if (deviceObject != nullptr)
        {
            IoDeleteDevice(deviceObject);
        }

        if (g_KnDbgProbeBuffer != nullptr)
        {
            MmFreeContiguousMemory(g_KnDbgProbeBuffer);
            g_KnDbgProbeBuffer = nullptr;
        }

        g_KnDbgProbeDriverObject = nullptr;
    }

    return status;
}

static VOID KnDbgProbeUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KNDBG_PROBE_DOS_DEVICE_NAME);

    KnDbgProbeUnregisterFirmwareTableProvider();

    IoDeleteSymbolicLink(&symbolicLinkName);

    if (DriverObject->DeviceObject != nullptr)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    if (g_KnDbgProbeBuffer != nullptr)
    {
        MmFreeContiguousMemory(g_KnDbgProbeBuffer);
        g_KnDbgProbeBuffer = nullptr;
    }

    g_KnDbgProbeDriverObject = nullptr;
}

static NTSTATUS KnDbgProbeCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KnDbgProbeCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS KnDbgProbeDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_KNDBG_PROBE_GET_INFO:
        status = KnDbgProbeHandleGetInfo(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_PROBE_RESET_PATTERN:
        status = KnDbgProbeHandleResetPattern(Irp, stack, buffer);
        break;
    default:
        status = KnDbgProbeCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        break;
    }

    return status;
}

static NTSTATUS KnDbgProbeNotSupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KnDbgProbeCompleteIrp(Irp, STATUS_NOT_SUPPORTED, 0);
}
