#include <fltKernel.h>
#include "ManagedCallbacks.h"

namespace
{
    PFLT_FILTER g_Filter = nullptr;

    NTSTATUS FLTAPI InstanceSetup(
        _In_ PCFLT_RELATED_OBJECTS objects,
        _In_ FLT_INSTANCE_SETUP_FLAGS flags,
        _In_ DEVICE_TYPE volumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE volumeFilesystemType)
    {
        UNREFERENCED_PARAMETER(objects);
        UNREFERENCED_PARAMETER(flags);

        if (volumeDeviceType !=
            FILE_DEVICE_DISK_FILE_SYSTEM)
        {
            return STATUS_FLT_DO_NOT_ATTACH;
        }

        if (volumeFilesystemType !=
                FLT_FSTYPE_NTFS &&
            volumeFilesystemType !=
                FLT_FSTYPE_REFS)
        {
            return STATUS_FLT_DO_NOT_ATTACH;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS FLTAPI InstanceQueryTeardown(
        _In_ PCFLT_RELATED_OBJECTS objects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags)
    {
        UNREFERENCED_PARAMETER(objects);
        UNREFERENCED_PARAMETER(flags);

        // The fixture exists to exercise a supported manual-detach path for
        // its own no-op instance. It never detaches another filter.
        return STATUS_SUCCESS;
    }

    VOID FLTAPI InstanceTeardown(
        _In_ PCFLT_RELATED_OBJECTS objects,
        _In_ FLT_INSTANCE_TEARDOWN_FLAGS reason)
    {
        UNREFERENCED_PARAMETER(objects);
        UNREFERENCED_PARAMETER(reason);
    }

    NTSTATUS FLTAPI FilterUnload(
        _In_ FLT_FILTER_UNLOAD_FLAGS flags)
    {
        UNREFERENCED_PARAMETER(flags);

        if (g_Filter != nullptr)
        {
            ManagedCallbacksStop();
            FltUnregisterFilter(g_Filter);
            ManagedCallbacksUnregistered();
            g_Filter = nullptr;
        }
        return STATUS_SUCCESS;
    }

    const FLT_OPERATION_REGISTRATION
        kOperationCallbacks[] =
        {
            {
                IRP_MJ_CREATE,
                0,
                ManagedPreCreate,
                ManagedPostCreate
            },
            {
                IRP_MJ_OPERATION_END,
                0,
                nullptr,
                nullptr
            }
        };

    FLT_REGISTRATION g_Registration = {};
}

extern "C"
DRIVER_INITIALIZE DriverEntry;

extern "C"
_Use_decl_annotations_
NTSTATUS DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath)
{
    if (driverObject == nullptr ||
        registryPath == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ManagedCallbacksInitialize();
    g_Registration =
        FLT_REGISTRATION{};
    g_Registration.Size =
        sizeof(g_Registration);
    g_Registration.Version =
        FLT_REGISTRATION_VERSION;
    g_Registration.OperationRegistration =
        kOperationCallbacks;
    g_Registration.FilterUnloadCallback =
        FilterUnload;
    g_Registration.InstanceSetupCallback =
        InstanceSetup;
    g_Registration.InstanceQueryTeardownCallback =
        InstanceQueryTeardown;
    g_Registration.InstanceTeardownStartCallback =
        InstanceTeardown;
    g_Registration.InstanceTeardownCompleteCallback =
        InstanceTeardown;

    NTSTATUS status =
        FltRegisterFilter(
            driverObject,
            &g_Registration,
            &g_Filter);
    if (!NT_SUCCESS(status))
    {
        g_Filter = nullptr;
        return status;
    }

    status = ManagedCallbacksStart(g_Filter);
    if (NT_SUCCESS(status)) status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status))
    {
        ManagedCallbacksStop();
        FltUnregisterFilter(g_Filter);
        ManagedCallbacksUnregistered();
        g_Filter = nullptr;
    }
    return status;
}
