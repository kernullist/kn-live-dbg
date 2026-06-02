#include <ntddk.h>

static DRIVER_UNLOAD KnByovdFixtureUnload;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        if (DriverObject == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DriverObject->DriverUnload = KnByovdFixtureUnload;
    } while (false);

    return status;
}

static VOID KnByovdFixtureUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}
