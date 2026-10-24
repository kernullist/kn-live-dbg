#include "ManagedCallbacks.h"
#include "../shared/KnLiveDbgManagedCallbacks.h"

namespace
{
    struct Client
    {
        ULONG_PTR Id;
        PFLT_PORT Port;
        HANDLE Pid;
    };

    PFLT_FILTER g_Filter;
    PFLT_PORT g_Server;
    BOOLEAN g_ProcessNotifyRegistered;
    KMUTEX g_Control; // PASSIVE_LEVEL: serialize transitions, disconnect, and unload.
    KSPIN_LOCK g_State;
    EX_RUNDOWN_REF g_Bodies[2];
    Client g_Clients[16];
    ULONG_PTR g_NextId;
    ULONG_PTR g_OwnerId;
    PEPROCESS g_OwnerProcess;
    KNDBG_MANAGED_CALLBACK_STATUS g_Status;
    ULONG g_HoldMask;
    ULONG g_HoldMilliseconds;
    ULONG g_HoldPid;

    void LockControl()
    {
        KeWaitForSingleObject(&g_Control, Executive, KernelMode, FALSE, nullptr);
    }

    void UnlockControl() { KeReleaseMutex(&g_Control, FALSE); }

    Client* FindClient(ULONG_PTR id)
    {
        for (auto& client : g_Clients)
        {
            if (id != 0 && client.Id == id) return &client;
        }
        return nullptr;
    }

    // Caller owns g_Control. The spin lock closes the "read enabled, then
    // acquire" race with ExReInitializeRundownProtection on later resumes.
    void SetEnabled(ULONG desired)
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        const ULONG previous = g_Status.EnabledMask;
        const ULONG disable = previous & ~desired;
        const ULONG enable = desired & ~previous;
        g_Status.EnabledMask &= ~disable;
        g_Status.DrainingMask |= disable;
        KeReleaseSpinLock(&g_State, irql);

        for (ULONG index = 0; index < 2; ++index)
        {
            if ((disable & (1u << index)) != 0)
                ExWaitForRundownProtectionRelease(&g_Bodies[index]);
            if ((enable & (1u << index)) != 0)
                ExReInitializeRundownProtection(&g_Bodies[index]);
        }

        KeAcquireSpinLock(&g_State, &irql);
        g_Status.DrainingMask &= ~disable;
        g_Status.EnabledMask |= enable;
        if (previous != desired) ++g_Status.Generation;
        KeReleaseSpinLock(&g_State, irql);
    }

    void ReleaseOwner(bool automatic)
    {
        if (g_OwnerId == 0) return;
        // Complete any one-shot test body before ending the owner's lease.
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        g_HoldMask = 0;
        KeReleaseSpinLock(&g_State, irql);
        SetEnabled(0);
        if (!g_Status.Stopping) SetEnabled(KNDBG_MANAGED_BOTH);
        PEPROCESS process = g_OwnerProcess;
        g_OwnerProcess = nullptr;
        g_OwnerId = 0;
        KeAcquireSpinLock(&g_State, &irql);
        g_Status.OwnerPid = 0;
        g_Status.OwnerConnection = 0;
        if (automatic) ++g_Status.AutomaticRestores;
        KeReleaseSpinLock(&g_State, irql);
        if (process != nullptr) ObDereferenceObject(process);
    }

    VOID ProcessNotify(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO createInfo)
    {
        UNREFERENCED_PARAMETER(processId);
        if (createInfo != nullptr) return;
        LockControl();
        if (g_OwnerProcess == process) ReleaseOwner(true);
        UnlockControl();
    }

    NTSTATUS FLTAPI Connect(PFLT_PORT port, PVOID serverCookie, PVOID context,
        ULONG contextSize, PVOID* cookie)
    {
        UNREFERENCED_PARAMETER(serverCookie);
        UNREFERENCED_PARAMETER(context);
        if (contextSize != 0) return STATUS_INVALID_PARAMETER;
        NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
        LockControl();
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        if (g_Status.Stopping)
        {
            status = STATUS_FLT_DELETING_OBJECT;
        }
        else if (g_NextId != MAXULONG_PTR)
        {
            for (auto& client : g_Clients)
            {
                if (client.Id != 0) continue;
                client.Id = ++g_NextId;
                client.Port = port;
                client.Pid = PsGetCurrentProcessId();
                // An opaque, non-reused number, not a pointer to freed memory.
                *cookie = reinterpret_cast<PVOID>(client.Id);
                ++g_Status.Connections;
                status = STATUS_SUCCESS;
                break;
            }
        }
        KeReleaseSpinLock(&g_State, irql);
        UnlockControl();
        return status;
    }

    VOID FLTAPI Disconnect(PVOID cookie)
    {
        const ULONG_PTR id = reinterpret_cast<ULONG_PTR>(cookie);
        PFLT_PORT port = nullptr;
        LockControl();
        if (g_OwnerId == id) ReleaseOwner(true);
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        Client* client = FindClient(id);
        if (client != nullptr)
        {
            port = client->Port;
            *client = Client{};
            --g_Status.Connections;
        }
        KeReleaseSpinLock(&g_State, irql);
        UnlockControl();
        // Never hold g_Control across FltMgr's close/unregister operations.
        if (port != nullptr) FltCloseClientPort(g_Filter, &port);
    }

    NTSTATUS FLTAPI Message(PVOID cookie, PVOID input, ULONG inputSize,
        PVOID output, ULONG outputSize, PULONG returned)
    {
        *returned = 0;
        if (input == nullptr || inputSize != sizeof(KNDBG_MANAGED_CALLBACK_REQUEST) ||
            output == nullptr || outputSize < sizeof(KNDBG_MANAGED_CALLBACK_STATUS))
            return STATUS_INVALID_PARAMETER;
        KNDBG_MANAGED_CALLBACK_REQUEST request = {};
        __try
        {
            RtlCopyMemory(&request, input, sizeof(request));
            ProbeForWrite(output, sizeof(KNDBG_MANAGED_CALLBACK_STATUS), 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
        if (request.Magic != KNDBG_MANAGED_CALLBACK_MAGIC ||
            request.Version != KNDBG_MANAGED_CALLBACK_VERSION ||
            request.Size != sizeof(request) || request.Reserved != 0 ||
            request.Action > KNDBG_MANAGED_TEST_HOLD)
            return STATUS_INVALID_PARAMETER;
        const bool query = request.Action == KNDBG_MANAGED_QUERY;
        const bool release = request.Action == KNDBG_MANAGED_RELEASE;
        const bool hold = request.Action == KNDBG_MANAGED_TEST_HOLD;
        if ((query || release) ? request.Mask != 0 :
            (request.Mask == 0 || (request.Mask & ~KNDBG_MANAGED_BOTH) != 0))
            return STATUS_INVALID_PARAMETER;
        if (hold ? (request.HoldMilliseconds == 0 || request.HoldMilliseconds > 500 ||
                    request.HoldProcessId <= 4 || request.Mask == KNDBG_MANAGED_BOTH) :
                   (request.HoldMilliseconds != 0 || request.HoldProcessId != 0))
            return STATUS_INVALID_PARAMETER;

        // Queries may observe a transition while a control request waits for
        // a real callback body. All state and client lookup are protected.
        if (!query) LockControl();
        const ULONG_PTR id = reinterpret_cast<ULONG_PTR>(cookie);
        NTSTATUS status = STATUS_SUCCESS;
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        Client* client = FindClient(id);
        if (client == nullptr || client->Pid != PsGetCurrentProcessId())
            status = STATUS_ACCESS_DENIED;
        else if (g_Status.Stopping)
            status = STATUS_FLT_DELETING_OBJECT;
        else if (!query && request.ExpectedFilter != g_Status.Filter)
            status = STATUS_REVISION_MISMATCH;
        const ULONG before = g_Status.EnabledMask;
        KeReleaseSpinLock(&g_State, irql);

        if (NT_SUCCESS(status) && !query)
        {
            if (g_OwnerId != 0 && g_OwnerId != id)
                status = STATUS_DEVICE_BUSY;
            else if (release)
                ReleaseOwner(false);
            else
            {
                if (g_OwnerId == 0)
                {
                    g_OwnerId = id;
                    g_OwnerProcess = PsGetCurrentProcess();
                    ObReferenceObject(g_OwnerProcess);
                    KeAcquireSpinLock(&g_State, &irql);
                    g_Status.OwnerPid = HandleToULong(PsGetCurrentProcessId());
                    g_Status.OwnerConnection = id;
                    KeReleaseSpinLock(&g_State, irql);
                }
                if (hold)
                {
                    KeAcquireSpinLock(&g_State, &irql);
                    g_HoldMask = request.Mask;
                    g_HoldMilliseconds = request.HoldMilliseconds;
                    g_HoldPid = request.HoldProcessId;
                    KeReleaseSpinLock(&g_State, irql);
                }
                else
                {
                    SetEnabled(request.Action == KNDBG_MANAGED_DISABLE
                        ? before & ~request.Mask : before | request.Mask);
                }
            }
        }
        if (NT_SUCCESS(status))
        {
            KNDBG_MANAGED_CALLBACK_STATUS snapshot;
            KeAcquireSpinLock(&g_State, &irql);
            snapshot = g_Status;
            // Queries have no before/after mutation. Use the same instant for
            // both masks even if another connection changed state since lookup.
            snapshot.PreviousEnabledMask = query ? snapshot.EnabledMask : before;
            KeReleaseSpinLock(&g_State, irql);
            __try
            {
                RtlCopyMemory(output, &snapshot, sizeof(snapshot));
                *returned = sizeof(snapshot);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }
            // A lost reply must not leave an unacknowledged paused provider.
            if (!NT_SUCCESS(status) && !query && g_OwnerId == id) ReleaseOwner(true);
        }
        if (!query) UnlockControl();
        return status;
    }

    void RunBody(ULONG index, PFLT_CALLBACK_DATA data)
    {
        // CREATE pre/post callbacks run at <= APC_LEVEL. Keep normal APCs
        // disabled for the entire acquired rundown interval, including delays.
        KeEnterCriticalRegion();
        KIRQL irql;
        KeAcquireSpinLock(&g_State, &irql);
        const ULONG bit = 1u << index;
        const bool acquired = (g_Status.EnabledMask & bit) != 0 &&
            ExAcquireRundownProtection(&g_Bodies[index]);
        ULONG delay = 0;
        if (acquired)
        {
            if (index == 0) { ++g_Status.ActivePre; ++g_Status.PreEntered; }
            else { ++g_Status.ActivePost; ++g_Status.PostEntered; }
            if (g_HoldMask == bit && FltGetRequestorProcessId(data) == g_HoldPid)
            {
                delay = g_HoldMilliseconds;
                g_HoldMask = 0;
                ++g_Status.HoldEntered;
            }
        }
        else if (index == 0) ++g_Status.PreSkipped;
        else ++g_Status.PostSkipped;
        KeReleaseSpinLock(&g_State, irql);

        // The fixture only counts calls. It never denies, changes, or pends I/O.
        if (delay != 0)
        {
            LARGE_INTEGER interval;
            interval.QuadPart = -static_cast<LONGLONG>(delay) * 10000;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
        if (acquired)
        {
            KeAcquireSpinLock(&g_State, &irql);
            if (index == 0) --g_Status.ActivePre;
            else --g_Status.ActivePost;
            if (delay != 0) ++g_Status.HoldCompleted;
            KeReleaseSpinLock(&g_State, irql);
            ExReleaseRundownProtection(&g_Bodies[index]);
        }
        KeLeaveCriticalRegion();
    }
}

void ManagedCallbacksInitialize()
{
    KeInitializeMutex(&g_Control, 0);
    KeInitializeSpinLock(&g_State);
    for (auto& body : g_Bodies) ExInitializeRundownProtection(&body);
    g_Status.Magic = KNDBG_MANAGED_CALLBACK_MAGIC;
    g_Status.Version = KNDBG_MANAGED_CALLBACK_VERSION;
    g_Status.Size = sizeof(g_Status);
    g_Status.SupportedMask = KNDBG_MANAGED_BOTH;
    g_Status.EnabledMask = KNDBG_MANAGED_BOTH;
}

NTSTATUS ManagedCallbacksStart(PFLT_FILTER filter)
{
    g_Filter = filter;
    g_Status.Filter = reinterpret_cast<ULONG_PTR>(filter);
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) return status;
    g_ProcessNotifyRegistered = TRUE;
    PSECURITY_DESCRIPTOR security = nullptr;
    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status))
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING(KNDBG_MANAGED_CALLBACK_PORT);
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, nullptr, security);
        status = FltCreateCommunicationPort(filter, &g_Server, &attributes, nullptr,
            Connect, Disconnect, Message, RTL_NUMBER_OF(g_Clients));
        FltFreeSecurityDescriptor(security);
    }
    return status;
}

void ManagedCallbacksStop()
{
    LockControl();
    KIRQL irql;
    KeAcquireSpinLock(&g_State, &irql);
    g_Status.Stopping = TRUE;
    g_HoldMask = 0;
    KeReleaseSpinLock(&g_State, irql);
    ReleaseOwner(false);
    SetEnabled(0);
    UnlockControl();
    if (g_Server != nullptr)
    {
        FltCloseCommunicationPort(g_Server);
        g_Server = nullptr;
    }
    if (g_ProcessNotifyRegistered)
    {
        // The OS waits for active notify invocations before returning.
        PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }
    // The caller must next FltUnregisterFilter, outside g_Control. FltMgr owns
    // wrapper code lifetime, including callers that haven't entered RunBody.
}

void ManagedCallbacksUnregistered() { g_Filter = nullptr; }

FLT_PREOP_CALLBACK_STATUS FLTAPI ManagedPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(objects);
    if (completionContext != nullptr) *completionContext = nullptr;
    RunBody(0, data);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI ManagedPostCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completionContext,
    FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(completionContext);
    if ((flags & FLTFL_POST_OPERATION_DRAINING) == 0) RunBody(1, data);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
