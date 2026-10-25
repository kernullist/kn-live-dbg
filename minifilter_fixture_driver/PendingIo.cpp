#include "PendingIo.h"
#include "../shared/KnLiveDbgPendingIo.h"

namespace
{
    constexpr ULONG kTag = 'ipNK';
    struct Instance
    {
        bool Lower;
        bool Stopping;
    };
    struct Operation
    {
        LIST_ENTRY AllLink, WorkLink;
        LONG References, LogicalReleased;
        Instance* InstanceState;
        PFILE_OBJECT FileObject; // Identity only while this I/O owns a context.
        PEPROCESS TargetProcess;
        PFLT_CALLBACK_DATA Data; // Owned until the matching FltComplete call.
        PFLT_CALLBACK_DATA PreIdentity; // Identity only, never dereferenced after pre.
        ULONGLONG Generation;
        ULONG_PTR Owner;
        ULONG Mode, DelayMilliseconds, WakeReason;
        ULONG Gate, GateMilliseconds;
        bool LowerClaimed, PostWork;
        KEVENT Resume;
    };
    struct Client { ULONG_PTR Id; PFLT_PORT Port; HANDLE Pid; };

    PFLT_FILTER g_Filter;
    PFLT_PORT g_Server;
    HANDLE g_Worker;
    KEVENT g_WorkAvailable;
    KSPIN_LOCK g_Lock;
    KMUTEX g_Control;
    LIST_ENTRY g_Operations, g_Work;
    Client g_Clients[16];
    ULONG_PTR g_NextClient, g_Owner;
    PEPROCESS g_OwnerProcess, g_Target;
    ULONG g_Delay;
    ULONG g_Gate, g_GateMilliseconds;
    KNDBG_PENDING_STATUS g_Status;
    FLT_CONTEXT_REGISTRATION g_Contexts[2];
    WCHAR g_AuditPath[512];

    void LockControl() { KeWaitForSingleObject(&g_Control, Executive, KernelMode, FALSE, nullptr); }
    void UnlockControl() { KeReleaseMutex(&g_Control, FALSE); }
    Client* FindClient(ULONG_PTR id)
    {
        for (auto& client : g_Clients) if (id != 0 && client.Id == id) return &client;
        return nullptr;
    }

    void DropReference(Operation* operation)
    {
        if (InterlockedDecrement(&operation->References) != 0) return;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        RemoveEntryList(&operation->AllLink);
        --g_Status.LiveContexts;
        ++g_Status.Freed;
        KeReleaseSpinLock(&g_Lock, irql);
        FltReleaseContext(operation->InstanceState);
        ObDereferenceObject(operation->TargetProcess);
        ExFreePoolWithTag(operation, kTag);
    }

    void FinishLogical(Operation* operation)
    {
        const bool first = InterlockedCompareExchange(&operation->LogicalReleased, 1, 0) == 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        if (first) ++g_Status.LogicalCompleted;
        else ++g_Status.Violations;
        KeReleaseSpinLock(&g_Lock, irql);
        if (first) DropReference(operation);
    }

    // g_Lock held. Cancellation only signals the unique completion worker;
    // it never completes or frees an operation from a second execution path.
    void Wake(Operation* operation, ULONG reason)
    {
        if (reason > operation->WakeReason) operation->WakeReason = reason;
        KeSetEvent(&operation->Resume, IO_NO_INCREMENT, FALSE);
    }

    // g_Lock held. Return the arm's process reference to release outside the
    // spin lock. Publication, consumption and retirement use this same lock.
    PEPROCESS Disarm()
    {
        PEPROCESS target = g_Target;
        g_Target = nullptr;
        g_Status.ArmedMode = 0;
        g_Status.ArmedRemaining = 0;
        g_Status.ArmedGeneration = 0;
        g_Gate = 0;
        return target;
    }

    PEPROCESS ChangeTopology()
    {
        ++g_Status.TopologyGeneration;
        if (g_Target != nullptr) ++g_Status.TopologyDisarms;
        return Disarm();
    }

    // PASSIVE_LEVEL, no spin lock. An exit code of STATUS_PENDING (259) is
    // legal, so the code alone is not a liveness test. Use a kernel handle
    // and a zero-time wait; never wait for process exit while owning g_Control.
    NTSTATUS ProbeTarget(PEPROCESS target)
    {
        if (PsGetProcessExitStatus(target) != STATUS_PENDING) return STATUS_PROCESS_IS_TERMINATING;
        HANDLE handle = nullptr;
        NTSTATUS status = ObOpenObjectByPointer(target, OBJ_KERNEL_HANDLE, nullptr,
            SYNCHRONIZE, *PsProcessType, KernelMode, &handle);
        if (!NT_SUCCESS(status)) return status;
        LARGE_INTEGER immediate = {};
        status = ZwWaitForSingleObject(handle, FALSE, &immediate);
        ZwClose(handle);
        if (status == STATUS_TIMEOUT) return STATUS_SUCCESS;
        return status == STATUS_SUCCESS ? STATUS_PROCESS_IS_TERMINATING : STATUS_UNSUCCESSFUL;
    }

    void WatchGate(PEPROCESS target, ULONG phase, NTSTATUS status)
    {
        ULONG delay = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        if (g_Target == target && g_Gate == phase)
        {
            delay = g_GateMilliseconds;
            g_Gate = 0;
            ++g_Status.WatchGateEntered;
            g_Status.WatchGateKind = phase;
            g_Status.WatchGateTargetPid = HandleToULong(PsGetProcessId(target));
            g_Status.WatchGateGeneration = g_Status.ArmedGeneration;
            g_Status.WatchGateStatus = static_cast<ULONG>(status);
        }
        KeReleaseSpinLock(&g_Lock, irql);
        if (delay == 0) return;
        // Test-only 50..500 ms hold at the existing control-lock boundary.
        // The worker retains its snapshot reference, and Stop joins the worker.
        LARGE_INTEGER timeout;
        timeout.QuadPart = -static_cast<LONGLONG>(delay) * 10000;
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        KeAcquireSpinLock(&g_Lock, &irql);
        ++g_Status.WatchGateCompleted;
        KeReleaseSpinLock(&g_Lock, irql);
    }

    void RetireExitedTarget()
    {
        LockControl();
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        PEPROCESS target = g_Target;
        if (target != nullptr) ObReferenceObject(target);
        KeReleaseSpinLock(&g_Lock, irql);
        PEPROCESS retired = nullptr;
        if (target != nullptr)
        {
            WatchGate(target, KNDBG_PENDING_GATE_WATCH_SNAPSHOT, STATUS_PENDING);
            const NTSTATUS status = ProbeTarget(target);
            if (!NT_SUCCESS(status)) WatchGate(target, KNDBG_PENDING_GATE_WATCH_RESULT, status);
            KeAcquireSpinLock(&g_Lock, &irql);
            ++g_Status.TargetWatchProbes;
            // Topology teardown can retire the arm while the probe runs.
            if (g_Target != target) ++g_Status.TargetWatchStaleResults;
            else if (!NT_SUCCESS(status))
            {
                retired = Disarm();
                ++g_Status.TargetWatchRetires;
                for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
                {
                    auto operation = CONTAINING_RECORD(entry, Operation, AllLink);
                    if (operation->TargetProcess == target) Wake(operation, 2);
                }
            }
            KeReleaseSpinLock(&g_Lock, irql);
        }
        UnlockControl();
        if (retired != nullptr) ObDereferenceObject(retired);
        if (target != nullptr) ObDereferenceObject(target);
    }

    // Caller owns g_Control. Do not wait for I/O while holding a control lock.
    void ReleaseOwner(bool automatic)
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        PEPROCESS target = Disarm();
        PEPROCESS owner = g_OwnerProcess;
        g_OwnerProcess = nullptr;
        for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
        {
            auto operation = CONTAINING_RECORD(entry, Operation, AllLink);
            if (operation->Owner == g_Owner) Wake(operation, 2);
        }
        if (g_Owner != 0 && automatic) ++g_Status.OwnerRestores;
        g_Owner = 0;
        g_Status.OwnerPid = 0;
        KeReleaseSpinLock(&g_Lock, irql);
        if (target != nullptr) ObDereferenceObject(target);
        if (owner != nullptr) ObDereferenceObject(owner);
    }

    bool Queue(Operation* operation, PFLT_CALLBACK_DATA data, bool post)
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        const bool injected = (!post && operation->Mode == KNDBG_PENDING_FAIL_PRE_QUEUE) ||
            (post && operation->Mode == KNDBG_PENDING_FAIL_POST_QUEUE);
        if (g_Status.Stopping || operation->InstanceState->Stopping || operation->WakeReason >= 2 || injected)
        {
            ++g_Status.QueueFailed;
            KeReleaseSpinLock(&g_Lock, irql);
            return false;
        }
        // A synchronous post may free the logical context inside
        // FltCompletePendedPreOperation. The worker needs a separate reference
        // until it has finished its own tail, even in that immediate-completion case.
        InterlockedIncrement(&operation->References);
        operation->Data = data;
        operation->PostWork = post;
        if (post)
        {
            operation->WakeReason = 0;
            KeClearEvent(&operation->Resume);
        }
        InsertTailList(&g_Work, &operation->WorkLink);
        ++g_Status.QueueDepth;
        if (post) ++g_Status.PostQueued;
        else ++g_Status.PreQueued;
        KeSetEvent(&g_WorkAvailable, IO_NO_INCREMENT, FALSE);
        KeReleaseSpinLock(&g_Lock, irql);
        return true;
    }

    NTSTATUS WaitPre(Operation* operation, PFLT_CALLBACK_DATA data)
    {
        const ULONGLONG deadline = KeQueryInterruptTime() +
            static_cast<ULONGLONG>(operation->DelayMilliseconds) * 10000;
        for (;;)
        {
            // A synchronous request's cancellation need not wake the system
            // thread's cancellable wait. Check the held IRP itself as well.
            // This fixture admits a bounded target batch, with a 10 ms poll;
            // it does not install another cancel callback with a separate lifetime.
            if (FltIsIoCanceled(data)) return STATUS_CANCELLED;
            const ULONGLONG now = KeQueryInterruptTime();
            if (now >= deadline) return STATUS_TIMEOUT;
            LARGE_INTEGER timeout;
            timeout.QuadPart = -static_cast<LONGLONG>(min(deadline - now, 100000ull));
            const NTSTATUS status = FltCancellableWaitForSingleObject(&operation->Resume, &timeout, data);
            if (FltIsIoCanceled(data)) return STATUS_CANCELLED;
            if (status != STATUS_TIMEOUT) return status;
        }
    }

    void TestGate(Operation* operation, PFLT_CALLBACK_DATA data, ULONG gate)
    {
        if (operation->Gate != gate) return;
        const bool early = gate == KNDBG_PENDING_GATE_BEFORE_LOWER;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        if (early) ++g_Status.BeforeLowerEntered;
        else ++g_Status.RaceEntered;
        KeReleaseSpinLock(&g_Lock, irql);
        // Test-only, bounded wait with no lock held. Keep the existing
        // ownership while cancellation, process exit and stop enter concurrently.
        // Stop joins this thread (or FltMgr drains the early pre callback).
        LARGE_INTEGER timeout;
        timeout.QuadPart = -static_cast<LONGLONG>(operation->GateMilliseconds) * 10000;
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        const bool cancelled = FltIsIoCanceled(data) != FALSE;
        KeAcquireSpinLock(&g_Lock, &irql);
        if (early)
        {
            ++g_Status.BeforeLowerCompleted;
            if (cancelled) ++g_Status.BeforeLowerCancelSeen;
            if (g_Status.Stopping) ++g_Status.BeforeLowerStopSeen;
            if (operation->InstanceState->Stopping) ++g_Status.BeforeLowerTeardownSeen;
        }
        else
        {
            ++g_Status.RaceCompleted;
            if (cancelled) ++g_Status.RaceCancelSeen;
            if (g_Status.Stopping) ++g_Status.RaceStopSeen;
            if (operation->InstanceState->Stopping) ++g_Status.RaceTeardownSeen;
        }
        KeReleaseSpinLock(&g_Lock, irql);
    }

    VOID Worker(PVOID)
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        g_Status.WorkerAlive = 1;
        KeReleaseSpinLock(&g_Lock, irql);
        for (;;)
        {
            // A new ARM can follow this target's exit notification but precede
            // its final process signal (including exit code 259). Notification
            // cleanup has already run in that case. Keep unused reservations
            // watched until they are consumed or retired, without a new thread.
            RetireExitedTarget();
            KeAcquireSpinLock(&g_Lock, &irql);
            const bool armed = g_Target != nullptr;
            KeReleaseSpinLock(&g_Lock, irql);
            LARGE_INTEGER probeInterval;
            probeInterval.QuadPart = -1000000; // 100 ms, only while an arm exists.
            KeWaitForSingleObject(&g_WorkAvailable, Executive, KernelMode, FALSE, armed ? &probeInterval : nullptr);
            for (;;)
            {
                KeAcquireSpinLock(&g_Lock, &irql);
                if (IsListEmpty(&g_Work))
                {
                    const bool stopping = g_Status.Stopping != 0;
                    if (stopping) g_Status.WorkerAlive = 0;
                    KeReleaseSpinLock(&g_Lock, irql);
                    if (stopping) PsTerminateSystemThread(STATUS_SUCCESS);
                    break;
                }
                auto operation = CONTAINING_RECORD(RemoveHeadList(&g_Work), Operation, WorkLink);
                const bool post = operation->PostWork;
                PFLT_CALLBACK_DATA data = operation->Data;
                --g_Status.QueueDepth;
                ++g_Status.ActiveWorkers;
                KeReleaseSpinLock(&g_Lock, irql);
                TestGate(operation, data, post ? KNDBG_PENDING_GATE_POST : KNDBG_PENDING_GATE_PRE);
                LARGE_INTEGER timeout;
                timeout.QuadPart = -static_cast<LONGLONG>(operation->DelayMilliseconds) * 10000;
                // Pre I/O has not reached lower drivers and has no cancel routine
                // installed by us. FltMgr safely arbitrates cancellation of this wait.
                // Post already owns the completion: preserve the underlying result
                // and always resume completion, including owner exit/teardown.
                const NTSTATUS waited = post
                    ? KeWaitForSingleObject(&operation->Resume, Executive, KernelMode, FALSE, &timeout)
                    : WaitPre(operation, data);
                KeAcquireSpinLock(&g_Lock, &irql);
                // A READ may continue in the System process only with its pages
                // locked. This guard also prevents future queue changes from
                // forwarding an unprepared user buffer to the file system.
                const bool missingMdl = !post && data->Iopb->MajorFunction == IRP_MJ_READ &&
                    data->Iopb->Parameters.Read.MdlAddress == nullptr;
                if (missingMdl) ++g_Status.Violations;
                const bool cancel = missingMdl || !NT_SUCCESS(waited) || operation->WakeReason >= 2 ||
                    g_Status.Stopping || operation->InstanceState->Stopping;
                if (post) ++g_Status.PostCompleted;
                else
                {
                    ++g_Status.PreCompleted;
                    if (cancel) ++g_Status.PreCancelled;
                }
                KeReleaseSpinLock(&g_Lock, irql);
                if (post)
                {
                    FltCompletePendedPostOperation(data);
                    FinishLogical(operation);
                }
                else if (cancel)
                {
                    data->IoStatus.Status = STATUS_CANCELLED;
                    data->IoStatus.Information = 0;
                    FltCompletePendedPreOperation(data, FLT_PREOP_COMPLETE, nullptr);
                    FinishLogical(operation);
                }
                else
                {
                    // Ownership of the logical reference passes to post. Do not
                    // access data again: downstream completion may run immediately.
                    FltCompletePendedPreOperation(data, FLT_PREOP_SUCCESS_WITH_CALLBACK, operation);
                }
                DropReference(operation); // Worker reference, not post's reference.
                KeAcquireSpinLock(&g_Lock, &irql);
                --g_Status.ActiveWorkers;
                KeReleaseSpinLock(&g_Lock, irql);
            }
        }
    }

    VOID FLTAPI ContextCleanup(PFLT_CONTEXT, FLT_CONTEXT_TYPE)
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        --g_Status.LiveInstances;
        KeReleaseSpinLock(&g_Lock, irql);
    }

    NTSTATUS FLTAPI Connect(PFLT_PORT port, PVOID, PVOID, ULONG size, PVOID* cookie)
    {
        if (size != 0) return STATUS_INVALID_PARAMETER;
        LockControl();
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
        if (g_Status.Stopping) status = STATUS_FLT_DELETING_OBJECT;
        else if (g_NextClient != MAXULONG_PTR)
        {
            for (auto& client : g_Clients)
            {
                if (client.Id != 0) continue;
                client = {++g_NextClient, port, PsGetCurrentProcessId()};
                *cookie = reinterpret_cast<PVOID>(client.Id);
                ++g_Status.Connections;
                status = STATUS_SUCCESS;
                break;
            }
        }
        KeReleaseSpinLock(&g_Lock, irql);
        UnlockControl();
        return status;
    }

    VOID FLTAPI Disconnect(PVOID cookie)
    {
        LockControl();
        const ULONG_PTR id = reinterpret_cast<ULONG_PTR>(cookie);
        if (g_Owner == id) ReleaseOwner(true);
        PFLT_PORT port = nullptr;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        auto client = FindClient(id);
        if (client != nullptr)
        {
            port = client->Port;
            *client = {};
            --g_Status.Connections;
        }
        KeReleaseSpinLock(&g_Lock, irql);
        UnlockControl();
        if (port != nullptr) FltCloseClientPort(g_Filter, &port);
    }

    NTSTATUS FLTAPI Message(PVOID cookie, PVOID input, ULONG inputSize,
        PVOID output, ULONG outputSize, PULONG returned)
    {
        *returned = 0;
        if (input == nullptr || inputSize != sizeof(KNDBG_PENDING_REQUEST) ||
            output == nullptr || outputSize < sizeof(KNDBG_PENDING_STATUS)) return STATUS_INVALID_PARAMETER;
        KNDBG_PENDING_REQUEST request = {};
        __try { RtlCopyMemory(&request, input, sizeof(request)); ProbeForWrite(output, sizeof(g_Status), 1); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
        if (request.Magic != KNDBG_PENDING_MAGIC || request.Version != KNDBG_PENDING_VERSION ||
            request.Size != sizeof(request) || request.Action > KNDBG_PENDING_QUERY_RACE)
            return STATUS_INVALID_PARAMETER;
        const bool queryRace = request.Action == KNDBG_PENDING_QUERY_RACE;
        const bool batch = request.Action == KNDBG_PENDING_ARM_READ_BATCH;
        const bool race = request.Action == KNDBG_PENDING_ARM_RACE || batch;
        const bool arm = request.Action == KNDBG_PENDING_ARM || race;
        if (batch)
        {
            if (request.Mode != KNDBG_PENDING_DRAIN_PAIR || request.Reserved < 2 || request.Reserved > 8 ||
                request.DelayMilliseconds < 50 || request.DelayMilliseconds > 500) return STATUS_INVALID_PARAMETER;
        }
        else if (race)
        {
            const bool gateValid =
                (request.Reserved == KNDBG_PENDING_GATE_PRE && request.Mode != KNDBG_PENDING_POST) ||
                (request.Reserved == KNDBG_PENDING_GATE_POST &&
                    (request.Mode == KNDBG_PENDING_POST || request.Mode == KNDBG_PENDING_BOTH)) ||
                ((request.Reserved == KNDBG_PENDING_GATE_BEFORE_LOWER ||
                  request.Reserved == KNDBG_PENDING_GATE_EXIT_TAIL ||
                  request.Reserved == KNDBG_PENDING_GATE_WATCH_SNAPSHOT ||
                  request.Reserved == KNDBG_PENDING_GATE_WATCH_RESULT) && request.Mode == KNDBG_PENDING_DRAIN_PAIR);
            if (!gateValid || request.Mode > KNDBG_PENDING_DRAIN_PAIR ||
                request.DelayMilliseconds < 50 || request.DelayMilliseconds > 500) return STATUS_INVALID_PARAMETER;
        }
        else if (request.Reserved != 0) return STATUS_INVALID_PARAMETER;
        if (queryRace ? (request.Mode != 0 || request.TargetPid != 0 ||
                        request.DelayMilliseconds < 50 || request.DelayMilliseconds > 500) :
            arm ? (request.Mode < KNDBG_PENDING_PRE || request.Mode > KNDBG_PENDING_FAIL_READ_LOCK ||
                   request.TargetPid <= 4 || request.DelayMilliseconds == 0 || request.DelayMilliseconds > 2000) :
                  (request.Mode != 0 || request.TargetPid != 0 || request.DelayMilliseconds != 0))
            return STATUS_INVALID_PARAMETER;
        if (request.Action == KNDBG_PENDING_QUERY || queryRace)
        {
            // A read-only snapshot must remain observable while the watcher or
            // a lifecycle transition owns g_Control. Client identity and status
            // already share g_Lock; do not hold it while touching user memory.
            KNDBG_PENDING_STATUS snapshot = {};
            KIRQL irql;
            KeAcquireSpinLock(&g_Lock, &irql);
            auto client = FindClient(reinterpret_cast<ULONG_PTR>(cookie));
            const bool allowed = client != nullptr && client->Pid == PsGetCurrentProcessId();
            if (allowed)
            {
                ++g_Status.QueryStarted;
                ++g_Status.QueryActive;
                if (queryRace) ++g_Status.QueryGateEntered;
                snapshot = g_Status;
            }
            else ++g_Status.QueryDenied;
            KeReleaseSpinLock(&g_Lock, irql);
            if (!allowed) return STATUS_ACCESS_DENIED;
            if (queryRace)
            {
                // Hold only an authorized, registered Message callback. No
                // client pointer survives the snapshot and no lock is held.
                // FltMgr must drain this callback before unloading its code.
                LARGE_INTEGER timeout;
                timeout.QuadPart = -static_cast<LONGLONG>(request.DelayMilliseconds) * 10000;
                KeDelayExecutionThread(KernelMode, FALSE, &timeout);
                KeAcquireSpinLock(&g_Lock, &irql);
                ++g_Status.QueryGateCompleted;
                KeReleaseSpinLock(&g_Lock, irql);
            }
            NTSTATUS status = STATUS_SUCCESS;
            __try { RtlCopyMemory(output, &snapshot, sizeof(snapshot)); *returned = sizeof(snapshot); }
            __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            KeAcquireSpinLock(&g_Lock, &irql);
            --g_Status.QueryActive;
            ++g_Status.QueryCompleted;
            if (!NT_SUCCESS(status)) ++g_Status.QueryReplyFailures;
            KeReleaseSpinLock(&g_Lock, irql);
            return status;
        }
        PEPROCESS target = nullptr;
        if (arm)
        {
            const NTSTATUS lookedUp = PsLookupProcessByProcessId(ULongToHandle(request.TargetPid), &target);
            if (!NT_SUCCESS(lookedUp)) return lookedUp;
        }
        LockControl();
        const ULONG_PTR id = reinterpret_cast<ULONG_PTR>(cookie);
        NTSTATUS status = STATUS_SUCCESS;
        const NTSTATUS targetStatus = arm ? ProbeTarget(target) : STATUS_SUCCESS;
        KIRQL irql;
        KeAcquireSpinLock(&g_Lock, &irql);
        auto client = FindClient(id);
        if (client == nullptr || client->Pid != PsGetCurrentProcessId()) status = STATUS_ACCESS_DENIED;
        else if (g_Status.Stopping) status = STATUS_FLT_DELETING_OBJECT;
        else if (g_Owner != 0 && g_Owner != id) status = STATUS_DEVICE_BUSY;
        else if (arm && !NT_SUCCESS(targetStatus))
        {
            ++g_Status.TargetArmRejected;
            status = targetStatus;
        }
        else if (arm && g_Status.InstanceStarts != g_Status.InstanceCompletes)
        {
            ++g_Status.ArmDuringTeardownRejected;
            status = STATUS_DEVICE_BUSY;
        }
        else if (arm && g_Status.LiveInstances == 0) status = STATUS_DEVICE_NOT_READY;
        else if (arm && (g_Status.ArmedMode != 0 || g_Status.LiveContexts != 0 ||
                         g_Status.ActiveWorkers != 0 || g_Status.QueueDepth != 0)) status = STATUS_DEVICE_BUSY;
        else if (arm)
        {
            if (g_Owner == 0)
            {
                g_Owner = id;
                g_OwnerProcess = PsGetCurrentProcess();
                ObReferenceObject(g_OwnerProcess);
                g_Status.OwnerPid = HandleToULong(PsGetCurrentProcessId());
            }
            g_Target = target; target = nullptr;
            g_Status.ArmedMode = request.Mode;
            g_Status.ArmedRemaining = batch ? request.Reserved : 1;
            g_Status.ArmedGeneration = g_Status.TopologyGeneration;
            if (batch) ++g_Status.BatchArms;
            g_Delay = race ? 2000 : request.DelayMilliseconds;
            g_Gate = batch ? KNDBG_PENDING_GATE_PRE : (race ? request.Reserved : 0);
            g_GateMilliseconds = race ? request.DelayMilliseconds : 0;
            KeSetEvent(&g_WorkAvailable, IO_NO_INCREMENT, FALSE);
        }
        else if (request.Action == KNDBG_PENDING_RESUME)
        {
            for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
            {
                auto operation = CONTAINING_RECORD(entry, Operation, AllLink);
                if (operation->Owner == id) Wake(operation, 1);
            }
        }
        KeReleaseSpinLock(&g_Lock, irql);
        if (NT_SUCCESS(status) && request.Action == KNDBG_PENDING_RELEASE) ReleaseOwner(false);
        if (NT_SUCCESS(status))
        {
            KNDBG_PENDING_STATUS snapshot;
            KeAcquireSpinLock(&g_Lock, &irql);
            snapshot = g_Status;
            KeReleaseSpinLock(&g_Lock, irql);
            __try { RtlCopyMemory(output, &snapshot, sizeof(snapshot)); *returned = sizeof(snapshot); }
            __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            if (!NT_SUCCESS(status) && g_Owner == id)
                ReleaseOwner(true);
        }
        UnlockControl();
        if (target != nullptr) ObDereferenceObject(target);
        return status;
    }
}

void PendingIoInitialize()
{
    KeInitializeSpinLock(&g_Lock);
    KeInitializeMutex(&g_Control, 0);
    KeInitializeEvent(&g_WorkAvailable, SynchronizationEvent, FALSE);
    InitializeListHead(&g_Work);
    InitializeListHead(&g_Operations);
    g_Status.Magic = KNDBG_PENDING_MAGIC;
    g_Status.Version = KNDBG_PENDING_VERSION;
    g_Status.Size = sizeof(g_Status);
    g_Contexts[0].ContextType = FLT_INSTANCE_CONTEXT;
    g_Contexts[0].ContextCleanupCallback = ContextCleanup;
    g_Contexts[0].Size = sizeof(Instance);
    g_Contexts[0].PoolTag = kTag;
    g_Contexts[1].ContextType = FLT_CONTEXT_END;
}

const FLT_CONTEXT_REGISTRATION* PendingIoContextRegistration() { return g_Contexts; }

NTSTATUS PendingIoStart(PFLT_FILTER filter, PCUNICODE_STRING registryPath)
{
    g_Filter = filter;
    constexpr WCHAR suffix[] = L"\\Parameters";
    if (registryPath->Length + sizeof(suffix) > sizeof(g_AuditPath)) return STATUS_NAME_TOO_LONG;
    RtlCopyMemory(g_AuditPath, registryPath->Buffer, registryPath->Length);
    RtlCopyMemory(reinterpret_cast<PUCHAR>(g_AuditPath) + registryPath->Length, suffix, sizeof(suffix));
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS status = PsCreateSystemThread(&g_Worker, THREAD_ALL_ACCESS, &attributes, nullptr, nullptr, Worker, nullptr);
    if (!NT_SUCCESS(status)) return status;
    PSECURITY_DESCRIPTOR security = nullptr;
    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status))
    {
        UNICODE_STRING name = RTL_CONSTANT_STRING(KNDBG_PENDING_PORT);
        InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, nullptr, security);
        status = FltCreateCommunicationPort(filter, &g_Server, &attributes, nullptr,
            Connect, Disconnect, Message, RTL_NUMBER_OF(g_Clients));
        FltFreeSecurityDescriptor(security);
    }
    return status;
}

void PendingIoStop()
{
    LockControl();
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    g_Status.Stopping = 1;
    for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
        Wake(CONTAINING_RECORD(entry, Operation, AllLink), 3);
    KeSetEvent(&g_WorkAvailable, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&g_Lock, irql);
    ReleaseOwner(false);
    UnlockControl();
    if (g_Server != nullptr) { FltCloseCommunicationPort(g_Server); g_Server = nullptr; }
    // The thread is joined, not just counted as idle. No worker instruction may
    // survive driver unload after completing the last I/O or freeing its context.
    if (g_Worker != nullptr)
    {
        ZwWaitForSingleObject(g_Worker, FALSE, nullptr);
        ZwClose(g_Worker);
        g_Worker = nullptr;
    }
}

void PendingIoUnregistered()
{
    // Called after FltUnregisterFilter has drained callbacks and instance contexts.
    // Keep a bounded final ledger across unload so tests can check the final frees.
    UNICODE_STRING path, value = RTL_CONSTANT_STRING(L"PendingIoFinalAudit");
    RtlInitUnicodeString(&path, g_AuditPath);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE key = nullptr;
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_SET_VALUE, &attributes)))
    {
        ZwSetValueKey(key, &value, 0, REG_BINARY, &g_Status, sizeof(g_Status));
        ZwClose(key);
    }
    g_Filter = nullptr;
}

void PendingIoProcessExit(PEPROCESS process)
{
    LockControl();
    if (g_OwnerProcess == process) ReleaseOwner(true);
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    PEPROCESS target = nullptr;
    ULONG exitGateMilliseconds = 0;
    if (g_Target == process)
    {
        if (g_Gate == KNDBG_PENDING_GATE_EXIT_TAIL)
        {
            exitGateMilliseconds = g_GateMilliseconds;
            ++g_Status.TargetExitGateEntered;
        }
        target = Disarm();
    }
    for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
    {
        auto operation = CONTAINING_RECORD(entry, Operation, AllLink);
        if (operation->TargetProcess == process) Wake(operation, 2);
    }
    KeReleaseSpinLock(&g_Lock, irql);
    if (target != nullptr) ObDereferenceObject(target);
    UnlockControl();
    if (exitGateMilliseconds != 0)
    {
        // Test-only 50..500 ms tail, with no control/spin lock held. The old
        // cancellation sweep is finished but the process is not signaled yet.
        // ManagedCallbacksStop removes/joins this notification before unload.
        LARGE_INTEGER timeout;
        timeout.QuadPart = -static_cast<LONGLONG>(exitGateMilliseconds) * 10000;
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        KeAcquireSpinLock(&g_Lock, &irql);
        ++g_Status.TargetExitGateCompleted;
        if (g_Status.Stopping) ++g_Status.TargetExitGateStopSeen;
        KeReleaseSpinLock(&g_Lock, irql);
    }
}

NTSTATUS PendingIoInstanceSetup(PCFLT_RELATED_OBJECTS objects)
{
    Instance* state = nullptr;
    NTSTATUS status = FltAllocateContext(g_Filter, FLT_INSTANCE_CONTEXT, sizeof(Instance),
        NonPagedPoolNx, reinterpret_cast<PFLT_CONTEXT*>(&state));
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(state, sizeof(*state));
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    ++g_Status.LiveInstances;
    KeReleaseSpinLock(&g_Lock, irql);
    alignas(8) UCHAR buffer[1024];
    ULONG size = 0;
    status = FltGetInstanceInformation(objects->Instance, InstanceBasicInformation, buffer, sizeof(buffer), &size);
    if (NT_SUCCESS(status))
    {
        auto information = reinterpret_cast<INSTANCE_BASIC_INFORMATION*>(buffer);
        if (size < sizeof(*information) || size > sizeof(buffer) ||
            static_cast<ULONG>(information->InstanceNameBufferOffset) + information->InstanceNameLength > size ||
            (information->InstanceNameBufferOffset | information->InstanceNameLength) % sizeof(WCHAR) != 0)
            status = STATUS_INVALID_PARAMETER;
        else
        {
            UNICODE_STRING name;
            name.Buffer = reinterpret_cast<PWCHAR>(buffer + information->InstanceNameBufferOffset);
            name.Length = name.MaximumLength = information->InstanceNameLength;
            UNICODE_STRING lower = RTL_CONSTANT_STRING(L"KnLiveDbgMiniFilterFixture.Lower");
            state->Lower = RtlEqualUnicodeString(&name, &lower, TRUE) != FALSE;
        }
    }
    if (NT_SUCCESS(status)) status = FltSetInstanceContext(objects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, state, nullptr);
    PEPROCESS retired = nullptr;
    if (NT_SUCCESS(status))
    {
        KeAcquireSpinLock(&g_Lock, &irql);
        if (g_Status.Stopping)
        {
            ++g_Status.SetupDuringStopRejected;
            status = STATUS_FLT_DELETING_OBJECT;
        }
        else retired = ChangeTopology();
        KeReleaseSpinLock(&g_Lock, irql);
    }
    if (retired != nullptr) ObDereferenceObject(retired);
    FltReleaseContext(state);
    return status;
}

void PendingIoInstanceTeardownStart(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_TEARDOWN_FLAGS reason)
{
    Instance* state = nullptr;
    if (!NT_SUCCESS(FltGetInstanceContext(objects->Instance, reinterpret_cast<PFLT_CONTEXT*>(&state)))) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    state->Stopping = true;
    PEPROCESS retired = ChangeTopology();
    ++g_Status.InstanceStarts;
    if (reason & FLTFL_INSTANCE_TEARDOWN_MANUAL) ++g_Status.ManualTeardowns;
    if (reason & (FLTFL_INSTANCE_TEARDOWN_FILTER_UNLOAD | FLTFL_INSTANCE_TEARDOWN_MANDATORY_FILTER_UNLOAD))
        ++g_Status.UnloadTeardowns;
    for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
    {
        auto operation = CONTAINING_RECORD(entry, Operation, AllLink);
        if (operation->InstanceState == state) Wake(operation, 3);
    }
    KeReleaseSpinLock(&g_Lock, irql);
    if (retired != nullptr) ObDereferenceObject(retired);
    FltReleaseContext(state);
}

void PendingIoInstanceTeardownComplete(PCFLT_RELATED_OBJECTS)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    ++g_Status.InstanceCompletes;
    KeReleaseSpinLock(&g_Lock, irql);
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PendingIoPreOperation(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects, PVOID* completionContext)
{
    *completionContext = nullptr;
    if (!FLT_IS_IRP_OPERATION(data) || (data->Iopb->IrpFlags & IRP_PAGING_IO) != 0 ||
        IoGetTopLevelIrp() != nullptr) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    Instance* state = nullptr;
    if (!NT_SUCCESS(FltGetInstanceContext(objects->Instance, reinterpret_cast<PFLT_CONTEXT*>(&state))))
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    PEPROCESS requestor = FltGetRequestorProcess(data), target = nullptr;
    ULONG mode = 0, delay = 0, gate = 0, gateMilliseconds = 0;
    ULONG_PTR owner = 0;
    ULONGLONG generation = 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    if (!g_Status.Stopping && !state->Stopping)
    {
        const bool read = data->Iopb->MajorFunction == IRP_MJ_READ;
        if (!state->Lower && g_Status.ArmedMode != 0 && requestor == g_Target &&
            read == (g_Status.ArmedMode == KNDBG_PENDING_DRAIN_PAIR ||
                     g_Status.ArmedMode == KNDBG_PENDING_FAIL_READ_LOCK))
        {
            mode = g_Status.ArmedMode;
            target = g_Target;
            generation = g_Status.ArmedGeneration;
            // The arm owns one process reference until its final admission.
            // Earlier members of a bounded batch each acquire their own.
            if (--g_Status.ArmedRemaining == 0)
            {
                g_Status.ArmedMode = 0; g_Target = nullptr; g_Status.ArmedGeneration = 0;
            }
            else ObReferenceObject(target);
            delay = g_Delay; owner = g_Owner;
            gate = g_Gate; gateMilliseconds = g_GateMilliseconds;
            // Hold only the first worker. The remaining READs can accumulate
            // behind it, then drain without serial per-request test delays.
            g_Gate = 0;
        }
        else if (state->Lower && read)
        {
            for (auto entry = g_Operations.Flink; entry != &g_Operations; entry = entry->Flink)
            {
                auto upper = CONTAINING_RECORD(entry, Operation, AllLink);
                if ((upper->Mode == KNDBG_PENDING_DRAIN_PAIR || upper->Mode == KNDBG_PENDING_FAIL_READ_LOCK) &&
                    !upper->LowerClaimed &&
                    upper->LogicalReleased == 0 &&
                    upper->FileObject == objects->FileObject && upper->TargetProcess == requestor)
                {
                    // Concurrent READs can share the file, process, offset and
                    // length. Only this I/O's callback data may claim its pair.
                    if (upper->PreIdentity != data)
                    {
                        ++g_Status.OtherReadSkipped;
                        continue;
                    }
                    // A live owner and the same I/O are insufficient after a
                    // lower instance was detached/replaced. An old upper pre
                    // must not start new pending work in the new topology.
                    if (upper->Generation != g_Status.TopologyGeneration)
                    {
                        ++g_Status.GenerationLowerRejected;
                        continue;
                    }
                    // Release/exit may have woken the upper context before this
                    // callback reached the lower instance. Do not publish a new
                    // unsignalled context after that owner's cancellation sweep.
                    // Check and publish under the same lock used by ReleaseOwner.
                    if (upper->Owner != g_Owner || upper->WakeReason >= 2)
                    {
                        ++g_Status.StaleLowerRejected;
                        continue;
                    }
                    upper->LowerClaimed = true;
                    mode = upper->Mode == KNDBG_PENDING_FAIL_READ_LOCK ?
                        KNDBG_PENDING_FAIL_READ_LOCK : KNDBG_PENDING_PRE;
                    target = requestor; ObReferenceObject(target);
                    delay = upper->DelayMilliseconds; owner = upper->Owner;
                    generation = upper->Generation;
                    gate = upper->Gate; gateMilliseconds = upper->GateMilliseconds;
                    break;
                }
            }
        }
    }
    if (target == nullptr)
    {
        KeReleaseSpinLock(&g_Lock, irql);
        FltReleaseContext(state);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    // The small, nonpaged allocation is valid at DISPATCH_LEVEL. Keep arm
    // consumption and publication atomic with owner/target exit and new ARM
    // requests: no unlisted operation may escape cancellation in that gap.
    Operation* operation = mode == KNDBG_PENDING_FAIL_ALLOC ? nullptr :
        static_cast<Operation*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Operation), kTag));
    if (operation == nullptr)
    {
        ++g_Status.AllocFailed;
        KeReleaseSpinLock(&g_Lock, irql);
        FltReleaseContext(state); ObDereferenceObject(target);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    operation->References = 1;
    operation->InstanceState = state;
    operation->FileObject = objects->FileObject;
    operation->PreIdentity = data;
    operation->Generation = generation;
    operation->TargetProcess = target;
    operation->Mode = mode;
    operation->Owner = owner;
    operation->DelayMilliseconds = delay;
    operation->Gate = gate;
    operation->GateMilliseconds = gateMilliseconds;
    KeInitializeEvent(&operation->Resume, NotificationEvent, FALSE);
    InsertTailList(&g_Operations, &operation->AllLink);
    ++g_Status.LiveContexts; ++g_Status.Created;
    KeReleaseSpinLock(&g_Lock, irql);
    if (!state->Lower && mode == KNDBG_PENDING_DRAIN_PAIR)
        TestGate(operation, data, KNDBG_PENDING_GATE_BEFORE_LOWER);
    const bool pend = mode == KNDBG_PENDING_PRE || mode == KNDBG_PENDING_BOTH ||
        mode == KNDBG_PENDING_FAIL_PRE_QUEUE || (state->Lower && mode == KNDBG_PENDING_FAIL_READ_LOCK);
    if (pend && data->Iopb->MajorFunction == IRP_MJ_READ)
    {
        // FltCompletePendedPreOperation continues below us in the worker's
        // process context. Preserve a valid MDL before handing off a READ;
        // retaining CallbackData or a process object does not pin user pages.
        // FltMgr owns this MDL and unlocks/frees it with the I/O. We never free
        // it ourselves or dereference the original user virtual address.
        const NTSTATUS locked = mode == KNDBG_PENDING_FAIL_READ_LOCK ? STATUS_INSUFFICIENT_RESOURCES :
            FltLockUserBuffer(data);
        const bool bufferReady = NT_SUCCESS(locked) && data->Iopb->Parameters.Read.MdlAddress != nullptr;
        KeAcquireSpinLock(&g_Lock, &irql);
        if (bufferReady) ++g_Status.BufferLocks;
        else ++g_Status.BufferLockFailures;
        KeReleaseSpinLock(&g_Lock, irql);
        if (!bufferReady)
        {
            // Even a pre callback can arrive in an arbitrary process context.
            // Do not forward an unpinned buffer after a failed lock. This I/O
            // was never queued, so the callback still owns its completion.
            data->IoStatus.Status = NT_SUCCESS(locked) ? STATUS_INVALID_USER_BUFFER : locked;
            data->IoStatus.Information = 0;
            FinishLogical(operation);
            return FLT_PREOP_COMPLETE;
        }
    }
    // On queue failure, continue inline with a valid buffer and pass only the
    // context to post. No completion worker has acquired this request.
    if (pend && Queue(operation, data, false)) return FLT_PREOP_PENDING;
    *completionContext = operation;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PendingIoPostOperation(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS, PVOID completionContext, FLT_POST_OPERATION_FLAGS flags)
{
    auto operation = static_cast<Operation*>(completionContext);
    if (operation == nullptr) return FLT_POSTOP_FINISHED_PROCESSING;
    const bool draining = (flags & FLTFL_POST_OPERATION_DRAINING) != 0;
    KIRQL irql;
    KeAcquireSpinLock(&g_Lock, &irql);
    ++g_Status.PostCalled;
    if (draining) ++g_Status.PostDrained;
    KeReleaseSpinLock(&g_Lock, irql);
    // Mandatory context cleanup is independent of the managed counting bodies.
    // A draining post must never queue more work or run normal completion logic.
    if (!draining && (operation->Mode == KNDBG_PENDING_POST || operation->Mode == KNDBG_PENDING_BOTH ||
        operation->Mode == KNDBG_PENDING_FAIL_POST_QUEUE) && Queue(operation, data, true))
        return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
    FinishLogical(operation);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
