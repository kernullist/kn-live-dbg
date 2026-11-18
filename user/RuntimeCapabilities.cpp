#include "RuntimeCapabilities.h"

#include "DeviceClient.h"
#include "ObservationSourceJson.h"
#include "ProcessObservationSource.h"
#include "ReadReceiptJson.h"
#include "TimelineStore.h"

#include <array>

RuntimeCapabilityProbe ProbeOwnedProcessCapabilities()
{
    RuntimeCapabilityProbe probe;
    ProcessHandleJournal handles;
    probe.NativeReason = L"outside_owned_process_scope";
    probe.StartedMs = GetTickCount64();
    probe.ProcessId = GetCurrentProcessId();
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
    {
        probe.ProcessCreateTime = (uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
        // A known owned stack range is the only memory read by this probe. LA48
        // is explicitly a compatibility shape, never a detection of active CR4.
        std::array<uint8_t, 32> control{};
        for (size_t i = 0; i < control.size(); ++i)
        {
            control[i] = static_cast<uint8_t>(0x51 + i);
        }
        probe.ProcessHandleAttempted = true;
        ObservedProcessHandle readOnly(handles, ProcessHandleSite::SelfProbe, probe.ProcessId, probe.ProcessCreateTime);
        readOnly.Open(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
        ProcessObservationSource source(readOnly.get(), probe.ProcessId, probe.ProcessCreateTime, {}, handles, readOnly.Acquisition().AcquisitionId);
        probe.ProcessSourceOpened = !source.Capabilities().SourceId.empty();
        if (probe.ProcessSourceOpened)
        {
            ObservationReadRequest request;
            request.SourceId = source.Capabilities().SourceId;
            request.Address = reinterpret_cast<uint64_t>(control.data());
            request.Length = static_cast<uint32_t>(control.size());
            request.ByteBudget = control.size();
            request.AllowResidencyChanges = true;
            ObservationOperationBudget budget;
            budget.MaximumBytes = control.size();
            budget.MaximumSourceCalls = 1;
            budget.MaximumReceipts = 2;
            const auto operation = std::make_shared<ObservationReadOperation>(
                L"capability_owned_read:" + source.Capabilities().SourceId + L":" + std::to_wstring(probe.StartedMs),
                L"process:" + std::to_wstring(probe.ProcessId) + L":" + std::to_wstring(probe.ProcessCreateTime),
                source.Capabilities().SourceId, budget);
            RecordingObservationSource recording(source, operation);
            const auto read = recording.Read(request);
            probe.ProcessReadAttempted = true;
            probe.ProcessReadPassed = CapabilityReadAccepted(read);
            probe.ProcessBytesMatched = probe.ProcessReadPassed && read.Spans.size() == 1 &&
                read.Spans.front().Bytes == std::vector<uint8_t>(control.begin(), control.end());
            probe.ProcessReadJson = ObservationReadJson(source.Capabilities(), request, read);
            probe.ProcessReadSetJson = ObservationReadSetJson(operation->Snapshot());
            probe.ProcessReason = probe.ProcessBytesMatched ? L"owned_control_bytes_match" :
                read.OperationDeadlineExceeded ? L"operation_deadline_exceeded" :
                read.CancellationObserved ? L"cancelled" : ObservationReadStateName(read.State);
        }
        else
        {
            probe.ProcessReason = L"owned_process_source_unavailable";
        }
    }
    else
    {
        probe.ProcessReason = L"process_identity_query_failed_win32_" + std::to_wstring(GetLastError());
    }
    const auto captured = handles.Snapshot();
    probe.ProcessHandlesAcquired = captured.Acquired;
    probe.ProcessHandlesClosed = captured.Closed;
    TimelineStore timeline;
    timeline.IngestProcessHandleActions(captured);
    const auto events = timeline.AllEvents();
    TimelineQueryOptions order;
    order.Source = L"observer";
    order.Domain = L"observer_action";
    order.NewestFirst = false;
    probe.ProcessHandleTimelineJson = BuildTimelineEventsJson(events, order, events.size());
    probe.FinishedMs = GetTickCount64();
    return probe;
}

RuntimeCapabilityProbe ProbeRuntimeCapabilities()
{
    auto probe = ProbeOwnedProcessCapabilities();
    {
        // Never create/start a service, load a driver, enable collection, switch
        // write mode, or acquire symbols. Another controller may deny this open.
        DeviceClient device;
        probe.NativeProbeAttempted = true;
        probe.NativeReason.clear();
        probe.NativeSourceOpened = device.Open(&probe.NativeReason);
        if (probe.NativeSourceOpened)
        {
            probe.NativeSourceEpoch = device.ObservationEpoch();
            probe.NativeContractPassed = device.QueryVersion(&probe.NativeReason);
            if (probe.NativeContractPassed)
            {
                probe.NativeVirtualAddressBits = device.AddressSpace().VirtualAddressBits;
                probe.NativeReadObservationSupported = device.HasReadObservationContract();
                DriverSessionStatus status{};
                probe.NativeSessionPassed = device.QuerySessionStatus(&status, &probe.NativeReason);
            }
            probe.NativeCloseAttempted = true;
            probe.NativeCloseSucceeded = device.Close(probe.NativeCloseError);
        }
    }
    probe.FinishedMs = GetTickCount64();
    return probe;
}
