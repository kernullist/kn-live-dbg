#include "RuntimeCapabilities.h"

#include "DeviceClient.h"
#include "ObservationSourceJson.h"
#include "ProcessObservationSource.h"
#include "ReadReceiptJson.h"

#include <array>

RuntimeCapabilityProbe ProbeRuntimeCapabilities()
{
    RuntimeCapabilityProbe probe;
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
        ProcessObservationSource source(GetCurrentProcess(), probe.ProcessId, probe.ProcessCreateTime, {});
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
            probe.ProcessReadPassed = read.State == ObservationReadState::Complete && read.IdentityRevalidated;
            probe.ProcessBytesMatched = probe.ProcessReadPassed && read.Spans.size() == 1 &&
                read.Spans.front().Bytes == std::vector<uint8_t>(control.begin(), control.end());
            probe.ProcessReadJson = ObservationReadJson(source.Capabilities(), request, read);
            probe.ProcessReadSetJson = ObservationReadSetJson(operation->Snapshot());
            probe.ProcessReason = probe.ProcessBytesMatched ? L"owned_control_bytes_match" : ObservationReadStateName(read.State);
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
    {
        // Never create/start a service, load a driver, enable collection, switch
        // write mode, or acquire symbols. Another controller may deny this open.
        DeviceClient device;
        probe.NativeSourceOpened = device.Open(&probe.NativeReason);
        if (probe.NativeSourceOpened)
        {
            probe.NativeSourceEpoch = device.ObservationEpoch();
            probe.NativeContractPassed = device.QueryVersion(&probe.NativeReason);
            if (probe.NativeContractPassed)
            {
                probe.NativeVirtualAddressBits = device.AddressSpace().VirtualAddressBits;
                DriverSessionStatus status{};
                probe.NativeSessionPassed = device.QuerySessionStatus(&status, &probe.NativeReason);
            }
        }
    }
    probe.FinishedMs = GetTickCount64();
    return probe;
}
