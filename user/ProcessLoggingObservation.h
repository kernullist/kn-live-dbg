#pragma once

#include "ProcessHandleObservation.h"
#include "../shared/KnLiveDbgIoctl.h"
#include <array>
#include <mutex>
#include <vector>

struct ProcessLoggingSubject
{
    DWORD Pid = 0;
    uint64_t Created = 0, IdentityAcquisition = 0;
};

enum class ProcessLoggingStep
{
    ControlOpenFailed, ApiUnavailable, NativeReturned,
    DriverNotSubmitted, DriverTransportFailed, DriverInvalidEnvelope, DriverInconsistentReply, DriverReturned
};

struct ProcessLoggingAction
{
    uint64_t Sequence = 0, RequestedUtc = 0, ReturnedUtc = 0, ControlOpenSequence = 0;
    uint64_t ExpectedDeviceEpoch = 0, DeviceEpoch = 0;
    ProcessLoggingSubject Subject;
    uint32_t RequestedFlags = 0, InformationClass = 0, CallFlags = 0, NtStatus = 0;
    DWORD Win32Status = 0, ReturnedBytes = 0;
    ProcessLoggingStep Step = ProcessLoggingStep::ControlOpenFailed;

    bool HasOperationStatus() const
    {
        return Step == ProcessLoggingStep::NativeReturned || Step == ProcessLoggingStep::DriverReturned;
    }
    bool ReportedSuccess() const
    {
        return HasOperationStatus() && NtStatus == 0;
    }
    bool Unconfirmed() const
    {
        // An informational result, timeout or warning supplies no completion contract for these setters.
        if (HasOperationStatus()) { return NtStatus != 0 && (NtStatus >> 30) != 3; }
        return Step == ProcessLoggingStep::DriverTransportFailed || Step == ProcessLoggingStep::DriverInvalidEnvelope ||
            Step == ProcessLoggingStep::DriverInconsistentReply;
    }
};

// Only a complete reply for this request can supply operation status. Never retain the kernel address.
inline void DecodeProcessLoggingReply(ProcessLoggingAction& row, bool delivered, const KNDBG_SET_PROCESS_LOGGING_RESPONSE& reply)
{
    row.InformationClass = row.CallFlags = row.NtStatus = 0;
    if (!delivered) { row.Step = ProcessLoggingStep::DriverTransportFailed; return; }
    if (row.ReturnedBytes != sizeof(reply) || reply.Size != sizeof(reply) || reply.ProcessId != row.Subject.Pid)
    {
        row.Step = ProcessLoggingStep::DriverInvalidEnvelope;
        return;
    }
    row.InformationClass = reply.InformationClassUsed;
    row.CallFlags = reply.LoggingFlagsApplied;
    row.NtStatus = reply.NtStatus;
    row.Step = ProcessLoggingStep::DriverReturned;
    if (!row.ReportedSuccess()) { return; }
    // The existing driver echoes the full request even when the legacy class takes only the low two bits.
    const bool legacy = row.InformationClass == KNDBG_PROCESS_INFO_ENABLE_READWRITEVM_LOGGING;
    if ((!legacy && row.InformationClass != KNDBG_PROCESS_INFO_ENABLE_LOGGING) || (legacy && row.RequestedFlags && !(row.RequestedFlags & 3u)) ||
        (row.CallFlags != row.RequestedFlags && !(legacy && row.CallFlags == (row.RequestedFlags & 3u))))
    {
        row.Step = ProcessLoggingStep::DriverInconsistentReply;
    }
}

struct ProcessLoggingSnapshot
{
    uint64_t Total = 0, ControllerCreateTime = 0;
    DWORD ControllerPid = 0;
    std::vector<ProcessLoggingAction> Actions;
};

class ProcessLoggingJournal
{
public:
    void Record(ProcessLoggingAction row)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        row.Sequence = ++Total;
        Rows[(Total - 1) % Rows.size()] = row;
    }
    ProcessLoggingSnapshot Snapshot() const
    {
        ProcessLoggingSnapshot result;
        {
            std::lock_guard<std::mutex> lock(Mutex);
            result.Total = Total;
            const size_t count = static_cast<size_t>(Total < Rows.size() ? Total : Rows.size());
            result.Actions.reserve(count);
            for (size_t i = 0; i < count; ++i) { result.Actions.push_back(Rows[(Total - count + i) % Rows.size()]); }
        }
        if (result.Total)
        {
            result.ControllerPid = GetCurrentProcessId();
            result.ControllerCreateTime = ReadProcessHandleIdentity(GetCurrentProcess()).Created;
        }
        return result;
    }
private:
    mutable std::mutex Mutex;
    std::array<ProcessLoggingAction, 64> Rows{};
    uint64_t Total = 0;
};

inline ProcessLoggingJournal& ControllerProcessLogging()
{
    static ProcessLoggingJournal journal;
    return journal;
}
