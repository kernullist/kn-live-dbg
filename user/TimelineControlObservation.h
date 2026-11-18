#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <cwchar>
#include <mutex>
#include <string>
#include <vector>
#include "../shared/TimelineCallbackControl.h"

enum class TimelineControlReply { TransportFailure, LegacyAck, InvalidReply, Detailed };

struct TimelineControlObservation
{
    uint64_t Sequence = 0, DeviceEpoch = 0, RequestId = 0, RequestedUtc = 0, ReturnedUtc = 0;
    DWORD Win32Status = 0, ReturnedBytes = 0;
    TimelineControlReply Reply = TimelineControlReply::TransportFailure;
    KNDBG_TIMELINE_CONTROL_REQUEST Request{};
    KNDBG_TIMELINE_CONTROL_RECEIPT Receipt{};
};

struct TimelineControlSnapshot
{
    uint64_t Total = 0, ControllerCreateTime = 0;
    DWORD ControllerPid = 0;
    std::vector<TimelineControlObservation> Actions;
};

struct TimelineControlLease
{
    uint64_t DeviceEpoch = 0;
    uint64_t RequestId = 0;
};

class TimelineControlJournal
{
public:
    TimelineControlSnapshot Snapshot() const;
    template <typename Send>
    bool Submit(uint32_t action, uint32_t capacity, uint64_t deviceEpoch, bool detailed, Send send, std::wstring* error,
        TimelineControlLease* acquired = nullptr, const TimelineControlLease* expected = nullptr);
private:
    void Record(TimelineControlObservation& observation);
    std::mutex DispatchMutex;
    TimelineControlLease LastStart;
    mutable std::mutex Mutex;
    std::array<TimelineControlObservation, 64> Rows{};
    uint64_t Total = 0;
};

TimelineControlJournal& GetTimelineControlJournal();
uint64_t TimelineControlUtc();
uint64_t NextTimelineControlId();
bool ValidateTimelineControlReply(const TimelineControlObservation& observation);
bool TimelineCallbackOwnershipSelfTest(bool native);

// One buffered control request. A transport error or malformed reply can follow
// a state change, so negotiation and decoding never replay the mutation.
template <typename Send>
bool TimelineControlJournal::Submit(uint32_t action, uint32_t capacity, uint64_t deviceEpoch, bool detailed,
    Send send, std::wstring* error, TimelineControlLease* acquired, const TimelineControlLease* expected)
{
    std::lock_guard<std::mutex> dispatch(DispatchMutex);
    if (acquired) { *acquired = {}; }
    if (expected && (action != KNDBG_TIMELINE_CONTROL_STOP || !expected->RequestId || expected->DeviceEpoch != deviceEpoch ||
        LastStart.DeviceEpoch != deviceEpoch || LastStart.RequestId != expected->RequestId))
    {
        if (error) { *error = L"Live callback rollback no longer owns the latest control request"; }
        return false;
    }
    LastStart = {};
    TimelineControlObservation row;
    row.DeviceEpoch = deviceEpoch;
    const DWORD inputSize = detailed ? sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST) : sizeof(row.Request);
    row.Request = {inputSize, action, detailed ? KNDBG_TIMELINE_CONTROL_WANT_RECEIPT : 0u,
        capacity, KNDBG_WRITE_ACK_MAGIC};
    row.Receipt.Request = row.Request;
    if (detailed)
    {
        row.RequestId = NextTimelineControlId();
        row.Receipt.RequestId = row.RequestId;
        row.Receipt.Size = sizeof(row.Receipt);
        row.Receipt.Version = KNDBG_TIMELINE_CONTROL_RECEIPT_VERSION;
    }
    const DWORD outputSize = detailed ? sizeof(row.Receipt) : sizeof(row.Request);
    row.RequestedUtc = TimelineControlUtc();
    const bool delivered = send(&row.Receipt, inputSize, outputSize, &row.ReturnedBytes, &row.Win32Status, error);
    row.ReturnedUtc = TimelineControlUtc();
    if (delivered)
    {
        row.Reply = ValidateTimelineControlReply(row) ?
            (detailed ? TimelineControlReply::Detailed : TimelineControlReply::LegacyAck) : TimelineControlReply::InvalidReply;
    }
    Record(row);
    if (row.Reply == TimelineControlReply::InvalidReply)
    {
        if (error) { *error = L"Invalid timeline control reply, operation outcome unconfirmed"; }
        return false;
    }
    if (row.Reply == TimelineControlReply::Detailed && row.Receipt.OperationStatus)
    {
        if (error)
        {
            wchar_t message[96]{};
            swprintf_s(message, L"Timeline control operation failed (NTSTATUS 0x%08X)", row.Receipt.OperationStatus);
            *error = message;
        }
        return false;
    }
    if (delivered && acquired && action == KNDBG_TIMELINE_CONTROL_START)
    {
        acquired->DeviceEpoch = deviceEpoch;
        if (row.Reply == TimelineControlReply::Detailed && !row.Receipt.BeforeFlags && row.Receipt.CallCount)
        {
            acquired->RequestId = row.RequestId;
            LastStart = *acquired;
        }
    }
    return delivered;
}
