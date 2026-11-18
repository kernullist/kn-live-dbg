#include "TimelineControlObservation.h"
#include <algorithm>
#include <atomic>
#include <cstddef>

static_assert(sizeof(KNDBG_TIMELINE_CONTROL_REQUEST) == 24 && sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST) == 40);
static_assert(offsetof(KNDBG_TIMELINE_CONTROL_RECEIPT, OperationStatus) == sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST));
static_assert(sizeof(KNDBG_TIMELINE_CALLBACK_CALL) == 32 && sizeof(KNDBG_TIMELINE_CONTROL_RECEIPT) == 312);

uint64_t NextTimelineControlId()
{
    static std::atomic<uint64_t> next{1};
    return next.fetch_add(1, std::memory_order_relaxed);
}

uint64_t TimelineControlUtc()
{
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return (uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

TimelineControlJournal& GetTimelineControlJournal()
{
    static TimelineControlJournal journal;
    return journal;
}

void TimelineControlJournal::Record(TimelineControlObservation& row)
{
    std::lock_guard<std::mutex> lock(Mutex);
    row.Sequence = Total + 1;
    Rows[Total % Rows.size()] = row;
    ++Total;
}

TimelineControlSnapshot TimelineControlJournal::Snapshot() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    TimelineControlSnapshot snapshot;
    if (!Total) { return snapshot; }
    snapshot.ControllerPid = GetCurrentProcessId();
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
    { snapshot.ControllerCreateTime = (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime; }
    snapshot.Total = Total;
    const auto retained = (std::min)(Total, static_cast<uint64_t>(Rows.size()));
    snapshot.Actions.reserve(static_cast<size_t>(retained));
    for (auto i = Total - retained; i < Total; ++i) { snapshot.Actions.push_back(Rows[i % Rows.size()]); }
    return snapshot;
}

bool ValidateTimelineControlReply(const TimelineControlObservation& row)
{
    const auto& r = row.Receipt;
    const auto& request = row.Request;
    if (row.Win32Status || r.Request.Size != request.Size || r.Request.Action != request.Action ||
        r.Request.Flags != request.Flags || r.Request.Capacity != request.Capacity || r.Request.Acknowledge != request.Acknowledge)
    { return false; }
    if (!request.Flags) { return request.Size == sizeof(request) && row.ReturnedBytes == sizeof(request); }
    if (request.Flags != KNDBG_TIMELINE_CONTROL_WANT_RECEIPT || request.Size != sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST) ||
        !row.RequestId || r.RequestId != row.RequestId || row.ReturnedBytes != sizeof(r) ||
        r.Size != sizeof(r) || r.Version != KNDBG_TIMELINE_CONTROL_RECEIPT_VERSION ||
        r.CallCount > KNDBG_TIMELINE_MAX_CALLBACK_CALLS) { return false; }
    const auto validFlags = [](uint32_t flags) {
        return !(flags & ~(timeline_callbacks::Registered | timeline_callbacks::Active)) &&
            (!(flags & timeline_callbacks::Active) || (flags & timeline_callbacks::Registered) == timeline_callbacks::Registered);
    };
    if (!validFlags(r.BeforeFlags) || !validFlags(r.AfterFlags)) { return false; }
    if (request.Action == KNDBG_TIMELINE_CONTROL_CLEAR)
    { return !r.CallCount && r.BeforeFlags == r.AfterFlags && !r.OperationStatus; }
    if (request.Action != KNDBG_TIMELINE_CONTROL_START && request.Action != KNDBG_TIMELINE_CONTROL_STOP) { return false; }
    // Ring allocation can fail before making any callback request.
    if (request.Action == KNDBG_TIMELINE_CONTROL_START && !r.CallCount && (r.OperationStatus & 0x80000000u))
    { return r.BeforeFlags == r.AfterFlags; }

    // Reconcile the reported mask and operation result with the ordered calls.
    KNDBG_TIMELINE_CONTROL_RECEIPT replay{};
    replay.AfterFlags = r.BeforeFlags;
    uint32_t cursor = 0;
    bool matched = true;
    auto call = [&](uint32_t flag, bool remove, uint64_t& requested, uint64_t& returned) -> uint32_t {
        if (cursor == r.CallCount) { matched = false; return timeline_callbacks::Unsuccessful; }
        const auto& item = r.Calls[cursor++];
        requested = item.RequestedUtcFileTime;
        returned = item.ReturnedUtcFileTime;
        if (item.CallbackFlag != flag || item.Remove != (remove ? 1u : 0u) || item.Reserved || !requested || !returned) { matched = false; }
        return item.NtStatus;
    };
    auto publish = [](uint32_t) {};
    const auto status = request.Action == KNDBG_TIMELINE_CONTROL_START ? timeline_callbacks::Start(replay, call, publish) :
        timeline_callbacks::Stop(replay, call, publish);
    return matched && cursor == r.CallCount && status == r.OperationStatus && replay.AfterFlags == r.AfterFlags;
}
