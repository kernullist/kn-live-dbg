#include "RebootEvent.h"
#include "McpJson.h"
#include <string_view>

namespace
{
    using mcpjson::Quote;
    constexpr int64_t TicksPerSecond = 10000000, UnixEpoch = 116444736000000000;

    std::optional<bool> SameSecond(int64_t raw, int64_t epoch, std::optional<ULONG> seconds)
    {
        // DbgEng can return S_OK with zero when a dump does not supply this clock.
        if (raw <= epoch || !seconds || !*seconds) { return {}; }
        const auto whole = (raw - epoch) / TicksPerSecond;
        if (!whole || whole > UINT32_MAX) { return {}; }
        return whole == *seconds;
    }

    template<class T> std::wstring DecimalString(std::optional<T> value)
    {
        return value ? Quote(std::to_wstring(*value)) : L"null";
    }

    const wchar_t* Agreement(std::optional<bool> value)
    {
        return !value ? L"null" : *value ? L"true" : L"false";
    }

    std::wstring Bounds(int64_t earliest, int64_t latest)
    {
        return L"{\"minimum\":" + Quote(std::to_wstring(earliest)) + L",\"maximum\":" + Quote(std::to_wstring(latest)) + L"}";
    }
}

RebootTimeline CompareRebootTime(const SavedCrashClock& dump, const RebootEventComparison& event)
{
    RebootTimeline result;
    const auto wall = SameSecond(dump.systemTime, UnixEpoch, dump.debuggerUnixSeconds);
    const auto uptime = SameSecond(dump.upTime, 0, dump.debuggerUptimeSeconds);
    const bool eventUsable = event.typedFileTime && *event.typedFileTime && *event.typedFileTime <= INT64_MAX;
    const auto agrees = eventUsable && event.xmlFileTime ? std::optional<bool>(*event.xmlFileTime == *event.typedFileTime) : std::nullopt;
    std::wstring delta = L"null", boot = L"null";
    const wchar_t* status;
    if (!event.dumpQualified) { status = L"dump_stop_unqualified"; }
    else if (!wall) { status = L"dump_time_unavailable"; }
    else if (!*wall) { status = L"dump_time_conflict"; }
    else
    {
        const auto start = UnixEpoch + static_cast<int64_t>(*dump.debuggerUnixSeconds) * TicksPerSecond;
        const auto end = start + TicksPerSecond - 1;
        result.dumpSecond = RebootTimeline::Bounds{start, end};
        if (uptime.value_or(false))
        {
            const auto duration = static_cast<int64_t>(*dump.debuggerUptimeSeconds) * TicksPerSecond;
            result.estimatedBoot = RebootTimeline::Bounds{start - (duration + TicksPerSecond - 1), end - duration};
            boot = Bounds(result.estimatedBoot->first, result.estimatedBoot->last);
        }
        if (!agrees) { status = L"event_time_unavailable"; }
        else if (!*agrees) { status = L"event_time_conflict"; }
        else
        {
            const auto when = static_cast<int64_t>(*event.typedFileTime);
            delta = Bounds(when - end, when - start);
            if (when < start) { result.order = RebootTimeline::Order::AfterEvent; status = L"dump_after_event"; }
            else if (when > end) { result.order = RebootTimeline::Order::BeforeEvent; status = L"dump_before_event"; }
            else { result.order = RebootTimeline::Order::SameSecond; status = L"same_recorded_second"; }
        }
    }
    result.report = L"{\"schema\":\"kn.reboot_timeline.v1\",\"status\":" + Quote(status) +
        L",\"header_system_filetime\":" + Quote(std::to_wstring(dump.systemTime)) +
        L",\"header_uptime_100ns\":" + Quote(std::to_wstring(dump.upTime)) +
        L",\"dbgeng_unix_seconds\":" + DecimalString(dump.debuggerUnixSeconds) +
        L",\"dbgeng_uptime_seconds\":" + DecimalString(dump.debuggerUptimeSeconds) +
        L",\"dump_time_seconds_agree\":" + Agreement(wall) + L",\"dump_uptime_seconds_agree\":" + Agreement(uptime) +
        L",\"event_xml_filetime\":" + DecimalString(event.xmlFileTime) + L",\"event_typed_filetime\":" + DecimalString(event.typedFileTime) +
        L",\"event_time_win32_error\":" + (event.timeError ? std::to_wstring(*event.timeError) : L"null") +
        L",\"event_time_fields_agree\":" + Agreement(agrees) + L",\"event_minus_dump_100ns\":" + delta +
        L",\"estimated_dump_boot_filetime\":" + boot + L",\"clock_correspondence_verified\":false}";
    return result;
}

std::optional<int64_t> RebootClockChange::Delta() const
{
    if (std::wstring_view(status) != L"observed" || !oldTime || !newTime || oldTime != typedOldTime || newTime != typedNewTime ||
        !*oldTime || !*newTime || *oldTime > INT64_MAX || *newTime > INT64_MAX) { return {}; }
    return static_cast<int64_t>(*newTime) - static_cast<int64_t>(*oldTime);
}

std::wstring RebootClockHistory::Json() const
{
    std::wstring rows;
    for (const auto& c : changes)
    {
        if (!rows.empty()) { rows += L","; }
        rows += L"{\"record_id\":" + Quote(std::to_wstring(c.recordId)) + L",\"version\":" +
            (c.version ? std::to_wstring(*c.version) : L"null") + L",\"status\":" + Quote(c.status) +
            L",\"clock_old_filetime\":" + DecimalString(c.oldTime) + L",\"clock_new_filetime\":" + DecimalString(c.newTime) +
            L",\"clock_typed_old_filetime\":" + DecimalString(c.typedOldTime) + L",\"clock_typed_new_filetime\":" + DecimalString(c.typedNewTime) +
            L",\"clock_delta_100ns\":" + DecimalString(c.Delta()) + L",\"win32_error\":" + (c.error ? std::to_wstring(*c.error) : L"null") + L"}";
    }
    return L"{\"schema\":\"kn.reboot_clock_history.v1\",\"status\":" + Quote(status) +
        L",\"first_record_id\":" + Quote(std::to_wstring(first)) + L",\"last_record_id\":" + Quote(std::to_wstring(last)) +
        L",\"requested_record_ids\":" + (ValidWindow(first, last) ? std::to_wstring(last - first + 1) : L"null") +
        L",\"records_read\":" + std::to_wstring(recordsRead) +
        L",\"same_channel_and_computer_records\":" + std::to_wstring(scopedRecords) + L",\"unclassified_records\":" + std::to_wstring(unclassified) +
        L",\"saved_window_complete\":" + (complete ? L"true" : L"false") + L",\"win32_error\":" + (error ? std::to_wstring(*error) : L"null") +
        L",\"changes\":[" + rows + L"],\"dump_clock_correspondence_verified\":false}";
}

std::wstring RebootClockHistory::Hypothesis() const
{
    bool forward = false, backward = false;
    for (const auto& change : changes)
    {
        const auto delta = change.Delta();
        if (delta) { forward |= *delta > 0; backward |= *delta < 0; }
    }
    const wchar_t* state = forward && backward ? L"forward_and_backward_steps_observed" : backward ? L"backward_step_observed" :
        forward ? L"forward_step_observed" : complete ? L"no_step_in_saved_window" : L"unresolved";
    const std::wstring evidence = L"[\"/reboot_event/log_sha256\",\"/clock_history/changes\",\"/clock_history/status\"]";
    return L"{\"candidate\":\"wall_clock_step_in_saved_restart_window\",\"state\":" + Quote(state) +
        L",\"support\":" + (forward || backward ? evidence : L"[]") + L",\"contrary\":" +
        (complete && !forward && !backward ? evidence : L"[]") +
        L",\"missing\":[" + (complete ? std::wstring() : L"\"/clock_history/status\",") +
        L"\"/clock_history/dump_clock_correspondence_verified\"],\"next\":\"verify_boot_and_clock_provenance_for_the_dump\"}";
}

bool RebootBootStart::Qualified() const
{
    return std::wstring_view(status) == L"observed" && !error && version == 0u && xmlTime && *xmlTime && *xmlTime <= INT64_MAX &&
        xmlTime == typedTime;
}

void RebootBootWindow::ObserveRecord(uint64_t id, bool inScope)
{
    if (!inScope) { contiguousFrom = 0; }
    else if (!contiguousFrom || id - 1 != lastRead) { contiguousFrom = id; }
    lastRead = id;
}

namespace
{
    std::wstring StartJson(const std::optional<RebootBootStart>& start)
    {
        if (!start) { return L"null"; }
        return L"{\"boot_start_record_id\":" + Quote(std::to_wstring(start->recordId)) + L",\"version\":" +
            (start->version ? std::to_wstring(*start->version) : L"null") + L",\"status\":" + Quote(start->status) +
            L",\"boot_start_xml_filetime\":" + DecimalString(start->xmlTime) +
            L",\"boot_start_typed_filetime\":" + DecimalString(start->typedTime) +
            L",\"win32_error\":" + (start->error ? std::to_wstring(*start->error) : L"null") + L"}";
    }

    struct BootClockChanges
    {
        unsigned steps = 0, unresolved = 0;
        std::wstring Json() const
        {
            return L"{\"nonzero_steps\":" + std::to_wstring(steps) + L",\"unresolved_changes\":" + std::to_wstring(unresolved) + L"}";
        }
    };
}

RebootBootAssessment CompareRebootBootWindow(const RebootClockHistory& history, const RebootTimeline& timeline,
    const RebootEventComparison& event)
{
    RebootBootAssessment result;
    const RebootBootWindow empty;
    const auto& b = history.boots ? *history.boots : empty;
    const auto& previous = b.previousStart;
    const auto& receiving = b.receivingStart;
    BootClockChanges priorClock, receivingClock;
    for (const auto& change : history.changes)
    {
        if (!receiving || change.recordId > history.last) { continue; }
        const bool afterStart = change.recordId >= receiving->recordId;
        if (!afterStart && (!previous || change.recordId < previous->recordId)) { continue; }
        auto& segment = afterStart ? receivingClock : priorClock;
        const auto delta = change.Delta();
        if (!delta) { ++segment.unresolved; }
        else if (*delta) { ++segment.steps; }
    }
    const std::wstring_view scan(history.status);
    const bool drained = scan == L"saved_window_observed" || scan == L"partial_saved_window";
    const bool covered = drained && previous && receiving && event.recordId == history.last && previous->recordId < receiving->recordId &&
        receiving->recordId < history.last && b.lastRead == history.last && b.contiguousFrom && b.contiguousFrom <= previous->recordId;
    const wchar_t* status = L"boot_window_observed";
    if (!history.boots || !drained) { status = L"history_unavailable"; }
    else if (!previous || !receiving) { status = L"two_start_records_unavailable"; }
    else if (!covered) { status = L"boot_record_coverage_incomplete"; }
    else if (!previous->Qualified() || !receiving->Qualified()) { status = L"boot_start_unqualified"; }
    else if (b.earlierRestart > receiving->recordId || b.lastShutdown > receiving->recordId) { status = L"ambiguous_receiving_boot"; }
    else if (priorClock.unresolved || receivingClock.unresolved) { status = L"boot_clock_change_unresolved"; }
    else if (priorClock.steps || receivingClock.steps) { status = L"boot_clock_step_observed"; }
    else if (!event.typedFileTime || !*event.typedFileTime || *event.typedFileTime > INT64_MAX ||
        event.xmlFileTime != event.typedFileTime) { status = L"restart_time_unqualified"; }
    else if (*previous->typedTime >= *receiving->typedTime || *receiving->typedTime > *event.typedFileTime)
    { status = L"boot_marker_order_conflict"; }

    const wchar_t* position = L"unresolved";
    if (std::wstring_view(status) == L"boot_window_observed" && event.dumpQualified && timeline.dumpSecond)
    {
        const auto lower = static_cast<int64_t>(*previous->typedTime), upper = static_cast<int64_t>(*receiving->typedTime);
        const auto& second = *timeline.dumpSecond;
        if (second.last < lower) { position = L"before_previous_start"; result.insidePrevious = false; }
        else if (second.first >= upper) { position = L"at_or_after_receiving_start"; result.insidePrevious = false; }
        else if (second.first >= lower && second.last < upper) { position = L"within_previous_boot_window"; result.insidePrevious = true; }
        else if (second.first < lower && second.last >= upper) { position = L"overlaps_both_starts"; }
        else { position = second.first < lower ? L"overlaps_previous_start" : L"overlaps_receiving_start"; }
        if (timeline.estimatedBoot)
        { result.previousStartInEstimate = timeline.estimatedBoot->first <= lower && lower <= timeline.estimatedBoot->last; }
    }
    const auto id = [](uint64_t value) { return value ? Quote(std::to_wstring(value)) : L"null"; };
    result.report = L"{\"schema\":\"kn.reboot_boot_window.v1\",\"status\":" + Quote(status) +
        L",\"previous_start\":" + StartJson(previous) + L",\"receiving_start\":" + StartJson(receiving) +
        L",\"contiguous_from_record_id\":" + id(b.contiguousFrom) + L",\"last_read_record_id\":" + id(b.lastRead) +
        L",\"boot_suffix_complete\":" + (covered ? L"true" : L"false") +
        L",\"last_shutdown_marker_id\":" + id(b.lastShutdown) + L",\"earlier_restart_record_id\":" + id(b.earlierRestart) +
        L",\"previous_clock_changes\":" + (previous && receiving ? priorClock.Json() : L"null") +
        L",\"receiving_clock_changes\":" + (receiving ? receivingClock.Json() : L"null") +
        L",\"dump_position\":" + Quote(position) + L",\"previous_start_in_estimated_boot\":" + Agreement(result.previousStartInEstimate) +
        L",\"same_host_boot_verified\":false}";
    return result;
}
