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
        if (uptime.value_or(false))
        {
            const auto duration = static_cast<int64_t>(*dump.debuggerUptimeSeconds) * TicksPerSecond;
            boot = Bounds(start - (duration + TicksPerSecond - 1), end - duration);
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
