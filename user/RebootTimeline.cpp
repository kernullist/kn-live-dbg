#include "RebootEvent.h"
#include "McpJson.h"

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
