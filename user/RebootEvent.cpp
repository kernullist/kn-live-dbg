#include "RebootEvent.h"
#include "McpJson.h"
#include "SavedEtlInput.h"

#include <winevt.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

namespace
{
    using EventHandle = std::unique_ptr<void, decltype(&EvtClose)>;
    using mcpjson::Quote;
    constexpr uint64_t MaxLogBytes = 256ull << 20;
    constexpr DWORD MaxRenderedBytes = 256u << 10;

    void ReadEventTime(EVT_HANDLE event, RebootEventComparison& result)
    {
        LPCWSTR path = L"Event/System/TimeCreated/@SystemTime";
        EventHandle context(EvtCreateRenderContext(1, &path, EvtRenderContextValues), EvtClose);
        if (!context) { result.timeError = GetLastError(); return; }
        EVT_VARIANT value{};
        DWORD used = 0, count = 0;
        if (!EvtRender(context.get(), event, EvtRenderEventValues, sizeof(value), &value, &used, &count))
        { result.timeError = GetLastError(); return; }
        if (used != sizeof(value) || count != 1 || value.Type != EvtVarTypeFileTime)
        { result.timeError = ERROR_INVALID_DATA; return; }
        result.typedFileTime = value.FileTimeVal;
    }

    const wchar_t* RenderXml(EVT_HANDLE event, std::vector<wchar_t>& xml, std::optional<DWORD>& error)
    {
        DWORD size = 0, properties = 0;
        if (EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &size, &properties)) { return L"event_render_failed"; }
        const DWORD probe = GetLastError();
        if (probe != ERROR_INSUFFICIENT_BUFFER) { error = probe; return L"event_render_failed"; }
        if (size > MaxRenderedBytes || size < 2 * sizeof(wchar_t) || size % sizeof(wchar_t)) { return L"event_render_size_invalid"; }
        xml.resize(size / sizeof(wchar_t));
        DWORD used = 0;
        if (!EvtRender(nullptr, event, EvtRenderEventXml, size, xml.data(), &used, &properties))
        { error = GetLastError(); return L"event_render_failed"; }
        if (used != size || xml.back() != L'\0' || std::find(xml.begin(), xml.end() - 1, L'\0') != xml.end() - 1)
        { return L"event_render_size_invalid"; }
        return nullptr;
    }

    const wchar_t* ReadChange(EVT_HANDLE event, EVT_HANDLE times, RebootClockChange& change)
    {
        std::vector<wchar_t> xml;
        if (auto failure = RenderXml(event, xml, change.error)) { return failure; }
        const auto xmlStatus = DecodeRebootClockChange(reinterpret_cast<const BYTE*>(xml.data()),
            static_cast<UINT>((xml.size() - 1) * sizeof(wchar_t)), change);
        EVT_VARIANT values[2]{};
        DWORD used = 0, count = 0;
        if (!EvtRender(times, event, EvtRenderEventValues, sizeof(values), values, &used, &count))
        { change.error = GetLastError(); return xmlStatus ? xmlStatus : L"clock_render_failed"; }
        if (used == sizeof(values) && count == 2)
        {
            if (values[0].Type == EvtVarTypeFileTime) { change.typedOldTime = values[0].FileTimeVal; }
            if (values[1].Type == EvtVarTypeFileTime) { change.typedNewTime = values[1].FileTimeVal; }
        }
        if (xmlStatus) { return xmlStatus; }
        if (!change.typedOldTime || !change.typedNewTime) { return L"clock_fields_unavailable"; }
        return change.typedOldTime == change.oldTime && change.typedNewTime == change.newTime ? L"observed" : L"clock_fields_conflict";
    }

    bool SystemValues(EVT_HANDLE context, EVT_HANDLE event, std::vector<EVT_VARIANT>& values, std::optional<DWORD>& error)
    {
        DWORD used = 0, count = 0;
        auto render = [&] { return EvtRender(context, event, EvtRenderEventValues,
            static_cast<DWORD>(values.size() * sizeof(EVT_VARIANT)), values.data(), &used, &count); };
        if (!render())
        {
            DWORD code = GetLastError();
            if (code != ERROR_INSUFFICIENT_BUFFER || used > 65536) { error = code; return false; }
            values.resize((used + sizeof(EVT_VARIANT) - 1) / sizeof(EVT_VARIANT));
            if (!render()) { error = GetLastError(); return false; }
        }
        if (count != EvtSystemPropertyIdEND || used < count * sizeof(EVT_VARIANT) || used > values.size() * sizeof(EVT_VARIANT))
        { error = ERROR_INVALID_DATA; return false; }
        return true;
    }

    std::wstring_view EventString(const EVT_VARIANT& value)
    {
        return value.Type == EvtVarTypeString && value.StringVal ? value.StringVal : L"";
    }

    void ReadHistory(const std::wstring& path, EVT_HANDLE anchor, RebootClockHistory& h)
    {
        if (!RebootClockHistory::ValidWindow(h.first, h.last)) { h.status = L"invalid_record_window"; return; }
        h.status = L"history_query_failed";
        EventHandle system(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem), EvtClose);
        if (!system) { h.error = GetLastError(); return; }
        std::vector<EVT_VARIANT> values(64);
        if (!SystemValues(system.get(), anchor, values, h.error)) { return; }
        const std::wstring computer(EventString(values[EvtSystemComputer]));
        if (computer.empty() || EventString(values[EvtSystemChannel]) != L"System" ||
            values[EvtSystemEventRecordId].Type != EvtVarTypeUInt64 || values[EvtSystemEventRecordId].UInt64Val != h.last)
        { h.status = L"restart_record_unavailable"; return; }

        LPCWSTR fields[] = {L"Event/EventData/Data[@Name='OldTime']", L"Event/EventData/Data[@Name='NewTime']"};
        EventHandle times(EvtCreateRenderContext(2, fields, EvtRenderContextValues), EvtClose);
        if (!times) { h.error = GetLastError(); return; }
        const std::wstring filter = L"*[System[(EventRecordID >= " + std::to_wstring(h.first) +
            L" and EventRecordID <= " + std::to_wstring(h.last) + L")]]";
        EventHandle query(EvtQuery(nullptr, path.c_str(), filter.c_str(), EvtQueryFilePath | EvtQueryForwardDirection), EvtClose);
        if (!query) { h.error = GetLastError(); return; }
        const auto deadline = GetTickCount64() + 15000;
        uint64_t previous = 0;
        for (;;)
        {
            const auto now = GetTickCount64();
            if (now >= deadline) { h.status = L"history_deadline_reached"; return; }
            EVT_HANDLE raw = nullptr;
            DWORD count = 0;
            if (!EvtNext(query.get(), 1, &raw, static_cast<DWORD>(deadline - now), 0, &count))
            {
                const DWORD end = GetLastError();
                if (end == ERROR_NO_MORE_ITEMS) { break; }
                if (end == ERROR_TIMEOUT) { h.status = L"history_deadline_reached"; }
                h.error = end;
                return;
            }
            EventHandle event(raw, EvtClose);
            if (!event || count != 1) { h.error = ERROR_INVALID_DATA; return; }
            ++h.recordsRead;
            if (!SystemValues(system.get(), event.get(), values, h.error)) { return; }
            const auto& id = values[EvtSystemEventRecordId];
            if (id.Type != EvtVarTypeUInt64 || id.UInt64Val < h.first || id.UInt64Val > h.last || id.UInt64Val <= previous)
            {
                // Individual record IDs cease to uniquely locate these findings.
                h.changes.clear();
                h.status = L"invalid_record_sequence";
                return;
            }
            previous = id.UInt64Val;
            if (EventString(values[EvtSystemChannel]) != L"System" || EventString(values[EvtSystemComputer]) != computer) { continue; }
            ++h.scopedRecords;
            const auto& eventId = values[EvtSystemEventID];
            const auto provider = EventString(values[EvtSystemProviderName]);
            if (eventId.Type != EvtVarTypeUInt16 || provider.empty()) { ++h.unclassified; continue; }
            if (eventId.UInt16Val != 1) { continue; }
            constexpr GUID general = {0xa68ca8b7,0x004f,0xd7b6,{0xa6,0x98,0x07,0xe2,0xde,0x0f,0x1f,0x5d}};
            const auto& guid = values[EvtSystemProviderGuid];
            const bool generalGuid = guid.Type == EvtVarTypeGuid && guid.GuidVal && IsEqualGUID(*guid.GuidVal, general);
            if (provider != L"Microsoft-Windows-Kernel-General" && !generalGuid) { continue; }
            auto& change = h.changes.emplace_back();
            change.recordId = previous;
            if (values[EvtSystemVersion].Type == EvtVarTypeByte) { change.version = values[EvtSystemVersion].ByteVal; }
            change.status = generalGuid && provider == L"Microsoft-Windows-Kernel-General" ?
                ReadChange(event.get(), times.get(), change) : L"provider_identity_conflict";
        }
        h.complete = h.scopedRecords == h.last - h.first + 1 && !h.unclassified &&
            std::all_of(h.changes.begin(), h.changes.end(), [](const auto& c) { return c.Delta().has_value(); });
        h.status = h.complete ? L"saved_window_observed" : L"partial_saved_window";
    }

    void ReadRecord(const std::wstring& path, RebootEventComparison& result, bool readTime, RebootClockHistory* history)
    {
        const auto queryText = L"*[System[EventRecordID=" + std::to_wstring(result.recordId) + L"]]";
        EventHandle query(EvtQuery(nullptr, path.c_str(), queryText.c_str(), EvtQueryFilePath | EvtQueryForwardDirection), EvtClose);
        if (!query) { result.win32Error = GetLastError(); result.status = L"event_query_failed"; return; }

        EVT_HANDLE raw = nullptr;
        DWORD count = 0;
        if (!EvtNext(query.get(), 1, &raw, 5000, 0, &count))
        {
            result.win32Error = GetLastError();
            result.status = *result.win32Error == ERROR_NO_MORE_ITEMS ? L"record_not_found" : L"event_query_failed";
            return;
        }
        EventHandle event(raw, EvtClose);
        if (!event || count != 1) { result.status = L"event_query_failed"; return; }
        raw = nullptr;
        if (EvtNext(query.get(), 1, &raw, 5000, 0, &count))
        {
            EventHandle other(raw, EvtClose);
            result.status = L"ambiguous_record_id";
            return;
        }
        const DWORD end = GetLastError();
        if (end != ERROR_NO_MORE_ITEMS) { result.win32Error = end; result.status = L"event_query_failed"; return; }

        std::vector<wchar_t> xml;
        if (auto failure = RenderXml(event.get(), xml, result.win32Error)) { result.status = failure; return; }
        DecodeRebootEvent(reinterpret_cast<const BYTE*>(xml.data()), static_cast<UINT>((xml.size() - 1) * sizeof(wchar_t)), result);
        if (readTime) { ReadEventTime(event.get(), result); }
        if (history && result.xmlFileTime) { ReadHistory(path, event.get(), *history); }
    }
}

RebootEventComparison CompareSavedRebootEvent(const std::wstring& name, const std::wstring& pin,
    uint64_t recordId, const SavedCrashStop* qualifiedDumpStop, bool readTime, RebootClockHistory* history)
{
    RebootEventComparison result;
    result.recordId = recordId;
    result.dumpQualified = qualifiedDumpStop != nullptr;
    etl_profile::SavedEtlInput archive;
    DWORD openError = 0;
    if (!archive.Open(name, MaxLogBytes, history ? &openError : nullptr))
    { if (history && openError) { result.win32Error = openError; } return result; }
    result.logDigest = archive.File.Sha256;
    result.logBytes = archive.File.Bytes();
    if (result.logDigest != pin) { result.status = L"event_digest_mismatch"; return result; }
    std::array<char, 8> signature{};
    DWORD used = 0;
    if (!approved_file::ReadAt(archive.File.Handle(), 0, signature.data(), static_cast<DWORD>(signature.size()), &used) ||
        used != signature.size() || std::memcmp(signature.data(), "ElfFile", signature.size()) != 0)
    { result.status = L"unsupported_event_archive"; return result; }
    ReadRecord(archive.PinnedVolumePath(), result, readTime, history);
    if (!archive.Revalidated())
    {
        RebootEventComparison changed;
        changed.recordId = recordId;
        changed.dumpQualified = result.dumpQualified;
        changed.status = L"event_source_changed_or_unreadable";
        if (history) { *history = RebootClockHistory{history->first, recordId}; }
        return changed;
    }
    if (result.eventCode.value_or(0) && qualifiedDumpStop) { result.sameCode = *result.eventCode == qualifiedDumpStop->code; }
    if (result.eventStop && result.eventStop->code)
    {
        if (!qualifiedDumpStop) { result.status = L"dump_stop_unqualified"; }
        else
        {
            result.sameStop = *qualifiedDumpStop == *result.eventStop;
            result.status = *result.sameStop ? L"matching_stop_tuple" : L"different_stop_tuple";
        }
    }
    return result;
}

std::wstring RebootEventComparison::Json() const
{
    return L"{\"schema\":\"kn.reboot_event_comparison.v1\",\"status\":" + Quote(status) +
        L",\"log_sha256\":" + (logDigest.empty() ? L"null" : Quote(logDigest)) +
        L",\"log_bytes\":" + (logDigest.empty() ? L"null" : std::to_wstring(logBytes)) +
        L",\"requested_record_id\":" + Quote(std::to_wstring(recordId)) +
        L",\"win32_error\":" + (win32Error ? std::to_wstring(*win32Error) : L"null") +
        L",\"event\":" + metadata + L",\"bugcheck_code_decimal\":" + (eventCode ? std::to_wstring(*eventCode) : L"null") +
        L",\"bugcheck\":" + (eventStop ? eventStop->Json() : L"null") +
        L",\"same_stop_code\":" + (sameCode ? (*sameCode ? L"true" : L"false") : L"null") +
        L",\"same_stop_tuple\":" + (sameStop ? (*sameStop ? L"true" : L"false") : L"null") +
        L",\"source_authenticated\":false,\"same_host_boot_verified\":false}";
}

std::wstring RebootEventComparison::Hypothesis(const RebootTimeline* timing) const
{
    const std::wstring evidence = L"[\"/header/bugcheck\",\"/dbgeng/bugcheck\",\"/reboot_event/log_sha256\","
        L"\"/reboot_event/event\",\"/reboot_event/bugcheck\"]";
    const bool match = sameStop.value_or(false);
    const bool codeConflict = sameCode && !*sameCode && !sameStop;
    std::wstring missing;
    if (!dumpQualified) { missing = L"\"/status\",\"/header\",\"/dbgeng/initial_stop\""; }
    if (!eventStop || !eventStop->code) { missing += (missing.empty() ? L"" : L",") + Quote(L"/reboot_event/status"); }
    const wchar_t* next = !dumpQualified ? L"obtain_an_ordinary_dump_with_a_qualified_stop" :
        (!eventStop || !eventStop->code) ? L"locate_the_original_record_with_full_stop_fields" : L"verify_host_boot_and_incident_provenance";
    const wchar_t* state = codeConflict ? L"contradicted_by_stop_code" : !sameStop ? L"unresolved" :
        match ? L"supported_by_stop_tuples" : L"conflicting_stop_tuples";
    std::wstring support = match ? evidence : L"[]";
    std::wstring contrary = codeConflict ?
        L"[\"/header/bugcheck/code\",\"/dbgeng/bugcheck/code\",\"/reboot_event/log_sha256\",\"/reboot_event/bugcheck_code_decimal\"]" :
        sameStop && !match ? evidence : L"[]";
    if (timing)
    {
        auto citeTime = [](std::wstring& array) {
            array.pop_back();
            if (array.size() > 1) { array += L","; }
            array += L"\"/reboot_timeline/event_minus_dump_100ns\"]";
        };
        if (timing->order == RebootTimeline::Order::AfterEvent)
        {
            state = codeConflict || (sameStop && !match) ? L"conflicting_stop_and_recorded_order" : L"conflicting_recorded_order";
            citeTime(contrary);
            next = L"check_clock_changes_and_verify_incident_provenance";
        }
        else if (timing->order == RebootTimeline::Order::BeforeEvent && match)
        { state = L"consistent_stop_and_recorded_order"; citeTime(support); }
        else if (match) { state = L"matching_stop_order_unresolved"; }
        if (timing->order == RebootTimeline::Order::Unknown || timing->order == RebootTimeline::Order::SameSecond)
        { missing += (missing.empty() ? L"" : L",") + Quote(L"/reboot_timeline/status"); }
        missing += (missing.empty() ? L"" : L",") + Quote(L"/reboot_event/same_host_boot_verified") +
            L",\"/reboot_timeline/clock_correspondence_verified\"";
    }
    return L"{\"candidate\":\"same_recorded_stop_at_restart\",\"state\":" + Quote(state) +
        L",\"support\":" + support + L",\"contrary\":" + contrary +
        L",\"missing\":[" + missing + L"],\"next\":" + Quote(next) + L"}";
}
