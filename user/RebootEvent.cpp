#include "RebootEvent.h"
#include "McpJson.h"
#include "SavedEtlInput.h"

#include <winevt.h>
#include <algorithm>
#include <cstring>
#include <memory>
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

    void ReadRecord(const std::wstring& path, RebootEventComparison& result, bool readTime)
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

        DWORD size = 0, properties = 0;
        if (EvtRender(nullptr, event.get(), EvtRenderEventXml, 0, nullptr, &size, &properties))
        { result.status = L"event_render_failed"; return; }
        const DWORD probe = GetLastError();
        if (probe != ERROR_INSUFFICIENT_BUFFER) { result.win32Error = probe; result.status = L"event_render_failed"; return; }
        if (size > MaxRenderedBytes || size < 2 * sizeof(wchar_t) || size % sizeof(wchar_t))
        { result.status = L"event_render_size_invalid"; return; }
        std::vector<wchar_t> xml(size / sizeof(wchar_t));
        DWORD used = 0;
        if (!EvtRender(nullptr, event.get(), EvtRenderEventXml, size, xml.data(), &used, &properties))
        { result.win32Error = GetLastError(); result.status = L"event_render_failed"; return; }
        if (used != size || xml.back() != L'\0' || std::find(xml.begin(), xml.end() - 1, L'\0') != xml.end() - 1)
        { result.status = L"event_render_size_invalid"; return; }
        DecodeRebootEvent(reinterpret_cast<const BYTE*>(xml.data()), used - static_cast<DWORD>(sizeof(wchar_t)), result);
        if (readTime) { ReadEventTime(event.get(), result); }
    }
}

RebootEventComparison CompareSavedRebootEvent(const std::wstring& name, const std::wstring& pin,
    uint64_t recordId, const SavedCrashStop* qualifiedDumpStop, bool readTime)
{
    RebootEventComparison result;
    result.recordId = recordId;
    result.dumpQualified = qualifiedDumpStop != nullptr;
    etl_profile::SavedEtlInput archive;
    if (!archive.Open(name, MaxLogBytes)) { return result; }
    result.logDigest = archive.File.Sha256;
    result.logBytes = archive.File.Bytes();
    if (result.logDigest != pin) { result.status = L"event_digest_mismatch"; return result; }
    std::array<char, 8> signature{};
    DWORD used = 0;
    if (!approved_file::ReadAt(archive.File.Handle(), 0, signature.data(), static_cast<DWORD>(signature.size()), &used) ||
        used != signature.size() || std::memcmp(signature.data(), "ElfFile", signature.size()) != 0)
    { result.status = L"unsupported_event_archive"; return result; }
    ReadRecord(archive.PinnedVolumePath(), result, readTime);
    if (!archive.Revalidated())
    {
        RebootEventComparison changed;
        changed.recordId = recordId;
        changed.dumpQualified = result.dumpQualified;
        changed.status = L"event_source_changed_or_unreadable";
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
