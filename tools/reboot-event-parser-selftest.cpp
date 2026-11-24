#include "../user/RebootEvent.h"
#include <iostream>
#include <stdexcept>
#include <utility>

namespace
{
    unsigned checked = 0;
    void Check(bool ok, const char* label)
    {
        if (!ok) { throw std::runtime_error(label); }
        ++checked;
    }

    const std::wstring document =
        L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        L"<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331C3B3A-2005-44C2-AC5E-77220C37D6B4}'/>"
        L"<EventID>41</EventID><Version>10</Version><TimeCreated SystemTime='2024-02-29T12:00:00.0000000Z'/>"
        L"<EventRecordID>42</EventRecordID><Channel>System</Channel></System><EventData>"
        L"<Data Name='BugcheckCode'>159</Data><Data Name='BugcheckParameter4'>0x0</Data>"
        L"<Data Name='BugcheckParameter2'>0XFFFFFFFFFFFFFFFF</Data><Data Name='BugcheckParameter1'>0x1</Data>"
        L"<Data Name='BugcheckParameter3'>0x8<![CDATA[0]]></Data></EventData></Event>";

    std::wstring Replace(std::wstring from, std::wstring to)
    {
        auto result = document;
        const auto at = result.find(from);
        Check(at != result.npos, "fixture substitution");
        return result.replace(at, from.size(), to);
    }

    RebootEventComparison Parse(const std::wstring& xml, const wchar_t* expected)
    {
        RebootEventComparison result;
        result.recordId = 42;
        DecodeRebootEvent(reinterpret_cast<const BYTE*>(xml.data()), static_cast<UINT>(xml.size() * sizeof(wchar_t)), result);
        Check(std::wstring(result.status) == expected, "parser status");
        Check(!result.sameStop, "parser made a dump comparison");
        return result;
    }

    void CheckChanges()
    {
        const std::wstring before = L"<Data Name='OldTime'>2024-02-29T12:00:00.1000000Z</Data>";
        const std::wstring after = L"<Data Name='NewTime'>2024-02-29T12:00:00.0999999Z</Data>";
        auto read = [&](unsigned version, const std::wstring& fields, unsigned expected, uint64_t record = 9) {
            const std::wstring xml = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                L"<Provider Name='Microsoft-Windows-Kernel-General' Guid='{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}'/>"
                L"<EventID>1</EventID><Version>" + std::to_wstring(version) +
                L"</Version><TimeCreated SystemTime='2024-02-29T12:00:01Z'/><EventRecordID>9</EventRecordID>"
                L"<Channel>System</Channel></System><EventData>" + fields + L"</EventData></Event>";
            RebootClockChange row;
            row.recordId = record;
            row.version = expected;
            const auto status = DecodeRebootClockChange(reinterpret_cast<const BYTE*>(xml.data()),
                static_cast<UINT>(xml.size() * sizeof(wchar_t)), row);
            row.status = status ? status : L"observed";
            return row;
        };
        for (unsigned v = 0; v <= 4; ++v)
        {
            auto row = read(v, after + before, v);
            Check(std::wstring(row.status) == L"observed" && row.oldTime && row.newTime, "named change fields across manifests");
            Check(!row.Delta(), "raw XML does not qualify a step alone");
            row.typedOldTime = row.oldTime; row.typedNewTime = row.newTime;
            Check(row.Delta() == -1, "signed 100 ns backward step");
            std::swap(row.typedOldTime, row.typedNewTime);
            Check(!row.Delta(), "typed conflict blocks step");
            std::swap(row.oldTime, row.newTime);
            Check(row.Delta() == 1, "forward step");
            row.typedOldTime = row.oldTime = row.newTime;
            Check(row.Delta() == 0, "recorded equal endpoints");
        }
        Check(std::wstring(read(0, before + before + after, 0).status) == L"ambiguous_event_fields", "duplicate old time");
        Check(std::wstring(read(1, after, 1).status) == L"clock_fields_invalid", "missing old time");
        Check(std::wstring(read(2, before + L"<Data Name='NewTime'>1601-01-01T00:00:00Z</Data>", 2).status) == L"clock_fields_invalid",
            "unavailable zero endpoint");
        Check(std::wstring(read(3, before + L"<Data Name='NewTime'>2024-02-29T12:00:00.123456789Z</Data>", 3).status) ==
            L"clock_fields_invalid", "unrepresentable precision");
        Check(std::wstring(read(5, after + before, 5).status) == L"unsupported_event_template", "future template");
        Check(std::wstring(read(4, after + before, 3).status) == L"unsupported_event_template", "rendered version conflict");
        Check(std::wstring(read(4, after + before, 4, 8).status) == L"record_id_mismatch", "rendered ID conflict");
        RebootClockHistory history{8, 9};
        Check(history.Hypothesis().find(L"\"state\":\"unresolved\"") != std::wstring::npos, "missing interval is unresolved");
        history.complete = true;
        Check(history.Hypothesis().find(L"no_step_in_saved_window") != std::wstring::npos, "complete saved window without a step");
        auto row = read(4, after + before, 4);
        row.typedOldTime = row.oldTime; row.typedNewTime = row.newTime;
        history.changes.push_back(row);
        Check(history.Hypothesis().find(L"backward_step_observed") != std::wstring::npos, "observed backward alternative");
        std::swap(row.oldTime, row.newTime); std::swap(row.typedOldTime, row.typedNewTime);
        history.changes.push_back(row);
        Check(history.Hypothesis().find(L"forward_and_backward_steps_observed") != std::wstring::npos, "both directions retained");
    }

    void CheckClock()
    {
        constexpr int64_t t = 133536816000000000LL, ticks = 10000000;
        auto event = Parse(document, L"dump_stop_unqualified");
        Check(event.xmlFileTime == static_cast<uint64_t>(t), "calendar conversion");
        for (const auto& sample : {std::make_pair(L".1Z", 1000000u), std::make_pair(L".0000001Z", 1u),
                std::make_pair(L".123456700Z", 1234567u), std::make_pair(L"Z", 0u)})
        {
            auto parsed = Parse(Replace(L".0000000Z", sample.first), L"dump_stop_unqualified");
            Check(parsed.xmlFileTime == static_cast<uint64_t>(t) + sample.second, "100 ns fraction");
        }
        Check(!Parse(Replace(L".0000000Z", L".000000001Z"), L"dump_stop_unqualified").xmlFileTime, "precision beyond FILETIME");
        event.dumpQualified = true;
        SavedCrashClock clock{t + ticks - 1, 2 * ticks + 1, 1709208000ul, 2ul};
        using Order = RebootTimeline::Order;
        for (const auto& sample : {std::make_pair(t - 1, Order::AfterEvent), std::make_pair(t, Order::SameSecond),
                std::make_pair(t + ticks - 1, Order::SameSecond), std::make_pair(t + ticks, Order::BeforeEvent)})
        {
            event.typedFileTime = event.xmlFileTime = sample.first;
            Check(CompareRebootTime(clock, event).order == sample.second, "closed tick interval");
        }
        auto has = [&](const wchar_t* text) { return CompareRebootTime(clock, event).report.find(text) != std::wstring::npos; };
        event.typedFileTime = t;
        Check(has(L"\"status\":\"event_time_conflict\""), "different XML and typed timestamp");
        event.xmlFileTime = event.typedFileTime = UINT64_MAX;
        Check(has(L"\"status\":\"event_time_unavailable\""), "event outside signed FILETIME");
        event.xmlFileTime = event.typedFileTime = t + ticks;
        clock.debuggerUptimeSeconds = 3;
        Check(has(L"\"dump_uptime_seconds_agree\":false") && has(L"\"estimated_dump_boot_filetime\":null") &&
            CompareRebootTime(clock, event).order == Order::BeforeEvent, "uptime conflict independent of wall time");
        clock.debuggerUnixSeconds = 1;
        Check(has(L"\"status\":\"dump_time_conflict\"") && has(L"\"event_minus_dump_100ns\":null"), "conflicting dump clocks");
        clock.debuggerUnixSeconds = 0;
        Check(has(L"\"status\":\"dump_time_unavailable\""), "zero debugger clock");
        event.dumpQualified = false;
        Check(has(L"\"status\":\"dump_stop_unqualified\""), "unqualified stop");
    }
}

int main()
{
    try
    {
        for (unsigned v = 2; v <= 10; ++v)
        {
            const auto r = Parse(Replace(L">10</Version>", L">" + std::to_wstring(v) + L"</Version>"), L"dump_stop_unqualified");
            Check(r.eventStop && r.eventStop->code == 0x9f &&
                r.eventStop->args == std::array<ULONG64, 4>{1, UINT64_MAX, 128, 0}, "named full-width tuple");
        }
        Check(Parse(Replace(L">159<", L">0<"), L"event_stop_code_unavailable").eventStop->code == 0, "zero code");
        Check(Parse(Replace(L">159<", L">4294967295<"), L"dump_stop_unqualified").eventStop->code == UINT32_MAX, "maximum code");
        for (const auto* value : {L"", L"-1", L"+9", L"0x9f", L"4294967296"})
            Check(!Parse(Replace(L">159<", L">" + std::wstring(value) + L"<"), L"event_stop_fields_invalid").eventStop, "invalid code");
        for (const auto* value : {L"0x", L"1", L"-0x1", L"0xzz", L"0x10000000000000000"})
            Check(!Parse(Replace(L">0x1<", L">" + std::wstring(value) + L"<"), L"event_stop_fields_invalid").eventStop, "invalid pointer");
        const auto partial = Parse(Replace(L"BugcheckParameter3", L"other"), L"event_stop_fields_invalid");
        Check(partial.eventCode == 159ul && !partial.eventStop, "named code survives a missing parameter");
        Parse(Replace(L"</EventData>", L"<Data Name='BugcheckParameter1'>0x1</Data></EventData>"), L"ambiguous_event_fields");
        Parse(Replace(L">159<", L">15<b/>9<"), L"nested_event_value");
        Parse(Replace(L">159<", L">" + std::wstring(300, L'9') + L"<"), L"event_field_limit");
        Parse(Replace(L"2004/08", L"2004/09"), L"unsupported_event_document");
        Parse(Replace(L"Kernel-Power", L"Kernel-Other"), L"different_event_source");
        Parse(Replace(L"331C3B3A", L"331C3B3B"), L"different_event_source");
        Parse(Replace(L">System<", L">Application<"), L"different_event_source");
        Parse(Replace(L"2024-02-29", L"2023-02-29"), L"event_metadata_incomplete");
        Parse(Replace(L">42<", L">43<"), L"record_id_mismatch");
        Parse(Replace(L">41<", L">42<"), L"unsupported_event_template");
        auto v1 = Parse(Replace(L">10</Version>", L">1</Version>"), L"event_code_only");
        Check(v1.eventCode == 159ul && !v1.eventStop, "version one exposes only its stop code");
        Check(!Parse(Replace(L">10</Version>", L">0</Version>"), L"event_stop_code_unavailable").eventCode, "version zero");
        Parse(Replace(L">10</Version>", L">11</Version>"), L"unsupported_event_template");
        Parse(L"<!DOCTYPE Event [<!ENTITY x '123'>]>" + document, L"malformed_event_xml");
        CheckClock();
        CheckChanges();
        std::cout << checked << " reboot event parser checks passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << " after " << checked << " checks\n";
        return 1;
    }
}
