#include "../user/RebootEvent.h"
#include <iostream>
#include <stdexcept>

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
        std::cout << checked << " reboot event parser checks passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << " after " << checked << " checks\n";
        return 1;
    }
}
