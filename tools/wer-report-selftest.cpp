#include "../user/WerReports.h"
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace
{
    unsigned checks = 0;
    void Check(bool passed, const char* label)
    {
        if (!passed) { throw std::runtime_error(label); }
        ++checks;
    }

    std::wstring Field(const std::wstring& name, const std::wstring& value)
    { return L"<Data Name='" + name + L"'>" + value + L"</Data>"; }

    const std::wstring identifier = L"12345678-ABCD-4567-8901-0123456789AB";
    const std::wstring sysStop = L"0x00000010 (0x0, 0xffffffffffffffff, 0x3, 0X4)";
    const std::wstring sysFields = Field(L"param1", sysStop) + Field(L"param3", L"{" + identifier + L"}");
    const std::wstring appStop = Field(L"P5", L"4") + Field(L"P2", L"0") + Field(L"P4", L"3") +
        Field(L"P1", L"10") + Field(L"P3", L"ffffffffffffffff");
    const std::wstring blue = Field(L"EventName", L"BlueScreen");
    const std::wstring appFields = blue + Field(L"ReportId", identifier) + appStop;

    std::wstring Document(bool system, const std::wstring& fields, unsigned version)
    {
        const std::wstring provider = system ?
            L"Microsoft-Windows-WER-SystemErrorReporting' Guid='{abce23e7-de45-4366-8631-84fa6c525952}" :
            L"Windows Error Reporting' Guid='{0ead09bd-2157-539a-8d6d-c87f95b64d70}";
        return L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='" + provider +
            L"'/><EventID>1001</EventID><Version>" + std::to_wstring(version) + L"</Version><EventRecordID>7</EventRecordID>"
            L"<TimeCreated SystemTime='2024-02-29T12:00:00Z'/><Computer>fixture</Computer><Channel>" +
            (system ? L"System" : L"Application") + L"</Channel></System><EventData>" + fields + L"</EventData></Event>";
    }

    WerRecord Read(bool system, const std::wstring& fields, unsigned version, uint64_t id = 7)
    {
        auto xml = Document(system, fields, version);
        WerRecord row{id};
        DecodeWerReport(reinterpret_cast<const BYTE*>(xml.data()), static_cast<UINT>(xml.size() * sizeof(wchar_t)),
            system ? WerRecordKind::SystemReport : WerRecordKind::ApplicationReport, row);
        return row;
    }
}

int main()
{
    try
    {
        WerArchive sys, app;
        sys.digest.assign(64, L'a'); app.digest.assign(64, L'b');
        sys.status = app.status = L"pinned_archive_read";
        sys.report = Read(true, sysFields + Field(L"param2", std::wstring(500, L'x')), 1);
        app.report = Read(false, appFields + Field(L"AttachedFiles", std::wstring(800, L'x')), 0);
        Check(std::wstring_view(sys.report.status) == L"observed" && std::wstring_view(app.report.status) == L"observed", "qualified templates");
        Check(sys.report.stop && sys.report.stop->code == 16 && sys.report.stop->args[1] == UINT64_MAX, "hex input widths");
        Check(sys.report.reportGuid == L"12345678-abcd-4567-8901-0123456789ab" && sys.report.time == app.report.time, "normalized GUID and clocks");
        auto pair = [&] { return CompareWerReportPair(sys, app); };
        Check(pair().matches, "independent record IDs and distinct log pins");
        app.report.id = 50; app.report.time = 1;
        Check(pair().matches, "cross-channel sequence and submission time are not incident identifiers");
        app.report.reportGuid[0] = L'f';
        Check(!pair().matches && pair().sameGuid == false && pair().sameStop == true, "same stop for different reports");
        app.report.reportGuid = sys.report.reportGuid;
        ++app.report.stop->args[0];
        Check(!pair().matches && pair().sameGuid == true && pair().sameStop == false, "same GUID with conflicting parameters");
        app.report.stop = sys.report.stop; app.report.computer = L"other";
        Check(!pair().matches && pair().sameComputer == false && pair().sameGuid == true, "conflicting computer label");
        app.report.computer.clear();
        Check(!pair().matches && !pair().sameComputer.has_value(), "absent label");
        app.report.computer = sys.report.computer; app.digest = sys.digest;
        Check(!pair().matches && std::wstring_view(pair().status) == L"shared_archive_input", "same archive");
        for (const auto input : {L"0x100000000 (0x0,0x0,0x0,0x0)", L"10 (0x0,0x0,0x0,0x0)", L"0x10 (0x0,0x0,0x0)",
            L"0x10 (0x0,0x0,0x0,0x0,0x1)", L"0x10 (0x0,0x0,0x0,-0x1)", L"0x10 (0x0,0x0,0x0,0x10000000000000000)",
            L"0x10 (0x0,0x0,0x0,0x0) trailing", L"0x0 (0x0,0x0,0x0,0x0)", L"", L"("})
        {
            auto row = Read(true, Field(L"param1", input) + Field(L"param3", identifier), 1);
            Check(!row.stop && !row.reportGuid.empty(), "invalid packed tuple retained the independent ID");
        }
        for (const auto guid : {L"", L"00000000-0000-0000-0000-000000000000", L"{12345678-ABCD-4567-8901-0123456789AB",
            L"12345678-ABCD-4567-8901-0123456789AZ", L"123456781ABCD-4567-8901-0123456789AB"})
        {
            auto row = Read(false, blue + appStop + Field(L"ReportId", guid), 0);
            Check(row.stop && row.reportGuid.empty(), "invalid ID retained the independent stop");
        }
        for (const auto& extra : {Field(L"ReportId", identifier), Field(L"P1", L"10"), Field(L"EventName", L"BlueScreen")})
        { Check(std::wstring_view(Read(false, appFields + extra, 0).status) == L"ambiguous_event_fields", "duplicate named field"); }
        Check(!Read(false, Field(L"EventName", L"APPCRASH") + appStop, 0).stop, "other application report type");
        Check(!Read(true, sysFields, 2).stop && !Read(false, appFields, 1).stop, "unknown templates");
        Check(!Read(false, appFields, 0, 8).stop, "other selected record ID");
        auto bad = Document(false, appFields, 0);
        bad.replace(bad.find(L"Application"), 11, L"System");
        DecodeWerReport(reinterpret_cast<const BYTE*>(bad.data()), static_cast<UINT>(bad.size() * sizeof(wchar_t)),
            WerRecordKind::ApplicationReport, app.report);
        Check(!app.report.stop && app.report.reportGuid.empty(), "reused decoder clears earlier evidence on source rejection");
        std::cout << checks << " WER parser and comparison checks passed\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << e.what() << " after " << checks << " checks\n"; return 1; }
}
