#pragma once

#include "RebootEvent.h"
#include <string_view>

enum class WerRecordKind { SystemReport, ApplicationReport, Restart };

struct WerRecord
{
    uint64_t id = 0;
    const wchar_t* status = L"record_unavailable";
    std::wstring computer, reportGuid;
    std::optional<unsigned> version;
    std::optional<uint64_t> time;
    std::optional<SavedCrashStop> stop;
    std::optional<DWORD> error;
    std::optional<bool> SameComputer(const WerRecord& other) const
    {
        if (computer.empty() || other.computer.empty()) { return {}; }
        return computer == other.computer;
    }
    std::optional<bool> SameStop(const WerRecord& other) const
    {
        if (!stop || !other.stop) { return {}; }
        return *stop == *other.stop;
    }
};

struct WerRestartInterval
{
    WerRecord restart;
    unsigned recordsRead = 0, classifiedRecords = 0;
    uint64_t interveningRecord = 0;
    const wchar_t* status = L"endpoints_unavailable";
    std::optional<DWORD> error;
};

struct WerArchive
{
    std::wstring digest;
    uint64_t bytes = 0;
    const wchar_t* status = L"event_source_unavailable";
    std::optional<DWORD> error;
    WerRecord report;
    std::optional<WerRestartInterval> interval;
};

struct WerReportPair
{
    std::optional<bool> sameComputer, sameGuid, sameStop;
    const wchar_t* status;
    bool matches;
};

inline WerReportPair CompareWerReportPair(const WerArchive& system, const WerArchive& application)
{
    WerReportPair pair{};
    pair.sameComputer = system.report.SameComputer(application.report);
    if (!system.report.reportGuid.empty() && !application.report.reportGuid.empty())
    { pair.sameGuid = system.report.reportGuid == application.report.reportGuid; }
    pair.sameStop = system.report.SameStop(application.report);
    const bool shared = !system.digest.empty() && system.digest == application.digest;
    pair.matches = std::wstring_view(system.status) == L"pinned_archive_read" && std::wstring_view(application.status) == L"pinned_archive_read" &&
        !shared && !system.digest.empty() && !application.digest.empty() &&
        pair.sameComputer == true && pair.sameGuid == true && pair.sameStop == true;
    if (pair.sameComputer == false || pair.sameGuid == false || pair.sameStop == false) { pair.status = L"conflicting_report_fields"; }
    else if (pair.matches) { pair.status = L"matching_recorded_report"; }
    else { pair.status = shared ? L"shared_archive_input" : L"report_fields_unavailable"; }
    return pair;
}

void DecodeWerReport(const BYTE* xml, UINT byteCount, WerRecordKind kind, WerRecord& record);
WerArchive ReadWerArchive(const std::wstring& name, const std::wstring& pin, WerRecordKind kind,
    uint64_t reportId, uint64_t restartId = 0);
int RunWerReports(const std::vector<std::wstring>& args);
