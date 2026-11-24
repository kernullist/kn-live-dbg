#include "WerReports.h"
#include "ArtifactOutput.h"
#include "McpJson.h"
#include "RuntimeCapabilities.h"
#include "SavedEtlInput.h"

#include <iostream>
#include <string_view>

namespace
{
    using mcpjson::Quote;
    std::wstring OptionalText(const std::wstring& text) { return text.empty() ? L"null" : Quote(text); }
    const wchar_t* Agreement(std::optional<bool> result) { return result ? (*result ? L"true" : L"false") : L"null"; }
    std::wstring Error(const std::optional<DWORD>& code) { return code ? std::to_wstring(*code) : L"null"; }

    std::wstring RecordJson(const WerRecord& row)
    {
        std::wstring parameters = L"null";
        if (row.stop)
        {
            parameters = L"[";
            for (const auto value : row.stop->args)
            {
                if (parameters.size() > 1) { parameters += L","; }
                parameters += Quote(std::to_wstring(value));
            }
            parameters += L"]";
        }
        return L"{\"wer_record_id\":" + Quote(std::to_wstring(row.id)) + L",\"status\":" + Quote(row.status) +
            L",\"version\":" + (row.version ? std::to_wstring(*row.version) : L"null") +
            L",\"wer_event_filetime\":" + (row.time ? Quote(std::to_wstring(*row.time)) : L"null") +
            L",\"computer_label_observed\":" + (row.computer.empty() ? L"false" : L"true") +
            L",\"wer_report_guid\":" + OptionalText(row.reportGuid) +
            L",\"wer_bugcheck_code\":" + (row.stop ? Quote(std::to_wstring(row.stop->code)) : L"null") +
            L",\"wer_bugcheck_parameters\":" + parameters +
            L",\"win32_error\":" + Error(row.error) + L"}";
    }

    std::wstring ArchiveJson(const WerArchive& log)
    {
        return L"{\"wer_log_sha256\":" + OptionalText(log.digest) + L",\"bytes\":" + Quote(std::to_wstring(log.bytes)) +
            L",\"status\":" + Quote(log.status) + L",\"win32_error\":" + Error(log.error) + L",\"report\":" + RecordJson(log.report) + L"}";
    }

    struct Evidence
    {
        std::vector<const wchar_t*> support, contrary, missing;

        void Cite(std::optional<bool> result, std::initializer_list<const wchar_t*> fields)
        {
            auto& list = !result ? missing : *result ? support : contrary;
            list.insert(list.end(), fields.begin(), fields.end());
        }

        static std::wstring Pointers(const std::vector<const wchar_t*>& fields)
        {
            std::wstring json = L"[";
            for (const auto field : fields)
            {
                if (json.size() > 1) { json += L","; }
                json += Quote(field);
            }
            return json + L"]";
        }

        std::wstring Json(const wchar_t* next) const
        {
            return L"{\"candidate\":\"same_recorded_bugcheck_report\",\"support\":" + Pointers(support) +
                L",\"contrary\":" + Pointers(contrary) + L",\"missing\":" + Pointers(missing) + L",\"next\":" + Quote(next) + L"}";
        }
    };

    struct Options
    {
        std::wstring systemPin, applicationPin;
        uint64_t systemRecord = 0, applicationRecord = 0, restart = 0;
        bool Parse(const std::vector<std::wstring>& a)
        {
            return (a.size() == 11 || a.size() == 13) && a[1] == L"--sha256" && etl_profile::NormalizeDigest(a[2], systemPin) &&
                a[3] == L"--system-record" && ParseEventRecordId(a[4], systemRecord) && a[5] == L"--application-log" &&
                a[7] == L"--application-sha256" && etl_profile::NormalizeDigest(a[8], applicationPin) &&
                a[9] == L"--application-record" && ParseEventRecordId(a[10], applicationRecord) &&
                (a.size() == 11 || (a[11] == L"--restart-record" && ParseEventRecordId(a[12], restart)));
        }
    };

    int Compare(const std::vector<std::wstring>& args, const Options& options)
    {
        const auto sys = ReadWerArchive(args[0], options.systemPin, WerRecordKind::SystemReport, options.systemRecord, options.restart);
        const auto app = ReadWerArchive(args[6], options.applicationPin, WerRecordKind::ApplicationReport, options.applicationRecord);
        const auto pair = CompareWerReportPair(sys, app);
        Evidence evidence;
        evidence.Cite(pair.sameGuid, {L"/report_pair/same_wer_report_id", L"/system_log/report/wer_report_guid", L"/application_log/report/wer_report_guid"});
        evidence.Cite(pair.sameStop, {L"/report_pair/same_reported_stop", L"/system_log/report/wer_bugcheck_code", L"/system_log/report/wer_bugcheck_parameters",
            L"/application_log/report/wer_bugcheck_code", L"/application_log/report/wer_bugcheck_parameters"});
        evidence.Cite(pair.sameComputer, {L"/report_pair/same_recorded_computer", L"/system_log/report/wer_record_id", L"/application_log/report/wer_record_id"});
        const auto pins = {L"/system_log/wer_log_sha256", L"/application_log/wer_log_sha256"};
        if (!evidence.support.empty()) { evidence.Cite(true, pins); }
        if (!evidence.contrary.empty()) { evidence.Cite(false, pins); }
        if (std::wstring_view(sys.status) != L"pinned_archive_read" || std::wstring_view(app.status) != L"pinned_archive_read" ||
            sys.digest == app.digest) { evidence.Cite({}, pins); }
        std::wstring spanJson = L"null";
        bool restartMatch = false;
        if (sys.interval)
        {
            const auto& span = *sys.interval;
            const auto restartStop = span.restart.SameStop(sys.report);
            const auto restartMachine = span.restart.SameComputer(sys.report);
            restartMatch = restartStop == true && std::wstring_view(span.status) == L"continuous_saved_system_records";
            evidence.Cite(restartStop, {L"/restart_interval/same_reported_stop", L"/system_log/report", L"/restart_interval/restart/wer_bugcheck_code",
                L"/restart_interval/restart/wer_bugcheck_parameters"});
            evidence.Cite(restartMachine, {L"/restart_interval/same_recorded_computer"});
            std::optional<bool> coverage;
            const std::wstring_view status(span.status);
            if (status == L"continuous_saved_system_records") { coverage = true; }
            else if (status == L"record_order_conflict" || status == L"recorded_clock_order_conflict") { coverage = false; }
            evidence.Cite(coverage, {L"/restart_interval/coverage"});
            spanJson = L"{\"restart\":" + RecordJson(span.restart) + L",\"coverage\":" + Quote(span.status) +
                L",\"records_read\":" + std::to_wstring(span.recordsRead) + L",\"classified_records\":" + std::to_wstring(span.classifiedRecords) +
                L",\"wer_intervening_record\":" + (span.interveningRecord ? Quote(std::to_wstring(span.interveningRecord)) : L"null") +
                L",\"same_recorded_computer\":" + Agreement(restartMachine) + L",\"same_reported_stop\":" + Agreement(restartStop) +
                L",\"restart_report_corroborated\":" + (restartMatch ? L"true" : L"false") + L",\"win32_error\":" + Error(span.error) + L"}";
        }
        const auto next = !evidence.contrary.empty() ? L"compare_the_original_records_for_conflicting_fields" :
            !pair.matches ? L"verify_selected_log_pins_and_records" :
            options.restart && !restartMatch ? L"inspect_the_selected_system_interval" : L"obtain_independently_collected_incident_dump";
        evidence.Cite({}, {L"/source_authenticated", L"/same_host_boot_verified", L"/dump_content_verified"});
        const auto json = L"{\"schema\":\"kn.wer_report_comparison.v1\",\"system_log\":" + ArchiveJson(sys) +
            L",\"application_log\":" + ArchiveJson(app) + L",\"report_pair\":{\"status\":" + Quote(pair.status) +
            L",\"same_wer_report_id\":" + Agreement(pair.sameGuid) + L",\"same_reported_stop\":" + Agreement(pair.sameStop) +
            L",\"same_recorded_computer\":" + Agreement(pair.sameComputer) + L"},\"restart_interval\":" + spanJson +
            L",\"assessment\":" + evidence.Json(next) +
            L",\"source_authenticated\":false,\"same_host_boot_verified\":false,\"dump_content_verified\":false,\"attributed_cause\":null}";
        return WriteCapabilityJson(json) ? (pair.matches && (!options.restart || restartMatch) ? 0 : 1) : 2;
    }
}

int RunWerReports(const std::vector<std::wstring>& args)
{
    Options options;
    const bool valid = options.Parse(args);
    const DWORD stream = valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE;
    if (GetFileType(GetStdHandle(stream)) == FILE_TYPE_DISK && std::count(args.begin(), args.end(), L"--application-log") > 1) { return 2; }
    return WriteWithDistinctSelectedInputs(stream, args, [](const std::wstring& s) { return s == L"--application-log"; }, [&] {
        return WriteWithDistinctInput(stream, args.empty() ? L"" : args.front(), [&] {
            if (valid) { return Compare(args, options); }
            std::wcerr << L"usage: KnLiveDbg.exe --wer-reports <system.evtx> --sha256 <digest> --system-record <id> "
                L"--application-log <application.evtx> --application-sha256 <digest> --application-record <id> [--restart-record <id>]\n";
            return 2;
        });
    });
}
