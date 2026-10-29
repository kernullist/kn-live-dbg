#include "HiddenProcessReport.h"
#include "McpJson.h"

#include <sstream>
#include <utility>

void AddHiddenProcessDecision(HiddenProcessScanResult& result, HiddenProcessRecord record)
{
    HiddenProcessMembership discovery;
    discovery.Kernel = record.InKernelList;
    discovery.Spi = record.InSystemProcessInfo;
    discovery.Toolhelp = record.InToolhelp;
    discovery.Cid = record.InCidTable;
    discovery.Handles = record.InHandleOwners;
    record.Decision = QualifyHiddenProcess(record.ProcessId, discovery, record.Qualification);
    const auto disposition = record.Decision.Disposition;
    if (disposition == HiddenProcessDisposition::None)
    {
        return;
    }
    record.Suspicious = disposition == HiddenProcessDisposition::CrossViewDiscrepancy;
    record.Unverified = disposition == HiddenProcessDisposition::Unverified;
    record.Auxiliary = disposition == HiddenProcessDisposition::Auxiliary;
    record.Terminating = disposition == HiddenProcessDisposition::Terminating;
    record.Notes = record.Decision.Notes;
    const auto& after = record.Qualification.After;
    record.HasActiveThreads = record.Decision.StableLifetime && after.HasActiveThreads;
    record.HasExitTime = record.Decision.StableLifetime && after.HasExitTime;
    record.ActiveThreads = record.HasActiveThreads ? after.ActiveThreads : 0;
    record.ExitTime = record.HasExitTime ? after.ExitTime : 0;
    result.SuspiciousCount += record.Suspicious ? 1 : 0;
    result.UnverifiedCount += record.Unverified ? 1 : 0;
    result.IgnoredAuxiliaryCount += record.Auxiliary ? 1 : 0;
    result.IgnoredTerminatingCount += record.Terminating ? 1 : 0;
    result.ReconciledCount += disposition == HiddenProcessDisposition::Reconciled ? 1 : 0;
    result.IgnoredCount += !record.Suspicious && !record.Unverified ? 1 : 0;
    if (record.Unverified)
    {
        result.CoverageComplete = false;
    }
    result.Records.push_back(std::move(record));
}

namespace
{
    void WriteLifetime(std::wostream& json, const HiddenProcessLifetime& value)
    {
        json << L"{\"pid\":" << value.Pid
            << L",\"eprocess\":\"0x" << std::hex << value.Eprocess << std::dec
            << L"\",\"create_time\":\"0x" << std::hex << value.CreateTime << std::dec
            << L"\",\"identity_valid\":" << (value.IdentityValid ? L"true" : L"false")
            << L",\"active_threads\":";
        if (value.IdentityValid && value.HasActiveThreads)
        {
            json << value.ActiveThreads;
        }
        else
        {
            json << L"null";
        }
        json << L",\"exit_time\":";
        if (value.IdentityValid && value.HasExitTime)
        {
            json << L"\"0x" << std::hex << value.ExitTime << std::dec << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"auxiliary\":";
        if (value.IdentityValid && value.HasAuxiliary)
        {
            json << (value.Auxiliary ? L"true" : L"false");
        }
        else
        {
            json << L"null";
        }
        json << L",\"state_transition\":";
        if (value.IdentityValid && value.HasStateFlags)
        {
            json << (value.StateTransition ? L"true" : L"false");
        }
        else
        {
            json << L"null";
        }
        json << L"}";
    }
}

std::wstring BuildHiddenProcessJson(const HiddenProcessScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.hidden-process.v1\"";
    json << L",\"policy\":\"lifetime-cross-view-v2\",\"membership_scope\":\"discovery\"";
    json << L",\"consistency\":\"live_non_atomic\",\"api_dependency\":\"shared_process_list\"";
    json << L",\"claim_scope\":\"sampled_cross_view_discrepancy\",\"actor_attributed\":false";
    json << L",\"kernel_list\":" << result.KernelListCount;
    json << L",\"spi\":" << result.SystemProcessInfoCount;
    json << L",\"toolhelp\":" << result.ToolhelpCount;
    json << L",\"handle_owners\":" << result.HandleOwnerCount;
    json << L",\"cid_table\":" << result.CidTableCount;
    json << L",\"suspicious\":" << result.SuspiciousCount;
    json << L",\"unverified\":" << result.UnverifiedCount;
    json << L",\"reconciled\":" << result.ReconciledCount;
    json << L",\"ignored\":" << result.IgnoredCount;
    json << L",\"ignored_auxiliary\":" << result.IgnoredAuxiliaryCount;
    json << L",\"ignored_terminating\":" << result.IgnoredTerminatingCount;
    json << L",\"ignored_race\":" << result.IgnoredRaceCount;
    json << L",\"inventory_complete\":" << (result.InventoryComplete ? L"true" : L"false");
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"comparison_started_ms\":" << result.ComparisonStartedMs;
    json << L",\"comparison_finished_ms\":" << result.ComparisonFinishedMs;
    json << L",\"warnings\":[";
    bool first = true;
    for (const auto& warning : result.Warnings)
    {
        if (!first)
        {
            json << L",";
        }
        first = false;
        json << L"\"" << mcpjson::Escape(warning) << L"\"";
    }
    json << L"],\"records\":[";
    first = true;
    for (const auto& record : result.Records)
    {
        if (!first)
        {
            json << L",";
        }
        first = false;
        const auto& q = record.Qualification;
        const uint64_t publishedObject = record.Decision.StableLifetime ? q.After.Eprocess : record.Eprocess;
        json << L"{\"pid\":" << record.ProcessId;
        json << L",\"eprocess\":\"0x" << std::hex << publishedObject << std::dec << L"\"";
        json << L",\"eprocess_scope\":\"" << (record.Decision.StableLifetime ? L"qualification" : L"discovery") << L"\"";
        json << L",\"discovery_eprocess\":\"0x" << std::hex << record.Eprocess << std::dec << L"\"";
        json << L",\"image\":\"" << mcpjson::Escape(record.ImageName) << L"\"";
        json << L",\"image_scope\":\"discovery_pid_hint\"";
        json << L",\"kernel\":" << (record.InKernelList ? L"true" : L"false");
        json << L",\"spi\":" << (record.InSystemProcessInfo ? L"true" : L"false");
        json << L",\"toolhelp\":" << (record.InToolhelp ? L"true" : L"false");
        json << L",\"handle_owner\":" << (record.InHandleOwners ? L"true" : L"false");
        json << L",\"cid_table\":" << (record.InCidTable ? L"true" : L"false");
        json << L",\"auxiliary\":" << (record.Auxiliary ? L"true" : L"false");
        json << L",\"terminating\":" << (record.Terminating ? L"true" : L"false");
        json << L",\"has_active_threads\":" << (record.HasActiveThreads ? L"true" : L"false");
        json << L",\"active_threads\":" << record.ActiveThreads;
        json << L",\"has_exit_time\":" << (record.HasExitTime ? L"true" : L"false");
        json << L",\"exit_time\":\"0x" << std::hex << record.ExitTime << std::dec << L"\"";
        json << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false");
        json << L",\"unverified\":" << (record.Unverified ? L"true" : L"false");
        json << L",\"state\":\"" << HiddenProcessDispositionName(record.Decision.Disposition) << L"\"";
        json << L",\"reason\":\"" << record.Decision.Reason << L"\"";
        json << L",\"qualification\":{\"attempted\":" << (q.Attempted ? L"true" : L"false")
            << L",\"budget_exceeded\":" << (q.BudgetExceeded ? L"true" : L"false")
            << L",\"stable_lifetime\":" << (record.Decision.StableLifetime ? L"true" : L"false")
            << L",\"kernel_complete\":" << (q.KernelComplete ? L"true" : L"false")
            << L",\"spi_complete\":" << (q.SpiComplete ? L"true" : L"false")
            << L",\"toolhelp_complete\":" << (q.ToolhelpComplete ? L"true" : L"false")
            << L",\"kernel\":" << (q.Views.Kernel ? L"true" : L"false")
            << L",\"spi\":" << (q.Views.Spi ? L"true" : L"false")
            << L",\"toolhelp\":" << (q.Views.Toolhelp ? L"true" : L"false")
            << L",\"kernel_eprocess\":\"0x" << std::hex << q.KernelIdentity.Eprocess << std::dec
            << L"\",\"kernel_create_time\":\"0x" << std::hex << q.KernelIdentity.CreateTime << std::dec
            << L"\",\"kernel_has_create_time\":" << (q.KernelIdentity.HasCreateTime ? L"true" : L"false")
            << L",\"before\":";
        WriteLifetime(json, q.Before);
        json << L",\"after\":";
        WriteLifetime(json, q.After);
        json << L"},\"notes\":\"" << mcpjson::Escape(record.Notes) << L"\"}";
    }
    json << L"]}";
    return json.str();
}
