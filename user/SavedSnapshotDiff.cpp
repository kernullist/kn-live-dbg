#include "SnapshotDiff.h"
#include "SnapshotJson.h"
#include "ArtifactOutput.h"
#include "RuntimeCapabilities.h"
#include "SavedEtlInput.h"
#include <iostream>

int RunSavedSnapshotDiff(const std::vector<std::wstring>& args)
{
    const bool valid = args.size() == 5 && !args[1].empty() && !args[2].empty() &&
        !_wcsicmp(args[3].c_str(), L"/summary") && !_wcsicmp(args[4].c_str(), L"/json");
    const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    std::vector<DistinctArtifactInput> guards;
    if (GetFileType(sink) == FILE_TYPE_DISK)
    {
        for (size_t i = 1; i < (valid ? 3 : args.size()); ++i)
        {
            if (!guards.emplace_back().Hold(sink, args[i], true)) { return 2; }
        }
    }
    if (!valid)
    {
        std::wcerr << L"usage: --offline !diff <baseline.json> <current.json> /summary /json\n";
        return 2;
    }

    etl_profile::SavedEtlInput baseline, current;
    SnapshotDocument first, second;
    SnapshotDiffResult diff;
    std::wstring error;
    const wchar_t* reason = nullptr;
    DWORD openError = ERROR_SUCCESS;
    // The parser reopens the pinned name. Hold each directory against renames
    // and use its volume GUID path for the entire comparison.
    if (!baseline.Open(args[1], SnapshotMaxTextFileBytes, &openError)) { reason = L"baseline_file_unavailable"; }
    else if (!current.Open(args[2], SnapshotMaxTextFileBytes, &openError)) { reason = L"current_file_unavailable"; }
    else if (!ReadSnapshotJsonFile(baseline.PinnedVolumePath(), &first, &error)) { reason = L"invalid_baseline_snapshot"; }
    else if (!ReadSnapshotJsonFile(current.PinnedVolumePath(), &second, &error)) { reason = L"invalid_current_snapshot"; }
    else if (!BuildSnapshotDiff(first, second, {}, &diff, &error)) { reason = L"comparison_failed"; }
    else if (!baseline.Revalidated() || !current.Revalidated()) { reason = L"source_revalidation_failed"; }

    std::wstring page = L"{\"schema\":\"kn.saved_snapshot_diff.v1\"";
    if (reason)
    {
        page += L",\"status\":\"unavailable\",\"reason\":" + mcpjson::Quote(reason);
        if (!baseline.File.Sha256.empty()) { page += L",\"baseline_sha256\":" + mcpjson::Quote(baseline.File.Sha256); }
        if (!current.File.Sha256.empty()) { page += L",\"current_sha256\":" + mcpjson::Quote(current.File.Sha256); }
        if (openError) { page += L",\"win32_status\":" + std::to_wstring(openError); }
        if (!error.empty()) { page += L",\"detail\":" + mcpjson::Quote(error); }
    }
    else
    {
        page += L",\"status\":\"compared\",\"baseline_sha256\":" + mcpjson::Quote(baseline.File.Sha256) +
            L",\"current_sha256\":" + mcpjson::Quote(current.File.Sha256) +
            L",\"baseline_boot_source\":" + mcpjson::Quote(SnapshotBootSourceName(first.BootSource)) +
            L",\"current_boot_source\":" + mcpjson::Quote(SnapshotBootSourceName(second.BootSource)) +
            L",\"same_boot\":" + (diff.SameBoot ? L"true" : L"false") + L",\"boot_basis\":" + mcpjson::Quote(diff.BootBasis) +
            L",\"added\":" + std::to_wstring(diff.Added) + L",\"escalated\":" + std::to_wstring(diff.Escalated) +
            L",\"removed\":" + std::to_wstring(diff.Removed) + L",\"high\":" + std::to_wstring(diff.High);
    }
    if (!WriteCapabilityJson(page + L"}")) { return 3; }
    return reason ? 1 : 0;
}
