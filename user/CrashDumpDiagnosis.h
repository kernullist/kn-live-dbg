#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The caller has already qualified both coordinates in the saved AMD64 header.
inline std::optional<bool> CompareSavedCrashContext(uint64_t savedIp, uint64_t savedSp,
    std::optional<uint64_t> selectedIp, std::optional<uint64_t> selectedSp)
{
    if ((selectedIp && *selectedIp != savedIp) || (selectedSp && *selectedSp != savedSp)) { return false; }
    if (selectedIp && selectedSp) { return true; }
    return std::nullopt;
}

int RunCrashDumpDiagnosis(const std::vector<std::wstring>& args);
