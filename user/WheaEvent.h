#pragma once

#include <optional>
#include <string>

struct WheaRecord;

struct WheaEventComparison
{
    std::wstring report;
    std::optional<bool> samePayload;
    bool dumpAvailable = false;
    bool eventAvailable = false;
    std::wstring Hypothesis() const;
};

// Compare a separately pinned Event Viewer XML export with the completed dump record.
WheaEventComparison CompareSavedWheaEvent(const std::wstring& path, const std::wstring& pin, const WheaRecord& dump);
