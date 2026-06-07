#pragma once

#include "DeviceClient.h"
#include "SnapshotModel.h"
#include "SymbolEngine.h"

#include <string>
#include <vector>

struct SnapshotCaptureOptions
{
    std::wstring Label;
    std::wstring ExecutableDirectory;
    bool IncludeAll = true;
    bool AllowByovdAutoUpdate = true;
    bool CaptureVadDkomForNewProcesses = false;
    const SnapshotDocument* BaselineForVadDkom = nullptr;
    std::vector<SnapshotProcessRecord> Processes;
};

class SnapshotCollector
{
public:
    SnapshotCollector(DeviceClient& device, SymbolEngine& symbols);

    bool Capture(const SnapshotCaptureOptions& options, SnapshotDocument* document, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
