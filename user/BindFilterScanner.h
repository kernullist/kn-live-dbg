#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct BindFilterMappingRecord
{
    std::wstring VolumeRoot;
    std::wstring VirtualRoot;
    std::vector<std::wstring> TargetRoots;
    uint32_t Flags = 0;
};

struct BindFilterScanResult
{
    std::vector<BindFilterMappingRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t VolumesAttempted = 0;
    uint64_t VolumesCompleted = 0;
    bool GlobalCoverageComplete = false;
    // BfGetMappings requires a specific job handle for a silo-scoped query.
    // The initial collector intentionally reports this residual limitation.
    bool SiloCoverageSupported = false;
};

class BindFilterScanner
{
public:
    bool ScanGlobal(
        BindFilterScanResult* result,
        std::wstring* error);
};

bool BindFilterScannerSelfTest();
