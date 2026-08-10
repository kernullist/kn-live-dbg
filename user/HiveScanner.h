#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One registry hive node with GetCellRoutine ownership evidence.
struct HiveRecord
{
    uint32_t Index = 0;
    uint64_t HiveAddress = 0;
    uint64_t ListEntryAddress = 0;
    uint64_t GetCellRoutine = 0;
    uint64_t ReleaseCellRoutine = 0;
    uint64_t Allocate = 0;
    uint64_t Free = 0;
    std::wstring GetCellModule;
    std::wstring GetCellSymbol;
    std::wstring ReleaseCellModule;
    std::wstring ReleaseCellSymbol;
    std::wstring Notes;
    bool Suspicious = false;
    bool HasReleaseCell = false;
    bool HasAllocate = false;
    bool HasFree = false;
};

struct HiveScanResult
{
    std::vector<HiveRecord> Hives;
    std::vector<std::wstring> Warnings;
    uint64_t ListHeadAddress = 0;
    std::wstring ListHeadSymbol;
    bool ListHeadResolved = false;
    bool LayoutFromPdb = false;
    bool CoverageComplete = false;
    uint32_t SuspiciousCount = 0;
    bool AnySuspicious = false;
    uint32_t HiveListOffset = 0;
    uint32_t GetCellOffset = 0;
    uint32_t ReleaseCellOffset = 0;
};

// Passive walk of CmpHiveListHead / _CMHIVE/_HHIVE GetCellRoutine ownership.
// Read-only; never invokes registry cell routines.
class HiveScanner
{
public:
    struct Options
    {
        bool Verbose = false;
        uint32_t Limit = 0;
    };

    HiveScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, HiveScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildHiveJson(const HiveScanResult& result);
