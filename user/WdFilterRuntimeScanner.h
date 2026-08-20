#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct WdFilterRuntimeRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    uint64_t Next = 0;
    std::wstring DriverName;
    std::wstring DriverPath;
    std::wstring Notes;
    bool InLoadedModules = false;
    bool Suspicious = false;
};

struct WdFilterRuntimeScanResult
{
    std::vector<WdFilterRuntimeRecord> Records;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> CoverageNotes;
    uint64_t ArrayAddress = 0;
    uint64_t CountAddress = 0;
    uint64_t ListAddress = 0;
    std::wstring ArraySymbol;
    std::wstring CountSymbol;
    std::wstring ListSymbol;
    std::wstring WalkMode;
    uint32_t CountValue = 0;
    uint32_t SuspiciousCount = 0;
    bool Resolved = false;
    bool CoverageComplete = false;
};

class WdFilterRuntimeScanner
{
public:
    WdFilterRuntimeScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(WdFilterRuntimeScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildWdFilterRuntimeJson(const WdFilterRuntimeScanResult& result);
bool WdFilterRuntimeNameSelfTest();
