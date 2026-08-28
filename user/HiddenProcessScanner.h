#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct HiddenProcessRecord
{
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    std::wstring ImageName;
    bool InKernelList = false;
    bool InSystemProcessInfo = false;
    bool InToolhelp = false;
    bool InHandleOwners = false;
    bool InCidTable = false;
    bool Suspicious = false;
    bool Auxiliary = false;
    bool Terminating = false;
    bool HasActiveThreads = false;
    bool HasExitTime = false;
    uint32_t ActiveThreads = 0;
    uint64_t ExitTime = 0;
    std::wstring Notes;
};

struct HiddenProcessScanResult
{
    std::vector<HiddenProcessRecord> Records;
    std::vector<std::wstring> Warnings;
    uint32_t KernelListCount = 0;
    uint32_t SystemProcessInfoCount = 0;
    uint32_t ToolhelpCount = 0;
    uint32_t HandleOwnerCount = 0;
    uint32_t CidTableCount = 0;
    uint32_t SuspiciousCount = 0;
    uint32_t IgnoredCount = 0;
    uint32_t IgnoredAuxiliaryCount = 0;
    uint32_t IgnoredTerminatingCount = 0;
    uint32_t IgnoredRaceCount = 0;
    bool CoverageComplete = false;
};

class HiddenProcessScanner
{
public:
    HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(HiddenProcessScanResult* result, std::wstring* error);
    bool Scan(
        HiddenProcessScanResult* result,
        const std::vector<uint32_t>& extraCandidatePids,
        std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildHiddenProcessJson(const HiddenProcessScanResult& result);
bool HiddenProcessViewSelfTest();
