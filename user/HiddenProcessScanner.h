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
    bool Suspicious = false;
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
    uint32_t SuspiciousCount = 0;
    bool CoverageComplete = false;
};

class HiddenProcessScanner
{
public:
    HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(HiddenProcessScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildHiddenProcessJson(const HiddenProcessScanResult& result);
bool HiddenProcessViewSelfTest();
