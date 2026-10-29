#pragma once

#include "HiddenProcessPolicy.h"
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
    bool Unverified = false;
    bool Auxiliary = false;
    bool Terminating = false;
    bool HasActiveThreads = false;
    bool HasExitTime = false;
    uint32_t ActiveThreads = 0;
    uint64_t ExitTime = 0;
    std::wstring Notes;
    HiddenProcessQualification Qualification;
    HiddenProcessDecision Decision;
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
    uint32_t UnverifiedCount = 0;
    uint32_t ReconciledCount = 0;
    uint32_t IgnoredCount = 0;
    uint32_t IgnoredAuxiliaryCount = 0;
    uint32_t IgnoredTerminatingCount = 0;
    uint32_t IgnoredRaceCount = 0;
    bool InventoryComplete = false;
    bool CoverageComplete = false;
    uint64_t ComparisonStartedMs = 0;
    uint64_t ComparisonFinishedMs = 0;
};

void AddHiddenProcessDecision(HiddenProcessScanResult& result, HiddenProcessRecord record);
std::wstring BuildHiddenProcessJson(const HiddenProcessScanResult& result);
