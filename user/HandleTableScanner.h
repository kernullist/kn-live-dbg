#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct HandleTableRecord
{
    uint32_t OwnerPid = 0;
    uint32_t HandleValue = 0;
    uint32_t GrantedAccess = 0;
    uint32_t ObjectTypeIndex = 0;
    uint32_t HandleAttributes = 0;
    uint64_t Object = 0;
    std::wstring OwnerImage;
    std::wstring TypeName;
    std::wstring AccessText;
    std::wstring Notes;
    bool PointsToProcess = false;
    uint32_t TargetPid = 0;
    uint64_t TargetEprocess = 0;
    std::wstring TargetImage;
    bool VmRead = false;
    bool VmWrite = false;
    bool VmOperation = false;
    bool DupHandle = false;
    bool Suspicious = false;
};

struct HandleTableScanOptions
{
    uint32_t OwnerPid = 0;
    bool HasOwnerPid = false;
    uint32_t TargetPid = 0;
    bool HasTargetPid = false;
    bool ProcessHandlesOnly = false;
    bool SuspiciousOnly = false;
    bool CollectRecords = true;
    uint32_t Limit = 0;
};

struct HandleTableScanResult
{
    std::vector<HandleTableRecord> Records;
    std::vector<uint32_t> OwnerPids;
    std::vector<std::wstring> Warnings;
    uint64_t HandlesEnumerated = 0;
    uint64_t MatchingHandles = 0;
    uint64_t ProcessHandles = 0;
    uint64_t SuspiciousHandles = 0;
    bool Truncated = false;
    bool CoverageComplete = false;
};

class HandleTableScanner
{
public:
    HandleTableScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const HandleTableScanOptions& options, HandleTableScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildHandleTableJson(const HandleTableScanResult& result);
bool HandleTableAccessMaskSelfTest();
