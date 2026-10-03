#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct HandleTableRecord
{
    uint32_t OwnerPid = 0;
    uint64_t HandleValue = 0;
    uint32_t GrantedAccess = 0;
    uint32_t ObjectTypeIndex = 0;
    uint32_t HandleAttributes = 0;
    uint64_t Object = 0;
    std::wstring OwnerImage;
    std::wstring TypeName;
    std::wstring AccessText;
    std::wstring Notes;
    bool PointsToProcess = false;
    bool TypeResolved = false;
    bool ObjectTypeValidated = false;
    bool RelationshipResolved = false;
    bool TargetIdentityKnown = false;
    uint64_t TargetCreateTime = 0;
    uint64_t DeviceObject = 0;
    uint64_t DriverObject = 0;
    uint32_t DeviceType = 0;
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
    bool ContinueHandles = false;
    uint64_t HandleAfter = 0;
    uint32_t MaxHandlesPerPass = 4096;
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
    bool ObjectTypeCoverageComplete = false;
    uint64_t ObjectTypeReadFailures = 0;
    bool ProcessInventoryRequested = false;
    bool ProcessInventoryComplete = false;
    bool RelationshipCoverageComplete = false;
    uint64_t RelationshipReadFailures = 0;
    uint64_t RelationshipUnsupported = 0;
    uint64_t HandleCandidates = 0;
    uint64_t HandlesVisited = 0;
    uint64_t InvalidHandleEntries = 0;
    uint64_t NextHandleAfter = 0;
    uint64_t RelationshipReadAttempts = 0;
    bool HandleCoveragePartial = false;
    bool RelationshipBudgetExhausted = false;
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
std::wstring HandleTableRecordIdentity(const HandleTableRecord& record);
bool HandleTableAccessMaskSelfTest();
std::vector<uint32_t> SelectHandleOwnerBatch(std::vector<uint32_t> pids, uint64_t* afterPid, size_t limit);
