#pragma once

#include "DeviceClient.h"
#include "ProcessTriageScanner.h"
#include "SnapshotModel.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

enum class HuntMode
{
    Quick,
    Default,
    Deep
};

struct HuntOptions
{
    HuntMode Mode = HuntMode::Default;
    uint32_t RenderLimit = 200;
    std::vector<SnapshotProcessRecord> Processes;
};

struct HuntModuleRecord
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    std::wstring Name;
    std::wstring Path;
    bool ToolhelpSeen = false;
    bool LdrLoadSeen = false;
    bool LdrMemorySeen = false;
    bool LdrInitSeen = false;
    bool PrivatePeVadSeen = false;
    bool VadImageSeen = false;
    uint64_t VadAddress = 0;
    std::wstring VadBackingPath;
    std::wstring VadBackingState;
};

struct HuntProcessRecord
{
    SnapshotProcessRecord Kernel = {};
    uint32_t ProcessId = 0;
    uint32_t ParentProcessId = 0;
    uint32_t SessionId = 0;
    bool HasParentProcessId = false;
    bool HasSessionId = false;
    bool ActiveProcessLinksSeen = false;
    bool SystemProcessInformationSeen = false;
    bool ToolhelpProcessSeen = false;
    bool HasCidTableView = false;
    bool CidTableSeen = false;
    std::wstring KernelImageName;
    std::wstring SystemProcessImageName;
    std::wstring ToolhelpImageName;
    std::wstring ApiImagePath;
    uint64_t PebImageBase = 0;
    bool HasPebImageBase = false;
    uint64_t MainImageBase = 0;
    uint64_t MainImageSize = 0;
    uint64_t MainImageVad = 0;
    std::wstring SectionBackingPath;
    std::wstring SectionBackingState;
    std::wstring DiskPath;
    std::wstring PebImagePath;
    std::wstring PebCommandLine;
    std::wstring ParentImageName;
    std::wstring BuiltinProfile;
    bool BuiltinProfileMatched = false;
    bool BuiltinSignatureVerified = false;
    std::vector<std::wstring> BuiltinProfileExpectedPaths;
    std::vector<std::wstring> BuiltinProfileViolations;
    bool ToolhelpModuleEnumerated = false;
    bool PebLdrEnumerated = false;
    bool PebLdrLoadEnumerated = false;
    bool PebLdrMemoryEnumerated = false;
    bool PebLdrInitEnumerated = false;
    std::vector<ProcessVadRecord> VadRecords;
    std::vector<ProcessHiddenVadPteRecord> HiddenPteRecords;
    std::vector<ProcessThreadRecord> ThreadRecords;
    std::vector<HuntModuleRecord> Modules;
    std::vector<std::wstring> Warnings;
    uint64_t VadNodesVisited = 0;
    uint64_t ExecutableVadCount = 0;
    uint64_t PrivateExecutableVadCount = 0;
    uint64_t WxVadCount = 0;
    uint64_t PeLikeVadCount = 0;
    uint64_t HiddenPteRanges = 0;
    uint64_t HiddenPteBytes = 0;
    uint64_t ThreadsVisited = 0;
    uint64_t SuspiciousThreadStarts = 0;
    uint64_t NonEmptyApcQueues = 0;
    uint64_t StackReferenceCount = 0;
};

struct HuntFinding
{
    std::wstring Risk;
    std::wstring Confidence;
    std::wstring ClassName;
    std::wstring Title;
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t Address = 0;
    std::wstring ImageName;
    std::wstring ModuleName;
    std::vector<std::wstring> ReasonCodes;
    std::map<std::wstring, std::wstring> Evidence;
    std::vector<std::wstring> Followups;
};

struct HuntResult
{
    std::wstring Schema;
    std::wstring TimestampUtc;
    std::wstring ModeText;
    std::vector<HuntProcessRecord> Processes;
    std::vector<HuntFinding> Findings;
    std::vector<std::wstring> Warnings;
    uint64_t KernelProcessCount = 0;
    uint64_t SystemProcessInfoCount = 0;
    uint64_t ToolhelpProcessCount = 0;
    uint64_t ScannedProcessCount = 0;
    uint64_t VadRecordCount = 0;
    uint64_t HiddenPteRangeCount = 0;
    uint64_t ThreadRecordCount = 0;
    uint64_t ModuleRecordCount = 0;
    uint64_t HighFindings = 0;
    uint64_t MediumFindings = 0;
    uint64_t LowFindings = 0;
    uint64_t InfoFindings = 0;
};

class UserModeHunter
{
public:
    UserModeHunter(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const HuntOptions& options, HuntResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring HuntModeToText(HuntMode mode);
std::wstring BuildHuntJson(const HuntResult& result);
