#pragma once

#include "DeviceClient.h"
#include "MemoryDumper.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct ProcessTriageTarget
{
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t DirectoryTableBase = 0;
    uint64_t UserDirectoryTableBase = 0;
    uint64_t Peb = 0;
    bool     HasPeb = false;
    std::wstring ImageName;
};

struct ProcessUserModuleRange
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    std::wstring ImageName;
    std::wstring ImagePath;
};

struct ProcessVadRecord
{
    uint64_t VadAddress = 0;
    uint64_t NodeAddress = 0;
    uint64_t Left = 0;
    uint64_t Right = 0;
    uint64_t StartVpn = 0;
    uint64_t EndVpn = 0;
    uint64_t StartAddress = 0;
    uint64_t EndAddress = 0;
    uint64_t Size = 0;
    uint64_t CommitCharge = 0;
    uint32_t Protection = 0;
    std::wstring ProtectionText;
    bool HasProtection = false;
    bool Executable = false;
    bool Writable = false;
    bool CopyOnWrite = false;
    bool HasPrivateMemory = false;
    bool PrivateMemory = false;
    bool HasNoChange = false;
    bool NoChange = false;
    bool HasLargePage = false;
    bool LargePage = false;
    bool HasSubsection = false;
    uint64_t Subsection = 0;
    bool PeProbeAttempted = false;
    bool PeHeaderFound = false;
    bool PeHeaderSuspicious = false;
    PeHeaderProbe PeProbe = {};
    std::wstring Classification;
    std::wstring Notes;
};

struct ProcessHiddenVadPteRecord
{
    uint64_t StartAddress = 0;
    uint64_t EndAddress = 0;
    uint64_t Size = 0;
    uint64_t PageSize = 0;
    uint64_t PageCount = 0;
    uint64_t PhysicalAddress = 0;
    uint64_t LeafEntryAddress = 0;
    uint64_t LeafEntry = 0;
    bool Writable = false;
    bool Executable = false;
    bool UserAccessible = false;
    bool LargePage = false;
    std::wstring Notes;
};

struct ProcessVadScanOptions
{
    ProcessTriageTarget Target = {};
    bool SummaryOnly = false;
    bool ExecOnly = false;
    bool PrivateOnly = false;
    bool WxOnly = false;
    bool PeOnly = false;
    bool ProbePe = false;
    bool ScanHiddenPtes = false;
    bool HiddenPteExecutableOnly = false;
    bool RequireVadCoverageForHiddenPtes = false;
    uint32_t HiddenPteLimit = 0;
    uint32_t Limit = 0;
};

struct ProcessVadScanResult
{
    ProcessTriageTarget Target = {};
    std::vector<ProcessVadRecord> Records;
    std::vector<ProcessHiddenVadPteRecord> HiddenPteRecords;
    std::vector<std::wstring> Warnings;
    uint64_t NodesVisited = 0;
    uint64_t TotalRecords = 0;
    uint64_t MatchingRecords = 0;
    uint64_t ExecutableCount = 0;
    uint64_t PrivateExecutableCount = 0;
    uint64_t WxCount = 0;
    uint64_t PeLikeCount = 0;
    uint64_t SuspiciousCount = 0;
    uint64_t PteLeafMappings = 0;
    uint64_t PageTablePagesRead = 0;
    uint64_t PageTableReadFailures = 0;
    uint64_t HiddenPteRanges = 0;
    uint64_t HiddenPteBytes = 0;
    uint64_t HiddenPteExecutableCount = 0;
    uint64_t HiddenPteWxCount = 0;
    uint32_t PagingLevels = 0;
    bool Truncated = false;
    bool HiddenPteScanEnabled = false;
    bool HiddenPteTruncated = false;
    // False when Protection/PrivateMemory metadata is missing so exec/private/PE
    // signals cannot be trusted as complete (not a clean empty result).
    bool ProtectionResolved = false;
    bool PrivateMemoryResolved = false;
    bool CoverageComplete = true;
    bool Incomplete = false;
    std::wstring LayoutSource;
};

struct ProcessApcEntryRecord
{
    uint64_t KapcAddress = 0;
    uint64_t KernelRoutine = 0;
    uint64_t RundownRoutine = 0;
    uint64_t NormalRoutine = 0;
    uint64_t NormalContext = 0;
    uint64_t SystemArgument1 = 0;
    uint64_t SystemArgument2 = 0;
    std::wstring KernelRoutineModule;
    std::wstring KernelRoutineSymbol;
    std::wstring NormalRoutineModule;
    std::wstring Notes;
    bool HasKernelRoutine = false;
    bool HasRundownRoutine = false;
    bool HasNormalRoutine = false;
    bool Suspicious = false;
};

struct ProcessApcQueueRecord
{
    std::wstring Name;
    uint64_t HeadAddress = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    uint32_t EntriesScanned = 0;
    bool Present = false;
    bool NonEmpty = false;
    bool Truncated = false;
    std::vector<ProcessApcEntryRecord> Entries;
};

struct ProcessStackReferenceRecord
{
    uint64_t StackAddress = 0;
    uint64_t Value = 0;
    std::wstring ValueModule;
    std::wstring VadClassification;
    std::wstring Notes;
    bool UserModuleEnumerationAvailable = false;
    bool ValueInUserModule = false;
    bool ValueOutsideUserModules = false;
    bool ValueInPrivateExecVad = false;
    bool ValueInWxVad = false;
    bool Suspicious = false;
};

struct ProcessThreadRecord
{
    uint64_t Ethread = 0;
    uint64_t ListEntry = 0;
    uint64_t ThreadId = 0;
    uint64_t StartAddress = 0;
    uint64_t Win32StartAddress = 0;
    uint64_t Teb = 0;
    uint64_t StackBase = 0;
    uint64_t StackLimit = 0;
    uint64_t UserStackBase = 0;
    uint64_t UserStackLimit = 0;
    std::wstring StartModule;
    std::wstring StartSymbol;
    std::wstring Win32StartModule;
    std::wstring VadClassification;
    std::wstring Notes;
    bool HasThreadId = false;
    bool HasStartAddress = false;
    bool HasWin32StartAddress = false;
    bool HasTeb = false;
    bool HasStackBounds = false;
    bool HasUserStackBounds = false;
    bool StartInUserModule = false;
    bool StartInPrivateExecVad = false;
    bool StartInWxVad = false;
    bool SuspiciousStart = false;
    std::vector<ProcessApcQueueRecord> ApcQueues;
    std::vector<ProcessStackReferenceRecord> StackReferences;
};

struct ProcessThreadScanOptions
{
    ProcessTriageTarget Target = {};
    bool IncludeApc = false;
    bool IncludeStacks = false;
    uint32_t Limit = 0;
};

struct ProcessThreadScanResult
{
    ProcessTriageTarget Target = {};
    std::vector<ProcessThreadRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t ThreadsVisited = 0;
    uint64_t MatchingRecords = 0;
    uint64_t SuspiciousStartCount = 0;
    uint64_t ApcNonEmptyCount = 0;
    uint64_t StackReferenceCount = 0;
    bool Truncated = false;
    std::wstring LayoutSource;
};

class ProcessTriageScanner
{
public:
    ProcessTriageScanner(DeviceClient& device, SymbolEngine& symbols);

    bool ScanVad(const ProcessVadScanOptions& options, ProcessVadScanResult* result, std::wstring* error);
    bool ScanThreads(const ProcessThreadScanOptions& options, ProcessThreadScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildProcessVadJson(const ProcessVadScanResult& result);
std::wstring BuildProcessThreadsJson(const ProcessThreadScanResult& result);
