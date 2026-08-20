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
    uint64_t CreateTime = 0;
    bool     HasCreateTime = false;
    std::wstring ImageName;
};

struct ProcessUserModuleRange
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    std::wstring ImageName;
    std::wstring ImagePath;
};

struct ProcessVadProtectionRange
{
    uint64_t StartAddress = 0;
    uint64_t EndAddress = 0;
    uint32_t Protection = 0;
    uint32_t Type = 0;
    bool Committed = false;
    bool Executable = false;
    bool Writable = false;
    bool CopyOnWrite = false;
    bool WritableExecutable = false;
    bool CopyOnWriteExecutable = false;
};

bool ProcessTriageEffectiveProtectionSelfTest();

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
    // VAD Protection is the allocation/default protection and can remain RW
    // after VirtualProtect turns committed pages into RX.  When available,
    // these fields summarize the current VirtualQueryEx view across the VAD.
    bool EffectiveProtectionQueried = false;
    bool EffectiveProtectionComplete = false;
    bool WritableExecutable = false;
    bool CopyOnWriteExecutable = false;
    uint64_t EffectiveCommittedBytes = 0;
    uint64_t EffectiveExecutableBytes = 0;
    uint64_t EffectiveWritableBytes = 0;
    uint64_t EffectiveCopyOnWriteBytes = 0;
    uint64_t EffectiveWritableExecutableBytes = 0;
    uint64_t EffectiveCopyOnWriteExecutableBytes = 0;
    bool EffectiveImageMapping = false;
    std::wstring EffectiveProtectionText;
    std::vector<ProcessVadProtectionRange> EffectiveProtectionRanges;
    bool HasPrivateMemory = false;
    bool PrivateMemory = false;
    bool HasNoChange = false;
    bool NoChange = false;
    bool HasLargePage = false;
    bool LargePage = false;
    bool HasSubsection = false;
    uint64_t Subsection = 0;
    bool HasControlArea = false;
    uint64_t ControlArea = 0;
    uint64_t FileObject = 0;
    uint32_t MappedViews = 0;
    std::wstring SectionFileName;
    bool PeProbeAttempted = false;
    bool PeProbeReadSucceeded = false;
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
    // Probe every plausible image-backed or executable-private mapping rather
    // than only legacy private-VAD candidates. Used by the mapped-PE inventory.
    bool ProbeAllPe = false;
    // Compose private executable, W+X, PE/manual-map, large executable, and
    // hidden executable-PTE evidence into one target scan.
    bool InjectionScan = false;
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
    bool EffectiveProtectionCoverageComplete = false;
    bool CoverageComplete = true;
    bool Incomplete = false;
    bool InjectionScan = false;
    std::wstring LayoutSource;
};

struct ProcessMappedPeRecord
{
    uint64_t Base = 0;
    uint64_t LoaderSize = 0;
    uint64_t VadAddress = 0;
    uint64_t VadStart = 0;
    uint64_t VadEnd = 0;
    uint64_t VadSize = 0;
    uint64_t HeaderImageSize = 0;
    uint64_t PreferredImageBase = 0;
    uint64_t EntryPointVa = 0;
    uint32_t EntryPointRva = 0;
    uint32_t SizeOfHeaders = 0;
    uint32_t TimeDateStamp = 0;
    uint16_t Machine = 0;
    uint16_t NumberOfSections = 0;
    std::wstring ImageName;
    std::wstring ImagePath;
    std::wstring MappedPath;
    std::wstring AllocationProtection;
    std::wstring EffectiveProtection;
    bool LoaderVisible = false;
    bool VadVisible = false;
    bool HeaderProbeAttempted = false;
    bool HeaderProbeReadSucceeded = false;
    bool MemoryHeaderVisible = false;
    bool MappedPathVisible = false;
    bool VirtualImageMapping = false;
    bool PrivateMapping = false;
    bool ImageBacked = false;
    bool Executable = false;
    bool WritableExecutable = false;
    bool Is64Bit = false;
    bool MzWiped = false;
    bool PeSignatureWiped = false;
    bool ELfanewMismatch = false;
    bool EntryPointValid = false;
    bool Suspicious = false;
    std::vector<std::wstring> Sources;
    std::vector<std::wstring> Reasons;
};

struct ProcessMappedPeScanOptions
{
    ProcessTriageTarget Target = {};
    uint32_t Limit = 0;
};

struct ProcessMappedPeScanResult
{
    ProcessTriageTarget Target = {};
    std::vector<ProcessMappedPeRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t VadNodesVisited = 0;
    uint64_t VadRecords = 0;
    uint64_t LoaderRecords = 0;
    uint64_t CandidateMappings = 0;
    uint64_t HeaderVisibleRecords = 0;
    uint64_t LoaderVisibleRecords = 0;
    uint64_t MemoryOnlyRecords = 0;
    uint64_t PrivateRecords = 0;
    uint64_t SuspiciousRecords = 0;
    bool VadCoverageComplete = false;
    bool LoaderCoverageComplete = false;
    bool HeaderProbeCoverageComplete = false;
    bool MappedPathCoverageComplete = false;
    bool CoverageComplete = false;
    bool Incomplete = false;
    bool Truncated = false;
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
    uint64_t UserRoutine = 0;
    std::wstring KernelRoutineModule;
    std::wstring KernelRoutineSymbol;
    std::wstring NormalRoutineModule;
    std::wstring NormalRoutineVadClassification;
    std::wstring UserRoutineSource;
    std::wstring UserRoutineModule;
    std::wstring UserRoutineVadClassification;
    std::wstring Notes;
    bool HasKernelRoutine = false;
    bool HasRundownRoutine = false;
    bool HasNormalRoutine = false;
    bool NormalRoutineInPrivateExecVad = false;
    bool NormalRoutineInWxVad = false;
    bool UserRoutineInPrivateExecVad = false;
    bool UserRoutineInWxVad = false;
    bool Suspicious = false;
};

struct ProcessApcQueueRecord
{
    std::wstring Name;
    uint64_t HeadAddress = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    uint32_t EntriesScanned = 0;
    std::wstring Notes;
    bool Present = false;
    bool NonEmpty = false;
    bool Truncated = false;
    bool Incomplete = false;
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
    uint32_t SuspendCount = 0;
    uint32_t FreezeCount = 0;
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
    bool HasSuspendCount = false;
    bool HasFreezeCount = false;
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
    // Hunt can provide its independently collected PEB/Toolhelp union so
    // protected processes do not lose module provenance merely because a
    // second Toolhelp snapshot is denied.
    std::vector<ProcessUserModuleRange> UserModules;
    bool UserModuleEnumerationComplete = false;
    bool IncludeApc = false;
    bool IncludeStacks = false;
    // Hunt enables this only for known security-product processes. A missing
    // suspend/freeze field or read then participates in retry/incomplete
    // coverage instead of being treated as unrelated thread telemetry.
    bool RequireSuspensionCoverage = false;
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
    uint64_t SuspensionStateResolvedCount = 0;
    uint64_t SuspendedThreadCount = 0;
    uint64_t ApcNonEmptyCount = 0;
    uint64_t StackReferenceCount = 0;
    bool Truncated = false;
    // True when the walk stopped early due to poisoned links, cycles, or
    // unreadable entries (not a clean complete thread inventory).
    bool Incomplete = false;
    bool CoverageComplete = true;
    // Independent from VAD/module correlation coverage. This proves that the
    // EPROCESS thread list itself was walked to a stable tail.
    bool InventoryComplete = false;
    // True only when both suspend and freeze fields were resolved and read for
    // every visited thread retained by an uncapped inventory.
    bool SuspensionStateCoverageComplete = false;
    std::wstring LayoutSource;
};

class ProcessTriageScanner
{
public:
    ProcessTriageScanner(DeviceClient& device, SymbolEngine& symbols);

    bool ScanVad(const ProcessVadScanOptions& options, ProcessVadScanResult* result, std::wstring* error);
    bool ScanMappedPe(const ProcessMappedPeScanOptions& options, ProcessMappedPeScanResult* result, std::wstring* error);
    bool ScanThreads(const ProcessThreadScanOptions& options, ProcessThreadScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildProcessVadJson(const ProcessVadScanResult& result);
std::wstring BuildProcessMappedPeJson(const ProcessMappedPeScanResult& result);
std::wstring BuildProcessThreadsJson(const ProcessThreadScanResult& result);

bool ProcessTriageVadTraversalSelfTest();
bool ProcessTriageVadFilterSelfTest();
bool ProcessTriageMappedPeSelfTest();
