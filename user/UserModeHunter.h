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

struct HuntTelemetryField
{
    std::wstring Name;
    std::wstring Value;
};

struct HuntTelemetryEvent
{
    uint64_t Timestamp = 0;
    uint32_t ProcessId = 0;
    uint32_t TargetProcessId = 0;
    uint16_t TaskId = 0;
    uint8_t Opcode = 0;
    std::wstring TaskName;
    std::wstring OpcodeName;
    std::wstring ImagePath;
    std::wstring TargetImageBase;
    std::vector<HuntTelemetryField> Payload;
    std::wstring RawPayloadHex;
};

struct HuntOptions
{
    HuntMode Mode = HuntMode::Default;
    uint32_t RenderLimit = 40;
    std::vector<SnapshotProcessRecord> Processes;
    bool ThreatIntelActive = false;
    // True when the TI collection surface was successfully available.  An
    // available ring can legitimately contain zero events on a quiet host.
    bool ThreatIntelAvailable = false;
    std::vector<HuntTelemetryEvent> ThreatIntelEvents;
    // Ring overflow / eviction count from the TI subscriber for this scan window.
    uint64_t ThreatIntelEventsDropped = 0;
    // Deep-triage these PIDs first (kmon watch set and/or !hunt /pid).
    std::vector<uint32_t> FocusPids;
    // When non-empty, skip VAD/module/hook deep triage for other PIDs.
    // Hidden/CID inventory still covers the whole system.
    std::vector<uint32_t> FilterPids;
    std::wstring MapperWatchId;
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
    bool VadSectionSeen = false;
    bool VadBackingManagedImage = false;
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
    bool ActiveProcessLinksRevalidated = false;
    bool ActiveProcessLinksStableUnlinked = false;
    bool SystemProcessInformationSeen = false;
    bool ToolhelpProcessSeen = false;
    // True when a CID lookup surface was attempted for this process.
    // CidTableEnumerated distinguishes a bounded whole process-CID inventory
    // (exported sweep or direct typed entry walk) from the legacy known-PID
    // fallback. CidDirectEntrySeen identifies the anti-hook direct view.
    bool HasCidTableView = false;
    bool CidTableSeen = false;
    bool CidDirectEntrySeen = false;
    bool CidLookupDirectAgreed = false;
    // The PID was discovered by the bounded full CID range rather than seeded
    // by ActiveProcessLinks or either user API view.
    bool CidTableEnumerated = false;
    bool CidTableDiscovered = false;
    // A second API snapshot and same-identity CID lookup completed after the
    // initial discovery. These gates suppress start/exit and PID-reuse races.
    bool CidApiViewsRevalidated = false;
    bool CidIdentityRevalidated = false;
    bool AddressContextRefreshed = false;
    bool LifecycleChangedBeforeTriage = false;
    bool HasProtection = false;
    uint8_t Protection = 0;
    std::wstring KernelImageName;
    std::wstring SystemProcessImageName;
    std::wstring ToolhelpImageName;
    std::wstring ApiImagePath;
    uint64_t PebImageBase = 0;
    bool HasPebImageBase = false;
    uint64_t MainImageBase = 0;
    uint64_t MainImageSize = 0;
    uint64_t MainImageVad = 0;
    uint64_t MainSectionObject = 0;
    uint64_t MainSectionSegment = 0;
    uint64_t MainSectionControlArea = 0;
    std::wstring MainSectionBackingPath;
    std::wstring MainSectionBackingState;
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
    uint64_t PageTablePagesRead = 0;
    uint64_t PageTableReadFailures = 0;
    uint32_t PagingLevels = 0;
    uint32_t VadScanAttempts = 0;
    uint32_t ThreadScanAttempts = 0;
    uint64_t ThreadsVisited = 0;
    uint64_t SuspensionStateResolvedThreads = 0;
    uint64_t SuspendedThreads = 0;
    uint64_t SuspiciousThreadStarts = 0;
    uint64_t NonEmptyApcQueues = 0;
    uint64_t StackReferenceCount = 0;
    bool ThreadInventoryComplete = false;
    bool ThreadSuspensionStateCoverageComplete = false;
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

struct HuntCloudFileImageRecord
{
    uint32_t ProcessId = 0;
    uint64_t ModuleBase = 0;
    uint64_t ModuleSize = 0;
    std::wstring ImageName;
    std::wstring ModuleName;
    std::wstring VadBackingPath;
    std::wstring NormalizedBackingPath;
    uint32_t FileAttributes = 0;
    uint32_t ReparseTag = 0;
    uint32_t PlaceholderState = 0;
    uint32_t PinState = 0;
    uint32_t InSyncState = 0;
    uint32_t PlaceholderInfoQueryStatus = 0;
    int64_t OnDiskDataSize = 0;
    int64_t ValidatedDataSize = 0;
    int64_t ModifiedDataSize = 0;
    int64_t PropertiesSize = 0;
    uint32_t FileIdentityLength = 0;
    bool CloudReparseTagObserved = false;
    bool PlaceholderInfoIdentificationFallbackUsed = false;
    bool ProcessProtectionResolved = false;
    uint8_t ProcessProtection = 0;
    bool DeepMismatchCorrelated = false;
    bool Suspicious = false;
    std::vector<std::wstring> Reasons;
};

struct HuntCidThreadRecord
{
    uint32_t ThreadId = 0;
    uint32_t ProcessId = 0;
    uint64_t ObjectHeader = 0;
    uint64_t Ethread = 0;
    uint64_t Eprocess = 0;
    uint64_t CreateTime = 0;
    uint64_t ExitTime = 0;
    bool HasCreateTime = false;
    bool HasExitTime = false;
    bool Terminated = false;
    bool DirectCidSeen = false;
    bool ExecutiveThreadListSeen = false;
    bool SchedulerThreadListSeen = false;
    bool SystemProcessInformationSeen = false;
    bool ToolhelpThreadSeen = false;
    bool IdentityRevalidated = false;
    bool ViewsRevalidated = false;
    bool LifecycleChanged = false;
    bool Suspicious = false;
    std::vector<std::wstring> Reasons;
    std::vector<std::wstring> Warnings;
};

struct HuntResult
{
    std::wstring Schema;
    std::wstring TimestampUtc;
    std::wstring ModeText;
    std::wstring MapperWatchId;
    std::vector<HuntProcessRecord> Processes;
    std::vector<HuntFinding> Findings;
    std::vector<HuntCloudFileImageRecord> CloudFileImages;
    std::vector<HuntCidThreadRecord> CidThreads;
    std::vector<std::wstring> Warnings;
    uint64_t KernelProcessCount = 0;
    uint64_t SystemProcessInfoCount = 0;
    uint64_t ToolhelpProcessCount = 0;
    uint64_t SystemProcessInfoThreadCount = 0;
    uint64_t ToolhelpThreadCount = 0;
    uint64_t ScannedProcessCount = 0;
    uint64_t VadRecordCount = 0;
    uint64_t HiddenPteRangeCount = 0;
    uint64_t ThreadRecordCount = 0;
    uint64_t ModuleRecordCount = 0;
    uint64_t KernelModuleCount = 0;
    uint64_t ByovdMatchedDriverCount = 0;
    uint64_t DriverObjectCount = 0;
    uint64_t SuspiciousDriverObjectCount = 0;
    uint64_t DriverServiceCount = 0;
    uint64_t EdrKillerDriverServiceCount = 0;
    // The SCM driver-service inventory could not be enumerated to completion.
    // A zero IOC count is not a whole-host clean result when this is true.
    bool DriverServiceCoverageIncomplete = false;
    uint64_t WfpFilterCount = 0;
    uint64_t SuspiciousWfpFilterCount = 0;
    bool WfpFilterCoverageIncomplete = false;
    uint64_t QosPolicyCount = 0;
    uint64_t SuspiciousQosPolicyCount = 0;
    bool QosPolicyCoverageIncomplete = false;
    uint64_t BindFilterMappingCount = 0;
    uint64_t SuspiciousBindFilterMappingCount = 0;
    uint64_t BindFilterProcessBindingCount = 0;
    bool BindFilterGlobalCoverageIncomplete = false;
    // A process matched the visible side of a high-signal global mapping, but
    // both the EPROCESS main-section and main-image VAD backing paths were not
    // resolved. An empty Process-Binding result is not clean proof when true.
    bool BindFilterProcessCorrelationCoverageIncomplete = false;
    bool BindFilterSiloCoverageUnsupported = true;
    uint64_t CloudFilePlaceholderImageCount = 0;
    uint64_t SuspiciousCloudFileImageCount = 0;
    bool CloudFilePlaceholderCoverageIncomplete = false;
    bool CloudFileProtectionCorrelationIncomplete = false;
    bool ThreatIntelActive = false;
    bool ThreatIntelAvailable = false;
    // Deep-mode TI correlation could not observe a usable collection surface,
    // or the ring dropped events.
    bool ThreatIntelCorrelationIncomplete = false;
    // Kernel ActiveProcessLinks inventory was partial (poisoned nodes skipped
    // or walk stopped early). Findings must not be read as whole-system clean.
    bool ProcessInventoryIncomplete = false;
    // Direct typed process/thread CID state. The whole-table flag is true only
    // when direct entry typing, both object classes, and the thread cross-view
    // all complete.
    bool CidTableFullEnumeration = false;
    bool CidTableFullProcessEnumeration = false;
    bool CidTableDirectEntryEnumeration = false;
    bool CidTableFullThreadEnumeration = false;
    bool CidTableThreadCrossViewComplete = false;
    bool CidTableLookupOnly = true;
    uint64_t CidTableAnchorAddress = 0;
    uint64_t CidTableAddress = 0;
    uint64_t CidTableCode = 0;
    uint32_t CidTableLevel = 0;
    uint32_t CidTableNextHandle = 0;
    uint32_t CidTableAllocatedLeafCount = 0;
    uint64_t CidTableAllocatedHandleCapacity = 0;
    uint64_t CidTableProbeCount = 0;
    uint64_t CidTableProcessCount = 0;
    uint64_t CidTableDiscoveredProcessCount = 0;
    uint64_t CidTableDirectEntryCount = 0;
    uint64_t CidTableDirectProcessCount = 0;
    uint64_t CidTableDirectThreadCount = 0;
    uint64_t CidTableUnclassifiedEntryCount = 0;
    uint64_t CidTableThreadFindingCount = 0;
    uint64_t CidTablePersistentThreadViewMissCount = 0;
    uint64_t CidTableProbeFailureCount = 0;
    uint64_t CidTablePersistentApiMissCount = 0;
    // VAD / hidden-PTE / thread collection surfaces reported incompleteness.
    bool ProcessTriageCoverageIncomplete = false;
    // Deep live-vs-disk comparison rejected a required relocation structure
    // or could not normalize an intended comparison page safely.
    bool DeepImageComparisonCoverageIncomplete = false;
    // Aggregate coverage flag: false when any critical collection surface was
    // incomplete (process inventory, TI drops, triage truncation, etc.).
    bool CoverageComplete = true;
    uint64_t ThreatIntelEventCount = 0;
    uint64_t ThreatIntelCorrelationCount = 0;
    uint64_t HighFindings = 0;
    uint64_t MediumFindings = 0;
    uint64_t LowFindings = 0;
    uint64_t InfoFindings = 0;
};

class UserModeHunter
{
public:
    UserModeHunter(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::wstring& executableDirectory);

    bool Scan(const HuntOptions& options, HuntResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
    std::wstring executableDirectory_;
};

std::wstring HuntModeToText(HuntMode mode);
std::wstring HuntFirstCommandLineImage(const std::wstring& commandLine);
bool HuntProcessLifecycleSelfTest();
bool HuntInjectedModuleSelfTest();
bool HuntInProcessHookSelfTest();
bool HuntCidTableAnchorSelfTest();
bool EnumerateCidProcessIds(
    DeviceClient& device,
    SymbolEngine& symbols,
    std::vector<uint32_t>* processIds,
    std::wstring* warning,
    bool* complete);
bool HuntDiskPeBoundsSelfTest();
bool HuntBaseRelocationMaskSelfTest();
bool HuntDynamicRelocationMaskSelfTest();
bool HuntEffectiveVadProtectionSelfTest();
bool HuntEdrKillerProfileSelfTest();
bool HuntManagedLoaderlessMappingSelfTest();
bool HuntSecurityProcessFreezeSelfTest();
bool HuntWfpPolicySelfTest();
bool HuntQosPolicySelfTest();
bool HuntBindFilterMappingSelfTest();
bool HuntCloudFilePlaceholderSelfTest();
std::wstring BuildHuntJson(const HuntResult& result);
