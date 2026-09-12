#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "ThreatIntelSubscriber.h"
#include "TimelineStore.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct KmonOptions
{
    std::vector<uint32_t> WatchPids;
    std::vector<std::wstring> WatchNames;
    std::vector<std::wstring> WatchDrivers;
    uint32_t ThrottlePerSecond = 50;
    uint32_t RingCapacity = 65536;
    std::wstring LogDirectory;
    // Root for on-disk scanner data (data\byovd\...); under --cloak the
    // process runs from a %TEMP% copy without the data tree, so main.cpp
    // anchors this to the original exe folder like LogDirectory.
    std::wstring DataDirectory;
    uint32_t HiddenScanIntervalMs = 5000;
    uint32_t MapperScanIntervalMs = 8000;
    bool VerboseDrivers = false;
    bool AttachLiveTail = true;
};

struct KmonEvent
{
    uint64_t Sequence = 0;
    uint64_t Timestamp = 0;
    std::wstring Kind;
    uint32_t ProcessId = 0;
    uint32_t TargetProcessId = 0;
    std::wstring Image;
    std::wstring TargetImage;
    std::wstring Driver;
    std::wstring Task;
    std::wstring Summary;
    std::map<std::wstring, std::wstring> Evidence;
};

// Returns full paths of files in <directory> whose leaf name starts with
// <prefix> and ends with <suffix>. Missing directory yields an empty list.
std::vector<std::wstring> KmonFindFilesWithPattern(
    const std::wstring& directory,
    const std::wstring& prefix,
    const std::wstring& suffix);

struct KmonStats
{
    uint64_t EventsKept = 0;
    uint64_t EventsDropped = 0;
    uint64_t EventsLogged = 0;
    uint64_t EventsWatchMatched = 0;
    uint64_t TiIngested = 0;
    uint64_t LiveIngested = 0;
    uint64_t HiddenScans = 0;
    uint64_t MapperScans = 0;
    uint64_t PoolPeScans = 0;
    uint64_t KpageScans = 0;
    uint64_t HookScans = 0;
    uint64_t CpuHookScans = 0;
    uint64_t UserHostilityScans = 0;
    uint64_t MapperWatchArmed = 0;
    uint64_t MapperWatchScans = 0;
    uint64_t MapperWatchRemainMs = 0;
    std::wstring MapperWatchDriver;
    std::wstring MapperWatchId;
    uint64_t LoggingEnabled = 0;
    uint64_t LoggingFailed = 0;
    uint64_t LogBytesWritten = 0;
    uint32_t LogRotations = 0;
    uint64_t StartTickMs = 0;
    uint64_t LastEventTickMs = 0;
};

// P1: post-load identity baseline for a loaded driver image. The image head
// and entry point hashes plus the DRIVER_OBJECT identity fields are captured
// when the load is observed; a later mismatch is driver.tampered. Fail-closed:
// a field that was never captured never produces a verdict, and an image that
// cannot be read only defers the check.
struct KmonDriverIdentitySnapshot
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    uint64_t HeaderHash = 0;
    uint64_t EntryHash = 0;
    uint64_t EntryOffset = 0;
    uint64_t DriverStart = 0;
    uint64_t DriverSize = 0;
    uint64_t DriverSection = 0;
    uint64_t DeviceObject = 0;
    bool HasImage = false;
    bool HasFields = false;
};

enum KmonTamperMask : uint32_t
{
    KmonTamperNone = 0,
    KmonTamperImage = 1u << 0,
    KmonTamperFields = 1u << 1,
};

uint64_t KmonHashBytes64(const uint8_t* data, size_t size);

// Returns the subset of KmonTamperMask that the live snapshot contradicts.
// Pure so the self-test can drive it with synthetic snapshots.
uint32_t KmonDriverTamperMask(
    const KmonDriverIdentitySnapshot& baseline,
    const KmonDriverIdentitySnapshot& live);

// P1 cross-view: PsLoadedModuleList still reports a driver while another view
// of it (its service key, its image file on disk) does not. Both views must be
// definitive before a verdict; an unavailable view only defers the check.
enum class KmonEvidenceAsymmetryKind
{
    None = 0,
    NoServiceKey,
    NoImageFile,
    NoServiceKeyNoImageFile,
};

// Pure decision function over the two view results, so the self-test can drive
// every combination without a live kernel.
KmonEvidenceAsymmetryKind KmonClassifyEvidenceAsymmetry(
    bool serviceKeyKnown,
    bool serviceKeyExists,
    bool imageFileKnown,
    bool imageFileExists,
    bool imagePathInbox);
const wchar_t* KmonEvidenceAsymmetryReason(KmonEvidenceAsymmetryKind kind);
// \Windows\System32 holds the keyless core images Windows always has loaded.
bool KmonImagePathIsInbox(const std::wstring& win32Path);

// R4: the service-key-only verdict is the noisy one. A non-inbox loader that
// lost its service key alone is ordinary on its own (a driver uninstalled while
// still resident), so it is reported only when another confirmed post-load
// hiding signal names the same image stem. The verdicts that already require
// the image file to be gone are unaffected.
bool KmonEvidenceAsymmetryIsReportable(
    KmonEvidenceAsymmetryKind kind,
    bool corroborated);
// Which independent signal names this stem: a fixed-order, '+'-joined source
// list, empty when nothing corroborates. Callers pass stems, not paths.
std::wstring KmonEvidenceAsymmetryCorroboration(
    const std::wstring& stem,
    const std::set<std::wstring>& divergenceStems,
    const std::set<std::wstring>& chainBreakStems,
    const std::set<std::wstring>& tamperStems);

enum class KmonModuleDiffKind
{
    None = 0,
    Vanished,
    UnnotifiedLoad,
    Remap,
};

class KernelMonitor
{
public:
    KernelMonitor();
    ~KernelMonitor();

    KernelMonitor(const KernelMonitor&) = delete;
    KernelMonitor& operator=(const KernelMonitor&) = delete;

    bool Start(
        const KmonOptions& options,
        TiSubscriber* ti,
        TimelineStore* timeline,
        DeviceClient* device,
        SymbolEngine* symbols,
        std::wstring* error);
    bool Stop(std::wstring* error);
    bool IsActive() const;

    // Session artifact inventory for the exit summary: kmon log files for
    // this process id (all rotations) and every capture written this
    // session. Empty when kmon never started.
    std::vector<std::wstring> SessionLogPaths() const;
    std::vector<std::wstring> SessionCapturePaths() const;

    bool AddWatchPid(uint32_t pid);
    bool RemoveWatchPid(uint32_t pid);
    bool AddWatchName(const std::wstring& imageBase);
    bool RemoveWatchName(const std::wstring& imageBase);
    bool AddWatchDriver(const std::wstring& driverBase);
    bool RemoveWatchDriver(const std::wstring& driverBase);

    bool ArmIotrace(uint64_t driverObjectAddress, const std::wstring& driverName, std::wstring* error);
    bool DisarmIotrace(std::wstring* error);
    bool IotraceArmed() const;

    void SetLiveOutput(bool enabled);
    bool IsLiveOutputEnabled() const;

    std::vector<KmonEvent> Recent(size_t maxCount, bool newestFirst) const;
    bool SaveTo(const std::wstring& path, std::wstring* error) const;
    void Clear();

    std::vector<KmonEvent> DrainPrintQueue(size_t maxCount);
    uint64_t ConsumeThrottleSuppressedCount();

    KmonStats SnapshotStats() const;
    KmonOptions CurrentOptions() const;
    bool IsMapperWatchActive() const;
    std::vector<uint32_t> SnapshotWatchPids() const;
    std::wstring SnapshotMapperWatchId() const;
    std::vector<uint64_t> SnapshotResiduePfns() const;

private:
    void WorkerLoop();
    void IngestThreatIntel();
    void IngestLiveTimeline();
    void NoteCredscanRead(
        const struct TiEventRecord& record,
        DeviceClient* device,
        SymbolEngine* symbols);
    // Auto-capture turns a mapper/user-mode detection into preserved
    // evidence: both the Berkan kernel arena and its explorer stub pages
    // were detected while resident but lost before a human could dump.
    // Returns an evidence note (" capture=<path> capture_bytes=<n>") on
    // success. Worker thread context.
    bool CaptureRegion(
        const wchar_t* layer,
        uint64_t address,
        uint64_t sizeBytes,
        uint32_t processId,
        bool userMode,
        DeviceClient* device,
        SymbolEngine* symbols,
        HANDLE processHandle,
        uint64_t maxBytes,
        std::wstring* captureNote);
    void ScanHiddenProcesses();
    void ScanMapperRemnants();
    void ScanPoolMappedImages();
    void ScanUnbackedDriverObjects();
    // P0: baseline/diff of the loaded kernel module inventory that
    // NtQuerySystemInformation reports (the PsLoadedModuleList view).
    void ScanModuleInventory();
    void ScanOrphanMappedPages();
    void ScanHookCallbacks();
    // dxgkrnl/GPU kernel driver writable data sections: per-adapter DDI
    // dispatch tables that no callback/FastIo/IDT scan reaches.
    void ScanGraphicsDispatchTables();
    void ScanHookInput();
    void ScanCpuIntegrityHooks();
    void ScanHookDataPointers();
    void ScanUserModeHostility();
    void NoteMapperWatchResidue(const std::wstring& layer, uint64_t physicalAddress);
    void NoteWatchTiWriteIfNeeded(const KmonEvent& event);
    bool GetLiveTargets(DeviceClient** device, SymbolEngine** symbols) const;
    void EmitUnique(
        const std::wstring& kind,
        const std::wstring& key,
        const std::wstring& driver,
        const std::wstring& layer,
        const std::wstring& summary,
        const std::wstring& notes,
        uint32_t processId = 0);
    void EmitMappedResidue(
        const std::wstring& key,
        const std::wstring& driver,
        const std::wstring& layer,
        const std::wstring& summary,
        const std::wstring& notes);
    std::wstring MakeEmittedKey(const std::wstring& key, uint32_t processId) const;
    void ClearEmittedKey(const std::wstring& key);
    void ClearEmittedKeyForPid(const std::wstring& key, uint32_t processId);
    void NoteDriverLoad(const KmonEvent& event);
    // P0: remember a lifecycle unload so the module diff does not report a
    // legitimate unload as a hiding event.
    void NoteDriverUnload(const KmonEvent& event);
    void ArmMapperWatch(const KmonEvent& event);
    void MaybeEmitShortLived(const KmonEvent& unloadEvent);
    void EnableLoggingForPid(uint32_t pid);
    bool NoteWatchActivityTask(uint32_t pid, const std::wstring& task);
    void ScanWatchedHandleTables();
    void DrainIotraceEvents();
    void PromoteNamedWatchPid(uint32_t pid);
    void EnableLoggingForWatchTargets();
    void PruneStalePromotedWatches();
    bool ResolveKernelImageName(uint32_t pid, std::wstring* name);
    void RecordEvent(KmonEvent&& event);
    bool WriteLogLine(const KmonEvent& event);
    void EnqueuePrint(KmonEvent&& event);
    bool EnsureLogOpenLocked();
    void CloseLogLocked();
    void RotateLogLocked();
    std::wstring BuildLogFilePath(int rotationIndex) const;

    mutable std::mutex StateMutex;
    KmonOptions Options;
    std::atomic<bool> Active{false};
    std::atomic<bool> StopRequested{false};
    std::thread Worker;

    TiSubscriber* Ti = nullptr;
    TimelineStore* Timeline = nullptr;
    DeviceClient* Device = nullptr;
    SymbolEngine* Symbols = nullptr;

    mutable std::mutex WatchMutex;
    std::unordered_set<uint32_t> WatchPids;
    std::unordered_set<uint32_t> WatchExplicitPids;
    std::vector<std::wstring> WatchNamesLower;
    std::vector<std::wstring> WatchDriversLower;
    std::unordered_set<uint32_t> WatchPromotedPids;
    std::unordered_map<uint32_t, uint64_t> WatchPromotedCreated;
    // Descendants of watched processes (loader -> 2nd stage) that were
    // auto-promoted; child pid -> parent pid. Pruned on liveness, not by
    // watch-name re-enumeration, so differently-named stages stay watched.
    std::unordered_map<uint32_t, uint32_t> WatchChildPids;
    // First-seen TI task names per watched pid backing loader.activity.
    std::unordered_map<uint32_t, std::unordered_set<std::wstring>> WatchActivityTasks;
    // Handle-table diff state for watched pids: pid -> known (handle,object)
    // pairs. First pass per pid is a silent baseline; later passes emit
    // driver.handle for new Device-typed handles.
    std::map<uint32_t, std::set<std::pair<uint64_t, uint64_t>>> WatchKnownHandles;
    uint32_t WatchDeviceTypeIndex = 0;
    bool WatchDeviceTypeKnown = false;
    // Iotrace state (guard with WatchMutex): armed flag for the worker
    // drain loop, target name for evidence, and first-seen (pid, ioctl)
    // pairs so the tail shows the traffic shape without a firehose.
    bool IotraceActive = false;
    std::wstring IotraceDriverName;
    std::set<std::pair<uint32_t, uint64_t>> IotraceSeen;
    bool IotraceSeenCapNoted = false;
    std::unordered_map<uint32_t, uint64_t> LoggingEnabledPids;
    std::unordered_map<uint32_t, uint64_t> LoggingFailedPids;
    std::map<uint32_t, uint64_t> RecentCreatePids;
    std::unordered_set<uint32_t> EmittedUnnamedPids;
    std::unordered_set<std::wstring> EmittedMapperKeys;
    struct RecentDriverLoad
    {
        std::wstring Base;
        std::wstring Path;
        std::wstring PathClass;
        uint64_t Timestamp = 0;
    };
    std::deque<RecentDriverLoad> RecentLoads;
    // P0 module inventory baseline. ModuleBaselineValid false means no
    // baseline was captured yet; the first scan after that only records the
    // baseline and never emits.
    struct ModuleInventoryEntry
    {
        std::wstring Name;
        uint64_t Base = 0;
        uint64_t Size = 0;
    };
    std::vector<ModuleInventoryEntry> ModuleBaseline;
    bool ModuleBaselineValid = false;
    uint64_t ModuleBaselineTickMs = 0;
    // P1 cross-view cursor: the service-key/image-file probe rotates over the
    // module list so no single scan tick pays for every module.
    uint64_t EvidenceAsymmetryCursor = 0;
    void ScanDriverEvidenceAsymmetry(
        const std::vector<std::pair<std::wstring, std::wstring>>& modules,
        const std::set<std::wstring>& divergenceStems,
        const std::set<std::wstring>& chainBreakStems,
        const std::set<std::wstring>& tamperStems);
    // Lifecycle unload correlation window for the module diff.
    struct RecentDriverUnload
    {
        std::wstring Base;
        uint64_t Timestamp = 0;
    };
    std::deque<RecentDriverUnload> RecentUnloads;
    // P1 driver tamper baselines, keyed by image stem. Populated when a load
    // event is observed; the DRIVER_OBJECT walk merges in the identity fields
    // on first sight and compares them on every later pass. Worker thread
    // only; guarded by WatchMutex.
    std::map<std::wstring, KmonDriverIdentitySnapshot> DriverTamperBaselines;
    std::map<std::wstring, uint32_t> DriverTamperStrikes;
    std::map<std::wstring, uint64_t> DriverTamperLastCheckMs;
    std::vector<std::wstring> DriverTamperOrder;
    uint64_t DriverTamperCursor = 0;
    uint64_t DriverTamperChecks = 0;
    void ScanDriverTamper();
    bool RecordDriverImageBaseline(
        const std::wstring& stem,
        uint64_t base,
        uint64_t size,
        DeviceClient* device);
    // Two-scan confirmation so a transient enumeration race cannot print a
    // hiding verdict. Key is "<kind>:<basename>".
    // Anomaly memory for the module diff. The accepted baseline advances on
    // every scan, so a persistent anomaly (a module that stays gone) is
    // re-confirmed from here instead of from the per-scan diff, which would
    // report it only once.
    struct PendingModuleAnomaly
    {
        KmonModuleDiffKind Kind = KmonModuleDiffKind::None;
        std::wstring Name;
        uint64_t Base = 0;
        uint64_t Size = 0;
        uint64_t PreviousBase = 0;
        uint32_t Strikes = 0;
    };
    std::map<std::wstring, PendingModuleAnomaly> ModulePending;
    uint64_t ModuleScans = 0;
    // R1/R2: two-scan confirmation for the kernel-context cross-view and the
    // loader link integrity, so a load/unload race inside one scan can neither
    // print a verdict nor corroborate the host-side diff.
    std::map<std::wstring, uint32_t> KernelViewPending;
    uint64_t NextKernelViewScanTickMs = 0;
    // P0 follow-up: the driver object type-list sweep costs a chain walk plus
    // one read per unknown candidate, so it runs on its own cadence and only
    // speeds up inside a mapper watch window.
    uint64_t NextTypeListScanTickMs = 0;
    struct MapperWatchFingerprint
    {
        std::unordered_set<std::wstring> Unloaded;
        std::unordered_set<std::wstring> Piddb;
        std::unordered_set<std::wstring> Hash;
        uint32_t PiddbElementCount = 0;
        uint32_t UnloadedSlotCount = 0;
        bool PiddbTruncated = false;
        bool HashTruncated = false;
        bool Complete = false;
    };
    MapperWatchFingerprint MapperWatchLast;
    std::wstring MapperWatchDriver;
    std::wstring MapperWatchId;
    std::unordered_map<std::wstring, uint64_t> MapperWatchEmitTick;
    std::atomic<uint64_t> MapperWatchUntilMs{0};
    std::atomic<uint64_t> MapperWatchOriginMs{0};
    std::atomic<bool> MapperWatchDeepPfnPending{false};
    bool MapperWatchHasResidue = false;
    bool MapperWatchHasOverlaySlot = false;
    std::unordered_set<uint32_t> MapperWatchTiWritePids;
    std::unordered_set<uint64_t> MapperWatchResiduePfns;

    struct CfgDataPtrSite
    {
        uint64_t SlotVa = 0;
        std::wstring ModuleLeaf;
    };
    std::vector<CfgDataPtrSite> CfgDataPtrSites;
    uint64_t CfgDataPtrNtosBase = 0;

    mutable std::mutex RingMutex;
    std::deque<KmonEvent> Ring;
    uint64_t NextSequence = 1;

    mutable std::mutex PrintMutex;
    std::deque<KmonEvent> PrintQueue;
    std::atomic<bool> LiveOutput{false};
    std::atomic<uint64_t> ThrottleWindowStartMs{0};
    std::atomic<uint32_t> ThrottleWindowCount{0};
    std::atomic<uint64_t> ThrottleSuppressed{0};

    mutable std::mutex LogMutex;
    HANDLE LogHandle = INVALID_HANDLE_VALUE;
    uint64_t LogCurrentBytes = 0;
    std::wstring LogActivePath;
    int LogActiveRotation = 0;
    uint64_t LogRotateBytes = 100ull * 1024ull * 1024ull;
    uint32_t LogRotateCount = 5;
    uint64_t LogLastFlushTickMs = 0;

    // Sustained lsass remote-read tracking (process.credscan). Keyed by the
    // (caller pid << 32 | target pid) pair so a scraper interleaving two
    // targets cannot reset its own window. Worker thread only; reset on
    // Start().
    struct KmonCredscanWindow
    {
        uint64_t Count = 0;
        uint64_t WindowStartMs = 0;
        bool Emitted = false;
    };
    std::map<uint64_t, KmonCredscanWindow> CredscanWindows;

    // TI caller/target image resolution cache, keyed by pid plus the
    // event's own image basename when present: the console-write flood
    // re-resolved the same pid through kernel queries thousands of times
    // and starved driver-lifecycle ingest, while a bare pid key would
    // misattribute after pid reuse. Worker thread only; reset on Start().
    std::map<std::wstring, std::wstring> TiResolvedImageCache;
    std::map<std::wstring, uint64_t> TiResolvedImageTickMs;

    // Detection-time evidence capture state: per-session (layer, address)
    // dedupe plus a byte budget so auto-capture can never fill the disk.
    // Guarded by CapturesMutex; reset on Start().
    mutable std::mutex CapturesMutex;
    std::set<std::wstring> CapturedKeys;
    std::vector<std::wstring> CapturedFiles;
    uint64_t CapturedBytes = 0;

    std::atomic<uint64_t> EventsKept{0};
    std::atomic<uint64_t> EventsDropped{0};
    std::atomic<uint64_t> EventsLogged{0};
    std::atomic<uint64_t> EventsWatchMatched{0};
    std::atomic<uint64_t> TiIngested{0};
    std::atomic<uint64_t> LiveIngested{0};
    std::atomic<uint64_t> HiddenScans{0};
    std::atomic<uint64_t> MapperScans{0};
    std::atomic<uint64_t> PoolPeScans{0};
    std::atomic<uint64_t> KpageScans{0};
    std::atomic<uint64_t> HookScans{0};
    std::atomic<uint64_t> CpuHookScans{0};
    std::atomic<uint64_t> UserHostilityScans{0};
    std::atomic<uint64_t> MapperWatchArmedCount{0};
    std::atomic<uint64_t> MapperWatchScans{0};
    std::atomic<uint64_t> LoggingEnabledCount{0};
    std::atomic<uint64_t> LoggingFailedCount{0};
    std::atomic<uint64_t> LogBytesWritten{0};
    std::atomic<uint32_t> LogRotations{0};
    std::atomic<uint64_t> StartTickMs{0};
    std::atomic<uint64_t> LastEventTickMs{0};

    uint64_t TiCursorSequence = 0;
    uint64_t LiveCursorEventId = 0;
    uint64_t NextHiddenScanTickMs = 0;
    uint64_t NextMapperScanTickMs = 0;
    uint64_t NextKpageScanTickMs = 0;
    uint64_t NextUserScanTickMs = 0;
};

std::wstring KmonBasenameLower(const std::wstring& path);
// P1: driver name stem -- basename lower case with a trailing ".sys"
// removed, so a TI load event ("\SystemRoot\...\x.sys") and a DRIVER_OBJECT
// name ("\Driver\x") key the same tamper baseline.
std::wstring KmonDriverNameStem(const std::wstring& name);
std::wstring KmonNormalizeDriverPath(const std::wstring& path);
std::wstring KmonClassifyDriverPath(const std::wstring& path);
bool KmonDriverPathIsInbox(const std::wstring& path);
bool KmonDriverPathHasFileDirectory(const std::wstring& path);
bool KmonPathLooksLikeSys(const std::wstring& path);
bool KmonIsWindowsBuiltinLeaf(const std::wstring& leaf);
bool KmonWindowsBuiltinPathLooksInbox(const std::wstring& path);
bool KmonTaskLooksLikeDriverObjectLoad(const std::wstring& task);
bool KmonTaskLooksLikeDriverObjectUnload(const std::wstring& task);
bool KmonTaskLooksLikeDeviceObject(const std::wstring& task);
bool KmonTaskLooksLikeRemoteInject(const std::wstring& task);
bool KmonTaskLooksLikeWindowHook(const std::wstring& task);
bool KmonTaskLooksLikeProcessImpairTask(const std::wstring& task);
std::wstring KmonExtractPayloadDriverName(const std::vector<TiPayloadField>& payload);
// P0: "loaded then hidden" kernel module inventory diff. The inventory view
// is the PsLoadedModuleList image NtQuerySystemInformation reports, and the
// verdict is event symmetry -- a change that no load/unload lifecycle event
// explains -- never a name allowlist, so a driver that keeps its image in the
// loader list while dropping its identity is still reported. Fail-closed:
// with either snapshot empty nothing is concluded.
struct KmonModuleInventoryView
{
    std::wstring Name;   // basename, lower case
    uint64_t Base = 0;
    uint64_t Size = 0;
};

struct KmonModuleDiffRecord
{
    KmonModuleDiffKind Kind = KmonModuleDiffKind::None;
    std::wstring Name;
    uint64_t Base = 0;
    uint64_t Size = 0;
    uint64_t PreviousBase = 0;
    std::wstring Layer;
};

std::vector<KmonModuleDiffRecord> KmonDiffModuleInventory(
    const std::vector<KmonModuleInventoryView>& previous,
    const std::vector<KmonModuleInventoryView>& current,
    const std::set<std::wstring>& recentUnloads,
    const std::set<std::wstring>& recentLoads);
const wchar_t* KmonModuleDiffKindName(KmonModuleDiffKind kind);

// R1: kernel-context view of the module list. The host inventory goes through
// NtQuerySystemInformation, so a filter on that query hides an otherwise
// resident module. This view walks the loader list straight out of kernel
// memory through the device, which the same filter does not cover.
enum class KmonModuleDivergenceDirection
{
    None = 0,
    UserViewMissing,
    KernelViewMissing,
};

// One loader entry as read by the kernel-context walk. Flink/Blink are the
// entry's own InLoadOrderLinks neighbours, kept so link integrity can be
// judged from the snapshot alone rather than from a second scan.
struct KmonKernelModuleView
{
    std::wstring Name;
    uint64_t Entry = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    uint64_t Base = 0;
    uint64_t Size = 0;
};

struct KmonModuleDivergenceRecord
{
    KmonModuleDivergenceDirection Direction = KmonModuleDivergenceDirection::None;
    std::wstring Name;
    uint64_t Base = 0;
    uint64_t Size = 0;
};

// R2: a loader entry whose neighbours disagree about the link was cut out of
// the list (DKOM unlink). Both neighbours must be inside the same snapshot, so
// a truncated walk can never invent a break.
struct KmonModuleChainBreakRecord
{
    std::wstring Name;
    uint64_t Entry = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    bool ForwardBreak = false;
    bool BackwardBreak = false;
};

// Pure comparisons over two snapshots, so the self-test can drive every
// combination without a live kernel. Both sides need usable entries;
// otherwise nothing is concluded.
std::vector<KmonModuleDivergenceRecord> KmonCompareModuleViews(
    const std::vector<KmonModuleInventoryView>& userView,
    const std::vector<KmonKernelModuleView>& kernelView);
const wchar_t* KmonModuleDivergenceDirectionName(KmonModuleDivergenceDirection direction);
std::vector<KmonModuleChainBreakRecord> KmonModuleChainBreaks(
    const std::vector<KmonKernelModuleView>& kernelView);
// Does an already-confirmed kernel-view signal name this module or range?
bool KmonModuleCorroborated(
    const std::wstring& name,
    uint64_t base,
    const std::vector<KmonModuleDivergenceRecord>& divergences,
    const std::vector<KmonModuleChainBreakRecord>& chainBreaks);

bool KmonClassifyTiEvent(const TiEventRecord& record, KmonEvent* out);
bool KmonClassifyLiveEvent(const TimelineEvent& event, KmonEvent* out);
bool KmonWatchMatches(const KmonEvent& event, const KmonOptions& options);
bool KmonDriverLoadArmsMapperWatch(const KmonEvent& event);
bool KmonDriverUnloadArmsMapperWatch(const KmonEvent& event);
bool KernelMonitorSelfTest();

// R6: the cross-process half of kmon-artifact-primitives can legitimately be
// skipped (no fixture next to the exe, no process creation, no readable PEB
// ImageBase). The reason is returned through this out-parameter so the console
// self-test can report the skip instead of passing silently; None means the
// half ran to a verdict.
enum class KmonArtifactSkipReason
{
    None = 0,
    FixtureMissing,
    LaunchFailed,
    ProcessOpenFailed,
    ImageBaseUnreadable,
    SledNotObserved,
    ChildDiedBeforeSample,
};
const wchar_t* KmonArtifactSkipReasonText(KmonArtifactSkipReason reason);

// R5: how the observer reads the fixture's /overwrite sled. The child's head is
// measured against the shared lab contract (KmonTestTargetContract.h) instead
// of a second hard-coded length, so a fixture that patches a different number
// of bytes fails this check rather than quietly skipping it.
enum class KmonSledObservation
{
    None = 0,
    Satisfied,
    ShortPatched,
};
uint32_t KmonLeadingSledRun(const uint8_t* bytes, size_t length, uint8_t pattern);
KmonSledObservation KmonClassifySledObservation(
    const uint8_t* bytes,
    size_t length,
    uint32_t contractBytes);
bool KernelMonitorArtifactSelfTest(KmonArtifactSkipReason* skipReason = nullptr);
// P2: deterministic regression for the "loaded then hidden" layer. Drives the
// pure module-inventory diff and tamper verdict from synthetic snapshots, so
// driver.vanished / driver.unnotified_load / driver.remap / driver.tampered
// semantics are covered without a live kernel.
bool KernelMonitorHiddenDriverSelfTest();
