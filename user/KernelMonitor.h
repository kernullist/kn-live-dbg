#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "ThreatIntelSubscriber.h"
#include "TimelineStore.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
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
    uint64_t LoggingEnabled = 0;
    uint64_t LoggingFailed = 0;
    uint64_t LogBytesWritten = 0;
    uint32_t LogRotations = 0;
    uint64_t StartTickMs = 0;
    uint64_t LastEventTickMs = 0;
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

    bool AddWatchPid(uint32_t pid);
    bool RemoveWatchPid(uint32_t pid);
    bool AddWatchName(const std::wstring& imageBase);
    bool RemoveWatchName(const std::wstring& imageBase);
    bool AddWatchDriver(const std::wstring& driverBase);
    bool RemoveWatchDriver(const std::wstring& driverBase);

    void SetLiveOutput(bool enabled);
    bool IsLiveOutputEnabled() const;

    std::vector<KmonEvent> Recent(size_t maxCount, bool newestFirst) const;
    bool SaveTo(const std::wstring& path, std::wstring* error) const;
    void Clear();

    std::vector<KmonEvent> DrainPrintQueue(size_t maxCount);
    uint64_t ConsumeThrottleSuppressedCount();

    KmonStats SnapshotStats() const;
    KmonOptions CurrentOptions() const;

private:
    void WorkerLoop();
    void IngestThreatIntel();
    void IngestLiveTimeline();
    void ScanHiddenProcesses();
    void ScanMapperRemnants();
    void ScanPoolMappedImages();
    void ScanUnbackedDriverObjects();
    void ScanOrphanMappedPages();
    void ScanHookCallbacks();
    void ScanHookInput();
    void ScanCpuIntegrityHooks();
    void ScanUserModeHostility();
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
    void MaybeEmitShortLived(const KmonEvent& unloadEvent);
    void EnableLoggingForPid(uint32_t pid);
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
std::wstring KmonExtractPayloadDriverName(const std::vector<TiPayloadField>& payload);
bool KmonClassifyTiEvent(const TiEventRecord& record, KmonEvent* out);
bool KmonClassifyLiveEvent(const TimelineEvent& event, KmonEvent* out);
bool KmonWatchMatches(const KmonEvent& event, const KmonOptions& options);
bool KernelMonitorSelfTest();
bool KernelMonitorArtifactSelfTest();
