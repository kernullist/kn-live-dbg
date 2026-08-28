#pragma once

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <map>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct TiPayloadField
{
    std::wstring Name;
    std::wstring Value;
    std::wstring TypeName;
};

struct TiEventRecord
{
    // Monotonic ring arrival id (assigned in RecordKeep). Used by timeline
    // recent-mode cursor so out-of-order ETW timestamps are not skipped.
    uint64_t Sequence = 0;
    uint64_t Timestamp = 0;       // FILETIME (100-ns ticks since 1601 UTC)
    uint32_t ProcessId = 0;
    uint32_t ThreadId = 0;
    uint16_t TaskId = 0;
    uint16_t Version = 0;
    uint8_t  Level = 0;
    uint8_t  Opcode = 0;
    uint8_t  Channel = 0;
    uint64_t Keyword = 0;
    std::wstring TaskName;        // resolved via TDH if available
    std::wstring OpcodeName;
    std::wstring ImagePath;       // best-effort process image (basename)
    std::vector<TiPayloadField> Payload;
    std::wstring RawPayloadHex;   // fallback when TDH/manifest can't decode
    bool DecodedByTdh = false;

    // First non-CallingProcessId target PID extracted from the payload and
    // its resolved image basename. Populated once during ingest so the
    // matcher and the printer don't have to walk the payload again.
    uint32_t TargetProcessId = 0;
    std::wstring TargetImageBase;
};

struct TiSubscriberStats
{
    uint64_t EventsReceived = 0;
    uint64_t EventsKept = 0;
    uint64_t EventsDropped = 0;       // ring overflow (oldest evicted)
    uint64_t EventsSelfExcluded = 0;
    uint64_t EventsWatchMatched = 0;
    uint64_t EventsLogged = 0;
    uint64_t LogBytesWritten = 0;
    uint32_t LogRotations = 0;
    uint64_t EventsLost = 0;          // ETW session lost-event counter
    uint64_t MatchAnyKeyword = 0;
    uint64_t MatchAllKeyword = 0;
    uint64_t StartTickMs = 0;          // GetTickCount64 at Start
    uint64_t LastEventTickMs = 0;
};

// Internal atomic mirror to keep increments on the ETW callback thread
// race-free without paying for a mutex on every event.
struct TiSubscriberStatsAtomic
{
    std::atomic<uint64_t> EventsReceived{0};
    std::atomic<uint64_t> EventsKept{0};
    std::atomic<uint64_t> EventsDropped{0};
    std::atomic<uint64_t> EventsSelfExcluded{0};
    std::atomic<uint64_t> EventsWatchMatched{0};
    std::atomic<uint64_t> EventsLogged{0};
    std::atomic<uint64_t> LogBytesWritten{0};
    std::atomic<uint32_t> LogRotations{0};
    std::atomic<uint64_t> EventsLost{0};
    std::atomic<uint64_t> StartTickMs{0};
    std::atomic<uint64_t> LastEventTickMs{0};
};

struct TiOptions
{
    std::vector<uint32_t> WatchPids;
    std::vector<std::wstring> WatchNames; // case-insensitive basename match
    uint32_t ThrottlePerSecond = 50;
    uint32_t RingCapacity = 1u << 20;     // 1M events default
    std::wstring LogDirectory;            // empty = exe directory
    std::wstring LogBaseName;             // empty = "ti-events"
    uint64_t LogRotateBytes = 100ull * 1024ull * 1024ull;
    uint32_t LogRotateCount = 10;
    bool     ExcludeSelf = true;
    uint32_t SelfPid = 0;                 // set by handler
    bool     LiveOutputEnabled = false;   // start-time default
};

class TiSubscriber
{
public:
    TiSubscriber();
    ~TiSubscriber();

    TiSubscriber(const TiSubscriber&) = delete;
    TiSubscriber& operator=(const TiSubscriber&) = delete;

    bool Start(const TiOptions& options, std::wstring* error);
    bool Stop(std::wstring* error);
    bool IsActive() const;

    bool AddWatchPid(uint32_t pid);
    bool RemoveWatchPid(uint32_t pid);
    bool AddWatchName(const std::wstring& imageBase);
    bool RemoveWatchName(const std::wstring& imageBase);

    void SetLiveOutput(bool enabled);
    bool IsLiveOutputEnabled() const;

    // Ring snapshot helpers. Copies under lock; returns newest-first when
    // newestFirst is true. maxCount == 0 means unlimited.
    std::vector<TiEventRecord> Recent(size_t maxCount, bool newestFirst) const;
    // Chronological events with Timestamp >= minTimestampInclusive.
    // maxCount == 0 means unlimited after the timestamp filter.
    std::vector<TiEventRecord> RecentSince(uint64_t minTimestampInclusive, size_t maxCount) const;
    // Chronological events with Sequence > minSequenceExclusive (preferred
    // for timeline recent ingest; avoids timestamp-reorder skips).
    std::vector<TiEventRecord> RecentAfterSequence(uint64_t minSequenceExclusive, size_t maxCount) const;
    std::vector<TiEventRecord> FilterByPid(uint32_t pid, size_t maxCount) const;
    std::vector<TiEventRecord> FilterByTask(const std::wstring& taskName, size_t maxCount) const;
    std::vector<TiEventRecord> Grep(const std::wstring& pattern, size_t maxCount) const;
    bool SaveTo(const std::wstring& path, std::wstring* error) const;
    void Clear();

    // Non-copying histogram over the ring. Avoids materialising the entire
    // ring into a temporary vector just to count entries.
    void Histogram(
        std::map<std::wstring, uint64_t>* byTaskName,
        std::map<std::wstring, uint64_t>* byImageBase,
        size_t* totalCounted) const;

    TiSubscriberStats SnapshotStats() const;
    TiOptions CurrentOptions() const;

    // Drain the bounded print queue used by '!ti watch'. Caller polls this
    // and prints returned events. Already throttled to <=
    // ThrottlePerSecond. Returned events do not affect the ring.
    std::vector<TiEventRecord> DrainPrintQueue(size_t maxCount);

    // Read suppression counter for the "[suppressed N events]" line.
    uint64_t ConsumeThrottleSuppressedCount();

    // Public helper for the printer: returns the lowercased image basename
    // for the given PID, hitting the same cache the callback path uses.
    // Returns an empty string when the PID cannot be opened (process gone,
    // protection too tight, etc.).
    std::wstring ResolveImageBasename(uint32_t pid);

private:
    static VOID WINAPI EventRecordCallbackThunk(PEVENT_RECORD eventRecord);
    static ULONG WINAPI BufferCallbackThunk(PEVENT_TRACE_LOGFILEW buffer);
    void OnEventRecord(PEVENT_RECORD eventRecord);
    void ProcessTraceThread();
    bool DecodeEvent(PEVENT_RECORD eventRecord, TiEventRecord* out);
    bool DecodePayloadViaTdh(PEVENT_RECORD eventRecord, TiEventRecord* out);
    void DecodePayloadAsRawHex(PEVENT_RECORD eventRecord, TiEventRecord* out);
    void RecordKeep(TiEventRecord&& record);
    // Not const: may mutate WatchPromotedPids when a name match promotes a
    // (possibly target-side) PID into the hot path, and may touch the image
    // cache to resolve target PIDs referenced by payload fields.
    bool MatchesWatch(const TiEventRecord& record);
    bool WriteLogLine(const TiEventRecord& record);
    void RotateLogLocked();
    void CloseLogLocked();
    bool EnsureLogOpenLocked();
    std::wstring BuildLogFilePath(int rotationIndex) const;
    void EnqueuePrint(TiEventRecord&& record);

    static std::wstring BasenameLower(const std::wstring& path);

    mutable std::mutex StateMutex;
    TiOptions Options;
    TiSubscriberStatsAtomic Stats;
    std::atomic<bool> Active{false};
    std::atomic<uint32_t> SelfPidSnapshot{0};
    std::atomic<bool> ExcludeSelfSnapshot{true};

    // ETW session handles.
    TRACEHANDLE SessionHandle = 0;          // from StartTraceW
    TRACEHANDLE ProcessHandle = INVALID_PROCESSTRACE_HANDLE;  // from OpenTraceW
    std::vector<uint8_t> SessionPropertiesBlob;
    std::wstring SessionName;

    // Worker thread that drives ProcessTrace.
    std::thread ProcessThread;
    std::atomic<bool> ProcessTraceShouldExit{false};

    // Watch set (mutex-protected for hot path read).
    mutable std::mutex WatchMutex;
    std::unordered_set<uint32_t> WatchPids;
    std::vector<std::wstring> WatchNamesLower;
    std::unordered_set<uint32_t> WatchPromotedPids;

    // Ring buffer (mutex-protected; deque keeps insertion order).
    mutable std::mutex RingMutex;
    std::deque<TiEventRecord> Ring;
    // Never reset on Clear(): timeline cursors remain valid across ring wipes.
    uint64_t NextRingSequence = 1;

    // Print queue (bounded, drained by '!ti watch' polling).
    mutable std::mutex PrintMutex;
    std::deque<TiEventRecord> PrintQueue;
    std::atomic<bool> LiveOutput{false};
    std::atomic<uint64_t> ThrottleWindowStartMs{0};
    std::atomic<uint32_t> ThrottleWindowCount{0};
    std::atomic<uint64_t> ThrottleSuppressed{0};

    // Log file state.
    mutable std::mutex LogMutex;
    HANDLE LogHandle = INVALID_HANDLE_VALUE;
    uint64_t LogCurrentBytes = 0;
    std::wstring LogActivePath;
    int LogActiveRotation = 0;

    // PID -> image path cache to avoid OpenProcess on every ETW event.
    struct ImageCacheEntry
    {
        std::wstring Path;
        uint64_t TickMs = 0;
        bool Failed = false;
    };
    mutable std::mutex ImageCacheMutex;
    std::unordered_map<uint32_t, ImageCacheEntry> ImageCache;
    std::wstring GetCachedImageOrResolve(uint32_t pid);
    static bool PayloadBasenameMatchesWatch(
        const TiEventRecord& record,
        const std::vector<std::wstring>& watchNamesLower);
};
