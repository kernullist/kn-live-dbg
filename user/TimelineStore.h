#pragma once

#include "SnapshotModel.h"
#include "ThreatIntelSubscriber.h"
#include "TimelineModel.h"

#include <cstdint>
#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <vector>

struct SnapshotDiffResult;

class TimelineStore
{
public:
    TimelineStore();
    explicit TimelineStore(size_t capacity);

    TimelineStore(const TimelineStore&) = delete;
    TimelineStore& operator=(const TimelineStore&) = delete;

    void Clear();
    void SetCapacity(size_t capacity);
    size_t Capacity() const;
    uint64_t Dropped() const;

    // mode: "recent" uses a timestamp cursor; "all" rescans every event.
    // maxAdd: when non-zero, stop after adding this many new timeline events
    // and only advance the recent cursor over events considered so far so a
    // limited newest window cannot permanently skip older ring records.
    TimelineIngestResult IngestThreatIntel(
        const std::vector<TiEventRecord>& events,
        const std::wstring& mode,
        size_t maxAdd = 0);
    TimelineIngestResult IngestSnapshot(
        const SnapshotDocument& document,
        const std::wstring& sourceName);
    TimelineIngestResult IngestSnapshotDiff(
        const SnapshotDiffResult& diff,
        const std::wstring& sourceName);
    TimelineIngestResult IngestEvents(
        const std::vector<TimelineEvent>& events);

    std::vector<TimelineEvent> Query(const TimelineQueryOptions& options) const;
    std::vector<TimelineEvent> AllEvents() const;
    // Chronological events with EventId > minExclusive. maxCount 0 = unlimited.
    std::vector<TimelineEvent> RecentAfterEventId(uint64_t minExclusive, size_t maxCount) const;
    // Cheap cursor helper for live consumers. Clear() resets this to 1, so a
    // stale minExclusive would otherwise skip every new event forever.
    uint64_t PeekNextEventId() const;
    TimelineGraphResult BuildGraph(const TimelineGraphQueryOptions& options) const;
    TimelineReconcileResult ReconcileSnapshot(
        const SnapshotDocument& document,
        const TimelineReconcileOptions& options) const;
    TimelineAnalysisResult AnalyzeLiveSignals(size_t limit) const;
    TimelineStats GetStats() const;
    bool ExportJsonl(const std::wstring& path, std::wstring* error) const;

    // TI recent-mode cursor for callers that want to pull only unprocessed
    // ring records instead of cloning the entire TI ring every update.
    // Prefer GetTiRecentCursorSequence; timestamp is retained for display /
    // legacy unsequenced records.
    uint64_t GetTiRecentCursorTimestamp(bool* initialized) const;
    uint64_t GetTiRecentCursorSequence(bool* initialized) const;

private:
    bool AddEventLocked(TimelineEvent event);
    void DropOldestEventLocked();
    uint64_t NextEventIdLocked();

    mutable std::mutex Mutex;
    std::deque<TimelineEvent> Events;
    std::deque<std::wstring> EventKeysInOrder;
    std::set<std::wstring> EventKeys;
    uint64_t NextEventId = 1;
    uint64_t DroppedEvents = 0;
    bool TiRecentCursorInitialized = false;
    uint64_t TiRecentCursorSequence = 0; // last ingested ring Sequence
    uint64_t TiRecentCursorTimestamp = 0; // last ingested timestamp (display/legacy)
    std::set<std::wstring> TiRecentCursorBoundaryKeys; // legacy Timestamp==cursor keys
    size_t MaxEvents = 262144;
};
