#pragma once

#include "SnapshotModel.h"
#include "ThreatIntelSubscriber.h"
#include "TimelineModel.h"

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

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

    TimelineIngestResult IngestThreatIntel(
        const std::vector<TiEventRecord>& events,
        const std::wstring& mode);
    TimelineIngestResult IngestSnapshot(
        const SnapshotDocument& document,
        const std::wstring& sourceName);
    TimelineIngestResult IngestEvents(
        const std::vector<TimelineEvent>& events);

    std::vector<TimelineEvent> Query(const TimelineQueryOptions& options) const;
    std::vector<TimelineEvent> AllEvents() const;
    TimelineGraphResult BuildGraph(const TimelineGraphQueryOptions& options) const;
    TimelineReconcileResult ReconcileSnapshot(
        const SnapshotDocument& document,
        const TimelineReconcileOptions& options) const;
    TimelineStats GetStats() const;
    bool ExportJsonl(const std::wstring& path, std::wstring* error) const;

private:
    void AddEventLocked(TimelineEvent event);
    uint64_t NextEventIdLocked();

    mutable std::mutex Mutex;
    std::deque<TimelineEvent> Events;
    uint64_t NextEventId = 1;
    uint64_t DroppedEvents = 0;
    size_t MaxEvents = 262144;
};
