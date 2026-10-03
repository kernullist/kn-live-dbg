#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include "ThreatIntelSubscriber.h"

struct ProcessVadProtectionRange;

enum class KmonRegionAction
{
    Snapshot,
    Allocate,
    Protect,
    Release
};

struct KmonRegionObservation
{
    uint32_t ProcessId = 0;
    uint64_t CreateTime = 0;
    uint64_t Base = 0;
    uint64_t Size = 0;
    uint64_t Timestamp = 0;
    uint64_t CollectionStartTimestamp = 0;
    uint64_t CollectionEndTimestamp = 0;
    uint64_t ReceiveTickMs = 0;
    uint32_t Protection = 0;
    bool ProtectionKnown = false;
    bool Executable = false;
    KmonRegionAction Action = KmonRegionAction::Snapshot;
};

struct KmonRegionTransition
{
    bool Accepted = false;
    bool OutOfOrder = false;
    bool CapacityEvicted = false;
    bool PreviousKnown = false;
    bool PreviousExecutable = false;
    bool NxToRx = false;
    bool RxToNx = false;
    bool RangeUnknown = false;
    bool ObservationTimeUnknown = false;
    bool CollectionIntervalsOverlap = false;
    bool LifetimeDiscontinuity = false;
    uint64_t ObservedInterval100ns = 0;
    uint64_t ObservedIntervalMin100ns = 0;
    uint64_t ObservedIntervalMax100ns = 0;
};

class KmonRegionHistory
{
public:
    KmonRegionTransition Observe(const KmonRegionObservation& observation);
    void Clear();

private:
    // Event operations and protection snapshots retain independent histories.
    using Key = std::tuple<uint32_t, uint64_t, bool, uint64_t>;
    struct StoredRegion
    {
        KmonRegionObservation Observation;
        // A protection update must not erase a known allocation boundary.
        uint64_t LifetimeBoundaryTimestamp = 0;
    };
    void ApplyLifetimeBoundary(const KmonRegionObservation& observation);
    bool TrimCapacity();
    std::map<Key, StoredRegion> Regions;
    uint64_t LastPruneTickMs = 0;
    std::map<uint32_t, uint64_t> Generations;
};

bool KmonTemporalEvidenceSelfTest();
bool KmonDecodeRegionEvent(const TiEventRecord& event, KmonRegionObservation* observation);
bool BuildKmonRegionSnapshot(uint32_t processId, uint64_t createTime,
    const ProcessVadProtectionRange& range, uint64_t receiveTickMs, KmonRegionObservation* observation);
bool KmonRegionNeedsFollowup(const KmonRegionObservation& observation, const KmonRegionTransition& transition);

template<typename Cursor>
void KmonRefreshExecutionHistory(const std::map<uint32_t, uint64_t>& inventory, uint64_t now,
    std::map<std::pair<uint32_t, uint64_t>, Cursor>* cursors)
{
    for (auto& cursor : *cursors)
    {
        const auto observed = inventory.find(cursor.first.first);
        if (observed != inventory.end() && (observed->second == 0 || observed->second == cursor.first.second))
        {
            cursor.second.LastObservedMs = now;
        }
    }
}

template<typename Cursor, typename Identity>
void KmonPruneExecutionHistory(const std::pair<uint32_t, uint64_t>& generation, uint64_t now,
    std::map<std::pair<uint32_t, uint64_t>, Cursor>* cursors,
    std::map<std::pair<uint32_t, uint64_t>, Identity>* identities)
{
    for (auto it = cursors->begin(); it != cursors->end();)
    {
        const bool replaced = it->first.first == generation.first && it->first.second < generation.second;
        const bool expired = it->first != generation && now >= it->second.LastObservedMs &&
            now - it->second.LastObservedMs > 120000;
        if (replaced || expired)
        {
            identities->erase(it->first);
            it = cursors->erase(it);
        }
        else
        {
            ++it;
        }
    }
    for (auto it = identities->begin(); it != identities->end();)
    {
        if (cursors->find(it->first) == cursors->end())
        {
            it = identities->erase(it);
        }
        else
        {
            ++it;
        }
    }
}
