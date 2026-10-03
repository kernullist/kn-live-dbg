#pragma once

#include "ObservationModel.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

struct ExecutableRegionObservation
{
    ObservationContext Context;
    ObservationRange Range;
    uint64_t BackingObject = 0;
    uint64_t PageSize = 0;
    bool Executable = false;
    bool Writable = false;
    bool CopyOnWrite = false;
    bool SessionUnverified = false;
    bool ImageMapping = false;
    std::wstring ContentSha256;
    uint64_t ContentBytes = 0;
};

struct ExecutableRegionRecord
{
    uint64_t Generation = 0;
    uint64_t FirstSeenMs = 0;
    uint64_t LastSeenMs = 0;
    uint64_t RetiredAtMs = 0;
    bool Active = true;
    ExecutableRegionObservation Latest;
    std::map<std::wstring, ExecutableRegionObservation> Sources;
    std::set<std::wstring> DependencyGroups;
};

struct ExecutableRegionLink
{
    uint64_t FromGeneration = 0;
    uint64_t ToGeneration = 0;
    uint64_t TimestampMs = 0;
    uint64_t Slot = 0;
    uint64_t Target = 0;
    ObservationRelation Relation = ObservationRelation::Temporal;
    std::wstring Role;
    bool ExecutionObserved = false;
};

// Analysis-thread owned. A generation is an observation epoch, not an
// allocation timestamp. Unobserved unmap/remap cycles cannot be ruled out.
class ExecutableRegionCatalog
{
public:
    explicit ExecutableRegionCatalog(size_t capacity = 16384) : Capacity((std::max<size_t>)(1, capacity))
    {
    }

    uint64_t Observe(const ExecutableRegionObservation& observation, bool* changed = nullptr)
    {
        if (changed != nullptr)
        {
            *changed = false;
        }
        if (!observation.Executable || observation.Range.Size == 0 ||
            observation.Range.Address > UINT64_MAX - observation.Range.Size ||
            observation.Context.Identity.BootId.empty() ||
            (observation.Context.Identity.ProcessId != 0 && observation.Context.Identity.CreateTime == 0))
        {
            ++Rejected;
            return 0;
        }
        ExecutableRegionRecord* previous = nullptr;
        for (auto& pair : Records)
        {
            auto& record = pair.second;
            const auto& old = record.Latest;
            if (old.Context.Identity.SameInstance(observation.Context.Identity) &&
                old.Range.Overlaps(observation.Range) &&
                ((!record.Active && record.RetiredAtMs != 0 && observation.Context.MonotonicMs <= record.RetiredAtMs) ||
                    (record.Active && observation.Context.MonotonicMs < record.LastSeenMs)))
            {
                ++StaleObservations;
                return 0;
            }
            if (record.Active && old.Range.Address == observation.Range.Address &&
                old.Range.Size == observation.Range.Size &&
                old.Context.Identity.SameInstance(observation.Context.Identity))
            {
                previous = &record;
            }
        }
        bool replacement = previous == nullptr;
        if (previous != nullptr)
        {
            const auto& old = previous->Latest;
            if (observation.Context.MonotonicMs < previous->LastSeenMs ||
                (observation.Context.MonotonicMs == previous->LastSeenMs &&
                    observation.Context.Timestamp != 0 && old.Context.Timestamp != 0 &&
                    observation.Context.Timestamp < old.Context.Timestamp))
            {
                // Persistence can lag analysis. Old captures must not revive
                // a retired mapping or replace a newer observation epoch.
                ++StaleObservations;
                return 0;
            }
            replacement = (old.Context.PfnKnown && observation.Context.PfnKnown && old.Context.Pfn != observation.Context.Pfn) ||
                (old.Context.AllocationBase != 0 && observation.Context.AllocationBase != 0 &&
                    old.Context.AllocationBase != observation.Context.AllocationBase) ||
                (old.BackingObject != 0 && observation.BackingObject != 0 && old.BackingObject != observation.BackingObject);
            if (replacement)
            {
                previous->Active = false;
                previous->RetiredAtMs = observation.Context.MonotonicMs;
            }
        }
        if (replacement)
        {
            if (Records.size() >= Capacity)
            {
                auto oldest = std::min_element(Records.begin(), Records.end(), [](const auto& a, const auto& b)
                {
                    return a.second.LastSeenMs < b.second.LastSeenMs;
                });
                Records.erase(oldest);
                ++Evicted;
            }
            ExecutableRegionRecord record;
            record.Generation = ++NextGeneration;
            record.FirstSeenMs = observation.Context.MonotonicMs;
            previous = &Records.emplace(record.Generation, std::move(record)).first->second;
        }
        if (changed != nullptr)
        {
            *changed = replacement || previous->Latest.Writable != observation.Writable ||
                previous->Latest.CopyOnWrite != observation.CopyOnWrite ||
                previous->Latest.Context.Ownership != observation.Context.Ownership ||
                previous->Sources.count(observation.Context.Source) == 0;
        }
        previous->LastSeenMs = observation.Context.MonotonicMs;
        previous->Latest = observation;
        previous->Latest.Context.MappingGeneration = previous->Generation;
        for (auto& pair : Records)
        {
            auto& containing = pair.second;
            if (containing.Generation == previous->Generation || !containing.Active ||
                !containing.Latest.Context.Identity.SameInstance(observation.Context.Identity) ||
                containing.LastSeenMs > previous->LastSeenMs || previous->LastSeenMs - containing.LastSeenMs > 1000)
            {
                continue;
            }
            const auto& range = containing.Latest.Range;
            if (range.Contains(observation.Range.Address) &&
                observation.Range.Size <= range.Size - (observation.Range.Address - range.Address) &&
                previous->Sources.size() < 16)
            {
                previous->Sources[L"containing:" + containing.Latest.Context.Source] = containing.Latest;
                previous->DependencyGroups.insert(containing.Latest.Context.DependencyGroup);
            }
        }
        // Keep source observations separately: VAD and PTE are not independent
        // evidence of execution, and an older source never supplies current PFNs.
        if (previous->Sources.size() < 16 || previous->Sources.count(observation.Context.Source) != 0)
        {
            previous->Sources[observation.Context.Source] = previous->Latest;
            previous->DependencyGroups.insert(observation.Context.DependencyGroup);
        }
        return previous->Generation;
    }

    const ExecutableRegionRecord* Find(const ObservationIdentity& identity, uint64_t address, uint64_t nowMs) const
    {
        const ExecutableRegionRecord* result = nullptr;
        for (const auto& pair : Records)
        {
            const auto& record = pair.second;
            if (record.Active && record.Latest.Context.Identity.SameInstance(identity) &&
                record.Latest.Range.Contains(address) && nowMs >= record.LastSeenMs &&
                nowMs - record.LastSeenMs <= 30000 &&
                (result == nullptr || record.LastSeenMs > result->LastSeenMs ||
                    (record.LastSeenMs == result->LastSeenMs && record.Latest.Range.Size < result->Latest.Range.Size)))
            {
                result = &record;
            }
        }
        return result;
    }

    void RetireRange(const ObservationIdentity& identity, const ObservationRange& range, uint64_t nowMs = 0)
    {
        if (range.Size == 0 || range.Address > UINT64_MAX - range.Size)
        {
            return;
        }
        for (auto& pair : Records)
        {
            auto& record = pair.second;
            const auto& old = record.Latest.Range;
            if (record.Latest.Context.Identity.SameInstance(identity) && old.Overlaps(range))
            {
                record.Active = false;
                record.RetiredAtMs = (std::max)(record.RetiredAtMs, (std::max)(nowMs, record.LastSeenMs));
            }
        }
    }

    bool LinkAddress(const ObservationIdentity& identity, uint64_t slot, uint64_t target,
        const std::wstring& role, uint64_t nowMs, ExecutableRegionLink* output = nullptr, uint64_t referenceMs = 0)
    {
        const auto destination = Find(identity, target, nowMs);
        if (destination == nullptr || (referenceMs != 0 && destination->FirstSeenMs > referenceMs))
        {
            return false;
        }
        const auto source = Find(identity, slot, nowMs);
        ExecutableRegionLink link;
        link.FromGeneration = source == nullptr || (referenceMs != 0 && source->FirstSeenMs > referenceMs) ? 0 : source->Generation;
        link.ToGeneration = destination->Generation;
        link.TimestampMs = nowMs;
        link.Slot = slot;
        link.Target = target;
        link.Relation = ObservationRelation::Address;
        link.Role = role;
        if (Links.size() >= 4096)
        {
            Links.erase(Links.begin());
            ++LinksEvicted;
        }
        Links.push_back(link);
        if (output != nullptr)
        {
            *output = link;
        }
        return true;
    }

    static ObservationRelation Correlate(const ExecutableRegionRecord& a, const ExecutableRegionRecord& b)
    {
        const auto& x = a.Latest;
        const auto& y = b.Latest;
        const uint64_t age = a.LastSeenMs > b.LastSeenMs ? a.LastSeenMs - b.LastSeenMs : b.LastSeenMs - a.LastSeenMs;
        const bool sameBoot = !x.Context.Identity.BootId.empty() && x.Context.Identity.BootId == y.Context.Identity.BootId;
        const bool sameContent = x.ContentSha256.size() == 64 && x.ContentSha256 == y.ContentSha256 &&
            x.ContentBytes != 0 && x.ContentBytes == y.ContentBytes;
        if (a.Active && b.Active && sameBoot && age <= 1000 && sameContent)
        {
            if (x.Context.PfnKnown && y.Context.PfnKnown && x.Context.Pfn == y.Context.Pfn &&
                x.ContentBytes == 4096 && (x.Range.Address & 4095) == 0 && (y.Range.Address & 4095) == 0)
            {
                return ObservationRelation::PhysicalPage;
            }
            return ObservationRelation::Content;
        }
        return ObservationRelation::Temporal;
    }

    const std::map<uint64_t, ExecutableRegionRecord>& Snapshot() const
    {
        return Records;
    }

    uint64_t Evicted = 0;
    uint64_t Rejected = 0;
    uint64_t StaleObservations = 0;
    uint64_t LinksEvicted = 0;

private:
    size_t Capacity;
    uint64_t NextGeneration = 0;
    std::map<uint64_t, ExecutableRegionRecord> Records;
    std::vector<ExecutableRegionLink> Links;
};

inline bool ExecutableRegionCatalogSelfTest()
{
    ExecutableRegionCatalog catalog(4);
    ExecutableRegionObservation region;
    region.Context.Identity.BootId = L"test_boot";
    region.Context.Identity.ProcessId = 45;
    region.Context.Identity.CreateTime = 100;
    region.Context.Source = L"pte";
    region.Context.DependencyGroup = L"page_tables";
    region.Context.MonotonicMs = 20;
    region.Context.PfnKnown = true;
    region.Context.Pfn = 12;
    region.Range = {0x1000, 4096};
    region.Executable = true;
    region.CopyOnWrite = true;
    region.SessionUnverified = true;
    bool changed = false;
    const uint64_t first = catalog.Observe(region, &changed);
    bool ok = first != 0 && changed && catalog.Snapshot().at(first).Latest.Context.Ownership == CodeOwnership::Unknown;
    const auto identity = region.Context.Identity;
    ExecutableRegionLink link;
    ok = ok && catalog.LinkAddress(identity, 0x8000, 0x1200, L"vtable", 21, &link) &&
        link.ToGeneration == first && !link.ExecutionObserved;
    region.Context.Pfn = 13;
    const uint64_t remap = catalog.Observe(region);
    ok = ok && remap != first && !catalog.Snapshot().at(first).Active;
    region.Context.Identity.CreateTime = 101;
    const uint64_t reuse = catalog.Observe(region);
    ok = ok && reuse != remap && catalog.Find(identity, 0x1200, 21)->Generation == remap;
    catalog.RetireRange(identity, region.Range);
    ok = ok && catalog.Find(identity, 0x1200, 21) == nullptr;
    region.ContentSha256 = std::wstring(64, L'a');
    region.ContentBytes = 4096;
    catalog.Observe(region);
    auto a = catalog.Snapshot().at(reuse);
    auto b = a;
    b.Latest.Context.Identity.ProcessId = 0;
    ok = ok && ExecutableRegionCatalog::Correlate(a, b) == ObservationRelation::PhysicalPage;
    b.Latest.ContentSha256[0] = L'b';
    ok = ok && ExecutableRegionCatalog::Correlate(a, b) == ObservationRelation::Temporal;
    b = a;
    b.LastSeenMs += 1001;
    ok = ok && ExecutableRegionCatalog::Correlate(a, b) == ObservationRelation::Temporal;
    for (uint64_t i = 0; i < 8; ++i)
    {
        region.Range.Address += 4096;
        catalog.Observe(region);
    }
    ok = ok && catalog.Evicted != 0 && catalog.Snapshot().size() == 4;
    ExecutableRegionCatalog ordered;
    region.Range = {0x10000, 0x4000};
    region.Context.MonotonicMs = 1000;
    const uint64_t current = ordered.Observe(region);
    region.Context.MonotonicMs = 900;
    const uint64_t delayed = ordered.Observe(region);
    ok = ok && delayed == 0 && ordered.Snapshot().at(current).Active &&
        ordered.Find(region.Context.Identity, 0x11000, 1001)->Generation == current;
    ordered.RetireRange(region.Context.Identity, {0x11000, 0x1000}, 1001);
    ok = ok && ordered.Find(region.Context.Identity, 0x11000, 1001) == nullptr;
    region.Range = {0x11000, 0x1000};
    ok = ok && ordered.Observe(region) == 0;
    region.Context.MonotonicMs = 1002;
    const uint64_t fresh = ordered.Observe(region);
    ok = ok && fresh != 0 && ordered.Find(region.Context.Identity, 0x11000, 1002)->Generation == fresh;
    ok = ok && !ordered.LinkAddress(region.Context.Identity, 0, 0x11000, L"stale_reference", 1003, nullptr, 1000);
    ExecutableRegionCatalog nested;
    region.Range = {0x20000, 4096};
    region.Context.MonotonicMs = 1000;
    nested.Observe(region);
    region.Range.Size = 16384;
    region.Context.MonotonicMs = 2000;
    const uint64_t containing = nested.Observe(region);
    ok = ok && nested.Find(region.Context.Identity, 0x20000, 2001)->Generation == containing;
    region.Range.Size = 4096;
    region.Context.MonotonicMs = 1500;
    ok = ok && nested.Observe(region) == 0;
    return ok;
}
