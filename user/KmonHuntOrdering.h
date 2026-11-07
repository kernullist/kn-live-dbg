#pragma once

#include "ObservationModel.h"
#include <set>

// All ticks supplied to one live hunt index belong to its local collector's
// monotonic millisecond clock. Source names, target boot IDs and FILETIME do not
// establish a clock conversion. Foreign-clock observations need an adapter.
class KmonHuntOrdering
{
public:
    explicit KmonHuntOrdering(size_t capacity = 16384) : Capacity((std::max<size_t>)(1,
        (std::min<size_t>)(capacity, 16384))) {}

    void Advance(uint64_t arrival)
    {
        Watermark = (std::max)(Watermark, arrival);
        while (!Expiry.empty() && Watermark >= Expiry.begin()->first && Watermark - Expiry.begin()->first > 30000)
        {
            Marks.erase(Expiry.begin()->second);
            Expiry.erase(Expiry.begin());
            ++Expired;
        }
    }

    // Empty means admitted. Guards survive hot-row eviction and explicit
    // retirement until every observation they protect is outside freshness.
    const wchar_t* Observe(const ObservationContext& context, uint64_t address,
        uint64_t root, uint64_t slot, const std::wstring& role)
    {
        const auto& identity = context.Identity;
        const auto tick = context.MonotonicMs;
        if (tick <= UntrackedTransitionThrough || (Watermark >= tick && Watermark - tick > 30000))
        { return L"historical_only"; }
        ObservationIdentity assertions = identity;
        const auto key = MakeKey(identity, root, slot, role, address & ~4095ull);
        const auto processStart = ProcessBegin(identity);
        bool generationChanged = false;
        uint64_t previousGenerationTick = 0;
        for (auto it = processStart; it != Marks.end() && SameProcess(it->first, identity); ++it)
        {
            const auto& old = it->second;
            if (std::get<0>(it->first) == std::get<0>(key))
            {
                if (old.GenerationRetired) { return L"prior_process_instance"; }
            }
            else if (old.Observed && !old.GenerationRetired)
            {
                generationChanged = true;
                previousGenerationTick = (std::max)(previousGenerationTick, old.ObservedTick);
            }
        }
        // Creation FILETIME identifies a generation; its numerical ordering is
        // not a clock conversion. Only observed transitions retire generations.
        if (generationChanged && tick < previousGenerationTick) { return L"historical_only"; }
        for (auto it = processStart; it != Marks.end() && SameProcess(it->first, identity); ++it)
        {
            const auto& old = it->second;
            if (std::get<0>(it->first) != std::get<0>(key)) { continue; }
            if (!MergeAssertions(assertions, old.Identity)) { return L"identity_conflict"; }
            if (SamePath(it->first, key) && tick < old.Tick) { return L"historical_only"; }
            if (std::get<4>(it->first) == (address & ~4095ull) && old.MappingGeneration != 0 &&
                context.MappingGeneration != 0 && old.MappingGeneration != context.MappingGeneration && tick < old.MappingTick)
            { return L"historical_only"; }
        }
        auto found = Marks.find(key);
        if (found == Marks.end() && Marks.size() == Capacity)
        {
            if (generationChanged) { RetireOtherGenerations(processStart, identity, std::get<0>(key)); }
            UntrackedTransitionThrough = (std::max)(UntrackedTransitionThrough, tick);
            ++Deferred;
            return L"current_capacity";
        }
        Mark mark{assertions, tick, context.MappingGeneration, context.MappingGeneration == 0 ? 0 : tick, tick, true, false};
        if (found != Marks.end())
        {
            mark.Tick = (std::max)(tick, found->second.Tick);
            if (mark.MappingGeneration == 0)
            {
                mark.MappingGeneration = found->second.MappingGeneration;
                mark.MappingTick = found->second.MappingTick;
            }
        }
        Store(key, mark);
        if (generationChanged) { RetireOtherGenerations(processStart, identity, std::get<0>(key)); }
        return L"";
    }

    bool Retire(const ObservationIdentity& identity, uint64_t root, uint64_t slot,
        const std::wstring& role, uint64_t tick)
    {
        ObservationIdentity assertions = identity;
        const auto key = MakeKey(identity, root, slot, role, UINT64_MAX);
        for (auto it = ProcessBegin(identity); it != Marks.end() && SameProcess(it->first, identity); ++it)
        {
            if (std::get<0>(it->first) == std::get<0>(key) &&
                (it->second.GenerationRetired || !MergeAssertions(assertions, it->second.Identity)))
            { return false; }
        }
        auto found = Marks.find(key);
        if (found != Marks.end()) { tick = (std::max)(tick, found->second.Tick); }
        if (found == Marks.end() && Marks.size() == Capacity)
        {
            // A missing tombstone must not allow stale work to revive a retired
            // path. Pressure is explicit; newer ticks can still make progress.
            UntrackedTransitionThrough = (std::max)(UntrackedTransitionThrough, tick);
            ++Deferred;
        }
        else { Store(key, {assertions, tick, 0, 0}); }
        return true;
    }

    size_t Size() const { return Marks.size(); }
    size_t Limit() const { return Capacity; }
    uint64_t CurrentWatermark() const { return Watermark; }
    uint64_t PressureFloor() const { return UntrackedTransitionThrough; }
    uint64_t Expired = 0, Deferred = 0;

private:
    // A slot identifies a pointer path even when its target/root changes. A
    // slotless root identifies its chain. Page distinguishes retained mapping
    // guards within a chain; UINT64_MAX cannot be an aligned page and denotes
    // an explicit path-retirement tombstone (page zero remains representable).
    using Key = std::tuple<ObservationIdentity::Key, uint64_t, uint64_t, std::wstring, uint64_t>;
    struct Mark
    {
        ObservationIdentity Identity;
        uint64_t Tick = 0, MappingGeneration = 0, MappingTick = 0;
        uint64_t ObservedTick = 0;
        bool Observed = false, GenerationRetired = false;
    };
    static Key MakeKey(const ObservationIdentity& identity, uint64_t root, uint64_t slot,
        const std::wstring& role, uint64_t page)
    { return {identity.CanonicalKey(), slot == 0 ? root : 0, slot, role, page}; }
    static bool SameProcess(const Key& key, const ObservationIdentity& identity)
    { return std::get<0>(std::get<0>(key)) == identity.BootId && std::get<1>(std::get<0>(key)) == identity.ProcessId; }
    static bool SamePath(const Key& a, const Key& b)
    { return std::get<1>(a) == std::get<1>(b) && std::get<2>(a) == std::get<2>(b) && std::get<3>(a) == std::get<3>(b); }
    // Call only after exact canonical-key equality. Avoid constructing and
    // allocating duplicate identity keys for every retained process mark.
    static bool MergeAssertions(ObservationIdentity& into, const ObservationIdentity& other)
    {
        if ((into.Eprocess != 0 && other.Eprocess != 0 && into.Eprocess != other.Eprocess) ||
            (into.SessionKnown && other.SessionKnown && into.SessionId != other.SessionId)) { return false; }
        if (into.Eprocess == 0) { into.Eprocess = other.Eprocess; }
        if (!into.SessionKnown && other.SessionKnown) { into.SessionKnown = true; into.SessionId = other.SessionId; }
        return true;
    }
    std::map<Key, Mark>::iterator ProcessBegin(const ObservationIdentity& identity)
    { return Marks.lower_bound(Key{{identity.BootId, identity.ProcessId, 0}, 0, 0, L"", 0}); }
    void RetireOtherGenerations(std::map<Key, Mark>::iterator begin, const ObservationIdentity& identity,
        const ObservationIdentity::Key& key)
    {
        // Existing map iterators survive insertion. No lookup-key allocation is
        // allowed after committing the newly observed generation.
        for (auto it = begin; it != Marks.end() && SameProcess(it->first, identity); ++it)
        { if (std::get<0>(it->first) != key) { it->second.GenerationRetired = true; } }
    }
    void Store(const Key& key, const Mark& mark)
    {
        // Insert the new expiry first. If allocation fails, admission has not
        // modified the guard; a failed mark insertion rolls that expiry back.
        Mark replacement = mark;
        auto found = Marks.find(key);
        // Forming a compound lookup key can allocate. Do that before changing
        // either index so failure cannot leave an obsolete expiry for a mark.
        const auto previousExpiry = found == Marks.end() ? Expiry.end() : Expiry.find({found->second.Tick, key});
        const auto inserted = Expiry.emplace(mark.Tick, key);
        if (found == Marks.end())
        {
            try { Marks.emplace(key, mark); }
            catch (...) { if (inserted.second) { Expiry.erase(inserted.first); } throw; }
        }
        else
        {
            const auto previous = found->second.Tick;
            std::swap(found->second, replacement);
            if (previous != mark.Tick && previousExpiry != Expiry.end()) { Expiry.erase(previousExpiry); }
        }
    }
    size_t Capacity;
    uint64_t Watermark = 0, UntrackedTransitionThrough = 0;
    std::map<Key, Mark> Marks;
    std::set<std::pair<uint64_t, Key>> Expiry;
};
