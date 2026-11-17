#pragma once
#include "KmonUserDeepScheduling.h"
#include <unordered_map>
#include <utility>

struct KmonUserTarget
{
    uint32_t Pid = 0;
    uint64_t CreateTime = 0, Eprocess = 0, SuspectExpiresMs = 0;
    uint32_t ThreadQueryQuota = 0;
    std::wstring ImagePath, Leaf;
    bool HighPriority = false, Interesting = false, Suspect = false, PinnedGeneration = false;
};
enum class KmonUserInventoryRead { Row, End, Error };

inline bool KmonUserInventoryInvalidates(uint64_t started, uint64_t lastObserved, uint64_t expectedGeneration,
    bool present, uint64_t observedGeneration, bool complete)
{
    // Analysis can admit a newer lead/page while an older snapshot is paused.
    // An older inventory cannot retire that work, including after PID reuse.
    if (lastObserved >= started) { return false; }
    return present ? observedGeneration != 0 && observedGeneration != expectedGeneration : complete;
}

// Source owns its native snapshot, and Resolve pins the queried process. Leaf
// may be a scheduling hint; ImagePath must belong to CreateTime or stay empty.
// Worker-owned: no locks or borrowed references cross Run's return boundary.
template<class Source, size_t SnapshotLimit = 4096, size_t WatchLimit = 8192, size_t SuspectLimit = 12288>
class KmonUserInventory
{
public:
    static_assert(0 < SnapshotLimit && SnapshotLimit < WatchLimit && WatchLimit < SuspectLimit);
    static constexpr size_t MaximumSteps = 32;
    static constexpr uint64_t BudgetMs = 25;
    KmonUserInventory(Source source, std::vector<uint32_t> watches,
        std::vector<KmonUserTarget> suspects, uint32_t self, uint64_t started, KmonUserInventoryPosition previous = {})
        : Reader(std::move(source)), Watches(std::move(watches)), Suspects(std::move(suspects)),
          Self(self), Started(started), LastClock(started), Previous(previous) {}
    ~KmonUserInventory() { Reader.Close(); }
    KmonUserInventory(const KmonUserInventory&) = delete;
    KmonUserInventory& operator=(const KmonUserInventory&) = delete;

    bool WalkIncomplete() const { return !WalkComplete; }
    bool Capped() const { return Truncated; }
    bool Complete() const { return Stage == Phase::Done && !Cancelled && !Failed; }
    uint64_t StartedMs() const { return Started; }
    const Source& SourceState() const { return Reader; }
    KmonUserInventoryPosition Reservation() const
    {
        if (!Complete() || Cancelled || Failed || InvalidClock || !Truncated || !WalkComplete || !Have.count(CandidatePid)) { return {}; }
        return {CandidatePid, Previous.InCurrentLap(CandidatePid) ? Previous.ThroughPid : HighestPid};
    }
    std::vector<KmonUserTarget> Take() { return Complete() ? std::move(Targets) : std::vector<KmonUserTarget>{}; }
    void Cancel() { if (!Complete()) { Cancelled = true; } Reader.Close(); }

    template<class Clock, class Stopping>
    KmonDiscoveryDispatch Run(Clock clock, Stopping stopping)
    {
        if (Complete()) { return KmonDiscoveryDispatch::Returned; }
        if (Cancelled || Failed) { return KmonDiscoveryDispatch::Cancelled; }
        ++Turns;
        const auto begin = clock();
        if (begin < LastClock) { InvalidClock = true; Cancel(); }
        else { LastClock = begin; }
        const auto sample = [&]()
        {
            const auto now = clock();
            if (now < LastClock) { InvalidClock = Cancelled = true; Reader.Close(); }
            else { LastClock = now; }
            return now;
        };
        size_t steps = 0;
        const auto finish = [&]()
        {
            const auto end = sample();
            if (!InvalidClock && end >= begin)
            { Service.Add(end - begin); Overruns += end - begin > BudgetMs; }
            LastSteps = steps; MaxSteps = (std::max)(MaxSteps, steps);
        };
        try
        {
            while (!Complete())
            {
                const auto now = sample();
                if (stopping()) { Cancel(); }
                if (Cancelled) { break; }
                if (steps >= MaximumSteps || now - begin >= BudgetMs) { ++Deferrals; break; }
                ++steps; ++Steps;
                Advance();
            }
        }
        catch (...) { Failed = true; Reader.Close(); finish(); throw; }
        finish();
        if (Cancelled) { return KmonDiscoveryDispatch::Cancelled; }
        return Complete() ? KmonDiscoveryDispatch::Returned : KmonDiscoveryDispatch::Continued;
    }
    std::wstring Json(uint64_t now) const
    {
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        const auto b = [](bool v) -> std::wstring { return v ? L"true" : L"false"; };
        static const wchar_t* names[] = {L"open", L"snapshot", L"rank_watches", L"rank_suspects",
            L"reserve_snapshot", L"watches", L"suspects", L"done"};
        const auto proposed = Reservation();
        return L"{\"schema\":\"kn.user_inventory.v1\",\"scope\":\"latest_hostility_inventory\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"target_success_reported\":false,\"hard_deadline_enforced\":false,"
            L"\"budget_ms\":" + n(BudgetMs) + L",\"step_limit\":" + n(MaximumSteps) +
            L",\"phase\":" + mcpjson::Quote(names[static_cast<size_t>(Stage)]) +
            L",\"started_ms\":" + n(Started) + L",\"elapsed_ms\":" + (!InvalidClock && now >= Started ? n(now - Started) : L"null") +
            L",\"complete\":" + b(Complete()) + L",\"walk_complete\":" + b(WalkComplete) +
            L",\"capped\":" + b(Truncated) + L",\"cancelled\":" + b(Cancelled) + L",\"faulted\":" + b(Failed) +
            L",\"invalid_clock\":" + b(InvalidClock) + L",\"turns\":" + n(Turns) + L",\"steps\":" + n(Steps) +
            L",\"last_steps\":" + n(LastSteps) + L",\"max_steps\":" + n(MaxSteps) +
            L",\"rows\":" + n(Rows) + L",\"queries\":" + n(Queries) + L",\"targets\":" + n(Targets.size()) +
            L",\"watch_cursor\":" + n(WatchCursor) + L",\"suspect_cursor\":" + n(SuspectCursor) +
            L",\"lap_after_pid\":" + n(Previous.AfterPid) + L",\"lap_through_pid\":" + n(Previous.ThroughPid) +
            L",\"reserved_pid\":" + n(proposed.AfterPid) + L",\"reserved_through_pid\":" + n(proposed.ThroughPid) +
            L",\"admission_deferred\":" + DeferredJson() +
            L",\"budget_deferrals\":" + n(Deferrals) + L",\"overruns\":" + n(Overruns) +
            L",\"service_samples\":" + n(Service.Samples) + L",\"service_max_ms\":" + n(Service.MaximumMs) + L"}";
    }
private:
    enum class Phase { Open, Snapshot, RankWatches, RankSuspects, ReserveSnapshot, Watches, Suspects, Done };
    enum class Input { Snapshot, Watch, Suspect };
    struct DeferredScope
    {
        Input Origin;
        bool Displaced;
        uint32_t Pid;
        uint64_t Generation, FirstMs, LastMs, Events;
    };
    Source Reader;
    std::vector<uint32_t> Watches;
    std::vector<KmonUserTarget> Suspects, Targets;
    std::unordered_map<uint32_t, size_t> Have;
    uint32_t Self;
    uint64_t Started, LastClock;
    KmonUserInventoryPosition Previous;
    uint32_t CandidatePid = 0, HighestPid = 0;
    Input CandidateSource = Input::Snapshot;
    std::wstring CandidateLeaf;
    KmonUserTarget DisplacedTarget;
    bool FirstOverflowNominated = false;
    size_t RankIndex = 0;
    static constexpr size_t ScopeLimit = 32;
    std::vector<DeferredScope> Scopes;
    uint64_t DeferredEvents = 0, UnrepresentedEvents = 0;
    Phase Stage = Phase::Open;
    size_t WatchCursor = 0, SuspectCursor = 0, LastSteps = 0, MaxSteps = 0;
    uint64_t Turns = 0, Steps = 0, Rows = 0, Queries = 0, Deferrals = 0, Overruns = 0;
    bool WalkComplete = false, Truncated = false, Cancelled = false, Failed = false, InvalidClock = false;
    KmonLatencyHistogram Service;
    bool Eligible(uint32_t pid) const { return pid > 4 && pid != Self; }
    bool Observe(uint32_t pid, Input source)
    {
        HighestPid = (std::max)(HighestPid, pid);
        // Order by membership in the frozen numeric lap, then by PID. If it
        // empties, start again at the smallest observed PID with a new ceiling.
        if (FirstOverflowNominated || (CandidatePid && std::make_pair(!Previous.InCurrentLap(pid), pid) >=
            std::make_pair(!Previous.InCurrentLap(CandidatePid), CandidatePid))) { return false; }
        CandidatePid = pid;
        CandidateSource = source;
        return true;
    }
    bool FirstOverflow(uint32_t pid, Input source)
    {
        if (Previous.AfterPid || FirstOverflowNominated) { return false; }
        // On the very first capped walk, give the first refused row an
        // immediate slot. Subsequent walks use the last entered PID.
        CandidatePid = pid;
        CandidateSource = source;
        FirstOverflowNominated = true;
        return true;
    }
    void Defer(Input source, uint32_t pid, uint64_t generation, bool displaced = false)
    {
        Truncated = true;
        ++DeferredEvents;
        for (auto& scope : Scopes)
        {
            if (scope.Origin == source && scope.Pid == pid && scope.Generation == generation && scope.Displaced == displaced)
            {
                scope.LastMs = LastClock;
                ++scope.Events;
                return;
            }
        }
        if (Scopes.size() == ScopeLimit)
        {
            if (!displaced) { ++UnrepresentedEvents; return; }
            // Preserve the exact row sacrificed for the reservation even when
            // the rejected-input sample has already filled. Account for every
            // encounter represented by the sample it replaces.
            UnrepresentedEvents += Scopes.back().Events;
            Scopes.pop_back();
        }
        Scopes.push_back({source, displaced, pid, generation, LastClock, LastClock, 1});
    }
    std::wstring DeferredJson() const
    {
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        static const wchar_t* inputs[] = {L"snapshot", L"watch", L"suspect"};
        std::wstring samples;
        for (const auto& scope : Scopes)
        {
            if (!samples.empty()) { samples += L","; }
            samples += L"{\"source\":" + mcpjson::Quote(inputs[static_cast<size_t>(scope.Origin)]) +
                L",\"reason\":" + mcpjson::Quote(scope.Displaced ? L"reserved_slot_displacement" : L"metadata_capacity") +
                L",\"pid\":" + n(scope.Pid) + L",\"generation\":" + (scope.Generation ? n(scope.Generation) : L"null") +
                L",\"first_ms\":" + n(scope.FirstMs) + L",\"last_ms\":" + n(scope.LastMs) +
                L",\"events\":" + n(scope.Events) + L"}";
        }
        return L"{\"scope\":\"this_inventory_capacity_events\",\"events\":" + n(DeferredEvents) +
            L",\"scope_limit\":" + n(ScopeLimit) + L",\"unrepresented_events\":" + n(UnrepresentedEvents) +
            L",\"scopes\":[" + samples + L"]}";
    }
    void DisplaceLast(Input source)
    {
        const auto& displaced = Targets.back();
        Defer(source, displaced.Pid, displaced.CreateTime, true);
        Have.erase(displaced.Pid);
        DisplacedTarget = std::move(Targets.back());
        Targets.pop_back();
    }
    bool HasSlot(size_t limit, Input source, uint32_t pid, uint64_t generation)
    {
        if (Targets.size() < limit) { return true; }
        if (WalkComplete) { FirstOverflow(pid, source); }
        if (WalkComplete && CandidatePid == pid && CandidateSource == source)
        {
            DisplaceLast(source);
            return true;
        }
        Defer(source, pid, generation);
        return false;
    }
    bool MayReachCapacity() const
    {
        const auto freeWatches = WatchLimit - Targets.size();
        return Truncated || Watches.size() > freeWatches ||
            Suspects.size() > SuspectLimit - Targets.size() - (std::min)(Watches.size(), freeWatches);
    }
    void Append(KmonUserTarget target)
    {
        // Allocation failure aborts this inventory; no partially updated map
        // is exposed to a later Run or used as an absence proof.
        Have.emplace(target.Pid, Targets.size()); Targets.push_back(std::move(target));
    }
    void Advance()
    {
        if (Stage == Phase::Open)
        {
            Stage = Reader.Open() ? Phase::Snapshot : Phase::Watches;
            if (Stage == Phase::Watches) { Reader.Close(); }
        }
        else if (Stage == Phase::Snapshot)
        {
            KmonUserTarget target;
            const auto result = Reader.Next(target);
            if (result != KmonUserInventoryRead::Row)
            {
                WalkComplete = result == KmonUserInventoryRead::End;
                Reader.Close();
                Stage = WalkComplete && MayReachCapacity() ? Phase::RankWatches : Phase::Watches;
            }
            else
            {
                ++Rows;
                if (!Eligible(target.Pid)) { return; }
                if (Observe(target.Pid, Input::Snapshot)) { CandidateLeaf = target.Leaf; }
                if (Have.count(target.Pid)) { return; }
                if (Targets.size() >= SnapshotLimit)
                {
                    if (FirstOverflow(target.Pid, Input::Snapshot)) { CandidateLeaf = target.Leaf; }
                    Defer(Input::Snapshot, target.Pid, 0);
                    return;
                }
                ++Queries; Reader.Resolve(target); target.Interesting = true; Append(std::move(target));
            }
        }
        else if (Stage == Phase::RankWatches)
        {
            if (RankIndex == Watches.size()) { RankIndex = 0; Stage = Phase::RankSuspects; return; }
            const auto pid = Watches[RankIndex++];
            if (Eligible(pid)) { Observe(pid, Input::Watch); }
        }
        else if (Stage == Phase::RankSuspects)
        {
            if (RankIndex == Suspects.size()) { Stage = Phase::ReserveSnapshot; return; }
            const auto& target = Suspects[RankIndex++];
            if (Eligible(target.Pid) && target.CreateTime) { Observe(target.Pid, Input::Suspect); }
        }
        else if (Stage == Phase::ReserveSnapshot)
        {
            if (CandidatePid && CandidateSource == Input::Snapshot && !Have.count(CandidatePid))
            {
                KmonUserTarget target;
                target.Pid = CandidatePid; target.Leaf = std::move(CandidateLeaf);
                ++Queries; Reader.Resolve(target); target.Interesting = true;
                DisplaceLast(Input::Snapshot);
                Append(std::move(target));
            }
            Stage = Phase::Watches;
        }
        else if (Stage == Phase::Watches)
        {
            if (WatchCursor == Watches.size()) { Stage = Phase::Suspects; return; }
            const auto pid = Watches[WatchCursor++];
            if (!Eligible(pid) || Have.count(pid)) { return; }
            if (!HasSlot(WatchLimit, Input::Watch, pid, 0)) { return; }
            KmonUserTarget target;
            if (DisplacedTarget.Pid == pid) { target = std::exchange(DisplacedTarget, {}); }
            else { target.Pid = pid; ++Queries; Reader.Resolve(target); }
            target.HighPriority = true; target.Interesting = true; Append(std::move(target));
        }
        else if (Stage == Phase::Suspects)
        {
            if (SuspectCursor == Suspects.size()) { Stage = Phase::Done; Reader.Close(); return; }
            auto& suspect = Suspects[SuspectCursor++];
            if (!Eligible(suspect.Pid) || !suspect.CreateTime) { return; }
            auto found = Have.find(suspect.Pid);
            if (found == Have.end() && DisplacedTarget.Pid == suspect.Pid)
            {
                // The reserved slot evicted a row we already resolved. A
                // later suspect must still pass that native generation fence.
                if (DisplacedTarget.CreateTime && DisplacedTarget.CreateTime != suspect.CreateTime) { return; }
                if (!HasSlot(SuspectLimit, Input::Suspect, suspect.Pid, suspect.CreateTime)) { return; }
                Append(std::exchange(DisplacedTarget, {}));
                found = Have.find(suspect.Pid);
            }
            if (found != Have.end())
            {
                auto& existing = Targets[found->second];
                if (existing.CreateTime != 0 && existing.CreateTime != suspect.CreateTime) { return; }
                if (existing.CreateTime == 0) { existing.ImagePath = suspect.ImagePath; existing.Leaf = suspect.Leaf; }
                existing.CreateTime = suspect.CreateTime; existing.Eprocess = suspect.Eprocess;
                existing.SuspectExpiresMs = suspect.SuspectExpiresMs;
                existing.Suspect = existing.HighPriority = existing.Interesting = true;
            }
            else if (HasSlot(SuspectLimit, Input::Suspect, suspect.Pid, suspect.CreateTime))
            {
                suspect.Suspect = suspect.HighPriority = suspect.Interesting = true; Append(std::move(suspect));
            }
        }
    }
};
