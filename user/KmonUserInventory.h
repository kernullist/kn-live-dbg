#pragma once
#include "KmonDiscoveryScheduling.h"
#include <unordered_map>

struct KmonUserTarget
{
    uint32_t Pid = 0;
    uint64_t CreateTime = 0, Eprocess = 0;
    uint32_t ThreadQueryQuota = 0;
    std::wstring ImagePath, Leaf;
    bool HighPriority = false, Interesting = false, Suspect = false;
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
template<class Source> class KmonUserInventory
{
public:
    static constexpr size_t MaximumSteps = 32;
    static constexpr uint64_t BudgetMs = 25;
    KmonUserInventory(Source source, std::vector<uint32_t> watches,
        std::vector<KmonUserTarget> suspects, uint32_t self, uint64_t started)
        : Reader(std::move(source)), Watches(std::move(watches)), Suspects(std::move(suspects)),
          Self(self), Started(started), LastClock(started) {}
    ~KmonUserInventory() { Reader.Close(); }
    KmonUserInventory(const KmonUserInventory&) = delete;
    KmonUserInventory& operator=(const KmonUserInventory&) = delete;

    bool WalkIncomplete() const { return !WalkComplete; }
    bool Capped() const { return Truncated; }
    bool Complete() const { return Stage == Phase::Done; }
    uint64_t StartedMs() const { return Started; }
    const Source& SourceState() const { return Reader; }
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
            if (now < LastClock) { InvalidClock = true; Cancel(); }
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
        static const wchar_t* names[] = {L"open", L"snapshot", L"watches", L"suspects", L"done"};
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
            L",\"budget_deferrals\":" + n(Deferrals) + L",\"overruns\":" + n(Overruns) +
            L",\"service_samples\":" + n(Service.Samples) + L",\"service_max_ms\":" + n(Service.MaximumMs) + L"}";
    }
private:
    enum class Phase { Open, Snapshot, Watches, Suspects, Done };
    Source Reader;
    std::vector<uint32_t> Watches;
    std::vector<KmonUserTarget> Suspects, Targets;
    std::unordered_map<uint32_t, size_t> Have;
    uint32_t Self;
    uint64_t Started, LastClock;
    Phase Stage = Phase::Open;
    size_t WatchCursor = 0, SuspectCursor = 0, LastSteps = 0, MaxSteps = 0;
    uint64_t Turns = 0, Steps = 0, Rows = 0, Queries = 0, Deferrals = 0, Overruns = 0;
    bool WalkComplete = false, Truncated = false, Cancelled = false, Failed = false, InvalidClock = false;
    KmonLatencyHistogram Service;
    bool Eligible(uint32_t pid) const { return pid > 4 && pid != Self; }
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
                Reader.Close(); Stage = Phase::Watches;
            }
            else
            {
                ++Rows;
                if (!Eligible(target.Pid) || Have.count(target.Pid)) { return; }
                if (Targets.size() >= 4096)
                { Truncated = true; Reader.Close(); Stage = Phase::Watches; return; }
                ++Queries; Reader.Resolve(target); target.Interesting = true; Append(std::move(target));
            }
        }
        else if (Stage == Phase::Watches)
        {
            if (WatchCursor == Watches.size()) { Stage = Phase::Suspects; return; }
            const auto pid = Watches[WatchCursor++];
            if (!Eligible(pid) || Have.count(pid)) { return; }
            if (Targets.size() >= 8192) { Truncated = true; Stage = Phase::Suspects; return; }
            KmonUserTarget target; target.Pid = pid;
            ++Queries; Reader.Resolve(target); target.HighPriority = true; target.Interesting = true; Append(std::move(target));
        }
        else if (Stage == Phase::Suspects)
        {
            if (SuspectCursor == Suspects.size()) { Stage = Phase::Done; Reader.Close(); return; }
            auto& suspect = Suspects[SuspectCursor++];
            if (!Eligible(suspect.Pid) || !suspect.CreateTime) { return; }
            const auto found = Have.find(suspect.Pid);
            if (found != Have.end())
            {
                auto& existing = Targets[found->second];
                if (existing.CreateTime != 0 && existing.CreateTime != suspect.CreateTime) { return; }
                if (existing.CreateTime == 0) { existing.ImagePath = suspect.ImagePath; existing.Leaf = suspect.Leaf; }
                existing.CreateTime = suspect.CreateTime; existing.Eprocess = suspect.Eprocess;
                existing.Suspect = existing.HighPriority = existing.Interesting = true;
            }
            else if (Targets.size() < 12288)
            {
                suspect.Suspect = suspect.HighPriority = suspect.Interesting = true; Append(std::move(suspect));
            }
            else { Truncated = true; Stage = Phase::Done; Reader.Close(); }
        }
    }
};
