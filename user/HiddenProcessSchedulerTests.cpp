#include "HiddenProcessScheduler.h"

#include <cstdio>
#include <functional>
#include <sstream>

namespace
{
    class Source final : public HiddenProcessQualificationSource
    {
    public:
        uint64_t NowMs() const override { return Now; }
        uint64_t Epoch() const override { return Connection; }
        bool Cancelled() const override { return Stop; }
        HiddenProcessLifetime ReadLifetime(uint32_t pid, uint64_t deadline) override
        {
            const bool after = Compared;
            (after ? After : Before).push_back(pid);
            Now += Cost;
            if (OnRead)
            {
                OnRead(pid, after);
            }
            HiddenProcessLifetime value;
            if (Failed.count(pid) != 0 || Now >= deadline || Stop)
            {
                return value;
            }
            value.Pid = pid;
            value.Eprocess = 0xffff800000000000ull + uint64_t{pid} * 4096;
            value.CreateTime = Generation + pid;
            value.IdentityValid = true;
            value.HasExitTime = true;
            value.HasActiveThreads = true;
            value.ActiveThreads = 3;
            value.HasAuxiliary = true;
            value.HasStateFlags = true;
            return value;
        }
        HiddenProcessComparison Compare(uint64_t deadline) override
        {
            HiddenProcessComparison result;
            result.StartedMs = Now;
            Now += ComparisonCost;
            Compared = true;
            if (OnCompare)
            {
                OnCompare();
            }
            result.Kernel.Complete = result.SpiComplete = result.ToolhelpComplete = Now < deadline && !Stop;
            result.FinishedMs = Now;
            return result;
        }
        void Begin()
        {
            Before.clear();
            After.clear();
            Compared = false;
            Stop = false;
            Now += 5000;
        }
        uint64_t Now = 100;
        uint64_t Connection = 1;
        uint64_t Generation = 100000;
        uint64_t Cost = 1;
        uint64_t ComparisonCost = 10;
        bool Stop = false;
        bool Compared = false;
        std::set<uint32_t> Failed;
        std::vector<uint32_t> Before;
        std::vector<uint32_t> After;
        std::function<void(uint32_t, bool)> OnRead;
        std::function<void()> OnCompare;
    };

    std::vector<HiddenProcessRecord> Candidates(uint32_t count, uint32_t first = 100)
    {
        std::vector<HiddenProcessRecord> values(count);
        for (uint32_t i = 0; i < count; ++i)
        {
            values[i].ProcessId = first + i;
            values[i].InCidTable = true;
        }
        return values;
    }

    HiddenProcessScanResult Run(HiddenProcessScheduler& scheduler, Source& source,
        std::vector<HiddenProcessRecord>& values, uint64_t budget = 5000)
    {
        source.Begin();
        HiddenProcessScanResult result;
        result.InventoryComplete = result.CoverageComplete = true;
        std::vector<HiddenProcessRecord*> pointers;
        for (auto& value : values)
        {
            pointers.push_back(&value);
        }
        scheduler.Qualify(source, pointers, result, budget);
        for (const auto& value : values)
        {
            AddHiddenProcessDecision(result, value);
        }
        return result;
    }
}

bool HiddenProcessSchedulerSelfTest(uint32_t* checks)
{
    uint32_t count = 0;
    bool passed = true;
    const auto check = [&](bool condition, const char* name)
    {
        ++count;
        if (!condition)
        {
            passed = false;
            std::fprintf(stderr, "hidden-process scheduler: %s (%u)\n", name, count);
        }
    };
    // Exercise the production orchestrator, not a model of its selection rule.
    for (uint32_t size : {257u, 1025u})
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(size);
        std::map<uint32_t, uint32_t> visits;
        const uint32_t rounds = (size + 127) / 128;
        for (uint32_t round = 0; round < rounds; ++round)
        {
            const auto result = Run(scheduler, source, values);
            check(result.Scheduling.Attempted == 128 && result.Scheduling.Deferred == size - 128,
                "stable exact attempt denominator");
            check(result.UnverifiedCount == size - 128 && result.SuspiciousCount == 128,
                "stable dispositions retain unvisited scope");
            check(source.Before == source.After, "same-batch fresh boundaries");
            for (auto pid : source.After)
            {
                ++visits[pid];
            }
        }
        check(visits.size() == size, "whole stable cohort receives service");
        for (const auto& visit : visits)
        {
            check(visit.second <= 2, "stable rotation avoids prefix monopoly");
        }
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(1025);
        // Each round admits fresh high-risk candidates and removes the previous
        // arrivals; the original cohort must progress despite that priority load.
        std::set<uint32_t> visited;
        for (uint32_t round = 0; round < 12; ++round)
        {
            values.resize(1025);
            auto arrivals = Candidates(200, 10000 + round * 200);
            values.insert(values.end(), arrivals.begin(), arrivals.end());
            for (uint32_t i = 0; i < 1025; ++i)
            {
                values[i].InSystemProcessInfo = true;
            }
            const auto result = Run(scheduler, source, values);
            uint32_t oldService = 0;
            for (auto pid : source.Before)
            {
                if (pid < 10000)
                {
                    visited.insert(pid);
                    ++oldService;
                }
            }
            check(oldService >= 96, "old cohort reserves three quarters under priority churn");
            check(result.Records.size() == 1225, "churn preserves current candidate denominator");
        }
        check(visited.size() == 1025, "churn cannot starve fixed cohort");
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(257);
        for (uint32_t pid = 100; pid < 228; ++pid)
        {
            source.Failed.insert(pid);
        }
        auto first = Run(scheduler, source, values);
        check(first.SuspiciousCount == 0 && first.UnverifiedCount == 257, "failed prefix remains unverified");
        auto second = Run(scheduler, source, values);
        check(second.SuspiciousCount == 128 && source.Before.front() == 228, "failed prefix rotates");
        check(second.Scheduling.MaxServicedWaitMs >= 5000, "pending age survives refresh");
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(257);
        source.Cost = 100;
        auto first = Run(scheduler, source, values);
        check(first.Scheduling.Attempted == 15 && first.Scheduling.CompletedBoundaries == 14,
            "before phase preserves comparison and after time");
        check(first.SuspiciousCount == 14 && first.UnverifiedCount == 243,
            "before deadline failure is not fabricated success");
        check(first.Records[14].Decision.Reason == std::wstring(L"qualification_budget"),
            "before phase timeout keeps its budget reason");
        auto second = Run(scheduler, source, values);
        check(second.Scheduling.BatchLimit < 128 && second.Scheduling.Attempted <= second.Scheduling.BatchLimit,
            "batch adapts to measured lifetime cost");
        check(source.Before.front() == 115, "partial before batch advances only attempted candidates");
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(257);
        source.OnRead = [&](uint32_t, bool after) { if (!after) source.Stop = true; };
        const auto stopped = Run(scheduler, source, values);
        check(stopped.Scheduling.Attempted == 1 && stopped.Scheduling.Deferred == 256,
            "cancelled exact admission denominator");
        check(stopped.UnverifiedCount == 257 && !source.Compared, "cancel before inventories preserves unknowns");
        check(stopped.Records.front().Decision.Reason == std::wstring(L"qualification_cancelled"),
            "cancel reason distinct from budget");
        source.OnRead = {};
        const auto next = Run(scheduler, source, values);
        check(source.Before.front() == 101 && next.SuspiciousCount == 128, "cancelled attempt rotates on resume");
        ++source.Connection;
        Run(scheduler, source, values);
        check(source.Before.front() == 100, "source replacement resets hints");
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(4);
        source.OnCompare = [&]() { ++source.Generation; };
        const auto reused = Run(scheduler, source, values);
        check(reused.UnverifiedCount == 4 && reused.SuspiciousCount == 0, "PID reuse cannot join boundary lifetimes");
        source.OnCompare = {};
        const auto fresh = Run(scheduler, source, values);
        check(fresh.SuspiciousCount == 4, "next batch uses only fresh same-generation samples");
        source.OnCompare = [&]() { ++source.Connection; };
        const auto changed = Run(scheduler, source, values);
        check(changed.SuspiciousCount == 0 && changed.UnverifiedCount == 4 && source.After.empty(),
            "source switch cannot join comparison and samples");
        source.OnCompare = {};
        const auto emptyBudget = Run(scheduler, source, values, 0);
        check(emptyBudget.UnverifiedCount == 4 && source.Before.empty() && source.After.empty(),
            "zero budget clears previously successful samples");
        source.Connection = 0;
        const auto unavailable = Run(scheduler, source, values);
        check(unavailable.Scheduling.Attempted == 0 && unavailable.UnverifiedCount == 4,
            "unavailable source is never attempted");
    }
    {
        HiddenProcessScheduler scheduler;
        Source source;
        auto values = Candidates(2);
        source.OnCompare = [&]() { source.Stop = true; };
        const auto cancelled = Run(scheduler, source, values);
        check(cancelled.UnverifiedCount == 2 && source.After.empty(), "cancel during comparison");
        source.OnCompare = {};
        source.OnRead = [&](uint32_t pid, bool after) { if (after && pid == 101) source.Stop = true; };
        const auto partial = Run(scheduler, source, values);
        check(partial.SuspiciousCount == 1 && partial.UnverifiedCount == 1,
            "cancel preserves already completed positive observation");
        source.OnRead = {};
        source.ComparisonCost = 6000;
        const auto slow = Run(scheduler, source, values);
        check(slow.SuspiciousCount == 0 && slow.UnverifiedCount == 2 && source.After.empty(),
            "single slow API leaves all after samples unverified");
        values.clear();
        const auto empty = Run(scheduler, source, values);
        check(empty.Scheduling.Candidates == 0 && empty.Scheduling.MaxPendingWaitMs == 0,
            "departed candidates release queue state");
    }
    if (checks != nullptr)
    {
        *checks = count;
    }
    return passed;
}

std::wstring BuildHiddenProcessSchedulingFixture()
{
    HiddenProcessScheduler scheduler;
    Source source;
    auto values = Candidates(257);
    std::wostringstream json;
    json << L"[";
    for (uint32_t round = 0; round < 3; ++round)
    {
        if (round != 0)
        {
            json << L",";
        }
        const auto result = Run(scheduler, source, values);
        json << BuildHiddenProcessJson(result);
    }
    json << L"]";
    return json.str();
}
