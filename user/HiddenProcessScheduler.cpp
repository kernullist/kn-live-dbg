#include "HiddenProcessScheduler.h"

#include <algorithm>
#include <limits>

namespace
{
    uint64_t Elapsed(uint64_t begin, uint64_t end)
    {
        return end >= begin ? end - begin : 0;
    }

    uint64_t Deadline(uint64_t begin, uint64_t allowance)
    {
        return allowance > UINT64_MAX - begin ? UINT64_MAX : begin + allowance;
    }

    uint64_t RecentCost(uint64_t previous, uint64_t measured)
    {
        // React immediately to slow calls; recover gradually after cheap ones.
        return (std::max)(uint64_t{1}, (std::max)(measured, previous - previous / 4));
    }
}

void HiddenProcessScheduler::Qualify(HiddenProcessQualificationSource& source,
    const std::vector<HiddenProcessRecord*>& candidates,
    HiddenProcessScanResult& result, uint64_t budgetMs)
{
    std::lock_guard<std::mutex> lock(Mutex);
    auto& stats = result.Scheduling;
    stats = {};
    result.ComparisonStartedMs = result.ComparisonFinishedMs = 0;
    stats.SourceEpoch = source.Epoch();
    stats.StartedMs = source.NowMs();
    stats.Candidates = static_cast<uint32_t>(candidates.size());
    if (SourceEpoch != stats.SourceEpoch || stats.SourceEpoch == 0)
    {
        Entries.clear();
        Order.clear();
        SourceEpoch = stats.SourceEpoch;
        LifetimeCostMs = 1;
        InventoryCostMs = 2000;
    }

    std::map<uint32_t, HiddenProcessRecord*> current;
    for (auto* candidate : candidates)
    {
        // Never reuse a prior before/after sample, even if a caller reuses output.
        candidate->Qualification = {};
        candidate->Qualification.BudgetExceeded = true;
        current.emplace(candidate->ProcessId, candidate);
    }
    for (auto it = Entries.begin(); it != Entries.end();)
    {
        if (current.count(it->first) == 0)
        {
            Order.erase(it->second.Position);
            it = Entries.erase(it);
        }
        else
        {
            ++it;
        }
    }
    for (const auto& item : current)
    {
        if (Entries.count(item.first) == 0)
        {
            const auto& candidate = *item.second;
            const bool priority = !candidate.InSystemProcessInfo && !candidate.InToolhelp;
            Order.push_back(item.first);
            try
            {
                Entries.emplace(item.first, Pending{std::prev(Order.end()), stats.StartedMs, priority});
            }
            catch (...)
            {
                Order.pop_back();
                throw;
            }
        }
    }

    // Leave room for fresh inventories and all after samples. Recent costs adapt
    // the batch size; a slow individual call can still overrun either deadline.
    budgetMs = (std::min)(budgetMs, uint64_t{5000});
    const uint64_t inventoryReserve = (std::min)(InventoryCostMs, budgetMs / 2);
    const uint64_t boundaryAllowance = (budgetMs - inventoryReserve) / 2;
    stats.BatchLimit = static_cast<uint32_t>((std::min)(uint64_t{128},
        (std::max)(uint64_t{1}, boundaryAllowance / LifetimeCostMs)));
    const uint64_t beforeDeadline = Deadline(stats.StartedMs, boundaryAllowance);
    const uint64_t deadline = Deadline(stats.StartedMs, budgetMs);

    std::vector<HiddenProcessRecord*> selected;
    std::set<uint32_t> selectedPids;
    auto oldest = Order.begin();
    auto priority = Order.begin();
    for (uint32_t slot = 0; slot < stats.BatchLimit && selected.size() < current.size(); ++slot)
    {
        // At least three in four slots serve the oldest pending candidates.
        // With a one-item batch the old cohort always receives service.
        auto chosen = Order.end();
        if (slot % 4 == 3)
        {
            while (priority != Order.end() &&
                (!Entries.at(*priority).NewPriority || selectedPids.count(*priority) != 0))
            {
                ++priority;
            }
            if (priority != Order.end())
            {
                chosen = priority++;
            }
        }
        if (chosen == Order.end())
        {
            while (oldest != Order.end() && selectedPids.count(*oldest) != 0)
            {
                ++oldest;
            }
            if (oldest == Order.end())
            {
                break;
            }
            chosen = oldest++;
        }
        selectedPids.insert(*chosen);
        selected.push_back(current.at(*chosen));
    }
    stats.Selected = static_cast<uint32_t>(selected.size());

    const auto sourceChanged = [&]() { return stats.SourceEpoch == 0 || source.Epoch() != stats.SourceEpoch; };
    uint64_t slowestLifetimeMs = 0;
    std::vector<HiddenProcessRecord*> attempted;
    attempted.reserve(selected.size());
    for (auto* candidate : selected)
    {
        if (source.Cancelled() || sourceChanged() || source.NowMs() >= beforeDeadline)
        {
            break;
        }
        auto& pending = Entries.at(candidate->ProcessId);
        const uint64_t begin = source.NowMs();
        stats.MaxServicedWaitMs = (std::max)(stats.MaxServicedWaitMs, Elapsed(pending.SinceMs, begin));
        // Advance failed attempts as well. A failing prefix cannot monopolize the
        // next scan. Selection without an actual attempt does not advance it.
        Order.splice(Order.end(), Order, pending.Position);
        pending.SinceMs = begin;
        pending.NewPriority = false;
        auto& q = candidate->Qualification;
        q.Attempted = true;
        q.BudgetExceeded = false;
        attempted.push_back(candidate);
        q.Before = source.ReadLifetime(candidate->ProcessId, beforeDeadline);
        q.BudgetExceeded = source.NowMs() >= beforeDeadline;
        slowestLifetimeMs = (std::max)(slowestLifetimeMs, Elapsed(begin, source.NowMs()));
    }
    stats.Attempted = static_cast<uint32_t>(attempted.size());
    stats.Deferred = stats.Candidates - stats.Attempted;
    if (!attempted.empty() && !source.Cancelled() && !sourceChanged() && source.NowMs() < deadline)
    {
        const uint64_t begin = source.NowMs();
        const auto comparison = source.Compare(deadline);
        InventoryCostMs = RecentCost(InventoryCostMs, Elapsed(begin, source.NowMs()));
        result.ComparisonStartedMs = comparison.StartedMs;
        result.ComparisonFinishedMs = comparison.FinishedMs;
        result.Warnings.insert(result.Warnings.end(), comparison.Warnings.begin(), comparison.Warnings.end());
        for (auto* candidate : attempted)
        {
            auto& q = candidate->Qualification;
            if (source.Cancelled() || sourceChanged() || source.NowMs() >= deadline)
            {
                q.BudgetExceeded = q.BudgetExceeded || source.NowMs() >= deadline;
                q.Cancelled = source.Cancelled();
                q.SourceChanged = sourceChanged();
                continue;
            }
            q.KernelComplete = comparison.Kernel.Complete;
            q.SpiComplete = comparison.SpiComplete;
            q.ToolhelpComplete = comparison.ToolhelpComplete;
            const auto found = comparison.Kernel.Entries.find(candidate->ProcessId);
            q.Views.Kernel = found != comparison.Kernel.Entries.end();
            if (q.Views.Kernel)
            {
                q.KernelIdentity = found->second;
            }
            q.Views.Spi = comparison.Spi.count(candidate->ProcessId) != 0;
            q.Views.Toolhelp = comparison.Toolhelp.count(candidate->ProcessId) != 0;
            const uint64_t sampleBegin = source.NowMs();
            q.After = source.ReadLifetime(candidate->ProcessId, deadline);
            slowestLifetimeMs = (std::max)(slowestLifetimeMs, Elapsed(sampleBegin, source.NowMs()));
            q.BudgetExceeded = q.BudgetExceeded || source.NowMs() >= deadline;
            q.Cancelled = source.Cancelled();
            q.SourceChanged = sourceChanged();
            if (!q.BudgetExceeded && !q.Cancelled && !q.SourceChanged)
            {
                ++stats.CompletedBoundaries;
            }
        }
    }
    LifetimeCostMs = RecentCost(LifetimeCostMs, slowestLifetimeMs);
    const bool batchSourceChanged = sourceChanged();
    for (auto* candidate : candidates)
    {
        auto& q = candidate->Qualification;
        // A connection change invalidates the whole batch. Cancellation only
        // marks unfinished boundaries; already finished observations survive.
        q.SourceChanged = q.SourceChanged || batchSourceChanged;
        if (!q.After.IdentityValid)
        {
            q.Cancelled = q.Cancelled || source.Cancelled();
            q.BudgetExceeded = q.BudgetExceeded || source.NowMs() >= deadline;
        }
    }
    stats.FinishedMs = source.NowMs();
    for (const auto& entry : Entries)
    {
        stats.MaxPendingWaitMs = (std::max)(stats.MaxPendingWaitMs, Elapsed(entry.second.SinceMs, stats.FinishedMs));
    }
}
