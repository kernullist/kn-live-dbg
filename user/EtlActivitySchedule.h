#pragma once

#include "EtlActivityWindow.h"
#include "EtlScheduleIntervals.h"

namespace etl_profile
{
    struct ActivitySchedule
    {
        std::vector<ScheduleSlice> page;
        struct ReadyTotals
        {
            uint32_t intervals = 0;
            uint64_t before = 0, after = 0, waitingBefore = 0;
        };
        uint32_t count = 0, offIntervals = 0;
        uint64_t running = 0, offCpu = 0;
        ReadyTotals split;
        int64_t cursor = 0;
        const wchar_t* intervalIssue = nullptr;

        ReadyTotals Readiness(const ScheduleHistory& history) const
        {
            return history.unsupportedReady || history.unassignedReady ? ReadyTotals{} : split;
        }

        void Prepare(int64_t start, uint32_t limit)
        {
            cursor = start;
            page.reserve(limit);
        }

        void Observe(ScheduleHistory& history, const SwitchEvent& e, const ActivityWindow& w, uint32_t after, uint32_t limit)
        {
            VisitScheduleSlices(history, e, w.start.tid, w.boundaryIssue ? 0 : w.start.tick, w.stop.tick,
                [&](const ScheduleSlice& slice) {
                    if (++count > after && page.size() < limit) { page.push_back(slice); }
                    if (intervalIssue) { return; }
                    const auto span = slice.Assess(history, w.start.logger, w.thread, true, false);
                    if (!span.measured) { intervalIssue = span.relation; return; }
                    if (slice.beginTick != cursor) { intervalIssue = L"incomplete_switch_coverage"; return; }
                    cursor = slice.endTick;
                    const auto ticks = TickDistance(slice.beginTick, slice.endTick);
                    if (slice.running) { running += ticks; return; }
                    ++offIntervals;
                    offCpu += ticks;
                    const auto ready = AssessReady(slice.witnesses.ready, slice.Start(), e, true,
                        history.unsupportedReady + history.unassignedReady);
                    if (!ready.measured) { return; }
                    ++split.intervals;
                    const auto pivot = slice.ReadyPivot();
                    const auto before = TickDistance(slice.beginTick, pivot);
                    split.before += before;
                    split.after += TickDistance(pivot, slice.endTick);
                    if (slice.Start().state == 5) { split.waitingBefore += before; }
                });
        }

        // A later record on this logger can invalidate every previously observed interval.
        const wchar_t* Issue(const ActivityWindow& w, const ScheduleHistory& history, bool gap) const
        {
            if (const auto issue = w.WindowIssue()) { return issue; }
            if (gap || history.unsupportedBoundaries || history.unknownSwitchTid) { return L"coverage_unqualified"; }
            if (!history.seenSwitch) { return L"no_switch_records"; }
            if (history.ambiguousScope || history.logger != w.start.logger) { return L"scheduler_scope_unqualified"; }
            if (history.reversedClock || history.cpuClockConflicts) { return L"clock_unqualified"; }
            if (history.cpuConflicts) { return L"cpu_history_conflict"; }
            const auto thread = history.Find(w.start.tid);
            if (thread == history.threads.end() || thread->tid != w.start.tid || thread->badTransitions)
            { return L"thread_transition_conflict"; }
            if (thread->badClock) { return L"clock_unqualified"; }
            if (intervalIssue) { return intervalIssue; }
            return cursor == w.stop.tick ? nullptr : L"incomplete_switch_coverage";
        }
    };
}
