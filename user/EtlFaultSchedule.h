#pragma once

#include "EtlHardFault.h"
#include "EtlScheduleIntervals.h"

namespace etl_profile
{
    inline ThreadPair FaultThreadPair(const ThreadIndex& index, const HardFault& fault, bool qpc, bool gap)
    {
        auto pair = index.Lookup(fault.faultingTid, fault.record, fault.timestamp, qpc, gap);
        if (pair.pairedPid)
        {
            if (pair.before->mixedLoggers || pair.before->logger != fault.loggerId)
            { pair.pairedPid = false; pair.relation = L"logger_conflict"; }
            else if (pair.before->tick >= fault.initialTime)
            { pair.pairedPid = false; pair.relation = L"start_outside_bracket"; }
        }
        return pair;
    }

    struct FaultSchedule
    {
        std::vector<ScheduleSlice> slices;
        uint32_t switches = 0, unsupportedSwitches = 0, candidates = 0;
        bool qpc = false;

        void Prepare(bool comparable)
        {
            qpc = comparable;
            slices.reserve(MaxPageRows);
        }

        void Observe(ScheduleHistory& history, const SwitchEvent& e, const HardFault& fault)
        {
            VisitScheduleSlices(history, e, fault.faultingTid, qpc ? fault.initialTime : 0, fault.timestamp,
                [&](const ScheduleSlice& slice) {
                    ++candidates;
                    if (slices.size() < MaxPageRows) { slices.push_back(slice); }
                });
        }

        struct Partition
        {
            const wchar_t* status;
            uint64_t running = 0, offCpu = 0;
            bool measured = false;
        };

        Partition Summarize(const ScheduleHistory& history, const HardFault& fault, const ThreadPair& pair, bool gap) const
        {
            if (!qpc) { return {L"clock_unqualified"}; }
            const auto elapsed = fault.OrderedTicks();
            if (!elapsed) { return {L"invalid_fault_interval"}; }
            if (!*elapsed) { return {L"zero_duration"}; }
            if (!fault.faultingTid || fault.faultingTid == UINT32_MAX) { return {L"unusable_tid"}; }
            if (gap || unsupportedSwitches || history.unsupportedBoundaries || history.unknownSwitchTid) { return {L"coverage_unqualified"}; }
            if (!history.seenSwitch) { return {L"no_switch_records"}; }
            if (history.logger != fault.loggerId || history.ambiguousScope) { return {L"scheduler_scope_unqualified"}; }
            if (history.reversedClock || history.cpuClockConflicts) { return {L"clock_unqualified"}; }
            if (history.cpuConflicts) { return {L"cpu_history_conflict"}; }
            if (!pair.pairedPid) { return {L"thread_bracket_unqualified"}; }
            if (candidates != slices.size()) { return {L"interval_limit"}; }
            Partition result{L"covered", 0, 0, true};
            auto cursor = fault.initialTime;
            for (const auto& slice : slices)
            {
                const auto span = slice.Assess(history, fault.loggerId, pair, qpc, gap || unsupportedSwitches);
                if (!span.measured) { return {span.relation}; }
                if (cursor != slice.beginTick) { return {L"incomplete_switch_coverage"}; }
                (slice.running ? result.running : result.offCpu) += TickDistance(slice.beginTick, slice.endTick);
                cursor = slice.endTick;
            }
            if (cursor != fault.timestamp) { return {L"incomplete_switch_coverage"}; }
            return result;
        }
    };
}
