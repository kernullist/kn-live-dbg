#pragma once

#include "EtlHardFault.h"
#include "EtlScheduleIntervals.h"

namespace etl_profile
{
    struct FaultSlice
    {
        SwitchEvent end;
        IntervalWitnesses witnesses;
        bool running;
        int64_t beginTick, endTick; // Intersection with the selected fault window.

        const ScheduleEdge& Start() const
        {
            return running ? witnesses.previousCpu : witnesses.previousIncomingThread;
        }

        int64_t ReadyPivot() const { return std::clamp(witnesses.ready.last.at.tick, beginTick, endTick); }

        ScheduleEdge End() const
        {
            const ScheduleRef at{end.timestamp, end.record, end.cpu, end.loggerId,
                (end.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) != 0};
            return {at, running ? EdgeKind::Out : EdgeKind::In, running ? end.fields.oldTid : end.fields.newTid,
                end.ordinal, 0, end.version, 36, end.fields.oldState, end.fields.oldWaitReason};
        }
    };

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
        std::vector<FaultSlice> slices;
        uint32_t switches = 0, unsupportedSwitches = 0, candidates = 0;
        bool qpc = false;

        void Prepare(bool comparable)
        {
            qpc = comparable;
            slices.reserve(MaxPageRows);
        }

        void Observe(ScheduleHistory& history, const SwitchEvent& e, const HardFault& fault)
        {
            const auto tid = fault.faultingTid;
            const bool outgoing = e.fields.oldTid == tid, incoming = e.fields.newTid == tid;
            if (!qpc || !tid || tid == UINT32_MAX || (!outgoing && !incoming) || !fault.OrderedTicks())
            { history.Observe(e, nullptr); return; }

            IntervalWitnesses witnesses;
            history.Observe(e, &witnesses);
            const auto retain = [&](bool running, const ScheduleEdge& start)
            {
                if (!start.switchOrdinal) { return; }
                const auto begin = (std::max)(start.at.tick, fault.initialTime);
                const auto end = (std::min)(e.timestamp, fault.timestamp);
                if (begin >= end) { return; }
                ++candidates;
                if (slices.size() < MaxPageRows) { slices.push_back({e, witnesses, running, begin, end}); }
            };
            if (outgoing) { retain(true, witnesses.previousCpu); }
            if (incoming) { retain(false, witnesses.previousIncomingThread); }
        }

        ReportedSpan Assess(const FaultSlice& slice, const ScheduleHistory& history,
            const HardFault& fault, const ThreadPair& pair, bool gap) const
        {
            const auto& start = slice.Start().at;
            if (history.unknownSwitchTid) { return {L"coverage_unqualified"}; }
            if (history.cpuConflicts) { return {L"cpu_history_conflict"}; }
            if (history.cpuClockConflicts) { return {L"clock_unqualified"}; }
            if (start.logger != fault.loggerId || slice.end.loggerId != fault.loggerId) { return {L"logger_conflict"}; }
            if (!pair.pairedPid) { return {L"thread_bracket_unqualified"}; }
            if (start.record <= pair.before->record || slice.end.record >= pair.after->record ||
                start.tick <= pair.before->tick || slice.end.timestamp >= pair.after->tick)
            { return {L"switch_outside_bracket"}; }
            return AssessSpan(history, slice.end, slice.witnesses, slice.running, qpc, gap || unsupportedSwitches);
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
                const auto span = Assess(slice, history, fault, pair, gap);
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
