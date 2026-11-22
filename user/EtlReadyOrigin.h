#pragma once

#include "EtlScheduleIntervals.h"

namespace etl_profile
{
    // Both switch selectors are original ETW records. A single CSwitch can
    // close the source CPU slice and dispatch the target in the same event.
    struct ReadyOrigin
    {
        struct Span
        {
            SwitchEvent end{};
            IntervalWitnesses witnesses;
        };

        ReadyPoint ready;
        uint32_t headerTid = 0, headerPid = 0;
        uint16_t headerFlags = 0;
        bool observed = false;
        Match match = Match::Other;
        Span source, target;
        ScheduleEdge cpuAtReady, targetAtReady;

        void ObserveContext(ScheduleHistory& history)
        {
            if (ready.at.cpu < history.cpus.size()) { cpuAtReady = history.cpus[ready.at.cpu].lastIn; }
            if (const auto thread = history.Watch(ready.tid)) { targetAtReady = thread->last; }
        }

        void Select(const EVENT_RECORD& e, uint32_t ordinal)
        {
            observed = true;
            match = DecodeReady(e, ordinal, ready);
            headerTid = e.EventHeader.ThreadId;
            headerPid = e.EventHeader.ProcessId;
            headerFlags = e.EventHeader.Flags;
        }

        bool SameReady(const EVENT_RECORD& e, uint32_t ordinal) const
        {
            ReadyPoint p;
            return DecodeReady(e, ordinal, p) == Match::Decoded &&
                p.at.record == ready.at.record && p.at.tick == ready.at.tick && p.at.cpu == ready.at.cpu &&
                p.at.logger == ready.at.logger && p.tid == ready.tid && p.flags == ready.flags &&
                p.reason == ready.reason && p.increment == ready.increment && p.reserved == ready.reserved &&
                e.EventHeader.ThreadId == headerTid && e.EventHeader.ProcessId == headerPid && e.EventHeader.Flags == headerFlags;
        }

        void SelectSwitch(const SwitchEvent& e)
        {
            if (match != Match::Decoded) { return; }
            if (!source.end.record && e.cpu == ready.at.cpu) { source.end = e; }
            if (!target.end.record && e.fields.newTid == ready.tid) { target.end = e; }
        }

        uint32_t ReplayRows() const { return 1u + (source.end.record != 0) + (target.end.record != 0); }

        void ReplaySwitch(ScheduleHistory& history, const SwitchEvent& e, size_t& rows, bool& mismatch)
        {
            const bool cpuEnd = e.record == source.end.record, targetIn = e.record == target.end.record;
            IntervalWitnesses w;
            history.Observe(e, cpuEnd || targetIn ? &w : nullptr);
            if (!cpuEnd && !targetIn) { return; }
            for (auto* span : {&source, &target})
            {
                const auto& first = span->end;
                if (first.record != e.record) { continue; }
                ++rows;
                mismatch |= first.ordinal != e.ordinal || first.timestamp != e.timestamp || first.cpu != e.cpu ||
                    first.flags != e.flags || first.loggerId != e.loggerId || first.version != e.version ||
                    std::memcmp(&first.fields, &e.fields, sizeof(e.fields)) != 0;
                span->witnesses = w;
            }
        }

        ThreadPair Bracket(const ThreadIndex& index, uint32_t tid, bool qpc, bool gap) const
        {
            auto pair = index.Lookup(tid, ready.at.record, ready.at.tick, qpc, gap);
            if (pair.pairedPid && (pair.before->mixedLoggers || pair.before->logger != ready.at.logger))
            {
                pair.pairedPid = false;
                pair.relation = L"logger_conflict";
            }
            return pair;
        }

        ReportedSpan Assess(const ScheduleHistory& history, const ThreadPair& pair, bool running, bool qpc, bool gap) const
        {
            const auto& span = running ? source : target;
            if (!span.end.record) { return {running ? L"no_following_cpu_switch" : L"no_following_target_switch_in"}; }
            const ScheduleSlice slice{span.end, span.witnesses, running, 0, 0};
            const auto& start = slice.Start();
            if (gap) { return {L"coverage_unqualified"}; }
            if (!qpc || history.reversedClock) { return {L"clock_unqualified"}; }
            if (!SameTransition(start, running ? cpuAtReady : targetAtReady)) { return {L"intervening_transition"}; }
            if (!start.switchOrdinal) { return {start.at.record ? L"thread_boundary" : L"no_preceding_switch"}; }
            if (ready.at.cpu >= history.cpus.size() || ready.at.indexed != history.indexed)
            { return {L"processor_scope_unqualified"}; }
            if (start.at.record >= ready.at.record || ready.at.record >= span.end.record ||
                start.at.tick >= ready.at.tick || ready.at.tick >= span.end.timestamp)
            { return {L"ready_outside_switches"}; }
            if (running && !span.end.fields.oldTid)
            {
                if (start.at.logger != ready.at.logger || span.end.loggerId != ready.at.logger) { return {L"logger_conflict"}; }
                return AssessSpan(history, span.end, span.witnesses, true, qpc, gap);
            }
            return slice.Assess(history, ready.at.logger, pair, qpc, gap);
        }

        ReportedSpan Dispatch(const ScheduleHistory& history, const ReportedSpan& off) const
        {
            const auto& w = target.witnesses;
            const auto split = AssessReady(w.ready, w.previousIncomingThread, target.end, off.measured,
                history.unsupportedReady + history.unassignedReady, true);
            if (!split.measured) { return split; }
            if (w.ready.invalidProcessorScope) { return {L"ready_scope_unqualified"}; }
            if (w.ready.last.at.record != ready.at.record) { return {L"selected_record_not_dispatchable"}; }
            return split;
        }

        struct HeaderAgreement { const wchar_t* relation; bool usable; };

        HeaderAgreement HeaderBinding(const ThreadPair& sourcePair) const
        {
            if (headerTid == UINT32_MAX && headerPid == UINT32_MAX) { return {L"unreported", true}; }
            if ((headerTid != UINT32_MAX && source.end.record && headerTid != source.end.fields.oldTid) ||
                (headerPid != UINT32_MAX && sourcePair.pairedPid && headerPid != sourcePair.before->pid))
            { return {L"conflict", false}; }
            if (!source.end.record || !sourcePair.pairedPid || headerTid == UINT32_MAX || headerPid == UINT32_MAX)
            { return {L"incomplete", false}; }
            return {L"matched", true};
        }

        ReportedSpan Relationship(const ReportedSpan& cpu, const ReportedSpan& dispatch, const ThreadPair& sourcePair) const
        {
            if (ready.flags & ReadyDpc) { return {L"dpc_context"}; }
            if (source.end.record && !source.end.fields.oldTid) { return {L"idle_context"}; }
            if (!cpu.measured) { return cpu; }
            if (!dispatch.measured) { return dispatch; }
            if (target.witnesses.previousIncomingThread.state != 5) { return {L"target_not_reported_waiting"}; }
            if (source.end.fields.oldTid == ready.tid) { return {L"same_thread"}; }
            if (!HeaderBinding(sourcePair).usable) { return {L"ready_header_unqualified"}; }
            return {L"readying_thread_context", true};
        }
    };
}
