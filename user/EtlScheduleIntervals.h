#pragma once

#include "EtlSwitchRecord.h"
#include "EtlThreadEvidence.h"
#include <algorithm>
#include <vector>

namespace etl_profile
{
    struct ScheduleRef
    {
        int64_t tick = 0;
        uint32_t record = 0, cpu = 0;
        uint16_t logger = 0;
        bool indexed = false;
    };

    inline ScheduleRef EventRef(const EVENT_RECORD& event, uint32_t ordinal)
    {
        return {event.EventHeader.TimeStamp.QuadPart, ordinal, GetEventProcessorIndex(&event),
            event.BufferContext.LoggerId, (event.EventHeader.Flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) != 0};
    }

    struct ReadyPoint
    {
        ScheduleRef at;
        uint32_t tid = 0;
        int8_t reason = 0, increment = 0, reserved = 0;
        uint8_t flags = 0;
    };

    inline Match DecodeReady(const EVENT_RECORD& event, uint32_t record, ReadyPoint& point)
    {
        const auto& h = event.EventHeader;
        if (!IsEqualGUID(h.ProviderId, ThreadProvider) || h.EventDescriptor.Opcode != 50) { return Match::Other; }
        if (!ClassicPointerWidth(h, 2) || !event.UserData || event.UserDataLength != 8 ||
            (event.ExtendedDataCount && !event.ExtendedData)) { return Match::Unsupported; }
        const auto* p = static_cast<const uint8_t*>(event.UserData);
        point.at = EventRef(event, record);
        std::memcpy(&point.tid, p, 4);
        std::memcpy(&point.reason, p + 4, 1);
        std::memcpy(&point.increment, p + 5, 1);
        point.flags = p[6];
        std::memcpy(&point.reserved, p + 7, 1);
        return Match::Decoded;
    }

    enum class EdgeKind { None, In, Out, Boundary };

    struct ScheduleEdge
    {
        ScheduleRef at;
        EdgeKind kind = EdgeKind::None;
        uint32_t tid = 0, switchOrdinal = 0, pid = 0;
        uint8_t version = 0, opcode = 0;
        int8_t state = 0, reason = 0;
    };

    inline constexpr unsigned ReadyDpc = 1, ReadyDeferredFlags = 6, ReadyDirectSwitchAttempt = 8;

    inline unsigned DispatchableReadyFlags(bool allowDirectSwitch)
    {
        return ReadyDpc | (allowDirectSwitch ? ReadyDirectSwitchAttempt : 0u);
    }

    struct ReadySequence
    {
        ReadyPoint first, last;
        uint32_t count = 0, dispatchable = 0;
        bool unknownFlags = false, badClock = false, mixedLogger = false, invalidProcessorScope = false;

        void Append(const ReadyPoint& p, bool allowDirectSwitch = false)
        {
            if (!count) { first = p; }
            else
            {
                badClock |= last.at.tick >= p.at.tick;
                mixedLogger |= last.at.logger != p.at.logger;
                invalidProcessorScope |= last.at.indexed != p.at.indexed;
            }
            ++count;
            const auto dispatchMask = DispatchableReadyFlags(allowDirectSwitch);
            unknownFlags |= (p.flags & ~(ReadyDeferredFlags | dispatchMask)) != 0 || (allowDirectSwitch && p.reserved != 0);
            if ((p.flags & ~dispatchMask) == 0) { ++dispatchable; }
            last = p;
        }
    };

    struct IntervalWitnesses
    {
        ScheduleEdge previousCpu, previousOutgoingThread, previousIncomingThread;
        ReadySequence ready;
    };

    // One switch can carry different roles for different threads on the same record.
    inline bool SameTransition(const ScheduleEdge& a, const ScheduleEdge& b)
    {
        return a.at.record == b.at.record && a.kind == b.kind && a.tid == b.tid;
    }

    struct CpuSchedule
    {
        ScheduleEdge lastIn;
        bool badTransitions = false, badClock = false;
    };

    struct ThreadSchedule
    {
        uint32_t tid;
        ScheduleEdge last;
        ReadySequence ready;
        bool badTransitions = false, badClock = false;

        void Transition(const ScheduleEdge& e)
        {
            if (last.switchOrdinal && e.switchOrdinal)
            {
                badTransitions |= last.kind == e.kind ||
                    (last.kind == EdgeKind::In && last.at.cpu != e.at.cpu);
                // A self-switch has two roles on the same source row.
                badClock |= last.at.record != e.at.record && last.at.tick >= e.at.tick;
            }
            last = e;
            ready = {};
        }
    };

    // The first pass selects page rows. Replay needs all CPUs and only the TIDs
    // on that page, including their transitions on CPUs outside the page.
    struct ScheduleHistory
    {
        std::vector<CpuSchedule> cpus;
        std::vector<ThreadSchedule> threads;
        uint32_t readyCount = 0, unsupportedReady = 0, unassignedReady = 0, boundaries = 0, unsupportedBoundaries = 0;
        uint32_t cpuConflicts = 0, cpuClockConflicts = 0;
        uint16_t logger = 0;
        bool seenSwitch = false, indexed = false, ambiguousScope = false, unknownSwitchTid = false;
        bool seenTick = false, reversedClock = false, allowDirectSwitch = false;
        int64_t lastTick = 0;

        void ObserveClock(int64_t tick)
        {
            if (seenTick && tick < lastTick) { reversedClock = true; }
            seenTick = true;
            lastTick = tick;
        }

        void PrepareProcessors(uint32_t processors)
        {
            // BufferContext's processor index is 16 bits.
            if (processors && processors <= 65536) { cpus.resize(processors); }
            else { ambiguousScope = true; }
        }

        void Prepare(uint32_t processors, const SwitchEvent* page, size_t used)
        {
            PrepareProcessors(processors);
            std::vector<uint32_t> ids;
            ids.reserve(2 * used);
            for (size_t i = 0; i < used; ++i)
            {
                for (const auto tid : {page[i].fields.oldTid, page[i].fields.newTid})
                {
                    if (tid && tid != UINT32_MAX) { ids.push_back(tid); }
                }
            }
            std::sort(ids.begin(), ids.end());
            ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
            threads.reserve(ids.size());
            for (const auto tid : ids) { threads.push_back({tid, {}, {}}); }
        }

        void Prepare(uint32_t processors, uint32_t tid, uint32_t second = 0)
        {
            PrepareProcessors(processors);
            if (second < tid) { std::swap(tid, second); }
            if (tid && tid != UINT32_MAX) { threads.push_back({tid, {}, {}}); }
            if (second && second != tid && second != UINT32_MAX) { threads.push_back({second, {}, {}}); }
        }

        auto Find(uint32_t tid) const
        {
            return std::lower_bound(threads.begin(), threads.end(), tid,
                [](const ThreadSchedule& t, uint32_t key) { return t.tid < key; });
        }

        ThreadSchedule* Watch(uint32_t tid)
        {
            const auto it = Find(tid);
            if (it == threads.end() || it->tid != tid) { return nullptr; }
            return &threads[static_cast<size_t>(it - threads.cbegin())];
        }

        void OtherThreadEvent(const EVENT_RECORD& event, uint32_t ordinal)
        {
            if (event.EventHeader.EventDescriptor.Opcode == 50)
            {
                ReadyPoint ready;
                const auto m = DecodeReady(event, ordinal, ready);
                if (m == Match::Unsupported) { ++unsupportedReady; }
                if (m != Match::Decoded) { return; }
                ++readyCount;
                if (!ready.tid || ready.tid == UINT32_MAX) { ++unassignedReady; }
                ObserveClock(ready.at.tick);
                auto* thread = Watch(ready.tid);
                if (thread && thread->last.kind == EdgeKind::Out)
                {
                    thread->ready.Append(ready, allowDirectSwitch);
                    thread->ready.invalidProcessorScope |= ready.at.cpu >= cpus.size() || (!ready.at.indexed && cpus.size() > 64);
                }
                return;
            }
            ThreadEvent e{};
            const auto m = DecodeThread(event, ordinal, e);
            if (m == Match::Unsupported) { ++unsupportedBoundaries; }
            if (m != Match::Decoded) { return; }
            ++boundaries;
            ObserveClock(e.tick);
            if (auto* thread = Watch(e.tid))
            {
                thread->Transition({EventRef(event, ordinal), EdgeKind::Boundary, e.tid, 0, e.pid, 3, e.opcode});
            }
        }

        void Observe(const SwitchEvent& e, IntervalWitnesses* witnesses)
        {
            const ScheduleRef here{e.timestamp, e.record, e.cpu, e.loggerId, (e.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) != 0};
            if (!seenSwitch) { logger = here.logger; indexed = here.indexed; seenSwitch = true; }
            else { ambiguousScope |= logger != here.logger || indexed != here.indexed; }
            ObserveClock(e.timestamp);
            unknownSwitchTid |= e.fields.oldTid == UINT32_MAX || e.fields.newTid == UINT32_MAX;
            ambiguousScope |= e.cpu >= cpus.size() || (!here.indexed && cpus.size() > 64);
            const ScheduleEdge in{here, EdgeKind::In, e.fields.newTid, e.ordinal, 0, e.version, 36};
            const ScheduleEdge out{here, EdgeKind::Out, e.fields.oldTid, e.ordinal, 0, e.version, 36,
                e.fields.oldState, e.fields.oldWaitReason};
            if (e.cpu < cpus.size())
            {
                auto& cpu = cpus[e.cpu];
                if (witnesses) { witnesses->previousCpu = cpu.lastIn; }
                if (cpu.lastIn.at.record)
                {
                    if (cpu.lastIn.tid != out.tid && !cpu.badTransitions)
                    { cpu.badTransitions = true; ++cpuConflicts; }
                    if (cpu.lastIn.at.tick >= here.tick && !cpu.badClock)
                    { cpu.badClock = true; ++cpuClockConflicts; }
                }
                cpu.lastIn = in;
            }
            if (auto* thread = Watch(out.tid))
            {
                if (witnesses) { witnesses->previousOutgoingThread = thread->last; }
                thread->Transition(out);
            }
            if (auto* thread = Watch(in.tid))
            {
                if (witnesses) { witnesses->previousIncomingThread = thread->last; witnesses->ready = thread->ready; }
                thread->Transition(in);
            }
        }
    };

    struct ReportedSpan
    {
        const wchar_t* relation;
        bool measured = false;
    };

    inline ReportedSpan AssessSpan(const ScheduleHistory& history, const SwitchEvent& e,
        const IntervalWitnesses& w, bool running, bool comparableClock, bool gap)
    {
        const auto tid = running ? e.fields.oldTid : e.fields.newTid;
        const auto& prior = running ? w.previousOutgoingThread : w.previousIncomingThread;
        const auto& start = running ? w.previousCpu : prior;
        if (tid == UINT32_MAX || (!running && !tid)) { return {tid ? L"unusable_tid" : L"idle_tid"}; }
        if (history.ambiguousScope || e.cpu >= history.cpus.size()) { return {L"processor_scope_unqualified"}; }
        if (!start.at.record) { return {running ? L"no_previous_on_cpu" : L"no_previous_thread_event"}; }
        if (prior.kind == EdgeKind::Boundary) { return {L"thread_boundary"}; }
        if (start.at.record == e.record) { return {L"same_switch"}; }
        if (running && start.tid != tid) { return {L"cpu_tid_conflict"}; }
        if (tid && (running ? (prior.kind != EdgeKind::In || prior.at.record != start.at.record) : prior.kind != EdgeKind::Out))
        { return {L"thread_transition_conflict"}; }
        if (gap || (tid && history.unsupportedBoundaries) || (!running && history.unknownSwitchTid)) { return {L"coverage_unqualified"}; }
        const auto& cpu = history.cpus[e.cpu];
        if (running ? cpu.badTransitions : history.cpuConflicts != 0) { return {L"cpu_history_conflict"}; }
        const auto thread = history.Find(tid);
        if (tid && (thread == history.threads.end() || thread->tid != tid || thread->badTransitions))
        { return {L"thread_transition_conflict"}; }
        if (!comparableClock || history.reversedClock || start.at.tick >= e.timestamp ||
            (running ? cpu.badClock : history.cpuClockConflicts != 0) || (tid && thread->badClock))
        { return {L"clock_unqualified"}; }
        if (!running) { return {L"off_cpu", true}; }
        return {tid ? L"running_on_cpu" : L"idle_on_cpu", true};
    }

    inline ReportedSpan AssessReady(const ReadySequence& ready, const ScheduleEdge& out, const SwitchEvent& in,
        bool offCpuMeasured, uint32_t unsupportedReady, bool allowDirectSwitch = false)
    {
        if (!offCpuMeasured) { return {L"off_cpu_unqualified"}; }
        if (unsupportedReady) { return {L"ready_coverage_unqualified"}; }
        if (!ready.count) { return {L"ready_unobserved"}; }
        if (ready.mixedLogger || ready.first.at.logger != in.loggerId) { return {L"ready_scope_unqualified"}; }
        if (ready.badClock || out.at.tick >= ready.first.at.tick || ready.last.at.tick >= in.timestamp)
        { return {L"ready_clock_unqualified"}; }
        if (ready.unknownFlags) { return {L"ready_flags_unqualified"}; }
        if (!ready.dispatchable) { return {L"ready_deferred"}; }
        if (ready.dispatchable != 1 || (ready.last.flags & ~DispatchableReadyFlags(allowDirectSwitch))) { return {L"ready_sequence_conflict"}; }
        return {out.state == 5 ? L"waiting_ready_switch_in" : L"ready_switch_in", true};
    }

    // Ordered signed ticks can span more than INT64_MAX.
    inline uint64_t TickDistance(int64_t begin, int64_t end)
    {
        return static_cast<uint64_t>(end) - static_cast<uint64_t>(begin);
    }

    struct ScheduleSlice
    {
        SwitchEvent end;
        IntervalWitnesses witnesses;
        bool running;
        int64_t beginTick, endTick; // Intersection with the selected time window.

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

        ReportedSpan Assess(const ScheduleHistory& history, uint16_t logger, const ThreadPair& pair, bool qpc, bool gap) const
        {
            const auto& start = Start().at;
            if (history.unknownSwitchTid) { return {L"coverage_unqualified"}; }
            if (history.cpuConflicts) { return {L"cpu_history_conflict"}; }
            if (history.cpuClockConflicts) { return {L"clock_unqualified"}; }
            if (start.logger != logger || end.loggerId != logger) { return {L"logger_conflict"}; }
            if (!pair.pairedPid) { return {L"thread_bracket_unqualified"}; }
            if (start.record <= pair.before->record || end.record >= pair.after->record ||
                start.tick <= pair.before->tick || end.timestamp >= pair.after->tick)
            { return {L"switch_outside_bracket"}; }
            return AssessSpan(history, end, witnesses, running, qpc, gap);
        }
    };

    template <class Visitor>
    void VisitScheduleSlices(ScheduleHistory& history, const SwitchEvent& e, uint32_t tid, int64_t lo, int64_t hi, Visitor visit)
    {
        const bool outgoing = e.fields.oldTid == tid, incoming = e.fields.newTid == tid;
        if (!tid || tid == UINT32_MAX || lo <= 0 || lo >= hi || (!outgoing && !incoming))
        { history.Observe(e, nullptr); return; }

        IntervalWitnesses witnesses;
        history.Observe(e, &witnesses);
        const auto retain = [&](bool running, const ScheduleEdge& start)
        {
            if (!start.switchOrdinal) { return; }
            const auto begin = (std::max)(start.at.tick, lo);
            const auto end = (std::min)(e.timestamp, hi);
            if (begin < end) { visit(ScheduleSlice{e, witnesses, running, begin, end}); }
        };
        if (outgoing) { retain(true, witnesses.previousCpu); }
        if (incoming) { retain(false, witnesses.previousIncomingThread); }
    }
}
