#pragma once

#include "EtlHardFault.h"
#include "EtlThreadEvidence.h"
#include <algorithm>
#include <array>
#include <vector>

namespace etl_profile
{
    struct ActivityMarker
    {
        GUID provider{}, activity{};
        uint32_t record = 0, pid = 0, tid = 0;
        int64_t tick = 0;
        uint16_t logger = 0, flags = 0, properties = 0, eventId = 0, task = 0;
        uint8_t opcode = 0, version = 0, channel = 0;

        static ActivityMarker Read(const EVENT_RECORD& e, uint32_t ordinal)
        {
            const auto& h = e.EventHeader;
            const auto& d = h.EventDescriptor;
            return {h.ProviderId, h.ActivityId, ordinal, h.ProcessId, h.ThreadId, h.TimeStamp.QuadPart,
                e.BufferContext.LoggerId, h.Flags, h.EventProperty, d.Id, d.Task, d.Opcode, d.Version, d.Channel};
        }

        bool StartOrStop() const
        {
            return !(flags & (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_TRACE_MESSAGE | EVENT_HEADER_FLAG_STRING_ONLY)) &&
                (opcode == 1 || opcode == 2);
        }

        bool Keyed() const
        {
            constexpr GUID empty{};
            constexpr auto logRepresentation = EVENT_HEADER_PROPERTY_XML | EVENT_HEADER_PROPERTY_FORWARDED_XML | EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG;
            return StartOrStop() && !(properties & logRepresentation) && !(flags & EVENT_HEADER_FLAG_DECODE_GUID) &&
                eventId && task && !IsEqualGUID(provider, empty) && !IsEqualGUID(activity, empty);
        }

        bool SameActivity(const ActivityMarker& other) const
        {
            return task == other.task && channel == other.channel &&
                IsEqualGUID(provider, other.provider) && IsEqualGUID(activity, other.activity);
        }

        bool SameKey(const ActivityMarker& other) const { return pid == other.pid && SameActivity(other); }

        bool SameRecord(const ActivityMarker& other) const
        {
            return SameKey(other) && record == other.record && tid == other.tid && tick == other.tick &&
                logger == other.logger && flags == other.flags && properties == other.properties && eventId == other.eventId &&
                opcode == other.opcode && version == other.version;
        }
    };

    struct ActivityFault
    {
        HardFault fault;
        int64_t begin, end;
    };

    struct ActivityWindow
    {
        ActivityMarker start, stop;
        ThreadPair thread;
        std::vector<ActivityFault> rows;
        uint32_t sameKey = 0, intervening = 0, unassignedMarkers = 0, loggerFaults = 0, candidates = 0;
        uint32_t untimed = 0, ambiguousTid = 0, foreignLogger = 0, outsideLifetime = 0;
        int64_t lastTick = 0;
        bool seenTick = false, reversedClock = false;
        const wchar_t* boundaryIssue = nullptr;

        void Prepare(const ThreadIndex& index, bool qpc, bool gap)
        {
            rows.reserve(MaxPageRows);
            thread = index.Lookup(start.tid, start.record, start.tick, qpc, gap);
            if (!start.Keyed() || start.opcode != 1) { boundaryIssue = L"invalid_start_marker"; }
            else if (!stop.Keyed() || stop.opcode != 2) { boundaryIssue = L"invalid_stop_marker"; }
            else if (!start.SameKey(stop)) { boundaryIssue = L"activity_key_mismatch"; }
            else if (!start.pid || start.pid == UINT32_MAX || !start.tid || start.tid == UINT32_MAX || start.tid != stop.tid)
            { boundaryIssue = L"thread_scope_unqualified"; }
            else if (start.logger != stop.logger) { boundaryIssue = L"logger_conflict"; }
            else if (!qpc || start.tick <= 0 || start.tick >= stop.tick) { boundaryIssue = L"clock_unqualified"; }
            else if (gap) { boundaryIssue = L"coverage_unqualified"; }
            else if (!thread.pairedPid || thread.before->pid != start.pid || thread.before->mixedLoggers ||
                thread.before->logger != start.logger || stop.record >= thread.after->record || stop.tick >= thread.after->tick)
            { boundaryIssue = L"thread_bracket_unqualified"; }
        }

        void ObserveClock(int64_t tick)
        {
            reversedClock |= seenTick && tick < lastTick;
            lastTick = tick;
            seenTick = true;
        }

        void ObserveMarker(const ActivityMarker& row)
        {
            if (!row.Keyed() || !start.SameActivity(row)) { return; }
            const bool inside = start.record < row.record && row.record < stop.record;
            if (row.pid != start.pid)
            {
                if (inside && (!row.pid || row.pid == UINT32_MAX)) { ++unassignedMarkers; }
                return;
            }
            ++sameKey;
            if (inside) { ++intervening; }
            if (row.logger == start.logger) { ObserveClock(row.tick); }
        }

        void ObserveFault(const HardFault& fault)
        {
            if (fault.loggerId == start.logger) { ++loggerFaults; }
            if (boundaryIssue) { return; }
            const bool unknown = !fault.faultingTid || fault.faultingTid == UINT32_MAX;
            if (!unknown && fault.faultingTid != start.tid) { return; }
            if (fault.loggerId != start.logger)
            {
                if (!unknown) { ++foreignLogger; }
                return;
            }
            ObserveClock(fault.timestamp);
            const auto duration = fault.OrderedTicks();
            if (!duration)
            {
                // A missing or reversed start cannot exclude a fault completing after the selected stop.
                if (fault.timestamp >= start.tick || fault.timestamp <= 0)
                { if (unknown) { ++ambiguousTid; } else { ++untimed; } }
                return;
            }
            const auto begin = (std::max)(start.tick, fault.initialTime);
            const auto end = (std::min)(stop.tick, fault.timestamp);
            if (begin >= end) { return; }
            if (unknown) { ++ambiguousTid; return; }
            ++candidates;
            if (fault.record <= thread.before->record || fault.record >= thread.after->record ||
                fault.initialTime <= thread.before->tick || fault.timestamp >= thread.after->tick)
            { ++outsideLifetime; }
            if (rows.size() < MaxPageRows) { rows.push_back({fault, begin, end}); }
        }

        const wchar_t* WindowIssue() const
        {
            if (boundaryIssue) { return boundaryIssue; }
            if (intervening) { return L"intervening_activity_boundary"; }
            if (unassignedMarkers) { return L"unknown_activity_pid"; }
            if (reversedClock) { return L"clock_unqualified"; }
            return nullptr;
        }

        const wchar_t* FaultIssue() const
        {
            if (const auto issue = WindowIssue()) { return issue; }
            if (foreignLogger) { return L"fault_logger_conflict"; }
            if (!loggerFaults) { return L"fault_family_unobserved_on_logger"; }
            if (ambiguousTid) { return L"unknown_fault_tid"; }
            if (untimed) { return L"untimed_thread_fault"; }
            if (outsideLifetime) { return L"fault_outside_thread_bracket"; }
            if (candidates != rows.size()) { return L"fault_limit"; }
            return nullptr;
        }

        // Keep raw witness rows in traversal order. Faults can complete in a
        // different order from their start ticks, and their intervals can nest.
        uint64_t UnionTicks() const
        {
            std::array<std::pair<int64_t, int64_t>, MaxPageRows> spans{};
            for (size_t i = 0; i < rows.size(); ++i) { spans[i] = {rows[i].begin, rows[i].end}; }
            std::sort(spans.begin(), spans.begin() + rows.size());
            uint64_t total = 0;
            auto cursor = start.tick;
            for (size_t i = 0; i < rows.size(); ++i)
            {
                const auto [begin, end] = spans[i];
                if (end > cursor)
                {
                    total += static_cast<uint64_t>(end - (std::max)(begin, cursor));
                    cursor = end;
                }
            }
            return total;
        }
    };
}
