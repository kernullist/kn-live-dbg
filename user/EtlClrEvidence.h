#pragma once

#include "ClrMethodEvent.h"
#include "EtlProcessEvidence.h"
#include <array>

namespace etl_profile
{
    inline constexpr size_t MaxClrEvents = 65536;

    struct ClrPoint
    {
        uint32_t record = 0, pid = 0;
        int64_t tick = 0;
        uint16_t logger = 0;
        uint8_t opcode = 0;
        KmonRuntimeCodeRange method;
    };

    struct ClrWitness
    {
        const ClrPoint* before = nullptr;
        const ClrPoint* after = nullptr;
        const wchar_t* relation = nullptr;
        bool lifetime = false;
    };

    struct ClrMatch
    {
        const wchar_t* relation = L"no_covering_declaration";
        std::array<ClrWitness, 2> witnesses{};
        size_t count = 0;
        bool lifetime = false;
    };

    inline bool ClrCovers(const ClrPoint* point, uint64_t ip)
    {
        return point && ip >= point->method.Start && ip - point->method.Start < point->method.Size;
    }

    struct ClrIndex
    {
        std::vector<ClrPoint> events;
        uint32_t loads = 0, unloads = 0, inventory = 0, unsupported = 0, unknownPid = 0;
        EventClockOrder clock;

        void Prepare() { events.reserve(MaxClrEvents); }
        bool Complete() const { return events.size() == static_cast<size_t>(loads) + unloads + inventory + unsupported; }

        void Observe(const EVENT_RECORD& event, uint32_t record)
        {
            const auto& h = event.EventHeader;
            ClrPoint p;
            const auto action = ReadClrMethodRange(event, p.method);
            if (action == ClrMethodAction::Ignore)
            {
                if (ProcessClockRecord(h)) { clock.Observe(h.TimeStamp.QuadPart); }
                return;
            }
            p.record = record;
            p.pid = h.ProcessId;
            p.tick = h.TimeStamp.QuadPart;
            p.logger = event.BufferContext.LoggerId;
            p.opcode = h.EventDescriptor.Opcode;
            clock.Observe(p.tick);
            const auto bits = h.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
            const uint64_t lastUser = bits == EVENT_HEADER_FLAG_32_BIT_HEADER ? UINT32_MAX : 0x00007fffffffffffULL;
            const bool noPid = !p.pid || p.pid == UINT32_MAX;
            if (action == ClrMethodAction::Unsupported || noPid ||
                bits == (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) ||
                p.method.Start < 0x10000 || !p.method.Size || p.method.Start > lastUser || p.method.Size - 1 > lastUser - p.method.Start)
            {
                ++unsupported;
                if (noPid) { ++unknownPid; }
                // Keep the process and source ordinal even if the affected range is unreadable.
                p.method = {};
            }
            else if (action == ClrMethodAction::Load) { ++loads; }
            else if (action == ClrMethodAction::Unload) { ++unloads; }
            else { ++inventory; }
            if (events.size() < MaxClrEvents) { events.push_back(p); }
        }

        void Sort()
        {
            std::sort(events.begin(), events.end(), [](const ClrPoint& a, const ClrPoint& b) {
                if (a.pid != b.pid) { return a.pid < b.pid; }
                return a.method.Start == b.method.Start ? a.record < b.record : a.method.Start < b.method.Start;
            });
        }

        using Iterator = std::vector<ClrPoint>::const_iterator;

        static ClrWitness At(Iterator begin, Iterator end, const Sample& sample, const ProcessPair& process)
        {
            ClrWitness w;
            const ClrPoint* active = nullptr;
            const ClrPoint* lastTransition = nullptr;
            const ClrPoint* nextTransition = nullptr;
            bool possibleEarlier = false, possibleLater = false;
            const ClrPoint* previous = nullptr;
            bool sawLoad = false, conflict = false, clockConflict = false, loggerConflict = false;
            for (auto it = begin; it != end; ++it)
            {
                const auto& e = *it;
                if (e.record <= process.before->record || e.record >= process.after->record) { continue; }
                if (e.record < sample.record) { w.before = &e; }
                else if (!w.after) { w.after = &e; }
                if (e.method.Observation != ClrMethodAction::Rundown)
                {
                    if (e.record < sample.record) { lastTransition = &e; }
                    else if (!nextTransition) { nextTransition = &e; }
                }
                if (ClrCovers(&e, sample.ip))
                {
                    possibleEarlier |= e.record < sample.record && e.method.Observation != ClrMethodAction::Unload;
                    possibleLater |= e.record > sample.record && e.method.Observation == ClrMethodAction::Unload;
                }
                clockConflict |= e.tick <= process.before->tick || e.tick >= process.after->tick ||
                    (previous && previous->tick >= e.tick);
                loggerConflict |= e.logger != sample.loggerId;
                if (active && !SameClrMethodRange(active->method, e.method)) { conflict = true; }
                if (e.method.Observation == ClrMethodAction::Unload)
                {
                    conflict |= previous && previous->method.Observation == ClrMethodAction::Unload;
                    active = nullptr;
                    sawLoad = false;
                }
                else
                {
                    if (e.method.Observation == ClrMethodAction::Load)
                    {
                        conflict |= sawLoad;
                        sawLoad = true;
                    }
                    active = &e;
                }
                previous = &e;
            }
            // Inventory corroborates presence at its own tick. It cannot open or
            // retire a method, or replace actual lifetime endpoints in the report.
            if (!conflict && ClrCovers(lastTransition, sample.ip) && ClrCovers(nextTransition, sample.ip) &&
                lastTransition->method.Observation == ClrMethodAction::Load && nextTransition->method.Observation == ClrMethodAction::Unload &&
                SameClrMethodRange(lastTransition->method, nextTransition->method) &&
                (!w.before || w.before->tick < sample.timestamp) && (!w.after || w.after->tick > sample.timestamp))
            {
                w.before = lastTransition;
                w.after = nextTransition;
            }
            const bool preceding = ClrCovers(w.before, sample.ip) && w.before->method.Observation != ClrMethodAction::Unload;
            const bool retiring = ClrCovers(w.after, sample.ip) && w.after->method.Observation == ClrMethodAction::Unload;
            if (!preceding && !retiring && !(conflict && (possibleEarlier || possibleLater))) { return {}; }
            if (clockConflict || (w.before && w.before->tick >= sample.timestamp) || (w.after && w.after->tick <= sample.timestamp))
            { w.relation = L"clock_unqualified"; }
            else if (loggerConflict) { w.relation = L"logger_conflict"; }
            else if (conflict) { w.relation = L"conflicting_declarations"; }
            else if (!preceding) { w.relation = L"unload_only"; }
            else if (!w.after || w.after->method.Observation == ClrMethodAction::Load) { w.relation = L"preceding_declaration"; }
            else if (!SameClrMethodRange(w.before->method, w.after->method)) { w.relation = L"method_identity_conflict"; }
            else if (!w.before->method.MethodId || !w.before->method.ModuleId) { w.relation = L"method_identity_unavailable"; }
            else if (w.before->method.Observation == ClrMethodAction::Load && retiring)
            {
                w.relation = L"load_unload";
                w.lifetime = true;
            }
            else { w.relation = L"rundown_bracket"; }
            return w;
        }

        ClrMatch Lookup(const Sample& sample, const ProcessPair& process, bool comparableClock, bool gap) const
        {
            ClrMatch match;
            if (!Complete()) { match.relation = L"index_limit"; return match; }
            if (!process.generation) { match.relation = L"process_generation_unavailable"; return match; }
            auto it = std::lower_bound(events.begin(), events.end(), process.candidatePid,
                [](const ClrPoint& e, uint32_t pid) { return e.pid < pid; });
            bool missing = gap || unknownPid != 0;
            while (it != events.end() && it->pid == process.candidatePid && it->method.Start <= sample.ip)
            {
                const auto first = it;
                const auto start = first->method.Start;
                do { ++it; } while (it != events.end() && it->pid == process.candidatePid && it->method.Start == start);
                if (!start)
                {
                    missing |= std::any_of(first, it, [&](const ClrPoint& e) {
                        return e.record > process.before->record && e.record < process.after->record;
                    });
                    continue;
                }
                const auto w = At(first, it, sample, process);
                if (w.relation)
                {
                    if (match.count < match.witnesses.size()) { match.witnesses[match.count] = w; }
                    ++match.count;
                }
            }
            if (missing) { match.relation = L"coverage_unqualified"; }
            else if (!comparableClock || clock.reversed) { match.relation = L"clock_unqualified"; }
            else if (match.count > 1) { match.relation = L"overlapping_ranges"; }
            else if (match.count == 1)
            {
                match.relation = match.witnesses[0].relation;
                match.lifetime = match.witnesses[0].lifetime;
            }
            return match;
        }
    };
}
