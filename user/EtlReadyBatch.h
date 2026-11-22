#pragma once

#include "EtlReadyOrigin.h"

namespace etl_profile
{
    // A CPU or TID can have several selected ready records before its next switch.
    // Storage is reserved before ETW invokes either traversal's callbacks.
    struct PendingOrigins
    {
        using Entry = std::pair<uint32_t, size_t>;
        std::vector<Entry> entries;

        void Add(uint32_t key, size_t slot)
        {
            const Entry entry{key, slot};
            entries.insert(std::lower_bound(entries.begin(), entries.end(), entry), entry);
        }

        template <class F>
        void Take(uint32_t key, F visit)
        {
            const auto first = std::lower_bound(entries.begin(), entries.end(), Entry{key, 0});
            auto end = first;
            while (end != entries.end() && end->first == key) { visit(end->second); ++end; }
            if (first != end) { entries.erase(first, end); }
        }
    };

    struct ReadyBatch
    {
        std::vector<ReadyOrigin> rows;
        PendingOrigins cpu, target;
        size_t next = 0, expectedRows = 0;

        void Prepare(size_t count)
        {
            rows.resize(count);
            cpu.entries.reserve(count);
            target.entries.reserve(count);
        }

        void Select(const EVENT_RECORD& event, uint32_t record, const std::vector<uint32_t>& requested)
        {
            if (next >= requested.size() || requested[next] != record) { return; }
            const auto slot = next++;
            auto& origin = rows[slot];
            origin.Select(event, record);
            if (origin.match == Match::Decoded)
            {
                cpu.Add(origin.ready.at.cpu, slot);
                target.Add(origin.ready.tid, slot);
            }
        }

        void SelectSwitch(const SwitchEvent& e)
        {
            cpu.Take(e.cpu, [&](size_t i) { rows[i].source.end = e; });
            target.Take(e.fields.newTid, [&](size_t i) { rows[i].target.end = e; });
        }

        void PrepareReplay(ScheduleHistory& history, uint32_t processors)
        {
            cpu.entries.clear();
            target.entries.clear();
            next = expectedRows = 0;
            std::vector<uint32_t> ids;
            ids.reserve(2 * rows.size());
            for (size_t i = 0; i < rows.size(); ++i)
            {
                const auto& origin = rows[i];
                expectedRows += origin.ReplayRows();
                for (const auto tid : {origin.ready.tid, origin.source.end.fields.oldTid})
                {
                    if (tid && tid != UINT32_MAX) { ids.push_back(tid); }
                }
                if (origin.source.end.record) { cpu.Add(origin.source.end.record, i); }
                if (origin.target.end.record) { target.Add(origin.target.end.record, i); }
            }
            history.PrepareProcessors(processors);
            history.WatchThreads(ids);
            history.allowDirectSwitch = true;
        }

        void ReplaySelection(const EVENT_RECORD& e, uint32_t record, const std::vector<uint32_t>& requested,
            ScheduleHistory& history, size_t& replayedRows, bool& mismatch)
        {
            if (next >= requested.size() || requested[next] != record) { return; }
            auto& origin = rows[next++];
            mismatch |= !origin.SameReady(e, record);
            origin.ObserveContext(history);
            ++replayedRows;
        }

        void ReplaySwitch(ScheduleHistory& history, const SwitchEvent& e, size_t& replayedRows, bool& mismatch)
        {
            const bool closing = (!cpu.entries.empty() && cpu.entries.front().first == e.record) ||
                (!target.entries.empty() && target.entries.front().first == e.record);
            IntervalWitnesses w;
            history.Observe(e, closing ? &w : nullptr);
            if (!closing) { return; }
            const auto save = [&](ReadyOrigin::Span& span) {
                mismatch |= !span.SameSwitch(e);
                span.witnesses = w;
                ++replayedRows;
            };
            cpu.Take(e.record, [&](size_t i) { save(rows[i].source); });
            target.Take(e.record, [&](size_t i) { save(rows[i].target); });
        }
    };
}
