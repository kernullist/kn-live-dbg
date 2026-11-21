#pragma once

#include "EtlProfileRecord.h"
#include <algorithm>
#include <vector>

namespace etl_profile
{
    inline constexpr size_t MaxThreadEvents = 65536;

    struct ThreadEvent
    {
        uint32_t record, pid, tid;
        int64_t tick;
        uint8_t opcode;
        bool transitionConflict = false, clockConflict = false;
    };

    inline Match DecodeThread(const EVENT_RECORD& event, uint32_t ordinal, ThreadEvent& result)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, ThreadProvider) || d.Opcode < 1 || d.Opcode > 4) { return Match::Other; }
        const auto width = ClassicPointerWidth(h, 3);
        // Thread_V3_TypeGroup1 contains two IDs, seven pointers, a tag and four byte fields.
        const auto bytes = static_cast<const uint8_t*>(event.UserData);
        const size_t fixed = 16 + 7 * width;
        if (!width || !bytes || event.UserDataLength < fixed ||
            (event.UserDataLength > fixed && !TerminatedUtf16(bytes + fixed, event.UserDataLength - fixed)))
        { return Match::Unsupported; }
        std::memcpy(&result.pid, bytes, sizeof(result.pid));
        std::memcpy(&result.tid, bytes + 4, sizeof(result.tid));
        result.record = ordinal;
        result.tick = h.TimeStamp.QuadPart;
        result.opcode = d.Opcode;
        return Match::Decoded;
    }

    inline bool Opening(uint8_t opcode) { return opcode == 1 || opcode == 3; }
    inline const wchar_t* ThreadEventName(uint8_t opcode)
    {
        switch (opcode)
        {
        case 1: return L"start";
        case 2: return L"end";
        case 3: return L"rundown_start";
        case 4: return L"rundown_end";
        default: return L"unknown";
        }
    }

    struct ThreadPair
    {
        const ThreadEvent* before = nullptr;
        const ThreadEvent* after = nullptr;
        const wchar_t* relation = L"no_record";
        bool pairedPid = false;
    };

    struct ThreadIndex
    {
        std::vector<ThreadEvent> events;
        uint32_t decoded = 0, unsupported = 0;

        // Reserve before entering ETW. A callback never allocates or retains
        // pointers into the event buffer.
        void Prepare() { events.reserve(MaxThreadEvents); }
        bool Complete() const { return decoded == events.size(); }

        void Observe(const EVENT_RECORD& event, uint32_t ordinal)
        {
            ThreadEvent point{};
            const auto match = DecodeThread(event, ordinal, point);
            if (match == Match::Unsupported) { ++unsupported; }
            if (match != Match::Decoded) { return; }
            ++decoded;
            if (events.size() < MaxThreadEvents) { events.push_back(point); }
        }

        void Sort()
        {
            std::sort(events.begin(), events.end(), [](const ThreadEvent& a, const ThreadEvent& b) {
                return a.tid == b.tid ? a.record < b.record : a.tid < b.tid;
            });
            for (size_t first = 0; first < events.size();)
            {
                size_t end = first + 1;
                bool badTransitions = false, badClock = false;
                while (end < events.size() && events[end].tid == events[first].tid)
                {
                    const auto& previous = events[end - 1];
                    const auto& current = events[end++];
                    badTransitions |= Opening(previous.opcode) == Opening(current.opcode);
                    badClock |= previous.tick >= current.tick;
                }
                for (size_t i = first; i < end; ++i)
                {
                    events[i].transitionConflict = badTransitions;
                    events[i].clockConflict = badClock;
                }
                first = end;
            }
        }

        ThreadPair Lookup(const Sample& sample, bool comparableClock, bool captureGap) const
        {
            ThreadPair pair;
            if (!Complete()) { pair.relation = L"index_limit"; return pair; }
            // TID zero is shared by per-processor idle contexts.
            if (sample.tid == 0 || sample.tid == UINT32_MAX) { pair.relation = L"unusable_tid"; return pair; }
            const auto next = std::lower_bound(events.begin(), events.end(), sample, [](const ThreadEvent& e, const Sample& s) {
                return e.tid == s.tid ? e.record < s.record : e.tid < s.tid;
            });
            if (next != events.end() && next->tid == sample.tid) { pair.after = &*next; }
            if (next != events.begin() && (next - 1)->tid == sample.tid) { pair.before = &*(next - 1); }
            if (!pair.before && !pair.after) { return pair; }
            if (!pair.before || !pair.after) { pair.relation = L"one_boundary"; return pair; }
            if (!Opening(pair.before->opcode) || Opening(pair.after->opcode))
            { pair.relation = L"outside_bracket"; return pair; }
            if (pair.before->pid != pair.after->pid || !pair.before->pid || pair.before->pid == UINT32_MAX)
            { pair.relation = L"pid_conflict"; return pair; }
            if (pair.before->transitionConflict) { pair.relation = L"conflicting_transitions"; return pair; }
            if (!comparableClock || pair.before->clockConflict ||
                !(pair.before->tick < sample.timestamp && sample.timestamp < pair.after->tick))
            { pair.relation = L"clock_unqualified"; return pair; }
            if (captureGap || unsupported) { pair.relation = L"coverage_unqualified"; return pair; }
            pair.relation = pair.before->opcode == 1 && pair.after->opcode == 2 ? L"start_end" : L"rundown_bracket";
            pair.pairedPid = true;
            return pair;
        }
    };
}
