#pragma once

#include "../user/EtlActivityWindow.h"
#include <string_view>

namespace etl_activity_test
{
    using namespace etl_profile;

    inline ActivityMarker Marker(uint32_t ordinal, int64_t tick, uint8_t opcode)
    {
        ActivityMarker m;
        m.record = ordinal; m.tick = tick; m.opcode = opcode; m.pid = 8; m.tid = 42;
        m.task = 5; m.eventId = opcode + 4; m.channel = 16; m.logger = 7;
        m.provider.Data1 = 1; m.activity.Data1 = 2;
        return m;
    }

    inline HardFault Fault(uint32_t record, int64_t start, int64_t end)
    {
        HardFault f{};
        f.record = record; f.ordinal = record; f.timestamp = end; f.initialTime = start;
        f.faultingTid = 42; f.headerTid = 99; f.loggerId = 7;
        return f;
    }

    inline bool Check()
    {
        ThreadIndex index;
        index.events = {{1, 8, 42, 50, 1}, {100, 8, 42, 1000, 2}};
        index.events[0].logger = index.events[1].logger = 7;
        index.decoded = 2; index.Sort();
        const auto first = Marker(30, 150, 1), last = Marker(60, 250, 2);
        auto setup = [&](ActivityMarker a, ActivityMarker b, bool qpc = true, bool gap = false)
        {
            ActivityWindow w;
            w.start = a; w.stop = b; w.Prepare(index, qpc, gap);
            return w;
        };
        const auto is = [](const ActivityWindow& w, std::wstring_view issue)
        {
            return w.FaultIssue() && std::wstring_view(w.FaultIssue()) == issue;
        };
        auto w = setup(first, last);
        if (!is(w, L"fault_family_unobserved_on_logger")) { return false; }
        auto unrelated = Fault(10, 55, 70); unrelated.faultingTid = 123;
        w.ObserveFault(unrelated);
        if (w.FaultIssue() || w.UnionTicks() != 0) { return false; }
        w.ObserveFault(Fault(28, 70, 150)); // Only touches the opening tick.
        w.ObserveMarker(first);
        w.ObserveFault(Fault(35, 140, 175));
        w.ObserveFault(Fault(40, 185, 195));
        w.ObserveFault(Fault(45, 160, 200)); // Encloses the previous fault and overlaps the first.
        w.ObserveMarker(last);
        w.ObserveFault(Fault(64, 235, 270)); // Completes outside the two selected records.
        w.ObserveFault(Fault(65, 250, 300));
        if (w.FaultIssue() || w.UnionTicks() != 65 || w.rows.size() != 4 || w.candidates != 4 ||
            w.rows.front().begin != 150 || w.rows.back().end != 250 || w.sameKey != 2) { return false; }

        auto changed = last; changed.tid++;
        if (!is(setup(first, changed), L"thread_scope_unqualified")) { return false; }
        changed = last; changed.pid++;
        if (!is(setup(first, changed), L"activity_key_mismatch")) { return false; }
        changed = last; changed.activity.Data1++;
        if (!is(setup(first, changed), L"activity_key_mismatch")) { return false; }
        changed = last; changed.logger++;
        if (!is(setup(first, changed), L"logger_conflict")) { return false; }
        changed = last; changed.tick = first.tick;
        if (!is(setup(first, changed), L"clock_unqualified")) { return false; }
        changed = first; changed.flags = EVENT_HEADER_FLAG_CLASSIC_HEADER;
        if (!is(setup(changed, last), L"invalid_start_marker")) { return false; }
        changed = first; changed.flags = EVENT_HEADER_FLAG_DECODE_GUID;
        if (!is(setup(changed, last), L"invalid_start_marker")) { return false; }
        constexpr uint16_t eventLogProperties[] = {EVENT_HEADER_PROPERTY_XML, EVENT_HEADER_PROPERTY_FORWARDED_XML, EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG};
        for (const auto property : eventLogProperties)
        {
            changed = last; changed.properties = property;
            if (!is(setup(first, changed), L"invalid_stop_marker")) { return false; }
        }
        changed = last; changed.activity = {};
        if (!is(setup(first, changed), L"invalid_stop_marker")) { return false; }
        changed = last; changed.record = 101;
        if (!is(setup(first, changed), L"thread_bracket_unqualified") ||
            !is(setup(first, last, true, true), L"coverage_unqualified") ||
            !is(setup(first, last, false), L"clock_unqualified")) { return false; }
        auto other = Marker(42, 190, 1); other.tid++;
        auto test = setup(first, last); test.ObserveMarker(other);
        if (!is(test, L"intervening_activity_boundary")) { return false; }
        test = setup(first, last); other.pid = UINT32_MAX; test.ObserveMarker(other);
        if (!is(test, L"unknown_activity_pid")) { return false; }
        test = setup(first, last); other.pid = 9; test.ObserveMarker(other);
        test.ObserveFault(unrelated);
        if (test.FaultIssue() || test.intervening) { return false; }
        auto f = Fault(42, 150, 220); f.faultingTid = UINT32_MAX; test.ObserveFault(f);
        if (!is(test, L"unknown_fault_tid")) { return false; }
        test = setup(first, last); f = Fault(70, 0, 290); test.ObserveFault(f);
        if (!is(test, L"untimed_thread_fault")) { return false; }
        test = setup(first, last); f = Fault(42, 149, 220); ++f.loggerId; test.ObserveFault(f);
        if (!is(test, L"fault_logger_conflict")) { return false; }
        test = setup(first, last); test.ObserveFault(Fault(42, 40, 220));
        if (!is(test, L"fault_outside_thread_bracket")) { return false; }
        test = setup(first, last); test.ObserveMarker(last); test.ObserveFault(Fault(70, 149, 220));
        if (!is(test, L"clock_unqualified")) { return false; }
        test = setup(first, last);
        for (uint32_t i = 0; i <= MaxPageRows; ++i) { test.ObserveFault(Fault(42, 149, 220)); }
        if (!is(test, L"fault_limit") || test.rows.size() != MaxPageRows || test.candidates != MaxPageRows + 1) { return false; }

        index.events[0].tick = 1; index.events[1].tick = INT64_MAX;
        auto a = first, b = last; a.tick = 2; b.tick = INT64_MAX - 1;
        test = setup(a, b);
        test.ObserveFault(Fault(40, 2, INT64_MAX - 1)); test.ObserveFault(Fault(41, 3, INT64_MAX - 1));
        return !test.FaultIssue() && test.UnionTicks() == static_cast<uint64_t>(INT64_MAX - 3);
    }
}
