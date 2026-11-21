#pragma once

#include "../user/EtlCaptureSettings.h"
#include <string>

namespace etl_settings_test
{
    using namespace etl_profile;

    inline EVENT_RECORD Envelope(const GUID& guid, uint8_t op, uint8_t version, uint8_t width)
    {
        EVENT_RECORD e{};
        e.EventHeader.ProviderId = guid;
        e.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_PROCESSOR_INDEX |
            (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        e.EventHeader.EventDescriptor.Opcode = op;
        e.EventHeader.EventDescriptor.Version = version;
        e.EventHeader.EventDescriptor.Keyword = 0x8000000080000001ull;
        e.EventHeader.EventDescriptor.Level = 3;
        e.EventHeader.EventDescriptor.Channel = 7;
        e.EventHeader.EventDescriptor.Task = 300;
        e.BufferContext.LoggerId = 3;
        e.BufferContext.ProcessorIndex = 7;
        return e;
    }

    inline bool Layout(uint8_t width)
    {
        CaptureSettings settings;
        settings.Prepare();
        std::array<uint8_t, 42> data{};
        auto* unaligned = data.data() + 1;
        for (uint32_t i = 0; i < 9; ++i)
        {
            const auto value = UINT32_MAX - i;
            std::memcpy(unaligned + 4 * i, &value, 4);
        }
        uint32_t ordinal = 0;
        for (uint8_t version : std::array<uint8_t, 3>{0, 1, 2})
        {
            for (uint8_t op : std::array<uint8_t, 2>{5, 32})
            {
                auto event = Envelope(EventTraceProvider, op, version, width);
                event.UserData = unaligned;
                event.EventHeader.TimeStamp.QuadPart = -21;
                const auto size = static_cast<USHORT>(version == 2 ? 36 : 32);
                for (USHORT length = 0; length <= size + 1; ++length)
                {
                    event.UserDataLength = length;
                    SettingRecord p;
                    if ((DecodeSetting(event, 18, p) == Match::Decoded) != (length == size)) { return false; }
                }
                event.UserDataLength = size;
                settings.Observe(event, ++ordinal);
                const auto& p = settings.records.back();
                if (p.record != ordinal || p.tick != -21 || p.width != width || p.opcode != op || p.version != version ||
                    p.logger != 3 || p.cpu != 7 || p.masks[0] != UINT32_MAX || p.masks[7] != UINT32_MAX - 7 ||
                    p.keyword != 0x8000000080000001ull || p.level != 3 || p.channel != 7 || p.task != 300 ||
                    p.kernelVersion != (version == 2 ? UINT32_MAX - 8 : 0)) { return false; }
            }
        }
        for (uint8_t version : std::array<uint8_t, 2>{2, 3})
        {
            for (uint8_t op : std::array<uint8_t, 3>{72, 73, 74})
            {
                auto event = Envelope(PerfInfo, op, version, width);
                event.UserData = unaligned;
                const wchar_t name[] = L"T\"\\\U0001f600";
                std::memcpy(unaligned + 12, name, sizeof(name));
                event.UserDataLength = static_cast<USHORT>(version == 2 ? 12 : 12 + sizeof(name));
                settings.Observe(event, ++ordinal);
                const auto& p = settings.records.back();
                if (p.record != ordinal || p.source != UINT32_MAX || p.newInterval != UINT32_MAX - 1 ||
                    p.oldInterval != UINT32_MAX - 2 || settings.Name(p) != (version == 2 ? L"" : name)) { return false; }
                SettingRecord temp;
                ++event.UserDataLength;
                if (DecodeSetting(event, 0, temp) != Match::Unsupported) { return false; }
                event.UserDataLength = 11;
                if (DecodeSetting(event, 0, temp) != Match::Unsupported) { return false; }
            }
        }
        auto invalid = Envelope(PerfInfo, 72, 3, width);
        invalid.UserData = unaligned;
        invalid.UserDataLength = 16;
        const uint8_t bad[] = {0, 0xd8, 0, 0};
        std::memcpy(unaligned + 12, bad, sizeof(bad));
        settings.Observe(invalid, ++ordinal);
        invalid.EventHeader.EventDescriptor.Version = 4;
        settings.Observe(invalid, ++ordinal);
        invalid = Envelope(EventTraceProvider, 5, 2, width);
        invalid.UserData = unaligned;
        invalid.UserDataLength = 36;
        invalid.EventHeader.EventDescriptor.Id = 1;
        settings.Observe(invalid, ++ordinal);
        invalid.EventHeader.EventDescriptor.Id = 0;
        invalid.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;
        settings.Observe(invalid, ++ordinal);
        invalid = Envelope(ThreadProvider, 73, 3, width);
        settings.Observe(invalid, ++ordinal);
        for (uint8_t op : std::array<uint8_t, 3>{32, 33, 34})
        {
            auto loss = Envelope(LostProvider, op, 0, width);
            settings.Observe(loss, ++ordinal);
            if (settings.records.back().kind != SettingKind::Loss || settings.records.back().opcode != op) { return false; }
        }
        const auto& rejected = settings.records[12];
        if (rejected.supported || rejected.record != 13 || rejected.version != 3 || rejected.payloadBytes != 16 ||
            rejected.kind != SettingKind::ProfileInterval || settings.records[14].eventId != 1) { return false; }
        return settings.Complete() && settings.maskCount == 8 && settings.intervalCount == 8 && settings.lossCount == 3 &&
            settings.unsupportedMasks == 2 && settings.unsupportedIntervals == 2;
    }

    inline SettingRecord Point(uint8_t op, uint32_t n, uint32_t old = 0, uint32_t next = 0)
    {
        SettingRecord p{};
        p.kind = op == 5 || op == 32 ? SettingKind::GroupMask : SettingKind::ProfileInterval;
        p.opcode = op;
        p.record = n;
        p.tick = 10ll * n;
        p.logger = 4;
        p.width = 8;
        p.version = 2;
        p.oldInterval = old;
        p.newInterval = next;
        return p;
    }

    inline bool Brackets()
    {
        const auto mask = SettingKind::GroupMask, timer = SettingKind::ProfileInterval;
        RecordEnvelope row{};
        row.loggerId = 4;
        row.width = 8;
        CaptureSettings settings;
        auto start = Point(73, 3, 100, 100), finish = Point(74, 11, 200, 200);
        auto foreign = Point(73, 4);
        foreign.logger = 5;
        auto counter = Point(74, 5);
        counter.source = 17;
        settings.records = {Point(5, 2), start, foreign, counter, Point(72, 7, 100, 200), Point(32, 10), finish};
        settings.maskCount = 2;
        settings.intervalCount = 5;
        auto at = [&](uint32_t n, SettingKind kind, bool clock = true, bool gap = false) {
            row.record = n;
            row.timestamp = 10ll * n;
            return settings.At(row, kind, clock, gap);
        };
        auto is = [](const SettingBracket& bracket, std::wstring_view relation) { return bracket.relation == relation; };
        auto a = at(6, timer), b = at(9, timer);
        if (a.period != 100 || b.period != 200 || a.before->record != 3 || b.before->record != 7 ||
            a.after->record != 7 || b.after->record != 11 || a.start->record != 3 || b.end->record != 11 ||
            !is(at(6, mask), L"equal_group_snapshots") || !is(at(12, timer), L"one_boundary") ||
            !is(at(1, timer), L"one_boundary") || !is(at(6, timer, false), L"clock_unqualified") ||
            !is(at(6, timer, true, true), L"coverage_unqualified")) { return false; }
        ++settings.records[5].masks[7];
        if (!is(at(6, mask), L"group_snapshots_differ")) { return false; }
        ++settings.unsupportedMasks;
        if (!is(at(6, mask), L"coverage_unqualified") || at(6, timer).period != 100) { return false; }
        --settings.unsupportedMasks;
        ++settings.unsupportedIntervals;
        if (!is(at(6, timer), L"coverage_unqualified")) { return false; }
        --settings.unsupportedIntervals;
        ++settings.records[4].oldInterval;
        if (!is(at(6, timer), L"interval_values_unresolved") || at(9, timer).period != 200) { return false; }
        --settings.records[4].oldInterval;
        ++settings.records[1].oldInterval;
        if (!is(at(9, timer), L"interval_values_unresolved")) { return false; }
        --settings.records[1].oldInterval;
        ++settings.records.back().newInterval;
        if (!is(at(6, timer), L"interval_values_unresolved")) { return false; }
        --settings.records.back().newInterval;
        settings.records[4].tick = start.tick;
        if (!is(at(6, timer), L"clock_unqualified")) { return false; }
        settings.records[4].tick = 70;
        settings.records.back().width = 4;
        if (!is(at(9, timer), L"setting_layout_conflict")) { return false; }
        settings.records.back().width = 8;
        for (auto& p : settings.records) { if (p.kind == timer) { p.version = 3; } }
        settings.names = {L'A', L'B'};
        settings.records[1].nameUnits = settings.records[4].nameUnits = settings.records.back().nameUnits = 1;
        settings.records.back().nameOffset = 1;
        if (!is(at(6, timer), L"profile_source_name_conflict")) { return false; }
        settings.records.back().nameOffset = 0;
        if (at(6, timer).period != 100) { return false; }
        auto loss = Point(32, 13);
        loss.kind = SettingKind::Loss;
        settings.records.push_back(loss);
        ++settings.lossCount;
        if (!is(at(6, timer), L"coverage_unqualified") || at(6, timer).period) { return false; }
        settings.records.pop_back();
        --settings.lossCount;
        settings.records[4] = Point(73, 7);
        auto ambiguous = at(9, timer);
        if (!is(ambiguous, L"ambiguous_boundaries") || ambiguous.period || ambiguous.start || ambiguous.end) { return false; }
        settings.records = {start, finish, Point(74, 12, 200, 200)};
        settings.maskCount = 0;
        settings.intervalCount = 3;
        ambiguous = at(6, timer);
        if (!is(ambiguous, L"ambiguous_boundaries") || ambiguous.start || ambiguous.end) { return false; }
        settings.records = {finish, Point(73, 15, 200, 200)};
        settings.intervalCount = 2;
        return is(at(13, timer), L"outside_recorded_collection") && is(at(13, mask), L"no_records");
    }

    inline bool Budgets()
    {
        CaptureSettings s;
        s.Prepare();
        auto loss = Envelope(LostProvider, 33, 0, 8);
        for (uint32_t n = 1; n <= MaxSettingRecords; ++n) { s.Observe(loss, n); }
        if (!s.Complete()) { return false; }
        s.Observe(loss, MaxSettingRecords + 1);
        RecordEnvelope row{};
        if (s.Complete() || std::wstring_view(s.retention) != L"record_limit" ||
            std::wstring_view(s.At(row, SettingKind::GroupMask, true, false).relation) != L"index_limit") { return false; }
        CaptureSettings longNames;
        longNames.Prepare();
        auto e = Envelope(PerfInfo, 73, 3, 8);
        std::vector<wchar_t> data(32767, L'X');
        data.back() = 0;
        e.UserData = data.data();
        e.UserDataLength = static_cast<USHORT>(data.size() * 2);
        longNames.Observe(e, 1);
        longNames.Observe(e, 2);
        data[22] = 0;
        e.UserDataLength = 46; // Twelve fixed bytes, sixteen units and the terminator.
        longNames.Observe(e, 3);
        if (!longNames.Complete() || longNames.names.size() != MaxSettingNameUnits) { return false; }
        data[7] = 0;
        e.UserDataLength = 16;
        longNames.Observe(e, 4);
        longNames.Observe(loss, 5);
        return !longNames.Complete() && longNames.intervalCount == 4 && longNames.lossCount == 1 &&
            longNames.records.size() == 3 && std::wstring_view(longNames.retention) == L"name_limit" &&
            longNames.Name(longNames.records.back()).size() == 16;
    }
}
