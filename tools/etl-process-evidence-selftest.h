#pragma once

#include "../user/EtlProcessEvidence.h"
#include <string_view>

namespace etl_process_test
{
    using namespace etl_profile;

    inline size_t Fixed(uint8_t width, uint8_t version)
    {
        return width + 16u + (version >= 3 ? width : 0u) + (version >= 4 ? 4u : 0u);
    }

    inline std::vector<uint8_t> Payload(uint8_t width, uint8_t version, bool withSid)
    {
        // Put the first payload byte at an odd address.
        std::vector<uint8_t> bytes(1 + Fixed(width, version), 0);
        const uint64_t key = 0x12345678aabbccddull;
        const uint32_t fields[] = {71, 22, 2, 0xfffffffd};
        std::memcpy(bytes.data() + 1, &key, width);
        std::memcpy(bytes.data() + 1 + width, fields, sizeof(fields));
        if (withSid)
        {
            const size_t base = bytes.size(), sid = base + 2u * width;
            bytes.resize(sid + 8 + 8);
            bytes[base] = 1;
            bytes[sid] = 1;
            bytes[sid + 1] = 2;
        }
        else { bytes.resize(bytes.size() + 4); }
        bytes.insert(bytes.end(), {'x', 0, 0x3d, 0xd8, 0x4c, 0xdf, 0, 0});
        if (version >= 4) { bytes.insert(bytes.end(), {0, 0, 'b', 0, 0, 0}); }
        if (version == 5) { bytes.insert(bytes.end(), {1, 0, 0, 0, 0, 0, 0, 0xf0}); }
        return bytes;
    }

    inline EVENT_RECORD Record(std::vector<uint8_t>& bytes, uint8_t width, uint8_t version, uint8_t op)
    {
        EVENT_RECORD e{};
        auto& h = e.EventHeader;
        h.ProviderId = ProcessProvider;
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER |
            (width == 8 ? EVENT_HEADER_FLAG_64_BIT_HEADER : EVENT_HEADER_FLAG_32_BIT_HEADER);
        h.EventDescriptor.Opcode = op;
        h.EventDescriptor.Version = version;
        h.TimeStamp.QuadPart = -71;
        h.ProcessId = 777;
        e.BufferContext.LoggerId = 7;
        e.UserData = bytes.data() + 1;
        e.UserDataLength = static_cast<USHORT>(bytes.size() - 1);
        return e;
    }

    inline bool Layout()
    {
        ProcessEvent point;
        for (uint8_t width : std::array<uint8_t, 2>{4, 8})
        {
            for (uint8_t v = 2; v <= 5; ++v)
            {
                for (bool sid : {false, true})
                {
                    auto data = Payload(width, v, sid);
                    for (uint8_t op : std::array<uint8_t, 5>{1, 2, 3, 4, 39})
                    {
                        auto e = Record(data, width, v, op);
                        auto m = DecodeProcess(e, 19, point);
                        if (v == 5 && op != 39) { if (m != Match::Unsupported) { return false; } continue; }
                        if (m != Match::Decoded || point.record != 19 || point.tick != -71 || point.pid != 71 ||
                            point.parent != 22 || point.session != 2 || point.exitStatus != -3 || point.logger != 7 ||
                            point.opcode != op || point.width != width || point.version != v ||
                            point.key != (width == 8 ? 0x12345678aabbccddull : 0xaabbccddu) ||
                            point.exitTime != (v == 5 ? 0xf000000000000001ull : 0ull)) { return false; }
                        const auto full = e.UserDataLength;
                        for (USHORT len = 0; len < full; ++len)
                        {
                            e.UserDataLength = len;
                            if (DecodeProcess(e, 19, point) != Match::Unsupported) { return false; }
                        }
                    }
                }
            }
        }
        auto data = Payload(8, 4, true);
        auto e = Record(data, 8, 4, 1);
        auto bad = e;
        bad.EventHeader.EventDescriptor.Id = 1;
        if (DecodeProcess(bad, 1, point) != Match::Unsupported) { return false; }
        bad = e;
        bad.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
        if (DecodeProcess(bad, 1, point) != Match::Unsupported) { return false; }
        bad = e;
        bad.ExtendedDataCount = 1;
        if (DecodeProcess(bad, 1, point) != Match::Unsupported) { return false; }
        bad = e;
        bad.UserData = nullptr;
        if (DecodeProcess(bad, 1, point) != Match::Unsupported) { return false; }
        bad = e;
        bad.EventHeader.ProviderId = ThreadProvider;
        if (DecodeProcess(bad, 1, point) != Match::Other) { return false; }
        bad = e;
        bad.EventHeader.EventDescriptor.Opcode = 11;
        if (DecodeProcess(bad, 1, point) != Match::Other) { return false; }
        bad = e;
        bad.EventHeader.EventDescriptor.Version = 6;
        if (DecodeProcess(bad, 1, point) != Match::Unsupported) { return false; }
        const size_t sid = 1 + Fixed(8, 4) + 16;
        auto invalid = [&](size_t at, uint8_t value) {
            auto broken = data;
            broken.at(at) = value;
            return DecodeProcess(Record(broken, 8, 4, 1), 1, point) == Match::Unsupported;
        };
        // SID revision/count, surrogate pairing and final string termination.
        if (!invalid(sid, 2) || !invalid(sid + 1, 16) || !invalid(sid + 16 + 2 + 3, 0) ||
            !invalid(data.size() - 1, 1)) { return false; }
        data.push_back(0);
        if (DecodeProcess(Record(data, 8, 4, 1), 1, point) != Match::Unsupported) { return false; }
        data = Payload(4, 2, false);
        const size_t ansi = 1 + Fixed(4, 2) + 4;
        data.resize(65536, 0x61);
        std::fill(data.begin() + ansi, data.end(), uint8_t{0x61});
        if (DecodeProcess(Record(data, 4, 2, 1), 1, point) != Match::Unsupported) { return false; }
        data[data.size() - 3] = data[data.size() - 2] = data.back() = 0;
        return DecodeProcess(Record(data, 4, 2, 1), 1, point) == Match::Decoded;
    }

    inline ProcessEvent Boundary(uint32_t n, uint8_t op)
    {
        ProcessEvent p;
        p.record = n;
        p.tick = 10ll * n;
        p.pid = 71;
        p.parent = 9;
        p.session = 1;
        p.key = 5;
        p.width = 8;
        p.version = 4;
        p.logger = 7;
        p.opcode = op;
        return p;
    }

    inline bool Brackets()
    {
        Sample sample{};
        sample.record = 20;
        sample.timestamp = 200;
        sample.tid = 42;
        sample.loggerId = 7;
        ThreadEvent first{12, 71, 42, 120, 1}, last{27, 71, 42, 270, 2};
        first.logger = last.logger = 7;
        ThreadPair thread{&first, &last, L"start_end", true};
        ProcessIndex index;
        auto lookup = [&](std::initializer_list<ProcessEvent> events, bool clock = true, bool gap = false) {
            index.events = events;
            index.decoded = static_cast<uint32_t>(events.size());
            index.Sort();
            return index.Lookup(sample, thread, clock, gap);
        };
        auto start = Boundary(10, 1), end = Boundary(30, 2);
        auto prior = Boundary(2, 1), priorEnd = Boundary(6, 2);
        auto later = Boundary(40, 1), laterEnd = Boundary(50, 2);
        prior.key = priorEnd.key = 17;
        later.key = laterEnd.key = 19;
        auto same = [](const ProcessPair& p, std::wstring_view relation) {
            return relation == p.relation && p.generation == (relation == L"start_end");
        };
        auto p = lookup({end, laterEnd, priorEnd, start, later, prior});
        if (!same(p, L"start_end") || !p.before || !p.after || p.before->record != 10 || p.after->record != 30 ||
            p.candidatePid != 71 || std::wstring_view(p.keyComparison) != L"equal") { return false; }
        if (!same(lookup({}), L"no_record") || !same(lookup({start}), L"one_boundary") ||
            !same(lookup({priorEnd, later}), L"outside_bracket") ||
            !same(lookup({start, end, later, Boundary(51, 1)}), L"conflicting_transitions") ||
            !same(lookup({start, end}, false), L"clock_unqualified") ||
            !same(lookup({start, end}, true, true), L"coverage_unqualified") ||
            !same(lookup({Boundary(13, 1), end}), L"thread_outside_process") ||
            !same(lookup({start, Boundary(26, 2)}), L"thread_outside_process")) { return false; }
        for (uint8_t a : std::array<uint8_t, 2>{1, 3})
        {
            for (uint8_t b : std::array<uint8_t, 2>{2, 4})
            {
                auto result = lookup({Boundary(a == 3 ? 14 : 10, a), Boundary(b == 4 ? 25 : 30, b)});
                if (!same(result, a == 1 && b == 2 ? L"start_end" : L"rundown_bracket")) { return false; }
            }
        }
        auto marker = Boundary(18, 39);
        if (!same(lookup({marker}), L"defunct_marker") || !same(lookup({start, marker, end}), L"defunct_marker") ||
            !same(lookup({start, end, Boundary(34, 39), later, laterEnd}), L"start_end")) { return false; }
        for (int i = 0; i < 3; ++i)
        {
            auto other = end;
            if (i == 0) { ++other.key; }
            if (i == 1) { ++other.session; }
            if (i == 2) { ++other.parent; }
            if (!same(lookup({start, other}), L"process_identity_conflict")) { return false; }
        }
        auto m = end;
        m.key = 0;
        if (std::wstring_view(lookup({start, m}).keyComparison) != L"one_unreported") { return false; }
        auto z = start;
        z.key = 0;
        auto zeroKeys = lookup({z, m});
        if (!same(zeroKeys, L"start_end") || std::wstring_view(zeroKeys.keyComparison) != L"unreported") { return false; }
        m = end; m.width = 4;
        if (!same(lookup({start, m}), L"layout_conflict")) { return false; }
        m = end; m.version = 3;
        if (!same(lookup({start, m}), L"layout_conflict")) { return false; }
        m = end; ++m.logger;
        if (!same(lookup({start, m}), L"logger_conflict")) { return false; }
        first.mixedLoggers = true;
        if (!same(lookup({start, end}), L"logger_conflict")) { return false; }
        first.mixedLoggers = false;
        ++sample.loggerId;
        if (!same(lookup({start, end}), L"logger_conflict")) { return false; }
        --sample.loggerId;
        m = end; m.tick = last.tick;
        if (!same(lookup({start, m}), L"clock_unqualified")) { return false; }
        m = laterEnd; m.tick = later.tick - 1;
        if (!same(lookup({start, end, later, m}), L"clock_unqualified")) { return false; }
        index.unsupported = 1;
        if (!same(lookup({start, end}), L"coverage_unqualified")) { return false; }
        index.unsupported = 0;
        thread.pairedPid = false;
        p = lookup({start, end});
        if (!same(p, L"thread_pid_unqualified") || !p.before || !p.after || !p.candidatePid) { return false; }
        ++last.pid;
        p = lookup({start, end});
        return same(p, L"thread_pid_unavailable") && !p.candidatePid && !p.before && !p.after;
    }

    inline bool ImagesAndLimits()
    {
        auto start = Boundary(10, 1), end = Boundary(40, 2);
        ProcessPair generation{&start, &end, L"start_end", L"equal", 71, true};
        ImageIndex images;
        images.names.push_back(L'x');
        auto fact = [](uint32_t n, uint8_t op) {
            ImageEvent e{};
            e.record = n; e.tick = 10ll * n;
            e.pid = 71; e.logger = 7; e.width = 8; e.opcode = op;
            e.base = 100; e.size = 16; e.nameUnits = 1;
            return e;
        };
        auto load = fact(15, 10), unload = fact(35, 2);
        Sample sample{};
        sample.record = 20; sample.timestamp = 200; sample.ip = 100;
        auto check = [&](std::initializer_list<ImageEvent> events, std::wstring_view wanted, bool reversed = false) {
            images.events = events;
            images.decoded = static_cast<uint32_t>(events.size());
            images.Sort();
            auto image = images.Lookup(sample, 71, true, false);
            const auto result = ImageInProcess(generation, image, reversed);
            return result.relation == wanted && result.paired == (wanted == L"inside_process_generation");
        };
        if (!check({load, unload}, L"inside_process_generation") || !check({load}, L"image_pair_unavailable") ||
            !check({load, unload}, L"clock_unqualified", true) || !check({fact(9, 10), unload}, L"image_outside_process") ||
            !check({load, fact(41, 2)}, L"image_outside_process")) { return false; }
        auto later = fact(44, 10);
        ++later.logger;
        if (!check({load, unload, later}, L"logger_conflict")) { return false; }
        auto equal = load;
        equal.tick = start.tick;
        if (!check({equal, unload}, L"clock_unqualified")) { return false; }
        generation.generation = false;
        if (!check({load, unload}, L"process_generation_unavailable")) { return false; }

        auto bytes = Payload(8, 4, false);
        auto event = Record(bytes, 8, 4, 1);
        event.EventHeader.TimeStamp.QuadPart = 100;
        ProcessIndex index;
        index.Prepare();
        for (uint32_t i = 0; i <= MaxProcessEvents; ++i) { index.Observe(event, i + 1, true); }
        if (index.events.size() != MaxProcessEvents || index.decoded != MaxProcessEvents + 1 ||
            std::wstring_view(index.Lookup(sample, {}, true, false).relation) != L"index_limit") { return false; }
        event.EventHeader.ProviderId = ImageProvider;
        event.EventHeader.EventDescriptor.Opcode = 10;
        event.EventHeader.TimeStamp.QuadPart = 90;
        index.Observe(event, index.decoded + 1, true);
        if (index.processClock.reversed || !index.imageClock.reversed) { return false; }
        event.EventHeader.ProviderId = ThreadProvider;
        event.EventHeader.EventDescriptor.Opcode = 2;
        index.Observe(event, index.decoded + 2, true);
        return index.processClock.reversed;
    }

    inline bool Check() { return Layout() && Brackets() && ImagesAndLimits(); }
}
