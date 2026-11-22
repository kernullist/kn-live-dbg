#include "../user/ExecutionTrace.h"
#include "../user/EtlThreadEvidence.h"
#include "../user/EtlImageEvidence.h"
#include "../user/EtlScheduleIntervals.h"
#include "etl-process-evidence-selftest.h"
#include "etl-reference-image-selftest.h"
#include "etl-build-evidence-selftest.h"
#include "etl-capture-settings-selftest.h"
#include "etl-clr-evidence-selftest.h"
#include "etl-disk-io-selftest.h"
#include "../user/EtlFaultSchedule.h"
#include "../user/EtlActivitySchedule.h"
#include "../user/EtlReadyBatch.h"
#include "etl-activity-window-selftest.h"

#include <array>

#include <iostream>

static bool CheckHardFaultRecord()
{
    using namespace etl_profile;
    for (unsigned width : {4u, 8u})
    {
        EVENT_RECORD event{};
        auto& h = event.EventHeader;
        h.ProviderId = PageFaultProvider;
        h.EventDescriptor.Version = 2;
        h.EventDescriptor.Opcode = 32;
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER |
            (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        h.TimeStamp.QuadPart = INT64_MAX;
        std::vector<uint8_t> bytes{0x5a}; // Unaligned payload; only the envelope determines pointer width.
        etl_disk_test::Append(bytes, int64_t{1});
        etl_disk_test::Append(bytes, UINT64_MAX);
        bytes.insert(bytes.end(), width * 2, 0xcd);
        etl_disk_test::Append(bytes, uint32_t{101});
        etl_disk_test::Append(bytes, UINT32_MAX);
        event.UserData = bytes.data() + 1;
        const auto size = static_cast<USHORT>(bytes.size() - 1);
        HardFault row{};
        for (USHORT n = 0; n <= size + 1; ++n)
        {
            event.UserDataLength = n;
            auto expected = n == size ? Match::Decoded : Match::Unsupported;
            if (DecodeHardFault(event, &row) != expected || DecodeHardFault(event, nullptr) != expected) { return false; }
        }
        if (row.width != width || row.readOffset != UINT64_MAX || row.faultingTid != 101 || row.byteCount != UINT32_MAX ||
            row.OrderedTicks() != INT64_MAX - 1ull) { return false; }
        HardFaultTotals totals;
        row.record = 4;
        row.initialTime = INT64_MAX;
        totals.Observe(row);
        if (row.OrderedTicks() != 0 || totals.longestTies != 1) { return false; }
        row.record = 5;
        --row.initialTime;
        totals.Observe(row);
        row.record = 6;
        totals.Observe(row);
        row.timestamp = INT64_MIN;
        totals.Observe(row);
        if (row.OrderedTicks()) { return false; }
        row.initialTime = 0;
        row.timestamp = 99;
        if (row.OrderedTicks()) { return false; }
        row.initialTime = INT64_MIN;
        totals.Observe(row);
        if (row.OrderedTicks() || totals.longest.record != 5 || totals.ordered != 3 ||
            totals.longestTies != 2 || totals.bytes != 5ull * UINT32_MAX) { return false; }
        event.UserDataLength = size;
        event.ExtendedDataCount = 1;
        if (DecodeHardFault(event, nullptr) != Match::Unsupported) { return false; }
        event.ExtendedDataCount = 0;
        for (auto flags : {0, EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER,
                          EVENT_HEADER_FLAG_STRING_ONLY, EVENT_HEADER_FLAG_TRACE_MESSAGE})
        {
            auto bad = event;
            bad.EventHeader.Flags = static_cast<USHORT>(flags ? h.Flags | flags : 0);
            if (DecodeHardFault(bad, &row) != Match::Unsupported) { return false; }
        }
        h.EventDescriptor.Version = 3;
        if (DecodeHardFault(event, &row) != Match::Unsupported) { return false; }
        h.EventDescriptor.Opcode = 14; // HardPageFault in the soft-fault layout is a different event.
        if (DecodeHardFault(event, &row) != Match::Other) { return false; }
    }
    return true;
}

static bool CheckProfileRecord()
{
    using namespace etl_profile;
    constexpr uint64_t ip = 0x8877665544332211ull;
    constexpr uint32_t tid = 0xa1b2c3d4;
    constexpr uint16_t count = 0x1102, reserved = 0xabcd;
    Sample row{};
    for (const uint8_t width : {uint8_t{8}, uint8_t{4}})
    {
        std::array<uint8_t, 17> bytes{};
        auto* payload = bytes.data() + 1;
        std::memcpy(payload, &ip, width);
        std::memcpy(payload + width, &tid, sizeof(tid));
        std::memcpy(payload + width + 4, &count, sizeof(count));
        std::memcpy(payload + width + 6, &reserved, sizeof(reserved));
        EVENT_HEADER_EXTENDED_DATA_ITEM extension{};
        extension.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
        EVENT_RECORD record{};
        record.EventHeader.ProviderId = PerfInfo;
        record.EventHeader.EventDescriptor.Opcode = 46;
        record.EventHeader.EventDescriptor.Version = 2;
        record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER |
            (width == 8 ? EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_PROCESSOR_INDEX : EVENT_HEADER_FLAG_32_BIT_HEADER);
        record.EventHeader.ThreadId = UINT32_MAX;
        if (width == 8) { record.BufferContext.ProcessorIndex = 291; }
        else { record.BufferContext.ProcessorNumber = 35; }
        record.UserData = payload;
        record.UserDataLength = width + 8;
        record.ExtendedDataCount = 1;
        record.ExtendedData = &extension;
        if (Decode(record, &row) != Match::Decoded || Decode(record, nullptr) != Match::Decoded ||
            row.width != width || row.ip != (width == 8 ? ip : static_cast<uint32_t>(ip)) ||
            row.tid != tid || row.headerTid != UINT32_MAX || row.count != count || row.reserved != reserved ||
            row.cpu != (width == 8 ? 291u : 35u) || row.extendedItems != 1 || row.stackItems != 1) { return false; }

        auto bad = record;
        bad.EventHeader.ProviderId = {};
        if (Decode(bad, &row) != Match::Other) { return false; }
        bad = record;
        ++bad.EventHeader.EventDescriptor.Opcode;
        if (Decode(bad, &row) != Match::Other) { return false; }
        for (const auto flags : {EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER,
                 EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER,
                 record.EventHeader.Flags | EVENT_HEADER_FLAG_STRING_ONLY, record.EventHeader.Flags | EVENT_HEADER_FLAG_TRACE_MESSAGE})
        {
            bad = record;
            bad.EventHeader.Flags = static_cast<USHORT>(flags);
            if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        }
        bad = record;
        bad.EventHeader.EventDescriptor.Version = 1;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        bad = record;
        bad.EventHeader.EventDescriptor.Id = 1;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        bad = record;
        --bad.UserDataLength;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        bad.UserDataLength += 2;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        bad = record;
        bad.ExtendedData = nullptr;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
        bad = record;
        bad.UserData = nullptr;
        if (Decode(bad, nullptr) != Match::Unsupported) { return false; }
    }
    return true;
}

static bool CheckThreadEvidence()
{
    using namespace etl_profile;
    std::array<uint8_t, 89> bytes{};
    const uint32_t payloadPid = 71, payloadTid = 93;
    auto* data = bytes.data() + 1;
    std::memcpy(data, &payloadPid, 4);
    std::memcpy(data + 4, &payloadTid, 4);
    EVENT_RECORD record{};
    auto& h = record.EventHeader;
    h.ProviderId = ThreadProvider;
    h.EventDescriptor.Version = 3;
    h.TimeStamp.QuadPart = 441;
    record.UserData = data;
    for (const uint8_t width : {uint8_t{4}, uint8_t{8}})
    {
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        for (uint8_t op = 1; op <= 4; ++op)
        {
            h.EventDescriptor.Opcode = op;
            record.UserDataLength = 16 + 7 * width;
            ThreadEvent point{};
            if (DecodeThread(record, 17, point) != Match::Decoded || point.pid != payloadPid || point.tid != payloadTid ||
                point.tick != 441 || point.record != 17 || point.opcode != op) { return false; }
            --record.UserDataLength;
            if (DecodeThread(record, 17, point) != Match::Unsupported) { return false; }
            const auto fixed = size_t{16} + 7 * width;
            auto suffix = [&](std::initializer_list<uint8_t> units, Match want) {
                std::copy(units.begin(), units.end(), data + fixed);
                record.UserDataLength = static_cast<USHORT>(fixed + units.size());
                if (DecodeThread(record, 17, point) != want) { return false; }
                return want != Match::Decoded || (point.pid == payloadPid && point.tid == payloadTid);
            };
            if (!suffix({0, 0}, Match::Decoded) || !suffix({0x41, 0, 0, 0}, Match::Decoded) ||
                !suffix({0x3d, 0xd8, 0, 0xde, 0, 0}, Match::Decoded) ||
                !suffix({0}, Match::Unsupported) || !suffix({0x41, 0}, Match::Unsupported) ||
                !suffix({0, 0, 0x41, 0}, Match::Unsupported) || !suffix({0, 0, 0, 0}, Match::Unsupported) ||
                !suffix({0x3d, 0xd8, 0, 0}, Match::Unsupported) || !suffix({0, 0xde, 0, 0}, Match::Unsupported) ||
                !suffix({0x3d, 0xd8, 0x41, 0, 0, 0}, Match::Unsupported)) { return false; }
        }
    }
    std::vector<uint8_t> large(UINT16_MAX);
    for (size_t offset = 72; offset < UINT16_MAX - 3; offset += 2) { large[offset] = 'a'; }
    record.UserData = large.data();
    record.UserDataLength = UINT16_MAX - 1;
    ThreadEvent boundary{};
    if (DecodeThread(record, 1, boundary) != Match::Decoded) { return false; }
    ++record.UserDataLength;
    if (DecodeThread(record, 1, boundary) != Match::Unsupported) { return false; }
    record.UserData = data;
    record.UserDataLength = 72;
    ThreadIndex index;
    index.Prepare();
    h.EventDescriptor.Version = 4;
    index.Observe(record, 4);
    h.EventDescriptor.Version = 3;
    h.EventDescriptor.Opcode = 36;
    index.Observe(record, 5);
    if (index.decoded || index.unsupported != 1) { return false; }

    Sample sample{};
    sample.tid = 93;
    sample.timestamp = 200;
    sample.record = 20;
    auto check = [&](const wchar_t* relation, bool pid, bool clock = true, bool gap = false) {
        const auto pair = index.Lookup(sample, clock, gap);
        return std::wstring(pair.relation) == relation && pair.pairedPid == pid;
    };
    if (!check(L"no_record", false)) { return false; }
    index.events = {{30, 71, 93, 300, 2}, {9, 14, 8, 80, 1}, {10, 71, 93, 100, 1}};
    index.decoded = 3;
    index.Sort();
    if (!check(L"coverage_unqualified", false)) { return false; }
    index.unsupported = 0;
    if (!check(L"start_end", true) || !check(L"clock_unqualified", false, false) ||
        !check(L"coverage_unqualified", false, true, true)) { return false; }
    auto pair = index.Lookup(sample, true, false);
    if (!pair.before || !pair.after || pair.before->record != 10 || pair.after->record != 30) { return false; }
    sample.timestamp = 300;
    if (!check(L"clock_unqualified", false)) { return false; }
    sample.timestamp = 200;
    sample.record = 5;
    if (!check(L"one_boundary", false)) { return false; }
    sample.record = 20;
    index.events[1].opcode = 3;
    if (!check(L"rundown_bracket", true)) { return false; }
    index.events[1].pid = 89;
    if (!check(L"pid_conflict", false)) { return false; }
    index.events[1].pid = 71;
    index.events[1].opcode = 2;
    if (!check(L"outside_bracket", false)) { return false; }
    index.events[1].opcode = 1;
    index.events.push_back({7, 71, 93, 60, 1});
    ++index.decoded;
    index.Sort();
    if (!check(L"conflicting_transitions", false)) { return false; }
    index.events = {{1, 45, 93, 10, 1}, {2, 45, 93, 40, 2}, {10, 71, 93, 100, 1}, {30, 71, 93, 300, 2}};
    index.Sort();
    pair = index.Lookup(sample, true, false);
    if (!pair.pairedPid || !pair.before || pair.before->pid != 71) { return false; }
    index.events[1].tick = 110;
    index.Sort();
    if (!check(L"clock_unqualified", false)) { return false; }
    sample.tid = 0;
    if (!check(L"unusable_tid", false)) { return false; }
    // Exercise the real retention bound and ensure no partial index can emit a bracket.
    index.events.clear();
    index.decoded = 0;
    record.EventHeader.EventDescriptor.Opcode = 1;
    for (uint32_t i = 0; i < MaxThreadEvents + 1; ++i) { index.Observe(record, i + 1); }
    sample.tid = payloadTid;
    return index.events.size() == MaxThreadEvents && index.decoded == MaxThreadEvents + 1 && check(L"index_limit", false);
}

static bool CheckImageLayout()
{
    using namespace etl_profile;
    ImageEvent point{};
    const uint8_t* name = nullptr;
    std::array<uint8_t, 73> storage{};
    auto* bytes = storage.data() + 1;
    EVENT_RECORD record{};
    auto& h = record.EventHeader;
    h.ProviderId = ImageProvider;
    h.TimeStamp.QuadPart = 123;
    record.UserData = bytes;
    for (uint8_t width : {uint8_t{4}, uint8_t{8}})
    {
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        const uint64_t max = width == 4 ? UINT32_MAX : UINT64_MAX;
        const uint64_t base = max - 3, size = 4, preferred = base - 91;
        const size_t fixed = 3 * width + 32;
        std::memcpy(bytes, &base, width);
        std::memcpy(bytes + width, &size, width);
        const uint32_t metadata[] = {19, 0xabcd, 4321, 0x0908};
        std::memcpy(bytes + 2 * width, metadata, sizeof(metadata));
        std::memcpy(bytes + 2 * width + 16, &preferred, width);
        const uint8_t suffix[] = {0x3d, 0xd8, 0, 0xde, 0, 0};
        std::memcpy(bytes + fixed, suffix, sizeof(suffix));
        record.UserDataLength = static_cast<USHORT>(fixed + sizeof(suffix));
        for (uint8_t version : {uint8_t{2}, uint8_t{3}})
        {
            h.EventDescriptor.Version = version;
            for (uint8_t op : {uint8_t{2}, uint8_t{3}, uint8_t{4}, uint8_t{10}})
            {
                h.EventDescriptor.Opcode = op;
                if (DecodeImage(record, 14, point, name) != Match::Decoded || name != bytes + fixed ||
                    point.nameUnits != 2 || point.base != base || point.size != size || point.preferred != preferred ||
                    point.checksum != metadata[1] || point.stamp != metadata[2] || point.pid != metadata[0] ||
                    point.version != version || point.width != width || point.opcode != op || point.record != 14 ||
                    point.tick != 123 || point.signatureLevel != (version == 3 ? 8 : 0) ||
                    point.signatureType != (version == 3 ? 9 : 0)) { return false; }
            }
        }
        auto bad = record;
        for (const size_t n : {fixed - 1, fixed, fixed + 2, fixed + 4, fixed + 5, fixed + 8})
        {
            bad.UserDataLength = static_cast<USHORT>(n);
            if (DecodeImage(bad, 1, point, name) != Match::Unsupported) { return false; }
        }
        bad = record;
        bad.EventHeader.Flags |= EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_32_BIT_HEADER;
        if (DecodeImage(bad, 1, point, name) != Match::Unsupported) { return false; }
        bad = record;
        bad.EventHeader.EventDescriptor.Version = 4;
        if (DecodeImage(bad, 1, point, name) != Match::Unsupported) { return false; }
        bad.EventHeader.EventDescriptor.Opcode = 33;
        if (DecodeImage(bad, 1, point, name) != Match::Other) { return false; }
        bytes[width] = 0;
        if (DecodeImage(record, 1, point, name) != Match::Unsupported) { return false; }
        bytes[width] = 5;
        if (DecodeImage(record, 1, point, name) != Match::Unsupported) { return false; }
        bytes[width] = 4;
        bytes[fixed + 3] = 0;
        if (DecodeImage(record, 1, point, name) != Match::Unsupported) { return false; }
    }
    std::memset(bytes, 0, 64);
    bytes[8] = 1;
    bytes[56] = 'a';
    record.UserDataLength = 60;
    ImageIndex index;
    index.Prepare();
    index.names.resize(MaxImageNameUnits - 1);
    index.Observe(record, 1);
    index.Observe(record, 2);
    index.Observe(record, 3);
    Sample sample{};
    if (index.names.size() != MaxImageNameUnits || index.events.size() != 1 || index.decoded != 3 ||
        index.Name(index.events.front()) != L"a" || std::wstring_view(index.retention) != L"name_limit" ||
        std::wstring_view(index.Lookup(sample, 19, true, false).relation) != L"index_limit") { return false; }
    index.names.clear();
    index.events.clear();
    index.decoded = 0;
    for (uint32_t i = 0; i <= MaxImageEvents; ++i) { index.Observe(record, i + 1); }
    return index.events.size() == MaxImageEvents && index.decoded == MaxImageEvents + 1 &&
        std::wstring_view(index.retention) == L"event_limit" && !index.Complete();
}

static bool CheckImageEvidence()
{
    using namespace etl_profile;
    ImageIndex index;
    index.names = {L'A', L'B'};
    auto point = [](uint32_t n, uint8_t op, uint32_t pid, uint64_t base) {
        ImageEvent e{};
        e.record = n; e.tick = 10 * n; e.opcode = op; e.pid = pid;
        e.base = base; e.size = 0x100; e.nameUnits = 1; e.width = 8; e.version = 3;
        return e;
    };
    const auto load = point(10, 10, 19, 0x1200), unload = point(30, 2, 19, 0x1200);
    Sample sample{};
    sample.ip = 0x1260;
    sample.record = 20;
    sample.timestamp = 200;
    auto lookup = [&](uint32_t pid = 19, bool clock = true, bool gap = false) {
        index.decoded = static_cast<uint32_t>(index.events.size());
        index.Sort();
        return index.Lookup(sample, pid, clock, gap);
    };
    auto is = [](const ImageMatch& result, const wchar_t* relation, bool paired = false) {
        return result.paired == paired && std::wstring_view(result.relation) == relation;
    };
    index.events = {unload, load, point(8, 10, 71, load.base), point(32, 2, 71, load.base)};
    auto matched = lookup();
    if (!is(matched, L"load_unload", true) || matched.count != 1 || matched.rva != 0x60 ||
        matched.witnesses[0].before->record != 10 || matched.witnesses[0].after->record != 30 ||
        !is(lookup(12), L"no_recorded_range") || !is(lookup(0), L"thread_pid_unavailable") ||
        !is(lookup(19, false), L"clock_unqualified") || !is(lookup(19, true, true), L"coverage_unqualified")) { return false; }
    index.unsupported = 1;
    if (!is(lookup(), L"coverage_unqualified")) { return false; }
    index.unsupported = 0;
    sample.ip = load.base + load.size;
    if (!is(lookup(), L"no_recorded_range")) { return false; }
    sample.ip = load.base;
    if (!is(lookup(), L"load_unload", true) || lookup().rva != 0) { return false; }
    sample.ip = load.base + 0x60;
    index.events = {load};
    if (!is(lookup(), L"one_boundary") || lookup().witnesses[0].after) { return false; }
    index.events = {point(10, 2, 19, load.base), point(30, 10, 19, load.base)};
    if (!is(lookup(), L"no_recorded_range")) { return false; }
    index.events = {point(10, 3, 19, load.base), point(30, 4, 19, load.base)};
    if (!is(lookup(), L"rundown_bracket", true)) { return false; }
    index.events[0].tick = sample.timestamp;
    if (!is(lookup(), L"clock_unqualified")) { return false; }
    index.events[0].tick = 400;
    if (!is(lookup(), L"clock_unqualified")) { return false; }
    index.events = {load, unload};
    index.events[1].nameOffset = 1;
    if (!is(lookup(), L"image_identity_conflict")) { return false; }
    index.events[1] = unload;
    index.events[1].signatureType = 7;
    if (!is(lookup(), L"image_identity_conflict")) { return false; }
    index.events[1] = unload;
    index.events[1].size = 64;
    if (!is(lookup(), L"image_identity_conflict")) { return false; }
    index.events[1] = unload;
    index.events[0].nameUnits = index.events[1].nameUnits = 0;
    if (!is(lookup(), L"missing_image_name")) { return false; }
    index.events = {load, unload, point(31, 10, 19, load.base), point(45, 2, 19, load.base)};
    index.events[2].nameOffset = index.events[3].nameOffset = 1;
    if (!is(lookup(), L"load_unload", true)) { return false; }
    sample.record = 40;
    sample.timestamp = 400;
    auto remap = lookup();
    if (!is(remap, L"load_unload", true) || index.Name(*remap.witnesses[0].before) != L"B") { return false; }
    sample.record = 20;
    sample.timestamp = 200;
    index.events = {load, unload, point(12, 10, 19, 0x1220), point(35, 2, 19, 0x1220), point(5, 3, 19, 0x1240)};
    auto overlap = lookup();
    if (!is(overlap, L"overlapping_ranges") || overlap.count != 3 ||
        overlap.witnesses[0].before->base != 0x1240 || overlap.witnesses[1].before->base != 0x1220) { return false; }
    index.events = {load, unload, point(5, 10, 19, 0x1220), point(12, 2, 19, 0x1220)};
    if (!is(lookup(), L"load_unload", true)) { return false; }
    index.events.push_back(point(11, 3, 19, load.base));
    return is(lookup(), L"conflicting_transitions");
}

static bool CheckSwitchRecord()
{
    using namespace etl_profile;
    std::array<uint8_t, 25> storage{
        0xee, 0x78, 0x56, 0x34, 0x12, 0x98, 0xba, 0xdc, 0xfe,
        0xff, 0x7f, 0xa5, 0xf0, 0x80, 0x86, 5, 0xff,
        1, 2, 3, 4, 0xff, 0xfe, 0xfd, 0xfc
    };
    EVENT_RECORD event{};
    event.UserData = storage.data() + 1;
    event.UserDataLength = 24;
    auto& h = event.EventHeader;
    h.ProviderId = ThreadProvider;
    h.EventDescriptor.Opcode = 36;
    h.ThreadId = 87;
    h.ProcessId = 92;
    h.TimeStamp.QuadPart = 1234;
    EVENT_HEADER_EXTENDED_DATA_ITEM ext{};
    ext.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
    event.ExtendedData = &ext;
    event.ExtendedDataCount = 1;
    SwitchEvent point{};
    for (const uint8_t width : {uint8_t{4}, uint8_t{8}})
    {
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER :
            EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_PROCESSOR_INDEX);
        event.BufferContext.ProcessorIndex = width == 4 ? 31 : 301;
        event.BufferContext.LoggerId = 29;
        for (uint8_t version = 2; version <= 4; ++version)
        {
            h.EventDescriptor.Version = version;
            if (DecodeSwitch(event, nullptr) != Match::Decoded || DecodeSwitch(event, &point) != Match::Decoded) { return false; }
            const auto& f = point.fields;
            if (point.version != version || point.timestamp != 1234 || point.headerTid != 87 || point.headerPid != 92 ||
                point.cpu != (width == 4 ? 31u : 301u) || point.width != width || point.loggerId != 29 ||
                point.stackItems != 1 || point.extendedItems != 1 || point.flags != h.Flags ||
                f.newTid != 0x12345678u || f.oldTid != 0xfedcba98u || f.newPriority != -1 ||
                f.oldPriority != 127 || f.previousCState != 0xa5 || f.spare != -16 ||
                f.oldWaitReason != -128 || f.modeOrFlags != -122 || f.oldState != 5 ||
                f.idealProcessor != -1 || f.newWaitTime != 0x04030201u || f.reserved != 0xfcfdfeffu) { return false; }
        }
    }
    auto bad = event;
    bad.ExtendedData = nullptr;
    if (DecodeSwitch(bad, nullptr) != Match::Unsupported) { return false; }
    bad = event;
    bad.UserData = nullptr;
    if (DecodeSwitch(bad, &point) != Match::Unsupported) { return false; }
    bad = event;
    for (USHORT length : {USHORT{0}, USHORT{23}, USHORT{25}, USHORT{65535}})
    {
        bad.UserDataLength = length;
        if (DecodeSwitch(bad, nullptr) != Match::Unsupported) { return false; }
    }
    bad = event;
    bad.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
    if (DecodeSwitch(bad, &point) != Match::Unsupported) { return false; }
    bad = event;
    bad.EventHeader.EventDescriptor.Id = 1;
    if (DecodeSwitch(bad, &point) != Match::Unsupported) { return false; }
    bad = event;
    for (uint8_t version : {uint8_t{0}, uint8_t{1}, uint8_t{5}})
    {
        bad.EventHeader.EventDescriptor.Version = version;
        if (DecodeSwitch(bad, nullptr) != Match::Unsupported) { return false; }
    }
    bad = event;
    bad.EventHeader.ProviderId = PerfInfo;
    if (DecodeSwitch(bad, &point) != Match::Other) { return false; }
    bad = event;
    bad.EventHeader.EventDescriptor.Opcode = 3;
    return DecodeSwitch(bad, nullptr) == Match::Other;
}

static EVENT_RECORD SchedulerRecord(void* data, USHORT size, uint8_t opcode, uint8_t version, int64_t tick)
{
    EVENT_RECORD e{};
    e.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_PROCESSOR_INDEX;
    e.EventHeader.ProviderId = etl_profile::ThreadProvider;
    e.EventHeader.EventDescriptor.Opcode = opcode;
    e.EventHeader.EventDescriptor.Version = version;
    e.EventHeader.TimeStamp.QuadPart = tick;
    e.BufferContext.ProcessorIndex = 1;
    e.BufferContext.LoggerId = 7;
    e.UserData = data;
    e.UserDataLength = size;
    return e;
}

static bool CheckReadyLayout()
{
    using namespace etl_profile;
    std::array<uint8_t, 9> storage{0, 0x12, 0x34, 0x56, 0x78, 0xfe, 0x81, 0x84, 0xff};
    auto e = SchedulerRecord(storage.data() + 1, 8, 50, 2, -10);
    ReadyPoint p{};
    for (const auto width : std::array<USHORT, 2>{EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER})
    {
        e.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | width | EVENT_HEADER_FLAG_PROCESSOR_INDEX;
        if (DecodeReady(e, 9, p) != Match::Decoded || p.tid != 0x78563412 || p.reason != -2 || p.increment != -127 ||
            p.flags != 0x84 || p.reserved != -1 || p.at.tick != -10 || p.at.record != 9 || p.at.logger != 7 ||
            !p.at.indexed || p.at.cpu != 1) { return false; }
    }
    for (const auto len : std::array<USHORT, 3>{0, 7, 9})
    {
        auto bad = e;
        bad.UserDataLength = len;
        if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    }
    auto bad = e;
    bad.UserData = nullptr;
    if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    bad = e;
    bad.ExtendedDataCount = 1;
    if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    bad = e;
    ++bad.EventHeader.EventDescriptor.Version;
    if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    bad = e;
    ++bad.EventHeader.EventDescriptor.Id;
    if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    bad = e;
    bad.EventHeader.Flags |= EVENT_HEADER_FLAG_32_BIT_HEADER;
    if (DecodeReady(bad, 1, p) != Match::Unsupported) { return false; }
    bad = e;
    ++bad.EventHeader.EventDescriptor.Opcode;
    if (DecodeReady(bad, 1, p) != Match::Other) { return false; }
    e.EventHeader.ProviderId = {};
    return DecodeReady(e, 1, p) == Match::Other;
}

static etl_profile::SwitchEvent SwitchAt(uint32_t record, int64_t tick, uint32_t cpu, uint32_t out, uint32_t in)
{
    etl_profile::SwitchEvent e{};
    e.record = e.ordinal = record;
    e.timestamp = tick;
    e.cpu = cpu;
    e.loggerId = 7;
    e.flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_PROCESSOR_INDEX;
    e.version = 4;
    e.fields.oldTid = out;
    e.fields.newTid = in;
    e.fields.oldState = 5;
    e.fields.oldWaitReason = 17;
    return e;
}

static bool IsSpan(etl_profile::ReportedSpan span, const wchar_t* name, bool measured = false)
{
    return span.measured == measured && std::wstring(span.relation) == name;
}

static bool CheckSchedulingIntervals()
{
    using namespace etl_profile;
    const auto first = SwitchAt(1, 100, 0, 500, 42), leave = SwitchAt(2, 200, 0, 42, 50);
    const auto back = SwitchAt(5, 300, 1, 700, 42), stop = SwitchAt(6, 350, 1, 42, 900);
    const std::array<SwitchEvent, 3> page{leave, back, stop};
    ScheduleHistory h;
    h.Prepare(2, page.data(), page.size());
    IntervalWitnesses atLeave{}, atBack{}, atStop{};
    h.Observe(first, nullptr);
    h.Observe(leave, &atLeave);
    auto beforeReady = h;
    std::array<uint8_t, 8> payload{42, 0, 0, 0, 2, 3, 2, 0};
    auto deferred = SchedulerRecord(payload.data(), 8, 50, 2, 220);
    h.OtherThreadEvent(deferred, 3);
    auto ready = deferred;
    payload[6] = 1;
    ready.EventHeader.TimeStamp.QuadPart = 240;
    h.OtherThreadEvent(ready, 4);
    h.Observe(back, &atBack);
    h.Observe(stop, &atStop);
    const auto& seq = atBack.ready;
    const auto& out = atBack.previousIncomingThread;
    auto off = [&](const ScheduleHistory& history) { return AssessSpan(history, back, atBack, false, true, false); };
    auto split = [&](const ReadySequence& s) { return AssessReady(s, out, back, true, 0); };
    if (!IsSpan(AssessSpan(h, leave, atLeave, true, true, false), L"running_on_cpu", true) ||
        !IsSpan(AssessSpan(h, stop, atStop, true, true, false), L"running_on_cpu", true) ||
        !IsSpan(off(h), L"off_cpu", true) || !IsSpan(split(seq), L"waiting_ready_switch_in", true) ||
        out.at.cpu == back.cpu || out.at.record != 2 || out.reason != 17 ||
        seq.count != 2 || seq.dispatchable != 1 || seq.first.at.record != 3 || seq.last.at.record != 4 ||
        TickDistance(out.at.tick, seq.last.at.tick) != 40 || TickDistance(seq.last.at.tick, back.timestamp) != 60 ||
        TickDistance(INT64_MIN, INT64_MAX) != UINT64_MAX) { return false; }
    auto preempted = out;
    preempted.state = 1;
    if (!IsSpan(AssessReady(seq, preempted, back, true, 0), L"ready_switch_in", true) ||
        !IsSpan(AssessReady(seq, out, back, false, 0), L"off_cpu_unqualified") ||
        !IsSpan(AssessReady(seq, out, back, true, 1), L"ready_coverage_unqualified") ||
        !IsSpan(split({}), L"ready_unobserved") ||
        !IsSpan(AssessSpan(h, back, atBack, false, false, false), L"clock_unqualified") ||
        !IsSpan(AssessSpan(h, back, atBack, false, true, true), L"coverage_unqualified")) { return false; }

    ReadySequence changes;
    changes.Append(seq.first);
    if (!IsSpan(split(changes), L"ready_deferred")) { return false; }
    auto candidate = seq.last;
    candidate.flags = 8;
    changes.Append(candidate);
    if (!IsSpan(split(changes), L"ready_flags_unqualified")) { return false; }
    changes = {};
    changes.Append(seq.last);
    candidate = seq.last;
    candidate.at.tick += 5;
    changes.Append(candidate);
    if (!IsSpan(split(changes), L"ready_sequence_conflict")) { return false; }
    changes = {};
    changes.Append(seq.last);
    candidate.flags = 4;
    changes.Append(candidate);
    if (!IsSpan(split(changes), L"ready_sequence_conflict")) { return false; }
    changes = {};
    changes.Append(seq.first);
    candidate = seq.last;
    ++candidate.at.logger;
    changes.Append(candidate);
    if (!IsSpan(split(changes), L"ready_scope_unqualified")) { return false; }
    for (const int64_t tick : {200, 220, 219, 300, 301})
    {
        changes = {};
        changes.Append(seq.first);
        candidate = seq.last;
        candidate.at.tick = tick;
        changes.Append(candidate);
        if (!IsSpan(split(changes), L"ready_clock_unqualified")) { return false; }
    }

    // Each lifecycle opcode splits the chain at the reused numeric thread ID.
    std::array<uint32_t, 18> boundary{123, 42};
    auto lifetime = SchedulerRecord(boundary.data(), 72, 1, 3, 260);
    for (uint8_t op = 1; op <= 4; ++op)
    {
        auto reuse = beforeReady;
        lifetime.EventHeader.EventDescriptor.Opcode = op;
        reuse.OtherThreadEvent(lifetime, 4);
        IntervalWitnesses atReuse{}, afterReuse{};
        reuse.Observe(back, &atReuse);
        reuse.Observe(stop, &afterReuse);
        if (!IsSpan(AssessSpan(reuse, back, atReuse, false, true, false), L"thread_boundary") ||
            atReuse.previousIncomingThread.pid != 123 || atReuse.previousIncomingThread.opcode != op ||
            atReuse.ready.count || !IsSpan(AssessSpan(reuse, stop, afterReuse, true, true, false), L"running_on_cpu", true))
        { return false; }
    }
    auto failed = h;
    lifetime.EventHeader.EventDescriptor.Version = 4;
    failed.OtherThreadEvent(lifetime, 7);
    if (failed.unsupportedBoundaries != 1 || !IsSpan(off(failed), L"coverage_unqualified")) { return false; }
    failed = h;
    ready.UserDataLength = 7;
    failed.OtherThreadEvent(ready, 7);
    if (failed.unsupportedReady != 1 || !IsSpan(off(failed), L"off_cpu", true) ||
        !IsSpan(AssessReady(seq, out, back, true, failed.unsupportedReady), L"ready_coverage_unqualified")) { return false; }
    failed = h;
    failed.Observe(SwitchAt(7, 380, 0, UINT32_MAX, 999), nullptr);
    if (!failed.unknownSwitchTid || !IsSpan(off(failed), L"coverage_unqualified")) { return false; }
    failed = h;
    failed.Observe(SwitchAt(7, 380, 0, 888, 999), nullptr);
    if (failed.cpuConflicts != 1 || !IsSpan(off(failed), L"cpu_history_conflict")) { return false; }
    failed = h;
    failed.Observe(SwitchAt(7, 380, 0, 50, 900), nullptr);
    if (!IsSpan(AssessSpan(failed, back, atBack, false, true, false), L"off_cpu", true) ||
        !failed.Watch(900)->badTransitions) { return false; }
    failed = h;
    ready.UserDataLength = 8;
    ready.EventHeader.TimeStamp.QuadPart = 310;
    failed.OtherThreadEvent(ready, 7);
    if (!failed.reversedClock || !IsSpan(off(failed), L"clock_unqualified")) { return false; }
    return true;
}

static bool CheckSchedulerScopes()
{
    using namespace etl_profile;
    auto a = SwitchAt(1, 10, 0, 12, 34), b = SwitchAt(2, 20, 0, 12, 56);
    IntervalWitnesses w{};
    ScheduleHistory conflict;
    conflict.Prepare(2, &b, 1);
    conflict.Observe(a, nullptr);
    conflict.Observe(b, &w);
    if (!IsSpan(AssessSpan(conflict, b, w, true, true, false), L"cpu_tid_conflict") ||
        w.previousCpu.at.record != w.previousOutgoingThread.at.record ||
        SameTransition(w.previousCpu, w.previousOutgoingThread)) { return false; }

    b = SwitchAt(2, 20, 0, 34, 34);
    ScheduleHistory self;
    self.Prepare(2, &b, 1);
    self.Observe(a, nullptr);
    self.Observe(b, &w);
    if (!IsSpan(AssessSpan(self, b, w, false, true, false), L"same_switch") ||
        !IsSpan(AssessSpan(self, b, w, true, true, false), L"running_on_cpu", true) ||
        !SameTransition(w.previousOutgoingThread, w.previousCpu)) { return false; }

    a = SwitchAt(1, 10, 0, 8, 0);
    b = SwitchAt(3, 30, 0, 0, 0);
    ScheduleHistory idle;
    idle.Prepare(2, &b, 1);
    idle.Observe(a, nullptr);
    idle.Observe(SwitchAt(2, 20, 1, 8, 0), nullptr);
    w = {};
    idle.Observe(b, &w);
    if (!idle.threads.empty() || w.previousCpu.at.record != 1 ||
        !IsSpan(AssessSpan(idle, b, w, true, true, false), L"idle_on_cpu", true) ||
        !IsSpan(AssessSpan(idle, b, w, false, true, false), L"idle_tid")) { return false; }
    auto unknown = SwitchAt(4, 40, 0, UINT32_MAX, UINT32_MAX);
    if (!IsSpan(AssessSpan(idle, unknown, {}, true, true, false), L"unusable_tid") ||
        !IsSpan(AssessSpan(idle, unknown, {}, false, true, false), L"unusable_tid")) { return false; }
    auto zeroTime = idle;
    zeroTime.Observe(SwitchAt(4, 30, 0, 0, 7), nullptr);
    if (zeroTime.cpuClockConflicts != 1 || !IsSpan(AssessSpan(zeroTime, b, w, true, true, false), L"clock_unqualified"))
    { return false; }
    for (int i = 0; i < 5; ++i)
    {
        ScheduleHistory scope;
        scope.Prepare(i == 0 ? 65 : i == 1 ? 65537 : 2, &b, 1);
        auto start = a, end = b;
        if (i == 0 || i == 2) { end.flags &= ~EVENT_HEADER_FLAG_PROCESSOR_INDEX; }
        if (i == 0) { start.flags = end.flags; }
        if (i == 3) { ++end.loggerId; }
        if (i == 4) { end.cpu = 2; }
        scope.Observe(start, nullptr);
        IntervalWitnesses probe{};
        scope.Observe(end, &probe);
        if (!IsSpan(AssessSpan(scope, end, probe, true, true, false), L"processor_scope_unqualified")) { return false; }
    }
    // A switch on CPU 1 provides a second incoming edge for the same watched TID.
    a = SwitchAt(1, 10, 0, 9, 42);
    b = SwitchAt(2, 20, 0, 42, 8);
    auto cross = SwitchAt(3, 25, 1, 7, 42);
    ScheduleHistory duplicate;
    duplicate.Prepare(2, &b, 1);
    duplicate.Observe(a, nullptr);
    IntervalWitnesses earlier{};
    duplicate.Observe(b, &earlier);
    duplicate.Observe(cross, nullptr);
    duplicate.Observe(SwitchAt(4, 30, 0, 8, 42), nullptr);
    return IsSpan(AssessSpan(duplicate, b, earlier, true, true, false), L"thread_transition_conflict");
}

static bool CheckReadyOrigin()
{
    using namespace etl_profile;
    std::array<uint8_t, 8> payload{42, 0, 0, 0, 1, 2, 8, 0};
    auto ready = SchedulerRecord(payload.data(), 8, 50, 2, 250);
    ready.EventHeader.ThreadId = 73;
    ready.EventHeader.ProcessId = 177;
    const auto targetOut = SwitchAt(3, 100, 0, 42, 77);
    const auto sourceIn = SwitchAt(4, 150, 1, 99, 73);
    const auto close = SwitchAt(6, 300, 1, 73, 42);
    ReadyBatch batch;
    const std::vector<uint32_t> requested{5};
    batch.Prepare(requested.size());
    auto& o = batch.rows.front();
    auto unavailable = ready;
    ++unavailable.EventHeader.EventDescriptor.Version;
    o.Select(unavailable, 5);
    if (!o.observed || o.match != Match::Unsupported) { return false; }
    unavailable.EventHeader.ProviderId = {};
    o.Select(unavailable, 5);
    if (o.match != Match::Other) { return false; }
    batch.Select(ready, 5, requested);
    batch.SelectSwitch(close);
    ScheduleHistory h;
    batch.PrepareReplay(h, 2);
    h.Observe(targetOut, nullptr);
    h.Observe(sourceIn, nullptr);
    size_t rows = 0;
    bool mismatch = false;
    batch.ReplaySelection(ready, 5, requested, h, rows, mismatch);
    h.OtherThreadEvent(ready, 5);
    auto alteredBatch = batch;
    auto changedHistory = h;
    batch.ReplaySwitch(h, close, rows, mismatch);
    if (o.ReplayRows() != 3 || rows != 3 || mismatch || !o.SameReady(ready, 5)) { return false; }
    auto changed = ready;
    ++changed.EventHeader.ThreadId;
    if (o.SameReady(changed, 5)) { return false; }
    auto wrongEnd = close;
    ++wrongEnd.fields.oldWaitReason;
    auto altered = o;
    alteredBatch.ReplaySwitch(changedHistory, wrongEnd, rows, mismatch);
    if (!mismatch) { return false; }
    ThreadIndex i;
    i.events = {{1, 101, 42, 20, 1, false, false, 7}, {2, 177, 73, 25, 3, false, false, 7},
                {7, 101, 42, 500, 2, false, false, 7}, {8, 177, 73, 550, 4, false, false, 7}};
    i.decoded = 4;
    i.Sort();
    const auto source = o.Bracket(i, 73, true, false);
    const auto target = o.Bracket(i, 42, true, false);
    const auto cpu = o.Assess(h, source, true, true, false);
    const auto off = o.Assess(h, target, false, true, false);
    const auto split = o.Dispatch(h, off);
    if (!source.pairedPid || !target.pairedPid || !IsSpan(cpu, L"running_on_cpu", true) ||
        !IsSpan(split, L"waiting_ready_switch_in", true) || !IsSpan(o.Relationship(cpu, split, source), L"readying_thread_context", true)) { return false; }

    const auto relation = [&](ReadyOrigin copy, const wchar_t* expected) {
        return IsSpan(copy.Relationship(cpu, copy.Dispatch(h, off), source), expected);
    };
    altered = o;
    ++altered.headerPid;
    if (!relation(altered, L"ready_header_unqualified")) { return false; }
    altered.headerPid = UINT32_MAX;
    if (!relation(altered, L"ready_header_unqualified")) { return false; }
    altered = o;
    altered.ready.flags |= 1;
    if (!relation(altered, L"dpc_context")) { return false; }
    altered = o;
    ++altered.target.witnesses.ready.last.at.record;
    if (!relation(altered, L"selected_record_not_dispatchable")) { return false; }
    altered = o;
    altered.target.witnesses.ready.invalidProcessorScope = true;
    if (!relation(altered, L"ready_scope_unqualified")) { return false; }
    altered = o;
    altered.target.witnesses.previousIncomingThread.state = 1;
    if (!relation(altered, L"target_not_reported_waiting")) { return false; }
    altered = o;
    ++altered.targetAtReady.at.record;
    if (!IsSpan(altered.Assess(h, target, false, true, false), L"intervening_transition")) { return false; }
    altered = o;
    altered.target.end = {};
    if (!IsSpan(altered.Assess(h, target, false, true, false), L"no_following_target_switch_in")) { return false; }
    altered = o;
    altered.source.end = {};
    if (!IsSpan(altered.Assess(h, source, true, true, false), L"no_following_cpu_switch")) { return false; }
    auto conflicting = i;
    conflicting.events.back().logger = 1;
    conflicting.Sort();
    if (o.Bracket(conflicting, 73, true, false).pairedPid) { return false; }
    ReadySequence legacy, current;
    legacy.Append(o.ready);
    current.Append(o.ready, true);
    if (!legacy.unknownFlags || legacy.dispatchable || current.unknownFlags || current.dispatchable != 1) { return false; }
    auto reserved = o.ready;
    reserved.reserved = 1;
    current.Append(reserved, true);
    return current.unknownFlags && IsSpan(o.Assess(h, target, false, true, true), L"coverage_unqualified") &&
        IsSpan(o.Assess(h, source, true, false, false), L"clock_unqualified");
}

static bool CheckSharedReadySwitches()
{
    using namespace etl_profile;
    const std::vector<uint32_t> selected{3, 4, 5};
    std::array<uint8_t, 8> body{};
    ReadyBatch batch;
    batch.Prepare(selected.size());
    const auto event = [&](uint32_t ordinal) {
        body[0] = ordinal == 4 ? 17 : 42;
        return SchedulerRecord(body.data(), 8, 50, 2, 100 * ordinal);
    };
    for (const auto n : selected) { batch.Select(event(n), n, selected); }
    const auto first = SwitchAt(6, 600, 1, 73, 42), second = SwitchAt(7, 700, 0, 22, 17);
    batch.SelectSwitch(first);
    batch.SelectSwitch(second);
    ScheduleHistory history;
    batch.PrepareReplay(history, 2);
    history.Observe(SwitchAt(1, 100, 1, 99, 73), nullptr);
    size_t count = 0;
    bool mismatch = false;
    for (const auto n : selected)
    {
        const auto ready = event(n);
        batch.ReplaySelection(ready, n, selected, history, count, mismatch);
        history.OtherThreadEvent(ready, n);
    }
    batch.ReplaySwitch(history, first, count, mismatch);
    batch.ReplaySwitch(history, second, count, mismatch);
    for (const auto& origin : batch.rows)
    {
        if (origin.source.end.record != 6 || origin.source.witnesses.previousCpu.tid != 73 ||
            origin.target.end.record != (origin.ready.tid == 17 ? 7u : 6u)) { return false; }
    }
    return !mismatch && count == 9 && count == batch.expectedRows && batch.cpu.entries.empty() && batch.target.entries.empty();
}

static bool CheckActivitySchedule()
{
    using namespace etl_profile;
    ThreadEvent first{1, 12, 42, 80, 1}, last{16, 12, 42, 500, 2};
    first.logger = last.logger = 7;
    ActivityWindow w;
    w.start.tid = 42; w.start.logger = 7; w.start.tick = 110; w.stop.tick = 350;
    w.thread.before = &first; w.thread.after = &last; w.thread.pairedPid = true;
    ScheduleHistory history;
    history.Prepare(2, 42);
    ActivitySchedule schedule;
    schedule.Prepare(w.start.tick, 1);
    const auto feed = [&](const SwitchEvent& event) { schedule.Observe(history, event, w, 1, 1); };
    const auto hasIssue = [&](const ScheduleHistory& source, const wchar_t* expected) {
        const auto issue = schedule.Issue(w, source, false);
        return issue && std::wstring(issue) == expected;
    };
    feed(SwitchAt(2, 100, 0, 11, 42));
    feed(SwitchAt(3, 180, 0, 42, 11));
    std::array<uint8_t, 8> payload{42, 0, 0, 0, 0, 0, 0, 0};
    auto ready = SchedulerRecord(payload.data(), 8, 50, 2, 220);
    history.OtherThreadEvent(ready, 5);
    feed(SwitchAt(6, 300, 1, 25, 42));
    if (!hasIssue(history, L"incomplete_switch_coverage")) { return false; }
    feed(SwitchAt(8, 410, 1, 42, 25));
    const auto split = schedule.Readiness(history);
    if (schedule.Issue(w, history, false) || schedule.page.size() != 1 || schedule.page[0].running ||
        schedule.count != 3 || schedule.running != 120 || schedule.offCpu != 120 ||
        schedule.offIntervals != 1 || split.intervals != 1 || split.before != 40 ||
        split.waitingBefore != 40 || split.after != 80) { return false; }
    const auto original = history;
    history.OtherThreadEvent(SchedulerRecord(payload.data(), 8, 50, 9, 440), 9);
    if (schedule.Issue(w, history, false) || history.unsupportedReady != 1 || schedule.Readiness(history).intervals) { return false; }
    history = original;
    std::fill_n(payload.begin(), 4, uint8_t{0xff});
    history.OtherThreadEvent(SchedulerRecord(payload.data(), 8, 50, 2, 440), 9);
    const auto unresolved = schedule.Readiness(history);
    if (schedule.Issue(w, history, false) || history.unassignedReady != 1 ||
        unresolved.intervals || unresolved.before || unresolved.after || unresolved.waitingBefore) { return false; }
    history = original;
    history.Observe(SwitchAt(10, 450, 1, 899, 12), nullptr);
    if (!hasIssue(history, L"cpu_history_conflict")) { return false; }
    history = original;
    history.ObserveClock(1);
    if (!hasIssue(history, L"clock_unqualified")) { return false; }
    w.intervening = 1;
    return hasIssue(original, L"intervening_activity_boundary");
}

static bool CheckFaultSchedule()
{
    using namespace etl_profile;
    HardFault fault{};
    fault.faultingTid = 42; fault.loggerId = 7; fault.record = 7;
    fault.initialTime = 110; fault.timestamp = 350;
    ThreadIndex index;
    index.events = {{1, 12, 42, 80, 1}, {10, 12, 42, 500, 2}, {12, 88, 42, 510, 1}, {15, 88, 42, 600, 2}};
    for (auto& boundary : index.events) { boundary.logger = 7; }
    index.decoded = 4;
    index.Sort();
    const auto pair = FaultThreadPair(index, fault, true, false);
    if (!pair.pairedPid || pair.before->pid != 12 || pair.after->record != 10) { return false; }
    ScheduleHistory history;
    history.Prepare(2, fault.faultingTid);
    FaultSchedule schedule;
    schedule.Prepare(true);
    schedule.Observe(history, SwitchAt(2, 100, 0, 11, 42), fault);
    schedule.Observe(history, SwitchAt(3, 180, 0, 42, 11), fault);
    std::array<uint8_t, 8> payload{42, 0, 0, 0, 0, 0, 0, 0};
    auto ready = SchedulerRecord(payload.data(), 8, 50, 2, 220);
    history.OtherThreadEvent(ready, 5);
    schedule.Observe(history, SwitchAt(6, 300, 1, 25, 42), fault);
    history.ObserveClock(fault.timestamp);
    schedule.Observe(history, SwitchAt(8, 410, 1, 42, 25), fault);
    const auto whole = schedule.Summarize(history, fault, pair, false);
    if (!whole.measured || whole.running != 120 || whole.offCpu != 120 || schedule.slices.size() != 3 ||
        schedule.slices[1].witnesses.ready.last.at.record != 5) { return false; }
    auto shorter = schedule.slices[1];
    if (shorter.ReadyPivot() != 220) { return false; }
    shorter.endTick = 210;
    if (shorter.ReadyPivot() != 210) { return false; }
    shorter.beginTick = 225; shorter.endTick = 230;
    if (shorter.ReadyPivot() != 225) { return false; }
    auto check = [&](const wchar_t* why, const HardFault& query, bool gap = false)
    {
        const auto bracket = FaultThreadPair(index, query, schedule.qpc, gap);
        const auto p = schedule.Summarize(history, query, bracket, gap);
        return !p.measured && !p.running && !p.offCpu && std::wstring_view(p.status) == why;
    };
    auto reused = fault;
    reused.record = 14; reused.timestamp = 550;
    if (std::wstring_view(FaultThreadPair(index, reused, true, false).relation) != L"start_outside_bracket" ||
        !check(L"thread_bracket_unqualified", reused) || !check(L"coverage_unqualified", fault, true)) { return false; }
    ++index.decoded;
    if (!check(L"thread_bracket_unqualified", fault)) { return false; }
    --index.decoded;
    index.events[0].tick = 105; // Fault starts in the bracket, but its first switch does not.
    if (!check(L"switch_outside_bracket", fault)) { return false; }
    index.events[0].tick = 80;
    index.events[0].mixedLoggers = true;
    if (!check(L"thread_bracket_unqualified", fault)) { return false; }
    index.events[0].mixedLoggers = false;
    ++schedule.unsupportedSwitches;
    if (!check(L"coverage_unqualified", fault)) { return false; }
    --schedule.unsupportedSwitches;
    auto original = history;
    history.unknownSwitchTid = true;
    if (!check(L"coverage_unqualified", fault)) { return false; }
    history = original;
    ++history.unsupportedBoundaries;
    if (!check(L"coverage_unqualified", fault)) { return false; }
    history = original;
    ++history.logger;
    if (!check(L"scheduler_scope_unqualified", fault)) { return false; }
    history = original;
    history.ObserveClock(1);
    if (!check(L"clock_unqualified", fault)) { return false; }
    history = original;
    history.Observe(SwitchAt(9, 430, 1, 899, 12), nullptr);
    if (!check(L"cpu_history_conflict", fault)) { return false; }
    history = original;
    reused = fault; reused.timestamp = reused.initialTime;
    if (!check(L"zero_duration", reused)) { return false; }
    --reused.timestamp;
    if (!check(L"invalid_fault_interval", reused)) { return false; }
    reused = fault; reused.faultingTid = UINT32_MAX;
    if (!check(L"unusable_tid", reused)) { return false; }
    schedule.qpc = false;
    if (!check(L"clock_unqualified", fault)) { return false; }
    schedule.qpc = true;
    schedule.slices.pop_back(); --schedule.candidates;
    if (!check(L"incomplete_switch_coverage", fault)) { return false; }

    // Feed the real retention path one more positive intersection than fits.
    fault.initialTime = 100; fault.timestamp = 100 + MaxPageRows + 1; fault.record = 300;
    index.events = {{1, 12, 42, 90, 1}, {500, 12, 42, 510, 2}};
    index.events[0].logger = index.events[1].logger = 7; index.decoded = 2; index.Sort();
    schedule = {}; schedule.Prepare(true);
    history = {}; history.Prepare(1, fault.faultingTid);
    for (uint32_t i = 0; i <= MaxPageRows + 1; ++i)
    { schedule.Observe(history, SwitchAt(i + 2, 100 + i, 0, i % 2 ? 42 : 11, i % 2 ? 11 : 42), fault); }
    return schedule.slices.size() == MaxPageRows && schedule.candidates == MaxPageRows + 1 && check(L"interval_limit", fault);
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--etl-record-check")
    {
        return CheckProfileRecord() && CheckThreadEvidence() && CheckImageLayout() && CheckImageEvidence() &&
            CheckSwitchRecord() && etl_disk_test::Check() && CheckHardFaultRecord() && CheckReadyLayout() && CheckSchedulingIntervals() && CheckSchedulerScopes() && CheckReadyOrigin() && CheckSharedReadySwitches() && CheckActivitySchedule() && CheckFaultSchedule() && etl_activity_test::Check() &&
            etl_settings_test::Layout(4) && etl_settings_test::Layout(8) && etl_settings_test::Brackets() && etl_settings_test::Budgets() &&
            etl_build_test::CheckDecoder(4) && etl_build_test::CheckDecoder(8) && etl_build_test::CheckJoin() && etl_build_test::CheckBudget() &&
            etl_clr_test::Check() && etl_process_test::Check() && etl_reference_test::Check() && etl_reference_test::CheckOwnedFile(argv[0]) ? 0 : 1;
    }
    if (argc == 2 && std::wstring(argv[1]) == L"--cancel-check")
    {
        std::atomic<bool> stop{true};
        ExecutionTrace trace;
        trace.SourceId = L"stale";
        std::wstring error;
        if (ParseExecutionTrace(L"{}", &trace, &error, &stop) || !trace.SourceId.empty() ||
            error.find(L"cancelled") == std::wstring::npos)
        {
            return 1;
        }
        return 0;
    }
    if (argc < 4 || std::wstring(argv[1]) != L"--offline" || std::wstring(argv[2]) != L"!kmon" ||
        std::wstring(argv[3]) != L"trace")
    {
        return 2;
    }
    return RunExecutionTraceCommand(std::vector<std::wstring>(argv + 4, argv + argc));
}
