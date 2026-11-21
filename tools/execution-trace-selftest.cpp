#include "../user/ExecutionTrace.h"
#include "../user/EtlThreadEvidence.h"

#include <array>

#include <iostream>

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
    std::array<uint8_t, 73> bytes{};
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
        }
    }
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

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--etl-record-check")
    {
        return CheckProfileRecord() && CheckThreadEvidence() ? 0 : 1;
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
