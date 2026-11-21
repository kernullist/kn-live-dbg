#include "../user/ExecutionTrace.h"
#include "../user/EtlProfileRecord.h"

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

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--etl-record-check")
    {
        return CheckProfileRecord() ? 0 : 1;
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
