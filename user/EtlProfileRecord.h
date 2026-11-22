#pragma once

#include <Windows.h>
#include <evntcons.h>
#include <cstdint>
#include <cstring>

namespace etl_profile
{
    inline constexpr GUID PerfInfo = {0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};
    inline constexpr GUID ThreadProvider = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

    inline constexpr uint64_t MaxFileBytes = 512ull << 20;
    inline constexpr uint32_t MaxEventRecords = 2'000'000;
    inline constexpr uint32_t MaxPageRows = 128;

    enum class BufferAccounting { Unavailable, Matched, Fewer, More };

    inline BufferAccounting AccountBuffers(uint32_t mode, uint32_t written, uint64_t processed)
    {
        // Circular and rotating logs do not describe a single sequential buffer range.
        if (!written || !(mode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) ||
            (mode & (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_FILE_MODE_NEWFILE))) { return BufferAccounting::Unavailable; }
        if (processed < written) { return BufferAccounting::Fewer; }
        if (processed > written) { return BufferAccounting::More; }
        return BufferAccounting::Matched;
    }

    inline bool RequiresPartialPage(uint32_t mode, BufferAccounting accounting)
    {
        return (mode & EVENT_TRACE_FILE_MODE_NEWFILE) ||
            accounting == BufferAccounting::Fewer || accounting == BufferAccounting::More;
    }

    inline const wchar_t* BufferComparisonName(BufferAccounting value)
    {
        switch (value)
        {
        case BufferAccounting::Matched: return L"matched";
        case BufferAccounting::Fewer: return L"fewer_than_declared";
        case BufferAccounting::More: return L"more_than_declared";
        default: return L"not_comparable";
        }
    }

    struct RecordEnvelope
    {
        uint32_t ordinal, record, headerTid, headerPid, cpu;
        uint16_t flags, extendedItems, stackItems, loggerId, task;
        uint8_t width, channel, level;
        uint64_t keyword;
        int64_t timestamp;
    };

    struct Sample : RecordEnvelope
    {
        uint32_t tid;
        uint16_t count, reserved;
        uint64_t ip;
    };

    enum class Match { Other, Unsupported, Decoded };

    // ETW payloads may be unaligned. Require exactly one complete UTF-16LE string.
    inline bool TerminatedUtf16(const uint8_t* bytes, size_t size)
    {
        if (!bytes || !size || size % 2) { return false; }
        bool needLow = false;
        for (size_t offset = 0; offset < size; offset += 2)
        {
            const unsigned unit = bytes[offset] | (static_cast<unsigned>(bytes[offset + 1]) << 8);
            if (unit == 0) { return !needLow && offset + 2 == size; }
            if (needLow)
            {
                if (unit < 0xdc00 || unit > 0xdfff) { return false; }
                needLow = false;
            }
            else if (unit >= 0xd800 && unit <= 0xdbff) { needLow = true; }
            else if (unit >= 0xdc00 && unit <= 0xdfff) { return false; }
        }
        return false;
    }

    inline uint8_t ClassicPointerWidth(const EVENT_HEADER& header, uint8_t version)
    {
        if (header.EventDescriptor.Id != 0 || header.EventDescriptor.Version != version ||
            !(header.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) ||
            (header.Flags & (EVENT_HEADER_FLAG_STRING_ONLY | EVENT_HEADER_FLAG_TRACE_MESSAGE))) { return 0; }
        switch (header.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER))
        {
        case EVENT_HEADER_FLAG_32_BIT_HEADER: return 4;
        case EVENT_HEADER_FLAG_64_BIT_HEADER: return 8;
        default: return 0;
        }
    }

    inline void ReadEnvelope(const EVENT_RECORD& event, uint8_t width, RecordEnvelope& row)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        row.width = width;
        row.timestamp = h.TimeStamp.QuadPart;
        row.cpu = GetEventProcessorIndex(&event);
        row.headerTid = h.ThreadId;
        row.headerPid = h.ProcessId;
        row.flags = h.Flags;
        row.keyword = d.Keyword;
        row.level = d.Level;
        row.channel = d.Channel;
        row.task = d.Task;
        row.extendedItems = event.ExtendedDataCount;
        row.stackItems = 0;
        row.loggerId = event.BufferContext.LoggerId;
        for (USHORT i = 0; i < event.ExtendedDataCount; ++i)
        {
            const auto type = event.ExtendedData[i].ExtType;
            if (type == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 || type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
            { ++row.stackItems; }
        }
    }

    // Windows supplies the EVENT_RECORD envelope. Only PerfInfo_V2 /
    // SampledProfile has the layout below. The consumer's bitness is irrelevant.
    inline Match Decode(const EVENT_RECORD& event, Sample* output)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, PerfInfo) || d.Opcode != 46) { return Match::Other; }
        const auto width = ClassicPointerWidth(h, 2);
        if (!width || event.UserDataLength != width + 8 || !event.UserData ||
            (event.ExtendedDataCount && !event.ExtendedData)) { return Match::Unsupported; }
        if (!output) { return Match::Decoded; }
        auto& row = *output;
        row = {};
        const auto payload = static_cast<const uint8_t*>(event.UserData);
        std::memcpy(&row.ip, payload, width);
        std::memcpy(&row.tid, payload + width, sizeof(row.tid));
        std::memcpy(&row.count, payload + width + 4, sizeof(row.count));
        std::memcpy(&row.reserved, payload + width + 6, sizeof(row.reserved));
        ReadEnvelope(event, width, row);
        return Match::Decoded;
    }
}
