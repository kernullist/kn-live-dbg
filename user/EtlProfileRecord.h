#pragma once

#include <Windows.h>
#include <evntcons.h>
#include <cstdint>
#include <cstring>

namespace etl_profile
{
    inline constexpr GUID PerfInfo = {0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};

    struct Sample
    {
        uint32_t ordinal, record, tid, headerTid, headerPid, cpu;
        uint16_t flags, count, reserved, extendedItems, stackItems, loggerId;
        uint8_t width, channel, level;
        uint16_t task;
        uint64_t ip, keyword;
        int64_t timestamp;
    };

    enum class Match { Other, Unsupported, Decoded };

    // Windows supplies the EVENT_RECORD envelope. Only PerfInfo_V2 /
    // SampledProfile has the layout below. The consumer's bitness is irrelevant.
    inline Match Decode(const EVENT_RECORD& event, Sample* output)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, PerfInfo) || d.Opcode != 46) { return Match::Other; }
        const auto bits = h.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
        const uint8_t width = bits == EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : bits == EVENT_HEADER_FLAG_64_BIT_HEADER ? 8 : 0;
        if (d.Id != 0 || d.Version != 2 || !(h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) ||
            (h.Flags & (EVENT_HEADER_FLAG_STRING_ONLY | EVENT_HEADER_FLAG_TRACE_MESSAGE)) ||
            !width || event.UserDataLength != width + 8 || !event.UserData ||
            (event.ExtendedDataCount && !event.ExtendedData)) { return Match::Unsupported; }
        if (!output) { return Match::Decoded; }
        auto& row = *output;
        row = {};
        row.width = width;
        const auto payload = static_cast<const uint8_t*>(event.UserData);
        std::memcpy(&row.ip, payload, width);
        std::memcpy(&row.tid, payload + width, sizeof(row.tid));
        std::memcpy(&row.count, payload + width + 4, sizeof(row.count));
        std::memcpy(&row.reserved, payload + width + 6, sizeof(row.reserved));
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
        row.loggerId = event.BufferContext.LoggerId;
        for (USHORT i = 0; i < event.ExtendedDataCount; ++i)
        {
            const auto type = event.ExtendedData[i].ExtType;
            if (type == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 || type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
            { ++row.stackItems; }
        }
        return Match::Decoded;
    }
}
