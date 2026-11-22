#pragma once

#include "EtlProfileRecord.h"
#include <optional>

namespace etl_profile
{
    inline constexpr GUID PageFaultProvider = {0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

    struct HardFault : RecordEnvelope
    {
        int64_t initialTime;
        uint64_t readOffset;
        uint32_t faultingTid, byteCount;

        std::optional<uint64_t> OrderedTicks() const
        {
            if (initialTime <= 0 || timestamp < initialTime) { return std::nullopt; }
            return static_cast<uint64_t>(timestamp - initialTime);
        }
    };

    inline Match DecodeHardFault(const EVENT_RECORD& event, HardFault* row)
    {
        const auto& h = event.EventHeader;
        if (!IsEqualGUID(h.ProviderId, PageFaultProvider) || h.EventDescriptor.Opcode != 32) { return Match::Other; }
        const auto width = ClassicPointerWidth(h, 2);
        if (!width || !event.UserData || event.UserDataLength != 24 + 2 * width ||
            (event.ExtendedDataCount && !event.ExtendedData)) { return Match::Unsupported; }
        if (!row) { return Match::Decoded; }
        *row = {};
        const auto* bytes = static_cast<const uint8_t*>(event.UserData);
        std::memcpy(&row->initialTime, bytes, 8);
        std::memcpy(&row->readOffset, bytes + 8, 8);
        // Faulting VA and FileObject precede the payload TID. Neither is a lifetime key.
        std::memcpy(&row->faultingTid, bytes + 16 + 2 * width, 4);
        std::memcpy(&row->byteCount, bytes + 20 + 2 * width, 4);
        ReadEnvelope(event, width, *row);
        return Match::Decoded;
    }

    struct HardFaultTotals
    {
        uint64_t bytes = 0, longestTicks = 0;
        uint32_t ordered = 0, longestTies = 0;
        HardFault longest{};

        void Observe(const HardFault& row)
        {
            bytes += row.byteCount; // MaxEventRecords bounds the sum of 32-bit byte counts.
            const auto ticks = row.OrderedTicks();
            if (!ticks) { return; }
            ++ordered;
            if (!longestTies || *ticks > longestTicks)
            {
                longest = row;
                longestTicks = *ticks;
                longestTies = 1;
            }
            else if (*ticks == longestTicks) { ++longestTies; }
        }
    };
}
