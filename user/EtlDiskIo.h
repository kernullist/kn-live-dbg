#pragma once

#include "EtlProfileRecord.h"
#include <cstddef>

namespace etl_profile
{
    inline constexpr GUID DiskIoProvider = {0x3d6fa8d4, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

    struct DiskEvent : RecordEnvelope
    {
        uint8_t opcode, version;
        uint32_t diskNumber, transferBytes, issuingTid;
        uint64_t responseTicks;

        bool IsTransfer() const { return opcode == 10 || opcode == 11; }
        bool IsCompletion() const { return IsTransfer() || opcode == 14; }
        size_t Operation() const
        {
            if (opcode == 10 || opcode == 12) { return 0; }
            if (opcode == 11 || opcode == 13) { return 1; }
            return 2;
        }
    };

    inline constexpr const wchar_t* DiskOperations[] = {L"read", L"write", L"flush"};

    // Classic DiskIo v2 and v3 use the event's pointer width on the wire.
    // Only the numeric performance fields are retained. IRP and file object
    // addresses do not establish request generations.
    inline Match DecodeDisk(const EVENT_RECORD& event, DiskEvent& out)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, DiskIoProvider) || d.Opcode < 10 || d.Opcode > 15) { return Match::Other; }
        const auto width = ClassicPointerWidth(h, d.Version);
        if ((d.Version != 2 && d.Version != 3) || !width || !event.UserData || (event.ExtendedDataCount && !event.ExtendedData))
        { return Match::Unsupported; }
        // The v3 issuing TID follows the entire v2 payload for each opcode.
        const size_t base = d.Opcode <= 11 ? 32 + 2 * width : d.Opcode == 14 ? 16 + width : width;
        if (event.UserDataLength != base + (d.Version == 3 ? 4 : 0)) { return Match::Unsupported; }
        out = {};
        out.opcode = d.Opcode;
        out.version = d.Version;
        const auto bytes = static_cast<const uint8_t*>(event.UserData);
        if (out.IsCompletion())
        {
            std::memcpy(&out.diskNumber, bytes, sizeof(out.diskNumber));
            const size_t responseOffset = out.IsTransfer() ? 24 + 2 * width : 8;
            std::memcpy(&out.responseTicks, bytes + responseOffset, sizeof(out.responseTicks));
            if (out.IsTransfer()) { std::memcpy(&out.transferBytes, bytes + 8, sizeof(out.transferBytes)); }
        }
        if (d.Version == 3) { std::memcpy(&out.issuingTid, bytes + base, sizeof(out.issuingTid)); }
        ReadEnvelope(event, width, out);
        return Match::Decoded;
    }

    struct DiskTotals
    {
        uint32_t starts = 0, completions = 0, longestTies = 0;
        uint64_t transferBytes = 0;
        DiskEvent longest{};

        void Observe(const DiskEvent& e)
        {
            if (!e.IsCompletion()) { ++starts; return; }
            ++completions;
            transferBytes += e.transferBytes; // At most MaxEventRecords unsigned 32-bit transfers.
            if (!longestTies || e.responseTicks > longest.responseTicks)
            {
                longest = e;
                longestTies = 1;
            }
            else if (e.responseTicks == longest.responseTicks) { ++longestTies; }
        }
    };
}
