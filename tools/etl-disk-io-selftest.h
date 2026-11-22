#pragma once
#include "../user/EtlDiskIo.h"
#include <vector>

namespace etl_disk_test
{
    template<class T>
    void Append(std::vector<uint8_t>& data, T value)
    {
        const auto bytes = reinterpret_cast<const uint8_t*>(&value);
        data.insert(data.end(), bytes, bytes + sizeof(value));
    }

    inline bool Layout(unsigned width, uint8_t version, uint8_t opcode)
    {
        using namespace etl_profile;
        EVENT_RECORD e{};
        auto& h = e.EventHeader;
        h.ProviderId = DiskIoProvider;
        h.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        h.EventDescriptor.Version = version;
        h.EventDescriptor.Opcode = opcode;
        h.TimeStamp.QuadPart = 0x1234567812345678;
        e.BufferContext.LoggerId = 7;
        std::vector<uint8_t> bytes{0xcc}; // Begin the ETW payload on an unaligned address.
        const bool transfer = opcode == 10 || opcode == 11;
        const bool completion = transfer || opcode == 14;
        if (completion)
        {
            Append(bytes, uint32_t{19});                      // DiskNumber
            Append(bytes, uint32_t{0xf0f0u});                // IrpFlags
        }
        if (transfer)
        {
            Append(bytes, UINT32_MAX);                        // TransferSize
            Append(bytes, uint32_t{99});                      // Reserved
            Append(bytes, uint64_t{0x1020304050607080});       // ByteOffset
            bytes.insert(bytes.end(), width * 2, 0xa5);        // FileObject, Irp
        }
        if (completion) { Append(bytes, UINT64_MAX - 2); }    // HighResResponseTime
        if (!transfer) { bytes.insert(bytes.end(), width, 0x5a); } // Irp
        if (version == 3) { Append(bytes, uint32_t{0x12345}); }
        e.UserData = bytes.data() + 1;
        e.UserDataLength = static_cast<USHORT>(bytes.size() - 1);
        DiskEvent row{};
        if (DecodeDisk(e, row) != Match::Decoded || row.width != width || row.version != version || row.opcode != opcode ||
            row.loggerId != 7 || row.timestamp != h.TimeStamp.QuadPart || row.IsCompletion() != completion ||
            row.transferBytes != (transfer ? UINT32_MAX : 0u) || row.diskNumber != (completion ? 19u : 0u) ||
            row.responseTicks != (completion ? UINT64_MAX - 2 : 0u) || row.issuingTid != (version == 3 ? 0x12345u : 0u))
        { return false; }
        for (USHORT n = 0; n <= e.UserDataLength + 1; ++n)
        {
            if (n == e.UserDataLength) { continue; }
            auto bad = e;
            bad.UserDataLength = n;
            if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        }
        for (const auto flags : {0, EVENT_HEADER_FLAG_STRING_ONLY, EVENT_HEADER_FLAG_TRACE_MESSAGE,
                                 EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER})
        {
            auto bad = e;
            bad.EventHeader.Flags = static_cast<USHORT>(flags ? h.Flags | flags : 0);
            if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        }
        auto bad = e;
        bad.ExtendedDataCount = 1;
        if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        bad = e; bad.UserData = nullptr;
        if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        bad = e; bad.EventHeader.EventDescriptor.Version = 1;
        if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        bad = e; bad.EventHeader.EventDescriptor.Id = 1;
        if (DecodeDisk(bad, row) != Match::Unsupported) { return false; }
        bad = e; bad.EventHeader.ProviderId = ThreadProvider;
        if (DecodeDisk(bad, row) != Match::Other) { return false; }
        bad = e; bad.EventHeader.EventDescriptor.Opcode = 34;
        return DecodeDisk(bad, row) == Match::Other;
    }

    inline bool Check()
    {
        for (const auto width : {4u, 8u})
        {
            for (uint8_t version = 2; version <= 3; ++version)
            {
                for (uint8_t opcode = 10; opcode <= 15; ++opcode)
                {
                    if (!Layout(width, version, opcode)) { return false; }
                }
            }
        }
        etl_profile::DiskTotals totals;
        etl_profile::DiskEvent e{};
        e.opcode = 12; totals.Observe(e);
        e.opcode = 10; e.transferBytes = UINT32_MAX; e.record = 2; totals.Observe(e);
        if (totals.longestTies != 1 || totals.longest.record != 2) { return false; }
        e.responseTicks = UINT64_MAX; e.record = 3; totals.Observe(e);
        e.record = 4; totals.Observe(e);
        return totals.starts == 1 && totals.completions == 3 && totals.transferBytes == 3ull * UINT32_MAX &&
            totals.longestTies == 2 && totals.longest.record == 3 && totals.longest.responseTicks == UINT64_MAX;
    }
}
