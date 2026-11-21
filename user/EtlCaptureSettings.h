#pragma once

#include "EtlProfileRecord.h"
#include <algorithm>
#include <array>
#include <string_view>
#include <vector>

namespace etl_profile
{
    inline constexpr GUID EventTraceProvider = {0x68fdd900, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};
    inline constexpr GUID LostProvider = {0x6a399ae0, 0x4bc6, 0x4de9, {0x87, 0x0b, 0x36, 0x57, 0xf8, 0x94, 0x7e, 0x7e}};
    inline constexpr size_t MaxSettingRecords = 1024;
    inline constexpr size_t MaxSettingNameUnits = 65536;

    inline bool LossMarker(const EVENT_HEADER& h)
    {
        return IsEqualGUID(h.ProviderId, LostProvider) && (h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) &&
            h.EventDescriptor.Opcode >= 32 && h.EventDescriptor.Opcode <= 34;
    }

    enum class SettingKind { GroupMask, ProfileInterval, Loss };

    struct SettingRecord
    {
        SettingKind kind{};
        uint32_t record = 0, cpu = 0, kernelVersion = 0;
        uint32_t source = 0, newInterval = 0, oldInterval = 0, nameOffset = 0;
        int64_t tick = 0;
        uint64_t keyword = 0;
        std::array<uint32_t, 8> masks{};
        uint16_t logger = 0, flags = 0, eventId = 0, payloadBytes = 0, nameUnits = 0, task = 0;
        uint8_t version = 0, opcode = 0, width = 0, level = 0, channel = 0;
        bool supported = true;
    };

    inline Match DecodeSetting(const EVENT_RECORD& e, uint32_t ordinal, SettingRecord& out)
    {
        const auto& h = e.EventHeader;
        const auto& d = h.EventDescriptor;
        out = {};
        if (IsEqualGUID(h.ProviderId, EventTraceProvider) && (d.Opcode == 5 || d.Opcode == 32))
        { out.kind = SettingKind::GroupMask; }
        else if (IsEqualGUID(h.ProviderId, PerfInfo) && d.Opcode >= 72 && d.Opcode <= 74)
        { out.kind = SettingKind::ProfileInterval; }
        else if (LossMarker(h)) { out.kind = SettingKind::Loss; }
        else { return Match::Other; }

        out.record = ordinal;
        out.tick = h.TimeStamp.QuadPart;
        out.cpu = GetEventProcessorIndex(&e);
        out.logger = e.BufferContext.LoggerId;
        out.flags = h.Flags;
        out.eventId = d.Id;
        out.keyword = d.Keyword;
        out.task = d.Task;
        out.level = d.Level;
        out.channel = d.Channel;
        out.version = d.Version;
        out.opcode = d.Opcode;
        out.width = ClassicPointerWidth(h, d.Version);
        out.payloadBytes = e.UserDataLength;
        // A loss indication is the original envelope. Its position does not
        // specify when loss started, how many samples were lost or their kind.
        if (out.kind == SettingKind::Loss) { return Match::Decoded; }
        const auto* bytes = static_cast<const uint8_t*>(e.UserData);
        if (!out.width || !bytes) { return Match::Unsupported; }
        if (out.kind == SettingKind::GroupMask)
        {
            if (d.Version > 2 || out.payloadBytes != (d.Version == 2 ? 36 : 32)) { return Match::Unsupported; }
            std::memcpy(out.masks.data(), bytes, sizeof(out.masks));
            if (d.Version == 2) { std::memcpy(&out.kernelVersion, bytes + 32, 4); }
        }
        else
        {
            if (d.Version == 2)
            {
                if (out.payloadBytes != 12) { return Match::Unsupported; }
            }
            else if (d.Version == 3 && out.payloadBytes >= 14 &&
                TerminatedUtf16(bytes + 12, out.payloadBytes - 12))
            { out.nameUnits = static_cast<uint16_t>((out.payloadBytes - 14) / 2); }
            else { return Match::Unsupported; }
            std::memcpy(&out.source, bytes, 4);
            std::memcpy(&out.newInterval, bytes + 4, 4);
            std::memcpy(&out.oldInterval, bytes + 8, 4);
        }
        return Match::Decoded;
    }

    struct SettingBracket
    {
        const SettingRecord* before = nullptr;
        const SettingRecord* after = nullptr;
        const SettingRecord* start = nullptr;
        const SettingRecord* end = nullptr;
        const wchar_t* relation = L"no_records";
        uint32_t period = 0;
    };

    struct CaptureSettings
    {
        std::vector<SettingRecord> records;
        std::vector<wchar_t> names;
        uint32_t maskCount = 0, intervalCount = 0, lossCount = 0, unsupportedMasks = 0, unsupportedIntervals = 0;
        const wchar_t* retention = L"complete";

        void Prepare() { records.reserve(MaxSettingRecords); names.reserve(MaxSettingNameUnits); }
        bool Complete() const { return records.size() == maskCount + intervalCount + lossCount; }
        std::wstring_view Name(const SettingRecord& e) const
        {
            return e.nameUnits ? std::wstring_view(names.data() + e.nameOffset, e.nameUnits) : std::wstring_view{};
        }

        void Observe(const EVENT_RECORD& e, uint32_t ordinal)
        {
            SettingRecord point;
            const auto match = DecodeSetting(e, ordinal, point);
            if (match == Match::Other) { return; }
            point.supported = match == Match::Decoded;
            if (!point.supported)
            {
                if (point.kind == SettingKind::GroupMask) { ++unsupportedMasks; }
                else { ++unsupportedIntervals; }
            }
            const bool retaining = Complete();
            if (point.kind == SettingKind::GroupMask) { ++maskCount; }
            else if (point.kind == SettingKind::ProfileInterval) { ++intervalCount; }
            else { ++lossCount; }
            if (!retaining) { return; }
            if (records.size() == MaxSettingRecords) { retention = L"record_limit"; return; }
            if (point.nameUnits > MaxSettingNameUnits - names.size()) { retention = L"name_limit"; return; }
            if (point.nameUnits)
            {
                point.nameOffset = static_cast<uint32_t>(names.size());
                names.resize(names.size() + point.nameUnits);
                std::memcpy(names.data() + point.nameOffset, static_cast<const uint8_t*>(e.UserData) + 12, 2u * point.nameUnits);
            }
            records.push_back(point);
        }

        SettingBracket At(const RecordEnvelope& row, SettingKind kind, bool clock, bool gap) const
        {
            SettingBracket result;
            const bool timer = kind == SettingKind::ProfileInterval;
            const auto opening = timer ? 73 : 5, closing = timer ? 74 : 32;
            const SettingRecord* open = nullptr;
            const SettingRecord* previous = nullptr;
            uint8_t lastBoundary = 0;
            bool clockConflict = !clock, ambiguous = false;
            for (const auto& p : records)
            {
                if (!p.supported || p.kind != kind || p.logger != row.loggerId || (timer && p.source != 0)) { continue; }
                if (previous && previous->tick >= p.tick) { clockConflict = true; }
                previous = &p;
                if (p.record < row.record) { result.before = &p; clockConflict |= p.tick >= row.timestamp; }
                else if (!result.after) { result.after = &p; clockConflict |= p.tick <= row.timestamp; }
                if (p.opcode != opening && p.opcode != closing) { continue; }
                ambiguous |= p.opcode == lastBoundary;
                lastBoundary = p.opcode;
                if (p.opcode == opening) { open = &p; }
                else
                {
                    if (open && open->record < row.record && row.record < p.record) { result.start = open; result.end = &p; }
                    open = nullptr;
                }
            }
            if (ambiguous) { result.start = result.end = nullptr; }
            const auto* left = result.before;
            const auto* right = result.after;
            if (!Complete()) { result.relation = L"index_limit"; }
            else if (gap || lossCount || (timer ? unsupportedIntervals : unsupportedMasks)) { result.relation = L"coverage_unqualified"; }
            else if (!left && !right) { result.relation = L"no_records"; }
            else if (clockConflict) { result.relation = L"clock_unqualified"; }
            else if (ambiguous) { result.relation = L"ambiguous_boundaries"; }
            else if (!left || !right) { result.relation = L"one_boundary"; }
            else if (!result.start) { result.relation = L"outside_recorded_collection"; }
            else if (left->width != row.width || right->width != row.width || result.start->width != row.width ||
                result.end->width != row.width || left->version != right->version || left->version != result.start->version ||
                left->version != result.end->version)
            { result.relation = L"setting_layout_conflict"; }
            else if (!timer)
            {
                result.relation = left->masks == right->masks && left->kernelVersion == right->kernelVersion ?
                    L"equal_group_snapshots" : L"group_snapshots_differ";
            }
            else if (Name(*left) != Name(*right) || Name(*left) != Name(*result.start) || Name(*left) != Name(*result.end))
            { result.relation = L"profile_source_name_conflict"; }
            else if (!left->newInterval || left->newInterval != right->oldInterval ||
                result.start->oldInterval != result.start->newInterval || result.end->oldInterval != result.end->newInterval)
            { result.relation = L"interval_values_unresolved"; }
            else
            {
                result.relation = L"recorded_timer_interval";
                result.period = left->newInterval;
            }
            return result;
        }
    };
}
