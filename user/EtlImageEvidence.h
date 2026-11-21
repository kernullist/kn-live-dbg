#pragma once

#include "EtlProfileRecord.h"
#include <algorithm>
#include <array>
#include <string_view>
#include <utility>
#include <vector>

namespace etl_profile
{
    inline constexpr GUID ImageProvider = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
    static_assert(sizeof(wchar_t) == 2);
    inline constexpr size_t MaxImageEvents = 65536;
    inline constexpr size_t MaxImageNameUnits = 8 * 1024 * 1024;

    struct ImageEvent
    {
        uint64_t base = 0, size = 0, preferred = 0;
        int64_t tick = 0;
        uint32_t record = 0, pid = 0, checksum = 0, stamp = 0, nameOffset = 0;
        uint16_t nameUnits = 0, logger = 0;
        uint8_t version = 0, opcode = 0, width = 0, signatureLevel = 0, signatureType = 0;
    };

    inline bool ImageOpening(uint8_t opcode) { return opcode == 10 || opcode == 3; }

    inline Match DecodeImage(const EVENT_RECORD& event, uint32_t ordinal, ImageEvent& result, const uint8_t*& name)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, ImageProvider) || (d.Opcode != 10 && (d.Opcode < 2 || d.Opcode > 4)))
        { return Match::Other; }
        if (d.Version != 2 && d.Version != 3) { return Match::Unsupported; }
        const auto width = ClassicPointerWidth(h, d.Version);
        const size_t fixed = 3 * width + 32;
        const auto* bytes = static_cast<const uint8_t*>(event.UserData);
        if (!width || !bytes || event.UserDataLength < fixed ||
            !TerminatedUtf16(bytes + fixed, event.UserDataLength - fixed)) { return Match::Unsupported; }

        result = {};
        std::memcpy(&result.base, bytes, width);
        std::memcpy(&result.size, bytes + width, width);
        const uint64_t maximum = width == 4 ? UINT32_MAX : UINT64_MAX;
        if (!result.size || result.size - 1 > maximum - result.base) { return Match::Unsupported; }
        const auto* fields = bytes + 2 * width;
        std::memcpy(&result.pid, fields, 4);
        std::memcpy(&result.checksum, fields + 4, 4);
        std::memcpy(&result.stamp, fields + 8, 4);
        if (d.Version == 3)
        {
            result.signatureLevel = fields[12];
            result.signatureType = fields[13];
        }
        std::memcpy(&result.preferred, fields + 16, width);
        result.record = ordinal;
        result.tick = h.TimeStamp.QuadPart;
        result.logger = event.BufferContext.LoggerId;
        result.opcode = d.Opcode;
        result.version = d.Version;
        result.width = width;
        name = bytes + fixed;
        result.nameUnits = static_cast<uint16_t>((event.UserDataLength - fixed) / 2 - 1);
        return Match::Decoded;
    }

    struct ImageGroup
    {
        uint32_t pid;
        uint64_t base, last, prefixLast;
        size_t first, end;
        bool transitionConflict, clockConflict, mixedLoggers = false;
    };

    struct ImageWitness
    {
        const ImageEvent* before = nullptr;
        const ImageEvent* after = nullptr;
        const wchar_t* relation = nullptr;
        bool paired = false, mixedLoggers = false;
    };

    struct ImageMatch
    {
        const wchar_t* relation = L"no_recorded_range";
        std::array<ImageWitness, 2> witnesses{};
        size_t count = 0;
        uint64_t rva = 0;
        bool paired = false;
    };

    struct ImageIndex
    {
        std::vector<ImageEvent> events;
        std::vector<wchar_t> names;
        std::vector<ImageGroup> groups;
        uint32_t decoded = 0, unsupported = 0;
        const wchar_t* retention = L"complete";

        void Prepare()
        {
            events.reserve(MaxImageEvents);
            names.reserve(MaxImageNameUnits);
            groups.reserve(MaxImageEvents);
        }
        bool Complete() const { return decoded == events.size(); }

        void Observe(const EVENT_RECORD& event, uint32_t ordinal)
        {
            ImageEvent point;
            const uint8_t* name = nullptr;
            const auto match = DecodeImage(event, ordinal, point, name);
            if (match == Match::Unsupported) { ++unsupported; }
            if (match != Match::Decoded) { return; }
            const bool retaining = Complete();
            ++decoded;
            if (!retaining) { return; }
            if (events.size() == MaxImageEvents) { retention = L"event_limit"; return; }
            if (point.nameUnits > MaxImageNameUnits - names.size()) { retention = L"name_limit"; return; }
            point.nameOffset = static_cast<uint32_t>(names.size());
            if (point.nameUnits)
            {
                names.resize(names.size() + point.nameUnits);
                std::memcpy(names.data() + point.nameOffset, name, 2u * point.nameUnits);
            }
            events.push_back(point);
        }

        std::wstring_view Name(const ImageEvent& e) const
        {
            return e.nameUnits ? std::wstring_view(names.data() + e.nameOffset, e.nameUnits) : std::wstring_view{};
        }

        void Sort()
        {
            std::sort(events.begin(), events.end(), [](const ImageEvent& a, const ImageEvent& b) {
                if (a.pid != b.pid) { return a.pid < b.pid; }
                return a.base == b.base ? a.record < b.record : a.base < b.base;
            });
            groups.clear();
            for (size_t first = 0; first < events.size();)
            {
                const auto& head = events[first];
                ImageGroup group{head.pid, head.base, head.base + (head.size - 1), 0, first, first + 1, false, false};
                while (group.end < events.size() && events[group.end].pid == head.pid && events[group.end].base == head.base)
                {
                    const auto& previous = events[group.end - 1];
                    const auto& current = events[group.end++];
                    group.last = (std::max)(group.last, current.base + (current.size - 1));
                    group.transitionConflict |= ImageOpening(previous.opcode) == ImageOpening(current.opcode);
                    group.clockConflict |= previous.tick >= current.tick;
                    group.mixedLoggers |= previous.logger != current.logger;
                }
                group.prefixLast = groups.empty() || groups.back().pid != head.pid ? group.last :
                    (std::max)(groups.back().prefixLast, group.last);
                groups.push_back(group);
                first = group.end;
            }
        }

        ImageWitness At(const ImageGroup& group, const Sample& sample, bool clock, bool gap) const
        {
            const auto first = events.begin() + group.first, end = events.begin() + group.end;
            const auto next = std::lower_bound(first, end, sample.record, [](const ImageEvent& e, uint32_t record) {
                return e.record < record;
            });
            const auto* left = next == first ? nullptr : &*(next - 1);
            const auto* right = next == end ? nullptr : &*next;
            const bool inLeft = left && sample.ip - group.base < left->size;
            const bool inRight = right && sample.ip - group.base < right->size;
            if (group.transitionConflict) { return {left, right, L"conflicting_transitions"}; }
            if (group.clockConflict) { return {left, right, L"clock_unqualified"}; }
            if (!inLeft && !inRight) { return {}; }
            if (!clock || (left && left->tick >= sample.timestamp) || (right && right->tick <= sample.timestamp))
            { return {left, right, L"clock_unqualified"}; }
            // A preceding unload or a future load alone does not place this image at the sample.
            if (!(inLeft && ImageOpening(left->opcode)) && !(inRight && !ImageOpening(right->opcode))) { return {}; }
            if (!left || !right) { return {left, right, L"one_boundary"}; }
            if (!inLeft || !inRight || left->size != right->size || left->width != right->width ||
                left->preferred != right->preferred || left->checksum != right->checksum || left->stamp != right->stamp ||
                left->version != right->version || left->signatureLevel != right->signatureLevel ||
                left->signatureType != right->signatureType || Name(*left) != Name(*right)) { return {left, right, L"image_identity_conflict"}; }
            if (!left->nameUnits) { return {left, right, L"missing_image_name"}; }
            if (gap || unsupported) { return {left, right, L"coverage_unqualified"}; }
            return {left, right, left->opcode == 10 && right->opcode == 2 ? L"load_unload" : L"rundown_bracket", true};
        }

        ImageMatch Lookup(const Sample& sample, uint32_t pairedPid, bool clock, bool gap) const
        {
            ImageMatch result;
            if (!Complete()) { result.relation = L"index_limit"; return result; }
            if (!pairedPid || pairedPid == UINT32_MAX) { result.relation = L"thread_pid_unavailable"; return result; }
            const auto key = std::make_pair(pairedPid, sample.ip);
            auto it = std::upper_bound(groups.begin(), groups.end(), key, [](const auto& k, const ImageGroup& g) {
                return k.first == g.pid ? k.second < g.base : k.first < g.pid;
            });
            while (it != groups.begin())
            {
                const auto& group = *--it;
                if (group.pid != pairedPid || group.prefixLast < sample.ip) { break; }
                if (group.last < sample.ip) { continue; }
                auto witness = At(group, sample, clock, gap);
                witness.mixedLoggers = group.mixedLoggers;
                if (!witness.relation) { continue; }
                if (result.count < result.witnesses.size()) { result.witnesses[result.count] = witness; }
                ++result.count;
            }
            if (result.count == 1)
            {
                const auto& w = result.witnesses.front();
                result.relation = w.relation;
                result.paired = w.paired;
                if (w.paired) { result.rva = sample.ip - w.before->base; }
            }
            else if (result.count > 1) { result.relation = L"overlapping_ranges"; }
            return result;
        }
    };
}
