#pragma once

#include "EtlImageEvidence.h"
#include <tuple>

namespace etl_profile
{
    inline constexpr GUID ImageIdProvider = {0xb3e675d7, 0x2554, 0x4f18, {0x83, 0x0b, 0x27, 0x62, 0x73, 0x25, 0x60, 0xde}};
    inline constexpr size_t MaxBuildEvents = 131072;

    struct BuildEvent
    {
        int64_t tick = 0;
        uint64_t base = 0, size = 0;
        uint32_t record = 0, pid = 0, headerPid = 0, stamp = 0, age = 0;
        GUID guid{};
        uint16_t logger = 0;
        uint8_t width = 0, opcode = 0;
    };

    inline bool BuildStampPresent(uint32_t stamp) { return stamp && stamp != UINT32_MAX; }

    inline bool DecodeBuild(const EVENT_RECORD& event, uint32_t record, BuildEvent& result)
    {
        const auto& h = event.EventHeader;
        const auto op = h.EventDescriptor.Opcode;
        const auto width = ClassicPointerWidth(h, 2);
        const auto* data = static_cast<const uint8_t*>(event.UserData);
        const size_t length = event.UserDataLength;
        if (!width || !data || length < width + 4u) { return false; }
        result = {};
        result.tick = h.TimeStamp.QuadPart;
        result.record = record;
        result.width = width;
        result.opcode = op;
        result.logger = event.BufferContext.LoggerId;
        result.headerPid = h.ProcessId;
        std::memcpy(&result.base, data, width);
        if (op == 0)
        {
            const size_t tail = 2u * width + 8;
            if (length < tail || !TerminatedUtf16(data + tail, length - tail)) { return false; }
            std::memcpy(&result.size, data + width, width);
            std::memcpy(&result.pid, data + 2 * width, 4);
            std::memcpy(&result.stamp, data + 2 * width + 4, 4);
            const uint64_t maximum = width == 4 ? UINT32_MAX : UINT64_MAX;
            return result.size && result.size - 1 <= maximum - result.base;
        }
        std::memcpy(&result.pid, data + width, 4);
        if (op == 32) { return length == width + 4u; }
        const size_t tail = width + 24u;
        if (op != 36 || length <= tail || data[length - 1] ||
            std::memchr(data + tail, 0, length - tail - 1)) { return false; }
        const auto nameBytes = static_cast<int>(length - tail - 1);
        if (nameBytes && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(data + tail), nameBytes, nullptr, 0)) { return false; }
        std::memcpy(&result.guid, data + width + 4, sizeof(GUID));
        std::memcpy(&result.age, data + width + 20, 4);
        return true;
    }

    // The merger borrows the loader timestamp. Distinct PID, base and logger
    // values can share that tick. Callback adjacency is not part of the key.
    using BuildKey = std::tuple<int64_t, uint64_t, uint32_t, uint16_t>;
    template<typename Event> BuildKey BuildKeyOf(const Event& e) { return {e.tick, e.base, e.pid, e.logger}; }

    struct MarkerRange
    {
        size_t count = 0;
        const BuildEvent* first = nullptr;
    };

    struct BuildEndpoint
    {
        size_t loaders = 0;
        MarkerRange info, none, rsds;
        const wchar_t* relation = L"markers_missing";
        bool qualified = false;
    };

    struct BuildIndex
    {
        std::vector<BuildEvent> events;
        std::vector<BuildKey> loaders;
        uint32_t decoded = 0, unsupported = 0, other = 0, pidConflicts = 0;

        void Prepare() { events.reserve(MaxBuildEvents); }
        bool Complete() const { return decoded == events.size(); }

        void Observe(const EVENT_RECORD& event, uint32_t ordinal)
        {
            if (!IsEqualGUID(event.EventHeader.ProviderId, ImageIdProvider)) { return; }
            const auto op = event.EventHeader.EventDescriptor.Opcode;
            if (op != 0 && op != 32 && op != 36) { ++other; return; }
            BuildEvent point;
            if (!DecodeBuild(event, ordinal, point)) { ++unsupported; return; }
            ++decoded;
            if (point.pid != point.headerPid) { ++pidConflicts; }
            if (events.size() < MaxBuildEvents) { events.push_back(point); }
        }

        void Sort(const ImageIndex& images)
        {
            loaders.clear();
            loaders.reserve(images.events.size());
            for (const auto& e : images.events) { loaders.push_back(BuildKeyOf(e)); }
            std::sort(loaders.begin(), loaders.end());
            std::sort(events.begin(), events.end(), [](const BuildEvent& a, const BuildEvent& b) {
                return std::make_tuple(BuildKeyOf(a), a.opcode, a.record) < std::make_tuple(BuildKeyOf(b), b.opcode, b.record);
            });
        }

        MarkerRange Markers(const BuildKey& key, uint8_t opcode) const
        {
            const auto match = std::make_pair(key, opcode);
            const auto first = std::lower_bound(events.begin(), events.end(), match, [](const auto& e, const auto& k) {
                return std::make_pair(BuildKeyOf(e), e.opcode) < k;
            });
            const auto end = std::upper_bound(first, events.end(), match, [](const auto& k, const auto& e) {
                return k < std::make_pair(BuildKeyOf(e), e.opcode);
            });
            return {static_cast<size_t>(end - first), end == first ? nullptr : &*first};
        }

        BuildEndpoint At(const ImageEvent& image, bool coverage) const
        {
            const auto key = BuildKeyOf(image);
            const auto range = std::equal_range(loaders.begin(), loaders.end(), key);
            BuildEndpoint r{static_cast<size_t>(range.second - range.first), Markers(key, 0), Markers(key, 32), Markers(key, 36)};
            if (!coverage || !Complete() || unsupported || pidConflicts) { r.relation = L"coverage_unqualified"; }
            else if (r.loaders != 1 || r.info.count > 1 || r.none.count > 1 || r.rsds.count > 1) { r.relation = L"ambiguous_records"; }
            else if (r.none.count && r.rsds.count) { r.relation = L"conflicting_debug_markers"; }
            else if ((r.info.first && (r.info.first->width != image.width || r.info.first->size != image.size ||
                (BuildStampPresent(image.stamp) && BuildStampPresent(r.info.first->stamp) && image.stamp != r.info.first->stamp))) ||
                (r.rsds.first && r.rsds.first->width != image.width) || (r.none.first && r.none.first->width != image.width))
            { r.relation = L"loader_marker_conflict"; }
            else if (r.none.first) { r.relation = L"reported_no_debug_id"; }
            else if (r.info.first && r.rsds.first)
            {
                if (IsEqualGUID(r.rsds.first->guid, GUID{})) { r.relation = L"empty_debug_id"; }
                else { r.relation = L"unique_merge_records"; r.qualified = true; }
            }
            return r;
        }
    };

    struct BuildPair
    {
        const wchar_t* relation = L"process_image_unavailable";
        const BuildEvent* rsds = nullptr;
        uint32_t stamp = 0;
    };

    inline BuildPair MatchBuildPair(const BuildEndpoint& left, const BuildEndpoint& right)
    {
        if (!left.qualified || !right.qualified) { return {L"endpoint_unqualified"}; }
        const auto& a = *left.rsds.first;
        const auto& b = *right.rsds.first;
        if (a.record == b.record || left.info.first->record == right.info.first->record ||
            a.age != b.age || !IsEqualGUID(a.guid, b.guid) || left.info.first->stamp != right.info.first->stamp)
        { return {L"endpoint_build_conflict"}; }
        return {L"paired_merge_build", &a, left.info.first->stamp};
    }
}
