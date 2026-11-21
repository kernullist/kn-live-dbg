#pragma once

#include "../user/EtlReferenceImage.h"

namespace etl_build_test
{
    using namespace etl_profile;

    inline bool CheckDecoder(uint8_t width)
    {
        // Deliberately unaligned payloads. The names only exercise record
        // boundaries and are never used to find a reference or a PDB.
        std::array<uint8_t, 80> buffer{};
        auto* data = buffer.data() + 1;
        EVENT_RECORD e{};
        e.EventHeader.ProviderId = ImageIdProvider;
        e.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER |
            (width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER);
        e.EventHeader.EventDescriptor.Version = 2;
        e.EventHeader.ProcessId = 17;
        e.BufferContext.LoggerId = 3;
        e.UserData = data;
        const uint64_t base = width == 4 ? 0x1000 : 0x100001000ull, length = 0x1800;
        const uint32_t pid = 17, stamp = 222, age = UINT32_MAX;
        BuildEvent out;
        for (const uint8_t op : std::array<uint8_t, 3>{0, 32, 36})
        {
            buffer.fill(0);
            std::memcpy(data, &base, width);
            e.EventHeader.EventDescriptor.Opcode = op;
            e.UserDataLength = width + 4;
            std::memcpy(data + width, &pid, 4);
            if (op == 0)
            {
                std::memcpy(data + width, &length, width);
                std::memcpy(data + 2 * width, &pid, 4);
                std::memcpy(data + 2 * width + 4, &stamp, 4);
                data[2 * width + 8] = 'A';
                e.UserDataLength = 2 * width + 12;
            }
            if (op == 36)
            {
                std::memcpy(data + width + 4, &ImageIdProvider, sizeof(GUID));
                std::memcpy(data + width + 20, &age, 4);
                data[width + 24] = 'X';
                e.UserDataLength = width + 26;
            }
            const auto size = e.UserDataLength;
            if (!DecodeBuild(e, 123, out) || out.width != width || out.record != 123 || out.base != base ||
                out.pid != pid || out.headerPid != pid || out.logger != 3 || out.opcode != op ||
                (!op && (out.stamp != stamp || out.size != length)) ||
                (op == 36 && (out.age != age || !IsEqualGUID(out.guid, ImageIdProvider)))) { return false; }
            for (e.UserDataLength = 0; e.UserDataLength < size; ++e.UserDataLength)
            {
                if (DecodeBuild(e, 0, out)) { return false; }
            }
            ++e.UserDataLength;
            if (DecodeBuild(e, 0, out)) { return false; }
            e.UserDataLength = size;
            if (op == 36)
            {
                data[width + 24] = 0xff;
                if (DecodeBuild(e, 0, out)) { return false; }
            }
            if (op == 0)
            {
                std::memset(data, 0xff, width);
                if (DecodeBuild(e, 0, out)) { return false; }
            }
        }
        e.EventHeader.EventDescriptor.Opcode = 32;
        e.UserDataLength = width + 4;
        BuildIndex index;
        index.Observe(e, 1);
        ++e.EventHeader.ProcessId;
        index.Observe(e, 2);
        e.EventHeader.EventDescriptor.Version = 3;
        index.Observe(e, 3);
        e.EventHeader.EventDescriptor.Opcode = 37;
        index.Observe(e, 4);
        e.EventHeader.ProviderId = ImageProvider;
        index.Observe(e, 5);
        return index.decoded == 2 && index.pidConflicts == 1 && index.unsupported == 1 && index.other == 1;
    }

    inline bool CheckBudget()
    {
        EVENT_RECORD event{};
        event.EventHeader.ProviderId = ImageIdProvider;
        event.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;
        event.EventHeader.EventDescriptor.Version = 2;
        event.EventHeader.EventDescriptor.Opcode = 32;
        std::array<uint8_t, 12> data{};
        event.UserData = data.data();
        event.UserDataLength = static_cast<USHORT>(data.size());
        BuildIndex index;
        index.Prepare();
        for (uint32_t n = 1; n <= MaxBuildEvents; ++n) { index.Observe(event, n); }
        if (!index.Complete() || index.events.size() != MaxBuildEvents) { return false; }
        index.Observe(event, static_cast<uint32_t>(MaxBuildEvents + 1));
        return !index.Complete() && index.decoded == MaxBuildEvents + 1 && index.events.back().record == MaxBuildEvents;
    }

    inline bool CheckJoin()
    {
        ImageEvent loader{};
        loader.tick = 100;
        loader.base = 0x2000;
        loader.size = 0x3000;
        loader.pid = 42;
        loader.logger = 1;
        loader.width = 8;
        loader.record = 10;
        BuildEvent info{};
        info.tick = loader.tick;
        info.base = loader.base;
        info.pid = info.headerPid = loader.pid;
        info.logger = loader.logger;
        info.width = loader.width;
        info.record = 12;
        info.size = loader.size;
        info.stamp = 20;
        auto debug = info;
        debug.record = 8;
        debug.opcode = 36;
        debug.guid = ImageIdProvider;
        auto none = info;
        none.record = 13;
        none.opcode = 32;
        auto endpoint = [&](std::vector<BuildEvent> markers, std::vector<ImageEvent> anchors, bool coverage = true) {
            BuildIndex index;
            index.events = std::move(markers);
            index.decoded = static_cast<uint32_t>(index.events.size());
            ImageIndex images;
            images.events = std::move(anchors);
            index.Sort(images);
            return std::wstring(index.At(loader, coverage).relation);
        };
        auto foreign = debug;
        ++foreign.pid;
        auto foreignLogger = debug;
        ++foreignLogger.logger;
        auto otherTime = debug;
        ++otherTime.tick;
        auto otherBase = debug;
        ++otherBase.base;
        if (endpoint({foreign, foreignLogger, otherTime, otherBase, debug, info}, {loader}) != L"unique_merge_records" ||
            endpoint({foreign, foreignLogger, otherTime, otherBase, info}, {loader}) != L"markers_missing" ||
            endpoint({debug, info}, {loader}, false) != L"coverage_unqualified" ||
            endpoint({debug, info}, {loader, loader}) != L"ambiguous_records" ||
            endpoint({debug, info, debug}, {loader}) != L"ambiguous_records" ||
            endpoint({debug, info, none}, {loader}) != L"conflicting_debug_markers" ||
            endpoint({info, none}, {loader}) != L"reported_no_debug_id") { return false; }
        none.width = 4;
        if (endpoint({none}, {loader}) != L"loader_marker_conflict") { return false; }
        auto altered = info;
        ++altered.size;
        if (endpoint({altered}, {loader}) != L"loader_marker_conflict") { return false; }
        if (endpoint({debug, altered}, {loader}) != L"loader_marker_conflict") { return false; }
        loader.stamp = 10;
        if (endpoint({debug, info}, {loader}) != L"loader_marker_conflict") { return false; }
        loader.stamp = UINT32_MAX;
        altered = debug;
        altered.width = 4;
        if (endpoint({altered, info}, {loader}) != L"loader_marker_conflict") { return false; }
        altered.guid = {};
        altered.width = loader.width;
        if (endpoint({altered, info}, {loader}) != L"empty_debug_id") { return false; }

        BuildEndpoint left{1, {1, &info}, {}, {1, &debug}, L"unique_merge_records", true};
        auto rightInfo = info, rightDebug = debug;
        ++rightInfo.record;
        ++rightDebug.record;
        BuildEndpoint right{1, {1, &rightInfo}, {}, {1, &rightDebug}, L"unique_merge_records", true};
        if (!MatchBuildPair(left, right).rsds || MatchBuildPair(left, left).rsds) { return false; }
        ++rightDebug.age;
        if (MatchBuildPair(left, right).rsds) { return false; }
        rightDebug.age = debug.age;
        ++rightDebug.guid.Data1;
        if (MatchBuildPair(left, right).rsds) { return false; }
        rightDebug.guid = debug.guid;
        ++rightInfo.stamp;
        if (MatchBuildPair(left, right).rsds) { return false; }
        right.qualified = false;
        if (std::wstring_view(MatchBuildPair(left, right).relation) != L"endpoint_unqualified") { return false; }

        BuildIndex index;
        index.events = {debug, info};
        ImageIndex images;
        images.events.push_back(loader);
        index.Sort(images);
        for (const auto counts : {std::array<unsigned, 3>{3, 0, 0}, {2, 1, 0}, {2, 0, 1}})
        {
            index.decoded = counts[0];
            index.unsupported = counts[1];
            index.pidConflicts = counts[2];
            const auto p = index.At(loader, true);
            if (p.qualified || p.info.count != 1 || p.rsds.count != 1) { return false; }
        }
        return true;
    }
}
