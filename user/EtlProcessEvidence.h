#pragma once

#include "EtlThreadEvidence.h"
#include "EtlImageEvidence.h"

namespace etl_profile
{
    inline constexpr GUID ProcessProvider = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
    inline constexpr size_t MaxProcessEvents = 65536;

    struct ProcessEvent
    {
        uint32_t record = 0, pid = 0, parent = 0, session = 0;
        int32_t exitStatus = 0;
        int64_t tick = 0;
        uint64_t key = 0, exitTime = 0;
        uint16_t logger = 0;
        uint8_t width = 0, version = 0, opcode = 0;
        bool badTransitions = false, badClock = false, mixedLoggers = false;
    };

    inline bool ProcessOpcode(uint8_t op) { return (op >= 1 && op <= 4) || op == 39; }

    inline bool ProcessClockRecord(const EVENT_HEADER& h)
    {
        const auto op = h.EventDescriptor.Opcode;
        return (IsEqualGUID(h.ProviderId, ProcessProvider) && ProcessOpcode(op)) ||
            (IsEqualGUID(h.ProviderId, PerfInfo) && op == 46) ||
            (IsEqualGUID(h.ProviderId, ThreadProvider) && op >= 1 && op <= 4);
    }

    inline bool ProcessSuffix(const uint8_t* p, size_t size, uint8_t width, uint8_t version)
    {
        // WBEM SID is either one zero ULONG or a TOKEN_USER and an inline SID.
        if (size < 4) { return false; }
        uint32_t present;
        std::memcpy(&present, p, sizeof(present));
        size_t offset = 4;
        if (present)
        {
            const size_t sid = 2u * width;
            if (size < sid + 8 || p[sid] != SID_REVISION || p[sid + 1] > SID_MAX_SUB_AUTHORITIES) { return false; }
            offset = sid + 8 + 4u * p[sid + 1];
            if (offset > size) { return false; }
        }
        const auto* zero = static_cast<const uint8_t*>(std::memchr(p + offset, 0, size - offset));
        if (!zero) { return false; }
        offset = static_cast<size_t>(zero - p) + 1;
        // Command line, followed in v4/v5 by package and application strings.
        for (int i = 0; i < (version >= 4 ? 3 : 1); ++i)
        {
            const size_t start = offset;
            while (size - offset >= 2 && (p[offset] || p[offset + 1])) { offset += 2; }
            if (size - offset < 2) { return false; }
            offset += 2;
            if (!TerminatedUtf16(p + start, offset - start)) { return false; }
        }
        return offset == size;
    }

    inline Match DecodeProcess(const EVENT_RECORD& event, uint32_t record, ProcessEvent& result)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, ProcessProvider) || !ProcessOpcode(d.Opcode)) { return Match::Other; }
        if (d.Version < 2 || d.Version > 5 || (d.Version == 5 && d.Opcode != 39)) { return Match::Unsupported; }
        const uint8_t width = ClassicPointerWidth(h, d.Version);
        // v3 adds a pointer after ExitStatus. v4 adds flags before the variable tail.
        const size_t fixed = width + 16u + (d.Version >= 3 ? width : 0u) + (d.Version >= 4 ? 4u : 0u);
        const size_t trailing = d.Version == 5 ? 8 : 0;
        const auto* p = static_cast<const uint8_t*>(event.UserData);
        if (!width || !p || (event.ExtendedDataCount && !event.ExtendedData) || event.UserDataLength < fixed + trailing ||
            !ProcessSuffix(p + fixed, event.UserDataLength - fixed - trailing, width, d.Version))
        { return Match::Unsupported; }

        result = {};
        result.record = record;
        result.tick = h.TimeStamp.QuadPart;
        result.logger = event.BufferContext.LoggerId;
        result.width = width;
        result.version = d.Version;
        result.opcode = d.Opcode;
        // Keep the key for equality checks. The report identifies a generation by its start record.
        std::memcpy(&result.key, p, width);
        std::memcpy(&result.pid, p + width, 4);
        std::memcpy(&result.parent, p + width + 4, 4);
        std::memcpy(&result.session, p + width + 8, 4);
        std::memcpy(&result.exitStatus, p + width + 12, 4);
        if (trailing) { std::memcpy(&result.exitTime, p + event.UserDataLength - trailing, 8); }
        return Match::Decoded;
    }

    struct ProcessPair
    {
        const ProcessEvent* before = nullptr;
        const ProcessEvent* after = nullptr;
        const wchar_t* relation = L"no_record";
        const wchar_t* keyComparison = L"not_compared";
        uint32_t candidatePid = 0;
        bool generation = false;
    };

    struct EventClockOrder
    {
        int64_t last = 0;
        bool seen = false, reversed = false;

        void Observe(int64_t tick)
        {
            reversed |= seen && tick < last;
            seen = true;
            last = tick;
        }
    };

    struct ProcessIndex
    {
        std::vector<ProcessEvent> events;
        uint32_t decoded = 0, unsupported = 0, defunct = 0;
        EventClockOrder processClock, imageClock;

        void Prepare() { events.reserve(MaxProcessEvents); }
        bool Complete() const { return events.size() == decoded; }

        void Observe(const EVENT_RECORD& event, uint32_t record, bool withImages = false)
        {
            const auto& h = event.EventHeader;
            const auto op = h.EventDescriptor.Opcode;
            const bool process = IsEqualGUID(h.ProviderId, ProcessProvider) && ProcessOpcode(op);
            const bool core = ProcessClockRecord(h);
            if (core) { processClock.Observe(h.TimeStamp.QuadPart); }
            if (withImages && (core || (IsEqualGUID(h.ProviderId, ImageProvider) && (op == 10 || (op >= 2 && op <= 4)))))
            { imageClock.Observe(h.TimeStamp.QuadPart); }
            if (!process) { return; }
            ProcessEvent point;
            if (DecodeProcess(event, record, point) != Match::Decoded) { ++unsupported; return; }
            ++decoded;
            if (point.opcode == 39) { ++defunct; }
            if (events.size() < MaxProcessEvents) { events.push_back(point); }
        }

        void Sort()
        {
            std::sort(events.begin(), events.end(), [](const ProcessEvent& a, const ProcessEvent& b) {
                return a.pid == b.pid ? a.record < b.record : a.pid < b.pid;
            });
            for (size_t first = 0; first < events.size();)
            {
                size_t end = first;
                uint8_t lastLife = 0;
                bool transitions = false, clock = false, loggers = false;
                while (end < events.size() && events[end].pid == events[first].pid)
                {
                    const auto& e = events[end];
                    clock |= end != first && events[end - 1].tick >= e.tick;
                    loggers |= e.logger != events[first].logger;
                    if (e.opcode != 39)
                    {
                        transitions |= lastLife && Opening(lastLife) == Opening(e.opcode);
                        lastLife = e.opcode;
                    }
                    ++end;
                }
                for (size_t i = first; i < end; ++i)
                {
                    events[i].badTransitions = transitions;
                    events[i].badClock = clock;
                    events[i].mixedLoggers = loggers;
                }
                first = end;
            }
        }

        ProcessPair Lookup(const Sample& sample, const ThreadPair& thread, bool clock, bool gap) const
        {
            ProcessPair p;
            if (!Complete()) { p.relation = L"index_limit"; return p; }
            const auto* begin = thread.before;
            const auto* end = thread.after;
            if (!begin || !end || !Opening(begin->opcode) || Opening(end->opcode) || begin->pid != end->pid ||
                !begin->pid || begin->pid == UINT32_MAX)
            { p.relation = L"thread_pid_unavailable"; return p; }
            p.candidatePid = begin->pid;
            const auto id = std::make_pair(p.candidatePid, sample.record);
            const auto next = std::lower_bound(events.begin(), events.end(), id, [](const ProcessEvent& e, const auto& k) {
                return e.pid == k.first ? e.record < k.second : e.pid < k.first;
            });
            if (next != events.end() && next->pid == p.candidatePid) { p.after = &*next; }
            if (next != events.begin() && (next - 1)->pid == p.candidatePid) { p.before = &*(next - 1); }
            if (!thread.pairedPid) { p.relation = L"thread_pid_unqualified"; return p; }
            if (!p.before && !p.after) { return p; }
            if ((p.before && p.before->opcode == 39) || (p.after && p.after->opcode == 39))
            { p.relation = L"defunct_marker"; return p; }
            if (!p.before || !p.after) { p.relation = L"one_boundary"; return p; }
            const auto& a = *p.before;
            const auto& b = *p.after;
            if (!Opening(a.opcode) || Opening(b.opcode)) { p.relation = L"outside_bracket"; return p; }
            if (a.mixedLoggers || begin->mixedLoggers || a.logger != sample.loggerId ||
                begin->logger != sample.loggerId || end->logger != sample.loggerId)
            { p.relation = L"logger_conflict"; return p; }
            if (a.width != b.width || a.version != b.version) { p.relation = L"layout_conflict"; return p; }
            p.keyComparison = !a.key && !b.key ? L"unreported" : !a.key || !b.key ? L"one_unreported" :
                a.key == b.key ? L"equal" : L"different";
            if (a.badTransitions) { p.relation = L"conflicting_transitions"; return p; }
            if ((a.key && b.key && a.key != b.key) || a.parent != b.parent || a.session != b.session)
            { p.relation = L"process_identity_conflict"; return p; }
            if ((a.opcode == 1 && a.record >= begin->record) || (b.opcode == 2 && b.record <= end->record))
            { p.relation = L"thread_outside_process"; return p; }
            if (!clock || processClock.reversed || a.badClock || a.tick >= sample.timestamp || b.tick <= sample.timestamp ||
                (a.opcode == 1 && a.tick >= begin->tick) || (b.opcode == 2 && b.tick <= end->tick))
            { p.relation = L"clock_unqualified"; return p; }
            if (gap || unsupported) { p.relation = L"coverage_unqualified"; return p; }
            p.generation = a.opcode == 1 && b.opcode == 2;
            p.relation = p.generation ? L"start_end" : L"rundown_bracket";
            return p;
        }
    };

    struct ProcessImagePair
    {
        const wchar_t* relation;
        bool paired = false;
    };

    inline ProcessImagePair ImageInProcess(const ProcessPair& process, const ImageMatch& image, bool reversedClock)
    {
        if (!process.generation) { return {L"process_generation_unavailable"}; }
        if (!image.paired) { return {L"image_pair_unavailable"}; }
        const auto& a = *image.witnesses[0].before;
        const auto& b = *image.witnesses[0].after;
        if (image.witnesses[0].mixedLoggers || a.logger != process.before->logger || b.logger != process.after->logger)
        { return {L"logger_conflict"}; }
        if (a.pid != process.candidatePid || b.pid != process.candidatePid ||
            a.record <= process.before->record || b.record >= process.after->record)
        { return {L"image_outside_process"}; }
        if (reversedClock || a.tick <= process.before->tick || b.tick >= process.after->tick) { return {L"clock_unqualified"}; }
        return {L"inside_process_generation", true};
    }
}
