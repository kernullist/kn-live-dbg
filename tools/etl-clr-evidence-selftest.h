#pragma once

#include "../user/EtlClrEvidence.h"
#include <string_view>

namespace etl_clr_test
{
    using namespace etl_profile;
    using A = ClrMethodAction;

    struct Fixture
    {
        ProcessEvent open{}, close{};
        Sample sample{};

        Fixture()
        {
            open.record = 10; open.tick = 100; open.pid = 7; open.opcode = 1; open.logger = 3;
            close.record = 90; close.tick = 900; close.pid = 7; close.opcode = 2; close.logger = 3;
            sample.record = 50; sample.timestamp = 500; sample.loggerId = 3; sample.ip = 0x20044;
        }

        ClrMatch Match(ClrIndex& index, bool generation = true, bool clock = true, bool loss = false) const
        {
            ProcessPair process;
            process.before = &open; process.after = &close; process.candidatePid = open.pid; process.generation = generation;
            index.Sort();
            return index.Lookup(sample, process, clock, loss);
        }
    };

    inline void Add(ClrIndex& index, A action, uint32_t ordinal, uint64_t start = 0x20000, uint64_t rejit = 1,
        uint8_t version = 2, uint32_t pid = 7, uint16_t logger = 3, int64_t tick = 0, uint32_t size = 0x80)
    {
        const uint64_t methodId = 0x123456789abcdef0ULL, moduleId = 0xecd5432112345678ULL;
        const uint32_t token = 0x06000001, flags = 8;
        const uint16_t instance = 0;
        std::array<uint8_t, 47> data{};
        auto* bytes = data.data() + 1;
        std::memcpy(bytes, &methodId, 8); std::memcpy(bytes + 8, &moduleId, 8);
        std::memcpy(bytes + 16, &start, 8); std::memcpy(bytes + 24, &size, 4);
        std::memcpy(bytes + 28, &token, 4); std::memcpy(bytes + 32, &flags, 4);
        std::memcpy(bytes + 36, &instance, 2); std::memcpy(bytes + 38, &rejit, 8);
        EVENT_RECORD e{};
        auto& h = e.EventHeader;
        h.ProviderId = action == A::Rundown ? kClrRundown : kClrRuntime;
        h.EventDescriptor.Id = action == A::Unload ? 142 : 141;
        h.EventDescriptor.Opcode = action == A::Rundown ? 35 : action == A::Unload ? 34 : 33;
        h.EventDescriptor.Task = action == A::Rundown ? 1 : 9;
        h.EventDescriptor.Version = version; h.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
        h.ProcessId = pid; h.TimeStamp.QuadPart = tick ? tick : 10LL * ordinal;
        e.BufferContext.LoggerId = logger;
        e.UserData = bytes;
        e.UserDataLength = action == A::Unsupported ? 9 : version == 2 ? 46 : version == 1 ? 38 : 36;
        index.Observe(e, ordinal);
    }

    inline bool Reason(const ClrMatch& m, const wchar_t* reason, bool lifetime = false)
    {
        return std::wstring_view(m.relation) == reason && m.lifetime == lifetime;
    }

    inline bool Check()
    {
        Fixture f;
        ClrIndex index;
        Add(index, A::Unload, 5, 0x20000, 13); // Previous incarnation of the same PID.
        Add(index, A::Load, 20);
        Add(index, A::Rundown, 30);
        Add(index, A::Rundown, 60);
        Add(index, A::Unload, 75);
        Add(index, A::Load, 95, 0x20000, 17);
        auto match = f.Match(index);
        if (!Reason(match, L"load_unload", true) || match.count != 1 ||
            match.witnesses[0].before->record != 20 || match.witnesses[0].after->record != 75 ||
            !Reason(f.Match(index, false), L"process_generation_unavailable") ||
            !Reason(f.Match(index, true, false), L"clock_unqualified") ||
            !Reason(f.Match(index, true, true, true), L"coverage_unqualified")) { return false; }
        f.sample.ip = 0x20000;
        if (!Reason(f.Match(index), L"load_unload", true)) { return false; }
        f.sample.ip += 0x80;
        if (!Reason(f.Match(index), L"no_covering_declaration")) { return false; }
        f.sample.ip = 0x20044;

        index = {};
        Add(index, A::Load, 20, 0x20000, 0);
        Add(index, A::Unload, 70, 0x20000, 0, 1);
        if (!Reason(f.Match(index), L"conflicting_declarations")) { return false; }
        index = {};
        Add(index, A::Load, 15, 0x20000, 1);
        Add(index, A::Unload, 25, 0x20000, 1);
        Add(index, A::Load, 35, 0x20000, 2);
        Add(index, A::Unload, 75, 0x20000, 2);
        match = f.Match(index);
        if (!Reason(match, L"load_unload", true) || match.witnesses[0].before->method.ReJitId.value_or(0) != 2) { return false; }
        index = {};
        Add(index, A::Load, 15);
        Add(index, A::Load, 35, 0x20000, 2);
        Add(index, A::Unload, 75, 0x20000, 2);
        if (!Reason(f.Match(index), L"conflicting_declarations")) { return false; }
        index = {};
        Add(index, A::Rundown, 65);
        if (!Reason(f.Match(index), L"no_covering_declaration")) { return false; }
        index = {};
        Add(index, A::Rundown, 30);
        Add(index, A::Unload, 60);
        if (!Reason(f.Match(index), L"rundown_bracket")) { return false; }
        index = {};
        Add(index, A::Load, 35);
        if (!Reason(f.Match(index), L"preceding_declaration")) { return false; }
        index = {};
        Add(index, A::Unload, 70);
        if (!Reason(f.Match(index), L"unload_only")) { return false; }
        index = {};
        Add(index, A::Load, 20);
        Add(index, A::Load, 22, 0x20010);
        Add(index, A::Load, 24, 0x20020);
        Add(index, A::Unload, 70);
        Add(index, A::Unload, 72, 0x20010);
        Add(index, A::Unload, 74, 0x20020);
        match = f.Match(index);
        if (!Reason(match, L"overlapping_ranges") || match.count != 3 || !match.witnesses[1].before) { return false; }
        index = {};
        Add(index, A::Load, 30);
        Add(index, A::Unload, 70, 0x20000, 1, 2, 7, 4);
        if (!Reason(f.Match(index), L"logger_conflict")) { return false; }
        index = {};
        Add(index, A::Load, 30, 0x20000, 1, 2, 7, 3, 500);
        Add(index, A::Unload, 70);
        if (!Reason(f.Match(index), L"clock_unqualified")) { return false; }
        index = {};
        Add(index, A::Load, 30, 0x20000, 1, 2, 7, 3, 710);
        Add(index, A::Unload, 70);
        if (!index.clock.reversed || !Reason(f.Match(index), L"clock_unqualified")) { return false; }
        index = {};
        Add(index, A::Unsupported, 5);
        Add(index, A::Load, 20);
        Add(index, A::Unsupported, 40, 0x20000, 1, 2, 8);
        Add(index, A::Unload, 70);
        if (index.unsupported != 2 || !Reason(f.Match(index), L"load_unload", true)) { return false; }
        Add(index, A::Unsupported, 80);
        if (!Reason(f.Match(index), L"coverage_unqualified")) { return false; }
        index = {};
        Add(index, A::Load, 20);
        Add(index, A::Unsupported, 30, 0x20000, 1, 2, UINT32_MAX);
        Add(index, A::Unload, 70);
        if (index.unknownPid != 1 || !Reason(f.Match(index), L"coverage_unqualified")) { return false; }
        index = {};
        Add(index, A::Load, 20, UINT64_MAX - 2);
        Add(index, A::Load, 30, 0x20000, 1, 2, 7, 3, 0, 0);
        if (index.unsupported != 2 || index.loads != 0) { return false; }
        index = {};
        index.Prepare();
        for (uint32_t i = 0; i <= MaxClrEvents; ++i) { Add(index, A::Load, i + 1); }
        return !index.Complete() && index.events.size() == MaxClrEvents && Reason(f.Match(index), L"index_limit");
    }
}
