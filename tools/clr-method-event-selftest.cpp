// Run without arguments for the manifest boundary controls. With an ETL,
// compare every CLR method declaration to Windows TDH's named properties.
#include "../user/ClrMethodEvent.h"

#include <tdh.h>

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

namespace
{
    void Append(std::vector<uint8_t>& bytes, uint64_t value, unsigned width)
    {
        for (unsigned i = 0; i < width; ++i)
        {
            bytes.push_back(static_cast<uint8_t>(value >> (i * 8)));
        }
    }

    template<typename T>
    std::optional<T> Named(EVENT_RECORD* e, const wchar_t* name)
    {
        PROPERTY_DATA_DESCRIPTOR property = {};
        property.PropertyName = reinterpret_cast<ULONGLONG>(name);
        property.ArrayIndex = ULONG_MAX;
        ULONG length = 0;
        T value{};
        if (TdhGetPropertySize(e, 0, nullptr, 1, &property, &length) == ERROR_SUCCESS && length == sizeof(T) &&
            TdhGetProperty(e, 0, nullptr, 1, &property, length, reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS)
        {
            return value;
        }
        return std::nullopt;
    }

    struct Case
    {
        uint16_t Id;
        uint8_t Opcode;
        bool InventoryProvider;
        bool Verbose;
        ClrMethodAction Action;
    };

    bool BoundaryControls()
    {
        using A = ClrMethodAction;
        const Case cases[] = {
            {137, 35, false, false, A::Rundown}, {138, 36, false, false, A::Rundown},
            {139, 39, false, true, A::Rundown}, {140, 40, false, true, A::Rundown},
            {141, 33, false, false, A::Load}, {142, 34, false, false, A::Unload},
            {143, 37, false, true, A::Load}, {144, 38, false, true, A::Unload},
            {141, 35, true, false, A::Rundown}, {142, 36, true, false, A::Rundown},
            {143, 39, true, true, A::Rundown}, {144, 40, true, true, A::Rundown}};
        for (const auto& c : cases)
        {
            for (uint8_t version = 0; version <= (c.Id < 141 ? 0 : 2); ++version)
            {
                for (int widthFlag : {EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER})
                {
                    EVENT_RECORD event = {};
                    auto& h = event.EventHeader;
                    h.ProviderId = c.InventoryProvider ? kClrRundown : kClrRuntime;
                    h.Flags = static_cast<USHORT>(widthFlag);
                    h.TimeStamp.QuadPart = 98765;
                    auto& d = h.EventDescriptor;
                    d.Task = c.InventoryProvider ? 1 : 9;
                    d.Opcode = c.Opcode;
                    d.Id = c.Id;
                    d.Version = version;
                    std::vector<uint8_t> bytes;
                    Append(bytes, 0x8765432112345678ULL, 8);
                    Append(bytes, 0xfedcba9876543210ULL, 8);
                    Append(bytes, 0x12345678, 8);
                    Append(bytes, 73, 4);
                    Append(bytes, 0x06000001, 4);
                    Append(bytes, 0x108, 4);
                    if (c.Verbose)
                    {
                        for (const char16_t* field : {u"", u"\u6f22M", u"void()"})
                        {
                            while (*field != 0)
                            {
                                Append(bytes, *field++, 2);
                            }
                            Append(bytes, 0, 2);
                        }
                    }
                    if (version >= 1) Append(bytes, 0, 2);
                    const uint64_t reJit = c.Verbose ? 0x8123456789abcdefULL : 0;
                    if (version == 2) Append(bytes, reJit, 8);
                    event.UserData = bytes.data();
                    event.UserDataLength = static_cast<USHORT>(bytes.size());
                    const auto action = ClassifyClrMethodEvent(h);
                    KmonRuntimeCodeRange range;
                    if (action != c.Action || ReadClrMethodRange(event, range) != c.Action ||
                        range.MethodId != 0x8765432112345678ULL || range.ModuleId != 0xfedcba9876543210ULL ||
                        range.Start != 0x12345678 || range.Size != 73 || range.MethodToken != 0x06000001 ||
                        range.MethodFlags != 0x108 || range.RuntimeInstance.has_value() != (version >= 1) ||
                        range.RuntimeInstance.value_or(0) != 0 || range.ReJitId.has_value() != (version == 2) ||
                        range.ReJitId.value_or(reJit) != reJit || range.EventId != c.Id ||
                        range.EventVersion != version || range.Observation != c.Action ||
                        range.RundownProvider != c.InventoryProvider || range.Timestamp != 98765)
                    {
                        return false;
                    }
                    // Read the constructed bytes through the installed Windows manifest too.
                    if (Named<uint64_t>(&event, L"MethodID") != range.MethodId ||
                        Named<uint32_t>(&event, L"MethodToken") != range.MethodToken ||
                        Named<uint16_t>(&event, L"ClrInstanceID") != range.RuntimeInstance ||
                        Named<uint64_t>(&event, L"ReJITID") != range.ReJitId)
                    {
                        std::fprintf(stderr, "TDH control mismatch id=%u v%u rundown_provider=%u\n",
                            c.Id, unsigned(version), unsigned(c.InventoryProvider));
                        return false;
                    }
                    range.MethodId = 42;
                    event.UserData = nullptr;
                    if (ReadClrMethodRange(event, range) != A::Unsupported || range.MethodId != 42) return false;
                    event.UserData = bytes.data();
                    for (USHORT n = 0; n < bytes.size(); ++n)
                    {
                        event.UserDataLength = n;
                        if (ReadClrMethodRange(event, range) != A::Unsupported || range.MethodId != 42) return false;
                    }
                    bytes.push_back(0);
                    event.UserData = bytes.data();
                    event.UserDataLength = static_cast<USHORT>(bytes.size());
                    if (ReadClrMethodRange(event, range) != A::Unsupported) return false;
                    ++d.Task;
                    if (ClassifyClrMethodEvent(h) != A::Unsupported) return false;
                    --d.Task;
                    ++d.Opcode;
                    if (ClassifyClrMethodEvent(h) != A::Unsupported) return false;
                    --d.Opcode;
                    d.Version = c.Id < 141 ? 1 : 3;
                    if (ClassifyClrMethodEvent(h) != A::Unsupported) return false;
                    d.Version = version;
                    h.Flags |= EVENT_HEADER_FLAG_STRING_ONLY;
                    if (ClassifyClrMethodEvent(h) != A::Unsupported) return false;
                    d.Id = 145;
                    if (ClassifyClrMethodEvent(h) != A::Ignore) return false;
                    h.ProviderId = kClrRundown;
                    d.Id = 137;
                    if (ClassifyClrMethodEvent(h) != A::Ignore) return false;
                    h.ProviderId = GUID{};
                    d.Id = 143;
                    if (ClassifyClrMethodEvent(h) != A::Ignore) return false;
                }
            }
        }
        return true;
    }

    struct Counts
    {
        uint64_t Records = 0, Load = 0, Unload = 0, Rundown = 0, Jitted = 0, Mismatch = 0;
        uint64_t CompactRundown = 0, LegacyRundown = 0;
        std::array<uint64_t, 3> Versions{};
    };

    void WINAPI Compare(EVENT_RECORD* event)
    {
        auto& h = event->EventHeader;
        auto& n = *static_cast<Counts*>(event->UserContext);
        ++n.Records;
        if (!IsEqualGUID(h.ProviderId, kClrRuntime) && !IsEqualGUID(h.ProviderId, kClrRundown)) return;
        KmonRuntimeCodeRange range;
        const auto action = ReadClrMethodRange(*event, range);
        const auto start = Named<uint64_t>(event, L"MethodStartAddress");
        if (!start && action == ClrMethodAction::Ignore) return;
        const auto opcode = h.EventDescriptor.Opcode;
        ClrMethodAction expected = ClrMethodAction::Ignore;
        switch (opcode)
        {
        case 33: case 37: expected = ClrMethodAction::Load; ++n.Load; break;
        case 34: case 38: expected = ClrMethodAction::Unload; ++n.Unload; break;
        case 35: case 36: case 39: case 40: expected = ClrMethodAction::Rundown; ++n.Rundown; break;
        }
        if (expected == ClrMethodAction::Rundown)
        {
            if (IsEqualGUID(h.ProviderId, kClrRuntime)) ++n.LegacyRundown;
            else if (opcode == 35 || opcode == 36) ++n.CompactRundown;
        }
        const auto flags = Named<uint32_t>(event, L"MethodFlags");
        if (flags.value_or(0) & 8) ++n.Jitted;
        if (h.EventDescriptor.Version < n.Versions.size()) ++n.Versions[h.EventDescriptor.Version];
        if (action != expected ||
            range.Start != start || range.Size != Named<uint32_t>(event, L"MethodSize") ||
            range.MethodId != Named<uint64_t>(event, L"MethodID") || range.ModuleId != Named<uint64_t>(event, L"ModuleID") ||
            range.MethodToken != Named<uint32_t>(event, L"MethodToken") || range.MethodFlags != flags ||
            range.RuntimeInstance != Named<uint16_t>(event, L"ClrInstanceID") || range.ReJitId != Named<uint64_t>(event, L"ReJITID"))
        {
            if (++n.Mismatch <= 4)
            {
                std::fprintf(stderr, "mismatch id=%u version=%u task=%u opcode=%u length=%u\n",
                    h.EventDescriptor.Id, h.EventDescriptor.Version, h.EventDescriptor.Task, opcode, event->UserDataLength);
            }
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (!BoundaryControls()) return 1;
    if (argc == 1)
    {
        std::puts("CLR method descriptor and payload controls passed");
        return 0;
    }
    if (argc != 3) return 2;
    std::wstring countArg(argv[2]);
    if (countArg.empty() || countArg.find_first_not_of(L"0123456789") != std::wstring::npos) return 2;
    Counts counts;
    EVENT_TRACE_LOGFILEW file{};
    file.LogFileName = argv[1];
    file.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    file.EventRecordCallback = Compare;
    file.Context = &counts;
    TRACEHANDLE trace = OpenTraceW(&file);
    if (trace == INVALID_PROCESSTRACE_HANDLE) return 1;
    const ULONG processed = ProcessTrace(&trace, 1, nullptr, nullptr);
    const ULONG closed = CloseTrace(trace);
    std::printf("load=%llu unload=%llu rundown=%llu jit_flag=%llu v0=%llu v1=%llu v2=%llu mismatches=%llu\n",
        counts.Load, counts.Unload, counts.Rundown, counts.Jitted, counts.Versions[0], counts.Versions[1], counts.Versions[2], counts.Mismatch);
    std::printf("records=%llu compact_rundown=%llu legacy_rundown=%llu\n", counts.Records, counts.CompactRundown, counts.LegacyRundown);
    return processed == ERROR_SUCCESS && closed == ERROR_SUCCESS && counts.Records != 0 && counts.Mismatch == 0 &&
        std::to_wstring(counts.Load + counts.Unload + counts.Rundown) == countArg ? 0 : 1;
}
