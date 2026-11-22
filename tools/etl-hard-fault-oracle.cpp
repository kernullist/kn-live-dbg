// Test reader. Windows TDH resolves properties by their registered names.
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <bcrypt.h>
#include <objbase.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")

namespace
{
    constexpr GUID PageFault = {0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
    constexpr GUID Thread = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
    constexpr GUID Handoff = {0x4dc673b7, 0xfb3f, 0x4099, {0x95, 0x2a, 0x37, 0xda, 0xc2, 0x7c, 0xf1, 0x94}};
    struct Counts { unsigned records = 0, faults = 0; ULONG error = 0; bool scheduler = false, activities = false, payloads = false; };

    template<typename T>
    bool Property(PEVENT_RECORD e, Counts& counts, PCWSTR name, T& value)
    {
        PROPERTY_DATA_DESCRIPTOR field{};
        field.PropertyName = reinterpret_cast<ULONGLONG>(name);
        field.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        counts.error = TdhGetPropertySize(e, 0, nullptr, 1, &field, &size);
        if (!counts.error && size != sizeof(T)) { counts.error = ERROR_INVALID_DATA; }
        if (!counts.error) { counts.error = TdhGetProperty(e, 0, nullptr, 1, &field, size, reinterpret_cast<PBYTE>(&value)); }
        return counts.error == ERROR_SUCCESS;
    }

    void Scheduler(PEVENT_RECORD e, Counts& counts)
    {
        const auto& h = e->EventHeader;
        const auto op = h.EventDescriptor.Opcode, version = h.EventDescriptor.Version;
        uint32_t tid = 0, other = 0;
        if (op == 36 && version >= 2 && version <= 4)
        {
            int8_t state = 0, reason = 0;
            if (!Property(e, counts, L"NewThreadId", tid) || !Property(e, counts, L"OldThreadId", other) ||
                !Property(e, counts, L"OldThreadState", state) || !Property(e, counts, L"OldThreadWaitReason", reason)) { return; }
            std::printf("{\"new_thread_id\":%u,\"old_thread_id\":%u,\"old_state\":%d,\"old_wait_reason\":%d", tid, other, state, reason);
        }
        else if (op == 50 && version == 2)
        {
            uint8_t flags = 0;
            if (!Property(e, counts, L"TThreadId", tid) || !Property(e, counts, L"Flag", flags)) { return; }
            int8_t reason = 0, increment = 0, reserved = 0;
            if (!Property(e, counts, L"AdjustReason", reason) || !Property(e, counts, L"AdjustIncrement", increment) ||
                !Property(e, counts, L"Reserved", reserved)) { return; }
            std::printf("{\"payload_tid\":%u,\"ready_flags\":%u,\"adjust_reason\":%d,\"adjust_increment\":%d,"
                "\"reserved_field\":%d,\"header_thread_id\":%lu,\"header_process_id\":%lu,\"header_flags\":%u",
                tid, static_cast<unsigned>(flags), reason, increment, reserved, h.ThreadId, h.ProcessId, static_cast<unsigned>(h.Flags));
        }
        else if (op >= 1 && op <= 4 && version == 3)
        {
            if (!Property(e, counts, L"TThreadId", tid) || !Property(e, counts, L"ProcessId", other)) { return; }
            std::printf("{\"payload_tid\":%u,\"payload_pid\":%u", tid, other);
        }
        else { return; }
        std::printf(",\"record_ordinal\":%u,\"raw_timestamp\":\"%lld\",\"cpu\":%u,\"logger_id\":%u,\"opcode\":%u,\"version\":%u}\n",
            counts.records, h.TimeStamp.QuadPart, static_cast<unsigned>(GetEventProcessorIndex(e)),
            static_cast<unsigned>(e->BufferContext.LoggerId), static_cast<unsigned>(op), static_cast<unsigned>(version));
    }

    void WINAPI Observe(PEVENT_RECORD event)
    {
        auto& counts = *static_cast<Counts*>(event->UserContext);
        ++counts.records;
        const auto& h = event->EventHeader;
        const auto& d = h.EventDescriptor;
        if (!counts.error && counts.activities && (d.Opcode == 1 || d.Opcode == 2) &&
            !(h.Flags & (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_TRACE_MESSAGE)))
        {
            wchar_t provider[40]{}, activity[40]{};
            if (!StringFromGUID2(h.ProviderId, provider, 40) || !StringFromGUID2(h.ActivityId, activity, 40))
            { counts.error = ERROR_INVALID_DATA; return; }
            std::printf("{\"record_kind\":\"activity_boundary\",\"record_ordinal\":%u,\"raw_timestamp\":\"%lld\","
                "\"provider_guid\":\"%ls\",\"activity_id\":\"%ls\",\"event_id\":%u,\"task\":%u,\"opcode\":%u,"
                "\"version\":%u,\"channel\":%u,\"header_flags\":%u,\"event_property\":%u,\"logger_id\":%u,\"header_process_id\":%lu,\"header_thread_id\":%lu",
                counts.records, h.TimeStamp.QuadPart, provider, activity, static_cast<unsigned>(d.Id), static_cast<unsigned>(d.Task),
                static_cast<unsigned>(d.Opcode), static_cast<unsigned>(d.Version), static_cast<unsigned>(d.Channel),
                static_cast<unsigned>(h.Flags), static_cast<unsigned>(h.EventProperty), static_cast<unsigned>(event->BufferContext.LoggerId), h.ProcessId, h.ThreadId);
            if (counts.payloads)
            {
                std::printf(",\"length\":%u,\"raw\":", static_cast<unsigned>(event->UserDataLength));
                const bool scheduling = IsEqualGUID(h.ProviderId, Handoff) && d.Version == 2 && d.Channel == 0 && d.Opcode == 2 &&
                    ((d.Id == 8 && d.Task == 4) || (d.Id == 10 && d.Task == 5) || (d.Id == 19 && d.Task == 8) || (d.Id == 21 && d.Task == 9));
                if (event->UserDataLength > 1024 || (event->UserDataLength && (!event->UserData || !scheduling))) { std::printf("null"); }
                else
                {
                    std::putchar('"');
                    const auto* bytes = static_cast<const unsigned char*>(event->UserData);
                    for (unsigned i = 0; i < event->UserDataLength; ++i) { std::printf("%02x", static_cast<unsigned>(bytes[i])); }
                    std::putchar('"');
                }
            }
            std::puts("}");
            return;
        }
        if (!counts.error && counts.activities && IsEqualGUID(h.ProviderId, Thread) && d.Id == 0 && d.Opcode >= 1 && d.Opcode <= 4)
        { Scheduler(event, counts); return; }
        if (!counts.error && counts.scheduler && h.EventDescriptor.Id == 0 && IsEqualGUID(h.ProviderId, Thread))
        { Scheduler(event, counts); return; }
        if (counts.error || !IsEqualGUID(h.ProviderId, PageFault) || h.EventDescriptor.Id != 0 ||
            h.EventDescriptor.Opcode != 32 || h.EventDescriptor.Version != 2) { return; }
        constexpr PCWSTR names[] = {L"InitialTime", L"ReadOffset", L"VirtualAddress", L"FileObject", L"TThreadId", L"ByteCount"};
        std::array<BYTE, 40> payload{};
        uint64_t values[6]{};
        ULONG length = 0, pointerWidth = 0;
        for (size_t i = 0; i < std::size(names); ++i)
        {
            PROPERTY_DATA_DESCRIPTOR field{};
            field.PropertyName = reinterpret_cast<ULONGLONG>(names[i]);
            field.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            counts.error = TdhGetPropertySize(event, 0, nullptr, 1, &field, &size);
            if (counts.error) { return; }
            if (i == 2) { pointerWidth = size; }
            if ((i < 2 && size != 8) || (i == 2 && size != 4 && size != 8) ||
                (i == 3 && size != pointerWidth) || (i >= 4 && size != 4) || size > payload.size() - length)
            { counts.error = ERROR_INVALID_DATA; return; }
            counts.error = TdhGetProperty(event, 0, nullptr, 1, &field, size, payload.data() + length);
            if (counts.error) { return; }
            std::memcpy(&values[i], payload.data() + length, size);
            length += size;
        }
        ++counts.faults;
        std::printf("{\"record_ordinal\":%u,\"pointer_bytes\":%lu,\"cpu\":%u,\"header_thread_id\":%lu,"
            "\"raw_timestamp\":\"%lld\",\"initial_time_raw\":\"%llu\",\"read_offset\":\"%llu\","
            "\"faulting_thread_id\":%llu,\"byte_count\":%llu", counts.records, pointerWidth,
            static_cast<unsigned>(GetEventProcessorIndex(event)), h.ThreadId, h.TimeStamp.QuadPart, values[0],
            values[1], values[4], values[5]);
        if (counts.faults == 1)
        {
            std::array<BYTE, 32> hash{};
            if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, payload.data(), length, hash.data(),
                           static_cast<ULONG>(hash.size())) < 0) { counts.error = ERROR_INVALID_DATA; return; }
            std::printf(",\"first_payload_sha256\":\"");
            for (auto b : hash) { std::printf("%02x", b); }
            std::putchar('"');
        }
        std::puts("}");
    }
}

int wmain(int argc, wchar_t** argv)
{
    const bool payloads = argc == 3 && std::wcscmp(argv[2], L"--marker-data") == 0;
    if ((argc != 2 && (argc != 3 || (!payloads && std::wcscmp(argv[2], L"--scheduler") != 0 && std::wcscmp(argv[2], L"--activities") != 0))) ||
        GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_PIPE) { return 2; }
    Counts counts;
    counts.scheduler = argc == 3 && std::wcscmp(argv[2], L"--scheduler") == 0;
    counts.payloads = payloads;
    counts.activities = payloads || (argc == 3 && std::wcscmp(argv[2], L"--activities") == 0);
    EVENT_TRACE_LOGFILEW log{};
    log.LogFileName = argv[1];
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.Context = &counts;
    log.EventRecordCallback = Observe;
    auto trace = OpenTraceW(&log);
    if (trace == INVALID_PROCESSTRACE_HANDLE) { return 1; }
    auto rc = ProcessTrace(&trace, 1, nullptr, nullptr);
    CloseTrace(trace);
    if (rc != ERROR_SUCCESS || counts.error)
    { std::fprintf(stderr, "Windows ETW status %lu, TDH status %lu\n", rc, counts.error); return 1; }
    std::printf("{\"records_seen\":%u,\"decoded_hard_faults\":%u,\"clock_type\":%lu,\"frequency\":%lld}\n",
        counts.records, counts.faults, log.LogfileHeader.ReservedFlags, log.LogfileHeader.PerfFreq.QuadPart);
    return std::ferror(stdout) ? 1 : 0;
}
