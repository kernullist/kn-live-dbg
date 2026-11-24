// The saved-file controls below feed constructed boundary records to the evaluator in memory.
// Only the collector's real marker is written to the private ETL.
#include "../user/EtlImageLifetime.cpp"
#include "../user/ProcessImageCapture.h"
#include <objbase.h>
#include <iostream>
#include <stdexcept>

namespace
{
    void Require(bool condition, const char* message) { if (!condition) { throw std::runtime_error(message); } }
    struct Properties
    {
        EVENT_TRACE_PROPERTIES Value{};
        wchar_t Name[1025]{}, File[1025]{};
        Properties()
        {
            Value.Wnode.BufferSize = sizeof(*this);
            Value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            Value.Wnode.ClientContext = 1;
            Value.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC;
            Value.LoggerNameOffset = offsetof(Properties, Name);
            Value.LogFileNameOffset = offsetof(Properties, File);
        }
    };
    int PrivateCapture(const wchar_t* path, const wchar_t* session, const std::vector<std::wstring>& args)
    {
        Properties open, close;
        if (wcscpy_s(open.File, path) ||
            FAILED(session ? IIDFromString(session, &open.Value.Wnode.Guid) : CoCreateGuid(&open.Value.Wnode.Guid))) { return 1; }
        close.Value.Wnode.Guid = open.Value.Wnode.Guid;
        const auto name = L"KnLiveDbg-private-loader-" + std::to_wstring(GetCurrentProcessId());
        REGHANDLE registered = 0;
        if (EventRegister(&image_loader::Provider, nullptr, nullptr, &registered) != ERROR_SUCCESS) { return 1; }
        TRACEHANDLE trace = 0;
        ULONG status = StartTraceW(&trace, name.c_str(), &open.Value);
        int result = 1;
        if (status == ERROR_SUCCESS)
        {
            status = EnableTraceEx2(trace, &image_loader::Provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, 5, 1, 0, 5000, nullptr);
            if (!status)
            {
                try { result = RunProcessImageCaptureCommand(args); }
                catch (...) { result = 1; }
            }
            const auto stop = ControlTraceW(trace, nullptr, &close.Value, EVENT_TRACE_CONTROL_STOP);
            if (stop != ERROR_SUCCESS) { status = stop; }
        }
        EventUnregister(registered);
        if (status) { std::cerr << "private trace status " << status << '\n'; }
        return status == ERROR_SUCCESS ? result : 1;
    }
    struct Row
    {
        int64_t Tick;
        GUID ProviderId;
        uint16_t Id;
        uint8_t Version;
        uint32_t HeaderPid;
        std::vector<uint8_t> Bytes;
        uint8_t Level = image_loader::Completed.Level;
    };
    template<class T> void Append(std::vector<uint8_t>& dest, T value)
    {
        const auto* data = reinterpret_cast<const uint8_t*>(&value);
        dest.insert(dest.end(), data, data + sizeof(value));
    }
    Row ProcessRow(int64_t tick, bool start, const Identity& identity)
    {
        Row r{tick, KernelProcess, static_cast<uint16_t>(start ? 1 : 2), static_cast<uint8_t>(start ? 5 : 2), 4, {}};
        Append(r.Bytes, identity.Pid); Append(r.Bytes, uint64_t{17}); Append(r.Bytes, identity.Birth);
        return r;
    }
    Row ImageRow(int64_t tick, bool load, const Scan& s)
    {
        Row r{tick, KernelProcess, static_cast<uint16_t>(load ? 5 : 6), 0, 4, {}};
        Append(r.Bytes, s.Recipe.ImageBase); Append(r.Bytes, uint64_t{0x100000});
        Append(r.Bytes, s.Target.Pid); Append(r.Bytes, uint32_t{17}); Append(r.Bytes, uint32_t{20});
        Append(r.Bytes, s.Recipe.ImageBase);
        for (const wchar_t unit : L"owned.dll") { Append(r.Bytes, unit); }
        return r;
    }

    void Controls(const wchar_t* etl, const wchar_t* capture, const std::wstring& pin)
    {
        DirectImageReplayEvidence evidence;
        const auto replay = ReplayImageRecipe(capture, false, nullptr, &evidence);
        Require(replay.Status == L"replayed" && replay.RecipeSha256 == pin, "original replay or pin");
        Scan actual{evidence.Recipe, pin};
        Require(Identities(actual), "process identity");
        etl_profile::SavedEtlInput input;
        TRACE_LOGFILE_HEADER header{};
        Require(input.Open(etl) && !ReadTrace(input, actual, header) && actual.Markers == 1, "read private marker");
        Outcome missing;
        Require(std::wstring(Assess(actual, header, missing)) == L"process_generation_unavailable" && missing.ReadWindowValidated,
            "valid private marker without process boundaries");
        const auto& w = actual.Window;
        const auto finish = actual.Marker.Tick + 1'000'000;
        std::vector<Row> rows{
            ProcessRow(w.Capture.Start - 1'000'000, true, actual.Target),
            ProcessRow(w.Capture.Start - 100'000, true, actual.Collector),
            ImageRow(w.Capture.Start - 1000, true, actual), ImageRow(w.Capture.End + 1000, false, actual),
            ProcessRow(finish, false, actual.Collector), ProcessRow(finish + 1000, false, actual.Target)};
        const auto* bytes = reinterpret_cast<const uint8_t*>(&w);
        rows.push_back({actual.Marker.Tick, image_loader::Provider, 1, 1, actual.Collector.Pid,
            {bytes, bytes + offsetof(image_loader::Window, Reads) + evidence.Recipe.Reads.size() * sizeof(image_loader::Interval)}});
        const auto check = [&](std::vector<Row> selected, const wchar_t* expected, bool gap = false, bool privateMode = false) {
            Scan candidate{evidence.Recipe, pin};
            Require(Identities(candidate), "candidate identity");
            std::stable_sort(selected.begin(), selected.end(), [](const Row& a, const Row& b) { return a.Tick < b.Tick; });
            for (const auto& row : selected)
            {
                EVENT_RECORD event{};
                event.EventHeader.ProviderId = row.ProviderId;
                event.EventHeader.ProcessId = row.HeaderPid;
                event.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
                event.EventHeader.TimeStamp.QuadPart = row.Tick;
                event.EventHeader.EventDescriptor.Id = row.Id;
                event.EventHeader.EventDescriptor.Version = row.Version;
                event.EventHeader.EventDescriptor.Level = row.Level;
                event.EventHeader.EventDescriptor.Keyword = IsEqualGUID(row.ProviderId, image_loader::Provider) ? 1 : 0;
                event.UserData = const_cast<uint8_t*>(row.Bytes.data());
                event.UserDataLength = static_cast<USHORT>(row.Bytes.size());
                event.BufferContext.LoggerId = actual.Marker.Logger;
                Observe(candidate, event);
            }
            candidate.Buffers = actual.Buffers;
            auto h = header;
            if (!privateMode) { h.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL; }
            if (gap) { ++h.EventsLost; }
            Outcome out;
            const auto issue = Assess(candidate, h, out);
            if (std::wstring(issue) != expected) { std::wcerr << expected << L" returned " << issue << L'\n'; }
            Require(std::wstring(issue) == expected, "lifetime disposition");
            Require(out.Qualified == (std::wstring(expected) == L"recorded_loader_interval"), "interval promotion");
            if (std::wstring(expected) == L"unsupported_or_malformed_record" || std::wstring(expected) == L"read_clock_conflict" || gap)
                { Require(!out.ReadWindowValidated, "invalid evidence cannot bind a read window"); }
        };
        check(rows, L"recorded_loader_interval");
        check(rows, L"kernel_events_in_private_session", false, true);
        check(rows, L"trace_coverage_gap", true);
        auto changed = rows;
        changed.erase(changed.begin() + 3);
        check(changed, L"loader_boundaries_unavailable");
        changed = rows;
        changed.push_back(rows.back());
        check(changed, L"ambiguous_capture_marker");
        changed = rows;
        changed.back().Bytes.front() ^= 1;
        check(changed, L"capture_marker_missing");
        changed = rows;
        changed.back().Level = 0;
        check(changed, L"unsupported_or_malformed_record");
        changed = rows;
        changed[4] = ProcessRow(finish, false, {actual.Collector.Pid, actual.Collector.Birth + 1});
        check(changed, L"process_generation_unavailable");
        changed = rows;
        changed.push_back(ProcessRow(w.Capture.Start + 1, true, {actual.Target.Pid, actual.Target.Birth + 1}));
        check(changed, L"process_generation_unavailable");
        changed = rows;
        changed[3].Bytes[16 + 4] ^= 1; // checksum on the unload row
        check(changed, L"conflicting_loader_transitions");
        changed = rows;
        changed[2].Version = 42;
        check(changed, L"unsupported_or_malformed_record");
        changed = rows;
        const auto& first = w.Reads.front();
        Require(first.End - first.Start > 4, "actual raw read interval");
        changed.push_back(ImageRow(first.Start + 1, false, actual));
        changed.push_back(ImageRow(first.End - 1, true, actual));
        check(changed, L"loader_transition_in_capture");
        changed = rows;
        changed[2].Tick = w.Capture.Start;
        check(changed, L"loader_boundary_coincident");
        --changed[2].Tick;
        check(changed, L"loader_boundary_coincident");
        changed = rows;
        const auto after = w.Capture.End + 100;
        std::memcpy(changed.back().Bytes.data() + offsetof(image_loader::Window, Reads), &after, sizeof(after));
        check(changed, L"read_clock_conflict");
        std::cout << "Genuine collector marker and 15 in-memory disposition controls passed.\n";
    }
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if (argc > 3 && std::wstring(argv[1]) == L"--private") { return PrivateCapture(argv[2], nullptr, {argv + 3, argv + argc}); }
        if (argc > 4 && std::wstring(argv[1]) == L"--private-session") { return PrivateCapture(argv[3], argv[2], {argv + 4, argv + argc}); }
        if (argc == 5 && std::wstring(argv[1]) == L"--controls") { Controls(argv[2], argv[3], argv[4]); return 0; }
        return 2;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
