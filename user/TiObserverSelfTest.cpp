#include "ThreatIntelSubscriber.h"
#include "TimelineStore.h"

#include <iostream>
#include <combaseapi.h>
#include <rpc.h>
#include <condition_variable>
#include <chrono>
#include <future>

namespace
{
    struct StopOverlap
    {
        std::mutex Mutex;
        std::condition_variable Changed;
        bool Entered = false;
        bool SecondAttempted = false;
    };

    struct Fixture
    {
        TRACEHANDLE Handle = 73;
        GUID Guid{};
        ULONG StartStatus = ERROR_ALREADY_EXISTS;
        ULONG EnableStatus = ERROR_ACCESS_DENIED;
        ULONG QueryStatus = ERROR_SUCCESS;
        ULONG StopStatus = ERROR_SUCCESS;
        ULONG CloseStatus = ERROR_SUCCESS;
        ULONG Starts = 0, Enables = 0, Queries = 0, Stops = 0;
        bool WrongGuid = false, WrongCall = false;
        bool Native = false, UseExistingGuid = false;
        StopOverlap* Overlap = nullptr;
        std::wstring Name;
    };
    thread_local Fixture* current;
    constexpr ULONG PrivateMode = EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC | EVENT_TRACE_BUFFERING_MODE;

    ULONG WINAPI StartFixture(PTRACEHANDLE out, LPCWSTR name, PEVENT_TRACE_PROPERTIES properties)
    {
        auto& f = *current;
        ++f.Starts;
        if (!name || std::wstring(name) != L"KnLiveDbg-Ti") { f.WrongCall = true; return ERROR_INVALID_PARAMETER; }
        if (f.Native)
        {
            struct { EVENT_TRACE_PROPERTIES Props; wchar_t Logger[1025]; } buffer{};
            buffer.Props = *properties;
            buffer.Props.Wnode.BufferSize = sizeof(buffer);
            buffer.Props.LogFileMode = PrivateMode;
            if (f.UseExistingGuid) { buffer.Props.Wnode.Guid = f.Guid; }
            const ULONG code = StartTraceW(out, f.Name.c_str(), &buffer.Props);
            if (code == ERROR_SUCCESS) { f.Handle = *out; f.Guid = buffer.Props.Wnode.Guid; }
            return code;
        }
        f.Guid = properties->Wnode.Guid;
        // Failed API output is intentionally nonzero. A caller cannot acquire it.
        *out = f.StartStatus == ERROR_SUCCESS ? f.Handle : 999;
        return f.StartStatus;
    }

    ULONG WINAPI EnableFixture(TRACEHANDLE handle, LPCGUID, ULONG code, UCHAR, ULONGLONG, ULONGLONG,
        ULONG, PENABLE_TRACE_PARAMETERS)
    {
        auto& f = *current;
        if (handle != f.Handle || code != EVENT_CONTROL_CODE_ENABLE_PROVIDER) { f.WrongCall = true; }
        ++f.Enables;
        return f.EnableStatus;
    }

    TRACEHANDLE WINAPI FailOpen(PEVENT_TRACE_LOGFILEW)
    {
        SetLastError(ERROR_INVALID_DATA);
        return INVALID_PROCESSTRACE_HANDLE;
    }

    constexpr TRACEHANDLE FixtureConsumer = 101;

    ULONG WINAPI CloseFixture(TRACEHANDLE handle)
    {
        if (handle != FixtureConsumer) { current->WrongCall = true; return ERROR_INVALID_HANDLE; }
        return current->CloseStatus;
    }

    ULONG WINAPI ControlFixture(TRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES props, ULONG code)
    {
        auto& f = *current;
        if (!handle || handle != f.Handle || name || (code != EVENT_TRACE_CONTROL_QUERY && code != EVENT_TRACE_CONTROL_STOP))
        {
            f.WrongCall = true;
            return ERROR_INVALID_PARAMETER;
        }
        if (code == EVENT_TRACE_CONTROL_QUERY) { ++f.Queries; }
        else { ++f.Stops; }
        if (code == EVENT_TRACE_CONTROL_STOP)
        {
            if (f.Overlap)
            {
                auto& barrier = *f.Overlap;
                std::unique_lock<std::mutex> lock(barrier.Mutex);
                barrier.Entered = true;
                barrier.Changed.notify_all();
                if (!barrier.Changed.wait_for(lock, std::chrono::seconds(5), [&] { return barrier.SecondAttempted; }))
                { return ERROR_TIMEOUT; }
            }
            if (!f.Native || f.StopStatus != ERROR_SUCCESS) { return f.StopStatus; }
        }
        if (f.Native)
        {
            props->LogFileMode = PrivateMode;
            return ControlTraceW(handle, nullptr, props, code);
        }
        props->Wnode.Guid = f.Guid;
        if (f.WrongGuid) { props->Wnode.Guid.Data1 ^= 1; }
        return f.QueryStatus;
    }

    // The sentinel owns an in-process buffered test logger. It enables no
    // provider and always releases by the handle returned by its own start.
    struct Sentinel
    {
        struct Buffer { EVENT_TRACE_PROPERTIES Properties; wchar_t Logger[1025]; wchar_t File[1025]; };
        TRACEHANDLE Handle = 0;
        GUID Guid{};
        ULONG Start(const std::wstring& name)
        {
            auto b = Properties();
            TRACEHANDLE created = 0;
            const ULONG status = StartTraceW(&created, name.c_str(), &b.Properties);
            if (status == ERROR_SUCCESS) { Handle = created; }
            return status;
        }
        Buffer Properties() const
        {
            Buffer b{};
            b.Properties.Wnode.BufferSize = sizeof(b);
            b.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            b.Properties.Wnode.Guid = Guid;
            b.Properties.LogFileMode = PrivateMode;
            b.Properties.LoggerNameOffset = offsetof(Buffer, Logger);
            return b;
        }
        ULONG Control(ULONG code)
        {
            auto b = Properties();
            b.Properties.LogFileNameOffset = offsetof(Buffer, File);
            const auto status = ControlTraceW(Handle, nullptr, &b.Properties, code);
            if (code == EVENT_TRACE_CONTROL_STOP && (status == ERROR_SUCCESS || status == ERROR_MORE_DATA ||
                status == ERROR_WMI_INSTANCE_NOT_FOUND)) { Handle = 0; }
            if (code == EVENT_TRACE_CONTROL_QUERY && status == ERROR_SUCCESS && !IsEqualGUID(b.Properties.Wnode.Guid, Guid))
            { return ERROR_INVALID_DATA; }
            return status;
        }
        ~Sentinel() { if (Handle) { Control(EVENT_TRACE_CONTROL_STOP); } }
    };
}

bool TiObserverOwnershipSelfTest(bool native)
{
    Fixture f;
    current = &f;
    struct Reset { ~Reset() { current = nullptr; } } reset;
    auto setup = [](TiSubscriber& sub)
    {
        sub.StartSession = StartFixture;
        sub.EnableProvider = EnableFixture;
        sub.OpenConsumer = FailOpen;
        sub.CloseConsumer = CloseFixture;
        sub.ControlSession = ControlFixture;
    };
    TiOptions options;
    std::wstring error;
    if (native)
    {
        Sentinel sentinel;
        const auto uuid = UuidCreate(&sentinel.Guid);
        if (uuid != RPC_S_OK && uuid != RPC_S_UUID_LOCAL_ONLY) { return false; }
        wchar_t guid[40]{};
        if (!StringFromGUID2(sentinel.Guid, guid, 40)) { return false; }
        f.Name = L"KnLiveDbg-ObserverTest-" + std::wstring(guid);
        f.Native = true;
        f.Guid = sentinel.Guid;
        const auto created = sentinel.Start(f.Name);
        if (created != ERROR_SUCCESS) { std::wcerr << L"private ETW sentinel start returned " << created << L"\n"; return false; }
        const auto queried = sentinel.Control(EVENT_TRACE_CONTROL_QUERY);
        if (queried != ERROR_SUCCESS) { std::wcerr << L"private ETW sentinel query returned " << queried << L"\n"; return false; }
        f.UseExistingGuid = true;
        {
            TiSubscriber contender;
            setup(contender);
            if (contender.Start(options, &error) || contender.HasTraceResources() || !contender.Stop(&error)) { return false; }
            const auto actions = contender.ObserverActions();
            if (actions.Total != 1 || actions.Actions.front().Status != ERROR_ALREADY_EXISTS)
            { std::wcerr << L"private ETW collision returned " << contender.SnapshotStats().Trace.StartStatus << L"\n"; return false; }
        }
        if (f.Starts != 1 || f.Enables || f.Queries || f.Stops || sentinel.Control(EVENT_TRACE_CONTROL_QUERY) != ERROR_SUCCESS) { return false; }
        if (sentinel.Control(EVENT_TRACE_CONTROL_STOP) != ERROR_SUCCESS) { return false; }
        f.UseExistingGuid = false;
        {
            TiSubscriber owner;
            setup(owner);
            if (owner.Start(options, &error) || owner.HasTraceResources() || f.Queries != 1 || f.Stops != 1) {
                std::wcerr << L"private ETW owner rollback: " << error << L"\n"; return false;
            }
            TimelineStore timeline;
            if (timeline.IngestTiObserverActions(owner.ObserverActions()).Added != 4) { return false; }
            for (const auto& row : timeline.AllEvents())
            {
                std::wcout << L"[ti.fixture.receipt] " << TimelineEventToJson(row) << L"\n";
            }
        }
        // Reacquire the same private name after rollback, proving release with
        // another native start rather than the subscriber's internal counters.
        sentinel.Guid = f.Guid;
        if (sentinel.Start(f.Name) != ERROR_SUCCESS) { return false; }
        if (sentinel.Control(EVENT_TRACE_CONTROL_STOP) != ERROR_SUCCESS || f.WrongCall) { return false; }

        // Keep the original controller alive while a second controller stops
        // the test logger through its captured handle and replaces the name.
        ULONG stopsBeforeRetry = 0;
        {
            TiSubscriber stale;
            setup(stale);
            f.StopStatus = ERROR_ACCESS_DENIED;
            if (stale.Start(options, &error) || !stale.HasTraceResources()) { return false; }
            sentinel.Handle = f.Handle;
            sentinel.Guid = f.Guid;
            if (sentinel.Control(EVENT_TRACE_CONTROL_STOP) != ERROR_SUCCESS) { return false; }
            const auto replaced = UuidCreate(&sentinel.Guid);
            if (replaced != RPC_S_OK && replaced != RPC_S_UUID_LOCAL_ONLY) { return false; }
            if (sentinel.Start(f.Name) != ERROR_SUCCESS) { return false; }
            stopsBeforeRetry = f.Stops;
            f.StopStatus = ERROR_SUCCESS;
            stale.Stop(&error);
        }
        const auto survivorStatus = sentinel.Control(EVENT_TRACE_CONTROL_QUERY);
        if (survivorStatus != ERROR_SUCCESS || f.Stops != stopsBeforeRetry || f.WrongCall)
        { std::wcerr << L"replacement survival query=" << survivorStatus << L" stop attempts=" << f.Stops - stopsBeforeRetry << L"\n"; return false; }
        if (sentinel.Control(EVENT_TRACE_CONTROL_STOP) != ERROR_SUCCESS) { return false; }
        std::wcout << L"[ti.ownership] native private ETW collision preserved, owned rollback released, name reacquired, replacement survived\n";
        return true;
    }

    TiSubscriber sub;
    setup(sub);
    for (size_t i = 0; i < 80; ++i)
    {
        if (sub.Start(options, &error) || sub.HasTraceResources() || !sub.Stop(&error)) { return false; }
    }
    auto collisions = sub.ObserverActions();
    if (f.Starts != 80 || f.Enables || f.Queries || f.Stops || collisions.Total != 80 || collisions.Actions.size() != 64) { return false; }
    TimelineStore timeline;
    const auto ingest = timeline.IngestTiObserverActions(collisions);
    if (ingest.Added != 64 || ingest.Warnings.size() != 1 || ingest.Warnings.front().find(L"16 ") != 0 ||
        timeline.IngestTiObserverActions(collisions).Added) { return false; }
    const auto events = timeline.AllEvents();
    for (size_t i = 0; i < events.size(); ++i)
    {
        const auto& row = events[i];
        if (row.Domain != L"observer_action" || row.Source != L"observer" || row.Action != L"etw.session.start" ||
            row.ProcessId != GetCurrentProcessId() || row.TargetProcessId || !row.TimestampFileTime ||
            row.Risk != L"info" || row.Confidence != L"controller_reported" ||
            row.Evidence.at(L"controller_create_time") == L"0" || row.Evidence.at(L"requested_utc_filetime") == L"0" ||
            row.Evidence.at(L"returned_utc_filetime") != std::to_wstring(row.TimestampFileTime) ||
            row.Evidence.at(L"sequence") != std::to_wstring(i + 17) || row.Evidence.at(L"outcome") != L"collision" ||
            row.Evidence.at(L"effect_verified") != L"false" || row.Evidence.at(L"ingest_origin") != L"local_controller" ||
            row.Evidence.at(L"status") != std::to_wstring(ERROR_ALREADY_EXISTS)) { return false; }
    }
    if (timeline.IngestEvents({events.front()}).Added != 1 ||
        timeline.AllEvents().back().Evidence.at(L"ingest_origin") != L"supplied_record") { return false; }
    auto supplied = events.front();
    supplied.Source = L"OBSERVER";
    supplied.Evidence.emplace(L"Ingest-Origin", L"local_controller");
    if (timeline.IngestEvents({supplied}).Added != 1) { return false; }
    const auto imported = timeline.AllEvents().back();
    if (imported.Evidence.count(L"Ingest-Origin") || imported.Evidence.at(L"ingest_origin") != L"supplied_record") { return false; }
    f.StartStatus = ERROR_SUCCESS;
    f.StopStatus = ERROR_ACCESS_DENIED;
    if (sub.Start(options, &error) || !sub.HasTraceResources() || error.find(L"cleanup") == std::wstring::npos ||
        sub.Start(options, &error) || f.Starts != 81 || f.Enables != 1 || f.Stops != 2) { return false; }
    f.StopStatus = ERROR_MORE_DATA;
    if (!sub.Stop(&error) || sub.HasTraceResources() || !sub.Stop(&error) || f.Stops != 3) { return false; }
    if (timeline.IngestTiObserverActions(sub.ObserverActions()).Added != 8 || timeline.IngestTiObserverActions(collisions).Added) { return false; }
    const auto settlement = timeline.AllEvents().back();
    if (settlement.Evidence.at(L"outcome") != L"stopped_properties_truncated") { return false; }

    f.QueryStatus = ERROR_MORE_DATA;
    if (sub.Start(options, &error) || !sub.HasTraceResources() || f.Stops != 3) { return false; }
    f.QueryStatus = ERROR_SUCCESS;
    f.WrongGuid = true;
    if (sub.Stop(&error) || sub.HasTraceResources() || f.Stops != 3 || !sub.ObserverActions().Actions.back().IdentityMismatch) { return false; }
    f.WrongGuid = false;
    f.EnableStatus = ERROR_SUCCESS;
    f.StopStatus = ERROR_ACTIVE_CONNECTIONS;
    if (sub.Start(options, &error) || sub.SnapshotStats().Trace.StartStatus != ERROR_INVALID_DATA || !sub.HasTraceResources()) { return false; }
    f.QueryStatus = ERROR_WMI_INSTANCE_NOT_FOUND;
    if (!sub.Stop(&error) || sub.HasTraceResources() || f.Stops != 4) { return false; }
    timeline.Clear();
    if (timeline.IngestTiObserverActions(sub.ObserverActions()).Added != 64 || f.WrongCall) { return false; }

    f.QueryStatus = ERROR_SUCCESS;
    f.EnableStatus = ERROR_ACCESS_DENIED;
    f.StopStatus = ERROR_ACCESS_DENIED;
    if (sub.Start(options, &error) || !sub.HasTraceResources()) { return false; }
    const auto stopsBeforeOverlap = f.Stops;
    f.StopStatus = ERROR_SUCCESS;
    StopOverlap overlap;
    f.Overlap = &overlap;
    bool firstReleased = false;
    std::thread first([&] {
        current = &f;
        firstReleased = sub.Stop(nullptr);
        current = nullptr;
    });
    bool observed;
    {
        std::unique_lock<std::mutex> lock(overlap.Mutex);
        observed = overlap.Changed.wait_for(lock, std::chrono::seconds(5), [&] { return overlap.Entered; });
        overlap.SecondAttempted = true;
        overlap.Changed.notify_all();
    }
    const bool secondReleased = sub.Stop(nullptr);
    first.join();
    f.Overlap = nullptr;
    if (!observed || !firstReleased || !secondReleased || sub.HasTraceResources() || f.Stops != stopsBeforeOverlap + 1) { return false; }

    sub.ProcessHandle = FixtureConsumer;
    std::promise<void> entered, finish;
    auto ready = entered.get_future();
    auto finished = finish.get_future();
    bool timedOut = false;
    sub.TraceLifecycle.ThreadRunning = true;
    sub.ProcessThread = std::thread([&] {
        entered.set_value();
        timedOut = finished.wait_for(std::chrono::seconds(5)) != std::future_status::ready;
        std::lock_guard<std::mutex> lock(sub.TraceMutex);
        sub.TraceLifecycle.ThreadRunning = false;
    });
    ready.wait();
    f.CloseStatus = ERROR_ACCESS_DENIED;
    const bool pending = !sub.Stop(&error) && sub.HasTraceResources() &&
        error.find(L"CloseTrace returned 5") != std::wstring::npos;
    f.CloseStatus = ERROR_CTX_CLOSE_PENDING;
    finish.set_value();
    const bool settled = sub.Stop(&error);
    if (!pending || !settled || sub.HasTraceResources() || timedOut || f.WrongCall) { return false; }
    timeline.IngestTiObserverActions(sub.ObserverActions());
    const auto closed = timeline.AllEvents().back();
    if (closed.Action != L"etw.consumer.close" || closed.Evidence.at(L"outcome") != L"close_pending" ||
        closed.Evidence.at(L"status") != std::to_wstring(ERROR_CTX_CLOSE_PENDING)) { return false; }
    std::wcout << L"[ti.ownership] collision, settlement, overlapping stops, stale handle and observer history passed\n";
    return true;
}
