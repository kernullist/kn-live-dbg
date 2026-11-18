#include "DeviceClient.h"
#include "TimelineStore.h"
#include <combaseapi.h>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>

namespace
{
    using namespace timeline_callbacks;
    constexpr uint32_t Denied = 0xc0000022u;
    constexpr uint32_t Busy = 0x80000011u;
    constexpr uint32_t All = Registered | Active;

    bool Check(bool condition, const wchar_t* label)
    {
        if (!condition) { std::wcerr << L"[callback.ownership] failed " << label << L"\n"; }
        return condition;
    }

    bool RequestBoundary()
    {
        constexpr uint32_t invalid = 0xc000000du, tooSmall = 0xc0000023u;
        constexpr uint32_t base = sizeof(KNDBG_TIMELINE_CONTROL_REQUEST), full = sizeof(KNDBG_TIMELINE_CONTROL_RECEIPT);
        KNDBG_TIMELINE_RECEIPT_REQUEST input{{sizeof(input), KNDBG_TIMELINE_CONTROL_START,
            KNDBG_TIMELINE_CONTROL_WANT_RECEIPT, 4096, KNDBG_WRITE_ACK_MAGIC}, full, KNDBG_TIMELINE_CONTROL_RECEIPT_VERSION, 73};
        auto check = [&](const void* data, uint32_t in, uint32_t out, bool writable, uint32_t expected, bool extended) {
            KNDBG_TIMELINE_CONTROL_RECEIPT receipt{};
            bool detailed = false;
            const auto code = Prepare(data, in, out, writable, receipt, detailed);
            return code == expected && detailed == extended && (!extended || (receipt.RequestId == 73 && receipt.Size == full));
        };
        if (!check(nullptr, 0, full, true, invalid, false) || !check(&input, sizeof(input) - 1, full, true, invalid, false) ||
            !check(&input, sizeof(input), full - 1, true, tooSmall, false) || !check(&input, sizeof(input), full, false, Denied, false) ||
            !check(&input, sizeof(input), full, true, 0, true)) { return false; }
        auto wrong = input;
        wrong.Request.Acknowledge = 0;
        if (!check(&wrong, sizeof(wrong), full, true, Denied, false)) { return false; }
        wrong = input; wrong.Version++;
        if (!check(&wrong, sizeof(wrong), full, true, invalid, false)) { return false; }
        wrong = input; wrong.ReceiptSize--;
        if (!check(&wrong, sizeof(wrong), full, true, invalid, false)) { return false; }
        wrong = input; wrong.RequestId = 0;
        if (!check(&wrong, sizeof(wrong), full, true, invalid, false)) { return false; }
        input.Request.Flags = 0;
        if (!check(&input, sizeof(input), full, true, 0, false)) { return false; } // Legacy padded input.
        input.Request.Size = base;
        return check(&input, base, full, true, 0, false) && check(&input, base, base, true, 0, false) &&
            check(&input, base, base - 1, true, tooSmall, false) && check(&input, base, base, false, Denied, false);
    }

    bool InFlightRemoval()
    {
        using namespace std::chrono_literals;
        std::promise<void> entered, release, exited, removing;
        auto started = entered.get_future(), allowed = release.get_future(), finished = exited.get_future(), stopping = removing.get_future();
        std::atomic<uint32_t> mask{All};
        std::atomic<bool> stopReturned{false};
        bool callbackTimedOut = false;
        std::thread callback([&] {
            entered.set_value();
            callbackTimedOut = allowed.wait_for(10s) != std::future_status::ready;
            exited.set_value();
        });
        const bool observed = started.wait_for(5s) == std::future_status::ready;
        std::thread controller([&] {
            KNDBG_TIMELINE_CONTROL_RECEIPT r{};
            r.AfterFlags = All;
            auto call = [&](uint32_t flag, bool, uint64_t& requested, uint64_t& returned) -> uint32_t {
                requested = 1;
                returned = 2;
                if (flag == Thread)
                {
                    removing.set_value();
                    if (finished.wait_for(10s) != std::future_status::ready) { return Busy; }
                }
                return 0;
            };
            auto publish = [&](uint32_t flags) { mask.store(flags); };
            Stop(r, call, publish);
            stopReturned.store(true);
        });
        const bool overlapping = stopping.wait_for(5s) == std::future_status::ready && mask.load() == Registered && !stopReturned.load();
        release.set_value();
        callback.join();
        controller.join();
        return observed && overlapping && !callbackTimedOut && stopReturned.load() && !mask.load();
    }

    // The host script supplies the ordered OS results independently of the
    // state machine. Check the published delivery gate at every remove call.
    bool Transition(bool start, uint32_t before, std::initializer_list<KNDBG_TIMELINE_CALLBACK_CALL> script,
        uint32_t result, uint32_t after, KNDBG_TIMELINE_CONTROL_RECEIPT* output)
    {
        KNDBG_TIMELINE_CONTROL_RECEIPT r{};
        r.Version = KNDBG_TIMELINE_CONTROL_RECEIPT_VERSION;
        r.Size = sizeof(r);
        r.BeforeFlags = r.AfterFlags = before;
        auto next = script.begin();
        bool matched = true;
        uint32_t published = before;
        auto call = [&](uint32_t flag, bool remove, uint64_t& requested, uint64_t& returned) {
            if (next == script.end()) { matched = false; return Unsuccessful; }
            requested = 133000000000000000ull + static_cast<uint64_t>(next - script.begin()) * 10;
            returned = requested + 5;
            auto step = *next++;
            if (step.CallbackFlag != flag || step.Remove != static_cast<uint32_t>(remove) ||
                (published & Active) || static_cast<bool>(published & flag) != remove) { matched = false; }
            return step.NtStatus;
        };
        auto publish = [&](uint32_t flags) { published = flags; };
        r.OperationStatus = start ? Start(r, call, publish) : Stop(r, call, publish);
        if (!matched || next != script.end() || published != after || r.AfterFlags != after ||
            r.OperationStatus != result || r.CallCount != script.size()) { return false; }
        size_t i = 0;
        for (auto step : script)
        {
            const auto& actual = r.Calls[i++];
            if (actual.CallbackFlag != step.CallbackFlag || actual.Remove != step.Remove || actual.NtStatus != step.NtStatus) { return false; }
        }
        if (output) { *output = r; }
        return true;
    }

    bool PipeControl()
    {
        GUID guid{};
        wchar_t text[40]{};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, text, 40)) { return false; }
        const std::wstring name = L"\\\\.\\pipe\\KnLiveDbg-CallbackReceipt-" + std::wstring(text);
        auto createServer = [&name]() {
            return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 1024, 0, nullptr);
        };
        struct ClosePipe { HANDLE Value; ~ClosePipe() { if (Value != INVALID_HANDLE_VALUE) { CloseHandle(Value); } } };
        ClosePipe server{createServer()};
        if (server.Value == INVALID_HANDLE_VALUE) { std::wcerr << L"test pipe creation returned " << GetLastError() << L"\n"; return false; }
        DeviceClient client;
        std::wstring error;
        auto& journal = GetTimelineControlJournal();
        const auto before = journal.Snapshot().Total;
        if (client.ControlTimeline(KNDBG_TIMELINE_CONTROL_CLEAR, 0, &error) || journal.Snapshot().Total != before) { return false; }
        if (!client.Open(name, &error)) { std::wcerr << L"test pipe open: " << error << L"\n"; return false; }
        const auto epoch = client.ObservationEpoch();
        if (client.ControlTimeline(KNDBG_TIMELINE_CONTROL_CLEAR, 0, &error))
        { std::wcerr << L"test pipe unexpectedly acknowledged timeline control\n"; return false; }
        client.Close();
        const auto snap = journal.Snapshot();
        if (snap.Total != before + 1 || snap.Actions.empty()) { std::wcerr << L"test pipe control receipt missing\n"; return false; }
        const auto& row = snap.Actions.back();
        const bool ok = epoch && row.DeviceEpoch == epoch && row.RequestedUtc && row.ReturnedUtc &&
            row.Reply == TimelineControlReply::TransportFailure && row.Win32Status != ERROR_SUCCESS &&
            error.find(std::to_wstring(row.Win32Status)) != std::wstring::npos;
        if (!ok) { std::wcerr << L"test pipe epoch=" << epoch << L" observed=" << row.DeviceEpoch << L" Win32=" << row.Win32Status << L" " << error << L"\n"; return false; }
        if (!CloseHandle(server.Value)) { return false; }
        server.Value = createServer();
        if (server.Value == INVALID_HANDLE_VALUE) { std::wcerr << L"test pipe replacement returned " << GetLastError() << L"\n"; return false; }
        if (!client.Open(name, &error) || client.ObservationEpoch() == epoch) { std::wcerr << L"test pipe reopen: " << error << L"\n"; return false; }
        const TimelineControlLease stale{epoch, 1};
        const bool rejected = !client.ControlTimeline(KNDBG_TIMELINE_CONTROL_STOP, 0, &error, nullptr, &stale) &&
            error.find(L"rollback no longer owns") != std::wstring::npos && journal.Snapshot().Total == snap.Total;
        client.Close();
        return rejected;
    }
}

bool TimelineCallbackOwnershipSelfTest(bool native)
{
    if (native) { return Check(PipeControl(), L"native owned pipe transport error"); }
    if (!Check(RequestBoundary(), L"write gate, acknowledgment, sizes and legacy request") ||
        !Check(InFlightRemoval(), L"delivery off while an observed callback is in flight")) { return false; }
    KNDBG_TIMELINE_CONTROL_RECEIPT start{}, failed{}, stop{};
    if (!Check(Transition(true, 0, {{Process,0,0},{Image,0,0},{Thread,0,0}}, 0, All, &start) &&
        Transition(true, All, {}, 0, All, nullptr) && Transition(false, 0, {}, 0, 0, nullptr), L"start and idempotence")) { return false; }
    if (!Check(Transition(false, All, {{Thread,1,ProcedureNotFound},{Process,1,ProcedureNotFound},{Image,1,0}},
        ProcedureNotFound, Process, nullptr) &&
        Transition(true, Process, {{Process,1,Denied}}, Denied, Process, nullptr) &&
        Transition(false, Process, {{Process,1,0}}, 0, 0, &stop), L"per-API absence and residual-only retry")) { return false; }
    if (!Check(Transition(true, Registered,
        {{Thread,1,0},{Process,1,0},{Image,1,0},{Process,0,0},{Image,0,0},{Thread,0,Denied},{Process,1,Busy},{Image,1,0}},
        Denied, Process, &failed) && failed.CallCount == KNDBG_TIMELINE_MAX_CALLBACK_CALLS &&
        Transition(true, 0, {{Process,0,0x103}}, Unsuccessful, 0, nullptr),
        L"original failure, rollback failure and maximum attempts")) { return false; }

    TimelineControlJournal journal;
    uint32_t sends = 0;
    bool correctSizes = true;
    auto submit = [&](uint32_t action, bool detailed, KNDBG_TIMELINE_CONTROL_RECEIPT body, DWORD returned, DWORD win32,
                      bool wrongEcho = false, bool staleId = false,
                      TimelineControlLease* acquired = nullptr, const TimelineControlLease* expected = nullptr, uint64_t epoch = 7) {
        std::wstring error;
        return journal.Submit(action, action == KNDBG_TIMELINE_CONTROL_START ? 128u : 0u, epoch, detailed,
            [&](KNDBG_TIMELINE_CONTROL_RECEIPT* buffer, DWORD in, DWORD out, DWORD* bytes, DWORD* raw, std::wstring*) {
                ++sends;
                correctSizes &= in == (detailed ? sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST) : sizeof(buffer->Request)) &&
                    (out == (detailed ? sizeof(*buffer) : sizeof(buffer->Request))) &&
                    buffer->Request.Acknowledge == KNDBG_WRITE_ACK_MAGIC && buffer->Request.Flags == (detailed ? 1u : 0u);
                KNDBG_TIMELINE_CONTROL_RECEIPT envelope{};
                bool negotiated = false;
                correctSizes &= Prepare(buffer, in, out, true, envelope, negotiated) == 0 && negotiated == detailed;
                body.Request = envelope.Request;
                body.RequestId = envelope.RequestId;
                if (staleId) { --body.RequestId; }
                if (wrongEcho) { ++body.Request.Action; }
                *buffer = body;
                *bytes = returned;
                *raw = win32;
                return win32 == ERROR_SUCCESS;
            }, &error, acquired, expected);
    };
    constexpr auto startAction = KNDBG_TIMELINE_CONTROL_START, stopAction = KNDBG_TIMELINE_CONTROL_STOP;
    for (unsigned i = 0; i < 70; ++i)
    {
        if (submit(startAction, true, {}, 0, ERROR_ACCESS_DENIED)) { return false; }
    }
    TimelineStore timeline;
    const auto old = journal.Snapshot();
    const auto first = timeline.IngestLiveObserverActions(old);
    if (!Check(first.Added == 64 && first.Warnings.size() == 1 && first.Warnings[0].find(L"6 ") == 0 &&
        !timeline.IngestLiveObserverActions(old).Added, L"retention, loss and stable cursor")) { return false; }
    constexpr DWORD full = sizeof(KNDBG_TIMELINE_CONTROL_RECEIPT), legacy = sizeof(KNDBG_TIMELINE_CONTROL_REQUEST);
    if (!submit(startAction, true, start, full, 0) || submit(startAction, true, failed, full, 0) ||
        !submit(stopAction, true, stop, full, 0) || !submit(startAction, false, {}, legacy, 0)) { return false; }
    const auto recorded = timeline.IngestLiveObserverActions(journal.Snapshot());
    const auto rows = timeline.AllEvents();
    if (recorded.Added != 4 || rows.size() != 68 || timeline.IngestLiveObserverActions(old).Added) { return false; }
    const auto& failure = rows[65];
    if (!Check(failure.Source == L"observer" && failure.Domain == L"observer_action" && failure.TargetProcessId == 0 &&
        failure.Risk == L"info" && failure.Evidence.at(L"outcome") == L"failed" && failure.Evidence.at(L"status") == L"0xc0000022" &&
        failure.Evidence.at(L"after_flags") == L"0x2" && failure.Evidence.at(L"callback_calls") == L"8" &&
        failure.Evidence.at(L"call.7.ntstatus") == L"0x80000011" && failure.Evidence.at(L"effect_verified") == L"false" &&
        rows.back().Evidence.at(L"outcome") == L"legacy_acknowledged" && !rows.back().Evidence.count(L"after_flags"),
        L"timeline distinguishes transport, operation, rollback and legacy evidence")) { return false; }
    auto corrupted = start;
    corrupted.CallCount = KNDBG_TIMELINE_MAX_CALLBACK_CALLS + 1;
    if (submit(startAction, true, corrupted, full, 0) || submit(startAction, true, start, legacy, 0) ||
        submit(startAction, false, {}, legacy - 1, 0) || submit(startAction, true, start, full, 0, true) ||
        submit(startAction, true, start, full, 0, false, true)) { return false; }
    corrupted = start;
    corrupted.Calls[1].Remove = 1;
    if (submit(startAction, true, corrupted, full, 0)) { return false; }
    corrupted = stop;
    corrupted.AfterFlags = Process;
    if (submit(stopAction, true, corrupted, full, 0)) { return false; }
    if (!Check(timeline.IngestLiveObserverActions(journal.Snapshot()).Added == 7 && correctSizes && sends == 81,
        L"malformed receipts cause one dispatch and no replay")) { return false; }
    const auto malformed = timeline.AllEvents().back();
    if (malformed.Evidence.at(L"outcome") != L"outcome_unconfirmed" || malformed.Evidence.count(L"callback_calls")) { return false; }
    if (timeline.IngestEvents({failure}).Added != 1 || timeline.AllEvents().back().Evidence.at(L"ingest_origin") != L"supplied_record") { return false; }
    timeline.Clear();
    if (timeline.IngestLiveObserverActions(journal.Snapshot()).Added != 64) { return false; }
    TimelineControlLease own, replacement, oldDriver;
    if (!submit(startAction, true, start, full, 0, false, false, &own) || !own.RequestId ||
        !submit(startAction, true, start, full, 0, false, false, &replacement) || own.RequestId == replacement.RequestId) { return false; }
    const uint32_t beforeRejections = sends;
    if (submit(stopAction, true, stop, full, 0, false, false, nullptr, &own) ||
        submit(stopAction, true, stop, full, 0, false, false, nullptr, &replacement, 8) || sends != beforeRejections ||
        !submit(stopAction, true, stop, full, 0, false, false, nullptr, &replacement) ||
        submit(stopAction, true, stop, full, 0, false, false, nullptr, &replacement) ||
        !submit(startAction, false, {}, legacy, 0, false, false, &oldDriver) || !oldDriver.DeviceEpoch || oldDriver.RequestId ||
        submit(stopAction, false, {}, legacy, 0, false, false, nullptr, &oldDriver) || sends != beforeRejections + 2) { return false; }
    auto existing = start;
    existing.BeforeFlags = existing.AfterFlags = All;
    existing.CallCount = 0;
    TimelineControlLease adopted;
    if (!submit(startAction, true, existing, full, 0, false, false, &adopted) || !adopted.DeviceEpoch || adopted.RequestId ||
        submit(stopAction, true, stop, full, 0, false, false, nullptr, &adopted) || sends != beforeRejections + 3) { return false; }
    if (submit(stopAction, true, stop, 16, ERROR_MORE_DATA)) { return false; }
    timeline.IngestLiveObserverActions(journal.Snapshot());
    const auto partial = timeline.AllEvents().back();
    if (partial.Evidence.at(L"returned_bytes") != L"16" || partial.Evidence.at(L"win32_status") != std::to_wstring(ERROR_MORE_DATA) ||
        partial.Evidence.at(L"outcome") != L"transport_failed" || partial.Evidence.count(L"callback_calls")) { return false; }
    std::wcout << L"[callback.fixture.receipt] " << TimelineEventToJson(failure) << L"\n";
    std::wcout << L"[callback.ownership] registration, failed rollback, retry, legacy and malformed receipts passed\n";
    return true;
}
