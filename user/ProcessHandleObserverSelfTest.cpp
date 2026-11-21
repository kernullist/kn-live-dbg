#include "KernelMonitor.h"
#include "DeviceClient.h"
#include "HandleTableScanner.h"
#include "ProcessObservationSource.h"
#include "ProcessLayoutMonitor.h"
#include "ProcessLoggingObservation.h"
#include "TimelineSelfTest.h"
#include "TimelineStore.h"

#include <chrono>
#include <condition_variable>
#include <future>
#include <iostream>
#include <objbase.h>
#include <sstream>

namespace
{
    bool OwnershipAndErrors(bool emit)
    {
        ProcessHandleJournal journal;
        const auto self = ReadProcessHandleIdentity(GetCurrentProcess());
        if (!self.Pid || !self.Created) { return false; }
        {
            ObservedProcessHandle bad(journal, ProcessHandleSite::IdentityLookup, 0);
            if (bad.Open(PROCESS_QUERY_LIMITED_INFORMATION)) { return false; }
            const DWORD error = GetLastError();
            if (error != ERROR_INVALID_PARAMETER || bad.Acquisition().Status != error || bad.Acquisition().AcquisitionId) { return false; }
        }
        {
            ObservedProcessHandle bad(journal, ProcessHandleSite::ObservationSource, self.Pid, self.Created);
            if (bad.Duplicate(nullptr)) { return false; }
            const DWORD error = GetLastError();
            if (!error || bad.Acquisition().Status != error || bad.Acquisition().Bound.Pid) { return false; }
        }
        {
            ObservedProcessHandle original(journal, ProcessHandleSite::IdentityLookup, self.Pid);
            if (!original.Open(PROCESS_QUERY_LIMITED_INFORMATION)) { return false; }
            {
                ProcessObservationSource mismatch(original.get(), self.Pid, self.Created + 1, {}, journal, original.Acquisition().AcquisitionId);
                if (!mismatch.Capabilities().SourceId.empty()) { return false; }
            }
            if (GetProcessId(original.get()) != self.Pid) { return false; }
            ProcessHandleJournal mismatchJournal;
            const DWORD otherPid = self.Pid == 1 ? 2 : 1;
            {
                ProcessObservationSource wrongPid(original.get(), otherPid, self.Created, {}, mismatchJournal);
                if (!wrongPid.Capabilities().SourceId.empty()) { return false; }
            }
            const auto binding = mismatchJournal.Snapshot();
            if (binding.Acquired != 1 || binding.Closed != 1 || binding.Actions.size() != 2 ||
                binding.Actions[0].Bound.Pid != self.Pid || binding.Actions[0].Bound.Created) { return false; }
            if (emit)
            {
                TimelineStore mismatches;
                mismatches.IngestProcessHandleActions(binding);
                for (const auto& row : mismatches.AllEvents()) { std::wcout << L"[handle.pid-mismatch] " << TimelineEventToJson(row) << L"\n"; }
            }
        }
        {
            std::unique_ptr<void, decltype(&CloseHandle)> event(CreateEventW(nullptr, TRUE, FALSE, nullptr), &CloseHandle);
            if (!event) { return false; }
            {
                ProcessObservationSource wrongType(event.get(), self.Pid, self.Created, {}, journal);
                if (!wrongType.Capabilities().SourceId.empty()) { return false; }
            }
            if (!SetEvent(event.get()) || WaitForSingleObject(event.get(), 0) != WAIT_OBJECT_0) { return false; }
        }
        // Protect only a disposable handle owned by this test. After recording the
        // failed close, the fixture removes that flag and releases its reference.
        HANDLE protectedHandle = nullptr;
        {
            ObservedProcessHandle owner(journal, ProcessHandleSite::IdentityLookup, self.Pid);
            if (!owner.Open(PROCESS_QUERY_LIMITED_INFORMATION) ||
                !SetHandleInformation(owner.get(), HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)) { return false; }
            protectedHandle = owner.get();
        }
        DWORD flags = 0;
        const bool stillOwned = GetHandleInformation(protectedHandle, &flags) && (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE);
        if (!SetHandleInformation(protectedHandle, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0) || !CloseHandle(protectedHandle)) { return false; }
        const auto snap = journal.Snapshot();
        if (!stillOwned || snap.Total != 10 || snap.Acquired != 4 || snap.Closed != 3) { return false; }
        const auto& last = snap.Actions.back();
        if (last.Call != ProcessHandleCall::Close || last.Succeeded || !last.Status || last.AcquisitionId != 9) { return false; }
        TimelineStore timeline;
        if (timeline.IngestProcessHandleActions(snap).Added != 10 || timeline.IngestProcessHandleActions(snap).SourceRecords) { return false; }
        const auto rows = timeline.AllEvents();
        if (rows.size() != 10 || rows[3].Evidence.at(L"observed_create_time") != std::to_wstring(self.Created) ||
            rows[3].Evidence.at(L"requested_create_time") != std::to_wstring(self.Created + 1) ||
            rows[6].Evidence.at(L"outcome") != L"succeeded" || rows[6].Evidence.at(L"identity_win32_status") == L"0" ||
            rows[6].Evidence.count(L"observed_create_time") || rows.back().Evidence.at(L"outcome") != L"failed") { return false; }
        SnapshotDocument empty;
        TimelineReconcileOptions observer;
        observer.Source = L"OBSERVER";
        if (!timeline.ReconcileSnapshot(empty, {}).Findings.empty() || !timeline.ReconcileSnapshot(empty, observer).Findings.empty() ||
            !timeline.AnalyzeLiveSignals(16).Findings.empty()) { return false; }
        SnapshotDocument snapshot;
        SnapshotRecord record;
        record.Domain = L"process";
        record.Risk = L"high";
        record.Evidence = {{L"pid", std::to_wstring(self.Pid)}, {L"image", L"snapshot-only.exe"}};
        snapshot.Records.push_back(record);
        const auto absent = timeline.ReconcileSnapshot(snapshot, {});
        if (absent.Findings.size() != 1 || absent.Findings.front().Kind != L"snapshot-record-without-event" ||
            !timeline.ReconcileSnapshot(snapshot, observer).Findings.empty()) { return false; }
        TimelineStore imported;
        if (imported.IngestEvents(rows).Added != rows.size() || imported.AllEvents()[0].Evidence.at(L"ingest_origin") != L"supplied_record" ||
            !imported.ReconcileSnapshot(empty, {}).Findings.empty()) { return false; }
        TimelineEvent target;
        target.Source = L"live"; target.Domain = L"process"; target.Action = L"process-create"; target.ProcessId = self.Pid;
        if (timeline.IngestEvents({target}).Added != 1 || timeline.ReconcileSnapshot(empty, {}).Findings.size() != 1) { return false; }
        target.Entity = L"target-fixture.exe";
        auto supplied = rows.front();
        supplied.Evidence[L"image"] = L"observer-fixture.exe";
        TimelineEvent thread;
        thread.Source = L"live"; thread.Domain = L"thread"; thread.Action = L"thread-create"; thread.ProcessId = self.Pid;
        auto suppliedThread = thread;
        suppliedThread.Source = L"OBSERVER";
        TimelineStore context;
        if (context.IngestEvents({target, supplied, suppliedThread, thread}).Added != 4) { return false; }
        const auto related = context.AllEvents();
        if (related[2].Evidence.count(L"process_image_context") ||
            related[3].Evidence.at(L"process_image_context") != target.Entity)
        {
            std::wcerr << L"Controller image supplied target thread context\n";
            return false;
        }
        if (emit) { for (const auto& row : rows) { std::wcout << L"[handle.fixture] " << TimelineEventToJson(row) << L"\n"; } }
        return true;
    }

    bool ConcurrentRetention()
    {
        using namespace std::chrono_literals;
        ProcessHandleJournal journal;
        const DWORD pid = GetCurrentProcessId();
        std::array<std::promise<bool>, 4> ready;
        std::array<std::future<bool>, 4> workers;
        std::promise<void> release;
        const auto proceed = release.get_future().share();
        for (size_t i = 0; i < workers.size(); ++i)
        {
            workers[i] = std::async(std::launch::async, [&, i] {
                {
                    ObservedProcessHandle owned(journal, ProcessHandleSite::IdentityLookup, pid);
                    const bool opened = owned.Open(PROCESS_QUERY_LIMITED_INFORMATION);
                    ready[i].set_value(opened);
                    if (!opened || proceed.wait_for(10s) != std::future_status::ready) { return false; }
                }
                for (unsigned n = 0; n < 20; ++n)
                {
                    ObservedProcessHandle owned(journal, ProcessHandleSite::IdentityLookup, pid);
                    if (!owned.Open(PROCESS_QUERY_LIMITED_INFORMATION)) { return false; }
                }
                return true;
            });
        }
        bool passed = true;
        for (auto& signal : ready)
        {
            auto observed = signal.get_future();
            if (observed.wait_for(5s) != std::future_status::ready || !observed.get()) { passed = false; }
        }
        const auto held = journal.Snapshot();
        release.set_value();
        for (auto& worker : workers) { if (!worker.get()) { passed = false; } }
        const auto final = journal.Snapshot();
        if (!passed || held.Acquired != 4 || held.Closed || final.Total != 168 || final.Acquired != 84 || final.Closed != 84 ||
            final.Actions.size() != 64 || final.Actions.front().Sequence != 105 || final.Actions.back().Sequence != 168) { return false; }
        TimelineStore store;
        const auto gap = store.IngestProcessHandleActions(final);
        if (gap.Added != 64 || gap.Warnings.size() != 1 || gap.Warnings[0].find(L"104 ") != 0 ||
            store.IngestProcessHandleActions(held).Added || store.IngestProcessHandleActions(final).Added) { return false; }
        store.Clear();
        return store.IngestProcessHandleActions(final).Added == 64;
    }
}

bool ProcessHandleObserverSelfTest(bool emit)
{
    if (!OwnershipAndErrors(emit) || !ConcurrentRetention()) { return false; }
    if (emit) { std::wcout << L"[handle.ownership] calls=10 acquired=4 successful_closes=3 fixture_cleanup=passed concurrent_calls=168 retained=64\n"; }
    return true;
}

bool LayoutProcessHandleFixture()
{
    const auto release = [](void* page) { VirtualFree(page, 0, MEM_RELEASE); };
    const std::unique_ptr<void, decltype(release)> guard(
        VirtualAlloc(nullptr, 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD), release);
    if (!guard) { return false; }
    const auto command = [](const wchar_t* expected) {
        std::wstring line;
        return std::getline(std::wcin, line) && line == expected;
    };
    // Keep the page allocated while the parent samples each protection change.
    std::wcout << L"[layout.guard] " << reinterpret_cast<uintptr_t>(guard.get()) << std::endl;
    if (!command(L"collect")) { return false; }
    ProcessLayoutMonitor monitor;
    monitor.Reset();
    ProcessLayoutScope self;
    self.All = false;
    self.Pids.insert(GetCurrentProcessId());
    std::atomic<bool> stop{false};
    TimelineStore timeline;
    std::wstring status;
    const auto deadline = GetTickCount64() + 10000;
    while (status.empty() && GetTickCount64() < deadline)
    {
        monitor.Tick(self, stop, [&](const ProcessLayoutNotice& item) {
            status = item.Status;
            return true;
        }, [](ProcessLayoutCandidate) { return true; });
        if (!timeline.IngestProcessHandleActions(ControllerProcessHandles().Snapshot()).Warnings.empty()) { return false; }
    }
    const auto stats = monitor.Stats();
    if (status.empty() || stats.Completed + stats.Failed != 1) { return false; }
    std::wcout << L"[layout.collect] completed=" << stats.Completed << L" failed=" << stats.Failed
        << L" rows=" << stats.StoredRows << L" status=" << status << std::endl;
    DWORD previous = 0;
    if (!command(L"clear") || !VirtualProtect(guard.get(), 1, PAGE_READWRITE, &previous) ||
        previous != (PAGE_READWRITE | PAGE_GUARD)) { return false; }
    std::wcout << L"[layout.control] cleared" << std::endl;
    if (!command(L"finish")) { return false; }
    for (const auto& row : timeline.AllEvents()) { std::wcout << L"[layout.handle] " << TimelineEventToJson(row) << L"\n"; }
    return true;
}

bool CollectorProcessHandleFixture(uintptr_t inherited, bool retention)
{
    const auto target = reinterpret_cast<HANDLE>(inherited);
    DWORD flags = 0;
    if (!GetHandleInformation(target, &flags) || !(flags & HANDLE_FLAG_INHERIT)) { return false; }
    const auto identity = ReadProcessHandleIdentity(target);
    if (!identity.Created || identity.Pid <= 4 || identity.Pid == GetCurrentProcessId()) { return false; }
    const std::unique_ptr<void, decltype(&CloseHandle)> reference(target, &CloseHandle);
    std::wstring image(32768, L'\0');
    DWORD size = static_cast<DWORD>(image.size());
    if (QueryFullProcessImageNameW(target, 0, image.data(), &size)) { image.resize(size); }
    else { image.clear(); }
    const auto leaf = image.substr(image.find_last_of(L"\\/") + 1);
    TiSubscriber ti;
    if (!ti.ResolveImageBasename(0).empty() || ti.ResolveImageBasename(4) != L"system") { return false; }
    if (retention)
    {
        if (leaf.empty()) { return false; }
        for (unsigned i = 0; i < 40; ++i)
        {
            if (_wcsicmp(ti.ResolveImageBasename(identity.Pid).c_str(), leaf.c_str()) != 0) { return false; }
        }
        return true;
    }
    for (int i = 0; i < 2; ++i)
    {
        const auto actual = ti.ResolveImageBasename(identity.Pid);
        std::wcout << L"[collector.ti] image=" << !actual.empty()
            << L" matches=" << (!actual.empty() && _wcsicmp(actual.c_str(), leaf.c_str()) == 0) << L"\n";
    }
    ReportKmonInventoryHandleFixture(identity.Pid, image, std::wcout);
    ReportHuntMetadataHandleFixture(identity.Pid, identity.Created, image, std::wcout);
    return true;
}

bool KmonWatchMaintenanceSelfTest(HANDLE exitedProcess, std::wstring& diagnostics)
{
    const DWORD pid = GetCurrentProcessId();
    const auto self = ReadProcessHandleIdentity(GetCurrentProcess(), pid);
    const auto exited = ReadProcessHandleIdentity(exitedProcess);
    DWORD exitCode = 0;
    if (!self.Created || !exited.Created || exited.Pid <= 4 || exited.Pid == pid ||
        !GetExitCodeProcess(exitedProcess, &exitCode) || exitCode == STILL_ACTIVE) { return false; }
    // All control cases target this controller. Require an independent Windows denial before seeding any ledger.
    ProcessHandleJournal calibration;
    ObservedProcessHandle denied(calibration, ProcessHandleSite::LoggingControl, pid);
    if (denied.Open(PROCESS_SET_INFORMATION) || denied.Acquisition().Status != ERROR_ACCESS_DENIED) { return false; }

    std::wostringstream result;
    bool valid = true;
    const auto run = [&](const wchar_t* name, auto exercise) {
        KernelMonitor monitor;
        const uint64_t before = ControllerProcessHandles().Snapshot().Total;
        exercise(monitor);
        std::wstring decision = L"none", outcome = L"none", enableDecision = L"none";
        uint64_t decisionGeneration = 0, acquisition = 0;
        std::vector<uint64_t> heldAcquisitions;
        size_t receipts = 0;
        for (const auto& event : monitor.Ring)
        {
            const auto found = event.Evidence.find(L"cleanup_decision");
            const auto enable = event.Evidence.find(L"enable_decision");
            const auto retry = event.Evidence.find(L"retry_decision");
            if (retry != event.Evidence.end())
            {
                valid = valid && retry->second == L"held_unconfirmed" &&
                    event.Observation.Identity.CreateTime == self.Created && event.Evidence.at(L"effect_verified") == L"false";
                heldAcquisitions.push_back(std::stoull(event.Evidence.at(L"identity_acquisition_id")));
            }
            if (enable != event.Evidence.end()) { enableDecision = enable->second; }
            if (found == event.Evidence.end() && enable == event.Evidence.end()) { continue; }
            valid = valid && event.Observation.Identity.ProcessId == pid && event.Evidence.at(L"effect_verified") == L"false";
            if (found != event.Evidence.end())
            {
                ++receipts;
                decision = found->second;
                outcome = event.Evidence.at(L"control_outcome");
                decisionGeneration = event.Observation.Identity.CreateTime;
                const auto id = event.Evidence.find(L"identity_acquisition_id");
                if (id != event.Evidence.end()) { acquisition = std::stoull(id->second); }
            }
        }
        result << L"[watch.case] name=" << name << L" before=" << before << L" after=" << ControllerProcessHandles().Snapshot().Total
            << L" watched=" << monitor.WatchPids.size() << L" promoted=" << monitor.WatchPromotedPids.size()
            << L" enabled=" << monitor.LoggingEnabledPids.size() << L" enabled_count=" << monitor.LoggingEnabledCount.load()
            << L" failed=" << monitor.LoggingFailedPids.size() << L" decision=" << decision << L" receipts=" << receipts
            << L" outcome=" << outcome << L" generation=" << decisionGeneration << L" acquisition=" << acquisition
            << L" enable_decision=" << enableDecision << L" held_ids=";
        for (size_t i = 0; i < heldAcquisitions.size(); ++i) { result << (i ? L"," : L"") << heldAcquisitions[i]; }
        result << L"\n";
        monitor.Active.store(false);
        monitor.LoggingEnabledPids.clear(); // Artificial entries must not dispatch during the fixture destructor.
        monitor.LoggingEnabledCount.store(0);
    };
    const auto promote = [&](KernelMonitor& monitor, uint64_t created) {
        monitor.WatchPids.insert(pid);
        monitor.WatchPromotedPids.insert(pid);
        monitor.WatchPromotedCreated[pid] = created;
    };
    const auto priorEnable = [&](KernelMonitor& monitor, uint64_t created) {
        monitor.LoggingEnabledPids[pid] = created;
        monitor.LoggingEnabledCount.store(1);
    };
    run(L"unowned", [&](KernelMonitor& monitor) {
        promote(monitor, self.Created);
        monitor.PruneStalePromotedWatches();
    });
    run(L"failed_only", [&](KernelMonitor& monitor) {
        promote(monitor, self.Created);
        monitor.LoggingFailedPids[pid] = {self.Created, false};
        monitor.PruneStalePromotedWatches();
    });
    run(L"withdrawn_current", [&](KernelMonitor& monitor) {
        promote(monitor, self.Created);
        priorEnable(monitor, self.Created);
        monitor.PruneStalePromotedWatches();
    });
    run(L"explicit_overlap", [&](KernelMonitor& monitor) {
        promote(monitor, self.Created);
        monitor.WatchExplicitPids.insert(pid);
        priorEnable(monitor, self.Created);
        monitor.PruneStalePromotedWatches();
    });
    run(L"mixed_logging", [&](KernelMonitor& monitor) {
        monitor.WatchPids.insert(pid);
        monitor.WatchExplicitPids.insert(pid);
        priorEnable(monitor, self.Created);
        monitor.LoggingFailedPids[pid] = {self.Created + 1, false};
        monitor.PruneStalePromotedWatches();
    });
    run(L"missing_logging", [&](KernelMonitor& monitor) {
        constexpr uint32_t missing = UINT32_MAX;
        monitor.WatchPids.insert(missing);
        monitor.WatchExplicitPids.insert(missing);
        monitor.LoggingFailedPids[missing] = {};
        monitor.PruneStalePromotedWatches();
    });
    run(L"child_only", [&](KernelMonitor& monitor) {
        promote(monitor, self.Created);
        monitor.WatchChildPids[pid] = pid;
        monitor.PruneStalePromotedWatches();
    });
    for (bool stale : {false, true})
    {
        run(stale ? L"overlap_stale" : L"overlap_current", [&](KernelMonitor& monitor) {
            monitor.WatchNamesLower.push_back(L"*");
            promote(monitor, self.Created + stale);
            monitor.WatchChildPids[pid] = pid;
            priorEnable(monitor, self.Created + stale);
            monitor.PruneStalePromotedWatches();
        });
    }
    run(L"exited", [&](KernelMonitor& monitor) {
        // An exited subject is only inspected. Its explicit watch is independent of its promoted entry.
        monitor.WatchPids.insert(exited.Pid);
        monitor.WatchExplicitPids.insert(exited.Pid);
        monitor.WatchPromotedPids.insert(exited.Pid);
        monitor.WatchPromotedCreated[exited.Pid] = exited.Created;
        monitor.WatchNamesLower.push_back(L"*");
        monitor.PruneStalePromotedWatches();
    });
    for (bool stop : {false, true})
    {
        for (const uint64_t generation : {uint64_t{0}, self.Created, self.Created + 1})
        {
            std::wstring name = stop ? L"stop_" : L"remove_";
            name += !generation ? L"unknown" : generation == self.Created ? L"current" : L"stale";
            run(name.c_str(), [&](KernelMonitor& monitor) {
                monitor.WatchPids.insert(pid);
                priorEnable(monitor, generation);
                if (stop) { monitor.Stop(nullptr); }
                else { monitor.RemoveWatchPid(pid); }
            });
        }
    }
    run(L"promote", [&](KernelMonitor& monitor) { monitor.PromoteNamedWatchPid(pid); });
    const auto enqueueCreate = [&](KernelMonitor& monitor, uint32_t parent) {
        TimelineEvent event;
        event.Source = L"kernel-live";
        event.Action = L"process-create";
        event.Entity = L"owned-watch-fixture.exe";
        event.ProcessId = pid;
        event.Evidence[L"parent_pid"] = std::to_wstring(parent);
        return monitor.CollectedLive.Push(std::move(event));
    };
    run(L"event_name", [&](KernelMonitor& monitor) {
        monitor.WatchNamesLower.push_back(L"owned-watch-fixture.exe");
        valid = enqueueCreate(monitor, 0) && valid;
        monitor.IngestLiveTimeline(1, 5000);
    });
    run(L"event_child", [&](KernelMonitor& monitor) {
        monitor.WatchPids.insert(exited.Pid);
        valid = enqueueCreate(monitor, exited.Pid) && valid;
        monitor.IngestLiveTimeline(1, 5000);
        valid = valid && monitor.WatchChildPids.count(pid) && monitor.WatchChildPids.at(pid) == exited.Pid;
    });
    run(L"withdraw_during_event", [&](KernelMonitor& monitor) {
        monitor.WatchNamesLower.push_back(L"owned-watch-fixture.exe");
        valid = enqueueCreate(monitor, 0) && valid;
        std::unique_lock<std::mutex> hold(monitor.LoggingControlMutex);
        std::thread ingest([&] { monitor.IngestLiveTimeline(1, 5000); });
        bool seen = false;
        const auto deadline = GetTickCount64() + 5000;
        while (!seen && GetTickCount64() < deadline)
        {
            {
                std::lock_guard<std::mutex> watchLock(monitor.WatchMutex);
                seen = monitor.RecentCreatePids.count(pid) != 0;
                if (seen) { monitor.WatchNamesLower.clear(); }
            }
            if (!seen) { std::this_thread::yield(); }
        }
        hold.unlock();
        ingest.join();
        valid = valid && seen;
    });
    run(L"remove_stop", [&](KernelMonitor& monitor) {
        monitor.WatchPids.insert(pid);
        priorEnable(monitor, self.Created);
        std::mutex mutex;
        std::condition_variable ready;
        size_t arrived = 0;
        const auto start = [&] {
            std::unique_lock<std::mutex> lock(mutex);
            ++arrived;
            ready.notify_all();
            ready.wait(lock, [&] { return arrived == 2; });
        };
        std::thread remove([&] { start(); monitor.RemoveWatchPid(pid); });
        start();
        monitor.Stop(nullptr);
        remove.join();
    });
    const auto enable = [&](KernelMonitor& monitor) {
        if (monitor.LogHandle == INVALID_HANDLE_VALUE)
        {
            monitor.LogHandle = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (monitor.LogHandle == INVALID_HANDLE_VALUE) { valid = false; return; }
        monitor.Active.store(true);
        monitor.EnableLoggingForPid(pid);
        monitor.Active.store(false);
    };
    for (bool stale : {false, true})
    {
        run(stale ? L"enable_stale" : L"enable_current", [&](KernelMonitor& monitor) {
            promote(monitor, self.Created + stale);
            enable(monitor);
        });
        run(stale ? L"held_other_generation" : L"held_current", [&](KernelMonitor& monitor) {
            promote(monitor, self.Created);
            ProcessLoggingAction earlier;
            earlier.Subject.Pid = pid;
            KNDBG_SET_PROCESS_LOGGING_RESPONSE shortReply{};
            DecodeProcessLoggingReply(earlier, true, shortReply);
            monitor.NoteLoggingFailure(pid, self.Created + stale, true, earlier.Unconfirmed());
            monitor.NoteLoggingFailure(pid, 0, false, false);
            enable(monitor);
            const auto& failure = monitor.LoggingFailedPids.at(pid);
            valid = valid && (failure.Unconfirmed ? failure.Created == self.Created + stale : stale && failure.Created == self.Created);
        });
    }
    run(L"held_withdrawn", [&](KernelMonitor& monitor) {
        monitor.WatchPids.insert(pid);
        monitor.NoteLoggingFailure(pid, self.Created, true, true);
        monitor.RemoveWatchPid(pid);
        valid = valid && monitor.LoggingFailedPids.empty();
        promote(monitor, self.Created);
        enable(monitor);
    });
    run(L"device_uncertain", [&](KernelMonitor& monitor) {
        GUID guid{};
        wchar_t token[40]{};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, token, 40)) { valid = false; return; }
        const std::wstring name = L"\\\\.\\pipe\\KnLiveDbg-LoggingReceipt-" + std::wstring(token);
        const std::wstring next = name + L"-next";
        const auto create = [](const std::wstring& path) {
            return CreateNamedPipeW(path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 1024, 0, nullptr);
        };
        struct Pipe { HANDLE Value; ~Pipe() { if (Value != INVALID_HANDLE_VALUE) { CloseHandle(Value); } } };
        Pipe server{create(name)}, replacement{create(next)};
        DeviceClient client;
        ULONG peer = 0;
        if (server.Value == INVALID_HANDLE_VALUE || replacement.Value == INVALID_HANDLE_VALUE || !client.Open(name, nullptr) ||
            !GetNamedPipeClientProcessId(server.Value, &peer) || peer != pid) { valid = false; return; }
        const auto epoch = client.ObservationEpoch();
        monitor.Device = &client;
        for (int watch = 0; watch < 2; ++watch)
        {
            valid = monitor.AddWatchPid(pid) && valid;
            enable(monitor);
            enable(monitor);
            valid = monitor.RemoveWatchPid(pid) && valid;
        }
        monitor.Device = nullptr;
        if (!client.Open(next, nullptr) || !GetNamedPipeClientProcessId(replacement.Value, &peer) || peer != pid) { valid = false; return; }
        ProcessLoggingAction stale;
        uint32_t untouched = 99;
        valid = !client.SetProcessLogging(pid, KNDBG_PROCESS_LOG_DEFAULT, &untouched, nullptr, nullptr, nullptr, nullptr, false, &stale, epoch) &&
            stale.Step == ProcessLoggingStep::DriverNotSubmitted && stale.Win32Status == ERROR_INVALID_HANDLE && !stale.ReturnedBytes &&
            !stale.Unconfirmed() && stale.ExpectedDeviceEpoch == epoch && stale.DeviceEpoch == client.ObservationEpoch() &&
            stale.DeviceEpoch != epoch && untouched == 99 && valid;
    });
    diagnostics = result.str();
    return valid;
}

bool KmonProcessLoggingSelfTest(std::wstring& diagnostics)
{
    const auto self = ReadProcessHandleIdentity(GetCurrentProcess());
    if (!self.Created || self.Pid != GetCurrentProcessId()) { return false; }

    // This disposable controller can request the normal enable only on itself. Its device stays unopened.
    KernelMonitor monitor;
    monitor.WatchPids.insert(self.Pid);
    monitor.WatchExplicitPids.insert(self.Pid);
    monitor.LogHandle = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (monitor.LogHandle == INVALID_HANDLE_VALUE) { return false; }
    monitor.Active.store(true);
    monitor.EnableLoggingForPid(self.Pid);
    const bool owned = monitor.LoggingEnabledPids.count(self.Pid) != 0;
    if (owned) { monitor.EnableLoggingForPid(self.Pid); }
    monitor.Active.store(false);
    monitor.LoggingEnabledPids.clear(); // Process exit ends the subject's lifetime.
    monitor.LoggingEnabledCount.store(0);
    std::wostringstream out;
    out << L"[logging.self] owned=" << owned << L" failed=" << monitor.LoggingFailedPids.size() << L"\n";

    // Decode fixed reply bytes in an isolated journal. No test reply reaches a device or the controller journal.
    ProcessLoggingJournal journal;
    ProcessLoggingAction row;
    row.Subject = {self.Pid, self.Created, 1};
    row.RequestedUtc = row.ReturnedUtc = TimelineControlUtc();
    row.RequestedFlags = KNDBG_PROCESS_LOG_DEFAULT;
    const auto record = [&](bool delivered, DWORD bytes, uint32_t size, uint32_t pid, uint32_t klass, uint32_t flags, uint32_t status) {
        KNDBG_SET_PROCESS_LOGGING_RESPONSE reply{};
        reply.Size = size; reply.ProcessId = pid; reply.InformationClassUsed = klass;
        reply.LoggingFlagsApplied = flags; reply.NtStatus = status;
        row.Win32Status = delivered ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
        row.ReturnedBytes = bytes;
        DecodeProcessLoggingReply(row, delivered, reply);
        journal.Record(row);
    };
    const uint32_t bytes = sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE);
    const uint32_t full = KNDBG_PROCESS_INFO_ENABLE_LOGGING, legacy = KNDBG_PROCESS_INFO_ENABLE_READWRITEVM_LOGGING;
    record(true, bytes, bytes, self.Pid, full, 63, 0);
    record(true, bytes, bytes, self.Pid, legacy, 63, 0);
    record(true, bytes, bytes, self.Pid, legacy, 3, 0);
    record(true, bytes, bytes, self.Pid, full, 63, 0xc0000022u);
    record(false, bytes, bytes, self.Pid, full, 63, 0);
    record(true, bytes - 1, bytes, self.Pid, full, 63, 0);
    record(true, bytes, bytes - 1, self.Pid, full, 63, 0);
    record(true, bytes, bytes, self.Pid + 1, full, 63, 0);
    record(true, bytes, bytes, self.Pid, full, 0, 0);
    record(true, bytes, bytes, self.Pid, legacy, 1, 0);
    record(true, bytes, bytes, self.Pid, 0, 63, 0);
    row.RequestedFlags = 0;
    record(true, bytes, bytes, self.Pid, full, 0, 0);
    record(true, bytes, bytes, self.Pid, full, 63, 0);
    row.RequestedFlags = 63;
    record(true, bytes, bytes, self.Pid, full, 63, STATUS_PENDING);
    record(true, bytes, bytes, self.Pid, full, 63, 0x102u);
    record(true, bytes, bytes, self.Pid, full, 63, 0x80000005u);
    record(true, bytes + 1, bytes, self.Pid, full, 63, 0);
    row.RequestedFlags = 32;
    record(true, bytes, bytes, self.Pid, legacy, 32, 0);
    if (row.ReportedSuccess() || !row.Unconfirmed()) { return false; }

    TimelineStore store;
    const auto early = journal.Snapshot();
    if (store.IngestProcessLoggingActions(early).Added != early.Total) { return false; }
    for (const auto& event : store.AllEvents()) { out << L"[logging.reply] " << TimelineEventToJson(event) << L"\n"; }
    for (int i = 0; i < 70; ++i) { journal.Record(row); }
    const auto late = journal.Snapshot();
    const auto gap = store.IngestProcessLoggingActions(late);
    if (gap.Added != 64 || gap.Warnings.size() != 1 || gap.Warnings[0] != L"6 process logging observer actions evicted before ingest" ||
        store.IngestProcessLoggingActions(early).SourceRecords || store.IngestProcessLoggingActions(late).SourceRecords) { return false; }
    store.Clear();
    if (store.IngestProcessLoggingActions(late).Added != 64) { return false; }

    DeviceClient closed;
    ProcessLoggingAction missing;
    uint32_t untouched = 99;
    if (closed.SetProcessLogging(self.Pid, 0, &untouched, nullptr, nullptr, nullptr, nullptr, false, &missing) ||
        missing.Unconfirmed() || missing.Step != ProcessLoggingStep::DriverNotSubmitted || missing.Win32Status != ERROR_INVALID_HANDLE ||
        missing.ReturnedBytes || missing.RequestedFlags != KNDBG_PROCESS_LOG_DEFAULT || untouched != 99) { return false; }
    if (closed.SetProcessLogging(0, 0, nullptr, nullptr, nullptr, nullptr, nullptr, false, &missing) ||
        missing.Step != ProcessLoggingStep::DriverNotSubmitted || missing.Win32Status != ERROR_INVALID_PARAMETER) { return false; }

    ProcessLoggingJournal native;
    for (uint32_t status : {0u, static_cast<uint32_t>(STATUS_PENDING), 0x40000000u, 0x80000005u, 0xc0000022u})
    {
        row.Step = ProcessLoggingStep::NativeReturned;
        row.RequestedFlags = 63; row.InformationClass = legacy; row.CallFlags = 3; row.NtStatus = status;
        native.Record(row);
    }
    store.Clear();
    if (store.IngestProcessLoggingActions(native.Snapshot()).Added != 5) { return false; }
    for (const auto& event : store.AllEvents()) { out << L"[logging.native-model] " << TimelineEventToJson(event) << L"\n"; }
    diagnostics = out.str();
    return true;
}

bool KmonHandleScanObserverSelfTest(HANDLE subjectProcess, std::wstring& diagnostics)
{
    const auto self = ReadProcessHandleIdentity(GetCurrentProcess());
    const auto subject = ReadProcessHandleIdentity(subjectProcess);
    DWORD exitCode = 0;
    if (!self.Created || !subject.Created || subject.Pid == self.Pid ||
        !GetExitCodeProcess(subjectProcess, &exitCode) || exitCode != STILL_ACTIVE) { return false; }
    std::wostringstream out;
    const auto run = [&](const wchar_t* name, DWORD pid, auto exercise) {
        KernelMonitor monitor;
        const auto before = ControllerProcessHandles().Snapshot().Total;
        exercise(monitor);
        const auto it = monitor.HandleWatches.find(pid);
        const auto* state = it == monitor.HandleWatches.end() ? nullptr : it->second.get();
        out << L"[scan.case] name=" << name << L" before=" << before << L" after=" << ControllerProcessHandles().Snapshot().Total
            << L" generation=" << (state ? state->Files.Generation : 0) << L" graph_after=" << (state ? state->GraphAfter : 0) << L"\n";
        for (const auto& event : monitor.Ring)
        {
            const auto field = [&](const wchar_t* key) {
                const auto found = event.Evidence.find(key);
                return found == event.Evidence.end() ? std::wstring(L"-") : found->second;
            };
            out << L"[scan.event] name=" << name << L" pid=" << event.Observation.Identity.ProcessId
                << L" created=" << event.Observation.Identity.CreateTime << L" state=" << field(L"state")
                << L" diagnostic=" << field(L"diagnostic_key") << L" snapshot=" << field(L"snapshot_generation")
                << L" before=" << field(L"snapshot_before_acquisition_id") << L" after=" << field(L"snapshot_after_acquisition_id")
                << L" graph=" << field(L"owner_acquisition_id") << L" controller=" << field(L"controller_pid")
                << L" controller_created=" << field(L"controller_create_time") << L" baseline="
                << (field(L"notes").find(L"first_owner_scan=1") != std::wstring::npos) << L"\n";
        }
    };
    const auto files = [](KernelMonitor& m, DWORD pid, const std::vector<NativeHandleEntry>& entries) {
        auto owner = m.BeginHandleScan(pid);
        if (owner.Watch && m.ObserveFileScanOwner(owner, false, nullptr, nullptr, owner.BeforeAcquisition))
        {
            m.FinishWatchedFileSnapshot(owner, entries, {}, nullptr, nullptr);
        }
    };
    const auto graph = [](KernelMonitor& m, DWORD pid, const HandleTableScanResult& result, const std::wstring* error) {
        auto owner = m.BeginHandleScan(pid);
        if (!owner.Watch) { return; }
        ObservedProcessHandle pin(ControllerProcessHandles(), ProcessHandleSite::HandleGraphOwner, pid, owner.Identity.CreateTime);
        if (m.PinHandleGraphOwner(owner, pin)) { m.FinishWatchedHandleGraph(owner, pin, result, error); }
    };
    const auto promote = [](KernelMonitor& m, DWORD pid, uint64_t created) {
        m.WatchPids.insert(pid);
        m.WatchPromotedPids.insert(pid);
        if (created) { m.WatchPromotedCreated[pid] = created; }
    };
    // These records have no live objects or device. Windows only supplies the owner's process handle.
    HandleTableScanResult complete;
    complete.CoverageComplete = complete.ObjectTypeCoverageComplete = complete.RelationshipCoverageComplete = true;
    complete.NextHandleAfter = 8;
    HandleTableRecord record;
    record.OwnerPid = self.Pid;
    record.TypeName = L"IoCompletion";
    record.GrantedAccess = 1;
    record.HandleValue = 4;
    complete.Records.push_back(record);
    run(L"resumed", self.Pid, [&](KernelMonitor& m) {
        m.AddWatchPid(self.Pid);
        std::vector<NativeHandleEntry> entries(129);
        for (size_t i = 0; i < entries.size(); ++i) { entries[i].HandleValue = 4 * (i + 1); }
        files(m, self.Pid, entries);
        files(m, self.Pid, entries);
        entries.pop_back();
        files(m, self.Pid, entries);
        const std::wstring failure = L"fixture snapshot unavailable";
        graph(m, self.Pid, complete, &failure);
        graph(m, self.Pid, complete, nullptr);
        auto partial = complete;
        partial.CoverageComplete = false;
        partial.NextHandleAfter = 12;
        partial.Records.front().HandleValue = 8;
        graph(m, self.Pid, partial, nullptr);
    });
    const auto both = [&](KernelMonitor& m, DWORD pid) { files(m, pid, {}); graph(m, pid, complete, nullptr); };
    run(L"promoted", self.Pid, [&](KernelMonitor& m) { promote(m, self.Pid, self.Created); both(m, self.Pid); });
    run(L"stale", self.Pid, [&](KernelMonitor& m) { promote(m, self.Pid, self.Created + 1); both(m, self.Pid); });
    run(L"unbound", self.Pid, [&](KernelMonitor& m) { promote(m, self.Pid, 0); both(m, self.Pid); });
    run(L"explicit_overlap", self.Pid, [&](KernelMonitor& m) {
        promote(m, self.Pid, self.Created + 1); m.AddWatchPid(self.Pid); both(m, self.Pid);
    });
    bool observedExit = false;
    run(L"exit_during_scan", subject.Pid, [&](KernelMonitor& m) {
        promote(m, subject.Pid, subject.Created);
        auto fileOwner = m.BeginHandleScan(subject.Pid);
        if (!m.ObserveFileScanOwner(fileOwner, false, nullptr, nullptr, fileOwner.BeforeAcquisition)) { return; }
        {
            auto graphOwner = m.BeginHandleScan(subject.Pid);
            ObservedProcessHandle pin(ControllerProcessHandles(), ProcessHandleSite::HandleGraphOwner, subject.Pid, subject.Created);
            if (!m.PinHandleGraphOwner(graphOwner, pin)) { return; }
            std::wcout << L"[scan.owner] pinned\n" << std::flush;
            std::wstring ack;
            observedExit = std::getline(std::wcin, ack) && ack == L"exited" &&
                WaitForSingleObject(subjectProcess, 0) == WAIT_OBJECT_0;
            if (!observedExit) { return; }
            m.FinishWatchedHandleGraph(graphOwner, pin, complete, nullptr);
        }
        m.FinishWatchedFileSnapshot(fileOwner, {}, {}, nullptr, nullptr);
    });
    if (!observedExit) { return false; }
    run(L"exited", subject.Pid, [&](KernelMonitor& m) { promote(m, subject.Pid, subject.Created); both(m, subject.Pid); });
    run(L"missing", UINT32_MAX, [&](KernelMonitor& m) { m.AddWatchPid(UINT32_MAX); both(m, UINT32_MAX); });
    run(L"stopping", self.Pid, [&](KernelMonitor& m) { m.AddWatchPid(self.Pid); m.StopRequested.store(true); both(m, self.Pid); });
    for (bool repin : {false, true})
    {
        run(repin ? L"repinned" : L"readded", self.Pid, [&](KernelMonitor& m) {
            if (repin) { promote(m, self.Pid, self.Created); }
            else { m.AddWatchPid(self.Pid); }
            auto fileOwner = m.BeginHandleScan(self.Pid);
            const bool sampled = m.ObserveFileScanOwner(fileOwner, false, nullptr, nullptr, fileOwner.BeforeAcquisition);
            auto graphOwner = m.BeginHandleScan(self.Pid);
            ObservedProcessHandle pin(ControllerProcessHandles(), ProcessHandleSite::HandleGraphOwner, self.Pid, graphOwner.Identity.CreateTime);
            const bool pinned = m.PinHandleGraphOwner(graphOwner, pin);
            auto replace = std::async(std::launch::async, [&] {
                if (repin)
                {
                    std::lock_guard<std::mutex> lock(m.WatchMutex);
                    m.WatchPromotedCreated[self.Pid] = self.Created + 1;
                }
                else
                {
                    m.RemoveWatchPid(self.Pid);
                    m.AddWatchPid(self.Pid);
                    m.BeginHandleScan(self.Pid);
                }
            });
            replace.get();
            if (sampled) { m.FinishWatchedFileSnapshot(fileOwner, {}, {}, nullptr, nullptr); }
            if (pinned) { m.FinishWatchedHandleGraph(graphOwner, pin, complete, nullptr); }
        });
    }
    run(L"withdrawn_during_read", self.Pid, [&](KernelMonitor& m) {
        m.AddWatchPid(self.Pid);
        auto owner = m.BeginHandleScan(self.Pid);
        if (!m.ObserveFileScanOwner(owner, false, nullptr, nullptr, owner.BeforeAcquisition)) { return; }
        NativeHandleEntry entry{};
        entry.HandleValue = 4;
        entry.Object = reinterpret_cast<void*>(0xffff800000000000ULL);
        m.ChannelLayout.Valid = true;
        // The sentinel only invokes this in-memory reader. It never dereferences the supplied address.
        const KmonMemoryReader withdraw = [&](uint64_t, size_t, void*) {
            m.RemoveWatchPid(self.Pid);
            m.AddWatchPid(self.Pid);
            m.BeginHandleScan(self.Pid);
            return false;
        };
        m.FinishWatchedFileSnapshot(owner, {entry}, withdraw, nullptr, nullptr);
    });
    diagnostics = out.str();
    return true;
}
