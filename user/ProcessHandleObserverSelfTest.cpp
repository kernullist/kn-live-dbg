#include "ProcessObservationSource.h"
#include "ProcessLayoutMonitor.h"
#include "TimelineSelfTest.h"
#include "TimelineStore.h"

#include <chrono>
#include <future>
#include <iostream>

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
