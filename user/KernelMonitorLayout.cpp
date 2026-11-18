#include "KernelMonitor.h"
#include "KmonHandleTracking.h"
#include "TimelineStore.h"

#include <chrono>
#include <memory>
#include <cstdio>

std::wstring KernelMonitor::LayoutsJson(uint32_t pid, bool initial) const
{
    auto json = LayoutMonitor.Json(pid, initial);
    json.pop_back();
    json += L",\"collection_active\":" + std::wstring(Active.load() ? L"true" : L"false");
    json += L",\"verification_pending\":" + std::to_wstring(LayoutCandidates.Size());
    json += L",\"verification_dropped\":" + std::to_wstring(LayoutCandidates.Loss());
    json += L",\"verification_mapping_checked\":" + std::to_wstring(LayoutChecked.load());
    json += L",\"collection_scheduling\":" + LayoutMonitor.SchedulingJson(GetTickCount64());
    json += L",\"verification_scheduling\":" + LayoutCandidates.Json(GetTickCount64());
    json += L",\"verification_rejected\":" + std::to_wstring(LayoutRejected.load()) + L"}";
    return json;
}

std::wstring KernelMonitor::LayoutsText(uint32_t pid, bool initial) const
{
    return LayoutMonitor.Text(pid, initial);
}

void KernelMonitor::LayoutLoop()
{
    while (!StopRequested.load())
    {
        try
        {
            ProcessLayoutScope scope;
            scope.All = LayoutAllProcesses;
            if (!scope.All)
            {
                std::lock_guard<std::mutex> lock(WatchMutex);
                scope.Pids.insert(WatchPids.begin(), WatchPids.end());
                scope.Names = WatchNamesLower;
            }
            LayoutMonitor.Tick(scope, StopRequested, [this](const ProcessLayoutNotice& item)
            {
                return QueueLayoutNotice(item);
            }, [this](ProcessLayoutCandidate candidate)
            {
                return QueueLayoutCandidate(std::move(candidate));
            });
        }
        catch (...)
        {
            LayoutMonitor.NoteException();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

bool KernelMonitor::QueueLayoutNotice(const ProcessLayoutNotice& item)
{
    // Leave room for capture/results producers; retry the entire source notice.
    if (PipelineEvents.Size() > 367) { return false; }
    std::vector<KmonEvent> batch;
    KmonEvent event;
    event.Kind = L"coverage.layout";
    event.Task = item.Status;
    event.ProcessId = item.Identity.ProcessId;
    event.Image = item.Name;
    event.Summary = L"process memory layout: " + item.Status;
    event.Observation.Identity = item.Identity;
    event.Observation.Timestamp = item.ObservedAt;
    event.Observation.MonotonicMs = item.FinishedMs;
    event.Observation.Source = L"virtual_query_layout";
    event.Observation.DependencyGroup = L"virtual_query";
    event.Observation.Coverage.Attempted = true;
    event.Observation.Coverage.TraversalComplete = item.Cycle != 0;
    event.Observation.Coverage.InventoryAvailable = item.Cycle != 0;
    event.Observation.Coverage.Reason = item.Status;
    event.Evidence[L"cycle"] = std::to_wstring(item.Cycle);
    event.Evidence[L"started_ms"] = std::to_wstring(item.StartedMs);
    event.Evidence[L"finished_ms"] = std::to_wstring(item.FinishedMs);
    event.Evidence[L"regions"] = std::to_wstring(item.Rows);
    event.Evidence[L"image_name_failures"] = std::to_wstring(item.ImageNameFailures);
    event.Evidence[L"image_allocations"] = std::to_wstring(item.ImageAllocations);
    event.Evidence[L"image_names_known"] = std::to_wstring(item.ImageNamesKnown);
    event.Evidence[L"image_name_capacity_failures"] = std::to_wstring(item.ImageNameCapacityFailures);
    event.Evidence[L"image_name_query_failures"] = std::to_wstring(item.ImageNameQueryFailures);
    event.Evidence[L"image_name_truncated"] = std::to_wstring(item.ImageNameTruncated);
    event.Evidence[L"image_name_unqueryable"] = std::to_wstring(item.ImageNameUnqueryable);
    event.Evidence[L"image_name_retry_attempts"] = std::to_wstring(item.ImageNameRetryAttempts);
    event.Evidence[L"image_name_recovered"] = std::to_wstring(item.ImageNameRecovered);
    event.Evidence[L"image_name_diagnostics_omitted"] = std::to_wstring(item.ImageNameDiagnosticsOmitted);
    event.Evidence[L"image_name_diagnostics"] = item.ImageNameDiagnostics;
    event.Evidence[L"changed_ranges"] = std::to_wstring(item.ChangedRanges);
    event.Evidence[L"candidate_ranges"] = std::to_wstring(item.CandidateRanges);
    event.Evidence[L"lead_event_limit"] = L"16";
    event.Evidence[L"verification_candidate_limit"] = L"8";
    event.Evidence[L"delta_truncated"] = item.ChangedRanges > item.Changes.size() ? L"true" : L"false";
    event.Evidence[L"snapshot_semantics"] = L"non_atomic; initial_is_not_clean; unseen_reuse_unknown";
    event.Evidence[L"execution_proven"] = L"false";
    batch.push_back(std::move(event));
    size_t budget = 16;
    for (const auto& change : item.Changes)
    {
        if (budget == 0 || !change.Candidate())
        {
            continue;
        }
        --budget;
        KmonEvent lead;
        lead.Kind = L"finding.layout_change";
        lead.ProcessId = item.Identity.ProcessId;
        lead.Image = item.Name;
        lead.Observation.Identity = item.Identity;
        lead.Observation.Timestamp = item.ObservedAt;
        lead.Observation.MonotonicMs = item.FinishedMs;
        lead.Observation.Source = L"virtual_query_layout";
        lead.Observation.DependencyGroup = L"virtual_query";
        lead.Summary = L"memory layout changed; executable or image investigation lead";
        lead.Evidence[L"base"] = std::to_wstring(change.Base);
        lead.Evidence[L"size"] = std::to_wstring(change.Size);
        lead.Evidence[L"flags"] = std::to_wstring(change.Flags);
        lead.Evidence[L"before_type"] = std::to_wstring(change.Before.Type);
        lead.Evidence[L"after_type"] = std::to_wstring(change.After.Type);
        lead.Evidence[L"before_protect"] = std::to_wstring(change.Before.Protect);
        lead.Evidence[L"after_protect"] = std::to_wstring(change.After.Protect);
        lead.Evidence[L"cycle"] = std::to_wstring(item.Cycle);
        lead.Evidence[L"claim"] = L"layout_delta; JIT_and_loader_changes_possible; technique_not_proven";
        lead.Evidence[L"execution_proven"] = L"false";
        batch.push_back(std::move(lead));
    }
    return PipelineEvents.TryPushBatch(std::move(batch), 384);
}

bool KernelMonitor::QueueLayoutCandidate(ProcessLayoutCandidate candidate)
{
    return KmonLayoutQueue::Accepted(LayoutCandidates.Admit(std::move(candidate), GetTickCount64()));
}

void KernelMonitor::DrainLayoutCandidates(bool finalDrain, const wchar_t* before, uint64_t budgetMs)
{
    const auto begin = GetTickCount64();
    if (LayoutLastServiceMs != 0 && begin >= LayoutLastServiceMs)
    {
        const uint64_t gap = begin - LayoutLastServiceMs;
        if (gap > LayoutMaxServiceGapMs.load())
        {
            LayoutMaxServiceGapMs.store(gap);
            LayoutMaxServiceGapBefore = before;
        }
    }
    LayoutLastServiceMs = begin;
    // A full-host burst must not wait through many scanner passes. Spend a
    // larger but still bounded slice once half the periodic admission window
    // is occupied. Never extend the candidate's original validity window.
    const bool pressure = LayoutCandidates.Size() >= (LayoutAdmissionLimit - LayoutChangeReserve) / 2;
    const size_t candidateBudget = pressure ? 64 : 16;
    const uint64_t timeBudgetMs = (std::min)(budgetMs, uint64_t(pressure ? 100 : 25));
    const auto watches = SnapshotWatchPids();
    ProcessLayoutCandidate item;
    for (size_t count = 0; count < candidateBudget && (finalDrain || !StopRequested.load()) && GetTickCount64() - begin < timeBudgetMs &&
        LayoutCandidates.Pop(&item); ++count)
    {
        const uint64_t selectedMs = GetTickCount64();
        struct Attempt
        {
            KmonLayoutQueue& Queue;
            const ProcessLayoutCandidate& Item;
            uint64_t Started;
            bool Shutdown;
            KmonLayoutOutcome Outcome = KmonLayoutOutcome::Fault;
            std::optional<uint64_t> Qualified;
            ~Attempt() { Queue.Finish(Item, Started, GetTickCount64(), Shutdown, Outcome, Qualified); }
        } attempt{LayoutCandidates, item, selectedMs, finalDrain || StopRequested.load()};
        const uint64_t queueWait = item.QueuedMs != 0 && selectedMs >= item.QueuedMs ? selectedMs - item.QueuedMs : 0;
        const uint64_t sourceWait = item.QueuedMs >= item.ObservedMs ? item.QueuedMs - item.ObservedMs : 0;
        LayoutMaxQueueWaitMs.store((std::max)(LayoutMaxQueueWaitMs.load(), queueWait));
        LayoutMaxSourceWaitMs.store((std::max)(LayoutMaxSourceWaitMs.load(), sourceWait));
        const auto pid = item.Identity.ProcessId;
        ObservedProcessHandle owner(ControllerProcessHandles(), ProcessHandleSite::LayoutVerification, pid, item.Identity.CreateTime);
        if (item.WithinObservationWindow(GetTickCount64()))
        {
            owner.Open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        }
        const HANDLE process = owner.get();
        const auto current = [&]()
        {
            return ProcessLayoutCandidateCurrent(process, item);
        };
        if (!current())
        {
            LayoutRejected.fetch_add(1);
            KmonEvent rejected;
            rejected.Kind = L"coverage.layout_verification";
            rejected.ProcessId = pid;
            rejected.Image = item.ImageName;
            rejected.Summary = L"layout candidate could not be revalidated; memory was not verified";
            rejected.Observation.Identity = item.Identity;
            rejected.Observation.Timestamp = item.ObservedAt;
            rejected.Observation.MonotonicMs = item.ObservedMs;
            rejected.Observation.Source = item.Role;
            rejected.Observation.Coverage.Attempted = true;
            const uint64_t now = GetTickCount64();
            const bool expired = !item.WithinObservationWindow(now);
            attempt.Outcome = expired ? KmonLayoutOutcome::Expired : KmonLayoutOutcome::Rejected;
            if (expired) { LayoutExpired.fetch_add(1); }
            rejected.Observation.Coverage.Reason = expired ? L"candidate_expired" : L"process_or_mapping_changed_or_unavailable";
            rejected.Evidence[L"base"] = std::to_wstring(item.Region.Base);
            rejected.Evidence[L"size"] = std::to_wstring(item.Region.Size);
            rejected.Evidence[L"candidate_role"] = item.Role;
            rejected.Evidence[L"candidate_age_ms"] = std::to_wstring(now >= item.ObservedMs ? now - item.ObservedMs : 0);
            rejected.Evidence[L"queue_wait_ms"] = std::to_wstring(queueWait);
            rejected.Evidence[L"source_wait_ms"] = std::to_wstring(sourceWait);
            rejected.Evidence[L"last_rediscovered_ms"] = std::to_wstring(item.LastObservedMs);
            rejected.Evidence[L"rediscoveries"] = std::to_wstring(item.Rediscoveries);
            RecordEvent(std::move(rejected));
            continue;
        }
        LayoutChecked.fetch_add(1);
        attempt.Qualified = GetTickCount64();
        const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (size == 0 || size > 4096 || address > UINT64_MAX - size || !current())
            {
                return false;
            }
            uint64_t cursor = address;
            while (cursor < address + size)
            {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(process, reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi) ||
                    mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
                    reinterpret_cast<uint64_t>(mbi.AllocationBase) != item.Region.AllocationBase ||
                    mbi.RegionSize == 0 || reinterpret_cast<uint64_t>(mbi.BaseAddress) > cursor ||
                    reinterpret_cast<uint64_t>(mbi.BaseAddress) > UINT64_MAX - mbi.RegionSize ||
                    reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize <= cursor)
                {
                    return false;
                }
                cursor = (std::min<uint64_t>)(address + size, reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize);
            }
            bytes->resize(size);
            SIZE_T read = 0;
            return ReadProcessMemory(process, reinterpret_cast<void*>(address), bytes->data(), size, &read) &&
                read == size && current();
        };
        ExecutableRegionObservation observation;
        observation.Context.Identity = item.Identity;
        observation.Context.Timestamp = item.ObservedAt;
        observation.Context.MonotonicMs = item.ObservedMs;
        observation.Context.Source = item.Role;
        observation.Context.DependencyGroup = L"virtual_query";
        observation.Context.AllocationBase = item.Region.AllocationBase;
        observation.Context.Ownership = CodeOwnership::Unknown;
        observation.Range = {item.Region.Base, item.Region.Size};
        observation.Executable = item.Region.Executable();
        observation.Writable = (item.Region.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        observation.CopyOnWrite = (item.Region.Protect & (PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)) != 0;
        observation.ImageMapping = item.Region.Type == MEM_IMAGE;
        ObserveExecutableRegion(observation);
        QueueExecutableRegionPages(observation, observation.ImageMapping ? L"image_page_candidate" : L"user_page_candidate");
        const bool watched = std::find(watches.begin(), watches.end(), pid) != watches.end();
        bool layoutLead = watched && observation.Executable && !observation.ImageMapping;
        if (observation.ImageMapping && !item.ImageName.empty())
        {
            // Preserve the device volume; path classification normalization is
            // intentionally lossy and must never select an on-disk reference.
            const auto path = ProcessLayoutReferencePath(item.ImageName);
            bool referenceUnavailable = false;
            const auto work = FindImageWork(path, item.Region.AllocationBase, item.Identity, &referenceUnavailable);
            // An admitted reference that could not be read/parsed warrants a
            // deep ownership check, including deleted files that return access
            // denied. Cache admission pressure alone is not such a lead.
            layoutLead = watched && observation.Executable && referenceUnavailable;
            if (work != nullptr)
            {
                HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                const std::unique_ptr<void, decltype(&CloseHandle)> fileOwner(file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
                std::vector<ObservationAnchor> anchors;
                const ObservationReader identityReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
                {
                    if (!reader(address, size, bytes) || anchors.size() >= 8)
                    {
                        return false;
                    }
                    anchors.push_back({address, *bytes});
                    return true;
                };
                std::wstring reason;
                const bool qualified = QualifyExecutableReference(work->Reference, item.Region.AllocationBase, identityReader, &reason);
                if (!qualified && reason == L"live_image_identity_mismatch" && file != INVALID_HANDLE_VALUE &&
                    executable_image::DiskFileIdentityMatches(file, work->Reference) &&
                    ObservationAnchorsMatch(anchors, reader) && current() && !work->LayoutIdentityReported)
                {
                    KmonEvent event;
                    event.Kind = L"finding.layout_image_identity";
                    event.ProcessId = pid;
                    event.Image = path;
                    event.Observation.Identity = item.Identity;
                    event.Observation.Timestamp = ObservationFileTime();
                    event.Observation.MonotonicMs = GetTickCount64();
                    event.Observation.Source = L"layout_image_identity";
                    event.Observation.DependencyGroup = L"memory_vs_file";
                    event.Summary = L"stable memory PE identity differs from the current mapped-name file";
                    event.Evidence[L"image_base"] = std::to_wstring(item.Region.AllocationBase);
                    event.Evidence[L"reason"] = reason;
                    event.Evidence[L"claim"] = L"image_tampering_lead; original_section_file_identity_unknown; technique_not_proven";
                    for (size_t i = 0; i < anchors.size(); ++i)
                    {
                        event.Evidence[L"metadata_capture_" + std::to_wstring(i)] = std::to_wstring(
                            QueueCapturedBytes(L"layout_image_metadata", anchors[i].Address, event.Observation, anchors[i].Bytes));
                    }
                    RecordEvent(std::move(event));
                    work->LayoutIdentityReported = true;
                }
                else if (qualified)
                {
                    work->LayoutIdentityReported = false;
                }
            }
            if (observation.Executable)
            {
                ScanExecutableImage(path, item.Region.AllocationBase, item.Identity, reader, 8);
            }
        }
        if (layoutLead && item.Identity.CreateTime != 0)
        {
            KmonRequestUserLayoutLead(pid, item.Identity.CreateTime, GetTickCount64(),
                watched, UserLastScanMs, &UserLayoutLeads, item.Role == L"layout_change");
        }
        attempt.Outcome = KmonLayoutOutcome::MappingCurrent;
    }
}

bool KmonLayoutSchedulingIntegrationSelfTest(std::wstring* diagnostics)
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* name)
    { ++checks; if (!ok) { ++failures; std::fprintf(stderr, "[layout.scheduler] FAIL %s\n", name); } return ok; };
    const auto owner = std::make_unique<KernelMonitor>();
    auto& monitor = *owner;
    auto* memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    const auto release = [](uint8_t* p) { if (p != nullptr) { VirtualFree(p, 0, MEM_RELEASE); } };
    const std::unique_ptr<uint8_t, decltype(release)> allocation(memory, release);
    if (!check(memory != nullptr, "owned-mapping-allocation")) { return false; }
    DWORD old = 0;
    check(VirtualProtect(memory + 2 * 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &old) != FALSE, "owned-guard-metadata");
    const auto identity = ObserveProcessIdentity(GetCurrentProcessId(), GetCurrentProcess());
    const uint64_t now = GetTickCount64();
    check(now > process_layout::MaxSweepMs, "uptime-supports-expiration-control");
    ProcessLayoutCandidate first, freshAfterExpired;
    for (unsigned i = 0; i < 4; ++i)
    {
        MEMORY_BASIC_INFORMATION mapping{};
        check(VirtualQuery(memory + i * 4096, &mapping, sizeof(mapping)) == sizeof(mapping), "owned-mapping-query");
        ProcessLayoutCandidate candidate;
        candidate.Identity = identity; candidate.Role = L"layout_periodic";
        candidate.Region = {reinterpret_cast<uint64_t>(memory + i * 4096), 4096, reinterpret_cast<uint64_t>(mapping.AllocationBase),
            mapping.State, mapping.Protect, mapping.AllocationProtect, mapping.Type};
        candidate.ObservedAt = ObservationFileTime(); candidate.ObservedMs = now;
        if (i == 1) { candidate.ObservedMs = now > process_layout::MaxSweepMs ? now - process_layout::MaxSweepMs - 1 : 0; }
        if (i == 3) { --candidate.Identity.CreateTime; }
        check(monitor.QueueLayoutCandidate(candidate), "actual-layout-admission");
        if (i == 0) { first = candidate; }
        if (i == 1)
        {
            candidate.ObservedMs = now;
            freshAfterExpired = candidate;
            check(!monitor.QueueLayoutCandidate(candidate), "fresh-source-observation-held-behind-expired-original");
        }
    }
    const auto pending = monitor.LayoutCandidates.Json(GetTickCount64());
    const auto priorHandleSequence = ControllerProcessHandles().Snapshot().Total;
    monitor.DrainLayoutCandidates(false);
    // A slow first turn may use the cooperative budget; finish only admitted work.
    const auto deadline = GetTickCount64() + 10000;
    while (monitor.LayoutCandidates.Size() != 0 && GetTickCount64() < deadline) { monitor.DrainLayoutCandidates(false); }
    const auto normal = monitor.LayoutCandidates.Json(GetTickCount64());
    const auto count = monitor.LayoutCandidates.Snapshot();
    check(count.Attempts == 4 && count.Qualified == 2 && count.Outcomes[static_cast<size_t>(KmonLayoutOutcome::Expired)] == 1 &&
        count.Outcomes[static_cast<size_t>(KmonLayoutOutcome::Rejected)] == 1 && count.InvalidClocks == 0,
        "mapping-success-stale-identity-and-original-expiry-remain-distinct");
    auto normalHandles = ControllerProcessHandles().Snapshot();
    auto& actions = normalHandles.Actions;
    actions.erase(std::remove_if(actions.begin(), actions.end(), [&](const ProcessHandleAction& action) {
        return action.Sequence <= priorHandleSequence || action.Site != ProcessHandleSite::LayoutVerification;
    }), actions.end());
    check(actions.size() == 6, "expired-original-skips-open-while-three-fresh-candidates-open-and-close");
    MEMORY_BASIC_INFORMATION guard{};
    check(VirtualQuery(memory + 2 * 4096, &guard, sizeof(guard)) == sizeof(guard) && (guard.Protect & PAGE_GUARD) != 0,
        "mapping-qualification-does-not-consume-guard");
    check(monitor.PriorityCaptures.Size() == 0 && monitor.ContinuedCaptures.Size() == 0 && monitor.CapturedPages.Size() == 0,
        "nonexecutable-mapping-success-does-not-claim-byte-capture");
    check(monitor.QueueLayoutCandidate(freshAfterExpired), "retained-fresh-source-observation-retried");
    monitor.DrainLayoutCandidates(false);
    const auto retried = monitor.LayoutCandidates.Json(GetTickCount64());
    check(monitor.LayoutCandidates.Snapshot().Attempts == 5 && monitor.LayoutCandidates.Snapshot().Qualified == 3,
        "fresh-retry-gets-actual-mapping-qualification");
    first.ObservedMs = GetTickCount64();
    check(monitor.QueueLayoutCandidate(first), "new-observation-after-completed-work");
    monitor.StopRequested.store(true);
    monitor.DrainLayoutCandidates(true);
    const auto stopped = monitor.LayoutCandidates.Json(GetTickCount64());
    check(monitor.LayoutCandidates.Snapshot(true).Attempts == 1 && monitor.LayoutCandidates.Snapshot(true).Qualified == 1 &&
        monitor.LayoutCandidates.Snapshot().Attempts == 5 && monitor.LayoutCandidates.Size() == 0,
        "shutdown-qualification-is-separated-and-drained");
    ProcessLayoutMonitor collector;
    collector.Reset();
    ProcessLayoutScope scope; scope.All = false; scope.Pids.insert(GetCurrentProcessId());
    std::atomic<bool> stoppedCollection{false};
    const auto collected = GetTickCount64() + 10000;
    while (collector.Stats().Completed == 0 && GetTickCount64() < collected)
    {
        collector.Tick(scope, stoppedCollection, [](const ProcessLayoutNotice&) { return true; }, [](ProcessLayoutCandidate) { return true; });
        std::this_thread::yield();
    }
    check(collector.Stats().Completed == 1, "owned-native-layout-sweep-completed");
    check(VirtualQuery(memory + 2 * 4096, &guard, sizeof(guard)) == sizeof(guard) && (guard.Protect & PAGE_GUARD) != 0,
        "native-collection-preserves-owned-guard");
    const auto collection = collector.SchedulingJson(GetTickCount64());
    if (diagnostics != nullptr)
    {
        TimelineStore timeline;
        timeline.IngestProcessHandleActions(normalHandles);
        const auto events = timeline.AllEvents();
        TimelineQueryOptions chronological;
        chronological.NewestFirst = false;
        *diagnostics = L"{\"schema\":\"kn.layout_scheduler_test.v1\",\"driver_loaded\":false,\"native_byte_reads\":false,"
            L"\"corpus\":\"owned_native_mapping_metadata_guard_expiry_and_identity\",\"passed\":" +
            std::wstring(failures == 0 ? L"true" : L"false") + L",\"checks\":" + std::to_wstring(checks) +
            L",\"pending\":" + pending + L",\"normal\":" + normal + L",\"retry\":" + retried + L",\"shutdown\":" + stopped + L",\"collection\":" + collection +
            L",\"verification_handle_timeline\":" + BuildTimelineEventsJson(events, chronological, events.size()) + L"}";
    }
    std::fprintf(stderr, "[layout.scheduler] checks=%u failed=%u\n", checks, failures);
    return failures == 0;
}
