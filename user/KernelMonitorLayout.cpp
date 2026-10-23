#include "KernelMonitor.h"

#include <chrono>
#include <memory>

std::wstring KernelMonitor::LayoutsJson(uint32_t pid, bool initial) const
{
    auto json = LayoutMonitor.Json(pid, initial);
    json.pop_back();
    json += L",\"collection_active\":" + std::wstring(Active.load() ? L"true" : L"false");
    json += L",\"verification_pending\":" + std::to_wstring(LayoutCandidates.Size());
    json += L",\"verification_dropped\":" + std::to_wstring(LayoutCandidates.Loss());
    json += L",\"verification_mapping_checked\":" + std::to_wstring(LayoutChecked.load());
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
    candidate.QueuedMs = GetTickCount64();
    // Keep admitted work near the consumer instead of filling a 30-second
    // stale backlog. The source retains a refused change or periodic cursor.
    return LayoutCandidates.TryPushLatest(std::move(candidate), [](const auto& old, const auto& fresh)
    {
        const auto& a = old.Region;
        const auto& b = fresh.Region;
        return old.Identity.SameInstance(fresh.Identity) && old.ImageName == fresh.ImageName &&
            (old.Role == L"layout_change") == (fresh.Role == L"layout_change") &&
            a.Base == b.Base && a.Size == b.Size && a.AllocationBase == b.AllocationBase &&
            a.State == b.State && a.Protect == b.Protect &&
            a.AllocationProtect == b.AllocationProtect && a.Type == b.Type;
    }, 128);
}

void KernelMonitor::DrainLayoutCandidates(bool finalDrain, const wchar_t* before)
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
    // larger but still bounded slice while at least half the admission queue
    // is occupied. Never extend the candidate's original validity window.
    const bool pressure = LayoutCandidates.Size() >= 64;
    const size_t candidateBudget = pressure ? 64 : 16;
    const uint64_t timeBudgetMs = pressure ? 100 : 25;
    ProcessLayoutCandidate item;
    for (size_t count = 0; count < candidateBudget && (finalDrain || !StopRequested.load()) && GetTickCount64() - begin < timeBudgetMs &&
        LayoutCandidates.Pop(&item); ++count)
    {
        const uint64_t selectedMs = GetTickCount64();
        const uint64_t queueWait = item.QueuedMs != 0 && selectedMs >= item.QueuedMs ? selectedMs - item.QueuedMs : 0;
        const uint64_t sourceWait = item.QueuedMs >= item.ObservedMs ? item.QueuedMs - item.ObservedMs : 0;
        LayoutMaxQueueWaitMs.store((std::max)(LayoutMaxQueueWaitMs.load(), queueWait));
        LayoutMaxSourceWaitMs.store((std::max)(LayoutMaxSourceWaitMs.load(), sourceWait));
        const auto pid = item.Identity.ProcessId;
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        const std::unique_ptr<void, decltype(&CloseHandle)> handle(process, &CloseHandle);
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
            const bool expired = now < item.ObservedMs || now - item.ObservedMs > process_layout::MaxSweepMs;
            if (expired) { LayoutExpired.fetch_add(1); }
            rejected.Observation.Coverage.Reason = expired ? L"candidate_expired" : L"process_or_mapping_changed_or_unavailable";
            rejected.Evidence[L"base"] = std::to_wstring(item.Region.Base);
            rejected.Evidence[L"size"] = std::to_wstring(item.Region.Size);
            rejected.Evidence[L"candidate_role"] = item.Role;
            rejected.Evidence[L"candidate_age_ms"] = std::to_wstring(now >= item.ObservedMs ? now - item.ObservedMs : 0);
            rejected.Evidence[L"queue_wait_ms"] = std::to_wstring(queueWait);
            rejected.Evidence[L"source_wait_ms"] = std::to_wstring(sourceWait);
            RecordEvent(std::move(rejected));
            continue;
        }
        LayoutChecked.fetch_add(1);
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
        if (observation.ImageMapping && !item.ImageName.empty())
        {
            // Preserve the device volume; path classification normalization is
            // intentionally lossy and must never select an on-disk reference.
            const auto path = ProcessLayoutReferencePath(item.ImageName);
            const auto work = FindImageWork(path, item.Region.AllocationBase, item.Identity);
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
    }
}
