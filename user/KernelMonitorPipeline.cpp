#include "KernelMonitor.h"
#include "ContentHash.h"

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <cstring>
#include <filesystem>
#include <memory>
#include <Psapi.h>
#include <cstdio>

namespace
{
    void UpdateMaximum(std::atomic<uint64_t>& value, uint64_t candidate)
    {
        uint64_t previous = value.load();
        while (previous < candidate && !value.compare_exchange_weak(previous, candidate))
        {
        }
    }

    std::wstring Lower(std::wstring text)
    {
        std::transform(text.begin(), text.end(), text.begin(), towlower);
        return text;
    }

    uint64_t NumericField(const TiEventRecord& event, const std::initializer_list<const wchar_t*>& names)
    {
        for (const auto& field : event.Payload)
        {
            const auto name = Lower(field.Name);
            for (const auto wanted : names)
            {
                if (name == wanted)
                {
                    wchar_t* end = nullptr;
                    const uint64_t value = wcstoull(field.Value.c_str(), &end, 0);
                    if (end != field.Value.c_str() && *end == L'\0')
                    {
                        return value;
                    }
                }
            }
        }
        return 0;
    }
}

void KernelMonitor::ResetPipeline()
{
    {
        std::lock_guard<std::mutex> lock(CapturesMutex);
        CandidateCaptures.clear();
    }
    CollectedTi.Reset();
    CollectedLive.Reset();
    PriorityCaptures.Reset();
    ContinuedCaptures.Reset();
    CapturedPages.Reset();
    PipelineEvents.Reset();
    CapturedRegions.Reset();
    CaptureStopping.store(false);
    WriterStopping.store(false);
    CollectorLastMs.store(0);
    CollectorMaxGapMs.store(0);
    CollectionLost.store(0);
    TiSessionLost.store(0);
    TiAvailable.store(false);
    CaptureQueued.store(0);
    CaptureFailed.store(0);
    CaptureFirstMaxMs.store(0);
    UserScanCursor.store(0);
    UserOldestScanMs.store(0);
    AnalysisBudgetExceeded.store(0);
    AnalysisLastCompleteMs.store(0);
    ImageRemainingPages.store(0);
    ImageLastCompleteMs.store(0);
    UserLastScanMs.clear();
    HeapPageCursors.clear();
    HighPriorityPidCursor = 0;
    BackgroundPidCursor = 0;
    NextPipelineStatusMs = 0;
}

void KernelMonitor::CollectorLoop()
{
    uint64_t priorTiLost = 0;
    bool tiLossBaseline = false;
    while (!StopRequested.load())
    {
        try
        {
            TiSubscriber* ti = nullptr;
            TimelineStore* timeline = nullptr;
            {
                std::lock_guard<std::mutex> lock(StateMutex);
                ti = Ti;
                timeline = Timeline;
            }
            const uint64_t now = GetTickCount64();
            const uint64_t previous = CollectorLastMs.exchange(now);
            if (previous != 0)
            {
                UpdateMaximum(CollectorMaxGapMs, now - previous);
            }
            TiAvailable.store(ti != nullptr && ti->IsActive());
            if (TiAvailable.load())
            {
                const auto stats = ti->SnapshotStats();
                TiSessionLost.store(stats.EventsLost);
                if (tiLossBaseline && stats.EventsLost > priorTiLost)
                {
                    CollectionLost.fetch_add(stats.EventsLost - priorTiLost);
                }
                priorTiLost = stats.EventsLost;
                tiLossBaseline = true;
                const auto latest = ti->Recent(1, true);
                if (!latest.empty() && latest.front().Sequence < TiCursorSequence)
                {
                    TiCursorSequence = 0;
                    CollectionLost.fetch_add(1);
                }
                auto events = ti->RecentAfterSequence(TiCursorSequence, 256);
                size_t captureBudget = 8;
                for (auto& event : events)
                {
                    if (event.Sequence > TiCursorSequence && event.Sequence - TiCursorSequence > 1)
                    {
                        CollectionLost.fetch_add(event.Sequence - TiCursorSequence - 1);
                    }
                    TiCursorSequence = event.Sequence;
                    const auto task = Lower(event.TaskName);
                    if (captureBudget != 0 && event.TargetProcessId > 4 &&
                        (task.find(L"apc") != std::wstring::npos || task.find(L"write") != std::wstring::npos ||
                            task.find(L"protect") != std::wstring::npos || task.find(L"thread") != std::wstring::npos))
                    {
                        const auto watches = SnapshotWatchPids();
                        if (std::find(watches.begin(), watches.end(), event.TargetProcessId) != watches.end())
                        {
                            const uint64_t address = NumericField(event, {L"apcroutine", L"apcroutineaddress", L"routine",
                                L"baseaddress", L"targetaddress", L"startaddress"});
                            if (address >= 0x10000 && address < 0x0000800000000000ull)
                            {
                                const auto identity = ObserveProcessIdentity(event.TargetProcessId);
                                if (identity.CreateTime != 0 && event.Timestamp >= identity.CreateTime)
                                {
                                    QueueCapture(L"event_target", address & ~4095ull, 4096, identity, event.Timestamp, nullptr);
                                    --captureBudget;
                                }
                            }
                        }
                    }
                    CollectedTi.Push(std::move(event));
                }
            }
            if (timeline != nullptr)
            {
                if (LiveCursorEventId != 0 && timeline->PeekNextEventId() <= LiveCursorEventId)
                {
                    LiveCursorEventId = 0;
                    CollectionLost.fetch_add(1);
                }
                auto events = timeline->RecentAfterEventId(LiveCursorEventId, 512);
                for (auto& event : events)
                {
                    if (event.EventId > LiveCursorEventId && event.EventId - LiveCursorEventId > 1)
                    {
                        CollectionLost.fetch_add(event.EventId - LiveCursorEventId - 1);
                    }
                    LiveCursorEventId = event.EventId;
                    if (Lower(event.Source) == L"kernel-live")
                    {
                        KmonEvent classified;
                        const bool known = KmonClassifyLiveEvent(event, &classified);
                        if (known &&
                            (classified.Kind == L"process.create" || classified.Kind == L"process.masquerade"))
                        {
                            LayoutMonitor.RequestDiscovery();
                        }
                        if (known &&
                            (classified.Kind == L"driver.drop_load" || classified.Kind == L"driver.official_load" ||
                                classified.Kind == L"driver.image_only"))
                        {
                            const auto base = event.Evidence.find(L"image_base");
                            if (base != event.Evidence.end())
                            {
                                wchar_t* end = nullptr;
                                const uint64_t address = wcstoull(base->second.c_str(), &end, 0);
                                if (end != base->second.c_str() && *end == L'\0' && address >= 0xFFFF800000000000ull)
                                {
                                    QueueCapture(L"driver_load_source", address, 4096, ObserveProcessIdentity(0), event.TimestampFileTime, nullptr);
                                }
                            }
                        }
                        CollectedLive.Push(std::move(event));
                    }
                }
            }
        }
        catch (...)
        {
            CollectionLost.fetch_add(1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

bool KernelMonitor::QueueCapture(const std::wstring& role, uint64_t address, uint64_t size,
    const ObservationIdentity& identity, uint64_t eventTimestamp, std::wstring* note,
    uint64_t mappingGeneration)
{
    if (CaptureStopping.load() || address == 0 || size == 0 || address > UINT64_MAX - size ||
        (identity.ProcessId != 0 && identity.CreateTime == 0))
    {
        CaptureFailed.fetch_add(1);
        return false;
    }
    CaptureRequest request;
    request.Id = NextCaptureId.fetch_add(1);
    request.Address = address;
    request.Size = (std::min<uint64_t>)(size, 16 * 1024 * 1024);
    request.SubmittedMs = GetTickCount64();
    request.EventTimestamp = eventTimestamp;
    request.MappingGeneration = mappingGeneration;
    request.Identity = identity;
    request.Role = role;
    request.Key = identity.BootId + L":" + std::to_wstring(identity.ProcessId) + L":" +
        std::to_wstring(identity.CreateTime) + L":" + std::to_wstring(address) + L":" + role + L":" +
        std::to_wstring(mappingGeneration);
    {
        std::lock_guard<std::mutex> lock(CapturesMutex);
        if (mappingGeneration != 0)
        {
            const auto previous = CandidateCaptures.find(mappingGeneration);
            if (previous != CandidateCaptures.end() && (previous->second.Persisted ||
                request.SubmittedMs - previous->second.LastAttemptMs < 5000))
            {
                return false;
            }
        }
        if (CapturedBytes >= 256ull * 1024 * 1024 || !CapturedKeys.insert(request.Key).second)
        {
            return false;
        }
        if (mappingGeneration != 0)
        {
            if (CandidateCaptures.count(mappingGeneration) == 0 && CandidateCaptures.size() >= 16384)
            {
                const auto oldest = std::min_element(CandidateCaptures.begin(), CandidateCaptures.end(),
                    [](const auto& a, const auto& b)
                    {
                        return a.second.LastAttemptMs < b.second.LastAttemptMs;
                    });
                CandidateCaptures.erase(oldest);
            }
            CandidateCaptures[mappingGeneration].LastAttemptMs = request.SubmittedMs;
        }
    }
    if (!PriorityCaptures.Push(request))
    {
        std::lock_guard<std::mutex> lock(CapturesMutex);
        CapturedKeys.erase(request.Key);
        CaptureFailed.fetch_add(1);
        return false;
    }
    CaptureQueued.fetch_add(1);
    if (note != nullptr)
    {
        *note = L" capture_queued=" + std::to_wstring(request.Id) + L" requested_bytes=" + std::to_wstring(request.Size);
    }
    return true;
}

uint64_t KernelMonitor::QueueCapturedBytes(const std::wstring& role, uint64_t address,
    const ObservationContext& context, const std::vector<uint8_t>& bytes)
{
    if (bytes.empty() || bytes.size() > 4096)
    {
        return 0;
    }
    CapturedPage page;
    page.Id = NextCaptureId.fetch_add(1);
    page.Address = address;
    page.RequestedBytes = bytes.size();
    page.Context = context;
    page.Context.Timestamp = context.Timestamp == 0 ? ObservationFileTime() : context.Timestamp;
    page.Context.MonotonicMs = context.MonotonicMs == 0 ? GetTickCount64() : context.MonotonicMs;
    page.Role = role;
    page.Bytes = bytes;
    const uint64_t id = page.Id;
    if (!CapturedPages.Push(std::move(page)))
    {
        CaptureFailed.fetch_add(1);
        return 0;
    }
    return id;
}

void KernelMonitor::CaptureLoop()
{
    size_t priorityBurst = 0;
    while (!CaptureStopping.load() || PriorityCaptures.Size() != 0 || ContinuedCaptures.Size() != 0)
    {
        CaptureRequest work;
        bool present = false;
        if (priorityBurst >= 8)
        {
            present = ContinuedCaptures.Pop(&work);
            priorityBurst = 0;
        }
        if (!present)
        {
            present = PriorityCaptures.Pop(&work);
            ++priorityBurst;
        }
        if (!present)
        {
            present = ContinuedCaptures.Pop(&work);
        }
        if (!present)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        bool success = false;
        try
        {
            DeviceClient* device = nullptr;
            {
                std::lock_guard<std::mutex> lock(StateMutex);
                device = Device;
            }
            bool byteBudget = false;
            {
                std::lock_guard<std::mutex> lock(CapturesMutex);
                byteBudget = CapturedBytes < 256ull * 1024 * 1024;
            }
            if (!byteBudget || (CaptureStopping.load() && work.Offset != 0))
            {
                KmonEvent event;
                event.Kind = L"coverage.capture";
                event.Observation.Identity = work.Identity;
                event.Summary = byteBudget ? L"capture continuation cancelled during shutdown" : L"capture byte budget exhausted";
                event.Evidence[L"capture_id"] = std::to_wstring(work.Id);
                event.Evidence[L"resume_offset"] = std::to_wstring(work.Offset);
                PipelineEvents.Push(std::move(event));
                CaptureFailed.fetch_add(1);
                std::lock_guard<std::mutex> lock(CapturesMutex);
                CapturedKeys.erase(work.Key);
                continue;
            }
            CapturedPage page;
            page.Id = work.Id;
            page.Offset = work.Offset;
            page.Address = work.Address + work.Offset;
            page.RequestedBytes = work.Size;
            page.Role = work.Role;
            page.Context.Identity = work.Identity;
            page.Context.MappingGeneration = work.MappingGeneration;
            page.Context.Source = L"priority_capture";
            page.Context.Timestamp = ObservationFileTime();
            page.Context.MonotonicMs = GetTickCount64();
            page.Context.Coverage.Attempted = true;
            const uint32_t count = static_cast<uint32_t>((std::min<uint64_t>)(work.Size - work.Offset,
                work.Offset == 0 ? 4096 - (page.Address & 4095) : 16384));
            if (work.Identity.ProcessId == 0)
            {
                PhysicalTranslationInfo before = {};
                PhysicalTranslationInfo after = {};
                const bool translated = device != nullptr && device->TranslateVirtual(0, page.Address, 1, &before, nullptr);
                success = device != nullptr && page.Address >= 0xFFFF800000000000ull &&
                    device->ReadMemory(page.Address, count, &page.Bytes, nullptr) && page.Bytes.size() == count;
                if (success && translated && device->TranslateVirtual(0, page.Address, 1, &after, nullptr) &&
                    before.PhysicalAddress == after.PhysicalAddress)
                {
                    page.Context.PfnKnown = true;
                    page.Context.Pfn = before.PhysicalAddress >> 12;
                    if (((before.Pml5e | before.Pml4e | before.Pdpte | before.Pde | before.Pte) >> 63) == 0)
                    {
                        page.Context.Coverage.InventoryAvailable = true;
                    }
                }
            }
            else
            {
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, work.Identity.ProcessId);
                const std::unique_ptr<void, decltype(&CloseHandle)> owner(process, &CloseHandle);
                if (process != nullptr && work.Identity.SameInstance(ObserveProcessIdentity(work.Identity.ProcessId, process)))
                {
                    MEMORY_BASIC_INFORMATION region = {};
                    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(page.Address), &region, sizeof(region)) == sizeof(region))
                    {
                        page.Context.AllocationBase = reinterpret_cast<uint64_t>(region.AllocationBase);
                        page.Context.Coverage.InventoryAvailable = region.State == MEM_COMMIT &&
                            (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    }
                    page.Bytes.resize(count);
                    SIZE_T read = 0;
                    success = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(page.Address), page.Bytes.data(), count, &read) && read == count;
                }
                if (!success && device != nullptr)
                {
                    success = device->ReadProcessVirtual(work.Identity.ProcessId, work.Identity.Eprocess,
                        work.Identity.CreateTime, page.Address, count, &page.Bytes, nullptr) && page.Bytes.size() == count;
                }
            }
            const uint64_t now = GetTickCount64();
            page.FirstDelayMs = now - work.SubmittedMs;
            if (work.EventTimestamp != 0 && ObservationFileTime() >= work.EventTimestamp)
            {
                page.FirstDelayMs = (std::max)(page.FirstDelayMs, (ObservationFileTime() - work.EventTimestamp) / 10000);
            }
            if (success)
            {
                if (work.Offset == 0)
                {
                    UpdateMaximum(CaptureFirstMaxMs, page.FirstDelayMs);
                }
                page.Context.Coverage.RequestedBytes = count;
                page.Context.Coverage.ComparedBytes = count;
                page.Context.Coverage.Reason = L"bytes_captured_not_integrity_verified";
                success = CapturedPages.Push(std::move(page));
                if (success)
                {
                    work.Offset += count;
                }
            }
            if (!success)
            {
                KmonEvent event;
                event.Kind = L"coverage.capture";
                event.ProcessId = work.Identity.ProcessId;
                event.Observation.Identity = work.Identity;
                event.Observation.Source = L"priority_capture";
                event.Summary = L"capture read, identity, or persistence queue failed";
                event.Evidence[L"capture_id"] = std::to_wstring(work.Id);
                event.Evidence[L"failed_offset"] = std::to_wstring(work.Offset);
                event.Evidence[L"first_byte_delay_ms"] = std::to_wstring(now - work.SubmittedMs);
                PipelineEvents.Push(std::move(event));
            }
        }
        catch (...)
        {
            success = false;
        }
        if (success && work.Offset < work.Size)
        {
            if (ContinuedCaptures.Push(work))
            {
                continue;
            }
            success = false;
        }
        if (!success)
        {
            CaptureFailed.fetch_add(1);
        }
        std::lock_guard<std::mutex> lock(CapturesMutex);
        CapturedKeys.erase(work.Key);
    }
}

void KernelMonitor::CaptureWriterLoop()
{
    while (!WriterStopping.load() || CapturedPages.Size() != 0)
    {
        CapturedPage page;
        if (!CapturedPages.Pop(&page))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        try
        {
            std::wstring directory;
            {
                std::lock_guard<std::mutex> lock(StateMutex);
                directory = Options.LogDirectory;
            }
            if (directory.empty())
            {
                wchar_t executable[32768] = {};
                GetModuleFileNameW(nullptr, executable, 32768);
                directory = std::filesystem::path(executable).parent_path().wstring();
            }
            directory += L"\\captures";
            std::error_code ignored;
            std::filesystem::create_directories(directory, ignored);
            const std::wstring path = directory + L"\\capture-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(StartTickMs.load()) + L"-" + std::to_wstring(page.Id) + L"-" + std::to_wstring(page.Offset) + L".bin";
            bool allowed = false;
            {
                std::lock_guard<std::mutex> lock(CapturesMutex);
                allowed = CapturedBytes + page.Bytes.size() <= 256ull * 1024 * 1024;
                if (allowed)
                {
                    CapturedBytes += page.Bytes.size();
                }
            }
            bool written = false;
            if (allowed)
            {
                HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (file != INVALID_HANDLE_VALUE)
                {
                    DWORD count = 0;
                    written = WriteFile(file, page.Bytes.data(), static_cast<DWORD>(page.Bytes.size()), &count, nullptr) && count == page.Bytes.size();
                    if (written)
                    {
                        written = FlushFileBuffers(file) != FALSE;
                    }
                    CloseHandle(file);
                    if (!written)
                    {
                        DeleteFileW(path.c_str());
                    }
                }
            }
            if (allowed && !written)
            {
                std::lock_guard<std::mutex> lock(CapturesMutex);
                CapturedBytes -= page.Bytes.size();
            }
            const std::wstring hash = ContentHash::Bytes(page.Bytes);
            if (page.Role == L"modified_code" || (page.Context.Coverage.InventoryAvailable &&
                (page.Role == L"kernel_exec_candidate" || page.Role == L"user_exec_candidate")))
            {
                ExecutableRegionObservation region;
                region.Context = page.Context;
                region.Context.Source = L"captured_bytes";
                region.Context.DependencyGroup = L"memory_capture";
                region.Range = {page.Address, page.Bytes.size()};
                region.Executable = true;
                region.ContentSha256 = hash;
                region.ContentBytes = page.Bytes.size();
                CapturedRegions.Push(std::move(region));
            }
            KmonEvent event;
            event.Kind = L"coverage.capture";
            event.ProcessId = page.Context.Identity.ProcessId;
            event.Observation = page.Context;
            event.Summary = written ? L"captured bytes persisted" : L"capture persistence failed or session byte budget exhausted";
            event.Evidence[L"capture_id"] = std::to_wstring(page.Id);
            event.Evidence[L"capture_role"] = page.Role;
            event.Evidence[L"capture_path"] = written ? path : L"";
            event.Evidence[L"capture_sha256"] = hash;
            event.Evidence[L"capture_bytes"] = std::to_wstring(page.Bytes.size());
            event.Evidence[L"requested_bytes"] = std::to_wstring(page.RequestedBytes);
            event.Evidence[L"address"] = std::to_wstring(page.Address);
            event.Evidence[L"chunk_offset"] = std::to_wstring(page.Offset);
            event.Evidence[L"first_byte_delay_ms"] = std::to_wstring(page.FirstDelayMs);
            event.Evidence[L"mapping_consistency"] = page.Context.PfnKnown ? L"pfn_checked_before_and_after" : L"unverified";
            event.Evidence[L"persistence"] = written ? L"complete" : L"failed";
            PipelineEvents.Push(std::move(event));
            if (written)
            {
                std::lock_guard<std::mutex> lock(CapturesMutex);
                const auto candidate = CandidateCaptures.find(page.Context.MappingGeneration);
                if (candidate != CandidateCaptures.end() && page.Offset == 0)
                {
                    candidate->second.Persisted = true;
                }
                if (CapturedFiles.size() < 65536)
                {
                    CapturedFiles.push_back(path);
                }
            }
            else
            {
                CaptureFailed.fetch_add(1);
            }
        }
        catch (...)
        {
            CaptureFailed.fetch_add(1);
        }
    }
}

void KernelMonitor::DrainPipelineEvents(bool finalDrain)
{
    for (auto& observation : CapturedRegions.Drain(finalDrain ? 2048 : 512))
    {
        ObserveExecutableRegion(std::move(observation));
    }
    for (auto& event : PipelineEvents.Drain(512))
    {
        RecordEvent(std::move(event));
    }
    const uint64_t now = GetTickCount64();
    if (finalDrain || now >= NextPipelineStatusMs)
    {
        KmonEvent event;
        event.Kind = L"coverage.pipeline";
        event.Summary = L"collector, capture and analysis coverage";
        event.Observation.Source = L"scheduler";
        event.Observation.Coverage.Attempted = true;
        event.Observation.Coverage.LostEvents = CollectionLost.load() + CollectedTi.Loss() + CollectedLive.Loss();
        event.Observation.Coverage.Reason = TiAvailable.load() ? L"ti_active_coverage_not_guaranteed" : L"ti_unavailable";
        event.Evidence[L"interval_end_ms"] = std::to_wstring(now);
        event.Evidence[L"collector_last_ms"] = std::to_wstring(CollectorLastMs.load());
        event.Evidence[L"collector_max_gap_ms"] = std::to_wstring(CollectorMaxGapMs.load());
        event.Evidence[L"ti_session_lost"] = std::to_wstring(TiSessionLost.load());
        event.Evidence[L"analysis_pending"] = std::to_wstring(CollectedTi.Size() + CollectedLive.Size());
        event.Evidence[L"capture_pending"] = std::to_wstring(PriorityCaptures.Size() + ContinuedCaptures.Size());
        event.Evidence[L"capture_queue_dropped"] = std::to_wstring(PriorityCaptures.Loss() + ContinuedCaptures.Loss());
        event.Evidence[L"persistence_queue_dropped"] = std::to_wstring(CapturedPages.Loss());
        event.Evidence[L"diagnostic_queue_dropped"] = std::to_wstring(PipelineEvents.Loss());
        event.Evidence[L"catalog_queue_dropped"] = std::to_wstring(CapturedRegions.Loss());
        const auto layout = LayoutMonitor.Stats();
        event.Evidence[L"layout_tracked"] = std::to_wstring(layout.Tracked);
        event.Evidence[L"layout_completed"] = std::to_wstring(layout.Completed);
        event.Evidence[L"layout_failed"] = std::to_wstring(layout.Failed);
        event.Evidence[L"layout_pending"] = std::to_wstring(LayoutCandidates.Size());
        event.Evidence[L"layout_dropped"] = std::to_wstring(LayoutCandidates.Loss());
        event.Evidence[L"layout_checked"] = std::to_wstring(LayoutChecked.load());
        event.Evidence[L"layout_rejected"] = std::to_wstring(LayoutRejected.load());
        event.Evidence[L"layout_oldest_ms"] = std::to_wstring(layout.OldestAgeMs);
        event.Evidence[L"catalog_stale_observations"] = std::to_wstring(RegionCatalog.StaleObservations);
        event.Evidence[L"catalog_rejected"] = std::to_wstring(RegionCatalog.Rejected);
        event.Evidence[L"catalog_links_evicted"] = std::to_wstring(RegionCatalog.LinksEvicted);
        event.Evidence[L"execution_references_dropped"] = std::to_wstring(ExecutionReferenceDropped);
        event.Evidence[L"final_drain"] = finalDrain ? L"true" : L"false";
        event.Evidence[L"first_capture_max_ms"] = std::to_wstring(CaptureFirstMaxMs.load());
        event.Evidence[L"capture_failures"] = std::to_wstring(CaptureFailed.load());
        event.Evidence[L"analysis_budget_exceeded"] = std::to_wstring(AnalysisBudgetExceeded.load());
        RecordEvent(std::move(event));
        NextPipelineStatusMs = now + 5000;
    }
}

bool KmonPipelineSelfTest()
{
    bool ok = false;
    wchar_t temporary[MAX_PATH] = {};
    wchar_t unique[MAX_PATH] = {};
    if (GetTempPathW(MAX_PATH, temporary) == 0 || GetTempFileNameW(temporary, L"knp", 0, unique) == 0)
    {
        return false;
    }
    DeleteFileW(unique);
    if (!CreateDirectoryW(unique, nullptr))
    {
        return false;
    }
    KernelMonitor monitor;
    monitor.Options.LogDirectory = unique;
    monitor.StartTickMs.store(GetTickCount64());
    void* allocation = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    const std::wstring referencePath = std::wstring(unique) + L"\\reference.exe";
    try
    {
        do
        {
            if (allocation == nullptr)
            {
                break;
            }
            std::vector<uint8_t> expected(4096, 0x53);
            std::memcpy(allocation, expected.data(), expected.size());
            DWORD previous = 0;
            if (!VirtualProtect(allocation, 4096, PAGE_EXECUTE_READ, &previous))
            {
                break;
            }
            monitor.CaptureWorker = std::thread(&KernelMonitor::CaptureLoop, &monitor);
            const auto identity = ObserveProcessIdentity(GetCurrentProcessId());
            if (!monitor.QueueCapture(L"selftest_rx", reinterpret_cast<uint64_t>(allocation), 4096,
                identity, ObservationFileTime(), nullptr, 42))
            {
                break;
            }
            const uint64_t deadline = GetTickCount64() + 3000;
            while (monitor.CapturedPages.Size() == 0 && GetTickCount64() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (monitor.CapturedPages.Size() != 1)
            {
                break;
            }
            // The source disappears while persistence is deliberately paused.
            // The writer must consume preserved bytes rather than reread it.
            VirtualFree(allocation, 0, MEM_RELEASE);
            allocation = nullptr;
            monitor.CaptureStopping.store(true);
            monitor.CaptureWorker.join();
            monitor.CaptureWriter = std::thread(&KernelMonitor::CaptureWriterLoop, &monitor);
            monitor.WriterStopping.store(true);
            monitor.CaptureWriter.join();
            const auto captures = monitor.SessionCapturePaths();
            ok = captures.size() == 1 && ContentHash::File(captures[0]) == ContentHash::Bytes(expected) &&
                monitor.CaptureFailed.load() == 0 && monitor.CaptureFirstMaxMs.load() < 3000;
            monitor.CaptureStopping.store(false);
            monitor.CandidateCaptures.at(42).LastAttemptMs = 0;
            ok = ok && !monitor.QueueCapture(L"selftest_rx", 0x10000, 4096,
                identity, ObservationFileTime(), nullptr, 42);
            auto stale = identity;
            ++stale.CreateTime;
            monitor.CaptureWorker = std::thread(&KernelMonitor::CaptureLoop, &monitor);
            monitor.QueueCapture(L"selftest_stale", 0x10000, 4096, stale, ObservationFileTime(), nullptr, 43);
            monitor.CaptureStopping.store(true);
            monitor.CaptureWorker.join();
            ok = ok && monitor.CaptureFailed.load() == 1;
            monitor.CaptureStopping.store(false);
            ok = ok && !monitor.QueueCapture(L"selftest_stale", 0x10000, 4096,
                stale, ObservationFileTime(), nullptr, 43);
            monitor.CandidateCaptures.at(43).LastAttemptMs = 0;
            ok = ok && monitor.QueueCapture(L"selftest_stale", 0x10000, 4096,
                stale, ObservationFileTime(), nullptr, 43);
            KernelMonitor::CaptureRequest retry;
            ok = ok && monitor.PriorityCaptures.Pop(&retry) && retry.MappingGeneration == 43;
            monitor.CapturedKeys.erase(retry.Key);
            monitor.CaptureStopping.store(true);
            const std::wstring blockedPath = std::wstring(unique) + L"\\blocked";
            HANDLE blocker = CreateFileW(blockedPath.c_str(), GENERIC_WRITE, 0, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (blocker == INVALID_HANDLE_VALUE)
            {
                ok = false;
                break;
            }
            CloseHandle(blocker);
            const uint64_t savedBudget = monitor.CapturedBytes;
            monitor.Options.LogDirectory = blockedPath;
            ObservationContext captureContext;
            captureContext.Identity = identity;
            const uint64_t queued = monitor.QueueCapturedBytes(L"selftest_persist_failure", 0x10000, captureContext, expected);
            monitor.CaptureWriterLoop();
            monitor.Options.LogDirectory = unique;
            DeleteFileW(blockedPath.c_str());
            ok = ok && queued != 0 && monitor.CapturedBytes == savedBudget && monitor.CaptureFailed.load() == 2;
            // More than one normal analysis batch must survive final shutdown.
            for (uint64_t i = 0; i < 600; ++i)
            {
                ExecutableRegionObservation region;
                region.Context.Identity = identity;
                region.Context.Source = L"shutdown_selftest";
                region.Context.MonotonicMs = GetTickCount64();
                region.Range = {0x100000 + i * 4096, 4096};
                region.Executable = true;
                ok = monitor.CapturedRegions.Push(std::move(region)) && ok;
            }
            monitor.NextPipelineStatusMs = UINT64_MAX;
            monitor.Stop(nullptr);
            ok = ok && monitor.CapturedRegions.Size() == 0 && monitor.CatalogRecords.load() == 600;
            bool finalStats = false;
            for (const auto& event : monitor.Ring)
            {
                const auto marker = event.Evidence.find(L"final_drain");
                finalStats = finalStats || (event.Kind == L"coverage.pipeline" &&
                    marker != event.Evidence.end() && marker->second == L"true");
            }
            ok = ok && finalStats;
            wchar_t executable[32768] = {};
            GetModuleFileNameW(nullptr, executable, 32768);
            if (!CopyFileW(executable, referencePath.c_str(), TRUE))
            {
                ok = false;
                break;
            }
            auto work = monitor.FindImageWork(referencePath, 0x140000000ull, identity);
            if (work == nullptr)
            {
                ok = false;
                break;
            }
            work->ManifestChecked = true;
            HANDLE append = CreateFileW(referencePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr);
            DWORD written = 0;
            const uint8_t value = 0;
            const bool appended = append != INVALID_HANDLE_VALUE && WriteFile(append, &value, 1, &written, nullptr) && written == 1;
            if (append != INVALID_HANDLE_VALUE)
            {
                CloseHandle(append);
            }
            work->LastReferenceCheckMs = 0;
            work = monitor.FindImageWork(referencePath, 0x140000000ull, identity);
            ok = ok && appended && work != nullptr && !work->ManifestChecked;

            // A queued image name must still describe the live allocation.
            monitor.StopRequested.store(false);
            ProcessLayoutCandidate candidate;
            candidate.Identity = identity;
            candidate.Role = L"layout_selftest";
            candidate.ObservedAt = ObservationFileTime();
            candidate.ObservedMs = GetTickCount64();
            MEMORY_BASIC_INFORMATION imageRegion{};
            wchar_t otherImage[1024]{};
            const DWORD otherLength = GetMappedFileNameW(GetCurrentProcess(), GetModuleHandleW(L"ntdll.dll"), otherImage, 1024);
            const bool imageReady = VirtualQuery(reinterpret_cast<void*>(&KmonPipelineSelfTest),
                &imageRegion, sizeof(imageRegion)) == sizeof(imageRegion) && otherLength != 0 && otherLength < 1024;
            if (imageReady)
            {
                candidate.Region = {reinterpret_cast<uint64_t>(imageRegion.BaseAddress), imageRegion.RegionSize,
                    reinterpret_cast<uint64_t>(imageRegion.AllocationBase), imageRegion.State, imageRegion.Protect,
                    imageRegion.AllocationProtect, imageRegion.Type};
                candidate.ImageName.assign(otherImage, otherLength);
                monitor.LayoutCandidates.Push(candidate);
                monitor.DrainLayoutCandidates();
            }
            const bool staleRejected = imageReady && monitor.LayoutRejected.load() == 1 && monitor.LayoutChecked.load() == 0;
            if (!staleRejected)
            {
                std::fprintf(stderr, "FAIL layout stale mapped-name revalidation\n");
            }
            ok = staleRejected && ok;

            const DWORD currentLength = imageReady ? GetMappedFileNameW(GetCurrentProcess(),
                imageRegion.BaseAddress, otherImage, 1024) : 0;
            if (currentLength != 0 && currentLength < 1024)
            {
                candidate.ImageName.assign(otherImage, currentLength);
                candidate.ObservedMs = GetTickCount64();
                monitor.LayoutCandidates.Push(candidate);
                monitor.DrainLayoutCandidates();
            }
            const bool imageChecked = currentLength != 0 && currentLength < 1024 &&
                monitor.LayoutChecked.load() == 1 && monitor.LayoutRejected.load() == 1;
            if (!imageChecked)
            {
                std::fprintf(stderr, "FAIL layout current mapped-name positive control\n");
            }
            ok = imageChecked && ok;

            // A passive COW mapping exercises the actual catalog projection.
            HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, 4096, nullptr);
            const std::unique_ptr<void, decltype(&CloseHandle)> sectionOwner(section, &CloseHandle);
            void* view = section == nullptr ? nullptr : MapViewOfFile(section, FILE_MAP_COPY | FILE_MAP_EXECUTE, 0, 0, 4096);
            const std::unique_ptr<void, decltype(&UnmapViewOfFile)> viewOwner(view, &UnmapViewOfFile);
            MEMORY_BASIC_INFORMATION cowRegion{};
            const bool cowReady = view != nullptr && VirtualQuery(view, &cowRegion, sizeof(cowRegion)) == sizeof(cowRegion) &&
                cowRegion.Protect == PAGE_EXECUTE_WRITECOPY;
            if (cowReady)
            {
                candidate.Region = {reinterpret_cast<uint64_t>(cowRegion.BaseAddress), cowRegion.RegionSize,
                    reinterpret_cast<uint64_t>(cowRegion.AllocationBase), cowRegion.State, cowRegion.Protect,
                    cowRegion.AllocationProtect, cowRegion.Type};
                candidate.ImageName.clear();
                candidate.ObservedMs = GetTickCount64();
                monitor.LayoutCandidates.Push(candidate);
                monitor.DrainLayoutCandidates();
            }
            bool cowRecorded = false;
            for (const auto& record : monitor.RegionCatalog.Snapshot())
            {
                const auto& observed = record.second.Latest;
                cowRecorded = cowRecorded || (observed.Range.Address == reinterpret_cast<uint64_t>(view) &&
                    observed.Context.Source == L"layout_selftest" && observed.CopyOnWrite && observed.Writable);
            }
            if (!cowReady || !cowRecorded)
            {
                std::fprintf(stderr, "FAIL layout copy-on-write catalog metadata\n");
            }
            ok = cowReady && cowRecorded && ok;
        } while (false);
    }
    catch (...)
    {
        ok = false;
    }
    monitor.Stop(nullptr);
    DeleteFileW(referencePath.c_str());
    if (allocation != nullptr)
    {
        VirtualFree(allocation, 0, MEM_RELEASE);
    }
    for (const auto& path : monitor.SessionCapturePaths())
    {
        DeleteFileW(path.c_str());
    }
    for (const auto& path : monitor.SessionLogPaths())
    {
        DeleteFileW(path.c_str());
    }
    RemoveDirectoryW((std::wstring(unique) + L"\\captures").c_str());
    RemoveDirectoryW(unique);
    return ok;
}
