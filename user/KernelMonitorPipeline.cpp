#include "KernelMonitor.h"
#include "ContentHash.h"
#include "McpJson.h"
#include "EvidenceInvestigation.h"

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
    // Only describe an unreadable whole-page range covered exclusively by a
    // discardable section in the header actually captured from this image.
    // Invalid/overlapping/truncated metadata never grants an exclusion.
    bool DiscardableCapturePage(const std::vector<uint8_t>& header, uint64_t imageSize,
        uint64_t offset, uint32_t count, std::wstring* sectionName)
    {
        if (header.size() < sizeof(IMAGE_DOS_HEADER) || count == 0 || offset >= imageSize || count > imageSize - offset)
        { return false; }
        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, header.data(), sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
            static_cast<size_t>(dos.e_lfanew) > header.size() - sizeof(IMAGE_DOS_HEADER)) { return false; }
        const size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
        if (header.size() - ntOffset < sizeof(IMAGE_NT_HEADERS64)) { return false; }
        IMAGE_NT_HEADERS64 nt{};
        std::memcpy(&nt, header.data() + ntOffset, sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96 ||
            nt.OptionalHeader.SizeOfImage != imageSize || nt.OptionalHeader.SectionAlignment != 4096 ||
            offset < nt.OptionalHeader.SizeOfHeaders) { return false; }
        const size_t table = ntOffset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        if (table > header.size() || nt.FileHeader.NumberOfSections > (header.size() - table) / sizeof(IMAGE_SECTION_HEADER))
        { return false; }
        bool found = false;
        for (size_t i = 0; i < nt.FileHeader.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER section{};
            std::memcpy(&section, header.data() + table + i * sizeof(section), sizeof(section));
            const uint64_t start = section.VirtualAddress;
            const uint64_t length = (std::max<uint64_t>)(section.Misc.VirtualSize, section.SizeOfRawData);
            const uint64_t end = start + ((length + 4095) & ~4095ull);
            if (start % 4096 != 0 || end > imageSize) { return false; }
            if (start < offset + count && end > offset)
            {
                if (found || start > offset || end < offset + count ||
                    (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) { return false; }
                found = true;
                sectionName->clear();
                for (const auto ch : section.Name) { if (ch == 0) { break; } sectionName->push_back(ch); }
            }
        }
        return found;
    }

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

    bool TiCaptureMatchesIdentity(const TiEventRecord& event, const ObservationIdentity& identity)
    {
        return identity.ProcessId != 0 && event.TargetProcessId == identity.ProcessId &&
            identity.CreateTime != 0 && event.TargetProcessCreateTime == identity.CreateTime &&
            event.Timestamp >= identity.CreateTime;
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
    CaptureTimings.Reset();
    CapturedPages.Reset();
    CapturedEvidenceBundles.Reset();
    EvidenceCollectionEpoch.store(KmonHuntQueryEpochSeed());
    EvidenceQueued.store(0);
    EvidenceWritten.store(0);
    EvidenceFailed.store(0);
    EvidenceDropped.store(0);
    EvidenceBytes.store(0);
    EvidenceLedgerFailed.store(0);
    PipelineEvents.Reset();
    CapturedRegions.Reset();
    CaptureStopping.store(false);
    CaptureStopDeadlineMs.store(0);
    WriterStopping.store(false);
    CaptureWorkerDone.store(false);
    CaptureWriterDone.store(false);
    CollectorLastMs.store(0);
    CollectorMaxGapMs.store(0);
    CollectionLost.store(0);
    TiSessionLost.store(0);
    TiAvailable.store(false);
    CaptureQueued.store(0);
    CaptureFailed.store(0);
    CaptureReadBytes.store(0);
    CaptureReadFailedBytes.store(0);
    CaptureUnreadableBytes.store(0);
    CaptureDiscardableUnreadableBytes.store(0);
    CaptureKernelContinuations.store(0);
    CaptureRootLayoutResolutions.store(0);
    CaptureRootIdentityChecks.store(0);
    CaptureReadFailedRequests.store(0);
    CaptureFallbackPages.store(0);
    CaptureTraversed.store(0);
    ShutdownLayoutProcessed = 0;
    ShutdownReferencesProcessed = 0;
    ShutdownDrainMs = 0;
    ShutdownEventsProcessed = 0;
    ShutdownEventsUnanalyzed = 0;
    CaptureFirstMaxMs.store(0);
    UserScanCursor.store(0);
    UserOldestScanMs.store(0);
    AnalysisBudgetExceeded.store(0);
    AnalysisLastCompleteMs.store(0);
    ImageRemainingPages.store(0);
    ImageLastCompleteMs.store(0);
    ImageSweepProcessCursors[0] = {};
    ImageSweepProcessCursors[1] = {};
    ImageSweepGroupTurns = {};
    ImageSweepClassTurns = {};
    ImageBorrowedBackgroundTurns = 0;
    ImageCompletionPriorityTurns = 0;
    ImageBulkProgressTurns = 0;
    NextImageSweepMs = 0;
    ImageSweepTurns = 0;
    ImageAdmissionDeferred = 0;
    ImageWatchAdmissionDeferred = 0;
    NextImageAdmissionReportMs = 0;
    ImageRescanDelays.clear();
    ImageRescanDelayHits = 0;
    ImageRescanHistoryHits = 0;
    UserLastScanMs.clear();
    UserLayoutLeads.clear();
    UrgentUserPidCursor = 0;
    WatchedReferenceSchedule = {};
    UserMemoryAnalysisYields.store(0);
    HeapPageCursors.clear();
    HighPriorityPidCursor = 0;
    LayoutExpired.store(0);
    LayoutMaxQueueWaitMs.store(0);
    LayoutMaxSourceWaitMs.store(0);
    LayoutMaxServiceGapMs.store(0);
    LayoutLastServiceMs = 0;
    LayoutMaxServiceGapBefore.clear();
    BackgroundPidCursor = 0;
    NextPipelineStatusMs = 0;
}

void KernelMonitor::ServicePendingAnalysis(const wchar_t* before)
{
    if (ServicingAnalysis || StopRequested.load()) { return; }
    ServicingAnalysis = true;
    struct Reset { bool& Flag; ~Reset() { Flag = false; } } reset{ServicingAnalysis};
    // All verifier/catalog state stays on the analysis thread. Yield at safe
    // scan boundaries instead of waiting for an entire multi-scanner pass.
    const auto serviceReferences = [this]()
    {
        if (!ExecutionReferences.empty())
        {
            ScanExecutionReferences(128, KmonReferenceDrainBudget(ExecutionReferences.size(),
                GetTickCount64(), ExecutionReferences.front().ObservedMs));
        }
    };
    // Older work gets a bounded turn before ingestion can add another burst.
    serviceReferences();
    DrainLayoutCandidates(false, before);
    IngestLiveTimeline();
    IngestThreatIntel();
    DrainIotraceEvents();
    DrainPipelineEvents();
    DrainLayoutCandidates(false, L"after_event_ingestion");
    ServiceWatchedReferences();
    serviceReferences();
    ContinueImageSweeps();
}

void KernelMonitor::CollectorLoop()
{
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
            if (ti != nullptr)
            {
                auto events = CollectTiPage(ti);
                size_t captureBudget = 8;
                for (auto& event : events)
                {
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
                                if (TiCaptureMatchesIdentity(event, identity))
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
                CollectLivePage(timeline);
            }
        }
        catch (...)
        {
            CollectionLost.fetch_add(1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

void KernelMonitor::CollectLivePage(TimelineStore* timeline, uint64_t throughEventId)
{
    if (timeline == nullptr) { return; }
    if (LiveCursorEventId != 0 && timeline->PeekNextEventId() <= LiveCursorEventId)
    {
        LiveCursorEventId = 0;
        CollectionLost.fetch_add(1);
    }
    const size_t room = (std::min<size_t>)(512, CollectedLive.Available());
    if (room == 0 || LiveCursorEventId >= throughEventId) { return; }
    // The collector is the sole producer (Stop takes over only after joining
    // it). Leave excess events in the timeline instead of consuming/dropping
    // them. RecentAfterEventId treats a zero limit as unlimited.
    auto events = timeline->RecentAfterEventId(LiveCursorEventId, room);
    for (auto& event : events)
    {
        const uint64_t next = (std::min)(event.EventId, throughEventId);
        if (next > LiveCursorEventId)
        {
            const uint64_t missing = next - LiveCursorEventId - (event.EventId <= throughEventId ? 1 : 0);
            if (missing != 0) { CollectionLost.fetch_add(missing); }
        }
        LiveCursorEventId = next;
        if (event.EventId > throughEventId) { break; }
        if (Lower(event.Source) != L"kernel-live") { continue; }
        KmonEvent classified;
        const bool known = KmonClassifyLiveEvent(event, &classified);
        if (known && (classified.Kind == L"process.create" || classified.Kind == L"process.masquerade"))
        {
            LayoutMonitor.RequestDiscovery();
        }
        if (known && (classified.Kind == L"driver.drop_load" || classified.Kind == L"driver.official_load" ||
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

bool KernelMonitor::QueueCapture(const std::wstring& role, uint64_t address, uint64_t size,
    const ObservationIdentity& identity, uint64_t eventTimestamp, std::wstring* note,
    uint64_t mappingGeneration, uint64_t rootCr3)
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
    request.QueuedMs = request.SubmittedMs;
    request.EventTimestamp = eventTimestamp;
    request.MappingGeneration = mappingGeneration;
    request.RootCr3 = rootCr3;
    request.Identity = identity;
    request.Role = role;
    request.Key = identity.BootId + L":" + std::to_wstring(identity.ProcessId) + L":" +
        std::to_wstring(identity.CreateTime) + L":" + std::to_wstring(address) + L":" + role + L":" +
        std::to_wstring(mappingGeneration) + L":" + std::to_wstring(rootCr3);
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
    CaptureWorkerDone.store(false);
    KmonCapturePicker picker;
    const auto timestamps = [](const CaptureRequest& work)
    {
        return std::make_pair(work.QueuedMs, work.SubmittedMs);
    };
    CaptureRequest immediate;
    bool haveImmediate = false;
    size_t quantumPages = 0;
    OrphanRootIdentityLayout rootLayout;
    SymbolEngine* rootLayoutSymbols = nullptr;
    bool rootLayoutKnown = false;
    const auto finished = [this](const CaptureRequest& work, const std::wstring& reason)
    {
        const bool traversed = work.Offset == work.Size;
        if (traversed) { CaptureTraversed.fetch_add(1); }
        const bool gaps = !traversed || work.FailedBytes != 0 || work.SkippedBytes != 0;
        if (gaps) { CaptureFailed.fetch_add(1); }
        if (work.FailedBytes != 0) { CaptureReadFailedRequests.fetch_add(1); }
        KmonEvent event;
        event.Kind = L"coverage.capture_result";
        event.ProcessId = work.Identity.ProcessId;
        event.Observation.Identity = work.Identity;
        event.Observation.Source = L"priority_capture";
        auto& coverage = event.Observation.Coverage;
        coverage.Attempted = true;
        coverage.InventoryAvailable = true;
        coverage.TraversalComplete = traversed;
        coverage.RequestedBytes = work.Size;
        coverage.ComparedBytes = work.ReadBytes;
        coverage.FailedBytes = work.FailedBytes;
        coverage.SkippedBytes = work.SkippedBytes + work.Size - work.Offset;
        coverage.ResumeAddress = traversed ? 0 : work.Address + work.Offset;
        coverage.Reason = traversed ? (gaps ? L"capture_read_complete_with_gaps" : L"capture_read_complete") : reason;
        event.Summary = coverage.Reason;
        event.Evidence[L"capture_id"] = std::to_wstring(work.Id);
        event.Evidence[L"capture_role"] = work.Role;
        event.Evidence[L"address"] = std::to_wstring(work.Address);
        event.Evidence[L"read_completion"] = traversed ? L"true" : L"false";
        event.Evidence[L"read_completion_delay_ms"] = std::to_wstring(GetTickCount64() - work.SubmittedMs);
        event.Evidence[L"unvisited_bytes"] = std::to_wstring(work.Size - work.Offset);
        event.Evidence[L"known_unreadable_bytes"] = std::to_wstring(work.SkippedBytes);
        event.Evidence[L"discardable_unreadable_bytes"] = std::to_wstring(work.DiscardableUnreadableBytes);
        event.Evidence[L"persistence_scope"] = L"per_chunk; consult coverage.capture";
        PipelineEvents.Push(std::move(event));
        std::lock_guard<std::mutex> lock(CapturesMutex);
        CapturedKeys.erase(work.Key);
    };
    while (!CaptureStopping.load() || haveImmediate || PriorityCaptures.Size() != 0 || ContinuedCaptures.Size() != 0)
    {
        const bool shutdownExpired = CaptureStopping.load() && CaptureStopDeadlineMs.load() != 0 &&
            GetTickCount64() >= CaptureStopDeadlineMs.load();
        // A readable image may contain thousands of pages. Let persistence
        // catch up instead of turning successful reads into queue losses.
        if (!shutdownExpired && CapturedPages.Size() >= (haveImmediate ? 388 : 384))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }
        CaptureRequest work;
        bool present = false;
        if (haveImmediate)
        {
            work = std::move(immediate);
            haveImmediate = false;
            present = true;
            ++quantumPages;
        }
        else
        {
            quantumPages = 1;
        }
        if (!present)
        {
            const auto now = GetTickCount64();
            const auto kind = picker.Pick(PriorityCaptures.Timing(now, timestamps), ContinuedCaptures.Timing(now, timestamps));
            if (kind == KmonCaptureClass::Continued)
            {
                present = ContinuedCaptures.Pop(&work);
            }
            else if (kind == KmonCaptureClass::First)
            {
                present = PriorityCaptures.Pop(&work);
            }
            if (present)
            {
                picker.Dispatched(kind);
                CaptureTimings.Dispatch(kind, work.QueuedMs, GetTickCount64(), CaptureStopping.load());
            }
        }
        if (!present)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        bool success = false;
        const bool firstAttempt = work.Offset == 0;
        bool attempted = false;
        bool shutdownAttempt = false;
        uint64_t attemptStarted = 0;
        bool fatal = false;
        bool unreadable = false;
        bool discardableUnreadable = false;
        std::wstring discardableSection;
        std::wstring reason = L"memory_read_failed";
        std::wstring detail;
        const uint32_t count = static_cast<uint32_t>((std::min<uint64_t>)(work.Size - work.Offset,
            4096 - ((work.Address + work.Offset) & 4095)));
        try
        {
            DeviceClient* device = nullptr;
            SymbolEngine* symbols = nullptr;
            {
                std::lock_guard<std::mutex> lock(StateMutex);
                device = Device;
                symbols = Symbols;
            }
            bool byteBudget = false;
            {
                std::lock_guard<std::mutex> lock(CapturesMutex);
                byteBudget = CapturedBytes < 256ull * 1024 * 1024;
            }
            if (!byteBudget || shutdownExpired)
            {
                finished(work, byteBudget ? L"shutdown_capture_budget" : L"session_capture_byte_budget");
                continue;
            }
            CapturedPage page;
            page.Id = work.Id;
            page.Offset = work.Offset;
            page.Address = work.Address + work.Offset;
            page.RequestedBytes = work.Size;
            page.Role = work.Role;
            page.RootCr3 = work.RootCr3;
            page.Context.Identity = work.Identity;
            page.Context.MappingGeneration = work.MappingGeneration;
            page.Context.Source = L"priority_capture";
            page.Context.Timestamp = ObservationFileTime();
            page.Context.MonotonicMs = GetTickCount64();
            attempted = true;
            attemptStarted = page.Context.MonotonicMs;
            shutdownAttempt = CaptureStopping.load();
            page.RequestAgeAtReadStartMs = page.Context.MonotonicMs - work.SubmittedMs;
            page.Context.Coverage.Attempted = true;
            if (work.RootCr3 != 0)
            {
                const OrphanKernelPageRoot root = {work.RootCr3, work.Identity.ProcessId, work.Identity.CreateTime};
                uint64_t beforeProcess = 0;
                uint64_t afterProcess = 0;
                if (rootLayoutSymbols != symbols)
                {
                    rootLayoutSymbols = symbols;
                    rootLayoutKnown = false;
                }
                if (root.ProcessId != 0 && symbols != nullptr && !rootLayoutKnown)
                {
                    CaptureRootLayoutResolutions.fetch_add(1);
                    rootLayoutKnown = ResolveOrphanRootIdentityLayout(*symbols, &rootLayout, &detail);
                }
                const auto readIdentity = [&](uint64_t* process)
                {
                    if (!rootLayoutKnown) { return false; }
                    CaptureRootIdentityChecks.fetch_add(1);
                    return ReadOrphanRootIdentity(*device, rootLayout, root, process, &detail);
                };
                const bool known = device != nullptr && (root.ProcessId == 0 ||
                    readIdentity(&beforeProcess));
                PhysicalTranslationInfo capturedMapping = {};
                // The reader already brackets its physical read with the full
                // page-table identity check. Return that evidence instead of
                // issuing two redundant translations around the same read.
                success = known && ReadOrphanRootMemory(*device, work.RootCr3, page.Address, count,
                    &page.Bytes, &detail, false, &capturedMapping) && page.Bytes.size() == count &&
                    (root.ProcessId == 0 || (readIdentity(&afterProcess) &&
                        beforeProcess == afterProcess));
                if (success)
                {
                    page.Context.Source = L"address_space_root_capture";
                    page.Context.PfnKnown = true;
                    page.Context.Pfn = capturedMapping.PhysicalAddress >> 12;
                }
                else if (!known)
                {
                    reason = L"address_space_identity_unavailable";
                    fatal = true;
                }
            }
            else if (work.Identity.ProcessId == 0)
            {
                PhysicalTranslationInfo before = {};
                PhysicalTranslationInfo after = {};
                const bool translated = device != nullptr && device->TranslateVirtual(0, page.Address, 1, &before, nullptr);
                success = device != nullptr && page.Address >= 0xFFFF800000000000ull &&
                    device->ReadMemory(page.Address, count, &page.Bytes, &detail) && page.Bytes.size() == count;
                if (success && work.Offset == 0 && work.Role == L"driver_image")
                {
                    work.KernelImageHeader = page.Bytes;
                }
                if (!success && !translated && device != nullptr &&
                    DiscardableCapturePage(work.KernelImageHeader, work.Size, work.Offset, count, &discardableSection))
                {
                    std::vector<uint8_t> currentHeader;
                    if (device->ReadMemory(work.Address, static_cast<uint32_t>(work.KernelImageHeader.size()), &currentHeader, nullptr) &&
                        currentHeader == work.KernelImageHeader && !device->TranslateVirtual(0, page.Address, 1, &after, nullptr))
                    {
                        unreadable = true;
                        discardableUnreadable = true;
                        reason = L"unreadable_discardable_section";
                    }
                }
                if (success && translated)
                {
                    success = device->TranslateVirtual(0, page.Address, 1, &after, nullptr) &&
                        before.PhysicalAddress == after.PhysicalAddress;
                    if (!success)
                    {
                        reason = L"mapping_changed_during_capture";
                        fatal = true;
                    }
                    else
                    {
                        page.Context.PfnKnown = true;
                        page.Context.Pfn = before.PhysicalAddress >> 12;
                        page.Context.Coverage.InventoryAvailable =
                            ((before.Pml5e | before.Pml4e | before.Pdpte | before.Pde | before.Pte) >> 63) == 0;
                    }
                }
            }
            else
            {
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, work.Identity.ProcessId);
                if (process == nullptr)
                {
                    detail = L"OpenProcess=" + std::to_wstring(GetLastError());
                    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, work.Identity.ProcessId);
                }
                const std::unique_ptr<void, decltype(&CloseHandle)> owner(process, &CloseHandle);
                MEMORY_BASIC_INFORMATION region{};
                const bool regionKnown = process != nullptr &&
                    VirtualQueryEx(process, reinterpret_cast<LPCVOID>(page.Address), &region, sizeof(region)) == sizeof(region);
                const bool inaccessible = regionKnown && (region.State != MEM_COMMIT ||
                    (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0);
                if (process != nullptr && !work.Identity.SameInstance(ObserveProcessIdentity(work.Identity.ProcessId, process)))
                {
                    reason = L"process_identity_changed";
                    fatal = true;
                }
                else if (inaccessible)
                {
                    // Reading guard pages changes target state. Never fall
                    // back through the driver to bypass a known protection.
                    unreadable = true;
                    reason = region.State != MEM_COMMIT ? L"page_not_committed" : L"page_protection_excluded";
                    detail = L"state=" + std::to_wstring(region.State) + L" protect=" + std::to_wstring(region.Protect);
                }
                else if (process != nullptr)
                {
                    if (regionKnown)
                    {
                        page.Context.AllocationBase = reinterpret_cast<uint64_t>(region.AllocationBase);
                        page.Context.Coverage.InventoryAvailable = region.State == MEM_COMMIT &&
                            (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    }
                    page.Bytes.resize(count);
                    SIZE_T read = 0;
                    success = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(page.Address), page.Bytes.data(), count, &read) && read == count;
                    if (!success) { detail += L" ReadProcessMemory=" + std::to_wstring(GetLastError()); }
                }
                if (!success && !fatal && !inaccessible && device != nullptr && symbols != nullptr)
                {
                    ProcessAddressContext context{};
                    if (work.Identity.Eprocess == 0 &&
                        !ResolveObservationProcess(*device, *symbols, work.Identity, &context))
                    {
                        reason = L"process_identity_unavailable";
                        fatal = true;
                    }
                    else
                    {
                        if (work.Identity.Eprocess == 0) { work.Identity.Eprocess = context.Eprocess; }
                        std::wstring driverError;
                        success = device->ReadProcessVirtual(work.Identity.ProcessId, work.Identity.Eprocess,
                            work.Identity.CreateTime, page.Address, count, &page.Bytes, &driverError) && page.Bytes.size() == count;
                        detail += L" driver=" + driverError;
                        if (success) { CaptureFallbackPages.fetch_add(1); }
                    }
                }
                if (success && process != nullptr)
                {
                    DWORD exitCode = 0;
                    MEMORY_BASIC_INFORMATION after{};
                    success = work.Identity.SameInstance(ObserveProcessIdentity(work.Identity.ProcessId, process)) &&
                        GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE &&
                        (!regionKnown || (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(page.Address), &after, sizeof(after)) == sizeof(after) &&
                            after.AllocationBase == region.AllocationBase && after.BaseAddress == region.BaseAddress &&
                            after.RegionSize == region.RegionSize && after.State == region.State &&
                            after.Type == region.Type && after.Protect == region.Protect));
                    if (!success) { reason = L"mapping_or_process_changed_during_capture"; fatal = true; }
                }
            }
            const uint64_t now = GetTickCount64();
            page.ReadDurationMs = now - page.Context.MonotonicMs;
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
                page.Context.Identity = work.Identity;
                success = CapturedPages.Push(std::move(page));
                if (success)
                {
                    CaptureReadBytes.fetch_add(count);
                    work.ReadBytes += count;
                    work.Offset += count;
                }
                else { reason = L"persistence_queue_full"; fatal = true; }
            }
            if (!success)
            {
                KmonEvent event;
                event.Kind = L"coverage.capture";
                event.ProcessId = work.Identity.ProcessId;
                event.Observation.Identity = work.Identity;
                event.Observation.Source = L"priority_capture";
                event.Summary = reason;
                event.Observation.Coverage.Attempted = true;
                event.Observation.Coverage.RequestedBytes = count;
                if (unreadable)
                {
                    event.Observation.Coverage.SkippedBytes = count;
                    event.Observation.Coverage.Skipped.push_back({page.Address, count});
                }
                else
                {
                    event.Observation.Coverage.FailedBytes = count;
                    event.Observation.Coverage.Failed.push_back({page.Address, count});
                }
                event.Observation.Coverage.Reason = reason;
                event.Evidence[L"capture_id"] = std::to_wstring(work.Id);
                event.Evidence[L"capture_role"] = work.Role;
                event.Evidence[L"address"] = std::to_wstring(page.Address);
                event.Evidence[L"read_error"] = detail;
                event.Evidence[L"discardable_section"] = discardableSection;
                event.Evidence[L"continuing"] = fatal ? L"false" : L"true";
                event.Evidence[L"failed_offset"] = std::to_wstring(work.Offset);
                event.Evidence[L"first_byte_delay_ms"] = std::to_wstring(now - work.SubmittedMs);
                event.Evidence[L"request_age_at_read_start_ms"] = std::to_wstring(page.RequestAgeAtReadStartMs);
                event.Evidence[L"page_read_duration_ms"] = std::to_wstring(page.ReadDurationMs);
                PipelineEvents.Push(std::move(event));
            }
        }
        catch (...)
        {
            success = false;
            fatal = true;
            reason = L"capture_exception";
        }
        if (attempted)
        {
            CaptureTimings.Attempt(work.SubmittedMs, attemptStarted, GetTickCount64(), firstAttempt, success, shutdownAttempt);
        }
        if (!success)
        {
            if (unreadable)
            {
                work.SkippedBytes += count;
                CaptureUnreadableBytes.fetch_add(count);
                if (discardableUnreadable)
                {
                    work.DiscardableUnreadableBytes += count;
                    CaptureDiscardableUnreadableBytes.fetch_add(count);
                }
            }
            else
            {
                work.FailedBytes += count;
                CaptureReadFailedBytes.fetch_add(count);
            }
            work.Offset += count;
        }
        if (!fatal && work.Offset < work.Size)
        {
            // Kernel windows are often only 16 KiB and can disappear while
            // waiting behind every other request between individual pages.
            // Keep a four-page quantum; elapsed wall time can include VM
            // preemption and must not split a 16 KiB window back into the queue.
            // Retain per-page identity, mapping and failure accounting, and
            // check shutdown before every page. Larger requests rotate again.
            if (work.Address >= 0xFFFF800000000000ull && quantumPages < 4 && !shutdownExpired)
            {
                immediate = std::move(work);
                haveImmediate = true;
                CaptureKernelContinuations.fetch_add(1);
                continue;
            }
            work.QueuedMs = GetTickCount64();
            if (ContinuedCaptures.Push(work))
            {
                continue;
            }
            reason = L"continuation_queue_full";
        }
        finished(work, reason);
    }
    CaptureWorkerDone.store(true);
}

uint64_t KernelMonitor::QueueEvidenceBundle(EvidenceBundle bundle)
{
    CapturedEvidence evidence;
    evidence.Id = NextCaptureId.fetch_add(1);
    bundle.CollectionId = std::to_wstring(EvidenceCollectionEpoch.load());
    evidence.Bundle = std::move(bundle);
    const uint64_t id = evidence.Id;
    if (!CapturedEvidenceBundles.Push(std::move(evidence))) { EvidenceDropped.fetch_add(1); return 0; }
    EvidenceQueued.fetch_add(1);
    return id;
}

void KernelMonitor::PersistEvidenceBundle(const CapturedEvidence& evidence) noexcept
{
    bool written = false;
    try
    {
        std::wstring directory;
        { std::lock_guard<std::mutex> lock(StateMutex); directory = Options.LogDirectory; }
        if (directory.empty()) { directory = L"."; }
        const auto folder = std::filesystem::path(directory) / L"cases";
        std::error_code error;
        std::filesystem::create_directories(folder, error);
        const auto path = folder / (L"case-" + evidence.Bundle.CollectionId + L"-" + std::to_wstring(evidence.Id) + L".kncase");
        const auto json = EvidenceBundleJson(evidence.Bundle);
        const auto bytes = mcpjson::WideToUtf8(json).size();
        std::wstring failure = L"invalid_bundle_or_session_byte_budget";
        if (!error && !json.empty() && bytes <= 128ull * 1024 * 1024 - EvidenceBytes.load())
        {
            written = SaveEvidenceBundle(path.wstring(), evidence.Bundle, &failure);
            if (written) { EvidenceBytes.fetch_add(bytes); }
        }
        KmonEvent event;
        event.Kind = L"coverage.evidence_bundle";
        event.ProcessId = evidence.Bundle.Receipt.Reference.Context.Identity.ProcessId;
        event.Observation = evidence.Bundle.Receipt.Reference.Context;
        event.Summary = written ? L"immutable evidence bundle committed" : L"evidence bundle publication failed";
        event.Evidence[L"evidence_id"] = std::to_wstring(evidence.Id);
        event.Evidence[L"collection_id"] = evidence.Bundle.CollectionId;
        event.Evidence[L"evidence_path"] = written ? path.wstring() : L"";
        event.Evidence[L"persistence"] = written ? L"committed" : L"failed";
        event.Evidence[L"failure"] = written ? L"" : failure;
        PipelineEvents.Push(std::move(event));
    }
    catch (...) {}
    if (written) { EvidenceWritten.fetch_add(1); }
    else { EvidenceFailed.fetch_add(1); }
}

void KernelMonitor::CloseEvidenceCollection() noexcept
{
    try
    {
        std::wstring directory;
        { std::lock_guard<std::mutex> lock(StateMutex); directory = Options.LogDirectory; }
        if (directory.empty()) { directory = L"."; }
        const auto folder = std::filesystem::path(directory) / L"cases";
        std::error_code error;
        std::filesystem::create_directories(folder, error);
        const auto collectionId = std::to_wstring(EvidenceCollectionEpoch.load());
        const auto json = EvidenceSessionJson({collectionId, EvidenceQueued.load(), EvidenceWritten.load(),
            EvidenceFailed.load(), EvidenceDropped.load(), EvidenceBytes.load()});
        std::wstring failure;
        if (!error && !json.empty() && SaveObservationJson((folder / (L"session-" + collectionId + L".knledger")).wstring(), json, &failure)) { return; }
    }
    catch (...) {}
    EvidenceLedgerFailed.fetch_add(1);
}

void KernelMonitor::CaptureWriterLoop()
{
    CaptureWriterDone.store(false);
    while (!WriterStopping.load() || CapturedPages.Size() != 0 || CapturedEvidenceBundles.Size() != 0)
    {
        CapturedEvidence evidence;
        const bool haveEvidence = CapturedEvidenceBundles.Pop(&evidence);
        if (haveEvidence) { PersistEvidenceBundle(evidence); }
        CapturedPage page;
        if (!CapturedPages.Pop(&page))
        {
            if (!haveEvidence) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }
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
            event.Evidence[L"root_cr3"] = std::to_wstring(page.RootCr3);
            event.Evidence[L"first_byte_delay_ms"] = std::to_wstring(page.FirstDelayMs);
            event.Evidence[L"request_age_at_read_start_ms"] = std::to_wstring(page.RequestAgeAtReadStartMs);
            event.Evidence[L"page_read_duration_ms"] = std::to_wstring(page.ReadDurationMs);
            event.Evidence[L"mapping_consistency"] = page.Context.PfnKnown ? L"pfn_checked_before_and_after" : L"unverified";
            event.Evidence[L"persistence"] = written ? L"complete" : L"failed";
            while (!StopRequested.load() && PipelineEvents.Size() >= 384)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
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
    CloseEvidenceCollection();
    CaptureWriterDone.store(true);
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
        event.Evidence[L"source_continuity_lost"] = std::to_wstring(CollectionLost.load());
        event.Evidence[L"ti_analysis_dropped"] = std::to_wstring(CollectedTi.Loss());
        event.Evidence[L"live_analysis_dropped"] = std::to_wstring(CollectedLive.Loss());
        event.Evidence[L"ti_analysis_peak"] = std::to_wstring(CollectedTi.Peak());
        event.Evidence[L"live_analysis_peak"] = std::to_wstring(CollectedLive.Peak());
        event.Evidence[L"analysis_pending"] = std::to_wstring(CollectedTi.Size() + CollectedLive.Size());
        event.Evidence[L"capture_pending"] = std::to_wstring(PriorityCaptures.Size() + ContinuedCaptures.Size());
        event.Evidence[L"capture_queue_dropped"] = std::to_wstring(PriorityCaptures.Loss() + ContinuedCaptures.Loss());
        const auto captureNow = GetTickCount64();
        const auto captureTimestamps = [](const CaptureRequest& work)
        {
            return std::make_pair(work.QueuedMs, work.SubmittedMs);
        };
        event.Evidence[L"capture_scheduling_json"] = KmonCaptureTimingJson(CaptureTimings.Snapshot(),
            PriorityCaptures.Timing(captureNow, captureTimestamps), ContinuedCaptures.Timing(captureNow, captureTimestamps));
        event.Evidence[L"persistence_queue_dropped"] = std::to_wstring(CapturedPages.Loss());
        event.Evidence[L"diagnostic_queue_dropped"] = std::to_wstring(PipelineEvents.Loss());
        event.Evidence[L"diagnostic_queue_peak"] = std::to_wstring(PipelineEvents.Peak());
        event.Evidence[L"catalog_queue_dropped"] = std::to_wstring(CapturedRegions.Loss());
        const auto layout = LayoutMonitor.Stats();
        event.Evidence[L"layout_tracked"] = std::to_wstring(layout.Tracked);
        event.Evidence[L"layout_completed"] = std::to_wstring(layout.Completed);
        event.Evidence[L"layout_failed"] = std::to_wstring(layout.Failed);
        event.Evidence[L"layout_stored_rows"] = std::to_wstring(layout.StoredRows);
        event.Evidence[L"layout_stored_names"] = std::to_wstring(layout.StoredNames);
        event.Evidence[L"layout_stored_name_characters"] = std::to_wstring(layout.StoredNameCharacters);
        event.Evidence[L"layout_notices_pending"] = std::to_wstring(layout.NoticesPending);
        event.Evidence[L"layout_notices_deferred"] = std::to_wstring(layout.NoticesDeferred);
        event.Evidence[L"layout_pending"] = std::to_wstring(LayoutCandidates.Size());
        event.Evidence[L"layout_dropped"] = std::to_wstring(LayoutCandidates.Loss());
        event.Evidence[L"layout_peak"] = std::to_wstring(LayoutCandidates.Peak());
        event.Evidence[L"layout_admission_limit"] = std::to_wstring(LayoutAdmissionLimit);
        event.Evidence[L"layout_change_reserved_slots"] = std::to_wstring(LayoutChangeReserve);
        event.Evidence[L"layout_coalesced"] = std::to_wstring(LayoutCandidates.Replacements());
        event.Evidence[L"layout_source_pending"] = std::to_wstring(layout.VerificationChangesPending);
        event.Evidence[L"layout_deferred"] = std::to_wstring(layout.VerificationDeferred);
        event.Evidence[L"layout_submitted"] = std::to_wstring(layout.VerificationSubmitted);
        event.Evidence[L"layout_changes_abandoned"] = std::to_wstring(layout.VerificationChangesAbandoned);
        event.Evidence[L"layout_checked"] = std::to_wstring(LayoutChecked.load());
        event.Evidence[L"layout_rejected"] = std::to_wstring(LayoutRejected.load());
        event.Evidence[L"layout_expired"] = std::to_wstring(LayoutExpired.load());
        event.Evidence[L"layout_max_queue_wait_ms"] = std::to_wstring(LayoutMaxQueueWaitMs.load());
        event.Evidence[L"layout_max_source_wait_ms"] = std::to_wstring(LayoutMaxSourceWaitMs.load());
        event.Evidence[L"layout_max_service_gap_ms"] = std::to_wstring(LayoutMaxServiceGapMs.load());
        event.Evidence[L"layout_max_service_gap_before"] = LayoutMaxServiceGapBefore;
        event.Evidence[L"layout_oldest_ms"] = std::to_wstring(layout.OldestAgeMs);
        event.Evidence[L"catalog_stale_observations"] = std::to_wstring(RegionCatalog.StaleObservations);
        event.Evidence[L"catalog_rejected"] = std::to_wstring(RegionCatalog.Rejected);
        event.Evidence[L"catalog_links_evicted"] = std::to_wstring(RegionCatalog.LinksEvicted);
        event.Evidence[L"execution_references_dropped"] = std::to_wstring(ExecutionReferenceDropped);
        event.Evidence[L"execution_references_pending"] = std::to_wstring(ExecutionReferences.size());
        event.Evidence[L"execution_references_queued"] = std::to_wstring(ExecutionReferenceQueued);
        event.Evidence[L"execution_references_processed"] = std::to_wstring(ExecutionReferenceProcessed);
        event.Evidence[L"execution_references_expired"] = std::to_wstring(ExecutionReferenceExpired);
        event.Evidence[L"execution_references_max_queue_wait_ms"] = std::to_wstring(ExecutionReferenceMaxWaitMs);
        event.Evidence[L"execution_references_peak"] = std::to_wstring(ExecutionReferencePeak);
        event.Evidence[L"reference_scan_cursors"] = std::to_wstring(ReferenceScanCursors.size());
        event.Evidence[L"reference_cursor_evicted"] = std::to_wstring(ReferenceCursorEvicted);
        event.Evidence[L"reference_scan_policy"] = L"rotating static sources: IAT/table 16, kernel tables 64; not complete path coverage";
        for (const auto& dropped : ExecutionReferenceQueueDropsByRole)
        {
            event.Evidence[L"reference_queue_dropped_" + dropped.first] = std::to_wstring(dropped.second);
        }
        event.Evidence[L"final_drain"] = finalDrain ? L"true" : L"false";
        event.Evidence[L"first_capture_max_ms"] = std::to_wstring(CaptureFirstMaxMs.load());
        event.Evidence[L"capture_failures"] = std::to_wstring(CaptureFailed.load());
        event.Evidence[L"evidence_bundles_queued"] = std::to_wstring(EvidenceQueued.load());
        event.Evidence[L"evidence_bundles_written"] = std::to_wstring(EvidenceWritten.load());
        event.Evidence[L"evidence_bundles_failed"] = std::to_wstring(EvidenceFailed.load());
        event.Evidence[L"evidence_bundles_dropped"] = std::to_wstring(EvidenceDropped.load());
        event.Evidence[L"evidence_bundles_pending"] = std::to_wstring(CapturedEvidenceBundles.Size());
        event.Evidence[L"evidence_bundle_bytes"] = std::to_wstring(EvidenceBytes.load());
        event.Evidence[L"evidence_ledger_failed"] = std::to_wstring(EvidenceLedgerFailed.load());
        event.Evidence[L"capture_read_bytes"] = std::to_wstring(CaptureReadBytes.load());
        event.Evidence[L"capture_read_failed_bytes"] = std::to_wstring(CaptureReadFailedBytes.load());
        event.Evidence[L"capture_discardable_unreadable_bytes"] = std::to_wstring(CaptureDiscardableUnreadableBytes.load());
        event.Evidence[L"capture_kernel_contiguous_pages"] = std::to_wstring(CaptureKernelContinuations.load());
        event.Evidence[L"capture_root_layout_resolutions"] = std::to_wstring(CaptureRootLayoutResolutions.load());
        event.Evidence[L"capture_root_identity_checks"] = std::to_wstring(CaptureRootIdentityChecks.load());
        event.Evidence[L"user_memory_analysis_yields"] = std::to_wstring(UserMemoryAnalysisYields.load());
        event.Evidence[L"capture_known_unreadable_bytes"] = std::to_wstring(CaptureUnreadableBytes.load());
        event.Evidence[L"capture_read_failed_requests"] = std::to_wstring(CaptureReadFailedRequests.load());
        event.Evidence[L"capture_fallback_pages"] = std::to_wstring(CaptureFallbackPages.load());
        event.Evidence[L"capture_requests_traversed"] = std::to_wstring(CaptureTraversed.load());
        event.Evidence[L"capture_requests_queued"] = std::to_wstring(CaptureQueued.load());
        event.Evidence[L"shutdown_layout_processed"] = std::to_wstring(ShutdownLayoutProcessed);
        event.Evidence[L"shutdown_references_processed"] = std::to_wstring(ShutdownReferencesProcessed);
        event.Evidence[L"shutdown_drain_ms"] = std::to_wstring(ShutdownDrainMs);
        event.Evidence[L"shutdown_events_processed"] = std::to_wstring(ShutdownEventsProcessed);
        event.Evidence[L"shutdown_events_unanalyzed"] = std::to_wstring(ShutdownEventsUnanalyzed);
        event.Evidence[L"image_work_items"] = std::to_wstring(ImageWork.size());
        event.Evidence[L"image_work_capacity"] = std::to_wstring(ImageWorkCapacity);
        event.Evidence[L"image_watch_reserved_slots"] = std::to_wstring(ImageWatchReserve);
        event.Evidence[L"image_admission_deferred_attempts"] = std::to_wstring(ImageAdmissionDeferred);
        event.Evidence[L"image_watch_admission_deferred_attempts"] = std::to_wstring(ImageWatchAdmissionDeferred);
        event.Evidence[L"image_rescan_delay_entries"] = std::to_wstring(ImageRescanDelays.size());
        event.Evidence[L"image_rescan_delay_hits"] = std::to_wstring(ImageRescanDelayHits);
        event.Evidence[L"image_rescan_history_hits"] = std::to_wstring(ImageRescanHistoryHits);
        event.Evidence[L"image_first_watched_turns"] = std::to_wstring(ImageSweepClassTurns[0][0]);
        event.Evidence[L"image_repeat_watched_turns"] = std::to_wstring(ImageSweepClassTurns[0][1]);
        event.Evidence[L"image_first_background_turns"] = std::to_wstring(ImageSweepClassTurns[1][0]);
        event.Evidence[L"image_repeat_background_turns"] = std::to_wstring(ImageSweepClassTurns[1][1]);
        event.Evidence[L"image_borrowed_background_turns"] = std::to_wstring(ImageBorrowedBackgroundTurns);
        event.Evidence[L"image_completion_priority_turns"] = std::to_wstring(ImageCompletionPriorityTurns);
        event.Evidence[L"image_bulk_progress_turns"] = std::to_wstring(ImageBulkProgressTurns);
        uint64_t imageScheduled = 0, imageTraversed = 0, imageRemaining = 0;
        for (const auto& item : ImageWork)
        {
            const auto& work = item.second;
            imageScheduled += work.Sweep.Coverage.Attempted ? 1 : 0;
            imageTraversed += work.Sweep.LastCompleteMs != 0 ? 1 : 0;
            imageRemaining += work.Sweep.Ranges.size() - work.Sweep.NextRange;
            if (finalDrain)
            {
                KmonEvent progress;
                progress.Kind = L"coverage.image_progress";
                progress.ProcessId = work.Identity.ProcessId;
                progress.Image = work.Path;
                progress.Summary = L"final image sweep cursor; traversal does not imply all bytes verified";
                progress.Observation.Identity = work.Identity;
                progress.Observation.Source = L"executable_page_sweep";
                progress.Observation.Coverage = work.Sweep.Coverage;
                progress.Evidence[L"image_base"] = std::to_wstring(work.Base);
                progress.Evidence[L"reference_loaded"] = work.Loaded ? L"true" : L"false";
                progress.Evidence[L"total_pages"] = std::to_wstring(work.Sweep.Ranges.size());
                progress.Evidence[L"cursor"] = std::to_wstring(work.Sweep.NextRange);
                progress.Evidence[L"cycle"] = std::to_wstring(work.Sweep.Cycle);
                progress.Evidence[L"remaining_pages"] = std::to_wstring(work.Sweep.Ranges.size() - work.Sweep.NextRange);
                progress.Evidence[L"last_completion_ms"] = std::to_wstring(work.Sweep.LastCompleteMs);
                progress.Evidence[L"last_sweep_ms"] = std::to_wstring(work.LastSweepMs);
                progress.Evidence[L"prior_traversal_ms"] = std::to_wstring(work.PriorTraversalMs);
                progress.Evidence[L"scheduling_turns"] = std::to_wstring(work.SweepSchedulingTurns);
                progress.Evidence[L"completion_priority_turns"] = std::to_wstring(work.CompletionPriorityTurns);
                progress.Evidence[L"bulk_progress_turns"] = std::to_wstring(work.BulkProgressTurns);
                progress.Evidence[L"completed_cycles"] = std::to_wstring(work.Sweep.CompletedCycles);
                progress.Evidence[L"last_cycle_requested_bytes"] = std::to_wstring(work.Sweep.LastCompleteCoverage.RequestedBytes);
                progress.Evidence[L"last_cycle_compared_bytes"] = std::to_wstring(work.Sweep.LastCompleteCoverage.ComparedBytes);
                progress.Evidence[L"last_cycle_failed_bytes"] = std::to_wstring(work.Sweep.LastCompleteCoverage.FailedBytes);
                progress.Evidence[L"last_cycle_skipped_bytes"] = std::to_wstring(work.Sweep.LastCompleteCoverage.SkippedBytes);
                progress.Evidence[L"function_override_compared_bytes"] = std::to_wstring(work.Sweep.Rel32ValidatedBytes);
                progress.Evidence[L"relocation_base"] = std::to_wstring(work.Sweep.RelocationBase);
                progress.Evidence[L"relocation_basis"] = work.Sweep.RelocationBase == 0 ? L"unverified" :
                    (work.Sweep.SecondaryImageView ? L"independent_sec_image_no_execute" : L"mapping_base");
                progress.Evidence[L"last_cycle_function_override_compared_bytes"] = std::to_wstring(work.Sweep.LastCompleteRel32ValidatedBytes);
                RecordEvent(std::move(progress));
            }
        }
        ImageRemainingPages.store(imageRemaining);
        event.Evidence[L"image_scheduled_items"] = std::to_wstring(imageScheduled);
        event.Evidence[L"image_traversed_items"] = std::to_wstring(imageTraversed);
        event.Evidence[L"image_remaining_pages"] = std::to_wstring(ImageRemainingPages.load());
        event.Evidence[L"image_last_complete_ms"] = std::to_wstring(ImageLastCompleteMs.load());
        event.Evidence[L"analysis_budget_exceeded"] = std::to_wstring(AnalysisBudgetExceeded.load());
        RecordEvent(std::move(event));
        NextPipelineStatusMs = now + 5000;
    }
}

bool KmonCaptureSchedulingIntegrationSelfTest(std::wstring* diagnostics)
{
    auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 8 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    const auto release = [](void* address)
    {
        if (address != nullptr)
        {
            VirtualFree(address, 0, MEM_RELEASE);
        }
    };
    const std::unique_ptr<void, decltype(release)> owner(memory, release);
    bool ok = false;
    KmonCaptureTimingStats normal, shutdown;
    do
    {
        if (memory == nullptr)
        {
            break;
        }
        std::memset(memory, 0x31, 8 * 4096);
        DWORD oldProtection = 0;
        if (!VirtualProtect(memory + 4096, 4096, PAGE_NOACCESS, &oldProtection) ||
            !VirtualProtect(memory + 2 * 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &oldProtection))
        {
            break;
        }
        const auto identity = ObserveProcessIdentity(GetCurrentProcessId(), GetCurrentProcess());
        KernelMonitor monitor;
        if (!monitor.QueueCapture(L"owned_scheduler_large", reinterpret_cast<uint64_t>(memory), 6 * 4096,
                identity, 0, nullptr) ||
            !monitor.QueueCapture(L"owned_scheduler_small", reinterpret_cast<uint64_t>(memory + 7 * 4096), 4096,
                identity, 0, nullptr))
        {
            break;
        }
        monitor.CaptureWorker = std::thread(&KernelMonitor::CaptureLoop, &monitor);
        const auto started = GetTickCount64();
        while (monitor.CaptureTraversed.load() != 2 && GetTickCount64() - started < 3000)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        monitor.CaptureStopping.store(true);
        monitor.CaptureWorker.join();
        normal = monitor.CaptureTimings.Snapshot();
        MEMORY_BASIC_INFORMATION guarded{};
        ok = monitor.CaptureTraversed.load() == 2 && monitor.CaptureReadBytes.load() == 5 * 4096 &&
            monitor.CaptureUnreadableBytes.load() == 2 * 4096 && monitor.CaptureReadFailedBytes.load() == 0 &&
            monitor.CapturedPages.Size() == 5 && normal.FirstQueueWait.Samples == 2 &&
            normal.ContinuedQueueWait.Samples == 5 && normal.FirstAttemptAge.Samples == 2 &&
            normal.PageService.Samples == 7 && normal.FailedAttempts == 2 && normal.InvalidClocks == 0 &&
            normal.ShutdownDispatches == 0 && normal.ShutdownAttempts == 0 &&
            VirtualQuery(memory + 2 * 4096, &guarded, sizeof(guarded)) == sizeof(guarded) &&
            (guarded.Protect & PAGE_GUARD) != 0;
        KernelMonitor draining;
        if (!draining.QueueCapture(L"owned_scheduler_shutdown", reinterpret_cast<uint64_t>(memory), 4096, identity, 0, nullptr))
        {
            ok = false;
            break;
        }
        draining.CaptureStopping.store(true);
        draining.CaptureLoop();
        shutdown = draining.CaptureTimings.Snapshot();
        ok = ok && shutdown.ShutdownDispatches == 1 && shutdown.ShutdownAttempts == 1 &&
            shutdown.FirstQueueWait.Samples == 0 && shutdown.PageService.Samples == 0 && draining.CapturedPages.Size() == 1;
        // Exercise kernel scheduling with an explicitly absent device. No kernel
        // read can succeed, but the existing four-page quantum must survive.
        KernelMonitor unavailable;
        const auto kernelIdentity = ObserveProcessIdentity(0);
        if (!unavailable.QueueCapture(L"owned_unavailable_kernel_large", 0xFFFF900000001000ull,
                9 * 4096, kernelIdentity, 0, nullptr) ||
            !unavailable.QueueCapture(L"owned_unavailable_kernel_small", 0xFFFF900000020000ull,
                4096, kernelIdentity, 0, nullptr))
        {
            ok = false;
            break;
        }
        unavailable.CaptureStopping.store(true);
        unavailable.CaptureLoop();
        const auto kernelStats = unavailable.CaptureTimings.Snapshot();
        ok = ok && unavailable.CaptureTraversed.load() == 2 && unavailable.CaptureKernelContinuations.load() == 6 &&
            unavailable.CaptureReadFailedBytes.load() == 10 * 4096 && unavailable.CapturedPages.Size() == 0 &&
            kernelStats.ShutdownAttempts == 10 && kernelStats.ShutdownDispatches == 4 && kernelStats.PageService.Samples == 0;
    } while (false);
    if (diagnostics != nullptr)
    {
        *diagnostics = L"{\"schema\":\"kn.capture_scheduler_test.v1\",\"passed\":" + std::wstring(ok ? L"true" : L"false") +
            L",\"corpus\":\"owned_process_and_absent_device\",\"driver_loaded\":false,\"normal\":" + KmonCaptureTimingJson(normal, {}, {}) +
            L",\"shutdown\":" + KmonCaptureTimingJson(shutdown, {}, {}) + L"}";
    }
    return ok;
}

bool KmonPipelineSelfTest()
{
    {
        KernelMonitor monitor;
        const auto process = GetCurrentProcess();
        const auto identity = ObserveProcessIdentity(GetCurrentProcessId(), process);
        if (!identity.HasCanonicalKey()) { return false; }
        const auto pid = identity.ProcessId;
        monitor.WatchPids.insert(pid);
        monitor.WatchPromotedPids.insert(pid);
        monitor.WatchChildPids[pid] = 42;
        monitor.WatchPromotedCreated[pid] = identity.CreateTime - 1;
        // Model a recycled PID before the deep scanner prunes promoted watches.
        // The retained new process is valid but does not inherit the old child watch.
        KmonReferenceSchedule schedule;
        if (schedule.Select({pid}, 0, 0) != pid || monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchPromotedCreated[pid] = identity.CreateTime;
        if (!monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchPromotedCreated.erase(pid);
        if (monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchChildPids.clear();
        monitor.WatchPromotedCreated[pid] = identity.CreateTime;
        if (monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchNamesLower = {L"not-the-owned-process.invalid"};
        if (monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        wchar_t path[32768] = {};
        if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)))) { return false; }
        monitor.WatchNamesLower = {KmonBasenameLower(path)};
        monitor.WatchPromotedCreated[pid] = identity.CreateTime - 1;
        if (!monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchNamesLower = {L"*.sys"};
        if (monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchNamesLower = {L"*.exe"};
        if (!monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchNamesLower = {L"*"};
        if (!monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        monitor.WatchNamesLower.clear();
        monitor.WatchExplicitPids.insert(pid);
        if (!monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
        auto changed = identity;
        ++changed.CreateTime;
        if (monitor.IsCurrentReferenceWatch(process, changed) || monitor.IsCurrentReferenceWatch(nullptr, identity)) { return false; }
        monitor.WatchExplicitPids.clear();
        if (monitor.IsCurrentReferenceWatch(process, identity)) { return false; }
    }
    {
        std::vector<uint8_t> header(4096);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 128;
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.NumberOfSections = 2;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = 16384;
        nt.OptionalHeader.SizeOfHeaders = 4096;
        nt.OptionalHeader.SectionAlignment = 4096;
        IMAGE_SECTION_HEADER sections[2]{};
        sections[0].VirtualAddress = 4096; sections[0].Misc.VirtualSize = 4096;
        sections[0].Characteristics = IMAGE_SCN_MEM_EXECUTE;
        sections[1].VirtualAddress = 8192; sections[1].Misc.VirtualSize = 4097;
        sections[1].Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
        std::memcpy(sections[1].Name, "INIT", 4);
        const auto write = [&]()
        {
            std::memcpy(header.data(), &dos, sizeof(dos));
            std::memcpy(header.data() + 128, &nt, sizeof(nt));
            std::memcpy(header.data() + 128 + sizeof(nt), sections, sizeof(sections));
        };
        write();
        std::wstring name;
        if (!DiscardableCapturePage(header, 16384, 8192, 4096, &name) || name != L"INIT" ||
            !DiscardableCapturePage(header, 16384, 12288, 4096, &name) ||
            DiscardableCapturePage(header, 16384, 4096, 4096, &name) ||
            DiscardableCapturePage(header, 16384, 0, 4096, &name) ||
            DiscardableCapturePage(header, 16384, 8191, 4096, &name) ||
            DiscardableCapturePage(header, 16384, 16384, 1, &name) ||
            DiscardableCapturePage(header, 12288, 8192, 4096, &name) ||
            DiscardableCapturePage(std::vector<uint8_t>(header.begin(), header.begin() + 256), 16384, 8192, 4096, &name))
        { return false; }
        sections[0].Misc.VirtualSize = 8192; write();
        if (DiscardableCapturePage(header, 16384, 8192, 4096, &name)) { return false; }
        sections[0].Misc.VirtualSize = 4096;
        sections[1].Characteristics = 0; write();
        if (DiscardableCapturePage(header, 16384, 8192, 4096, &name)) { return false; }
        sections[1].Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
        sections[1].Misc.VirtualSize = UINT32_MAX; write();
        if (DiscardableCapturePage(header, 16384, 8192, 4096, &name)) { return false; }
    }
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
            {
                // A periodic burst cannot consume the changed-range reserve.
                // Refusal retains source work; neither admission class may drop
                // entries or renew a retained observation's original timestamp.
                bool admission = true;
                ProcessLayoutCandidate queued;
                queued.Identity = identity;
                queued.Role = L"layout_periodic";
                queued.ObservedMs = 1;
                for (size_t index = 0; index < 128; ++index)
                {
                    queued.Region.Base = 0x10000 + index * 4096;
                    admission &= monitor.QueueLayoutCandidate(queued);
                }
                queued.Region.Base = 0x100000;
                admission &= !monitor.QueueLayoutCandidate(queued);
                queued.Role = L"layout_change";
                for (size_t index = 0; index < 32; ++index)
                {
                    queued.Region.Base = 0x100000 + index * 4096;
                    admission &= monitor.QueueLayoutCandidate(queued);
                }
                queued.Region.Base = 0x200000;
                admission &= !monitor.QueueLayoutCandidate(queued);
                queued.Role = L"layout_periodic";
                queued.Region.Base = 0x10000;
                queued.ObservedMs = 2; // A genuinely newer producer observation.
                admission &= monitor.QueueLayoutCandidate(queued);
                auto retainedCandidates = monitor.LayoutCandidates.Drain(160);
                admission &= retainedCandidates.size() == 160 && monitor.LayoutCandidates.Loss() == 0 &&
                    monitor.LayoutCandidates.Replacements() == 1 && retainedCandidates.front().ObservedMs == 2;
                for (size_t index = 1; index < retainedCandidates.size(); ++index)
                {
                    admission &= retainedCandidates[index].ObservedMs == 1 &&
                        retainedCandidates[index].Role == (index < 128 ? L"layout_periodic" : L"layout_change");
                }
                monitor.LayoutCandidates.Reset();
                if (!admission) { break; }
            }
            const uint64_t selfBase = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
            wchar_t selfPath[32768]{};
            GetModuleFileNameW(nullptr, selfPath, 32768);
            bool referenceUnavailable = true;
            auto imageWork = monitor.FindImageWork(selfPath, selfBase, identity, &referenceUnavailable);
            if (imageWork == nullptr || referenceUnavailable || imageWork->Sweep.Ranges.size() < 2) { break; }
            imageWork->Sweep.NextRange = 1;
            const std::wstring aliasPath = L"\\\\?\\" + std::wstring(selfPath);
            if (monitor.FindImageWork(aliasPath, selfBase, identity) != imageWork ||
                imageWork->Sweep.NextRange != 1 || monitor.ImageWork.size() != 1) { break; }
            auto reusedIdentity = identity;
            ++reusedIdentity.CreateTime;
            if (monitor.FindImageWork(aliasPath, selfBase, reusedIdentity) == imageWork) { break; }
            wchar_t differentReference[32768]{};
            GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), differentReference, 32768);
            if (monitor.FindImageWork(differentReference, selfBase, identity) == imageWork ||
                monitor.ImageWork.size() != 3) { break; }
            monitor.ImageWork.clear();
            const auto missingReference = std::wstring(unique) + L"\\missing-reference.exe";
            if (monitor.FindImageWork(missingReference, selfBase, identity, &referenceUnavailable) != nullptr ||
                !referenceUnavailable || monitor.ImageWork.size() != 1) { break; }
            referenceUnavailable = false;
            if (monitor.FindImageWork(missingReference, selfBase, identity, &referenceUnavailable) != nullptr ||
                !referenceUnavailable) { break; }
            if (monitor.FindImageWork(missingReference, 0, identity, &referenceUnavailable) != nullptr ||
                referenceUnavailable) { break; }
            monitor.ImageWork.clear();
            // Eviction must retain the normal 30-second rescan deadline, not
            // turn a completed image into permanently competing "initial" work.
            auto completed = monitor.FindImageWork(selfPath, selfBase, identity);
            if (completed == nullptr) { break; }
            completed->Sweep.Coverage.TraversalComplete = true;
            completed->Sweep.LastCompleteMs = GetTickCount64();
            completed->NextSweepDueMs = GetTickCount64() + 30000;
            monitor.RememberImageRescanDelay(*completed, GetTickCount64());
            if (monitor.ImageRescanDelays.size() != 1) { break; }
            monitor.ImageWork.clear();
            referenceUnavailable = true;
            if (monitor.FindImageWork(aliasPath, selfBase, identity, &referenceUnavailable) != nullptr || referenceUnavailable ||
                !monitor.ImageWork.empty() || monitor.ImageRescanDelayHits != 1) { break; }
            // Process reuse, allocation reuse with a different file, and a
            // changed full file ID must not inherit the previous deadline.
            if (monitor.ImageRescanDelayed(selfPath, selfBase, reusedIdentity, GetTickCount64()) ||
                monitor.ImageRescanDelayed(selfPath, selfBase + 4096, identity, GetTickCount64()) ||
                monitor.ImageRescanDelayed(differentReference, selfBase, identity, GetTickCount64()) ||
                !monitor.ImageRescanDelays.empty()) { break; }
            completed = monitor.FindImageWork(selfPath, selfBase, identity);
            if (completed == nullptr) { break; }
            completed->Sweep.Coverage.TraversalComplete = true;
            completed->Sweep.LastCompleteMs = GetTickCount64();
            completed->NextSweepDueMs = GetTickCount64() + 30000;
            monitor.RememberImageRescanDelay(*completed, GetTickCount64());
            monitor.ImageRescanDelays.begin()->second.FileId.FileId.Identifier[15] ^= 1;
            if (monitor.ImageRescanDelayed(selfPath, selfBase, identity, GetTickCount64()) ||
                !monitor.ImageRescanDelays.empty()) { break; }
            monitor.RememberImageRescanDelay(*completed, GetTickCount64());
            monitor.ImageRescanDelays.begin()->second.DueMs = GetTickCount64() - 1;
            monitor.ImageWork.clear();
            completed = monitor.FindImageWork(aliasPath, selfBase, identity);
            // An evicted repeat keeps only its scheduling class. It still has
            // to read every byte again, and cannot claim a completed cycle.
            if (completed == nullptr || completed->PriorTraversalMs == 0 ||
                completed->Sweep.LastCompleteMs != 0 || completed->Sweep.Coverage.TraversalComplete ||
                completed->Sweep.Coverage.ComparedBytes != 0 || monitor.ImageRescanHistoryHits != 1) { break; }
            const uint64_t historyNow = GetTickCount64();
            auto& history = monitor.ImageRescanDelays.begin()->second;
            const auto due = history.DueMs, traversed = history.TraversedMs;
            history.ExpiresMs = historyNow + 1;
            uint64_t rememberedTraversal = 0;
            if (monitor.ImageRescanDelayed(aliasPath, selfBase, identity, historyNow, &rememberedTraversal) ||
                rememberedTraversal != traversed || history.ExpiresMs != historyNow + 300000 ||
                history.DueMs != due || history.TraversedMs != traversed) { break; }
            // Activity can outlive the original expiry without postponing a
            // rescan or turning historical traversal into current verification.
            if (monitor.ImageRescanDelayed(aliasPath, selfBase, identity, historyNow + 2, &rememberedTraversal) ||
                rememberedTraversal != traversed || history.DueMs != due ||
                completed->Sweep.Coverage.ComparedBytes != 0 || completed->Sweep.CompletedCycles != 0) { break; }
            const ObservationReader unreadableRepeat = [](uint64_t, size_t, std::vector<uint8_t>*) { return false; };
            if (monitor.ScanExecutableImage(aliasPath, selfBase, identity, unreadableRepeat, 1) != CodeOwnership::OwnedUnverified ||
                completed->Sweep.Coverage.ComparedBytes != 0 || completed->Sweep.CompletedCycles != 0) { break; }
            monitor.ImageRescanDelays.begin()->second.ExpiresMs = GetTickCount64() - 1;
            uint64_t expiredTraversal = 1;
            if (monitor.ImageRescanDelayed(selfPath, selfBase, identity, GetTickCount64(), &expiredTraversal) ||
                expiredTraversal != 0 ||
                !monitor.ImageRescanDelays.empty()) { break; }
            completed->Sweep.Coverage.TraversalComplete = true;
            completed->Sweep.LastCompleteMs = GetTickCount64();
            completed->NextSweepDueMs = GetTickCount64() + 30000;
            for (size_t i = 0; i < 4096; ++i)
            {
                KernelMonitor::ImageRescanDelay delay;
                delay.DueMs = GetTickCount64() + 30000;
                delay.ExpiresMs = GetTickCount64() + 300000;
                monitor.ImageRescanDelays.emplace(std::to_wstring(i), delay);
            }
            monitor.RememberImageRescanDelay(*completed, GetTickCount64());
            if (monitor.ImageRescanDelays.size() != 4096) { break; }
            monitor.ImageRescanDelays.clear();
            monitor.ImageWork.clear();
            // A late discovered watched mapping must still enter a cache
            // filled with unfinished background traversals. No tail is evicted.
            bool admissionWatched = false;
            if (monitor.ImageWorkAdmissionLimit(0, &admissionWatched) != KernelMonitor::ImageWorkCapacity ||
                admissionWatched) { break; }
            monitor.WatchNamesLower.push_back(L"pending-watch.exe");
            if (monitor.ImageWorkAdmissionLimit(0, &admissionWatched) !=
                KernelMonitor::ImageWorkCapacity - KernelMonitor::ImageWatchReserve) { break; }
            monitor.WatchNamesLower.clear();
            monitor.WatchPids.insert(identity.ProcessId);
            for (size_t i = 0; i < KernelMonitor::ImageWorkCapacity - KernelMonitor::ImageWatchReserve; ++i)
            {
                KernelMonitor::ImageVerificationWork work;
                work.LastUsedMs = GetTickCount64();
                work.Sweep.Ranges.resize(2);
                work.Sweep.NextRange = 1;
                monitor.ImageWork.emplace(L"background-" + std::to_wstring(i), std::move(work));
            }
            ObservationIdentity backgroundIdentity = identity;
            backgroundIdentity.ProcessId = 0;
            const auto backgroundSize = monitor.ImageWork.size();
            referenceUnavailable = true;
            if (monitor.FindImageWork(selfPath, selfBase, backgroundIdentity, &referenceUnavailable) != nullptr || referenceUnavailable ||
                monitor.ImageWork.size() != backgroundSize || monitor.ImageAdmissionDeferred != 1 ||
                monitor.ImageWatchAdmissionDeferred != 0) { break; }
            auto admitted = monitor.FindImageWork(selfPath, selfBase, identity);
            if (admitted == nullptr || monitor.ImageWork.size() != backgroundSize + 1 ||
                monitor.ImageWork.at(L"background-0").Sweep.NextRange != 1 ||
                monitor.ImageWorkAdmissionLimit(0, &admissionWatched) != backgroundSize + 1 || admissionWatched) { break; }
            for (size_t i = 1; i < KernelMonitor::ImageWatchReserve; ++i)
            {
                KernelMonitor::ImageVerificationWork work;
                work.Identity = identity;
                work.LastUsedMs = GetTickCount64();
                monitor.ImageWork.emplace(L"watched-" + std::to_wstring(i), std::move(work));
            }
            if (monitor.ImageWork.size() != KernelMonitor::ImageWorkCapacity ||
                monitor.ImageWorkAdmissionLimit(0, &admissionWatched) != KernelMonitor::ImageWorkCapacity ||
                monitor.FindImageWork(selfPath, selfBase + 4096, identity) != nullptr ||
                monitor.ImageAdmissionDeferred != 2 || monitor.ImageWatchAdmissionDeferred != 1 ||
                monitor.ImageWork.size() != KernelMonitor::ImageWorkCapacity) { break; }
            // Reclaiming completed work still permits new background admission;
            // removing the watch restores the ordinary capacity immediately.
            monitor.ImageWork.at(L"background-0").Sweep.Coverage.TraversalComplete = true;
            if (monitor.FindImageWork(selfPath, selfBase, backgroundIdentity) == nullptr ||
                monitor.ImageWork.count(L"background-0") != 0 ||
                monitor.ImageWork.at(L"background-1").Sweep.NextRange != 1 ||
                monitor.ImageWork.size() != KernelMonitor::ImageWorkCapacity) { break; }
            monitor.ImageWork.clear();
            monitor.WatchPids.clear();
            if (monitor.ImageWorkAdmissionLimit(0, &admissionWatched) != KernelMonitor::ImageWorkCapacity) { break; }
            // A DLL-rich process must not consume every watched image turn.
            for (uint32_t index = 0; index < 20; ++index)
            {
                KernelMonitor::ImageVerificationWork work;
                work.Loaded = true;
                work.Identity.ProcessId = index == 19 ? 200 : 100;
                work.Identity.CreateTime = 1;
                work.Base = 0x10000 + index * 4096;
                monitor.ImageWork.emplace(std::to_wstring(index), std::move(work));
            }
            monitor.WatchPids.insert(100);
            monitor.WatchPids.insert(200);
            bool fair = true;
            for (uint32_t turn = 0; turn < 8; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                fair = fair && selected != nullptr && selected->Identity.ProcessId == (turn % 2 == 0 ? 100u : 200u);
                if (selected) { selected->LastSweepMs = turn + 1; }
            }
            monitor.ImageWork.clear();
            monitor.WatchPids.clear();
            monitor.ImageSweepProcessCursors[0] = {};
            monitor.ImageSweepProcessCursors[1] = {};
            monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {};
            monitor.ImageSweepClassTurns = {};
            if (!fair) { break; }
            KernelMonitor::ImageVerificationWork initial, repeat;
            initial.Loaded = repeat.Loaded = true;
            initial.Identity.ProcessId = repeat.Identity.ProcessId = 100;
            initial.Identity.CreateTime = repeat.Identity.CreateTime = 1;
            initial.Base = 0x10000;
            initial.LastSweepMs = 900;
            repeat.Base = 0x20000;
            repeat.Sweep.LastCompleteMs = 1;
            monitor.ImageWork.emplace(L"initial", std::move(initial));
            monitor.ImageWork.emplace(L"repeat", std::move(repeat));
            monitor.WatchPids.insert(100);
            for (size_t turn = 0; turn < 8; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                fair = fair && selected == &monitor.ImageWork.at(turn % 4 == 3 ? L"repeat" : L"initial");
            }
            monitor.ImageWork.clear();
            monitor.WatchPids.clear();
            monitor.ImageSweepProcessCursors[0] = {};
            monitor.ImageSweepProcessCursors[1] = {};
            monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {};
            monitor.ImageSweepClassTurns = {};
            if (!fair) { break; }
            // Many repeat-only processes must not dilute first traversal
            // service. Each repeat process still gets a turn, including an
            // evicted/recreated entry whose sweep itself has never completed.
            for (uint32_t index = 0; index < 14; ++index)
            {
                KernelMonitor::ImageVerificationWork work;
                work.Loaded = true;
                work.Identity.ProcessId = 100 + index;
                work.Identity.CreateTime = 1;
                work.Base = 0x10000;
                if (index != 0) { work.PriorTraversalMs = 1; }
                monitor.ImageWork.emplace(std::to_wstring(index), std::move(work));
                monitor.WatchPids.insert(100 + index);
            }
            std::set<uint32_t> repeatedPids;
            size_t firstService = 0;
            for (size_t turn = 0; turn < 104; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                if (selected == nullptr) { fair = false; break; }
                if (turn % 4 == 3)
                {
                    fair &= selected->PriorTraversalMs != 0;
                    repeatedPids.insert(selected->Identity.ProcessId);
                }
                else { fair &= selected->Identity.ProcessId == 100; ++firstService; }
                // Completion/eviction of an individual image cannot reset the
                // group-level reservation for periodic rescans.
                selected->SweepSchedulingTurns = 0;
                selected->LastSweepMs = turn + 1;
            }
            fair &= firstService == 78 && repeatedPids.size() == 13;
            for (auto& item : monitor.ImageWork) { item.second.NextSweepDueMs = 2000; }
            const auto served = monitor.ImageSweepGroupTurns;
            fair &= monitor.SelectImageSweepWork(1000) == nullptr && monitor.ImageSweepGroupTurns == served;
            monitor.ImageWork.at(L"1").NextSweepDueMs = 0;
            fair &= monitor.SelectImageSweepWork(1000) == &monitor.ImageWork.at(L"1");
            monitor.ImageWork.clear(); monitor.WatchPids.clear();
            monitor.ImageSweepProcessCursors = {}; monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {}; monitor.ImageSweepClassTurns = {};
            if (!fair) { break; }
            // Lend unused watched initial slots to background first work,
            // while the planned watched counter still reaches its rescan slot.
            for (uint32_t index = 0; index < 3; ++index)
            {
                KernelMonitor::ImageVerificationWork work;
                work.Loaded = true; work.Identity.ProcessId = 100 + index;
                work.Identity.CreateTime = 1; work.Base = 0x10000;
                if (index == 0) { work.PriorTraversalMs = 1; }
                monitor.ImageWork.emplace(std::to_wstring(index), std::move(work));
            }
            monitor.WatchPids.insert(100);
            for (size_t turn = 0; turn < 64; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                if (selected == nullptr) { fair = false; break; }
                selected->LastSweepMs = turn + 1;
            }
            fair &= monitor.ImageSweepClassTurns[0][1] == 12 && monitor.ImageSweepClassTurns[1][0] == 52 &&
                monitor.ImageBorrowedBackgroundTurns == 36;
            // With only background work, it receives the whole schedule and
            // keeps one in four turns for rescans, not just the native share.
            monitor.WatchPids.clear(); monitor.ImageSweepProcessCursors = {}; monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {}; monitor.ImageSweepClassTurns = {};
            monitor.ImageBorrowedBackgroundTurns = 0;
            for (size_t turn = 0; turn < 32; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                if (selected == nullptr) { fair = false; break; }
                selected->LastSweepMs = turn + 1;
            }
            fair &= monitor.ImageSweepClassTurns[1][0] == 24 && monitor.ImageSweepClassTurns[1][1] == 8 &&
                monitor.ImageBorrowedBackgroundTurns == 0;
            monitor.ImageWork.clear(); monitor.ImageSweepProcessCursors = {}; monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {}; monitor.ImageSweepClassTurns = {};
            if (!fair) { break; }
            std::vector<KernelModuleInfo> owner{{selfBase, 1, selfPath, L"self"}};
            for (uint32_t i = 0; i < 5; ++i)
            {
                KernelMonitor::ImageVerificationWork work;
                work.Loaded = true; work.Identity.ProcessId = 100 + i; work.Identity.CreateTime = 1;
                work.Base = 0x10000 + i * 4096;
                work.Sweep.Ranges.resize(i == 2 || i == 3 ? 4096 : 4);
                if (i == 4) { work.PriorTraversalMs = 1; }
                monitor.ImageWork.emplace(std::to_wstring(i), std::move(work));
            }
            monitor.WatchPids.insert(100);
            size_t watchedTurns = 0, bulkTurns = 0, ordinaryTurns = 0, finishTurns = 0;
            monitor.ImageCompletionPriorityTurns = 0;
            monitor.ImageBulkProgressTurns = 0;
            std::set<uint32_t> bulkServed, ordinaryServed;
            for (size_t turn = 1; turn <= 64; ++turn)
            {
                auto selected = monitor.SelectImageSweepWork(1000);
                if (selected == nullptr) { fair = false; break; }
                const size_t backgroundPhase = ((turn - 1) / 4) % 4;
                if (turn % 4 == 0 && backgroundPhase == 1)
                {
                    fair &= selected->Identity.ProcessId == 102 || selected->Identity.ProcessId == 103;
                    ++bulkTurns;
                    bulkServed.insert(selected->Identity.ProcessId);
                    selected->Sweep.NextRange += 16;
                }
                else if (turn % 4 == 0 && backgroundPhase == 2)
                {
                    fair &= selected->Identity.ProcessId == 101;
                    ++finishTurns;
                }
                else if (turn % 4 != 0) { fair &= selected->Identity.ProcessId == 100; ++watchedTurns; }
                else
                {
                    fair &= selected->Identity.ProcessId != 100;
                    if (backgroundPhase == 3) { fair &= selected->Identity.ProcessId == 104; }
                    else { ordinaryServed.insert(selected->Identity.ProcessId); }
                    ++ordinaryTurns;
                }
                selected->LastSweepMs = turn;
            }
            fair &= watchedTurns == 48 && bulkTurns == 4 && ordinaryTurns == 8 && finishTurns == 4 &&
                monitor.ImageCompletionPriorityTurns == 4 && bulkServed.size() == 2 && ordinaryServed.size() == 3;
            fair &= monitor.ImageBulkProgressTurns == 4;
            fair &= monitor.ImageSweepClassTurns[1][0] == 12 && monitor.ImageSweepClassTurns[1][1] == 4;
            // No short tail: the completion slot goes back to large work.
            monitor.ImageWork.at(L"1").NextSweepDueMs = 2000;
            monitor.ImageSweepTurns = 3;
            monitor.ImageSweepGroupTurns[1] = 0;
            monitor.ImageSweepClassTurns[1][0] = 2;
            const auto fallback = monitor.SelectImageSweepWork(1000);
            fair &= fallback != nullptr && (fallback->Identity.ProcessId == 102 || fallback->Identity.ProcessId == 103) &&
                monitor.ImageCompletionPriorityTurns == 4;
            // A recent incidental read must not put a barely scanned large
            // image behind one that already advanced much farther.
            auto& ahead = monitor.ImageWork.at(L"2");
            auto& behind = monitor.ImageWork.at(L"3");
            ahead.Sweep.NextRange = 2048; ahead.LastSweepMs = 1;
            behind.Sweep.NextRange = 128; behind.LastSweepMs = 999;
            const auto selectBulk = [&]()
            {
                monitor.ImageSweepTurns = 3;
                monitor.ImageSweepGroupTurns[1] = 0;
                monitor.ImageSweepClassTurns[1][0] = 1;
                return monitor.SelectImageSweepWork(1000);
            };
            fair &= selectBulk() == &behind;
            behind.Sweep.Coverage.Attempted = true;
            behind.Sweep.Coverage.InventoryAvailable = false;
            behind.Sweep.NextRange = 0;
            fair &= selectBulk() == &ahead;
            // Failed identities keep ordinary service, including when all
            // large work is unavailable. They cannot monopolize the bulk lane.
            ahead.Sweep.Coverage.Attempted = true;
            ahead.Sweep.Coverage.InventoryAvailable = false;
            monitor.ImageWork.at(L"0").NextSweepDueMs = 2000;
            monitor.ImageWork.at(L"4").NextSweepDueMs = 2000;
            std::set<uint32_t> unavailableServed;
            for (size_t turn = 0; turn < 4; ++turn)
            {
                auto retry = selectBulk();
                fair &= retry != nullptr;
                if (retry) { unavailableServed.insert(retry->Identity.ProcessId); }
            }
            fair &= unavailableServed.size() == 2;
            monitor.ImageWork.clear(); monitor.WatchPids.clear();
            monitor.ImageSweepProcessCursors[0] = {}; monitor.ImageSweepProcessCursors[1] = {}; monitor.ImageSweepTurns = 0;
            monitor.ImageSweepGroupTurns = {}; monitor.ImageSweepClassTurns = {};
            if (!fair) { break; }
            const uint64_t code = reinterpret_cast<uint64_t>(&KmonPipelineSelfTest);
            // Allocation membership can extend beyond the reported module size;
            // it establishes neither matching code bytes nor a trusted image.
            if (!KmonLoadedImageAllocation(GetCurrentProcess(), code, owner) ||
                KmonLoadedImageAllocation(GetCurrentProcess(), reinterpret_cast<uint64_t>(allocation), owner) ||
                KmonLoadedImageAllocation(GetCurrentProcess(), code, {})) { break; }
            owner[0].ImagePath = L"C:\\nonexistent-kmon-image-reference.dll";
            if (KmonLoadedImageAllocation(GetCurrentProcess(), code, owner)) { break; }
            wchar_t otherPath[32768]{};
            GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), otherPath, 32768);
            owner[0].ImagePath = otherPath;
            if (KmonLoadedImageAllocation(GetCurrentProcess(), code, owner)) { break; }
            if (monitor.CaptureRegion(L"selftest_stale_ti", 0x10000, 4096,
                    identity.ProcessId, true, nullptr, nullptr, nullptr, 4096, nullptr, 0,
                    identity.CreateTime + 1) || monitor.PriorityCaptures.Size() != 0)
            {
                break;
            }
            TiEventRecord source;
            source.TargetProcessId = identity.ProcessId;
            source.TargetProcessCreateTime = identity.CreateTime;
            source.Timestamp = ObservationFileTime();
            if (!TiCaptureMatchesIdentity(source, identity))
            {
                break;
            }
            ++source.TargetProcessCreateTime;
            if (TiCaptureMatchesIdentity(source, identity))
            {
                break;
            }
            source.TargetProcessCreateTime = 0;
            if (TiCaptureMatchesIdentity(source, identity))
            {
                break;
            }
            source.TargetProcessCreateTime = identity.CreateTime;
            source.Timestamp = identity.CreateTime - 1;
            if (TiCaptureMatchesIdentity(source, identity))
            {
                break;
            }
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
            EvidenceBundle ownedEvidence;
            ownedEvidence.Acquisition = L"local_user_reader";
            ownedEvidence.CaptureStartedMs = GetTickCount64();
            KmonHuntReference ownedReference;
            ownedReference.Context.Identity = identity;
            ownedReference.Context.MonotonicMs = GetTickCount64();
            ownedReference.Context.Timestamp = ObservationFileTime();
            ownedReference.Context.Source = L"owned_pointer_fixture";
            ownedReference.Context.DependencyGroup = L"owned_fixture_memory";
            ownedReference.Context.Ownership = CodeOwnership::UnownedExecutable;
            ownedReference.Address = ownedReference.Root = reinterpret_cast<uint64_t>(allocation);
            const uint64_t pointer = ownedReference.Address;
            ownedReference.Slot = reinterpret_cast<uint64_t>(&pointer);
            ownedReference.Role = L"manifest_vtable";
            ownedReference.SlotStable = true;
            std::vector<uint8_t> ownedHead(32), ownedSlot(8);
            SIZE_T headRead = 0, slotRead = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), allocation, ownedHead.data(), ownedHead.size(), &headRead) || headRead != ownedHead.size() ||
                !ReadProcessMemory(GetCurrentProcess(), &pointer, ownedSlot.data(), ownedSlot.size(), &slotRead) || slotRead != ownedSlot.size()) { break; }
            ownedEvidence.Spans = {{ownedReference.Address, 32, L"target_head", L"valid", ownedHead},
                {ownedReference.Slot, 8, L"pointer_slot", L"valid", ownedSlot}};
            ownedEvidence.CaptureEndedMs = GetTickCount64();
            ownedEvidence.ReferenceConsistent = true;
            if (monitor.HuntIndex.Observe(ownedReference, GetTickCount64(), &ownedEvidence.Receipt) == 0) { break; }
            const uint64_t evidenceId = monitor.QueueEvidenceBundle(std::move(ownedEvidence));
            if (evidenceId == 0) { break; }
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
            EvidenceBundle recovered;
            std::wstring recoveryError;
            const auto evidencePath = std::wstring(unique) + L"\\cases\\case-" +
                std::to_wstring(monitor.EvidenceCollectionEpoch.load()) + L"-" + std::to_wstring(evidenceId) + L".kncase";
            ok = ok && monitor.EvidenceWritten.load() == 1 && monitor.EvidenceFailed.load() == 0 &&
                monitor.EvidenceLedgerFailed.load() == 0 && LoadEvidenceBundle(evidencePath, &recovered, &recoveryError) &&
                ReplayEvidence(recovered).ReferenceReached && ReplayEvidence(recovered).Gaps.empty();
            if (ok)
            {
                KernelMonitor pressure;
                for (size_t i = 0; i < 65; ++i) { pressure.QueueEvidenceBundle(recovered); }
                ok = pressure.EvidenceQueued.load() == 64 && pressure.EvidenceDropped.load() == 1 &&
                    pressure.CapturedEvidenceBundles.Size() == 64;
                KernelMonitor exhausted;
                exhausted.Options.LogDirectory = std::wstring(unique) + L"\\budget";
                exhausted.EvidenceBytes.store(128ull * 1024 * 1024);
                exhausted.QueueEvidenceBundle(recovered);
                exhausted.WriterStopping.store(true);
                exhausted.CaptureWriterLoop();
                ok = ok && exhausted.EvidenceWritten.load() == 0 && exhausted.EvidenceFailed.load() == 1 &&
                    exhausted.CapturedEvidenceBundles.Size() == 0;
            }
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
            // The same virtual address in two roots must remain distinct.
            for (const uint64_t root : {0x1000ull, 0x2000ull})
            {
                ok = monitor.QueueCapture(L"selftest_root", 0x10000, 4096,
                    identity, ObservationFileTime(), nullptr, 0, root) && ok;
            }
            KernelMonitor::CaptureRequest rootFirst;
            KernelMonitor::CaptureRequest rootSecond;
            ok = monitor.PriorityCaptures.Pop(&rootFirst) && ok;
            ok = monitor.PriorityCaptures.Pop(&rootSecond) && ok;
            ok = ok && rootFirst.RootCr3 == 0x1000 && rootSecond.RootCr3 == 0x2000 &&
                rootFirst.Key != rootSecond.Key && rootFirst.Identity.SameInstance(identity) &&
                rootSecond.Identity.SameInstance(identity);
            monitor.CapturedKeys.erase(rootFirst.Key);
            monitor.CapturedKeys.erase(rootSecond.Key);
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
            // A failed middle page must not hide the readable tail, including
            // when stop is requested after admission. Guard protection must
            // survive; no kernel fallback is allowed for a known guard page.
            {
                KernelMonitor unavailable;
                const auto kernel = ObserveProcessIdentity(0);
                ok = unavailable.QueueCapture(L"selftest_kernel_unavailable", 0xFFFF900000001000ull,
                    9 * 4096, kernel, ObservationFileTime(), nullptr) && ok;
                ok = unavailable.QueueCapture(L"selftest_kernel_fairness", 0xFFFF900000020000ull,
                    4096, kernel, ObservationFileTime(), nullptr) && ok;
                unavailable.CaptureStopping.store(true);
                unavailable.CaptureLoop();
                ok = ok && unavailable.CaptureTraversed.load() == 2 && unavailable.CaptureKernelContinuations.load() == 6 &&
                    unavailable.CaptureReadFailedBytes.load() == 10 * 4096 &&
                    unavailable.CaptureReadBytes.load() == 0 && unavailable.CapturedPages.Size() == 0 &&
                    unavailable.PriorityCaptures.Loss() == 0 && unavailable.ContinuedCaptures.Loss() == 0;
                std::vector<std::wstring> order;
                for (const auto& event : unavailable.PipelineEvents.Drain(32))
                {
                    if (event.Kind == L"coverage.capture" && event.Observation.Coverage.FailedBytes == 4096)
                    { order.push_back(event.Evidence.at(L"capture_id")); }
                }
                const auto other = std::find_if(order.begin(), order.end(), [&](const auto& id) { return id != order.front(); });
                ok = ok && order.size() == 10 && other != order.end() &&
                    other - order.begin() == 4 && order.front() == order.back();
            }
            for (const DWORD protection : {PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD})
            {
                auto memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 3 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (memory == nullptr) { ok = false; break; }
                std::memset(memory, 0x53, 4096);
                std::memset(memory + 8192, 0x74, 4096);
                DWORD old = 0;
                const bool protectedPage = VirtualProtect(memory + 4096, 4096, protection, &old) != FALSE;
                KernelMonitor holes;
                const uint64_t start = reinterpret_cast<uint64_t>(memory) + 17;
                ok = protectedPage && holes.QueueCapture(L"selftest_hole", start, 12288 - 17,
                    identity, ObservationFileTime(), nullptr) && ok;
                holes.CaptureStopping.store(true);
                holes.CaptureLoop();
                const auto pages = holes.CapturedPages.Drain(8);
                MEMORY_BASIC_INFORMATION middle{};
                ok = ok && VirtualQuery(memory + 4096, &middle, sizeof(middle)) == sizeof(middle) &&
                    middle.Protect == protection && pages.size() == 2 &&
                    pages[0].Offset == 0 && pages[0].Bytes == std::vector<uint8_t>(4096 - 17, 0x53) &&
                    pages[1].Offset == 8192 - 17 && pages[1].Bytes == std::vector<uint8_t>(4096, 0x74) &&
                    holes.CaptureFailed.load() == 1 && holes.CaptureTraversed.load() == 1 &&
                    holes.CaptureReadBytes.load() == 8192 - 17 && holes.CaptureReadFailedBytes.load() == 0 &&
                    holes.CaptureUnreadableBytes.load() == 4096;
                bool honestResult = false;
                for (const auto& event : holes.PipelineEvents.Drain(16))
                {
                    const auto& coverage = event.Observation.Coverage;
                    honestResult = honestResult || (event.Kind == L"coverage.capture_result" &&
                        coverage.TraversalComplete && !coverage.Complete() && coverage.FailedBytes == 0 &&
                        coverage.ComparedBytes == 8192 - 17 && coverage.SkippedBytes == 4096);
                }
                ok = ok && honestResult;
                MEMORY_BASIC_INFORMATION head{};
                if (VirtualQuery(memory, &head, sizeof(head)) == sizeof(head))
                {
                    ProcessLayoutCandidate candidate;
                    candidate.Identity = identity;
                    candidate.Region = {reinterpret_cast<uint64_t>(head.BaseAddress), head.RegionSize,
                        reinterpret_cast<uint64_t>(head.AllocationBase), head.State, head.Protect, head.AllocationProtect, head.Type};
                    candidate.ObservedAt = ObservationFileTime();
                    candidate.ObservedMs = GetTickCount64();
                    candidate.Role = L"selftest_shutdown";
                    holes.LayoutCandidates.Push(candidate);
                    ++candidate.Identity.CreateTime;
                    holes.LayoutCandidates.Push(candidate);
                    holes.Options.LogDirectory = unique;
                    holes.Stop(nullptr);
                    ok = ok && holes.LayoutCandidates.Size() == 0 && holes.LayoutChecked.load() == 1 &&
                        holes.LayoutRejected.load() == 1 && holes.ShutdownLayoutProcessed == 2;
                }
                else { ok = false; }
                VirtualFree(memory, 0, MEM_RELEASE);
            }
            // Backpressure must preserve unread source events, including when
            // shutdown starts with a full analysis queue. Real source eviction
            // must still be reported instead of disguised as successful drain.
            {
                KernelMonitor bounded;
                for (size_t i = 0; i < 368; ++i) { bounded.PipelineEvents.Push(KmonEvent{}); }
                ProcessLayoutNotice notice;
                notice.Identity = identity;
                notice.Status = L"complete";
                notice.Cycle = 1;
                notice.ChangedRanges = notice.CandidateRanges = 17;
                notice.Changes.resize(17);
                for (auto& change : notice.Changes) { change.Flags = process_layout::BecameExecutable; }
                bool atomic = !bounded.QueueLayoutNotice(notice) && bounded.PipelineEvents.Size() == 368 &&
                    bounded.PipelineEvents.Loss() == 0;
                bounded.PipelineEvents.Drain(512);
                atomic = bounded.QueueLayoutNotice(notice) && bounded.PipelineEvents.Size() == 17 && atomic;
                const auto records = bounded.PipelineEvents.Drain(512);
                atomic = records.size() == 17 && records.front().Kind == L"coverage.layout" && atomic;
                for (size_t i = 1; i < records.size(); ++i) { atomic = records[i].Kind == L"finding.layout_change" && atomic; }
                if (!atomic) { std::fprintf(stderr, "FAIL atomic layout diagnostic admission\n"); }
                ok = atomic && ok;
                // With no admitted candidates, stop must retry the source
                // notice after its first iteration frees the diagnostic queue.
                for (size_t i = 0; i < 368; ++i) { bounded.PipelineEvents.Push(KmonEvent{}); }
                bounded.Options.LogDirectory = unique;
                bounded.LayoutMonitor.Reset();
                ProcessLayoutScope scope;
                scope.All = false;
                scope.Pids.insert(GetCurrentProcessId());
                std::atomic<bool> stop{false};
                const auto noticeDeadline = GetTickCount64() + 5000;
                while (bounded.LayoutMonitor.Stats().NoticesPending == 0 && GetTickCount64() < noticeDeadline)
                {
                    bounded.LayoutMonitor.Tick(scope, stop,
                        [&](const ProcessLayoutNotice& item) { return bounded.QueueLayoutNotice(item); },
                        [](ProcessLayoutCandidate) { return true; });
                }
                const bool retained = bounded.LayoutMonitor.Stats().NoticesPending == 1;
                bounded.Stop(nullptr);
                const bool drained = retained && bounded.LayoutMonitor.Stats().NoticesPending == 0 &&
                    bounded.PipelineEvents.Loss() == 0 && bounded.PipelineEvents.Size() == 0;
                if (!drained) { std::fprintf(stderr, "FAIL retained layout notice shutdown\n"); }
                ok = drained && ok;
            }
            for (const size_t sourceCapacity : {4096u, 1024u})
            {
                TimelineStore upstream(sourceCapacity);
                std::vector<TimelineEvent> rawEvents(3000);
                for (size_t index = 0; index < rawEvents.size(); ++index)
                {
                    auto& raw = rawEvents[index];
                    raw.Source = L"kernel-live";
                    raw.Action = L"selftest-unclassified";
                    raw.Entity = L"backpressure-" + std::to_wstring(index);
                    raw.TimestampFileTime = ObservationFileTime() + index;
                }
                const auto added = upstream.IngestEvents(rawEvents);
                KernelMonitor pressure;
                pressure.Options.LogDirectory = unique;
                pressure.Timeline = &upstream;
                bool preserved = added.Added == 3000;
                if (sourceCapacity == 4096)
                {
                    for (size_t page = 0; page < 4; ++page) { pressure.CollectLivePage(&upstream); }
                    preserved = preserved && pressure.CollectedLive.Available() == 0 &&
                        pressure.LiveCursorEventId == 2048;
                    pressure.CollectLivePage(&upstream);
                    preserved = preserved && pressure.LiveCursorEventId == 2048 &&
                        pressure.CollectedLive.Loss() == 0 && pressure.CollectionLost.load() == 0;
                }
                else
                {
                    // The first retained event lies one past the shutdown
                    // fence: the single evicted event must count as lost.
                    pressure.LiveCursorEventId = 1975;
                    pressure.CollectLivePage(&upstream, 1976);
                    preserved = preserved && pressure.LiveCursorEventId == 1976 &&
                        pressure.CollectionLost.load() == 1 && pressure.CollectedLive.Size() == 0;
                    pressure.LiveCursorEventId = 0;
                    pressure.CollectionLost.store(0);
                }
                pressure.Stop(nullptr);
                const uint64_t retained = sourceCapacity == 4096 ? 3000 : 1024;
                preserved = preserved && pressure.LiveCursorEventId == 3000 &&
                    pressure.LiveIngested.load() == retained && pressure.ShutdownEventsProcessed == retained &&
                    pressure.CollectedLive.Size() == 0 && pressure.CollectedLive.Loss() == 0 &&
                    pressure.CollectionLost.load() == 3000 - retained && pressure.ShutdownEventsUnanalyzed == 0;
                if (!preserved) { std::fprintf(stderr, "FAIL live source backpressure/shutdown capacity=%zu\n", sourceCapacity); }
                ok = preserved && ok;
                for (const auto& path : pressure.SessionLogPaths()) { DeleteFileW(path.c_str()); }
            }
            for (const size_t sourceCapacity : {4096u, 1024u})
            {
                // Seed a stopped subscriber's actual ring without starting ETW
                // or writing source logs. Sequence 1 is the consumer baseline.
                TiSubscriber upstream;
                upstream.TraceLifecycle.Generation = 7;
                upstream.NextRingSequence = 3002;
                for (uint64_t sequence = sourceCapacity == 4096 ? 1 : 1978; sequence <= 3001; ++sequence)
                {
                    TiEventRecord raw;
                    raw.Sequence = sequence;
                    raw.Timestamp = ObservationFileTime();
                    raw.TaskName = L"selftest-unclassified";
                    upstream.Ring.push_back(std::move(raw));
                }
                KernelMonitor pressure;
                pressure.Options.LogDirectory = unique;
                pressure.Ti = &upstream;
                pressure.TiTraceGeneration = 7;
                pressure.TiCursorSequence = 1;
                auto fence = upstream.RecentAfterSequenceWithStatus(pressure.TiCursorSequence, 1);
                bool preserved = true;
                if (sourceCapacity == 4096)
                {
                    // A restarted source and records past the frozen tail must
                    // neither satisfy the old fence nor advance its cursor.
                    upstream.TraceLifecycle.Generation = 8;
                    preserved &= pressure.CollectTiPage(&upstream, &fence).empty() &&
                        pressure.TiCursorSequence == 1 && pressure.TiTraceGeneration == 7;
                    upstream.TraceLifecycle.Generation = 7;
                    fence.LatestAssignedSequence = 17;
                    const auto fenced = pressure.CollectTiPage(&upstream, &fence);
                    preserved &= fenced.size() == 16 && pressure.TiCursorSequence == 17;
                    for (size_t index = 0; index < fenced.size(); ++index)
                    { preserved &= fenced[index].Sequence == index + 2; }
                    pressure.TiCursorSequence = 1;
                    for (size_t page = 0; page < 4; ++page)
                    {
                        const auto events = pressure.CollectTiPage(&upstream);
                        preserved &= events.size() == 512;
                        for (size_t index = 0; index < events.size(); ++index)
                        {
                            preserved &= events[index].Sequence == page * 512 + index + 2;
                            preserved &= pressure.CollectedTi.Push(events[index]);
                        }
                    }
                    preserved &= pressure.CollectedTi.Available() == 0 && pressure.TiCursorSequence == 2049 &&
                        pressure.CollectTiPage(&upstream).empty() && pressure.TiCursorSequence == 2049;
                    TiEventRecord consumed;
                    preserved &= pressure.CollectedTi.Pop(&consumed) && consumed.Sequence == 2;
                    const auto one = pressure.CollectTiPage(&upstream);
                    preserved &= one.size() == 1 && pressure.TiCursorSequence == 2050;
                    if (one.size() == 1) { preserved &= one.front().Sequence == 2050 && pressure.CollectedTi.Push(one.front()); }
                }
                else
                {
                    // Eviction beyond a shutdown boundary counts only the
                    // missing records through that boundary, never later ones.
                    pressure.TiCursorSequence = 1975;
                    fence.LatestAssignedSequence = 1976;
                    preserved &= pressure.CollectTiPage(&upstream, &fence).empty() &&
                        pressure.TiCursorSequence == 1976 && pressure.CollectionLost.load() == 1;
                    pressure.TiCursorSequence = 1;
                    pressure.CollectionLost.store(0);
                }
                pressure.Stop(nullptr);
                const uint64_t retained = sourceCapacity == 4096 ? 2999 : 1024;
                preserved &= pressure.TiCursorSequence == 3001 && pressure.TiIngested.load() == retained &&
                    pressure.ShutdownEventsProcessed == retained && pressure.CollectedTi.Size() == 0 &&
                    pressure.CollectedTi.Loss() == 0 && pressure.CollectionLost.load() == (sourceCapacity == 4096 ? 0 : 1976) &&
                    pressure.ShutdownEventsUnanalyzed == 0;
                if (!preserved) { std::fprintf(stderr, "FAIL TI source backpressure/shutdown capacity=%zu\n", sourceCapacity); }
                ok = preserved && ok;
                for (const auto& path : pressure.SessionLogPaths()) { DeleteFileW(path.c_str()); }
            }
            // More than one normal analysis batch must survive final shutdown.
            monitor.WatchPids.insert(GetCurrentProcessId());
            for (uint64_t i = 0; i < 513; ++i)
            {
                TimelineEvent raw;
                raw.Source = L"kernel-live";
                raw.Action = L"process-create";
                raw.Entity = L"kn-shutdown-fixture.exe";
                raw.ProcessId = GetCurrentProcessId();
                raw.TimestampFileTime = ObservationFileTime();
                raw.EventId = i + 1;
                ok = monitor.CollectedLive.Push(std::move(raw)) && ok;
            }
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
            ok = ok && monitor.CapturedRegions.Size() == 0 && monitor.CatalogRecords.load() == 600 &&
                monitor.LiveIngested.load() == 513 && monitor.ShutdownEventsProcessed == 513 &&
                monitor.ShutdownEventsUnanalyzed == 0;
            bool finalStats = false;
            size_t classifiedShutdown = 0;
            for (const auto& event : monitor.Ring)
            {
                if (event.Kind == L"process.create" && event.Image == L"kn-shutdown-fixture.exe") { ++classifiedShutdown; }
                ok = ok && event.Kind != L"coverage.shutdown_event";
                const auto marker = event.Evidence.find(L"final_drain");
                finalStats = finalStats || (event.Kind == L"coverage.pipeline" &&
                    marker != event.Evidence.end() && marker->second == L"true");
            }
            if (!finalStats || classifiedShutdown != 513 || monitor.ShutdownEventsUnanalyzed != 0)
            {
                std::fprintf(stderr, "FAIL shutdown event analysis: classified=%zu unprocessed=%llu\n",
                    classifiedShutdown, static_cast<unsigned long long>(monitor.ShutdownEventsUnanalyzed));
            }
            ok = ok && finalStats && classifiedShutdown == 513;
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
            // Classification is applied at the publication boundary, including
            // events with an older or overconfident producer-supplied category.
            KmonEvent normal;
            normal.Kind = L"finding.layout_change";
            normal.Evidence[L"event_category"] = L"finding";
            normal.Evidence[L"maliciousness"] = L"confirmed";
            monitor.RecordEvent(std::move(normal));
            KmonEvent lead;
            lead.Kind = L"driver.tampered";
            monitor.RecordEvent(std::move(lead));
            const auto published = monitor.Recent(2, true);
            const bool claims = published.size() == 2 &&
                published[0].Evidence.at(L"event_category") == L"lead" &&
                published[1].Evidence.at(L"event_category") == L"observation" &&
                published[0].Evidence.at(L"maliciousness") == L"not_established" &&
                published[1].Evidence.at(L"maliciousness") == L"not_established";
            if (!claims)
            {
                std::fprintf(stderr, "FAIL kmon event evidence classification\n");
            }
            ok = claims && ok;
            for (bool knownRange : {false, true})
            {
                KmonEvent load;
                load.Kind = L"driver.official_load";
                load.Driver = L"review-baseline.sys";
                if (knownRange)
                {
                    load.Evidence[L"image_base"] = L"0xfffff80000100000";
                    load.Evidence[L"image_size"] = L"0x4000";
                }
                const std::wstring stem = KmonDriverNameStem(load.Driver);
                monitor.DriverTamperBaselines[stem].HasImage = true;
                monitor.DriverTamperStrikes[stem].Image.Observe(L"old-image", 1, 10);
                monitor.DriverTamperLastCheckMs[stem] = 1;
                monitor.NoteDriverLoad(load);
                const bool reset = monitor.DriverTamperBaselines.count(stem) == 0 &&
                    monitor.DriverTamperStrikes.count(stem) == 0 && monitor.DriverTamperLastCheckMs.count(stem) == 0;
                if (!reset)
                {
                    std::fprintf(stderr, "[kmon.review] FAIL load with unavailable baseline resets prior instance\n");
                }
                ok = reset && ok;
            }
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
