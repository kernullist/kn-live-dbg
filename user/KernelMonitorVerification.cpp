#include "KernelMonitor.h"
#include "ImageSliceRecipe.h"
#include "ContentHash.h"
#include "KmonHuntingJson.h"
#include "ExecutableImagePermissions.h"
#include "ExecutionSurfaceScanner.h"
#include "NativeObservationSource.h"
#include "ProcessObservationSource.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <memory>
#include <tuple>

namespace
{
    std::wstring BytesHex(const std::vector<uint8_t>& bytes)
    {
        const wchar_t* hex = L"0123456789abcdef";
        std::wstring result;
        const size_t count = (std::min<size_t>)(bytes.size(), 64);
        result.reserve(count * 2);
        for (size_t i = 0; i < count; ++i)
        {
            const uint8_t value = bytes[i];
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 15]);
        }
        return result;
    }

    std::wstring ImageKey(const std::wstring& path, uint64_t base, const ObservationIdentity& identity)
    {
        return identity.BootId + L":" + std::to_wstring(identity.ProcessId) + L":" +
            std::to_wstring(identity.CreateTime) + L":" + std::to_wstring(base) + L":" + path;
    }

    std::wstring ReferenceKey(uint64_t target, uint64_t slot, const std::wstring& role,
        const ObservationIdentity& identity)
    {
        return ImageKey(role, target, identity) + L":" + std::to_wstring(slot);
    }

    bool SameReferenceFile(HANDLE alias, const std::wstring& path,
        const executable_image::DiskPeMetadata* reference)
    {
        // Use the full volume/file ID for aliasing (also on file systems with
        // 128-bit IDs), and the metadata stamp to reject a replaced reference.
        HANDLE original = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (original == INVALID_HANDLE_VALUE) { return false; }
        const std::unique_ptr<void, decltype(&CloseHandle)> owner(original, &CloseHandle);
        FILE_ID_INFO a{}, b{};
        // A pending job has no parsed metadata yet. Full file identity is
        // enough to share that preparation request, never to qualify bytes.
        return (reference == nullptr || (executable_image::DiskFileIdentityMatches(alias, *reference) &&
            executable_image::DiskFileIdentityMatches(original, *reference))) &&
            GetFileInformationByHandleEx(alias, FileIdInfo, &a, sizeof(a)) &&
            GetFileInformationByHandleEx(original, FileIdInfo, &b, sizeof(b)) &&
            a.VolumeSerialNumber == b.VolumeSerialNumber &&
            std::memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier)) == 0;
    }

    std::vector<KernelModuleInfo> UserModules(uint32_t pid)
    {
        std::vector<KernelModuleInfo> modules;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (Module32FirstW(snapshot, &entry))
            {
                do
                {
                    modules.push_back({reinterpret_cast<uint64_t>(entry.modBaseAddr),
                        entry.modBaseSize, entry.szExePath, entry.szModule});
                } while (modules.size() < 4096 && Module32NextW(snapshot, &entry));
                if (modules.size() >= 4096 || GetLastError() != ERROR_NO_MORE_FILES)
                {
                    modules.clear();
                }
            }
            CloseHandle(snapshot);
        }
        return modules;
    }

    bool ResolveHuntAddressSpace(DeviceClient& device, SymbolEngine& symbols,
        const ObservationIdentity& identity, ProcessAddressContext* context)
    {
        TypeFieldInfo pcb = {}, dtb = {}, create = {};
        if (!symbols.FindField(L"nt!_EPROCESS", L"Pcb", &pcb, nullptr) ||
            !symbols.FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtb, nullptr) ||
            !symbols.FindField(L"nt!_EPROCESS", L"CreateTime", &create, nullptr) ||
            pcb.IsBitField || dtb.IsBitField || create.IsBitField || dtb.Length != 8 || create.Length != 8 ||
            pcb.Offset >= 0x10000 || dtb.Offset >= 0x10000 || create.Offset >= 0x10000 ||
            pcb.Offset + dtb.Offset > 0x10000 - 8 ||
            !device.ResolveProcess(identity.ProcessId, static_cast<uint32_t>(pcb.Offset + dtb.Offset), 0, context, nullptr) ||
            !device.AddressSpace().KernelRange(context->Eprocess, create.Offset + 8) ||
            (identity.Eprocess != 0 && identity.Eprocess != context->Eprocess))
        {
            return false;
        }
        std::vector<uint8_t> bytes;
        uint64_t creation = 0;
        if (!device.ReadMemory(context->Eprocess + create.Offset, 8, &bytes, nullptr) || bytes.size() != 8)
        {
            return false;
        }
        std::memcpy(&creation, bytes.data(), 8);
        return creation == identity.CreateTime && creation != 0 && context->DirectoryTableBase != 0;
    }
}

bool KernelMonitor::ResolveObservationProcess(DeviceClient& device, SymbolEngine& symbols,
    const ObservationIdentity& identity, ProcessAddressContext* context)
{
    return ResolveHuntAddressSpace(device, symbols, identity, context);
}

void KernelMonitor::RememberImageRescanDelay(const ImageVerificationWork& work, uint64_t now)
{
    if (!work.Loaded || !work.Sweep.Coverage.TraversalComplete || work.Sweep.LastCompleteMs == 0 ||
        !work.Reference.HasFileIdentity || !work.Reference.HasFileBasicIdentity) { return; }
    for (auto it = ImageRescanDelays.begin(); it != ImageRescanDelays.end();)
    {
        if (now >= it->second.ExpiresMs) { it = ImageRescanDelays.erase(it); }
        else { ++it; }
    }
    // These records hold only file identities/deadlines, never PE ranges or
    // verification results. Retain prior traversal classification beyond the
    // delay so cache churn cannot promote repeat work into the initial lane.
    // Losing history at this bound merely gives work earlier service.
    if (ImageRescanDelays.size() >= 4096) { return; }
    HANDLE file = CreateFileW(work.Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) { return; }
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(file, &CloseHandle);
    ImageRescanDelay delay;
    if (!executable_image::DiskFileIdentityMatches(file, work.Reference) ||
        !GetFileInformationByHandleEx(file, FileIdInfo, &delay.FileId, sizeof(delay.FileId))) { return; }
    delay.FileIdentity = work.Reference.FileIdentity;
    delay.FileBasicIdentity = work.Reference.FileBasicIdentity;
    delay.DueMs = work.NextSweepDueMs;
    delay.TraversedMs = work.Sweep.LastCompleteMs;
    delay.ExpiresMs = now + 300000;
    ImageRescanDelays[ImageKey(L"", work.Base, work.Identity)] = delay;
}

bool KernelMonitor::ImageRescanDelayed(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, uint64_t now, uint64_t* priorTraversal)
{
    if (priorTraversal != nullptr) { *priorTraversal = 0; }
    const auto it = ImageRescanDelays.find(ImageKey(L"", base, identity));
    if (it == ImageRescanDelays.end()) { return false; }
    if (now < it->second.ExpiresMs)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            const std::unique_ptr<void, decltype(&CloseHandle)> owner(file, &CloseHandle);
            executable_image::DiskPeMetadata reference;
            reference.HasFileIdentity = reference.HasFileBasicIdentity = true;
            reference.FileIdentity = it->second.FileIdentity;
            reference.FileBasicIdentity = it->second.FileBasicIdentity;
            FILE_ID_INFO id{};
            if (executable_image::DiskFileIdentityMatches(file, reference) &&
                GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) &&
                id.VolumeSerialNumber == it->second.FileId.VolumeSerialNumber &&
                std::memcmp(id.FileId.Identifier, it->second.FileId.FileId.Identifier, sizeof(id.FileId.Identifier)) == 0)
            {
                // Keep actively rediscovered identities in the repeat lane.
                // Only the idle eviction deadline moves: the original rescan
                // due time, traversal timestamp and current coverage do not.
                it->second.ExpiresMs = now + 300000;
                if (now < it->second.DueMs)
                {
                    ++ImageRescanDelayHits;
                    return true;
                }
                if (priorTraversal != nullptr)
                {
                    *priorTraversal = it->second.TraversedMs;
                    ++ImageRescanHistoryHits;
                }
                return false;
            }
        }
    }
    // File replacement, unavailable identity, expiry, or a new process/base
    // must be able to start fresh. A path alias alone never justifies delay.
    ImageRescanDelays.erase(it);
    return false;
}

size_t KernelMonitor::ImageWorkAdmissionLimit(uint32_t pid, bool* watched)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    *watched = pid != 0 && WatchPids.count(pid) != 0;
    if (*watched || (WatchPids.empty() && WatchNamesLower.empty())) { return ImageWorkCapacity; }
    size_t occupied = 0;
    for (const auto& item : ImageWork)
    {
        if (item.second.Identity.ProcessId != 0 && WatchPids.count(item.second.Identity.ProcessId) != 0)
        {
            if (++occupied == ImageWatchReserve) { break; }
        }
    }
    // Scheduling already favors watched processes. Reserve admission space as
    // well, otherwise unfinished background images can prevent a late-discovered
    // watched view from ever reaching that scheduler. Keep the same total cap
    // and retain every in-progress cursor; unused space returns as watches fill it.
    return ImageWorkCapacity - (ImageWatchReserve - occupied);
}

void KernelMonitor::ApplyImageReferenceResults()
{
    while (auto result = ImageReferences->Take())
    {
        const auto found = ImageWork.find(result->Work.Key);
        const bool current = found != ImageWork.end() && found->second.RetentionEpisode == result->Work.Episode &&
            found->second.PreparationId == result->Id && found->second.Base == result->Work.Base &&
            found->second.Path == result->Work.Path && found->second.Identity.SameCanonicalKey(result->Work.Identity) &&
            found->second.Identity.Eprocess == result->Work.Identity.Eprocess &&
            found->second.Identity.SessionKnown == result->Work.Identity.SessionKnown &&
            (!found->second.Identity.SessionKnown || found->second.Identity.SessionId == result->Work.Identity.SessionId);
        ImageReferences->Disposition(*result, current && !StopRequested.load());
        if (!current) { continue; }
        auto& work = found->second;
        work.PreparationId = 0;
        if (StopRequested.load()) { work.PreparationCancelled = true; continue; }
        work.PreparationOutcome = result->Status; work.PreparationCancelled = false;
        work.LastAttemptMs = result->Started;
        work.PreparationFinishedMs = result->Finished;
        work.PreparationFailed = result->Status != ImageReferencePreparation::Outcome::Prepared;
        if (!work.PreparationFailed && result->Value)
        {
            work.Reference = std::move(result->Value->Reference);
            work.Sweep = std::move(result->Value->Sweep);
            work.Loaded = true; work.LastReferenceCheckMs = 0; work.ReferenceRetryAfterMs = 0;
            work.PreparationSuccessMs = result->Finished; work.PreparationSuccessEpisode = work.RetentionEpisode;
        }
        else
        {
            work.Loaded = false;
            work.ReferenceRetryAfterMs = result->Finished + 30000;
            const auto now = GetTickCount64();
            if (work.Scheduling.Begin(now))
            { work.Scheduling.Finish(now, KmonImageAttemptOutcome::ReferenceUnavailable, false, false, work.RetentionEpisode); }
            EmitUnique(L"coverage.image", L"scan_failed:image:" + found->first, work.Path, L"image",
                L"executable image reference unavailable", ImageReferencePreparation::OutcomeName(result->Status) +
                    std::wstring(L": ") + result->Error, work.Identity.ProcessId);
        }
    }
}

KernelMonitor::ImageVerificationWork* KernelMonitor::FindImageWork(const std::wstring& path,
    uint64_t base, const ObservationIdentity& identity, bool* referenceUnavailable, ImageVerificationWork** admitted, bool discovery)
{
    if (admitted != nullptr) { *admitted = nullptr; }
    const auto lookupStarted = GetTickCount64();
    bool lookupReady = false;
    struct LookupTiming
    {
        KmonImageTimings& Stats; uint64_t Started; const bool& Ready; bool Shutdown;
        ~LookupTiming() { Stats.Lookup(Started, GetTickCount64(), Ready, Shutdown); }
    } lookupTiming{ImageTimings, lookupStarted, lookupReady, StopRequested.load()};
    ApplyImageReferenceResults();
    if (referenceUnavailable != nullptr) { *referenceUnavailable = false; }
    if (base == 0 || path.empty() || (identity.ProcessId != 0 && identity.CreateTime == 0))
    {
        return nullptr;
    }
    const auto key = ImageKey(path, base, identity);
    const uint64_t now = GetTickCount64();
    auto it = ImageWork.find(key);
    if (it == ImageWork.end())
    {
        // A mapped device path and a loader DOS path can name the same file.
        // Share a cursor only after checking the backing identity and process
        // generation; basename/path normalization alone is not evidence.
        HANDLE alias = INVALID_HANDLE_VALUE;
        for (auto candidate = ImageWork.begin(); candidate != ImageWork.end(); ++candidate)
        {
            if (candidate->second.Base != base || (!candidate->second.Loaded && candidate->second.PreparationId == 0) ||
                !candidate->second.Identity.SameInstance(identity)) { continue; }
            if (alias == INVALID_HANDLE_VALUE)
            {
                alias = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (alias == INVALID_HANDLE_VALUE) { break; }
            }
            if (SameReferenceFile(alias, candidate->second.Path, candidate->second.Loaded ? &candidate->second.Reference : nullptr))
            {
                it = candidate;
                break;
            }
        }
        if (alias != INVALID_HANDLE_VALUE) { CloseHandle(alias); }
    }
    if (it == ImageWork.end())
    {
        uint64_t priorTraversal = 0;
        if (ImageRescanDelayed(path, base, identity, now, &priorTraversal)) { return nullptr; }
        bool watched = false;
        auto limit = ImageWorkAdmissionLimit(identity.ProcessId, &watched);
        if (ImageWork.size() >= limit)
        {
            for (auto old = ImageWork.begin(); old != ImageWork.end();)
            {
                if (now - old->second.LastUsedMs > 300000 || old->second.Sweep.Coverage.TraversalComplete)
                {
                    RememberImageRescanDelay(old->second, now);
                    ImageReferences->Abandon(old->second.PreparationId);
                    old = ImageWork.erase(old);
                    ++ImageWorkEvicted;
                }
                else
                {
                    ++old;
                }
            }
        }
        limit = ImageWorkAdmissionLimit(identity.ProcessId, &watched);
        if (ImageWork.size() >= limit)
        {
            ++ImageAdmissionDeferred;
            if (watched) { ++ImageWatchAdmissionDeferred; }
            // These are retry attempts, not a count of distinct missing views.
            // Sample with the actual process/mapping identity instead of one
            // global PID-zero diagnostic that hides which image was deferred.
            if (now >= NextImageAdmissionReportMs)
            {
                KmonEvent deferred;
                deferred.Kind = L"coverage.image";
                deferred.ProcessId = identity.ProcessId;
                deferred.Image = path;
                deferred.Summary = L"image_reference_admission_deferred";
                deferred.Observation.Identity = identity;
                deferred.Observation.Source = L"executable_page_sweep";
                deferred.Observation.Coverage.Attempted = true;
                deferred.Observation.Coverage.Reason = L"image_reference_admission_deferred";
                deferred.Evidence[L"image_base"] = std::to_wstring(base);
                deferred.Evidence[L"image_work_items"] = std::to_wstring(ImageWork.size());
                deferred.Evidence[L"admission_limit"] = std::to_wstring(limit);
                deferred.Evidence[L"watched"] = watched ? L"true" : L"false";
                deferred.Evidence[L"policy"] = L"bounded_cache; preserve_incomplete_cursors; retry_on_rediscovery";
                RecordEvent(std::move(deferred));
                NextImageAdmissionReportMs = now + 5000;
            }
            return nullptr;
        }
        it = ImageWork.emplace(key, ImageVerificationWork{}).first;
        it->second.Identity = identity;
        it->second.RetentionEpisode = NextCaptureId.fetch_add(1);
        it->second.Path = path;
        it->second.Base = base;
        it->second.PriorTraversalMs = priorTraversal;
    }
    auto& work = it->second;
    if (admitted != nullptr) { *admitted = &work; }
    if (discovery || !work.Scheduling.Seen) { work.Scheduling.Discover(now); work.LastUsedMs = now; }
    if (work.Loaded && (work.LastReferenceCheckMs == 0 || now - work.LastReferenceCheckMs >= 1000))
    {
        work.LastReferenceCheckMs = now;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        const bool stable = file != INVALID_HANDLE_VALUE && executable_image::DiskFileIdentityMatches(file, work.Reference);
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
        if (!stable)
        {
            // A DLL can be unloaded and replaced at the same base/path. Never
            // let a failed cached reference disable verification indefinitely.
            work.Loaded = false;
            if (!work.Scheduling.Pending) { work.Scheduling.Pending = true; work.Scheduling.PendingSince = now; }
            work.RetentionEpisode = NextCaptureId.fetch_add(1);
            work.LayoutIdentityReported = false;
            work.LastAttemptMs = 0;
            ImageReferences->Abandon(work.PreparationId);
            work.PreparationId = 0; work.ReferenceRetryAfterMs = 0; work.PreparationFailed = false;
            work.ManifestChecked = false;
            work.ManifestMatches = false;
            work.ObjectCursor = 0;
            work.PermissionCursor = 0;
            work.ObjectReports.clear();
            work.ReportedHashes.clear();
            work.Sweep = {};
            work.NextSweepDueMs = 0;
            work.PriorTraversalMs = 0;
        }
    }
    if (!work.Loaded && work.PreparationId == 0 && now >= work.ReferenceRetryAfterMs && !StopRequested.load())
    {
        work.LastSweepMs = now;
        ImageReferencePreparation::Request request;
        request.Key = it->first; request.Path = work.Path; request.Identity = work.Identity;
        request.Base = work.Base; request.Episode = work.RetentionEpisode; request.FirstSeen = work.Scheduling.FirstSeen;
        const auto ticket = ImageReferences->Submit(std::move(request), now);
        if (ticket.Status == ImageReferencePreparation::Admission::Queued)
        {
            work.PreparationId = work.LastPreparationId = ticket.Id; work.PreparationQueuedMs = now;
            work.PreparationFailed = work.PreparationCancelled = false;
        }
    }
    // Queueing/backpressure is not evidence that the file could not be parsed.
    if (referenceUnavailable != nullptr) { *referenceUnavailable = work.PreparationFailed; }
    lookupReady = work.Loaded;
    return work.Loaded ? &work : nullptr;
}

CodeOwnership KernelMonitor::ScanExecutableImage(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader, size_t pageBudget,
    const ObservationReadRouting* routing, bool discovery)
{
    const auto turnStarted = GetTickCount64();
    ImageVerificationWork* admitted = nullptr;
    KmonImageAttemptOutcome outcome = KmonImageAttemptOutcome::Fault;
    ExecutableSweepTiming timing;
    KmonImageObservationDebt before;
    bool attempted = false;
    bool traversed = false, gapFree = false;
    struct TurnTiming
    {
        KmonImageTimings& Stats; ImageVerificationWork*& Work; KmonImageObservationDebt& Before;
        ExecutableSweepTiming& Timing; KmonImageAttemptOutcome& Outcome; bool& Attempted;
        bool& Traversed; bool& GapFree; uint64_t Started; bool Shutdown;
        ~TurnTiming()
        {
            const auto ended = GetTickCount64();
            if (Work != nullptr && Attempted)
            {
                Work->Scheduling.Finish(ended, Outcome, Traversed, GapFree, Work->RetentionEpisode);
                Stats.Milestones(Before, Work->Scheduling, Shutdown);
            }
            Stats.Turn(Started, ended, Timing, Outcome, Shutdown);
        }
    } turnTiming{ImageTimings, admitted, before, timing, outcome, attempted, traversed, gapFree, turnStarted, StopRequested.load()};
    auto work = FindImageWork(path, base, identity, nullptr, &admitted, discovery);
    if (work == nullptr)
    {
        outcome = admitted == nullptr ? KmonImageAttemptOutcome::NotAdmitted :
            admitted->PreparationFailed ? KmonImageAttemptOutcome::ReferenceUnavailable : KmonImageAttemptOutcome::ReferencePending;
        return CodeOwnership::OwnedUnverified;
    }
    const uint64_t now = GetTickCount64();
    if (now < work->NextSweepDueMs) { outcome = KmonImageAttemptOutcome::Deferred; return CodeOwnership::OwnedUnverified; }
    before = work->Scheduling;
    attempted = work->Scheduling.Begin(now);
    if (!attempted) { outcome = KmonImageAttemptOutcome::InvalidClock; return CodeOwnership::OwnedUnverified; }
    work->LastSweepMs = now;
    FILETIME observedTime{};
    GetSystemTimeAsFileTime(&observedTime);
    const uint64_t observedFileTime = (uint64_t(observedTime.dwHighDateTime) << 32) | observedTime.dwLowDateTime;
    std::unique_ptr<ObservationReadRouter> router;
    ObservationReader observedReader = reader;
    std::wstring operationId;
    if (routing != nullptr)
    {
        operationId = L"kmon-image:" + std::to_wstring(EvidenceCollectionEpoch.load()) + L":" +
            std::to_wstring(NextCaptureId.fetch_add(1));
        auto operation = std::make_shared<ObservationReadOperation>(operationId, routing->TargetId, routing->AddressSpaceId,
            ObservationOperationBudget{16 * 1024 * 1024, 4096, 4096, 65536, 5000});
        router = std::make_unique<ObservationReadRouter>(*routing, std::move(operation), &StopRequested);
        observedReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            return router->ReadExact(address, size, bytes);
        };
        if (work->RecordingSweep.SweepId.empty() || work->Sweep.NextRange == 0 || work->Sweep.NextRange == work->Sweep.Ranges.size())
        {
            auto& recording = work->RecordingSweep;
            recording = {};
            recording.CollectionId = std::to_wstring(EvidenceCollectionEpoch.load());
            recording.SweepId = recording.CollectionId + L"-" + std::to_wstring(NextCaptureId.fetch_add(1));
            recording.Identity = work->Identity;
            recording.Image = work->Path;
            recording.ImageBase = base;
            recording.TargetId = routing->TargetId;
            recording.AddressSpaceId = routing->AddressSpaceId;
            recording.TotalRanges = static_cast<uint32_t>(work->Sweep.Ranges.size());
            recording.ExpectedBytes = work->Sweep.Coverage.RequestedBytes;
            recording.StartedTick = now;
            recording.StartedFileTime = observedFileTime;
            work->RecordingSlice = 0;
            ImageSweepsStarted.fetch_add(1);
        }
    }
    const auto read = observedReader;
    observedReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
    {
        if (!work->Scheduling.ParserAttempted)
        { work->Scheduling.FirstParserAttempt = GetTickCount64(); work->Scheduling.ParserAttempted = true; }
        const bool ok = read && read(address, size, bytes) && bytes->size() == size;
        if (ok && !work->Scheduling.ExactRead)
        { work->Scheduling.FirstExactRead = GetTickCount64(); work->Scheduling.ExactRead = true; }
        return ok;
    };
    ExecutableSweepReference capturedReference;
    ExecutableSliceTrace slice;
    const auto pages = AdvanceExecutableSweep(path, work->Reference, base, observedReader, pageBudget, now, &work->Sweep, KmonImageTurnBudgetMs,
        router == nullptr ? nullptr : &capturedReference, router == nullptr ? nullptr : &slice, &timing, turnStarted);
    uint64_t readSetId = 0;
    std::wstring readPersistence = routing == nullptr ? L"unrecorded_reader" : L"not_selected_for_retention";
    // Retain clean ranges as well as changes and gaps from the original slice.
    // Recipe eligibility is separate from raw-read/reference preservation.
    if (router != nullptr)
    {
        const auto reads = router->Snapshot();
        const auto recipe = CaptureImageSliceRecipeJson(work->Reference, base, capturedReference, slice, reads, pages);
        ImageSweepContext context;
        context.Sweep = work->RecordingSweep;
        // Never compress the ordinal when the bounded publication queue rejects
        // an item: later entries and the terminal record must expose that hole.
        context.Slice.Ordinal = ++work->RecordingSlice;
        context.Slice.StartRange = slice.StartRange;
        context.Slice.RangeCount = slice.PageCount;
        context.Slice.StartedTick = reads.Attempts.StartedTick;
        context.Slice.EndedTick = reads.Attempts.SnapshotTick;
        context.Slice.ObservedFileTime = observedFileTime;
        context.Slice.TraversalComplete = work->Sweep.Coverage.TraversalComplete;
        context.Slice.Terminal = context.Slice.TraversalComplete || work->Sweep.NextRange == 0;
        if (context.Slice.Terminal) { ImageSweepTerminalsObserved.fetch_add(1); }
        context.Slice.Reason = work->Sweep.Coverage.Reason;
        if (capturedReference.Artifact != nullptr) { context.Slice.ReferenceSha256 = capturedReference.Artifact->Sha256; }
        readSetId = QueueImageReadSet(reads, identity, path, base, &capturedReference, recipe, &slice, &context, &pages,
            work->RetentionEpisode, {turnStarted, timing.FinishedMs, true});
        readPersistence = readSetId == 0 ? L"not_queued" : L"queued";
    }
    // Completed small images must not continually restart while larger images
    // still have an unvisited tail. Failed identities are retried, not trusted.
    work->NextSweepDueMs = work->Sweep.Coverage.TraversalComplete ? now + 30000 :
        (pages.empty() ? now + 5000 : 0);
    if (pages.empty() && !work->Sweep.Coverage.InventoryAvailable)
    {
        work->ReportedHashes.clear();
    }
    CodeOwnership state = CodeOwnership::OwnedUnverified;
    for (size_t pageIndex = 0; pageIndex < pages.size(); ++pageIndex)
    {
        const auto& page = pages[pageIndex];
        ExecutableRegionObservation observation;
        observation.Context.Identity = identity;
        observation.Context.Source = L"executable_page_compare";
        observation.Context.DependencyGroup = L"memory_vs_file";
        observation.Context.Coverage = page.Coverage;
        observation.Context.Ownership = page.Ownership;
        observation.Context.AllocationBase = base;
        observation.Range = {base + page.Rva, page.Coverage.RequestedBytes};
        observation.Executable = true;
        observation.ImageMapping = true;
        // Keep altered/partial pages individual. Consecutive fully compared
        // pages can publish one coverage range; every byte was still read and
        // compared. A fixed 64 KiB boundary bounds catalog granularity/cost.
        if (page.Ownership == CodeOwnership::OwnedVerified && page.Rel32ValidatedBytes == 0)
        {
            work->ReportedHashes.erase(page.Rva);
            while (pageIndex + 1 < pages.size())
            {
                const auto& next = pages[pageIndex + 1];
                if (next.Ownership != CodeOwnership::OwnedVerified || next.Rel32ValidatedBytes != 0 ||
                    (page.Rva >> 16) != (next.Rva >> 16) ||
                    base + next.Rva != observation.Range.Address + observation.Range.Size) { break; }
                observation.Range.Size += next.Coverage.RequestedBytes;
                observation.Context.Coverage.RequestedBytes += next.Coverage.RequestedBytes;
                observation.Context.Coverage.ComparedBytes += next.Coverage.ComparedBytes;
                for (const auto& range : next.Coverage.Compared)
                {
                    AddObservationRange(&observation.Context.Coverage.Compared, range,
                        &observation.Context.Coverage.RangesTruncated);
                }
                work->ReportedHashes.erase(next.Rva);
                ++pageIndex;
            }
        }
        const uint64_t generation = ObserveExecutableRegion(observation);
        if (page.Ownership != CodeOwnership::OwnedModified)
        {
            if (page.Ownership == CodeOwnership::OwnedVerified)
            {
                work->ReportedHashes.erase(page.Rva);
            }
            continue;
        }
        state = CodeOwnership::OwnedModified;
        const uint64_t hash = KmonHashBytes64(page.Observed.data(), page.Observed.size());
        auto reported = work->ReportedHashes.find(page.Rva);
        if (reported != work->ReportedHashes.end() && reported->second == hash)
        {
            continue;
        }
        work->ReportedHashes[page.Rva] = hash;
        KmonEvent event;
        event.Kind = L"finding.code_modified";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Summary = L"executable bytes differ from the qualified disk image";
        event.Observation.Identity = identity;
        event.Observation.Source = L"executable_page_compare";
        event.Observation.DependencyGroup = L"memory_vs_file";
        event.Observation.ReferenceSource = work->Reference.HasPdbIdentity ? L"disk_pe_pdb_identity" : L"disk_pe_identity";
        event.Observation.Ownership = page.Ownership;
        event.Observation.Coverage = page.Coverage;
        event.Observation.MappingGeneration = generation;
        event.Evidence[L"image_base"] = std::to_wstring(base);
        event.Evidence[L"read_operation_id"] = operationId;
        event.Evidence[L"read_set_queued_id"] = std::to_wstring(readSetId);
        event.Evidence[L"read_set_persistence"] = readPersistence;
        event.Evidence[L"image_sweep_id"] = router == nullptr ? L"" : work->RecordingSweep.SweepId;
        event.Evidence[L"image_sweep_slice"] = router == nullptr ? L"0" : std::to_wstring(work->RecordingSlice);
        event.Evidence[L"verification_recipe_preserved"] = L"false";
        event.Evidence[L"rva"] = std::to_wstring(page.Rva);
        event.Evidence[L"cycle"] = std::to_wstring(work->Sweep.Cycle);
        event.Evidence[L"function_override_compared_bytes"] = std::to_wstring(page.Rel32ValidatedBytes);
        event.Evidence[L"relocation_base"] = std::to_wstring(page.RelocationBase);
        event.Evidence[L"relocation_basis"] = page.SecondaryImageView ? L"independent_sec_image_no_execute" : L"mapping_base";
        if (page.Rel32ValidatedBytes != 0)
        {
            event.Evidence[L"function_override_policy"] = L"file_declared_rel32_targets; feature_selection_not_attested";
        }
        event.Evidence[L"code_hash"] = std::to_wstring(hash);
        event.Evidence[L"observed_capture_id"] = std::to_wstring(QueueCapturedBytes(L"modified_code",
            base + page.Rva, event.Observation, page.Observed));
        event.Evidence[L"expected_capture_id"] = std::to_wstring(QueueCapturedBytes(L"expected_code",
            base + page.Rva, event.Observation, page.Expected));
        event.Evidence[L"observed_prefix"] = BytesHex(std::vector<uint8_t>(page.Observed.begin(),
            page.Observed.begin() + (std::min<size_t>)(64, page.Observed.size())));
        event.Evidence[L"reference_trust"] = L"local_file_identity; no publisher or maliciousness assertion";
        for (size_t i = 0; i < page.Changes.size() && i < 64; ++i)
        {
            event.Evidence[L"change_" + std::to_wstring(i)] = std::to_wstring(page.Changes[i].Address) +
                L":" + std::to_wstring(page.Changes[i].Size);
        }
        RecordEvent(std::move(event));
    }
    if (work->Sweep.Coverage.TraversalComplete || pages.empty())
    {
        KmonEvent coverage;
        coverage.Kind = L"coverage.image";
        coverage.ProcessId = identity.ProcessId;
        coverage.Image = path;
        coverage.Summary = work->Sweep.Coverage.Reason;
        coverage.Observation.Identity = identity;
        coverage.Observation.Source = L"executable_page_sweep";
        coverage.Observation.Coverage = work->Sweep.Coverage;
        coverage.Evidence[L"cycle"] = std::to_wstring(work->Sweep.Cycle);
        coverage.Evidence[L"read_operation_id"] = operationId;
        coverage.Evidence[L"read_set_queued_id"] = std::to_wstring(readSetId);
        coverage.Evidence[L"read_set_persistence"] = readPersistence;
        coverage.Evidence[L"image_sweep_id"] = router == nullptr ? L"" : work->RecordingSweep.SweepId;
        coverage.Evidence[L"image_sweep_slice"] = router == nullptr ? L"0" : std::to_wstring(work->RecordingSlice);
        coverage.Evidence[L"cursor"] = std::to_wstring(work->Sweep.NextRange);
        coverage.Evidence[L"remaining_pages"] = std::to_wstring(work->Sweep.Ranges.size() - work->Sweep.NextRange);
        coverage.Evidence[L"last_completion_ms"] = std::to_wstring(work->Sweep.LastCompleteMs);
        coverage.Evidence[L"image_base"] = std::to_wstring(base);
        coverage.Evidence[L"function_override_compared_bytes"] = std::to_wstring(work->Sweep.Rel32ValidatedBytes);
        coverage.Evidence[L"relocation_base"] = std::to_wstring(work->Sweep.RelocationBase);
        coverage.Evidence[L"relocation_basis"] = work->Sweep.RelocationBase == 0 ? L"unverified" :
            (work->Sweep.SecondaryImageView ? L"independent_sec_image_no_execute" : L"mapping_base");
        RecordEvent(std::move(coverage));
    }
    if (state != CodeOwnership::OwnedModified && work->Sweep.Coverage.Complete())
    {
        state = CodeOwnership::OwnedVerified;
        for (const auto& page : work->Sweep.Pages)
        {
            if (page.second == CodeOwnership::OwnedModified)
            {
                state = CodeOwnership::OwnedModified;
                break;
            }
        }
    }
    uint64_t remaining = 0;
    uint64_t lastComplete = 0;
    for (const auto& item : ImageWork)
    {
        remaining += item.second.Sweep.Ranges.size() - item.second.Sweep.NextRange;
        lastComplete = (std::max)(lastComplete, item.second.Sweep.LastCompleteMs);
    }
    ImageRemainingPages.store(remaining);
    ImageLastCompleteMs.store(lastComplete);
    outcome = !pages.empty() && std::all_of(pages.begin(), pages.end(), [](const auto& page) { return page.Coverage.Complete(); }) ?
        KmonImageAttemptOutcome::Observed : KmonImageAttemptOutcome::Gaps;
    traversed = timing.Pages != 0 && work->Sweep.Coverage.TraversalComplete;
    gapFree = traversed && work->Sweep.Coverage.Complete();
    return state;
}

std::wstring KernelMonitor::ImageSchedulingJson(uint64_t now) const
{
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    std::vector<const ImageVerificationWork*> ordered;
    uint64_t pending = 0, loaded = 0, debt = 0, known = 0, invalid = 0;
    for (const auto& item : ImageWork)
    {
        const auto& work = item.second;
        ordered.push_back(&work);
        pending += work.Scheduling.Pending;
        loaded += work.Loaded;
        if (work.Scheduling.Seen)
        {
            ++known;
            if (work.Scheduling.DebtSince() <= now) { debt = (std::max)(debt, now - work.Scheduling.DebtSince()); }
            else { ++invalid; }
        }
    }
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto* a, const auto* b)
    {
        if (a->Scheduling.Seen != b->Scheduling.Seen) { return a->Scheduling.Seen; }
        return std::make_tuple(a->Scheduling.DebtSince(), a->LastSweepMs, a->Base) <
            std::make_tuple(b->Scheduling.DebtSince(), b->LastSweepMs, b->Base);
    });
    // Exact scopes or explicit omissions. Never shorten a path into a different
    // identity, and bound both the number and serialized UTF-16 size of rows.
    constexpr size_t detailCapacity = 64, detailUnits = 65536;
    size_t details = 0;
    std::wstring rows;
    for (const auto* work : ordered)
    {
        if (details == detailCapacity) { break; }
        const auto remaining = work->Loaded && work->Sweep.NextRange <= work->Sweep.Ranges.size() ?
            n(work->Sweep.Ranges.size() - work->Sweep.NextRange) : L"null";
        const auto row = L"{\"boot_id\":" + mcpjson::Quote(work->Identity.BootId) + L",\"pid\":" + n(work->Identity.ProcessId) +
            L",\"create_time\":" + n(work->Identity.CreateTime) + L",\"base\":" + n(work->Base) + L",\"path\":" + mcpjson::Quote(work->Path) +
            L",\"retention_episode\":" + n(work->RetentionEpisode) + L",\"reference_loaded\":" + (work->Loaded ? L"true" : L"false") +
            L",\"remaining_pages\":" + remaining + L",\"next_sweep_due_ms\":" + n(work->NextSweepDueMs) +
            L",\"reference_last_attempt_ms\":" + (work->LastAttemptMs == 0 ? L"null" : n(work->LastAttemptMs)) +
            L",\"preparation_id\":" + (work->PreparationId == 0 ? L"null" : n(work->PreparationId)) +
            L",\"last_preparation_id\":" + (work->LastPreparationId == 0 ? L"null" : n(work->LastPreparationId)) +
            L",\"preparation_queued_ms\":" + (work->LastPreparationId == 0 ? L"null" : n(work->PreparationQueuedMs)) +
            L",\"preparation_cancelled\":" + (work->PreparationCancelled ? L"true" : L"false") +
            L",\"reference_retry_after_ms\":" + n(work->ReferenceRetryAfterMs) +
            L",\"reference_last_finished_ms\":" + (work->PreparationFinishedMs == 0 ? L"null" : n(work->PreparationFinishedMs)) +
            L",\"reference_last_success_ms\":" + (work->PreparationSuccessMs == 0 ? L"null" : n(work->PreparationSuccessMs)) +
            L",\"reference_last_success_episode\":" + (work->PreparationSuccessMs == 0 ? L"null" : n(work->PreparationSuccessEpisode)) +
            L",\"reference_last_outcome\":" + (work->PreparationFinishedMs == 0 ? L"null" :
                mcpjson::Quote(ImageReferencePreparation::OutcomeName(work->PreparationOutcome))) +
            L",\"observation\":" + work->Scheduling.Json(now) + L"}";
        if (row.size() + (rows.empty() ? 0 : 1) > detailUnits - rows.size()) { continue; }
        if (!rows.empty()) { rows += L","; }
        rows += row;
        ++details;
    }
    return L"{\"schema\":\"kn.image_scheduling.v1\",\"scope\":\"resident_image_work_entries\","
        L"\"clock_domain\":\"GetTickCount64_ms\",\"policy\":\"bounded_debt_with_process_bulk_tail_rotation.v1\","
        L"\"success_scope\":\"qualified_comparison_not_execution_or_durable_publication\","
        L"\"debt_origin\":\"last_gap_free_traversal_or_first_discovery\",\"parser_attempt_is_native_read\":false,"
        L"\"hard_deadline_enforced\":false,\"minimum_page_and_final_fences_may_overrun\":true,"
        L"\"shutdown_in_normal_samples\":false,\"percentiles\":\"log2_bucket_upper_bounds\","
        L"\"snapshot_ms\":" + n(now) + L",\"cooperative_turn_budget_ms\":" + n(KmonImageTurnBudgetMs) +
        L",\"reference_retry_ms\":\"30000\",\"debt_priority_ordinary_stride\":\"4\",\"debt_priority_turns\":" + n(ImageDebtPriorityTurns) +
        L",\"resident\":" + n(ImageWork.size()) + L",\"loaded\":" + n(loaded) + L",\"pending\":" + n(pending) +
        L",\"debt_known\":" + n(known) + L",\"max_resident_observation_debt_ms\":" + n(debt) +
        L",\"evicted\":" + n(ImageWorkEvicted) + L",\"deferred_admission_attempts\":" + n(ImageAdmissionDeferred) +
        L",\"deferred_rediscovery_guaranteed\":false,\"detail_capacity\":" + n(detailCapacity) + L",\"detail_utf16_capacity\":" + n(detailUnits) +
        L",\"details_omitted\":" + n(ImageWork.size() - details) + L",\"details\":[" + rows + L"],\"snapshot_invalid_clocks\":" + n(invalid) +
        L",\"normal\":" + ImageTimings.Json() + L",\"shutdown\":" + ImageTimings.Json(true) + L"}";
}

KernelMonitor::ImageVerificationWork* KernelMonitor::SelectImageSweepWork(uint64_t now)
{
    ApplyImageReferenceResults();
    std::set<uint32_t> watched;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        watched.insert(WatchPids.begin(), WatchPids.end());
    }
    // Select first traversal vs rescan across processes, then rotate process
    // generations and their least recently scanned image within that class.
    // Per-process classification let repeat-only processes dilute every turn
    // of a DLL-rich process that still had unseen tails.
    std::map<std::pair<uint32_t, uint64_t>, ImageVerificationWork*> eligible[2][2];
    ImageVerificationWork* oldest[2][2]{};
    ImageVerificationWork* bulk = nullptr;
    ImageVerificationWork* finishing = nullptr;
    for (auto& item : ImageWork)
    {
        auto& work = item.second;
        if (now < work.NextSweepDueMs || work.PreparationId != 0 || (!work.Loaded && now < work.ReferenceRetryAfterMs)) { continue; }
        const size_t group = work.Identity.ProcessId != 0 && watched.count(work.Identity.ProcessId) != 0 ? 0 : 1;
        const size_t phase = work.Sweep.LastCompleteMs == 0 && work.PriorTraversalMs == 0 ? 0 : 1;
        auto& candidate = eligible[group][phase][{work.Identity.ProcessId, work.Identity.CreateTime}];
        if (candidate == nullptr || std::make_pair(work.LastSweepMs, work.Base) <
            std::make_pair(candidate->LastSweepMs, candidate->Base)) { candidate = &work; }
        auto& debt = oldest[group][phase];
        if (work.Scheduling.Seen && work.Scheduling.DebtSince() <= now && (debt == nullptr ||
            std::make_tuple(work.Scheduling.DebtSince(), work.LastSweepMs, work.Base) <
            std::make_tuple(debt->Scheduling.DebtSince(), debt->LastSweepMs, debt->Base))) { debt = &work; }
        // Incidental layout scans also update LastSweepMs. Equal turns did
        // not mean equal progress under the time budget, and a small incidental
        // read could postpone a large unvisited tail. Raise the lowest cursor
        // first; ordinary rotation still retries unavailable identities.
        const bool bulkReady = work.Loaded && (!work.Sweep.Coverage.Attempted || work.Sweep.Coverage.InventoryAvailable);
        if (group == 1 && phase == 0 && work.Sweep.Ranges.size() >= 4096 && bulkReady &&
            (bulk == nullptr || std::make_pair(work.Sweep.NextRange, work.LastSweepMs) <
                std::make_pair(bulk->Sweep.NextRange, bulk->LastSweepMs))) { bulk = &work; }
        const auto remaining = work.Sweep.NextRange <= work.Sweep.Ranges.size() ? work.Sweep.Ranges.size() - work.Sweep.NextRange : 0;
        if (work.Loaded && group == 1 && phase == 0 && remaining > 0 && remaining <= 1024 &&
            (finishing == nullptr || std::make_pair(remaining, work.LastSweepMs) <
                std::make_pair(finishing->Sweep.Ranges.size() - finishing->Sweep.NextRange, finishing->LastSweepMs)))
        { finishing = &work; }
    }
    const auto ready = [&](size_t group) { return !eligible[group][0].empty() || !eligible[group][1].empty(); };
    if (!ready(0) && !ready(1)) { return nullptr; }
    size_t scheduledGroup = (++ImageSweepTurns % 4) == 0 ? 1 : 0;
    if (!ready(scheduledGroup)) { scheduledGroup = 1 - scheduledGroup; }
    // Advance the planned slot even when it is lent out; otherwise an empty
    // watched first-traversal lane would never reach its reserved rescan slot.
    const size_t scheduledPhase = ImageSweepGroupTurns[scheduledGroup]++ % 4 == 3 ? 1 : 0;
    std::array<std::pair<size_t, size_t>, 4> order{{
        {scheduledGroup, scheduledPhase}, {scheduledGroup, 1 - scheduledPhase},
        {1 - scheduledGroup, 0}, {1 - scheduledGroup, 1}}};
    if (scheduledGroup == 0 && scheduledPhase == 0)
    {
        // Finished watched processes must not spend all their unused initial
        // share on rescans while background images still have unseen bytes.
        // Keep the watched rescan slots and the entire native background share.
        std::swap(order[1], order[2]);
    }
    for (const auto& slot : order)
    {
        const auto group = slot.first, phase = slot.second;
        auto& candidates = eligible[group][phase];
        if (candidates.empty()) { continue; }
        ImageVerificationWork* selected = nullptr;
        // Preserve ordinary rotation and a dedicated large-image turn. Spend
        // the second bulk turn on a bounded tail when one is ready; spreading
        // every turn across large images left many small tails unfinished.
        // Only a third of initial background turns may prefer short work.
        if (group == 1 && phase == 0 && ImageSweepClassTurns[1][0] % 3 == 2 && finishing != nullptr)
        {
            selected = finishing;
            ++ImageCompletionPriorityTurns;
            ++selected->CompletionPriorityTurns;
        }
        else if (group == 1 && phase == 0 && ImageSweepClassTurns[1][0] % 3 != 0 && bulk != nullptr)
        {
            selected = bulk;
            ++ImageBulkProgressTurns;
            ++selected->BulkProgressTurns;
        }
        else
        {
            // Debt can borrow one in four ordinary turns. Keep the ordinary
            // process cursor unchanged on a borrowed turn so even a permanent
            // failure cannot starve rotation, bulk progress, or bounded tails.
            if (ImageOrdinaryTurns[group][phase]++ % 4 == 3 && oldest[group][phase] != nullptr)
            { selected = oldest[group][phase]; ++ImageDebtPriorityTurns; }
            else
            {
                auto& cursor = ImageSweepProcessCursors[group][phase];
                auto next = candidates.upper_bound(cursor);
                if (next == candidates.end()) { next = candidates.begin(); }
                cursor = next->first;
                selected = next->second;
            }
        }
        if (scheduledGroup == 0 && scheduledPhase == 0 && group == 1 && phase == 0) { ++ImageBorrowedBackgroundTurns; }
        ++ImageSweepClassTurns[group][phase];
        ++selected->SweepSchedulingTurns;
        return selected;
    }
    return nullptr;
}

void KernelMonitor::ContinueImageSweeps()
{
    const uint64_t now = GetTickCount64();
    if (StopRequested.load() || now < NextImageSweepMs || ImageWork.empty() ||
        LayoutCandidates.Size() >= 256 || ExecutionReferences.size() >= 256 ||
        CollectedLive.Size() >= 1024 || CollectedTi.Size() >= 1024) { return; }
    NextImageSweepMs = now + 50;
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols)) { return; }
    auto selected = SelectImageSweepWork(now);
    if (selected == nullptr) { return; }
    // Copy these before calling the verifier (which rechecks the disk cache).
    const auto identity = selected->Identity;
    const auto path = selected->Path;
    const auto base = selected->Base;
    const uint32_t pid = identity.ProcessId;
    HANDLE process = pid == 0 ? nullptr : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (pid != 0 && process == nullptr)
    {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(process, &CloseHandle);
    ProcessAddressContext context{};
    bool resolved = false, tried = false;
    const auto sameProcess = [&]()
    {
        if (pid == 0) { return true; }
        if (process != nullptr)
        {
            DWORD exitCode = 0;
            return GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE &&
                identity.SameInstance(ObserveProcessIdentity(pid, process));
        }
        ProcessAddressContext current{};
        return ResolveObservationProcess(*device, *symbols, identity, &current);
    };
    ProcessObservationSource processSource(process, pid, identity.CreateTime, device->AddressSpace());
    NativeObservationSource kernelSource(*device);
    auto unavailableCaps = processSource.Capabilities();
    const auto targetId = identity.BootId + L":process:" + std::to_wstring(pid) + L":" + std::to_wstring(identity.CreateTime);
    unavailableCaps.SourceId = L"unavailable_process_handle:" + targetId;
    UnavailableObservationSource unavailableSource(unavailableCaps);
    std::unique_ptr<NativeObservationSource> nativeSource;
    ObservationReadRouting routing;
    routing.TargetId = targetId;
    routing.AddressSpaceId = targetId + (pid == 0 ? L":kernel" : L":user");
    routing.Primary = pid == 0 ? static_cast<IObservationSource*>(&kernelSource) :
        processSource.Capabilities().SourceId.empty() ? static_cast<IObservationSource*>(&unavailableSource) : &processSource;
    routing.AllowResidencyChanges = true;
    routing.AllowFallback = pid != 0;
    routing.Fallback = [&]() -> IObservationSource*
    {
        if (!tried)
        {
            tried = true;
            resolved = ResolveObservationProcess(*device, *symbols, identity, &context);
        }
        if (!resolved) { return nullptr; }
        if (nativeSource == nullptr) { nativeSource = std::make_unique<NativeObservationSource>(*device, pid, context.Eprocess, identity.CreateTime); }
        return nativeSource.get();
    };
    MEMORY_BASIC_INFORMATION before{};
    bool known = false;
    routing.BeforeRead = [&](uint64_t address, size_t size)
    {
        if (!sameProcess()) { return false; }
        if (pid == 0) { return device->AddressSpace().KernelRange(address, size); }
        before = {};
        known = process != nullptr && VirtualQueryEx(process, reinterpret_cast<void*>(address),
            &before, sizeof(before)) == sizeof(before);
        if (known && (before.State != MEM_COMMIT || before.Type != MEM_IMAGE ||
            reinterpret_cast<uint64_t>(before.AllocationBase) != base ||
            (before.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
            address < reinterpret_cast<uint64_t>(before.BaseAddress) || size > before.RegionSize ||
            address - reinterpret_cast<uint64_t>(before.BaseAddress) > before.RegionSize - size)) { return false; }
        return true;
    };
    routing.AfterRead = [&](uint64_t address, size_t)
    {
        MEMORY_BASIC_INFORMATION after{};
        return sameProcess() && (pid == 0 || !known ||
            (VirtualQueryEx(process, reinterpret_cast<void*>(address), &after, sizeof(after)) == sizeof(after) &&
                before.BaseAddress == after.BaseAddress && before.AllocationBase == after.AllocationBase &&
                before.RegionSize == after.RegionSize && before.State == after.State &&
                before.Protect == after.Protect && before.Type == after.Type));
    };
    // The cooperative budget includes reference lookup. Minimum first-page
    // progress and mandatory final fences can overrun; the timing report
    // preserves those overruns. Continuation never refreshes discovery age.
    ScanExecutableImage(path, base, identity, {}, 1024, &routing, false);
}

void KernelMonitor::ScanImagePermissionCandidates(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader)
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols) || ExecutionReferences.size() >= 64)
    {
        return;
    }
    auto work = FindImageWork(path, base, identity);
    if (work == nullptr || !QualifyExecutableReference(work->Reference, base, reader, nullptr))
    {
        return;
    }
    ProcessAddressContext context = {};
    if (identity.ProcessId != 0 && !ResolveHuntAddressSpace(*device, *symbols, identity, &context))
    {
        EmitUnique(L"coverage.image_permissions", L"image:permissions:identity:" + ImageKey(path, base, identity),
            path, L"image", L"image permission scan unavailable", L"process address-space identity unavailable", identity.ProcessId);
        return;
    }
    uint32_t checked = 0;
    uint32_t failed = 0;
    uint32_t candidates = 0;
    bool complete = false;
    for (uint32_t visited = 0; visited < 4096 && checked < 4 && !StopRequested.load(); ++visited)
    {
        const uint64_t rva = work->PermissionCursor;
        if (rva >= work->Reference.SizeOfImage || base > UINT64_MAX - rva)
        {
            work->PermissionCursor = 0;
            complete = true;
            break;
        }
        work->PermissionCursor += 4096;
        if (DeclaredExecutableImagePage(work->Reference, rva))
        {
            continue;
        }
        ++checked;
        PhysicalTranslationInfo mapping = {};
        if (!device->TranslateVirtual(identity.ProcessId == 0 ? 0 : context.DirectoryTableBase, base + rva, 1, &mapping, nullptr))
        {
            ++failed;
            continue;
        }
        if (KmonHardwareExecutable(mapping.Pml5e, mapping.Pml4e, mapping.Pdpte, mapping.Pde,
            mapping.Pte, mapping.PageSize, mapping.PagingLevels, identity.ProcessId != 0))
        {
            QueueExecutionReference(base + rva, 0, L"image_page_candidate", identity);
            ++candidates;
        }
    }
    KmonEvent event;
    event.Kind = L"coverage.image_permissions";
    event.ProcessId = identity.ProcessId;
    event.Image = path;
    event.Observation.Identity = identity;
    event.Observation.Source = L"image_pte_permissions";
    event.Summary = L"non-executable PE pages checked against current hardware permissions";
    event.Evidence[L"pages_checked"] = std::to_wstring(checked);
    event.Evidence[L"translations_unavailable"] = std::to_wstring(failed);
    event.Evidence[L"candidates"] = std::to_wstring(candidates);
    event.Evidence[L"cursor_rva"] = std::to_wstring(work->PermissionCursor);
    event.Evidence[L"cycle_finished"] = complete ? L"true" : L"false";
    RecordEvent(std::move(event));
}

void KernelMonitor::ScanKernelExecutableImages()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols))
    {
        return;
    }
    auto modules = symbols->CopyModules();
    std::sort(modules.begin(), modules.end(), [](const KernelModuleInfo& a, const KernelModuleInfo& b)
    {
        return a.Base < b.Base;
    });
    if (!modules.empty())
    {
        auto it = std::upper_bound(modules.begin(), modules.end(), KernelImageCursor,
            [](uint64_t base, const KernelModuleInfo& module)
            {
                return base < module.Base;
            });
        if (it == modules.end())
        {
            it = modules.begin();
        }
        KernelImageCursor = it->Base;
        const ObservationReader reader = [device](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            return device->AddressSpace().KernelRange(address, size) && size <= 4096 &&
                device->ReadMemory(address, static_cast<uint32_t>(size), bytes, nullptr);
        };
        const auto identity = ObserveProcessIdentity(0);
        NativeObservationSource source(*device);
        ObservationReadRouting routing;
        routing.Primary = &source;
        routing.TargetId = identity.BootId + L":kernel";
        routing.AddressSpaceId = routing.TargetId;
        routing.AllowResidencyChanges = true;
        ScanExecutableImage(KmonNormalizeDriverPath(it->ImagePath), it->Base, identity, reader, 16, &routing);
        ScanImagePermissionCandidates(KmonNormalizeDriverPath(it->ImagePath), it->Base, ObserveProcessIdentity(0), reader);
    }
}

bool KmonLoadedImageAllocation(HANDLE process, uint64_t address, const std::vector<KernelModuleInfo>& modules)
{
    MEMORY_BASIC_INFORMATION mapping{};
    if (process == nullptr || VirtualQueryEx(process, reinterpret_cast<void*>(address), &mapping,
        sizeof(mapping)) != sizeof(mapping) || mapping.State != MEM_COMMIT || mapping.Type != MEM_IMAGE)
    {
        return false;
    }
    const auto base = reinterpret_cast<uint64_t>(mapping.AllocationBase);
    const auto owner = std::find_if(modules.begin(), modules.end(), [&](const auto& module) { return module.Base == base; });
    if (owner == modules.end() || owner->ImagePath.empty()) { return false; }
    wchar_t name[32768]{};
    const DWORD length = GetMappedFileNameW(process, reinterpret_cast<void*>(address), name, 32768);
    if (length == 0 || length >= 32768) { return false; }
    const auto mappedPath = ProcessLayoutReferencePath(std::wstring(name, length));
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE mapped = CreateFileW(mappedPath.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING, 0, nullptr);
    HANDLE listed = CreateFileW(owner->ImagePath.c_str(), FILE_READ_ATTRIBUTES, share, nullptr, OPEN_EXISTING, 0, nullptr);
    const std::unique_ptr<void, decltype(&CloseHandle)> mappedOwner(mapped == INVALID_HANDLE_VALUE ? nullptr : mapped, &CloseHandle);
    const std::unique_ptr<void, decltype(&CloseHandle)> listedOwner(listed == INVALID_HANDLE_VALUE ? nullptr : listed, &CloseHandle);
    FILE_ID_INFO mappedId{}, listedId{};
    MEMORY_BASIC_INFORMATION after{};
    const bool sameFile = mapped != INVALID_HANDLE_VALUE && listed != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(mapped, FileIdInfo, &mappedId, sizeof(mappedId)) &&
        GetFileInformationByHandleEx(listed, FileIdInfo, &listedId, sizeof(listedId)) &&
        mappedId.VolumeSerialNumber == listedId.VolumeSerialNumber &&
        std::memcmp(mappedId.FileId.Identifier, listedId.FileId.Identifier, sizeof(mappedId.FileId.Identifier)) == 0 &&
        VirtualQueryEx(process, reinterpret_cast<void*>(address), &after, sizeof(after)) == sizeof(after) &&
        after.State == MEM_COMMIT && after.Type == MEM_IMAGE && after.AllocationBase == mapping.AllocationBase;
    wchar_t confirmedName[32768]{};
    return sameFile && GetMappedFileNameW(process, reinterpret_cast<void*>(address), confirmedName, 32768) == length &&
        std::wstring(name, length) == std::wstring(confirmedName, length);
}

void KernelMonitor::QueueExecutionReference(uint64_t target, uint64_t slot,
    const std::wstring& role, const ObservationIdentity& identity, uint64_t observedAt,
    const std::vector<ObservationAnchor>& anchors, uint64_t expectedPeb)
{
    if ((target == 0 && !KmonPageRole(role)) || anchors.size() > 8)
    {
        return;
    }
    ObservationIdentity actual = identity;
    if (actual.BootId.empty())
    {
        actual.BootId = ObservationBootId();
    }
    const auto admitted = ExecutionReferences.Admit({target, slot, observedAt == 0 ? ObservationFileTime() : observedAt,
        GetTickCount64(), actual, role, anchors, expectedPeb});
    if (admitted == KmonReferenceAdmission::Duplicate || admitted == KmonReferenceAdmission::Cooldown) { return; }
    if (admitted != KmonReferenceAdmission::Queued)
    {
        ++ExecutionReferenceDropped;
        ++ExecutionReferenceQueueDropsByRole[role];
        EmitUnique(L"coverage.references", L"scan_failed:references:admission:" + std::wstring(KmonReferenceAdmissionName(admitted)), L"", L"references",
            L"execution reference admission deferred", L"bounded scope receipts in reference_scheduling_json; later rediscovery is not guaranteed");
        return;
    }
    ++ExecutionReferenceQueued;
    ExecutionReferencePeak = (std::max)(ExecutionReferencePeak, ExecutionReferences.size());
}

void KernelMonitor::ScanExecutionReferences(size_t maxCount, uint64_t budgetMs, bool finalDrain)
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols))
    {
        return;
    }
    DrainExecutionReferences(device, symbols, maxCount, budgetMs, finalDrain);
}

void KernelMonitor::DrainExecutionReferences(DeviceClient* device, SymbolEngine* symbols,
    size_t maxCount, uint64_t budgetMs, bool finalDrain)
{
    const auto begin = GetTickCount64();
    for (size_t n = 0; n < maxCount && !ExecutionReferences.empty() && (finalDrain || !StopRequested.load()) &&
        GetTickCount64() - begin < budgetMs; ++n)
    {
        auto work = ExecutionReferences.Pop();
        const uint64_t captureStartedMs = GetTickCount64();
        KmonReferenceOutcome outcome = KmonReferenceOutcome::Fault;
        struct Completion
        {
            KmonReferenceQueue& Queue;
            const KmonExecutionReferenceWork& Work;
            const uint64_t Started;
            KmonReferenceOutcome& Outcome;
            const bool Shutdown;
            ~Completion() { Queue.Finish(Work, Started, GetTickCount64(), Outcome, Shutdown); }
        } completion{ExecutionReferences, work, captureStartedMs, outcome, finalDrain};
        const auto captureId = NewEvidenceScope();
        const auto captureNativeEpoch = device->ObservationEpoch();
        ++ExecutionReferenceProcessed;
        const auto referenceKey = ReferenceKey(work.Target, work.Slot, work.Role, work.Identity);
        {
            std::lock_guard<std::mutex> lock(HuntMutex);
            HuntIndex.Retire(work.Identity, work.Target, work.Slot, work.Role, captureStartedMs);
        }
        const uint64_t waited = captureStartedMs >= work.ObservedMs ? captureStartedMs - work.ObservedMs : 0;
        ExecutionReferenceMaxWaitMs = (std::max)(ExecutionReferenceMaxWaitMs, waited);
        if (!ExecutionReferences.Start(work, captureStartedMs))
        {
            outcome = captureStartedMs < work.ObservedMs ? KmonReferenceOutcome::InvalidClock : KmonReferenceOutcome::Expired;
            ++ExecutionReferenceDropped;
            ExecutionReferenceExpired += outcome == KmonReferenceOutcome::Expired;
            EmitUnique(L"coverage.references", L"scan_failed:references:" + std::wstring(KmonReferenceOutcomeName(outcome)), L"", L"references",
                L"queued reference could not start", KmonReferenceOutcomeName(outcome), work.Identity.ProcessId);
            continue;
        }
        const uint32_t pid = work.Identity.ProcessId;
        HANDLE process = pid == 0 ? nullptr : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (pid != 0 && process == nullptr)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        const std::unique_ptr<void, decltype(&CloseHandle)> processOwner(process, &CloseHandle);
        const auto sameProcess = [&]()
        {
            if (pid == 0)
            {
                return true;
            }
            if (work.ExpectedPeb != 0)
            {
                uint64_t peb = 0;
                if (!QueryExecutionSurfacePeb(process, pid, &peb) || peb != work.ExpectedPeb)
                {
                    return false;
                }
            }
            if (process != nullptr)
            {
                return work.Identity.SameInstance(ObserveProcessIdentity(pid, process));
            }
            ProcessAddressContext current = {};
            return ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current);
        };
        if (!sameProcess())
        {
            outcome = KmonReferenceOutcome::IdentityUnavailable;
            EmitUnique(L"coverage.references", L"scan_failed:references:identity:" + std::to_wstring(pid),
                L"", L"references", L"queued reference has stale or unknown process identity", L"", pid);
            continue;
        }
        BOOL wow64 = FALSE;
        const bool pageCheck = KmonPageRole(work.Role) || work.Role == L"etw_stack_return";
        if (pid != 0 && !pageCheck && (process == nullptr || !IsWow64Process(process, &wow64) || wow64))
        {
            outcome = KmonReferenceOutcome::ArchitectureUnavailable;
            EmitUnique(L"coverage.references", L"scan_failed:references:architecture:" + std::to_wstring(pid),
                L"", L"references", L"static target decoding requires a confirmed native x64 process",
                L"image page comparisons remain available; target architecture is unsupported or unknown", pid);
            continue;
        }
        const auto modules = pid == 0 ? symbols->CopyModules() : UserModules(pid);
        ProcessAddressContext addressSpace = {};
        bool addressSpaceTried = false;
        bool addressSpaceValid = false;
        const auto executableMapping = [&](uint64_t address, PhysicalTranslationInfo* mapping)
        {
            *mapping = {};
            MEMORY_BASIC_INFORMATION region = {};
            const bool regionKnown = pid != 0 && process != nullptr &&
                VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) == sizeof(region);
            if (pid != 0 && !addressSpaceTried)
            {
                addressSpaceTried = true;
                addressSpaceValid = ResolveHuntAddressSpace(*device, *symbols, work.Identity, &addressSpace);
            }
            if ((pid == 0 || addressSpaceValid) &&
                device->TranslateVirtual(pid == 0 ? 0 : addressSpace.DirectoryTableBase, address, 1, mapping, nullptr))
            {
                return KmonHardwareExecutable(mapping->Pml5e, mapping->Pml4e, mapping->Pdpte,
                    mapping->Pde, mapping->Pte, mapping->PageSize, mapping->PagingLevels, pid != 0);
            }
            *mapping = {};
            return regionKnown &&
                region.State == MEM_COMMIT && (region.Protect & PAGE_GUARD) == 0 &&
                (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        };
        PhysicalTranslationInfo candidateMapping = {};
        if (KmonPageRole(work.Role) && !executableMapping(work.Target, &candidateMapping))
        {
            outcome = KmonReferenceOutcome::MappingUnavailable;
            EmitUnique(L"coverage.execution_path", L"page:unavailable:" + referenceKey, L"", work.Role,
                L"candidate page is no longer executable or its mapping is unavailable", L"current mapping revalidation failed", pid);
            continue;
        }
        bool physicalPageRead = false;
        bool kernelReaderUsed = false;
        bool userReaderUsed = false;
        uint64_t lastReadPhysical = 0;
        uint64_t pageHeadPhysical = 0;
        NativeObservationSource nativeSource(*device);
        const ObservationReader reader = [device, symbols, process, &work, &executableMapping,
            &nativeSource, &physicalPageRead, &kernelReaderUsed, &userReaderUsed, &lastReadPhysical,
            &addressSpaceTried, &addressSpaceValid, &addressSpace]
            (uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            lastReadPhysical = 0;
            if (size > 4096 || address > UINT64_MAX - size)
            {
                return false;
            }
            if (KmonPageRole(work.Role) && size == 4096 && (address & 4095) == 0)
            {
                PhysicalTranslationInfo mapping = {};
                if (executableMapping(address, &mapping) && mapping.PhysicalAddress != 0 &&
                    device->ReadPhysical(mapping.PhysicalAddress, 4096, bytes, nullptr) && bytes->size() == 4096)
                {
                    physicalPageRead = true;
                    kernelReaderUsed = true;
                    lastReadPhysical = mapping.PhysicalAddress;
                    return true;
                }
            }
            if (work.Identity.ProcessId == 0)
            {
                const bool read = ReadObservationExact(nativeSource, address, size, bytes, true);
                kernelReaderUsed = kernelReaderUsed || read;
                return read;
            }
            if (work.Role == L"instrumentation_callback" && work.Slot != 0 && address == work.Slot && size == 8)
            {
                const bool read = ReadObservationExact(nativeSource, address, 8, bytes, true);
                kernelReaderUsed = kernelReaderUsed || read;
                return read;
            }
            MEMORY_BASIC_INFORMATION protection = {};
            if (process != nullptr && VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &protection,
                sizeof(protection)) == sizeof(protection) && (protection.Protect & PAGE_GUARD) != 0)
            {
                return false;
            }
            bytes->resize(size);
            SIZE_T read = 0;
            if (process != nullptr && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                bytes->data(), size, &read) && read == size)
            {
                userReaderUsed = true;
                return true;
            }
            if (!addressSpaceTried)
            {
                addressSpaceTried = true;
                addressSpaceValid = ResolveObservationProcess(*device, *symbols, work.Identity, &addressSpace);
            }
            const bool captured = addressSpaceValid && device->ReadProcessVirtual(work.Identity.ProcessId, addressSpace.Eprocess,
                work.Identity.CreateTime, address, static_cast<uint32_t>(size), bytes, nullptr);
            kernelReaderUsed = kernelReaderUsed || captured;
            return captured;
        };
        if (!ObservationAnchorsMatch(work.Anchors, reader))
        {
            outcome = KmonReferenceOutcome::Inconsistent;
            EmitUnique(L"coverage.references", L"reference:anchor_changed:" + referenceKey, L"", work.Role,
                L"reference root or PE metadata changed before decoding", L"queued reference withheld", pid);
            continue;
        }
        bool imageAllocationExtension = false;
        const CodeTargetInspector inspect = [&](uint64_t address, const std::vector<uint8_t>& bytes)
        {
            for (const auto& module : modules)
            {
                if (address >= module.Base && address - module.Base < module.Size)
                {
                    const std::wstring path = pid == 0 ? KmonNormalizeDriverPath(module.ImagePath) : module.ImagePath;
                    auto image = FindImageWork(path, module.Base, work.Identity);
                    if (image == nullptr || !QualifyExecutableReference(image->Reference, module.Base, reader, nullptr))
                    {
                        return CodeOwnership::OwnedUnverified;
                    }
                    PhysicalTranslationInfo mapping = {};
                    if (UnexpectedExecutableImageAddress(image->Reference, address - module.Base) && executableMapping(address, &mapping))
                    {
                        return QualifyExecutableReference(image->Reference, module.Base, reader, nullptr)
                            ? CodeOwnership::OwnedUnexpectedExecutable : CodeOwnership::OwnedUnverified;
                    }
                    bool reusedCapture = false;
                    const ObservationReader captured = [&](uint64_t at, size_t count, std::vector<uint8_t>* out)
                    {
                        if (!reusedCapture && at == address && count == bytes.size())
                        {
                            reusedCapture = true;
                            *out = bytes;
                            return true;
                        }
                        return reader(at, count, out);
                    };
                    const auto result = CompareExecutableRange(path, image->Reference, module.Base,
                        static_cast<uint32_t>(address - module.Base), static_cast<uint32_t>(bytes.size()), captured);
                    return !QualifyExecutableReference(image->Reference, module.Base, reader, nullptr)
                        ? CodeOwnership::OwnedUnverified : result.Ownership;
                }
            }
            if (!KmonKernelModuleRangesKnown(modules))
            {
                return CodeOwnership::Unknown;
            }
            if (pid != 0 && KmonLoadedImageAllocation(process, address, modules))
            {
                imageAllocationExtension = true;
                return CodeOwnership::OwnedUnverified;
            }
            PhysicalTranslationInfo page = {};
            return executableMapping(address, &page) ? CodeOwnership::UnownedExecutable : CodeOwnership::Unknown;
        };
        const bool pointerSlot = work.Slot != 0 && KmonPointerReference(work.Role);
        CodeTargetChain chain;
        if (pageCheck)
        {
            CodeTargetHop hop;
            hop.Address = work.Target & ~4095ull;
            if (reader(hop.Address, 4096, &hop.Bytes) && hop.Bytes.size() == 4096)
            {
                pageHeadPhysical = lastReadPhysical;
                hop.Ownership = inspect(hop.Address, hop.Bytes);
                chain.HasModifiedCode = hop.Ownership == CodeOwnership::OwnedModified;
                chain.HasUnownedExecutable = hop.Ownership == CodeOwnership::UnownedExecutable;
                chain.HasUnexpectedExecutable = hop.Ownership == CodeOwnership::OwnedUnexpectedExecutable;
                chain.Hops.push_back(std::move(hop));
                chain.Termination = work.Role == L"etw_stack_return" ?
                    L"historical_stack_page_checked; not_a_function_entry" : L"executable_page_checked; no_execution_reference";
            }
            else
            {
                chain.Termination = L"page_location_unreadable";
            }
        }
        else
        {
            chain = pointerSlot ? ResolveReferencedCodeTarget(work.Target, work.Slot, reader, inspect) :
                ResolveCodeTarget(work.Target, reader, inspect);
        }
        KmonEvent event;
        event.Kind = chain.HasModifiedCode || chain.HasUnownedExecutable ? L"finding.execution_path" : L"coverage.execution_path";
        if (KmonPageRole(work.Role) && (chain.HasModifiedCode || chain.HasUnownedExecutable))
        {
            event.Kind = L"finding.executable_memory";
        }
        if (chain.HasUnexpectedExecutable)
        {
            event.Kind = L"finding.executable_permission";
        }
        event.ProcessId = pid;
        event.Summary = work.Role + L" target path: " + chain.Termination;
        event.Observation.Identity = work.Identity;
        event.Observation.Source = work.Role;
        event.Observation.Timestamp = work.ObservedAt;
        event.Observation.MonotonicMs = work.ObservedMs;
        event.Observation.DependencyGroup = L"static_code_reference";
        event.Evidence[L"module_inventory"] = modules.empty() ? L"unavailable" : L"snapshot";
        if (imageAllocationExtension)
        {
            event.Evidence[L"image_allocation_extension"] = L"same_allocation_and_backing_file; outside_reported_module_size; bytes_unverified";
        }
        event.Evidence[L"relationship"] = L"address";
        event.Evidence[L"reference_role"] = work.Role;
        event.Evidence[L"slot"] = std::to_wstring(work.Slot);
        event.Evidence[L"reference_target"] = std::to_wstring(work.Target);
        event.Evidence[L"termination"] = chain.Termination;
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"reference_consistency"] = !chain.ReferenceChecked ? L"not_revalidated" :
            (chain.ReferenceStable ? L"slot_checked_before_and_after" : L"changed_or_unreadable");
        event.Evidence[L"path_read_at"] = std::to_wstring(ObservationFileTime());
        size_t captures = 0;
        size_t acceptedReferences = 0;
        bool referenceSnapshotValid = !chain.ReferenceChecked || chain.ReferenceStable;
        std::vector<std::pair<size_t, KmonHuntReference>> pendingReferences;
        std::map<size_t, EvidenceSpan> evidencePages;
        for (size_t i = 0; i < chain.Hops.size(); ++i)
        {
            const auto& hop = chain.Hops[i];
            const std::wstring key = L"hop_" + std::to_wstring(i) + L"_";
            event.Evidence[key + L"address"] = std::to_wstring(hop.Address);
            event.Evidence[key + L"target"] = std::to_wstring(hop.Target);
            event.Evidence[key + L"ownership"] = CodeOwnershipName(hop.Ownership);
            event.Evidence[key + L"bytes"] = BytesHex(hop.Bytes);
            event.Evidence[key + L"bytes_read"] = std::to_wstring(hop.Bytes.size());
            event.Evidence[key + L"bytes_prefix_length"] = std::to_wstring((std::min<size_t>)(hop.Bytes.size(), 64));
            if ((KmonHuntOwnership(hop.Ownership) || (KmonPageRole(work.Role) &&
                (hop.Ownership == CodeOwnership::Unknown || hop.Ownership == CodeOwnership::OwnedUnverified))) &&
                (!chain.ReferenceChecked || chain.ReferenceStable))
            {
                KmonHuntReference reference;
                reference.Context.Identity = work.Identity;
                reference.Context.Source = work.Role;
                reference.Context.DependencyGroup = hop.Ownership == CodeOwnership::OwnedModified ?
                    L"memory_vs_file" : L"executable_memory_metadata";
                reference.Context.Ownership = hop.Ownership;
                reference.Address = hop.Address;
                reference.Root = work.Target;
                reference.Slot = work.Slot;
                reference.Role = work.Role;
                reference.ReferenceTimestamp = work.ObservedAt;
                reference.SlotStable = chain.ReferenceChecked && chain.ReferenceStable;
                const uint64_t base = hop.Address & ~4095ull;
                PhysicalTranslationInfo beforeMapping = {};
                const bool executableBefore = executableMapping(base, &beforeMapping);
                std::vector<uint8_t> page;
                uint64_t capturePhysical = 0;
                bool comparable = false;
                const bool pageAttempted = captures < 2;
                const bool pageCaptured = pageAttempted && reader(base, 4096, &page) && page.size() == 4096;
                if (pageCaptured)
                {
                    capturePhysical = lastReadPhysical;
                    ++captures;
                    const size_t offset = static_cast<size_t>(hop.Address - base);
                    comparable = hop.Bytes.size() <= page.size() - offset &&
                        std::equal(hop.Bytes.begin(), hop.Bytes.end(), page.begin() + offset);
                }
                if (reference.SlotStable)
                {
                    std::vector<uint8_t> slotBytes;
                    uint64_t target = 0;
                    reference.SlotStable = reader(work.Slot, 8, &slotBytes) && slotBytes.size() == 8;
                    if (reference.SlotStable)
                    {
                        std::memcpy(&target, slotBytes.data(), 8);
                        reference.SlotStable = target == work.Target;
                    }
                    if (!reference.SlotStable)
                    {
                        referenceSnapshotValid = false;
                        event.Evidence[L"capture_reference_consistency"] = L"changed_or_unreadable";
                        continue;
                    }
                }
                if (!sameProcess())
                {
                    referenceSnapshotValid = false;
                    continue;
                }
                if (pid != 0 && addressSpaceValid)
                {
                    ProcessAddressContext current = {};
                    if (!ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current) ||
                        current.Eprocess != addressSpace.Eprocess ||
                        current.DirectoryTableBase != addressSpace.DirectoryTableBase)
                    {
                        referenceSnapshotValid = false;
                        event.Evidence[key + L"page_mapping"] = L"address_space_changed_or_unavailable";
                        continue;
                    }
                }
                PhysicalTranslationInfo afterMapping = {};
                const bool executableAfter = executableMapping(base, &afterMapping);
                reference.PageExecutableVerified = executableBefore && executableAfter;
                if ((KmonPageRole(work.Role) || hop.Ownership == CodeOwnership::OwnedUnexpectedExecutable) &&
                    (!executableBefore || !executableAfter))
                {
                    event.Evidence[key + L"page_mapping"] = L"changed_or_unavailable";
                    continue;
                }
                if (KmonPageRole(work.Role) && !comparable)
                {
                    event.Evidence[key + L"page_mapping"] = L"page_bytes_changed_or_unreadable";
                    continue;
                }
                if (!KmonPhysicalPageSamplesAgree({candidateMapping.PhysicalAddress, pageHeadPhysical,
                    beforeMapping.PhysicalAddress, capturePhysical, afterMapping.PhysicalAddress}))
                {
                    event.Evidence[key + L"page_mapping"] = L"physical_page_changed";
                    continue;
                }
                if (beforeMapping.PhysicalAddress != 0 && afterMapping.PhysicalAddress != 0)
                {
                    reference.Context.PfnKnown = executableBefore && executableAfter;
                    reference.Context.Pfn = afterMapping.PhysicalAddress >> 12;
                }
                reference.Context.Timestamp = ObservationFileTime();
                reference.Context.MonotonicMs = GetTickCount64();
                if (comparable)
                {
                    ExecutableRegionObservation observation;
                    observation.Context = reference.Context;
                    // A page boundary is not an allocation boundary.
                    MEMORY_BASIC_INFORMATION region = {};
                    if (pid != 0 && process != nullptr && VirtualQueryEx(process, reinterpret_cast<LPCVOID>(base),
                        &region, sizeof(region)) == sizeof(region))
                    {
                        observation.Context.AllocationBase = reinterpret_cast<uint64_t>(region.AllocationBase);
                    }
                    observation.Range = {base, 4096};
                    observation.Executable = true;
                    observation.ContentSha256 = ContentHash::Bytes(page);
                    observation.ContentBytes = page.size();
                    reference.Context.MappingGeneration = ObserveExecutableRegion(observation);
                    reference.PageSha256 = observation.ContentSha256;
                    reference.PageComparable = KmonComparablePage(page);
                    event.Evidence[key + L"capture_id"] = std::to_wstring(
                        QueueCapturedBytes(L"hunt_reference", base, reference.Context, page));
                }
                evidencePages.emplace(i, EvidenceSpan{base, 4096, L"target_page",
                    pageCaptured ? L"valid" : (pageAttempted ? L"read_failed" : L"skipped"),
                    pageCaptured ? std::move(page) : std::vector<uint8_t>{}});
                pendingReferences.emplace_back(i, std::move(reference));
            }
        }
        std::vector<EvidenceSpan> confirmedReads;
        bool evidenceTruncated = false;
        for (const auto& hop : chain.Hops)
        {
            if (hop.Bytes.empty())
            {
                confirmedReads.push_back({hop.Address, (std::min<uint64_t>)(32, 4096 - (hop.Address & 4095)),
                    L"target_head", L"read_failed", {}});
            }
        }
        const ObservationReader evidenceReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            const bool read = reader(address, size, bytes) && bytes->size() == size;
            if (confirmedReads.size() >= EvidenceBundleMaxSpans - 1) { evidenceTruncated = true; }
            else if (size != 0 && size <= 4096)
            {
                const bool head = std::any_of(chain.Hops.begin(), chain.Hops.end(), [&](const auto& hop) { return hop.Address == address; });
                const bool slot = address == work.Slot || std::any_of(chain.Hops.begin(), chain.Hops.end(),
                    [&](const auto& hop) { return hop.Slot != 0 && hop.Slot == address; });
                confirmedReads.push_back({address, size, slot ? L"pointer_slot" : head ? L"target_head" : L"reference_anchor",
                    read ? L"valid" : L"read_failed", read ? *bytes : std::vector<uint8_t>{}});
            }
            else { evidenceTruncated = true; }
            return read;
        };
        referenceSnapshotValid = referenceSnapshotValid && sameProcess() &&
            ObservationAnchorsMatch(work.Anchors, evidenceReader) &&
            (pageCheck || CodeTargetChainMatches(chain, evidenceReader)) &&
            (!pointerSlot || CodeTargetSlotMatches(work.Target, work.Slot, evidenceReader));
        if (referenceSnapshotValid && pid != 0 && addressSpaceValid)
        {
            ProcessAddressContext current = {};
            referenceSnapshotValid = ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current) &&
                current.Eprocess == addressSpace.Eprocess && current.DirectoryTableBase == addressSpace.DirectoryTableBase;
        }
        const uint64_t captureEndedMs = GetTickCount64();
        if (referenceSnapshotValid)
        {
            for (size_t i = 0; i < chain.Hops.size(); ++i)
            {
                ExecutableRegionLink link;
                if (RegionCatalog.LinkAddress(work.Identity, work.Slot, chain.Hops[i].Address, work.Role, GetTickCount64(), &link,
                    chain.ReferenceStable ? GetTickCount64() : work.ObservedMs))
                {
                    event.Evidence[L"hop_" + std::to_wstring(i) + L"_generation"] = std::to_wstring(link.ToGeneration);
                }
            }
            std::lock_guard<std::mutex> lock(HuntMutex);
            for (auto& pending : pendingReferences)
            {
                auto& reference = pending.second;
                reference.Context.AddressSpace = device->AddressSpace();
                KmonHuntReceipt receipt;
                reference.Id = HuntIndex.Observe(reference, GetTickCount64(), &receipt);
                if (!receipt.Disposition.empty())
                {
                    event.Evidence[L"hop_" + std::to_wstring(pending.first) + L"_hunt_receipt"] = KmonHuntReceiptJson(receipt);
                    EvidenceBundle bundle;
                    bundle.Receipt = receipt;
                    bundle.Acquisition = kernelReaderUsed ? (userReaderUsed ? L"local_mixed_reader" : L"local_kernel_reader") : L"local_user_reader";
                    bundle.CaptureStartedMs = captureStartedMs;
                    bundle.CaptureEndedMs = captureEndedMs;
                    bundle.ReferenceConsistent = true;
                    bundle.CaptureTruncated = evidenceTruncated;
                    bundle.Spans = confirmedReads;
                    bundle.Spans.push_back(evidencePages.at(pending.first));
                    BindEvidenceOrigin(bundle, captureId, captureNativeEpoch, device->ObservationEpoch());
                    event.Evidence[L"hop_" + std::to_wstring(pending.first) + L"_bundle_queued_id"] =
                        std::to_wstring(QueueEvidenceBundle(std::move(bundle), {captureStartedMs, captureEndedMs, true}));
                }
                if (reference.Id != 0)
                {
                    ++acceptedReferences;
                    event.Evidence[L"hop_" + std::to_wstring(pending.first) + L"_hunt_reference"] = KmonHuntReferenceJson(receipt.Reference);
                }
            }
        }
        else
        {
            event.Evidence[L"capture_reference_consistency"] = L"changed_or_unreadable; path_references_withheld";
        }
        if (!referenceSnapshotValid || (KmonPageRole(work.Role) && acceptedReferences == 0))
        {
            event.Kind = L"coverage.execution_path";
        }
        else if (KmonPageRole(work.Role) && !chain.HasModifiedCode && !chain.HasUnownedExecutable && !chain.HasUnexpectedExecutable)
        {
            event.Kind = L"coverage.executable_memory";
        }
        event.Evidence[L"physical_page_reader_used"] = physicalPageRead ? L"true" : L"false";
        const bool allHeadsRead = !chain.Hops.empty() && std::all_of(chain.Hops.begin(), chain.Hops.end(),
            [](const auto& hop) { return !hop.Bytes.empty(); });
        const auto resolvedOutcome = chain.ReferenceChecked && !chain.ReferenceStable ? KmonReferenceOutcome::Inconsistent :
            (!allHeadsRead || chain.Termination == L"unreadable" || chain.Termination == L"page_location_unreadable" ? KmonReferenceOutcome::ReadUnavailable :
            (!referenceSnapshotValid ? KmonReferenceOutcome::Inconsistent :
            ((pageCheck ? acceptedReferences != 0 : chain.Termination == L"no_supported_head_transfer") ?
                KmonReferenceOutcome::Observed : KmonReferenceOutcome::Partial)));
        event.Evidence[L"reference_scheduling_outcome"] = KmonReferenceOutcomeName(resolvedOutcome);
        RecordEvent(std::move(event));
        outcome = resolvedOutcome;
    }
}

bool KmonReferenceSchedulingIntegrationSelfTest(std::wstring* diagnostics)
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool value) { ++checks; if (!value) { ++failures; std::fprintf(stderr, "[reference.integration] failed %u\n", checks); } };
    auto* memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    const auto release = [](void* value) { if (value != nullptr) { VirtualFree(value, 0, MEM_RELEASE); } };
    const std::unique_ptr<void, decltype(release)> owner(memory, release);
    if (memory == nullptr) { if (diagnostics) { *diagnostics = L"{\"passed\":false,\"issue\":\"allocation_failed\"}"; } return false; }
    std::memset(memory, 0x90, 4 * 4096);
    memory[64] = 0xFF; memory[65] = 0xE0; // A register-indirect target remains partial.
    const uint64_t base = reinterpret_cast<uint64_t>(memory);
    const uint64_t other = base + 32;
    std::memcpy(memory + 3 * 4096, &other, sizeof(other));
    DWORD previous = 0;
    check(VirtualProtect(memory + 4096, 4096, PAGE_NOACCESS, &previous) != FALSE);
    check(VirtualProtect(memory + 2 * 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &previous) != FALSE);
    const auto identity = ObserveProcessIdentity(GetCurrentProcessId(), GetCurrentProcess());
    check(identity.HasCanonicalKey());
    DeviceClient absent;
    SymbolEngine symbols;
    KernelMonitor monitor;
    monitor.QueueExecutionReference(base, 0, L"owned_stable", identity);
    monitor.QueueExecutionReference(base + 4096, 0, L"owned_unreadable", identity);
    monitor.QueueExecutionReference(base + 2 * 4096, 0, L"owned_guard", identity);
    monitor.QueueExecutionReference(base, 0, L"owned_anchor", identity, 0, {{base, {0x91}}});
    monitor.QueueExecutionReference(base, base + 3 * 4096, L"iat", identity);
    auto stale = identity; ++stale.CreateTime;
    monitor.QueueExecutionReference(base, 0, L"owned_stale", stale);
    monitor.QueueExecutionReference(base, 0, L"user_page_candidate", identity);
    monitor.QueueExecutionReference(base + 64, 0, L"owned_partial", identity);
    check(monitor.ExecutionReferences.size() == 8);
    monitor.ScanExecutionReferences(32, 1000);
    check(monitor.ExecutionReferences.size() == 8 && monitor.ExecutionReferenceProcessed == 0);
    // Run the production drain with owned user memory and an unopened native
    // backend. The public live-source gate above remains unchanged.
    monitor.DrainExecutionReferences(&absent, &symbols, 32, 5000, false);
    check(monitor.ExecutionReferences.empty() && monitor.ExecutionReferenceProcessed == 8);
    const auto& normal = monitor.ExecutionReferences.Normal();
    const auto count = [&](KmonReferenceOutcome outcome) { return normal.Outcomes[static_cast<size_t>(outcome)]; };
    check(count(KmonReferenceOutcome::Observed) == 1 && count(KmonReferenceOutcome::ReadUnavailable) == 2 &&
        count(KmonReferenceOutcome::Inconsistent) == 2 && count(KmonReferenceOutcome::IdentityUnavailable) == 1 &&
        count(KmonReferenceOutcome::MappingUnavailable) == 1 && count(KmonReferenceOutcome::Partial) == 1);
    check(normal.SuccessService.Samples == 1 && normal.FailedService.Samples == 7);
    MEMORY_BASIC_INFORMATION guarded{};
    check(VirtualQuery(memory + 2 * 4096, &guarded, sizeof(guarded)) == sizeof(guarded) && (guarded.Protect & PAGE_GUARD) != 0);
    monitor.DrainPipelineEvents(true);
    std::wstring pipeline;
    bool failedHeadEmpty = false;
    for (const auto& event : monitor.Ring)
    {
        if (event.Observation.Source == L"owned_unreadable")
        {
            const auto bytes = event.Evidence.find(L"hop_0_bytes_read");
            failedHeadEmpty = bytes != event.Evidence.end() && bytes->second == L"0";
        }
        const auto found = event.Evidence.find(L"reference_scheduling_json");
        if (event.Kind == L"coverage.pipeline" && found != event.Evidence.end()) { pipeline = found->second; }
    }
    check(!pipeline.empty() && failedHeadEmpty);

    KernelMonitor draining;
    draining.QueueExecutionReference(base, 0, L"owned_shutdown", identity);
    draining.StopRequested.store(true);
    draining.DrainExecutionReferences(&absent, &symbols, 32, 5000, false);
    check(draining.ExecutionReferences.size() == 1);
    draining.DrainExecutionReferences(&absent, &symbols, 32, 5000, true);
    check(draining.ExecutionReferences.empty() && draining.ExecutionReferences.Normal().QueueWait.Samples == 0 &&
        draining.ExecutionReferences.Shutdown().SuccessService.Samples == 1);

    KernelMonitor flooding;
    for (unsigned i = 0; i != 40; ++i) { flooding.QueueExecutionReference(base + i, 0, L"owned_flood", identity); }
    flooding.QueueExecutionReference(base, 0, L"owned_quiet", identity);
    check(flooding.ExecutionReferences.size() == 17 && flooding.ExecutionReferenceQueued == 17 && flooding.ExecutionReferenceDropped == 24);
    flooding.QueueExecutionReference(base, 0, L"owned_flood", identity, 0, {{base, {0}}});
    check(flooding.ExecutionReferenceQueued == 17);
    flooding.DrainExecutionReferences(&absent, &symbols, 2, 5000, false);
    KmonExecutionReferenceWork quiet; quiet.Identity = identity; quiet.Role = L"owned_quiet"; quiet.Target = base;
    const auto* quietResult = flooding.ExecutionReferences.Find(quiet);
    check(quietResult != nullptr && quietResult->HasSuccess && flooding.ExecutionReferences.size() == 15);
    check(!absent.IsOpen());
    if (diagnostics)
    {
        *diagnostics = L"{\"schema\":\"kn.reference_scheduler_test.v1\",\"passed\":" + std::wstring(failures == 0 ? L"true" : L"false") +
            L",\"checks\":" + std::to_wstring(checks) + L",\"driver_loaded\":false,\"corpus\":\"owned_process_and_absent_device\",\"pipeline\":" +
            (pipeline.empty() ? L"null" : pipeline) + L",\"shutdown\":" + draining.ExecutionReferences.Json(GetTickCount64()) +
            L",\"admission\":" + flooding.ExecutionReferences.Json(GetTickCount64()) + L"}";
    }
    return failures == 0;
}

void KernelMonitor::ScanGameObjectManifest(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader)
{
    if (!GameManifestActive)
    {
        return;
    }
    auto image = FindImageWork(path, base, identity);
    if (image == nullptr)
    {
        return;
    }
    if (!image->ManifestChecked)
    {
        std::wstring error;
        image->ManifestMatches = MatchGameManifest(GameManifest, path, image->Reference, &error);
        image->ManifestChecked = true;
        KmonEvent event;
        event.Kind = L"coverage.manifest";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Observation.Identity = identity;
        event.Observation.Source = L"game_build_manifest";
        event.Summary = image->ManifestMatches ? L"exact image and PDB identity match; object rules enabled" : error;
        event.Evidence[L"manifest_applied"] = image->ManifestMatches ? L"true" : L"false";
        event.Evidence[L"image_sha256"] = GameManifest.ImageSha256;
        event.Evidence[L"pdb_age"] = std::to_wstring(GameManifest.PdbAge);
        RecordEvent(std::move(event));
    }
    if (!image->ManifestMatches || !QualifyExecutableReference(image->Reference, base, reader, nullptr))
    {
        return;
    }
    // File identity is checked again so a changed reference never inherits a
    // previous exact-build match. The full hash is paid only at initial bind.
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    const bool stableFile = file != INVALID_HANDLE_VALUE && executable_image::DiskFileIdentityMatches(file, image->Reference);
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (!stableFile)
    {
        image->ManifestMatches = false;
        EmitUnique(L"coverage.manifest", L"scan_failed:manifest:file_identity:" + path, path,
            L"manifest", L"manifest reference changed; object rules disabled", L"restart with a new qualified manifest", identity.ProcessId);
        return;
    }
    const auto observations = VerifyGameObjects(GameManifest, base, reader, 2, &image->ObjectCursor);
    size_t allowed = 0;
    size_t unknown = 0;
    for (const auto& observation : observations)
    {
        const auto reportKey = std::make_pair(observation.RuleIndex,
            observation.IsVptr ? UINT32_MAX : observation.SlotIndex);
        if (observation.Readable && !observation.IsVptr)
        {
            QueueExecutionReference(observation.Target, observation.SlotAddress, L"manifest_vtable", identity);
        }
        if (observation.Readable && !observation.Modified)
        {
            image->ObjectReports.erase(reportKey);
            ++allowed;
            continue;
        }
        if (!observation.Readable)
        {
            ++unknown;
        }
        const std::wstring signature = observation.Reason + L":" + std::to_wstring(observation.ObjectAddress) +
            L":" + std::to_wstring(observation.SlotAddress) + L":" + std::to_wstring(observation.Target);
        if (image->ObjectReports[reportKey] == signature)
        {
            continue;
        }
        image->ObjectReports[reportKey] = signature;
        const auto& rule = GameManifest.Vptrs[observation.RuleIndex];
        KmonEvent event;
        event.Kind = observation.Modified ? L"finding.game_object" : L"coverage.game_object";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Summary = observation.Reason;
        event.Observation.Identity = identity;
        event.Observation.Source = L"game_build_manifest";
        event.Observation.ReferenceSource = L"sha256_and_private_pdb_object_rules";
        event.Evidence[L"object"] = GameManifest.Objects[rule.ObjectIndex].Name;
        event.Evidence[L"object_address"] = std::to_wstring(observation.ObjectAddress);
        event.Evidence[L"vptr_offset"] = std::to_wstring(rule.Offset);
        event.Evidence[L"slot_index"] = observation.IsVptr ? L"vptr" : std::to_wstring(observation.SlotIndex);
        event.Evidence[L"slot_address"] = std::to_wstring(observation.SlotAddress);
        event.Evidence[L"target"] = std::to_wstring(observation.Target);
        event.Evidence[L"relationship"] = L"object_and_address";
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"manifest_sha256"] = GameManifest.ImageSha256;
        if (observation.Readable)
        {
            std::vector<uint8_t> bytes(sizeof(observation.Target));
            std::memcpy(bytes.data(), &observation.Target, bytes.size());
            event.Evidence[L"capture_id"] = std::to_wstring(QueueCapturedBytes(L"manifest_slot", observation.SlotAddress, event.Observation, bytes));
        }
        RecordEvent(std::move(event));
    }
    KmonEvent coverage;
    coverage.Kind = L"coverage.manifest";
    coverage.ProcessId = identity.ProcessId;
    coverage.Observation.Identity = identity;
    coverage.Observation.Source = L"game_object_sweep";
    coverage.Evidence[L"rule_cursor"] = std::to_wstring(image->ObjectCursor);
    coverage.Evidence[L"rules_total"] = std::to_wstring(GameManifest.Vptrs.size());
    coverage.Evidence[L"allowed_observations"] = std::to_wstring(allowed);
    coverage.Evidence[L"unreadable_observations"] = std::to_wstring(unknown);
    coverage.Summary = L"manifest object pass completed; target code is verified separately";
    RecordEvent(std::move(coverage));
}
