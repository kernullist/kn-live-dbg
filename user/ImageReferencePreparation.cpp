#include "ImageReferencePreparation.h"
#include "KmonFairRing.h"
#include "KmonCaptureScheduling.h"
#include <condition_variable>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>

namespace
{
    uint64_t RetainedBytes(const ImageReferencePreparation::Prepared& p)
    {
        const auto& r = p.Reference;
        uint64_t bytes = sizeof(p) + r.Sections.capacity() * sizeof(executable_image::DiskPeSection) +
            r.RelocationPages.size() * 64ull + r.BaseRelocations.capacity() * sizeof(executable_image::DiskPeBaseRelocation) +
            (r.CrossPageRelocationRanges.capacity() + r.LoaderMutableRanges.capacity() + r.DynamicRelocationRanges.capacity()) *
                sizeof(executable_image::DiskPeMutableRange) + r.Rel32Overrides.capacity() * sizeof(executable_image::DiskPeRel32Override) +
            p.Sweep.Ranges.capacity() * sizeof(ObservationRange);
        for (const auto& section : r.Sections) { bytes += section.Name.capacity() * sizeof(wchar_t); }
        for (const auto& range : r.Rel32Overrides) { bytes += range.Targets.capacity() * sizeof(uint32_t); }
        return bytes + (p.Content ? p.Content->RetainedBytes() : 0);
    }
}

struct ImageReferencePreparation::State
{
    struct Entry
    {
        std::unique_ptr<Result> Output;
        std::atomic<bool> Cancel{false};
        bool Running = false, Ready = false;
    };
    struct Timing
    {
        uint64_t Attempts = 0, Prepared = 0, Failed = 0, Cancelled = 0;
        uint64_t RetainedSnapshots = 0, UnretainedLeases = 0;
        KmonLatencyHistogram Queue, Service, PreparedService, FailedService, CancelledService, AdmissionToReady;
    };
    struct Deferred { Request Work; Admission Reason; uint64_t First = 0, Last = 0, Attempts = 0; };
    mutable std::mutex Mutex;
    std::mutex Lifecycle;
    std::condition_variable Changed;
    std::map<uint64_t, std::shared_ptr<Entry>> Entries;
    std::map<ObservationIdentity::Key, std::deque<uint64_t>> Queues;
    KmonFairRing<ObservationIdentity::Key> Order;
    std::vector<uint64_t> Ready;
    std::deque<Deferred> Deferrals;
    std::array<std::thread, WorkerCount> Threads;
    std::array<Timing, 2> Timings;
    Loader Load;
    Kind Mode = Kind::Metadata;
    bool Started = false, Closing = false;
    size_t Running = 0, Peak = 0;
    uint64_t NextId = 0, Admitted = 0, Refused = 0, Invalid = 0, Applied = 0, Stale = 0;
    uint64_t CancelledQueued = 0, DiscardedReady = 0, DeferredEvicted = 0, Abandoned = 0;
    uint64_t InvalidClocks = 0, CancelIoRequests = 0, CancelIoAccepted = 0, WorkerFaults = 0;
    uint64_t ExpiredReady = 0;
    KmonLatencyHistogram ReadyToConsumer;

    void RemoveQueued(uint64_t id, const ObservationIdentity::Key& subject)
    {
        const auto it = Queues.find(subject);
        if (it == Queues.end()) { return; }
        auto& queue = it->second;
        queue.erase(std::remove(queue.begin(), queue.end(), id), queue.end());
        if (queue.empty()) { Queues.erase(it); Order.Remove(subject); }
    }
    void ExpireReady(uint64_t now)
    {
        if (Mode != Kind::Content) { return; }
        for (auto it = Ready.begin(); it != Ready.end();)
        {
            const auto& result = *Entries.at(*it)->Output;
            if (result.Finished > now || now - result.Finished < ContentReadyLifetimeMs) { ++it; continue; }
            Entries.erase(*it); it = Ready.erase(it);
            ++ExpiredReady; ++DiscardedReady;
        }
    }
};

ImageReferencePreparation::ImageReferencePreparation(Loader loader) : ImageReferencePreparation(Kind::Metadata, std::move(loader)) {}
ImageReferencePreparation::ImageReferencePreparation(Kind kind, Loader loader) : Data(std::make_unique<State>())
{ Data->Mode = kind; Data->Load = loader ? std::move(loader) : kind == Kind::Content ? LoadContent : LoadNative; }
ImageReferencePreparation::~ImageReferencePreparation() { RequestStop(); Join(); }

const wchar_t* ImageReferencePreparation::OutcomeName(Outcome outcome, Kind kind)
{
    switch (outcome)
    {
    case Outcome::Prepared: return kind == Kind::Content ? L"prepared_content_lease" : L"prepared_metadata";
    case Outcome::Unavailable: return L"reference_unavailable";
    case Outcome::NoExecutableRanges: return L"no_supported_executable_ranges";
    case Outcome::StorageLimit: return L"prepared_storage_limit";
    case Outcome::Cancelled: return L"cancelled";
    default: return L"fault";
    }
}
const wchar_t* ImageReferencePreparation::AdmissionName(Admission status)
{
    switch (status)
    {
    case Admission::Queued: return L"queued";
    case Admission::GlobalLimit: return L"global_limit";
    case Admission::SubjectLimit: return L"subject_limit";
    case Admission::Stopping: return L"stopping";
    default: return L"invalid";
    }
}

ImageReferencePreparation::Outcome ImageReferencePreparation::LoadNative(const Request& work,
    const std::atomic<bool>& stop, Prepared& value, std::wstring& error)
{
    if (stop.load()) { return Outcome::Cancelled; }
    if (!executable_image::ReadDiskPeMetadataCancelable(work.Path, &value.Reference, &error, stop))
    { return stop.load() ? Outcome::Cancelled : Outcome::Unavailable; }
    if (stop.load()) { return Outcome::Cancelled; }
    if (!value.Sweep.Initialize(value.Reference)) { return Outcome::NoExecutableRanges; }
    return stop.load() ? Outcome::Cancelled : Outcome::Prepared;
}

ImageReferencePreparation::Outcome ImageReferencePreparation::LoadContent(const Request& work,
    const std::atomic<bool>& stop, Prepared& value, std::wstring& error)
{
    if (stop.load()) { return Outcome::Cancelled; }
    value.Content = std::make_unique<ExecutableReferenceLease>();
    if (!value.Content->Open(work.Path, stop))
    { error = L"reference content lease unavailable"; return stop.load() ? Outcome::Cancelled : Outcome::Unavailable; }
    return stop.load() ? Outcome::Cancelled : Outcome::Prepared;
}

void ImageReferencePreparation::Start()
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lifecycle(s.Lifecycle);
    std::unique_lock<std::mutex> lock(s.Mutex);
    if (s.Started || s.Closing) { return; }
    try
    {
        s.Ready.reserve(ResultSlots);
        for (auto& thread : s.Threads) { thread = std::thread(&ImageReferencePreparation::Run, this); }
        s.Started = true;
    }
    catch (...)
    {
        s.Closing = true;
        lock.unlock(); s.Changed.notify_all();
        for (auto& thread : s.Threads) { if (thread.joinable()) { thread.join(); } }
        throw;
    }
}

ImageReferencePreparation::Ticket ImageReferencePreparation::Submit(Request work, uint64_t now)
{
    Start();
    auto& s = *Data;
    std::lock_guard<std::mutex> lock(s.Mutex);
    s.ExpireReady(GetTickCount64());
    if (work.Key.empty() || work.Key.size() > 65536 || work.Path.empty() || work.Path.size() > 32768 ||
        work.Key.find(L'\0') != std::wstring::npos || work.Path.find(L'\0') != std::wstring::npos ||
        work.Identity.BootId.empty() || work.Identity.BootId.size() > 128 || work.Base == 0 || work.Episode == 0 ||
        (work.Identity.ProcessId != 0 && !work.Identity.HasCanonicalKey()) || work.FirstSeen > now || s.NextId == UINT64_MAX)
    { ++s.Invalid; return {}; }
    Admission reason = Admission::Queued;
    const auto subject = work.Identity.CanonicalKey();
    size_t own = 0;
    for (const auto& item : s.Entries) { own += item.second->Output->Work.Identity.CanonicalKey() == subject; }
    if (s.Closing) { reason = Admission::Stopping; }
    else if (s.Entries.size() >= Capacity) { reason = Admission::GlobalLimit; }
    else if (own >= SubjectCapacity) { reason = Admission::SubjectLimit; }
    if (reason != Admission::Queued)
    {
        ++s.Refused;
        for (auto& d : s.Deferrals)
        { if (d.Work.Key == work.Key && d.Work.Episode == work.Episode) { d.Last = now; ++d.Attempts; d.Reason = reason; return {reason, 0}; } }
        if (s.Deferrals.size() == 64) { s.Deferrals.pop_front(); ++s.DeferredEvicted; }
        s.Deferrals.push_back({std::move(work), reason, now, now, 1});
        return {reason, 0};
    }
    auto entry = std::make_shared<State::Entry>();
    entry->Output = std::make_unique<Result>();
    auto& out = *entry->Output;
    out.Work = std::move(work); out.Id = ++s.NextId; out.Queued = now;
    s.Entries.emplace(out.Id, entry);
    try { s.Order.Add(subject); s.Queues[subject].push_back(out.Id); }
    catch (...)
    {
        s.RemoveQueued(out.Id, subject);
        if (s.Queues.count(subject) == 0) { s.Order.Remove(subject); }
        s.Entries.erase(out.Id); throw;
    }
    s.Deferrals.erase(std::remove_if(s.Deferrals.begin(), s.Deferrals.end(), [&](const auto& d)
        { return d.Work.Key == out.Work.Key && d.Work.Episode == out.Work.Episode; }), s.Deferrals.end());
    ++s.Admitted; s.Peak = (std::max)(s.Peak, s.Entries.size());
    s.Changed.notify_one();
    return {Admission::Queued, out.Id};
}

void ImageReferencePreparation::Run()
{
    auto& s = *Data;
    try
    {
    for (;;)
    {
        std::shared_ptr<State::Entry> entry;
        {
            std::unique_lock<std::mutex> lock(s.Mutex);
            const auto available = [&]
            {
                s.ExpireReady(GetTickCount64());
                return s.Closing || (!s.Queues.empty() && s.Ready.size() + s.Running < ResultSlots);
            };
            if (s.Mode == Kind::Content) { s.Changed.wait_for(lock, std::chrono::milliseconds(100), available); }
            else { s.Changed.wait(lock, available); }
            if (s.Closing) { return; }
            if (s.Queues.empty() || s.Ready.size() + s.Running >= ResultSlots) { continue; }
            std::optional<ObservationIdentity::Key> oldest;
            uint64_t age = UINT64_MAX;
            if (s.Order.MayBorrow()) for (const auto& subject : s.Order.Keys())
            {
                const auto queued = s.Entries.at(s.Queues.at(subject).front())->Output->Queued;
                if (!oldest || queued < age) { oldest = subject; age = queued; }
            }
            const auto subject = *s.Order.Pick(oldest);
            const auto id = s.Queues.at(subject).front();
            entry = s.Entries.at(id);
            s.RemoveQueued(id, subject);
            entry->Running = true; ++s.Running;
            entry->Output->Started = GetTickCount64();
        }
        auto& result = *entry->Output;
        try
        {
            result.Value = std::make_unique<Prepared>();
            result.Status = s.Load(result.Work, entry->Cancel, *result.Value, result.Error);
            if (result.Status == Outcome::Prepared)
            {
                result.RetainedBytes = RetainedBytes(*result.Value);
                if (result.RetainedBytes > MaximumPreparedBytes) { result.Status = Outcome::StorageLimit; }
            }
        }
        catch (...) { result.Status = Outcome::Fault; }
        if (entry->Cancel.load()) { result.Status = Outcome::Cancelled; }
        if (result.Status != Outcome::Prepared) { result.Value.reset(); result.RetainedBytes = 0; }
        if (result.Error.size() > 512) { result.Error.resize(512); }
        result.Finished = GetTickCount64();
        {
            std::lock_guard<std::mutex> lock(s.Mutex);
            --s.Running; entry->Running = false;
            if (entry->Cancel.load()) { result.Status = Outcome::Cancelled; result.Value.reset(); result.RetainedBytes = 0; }
            auto& t = s.Timings[s.Closing ? 1 : 0];
            ++t.Attempts;
            if (result.Status == Outcome::Prepared) { ++t.Prepared; }
            else if (result.Status == Outcome::Cancelled) { ++t.Cancelled; }
            else { ++t.Failed; }
            if (result.Status == Outcome::Prepared && s.Mode == Kind::Content && result.Value->Content)
            {
                if (result.Value->Content->HasSnapshot()) { ++t.RetainedSnapshots; } else { ++t.UnretainedLeases; }
            }
            if (result.Queued <= result.Started && result.Started <= result.Finished)
            { t.Queue.Add(result.Started - result.Queued); t.Service.Add(result.Finished - result.Started);
              (result.Status == Outcome::Prepared ? t.PreparedService : result.Status == Outcome::Cancelled ? t.CancelledService : t.FailedService).Add(result.Finished - result.Started);
              if (result.Status == Outcome::Prepared) { t.AdmissionToReady.Add(result.Finished - result.Queued); } }
            else { ++s.InvalidClocks; }
            if (s.Closing || entry->Cancel.load()) { s.Entries.erase(result.Id); }
            else { entry->Ready = true; s.Ready.push_back(result.Id); }
        }
        s.Changed.notify_all();
    }
    }
    catch (...)
    {
        // Allocation/dispatch failure must not escape a native thread or leave
        // a silent live queue. Stop admission and expose the infrastructure fault.
        std::lock_guard<std::mutex> lock(s.Mutex);
        ++s.WorkerFaults; s.Closing = true;
        for (const auto& item : s.Entries) { item.second->Cancel.store(true); }
        s.Changed.notify_all();
    }
}

std::unique_ptr<ImageReferencePreparation::Result> ImageReferencePreparation::Take(uint64_t requestedId)
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lock(s.Mutex);
    s.ExpireReady(GetTickCount64());
    const auto ready = requestedId == 0 ? s.Ready.begin() : std::find(s.Ready.begin(), s.Ready.end(), requestedId);
    if (ready == s.Ready.end()) { return {}; }
    const auto id = *ready;
    auto output = std::move(s.Entries.at(id)->Output);
    s.Ready.erase(ready); s.Entries.erase(id);
    s.Changed.notify_all();
    return output;
}
bool ImageReferencePreparation::Contains(uint64_t id)
{
    auto& s = *Data; std::lock_guard<std::mutex> lock(s.Mutex);
    s.ExpireReady(GetTickCount64());
    return s.Entries.count(id) != 0;
}
bool ImageReferencePreparation::IsReady(uint64_t id)
{
    auto& s = *Data; std::lock_guard<std::mutex> lock(s.Mutex);
    s.ExpireReady(GetTickCount64());
    const auto found = s.Entries.find(id);
    return found != s.Entries.end() && found->second->Ready;
}
void ImageReferencePreparation::Disposition(const Result& result, bool applied, uint64_t now)
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lock(s.Mutex);
    if (applied) { ++s.Applied; } else { ++s.Stale; }
    if (now >= result.Finished) { s.ReadyToConsumer.Add(now - result.Finished); } else { ++s.InvalidClocks; }
}
void ImageReferencePreparation::Abandon(uint64_t id)
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lock(s.Mutex);
    const auto it = s.Entries.find(id);
    if (it == s.Entries.end()) { return; }
    ++s.Abandoned;
    const auto& e = it->second;
    e->Cancel.store(true);
    if (e->Running) { return; }
    if (e->Ready)
    { s.Ready.erase(std::remove(s.Ready.begin(), s.Ready.end(), id), s.Ready.end()); ++s.DiscardedReady; }
    else { s.RemoveQueued(id, e->Output->Work.Identity.CanonicalKey()); ++s.CancelledQueued; }
    s.Entries.erase(it); s.Changed.notify_all();
}
void ImageReferencePreparation::RequestStop()
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lifecycle(s.Lifecycle);
    std::lock_guard<std::mutex> lock(s.Mutex);
    s.Closing = true;
    for (auto it = s.Entries.begin(); it != s.Entries.end();)
    {
        it->second->Cancel.store(true);
        if (it->second->Running) { ++it; continue; }
        if (it->second->Ready) { ++s.DiscardedReady; } else { ++s.CancelledQueued; }
        it = s.Entries.erase(it);
    }
    s.Queues.clear(); s.Order.ClearMembers(); s.Ready.clear();
    // These dedicated threads cannot start another job after Closing. This is
    // a cancellation request, never a claim that native I/O has completed.
    for (auto& thread : s.Threads) if (thread.joinable())
    { ++s.CancelIoRequests; s.CancelIoAccepted += CancelSynchronousIo(thread.native_handle()) != FALSE; }
    s.Changed.notify_all();
}
void ImageReferencePreparation::Join()
{
    auto& s = *Data;
    std::lock_guard<std::mutex> lifecycle(s.Lifecycle);
    for (auto& thread : s.Threads) { if (thread.joinable()) { thread.join(); } }
}
void ImageReferencePreparation::Reset()
{
    RequestStop(); Join();
    auto replacement = std::make_unique<State>();
    replacement->Mode = Data->Mode;
    replacement->Load = Data->Load;
    Data = std::move(replacement); // Owner has stopped all producers/readers.
}

std::wstring ImageReferencePreparation::Json(uint64_t now) const
{
    const auto& s = *Data;
    std::lock_guard<std::mutex> lock(s.Mutex);
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    const auto h = [&](const KmonLatencyHistogram& histogram)
    { return L"{\"samples\":" + n(histogram.Samples) + L",\"p95_upper_ms\":" + n(histogram.UpperPercentile(95)) +
        L",\"p99_upper_ms\":" + n(histogram.UpperPercentile(99)) + L",\"max_ms\":" + n(histogram.MaximumMs) + L"}"; };
    const auto timing = [&](const State::Timing& t)
    { return L"{\"attempts\":" + n(t.Attempts) + L",\"prepared\":" + n(t.Prepared) + L",\"failed\":" + n(t.Failed) +
        L",\"cancelled\":" + n(t.Cancelled) + L",\"retained_snapshots\":" + n(t.RetainedSnapshots) +
        L",\"unretained_leases\":" + n(t.UnretainedLeases) + L",\"queue_wait\":" + h(t.Queue) + L",\"service\":" + h(t.Service) +
        L",\"prepared_service\":" + h(t.PreparedService) + L",\"failed_service\":" + h(t.FailedService) + L",\"cancelled_service\":" + h(t.CancelledService) +
        L",\"admission_to_ready\":" + h(t.AdmissionToReady) + L"}"; };
    const auto scope = [&](const Request& w)
    { return L"{\"boot_id\":" + mcpjson::Quote(w.Identity.BootId) + L",\"pid\":" + n(w.Identity.ProcessId) +
        L",\"create_time\":" + n(w.Identity.CreateTime) + L",\"base\":" + n(w.Base) + L",\"episode\":" + n(w.Episode) +
        L",\"path\":" + mcpjson::Quote(w.Path) + L",\"first_seen_ms\":" + n(w.FirstSeen); };
    std::wstring rows, deferred;
    size_t count = 0, deferredCount = 0, characters = 0;
    uint64_t retained = 0;
    for (const auto& item : s.Entries)
    {
        const auto& e = *item.second; const auto& r = *e.Output;
        // The worker owns its result while Running. Only immutable request and
        // dispatch fields may be read before it publishes Ready under Mutex.
        if (e.Ready) { retained += r.RetainedBytes; }
        auto row = scope(r.Work) + L",\"id\":" + n(r.Id) + L",\"queued_ms\":" + n(r.Queued) +
            L",\"age_ms\":" + (r.Queued <= now ? n(now - r.Queued) : L"null") + L",\"state\":" +
            mcpjson::Quote(e.Ready ? L"ready" : e.Running ? L"running" : L"queued") + L",\"outcome\":" +
            (e.Ready ? mcpjson::Quote(OutcomeName(r.Status, s.Mode)) : L"null") + L"}";
        const auto needed = row.size() + (rows.empty() ? 0 : 1);
        if (needed > 65536 - characters) { continue; }
        characters += needed; ++count; if (!rows.empty()) { rows += L","; } rows += row;
    }
    for (const auto& d : s.Deferrals)
    {
        auto row = scope(d.Work) + L",\"reason\":" + mcpjson::Quote(AdmissionName(d.Reason)) + L",\"first_deferred_ms\":" +
            n(d.First) + L",\"last_deferred_ms\":" + n(d.Last) + L",\"attempts\":" + n(d.Attempts) + L"}";
        const auto needed = row.size() + (deferred.empty() ? 0 : 1);
        if (needed > 65536 - characters) { continue; }
        characters += needed; ++deferredCount; if (!deferred.empty()) { deferred += L","; } deferred += row;
    }
    return L"{\"schema\":\"kn.image_reference_preparation.v1\",\"phase\":" + mcpjson::Quote(s.Mode == Kind::Content ? L"content" : L"metadata") +
        L",\"success_scope\":" + mcpjson::Quote(s.Mode == Kind::Content ? L"file_lease_prepared_not_live_image_verified" : L"metadata_prepared_not_live_image_verified") + L","
        L"\"clock_domain\":\"GetTickCount64_ms\",\"hard_deadline_enforced\":false,\"native_io_cancellation_guaranteed\":false,"
        L"\"shutdown_in_normal_samples\":false,\"policy\":\"subject_ring_bounded_oldest_loan.v1\",\"workers\":" + n(WorkerCount) +
        L",\"capacity\":" + n(Capacity) + L",\"subject_capacity\":" + n(SubjectCapacity) + L",\"result_slots\":" + n(ResultSlots) +
        L",\"resident\":" + n(s.Entries.size()) + L",\"running\":" + n(s.Running) + L",\"ready\":" + n(s.Ready.size()) +
        L",\"queued\":" + n(s.Entries.size() - s.Running - s.Ready.size()) + L",\"peak\":" + n(s.Peak) +
        L",\"admitted\":" + n(s.Admitted) + L",\"refused\":" + n(s.Refused) + L",\"invalid\":" + n(s.Invalid) +
        L",\"applied\":" + n(s.Applied) + L",\"stale_completions\":" + n(s.Stale) + L",\"cancelled_queued\":" + n(s.CancelledQueued) +
        L",\"discarded_ready\":" + n(s.DiscardedReady) + L",\"abandoned\":" + n(s.Abandoned) +
        L",\"expired_ready\":" + n(s.ExpiredReady) + L",\"ready_lifetime_ms\":" + n(s.Mode == Kind::Content ? ContentReadyLifetimeMs : 0) +
        L",\"ready_retained_estimate_bytes\":" + n(retained) + L",\"per_result_estimate_limit\":" + n(MaximumPreparedBytes) +
        L",\"hard_process_memory_bound\":false,\"invalid_clocks\":" + n(s.InvalidClocks) + L",\"debt_loans\":" + n(s.Order.DebtLoans()) +
        L",\"cancel_io_requests\":" + n(s.CancelIoRequests) + L",\"cancel_io_accepted\":" + n(s.CancelIoAccepted) +
        L",\"worker_faults\":" + n(s.WorkerFaults) + L",\"stopping\":" + (s.Closing ? L"true" : L"false") +
        L",\"normal\":" + timing(s.Timings[0]) + L",\"shutdown\":" + timing(s.Timings[1]) + L",\"ready_to_consumer\":" + h(s.ReadyToConsumer) +
        L",\"records_omitted\":" + n(s.Entries.size() - count) + L",\"deferred_evicted\":" + n(s.DeferredEvicted) +
        L",\"deferred_omitted\":" + n(s.Deferrals.size() - deferredCount) + L",\"records\":[" + rows + L"],\"deferred\":[" + deferred + L"]}";
}
