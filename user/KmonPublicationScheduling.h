#pragma once

#include "KmonCaptureScheduling.h"
#include <memory>

enum class KmonPublicationFamily : size_t { Image, Evidence, Irp, Page, None };
constexpr size_t KmonPublicationFamilies = 4;
inline const wchar_t* KmonPublicationFamilyName(size_t family)
{
    static const wchar_t* names[] = {L"image_reads", L"evidence_bundle", L"irp_capture", L"captured_page"};
    return names[family];
}

// Passed only by the local acquiring caller, never reconstructed from serialized
// target/provider timestamps or from a retained artifact's admission time.
struct KmonAcquisitionWindow
{
    uint64_t Started = 0, Finished = 0;
    bool Known = false;
};
struct KmonPublicationStamp
{
    KmonAcquisitionWindow Acquisition;
    uint64_t Queued = 0;
    bool QueuedKnown = false;
};
struct KmonPublicationResult
{
    bool FilePublished = false, JournalCommitted = false, Complete = false;
    uint64_t FileMs = 0, JournalMs = 0;
};
struct KmonPublicationPending
{
    uint64_t Count = 0, OldestQueued = 0, UnknownQueued = 0, InvalidClocks = 0;
    bool OldestKnown = false;
    void Add(const KmonPublicationStamp& stamp, uint64_t now)
    {
        ++Count;
        if (!stamp.QueuedKnown) { ++UnknownQueued; return; }
        if (stamp.Queued > now) { ++InvalidClocks; return; }
        if (!OldestKnown || stamp.Queued < OldestQueued) { OldestQueued = stamp.Queued; OldestKnown = true; }
    }
};

// A single writer consumes each family; each family's existing retention-class
// rotation is independent. A loan never moves the ordinary family cursor.
class KmonPublicationPicker
{
public:
    KmonPublicationFamily Pick(const std::array<KmonPublicationPending, KmonPublicationFamilies>& pending)
    {
        size_t ordinary = KmonPublicationFamilies, oldest = KmonPublicationFamilies;
        for (size_t offset = 0; offset < KmonPublicationFamilies; ++offset)
        {
            const auto i = (Next + offset) % KmonPublicationFamilies;
            if (pending[i].Count == 0) { continue; }
            if (ordinary == KmonPublicationFamilies) { ordinary = i; }
            if (pending[i].OldestKnown && (oldest == KmonPublicationFamilies || pending[i].OldestQueued < pending[oldest].OldestQueued))
            { oldest = i; }
        }
        if (ordinary == KmonPublicationFamilies) { return KmonPublicationFamily::None; }
        if (Turns++ % 4 == 3 && oldest != KmonPublicationFamilies && oldest != ordinary)
        { ++Loans; return static_cast<KmonPublicationFamily>(oldest); }
        Next = (ordinary + 1) % KmonPublicationFamilies;
        return static_cast<KmonPublicationFamily>(ordinary);
    }
    uint64_t DebtLoans() const { return Loans; }
private:
    size_t Next = 0;
    uint64_t Turns = 0, Loans = 0;
};

class KmonPublicationTimings
{
public:
    struct Counts
    {
        uint64_t Attempts = 0, Complete = 0, Partial = 0, Failed = 0;
        uint64_t Files = 0, Journals = 0, UnknownQueued = 0, UnknownAcquisition = 0, InvalidClocks = 0;
    };
    struct Samples
    {
        Counts Count;
        KmonLatencyHistogram QueueWait, CompleteService, IncompleteService, QueueToFile, QueueToJournal;
        KmonLatencyHistogram AcquisitionEndToFile, AcquisitionStartToFile, AcquisitionEndToJournal, AcquisitionStartToJournal;
    };
    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        State = std::make_unique<Data>();
    }
    void Admission(KmonPublicationFamily family, bool admitted)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& count = admitted ? State->Admitted[static_cast<size_t>(family)] : State->Rejected[static_cast<size_t>(family)];
        ++count;
    }
    void Begin(KmonPublicationFamily family, const KmonPublicationStamp& stamp, uint64_t now, bool shutdown, uint64_t loans)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        State->Active = family; State->ActiveStamp = stamp; State->ActiveSince = now; State->ActiveShutdown = shutdown; State->Loans = loans;
    }
    void Finish(KmonPublicationFamily family, const KmonPublicationStamp& stamp, uint64_t started, uint64_t ended,
        bool shutdown, const KmonPublicationResult& result)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& samples = State->Families[static_cast<size_t>(family)][shutdown ? 1 : 0];
        auto& counts = samples.Count;
        ++counts.Attempts;
        if (result.Complete) { ++counts.Complete; }
        else if (result.FilePublished || result.JournalCommitted) { ++counts.Partial; }
        else { ++counts.Failed; }
        counts.Files += result.FilePublished; counts.Journals += result.JournalCommitted;
        counts.UnknownQueued += !stamp.QueuedKnown; counts.UnknownAcquisition += !stamp.Acquisition.Known;
        State->Active = KmonPublicationFamily::None;
        if (ended < started) { ++counts.InvalidClocks; return; }
        (result.Complete ? samples.CompleteService : samples.IncompleteService).Add(ended - started);
        const bool queueValid = stamp.QueuedKnown && stamp.Queued <= started;
        const bool acquisitionValid = queueValid && stamp.Acquisition.Known && stamp.Acquisition.Started <= stamp.Acquisition.Finished &&
            stamp.Acquisition.Finished <= stamp.Queued;
        if ((stamp.QueuedKnown && !queueValid) || (stamp.Acquisition.Known && !acquisitionValid)) { ++counts.InvalidClocks; }
        if (queueValid) { samples.QueueWait.Add(started - stamp.Queued); }
        const auto milestone = [&](bool known, uint64_t tick, KmonLatencyHistogram& queue, KmonLatencyHistogram& lower, KmonLatencyHistogram& upper)
        {
            if (!known) { return; }
            if (tick < started || tick > ended) { ++counts.InvalidClocks; return; }
            if (queueValid) { queue.Add(tick - stamp.Queued); }
            if (acquisitionValid) { lower.Add(tick - stamp.Acquisition.Finished); upper.Add(tick - stamp.Acquisition.Started); }
        };
        milestone(result.FilePublished, result.FileMs, samples.QueueToFile, samples.AcquisitionEndToFile, samples.AcquisitionStartToFile);
        if (result.JournalCommitted && result.FilePublished && result.JournalMs < result.FileMs) { ++counts.InvalidClocks; }
        else { milestone(result.JournalCommitted, result.JournalMs, samples.QueueToJournal, samples.AcquisitionEndToJournal, samples.AcquisitionStartToJournal); }
    }
    Counts Snapshot(KmonPublicationFamily family, bool shutdown = false) const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return State->Families[static_cast<size_t>(family)][shutdown ? 1 : 0].Count;
    }
    std::wstring Json(const std::array<KmonPublicationPending, KmonPublicationFamilies>& pending, uint64_t now) const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        const auto histogram = [&](const KmonLatencyHistogram& h)
        { return L"{\"samples\":" + n(h.Samples) + L",\"p50_upper_ms\":" + n(h.UpperPercentile(50)) +
            L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) + L",\"max_ms\":" + n(h.MaximumMs) + L"}"; };
        const auto samples = [&](const Samples& s)
        {
            const auto& c = s.Count;
            return L"{\"attempts\":" + n(c.Attempts) + L",\"complete\":" + n(c.Complete) + L",\"partial\":" + n(c.Partial) +
                L",\"failed\":" + n(c.Failed) + L",\"file_publications\":" + n(c.Files) + L",\"journal_commits\":" + n(c.Journals) +
                L",\"unknown_queue_origins\":" + n(c.UnknownQueued) + L",\"unknown_acquisition_origins\":" + n(c.UnknownAcquisition) +
                L",\"invalid_clocks\":" + n(c.InvalidClocks) + L",\"queue_wait\":" + histogram(s.QueueWait) +
                L",\"complete_service\":" + histogram(s.CompleteService) + L",\"incomplete_service\":" + histogram(s.IncompleteService) +
                L",\"queue_to_file\":" + histogram(s.QueueToFile) + L",\"queue_to_journal\":" + histogram(s.QueueToJournal) +
                L",\"acquisition_end_to_file\":" + histogram(s.AcquisitionEndToFile) + L",\"acquisition_start_to_file\":" + histogram(s.AcquisitionStartToFile) +
                L",\"acquisition_end_to_journal\":" + histogram(s.AcquisitionEndToJournal) + L",\"acquisition_start_to_journal\":" + histogram(s.AcquisitionStartToJournal) + L"}";
        };
        std::wstring families;
        for (size_t i = 0; i < KmonPublicationFamilies; ++i)
        {
            if (i != 0) { families += L","; }
            const auto& p = pending[i];
            families += L"{\"family\":" + mcpjson::Quote(KmonPublicationFamilyName(i)) + L",\"admitted\":" + n(State->Admitted[i]) +
                L",\"rejected\":" + n(State->Rejected[i]) + L",\"pending\":" + n(p.Count) + L",\"unknown_queued\":" + n(p.UnknownQueued) +
                L",\"pending_invalid_clocks\":" + n(p.InvalidClocks) + L",\"oldest_wait_ms\":" +
                (p.OldestKnown && p.OldestQueued <= now ? n(now - p.OldestQueued) : L"null") +
                L",\"normal\":" + samples(State->Families[i][0]) + L",\"shutdown\":" + samples(State->Families[i][1]) + L"}";
        }
        const bool active = State->Active != KmonPublicationFamily::None;
        return L"{\"schema\":\"kn.publication_scheduling.v1\",\"scope\":\"capture_writer_admitted_work\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"policy\":\"family_rotation_bounded_oldest_loan.v1\","
            L"\"acquisition_scope\":\"explicit_local_caller_window_not_imported_or_native_api_clock\","
            L"\"file_scope\":\"existing_publication_api_success_not_media_power_loss_proof\","
            L"\"snapshot_atomic_across_queues\":false,\"hard_deadline_enforced\":false,\"shutdown_in_normal_samples\":false,"
            L"\"percentiles\":\"log2_bucket_upper_bounds\",\"ordinary_turns_per_loan\":\"3\",\"families\":[" + families +
            L"],\"debt_loans\":" + n(State->Loans) + L",\"active_family\":" +
            (active ? mcpjson::Quote(KmonPublicationFamilyName(static_cast<size_t>(State->Active))) : L"null") +
            L",\"active_service_ms\":" + (active && State->ActiveSince <= now ? n(now - State->ActiveSince) : L"null") +
            L",\"active_queue_wait_ms\":" + (active && State->ActiveStamp.QueuedKnown && State->ActiveStamp.Queued <= State->ActiveSince ?
                n(State->ActiveSince - State->ActiveStamp.Queued) : L"null") +
            L",\"active_shutdown\":" + (active && State->ActiveShutdown ? L"true" : L"false") + L"}";
    }
private:
    struct Data
    {
        std::array<std::array<Samples, 2>, KmonPublicationFamilies> Families;
        std::array<uint64_t, KmonPublicationFamilies> Admitted{}, Rejected{};
        KmonPublicationFamily Active = KmonPublicationFamily::None;
        KmonPublicationStamp ActiveStamp;
        uint64_t ActiveSince = 0, Loans = 0;
        bool ActiveShutdown = false;
    };
    mutable std::mutex Mutex;
    std::unique_ptr<Data> State = std::make_unique<Data>();
};
static_assert(sizeof(KmonPublicationTimings) <= 128, "Publication histogram storage must remain on the heap");

struct KmonPublicationAdmission
{
    KmonPublicationTimings& Timings;
    KmonPublicationFamily Family;
    bool Admitted = false;
    ~KmonPublicationAdmission() { Timings.Admission(Family, Admitted); }
};
