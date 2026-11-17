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
enum class KmonCollectionClosePhase : size_t { SweepFlush, EvidenceLedger, IrpLedger, ImageJournal };
constexpr size_t KmonCollectionClosePhases = 4;
struct KmonCollectionTotals
{
    uint64_t SweepPublications = 0, SweepMetadata = 0, IrpUnavailable = 0;
    uint64_t AuxiliaryPublications = 0; // Successful reference/recipe/sweep operations, including verified reuse; not unique files.
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
    void StartCollection(uint64_t now)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& c = State->Collection;
        if (c.StartKnown) { ++c.ProtocolErrors; return; }
        c.Start = now; c.StartKnown = true;
    }
    void Admission(KmonPublicationFamily family, bool admitted)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& count = admitted ? State->Admitted[static_cast<size_t>(family)] : State->Rejected[static_cast<size_t>(family)];
        ++count;
        if (State->Collection.EndKnown) { ++State->Collection.ProtocolErrors; }
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
        auto& collection = State->Collection;
        if (collection.EndKnown) { ++collection.ProtocolErrors; }
        if (ended < started) { ++counts.InvalidClocks; return; }
        if (!collection.WorkEndKnown || ended > collection.WorkEnd) { collection.WorkEnd = ended; collection.WorkEndKnown = true; }
        (result.Complete ? samples.CompleteService : samples.IncompleteService).Add(ended - started);
        const bool queueValid = stamp.QueuedKnown && stamp.Queued <= started && (!collection.StartKnown || collection.Start <= stamp.Queued);
        const bool acquisitionValid = queueValid && stamp.Acquisition.Known && stamp.Acquisition.Started <= stamp.Acquisition.Finished &&
            stamp.Acquisition.Finished <= stamp.Queued && (!collection.StartKnown || collection.Start <= stamp.Acquisition.Started);
        if ((stamp.QueuedKnown && !queueValid) || (stamp.Acquisition.Known && !acquisitionValid)) { ++counts.InvalidClocks; }
        if (queueValid) { collection.Queue.Observe(stamp.Queued, stamp.Queued); }
        if (acquisitionValid) { collection.Acquisition.Observe(stamp.Acquisition.Started, stamp.Acquisition.Finished); }
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
    // Only the writer calls these, after all producers have joined and their
    // queues drained. Readers can observe an in-progress close without I/O locks.
    void BeginClose(KmonCollectionClosePhase phase, uint64_t now, bool required = true)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& c = State->Collection;
        const auto index = static_cast<size_t>(phase);
        if (index >= c.Close.size() || c.EndKnown || c.Close[index].StartedKnown)
        { ++c.ProtocolErrors; return; }
        auto& step = c.Close[index];
        step.Started = now; step.StartedKnown = true; step.Required = required;
        if ((index && (!c.Close[index - 1].EndedKnown || c.Close[index - 1].Ended > now)) ||
            (c.StartKnown && now < c.Start) || (c.WorkEndKnown && c.WorkEnd > now)) { ++c.ProtocolErrors; }
    }
    void FinishClose(KmonCollectionClosePhase phase, uint64_t now, const KmonPublicationResult& result)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& c = State->Collection;
        const auto index = static_cast<size_t>(phase);
        if (index >= c.Close.size() || c.EndKnown || !c.Close[index].StartedKnown || c.Close[index].EndedKnown)
        { ++c.ProtocolErrors; return; }
        auto& step = c.Close[index];
        step.Ended = now; step.EndedKnown = true; step.Result = result;
        const auto valid = [&](bool known, uint64_t tick) { return !known || (tick >= step.Started && tick <= now); };
        if (now < step.Started || !valid(result.FilePublished, result.FileMs) || !valid(result.JournalCommitted, result.JournalMs) ||
            (result.FilePublished && result.JournalCommitted && result.JournalMs < result.FileMs) ||
            (!step.Required && (result.FilePublished || result.JournalCommitted)) ||
            (step.Required && result.Complete && index != 0 && (!result.FilePublished || (index >= 2 && !result.JournalCommitted))))
        { ++c.ProtocolErrors; }
    }
    void FinishCollection(uint64_t now, KmonCollectionTotals totals = {})
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& c = State->Collection;
        if (c.EndKnown) { ++c.ProtocolErrors; return; }
        c.End = now; c.EndKnown = true; c.Totals = totals;
        for (const auto& step : c.Close)
        { if (!step.EndedKnown || step.Ended > now) { ++c.ProtocolErrors; } }
        if (c.StartKnown && now < c.Start) { ++c.ProtocolErrors; }
    }
    std::wstring CollectionJson(const std::wstring& id, uint64_t now) const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto& c = State->Collection;
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        const auto b = [](bool v) { return v ? L"true" : L"false"; };
        const auto tick = [&](bool known, uint64_t v) { return known ? n(v) : L"null"; };
        const auto duration = [&](bool known, uint64_t first, uint64_t last) { return known && first <= last ? n(last - first) : L"null"; };
        uint64_t admitted = 0, rejected = 0, attempts = 0, complete = 0, files = 0, journals = 0, invalid = 0, shutdown = 0;
        for (size_t i = 0; i < KmonPublicationFamilies; ++i)
        {
            admitted += State->Admitted[i]; rejected += State->Rejected[i];
            for (size_t j = 0; j < 2; ++j)
            {
                const auto& count = State->Families[i][j].Count;
                attempts += count.Attempts; complete += count.Complete; files += count.Files; journals += count.Journals;
                invalid += count.InvalidClocks; if (j) { shutdown += count.Attempts; }
            }
        }
        std::wstring phases;
        bool settled = true, closed = true, anyClosure = false, closureMaterial = false;
        static const wchar_t* names[] = {L"sweep_flush", L"evidence_ledger", L"irp_ledger", L"image_journal"};
        for (size_t i = 0; i < c.Close.size(); ++i)
        {
            const auto& s = c.Close[i]; const auto& r = s.Result;
            settled &= s.EndedKnown; closed &= s.EndedKnown && (!s.Required || r.Complete);
            anyClosure |= s.StartedKnown; closureMaterial |= r.FilePublished || r.JournalCommitted;
            const auto outcome = !s.StartedKnown ? L"not_started" : !s.EndedKnown ? L"in_progress" : !s.Required ? L"not_applicable" :
                r.Complete ? L"complete" : r.FilePublished || r.JournalCommitted ? L"partial" : L"failed";
            if (i) { phases += L","; }
            phases += L"{\"phase\":" + mcpjson::Quote(names[i]) + L",\"required\":" + b(s.Required) +
                L",\"outcome\":" + mcpjson::Quote(outcome) + L",\"start_ms\":" + tick(s.StartedKnown, s.Started) +
                L",\"end_ms\":" + tick(s.EndedKnown, s.Ended) + L",\"service_ms\":" + duration(s.StartedKnown && s.EndedKnown, s.Started, s.Ended) +
                L",\"file_ms\":" + tick(r.FilePublished, r.FileMs) + L",\"journal_ms\":" + tick(r.JournalCommitted, r.JournalMs) + L"}";
        }
        const bool final = c.EndKnown && settled && State->Active == KmonPublicationFamily::None && admitted == attempts && c.ProtocolErrors == 0;
        const bool ok = final && closed && complete == attempts && rejected == 0 &&
            c.Totals.SweepPublications == 0 && c.Totals.SweepMetadata == 0 && c.Totals.IrpUnavailable == 0;
        const bool anyMaterial = files != 0 || journals != 0 || closureMaterial || c.Totals.AuxiliaryPublications != 0;
        const auto outcome = !final ? L"incomplete" : ok ? (attempts ? L"complete" : L"empty") : anyMaterial ? L"partial" : L"failed";
        const bool allAcquired = attempts != 0 && c.Acquisition.Samples == attempts && admitted == attempts && invalid == 0;
        const auto elapsedEnd = c.EndKnown ? c.End : now;
        return L"{\"schema\":\"kn.collection_timing.v1\",\"collection_id\":" + mcpjson::Quote(id) +
            L",\"scope\":\"capture_writer_session\",\"clock_domain\":\"GetTickCount64_ms\","
            L"\"acquisition_scope\":\"processed_jobs_explicit_local_caller_windows\","
            L"\"closure_scope\":\"existing_publication_api_success_not_media_power_loss_proof\","
            L"\"timing_journal_member\":false,\"source_coverage_evaluated\":false,\"captured_page_ledger\":false,"
            L"\"snapshot_atomic_with_producer_queues\":false,\"hard_deadline_enforced\":false,"
            L"\"writer_finished\":" + b(c.EndKnown) + L",\"final\":" + b(final) + L",\"publication_outcome\":" + mcpjson::Quote(outcome) +
            L",\"closure_outcome\":" + mcpjson::Quote(!anyClosure ? L"not_started" : !settled ? L"in_progress" : closed ? L"complete" : closureMaterial ? L"partial" : L"failed") +
            L",\"start_ms\":" + tick(c.StartKnown, c.Start) + L",\"writer_end_ms\":" + tick(c.EndKnown, c.End) +
            L",\"elapsed_ms\":" + duration(c.StartKnown, c.Start, elapsedEnd) + L",\"admitted\":" + n(admitted) +
            L",\"rejected\":" + n(rejected) + L",\"attempts\":" + n(attempts) + L",\"complete_jobs\":" + n(complete) +
            L",\"normal_attempts\":" + n(attempts - shutdown) + L",\"shutdown_attempts\":" + n(shutdown) +
            L",\"known_acquisition_jobs\":" + n(c.Acquisition.Samples) + L",\"all_acquisitions_known\":" + b(allAcquired) +
            L",\"first_known_acquisition_ms\":" + tick(c.Acquisition.Samples != 0, c.Acquisition.First) +
            L",\"last_known_acquisition_ms\":" + tick(c.Acquisition.Samples != 0, c.Acquisition.Last) +
            L",\"first_known_queue_ms\":" + tick(c.Queue.Samples != 0, c.Queue.First) +
            L",\"known_subset_start_to_writer_end_ms\":" + duration(c.EndKnown && c.Acquisition.Samples != 0, c.Acquisition.First, c.End) +
            L",\"acquisition_to_successful_close_ms\":" + duration(ok && allAcquired, c.Acquisition.First, c.End) +
            L",\"invalid_clocks\":" + n(invalid) + L",\"protocol_errors\":" + n(c.ProtocolErrors) +
            L",\"sweep_publication_failures\":" + n(c.Totals.SweepPublications) + L",\"sweep_metadata_gaps\":" + n(c.Totals.SweepMetadata) +
            L",\"irp_unavailable\":" + n(c.Totals.IrpUnavailable) + L",\"auxiliary_publication_successes\":" + n(c.Totals.AuxiliaryPublications) +
            L",\"phases\":[" + phases + L"]}";
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
    struct Window
    {
        uint64_t First = 0, Last = 0, Samples = 0;
        void Observe(uint64_t first, uint64_t last)
        {
            if (!Samples || first < First) { First = first; }
            if (!Samples || last > Last) { Last = last; }
            ++Samples;
        }
    };
    struct CloseStep
    {
        uint64_t Started = 0, Ended = 0;
        bool StartedKnown = false, EndedKnown = false, Required = true;
        KmonPublicationResult Result;
    };
    struct CollectionData
    {
        uint64_t Start = 0, End = 0, WorkEnd = 0, ProtocolErrors = 0;
        bool StartKnown = false, EndKnown = false, WorkEndKnown = false;
        Window Queue, Acquisition;
        std::array<CloseStep, KmonCollectionClosePhases> Close;
        KmonCollectionTotals Totals;
    };
    struct Data
    {
        CollectionData Collection;
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
