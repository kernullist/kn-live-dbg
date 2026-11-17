#pragma once
#include "ProcessLayoutMonitor.h"
#include "KmonCaptureScheduling.h"
#include "KmonFairRing.h"
#include <memory>
#include <type_traits>

static_assert(std::is_nothrow_move_assignable_v<ProcessLayoutCandidate>, "Admission commits a prepared candidate without allocating");

enum class KmonLayoutAdmission { Queued, Rediscovered, GlobalLimit, ClassLimit, SubjectLimit, SubjectClassLimit, Busy, ExpiredOriginal, Invalid };
enum class KmonLayoutOutcome { MappingCurrent, Rejected, Expired, Fault, Count };
inline const wchar_t* KmonLayoutAdmissionName(KmonLayoutAdmission value)
{
    static const wchar_t* names[] = {L"queued", L"already_pending", L"global_limit", L"class_limit", L"subject_limit",
        L"subject_class_limit", L"in_flight", L"expired_original_pending", L"invalid_input_or_clock"};
    return names[static_cast<size_t>(value)];
}
inline const wchar_t* KmonLayoutOutcomeName(KmonLayoutOutcome value)
{
    static const wchar_t* names[] = {L"mapping_revalidated", L"mapping_or_identity_unavailable", L"expired", L"fault"};
    return names[static_cast<size_t>(value)];
}

class KmonLayoutQueue
{
public:
    static constexpr size_t Capacity = 160, ClassCapacity = 128, SubjectCapacity = 16, SubjectClassCapacity = 8;
    static constexpr size_t HistoryCapacity = 512, DeferredCapacity = 64, ScopeCapacity = 64, JsonCharacters = 65536;
    using Subject = ObservationIdentity::Key;
    struct Counts
    {
        uint64_t Attempts = 0, Qualified = 0, InvalidClocks = 0;
        std::array<uint64_t, static_cast<size_t>(KmonLayoutOutcome::Count)> Outcomes{};
    };
    struct Timings
    {
        Counts Count;
        KmonLatencyHistogram QueueWait, SourceWait, AdmissionToQualification, ObservationToQualification, CompleteService, FailedService;
    };
    static size_t Class(const ProcessLayoutCandidate& item) { return item.Role == L"layout_change" ? 0 : 1; }
    static bool SameWork(const ProcessLayoutCandidate& a, const ProcessLayoutCandidate& b)
    {
        // Compatibility through unknown assertions is not transitive. Keep
        // differing assertion sets as separate originals instead of merging
        // contradictory known identities through an unknown queued candidate.
        const auto& x = a.Identity; const auto& y = b.Identity;
        return x.HasCanonicalKey() && y.HasCanonicalKey() && x.BootId == y.BootId && x.ProcessId == y.ProcessId &&
            x.CreateTime == y.CreateTime && x.Eprocess == y.Eprocess && x.SessionKnown == y.SessionKnown &&
            (!x.SessionKnown || x.SessionId == y.SessionId) && a.ImageName == b.ImageName && Class(a) == Class(b) &&
            a.Region.Base == b.Region.Base && a.Region.Size == b.Region.Size && a.Region.SameAttributes(b.Region);
    }
    static bool Accepted(KmonLayoutAdmission result)
    { return result == KmonLayoutAdmission::Queued || result == KmonLayoutAdmission::Rediscovered; }
    KmonLayoutAdmission Admit(ProcessLayoutCandidate item, uint64_t now)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& s = *State;
        if (!item.Identity.HasCanonicalKey() || item.Identity.ProcessId <= 4 || item.Identity.BootId.size() > 128 ||
            item.Role.empty() || item.Role.size() > 128 || item.ImageName.size() > 32768 || item.Region.Size == 0 ||
            item.Region.Base > UINT64_MAX - item.Region.Size || item.ObservedMs > now || s.NextId == UINT64_MAX)
        { ++s.Invalid; return KmonLayoutAdmission::Invalid; }
        std::shared_ptr<Record> record;
        for (const auto& saved : s.History) { if (SameWork(saved->Work, item)) { record = saved; break; } }
        if (record && item.ObservedMs < record->LastSeen) { ++s.Invalid; return KmonLayoutAdmission::Invalid; }
        if (record && record->Pending)
        {
            record->LastSeen = item.ObservedMs; ++record->Rediscoveries;
            if (item.ObservedMs > record->Work.ObservedMs && now - record->Work.ObservedMs > process_layout::MaxSweepMs)
            {
                // Keep the fresh source candidate until the expired original
                // is accounted for. Accepting it as a duplicate would lose a
                // newer observation without ever attempting its validation.
                Defer(item, now, KmonLayoutAdmission::ExpiredOriginal);
                return KmonLayoutAdmission::ExpiredOriginal;
            }
            ++s.Coalesced;
            return KmonLayoutAdmission::Rediscovered; // Original bytes, timestamps and deadline stay pinned.
        }
        const auto subject = item.Identity.CanonicalKey();
        const auto lane = Class(item);
        const auto found = s.Subjects.find(subject);
        const auto own = found == s.Subjects.end() ? 0 : found->second.Lanes[0].size() + found->second.Lanes[1].size();
        const auto ownClass = found == s.Subjects.end() ? 0 : found->second.Lanes[lane].size();
        KmonLayoutAdmission reason = KmonLayoutAdmission::Queued;
        if (record && record->Busy) { reason = KmonLayoutAdmission::Busy; }
        else if (s.Pending >= Capacity) { reason = KmonLayoutAdmission::GlobalLimit; }
        else if (s.Classes[lane] >= ClassCapacity) { reason = KmonLayoutAdmission::ClassLimit; }
        else if (own >= SubjectCapacity) { reason = KmonLayoutAdmission::SubjectLimit; }
        else if (ownClass >= SubjectClassCapacity) { reason = KmonLayoutAdmission::SubjectClassLimit; }
        if (reason != KmonLayoutAdmission::Queued) { Defer(item, now, reason); return reason; }
        const bool newRecord = !record;
        if (newRecord)
        {
            if (s.History.size() >= HistoryCapacity)
            {
                const auto removable = std::find_if(s.History.begin(), s.History.end(), [](const auto& r) { return !r->Pending && !r->Busy; });
                if (removable == s.History.end()) { ++s.Invalid; return KmonLayoutAdmission::Invalid; }
                s.History.erase(removable); ++s.Evicted;
            }
            record = std::make_shared<Record>(); record->FirstSeen = item.ObservedMs;
            s.History.push_back(record);
        }
        item.QueuedMs = now; item.SchedulingId = ++s.NextId;
        try { auto& owner = s.Subjects[subject]; s.Order.Add(subject); owner.Lanes[lane].push_back(record); }
        catch (...)
        {
            const auto empty = s.Subjects.find(subject);
            if (empty != s.Subjects.end() && empty->second.Lanes[0].empty() && empty->second.Lanes[1].empty())
            { s.Subjects.erase(empty); s.Order.Remove(subject); }
            if (newRecord) { s.History.pop_back(); }
            throw;
        }
        record->Work = std::move(item); record->LastSeen = record->Work.ObservedMs;
        record->Pending = true; record->Rediscoveries = 0;
        ++s.Pending; ++s.Classes[lane]; ++s.Admitted; s.Peak = (std::max)(s.Peak, s.Pending);
        s.Deferred.erase(std::remove_if(s.Deferred.begin(), s.Deferred.end(), [&](const auto& d) { return SameWork(d.Work, record->Work); }), s.Deferred.end());
        return KmonLayoutAdmission::Queued;
    }
    bool Push(ProcessLayoutCandidate item) { return Accepted(Admit(std::move(item), GetTickCount64())); }
    bool Pop(ProcessLayoutCandidate* item, uint64_t now = GetTickCount64())
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& s = *State;
        if (s.Pending == 0) { return false; }
        std::optional<Subject> oldest;
        uint64_t oldestTime = UINT64_MAX;
        if (s.Order.MayBorrow()) for (const auto& subject : s.Order.Keys())
        {
            for (const auto& lane : s.Subjects.at(subject).Lanes)
            {
                if (!lane.empty() && lane.front()->Work.ObservedMs <= oldestTime && (!oldest || lane.front()->Work.ObservedMs < oldestTime))
                { oldest = subject; oldestTime = lane.front()->Work.ObservedMs; }
            }
        }
        const auto subject = *s.Order.Pick(oldest);
        auto& owner = s.Subjects.at(subject);
        auto lane = owner.NextClass;
        if (s.Order.LastWasLoan())
        { lane = owner.Lanes[0].empty() || (!owner.Lanes[1].empty() && owner.Lanes[1].front()->Work.ObservedMs < owner.Lanes[0].front()->Work.ObservedMs) ? 1 : 0; }
        else
        { if (owner.Lanes[lane].empty()) { lane = 1 - lane; } owner.NextClass = 1 - lane; }
        const auto record = owner.Lanes[lane].front();
        *item = record->Work; item->LastObservedMs = record->LastSeen; item->Rediscoveries = record->Rediscoveries;
        owner.Lanes[lane].pop_front();
        record->Pending = false; record->Busy = true; record->LastAttempt = now;
        record->HasAttempt = true;
        --s.Pending; --s.Classes[lane];
        if (owner.Lanes[0].empty() && owner.Lanes[1].empty()) { s.Subjects.erase(subject); s.Order.Remove(subject); }
        return true;
    }
    void Finish(const ProcessLayoutCandidate& item, uint64_t started, uint64_t ended, bool shutdown,
        KmonLayoutOutcome outcome, std::optional<uint64_t> qualified = {})
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto& s = *State;
        auto& timing = s.Timing[shutdown ? 1 : 0];
        auto& c = timing.Count;
        const auto it = std::find_if(s.History.begin(), s.History.end(), [&](const auto& r) { return r->Work.SchedulingId == item.SchedulingId && r->Busy; });
        if (it == s.History.end()) { ++s.Invalid; return; }
        auto& r = **it; r.Busy = false; r.Outcome = outcome;
        ++c.Attempts; ++c.Outcomes[static_cast<size_t>(outcome)];
        if (ended < started) { ++c.InvalidClocks; return; }
        (outcome == KmonLayoutOutcome::MappingCurrent ? timing.CompleteService : timing.FailedService).Add(ended - started);
        const bool clocks = item.ObservedMs <= item.QueuedMs && item.QueuedMs <= started;
        if (clocks) { timing.QueueWait.Add(started - item.QueuedMs); timing.SourceWait.Add(item.QueuedMs - item.ObservedMs); }
        else { ++c.InvalidClocks; }
        if (qualified)
        {
            if (*qualified < started || *qualified > ended || !clocks || (r.HasSuccess && *qualified < r.LastSuccess)) { ++c.InvalidClocks; }
            else
            {
                ++c.Qualified; r.LastSuccess = *qualified; r.HasSuccess = true;
                timing.AdmissionToQualification.Add(*qualified - item.QueuedMs);
                timing.ObservationToQualification.Add(*qualified - item.ObservedMs);
            }
        }
    }
    void Reset() { std::lock_guard<std::mutex> lock(Mutex); State = std::make_unique<Data>(); }
    size_t Size() const { std::lock_guard<std::mutex> lock(Mutex); return State->Pending; }
    size_t Peak() const { std::lock_guard<std::mutex> lock(Mutex); return State->Peak; }
    uint64_t Replacements() const { std::lock_guard<std::mutex> lock(Mutex); return State->Coalesced; }
    uint64_t Loss() const { return 0; } // Refused work stays in its source; it was never admitted then dropped.
    Counts Snapshot(bool shutdown = false) const { std::lock_guard<std::mutex> lock(Mutex); return State->Timing[shutdown ? 1 : 0].Count; }
    std::wstring Json(uint64_t now) const;
private:
    struct Record
    {
        ProcessLayoutCandidate Work;
        uint64_t FirstSeen = 0, LastSeen = 0, LastAttempt = 0, LastSuccess = 0, Rediscoveries = 0;
        bool Pending = false, Busy = false, HasAttempt = false, HasSuccess = false;
        KmonLayoutOutcome Outcome = KmonLayoutOutcome::Fault;
    };
    struct Owner { std::array<std::deque<std::shared_ptr<Record>>, 2> Lanes; size_t NextClass = 0; };
    struct DeferredRecord { ProcessLayoutCandidate Work; uint64_t First = 0, Last = 0, Attempts = 0; KmonLayoutAdmission Reason; };
    struct Data
    {
        std::map<Subject, Owner> Subjects;
        KmonFairRing<Subject> Order;
        std::deque<std::shared_ptr<Record>> History;
        std::deque<DeferredRecord> Deferred;
        std::array<Timings, 2> Timing;
        std::array<size_t, 2> Classes{};
        size_t Pending = 0, Peak = 0;
        uint64_t NextId = 0, Admitted = 0, Coalesced = 0, Refused = 0, Invalid = 0, Evicted = 0, DeferredEvicted = 0;
    };
    void Defer(const ProcessLayoutCandidate& item, uint64_t now, KmonLayoutAdmission reason)
    {
        auto& s = *State; ++s.Refused;
        for (auto& d : s.Deferred)
        { if (SameWork(d.Work, item)) { d.Last = now; ++d.Attempts; d.Reason = reason; return; } }
        if (s.Deferred.size() == DeferredCapacity) { s.Deferred.pop_front(); ++s.DeferredEvicted; }
        s.Deferred.push_back({item, now, now, 1, reason});
    }
    mutable std::mutex Mutex;
    std::unique_ptr<Data> State = std::make_unique<Data>();
};
static_assert(sizeof(KmonLayoutQueue) <= 128, "Layout timing storage must stay on the heap");
