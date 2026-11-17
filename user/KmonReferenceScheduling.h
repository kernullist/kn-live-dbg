#pragma once

#include "ObservationModel.h"
#include "KmonCaptureScheduling.h"
#include <deque>
#include <memory>
#include <set>

struct KmonExecutionReferenceWork
{
    uint64_t Target = 0, Slot = 0, ObservedAt = 0, ObservedMs = 0;
    ObservationIdentity Identity;
    std::wstring Role;
    std::vector<ObservationAnchor> Anchors;
    uint64_t ExpectedPeb = 0;
};

enum class KmonReferenceAdmission { Queued, Duplicate, Cooldown, GlobalLimit, SubjectLimit, SubjectRoleLimit, RoleLimit, Invalid };
enum class KmonReferenceOutcome { None, Observed, IdentityUnavailable, ArchitectureUnavailable, MappingUnavailable,
    Inconsistent, ReadUnavailable, Partial, Expired, Cancelled, Fault, InvalidClock, Count };

inline const wchar_t* KmonReferenceOutcomeName(KmonReferenceOutcome value)
{
    switch (value)
    {
    case KmonReferenceOutcome::None: return L"not_attempted";
    case KmonReferenceOutcome::Observed: return L"observed";
    case KmonReferenceOutcome::IdentityUnavailable: return L"identity_unavailable";
    case KmonReferenceOutcome::ArchitectureUnavailable: return L"architecture_unavailable";
    case KmonReferenceOutcome::MappingUnavailable: return L"mapping_unavailable";
    case KmonReferenceOutcome::Inconsistent: return L"changed_or_unreadable";
    case KmonReferenceOutcome::ReadUnavailable: return L"read_unavailable";
    case KmonReferenceOutcome::Partial: return L"partial_path";
    case KmonReferenceOutcome::Expired: return L"expired";
    case KmonReferenceOutcome::Cancelled: return L"cancelled";
    case KmonReferenceOutcome::InvalidClock: return L"invalid_clock";
    default: return L"fault";
    }
}

inline const wchar_t* KmonReferenceAdmissionName(KmonReferenceAdmission value)
{
    switch (value)
    {
    case KmonReferenceAdmission::Queued: return L"queued";
    case KmonReferenceAdmission::Duplicate: return L"already_pending";
    case KmonReferenceAdmission::Cooldown: return L"attempt_cooldown";
    case KmonReferenceAdmission::GlobalLimit: return L"global_limit";
    case KmonReferenceAdmission::SubjectLimit: return L"subject_limit";
    case KmonReferenceAdmission::SubjectRoleLimit: return L"subject_role_limit";
    case KmonReferenceAdmission::RoleLimit: return L"role_limit";
    default: return L"invalid_input";
    }
}

// Owned by the analysis thread; after it joins, owned by the shutdown drain.
// Limits are admission policy, not measured deadlines or full-source coverage.
class KmonReferenceQueue
{
public:
    static constexpr size_t Capacity = 1024, SubjectCapacity = 64, SubjectRoleCapacity = 16, RoleCapacity = 256;
    static constexpr size_t HistoryCapacity = 16384, DeferredCapacity = 128, JsonScopeCapacity = 64;
    static constexpr uint64_t ExpiryMs = 30000, AttemptCooldownMs = 10000;
    using Key = std::tuple<std::wstring, uint32_t, uint64_t, std::wstring, uint64_t, uint64_t>;
    using KeyView = std::tuple<const std::wstring&, uint32_t, uint64_t, const std::wstring&, uint64_t, uint64_t>;
    struct Record
    {
        uint64_t FirstSeen = 0, LastSeen = 0, PendingSince = 0, LastAttempt = 0, LastSuccess = 0;
        uint64_t Rediscoveries = 0;
        bool Pending = false, Busy = false, HasAttempt = false, HasSuccess = false;
        KmonReferenceOutcome Outcome = KmonReferenceOutcome::None;
    };
    struct Timings
    {
        KmonLatencyHistogram QueueWait, SuccessService, FailedService;
        std::array<uint64_t, static_cast<size_t>(KmonReferenceOutcome::Count)> Outcomes{};
    };

    static Key WorkKey(const KmonExecutionReferenceWork& work)
    {
        return {work.Identity.BootId, work.Identity.ProcessId, work.Identity.ProcessId == 0 ? 0 : work.Identity.CreateTime,
            work.Role, work.Target, work.Slot};
    }
    static KeyView WorkKeyView(const KmonExecutionReferenceWork& work)
    {
        return {work.Identity.BootId, work.Identity.ProcessId, work.Identity.ProcessId == 0 ? 0 : work.Identity.CreateTime,
            work.Role, work.Target, work.Slot};
    }
    size_t size() const { return Entries.size(); }
    bool empty() const { return Entries.empty(); }
    void clear() { *this = {}; }
    const Timings& Normal() const { return Timing->Normal; }
    const Timings& Shutdown() const { return Timing->Shutdown; }
    const Record* Find(const KmonExecutionReferenceWork& work) const
    {
        const auto it = History.find(WorkKeyView(work));
        return it == History.end() ? nullptr : &it->second;
    }
    uint64_t OldestPendingMs() const
    {
        uint64_t oldest = UINT64_MAX;
        for (const auto& entry : Entries) { oldest = (std::min)(oldest, entry.Work.ObservedMs); }
        return empty() ? 0 : oldest;
    }

    KmonReferenceAdmission Admit(KmonExecutionReferenceWork work)
    {
        if (work.Anchors.size() > 8) { Increment(InvalidInputs); return KmonReferenceAdmission::Invalid; }
        size_t anchorBytes = 0;
        for (const auto& anchor : work.Anchors)
        {
            if (anchor.Bytes.size() > 4096 || anchor.Address > UINT64_MAX - anchor.Bytes.size())
            { Increment(InvalidInputs); return KmonReferenceAdmission::Invalid; }
            anchorBytes += anchor.Bytes.size();
        }
        if (anchorBytes > 32768 || work.Role.empty() || work.Role.size() > 128 ||
            work.Identity.BootId.empty() || work.Identity.BootId.size() > 128)
        { Increment(InvalidInputs); return KmonReferenceAdmission::Invalid; }
        const auto key = WorkKey(work);
        auto history = History.find(key);
        if (history != History.end())
        {
            auto& record = history->second;
            if (work.ObservedMs < record.LastSeen) { Increment(InvalidClocks); return KmonReferenceAdmission::Invalid; }
            record.LastSeen = work.ObservedMs;
            Increment(record.Rediscoveries);
            if (record.Busy) { Increment(Duplicates); return KmonReferenceAdmission::Duplicate; }
            if (record.HasAttempt && (work.ObservedMs < record.LastAttempt || work.ObservedMs - record.LastAttempt < AttemptCooldownMs))
            { Increment(Cooldowns); return KmonReferenceAdmission::Cooldown; }
        }
        size_t subjectCount = 0, subjectRoleCount = 0, roleCount = 0;
        uint64_t subjectTicket = 0, roleTicket = 0;
        RebaseTicketsIfNeeded();
        for (const auto& entry : Entries)
        {
            if (entry.Work.Role == work.Role) { ++roleCount; }
            if (entry.Work.Identity.CanonicalKey() == work.Identity.CanonicalKey())
            {
                ++subjectCount;
                subjectTicket = entry.SubjectTicket;
                if (entry.Work.Role == work.Role) { ++subjectRoleCount; roleTicket = entry.RoleTicket; }
            }
        }
        auto result = KmonReferenceAdmission::Queued;
        if (size() >= Capacity) { result = KmonReferenceAdmission::GlobalLimit; }
        else if (subjectCount >= SubjectCapacity) { result = KmonReferenceAdmission::SubjectLimit; }
        else if (subjectRoleCount >= SubjectRoleCapacity) { result = KmonReferenceAdmission::SubjectRoleLimit; }
        else if (roleCount >= RoleCapacity) { result = KmonReferenceAdmission::RoleLimit; }
        if (result != KmonReferenceAdmission::Queued) { Defer(key, work.ObservedMs, result); return result; }

        // Allocate the queue entry before marking its history busy. Failure
        // leaves existing work/anchors intact and no phantom pending key.
        const bool newHistory = history == History.end();
        if (newHistory)
        {
            if (History.size() >= HistoryCapacity)
            {
                auto oldest = History.end();
                for (auto it = History.begin(); it != History.end(); ++it)
                {
                    if (!it->second.Busy && (oldest == History.end() || it->second.LastSeen < oldest->second.LastSeen)) { oldest = it; }
                }
                if (oldest == History.end()) { Defer(key, work.ObservedMs, KmonReferenceAdmission::GlobalLimit); return KmonReferenceAdmission::GlobalLimit; }
                History.erase(oldest);
                Increment(HistoryEvicted);
            }
            Record record;
            record.FirstSeen = record.LastSeen = work.ObservedMs;
            history = History.emplace(key, record).first;
        }
        if (subjectTicket == 0) { subjectTicket = NextTicket++; }
        if (roleTicket == 0) { roleTicket = NextTicket++; }
        try { Entries.push_back({std::move(work), subjectTicket, roleTicket}); }
        catch (...) { if (newHistory) { History.erase(history); } throw; }
        auto& record = history->second;
        record.PendingSince = Entries.back().Work.ObservedMs;
        record.Pending = record.Busy = true;
        Increment(Admitted);
        return result;
    }

    KmonExecutionReferenceWork Pop()
    {
        RebaseTicketsIfNeeded();
        auto selected = std::min_element(Entries.begin(), Entries.end(), [](const auto& a, const auto& b)
        { return std::tie(a.SubjectTicket, a.RoleTicket) < std::tie(b.SubjectTicket, b.RoleTicket); });
        if (selected == Entries.end()) { return {}; }
        auto work = std::move(selected->Work);
        const auto subjectTicket = selected->SubjectTicket, roleTicket = selected->RoleTicket;
        Entries.erase(selected);
        const auto newSubject = NextTicket++, newRole = NextTicket++;
        for (auto& entry : Entries)
        {
            if (entry.SubjectTicket == subjectTicket)
            {
                entry.SubjectTicket = newSubject;
                if (entry.RoleTicket == roleTicket) { entry.RoleTicket = newRole; }
            }
        }
        History.find(WorkKeyView(work))->second.Pending = false;
        return work;
    }

    // Call only once for each popped work item, before identity qualification.
    bool Start(const KmonExecutionReferenceWork& work, uint64_t now)
    {
        auto& record = History.find(WorkKeyView(work))->second;
        if (now < work.ObservedMs || now - work.ObservedMs > ExpiryMs) { return false; }
        record.LastAttempt = now;
        record.HasAttempt = true;
        return true;
    }

    void Finish(const KmonExecutionReferenceWork& work, uint64_t started, uint64_t ended,
        KmonReferenceOutcome outcome, bool shutdown)
    {
        const auto found = History.find(WorkKeyView(work));
        if (found == History.end() || !found->second.Busy || found->second.Pending) { return; }
        auto& record = found->second;
        auto& stats = shutdown ? Timing->Shutdown : Timing->Normal;
        const bool validClock = work.ObservedMs <= started && started <= ended;
        if (!validClock) { outcome = KmonReferenceOutcome::InvalidClock; Increment(InvalidClocks); }
        record.Busy = false;
        record.Outcome = outcome;
        Increment(stats.Outcomes.at(static_cast<size_t>(outcome)));
        if (validClock)
        {
            stats.QueueWait.Add(started - work.ObservedMs);
            if (outcome != KmonReferenceOutcome::Expired && outcome != KmonReferenceOutcome::Cancelled)
            {
                (outcome == KmonReferenceOutcome::Observed ? stats.SuccessService : stats.FailedService).Add(ended - started);
            }
        }
        if (outcome == KmonReferenceOutcome::Observed)
        {
            record.LastSuccess = ended;
            record.HasSuccess = true;
        }
    }

    std::wstring Json(uint64_t now) const
    {
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        const auto histogram = [&](const KmonLatencyHistogram& h)
        { return L"{\"samples\":" + n(h.Samples) + L",\"p50_upper_ms\":" + n(h.UpperPercentile(50)) +
            L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) + L",\"max_ms\":" + n(h.MaximumMs) + L"}"; };
        const auto timings = [&](const Timings& stats)
        {
            std::wstring values;
            for (size_t i = 1; i < stats.Outcomes.size(); ++i)
            { if (!values.empty()) { values += L","; } values += mcpjson::Quote(KmonReferenceOutcomeName(static_cast<KmonReferenceOutcome>(i))) + L":" + n(stats.Outcomes[i]); }
            return L"{\"outcomes\":{" + values + L"},\"queue_wait\":" + histogram(stats.QueueWait) +
                L",\"success_service\":" + histogram(stats.SuccessService) + L",\"failed_service\":" + histogram(stats.FailedService) + L"}";
        };
        const auto scope = [&](const Key& key)
        { return L"\"boot_id\":" + mcpjson::Quote(std::get<0>(key)) + L",\"pid\":" + n(std::get<1>(key)) +
            L",\"create_time\":" + n(std::get<2>(key)) + L",\"role\":" + mcpjson::Quote(std::get<3>(key)) +
            L",\"target\":" + n(std::get<4>(key)) + L",\"slot\":" + n(std::get<5>(key)); };
        std::vector<std::pair<const Key*, const Record*>> ordered;
        uint64_t debt = 0, snapshotInvalid = 0, expiryRisk = 0;
        for (const auto& item : History)
        {
            ordered.emplace_back(&item.first, &item.second);
            const auto since = item.second.HasSuccess ? item.second.LastSuccess : item.second.FirstSeen;
            if (since <= now) { debt = (std::max)(debt, now - since); } else { ++snapshotInvalid; }
            if (item.second.Pending && item.second.PendingSince <= now && now - item.second.PendingSince > ExpiryMs) { ++expiryRisk; }
        }
        std::stable_sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b)
        {
            if (a.second->Busy != b.second->Busy) { return a.second->Busy; }
            const auto age = [](const Record* record) { return record->Busy ? record->PendingSince : record->LastSeen; };
            return age(a.second) < age(b.second);
        });
        std::wstring scopes;
        for (size_t i = 0; i < (std::min)(ordered.size(), JsonScopeCapacity); ++i)
        {
            const auto& record = *ordered[i].second;
            if (!scopes.empty()) { scopes += L","; }
            scopes += L"{" + scope(*ordered[i].first) + L",\"first_seen_ms\":" + n(record.FirstSeen) + L",\"last_seen_ms\":" + n(record.LastSeen) +
                L",\"pending_since_ms\":" + (record.Busy ? n(record.PendingSince) : L"null") +
                L",\"last_attempt_ms\":" + (record.HasAttempt ? n(record.LastAttempt) : L"null") +
                L",\"last_success_ms\":" + (record.HasSuccess ? n(record.LastSuccess) : L"null") +
                L",\"outcome\":" + mcpjson::Quote(KmonReferenceOutcomeName(record.Outcome)) + L",\"rediscoveries\":" + n(record.Rediscoveries) + L"}";
        }
        std::wstring deferred;
        for (const auto& item : Deferred)
        {
            if (!deferred.empty()) { deferred += L","; }
            deferred += L"{" + scope(item.Scope) + L",\"reason\":" + mcpjson::Quote(KmonReferenceAdmissionName(item.Reason)) +
                L",\"first_ms\":" + n(item.First) + L",\"last_ms\":" + n(item.Last) + L",\"attempts\":" + n(item.Attempts) + L"}";
        }
        const auto oldest = OldestPendingMs();
        if (!empty() && oldest > now) { ++snapshotInvalid; }
        return L"{\"schema\":\"kn.reference_scheduling.v1\",\"scope\":\"execution_reference_queue\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"policy\":\"subject_role_round_robin.v1\","
            L"\"debt_scope\":\"resident_admitted_keys\",\"success_scope\":\"consistent_bounded_static_check_not_execution_or_full_path\","
            L"\"deferred_rediscovery_guaranteed\":false,\"hard_deadline_enforced\":false,\"shutdown_in_normal_samples\":false,"
            L"\"percentiles\":\"log2_bucket_upper_bounds\",\"snapshot_ms\":" + n(now) + L",\"capacity\":" + n(Capacity) +
            L",\"subject_capacity\":" + n(SubjectCapacity) + L",\"subject_role_capacity\":" + n(SubjectRoleCapacity) + L",\"role_capacity\":" + n(RoleCapacity) +
            L",\"pending\":" + n(size()) + L",\"oldest_pending_ms\":" + (empty() ? L"null" : n(oldest)) +
            L",\"expiry_ms\":" + n(ExpiryMs) + L",\"expired_pending\":" + n(expiryRisk) + L",\"attempt_cooldown_ms\":" + n(AttemptCooldownMs) +
            L",\"oldest_wait_ms\":" + n(!empty() && oldest <= now ? now - oldest : 0) +
            L",\"max_resident_observation_debt_ms\":" + n(debt) + L",\"admitted\":" + n(Admitted) +
            L",\"duplicates\":" + n(Duplicates) + L",\"cooldowns\":" + n(Cooldowns) + L",\"deferred_attempts\":" + n(DeferredAttempts) +
            L",\"deferred_scopes\":[" + deferred + L"],\"omitted_deferred_attempts\":" + n(OmittedDeferred) +
            L",\"history_resident\":" + n(History.size()) + L",\"history_evicted\":" + n(HistoryEvicted) +
            L",\"scopes_omitted\":" + n(ordered.size() > JsonScopeCapacity ? ordered.size() - JsonScopeCapacity : 0) +
            L",\"scopes\":[" + scopes + L"],\"invalid_inputs\":" + n(InvalidInputs) + L",\"invalid_clocks\":" + n(InvalidClocks) +
            L",\"snapshot_invalid_clocks\":" + n(snapshotInvalid) + L",\"normal\":" + timings(Normal()) + L",\"shutdown\":" + timings(Shutdown()) + L"}";
    }

private:
    struct Entry { KmonExecutionReferenceWork Work; uint64_t SubjectTicket = 0, RoleTicket = 0; };
    struct DeferredRecord { Key Scope; KmonReferenceAdmission Reason; uint64_t First = 0, Last = 0, Attempts = 0; };
    std::deque<Entry> Entries;
    std::map<Key, Record, std::less<>> History;
    std::vector<DeferredRecord> Deferred;
    struct TimingPair { Timings Normal, Shutdown; };
    // Six fixed histograms must not enlarge every enclosing monitor's stack
    // frame. Allocate once, before any no-allocation completion guard runs.
    std::unique_ptr<TimingPair> Timing = std::make_unique<TimingPair>();
    uint64_t NextTicket = 1, Admitted = 0, Duplicates = 0, Cooldowns = 0, DeferredAttempts = 0;
    uint64_t OmittedDeferred = 0, HistoryEvicted = 0, InvalidInputs = 0, InvalidClocks = 0;
    static void Increment(uint64_t& value) { if (value != UINT64_MAX) { ++value; } }
    void Defer(const Key& key, uint64_t now, KmonReferenceAdmission reason)
    {
        Increment(DeferredAttempts);
        for (auto& item : Deferred)
        {
            if (item.Scope == key && item.Reason == reason) { item.Last = (std::max)(item.Last, now); Increment(item.Attempts); return; }
        }
        if (Deferred.size() < DeferredCapacity) { Deferred.push_back({key, reason, now, now, 1}); }
        else { Increment(OmittedDeferred); }
    }
    void RebaseTicketsIfNeeded()
    {
        if (NextTicket < UINT64_MAX - 4) { return; }
        std::set<uint64_t> ordered;
        for (const auto& entry : Entries) { ordered.insert(entry.SubjectTicket); ordered.insert(entry.RoleTicket); }
        std::map<uint64_t, uint64_t> ranks;
        uint64_t next = 1;
        for (const auto value : ordered) { ranks.emplace(value, next++); }
        for (auto& entry : Entries) { entry.SubjectTicket = ranks.at(entry.SubjectTicket); entry.RoleTicket = ranks.at(entry.RoleTicket); }
        NextTicket = next;
    }
};
static_assert(sizeof(KmonReferenceQueue) <= 256, "Keep reference queue statistics off the caller stack");
