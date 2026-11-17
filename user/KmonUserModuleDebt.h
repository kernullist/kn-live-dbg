#pragma once
#include "KmonUserInventory.h"
#include <map>
#include <new>
#include <tuple>

enum class KmonModuleResult
{
    Unattempted, Observed, IdentityUnavailable, GenerationChanged, AccessDenied,
    Unsupported, Incomplete, Cancelled, Fault, InvalidClock, Count
};

inline const wchar_t* KmonModuleResultName(KmonModuleResult result)
{
    static constexpr const wchar_t* names[] = {L"unattempted", L"observed", L"identity_unavailable",
        L"generation_changed", L"access_denied", L"unsupported", L"incomplete", L"cancelled", L"fault", L"invalid_clock"};
    static_assert(std::size(names) == static_cast<size_t>(KmonModuleResult::Count));
    return names[static_cast<size_t>(result)];
}

// Worker-owned history of one source in the current monitor session. A known
// input generation can accrue debt; only a pinned, complete module walk can
// pay it. Unknown input generations have no shared PID-only history.
class KmonUserModuleDebt
{
public:
    using Key = std::pair<uint32_t, uint64_t>;
    static constexpr size_t Capacity = 12288, ScopeLimit = 32;
    static constexpr uint64_t LoanRetryMs = 30000;
    struct Record
    {
        uint64_t FirstSeen = 0, LastSeen = 0, PendingSince = 0, LastAttempt = 0, LastSuccess = 0;
        uint64_t HintExpires = 0;
        bool Current = false, Pending = false, Attempted = false, Successful = false;
        bool LoanUnsupported = false;
        KmonModuleResult Result = KmonModuleResult::Unattempted;
        uint32_t Error = 0;
        uint64_t DebtSince() const { return Successful ? LastSuccess : FirstSeen; }
    };
    struct Attempt
    {
        Key Target;
        uint64_t Start;
        bool Valid, Pinned = false, PinConflict = false, Closed = false;
        Attempt(Key key, uint64_t start, bool valid) : Target(key), Start(start), Valid(valid) {}
        Attempt(const Attempt&) = delete;
        Attempt(Attempt&& other) noexcept : Target(other.Target), Start(other.Start), Valid(other.Valid),
            Pinned(other.Pinned), PinConflict(other.PinConflict), Closed(std::exchange(other.Closed, true)) {}
    };

    explicit KmonUserModuleDebt(size_t limit = Capacity) : Limit((std::min)(limit, Capacity)) {}
    const Record* Find(Key key) const
    {
        const auto it = Records.find(key);
        return it == Records.end() ? nullptr : &it->second;
    }
    Key Refresh(const std::vector<KmonUserTarget>& targets, const std::map<uint32_t, uint64_t>& generations,
        bool complete, uint64_t now)
    {
        if (!AdvanceClock(now)) { return {}; }
        CensusComplete = complete;
        UnknownInCensus = 0;
        // A cached suspect generation is a candidate, not evidence that the
        // other instance exited. A pinned observation can retire its siblings.
        for (const auto& t : targets)
        {
            if (!t.PinnedGeneration || !t.CreateTime) { continue; }
            for (auto it = Records.lower_bound({t.Pid, 0}); it != Records.end() && it->first.first == t.Pid;)
            {
                if (it->first.second != t.CreateTime) { it = Records.erase(it); ++Replaced; }
                else { ++it; }
            }
        }
        for (auto it = Records.begin(); it != Records.end();)
        {
            const auto found = generations.find(it->first.first);
            if (complete && found == generations.end()) { it = Records.erase(it); ++Absent; }
            else
            {
                it->second.Current = found != generations.end() && found->second == it->first.second;
                ++it;
            }
        }
        auto victim = Records.begin();
        for (const auto& t : targets)
        {
            if (!t.Interesting || t.Pid <= 4) { continue; }
            if (!t.CreateTime) { ++UnknownInCensus; continue; }
            auto* record = GetOrAdd({t.Pid, t.CreateTime}, now, victim);
            if (!record) { continue; }
            record->Current = true; record->LastSeen = now; record->HintExpires = t.SuspectExpiresMs;
            MarkPending(*record, now);
        }
        // An incomplete view cannot displace a normal selection. Capped
        // inventories already spend their reserved slot on population coverage.
        if (!complete || ++CompleteCensuses % 4 != 0) { return {}; }
        const Entry* oldest = nullptr;
        for (const auto& t : targets)
        {
            if (!t.Interesting || !t.CreateTime) { continue; }
            const auto found = Records.find({t.Pid, t.CreateTime});
            if (found == Records.end()) { continue; }
            const auto& entry = *found;
            const auto& r = entry.second;
            if (!r.Current || !r.Pending || r.LoanUnsupported) { continue; }
            if (r.Attempted && r.Result != KmonModuleResult::Observed && now - r.LastAttempt < LoanRetryMs) { continue; }
            if (!oldest || Order(entry, now) < Order(*oldest, now)) { oldest = &entry; }
        }
        if (!oldest) { return {}; }
        ++Offered;
        return oldest->first;
    }
    Attempt Begin(Key key, uint64_t now, bool loan = false)
    {
        if (key.first <= 4) { key.second = 0; }
        Attempt visit{key, now, AdvanceClock(now)};
        ++Starts;
        if (loan) { ++Entered; }
        if (visit.Valid && key.second) { MarkAttempt(key, now); }
        return visit;
    }
    void Pin(Attempt& visit, uint64_t generation, uint64_t now)
    {
        if (visit.Closed || !visit.Valid || visit.Target.first <= 4) { return; }
        if (!AdvanceClock(now)) { visit.Valid = false; return; }
        if (!generation) { visit.Pinned = false; return; }
        if (visit.Target.second && visit.Target.second != generation) { visit.PinConflict = true; return; }
        if (!visit.Target.second)
        {
            visit.Target.second = generation;
            MarkAttempt(visit.Target, now, true);
            ++LatePins;
        }
        visit.Pinned = true;
    }
    void ConcludeWalk(Attempt& visit, uint64_t after, bool complete, uint32_t error, bool stopping, uint64_t now)
    {
        KmonModuleResult result;
        if (visit.PinConflict) { result = KmonModuleResult::GenerationChanged; }
        else if (!visit.Pinned || !after) { result = KmonModuleResult::IdentityUnavailable; }
        else if (after != visit.Target.second) { result = KmonModuleResult::GenerationChanged; }
        else if (stopping) { result = KmonModuleResult::Cancelled; }
        else if (complete && error == ERROR_NO_MORE_FILES) { result = KmonModuleResult::Observed; }
        else if (error == ERROR_ACCESS_DENIED) { result = KmonModuleResult::AccessDenied; }
        else if (error == ERROR_NOT_SUPPORTED || error == ERROR_CALL_NOT_IMPLEMENTED) { result = KmonModuleResult::Unsupported; }
        else { result = KmonModuleResult::Incomplete; }
        if (result == KmonModuleResult::Observed || (result == KmonModuleResult::Cancelled && error != ERROR_CANCELLED)) { error = 0; }
        Finish(visit, result, now, error);
    }
    void Fail(Attempt& visit, KmonModuleResult reason, uint64_t now, uint32_t error = 0)
    {
        if (reason == KmonModuleResult::Observed || reason == KmonModuleResult::Unattempted || reason == KmonModuleResult::Count)
        { reason = KmonModuleResult::Fault; }
        Finish(visit, reason, now, error);
    }
    std::wstring Json(uint64_t now) const;

private:
    using History = std::map<Key, Record>;
    using Entry = History::value_type;
    History Records;
    size_t Limit;
    uint64_t Clock = 0, ClockErrors = 0, CompleteCensuses = 0, UnknownInCensus = 0;
    uint64_t Evicted = 0, Refused = 0, Absent = 0, Replaced = 0, Offered = 0, Entered = 0;
    uint64_t Starts = 0, LatePins = 0, UntrackedEnds = 0, AllocationFailures = 0;
    Key LastEvicted{}, LastRefused{};
    bool CensusComplete = false;
    std::array<uint64_t, static_cast<size_t>(KmonModuleResult::Count)> Outcomes{};
    KmonLatencyHistogram SuccessfulService, FailedService, CancelledService, FirstObservation, Revisit;
    bool AdvanceClock(uint64_t now)
    {
        if (now < Clock) { ++ClockErrors; return false; }
        Clock = now;
        return true;
    }
    static auto Order(const Entry& item, uint64_t now)
        -> std::tuple<uint64_t, uint64_t, bool, uint64_t, Key>
    {
        const auto& r = item.second;
        // The hint's own expiry is known. The process's future lifetime is not.
        const auto expires = r.HintExpires > now ? r.HintExpires : UINT64_MAX;
        return {r.DebtSince(), expires, r.Attempted, r.LastAttempt, item.first};
    }
    static void MarkPending(Record& r, uint64_t now)
    {
        if (!r.Pending) { r.PendingSince = now; r.Pending = true; }
    }
    Record* GetOrAdd(Key key, uint64_t now, History::iterator& victim)
    {
        const auto found = Records.find(key);
        if (found != Records.end()) { return &found->second; }
        if (Records.size() >= Limit)
        {
            while (victim != Records.end() && victim->second.Current) { ++victim; }
            if (victim == Records.end()) { LastRefused = key; ++Refused; return nullptr; }
        }
        Record fresh;
        fresh.FirstSeen = fresh.LastSeen = now;
        // Allocate before evicting, so allocation failure preserves history.
        History::iterator inserted;
        try { inserted = Records.emplace(key, fresh).first; }
        catch (const std::bad_alloc&) { ++AllocationFailures; LastRefused = key; return nullptr; }
        if (Records.size() > Limit)
        {
            LastEvicted = victim->first; victim = Records.erase(victim); ++Evicted;
        }
        return &inserted->second;
    }
    void MarkAttempt(Key key, uint64_t now, bool latePin = false)
    {
        auto victim = Records.begin();
        if (auto* r = GetOrAdd(key, now, victim))
        {
            MarkPending(*r, now); r->Attempted = true; r->LastAttempt = now;
            if (latePin) { r->LastSeen = now; }
        }
    }
    void Finish(Attempt& visit, KmonModuleResult result, uint64_t now, uint32_t error)
    {
        if (visit.Closed) { return; }
        visit.Closed = true;
        const bool clockOk = AdvanceClock(now);
        if (!visit.Valid || !clockOk) { result = KmonModuleResult::InvalidClock; }
        ++Outcomes[static_cast<size_t>(result)];
        const bool observed = result == KmonModuleResult::Observed;
        if (result != KmonModuleResult::InvalidClock)
        {
            auto& service = observed ? SuccessfulService :
                result == KmonModuleResult::Cancelled ? CancelledService : FailedService;
            service.Add(now - visit.Start);
        }
        auto it = Records.find(visit.Target);
        if (it == Records.end()) { ++UntrackedEnds; return; }
        auto& r = it->second;
        r.Result = result; r.Error = error;
        if (result == KmonModuleResult::Unsupported) { r.LoanUnsupported = true; }
        if (observed)
        {
            r.LoanUnsupported = false;
            if (r.Successful) { Revisit.Add(now - r.LastSuccess); }
            else { FirstObservation.Add(now - r.FirstSeen); }
            r.Successful = true; r.LastSuccess = now; r.Pending = false;
        }
    }
};

inline std::wstring KmonUserModuleDebt::Json(uint64_t now) const
{
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    const auto maybe = [&](bool known, uint64_t value) { return known ? n(value) : std::wstring(L"null"); };
    const auto keyJson = [&](Key key) -> std::wstring
    {
        return key.second ? L"{\"pid\":" + n(key.first) + L",\"generation\":" + n(key.second) + L"}" : L"null";
    };
    const auto hist = [&](const KmonLatencyHistogram& h)
    {
        return L"{\"samples\":" + n(h.Samples) + L",\"max_ms\":" + n(h.MaximumMs) +
            L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) + L"}";
    };
    const bool validTime = now >= Clock;
    const auto earlier = [&](const Entry* a, const Entry* b)
    {
        if (a->second.Current != b->second.Current) { return a->second.Current; }
        if (a->second.Pending != b->second.Pending) { return a->second.Pending; }
        return Order(*a, now) < Order(*b, now);
    };
    std::vector<const Entry*> sample;
    sample.reserve((std::min)(ScopeLimit, Records.size()));
    uint64_t current = 0, pending = 0;
    for (const auto& item : Records)
    {
        current += item.second.Current;
        pending += item.second.Current && item.second.Pending;
        if (sample.size() < ScopeLimit)
        {
            sample.push_back(&item); std::push_heap(sample.begin(), sample.end(), earlier);
        }
        else if (earlier(&item, sample.front()))
        {
            std::pop_heap(sample.begin(), sample.end(), earlier);
            sample.back() = &item;
            std::push_heap(sample.begin(), sample.end(), earlier);
        }
    }
    std::sort_heap(sample.begin(), sample.end(), earlier);
    std::wstring scopes, outcomes;
    for (const auto* item : sample)
    {
        if (!scopes.empty()) { scopes += L","; }
        const auto& r = item->second;
        const wchar_t* expiry = !r.HintExpires || !validTime ? L"unknown" :
            r.HintExpires > now ? L"suspect_hint_deadline" : L"suspect_hint_expired";
        scopes += L"{\"key\":" + keyJson(item->first) +
            L",\"in_latest_inventory\":" + (r.Current ? L"true" : L"false") + L",\"first_seen_ms\":" + n(r.FirstSeen) +
            L",\"last_seen_ms\":" + n(r.LastSeen) + L",\"pending_since_ms\":" + maybe(r.Pending, r.PendingSince) +
            L",\"last_attempt_ms\":" + maybe(r.Attempted, r.LastAttempt) + L",\"last_success_ms\":" + maybe(r.Successful, r.LastSuccess) +
            L",\"remaining_work\":" + mcpjson::Quote(r.Pending ? L"complete_module_inventory" : L"none") +
            L",\"expiry_risk\":" + mcpjson::Quote(expiry) + L",\"suspect_hint_expires_ms\":" + maybe(r.HintExpires != 0, r.HintExpires) +
            L",\"failure_class\":" + mcpjson::Quote(r.Result == KmonModuleResult::Observed ? L"none" : KmonModuleResultName(r.Result)) +
            L",\"loan_suppressed_unsupported\":" + (r.LoanUnsupported ? L"true" : L"false") +
            L",\"win32_error\":" + maybe(r.Error != 0, r.Error) +
            L",\"observation_age_ms\":" + maybe(validTime && now >= r.DebtSince(), now - (std::min)(now, r.DebtSince())) + L"}";
    }
    for (size_t i = 1; i < Outcomes.size(); ++i)
    {
        if (!outcomes.empty()) { outcomes += L","; }
        outcomes += mcpjson::Quote(KmonModuleResultName(static_cast<KmonModuleResult>(i))) + L":" + n(Outcomes[i]);
    }
    return L"{\"schema\":\"kn.user_module_observation_debt.v1\",\"source\":\"toolhelp_process_modules\","
        L"\"scope\":\"monitor_session_retained_generations\",\"clock_domain\":\"GetTickCount64_ms\","
        L"\"first_seen_origin\":\"inventory_admission_or_attempt_binding\",\"whole_target_success_reported\":false,"
        L"\"history_limit\":" + n(Limit) + L",\"retained\":" + n(Records.size()) + L",\"current\":" + n(current) +
        L",\"current_pending\":" + n(pending) + L",\"unknown_inventory_generations\":" + n(UnknownInCensus) +
        L",\"inventory_complete\":" + (CensusComplete ? L"true" : L"false") + L",\"retired_absent\":" + n(Absent) +
        L",\"retired_replaced\":" + n(Replaced) + L",\"capacity_evictions\":" + n(Evicted) +
        L",\"last_evicted\":" + keyJson(LastEvicted) + L",\"capacity_refusals\":" + n(Refused) +
        L",\"history_allocation_failures\":" + n(AllocationFailures) + L",\"last_refused\":" + keyJson(LastRefused) +
        L",\"complete_censuses\":" + n(CompleteCensuses) + L",\"loan_offers\":" + n(Offered) +
        L",\"loan_entries\":" + n(Entered) + L",\"loan_retry_ms\":" + n(LoanRetryMs) +
        L",\"attempts\":" + n(Starts) + L",\"late_pins\":" + n(LatePins) + L",\"untracked_outcomes\":" + n(UntrackedEnds) +
        L",\"invalid_clock_samples\":" + n(ClockErrors) + L",\"outcomes\":{" + outcomes + L"},\"observed_service\":" + hist(SuccessfulService) +
        L",\"failed_service\":" + hist(FailedService) + L",\"cancelled_service\":" + hist(CancelledService) +
        L",\"first_observation_wait\":" + hist(FirstObservation) + L",\"successful_revisit\":" + hist(Revisit) +
        L",\"scopes_omitted\":" + n(Records.size() - sample.size()) + L",\"scopes\":[" + scopes + L"]}";
}
