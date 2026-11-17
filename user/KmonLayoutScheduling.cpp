#include "KmonLayoutScheduling.h"

std::wstring KmonLayoutQueue::Json(uint64_t now) const
{
    std::lock_guard<std::mutex> lock(Mutex);
    const auto& s = *State;
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    const auto histogram = [&](const KmonLatencyHistogram& h)
    { return L"{\"samples\":" + n(h.Samples) + L",\"p50_upper_ms\":" + n(h.UpperPercentile(50)) +
        L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) + L",\"max_ms\":" + n(h.MaximumMs) + L"}"; };
    const auto timing = [&](const Timings& t)
    {
        std::wstring outcomes;
        for (size_t i = 0; i < t.Count.Outcomes.size(); ++i)
        { if (i != 0) { outcomes += L","; } outcomes += mcpjson::Quote(KmonLayoutOutcomeName(static_cast<KmonLayoutOutcome>(i))) + L":" + n(t.Count.Outcomes[i]); }
        return L"{\"attempts\":" + n(t.Count.Attempts) + L",\"qualified_mappings\":" + n(t.Count.Qualified) +
            L",\"invalid_clocks\":" + n(t.Count.InvalidClocks) + L",\"outcomes\":{" + outcomes + L"},\"queue_wait\":" + histogram(t.QueueWait) +
            L",\"source_wait\":" + histogram(t.SourceWait) + L",\"admission_to_qualification\":" + histogram(t.AdmissionToQualification) +
            L",\"observation_to_qualification\":" + histogram(t.ObservationToQualification) + L",\"complete_service\":" + histogram(t.CompleteService) +
            L",\"incomplete_service\":" + histogram(t.FailedService) + L"}";
    };
    const auto scope = [&](const ProcessLayoutCandidate& w)
    {
        return L"{\"boot_id\":" + mcpjson::Quote(w.Identity.BootId) + L",\"pid\":" + n(w.Identity.ProcessId) +
            L",\"create_time\":" + n(w.Identity.CreateTime) + L",\"eprocess\":" + n(w.Identity.Eprocess) +
            L",\"session_id\":" + (w.Identity.SessionKnown ? n(w.Identity.SessionId) : L"null") +
            L",\"base\":" + n(w.Region.Base) + L",\"size\":" + n(w.Region.Size) + L",\"allocation_base\":" + n(w.Region.AllocationBase) +
            L",\"state\":" + n(w.Region.State) + L",\"protect\":" + n(w.Region.Protect) + L",\"allocation_protect\":" + n(w.Region.AllocationProtect) +
            L",\"type\":" + n(w.Region.Type) + L",\"role\":" + mcpjson::Quote(w.Role) + L",\"mapped_name\":" + mcpjson::Quote(w.ImageName);
    };
    size_t characters = 0, rows = 0, deferredRows = 0;
    uint64_t busy = 0, oldest = 0;
    std::wstring history, deferred;
    for (const auto& item : s.History)
    {
        const auto& r = *item;
        busy += r.Busy;
        if (r.Pending && r.Work.QueuedMs <= now) { oldest = (std::max)(oldest, now - r.Work.QueuedMs); }
        if (rows >= ScopeCapacity) { continue; }
        auto row = scope(r.Work) + L",\"id\":" + n(r.Work.SchedulingId) + L",\"first_seen_ms\":" + n(r.FirstSeen) +
            L",\"last_seen_ms\":" + n(r.LastSeen) + L",\"original_observed_ms\":" + n(r.Work.ObservedMs) +
            L",\"pending_since_ms\":" + (r.Pending ? n(r.Work.QueuedMs) : L"null") + L",\"rediscoveries\":" + n(r.Rediscoveries) +
            L",\"last_attempt_ms\":" + (r.HasAttempt ? n(r.LastAttempt) : L"null") +
            L",\"last_mapping_success_ms\":" + (r.HasSuccess ? n(r.LastSuccess) : L"null") +
            L",\"in_flight\":" + (r.Busy ? L"true" : L"false") + L",\"outcome\":" +
            (r.HasAttempt && !r.Busy ? mcpjson::Quote(KmonLayoutOutcomeName(r.Outcome)) : L"null") + L"}";
        const auto needed = row.size() + (history.empty() ? 0 : 1);
        if (needed > JsonCharacters - characters) { continue; }
        characters += needed; ++rows; if (!history.empty()) { history += L","; } history += row;
    }
    for (const auto& d : s.Deferred)
    {
        auto row = scope(d.Work) + L",\"first_deferred_ms\":" + n(d.First) + L",\"last_deferred_ms\":" + n(d.Last) +
            L",\"attempts\":" + n(d.Attempts) + L",\"reason\":" + mcpjson::Quote(KmonLayoutAdmissionName(d.Reason)) + L"}";
        const auto needed = row.size() + (deferred.empty() ? 0 : 1);
        if (needed > JsonCharacters - characters) { continue; }
        characters += needed; ++deferredRows; if (!deferred.empty()) { deferred += L","; } deferred += row;
    }
    return L"{\"schema\":\"kn.layout_verification_scheduling.v1\",\"scope\":\"bounded_resident_mapping_candidates\","
        L"\"clock_domain\":\"GetTickCount64_ms\",\"success_scope\":\"mapping_revalidation_not_byte_read_or_image_verification\","
        L"\"unseen_identical_mapping_reuse_excluded\":false,\"hard_deadline_enforced\":false,\"shutdown_in_normal_samples\":false,"
        L"\"policy\":\"process_ring_class_rotation_bounded_oldest_loan.v1\",\"pending\":" + n(s.Pending) + L",\"in_flight\":" + n(busy) +
        L",\"capacity\":" + n(Capacity) + L",\"class_capacity\":" + n(ClassCapacity) + L",\"subject_capacity\":" + n(SubjectCapacity) +
        L",\"subject_class_capacity\":" + n(SubjectClassCapacity) + L",\"oldest_queue_wait_ms\":" + n(oldest) +
        L",\"admitted\":" + n(s.Admitted) + L",\"rediscovered\":" + n(s.Coalesced) + L",\"refused\":" + n(s.Refused) +
        L",\"invalid_inputs\":" + n(s.Invalid) + L",\"debt_loans\":" + n(s.Order.DebtLoans()) +
        L",\"history_resident\":" + n(s.History.size()) + L",\"history_evicted\":" + n(s.Evicted) +
        L",\"history_omitted\":" + n(s.History.size() - rows) + L",\"deferred_resident\":" + n(s.Deferred.size()) +
        L",\"deferred_evicted\":" + n(s.DeferredEvicted) + L",\"deferred_omitted\":" + n(s.Deferred.size() - deferredRows) +
        L",\"normal\":" + timing(s.Timing[0]) + L",\"shutdown\":" + timing(s.Timing[1]) +
        L",\"records\":[" + history + L"],\"deferred\":[" + deferred + L"]}";
}
