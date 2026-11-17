#pragma once

#include "KmonCaptureScheduling.h"
#include "ExecutableImageVerifier.h"
#include <memory>

constexpr uint64_t KmonImageTurnBudgetMs = 25;

enum class KmonImageAttemptOutcome { None, Observed, Gaps, ReferenceUnavailable, Deferred, NotAdmitted, Fault, InvalidClock, ReferencePending, Count };
inline const wchar_t* KmonImageAttemptOutcomeName(KmonImageAttemptOutcome outcome)
{
    switch (outcome)
    {
    case KmonImageAttemptOutcome::None: return L"not_attempted";
    case KmonImageAttemptOutcome::Observed: return L"fully_compared_slice";
    case KmonImageAttemptOutcome::Gaps: return L"comparison_gaps";
    case KmonImageAttemptOutcome::ReferenceUnavailable: return L"reference_unavailable";
    case KmonImageAttemptOutcome::ReferencePending: return L"reference_preparation_pending";
    case KmonImageAttemptOutcome::Deferred: return L"not_due";
    case KmonImageAttemptOutcome::NotAdmitted: return L"not_admitted";
    case KmonImageAttemptOutcome::InvalidClock: return L"invalid_clock";
    default: return L"fault";
    }
}

// One resident cache key, not an assertion of continuous mapping lifetime.
struct KmonImageObservationDebt
{
    uint64_t FirstSeen = 0, LastSeen = 0, PendingSince = 0, LastAttempt = 0, LastSuccess = 0;
    uint64_t FirstParserAttempt = 0, FirstExactRead = 0, FirstTraversal = 0, LastTraversal = 0;
    uint64_t FirstGapFree = 0, LastGapFree = 0, LastSuccessEpisode = 0, LastGapFreeEpisode = 0;
    bool Seen = false, Pending = false, Attempted = false, Successful = false;
    bool ParserAttempted = false, ExactRead = false, Traversed = false, GapFree = false;
    KmonImageAttemptOutcome Outcome = KmonImageAttemptOutcome::None;

    bool Discover(uint64_t now)
    {
        if (!Seen) { FirstSeen = LastSeen = PendingSince = now; Seen = Pending = true; return true; }
        if (now < LastSeen) { return false; }
        LastSeen = now;
        return true;
    }
    bool Begin(uint64_t now)
    {
        if (!Seen || now < LastSeen || (Attempted && now < LastAttempt) || (Successful && now < LastSuccess))
        { Outcome = KmonImageAttemptOutcome::InvalidClock; return false; }
        LastAttempt = now;
        Attempted = true;
        if (!Pending) { Pending = true; PendingSince = now; }
        return true;
    }
    bool Finish(uint64_t now, KmonImageAttemptOutcome outcome, bool traversal, bool gapFree, uint64_t episode)
    {
        if (!Attempted || now < LastAttempt) { Outcome = KmonImageAttemptOutcome::InvalidClock; return false; }
        Outcome = outcome;
        if (outcome == KmonImageAttemptOutcome::Observed)
        { LastSuccess = now; LastSuccessEpisode = episode; Successful = true; }
        if (traversal && (outcome == KmonImageAttemptOutcome::Observed || outcome == KmonImageAttemptOutcome::Gaps))
        {
            if (!Traversed) { FirstTraversal = now; }
            LastTraversal = now; Traversed = true;
        }
        if (gapFree && traversal && outcome == KmonImageAttemptOutcome::Observed)
        {
            if (!GapFree) { FirstGapFree = now; }
            LastGapFree = now; LastGapFreeEpisode = episode; GapFree = true; Pending = false;
        }
        return true;
    }
    // Failure/rediscovery never renew this observation timestamp. Selection
    // grants debt priority only on bounded turns alongside ordinary rotation.
    uint64_t DebtSince() const { return GapFree ? LastGapFree : FirstSeen; }
    std::wstring Json(uint64_t now) const
    {
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        const auto time = [&](bool known, uint64_t value) { return known ? n(value) : L"null"; };
        return L"{\"first_seen_ms\":" + time(Seen, FirstSeen) + L",\"last_seen_ms\":" + time(Seen, LastSeen) +
            L",\"pending_since_ms\":" + time(Pending, PendingSince) + L",\"last_attempt_ms\":" + time(Attempted, LastAttempt) +
            L",\"last_successful_slice_ms\":" + time(Successful, LastSuccess) + L",\"last_success_episode\":" + time(Successful, LastSuccessEpisode) +
            L",\"first_parser_attempt_ms\":" + time(ParserAttempted, FirstParserAttempt) + L",\"first_exact_read_ms\":" + time(ExactRead, FirstExactRead) +
            L",\"first_traversal_ms\":" + time(Traversed, FirstTraversal) + L",\"last_traversal_ms\":" + time(Traversed, LastTraversal) +
            L",\"first_gap_free_traversal_ms\":" + time(GapFree, FirstGapFree) + L",\"last_gap_free_traversal_ms\":" + time(GapFree, LastGapFree) +
            L",\"last_gap_free_episode\":" + time(GapFree, LastGapFreeEpisode) +
            L",\"observation_debt_ms\":" + time(Seen && DebtSince() <= now, now >= DebtSince() ? now - DebtSince() : 0) +
            L",\"outcome\":" + mcpjson::Quote(KmonImageAttemptOutcomeName(Outcome)) + L"}";
    }
};

// Analysis-thread owned; keep large histogram storage off monitor stack frames.
class KmonImageTimings
{
public:
    struct Samples
    {
        KmonLatencyHistogram ReferenceLookup, SuccessfulTurn, FailedTurn, DeferredTurn, PreparationPendingTurn;
        KmonLatencyHistogram FirstParserAge, FirstExactReadAge, FirstTraversalAge, FirstGapFreeAge;
        std::array<KmonLatencyHistogram, 4> Stages;
        std::array<uint64_t, static_cast<size_t>(KmonImageAttemptOutcome::Count)> Outcomes{};
        uint64_t UnavailableLookups = 0, OverBudget = 0, BorrowedFirstPage = 0, InvalidClocks = 0;
    };
    void Reset() { State = std::make_unique<std::array<Samples, 2>>(); }
    const Samples& Snapshot(bool shutdown = false) const { return (*State)[shutdown ? 1 : 0]; }
    void Lookup(uint64_t started, uint64_t ended, bool ready, bool shutdown)
    {
        auto& stats = (*State)[shutdown ? 1 : 0];
        if (ended < started) { ++stats.InvalidClocks; return; }
        stats.ReferenceLookup.Add(ended - started);
        stats.UnavailableLookups += !ready;
    }
    void Turn(uint64_t started, uint64_t ended, const ExecutableSweepTiming& timing,
        KmonImageAttemptOutcome outcome, bool shutdown)
    {
        auto& stats = (*State)[shutdown ? 1 : 0];
        ++stats.Outcomes[static_cast<size_t>(outcome)];
        if (ended < started || timing.InvalidBudgetClock || outcome == KmonImageAttemptOutcome::InvalidClock ||
            (timing.StagesEntered != 0 && (timing.StartedMs < started || timing.FinishedMs < timing.StartedMs || ended < timing.FinishedMs)))
        { ++stats.InvalidClocks; return; }
        (outcome == KmonImageAttemptOutcome::Observed ? stats.SuccessfulTurn :
            outcome == KmonImageAttemptOutcome::ReferencePending ? stats.PreparationPendingTurn :
            outcome == KmonImageAttemptOutcome::Deferred ? stats.DeferredTurn : stats.FailedTurn).Add(ended - started);
        stats.OverBudget += ended - started > KmonImageTurnBudgetMs;
        stats.BorrowedFirstPage += timing.MinimumProgressOverBudget;
        for (size_t i = 0; i < timing.StageMs.size(); ++i)
        { if ((timing.StagesEntered & (1u << i)) != 0) { stats.Stages[i].Add(timing.StageMs[i]); } }
    }
    void Milestones(const KmonImageObservationDebt& before, const KmonImageObservationDebt& after, bool shutdown)
    {
        auto& stats = (*State)[shutdown ? 1 : 0];
        const auto add = [&](bool newlyKnown, uint64_t tick, KmonLatencyHistogram& histogram)
        {
            if (!newlyKnown) { return; }
            if (!after.Seen || tick < after.FirstSeen) { ++stats.InvalidClocks; return; }
            histogram.Add(tick - after.FirstSeen);
        };
        add(!before.ParserAttempted && after.ParserAttempted, after.FirstParserAttempt, stats.FirstParserAge);
        add(!before.ExactRead && after.ExactRead, after.FirstExactRead, stats.FirstExactReadAge);
        add(!before.Traversed && after.Traversed, after.FirstTraversal, stats.FirstTraversalAge);
        add(!before.GapFree && after.GapFree, after.FirstGapFree, stats.FirstGapFreeAge);
    }
    std::wstring Json(bool shutdown = false) const
    {
        const auto& stats = Snapshot(shutdown);
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        const auto histogram = [&](const KmonLatencyHistogram& h)
        { return L"{\"samples\":" + n(h.Samples) + L",\"p50_upper_ms\":" + n(h.UpperPercentile(50)) +
            L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) + L",\"max_ms\":" + n(h.MaximumMs) + L"}"; };
        std::wstring outcomes;
        for (size_t i = 1; i < stats.Outcomes.size(); ++i)
        { if (!outcomes.empty()) { outcomes += L","; } outcomes += mcpjson::Quote(KmonImageAttemptOutcomeName(static_cast<KmonImageAttemptOutcome>(i))) + L":" + n(stats.Outcomes[i]); }
        return L"{\"outcomes\":{" + outcomes + L"},\"reference_lookup\":" + histogram(stats.ReferenceLookup) +
            L",\"reference_pending_turn\":" + histogram(stats.PreparationPendingTurn) +
            L",\"successful_turn\":" + histogram(stats.SuccessfulTurn) + L",\"failed_turn\":" + histogram(stats.FailedTurn) +
            L",\"deferred_turn\":" + histogram(stats.DeferredTurn) +
            L",\"discovery_to_first_parser_attempt\":" + histogram(stats.FirstParserAge) + L",\"discovery_to_first_exact_read\":" + histogram(stats.FirstExactReadAge) +
            L",\"discovery_to_first_traversal\":" + histogram(stats.FirstTraversalAge) + L",\"discovery_to_first_gap_free_traversal\":" + histogram(stats.FirstGapFreeAge) +
            L",\"reference_open_retention\":" + histogram(stats.Stages[0]) + L",\"identity_secondary_qualification\":" + histogram(stats.Stages[1]) +
            L",\"page_comparison\":" + histogram(stats.Stages[2]) + L",\"final_identity_content_checks\":" + histogram(stats.Stages[3]) +
            L",\"unavailable_lookups\":" + n(stats.UnavailableLookups) + L",\"turns_over_budget\":" + n(stats.OverBudget) +
            L",\"minimum_progress_over_budget\":" + n(stats.BorrowedFirstPage) + L",\"invalid_clocks\":" + n(stats.InvalidClocks) + L"}";
    }
private:
    std::unique_ptr<std::array<Samples, 2>> State = std::make_unique<std::array<Samples, 2>>();
};
static_assert(sizeof(KmonImageTimings) <= 64, "Image timing histograms must stay off monitor stack frames");
