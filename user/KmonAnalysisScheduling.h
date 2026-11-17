#pragma once
#include "KmonCaptureScheduling.h"
#include <memory>

enum class KmonAnalysisStage : size_t { References, Layout, Live, Ti, Iotrace, Events, Regions, Watched, Images, None };
constexpr size_t KmonAnalysisStages = static_cast<size_t>(KmonAnalysisStage::None);
constexpr uint64_t KmonAnalysisTurnBudgetMs = 250, KmonAnalysisMaximumSliceMs = 100;
inline const wchar_t* KmonAnalysisStageName(size_t i)
{
    static const wchar_t* names[] = {L"execution_references", L"layout", L"live_events", L"ti_events", L"iotrace",
        L"pipeline_events", L"captured_regions", L"watched_references", L"image_sweeps"};
    return names[i];
}
enum class KmonAnalysisDependency { None, Empty, NotDue, LiveBindingAbsent };
struct KmonAnalysisPending
{
    uint64_t Count = 0;
    KmonAnalysisDependency Dependency = KmonAnalysisDependency::Empty;
    uint64_t SliceMs = 25;
    bool Ready() const { return Count != 0 && Dependency == KmonAnalysisDependency::None && SliceMs != 0; }
};

// Analysis-thread owned; shutdown/reset only after that thread joins. No lock
// crosses a callback. Stage returns measure service, never successful target
// observations; those remain in the original per-item scheduling ledgers.
class KmonAnalysisScheduling
{
public:
    void Reset() { State = std::make_unique<Data>(); }
    template<class Clock, class Pending, class Execute, class Stopping>
    void Run(Clock clock, Pending pending, Execute execute, Stopping stopping)
    {
        auto& s = *State;
        if (s.Running) { ++s.Reentrant; return; }
        s.Running = true;
        const uint64_t begin = clock();
        ++s.Turns;
        struct ResetRunning { Data& State; ~ResetRunning() { State.Running = false; State.Active = KmonAnalysisStage::None; State.ActiveAllowance = 0; } } reset{s};
        uint64_t last = begin;
        bool validClock = true;
        const auto sample = [&]()
        {
            const auto now = clock();
            if (now < last) { ++s.InvalidClocks; validClock = false; }
            last = now;
            return now;
        };
        const auto finishTurn = [&]()
        {
            const auto end = sample();
            if (validClock) { s.TurnService.Add(end - begin); s.TurnOverruns += end - begin > KmonAnalysisTurnBudgetMs; }
        };
        const auto run = [&]()
        {
        std::array<bool, KmonAnalysisStages> visited{};
        for (size_t dispatch = 0; dispatch < KmonAnalysisStages; ++dispatch)
        {
            const auto available = pending();
            const auto now = sample();
            if (!validClock) { return; }
            Observe(available, now);
            if (stopping()) { ++s.StoppedTurns; return; }
            if (now - begin >= KmonAnalysisTurnBudgetMs)
            {
                ++s.ExhaustedTurns;
                for (size_t i = 0; i < KmonAnalysisStages; ++i)
                { if (!visited[i] && available[i].Ready()) { ++s.Stages[i].BudgetDeferrals; } }
                return;
            }
            size_t selected = KmonAnalysisStages;
            for (size_t offset = 0; offset < KmonAnalysisStages; ++offset)
            {
                const auto i = (s.Next + offset) % KmonAnalysisStages;
                if (!visited[i] && available[i].Ready()) { selected = i; break; }
            }
            if (selected == KmonAnalysisStages) { return; }
            visited[selected] = true;
            s.Next = (selected + 1) % KmonAnalysisStages; // Includes failed/overrunning callbacks.
            const auto allowance = (std::min)({available[selected].SliceMs, KmonAnalysisMaximumSliceMs,
                KmonAnalysisTurnBudgetMs - (now - begin)});
            auto& stage = s.Stages[selected];
            if (stage.Dispatched && now >= stage.LastDispatch) { stage.Gap.Add(now - stage.LastDispatch); }
            ++stage.Dispatches; stage.Dispatched = true; stage.LastDispatch = now;
            s.Active = static_cast<KmonAnalysisStage>(selected); s.ActiveSince = now; s.ActiveAllowance = allowance;
            try { execute(s.Active, allowance); }
            catch (...)
            {
                const auto end = sample();
                Finish(selected, now, end, allowance, true, validClock);
                throw;
            }
            const auto end = sample();
            Finish(selected, now, end, allowance, false, validClock);
            if (!validClock) { return; }
        }
        const auto available = pending();
        const auto now = sample();
        if (validClock) { Observe(available, now); }
        };
        try { run(); }
        catch (...) { finishTurn(); throw; }
        finishTurn();
    }
    std::wstring Json(uint64_t now) const
    {
        const auto& s = *State;
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        const auto h = [&](const KmonLatencyHistogram& v) { return L"{\"samples\":" + n(v.Samples) +
            L",\"max_ms\":" + n(v.MaximumMs) + L",\"p95_upper_ms\":" + n(v.UpperPercentile(95)) + L"}"; };
        static const wchar_t* reasons[] = {L"none", L"empty", L"not_due", L"live_binding_absent"};
        std::wstring rows;
        for (size_t i = 0; i < KmonAnalysisStages; ++i)
        {
            const auto& v = s.Stages[i];
            if (i) { rows += L","; }
            rows += L"{\"stage\":" + mcpjson::Quote(KmonAnalysisStageName(i)) + L",\"pending\":" + n(v.Pending.Count) +
                L",\"dependency\":" + mcpjson::Quote(reasons[static_cast<size_t>(v.Pending.Dependency)]) +
                L",\"backlog_since_ms\":" + (v.PendingKnown ? n(v.PendingSince) : L"null") +
                L",\"backlog_age_ms\":" + (v.PendingKnown && now >= v.PendingSince ? n(now - v.PendingSince) : L"null") +
                L",\"dispatches\":" + n(v.Dispatches) + L",\"returned\":" + n(v.Returned) + L",\"faults\":" + n(v.Faults) +
                L",\"overruns\":" + n(v.Overruns) + L",\"budget_deferrals\":" + n(v.BudgetDeferrals) +
                L",\"last_dispatch_ms\":" + (v.Dispatched ? n(v.LastDispatch) : L"null") +
                L",\"last_return_ms\":" + (v.ReturnKnown ? n(v.LastReturn) : L"null") +
                L",\"service\":" + h(v.Service) + L",\"failed_service\":" + h(v.FailedService) + L",\"dispatch_gap\":" + h(v.Gap) + L"}";
        }
        return L"{\"schema\":\"kn.analysis_scheduling.v1\",\"scope\":\"cooperative_analysis_boundaries\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"policy\":\"persistent_stage_rotation.v1\","
            L"\"backlog_scope\":\"first_scheduler_observation_of_continuous_stage_backlog\","
            L"\"target_freshness_success_reported\":false,\"hard_deadline_enforced\":false,\"shutdown_drain_included\":false,"
            L"\"snapshot_atomic_across_queues\":false,\"turn_budget_ms\":" + n(KmonAnalysisTurnBudgetMs) +
            L",\"maximum_slice_ms\":" + n(KmonAnalysisMaximumSliceMs) + L",\"turns\":" + n(s.Turns) +
            L",\"exhausted_turns\":" + n(s.ExhaustedTurns) + L",\"stopped_turns\":" + n(s.StoppedTurns) +
            L",\"turn_overruns\":" + n(s.TurnOverruns) + L",\"turn_service\":" + h(s.TurnService) +
            L",\"reentrant_calls\":" + n(s.Reentrant) + L",\"invalid_clocks\":" + n(s.InvalidClocks) +
            L",\"next_stage\":" + mcpjson::Quote(KmonAnalysisStageName(s.Next)) + L",\"active_stage\":" +
            (s.Active == KmonAnalysisStage::None ? L"null" : mcpjson::Quote(KmonAnalysisStageName(static_cast<size_t>(s.Active)))) +
            L",\"active_allowance_ms\":" + n(s.ActiveAllowance) + L",\"active_service_ms\":" +
            (s.Active != KmonAnalysisStage::None && now >= s.ActiveSince ? n(now - s.ActiveSince) : L"null") + L",\"stages\":[" + rows + L"]}";
    }
private:
    struct Stage
    {
        KmonAnalysisPending Pending;
        uint64_t PendingSince = 0, LastDispatch = 0, LastReturn = 0;
        bool PendingKnown = false, Dispatched = false, ReturnKnown = false;
        uint64_t Dispatches = 0, Returned = 0, Faults = 0, Overruns = 0, BudgetDeferrals = 0;
        KmonLatencyHistogram Service, FailedService, Gap;
    };
    struct Data
    {
        std::array<Stage, KmonAnalysisStages> Stages;
        size_t Next = 0;
        uint64_t Turns = 0, ExhaustedTurns = 0, StoppedTurns = 0, Reentrant = 0, InvalidClocks = 0;
        uint64_t TurnOverruns = 0;
        KmonLatencyHistogram TurnService;
        KmonAnalysisStage Active = KmonAnalysisStage::None;
        uint64_t ActiveSince = 0, ActiveAllowance = 0;
        bool Running = false;
    };
    std::unique_ptr<Data> State = std::make_unique<Data>();
    void Observe(const std::array<KmonAnalysisPending, KmonAnalysisStages>& pending, uint64_t now)
    {
        for (size_t i = 0; i < KmonAnalysisStages; ++i)
        {
            auto& v = State->Stages[i];
            if (pending[i].Count == 0) { v.PendingKnown = false; }
            else if (!v.PendingKnown) { v.PendingSince = now; v.PendingKnown = true; }
            v.Pending = pending[i];
        }
    }
    void Finish(size_t i, uint64_t started, uint64_t ended, uint64_t allowance, bool fault, bool validClock)
    {
        auto& v = State->Stages[i];
        State->Active = KmonAnalysisStage::None; State->ActiveAllowance = 0;
        if (fault) { ++v.Faults; } else { ++v.Returned; }
        if (!validClock) { return; }
        if (!fault) { v.LastReturn = ended; v.ReturnKnown = true; }
        (fault ? v.FailedService : v.Service).Add(ended - started);
        v.Overruns += ended - started > allowance;
    }
};
static_assert(sizeof(KmonAnalysisScheduling) <= 128, "Analysis scheduling histograms stay on the heap");
