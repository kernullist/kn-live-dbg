#pragma once
#include "KmonCaptureScheduling.h"
#include <exception>
#include <memory>

enum class KmonWorkerBoundary { Analysis, Discovery };
template<class Analysis, class Discovery, class Failure>
bool KmonRunWorkerBoundaries(Analysis analysis, Discovery discovery, Failure failure)
{
    const auto run = [&](auto operation, KmonWorkerBoundary boundary)
    {
        try { operation(); return true; }
        catch (const std::exception& ex) { failure(boundary, ex.what() != nullptr ? ex.what() : ""); }
        catch (...) { failure(boundary, "unknown exception"); }
        return false;
    };
    const bool a = run(analysis, KmonWorkerBoundary::Analysis);
    const bool d = run(discovery, KmonWorkerBoundary::Discovery);
    return a && d; // Both boundaries run, including after an analysis failure.
}

enum class KmonDiscoveryGroup : size_t { Runtime, Hidden, Mapper, KernelPages, User, Inline, Threads, Channels, Images, Pages, None };
enum class KmonDiscoveryPhase : size_t
{
    Runtime, Hidden, MapperRemnants, PoolImages, UnbackedDrivers, ModuleInventory, ImageIntegrity, DriverTamper,
    HookCallbacks, CallbackLifecycle, PlatformEvidence, HookInput, GraphicsDispatch, GraphicsReferences,
    CpuIntegrity, OrphanPages, UserPrune, UserLogging, UserHostility, UserHandles, UserCapabilities,
    Inline, Threads, Channels, Images, Pages, None
};
constexpr size_t KmonDiscoveryGroups = static_cast<size_t>(KmonDiscoveryGroup::None);
constexpr size_t KmonDiscoveryPhases = static_cast<size_t>(KmonDiscoveryPhase::None);
constexpr uint64_t KmonDiscoveryTurnBudgetMs = 250;
struct KmonDiscoveryDefinition { const wchar_t* Name; size_t First, Count; uint64_t InitialDelay; };
inline constexpr KmonDiscoveryDefinition KmonDiscoveryDefinitions[] = {
    {L"runtime", 0, 1, 0}, {L"hidden", 1, 1, 1000}, {L"mapper", 2, 12, 1000},
    {L"kernel_pages", 14, 2, 2000}, {L"user", 16, 5, 1500}, {L"inline", 21, 1, 2000},
    {L"threads", 22, 1, 2000}, {L"channels", 23, 1, 0}, {L"kernel_images", 24, 1, 0}, {L"page_candidates", 25, 1, 0}};
inline constexpr const wchar_t* KmonDiscoveryPhaseNames[] = {L"runtime_provider", L"hidden_processes", L"mapper_remnants",
    L"pool_images", L"unbacked_drivers", L"module_inventory", L"image_integrity", L"driver_tamper", L"hook_callbacks",
    L"callback_lifecycle", L"platform_evidence", L"hook_input", L"graphics_dispatch", L"graphics_references",
    L"cpu_integrity", L"orphan_pages", L"user_prune", L"user_logging", L"user_hostility", L"user_handles",
    L"user_capabilities", L"inline_patches", L"kernel_threads", L"communication", L"kernel_images", L"page_candidates"};
static_assert(std::size(KmonDiscoveryDefinitions) == KmonDiscoveryGroups &&
    std::size(KmonDiscoveryPhaseNames) == KmonDiscoveryPhases, "Discovery phase inventory must be complete");
inline constexpr bool KmonDiscoveryInventoryValid()
{
    size_t next = 0;
    for (const auto& d : KmonDiscoveryDefinitions) { if (d.First != next || d.Count == 0) { return false; } next += d.Count; }
    return next == KmonDiscoveryPhases;
}
static_assert(KmonDiscoveryInventoryValid(), "Discovery group phases must be contiguous and nonoverlapping");
struct KmonDiscoveryConfig { bool Enabled = false; uint64_t IntervalMs = 0; };
struct KmonDiscoveryStep { KmonDiscoveryGroup Group; KmonDiscoveryPhase Phase; bool First; };
enum class KmonDiscoveryDispatch { Returned, Cancelled };

// Analysis-thread owned. Reset only after joining that worker. A completed
// dispatch cycle says nothing about successful target observation; scanners
// retain their original identity, coverage, target debt and failure evidence.
class KmonDiscoveryScheduling
{
public:
    void Reset() { State = std::make_unique<Data>(); }
    void Request(KmonDiscoveryGroup group, uint64_t due)
    {
        auto& g = State->Groups[static_cast<size_t>(group)];
        ++State->Requests; ++g.Requests;
        if (g.Requested) { ++g.Coalesced; g.RequestDue = (std::min)(g.RequestDue, due); }
        else { g.Requested = true; g.RequestDue = due; }
    }
    bool HasRequest(KmonDiscoveryGroup group) const { return State->Groups[static_cast<size_t>(group)].Requested; }
    template<class Clock, class Configure, class Execute, class Yield, class Stopping>
    void Run(Clock clock, Configure configure, Execute execute, Yield yield, Stopping stopping)
    {
        auto& s = *State;
        if (s.Running) { ++s.Reentrant; return; }
        s.Running = true;
        struct Clear { Data& S; ~Clear() { S.Running = false; S.Active = KmonDiscoveryPhase::None; } } clear{s};
        const uint64_t begin = clock();
        ++s.Turns;
        if (s.ClockKnown && begin < s.LastClock) { ++s.InvalidClocks; return; }
        s.LastClock = begin; s.ClockKnown = true;
        bool valid = true;
        const auto sample = [&]()
        {
            const auto now = clock();
            if (now < s.LastClock) { if (valid) { ++s.InvalidClocks; } valid = false; }
            else { s.LastClock = now; }
            return now;
        };
        if (!s.Initialized)
        {
            for (size_t i = 0; i < KmonDiscoveryGroups; ++i) { s.Groups[i].Due = Add(begin, KmonDiscoveryDefinitions[i].InitialDelay); }
            s.Initialized = true;
        }
        const auto finishTurn = [&]()
        {
            const auto end = sample();
            if (valid) { s.TurnService.Add(end - begin); s.Overruns += end - begin > KmonDiscoveryTurnBudgetMs; }
        };
        const auto run = [&]()
        {
            std::array<bool, KmonDiscoveryGroups> completed{};
            for (size_t count = 0; count < KmonDiscoveryPhases; ++count)
            {
                const auto config = configure();
                const auto now = sample();
                if (!valid) { return; }
                s.Config = config;
                if (stopping()) { ++s.Stopped; return; }
                if (now - begin >= KmonDiscoveryTurnBudgetMs)
                {
                    ++s.Exhausted;
                    for (size_t i = 0; i < KmonDiscoveryGroups; ++i)
                    { if (!completed[i] && config[i].Enabled && Ready(i, now)) { ++s.Groups[i].Deferrals; } }
                    return;
                }
                size_t selected = KmonDiscoveryGroups;
                for (size_t n = 0; n < KmonDiscoveryGroups; ++n)
                {
                    const auto i = (s.Next + n) % KmonDiscoveryGroups;
                    if (!completed[i] && config[i].Enabled && Ready(i, now)) { selected = i; break; }
                }
                if (selected == KmonDiscoveryGroups) { return; }
                auto& g = s.Groups[selected];
                const auto& definition = KmonDiscoveryDefinitions[selected];
                const bool first = !g.Cycling;
                if (first)
                {
                    g.Cycling = true; g.CycleFault = false; g.CycleInvalid = false;
                    g.CycleDue = EffectiveDue(g); g.CycleStarted = now; ++g.Started;
                    g.Wait.Add(now - g.CycleDue);
                    if (g.Requested && g.RequestDue <= now) { g.Requested = false; ++g.RequestsConsumed; }
                }
                const bool firstPhase = g.NextPhase == 0;
                const auto phase = definition.First + g.NextPhase++;
                const bool finalPhase = g.NextPhase == definition.Count;
                s.Next = (selected + 1) % KmonDiscoveryGroups;
                s.Active = static_cast<KmonDiscoveryPhase>(phase); s.ActiveSince = now;
                auto& p = s.Phases[phase];
                if (p.Attempts && now >= p.LastAttempt) { p.Gap.Add(now - p.LastAttempt); }
                ++p.Attempts; p.LastAttempt = now;
                const auto finish = [&](bool fault)
                {
                    const auto end = sample();
                    s.Active = KmonDiscoveryPhase::None;
                    if (fault) { ++p.Faults; } else { ++p.Returned; }
                    g.CycleFault = g.CycleFault || fault; g.CycleInvalid = g.CycleInvalid || !valid;
                    if (valid)
                    {
                        (fault ? p.FailedService : p.Service).Add(end - now);
                        p.Overruns += end - now > KmonDiscoveryTurnBudgetMs - (now - begin);
                        if (!fault) { p.LastReturn = end; p.ReturnKnown = true; }
                    }
                    if (finalPhase)
                    {
                        completed[selected] = true; g.Cycling = false; g.NextPhase = 0;
                        if (g.CycleFault) { ++g.Faulted; } else { ++g.Returned; }
                        if (!g.CycleInvalid)
                        {
                            (g.CycleFault ? g.FailedCycle : g.CycleService).Add(end - g.CycleStarted);
                            (g.CycleFault ? g.FailedDueToEnd : g.DueToEnd).Add(end - g.CycleDue);
                        }
                        else { ++g.InvalidCycles; }
                        // Re-evaluate cadence after the final scanner: a mapper
                        // watch may have changed while its cycle was in progress.
                        g.Due = Add(valid ? end : now, configure()[selected].IntervalMs);
                        // A request admitted after cycle start remains pending.
                    }
                };
                KmonDiscoveryDispatch result;
                try { result = execute({static_cast<KmonDiscoveryGroup>(selected), static_cast<KmonDiscoveryPhase>(phase), firstPhase}); }
                catch (...) { finish(true); throw; }
                if (result == KmonDiscoveryDispatch::Cancelled)
                {
                    // Stop can race selection before the actual scanner entry.
                    // Retain that phase and its original cycle/request debt.
                    const auto end = sample();
                    --g.NextPhase; ++p.Cancelled; ++s.Cancelled;
                    s.Active = KmonDiscoveryPhase::None;
                    g.CycleInvalid = g.CycleInvalid || !valid;
                    if (valid)
                    {
                        p.CancelledService.Add(end - now);
                        p.Overruns += end - now > KmonDiscoveryTurnBudgetMs - (now - begin);
                    }
                    return;
                }
                finish(false);
                if (!valid) { return; }
                try { yield(); }
                catch (...) { ++s.YieldFaults; throw; }
            }
        };
        try { run(); }
        catch (...) { finishTurn(); throw; }
        finishTurn();
    }
    std::wstring Json(uint64_t now) const
    {
        const auto& s = *State;
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        const auto b = [](bool v) -> std::wstring { return v ? L"true" : L"false"; };
        const auto h = [&](const KmonLatencyHistogram& v) { return L"{\"samples\":" + n(v.Samples) + L",\"max_ms\":" + n(v.MaximumMs) +
            L",\"p95_upper_ms\":" + n(v.UpperPercentile(95)) + L"}"; };
        std::wstring groups, phases;
        for (size_t i = 0; i < KmonDiscoveryGroups; ++i)
        {
            const auto& g = s.Groups[i]; const auto& d = KmonDiscoveryDefinitions[i];
            const auto due = g.Cycling ? g.CycleDue : EffectiveDue(g);
            if (i) { groups += L","; }
            groups += L"{\"group\":" + mcpjson::Quote(d.Name) + L",\"binding_enabled\":" + b(s.Config[i].Enabled) +
                L",\"initialized\":" + b(s.Initialized) + L",\"cycle_active\":" + b(g.Cycling) +
                L",\"next_phase\":" + mcpjson::Quote(KmonDiscoveryPhaseNames[d.First + (g.NextPhase % d.Count)]) +
                L",\"remaining_phases\":" + n(g.Cycling ? d.Count - g.NextPhase : d.Count) +
                L",\"periodic_due_ms\":" + (s.Initialized ? n(g.Due) : L"null") +
                L",\"pending_since_ms\":" + (s.Initialized && (g.Cycling || now >= due) ? n(due) : L"null") +
                L",\"pending_age_ms\":" + (s.Initialized && now >= due ? n(now - due) : L"null") +
                L",\"request_due_ms\":" + (g.Requested ? n(g.RequestDue) : L"null") +
                L",\"requests\":" + n(g.Requests) + L",\"coalesced_requests\":" + n(g.Coalesced) +
                L",\"consumed_request_batches\":" + n(g.RequestsConsumed) + L",\"started_cycles\":" + n(g.Started) +
                L",\"returned_cycles\":" + n(g.Returned) + L",\"faulted_cycles\":" + n(g.Faulted) +
                L",\"cycles_without_valid_clock\":" + n(g.InvalidCycles) +
                L",\"budget_deferrals\":" + n(g.Deferrals) + L",\"due_to_first_dispatch\":" + h(g.Wait) +
                L",\"cycle_service\":" + h(g.CycleService) + L",\"failed_cycle_service\":" + h(g.FailedCycle) +
                L",\"due_to_returned_cycle\":" + h(g.DueToEnd) + L",\"due_to_faulted_cycle\":" + h(g.FailedDueToEnd) + L"}";
        }
        for (size_t i = 0; i < KmonDiscoveryPhases; ++i)
        {
            const auto& p = s.Phases[i]; if (i) { phases += L","; }
            phases += L"{\"phase\":" + mcpjson::Quote(KmonDiscoveryPhaseNames[i]) + L",\"attempts\":" + n(p.Attempts) +
                L",\"returned\":" + n(p.Returned) + L",\"faults\":" + n(p.Faults) + L",\"cancelled\":" + n(p.Cancelled) + L",\"overruns\":" + n(p.Overruns) +
                L",\"last_attempt_ms\":" + (p.Attempts ? n(p.LastAttempt) : L"null") +
                L",\"last_return_ms\":" + (p.ReturnKnown ? n(p.LastReturn) : L"null") +
                L",\"service\":" + h(p.Service) + L",\"failed_service\":" + h(p.FailedService) + L",\"cancelled_service\":" + h(p.CancelledService) +
                L",\"attempt_gap\":" + h(p.Gap) + L"}";
        }
        return L"{\"schema\":\"kn.discovery_scheduling.v1\",\"policy\":\"persistent_group_and_phase_rotation.v1\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"debt_scope\":\"scheduled_discovery_cycle_due\","
            L"\"target_success_reported\":false,\"hard_deadline_enforced\":false,\"individual_scanner_preemption\":false,"
            L"\"shutdown_drain_included\":false,\"interleaved_analysis_in_turn_service\":true,"
            L"\"turn_budget_ms\":" + n(KmonDiscoveryTurnBudgetMs) + L",\"turns\":" + n(s.Turns) +
            L",\"exhausted_turns\":" + n(s.Exhausted) + L",\"overrunning_turns\":" + n(s.Overruns) +
            L",\"stopped_turns\":" + n(s.Stopped) + L",\"cancelled_turns\":" + n(s.Cancelled) + L",\"invalid_clocks\":" + n(s.InvalidClocks) +
            L",\"reentrant_calls\":" + n(s.Reentrant) + L",\"analysis_yield_faults\":" + n(s.YieldFaults) +
            L",\"requests\":" + n(s.Requests) + L",\"next_group\":" + mcpjson::Quote(KmonDiscoveryDefinitions[s.Next].Name) +
            L",\"active_phase\":" + (s.Active == KmonDiscoveryPhase::None ? L"null" : mcpjson::Quote(KmonDiscoveryPhaseNames[static_cast<size_t>(s.Active)])) +
            L",\"active_service_ms\":" + (s.Active != KmonDiscoveryPhase::None && now >= s.ActiveSince ? n(now - s.ActiveSince) : L"null") +
            L",\"turn_service\":" + h(s.TurnService) + L",\"groups\":[" + groups + L"],\"phases\":[" + phases + L"]}";
    }
private:
    struct Group
    {
        uint64_t Due = 0, RequestDue = 0, CycleDue = 0, CycleStarted = 0;
        bool Requested = false, Cycling = false, CycleFault = false, CycleInvalid = false;
        size_t NextPhase = 0;
        uint64_t Requests = 0, Coalesced = 0, RequestsConsumed = 0, Started = 0, Returned = 0, Faulted = 0, Deferrals = 0;
        uint64_t InvalidCycles = 0;
        KmonLatencyHistogram Wait, CycleService, FailedCycle, DueToEnd, FailedDueToEnd;
    };
    struct Phase
    {
        uint64_t Attempts = 0, Returned = 0, Faults = 0, Cancelled = 0, Overruns = 0, LastAttempt = 0, LastReturn = 0;
        bool ReturnKnown = false;
        KmonLatencyHistogram Service, FailedService, CancelledService, Gap;
    };
    struct Data
    {
        std::array<Group, KmonDiscoveryGroups> Groups;
        std::array<Phase, KmonDiscoveryPhases> Phases;
        std::array<KmonDiscoveryConfig, KmonDiscoveryGroups> Config{};
        size_t Next = 0;
        uint64_t Turns = 0, Requests = 0, Exhausted = 0, Overruns = 0, Stopped = 0, Cancelled = 0, InvalidClocks = 0, Reentrant = 0, YieldFaults = 0;
        bool Initialized = false, Running = false, ClockKnown = false;
        uint64_t LastClock = 0;
        KmonDiscoveryPhase Active = KmonDiscoveryPhase::None;
        uint64_t ActiveSince = 0;
        KmonLatencyHistogram TurnService;
    };
    std::unique_ptr<Data> State = std::make_unique<Data>();
    static uint64_t Add(uint64_t time, uint64_t delay) { return delay > UINT64_MAX - time ? UINT64_MAX : time + delay; }
    static uint64_t EffectiveDue(const Group& g) { return g.Requested ? (std::min)(g.Due, g.RequestDue) : g.Due; }
    bool Ready(size_t group, uint64_t now) const { const auto& g = State->Groups[group]; return g.Cycling || now >= EffectiveDue(g); }
};
static_assert(sizeof(KmonDiscoveryScheduling) <= 128, "Discovery diagnostics stay off the worker stack");
