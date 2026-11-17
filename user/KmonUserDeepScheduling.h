#pragma once
#include "KmonDiscoveryScheduling.h"
#include <stdexcept>

enum class KmonUserDeepResult { Returned, IdentityRejected, Cancelled };

// The inventory proposes the next position. Only entry into its selected
// deep inspection spends it; a PID position carries no process identity.
struct KmonUserInventoryPosition
{
    uint32_t AfterPid = 0, ThroughPid = 0;
    bool InCurrentLap(uint32_t pid) const { return pid > AfterPid && pid <= ThroughPid; }
};

// A fixed, selected cohort. One callback per turn; selection/attempt clocks
// are not target-qualified observation success. Native calls are cooperative.
class KmonUserDeepScheduling
{
public:
    static constexpr size_t Capacity = 8;
    KmonUserDeepScheduling(size_t count, uint64_t selected) : Count(count), Selected(selected), LastClock(selected)
    { if (count > Capacity) { throw std::invalid_argument("user deep cohort exceeds selection capacity"); } }
    bool Complete() const { return Next == Count; }
    size_t NextIndex() const { return Next; }
    void Cancel() { if (!Complete()) { Cancelled = true; } }

    template<class Clock, class Execute, class Stopping, class Failure>
    KmonDiscoveryDispatch Run(Clock clock, Execute execute, Stopping stopping, Failure failure)
    {
        if (Running) { ++Reentrant; return KmonDiscoveryDispatch::Continued; }
        if (Complete()) { return KmonDiscoveryDispatch::Returned; }
        if (Cancelled) { return KmonDiscoveryDispatch::Cancelled; }
        const auto begin = clock(); ++Turns;
        if (begin < LastClock) { ++InvalidClocks; Cancel(); return KmonDiscoveryDispatch::Cancelled; }
        LastClock = begin;
        if (stopping()) { ++PreEntryStops; Cancel(); return KmonDiscoveryDispatch::Cancelled; }
        Running = true;
        struct Clear { bool& Flag; ~Clear() { Flag = false; } } clear{Running};
        auto& slot = Slots[Next];
        if (!slot.Attempts) { slot.First = begin; Wait.Add(begin - Selected); }
        ++slot.Attempts; ++Attempts; slot.Last = begin;
        bool fault = false;
        auto result = KmonUserDeepResult::Returned;
        const auto report = [&](const char* message)
        {
            // Diagnostic failure cannot discard the rest of the cohort.
            try { failure(Next, message); } catch (...) { ++ReportFailures; }
        };
        try { result = execute(Next); }
        catch (const std::exception& ex) { fault = true; report(ex.what() != nullptr ? ex.what() : ""); }
        catch (...) { fault = true; report("unknown exception"); }
        const auto end = clock();
        const bool valid = end >= LastClock;
        if (valid) { LastClock = end; }
        else { ++InvalidClocks; }
        // A stopped partial inspection stays pending. Faults remain explicit
        // even when stop arrives during error reporting.
        if (!fault && (!valid || stopping())) { result = KmonUserDeepResult::Cancelled; }
        if (fault) { slot.Outcome = 4; ++Faults; }
        else if (result == KmonUserDeepResult::Cancelled) { slot.Outcome = 3; ++Cancellations; }
        else if (result == KmonUserDeepResult::IdentityRejected) { slot.Outcome = 2; ++Rejected; }
        else { slot.Outcome = 1; ++Returned; }
        if (valid)
        {
            Service[slot.Outcome - 1].Add(end - begin);
            slot.End = end; slot.EndKnown = true;
            Overruns += end - begin > KmonDiscoveryTurnBudgetMs;
        }
        if (slot.Outcome == 3) { Cancel(); return KmonDiscoveryDispatch::Cancelled; }
        ++Next;
        if (!valid) { Cancel(); }
        if (Complete()) { return KmonDiscoveryDispatch::Returned; }
        return Cancelled ? KmonDiscoveryDispatch::Cancelled : KmonDiscoveryDispatch::Continued;
    }
    std::wstring Json(uint64_t now) const
    {
        const auto n = [](uint64_t v) { return mcpjson::Quote(std::to_wstring(v)); };
        const auto b = [](bool v) -> std::wstring { return v ? L"true" : L"false"; };
        const auto h = [&](const KmonLatencyHistogram& v)
        { return L"{\"samples\":" + n(v.Samples) + L",\"max_ms\":" + n(v.MaximumMs) + L",\"p95_upper_ms\":" + n(v.UpperPercentile(95)) + L"}"; };
        static const wchar_t* outcomes[] = {L"pending", L"returned", L"identity_rejected", L"cancelled", L"faulted"};
        std::wstring slots;
        for (size_t i = 0; i < Count; ++i)
        {
            const auto& slot = Slots[i]; if (i) { slots += L","; }
            slots += L"{\"index\":" + n(i) + L",\"attempts\":" + n(slot.Attempts) +
                L",\"outcome\":" + mcpjson::Quote(outcomes[slot.Outcome]) +
                L",\"first_dispatch_ms\":" + (slot.Attempts ? n(slot.First) : L"null") +
                L",\"last_dispatch_ms\":" + (slot.Attempts ? n(slot.Last) : L"null") +
                L",\"end_ms\":" + (slot.EndKnown ? n(slot.End) : L"null") + L"}";
        }
        return L"{\"schema\":\"kn.user_deep_scheduling.v1\",\"scope\":\"latest_selected_cohort\","
            L"\"clock_domain\":\"GetTickCount64_ms\",\"target_success_reported\":false,\"hard_deadline_enforced\":false,"
            L"\"callbacks_per_turn\":\"1\",\"overrun_threshold_ms\":" + n(KmonDiscoveryTurnBudgetMs) +
            L",\"selected_ms\":" + n(Selected) + L",\"selected\":" + n(Count) +
            L",\"next_index\":" + n(Next) + L",\"remaining\":" + n(Count - Next) +
            L",\"pending_age_ms\":" + (!Complete() && now >= Selected && !InvalidClocks ? n(now - Selected) : L"null") +
            L",\"complete\":" + b(Complete()) + L",\"cancelled\":" + b(Cancelled) + L",\"running\":" + b(Running) +
            L",\"turns\":" + n(Turns) + L",\"attempts\":" + n(Attempts) + L",\"returned\":" + n(Returned) +
            L",\"identity_rejected\":" + n(Rejected) + L",\"faults\":" + n(Faults) + L",\"cancellations\":" + n(Cancellations) +
            L",\"pre_entry_stops\":" + n(PreEntryStops) + L",\"invalid_clocks\":" + n(InvalidClocks) +
            L",\"reentrant_calls\":" + n(Reentrant) + L",\"failure_report_faults\":" + n(ReportFailures) +
            L",\"overruns\":" + n(Overruns) + L",\"selection_to_first_dispatch\":" + h(Wait) +
            L",\"returned_service\":" + h(Service[0]) + L",\"rejected_service\":" + h(Service[1]) +
            L",\"cancelled_service\":" + h(Service[2]) + L",\"faulted_service\":" + h(Service[3]) +
            L",\"slots\":[" + slots + L"]}";
    }
private:
    struct Slot
    {
        uint64_t Attempts = 0, First = 0, Last = 0, End = 0;
        unsigned Outcome = 0;
        bool EndKnown = false;
    };
    size_t Count, Next = 0;
    uint64_t Selected, LastClock;
    bool Running = false, Cancelled = false;
    uint64_t Turns = 0, Attempts = 0, Returned = 0, Rejected = 0, Faults = 0, Cancellations = 0;
    uint64_t PreEntryStops = 0, InvalidClocks = 0, Reentrant = 0, ReportFailures = 0, Overruns = 0;
    std::array<Slot, Capacity> Slots{};
    KmonLatencyHistogram Wait;
    std::array<KmonLatencyHistogram, 4> Service;
};
