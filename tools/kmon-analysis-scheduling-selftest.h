#pragma once
#include "../user/KmonAnalysisScheduling.h"
#include <iostream>
#include <stdexcept>

inline std::wstring AnalysisSchedulingFixturesJson()
{
    std::wstring rows;
    for (const std::wstring name : {L"fixed", L"growing", L"churn", L"blocked", L"not_due", L"slow", L"fault",
        L"stop", L"reentrant", L"backward", L"last_stage_overrun", L"depletion"})
    {
        KmonAnalysisScheduling scheduler;
        std::array<KmonAnalysisPending, KmonAnalysisStages> pending{};
        uint64_t now = name == L"backward" ? 1000 : 0;
        bool stopping = false, special = false;
        std::wstring turns;
        for (unsigned turn = 0; turn < 36; ++turn)
        {
            stopping = false;
            for (size_t i = 0; i < pending.size(); ++i)
            {
                auto& p = pending[i];
                p = {name == L"growing" ? uint64_t(turn + 1) : 1, KmonAnalysisDependency::None, 100};
                if (name == L"churn" && (turn + i) % 4 == 0) { p.Count = 0; p.Dependency = KmonAnalysisDependency::Empty; }
                if (name == L"blocked" && i == 0 && turn < 18) { p.Dependency = KmonAnalysisDependency::LiveBindingAbsent; }
                if (name == L"not_due" && i == 8 && turn % 3 != 2) { p.Dependency = KmonAnalysisDependency::NotDue; }
            }
            const auto begin = now;
            const auto before = scheduler.Json(now);
            std::wstring availability, trace;
            for (size_t i = 0; i < pending.size(); ++i)
            {
                if (i) { availability += L","; }
                availability += pending[i].Ready() ? L"true" : L"false";
            }
            bool threw = false;
            try
            {
                scheduler.Run([&]() { return now; }, [&]() { return pending; },
                    [&](KmonAnalysisStage stage, uint64_t allowance)
                    {
                        const auto i = static_cast<size_t>(stage);
                        const auto started = now;
                        if (name == L"reentrant" && !special)
                        {
                            special = true;
                            scheduler.Run([&]() { return now; }, [&]() { return pending; },
                                [](KmonAnalysisStage, uint64_t) { throw std::runtime_error("reentrant dispatch"); }, []() { return false; });
                        }
                        if (name == L"backward" && !special) { --now; special = true; }
                        else { now += name == L"slow" && i == 0 ? 350 : name == L"last_stage_overrun" ? (i == 8 ? 300 : 1) : 100; }
                        if (!trace.empty()) { trace += L","; }
                        trace += L"{\"stage\":" + std::to_wstring(i) + L",\"allowance\":" + std::to_wstring(allowance) +
                            L",\"begin\":" + std::to_wstring(started) + L",\"end\":" + std::to_wstring(now) + L"}";
                        if (name == L"stop") { stopping = true; }
                        if (name == L"depletion") { pending[i].Count = 0; pending[i].Dependency = KmonAnalysisDependency::Empty; }
                        if (name == L"fault" && !special) { special = true; throw std::runtime_error("owned stage fault"); }
                    }, [&]() { return stopping; });
            }
            catch (const std::runtime_error&) { threw = true; }
            if (!turns.empty()) { turns += L","; }
            turns += L"{\"begin\":" + std::to_wstring(begin) + L",\"end\":" + std::to_wstring(now) +
                L",\"ready\":[" + availability + L"],\"before\":" + before + L",\"threw\":" +
                std::wstring(threw ? L"true" : L"false") + L",\"trace\":[" + trace + L"]}";
        }
        if (!rows.empty()) { rows += L","; }
        rows += L"{\"name\":" + mcpjson::Quote(name) + L",\"turns\":[" + turns + L"],\"final\":" + scheduler.Json(now) + L"}";
    }
    return L"{\"schema\":\"kn.analysis_scheduler_fixtures.v1\",\"synthetic_clock\":true,\"scenarios\":[" + rows + L"]}";
}

inline bool KmonAnalysisSchedulingSelfTest()
{
    size_t checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* why)
    { ++checks; if (!ok) { ++failures; std::cerr << "[analysis.scheduler] FAIL " << why << "\n"; } };
    KmonAnalysisScheduling scheduler;
    std::array<KmonAnalysisPending, KmonAnalysisStages> pending{};
    uint64_t now = 0;
    size_t expected = 0, dispatched = 0;
    for (auto& item : pending) { item = {1, KmonAnalysisDependency::None, 1000}; }
    for (unsigned turn = 0; turn < 60; ++turn)
    {
        const auto begin = now;
        scheduler.Run([&]() { return now; }, [&]() { return pending; }, [&](KmonAnalysisStage stage, uint64_t slice)
        {
            check(static_cast<size_t>(stage) == expected, "continuous readiness preserves rotation across turns");
            check(slice > 0 && slice <= 100 && slice <= 250 - (now - begin), "allowance includes elapsed turn and stage cap");
            expected = (expected + 1) % KmonAnalysisStages; ++dispatched; now += 100;
        }, []() { return false; });
        check(now - begin == 300, "native overrun is not reported as a hard deadline");
    }
    check(dispatched == 180 && expected == 0, "all nine stages get finite revisit under continuous arrivals");
    check(mcpjson::ValidateDocument(scheduler.Json(now)), "diagnostics are valid JSON");
    scheduler.Reset();
    for (auto& item : pending) { item = {}; }
    scheduler.Run([&]() { return now; }, [&]() { return pending; }, [&](KmonAnalysisStage, uint64_t) { check(false, "empty dispatch"); }, []() { return false; });
    check(scheduler.Json(now).find(L"\"dispatches\":\"1\"") == std::wstring::npos, "reset clears histories and empty work never dispatches");
    std::cout << "[analysis.scheduler] checks=" << checks << " failed=" << failures << "\n";
    return failures == 0;
}
