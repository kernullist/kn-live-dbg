#pragma once
#include "../user/KmonDiscoveryScheduling.h"
#include <iostream>
#include <stdexcept>

inline std::wstring DiscoverySchedulingFixturesJson()
{
    std::wstring scenarios;
    for (const std::wstring name : {L"fixed", L"flood", L"churn", L"blocked", L"slow", L"head_fault", L"midcycle_request",
        L"yield_fault", L"stop", L"reentrant", L"backward_between", L"backward_inside", L"last_phase_overrun", L"depletion", L"cancel"})
    {
        KmonDiscoveryScheduling scheduler;
        std::array<KmonDiscoveryConfig, KmonDiscoveryGroups> config{};
        uint64_t now = name == L"backward_inside" ? 1000 : 0;
        bool special = false, stopping = false;
        std::wstring turns;
        for (unsigned turn = 0; turn < 160; ++turn)
        {
            stopping = false;
            for (size_t i = 0; i < config.size(); ++i)
            {
                config[i] = {true, name == L"flood" ? 4000ull :
                    (name == L"midcycle_request" || name == L"last_phase_overrun" || name == L"depletion") ? 100000ull : 0ull};
                if (name == L"churn") { config[i].Enabled = (turn + i) % 5 < 3; }
                if (name == L"blocked" && i == 2 && turn < 12) { config[i].Enabled = false; }
                if (name == L"midcycle_request") { config[i].Enabled = i == 2; }
            }
            if (name == L"backward_between" && turn == 4) { now -= 20; }
            std::wstring beforeRequests, trace, enabled;
            const auto request = [&](size_t group, uint64_t due, std::wstring& list)
            {
                scheduler.Request(static_cast<KmonDiscoveryGroup>(group), due);
                if (!list.empty()) { list += L","; }
                list += L"[" + std::to_wstring(group) + L"," + std::to_wstring(due) + L"]";
            };
            if (name == L"flood") { request(2, now, beforeRequests); request(2, now + 100, beforeRequests); }
            if (name == L"midcycle_request" && turn == 0) { request(2, now, beforeRequests); }
            if ((name == L"last_phase_overrun" || name == L"depletion") && turn == 0)
            { for (size_t i = 0; i < config.size(); ++i) { request(i, now, beforeRequests); } }
            for (const auto& c : config) { if (!enabled.empty()) { enabled += L","; } enabled += c.Enabled ? L"true" : L"false"; }
            const auto begin = now;
            bool threw = false;
            try
            {
                scheduler.Run([&]() { return now; }, [&]() { return config; }, [&](KmonDiscoveryStep step)
                {
                    const auto group = static_cast<size_t>(step.Group), phase = static_cast<size_t>(step.Phase);
                    const auto started = now;
                    std::wstring requests;
                    if (name == L"midcycle_request" && !special)
                    { special = true; request(group, now + 10, requests); request(group, now + 100, requests); }
                    if (name == L"reentrant" && !special)
                    {
                        special = true;
                        scheduler.Run([&]() { return now; }, [&]() { return config; },
                            [](KmonDiscoveryStep) -> KmonDiscoveryDispatch { throw std::runtime_error("recursive dispatch"); }, []() {}, []() { return false; });
                    }
                    const bool cancelled = name == L"cancel" && !special;
                    if (cancelled) { special = true; }
                    else if (name == L"backward_inside" && !special) { --now; special = true; }
                    else { now += (name == L"slow" && phase == 2) || (name == L"last_phase_overrun" && phase == 13) ? 350 :
                        name == L"last_phase_overrun" ? 1 : name == L"depletion" ? 10 : 100; }
                    const bool fault = name == L"head_fault" && phase == 2;
                    if (!trace.empty()) { trace += L","; }
                    trace += L"{\"group\":" + std::to_wstring(group) + L",\"phase\":" + std::to_wstring(phase) +
                        L",\"first\":" + std::wstring(step.First ? L"true" : L"false") + L",\"begin\":" + std::to_wstring(started) +
                        L",\"end\":" + std::to_wstring(now) + L",\"fault\":" + (fault ? L"true" : L"false") +
                        L",\"cancelled\":" + (cancelled ? L"true" : L"false") + L",\"requests\":[" + requests + L"]}";
                    if (name == L"stop") { stopping = true; }
                    if (fault) { throw std::runtime_error("owned repeated head fault"); }
                    return cancelled ? KmonDiscoveryDispatch::Cancelled : KmonDiscoveryDispatch::Returned;
                }, [&]()
                {
                    if (name == L"yield_fault" && !special) { special = true; throw std::runtime_error("owned analysis yield fault"); }
                    // Analysis service consumes the enclosing discovery budget.
                    if (name == L"flood") { now += 50; }
                }, [&]() { return stopping; });
            }
            catch (const std::runtime_error&) { threw = true; }
            if (!turns.empty()) { turns += L","; }
            turns += L"{\"begin\":" + std::to_wstring(begin) + L",\"end\":" + std::to_wstring(now) +
                L",\"enabled\":[" + enabled + L"],\"requests\":[" + beforeRequests + L"],\"threw\":" +
                std::wstring(threw ? L"true" : L"false") + L",\"trace\":[" + trace + L"]}";
            now += 10;
        }
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += L"{\"name\":" + mcpjson::Quote(name) + L",\"snapshot_ms\":" + std::to_wstring(now) +
            L",\"turns\":[" + turns + L"],\"final\":" + scheduler.Json(now) + L"}";
    }
    return L"{\"schema\":\"kn.discovery_scheduler_fixtures.v1\",\"synthetic_clock\":true,\"scenarios\":[" + scenarios + L"]}";
}

inline bool KmonDiscoverySchedulingSelfTest()
{
    size_t checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* why)
    { ++checks; if (!ok) { ++failures; std::cerr << "[discovery.scheduler] FAIL " << why << "\n"; } };
    KmonDiscoveryScheduling scheduler;
    std::array<KmonDiscoveryConfig, KmonDiscoveryGroups> config{};
    for (auto& c : config) { c = {true, 0}; }
    std::array<uint64_t, KmonDiscoveryPhases> seen{};
    std::array<size_t, KmonDiscoveryGroups> next{};
    uint64_t now = 0;
    for (unsigned turn = 0; turn < 180; ++turn)
    {
        scheduler.Run([&]() { return now; }, [&]() { return config; }, [&](KmonDiscoveryStep step)
        {
            const auto group = static_cast<size_t>(step.Group), phase = static_cast<size_t>(step.Phase);
            const auto& d = KmonDiscoveryDefinitions[group];
            check(phase == d.First + next[group] && step.First == (next[group] == 0), "each group resumes its original phase order");
            next[group] = (next[group] + 1) % d.Count;
            ++seen[phase]; now += 100;
            return KmonDiscoveryDispatch::Returned;
        }, [&]() { now += 50; }, []() { return false; });
        now += 10;
    }
    check(std::all_of(seen.begin(), seen.end(), [](uint64_t n) { return n != 0; }), "long group tails and independent groups all make progress");
    check(mcpjson::ValidateDocument(scheduler.Json(now)), "private diagnostics valid");
    scheduler.Request(KmonDiscoveryGroup::Threads, now);
    check(scheduler.HasRequest(KmonDiscoveryGroup::Threads), "request retained");
    scheduler.Reset();
    check(!scheduler.HasRequest(KmonDiscoveryGroup::Threads), "new session removes prior request");
    unsigned analysis = 0, discovery = 0, errors = 0;
    check(!KmonRunWorkerBoundaries([]() { throw std::runtime_error("owned analysis failure"); }, [&]() { ++discovery; },
        [&](KmonWorkerBoundary boundary, const char*) { check(boundary == KmonWorkerBoundary::Analysis, "analysis failure provenance"); ++errors; }) &&
        discovery == 1 && errors == 1, "persistent analysis failure cannot prevent discovery service");
    check(!KmonRunWorkerBoundaries([&]() { ++analysis; }, []() { throw 1; },
        [&](KmonWorkerBoundary boundary, const char*) { check(boundary == KmonWorkerBoundary::Discovery, "discovery failure provenance"); ++errors; }) &&
        analysis == 1 && errors == 2, "unknown discovery exception is isolated and reported");
    check(KmonRunWorkerBoundaries([&]() { ++analysis; }, [&]() { ++discovery; }, [](KmonWorkerBoundary, const char*) {}) &&
        analysis == 2 && discovery == 2, "normal worker boundaries both finish");
    std::cout << "[discovery.scheduler] checks=" << checks << " failed=" << failures << "\n";
    return failures == 0;
}
