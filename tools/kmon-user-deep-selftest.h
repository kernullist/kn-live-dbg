#pragma once
#include "../user/KmonUserDeepScheduling.h"
#include <iostream>

inline std::wstring UserDeepFixturesJson(bool* passed)
{
    *passed = true; std::wstring scenarios;
    for (const std::wstring name : {L"fixed", L"slow", L"faults", L"reject", L"stop_before", L"stop_inside",
        L"cancel", L"clock_before", L"clock_inside", L"fault_clock", L"reentrant", L"empty", L"external_cancel"})
    {
        KmonUserDeepScheduling scheduler(name == L"empty" ? 0 : 8, 1000);
        uint64_t now = 1025, live = 0, calls = 0, failures = 0;
        bool stop = false;
        if (name == L"external_cancel") { scheduler.Cancel(); }
        std::wstring frames;
        for (size_t turn = 0; turn < 12; ++turn)
        {
            if (name == L"stop_before" && turn == 3) { stop = true; }
            if (name == L"clock_before" && turn == 3) { now -= 1000; }
            const auto begin = now, before = calls;
            const auto result = scheduler.Run([&]() { return now; }, [&](size_t index)
            {
                ++calls; ++live;
                struct Release { uint64_t& N; ~Release() { --N; } } owner{live};
                if (name == L"reentrant" && index == 1)
                {
                    const auto inner = scheduler.Run([&]() { return now; }, [](size_t) -> KmonUserDeepResult { throw std::runtime_error("unexpected recursive target"); },
                        []() { return false; }, [](size_t, const char*) {});
                    *passed = *passed && inner == KmonDiscoveryDispatch::Continued;
                }
                if ((name == L"clock_inside" || name == L"fault_clock") && index == 2) { --now; }
                else { now += name == L"slow" && index == 0 ? 350 : 5 + index; }
                if (name == L"faults" && (index == 0 || index == 3)) { throw std::runtime_error("owned target fault"); }
                if (name == L"faults" && index == 5) { throw 1; }
                if (name == L"fault_clock" && index == 2) { throw std::runtime_error("owned fault with reversed clock"); }
                if (name == L"stop_inside" && index == 2) { stop = true; }
                if (name == L"cancel" && index == 3) { return KmonUserDeepResult::Cancelled; }
                return name == L"reject" && (index == 2 || index == 6) ? KmonUserDeepResult::IdentityRejected : KmonUserDeepResult::Returned;
            }, [&]() { return stop; }, [&](size_t index, const char*)
            {
                ++failures;
                if (name != L"fault_clock") { now += 3; }
                if (name == L"faults" && index == 3) { throw std::runtime_error("owned failure reporter fault"); }
            });
            *passed = *passed && live == 0 && calls - before <= 1;
            if (!frames.empty()) { frames += L","; }
            frames += L"{\"begin\":" + std::to_wstring(begin) + L",\"end\":" + std::to_wstring(now) +
                L",\"calls\":" + std::to_wstring(calls - before) + L",\"result\":" + std::to_wstring(static_cast<unsigned>(result)) +
                L",\"state\":" + scheduler.Json(now) + L"}";
            if (result != KmonDiscoveryDispatch::Continued) { break; }
            now += 7;
        }
        const auto frozen = scheduler.Json(now);
        const auto end = scheduler.Run([&]() { return now; }, [&](size_t) { ++calls; return KmonUserDeepResult::Returned; },
            []() { return false; }, [](size_t, const char*) {});
        *passed = *passed && frozen == scheduler.Json(now) && end != KmonDiscoveryDispatch::Continued;
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += L"{\"name\":" + mcpjson::Quote(name) + L",\"live_owners\":" + std::to_wstring(live) +
            L",\"calls\":" + std::to_wstring(calls) + L",\"failure_reports\":" + std::to_wstring(failures) + L",\"frames\":[" + frames + L"]}";
    }
    return L"{\"schema\":\"kn.user_deep_fixtures.v1\",\"synthetic_clock\":true,\"scenarios\":[" + scenarios + L"]}";
}

inline bool KmonUserDeepSelfTest()
{
    bool passed = false; const auto json = UserDeepFixturesJson(&passed);
    passed = passed && mcpjson::ValidateDocument(json);
    bool rejected = false;
    try { KmonUserDeepScheduling oversized(9, 0); }
    catch (const std::invalid_argument&) { rejected = true; }
    passed = passed && rejected;
    KmonUserDeepScheduling restart(8, 10);
    unsigned calls = 0;
    const auto result = restart.Run([]() { return uint64_t(20); }, [&](size_t i) { ++calls; passed = passed && i == 0; return KmonUserDeepResult::Returned; },
        []() { return false; }, [](size_t, const char*) {});
    passed = passed && calls == 1 && result == KmonDiscoveryDispatch::Continued && restart.NextIndex() == 1;
    std::cerr << "[user.deep] scenarios=13 capacity_and_restart_controls=2 passed=" << passed << "\n";
    return passed;
}
