#pragma once
#include "../user/KmonUserModuleDebt.h"
#include "../user/KmonHandleTracking.h"
#include "kmon-user-inventory-selftest.h"

namespace user_module_debt_test
{
    using Key = KmonUserModuleDebt::Key;
    inline KmonUserTarget Target(uint32_t pid, uint64_t generation, bool pinned = true, uint64_t expires = 0)
    {
        KmonUserTarget t; t.Pid = pid; t.CreateTime = generation; t.Interesting = true;
        t.PinnedGeneration = pinned && generation; t.SuspectExpiresMs = expires;
        return t;
    }
    inline Key Census(KmonUserModuleDebt& debt, const std::vector<KmonUserTarget>& targets, bool complete, uint64_t now)
    {
        std::map<uint32_t, uint64_t> generations;
        for (const auto& t : targets) { generations[t.Pid] = t.CreateTime; }
        return debt.Refresh(targets, generations, complete, now);
    }
    inline void Walk(KmonUserModuleDebt& debt, Key key, uint64_t pin, uint64_t after, bool complete, DWORD error,
        uint64_t start, uint64_t end, bool stop = false, bool loan = false)
    {
        auto visit = debt.Begin(key, start, loan);
        if (pin) { debt.Pin(visit, pin, start + 1); }
        debt.ConcludeWalk(visit, after, complete, error, stop, end);
        debt.Fail(visit, KmonModuleResult::Fault, end + 1); // a later failure cannot rewrite a closed source receipt
    }
    inline void Frame(std::wstring& out, const wchar_t* name, const KmonUserModuleDebt& debt, uint64_t now)
    {
        if (!out.empty()) { out += L","; }
        out += mcpjson::Quote(name) + L":" + debt.Json(now);
    }
    inline std::wstring Lifecycle()
    {
        KmonUserModuleDebt d;
        const auto population = std::vector<KmonUserTarget>{Target(10, 100), Target(20, 200, false, 180), Target(30, 0)};
        std::wstring f;
        Census(d, population, true, 100); Frame(f, L"seen", d, 100);
        auto denied = d.Begin({10, 100}, 110);
        d.Fail(denied, KmonModuleResult::AccessDenied, 114, ERROR_ACCESS_DENIED);
        Census(d, population, true, 120); Frame(f, L"rediscovered", d, 120);
        Walk(d, {10, 100}, 100, 100, true, ERROR_NO_MORE_FILES, 130, 135);
        Frame(f, L"first", d, 135);
        Census(d, population, true, 140);
        Walk(d, {10, 100}, 100, 100, false, ERROR_MORE_DATA, 150, 155);
        Walk(d, {10, 100}, 100, 101, true, ERROR_NO_MORE_FILES, 160, 167);
        Walk(d, {30, 0}, 300, 300, true, ERROR_NO_MORE_FILES, 170, 178);
        Frame(f, L"partial_and_pin", d, 180);
        Walk(d, {10, 100}, 100, 100, true, ERROR_NO_MORE_FILES, 190, 193);
        Walk(d, {30, 300}, 300, 300, true, ERROR_NO_MORE_FILES, 195, 200, true);
        Frame(f, L"revisit_and_stop", d, 200);
        Census(d, {Target(10, 101, false), Target(20, 0)}, false, 210);
        Frame(f, L"unconfirmed_reuse", d, 210);
        Census(d, {Target(10, 101), Target(20, 0)}, true, 220);
        Frame(f, L"confirmed_reuse", d, 220);
        auto unknown = d.Begin({40, 0}, 230);
        d.Fail(unknown, KmonModuleResult::IdentityUnavailable, 232);
        Walk(d, {10, 101}, 0, 101, true, ERROR_NO_MORE_FILES, 235, 240);
        Walk(d, {10, 101}, 101, 101, true, ERROR_ACCESS_DENIED, 245, 249);
        Frame(f, L"no_pin_or_bad_terminal", d, 250);
        Walk(d, {10, 101}, 101, 101, true, ERROR_NO_MORE_FILES, 243, 260);
        auto reversePin = d.Begin({20, 0}, 270);
        d.Pin(reversePin, 200, 265); d.ConcludeWalk(reversePin, 200, true, ERROR_NO_MORE_FILES, false, 272);
        Walk(d, {10, 101}, 101, 101, true, ERROR_NO_MORE_FILES, 280, 278);
        Census(d, {}, true, 277); Frame(f, L"clock_reversals", d, 277);
        return L"{" + f + L"}";
    }
    inline std::wstring HintHandoff()
    {
        const auto source = std::make_shared<user_inventory_test::State>();
        source->Name = L"fast";
        source->Rows = {41, 42, 160};
        std::vector<KmonUserTarget> hints{Target(41, 411, false, 140), Target(42, 420, false, 125),
            Target(160, 1600, false, 170), Target(99, 990, false, 180)};
        KmonUserInventory<user_inventory_test::Source> inventory({source}, {}, std::move(hints), 999, 100);
        while (inventory.Run([&]() { return source->Now; }, []() { return false; }) == KmonDiscoveryDispatch::Continued) {}
        const auto targets = inventory.Take();
        KmonUserModuleDebt d;
        for (uint64_t now : {100ull, 110ull, 120ull}) { Census(d, targets, true, now); }
        const Key loan = Census(d, targets, true, 130);
        return L"{\"loan\":" + std::to_wstring(loan.first) + L",\"state\":" + d.Json(130) + L"}";
    }
    inline std::wstring UnsupportedRetry()
    {
        KmonUserModuleDebt d;
        std::wstring frames;
        const Key key{19, 190};
        const std::vector<KmonUserTarget> population{Target(key.first, key.second)};
        Census(d, population, true, 100);
        Walk(d, key, 190, 190, false, ERROR_NOT_SUPPORTED, 110, 115);
        Walk(d, key, 190, 190, false, ERROR_CANCELLED, 120, 125, true);
        Walk(d, key, 190, 190, true, ERROR_NO_MORE_FILES, 117, 130);
        auto conflict = d.Begin(key, 135);
        d.Pin(conflict, 190, 136);
        d.Pin(conflict, 191, 137);
        auto moved = std::move(conflict);
        d.ConcludeWalk(conflict, 190, true, ERROR_NO_MORE_FILES, false, 138);
        d.ConcludeWalk(moved, 190, true, ERROR_NO_MORE_FILES, false, 139);
        for (uint64_t now = 70000; now < 70003; ++now) { Census(d, population, true, now); }
        Frame(frames, L"suppressed", d, 70003);
        Walk(d, key, 190, 190, true, ERROR_NO_MORE_FILES, 71000, 71005);
        for (uint64_t now = 72000; now < 72004; ++now) { Census(d, population, true, now); }
        Frame(frames, L"recovered", d, 72004);
        return L"{" + frames + L"}";
    }
    inline std::wstring Capacity()
    {
        KmonUserModuleDebt d(3);
        std::wstring f;
        Census(d, {Target(10, 100), Target(20, 200), Target(30, 300), Target(40, 400)}, true, 100);
        Walk(d, {40, 0}, 400, 400, true, ERROR_NO_MORE_FILES, 110, 120);
        Frame(f, L"refused", d, 120);
        Census(d, {Target(40, 400), Target(20, 200), Target(30, 300)}, false, 130);
        Frame(f, L"partial_eviction", d, 130);
        Census(d, {Target(20, 201), Target(40, 400)}, true, 140);
        Frame(f, L"retired", d, 140);
        KmonUserModuleDebt full;
        std::vector<KmonUserTarget> population;
        for (uint32_t pid = 10; pid <= 10 + KmonUserModuleDebt::Capacity; ++pid) { population.push_back(Target(pid, pid * 10ull)); }
        Census(full, population, true, 10);
        Frame(f, L"full_size", full, 10);
        return L"{" + f + L"}";
    }
    inline std::wstring Workload(bool growing)
    {
        KmonUserModuleDebt d;
        uint32_t wc = 0, pc = 0, bc = 0, uc = 0;
        std::wstring frames;
        for (uint32_t round = 0; round < 80; ++round)
        {
            const uint64_t now = 100 + round * 10000ull;
            const bool partial = round % 13 == 7, capped = round % 11 == 5;
            const uint32_t size = 26 + (growing ? round : 0);
            std::vector<KmonUserTarget> population;
            std::vector<uint32_t> watched, priority, background, urgent;
            for (uint32_t pid = 100; pid < 100 + size; ++pid)
            {
                const uint64_t generation = pid * 10ull + (pid == 106 && round >= 23 ? 1 : 0);
                population.push_back(Target(pid, generation, true, pid % 9 == 0 ? now + 120001 : 0));
                if (pid % 3 == 0) { watched.push_back(pid); if (pid % 2 == 0) { urgent.push_back(pid); } }
                else if (pid % 3 == 1) { priority.push_back(pid); }
                else { background.push_back(pid); }
            }
            const Key loan = Census(d, population, !partial && !capped, now);
            const uint32_t reservation = capped && !partial ? 99 + size : 0;
            const auto selected = KmonSelectUserPids(watched, priority, background, &wc, &pc, &bc, urgent, &uc,
                reservation ? reservation : loan.first);
            std::wstring picks;
            for (size_t i = 0; i < selected.size(); ++i)
            {
                const auto pid = selected[i]; const uint64_t g = population[pid - 100].CreateTime;
                const auto start = now + 10 * (i + 1);
                const DWORD error = pid == 100 ? ERROR_NOT_SUPPORTED : pid % 13 == 0 ? ERROR_ACCESS_DENIED : ERROR_NO_MORE_FILES;
                Walk(d, {pid, g}, g, g, error == ERROR_NO_MORE_FILES, error, start, start + 4, false, loan == Key{pid, g});
                if (i) { picks += L","; }
                picks += std::to_wstring(pid);
            }
            if (round) { frames += L","; }
            frames += L"{\"loan\":" + std::to_wstring(loan.first) + L",\"generation\":" + std::to_wstring(loan.second) +
                L",\"population_reservation\":" + std::to_wstring(reservation) + L",\"selected\":[" + picks + L"]}";
        }
        return L"{\"rounds\":[" + frames + L"],\"final\":" + d.Json(800100) + L"}";
    }
}

inline std::wstring KmonUserModuleDebtFixturesJson()
{
    using namespace user_module_debt_test;
    return L"{\"synthetic_clock\":true,\"lifecycle\":" + Lifecycle() + L",\"capacity\":" + Capacity() +
        L",\"unsupported_retry\":" + UnsupportedRetry() + L",\"hint_handoff\":" + HintHandoff() +
        L",\"fixed\":" + Workload(false) + L",\"growing\":" + Workload(true) + L"}";
}
