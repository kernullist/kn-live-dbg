#pragma once
#include "../user/KmonUserInventory.h"
#include <iostream>
#include <stdexcept>

namespace user_inventory_test
{
    struct State
    {
        std::wstring Name;
        std::vector<uint32_t> Rows;
        uint64_t Now = 100, Opens = 0, Closes = 0, Queries = 0;
        size_t Cursor = 0;
        bool Open = false;
    };
    struct Source
    {
        std::shared_ptr<State> S;
        void Close() noexcept { if (S->Open) { S->Open = false; ++S->Closes; } }
        bool Open()
        {
            if (S->Name == L"open_error") { return false; }
            ++S->Opens; S->Open = true;
            if (S->Name == L"slow_open") { S->Now += 80; }
            return true;
        }
        KmonUserInventoryRead Next(KmonUserTarget& target)
        {
            S->Now += S->Name == L"fast" ? 0 : 1;
            if (S->Name == L"walk_error" && S->Cursor == 40) { return KmonUserInventoryRead::Error; }
            if (S->Cursor == S->Rows.size()) { return KmonUserInventoryRead::End; }
            target.Pid = S->Rows[S->Cursor++]; target.Leaf = L"hint.exe";
            return KmonUserInventoryRead::Row;
        }
        void Resolve(KmonUserTarget& target)
        {
            ++S->Queries; S->Now += S->Name == L"slow_query" ? 40 : S->Name == L"fast" ? 0 : 2;
            if (S->Name == L"fault" && target.Pid == 130) { throw std::runtime_error("owned resolver fault"); }
            target.CreateTime = target.Pid == 160 ? 0 : target.Pid * 10ull;
            if (target.CreateTime) { target.ImagePath = L"owned.exe"; }
            target.HighPriority = target.Pid % 2 == 0;
        }
    };
    inline std::wstring Fixture(const std::wstring& name, bool* passed)
    {
        const auto s = std::make_shared<State>(); s->Name = name;
        if (name != L"empty" && name != L"watch_cap" && name != L"suspect_cap")
        {
            const uint32_t size = name == L"cap" ? 4300 : 100;
            for (uint32_t i = 0; i < size; ++i) { s->Rows.push_back(100 + i); }
            s->Rows.push_back(0); s->Rows.push_back(100); s->Rows.push_back(4);
        }
        std::vector<uint32_t> watches = name == L"watch_suspect" || name == L"open_error" ?
            std::vector<uint32_t>{102, 600, 601, 600, 4, 150} : std::vector<uint32_t>{};
        std::vector<KmonUserTarget> suspects;
        if (name == L"watch_cap" || name == L"suspect_cap")
        { for (uint32_t pid = 8000; pid < 17000; ++pid) { watches.push_back(pid); } }
        if (name == L"suspect_cap")
        {
            for (uint32_t pid = 30000; pid < 34300; ++pid)
            {
                KmonUserTarget t; t.Pid = pid; t.CreateTime = pid * 10ull; t.Eprocess = pid * 100ull;
                t.ImagePath = t.Leaf = L"suspect.exe"; suspects.push_back(std::move(t));
            }
        }
        if (name == L"watch_suspect")
        {
            for (uint32_t pid : {160, 165, 170, 700, 4, 150})
            {
                KmonUserTarget t; t.Pid = pid; t.CreateTime = pid == 160 || pid == 170 ? 777 : pid * 10ull;
                t.Eprocess = pid * 100ull; t.ImagePath = L"suspect.exe"; t.Leaf = L"suspect.exe"; suspects.push_back(t);
            }
        }
        std::wstring frames, report, rows;
        bool fault = false;
        {
            KmonUserInventory<Source> inventory(Source{s}, watches, suspects, 150, s->Now);
            for (unsigned turn = 0; turn < 10000; ++turn)
            {
                if (name == L"clock" && turn == 1) { s->Now -= 70; }
                const auto begin = s->Now;
                auto result = KmonDiscoveryDispatch::Cancelled;
                try { result = inventory.Run([&]() { return s->Now; }, [&]() { return name == L"stop" && turn == 1; }); }
                catch (const std::runtime_error&) { fault = true; }
                report = inventory.Json(s->Now);
                if (!frames.empty()) { frames += L","; }
                frames += L"{\"begin\":" + std::to_wstring(begin) + L",\"end\":" + std::to_wstring(s->Now) +
                    L",\"result\":" + std::to_wstring(static_cast<unsigned>(result)) + L",\"state\":" + report + L"}";
                if (fault || result != KmonDiscoveryDispatch::Continued) { break; }
                s->Now += 7;
            }
            *passed = *passed && (inventory.Complete() || name == L"stop" || name == L"clock" || fault);
            const auto targets = inventory.Take();
            for (const auto& t : targets)
            {
                if (!rows.empty()) { rows += L","; }
                rows += L"[" + std::to_wstring(t.Pid) + L"," + std::to_wstring(t.CreateTime) + L"," +
                    std::to_wstring(t.Eprocess) + L"," + (t.Suspect ? L"true" : L"false") + L"," +
                    mcpjson::Quote(t.ImagePath) + L"]";
            }
        }
        *passed = *passed && !s->Open && s->Closes == s->Opens && mcpjson::ValidateDocument(report);
        return L"{\"name\":" + mcpjson::Quote(name) + L",\"fault\":" + (fault ? L"true" : L"false") +
            L",\"opens\":" + std::to_wstring(s->Opens) + L",\"closes\":" + std::to_wstring(s->Closes) +
            L",\"queries\":" + std::to_wstring(s->Queries) + L",\"frames\":[" + frames + L"],\"targets\":[" + rows + L"]}";
    }
}
inline std::wstring UserInventoryFixturesJson(bool* passed)
{
    *passed = true; std::wstring scenarios;
    for (const std::wstring name : {L"fixed", L"fast", L"slow_open", L"slow_query", L"empty", L"open_error", L"walk_error",
        L"cap", L"watch_cap", L"suspect_cap", L"watch_suspect", L"stop", L"fault", L"clock"})
    {
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += user_inventory_test::Fixture(name, passed);
    }
    return L"{\"schema\":\"kn.user_inventory_fixtures.v1\",\"synthetic_clock\":true,\"scenarios\":[" + scenarios + L"]}";
}
inline bool KmonUserInventorySelfTest()
{
    bool passed = false; const auto json = UserInventoryFixturesJson(&passed);
    passed = passed && mcpjson::ValidateDocument(json);
    passed = passed && !KmonUserInventoryInvalidates(100, 101, 10, false, 0, true) &&
        !KmonUserInventoryInvalidates(100, 100, 10, true, 9, true) &&
        !KmonUserInventoryInvalidates(100, 99, 10, false, 0, false) &&
        !KmonUserInventoryInvalidates(100, 99, 10, true, 0, true) &&
        !KmonUserInventoryInvalidates(100, 99, 10, true, 10, true) &&
        KmonUserInventoryInvalidates(100, 99, 10, true, 11, false) &&
        KmonUserInventoryInvalidates(100, 99, 10, false, 0, true);
    std::cerr << "[user.inventory] scenarios=14 retirement_controls=7 passed=" << passed << "\n";
    return passed;
}
