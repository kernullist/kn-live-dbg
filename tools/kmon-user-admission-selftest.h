#pragma once
#include "../user/KmonUserInventory.h"
#include "../user/KmonHandleTracking.h"
#include <stdexcept>

namespace user_admission_test
{
    struct Source
    {
        const std::vector<uint32_t>& Rows;
        unsigned Pass;
        std::wstring Mode;
        size_t Index = 0;
        bool Opened = false;
        unsigned ReadsOf107 = 0;

        bool Open() { Opened = Mode != L"open_error"; return Opened; }
        void Close() noexcept { Opened = false; }
        KmonUserInventoryRead Next(KmonUserTarget& target)
        {
            if (Mode == L"walk_error" && Index == 13) { return KmonUserInventoryRead::Error; }
            if (Index == Rows.size()) { return KmonUserInventoryRead::End; }
            target.Pid = Rows.at(Index++); target.Leaf = L"snapshot-hint";
            return KmonUserInventoryRead::Row;
        }
        uint64_t Generation(uint32_t pid) const
        {
            if (pid == 111) { return 0; }
            return pid * 10ull + (pid == 104 && Pass >= 16 ? 1 : 0);
        }
        void Resolve(KmonUserTarget& target)
        {
            if (Mode == L"fault" && target.Pid == 108) { throw std::runtime_error("fixture resolve failure"); }
            target.CreateTime = Generation(target.Pid);
            if (target.Pid == 107 && ++ReadsOf107 > 1) { ++target.CreateTime; }
            if (target.CreateTime) { target.ImagePath = L"pinned"; }
            target.HighPriority = target.Pid % 3 == 0;
        }
    };

    inline std::wstring Numbers(const std::vector<uint32_t>& values)
    {
        std::wstring json = L"[";
        for (auto value : values)
        {
            if (json.size() > 1) { json += L","; }
            json += std::to_wstring(value);
        }
        return json + L"]";
    }

    inline std::wstring Scenario(const std::wstring& name, bool* passed)
    {
        KmonUserInventoryPosition previous;
        uint32_t watchedAfter = 0, priorityAfter = 0, backgroundAfter = 0, urgentAfter = 0;
        std::wstring frames;
        const unsigned passes = (name == L"fixed" || name == L"growing" || name == L"churn") ? 96 : 3;
        for (unsigned pass = 0; pass < passes; ++pass)
        {
            std::vector<uint32_t> rows, watches, suspectPids;
            if (name != L"watch_cap" && name != L"suspect_cap")
            {
                for (uint32_t p = 100; p < 119; ++p)
                {
                    if (name != L"churn" || p != 104 || pass < 8 || pass >= 16) { rows.push_back(p); }
                }
                if (name == L"growing")
                { for (unsigned i = 0; i <= pass; ++i) { rows.push_back(1000 + i); } }
                if (name == L"churn")
                {
                    std::rotate(rows.begin(), rows.begin() + pass % rows.size(), rows.end());
                    if (pass % 2) { std::reverse(rows.begin(), rows.end()); }
                }
                rows.insert(rows.end(), {0, 4, 99, 118, 118});
            }
            if (name != L"suspect_cap")
            {
                watches = {101, 105, 108};
                if (name == L"restore_watch") { watches.push_back(107); }
                for (uint32_t p = 300; p < 320; ++p) { watches.push_back(p); }
                watches.insert(watches.end(), {319, 319, 4, 99});
            }
            suspectPids = {104, 107, 111, 118};
            if (name == L"restore_suspect") { suspectPids.push_back(107); }
            for (uint32_t p = 500; p < 521; ++p) { suspectPids.push_back(p); }
            suspectPids.insert(suspectPids.end(), {520, 520, 4, 99});
            std::vector<KmonUserTarget> suspects;
            bool saw107 = false;
            for (auto pid : suspectPids)
            {
                KmonUserTarget t; t.Pid = pid;
                t.CreateTime = pid == 107 || pid == 111 ? 777 : pid * 10ull;
                if (pid == 107 && std::exchange(saw107, true)) { t.CreateTime = 1070; }
                t.Eprocess = pid * 100ull; t.ImagePath = t.Leaf = L"suspect";
                suspects.push_back(std::move(t));
            }
            const auto mode = name == L"churn" && pass % 11 == 4 ? std::wstring(L"walk_error") : name;
            uint64_t now = 100 + pass * 1000;
            KmonUserInventory<Source, 8, 14, 18> inventory(Source{rows, pass, mode}, watches, std::move(suspects), 99, now, previous);
            bool fault = false;
            unsigned turns = 0;
            for (; turns < 64; ++turns)
            {
                try
                {
                    const auto result = inventory.Run([&]() { return mode == L"final_clock" && inventory.Complete() ? now - 1 : now; },
                        [&]() { return mode == L"stop" && turns == 2; });
                    if (result != KmonDiscoveryDispatch::Continued) { break; }
                }
                catch (const std::runtime_error&) { fault = true; break; }
                ++now;
            }
            const auto proposed = inventory.Reservation();
            const auto state = inventory.Json(now);
            const auto targets = inventory.Take();
            std::vector<uint32_t> watched, priority, background, urgent;
            std::wstring identities;
            for (const auto& target : targets)
            {
                const auto pid = target.Pid;
                const bool watch = std::find(watches.begin(), watches.end(), pid) != watches.end();
                (watch ? watched : target.HighPriority ? priority : background).push_back(pid);
                if (watch && pid % 2 == 0) { urgent.push_back(pid); }
                if (!identities.empty()) { identities += L","; }
                identities += L"[" + std::to_wstring(pid) + L"," + std::to_wstring(target.CreateTime) + L"," +
                    std::to_wstring(target.Eprocess) + L"," + mcpjson::Quote(target.ImagePath) + L"]";
            }
            const auto selected = KmonSelectUserPids(watched, priority, background, &watchedAfter,
                &priorityAfter, &backgroundAfter, urgent, &urgentAfter, proposed.AfterPid);
            *passed = *passed && turns < 64 && !inventory.SourceState().Opened && selected.size() <= 8 &&
                (!proposed.AfterPid || std::find(selected.begin(), selected.end(), proposed.AfterPid) != selected.end());
            if (!frames.empty()) { frames += L","; }
            frames += L"{\"rows\":" + Numbers(rows) + L",\"watches\":" + Numbers(watches) +
                L",\"suspects\":" + Numbers(suspectPids) + L",\"mode\":" + mcpjson::Quote(mode) +
                L",\"reads_107\":" + std::to_wstring(inventory.SourceState().ReadsOf107) +
                L",\"fault\":" + (fault ? L"true" : L"false") + L",\"state\":" + state +
                L",\"targets\":[" + identities + L"],\"selected\":" + Numbers(selected) +
                L",\"tier_cursors\":" + Numbers({watchedAfter, priorityAfter, backgroundAfter, urgentAfter}) + L"}";
            if (proposed.AfterPid) { previous = proposed; }
        }
        return L"{\"name\":" + mcpjson::Quote(name) + L",\"frames\":[" + frames + L"]}";
    }
}

inline std::wstring KmonUserAdmissionFixturesJson(bool* passed)
{
    *passed = true;
    std::wstring scenarios;
    for (const wchar_t* name : {L"fixed", L"growing", L"churn", L"watch_cap", L"suspect_cap",
        L"open_error", L"walk_error", L"stop", L"fault", L"final_clock", L"restore_watch", L"restore_suspect"})
    {
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += user_admission_test::Scenario(name, passed);
    }
    return L"{\"limits\":[8,14,18],\"synthetic_clock\":true,\"scenarios\":[" + scenarios + L"]}";
}
