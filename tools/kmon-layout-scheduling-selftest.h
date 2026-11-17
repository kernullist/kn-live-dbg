#pragma once
#include "../user/KmonLayoutScheduling.h"
#include <iostream>
#include <atomic>
#include <chrono>
#include <thread>

inline ProcessLayoutCandidate LayoutSchedulingWork(uint32_t pid, uint64_t generation, size_t lane, uint64_t address, uint64_t observed)
{
    ProcessLayoutCandidate item;
    item.Identity.BootId = L"synthetic:layout-scheduling"; item.Identity.ProcessId = pid; item.Identity.CreateTime = generation;
    item.Region = {address, 4096, address, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_PRIVATE};
    item.Role = lane == 0 ? L"layout_change" : L"layout_periodic"; item.ObservedMs = observed;
    return item;
}

inline bool KmonLayoutSchedulingSelfTest()
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* why)
    { ++checks; if (!ok) { ++failures; std::cerr << "[layout.queue] FAIL " << why << '\n'; } };
    KmonLayoutQueue queue;
    for (size_t i = 0; i < 8; ++i)
    { check(queue.Admit(LayoutSchedulingWork(100, 1, 1, 0x10000 + i * 4096, 1), 10) == KmonLayoutAdmission::Queued, "subject periodic slots"); }
    check(queue.Admit(LayoutSchedulingWork(100, 1, 1, 0x90000, 1), 10) == KmonLayoutAdmission::SubjectClassLimit, "subject class cap");
    for (size_t i = 0; i < 8; ++i)
    { check(queue.Admit(LayoutSchedulingWork(100, 1, 0, 0x10000 + i * 4096, 1), 10) == KmonLayoutAdmission::Queued, "subject changed slots"); }
    check(queue.Admit(LayoutSchedulingWork(100, 1, 0, 0x90000, 1), 10) == KmonLayoutAdmission::SubjectLimit, "subject total cap");
    for (uint32_t pid = 101; pid < 116; ++pid)
    { for (size_t i = 0; i < 8; ++i) { check(queue.Admit(LayoutSchedulingWork(pid, 1, 1, 0x10000 + i * 4096, 1), 10) == KmonLayoutAdmission::Queued, "class reserve fill"); } }
    check(queue.Admit(LayoutSchedulingWork(200, 1, 1, 0x10000, 1), 10) == KmonLayoutAdmission::ClassLimit, "periodic cannot consume changed reserve");
    for (uint32_t pid = 101; pid < 104; ++pid)
    { for (size_t i = 0; i < 8; ++i) { check(queue.Admit(LayoutSchedulingWork(pid, 1, 0, 0x10000 + i * 4096, 1), 10) == KmonLayoutAdmission::Queued, "changed reserved slots"); } }
    check(queue.Size() == 160 && queue.Admit(LayoutSchedulingWork(200, 1, 0, 0x10000, 1), 10) == KmonLayoutAdmission::GlobalLimit, "global cap");
    check(queue.Admit(LayoutSchedulingWork(100, 1, 1, 0x10000, 99), 100) == KmonLayoutAdmission::Rediscovered, "rediscovery permitted at capacity");
    check(queue.Admit(LayoutSchedulingWork(100, 1, 1, 0x10000, 98), 100) == KmonLayoutAdmission::Invalid, "out of order rediscovery cannot rewind last seen");
    ProcessLayoutCandidate item;
    size_t taken = 0, pinned = 0;
    while (queue.Pop(&item, 200))
    {
        ++taken;
        if (item.Identity.ProcessId == 100 && item.Region.Base == 0x10000 && KmonLayoutQueue::Class(item) == 1)
        { check(item.ObservedMs == 1 && item.QueuedMs == 10 && item.LastObservedMs == 99 && item.Rediscoveries == 1, "original deadline and pending time pinned"); ++pinned; }
        queue.Finish(item, 200, 201, false, KmonLayoutOutcome::MappingCurrent, 201);
    }
    check(taken == 160 && pinned == 1 && queue.Snapshot().Qualified == 160 && queue.Snapshot().InvalidClocks == 0, "all admitted scopes complete exactly once");
    check(mcpjson::ValidateDocument(queue.Json(300)), "bounded valid report");
    queue.Reset();
    for (uint32_t pid = 100; pid < 116; ++pid)
    { for (size_t i = 0; i < 8; ++i) { check(queue.Admit(LayoutSchedulingWork(pid, 1, 0, 0x10000 + i * 4096, 1), 10) == KmonLayoutAdmission::Queued, "changed flood"); } }
    check(queue.Admit(LayoutSchedulingWork(200, 1, 0, 0x10000, 1), 10) == KmonLayoutAdmission::ClassLimit &&
        queue.Admit(LayoutSchedulingWork(200, 1, 1, 0x10000, 1), 10) == KmonLayoutAdmission::Queued, "changed flood leaves periodic admission");
    queue.Reset();
    auto same = LayoutSchedulingWork(100, 1, 1, 0x10000, 1);
    check(KmonLayoutQueue::Accepted(queue.Admit(same, 10)) && queue.Pop(&item, 20), "first attempt starts");
    check(queue.Admit(same, 21) == KmonLayoutAdmission::Busy, "source retains rediscovery while original is in flight");
    queue.Finish(item, 20, 30, false, KmonLayoutOutcome::MappingCurrent, 25);
    same.ObservedMs = 40;
    check(KmonLayoutQueue::Accepted(queue.Admit(same, 45)) && queue.Pop(&item, 50), "new observation after completed attempt");
    queue.Finish(item, 50, 60, true, KmonLayoutOutcome::Rejected);
    const auto failed = queue.Json(60);
    check(failed.find(L"\"last_mapping_success_ms\":\"25\"") != std::wstring::npos && queue.Snapshot().Qualified == 1 &&
        queue.Snapshot(true).Qualified == 0 && queue.Snapshot(true).Attempts == 1, "failed shutdown cannot refresh last success");
    same.ObservedMs = 70;
    check(KmonLayoutQueue::Accepted(queue.Admit(same, 75)) && queue.Pop(&item, 80), "invalid timing control starts");
    queue.Finish(item, 80, 79, false, KmonLayoutOutcome::Fault);
    check(queue.Snapshot().InvalidClocks == 1 && queue.Snapshot().Qualified == 1, "backward service clock does not underflow or qualify");
    queue.Reset();
    same = LayoutSchedulingWork(100, 1, 1, 0x10000, 1);
    check(queue.Admit(same, 10) == KmonLayoutAdmission::Queued, "original queued before expiry");
    same.ObservedMs = 40000;
    check(queue.Admit(same, 40000) == KmonLayoutAdmission::ExpiredOriginal && queue.Pop(&item, 40001) && item.ObservedMs == 1,
        "new observation stays at source until expired original is consumed");
    queue.Finish(item, 40001, 40002, false, KmonLayoutOutcome::Expired);
    check(queue.Admit(same, 40003) == KmonLayoutAdmission::Queued && queue.Pop(&item, 40004) && item.ObservedMs == 40000,
        "source retry gets its own validation after original expiry");
    queue.Finish(item, 40004, 40005, false, KmonLayoutOutcome::MappingCurrent, 40005);
    check(queue.Snapshot().Attempts == 2 && queue.Snapshot().Qualified == 1 && queue.Snapshot().Outcomes[static_cast<size_t>(KmonLayoutOutcome::Expired)] == 1,
        "new success does not erase expired attempt population");
    queue.Reset();
    same = LayoutSchedulingWork(100, 1, 1, 0x10000, 1);
    check(KmonLayoutQueue::Accepted(queue.Admit(same, 10)), "unknown identity assertion original");
    same.Identity.Eprocess = 0x100;
    check(queue.Admit(same, 10) == KmonLayoutAdmission::Queued, "known pointer does not replace unknown original");
    same.Identity.Eprocess = 0x200;
    check(queue.Admit(same, 10) == KmonLayoutAdmission::Queued && queue.Size() == 3 && queue.Replacements() == 0,
        "unknown assertion cannot bridge contradictory known pointers");
    same.Identity.SessionKnown = true; same.Identity.SessionId = 1;
    check(queue.Admit(same, 10) == KmonLayoutAdmission::Queued, "known session assertion original");
    same.Identity.SessionId = 2;
    check(queue.Admit(same, 10) == KmonLayoutAdmission::Queued && queue.Size() == 5, "conflicting session is not coalesced");
    queue.Reset();
    std::atomic<bool> done{false}, ready{false}, middle{false}, valid{true};
    std::thread reader([&]
    {
        while (!done.load())
        {
            if (!mcpjson::ValidateDocument(queue.Json(10000))) { valid.store(false); }
            ready.store(true);
            const auto attempts = queue.Snapshot().Attempts;
            if (attempts > 0 && attempts < 200) { middle.store(true); }
            std::this_thread::yield();
        }
    });
    const auto waitObserved = [](const std::atomic<bool>& signal)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!signal.load() && std::chrono::steady_clock::now() < deadline) { std::this_thread::yield(); }
        return signal.load();
    };
    const bool began = waitObserved(ready);
    bool observed = false, completed = true;
    for (unsigned i = 0; i < 200; ++i)
    {
        completed &= KmonLayoutQueue::Accepted(queue.Admit(LayoutSchedulingWork(100, 1, 1, 0x10000, 100 + i), 1000 + i)) && queue.Pop(&item, 2000);
        queue.Finish(item, 2000, 2001, false, KmonLayoutOutcome::MappingCurrent, 2001);
        if (i == 99) { observed = waitObserved(middle); }
    }
    done.store(true); reader.join();
    check(began && observed && completed && valid.load() && queue.Snapshot().Qualified == 200,
        "observed reader overlap preserves admitted and completed snapshots");
    queue.Reset();
    for (unsigned i = 0; i < 700; ++i)
    {
        auto work = LayoutSchedulingWork(100, 1, 1, 0x10000 + uint64_t(i) * 4096, 1);
        check(KmonLayoutQueue::Accepted(queue.Admit(work, 10)) && queue.Pop(&item, 20), "bounded history turnover");
        queue.Finish(item, 20, 30, false, KmonLayoutOutcome::Expired);
    }
    const auto trimmed = queue.Json(100);
    check(trimmed.find(L"\"history_resident\":\"512\"") != std::wstring::npos &&
        trimmed.find(L"\"history_evicted\":\"188\"") != std::wstring::npos, "eviction is reported without inventing all-time scope coverage");
    queue.Reset();
    same = LayoutSchedulingWork(100, 1, 1, 0x10000, 1); same.ImageName.assign(32768, wchar_t{1});
    check(KmonLayoutQueue::Accepted(queue.Admit(same, 10)), "bounded maximum mapped name accepted");
    const auto bounded = queue.Json(100);
    check(bounded.size() < 80000 && bounded.find(L"\"history_omitted\":\"1\"") != std::wstring::npos &&
        mcpjson::ValidateDocument(bounded), "escaped scope rows obey byte-independent UTF16 detail cap");
    std::cout << "[layout.queue] checks=" << checks << " failed=" << failures << '\n';
    return failures == 0;
}

inline std::wstring LayoutQueueSchedulingFixturesJson()
{
    std::wstring scenarios;
    for (unsigned scenario = 0; scenario < 3; ++scenario)
    {
        KmonLayoutQueue queue;
        std::wstring operations;
        const auto add = [&](const std::wstring& row) { if (!operations.empty()) { operations += L","; } operations += row; };
        const auto push = [&](uint32_t pid, uint64_t generation, size_t lane, uint64_t address, uint64_t observed, uint64_t now)
        {
            const auto result = queue.Admit(LayoutSchedulingWork(pid, generation, lane, address, observed), now);
            add(L"{\"op\":\"admit\",\"pid\":" + std::to_wstring(pid) + L",\"generation\":" + std::to_wstring(generation) +
                L",\"lane\":" + std::to_wstring(lane) + L",\"base\":" + std::to_wstring(address) + L",\"observed\":" + std::to_wstring(observed) +
                L",\"now\":" + std::to_wstring(now) + L",\"result\":" + mcpjson::Quote(KmonLayoutAdmissionName(result)) + L"}");
        };
        for (uint32_t pid = 100; pid < 104; ++pid)
        { for (size_t lane = 0; lane < 2; ++lane) { for (unsigned i = 0; i < 4; ++i) { push(pid, 1, lane, 0x10000 + i * 4096, pid + i, 1000); } } }
        for (unsigned turn = 0; turn < 300; ++turn)
        {
            const uint64_t now = 2000 + turn * 4;
            if (scenario != 0)
            {
                push(100 + turn % 32, scenario == 2 ? 1 + turn / 32 : 1, turn % 2, 0x100000 + uint64_t(turn) * 4096, now, now);
                push(100, 1, 0, 0x800000 + uint64_t(turn) * 4096, now, now);
                if (turn % 7 == 0) { push(100, 1, 1, 0x10000, now, now); }
            }
            ProcessLayoutCandidate selected;
            if (queue.Pop(&selected, now + 1))
            {
                add(L"{\"op\":\"pop\",\"pid\":" + std::to_wstring(selected.Identity.ProcessId) + L",\"generation\":" + std::to_wstring(selected.Identity.CreateTime) +
                    L",\"lane\":" + std::to_wstring(KmonLayoutQueue::Class(selected)) + L",\"base\":" + std::to_wstring(selected.Region.Base) +
                    L",\"observed\":" + std::to_wstring(selected.ObservedMs) + L",\"queued\":" + std::to_wstring(selected.QueuedMs) +
                    L",\"last_seen\":" + std::to_wstring(selected.LastObservedMs) + L",\"rediscoveries\":" + std::to_wstring(selected.Rediscoveries) + L"}");
                queue.Finish(selected, now + 1, now + 2, false, KmonLayoutOutcome::MappingCurrent, now + 2);
            }
            else { add(L"{\"op\":\"empty\"}"); }
        }
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += L"{\"name\":" + mcpjson::Quote(scenario == 0 ? L"fixed" : scenario == 1 ? L"growing_flood" : L"instance_reuse") + L",\"operations\":[" + operations + L"]}";
    }
    return L"[" + scenarios + L"]";
}
