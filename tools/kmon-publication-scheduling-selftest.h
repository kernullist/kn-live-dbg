#pragma once
#include "../user/KmonPublicationScheduling.h"
#include <iostream>
#include <atomic>
#include <chrono>
#include <thread>

inline bool KmonPublicationSchedulingSelfTest()
{
    size_t checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* message)
    { ++checks; if (!ok) { ++failures; std::cerr << "[publication.scheduler] FAIL " << message << "\n"; } };
    KmonPublicationPicker picker;
    std::array<KmonPublicationPending, 4> pending{};
    check(picker.Pick(pending) == KmonPublicationFamily::None && picker.DebtLoans() == 0, "empty does not dispatch or consume a loan slot");
    for (size_t i = 0; i < 4; ++i) { pending[i].Add({{}, i, true}, 1000); }
    std::array<size_t, 4> previous{}, counts{};
    for (size_t turn = 1; turn <= 512; ++turn)
    {
        const auto family = static_cast<size_t>(picker.Pick(pending));
        if (family >= 4) { check(false, "nonempty picker cannot return none"); break; }
        check(family < 4 && (previous[family] == 0 || turn - previous[family] <= 6), "permanent oldest cannot starve a continuously ready family");
        previous[family] = turn; ++counts[family];
    }
    check(picker.DebtLoans() != 0 && std::all_of(counts.begin(), counts.end(), [](size_t count) { return count >= 90; }),
        "bounded loans retain ordinary progress");
    KmonPublicationPending invalid;
    invalid.Add({}, 20); invalid.Add({{}, 21, true}, 20); invalid.Add({{}, 0, true}, 20);
    check(invalid.Count == 3 && invalid.UnknownQueued == 1 && invalid.InvalidClocks == 1 &&
        invalid.OldestKnown && invalid.OldestQueued == 0, "zero, missing and future queue times are distinct");
    KmonPublicationTimings timing;
    KmonPublicationStamp stamp{{10, 20, true}, 30, true};
    timing.Admission(KmonPublicationFamily::Image, true);
    timing.Begin(KmonPublicationFamily::Image, stamp, 40, false, 1);
    timing.Finish(KmonPublicationFamily::Image, stamp, 40, 80, false, {true, true, true, 50, 70});
    timing.Finish(KmonPublicationFamily::Image, stamp, 40, 90, false, {true, false, false, 60, 0});
    timing.Finish(KmonPublicationFamily::Image, stamp, 40, 100, true, {});
    timing.Finish(KmonPublicationFamily::Evidence, {{}, 30, true}, 40, 50, false, {true, false, true, 45, 0});
    const auto normal = timing.Snapshot(KmonPublicationFamily::Image), stopped = timing.Snapshot(KmonPublicationFamily::Image, true);
    check(normal.Attempts == 2 && normal.Complete == 1 && normal.Partial == 1 && normal.Files == 2 && normal.Journals == 1 &&
        normal.InvalidClocks == 0 && stopped.Failed == 1 && stopped.Attempts == 1, "file-only and journal-qualified completion are distinct");
    check(timing.Snapshot(KmonPublicationFamily::Evidence).UnknownAcquisition == 1, "admission cannot invent acquisition freshness");
    const auto validJson = timing.Json({}, 100);
    check(mcpjson::ValidateDocument(validJson) && validJson.find(L"\"active_family\":null") != std::wstring::npos,
        "bounded report and inactive state");
    timing.Finish(KmonPublicationFamily::Page, {{50, 40, true}, 30, true}, 40, 60, false, {true, false, true, 70, 0});
    timing.Finish(KmonPublicationFamily::Page, {}, 40, 39, false, {});
    check(timing.Snapshot(KmonPublicationFamily::Page).InvalidClocks == 3, "invalid acquisition, milestone and service clocks do not underflow");
    std::atomic<bool> done{false};
    std::atomic<bool> valid{true};
    std::atomic<bool> readerReady{false}, observedMiddle{false};
    std::thread reader([&]
    {
        while (!done.load())
        {
            if (!mcpjson::ValidateDocument(timing.Json({}, 1000)) ||
                !mcpjson::ValidateDocument(timing.CollectionJson(L"synthetic:overlap", 1000))) { valid.store(false); }
            readerReady.store(true);
            const auto attempts = timing.Snapshot(KmonPublicationFamily::Irp).Attempts;
            if (attempts > 0 && attempts < 200) { observedMiddle.store(true); }
            std::this_thread::yield();
        }
    });
    const auto observed = [](const std::atomic<bool>& signal)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!signal.load() && std::chrono::steady_clock::now() < deadline) { std::this_thread::yield(); }
        return signal.load();
    };
    const bool started = observed(readerReady);
    for (unsigned i = 0; i < 100; ++i)
    { timing.Finish(KmonPublicationFamily::Irp, stamp, 40, 100, false, {true, true, true, 50, 90}); }
    const bool overlapped = observed(observedMiddle);
    for (unsigned i = 100; i < 200; ++i)
    { timing.Finish(KmonPublicationFamily::Irp, stamp, 40, 100, false, {true, true, true, 50, 90}); }
    done.store(true); reader.join();
    check(started && overlapped && valid.load() && timing.Snapshot(KmonPublicationFamily::Irp).Complete == 200,
        "observed reader overlap cannot tear histogram state");
    timing.Reset();
    check(timing.Snapshot(KmonPublicationFamily::Irp).Attempts == 0, "session reset clears histograms");
    std::cout << "[publication.scheduler] checks=" << checks << " failed=" << failures << "\n";
    return failures == 0;
}

inline std::wstring PublicationSchedulingFixturesJson()
{
    std::wstring scenarios;
    for (unsigned scenario = 0; scenario < 3; ++scenario)
    {
        KmonPublicationPicker picker;
        std::array<std::deque<uint64_t>, 4> queues;
        std::wstring operations;
        const auto add = [&](const std::wstring& row) { if (!operations.empty()) { operations += L","; } operations += row; };
        const auto push = [&](size_t family, uint64_t now)
        {
            const bool admitted = queues[family].size() < 12;
            if (admitted) { queues[family].push_back(now); }
            add(L"{\"op\":\"push\",\"family\":" + std::to_wstring(family) + L",\"now\":" + std::to_wstring(now) +
                L",\"admitted\":" + (admitted ? L"true" : L"false") + L"}");
        };
        for (size_t i = 0; i < 4; ++i) { for (unsigned item = 0; item < 8; ++item) { push(i, i * 20 + item); } }
        for (unsigned turn = 0; turn < 240; ++turn)
        {
            const uint64_t now = 1000 + turn;
            if (scenario != 0)
            {
                push(turn % 4, now);
                if (turn % 2 == 0) { push(0, now); }
                if (scenario == 2 && turn % 9 == 0)
                {
                    const auto family = (turn / 9) % 4;
                    queues[family].clear();
                    add(L"{\"op\":\"clear\",\"family\":" + std::to_wstring(family) + L"}");
                    push(family, now);
                }
            }
            std::array<KmonPublicationPending, 4> ready{};
            for (size_t i = 0; i < 4; ++i) { for (const auto queued : queues[i]) { ready[i].Add({{}, queued, true}, now); } }
            const auto selected = picker.Pick(ready);
            if (selected != KmonPublicationFamily::None) { queues[static_cast<size_t>(selected)].pop_front(); }
            add(L"{\"op\":\"select\",\"family\":" + std::to_wstring(static_cast<size_t>(selected)) +
                L",\"loans\":" + std::to_wstring(picker.DebtLoans()) + L"}");
        }
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += L"{\"name\":" + mcpjson::Quote(scenario == 0 ? L"fixed" : scenario == 1 ? L"growing" : L"clear_reuse") +
            L",\"operations\":[" + operations + L"]}";
    }
    std::wstring collections;
    for (const std::wstring name : {L"complete", L"partial_job", L"failed", L"unknown", L"rejected", L"pending", L"open", L"closing",
        L"empty", L"invalid_acquisition", L"invalid_closure", L"late_admission", L"duplicate_closure", L"sweep_loss", L"irp_unavailable", L"optional_irp",
        L"journal_only", L"failed_closure", L"auxiliary_only"})
    {
        KmonPublicationTimings timing;
        timing.StartCollection(0);
        if (name != L"empty")
        {
            timing.Admission(KmonPublicationFamily::Image, true);
            if (name != L"pending")
            {
                KmonAcquisitionWindow origin{10, 20, true};
                if (name == L"unknown") { origin = {}; }
                if (name == L"invalid_acquisition") { origin = {25, 20, true}; }
                const KmonPublicationStamp stamp{origin, 30, true};
                timing.Begin(KmonPublicationFamily::Image, stamp, 32, false, 0);
                timing.Finish(KmonPublicationFamily::Image, stamp, 32, 36, false,
                    (name == L"failed" || name == L"auxiliary_only") ? KmonPublicationResult{} :
                    name == L"journal_only" ? KmonPublicationResult{false, true, false, 0, 35} :
                    name == L"partial_job" ? KmonPublicationResult{true, false, false, 33, 0} : KmonPublicationResult{true, true, true, 33, 35});
                if (name == L"complete")
                {
                    // Dispatch order is not acquisition order, and tick zero is valid.
                    timing.Admission(KmonPublicationFamily::Page, true);
                    timing.Finish(KmonPublicationFamily::Page, {{0, 5, true}, 31, true}, 36, 38, true, {true, false, true, 37, 0});
                }
            }
        }
        if (name == L"rejected") { timing.Admission(KmonPublicationFamily::Image, false); }
        if (name == L"closing") { timing.BeginClose(KmonCollectionClosePhase::SweepFlush, 40); }
        else if (name != L"open")
        {
            for (size_t i = 0; i < KmonCollectionClosePhases; ++i)
            {
                const auto phase = static_cast<KmonCollectionClosePhase>(i);
                const uint64_t start = 40 + 10 * i;
                const bool required = name != L"optional_irp" || i != 2;
                timing.BeginClose(phase, start, required);
                auto result = KmonPublicationResult{i != 0, i >= 2, true, start + 2, start + 4};
                if (!required || name == L"failed" || name == L"journal_only" || name == L"failed_closure" || name == L"auxiliary_only") { result = {}; }
                if (name == L"invalid_closure" && i == 3) { result.JournalMs = start - 1; }
                timing.FinishClose(phase, start + 6, result);
            }
            timing.FinishCollection(100, {name == L"sweep_loss" ? 1ull : 0ull, 0, name == L"irp_unavailable" ? 1ull : 0ull,
                name == L"auxiliary_only" ? 1ull : 0ull});
            if (name == L"late_admission") { timing.Admission(KmonPublicationFamily::Page, true); }
            if (name == L"duplicate_closure") { timing.FinishCollection(200); }
        }
        if (!collections.empty()) { collections += L","; }
        collections += L"{\"name\":" + mcpjson::Quote(name) + L",\"report\":" + timing.CollectionJson(L"synthetic:collection", 300) + L"}";
    }
    return L"{\"schema\":\"kn.publication_picker_test.v1\",\"scenarios\":[" + scenarios + L"],\"collections\":[" + collections + L"]}";
}
