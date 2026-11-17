#pragma once
#include "../user/KmonReferenceScheduling.h"
#include <iostream>

inline KmonExecutionReferenceWork ReferenceTestWork(uint32_t pid, const std::wstring& role, uint64_t target, uint64_t now)
{
    KmonExecutionReferenceWork work;
    work.Identity = {L"owned-synthetic-boot", pid, pid == 0 ? 0 : 1000 + pid};
    work.Role = role;
    work.Target = target;
    work.Slot = target + 8;
    work.ObservedMs = now;
    work.ObservedAt = now + 100000;
    work.Anchors = {{target, {static_cast<uint8_t>(now & 255)}}};
    work.ExpectedPeb = now + 9000;
    return work;
}

inline std::wstring ReferenceSchedulingFixturesJson()
{
    std::wstring scenarios;
    for (unsigned scenario = 0; scenario != 3; ++scenario)
    {
        KmonReferenceQueue queue;
        std::wstring operations;
        const auto n = [](uint64_t value) { return std::to_wstring(value); };
        const auto identity = [&](const KmonExecutionReferenceWork& work)
        {
            return L"\"pid\":" + n(work.Identity.ProcessId) + L",\"create_time\":" + n(work.Identity.CreateTime) +
                L",\"role\":" + mcpjson::Quote(work.Role) + L",\"target\":" + n(work.Target) + L",\"slot\":" + n(work.Slot);
        };
        const auto add = [&](const std::wstring& value) { if (!operations.empty()) { operations += L","; } operations += value; };
        const auto admit = [&](KmonExecutionReferenceWork work)
        {
            const auto result = queue.Admit(work);
            add(L"{\"op\":\"admit\"," + identity(work) + L",\"ms\":" + n(work.ObservedMs) +
                L",\"result\":" + mcpjson::Quote(KmonReferenceAdmissionName(result)) + L"}");
        };
        const auto pop = [&](uint64_t now, KmonReferenceOutcome result, bool shutdown = false)
        {
            if (queue.empty()) { return; }
            const auto work = queue.Pop();
            const bool started = queue.Start(work, now);
            const auto outcome = started ? result : (now < work.ObservedMs ? KmonReferenceOutcome::InvalidClock : KmonReferenceOutcome::Expired);
            queue.Finish(work, now, now + 1, outcome, shutdown);
            add(L"{\"op\":\"pop\"," + identity(work) + L",\"ms\":" + n(now) + L",\"end\":" + n(now + 1) +
                L",\"started\":" + (started ? L"true" : L"false") + L",\"shutdown\":" + (shutdown ? L"true" : L"false") +
                L",\"outcome\":" + mcpjson::Quote(KmonReferenceOutcomeName(outcome)) + L",\"original_ms\":" + n(work.ObservedMs) +
                L",\"original_at\":" + n(work.ObservedAt) + L",\"anchor\":" + n(work.Anchors.front().Bytes.front()) + L",\"peb\":" + n(work.ExpectedPeb) + L"}");
        };
        const auto snapshot = [&](uint64_t now) { add(L"{\"op\":\"snapshot\",\"report\":" + queue.Json(now) + L"}"); };
        if (scenario == 0)
        {
            for (uint32_t pid = 1; pid <= 5; ++pid)
            {
                for (unsigned role = 0; role != 3; ++role)
                {
                    for (uint64_t i = 0; i != 5; ++i) { admit(ReferenceTestWork(pid, L"role" + n(role), 100 + i, 100)); }
                }
            }
            auto duplicate = ReferenceTestWork(1, L"role0", 100, 190);
            duplicate.Identity.Eprocess = 123;
            admit(duplicate);
            snapshot(200);
            for (unsigned i = 0; i != 75; ++i)
            { pop(210 + i, i % 4 == 0 ? KmonReferenceOutcome::ReadUnavailable : KmonReferenceOutcome::Observed); }
            snapshot(300);
            admit(ReferenceTestWork(1, L"role0", 100, 400));
            admit(ReferenceTestWork(1, L"role0", 100, 11000));
            pop(11010, KmonReferenceOutcome::Observed);
            admit(ReferenceTestWork(1, L"role0", 100, 22000));
            pop(22010, KmonReferenceOutcome::Inconsistent);
            snapshot(23000);
            admit(ReferenceTestWork(1, L"role0", 100, 33000));
            pop(64000, KmonReferenceOutcome::Observed, true);
            snapshot(65000);
        }
        else if (scenario == 1)
        {
            for (uint64_t i = 0; i != 160; ++i) { admit(ReferenceTestWork(1, L"flood", i + 1, 100)); }
            for (unsigned role = 1; role != 6; ++role)
            { for (uint64_t i = 0; i != 17; ++i) { admit(ReferenceTestWork(1, L"role" + n(role), i + 1, 100)); } }
            for (uint32_t pid = 2; pid <= 5; ++pid) { admit(ReferenceTestWork(pid, L"quiet", 1, 100)); }
            for (unsigned i = 0; i != 80; ++i)
            {
                pop(200 + i * 2, KmonReferenceOutcome::Observed);
                admit(ReferenceTestWork(1, L"flood", 1000 + i, 201 + i * 2));
                admit(ReferenceTestWork(10 + i, L"arriving", 1000 + i, 201 + i * 2));
            }
            snapshot(400);
            uint64_t tick = 500;
            while (!queue.empty()) { pop(tick++, KmonReferenceOutcome::ReadUnavailable, true); }
            snapshot(tick + 1);
        }
        else
        {
            for (unsigned role = 0; role != 4; ++role)
            {
                for (uint32_t pid = 1; pid <= 16; ++pid)
                { for (uint64_t i = 0; i != 16; ++i) { admit(ReferenceTestWork(pid, L"role" + n(role), i + 1, 100)); } }
                if (role == 0) { admit(ReferenceTestWork(17, L"role0", 1, 100)); }
            }
            for (unsigned i = 0; i != 160; ++i) { admit(ReferenceTestWork(100 + i, L"overflow", i + 1, 100)); }
            snapshot(30200);
            uint64_t tick = 30201;
            while (!queue.empty()) { pop(tick++, KmonReferenceOutcome::Observed); }
            auto reused = ReferenceTestWork(1, L"role0", 1, 33000);
            reused.Identity.CreateTime += 99999;
            admit(reused);
            pop(33001, KmonReferenceOutcome::Observed);
            snapshot(34000);
        }
        if (!scenarios.empty()) { scenarios += L","; }
        scenarios += L"{\"id\":" + n(scenario) + L",\"operations\":[" + operations + L"]}";
    }
    return L"{\"schema\":\"kn.reference_scheduler_fixtures.v1\",\"scenarios\":[" + scenarios + L"]}";
}

inline bool KmonReferenceSchedulingSelfTest()
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool value) { ++checks; if (!value) { ++failures; std::cerr << "[reference.scheduler] failed " << checks << "\n"; } };
    KmonReferenceQueue queue;
    auto original = ReferenceTestWork(1, L"owned", 100, 100);
    check(queue.Admit(original) == KmonReferenceAdmission::Queued);
    auto later = original;
    later.ObservedMs = 200;
    later.Anchors[0].Bytes[0] = 0;
    later.ExpectedPeb = 0;
    check(queue.Admit(later) == KmonReferenceAdmission::Duplicate);
    auto work = queue.Pop();
    check(work.ObservedMs == 100 && work.Anchors[0].Bytes[0] == 100 && work.ExpectedPeb == 9100);
    check(queue.Start(work, 210));
    queue.Finish(work, 210, 220, KmonReferenceOutcome::Observed, false);
    check(queue.Find(work)->LastSuccess == 220 && queue.Find(work)->LastAttempt == 210);
    later.ObservedMs = 11000;
    check(queue.Admit(later) == KmonReferenceAdmission::Queued);
    work = queue.Pop(); check(queue.Start(work, 11010));
    queue.Finish(work, 11010, 11020, KmonReferenceOutcome::ReadUnavailable, false);
    check(queue.Find(work)->LastSuccess == 220 && queue.Find(work)->LastAttempt == 11010);
    later.ObservedMs = 22000;
    check(queue.Admit(later) == KmonReferenceAdmission::Queued);
    work = queue.Pop(); check(!queue.Start(work, 21999));
    queue.Finish(work, 21999, 22001, KmonReferenceOutcome::Observed, false);
    check(queue.Find(work)->LastSuccess == 220 && queue.Find(work)->Outcome == KmonReferenceOutcome::InvalidClock);
    later.ObservedMs = 21000;
    check(queue.Admit(later) == KmonReferenceAdmission::Invalid);
    later.ObservedMs = 33000;
    check(queue.Admit(later) == KmonReferenceAdmission::Queued);
    work = queue.Pop(); check(!queue.Start(work, 64000));
    queue.Finish(work, 64000, 64001, KmonReferenceOutcome::Expired, true);
    check(queue.Find(work)->LastSuccess == 220 && queue.Find(work)->LastAttempt == 11010);
    check(queue.Normal().SuccessService.Samples == 1 && queue.Normal().FailedService.Samples == 1 &&
        queue.Shutdown().QueueWait.Samples == 1 && queue.Shutdown().FailedService.Samples == 0);
    auto invalid = ReferenceTestWork(1, L"owned", 10, 1);
    invalid.Anchors.resize(9);
    check(queue.Admit(invalid) == KmonReferenceAdmission::Invalid);
    invalid.Anchors.resize(1); invalid.Anchors[0] = {UINT64_MAX, {1, 2}};
    check(queue.Admit(invalid) == KmonReferenceAdmission::Invalid);
    invalid.Anchors[0] = {1, std::vector<uint8_t>(4097)};
    check(queue.Admit(invalid) == KmonReferenceAdmission::Invalid);
    queue.clear();
    // Keep one never-dispatched entry pinned while completed history churns.
    const auto pinned = ReferenceTestWork(1, L"pinned", 1, 100);
    check(queue.Admit(pinned) == KmonReferenceAdmission::Queued);
    work = queue.Pop();
    for (uint32_t i = 0; i != KmonReferenceQueue::HistoryCapacity + 2; ++i)
    {
        const auto candidate = ReferenceTestWork(10 + i, L"churn", i + 1, 100 + i);
        check(queue.Admit(candidate) == KmonReferenceAdmission::Queued);
        const auto popped = queue.Pop();
        check(queue.Start(popped, 100 + i));
        queue.Finish(popped, 100 + i, 100 + i, KmonReferenceOutcome::Partial, false);
    }
    check(queue.Find(pinned) != nullptr && queue.Find(pinned)->Busy);
    check(queue.Find(ReferenceTestWork(10, L"churn", 1, 100)) == nullptr);
    check(queue.Json(20000).find(L"\"history_evicted\":\"3\"") != std::wstring::npos);
    queue.Finish(work, 20000, 20001, KmonReferenceOutcome::Cancelled, true);
    check(!queue.Find(pinned)->Busy && !queue.Find(pinned)->HasSuccess);
    std::cout << "[reference.scheduler] " << checks << " checks: " << (failures == 0 ? "PASS" : "FAIL") << "\n";
    return failures == 0;
}
