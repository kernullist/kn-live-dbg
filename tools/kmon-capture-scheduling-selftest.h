#pragma once

#include "../user/KmonCaptureScheduling.h"
#include <iostream>
#include <thread>

inline bool KmonCaptureSchedulingSelfTest()
{
    size_t passed = 0, failed = 0;
    const auto check = [&](bool value, const char* name)
    {
        if (value)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::cerr << "[capture.scheduling] FAIL " << name << "\n";
        }
    };
    KmonCapturePicker picker;
    KmonQueueTiming first, continued;
    check(picker.Pick(first, continued) == KmonCaptureClass::None, "empty queues do not dispatch");
    first.Pending = continued.Pending = 1;
    for (size_t i = 0; i < 8; ++i)
    {
        check(picker.Pick(first, continued) == KmonCaptureClass::First, "fresh requests retain the initial burst");
        picker.Dispatched(KmonCaptureClass::First);
    }
    check(picker.Pick(first, continued) == KmonCaptureClass::Continued, "continuations cannot starve behind fresh arrivals");
    picker.Dispatched(KmonCaptureClass::Continued);
    continued.OldestQueueWaitMs = 5000;
    check(picker.Pick(first, continued) == KmonCaptureClass::First, "aged continuations cannot take consecutive turns");
    picker.Dispatched(KmonCaptureClass::First);
    check(picker.Pick(first, continued) == KmonCaptureClass::Continued, "older overdue continuation borrows an early turn");
    first.OldestQueueWaitMs = 6000;
    check(picker.Pick(first, continued) == KmonCaptureClass::First, "greater first-capture lateness wins within its burst");

    KmonLatencyHistogram histogram;
    const std::vector<uint64_t> values = {0, 1, 2, 3, 4, 7, 8, 15, 16, UINT64_MAX};
    for (const auto value : values)
    {
        histogram.Add(value);
    }
    check(histogram.Samples == values.size() && histogram.MaximumMs == UINT64_MAX, "histogram retains zero and full-width durations");
    for (unsigned percentile = 1; percentile <= 100; ++percentile)
    {
        const auto actual = values[(values.size() * percentile + 99) / 100 - 1];
        const auto upper = histogram.UpperPercentile(percentile);
        check(actual <= upper && (upper == 0 || actual >= (upper >> 1) + 1), "percentile bucket bounds the independent ordered sample");
    }
    check(KmonLatencyHistogram{}.UpperPercentile(99) == 0 && histogram.UpperPercentile(0) == 0 &&
        histogram.UpperPercentile(101) == 0, "empty and invalid percentile requests are bounded");

    using Times = std::pair<uint64_t, uint64_t>;
    KmonWorkQueue<Times> queue(2);
    check(queue.Push({100, 10}) && queue.Push({200, 20}), "owned queue timing fixture admitted");
    const auto timing = queue.Timing(300, [](const Times& item)
    {
        return item;
    });
    check(timing.Pending == 2 && timing.Capacity == 2 && timing.OldestQueueWaitMs == 200 &&
        timing.OldestRequestAgeMs == 290 && timing.InvalidClocks == 0, "queue wait and original request age have separate clocks");
    const auto regressed = queue.Timing(50, [](const Times& item)
    {
        return item;
    });
    check(regressed.InvalidClocks == 2 && regressed.OldestQueueWaitMs == 0, "future timestamps cannot underflow queue age");
    check(mcpjson::ValidateDocument(KmonCaptureTimingJson({}, timing, {})), "scheduling DTO is valid JSON");

    KmonCaptureTimings timings;
    timings.Dispatch(KmonCaptureClass::First, 10, 310, false);
    timings.Dispatch(KmonCaptureClass::Continued, 100, 1200, false);
    timings.Attempt(10, 310, 317, true, false, false);
    timings.Dispatch(KmonCaptureClass::First, 0, UINT64_MAX, true);
    timings.Attempt(0, 0, UINT64_MAX, true, true, true);
    timings.Dispatch(KmonCaptureClass::First, 400, 300, false);
    timings.Attempt(400, 300, 500, true, true, false);
    const auto stats = timings.Snapshot();
    check(stats.FirstQueueWait.Samples == 1 && stats.FirstQueueWait.MaximumMs == 300 &&
        stats.ContinuedQueueWait.MaximumMs == 1100 && stats.FirstOverUrgency == 1 && stats.ContinuedOverUrgency == 1,
        "dispatch records urgency misses separately for each queue");
    check(stats.FirstAttemptAge.Samples == 1 && stats.FirstAttemptAge.MaximumMs == 300 &&
        stats.PageService.MaximumMs == 7 && stats.FailedAttempts == 1, "failed attempts remain in normal service latency");
    check(stats.ShutdownDispatches == 1 && stats.ShutdownAttempts == 1 && stats.InvalidClocks == 2,
        "shutdown and clock failures cannot improve normal sample distributions");
    timings.Reset();
    check(timings.Snapshot().FirstQueueWait.Samples == 0, "new sessions reset timing evidence");
    std::thread one([&]()
    {
        for (size_t i = 0; i < 1000; ++i)
        {
            timings.Dispatch(KmonCaptureClass::First, 0, i, false);
        }
    });
    std::thread two([&]()
    {
        for (size_t i = 0; i < 1000; ++i)
        {
            timings.Attempt(0, i, i + 1, true, true, false);
            timings.Snapshot();
        }
    });
    one.join();
    two.join();
    check(timings.Snapshot().FirstQueueWait.Samples == 1000 && timings.Snapshot().PageService.Samples == 1000,
        "concurrent observations and health snapshots do not lose samples");

    // Model fixed and churning cohorts with the production picker and FIFO queues.
    for (const bool churn : {false, true})
    {
        struct Work
        {
            size_t Id = 0;
            size_t Remaining = 0;
            uint64_t Queued = 0;
            uint64_t Submitted = 0;
        };
        KmonWorkQueue<Work> fresh(2048), resumed(2048);
        KmonCapturePicker model;
        std::array<size_t, 32> progress{};
        size_t expected = 0, serviced = 0, firstBurst = 0, continuedBurst = 0;
        uint64_t now = 0;
        for (size_t id = 0; id < progress.size(); ++id)
        {
            const size_t pages = id % 12 + 2;
            fresh.Push({id, pages, now, now});
            expected += pages;
        }
        bool fair = true;
        const auto times = [](const Work& work)
        {
            return std::make_pair(work.Queued, work.Submitted);
        };
        while (serviced < (churn ? 800 : expected))
        {
            if (churn)
            {
                fresh.Push({progress.size(), 1, now, now});
            }
            const auto f = fresh.Timing(now, times), c = resumed.Timing(now, times);
            const auto kind = model.Pick(f, c);
            Work work;
            const bool found = kind == KmonCaptureClass::First ? fresh.Pop(&work) :
                (kind == KmonCaptureClass::Continued && resumed.Pop(&work));
            if (!found)
            {
                fair = false;
                break;
            }
            model.Dispatched(kind);
            if (f.Pending != 0 && c.Pending != 0)
            {
                firstBurst = kind == KmonCaptureClass::First ? firstBurst + 1 : 0;
                continuedBurst = kind == KmonCaptureClass::Continued ? continuedBurst + 1 : 0;
                fair = fair && firstBurst <= 8 && continuedBurst <= 1;
            }
            else
            {
                firstBurst = continuedBurst = 0;
            }
            if (work.Id < progress.size())
            {
                ++progress[work.Id];
            }
            ++serviced;
            now += 17;
            if (--work.Remaining != 0)
            {
                work.Queued = now;
                fair = resumed.Push(work) && fair;
            }
        }
        check(fair && fresh.Loss() == 0 && resumed.Loss() == 0, "cohort service remains bounded and loss-free under the admitted load");
        check(std::all_of(progress.begin(), progress.end(), [](size_t count)
        {
            return count >= 2;
        }), "every original cohort member gets a continuation despite fresh work");
        check(churn ? fresh.Size() + resumed.Size() != 0 : fresh.Size() + resumed.Size() == 0,
            "fixed completion and ongoing churn backlog remain distinct outcomes");
    }
    std::cout << "[capture.scheduling] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    return failed == 0;
}
