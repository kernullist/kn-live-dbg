#pragma once

#include "KmonWorkQueue.h"
#include "McpJson.h"
#include <array>
#include <mutex>

enum class KmonCaptureClass
{
    None,
    First,
    Continued
};

// Urgency thresholds are scheduling policy, not measured latency guarantees.
constexpr uint64_t KmonFirstCaptureUrgencyMs = 250;
constexpr uint64_t KmonContinuedCaptureUrgencyMs = 1000;
constexpr size_t KmonFirstCaptureBurstLimit = 8;

class KmonCapturePicker
{
public:
    KmonCaptureClass Pick(const KmonQueueTiming& first, const KmonQueueTiming& continued) const
    {
        if (first.Pending == 0)
        {
            return continued.Pending == 0 ? KmonCaptureClass::None : KmonCaptureClass::Continued;
        }
        if (continued.Pending == 0)
        {
            return KmonCaptureClass::First;
        }
        if (FirstBurst >= KmonFirstCaptureBurstLimit)
        {
            return KmonCaptureClass::Continued;
        }
        // An aged continuation may borrow a turn, but never two consecutive
        // turns while first-capture requests are also waiting.
        const uint64_t firstLate = first.OldestQueueWaitMs > KmonFirstCaptureUrgencyMs ?
            first.OldestQueueWaitMs - KmonFirstCaptureUrgencyMs : 0;
        const uint64_t continuedLate = continued.OldestQueueWaitMs > KmonContinuedCaptureUrgencyMs ?
            continued.OldestQueueWaitMs - KmonContinuedCaptureUrgencyMs : 0;
        return Last != KmonCaptureClass::Continued && continuedLate != 0 && continuedLate >= firstLate ?
            KmonCaptureClass::Continued : KmonCaptureClass::First;
    }

    void Dispatched(KmonCaptureClass kind)
    {
        if (kind == KmonCaptureClass::First)
        {
            FirstBurst = (std::min)(FirstBurst + 1, KmonFirstCaptureBurstLimit);
        }
        else if (kind == KmonCaptureClass::Continued)
        {
            FirstBurst = 0;
        }
        Last = kind;
    }

private:
    size_t FirstBurst = 0;
    KmonCaptureClass Last = KmonCaptureClass::None;
};

struct KmonLatencyHistogram
{
    std::array<uint64_t, 65> Buckets{};
    uint64_t Samples = 0;
    uint64_t MaximumMs = 0;

    void Add(uint64_t milliseconds)
    {
        if (Samples == UINT64_MAX)
        {
            return;
        }
        size_t bucket = 0;
        for (uint64_t remaining = milliseconds; remaining != 0; remaining >>= 1)
        {
            ++bucket;
        }
        ++Buckets[bucket];
        ++Samples;
        MaximumMs = (std::max)(MaximumMs, milliseconds);
    }

    uint64_t UpperPercentile(unsigned percent) const
    {
        if (Samples == 0 || percent == 0 || percent > 100)
        {
            return 0;
        }
        const uint64_t rank = (Samples / 100) * percent + ((Samples % 100) * percent + 99) / 100;
        uint64_t sum = 0;
        for (size_t i = 0; i < Buckets.size(); ++i)
        {
            sum += Buckets[i];
            if (sum >= rank)
            {
                return i == 0 ? 0 : (i == 64 ? UINT64_MAX : (uint64_t{1} << i) - 1);
            }
        }
        return UINT64_MAX;
    }
};

struct KmonCaptureTimingStats
{
    KmonLatencyHistogram FirstQueueWait;
    KmonLatencyHistogram ContinuedQueueWait;
    KmonLatencyHistogram FirstAttemptAge;
    KmonLatencyHistogram PageService;
    uint64_t FirstOverUrgency = 0;
    uint64_t ContinuedOverUrgency = 0;
    uint64_t FailedAttempts = 0;
    uint64_t ShutdownDispatches = 0;
    uint64_t ShutdownAttempts = 0;
    uint64_t InvalidClocks = 0;
};

class KmonCaptureTimings
{
public:
    void Dispatch(KmonCaptureClass kind, uint64_t queuedAt, uint64_t now, bool shutdown)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (kind == KmonCaptureClass::None)
        {
            return;
        }
        if (shutdown)
        {
            ++Stats.ShutdownDispatches;
            return;
        }
        if (queuedAt > now)
        {
            ++Stats.InvalidClocks;
            return;
        }
        const auto wait = now - queuedAt;
        if (kind == KmonCaptureClass::First)
        {
            Stats.FirstQueueWait.Add(wait);
            Stats.FirstOverUrgency += wait > KmonFirstCaptureUrgencyMs;
        }
        else
        {
            Stats.ContinuedQueueWait.Add(wait);
            Stats.ContinuedOverUrgency += wait > KmonContinuedCaptureUrgencyMs;
        }
    }

    void Attempt(uint64_t submittedAt, uint64_t startedAt, uint64_t endedAt,
        bool first, bool success, bool shutdown)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (shutdown)
        {
            ++Stats.ShutdownAttempts;
            return;
        }
        if (submittedAt > startedAt || startedAt > endedAt)
        {
            ++Stats.InvalidClocks;
            return;
        }
        Stats.PageService.Add(endedAt - startedAt);
        Stats.FailedAttempts += !success;
        if (first)
        {
            Stats.FirstAttemptAge.Add(startedAt - submittedAt);
        }
    }

    KmonCaptureTimingStats Snapshot() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Stats;
    }

    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        Stats = {};
    }

private:
    mutable std::mutex Mutex;
    KmonCaptureTimingStats Stats;
};

inline std::wstring KmonCaptureTimingJson(const KmonCaptureTimingStats& stats,
    const KmonQueueTiming& first, const KmonQueueTiming& continued)
{
    const auto n = [](uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    };
    const auto histogram = [&](const KmonLatencyHistogram& h)
    {
        return L"{\"samples\":" + n(h.Samples) + L",\"p50_upper_ms\":" + n(h.UpperPercentile(50)) +
            L",\"p95_upper_ms\":" + n(h.UpperPercentile(95)) + L",\"p99_upper_ms\":" + n(h.UpperPercentile(99)) +
            L",\"max_ms\":" + n(h.MaximumMs) + L"}";
    };
    const auto queue = [&](const KmonQueueTiming& q)
    {
        return L"{\"pending\":" + n(q.Pending) + L",\"capacity\":" + n(q.Capacity) +
            L",\"oldest_queue_wait_ms\":" + n(q.OldestQueueWaitMs) + L",\"oldest_request_age_ms\":" + n(q.OldestRequestAgeMs) +
            L",\"invalid_clocks\":" + n(q.InvalidClocks) + L"}";
    };
    const bool saturated = (first.Capacity != 0 && first.Pending == first.Capacity) ||
        (continued.Capacity != 0 && continued.Pending == continued.Capacity);
    return L"{\"schema\":\"kn.capture_scheduling.v1\",\"scope\":\"capture_worker\","
        L"\"clock_domain\":\"GetTickCount64_ms\",\"percentiles\":\"log2_bucket_upper_bounds\","
        L"\"shutdown_in_normal_samples\":false,\"hard_deadline_enforced\":false,"
        L"\"saturation_scope\":\"first_and_continuation_request_queues\",\"scope_saturated\":" +
        std::wstring(saturated ? L"true" : L"false") + L",\"first_urgency_ms\":" + n(KmonFirstCaptureUrgencyMs) +
        L",\"continued_urgency_ms\":" + n(KmonContinuedCaptureUrgencyMs) + L",\"first_burst_limit\":" + n(KmonFirstCaptureBurstLimit) +
        L",\"first_pending\":" + queue(first) + L",\"continued_pending\":" + queue(continued) +
        L",\"first_queue_wait\":" + histogram(stats.FirstQueueWait) + L",\"continued_queue_wait\":" + histogram(stats.ContinuedQueueWait) +
        L",\"first_attempt_age\":" + histogram(stats.FirstAttemptAge) + L",\"page_service\":" + histogram(stats.PageService) +
        L",\"first_over_urgency\":" + n(stats.FirstOverUrgency) + L",\"continued_over_urgency\":" + n(stats.ContinuedOverUrgency) +
        L",\"failed_attempts\":" + n(stats.FailedAttempts) + L",\"shutdown_dispatches\":" + n(stats.ShutdownDispatches) +
        L",\"shutdown_attempts\":" + n(stats.ShutdownAttempts) + L",\"invalid_clocks\":" + n(stats.InvalidClocks) + L"}";
}
