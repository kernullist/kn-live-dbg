#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

struct KmonQueueTiming
{
    size_t Pending = 0;
    size_t Capacity = 0;
    uint64_t OldestQueueWaitMs = 0;
    uint64_t OldestRequestAgeMs = 0;
    size_t InvalidClocks = 0;
};

template<typename T>
class KmonWorkQueue
{
public:
    explicit KmonWorkQueue(size_t capacity) : Capacity(capacity)
    {
    }

    bool Push(T item)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (Items.size() >= Capacity)
        {
            ++Dropped;
            return false;
        }
        Items.push_back(std::move(item));
        HighWater = (std::max)(HighWater, Items.size());
        return true;
    }

    bool Pop(T* item)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (Items.empty())
        {
            return false;
        }
        *item = std::move(Items.front());
        Items.pop_front();
        return true;
    }

    // All-or-none admission for a retained source record and its related leads.
    bool TryPushBatch(std::vector<T> items, size_t admissionLimit)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const size_t limit = (std::min)(Capacity, admissionLimit);
        if (Items.size() > limit || items.size() > limit - Items.size()) { return false; }
        for (auto& item : items) { Items.push_back(std::move(item)); }
        HighWater = (std::max)(HighWater, Items.size());
        return true;
    }

    template<typename SameWork>
    bool PushLatest(T item, SameWork sameWork)
    {
        return InsertLatest(std::move(item), sameWork, Capacity, true);
    }

    // Admission refusal is not loss when the producer retains its work.
    // Existing entries can still refresh at the admission limit.
    template<typename SameWork>
    bool TryPushLatest(T item, SameWork sameWork, size_t admissionLimit)
    {
        return InsertLatest(std::move(item), sameWork, admissionLimit, false);
    }

private:
    template<typename SameWork>
    bool InsertLatest(T item, SameWork sameWork, size_t admissionLimit, bool countLoss)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        for (auto& pending : Items)
        {
            if (sameWork(pending, item))
            {
                pending = std::move(item); // Refresh evidence without moving its FIFO position.
                ++Coalesced;
                return true;
            }
        }
        if (Items.size() >= (std::min)(Capacity, admissionLimit))
        {
            if (countLoss) { ++Dropped; }
            return false;
        }
        Items.push_back(std::move(item));
        HighWater = (std::max)(HighWater, Items.size());
        return true;
    }

public:
    uint64_t Replacements() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Coalesced;
    }

    std::vector<T> Drain(size_t limit)
    {
        std::vector<T> result;
        std::lock_guard<std::mutex> lock(Mutex);
        while (!Items.empty() && result.size() < limit)
        {
            result.push_back(std::move(Items.front()));
            Items.pop_front();
        }
        return result;
    }

    size_t Size() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Items.size();
    }

    // The projection returns queue-admission and original-request timestamps.
    // It must be bounded, nonblocking, and must not call back into this queue.
    template<typename Timestamps>
    KmonQueueTiming Timing(uint64_t now, Timestamps timestamps) const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        KmonQueueTiming timing;
        timing.Pending = Items.size();
        timing.Capacity = Capacity;
        for (const auto& item : Items)
        {
            const auto times = timestamps(item);
            if (times.first > now || times.second > times.first)
            {
                ++timing.InvalidClocks;
                continue;
            }
            timing.OldestQueueWaitMs = (std::max)(timing.OldestQueueWaitMs, now - times.first);
            timing.OldestRequestAgeMs = (std::max)(timing.OldestRequestAgeMs, now - times.second);
        }
        return timing;
    }

    // A sole producer can use this as a source read budget. Concurrent
    // consumers only increase the available room; zero must not mean unlimited.
    size_t Available() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Capacity - Items.size();
    }

    uint64_t Loss() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Dropped;
    }

    size_t Peak() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return HighWater;
    }

    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        Items.clear();
        Dropped = 0;
        HighWater = 0;
        Coalesced = 0;
    }

private:
    size_t Capacity;
    size_t HighWater = 0;
    uint64_t Dropped = 0;
    uint64_t Coalesced = 0;
    mutable std::mutex Mutex;
    std::deque<T> Items;
};

// A full source walk can keep its cheap anomaly checks while rotating the
// expensive code-reference work. Backpressure never advances past unqueued work.
class KmonReferenceWindow
{
public:
    KmonReferenceWindow(size_t& cursor, size_t budget) : Cursor(cursor), Start(cursor), Next(cursor), Budget(budget) {}
    ~KmonReferenceWindow() { Cursor = Next >= Seen ? 0 : Next; }
    KmonReferenceWindow(const KmonReferenceWindow&) = delete;
    KmonReferenceWindow& operator=(const KmonReferenceWindow&) = delete;
    bool Select(bool available)
    {
        const size_t index = Seen++;
        if (index < Start || Accepted >= Budget || Blocked)
        {
            return false;
        }
        if (!available)
        {
            Next = index;
            Blocked = true;
            return false;
        }
        ++Accepted;
        Next = index + 1;
        return true;
    }
private:
    size_t& Cursor;
    size_t Start;
    size_t Next;
    size_t Budget;
    size_t Seen = 0;
    size_t Accepted = 0;
    bool Blocked = false;
};

inline bool KmonWorkQueueSelfTest()
{
    KmonWorkQueue<uint64_t> queue(2);
    bool ok = queue.Push(11) && queue.Push(12) && !queue.Push(13) && queue.Loss() == 1;
    uint64_t value = 0;
    ok = ok && queue.Pop(&value) && value == 11 && queue.Push(14);
    const auto batch = queue.Drain(2);
    ok = ok && batch.size() == 2 && batch[0] == 12 && batch[1] == 14 && !queue.Pop(&value);
    queue.Reset();
    ok = ok && queue.Loss() == 0 && queue.Size() == 0 && queue.Peak() == 0;
    ok = ok && !queue.TryPushBatch({1, 2, 3}, 2) && queue.Size() == 0 && queue.Loss() == 0 &&
        queue.TryPushBatch({1, 2}, 2) && !queue.TryPushBatch({3}, 2) && queue.Size() == 2 && queue.Loss() == 0;
    queue.Reset();
    KmonWorkQueue<std::pair<int, int>> latest(2);
    const auto same = [](const auto& a, const auto& b) { return a.first == b.first; };
    ok = ok && latest.PushLatest({1, 10}, same) && latest.PushLatest({2, 20}, same) &&
        latest.PushLatest({1, 30}, same) && latest.Replacements() == 1 && latest.Loss() == 0 &&
        latest.Peak() == 2 && !latest.PushLatest({3, 40}, same) && latest.Loss() == 1;
    const auto refreshed = latest.Drain(2);
    ok = ok && refreshed.size() == 2 && refreshed[0] == std::make_pair(1, 30) && refreshed[1].first == 2;
    latest.Reset();
    ok = ok && latest.TryPushLatest({1, 1}, same, 1) &&
        !latest.TryPushLatest({2, 2}, same, 1) && latest.Loss() == 0 && latest.Size() == 1 &&
        latest.TryPushLatest({1, 3}, same, 0) && latest.Replacements() == 1;
    const auto limited = latest.Drain(2);
    ok = ok && limited.size() == 1 && limited[0] == std::make_pair(1, 3);
    latest.Reset();
    for (int n = 0; n < 1000; ++n) { ok = ok && latest.PushLatest({n % 2, n}, same); }
    ok = ok && latest.Size() == 2 && latest.Loss() == 0 && latest.Replacements() == 998;
    size_t cursor = 0;
    std::vector<size_t> selected;
    for (size_t pass = 0; pass < 4; ++pass)
    {
        KmonReferenceWindow window(cursor, 3);
        for (size_t i = 0; i < 10; ++i)
        {
            if (window.Select(true)) { selected.push_back(i); }
        }
    }
    ok = ok && selected.size() == 10 && cursor == 0;
    for (size_t i = 0; i < selected.size(); ++i) { ok = ok && selected[i] == i; }
    cursor = 4;
    {
        KmonReferenceWindow window(cursor, 3);
        for (size_t i = 0; i < 10; ++i) { ok = ok && !window.Select(false); }
    }
    ok = ok && cursor == 4; // Retry the same tail after a full queue.
    {
        KmonReferenceWindow window(cursor, 3);
        for (size_t i = 0; i < 2; ++i) { ok = ok && !window.Select(true); }
    }
    return ok && cursor == 0; // A shrinking source cannot strand its cursor.
}
