#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

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

    uint64_t Loss() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Dropped;
    }

    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        Items.clear();
        Dropped = 0;
        HighWater = 0;
    }

private:
    size_t Capacity;
    size_t HighWater = 0;
    uint64_t Dropped = 0;
    mutable std::mutex Mutex;
    std::deque<T> Items;
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
    return ok && queue.Loss() == 0 && queue.Size() == 0;
}
