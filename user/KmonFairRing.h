#pragma once
#include <algorithm>
#include <cstdint>
#include <deque>
#include <optional>

// Owner supplies synchronization. New members join behind existing waiters;
// an old-work loan never consumes the ordinary head's turn.
template<typename Key> class KmonFairRing
{
public:
    void Add(const Key& key)
    { if (std::find(Order.begin(), Order.end(), key) == Order.end()) { Order.push_back(key); } }
    void Remove(const Key& key)
    { Order.erase(std::remove(Order.begin(), Order.end(), key), Order.end()); }
    std::optional<Key> Pick(const std::optional<Key>& oldest = {})
    {
        Loan = false;
        if (Order.empty()) { return {}; }
        if (Turns++ % 4 == 3 && oldest && *oldest != Order.front() &&
            std::find(Order.begin(), Order.end(), *oldest) != Order.end())
        { Loan = true; ++Loans; return oldest; }
        const auto key = Order.front();
        std::rotate(Order.begin(), Order.begin() + 1, Order.end());
        return key;
    }
    const std::deque<Key>& Keys() const { return Order; }
    bool LastWasLoan() const { return Loan; }
    bool MayBorrow() const { return Turns % 4 == 3; }
    uint64_t DebtLoans() const { return Loans; }
    void Reset() { *this = {}; }
private:
    std::deque<Key> Order;
    uint64_t Turns = 0, Loans = 0;
    bool Loan = false;
};
