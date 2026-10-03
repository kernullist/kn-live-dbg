#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

struct UserPteLeaf
{
    uint64_t Address = 0;
    uint64_t Size = 0;
    uint64_t Physical = 0;
    uint64_t EntryAddress = 0;
    uint64_t Entry = 0;
    bool Writable = false;
    bool Executable = false;
};

struct UserPteWalkResult
{
    uint64_t TablesAttempted = 0;
    uint64_t TablesRead = 0;
    uint64_t ReadFailures = 0;
    uint64_t Leaves = 0;
    uint64_t ResumeAddress = 0;
    bool Finished = false;
    bool BudgetExhausted = false;
};

using UserPteTableReader = std::function<bool(uint64_t, std::vector<uint8_t>*)>;
using UserPteVisitor = std::function<bool(const UserPteLeaf&)>;

// Depth is bounded by the paging mode. Shared table pages are visited for each VA alias.
inline UserPteWalkResult WalkUserPtes(uint64_t root, uint32_t levels, uint64_t resume,
    uint32_t tableBudget, bool executableOnly, const UserPteTableReader& read,
    const UserPteVisitor& visit)
{
    UserPteWalkResult result;
    if ((levels != 4 && levels != 5) || root == 0 || !read || !visit)
    {
        return result;
    }
    const uint64_t maxUser = (1ull << (12 + 9 * levels - 1)) - 1;
    if (resume > maxUser)
    {
        return result;
    }
    const uint64_t pfnMask = 0x000FFFFFFFFFF000ull;
    const uint32_t budget = (std::max<uint32_t>)(levels + 1,
        (std::min<uint32_t>)(tableBudget == 0 ? 32768 : tableBudget, 32768));
    bool stopped = false;
    std::function<void(uint64_t, uint32_t, uint64_t, bool, bool)> walk;
    walk = [&](uint64_t physical, uint32_t level, uint64_t base, bool writable, bool nx)
    {
        if (result.TablesAttempted >= budget)
        {
            result.ResumeAddress = (std::max)(base, resume);
            result.BudgetExhausted = true;
            stopped = true;
            return;
        }
        ++result.TablesAttempted;
        std::vector<uint8_t> bytes;
        if (!read(physical & pfnMask, &bytes) || bytes.size() != 4096)
        {
            ++result.ReadFailures;
            return;
        }
        ++result.TablesRead;
        const uint64_t span = 1ull << (12 + 9 * (level - 1));
        const size_t count = level == levels ? 256 : 512;
        for (size_t index = 0; index < count && !stopped; ++index)
        {
            const uint64_t address = base + index * span;
            if (address > maxUser || address + span - 1 < resume)
            {
                continue;
            }
            uint64_t entry = 0;
            std::memcpy(&entry, bytes.data() + index * 8, 8);
            if ((entry & 5) != 5)
            {
                continue;
            }
            const bool entryNx = nx || (entry >> 63) != 0;
            const bool entryWritable = writable && (entry & 2) != 0;
            if (executableOnly && entryNx)
            {
                continue;
            }
            const bool large = (entry & 0x80) != 0 && (level == 2 || level == 3);
            if (large && (entry & pfnMask & (span - 1) & ~0x1000ull) != 0)
            {
                ++result.ReadFailures;
                continue;
            }
            if (level == 1 || large)
            {
                UserPteLeaf leaf;
                leaf.Address = address;
                leaf.Size = span;
                leaf.Physical = entry & pfnMask & ~(span - 1);
                leaf.EntryAddress = (physical & pfnMask) + index * 8;
                leaf.Entry = entry;
                leaf.Writable = entryWritable;
                leaf.Executable = !entryNx;
                ++result.Leaves;
                if (!visit(leaf))
                {
                    result.ResumeAddress = (std::max)(address, resume);
                    stopped = true;
                }
            }
            else if ((entry & 0x80) == 0)
            {
                walk(entry & pfnMask, level - 1, address, entryWritable, entryNx);
            }
            else
            {
                ++result.ReadFailures;
            }
        }
    };
    walk(root, levels, 0, true, false);
    result.Finished = !stopped;
    return result;
}
