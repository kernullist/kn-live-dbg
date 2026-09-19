#pragma once

#include "ObservationModel.h"
#include <algorithm>
#include <vector>

inline bool KmonPageRole(const std::wstring& role)
{
    return role == L"kernel_page_candidate" || role == L"user_page_candidate" ||
        role == L"user_hidden_pte_page" || role == L"image_page_candidate";
}

inline bool KmonHardwareExecutable(uint64_t pml5e, uint64_t pml4e, uint64_t pdpte,
    uint64_t pde, uint64_t pte, uint64_t pageSize, uint32_t levels, bool user)
{
    const auto valid = [user](uint64_t entry)
    {
        return (entry & 1) != 0 && (entry >> 63) == 0 && (!user || (entry & 4) != 0);
    };
    if ((levels != 4 && levels != 5) || (levels == 5 && !valid(pml5e)) ||
        !valid(pml4e) || !valid(pdpte))
    {
        return false;
    }
    if ((pdpte & 0x80) != 0)
    {
        return pageSize == (1ull << 30);
    }
    if (!valid(pde))
    {
        return false;
    }
    if ((pde & 0x80) != 0)
    {
        return pageSize == (1ull << 21);
    }
    return pageSize == 4096 && valid(pte);
}

struct KmonPageWork
{
    ObservationIdentity Identity;
    ObservationRange Range;
    uint64_t AllocationBase = 0;
    uint64_t NextOffset = 0;
    uint64_t LastSeenMs = 0;
    uint64_t EligibleMs = 0;
    std::wstring Role;
};

// Analysis-thread owned. Scheduling a page does not claim that its read succeeded.
class KmonExecutablePages
{
public:
    explicit KmonExecutablePages(size_t capacity = 512) : Capacity((std::max<size_t>)(1, (std::min<size_t>)(capacity, 512)))
    {
    }

    bool Observe(const ObservationIdentity& identity, ObservationRange range, uint64_t allocation,
        const std::wstring& role, uint64_t now)
    {
        if (identity.BootId.empty() || identity.BootId.size() > 128 || !KmonPageRole(role) ||
            now == 0 || now < LastMs || (range.Address & 4095) != 0 || (range.Size & 4095) != 0 ||
            range.Size == 0 || range.Address > UINT64_MAX - range.Size ||
            (identity.ProcessId == 0 && (range.Address < 0xFFFF800000000000ull ||
                (role != L"kernel_page_candidate" && role != L"image_page_candidate"))) ||
            (identity.ProcessId != 0 && (identity.ProcessId <= 4 || identity.CreateTime == 0 ||
                range.Address + range.Size > 0x0000800000000000ull || role == L"kernel_page_candidate")))
        {
            ++Rejected;
            return false;
        }
        for (const auto& old : Work)
        {
            if (old.Identity.BootId == identity.BootId && old.Identity.ProcessId == identity.ProcessId &&
                old.Identity.CreateTime > identity.CreateTime)
            {
                ++Rejected;
                return false;
            }
        }
        LastMs = now;
        Work.erase(std::remove_if(Work.begin(), Work.end(), [&](const auto& old)
        {
            return old.Identity.BootId != identity.BootId ||
                (old.Identity.ProcessId == identity.ProcessId && old.Identity.CreateTime != identity.CreateTime);
        }), Work.end());
        Expire(now);
        for (auto& old : Work)
        {
            if (old.Identity.SameInstance(identity) && old.Range.Address == range.Address && old.Role == role)
            {
                if (old.Range.Size != range.Size || (old.AllocationBase != 0 && allocation != 0 && old.AllocationBase != allocation))
                {
                    old.NextOffset = 0;
                    old.EligibleMs = 0;
                }
                old.Range = range;
                old.AllocationBase = allocation;
                old.LastSeenMs = now;
                return true;
            }
        }
        if (Work.size() == Capacity)
        {
            const auto victim = std::min_element(Work.begin(), Work.end(), [](const auto& a, const auto& b)
            {
                if ((a.Role == L"image_page_candidate") != (b.Role == L"image_page_candidate"))
                {
                    return a.Role == L"image_page_candidate";
                }
                return a.LastSeenMs < b.LastSeenMs;
            });
            if (role == L"image_page_candidate" && victim->Role != L"image_page_candidate")
            {
                ++Rejected;
                return false;
            }
            Work.erase(victim);
            ++Evicted;
        }
        Work.push_back({identity, range, allocation, 0, now, 0, role});
        return true;
    }

    bool Next(uint64_t now, KmonPageWork* page)
    {
        if (page == nullptr || now < LastMs)
        {
            return false;
        }
        LastMs = now;
        Expire(now);
        for (size_t count = 0; count < Work.size(); ++count)
        {
            Cursor %= Work.size();
            auto& row = Work[Cursor++];
            if (now < row.EligibleMs)
            {
                continue;
            }
            *page = row;
            page->Range = {row.Range.Address + row.NextOffset, 4096};
            row.NextOffset += 4096;
            if (row.NextOffset == row.Range.Size)
            {
                row.NextOffset = 0;
                row.EligibleMs = now <= UINT64_MAX - 10000 ? now + 10000 : UINT64_MAX;
                ++CyclesScheduled;
            }
            ++PagesScheduled;
            return true;
        }
        return false;
    }

    size_t Size() const
    {
        return Work.size();
    }

    uint64_t PagesScheduled = 0;
    uint64_t CyclesScheduled = 0;
    uint64_t Evicted = 0;
    uint64_t Expired = 0;
    uint64_t Rejected = 0;

private:
    void Expire(uint64_t now)
    {
        const size_t before = Work.size();
        Work.erase(std::remove_if(Work.begin(), Work.end(), [now](const auto& row)
        {
            return now >= row.LastSeenMs && now - row.LastSeenMs > 300000;
        }), Work.end());
        Expired += before - Work.size();
    }

    size_t Capacity;
    size_t Cursor = 0;
    uint64_t LastMs = 0;
    std::vector<KmonPageWork> Work;
};
