#pragma once

#include "ObservationModel.h"
#include <algorithm>
#include <initializer_list>
#include <tuple>
#include <vector>

inline bool KmonPageRole(const std::wstring& role)
{
    return role == L"kernel_page_candidate" || role == L"user_page_candidate" ||
        role == L"user_hidden_pte_page" || role == L"image_page_candidate";
}

inline bool KmonPhysicalPageSamplesAgree(std::initializer_list<uint64_t> physicalAddresses)
{
    uint64_t known = 0;
    for (const auto address : physicalAddresses)
    {
        if (address == 0)
        {
            continue;
        }
        if (known != 0 && (known >> 12) != (address >> 12))
        {
            return false;
        }
        known = address;
    }
    return true;
}

inline bool KmonHardwareExecutable(uint64_t pml5e, uint64_t pml4e, uint64_t pdpte,
    uint64_t pde, uint64_t pte, uint64_t pageSize, uint32_t levels, bool user)
{
    const auto valid = [user](uint64_t entry)
    {
        return (entry & 1) != 0 && (entry >> 63) == 0 && (!user || (entry & 4) != 0);
    };
    if ((levels != 4 && levels != 5) ||
        (levels == 5 && (!valid(pml5e) || (pml5e & 0x80) != 0)) ||
        !valid(pml4e) || (pml4e & 0x80) != 0 || !valid(pdpte))
    {
        return false;
    }
    if ((pdpte & 0x80) != 0)
    {
        return pageSize == (1ull << 30) && (pdpte & 0x3FFFE000ull) == 0;
    }
    if (!valid(pde))
    {
        return false;
    }
    if ((pde & 0x80) != 0)
    {
        return pageSize == (1ull << 21) && (pde & 0x1FE000ull) == 0;
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
        RemoveIf([&](const auto& old)
        {
            return old.Identity.BootId != identity.BootId ||
                (old.Identity.ProcessId == identity.ProcessId && old.Identity.CreateTime != identity.CreateTime);
        });
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
            const AdmissionView incoming = {identity.ProcessId, identity.CreateTime, range.Address, role};
            auto victim = Work.end();
            for (auto row = Work.begin(); row != Work.end(); ++row)
            {
                const bool lowerPriority = row->Role == L"image_page_candidate" && role != L"image_page_candidate";
                if ((!lowerPriority && (row->NextOffset != 0 || !PreferAdmission(incoming, Key(*row)))) ||
                    (role == L"image_page_candidate" && row->Role != L"image_page_candidate"))
                {
                    continue;
                }
                if (victim == Work.end() ||
                    (row->Role == L"image_page_candidate" && victim->Role != L"image_page_candidate") ||
                    ((row->Role == L"image_page_candidate") == (victim->Role == L"image_page_candidate") &&
                        PreferAdmission(Key(*victim), Key(*row))))
                {
                    victim = row;
                }
            }
            if (victim == Work.end())
            {
                ++Deferred;
                return false;
            }
            Erase(victim);
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
                AdmissionAfter = Key(row);
                AdmissionKnown = true;
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
    uint64_t Deferred = 0;

private:
    using AdmissionKey = std::tuple<uint32_t, uint64_t, uint64_t, std::wstring>;
    using AdmissionView = std::tuple<const uint32_t&, const uint64_t&, const uint64_t&, const std::wstring&>;

    static AdmissionView Key(const KmonPageWork& row)
    {
        return {row.Identity.ProcessId, row.Identity.CreateTime, row.Range.Address, row.Role};
    }

    bool PreferAdmission(const AdmissionView& candidate, const AdmissionView& current) const
    {
        // Rotate after a completed range. Inventory order cannot always favor
        // the first nonresident range when a slot becomes available.
        if (AdmissionKnown && (candidate > AdmissionAfter) != (current > AdmissionAfter))
        {
            return candidate > AdmissionAfter;
        }
        return candidate < current;
    }

    std::vector<KmonPageWork>::iterator Erase(std::vector<KmonPageWork>::iterator row)
    {
        if (static_cast<size_t>(row - Work.begin()) < Cursor)
        {
            --Cursor;
        }
        return Work.erase(row);
    }

    template <typename Predicate>
    void RemoveIf(const Predicate& predicate)
    {
        for (auto row = Work.begin(); row != Work.end();)
        {
            if (predicate(*row))
            {
                row = Erase(row);
            }
            else
            {
                ++row;
            }
        }
    }

    void Expire(uint64_t now)
    {
        const size_t before = Work.size();
        RemoveIf([now](const auto& row)
        {
            return now >= row.LastSeenMs && now - row.LastSeenMs > 300000;
        });
        Expired += before - Work.size();
    }

    size_t Capacity;
    size_t Cursor = 0;
    uint64_t LastMs = 0;
    AdmissionKey AdmissionAfter;
    bool AdmissionKnown = false;
    std::vector<KmonPageWork> Work;
};
