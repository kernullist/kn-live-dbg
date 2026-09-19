#pragma once

#include "ObservationModel.h"

#include <algorithm>
#include <memory>

namespace process_layout
{
    constexpr uint32_t Commit = 0x1000;
    constexpr uint32_t Reserve = 0x2000;
    constexpr uint32_t Free = 0x10000;
    constexpr uint32_t Private = 0x20000;
    constexpr uint32_t Mapped = 0x40000;
    constexpr uint32_t Image = 0x1000000;
    constexpr size_t MaxRegions = 32768;
    constexpr uint64_t MaxSweepMs = 30000;

    struct Region
    {
        uint64_t Base = 0;
        uint64_t Size = 0;
        uint64_t AllocationBase = 0;
        uint32_t State = Free;
        uint32_t Protect = 0;
        uint32_t AllocationProtect = 0;
        uint32_t Type = 0;

        bool Executable() const
        {
            return State == Commit && (Protect & 0xF0) != 0;
        }

        bool SameAttributes(const Region& other) const
        {
            return AllocationBase == other.AllocationBase && State == other.State &&
                Protect == other.Protect && AllocationProtect == other.AllocationProtect && Type == other.Type;
        }
    };

    struct Snapshot
    {
        ObservationIdentity Identity;
        uint64_t StartedMs = 0;
        uint64_t FinishedMs = 0;
        uint64_t ObservedAt = 0;
        uint64_t Limit = 0;
        uint64_t Cursor = 0;
        uint64_t Queries = 0;
        bool Complete = false;
        std::vector<Region> Regions;
        // Names identify observations, not the file object that created a section.
        std::map<uint64_t, std::wstring> ImageNames;
        uint64_t ImageNameFailures = 0;

        bool Valid() const
        {
            if (!Complete || Limit == 0 || Limit > 0x800000000000ull || Cursor != Limit ||
                Identity.ProcessId <= 4 || Identity.CreateTime == 0 || Identity.BootId.empty() ||
                FinishedMs < StartedMs || FinishedMs - StartedMs > MaxSweepMs || Regions.size() > MaxRegions)
            {
                return false;
            }
            uint64_t end = 0;
            for (const auto& row : Regions)
            {
                if (row.Base < end || row.Base >= Limit || row.Size == 0 || row.Size > Limit - row.Base ||
                    row.AllocationBase > row.Base || (row.State != Commit && row.State != Reserve))
                {
                    return false;
                }
                end = row.Base + row.Size;
            }
            return true;
        }
    };

    // A query must cover the exact next address. A changed boundary invalidates
    // the sweep instead of stitching a newly merged range onto stale rows.
    inline bool Append(Snapshot& snapshot, Region row, size_t capacity = MaxRegions)
    {
        bool accepted = false;
        do
        {
            if (snapshot.Complete || snapshot.Limit == 0 || snapshot.Cursor >= snapshot.Limit ||
                row.Base != snapshot.Cursor || row.Size == 0 || row.Base > UINT64_MAX - row.Size ||
                (row.State != Commit && row.State != Reserve && row.State != Free) ||
                (row.State != Free && row.AllocationBase > row.Base))
            {
                break;
            }
            row.Size = (std::min)(row.Size, snapshot.Limit - row.Base);
            if (row.State != Free)
            {
                if (snapshot.Regions.size() >= (std::min)(capacity, MaxRegions))
                {
                    break;
                }
                if (row.State == Reserve)
                {
                    row.Protect = 0;
                }
                snapshot.Regions.push_back(row);
            }
            snapshot.Cursor = row.Base + row.Size;
            ++snapshot.Queries;
            accepted = true;
        }
        while (false);
        return accepted;
    }

    enum ChangeFlag : uint32_t
    {
        Added = 1,
        Removed = 2,
        AllocationChanged = 4,
        StateChanged = 8,
        ProtectionChanged = 16,
        TypeChanged = 32,
        BecameExecutable = 64,
        LostExecutable = 128,
        ImageReplaced = 256,
        ImageNameChanged = 512
    };

    struct Change
    {
        uint64_t Base = 0;
        uint64_t Size = 0;
        uint32_t Flags = 0;
        Region Before;
        Region After;

        bool Candidate() const
        {
            return (Flags & (BecameExecutable | ImageReplaced | ImageNameChanged)) != 0 ||
                ((Flags & LostExecutable) != 0 && After.State != Free) ||
                (After.Executable() && (Flags & (AllocationChanged | ProtectionChanged | TypeChanged)) != 0);
        }
    };

    struct Delta
    {
        bool Comparable = false;
        uint64_t BeforeMs = 0;
        uint64_t AfterMs = 0;
        uint64_t ChangedRanges = 0;
        uint64_t CandidateRanges = 0;
        std::vector<Change> Changes;
    };

    inline bool ChangedName(const Snapshot& before, const Snapshot& after, const Region& left, const Region& right)
    {
        const auto a = before.ImageNames.find(left.AllocationBase);
        const auto b = after.ImageNames.find(right.AllocationBase);
        return left.Type == Image && right.Type == Image && a != before.ImageNames.end() &&
            b != after.ImageNames.end() && !a->second.empty() && !b->second.empty() && a->second != b->second;
    }

    // Compare intervals, not vector indices: VirtualProtect may split one MBI
    // into three, and a later protection change may merge them again.
    inline Delta Compare(const Snapshot& before, const Snapshot& after, size_t limit = 256)
    {
        Delta result;
        if (!before.Valid() || !after.Valid() || !before.Identity.SameInstance(after.Identity) ||
            before.Limit != after.Limit || after.StartedMs < before.FinishedMs)
        {
            return result;
        }
        result.Comparable = true;
        result.BeforeMs = before.FinishedMs;
        result.AfterMs = after.FinishedMs;
        size_t leftIndex = 0;
        size_t rightIndex = 0;
        uint64_t cursor = 0;
        while (cursor < before.Limit)
        {
            while (leftIndex < before.Regions.size() &&
                before.Regions[leftIndex].Base + before.Regions[leftIndex].Size <= cursor)
            {
                ++leftIndex;
            }
            while (rightIndex < after.Regions.size() &&
                after.Regions[rightIndex].Base + after.Regions[rightIndex].Size <= cursor)
            {
                ++rightIndex;
            }
            Region a;
            Region b;
            uint64_t next = before.Limit;
            const auto select = [&](const std::vector<Region>& rows, size_t index, Region& row)
            {
                if (index < rows.size())
                {
                    if (rows[index].Base <= cursor)
                    {
                        row = rows[index];
                        next = (std::min)(next, row.Base + row.Size);
                    }
                    else
                    {
                        next = (std::min)(next, rows[index].Base);
                    }
                }
            };
            select(before.Regions, leftIndex, a);
            select(after.Regions, rightIndex, b);
            uint32_t flags = 0;
            if (!a.SameAttributes(b))
            {
                if (a.State == Free)
                {
                    flags |= Added;
                }
                else if (b.State == Free)
                {
                    flags |= Removed;
                }
                else
                {
                    flags |= a.AllocationBase != b.AllocationBase ? AllocationChanged : 0;
                    flags |= a.State != b.State ? StateChanged : 0;
                    flags |= a.Protect != b.Protect || a.AllocationProtect != b.AllocationProtect ? ProtectionChanged : 0;
                    flags |= a.Type != b.Type ? TypeChanged : 0;
                }
                flags |= !a.Executable() && b.Executable() ? BecameExecutable : 0;
                flags |= a.Executable() && !b.Executable() ? LostExecutable : 0;
                flags |= a.Type == Image && b.State != Free &&
                    (b.Type != Image || a.AllocationBase != b.AllocationBase) ? ImageReplaced : 0;
            }
            if (ChangedName(before, after, a, b))
            {
                flags |= ImageNameChanged;
            }
            if (flags != 0)
            {
                Change change{cursor, next - cursor, flags, a, b};
                ++result.ChangedRanges;
                if (change.Candidate())
                {
                    ++result.CandidateRanges;
                }
                if (result.Changes.size() < limit)
                {
                    result.Changes.push_back(change);
                }
                else if (change.Candidate())
                {
                    // Ordinary heap churn must not crowd all executable leads out.
                    auto ordinary = std::find_if(result.Changes.rbegin(), result.Changes.rend(),
                        [](const Change& item)
                        {
                            return !item.Candidate();
                        });
                    if (ordinary != result.Changes.rend())
                    {
                        *ordinary = change;
                    }
                }
            }
            cursor = next;
        }
        return result;
    }

    struct History
    {
        std::shared_ptr<const Snapshot> Initial;
        std::shared_ptr<const Snapshot> Current;
        Delta LastDelta;
        uint64_t Completed = 0;

        bool Accept(std::shared_ptr<const Snapshot> snapshot)
        {
            if (!snapshot || !snapshot->Valid() || (Current &&
                (!Current->Identity.SameInstance(snapshot->Identity) || Current->Limit != snapshot->Limit ||
                    snapshot->StartedMs < Current->FinishedMs)))
            {
                return false;
            }
            LastDelta = Current ? Compare(*Current, *snapshot) : Delta{};
            if (!Initial)
            {
                Initial = snapshot;
            }
            Current = std::move(snapshot);
            ++Completed;
            return true;
        }

        size_t StoredRows() const
        {
            return (Initial ? Initial->Regions.size() : 0) +
                (Current && Current != Initial ? Current->Regions.size() : 0);
        }
    };
}
