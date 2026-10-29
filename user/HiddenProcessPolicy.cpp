#include "HiddenProcessPolicy.h"

#include <limits>
#include <unordered_set>

namespace
{
    bool ReadAt(HiddenProcessReader& reader, const AddressSpaceDescriptor& space,
        uint64_t base, uint64_t offset, uint8_t bytes, uint64_t* value)
    {
        if (reader.Stopped() || value == nullptr ||
            (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
            offset > UINT64_MAX - base || !space.KernelRange(base + offset, bytes))
        {
            return false;
        }
        *value = 0;
        return reader.Read(base + offset, bytes, value);
    }

    bool ReadField(HiddenProcessReader& reader, const AddressSpaceDescriptor& space,
        uint64_t base, const HiddenProcessField& field, uint64_t* value)
    {
        if (!field.Available || field.Offset > 0x10000 || field.BitCount > 64 ||
            (field.BitCount != 0 &&
                static_cast<unsigned>(field.BitPosition) + field.BitCount > field.Bytes * 8u) ||
            !ReadAt(reader, space, base, field.Offset, field.Bytes, value))
        {
            return false;
        }
        if (field.BitCount != 0)
        {
            *value >>= field.BitPosition;
            if (field.BitCount != 64)
            {
                *value &= (uint64_t{1} << field.BitCount) - 1;
            }
        }
        return true;
    }

    bool IntegerField(const HiddenProcessField& field, uint8_t bytes)
    {
        return field.Available && field.Bytes == bytes && field.BitCount == 0 &&
            field.BitPosition == 0;
    }
}

bool IsHiddenProcessCandidate(uint32_t pid, const HiddenProcessMembership& discovery)
{
    if (pid <= 4)
    {
        return false;
    }
    const bool api = discovery.Spi || discovery.Toolhelp;
    return discovery.Kernel ? !api : api || discovery.Cid || discovery.Handles;
}

HiddenProcessLifetime ReadHiddenProcessLifetime(
    HiddenProcessReader& reader, const AddressSpaceDescriptor& space,
    const HiddenProcessLayout& layout, uint32_t pid)
{
    HiddenProcessLifetime result;
    result.Pid = pid;
    do
    {
        if (pid <= 4 || reader.Stopped() || !IntegerField(layout.Pid, 8) ||
            !IntegerField(layout.CreateTime, 8) ||
            !reader.Resolve(pid, &result.Eprocess) || !space.KernelRange(result.Eprocess, 8))
        {
            break;
        }
        uint64_t observedPid = 0;
        if (!ReadField(reader, space, result.Eprocess, layout.Pid, &observedPid) ||
            observedPid != pid ||
            !ReadField(reader, space, result.Eprocess, layout.CreateTime, &result.CreateTime) ||
            result.CreateTime == 0)
        {
            break;
        }
        uint64_t threads = 0;
        result.HasActiveThreads = IntegerField(layout.ActiveThreads, 4) &&
            ReadField(reader, space, result.Eprocess, layout.ActiveThreads, &threads) &&
            threads <= UINT32_MAX;
        result.ActiveThreads = static_cast<uint32_t>(threads);
        result.HasExitTime = IntegerField(layout.ExitTime, 8) &&
            ReadField(reader, space, result.Eprocess, layout.ExitTime, &result.ExitTime);
        uint64_t auxiliary = 0;
        result.HasAuxiliary = layout.Auxiliary.BitCount == 1 &&
            ReadField(reader, space, result.Eprocess, layout.Auxiliary, &auxiliary);
        result.Auxiliary = result.HasAuxiliary && auxiliary != 0;
        uint64_t exiting = 0;
        uint64_t deleting = 0;
        uint64_t rundown = 0;
        result.HasStateFlags = layout.ProcessExiting.BitCount == 1 &&
            layout.ProcessDelete.BitCount == 1 && layout.ProcessRundown.BitCount == 1 &&
            ReadField(reader, space, result.Eprocess, layout.ProcessExiting, &exiting) &&
            ReadField(reader, space, result.Eprocess, layout.ProcessDelete, &deleting) &&
            ReadField(reader, space, result.Eprocess, layout.ProcessRundown, &rundown);
        result.StateTransition = exiting != 0 || deleting != 0 || rundown != 0;

        uint64_t finalPid = 0;
        uint64_t finalCreated = 0;
        uint64_t finalObject = 0;
        result.IdentityValid =
            ReadField(reader, space, result.Eprocess, layout.Pid, &finalPid) && finalPid == pid &&
            ReadField(reader, space, result.Eprocess, layout.CreateTime, &finalCreated) &&
            finalCreated == result.CreateTime && !reader.Stopped() &&
            reader.Resolve(pid, &finalObject) && finalObject == result.Eprocess;
    } while (false);
    return result;
}

HiddenProcessKernelView ReadHiddenProcessKernelView(
    HiddenProcessReader& reader, const AddressSpaceDescriptor& space,
    const HiddenProcessLayout& layout, uint32_t limit)
{
    HiddenProcessKernelView result;
    result.Reason = L"ActiveProcessLinks layout or list head was unavailable";
    do
    {
        if (!layout.LinksAvailable || layout.LinksOffset > 0x10000 ||
            !IntegerField(layout.Pid, 8) || limit == 0 || limit > 8192 ||
            !space.KernelRange(layout.ListHead, 16) || (layout.ListHead & 7) != 0)
        {
            break;
        }
        uint64_t first = 0;
        uint64_t initialLast = 0;
        if (!ReadAt(reader, space, layout.ListHead, 0, 8, &first) ||
            !ReadAt(reader, space, layout.ListHead, 8, 8, &initialLast))
        {
            result.Reason = L"ActiveProcessLinks list head read failed";
            break;
        }
        uint64_t current = first;
        uint64_t previous = layout.ListHead;
        std::unordered_set<uint64_t> visited;
        result.Reason = L"ActiveProcessLinks was truncated, unreadable, or changed during the walk";
        while (current != layout.ListHead && !reader.Stopped())
        {
            if (result.Entries.size() >= limit || !space.KernelRange(current, 16) ||
                (current & 7) != 0 || current < layout.LinksOffset || !visited.insert(current).second)
            {
                break;
            }
            uint64_t next = 0;
            uint64_t back = 0;
            uint64_t pid = 0;
            HiddenProcessKernelEntry entry;
            entry.Eprocess = current - layout.LinksOffset;
            if (!ReadAt(reader, space, current, 0, 8, &next) ||
                !ReadAt(reader, space, current, 8, 8, &back) || back != previous ||
                !ReadField(reader, space, entry.Eprocess, layout.Pid, &pid) || pid > UINT32_MAX)
            {
                break;
            }
            entry.HasCreateTime = IntegerField(layout.CreateTime, 8) &&
                ReadField(reader, space, entry.Eprocess, layout.CreateTime, &entry.CreateTime) &&
                entry.CreateTime != 0;
            if (!result.Entries.emplace(static_cast<uint32_t>(pid), entry).second)
            {
                result.Reason = L"ActiveProcessLinks contained a duplicate PID";
                break;
            }
            previous = current;
            current = next;
        }
        uint64_t finalFirst = 0;
        uint64_t finalLast = 0;
        if (current == layout.ListHead && !result.Entries.empty() && previous == initialLast &&
            ReadAt(reader, space, layout.ListHead, 0, 8, &finalFirst) && first == finalFirst &&
            ReadAt(reader, space, layout.ListHead, 8, 8, &finalLast) && previous == finalLast &&
            !reader.Stopped())
        {
            result.Complete = true;
            result.Reason.clear();
        }
    } while (false);
    return result;
}

HiddenProcessDecision QualifyHiddenProcess(uint32_t pid,
    const HiddenProcessMembership& discovery, const HiddenProcessQualification& q)
{
    HiddenProcessDecision result;
    if (!IsHiddenProcessCandidate(pid, discovery))
    {
        return result;
    }
    result.Disposition = HiddenProcessDisposition::Unverified;
    result.Reason = L"comparison_unavailable";
    result.Notes = L"candidate has no lifetime-bracketed comparison";
    if (q.BudgetExceeded)
    {
        result.Reason = L"qualification_budget";
        result.Notes = L"candidate qualification exceeded its count or cooperative time budget";
        return result;
    }
    if (!q.Attempted)
    {
        return result;
    }
    if (!q.KernelComplete || !q.SpiComplete || !q.ToolhelpComplete)
    {
        result.Reason = L"incomplete_comparison";
        result.Notes = L"kernel, SPI, or Toolhelp comparison inventory was incomplete";
        return result;
    }
    const auto& a = q.Before;
    const auto& b = q.After;
    if (!a.IdentityValid || !b.IdentityValid || a.Pid != pid || b.Pid != pid ||
        a.Eprocess == 0 || b.Eprocess == 0 || a.CreateTime == 0 || b.CreateTime == 0)
    {
        result.Reason = L"identity_unavailable";
        result.Notes = L"PID, EPROCESS, and creation time were not readable at both comparison boundaries";
        return result;
    }
    if (a.Eprocess != b.Eprocess || a.CreateTime != b.CreateTime ||
        (q.Views.Kernel && (!q.KernelIdentity.HasCreateTime ||
            q.KernelIdentity.Eprocess != a.Eprocess || q.KernelIdentity.CreateTime != a.CreateTime)))
    {
        result.Reason = L"identity_changed";
        result.Notes = L"process identity changed or conflicted within the comparison window";
        return result;
    }
    result.StableLifetime = true;
    if (!a.HasExitTime || !b.HasExitTime || !a.HasActiveThreads || !b.HasActiveThreads)
    {
        result.Reason = L"lifecycle_unavailable";
        result.Notes = L"ExitTime and ActiveThreads were not readable at both comparison boundaries";
        return result;
    }
    if (a.ExitTime != 0 || b.ExitTime != 0 || a.ActiveThreads == 0 || b.ActiveThreads == 0)
    {
        result.Disposition = HiddenProcessDisposition::Terminating;
        result.Reason = L"terminating";
        result.Notes = L"the matched process lifetime had exit or zero-thread state during comparison";
        return result;
    }
    const bool api = q.Views.Spi || q.Views.Toolhelp;
    if (q.Views.Kernel && api)
    {
        result.Disposition = HiddenProcessDisposition::Reconciled;
        result.Reason = L"reconciled";
        result.Notes = L"candidate was present in kernel and API views during the qualified comparison";
        return result;
    }
    if (!a.HasStateFlags || !b.HasStateFlags)
    {
        result.Reason = L"lifecycle_unavailable";
        result.Notes = L"process exit/delete/rundown flags were not readable at both comparison boundaries";
        return result;
    }
    if (a.StateTransition || b.StateTransition)
    {
        result.Reason = L"lifecycle_transition";
        result.Notes = L"process exit/delete/rundown state was active during the comparison window";
        return result;
    }
    if (q.Views.Kernel && !api)
    {
        if (!a.HasAuxiliary || !b.HasAuxiliary || a.Auxiliary != b.Auxiliary)
        {
            result.Reason = L"auxiliary_unavailable";
            result.Notes = L"auxiliary/snapshot-clone state was unavailable or changed during comparison";
            return result;
        }
        if (a.Auxiliary)
        {
            result.Disposition = HiddenProcessDisposition::Auxiliary;
            result.Reason = L"auxiliary";
            result.Notes = L"matched auxiliary/snapshot clone was linked but omitted from API views";
            return result;
        }
    }
    result.Disposition = HiddenProcessDisposition::CrossViewDiscrepancy;
    result.Reason = q.Views.Kernel ? L"kernel_only" : api ? L"api_only" : L"cid_only";
    result.Notes = L"same sampled process lifetime had a complete cross-view discrepancy; no hiding mechanism or actor established";
    return result;
}

const wchar_t* HiddenProcessDispositionName(HiddenProcessDisposition value)
{
    switch (value)
    {
    case HiddenProcessDisposition::Unverified:
        return L"unverified";
    case HiddenProcessDisposition::CrossViewDiscrepancy:
        return L"cross_view_discrepancy";
    case HiddenProcessDisposition::Auxiliary:
        return L"auxiliary";
    case HiddenProcessDisposition::Terminating:
        return L"terminating";
    case HiddenProcessDisposition::Reconciled:
        return L"reconciled";
    default:
        return L"not_candidate";
    }
}
