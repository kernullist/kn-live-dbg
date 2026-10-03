#pragma once

#include "KnLiveDbgIoctl.h"

// Check fixed architectural reserved bits in a present IA-32e paging entry.
// Levels are PTE=1, PDE=2, PDPTE=3, PML4E=4, and PML5E=5.
// MAXPHYADDR and optional platform paging features require separate checks.
inline bool KnDbgPresentPagingEntryValid(KNDBG_UINT64 entry, unsigned int level)
{
    bool valid = false;

    do
    {
        if (level < 1 || level > 5 || (entry & 1ull) == 0)
        {
            break;
        }
        const bool pageSize = (entry & 0x80ull) != 0;
        if (level >= 4 && pageSize)
        {
            break;
        }
        if (level == 3 && pageSize && (entry & 0x3FFFE000ull) != 0)
        {
            break;
        }
        if (level == 2 && pageSize && (entry & 0x1FE000ull) != 0)
        {
            break;
        }
        // PAT is bit 12 in large leaves and bit 7 in a 4 KB PTE; NX is legal.
        valid = true;
    } while (false);

    return valid;
}
