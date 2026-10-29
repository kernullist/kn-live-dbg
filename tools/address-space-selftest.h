#pragma once

#include "../user/KmonHunting.h"

inline bool AddressSpaceSelfTest()
{
    for (uint32_t levels : {4u, 5u})
    {
        auto space = AddressSpaceDescriptor::FromPagingLevels(levels);
        const uint64_t sign = uint64_t{1} << (space.VirtualAddressBits - 1);
        const uint64_t kernel = ~(sign - 1);
        if (!space.Valid() || !space.Canonical(sign - 1) || space.Canonical(sign) ||
            space.Canonical(kernel - 1) || !space.Canonical(kernel) ||
            !space.UserRange(sign - 4096, 4096) || space.UserRange(sign - 4096, 4097) ||
            !space.KernelRange(kernel, 4096) || space.KernelRange(kernel - 1, 4096) ||
            !space.KernelRange(UINT64_MAX, 1) || space.KernelRange(UINT64_MAX, 2) ||
            space.KernelRange(kernel, 0) || space.UserRange(sign - 1, UINT64_MAX))
        {
            return false;
        }
        KmonHuntReference reference;
        reference.Context.Identity.BootId = L"address_fixture";
        reference.Context.Identity.ProcessId = 100;
        reference.Context.Identity.CreateTime = 1;
        reference.Context.AddressSpace = space;
        reference.Context.MonotonicMs = 100;
        reference.Context.Ownership = CodeOwnership::UnownedExecutable;
        reference.Address = sign - 4096;
        reference.Role = L"tls_callback";
        KmonHuntIndex index;
        if (index.Observe(reference, 100) == 0)
        {
            return false;
        }
        reference.Address = sign;
        if (index.Observe(reference, 100) != 0)
        {
            return false;
        }
        reference.Context.Identity.ProcessId = 0;
        reference.Address = kernel;
        if (index.Observe(reference, 100) == 0 || !KmonChannelCandidate(kernel, kernel + 8, true, space))
        {
            return false;
        }
        KmonExecutablePages pages;
        if (!pages.Observe(reference.Context.Identity, {kernel, 4096}, kernel, L"kernel_page_candidate", 100, space))
        {
            return false;
        }
        space.UserMaximum = 0x7fffffff;
        space.KernelMinimum = 0xffff800000000000ull;
        if (!space.Valid() || space.UserRange(0x80000000, 1) ||
            (levels == 5 && space.KernelRange(kernel, 1)))
        {
            return false;
        }
    }
    auto invalid = AddressSpaceDescriptor::FromPagingLevels(0);
    if (invalid.Valid() || invalid.Canonical(0) || invalid.UserRange(0x10000, 1))
    {
        return false;
    }
    invalid = AddressSpaceDescriptor::FromPagingLevels(5);
    invalid.LegacyAssumed = true;
    return !invalid.Valid() && !AddressSpaceDescriptor{}.Canonical(0x1000000000000ull);
}
