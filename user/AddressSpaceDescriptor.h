#pragma once

#include <cstdint>

// Address shape is independent of mapping validity, ownership and OS policy.
// The default is the explicit compatibility contract for legacy v1 records.
struct AddressSpaceDescriptor
{
    uint8_t VirtualAddressBits = 48;
    uint8_t PointerBytes = 8;
    uint8_t PhysicalAddressBits = 0;
    bool LegacyAssumed = true;
    uint64_t UserMaximum = 0;
    uint64_t KernelMinimum = 0;

    static AddressSpaceDescriptor FromPagingLevels(uint32_t levels)
    {
        AddressSpaceDescriptor space;
        space.VirtualAddressBits = levels == 4 ? 48 : levels == 5 ? 57 : 0;
        space.LegacyAssumed = false;
        return space;
    }

    bool Valid() const
    {
        if ((VirtualAddressBits != 48 && VirtualAddressBits != 57) || PointerBytes != 8 ||
            (PhysicalAddressBits != 0 && (PhysicalAddressBits < 32 || PhysicalAddressBits > 52)) ||
            (LegacyAssumed && VirtualAddressBits != 48))
        {
            return false;
        }
        const uint64_t sign = uint64_t{1} << (VirtualAddressBits - 1);
        return (UserMaximum == 0 || UserMaximum < sign) &&
            (KernelMinimum == 0 || KernelMinimum >= ~(sign - 1));
    }

    bool Canonical(uint64_t address) const
    {
        if (!Valid())
        {
            return false;
        }
        const uint64_t sign = uint64_t{1} << (VirtualAddressBits - 1);
        return address < sign || address >= ~(sign - 1);
    }

    bool Range(uint64_t address, uint64_t bytes, bool kernel) const
    {
        if (!Valid() || bytes == 0 || address > UINT64_MAX - (bytes - 1))
        {
            return false;
        }
        const uint64_t last = address + bytes - 1;
        const uint64_t sign = uint64_t{1} << (VirtualAddressBits - 1);
        if (kernel)
        {
            return address >= ~(sign - 1) && (KernelMinimum == 0 || address >= KernelMinimum);
        }
        return last < sign && (UserMaximum == 0 || last <= UserMaximum);
    }

    bool KernelRange(uint64_t address, uint64_t bytes) const
    {
        return Range(address, bytes, true);
    }

    bool UserRange(uint64_t address, uint64_t bytes) const
    {
        return Range(address, bytes, false);
    }
};
