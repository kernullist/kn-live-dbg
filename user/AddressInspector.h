#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct AddressInspectResult
{
    uint64_t VirtualAddress = 0;

    // Canonicality / half-space
    bool     IsCanonical = false;
    bool     IsKernelSpace = false;
    bool     IsUserSpace = false;
    bool     IsZeroPage = false;
    bool     La57Active = false;

    // Module containing the address (if any kernel module spans it).
    bool     HasModule = false;
    std::wstring ModuleName;
    std::wstring ModulePath;
    uint64_t ModuleBase = 0;
    uint32_t ModuleSize = 0;
    uint64_t OffsetInModule = 0;

    // Nearest symbol (may span module boundary).
    bool     HasSymbol = false;
    std::wstring SymbolName;
    uint64_t SymbolDisplacement = 0;

    // Page-table walk (driver TranslateVirtual).
    bool     TranslationAttempted = false;
    bool     TranslationSucceeded = false;
    std::wstring TranslationError;
    uint64_t DirectoryTableBase = 0;
    uint64_t PhysicalAddress = 0;
    uint64_t PageSize = 0;
    uint64_t PageOffset = 0;
    uint64_t PageBytes = 0;
    uint32_t PagingLevels = 0;
    bool     LargePage = false;
    uint64_t Pml5e = 0;
    uint64_t Pml4e = 0;
    uint64_t Pdpte = 0;
    uint64_t Pde = 0;
    uint64_t Pte = 0;
    uint64_t Pml5eAddress = 0;
    uint64_t Pml4eAddress = 0;
    uint64_t PdpteAddress = 0;
    uint64_t PdeAddress = 0;
    uint64_t PteAddress = 0;

    // Effective permissions after ANDing W and ORing NX across all walked
    // levels. EffectiveExecutable = (no level has NX); EffectiveWritable =
    // (every level allows write). EffectiveUserAccessible mirrors the AND
    // of the U/S bit across levels.
    bool     EffectivePresent = false;
    bool     EffectiveWritable = false;
    bool     EffectiveExecutable = false;
    bool     EffectiveUserAccessible = false;

    std::vector<std::wstring> Warnings;
};

bool InspectAddress(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint64_t address,
    AddressInspectResult* result,
    std::wstring* error,
    uint64_t directoryTableBase = 0);

std::wstring BuildAddressInspectJson(const AddressInspectResult& result);
