#include "AddressInspector.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "McpJson.h"

#include <Windows.h>
#include <cstdio>

namespace
{
    // x86-64 canonical address test. Bits above the addressable line must be
    // all-zero or all-one. With LA48 (typical) the cut-off is bit 47, with
    // LA57 it is bit 56. We optimistically check both -- the helper accepts
    // any address that satisfies either rule because we only know which rule
    // applies after a TranslateVirtual round-trip.
    bool IsCanonicalAddress(uint64_t address)
    {
        uint64_t hiLa48 = address >> 47;
        if (hiLa48 == 0 || hiLa48 == 0x1FFFFull)
        {
            return true;
        }
        uint64_t hiLa57 = address >> 56;
        if (hiLa57 == 0 || hiLa57 == 0xFFull)
        {
            return true;
        }
        return false;
    }

    bool IsKernelHalfLa48(uint64_t address)
    {
        return address >= 0xFFFF800000000000ull;
    }

    bool IsKernelHalfLa57(uint64_t address)
    {
        return address >= 0xFF00000000000000ull;
    }

    void WalkPtePermissions(const AddressInspectResult& r,
                            const PhysicalTranslationInfo& info,
                            bool* present,
                            bool* writable,
                            bool* executable,
                            bool* userAccess)
    {
        const bool la57 = (info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
        const uint64_t levels[5] =
        {
            info.Pml5e,
            info.Pml4e,
            info.Pdpte,
            info.Pde,
            info.Pte
        };

        const size_t startIndex = la57 ? 0 : 1;
        size_t walkCount = info.PagingLevels;
        if (walkCount > 5)
        {
            walkCount = 5;
        }

        bool p = walkCount > 0;
        bool w = walkCount > 0;
        bool x = walkCount > 0;
        bool u = walkCount > 0;

        for (size_t step = 0; step < walkCount; ++step)
        {
            size_t levelIdx = startIndex + step;
            if (levelIdx >= 5)
            {
                break;
            }
            uint64_t pte = levels[levelIdx];
            if ((pte & 1ULL) == 0)        p = false;
            if ((pte & (1ULL << 1)) == 0) w = false;
            if ((pte & (1ULL << 2)) == 0) u = false;
            if ((pte & (1ULL << 63)) != 0) x = false;

            // Large-page short-circuit: PS=1 at PDPTE (1 GB) or PDE (2 MB)
            // marks the leaf. The PTE level below is unused (and reported
            // as zero by the driver), so walking it would erroneously clear
            // Present/Writable on what is actually a valid large mapping.
            // PS lives in bit 7 of PDPTE and PDE only -- bit 7 of PTE is
            // the PAT bit and must not be tested. levelIdx 2 = PDPTE,
            // levelIdx 3 = PDE (same indices for both LA48 and LA57).
            if ((levelIdx == 2 || levelIdx == 3) && (pte & (1ULL << 7)) != 0)
            {
                break;
            }
        }

        *present = p;
        *writable = p && w;
        *executable = p && x;
        *userAccess = p && u;

        (void)r;
    }
}

bool InspectAddress(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint64_t address,
    AddressInspectResult* result,
    std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"InspectAddress called without result buffer";
        }
        return false;
    }

    *result = AddressInspectResult{};
    result->VirtualAddress = address;
    result->IsCanonical = IsCanonicalAddress(address);
    result->IsZeroPage = (address < 0x1000ull);

    // Defer LA57 detection until we have a real TranslateVirtual response;
    // for now use the LA48 split as the working hypothesis.
    result->IsKernelSpace = IsKernelHalfLa48(address);
    result->IsUserSpace = result->IsCanonical && !result->IsKernelSpace;

    // Module containing the address. SymbolEngine.Modules() returns the
    // currently-loaded kernel modules; we treat ranges as half-open.
    const std::vector<KernelModuleInfo>& modules = symbols.Modules();
    for (const KernelModuleInfo& module : modules)
    {
        if (address >= module.Base &&
            address < module.Base + static_cast<uint64_t>(module.Size))
        {
            result->HasModule = true;
            result->ModuleName = module.ImageName;
            result->ModulePath = module.ImagePath;
            result->ModuleBase = module.Base;
            result->ModuleSize = module.Size;
            result->OffsetInModule = address - module.Base;
            break;
        }
    }

    // Nearest symbol via DbgHelp / DIA. This works even for addresses
    // outside the module-list span (e.g. pool allocations near a module),
    // although the displacement may be large.
    std::wstring symbolName;
    uint64_t symbolDisplacement = 0;
    std::wstring symbolError;
    if (symbols.FindNearestSymbol(address, &symbolName, &symbolDisplacement, &symbolError))
    {
        result->HasSymbol = true;
        result->SymbolName = symbolName;
        result->SymbolDisplacement = symbolDisplacement;
    }

    // Page-table walk via the driver IOCTL. We only attempt this for
    // canonical addresses; non-canonical reads would fault deterministically.
    if (result->IsCanonical)
    {
        PhysicalTranslationInfo info = {};
        std::wstring translateError;
        result->TranslationAttempted = true;

        if (device.TranslateVirtual(0, address, 1, &info, &translateError))
        {
            result->TranslationSucceeded = true;
            result->DirectoryTableBase = info.DirectoryTableBase;
            result->PhysicalAddress = info.PhysicalAddress;
            result->PageSize = info.PageSize;
            result->PageOffset = info.PageOffset;
            result->PageBytes = info.PageBytes;
            result->PagingLevels = info.PagingLevels;
            result->LargePage = (info.Flags & KNDBG_TRANSLATE_FLAG_LARGE_PAGE) != 0;
            result->La57Active = (info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
            result->Pml5e = info.Pml5e;
            result->Pml4e = info.Pml4e;
            result->Pdpte = info.Pdpte;
            result->Pde = info.Pde;
            result->Pte = info.Pte;
            result->Pml5eAddress = info.Pml5eAddress;
            result->Pml4eAddress = info.Pml4eAddress;
            result->PdpteAddress = info.PdpteAddress;
            result->PdeAddress = info.PdeAddress;
            result->PteAddress = info.PteAddress;

            // Re-evaluate kernel/user split using LA57 if active.
            if (result->La57Active)
            {
                result->IsKernelSpace = IsKernelHalfLa57(address);
                result->IsUserSpace = result->IsCanonical && !result->IsKernelSpace;
            }

            bool present = false;
            bool writable = false;
            bool executable = false;
            bool userAccess = false;
            WalkPtePermissions(*result, info, &present, &writable, &executable, &userAccess);
            result->EffectivePresent = present;
            result->EffectiveWritable = writable;
            result->EffectiveExecutable = executable;
            result->EffectiveUserAccessible = userAccess;
        }
        else
        {
            result->TranslationError = translateError;
        }
    }
    else
    {
        result->Warnings.push_back(L"address is non-canonical; skipping page-table walk");
    }

    (void)error;
    return true;
}

namespace
{
    std::wstring AddressJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildAddressInspectJson(const AddressInspectResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.address.v1\"";

    // Identity: always emit the inspected virtual address.
    out += L",\"virtualAddress\":" + mcpjson::Quote(AddressJsonHex(result.VirtualAddress));

    // Canonicality / half-space classification.
    out += L",\"isCanonical\":";
    out += result.IsCanonical ? L"true" : L"false";
    out += L",\"isKernelSpace\":";
    out += result.IsKernelSpace ? L"true" : L"false";
    out += L",\"isUserSpace\":";
    out += result.IsUserSpace ? L"true" : L"false";
    out += L",\"isZeroPage\":";
    out += result.IsZeroPage ? L"true" : L"false";
    out += L",\"la57Active\":";
    out += result.La57Active ? L"true" : L"false";

    // Module containing the address (if any kernel module spans it).
    if (result.HasModule)
    {
        out += L",\"moduleName\":" + mcpjson::Quote(result.ModuleName);
        out += L",\"modulePath\":" + mcpjson::Quote(result.ModulePath);
        out += L",\"moduleBase\":" + mcpjson::Quote(AddressJsonHex(result.ModuleBase));
        out += L",\"moduleSize\":" + std::to_wstring(result.ModuleSize);
        out += L",\"offsetInModule\":" + mcpjson::Quote(AddressJsonHex(result.OffsetInModule));
    }

    // Nearest symbol (may span the module boundary).
    if (result.HasSymbol)
    {
        out += L",\"symbolName\":" + mcpjson::Quote(result.SymbolName);
        out += L",\"symbolDisplacement\":" + mcpjson::Quote(AddressJsonHex(result.SymbolDisplacement));
    }

    // Page-table walk state.
    out += L",\"translationAttempted\":";
    out += result.TranslationAttempted ? L"true" : L"false";
    out += L",\"translationSucceeded\":";
    out += result.TranslationSucceeded ? L"true" : L"false";
    if (!result.TranslationError.empty())
    {
        out += L",\"translationError\":" + mcpjson::Quote(result.TranslationError);
    }

    if (result.TranslationSucceeded)
    {
        out += L",\"directoryTableBase\":" + mcpjson::Quote(AddressJsonHex(result.DirectoryTableBase));
        out += L",\"physicalAddress\":" + mcpjson::Quote(AddressJsonHex(result.PhysicalAddress));
        out += L",\"pageSize\":" + std::to_wstring(result.PageSize);
        out += L",\"pageOffset\":" + std::to_wstring(result.PageOffset);
        out += L",\"pageBytes\":" + std::to_wstring(result.PageBytes);
        out += L",\"pagingLevels\":" + std::to_wstring(result.PagingLevels);
        out += L",\"largePage\":";
        out += result.LargePage ? L"true" : L"false";

        // Walk entries plus their slot addresses. Each is emitted only when
        // non-zero so unused levels (e.g. PML5E without LA57) stay out of the
        // record and the leaf large-page level does not advertise a stale PTE.
        if (result.Pml5e != 0)
        {
            out += L",\"pml5e\":" + mcpjson::Quote(AddressJsonHex(result.Pml5e));
        }
        if (result.Pml4e != 0)
        {
            out += L",\"pml4e\":" + mcpjson::Quote(AddressJsonHex(result.Pml4e));
        }
        if (result.Pdpte != 0)
        {
            out += L",\"pdpte\":" + mcpjson::Quote(AddressJsonHex(result.Pdpte));
        }
        if (result.Pde != 0)
        {
            out += L",\"pde\":" + mcpjson::Quote(AddressJsonHex(result.Pde));
        }
        if (result.Pte != 0)
        {
            out += L",\"pte\":" + mcpjson::Quote(AddressJsonHex(result.Pte));
        }
        if (result.Pml5eAddress != 0)
        {
            out += L",\"pml5eAddress\":" + mcpjson::Quote(AddressJsonHex(result.Pml5eAddress));
        }
        if (result.Pml4eAddress != 0)
        {
            out += L",\"pml4eAddress\":" + mcpjson::Quote(AddressJsonHex(result.Pml4eAddress));
        }
        if (result.PdpteAddress != 0)
        {
            out += L",\"pdpteAddress\":" + mcpjson::Quote(AddressJsonHex(result.PdpteAddress));
        }
        if (result.PdeAddress != 0)
        {
            out += L",\"pdeAddress\":" + mcpjson::Quote(AddressJsonHex(result.PdeAddress));
        }
        if (result.PteAddress != 0)
        {
            out += L",\"pteAddress\":" + mcpjson::Quote(AddressJsonHex(result.PteAddress));
        }

        // Effective permissions after combining all walked levels.
        out += L",\"effectivePresent\":";
        out += result.EffectivePresent ? L"true" : L"false";
        out += L",\"effectiveWritable\":";
        out += result.EffectiveWritable ? L"true" : L"false";
        out += L",\"effectiveExecutable\":";
        out += result.EffectiveExecutable ? L"true" : L"false";
        out += L",\"effectiveUserAccessible\":";
        out += result.EffectiveUserAccessible ? L"true" : L"false";
    }

    out += L",\"warnings\":[";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[index]);
    }
    out += L"]}";

    return out;
}
