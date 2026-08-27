#include "OrphanKernelPageScanner.h"

#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace
{
    constexpr uint64_t kPtePresent = 1ull;
    constexpr uint64_t kPteWritable = 1ull << 1;
    constexpr uint64_t kPteUser = 1ull << 2;
    constexpr uint64_t kPteLarge = 1ull << 7;
    constexpr uint64_t kPteNx = 1ull << 63;
    constexpr uint64_t kPtePfnMask = 0x000FFFFFFFFFF000ull;
    constexpr uint32_t kActiveAndValid = 6;
    constexpr uint32_t kDefaultLimit = 64;
    constexpr uint32_t kMaxLimit = 512;
    constexpr uint32_t kDefaultMaxPfn = 4u * 1024u * 1024u;
    constexpr uint32_t kPfnChunkBytes = 0x40000;

    uint64_t EntryPhysical(uint64_t entry)
    {
        return entry & kPtePfnMask;
    }

    bool EntryPresent(uint64_t entry)
    {
        return (entry & kPtePresent) != 0;
    }

    bool EntryWritable(uint64_t entry)
    {
        return (entry & kPteWritable) != 0;
    }

    bool EntryExecutable(uint64_t entry)
    {
        return (entry & kPteNx) == 0;
    }

    bool EntryLarge(uint64_t entry)
    {
        return (entry & kPteLarge) != 0;
    }

    bool RegionOverlapsModule(
        const std::vector<LeftoverModuleRange>& modules,
        uint64_t start,
        uint64_t size)
    {
        bool overlaps = false;
        uint64_t end = 0;
        if (!LeftoverTryAdd(start, size, &end))
        {
            return true;
        }

        for (const LeftoverModuleRange& module : modules)
        {
            if (start < module.End && end > module.Base)
            {
                overlaps = true;
                break;
            }
        }
        return overlaps;
    }

    bool LooksLikePciMmioHole(uint64_t physical)
    {
        return physical >= 0x00000000F0000000ull &&
            physical < 0x0000000100000000ull;
    }

    bool LooksLikeSystemWxWindow(const OrphanKernelPageRegion& region)
    {
        if (region.HasPe)
        {
            return false;
        }
        // Coalesced 4K RWX runs are not large pages. Only PS=1 leaves.
        if (region.LargePage && region.Size >= 0x200000ull)
        {
            return true;
        }
        // Firmware option-ROM in the PCI hole is typically not writable.
        // W+X in that window is leftover executable, not an MMIO ROM.
        return LooksLikePciMmioHole(region.PhysicalAddress) && !region.Writable;
    }

    std::wstring ClassifyRegion(const OrphanKernelPageRegion& region)
    {
        std::wstring classification = L"independent_or_system_pte";

        do
        {
            if (region.HasPe && region.InBigPool)
            {
                classification = L"big_pool_pe";
                break;
            }
            if (region.HasPe)
            {
                classification = L"unbacked_pe";
                break;
            }
            if (region.Writable &&
                region.Executable &&
                !LooksLikeSystemWxWindow(region))
            {
                classification = L"wx_orphan";
                break;
            }
            if (region.LargePage && region.Size >= 0x200000ull && !region.HasPe)
            {
                classification = L"large_page";
                break;
            }
            if (region.InBigPool)
            {
                classification = L"big_pool";
                break;
            }
            if (region.SessionSpace)
            {
                classification = L"session";
                break;
            }
            if (LooksLikePciMmioHole(region.PhysicalAddress) &&
                !region.HasPe &&
                !region.Writable)
            {
                classification = L"mmio";
                break;
            }
        } while (false);

        return classification;
    }

    std::wstring RiskForRegion(const OrphanKernelPageRegion& region)
    {
        std::wstring risk = L"medium";

        do
        {
            if (region.HasPe)
            {
                risk = L"high";
                break;
            }
            if (LooksLikeSystemWxWindow(region))
            {
                risk = L"medium";
                break;
            }
            if (region.Writable && region.Executable)
            {
                risk = L"high";
                break;
            }
            if (region.SessionSpace)
            {
                risk = L"low";
                break;
            }
            if (region.InBigPool || region.Classification == L"independent_or_system_pte")
            {
                risk = L"medium";
                break;
            }
        } while (false);

        return risk;
    }

    int RegionRank(const OrphanKernelPageRegion& region)
    {
        int rank = 3;
        if (region.Risk == L"high" && region.HasPe)
        {
            rank = 0;
        }
        else if (region.Risk == L"high")
        {
            rank = 1;
        }
        else if (region.Risk == L"medium")
        {
            rank = 2;
        }
        return rank;
    }
}

OrphanKernelPageScanner::OrphanKernelPageScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool OrphanKernelPageScanner::WalkKernelPageTables(
    const OrphanKernelPageOptions& options,
    OrphanKernelPageResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        ControlRegisters regs = {};
        if (!device_.ReadControlRegisters(0, &regs, error))
        {
            break;
        }

        result->Cr3 = regs.Cr3;
        result->La57 = (regs.Cr4 & (1ull << 12)) != 0;
        result->PagingLevels = result->La57 ? 5u : 4u;

        uint64_t pteBaseSymbol = 0;
        if (symbols_.ResolveSymbol(L"nt!MmPteBase", &pteBaseSymbol, nullptr))
        {
            uint64_t pteBase = 0;
            if (LeftoverReadU64(device_, pteBaseSymbol, &pteBase, nullptr) &&
                LeftoverIsKernelCanonical(pteBase))
            {
                result->PteBase = pteBase;
            }
        }
        if (result->PteBase == 0)
        {
            result->Warnings.push_back(
                L"nt!MmPteBase unresolved; using the classic LA48 self-map window");
        }

        struct Level
        {
            uint64_t TablePa = 0;
            uint64_t VaBase = 0;
            uint32_t Depth = 0;
            uint32_t Index = 0;
            bool AncestorsWritable = true;
            bool AncestorsExecutable = true;
        };

        std::vector<Level> stack;
        Level root = {};
        root.TablePa = regs.Cr3 & kPtePfnMask;
        root.VaBase = 0;
        root.Depth = 0;
        root.Index = result->La57 ? 256u : 256u;
        stack.push_back(root);

        OrphanKernelPageRegion open = {};
        bool haveOpen = false;
        const uint32_t maxDepth = result->PagingLevels;
        const uint32_t leafDepth = maxDepth - 1;
        const int shifts[5] = { 48, 39, 30, 21, 12 };
        const int* shiftBase = result->La57 ? &shifts[0] : &shifts[1];

        auto flushOpen = [&]()
        {
            if (!haveOpen)
            {
                return;
            }
            open.Size = open.End - open.Start;
            open.PageCount = static_cast<uint32_t>(open.Size / kLeftoverPageSize);
            result->Regions.push_back(open);
            ++result->RegionsCoalesced;
            haveOpen = false;
            open = OrphanKernelPageRegion{};
        };

        auto addLeaf = [&](
            uint64_t va,
            uint64_t size,
            uint64_t entry,
            bool largePage,
            bool ancestorsWritable,
            bool ancestorsExecutable)
        {
            if (!EntryPresent(entry) || !EntryExecutable(entry) || !ancestorsExecutable)
            {
                return;
            }
            ++result->ExecutableLeaves;
            if (LeftoverIsPageTableSelfMap(va, result->PteBase, result->La57))
            {
                ++result->SelfMapLeavesSkipped;
                return;
            }
            if (RegionOverlapsModule(modules_, va, size))
            {
                ++result->ModuleLeavesSkipped;
                return;
            }

            const bool writable = ancestorsWritable && EntryWritable(entry);
            const bool session = LeftoverIsSessionSpace(va);
            if (!options.IncludeSession && session)
            {
                return;
            }

            if (haveOpen &&
                open.End == va &&
                open.Writable == writable &&
                open.LargePage == largePage &&
                open.SessionSpace == session)
            {
                open.End = va + size;
                return;
            }

            flushOpen();
            open.Start = va;
            open.End = va + size;
            open.PhysicalAddress = EntryPhysical(entry);
            open.Writable = writable;
            open.Executable = true;
            open.LargePage = largePage;
            open.SessionSpace = session;
            haveOpen = true;
        };

        bool truncated = false;
        while (!stack.empty() && !truncated)
        {
            Level current = stack.back();
            stack.pop_back();

            if (result->TablePagesWalked >= options.MaxTablePages)
            {
                truncated = true;
                break;
            }

            std::vector<uint8_t> page;
            std::wstring readError;
            if (!LeftoverReadPhysicalPage(device_, current.TablePa, &page, &readError))
            {
                result->Warnings.push_back(
                    L"page-table read failed at PA " +
                    LeftoverFormatHex(current.TablePa, 16) + L": " + readError);
                continue;
            }
            ++result->TablePagesWalked;

            const uint64_t* entries = reinterpret_cast<const uint64_t*>(page.data());
            const uint32_t startIndex = current.Index;
            for (uint32_t index = startIndex; index < 512; ++index)
            {
                const uint64_t entry = entries[index];
                if (!EntryPresent(entry))
                {
                    continue;
                }
                if ((entry & kPteUser) != 0 && current.Depth == 0)
                {
                    continue;
                }

                const int shift = shiftBase[current.Depth];
                uint64_t va = current.VaBase | (static_cast<uint64_t>(index) << shift);
                va = LeftoverSignExtendVa(va, result->La57);
                if (!LeftoverIsKernelCanonical(va) && current.Depth == 0)
                {
                    continue;
                }

                const bool isLeaf = (current.Depth == leafDepth) ||
                    (EntryLarge(entry) && current.Depth >= (result->La57 ? 2u : 1u));
                if (isLeaf)
                {
                    uint64_t size = 1ull << shift;
                    if (current.Depth == leafDepth)
                    {
                        size = kLeftoverPageSize;
                    }
                    addLeaf(
                        va,
                        size,
                        entry,
                        current.Depth != leafDepth,
                        current.AncestorsWritable,
                        current.AncestorsExecutable);
                    continue;
                }

                Level child = {};
                child.TablePa = EntryPhysical(entry);
                child.VaBase = current.VaBase | (static_cast<uint64_t>(index) << shift);
                child.Depth = current.Depth + 1;
                child.Index = 0;
                child.AncestorsWritable = current.AncestorsWritable && EntryWritable(entry);
                child.AncestorsExecutable = current.AncestorsExecutable && EntryExecutable(entry);
                if (child.TablePa == 0)
                {
                    continue;
                }
                if (stack.size() >= 4096)
                {
                    truncated = true;
                    break;
                }
                stack.push_back(child);
            }
        }

        flushOpen();
        result->PageWalkComplete = !truncated;
        if (truncated)
        {
            result->Warnings.push_back(
                L"kernel page-table walk hit the table-page cap; coverage is partial");
        }
        ok = true;
    } while (false);

    return ok;
}

bool OrphanKernelPageScanner::WalkPfnDatabase(
    const OrphanKernelPageOptions& options,
    OrphanKernelPageResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        result->PfnWalkAttempted = true;

        uint64_t pfnSymbol = 0;
        std::wstring resolveError;
        if (!symbols_.ResolveSymbol(L"nt!MmPfnDatabase", &pfnSymbol, &resolveError))
        {
            result->CoverageNotes.push_back(
                L"nt!MmPfnDatabase was not resolved; /deep PFN coverage is absent");
            if (error != nullptr)
            {
                *error = resolveError;
            }
            break;
        }

        uint64_t database = 0;
        if (!LeftoverReadU64(device_, pfnSymbol, &database, &resolveError) ||
            !LeftoverIsKernelCanonical(database))
        {
            result->Warnings.push_back(
                L"nt!MmPfnDatabase did not dereference to a kernel pointer");
            break;
        }
        result->PfnDatabase = database;

        TypeLayoutInfo layout = {};
        if (!symbols_.GetTypeLayout(L"nt!_MMPFN", &layout, &resolveError) ||
            layout.Size < 16 ||
            layout.Size > 256)
        {
            result->Warnings.push_back(
                L"nt!_MMPFN layout is unavailable or implausible; /deep aborted");
            break;
        }

        TypeFieldInfo pteField = {};
        if (!symbols_.FindField(L"nt!_MMPFN", L"PteAddress", &pteField, &resolveError))
        {
            result->Warnings.push_back(L"nt!_MMPFN.PteAddress is not in the PDB; /deep aborted");
            break;
        }

        uint32_t pageLocationOffset = 0;
        uint32_t pageLocationBits = 0;
        bool havePageLocation = false;
        TypeFieldInfo locField = {};
        if (symbols_.FindField(L"nt!_MMPFN", L"u3.e1.PageLocation", &locField, nullptr) ||
            symbols_.FindField(L"nt!_MMPFN", L"u3.e2.PageLocation", &locField, nullptr))
        {
            pageLocationOffset = locField.Offset;
            pageLocationBits = locField.IsBitField ? locField.BitPosition : 0;
            havePageLocation = true;
        }

        if (result->PteBase == 0)
        {
            result->Warnings.push_back(
                L"MmPteBase is required to decode PFN PTE addresses; /deep aborted");
            break;
        }

        std::vector<PhysicalMemoryRange> ranges;
        uint64_t totalBytes = 0;
        if (!device_.GetPhysicalMemoryRanges(&ranges, &totalBytes, &resolveError))
        {
            result->Warnings.push_back(L"physical range query failed: " + resolveError);
            break;
        }

        uint32_t maxEntries = options.MaxPfnEntries;
        if (maxEntries == 0)
        {
            maxEntries = kDefaultMaxPfn;
        }

        std::set<uint64_t> seenPages;
        for (const OrphanKernelPageRegion& region : result->Regions)
        {
            seenPages.insert(region.Start);
        }

        bool truncated = false;
        for (const PhysicalMemoryRange& range : ranges)
        {
            if (truncated)
            {
                break;
            }

            uint64_t startPfn = range.BaseAddress >> kLeftoverPageShift;
            uint64_t pfnCount = range.ByteCount >> kLeftoverPageShift;
            if (pfnCount == 0)
            {
                continue;
            }

            uint64_t pfn = startPfn;
            const uint64_t endPfn = startPfn + pfnCount;
            while (pfn < endPfn && !truncated)
            {
                const uint32_t entriesPerChunk =
                    kPfnChunkBytes / static_cast<uint32_t>(layout.Size);
                uint32_t batch = entriesPerChunk;
                if (batch == 0)
                {
                    batch = 1;
                }
                if (pfn + batch > endPfn)
                {
                    batch = static_cast<uint32_t>(endPfn - pfn);
                }

                uint64_t chunkAddr = 0;
                uint64_t byteOffset = pfn * layout.Size;
                if (!LeftoverTryAdd(database, byteOffset, &chunkAddr))
                {
                    truncated = true;
                    break;
                }

                const uint32_t bytes = batch * static_cast<uint32_t>(layout.Size);
                std::vector<uint8_t> chunk;
                std::wstring readError;
                if (!device_.ReadMemory(chunkAddr, bytes, &chunk, &readError) ||
                    chunk.size() != bytes)
                {
                    result->Warnings.push_back(
                        L"PFN database read failed at " + LeftoverFormatHex(chunkAddr, 16));
                    pfn += batch;
                    continue;
                }

                for (uint32_t index = 0; index < batch; ++index)
                {
                    if (result->PfnEntriesExamined >= maxEntries)
                    {
                        truncated = true;
                        break;
                    }
                    ++result->PfnEntriesExamined;

                    const uint8_t* entry = chunk.data() + (index * layout.Size);
                    if (havePageLocation && pageLocationOffset + sizeof(uint8_t) <= layout.Size)
                    {
                        const uint8_t raw = entry[pageLocationOffset];
                        const uint32_t location = (raw >> pageLocationBits) & 0x7u;
                        if (location != kActiveAndValid)
                        {
                            continue;
                        }
                    }

                    if (pteField.Offset + sizeof(uint64_t) > layout.Size)
                    {
                        continue;
                    }
                    uint64_t pteAddress = 0;
                    memcpy(&pteAddress, entry + pteField.Offset, sizeof(uint64_t));
                    if (!LeftoverIsKernelCanonical(pteAddress) ||
                        !LeftoverIsPageTableSelfMap(pteAddress, result->PteBase, result->La57))
                    {
                        continue;
                    }

                    const uint64_t va = LeftoverDecodeVaFromPteAddress(
                        pteAddress,
                        result->PteBase,
                        result->La57);
                    if (!LeftoverIsKernelCanonical(va))
                    {
                        continue;
                    }
                    if (LeftoverIsPageTableSelfMap(va, result->PteBase, result->La57) ||
                        RegionOverlapsModule(modules_, va, kLeftoverPageSize))
                    {
                        continue;
                    }
                    if (!options.IncludeSession && LeftoverIsSessionSpace(va))
                    {
                        continue;
                    }
                    if (seenPages.find(va) != seenPages.end())
                    {
                        continue;
                    }

                    uint64_t pte = 0;
                    if (!LeftoverReadU64(device_, pteAddress, &pte, nullptr) ||
                        !EntryPresent(pte) ||
                        !EntryExecutable(pte))
                    {
                        continue;
                    }

                    OrphanKernelPageRegion region = {};
                    region.Start = va;
                    region.End = va + kLeftoverPageSize;
                    region.Size = kLeftoverPageSize;
                    region.PageCount = 1;
                    region.PhysicalAddress = (pfn + index) << kLeftoverPageShift;
                    region.Writable = EntryWritable(pte);
                    region.Executable = true;
                    region.SessionSpace = LeftoverIsSessionSpace(va);
                    region.FromPfn = true;
                    LeftoverAppendNote(&region.Notes, L"discovered via PFN walk");
                    result->Regions.push_back(region);
                    seenPages.insert(va);
                    ++result->PfnHits;
                }

                pfn += batch;
            }
        }

        result->PfnWalkComplete = !truncated;
        if (truncated)
        {
            result->Warnings.push_back(
                L"PFN walk hit the entry cap; /deep coverage is partial");
        }
        ok = true;
    } while (false);

    return ok;
}

void OrphanKernelPageScanner::FinalizeRegions(
    const OrphanKernelPageOptions& options,
    OrphanKernelPageResult* result)
{
    if (result == nullptr)
    {
        return;
    }

    for (OrphanKernelPageRegion& region : result->Regions)
    {
        const LeftoverBigPoolEntry* pool = LeftoverFindBigPool(pool_, region.Start);
        if (pool != nullptr)
        {
            region.InBigPool = true;
            region.PoolAddress = pool->VirtualAddress;
            region.PoolSize = pool->SizeInBytes;
            region.PoolTag = pool->TagRaw;
            region.PoolNonPaged = pool->NonPaged;
        }

        std::vector<uint8_t> head;
        std::wstring ignored;
        const uint64_t probeAt = region.InBigPool ? region.PoolAddress : region.Start;
        if (device_.ReadMemory(probeAt, 0x1000, &head, &ignored) && head.size() >= 0x40)
        {
            PeHeaderProbe probe = {};
            // Kernel leftover pages that execute on x64 are PE32+. PE32/I386
            // headers in this VA range are firmware/option-ROM mappings, not
            // a mapped kernel driver.
            if (ProbeForPageStartPeHeader(head.data(), head.size(), &probe) &&
                PeProbeLooksLikeImage(probe, 0) &&
                probe.Is64Bit &&
                probe.Machine == IMAGE_FILE_MACHINE_AMD64)
            {
                region.HasPe = true;
                region.Pe = probe;
            }
        }

        region.Classification = ClassifyRegion(region);
        region.Risk = RiskForRegion(region);
        if (region.Classification == L"mmio")
        {
            LeftoverAppendNote(&region.Notes, L"PCI MMIO hole");
        }
        if (region.Writable && region.Executable)
        {
            LeftoverAppendNote(&region.Notes, L"effective W+X");
            if (!LooksLikeSystemWxWindow(region))
            {
                result->AnyHighRisk = true;
            }
        }
        if (region.HasPe)
        {
            LeftoverAppendNote(&region.Notes, L"PE header");
            result->AnyHighRisk = true;
        }
    }

    std::vector<OrphanKernelPageRegion> filtered;
    filtered.reserve(result->Regions.size());
    for (const OrphanKernelPageRegion& region : result->Regions)
    {
        if (options.WxOnly && !(region.Writable && region.Executable))
        {
            continue;
        }
        if (options.PeOnly && !region.HasPe)
        {
            continue;
        }
        filtered.push_back(region);
    }

    std::sort(
        filtered.begin(),
        filtered.end(),
        [](const OrphanKernelPageRegion& left, const OrphanKernelPageRegion& right)
        {
            const int leftRank = RegionRank(left);
            const int rightRank = RegionRank(right);
            if (leftRank != rightRank)
            {
                return leftRank < rightRank;
            }
            return left.Size > right.Size;
        });

    uint32_t limit = options.Limit;
    if (limit == 0)
    {
        limit = kDefaultLimit;
    }
    if (limit > kMaxLimit)
    {
        limit = kMaxLimit;
    }
    if (filtered.size() > limit)
    {
        result->Warnings.push_back(
            L"orphan-page output truncated to " + std::to_wstring(limit) +
            L" of " + std::to_wstring(filtered.size()) + L" region(s)");
        filtered.resize(limit);
    }
    result->Regions = std::move(filtered);
}

bool OrphanKernelPageScanner::Scan(
    const OrphanKernelPageOptions& options,
    OrphanKernelPageResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"orphan page scan output is null";
            }
            break;
        }

        *result = OrphanKernelPageResult{};
        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = loadError;
                }
                break;
            }
        }
        LeftoverBuildModuleRanges(symbols_, &modules_);

        std::wstring poolError;
        if (LeftoverQueryBigPool(&pool_, &poolError))
        {
            result->BigPoolQueried = true;
        }
        else if (!poolError.empty())
        {
            result->Warnings.push_back(L"big pool query failed: " + poolError);
        }

        OrphanKernelPageOptions local = options;
        if (local.MaxTablePages == 0)
        {
            local.MaxTablePages = 32768;
        }
        if (local.Limit == 0)
        {
            local.Limit = kDefaultLimit;
        }

        if (!WalkKernelPageTables(local, result, error))
        {
            break;
        }

        if (local.DeepPfn)
        {
            std::wstring pfnError;
            if (!WalkPfnDatabase(local, result, &pfnError) && !result->PfnWalkComplete)
            {
                if (!pfnError.empty())
                {
                    result->Warnings.push_back(L"pfn: " + pfnError);
                }
            }
        }

        FinalizeRegions(local, result);
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildOrphanKernelPageJson(const OrphanKernelPageResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.kpage.v1\"";
    out += L",\"la57\":";
    out += result.La57 ? L"true" : L"false";
    out += L",\"pagingLevels\":" + std::to_wstring(result.PagingLevels);
    out += L",\"cr3\":" + mcpjson::Quote(LeftoverFormatHex(result.Cr3, 16));
    out += L",\"pteBase\":" + mcpjson::Quote(LeftoverFormatHex(result.PteBase, 16));
    out += L",\"pageWalkComplete\":";
    out += result.PageWalkComplete ? L"true" : L"false";
    out += L",\"pfnWalkAttempted\":";
    out += result.PfnWalkAttempted ? L"true" : L"false";
    out += L",\"pfnWalkComplete\":";
    out += result.PfnWalkComplete ? L"true" : L"false";
    out += L",\"tablePagesWalked\":" + std::to_wstring(result.TablePagesWalked);
    out += L",\"executableLeaves\":" + std::to_wstring(result.ExecutableLeaves);
    out += L",\"moduleLeavesSkipped\":" + std::to_wstring(result.ModuleLeavesSkipped);
    out += L",\"selfMapLeavesSkipped\":" + std::to_wstring(result.SelfMapLeavesSkipped);
    out += L",\"pfnEntriesExamined\":" + std::to_wstring(result.PfnEntriesExamined);
    out += L",\"pfnHits\":" + std::to_wstring(result.PfnHits);
    out += L",\"anyHighRisk\":";
    out += result.AnyHighRisk ? L"true" : L"false";
    out += L",\"regions\":[";

    for (size_t index = 0; index < result.Regions.size(); ++index)
    {
        const OrphanKernelPageRegion& region = result.Regions[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"start\":" + mcpjson::Quote(LeftoverFormatHex(region.Start, 16));
        out += L",\"end\":" + mcpjson::Quote(LeftoverFormatHex(region.End, 16));
        out += L",\"size\":" + std::to_wstring(region.Size);
        out += L",\"pages\":" + std::to_wstring(region.PageCount);
        out += L",\"physical\":" + mcpjson::Quote(LeftoverFormatHex(region.PhysicalAddress, 16));
        out += L",\"writable\":";
        out += region.Writable ? L"true" : L"false";
        out += L",\"executable\":";
        out += region.Executable ? L"true" : L"false";
        out += L",\"largePage\":";
        out += region.LargePage ? L"true" : L"false";
        out += L",\"session\":";
        out += region.SessionSpace ? L"true" : L"false";
        out += L",\"inBigPool\":";
        out += region.InBigPool ? L"true" : L"false";
        out += L",\"pe\":";
        out += region.HasPe ? L"true" : L"false";
        out += L",\"fromPfn\":";
        out += region.FromPfn ? L"true" : L"false";
        out += L",\"classification\":" + mcpjson::Quote(region.Classification);
        out += L",\"risk\":" + mcpjson::Quote(region.Risk);
        out += L",\"notes\":" + mcpjson::Quote(region.Notes);
        if (region.InBigPool)
        {
            out += L",\"poolTag\":" + mcpjson::Quote(LeftoverFormatTag(region.PoolTag));
        }
        out += L"}";
    }

    out += L"],\"warnings\":[";
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

bool OrphanKernelPageSelfTest()
{
    bool ok = true;

    do
    {
        const uint64_t pteBase = 0xFFFFF68000000000ull;
        const uint64_t va = 0xFFFFC08012345000ull;
        const uint64_t va48 = va & 0x0000FFFFFFFFFFFFull;
        const uint64_t pte = pteBase + ((va48 >> 12) * 8ull);
        if (LeftoverDecodeVaFromPteAddress(pte, pteBase, false) != va)
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion region = {};
        region.Writable = true;
        region.Executable = true;
        region.HasPe = true;
        region.Classification = ClassifyRegion(region);
        if (region.Classification != L"unbacked_pe" || RiskForRegion(region) != L"high")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion coalescedWx = {};
        coalescedWx.Writable = true;
        coalescedWx.Executable = true;
        coalescedWx.LargePage = false;
        coalescedWx.Size = 0x200000;
        coalescedWx.HasPe = false;
        if (ClassifyRegion(coalescedWx) != L"wx_orphan" ||
            RiskForRegion(coalescedWx) != L"high")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion largePage = {};
        largePage.Writable = true;
        largePage.Executable = true;
        largePage.LargePage = true;
        largePage.Size = 0x200000;
        largePage.HasPe = false;
        if (ClassifyRegion(largePage) != L"large_page" ||
            RiskForRegion(largePage) != L"medium")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion largePool = largePage;
        largePool.InBigPool = true;
        if (ClassifyRegion(largePool) != L"large_page" ||
            RiskForRegion(largePool) != L"medium")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion mmioWx = {};
        mmioWx.Writable = true;
        mmioWx.Executable = true;
        mmioWx.Size = 0x86000;
        mmioWx.PhysicalAddress = 0x00000000FFF7A000ull;
        mmioWx.HasPe = false;
        if (ClassifyRegion(mmioWx) != L"wx_orphan" || RiskForRegion(mmioWx) != L"high")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion mmioRom = {};
        mmioRom.Writable = false;
        mmioRom.Executable = true;
        mmioRom.Size = 0x86000;
        mmioRom.PhysicalAddress = 0x00000000FFF7A000ull;
        mmioRom.HasPe = false;
        if (ClassifyRegion(mmioRom) != L"mmio" || RiskForRegion(mmioRom) != L"medium")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion poolWx = {};
        poolWx.Writable = true;
        poolWx.Executable = true;
        poolWx.InBigPool = true;
        poolWx.HasPe = false;
        poolWx.Size = 0x1000;
        if (ClassifyRegion(poolWx) != L"wx_orphan" || RiskForRegion(poolWx) != L"high")
        {
            ok = false;
            break;
        }

        PeHeaderProbe tooSmall = {};
        tooSmall.IsPe = true;
        tooSmall.Machine = 0x8664;
        tooSmall.NumberOfSections = 3;
        tooSmall.SizeOfImage = 0x760;
        PeHeaderProbe overflow = tooSmall;
        overflow.SizeOfImage = 0x1d000;
        PeHeaderProbe aligned = tooSmall;
        aligned.SizeOfImage = 0x3000;
        PeHeaderProbe i386 = aligned;
        i386.Machine = 0x14c;
        i386.Is64Bit = false;
        if (PeProbeLooksLikeImage(tooSmall, 0x3000) ||
            !PeProbeLooksLikeImage(overflow, 0x1000) ||
            !PeProbeLooksLikeImage(aligned, 0x3000) ||
            !PeProbeLooksLikeImage(aligned, 0) ||
            !PeProbeLooksLikeImage(i386, 0))
        {
            ok = false;
            break;
        }

        uint8_t emptyPage[0x80] = {};
        PeHeaderProbe probe = {};
        if (ProbeForPageStartPeHeader(emptyPage, sizeof(emptyPage), &probe) && probe.IsPe)
        {
            ok = false;
            break;
        }

        uint8_t interiorOnly[0x200] = {};
        const uint32_t peSig = 0x00004550;
        memcpy(interiorOnly + 0x80, &peSig, sizeof(peSig));
        uint16_t machine = 0x8664;
        memcpy(interiorOnly + 0x84, &machine, sizeof(machine));
        uint16_t sections = 3;
        memcpy(interiorOnly + 0x86, &sections, sizeof(sections));
        uint16_t optional = 0x00F0;
        memcpy(interiorOnly + 0x94, &optional, sizeof(optional));
        uint16_t magic = 0x020B;
        memcpy(interiorOnly + 0x98, &magic, sizeof(magic));
        PeHeaderProbe interior = {};
        if (ProbeForPageStartPeHeader(interiorOnly, sizeof(interiorOnly), &interior) &&
            interior.IsPe)
        {
            ok = false;
            break;
        }
    } while (false);

    return ok;
}
