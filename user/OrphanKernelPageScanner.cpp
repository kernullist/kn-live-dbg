#include "OrphanKernelPageScanner.h"

#include "McpJson.h"
#include "../shared/KnLiveDbgPaging.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>

namespace
{
    constexpr uint64_t kPtePresent = 1ull;
    constexpr uint64_t kPteWritable = 1ull << 1;
    constexpr uint64_t kPteLarge = 1ull << 7;
    constexpr uint64_t kPteNx = 1ull << 63;
    constexpr uint64_t kPtePfnMask = 0x000FFFFFFFFFF000ull;
    constexpr uint32_t kActiveAndValid = 6;
    constexpr uint32_t kDefaultLimit = 64;
    constexpr uint32_t kMaxLimit = 512;
    constexpr uint32_t kDefaultMaxPfn = 4u * 1024u * 1024u;
    constexpr uint32_t kPfnChunkBytes = 0x40000;
    constexpr uint32_t kMaxReadWarnings = 16;
    constexpr size_t kMaxRetainedRegions = 65536;
    constexpr uint64_t kMaxBodyWindowBytes = 0x10000;

    struct AddressSpan
    {
        uint64_t Start = 0;
        uint64_t End = 0;
    };

    uint64_t LeafPhysicalBase(uint64_t entry, uint64_t pageBytes)
    {
        return (entry & kPtePfnMask) & ~(pageBytes - 1);
    }

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

    uint64_t LeafPhysical(uint64_t entry, uint64_t size)
    {
        // Large-page PAT is bit 12; physical bases are aligned to leaf size.
        return EntryPhysical(entry) & ~(size - 1);
    }

    std::vector<std::pair<uint64_t, uint64_t>> UnownedLeafRanges(
        const std::vector<LeftoverModuleRange>& modules, uint64_t start, uint64_t size, uint64_t resume)
    {
        std::vector<std::pair<uint64_t, uint64_t>> uncovered;
        uint64_t end = 0;
        if (!LeftoverTryAdd(start, size, &end) || size == 0 || resume >= end)
        {
            return uncovered;
        }
        uint64_t cursor = (std::max)(start, resume);
        std::vector<std::pair<uint64_t, uint64_t>> covered;
        for (const auto& module : modules)
        {
            if (module.Base < module.End && module.Base < end && module.End > cursor)
            {
                covered.emplace_back((std::max)(cursor, module.Base), (std::min)(end, module.End));
            }
        }
        std::sort(covered.begin(), covered.end());
        for (const auto& range : covered)
        {
            if (cursor < range.first)
            {
                uncovered.emplace_back(cursor, range.first);
            }
            cursor = (std::max)(cursor, range.second);
        }
        if (cursor < end)
        {
            uncovered.emplace_back(cursor, end);
        }
        return uncovered;
    }

    bool BuildUnownedLeafSpans(
        const std::vector<LeftoverModuleRange>& modules,
        uint64_t start,
        uint64_t size,
        std::vector<AddressSpan>* spans)
    {
        spans->clear();
        uint64_t end = 0;
        if (size == 0 || !LeftoverTryAdd(start, size, &end))
        {
            return false;
        }

        uint64_t cursor = start;
        for (const LeftoverModuleRange& module : modules)
        {
            if (module.End <= module.Base)
            {
                continue;
            }
            const uint64_t moduleStart = module.Base & ~0xFFFull;
            uint64_t moduleEnd = module.End;
            if ((moduleEnd & 0xFFFull) != 0 &&
                !LeftoverTryAdd(moduleEnd, 0x1000ull - (moduleEnd & 0xFFFull), &moduleEnd))
            {
                moduleEnd = (std::numeric_limits<uint64_t>::max)();
            }
            if (moduleEnd <= cursor || moduleStart >= end)
            {
                continue;
            }
            if (cursor < moduleStart)
            {
                spans->push_back({ cursor, moduleStart });
            }
            cursor = (std::max)(cursor, moduleEnd);
            if (cursor >= end)
            {
                break;
            }
        }
        if (cursor < end)
        {
            spans->push_back({ cursor, end });
        }
        return true;
    }

    bool CanCoalesceRegions(
        const OrphanKernelPageRegion& left,
        const OrphanKernelPageRegion& right)
    {
        return left.End == right.Start &&
            left.Writable == right.Writable &&
            left.LargePage == right.LargePage &&
            left.MappingPageSize == right.MappingPageSize &&
            left.SessionSpace == right.SessionSpace &&
            left.InBigPool == right.InBigPool &&
            left.PoolAddress == right.PoolAddress;
    }

    bool SelectRegionWindows(
        const std::vector<OrphanKernelPageRegion>& regions,
        uint64_t windowBytes,
        uint64_t offset,
        uint32_t limit,
        OrphanKernelPageResult* result,
        const OrphanKernelPageBodyCursor* bodyCursor = nullptr)
    {
        if (windowBytes == 0 || result == nullptr)
        {
            return false;
        }
        uint64_t total = 0;
        uint64_t largest = 0;
        std::vector<uint64_t> counts;
        counts.reserve(regions.size());
        for (const OrphanKernelPageRegion& region : regions)
        {
            const uint64_t count = region.Size / windowBytes +
                ((region.Size % windowBytes) != 0 ? 1ull : 0ull);
            if (!LeftoverTryAdd(total, count, &total))
            {
                return false;
            }
            largest = (std::max)(largest, count);
            counts.push_back(count);
        }
        result->RegionsDiscovered = total;
        if (total == 0)
        {
            result->NextRegionOffset = 0;
            result->NextBodyRegionAfter = 0;
            result->NextBodyWindowRound = 0;
            result->RegionsTruncated = false;
            return true;
        }
        if (bodyCursor != nullptr)
        {
            // Address anchors retain progress when earlier allocations appear
            // or disappear. Numeric indices can repeatedly skip a stable page.
            uint64_t round = bodyCursor->WindowRound < largest ? bodyCursor->WindowRound : 0;
            uint64_t after = bodyCursor->WindowRound < largest ? bodyCursor->RegionAfter : 0;
            size_t index = static_cast<size_t>(std::upper_bound(regions.begin(), regions.end(), after,
                [](uint64_t address, const OrphanKernelPageRegion& region)
                {
                    return address < region.Start;
                }) - regions.begin());
            const uint64_t wanted = (std::min<uint64_t>)(total, limit);
            while (result->Regions.size() < wanted)
            {
                if (index == regions.size())
                {
                    round = round + 1 < largest ? round + 1 : 0;
                    after = 0;
                    index = 0;
                }
                if (counts[index] > round)
                {
                    const OrphanKernelPageRegion& region = regions[index];
                    OrphanKernelPageRegion window = region;
                    const uint64_t delta = round * windowBytes;
                    window.Start += delta;
                    window.Size = (std::min)(windowBytes, region.Size - delta);
                    window.End = window.Start + window.Size;
                    window.PageCount = static_cast<uint32_t>(window.Size / kLeftoverPageSize);
                    if (delta != 0)
                    {
                        window.PhysicalAddress = 0;
                    }
                    result->Regions.push_back(std::move(window));
                    after = region.Start;
                }
                ++index;
            }
            if (index == regions.size())
            {
                round = round + 1 < largest ? round + 1 : 0;
                after = 0;
            }
            result->NextBodyRegionAfter = after;
            result->NextBodyWindowRound = round;
            uint64_t ordinal = 0;
            for (size_t regionIndex = 0; regionIndex < regions.size(); ++regionIndex)
            {
                ordinal += (std::min)(round, counts[regionIndex]);
                if (counts[regionIndex] > round && regions[regionIndex].Start <= after)
                {
                    ++ordinal;
                }
            }
            result->NextRegionOffset = ordinal < total ? ordinal : 0;
            result->RegionsTruncated = result->Regions.size() < total;
            return true;
        }
        if (offset >= total)
        {
            offset = 0;
        }
        // Interleave allocations: one huge mapping must not monopolize all
        // passes before a small allocation at a later address gets sampled.
        auto consumedBeforeRound = [&](uint64_t round)
        {
            uint64_t consumed = 0;
            for (uint64_t count : counts)
            {
                consumed += (std::min)(round, count);
            }
            return consumed;
        };
        uint64_t low = 0;
        uint64_t high = largest;
        while (low < high)
        {
            const uint64_t middle = low + (high - low + 1) / 2;
            if (consumedBeforeRound(middle) <= offset)
            {
                low = middle;
            }
            else
            {
                high = middle - 1;
            }
        }
        uint64_t skip = offset - consumedBeforeRound(low);
        for (uint64_t round = low; round < largest && result->Regions.size() < limit; ++round)
        {
            for (size_t index = 0; index < regions.size() && result->Regions.size() < limit; ++index)
            {
                if (counts[index] <= round)
                {
                    continue;
                }
                if (skip != 0)
                {
                    --skip;
                    continue;
                }
                const OrphanKernelPageRegion& region = regions[index];
                OrphanKernelPageRegion window = region;
                const uint64_t delta = round * windowBytes;
                window.Start += delta;
                window.Size = (std::min)(windowBytes, region.Size - delta);
                window.End = window.Start + window.Size;
                window.PageCount = static_cast<uint32_t>(window.Size / kLeftoverPageSize);
                if (delta != 0)
                {
                    // Coalesced 4K pages need not be physically contiguous.
                    window.PhysicalAddress = 0;
                }
                result->Regions.push_back(std::move(window));
            }
        }
        const uint64_t next = offset + result->Regions.size();
        result->NextRegionOffset = next < total ? next : 0;
        result->RegionsTruncated = result->Regions.size() < total;
        return true;
    }

    bool ValidatePfnTranslation(
        const PhysicalTranslationInfo& translation,
        uint64_t expectedPhysical,
        bool* writable)
    {
        *writable = false;
        const bool la57 = (translation.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
        if ((translation.PhysicalAddress & ~0xFFFull) != expectedPhysical ||
            translation.PagingLevels != (la57 ? 5u : 4u))
        {
            return false;
        }
        const uint64_t entries[] =
        {
            translation.Pml5e, translation.Pml4e, translation.Pdpte,
            translation.Pde, translation.Pte
        };
        bool writeOk = true;
        const size_t first = translation.PagingLevels == 5 ? 0 : 1;
        for (size_t level = first; level < 5; ++level)
        {
            if (!KnDbgPresentPagingEntryValid(entries[level], static_cast<unsigned int>(5 - level)) ||
                !EntryExecutable(entries[level]))
            {
                return false;
            }
            writeOk = writeOk && EntryWritable(entries[level]);
            if (level == 4 || ((level == 2 || level == 3) && EntryLarge(entries[level])))
            {
                *writable = writeOk;
                return true;
            }
        }
        return false;
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
            if (region.Writable && region.Executable)
            {
                classification = L"wx_orphan";
                break;
            }
            if (region.LargePage && region.MappingPageSize >= 0x200000ull && !region.HasPe)
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

    struct RegionPeObservation
    {
        uint64_t Address = 0;
        uint64_t ReadFailures = 0;
        PeHeaderProbe Probe = {};
    };

    template<typename Read>
    RegionPeObservation ProbeRegionPageHeaders(Read read, uint64_t base, uint64_t size)
    {
        RegionPeObservation observation;
        uint64_t end = 0;
        if (size == 0 || size > kMaxBodyWindowBytes ||
            !LeftoverTryAdd(base, size, &end))
        {
            observation.ReadFailures = 1;
            return observation;
        }
        for (uint64_t offset = 0; offset < size; offset += kLeftoverPageSize)
        {
            const uint32_t length = static_cast<uint32_t>(
                (std::min<uint64_t>)(kLeftoverPageSize, size - offset));
            std::vector<uint8_t> bytes;
            const bool readable = read(base + offset, length, &bytes);
            if (!readable || bytes.size() != length)
            {
                ++observation.ReadFailures;
            }
            PeHeaderProbe probe = {};
            if (observation.Address == 0 && readable && bytes.size() >= 0x40 &&
                ProbeForPageStartPeHeader(bytes.data(), bytes.size(), &probe) &&
                PeProbeLooksLikeImage(probe, 0) && probe.Is64Bit &&
                probe.Machine == IMAGE_FILE_MACHINE_AMD64)
            {
                observation.Address = base + offset;
                observation.Probe = probe;
            }
        }
        return observation;
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

template<typename Reader, typename Visitor>
static bool WalkKernelTableBatch(
    Reader readPage,
    Visitor visitLeaf,
    const OrphanKernelPageOptions& options,
    OrphanKernelPageResult* result,
    bool& invalidRange,
    bool& truncated,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr || (result->PagingLevels != 4 && result->PagingLevels != 5))
        {
            break;
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
        root.TablePa = result->Cr3 & kPtePfnMask;
        root.VaBase = 0;
        root.Depth = 0;
        root.Index = 256u;
        if (root.TablePa == 0)
        {
            if (error != nullptr)
            {
                *error = L"kernel page-table root is null";
            }
            break;
        }
        stack.push_back(root);

        const uint32_t maxDepth = result->PagingLevels;
        const uint32_t leafDepth = maxDepth - 1;
        const int shifts[5] = { 48, 39, 30, 21, 12 };
        const int* shiftBase = result->La57 ? &shifts[0] : &shifts[1];

        while (!stack.empty() && !truncated)
        {
            Level current = stack.back();
            stack.pop_back();

            if (current.Index >= 512)
            {
                continue;
            }

            if (result->TablePagesWalked + result->TableReadFailures >= options.MaxTablePages)
            {
                truncated = true;
                result->NextPageAddress = (std::max)(options.PageStartAddress,
                    LeftoverSignExtendVa(current.VaBase | (static_cast<uint64_t>(current.Index) << shiftBase[current.Depth]), result->La57));
                break;
            }

            std::vector<uint8_t> page;
            std::wstring readError;
            if (!readPage(current.TablePa, &page, &readError) || page.size() != kLeftoverPageSize)
            {
                ++result->TableReadFailures;
                if (result->TableReadFailures <= kMaxReadWarnings)
                {
                    result->Warnings.push_back(
                        L"page-table read failed at PA " +
                        LeftoverFormatHex(current.TablePa, 16) + L": " + readError);
                }
                continue;
            }
            ++result->TablePagesWalked;

            const uint64_t* entries = reinterpret_cast<const uint64_t*>(page.data());
            const uint32_t startIndex = current.Index;
            for (uint32_t index = startIndex; index < 512 && !truncated; ++index)
            {
                const uint64_t entry = entries[index];
                if (!EntryPresent(entry) || !EntryExecutable(entry) ||
                    !current.AncestorsExecutable)
                {
                    continue;
                }
                if (!KnDbgPresentPagingEntryValid(entry, maxDepth - current.Depth))
                {
                    invalidRange = true;
                    continue;
                }
                const int shift = shiftBase[current.Depth];
                uint64_t va = current.VaBase | (static_cast<uint64_t>(index) << shift);
                va = LeftoverSignExtendVa(va, result->La57);
                const uint64_t spanBytes = 1ull << shift;
                if (va <= (std::numeric_limits<uint64_t>::max)() - spanBytes &&
                    va + spanBytes <= options.PageStartAddress)
                {
                    continue;
                }
                if (!LeftoverIsKernelCanonical(va, result->La57) && current.Depth == 0)
                {
                    continue;
                }
                if (LeftoverIsPageTableSelfMap(va, result->PteBase, result->La57))
                {
                    ++result->SelfMapLeavesSkipped;
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
                    visitLeaf(
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
                    invalidRange = true;
                    continue;
                }
                if (current.Depth == 0 && child.TablePa == root.TablePa)
                {
                    ++result->SelfMapLeavesSkipped;
                    continue;
                }
                if (stack.size() >= 4096)
                {
                    truncated = true;
                    result->NextPageAddress = va;
                    break;
                }
                // Resume by virtual address on the next pass. Never retain a
                // table PA across scans; rebuild each ancestor from this root.
                current.Index = index + 1;
                stack.push_back(current);
                stack.push_back(child);
                break;
            }
        }

        ok = true;
    } while (false);
    return ok;
}

static bool PfnRangeBounds(
    const PhysicalMemoryRange& range, uint64_t resumeAddress,
    uint64_t* firstPfn, uint64_t* lastPfn)
{
    if (range.ByteCount == 0 || (range.BaseAddress & 0xFFF) != 0 || (range.ByteCount & 0xFFF) != 0 ||
        range.BaseAddress > (std::numeric_limits<uint64_t>::max)() - range.ByteCount ||
        (resumeAddress & 0xFFF) != 0)
    {
        return false;
    }
    *firstPfn = (std::max)(range.BaseAddress, resumeAddress) >> kLeftoverPageShift;
    *lastPfn = (range.BaseAddress + range.ByteCount) >> kLeftoverPageShift;
    return true;
}

static uint32_t PfnBatchSize(uint64_t recordSize, uint64_t remaining, uint64_t budget)
{
    if (recordSize == 0 || recordSize > kPfnChunkBytes)
    {
        return 0;
    }
    return static_cast<uint32_t>((std::min)((std::min)(remaining, budget), kPfnChunkBytes / recordSize));
}

static bool SameBodyBatch(const OrphanKernelPageBodyCursor& left, const OrphanKernelPageBodyCursor& right)
{
    return left.PageAddress == right.PageAddress && left.PfnAddress == right.PfnAddress &&
        left.DeepPfn == right.DeepPfn;
}

static uint64_t FindBodyBatchOffset(
    const OrphanKernelPageCursor& cursor, const OrphanKernelPageBodyCursor& batch)
{
    for (const OrphanKernelPageBodyCursor& saved : cursor.BodyWindows)
    {
        if (SameBodyBatch(saved, batch))
        {
            return saved.RegionOffset;
        }
    }
    return 0;
}

static OrphanKernelPageBodyCursor FindBodyBatchCursor(
    const OrphanKernelPageCursor& cursor, OrphanKernelPageBodyCursor batch)
{
    for (const OrphanKernelPageBodyCursor& saved : cursor.BodyWindows)
    {
        if (SameBodyBatch(saved, batch))
        {
            return saved;
        }
    }
    return batch;
}

static bool SaveBodyBatchOffset(OrphanKernelPageCursor* cursor, OrphanKernelPageBodyCursor batch)
{
    auto& saved = cursor->BodyWindows;
    saved.erase(std::remove_if(saved.begin(), saved.end(), [&](const OrphanKernelPageBodyCursor& previous)
    {
        return SameBodyBatch(previous, batch);
    }), saved.end());
    bool evicted = false;
    if (batch.RegionOffset != 0 || batch.RegionAfter != 0 || batch.WindowRound != 0)
    {
        constexpr size_t kMaxBodyBatchesPerRoot = 64;
        if (saved.size() >= kMaxBodyBatchesPerRoot)
        {
            saved.erase(saved.begin());
            evicted = true;
        }
        saved.push_back(batch);
    }
    return evicted;
}

static bool OrphanRootIdentityMatches(
    const OrphanKernelPageRoot& expected,
    const OrphanKernelPageRoot& observed)
{
    return expected.Cr3 != 0 && expected.Cr3 == observed.Cr3 &&
        expected.ProcessId != 0 && expected.ProcessId == observed.ProcessId &&
        expected.CreateTime != 0 && expected.CreateTime == observed.CreateTime;
}

static bool ArmOrphanDeepRoots(
    OrphanKernelPageContinuation* continuation,
    const std::vector<OrphanKernelPageRoot>& roots)
{
    bool reset = false;
    constexpr size_t kRootLimit = 4096;
    for (const OrphanKernelPageRoot& root : roots)
    {
        auto cached = std::find_if(continuation->Roots.begin(), continuation->Roots.end(),
            [&](const OrphanKernelPageCursor& cursor)
            {
                return cursor.Root.Cr3 == root.Cr3;
            });
        if (cached == continuation->Roots.end())
        {
            if (continuation->Roots.size() >= kRootLimit)
            {
                continuation->Roots.erase(continuation->Roots.begin());
                reset = true;
            }
            continuation->Roots.push_back({});
            cached = continuation->Roots.end() - 1;
            cached->Root = root;
        }
        else if (cached->Root.ProcessId != root.ProcessId || cached->Root.CreateTime != root.CreateTime)
        {
            *cached = OrphanKernelPageCursor{};
            cached->Root = root;
            reset = true;
        }
        cached->PfnPending = true;
    }
    return reset;
}

bool ReadOrphanRootIdentity(
    DeviceClient& device, SymbolEngine& symbols,
    const OrphanKernelPageRoot& expected, uint64_t* eprocess,
    std::wstring* error)
{
    if (eprocess == nullptr)
    {
        return false;
    }
    TypeFieldInfo dtb = {};
    TypeFieldInfo created = {};
    if (!symbols.FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtb, nullptr) ||
        !symbols.FindField(L"nt!_EPROCESS", L"CreateTime", &created, nullptr) ||
        dtb.Length != sizeof(uint64_t) || created.Length != sizeof(uint64_t) ||
        dtb.Offset == 0 || dtb.Offset > 0x10000 || created.Offset > 0x10000)
    {
        if (error != nullptr)
        {
            *error = L"process root identity fields are unavailable";
        }
        return false;
    }
    ProcessAddressContext context = {};
    ProcessAddressContext after = {};
    uint64_t creation = 0;
    uint64_t creationAddress = 0;
    if (!device.ResolveProcess(expected.ProcessId, dtb.Offset, 0, &context, error) ||
        context.Eprocess == 0 || !LeftoverTryAdd(context.Eprocess, created.Offset, &creationAddress) ||
        !LeftoverReadU64(device, creationAddress, &creation, error) ||
        !device.ResolveProcess(expected.ProcessId, dtb.Offset, 0, &after, error))
    {
        return false;
    }
    const OrphanKernelPageRoot observed =
    {
        context.DirectoryTableBase & kPtePfnMask, context.ProcessId, creation
    };
    if (!OrphanRootIdentityMatches(expected, observed) ||
        context.Eprocess != after.Eprocess || context.ProcessId != after.ProcessId ||
        (context.DirectoryTableBase & kPtePfnMask) != (after.DirectoryTableBase & kPtePfnMask))
    {
        if (error != nullptr)
        {
            *error = L"process root identity changed or is unknown";
        }
        return false;
    }
    *eprocess = context.Eprocess;
    return true;
}

static bool SameOrphanRootMapping(const PhysicalTranslationInfo& before, const PhysicalTranslationInfo& after)
{
    constexpr uint64_t mask = kPtePfnMask | kPteNx | 0x87;
    return before.PageSize != 0 && before.PageSize == after.PageSize &&
        before.PhysicalAddress == after.PhysicalAddress && before.PagingLevels == after.PagingLevels &&
        ((before.Flags ^ after.Flags) & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) == 0 &&
        ((before.Pml5e ^ after.Pml5e) & mask) == 0 &&
        ((before.Pml4e ^ after.Pml4e) & mask) == 0 &&
        ((before.Pdpte ^ after.Pdpte) & mask) == 0 &&
        ((before.Pde ^ after.Pde) & mask) == 0 &&
        ((before.Pte ^ after.Pte) & mask) == 0;
}

bool ReadOrphanRootMemory(
    DeviceClient& device, uint64_t cr3, uint64_t address, uint32_t length,
    std::vector<uint8_t>* bytes, std::wstring* error, bool requireExecutable)
{
    if (bytes == nullptr || cr3 == 0 || length == 0 || length > 0x10000 ||
        address > (std::numeric_limits<uint64_t>::max)() - length)
    {
        return false;
    }
    bytes->clear();
    bytes->reserve(length);
    while (bytes->size() < length)
    {
        const uint64_t current = address + bytes->size();
        const uint32_t count = (std::min)(length - static_cast<uint32_t>(bytes->size()),
            static_cast<uint32_t>(0x1000 - (current & 0xFFF)));
        PhysicalTranslationInfo before = {};
        PhysicalTranslationInfo after = {};
        bool writable = false;
        std::vector<uint8_t> part;
        if (!device.TranslateVirtual(cr3, current, 1, &before, error) || before.PageSize == 0 ||
            (requireExecutable && !ValidatePfnTranslation(before, before.PhysicalAddress & ~0xFFFull, &writable)) ||
            !device.ReadPhysical(before.PhysicalAddress, count, &part, error) || part.size() != count ||
            !device.TranslateVirtual(cr3, current, 1, &after, error) || !SameOrphanRootMapping(before, after))
        {
            if (error != nullptr && error->empty())
            {
                *error = L"root mapping changed or bytes were unreadable";
            }
            return false;
        }
        bytes->insert(bytes->end(), part.begin(), part.end());
    }
    return true;
}

bool ProbeOrphanRootExecutable(
    DeviceClient& device, uint64_t cr3, uint64_t address, bool* executable)
{
    if (executable == nullptr)
    {
        return false;
    }
    *executable = false;
    PhysicalTranslationInfo translation = {};
    if (cr3 == 0 || !device.TranslateVirtual(cr3, address, 1, &translation, nullptr))
    {
        return false;
    }
    bool writable = false;
    *executable = ValidatePfnTranslation(translation, translation.PhysicalAddress & ~0xFFFull, &writable);
    return true;
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

        uint64_t pteBaseSymbol = 0;
        if (symbols_.ResolveSymbol(L"nt!MmPteBase", &pteBaseSymbol, nullptr))
        {
            uint64_t pteBase = 0;
            if (LeftoverReadU64(device_, pteBaseSymbol, &pteBase, nullptr) &&
                LeftoverIsKernelCanonical(pteBase, result->La57))
            {
                result->PteBase = pteBase;
            }
        }
        if (result->PteBase == 0)
        {
            result->Warnings.push_back(
                L"nt!MmPteBase unresolved; using the classic LA48 self-map window");
        }


        OrphanKernelPageRegion open = {};
        bool haveOpen = false;
        bool invalidRange = false;
        bool truncated = false;

        auto flushOpen = [&]()
        {
            if (!haveOpen)
            {
                return;
            }
            open.Size = open.End - open.Start;
            open.PageCount = static_cast<uint32_t>(open.Size / kLeftoverPageSize);
            if (result->Regions.size() >= kMaxRetainedRegions)
            {
                truncated = true;
                result->NextPageAddress = open.Start;
                haveOpen = false;
                return;
            }
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
            const bool writable = ancestorsWritable && EntryWritable(entry);
            const bool session = LeftoverIsSessionSpace(va);
            if (!options.IncludeSession && session)
            {
                return;
            }

            std::vector<AddressSpan> spans;
            if (!BuildUnownedLeafSpans(modules_, va, size, &spans))
            {
                invalidRange = true;
                return;
            }
            if (spans.empty() || spans.front().Start != va ||
                spans.back().End - va != size || spans.size() != 1)
            {
                ++result->ModuleLeavesSkipped;
            }

            for (const AddressSpan& span : spans)
            {
                uint64_t cursor = (std::max)(span.Start, options.PageStartAddress);
                while (cursor < span.End && !truncated)
                {
                    OrphanKernelPageRegion next = {};
                    next.Cr3 = result->Cr3;
                    next.RootProcessId = result->RootProcessId;
                    next.RootCreateTime = result->RootCreateTime;
                    next.Start = cursor;
                    next.End = span.End;
                    next.PhysicalAddress = LeafPhysicalBase(entry, size) + (cursor - va);
                    next.MappingPageSize = size;
                    next.Writable = writable;
                    next.Executable = true;
                    next.LargePage = largePage;
                    next.SessionSpace = session;
                    const LeftoverBigPoolEntry* allocation = LeftoverFindBigPool(pool_, cursor);
                    if (allocation != nullptr)
                    {
                        next.InBigPool = true;
                        next.PoolAddress = allocation->VirtualAddress;
                        next.PoolSize = allocation->SizeInBytes;
                        next.PoolTag = allocation->TagRaw;
                        next.PoolNonPaged = allocation->NonPaged;
                        next.End = (std::min)(next.End, allocation->VirtualAddress + allocation->SizeInBytes);
                    }
                    else
                    {
                        const auto following = std::upper_bound(
                            pool_.Entries.begin(), pool_.Entries.end(), cursor,
                            [](uint64_t address, const LeftoverBigPoolEntry& allocation)
                            {
                                return address < allocation.VirtualAddress;
                            });
                        if (following != pool_.Entries.end())
                        {
                            next.End = (std::min)(next.End, following->VirtualAddress);
                        }
                    }

                    if (haveOpen && CanCoalesceRegions(open, next))
                    {
                        open.End = next.End;
                    }
                    else
                    {
                        flushOpen();
                        if (truncated)
                        {
                            break;
                        }
                        open = std::move(next);
                        haveOpen = true;
                    }
                    cursor = open.End;
                }
            }
        };

        if (!WalkKernelTableBatch(
            [this](uint64_t address, std::vector<uint8_t>* bytes, std::wstring* readError)
            {
                return LeftoverReadPhysicalPage(device_, address, bytes, readError);
            },
            addLeaf, options, result, invalidRange, truncated, error))
        {
            break;
        }

        flushOpen();
        result->TraversalFinished = !truncated;
        result->ResumeAddress = result->NextPageAddress;
        result->PageWalkComplete = options.PageStartAddress == 0 &&
            !truncated && !invalidRange && result->TableReadFailures == 0;
        if (truncated)
        {
            result->Warnings.push_back(
                L"kernel page-table walk hit a table-page, stack, or retained-region cap; coverage is partial");
        }
        if (invalidRange)
        {
            result->Warnings.push_back(L"kernel page-table walk encountered an invalid range or paging entry; coverage is partial");
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
            !LeftoverIsKernelCanonical(database, result->La57))
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
        if (pteField.Offset > layout.Size || layout.Size - pteField.Offset < sizeof(uint64_t))
        {
            result->Warnings.push_back(L"nt!_MMPFN.PteAddress exceeds its record; /deep aborted");
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
            havePageLocation = pageLocationOffset < layout.Size && pageLocationBits <= 5;
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
        std::vector<AddressSpan> covered;
        for (const OrphanKernelPageRegion& region : result->Regions)
        {
            covered.push_back({ region.Start, region.End });
        }
        std::sort(covered.begin(), covered.end(), [](const AddressSpan& left, const AddressSpan& right)
        {
            return left.Start < right.Start;
        });

        bool truncated = false;
        std::sort(ranges.begin(), ranges.end(), [](const PhysicalMemoryRange& left, const PhysicalMemoryRange& right)
        {
            return left.BaseAddress < right.BaseAddress;
        });
        for (const PhysicalMemoryRange& range : ranges)
        {
            if (truncated)
            {
                break;
            }

            uint64_t pfn = 0;
            uint64_t endPfn = 0;
            if (!PfnRangeBounds(range, options.PfnStartAddress, &pfn, &endPfn))
            {
                ++result->PfnValidationFailures;
                continue;
            }
            while (pfn < endPfn && !truncated)
            {
                if (result->PfnEntriesExamined >= maxEntries ||
                    result->Regions.size() >= kMaxRetainedRegions)
                {
                    truncated = true;
                    result->NextPfnAddress = pfn << kLeftoverPageShift;
                    break;
                }
                const uint32_t batch = PfnBatchSize(layout.Size, endPfn - pfn,
                    maxEntries - result->PfnEntriesExamined);

                uint64_t chunkAddr = 0;
                if (pfn > (std::numeric_limits<uint64_t>::max)() / layout.Size ||
                    !LeftoverTryAdd(database, pfn * layout.Size, &chunkAddr))
                {
                    truncated = true;
                    result->NextPfnAddress = pfn << kLeftoverPageShift;
                    break;
                }

                const uint32_t bytes = batch * static_cast<uint32_t>(layout.Size);
                std::vector<uint8_t> chunk;
                std::wstring readError;
                if (!device_.ReadMemory(chunkAddr, bytes, &chunk, &readError) ||
                    chunk.size() != bytes)
                {
                    ++result->PfnReadFailures;
                    if (result->PfnReadFailures <= kMaxReadWarnings)
                    {
                        result->Warnings.push_back(
                            L"PFN database read failed at " + LeftoverFormatHex(chunkAddr, 16));
                    }
                    result->PfnEntriesExamined += batch;
                    pfn += batch;
                    continue;
                }

                for (uint32_t index = 0; index < batch; ++index)
                {
                    if (result->PfnEntriesExamined >= maxEntries ||
                        result->Regions.size() >= kMaxRetainedRegions)
                    {
                        truncated = true;
                        result->NextPfnAddress = (pfn + index) << kLeftoverPageShift;
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

                    uint64_t pteAddress = 0;
                    memcpy(&pteAddress, entry + pteField.Offset, sizeof(uint64_t));
                    if (!LeftoverIsKernelCanonical(pteAddress, result->La57) ||
                        !LeftoverIsPageTableSelfMap(pteAddress, result->PteBase, result->La57))
                    {
                        continue;
                    }

                    const uint64_t va = LeftoverDecodeVaFromPteAddress(
                        pteAddress,
                        result->PteBase,
                        result->La57);
                    if (!LeftoverIsKernelCanonical(va, result->La57))
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
                    const auto after = std::upper_bound(
                        covered.begin(), covered.end(), va,
                        [](uint64_t address, const AddressSpan& span)
                        {
                            return address < span.Start;
                        });
                    if (after != covered.begin() && va < (after - 1)->End)
                    {
                        continue;
                    }

                    uint64_t pte = 0;
                    std::vector<uint8_t> pteBytes;
                    if (!ReadOrphanRootMemory(device_, result->Cr3, pteAddress, sizeof(pte), &pteBytes, nullptr))
                    {
                        ++result->PfnReadFailures;
                        continue;
                    }
                    std::memcpy(&pte, pteBytes.data(), sizeof(pte));
                    const uint64_t physical = (pfn + index) << kLeftoverPageShift;
                    if (!EntryPresent(pte) || !EntryExecutable(pte) || EntryPhysical(pte) != physical)
                    {
                        continue;
                    }
                    PhysicalTranslationInfo translation = {};
                    if (!device_.TranslateVirtual(result->Cr3, va, 1, &translation, nullptr))
                    {
                        ++result->PfnValidationFailures;
                        continue;
                    }
                    bool writable = false;
                    if (!ValidatePfnTranslation(translation, physical, &writable))
                    {
                        continue;
                    }

                    OrphanKernelPageRegion region = {};
                    region.Cr3 = result->Cr3;
                    region.RootProcessId = result->RootProcessId;
                    region.RootCreateTime = result->RootCreateTime;
                    region.Start = va;
                    region.End = va + kLeftoverPageSize;
                    region.Size = kLeftoverPageSize;
                    region.PageCount = 1;
                    region.PhysicalAddress = physical;
                    region.MappingPageSize = translation.PageSize;
                    region.LargePage = translation.PageSize > kLeftoverPageSize;
                    region.Writable = writable;
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

        result->PfnContinuationPending = truncated;
        result->PfnWalkComplete = options.PfnStartAddress == 0 && !truncated && result->PfnReadFailures == 0 &&
            result->PfnValidationFailures == 0;
        if (truncated)
        {
            result->Warnings.push_back(
                L"PFN walk hit an entry or retained-region cap; /deep coverage is partial");
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

    const uint32_t limit = (std::min)(options.Limit == 0 ? kDefaultLimit : options.Limit, kMaxLimit);
    const bool windowed = options.MaxRegionBytes != 0;
    if (windowed)
    {
        std::vector<OrphanKernelPageRegion> regions = std::move(result->Regions);
        result->Regions.clear();
        std::sort(regions.begin(), regions.end(),
            [](const OrphanKernelPageRegion& left, const OrphanKernelPageRegion& right)
            {
                return left.Start < right.Start;
            });
        const uint64_t windowBytes = (std::min<uint64_t>)(kMaxBodyWindowBytes, (std::max<uint64_t>)(
            kLeftoverPageSize, options.MaxRegionBytes & ~(kLeftoverPageSize - 1)));
        OrphanKernelPageBodyCursor bodyCursor;
        bodyCursor.RegionAfter = options.BodyRegionAfter;
        bodyCursor.WindowRound = options.BodyWindowRound;
        if (!SelectRegionWindows(regions, windowBytes, options.RegionOffset, limit, result,
                options.UseAddressBodyCursor ? &bodyCursor : nullptr))
        {
            result->PageWalkComplete = false;
            result->Warnings.push_back(L"orphan-page sample count overflow; coverage is partial");
            return;
        }
        if (result->RegionsTruncated)
        {
            result->Warnings.push_back(
                L"orphan-page body sampling returned " + std::to_wstring(result->Regions.size()) +
                L" of " + std::to_wstring(result->RegionsDiscovered) +
                L" window(s); next offset=" + std::to_wstring(result->NextRegionOffset) +
                L", after=" + LeftoverFormatHex(result->NextBodyRegionAfter, 16) +
                L", round=" + std::to_wstring(result->NextBodyWindowRound));
        }
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

        if (windowed || region.Cr3 != 0)
        {
            PhysicalTranslationInfo translation = {};
            if (device_.TranslateVirtual(result->Cr3, region.Start, 1, &translation, nullptr))
            {
                bool writable = false;
                const uint64_t physical = translation.PhysicalAddress & ~0xFFFull;
                if (ValidatePfnTranslation(translation, physical, &writable))
                {
                    region.PhysicalAddress = translation.PhysicalAddress;
                    region.Writable = writable;
                    region.MappingPageSize = translation.PageSize;
                    region.LargePage = translation.PageSize > kLeftoverPageSize;
                }
                else
                {
                    region.Executable = false;
                    LeftoverAppendNote(&region.Notes, L"sample translation changed after page walk");
                }
            }
            else
            {
                region.Executable = false;
                LeftoverAppendNote(&region.Notes, L"sample translation was unreadable");
            }
            if (!region.Executable)
            {
                ++result->SampleValidationFailures;
                result->PageWalkComplete = false;
                if (result->SampleValidationFailures <= kMaxReadWarnings)
                {
                    result->Warnings.push_back(
                        L"orphan sample validation incomplete at " +
                        LeftoverFormatHex(region.Start, 16) + L": " + region.Notes);
                }
                continue;
            }
        }

        const uint64_t probeAt = !windowed && region.InBigPool ? region.PoolAddress : region.Start;
        const RegionPeObservation pe = ProbeRegionPageHeaders(
            [this, result, windowed](uint64_t address, uint32_t length, std::vector<uint8_t>* bytes)
            {
                return ReadOrphanRootMemory(device_, result->Cr3, address, length, bytes, nullptr, windowed);
            },
            probeAt, windowed ? region.Size : kLeftoverPageSize);
        if (pe.ReadFailures != 0)
        {
            result->SampleValidationFailures += pe.ReadFailures;
            result->PageWalkComplete = false;
            if (result->SampleValidationFailures <= kMaxReadWarnings)
            {
                result->Warnings.push_back(
                    L"orphan PE probe incomplete at " + LeftoverFormatHex(probeAt, 16) +
                    L"; failed_pages=" + std::to_wstring(pe.ReadFailures));
            }
        }
        if (pe.Address != 0)
        {
            region.HasPe = true;
            region.PeAddress = pe.Address;
            region.Pe = pe.Probe;
        }

        region.Classification = ClassifyRegion(region);
        region.Risk = RiskForRegion(region);
        if (region.Writable && region.Executable)
        {
            LeftoverAppendNote(&region.Notes, L"effective W+X");
            result->AnyHighRisk = true;
        }
        if (region.HasPe)
        {
            LeftoverAppendNote(&region.Notes,
                L"PE header at " + LeftoverFormatHex(region.PeAddress, 16));
            result->AnyHighRisk = true;
        }
    }

    std::vector<OrphanKernelPageRegion> filtered;
    filtered.reserve(result->Regions.size());
    for (const OrphanKernelPageRegion& region : result->Regions)
    {
        if (!region.Executable)
        {
            continue;
        }
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
            return left.Size != right.Size ? left.Size > right.Size : left.Start < right.Start;
        });

    if (!windowed)
    {
        result->RegionsDiscovered = filtered.size();
        const size_t offset = options.RegionOffset < filtered.size()
            ? static_cast<size_t>(options.RegionOffset) : 0;
        const size_t count = (std::min)(static_cast<size_t>(limit), filtered.size() - offset);
        result->RegionsTruncated = count < filtered.size();
        result->RegionsDropped = filtered.size() - count;
        result->NextRegionOffset = offset + count < filtered.size() ? offset + count : 0;
        if (result->RegionsTruncated)
        {
            result->Warnings.push_back(
                L"orphan-page output truncated to " + std::to_wstring(count) +
                L" of " + std::to_wstring(filtered.size()) + L" region(s)");
        }
        filtered = std::vector<OrphanKernelPageRegion>(
            filtered.begin() + offset, filtered.begin() + offset + count);
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
        bool moduleRangesComplete = false;
        LeftoverBuildModuleRanges(symbols_, &modules_, &moduleRangesComplete);
        if (!moduleRangesComplete)
        {
            if (error != nullptr)
            {
                *error = L"loaded-module ranges are incomplete; orphan ownership cannot be classified";
            }
            break;
        }

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
        if (options.Incremental && options.Continuation == nullptr)
        {
            local.PageStartAddress = options.ResumeAddress;
        }
        ControlRegisters registers = {};
        if (!device_.ReadControlRegisters(0, &registers, error))
        {
            break;
        }
        result->La57 = (registers.Cr4 & (1ull << 12)) != 0;
        result->PagingLevels = result->La57 ? 5u : 4u;
        const uint64_t currentRoot = registers.Cr3 & kPtePfnMask;
        if (currentRoot == 0)
        {
            break;
        }
        std::vector<OrphanKernelPageRoot> roots;
        roots.push_back({ currentRoot, 0, 0 });
        result->RootInventoryComplete = options.RootInventoryComplete;
        constexpr size_t kRootLimit = 4096;
        for (const OrphanKernelPageRoot& supplied : options.Roots)
        {
            if (roots.size() >= kRootLimit)
            {
                result->RootInventoryComplete = false;
                result->Warnings.push_back(L"address-space root input exceeded the bounded inventory");
                break;
            }
            OrphanKernelPageRoot root = supplied;
            root.Cr3 &= kPtePfnMask;
            if (root.Cr3 == 0 || root.ProcessId == 0 || root.CreateTime == 0)
            {
                result->RootInventoryComplete = false;
                continue;
            }
            roots.push_back(root);
        }
        std::sort(roots.begin(), roots.end(), [](const OrphanKernelPageRoot& left, const OrphanKernelPageRoot& right)
        {
            return left.Cr3 != right.Cr3 ? left.Cr3 < right.Cr3 : left.ProcessId < right.ProcessId;
        });
        roots.erase(std::unique(roots.begin(), roots.end(), [](const OrphanKernelPageRoot& left, const OrphanKernelPageRoot& right)
        {
            return left.Cr3 == right.Cr3;
        }), roots.end());
        if (options.Continuation != nullptr && options.DeepPfn)
        {
            result->ContinuationReset = ArmOrphanDeepRoots(options.Continuation, roots);
        }
        result->RootCount = roots.size();
        const uint64_t afterRoot = options.Continuation == nullptr ? 0 : options.Continuation->RootAfter;
        const auto followingRoot = std::upper_bound(roots.begin(), roots.end(), afterRoot,
            [](uint64_t address, const OrphanKernelPageRoot& root)
            {
                return address < root.Cr3;
            });
        const OrphanKernelPageRoot selected = followingRoot == roots.end() ? roots.front() : *followingRoot;
        result->Cr3 = selected.Cr3;
        result->RootProcessId = selected.ProcessId;
        result->RootCreateTime = selected.CreateTime;
        result->AlternateRoot = selected.Cr3 != currentRoot;
        if (options.Continuation != nullptr)
        {
            // A dead root must not prevent the following root from running.
            options.Continuation->RootAfter = selected.Cr3;
        }
        uint64_t rootEprocess = 0;
        if (selected.ProcessId != 0 &&
            !ReadOrphanRootIdentity(device_, symbols_, selected, &rootEprocess, error))
        {
            result->ContinuationReset = true;
            break;
        }
        OrphanKernelPageCursor cursor = {};
        cursor.Root = selected;
        if (options.Continuation != nullptr)
        {
            for (const OrphanKernelPageCursor& previous : options.Continuation->Roots)
            {
                if (previous.Root.Cr3 == selected.Cr3)
                {
                    if (previous.Root.ProcessId == selected.ProcessId && previous.Root.CreateTime == selected.CreateTime)
                    {
                        cursor = previous;
                    }
                    else
                    {
                        result->ContinuationReset = true;
                    }
                    break;
                }
            }
            local.PageStartAddress = cursor.PageAddress;
            local.PfnStartAddress = cursor.PfnAddress;
            local.DeepPfn = local.DeepPfn || cursor.PfnPending;
        }
        const OrphanKernelPageBodyCursor bodyBatch =
        {
            local.PageStartAddress, local.DeepPfn ? local.PfnStartAddress : 0, 0, local.DeepPfn
        };
        if (options.Continuation != nullptr)
        {
            const OrphanKernelPageBodyCursor savedBody = FindBodyBatchCursor(cursor, bodyBatch);
            local.RegionOffset = savedBody.RegionOffset;
            local.UseAddressBodyCursor = true;
            local.BodyRegionAfter = savedBody.RegionAfter;
            local.BodyWindowRound = savedBody.WindowRound;
        }
        if (local.MaxTablePages == 0)
        {
            local.MaxTablePages = 32768;
        }
        local.MaxTablePages = (std::max)(local.MaxTablePages, result->PagingLevels + 1);
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
                result->PfnContinuationPending = true;
                if (!pfnError.empty())
                {
                    result->Warnings.push_back(L"pfn: " + pfnError);
                }
            }
        }

        FinalizeRegions(local, result);
        if (selected.ProcessId != 0)
        {
            uint64_t afterEprocess = 0;
            if (!ReadOrphanRootIdentity(device_, symbols_, selected, &afterEprocess, error) ||
                afterEprocess != rootEprocess)
            {
                result->Regions.clear();
                result->PageWalkComplete = false;
                result->PfnWalkComplete = false;
                result->AnyHighRisk = false;
                result->ContinuationReset = true;
                if (error != nullptr && error->empty())
                {
                    *error = L"process root identity changed during the scan";
                }
                break;
            }
        }
        if (options.Continuation != nullptr)
        {
            cursor.RegionOffset = result->NextRegionOffset;
            OrphanKernelPageBodyCursor nextBody = bodyBatch;
            nextBody.RegionOffset = result->NextRegionOffset;
            nextBody.RegionAfter = result->NextBodyRegionAfter;
            nextBody.WindowRound = result->NextBodyWindowRound;
            result->BodyCursorEvicted = SaveBodyBatchOffset(&cursor, nextBody);
            if (result->BodyCursorEvicted)
            {
                result->Warnings.push_back(L"body batch continuation cache eviction; prior body progress was lost");
            }
            // Advance enumeration independently of large-region body windows.
            // A bounded cache resumes those windows when this batch returns.
            cursor.PageAddress = result->NextPageAddress;
            if (local.DeepPfn)
            {
                cursor.PfnAddress = result->NextPfnAddress;
            }
            cursor.PfnPending = result->PfnContinuationPending ||
                std::any_of(cursor.BodyWindows.begin(), cursor.BodyWindows.end(),
                    [](const OrphanKernelPageBodyCursor& savedBody)
                    {
                        return savedBody.DeepPfn;
                    });
            auto& saved = options.Continuation->Roots;
            saved.erase(std::remove_if(saved.begin(), saved.end(), [&](const OrphanKernelPageCursor& previous)
            {
                return previous.Root.Cr3 == selected.Cr3;
            }), saved.end());
            if (saved.size() >= kRootLimit)
            {
                saved.erase(saved.begin());
                result->ContinuationReset = true;
                result->Warnings.push_back(L"root continuation cache eviction; prior progress was lost");
            }
            saved.push_back(cursor);
            options.Continuation->RootAfter = selected.Cr3;
            result->PfnContinuationPending = cursor.PfnPending;
        }
        if (!result->RootInventoryComplete || result->RootCount > 1)
        {
            result->CoverageNotes.push_back(L"this pass observes one address-space root; other roots are pending or unknown");
        }
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
    out += L",\"rootProcessId\":" + std::to_wstring(result.RootProcessId);
    out += L",\"rootCreateTime\":" + std::to_wstring(result.RootCreateTime);
    out += L",\"rootCount\":" + std::to_wstring(result.RootCount);
    out += L",\"rootInventoryComplete\":";
    out += result.RootInventoryComplete ? L"true" : L"false";
    out += L",\"alternateRoot\":";
    out += result.AlternateRoot ? L"true" : L"false";
    out += L",\"continuationReset\":";
    out += result.ContinuationReset ? L"true" : L"false";
    out += L",\"bodyCursorEvicted\":";
    out += result.BodyCursorEvicted ? L"true" : L"false";
    out += L",\"pfnContinuationPending\":";
    out += result.PfnContinuationPending ? L"true" : L"false";
    out += L",\"nextPageAddress\":" + mcpjson::Quote(LeftoverFormatHex(result.NextPageAddress, 16));
    out += L",\"nextPfnAddress\":" + mcpjson::Quote(LeftoverFormatHex(result.NextPfnAddress, 16));
    out += L",\"pteBase\":" + mcpjson::Quote(LeftoverFormatHex(result.PteBase, 16));
    out += L",\"pageWalkComplete\":";
    out += result.PageWalkComplete ? L"true" : L"false";
    out += L",\"pfnWalkAttempted\":";
    out += result.PfnWalkAttempted ? L"true" : L"false";
    out += L",\"pfnWalkComplete\":";
    out += result.PfnWalkComplete ? L"true" : L"false";
    out += L",\"tablePagesWalked\":" + std::to_wstring(result.TablePagesWalked);
    out += L",\"resumeAddress\":" + std::to_wstring(result.ResumeAddress);
    out += L",\"tableReadFailures\":" + std::to_wstring(result.TableReadFailures);
    out += L",\"regionsDropped\":" + std::to_wstring(result.RegionsDropped);
    out += L",\"executableLeaves\":" + std::to_wstring(result.ExecutableLeaves);
    out += L",\"moduleLeavesSkipped\":" + std::to_wstring(result.ModuleLeavesSkipped);
    out += L",\"selfMapLeavesSkipped\":" + std::to_wstring(result.SelfMapLeavesSkipped);
    out += L",\"pfnEntriesExamined\":" + std::to_wstring(result.PfnEntriesExamined);
    out += L",\"pfnHits\":" + std::to_wstring(result.PfnHits);
    out += L",\"pfnReadFailures\":" + std::to_wstring(result.PfnReadFailures);
    out += L",\"pfnValidationFailures\":" + std::to_wstring(result.PfnValidationFailures);
    out += L",\"sampleValidationFailures\":" + std::to_wstring(result.SampleValidationFailures);
    out += L",\"regionsDiscovered\":" + std::to_wstring(result.RegionsDiscovered);
    out += L",\"nextRegionOffset\":" + std::to_wstring(result.NextRegionOffset);
    out += L",\"nextBodyRegionAfter\":" + mcpjson::Quote(LeftoverFormatHex(result.NextBodyRegionAfter, 16));
    out += L",\"nextBodyWindowRound\":" + std::to_wstring(result.NextBodyWindowRound);
    out += L",\"regionsTruncated\":";
    out += result.RegionsTruncated ? L"true" : L"false";
    out += L",\"bigPoolQueried\":";
    out += result.BigPoolQueried ? L"true" : L"false";
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
        out += L",\"cr3\":" + mcpjson::Quote(LeftoverFormatHex(region.Cr3, 16));
        out += L",\"rootProcessId\":" + std::to_wstring(region.RootProcessId);
        out += L",\"rootCreateTime\":" + std::to_wstring(region.RootCreateTime);
        out += L",\"end\":" + mcpjson::Quote(LeftoverFormatHex(region.End, 16));
        out += L",\"size\":" + std::to_wstring(region.Size);
        out += L",\"pages\":" + std::to_wstring(region.PageCount);
        out += L",\"physical\":" + mcpjson::Quote(LeftoverFormatHex(region.PhysicalAddress, 16));
        out += L",\"mappingPageSize\":" + std::to_wstring(region.MappingPageSize);
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
        out += L",\"peAddress\":" + mcpjson::Quote(LeftoverFormatHex(region.PeAddress, 16));
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
    out += L"],\"coverageNotes\":[";
    for (size_t index = 0; index < result.CoverageNotes.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.CoverageNotes[index]);
    }
    out += L"]}";
    return out;
}

bool OrphanKernelPageSelfTest()
{
    bool ok = true;

    {
        PhysicalTranslationInfo before = {};
        before.PageSize = 0x1000;
        before.PhysicalAddress = 0x100000;
        before.PagingLevels = 4;
        before.Pml4e = 0x2003;
        before.Pdpte = 0x3003;
        before.Pde = 0x4003;
        before.Pte = 0x100003;
        PhysicalTranslationInfo after = before;
        after.Pte |= (1ull << 5) | (1ull << 6);
        ok = ok && SameOrphanRootMapping(before, after);
        after.Pte |= kPteNx;
        ok = ok && !SameOrphanRootMapping(before, after);
        after = before;
        after.PhysicalAddress += 0x1000;
        ok = ok && !SameOrphanRootMapping(before, after);
        after = before;
        after.Pml4e ^= 2;
        ok = ok && !SameOrphanRootMapping(before, after);
    }

    {
        PhysicalMemoryRange range = {};
        range.BaseAddress = 0x1000;
        range.ByteCount = 0x10000;
        uint64_t first = 0;
        uint64_t last = 0;
        ok = ok && PfnRangeBounds(range, 0x9000, &first, &last) && first == 9 && last == 17;
        ok = ok && PfnBatchSize(48, last - first, 5) == 5 && PfnBatchSize(48, 3, 5) == 3 &&
            PfnBatchSize(48, 3, 0) == 0 && PfnBatchSize(0, 3, 5) == 0;
        ok = ok && PfnRangeBounds(range, 0x11000, &first, &last) && first == last;
        range.BaseAddress = 0xFFFFFFFFFFFFF000ull;
        ok = ok && !PfnRangeBounds(range, 0, &first, &last);
        range.BaseAddress = 1;
        ok = ok && !PfnRangeBounds(range, 0, &first, &last);
    }

    // Exercise the production page-table traversal with a five-read budget.
    // Continuations reread ancestors and observe remapped table pages.
    {
        constexpr uint64_t base = 0xFFFF800000000000ull;
        std::map<uint64_t, std::vector<uint8_t>> tables;
        for (uint64_t pa = 0x1000; pa <= 0x7000; pa += 0x1000)
        {
            tables.emplace(pa, std::vector<uint8_t>(0x1000, 0));
        }
        auto setEntry = [&](uint64_t pa, size_t index, uint64_t entry)
        {
            std::memcpy(tables[pa].data() + index * sizeof(entry), &entry, sizeof(entry));
        };
        setEntry(0x1000, 256, 0x2003);
        setEntry(0x2000, 0, 0x3003);
        setEntry(0x3000, 0, 0x4003);
        setEntry(0x3000, 1, 0x5003);
        setEntry(0x3000, 2, 0x6003);
        setEntry(0x4000, 0, 0x100003);
        setEntry(0x5000, 0, 0x200003);
        setEntry(0x6000, 0, 0x300003);
        setEntry(0x7000, 0, 0x400003);
        uint64_t failedTable = 0;
        bool shortRead = false;
        auto readTable = [&](uint64_t pa, std::vector<uint8_t>* bytes, std::wstring*)
        {
            const auto found = tables.find(pa);
            if (pa == failedTable || found == tables.end())
            {
                return false;
            }
            *bytes = found->second;
            if (shortRead)
            {
                bytes->resize(0xFFF);
            }
            return true;
        };
        std::map<uint64_t, uint64_t> observed;
        auto visit = [&](uint64_t va, uint64_t, uint64_t entry, bool, bool, bool)
        {
            observed[va] = EntryPhysical(entry);
        };
        OrphanKernelPageOptions options;
        options.MaxTablePages = 5;
        bool finished = false;
        for (uint32_t pass = 0; pass < 16; ++pass)
        {
            OrphanKernelPageResult batch;
            batch.Cr3 = 0x1000;
            bool invalid = false;
            bool truncated = false;
            ok = ok && WalkKernelTableBatch(readTable, visit, options, &batch, invalid, truncated, nullptr);
            ok = ok && !invalid && batch.TableReadFailures == 0 && batch.TablePagesWalked <= 5;
            if (pass == 0)
            {
                ok = ok && truncated && batch.NextPageAddress == base + 0x200000;
                setEntry(0x3000, 1, 0x7003);
            }
            if (batch.NextPageAddress == 0)
            {
                finished = true;
                break;
            }
            ok = ok && batch.NextPageAddress > options.PageStartAddress;
            options.PageStartAddress = batch.NextPageAddress;
        }
        ok = ok && finished && observed.size() == 3 && observed[base] == 0x100000 &&
            observed[base + 0x200000] == 0x400000 && observed[base + 0x400000] == 0x300000;

        // A failed or short table is unknown, never an empty successful read.
        options.PageStartAddress = 0;
        failedTable = 0x1000;
        for (uint32_t attempt = 0; attempt < 2; ++attempt)
        {
            OrphanKernelPageResult batch;
            batch.Cr3 = 0x1000;
            bool invalid = false;
            bool truncated = false;
            WalkKernelTableBatch(readTable, visit, options, &batch, invalid, truncated, nullptr);
            ok = ok && batch.TableReadFailures == 1 && batch.TablePagesWalked == 0;
            failedTable = 0;
            shortRead = true;
        }
        shortRead = false;
        for (auto& table : tables)
        {
            std::fill(table.second.begin(), table.second.end(), uint8_t(0));
        }
        setEntry(0x1000, 511, 0x2003);
        setEntry(0x2000, 511, 0x3003);
        setEntry(0x3000, 511, 0x4003);
        setEntry(0x4000, 511, 0x100003);
        observed.clear();
        OrphanKernelPageResult last;
        last.Cr3 = 0x1000;
        bool invalid = false;
        bool truncated = false;
        WalkKernelTableBatch(readTable, visit, options, &last, invalid, truncated, nullptr);
        ok = ok && !invalid && !truncated && observed.size() == 1 &&
            observed.begin()->first == 0xFFFFFFFFFFFFF000ull;

        const OrphanKernelPageRoot generation = { 0x1000, 10, 100 };
        ok = ok && OrphanRootIdentityMatches(generation, generation) &&
            !OrphanRootIdentityMatches(generation, { 0x2000, 10, 100 }) &&
            !OrphanRootIdentityMatches(generation, { 0x1000, 11, 100 }) &&
            !OrphanRootIdentityMatches(generation, { 0x1000, 10, 101 }) &&
            !OrphanRootIdentityMatches(generation, { 0x1000, 10, 0 });

        OrphanKernelPageContinuation continuation;
        std::vector<OrphanKernelPageRoot> roots = { generation, { 0x2000, 11, 200 } };
        ok = ok && !ArmOrphanDeepRoots(&continuation, roots) && continuation.Roots.size() == 2 &&
            continuation.Roots[0].PfnPending && continuation.Roots[1].PfnPending;
        continuation.Roots[0].PfnPending = false;
        continuation.Roots[1].PageAddress = base;
        continuation.Roots[1].PfnAddress = 0x8000;
        roots[1].CreateTime = 201;
        ok = ok && ArmOrphanDeepRoots(&continuation, roots) && continuation.Roots[0].PfnPending &&
            continuation.Roots[1].PfnPending && continuation.Roots[1].PageAddress == 0 &&
            continuation.Roots[1].PfnAddress == 0;

        OrphanKernelPageCursor bodyCursor;
        const OrphanKernelPageBodyCursor batchA = { base, 0, 128, false };
        const OrphanKernelPageBodyCursor batchB = { base + 0x200000, 0, 256, false };
        ok = ok && !SaveBodyBatchOffset(&bodyCursor, batchA) && !SaveBodyBatchOffset(&bodyCursor, batchB) &&
            FindBodyBatchOffset(bodyCursor, batchA) == 128 && FindBodyBatchOffset(bodyCursor, batchB) == 256;
        OrphanKernelPageBodyCursor completed = batchA;
        completed.RegionOffset = 0;
        ok = ok && !SaveBodyBatchOffset(&bodyCursor, completed) && FindBodyBatchOffset(bodyCursor, batchA) == 0;
        for (uint64_t index = 0; index < 64; ++index)
        {
            SaveBodyBatchOffset(&bodyCursor, { base + index * 0x400000, 0, index + 1, true });
        }
        ok = ok && bodyCursor.BodyWindows.size() == 64 &&
            SaveBodyBatchOffset(&bodyCursor, { base + 64 * 0x400000, 0, 1, true }) &&
            bodyCursor.BodyWindows.size() == 64;
    }

    do
    {
        constexpr uint64_t sampleBase = 0xFFFFC00000100000ull;
        std::vector<uint8_t> sample(0x4000, 0);
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        IMAGE_NT_HEADERS64 nt = {};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.SizeOfImage = 0x3000;
        std::memcpy(sample.data() + 0x1000, &dos, sizeof(dos));
        std::memcpy(sample.data() + 0x1080, &nt, sizeof(nt));
        uint64_t shortPage = 0;
        uint64_t failedPage = 0;
        uint32_t reads = 0;
        auto readSample = [&](uint64_t address, uint32_t length, std::vector<uint8_t>* bytes)
        {
            ++reads;
            bytes->clear();
            if (address == failedPage || address < sampleBase ||
                address - sampleBase >= sample.size() ||
                length > sample.size() - (address - sampleBase))
            {
                return false;
            }
            const size_t offset = static_cast<size_t>(address - sampleBase);
            const size_t count = address == shortPage ? 0x20 : length;
            bytes->assign(sample.begin() + offset, sample.begin() + offset + count);
            return true;
        };
        RegionPeObservation observed = ProbeRegionPageHeaders(readSample, sampleBase, sample.size());
        if (observed.Address != sampleBase + 0x1000 || observed.ReadFailures != 0 || reads != 4)
        {
            ok = false;
            break;
        }
        shortPage = sampleBase;
        failedPage = sampleBase + 0x2000;
        observed = ProbeRegionPageHeaders(readSample, sampleBase, sample.size());
        if (observed.Address != sampleBase + 0x1000 || observed.ReadFailures != 2 || reads != 8)
        {
            ok = false;
            break;
        }
        shortPage = 0;
        failedPage = 0;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        std::memcpy(sample.data() + 0x1080, &nt, sizeof(nt));
        observed = ProbeRegionPageHeaders(readSample, sampleBase, sample.size());
        if (observed.Address != 0 || observed.ReadFailures != 0)
        {
            ok = false;
            break;
        }
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        std::fill(sample.begin(), sample.end(), uint8_t(0));
        std::memcpy(sample.data() + 0x1080, &dos, sizeof(dos));
        std::memcpy(sample.data() + 0x1100, &nt, sizeof(nt));
        observed = ProbeRegionPageHeaders(readSample, sampleBase, sample.size());
        const uint32_t previousReads = reads;
        const auto overflowProbe = ProbeRegionPageHeaders(readSample, ~uint64_t(0) - 0xFFF, 0x1000);
        if (observed.Address != 0 || observed.ReadFailures != 0 ||
            overflowProbe.ReadFailures != 1 || reads != previousReads)
        {
            ok = false;
            break;
        }
        const std::vector<LeftoverModuleRange> overlapping =
        {
            {0x404000, 0x406000, L"second"},
            {0x401000, 0x402000, L"first"},
            {0x405000, 0x407000, L"overlap"}
        };
        const auto gaps = UnownedLeafRanges(overlapping, 0x400000, 0x200000, 0);
        const auto resumed = UnownedLeafRanges(overlapping, 0x400000, 0x200000, 0x403000);
        if (gaps.size() != 3 || gaps[0] != std::make_pair(0x400000ull, 0x401000ull) ||
            gaps[1] != std::make_pair(0x402000ull, 0x404000ull) ||
            gaps[2] != std::make_pair(0x407000ull, 0x600000ull) ||
            resumed.size() != 2 || resumed[0] != std::make_pair(0x403000ull, 0x404000ull) ||
            resumed[1] != gaps[2] ||
            LeafPhysical(0x80001083, 0x200000) != 0x80000000 ||
            LeafPhysical(0x80001083, 0x40000000) != 0x80000000 ||
            LeafPhysical(0x80001003, 0x1000) != 0x80001000 ||
            !UnownedLeafRanges(overlapping, 0x400000, 0x200000, 0x600000).empty() ||
            !UnownedLeafRanges({{0x400000, 0x600000, L"full"}}, 0x400000, 0x200000, 0).empty())
        {
            ok = false;
            break;
        }
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
        largePage.MappingPageSize = 0x200000;
        largePage.Size = 0x200000;
        largePage.HasPe = false;
        if (ClassifyRegion(largePage) != L"wx_orphan" ||
            RiskForRegion(largePage) != L"high")
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion largePool = largePage;
        largePool.InBigPool = true;
        if (ClassifyRegion(largePool) != L"wx_orphan" ||
            RiskForRegion(largePool) != L"high")
        {
            ok = false;
            break;
        }
        OrphanKernelPageRegion largeWindow = largePage;
        largeWindow.Size = 0x4000;
        if (ClassifyRegion(largeWindow) != L"wx_orphan" || RiskForRegion(largeWindow) != L"high")
        {
            ok = false;
            break;
        }

        const uint64_t leafVa = 0xFFFFC08000000000ull;
        LeftoverModuleRange middle = {};
        middle.Base = leafVa + 0x4000;
        middle.End = leafVa + 0x6001;
        std::vector<AddressSpan> unowned;
        if (!BuildUnownedLeafSpans({ middle }, leafVa, 0x200000, &unowned) ||
            unowned.size() != 2 || unowned[0].Start != leafVa ||
            unowned[0].End != leafVa + 0x4000 ||
            unowned[1].Start != leafVa + 0x7000 || unowned[1].End != leafVa + 0x200000 ||
            BuildUnownedLeafSpans({}, ~0ull - 0x1000, 0x2000, &unowned) ||
            LeafPhysicalBase(0x201083, 0x200000) != 0x200000 ||
            LeafPhysicalBase(0x40001083, 0x40000000) != 0x40000000)
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion poolLeft = {};
        poolLeft.Start = leafVa;
        poolLeft.End = leafVa + 0x1000;
        poolLeft.InBigPool = true;
        poolLeft.PoolAddress = leafVa;
        OrphanKernelPageRegion poolRight = poolLeft;
        poolRight.Start = poolLeft.End;
        poolRight.End = poolRight.Start + 0x1000;
        if (!CanCoalesceRegions(poolLeft, poolRight))
        {
            ok = false;
            break;
        }
        poolRight.PoolAddress = poolRight.Start;
        if (CanCoalesceRegions(poolLeft, poolRight))
        {
            ok = false;
            break;
        }

        OrphanKernelPageRegion huge = {};
        huge.Start = leafVa;
        huge.Size = 0x40001000;
        huge.End = huge.Start + huge.Size;
        huge.PhysicalAddress = 0x200000;
        huge.MappingPageSize = 0x40000000;
        huge.LargePage = true;
        OrphanKernelPageResult windows = {};
        if (!SelectRegionWindows({ huge }, 0x4000, 65535, 2, &windows) ||
            windows.Regions.size() != 2 || windows.RegionsDiscovered != 65537 ||
            !windows.RegionsTruncated || windows.NextRegionOffset != 0 ||
            windows.Regions[0].Start != leafVa + 0x3FFFC000 ||
            windows.Regions[0].PhysicalAddress != 0 ||
            windows.Regions[0].MappingPageSize != 0x40000000 ||
            windows.Regions[1].Size != 0x1000)
        {
            ok = false;
            break;
        }
        windows = {};
        if (!SelectRegionWindows({ huge }, 0x4000, 65537, 2, &windows) ||
            windows.Regions.size() != 2 || windows.Regions[0].Start != leafVa ||
            windows.NextRegionOffset != 2)
        {
            ok = false;
            break;
        }
        OrphanKernelPageRegion small = huge;
        small.Start = huge.End + 0x1000;
        small.Size = 0x1000;
        small.End = small.Start + small.Size;
        windows = {};
        if (!SelectRegionWindows({ huge, small }, 0x4000, 0, 2, &windows) ||
            windows.Regions.size() != 2 || windows.Regions[0].Start != huge.Start ||
            windows.Regions[1].Start != small.Start || windows.NextRegionOffset != 2)
        {
            ok = false;
            break;
        }
        windows = {};
        if (!SelectRegionWindows({ huge, small }, 0x4000, 2, 1, &windows) ||
            windows.Regions.size() != 1 || windows.Regions[0].Start != huge.Start + 0x4000 ||
            windows.NextRegionOffset != 3)
        {
            ok = false;
            break;
        }

        OrphanKernelPageBodyCursor addressCursor;
        windows = {};
        if (!SelectRegionWindows({ huge, small }, 0x4000, 0, 2, &windows, &addressCursor) ||
            windows.Regions.size() != 2 || windows.Regions[0].Start != huge.Start ||
            windows.Regions[1].Start != small.Start || windows.NextBodyRegionAfter != 0 ||
            windows.NextBodyWindowRound != 1)
        {
            ok = false;
            break;
        }
        addressCursor.RegionAfter = windows.NextBodyRegionAfter;
        addressCursor.WindowRound = windows.NextBodyWindowRound;
        windows = {};
        if (!SelectRegionWindows({ huge, small }, 0x4000, 0, 1, &windows, &addressCursor) ||
            windows.Regions.size() != 1 || windows.Regions[0].Start != huge.Start + 0x4000 ||
            windows.Regions[0].PhysicalAddress != 0)
        {
            ok = false;
            break;
        }
        windows = {};
        addressCursor = {};
        if (!SelectRegionWindows({ small }, 0x4000, 0, 4, &windows, &addressCursor) ||
            windows.Regions.size() != 1 || windows.RegionsTruncated ||
            windows.NextBodyRegionAfter != 0 || windows.NextBodyWindowRound != 0)
        {
            ok = false;
            break;
        }

        // The same target remains present while 64 neighbors alternate from
        // below it to above it. Index offsets 0/64 would miss it indefinitely.
        const uint64_t stableTarget = leafVa + 0x100000;
        std::vector<OrphanKernelPageRegion> before, after;
        const auto onePage = [](uint64_t start)
        {
            OrphanKernelPageRegion region;
            region.Start = start;
            region.Size = 0x1000;
            region.End = start + region.Size;
            return region;
        };
        for (uint32_t index = 0; index < 64; ++index)
        {
            before.push_back(onePage(leafVa + index * 0x2000ull));
        }
        before.push_back(onePage(stableTarget));
        after.push_back(onePage(stableTarget));
        for (uint32_t index = 0; index < 64; ++index)
        {
            after.push_back(onePage(stableTarget + (index + 1) * 0x2000ull));
        }
        OrphanKernelPageCursor changingBatch;
        const OrphanKernelPageBodyCursor changingIdentity = {leafVa, 0, 0, false};
        uint32_t targetVisits = 0;
        for (uint32_t pass = 0; pass < 8; ++pass)
        {
            addressCursor = FindBodyBatchCursor(changingBatch, changingIdentity);
            windows = {};
            if (!SelectRegionWindows((pass & 1) == 0 ? before : after,
                    0x4000, 0, 64, &windows, &addressCursor))
            {
                ok = false;
                break;
            }
            for (const OrphanKernelPageRegion& region : windows.Regions)
            {
                if (region.Start == stableTarget)
                {
                    ++targetVisits;
                }
            }
            addressCursor.RegionOffset = windows.NextRegionOffset;
            addressCursor.RegionAfter = windows.NextBodyRegionAfter;
            addressCursor.WindowRound = windows.NextBodyWindowRound;
            if (SaveBodyBatchOffset(&changingBatch, addressCursor))
            {
                ok = false;
                break;
            }
        }
        if (!ok || targetVisits < 4)
        {
            ok = false;
            break;
        }

        PhysicalTranslationInfo translation = {};
        translation.PagingLevels = 4;
        translation.PhysicalAddress = 0x1000;
        translation.Pml4e = 3;
        translation.Pdpte = 3;
        translation.Pde = 3;
        translation.Pte = 0x1003;
        bool writable = false;
        if (!ValidatePfnTranslation(translation, 0x1000, &writable) || !writable ||
            ValidatePfnTranslation(translation, 0x2000, &writable))
        {
            ok = false;
            break;
        }
        translation.Pde |= kPteNx;
        if (ValidatePfnTranslation(translation, 0x1000, &writable))
        {
            ok = false;
            break;
        }
        translation.Pde = 1;
        if (!ValidatePfnTranslation(translation, 0x1000, &writable) || writable)
        {
            ok = false;
            break;
        }
        translation.Pml4e = 0x83;
        if (ValidatePfnTranslation(translation, 0x1000, &writable))
        {
            ok = false;
            break;
        }
        translation.Pml4e = 3;
        translation.Pde = 0x201083;
        translation.PhysicalAddress = 0x200000;
        if (!ValidatePfnTranslation(translation, 0x200000, &writable) || !writable)
        {
            ok = false;
            break;
        }
        translation.Pde |= 1ull << 13;
        if (ValidatePfnTranslation(translation, 0x200000, &writable))
        {
            ok = false;
            break;
        }
        translation.Pdpte = 0x40001083;
        translation.PhysicalAddress = 0x40000000;
        if (!ValidatePfnTranslation(translation, 0x40000000, &writable) || !writable)
        {
            ok = false;
            break;
        }
        translation.Pdpte |= 1ull << 29;
        if (ValidatePfnTranslation(translation, 0x40000000, &writable))
        {
            ok = false;
            break;
        }
        translation.Pdpte = 0x40001083;
        translation.PagingLevels = 5;
        translation.Pml5e = 3;
        if (ValidatePfnTranslation(translation, 0x40000000, &writable))
        {
            ok = false;
            break;
        }
        translation.Flags = KNDBG_TRANSLATE_FLAG_LA57_ACTIVE;
        if (!ValidatePfnTranslation(translation, 0x40000000, &writable) || !writable)
        {
            ok = false;
            break;
        }
        translation.Pml5e |= 0x80;
        if (ValidatePfnTranslation(translation, 0x40000000, &writable))
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
        if (ClassifyRegion(mmioRom) != L"independent_or_system_pte" || RiskForRegion(mmioRom) != L"medium")
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
