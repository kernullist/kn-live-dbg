#include "KernelMonitor.h"

#include "LeftoverCommon.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

// Stage 3: mapper-residual and pool-residual signals.
//
// Two residual artifacts outlive a mapper or BYOVD driver, and neither was a
// verdict of its own before this layer:
//
//   * a stub body -- an allocation whose sampled bytes still carry stub thunks
//     (an import-slot indirect jmp/call, an mov reg,imm64 followed by
//     jmp/call reg, or a near-jump head thunk) whose destination is code that
//     no loaded module owns. The kernel-import stub counter the orphan-page
//     layer already runs only counts thunks that land inside
//     ntoskrnl/hal/wdf*, so a destination that no module backs was invisible;
//   * a pool-table-silent region -- the same stub body lives in a kernel
//     executable region that the big pool address view
//     (SystemBigPoolInformation, i.e. nt!PoolBigPageTable) does not cover at
//     all, which is what hiding an allocation from the pool table looks like
//     from the table side: the pages stay mapped and executable while the table
//     is silent. That silence is all the table can report, so it cannot tell an
//     allocation that was removed from the table apart from an executable
//     mapping that never was a big-pool allocation (an MDL/section/contiguous
//     mapping, a large page, or a page-table-backed window, i.e. the
//     independent_or_system_pte class). The verdict therefore states the table
//     silence, and the notes carry the region class so the two can be told
//     apart; the stub evidence itself does not depend on that split.
//
// The two verdicts are disjoint, and the table view is what separates them:
// the same stub body inside a region the table reports is mapper.stub, and
// inside a region the table does not report it is pool.hidden. A region
// that carries a PE header keeps the older unbacked_pe / orphan_page verdict,
// because the caller gates this layer on region.HasPe, so one region is never
// reported twice by two layers.
//
// Boundaries, all fail-closed:
//   * an unavailable big pool query leaves the table fact unknown, so both
//     verdicts are withheld and one scan_failed:mapperpool:table diagnostic is
//     emitted instead of a guess (released as soon as the view is back). That
//     fact is per pass, so it is settled before any region gate and the
//     diagnostic is tied to the layer being asked about a region;
//   * a body that cannot be read is a deferral, never a verdict;
//   * an empty module range set cannot separate "no loaded module owns this
//     destination" from "the owner ranges were not readable", so both verdicts
//     are withheld for that pass with one scan_failed:mapperpool:modules
//     diagnostic instead of a guess;
//   * a destination that is not a canonical kernel address, a slot whose
//     address falls outside the sampled body, and a destination inside the
//     sampled region itself are all ignored, so ordinary data bytes cannot
//     invent a stub;
//   * an mov reg,imm64 whose transfer consumes any other register is left
//     alone: the immediate is only the transfer target when that same register
//     is what the jmp or call reads, so a mismatched pair cannot report a
//     destination it does not use;
//   * absolute-target forms include matching rax..r15 transfers and an
//     optional single NOP; arbitrary intervening instructions are rejected;
//   * a near jump is decoded only at the head of the body and only when it
//     transfers to a page-aligned address: a lone 0xE9 byte occurs in ordinary
//     data far too often to be a signal on its own, so the form is held to the
//     shape a mapper's relocated head jump actually has;
//   * module-owned ranges never reach the verdict. Session candidates do not
//     infer hidden pool ownership from absence in the global big pool table.
//
// The layer shares the region snapshot the orphan-page (kpage) walk already
// produced, so it adds no second page-table walk; its only cost is one bounded
// body read per surviving candidate region.

namespace
{
    // Same canonical-address floor the kernel helpers apply: a stub transfers
    // into kernel code, so anything below it is data.
    constexpr uint64_t kKernelVaFloor = 0xFFFF800000000000ull;
    constexpr uint32_t kMaxBodyBytes = 0x4000;
    constexpr size_t kMinStubBytes = 5;
    constexpr size_t kMaxStubTargets = 32;
    constexpr size_t kMaxTargetCursorRegions = 4096;
    const wchar_t* const kLayer = L"mapper_pool";
    const wchar_t* const kTableDeferKey = L"scan_failed:mapperpool:table";
    const wchar_t* const kModuleRangeDeferKey = L"scan_failed:mapperpool:modules";

    bool AddNoOverflow(uint64_t left, uint64_t right, uint64_t* result)
    {
        if (left > (std::numeric_limits<uint64_t>::max)() - right)
        {
            return false;
        }
        *result = left + right;
        return true;
    }

    bool AddRelative32(uint64_t base, int32_t delta, uint64_t* result)
    {
        if (delta < 0)
        {
            const uint64_t distance = static_cast<uint64_t>(-static_cast<int64_t>(delta));
            if (base < distance)
            {
                return false;
            }
            *result = base - distance;
            return true;
        }
        return AddNoOverflow(base, static_cast<uint32_t>(delta), result);
    }

    std::wstring ResidualHex(uint64_t value)
    {
        wchar_t buf[32] = {};
        swprintf_s(buf, L"0x%llx", static_cast<unsigned long long>(value));
        return buf;
    }

    // ntoskrnl, hal, and the wdf* host libraries are the imports a kernel
    // payload resolves first. The predicate is repeated here (the sibling copy
    // lives in an anonymous namespace of KernelMonitor.cpp) so this decision
    // stays a pure function the self-test can drive on its own.
    bool ResidualIsKernelImportLeaf(const std::wstring& leaf)
    {
        return leaf == L"ntoskrnl.exe" ||
            leaf == L"ntkrnlmp.exe" ||
            leaf == L"hal.dll" ||
            (leaf.size() >= 3 && leaf.compare(0, 3, L"wdf") == 0);
    }

    bool ReadSampleU64(
        const uint8_t* bytes,
        size_t size,
        uint64_t regionVa,
        uint64_t slotVa,
        uint64_t* value)
    {
        if (bytes == nullptr || value == nullptr || slotVa < regionVa)
        {
            return false;
        }
        const uint64_t offset = slotVa - regionVa;
        if (offset > size || size - static_cast<size_t>(offset) < sizeof(uint64_t))
        {
            return false;
        }
        uint64_t read = 0;
        std::memcpy(&read, bytes + static_cast<size_t>(offset), sizeof(read));
        *value = read;
        return true;
    }

    // A stub transfers into kernel code: a user-mode or empty slot value is
    // data, so it is not counted as a stub at all. The caller gates on this,
    // which is what keeps ordinary pool bytes quiet.
    bool IsKernelDestination(uint64_t destination)
    {
        return destination >= kKernelVaFloor;
    }

    void NoteStubDestination(
        uint64_t destination,
        uint64_t regionVa,
        uint64_t regionEnd,
        const std::vector<KmonStubModuleRange>& modules,
        KmonMapperStubStats* stats,
        std::vector<uint64_t>* unbackedTargets)
    {
        // The caller already rejected a non-kernel destination.
        if (destination >= regionVa && destination < regionEnd)
        {
            ++stats->Internal;
            return;
        }
        for (const KmonStubModuleRange& range : modules)
        {
            if (range.Base == 0 || range.End <= range.Base)
            {
                continue;
            }
            if (destination < range.Base || destination >= range.End)
            {
                continue;
            }
            ++stats->InModule;
            if (range.KernelImport)
            {
                ++stats->KernelImport;
            }
            return;
        }
        ++stats->Unbacked;
        if (stats->FirstUnbacked == 0)
        {
            stats->FirstUnbacked = destination;
        }
        if (unbackedTargets != nullptr)
        {
            unbackedTargets->push_back(destination);
        }
    }

    using MapperTargetCursorMap = std::map<std::pair<uint64_t, uint64_t>, std::pair<uint64_t, uint64_t>>;

    struct MapperTargetProbeWindow
    {
        size_t First = 0;
        size_t Count = 0;
        bool CursorEvicted = false;
    };

    MapperTargetProbeWindow ClaimMapperTargetProbeWindow(
        MapperTargetCursorMap* cursors,
        uint64_t region,
        const std::vector<uint64_t>& destinations,
        uint64_t now,
        uint64_t cr3 = 0)
    {
        const auto key = std::make_pair(cr3, region);
        MapperTargetProbeWindow window;
        window.Count = (std::min)(destinations.size(), kMaxStubTargets);
        if (destinations.size() <= kMaxStubTargets)
        {
            cursors->erase(key);
        }
        else
        {
            auto current = cursors->find(key);
            if (current == cursors->end())
            {
                if (cursors->size() >= kMaxTargetCursorRegions)
                {
                    const auto oldest = std::min_element(
                        cursors->begin(), cursors->end(),
                        [](const auto& left, const auto& right)
                        {
                            return left.second.second < right.second.second;
                        });
                    cursors->erase(oldest);
                    window.CursorEvicted = true;
                }
                current = cursors->emplace(key, std::make_pair(0ull, now)).first;
            }
            const auto next = std::upper_bound(destinations.begin(), destinations.end(), current->second.first);
            window.First = next == destinations.end() ? 0 : static_cast<size_t>(next - destinations.begin());
            // Preserve address progress when lower targets appear or disappear.
            // The claimed window is always fully attempted by the caller.
            current->second.first = destinations[(window.First + window.Count - 1) % destinations.size()];
            current->second.second = now;
        }
        return window;
    }

    template<typename Probe>
    bool SelectExecutableStubTarget(
        const std::vector<uint64_t>& destinations,
        const MapperTargetProbeWindow& window,
        Probe& probe,
        uint64_t* verifiedTarget,
        bool* incomplete)
    {
        *verifiedTarget = 0;
        *incomplete = window.Count < destinations.size() || window.CursorEvicted;
        for (size_t index = 0; index < window.Count; ++index)
        {
            const uint64_t destination = destinations[(window.First + index) % destinations.size()];
            bool executable = false;
            if (!probe(destination, &executable))
            {
                *incomplete = true;
                continue;
            }
            if (executable && *verifiedTarget == 0)
            {
                *verifiedTarget = destination;
            }
        }
        return *verifiedTarget != 0;
    }
}

static void CountMapperStubsImpl(
    const uint8_t* bytes,
    size_t size,
    uint64_t regionVa,
    const std::vector<KmonStubModuleRange>& modules,
    KmonMapperStubStats* stats,
    std::vector<uint64_t>* unbackedTargets)
{
    if (stats == nullptr)
    {
        return;
    }
    *stats = KmonMapperStubStats();
    if (unbackedTargets != nullptr)
    {
        unbackedTargets->clear();
    }
    if (bytes == nullptr || size < kMinStubBytes || regionVa < kKernelVaFloor)
    {
        return;
    }

    uint64_t regionEnd = regionVa;
    if (!AddNoOverflow(regionVa, static_cast<uint64_t>(size), &regionEnd))
    {
        return;
    }

    for (size_t i = 0; i + 2 <= size; ++i)
    {
        const uint8_t first = bytes[i];
        const uint8_t second = bytes[i + 1];

        // jmp/call qword ptr [rip+disp32]: the destination is the slot value,
        // so the slot must sit inside the sampled body to be readable at all.
        if (first == 0xFF && (second == 0x25 || second == 0x15) && size - i >= 6)
        {
            int32_t disp = 0;
            std::memcpy(&disp, bytes + i + 2, sizeof(disp));
            uint64_t instructionEnd = 0;
            if (!AddNoOverflow(regionVa, static_cast<uint64_t>(i) + 6ull, &instructionEnd))
            {
                continue;
            }
            uint64_t slotVa = 0;
            uint64_t destination = 0;
            if (!AddRelative32(instructionEnd, disp, &slotVa) ||
                !ReadSampleU64(bytes, size, regionVa, slotVa, &destination) ||
                !IsKernelDestination(destination))
            {
                continue;
            }
            ++stats->Slots;
            NoteStubDestination(destination, regionVa, regionEnd, modules, stats, unbackedTargets);
            i += 5;
            continue;
        }

        // mov reg,imm64 (REX.W, rax..r15) whose immediate is consumed by a
        // following jmp/call of the same register, optionally after a NOP: the
        // absolute-target thunk mappers use when they resolve imports without
        // an image import table. The transfer has to name the register the load
        // wrote, because only then is the immediate what control flow reads; a
        // jump through any other register has no statically known destination,
        // so reporting this immediate as its target would be a false one.
        if ((first == 0x48 || first == 0x49) &&
            second >= 0xB8 && second <= 0xBF && size - i >= 12)
        {
            uint64_t destination = 0;
            std::memcpy(&destination, bytes + i + 2, sizeof(destination));
            if (!IsKernelDestination(destination))
            {
                continue;
            }
            const uint8_t loadedRegister = static_cast<uint8_t>(
                (second - 0xB8) + ((first & 1) != 0 ? 8 : 0));
            size_t transfer = i + 10;
            if (bytes[transfer] == 0x90)
            {
                ++transfer;
            }
            uint8_t transferExtension = 0;
            if (transfer < size && bytes[transfer] >= 0x40 && bytes[transfer] <= 0x4F)
            {
                transferExtension = (bytes[transfer] & 1) != 0 ? 8 : 0;
                ++transfer;
            }
            if (transfer + 2 > size || bytes[transfer] != 0xFF ||
                ((bytes[transfer + 1] & 0xF8) != 0xE0 &&
                 (bytes[transfer + 1] & 0xF8) != 0xD0))
            {
                continue;
            }
            const uint8_t targetRegister = static_cast<uint8_t>(
                (bytes[transfer + 1] & 7) + transferExtension);
            if (targetRegister != loadedRegister)
            {
                continue;
            }
            ++stats->Slots;
            NoteStubDestination(destination, regionVa, regionEnd, modules, stats, unbackedTargets);
            i = transfer + 1;
            continue;
        }

        // jmp rel32 (E9): a near-jump head thunk, the form a mapper uses when
        // the payload it jumps to sits inside +/-2GB. Only the head of the body
        // counts and only a page-aligned destination does, because a single
        // 0xE9 byte is ordinary data far too often for the opcode alone to mean
        // anything: a relocation stub transfers to a mapped image base, which
        // is page-aligned, while a data byte would land anywhere.
        if (first == 0xE9 && i == 0 && i + 5 <= size)
        {
            int32_t rel = 0;
            std::memcpy(&rel, bytes + i + 1, sizeof(rel));
            uint64_t instructionEnd = 0;
            if (!AddNoOverflow(regionVa, static_cast<uint64_t>(i) + 5ull, &instructionEnd))
            {
                continue;
            }
            uint64_t destination = 0;
            if (!AddRelative32(instructionEnd, rel, &destination) ||
                !IsKernelDestination(destination) || (destination & 0xFFFull) != 0)
            {
                continue;
            }
            ++stats->Slots;
            ++stats->NearJumps;
            NoteStubDestination(destination, regionVa, regionEnd, modules, stats, unbackedTargets);
            i += 4;
            continue;
        }
    }
    if (unbackedTargets != nullptr)
    {
        std::sort(unbackedTargets->begin(), unbackedTargets->end());
        unbackedTargets->erase(
            std::unique(unbackedTargets->begin(), unbackedTargets->end()),
            unbackedTargets->end());
    }
}

void KmonCountMapperStubs(
    const uint8_t* bytes,
    size_t size,
    uint64_t regionVa,
    const std::vector<KmonStubModuleRange>& modules,
    KmonMapperStubStats* stats)
{
    CountMapperStubsImpl(bytes, size, regionVa, modules, stats, nullptr);
}

KmonResidualSignalKind KmonClassifyResidualSignal(const KmonResidualSignalInput& input)
{
    // Every missing fact is a deferral: an incomplete page-walk record, an
    // unreadable body, an unavailable big pool view, a region that is not
    // executable, and a module-owned range all withhold the
    // verdict instead of guessing.
    if (!input.RegionKnown ||
        !input.Executable ||
        input.InLoadedModule ||
        !input.TableViewKnown ||
        !input.BodyReadKnown ||
        !input.ModuleViewKnown)
    {
        return KmonResidualSignalKind::None;
    }
    // Without a stub that transfers to code no module owns there is nothing to
    // report; this is the boundary that keeps ordinary pool code quiet.
    if (input.UnbackedStubs == 0)
    {
        return KmonResidualSignalKind::None;
    }
    return input.InBigPoolTable || input.SessionSpace
        ? KmonResidualSignalKind::MapperStub
        : KmonResidualSignalKind::PoolHidden;
}

const wchar_t* KmonResidualSignalKindName(KmonResidualSignalKind kind)
{
    switch (kind)
    {
    case KmonResidualSignalKind::PoolHidden:
        return L"pool.hidden";
    case KmonResidualSignalKind::MapperStub:
        return L"mapper.stub";
    case KmonResidualSignalKind::None:
    default:
        return L"";
    }
}

bool KernelMonitor::EmitMapperPoolResidual(
    DeviceClient* device,
    SymbolEngine* symbols,
    const std::vector<KernelModuleInfo>& modules,
    const OrphanKernelPageRegion& region,
    bool tableViewKnown)
{
    if (device == nullptr)
    {
        return false;
    }
    // The big pool table view is a per-pass fact and it is the fact the two
    // verdicts are separated by, so it is settled before any region gate: an
    // unavailable view withholds both verdicts and reports itself once per
    // layer until the view is back. The diagnostic is tied to the layer being
    // asked about a region, so a pass with no candidate region stays quiet
    // about this layer rather than about the table.
    if (!tableViewKnown)
    {
        EmitUnique(
            L"driver.mapped_residue",
            kTableDeferKey,
            std::wstring(),
            kLayer,
            L"mapper/pool residual verdict deferred; the big pool table view is unavailable",
            L"BigPoolQueried is false");
        return false;
    }
    ClearEmittedKey(kTableDeferKey);

    // A region that carries a PE header is already reported as unbacked_pe or
    // orphan_page; this layer never doubles that verdict.
    if (region.HasPe)
    {
        return false;
    }
    if (!region.Executable)
    {
        return false;
    }

    const uint32_t bodyBytes = region.Size > kMaxBodyBytes
        ? kMaxBodyBytes
        : static_cast<uint32_t>(region.Size);
    // The module ranges decide whether a stub destination is backed by an
    // image, so an empty range list cannot back the verdict: every destination
    // would look unbacked. That is the same deferral the kernel-thread and
    // inline-patch layers take on an empty inventory, and it is settled before
    // the body read so an unreadable inventory is never reported as a stub.
    std::vector<KmonStubModuleRange> ranges;
    ranges.reserve(modules.size());
    bool moduleRangesComplete = !modules.empty();
    for (const KernelModuleInfo& module : modules)
    {
        if (module.Base < kKernelVaFloor || module.Size == 0)
        {
            moduleRangesComplete = false;
            continue;
        }
        KmonStubModuleRange range;
        range.Base = module.Base;
        if (!AddNoOverflow(module.Base, module.Size, &range.End))
        {
            moduleRangesComplete = false;
            continue;
        }
        const std::wstring leaf = KmonBasenameLower(
            module.ImageName.empty() ? module.ImagePath : module.ImageName);
        range.KernelImport = ResidualIsKernelImportLeaf(leaf);
        ranges.push_back(range);
    }
    if (!moduleRangesComplete || ranges.empty() || !KmonKernelModuleRangesKnown(modules))
    {
        EmitUnique(
            L"driver.mapped_residue",
            kModuleRangeDeferKey,
            std::wstring(),
            kLayer,
            L"mapper/pool residual verdict deferred; kernel module ranges are incomplete",
            L"the stub destination check requires every loaded module range");
        return false;
    }
    ClearEmittedKey(kModuleRangeDeferKey);

    bool bodyKnown = false;
    bool bodyComplete = false;
    size_t bodyReadBytes = 0;
    KmonMapperStubStats stats = {};
    std::vector<uint64_t> unbackedTargets;
    if (bodyBytes >= kMinStubBytes)
    {
        std::vector<uint8_t> body;
        std::wstring ignored;
        const bool bodyRead = ReadOrphanRootMemory(*device, region.Cr3, region.Start, bodyBytes, &body, &ignored, true);
        bodyReadBytes = body.size();
        bodyComplete = bodyRead && body.size() == bodyBytes;
        if (bodyRead && body.size() >= kMinStubBytes)
        {
            CountMapperStubsImpl(body.data(), body.size(), region.Start, ranges, &stats, &unbackedTargets);
            bodyKnown = true;
        }
    }
    const std::wstring rootKey = ResidualHex(region.Cr3) + L":" +
        std::to_wstring(region.RootProcessId) + L":" + std::to_wstring(region.RootCreateTime) + L":";
    const std::wstring bodyDeferKey = L"scan_failed:mapperpool:body:" + rootKey + ResidualHex(region.Start);
    if (!bodyComplete)
    {
        EmitUnique(
            L"driver.mapped_residue",
            bodyDeferKey,
            std::wstring(),
            kLayer,
            L"mapper/pool body coverage is partial; the complete sample was unreadable",
            L"sample=" + ResidualHex(region.Start) + L" requested=" + std::to_wstring(bodyBytes) +
                L" readable=" + std::to_wstring(bodyReadBytes));
    }
    else
    {
        ClearEmittedKey(bodyDeferKey);
    }
    if (!bodyKnown)
    {
        return false;
    }

    MapperTargetProbeWindow targetWindow;
    size_t cursorCount = 0;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        // Every claimed slot is attempted below, including unreadable targets.
        // Small or clean samples no longer need continuation state.
        targetWindow = ClaimMapperTargetProbeWindow(
            &MapperTargetCursors, region.Start, unbackedTargets, GetTickCount64(), region.Cr3);
        cursorCount = MapperTargetCursors.size();
    }
    const std::wstring cursorDeferKey = L"scan_failed:mapperpool:target_cursor_capacity";
    if (targetWindow.CursorEvicted)
    {
        EmitUnique(L"driver.mapped_residue", cursorDeferKey, std::wstring(), kLayer,
            L"mapper target continuation cache reached its capacity; oldest continuation was evicted",
            L"capacity=" + std::to_wstring(kMaxTargetCursorRegions) +
                L"; repeated scans cannot promise progress for evicted regions");
    }
    else if (cursorCount < kMaxTargetCursorRegions)
    {
        ClearEmittedKey(cursorDeferKey);
    }
    const std::wstring targetDeferKey = L"scan_failed:mapperpool:targets:" + rootKey + ResidualHex(region.Start);
    if (stats.Unbacked != 0)
    {
        auto probe = [&](uint64_t address, bool* executable)
        {
            return ProbeOrphanRootExecutable(*device, region.Cr3, address, executable);
        };
        uint64_t verifiedTarget = 0;
        bool incomplete = false;
        const bool verified = SelectExecutableStubTarget(
            unbackedTargets, targetWindow, probe, &verifiedTarget, &incomplete);
        if (incomplete)
        {
            EmitUnique(L"driver.mapped_residue", targetDeferKey, std::wstring(), kLayer,
                L"mapper/pool target validation was incomplete; deferred targets rotate on later visits",
                L"sample=" + ResidualHex(region.Start) + L" target_limit=" + std::to_wstring(kMaxStubTargets) +
                    L" targets=" + std::to_wstring(unbackedTargets.size()) +
                    L" first_target=" + std::to_wstring(targetWindow.First) +
                    L" cursor_evicted=" + std::to_wstring(targetWindow.CursorEvicted ? 1 : 0));
        }
        else
        {
            ClearEmittedKey(targetDeferKey);
        }
        if (!verified)
        {
            return false;
        }
        stats.FirstUnbacked = verifiedTarget;
    }
    else
    {
        ClearEmittedKey(targetDeferKey);
    }

    KmonResidualSignalInput input;
    input.RegionKnown = region.Size != 0;
    input.Executable = region.Executable;
    input.SessionSpace = region.SessionSpace;
    // The caller filters module-owned regions before this layer runs, so the
    // fact is already solved; it is passed as false rather than re-derived to
    // keep one definition of "owned by a loaded module".
    input.InLoadedModule = false;
    input.TableViewKnown = tableViewKnown;
    input.InBigPoolTable = region.InBigPool;
    input.BodyReadKnown = bodyKnown;
    // The range set is non-empty here, because an empty one deferred above, so
    // the "no loaded module owns this destination" claim has a usable view.
    input.ModuleViewKnown = true;
    input.MapperStubs = stats.Slots;
    input.UnbackedStubs = stats.Unbacked;

    const KmonResidualSignalKind kind = KmonClassifyResidualSignal(input);
    if (kind == KmonResidualSignalKind::None)
    {
        return false;
    }

    std::wstring notes = std::wstring(L"table=") +
        (region.InBigPool ? L"visible" : L"silent") +
        L" stub_slots=" + std::to_wstring(stats.Slots) +
        L" near_jumps=" + std::to_wstring(stats.NearJumps) +
        L" in_module=" + std::to_wstring(stats.InModule) +
        L" kernel_import=" + std::to_wstring(stats.KernelImport) +
        L" internal=" + std::to_wstring(stats.Internal) +
        L" unbacked=" + std::to_wstring(stats.Unbacked) +
        L" first_unbacked=" + ResidualHex(stats.FirstUnbacked) +
        L" first_unbacked_execute_verified=true" +
        L" class=" + region.Classification +
        L" size=" + ResidualHex(region.Size) + L" cr3=" + ResidualHex(region.Cr3) +
        L" root_pid=" + std::to_wstring(region.RootProcessId) +
        L" root_created=" + std::to_wstring(region.RootCreateTime);
    if (region.SessionSpace)
    {
        notes += L" session=true pool_absence_not_inferred=true";
    }
    if (region.Writable && region.Executable)
    {
        notes += L" wx=true";
    }
    if (region.PoolTag != 0)
    {
        notes += L" tag=" + LeftoverFormatTag(region.PoolTag);
    }
    if (region.PhysicalAddress != 0)
    {
        notes += L" pfn=" + std::to_wstring(region.PhysicalAddress >> 12);
    }

    const bool hidden = kind == KmonResidualSignalKind::PoolHidden;
    const wchar_t* captureLayer = hidden ? L"pool_hidden" : L"mapper_stub";
    std::wstring captureNote;
    CaptureRegion(
        captureLayer,
        region.Start,
        region.Size,
        region.RootProcessId,
        false,
        device,
        symbols,
        nullptr,
        2ull * 1024ull * 1024ull,
        &captureNote,
        region.Cr3,
        region.RootCreateTime);
    NoteMapperWatchResidue(captureLayer, region.PhysicalAddress);

    return EmitUnique(
        KmonResidualSignalKindName(kind),
        (hidden ? L"poolhidden:" : L"mapperstub:") + rootKey + ResidualHex(region.Start),
        region.Classification,
        kLayer,
        std::wstring(hidden
            ? L"executable region the big pool table view does not report, holding a stub body whose destination no loaded module owns "
            : L"stub body transferring to code outside the observed module ranges ") +
            ResidualHex(region.Start),
        notes + captureNote);
}

bool KernelMonitorMapperPoolSelfTest()
{
    bool ok = false;

    do
    {
        const uint64_t regionVa = 0xFFFFF88000010000ull;
        const uint64_t moduleBase = 0xFFFFF80200000000ull;
        const uint64_t moduleEnd = 0xFFFFF80200100000ull;
        const uint64_t kernelImportBase = 0xFFFFF80000000000ull;
        const uint64_t kernelImportEnd = 0xFFFFF80008000000ull;
        const uint64_t unbackedTarget = 0xFFFFF88000A00000ull;

        MapperTargetCursorMap rootCursors;
        std::vector<uint64_t> rootTargets;
        for (uint64_t index = 0; index < 70; ++index)
        {
            rootTargets.push_back(unbackedTarget + index * 0x1000);
        }
        const MapperTargetProbeWindow rootA = ClaimMapperTargetProbeWindow(&rootCursors, regionVa, rootTargets, 1, 0x1000);
        const MapperTargetProbeWindow rootB = ClaimMapperTargetProbeWindow(&rootCursors, regionVa, rootTargets, 2, 0x2000);
        const MapperTargetProbeWindow rootASecond = ClaimMapperTargetProbeWindow(&rootCursors, regionVa, rootTargets, 3, 0x1000);
        if (rootA.First != 0 || rootB.First != 0 || rootASecond.First != 32 || rootCursors.size() != 2)
        {
            break;
        }

        std::vector<KmonStubModuleRange> modules;
        KmonStubModuleRange owned;
        owned.Base = moduleBase;
        owned.End = moduleEnd;
        owned.KernelImport = false;
        modules.push_back(owned);
        KmonStubModuleRange import;
        import.Base = kernelImportBase;
        import.End = kernelImportEnd;
        import.KernelImport = true;
        modules.push_back(import);

        KmonMapperStubStats stats = {};

        // An import-slot thunk (jmp qword ptr [rip+disp32]) whose slot sits at
        // the end of the body resolves to the slot value.
        uint8_t slotStub[32] = {};
        slotStub[0] = 0xFF;
        slotStub[1] = 0x25;
        const int32_t slotDisp = static_cast<int32_t>(0x14 - 6);
        std::memcpy(slotStub + 2, &slotDisp, sizeof(slotDisp));
        std::memcpy(slotStub + 0x14, &moduleBase, sizeof(moduleBase));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.InModule != 1 || stats.Unbacked != 0 ||
            stats.Internal != 0)
        {
            break;
        }

        // The same thunk resolving into a kernel import module is what the
        // older kernel-import counter reports; it is not this layer's verdict.
        std::memcpy(slotStub + 0x14, &kernelImportBase, sizeof(kernelImportBase));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.KernelImport != 1 || stats.Unbacked != 0)
        {
            break;
        }

        // A slot value no module owns is the mapper stub target.
        std::memcpy(slotStub + 0x14, &unbackedTarget, sizeof(unbackedTarget));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Unbacked != 1 || stats.InModule != 0 ||
            stats.FirstUnbacked != unbackedTarget)
        {
            break;
        }

        // A slot value inside the sampled region itself is an internal jump,
        // not a stub transfer.
        const uint64_t internalTarget = regionVa + 0x18;
        std::memcpy(slotStub + 0x14, &internalTarget, sizeof(internalTarget));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Internal != 1 || stats.Unbacked != 0)
        {
            break;
        }

        // mov reg,imm64 followed by jmp reg carries its own absolute target.
        uint8_t absoluteStub[16] = {};
        absoluteStub[0] = 0x48;
        absoluteStub[1] = 0xB8;
        std::memcpy(absoluteStub + 2, &unbackedTarget, sizeof(unbackedTarget));
        absoluteStub[10] = 0xFF;
        absoluteStub[11] = 0xE0;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(absoluteStub, sizeof(absoluteStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Unbacked != 1 ||
            stats.FirstUnbacked != unbackedTarget)
        {
            break;
        }

        // REX.B extends both the load and the consuming transfer register.
        bool extendedGood = true;
        for (uint8_t reg = 8; reg < 16; ++reg)
        {
            uint8_t extended[13] = {};
            extended[0] = 0x49;
            extended[1] = static_cast<uint8_t>(0xB8 + (reg & 7));
            std::memcpy(extended + 2, &unbackedTarget, sizeof(unbackedTarget));
            extended[10] = 0x41;
            extended[11] = 0xFF;
            extended[12] = static_cast<uint8_t>(0xD0 + (reg & 7));
            KmonCountMapperStubs(extended, sizeof(extended), regionVa, modules, &stats);
            if (stats.Slots != 1 || stats.Unbacked != 1)
            {
                extendedGood = false;
                break;
            }
            extended[12] = static_cast<uint8_t>(0xE0 + (reg & 7));
            KmonCountMapperStubs(extended, sizeof(extended), regionVa, modules, &stats);
            if (stats.Slots != 1 || stats.Unbacked != 1)
            {
                extendedGood = false;
                break;
            }
            extended[10] = 0x40;
            KmonCountMapperStubs(extended, sizeof(extended), regionVa, modules, &stats);
            if (stats.Slots != 0)
            {
                extendedGood = false;
                break;
            }
        }
        if (!extendedGood)
        {
            break;
        }
        KmonCountMapperStubs(absoluteStub, 12, regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Unbacked != 1)
        {
            break;
        }
        uint8_t separated[13] = {};
        std::memcpy(separated, absoluteStub, 10);
        separated[10] = 0x90;
        separated[11] = 0xFF;
        separated[12] = 0xE0;
        KmonCountMapperStubs(separated, sizeof(separated), regionVa, modules, &stats);
        if (stats.Slots != 1)
        {
            break;
        }
        separated[10] = 0xCC;
        KmonCountMapperStubs(separated, sizeof(separated), regionVa, modules, &stats);
        if (stats.Slots != 0)
        {
            break;
        }
        KmonCountMapperStubs(absoluteStub, sizeof(absoluteStub), ~0ull - 7, modules, &stats);
        if (stats.Slots != 0)
        {
            break;
        }

        uint8_t multipleTargets[32] = {};
        std::memcpy(multipleTargets, absoluteStub, 12);
        std::memcpy(multipleTargets + 16, absoluteStub, 12);
        const uint64_t laterTarget = unbackedTarget + 0x1000;
        std::memcpy(multipleTargets + 18, &laterTarget, sizeof(laterTarget));
        std::vector<uint64_t> unbackedTargets;
        CountMapperStubsImpl(multipleTargets, sizeof(multipleTargets), regionVa, modules,
            &stats, &unbackedTargets);
        if (unbackedTargets.size() != 2 || unbackedTargets[0] != unbackedTarget ||
            unbackedTargets[1] != laterTarget)
        {
            break;
        }
        auto nxThenExecute = [&](uint64_t address, bool* executable)
        {
            *executable = address == laterTarget;
            return true;
        };
        uint64_t verifiedTarget = 0;
        bool incomplete = false;
        MapperTargetCursorMap targetCursors;
        MapperTargetProbeWindow targetWindow = ClaimMapperTargetProbeWindow(
            &targetCursors, regionVa, unbackedTargets, 1);
        if (!SelectExecutableStubTarget(
                unbackedTargets, targetWindow, nxThenExecute, &verifiedTarget, &incomplete) ||
            verifiedTarget != laterTarget || incomplete)
        {
            break;
        }
        auto unreadableThenExecute = [&](uint64_t address, bool* executable)
        {
            *executable = address == laterTarget;
            return address == laterTarget;
        };
        if (!SelectExecutableStubTarget(
                unbackedTargets, targetWindow, unreadableThenExecute, &verifiedTarget, &incomplete) ||
            verifiedTarget != laterTarget || !incomplete)
        {
            break;
        }

        // Reverse ordering and a duplicate must still retain all 33 distinct
        // destinations. Only the 33rd sorted target is executable.
        std::vector<uint8_t> manyStubs(34 * 16, 0);
        for (size_t index = 0; index < 34; ++index)
        {
            const uint64_t destination = unbackedTarget +
                (index < 33 ? 32 - index : 32) * 0x1000;
            std::memcpy(manyStubs.data() + index * 16, absoluteStub, 12);
            std::memcpy(manyStubs.data() + index * 16 + 2, &destination, sizeof(destination));
        }
        CountMapperStubsImpl(manyStubs.data(), manyStubs.size(), regionVa, modules,
            &stats, &unbackedTargets);
        if (stats.Unbacked != 34 || unbackedTargets.size() != 33 ||
            unbackedTargets.front() != unbackedTarget ||
            unbackedTargets.back() != unbackedTarget + 32 * 0x1000)
        {
            break;
        }
        size_t targetProbes = 0;
        auto onlyLastExecutable = [&](uint64_t address, bool* executable)
        {
            ++targetProbes;
            *executable = address == unbackedTargets.back();
            return true;
        };
        targetWindow = ClaimMapperTargetProbeWindow(
            &targetCursors, regionVa, unbackedTargets, 2);
        if (targetWindow.First != 0 || targetWindow.Count != 32 ||
            SelectExecutableStubTarget(
                unbackedTargets, targetWindow, onlyLastExecutable, &verifiedTarget, &incomplete) ||
            targetProbes != 32 || !incomplete)
        {
            break;
        }
        targetProbes = 0;
        targetWindow = ClaimMapperTargetProbeWindow(
            &targetCursors, regionVa, unbackedTargets, 3);
        if (targetWindow.First != 32 ||
            !SelectExecutableStubTarget(
                unbackedTargets, targetWindow, onlyLastExecutable, &verifiedTarget, &incomplete) ||
            verifiedTarget != unbackedTargets.back() || targetProbes != 32 || !incomplete)
        {
            break;
        }

        // If every address after the anchor disappears, wrap to the new head.
        targetCursors.clear();
        ClaimMapperTargetProbeWindow(&targetCursors, regionVa, rootTargets, 4);
        ClaimMapperTargetProbeWindow(&targetCursors, regionVa, rootTargets, 5);
        targetWindow = ClaimMapperTargetProbeWindow(&targetCursors, regionVa, unbackedTargets, 6);
        targetProbes = 0;
        if (targetWindow.First != 0 || targetWindow.Count != 32 ||
            SelectExecutableStubTarget(
                unbackedTargets, targetWindow, onlyLastExecutable, &verifiedTarget, &incomplete) ||
            targetProbes != 32 || !incomplete)
        {
            break;
        }

        // A stable executable destination alternates between sorted indices
        // 32 and 0 as its neighbors change. Numeric 0/32 cursors miss it forever.
        MapperTargetCursorMap changingCursors;
        const uint64_t stableTarget = unbackedTarget + 0x400000;
        uint32_t stableVisits = 0;
        bool changingValid = true;
        for (uint32_t pass = 0; pass < 8; ++pass)
        {
            std::vector<uint64_t> addresses;
            if ((pass & 1) == 0)
            {
                for (uint64_t index = 0; index < 32; ++index)
                {
                    addresses.push_back(unbackedTarget + index * 0x1000);
                }
            }
            addresses.push_back(stableTarget);
            while (addresses.size() < 64)
            {
                addresses.push_back(stableTarget + (addresses.size() - ((pass & 1) == 0 ? 32 : 0)) * 0x1000);
            }
            std::vector<uint8_t> changingStubs(addresses.size() * 16, 0);
            for (size_t index = 0; index < addresses.size(); ++index)
            {
                std::memcpy(changingStubs.data() + index * 16, absoluteStub, 12);
                std::memcpy(changingStubs.data() + index * 16 + 2, &addresses[index], sizeof(uint64_t));
            }
            std::vector<uint64_t> changingTargets;
            CountMapperStubsImpl(changingStubs.data(), changingStubs.size(), regionVa, modules,
                &stats, &changingTargets);
            if (changingTargets != addresses)
            {
                changingValid = false;
                break;
            }
            const MapperTargetProbeWindow changingWindow = ClaimMapperTargetProbeWindow(
                &changingCursors, regionVa, changingTargets, pass);
            size_t changingProbes = 0;
            auto stableOnly = [&](uint64_t address, bool* executable)
            {
                ++changingProbes;
                *executable = address == stableTarget;
                return true;
            };
            if (SelectExecutableStubTarget(changingTargets, changingWindow, stableOnly, &verifiedTarget, &incomplete))
            {
                ++stableVisits;
                if (verifiedTarget != stableTarget)
                {
                    changingValid = false;
                }
            }
            if (changingProbes != 32 || !incomplete)
            {
                changingValid = false;
            }
        }
        if (!changingValid || stableVisits < 4)
        {
            break;
        }

        // Exactly 32 readable NX targets are complete negative evidence.
        unbackedTargets.resize(32);
        targetWindow = ClaimMapperTargetProbeWindow(
            &targetCursors, regionVa, unbackedTargets, 7);
        targetProbes = 0;
        auto allNx = [&](uint64_t, bool* executable)
        {
            ++targetProbes;
            *executable = false;
            return true;
        };
        if (!targetCursors.empty() || targetWindow.First != 0 || targetWindow.Count != 32 ||
            SelectExecutableStubTarget(unbackedTargets, targetWindow, allNx, &verifiedTarget, &incomplete) ||
            targetProbes != 32 || incomplete || verifiedTarget != 0)
        {
            break;
        }
        targetProbes = 0;
        if (!SelectExecutableStubTarget(
                unbackedTargets, targetWindow, onlyLastExecutable, &verifiedTarget, &incomplete) ||
            targetProbes != 32 || incomplete || verifiedTarget != unbackedTargets.back())
        {
            break;
        }
        auto allUnreadable = [&](uint64_t, bool* executable)
        {
            *executable = false;
            return false;
        };
        if (SelectExecutableStubTarget(
                unbackedTargets, targetWindow, allUnreadable, &verifiedTarget, &incomplete) ||
            !incomplete)
        {
            break;
        }

        // Keep the cache bounded, retain recently used regions, and expose
        // eviction rather than promising progress for forgotten regions.
        for (size_t index = 0; index < kMaxTargetCursorRegions; ++index)
        {
            targetCursors.emplace(std::make_pair(0ull, regionVa + index * 0x1000),
                std::make_pair(0ull, static_cast<uint64_t>(index)));
        }
        ClaimMapperTargetProbeWindow(&targetCursors, regionVa, rootTargets, kMaxTargetCursorRegions);
        targetWindow = ClaimMapperTargetProbeWindow(&targetCursors,
            regionVa + kMaxTargetCursorRegions * 0x1000, rootTargets, kMaxTargetCursorRegions + 1);
        if (!targetWindow.CursorEvicted || targetCursors.size() != kMaxTargetCursorRegions ||
            targetCursors.find(std::make_pair(0ull, regionVa)) == targetCursors.end() ||
            targetCursors.find(std::make_pair(0ull, regionVa + 0x1000)) != targetCursors.end())
        {
            break;
        }
        unbackedTargets.clear();
        targetWindow = ClaimMapperTargetProbeWindow(&targetCursors, regionVa, unbackedTargets, kMaxTargetCursorRegions + 2);
        targetProbes = 0;
        if (targetCursors.find(std::make_pair(0ull, regionVa)) != targetCursors.end() ||
            SelectExecutableStubTarget(
                unbackedTargets, targetWindow, onlyLastExecutable, &verifiedTarget, &incomplete) ||
            targetProbes != 0 || incomplete)
        {
            break;
        }

        // The same thunk through another register of the decoded set is the same
        // stub: the load is what the transfer consumes, so the immediate is the
        // target for `mov rcx,imm64; jmp rcx` and for `mov rdi,imm64; jmp rdi`.
        uint8_t otherRegisterStub[16] = {};
        otherRegisterStub[0] = 0x48;
        otherRegisterStub[1] = 0xB9;
        std::memcpy(otherRegisterStub + 2, &unbackedTarget, sizeof(unbackedTarget));
        otherRegisterStub[10] = 0xFF;
        otherRegisterStub[11] = 0xE1;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(
            otherRegisterStub, sizeof(otherRegisterStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Unbacked != 1 ||
            stats.FirstUnbacked != unbackedTarget)
        {
            break;
        }
        otherRegisterStub[1] = 0xBF;
        std::memcpy(otherRegisterStub + 2, &unbackedTarget, sizeof(unbackedTarget));
        otherRegisterStub[10] = 0xFF;
        otherRegisterStub[11] = 0xE7;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(
            otherRegisterStub, sizeof(otherRegisterStub), regionVa, modules, &stats);
        if (stats.Slots != 1 || stats.Unbacked != 1 ||
            stats.FirstUnbacked != unbackedTarget)
        {
            break;
        }

        // A transfer through a register the load did not write has no statically
        // known destination, so this immediate must not be reported as its
        // target: the thunk is not a stub of this layer.
        uint8_t mismatchedStub[16] = {};
        mismatchedStub[0] = 0x48;
        mismatchedStub[1] = 0xB9;
        std::memcpy(mismatchedStub + 2, &unbackedTarget, sizeof(unbackedTarget));
        mismatchedStub[10] = 0xFF;
        mismatchedStub[11] = 0xE0;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(
            mismatchedStub, sizeof(mismatchedStub), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }
        mismatchedStub[1] = 0xBF;
        mismatchedStub[10] = 0xFF;
        mismatchedStub[11] = 0xD0;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(
            mismatchedStub, sizeof(mismatchedStub), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }

        // The same load without the transfer is a plain constant: no stub.
        absoluteStub[10] = 0x90;
        absoluteStub[11] = 0x90;
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(absoluteStub, sizeof(absoluteStub), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }

        // Non-canonical and empty destinations never count: a user-mode value
        // in a slot is data, so ordinary pool bytes cannot invent a stub.
        const uint64_t userTarget = 0x0000000100000000ull;
        std::memcpy(slotStub + 0x14, &userTarget, sizeof(userTarget));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }
        std::memcpy(slotStub + 0x14, "\0\0\0\0\0\0\0\0", 8);
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(slotStub, sizeof(slotStub), regionVa, modules, &stats);
        if (stats.Slots != 0)
        {
            break;
        }

        // A slot outside the sampled body cannot be read, so the thunk is not
        // counted at all: an unreadable slot is a deferral, not a verdict.
        uint8_t farSlot[24] = {};
        farSlot[0] = 0xFF;
        farSlot[1] = 0x25;
        const int32_t farDisp = static_cast<int32_t>(0x400 - 6);
        std::memcpy(farSlot + 2, &farDisp, sizeof(farDisp));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(farSlot, sizeof(farSlot), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }

        // A near-jump head thunk (E9 rel32) carries its destination in the
        // instruction itself. It counts only at the head of the body and only
        // when the destination is page-aligned, because a lone 0xE9 byte is
        // ordinary data far too often to be a signal on its own. The module
        // below is reachable from this region with a 32-bit displacement.
        KmonStubModuleRange nearby;
        nearby.Base = 0xFFFFF88002000000ull;
        nearby.End = 0xFFFFF88002100000ull;
        nearby.KernelImport = false;
        modules.push_back(nearby);

        const uint64_t nearTarget = 0xFFFFF88001000000ull;
        uint8_t nearJump[24] = {};
        nearJump[0] = 0xE9;
        int32_t nearRel = static_cast<int32_t>(nearTarget - (regionVa + 5));
        std::memcpy(nearJump + 1, &nearRel, sizeof(nearRel));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(nearJump, sizeof(nearJump), regionVa, modules, &stats);
        if (stats.NearJumps != 1 || stats.Slots != 1 || stats.Unbacked != 1 ||
            stats.Internal != 0 || stats.FirstUnbacked != nearTarget)
        {
            break;
        }

        // The same jump into a module the region can reach is not an unbacked
        // transfer.
        nearRel = static_cast<int32_t>(nearby.Base - (regionVa + 5));
        std::memcpy(nearJump + 1, &nearRel, sizeof(nearRel));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(nearJump, sizeof(nearJump), regionVa, modules, &stats);
        if (stats.NearJumps != 1 || stats.InModule != 1 || stats.Unbacked != 0)
        {
            break;
        }

        // A near jump back into the sampled region itself is an internal jump.
        nearRel = static_cast<int32_t>(regionVa - (regionVa + 5));
        std::memcpy(nearJump + 1, &nearRel, sizeof(nearRel));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(nearJump, sizeof(nearJump), regionVa, modules, &stats);
        if (stats.NearJumps != 1 || stats.Internal != 1 || stats.Unbacked != 0)
        {
            break;
        }

        // Off the head of the body the same byte sequence is data, not a thunk.
        uint8_t offsetJump[24] = {};
        offsetJump[0] = 0x90;
        offsetJump[1] = 0x90;
        offsetJump[2] = 0xE9;
        const int32_t offsetRel = static_cast<int32_t>(nearTarget - (regionVa + 5 + 2));
        std::memcpy(offsetJump + 3, &offsetRel, sizeof(offsetRel));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(offsetJump, sizeof(offsetJump), regionVa, modules, &stats);
        if (stats.NearJumps != 0 || stats.Slots != 0)
        {
            break;
        }

        // A destination that is not page-aligned is not the mapped image base a
        // relocation stub hands control to, so the form stays quiet.
        uint8_t misalignedJump[24] = {};
        misalignedJump[0] = 0xE9;
        const uint64_t misalignedTarget = nearTarget + 0x800ull;
        const int32_t misalignedRel =
            static_cast<int32_t>(misalignedTarget - (regionVa + 5));
        std::memcpy(misalignedJump + 1, &misalignedRel, sizeof(misalignedRel));
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(
            misalignedJump, sizeof(misalignedJump), regionVa, modules, &stats);
        if (stats.NearJumps != 0 || stats.Unbacked != 0)
        {
            break;
        }

        // A body too short to hold the instruction, and a body that is not a
        // kernel address at all, both stay empty.
        uint8_t shortJump[4] = { 0xE9, 0x00, 0x00, 0x00 };
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(shortJump, sizeof(shortJump), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.NearJumps != 0)
        {
            break;
        }
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(nearJump, sizeof(nearJump), 0x1000ull, modules, &stats);
        if (stats.Slots != 0 || stats.NearJumps != 0 || stats.Unbacked != 0)
        {
            break;
        }

        // Degenerate inputs stay quiet: no body, a short body, a raw data
        // buffer, and a null out-parameter are all handled without a verdict.
        stats = KmonMapperStubStats();
        KmonCountMapperStubs(nullptr, 64, regionVa, modules, &stats);
        if (stats.Slots != 0)
        {
            break;
        }
        uint8_t shortBody[8] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        KmonCountMapperStubs(shortBody, sizeof(shortBody), regionVa, modules, &stats);
        if (stats.Slots != 0)
        {
            break;
        }
        uint8_t dataBody[64] = {};
        for (size_t i = 0; i < sizeof(dataBody); ++i)
        {
            dataBody[i] = static_cast<uint8_t>(0x40 + (i % 0x20));
        }
        KmonCountMapperStubs(dataBody, sizeof(dataBody), regionVa, modules, &stats);
        if (stats.Slots != 0 || stats.Unbacked != 0)
        {
            break;
        }
        KmonCountMapperStubs(dataBody, sizeof(dataBody), regionVa, modules, nullptr);

        // The verdict: every fact present, no unbacked stub, is quiet.
        KmonResidualSignalInput input;
        input.RegionKnown = true;
        input.Executable = true;
        input.TableViewKnown = true;
        input.BodyReadKnown = true;
        input.ModuleViewKnown = true;
        if (KmonClassifyResidualSignal(input) != KmonResidualSignalKind::None)
        {
            break;
        }

        // An unbacked stub in a region the table still reports is a mapper
        // stub; in a region the table does not report it is a hidden pool
        // allocation. That single fact is the only difference.
        KmonResidualSignalInput stub = input;
        stub.MapperStubs = 2;
        stub.UnbackedStubs = 2;
        stub.InBigPoolTable = true;
        if (KmonClassifyResidualSignal(stub) != KmonResidualSignalKind::MapperStub)
        {
            break;
        }
        KmonResidualSignalInput hidden = stub;
        hidden.InBigPoolTable = false;
        if (KmonClassifyResidualSignal(hidden) != KmonResidualSignalKind::PoolHidden)
        {
            break;
        }

        // Fail-closed: an unavailable table view, an unreadable body, an empty
        // module range view, an incomplete record, a non-executable region,
        // session space, and a module-owned range each withhold both verdicts
        // on their own.
        KmonResidualSignalInput noTable = stub;
        noTable.TableViewKnown = false;
        if (KmonClassifyResidualSignal(noTable) != KmonResidualSignalKind::None)
        {
            break;
        }
        KmonResidualSignalInput noBody = stub;
        noBody.BodyReadKnown = false;
        if (KmonClassifyResidualSignal(noBody) != KmonResidualSignalKind::None)
        {
            break;
        }
        // An empty module range set cannot tell "no module owns it" from "the
        // owner range was not readable", so both verdicts are withheld.
        KmonResidualSignalInput noModuleView = stub;
        noModuleView.ModuleViewKnown = false;
        if (KmonClassifyResidualSignal(noModuleView) != KmonResidualSignalKind::None)
        {
            break;
        }
        KmonResidualSignalInput noRegion = stub;
        noRegion.RegionKnown = false;
        if (KmonClassifyResidualSignal(noRegion) != KmonResidualSignalKind::None)
        {
            break;
        }
        KmonResidualSignalInput noExecute = stub;
        noExecute.Executable = false;
        if (KmonClassifyResidualSignal(noExecute) != KmonResidualSignalKind::None)
        {
            break;
        }
        KmonResidualSignalInput session = stub;
        session.SessionSpace = true;
        if (KmonClassifyResidualSignal(session) != KmonResidualSignalKind::MapperStub)
        {
            break;
        }
        KmonResidualSignalInput ownedInput = stub;
        ownedInput.InLoadedModule = true;
        if (KmonClassifyResidualSignal(ownedInput) != KmonResidualSignalKind::None)
        {
            break;
        }
        // Stubs that all resolved into modules or into the region itself are
        // not an unbacked transfer, even with a silent table view.
        KmonResidualSignalInput resolved = hidden;
        resolved.UnbackedStubs = 0;
        if (KmonClassifyResidualSignal(resolved) != KmonResidualSignalKind::None)
        {
            break;
        }

        if (KmonResidualSignalKindName(KmonResidualSignalKind::None)[0] != L'\0' ||
            std::wstring(KmonResidualSignalKindName(
                KmonResidualSignalKind::PoolHidden)) != L"pool.hidden" ||
            std::wstring(KmonResidualSignalKindName(
                KmonResidualSignalKind::MapperStub)) != L"mapper.stub")
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
