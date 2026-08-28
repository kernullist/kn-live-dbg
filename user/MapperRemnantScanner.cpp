#include "MapperRemnantScanner.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

namespace
{
    std::wstring MapperToLower(const std::wstring& value)
    {
        std::wstring lower = value;
        for (wchar_t& ch : lower)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }

        return lower;
    }

    constexpr uint32_t kDefaultUnloadedSlots = 50;
    constexpr uint32_t kMaxUnloadedSlots = 64;
    constexpr uint32_t kMaxAvlNodes = 4096;
    constexpr uint32_t kMaxHashEntries = 4096;
    constexpr uint32_t kMaxPiddbListEntries = 4096;
    constexpr uint64_t kAvlLeft = 0x08;
    constexpr uint64_t kAvlRight = 0x10;
    constexpr uint64_t kAvlLinksSize = 0x20;

    // x64 RTL_AVL_TABLE: BalancedRoot (0x20) + OrderedPointer + two ULONGS,
    // then DepthOfTree/RestartKey/DeleteCount, then the three routines.
    // Older mapper code treated 0x30 as CompareRoutine (that is DepthOfTree).
    struct AvlTableLayout
    {
        uint32_t BalancedRoot = 0x00;
        uint32_t NumberGenericTableElements = 0x2c;
        uint32_t CompareRoutine = 0x48;
        uint32_t AllocateRoutine = 0x50;
        uint32_t FreeRoutine = 0x58;
    };

    void SanitizeAvlTableLayout(AvlTableLayout* layout)
    {
        if (layout == nullptr)
        {
            return;
        }

        // x64 CompareRoutine cannot sit on DepthOfTree (0x30). A bad PDB
        // match that is 8-byte-strided at 0x30/0x38/0x40 is the old mapper bug.
        if (layout->CompareRoutine < 0x40 ||
            layout->AllocateRoutine != layout->CompareRoutine + 8 ||
            layout->FreeRoutine != layout->AllocateRoutine + 8)
        {
            layout->CompareRoutine = 0x48;
            layout->AllocateRoutine = 0x50;
            layout->FreeRoutine = 0x58;
        }
    }

    AvlTableLayout ResolveAvlTableLayout()
    {
        // Public PDB has this type, but a field miss still walks every
        // kernel module through GetTypeLayout. The x64 slots are stable;
        // LooksLikeAvlTable validates them against live pointers.
        AvlTableLayout layout;
        SanitizeAvlTableLayout(&layout);
        return layout;
    }

    bool RoutinePointsAtLoadedImage(
        SymbolEngine& symbols,
        uint64_t value)
    {
        bool ok = false;
        if (!LeftoverIsKernelCanonical(value))
        {
            return false;
        }

        const std::vector<KernelModuleInfo> modules = symbols.CopyModules();
        for (const KernelModuleInfo& module : modules)
        {
            uint64_t end = 0;
            if (!LeftoverTryAdd(module.Base, module.Size, &end))
            {
                continue;
            }
            if (value >= module.Base && value < end)
            {
                ok = true;
                break;
            }
        }

        return ok;
    }

    bool LooksLikeAvlTable(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t tableAddr,
        const AvlTableLayout& layout)
    {
        bool ok = false;

        do
        {
            uint32_t goodRoutines = 0;
            const uint32_t routineOffs[3] = {
                layout.CompareRoutine,
                layout.AllocateRoutine,
                layout.FreeRoutine
            };
            for (uint32_t off : routineOffs)
            {
                uint64_t field = 0;
                uint64_t value = 0;
                if (!LeftoverTryAdd(tableAddr, off, &field) ||
                    !LeftoverReadU64(device, field, &value, nullptr))
                {
                    continue;
                }
                if (RoutinePointsAtLoadedImage(symbols, value))
                {
                    ++goodRoutines;
                }
            }

            uint32_t count = 0;
            uint64_t countAddr = 0;
            if (!LeftoverTryAdd(tableAddr, layout.NumberGenericTableElements, &countAddr) ||
                !LeftoverReadU32(device, countAddr, &count, nullptr) ||
                count > 0x100000)
            {
                break;
            }

            uint64_t rootField = 0;
            uint64_t root = 0;
            const uint64_t rootOffset =
                static_cast<uint64_t>(layout.BalancedRoot) + kAvlRight;
            if (!LeftoverTryAdd(tableAddr, rootOffset, &rootField) ||
                !LeftoverReadU64(device, rootField, &root, nullptr))
            {
                break;
            }

            if (count == 0)
            {
                ok = (goodRoutines >= 2) || (root == 0);
                break;
            }

            if (goodRoutines < 2)
            {
                break;
            }
            if (!LeftoverIsKernelCanonical(root))
            {
                break;
            }

            uint64_t parent = 0;
            uint64_t sentinel = 0;
            if (!LeftoverTryAdd(tableAddr, layout.BalancedRoot, &sentinel) ||
                !LeftoverReadU64(device, root, &parent, nullptr))
            {
                break;
            }
            if (parent != tableAddr && parent != sentinel)
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadAvlChildren(
        DeviceClient& device,
        uint64_t node,
        uint64_t* left,
        uint64_t* right)
    {
        bool ok = false;

        do
        {
            if (left == nullptr || right == nullptr)
            {
                break;
            }
            *left = 0;
            *right = 0;

            std::vector<uint8_t> links;
            if (!LeftoverReadBytes(device, node, 0x18, &links, nullptr) ||
                links.size() < 0x18)
            {
                break;
            }
            memcpy(left, links.data() + static_cast<size_t>(kAvlLeft), sizeof(uint64_t));
            memcpy(right, links.data() + static_cast<size_t>(kAvlRight), sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadBlobU16(const std::vector<uint8_t>& blob, uint32_t offset, uint16_t* value)
    {
        bool ok = false;
        if (value != nullptr &&
            static_cast<uint64_t>(offset) + sizeof(uint16_t) <= blob.size())
        {
            memcpy(value, blob.data() + offset, sizeof(uint16_t));
            ok = true;
        }

        return ok;
    }

    bool ReadBlobU64(const std::vector<uint8_t>& blob, uint32_t offset, uint64_t* value)
    {
        bool ok = false;
        if (value != nullptr &&
            static_cast<uint64_t>(offset) + sizeof(uint64_t) <= blob.size())
        {
            memcpy(value, blob.data() + offset, sizeof(uint64_t));
            ok = true;
        }

        return ok;
    }

    bool ProbeRangeStillExecutable(
        DeviceClient& device,
        uint64_t address,
        bool* present,
        bool* executable)
    {
        bool ok = false;

        do
        {
            if (present == nullptr || executable == nullptr)
            {
                break;
            }
            *present = false;
            *executable = false;

            PhysicalTranslationInfo info = {};
            std::wstring translateError;
            if (!device.TranslateVirtual(0, address, 1, &info, &translateError))
            {
                break;
            }

            const bool la57 = (info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
            const uint64_t levels[5] = {
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

            bool mapped = walkCount > 0;
            bool nxClear = walkCount > 0;
            for (size_t step = 0; step < walkCount; ++step)
            {
                const size_t levelIdx = startIndex + step;
                if (levelIdx >= 5)
                {
                    break;
                }
                const uint64_t pte = levels[levelIdx];
                if ((pte & 1ull) == 0)
                {
                    mapped = false;
                }
                if ((pte & (1ull << 63)) != 0)
                {
                    nxClear = false;
                }
                if ((levelIdx == 2 || levelIdx == 3) && (pte & (1ull << 7)) != 0)
                {
                    break;
                }
            }

            *present = mapped;
            *executable = mapped && nxClear;
            ok = true;
        } while (false);

        return ok;
    }

    bool WalkAvlInOrder(
        DeviceClient& device,
        uint64_t tableAddr,
        const AvlTableLayout& layout,
        std::vector<uint64_t>* nodes,
        bool* complete)
    {
        bool ok = false;

        do
        {
            if (nodes == nullptr || complete == nullptr)
            {
                break;
            }
            nodes->clear();
            *complete = false;

            uint64_t rootField = 0;
            uint64_t root = 0;
            const uint64_t rootOffset =
                static_cast<uint64_t>(layout.BalancedRoot) + kAvlRight;
            if (!LeftoverTryAdd(tableAddr, rootOffset, &rootField) ||
                !LeftoverReadU64(device, rootField, &root, nullptr))
            {
                break;
            }
            if (root == 0)
            {
                *complete = true;
                ok = true;
                break;
            }
            if (!LeftoverIsKernelCanonical(root))
            {
                break;
            }

            struct AvlWalkFrame
            {
                uint64_t Node = 0;
                uint64_t Right = 0;
            };
            std::vector<AvlWalkFrame> stack;
            std::set<uint64_t> visited;
            uint64_t current = root;
            uint32_t steps = 0;
            bool truncated = false;

            while ((current != 0 || !stack.empty()) && !truncated)
            {
                ++steps;
                if (steps > kMaxAvlNodes * 4)
                {
                    truncated = true;
                    break;
                }

                while (current != 0)
                {
                    if (!LeftoverIsKernelCanonical(current) || !visited.insert(current).second)
                    {
                        truncated = true;
                        current = 0;
                        break;
                    }
                    if (stack.size() >= kMaxAvlNodes)
                    {
                        truncated = true;
                        current = 0;
                        break;
                    }

                    uint64_t left = 0;
                    uint64_t right = 0;
                    if (!ReadAvlChildren(device, current, &left, &right))
                    {
                        truncated = true;
                        left = 0;
                        right = 0;
                    }
                    AvlWalkFrame frame = {};
                    frame.Node = current;
                    frame.Right = right;
                    stack.push_back(frame);
                    current = left;
                }

                if (stack.empty())
                {
                    break;
                }

                const AvlWalkFrame frame = stack.back();
                stack.pop_back();
                if (nodes->size() >= kMaxAvlNodes)
                {
                    truncated = true;
                    break;
                }
                nodes->push_back(frame.Node);
                current = frame.Right;
            }

            *complete = !truncated;
            ok = true;
        } while (false);

        return ok;
    }

    uint16_t EffectiveUnicodeMaximum(uint16_t length, uint16_t maximumLength)
    {
        return (maximumLength == 0) ? length : maximumLength;
    }

    bool ReadUnicodeFromFields(
        DeviceClient& device,
        uint16_t length,
        uint16_t maximumLength,
        uint64_t buffer,
        std::wstring* name)
    {
        bool ok = false;

        do
        {
            if (name == nullptr)
            {
                break;
            }
            name->clear();
            const uint16_t effectiveMax = EffectiveUnicodeMaximum(length, maximumLength);
            if (!LeftoverLooksLikeUnicodeString(length, effectiveMax, buffer))
            {
                break;
            }
            if (length == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> bytes;
            if (!LeftoverReadBytes(device, buffer, length, &bytes, nullptr) ||
                bytes.size() != length)
            {
                break;
            }
            name->assign(
                reinterpret_cast<const wchar_t*>(bytes.data()),
                bytes.size() / sizeof(wchar_t));
            while (!name->empty() && (name->back() == L'\0' || name->back() < 0x20))
            {
                name->pop_back();
            }
            ok = !name->empty();
        } while (false);

        return ok;
    }

    bool ProbeUnicodeAt(
        DeviceClient& device,
        uint64_t address,
        std::wstring* name)
    {
        bool ok = false;

        do
        {
            if (name == nullptr)
            {
                break;
            }
            name->clear();

            std::vector<uint8_t> header;
            if (!LeftoverReadBytes(device, address, 16, &header, nullptr) ||
                header.size() < 16)
            {
                break;
            }

            uint16_t length = 0;
            uint16_t maximumLength = 0;
            uint64_t buffer = 0;
            memcpy(&length, header.data(), sizeof(length));
            memcpy(&maximumLength, header.data() + 2, sizeof(maximumLength));
            memcpy(&buffer, header.data() + 8, sizeof(buffer));
            ok = ReadUnicodeFromFields(device, length, maximumLength, buffer, name);
        } while (false);

        return ok;
    }

    bool ProbePiddbDriverName(
        DeviceClient& device,
        uint64_t node,
        bool listEntry,
        uint32_t preferredNameOffset,
        uint64_t* entryOut,
        uint32_t* nameOffsetOut,
        std::wstring* nameOut)
    {
        bool ok = false;

        do
        {
            if (entryOut == nullptr || nameOffsetOut == nullptr || nameOut == nullptr)
            {
                break;
            }
            *entryOut = 0;
            *nameOffsetOut = 0;
            nameOut->clear();

            uint64_t bases[2] = { node, 0 };
            uint32_t baseCount = 1;
            if (!listEntry)
            {
                uint64_t afterLinks = 0;
                if (LeftoverTryAdd(node, kAvlLinksSize, &afterLinks) && afterLinks != node)
                {
                    bases[1] = afterLinks;
                    baseCount = 2;
                }
            }

            const uint32_t offsets[] = { preferredNameOffset, 0x10, 0x30, 0x20 };
            for (uint32_t baseIndex = 0; baseIndex < baseCount && !ok; ++baseIndex)
            {
                for (uint32_t off : offsets)
                {
                    if (off == 0)
                    {
                        continue;
                    }

                    uint64_t nameAddr = 0;
                    std::wstring name;
                    if (!LeftoverTryAdd(bases[baseIndex], off, &nameAddr))
                    {
                        continue;
                    }
                    if (!ProbeUnicodeAt(device, nameAddr, &name) ||
                        name.empty() ||
                        !LeftoverLooksLikeDriverName(name))
                    {
                        continue;
                    }

                    *entryOut = bases[baseIndex];
                    *nameOffsetOut = off;
                    *nameOut = std::move(name);
                    ok = true;
                    break;
                }
            }
        } while (false);

        return ok;
    }

    bool LooksLikeDumpStackDriver(const std::wstring& name)
    {
        const std::wstring base = MapperToLower(LeftoverModuleBaseName(name));
        bool ok = false;
        if (base.size() >= 5 && base.compare(0, 5, L"dump_") == 0)
        {
            ok = true;
        }
        else if (base.size() >= 4 && base.compare(0, 4, L"dump") == 0 &&
                 (base == L"dumpfve.sys" ||
                  base == L"dumpstorport.sys" ||
                  base == L"dumpstornvme.sys"))
        {
            ok = true;
        }

        return ok;
    }

    bool IsBrokenCircularFlink(uint64_t next, uint64_t current)
    {
        return next == 0 || next == current;
    }

    bool LooksLikeInlineUnloadedArrayHead(uint16_t length, uint16_t maximum, uint64_t buffer)
    {
        if (length == 0)
        {
            // Empty first circular-log slot is valid. Reject the dummy-VA
            // even-Length trap (maximum 0 / non-canonical Buffer).
            return (maximum % 2) == 0 &&
                maximum >= 2 &&
                maximum <= kLeftoverMaxUnicodeBytes &&
                (buffer == 0 || LeftoverIsKernelCanonical(buffer));
        }
        return LeftoverLooksLikeUnicodeString(length, maximum, buffer);
    }

    bool NameInRecordList(
        const std::vector<MapperUnloadedRecord>& unloaded,
        const std::wstring& name)
    {
        bool found = false;
        for (const MapperUnloadedRecord& record : unloaded)
        {
            if (!record.Name.empty() && LeftoverNamesMatch(record.Name, name))
            {
                found = true;
                break;
            }
        }

        return found;
    }

    bool ExplainedByUnloadOrBootStack(
        const std::vector<MapperUnloadedRecord>& unloaded,
        const std::wstring& name)
    {
        return NameInRecordList(unloaded, name) || LooksLikeDumpStackDriver(name);
    }

    void CoalesceUnloadedRecords(std::vector<MapperUnloadedRecord>* records)
    {
        if (records == nullptr || records->size() < 2)
        {
            return;
        }

        std::vector<MapperUnloadedRecord> coalesced;
        coalesced.reserve(records->size());
        for (const MapperUnloadedRecord& record : *records)
        {
            if (!coalesced.empty())
            {
                MapperUnloadedRecord& last = coalesced.back();
                if (!record.Name.empty() &&
                    LeftoverNamesMatch(last.Name, record.Name) &&
                    last.StartAddress == record.StartAddress)
                {
                    last.RepeatCount += 1;
                    if (record.EndAddress > last.EndAddress)
                    {
                        last.EndAddress = record.EndAddress;
                    }
                    if (record.Suspicious)
                    {
                        last.Suspicious = true;
                    }
                    if (record.StillExecutable)
                    {
                        last.StillExecutable = true;
                    }
                    if (record.SameImageReload)
                    {
                        last.SameImageReload = true;
                    }
                    if (record.RangeReused)
                    {
                        last.RangeReused = true;
                    }
                    if (record.StillPresent)
                    {
                        last.StillPresent = true;
                    }
                    if (record.OverlapsLoadedModule)
                    {
                        last.OverlapsLoadedModule = true;
                    }
                    continue;
                }
            }

            coalesced.push_back(record);
        }

        *records = std::move(coalesced);
    }
}

MapperRemnantScanner::MapperRemnantScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool MapperRemnantScanner::NameInLoadedModules(const std::wstring& name) const
{
    bool found = false;

    for (const LeftoverModuleRange& module : modules_)
    {
        if (LeftoverNamesMatch(module.Name, name))
        {
            found = true;
            break;
        }
    }

    return found;
}

bool MapperRemnantScanner::ScanUnloaded(MapperScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        uint64_t symbol = 0;
        std::wstring resolveError;
        if (!symbols_.ResolveSymbol(L"nt!MmUnloadedDrivers", &symbol, &resolveError))
        {
            result->CoverageNotes.push_back(
                L"nt!MmUnloadedDrivers was not resolved; unloaded-driver coverage is absent");
            if (error != nullptr)
            {
                *error = resolveError;
            }
            break;
        }

        result->MmUnloadedDrivers = symbol;
        uint64_t array = 0;
        if (!LeftoverReadU64(device_, symbol, &array, &resolveError))
        {
            result->Warnings.push_back(L"failed to read nt!MmUnloadedDrivers: " + resolveError);
            break;
        }

        // Public PDBs omit _MM_UNLOADED_DRIVER. The x64 slot is UNICODE_STRING
        // + Start/End + CurrentTime (0x28). Do not GetTypeLayout-miss here:
        // a missing type walks every kernel module and loads PDBs.
        const uint32_t nameOffset = 0;
        const uint32_t startOffset = 0x10;
        const uint32_t endOffset = 0x18;
        const uint32_t timeOffset = 0x20;
        const uint32_t entrySize = 0x28;

        if (array == 0)
        {
            result->UnloadedResolved = true;
            result->UnloadedComplete = true;
            result->CoverageNotes.push_back(
                L"nt!MmUnloadedDrivers is NULL; the circular log is empty or wiped");
            ok = true;
            break;
        }
        if (!LeftoverIsKernelCanonical(array))
        {
            // Some builds store the array at the symbol instead of a pointer.
            // Probe the real UNICODE_STRING Buffer; do not pass a dummy kernel
            // VA that would accept any even Length.
            uint16_t length = 0;
            uint16_t maximum = 0;
            uint64_t buffer = 0;
            uint64_t maxAddr = 0;
            uint64_t bufAddr = 0;
            if (LeftoverReadU16(device_, symbol, &length, nullptr) &&
                LeftoverTryAdd(symbol, 2, &maxAddr) &&
                LeftoverReadU16(device_, maxAddr, &maximum, nullptr) &&
                LeftoverTryAdd(symbol, 8, &bufAddr) &&
                LeftoverReadU64(device_, bufAddr, &buffer, nullptr) &&
                LooksLikeInlineUnloadedArrayHead(length, maximum, buffer))
            {
                array = symbol;
            }
            else
            {
                result->Warnings.push_back(
                    L"nt!MmUnloadedDrivers did not dereference to a kernel pointer");
                break;
            }
        }

        result->MmUnloadedArray = array;
        result->UnloadedResolved = true;

        uint64_t lastSymbol = 0;
        uint32_t lastIndex = 0;
        if (symbols_.ResolveSymbol(L"nt!MmLastUnloadedDriver", &lastSymbol, nullptr))
        {
            LeftoverReadU32(device_, lastSymbol, &lastIndex, nullptr);
            result->MmLastUnloadedDriver = lastIndex;
        }

        result->UnloadedSlotCount = kDefaultUnloadedSlots;
        bool walkedAll = true;
        const uint32_t blobBytes = kDefaultUnloadedSlots * entrySize;
        std::vector<uint8_t> blob;
        std::wstring blobError;
        const bool usedBulk =
            LeftoverReadBytes(device_, array, blobBytes, &blob, &blobError) &&
            blob.size() == blobBytes;
        if (!usedBulk)
        {
            result->Warnings.push_back(
                L"MmUnloadedDrivers bulk read failed; falling back to per-slot");
        }

        uint32_t readableSlots = 0;
        for (uint32_t index = 0;
             index < kDefaultUnloadedSlots && index < kMaxUnloadedSlots;
             ++index)
        {
            uint64_t entry = 0;
            if (!LeftoverTryAdd(array, static_cast<uint64_t>(index) * entrySize, &entry))
            {
                walkedAll = false;
                result->Warnings.push_back(L"unloaded-driver entry address overflow");
                break;
            }

            uint32_t slot = 0;
            const std::vector<uint8_t>* view = &blob;
            std::vector<uint8_t> slotBlob;
            if (usedBulk)
            {
                slot = index * entrySize;
            }
            else if (LeftoverReadBytes(device_, entry, entrySize, &slotBlob, nullptr) &&
                     slotBlob.size() == entrySize)
            {
                view = &slotBlob;
                ++readableSlots;
            }
            else
            {
                continue;
            }

            uint64_t start = 0;
            uint64_t end = 0;
            uint64_t time = 0;
            uint16_t nameLength = 0;
            uint16_t nameMaximum = 0;
            uint64_t nameBuffer = 0;
            if (!ReadBlobU64(*view, slot + startOffset, &start) ||
                !ReadBlobU64(*view, slot + endOffset, &end) ||
                !ReadBlobU64(*view, slot + timeOffset, &time) ||
                !ReadBlobU16(*view, slot + nameOffset, &nameLength) ||
                !ReadBlobU16(*view, slot + nameOffset + 2, &nameMaximum) ||
                !ReadBlobU64(*view, slot + nameOffset + 8, &nameBuffer))
            {
                continue;
            }
            if (start == 0 && end == 0 && nameLength == 0)
            {
                continue;
            }

            std::wstring name;
            ReadUnicodeFromFields(device_, nameLength, nameMaximum, nameBuffer, &name);

            MapperUnloadedRecord record = {};
            record.Index = index;
            record.EntryAddress = entry;
            record.StartAddress = start;
            record.EndAddress = end;
            record.TimeStamp = time;
            record.Name = name;
            if (start != 0 && end != 0 && end <= start)
            {
                record.Suspicious = true;
                LeftoverAppendNote(&record.Notes, L"end <= start");
            }

            if (LeftoverIsKernelCanonical(start))
            {
                const LeftoverModuleRange* owner = LeftoverFindModule(modules_, start);
                if (owner != nullptr)
                {
                    record.OverlapsLoadedModule = true;
                    record.StillPresent = true;
                    record.StillExecutable = true;
                    if (!name.empty() && LeftoverNamesMatch(owner->Name, name))
                    {
                        record.SameImageReload = true;
                        LeftoverAppendNote(
                            &record.Notes,
                            L"same image still loaded at this range (reload)");
                    }
                    else
                    {
                        record.RangeReused = true;
                        LeftoverAppendNote(
                            &record.Notes,
                            L"range reused by " + owner->Name);
                    }
                }
                else
                {
                    bool present = false;
                    bool executable = false;
                    if (ProbeRangeStillExecutable(device_, start, &present, &executable))
                    {
                        record.StillPresent = present;
                        record.StillExecutable = executable;
                        if (executable)
                        {
                            record.Suspicious = true;
                            LeftoverAppendNote(
                                &record.Notes,
                                L"unloaded range is still present+executable");
                        }
                    }
                }
            }

            if (name.empty() && start != 0)
            {
                record.Suspicious = true;
                LeftoverAppendNote(&record.Notes, L"name wiped but range is non-zero");
            }

            if (record.Suspicious)
            {
                result->AnySuspicious = true;
            }
            result->Unloaded.push_back(record);
        }

        if (!usedBulk && readableSlots == 0)
        {
            walkedAll = false;
        }

        CoalesceUnloadedRecords(&result->Unloaded);
        result->UnloadedComplete = walkedAll;
        ok = true;
    } while (false);

    return ok;
}

bool MapperRemnantScanner::ScanPiddb(MapperScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        uint64_t table = 0;
        std::wstring resolveError;
        if (!symbols_.ResolveSymbol(L"nt!PiDDBCacheTable", &table, &resolveError))
        {
            table = 0;
        }

        result->PiDDBCacheTable = table;
        const AvlTableLayout avlLayout = ResolveAvlTableLayout();
        std::vector<uint64_t> nodes;
        bool complete = false;
        bool usedAvl = false;
        if (table != 0 && LooksLikeAvlTable(device_, symbols_, table, avlLayout))
        {
            if (!WalkAvlInOrder(device_, table, avlLayout, &nodes, &complete))
            {
                result->Warnings.push_back(L"PiDDB AVL walk failed");
            }
            else if (complete || !nodes.empty())
            {
                usedAvl = true;
                result->PiddbWalkMode = L"avl";
                uint32_t declared = 0;
                uint64_t countAddr = 0;
                if (LeftoverTryAdd(table, avlLayout.NumberGenericTableElements, &countAddr))
                {
                    LeftoverReadU32(device_, countAddr, &declared, nullptr);
                }
                result->PiddbElementCount = declared;
            }
        }

        if (!usedAvl)
        {
            uint64_t listHead = 0;
            if (symbols_.ResolveSymbol(L"nt!PiDDBCacheList", &listHead, nullptr) &&
                LeftoverIsKernelCanonical(listHead))
            {
                uint64_t flink = 0;
                if (LeftoverReadU64(device_, listHead, &flink, nullptr))
                {
                    uint64_t current = flink;
                    uint32_t steps = 0;
                    complete = true;
                    std::set<uint64_t> visited;
                    visited.insert(listHead);
                    if (flink == 0)
                    {
                        complete = false;
                    }
                    while (current != 0 && current != listHead && steps < kMaxPiddbListEntries)
                    {
                        ++steps;
                        if (!LeftoverIsKernelCanonical(current) || !visited.insert(current).second)
                        {
                            complete = false;
                            break;
                        }
                        nodes.push_back(current);
                        uint64_t next = 0;
                        if (!LeftoverReadU64(device_, current, &next, nullptr) ||
                            IsBrokenCircularFlink(next, current))
                        {
                            complete = false;
                            break;
                        }
                        current = next;
                    }
                    if (current != 0 && current != listHead)
                    {
                        complete = false;
                    }
                    result->PiddbWalkMode = L"list";
                    result->PiddbElementCount = static_cast<uint32_t>(nodes.size());
                    result->Warnings.push_back(
                        L"PiDDB AVL header did not validate; walked nt!PiDDBCacheList");
                }
            }
        }

        if (nodes.empty() && result->PiddbWalkMode.empty())
        {
            if (table == 0)
            {
                result->CoverageNotes.push_back(
                    L"nt!PiDDBCacheTable was not resolved; PiDDB coverage is absent");
                if (error != nullptr)
                {
                    *error = resolveError;
                }
            }
            else
            {
                result->Warnings.push_back(
                    L"nt!PiDDBCacheTable does not look like RTL_AVL_TABLE and PiDDBCacheList was empty");
            }
            break;
        }
        result->PiddbResolved = true;
        result->PiddbComplete = complete;
        if (!complete)
        {
            result->Warnings.push_back(L"PiDDB walk hit the node cap or a cycle");
        }

        const bool listEntries = (result->PiddbWalkMode == L"list");

        uint32_t nameOffset = 0x10;
        uint32_t index = 0;
        for (uint64_t node : nodes)
        {
            uint64_t entry = 0;
            uint32_t usedNameOffset = nameOffset;
            std::wstring name;
            if (!ProbePiddbDriverName(
                    device_,
                    node,
                    listEntries,
                    nameOffset,
                    &entry,
                    &usedNameOffset,
                    &name))
            {
                continue;
            }
            nameOffset = usedNameOffset;

            MapperPiddbRecord record = {};
            record.Index = index++;
            record.NodeAddress = node;
            record.EntryAddress = entry;
            record.DriverName = name;
            record.InLoadedModules = NameInLoadedModules(name);

            const uint32_t usedTimeOffset = usedNameOffset + 0x10;
            const uint32_t usedStatusOffset = usedNameOffset + 0x14;
            uint64_t timeAddr = 0;
            uint64_t statusAddr = 0;
            if (LeftoverTryAdd(entry, usedTimeOffset, &timeAddr))
            {
                LeftoverReadU32(device_, timeAddr, &record.TimeDateStamp, nullptr);
            }
            if (LeftoverTryAdd(entry, usedStatusOffset, &statusAddr))
            {
                LeftoverReadU32(device_, statusAddr, &record.LoadStatus, nullptr);
            }

            if (!record.InLoadedModules)
            {
                if (ExplainedByUnloadOrBootStack(result->Unloaded, name))
                {
                    record.Expected = true;
                    LeftoverAppendNote(&record.Notes, L"explained by unload log or dump/boot stack");
                }
                else
                {
                    LeftoverAppendNote(&record.Notes, L"name is not in the live module list");
                    if (!LeftoverLooksLikeDriverName(name) || record.TimeDateStamp == 0)
                    {
                        record.Suspicious = true;
                        LeftoverAppendNote(&record.Notes, L"implausible leftover cache entry");
                        result->AnySuspicious = true;
                    }
                }
            }
            result->Piddb.push_back(record);
        }

        if (!nodes.empty() && result->Piddb.empty())
        {
            result->Warnings.push_back(
                L"PiDDB nodes were walked but no driver names parsed");
        }

        ok = true;
    } while (false);

    return ok;
}

bool MapperRemnantScanner::ScanHash(MapperScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        uint64_t symbol = 0;
        std::wstring matched;
        std::wstring resolveError;
        const std::wstring candidates[] = {
            L"ci!g_KernelHashBucketList",
            L"ci!g_CiKernelHashBucketList",
            L"ci!KernelHashBucketList",
            L"ci!g_HashBucketList"
        };
        for (const std::wstring& name : candidates)
        {
            if (symbols_.ResolveSymbol(name, &symbol, &resolveError))
            {
                matched = name;
                break;
            }
            symbol = 0;
        }
        if (symbol == 0)
        {
            result->CoverageNotes.push_back(
                L"ci!g_KernelHashBucketList was not resolved; hash-bucket coverage is absent");
            if (error != nullptr)
            {
                *error = resolveError;
            }
            break;
        }

        result->HashListSymbol = symbol;
        result->HashListSymbolName = matched;
        result->HashResolved = true;

        uint64_t first = 0;
        if (!LeftoverReadU64(device_, symbol, &first, &resolveError))
        {
            result->Warnings.push_back(L"failed to read " + matched + L": " + resolveError);
            break;
        }

        bool listHeadAtSymbol = false;
        uint64_t blink = 0;
        uint64_t blinkField = 0;
        if (LeftoverTryAdd(symbol, 8, &blinkField) &&
            LeftoverReadU64(device_, blinkField, &blink, nullptr) &&
            LeftoverIsKernelCanonical(first) &&
            LeftoverIsKernelCanonical(blink))
        {
            uint64_t firstBlink = 0;
            uint64_t firstBlinkField = 0;
            if (LeftoverTryAdd(first, 8, &firstBlinkField) &&
                LeftoverReadU64(device_, firstBlinkField, &firstBlink, nullptr) &&
                firstBlink == symbol)
            {
                listHeadAtSymbol = true;
            }
        }

        std::set<uint64_t> visited;
        uint32_t index = 0;
        bool truncated = false;
        uint64_t current = 0;
        uint32_t nameOffset = 0x08;

        if (listHeadAtSymbol)
        {
            result->HashWalkMode = L"list_entry";
            current = first;
            nameOffset = 0x10;
            if (current == symbol)
            {
                result->HashComplete = true;
                ok = true;
                break;
            }
        }
        else if (LeftoverIsKernelCanonical(first))
        {
            result->HashWalkMode = L"singly_linked";
            current = first;
            nameOffset = 0x08;
        }
        else if (first == 0)
        {
            result->HashWalkMode = L"empty";
            result->HashComplete = true;
            result->CoverageNotes.push_back(matched + L" is NULL; the list is empty or wiped");
            ok = true;
            break;
        }
        else
        {
            result->Warnings.push_back(matched + L" first pointer is not kernel-canonical");
            break;
        }

        while (current != 0 && current != symbol)
        {
            if (!LeftoverIsKernelCanonical(current) || !visited.insert(current).second)
            {
                truncated = true;
                break;
            }
            if (visited.size() > kMaxHashEntries)
            {
                truncated = true;
                break;
            }

            uint64_t nameAddr = 0;
            std::wstring name;
            bool named = false;
            const uint32_t nameCandidates[] = { nameOffset, 0x08, 0x10, 0x18 };
            for (uint32_t off : nameCandidates)
            {
                if (!LeftoverTryAdd(current, off, &nameAddr))
                {
                    continue;
                }
                if (ProbeUnicodeAt(device_, nameAddr, &name) &&
                    !name.empty() &&
                    LeftoverLooksLikeDriverName(name))
                {
                    named = true;
                    nameOffset = off;
                    break;
                }
            }

            uint64_t next = 0;
            const bool readNext = LeftoverReadU64(device_, current, &next, nullptr);

            if (named)
            {
                MapperHashRecord record = {};
                record.Index = index++;
                record.EntryAddress = current;
                record.Next = next;
                record.DriverName = name;
                record.InLoadedModules = NameInLoadedModules(name);
                if (!record.InLoadedModules)
                {
                    if (ExplainedByUnloadOrBootStack(result->Unloaded, name))
                    {
                        record.Expected = true;
                        LeftoverAppendNote(
                            &record.Notes,
                            L"explained by unload log or dump/boot stack");
                    }
                    else
                    {
                        LeftoverAppendNote(&record.Notes, L"name is not in the live module list");
                        if (name.find(L'.') == std::wstring::npos)
                        {
                            record.Suspicious = true;
                            result->AnySuspicious = true;
                        }
                    }
                }
                result->HashEntries.push_back(record);
            }

            if (!readNext)
            {
                truncated = true;
                break;
            }

            if (listHeadAtSymbol)
            {
                if (IsBrokenCircularFlink(next, current))
                {
                    truncated = true;
                    break;
                }
                current = next;
            }
            else
            {
                if (!LeftoverIsKernelCanonical(next))
                {
                    if (next != 0)
                    {
                        truncated = true;
                    }
                    break;
                }
                current = next;
            }
        }

        result->HashComplete = !truncated;
        if (truncated)
        {
            result->Warnings.push_back(L"kernel hash bucket walk hit a cycle or entry cap");
        }
        ok = true;
    } while (false);

    return ok;
}

bool MapperRemnantScanner::Scan(
    const MapperScanOptions& options,
    MapperScanResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"mapper scan output is null";
            }
            break;
        }

        *result = MapperScanResult{};
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

        const bool keepUnloaded = options.IncludeUnloaded;
        if (keepUnloaded || options.IncludePiddb || options.IncludeHash)
        {
            std::wstring localError;
            if (!ScanUnloaded(result, &localError) && !result->UnloadedResolved)
            {
                if (!localError.empty())
                {
                    result->Warnings.push_back(L"unloaded: " + localError);
                }
            }
        }
        if (options.IncludePiddb)
        {
            std::wstring localError;
            if (!ScanPiddb(result, &localError) && !result->PiddbResolved)
            {
                if (!localError.empty())
                {
                    result->Warnings.push_back(L"piddb: " + localError);
                }
            }
        }
        if (options.IncludeHash)
        {
            std::wstring localError;
            if (!ScanHash(result, &localError) && !result->HashResolved)
            {
                if (!localError.empty())
                {
                    result->Warnings.push_back(L"cihash: " + localError);
                }
            }
        }

        if (!keepUnloaded)
        {
            result->Unloaded.clear();
            result->MmUnloadedDrivers = 0;
            result->MmUnloadedArray = 0;
            result->MmLastUnloadedDriver = 0;
            result->UnloadedSlotCount = 0;
            result->UnloadedResolved = false;
            result->UnloadedComplete = false;
        }

        if (options.Limit != 0)
        {
            auto keepSuspiciousFirst = [](auto* items, uint32_t limit)
            {
                if (items == nullptr || items->size() <= limit)
                {
                    return;
                }
                std::stable_partition(
                    items->begin(),
                    items->end(),
                    [](const auto& item)
                    {
                        return item.Suspicious;
                    });
                items->resize(limit);
            };
            keepSuspiciousFirst(&result->Unloaded, options.Limit);
            auto keepLeftoverFirst = [](auto* items, uint32_t limit)
            {
                if (items == nullptr || items->size() <= limit)
                {
                    return;
                }
                std::stable_partition(
                    items->begin(),
                    items->end(),
                    [](const auto& item)
                    {
                        return item.Suspicious || (!item.InLoadedModules && !item.Expected);
                    });
                items->resize(limit);
            };
            keepLeftoverFirst(&result->Piddb, options.Limit);
            keepLeftoverFirst(&result->HashEntries, options.Limit);
        }

        result->AnySuspicious = false;
        for (const MapperUnloadedRecord& record : result->Unloaded)
        {
            if (record.Suspicious)
            {
                result->AnySuspicious = true;
            }
        }
        for (const MapperPiddbRecord& record : result->Piddb)
        {
            if (record.Suspicious)
            {
                result->AnySuspicious = true;
            }
        }
        for (const MapperHashRecord& record : result->HashEntries)
        {
            if (record.Suspicious)
            {
                result->AnySuspicious = true;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildMapperJson(const MapperScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.mapper.v1\"";
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"unloadedResolved\":";
    out += result.UnloadedResolved ? L"true" : L"false";
    out += L",\"unloadedComplete\":";
    out += result.UnloadedComplete ? L"true" : L"false";
    out += L",\"piddbResolved\":";
    out += result.PiddbResolved ? L"true" : L"false";
    out += L",\"piddbComplete\":";
    out += result.PiddbComplete ? L"true" : L"false";
    out += L",\"hashResolved\":";
    out += result.HashResolved ? L"true" : L"false";
    out += L",\"hashComplete\":";
    out += result.HashComplete ? L"true" : L"false";
    out += L",\"hashWalkMode\":" + mcpjson::Quote(result.HashWalkMode);
    out += L",\"piddbWalkMode\":" + mcpjson::Quote(result.PiddbWalkMode);
    out += L",\"mmUnloadedDrivers\":" + mcpjson::Quote(LeftoverFormatHex(result.MmUnloadedDrivers, 16));
    out += L",\"piDDBCacheTable\":" + mcpjson::Quote(LeftoverFormatHex(result.PiDDBCacheTable, 16));
    out += L",\"hashListSymbol\":" + mcpjson::Quote(result.HashListSymbolName);

    out += L",\"unloaded\":[";
    for (size_t index = 0; index < result.Unloaded.size(); ++index)
    {
        const MapperUnloadedRecord& record = result.Unloaded[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"name\":" + mcpjson::Quote(record.Name);
        out += L",\"start\":" + mcpjson::Quote(LeftoverFormatHex(record.StartAddress, 16));
        out += L",\"end\":" + mcpjson::Quote(LeftoverFormatHex(record.EndAddress, 16));
        out += L",\"stillPresent\":";
        out += record.StillPresent ? L"true" : L"false";
        out += L",\"stillExecutable\":";
        out += record.StillExecutable ? L"true" : L"false";
        out += L",\"rangeReused\":";
        out += record.RangeReused ? L"true" : L"false";
        out += L",\"sameImageReload\":";
        out += record.SameImageReload ? L"true" : L"false";
        out += L",\"repeatCount\":" + std::to_wstring(record.RepeatCount);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }

    out += L"],\"piddb\":[";
    for (size_t index = 0; index < result.Piddb.size(); ++index)
    {
        const MapperPiddbRecord& record = result.Piddb[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"name\":" + mcpjson::Quote(record.DriverName);
        out += L",\"timeDateStamp\":" + std::to_wstring(record.TimeDateStamp);
        out += L",\"inLoadedModules\":";
        out += record.InLoadedModules ? L"true" : L"false";
        out += L",\"expected\":";
        out += record.Expected ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }

    out += L"],\"hashEntries\":[";
    for (size_t index = 0; index < result.HashEntries.size(); ++index)
    {
        const MapperHashRecord& record = result.HashEntries[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"name\":" + mcpjson::Quote(record.DriverName);
        out += L",\"inLoadedModules\":";
        out += record.InLoadedModules ? L"true" : L"false";
        out += L",\"expected\":";
        out += record.Expected ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
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

bool MapperRemnantSelfTest()
{
    bool ok = true;

    do
    {
        if (LeftoverLooksLikeUnicodeString(8, 16, 0x10))
        {
            ok = false;
            break;
        }
        if (!LeftoverLooksLikeUnicodeString(8, 16, 0xFFFFF80000001000ull))
        {
            ok = false;
            break;
        }

        const AvlTableLayout fallback = {};
        if (fallback.CompareRoutine != 0x48 ||
            fallback.AllocateRoutine != 0x50 ||
            fallback.FreeRoutine != 0x58 ||
            fallback.NumberGenericTableElements != 0x2c)
        {
            ok = false;
            break;
        }

        AvlTableLayout badRoutines = fallback;
        badRoutines.CompareRoutine = 0x30;
        badRoutines.AllocateRoutine = 0x38;
        badRoutines.FreeRoutine = 0x40;
        SanitizeAvlTableLayout(&badRoutines);
        if (badRoutines.CompareRoutine != 0x48 ||
            badRoutines.AllocateRoutine != 0x50 ||
            badRoutines.FreeRoutine != 0x58)
        {
            ok = false;
            break;
        }

        if (EffectiveUnicodeMaximum(8, 0) != 8 ||
            EffectiveUnicodeMaximum(8, 16) != 16 ||
            LeftoverLooksLikeUnicodeString(8, 0, 0xFFFFF80000001000ull) ||
            !LeftoverLooksLikeUnicodeString(
                8,
                EffectiveUnicodeMaximum(8, 0),
                0xFFFFF80000001000ull))
        {
            ok = false;
            break;
        }

        std::vector<uint8_t> blob(24, 0);
        blob[0] = 8;
        blob[8] = 0x00;
        blob[9] = 0x10;
        blob[10] = 0x00;
        blob[11] = 0x00;
        blob[12] = 0x00;
        blob[13] = 0x80;
        blob[14] = 0xFF;
        blob[15] = 0xFF;
        uint16_t nameLength = 0;
        uint64_t nameBuffer = 0;
        if (!ReadBlobU16(blob, 0, &nameLength) ||
            nameLength != 8 ||
            !ReadBlobU64(blob, 8, &nameBuffer) ||
            nameBuffer != 0xFFFF800000001000ull ||
            ReadBlobU64(blob, 17, &nameBuffer))
        {
            ok = false;
            break;
        }

        if (!LooksLikeDumpStackDriver(L"dump_storport.sys") ||
            !LooksLikeDumpStackDriver(L"\\SystemRoot\\System32\\drivers\\Dumpstorport.sys") ||
            !LooksLikeDumpStackDriver(L"dumpfve.sys") ||
            LooksLikeDumpStackDriver(L"WdBoot.sys") ||
            LooksLikeDumpStackDriver(L"capcom.sys"))
        {
            ok = false;
            break;
        }

        std::vector<MapperUnloadedRecord> repeats;
        MapperUnloadedRecord first = {};
        first.Name = L"KnLiveDbg.sys";
        first.StartAddress = 0xFFFFF80010000000ull;
        first.EndAddress = 0xFFFFF80010001000ull;
        first.SameImageReload = true;
        MapperUnloadedRecord second = first;
        second.EndAddress = 0xFFFFF80010001400ull;
        repeats.push_back(first);
        repeats.push_back(second);
        CoalesceUnloadedRecords(&repeats);
        if (repeats.size() != 1 ||
            repeats[0].RepeatCount != 2 ||
            repeats[0].EndAddress != 0xFFFFF80010001400ull)
        {
            ok = false;
            break;
        }

        if (!IsBrokenCircularFlink(0, 0xFFFFF80000001000ull) ||
            !IsBrokenCircularFlink(0xFFFFF80000001000ull, 0xFFFFF80000001000ull) ||
            IsBrokenCircularFlink(0xFFFFF80000002000ull, 0xFFFFF80000001000ull) ||
            LooksLikeInlineUnloadedArrayHead(0, 0, 0xFFFFF80000001000ull) ||
            LooksLikeInlineUnloadedArrayHead(8, 8, 0x10) ||
            LooksLikeInlineUnloadedArrayHead(0, 16, 0x10) ||
            !LooksLikeInlineUnloadedArrayHead(0, 16, 0xFFFFF80000001000ull) ||
            !LooksLikeInlineUnloadedArrayHead(8, 16, 0xFFFFF80000001000ull))
        {
            ok = false;
            break;
        }

        std::vector<MapperUnloadedRecord> damOnly;
        MapperUnloadedRecord dam = {};
        dam.Name = L"dam.sys";
        dam.StartAddress = 0xFFFFF80020000000ull;
        damOnly.push_back(dam);
        if (!ExplainedByUnloadOrBootStack(
                damOnly,
                L"\\Windows\\System32\\drivers\\dam.sys") ||
            ExplainedByUnloadOrBootStack(
                repeats,
                L"\\Windows\\System32\\DriverStore\\FileRepository\\x\\NetworkPrivacyPolicy.sys") ||
            ExplainedByUnloadOrBootStack(damOnly, L"capcom.sys") ||
            !ExplainedByUnloadOrBootStack(damOnly, L"dumpfve.sys"))
        {
            ok = false;
            break;
        }
    } while (false);

    return ok;
}
