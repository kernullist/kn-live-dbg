#include "MapperRemnantScanner.h"

#include "AddressInspector.h"
#include "McpJson.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace
{
    constexpr uint32_t kDefaultUnloadedSlots = 50;
    constexpr uint32_t kMaxUnloadedSlots = 64;
    constexpr uint32_t kMaxAvlNodes = 4096;
    constexpr uint32_t kMaxHashEntries = 4096;
    constexpr uint64_t kAvlParent = 0x00;
    constexpr uint64_t kAvlLeft = 0x08;
    constexpr uint64_t kAvlRight = 0x10;
    constexpr uint64_t kAvlLinksSize = 0x20;
    constexpr uint64_t kAvlNumberOfElements = 0x2c;
    constexpr uint64_t kAvlCompareRoutine = 0x30;
    constexpr uint64_t kAvlAllocateRoutine = 0x38;
    constexpr uint64_t kAvlFreeRoutine = 0x40;

    bool LooksLikeAvlTable(DeviceClient& device, SymbolEngine& symbols, uint64_t tableAddr)
    {
        bool ok = false;

        do
        {
            uint32_t goodRoutines = 0;
            const uint64_t routineOffs[3] = {
                kAvlCompareRoutine,
                kAvlAllocateRoutine,
                kAvlFreeRoutine
            };
            for (uint64_t off : routineOffs)
            {
                uint64_t field = 0;
                uint64_t value = 0;
                if (!LeftoverTryAdd(tableAddr, off, &field) ||
                    !LeftoverReadU64(device, field, &value, nullptr))
                {
                    continue;
                }
                if (!LeftoverIsKernelCanonical(value))
                {
                    continue;
                }
                for (const KernelModuleInfo& module : symbols.Modules())
                {
                    uint64_t end = 0;
                    if (!LeftoverTryAdd(module.Base, module.Size, &end))
                    {
                        continue;
                    }
                    if (value >= module.Base && value < end)
                    {
                        ++goodRoutines;
                        break;
                    }
                }
            }
            if (goodRoutines < 2)
            {
                break;
            }

            uint32_t count = 0;
            uint64_t countAddr = 0;
            if (!LeftoverTryAdd(tableAddr, kAvlNumberOfElements, &countAddr) ||
                !LeftoverReadU32(device, countAddr, &count, nullptr))
            {
                break;
            }
            if (count > 0x100000)
            {
                break;
            }
            if (count == 0)
            {
                ok = true;
                break;
            }

            uint64_t rootField = 0;
            uint64_t root = 0;
            if (!LeftoverTryAdd(tableAddr, kAvlRight, &rootField) ||
                !LeftoverReadU64(device, rootField, &root, nullptr))
            {
                break;
            }
            if (!LeftoverIsKernelCanonical(root))
            {
                break;
            }

            uint64_t parent = 0;
            if (!LeftoverReadU64(device, root, &parent, nullptr) || parent != tableAddr)
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool WalkAvlInOrder(
        DeviceClient& device,
        uint64_t tableAddr,
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
            if (!LeftoverTryAdd(tableAddr, kAvlRight, &rootField) ||
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

            std::vector<uint64_t> stack;
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
                        current = 0;
                        break;
                    }
                    if (stack.size() >= kMaxAvlNodes)
                    {
                        truncated = true;
                        break;
                    }
                    stack.push_back(current);
                    uint64_t leftField = 0;
                    uint64_t left = 0;
                    if (!LeftoverTryAdd(current, kAvlLeft, &leftField) ||
                        !LeftoverReadU64(device, leftField, &left, nullptr))
                    {
                        current = 0;
                        break;
                    }
                    current = left;
                }

                if (truncated || stack.empty())
                {
                    break;
                }

                current = stack.back();
                stack.pop_back();
                if (nodes->size() >= kMaxAvlNodes)
                {
                    truncated = true;
                    break;
                }
                nodes->push_back(current);

                uint64_t rightField = 0;
                uint64_t right = 0;
                if (!LeftoverTryAdd(current, kAvlRight, &rightField) ||
                    !LeftoverReadU64(device, rightField, &right, nullptr))
                {
                    current = 0;
                    continue;
                }
                current = right;
            }

            *complete = !truncated;
            ok = true;
        } while (false);

        return ok;
    }

    bool ProbeUnicodeAt(
        DeviceClient& device,
        SymbolEngine& symbols,
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

            uint16_t length = 0;
            uint16_t maximumLength = 0;
            uint64_t maxAddr = 0;
            uint64_t buffer = 0;
            uint64_t bufferAddr = 0;
            if (!LeftoverReadU16(device, address, &length, nullptr) ||
                !LeftoverTryAdd(address, 2, &maxAddr) ||
                !LeftoverReadU16(device, maxAddr, &maximumLength, nullptr) ||
                !LeftoverTryAdd(address, 8, &bufferAddr) ||
                !LeftoverReadU64(device, bufferAddr, &buffer, nullptr))
            {
                break;
            }
            if (!LeftoverLooksLikeUnicodeString(length, maximumLength, buffer))
            {
                break;
            }
            if (length == 0)
            {
                ok = true;
                break;
            }
            if (!LeftoverReadUnicodeString(device, symbols, address, name, nullptr) ||
                name->empty())
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
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

        uint32_t nameOffset = 0;
        uint32_t startOffset = 0x10;
        uint32_t endOffset = 0x18;
        uint32_t timeOffset = 0x20;
        uint32_t entrySize = 0x28;
        TypeLayoutInfo layout = {};
        std::wstring layoutError;
        if (symbols_.GetTypeLayout(L"nt!_MM_UNLOADED_DRIVER", &layout, &layoutError) &&
            layout.Size != 0 &&
            layout.Size <= 0x80)
        {
            entrySize = static_cast<uint32_t>(layout.Size);
            TypeFieldInfo field = {};
            if (symbols_.FindField(L"nt!_MM_UNLOADED_DRIVER", L"Name", &field, nullptr))
            {
                nameOffset = field.Offset;
            }
            if (symbols_.FindField(L"nt!_MM_UNLOADED_DRIVER", L"StartAddress", &field, nullptr))
            {
                startOffset = field.Offset;
            }
            if (symbols_.FindField(L"nt!_MM_UNLOADED_DRIVER", L"EndAddress", &field, nullptr))
            {
                endOffset = field.Offset;
            }
            if (symbols_.FindField(L"nt!_MM_UNLOADED_DRIVER", L"CurrentTime", &field, nullptr))
            {
                timeOffset = field.Offset;
            }
        }
        else
        {
            result->Warnings.push_back(
                L"nt!_MM_UNLOADED_DRIVER was not in the PDB; using guarded x64 fallback 0x28");
        }

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
            uint16_t length = 0;
            if (LeftoverReadU16(device_, symbol, &length, nullptr) &&
                LeftoverLooksLikeUnicodeString(length, length, 0xFFFF800000000000ull))
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
        for (uint32_t index = 0; index < kDefaultUnloadedSlots && index < kMaxUnloadedSlots; ++index)
        {
            uint64_t entry = 0;
            if (!LeftoverTryAdd(array, static_cast<uint64_t>(index) * entrySize, &entry))
            {
                result->UnloadedComplete = false;
                result->Warnings.push_back(L"unloaded-driver entry address overflow");
                break;
            }

            uint64_t start = 0;
            uint64_t end = 0;
            uint64_t time = 0;
            uint64_t startAddr = 0;
            uint64_t endAddr = 0;
            uint64_t timeAddr = 0;
            uint64_t nameAddr = 0;
            if (!LeftoverTryAdd(entry, startOffset, &startAddr) ||
                !LeftoverTryAdd(entry, endOffset, &endAddr) ||
                !LeftoverTryAdd(entry, timeOffset, &timeAddr) ||
                !LeftoverTryAdd(entry, nameOffset, &nameAddr))
            {
                continue;
            }
            LeftoverReadU64(device_, startAddr, &start, nullptr);
            LeftoverReadU64(device_, endAddr, &end, nullptr);
            LeftoverReadU64(device_, timeAddr, &time, nullptr);

            std::wstring name;
            ProbeUnicodeAt(device_, symbols_, nameAddr, &name);
            if (start == 0 && end == 0 && name.empty())
            {
                continue;
            }

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
                    LeftoverAppendNote(&record.Notes, L"start still overlaps " + owner->Name);
                }

                AddressInspectResult inspect = {};
                std::wstring inspectError;
                if (InspectAddress(device_, symbols_, start, &inspect, &inspectError, 0))
                {
                    record.StillPresent = inspect.EffectivePresent;
                    record.StillExecutable = inspect.EffectivePresent && inspect.EffectiveExecutable;
                    if (record.StillExecutable && !record.OverlapsLoadedModule)
                    {
                        record.Suspicious = true;
                        LeftoverAppendNote(&record.Notes, L"unloaded range is still present+executable");
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

        result->UnloadedComplete = true;
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
        const std::wstring candidates[] = {
            L"nt!PiDDBCacheTable",
            L"nt!PiDDBCacheList"
        };
        for (const std::wstring& name : candidates)
        {
            if (symbols_.ResolveSymbol(name, &table, &resolveError))
            {
                break;
            }
            table = 0;
        }
        if (table == 0)
        {
            result->CoverageNotes.push_back(
                L"nt!PiDDBCacheTable was not resolved; PiDDB coverage is absent");
            if (error != nullptr)
            {
                *error = resolveError;
            }
            break;
        }

        result->PiDDBCacheTable = table;
        if (!LooksLikeAvlTable(device_, symbols_, table))
        {
            result->Warnings.push_back(
                L"nt!PiDDBCacheTable does not look like RTL_AVL_TABLE; walk aborted");
            break;
        }
        result->PiddbResolved = true;

        uint32_t declared = 0;
        uint64_t countAddr = 0;
        if (LeftoverTryAdd(table, kAvlNumberOfElements, &countAddr))
        {
            LeftoverReadU32(device_, countAddr, &declared, nullptr);
        }
        result->PiddbElementCount = declared;

        std::vector<uint64_t> nodes;
        bool complete = false;
        if (!WalkAvlInOrder(device_, table, &nodes, &complete))
        {
            result->Warnings.push_back(L"PiDDB AVL walk failed");
            break;
        }
        result->PiddbComplete = complete;
        if (!complete)
        {
            result->Warnings.push_back(L"PiDDB AVL walk hit the node cap or a cycle");
        }

        uint32_t nameOffset = 0x10;
        uint32_t timeOffset = 0x20;
        uint32_t statusOffset = 0x24;
        const std::wstring typeNames[] = {
            L"nt!_DDBCACHE_ENTRY",
            L"nt!_PIDDB_CACHE_ENTRY",
            L"nt!_PiDDBCacheEntry"
        };
        bool layoutFromPdb = false;
        for (const std::wstring& typeName : typeNames)
        {
            TypeFieldInfo field = {};
            if (symbols_.FindField(typeName, L"DriverName", &field, nullptr))
            {
                nameOffset = field.Offset;
                layoutFromPdb = true;
            }
            if (symbols_.FindField(typeName, L"TimeDateStamp", &field, nullptr))
            {
                timeOffset = field.Offset;
                layoutFromPdb = true;
            }
            if (symbols_.FindField(typeName, L"LoadStatus", &field, nullptr))
            {
                statusOffset = field.Offset;
            }
            if (layoutFromPdb)
            {
                break;
            }
        }
        if (!layoutFromPdb)
        {
            result->Warnings.push_back(
                L"PiDDB cache entry type was not in the PDB; using LIST_ENTRY+UNICODE_STRING fallback");
        }

        uint32_t index = 0;
        for (uint64_t node : nodes)
        {
            uint64_t entry = 0;
            if (!LeftoverTryAdd(node, kAvlLinksSize, &entry))
            {
                continue;
            }

            uint64_t nameAddr = 0;
            if (!LeftoverTryAdd(entry, nameOffset, &nameAddr))
            {
                continue;
            }

            std::wstring name;
            if (!ProbeUnicodeAt(device_, symbols_, nameAddr, &name) || name.empty())
            {
                continue;
            }

            MapperPiddbRecord record = {};
            record.Index = index++;
            record.NodeAddress = node;
            record.EntryAddress = entry;
            record.DriverName = name;
            record.InLoadedModules = NameInLoadedModules(name);

            uint64_t timeAddr = 0;
            uint64_t statusAddr = 0;
            if (LeftoverTryAdd(entry, timeOffset, &timeAddr))
            {
                LeftoverReadU32(device_, timeAddr, &record.TimeDateStamp, nullptr);
            }
            if (LeftoverTryAdd(entry, statusOffset, &statusAddr))
            {
                LeftoverReadU32(device_, statusAddr, &record.LoadStatus, nullptr);
            }

            if (!record.InLoadedModules)
            {
                LeftoverAppendNote(&record.Notes, L"name is not in the live module list");
                if (!LeftoverLooksLikeDriverName(name) || record.TimeDateStamp == 0)
                {
                    record.Suspicious = true;
                    LeftoverAppendNote(&record.Notes, L"implausible leftover cache entry");
                    result->AnySuspicious = true;
                }
            }
            result->Piddb.push_back(record);
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
                if (ProbeUnicodeAt(device_, symbols_, nameAddr, &name) && !name.empty())
                {
                    named = true;
                    nameOffset = off;
                    break;
                }
            }

            uint64_t next = 0;
            LeftoverReadU64(device_, current, &next, nullptr);

            if (named)
            {
                MapperHashRecord record = {};
                record.Index = index++;
                record.EntryAddress = current;
                record.Next = next;
                record.DriverName = name;
                record.InLoadedModules = NameInLoadedModules(name);
                if (!LeftoverLooksLikeDriverName(name))
                {
                    continue;
                }
                if (!record.InLoadedModules)
                {
                    LeftoverAppendNote(&record.Notes, L"name is not in the live module list");
                    if (name.find(L'.') == std::wstring::npos)
                    {
                        record.Suspicious = true;
                        result->AnySuspicious = true;
                    }
                }
                result->HashEntries.push_back(record);
            }

            if (listHeadAtSymbol)
            {
                current = next;
            }
            else
            {
                if (!LeftoverIsKernelCanonical(next))
                {
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

        if (options.IncludeUnloaded)
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
                        return item.Suspicious || !item.InLoadedModules;
                    });
                items->resize(limit);
            };
            keepLeftoverFirst(&result->Piddb, options.Limit);
            keepLeftoverFirst(&result->HashEntries, options.Limit);
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
    } while (false);

    return ok;
}
