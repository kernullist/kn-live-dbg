#include "DpcTimerScanner.h"

#include "McpJson.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxDpcRecords = 4096;
    constexpr uint32_t kMaxTimerRecords = 8192;
    constexpr uint32_t kMaxListWalk = 512;
    constexpr uint32_t kMaxTimerBuckets = 512;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    std::wstring FindOwningModule(SymbolEngine& symbols, uint64_t address)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                return module.ImageName;
            }
        }
        return std::wstring();
    }

    std::wstring NearestSymbolText(SymbolEngine& symbols, uint64_t address)
    {
        std::wstring nearest;
        uint64_t displacement = 0;
        std::wstring ignored;
        if (!symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
        {
            return std::wstring();
        }
        std::wstringstream stream;
        stream << nearest;
        if (displacement != 0)
        {
            stream << L"+0x" << std::hex << displacement;
        }
        return stream.str();
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    void ClassifyRoutine(
        SymbolEngine& symbols,
        uint64_t routine,
        std::wstring* module,
        std::wstring* symbol,
        bool* suspicious,
        std::wstring* notes)
    {
        if (module != nullptr)
        {
            *module = FindOwningModule(symbols, routine);
        }
        if (symbol != nullptr)
        {
            *symbol = NearestSymbolText(symbols, routine);
        }
        if (suspicious != nullptr)
        {
            *suspicious = false;
        }
        if (notes != nullptr)
        {
            notes->clear();
        }

        if (routine == 0)
        {
            return;
        }
        if (!IsKernelAddress(routine) || (module != nullptr && module->empty()))
        {
            if (suspicious != nullptr)
            {
                *suspicious = true;
            }
            if (notes != nullptr)
            {
                *notes = L"callback routine outside loaded kernel modules";
            }
        }
    }

    bool ResolvePrcbArray(SymbolEngine& symbols, uint64_t* arrayBase, uint32_t* count, std::wstring* symbolName)
    {
        const std::wstring candidates[] =
        {
            L"nt!KiProcessorBlock",
            L"nt!KeProcessorBlock",
            L"nt!KiProcessorBlocks"
        };

        for (const std::wstring& name : candidates)
        {
            uint64_t base = 0;
            if (symbols.ResolveSymbol(name, &base, nullptr) && base != 0 && IsKernelAddress(base))
            {
                *arrayBase = base;
                *symbolName = name;
                // Active processor count from usermode as a soft bound.
                DWORD active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
                if (active == 0)
                {
                    active = 1;
                }
                if (active > 256)
                {
                    active = 256;
                }
                *count = active;
                return true;
            }
        }
        return false;
    }

    bool WalkListForDpcRoutines(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t listHead,
        uint32_t processor,
        const std::wstring& source,
        uint32_t deferredRoutineOffset,
        uint32_t dpcObjectOffsetFromList,
        uint32_t limit,
        DpcTimerScanResult* result)
    {
        if (result == nullptr ||
            listHead == 0 ||
            !IsKernelAddress(listHead) ||
            result->Dpcs.size() >= limit)
        {
            return false;
        }

        uint64_t flink = 0;
        uint64_t blink = 0;
        if (!ReadU64(device, listHead, &flink) ||
            !ReadU64(device, listHead + sizeof(uint64_t), &blink) ||
            flink == 0 ||
            blink == 0)
        {
            return false;
        }
        if (flink == listHead)
        {
            return blink == listHead;
        }

        std::set<uint64_t> visited;
        uint64_t entry = flink;
        uint64_t previous = listHead;
        uint32_t walked = 0;
        while (entry != 0 && entry != listHead && walked < kMaxListWalk)
        {
            if (visited.find(entry) != visited.end())
            {
                return false;
            }
            visited.insert(entry);
            if (!IsKernelAddress(entry))
            {
                return false;
            }

            uint64_t next = 0;
            uint64_t previousLink = 0;
            if (!ReadU64(device, entry, &next) ||
                !ReadU64(device, entry + sizeof(uint64_t), &previousLink) ||
                previousLink != previous ||
                next == 0 ||
                (next != listHead && !IsKernelAddress(next)))
            {
                return false;
            }
            uint64_t nextBacklink = 0;
            if (!ReadU64(
                    device,
                    next + sizeof(uint64_t),
                    &nextBacklink) ||
                nextBacklink != entry)
            {
                return false;
            }

            uint64_t objectAddress = entry;
            if (dpcObjectOffsetFromList != 0 && entry >= dpcObjectOffsetFromList)
            {
                objectAddress = entry - dpcObjectOffsetFromList;
            }

            uint64_t routine = 0;
            if (!ReadU64(device, objectAddress + deferredRoutineOffset, &routine))
            {
                return false;
            }
            if (routine != 0)
            {
                DpcRoutineRecord record = {};
                record.Index = static_cast<uint32_t>(result->Dpcs.size());
                record.Processor = processor;
                record.Source = source;
                record.ObjectAddress = objectAddress;
                record.Routine = routine;
                ClassifyRoutine(
                    symbols,
                    routine,
                    &record.Module,
                    &record.Symbol,
                    &record.Suspicious,
                    &record.Notes);
                if (record.Suspicious)
                {
                    ++result->SuspiciousDpcCount;
                    result->AnySuspicious = true;
                }
                result->Dpcs.push_back(record);
                if (result->Dpcs.size() >= limit)
                {
                    return next == listHead;
                }
            }

            previous = entry;
            entry = next;
            ++walked;
        }

        return entry == listHead;
    }

    bool ResolveExactSymbolSize(
        SymbolEngine& symbols,
        const std::wstring& name,
        uint64_t address,
        uint32_t* size)
    {
        if (size == nullptr)
        {
            return false;
        }
        *size = 0;

        std::vector<SymbolMatchInfo> matches;
        if (!symbols.EnumerateSymbols(name, 8, &matches, nullptr))
        {
            return false;
        }
        for (const SymbolMatchInfo& match : matches)
        {
            if (match.Address == address && match.Size != 0)
            {
                *size = match.Size;
                return true;
            }
        }
        return false;
    }
}

DpcTimerScanner::DpcTimerScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool DpcTimerScanner::Scan(const Options& options, DpcTimerScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid dpc/timer scan result output";
            }
            break;
        }

        *result = DpcTimerScanResult{};

        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = L"could not load kernel modules: " + loadError;
                }
                break;
            }
        }

        TypeFieldInfo deferredRoutine = {};
        TypeFieldInfo dpcListEntry = {};
        TypeFieldInfo timerDpc = {};
        TypeFieldInfo timerListEntry = {};
        std::wstring ignored;
        const bool dpcObjectLayoutFromPdb =
            symbols_.FindField(
                L"nt!_KDPC",
                L"DeferredRoutine",
                &deferredRoutine,
                &ignored) &&
            symbols_.FindField(
                L"nt!_KDPC",
                L"DpcListEntry",
                &dpcListEntry,
                &ignored);
        const bool timerObjectLayoutFromPdb =
            symbols_.FindField(L"nt!_KTIMER", L"Dpc", &timerDpc, &ignored) &&
            symbols_.FindField(
                L"nt!_KTIMER",
                L"TimerListEntry",
                &timerListEntry,
                &ignored);

        const uint32_t dpcLimit = options.Limit == 0
            ? kMaxDpcRecords
            : (std::min)(options.Limit, kMaxDpcRecords);
        const uint32_t timerLimit = options.Limit == 0
            ? kMaxTimerRecords
            : (std::min)(options.Limit, kMaxTimerRecords);

        // ---- DPC path: per-PRCB list heads when available ----
        if (options.Target == Scope::Dpc || options.Target == Scope::All)
        {
            uint64_t prcbArray = 0;
            uint32_t processorCount = 0;
            std::wstring prcbSymbol;
            TypeFieldInfo dpcDataField = {};
            TypeFieldInfo dpcListHeadField = {};
            TypeLayoutInfo dpcDataLayout = {};
            const bool dpcQueueLayoutFromPdb =
                dpcObjectLayoutFromPdb &&
                symbols_.FindField(
                    L"nt!_KPRCB",
                    L"DpcData",
                    &dpcDataField,
                    &ignored) &&
                symbols_.FindField(
                    L"nt!_KDPC_DATA",
                    L"DpcListHead",
                    &dpcListHeadField,
                    &ignored) &&
                symbols_.GetTypeLayout(
                    L"nt!_KDPC_DATA",
                    &dpcDataLayout,
                    &ignored) &&
                dpcDataLayout.Size >= sizeof(uint64_t) * 2;

            uint32_t dpcDataCount = 0;
            if (dpcQueueLayoutFromPdb)
            {
                dpcDataCount = static_cast<uint32_t>(
                    dpcDataField.Length / dpcDataLayout.Size);
                if (dpcDataCount == 0 || dpcDataCount > 4)
                {
                    dpcDataCount = 0;
                }
            }

            if (!dpcQueueLayoutFromPdb || dpcDataCount == 0)
            {
                result->Warnings.push_back(
                    L"PDB DPC queue layout unavailable; heuristic PRCB probing disabled");
                result->DpcCoverageComplete = false;
            }
            else if (!ResolvePrcbArray(
                         symbols_,
                         &prcbArray,
                         &processorCount,
                         &prcbSymbol))
            {
                result->Warnings.push_back(
                    L"KiProcessorBlock not resolved; DPC per-CPU queues unavailable");
                result->DpcCoverageComplete = false;
            }
            else
            {
                bool coverageComplete = true;
                if (options.MaxProcessors != 0 && processorCount > options.MaxProcessors)
                {
                    processorCount = options.MaxProcessors;
                    coverageComplete = false;
                    result->Warnings.push_back(
                        L"processor limit truncated DPC coverage");
                }
                result->Warnings.push_back(L"PRCB array via " + prcbSymbol);

                for (uint32_t cpu = 0; cpu < processorCount; ++cpu)
                {
                    uint64_t prcbPtr = 0;
                    if (!ReadU64(device_, prcbArray + static_cast<uint64_t>(cpu) * sizeof(uint64_t), &prcbPtr) ||
                        !IsKernelAddress(prcbPtr))
                    {
                        coverageComplete = false;
                        continue;
                    }
                    ++result->ProcessorsSampled;

                    for (uint32_t dataIndex = 0; dataIndex < dpcDataCount; ++dataIndex)
                    {
                        const uint64_t listHead =
                            prcbPtr + dpcDataField.Offset +
                            static_cast<uint64_t>(dataIndex) * dpcDataLayout.Size +
                            dpcListHeadField.Offset;
                        const bool queueComplete = WalkListForDpcRoutines(
                            device_,
                            symbols_,
                            listHead,
                            cpu,
                            L"prcb.dpcdata[" + std::to_wstring(dataIndex) + L"]",
                            deferredRoutine.Offset,
                            dpcListEntry.Offset,
                            dpcLimit,
                            result);
                        if (!queueComplete)
                        {
                            coverageComplete = false;
                        }
                    }

                    if (result->Dpcs.size() >= dpcLimit)
                    {
                        result->Warnings.push_back(L"DPC walk hit limit; coverage incomplete");
                        coverageComplete = false;
                        break;
                    }
                }

                result->DpcCoverageComplete = coverageComplete;
            }
        }

        // ---- Timer path: KiTimerTable when present ----
        if (options.Target == Scope::Timer || options.Target == Scope::All)
        {
            uint64_t timerTable = 0;
            uint32_t timerTableSize = 0;
            const std::wstring timerSymbol = L"nt!KiTimerTableListHead";
            TypeLayoutInfo timerTableEntryLayout = {};
            TypeFieldInfo timerTableListField = {};
            bool timerTableListFieldFromPdb = symbols_.FindField(
                L"nt!_KTIMER_TABLE_ENTRY",
                L"Entry",
                &timerTableListField,
                &ignored);
            if (!timerTableListFieldFromPdb)
            {
                timerTableListFieldFromPdb = symbols_.FindField(
                    L"nt!_KTIMER_TABLE_ENTRY",
                    L"ListHead",
                    &timerTableListField,
                    &ignored);
            }
            const bool foundTimerRoot =
                dpcObjectLayoutFromPdb &&
                timerObjectLayoutFromPdb &&
                timerTableListFieldFromPdb &&
                symbols_.GetTypeLayout(
                    L"nt!_KTIMER_TABLE_ENTRY",
                    &timerTableEntryLayout,
                    &ignored) &&
                timerTableEntryLayout.Size >= sizeof(uint64_t) * 2 &&
                timerTableEntryLayout.Size <= 0x100 &&
                static_cast<uint64_t>(timerTableListField.Offset) +
                        sizeof(uint64_t) * 2 <=
                    timerTableEntryLayout.Size &&
                symbols_.ResolveSymbol(timerSymbol, &timerTable, nullptr) &&
                IsKernelAddress(timerTable) &&
                ResolveExactSymbolSize(
                    symbols_,
                    timerSymbol,
                    timerTable,
                    &timerTableSize) &&
                timerTableSize % timerTableEntryLayout.Size == 0;
            const uint32_t bucketCount = foundTimerRoot
                ? static_cast<uint32_t>(
                      timerTableSize / timerTableEntryLayout.Size)
                : 0;

            if (!foundTimerRoot ||
                bucketCount == 0 ||
                bucketCount > kMaxTimerBuckets)
            {
                result->Warnings.push_back(
                    L"PDB-bounded KiTimerTableListHead unavailable; heuristic timer "
                    L"table probing disabled");
                result->TimerCoverageComplete = false;
            }
            else
            {
                bool coverageComplete = true;
                result->Warnings.push_back(
                    L"timer root via PDB-bounded " + timerSymbol);

                for (uint32_t bucket = 0; bucket < bucketCount; ++bucket)
                {
                    const uint64_t listHead =
                        timerTable +
                        static_cast<uint64_t>(bucket) *
                            timerTableEntryLayout.Size +
                        timerTableListField.Offset;
                    uint64_t flink = 0;
                    uint64_t blink = 0;
                    if (!ReadU64(device_, listHead, &flink) ||
                        !ReadU64(
                            device_,
                            listHead + sizeof(uint64_t),
                            &blink) ||
                        flink == 0 ||
                        blink == 0)
                    {
                        coverageComplete = false;
                        continue;
                    }
                    if (flink == listHead)
                    {
                        if (blink != listHead)
                        {
                            coverageComplete = false;
                        }
                        continue;
                    }

                    std::set<uint64_t> visited;
                    uint64_t entry = flink;
                    uint64_t previous = listHead;
                    uint32_t walked = 0;
                    while (entry != 0 &&
                           entry != listHead &&
                           walked < kMaxListWalk)
                    {
                        if (!IsKernelAddress(entry) ||
                            entry < timerListEntry.Offset ||
                            !visited.insert(entry).second)
                        {
                            coverageComplete = false;
                            break;
                        }

                        uint64_t next = 0;
                        uint64_t previousLink = 0;
                        if (!ReadU64(device_, entry, &next) ||
                            !ReadU64(
                                device_,
                                entry + sizeof(uint64_t),
                                &previousLink) ||
                            previousLink != previous ||
                            next == 0 ||
                            (next != listHead && !IsKernelAddress(next)))
                        {
                            coverageComplete = false;
                            break;
                        }
                        uint64_t nextBacklink = 0;
                        if (!ReadU64(
                                device_,
                                next + sizeof(uint64_t),
                                &nextBacklink) ||
                            nextBacklink != entry)
                        {
                            coverageComplete = false;
                            break;
                        }

                        const uint64_t timerAddress =
                            entry - timerListEntry.Offset;
                        uint64_t dpcPtr = 0;
                        if (!ReadU64(
                                device_,
                                timerAddress + timerDpc.Offset,
                                &dpcPtr))
                        {
                            coverageComplete = false;
                            break;
                        }
                        if (dpcPtr != 0)
                        {
                            if (!IsKernelAddress(dpcPtr))
                            {
                                coverageComplete = false;
                                break;
                            }

                            uint64_t routine = 0;
                            if (!ReadU64(
                                    device_,
                                    dpcPtr + deferredRoutine.Offset,
                                    &routine))
                            {
                                coverageComplete = false;
                                break;
                            }
                            if (routine != 0)
                            {
                                TimerRoutineRecord record = {};
                                record.Index =
                                    static_cast<uint32_t>(result->Timers.size());
                                record.TimerAddress = timerAddress;
                                record.DpcAddress = dpcPtr;
                                record.Routine = routine;
                                ClassifyRoutine(
                                    symbols_,
                                    routine,
                                    &record.Module,
                                    &record.Symbol,
                                    &record.Suspicious,
                                    &record.Notes);
                                if (record.Suspicious)
                                {
                                    ++result->SuspiciousTimerCount;
                                    result->AnySuspicious = true;
                                }
                                result->Timers.push_back(record);
                                if (result->Timers.size() >= timerLimit)
                                {
                                    break;
                                }
                            }
                        }

                        previous = entry;
                        entry = next;
                        ++walked;
                    }

                    if (entry != listHead)
                    {
                        coverageComplete = false;
                    }
                    if (result->Timers.size() >= timerLimit)
                    {
                        coverageComplete = false;
                        result->Warnings.push_back(
                            L"timer walk hit limit; coverage incomplete");
                        break;
                    }
                }

                result->TimerCoverageComplete = coverageComplete;
            }
        }

        // ---- Work-item best-effort ----
        if (options.Target == Scope::WorkItem || options.Target == Scope::All)
        {
            result->WorkItemAttempted = true;
            uint64_t workQueue = 0;
            const std::wstring workSymbols[] =
            {
                L"nt!ExWorkerQueue",
                L"nt!ExpWorkerQueue",
                L"nt!ExWorkerQueueCritical"
            };
            bool found = false;
            for (const std::wstring& name : workSymbols)
            {
                if (symbols_.ResolveSymbol(name, &workQueue, nullptr) && IsKernelAddress(workQueue))
                {
                    found = true;
                    result->Warnings.push_back(
                        L"work-item root " + name +
                        L" resolved but modern threadpool layouts are not fully decoded; coverage incomplete");
                    break;
                }
            }
            if (!found)
            {
                result->Warnings.push_back(
                    L"work-item queue symbols not resolved; workitem coverage incomplete");
            }
            result->WorkItemCoverageComplete = false;
        }

        // Success even when some coverage is incomplete - incomplete is explicit.
        if (options.Target == Scope::Dpc &&
            result->Dpcs.empty() &&
            !result->DpcCoverageComplete &&
            result->ProcessorsSampled == 0)
        {
            // still ok: return empty with warnings
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring BuildSharedHeader(const DpcTimerScanResult& result, const wchar_t* schema)
    {
        std::wstring out = L"{\"schema\":";
        out += mcpjson::Quote(schema);
        out += L",\"anySuspicious\":";
        out += result.AnySuspicious ? L"true" : L"false";
        out += L",\"processorsSampled\":" + std::to_wstring(result.ProcessorsSampled);
        out += L",\"dpcCoverageComplete\":";
        out += result.DpcCoverageComplete ? L"true" : L"false";
        out += L",\"timerCoverageComplete\":";
        out += result.TimerCoverageComplete ? L"true" : L"false";
        out += L",\"workItemCoverageComplete\":";
        out += result.WorkItemCoverageComplete ? L"true" : L"false";
        out += L",\"warnings\":[";
        for (size_t i = 0; i < result.Warnings.size(); ++i)
        {
            if (i > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(result.Warnings[i]);
        }
        out += L"]";
        return out;
    }
}

std::wstring BuildDpcJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.dpc.v1");
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousDpcCount);
    out += L",\"dpcCount\":" + std::to_wstring(result.Dpcs.size());
    out += L",\"dpcs\":[";
    for (size_t i = 0; i < result.Dpcs.size(); ++i)
    {
        const DpcRoutineRecord& record = result.Dpcs[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"processor\":" + std::to_wstring(record.Processor);
        out += L",\"source\":" + mcpjson::Quote(record.Source);
        out += L",\"object\":" + mcpjson::Quote(JsonHex(record.ObjectAddress));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildTimerJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.timer.v1");
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousTimerCount);
    out += L",\"timerCount\":" + std::to_wstring(result.Timers.size());
    out += L",\"timers\":[";
    for (size_t i = 0; i < result.Timers.size(); ++i)
    {
        const TimerRoutineRecord& record = result.Timers[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"timer\":" + mcpjson::Quote(JsonHex(record.TimerAddress));
        out += L",\"dpc\":" + mcpjson::Quote(JsonHex(record.DpcAddress));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildWorkItemJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.workitem.v1");
    out += L",\"attempted\":";
    out += result.WorkItemAttempted ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousWorkItemCount);
    out += L",\"workItemCount\":" + std::to_wstring(result.WorkItems.size());
    out += L",\"workItems\":[";
    for (size_t i = 0; i < result.WorkItems.size(); ++i)
    {
        const WorkItemRecord& record = result.WorkItems[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"entry\":" + mcpjson::Quote(JsonHex(record.EntryAddress));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}
