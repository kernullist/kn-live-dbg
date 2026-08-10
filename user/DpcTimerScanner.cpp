#include "DpcTimerScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <Windows.h>
#include <cstring>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxDpcRecords = 4096;
    constexpr uint32_t kMaxTimerRecords = 8192;
    constexpr uint32_t kMaxWorkItems = 1024;
    constexpr uint32_t kMaxListWalk = 512;

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

    void WalkListForDpcRoutines(
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
        if (result == nullptr || listHead == 0 || !IsKernelAddress(listHead))
        {
            return;
        }

        uint64_t flink = 0;
        if (!ReadU64(device, listHead, &flink) || flink == 0)
        {
            return;
        }
        if (flink == listHead)
        {
            return;
        }

        std::set<uint64_t> visited;
        uint64_t entry = flink;
        uint32_t walked = 0;
        while (entry != 0 && entry != listHead && walked < kMaxListWalk)
        {
            if (visited.find(entry) != visited.end())
            {
                break;
            }
            visited.insert(entry);
            if (!IsKernelAddress(entry))
            {
                break;
            }

            uint64_t objectAddress = entry;
            if (dpcObjectOffsetFromList != 0 && entry >= dpcObjectOffsetFromList)
            {
                objectAddress = entry - dpcObjectOffsetFromList;
            }

            uint64_t routine = 0;
            if (ReadU64(device, objectAddress + deferredRoutineOffset, &routine) && routine != 0)
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
                    return;
                }
            }

            uint64_t next = 0;
            if (!ReadU64(device, entry, &next))
            {
                break;
            }
            entry = next;
            ++walked;
        }
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

        ResolvedFieldOffset deferredRoutine =
            ResolveFieldOffset(symbols_, L"nt!_KDPC", L"DeferredRoutine", 0x18);
        ResolvedFieldOffset dpcListEntry =
            ResolveFieldOffset(symbols_, L"nt!_KDPC", L"DpcListEntry", 0x08);
        ResolvedFieldOffset timerDpc =
            ResolveFieldOffset(symbols_, L"nt!_KTIMER", L"Dpc", 0x30);
        ResolvedFieldOffset timerListEntry =
            ResolveFieldOffset(symbols_, L"nt!_KTIMER", L"TimerListEntry", 0x20);

        if (!deferredRoutine.FromPdb)
        {
            result->Warnings.push_back(
                L"_KDPC.DeferredRoutine not in PDB; using guarded x64 fallback 0x18");
        }
        if (!timerDpc.FromPdb)
        {
            result->Warnings.push_back(
                L"_KTIMER.Dpc not in PDB; using guarded x64 fallback 0x30");
        }

        const uint32_t dpcLimit = options.Limit == 0 ? kMaxDpcRecords : options.Limit;
        const uint32_t timerLimit = options.Limit == 0 ? kMaxTimerRecords : options.Limit;

        // ---- DPC path: per-PRCB list heads when available ----
        if (options.Target == Scope::Dpc || options.Target == Scope::All)
        {
            uint64_t prcbArray = 0;
            uint32_t processorCount = 0;
            std::wstring prcbSymbol;
            if (!ResolvePrcbArray(symbols_, &prcbArray, &processorCount, &prcbSymbol))
            {
                result->Warnings.push_back(
                    L"KiProcessorBlock not resolved; DPC per-CPU queues unavailable");
                result->DpcCoverageComplete = false;
            }
            else
            {
                if (options.MaxProcessors != 0 && processorCount > options.MaxProcessors)
                {
                    processorCount = options.MaxProcessors;
                }
                result->ProcessorsSampled = processorCount;
                result->Warnings.push_back(L"PRCB array via " + prcbSymbol);

                // Candidate offsets of DpcData / DpcList heads inside KPRCB.
                // Public PDBs often expose DpcData; otherwise probe known regions.
                ResolvedFieldOffset dpcData =
                    ResolveFieldOffset(symbols_, L"nt!_KPRCB", L"DpcData", 0x2d80);

                for (uint32_t cpu = 0; cpu < processorCount; ++cpu)
                {
                    uint64_t prcbPtr = 0;
                    if (!ReadU64(device_, prcbArray + static_cast<uint64_t>(cpu) * sizeof(uint64_t), &prcbPtr) ||
                        !IsKernelAddress(prcbPtr))
                    {
                        continue;
                    }

                    // DpcData is typically an array of KDPC_DATA; each has a LIST_ENTRY.
                    // Read a few candidate list heads around DpcData.
                    const uint32_t candidateOffsets[] =
                    {
                        dpcData.Offset,
                        dpcData.Offset + 0x00,
                        dpcData.Offset + 0x20,
                        dpcData.Offset + 0x40,
                    };

                    for (uint32_t offset : candidateOffsets)
                    {
                        uint64_t listHead = prcbPtr + offset;
                        uint64_t flink = 0;
                        uint64_t blink = 0;
                        if (!ReadU64(device_, listHead, &flink) || !ReadU64(device_, listHead + 8, &blink))
                        {
                            continue;
                        }
                        if (!IsKernelAddress(flink) || !IsKernelAddress(blink))
                        {
                            continue;
                        }
                        // Valid list head: empty (self) or flink->blink round trip.
                        if (flink != listHead)
                        {
                            uint64_t flinkBlink = 0;
                            if (!ReadU64(device_, flink + 8, &flinkBlink) || flinkBlink != listHead)
                            {
                                continue;
                            }
                        }

                        WalkListForDpcRoutines(
                            device_,
                            symbols_,
                            listHead,
                            cpu,
                            L"prcb.dpcdata",
                            deferredRoutine.Offset,
                            dpcListEntry.FromPdb ? dpcListEntry.Offset : 0x08,
                            dpcLimit,
                            result);

                        if (result->Dpcs.size() >= dpcLimit)
                        {
                            break;
                        }
                    }

                    if (result->Dpcs.size() >= dpcLimit)
                    {
                        result->Warnings.push_back(L"DPC walk hit limit; coverage incomplete");
                        break;
                    }
                }

                result->DpcCoverageComplete = result->Dpcs.size() < dpcLimit;
            }

            // Also resolve any global DPC-related list symbols if present.
            const std::wstring globalDpcHeads[] =
            {
                L"nt!KiDpcQueue",
                L"nt!IopWaitCompletionPacketDpc"
            };
            for (const std::wstring& name : globalDpcHeads)
            {
                uint64_t head = 0;
                if (symbols_.ResolveSymbol(name, &head, nullptr) && IsKernelAddress(head))
                {
                    WalkListForDpcRoutines(
                        device_,
                        symbols_,
                        head,
                        0,
                        name,
                        deferredRoutine.Offset,
                        dpcListEntry.FromPdb ? dpcListEntry.Offset : 0x08,
                        dpcLimit,
                        result);
                }
            }
        }

        // ---- Timer path: KiTimerTable when present ----
        if (options.Target == Scope::Timer || options.Target == Scope::All)
        {
            uint64_t timerTable = 0;
            const std::wstring timerSymbols[] =
            {
                L"nt!KiTimerTableListHead",
                L"nt!KiTimerTable",
                L"nt!ExpKernelTimer"
            };

            bool foundTimerRoot = false;
            for (const std::wstring& name : timerSymbols)
            {
                if (symbols_.ResolveSymbol(name, &timerTable, nullptr) && IsKernelAddress(timerTable))
                {
                    foundTimerRoot = true;
                    result->Warnings.push_back(L"timer root via " + name);

                    // Treat as an array of LIST_ENTRY heads. Bound to 256 or 512 buckets.
                    const uint32_t bucketCount = 256;
                    for (uint32_t bucket = 0; bucket < bucketCount; ++bucket)
                    {
                        uint64_t listHead = timerTable + static_cast<uint64_t>(bucket) * 0x10;
                        uint64_t flink = 0;
                        if (!ReadU64(device_, listHead, &flink) || flink == 0 || flink == listHead)
                        {
                            continue;
                        }
                        if (!IsKernelAddress(flink))
                        {
                            continue;
                        }

                        std::set<uint64_t> visited;
                        uint64_t entry = flink;
                        uint32_t walked = 0;
                        while (entry != 0 && entry != listHead && walked < kMaxListWalk)
                        {
                            if (visited.find(entry) != visited.end())
                            {
                                break;
                            }
                            visited.insert(entry);

                            uint64_t timerAddress = entry;
                            if (timerListEntry.Offset != 0 && entry >= timerListEntry.Offset)
                            {
                                timerAddress = entry - timerListEntry.Offset;
                            }

                            uint64_t dpcPtr = 0;
                            if (ReadU64(device_, timerAddress + timerDpc.Offset, &dpcPtr) &&
                                dpcPtr != 0 &&
                                IsKernelAddress(dpcPtr))
                            {
                                uint64_t routine = 0;
                                if (ReadU64(device_, dpcPtr + deferredRoutine.Offset, &routine) && routine != 0)
                                {
                                    TimerRoutineRecord record = {};
                                    record.Index = static_cast<uint32_t>(result->Timers.size());
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

                            uint64_t next = 0;
                            if (!ReadU64(device_, entry, &next))
                            {
                                break;
                            }
                            entry = next;
                            ++walked;
                        }

                        if (result->Timers.size() >= timerLimit)
                        {
                            break;
                        }
                    }
                    break;
                }
            }

            if (!foundTimerRoot)
            {
                result->Warnings.push_back(
                    L"timer table symbol not resolved; timer coverage incomplete");
                result->TimerCoverageComplete = false;
            }
            else
            {
                result->TimerCoverageComplete = result->Timers.size() < timerLimit;
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
