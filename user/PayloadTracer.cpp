#include "PayloadTracer.h"

#include "CallbackScanner.h"
#include "DpcTimerScanner.h"
#include "EtwScanner.h"
#include "FirmwareTableScanner.h"
#include "HalDispatchScanner.h"
#include "IdtScanner.h"
#include "IntegrityScanner.h"
#include "McpJson.h"
#include "MsrScanner.h"
#include "NmiScanner.h"
#include "SsdtScanner.h"
#include "WfpCalloutScanner.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace
{
    constexpr uint32_t kMaxDisasmInstructions = 32;
    constexpr uint32_t kMaxDisasmBytes = 128;
    constexpr uint32_t kDefaultScanLimit = 16;
    constexpr uint32_t kMaxScanLimit = 128;

    void AddPointer(
        std::vector<PayloadHookPointer>* pointers,
        uint64_t address,
        const std::wstring& source)
    {
        if (pointers == nullptr || address == 0 || !LeftoverIsKernelCanonical(address))
        {
            return;
        }

        PayloadHookPointer item = {};
        item.Address = address;
        item.Source = source;
        pointers->push_back(item);
    }

    bool KeepPayloadScanRecord(const PayloadTraceRecord& record)
    {
        bool keep = false;
        if (record.Risk == L"high")
        {
            keep = true;
        }
        else if (record.PeProbed && record.Pe.IsPe)
        {
            keep = true;
        }
        else if (record.Inspect.EffectiveExecutable)
        {
            keep = true;
        }

        return keep;
    }

}

std::wstring ClassifyPayloadRecord(const PayloadTraceRecord& record)
{
    std::wstring classification = L"unknown";

    do
    {
        if (!LeftoverIsKernelCanonical(record.Address))
        {
            classification = LeftoverIsLikelyUserAddress(record.Address)
                ? L"user"
                : L"noncanonical";
            break;
        }
        if (record.InLoadedModule)
        {
            classification = L"inside_module";
            break;
        }
        if (!record.Inspect.TranslationSucceeded || !record.Inspect.EffectivePresent)
        {
            classification = L"unmapped";
            break;
        }
        if (record.PeProbed && record.Pe.IsPe)
        {
            classification = record.InBigPool ? L"big_pool_pe" : L"unbacked_pe";
            break;
        }
        if (record.InBigPool)
        {
            classification = L"big_pool";
            break;
        }
        if (LeftoverIsSessionSpace(record.Address))
        {
            classification = L"session";
            break;
        }
        if (!record.Inspect.EffectiveExecutable)
        {
            classification = L"nonexec_kernel_pointer";
            break;
        }
        classification = L"independent_or_untracked";
    } while (false);

    return classification;
}

std::wstring RiskForPayloadRecord(const PayloadTraceRecord& record)
{
    std::wstring risk = L"low";

    do
    {
        if (record.Classification == L"user" ||
            record.Classification == L"noncanonical" ||
            record.Classification == L"inside_module")
        {
            risk = L"low";
            break;
        }
        if (record.Classification == L"unmapped")
        {
            risk = L"medium";
            break;
        }
        if (record.Inspect.EffectivePresent &&
            record.Inspect.EffectiveWritable &&
            record.Inspect.EffectiveExecutable)
        {
            risk = L"high";
            break;
        }
        if (record.PeProbed && record.Pe.IsPe)
        {
            risk = L"high";
            break;
        }
        if (record.Classification == L"independent_or_untracked" ||
            record.Classification == L"big_pool")
        {
            risk = record.Inspect.EffectiveExecutable ? L"high" : L"medium";
            break;
        }
        if (record.Classification == L"session")
        {
            risk = L"medium";
            break;
        }
        if (record.Classification == L"nonexec_kernel_pointer")
        {
            risk = L"low";
            break;
        }
    } while (false);

    return risk;
}

void ProbePeAt(
    DeviceClient& device,
    uint64_t address,
    PayloadTraceRecord* record)
{
    do
    {
        if (record == nullptr || address == 0)
        {
            break;
        }

        std::vector<uint8_t> bytes;
        std::wstring ignored;
        if (!device.ReadMemory(address, 0x1000, &bytes, &ignored) ||
            bytes.size() < 0x40)
        {
            break;
        }

        PeHeaderProbe probe = {};
        if (!ProbeForPageStartPeHeader(bytes.data(), bytes.size(), &probe) || !probe.IsPe)
        {
            break;
        }

        record->PeProbed = true;
        record->Pe = probe;
        record->PeProbeAddress = address;
    } while (false);
}

PayloadTracer::PayloadTracer(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool PayloadTracer::TraceAddress(
    uint64_t address,
    const std::wstring& source,
    const PayloadTraceOptions& options,
    PayloadTraceRecord* record,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (record == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"payload trace output is null";
            }
            break;
        }

        *record = PayloadTraceRecord{};
        record->Address = address;
        record->Source = source.empty() ? L"user" : source;

        if (!modulesReady_)
        {
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
            modulesReady_ = true;
        }

        if (!poolReady_)
        {
            std::wstring poolError;
            if (!LeftoverQueryBigPool(&pool_, &poolError))
            {
                if (!poolError.empty())
                {
                    LeftoverAppendNote(&record->Notes, L"big pool query failed: " + poolError);
                }
            }
            poolReady_ = true;
        }

        const LeftoverModuleRange* module = LeftoverFindModule(modules_, address);
        if (module != nullptr)
        {
            record->InLoadedModule = true;
            record->ModuleName = module->Name;
            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols_.FindNearestSymbol(address, &nearest, &displacement, &ignored) &&
                !nearest.empty())
            {
                std::wstringstream stream;
                stream << nearest;
                if (displacement != 0)
                {
                    stream << L"+0x" << std::hex << displacement;
                }
                record->SymbolName = stream.str();
            }
        }

        bool present = false;
        bool writable = false;
        bool executable = false;
        uint64_t physical = 0;
        if (LeftoverProbePagePermissions(
                device_,
                address,
                &present,
                &writable,
                &executable,
                &physical))
        {
            record->Inspect.TranslationAttempted = true;
            record->Inspect.TranslationSucceeded = true;
            record->Inspect.EffectivePresent = present;
            record->Inspect.EffectiveWritable = writable;
            record->Inspect.EffectiveExecutable = executable;
            record->Inspect.PhysicalAddress = physical;
        }
        else
        {
            record->Inspect.TranslationAttempted = true;
            LeftoverAppendNote(&record->Notes, L"page-table translate failed");
        }

        const LeftoverBigPoolEntry* pool = LeftoverFindBigPool(pool_, address);
        if (pool != nullptr)
        {
            record->InBigPool = true;
            record->PoolAddress = pool->VirtualAddress;
            record->PoolSize = pool->SizeInBytes;
            record->PoolTag = pool->TagRaw;
            record->PoolNonPaged = pool->NonPaged;
        }

        if (record->InBigPool)
        {
            ProbePeAt(device_, record->PoolAddress, record);
        }
        if (!record->PeProbed)
        {
            ProbePeAt(device_, address & ~0xFFFull, record);
        }

        uint32_t instructionCount = options.DisasmInstructions;
        if (instructionCount == 0)
        {
            instructionCount = 16;
        }
        if (instructionCount > kMaxDisasmInstructions)
        {
            instructionCount = kMaxDisasmInstructions;
        }

        const bool skipDisasm = options.ScanHooks && !record->Inspect.EffectiveExecutable;
        std::vector<uint8_t> code;
        std::wstring readError;
        if (skipDisasm)
        {
            LeftoverAppendNote(&record->Notes, L"skipped disasm; pointer is not executable");
        }
        else if (device_.ReadMemory(address, kMaxDisasmBytes, &code, &readError) &&
            !code.empty())
        {
            std::wstring disasmError;
            if (DisassembleX64CodeBytes(
                    address,
                    code,
                    instructionCount,
                    &record->Disasm,
                    &disasmError))
            {
                record->DisasmOk = record->Disasm.InstructionsDecoded != 0;
            }
            else if (!disasmError.empty())
            {
                LeftoverAppendNote(&record->Notes, disasmError);
            }
        }
        else if (!readError.empty())
        {
            LeftoverAppendNote(&record->Notes, L"code read failed: " + readError);
        }

        record->Classification = ClassifyPayloadRecord(*record);
        record->Risk = RiskForPayloadRecord(*record);
        if (record->Inspect.EffectivePresent &&
            record->Inspect.EffectiveWritable &&
            record->Inspect.EffectiveExecutable)
        {
            LeftoverAppendNote(&record->Notes, L"effective W+X");
        }
        if (record->PeProbed && record->Pe.IsPe)
        {
            std::wstring peNote = L"PE header";
            if (record->Pe.MzWiped || record->Pe.PeSignatureWiped || record->Pe.ELfanewMismatch)
            {
                peNote += L" wiped";
            }
            LeftoverAppendNote(&record->Notes, peNote);
        }
        if (!record->InLoadedModule && LeftoverIsKernelCanonical(address))
        {
            LeftoverAppendNote(&record->Notes, L"outside loaded modules");
        }

        ok = true;
    } while (false);

    return ok;
}

void PayloadTracer::CollectHookPointers(
    std::vector<PayloadHookPointer>* pointers,
    PayloadTraceResult* result)
{
    if (pointers == nullptr || result == nullptr)
    {
        return;
    }

    bool anyFailed = false;

    do
    {
        KernelCallbackScanner callbacks(device_, symbols_);
        KernelCallbackScanResult callbackResult = {};
        std::wstring error;
        if (callbacks.Scan(L"all", &callbackResult, &error))
        {
            for (const KernelCallbackRecord& record : callbackResult.Records)
            {
                if (record.Function != 0 && record.FunctionModule.empty())
                {
                    AddPointer(pointers, record.Function, L"callbacks:" + record.Kind);
                }
                if (record.PostFunction != 0 && record.PostFunctionModule.empty())
                {
                    AddPointer(pointers, record.PostFunction, L"callbacks:" + record.Kind + L":post");
                }
            }
            if (callbackResult.Incomplete)
            {
                result->CoverageNotes.push_back(L"callbacks walk was incomplete");
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(
                error.empty() ? L"callbacks scan failed" : L"callbacks: " + error);
        }

        SsdtScanner ssdt(device_, symbols_);
        SsdtScanResult ssdtResult = {};
        if (ssdt.Scan(&ssdtResult, &error))
        {
            for (const SsdtTable& table : ssdtResult.Tables)
            {
                for (const SsdtEntry& entry : table.Entries)
                {
                    if (entry.Suspicious && entry.Module.empty())
                    {
                        AddPointer(pointers, entry.Routine, L"ssdt:" + table.Name);
                    }
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"ssdt scan failed" : L"ssdt: " + error);
        }

        IdtScanner idt(device_, symbols_);
        IdtScanResult idtResult = {};
        if (idt.Scan(&idtResult, &error))
        {
            for (const IdtEntry& entry : idtResult.Entries)
            {
                if (entry.Suspicious && entry.Module.empty())
                {
                    AddPointer(pointers, entry.Handler, L"idt");
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"idt scan failed" : L"idt: " + error);
        }

        NmiScanner nmi(device_, symbols_);
        NmiScanResult nmiResult = {};
        if (nmi.Scan(&nmiResult, &error))
        {
            for (const NmiCallbackRecord& record : nmiResult.Callbacks)
            {
                if (record.Suspicious && record.CallbackModule.empty())
                {
                    AddPointer(pointers, record.Callback, L"nmi");
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"nmi scan failed" : L"nmi: " + error);
        }

        HalDispatchScanner hal(device_, symbols_);
        HalDispatchScanResult halResult = {};
        HalDispatchScanner::Options halOptions = {};
        if (hal.Scan(halOptions, &halResult, &error))
        {
            for (const HalDispatchTable& table : halResult.Tables)
            {
                for (const HalDispatchSlot& slot : table.Slots)
                {
                    if (slot.Suspicious && slot.Module.empty())
                    {
                        AddPointer(pointers, slot.Routine, L"hal:" + table.Name);
                    }
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"hal scan failed" : L"hal: " + error);
        }

        MsrScanner msr(device_, symbols_);
        MsrScanResult msrResult = {};
        if (msr.Scan(&msrResult, &error))
        {
            for (const MsrReading& reading : msrResult.Readings)
            {
                if (reading.IsPointer &&
                    reading.Suspicious &&
                    !reading.PointsIntoKernelModule &&
                    !reading.PerCpuValues.empty())
                {
                    AddPointer(pointers, reading.PerCpuValues.front(), L"msr:" + reading.MsrName);
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"msr scan failed" : L"msr: " + error);
        }

        EtwScanner etw(device_, symbols_);
        EtwScanner::Options etwOptions = {};
        EtwScanResult etwResult = {};
        if (etw.Scan(etwOptions, &etwResult, &error))
        {
            for (const EtwLoggerRecord& logger : etwResult.Loggers)
            {
                if (logger.Suspicious &&
                    logger.HasGetCpuClockCallback &&
                    logger.GetCpuClockModule.empty())
                {
                    AddPointer(pointers, logger.GetCpuClockCallback, L"etw:GetCpuClock");
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"etw scan failed" : L"etw: " + error);
        }

        EtwIntegrityResult etwIntegrity = {};
        if (etw.ScanIntegrity(&etwIntegrity, &error))
        {
            for (const EtwIntegrityRecord& record : etwIntegrity.Records)
            {
                for (const EtwIntegrityFinding& finding : record.Findings)
                {
                    if (finding.HasTarget && !finding.TargetInLoadedModule)
                    {
                        AddPointer(pointers, finding.Target, L"etw-integrity:" + record.Symbol);
                    }
                }
            }
        }
        else
        {
            result->Warnings.push_back(
                error.empty() ? L"etw integrity scan failed" : L"etw integrity: " + error);
        }

        WfpCalloutScanner wfp(device_, symbols_);
        WfpCalloutScanResult wfpResult = {};
        if (wfp.Scan(&wfpResult, &error))
        {
            for (const WfpKernelCallout& callout : wfpResult.Callouts)
            {
                if (callout.ClassifySuspicious && callout.ClassifyModule.empty())
                {
                    AddPointer(pointers, callout.ClassifyFn, L"wfp:classify");
                }
                if (callout.NotifySuspicious && callout.NotifyModule.empty())
                {
                    AddPointer(pointers, callout.NotifyFn, L"wfp:notify");
                }
                if (callout.FlowDeleteSuspicious && callout.FlowDeleteModule.empty())
                {
                    AddPointer(pointers, callout.FlowDeleteFn, L"wfp:flowDelete");
                }
            }
            if (!wfpResult.CoverageComplete)
            {
                result->CoverageNotes.push_back(L"wfp kernel callout coverage is incomplete");
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"wfp scan failed" : L"wfp: " + error);
        }

        DpcTimerScanner dpc(device_, symbols_);
        DpcTimerScanner::Options dpcOptions = {};
        DpcTimerScanResult dpcResult = {};
        if (dpc.Scan(dpcOptions, &dpcResult, &error))
        {
            for (const DpcRoutineRecord& record : dpcResult.Dpcs)
            {
                if (record.Suspicious && record.Module.empty())
                {
                    AddPointer(pointers, record.Routine, L"dpc");
                }
            }
            for (const TimerRoutineRecord& record : dpcResult.Timers)
            {
                if (record.Suspicious && record.Module.empty())
                {
                    AddPointer(pointers, record.Routine, L"timer");
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(error.empty() ? L"dpc/timer scan failed" : L"dpc/timer: " + error);
        }

        IntegrityScanner integrity(device_, symbols_);
        DriverIntegrityOptions driverOptions = {};
        DriverIntegrityResult driverResult = {};
        if (integrity.ScanDrivers(driverOptions, &driverResult, &error))
        {
            for (const DriverIntegrityRecord& driver : driverResult.Records)
            {
                if (driver.HasDriverStart && driver.OwningModule.empty())
                {
                    AddPointer(pointers, driver.DriverStart, L"driver:" + driver.Name + L":start");
                }
                for (const DriverDispatchRecord& dispatch : driver.Dispatch)
                {
                    if (dispatch.Suspicious && !dispatch.InLoadedModule)
                    {
                        AddPointer(
                            pointers,
                            dispatch.Function,
                            L"driver:" + driver.Name + L":" + dispatch.Name);
                    }
                }
            }
        }
        else
        {
            anyFailed = true;
            result->Warnings.push_back(
                error.empty() ? L"driver integrity scan failed" : L"driver integrity: " + error);
        }

        FirmwareTableScanner firmware(device_, symbols_);
        FirmwareTableScanResult firmwareResult = {};
        if (firmware.Scan(&firmwareResult, &error))
        {
            for (const FirmwareTableProviderRecord& record : firmwareResult.Records)
            {
                if (record.Suspicious && record.HandlerModule.empty())
                {
                    AddPointer(pointers, record.FirmwareTableHandler, L"fwtable");
                }
            }
        }
        else
        {
            result->Warnings.push_back(
                error.empty() ? L"fwtable scan failed" : L"fwtable: " + error);
        }
    } while (false);

    result->HookSweepComplete = !anyFailed;
    if (anyFailed)
    {
        result->Incomplete = true;
    }
}

void PayloadTracer::TracePrepared(
    const std::vector<PayloadHookPointer>& pointers,
    const PayloadTraceOptions& options,
    PayloadTraceResult* result)
{
    if (result == nullptr)
    {
        return;
    }

    std::map<uint64_t, std::wstring> unique;
    for (const PayloadHookPointer& pointer : pointers)
    {
        auto existing = unique.find(pointer.Address);
        if (existing == unique.end())
        {
            unique[pointer.Address] = pointer.Source;
        }
        else if (existing->second.find(pointer.Source) == std::wstring::npos)
        {
            existing->second += L",";
            existing->second += pointer.Source;
        }
    }

    result->HookPointersSeen = pointers.size();
    result->UniqueUnbacked = unique.size();

    uint32_t limit = options.Limit;
    if (limit == 0)
    {
        limit = kDefaultScanLimit;
    }
    if (limit > kMaxScanLimit)
    {
        limit = kMaxScanLimit;
    }

    uint32_t traced = 0;
    for (const auto& item : unique)
    {
        if (traced >= limit)
        {
            result->Incomplete = true;
            result->Warnings.push_back(
                L"payload scan truncated after " + std::to_wstring(limit) +
                L" kept unbacked pointer(s); " +
                std::to_wstring(unique.size()) + L" unique address(es) observed");
            break;
        }

        PayloadTraceRecord record = {};
        std::wstring error;
        if (!TraceAddress(item.first, item.second, options, &record, &error))
        {
            result->Warnings.push_back(
                L"trace " + LeftoverFormatHex(item.first, 16) + L" failed: " + error);
            continue;
        }
        if (!KeepPayloadScanRecord(record))
        {
            ++result->FilteredLowRisk;
            continue;
        }
        result->Records.push_back(record);
        ++traced;
    }

    result->Traced = traced;
    result->BigPoolQueried = pool_.Queried;
    for (const std::wstring& warning : pool_.Warnings)
    {
        result->Warnings.push_back(warning);
    }
}

bool PayloadTracer::Scan(
    const PayloadTraceOptions& options,
    PayloadTraceResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"payload scan output is null";
            }
            break;
        }

        *result = PayloadTraceResult{};
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
        modulesReady_ = true;

        std::vector<PayloadHookPointer> pointers;
        CollectHookPointers(&pointers, result);
        TracePrepared(pointers, options, result);
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildPayloadTraceJson(const PayloadTraceResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.payload.v1\"";
    out += L",\"hookPointersSeen\":" + std::to_wstring(result.HookPointersSeen);
    out += L",\"uniqueUnbacked\":" + std::to_wstring(result.UniqueUnbacked);
    out += L",\"traced\":" + std::to_wstring(result.Traced);
    out += L",\"filteredLowRisk\":" + std::to_wstring(result.FilteredLowRisk);
    out += L",\"hookSweepComplete\":";
    out += result.HookSweepComplete ? L"true" : L"false";
    out += L",\"incomplete\":";
    out += result.Incomplete ? L"true" : L"false";
    out += L",\"bigPoolQueried\":";
    out += result.BigPoolQueried ? L"true" : L"false";
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const PayloadTraceRecord& record = result.Records[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"address\":" + mcpjson::Quote(LeftoverFormatHex(record.Address, 16));
        out += L",\"source\":" + mcpjson::Quote(record.Source);
        out += L",\"classification\":" + mcpjson::Quote(record.Classification);
        out += L",\"risk\":" + mcpjson::Quote(record.Risk);
        out += L",\"inLoadedModule\":";
        out += record.InLoadedModule ? L"true" : L"false";
        out += L",\"module\":" + mcpjson::Quote(record.ModuleName);
        out += L",\"symbol\":" + mcpjson::Quote(record.SymbolName);
        out += L",\"present\":";
        out += record.Inspect.EffectivePresent ? L"true" : L"false";
        out += L",\"writable\":";
        out += record.Inspect.EffectiveWritable ? L"true" : L"false";
        out += L",\"executable\":";
        out += record.Inspect.EffectiveExecutable ? L"true" : L"false";
        out += L",\"physical\":" + mcpjson::Quote(LeftoverFormatHex(record.Inspect.PhysicalAddress, 16));
        out += L",\"inBigPool\":";
        out += record.InBigPool ? L"true" : L"false";
        if (record.InBigPool)
        {
            out += L",\"poolAddress\":" + mcpjson::Quote(LeftoverFormatHex(record.PoolAddress, 16));
            out += L",\"poolSize\":" + std::to_wstring(record.PoolSize);
            out += L",\"poolTag\":" + mcpjson::Quote(LeftoverFormatTag(record.PoolTag));
            out += L",\"poolNonPaged\":";
            out += record.PoolNonPaged ? L"true" : L"false";
        }
        out += L",\"pe\":";
        out += (record.PeProbed && record.Pe.IsPe) ? L"true" : L"false";
        if (record.PeProbed && record.Pe.IsPe)
        {
            out += L",\"peAddress\":" + mcpjson::Quote(LeftoverFormatHex(record.PeProbeAddress, 16));
            out += L",\"peWiped\":";
            out += (record.Pe.MzWiped || record.Pe.PeSignatureWiped || record.Pe.ELfanewMismatch)
                ? L"true"
                : L"false";
        }
        out += L",\"disasm\":" + mcpjson::Quote(record.Disasm.Text);
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

bool PayloadTracerSelfTest()
{
    bool ok = true;

    do
    {
        PayloadTraceRecord record = {};
        record.Address = 0xFFFFC08000123000ull;
        record.Inspect.TranslationSucceeded = true;
        record.Inspect.EffectivePresent = true;
        record.Inspect.EffectiveWritable = true;
        record.Inspect.EffectiveExecutable = true;
        record.InBigPool = true;
        record.Classification = ClassifyPayloadRecord(record);
        if (record.Classification != L"big_pool")
        {
            ok = false;
            break;
        }
        if (RiskForPayloadRecord(record) != L"high")
        {
            ok = false;
            break;
        }

        record = PayloadTraceRecord{};
        record.Address = 0xFFFFF80012340000ull;
        record.InLoadedModule = true;
        record.Classification = ClassifyPayloadRecord(record);
        if (record.Classification != L"inside_module" || RiskForPayloadRecord(record) != L"low")
        {
            ok = false;
            break;
        }

        record = PayloadTraceRecord{};
        record.Address = 0xFFFF9886C6359900ull;
        record.Inspect.TranslationSucceeded = true;
        record.Inspect.EffectivePresent = true;
        record.Inspect.EffectiveWritable = true;
        record.Inspect.EffectiveExecutable = false;
        record.Classification = ClassifyPayloadRecord(record);
        if (record.Classification != L"nonexec_kernel_pointer" ||
            RiskForPayloadRecord(record) != L"low")
        {
            ok = false;
            break;
        }

        record.Inspect.EffectiveExecutable = true;
        record.Classification = ClassifyPayloadRecord(record);
        if (record.Classification != L"independent_or_untracked" ||
            RiskForPayloadRecord(record) != L"high")
        {
            ok = false;
            break;
        }
    } while (false);

    return ok;
}
