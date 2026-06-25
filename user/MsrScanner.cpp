#include "MsrScanner.h"
#include "McpJson.h"

#include <cstdio>
#include <sstream>

#include "../shared/KnLiveDbgIoctl.h"

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool AddressInLoadedModule(SymbolEngine& symbols, uint64_t address)
    {
        bool inside = false;

        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                inside = true;
                break;
            }
        }

        return inside;
    }

    void AnnotateAddress(
        SymbolEngine& symbols,
        uint64_t address,
        std::wstring* moduleName,
        std::wstring* symbolName)
    {
        if (moduleName != nullptr)
        {
            moduleName->clear();
        }
        if (symbolName != nullptr)
        {
            symbolName->clear();
        }

        do
        {
            if (address == 0 || !IsKernelAddress(address))
            {
                break;
            }

            for (const KernelModuleInfo& module : symbols.Modules())
            {
                uint64_t end = module.Base + module.Size;
                if (end < module.Base)
                {
                    continue;
                }
                if (address >= module.Base && address < end)
                {
                    if (moduleName != nullptr)
                    {
                        *moduleName = module.ImageName;
                    }
                    break;
                }
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
            {
                if (symbolName != nullptr)
                {
                    std::wstringstream stream;
                    stream << nearest;
                    if (displacement != 0)
                    {
                        stream << L"+0x" << std::hex << displacement;
                    }
                    *symbolName = stream.str();
                }
            }
        } while (false);
    }

    void AppendNote(std::wstring* notes, const std::wstring& text)
    {
        if (notes == nullptr)
        {
            return;
        }
        if (!notes->empty())
        {
            *notes += L"; ";
        }
        *notes += text;
    }

    struct MsrSpec
    {
        uint32_t Index;
        const wchar_t* Name;
        bool IsPointer;
    };
}

MsrScanner::MsrScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool MsrScanner::Scan(MsrScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid MSR scan result output";
            }
            break;
        }

        *result = MsrScanResult{};

        // Iterate every active logical processor across all groups; the driver
        // pins to the matching system-wide processor index, so >64-processor
        // (multi-group) machines are fully covered.
        uint32_t cpuCount = static_cast<uint32_t>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        if (cpuCount == 0)
        {
            cpuCount = 1;
        }
        result->ProcessorCount = cpuCount;

        uint64_t kiSystemCall64 = 0;
        symbols_.ResolveSymbol(L"nt!KiSystemCall64", &kiSystemCall64, nullptr);
        uint64_t kiSystemCall32 = 0;
        symbols_.ResolveSymbol(L"nt!KiSystemCall32", &kiSystemCall32, nullptr);

        const MsrSpec specs[] =
        {
            { KNDBG_MSR_IA32_LSTAR, L"IA32_LSTAR", true },
            { KNDBG_MSR_IA32_CSTAR, L"IA32_CSTAR", true },
            { KNDBG_MSR_IA32_STAR,  L"IA32_STAR",  false },
            { KNDBG_MSR_IA32_FMASK, L"IA32_FMASK", false },
            { KNDBG_MSR_IA32_EFER,  L"IA32_EFER",  false }
        };

        for (const MsrSpec& spec : specs)
        {
            MsrReading reading = {};
            reading.MsrIndex = spec.Index;
            reading.MsrName = spec.Name;
            reading.IsPointer = spec.IsPointer;

            bool anyRead = false;
            uint64_t firstValue = 0;
            for (uint32_t cpu = 0; cpu < cpuCount; ++cpu)
            {
                uint64_t value = 0;
                uint32_t actual = 0;
                std::wstring readError;
                if (!device_.ReadMsr(spec.Index, cpu, &value, &actual, &readError))
                {
                    reading.ReadFailed = true;
                    result->Warnings.push_back(
                        reading.MsrName + L": read failed on cpu " + std::to_wstring(cpu) + L": " + readError);
                    continue;
                }

                if (!anyRead)
                {
                    firstValue = value;
                    anyRead = true;
                }
                else if (value != firstValue)
                {
                    reading.Divergent = true;
                }

                reading.PerCpuValues.push_back(value);
            }

            if (!anyRead)
            {
                result->Readings.push_back(reading);
                continue;
            }

            uint64_t primary = firstValue;

            // The kernel programs every SYSCALL-configuration MSR identically
            // on all cores; a per-CPU divergence is a single-core hook signal.
            if (reading.Divergent)
            {
                reading.Suspicious = true;
                result->AnySuspicious = true;
                AppendNote(&reading.Notes, L"value diverges across processors (kernel programs these MSRs uniformly)");
            }

            if (spec.IsPointer)
            {
                AnnotateAddress(symbols_, primary, &reading.OwningModule, &reading.NearestSymbol);
                reading.PointsIntoKernelModule = AddressInLoadedModule(symbols_, primary);

                if (spec.Index == KNDBG_MSR_IA32_LSTAR)
                {
                    if (kiSystemCall64 != 0)
                    {
                        if (primary != kiSystemCall64)
                        {
                            reading.Suspicious = true;
                            result->AnySuspicious = true;
                            AppendNote(&reading.Notes, L"LSTAR does not point to nt!KiSystemCall64 (possible SYSCALL hook)");
                        }
                    }
                    else if (!reading.PointsIntoKernelModule)
                    {
                        reading.Suspicious = true;
                        result->AnySuspicious = true;
                        AppendNote(&reading.Notes, L"LSTAR target outside loaded kernel modules");
                    }
                }
                else // CSTAR
                {
                    // CSTAR is often 0 on Intel (compat-mode SYSCALL unused), so
                    // only a non-zero target that escapes the loaded modules is
                    // treated as suspicious.
                    if (primary == 0)
                    {
                        AppendNote(&reading.Notes, L"CSTAR is 0 (compat-mode SYSCALL unused)");
                    }
                    else if (kiSystemCall32 != 0 && primary != kiSystemCall32 && !reading.PointsIntoKernelModule)
                    {
                        reading.Suspicious = true;
                        result->AnySuspicious = true;
                        AppendNote(&reading.Notes, L"CSTAR target outside loaded kernel modules");
                    }
                    else if (kiSystemCall32 == 0 && !reading.PointsIntoKernelModule)
                    {
                        reading.Suspicious = true;
                        result->AnySuspicious = true;
                        AppendNote(&reading.Notes, L"CSTAR target outside loaded kernel modules");
                    }
                }
            }

            result->Readings.push_back(reading);
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring MsrJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildMsrJson(const MsrScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.msr.v1\",\"processorCount\":";
    out += std::to_wstring(result.ProcessorCount);
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"readings\":[";

    for (size_t index = 0; index < result.Readings.size(); ++index)
    {
        const MsrReading& reading = result.Readings[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"msrIndex\":" + mcpjson::Quote(MsrJsonHex(reading.MsrIndex));
        out += L",\"msrName\":" + mcpjson::Quote(reading.MsrName);
        out += L",\"perCpuValues\":[";
        for (size_t valueIndex = 0; valueIndex < reading.PerCpuValues.size(); ++valueIndex)
        {
            if (valueIndex > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(MsrJsonHex(reading.PerCpuValues[valueIndex]));
        }
        out += L"]";
        out += L",\"isPointer\":";
        out += reading.IsPointer ? L"true" : L"false";
        out += L",\"divergent\":";
        out += reading.Divergent ? L"true" : L"false";
        out += L",\"readFailed\":";
        out += reading.ReadFailed ? L"true" : L"false";
        out += L",\"pointsIntoKernelModule\":";
        out += reading.PointsIntoKernelModule ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += reading.Suspicious ? L"true" : L"false";
        if (!reading.OwningModule.empty())
        {
            out += L",\"owningModule\":" + mcpjson::Quote(reading.OwningModule);
        }
        if (!reading.NearestSymbol.empty())
        {
            out += L",\"nearestSymbol\":" + mcpjson::Quote(reading.NearestSymbol);
        }
        if (!reading.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(reading.Notes);
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
