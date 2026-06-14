#include "MsrScanner.h"

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

        // Iterate processors in group 0; the driver clamps to the same group's
        // active count. Multi-group (>64 logical processors) systems are not
        // fully covered by this first slice.
        uint32_t cpuCount = static_cast<uint32_t>(GetActiveProcessorCount(0));
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
