#include "CrScanner.h"
#include "McpJson.h"

#include <cstdio>

namespace
{
    constexpr uint64_t kCr0Wp = 1ull << 16;  // write protect
    constexpr uint64_t kCr4Smep = 1ull << 20;
    constexpr uint64_t kCr4Smap = 1ull << 21;

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

    // Reads one control register across all processors into a CrReading,
    // tracking per-CPU divergence.
    CrReading SampleRegister(const std::wstring& name, const std::vector<ControlRegisters>& perCpu, uint64_t ControlRegisters::* member)
    {
        CrReading reading = {};
        reading.Name = name;

        bool first = true;
        uint64_t firstValue = 0;
        for (const ControlRegisters& regs : perCpu)
        {
            uint64_t value = regs.*member;
            if (first)
            {
                firstValue = value;
                first = false;
            }
            else if (value != firstValue)
            {
                reading.Divergent = true;
            }
            reading.PerCpuValues.push_back(value);
        }

        return reading;
    }
}

CrScanner::CrScanner(DeviceClient& device) :
    device_(device)
{
}

bool CrScanner::Scan(CrScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid CR scan result output";
            }
            break;
        }

        *result = CrScanResult{};

        uint32_t cpuCount = static_cast<uint32_t>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        if (cpuCount == 0)
        {
            cpuCount = 1;
        }
        result->ProcessorCount = cpuCount;

        std::vector<ControlRegisters> perCpu;
        perCpu.reserve(cpuCount);
        for (uint32_t cpu = 0; cpu < cpuCount; ++cpu)
        {
            ControlRegisters regs = {};
            std::wstring readError;
            if (!device_.ReadControlRegisters(cpu, &regs, &readError))
            {
                result->Warnings.push_back(L"control register read failed on cpu " + std::to_wstring(cpu) + L": " + readError);
                continue;
            }
            perCpu.push_back(regs);
        }

        if (perCpu.empty())
        {
            if (error != nullptr)
            {
                *error = L"no control registers could be read";
            }
            break;
        }

        CrReading cr0 = SampleRegister(L"CR0", perCpu, &ControlRegisters::Cr0);
        CrReading cr4 = SampleRegister(L"CR4", perCpu, &ControlRegisters::Cr4);
        CrReading cr8 = SampleRegister(L"CR8", perCpu, &ControlRegisters::Cr8);

        uint64_t cr0Value = cr0.PerCpuValues.front();
        if ((cr0Value & kCr0Wp) == 0)
        {
            cr0.Suspicious = true;
            result->AnySuspicious = true;
            AppendNote(&cr0.Notes, L"CR0.WP disabled (kernel write-protect off; enables code patching)");
        }
        if (cr0.Divergent)
        {
            cr0.Suspicious = true;
            result->AnySuspicious = true;
            AppendNote(&cr0.Notes, L"CR0 diverges across processors");
        }

        uint64_t cr4Value = cr4.PerCpuValues.front();
        if ((cr4Value & kCr4Smep) == 0)
        {
            // Not flagged SUSPICIOUS on its own (legacy CPUs may lack SMEP), but
            // surfaced prominently for operator judgement.
            AppendNote(&cr4.Notes, L"SMEP disabled (exploit-mitigation weakened; expected enabled on modern Windows)");
        }
        if ((cr4Value & kCr4Smap) == 0)
        {
            AppendNote(&cr4.Notes, L"SMAP disabled (exploit-mitigation weakened; expected enabled on modern Windows)");
        }
        if (cr4.Divergent)
        {
            cr4.Suspicious = true;
            result->AnySuspicious = true;
            AppendNote(&cr4.Notes, L"CR4 diverges across processors");
        }

        result->Readings.push_back(cr0);
        result->Readings.push_back(cr4);
        result->Readings.push_back(cr8);

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring CrJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildCrJson(const CrScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.cr.v1\",\"processorCount\":";
    out += std::to_wstring(result.ProcessorCount);
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"readings\":[";

    for (size_t index = 0; index < result.Readings.size(); ++index)
    {
        const CrReading& reading = result.Readings[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"name\":" + mcpjson::Quote(reading.Name);
        out += L",\"perCpuValues\":[";
        for (size_t valueIndex = 0; valueIndex < reading.PerCpuValues.size(); ++valueIndex)
        {
            if (valueIndex > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(CrJsonHex(reading.PerCpuValues[valueIndex]));
        }
        out += L"]";
        out += L",\"divergent\":";
        out += reading.Divergent ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += reading.Suspicious ? L"true" : L"false";
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
