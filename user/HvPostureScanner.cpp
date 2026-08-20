#include "HvPostureScanner.h"

#include "CrScanner.h"
#include "McpJson.h"

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <sstream>
#include <vector>

namespace
{
    constexpr uint64_t kCr4Vmxe = 1ull << 13;

    uint64_t Median(std::vector<uint64_t> values)
    {
        uint64_t median = 0;
        if (!values.empty())
        {
            std::sort(values.begin(), values.end());
            median = values[values.size() / 2];
        }
        return median;
    }

    std::wstring VendorFromCpuid()
    {
        int regs[4] = {};
        __cpuid(regs, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor + 0, &regs[1], sizeof(int));
        memcpy(vendor + 4, &regs[2], sizeof(int));
        memcpy(vendor + 8, &regs[3], sizeof(int));
        vendor[12] = 0;
        std::wstring text;
        for (size_t i = 0; i < 12 && vendor[i] != 0; ++i)
        {
            unsigned char ch = static_cast<unsigned char>(vendor[i]);
            if (ch >= 0x20 && ch < 0x7f)
            {
                text.push_back(static_cast<wchar_t>(ch));
            }
        }
        return text;
    }
}

HvPostureScanner::HvPostureScanner(DeviceClient* device) :
    device_(device)
{
}

bool HvPostureScanner::Scan(HvPostureScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid HV posture result output";
            }
            break;
        }

        *result = HvPostureScanResult{};
        int regs[4] = {};
        __cpuid(regs, 1);
        const uint32_t ecx = static_cast<uint32_t>(regs[2]);
        result->CpuidLeaf1Ecx = ecx;
        result->CpuidHypervisorPresent = (ecx & (1u << 31)) != 0;
        result->VmxSupported = (ecx & (1u << 5)) != 0;

        int extMax[4] = {};
        __cpuid(extMax, static_cast<int>(0x80000000));
        if (static_cast<uint32_t>(extMax[0]) >= 0x80000001u)
        {
            int ext[4] = {};
            __cpuid(ext, static_cast<int>(0x80000001));
            result->SvmSupported = (static_cast<uint32_t>(ext[2]) & (1u << 2)) != 0;
        }

        if (result->CpuidHypervisorPresent)
        {
            __cpuid(regs, 0x40000000);
            result->HvLeafBase = static_cast<uint32_t>(regs[0]);
            result->VendorSignature = VendorFromCpuid();
        }

        constexpr uint32_t kSamples = 16;
        std::vector<uint64_t> cpuidTicks;
        std::vector<uint64_t> nopTicks;
        cpuidTicks.reserve(kSamples);
        nopTicks.reserve(kSamples);
        for (uint32_t i = 0; i < kSamples; ++i)
        {
            int dummy[4] = {};
            unsigned int aux = 0;
            const uint64_t c0 = __rdtscp(&aux);
            __cpuid(dummy, 0);
            const uint64_t c1 = __rdtscp(&aux);
            cpuidTicks.push_back(c1 - c0);

            volatile int sink = 0;
            const uint64_t n0 = __rdtscp(&aux);
            sink += 1;
            const uint64_t n1 = __rdtscp(&aux);
            (void)sink;
            nopTicks.push_back(n1 - n0);
        }
        result->TimingSamples = kSamples;
        result->CpuidMedianTicks = Median(cpuidTicks);
        result->NopMedianTicks = Median(nopTicks);
        if (result->NopMedianTicks != 0 &&
            result->CpuidMedianTicks > (result->NopMedianTicks * 50ull))
        {
            result->TimingElevated = true;
            result->Notes = L"CPUID median latency is elevated versus a NOP baseline; telemetry only, not proof of a hypervisor";
        }

        if (device_ != nullptr && device_->IsOpen())
        {
            CrScanner cr(*device_);
            CrScanResult crResult = {};
            std::wstring crError;
            if (cr.Scan(&crResult, &crError))
            {
                for (const CrReading& reading : crResult.Readings)
                {
                    if (reading.Name != L"CR4")
                    {
                        continue;
                    }
                    result->Cr4Queried = !reading.PerCpuValues.empty();
                    result->Cr4Values = reading.PerCpuValues;
                    result->Cr4Divergent = reading.Divergent;
                    if (!reading.PerCpuValues.empty())
                    {
                        result->Cr4Vmxe = (reading.PerCpuValues.front() & kCr4Vmxe) != 0;
                    }
                }
            }
            else if (!crError.empty())
            {
                result->Warnings.push_back(L"CR4 query failed: " + crError);
            }
        }
        else
        {
            result->Warnings.push_back(
                L"CR4.VMXE was not sampled because the driver device is closed");
        }

        result->Warnings.push_back(
            L"IA32_FEATURE_CONTROL is not read; that MSR can #GP on AMD hosts");
        result->CoverageComplete = true;
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHvPostureJson(const HvPostureScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.hv-posture.v1\"";
    json << L",\"cpuid_hypervisor\":" << (result.CpuidHypervisorPresent ? L"true" : L"false");
    json << L",\"vmx\":" << (result.VmxSupported ? L"true" : L"false");
    json << L",\"svm\":" << (result.SvmSupported ? L"true" : L"false");
    json << L",\"cr4_vmxe\":" << (result.Cr4Vmxe ? L"true" : L"false");
    json << L",\"cr4_queried\":" << (result.Cr4Queried ? L"true" : L"false");
    json << L",\"vendor\":\"" << mcpjson::Escape(result.VendorSignature) << L"\"";
    json << L",\"cpuid_median_ticks\":" << result.CpuidMedianTicks;
    json << L",\"nop_median_ticks\":" << result.NopMedianTicks;
    json << L",\"timing_elevated\":" << (result.TimingElevated ? L"true" : L"false");
    json << L",\"notes\":\"" << mcpjson::Escape(result.Notes) << L"\"";
    json << L",\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << mcpjson::Escape(result.Warnings[i]) << L"\"";
    }
    json << L"]}";
    return json.str();
}

bool HvCpuidMaskSelfTest()
{
    bool ok = false;

    do
    {
        uint32_t hypervisor = 0;
        hypervisor = 1u << 31;
        uint32_t vmx = 0;
        vmx = 1u << 5;
        uint32_t combined = hypervisor | vmx;
        if ((combined & hypervisor) == 0 || (combined & vmx) == 0)
        {
            break;
        }
        if ((combined & hypervisor & vmx) != 0)
        {
            break;
        }
        uint64_t cr4Bit = 0;
        cr4Bit = 1ull << 13;
        if ((kCr4Vmxe & cr4Bit) == 0)
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}
