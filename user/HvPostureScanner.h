#pragma once

#include "DeviceClient.h"

#include <cstdint>
#include <string>
#include <vector>

struct HvPostureScanResult
{
    bool CpuidHypervisorPresent = false;
    bool VmxSupported = false;
    bool SvmSupported = false;
    bool Cr4Vmxe = false;
    bool Cr4Queried = false;
    bool Cr4Divergent = false;
    std::wstring VendorSignature;
    uint32_t HvLeafBase = 0;
    uint32_t CpuidLeaf1Ecx = 0;
    uint64_t CpuidMedianTicks = 0;
    uint64_t NopMedianTicks = 0;
    uint32_t TimingSamples = 0;
    std::vector<uint64_t> Cr4Values;
    std::vector<std::wstring> Warnings;
    std::wstring Notes;
    bool TimingElevated = false;
    bool CoverageComplete = false;
};

class HvPostureScanner
{
public:
    explicit HvPostureScanner(DeviceClient* device);

    bool Scan(HvPostureScanResult* result, std::wstring* error);

private:
    DeviceClient* device_;
};

std::wstring BuildHvPostureJson(const HvPostureScanResult& result);
bool HvCpuidMaskSelfTest();
