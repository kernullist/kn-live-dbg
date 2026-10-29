#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "HiddenProcessReport.h"

#include <cstdint>
#include <string>
#include <vector>

class HiddenProcessScanner
{
public:
    HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(HiddenProcessScanResult* result, std::wstring* error);
    bool Scan(
        HiddenProcessScanResult* result,
        const std::vector<uint32_t>& extraCandidatePids,
        std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

bool HiddenProcessViewSelfTest();
