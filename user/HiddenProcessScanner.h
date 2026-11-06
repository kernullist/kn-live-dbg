#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "HiddenProcessReport.h"
#include "HiddenProcessScheduler.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

class HiddenProcessScanner
{
public:
    HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols,
        HiddenProcessScheduler& scheduler, const std::atomic<bool>* cancelled = nullptr);

    bool Scan(HiddenProcessScanResult* result, std::wstring* error);
    bool Scan(
        HiddenProcessScanResult* result,
        const std::vector<uint32_t>& extraCandidatePids,
        std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
    HiddenProcessScheduler& scheduler_;
    const std::atomic<bool>* cancelled_;
};

bool HiddenProcessViewSelfTest();
