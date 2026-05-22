#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct NmiCallbackRecord
{
    uint32_t Slot = 0;
    uint64_t NodeAddress = 0;
    uint64_t Callback = 0;
    uint64_t Context = 0;
    uint64_t Handle = 0;
    std::wstring CallbackModule;
    std::wstring CallbackSymbol;
    std::wstring Notes;
    bool Suspicious = false;
};

struct NmiScanResult
{
    std::vector<NmiCallbackRecord> Callbacks;
    std::vector<std::wstring>      Warnings;
    uint64_t ListHeadAddress = 0;
    uint64_t FirstNodeAddress = 0;
    std::wstring ListHeadSymbol;
    bool     ListHeadResolved = false;
};

class NmiScanner
{
public:
    NmiScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(NmiScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
