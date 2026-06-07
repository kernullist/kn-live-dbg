#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct FirmwareTableProviderRecord
{
    uint32_t Slot = 0;
    uint32_t ProviderSignature = 0;
    uint8_t RegisterFlag = 0;
    uint64_t NodeAddress = 0;
    uint64_t ListEntry = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    uint64_t FirmwareTableHandler = 0;
    uint64_t DriverObject = 0;
    uint64_t DriverStart = 0;
    uint32_t DriverSize = 0;
    std::wstring ProviderText;
    std::wstring HandlerModule;
    std::wstring HandlerSymbol;
    std::wstring DriverModule;
    std::wstring DriverName;
    std::wstring Notes;
    bool StandardProvider = false;
    bool Suspicious = false;
};

struct FirmwareTableScanResult
{
    std::vector<FirmwareTableProviderRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t ListHeadAddress = 0;
    uint64_t ResourceAddress = 0;
    std::wstring ListHeadSymbol;
    std::wstring ResourceSymbol;
    std::wstring LayoutName;
    bool UsedFallbackLayout = true;
};

class FirmwareTableScanner
{
public:
    FirmwareTableScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(FirmwareTableScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
