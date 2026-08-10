#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One function-pointer slot from HalDispatchTable or HalPrivateDispatchTable.
struct HalDispatchSlot
{
    uint32_t Index = 0;
    uint64_t SlotAddress = 0;
    uint64_t Routine = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool NullSlot = false;
    bool Suspicious = false;
    std::wstring Notes;
};

struct HalDispatchTable
{
    std::wstring Name;
    std::wstring Symbol;
    uint64_t Base = 0;
    uint32_t SlotCount = 0;
    uint32_t NonNullCount = 0;
    uint32_t SuspiciousCount = 0;
    bool Resolved = false;
    bool BoundFromPdb = false;
    std::vector<HalDispatchSlot> Slots;
    std::wstring Warning;
};

struct HalDispatchScanResult
{
    std::vector<HalDispatchTable> Tables;
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
    uint32_t SuspiciousCount = 0;
};

// Read-only ownership check for HAL dispatch function-pointer tables.
// Reuses DeviceClient::ReadMemory; no new driver IOCTL.
class HalDispatchScanner
{
public:
    enum class Scope
    {
        All,
        Dispatch,
        Private
    };

    struct Options
    {
        Scope Target = Scope::All;
        bool Verbose = false;
        uint32_t Limit = 0;
    };

    HalDispatchScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, HalDispatchScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildHalDispatchJson(const HalDispatchScanResult& result);
