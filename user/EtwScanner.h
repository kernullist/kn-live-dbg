#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct EtwLoggerRecord
{
    uint32_t Slot = 0;
    uint64_t ContextAddress = 0;
    std::wstring Name;
    uint64_t GetCpuClockRaw = 0;
    uint32_t GetCpuClockMode = 0xffffffffu;
    std::wstring GetCpuClockModeText;
    uint64_t GetCpuClockCallback = 0;
    std::wstring GetCpuClockModule;
    std::wstring GetCpuClockSymbol;
    std::wstring GetCpuClockCallbackSource;
    std::wstring Notes;
    bool HasGetCpuClockRaw = false;
    bool HasGetCpuClockMode = false;
    bool HasGetCpuClockCallback = false;
    bool Suspicious = false;
};

struct EtwScanResult
{
    std::vector<EtwLoggerRecord> Loggers;
    std::vector<std::wstring>    Warnings;
    std::wstring LoggerArraySource;
    uint64_t DebuggerDataAddress = 0;
    uint64_t SiloStateAddress = 0;
    uint64_t LoggerArrayBase = 0;
    uint32_t SlotCount = 0;
    uint32_t NonCanonicalSlotCount = 0;
    bool     DebuggerDataResolved = false;
    bool     LayoutFromPdb = false;
    bool     UsedSiloPath = false;
    uint64_t LoggerNameOffset = 0;
    uint64_t GetCpuClockOffset = 0;
};

class EtwScanner
{
public:
    enum class Scope
    {
        Loggers,
        Logger
    };

    struct Options
    {
        Scope    Target = Scope::Loggers;
        std::wstring NameFilter;
        uint32_t IndexFilter = 0;
        bool     HasIndexFilter = false;
    };

    EtwScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, EtwScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
