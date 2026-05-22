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

struct EtwIntegrityFinding
{
    uint32_t InstructionIndex = 0;
    uint32_t InstructionOffset = 0;
    std::wstring Mnemonic;
    uint64_t Target = 0;
    std::wstring TargetModule;
    std::wstring TargetSymbol;
    std::wstring Reason;
    bool HasTarget = false;
    bool TargetInLoadedModule = false;
};

struct EtwIntegrityRecord
{
    std::wstring Symbol;
    std::wstring Description;
    std::wstring OwningModule;
    std::wstring HeadBytesHex;
    std::wstring DisassemblySummary;
    uint64_t Address = 0;
    uint32_t InstructionsAnalyzed = 0;
    std::vector<EtwIntegrityFinding> Findings;
    bool SymbolResolved = false;
    bool BytesRead = false;
    bool DecodeOk = false;
};

struct EtwIntegrityResult
{
    std::vector<EtwIntegrityRecord> Records;
    std::vector<std::wstring>       Warnings;
};

class EtwScanner
{
public:
    enum class Scope
    {
        Loggers,
        Logger,
        Integrity
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
    bool ScanIntegrity(EtwIntegrityResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
