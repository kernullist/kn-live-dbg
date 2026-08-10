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

// Best-effort ETW provider registration surface. Full tree reconstruction is
// not guaranteed across builds; CoverageComplete must be trusted over empty.
struct EtwProviderRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    std::wstring GuidText;
    uint64_t EnableCallback = 0;
    std::wstring EnableCallbackModule;
    std::wstring EnableCallbackSymbol;
    uint64_t RegEntry = 0;
    bool Suspicious = false;
    std::wstring Notes;
};

struct EtwProviderScanResult
{
    std::vector<EtwProviderRecord> Providers;
    std::vector<std::wstring> Warnings;
    uint64_t AnchorAddress = 0;
    std::wstring AnchorSymbol;
    bool AnchorResolved = false;
    bool CoverageComplete = false;
    bool LayoutFromPdb = false;
    uint32_t SuspiciousCount = 0;
    bool AnySuspicious = false;
    uint32_t UserModeProviderCount = 0;
    bool UserModeEnumerationOk = false;
};

// Correlates Threat-Intelligence subscription health with kernel ETW evidence.
struct EtwTiCrossInput
{
    bool TiActive = false;
    bool PplAntimalware = false;
    uint64_t EventsReceived = 0;
    uint64_t EventsKept = 0;
    uint64_t EventsDropped = 0;
    uint64_t StartTickMs = 0;
    uint64_t LastEventTickMs = 0;
    uint64_t NowTickMs = 0;
    uint64_t MinSilentSeconds = 15;
};

struct EtwTiCrossResult
{
    bool TiActive = false;
    bool Skipped = false;
    bool Suspicious = false;
    std::wstring Status; // skipped | silent | healthy | dropping | starting
    std::wstring Reason;
    double EventsPerSecond = 0.0;
    uint64_t EventsReceived = 0;
    uint64_t EventsDropped = 0;
    uint64_t ElapsedSeconds = 0;
    uint64_t SecondsSinceLastEvent = 0;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> Notes;
};

class EtwScanner
{
public:
    enum class Scope
    {
        Loggers,
        Logger,
        Integrity,
        Providers,
        TiCross
    };

    struct Options
    {
        Scope    Target = Scope::Loggers;
        std::wstring NameFilter;
        uint32_t IndexFilter = 0;
        bool     HasIndexFilter = false;
        uint32_t Limit = 0;
    };

    EtwScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, EtwScanResult* result, std::wstring* error);
    bool ScanIntegrity(EtwIntegrityResult* result, std::wstring* error);
    bool ScanProviders(const Options& options, EtwProviderScanResult* result, std::wstring* error);
    static bool BuildTiCrossView(const EtwTiCrossInput& input, EtwTiCrossResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildEtwIntegrityJson(const EtwIntegrityResult& result);
std::wstring BuildEtwProvidersJson(const EtwProviderScanResult& result);
std::wstring BuildEtwTiCrossJson(const EtwTiCrossResult& result);
