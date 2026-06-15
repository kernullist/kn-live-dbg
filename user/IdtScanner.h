#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One decoded x64 interrupt gate descriptor. The handler address is rebuilt
// from the three split offset fields: OffsetLow | (OffsetMiddle << 16) |
// (OffsetHigh << 32).
struct IdtEntry
{
    uint32_t Vector = 0;
    uint64_t Handler = 0;
    uint16_t Selector = 0;
    uint8_t Ist = 0;
    uint8_t GateType = 0;
    uint8_t Dpl = 0;
    bool Present = false;
    bool InKernelModule = false;
    bool Suspicious = false;
    bool Divergent = false; // this vector's handler differs across processors
    std::wstring Module;
    std::wstring Symbol;
    std::wstring Notes;
};

struct IdtScanResult
{
    uint32_t ProcessorNumber = 0;
    uint64_t IdtBase = 0;
    uint32_t IdtLimit = 0;
    uint32_t EntryCount = 0;
    uint32_t ProcessorsCompared = 0; // processors whose IDT was cross-checked against the BSP
    uint32_t DivergentCount = 0;     // vectors whose handler differs across processors
    std::vector<IdtEntry> Entries;
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
    uint32_t SuspiciousCount = 0;
};

// Reads the IDTR for the boot processor through the read-only
// IOCTL_KNDBG_READ_IDT primitive, walks the interrupt gate descriptors from
// live kernel memory, and flags any present gate whose handler falls outside
// every loaded kernel module as interrupt-hook evidence. Requires the driver
// device to be open.
class IdtScanner
{
public:
    IdtScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(IdtScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
