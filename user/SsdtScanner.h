#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One System Service Descriptor Table entry: the decoded service routine for a
// syscall index plus its module/symbol annotation. On x64 each KiServiceTable
// slot is a 32-bit value encoding (offset << 4) | argbytes, and the routine is
// KiServiceTable + (value >> 4) using an arithmetic shift.
struct SsdtEntry
{
    uint32_t Index = 0;
    int32_t RawValue = 0;
    uint8_t ArgBytes = 0;
    uint64_t Routine = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool InExpectedModule = false;
    bool Suspicious = false;
    std::wstring Notes;
};

// One service table (the native ntoskrnl table or the win32k shadow table).
struct SsdtTable
{
    std::wstring Name;
    std::wstring DescriptorSymbol;
    uint64_t TableBase = 0;   // KiServiceTable base
    uint32_t Limit = 0;
    std::wstring ExpectedModule;
    bool Resolved = false;
    std::vector<SsdtEntry> Entries;
    uint32_t SuspiciousCount = 0;
    std::wstring Warning;
};

struct SsdtScanResult
{
    std::vector<SsdtTable> Tables;
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
    uint32_t SuspiciousCount = 0;
};

// Walks the native SSDT (nt!KeServiceDescriptorTable) and, best-effort, the
// win32k shadow table (nt!KeServiceDescriptorTableShadow[1]) from live kernel
// memory, decoding each service routine and flagging routines that fall
// outside the expected owning kernel image as syscall-hook evidence. Reuses the
// existing read primitive and PDB-first layout resolver; no new driver IOCTL is
// required. Requires the driver device to be open.
class SsdtScanner
{
public:
    SsdtScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(SsdtScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildSsdtJson(const SsdtScanResult& result);
