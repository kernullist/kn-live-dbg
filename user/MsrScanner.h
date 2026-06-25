#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One architectural SYSCALL-configuration MSR sampled across every logical
// processor. The kernel programs these MSRs identically on each core, so a
// value that differs between processors, or a LSTAR/CSTAR entry pointer that no
// longer lands on the expected ntoskrnl SYSCALL entry, is a strong SYSCALL-hook
// signal.
struct MsrReading
{
    uint32_t MsrIndex = 0;
    std::wstring MsrName;
    std::vector<uint64_t> PerCpuValues;
    bool IsPointer = false;
    bool Divergent = false;
    bool ReadFailed = false;
    bool PointsIntoKernelModule = false;
    bool Suspicious = false;
    std::wstring OwningModule;
    std::wstring NearestSymbol;
    std::wstring Notes;
};

struct MsrScanResult
{
    uint32_t ProcessorCount = 0;
    std::vector<MsrReading> Readings;
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
};

// Reads the SYSCALL-configuration MSRs (LSTAR/CSTAR/STAR/FMASK/EFER) through
// the driver's read-only IOCTL_KNDBG_READ_MSR primitive, on every active
// processor in group 0, and validates the entry pointers against the loaded
// kernel image. Requires the driver device to be open.
class MsrScanner
{
public:
    MsrScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(MsrScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildMsrJson(const MsrScanResult& result);
