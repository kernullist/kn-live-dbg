#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"

// One control register sampled across every logical processor. CR0 and CR4 are
// programmed uniformly by the kernel, so a per-CPU divergence is a tamper
// signal, and CR0.WP=0 (kernel write-protect disabled) is a classic
// code-patching enabler.
struct CrReading
{
    std::wstring Name;
    std::vector<uint64_t> PerCpuValues;
    bool Divergent = false;
    bool Suspicious = false;
    std::wstring Notes;
};

struct CrScanResult
{
    uint32_t ProcessorCount = 0;
    std::vector<CrReading> Readings; // CR0, CR4, CR8
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
};

// Reads CR0/CR4/CR8 on every active processor in group 0 through the driver's
// read-only IOCTL_KNDBG_READ_CONTROL_REGISTERS primitive and flags integrity
// anomalies. Requires the driver device to be open.
class CrScanner
{
public:
    explicit CrScanner(DeviceClient& device);

    bool Scan(CrScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
};

std::wstring BuildCrJson(const CrScanResult& result);
