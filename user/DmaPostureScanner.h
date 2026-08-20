#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct DmaAcpiTableRecord
{
    std::wstring Signature;
    uint32_t Length = 0;
    bool Present = false;
    std::wstring Notes;
};

struct DmaPciDeviceRecord
{
    std::wstring InstanceId;
    std::wstring Description;
    std::wstring HardwareId;
    std::wstring Class;
    bool RemovableBus = false;
    bool Suspicious = false;
    std::wstring Notes;
};

struct DmaPostureScanResult
{
    std::vector<DmaAcpiTableRecord> AcpiTables;
    std::vector<DmaPciDeviceRecord> PciDevices;
    std::vector<std::wstring> Warnings;
    bool DmarPresent = false;
    bool IvrsPresent = false;
    bool IommuFirmwarePresent = false;
    bool KernelDmaProtectionEnabled = false;
    bool KernelDmaProtectionResolved = false;
    std::wstring DmaSecurityPath;
    std::wstring DmaSecurityValue;
    uint32_t RemovableBusCount = 0;
    bool CoverageComplete = false;
};

class DmaPostureScanner
{
public:
    bool Scan(DmaPostureScanResult* result, std::wstring* error);
};

std::wstring BuildDmaPostureJson(const DmaPostureScanResult& result);
bool DmaAcpiSignatureSelfTest();
