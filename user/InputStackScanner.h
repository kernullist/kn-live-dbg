#pragma once

#include "DeviceClient.h"
#include "IntegrityScanner.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct InputStackRecord
{
    std::wstring Role;
    std::wstring DriverFilter;
    DriverObjectInspectResult Driver;
    bool Suspicious = false;
    std::wstring Notes;
};

struct InputStackScanResult
{
    std::vector<InputStackRecord> Records;
    std::vector<std::wstring> Warnings;
    uint32_t SuspiciousStacks = 0;
    bool CoverageComplete = false;
};

class InputStackScanner
{
public:
    InputStackScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(InputStackScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildInputStackJson(const InputStackScanResult& result);
bool InputStackKnownDriverSelfTest();
