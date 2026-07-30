#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct QosPolicyRecord
{
    std::wstring Name;
    std::wstring InstanceId;
    std::wstring Owner;
    std::wstring AppPathName;
    uint64_t ThrottleRateBitsPerSecond = 0;
    uint32_t NetworkProfile = 0;
    uint32_t Precedence = 0;
    bool HasThrottleRate = false;
    bool FromActiveStore = false;
};

struct QosPolicyScanResult
{
    std::vector<QosPolicyRecord> Records;
    std::vector<std::wstring> Warnings;
    bool CoverageComplete = false;
};

class QosPolicyScanner
{
public:
    bool Scan(
        QosPolicyScanResult* result,
        std::wstring* error);
};

bool QosPolicyHasSevereThrottle(
    const QosPolicyRecord& record);
bool QosPolicyScannerSelfTest();
