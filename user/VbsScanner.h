#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct VbsCiOptionsInfo
{
    uint32_t Raw = 0;
    bool Resolved = false;
    std::wstring SymbolSource;
    bool CodeIntegrityEnabled = false;
    bool TestSign = false;
    bool UmciEnabled = false;
    bool UmciAuditMode = false;
    bool HvciEnforced = false;
    bool UmciExclusionPaths = false;
    bool TestBuild = false;
    bool PreproductionBuild = false;
    bool FlightBuild = false;
    bool HvciStrictMode = false;
    bool HvciDebugMode = false;
};

struct VbsHypervisorInfo
{
    bool HypervisorPresent = false;
    std::wstring VendorSignature;
    uint32_t HvHardwareFeatures = 0;
    uint32_t HvLeafBase = 0;
    bool HvFeaturesValid = false;
};

struct VbsModuleHit
{
    std::wstring ImageName;
    std::wstring ImagePath;
    uint64_t Base = 0;
    uint32_t Size = 0;
};

struct VbsTrustletInfo
{
    uint64_t Eprocess = 0;
    uint64_t ProcessId = 0;
    std::wstring ImageName;
    uint32_t SecureState = 0;
    bool HasSecureState = false;
    bool SecureKernelInProcess = false;
};

struct VbsScanResult
{
    VbsCiOptionsInfo CiOptions;
    VbsHypervisorInfo Hypervisor;

    uint64_t HvlpVsmVtlCallVa = 0;
    std::wstring HvlpVsmVtlCallVaSymbol;
    bool HvlpVsmVtlCallVaResolved = false;
    bool VbsActive = false;

    uint64_t HvcallStubAddress = 0;
    std::wstring HvcallStubSymbol;
    bool HvcallStubResolved = false;

    std::vector<VbsModuleHit> SecureKernelModules;
    bool SecureKernelLoaded = false;
    bool SkciLoaded = false;

    std::vector<VbsTrustletInfo> Trustlets;
    bool TrustletEnumerationAttempted = false;
    bool TrustletEnumerationOk = false;

    std::vector<std::wstring> Warnings;
};

class VbsScanner
{
public:
    enum class Scope
    {
        Vbs,
        Ci,
        SecureKernel
    };

    struct Options
    {
        Scope Target = Scope::Vbs;
    };

    VbsScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, VbsScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildVbsJson(const VbsScanResult& result);
