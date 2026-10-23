#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "CodeIntegrityState.h"

#include <cstdint>
#include <string>
#include <vector>

using VbsCiOptionsInfo = codeintegrity::State;

struct VbsHypervisorInfo
{
    bool HypervisorPresent = false;
    std::wstring VendorSignature;
    uint32_t HvHardwareFeatures = 0;
    uint32_t HvMaxLeaf = 0;
    uint32_t HvInterfaceSignature = 0;
    bool HvInterfaceQueried = false;
    bool HvFeaturesValid = false;
};

inline bool HasMicrosoftHypervisorHardwareLeaf(uint32_t maximumLeaf, uint32_t interfaceSignature)
{
    // TLFS compatibility is defined by the vendor-neutral "Hv#1" interface,
    // not the vendor name or the presence of numerically higher CPUID leaves.
    return maximumLeaf >= 0x40000006u && interfaceSignature == 0x31237648u;
}

using VbsCpuidQuery = void (*)(int* registers, int leaf);
VbsHypervisorInfo QueryVbsHypervisorInfo(VbsCpuidQuery query);

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
    // Reading a private symbol successfully does not validate its pointer value.
    bool IsVbsActivityKnown() const;

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
