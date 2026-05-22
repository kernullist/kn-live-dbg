#include "VbsScanner.h"

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <utility>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxProcessRecords = 4096;
    constexpr uint32_t kMaxImageNameBytes = 16;
    constexpr uint32_t kMaxRawBytesPerRead = 0x1000;

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }

            if (left > (~0ull - right))
            {
                break;
            }

            *result = left + right;
            ok = true;
        } while (false);

        return ok;
    }

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0 || length > kMaxRawBytesPerRead)
            {
                if (error != nullptr)
                {
                    *error = L"invalid read request";
                }
                break;
            }

            if (!device.ReadMemory(address, length, bytes, error))
            {
                break;
            }

            if (bytes->size() != length)
            {
                if (error != nullptr)
                {
                    *error = L"short kernel read";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU32(DeviceClient& device, uint64_t address, uint32_t* value, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint32_t), &bytes, error))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint32_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint64_t), &bytes, error))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveSymbol(SymbolEngine& symbols, const std::wstring& name, uint64_t* address)
    {
        std::wstring ignored;
        return symbols.ResolveSymbol(name, address, &ignored);
    }

    bool ResolveFirst(
        SymbolEngine& symbols,
        const std::vector<std::wstring>& candidates,
        uint64_t* address,
        std::wstring* matched)
    {
        bool ok = false;

        do
        {
            if (address == nullptr || matched == nullptr)
            {
                break;
            }

            for (const std::wstring& name : candidates)
            {
                uint64_t value = 0;
                if (ResolveSymbol(symbols, name, &value))
                {
                    *address = value;
                    *matched = name;
                    ok = true;
                    break;
                }
            }
        } while (false);

        return ok;
    }

    bool FindField(SymbolEngine& symbols, const std::wstring& typeName, const std::wstring& fieldName, TypeFieldInfo* field)
    {
        std::wstring ignored;
        return symbols.FindField(typeName, fieldName, field, &ignored);
    }

    void DecodeCiOptionsBits(uint32_t raw, VbsCiOptionsInfo* info)
    {
        info->CodeIntegrityEnabled = (raw & 0x00000001u) != 0;
        info->TestSign             = (raw & 0x00000002u) != 0;
        info->UmciEnabled          = (raw & 0x00000004u) != 0;
        info->UmciAuditMode        = (raw & 0x00000008u) != 0;
        info->HvciEnforced         = (raw & 0x00000020u) != 0;
        info->UmciExclusionPaths   = (raw & 0x00000040u) != 0;
        info->TestBuild            = (raw & 0x00000080u) != 0;
        info->PreproductionBuild   = (raw & 0x00000100u) != 0;
        info->FlightBuild          = (raw & 0x00000200u) != 0;
        info->HvciStrictMode       = (raw & 0x00000400u) != 0;
        info->HvciDebugMode        = (raw & 0x00000800u) != 0;
    }

    void ReadCiOptions(DeviceClient& device, SymbolEngine& symbols, VbsScanResult* result)
    {
        const std::vector<std::wstring> candidates =
        {
            L"nt!g_CiOptions",
            L"ci!g_CiOptions",
            L"nt!CiOptions"
        };

        uint64_t address = 0;
        std::wstring matched;
        if (!ResolveFirst(symbols, candidates, &address, &matched))
        {
            result->Warnings.push_back(L"CiOptions symbol not resolved; HVCI/CI state will be reported as unknown");
            return;
        }

        uint32_t raw = 0;
        std::wstring readError;
        if (!ReadU32(device, address, &raw, &readError))
        {
            result->Warnings.push_back(L"failed to read " + matched + L": " + readError);
            return;
        }

        result->CiOptions.Raw = raw;
        result->CiOptions.Resolved = true;
        result->CiOptions.SymbolSource = matched;
        DecodeCiOptionsBits(raw, &result->CiOptions);
    }

    void DetectHypervisor(VbsScanResult* result)
    {
        int regs[4] = {0, 0, 0, 0};
        __cpuid(regs, 1);
        if ((static_cast<uint32_t>(regs[2]) & 0x80000000u) == 0)
        {
            return;
        }

        result->Hypervisor.HypervisorPresent = true;

        __cpuid(regs, 0x40000000);
        uint32_t leafBase = static_cast<uint32_t>(regs[0]);
        result->Hypervisor.HvLeafBase = leafBase;

        char vendor[13] = {0};
        memcpy(vendor + 0, &regs[1], sizeof(int));
        memcpy(vendor + 4, &regs[2], sizeof(int));
        memcpy(vendor + 8, &regs[3], sizeof(int));
        vendor[12] = 0;
        std::wstring vendorWide;
        for (size_t i = 0; i < 12 && vendor[i] != 0; ++i)
        {
            unsigned char ch = static_cast<unsigned char>(vendor[i]);
            if (ch >= 0x20 && ch < 0x7f)
            {
                vendorWide.push_back(static_cast<wchar_t>(ch));
            }
        }
        result->Hypervisor.VendorSignature = vendorWide;

        if (leafBase >= 0x40000006u)
        {
            __cpuid(regs, 0x40000006);
            uint32_t features = static_cast<uint32_t>(regs[0]);
            result->Hypervisor.HvHardwareFeatures = features;
            result->Hypervisor.HvFeaturesValid = true;
        }
    }

    void ResolveVbsPointers(DeviceClient& device, SymbolEngine& symbols, VbsScanResult* result)
    {
        const std::vector<std::wstring> vtlCallCandidates =
        {
            L"nt!HvlpVsmVtlCallVa",
            L"nt!HvlpVtlCallVa",
            L"nt!HvlVtlCallVa"
        };

        uint64_t address = 0;
        std::wstring matched;
        if (ResolveFirst(symbols, vtlCallCandidates, &address, &matched))
        {
            uint64_t pointer = 0;
            std::wstring readError;
            if (ReadU64(device, address, &pointer, &readError))
            {
                result->HvlpVsmVtlCallVa = pointer;
                result->HvlpVsmVtlCallVaSymbol = matched;
                result->HvlpVsmVtlCallVaResolved = true;
                result->VbsActive = (pointer != 0 && IsKernelAddress(pointer));
            }
            else
            {
                result->Warnings.push_back(L"failed to read " + matched + L": " + readError);
            }
        }
        else
        {
            result->Warnings.push_back(L"HvlpVsmVtlCallVa/HvlpVtlCallVa symbol not resolved");
        }

        const std::vector<std::wstring> hvcallStubCandidates =
        {
            L"nt!HvcallpVtlCallStub",
            L"nt!HvcallCodeVa",
            L"nt!HvlpVtlCallStub"
        };

        uint64_t stub = 0;
        std::wstring stubMatched;
        if (ResolveFirst(symbols, hvcallStubCandidates, &stub, &stubMatched))
        {
            result->HvcallStubAddress = stub;
            result->HvcallStubSymbol = stubMatched;
            result->HvcallStubResolved = true;
        }
    }

    bool ImageNameMatches(const std::wstring& imageName, const wchar_t* target)
    {
        std::wstring left = ToLowerCopy(imageName);
        std::wstring right = ToLowerCopy(std::wstring(target));
        return left == right;
    }

    void ScanSecureKernelModules(SymbolEngine& symbols, VbsScanResult* result)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            std::wstring name = ToLowerCopy(module.ImageName);
            if (name == L"securekernel.exe" || name == L"skci.dll")
            {
                VbsModuleHit hit = {};
                hit.ImageName = module.ImageName;
                hit.ImagePath = module.ImagePath;
                hit.Base = module.Base;
                hit.Size = module.Size;
                result->SecureKernelModules.push_back(std::move(hit));

                if (name == L"securekernel.exe")
                {
                    result->SecureKernelLoaded = true;
                }
                if (name == L"skci.dll")
                {
                    result->SkciLoaded = true;
                }
            }
        }
    }

    struct EprocessLayout
    {
        TypeFieldInfo ActiveProcessLinks = {};
        TypeFieldInfo UniqueProcessId = {};
        TypeFieldInfo ImageFileName = {};
        TypeFieldInfo SecureState = {};
        bool HasActiveProcessLinks = false;
        bool HasUniqueProcessId = false;
        bool HasImageFileName = false;
        bool HasSecureState = false;
        bool SecureStateInKProcess = false;
    };

    void ResolveEprocessLayout(SymbolEngine& symbols, EprocessLayout* layout)
    {
        if (layout == nullptr)
        {
            return;
        }

        layout->HasActiveProcessLinks = FindField(symbols, L"nt!_EPROCESS", L"ActiveProcessLinks", &layout->ActiveProcessLinks);
        layout->HasUniqueProcessId = FindField(symbols, L"nt!_EPROCESS", L"UniqueProcessId", &layout->UniqueProcessId);
        layout->HasImageFileName = FindField(symbols, L"nt!_EPROCESS", L"ImageFileName", &layout->ImageFileName);

        if (FindField(symbols, L"nt!_EPROCESS", L"SecureState", &layout->SecureState))
        {
            layout->HasSecureState = true;
            layout->SecureStateInKProcess = false;
        }
        else if (FindField(symbols, L"nt!_KPROCESS", L"SecureState", &layout->SecureState))
        {
            layout->HasSecureState = true;
            layout->SecureStateInKProcess = true;
        }
    }

    std::wstring ReadImageFileName(
        DeviceClient& device,
        uint64_t eprocess,
        const TypeFieldInfo& field)
    {
        std::wstring result;

        do
        {
            if (eprocess == 0 || field.Name.empty())
            {
                break;
            }

            uint64_t fieldAddress = 0;
            if (!TryAdd(eprocess, field.Offset, &fieldAddress))
            {
                break;
            }

            uint32_t length = static_cast<uint32_t>(field.Length);
            if (length == 0 || length > kMaxImageNameBytes)
            {
                length = kMaxImageNameBytes;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, fieldAddress, length, &bytes, nullptr))
            {
                break;
            }

            for (uint8_t byte : bytes)
            {
                if (byte == 0)
                {
                    break;
                }

                if (byte >= 0x20 && byte < 0x7f)
                {
                    result.push_back(static_cast<wchar_t>(byte));
                }
                else
                {
                    result.push_back(L'?');
                }
            }
        } while (false);

        return result;
    }

    bool ReadSecureStateRaw(
        DeviceClient& device,
        const EprocessLayout& layout,
        uint64_t eprocess,
        uint32_t* value)
    {
        bool ok = false;

        do
        {
            if (!layout.HasSecureState || value == nullptr)
            {
                break;
            }

            uint64_t base = eprocess;
            uint64_t fieldAddress = 0;
            if (!TryAdd(base, layout.SecureState.Offset, &fieldAddress))
            {
                break;
            }

            uint32_t length = static_cast<uint32_t>(layout.SecureState.Length);
            if (length == 0 || length > sizeof(uint32_t))
            {
                length = sizeof(uint32_t);
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, fieldAddress, length, &bytes, nullptr))
            {
                break;
            }

            uint32_t raw = 0;
            memcpy(&raw, bytes.data(), bytes.size());
            *value = raw;
            ok = true;
        } while (false);

        return ok;
    }

    void EnumerateTrustlets(
        DeviceClient& device,
        SymbolEngine& symbols,
        VbsScanResult* result)
    {
        result->TrustletEnumerationAttempted = true;

        EprocessLayout layout = {};
        ResolveEprocessLayout(symbols, &layout);
        if (!layout.HasActiveProcessLinks || !layout.HasUniqueProcessId)
        {
            result->Warnings.push_back(L"_EPROCESS.ActiveProcessLinks or UniqueProcessId not resolved; trustlet enumeration skipped");
            return;
        }

        if (!layout.HasSecureState)
        {
            result->Warnings.push_back(L"_EPROCESS/_KPROCESS.SecureState not resolved; SecureKernelInProcess bit will be unknown");
        }

        uint64_t listHead = 0;
        if (!ResolveSymbol(symbols, L"nt!PsActiveProcessHead", &listHead))
        {
            result->Warnings.push_back(L"nt!PsActiveProcessHead not resolved; trustlet enumeration skipped");
            return;
        }

        uint64_t firstLink = 0;
        std::wstring readError;
        if (!ReadU64(device, listHead, &firstLink, &readError))
        {
            result->Warnings.push_back(L"failed to read PsActiveProcessHead Flink: " + readError);
            return;
        }

        uint64_t current = firstLink;
        std::vector<uint64_t> visited;
        visited.reserve(256);

        while (current != 0 && current != listHead && visited.size() < kMaxProcessRecords)
        {
            if (!IsKernelAddress(current))
            {
                result->Warnings.push_back(L"trustlet walk encountered non-canonical pointer");
                break;
            }

            if (std::find(visited.begin(), visited.end(), current) != visited.end())
            {
                result->Warnings.push_back(L"trustlet walk cycle detected");
                break;
            }
            visited.push_back(current);

            uint64_t eprocess = 0;
            if (current >= layout.ActiveProcessLinks.Offset)
            {
                eprocess = current - layout.ActiveProcessLinks.Offset;
            }
            else
            {
                break;
            }

            VbsTrustletInfo info = {};
            info.Eprocess = eprocess;

            uint64_t pidAddress = 0;
            uint64_t pid = 0;
            if (TryAdd(eprocess, layout.UniqueProcessId.Offset, &pidAddress) &&
                ReadU64(device, pidAddress, &pid, nullptr))
            {
                info.ProcessId = pid;
            }

            if (layout.HasImageFileName)
            {
                info.ImageName = ReadImageFileName(device, eprocess, layout.ImageFileName);
            }

            if (layout.HasSecureState)
            {
                uint32_t secureStateRaw = 0;
                if (ReadSecureStateRaw(device, layout, eprocess, &secureStateRaw))
                {
                    info.SecureState = secureStateRaw;
                    info.HasSecureState = true;
                    info.SecureKernelInProcess = (secureStateRaw & 0x1u) != 0;
                }
            }

            bool include = false;
            if (info.SecureKernelInProcess)
            {
                include = true;
            }
            else if (!layout.HasSecureState && !info.ImageName.empty())
            {
                std::wstring lowered = ToLowerCopy(info.ImageName);
                static const wchar_t* kKnownTrustletPrefixes[] =
                {
                    L"lsaiso",
                    L"bioiso",
                    L"securesystem",
                    L"kdcustomization"
                };
                for (const wchar_t* prefix : kKnownTrustletPrefixes)
                {
                    if (lowered.rfind(prefix, 0) == 0)
                    {
                        include = true;
                        break;
                    }
                }
            }

            if (include)
            {
                result->Trustlets.push_back(std::move(info));
            }

            uint64_t nextLink = 0;
            if (!ReadU64(device, current, &nextLink, nullptr))
            {
                result->Warnings.push_back(L"trustlet walk read failed at " + std::to_wstring(current));
                break;
            }

            current = nextLink;
        }

        result->TrustletEnumerationOk = true;
    }
}

VbsScanner::VbsScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool VbsScanner::Scan(const Options& options, VbsScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid scan result output";
            }
            break;
        }

        *result = VbsScanResult{};

        ReadCiOptions(device_, symbols_, result);
        DetectHypervisor(result);

        if (options.Target == Scope::Vbs || options.Target == Scope::SecureKernel)
        {
            ResolveVbsPointers(device_, symbols_, result);
            ScanSecureKernelModules(symbols_, result);
        }

        if (options.Target == Scope::Vbs || options.Target == Scope::SecureKernel)
        {
            EnumerateTrustlets(device_, symbols_, result);
        }

        ok = true;
    } while (false);

    return ok;
}
