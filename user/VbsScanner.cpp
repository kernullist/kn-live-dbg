#include "VbsScanner.h"
#include "McpJson.h"

#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <cstdio>
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

    void ReadCiOptions(VbsScanResult* result)
    {
        result->CiOptions = codeintegrity::Query();
        if (!result->CiOptions.Resolved)
        {
            result->Warnings.push_back(L"SystemCodeIntegrityInformation unavailable or incomplete; CI/HVCI state is unknown");
        }
        else if (result->CiOptions.UnknownOptions != 0)
        {
            result->Warnings.push_back(L"SystemCodeIntegrityInformation contains additional option bits; retained in unknownOptions without interpretation");
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
                if (!result->IsVbsActivityKnown())
                {
                    result->Warnings.push_back(matched + L" has an unrecognized nonzero pointer; VBS activity is unknown");
                }
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

bool VbsScanResult::IsVbsActivityKnown() const
{
    // A null pointer is the inactive marker; an unrecognized nonzero pointer
    // could be layout drift/corruption (or an unsupported address range).
    return HvlpVsmVtlCallVaResolved &&
        (HvlpVsmVtlCallVa == 0 || IsKernelAddress(HvlpVsmVtlCallVa));
}

VbsHypervisorInfo QueryVbsHypervisorInfo(VbsCpuidQuery query)
{
    VbsHypervisorInfo result;
    int regs[4] = {};
    query(regs, 1);
    if ((static_cast<uint32_t>(regs[2]) & 0x80000000u) == 0)
    {
        return result;
    }
    result.HypervisorPresent = true;

    query(regs, 0x40000000);
    result.HvMaxLeaf = static_cast<uint32_t>(regs[0]);
    char vendor[13] = {};
    memcpy(vendor + 0, &regs[1], sizeof(int));
    memcpy(vendor + 4, &regs[2], sizeof(int));
    memcpy(vendor + 8, &regs[3], sizeof(int));
    for (size_t i = 0; i < 12 && vendor[i] != 0; ++i)
    {
        const unsigned char ch = static_cast<unsigned char>(vendor[i]);
        if (ch >= 0x20 && ch < 0x7f)
        {
            result.VendorSignature.push_back(static_cast<wchar_t>(ch));
        }
    }
    if (result.HvMaxLeaf >= 0x40000001u)
    {
        query(regs, 0x40000001);
        result.HvInterfaceSignature = static_cast<uint32_t>(regs[0]);
        result.HvInterfaceQueried = true;
    }
    if (HasMicrosoftHypervisorHardwareLeaf(result.HvMaxLeaf, result.HvInterfaceSignature))
    {
        query(regs, 0x40000006);
        result.HvHardwareFeatures = static_cast<uint32_t>(regs[0]);
        result.HvFeaturesValid = true;
    }
    return result;
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

        ReadCiOptions(result);
        result->Hypervisor = QueryVbsHypervisorInfo([](int* registers, int leaf)
        {
            __cpuidex(registers, leaf, 0);
        });

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

namespace
{
    std::wstring VbsJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildVbsJson(const VbsScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.vbs.v2\",\"vbsActive\":";
    out += !result.IsVbsActivityKnown() ? L"null" : (result.VbsActive ? L"true" : L"false");
    out += L",\"vbsActiveKnown\":";
    out += result.IsVbsActivityKnown() ? L"true" : L"false";

    // Query failure is unknown, not disabled. Preserve unrecognized option bits
    // without guessing their meaning on newer Windows builds.
    const auto& ci = result.CiOptions;
    const auto flag = [&](bool value) -> const wchar_t*
    {
        return !ci.Resolved ? L"null" : (value ? L"true" : L"false");
    };
    out += L",\"ciOptions\":{\"source\":" + mcpjson::Quote(codeintegrity::kSource);
    out += L",\"raw\":";
    out += ci.Resolved ? mcpjson::Quote(VbsJsonHex(ci.Raw)) : L"null";
    out += L",\"unknownOptions\":";
    out += ci.Resolved ? mcpjson::Quote(VbsJsonHex(ci.UnknownOptions)) : L"null";
    out += L",\"ntstatus\":" + mcpjson::Quote(VbsJsonHex(ci.NtStatus));
    out += L",\"returnedLength\":" + std::to_wstring(ci.ReturnedLength);
    out += L",\"resolved\":";
    out += ci.Resolved ? L"true" : L"false";
    out += L",\"codeIntegrityEnabled\":";
    out += flag(ci.CodeIntegrityEnabled);
    out += L",\"testSign\":";
    out += flag(ci.TestSign);
    out += L",\"umciEnabled\":";
    out += flag(ci.UmciEnabled);
    out += L",\"umciAuditMode\":";
    out += flag(ci.UmciAuditMode);
    out += L",\"umciExclusionPaths\":";
    out += flag(ci.UmciExclusionPaths);
    out += L",\"testBuild\":";
    out += flag(ci.TestBuild);
    out += L",\"preproductionBuild\":";
    out += flag(ci.PreproductionBuild);
    out += L",\"debugMode\":";
    out += flag(ci.DebugMode);
    out += L",\"flightBuild\":";
    out += flag(ci.FlightBuild);
    out += L",\"flightingEnabled\":";
    out += flag(ci.FlightingEnabled);
    out += L",\"hvciEnabled\":";
    out += flag(ci.HvciEnabled);
    out += L",\"hvciAuditMode\":";
    out += flag(ci.HvciAuditMode);
    out += L",\"hvciStrictMode\":";
    out += flag(ci.HvciStrictMode);
    out += L",\"hvciIumEnabled\":";
    out += flag(ci.HvciIumEnabled);
    out += L"}";

    // Hypervisor presence and CPUID-derived vendor signature.
    out += L",\"hypervisor\":{\"present\":";
    out += result.Hypervisor.HypervisorPresent ? L"true" : L"false";
    if (!result.Hypervisor.VendorSignature.empty())
    {
        out += L",\"vendor\":" + mcpjson::Quote(result.Hypervisor.VendorSignature);
    }
    out += L",\"featuresValid\":";
    out += result.Hypervisor.HvFeaturesValid ? L"true" : L"false";
    out += L",\"maximumLeaf\":" + mcpjson::Quote(VbsJsonHex(result.Hypervisor.HvMaxLeaf));
    out += L",\"interfaceSignature\":";
    out += result.Hypervisor.HvInterfaceQueried ?
        mcpjson::Quote(VbsJsonHex(result.Hypervisor.HvInterfaceSignature)) : L"null";
    out += L",\"hardwareFeatures\":";
    out += result.Hypervisor.HvFeaturesValid ?
        mcpjson::Quote(VbsJsonHex(result.Hypervisor.HvHardwareFeatures)) : L"null";
    out += L"}";

    out += L",\"secureKernelLoaded\":";
    out += result.SecureKernelLoaded ? L"true" : L"false";
    out += L",\"skciLoaded\":";
    out += result.SkciLoaded ? L"true" : L"false";

    out += L",\"secureKernelModules\":[";
    for (size_t index = 0; index < result.SecureKernelModules.size(); ++index)
    {
        const VbsModuleHit& module = result.SecureKernelModules[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"imageName\":" + mcpjson::Quote(module.ImageName);
        if (!module.ImagePath.empty())
        {
            out += L",\"imagePath\":" + mcpjson::Quote(module.ImagePath);
        }
        out += L",\"base\":" + mcpjson::Quote(VbsJsonHex(module.Base));
        out += L",\"size\":" + std::to_wstring(module.Size);
        out += L"}";
    }
    out += L"]";

    out += L",\"trustletEnumerationOk\":";
    out += result.TrustletEnumerationOk ? L"true" : L"false";

    out += L",\"trustlets\":[";
    for (size_t index = 0; index < result.Trustlets.size(); ++index)
    {
        const VbsTrustletInfo& trustlet = result.Trustlets[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"eprocess\":" + mcpjson::Quote(VbsJsonHex(trustlet.Eprocess));
        out += L",\"processId\":" + std::to_wstring(trustlet.ProcessId);
        if (!trustlet.ImageName.empty())
        {
            out += L",\"imageName\":" + mcpjson::Quote(trustlet.ImageName);
        }
        if (trustlet.HasSecureState)
        {
            out += L",\"secureState\":" + std::to_wstring(trustlet.SecureState);
        }
        out += L",\"secureKernelInProcess\":";
        out += trustlet.SecureKernelInProcess ? L"true" : L"false";
        out += L"}";
    }
    out += L"]";

    out += L",\"warnings\":[";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[index]);
    }
    out += L"]}";

    return out;
}
