#include "TokenPrivilegeScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint64_t kExFastRefMask = ~0xFull;
    constexpr uint32_t kMaxProcesses = 4096;
    constexpr uint32_t kMaxPrivilegeBits = 64;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    bool ReadBytes(DeviceClient& device, uint64_t address, uint32_t length, std::vector<uint8_t>* bytes)
    {
        if (bytes == nullptr)
        {
            return false;
        }
        if (!device.ReadMemory(address, length, bytes, nullptr))
        {
            return false;
        }
        return bytes->size() == length;
    }

    bool EqualsCI(const std::wstring& a, const std::wstring& b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (size_t i = 0; i < a.size(); ++i)
        {
            wchar_t ca = a[i];
            wchar_t cb = b[i];
            if (ca >= L'A' && ca <= L'Z')
            {
                ca = static_cast<wchar_t>(ca - L'A' + L'a');
            }
            if (cb >= L'A' && cb <= L'Z')
            {
                cb = static_cast<wchar_t>(cb - L'A' + L'a');
            }
            if (ca != cb)
            {
                return false;
            }
        }
        return true;
    }

    bool ContainsCI(const std::wstring& haystack, const std::wstring& needle)
    {
        if (needle.empty())
        {
            return true;
        }
        if (haystack.size() < needle.size())
        {
            return false;
        }
        for (size_t i = 0; i + needle.size() <= haystack.size(); ++i)
        {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j)
            {
                wchar_t ca = haystack[i + j];
                wchar_t cb = needle[j];
                if (ca >= L'A' && ca <= L'Z')
                {
                    ca = static_cast<wchar_t>(ca - L'A' + L'a');
                }
                if (cb >= L'A' && cb <= L'Z')
                {
                    cb = static_cast<wchar_t>(cb - L'A' + L'a');
                }
                if (ca != cb)
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return true;
            }
        }
        return false;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    // Windows privilege bit positions in _SEP_TOKEN_PRIVILEGES bitmasks.
    // Present/Enabled bit N is set when privilege constant value N is present
    // (winnt.h SE_*_PRIVILEGE LUID.LowPart values).
    struct KnownPrivilege
    {
        uint32_t Bit; // privilege value / bit index in Present/Enabled masks
        const wchar_t* Name;
        bool HighRiskDisplay;   // shown as high-risk in !token output
        bool ElevatingFinding;  // enough alone to mark Suspicious (rare/admin-abuse)
    };

    const KnownPrivilege kKnownPrivileges[] =
    {
        { 2,  L"SeCreateTokenPrivilege", true, true },
        { 3,  L"SeAssignPrimaryTokenPrivilege", true, true },
        { 7,  L"SeTcbPrivilege", true, true },
        { 8,  L"SeSecurityPrivilege", true, false },
        { 9,  L"SeTakeOwnershipPrivilege", true, false },
        { 10, L"SeLoadDriverPrivilege", true, true },
        { 17, L"SeBackupPrivilege", false, false },
        { 18, L"SeRestorePrivilege", false, false },
        { 20, L"SeDebugPrivilege", true, false },
        { 21, L"SeAuditPrivilege", false, false },
        { 22, L"SeSystemEnvironmentPrivilege", true, false },
        { 29, L"SeImpersonatePrivilege", false, false },
        { 30, L"SeCreateGlobalPrivilege", false, false },
        { 32, L"SeRelabelPrivilege", true, true },
        { 33, L"SeIncreaseWorkingSetPrivilege", false, false },
    };

    const wchar_t* NameForBit(uint32_t bit)
    {
        for (const KnownPrivilege& item : kKnownPrivileges)
        {
            if (item.Bit == bit)
            {
                return item.Name;
            }
        }
        return nullptr;
    }

    bool HighRiskDisplayBit(uint32_t bit)
    {
        for (const KnownPrivilege& item : kKnownPrivileges)
        {
            if (item.Bit == bit)
            {
                return item.HighRiskDisplay;
            }
        }
        return false;
    }

    bool IsCommonAdminPrivilegeName(const std::wstring& name)
    {
        return EqualsCI(name, L"SeDebugPrivilege") ||
            EqualsCI(name, L"SeSecurityPrivilege") ||
            EqualsCI(name, L"SeTakeOwnershipPrivilege") ||
            EqualsCI(name, L"SeSystemEnvironmentPrivilege");
    }

    bool IsElevatingPrivilegeName(const std::wstring& name)
    {
        return EqualsCI(name, L"SeCreateTokenPrivilege") ||
            EqualsCI(name, L"SeAssignPrimaryTokenPrivilege") ||
            EqualsCI(name, L"SeTcbPrivilege") ||
            EqualsCI(name, L"SeLoadDriverPrivilege") ||
            EqualsCI(name, L"SeRelabelPrivilege");
    }

    bool ResolveActiveProcessHead(SymbolEngine& symbols, uint64_t* address)
    {
        return symbols.ResolveSymbol(L"nt!PsActiveProcessHead", address, nullptr) &&
            *address != 0 &&
            IsKernelAddress(*address);
    }

    std::wstring ReadImageFileName(
        DeviceClient& device,
        uint64_t eprocess,
        uint32_t offset,
        bool* resolved)
    {
        if (resolved != nullptr)
        {
            *resolved = false;
        }
        std::vector<uint8_t> bytes;
        if (!ReadBytes(device, eprocess + offset, 15, &bytes))
        {
            return std::wstring();
        }
        std::wstring name;
        bool valid = true;
        for (uint8_t ch : bytes)
        {
            if (ch == 0)
            {
                break;
            }
            if (ch < 32 || ch > 126)
            {
                valid = false;
                break;
            }
            name.push_back(static_cast<wchar_t>(ch));
        }
        if (resolved != nullptr)
        {
            *resolved = valid && !name.empty();
        }
        return name;
    }
}

bool TokenPrivilegeScanner::IsHighRiskPrivilegeName(const std::wstring& name)
{
    static const wchar_t* kHighRisk[] =
    {
        L"SeDebugPrivilege",
        L"SeLoadDriverPrivilege",
        L"SeTcbPrivilege",
        L"SeCreateTokenPrivilege",
        L"SeAssignPrimaryTokenPrivilege",
        L"SeRelabelPrivilege",
        L"SeSecurityPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeSystemEnvironmentPrivilege",
        L"SeBackupPrivilege",
        L"SeRestorePrivilege",
    };
    for (const wchar_t* item : kHighRisk)
    {
        if (EqualsCI(name, item))
        {
            return true;
        }
    }
    return false;
}

bool TokenPrivilegeScanner::IsSystemProfileImage(const std::wstring& imageName, uint32_t pid)
{
    if (pid == 0 || pid == 4)
    {
        return true;
    }
    // Keep this list to true kernel/session service hosts. Do not include
    // interactive shells (explorer, conhost) or arbitrary user apps - those
    // are exactly the surfaces where unexpected elevation matters.
    static const wchar_t* kSystemImages[] =
    {
        L"System",
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"services.exe",
        L"lsass.exe",
        L"svchost.exe",
        L"LsaIso.exe",
        L"Memory Compression",
        L"Registry",
        L"Secure System",
        L"fontdrvhost.exe",
        L"dwm.exe",
        L"MsMpEng.exe",
        L"NisSrv.exe",
        L"SecurityHealthService.exe",
        L"TrustedInstaller.exe",
        L"TiWorker.exe",
        L"spoolsv.exe",
        L"WmiPrvSE.exe",
    };
    for (const wchar_t* item : kSystemImages)
    {
        if (EqualsCI(imageName, item))
        {
            return true;
        }
    }
    return false;
}

std::wstring TokenPrivilegeScanner::PrivilegeNameFromBit(uint32_t bitIndex)
{
    const wchar_t* known = NameForBit(bitIndex);
    if (known != nullptr)
    {
        return known;
    }
    return L"PrivilegeBit" + std::to_wstring(bitIndex);
}

std::wstring TokenPrivilegeScanner::BuildPrivilegeFingerprint(uint64_t present, uint64_t enabled)
{
    std::wstringstream stream;
    stream << L"p:" << std::hex << present << L"|e:" << enabled;
    return stream.str();
}

TokenPrivilegeScanner::TokenPrivilegeScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool TokenPrivilegeScanner::Scan(const Options& options, TokenPrivilegeScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid token scan result output";
            }
            break;
        }

        *result = TokenPrivilegeScanResult{};

        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = L"could not load kernel modules: " + loadError;
                }
                break;
            }
        }

        ResolvedFieldOffset tokenField = ResolveFieldOffset(symbols_, L"nt!_EPROCESS", L"Token", 0x4b8);
        ResolvedFieldOffset pidField = ResolveFieldOffset(symbols_, L"nt!_EPROCESS", L"UniqueProcessId", 0x440);
        ResolvedFieldOffset linksField = ResolveFieldOffset(symbols_, L"nt!_EPROCESS", L"ActiveProcessLinks", 0x448);
        ResolvedFieldOffset imageField = ResolveFieldOffset(symbols_, L"nt!_EPROCESS", L"ImageFileName", 0x5a8);
        ResolvedFieldOffset privilegesField = ResolveFieldOffset(symbols_, L"nt!_TOKEN", L"Privileges", 0x40);

        // _SEP_TOKEN_PRIVILEGES layout: Present, Enabled, EnabledByDefault (3x ULONG64)
        ResolvedFieldOffset presentField = ResolveFieldOffset(symbols_, L"nt!_SEP_TOKEN_PRIVILEGES", L"Present", 0x00);
        ResolvedFieldOffset enabledField = ResolveFieldOffset(symbols_, L"nt!_SEP_TOKEN_PRIVILEGES", L"Enabled", 0x08);
        ResolvedFieldOffset enabledByDefaultField =
            ResolveFieldOffset(symbols_, L"nt!_SEP_TOKEN_PRIVILEGES", L"EnabledByDefault", 0x10);

        result->LayoutFromPdb =
            tokenField.FromPdb &&
            privilegesField.FromPdb &&
            presentField.FromPdb &&
            enabledField.FromPdb &&
            enabledByDefaultField.FromPdb;
        result->ProcessLayoutFromPdb =
            pidField.FromPdb && linksField.FromPdb && imageField.FromPdb;

        if (!result->LayoutFromPdb)
        {
            result->Warnings.push_back(
                L"token privilege layout partially from fallback offsets; treat findings as evidence");
        }
        if (!result->ProcessLayoutFromPdb &&
            !options.HasEprocess)
        {
            result->Warnings.push_back(
                L"process-list layout partially from fallback offsets; walk coverage is incomplete");
        }

        struct Target
        {
            uint64_t Eprocess = 0;
            uint32_t Pid = 0;
            std::wstring Image;
            bool IdentityResolved = false;
        };

        std::vector<Target> targets;

        if (options.HasEprocess)
        {
            Target target = {};
            target.Eprocess = options.Eprocess;
            // Best-effort identity fill so !token <eprocess> and snapshot paths
            // still show pid/image when the EPROCESS is readable.
            uint64_t pidValue = 0;
            const bool pidResolved =
                ReadU64(device_, options.Eprocess + pidField.Offset, &pidValue) &&
                pidValue <= 0xffffffffull;
            if (pidResolved)
            {
                target.Pid = static_cast<uint32_t>(pidValue & 0xffffffffu);
            }
            bool imageResolved = false;
            target.Image = ReadImageFileName(
                device_,
                options.Eprocess,
                imageField.Offset,
                &imageResolved);
            target.IdentityResolved = pidResolved && imageResolved;
            result->ProcessWalkComplete =
                target.IdentityResolved && result->ProcessLayoutFromPdb;
            targets.push_back(target);
        }
        else if (options.HasProcessId || options.ScanAll || !options.ImageFilter.empty())
        {
            uint64_t listHead = 0;
            if (!ResolveActiveProcessHead(symbols_, &listHead))
            {
                if (error != nullptr)
                {
                    *error = L"nt!PsActiveProcessHead not resolved";
                }
                break;
            }

            uint64_t flink = 0;
            uint64_t blink = 0;
            if (!ReadU64(device_, listHead, &flink) ||
                !ReadU64(
                    device_,
                    listHead + sizeof(uint64_t),
                    &blink))
            {
                if (error != nullptr)
                {
                    *error = L"failed to read PsActiveProcessHead links";
                }
                break;
            }
            if ((flink != listHead && !IsKernelAddress(flink)) ||
                (blink != listHead && !IsKernelAddress(blink)) ||
                (flink == listHead && blink != listHead))
            {
                if (error != nullptr)
                {
                    *error = L"PsActiveProcessHead contains invalid sentinel links";
                }
                break;
            }

            std::set<uint64_t> visited;
            uint64_t entry = flink;
            uint64_t previous = listHead;
            uint32_t walked = 0;
            bool exactTargetFound = false;
            while (entry != 0 && entry != listHead && walked < kMaxProcesses)
            {
                if (visited.find(entry) != visited.end())
                {
                    result->Warnings.push_back(
                        L"active process list cycle detected; walk stopped");
                    break;
                }
                visited.insert(entry);

                if (!IsKernelAddress(entry) || entry < linksField.Offset)
                {
                    result->Warnings.push_back(
                        L"active process list entry is invalid; walk stopped");
                    break;
                }

                uint64_t next = 0;
                uint64_t previousLink = 0;
                if (!ReadU64(device_, entry, &next) ||
                    !ReadU64(device_, entry + sizeof(uint64_t), &previousLink))
                {
                    result->Warnings.push_back(
                        L"active process list link read failed; walk stopped");
                    break;
                }
                if (previousLink != previous ||
                    next == 0 ||
                    (next != listHead && !IsKernelAddress(next)))
                {
                    result->Warnings.push_back(
                        L"active process list link validation failed; walk stopped");
                    break;
                }
                uint64_t nextBacklink = 0;
                if (!ReadU64(
                        device_,
                        next + sizeof(uint64_t),
                        &nextBacklink) ||
                    nextBacklink != entry)
                {
                    result->Warnings.push_back(
                        L"active process list backlink mismatch; walk stopped");
                    break;
                }

                uint64_t eprocess = entry - linksField.Offset;
                uint64_t pidValue = 0;
                const bool pidResolved =
                    ReadU64(device_, eprocess + pidField.Offset, &pidValue) &&
                    pidValue <= 0xffffffffull;
                uint32_t pid = static_cast<uint32_t>(pidValue & 0xffffffffu);
                bool imageResolved = false;
                std::wstring image = ReadImageFileName(
                    device_,
                    eprocess,
                    imageField.Offset,
                    &imageResolved);

                bool keep = options.ScanAll;
                if (options.HasProcessId && pidResolved && pid == options.ProcessId)
                {
                    keep = true;
                }
                if (!options.ImageFilter.empty() &&
                    imageResolved &&
                    ContainsCI(image, options.ImageFilter))
                {
                    keep = true;
                }
                if (keep)
                {
                    Target target = {};
                    target.Eprocess = eprocess;
                    target.Pid = pid;
                    target.Image = image;
                    target.IdentityResolved = pidResolved && imageResolved;
                    targets.push_back(target);
                    if (options.HasProcessId && !options.ScanAll && options.ImageFilter.empty())
                    {
                        exactTargetFound = true;
                        break;
                    }
                }

                previous = entry;
                entry = next;
                ++walked;
            }

            if (exactTargetFound)
            {
                result->ProcessWalkComplete = result->ProcessLayoutFromPdb;
            }
            else
            {
                result->ProcessWalkComplete =
                    result->ProcessLayoutFromPdb && entry == listHead;
                if (walked >= kMaxProcesses && entry != listHead)
                {
                    result->Warnings.push_back(
                        L"active process walk hit safety limit; coverage incomplete");
                }
            }
        }
        else
        {
            if (error != nullptr)
            {
                *error = L"token scan requires pid, eprocess, image filter, or /all";
            }
            break;
        }

        if (targets.empty())
        {
            if (error != nullptr)
            {
                *error = L"no matching process found for token scan";
            }
            break;
        }

        uint32_t limit = options.Limit == 0 ? static_cast<uint32_t>(targets.size()) : options.Limit;
        if (limit > static_cast<uint32_t>(targets.size()))
        {
            limit = static_cast<uint32_t>(targets.size());
        }
        if (limit < static_cast<uint32_t>(targets.size()))
        {
            result->ProcessWalkComplete = false;
            result->Warnings.push_back(
                L"token record limit truncated matching processes; coverage incomplete");
        }

        for (uint32_t i = 0; i < limit; ++i)
        {
            const Target& target = targets[i];
            TokenPrivilegeRecord record = {};
            record.Eprocess = target.Eprocess;
            record.ProcessId = target.Pid;
            record.ImageName = target.Image;
            record.IdentityResolved = target.IdentityResolved;
            record.SystemProfile =
                target.IdentityResolved &&
                IsSystemProfileImage(target.Image, target.Pid);
            if (!record.IdentityResolved)
            {
                record.CoverageIncomplete = true;
                record.Notes.push_back(
                    L"process identity read incomplete; system-profile suppression disabled");
            }

            uint64_t tokenRaw = 0;
            if (!ReadU64(device_, target.Eprocess + tokenField.Offset, &tokenRaw) || tokenRaw == 0)
            {
                record.CoverageIncomplete = true;
                record.Notes.push_back(L"Token field read failed");
                result->Records.push_back(record);
                continue;
            }

            record.TokenRaw = tokenRaw;
            record.TokenObject = tokenRaw & kExFastRefMask;
            if (!IsKernelAddress(record.TokenObject))
            {
                record.CoverageIncomplete = true;
                record.Notes.push_back(L"Token object not kernel-canonical after EX_FAST_REF unmask");
                result->Records.push_back(record);
                continue;
            }
            record.TokenResolved = true;

            uint64_t privBase = record.TokenObject + privilegesField.Offset;
            uint64_t present = 0;
            uint64_t enabled = 0;
            uint64_t enabledByDefault = 0;
            if (!ReadU64(device_, privBase + presentField.Offset, &present) ||
                !ReadU64(device_, privBase + enabledField.Offset, &enabled) ||
                !ReadU64(device_, privBase + enabledByDefaultField.Offset, &enabledByDefault))
            {
                record.CoverageIncomplete = true;
                record.Notes.push_back(L"SEP_TOKEN_PRIVILEGES read failed");
                result->Records.push_back(record);
                continue;
            }

            record.PrivilegesResolved = true;
            record.PresentMask = present;
            record.EnabledMask = enabled;
            record.EnabledByDefaultMask = enabledByDefault;
            record.PrivilegeFingerprint = BuildPrivilegeFingerprint(present, enabled);

            const bool privilegeFindingsAllowed =
                !options.RequirePdbLayoutForPrivilegeFindings || result->LayoutFromPdb;

            // Enabled and EnabledByDefault bits must be subsets of Present.
            if (privilegeFindingsAllowed && (enabled & ~present) != 0)
            {
                record.Suspicious = true;
                record.Notes.push_back(L"Enabled privilege bits not present in Present mask");
            }
            if (privilegeFindingsAllowed && (enabledByDefault & ~present) != 0)
            {
                record.Suspicious = true;
                record.Notes.push_back(
                    L"EnabledByDefault privilege bits not present in Present mask");
            }

            for (uint32_t bit = 0; bit < kMaxPrivilegeBits; ++bit)
            {
                const uint64_t mask = 1ull << bit;
                const bool isPresent = (present & mask) != 0;
                const bool isEnabled = (enabled & mask) != 0;
                const bool isDefault = (enabledByDefault & mask) != 0;
                if (!isPresent && !isEnabled && !isDefault)
                {
                    continue;
                }

                TokenPrivilegeBit item = {};
                item.LuidLow = bit;
                item.Name = PrivilegeNameFromBit(bit);
                item.Present = isPresent;
                item.Enabled = isEnabled;
                item.EnabledByDefault = isDefault;
                item.HighRisk =
                    HighRiskDisplayBit(bit) ||
                    IsHighRiskPrivilegeName(item.Name) ||
                    IsElevatingPrivilegeName(item.Name);
                record.Privileges.push_back(item);

                if (item.HighRisk && item.Enabled)
                {
                    record.HighRiskEnabled.push_back(item.Name);
                }
            }

            if (!record.HighRiskEnabled.empty() && !record.SystemProfile && privilegeFindingsAllowed)
            {
                bool elevating = false;
                bool commonAdmin = false;
                for (const std::wstring& name : record.HighRiskEnabled)
                {
                    if (IsElevatingPrivilegeName(name))
                    {
                        elevating = true;
                    }
                    if (IsCommonAdminPrivilegeName(name))
                    {
                        commonAdmin = true;
                    }
                }

                if (elevating)
                {
                    record.Suspicious = true;
                    record.Notes.push_back(
                        L"elevating privileges enabled on non-system profile process");
                }
                else if (commonAdmin && options.TreatCommonAdminPrivilegesAsSuspicious)
                {
                    // Interactive !token: surface SeDebug-class admin rights.
                    record.Suspicious = true;
                    record.Notes.push_back(
                        L"common admin privileges enabled on non-system profile process");
                }
                else if (commonAdmin && !options.TreatCommonAdminPrivilegesAsSuspicious)
                {
                    record.Notes.push_back(
                        L"common admin privileges present (not auto-suspicious in hunt/snapshot mode)");
                }
            }
            else if (!record.HighRiskEnabled.empty() &&
                     record.SystemProfile &&
                     options.IncludeSystemProfile &&
                     privilegeFindingsAllowed)
            {
                record.Suspicious = true;
                record.Notes.push_back(
                    L"high-risk privileges enabled on explicitly included system-profile process");
            }
            else if (!privilegeFindingsAllowed && !record.HighRiskEnabled.empty())
            {
                record.Notes.push_back(
                    L"privilege findings suppressed: PDB layout incomplete");
            }

            if (record.Suspicious)
            {
                ++result->SuspiciousCount;
                result->AnySuspicious = true;
            }

            result->Records.push_back(record);
        }

        result->CoverageComplete =
            result->LayoutFromPdb && result->ProcessWalkComplete;
        for (const TokenPrivilegeRecord& record : result->Records)
        {
            if (record.CoverageIncomplete)
            {
                result->CoverageComplete = false;
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildTokenPrivilegeJson(const TokenPrivilegeScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.token.v1\"";
    out += L",\"layoutFromPdb\":";
    out += result.LayoutFromPdb ? L"true" : L"false";
    out += L",\"processLayoutFromPdb\":";
    out += result.ProcessLayoutFromPdb ? L"true" : L"false";
    out += L",\"processWalkComplete\":";
    out += result.ProcessWalkComplete ? L"true" : L"false";
    out += L",\"coverageComplete\":";
    out += result.CoverageComplete ? L"true" : L"false";
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousCount);
    out += L",\"recordCount\":" + std::to_wstring(result.Records.size());
    out += L",\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[i]);
    }
    out += L"],\"records\":[";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const TokenPrivilegeRecord& record = result.Records[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"pid\":" + std::to_wstring(record.ProcessId);
        out += L",\"eprocess\":" + mcpjson::Quote(JsonHex(record.Eprocess));
        out += L",\"image\":" + mcpjson::Quote(record.ImageName);
        out += L",\"token\":" + mcpjson::Quote(JsonHex(record.TokenObject));
        out += L",\"present\":" + mcpjson::Quote(JsonHex(record.PresentMask));
        out += L",\"enabled\":" + mcpjson::Quote(JsonHex(record.EnabledMask));
        out += L",\"enabledByDefault\":" + mcpjson::Quote(JsonHex(record.EnabledByDefaultMask));
        out += L",\"fingerprint\":" + mcpjson::Quote(record.PrivilegeFingerprint);
        out += L",\"systemProfile\":";
        out += record.SystemProfile ? L"true" : L"false";
        out += L",\"identityResolved\":";
        out += record.IdentityResolved ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"tokenResolved\":";
        out += record.TokenResolved ? L"true" : L"false";
        out += L",\"privilegesResolved\":";
        out += record.PrivilegesResolved ? L"true" : L"false";
        out += L",\"highRiskEnabled\":[";
        for (size_t j = 0; j < record.HighRiskEnabled.size(); ++j)
        {
            if (j > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(record.HighRiskEnabled[j]);
        }
        out += L"],\"privileges\":[";
        for (size_t j = 0; j < record.Privileges.size(); ++j)
        {
            const TokenPrivilegeBit& bit = record.Privileges[j];
            if (j > 0)
            {
                out += L",";
            }
            out += L"{\"bit\":" + std::to_wstring(bit.LuidLow);
            out += L",\"name\":" + mcpjson::Quote(bit.Name);
            out += L",\"present\":";
            out += bit.Present ? L"true" : L"false";
            out += L",\"enabled\":";
            out += bit.Enabled ? L"true" : L"false";
            out += L",\"enabledByDefault\":";
            out += bit.EnabledByDefault ? L"true" : L"false";
            out += L",\"highRisk\":";
            out += bit.HighRisk ? L"true" : L"false";
            out += L"}";
        }
        out += L"],\"notes\":[";
        for (size_t j = 0; j < record.Notes.size(); ++j)
        {
            if (j > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(record.Notes[j]);
        }
        out += L"]}";
    }
    out += L"]}";
    return out;
}
