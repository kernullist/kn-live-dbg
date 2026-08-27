#include "HandleTableScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr ULONG kSystemExtendedHandleInformation = 64;
    constexpr uint32_t kMaxHandleBytes = 64u * 1024u * 1024u;
    constexpr uint32_t kMaxProcesses = 8192;
    constexpr ULONG kProcessVmRead = 0x0010;
    constexpr ULONG kProcessVmWrite = 0x0020;
    constexpr ULONG kProcessVmOperation = 0x0008;
    constexpr ULONG kProcessDupHandle = 0x0040;

    typedef LONG NTSTATUS_LOCAL;
    typedef NTSTATUS_LOCAL (NTAPI* PfnNtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    struct SystemHandleTableEntryEx
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    struct SystemHandleInformationEx
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SystemHandleTableEntryEx Handles[1];
    };

    struct ProcessIdentity
    {
        uint32_t Pid = 0;
        uint64_t Eprocess = 0;
        std::wstring Image;
        std::wstring ImagePath;
    };

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU16(DeviceClient& device, uint64_t address, uint16_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint16_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint16_t))
        {
            return false;
        }

        memcpy(value, bytes.data(), sizeof(uint16_t));
        return true;
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

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return lowered;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    std::wstring AccessTextFromMask(uint32_t access)
    {
        std::wstring text;
        if ((access & kProcessVmRead) != 0)
        {
            text += L"VM_READ";
        }
        if ((access & kProcessVmWrite) != 0)
        {
            if (!text.empty())
            {
                text += L"|";
            }
            text += L"VM_WRITE";
        }
        if ((access & kProcessVmOperation) != 0)
        {
            if (!text.empty())
            {
                text += L"|";
            }
            text += L"VM_OPERATION";
        }
        if ((access & kProcessDupHandle) != 0)
        {
            if (!text.empty())
            {
                text += L"|";
            }
            text += L"DUP_HANDLE";
        }
        if (text.empty())
        {
            wchar_t buffer[16];
            swprintf_s(buffer, L"0x%08x", access);
            text = buffer;
        }

        return text;
    }

    std::wstring ImageBaseName(const std::wstring& image)
    {
        std::wstring lowered = ToLowerCopy(image);
        const size_t slash = lowered.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < lowered.size())
        {
            lowered = lowered.substr(slash + 1);
        }
        return lowered;
    }

    std::wstring NormalizeKernelImagePath(const std::wstring& path)
    {
        std::wstring normalized = ToLowerCopy(path);
        for (wchar_t& ch : normalized)
        {
            if (ch == L'/')
            {
                ch = L'\\';
            }
        }

        while (normalized.size() >= 4 &&
            (normalized.compare(0, 4, L"\\??\\") == 0 ||
             normalized.compare(0, 4, L"\\\\?\\") == 0 ||
             normalized.compare(0, 4, L"\\\\.\\") == 0))
        {
            normalized.erase(0, 4);
        }

        if (normalized.compare(0, 8, L"\\device\\") == 0)
        {
            const size_t slash = normalized.find(L'\\', 8);
            if (slash != std::wstring::npos)
            {
                normalized = normalized.substr(slash);
            }
        }

        if (normalized.compare(0, 11, L"\\systemroot") == 0)
        {
            normalized = std::wstring(L"\\windows") + normalized.substr(11);
        }

        return normalized;
    }

    bool NormalizedPathStartsWithWindowsDir(const std::wstring& normalized, const wchar_t* directory)
    {
        bool matched = false;

        do
        {
            if (directory == nullptr || *directory == L'\0')
            {
                break;
            }

            const std::wstring needle = std::wstring(L"\\windows\\") + directory + L"\\";
            if (normalized.size() >= 2 && normalized[1] == L':')
            {
                matched = normalized.compare(2, needle.size(), needle) == 0;
                break;
            }

            matched = normalized.compare(0, needle.size(), needle) == 0;
        } while (false);

        return matched;
    }

    bool PathLooksLikeInboxSystem32(const std::wstring& path)
    {
        if (path.empty())
        {
            return false;
        }

        const std::wstring normalized = NormalizeKernelImagePath(path);
        return NormalizedPathStartsWithWindowsDir(normalized, L"system32") ||
            NormalizedPathStartsWithWindowsDir(normalized, L"syswow64");
    }

    bool PathLooksLikeWindowsRootImage(const std::wstring& path, const wchar_t* leaf)
    {
        bool matched = false;

        do
        {
            if (path.empty() || leaf == nullptr || *leaf == L'\0')
            {
                break;
            }

            const std::wstring normalized = NormalizeKernelImagePath(path);
            const std::wstring want = std::wstring(L"\\windows\\") + ToLowerCopy(leaf);
            if (normalized.size() >= 2 && normalized[1] == L':')
            {
                matched = normalized.compare(2, want.size(), want) == 0 &&
                    normalized.size() == 2 + want.size();
                break;
            }

            matched = normalized == want;
        } while (false);

        return matched;
    }

    bool PathHasDirectorySeparator(const std::wstring& path)
    {
        return path.find_last_of(L"\\/") != std::wstring::npos;
    }

    bool ReadKernelUnicodeString(DeviceClient& device, uint64_t address, std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            value->clear();
            uint16_t length = 0;
            uint64_t buffer = 0;
            if (!ReadU16(device, address, &length))
            {
                break;
            }
            uint16_t maximum = 0;
            ReadU16(device, address + 2, &maximum);
            if (!ReadU64(device, address + 8, &buffer))
            {
                break;
            }
            if (length == 0)
            {
                ok = true;
                break;
            }
            if (maximum != 0 && maximum < length)
            {
                length = maximum;
            }
            length = static_cast<uint16_t>(length & ~static_cast<uint16_t>(1));
            if (length == 0)
            {
                ok = true;
                break;
            }
            if (buffer == 0 || !IsKernelAddress(buffer))
            {
                break;
            }
            if (length > 2048)
            {
                length = 2048;
            }

            std::vector<uint8_t> bytes;
            if (!device.ReadMemory(buffer, length, &bytes, nullptr) || bytes.size() < 2)
            {
                break;
            }

            value->assign(
                reinterpret_cast<const wchar_t*>(bytes.data()),
                bytes.size() / sizeof(wchar_t));
            ok = !value->empty();
        } while (false);

        return ok;
    }

    bool ReadProcessImagePath(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t eprocess,
        std::wstring* path)
    {
        bool ok = false;

        do
        {
            if (path == nullptr || eprocess == 0)
            {
                break;
            }

            path->clear();
            TypeFieldInfo field = {};
            std::wstring ignored;
            uint64_t nameInfo = 0;
            if (symbols.FindField(
                    L"nt!_EPROCESS",
                    L"SeAuditProcessCreationInfo.ImageFileName",
                    &field,
                    &ignored) ||
                symbols.FindField(
                    L"nt!_EPROCESS",
                    L"SeAuditProcessCreationInfo",
                    &field,
                    &ignored))
            {
                if (ReadU64(device, eprocess + field.Offset, &nameInfo) &&
                    nameInfo != 0 &&
                    IsKernelAddress(nameInfo) &&
                    ReadKernelUnicodeString(device, nameInfo, path) &&
                    !path->empty())
                {
                    ok = true;
                    break;
                }
            }

            TypeFieldInfo imageFile = {};
            TypeFieldInfo fileName = {};
            if (!symbols.FindField(L"nt!_EPROCESS", L"ImageFilePointer", &imageFile, &ignored) ||
                !symbols.FindField(L"nt!_FILE_OBJECT", L"FileName", &fileName, &ignored))
            {
                break;
            }

            uint64_t fileObject = 0;
            if (!ReadU64(device, eprocess + imageFile.Offset, &fileObject) ||
                fileObject == 0 ||
                !IsKernelAddress(fileObject))
            {
                break;
            }

            ok = ReadKernelUnicodeString(device, fileObject + fileName.Offset, path) &&
                !path->empty();
        } while (false);

        return ok;
    }

    bool IsSystemOwnerName(const std::wstring& image)
    {
        const std::wstring lowered = ImageBaseName(image);
        return lowered == L"csrss.exe" ||
            lowered == L"smss.exe" ||
            lowered == L"lsass.exe" ||
            lowered == L"services.exe" ||
            lowered == L"svchost.exe" ||
            lowered == L"wininit.exe";
    }

    bool IsWindowsHostHandleStem(const std::wstring& stem)
    {
        return stem == L"csrss" ||
            stem == L"smss" ||
            stem == L"lsass" ||
            stem == L"services" ||
            stem == L"svchost" ||
            stem == L"wininit" ||
            stem == L"winlogon" ||
            stem == L"conhost" ||
            stem == L"openconsole" ||
            stem == L"windowsterminal" ||
            stem == L"windowstermina" ||
            stem == L"runtimebroker" ||
            stem == L"explorer" ||
            stem == L"searchindexer";
    }

    bool PathLooksLikeWindowsAppsHost(const std::wstring& path)
    {
        bool matched = false;

        do
        {
            if (path.empty())
            {
                break;
            }

            const std::wstring normalized = NormalizeKernelImagePath(path);
            const std::wstring needle = L"\\program files\\windowsapps\\";
            const std::wstring needleX86 = L"\\program files (x86)\\windowsapps\\";
            if (normalized.size() >= 2 && normalized[1] == L':')
            {
                matched = normalized.compare(2, needle.size(), needle) == 0 ||
                    normalized.compare(2, needleX86.size(), needleX86) == 0;
                break;
            }

            matched = normalized.compare(0, needle.size(), needle) == 0 ||
                normalized.compare(0, needleX86.size(), needleX86) == 0;
        } while (false);

        return matched;
    }

    bool OwnerPathAllowsWindowsHandlePair(const std::wstring& stem, const std::wstring& path)
    {
        bool allowed = true;

        do
        {
            if (!IsWindowsHostHandleStem(stem) || !PathHasDirectorySeparator(path))
            {
                break;
            }

            if (stem == L"explorer")
            {
                allowed = PathLooksLikeWindowsRootImage(path, L"explorer.exe");
                break;
            }

            if (stem == L"openconsole" ||
                stem == L"windowsterminal" ||
                stem == L"windowstermina")
            {
                allowed = PathLooksLikeWindowsAppsHost(path) ||
                    PathLooksLikeInboxSystem32(path);
                break;
            }

            allowed = PathLooksLikeInboxSystem32(path);
        } while (false);

        return allowed;
    }

    bool IsSystemOwnerImage(
        const std::wstring& image,
        uint32_t pid,
        const std::wstring& imagePath = std::wstring())
    {
        bool systemOwner = false;

        do
        {
            if (pid == 0 || pid == 4)
            {
                systemOwner = true;
                break;
            }

            if (!IsSystemOwnerName(image))
            {
                break;
            }

            const std::wstring& pathToCheck = imagePath.empty() ? image : imagePath;
            if (!PathHasDirectorySeparator(pathToCheck))
            {
                // Name-only identity (15-byte ImageFileName). Do not treat that
                // as proof of a fake path; WRITE/DUP is still gated below.
                systemOwner = true;
                break;
            }

            systemOwner = PathLooksLikeInboxSystem32(pathToCheck);
        } while (false);

        return systemOwner;
    }

    std::wstring ImageStem(const std::wstring& image)
    {
        std::wstring base = ImageBaseName(image);
        const size_t dot = base.find_last_of(L'.');
        if (dot != std::wstring::npos && dot > 0)
        {
            const std::wstring ext = base.substr(dot);
            if (ext == L"." || ext == L".exe" || ext == L".ex" || ext == L".e" ||
                ext == L".sys" || ext == L".dll")
            {
                base.resize(dot);
            }
        }
        return base;
    }

    bool SameProcessImage(const std::wstring& left, const std::wstring& right)
    {
        if (left.empty() || right.empty())
        {
            return false;
        }

        const std::wstring leftBase = ImageBaseName(left);
        const std::wstring rightBase = ImageBaseName(right);
        if (leftBase == rightBase)
        {
            return true;
        }

        // EPROCESS.ImageFileName is 15 bytes. Only treat a prefix as the same
        // image when the shorter name is exactly that cap; "security" must not
        // match "securityhealth.exe". Truncated extensions (.e / .ex) collapse
        // through ImageStem.
        const size_t minSize = (std::min)(leftBase.size(), rightBase.size());
        if (minSize == 15 &&
            (leftBase.compare(0, minSize, rightBase, 0, minSize) == 0))
        {
            return true;
        }

        const std::wstring leftStem = ImageStem(left);
        const std::wstring rightStem = ImageStem(right);
        return !leftStem.empty() && leftStem == rightStem;
    }

    bool IsSensitiveSystemTarget(const std::wstring& stem)
    {
        return stem == L"lsass" ||
            stem == L"csrss" ||
            stem == L"smss" ||
            stem == L"services" ||
            stem == L"wininit" ||
            stem == L"winlogon" ||
            stem == L"system";
    }

    bool StemHasInboxPrefix(const std::wstring& stem, const std::wstring& token)
    {
        if (stem.size() < token.size())
        {
            return false;
        }
        if (stem.compare(0, token.size(), token) != 0)
        {
            return false;
        }
        if (stem.size() == token.size())
        {
            return true;
        }
        const wchar_t next = stem[token.size()];
        return next == L' ' ||
            next == L'-' ||
            next == L'_' ||
            next == L'.' ||
            (next >= L'0' && next <= L'9');
    }

    bool LooksLikeNvidiaHelperStem(const std::wstring& stem)
    {
        bool nvidia = false;

        do
        {
            if (stem.size() < 4)
            {
                break;
            }
            if (StemHasInboxPrefix(stem, L"nvidia") ||
                StemHasInboxPrefix(stem, L"nvcontainer") ||
                StemHasInboxPrefix(stem, L"nvsphelper") ||
                StemHasInboxPrefix(stem, L"nvdisplay") ||
                StemHasInboxPrefix(stem, L"nvxdsync"))
            {
                nvidia = true;
                break;
            }
            nvidia = stem == L"nvvsvc" ||
                stem == L"nvtray" ||
                stem == L"nview" ||
                stem == L"nvnode" ||
                stem == L"nvbackend" ||
                stem == L"nvshim";
        } while (false);

        return nvidia;
    }

    bool IsKnownOsHandlePair(
        const std::wstring& owner,
        const std::wstring& target,
        uint32_t grantedAccess,
        const std::wstring& ownerPath = std::wstring())
    {
        const std::wstring ownerStem = ImageStem(owner);
        const std::wstring targetStem = ImageStem(target);
        if (ownerStem.empty() || targetStem.empty())
        {
            return false;
        }
        if (!OwnerPathAllowsWindowsHandlePair(ownerStem, ownerPath.empty() ? owner : ownerPath))
        {
            return false;
        }

        const bool writeOrDup =
            (grantedAccess & (kProcessVmWrite | kProcessVmOperation | kProcessDupHandle)) != 0;
        const bool consoleHost =
            ownerStem == L"conhost" ||
            ownerStem == L"openconsole" ||
            ownerStem == L"windowsterminal" ||
            ownerStem == L"windowstermina";
        // Console/RuntimeBroker attachments are QUERY/VM_READ. VM_WRITE and
        // DUP_HANDLE from those names is the cheat-impersonation path.
        if ((consoleHost || ownerStem == L"runtimebroker") &&
            !writeOrDup &&
            !IsSensitiveSystemTarget(targetStem))
        {
            return true;
        }

        if ((ownerStem == L"winlogon" &&
                (targetStem == L"dwm" ||
                 targetStem == L"userinit" ||
                 targetStem == L"logonui" ||
                 targetStem == L"lsass" ||
                 targetStem == L"csrss" ||
                 targetStem == L"explorer")) ||
            (ownerStem == L"explorer" && targetStem == L"runtimebroker") ||
            (ownerStem == L"searchindexer" &&
                (targetStem == L"searchfilterhost" ||
                 targetStem == L"searchprotocolhost" ||
                 targetStem == L"searchfilterhos" ||
                 targetStem == L"searchprotocolh" ||
                 targetStem == L"searchfilterho" ||
                 targetStem == L"searchprotocol")) ||
            ((ownerStem == L"searchapp" || targetStem == L"searchapp") &&
                (ownerStem == L"msedgewebview2" || ownerStem == L"msedgewebview" ||
                 targetStem == L"msedgewebview2" || targetStem == L"msedgewebview")) ||
            (StemHasInboxPrefix(ownerStem, L"copilot") &&
                (targetStem == L"msedgewebview2" || targetStem == L"msedgewebview")) ||
            (ownerStem == L"steam" && targetStem == L"steamwebhelper") ||
            (ownerStem == L"steamwebhelper" && targetStem == L"steam") ||
            (StemHasInboxPrefix(ownerStem, L"protonvpn") &&
                StemHasInboxPrefix(targetStem, L"protonvpn")))
        {
            return true;
        }

        // NVIDIA overlay/container helpers open VM/DUP into sibling NVIDIA
        // processes and rundll32 hosts. Same-stem already covers nvcontainer
        // to nvcontainer. Do not treat every nv* image as NVIDIA -- nv.exe,
        // nvi.exe, and cheat names like nvhook.exe are not inbox helpers.
        if (LooksLikeNvidiaHelperStem(ownerStem) &&
            (LooksLikeNvidiaHelperStem(targetStem) || targetStem == L"rundll32"))
        {
            return true;
        }

        return false;
    }

    bool IsWriteOrDupAccess(uint32_t grantedAccess)
    {
        return (grantedAccess & (kProcessVmWrite | kProcessVmOperation | kProcessDupHandle)) != 0;
    }

    bool SystemOwnerWriteIsUnexpected(const std::wstring& ownerImage)
    {
        const std::wstring stem = ImageStem(ownerImage);
        // csrss attaches to the session with VM/DUP on a clean host. The
        // remaining service hosts should not VM_WRITE a game or cheat target.
        return stem == L"svchost" ||
            stem == L"lsass" ||
            stem == L"services" ||
            stem == L"wininit" ||
            stem == L"smss";
    }

    bool IsExpectedVmDupHandle(
        const std::wstring& ownerImage,
        uint32_t ownerPid,
        const std::wstring& targetImage,
        uint32_t targetPid,
        uint32_t grantedAccess = kProcessVmRead,
        const std::wstring& ownerPath = std::wstring())
    {
        if (ownerPid == targetPid)
        {
            return true;
        }
        if (IsSystemOwnerImage(ownerImage, ownerPid, ownerPath))
        {
            if (!(IsWriteOrDupAccess(grantedAccess) && SystemOwnerWriteIsUnexpected(ownerImage)))
            {
                return true;
            }
        }
        if (SameProcessImage(ownerImage, targetImage))
        {
            return true;
        }
        return IsKnownOsHandlePair(ownerImage, targetImage, grantedAccess, ownerPath);
    }

    bool EnumerateKernelProcesses(
        DeviceClient& device,
        SymbolEngine& symbols,
        std::vector<ProcessIdentity>* processes,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();
            TypeFieldInfo linksField = {};
            TypeFieldInfo pidField = {};
            TypeFieldInfo imageField = {};
            std::wstring ignored;
            if (!symbols.FindField(L"nt!_EPROCESS", L"ActiveProcessLinks", &linksField, &ignored) ||
                !symbols.FindField(L"nt!_EPROCESS", L"UniqueProcessId", &pidField, &ignored))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"EPROCESS ActiveProcessLinks/UniqueProcessId not in PDB");
                }
                break;
            }

            symbols.FindField(L"nt!_EPROCESS", L"ImageFileName", &imageField, &ignored);

            uint64_t listHead = 0;
            if (!symbols.ResolveSymbol(L"nt!PsActiveProcessHead", &listHead, &ignored) ||
                listHead == 0)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"nt!PsActiveProcessHead was not resolved");
                }
                break;
            }

            uint64_t flink = 0;
            if (!ReadU64(device, listHead, &flink))
            {
                break;
            }

            uint32_t walked = 0;
            uint64_t current = flink;
            std::unordered_set<uint64_t> visited;
            visited.insert(listHead);
            while (current != 0 &&
                current != listHead &&
                IsKernelAddress(current) &&
                walked < kMaxProcesses)
            {
                ++walked;
                if (!visited.insert(current).second)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(L"ActiveProcessLinks walk hit a cycle");
                    }
                    break;
                }
                if (current < linksField.Offset)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(L"ActiveProcessLinks entry underflowed the list offset");
                    }
                    break;
                }
                uint64_t eprocess = current - linksField.Offset;
                if (pidField.Offset > (~0ull - eprocess))
                {
                    break;
                }
                size_t pidWidth = sizeof(uint64_t);
                if (pidField.Length > 0 && pidField.Length <= sizeof(uint64_t))
                {
                    pidWidth = static_cast<size_t>(pidField.Length);
                }
                std::vector<uint8_t> pidBytes;
                if (!device.ReadMemory(
                        eprocess + pidField.Offset,
                        static_cast<uint32_t>(pidWidth),
                        &pidBytes,
                        nullptr) ||
                    pidBytes.size() != pidWidth)
                {
                    break;
                }
                uint64_t pidValue = 0;
                memcpy(&pidValue, pidBytes.data(), pidWidth);
                if (pidValue > 0xFFFFFFFFull)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"ActiveProcessLinks UniqueProcessId was outside the 32-bit PID range");
                    }
                    break;
                }

                ProcessIdentity identity = {};
                identity.Pid = static_cast<uint32_t>(pidValue);
                identity.Eprocess = eprocess;
                if (imageField.Offset != 0 &&
                    imageField.Length >= 1 &&
                    imageField.Offset <= (~0ull - eprocess))
                {
                    std::vector<uint8_t> nameBytes;
                    uint32_t nameLen = static_cast<uint32_t>(imageField.Length);
                    if (nameLen > 16)
                    {
                        nameLen = 16;
                    }
                    if (device.ReadMemory(eprocess + imageField.Offset, nameLen, &nameBytes, nullptr) &&
                        !nameBytes.empty())
                    {
                        std::string ascii(
                            reinterpret_cast<const char*>(nameBytes.data()),
                            strnlen(reinterpret_cast<const char*>(nameBytes.data()), nameBytes.size()));
                        identity.Image = mcpjson::Utf8ToWide(ascii);
                    }
                }

                ReadProcessImagePath(device, symbols, eprocess, &identity.ImagePath);
                processes->push_back(identity);

                uint64_t next = 0;
                if (!ReadU64(device, current, &next) || next == current)
                {
                    break;
                }
                current = next;
            }

            ok = !processes->empty();
        } while (false);

        return ok;
    }
}

HandleTableScanner::HandleTableScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool HandleTableScanner::Scan(
    const HandleTableScanOptions& options,
    HandleTableScanResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid handle-table result output";
            }
            break;
        }

        *result = HandleTableScanResult{};
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"ntdll.dll is not loaded";
            }
            break;
        }

        auto query = reinterpret_cast<PfnNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"NtQuerySystemInformation is unavailable";
            }
            break;
        }

        std::vector<ProcessIdentity> processes;
        EnumerateKernelProcesses(device_, symbols_, &processes, &result->Warnings);
        std::unordered_map<uint64_t, ProcessIdentity> byEprocess;
        std::unordered_map<uint32_t, ProcessIdentity> byPid;
        bool duplicatePidWarned = false;
        for (const ProcessIdentity& process : processes)
        {
            auto pidIt = byPid.find(process.Pid);
            if (pidIt != byPid.end() &&
                pidIt->second.Eprocess != 0 &&
                pidIt->second.Eprocess != process.Eprocess)
            {
                if (!duplicatePidWarned)
                {
                    result->Warnings.push_back(
                        L"ActiveProcessLinks contained a duplicate PID with a different EPROCESS");
                    duplicatePidWarned = true;
                }
            }
            byEprocess[process.Eprocess] = process;
            if (pidIt == byPid.end())
            {
                byPid[process.Pid] = process;
            }
        }

        ULONG needed = 0;
        size_t cap = 0x100000;
        std::vector<uint8_t> buffer(cap);
        NTSTATUS_LOCAL status = query(
            kSystemExtendedHandleInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &needed);
        while (status < 0 && cap < kMaxHandleBytes)
        {
            if (needed > cap && needed <= kMaxHandleBytes)
            {
                cap = static_cast<size_t>(needed) + 0x10000;
            }
            else
            {
                cap *= 2;
            }
            if (cap > kMaxHandleBytes)
            {
                cap = kMaxHandleBytes;
            }
            buffer.resize(cap);
            status = query(
                kSystemExtendedHandleInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &needed);
        }

        if (status < 0)
        {
            if (error != nullptr)
            {
                wchar_t message[64];
                swprintf_s(message, L"NtQuerySystemInformation failed: 0x%08x", static_cast<unsigned int>(status));
                *error = message;
            }
            break;
        }

        if (buffer.size() < sizeof(ULONG_PTR) * 2)
        {
            if (error != nullptr)
            {
                *error = L"handle snapshot is truncated";
            }
            break;
        }

        const SystemHandleInformationEx* table =
            reinterpret_cast<const SystemHandleInformationEx*>(buffer.data());
        const size_t headerBytes = offsetof(SystemHandleInformationEx, Handles);
        const uint64_t count = static_cast<uint64_t>(table->NumberOfHandles);
        const uint64_t maxCount = (buffer.size() - headerBytes) / sizeof(SystemHandleTableEntryEx);
        const uint64_t useCount = count < maxCount ? count : maxCount;
        if (count > maxCount)
        {
            result->Warnings.push_back(L"handle snapshot was truncated by buffer size");
        }

        result->HandlesEnumerated = useCount;
        result->CoverageComplete = count <= maxCount && status >= 0;
        std::unordered_set<uint32_t> owners;
        bool storeCapWarned = false;

        for (uint64_t index = 0; index < useCount; ++index)
        {
            const SystemHandleTableEntryEx& entry = table->Handles[index];
            HandleTableRecord record = {};
            if (static_cast<uint64_t>(entry.UniqueProcessId) > 0xFFFFFFFFull)
            {
                continue;
            }
            record.OwnerPid = static_cast<uint32_t>(entry.UniqueProcessId);
            if (static_cast<uint64_t>(entry.HandleValue) > 0xFFFFFFFFull)
            {
                continue;
            }
            record.HandleValue = static_cast<uint32_t>(entry.HandleValue);
            record.GrantedAccess = entry.GrantedAccess;
            record.ObjectTypeIndex = entry.ObjectTypeIndex;
            record.HandleAttributes = entry.HandleAttributes;
            record.Object = reinterpret_cast<uint64_t>(entry.Object);
            record.AccessText = AccessTextFromMask(record.GrantedAccess);
            record.VmRead = (record.GrantedAccess & kProcessVmRead) != 0;
            record.VmWrite = (record.GrantedAccess & kProcessVmWrite) != 0;
            record.VmOperation = (record.GrantedAccess & kProcessVmOperation) != 0;
            record.DupHandle = (record.GrantedAccess & kProcessDupHandle) != 0;

            std::wstring ownerPath;
            auto ownerIt = byPid.find(record.OwnerPid);
            if (ownerIt != byPid.end())
            {
                record.OwnerImage = ownerIt->second.Image;
                ownerPath = ownerIt->second.ImagePath;
            }

            auto objectIt = byEprocess.find(record.Object);
            if (objectIt != byEprocess.end())
            {
                record.PointsToProcess = true;
                record.TypeName = L"Process";
                record.TargetPid = objectIt->second.Pid;
                record.TargetEprocess = objectIt->second.Eprocess;
                record.TargetImage = objectIt->second.Image;
                ++result->ProcessHandles;
            }

            if (options.HasOwnerPid && record.OwnerPid != options.OwnerPid)
            {
                continue;
            }
            if (options.HasTargetPid)
            {
                if (!record.PointsToProcess || record.TargetPid != options.TargetPid)
                {
                    continue;
                }
            }
            if (options.ProcessHandlesOnly && !record.PointsToProcess)
            {
                continue;
            }

            if (record.PointsToProcess &&
                record.OwnerPid != record.TargetPid &&
                (record.VmRead || record.VmWrite || record.VmOperation || record.DupHandle))
            {
                if (!IsExpectedVmDupHandle(
                        record.OwnerImage,
                        record.OwnerPid,
                        record.TargetImage,
                        record.TargetPid,
                        record.GrantedAccess,
                        ownerPath))
                {
                    record.Suspicious = true;
                    if (IsSystemOwnerName(record.OwnerImage) &&
                        PathHasDirectorySeparator(ownerPath.empty() ? record.OwnerImage : ownerPath) &&
                        !PathLooksLikeInboxSystem32(ownerPath.empty() ? record.OwnerImage : ownerPath))
                    {
                        record.Notes =
                            L"system-named process from a non-system path holds VM/DUP access to another process";
                    }
                    else if (IsSystemOwnerName(record.OwnerImage) &&
                        IsWriteOrDupAccess(record.GrantedAccess))
                    {
                        record.Notes =
                            L"system process holds VM_WRITE/DUP access to another process";
                    }
                    else
                    {
                        record.Notes = L"non-system process holds VM/DUP access to another process";
                    }
                }
            }

            if (options.SuspiciousOnly && !record.Suspicious)
            {
                continue;
            }

            ++result->MatchingHandles;
            if (record.Suspicious)
            {
                ++result->SuspiciousHandles;
            }
            owners.insert(record.OwnerPid);
            if (!options.CollectRecords)
            {
                continue;
            }
            if (options.Limit != 0 && result->Records.size() >= options.Limit)
            {
                result->Truncated = true;
                continue;
            }
            if (options.Limit == 0 && result->Records.size() >= 100000)
            {
                result->Truncated = true;
                if (!storeCapWarned)
                {
                    result->Warnings.push_back(L"handle record store hit the 100000 safety cap");
                    storeCapWarned = true;
                }
                continue;
            }

            result->Records.push_back(record);
        }

        result->OwnerPids.assign(owners.begin(), owners.end());
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHandleTableJson(const HandleTableScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.handle-table.v1\"";
    json << L",\"handles_enumerated\":" << result.HandlesEnumerated;
    json << L",\"matching\":" << result.MatchingHandles;
    json << L",\"process_handles\":" << result.ProcessHandles;
    json << L",\"suspicious\":" << result.SuspiciousHandles;
    json << L",\"truncated\":" << (result.Truncated ? L"true" : L"false");
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"records\":[";
    bool first = true;
    for (const HandleTableRecord& record : result.Records)
    {
        if (!first)
        {
            json << L",";
        }
        first = false;
        json << L"{\"owner_pid\":" << record.OwnerPid;
        json << L",\"owner_image\":\"" << mcpjson::Escape(record.OwnerImage) << L"\"";
        json << L",\"handle\":" << record.HandleValue;
        json << L",\"access\":\"" << mcpjson::Escape(record.AccessText) << L"\"";
        json << L",\"object\":\"" << JsonHex(record.Object) << L"\"";
        json << L",\"type\":\"" << mcpjson::Escape(record.TypeName) << L"\"";
        json << L",\"target_pid\":" << record.TargetPid;
        json << L",\"target_image\":\"" << mcpjson::Escape(record.TargetImage) << L"\"";
        json << L",\"vm_read\":" << (record.VmRead ? L"true" : L"false");
        json << L",\"vm_write\":" << (record.VmWrite ? L"true" : L"false");
        json << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false");
        json << L",\"notes\":\"" << mcpjson::Escape(record.Notes) << L"\"}";
    }
    json << L"],\"warnings\":[";
    first = true;
    for (const std::wstring& warning : result.Warnings)
    {
        if (!first)
        {
            json << L",";
        }
        first = false;
        json << L"\"" << mcpjson::Escape(warning) << L"\"";
    }
    json << L"]}";
    return json.str();
}

bool HandleTableAccessMaskSelfTest()
{
    bool ok = false;

    do
    {
        if (AccessTextFromMask(kProcessVmRead) != L"VM_READ")
        {
            break;
        }
        if (AccessTextFromMask(kProcessVmRead | kProcessVmWrite).find(L"VM_WRITE") == std::wstring::npos)
        {
            break;
        }
        if (!IsSystemOwnerImage(L"csrss.exe", 500) ||
            !IsSystemOwnerImage(L"C:\\Windows\\System32\\lsass.exe", 500) ||
            IsSystemOwnerImage(L"C:\\Temp\\lsass.exe", 500) ||
            IsSystemOwnerImage(L"csrss.exe", 500, L"C:\\Temp\\csrss.exe") ||
            !IsSystemOwnerImage(
                L"csrss.exe",
                500,
                L"C:\\Windows\\System32\\csrss.exe") ||
            IsSystemOwnerImage(L"winlogon.exe", 500) ||
            IsSystemOwnerImage(L"conhost.exe", 500) ||
            IsSystemOwnerImage(L"OpenConsole.exe", 500))
        {
            break;
        }
        if (IsSystemOwnerImage(L"cheat.exe", 1234) ||
            IsSystemOwnerImage(L"System", 1234) ||
            !IsSystemOwnerImage(L"System", 4) ||
            IsSystemOwnerImage(
                L"svchost.exe",
                500,
                L"C:\\cheat\\Windows\\System32\\svchost.exe") ||
            !IsSystemOwnerImage(
                L"svchost.exe",
                500,
                L"\\\\?\\C:\\Windows\\System32\\svchost.exe") ||
            !IsSystemOwnerImage(
                L"lsass.exe",
                500,
                L"\\\\.\\C:\\Windows\\System32\\lsass.exe"))
        {
            break;
        }
        if (!SameProcessImage(L"chrome.exe", L"chrome.exe") ||
            !SameProcessImage(L"nvcontainer.ex", L"nvcontainer.exe") ||
            !SameProcessImage(L"RuntimeBroker.e", L"RuntimeBroker.exe") ||
            SameProcessImage(L"chrome.exe", L"notepad.exe") ||
            SameProcessImage(L"security", L"securityhealth.exe") ||
            SameProcessImage(L"lsass.exe", L"lsass.exe.bak"))
        {
            break;
        }
        if (!IsExpectedVmDupHandle(L"chrome.exe", 10, L"chrome.exe", 11) ||
            !IsExpectedVmDupHandle(L"winlogon.exe", 10, L"dwm.exe", 11) ||
            !IsExpectedVmDupHandle(L"winlogon.exe", 10, L"userinit.exe", 11) ||
            IsExpectedVmDupHandle(L"winlogon.exe", 10, L"cheat.exe", 11) ||
            IsExpectedVmDupHandle(L"nvxdll.exe", 10, L"rundll32.exe", 11) ||
            !IsExpectedVmDupHandle(L"nvcontainer.exe", 10, L"nvsphelper64.exe", 11) ||
            !IsExpectedVmDupHandle(L"nvcontainer.exe", 10, L"rundll32.exe", 11) ||
            !IsExpectedVmDupHandle(L"SearchIndexer.", 10, L"SearchFilterHo", 11) ||
            !IsExpectedVmDupHandle(L"SearchIndexer.exe", 10, L"SearchFilterHos", 11) ||
            !IsExpectedVmDupHandle(L"SearchIndexer.exe", 10, L"SearchProtocolH", 11) ||
            !IsExpectedVmDupHandle(L"OpenConsole.exe", 10, L"pwsh.exe", 11) ||
            !IsExpectedVmDupHandle(
                L"OpenConsole.exe",
                10,
                L"pwsh.exe",
                11,
                kProcessVmRead,
                L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.0_x64__8wekyb3d8bbwe\\OpenConsole.exe") ||
            IsExpectedVmDupHandle(
                L"OpenConsole.exe",
                10,
                L"pwsh.exe",
                11,
                kProcessVmRead,
                L"C:\\Temp\\OpenConsole.exe") ||
            !IsExpectedVmDupHandle(L"steam.exe", 10, L"steamwebhelper.exe", 11) ||
            !IsExpectedVmDupHandle(L"ProtonVPN.exe", 10, L"ProtonVPN Service.exe", 11) ||
            IsExpectedVmDupHandle(L"protonvp-hook.exe", 10, L"ProtonVPN.exe", 11) ||
            IsExpectedVmDupHandle(L"notcopilot.exe", 10, L"msedgewebview2.exe", 11) ||
            !IsExpectedVmDupHandle(L"svchost.exe", 10, L"notepad.exe", 11) ||
            IsExpectedVmDupHandle(
                L"svchost.exe",
                10,
                L"notepad.exe",
                11,
                kProcessVmWrite) ||
            IsExpectedVmDupHandle(L"cheat.exe", 10, L"lsass.exe", 11) ||
            IsExpectedVmDupHandle(L"nv.exe", 10, L"rundll32.exe", 11) ||
            IsExpectedVmDupHandle(L"nvhook.exe", 10, L"rundll32.exe", 11) ||
            IsExpectedVmDupHandle(L"nvhelper.exe", 10, L"rundll32.exe", 11) ||
            !IsExpectedVmDupHandle(L"NVIDIA Overlay.exe", 10, L"rundll32.exe", 11) ||
            !IsExpectedVmDupHandle(L"OpenConsole.exe", 10, L"grok.exe", 11) ||
            !IsExpectedVmDupHandle(L"RuntimeBroker.exe", 10, L"LockApp.exe", 11) ||
            IsExpectedVmDupHandle(L"OpenConsole.exe", 10, L"lsass.exe", 11) ||
            IsExpectedVmDupHandle(L"conhost.exe", 10, L"lsass.exe", 11) ||
            IsExpectedVmDupHandle(L"RuntimeBroker.exe", 10, L"lsass.exe", 11) ||
            IsExpectedVmDupHandle(
                L"OpenConsole.exe",
                10,
                L"grok.exe",
                11,
                kProcessVmWrite) ||
            IsExpectedVmDupHandle(
                L"RuntimeBroker.exe",
                10,
                L"LockApp.exe",
                11,
                kProcessVmWrite | kProcessDupHandle) ||
            IsExpectedVmDupHandle(L"nvidiacheat.exe", 10, L"rundll32.exe", 11) ||
            IsExpectedVmDupHandle(L"nvcontainercheat.exe", 10, L"rundll32.exe", 11) ||
            IsExpectedVmDupHandle(
                L"csrss.exe",
                10,
                L"game.exe",
                11,
                kProcessVmRead,
                L"C:\\Temp\\csrss.exe") ||
            !IsExpectedVmDupHandle(
                L"csrss.exe",
                10,
                L"game.exe",
                11,
                kProcessVmRead,
                L"C:\\Windows\\System32\\csrss.exe") ||
            IsExpectedVmDupHandle(
                L"lsass.exe",
                10,
                L"game.exe",
                11,
                kProcessVmWrite,
                L"C:\\Windows\\System32\\lsass.exe") ||
            IsExpectedVmDupHandle(
                L"services.exe",
                10,
                L"game.exe",
                11,
                kProcessDupHandle,
                L"C:\\Windows\\System32\\services.exe") ||
            IsExpectedVmDupHandle(
                L"winlogon.exe",
                10,
                L"dwm.exe",
                11,
                kProcessVmRead,
                L"C:\\Temp\\winlogon.exe") ||
            !IsExpectedVmDupHandle(
                L"winlogon.exe",
                10,
                L"dwm.exe",
                11,
                kProcessVmRead,
                L"C:\\Windows\\System32\\winlogon.exe") ||
            !IsExpectedVmDupHandle(
                L"svchost.exe",
                10,
                L"notepad.exe",
                11,
                kProcessVmRead,
                L"C:\\Windows\\System32\\svchost.exe"))
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}
