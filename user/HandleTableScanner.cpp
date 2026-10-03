#include "HandleTableScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <map>
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

    struct HandleRecordBatch
    {
        std::vector<size_t> Indices;
        uint64_t Candidates = 0;
        uint64_t InvalidEntries = 0;
    };

    HandleRecordBatch SelectHandleRecordBatch(const SystemHandleTableEntryEx* entries, size_t count,
        const HandleTableScanOptions& options)
    {
        HandleRecordBatch batch;
        for (size_t index = 0; index < count; ++index)
        {
            if (entries[index].UniqueProcessId != options.OwnerPid)
            {
                continue;
            }
            if (entries[index].HandleValue > UINT32_MAX)
            {
                ++batch.InvalidEntries;
                continue;
            }
            batch.Indices.push_back(index);
        }
        std::sort(batch.Indices.begin(), batch.Indices.end(), [&](size_t left, size_t right)
        {
            return entries[left].HandleValue < entries[right].HandleValue;
        });
        size_t retained = 0;
        for (size_t first = 0; first < batch.Indices.size();)
        {
            size_t next = first + 1;
            while (next < batch.Indices.size() &&
                entries[batch.Indices[first]].HandleValue == entries[batch.Indices[next]].HandleValue)
            {
                ++next;
            }
            if (next - first == 1)
            {
                batch.Indices[retained++] = batch.Indices[first];
            }
            else
            {
                batch.InvalidEntries += next - first;
            }
            first = next;
        }
        batch.Indices.resize(retained);
        batch.Candidates = retained;
        const auto start = std::upper_bound(batch.Indices.begin(), batch.Indices.end(), options.HandleAfter,
            [&](uint64_t after, size_t index)
            {
                return after < entries[index].HandleValue;
            });
        std::rotate(batch.Indices.begin(), start, batch.Indices.end());
        size_t limit = (std::min)(size_t(4096),
            options.MaxHandlesPerPass == 0 ? size_t(4096) : static_cast<size_t>(options.MaxHandlesPerPass));
        if (options.CollectRecords && options.Limit != 0)
        {
            limit = (std::min)(limit, static_cast<size_t>(options.Limit));
        }
        batch.Indices.resize((std::min)(limit, batch.Indices.size()));
        return batch;
    }

    struct HandleReadBudget
    {
        uint64_t Limit = 0;
        uint64_t Attempts = 0;
        bool Denied = false;

        bool Acquire()
        {
            if (Limit != 0 && Attempts >= Limit)
            {
                Denied = true;
                return false;
            }
            ++Attempts;
            return true;
        }
    };

    bool CompleteHandleVisit(uint64_t handle, bool continued, const HandleReadBudget& budget,
        HandleTableScanResult* result)
    {
        if (budget.Denied)
        {
            result->RelationshipBudgetExhausted = true;
            result->HandleCoveragePartial = true;
            return false;
        }
        ++result->HandlesVisited;
        if (continued)
        {
            result->NextHandleAfter = handle;
        }
        return true;
    }

    struct ProcessIdentity
    {
        uint32_t Pid = 0;
        uint64_t Eprocess = 0;
        uint64_t CreateTime = 0;
        std::wstring Image;
        std::wstring ImagePath;
    };

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ValidHandleField(const TypeFieldInfo& field, uint64_t width)
    {
        return field.Length == width && field.Offset <= 0x10000 - width;
    }

    struct HandleObjectLayout
    {
        uint64_t BodyOffset = 0;
        uint64_t TypeOffset = 0;
        uint8_t Cookie = 0;
        bool Known = false;
    };

    template<typename Read>
    bool ReadHandleObjectType(Read read, const HandleObjectLayout& layout, uint64_t object, uint32_t* type)
    {
        if (!layout.Known || !IsKernelAddress(object) || object > UINT64_MAX - 0x10000 ||
            layout.BodyOffset == 0 || object < layout.BodyOffset)
        {
            return false;
        }
        const uint64_t header = object - layout.BodyOffset;
        uint8_t raw = 0;
        if (!read(header + layout.TypeOffset, &raw, sizeof(raw)))
        {
            return false;
        }
        *type = raw ^ layout.Cookie ^ static_cast<uint8_t>(header >> 8);
        return *type != 0;
    }

    template<typename Read, typename CheckType>
    bool ReadStableHandleProcess(Read read, CheckType checkType, uint64_t object,
        uint64_t pidOffset, uint64_t createOffset, uint32_t* pid, uint64_t* created)
    {
        uint64_t beforePid = 0, beforeCreated = 0, afterPid = 0, afterCreated = 0;
        if (!IsKernelAddress(object) || object > UINT64_MAX - 0x10000 ||
            !checkType(object, L"Process") ||
            !read(object + pidOffset, &beforePid, sizeof(beforePid)) ||
            !read(object + createOffset, &beforeCreated, sizeof(beforeCreated)) ||
            !read(object + createOffset, &afterCreated, sizeof(afterCreated)) ||
            !read(object + pidOffset, &afterPid, sizeof(afterPid)) ||
            !checkType(object, L"Process") || beforePid == 0 || beforePid > UINT32_MAX ||
            beforeCreated == 0 || beforePid != afterPid || beforeCreated != afterCreated)
        {
            return false;
        }
        *pid = static_cast<uint32_t>(beforePid);
        *created = beforeCreated;
        return true;
    }

    struct HandleRelationshipLayout
    {
        bool ProcessKnown = false;
        uint64_t Pid = 0;
        uint64_t Created = 0;
        bool ThreadKnown = false;
        uint64_t ThreadProcess = 0;
        uint64_t ThreadProcessAdjustment = 0;
        bool WorkerKnown = false;
        uint64_t WorkerProcess = 0;
        bool FileKnown = false;
        uint64_t FileDevice = 0;
        uint64_t DeviceDriver = 0;
        uint64_t DeviceType = 0;
    };

    enum class HandleRelationshipStatus
    {
        NotApplicable,
        Unsupported,
        Unreadable,
        Resolved
    };

    template<typename Read, typename CheckType>
    HandleRelationshipStatus ReadHandleRelationship(Read read, CheckType checkType,
        const HandleRelationshipLayout& layout, HandleTableRecord* record)
    {
        const bool process = record->TypeName == L"Process";
        const bool thread = record->TypeName == L"Thread";
        const bool worker = record->TypeName == L"TpWorkerFactory";
        const bool file = record->TypeName == L"File";
        if (!process && !thread && !worker && !file)
        {
            return HandleRelationshipStatus::NotApplicable;
        }
        if (((process || thread || worker) && !layout.ProcessKnown) ||
            (thread && !layout.ThreadKnown) || (worker && !layout.WorkerKnown) || (file && !layout.FileKnown))
        {
            return HandleRelationshipStatus::Unsupported;
        }
        if (!checkType(record->Object, record->TypeName.c_str()))
        {
            return HandleRelationshipStatus::Unreadable;
        }
        if (process || thread || worker)
        {
            uint64_t target = record->Object, related = 0, relatedAfter = 0;
            const uint64_t relationOffset = thread ? layout.ThreadProcess : layout.WorkerProcess;
            if (!process)
            {
                if (!read(record->Object + relationOffset, &related, sizeof(related)) ||
                    related < (thread ? layout.ThreadProcessAdjustment : 0))
                {
                    return HandleRelationshipStatus::Unreadable;
                }
                target = related - (thread ? layout.ThreadProcessAdjustment : 0);
            }
            uint32_t pid = 0;
            uint64_t created = 0;
            if (!ReadStableHandleProcess(read, checkType, target, layout.Pid, layout.Created, &pid, &created) ||
                (!process && (!read(record->Object + relationOffset, &relatedAfter, sizeof(relatedAfter)) ||
                    related != relatedAfter)) || !checkType(record->Object, record->TypeName.c_str()))
            {
                return HandleRelationshipStatus::Unreadable;
            }
            record->TargetPid = pid;
            record->TargetEprocess = target;
            record->TargetCreateTime = created;
            record->TargetIdentityKnown = true;
            record->PointsToProcess = process;
        }
        else
        {
            uint64_t device = 0, driver = 0, deviceAfter = 0, driverAfter = 0;
            uint32_t deviceType = 0, deviceTypeAfter = 0;
            if (!read(record->Object + layout.FileDevice, &device, sizeof(device)) ||
                !checkType(device, L"Device") ||
                !read(device + layout.DeviceDriver, &driver, sizeof(driver)) ||
                !checkType(driver, L"Driver") ||
                !read(device + layout.DeviceType, &deviceType, sizeof(deviceType)) ||
                !read(record->Object + layout.FileDevice, &deviceAfter, sizeof(deviceAfter)) || device != deviceAfter ||
                !read(device + layout.DeviceDriver, &driverAfter, sizeof(driverAfter)) || driver != driverAfter ||
                !read(device + layout.DeviceType, &deviceTypeAfter, sizeof(deviceTypeAfter)) || deviceType != deviceTypeAfter ||
                !checkType(device, L"Device") || !checkType(driver, L"Driver") ||
                !checkType(record->Object, L"File"))
            {
                return HandleRelationshipStatus::Unreadable;
            }
            record->DeviceObject = device;
            record->DriverObject = driver;
            record->DeviceType = deviceType;
        }
        record->RelationshipResolved = true;
        return HandleRelationshipStatus::Resolved;
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

    template<typename Read>
    bool ReadHandleUnicodeString(Read read, uint64_t address, std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            value->clear();
            uint8_t header[16] = {}, verified[16] = {};
            uint16_t length = 0, maximum = 0;
            uint64_t buffer = 0;
            if (!read(address, header, sizeof(header)))
            {
                break;
            }
            std::memcpy(&length, header, sizeof(length));
            std::memcpy(&maximum, header + 2, sizeof(maximum));
            std::memcpy(&buffer, header + 8, sizeof(buffer));
            if ((length & 1u) != 0 || (maximum & 1u) != 0 || length > maximum || length > 2048)
            {
                break;
            }
            if (length == 0)
            {
                ok = true;
                break;
            }
            if (!IsKernelAddress(buffer) || buffer > UINT64_MAX - length)
            {
                break;
            }
            std::wstring complete(length / sizeof(wchar_t), L'\0');
            if (!read(buffer, &complete[0], length) || !read(address, verified, sizeof(verified)) ||
                std::memcmp(header, verified, sizeof(header)) != 0 || complete.find(L'\0') != std::wstring::npos)
            {
                break;
            }

            *value = std::move(complete);
            ok = !value->empty();
        } while (false);

        return ok;
    }

    bool ReadKernelUnicodeString(DeviceClient& device, uint64_t address, std::wstring* value)
    {
        return ReadHandleUnicodeString([&](uint64_t at, void* output, size_t length)
        {
            std::vector<uint8_t> bytes;
            if (length > UINT32_MAX || !device.ReadMemory(at, static_cast<uint32_t>(length), &bytes, nullptr) ||
                bytes.size() != length)
            {
                return false;
            }
            std::memcpy(output, bytes.data(), length);
            return true;
        }, address, value);
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
            TypeFieldInfo createdField = {};
            std::wstring ignored;
            if (!symbols.FindField(L"nt!_EPROCESS", L"ActiveProcessLinks", &linksField, &ignored) ||
                !symbols.FindField(L"nt!_EPROCESS", L"UniqueProcessId", &pidField, &ignored) ||
                !ValidHandleField(linksField, 16) || !ValidHandleField(pidField, 8))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"EPROCESS ActiveProcessLinks/UniqueProcessId not in PDB");
                }
                break;
            }

            symbols.FindField(L"nt!_EPROCESS", L"ImageFileName", &imageField, &ignored);
            const bool creationKnown = symbols.FindField(L"nt!_EPROCESS", L"CreateTime", &createdField, &ignored) &&
                ValidHandleField(createdField, 8);

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
                if (!IsKernelAddress(eprocess) || eprocess > UINT64_MAX - 0x10000)
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
                if (creationKnown && !ReadU64(device, eprocess + createdField.Offset, &identity.CreateTime))
                {
                    break;
                }
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
                uint64_t verifiedPid = 0, verifiedCreated = 0;
                if (!ReadU64(device, eprocess + pidField.Offset, &verifiedPid) || verifiedPid != pidValue ||
                    (creationKnown && (!ReadU64(device, eprocess + createdField.Offset, &verifiedCreated) ||
                    verifiedCreated != identity.CreateTime)))
                {
                    break;
                }
                processes->push_back(identity);

                uint64_t next = 0;
                if (!ReadU64(device, current, &next) || next == current)
                {
                    break;
                }
                current = next;
            }

            ok = current == listHead;
            if (!ok && warnings != nullptr)
            {
                warnings->push_back(L"ActiveProcessLinks inventory was incomplete or changed during collection");
            }
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
        result->NextHandleAfter = options.HandleAfter;
        if (options.ContinueHandles && !options.HasOwnerPid)
        {
            if (error != nullptr)
            {
                *error = L"handle continuation requires one owner PID";
            }
            break;
        }
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
        result->ProcessInventoryRequested = !options.ContinueHandles;
        if (result->ProcessInventoryRequested)
        {
            result->ProcessInventoryComplete = EnumerateKernelProcesses(device_, symbols_, &processes, &result->Warnings);
        }
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

        const size_t returnedBytes = needed != 0 && needed <= buffer.size() ? needed : 0;
        if (returnedBytes < sizeof(ULONG_PTR) * 2)
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
        const uint64_t maxCount = (returnedBytes - headerBytes) / sizeof(SystemHandleTableEntryEx);
        const uint64_t useCount = count < maxCount ? count : maxCount;
        if (count > maxCount)
        {
            result->Warnings.push_back(L"handle snapshot was truncated by buffer size");
        }

        result->HandlesEnumerated = useCount;
        result->CoverageComplete = count <= maxCount && status >= 0;
        HandleRecordBatch batch;
        if (options.ContinueHandles)
        {
            batch = SelectHandleRecordBatch(table->Handles, static_cast<size_t>(useCount), options);
            result->HandleCandidates = batch.Candidates;
            result->InvalidHandleEntries = batch.InvalidEntries;
            result->HandleCoveragePartial = batch.Indices.size() < batch.Candidates || batch.InvalidEntries != 0;
        }
        std::unordered_set<uint32_t> owners;
        bool storeCapWarned = false;
        uint64_t typeTable = 0;
        TypeFieldInfo typeName = {};
        TypeFieldInfo typeIndex = {};
        const bool typeLayout = symbols_.ResolveSymbol(L"nt!ObTypeIndexTable", &typeTable, nullptr) &&
            IsKernelAddress(typeTable) && symbols_.FindField(L"nt!_OBJECT_TYPE", L"Name", &typeName, nullptr) &&
            symbols_.FindField(L"nt!_OBJECT_TYPE", L"Index", &typeIndex, nullptr) &&
            ValidHandleField(typeIndex, 1) && ValidHandleField(typeName, 16);
        std::unordered_map<uint32_t, std::wstring> typeNames;
        HandleReadBudget relationshipBudget;
        relationshipBudget.Limit = options.ContinueHandles ? 4096 : 0;
        const auto read = [&](uint64_t address, void* output, size_t length)
        {
            std::vector<uint8_t> bytes;
            if (!IsKernelAddress(address) || length > UINT32_MAX || address > UINT64_MAX - length ||
                !relationshipBudget.Acquire() ||
                !device_.ReadMemory(address, static_cast<uint32_t>(length), &bytes, nullptr) || bytes.size() != length)
            {
                return false;
            }
            std::memcpy(output, bytes.data(), length);
            return true;
        };
        const auto resolveTypeName = [&](uint32_t index) -> const std::wstring&
        {
            auto found = typeNames.find(index);
            if (found == typeNames.end())
            {
                std::wstring name;
                uint64_t objectType = 0;
                uint8_t actualIndex = 0;
                if (typeLayout && index > 0 && index < 256 &&
                    read(typeTable + index * sizeof(uint64_t), &objectType, sizeof(objectType)) &&
                    IsKernelAddress(objectType) && objectType <= UINT64_MAX - 0x10000 &&
                    read(objectType + typeIndex.Offset, &actualIndex, sizeof(actualIndex)) && actualIndex == index)
                {
                    ReadHandleUnicodeString(read, objectType + typeName.Offset, &name);
                }
                found = typeNames.emplace(index, std::move(name)).first;
            }
            return found->second;
        };
        HandleObjectLayout objectLayout;
        TypeFieldInfo objectBody = {}, objectIndex = {};
        uint64_t cookieAddress = 0;
        objectLayout.Known = symbols_.FindField(L"nt!_OBJECT_HEADER", L"Body", &objectBody, nullptr) &&
            symbols_.FindField(L"nt!_OBJECT_HEADER", L"TypeIndex", &objectIndex, nullptr) &&
            objectBody.Offset > 0 && objectBody.Offset <= 0x1000 && objectIndex.Offset < objectBody.Offset &&
            objectIndex.Length == 1 && symbols_.ResolveSymbol(L"nt!ObHeaderCookie", &cookieAddress, nullptr) &&
            read(cookieAddress, &objectLayout.Cookie, sizeof(objectLayout.Cookie));
        objectLayout.BodyOffset = objectBody.Offset;
        objectLayout.TypeOffset = objectIndex.Offset;
        const auto checkType = [&](uint64_t object, const wchar_t* expected)
        {
            uint32_t index = 0;
            return ReadHandleObjectType(read, objectLayout, object, &index) && resolveTypeName(index) == expected;
        };
        TypeFieldInfo threadProcess = {}, processPcb = {}, workerProcess = {}, processCreated = {}, processPid = {};
        TypeFieldInfo fileDevice = {}, deviceDriver = {}, deviceType = {};
        HandleRelationshipLayout relationship;
        relationship.ProcessKnown = symbols_.FindField(L"nt!_EPROCESS", L"UniqueProcessId", &processPid, nullptr) &&
            symbols_.FindField(L"nt!_EPROCESS", L"CreateTime", &processCreated, nullptr) &&
            ValidHandleField(processPid, 8) && ValidHandleField(processCreated, 8);
        relationship.Pid = processPid.Offset;
        relationship.Created = processCreated.Offset;
        relationship.ThreadKnown = symbols_.FindField(L"nt!_ETHREAD", L"ThreadsProcess", &threadProcess, nullptr) &&
            ValidHandleField(threadProcess, 8);
        if (!relationship.ThreadKnown)
        {
            relationship.ThreadKnown = symbols_.FindField(L"nt!_ETHREAD", L"Tcb.Process", &threadProcess, nullptr) &&
                ValidHandleField(threadProcess, 8) && symbols_.FindField(L"nt!_EPROCESS", L"Pcb", &processPcb, nullptr) &&
                processPcb.Offset < 0x10000;
            relationship.ThreadProcessAdjustment = processPcb.Offset;
        }
        relationship.ThreadProcess = threadProcess.Offset;
        relationship.WorkerKnown = symbols_.FindField(L"nt!_WORKER_FACTORY", L"Process", &workerProcess, nullptr) &&
            ValidHandleField(workerProcess, 8);
        relationship.WorkerProcess = workerProcess.Offset;
        relationship.FileKnown = symbols_.FindField(L"nt!_FILE_OBJECT", L"DeviceObject", &fileDevice, nullptr) &&
            symbols_.FindField(L"nt!_DEVICE_OBJECT", L"DriverObject", &deviceDriver, nullptr) &&
            symbols_.FindField(L"nt!_DEVICE_OBJECT", L"DeviceType", &deviceType, nullptr) &&
            ValidHandleField(fileDevice, 8) && ValidHandleField(deviceDriver, 8) && ValidHandleField(deviceType, 4);
        relationship.FileDevice = fileDevice.Offset;
        relationship.DeviceDriver = deviceDriver.Offset;
        relationship.DeviceType = deviceType.Offset;

        const size_t visitCount = options.ContinueHandles ? batch.Indices.size() : static_cast<size_t>(useCount);
        for (size_t visit = 0; visit < visitCount; ++visit)
        {
            const size_t index = options.ContinueHandles ? batch.Indices[visit] : visit;
            const SystemHandleTableEntryEx& entry = table->Handles[index];
            const uint64_t typeFailuresBefore = result->ObjectTypeReadFailures;
            const uint64_t relationshipFailuresBefore = result->RelationshipReadFailures;
            const uint64_t unsupportedBefore = result->RelationshipUnsupported;
            HandleTableRecord record = {};
            if (static_cast<uint64_t>(entry.UniqueProcessId) > 0xFFFFFFFFull)
            {
                continue;
            }
            record.OwnerPid = static_cast<uint32_t>(entry.UniqueProcessId);
            if (options.HasOwnerPid && record.OwnerPid != options.OwnerPid)
            {
                continue;
            }
            if (static_cast<uint64_t>(entry.HandleValue) > 0xFFFFFFFFull)
            {
                continue;
            }
            record.HandleValue = static_cast<uint32_t>(entry.HandleValue);
            if (!options.ContinueHandles)
            {
                ++result->HandleCandidates;
            }
            record.GrantedAccess = entry.GrantedAccess;
            record.ObjectTypeIndex = entry.ObjectTypeIndex;
            record.HandleAttributes = entry.HandleAttributes;
            record.Object = reinterpret_cast<uint64_t>(entry.Object);
            record.AccessText = JsonHex(record.GrantedAccess);
            record.TypeName = resolveTypeName(record.ObjectTypeIndex);
            record.TypeResolved = !record.TypeName.empty();
            if (!record.TypeResolved)
            {
                ++result->ObjectTypeReadFailures;
            }

            std::wstring ownerPath;
            auto ownerIt = byPid.find(record.OwnerPid);
            if (ownerIt != byPid.end())
            {
                record.OwnerImage = ownerIt->second.Image;
                ownerPath = ownerIt->second.ImagePath;
            }

            if (record.TypeName == L"Process")
            {
                record.AccessText = AccessTextFromMask(record.GrantedAccess);
                record.VmRead = (record.GrantedAccess & kProcessVmRead) != 0;
                record.VmWrite = (record.GrantedAccess & kProcessVmWrite) != 0;
                record.VmOperation = (record.GrantedAccess & kProcessVmOperation) != 0;
                record.DupHandle = (record.GrantedAccess & kProcessDupHandle) != 0;
            }
            if (record.TypeResolved)
            {
                uint32_t beforeType = 0, afterType = 0;
                const bool typeMatches = ReadHandleObjectType(read, objectLayout, record.Object, &beforeType) &&
                    beforeType == record.ObjectTypeIndex;
                const auto relationshipStatus = typeMatches ? ReadHandleRelationship(read, checkType, relationship, &record) :
                    objectLayout.Known ? HandleRelationshipStatus::Unreadable : HandleRelationshipStatus::Unsupported;
                record.ObjectTypeValidated = typeMatches &&
                    ReadHandleObjectType(read, objectLayout, record.Object, &afterType) && beforeType == afterType;
                if (!record.ObjectTypeValidated || relationshipStatus == HandleRelationshipStatus::Unreadable ||
                    relationshipStatus == HandleRelationshipStatus::Unsupported)
                {
                    if (relationshipStatus == HandleRelationshipStatus::Unsupported)
                    {
                        ++result->RelationshipUnsupported;
                    }
                    else
                    {
                        ++result->RelationshipReadFailures;
                    }
                    record.RelationshipResolved = false;
                    record.PointsToProcess = false;
                    record.TargetIdentityKnown = false;
                    record.TargetPid = 0;
                    record.TargetEprocess = 0;
                    record.TargetCreateTime = 0;
                    record.DeviceObject = 0;
                    record.DriverObject = 0;
                    record.DeviceType = 0;
                }
            }
            if (!CompleteHandleVisit(record.HandleValue, options.ContinueHandles, relationshipBudget, result))
            {
                result->ObjectTypeReadFailures = typeFailuresBefore;
                result->RelationshipReadFailures = relationshipFailuresBefore;
                result->RelationshipUnsupported = unsupportedBefore;
                break;
            }
            record.PointsToProcess = record.TypeResolved && record.TypeName == L"Process";
            if (record.PointsToProcess)
            {
                ++result->ProcessHandles;
            }
            const auto targetIdentity = byEprocess.find(record.TargetEprocess);
            if (record.TargetIdentityKnown && targetIdentity != byEprocess.end() &&
                targetIdentity->second.Pid == record.TargetPid && targetIdentity->second.CreateTime == record.TargetCreateTime)
            {
                record.TargetImage = targetIdentity->second.Image;
            }

            if (options.HasOwnerPid && record.OwnerPid != options.OwnerPid)
            {
                continue;
            }
            if (options.HasTargetPid)
            {
                if (!record.TargetIdentityKnown || record.TargetPid != options.TargetPid)
                {
                    continue;
                }
            }
            if (options.ProcessHandlesOnly && !record.PointsToProcess)
            {
                continue;
            }

            if (record.PointsToProcess &&
                record.TargetIdentityKnown &&
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
        result->RelationshipReadAttempts = relationshipBudget.Attempts;
        result->ObjectTypeCoverageComplete = typeLayout && result->ObjectTypeReadFailures == 0;
        result->RelationshipCoverageComplete = objectLayout.Known && result->ObjectTypeCoverageComplete &&
            result->RelationshipReadFailures == 0 && result->RelationshipUnsupported == 0 &&
            !result->RelationshipBudgetExhausted && !result->HandleCoveragePartial;
        result->CoverageComplete = result->CoverageComplete && !result->Truncated && !result->HandleCoveragePartial;
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
    json << L",\"process_inventory_requested\":" << (result.ProcessInventoryRequested ? L"true" : L"false");
    json << L",\"process_inventory_complete\":" << (result.ProcessInventoryComplete ? L"true" : L"false");
    json << L",\"object_type_coverage_complete\":" << (result.ObjectTypeCoverageComplete ? L"true" : L"false");
    json << L",\"object_type_read_failures\":" << result.ObjectTypeReadFailures;
    json << L",\"relationship_coverage_complete\":" << (result.RelationshipCoverageComplete ? L"true" : L"false");
    json << L",\"relationship_read_failures\":" << result.RelationshipReadFailures;
    json << L",\"relationship_unsupported\":" << result.RelationshipUnsupported;
    json << L",\"handle_candidates\":" << result.HandleCandidates;
    json << L",\"handles_visited\":" << result.HandlesVisited;
    json << L",\"invalid_handle_entries\":" << result.InvalidHandleEntries;
    json << L",\"next_handle_after\":\"" << JsonHex(result.NextHandleAfter) << L"\"";
    json << L",\"relationship_read_attempts\":" << result.RelationshipReadAttempts;
    json << L",\"handle_coverage_partial\":" << (result.HandleCoveragePartial ? L"true" : L"false");
    json << L",\"relationship_budget_exhausted\":" << (result.RelationshipBudgetExhausted ? L"true" : L"false");
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
        json << L",\"type_resolved\":" << (record.TypeResolved ? L"true" : L"false");
        json << L",\"object_type_validated\":" << (record.ObjectTypeValidated ? L"true" : L"false");
        json << L",\"relationship_resolved\":" << (record.RelationshipResolved ? L"true" : L"false");
        json << L",\"target_identity_known\":" << (record.TargetIdentityKnown ? L"true" : L"false");
        json << L",\"target_eprocess\":\"" << JsonHex(record.TargetEprocess) << L"\"";
        json << L",\"target_create_time\":\"" << JsonHex(record.TargetCreateTime) << L"\"";
        json << L",\"device_object\":\"" << JsonHex(record.DeviceObject) << L"\"";
        json << L",\"driver_object\":\"" << JsonHex(record.DriverObject) << L"\"";
        json << L",\"device_type\":" << record.DeviceType;
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

std::wstring HandleTableRecordIdentity(const HandleTableRecord& record)
{
    return JsonHex(record.HandleValue) + L":" + JsonHex(record.Object) + L":" + JsonHex(record.GrantedAccess) +
        L":" + std::to_wstring(record.ObjectTypeIndex) + L":" + std::to_wstring(record.ObjectTypeValidated) +
        L":" + std::to_wstring(record.RelationshipResolved) + L":" + std::to_wstring(record.TargetPid) +
        L":" + JsonHex(record.TargetEprocess) + L":" + JsonHex(record.TargetCreateTime) +
        L":" + JsonHex(record.DeviceObject) + L":" + JsonHex(record.DriverObject) + L":" + JsonHex(record.DeviceType);
}

std::vector<uint32_t> SelectHandleOwnerBatch(std::vector<uint32_t> pids, uint64_t* afterPid, size_t limit)
{
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    if (afterPid != nullptr && !pids.empty() && limit != 0)
    {
        const auto start = std::upper_bound(pids.begin(), pids.end(), *afterPid);
        std::rotate(pids.begin(), start, pids.end());
        pids.resize((std::min)(limit, pids.size()));
        *afterPid = pids.back();
    }

    else
    {
        pids.clear();
    }
    return pids;
}

bool HandleTableAccessMaskSelfTest()
{
    bool ok = false;

    do
    {
        std::vector<SystemHandleTableEntryEx> inventory(4097);
        for (size_t index = 0; index < inventory.size(); ++index)
        {
            inventory[index].UniqueProcessId = 100;
            inventory[index].HandleValue = (index + 1) * 4;
        }
        HandleTableScanOptions continued;
        continued.HasOwnerPid = true;
        continued.OwnerPid = 100;
        continued.ContinueHandles = true;
        continued.MaxHandlesPerPass = UINT32_MAX;
        const auto firstHandles = SelectHandleRecordBatch(inventory.data(), inventory.size(), continued);
        if (firstHandles.Indices.size() != 4096 || firstHandles.Candidates != 4097 || firstHandles.InvalidEntries != 0)
        {
            break;
        }
        continued.HandleAfter = inventory[firstHandles.Indices.back()].HandleValue;
        inventory.erase(inventory.begin() + 4095);
        SystemHandleTableEntryEx prefix = {};
        prefix.UniqueProcessId = 100;
        prefix.HandleValue = 1;
        inventory.insert(inventory.begin(), prefix);
        const auto tailHandles = SelectHandleRecordBatch(inventory.data(), inventory.size(), continued);
        if (tailHandles.Indices.empty() || inventory[tailHandles.Indices.front()].HandleValue != 4097 * 4)
        {
            break;
        }
        continued.HandleAfter = UINT64_MAX;
        continued.Limit = 1;
        const auto wrappedHandles = SelectHandleRecordBatch(inventory.data(), inventory.size(), continued);
        if (wrappedHandles.Indices.size() != 1 || inventory[wrappedHandles.Indices.front()].HandleValue != 1)
        {
            break;
        }
        prefix.HandleValue = UINT64_MAX;
        inventory.push_back(prefix);
        inventory.push_back(inventory.front());
        const auto ambiguous = SelectHandleRecordBatch(inventory.data(), inventory.size(), continued);
        if (ambiguous.InvalidEntries != 3 || ambiguous.Indices.empty() ||
            inventory[ambiguous.Indices.front()].HandleValue == 1)
        {
            break;
        }
        HandleReadBudget strictBudget;
        strictBudget.Limit = 4096;
        for (uint32_t attempt = 0; attempt < 4096; ++attempt)
        {
            if (!strictBudget.Acquire())
            {
                return false;
            }
        }
        HandleTableScanResult exactFit;
        if (!CompleteHandleVisit(12, true, strictBudget, &exactFit) || exactFit.RelationshipBudgetExhausted ||
            exactFit.HandleCoveragePartial || exactFit.NextHandleAfter != 12)
        {
            break;
        }
        if (strictBudget.Acquire() || strictBudget.Attempts != 4096 || !strictBudget.Denied)
        {
            break;
        }
        HandleTableScanResult pending;
        pending.NextHandleAfter = 12;
        if (CompleteHandleVisit(16, true, strictBudget, &pending) || pending.NextHandleAfter != 12 ||
            !pending.RelationshipBudgetExhausted || !pending.HandleCoveragePartial || pending.HandlesVisited != 0)
        {
            break;
        }
        inventory.clear();
        for (uint32_t handle : {4, 8, 12, 16})
        {
            prefix.HandleValue = handle;
            inventory.push_back(prefix);
        }
        continued.HandleAfter = pending.NextHandleAfter;
        const auto retry = SelectHandleRecordBatch(inventory.data(), inventory.size(), continued);
        HandleReadBudget freshBudget;
        freshBudget.Limit = 4096;
        if (retry.Indices.empty() || inventory[retry.Indices.front()].HandleValue != 16 ||
            !freshBudget.Acquire() || !CompleteHandleVisit(16, true, freshBudget, &pending) || pending.NextHandleAfter != 16)
        {
            break;
        }
        const uint64_t oldProcess = 0xffff800000100000ull;
        const uint64_t newProcess = 0xffff800000200000ull;
        const uint64_t thread = 0xffff800000300000ull;
        const uint64_t file = 0xffff800000400000ull;
        const uint64_t device = 0xffff800000500000ull;
        const uint64_t driver = 0xffff800000600000ull;
        std::map<uint64_t, std::vector<uint8_t>> memory;
        std::map<uint64_t, std::wstring> types = {{oldProcess, L"Process"}, {newProcess, L"Process"},
            {thread, L"Thread"}, {file, L"File"}, {device, L"Device"}, {driver, L"Driver"}};
        const auto put = [&](uint64_t address, auto value)
        {
            memory[address].resize(sizeof(value));
            std::memcpy(memory[address].data(), &value, sizeof(value));
        };
        uint64_t failRead = 0;
        bool mutatePid = false;
        uint32_t pidReads = 0;
        const auto read = [&](uint64_t address, void* output, size_t length)
        {
            const auto found = memory.find(address);
            if (address == failRead || found == memory.end() || found->second.size() != length)
            {
                return false;
            }
            std::memcpy(output, found->second.data(), length);
            if (address == oldProcess + 16 && mutatePid && ++pidReads == 2)
            {
                const uint64_t reusedPid = 901;
                std::memcpy(output, &reusedPid, sizeof(reusedPid));
            }
            return true;
        };
        const auto checkType = [&](uint64_t object, const wchar_t* expected)
        {
            const auto found = types.find(object);
            return found != types.end() && found->second == expected;
        };
        HandleObjectLayout header;
        header.Known = true;
        header.BodyOffset = 0x30;
        header.TypeOffset = 0x18;
        header.Cookie = 0x5a;
        const uint64_t headerAddress = file - header.BodyOffset;
        put(headerAddress + header.TypeOffset, static_cast<uint8_t>(7 ^ header.Cookie ^ static_cast<uint8_t>(headerAddress >> 8)));
        uint32_t actualType = 0;
        if (!ReadHandleObjectType(read, header, file, &actualType) || actualType != 7)
        {
            break;
        }
        failRead = headerAddress + header.TypeOffset;
        if (ReadHandleObjectType(read, header, file, &actualType))
        {
            break;
        }
        failRead = 0;
        HandleRelationshipLayout layout;
        layout.ProcessKnown = true;
        layout.Pid = 16;
        layout.Created = 24;
        layout.ThreadKnown = true;
        layout.ThreadProcess = 32;
        layout.ThreadProcessAdjustment = 0x80;
        layout.WorkerKnown = true;
        layout.WorkerProcess = 32;
        layout.FileKnown = true;
        layout.FileDevice = 32;
        layout.DeviceDriver = 40;
        layout.DeviceType = 48;
        put(oldProcess + 16, uint64_t(900));
        put(oldProcess + 24, uint64_t(123));
        put(newProcess + 16, uint64_t(900));
        put(newProcess + 24, uint64_t(124));
        put(thread + 32, oldProcess + layout.ThreadProcessAdjustment);
        HandleTableRecord threadRecord;
        threadRecord.Object = thread;
        threadRecord.TypeName = L"Thread";
        if (ReadHandleRelationship(read, checkType, layout, &threadRecord) != HandleRelationshipStatus::Resolved ||
            threadRecord.TargetEprocess != oldProcess || threadRecord.TargetCreateTime != 123 ||
            !threadRecord.TargetIdentityKnown)
        {
            break;
        }
        threadRecord = {};
        threadRecord.Object = thread;
        threadRecord.TypeName = L"Thread";
        mutatePid = true;
        if (ReadHandleRelationship(read, checkType, layout, &threadRecord) != HandleRelationshipStatus::Unreadable ||
            threadRecord.TargetIdentityKnown)
        {
            break;
        }
        mutatePid = false;
        put(file + 32, device);
        put(device + 40, driver);
        put(device + 48, uint32_t(0x22));
        HandleTableRecord fileRecord;
        fileRecord.HandleValue = 4;
        fileRecord.Object = file;
        fileRecord.TypeName = L"File";
        fileRecord.ObjectTypeIndex = 7;
        const std::wstring incompleteIdentity = HandleTableRecordIdentity(fileRecord);
        failRead = device + 40;
        if (ReadHandleRelationship(read, checkType, layout, &fileRecord) != HandleRelationshipStatus::Unreadable ||
            fileRecord.DeviceObject != 0 || fileRecord.DriverObject != 0)
        {
            break;
        }
        failRead = 0;
        if (ReadHandleRelationship(read, checkType, layout, &fileRecord) != HandleRelationshipStatus::Resolved ||
            fileRecord.DeviceObject != device || fileRecord.DriverObject != driver || fileRecord.DeviceType != 0x22 ||
            incompleteIdentity == HandleTableRecordIdentity(fileRecord))
        {
            break;
        }
        fileRecord = {};
        fileRecord.Object = file;
        fileRecord.TypeName = L"File";
        types[device] = L"Thread";
        if (ReadHandleRelationship(read, checkType, layout, &fileRecord) != HandleRelationshipStatus::Unreadable)
        {
            break;
        }
        types[device] = L"Device";
        layout.FileKnown = false;
        if (ReadHandleRelationship(read, checkType, layout, &fileRecord) != HandleRelationshipStatus::Unsupported)
        {
            break;
        }
        const uint64_t unicode = 0xffff800000700000ull;
        const uint64_t text = unicode + 0x100;
        memory[unicode].assign(16, uint8_t(0));
        uint16_t length = 8;
        std::memcpy(memory[unicode].data(), &length, sizeof(length));
        std::memcpy(memory[unicode].data() + 2, &length, sizeof(length));
        std::memcpy(memory[unicode].data() + 8, &text, sizeof(text));
        memory[text].resize(length);
        std::memcpy(memory[text].data(), L"File", length);
        std::wstring name;
        if (!ReadHandleUnicodeString(read, unicode, &name) || name != L"File")
        {
            break;
        }
        memory[text].pop_back();
        if (ReadHandleUnicodeString(read, unicode, &name) || !name.empty())
        {
            break;
        }
        memory[unicode][0] = 7;
        if (ReadHandleUnicodeString(read, unicode, &name))
        {
            break;
        }
        memory[unicode][0] = 8;
        memory[unicode][2] = 6;
        if (ReadHandleUnicodeString(read, unicode, &name))
        {
            break;
        }
        uint64_t anchor = 0;
        const auto first = SelectHandleOwnerBatch({10,20,30,40,50,60,70,80,90}, &anchor, 8);
        const auto second = SelectHandleOwnerBatch({1,2,3,10,20,30,40,50,60,70,80,90}, &anchor, 8);
        if (first.size() != 8 || first.back() != 80 || second.empty() || second.front() != 90)
        {
            break;
        }
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
