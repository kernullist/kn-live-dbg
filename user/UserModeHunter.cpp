#include "UserModeHunter.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace
{
    constexpr uint32_t kSystemProcessInformation = 5;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xc0000004);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xc0000023);
    constexpr uint64_t kPageSize = 0x1000ull;
    constexpr uint64_t kLargePrivateExecThreshold = 64ull * 1024ull * 1024ull;
    constexpr size_t kMaxPebStringBytes = 32768;
    constexpr size_t kMaxLdrModules = 1024;
    constexpr size_t kMaxDeepModuleComparisonsPerProcess = 96;
    constexpr size_t kMaxDeepPagesPerProcess = 512;
    constexpr size_t kMaxSampledExecPagesPerSection = 2;
    constexpr uint64_t kKernelAddressMin = 0xffff800000000000ull;

    struct HuntLocalUnicodeString
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct HuntSystemProcessInformation
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        HuntLocalUnicodeString ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
    };

    typedef LONG (NTAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

    struct ApiProcessRecord
    {
        uint32_t ProcessId = 0;
        uint32_t ParentProcessId = 0;
        bool HasParentProcessId = false;
        std::wstring ImageName;
    };

    struct DiskPeSection
    {
        std::wstring Name;
        uint32_t VirtualAddress = 0;
        uint32_t VirtualSize = 0;
        uint32_t PointerToRawData = 0;
        uint32_t SizeOfRawData = 0;
        uint32_t Characteristics = 0;
        bool Executable = false;
    };

    struct DiskPeMetadata
    {
        uint32_t EntryPointRva = 0;
        uint32_t FirstExecutableSectionRva = 0;
        uint32_t SizeOfHeaders = 0;
        bool HasEntryPoint = false;
        bool HasExecutableSection = false;
        std::vector<DiskPeSection> Sections;
    };

    struct BuiltinProcessProfile
    {
        const wchar_t* ImageName;
        bool System32;
        bool SysWow64;
        bool WindowsRoot;
        bool SessionZeroOnly;
        const wchar_t* const* ParentNames;
        size_t ParentNameCount;
        bool SvchostCommandLine;
    };

    struct SectionBackingLayout
    {
        TypeFieldInfo SubsectionControlArea = {};
        TypeFieldInfo ControlAreaFilePointer = {};
        TypeFieldInfo FileObjectFileName = {};
        bool HasSubsectionControlArea = false;
        bool HasControlAreaFilePointer = false;
        bool HasFileObjectFileName = false;
        bool Resolved = false;
        std::vector<std::wstring> Warnings;
    };

    std::wstring HuntHex(uint64_t value, uint32_t width = 0)
    {
        std::wstringstream stream;
        stream << L"0x";
        if (width != 0)
        {
            stream << std::setw(static_cast<int>(width)) << std::setfill(L'0');
        }
        stream << std::hex << std::nouppercase << value;
        return stream.str();
    }

    std::wstring HuntJsonEscape(const std::wstring& value)
    {
        std::wstring result;

        for (wchar_t ch : value)
        {
            switch (ch)
            {
            case L'\\':
                result += L"\\\\";
                break;
            case L'"':
                result += L"\\\"";
                break;
            case L'\b':
                result += L"\\b";
                break;
            case L'\f':
                result += L"\\f";
                break;
            case L'\n':
                result += L"\\n";
                break;
            case L'\r':
                result += L"\\r";
                break;
            case L'\t':
                result += L"\\t";
                break;
            default:
                if (ch < 0x20)
                {
                    std::wstringstream stream;
                    stream << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
                           << static_cast<uint32_t>(ch);
                    result += stream.str();
                }
                else
                {
                    result.push_back(ch);
                }
                break;
            }
        }

        return result;
    }

    std::wstring HuntToLower(const std::wstring& value)
    {
        std::wstring lowered = value;
        std::transform(
            lowered.begin(),
            lowered.end(),
            lowered.begin(),
            [](wchar_t ch)
            {
                return static_cast<wchar_t>(std::towlower(ch));
            });
        return lowered;
    }

    std::wstring NormalizePathText(const std::wstring& value)
    {
        std::wstring normalized = HuntToLower(value);
        std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
        return normalized;
    }

    std::wstring LeafName(const std::wstring& value)
    {
        std::wstring normalized = NormalizePathText(value);
        size_t slash = normalized.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < normalized.size())
        {
            return normalized.substr(slash + 1);
        }

        return normalized;
    }

    bool SameNonEmptyLeaf(const std::wstring& left, const std::wstring& right)
    {
        bool same = false;

        do
        {
            std::wstring leftLeaf = LeafName(left);
            std::wstring rightLeaf = LeafName(right);
            if (leftLeaf.empty() || rightLeaf.empty())
            {
                break;
            }

            same = leftLeaf == rightLeaf;
        } while (false);

        return same;
    }

    std::wstring FirstCommandLineImage(const std::wstring& commandLine)
    {
        std::wstring image;

        do
        {
            size_t begin = commandLine.find_first_not_of(L" \t\r\n");
            if (begin == std::wstring::npos)
            {
                break;
            }

            if (commandLine[begin] == L'"')
            {
                size_t end = commandLine.find(L'"', begin + 1);
                if (end != std::wstring::npos)
                {
                    image = commandLine.substr(begin + 1, end - begin - 1);
                }
                else
                {
                    image = commandLine.substr(begin + 1);
                }
                break;
            }

            size_t end = commandLine.find_first_of(L" \t\r\n", begin);
            if (end == std::wstring::npos)
            {
                image = commandLine.substr(begin);
            }
            else
            {
                image = commandLine.substr(begin, end - begin);
            }
        } while (false);

        return image;
    }

    uint32_t ConfidenceRank(const std::wstring& confidence)
    {
        uint32_t rank = 0;
        std::wstring lowered = HuntToLower(confidence);

        if (lowered == L"low")
        {
            rank = 1;
        }
        else if (lowered == L"medium")
        {
            rank = 2;
        }
        else if (lowered == L"high")
        {
            rank = 3;
        }

        return rank;
    }

    uint64_t TargetUserDtb(const SnapshotProcessRecord& process)
    {
        return process.UserDirectoryTableBase != 0
            ? process.UserDirectoryTableBase
            : process.DirectoryTableBase;
    }

    bool IsUserAddress(uint64_t value)
    {
        return value != 0 && value < 0x0000800000000000ull;
    }

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelAddressMin;
    }

    bool TryAdd(uint64_t base, uint64_t offset, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || offset > std::numeric_limits<uint64_t>::max() - base)
            {
                break;
            }

            *result = base + offset;
            ok = true;
        } while (false);

        return ok;
    }

    uint64_t DecodeInteger(const uint8_t* bytes, size_t width)
    {
        uint64_t value = 0;

        for (size_t index = 0; index < width && index < sizeof(value); ++index)
        {
            value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
        }

        return value;
    }

    bool AddUnique(std::vector<std::wstring>* values, const std::wstring& value)
    {
        bool added = false;

        do
        {
            if (values == nullptr || value.empty())
            {
                break;
            }

            if (std::find(values->begin(), values->end(), value) != values->end())
            {
                break;
            }

            values->push_back(value);
            added = true;
        } while (false);

        return added;
    }

    std::wstring JoinWideValues(const std::vector<std::wstring>& values, const std::wstring& delimiter)
    {
        std::wstringstream stream;

        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                stream << delimiter;
            }
            stream << values[index];
        }

        return stream.str();
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
            if (bytes == nullptr || address == 0 || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid kernel read request";
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

    bool ReadKernelInteger(
        DeviceClient& device,
        uint64_t address,
        size_t width,
        uint64_t* value,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || width == 0 || width > sizeof(uint64_t))
            {
                if (error != nullptr)
                {
                    *error = L"invalid integer read";
                }
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, static_cast<uint32_t>(width), &bytes, error))
            {
                break;
            }

            *value = DecodeInteger(bytes.data(), width);
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelPointer(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
    {
        return ReadKernelInteger(device, address, sizeof(uint64_t), value, error);
    }

    size_t FieldStorageWidth(const TypeFieldInfo& field, size_t fallback)
    {
        size_t width = fallback;

        if (field.IsBitField)
        {
            uint64_t bitEnd = static_cast<uint64_t>(field.BitPosition) + field.Length;
            if (bitEnd <= 8)
            {
                width = 1;
            }
            else if (bitEnd <= 16)
            {
                width = 2;
            }
            else if (bitEnd <= 32)
            {
                width = 4;
            }
            else
            {
                width = 8;
            }
        }
        else if (field.Length > 0 && field.Length <= sizeof(uint64_t))
        {
            width = static_cast<size_t>(field.Length);
        }

        return width;
    }

    bool ReadFieldInteger(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        size_t fallbackWidth,
        uint64_t* value,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            uint64_t address = 0;
            if (!TryAdd(base, field.Offset, &address))
            {
                if (error != nullptr)
                {
                    *error = L"field address overflow";
                }
                break;
            }

            uint64_t raw = 0;
            if (!ReadKernelInteger(device, address, FieldStorageWidth(field, fallbackWidth), &raw, error))
            {
                break;
            }

            if (field.IsBitField)
            {
                if (field.Length == 0 || field.Length > 64 || field.BitPosition >= 64)
                {
                    if (error != nullptr)
                    {
                        *error = L"invalid bitfield metadata";
                    }
                    break;
                }

                uint64_t mask = field.Length == 64
                    ? std::numeric_limits<uint64_t>::max()
                    : ((1ull << field.Length) - 1ull);
                raw = (raw >> field.BitPosition) & mask;
            }

            *value = raw;
            ok = true;
        } while (false);

        return ok;
    }

    bool FieldNameEquals(const TypeFieldInfo& field, const std::wstring& name)
    {
        return _wcsicmp(field.Name.c_str(), name.c_str()) == 0;
    }

    bool FindFieldRecursiveById(
        SymbolEngine& symbols,
        uint64_t moduleBase,
        ULONG typeId,
        const std::wstring& typeName,
        const std::wstring& fieldName,
        uint64_t baseOffset,
        uint32_t depth,
        std::vector<ULONG>* visited,
        TypeFieldInfo* out)
    {
        bool found = false;

        do
        {
            if (out == nullptr || visited == nullptr || typeId == 0 || depth > 5)
            {
                break;
            }

            if (std::find(visited->begin(), visited->end(), typeId) != visited->end())
            {
                break;
            }
            visited->push_back(typeId);

            TypeLayoutInfo layout = {};
            std::wstring ignored;
            if (!symbols.GetTypeLayoutById(moduleBase, typeId, typeName, &layout, &ignored))
            {
                break;
            }

            for (const TypeFieldInfo& field : layout.Fields)
            {
                if (FieldNameEquals(field, fieldName))
                {
                    *out = field;
                    out->Offset = static_cast<ULONG>(baseOffset + field.Offset);
                    found = true;
                    break;
                }
            }

            if (found)
            {
                break;
            }

            for (const TypeFieldInfo& field : layout.Fields)
            {
                if (field.ChildTypeId == 0 || field.ChildTypeId == typeId)
                {
                    continue;
                }

                std::vector<ULONG> branchVisited = *visited;
                if (FindFieldRecursiveById(
                        symbols,
                        field.ModuleBase != 0 ? field.ModuleBase : moduleBase,
                        field.ChildTypeId,
                        field.TypeName,
                        fieldName,
                        baseOffset + field.Offset,
                        depth + 1,
                        &branchVisited,
                        out))
                {
                    found = true;
                    break;
                }
            }
        } while (false);

        return found;
    }

    bool FindFieldRecursive(
        SymbolEngine& symbols,
        const std::vector<std::wstring>& typeNames,
        const std::wstring& fieldName,
        TypeFieldInfo* out)
    {
        bool found = false;

        do
        {
            if (out == nullptr)
            {
                break;
            }

            for (const std::wstring& typeName : typeNames)
            {
                TypeLayoutInfo layout = {};
                std::wstring ignored;
                if (!symbols.GetTypeLayout(typeName, &layout, &ignored))
                {
                    continue;
                }

                for (const TypeFieldInfo& field : layout.Fields)
                {
                    if (FieldNameEquals(field, fieldName))
                    {
                        *out = field;
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    break;
                }

                for (const TypeFieldInfo& field : layout.Fields)
                {
                    if (field.ChildTypeId == 0)
                    {
                        continue;
                    }

                    std::vector<ULONG> visited;
                    if (FindFieldRecursiveById(
                            symbols,
                            field.ModuleBase != 0 ? field.ModuleBase : layout.ModuleBase,
                            field.ChildTypeId,
                            field.TypeName,
                            fieldName,
                            field.Offset,
                            1,
                            &visited,
                            out))
                    {
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    break;
                }
            }
        } while (false);

        return found;
    }

    std::wstring Win32FilePathFromMaybeNtPath(const std::wstring& path)
    {
        std::wstring result = path;

        do
        {
            if (result.size() > 4 && result.compare(0, 4, L"\\??\\") == 0)
            {
                result = result.substr(4);
                break;
            }

            std::wstring lowered = NormalizePathText(result);
            if (lowered.compare(0, 12, L"\\systemroot\\") == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(_countof(windowsDirectory))) != 0)
                {
                    result = std::wstring(windowsDirectory) + result.substr(11);
                }
                break;
            }

            if (lowered.compare(0, 9, L"\\windows\\") == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(_countof(windowsDirectory))) != 0)
                {
                    std::wstring windowsPath = windowsDirectory;
                    if (windowsPath.size() >= 2 && windowsPath[1] == L':')
                    {
                        result = windowsPath.substr(0, 2) + result;
                    }
                }
                break;
            }

            if (lowered.compare(0, 4, L"\\\\?\\") == 0)
            {
                result = result.substr(4);
                break;
            }
        } while (false);

        return result;
    }

    std::wstring DosPathFromDevicePath(const std::wstring& path)
    {
        std::wstring result = path;

        do
        {
            std::wstring lowered = NormalizePathText(path);
            if (lowered.compare(0, 8, L"\\device\\") != 0)
            {
                break;
            }

            wchar_t drive[] = L"A:";
            for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
            {
                drive[0] = letter;
                wchar_t target[1024] = {};
                DWORD length = QueryDosDeviceW(drive, target, static_cast<DWORD>(_countof(target)));
                if (length == 0)
                {
                    continue;
                }

                std::wstring deviceName = NormalizePathText(target);
                if (deviceName.empty())
                {
                    continue;
                }

                if (lowered.compare(0, deviceName.size(), deviceName) == 0 &&
                    (lowered.size() == deviceName.size() || lowered[deviceName.size()] == L'\\'))
                {
                    result = std::wstring(drive) + path.substr(deviceName.size());
                    break;
                }
            }
        } while (false);

        return result;
    }

    std::wstring CanonicalPathForCompare(const std::wstring& path)
    {
        std::wstring result;

        do
        {
            if (path.empty())
            {
                break;
            }

            result = Win32FilePathFromMaybeNtPath(path);
            result = DosPathFromDevicePath(result);
            result = NormalizePathText(result);

            if (result.compare(0, 4, L"\\\\?\\") == 0)
            {
                result = result.substr(4);
            }
        } while (false);

        return result;
    }

    std::wstring EnsureTrailingSlash(std::wstring path)
    {
        if (!path.empty() && path.back() != L'\\')
        {
            path.push_back(L'\\');
        }

        return path;
    }

    std::wstring WindowsDirectory()
    {
        std::wstring result;
        wchar_t buffer[MAX_PATH] = {};

        if (GetWindowsDirectoryW(buffer, static_cast<UINT>(_countof(buffer))) != 0)
        {
            result = buffer;
        }
        else
        {
            result = L"C:\\Windows";
        }

        return result;
    }

    std::wstring SystemDirectory()
    {
        std::wstring result;
        wchar_t buffer[MAX_PATH] = {};

        if (GetSystemDirectoryW(buffer, static_cast<UINT>(_countof(buffer))) != 0)
        {
            result = buffer;
        }
        else
        {
            result = WindowsDirectory() + L"\\System32";
        }

        return result;
    }

    std::wstring ExpectedSystem32Path(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(SystemDirectory()) + imageName;
    }

    std::wstring ExpectedSysWow64Path(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + L"SysWOW64\\" + imageName;
    }

    std::wstring ExpectedWindowsRootPath(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + imageName;
    }

    bool SameCanonicalPath(const std::wstring& left, const std::wstring& right)
    {
        bool same = false;

        do
        {
            std::wstring l = CanonicalPathForCompare(left);
            std::wstring r = CanonicalPathForCompare(right);
            if (l.empty() || r.empty())
            {
                break;
            }

            same = l == r;
        } while (false);

        return same;
    }

    bool MatchesAnyCanonicalPath(const std::wstring& actual, const std::vector<std::wstring>& expected)
    {
        bool matched = false;

        do
        {
            if (actual.empty())
            {
                break;
            }

            for (const std::wstring& path : expected)
            {
                if (SameCanonicalPath(actual, path))
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    const BuiltinProcessProfile* FindBuiltinProfileByLeaf(const std::wstring& leaf)
    {
        const BuiltinProcessProfile* profile = nullptr;

        static const wchar_t* kParentSmss[] = { L"smss.exe" };
        static const wchar_t* kParentWininit[] = { L"wininit.exe" };
        static const wchar_t* kParentServices[] = { L"services.exe" };
        static const BuiltinProcessProfile kProfiles[] =
        {
            { L"smss.exe", true, false, false, true, nullptr, 0, false },
            { L"csrss.exe", true, false, false, false, kParentSmss, _countof(kParentSmss), false },
            { L"wininit.exe", true, false, false, true, kParentSmss, _countof(kParentSmss), false },
            { L"winlogon.exe", true, false, false, false, kParentSmss, _countof(kParentSmss), false },
            { L"services.exe", true, false, false, true, kParentWininit, _countof(kParentWininit), false },
            { L"lsass.exe", true, false, false, true, kParentWininit, _countof(kParentWininit), false },
            { L"svchost.exe", true, false, false, false, kParentServices, _countof(kParentServices), true },
            { L"spoolsv.exe", true, false, false, true, kParentServices, _countof(kParentServices), false },
            { L"conhost.exe", true, false, false, false, nullptr, 0, false },
            { L"dllhost.exe", true, true, false, false, nullptr, 0, false },
            { L"rundll32.exe", true, true, false, false, nullptr, 0, false },
            { L"regsvr32.exe", true, true, false, false, nullptr, 0, false },
            { L"taskhostw.exe", true, false, false, false, nullptr, 0, false },
            { L"runtimebroker.exe", true, false, false, false, nullptr, 0, false },
            { L"explorer.exe", false, false, true, false, nullptr, 0, false },
            { L"sihost.exe", true, false, false, false, nullptr, 0, false },
            { L"searchindexer.exe", true, false, false, true, kParentServices, _countof(kParentServices), false },
            { L"wmiprvse.exe", true, false, false, false, nullptr, 0, false }
        };

        do
        {
            if (leaf.empty())
            {
                break;
            }

            for (const BuiltinProcessProfile& item : kProfiles)
            {
                if (leaf == item.ImageName)
                {
                    profile = &item;
                    break;
                }
            }
        } while (false);

        return profile;
    }

    bool IsHuntLabBuiltinProfile(const HuntProcessRecord& process)
    {
        bool matched = false;

        do
        {
            std::wstring commandLine = HuntToLower(process.PebCommandLine);
            if (commandLine.find(L"/lab-builtin-profile") == std::wstring::npos &&
                commandLine.find(L"/all") == std::wstring::npos)
            {
                break;
            }

            if (LeafName(process.ApiImagePath) == L"knlivedbghunttarget.exe" ||
                LeafName(process.PebImagePath) == L"knlivedbghunttarget.exe" ||
                LeafName(process.KernelImageName) == L"knlivedbghunttarget.exe")
            {
                matched = true;
            }
        } while (false);

        return matched;
    }

    bool IsSystemNameFromNonSystemPath(const std::wstring& imagePath)
    {
        bool suspicious = false;

        do
        {
            std::wstring leaf = LeafName(imagePath);
            if (leaf.empty())
            {
                break;
            }

            const BuiltinProcessProfile* profile = FindBuiltinProfileByLeaf(leaf);
            if (profile == nullptr)
            {
                break;
            }

            std::vector<std::wstring> expected;
            if (profile->System32)
            {
                expected.push_back(ExpectedSystem32Path(leaf));
            }
            if (profile->SysWow64)
            {
                expected.push_back(ExpectedSysWow64Path(leaf));
            }
            if (profile->WindowsRoot)
            {
                expected.push_back(ExpectedWindowsRootPath(leaf));
            }

            suspicious = !MatchesAnyCanonicalPath(imagePath, expected);
        } while (false);

        return suspicious;
    }

    uint64_t Fnv1a64(const std::vector<uint8_t>& bytes)
    {
        uint64_t hash = 14695981039346656037ull;

        for (uint8_t byte : bytes)
        {
            hash ^= static_cast<uint64_t>(byte);
            hash *= 1099511628211ull;
        }

        return hash;
    }

    bool ReadProcessMemoryByDtb(
        DeviceClient& device,
        uint64_t dtb,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || dtb == 0 || address == 0 || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid process memory read request";
                }
                break;
            }

            bytes->clear();
            bytes->reserve(length);

            uint64_t current = address;
            uint32_t remaining = length;
            while (remaining != 0)
            {
                PhysicalTranslationInfo translation = {};
                if (!device.TranslateVirtual(dtb, current, remaining, &translation, error))
                {
                    break;
                }

                if (translation.TranslatedLength == 0)
                {
                    if (error != nullptr)
                    {
                        *error = L"zero-length process translation";
                    }
                    break;
                }

                uint32_t chunk = translation.TranslatedLength;
                if (chunk > remaining)
                {
                    chunk = remaining;
                }

                std::vector<uint8_t> pageBytes;
                if (!device.ReadPhysical(translation.PhysicalAddress, chunk, &pageBytes, error) ||
                    pageBytes.size() != chunk)
                {
                    break;
                }

                bytes->insert(bytes->end(), pageBytes.begin(), pageBytes.end());
                current += chunk;
                remaining -= chunk;
            }

            ok = bytes->size() == length;
        } while (false);

        return ok;
    }

    bool ReadProcessU64(DeviceClient& device, const SnapshotProcessRecord& process, uint64_t address, uint64_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), address, sizeof(uint64_t), &bytes, &ignored))
            {
                break;
            }

            uint64_t result = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                result |= static_cast<uint64_t>(bytes[index]) << (index * 8);
            }

            *value = result;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadProcessU32(DeviceClient& device, const SnapshotProcessRecord& process, uint64_t address, uint32_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), address, sizeof(uint32_t), &bytes, &ignored))
            {
                break;
            }

            uint32_t result = 0;
            for (size_t index = 0; index < sizeof(uint32_t); ++index)
            {
                result |= static_cast<uint32_t>(bytes[index]) << (index * 8);
            }

            *value = result;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadRemoteUnicodeString(
        DeviceClient& device,
        const SnapshotProcessRecord& process,
        uint64_t unicodeStringAddress,
        size_t maxBytes,
        std::wstring* text)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || unicodeStringAddress == 0)
            {
                break;
            }

            text->clear();

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), unicodeStringAddress, 16, &bytes, &ignored))
            {
                break;
            }

            uint16_t length = static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
            uint64_t buffer = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                buffer |= static_cast<uint64_t>(bytes[8 + index]) << (index * 8);
            }

            if (length == 0 || buffer == 0 || !IsUserAddress(buffer))
            {
                ok = true;
                break;
            }

            size_t cappedLength = std::min<size_t>(length, maxBytes);
            cappedLength &= ~static_cast<size_t>(1);
            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> stringBytes;
            if (!ReadProcessMemoryByDtb(
                    device,
                    TargetUserDtb(process),
                    buffer,
                    static_cast<uint32_t>(cappedLength),
                    &stringBytes,
                    &ignored))
            {
                break;
            }

            text->assign(
                reinterpret_cast<const wchar_t*>(stringBytes.data()),
                stringBytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelUnicodeString(
        DeviceClient& device,
        uint64_t unicodeStringAddress,
        size_t maxBytes,
        std::wstring* text,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || unicodeStringAddress == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid kernel unicode string request";
                }
                break;
            }

            text->clear();

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, unicodeStringAddress, 16, &bytes, error))
            {
                break;
            }

            uint16_t length = static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
            uint64_t buffer = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                buffer |= static_cast<uint64_t>(bytes[8 + index]) << (index * 8);
            }

            if (length == 0 || buffer == 0)
            {
                ok = true;
                break;
            }

            if (!IsKernelAddress(buffer))
            {
                if (error != nullptr)
                {
                    *error = L"kernel unicode string buffer is not a kernel address";
                }
                break;
            }

            size_t cappedLength = std::min<size_t>(length, maxBytes);
            cappedLength &= ~static_cast<size_t>(1);
            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> stringBytes;
            if (!ReadKernelBytes(
                    device,
                    buffer,
                    static_cast<uint32_t>(cappedLength),
                    &stringBytes,
                    error))
            {
                break;
            }

            text->assign(
                reinterpret_cast<const wchar_t*>(stringBytes.data()),
                stringBytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveSectionBackingLayout(SymbolEngine& symbols, SectionBackingLayout* layout)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                break;
            }

            if (layout->Resolved)
            {
                ok = layout->HasSubsectionControlArea &&
                    layout->HasControlAreaFilePointer &&
                    layout->HasFileObjectFileName;
                break;
            }

            *layout = SectionBackingLayout{};
            layout->Resolved = true;
            layout->HasSubsectionControlArea =
                FindFieldRecursive(symbols, {L"nt!_SUBSECTION", L"_SUBSECTION"}, L"ControlArea", &layout->SubsectionControlArea);
            layout->HasControlAreaFilePointer =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"FilePointer", &layout->ControlAreaFilePointer);
            layout->HasFileObjectFileName =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"FileName", &layout->FileObjectFileName);

            if (!layout->HasSubsectionControlArea)
            {
                layout->Warnings.push_back(L"_SUBSECTION.ControlArea field unavailable");
            }
            if (!layout->HasControlAreaFilePointer)
            {
                layout->Warnings.push_back(L"_CONTROL_AREA.FilePointer field unavailable");
            }
            if (!layout->HasFileObjectFileName)
            {
                layout->Warnings.push_back(L"_FILE_OBJECT.FileName field unavailable");
            }

            ok = layout->HasSubsectionControlArea &&
                layout->HasControlAreaFilePointer &&
                layout->HasFileObjectFileName;
        } while (false);

        return ok;
    }

    bool ResolveVadSectionBackingPath(
        DeviceClient& device,
        SymbolEngine& symbols,
        const ProcessVadRecord& vad,
        std::wstring* path,
        std::wstring* state,
        std::wstring* warning)
    {
        bool ok = false;
        static SectionBackingLayout layout;

        do
        {
            if (path == nullptr || state == nullptr)
            {
                break;
            }

            path->clear();
            *state = L"unavailable";

            if (!vad.HasSubsection || vad.Subsection == 0)
            {
                *state = L"unbacked";
                ok = true;
                break;
            }

            if (!ResolveSectionBackingLayout(symbols, &layout))
            {
                if (warning != nullptr)
                {
                    *warning = L"section backing resolver unavailable: " + JoinWideValues(layout.Warnings, L"; ");
                }
                break;
            }

            uint64_t controlArea = 0;
            if (!ReadFieldInteger(device, vad.Subsection, layout.SubsectionControlArea, sizeof(uint64_t), &controlArea, warning) ||
                controlArea == 0 ||
                !IsKernelAddress(controlArea))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read VAD subsection control area";
                }
                break;
            }

            uint64_t fileFastRef = 0;
            if (!ReadFieldInteger(device, controlArea, layout.ControlAreaFilePointer, sizeof(uint64_t), &fileFastRef, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read control area file pointer";
                }
                break;
            }

            uint64_t fileObject = fileFastRef & ~0xfull;
            if (fileObject == 0)
            {
                *state = L"unbacked";
                ok = true;
                break;
            }

            if (!IsKernelAddress(fileObject))
            {
                if (warning != nullptr)
                {
                    *warning = L"control area file pointer is not a kernel address";
                }
                break;
            }

            uint64_t fileNameAddress = 0;
            if (!TryAdd(fileObject, layout.FileObjectFileName.Offset, &fileNameAddress))
            {
                if (warning != nullptr)
                {
                    *warning = L"FILE_OBJECT.FileName address overflow";
                }
                break;
            }

            std::wstring backingPath;
            if (!ReadKernelUnicodeString(device, fileNameAddress, kMaxPebStringBytes, &backingPath, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read FILE_OBJECT.FileName";
                }
                break;
            }

            *path = backingPath;
            *state = backingPath.empty() ? L"empty_file_name" : L"resolved";
            ok = true;
        } while (false);

        return ok;
    }

    void MergeModule(std::vector<HuntModuleRecord>* modules, const HuntModuleRecord& incoming)
    {
        do
        {
            if (modules == nullptr || incoming.Base == 0)
            {
                break;
            }

            HuntModuleRecord* target = nullptr;
            for (HuntModuleRecord& module : *modules)
            {
                if (module.Base == incoming.Base)
                {
                    target = &module;
                    break;
                }
            }

            if (target == nullptr)
            {
                modules->push_back(incoming);
                break;
            }

            if (target->Size == 0)
            {
                target->Size = incoming.Size;
            }
            if (target->Name.empty())
            {
                target->Name = incoming.Name;
            }
            if (target->Path.empty())
            {
                target->Path = incoming.Path;
            }

            target->ToolhelpSeen = target->ToolhelpSeen || incoming.ToolhelpSeen;
            target->LdrLoadSeen = target->LdrLoadSeen || incoming.LdrLoadSeen;
            target->LdrMemorySeen = target->LdrMemorySeen || incoming.LdrMemorySeen;
            target->LdrInitSeen = target->LdrInitSeen || incoming.LdrInitSeen;
            target->PrivatePeVadSeen = target->PrivatePeVadSeen || incoming.PrivatePeVadSeen;
            target->VadImageSeen = target->VadImageSeen || incoming.VadImageSeen;
            if (target->VadAddress == 0)
            {
                target->VadAddress = incoming.VadAddress;
            }
            if (target->VadBackingPath.empty())
            {
                target->VadBackingPath = incoming.VadBackingPath;
            }
            if (target->VadBackingState.empty())
            {
                target->VadBackingState = incoming.VadBackingState;
            }
        } while (false);
    }

    bool AddressInsideModule(const HuntModuleRecord& module, uint64_t address)
    {
        bool inside = false;

        do
        {
            uint64_t end = module.Base + module.Size;
            if (module.Size == 0 || end < module.Base)
            {
                break;
            }

            inside = address >= module.Base && address < end;
        } while (false);

        return inside;
    }

    bool ModuleHasLoaderView(const HuntModuleRecord& module)
    {
        return module.ToolhelpSeen || module.LdrLoadSeen || module.LdrMemorySeen || module.LdrInitSeen;
    }

    bool LoaderModuleCoversAddress(
        const HuntProcessRecord& process,
        uint64_t address,
        const HuntModuleRecord* excluded)
    {
        bool covered = false;

        for (const HuntModuleRecord& module : process.Modules)
        {
            if (excluded != nullptr && &module == excluded)
            {
                continue;
            }

            if (ModuleHasLoaderView(module) && AddressInsideModule(module, address))
            {
                covered = true;
                break;
            }
        }

        return covered;
    }

    const ProcessVadRecord* FindVadContaining(const HuntProcessRecord& process, uint64_t address)
    {
        const ProcessVadRecord* found = nullptr;

        for (const ProcessVadRecord& vad : process.VadRecords)
        {
            if (address >= vad.StartAddress && address <= vad.EndAddress)
            {
                found = &vad;
                break;
            }
        }

        return found;
    }

    bool ReadFileBytesAt(HANDLE file, uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || file == INVALID_HANDLE_VALUE || length == 0)
            {
                break;
            }

            LARGE_INTEGER distance = {};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN))
            {
                break;
            }

            bytes->assign(length, 0);
            DWORD read = 0;
            if (!ReadFile(file, bytes->data(), length, &read, nullptr))
            {
                break;
            }

            bytes->resize(read);
            ok = !bytes->empty();
        } while (false);

        return ok;
    }

    bool ReadDiskPeMetadata(const std::wstring& rawPath, DiskPeMetadata* metadata, std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (metadata == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid PE metadata output";
                }
                break;
            }

            *metadata = {};
            std::wstring path = Win32FilePathFromMaybeNtPath(rawPath);
            file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }

            std::vector<uint8_t> header;
            if (!ReadFileBytesAt(file, 0, 0x1000, &header) || header.size() < sizeof(IMAGE_DOS_HEADER))
            {
                if (error != nullptr)
                {
                    *error = L"read disk image header failed";
                }
                break;
            }

            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header.data());
            if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0 ||
                static_cast<size_t>(dos->e_lfanew) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > header.size())
            {
                if (error != nullptr)
                {
                    *error = L"disk image is not a PE file";
                }
                break;
            }

            size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
            uint32_t signature = *reinterpret_cast<const uint32_t*>(header.data() + ntOffset);
            if (signature != IMAGE_NT_SIGNATURE)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid NT signature";
                }
                break;
            }

            const IMAGE_FILE_HEADER* fileHeader =
                reinterpret_cast<const IMAGE_FILE_HEADER*>(header.data() + ntOffset + sizeof(uint32_t));
            size_t optionalOffset = ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
            size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
            size_t required = sectionOffset + static_cast<size_t>(fileHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (required > header.size())
            {
                if (!ReadFileBytesAt(file, 0, static_cast<uint32_t>(required), &header) || header.size() < required)
                {
                    if (error != nullptr)
                    {
                        *error = L"read disk image section table failed";
                    }
                    break;
                }
            }

            uint16_t magic = *reinterpret_cast<const uint16_t*>(header.data() + optionalOffset);
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER64* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(header.data() + optionalOffset);
                metadata->EntryPointRva = optional->AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional->SizeOfHeaders;
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER32* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(header.data() + optionalOffset);
                metadata->EntryPointRva = optional->AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional->SizeOfHeaders;
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"unsupported PE optional header magic";
                }
                break;
            }

            metadata->HasEntryPoint = metadata->EntryPointRva != 0;

            const IMAGE_SECTION_HEADER* sections =
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(header.data() + sectionOffset);
            for (uint16_t index = 0; index < fileHeader->NumberOfSections; ++index)
            {
                DiskPeSection section = {};
                char sectionName[9] = {};
                std::memcpy(sectionName, sections[index].Name, IMAGE_SIZEOF_SHORT_NAME);
                std::string narrowName(sectionName);
                section.Name.assign(narrowName.begin(), narrowName.end());
                section.VirtualAddress = sections[index].VirtualAddress;
                section.VirtualSize = sections[index].Misc.VirtualSize;
                section.PointerToRawData = sections[index].PointerToRawData;
                section.SizeOfRawData = sections[index].SizeOfRawData;
                section.Characteristics = sections[index].Characteristics;
                section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                metadata->Sections.push_back(section);

                if (!metadata->HasExecutableSection &&
                    section.Executable)
                {
                    metadata->FirstExecutableSectionRva = section.VirtualAddress;
                    metadata->HasExecutableSection = true;
                }
            }

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool CopyRawBytesIntoMappedPage(
        HANDLE file,
        uint64_t rawOffset,
        uint64_t pageOffset,
        uint64_t length,
        std::vector<uint8_t>* page)
    {
        bool ok = false;

        do
        {
            if (page == nullptr || page->size() != kPageSize || pageOffset >= kPageSize)
            {
                break;
            }

            uint64_t cappedLength = length;
            if (pageOffset + cappedLength > kPageSize)
            {
                cappedLength = kPageSize - pageOffset;
            }

            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadFileBytesAt(file, rawOffset, static_cast<uint32_t>(cappedLength), &bytes))
            {
                break;
            }

            if (bytes.size() != cappedLength)
            {
                break;
            }

            std::copy(
                bytes.begin(),
                bytes.end(),
                page->begin() + static_cast<std::ptrdiff_t>(pageOffset));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadDiskPageForRva(
        const std::wstring& rawPath,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        std::vector<uint8_t>* page,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (page == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid disk page output";
                }
                break;
            }

            uint32_t pageRva = rva & 0xfffff000u;
            uint64_t pageStart = pageRva;
            uint64_t pageEnd = pageStart + kPageSize;
            bool mapped = false;
            bool copied = true;
            page->assign(static_cast<size_t>(kPageSize), 0);

            std::wstring path = Win32FilePathFromMaybeNtPath(rawPath);
            file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }

            if (metadata.SizeOfHeaders != 0 && pageStart < metadata.SizeOfHeaders)
            {
                uint64_t copyEnd = metadata.SizeOfHeaders;
                if (copyEnd > pageEnd)
                {
                    copyEnd = pageEnd;
                }

                if (copyEnd > pageStart)
                {
                    mapped = true;
                    copied = CopyRawBytesIntoMappedPage(file, pageStart, 0, copyEnd - pageStart, page) && copied;
                }
            }

            for (const DiskPeSection& section : metadata.Sections)
            {
                uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan == 0)
                {
                    continue;
                }

                uint64_t sectionStart = section.VirtualAddress;
                uint64_t sectionEnd = sectionStart + mappedSpan;
                if (sectionEnd < sectionStart)
                {
                    continue;
                }

                uint64_t overlapStart = pageStart > sectionStart ? pageStart : sectionStart;
                uint64_t overlapEnd = pageEnd < sectionEnd ? pageEnd : sectionEnd;
                if (overlapEnd <= overlapStart)
                {
                    continue;
                }

                mapped = true;

                uint64_t rawSpan = section.SizeOfRawData;
                if (rawSpan > mappedSpan)
                {
                    rawSpan = mappedSpan;
                }

                uint64_t rawEnd = sectionStart + rawSpan;
                if (rawEnd < sectionStart || overlapStart >= rawEnd)
                {
                    continue;
                }

                uint64_t rawCopyEnd = overlapEnd < rawEnd ? overlapEnd : rawEnd;
                if (rawCopyEnd <= overlapStart)
                {
                    continue;
                }

                uint64_t rawOffset = static_cast<uint64_t>(section.PointerToRawData) + (overlapStart - sectionStart);
                uint64_t mappedOffset = overlapStart - pageStart;
                copied = CopyRawBytesIntoMappedPage(file, rawOffset, mappedOffset, rawCopyEnd - overlapStart, page) && copied;
            }

            if (!mapped)
            {
                if (error != nullptr)
                {
                    *error = L"RVA has no disk mapping";
                }
                break;
            }

            if (!copied)
            {
                if (error != nullptr)
                {
                    *error = L"read mapped disk image page failed";
                }
                break;
            }

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool CollectSystemProcessInformation(
        std::map<uint32_t, ApiProcessRecord>* processes,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();

            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation unavailable: ntdll not loaded";
                }
                break;
            }

            NtQuerySystemInformationFn query =
                reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (query == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation unavailable";
                }
                break;
            }

            ULONG length = 0x20000;
            std::vector<uint8_t> buffer;
            LONG status = 0;
            for (uint32_t attempt = 0; attempt < 8; ++attempt)
            {
                buffer.assign(length, 0);
                ULONG returned = 0;
                status = query(kSystemProcessInformation, buffer.data(), length, &returned);
                if (status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall)
                {
                    length = returned != 0 ? returned + 0x10000 : length * 2;
                    continue;
                }
                break;
            }

            if (status < 0)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation(SystemProcessInformation) failed status=" + HuntHex(static_cast<uint32_t>(status), 8);
                }
                break;
            }

            size_t offset = 0;
            while (offset + sizeof(HuntSystemProcessInformation) <= buffer.size())
            {
                const HuntSystemProcessInformation* spi =
                    reinterpret_cast<const HuntSystemProcessInformation*>(buffer.data() + offset);

                ApiProcessRecord record = {};
                record.ProcessId = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(spi->UniqueProcessId));
                record.ParentProcessId = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(spi->InheritedFromUniqueProcessId));
                record.HasParentProcessId = spi->InheritedFromUniqueProcessId != nullptr;
                if (spi->ImageName.Buffer != nullptr && spi->ImageName.Length != 0)
                {
                    record.ImageName.assign(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(wchar_t));
                }
                else if (record.ProcessId == 0)
                {
                    record.ImageName = L"Idle";
                }
                else if (record.ProcessId == 4)
                {
                    record.ImageName = L"System";
                }

                (*processes)[record.ProcessId] = record;

                if (spi->NextEntryOffset == 0)
                {
                    break;
                }

                offset += spi->NextEntryOffset;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CollectToolhelpProcesses(
        std::map<uint32_t, ApiProcessRecord>* processes,
        std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();
            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning = L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (!Process32FirstW(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning = L"Process32FirstW failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            do
            {
                ApiProcessRecord record = {};
                record.ProcessId = entry.th32ProcessID;
                record.ParentProcessId = entry.th32ParentProcessID;
                record.HasParentProcessId = true;
                record.ImageName = entry.szExeFile;
                (*processes)[record.ProcessId] = record;
                entry.dwSize = sizeof(entry);
            } while (Process32NextW(snapshot, &entry));

            ok = true;
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            CloseHandle(snapshot);
        }

        return ok;
    }

    void QueryProcessPublicDetails(HuntProcessRecord* process)
    {
        HANDLE handle = nullptr;

        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            DWORD sessionId = 0;
            if (ProcessIdToSessionId(process->ProcessId, &sessionId))
            {
                process->SessionId = sessionId;
                process->HasSessionId = true;
            }

            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process->ProcessId);
            if (handle == nullptr)
            {
                break;
            }

            std::vector<wchar_t> buffer(32768);
            DWORD length = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(handle, 0, buffer.data(), &length) && length != 0)
            {
                process->ApiImagePath.assign(buffer.data(), length);
            }
        } while (false);

        if (handle != nullptr)
        {
            CloseHandle(handle);
        }
    }

    bool CollectToolhelpModules(HuntProcessRecord* process, std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process->ProcessId);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning = L"toolhelp module snapshot failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (!Module32FirstW(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning = L"toolhelp module first failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            do
            {
                HuntModuleRecord module = {};
                module.Base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                module.Size = entry.modBaseSize;
                module.Name = entry.szModule;
                module.Path = entry.szExePath;
                module.ToolhelpSeen = true;
                MergeModule(&process->Modules, module);
                entry.dwSize = sizeof(entry);
            } while (Module32NextW(snapshot, &entry));

            process->ToolhelpModuleEnumerated = true;
            ok = true;
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            CloseHandle(snapshot);
        }

        return ok;
    }

    void CollectPebIdentity(DeviceClient& device, HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr ||
                !process->Kernel.HasPeb ||
                process->Kernel.Peb == 0 ||
                TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            uint64_t imageBase = 0;
            if (ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x10, &imageBase) &&
                IsUserAddress(imageBase))
            {
                process->PebImageBase = imageBase;
                process->HasPebImageBase = true;
            }
            else
            {
                AddUnique(&process->Warnings, L"PEB ImageBaseAddress read failed");
            }

            uint64_t parameters = 0;
            if (!ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x20, &parameters) ||
                parameters == 0 ||
                !IsUserAddress(parameters))
            {
                AddUnique(&process->Warnings, L"PEB process parameter pointer read failed");
                break;
            }

            if (!ReadRemoteUnicodeString(device, process->Kernel, parameters + 0x60, kMaxPebStringBytes, &process->PebImagePath))
            {
                AddUnique(&process->Warnings, L"PEB ImagePathName read failed");
            }

            if (!ReadRemoteUnicodeString(device, process->Kernel, parameters + 0x70, kMaxPebStringBytes, &process->PebCommandLine))
            {
                AddUnique(&process->Warnings, L"PEB CommandLine read failed");
            }
        } while (false);
    }

    bool WalkPebLdrList(
        DeviceClient& device,
        HuntProcessRecord* process,
        uint64_t listHead,
        uint64_t listEntryOffset,
        const std::wstring& source)
    {
        bool ok = false;

        do
        {
            if (process == nullptr || listHead == 0)
            {
                break;
            }

            uint64_t current = 0;
            if (!ReadProcessU64(device, process->Kernel, listHead, &current))
            {
                break;
            }

            ok = true;
            std::set<uint64_t> visited;
            size_t scanned = 0;
            while (current != 0 && current != listHead && scanned < kMaxLdrModules)
            {
                if (visited.find(current) != visited.end())
                {
                    AddUnique(&process->Warnings, L"PEB LDR list loop detected");
                    break;
                }

                visited.insert(current);
                uint64_t entryBase = current - listEntryOffset;
                HuntModuleRecord module = {};
                ReadProcessU64(device, process->Kernel, entryBase + 0x30, &module.Base);
                uint32_t size = 0;
                if (ReadProcessU32(device, process->Kernel, entryBase + 0x40, &size))
                {
                    module.Size = size;
                }
                ReadRemoteUnicodeString(device, process->Kernel, entryBase + 0x48, kMaxPebStringBytes, &module.Path);
                ReadRemoteUnicodeString(device, process->Kernel, entryBase + 0x58, kMaxPebStringBytes, &module.Name);

                if (source == L"load")
                {
                    module.LdrLoadSeen = true;
                }
                else if (source == L"memory")
                {
                    module.LdrMemorySeen = true;
                }
                else if (source == L"init")
                {
                    module.LdrInitSeen = true;
                }

                MergeModule(&process->Modules, module);

                uint64_t next = 0;
                if (!ReadProcessU64(device, process->Kernel, current, &next))
                {
                    break;
                }

                current = next;
                ++scanned;
            }

            if (scanned >= kMaxLdrModules)
            {
                AddUnique(&process->Warnings, L"PEB LDR list traversal hit the module limit");
            }
        } while (false);

        return ok;
    }

    void CollectPebLdrModules(DeviceClient& device, HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr ||
                !process->Kernel.HasPeb ||
                process->Kernel.Peb == 0 ||
                TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            uint64_t ldr = 0;
            if (!ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x18, &ldr) ||
                ldr == 0 ||
                !IsUserAddress(ldr))
            {
                AddUnique(&process->Warnings, L"PEB Ldr pointer read failed");
                break;
            }

            bool loadSeen = WalkPebLdrList(device, process, ldr + 0x10, 0x00, L"load");
            bool memorySeen = WalkPebLdrList(device, process, ldr + 0x20, 0x10, L"memory");
            bool initSeen = WalkPebLdrList(device, process, ldr + 0x30, 0x20, L"init");
            process->PebLdrEnumerated = loadSeen || memorySeen || initSeen;
            if (!process->PebLdrEnumerated)
            {
                AddUnique(&process->Warnings, L"PEB LDR list heads could not be read");
            }
        } while (false);
    }

    ProcessTriageTarget BuildTriageTarget(const SnapshotProcessRecord& process)
    {
        ProcessTriageTarget target = {};
        target.ProcessId = process.ProcessId;
        target.Eprocess = process.Eprocess;
        target.DirectoryTableBase = process.DirectoryTableBase;
        target.UserDirectoryTableBase = process.UserDirectoryTableBase;
        target.Peb = process.Peb;
        target.HasPeb = process.HasPeb;
        target.ImageName = process.ImageName;
        return target;
    }

    std::wstring BestProcessImageName(const HuntProcessRecord& process)
    {
        std::wstring image = process.KernelImageName;

        if (image.empty())
        {
            image = process.ToolhelpImageName;
        }
        if (image.empty())
        {
            image = process.SystemProcessImageName;
        }
        if (image.empty())
        {
            image = LeafName(process.ApiImagePath);
        }
        if (image.empty())
        {
            image = LeafName(process.PebImagePath);
        }

        return image;
    }

    std::wstring BestProcessImagePath(const HuntProcessRecord& process)
    {
        std::wstring path = process.ApiImagePath;

        if (path.empty())
        {
            path = process.PebImagePath;
        }
        if (path.empty())
        {
            path = process.DiskPath;
        }

        return path;
    }

    std::vector<std::wstring> ExpectedPathsForBuiltinProfile(
        const BuiltinProcessProfile& profile,
        const std::wstring& leaf)
    {
        std::vector<std::wstring> expected;

        if (profile.System32)
        {
            expected.push_back(ExpectedSystem32Path(leaf));
        }
        if (profile.SysWow64)
        {
            expected.push_back(ExpectedSysWow64Path(leaf));
        }
        if (profile.WindowsRoot)
        {
            expected.push_back(ExpectedWindowsRootPath(leaf));
        }

        return expected;
    }

    void ApplyBuiltinProfile(HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr)
            {
                break;
            }

            process->BuiltinProfile.clear();
            process->BuiltinProfileMatched = false;
            process->BuiltinSignatureVerified = false;
            process->BuiltinProfileExpectedPaths.clear();
            process->BuiltinProfileViolations.clear();

            bool labProfile = IsHuntLabBuiltinProfile(*process);
            std::wstring leaf = LeafName(BestProcessImageName(*process));
            const BuiltinProcessProfile* profile = nullptr;
            if (!labProfile)
            {
                profile = FindBuiltinProfileByLeaf(leaf);
            }

            if (profile == nullptr && !labProfile)
            {
                break;
            }

            process->BuiltinProfileMatched = true;
            process->BuiltinProfile = labProfile ? L"hunt_lab_builtin_profile" : leaf;

            if (labProfile)
            {
                process->BuiltinProfileExpectedPaths.push_back(ExpectedSystem32Path(L"KnLiveDbgHuntTarget.exe"));
            }
            else
            {
                process->BuiltinProfileExpectedPaths = ExpectedPathsForBuiltinProfile(*profile, leaf);
            }

            std::wstring actualPath = BestProcessImagePath(*process);
            if (!actualPath.empty() &&
                !MatchesAnyCanonicalPath(actualPath, process->BuiltinProfileExpectedPaths))
            {
                AddUnique(&process->BuiltinProfileViolations, L"path_mismatch");
            }

            if (profile != nullptr && profile->SessionZeroOnly && process->HasSessionId && process->SessionId != 0)
            {
                AddUnique(&process->BuiltinProfileViolations, L"session_mismatch");
            }

            if (profile != nullptr &&
                profile->ParentNameCount != 0 &&
                !process->ParentImageName.empty())
            {
                std::wstring parentLeaf = LeafName(process->ParentImageName);
                bool parentMatched = false;
                for (size_t index = 0; index < profile->ParentNameCount; ++index)
                {
                    if (parentLeaf == profile->ParentNames[index])
                    {
                        parentMatched = true;
                        break;
                    }
                }

                if (!parentMatched)
                {
                    AddUnique(&process->BuiltinProfileViolations, L"parent_mismatch");
                }
            }

            if (profile != nullptr &&
                profile->SvchostCommandLine &&
                !process->PebCommandLine.empty())
            {
                std::wstring commandLine = HuntToLower(process->PebCommandLine);
                if (commandLine.find(L" -k ") == std::wstring::npos &&
                    commandLine.find(L" -k") == std::wstring::npos &&
                    commandLine.find(L"\t-k") == std::wstring::npos)
                {
                    AddUnique(&process->BuiltinProfileViolations, L"command_line_mismatch");
                }
            }
        } while (false);
    }

    void AddBuiltinEvidence(
        const HuntProcessRecord& process,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (evidence == nullptr || !process.BuiltinProfileMatched)
            {
                break;
            }

            (*evidence)[L"builtin_profile"] = process.BuiltinProfile;
            (*evidence)[L"builtin_profile_matched"] = L"true";
            (*evidence)[L"builtin_profile_expected_paths"] = JoinWideValues(process.BuiltinProfileExpectedPaths, L";");
            (*evidence)[L"builtin_profile_violations"] = JoinWideValues(process.BuiltinProfileViolations, L";");
        } while (false);
    }

    void AddBuiltinInjectionReasonIfNeeded(
        const HuntProcessRecord& process,
        std::vector<std::wstring>* reasons,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (!process.BuiltinProfileMatched || reasons == nullptr)
            {
                break;
            }

            AddUnique(reasons, L"builtin_process_injection_evidence");
            AddBuiltinEvidence(process, evidence);
        } while (false);
    }

    void AddFinding(
        HuntResult* result,
        const HuntProcessRecord& process,
        const std::wstring& risk,
        const std::wstring& confidence,
        const std::wstring& className,
        const std::wstring& title,
        uint64_t address,
        const std::wstring& moduleName,
        const std::vector<std::wstring>& reasons,
        const std::map<std::wstring, std::wstring>& evidence)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            HuntFinding finding = {};
            finding.Risk = SnapshotRiskNormalize(risk);
            finding.Confidence = confidence;
            finding.ClassName = className;
            finding.Title = title;
            finding.ProcessId = process.ProcessId;
            finding.Eprocess = process.Kernel.Eprocess;
            finding.Address = address;
            finding.ImageName = !process.KernelImageName.empty() ? process.KernelImageName : process.ToolhelpImageName;
            finding.ModuleName = moduleName;
            finding.ReasonCodes = reasons;
            finding.Evidence = evidence;

            std::wstring target = process.Kernel.Eprocess != 0
                ? HuntHex(process.Kernel.Eprocess, 16)
                : std::to_wstring(process.ProcessId);
            if (process.Kernel.Eprocess != 0)
            {
                finding.Followups.push_back(L"!vad " + target + L" /pe /hiddenpte /limit 40");
                finding.Followups.push_back(L"!threads " + target + L" /apc /stacks /limit 40");
            }
            if (address != 0)
            {
                finding.Followups.push_back(L"!address " + HuntHex(address, 16));
            }
            finding.Followups.push_back(L"!dml_proc " + std::to_wstring(process.ProcessId));

            result->Findings.push_back(std::move(finding));
        } while (false);
    }

    void AddProcessViewFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"active_process_links_seen"] = process.ActiveProcessLinksSeen ? L"true" : L"false";
            evidence[L"system_process_information_seen"] = process.SystemProcessInformationSeen ? L"true" : L"false";
            evidence[L"toolhelp_seen"] = process.ToolhelpProcessSeen ? L"true" : L"false";
            evidence[L"cid_table_seen"] = process.HasCidTableView ? (process.CidTableSeen ? L"true" : L"false") : L"null";
            evidence[L"eprocess"] = process.Kernel.Eprocess != 0 ? HuntHex(process.Kernel.Eprocess, 16) : L"0x0";
            evidence[L"image_name"] = !process.KernelImageName.empty() ? process.KernelImageName : process.ToolhelpImageName;

            if (process.ActiveProcessLinksSeen &&
                !process.SystemProcessInformationSeen &&
                !process.ToolhelpProcessSeen)
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_cross_view",
                    L"process is visible in ActiveProcessLinks but missing from user API views",
                    0,
                    L"",
                    {L"kernel_only_process", L"process_view_mismatch"},
                    evidence);
            }
            else if (!process.ActiveProcessLinksSeen &&
                     (process.SystemProcessInformationSeen || process.ToolhelpProcessSeen))
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"low",
                    L"process_cross_view",
                    L"process is visible through user API views but missing from ActiveProcessLinks",
                    0,
                    L"",
                    {L"api_only_process", L"missing_from_active_process_links"},
                    evidence);
            }
            else if (process.ActiveProcessLinksSeen &&
                     (!process.SystemProcessInformationSeen || !process.ToolhelpProcessSeen))
            {
                AddFinding(
                    result,
                    process,
                    L"low",
                    L"medium",
                    L"process_cross_view",
                    L"process has a partial cross-view mismatch",
                    0,
                    L"",
                    {L"process_view_mismatch"},
                    evidence);
            }
        } while (false);
    }

    void AddIdentityFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"eprocess_image"] = process.KernelImageName;
            evidence[L"system_process_image"] = process.SystemProcessImageName;
            evidence[L"toolhelp_image"] = process.ToolhelpImageName;
            evidence[L"api_image_path"] = process.ApiImagePath;
            if (process.HasPebImageBase)
            {
                evidence[L"peb_image_base"] = HuntHex(process.PebImageBase, 16);
            }
            evidence[L"peb_image_path"] = process.PebImagePath;
            evidence[L"peb_command_line"] = process.PebCommandLine;
            std::wstring commandImage = FirstCommandLineImage(process.PebCommandLine);
            evidence[L"peb_command_image"] = commandImage;
            if (process.HasParentProcessId)
            {
                evidence[L"parent_pid"] = std::to_wstring(process.ParentProcessId);
            }
            if (process.HasSessionId)
            {
                evidence[L"session_id"] = std::to_wstring(process.SessionId);
            }
            if (!process.ParentImageName.empty())
            {
                evidence[L"parent_image"] = process.ParentImageName;
            }
            AddBuiltinEvidence(process, &evidence);

            if (!process.KernelImageName.empty() &&
                !process.ApiImagePath.empty() &&
                !SameNonEmptyLeaf(process.KernelImageName, process.ApiImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_identity",
                    L"EPROCESS image name and resolved image path disagree",
                    0,
                    L"",
                    {L"image_name_mismatch", L"image_path_mismatch"},
                    evidence);
            }

            if (!process.KernelImageName.empty() &&
                !process.PebImagePath.empty() &&
                !SameNonEmptyLeaf(process.KernelImageName, process.PebImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_identity",
                    L"EPROCESS image name and PEB image path disagree",
                    0,
                    L"",
                    {L"image_name_mismatch", L"peb_image_path_mismatch"},
                    evidence);
            }

            if (!process.PebImagePath.empty() &&
                !commandImage.empty() &&
                !SameNonEmptyLeaf(process.PebImagePath, commandImage))
            {
                AddFinding(
                    result,
                    process,
                    L"low",
                    L"low",
                    L"process_identity",
                    L"PEB image path and command line first path disagree",
                    0,
                    L"",
                    {L"command_line_path_mismatch"},
                    evidence);
            }

            if (process.BuiltinProfileMatched && !process.BuiltinProfileViolations.empty())
            {
                std::vector<std::wstring> reasons;
                for (const std::wstring& violation : process.BuiltinProfileViolations)
                {
                    if (violation == L"path_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_path_mismatch");
                        AddUnique(&reasons, L"system_name_from_non_system_path");
                    }
                    else if (violation == L"parent_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_parent_mismatch");
                    }
                    else if (violation == L"session_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_session_mismatch");
                    }
                    else if (violation == L"command_line_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_command_line_mismatch");
                    }
                }

                if (!reasons.empty())
                {
                    AddFinding(
                        result,
                        process,
                        std::find(reasons.begin(), reasons.end(), L"builtin_profile_path_mismatch") != reasons.end() ? L"high" : L"medium",
                        L"medium",
                        L"process_masquerade",
                        L"process violates built-in Windows process profile",
                        0,
                        L"",
                        reasons,
                        evidence);
                }
            }

            if (!process.ApiImagePath.empty() && IsSystemNameFromNonSystemPath(process.ApiImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"high",
                    L"medium",
                    L"process_masquerade",
                    L"system process name is running from a non-system directory",
                    0,
                    L"",
                    {L"system_name_from_non_system_path"},
                    evidence);
            }
        } while (false);
    }

    bool CanOpenDiskImagePath(const std::wstring& rawPath)
    {
        bool openable = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (rawPath.empty())
            {
                break;
            }

            std::wstring openPath = DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(rawPath));
            file = CreateFileW(
                openPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }

            openable = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return openable;
    }

    void AddVadFindings(DeviceClient& device, SymbolEngine& symbols, HuntResult* result, HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr)
            {
                break;
            }

            for (const ProcessVadRecord& vad : process->VadRecords)
            {
                bool privateMemory = vad.HasPrivateMemory && vad.PrivateMemory;
                bool privateExecutable = vad.Executable && privateMemory;
                bool wx = vad.Executable && vad.Writable;
                bool largePrivateExecutable = privateExecutable && vad.Size >= kLargePrivateExecThreshold;
                bool privatePe = privateMemory && vad.PeHeaderFound;
                bool sectionBackedExecutable = vad.Executable &&
                    vad.HasSubsection &&
                    vad.Subsection != 0 &&
                    !privateMemory &&
                    vad.PeHeaderFound;
                bool loaderCovered = sectionBackedExecutable &&
                    LoaderModuleCoversAddress(*process, vad.StartAddress, nullptr);

                if (sectionBackedExecutable &&
                    !loaderCovered &&
                    process->PebLdrEnumerated &&
                    process->ToolhelpModuleEnumerated)
                {
                    std::wstring backingPath;
                    std::wstring backingState = L"unresolved";
                    std::wstring backingWarning;
                    if (ResolveVadSectionBackingPath(device, symbols, vad, &backingPath, &backingState, &backingWarning))
                    {
                        if (backingState == L"resolved" &&
                            !backingPath.empty() &&
                            !CanOpenDiskImagePath(backingPath))
                        {
                            backingState = L"inaccessible";
                        }
                    }
                    else if (!backingWarning.empty())
                    {
                        AddUnique(&process->Warnings, L"VAD section backing failed: " + backingWarning);
                    }

                    HuntModuleRecord module = {};
                    module.Base = vad.StartAddress;
                    module.Size = vad.PeProbe.SizeOfImage != 0 ? vad.PeProbe.SizeOfImage : vad.Size;
                    module.Name = backingPath.empty() ? L"section-image" : LeafName(backingPath);
                    module.Path = backingPath;
                    module.VadImageSeen = true;
                    module.VadAddress = vad.VadAddress;
                    module.VadBackingPath = backingPath;
                    module.VadBackingState = backingState;
                    MergeModule(&process->Modules, module);
                }

                if (!privateExecutable && !wx && !largePrivateExecutable && !privatePe && !vad.PeHeaderSuspicious)
                {
                    continue;
                }

                HuntModuleRecord module = {};
                if (privatePe)
                {
                    module.Base = vad.StartAddress;
                    module.Size = vad.PeProbe.SizeOfImage != 0 ? vad.PeProbe.SizeOfImage : vad.Size;
                    module.Name = L"private-pe";
                    module.PrivatePeVadSeen = true;
                    MergeModule(&process->Modules, module);
                }

                std::vector<std::wstring> reasons;
                if (privateExecutable)
                {
                    reasons.push_back(L"private_executable_vad");
                }
                if (wx)
                {
                    reasons.push_back(L"wx_user_vad");
                }
                if (largePrivateExecutable)
                {
                    reasons.push_back(L"large_private_executable_vad");
                }
                if (privatePe)
                {
                    reasons.push_back(L"private_pe_mapping");
                }
                if (vad.PeHeaderSuspicious)
                {
                    reasons.push_back(L"wiped_pe_header");
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"vad"] = HuntHex(vad.VadAddress, 16);
                evidence[L"start"] = HuntHex(vad.StartAddress, 16);
                evidence[L"end"] = HuntHex(vad.EndAddress, 16);
                evidence[L"size"] = std::to_wstring(vad.Size);
                evidence[L"protection"] = vad.ProtectionText;
                evidence[L"private"] = privateMemory ? L"true" : L"false";
                evidence[L"pe_like"] = vad.PeHeaderFound ? L"true" : L"false";
                evidence[L"pe_suspicious"] = vad.PeHeaderSuspicious ? L"true" : L"false";
                evidence[L"classification"] = vad.Classification;
                if (vad.PeProbeAttempted)
                {
                    evidence[L"pe_mz_wiped"] = vad.PeProbe.MzWiped ? L"true" : L"false";
                    evidence[L"pe_signature_wiped"] = vad.PeProbe.PeSignatureWiped ? L"true" : L"false";
                    evidence[L"pe_elfanew_mismatch"] = vad.PeProbe.ELfanewMismatch ? L"true" : L"false";
                    evidence[L"pe_size_of_image"] = std::to_wstring(vad.PeProbe.SizeOfImage);
                }
                AddBuiltinInjectionReasonIfNeeded(*process, &reasons, &evidence);

                std::wstring risk = wx || vad.PeHeaderSuspicious || privatePe || process->BuiltinProfileMatched ? L"high" : L"medium";
                std::wstring confidence = privatePe || wx ? L"high" : L"medium";
                AddFinding(
                    result,
                    *process,
                    risk,
                    confidence,
                    L"mapped_code",
                    L"suspicious executable user VAD",
                    vad.StartAddress,
                    L"",
                    reasons,
                    evidence);
            }

            for (const ProcessHiddenVadPteRecord& hidden : process->HiddenPteRecords)
            {
                std::vector<std::wstring> reasons;
                if (hidden.Executable)
                {
                    reasons.push_back(L"vadless_executable_pte");
                }
                if (hidden.Executable && hidden.Writable)
                {
                    reasons.push_back(L"vadless_wx_pte");
                }

                if (reasons.empty())
                {
                    continue;
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"start"] = HuntHex(hidden.StartAddress, 16);
                evidence[L"end"] = HuntHex(hidden.EndAddress, 16);
                evidence[L"size"] = std::to_wstring(hidden.Size);
                evidence[L"page_size"] = std::to_wstring(hidden.PageSize);
                evidence[L"page_count"] = std::to_wstring(hidden.PageCount);
                evidence[L"physical"] = HuntHex(hidden.PhysicalAddress, 16);
                evidence[L"leaf_entry"] = HuntHex(hidden.LeafEntry, 16);
                evidence[L"leaf_entry_address"] = HuntHex(hidden.LeafEntryAddress, 16);
                evidence[L"writable"] = hidden.Writable ? L"true" : L"false";
                evidence[L"executable"] = hidden.Executable ? L"true" : L"false";
                evidence[L"user_accessible"] = hidden.UserAccessible ? L"true" : L"false";
                AddBuiltinInjectionReasonIfNeeded(*process, &reasons, &evidence);

                AddFinding(
                    result,
                    *process,
                    L"high",
                    L"high",
                    L"vad_dkom",
                    L"present executable user PTE range is not covered by a VAD",
                    hidden.StartAddress,
                    L"",
                    reasons,
                    evidence);
            }
        } while (false);
    }

    void AddThreadFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (thread.SuspiciousStart)
                {
                    uint64_t findingAddress = thread.HasWin32StartAddress && thread.Win32StartAddress != 0
                        ? thread.Win32StartAddress
                        : thread.StartAddress;
                    std::wstring findingModule = thread.HasWin32StartAddress && !thread.Win32StartModule.empty()
                        ? thread.Win32StartModule
                        : thread.StartModule;

                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                    evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                    evidence[L"start"] = HuntHex(thread.StartAddress, 16);
                    evidence[L"win32_start"] = HuntHex(thread.Win32StartAddress, 16);
                    evidence[L"start_module"] = thread.StartModule;
                    evidence[L"win32_start_module"] = thread.Win32StartModule;
                    evidence[L"vad"] = thread.VadClassification;
                    evidence[L"start_in_private_exec_vad"] = thread.StartInPrivateExecVad ? L"true" : L"false";
                    evidence[L"start_in_wx_vad"] = thread.StartInWxVad ? L"true" : L"false";
                    evidence[L"notes"] = thread.Notes;

                    std::vector<std::wstring> reasons = {L"suspicious_thread_start"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                    std::wstring risk = thread.StartInPrivateExecVad || thread.StartInWxVad || process.BuiltinProfileMatched ? L"high" : L"medium";
                    AddFinding(
                        result,
                        process,
                        risk,
                        L"high",
                        L"thread_provenance",
                        L"thread start address is outside expected user module ownership",
                        findingAddress,
                        findingModule,
                        reasons,
                        evidence);
                }

                for (const ProcessApcQueueRecord& queue : thread.ApcQueues)
                {
                    for (const ProcessApcEntryRecord& apc : queue.Entries)
                    {
                        if (!apc.Suspicious)
                        {
                            continue;
                        }

                        uint64_t findingAddress = apc.NormalRoutine != 0
                            ? apc.NormalRoutine
                            : apc.KernelRoutine;
                        std::wstring findingModule = apc.NormalRoutine != 0
                            ? apc.NormalRoutineModule
                            : apc.KernelRoutineModule;

                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                        evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                        evidence[L"queue"] = queue.Name;
                        evidence[L"kapc"] = HuntHex(apc.KapcAddress, 16);
                        evidence[L"kernel_routine"] = HuntHex(apc.KernelRoutine, 16);
                        evidence[L"normal_routine"] = HuntHex(apc.NormalRoutine, 16);
                        evidence[L"kernel_routine_module"] = apc.KernelRoutineModule;
                        evidence[L"normal_routine_module"] = apc.NormalRoutineModule;
                        evidence[L"notes"] = apc.Notes;

                        std::vector<std::wstring> reasons = {L"suspicious_apc_routine"};
                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                        AddFinding(
                            result,
                            process,
                            L"high",
                            L"medium",
                            L"apc_redirection",
                            L"queued APC has suspicious user or kernel routine provenance",
                            findingAddress,
                            findingModule,
                            reasons,
                            evidence);
                    }
                }
            }
        } while (false);
    }

    void AddModuleCrossViewFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const HuntModuleRecord& module : process.Modules)
            {
                bool ldrSeen = module.LdrLoadSeen || module.LdrMemorySeen || module.LdrInitSeen;
                std::map<std::wstring, std::wstring> evidence;
                evidence[L"base"] = HuntHex(module.Base, 16);
                evidence[L"size"] = std::to_wstring(module.Size);
                evidence[L"module_name"] = module.Name;
                evidence[L"module_path"] = module.Path;
                evidence[L"toolhelp_seen"] = module.ToolhelpSeen ? L"true" : L"false";
                evidence[L"ldr_load_seen"] = module.LdrLoadSeen ? L"true" : L"false";
                evidence[L"ldr_memory_seen"] = module.LdrMemorySeen ? L"true" : L"false";
                evidence[L"ldr_init_seen"] = module.LdrInitSeen ? L"true" : L"false";
                evidence[L"private_pe_vad_seen"] = module.PrivatePeVadSeen ? L"true" : L"false";
                evidence[L"vad_image_seen"] = module.VadImageSeen ? L"true" : L"false";
                if (module.VadAddress != 0)
                {
                    evidence[L"vad"] = HuntHex(module.VadAddress, 16);
                }
                evidence[L"vad_backing_path"] = module.VadBackingPath;
                evidence[L"vad_backing_state"] = module.VadBackingState;

                if (module.VadImageSeen && process.PebLdrEnumerated && process.ToolhelpModuleEnumerated)
                {
                    bool covered = LoaderModuleCoversAddress(process, module.Base, &module);
                    if (!covered)
                    {
                        std::vector<std::wstring> reasons = {L"section_image_without_loader_entry", L"vad_image_not_in_loader"};
                        if (module.VadBackingState == L"inaccessible")
                        {
                            reasons.push_back(L"section_backing_inaccessible");
                        }
                        else if (module.VadBackingState == L"empty_file_name" || module.VadBackingState == L"unbacked")
                        {
                            reasons.push_back(L"section_backing_missing");
                        }

                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                        AddFinding(
                            result,
                            process,
                            module.VadBackingState == L"inaccessible" ? L"high" : L"medium",
                            module.VadBackingPath.empty() ? L"medium" : L"high",
                            L"module_cross_view",
                            L"section-backed executable image mapping is absent from loader module views",
                            module.Base,
                            module.Name,
                            reasons,
                            evidence);
                    }
                }

                if (module.PrivatePeVadSeen && process.PebLdrEnumerated && process.ToolhelpModuleEnumerated)
                {
                    bool covered = false;
                    for (const HuntModuleRecord& other : process.Modules)
                    {
                        if (&other == &module)
                        {
                            continue;
                        }

                        if ((other.ToolhelpSeen || other.LdrLoadSeen || other.LdrMemorySeen) &&
                            AddressInsideModule(other, module.Base))
                        {
                            covered = true;
                            break;
                        }
                    }

                    if (!covered)
                    {
                        std::vector<std::wstring> reasons = {L"private_pe_without_loader_entry"};
                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                        AddFinding(
                            result,
                            process,
                            L"high",
                            L"high",
                            L"manual_map",
                            L"private PE-like mapping is absent from loader module views",
                            module.Base,
                            module.Name,
                            reasons,
                            evidence);
                    }
                }

                if (process.PebLdrEnumerated &&
                    ldrSeen &&
                    !(module.LdrLoadSeen && module.LdrMemorySeen))
                {
                    std::vector<std::wstring> reasons = {L"partial_ldr_unlink"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                    AddFinding(
                        result,
                        process,
                        process.BuiltinProfileMatched ? L"high" : L"medium",
                        L"medium",
                        L"module_cross_view",
                        L"module is only partially present across PEB LDR lists",
                        module.Base,
                        module.Name,
                        reasons,
                        evidence);
                }

                if (process.ToolhelpModuleEnumerated &&
                    process.PebLdrEnumerated &&
                    module.ToolhelpSeen != ldrSeen &&
                    !module.PrivatePeVadSeen)
                {
                    std::vector<std::wstring> reasons = {L"module_view_mismatch"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                    AddFinding(
                        result,
                        process,
                        process.BuiltinProfileMatched ? L"high" : L"medium",
                        L"medium",
                        L"module_cross_view",
                        L"module differs between Toolhelp and PEB loader views",
                        module.Base,
                        module.Name,
                        reasons,
                        evidence);
                }
            }
        } while (false);
    }

    bool IsMainImageModule(const HuntProcessRecord& process, const HuntModuleRecord& module)
    {
        bool isMain = false;

        do
        {
            if (process.HasPebImageBase &&
                module.Base == process.PebImageBase)
            {
                isMain = true;
                break;
            }

            if (!process.ApiImagePath.empty() && SameNonEmptyLeaf(process.ApiImagePath, module.Path))
            {
                isMain = true;
                break;
            }

            if (!process.PebImagePath.empty() && SameNonEmptyLeaf(process.PebImagePath, module.Path))
            {
                isMain = true;
                break;
            }

            std::wstring leaf = LeafName(module.Name);
            if (!process.KernelImageName.empty() &&
                !leaf.empty() &&
                leaf == LeafName(process.KernelImageName))
            {
                isMain = true;
                break;
            }
        } while (false);

        return isMain;
    }

    void AddMainImageVadFinding(
        DeviceClient& device,
        SymbolEngine& symbols,
        HuntResult* result,
        HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr)
            {
                break;
            }

            for (const HuntModuleRecord& module : process->Modules)
            {
                if (!module.ToolhelpSeen || !IsMainImageModule(*process, module))
                {
                    continue;
                }

                process->MainImageBase = module.Base;
                process->MainImageSize = module.Size;
                process->DiskPath = module.Path;

                const ProcessVadRecord* vad = FindVadContaining(*process, module.Base);
                if (vad == nullptr)
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"disk_path"] = module.Path;
                    if (process->HasPebImageBase)
                    {
                        evidence[L"peb_image_base"] = HuntHex(process->PebImageBase, 16);
                    }
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"medium",
                        L"process_image_integrity",
                        L"main image module base is not covered by a VAD record",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked"},
                        evidence);
                    break;
                }

                process->MainImageVad = vad->VadAddress;

                std::wstring backingWarning;
                std::wstring backingPath;
                std::wstring backingState;
                if (ResolveVadSectionBackingPath(device, symbols, *vad, &backingPath, &backingState, &backingWarning))
                {
                    process->SectionBackingPath = backingPath;
                    process->SectionBackingState = backingState;
                }
                else
                {
                    process->SectionBackingState = L"unavailable";
                    if (!backingWarning.empty())
                    {
                        AddUnique(&process->Warnings, L"main image section backing unresolved: " + backingWarning);
                    }
                }

                if (process->SectionBackingState == L"unbacked")
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"disk_path"] = module.Path;
                    evidence[L"section_backing_state"] = process->SectionBackingState;
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"medium",
                        L"process_image_integrity",
                        L"main image VAD has no section file backing",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked"},
                        evidence);
                }
                else if (!process->SectionBackingPath.empty())
                {
                    bool diskOpen = false;
                    std::wstring openPath = DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(process->SectionBackingPath));
                    HANDLE file = CreateFileW(
                        openPath.c_str(),
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr);
                    if (file != INVALID_HANDLE_VALUE)
                    {
                        diskOpen = true;
                        CloseHandle(file);
                    }

                    if (!diskOpen)
                    {
                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                        evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                        evidence[L"disk_path"] = module.Path;
                        evidence[L"section_backing_path"] = process->SectionBackingPath;
                        evidence[L"section_backing_state"] = L"inaccessible";
                        process->SectionBackingState = L"inaccessible";
                        AddFinding(
                            result,
                            *process,
                            L"medium",
                            L"medium",
                            L"process_image_integrity",
                            L"main image section backing file cannot be opened",
                            module.Base,
                            module.Name,
                            {L"section_backing_inaccessible"},
                            evidence);
                    }

                    if (!module.Path.empty() &&
                        !SameCanonicalPath(process->SectionBackingPath, module.Path))
                    {
                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                        evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                        evidence[L"disk_path"] = module.Path;
                        evidence[L"section_backing_path"] = process->SectionBackingPath;
                        evidence[L"section_backing_state"] = process->SectionBackingState;
                        AddFinding(
                            result,
                            *process,
                            L"high",
                            L"medium",
                            L"process_image_integrity",
                            L"main image section backing path differs from process image path",
                            module.Base,
                            module.Name,
                            {L"section_path_mismatch"},
                            evidence);
                    }
                }

                if (vad->HasPrivateMemory && vad->PrivateMemory)
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"disk_path"] = module.Path;
                    evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"section_backing_path"] = process->SectionBackingPath;
                    evidence[L"section_backing_state"] = process->SectionBackingState;
                    if (process->HasPebImageBase)
                    {
                        evidence[L"peb_image_base"] = HuntHex(process->PebImageBase, 16);
                    }
                    evidence[L"vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"vad_start"] = HuntHex(vad->StartAddress, 16);
                    evidence[L"vad_end"] = HuntHex(vad->EndAddress, 16);
                    evidence[L"vad_private"] = L"true";
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"high",
                        L"process_image_integrity",
                        L"main image module is backed by private memory",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked", L"process_hollowing_evidence"},
                        evidence);
                    break;
                }
            }
        } while (false);
    }

    void AddDeepPageCompareFinding(
        HuntResult* result,
        const HuntProcessRecord& process,
        const HuntModuleRecord& module,
        const std::wstring& pageName,
        const std::wstring& sectionName,
        uint32_t rva,
        const std::vector<uint8_t>& livePage,
        const std::vector<uint8_t>& diskPage)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"module_base"] = HuntHex(module.Base, 16);
            evidence[L"module_size"] = std::to_wstring(module.Size);
            evidence[L"module_name"] = module.Name;
            evidence[L"module_path"] = module.Path;
            evidence[L"disk_path"] = module.Path;
            evidence[L"page"] = pageName;
            evidence[L"section_name"] = sectionName;
            evidence[L"rva"] = HuntHex(rva, 8);
            evidence[L"live_hash"] = HuntHex(Fnv1a64(livePage), 16);
            evidence[L"disk_hash"] = HuntHex(Fnv1a64(diskPage), 16);
            evidence[L"live_bytes"] = std::to_wstring(livePage.size());
            evidence[L"disk_bytes"] = std::to_wstring(diskPage.size());
            evidence[L"modified_page_owner"] = module.Name;

            bool mainImage = IsMainImageModule(process, module);
            std::vector<std::wstring> reasons;
            if (mainImage)
            {
                reasons.push_back(L"disk_live_image_mismatch");
                evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                evidence[L"main_image_vad"] = process.MainImageVad != 0 ? HuntHex(process.MainImageVad, 16) : L"";
                evidence[L"section_backing_path"] = process.SectionBackingPath;
                evidence[L"section_backing_state"] = process.SectionBackingState;
                if (pageName == L"entrypoint")
                {
                    reasons.push_back(L"main_image_entrypoint_mismatch");
                }
                else
                {
                    reasons.push_back(L"main_image_hash_mismatch");
                }

                if (process.SectionBackingState == L"unbacked" ||
                    process.SectionBackingState == L"inaccessible" ||
                    process.SectionBackingState == L"empty_file_name")
                {
                    reasons.push_back(L"process_doppelganging_evidence");
                }
                else if (!process.SectionBackingPath.empty() &&
                         !module.Path.empty() &&
                         !SameCanonicalPath(process.SectionBackingPath, module.Path))
                {
                    reasons.push_back(L"section_path_mismatch");
                    reasons.push_back(L"process_doppelganging_evidence");
                }
            }
            else
            {
                reasons.push_back(L"live_disk_exec_page_mismatch");
                reasons.push_back(L"module_stomping_evidence");
                if (pageName == L"entrypoint")
                {
                    reasons.push_back(L"module_entrypoint_mismatch");
                }
                else
                {
                    reasons.push_back(L"module_text_mismatch");
                }
            }

            uint64_t pageStart = module.Base + rva;
            uint64_t pageEnd = pageStart + kPageSize;
            std::vector<std::wstring> threadIds;
            std::vector<std::wstring> apcThreadIds;
            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (thread.HasStartAddress &&
                    thread.StartAddress >= pageStart &&
                    thread.StartAddress < pageEnd)
                {
                    AddUnique(&threadIds, std::to_wstring(thread.ThreadId));
                }
                if (thread.HasWin32StartAddress &&
                    thread.Win32StartAddress >= pageStart &&
                    thread.Win32StartAddress < pageEnd)
                {
                    AddUnique(&threadIds, std::to_wstring(thread.ThreadId));
                }

                for (const ProcessApcQueueRecord& queue : thread.ApcQueues)
                {
                    for (const ProcessApcEntryRecord& apc : queue.Entries)
                    {
                        if (apc.NormalRoutine >= pageStart &&
                            apc.NormalRoutine < pageEnd)
                        {
                            AddUnique(&apcThreadIds, std::to_wstring(thread.ThreadId));
                        }
                    }
                }
            }

            evidence[L"thread_start_count"] = std::to_wstring(threadIds.size());
            evidence[L"apc_target_count"] = std::to_wstring(apcThreadIds.size());
            evidence[L"thread_ids"] = JoinWideValues(threadIds, L";");
            evidence[L"apc_thread_ids"] = JoinWideValues(apcThreadIds, L";");

            if (!threadIds.empty())
            {
                AddUnique(&reasons, L"thread_start_in_modified_module_page");
            }
            if (!apcThreadIds.empty())
            {
                AddUnique(&reasons, L"apc_target_in_modified_module_page");
            }
            AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

            bool executionOnPage = !threadIds.empty() || !apcThreadIds.empty();
            bool doppelganging = mainImage &&
                std::find(reasons.begin(), reasons.end(), L"process_doppelganging_evidence") != reasons.end();
            std::wstring risk = mainImage || executionOnPage || process.BuiltinProfileMatched ? L"high" : L"medium";
            std::wstring confidence = executionOnPage || doppelganging ? L"high" : L"medium";

            AddFinding(
                result,
                process,
                risk,
                confidence,
                doppelganging ? L"process_doppelganging" : (mainImage ? L"process_image_integrity" : L"module_stomping"),
                mainImage ? L"live main image page differs from disk" : L"live module executable page differs from disk",
                module.Base + rva,
                module.Name,
                reasons,
                evidence);
        } while (false);
    }

    void CompareModulePage(
        DeviceClient& device,
        HuntResult* result,
        const HuntProcessRecord& process,
        const HuntModuleRecord& module,
        const DiskPeMetadata& metadata,
        const std::wstring& pageName,
        const std::wstring& sectionName,
        uint32_t rva)
    {
        do
        {
            uint32_t pageRva = rva & 0xfffff000u;
            std::vector<uint8_t> livePage;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(
                    device,
                    TargetUserDtb(process.Kernel),
                    module.Base + pageRva,
                    static_cast<uint32_t>(kPageSize),
                    &livePage,
                    &ignored))
            {
                break;
            }

            std::vector<uint8_t> diskPage;
            if (!ReadDiskPageForRva(module.Path, metadata, pageRva, &diskPage, &ignored))
            {
                break;
            }

            if (livePage.size() != diskPage.size())
            {
                size_t shorter = std::min(livePage.size(), diskPage.size());
                livePage.resize(shorter);
                diskPage.resize(shorter);
            }

            if (!livePage.empty() && livePage != diskPage)
            {
                AddDeepPageCompareFinding(result, process, module, pageName, sectionName, pageRva, livePage, diskPage);
            }
        } while (false);
    }

    void AddDeepImageIntegrityFindings(DeviceClient& device, HuntResult* result, HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr || TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            size_t compared = 0;
            size_t pagesCompared = 0;
            for (const HuntModuleRecord& module : process->Modules)
            {
                if (compared >= kMaxDeepModuleComparisonsPerProcess)
                {
                    AddUnique(&process->Warnings, L"deep module comparison limit reached");
                    break;
                }

                if (module.Base == 0 || module.Path.empty() || module.PrivatePeVadSeen)
                {
                    continue;
                }

                DiskPeMetadata metadata = {};
                std::wstring metadataError;
                if (!ReadDiskPeMetadata(module.Path, &metadata, &metadataError))
                {
                    continue;
                }

                bool mainImage = IsMainImageModule(*process, module);
                bool compareFullExecutableSections = process->BuiltinProfileMatched || mainImage;
                std::set<uint32_t> comparedPageRvas;
                if (metadata.HasEntryPoint)
                {
                    uint32_t pageRva = metadata.EntryPointRva & 0xfffff000u;
                    if (pagesCompared < kMaxDeepPagesPerProcess)
                    {
                        CompareModulePage(device, result, *process, module, metadata, L"entrypoint", L"", metadata.EntryPointRva);
                        comparedPageRvas.insert(pageRva);
                        ++pagesCompared;
                    }
                }

                for (const DiskPeSection& section : metadata.Sections)
                {
                    if (!section.Executable)
                    {
                        continue;
                    }

                    uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                    if (mappedSpan == 0)
                    {
                        continue;
                    }

                    uint64_t sectionStart = section.VirtualAddress;
                    uint64_t sectionEnd = sectionStart + mappedSpan;
                    if (sectionEnd < sectionStart)
                    {
                        continue;
                    }

                    size_t sectionPagesCompared = 0;
                    for (uint64_t pageRva64 = sectionStart & ~0xfffull;
                         pageRva64 < sectionEnd;
                         pageRva64 += kPageSize)
                    {
                        if (pagesCompared >= kMaxDeepPagesPerProcess)
                        {
                            AddUnique(&process->Warnings, L"deep executable page comparison limit reached");
                            break;
                        }

                        if (!compareFullExecutableSections &&
                            sectionPagesCompared >= kMaxSampledExecPagesPerSection)
                        {
                            AddUnique(&process->Warnings, L"deep module comparison sampled non-builtin executable sections");
                            break;
                        }

                        if (pageRva64 > std::numeric_limits<uint32_t>::max())
                        {
                            break;
                        }

                        uint32_t pageRva = static_cast<uint32_t>(pageRva64);
                        if (comparedPageRvas.find(pageRva) != comparedPageRvas.end())
                        {
                            continue;
                        }

                        CompareModulePage(
                            device,
                            result,
                            *process,
                            module,
                            metadata,
                            L"executable_section",
                            section.Name,
                            pageRva);
                        comparedPageRvas.insert(pageRva);
                        ++sectionPagesCompared;
                        ++pagesCompared;
                    }
                }

                ++compared;
            }
        } while (false);
    }

    void SortAndCountFindings(HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::sort(
                result->Findings.begin(),
                result->Findings.end(),
                [](const HuntFinding& left, const HuntFinding& right)
                {
                    uint32_t leftRisk = SnapshotRiskRank(left.Risk);
                    uint32_t rightRisk = SnapshotRiskRank(right.Risk);
                    if (leftRisk != rightRisk)
                    {
                        return leftRisk > rightRisk;
                    }

                    uint32_t leftConfidence = ConfidenceRank(left.Confidence);
                    uint32_t rightConfidence = ConfidenceRank(right.Confidence);
                    if (leftConfidence != rightConfidence)
                    {
                        return leftConfidence > rightConfidence;
                    }

                    if (left.ProcessId != right.ProcessId)
                    {
                        return left.ProcessId < right.ProcessId;
                    }

                    return left.Address < right.Address;
                });

            result->HighFindings = 0;
            result->MediumFindings = 0;
            result->LowFindings = 0;
            result->InfoFindings = 0;
            for (const HuntFinding& finding : result->Findings)
            {
                std::wstring risk = SnapshotRiskNormalize(finding.Risk);
                if (risk == L"high")
                {
                    ++result->HighFindings;
                }
                else if (risk == L"medium")
                {
                    ++result->MediumFindings;
                }
                else if (risk == L"low")
                {
                    ++result->LowFindings;
                }
                else
                {
                    ++result->InfoFindings;
                }
            }
        } while (false);
    }

    void AppendJsonStringArray(std::wstringstream& json, const std::vector<std::wstring>& values)
    {
        json << L"[";
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                json << L",";
            }
            json << L"\"" << HuntJsonEscape(values[index]) << L"\"";
        }
        json << L"]";
    }
}

std::wstring HuntModeToText(HuntMode mode)
{
    std::wstring text = L"default";

    if (mode == HuntMode::Quick)
    {
        text = L"quick";
    }
    else if (mode == HuntMode::Deep)
    {
        text = L"deep";
    }

    return text;
}

UserModeHunter::UserModeHunter(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool UserModeHunter::Scan(const HuntOptions& options, HuntResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid hunt result output";
            }
            break;
        }

        *result = {};
        result->Schema = L"kn-live-dbg.hunt.v1";
        result->TimestampUtc = SnapshotCurrentUtcTimestamp();
        result->ModeText = HuntModeToText(options.Mode);
        result->Warnings.push_back(L"PspCidTable process-object cross-view is not implemented; cid_table_seen is null");
        result->Warnings.push_back(L"builtin process signer verification is not implemented; publisher evidence unavailable");

        std::map<uint32_t, HuntProcessRecord> processes;
        for (const SnapshotProcessRecord& process : options.Processes)
        {
            HuntProcessRecord record = {};
            record.Kernel = process;
            record.ProcessId = process.ProcessId;
            record.ActiveProcessLinksSeen = true;
            record.KernelImageName = process.ImageName;
            processes[record.ProcessId] = record;
        }

        result->KernelProcessCount = processes.size();

        std::map<uint32_t, ApiProcessRecord> systemProcesses;
        std::wstring warning;
        if (CollectSystemProcessInformation(&systemProcesses, &warning))
        {
            result->SystemProcessInfoCount = systemProcesses.size();
            for (const auto& item : systemProcesses)
            {
                HuntProcessRecord& record = processes[item.first];
                record.ProcessId = item.first;
                record.SystemProcessInformationSeen = true;
                record.SystemProcessImageName = item.second.ImageName;
                if (item.second.HasParentProcessId)
                {
                    record.ParentProcessId = item.second.ParentProcessId;
                    record.HasParentProcessId = true;
                }
            }
        }
        else if (!warning.empty())
        {
            result->Warnings.push_back(warning);
        }

        std::map<uint32_t, ApiProcessRecord> toolhelpProcesses;
        warning.clear();
        if (CollectToolhelpProcesses(&toolhelpProcesses, &warning))
        {
            result->ToolhelpProcessCount = toolhelpProcesses.size();
            for (const auto& item : toolhelpProcesses)
            {
                HuntProcessRecord& record = processes[item.first];
                record.ProcessId = item.first;
                record.ToolhelpProcessSeen = true;
                record.ToolhelpImageName = item.second.ImageName;
                if (item.second.HasParentProcessId)
                {
                    record.ParentProcessId = item.second.ParentProcessId;
                    record.HasParentProcessId = true;
                }
            }
        }
        else if (!warning.empty())
        {
            result->Warnings.push_back(warning);
        }

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (process.HasParentProcessId)
            {
                auto parent = processes.find(process.ParentProcessId);
                if (parent != processes.end())
                {
                    process.ParentImageName = BestProcessImageName(parent->second);
                }
            }
        }

        ProcessTriageScanner triage(device_, symbols_);

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (process.ProcessId == 0 && process.Kernel.ProcessId == 0)
            {
                process.Kernel.ProcessId = process.ProcessId;
            }

            QueryProcessPublicDetails(&process);
            AddProcessViewFindings(result, process);

            if (process.ActiveProcessLinksSeen && process.Kernel.Eprocess != 0)
            {
                CollectPebIdentity(device_, &process);
                ApplyBuiltinProfile(&process);
                CollectPebLdrModules(device_, &process);

                warning.clear();
                if (!CollectToolhelpModules(&process, &warning) && !warning.empty())
                {
                    AddUnique(&process.Warnings, warning);
                }

                ProcessVadScanOptions vadOptions = {};
                vadOptions.Target = BuildTriageTarget(process.Kernel);
                vadOptions.ProbePe = true;
                vadOptions.ScanHiddenPtes = options.Mode != HuntMode::Quick;

                ProcessVadScanResult vadResult = {};
                std::wstring scanError;
                if (triage.ScanVad(vadOptions, &vadResult, &scanError))
                {
                    process.VadRecords = std::move(vadResult.Records);
                    process.HiddenPteRecords = std::move(vadResult.HiddenPteRecords);
                    process.VadNodesVisited = vadResult.NodesVisited;
                    process.ExecutableVadCount = vadResult.ExecutableCount;
                    process.PrivateExecutableVadCount = vadResult.PrivateExecutableCount;
                    process.WxVadCount = vadResult.WxCount;
                    process.PeLikeVadCount = vadResult.PeLikeCount;
                    process.HiddenPteRanges = vadResult.HiddenPteRanges;
                    process.HiddenPteBytes = vadResult.HiddenPteBytes;
                    process.Warnings.insert(process.Warnings.end(), vadResult.Warnings.begin(), vadResult.Warnings.end());
                    result->VadRecordCount += vadResult.TotalRecords;
                    result->HiddenPteRangeCount += vadResult.HiddenPteRanges;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"VAD scan failed: " + scanError);
                }

                ProcessThreadScanOptions threadOptions = {};
                threadOptions.Target = BuildTriageTarget(process.Kernel);
                threadOptions.IncludeApc = true;
                threadOptions.IncludeStacks = options.Mode == HuntMode::Deep;

                ProcessThreadScanResult threadResult = {};
                scanError.clear();
                if (triage.ScanThreads(threadOptions, &threadResult, &scanError))
                {
                    process.ThreadRecords = std::move(threadResult.Records);
                    process.ThreadsVisited = threadResult.ThreadsVisited;
                    process.SuspiciousThreadStarts = threadResult.SuspiciousStartCount;
                    process.NonEmptyApcQueues = threadResult.ApcNonEmptyCount;
                    process.Warnings.insert(process.Warnings.end(), threadResult.Warnings.begin(), threadResult.Warnings.end());
                    result->ThreadRecordCount += threadResult.MatchingRecords;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"thread scan failed: " + scanError);
                }

                AddIdentityFindings(result, process);
                AddVadFindings(device_, symbols_, result, &process);
                AddThreadFindings(result, process);
                AddModuleCrossViewFindings(result, process);
                AddMainImageVadFinding(device_, symbols_, result, &process);

                if (options.Mode == HuntMode::Deep)
                {
                    AddDeepImageIntegrityFindings(device_, result, &process);
                }

                ++result->ScannedProcessCount;
            }
            else
            {
                ApplyBuiltinProfile(&process);
                AddIdentityFindings(result, process);
            }

            result->ModuleRecordCount += process.Modules.size();
        }

        result->Processes.reserve(processes.size());
        for (auto& item : processes)
        {
            result->Processes.push_back(std::move(item.second));
        }

        SortAndCountFindings(result);
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHuntJson(const HuntResult& result)
{
    std::wstringstream json;

    json << L"{\n";
    json << L"  \"schema\":\"" << HuntJsonEscape(result.Schema) << L"\",\n";
    json << L"  \"timestamp_utc\":\"" << HuntJsonEscape(result.TimestampUtc) << L"\",\n";
    json << L"  \"mode\":\"" << HuntJsonEscape(result.ModeText) << L"\",\n";
    json << L"  \"summary\":{";
    json << L"\"kernel_processes\":" << result.KernelProcessCount;
    json << L",\"system_process_information_processes\":" << result.SystemProcessInfoCount;
    json << L",\"toolhelp_processes\":" << result.ToolhelpProcessCount;
    json << L",\"scanned_processes\":" << result.ScannedProcessCount;
    json << L",\"findings\":" << result.Findings.size();
    json << L",\"high\":" << result.HighFindings;
    json << L",\"medium\":" << result.MediumFindings;
    json << L",\"low\":" << result.LowFindings;
    json << L",\"info\":" << result.InfoFindings;
    json << L",\"vad_records\":" << result.VadRecordCount;
    json << L",\"hidden_pte_ranges\":" << result.HiddenPteRangeCount;
    json << L",\"thread_records\":" << result.ThreadRecordCount;
    json << L",\"module_records\":" << result.ModuleRecordCount;
    json << L"},\n";

    json << L"  \"warnings\":";
    AppendJsonStringArray(json, result.Warnings);
    json << L",\n";

    json << L"  \"findings\":[\n";
    for (size_t index = 0; index < result.Findings.size(); ++index)
    {
        const HuntFinding& finding = result.Findings[index];
        json << L"    {";
        json << L"\"risk\":\"" << HuntJsonEscape(finding.Risk) << L"\"";
        json << L",\"confidence\":\"" << HuntJsonEscape(finding.Confidence) << L"\"";
        json << L",\"class\":\"" << HuntJsonEscape(finding.ClassName) << L"\"";
        json << L",\"title\":\"" << HuntJsonEscape(finding.Title) << L"\"";
        json << L",\"pid\":" << finding.ProcessId;
        json << L",\"eprocess\":\"" << HuntHex(finding.Eprocess, 16) << L"\"";
        json << L",\"address\":\"" << HuntHex(finding.Address, 16) << L"\"";
        json << L",\"image\":\"" << HuntJsonEscape(finding.ImageName) << L"\"";
        json << L",\"module\":\"" << HuntJsonEscape(finding.ModuleName) << L"\"";
        json << L",\"reasons\":";
        AppendJsonStringArray(json, finding.ReasonCodes);
        json << L",\"evidence\":{";
        size_t evidenceIndex = 0;
        for (const auto& item : finding.Evidence)
        {
            if (evidenceIndex != 0)
            {
                json << L",";
            }
            json << L"\"" << HuntJsonEscape(item.first) << L"\":\"" << HuntJsonEscape(item.second) << L"\"";
            ++evidenceIndex;
        }
        json << L"},\"followups\":";
        AppendJsonStringArray(json, finding.Followups);
        json << L"}";
        if (index + 1 != result.Findings.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ],\n";

    json << L"  \"processes\":[\n";
    for (size_t index = 0; index < result.Processes.size(); ++index)
    {
        const HuntProcessRecord& process = result.Processes[index];
        json << L"    {";
        json << L"\"pid\":" << process.ProcessId;
        json << L",\"eprocess\":\"" << HuntHex(process.Kernel.Eprocess, 16) << L"\"";
        json << L",\"active_process_links_seen\":" << (process.ActiveProcessLinksSeen ? L"true" : L"false");
        json << L",\"system_process_information_seen\":" << (process.SystemProcessInformationSeen ? L"true" : L"false");
        json << L",\"toolhelp_seen\":" << (process.ToolhelpProcessSeen ? L"true" : L"false");
        json << L",\"cid_table_seen\":";
        if (process.HasCidTableView)
        {
            json << (process.CidTableSeen ? L"true" : L"false");
        }
        else
        {
            json << L"null";
        }
        json << L",\"image_name\":\"" << HuntJsonEscape(process.KernelImageName) << L"\"";
        json << L",\"system_process_image\":\"" << HuntJsonEscape(process.SystemProcessImageName) << L"\"";
        json << L",\"toolhelp_image\":\"" << HuntJsonEscape(process.ToolhelpImageName) << L"\"";
        json << L",\"api_image_path\":\"" << HuntJsonEscape(process.ApiImagePath) << L"\"";
        json << L",\"peb_image_base\":";
        if (process.HasPebImageBase)
        {
            json << L"\"" << HuntHex(process.PebImageBase, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"peb_image_path\":\"" << HuntJsonEscape(process.PebImagePath) << L"\"";
        json << L",\"peb_command_line\":\"" << HuntJsonEscape(process.PebCommandLine) << L"\"";
        json << L",\"parent_image\":\"" << HuntJsonEscape(process.ParentImageName) << L"\"";
        json << L",\"builtin_profile\":\"" << HuntJsonEscape(process.BuiltinProfile) << L"\"";
        json << L",\"builtin_profile_matched\":" << (process.BuiltinProfileMatched ? L"true" : L"false");
        json << L",\"builtin_profile_expected_paths\":";
        AppendJsonStringArray(json, process.BuiltinProfileExpectedPaths);
        json << L",\"builtin_profile_violations\":";
        AppendJsonStringArray(json, process.BuiltinProfileViolations);
        json << L",\"builtin_signature_verified\":" << (process.BuiltinSignatureVerified ? L"true" : L"false");
        json << L",\"main_image_base\":";
        if (process.MainImageBase != 0)
        {
            json << L"\"" << HuntHex(process.MainImageBase, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"main_image_size\":" << process.MainImageSize;
        json << L",\"main_image_vad\":";
        if (process.MainImageVad != 0)
        {
            json << L"\"" << HuntHex(process.MainImageVad, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"section_backing_path\":\"" << HuntJsonEscape(process.SectionBackingPath) << L"\"";
        json << L",\"section_backing_state\":\"" << HuntJsonEscape(process.SectionBackingState) << L"\"";
        json << L",\"disk_path\":\"" << HuntJsonEscape(process.DiskPath) << L"\"";
        json << L",\"parent_pid\":";
        if (process.HasParentProcessId)
        {
            json << process.ParentProcessId;
        }
        else
        {
            json << L"null";
        }
        json << L",\"session_id\":";
        if (process.HasSessionId)
        {
            json << process.SessionId;
        }
        else
        {
            json << L"null";
        }
        json << L",\"counts\":{";
        json << L"\"vad_records\":" << process.VadRecords.size();
        json << L",\"hidden_pte_records\":" << process.HiddenPteRecords.size();
        json << L",\"threads\":" << process.ThreadRecords.size();
        json << L",\"modules\":" << process.Modules.size();
        json << L",\"private_executable_vads\":" << process.PrivateExecutableVadCount;
        json << L",\"wx_vads\":" << process.WxVadCount;
        json << L",\"pe_like_vads\":" << process.PeLikeVadCount;
        json << L",\"hidden_pte_ranges\":" << process.HiddenPteRanges;
        json << L",\"suspicious_thread_starts\":" << process.SuspiciousThreadStarts;
        json << L"},\"warnings\":";
        AppendJsonStringArray(json, process.Warnings);
        json << L"}";
        if (index + 1 != result.Processes.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";

    return json.str();
}
