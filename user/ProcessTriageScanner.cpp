#include "ProcessTriageScanner.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <unordered_set>

namespace
{
    constexpr uint64_t kPageSize = 0x1000ull;
    constexpr uint64_t kUserAddressMax = 0x00007fffffffffffull;
    constexpr uint64_t kLa57UserAddressMax = 0x00ffffffffffffffull;
    constexpr uint64_t kKernelAddressMin = 0xffff800000000000ull;
    constexpr uint64_t kLargeVadThreshold = 64ull * 1024ull * 1024ull;
    constexpr uint64_t kPtePresent = 0x1ull;
    constexpr uint64_t kPteWrite = 0x2ull;
    constexpr uint64_t kPteUser = 0x4ull;
    constexpr uint64_t kPteLargePage = 0x80ull;
    constexpr uint64_t kPteNx = 0x8000000000000000ull;
    constexpr uint64_t kPte4KBaseMask = 0x000ffffffffff000ull;
    constexpr uint64_t kPte2MBaseMask = 0x000fffffffe00000ull;
    constexpr uint64_t kPte1GBaseMask = 0x000fffffc0000000ull;
    constexpr size_t kPageTableEntries = 512;
    constexpr uint32_t kDefaultHiddenPteRecordLimit = 4096;
    constexpr uint32_t kMaxPageTableReadWarnings = 8;
    constexpr size_t kMaxVadNodes = 65536;
    constexpr size_t kMaxThreads = 16384;
    constexpr size_t kMaxApcEntriesPerQueue = 16;
    constexpr uint64_t kMaxThreadStackScanBytes = 64ull * 1024ull;
    constexpr size_t kMaxStackReferencesPerThread = 16;

    struct VadInterval
    {
        uint64_t StartAddress = 0;
        uint64_t EndAddress = 0;
        bool EffectiveProtectionComplete = false;
        bool EffectiveExecutable = false;
        bool HasVadProtection = false;
        bool VadProtectionExecutable = false;
    };

    struct PteLeafMapping
    {
        uint64_t StartAddress = 0;
        uint64_t EndAddress = 0;
        uint64_t PageSize = 0;
        uint64_t PhysicalAddress = 0;
        uint64_t LeafEntryAddress = 0;
        uint64_t LeafEntry = 0;
        bool Writable = false;
        bool Executable = false;
        bool UserAccessible = false;
        bool LargePage = false;
    };

    std::wstring ToLowerLocal(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    bool EqualsNoCase(const std::wstring& a, const std::wstring& b)
    {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }

    bool IsKernelOnlyProcessTarget(
        const ProcessTriageTarget& target)
    {
        // HasPeb means the EPROCESS.Peb field was read successfully; it does
        // not mean the pointer stored in that field is non-null.  Kernel-only
        // pseudo processes normally expose a readable, zero Peb value.
        if (target.Peb != 0)
        {
            return false;
        }

        return target.ProcessId == 0 ||
            target.ProcessId == 4 ||
            EqualsNoCase(target.ImageName, L"registry") ||
            EqualsNoCase(
                target.ImageName,
                L"memcompression") ||
            EqualsNoCase(
                target.ImageName,
                L"secure system");
    }

    bool IsKernelAddress(uint64_t address)
    {
        return address >= kKernelAddressMin;
    }

    bool IsUserAddress(uint64_t address)
    {
        // Include the LA57 user half so TEB/stack/start classification works
        // on 5-level paging. LA48-only hosts never form canonical VAs above
        // kUserAddressMax for real thread state.
        return address != 0 && address <= kLa57UserAddressMax;
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

    bool TrySub(uint64_t base, uint64_t offset, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || base < offset)
            {
                break;
            }

            *result = base - offset;
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

    std::wstring Hex(uint64_t value, size_t width = 0)
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

    std::wstring JsonEscape(const std::wstring& value)
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
            if (bytes == nullptr || length == 0)
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
                if (field.Length == 0 ||
                    field.Length > 64 ||
                    field.BitPosition >= 64 ||
                    field.Length > 64 - field.BitPosition)
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
        return EqualsNoCase(field.Name, name);
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
        TypeFieldInfo* out,
        std::wstring* source)
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
                        if (source != nullptr)
                        {
                            *source = typeName + L"." + field.Name;
                        }
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
                        if (source != nullptr)
                        {
                            *source = typeName + L"." + field.Name + L"." + fieldName;
                        }
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

    bool ResolveRequiredField(
        SymbolEngine& symbols,
        const std::vector<std::wstring>& typeNames,
        const std::wstring& fieldName,
        TypeFieldInfo* field,
        std::wstring* error)
    {
        bool ok = false;
        std::wstring source;

        do
        {
            if (FindFieldRecursive(symbols, typeNames, fieldName, field, &source))
            {
                ok = true;
                break;
            }

            if (error != nullptr)
            {
                *error = L"missing required field " + fieldName;
            }
        } while (false);

        return ok;
    }

    bool IsValidListEntry(uint64_t flink, uint64_t blink)
    {
        return (flink == 0 && blink == 0) ||
            (IsKernelAddress(flink) && IsKernelAddress(blink));
    }

    std::wstring ProtectionText(uint32_t protection)
    {
        switch (protection & 0x7u)
        {
        case 0:
            return L"NOACCESS";
        case 1:
            return L"READONLY";
        case 2:
            return L"EXECUTE";
        case 3:
            return L"EXECUTE_READ";
        case 4:
            return L"READWRITE";
        case 5:
            return L"WRITECOPY";
        case 6:
            return L"EXECUTE_READWRITE";
        case 7:
            return L"EXECUTE_WRITECOPY";
        default:
            break;
        }

        return L"UNKNOWN";
    }

    bool ProtectionExecutable(uint32_t protection)
    {
        uint32_t p = protection & 0x7u;
        return p == 2 || p == 3 || p == 6 || p == 7;
    }

    bool ProtectionWritable(uint32_t protection)
    {
        uint32_t p = protection & 0x7u;
        return p == 4 || p == 6;
    }

    bool ProtectionCopyOnWrite(uint32_t protection)
    {
        uint32_t p = protection & 0x7u;
        return p == 5 || p == 7;
    }

    bool WindowsProtectionExecutable(DWORD protection)
    {
        switch (protection & 0xffu)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    bool WindowsProtectionWritable(DWORD protection)
    {
        switch (protection & 0xffu)
        {
        case PAGE_READWRITE:
        case PAGE_EXECUTE_READWRITE:
            return true;
        default:
            return false;
        }
    }

    bool WindowsProtectionCopyOnWrite(DWORD protection)
    {
        switch (protection & 0xffu)
        {
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    constexpr size_t kMaxEffectiveProtectionRangesPerVad = 4096;

    bool SameEffectiveProtection(
        const ProcessVadProtectionRange& left,
        const ProcessVadProtectionRange& right)
    {
        return
            left.Protection == right.Protection &&
            left.Type == right.Type &&
            left.Committed == right.Committed &&
            left.Executable == right.Executable &&
            left.Writable == right.Writable &&
            left.CopyOnWrite == right.CopyOnWrite &&
            left.WritableExecutable == right.WritableExecutable &&
            left.CopyOnWriteExecutable == right.CopyOnWriteExecutable;
    }

    bool AppendEffectiveProtectionRange(
        std::vector<ProcessVadProtectionRange>* ranges,
        const ProcessVadProtectionRange& range)
    {
        if (ranges == nullptr ||
            range.EndAddress < range.StartAddress)
        {
            return false;
        }

        if (!ranges->empty())
        {
            ProcessVadProtectionRange& previous = ranges->back();
            if (previous.EndAddress != std::numeric_limits<uint64_t>::max() &&
                previous.EndAddress + 1 == range.StartAddress &&
                SameEffectiveProtection(previous, range))
            {
                previous.EndAddress = range.EndAddress;
                return true;
            }
        }

        if (ranges->size() >= kMaxEffectiveProtectionRangesPerVad)
        {
            return false;
        }
        ranges->push_back(range);
        return true;
    }

    void EnrichVadEffectiveProtection(HANDLE process, ProcessVadRecord* record)
    {
        do
        {
            if (process == nullptr ||
                process == INVALID_HANDLE_VALUE ||
                record == nullptr ||
                record->EndAddress < record->StartAddress)
            {
                break;
            }

            record->EffectiveProtectionQueried = false;
            record->EffectiveProtectionComplete = false;
            record->EffectiveCommittedBytes = 0;
            record->EffectiveExecutableBytes = 0;
            record->EffectiveWritableBytes = 0;
            record->EffectiveCopyOnWriteBytes = 0;
            record->EffectiveWritableExecutableBytes = 0;
            record->EffectiveCopyOnWriteExecutableBytes = 0;
            record->EffectiveImageMapping = false;
            record->EffectiveProtectionText.clear();
            record->EffectiveProtectionRanges.clear();

            uint64_t cursor = record->StartAddress;
            bool complete = false;
            bool queried = false;
            bool rangeLimitReached = false;
            while (cursor <= record->EndAddress)
            {
                MEMORY_BASIC_INFORMATION memory = {};
                SIZE_T returned = VirtualQueryEx(
                    process,
                    reinterpret_cast<const void*>(cursor),
                    &memory,
                    sizeof(memory));
                if (returned < sizeof(memory) || memory.RegionSize == 0)
                {
                    break;
                }
                queried = true;

                uint64_t regionStart = reinterpret_cast<uint64_t>(memory.BaseAddress);
                uint64_t regionSize = static_cast<uint64_t>(memory.RegionSize);
                uint64_t regionEnd = std::numeric_limits<uint64_t>::max();
                if (regionSize - 1 <= std::numeric_limits<uint64_t>::max() - regionStart)
                {
                    regionEnd = regionStart + regionSize - 1;
                }
                if (regionEnd < cursor)
                {
                    break;
                }

                uint64_t overlapStart = cursor > regionStart ? cursor : regionStart;
                uint64_t overlapEnd = regionEnd < record->EndAddress
                    ? regionEnd
                    : record->EndAddress;
                if (overlapEnd < overlapStart)
                {
                    break;
                }

                uint64_t overlapBytes = overlapEnd - overlapStart + 1;
                ProcessVadProtectionRange protectionRange = {};
                protectionRange.StartAddress = overlapStart;
                protectionRange.EndAddress = overlapEnd;
                protectionRange.Protection = memory.Protect;
                protectionRange.Type = memory.Type;
                protectionRange.Committed = memory.State == MEM_COMMIT;
                if (memory.Type == MEM_IMAGE)
                {
                    record->EffectiveImageMapping = true;
                }
                if (memory.State == MEM_COMMIT)
                {
                    bool executable = WindowsProtectionExecutable(memory.Protect);
                    bool writable = WindowsProtectionWritable(memory.Protect);
                    bool copyOnWrite = WindowsProtectionCopyOnWrite(memory.Protect);
                    protectionRange.Executable = executable;
                    protectionRange.Writable = writable;
                    protectionRange.CopyOnWrite = copyOnWrite;
                    protectionRange.WritableExecutable = executable && writable;
                    protectionRange.CopyOnWriteExecutable = executable && copyOnWrite;
                    record->EffectiveCommittedBytes += overlapBytes;
                    if (executable)
                    {
                        record->EffectiveExecutableBytes += overlapBytes;
                    }
                    if (writable)
                    {
                        record->EffectiveWritableBytes += overlapBytes;
                    }
                    if (copyOnWrite)
                    {
                        record->EffectiveCopyOnWriteBytes += overlapBytes;
                    }
                    if (executable && writable)
                    {
                        record->EffectiveWritableExecutableBytes += overlapBytes;
                    }
                    if (executable && copyOnWrite)
                    {
                        record->EffectiveCopyOnWriteExecutableBytes += overlapBytes;
                    }
                }
                if (!AppendEffectiveProtectionRange(
                        &record->EffectiveProtectionRanges,
                        protectionRange))
                {
                    rangeLimitReached = true;
                    break;
                }

                if (regionEnd >= record->EndAddress)
                {
                    complete = true;
                    break;
                }
                if (regionEnd == std::numeric_limits<uint64_t>::max())
                {
                    break;
                }
                cursor = regionEnd + 1;
            }

            record->EffectiveProtectionQueried = queried;
            record->EffectiveProtectionComplete =
                queried && complete && !rangeLimitReached;
            if (!record->EffectiveProtectionComplete)
            {
                record->EffectiveProtectionRanges.clear();
                record->EffectiveCommittedBytes = 0;
                record->EffectiveExecutableBytes = 0;
                record->EffectiveWritableBytes = 0;
                record->EffectiveCopyOnWriteBytes = 0;
                record->EffectiveWritableExecutableBytes = 0;
                record->EffectiveCopyOnWriteExecutableBytes = 0;
                record->EffectiveImageMapping = false;
                break;
            }

            record->Executable = record->EffectiveExecutableBytes != 0;
            record->Writable = record->EffectiveWritableBytes != 0;
            record->WritableExecutable =
                record->EffectiveWritableExecutableBytes != 0;
            record->CopyOnWriteExecutable =
                record->EffectiveCopyOnWriteExecutableBytes != 0;
            record->CopyOnWrite =
                record->EffectiveCopyOnWriteBytes != 0;

            std::wstringstream summary;
            summary << L"committed=" << record->EffectiveCommittedBytes
                    << L",exec=" << record->EffectiveExecutableBytes
                    << L",write=" << record->EffectiveWritableBytes
                    << L",cow=" << record->EffectiveCopyOnWriteBytes
                    << L",wx=" << record->EffectiveWritableExecutableBytes
                    << L",x_cow=" << record->EffectiveCopyOnWriteExecutableBytes;
            record->EffectiveProtectionText = summary.str();
        } while (false);
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
            if (bytes == nullptr || dtb == 0 || length == 0)
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

    uint64_t TargetUserDtb(const ProcessTriageTarget& target)
    {
        return target.UserDirectoryTableBase != 0
            ? target.UserDirectoryTableBase
            : target.DirectoryTableBase;
    }

    uint64_t MaxUserAddressForPagingLevels(uint32_t pagingLevels)
    {
        return pagingLevels >= 5 ? kLa57UserAddressMax : kUserAddressMax;
    }

    uint64_t PageTableIndexShift(uint32_t level)
    {
        return 12ull + (static_cast<uint64_t>(level) - 1ull) * 9ull;
    }

    uint64_t DecodePageTableEntry(const std::vector<uint8_t>& page, size_t index)
    {
        uint64_t value = 0;
        size_t offset = index * sizeof(uint64_t);

        if (offset + sizeof(uint64_t) <= page.size())
        {
            memcpy(&value, page.data() + offset, sizeof(value));
        }

        return value;
    }

    void AddPageTableReadWarning(ProcessVadScanResult* result, const std::wstring& warning)
    {
        if (result == nullptr)
        {
            return;
        }

        ++result->PageTableReadFailures;
        if (result->PageTableReadFailures <= kMaxPageTableReadWarnings)
        {
            result->Warnings.push_back(warning);
        }
        else if (result->PageTableReadFailures == kMaxPageTableReadWarnings + 1)
        {
            result->Warnings.push_back(L"additional page-table read failures suppressed");
        }
    }

    bool ReadPhysicalPage(
        DeviceClient& device,
        uint64_t physicalAddress,
        std::vector<uint8_t>* page,
        ProcessVadScanResult* result)
    {
        bool ok = false;

        do
        {
            if (page == nullptr)
            {
                break;
            }

            page->clear();
            std::wstring readError;
            if (!device.ReadPhysical(physicalAddress & kPte4KBaseMask, static_cast<uint32_t>(kPageSize), page, &readError) ||
                page->size() != kPageSize)
            {
                AddPageTableReadWarning(
                    result,
                    L"failed to read page-table page " + Hex(physicalAddress & kPte4KBaseMask, 16) + L": " + readError);
                break;
            }

            if (result != nullptr)
            {
                ++result->PageTablePagesRead;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool SameHiddenPteShape(const ProcessHiddenVadPteRecord& left, const ProcessHiddenVadPteRecord& right)
    {
        return left.PageSize == right.PageSize &&
            left.Writable == right.Writable &&
            left.Executable == right.Executable &&
            left.UserAccessible == right.UserAccessible &&
            left.LargePage == right.LargePage &&
            left.Notes == right.Notes;
    }

    bool SameVadIntervalShape(const VadInterval& left, const VadInterval& right)
    {
        return left.EffectiveProtectionComplete == right.EffectiveProtectionComplete &&
            left.EffectiveExecutable == right.EffectiveExecutable &&
            left.HasVadProtection == right.HasVadProtection &&
            left.VadProtectionExecutable == right.VadProtectionExecutable;
    }

    void AppendHiddenPteRecord(
        const ProcessVadScanOptions& options,
        const PteLeafMapping& mapping,
        uint64_t startAddress,
        uint64_t endAddress,
        ProcessVadScanResult* result,
        const wchar_t* notes = nullptr)
    {
        do
        {
            if (result == nullptr || endAddress < startAddress)
            {
                break;
            }

            if (result->HiddenPteTruncated)
            {
                break;
            }

            if (options.HiddenPteExecutableOnly && !mapping.Executable)
            {
                break;
            }

            uint64_t size = endAddress - startAddress + 1ull;
            uint64_t offset = startAddress - mapping.StartAddress;

            ++result->HiddenPteRanges;
            result->HiddenPteBytes += size;
            if (mapping.Executable)
            {
                ++result->HiddenPteExecutableCount;
            }
            if (mapping.Executable && mapping.Writable)
            {
                ++result->HiddenPteWxCount;
            }

            ProcessHiddenVadPteRecord record = {};
            record.StartAddress = startAddress;
            record.EndAddress = endAddress;
            record.Size = size;
            record.PageSize = mapping.PageSize;
            record.PageCount = (size + kPageSize - 1ull) / kPageSize;
            record.PhysicalAddress = mapping.PhysicalAddress + offset;
            record.LeafEntryAddress = mapping.LeafEntryAddress;
            record.LeafEntry = mapping.LeafEntry;
            record.Writable = mapping.Writable;
            record.Executable = mapping.Executable;
            record.UserAccessible = mapping.UserAccessible;
            record.LargePage = mapping.LargePage;
            record.Notes = (notes != nullptr && notes[0] != L'\0')
                ? notes
                : L"present_pte_without_vad";

            if (!result->HiddenPteRecords.empty())
            {
                ProcessHiddenVadPteRecord& last = result->HiddenPteRecords.back();
                if (last.EndAddress != std::numeric_limits<uint64_t>::max() &&
                    last.EndAddress + 1ull == record.StartAddress &&
                    SameHiddenPteShape(last, record))
                {
                    last.EndAddress = record.EndAddress;
                    last.Size += record.Size;
                    last.PageCount += record.PageCount;
                    break;
                }
            }

            // HiddenPteLimit is an internal safety bound.  The public /limit
            // option is output-only and must never stop the page-table walk.
            uint32_t recordLimit = options.HiddenPteLimit != 0
                ? options.HiddenPteLimit
                : kDefaultHiddenPteRecordLimit;
            if (result->HiddenPteRecords.size() >= recordLimit)
            {
                result->HiddenPteTruncated = true;
                result->Truncated = true;
                break;
            }

            result->HiddenPteRecords.push_back(record);
        } while (false);
    }

    void ReportHiddenPteGaps(
        const ProcessVadScanOptions& options,
        const std::vector<VadInterval>& vadIntervals,
        PteLeafMapping mapping,
        size_t* vadCursor,
        ProcessVadScanResult* result)
    {
        do
        {
            if (vadCursor == nullptr || result == nullptr || mapping.EndAddress < mapping.StartAddress)
            {
                break;
            }

            if (result->HiddenPteTruncated)
            {
                break;
            }

            if (options.HiddenPteExecutableOnly && !mapping.Executable)
            {
                break;
            }

            ++result->PteLeafMappings;

            while (*vadCursor < vadIntervals.size() &&
                   vadIntervals[*vadCursor].EndAddress < mapping.StartAddress)
            {
                ++(*vadCursor);
            }

            uint64_t uncoveredStart = mapping.StartAddress;
            size_t index = *vadCursor;
            while (index < vadIntervals.size() &&
                   vadIntervals[index].StartAddress <= mapping.EndAddress)
            {
                const VadInterval& interval = vadIntervals[index];
                bool vadLooksNonExec = false;
                if (interval.EffectiveProtectionComplete)
                {
                    vadLooksNonExec = !interval.EffectiveExecutable;
                }
                else if (interval.HasVadProtection)
                {
                    vadLooksNonExec = !interval.VadProtectionExecutable;
                }
                if (mapping.Executable && vadLooksNonExec)
                {
                    const uint64_t overlapStart =
                        (mapping.StartAddress > interval.StartAddress)
                            ? mapping.StartAddress
                            : interval.StartAddress;
                    const uint64_t overlapEnd =
                        (mapping.EndAddress < interval.EndAddress)
                            ? mapping.EndAddress
                            : interval.EndAddress;
                    if (overlapStart <= overlapEnd)
                    {
                        AppendHiddenPteRecord(
                            options,
                            mapping,
                            overlapStart,
                            overlapEnd,
                            result,
                            L"pte_exec_vad_rw");
                        if (result->HiddenPteTruncated)
                        {
                            break;
                        }
                    }
                }
                if (interval.StartAddress > uncoveredStart)
                {
                    AppendHiddenPteRecord(
                        options,
                        mapping,
                        uncoveredStart,
                        (std::min)(mapping.EndAddress, interval.StartAddress - 1ull),
                        result);
                    if (result->HiddenPteTruncated)
                    {
                        break;
                    }
                }

                if (interval.EndAddress == std::numeric_limits<uint64_t>::max())
                {
                    uncoveredStart = std::numeric_limits<uint64_t>::max();
                    break;
                }

                if (interval.EndAddress + 1ull > uncoveredStart)
                {
                    uncoveredStart = interval.EndAddress + 1ull;
                }
                if (uncoveredStart > mapping.EndAddress)
                {
                    break;
                }
                ++index;
            }

            if (!result->HiddenPteTruncated && uncoveredStart <= mapping.EndAddress)
            {
                AppendHiddenPteRecord(options, mapping, uncoveredStart, mapping.EndAddress, result);
            }
        } while (false);
    }

    void WalkUserPageTableLevel(
        DeviceClient& device,
        uint64_t tablePhysical,
        uint32_t level,
        uint32_t pagingLevels,
        uint64_t baseAddress,
        bool writableSoFar,
        bool userSoFar,
        bool nxSoFar,
        const ProcessVadScanOptions& options,
        const std::vector<VadInterval>& vadIntervals,
        size_t* vadCursor,
        ProcessVadScanResult* result)
    {
        std::vector<uint8_t> page;
        if (!ReadPhysicalPage(device, tablePhysical, &page, result))
        {
            return;
        }

        size_t lastIndex = kPageTableEntries - 1;
        if (level == pagingLevels)
        {
            lastIndex = 255;
        }

        uint64_t indexShift = PageTableIndexShift(level);
        uint64_t maxUserAddress = MaxUserAddressForPagingLevels(pagingLevels);
        for (size_t index = 0; index <= lastIndex; ++index)
        {
            if (result != nullptr && result->HiddenPteTruncated)
            {
                break;
            }

            uint64_t entry = DecodePageTableEntry(page, index);
            if ((entry & kPtePresent) == 0)
            {
                continue;
            }

            uint64_t entryBaseAddress = baseAddress + (static_cast<uint64_t>(index) << indexShift);
            if (entryBaseAddress > maxUserAddress)
            {
                continue;
            }

            bool entryWritable = writableSoFar && ((entry & kPteWrite) != 0);
            bool entryUser = userSoFar && ((entry & kPteUser) != 0);
            bool entryNx = nxSoFar || ((entry & kPteNx) != 0);
            uint64_t entryPhysicalAddress = (tablePhysical & kPte4KBaseMask) + index * sizeof(uint64_t);

            if (!entryUser)
            {
                continue;
            }

            if (level == 3 && ((entry & kPteLargePage) != 0))
            {
                uint64_t endAddress = entryBaseAddress + 0x40000000ull - 1ull;
                if (endAddress > maxUserAddress)
                {
                    endAddress = maxUserAddress;
                }

                PteLeafMapping mapping = {};
                mapping.StartAddress = entryBaseAddress;
                mapping.EndAddress = endAddress;
                mapping.PageSize = 0x40000000ull;
                mapping.PhysicalAddress = entry & kPte1GBaseMask;
                mapping.LeafEntryAddress = entryPhysicalAddress;
                mapping.LeafEntry = entry;
                mapping.Writable = entryWritable;
                mapping.Executable = !entryNx;
                mapping.UserAccessible = entryUser;
                mapping.LargePage = true;
                ReportHiddenPteGaps(options, vadIntervals, mapping, vadCursor, result);
                continue;
            }

            if (level == 2 && ((entry & kPteLargePage) != 0))
            {
                uint64_t endAddress = entryBaseAddress + 0x200000ull - 1ull;
                if (endAddress > maxUserAddress)
                {
                    endAddress = maxUserAddress;
                }

                PteLeafMapping mapping = {};
                mapping.StartAddress = entryBaseAddress;
                mapping.EndAddress = endAddress;
                mapping.PageSize = 0x200000ull;
                mapping.PhysicalAddress = entry & kPte2MBaseMask;
                mapping.LeafEntryAddress = entryPhysicalAddress;
                mapping.LeafEntry = entry;
                mapping.Writable = entryWritable;
                mapping.Executable = !entryNx;
                mapping.UserAccessible = entryUser;
                mapping.LargePage = true;
                ReportHiddenPteGaps(options, vadIntervals, mapping, vadCursor, result);
                continue;
            }

            if (level == 1)
            {
                uint64_t endAddress = entryBaseAddress + kPageSize - 1ull;
                if (endAddress > maxUserAddress)
                {
                    endAddress = maxUserAddress;
                }

                PteLeafMapping mapping = {};
                mapping.StartAddress = entryBaseAddress;
                mapping.EndAddress = endAddress;
                mapping.PageSize = kPageSize;
                mapping.PhysicalAddress = entry & kPte4KBaseMask;
                mapping.LeafEntryAddress = entryPhysicalAddress;
                mapping.LeafEntry = entry;
                mapping.Writable = entryWritable;
                mapping.Executable = !entryNx;
                mapping.UserAccessible = entryUser;
                mapping.LargePage = false;
                ReportHiddenPteGaps(options, vadIntervals, mapping, vadCursor, result);
                continue;
            }

            WalkUserPageTableLevel(
                device,
                entry & kPte4KBaseMask,
                level - 1u,
                pagingLevels,
                entryBaseAddress,
                entryWritable,
                entryUser,
                entryNx,
                options,
                vadIntervals,
                vadCursor,
                result);
        }
    }

    uint32_t DetectPagingLevels(
        DeviceClient& device,
        const ProcessTriageTarget& target,
        uint64_t dtb,
        const std::vector<VadInterval>& vadIntervals,
        ProcessVadScanResult* result)
    {
        uint32_t pagingLevels = 4;
        bool detected = false;

        do
        {
            PhysicalTranslationInfo info = {};
            std::wstring ignored;
            if (target.Eprocess != 0 &&
                device.TranslateVirtual(0, target.Eprocess, 1, &info, &ignored) &&
                info.PagingLevels >= 4 &&
                info.PagingLevels <= 5)
            {
                pagingLevels = info.PagingLevels;
                detected = true;
                break;
            }

            if (dtb != 0 && target.HasPeb && target.Peb != 0 &&
                device.TranslateVirtual(dtb, target.Peb, 1, &info, &ignored) &&
                info.PagingLevels >= 4 &&
                info.PagingLevels <= 5)
            {
                pagingLevels = info.PagingLevels;
                detected = true;
                break;
            }

            for (const VadInterval& interval : vadIntervals)
            {
                if (dtb != 0 &&
                    interval.StartAddress != 0 &&
                    device.TranslateVirtual(dtb, interval.StartAddress, 1, &info, &ignored) &&
                    info.PagingLevels >= 4 &&
                    info.PagingLevels <= 5)
                {
                    pagingLevels = info.PagingLevels;
                    detected = true;
                    break;
                }
            }

            if (!detected && result != nullptr)
            {
                result->Warnings.push_back(L"could not confirm LA57 state from translation; assuming 4-level paging");
            }
        } while (false);

        return pagingLevels;
    }

    void ScanHiddenVadPtes(
        DeviceClient& device,
        const ProcessVadScanOptions& options,
        const std::vector<VadInterval>& vadIntervals,
        ProcessVadScanResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            result->HiddenPteScanEnabled = true;

            uint64_t dtb = TargetUserDtb(options.Target) & kPte4KBaseMask;
            if (dtb == 0)
            {
                result->Warnings.push_back(L"hidden PTE scan skipped: target DTB is unavailable");
                break;
            }

            uint32_t pagingLevels = DetectPagingLevels(device, options.Target, dtb, vadIntervals, result);
            result->PagingLevels = pagingLevels;
            size_t vadCursor = 0;
            WalkUserPageTableLevel(
                device,
                dtb,
                pagingLevels,
                pagingLevels,
                0,
                true,
                true,
                false,
                options,
                vadIntervals,
                &vadCursor,
                result);

            if (result->PageTableReadFailures != 0)
            {
                // A lock-free page-table walk can race process teardown or
                // page-table reclamation.  Once an intermediate page cannot
                // be read, bytes reached through that snapshot are no longer
                // trustworthy as DKOM evidence.  Fail closed and let the hunt
                // caller retry from a fresh VAD/page-table snapshot.
                result->HiddenPteRecords.clear();
                result->HiddenPteRanges = 0;
                result->HiddenPteBytes = 0;
                result->HiddenPteExecutableCount = 0;
                result->HiddenPteWxCount = 0;
                result->HiddenPteTruncated = false;
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"hidden PTE evidence suppressed because the page-table walk had read failures");
            }
        } while (false);
    }

    void ApplyHiddenPteOutputLimit(
        const ProcessVadScanOptions& options,
        ProcessVadScanResult* result)
    {
        if (result == nullptr ||
            options.Limit == 0 ||
            result->HiddenPteRecords.size() <= options.Limit)
        {
            return;
        }

        result->HiddenPteRecords.resize(options.Limit);
        result->Truncated = true;
    }

    void NormalizeVadIntervals(std::vector<VadInterval>* intervals)
    {
        do
        {
            if (intervals == nullptr || intervals->empty())
            {
                break;
            }

            std::sort(
                intervals->begin(),
                intervals->end(),
                [](const VadInterval& left, const VadInterval& right)
                {
                    if (left.StartAddress != right.StartAddress)
                    {
                        return left.StartAddress < right.StartAddress;
                    }

                    return left.EndAddress < right.EndAddress;
                });

            std::vector<VadInterval> merged;
            for (const VadInterval& interval : *intervals)
            {
                if (interval.EndAddress < interval.StartAddress)
                {
                    continue;
                }

                bool touchesPrevious = !merged.empty() &&
                    SameVadIntervalShape(merged.back(), interval) &&
                    (merged.back().EndAddress == std::numeric_limits<uint64_t>::max() ||
                     interval.StartAddress <= merged.back().EndAddress + 1ull);
                if (touchesPrevious)
                {
                    if (interval.EndAddress > merged.back().EndAddress)
                    {
                        merged.back().EndAddress = interval.EndAddress;
                    }
                    continue;
                }

                merged.push_back(interval);
            }

            *intervals = merged;
        } while (false);
    }

    void AddKnownVadlessUserMappings(std::vector<VadInterval>* intervals)
    {
        if (intervals != nullptr)
        {
            intervals->push_back({0x000000007ffe0000ull, 0x000000007ffeffffull});
        }
    }

    bool EnumerateUserModules(uint32_t pid, std::vector<ProcessUserModuleRange>* modules, std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (modules == nullptr)
            {
                break;
            }

            modules->clear();
            DWORD snapshotError = ERROR_SUCCESS;
            constexpr size_t kMaxModuleSnapshotAttempts = 8;
            for (size_t attempt = 0;
                 attempt < kMaxModuleSnapshotAttempts;
                 ++attempt)
            {
                snapshot = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                    pid);
                if (snapshot != INVALID_HANDLE_VALUE)
                {
                    break;
                }

                snapshotError = GetLastError();
                if (snapshotError != ERROR_BAD_LENGTH)
                {
                    break;
                }
                SwitchToThread();
            }
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"user module enumeration failed: CreateToolhelp32Snapshot gle=" +
                        std::to_wstring(snapshotError);
                }
                break;
            }

            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (!Module32FirstW(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning = L"user module enumeration failed: Module32FirstW gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            for (;;)
            {
                ProcessUserModuleRange module = {};
                module.Base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                module.Size = static_cast<uint64_t>(entry.modBaseSize);
                module.ImageName = entry.szModule;
                module.ImagePath = entry.szExePath;
                modules->push_back(module);
                entry.dwSize = sizeof(entry);
                if (Module32NextW(snapshot, &entry))
                {
                    continue;
                }

                const DWORD enumerationError = GetLastError();
                if (enumerationError == ERROR_NO_MORE_FILES)
                {
                    ok = true;
                }
                else if (warning != nullptr)
                {
                    *warning =
                        L"user module enumeration failed: Module32NextW gle=" +
                        std::to_wstring(enumerationError);
                }
                break;
            }
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            if (snapshot != nullptr)
            {
                CloseHandle(snapshot);
            }
        }
        return ok;
    }

    bool HasExactProcessIdentity(
        const ProcessTriageTarget& target)
    {
        return target.ProcessId != 0 &&
            target.Eprocess != 0 &&
            target.HasCreateTime &&
            target.CreateTime != 0;
    }

    bool ProcessHandleMatchesTriageTarget(
        HANDLE handle,
        const ProcessTriageTarget& target)
    {
        if (handle == nullptr ||
            handle == INVALID_HANDLE_VALUE ||
            !HasExactProcessIdentity(target))
        {
            return false;
        }

        FILETIME createTime = {};
        FILETIME exitTime = {};
        FILETIME kernelTime = {};
        FILETIME userTime = {};
        DWORD exitCode = 0;
        if (!GetProcessTimes(
                handle,
                &createTime,
                &exitTime,
                &kernelTime,
                &userTime) ||
            !GetExitCodeProcess(
                handle,
                &exitCode))
        {
            return false;
        }

        ULARGE_INTEGER observed = {};
        observed.LowPart = createTime.dwLowDateTime;
        observed.HighPart = createTime.dwHighDateTime;
        return observed.QuadPart ==
                target.CreateTime &&
            exitCode == STILL_ACTIVE;
    }

    bool ReadTargetProcessMemory(
        DeviceClient& device,
        const ProcessTriageTarget& target,
        uint64_t dtb,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        if (HasExactProcessIdentity(target))
        {
            // An exact read failure may mean process exit or PID reuse. Do not
            // accept bytes from the captured DTB after that identity gate
            // failed.
            return device.ReadProcessVirtual(
                target.ProcessId,
                target.Eprocess,
                target.CreateTime,
                address,
                length,
                bytes,
                error);
        }

        return ReadProcessMemoryByDtb(
            device,
            dtb,
            address,
            length,
            bytes,
            error);
    }

    void MergeUserModuleRanges(
        std::vector<ProcessUserModuleRange>* destination,
        const std::vector<ProcessUserModuleRange>& source)
    {
        if (destination == nullptr)
        {
            return;
        }

        for (const ProcessUserModuleRange& incoming : source)
        {
            if (incoming.Base == 0 || incoming.Size == 0)
            {
                continue;
            }

            auto existing = std::find_if(
                destination->begin(),
                destination->end(),
                [&incoming](const ProcessUserModuleRange& candidate)
                {
                    return candidate.Base == incoming.Base;
                });
            if (existing == destination->end())
            {
                destination->push_back(incoming);
                continue;
            }

            if (existing->Size == 0)
            {
                existing->Size = incoming.Size;
            }
            if (existing->ImageName.empty())
            {
                existing->ImageName = incoming.ImageName;
            }
            if (existing->ImagePath.empty())
            {
                existing->ImagePath = incoming.ImagePath;
            }
        }
    }

    const ProcessUserModuleRange* FindUserModule(
        const std::vector<ProcessUserModuleRange>& modules,
        uint64_t address)
    {
        const ProcessUserModuleRange* found = nullptr;

        for (const ProcessUserModuleRange& module : modules)
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }

            if (address >= module.Base && address < end)
            {
                found = &module;
                break;
            }
        }

        return found;
    }

    const ProcessVadRecord* FindVadForAddress(
        const std::vector<ProcessVadRecord>& records,
        uint64_t address)
    {
        const ProcessVadRecord* found = nullptr;

        for (const ProcessVadRecord& record : records)
        {
            if (address >= record.StartAddress && address <= record.EndAddress)
            {
                found = &record;
                break;
            }
        }

        return found;
    }

    const ProcessVadProtectionRange* FindEffectiveProtectionForAddress(
        const ProcessVadRecord& record,
        uint64_t address)
    {
        auto after = std::upper_bound(
            record.EffectiveProtectionRanges.begin(),
            record.EffectiveProtectionRanges.end(),
            address,
            [](uint64_t value, const ProcessVadProtectionRange& range)
            {
                return value < range.StartAddress;
            });
        if (after == record.EffectiveProtectionRanges.begin())
        {
            return nullptr;
        }

        --after;
        return address <= after->EndAddress ? &*after : nullptr;
    }

    bool VadAddressIsExecutable(const ProcessVadRecord& record, uint64_t address)
    {
        if (!record.EffectiveProtectionComplete)
        {
            return record.Executable;
        }

        const ProcessVadProtectionRange* range =
            FindEffectiveProtectionForAddress(record, address);
        return range != nullptr && range->Committed && range->Executable;
    }

    bool VadAddressIsWritableExecutable(const ProcessVadRecord& record, uint64_t address)
    {
        if (!record.EffectiveProtectionComplete)
        {
            return record.WritableExecutable;
        }

        const ProcessVadProtectionRange* range =
            FindEffectiveProtectionForAddress(record, address);
        return range != nullptr &&
            range->Committed &&
            range->WritableExecutable;
    }

    bool ReadTargetProcessU64(
        DeviceClient& device,
        const ProcessTriageTarget& target,
        uint64_t dtb,
        uint64_t address,
        uint64_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            *value = 0;
            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadTargetProcessMemory(
                    device,
                    target,
                    dtb,
                    address,
                    sizeof(uint64_t),
                    &bytes,
                    &ignored) ||
                bytes.size() != sizeof(uint64_t))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadUserStackBoundsFromTeb(
        DeviceClient& device,
        const ProcessTriageTarget& target,
        uint64_t dtb,
        ProcessThreadRecord* record)
    {
        bool ok = false;

        do
        {
            if (record == nullptr)
            {
                break;
            }

            record->UserStackBase = 0;
            record->UserStackLimit = 0;
            record->HasUserStackBounds = false;

            uint64_t stackBase = 0;
            uint64_t stackLimit = 0;
            if (record->HasTeb && IsUserAddress(record->Teb))
            {
                if (!ReadTargetProcessU64(
                        device,
                        target,
                        dtb,
                        record->Teb + 0x08,
                        &stackBase) ||
                    !ReadTargetProcessU64(
                        device,
                        target,
                        dtb,
                        record->Teb + 0x10,
                        &stackLimit))
                {
                    stackBase = 0;
                    stackLimit = 0;
                }
            }

            if ((stackBase == 0 || stackLimit == 0) &&
                record->HasStackBounds &&
                IsUserAddress(record->StackBase) &&
                IsUserAddress(record->StackLimit))
            {
                stackBase = record->StackBase;
                stackLimit = record->StackLimit;
            }

            if (!IsUserAddress(stackBase) ||
                !IsUserAddress(stackLimit) ||
                stackBase <= stackLimit)
            {
                break;
            }

            uint64_t stackSize = stackBase - stackLimit;
            if (stackSize == 0 || stackSize > 512ull * 1024ull * 1024ull)
            {
                break;
            }

            record->UserStackBase = stackBase;
            record->UserStackLimit = stackLimit;
            record->HasUserStackBounds = true;
            ok = true;
        } while (false);

        return ok;
    }

    bool StackReferenceAlreadyRecorded(const ProcessThreadRecord& record, uint64_t value)
    {
        bool found = false;

        for (const ProcessStackReferenceRecord& item : record.StackReferences)
        {
            if (item.Value == value)
            {
                found = true;
                break;
            }
        }

        return found;
    }

    void TryAppendStackReference(
        const std::vector<ProcessUserModuleRange>& modules,
        bool userModuleCoverageComplete,
        const std::vector<ProcessVadRecord>& vadRecords,
        uint64_t stackAddress,
        uint64_t value,
        ProcessThreadRecord* record)
    {
        do
        {
            if (record == nullptr ||
                record->StackReferences.size() >= kMaxStackReferencesPerThread ||
                !IsUserAddress(value) ||
                StackReferenceAlreadyRecorded(*record, value))
            {
                break;
            }

            const ProcessVadRecord* vad = FindVadForAddress(vadRecords, value);
            if (vad == nullptr || !VadAddressIsExecutable(*vad, value))
            {
                break;
            }

            const ProcessUserModuleRange* module = FindUserModule(modules, value);
            bool privateExec =
                vad->HasPrivateMemory &&
                vad->PrivateMemory;
            bool wx = VadAddressIsWritableExecutable(*vad, value);
            bool executableOutsideModule =
                userModuleCoverageComplete &&
                module == nullptr;
            if (!privateExec && !wx && !executableOutsideModule)
            {
                break;
            }

            ProcessStackReferenceRecord ref = {};
            ref.StackAddress = stackAddress;
            ref.Value = value;
            ref.UserModuleEnumerationAvailable =
                userModuleCoverageComplete;
            ref.ValueInUserModule = module != nullptr;
            ref.ValueOutsideUserModules = executableOutsideModule;
            ref.ValueModule = module != nullptr ? module->ImageName : L"";
            ref.VadClassification = vad->Classification;
            ref.ValueInPrivateExecVad = privateExec;
            ref.ValueInWxVad = wx;
            ref.Suspicious = true;
            if (privateExec)
            {
                ref.Notes = L"stack value lands in private executable VAD";
            }
            else if (wx)
            {
                ref.Notes = L"stack value lands in writable executable VAD";
            }
            else
            {
                ref.Notes = L"stack value lands in executable VAD outside enumerated modules";
            }

            record->StackReferences.push_back(ref);
        } while (false);
    }

    void ScanUserStackReferences(
        DeviceClient& device,
        const ProcessTriageTarget& target,
        const std::vector<ProcessUserModuleRange>& modules,
        bool userModuleCoverageComplete,
        const std::vector<ProcessVadRecord>& vadRecords,
        uint64_t dtb,
        ProcessThreadRecord* record)
    {
        do
        {
            if (record == nullptr ||
                !record->HasUserStackBounds ||
                (dtb == 0 &&
                 !HasExactProcessIdentity(target)) ||
                record->UserStackBase <= record->UserStackLimit)
            {
                break;
            }

            uint64_t scanEnd = record->UserStackBase;
            uint64_t scanStart = record->UserStackLimit;
            if (scanEnd - scanStart > kMaxThreadStackScanBytes)
            {
                scanStart = scanEnd - kMaxThreadStackScanBytes;
            }
            if ((scanStart & 0x7ull) != 0)
            {
                scanStart = (scanStart + 0x7ull) & ~0x7ull;
            }
            if (scanEnd < sizeof(uint64_t))
            {
                break;
            }

            uint64_t current = scanStart;
            while (current <= scanEnd - sizeof(uint64_t) &&
                   record->StackReferences.size() < kMaxStackReferencesPerThread)
            {
                uint64_t nextPage = (current & ~(kPageSize - 1ull)) + kPageSize;
                uint64_t chunkEnd = nextPage < scanEnd ? nextPage : scanEnd;
                if (chunkEnd <= current)
                {
                    break;
                }

                uint32_t chunkSize = static_cast<uint32_t>(chunkEnd - current);
                std::vector<uint8_t> bytes;
                std::wstring ignored;
                if (ReadTargetProcessMemory(
                        device,
                        target,
                        dtb,
                        current,
                        chunkSize,
                        &bytes,
                        &ignored))
                {
                    for (size_t offset = 0;
                         offset + sizeof(uint64_t) <= bytes.size() &&
                         record->StackReferences.size() < kMaxStackReferencesPerThread;
                         offset += sizeof(uint64_t))
                    {
                        uint64_t value = 0;
                        memcpy(&value, bytes.data() + offset, sizeof(uint64_t));
                        TryAppendStackReference(
                            modules,
                            userModuleCoverageComplete,
                            vadRecords,
                            current + offset,
                            value,
                            record);
                    }
                }

                current = chunkEnd;
                if ((current & 0x7ull) != 0)
                {
                    current = (current + 0x7ull) & ~0x7ull;
                }
            }
        } while (false);
    }

    void AnnotateKernelPointer(SymbolEngine& symbols, uint64_t address, std::wstring* moduleName, std::wstring* symbolName)
    {
        do
        {
            if (moduleName != nullptr)
            {
                moduleName->clear();
            }
            if (symbolName != nullptr)
            {
                symbolName->clear();
            }

            if (address == 0)
            {
                break;
            }

            for (const KernelModuleInfo& module : symbols.Modules())
            {
                uint64_t end = module.Base + module.Size;
                if (end < module.Base)
                {
                    continue;
                }
                if (address >= module.Base && address < end)
                {
                    if (moduleName != nullptr)
                    {
                        *moduleName = module.ImageName;
                    }
                    break;
                }
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
            {
                if (symbolName != nullptr)
                {
                    std::wstringstream stream;
                    stream << nearest;
                    if (displacement != 0)
                    {
                        stream << L"+0x" << std::hex << displacement;
                    }
                    *symbolName = stream.str();
                }
            }
        } while (false);
    }

    struct VadLayout
    {
        TypeFieldInfo VadRoot = {};
        TypeFieldInfo RtlRoot = {};
        TypeFieldInfo Left = {};
        TypeFieldInfo Right = {};
        TypeFieldInfo VadNode = {};
        TypeFieldInfo StartingVpn = {};
        TypeFieldInfo EndingVpn = {};
        TypeFieldInfo StartingVpnHigh = {};
        TypeFieldInfo EndingVpnHigh = {};
        TypeFieldInfo Protection = {};
        TypeFieldInfo PrivateMemory = {};
        TypeFieldInfo CommitCharge = {};
        TypeFieldInfo NoChange = {};
        TypeFieldInfo Large = {};
        TypeFieldInfo Subsection = {};
        TypeFieldInfo ControlArea = {};
        TypeFieldInfo FilePointer = {};
        TypeFieldInfo FileName = {};
        TypeFieldInfo MappedViews = {};
        bool HasRtlRoot = false;
        bool HasVadNode = false;
        bool HasStartingVpnHigh = false;
        bool HasEndingVpnHigh = false;
        bool HasProtection = false;
        bool HasPrivateMemory = false;
        bool HasCommitCharge = false;
        bool HasNoChange = false;
        bool HasLarge = false;
        bool HasSubsection = false;
        bool HasControlArea = false;
        bool HasFilePointer = false;
        bool HasFileName = false;
        bool HasMappedViews = false;
        std::vector<std::wstring> Warnings;
    };

    bool ResolveVadLayout(SymbolEngine& symbols, VadLayout* layout, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                break;
            }

            *layout = VadLayout{};
            if (!ResolveRequiredField(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"VadRoot", &layout->VadRoot, error))
            {
                break;
            }

            layout->HasRtlRoot =
                FindFieldRecursive(symbols, {L"nt!_RTL_AVL_TREE", L"_RTL_AVL_TREE"}, L"Root", &layout->RtlRoot, nullptr);
            if (!layout->HasRtlRoot)
            {
                layout->Warnings.push_back(L"_RTL_AVL_TREE.Root not found; treating EPROCESS.VadRoot as the root pointer");
            }

            if (!ResolveRequiredField(symbols, {L"nt!_RTL_BALANCED_NODE", L"_RTL_BALANCED_NODE"}, L"Left", &layout->Left, error) ||
                !ResolveRequiredField(symbols, {L"nt!_RTL_BALANCED_NODE", L"_RTL_BALANCED_NODE"}, L"Right", &layout->Right, error))
            {
                break;
            }

            layout->HasVadNode =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"VadNode", &layout->VadNode, nullptr);
            if (!layout->HasVadNode)
            {
                layout->Warnings.push_back(L"_MMVAD_SHORT.VadNode not found; assuming the balanced node is at offset 0");
                layout->VadNode.Offset = 0;
            }

            if (!ResolveRequiredField(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"StartingVpn", &layout->StartingVpn, error) ||
                !ResolveRequiredField(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"EndingVpn", &layout->EndingVpn, error))
            {
                break;
            }

            layout->HasStartingVpnHigh =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"StartingVpnHigh", &layout->StartingVpnHigh, nullptr);
            layout->HasEndingVpnHigh =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"EndingVpnHigh", &layout->EndingVpnHigh, nullptr);
            layout->HasProtection =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"Protection", &layout->Protection, nullptr);
            layout->HasPrivateMemory =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"PrivateMemory", &layout->PrivateMemory, nullptr);
            layout->HasCommitCharge =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"CommitCharge", &layout->CommitCharge, nullptr);
            layout->HasNoChange =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"NoChange", &layout->NoChange, nullptr);
            layout->HasLarge =
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"Large", &layout->Large, nullptr) ||
                FindFieldRecursive(symbols, {L"nt!_MMVAD_SHORT", L"_MMVAD_SHORT", L"nt!_MMVAD", L"_MMVAD"}, L"LargePages", &layout->Large, nullptr);
            layout->HasSubsection =
                FindFieldRecursive(symbols, {L"nt!_MMVAD", L"_MMVAD"}, L"Subsection", &layout->Subsection, nullptr);
            layout->HasControlArea =
                FindFieldRecursive(symbols, {L"nt!_SUBSECTION", L"_SUBSECTION"}, L"ControlArea", &layout->ControlArea, nullptr);
            layout->HasFilePointer =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"FilePointer", &layout->FilePointer, nullptr);
            layout->HasFileName =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"FileName", &layout->FileName, nullptr);
            layout->HasMappedViews =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"NumberOfMappedViews", &layout->MappedViews, nullptr) ||
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"NumberOfUserReferences", &layout->MappedViews, nullptr);

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadVadChildPointers(
        DeviceClient& device,
        const VadLayout& layout,
        uint64_t nodeAddress,
        uint64_t* left,
        uint64_t* right,
        std::wstring* error)
    {
        uint64_t leftAddress = 0;
        uint64_t rightAddress = 0;
        if (left == nullptr ||
            right == nullptr ||
            !TryAdd(nodeAddress, layout.Left.Offset, &leftAddress) ||
            !TryAdd(nodeAddress, layout.Right.Offset, &rightAddress))
        {
            if (error != nullptr)
            {
                *error = L"VAD child pointer address overflow";
            }
            return false;
        }

        *left = 0;
        *right = 0;
        std::wstring leftError;
        std::wstring rightError;
        const bool leftRead = ReadKernelPointer(
            device,
            leftAddress,
            left,
            &leftError);
        const bool rightRead = ReadKernelPointer(
            device,
            rightAddress,
            right,
            &rightError);
        if ((!leftRead || !rightRead) && error != nullptr)
        {
            *error = !leftRead && !rightRead
                ? L"left=" + leftError + L"; right=" + rightError
                : (!leftRead
                       ? L"left=" + leftError
                       : L"right=" + rightError);
        }
        return leftRead && rightRead;
    }

    struct VadTraversalOutcome
    {
        uint64_t NodesVisited = 0;
        bool CoverageReliable = true;
        bool HitLimit = false;
    };

    using VadChildReader = std::function<bool(
        uint64_t,
        uint64_t*,
        uint64_t*,
        std::wstring*)>;
    using VadRecordVisitor = std::function<bool(
        uint64_t,
        uint64_t,
        uint64_t,
        std::wstring*)>;

    VadTraversalOutcome TraverseVadNodes(
        uint64_t root,
        uint64_t maxNodes,
        const VadChildReader& readChildren,
        const VadRecordVisitor& visitRecord,
        std::vector<std::wstring>* warnings)
    {
        VadTraversalOutcome outcome = {};
        if (root == 0 ||
            maxNodes == 0 ||
            !readChildren ||
            !visitRecord)
        {
            return outcome;
        }

        std::vector<uint64_t> stack;
        std::unordered_set<uint64_t> visited;
        stack.push_back(root);
        visited.reserve(static_cast<size_t>(
            std::min<uint64_t>(maxNodes, 4096)));

        while (!stack.empty() && outcome.NodesVisited < maxNodes)
        {
            const uint64_t node = stack.back();
            stack.pop_back();

            if (node == 0)
            {
                continue;
            }
            if (!IsKernelAddress(node))
            {
                outcome.CoverageReliable = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"VAD node is not kernel-canonical: " +
                        Hex(node, 16));
                }
                continue;
            }
            if (!visited.insert(node).second)
            {
                outcome.CoverageReliable = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"VAD cycle or duplicate child detected at " +
                        Hex(node, 16));
                }
                continue;
            }

            ++outcome.NodesVisited;

            uint64_t left = 0;
            uint64_t right = 0;
            std::wstring childError;
            const bool childrenComplete = readChildren(
                    node,
                    &left,
                    &right,
                    &childError);
            if (!childrenComplete)
            {
                outcome.CoverageReliable = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"failed to read VAD child links " +
                        Hex(node, 16) + L": " + childError);
                }
            }

            // Queue the descendants before decoding optional VAD metadata.
            // A poisoned current record must not hide otherwise readable
            // child subtrees.
            if (right != 0)
            {
                stack.push_back(right);
            }
            if (left != 0)
            {
                stack.push_back(left);
            }

            std::wstring recordError;
            if (!visitRecord(
                    node,
                    left,
                    right,
                    &recordError))
            {
                outcome.CoverageReliable = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"failed to read VAD node " +
                        Hex(node, 16) + L": " + recordError +
                        L" (continuing descendants)");
                }
            }
        }

        if (!stack.empty())
        {
            outcome.HitLimit = true;
            outcome.CoverageReliable = false;
        }
        return outcome;
    }

    bool ReadVadRecord(
        DeviceClient& device,
        const VadLayout& layout,
        uint64_t nodeAddress,
        uint64_t left,
        uint64_t right,
        ProcessVadRecord* record,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (record == nullptr)
            {
                break;
            }

            *record = ProcessVadRecord{};
            record->NodeAddress = nodeAddress;
            record->Left = left;
            record->Right = right;
            if (!TrySub(nodeAddress, layout.VadNode.Offset, &record->VadAddress))
            {
                if (error != nullptr)
                {
                    *error = L"VAD node address underflow";
                }
                break;
            }

            uint64_t startVpn = 0;
            uint64_t endVpn = 0;
            if (!ReadFieldInteger(device, record->VadAddress, layout.StartingVpn, sizeof(uint32_t), &startVpn, error) ||
                !ReadFieldInteger(device, record->VadAddress, layout.EndingVpn, sizeof(uint32_t), &endVpn, error))
            {
                break;
            }

            if (layout.HasStartingVpnHigh)
            {
                uint64_t high = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.StartingVpnHigh, sizeof(uint8_t), &high, nullptr))
                {
                    startVpn |= high << 32;
                }
            }

            if (layout.HasEndingVpnHigh)
            {
                uint64_t high = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.EndingVpnHigh, sizeof(uint8_t), &high, nullptr))
                {
                    endVpn |= high << 32;
                }
            }

            record->StartVpn = startVpn;
            record->EndVpn = endVpn;
            constexpr uint64_t maxVpn = std::numeric_limits<uint64_t>::max() >> 12;
            if (startVpn > maxVpn || endVpn > maxVpn || endVpn < startVpn)
            {
                if (error != nullptr)
                {
                    *error = L"invalid VAD VPN range";
                }
                break;
            }

            record->StartAddress = startVpn << 12;
            if (endVpn == maxVpn)
            {
                record->EndAddress = std::numeric_limits<uint64_t>::max();
            }
            else
            {
                record->EndAddress = ((endVpn + 1ull) << 12) - 1ull;
            }

            if (record->EndAddress >= record->StartAddress)
            {
                record->Size = record->EndAddress - record->StartAddress + 1ull;
            }

            if (layout.HasProtection)
            {
                uint64_t protection = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.Protection, sizeof(uint32_t), &protection, nullptr))
                {
                    record->Protection = static_cast<uint32_t>(protection);
                    record->ProtectionText = ProtectionText(record->Protection);
                    record->Executable = ProtectionExecutable(record->Protection);
                    record->Writable = ProtectionWritable(record->Protection);
                    record->CopyOnWrite = ProtectionCopyOnWrite(record->Protection);
                    record->WritableExecutable =
                        record->Executable && record->Writable;
                    record->CopyOnWriteExecutable =
                        record->Executable && record->CopyOnWrite;
                    record->HasProtection = true;
                }
            }

            if (layout.HasPrivateMemory)
            {
                uint64_t privateMemory = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.PrivateMemory, sizeof(uint32_t), &privateMemory, nullptr))
                {
                    record->PrivateMemory = privateMemory != 0;
                    record->HasPrivateMemory = true;
                }
            }

            if (layout.HasCommitCharge)
            {
                ReadFieldInteger(device, record->VadAddress, layout.CommitCharge, sizeof(uint64_t), &record->CommitCharge, nullptr);
            }

            if (layout.HasNoChange)
            {
                uint64_t noChange = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.NoChange, sizeof(uint32_t), &noChange, nullptr))
                {
                    record->NoChange = noChange != 0;
                    record->HasNoChange = true;
                }
            }

            if (layout.HasLarge)
            {
                uint64_t large = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.Large, sizeof(uint32_t), &large, nullptr))
                {
                    record->LargePage = large != 0;
                    record->HasLargePage = true;
                }
            }

            if (layout.HasSubsection)
            {
                uint64_t subsection = 0;
                if (ReadFieldInteger(device, record->VadAddress, layout.Subsection, sizeof(uint64_t), &subsection, nullptr))
                {
                    record->Subsection = subsection;
                    record->HasSubsection = subsection != 0;
                    if (record->HasSubsection &&
                        layout.HasControlArea &&
                        subsection != 0)
                    {
                        uint64_t controlArea = 0;
                        if (ReadFieldInteger(
                                device,
                                subsection,
                                layout.ControlArea,
                                sizeof(uint64_t),
                                &controlArea,
                                nullptr) &&
                            controlArea != 0 &&
                            controlArea >= 0xffff800000000000ull)
                        {
                            record->ControlArea = controlArea;
                            record->HasControlArea = true;
                            if (layout.HasMappedViews)
                            {
                                uint64_t views = 0;
                                if (ReadFieldInteger(
                                        device,
                                        controlArea,
                                        layout.MappedViews,
                                        sizeof(uint32_t),
                                        &views,
                                        nullptr))
                                {
                                    record->MappedViews = static_cast<uint32_t>(views);
                                }
                            }
                            if (layout.HasFilePointer)
                            {
                                uint64_t fileRaw = 0;
                                if (ReadFieldInteger(
                                        device,
                                        controlArea,
                                        layout.FilePointer,
                                        sizeof(uint64_t),
                                        &fileRaw,
                                        nullptr))
                                {
                                    const uint64_t fileObject = fileRaw & ~0xFull;
                                    record->FileObject = fileObject;
                                    if (fileObject >= 0xffff800000000000ull && layout.HasFileName)
                                    {
                                        uint64_t nameAddress = 0;
                                        if (TryAdd(fileObject, layout.FileName.Offset, &nameAddress))
                                        {
                                            std::vector<uint8_t> header;
                                            if (device.ReadMemory(nameAddress, 16, &header, nullptr) &&
                                                header.size() >= 16)
                                            {
                                                uint16_t length = 0;
                                                uint64_t buffer = 0;
                                                memcpy(&length, header.data(), sizeof(length));
                                                memcpy(&buffer, header.data() + 8, sizeof(buffer));
                                                if (length > 0 && length <= 2048 && buffer != 0)
                                                {
                                                    std::vector<uint8_t> nameBytes;
                                                    if (device.ReadMemory(buffer, length, &nameBytes, nullptr) &&
                                                        nameBytes.size() >= 2)
                                                    {
                                                        record->SectionFileName.assign(
                                                            reinterpret_cast<const wchar_t*>(nameBytes.data()),
                                                            nameBytes.size() / sizeof(wchar_t));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!record->SectionFileName.empty())
            {
                if (!record->Notes.empty())
                {
                    record->Notes += L"; ";
                }
                record->Notes += L"section=" + record->SectionFileName;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool VadMatchesOptions(const ProcessVadRecord& record, const ProcessVadScanOptions& options)
    {
        const uint64_t executableBytes =
            record.EffectiveProtectionComplete
                ? record.EffectiveExecutableBytes
                : (record.Executable ? record.Size : 0);
        bool matched = !options.InjectionScan ||
            record.WritableExecutable ||
            (record.Executable &&
             record.HasPrivateMemory &&
             record.PrivateMemory) ||
            record.PeHeaderFound ||
            (executableBytes >= kLargeVadThreshold &&
             record.HasPrivateMemory &&
             record.PrivateMemory);

        do
        {
            if (!matched)
            {
                break;
            }

            if (options.ExecOnly && !record.Executable)
            {
                matched = false;
                break;
            }

            if (options.PrivateOnly && (!record.HasPrivateMemory || !record.PrivateMemory))
            {
                matched = false;
                break;
            }

            if (options.WxOnly && !record.WritableExecutable)
            {
                matched = false;
                break;
            }

            if (options.PeOnly && !record.PeHeaderFound)
            {
                matched = false;
                break;
            }
        } while (false);

        return matched;
    }

    void AccumulateMatchingVadRecord(
        const ProcessVadRecord& record,
        const ProcessVadScanOptions& options,
        ProcessVadScanResult* result)
    {
        if (result == nullptr ||
            !VadMatchesOptions(record, options))
        {
            return;
        }

        ++result->MatchingRecords;
        if (options.Limit == 0 ||
            result->Records.size() < options.Limit)
        {
            result->Records.push_back(record);
        }
        else
        {
            result->Truncated = true;
        }
    }

    void ClassifyVad(ProcessVadRecord* record)
    {
        do
        {
            if (record == nullptr)
            {
                break;
            }

            std::vector<std::wstring> tags;
            if (record->Executable)
            {
                tags.push_back(L"exec");
            }
            if (record->WritableExecutable)
            {
                tags.push_back(L"W+X");
            }
            if (record->CopyOnWriteExecutable)
            {
                tags.push_back(L"X+COW");
            }
            if (record->HasPrivateMemory && record->PrivateMemory)
            {
                tags.push_back(L"private");
            }
            if (record->HasPrivateMemory && record->PrivateMemory && record->Executable)
            {
                tags.push_back(L"private-exec");
            }
            uint64_t executableBytes = record->EffectiveProtectionComplete
                ? record->EffectiveExecutableBytes
                : (record->Executable ? record->Size : 0);
            if (executableBytes >= kLargeVadThreshold &&
                record->HasPrivateMemory &&
                record->PrivateMemory)
            {
                tags.push_back(L"large-private-exec");
            }
            if (record->PeHeaderFound)
            {
                tags.push_back(record->PeHeaderSuspicious ? L"PE-wiped" : L"PE");
            }

            std::wstringstream stream;
            for (size_t index = 0; index < tags.size(); ++index)
            {
                if (index != 0)
                {
                    stream << L",";
                }
                stream << tags[index];
            }

            record->Classification = stream.str();
        } while (false);
    }

    struct ThreadLayout
    {
        TypeFieldInfo ThreadListHead = {};
        TypeFieldInfo ThreadListEntry = {};
        TypeFieldInfo UniqueThread = {};
        TypeFieldInfo StartAddress = {};
        TypeFieldInfo Win32StartAddress = {};
        TypeFieldInfo Teb = {};
        TypeFieldInfo StackBase = {};
        TypeFieldInfo StackLimit = {};
        TypeFieldInfo SuspendCount = {};
        TypeFieldInfo FreezeCount = {};
        TypeFieldInfo ApcState = {};
        TypeFieldInfo ApcListHead = {};
        TypeFieldInfo KapcListEntry = {};
        TypeFieldInfo KapcKernelRoutine = {};
        TypeFieldInfo KapcRundownRoutine = {};
        TypeFieldInfo KapcNormalRoutine = {};
        TypeFieldInfo KapcNormalContext = {};
        TypeFieldInfo KapcSystemArgument1 = {};
        TypeFieldInfo KapcSystemArgument2 = {};
        bool HasUniqueThread = false;
        bool HasStartAddress = false;
        bool HasWin32StartAddress = false;
        bool HasTeb = false;
        bool HasStackBase = false;
        bool HasStackLimit = false;
        bool HasSuspendCount = false;
        bool HasFreezeCount = false;
        bool HasApcState = false;
        bool HasApcListHead = false;
        bool HasKapcLayout = false;
        std::vector<std::wstring> Warnings;
    };

    bool ResolveThreadLayout(SymbolEngine& symbols, ThreadLayout* layout, bool needApc, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                break;
            }

            *layout = ThreadLayout{};
            if (!ResolveRequiredField(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"ThreadListHead", &layout->ThreadListHead, error))
            {
                break;
            }

            if (!ResolveRequiredField(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"ThreadListEntry", &layout->ThreadListEntry, error))
            {
                break;
            }

            layout->HasUniqueThread =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"UniqueThread", &layout->UniqueThread, nullptr);
            layout->HasStartAddress =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"StartAddress", &layout->StartAddress, nullptr);
            layout->HasWin32StartAddress =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"Win32StartAddress", &layout->Win32StartAddress, nullptr);
            layout->HasTeb =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"Teb", &layout->Teb, nullptr);
            layout->HasStackBase =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"StackBase", &layout->StackBase, nullptr);
            layout->HasStackLimit =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"StackLimit", &layout->StackLimit, nullptr);
            layout->HasSuspendCount =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"SuspendCount", &layout->SuspendCount, nullptr);
            layout->HasFreezeCount =
                FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"FreezeCount", &layout->FreezeCount, nullptr);

            if (!layout->HasUniqueThread)
            {
                layout->Warnings.push_back(L"_ETHREAD.Cid.UniqueThread not found; thread IDs may be unavailable");
            }
            if (!layout->HasStartAddress && !layout->HasWin32StartAddress)
            {
                layout->Warnings.push_back(L"thread start address fields not found");
            }
            if (!layout->HasSuspendCount ||
                !layout->HasFreezeCount)
            {
                layout->Warnings.push_back(
                    L"_ETHREAD suspend/freeze layout is incomplete; "
                    L"security-process freeze detection is unavailable");
            }

            if (needApc)
            {
                layout->HasApcState =
                    FindFieldRecursive(symbols, {L"nt!_ETHREAD", L"_ETHREAD"}, L"ApcState", &layout->ApcState, nullptr);
                layout->HasApcListHead =
                    FindFieldRecursive(symbols, {L"nt!_KAPC_STATE", L"_KAPC_STATE"}, L"ApcListHead", &layout->ApcListHead, nullptr);
                layout->HasKapcLayout =
                    FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"ApcListEntry", &layout->KapcListEntry, nullptr) &&
                    FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"KernelRoutine", &layout->KapcKernelRoutine, nullptr) &&
                    FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"NormalRoutine", &layout->KapcNormalRoutine, nullptr);

                FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"RundownRoutine", &layout->KapcRundownRoutine, nullptr);
                FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"NormalContext", &layout->KapcNormalContext, nullptr);
                FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"SystemArgument1", &layout->KapcSystemArgument1, nullptr);
                FindFieldRecursive(symbols, {L"nt!_KAPC", L"_KAPC"}, L"SystemArgument2", &layout->KapcSystemArgument2, nullptr);

                if (!layout->HasApcState || !layout->HasApcListHead || !layout->HasKapcLayout)
                {
                    layout->Warnings.push_back(L"APC queue layout is incomplete; /apc will only report available evidence");
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadListEntry(DeviceClient& device, uint64_t address, uint64_t* flink, uint64_t* blink, std::wstring* error)
    {
        bool ok = false;

        do
        {
            uint64_t blinkAddress = 0;
            if (!TryAdd(address, sizeof(uint64_t), &blinkAddress))
            {
                if (error != nullptr)
                {
                    *error = L"LIST_ENTRY address overflow";
                }
                break;
            }

            if (!ReadKernelPointer(device, address, flink, error) ||
                !ReadKernelPointer(device, blinkAddress, blink, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    void ReadOptionalPointerField(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        bool hasField,
        uint64_t* value,
        bool* present)
    {
        do
        {
            if (value == nullptr || present == nullptr)
            {
                break;
            }

            *value = 0;
            *present = false;
            if (!hasField)
            {
                break;
            }

            if (ReadFieldInteger(device, base, field, sizeof(uint64_t), value, nullptr))
            {
                *present = true;
            }
        } while (false);
    }

    void AnnotateUserOrKernelAddress(
        SymbolEngine& symbols,
        const std::vector<ProcessUserModuleRange>& modules,
        uint64_t address,
        std::wstring* module,
        std::wstring* symbol)
    {
        do
        {
            if (module != nullptr)
            {
                module->clear();
            }
            if (symbol != nullptr)
            {
                symbol->clear();
            }

            const ProcessUserModuleRange* userModule = FindUserModule(modules, address);
            if (userModule != nullptr)
            {
                if (module != nullptr)
                {
                    *module = userModule->ImageName;
                }
                if (symbol != nullptr)
                {
                    std::wstringstream stream;
                    stream << userModule->ImageName << L"+0x" << std::hex << (address - userModule->Base);
                    *symbol = stream.str();
                }
                break;
            }

            if (IsKernelAddress(address))
            {
                AnnotateKernelPointer(symbols, address, module, symbol);
            }
        } while (false);
    }

    bool ReadApcEntry(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<ProcessUserModuleRange>& modules,
        bool userModuleCoverageComplete,
        const std::vector<ProcessVadRecord>& vadRecords,
        const ThreadLayout& layout,
        uint64_t listEntry,
        bool userQueue,
        ProcessApcEntryRecord* record)
    {
        bool ok = false;

        do
        {
            if (record == nullptr)
            {
                break;
            }

            *record = ProcessApcEntryRecord{};
            if (!TrySub(listEntry, layout.KapcListEntry.Offset, &record->KapcAddress))
            {
                break;
            }

            uint64_t value = 0;
            const bool kernelRoutineRead = ReadFieldInteger(
                device,
                record->KapcAddress,
                layout.KapcKernelRoutine,
                sizeof(uint64_t),
                &value,
                nullptr);
            if (kernelRoutineRead)
            {
                record->KernelRoutine = value;
                record->HasKernelRoutine = true;
                AnnotateKernelPointer(symbols, value, &record->KernelRoutineModule, &record->KernelRoutineSymbol);
                if (value != 0 && !IsKernelAddress(value))
                {
                    record->Suspicious = true;
                    record->Notes += L"kernel routine is not kernel-canonical";
                }
            }

            if (layout.KapcRundownRoutine.Name.size() > 0 &&
                ReadFieldInteger(device, record->KapcAddress, layout.KapcRundownRoutine, sizeof(uint64_t), &value, nullptr))
            {
                record->RundownRoutine = value;
                record->HasRundownRoutine = true;
            }

            const bool normalRoutineRead = ReadFieldInteger(
                device,
                record->KapcAddress,
                layout.KapcNormalRoutine,
                sizeof(uint64_t),
                &value,
                nullptr);
            if (normalRoutineRead)
            {
                record->NormalRoutine = value;
                record->HasNormalRoutine = true;
                AnnotateUserOrKernelAddress(symbols, modules, value, &record->NormalRoutineModule, nullptr);
                const ProcessVadRecord* normalVad =
                    FindVadForAddress(vadRecords, value);
                if (normalVad != nullptr)
                {
                    record->NormalRoutineVadClassification =
                        normalVad->Classification;
                    record->NormalRoutineInPrivateExecVad =
                        VadAddressIsExecutable(*normalVad, value) &&
                        normalVad->HasPrivateMemory &&
                        normalVad->PrivateMemory;
                    record->NormalRoutineInWxVad =
                        VadAddressIsWritableExecutable(*normalVad, value);
                }
                if (userQueue)
                {
                    record->UserRoutine = value;
                    record->UserRoutineSource = L"normal_routine";
                    record->UserRoutineModule =
                        record->NormalRoutineModule;
                    record->UserRoutineVadClassification =
                        record->NormalRoutineVadClassification;
                    record->UserRoutineInPrivateExecVad =
                        record->NormalRoutineInPrivateExecVad;
                    record->UserRoutineInWxVad =
                        record->NormalRoutineInWxVad;
                }
                if (value != 0 &&
                    userQueue &&
                    IsUserAddress(value) &&
                    userModuleCoverageComplete &&
                    FindUserModule(modules, value) == nullptr)
                {
                    record->Suspicious = true;
                    if (!record->Notes.empty())
                    {
                        record->Notes += L"; ";
                    }
                    record->Notes += L"user APC normal routine is outside enumerated user modules";
                }
                if (value != 0 &&
                    userQueue &&
                    (record->NormalRoutineInPrivateExecVad ||
                     record->NormalRoutineInWxVad))
                {
                    record->Suspicious = true;
                    if (!record->Notes.empty())
                    {
                        record->Notes += L"; ";
                    }
                    record->Notes += L"user APC normal routine lands in suspicious VAD";
                }
            }

            if (layout.KapcNormalContext.Name.size() > 0)
            {
                ReadFieldInteger(device, record->KapcAddress, layout.KapcNormalContext, sizeof(uint64_t), &record->NormalContext, nullptr);
            }
            if (layout.KapcSystemArgument1.Name.size() > 0)
            {
                ReadFieldInteger(device, record->KapcAddress, layout.KapcSystemArgument1, sizeof(uint64_t), &record->SystemArgument1, nullptr);
            }
            if (layout.KapcSystemArgument2.Name.size() > 0)
            {
                ReadFieldInteger(device, record->KapcAddress, layout.KapcSystemArgument2, sizeof(uint64_t), &record->SystemArgument2, nullptr);
            }

            // Current Windows builds can queue a user APC through an ntdll
            // dispatcher.  In that form KAPC.NormalRoutine belongs to ntdll
            // and the caller-supplied callback is carried in the context or
            // argument slots.  Only promote such a slot when it resolves to
            // executable memory with suspicious VAD/module provenance; plain
            // data arguments remain telemetry.
            if (userQueue &&
                EqualsNoCase(record->NormalRoutineModule, L"ntdll.dll"))
            {
                struct ApcUserRoutineCandidate
                {
                    uint64_t Address;
                    const wchar_t* Source;
                };
                const ApcUserRoutineCandidate candidates[] =
                {
                    {record->NormalContext, L"normal_context"},
                    {record->SystemArgument1, L"system_argument1"},
                    {record->SystemArgument2, L"system_argument2"}
                };

                for (const ApcUserRoutineCandidate& candidate : candidates)
                {
                    if (!IsUserAddress(candidate.Address))
                    {
                        continue;
                    }

                    const ProcessVadRecord* candidateVad =
                        FindVadForAddress(vadRecords, candidate.Address);
                    if (candidateVad == nullptr ||
                        !VadAddressIsExecutable(*candidateVad, candidate.Address))
                    {
                        continue;
                    }

                    const ProcessUserModuleRange* candidateModule =
                        FindUserModule(modules, candidate.Address);
                    bool privateExecutable =
                        candidateVad->HasPrivateMemory &&
                        candidateVad->PrivateMemory;
                    bool writableExecutable =
                        VadAddressIsWritableExecutable(
                            *candidateVad,
                            candidate.Address);
                    bool outsideModules =
                        userModuleCoverageComplete &&
                        candidateModule == nullptr;
                    if (!privateExecutable &&
                        !writableExecutable &&
                        !outsideModules)
                    {
                        continue;
                    }

                    record->UserRoutine = candidate.Address;
                    record->UserRoutineSource = candidate.Source;
                    record->UserRoutineModule =
                        candidateModule != nullptr
                            ? candidateModule->ImageName
                            : L"";
                    record->UserRoutineVadClassification =
                        candidateVad->Classification;
                    record->UserRoutineInPrivateExecVad =
                        privateExecutable;
                    record->UserRoutineInWxVad =
                        writableExecutable;
                    record->Suspicious = true;
                    if (!record->Notes.empty())
                    {
                        record->Notes += L"; ";
                    }
                    record->Notes +=
                        L"ntdll APC dispatcher carries an executable callback in " +
                        std::wstring(candidate.Source);
                    break;
                }
            }

            // Without both essential routines this entry cannot be classified
            // as benign; let the queue mark the snapshot incomplete and retry.
            ok = kernelRoutineRead && normalRoutineRead;
        } while (false);

        return ok;
    }

    ProcessApcQueueRecord ReadApcQueue(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<ProcessUserModuleRange>& modules,
        bool userModuleCoverageComplete,
        const std::vector<ProcessVadRecord>& vadRecords,
        const ThreadLayout& layout,
        uint64_t headAddress,
        const std::wstring& name,
        bool userQueue)
    {
        ProcessApcQueueRecord queue = {};
        queue.Name = name;
        queue.HeadAddress = headAddress;

        do
        {
            if (!layout.HasKapcLayout)
            {
                break;
            }

            if (!ReadListEntry(device, headAddress, &queue.Flink, &queue.Blink, nullptr) ||
                !IsValidListEntry(queue.Flink, queue.Blink))
            {
                queue.Incomplete = true;
                queue.Notes = L"APC queue head is unreadable or invalid";
                break;
            }

            queue.Present = true;
            if ((queue.Flink == headAddress) !=
                (queue.Blink == headAddress))
            {
                queue.Incomplete = true;
                queue.Notes =
                    L"APC queue empty-state links are inconsistent";
                break;
            }
            queue.NonEmpty = queue.Flink != headAddress;
            if (!queue.NonEmpty)
            {
                break;
            }

            uint64_t current = queue.Flink;
            uint64_t previous = headAddress;
            std::vector<uint64_t> visited;
            while (current != 0 && current != headAddress && queue.EntriesScanned < kMaxApcEntriesPerQueue)
            {
                if (!IsKernelAddress(current))
                {
                    queue.Incomplete = true;
                    queue.Notes = L"APC queue contains a non-kernel list pointer";
                    break;
                }
                if (std::find(visited.begin(), visited.end(), current) != visited.end())
                {
                    queue.Incomplete = true;
                    queue.Notes = L"APC queue cycle does not return to its head";
                    break;
                }

                visited.push_back(current);
                ProcessApcEntryRecord entry = {};
                if (ReadApcEntry(
                        device,
                        symbols,
                        modules,
                        userModuleCoverageComplete,
                        vadRecords,
                        layout,
                        current,
                        userQueue,
                        &entry))
                {
                    queue.Entries.push_back(entry);
                }
                else
                {
                    queue.Incomplete = true;
                    queue.Notes = L"APC entry routines could not be read";
                }

                uint64_t next = 0;
                uint64_t blink = 0;
                if (!ReadListEntry(device, current, &next, &blink, nullptr))
                {
                    queue.Incomplete = true;
                    queue.Notes = L"APC queue link could not be read";
                    break;
                }
                if (blink != previous)
                {
                    queue.Incomplete = true;
                    queue.Notes = L"APC queue backward link is inconsistent";
                    break;
                }

                previous = current;
                current = next;
                ++queue.EntriesScanned;
            }

            if (current == 0)
            {
                queue.Incomplete = true;
                queue.Notes = L"APC queue terminated at a null link";
            }
            else if (current == headAddress &&
                     previous != queue.Blink)
            {
                queue.Incomplete = true;
                queue.Notes = L"APC queue tail changed during traversal";
            }
            else if (queue.EntriesScanned >= kMaxApcEntriesPerQueue &&
                     current != headAddress)
            {
                queue.Truncated = true;
                queue.Incomplete = true;
                queue.Notes = L"APC queue hit the per-queue entry limit";
            }
        } while (false);

        return queue;
    }

    void AddUniqueText(
        std::vector<std::wstring>* values,
        const std::wstring& value)
    {
        if (values == nullptr || value.empty())
        {
            return;
        }
        if (std::find(values->begin(), values->end(), value) ==
            values->end())
        {
            values->push_back(value);
        }
    }

    std::wstring PathLeafLocal(const std::wstring& path)
    {
        const size_t separator = path.find_last_of(L"\\/");
        return separator == std::wstring::npos
            ? path
            : path.substr(separator + 1);
    }

    ProcessMappedPeRecord* FindMappedPeByBase(
        std::vector<ProcessMappedPeRecord>* records,
        uint64_t base)
    {
        if (records == nullptr || base == 0)
        {
            return nullptr;
        }
        const auto found = std::find_if(
            records->begin(),
            records->end(),
            [base](const ProcessMappedPeRecord& record)
            {
                return record.Base == base;
            });
        return found == records->end() ? nullptr : &(*found);
    }

    const ProcessVadRecord* FindVadContainingBase(
        const std::vector<ProcessVadRecord>& records,
        uint64_t base)
    {
        const auto exact = std::find_if(
            records.begin(),
            records.end(),
            [base](const ProcessVadRecord& record)
            {
                return record.StartAddress == base;
            });
        if (exact != records.end())
        {
            return &(*exact);
        }

        const auto containing = std::find_if(
            records.begin(),
            records.end(),
            [base](const ProcessVadRecord& record)
            {
                return record.StartAddress <= base &&
                    base <= record.EndAddress;
            });
        return containing == records.end() ? nullptr : &(*containing);
    }

    void ApplyPeProbeToMappedRecord(
        const PeHeaderProbe& probe,
        ProcessMappedPeRecord* record)
    {
        if (record == nullptr || !probe.IsPe)
        {
            return;
        }

        record->MemoryHeaderVisible = true;
        record->HeaderImageSize = probe.SizeOfImage;
        record->PreferredImageBase = probe.ImageBase;
        record->EntryPointRva = probe.AddressOfEntryPoint;
        record->SizeOfHeaders = probe.SizeOfHeaders;
        record->TimeDateStamp = probe.TimeDateStamp;
        record->Machine = probe.Machine;
        record->NumberOfSections = probe.NumberOfSections;
        record->Is64Bit = probe.Is64Bit;
        record->MzWiped = probe.MzWiped;
        record->PeSignatureWiped = probe.PeSignatureWiped;
        record->ELfanewMismatch = probe.ELfanewMismatch;
        AddUniqueText(&record->Sources, L"memory_header");

        if (probe.MzWiped)
        {
            AddUniqueText(&record->Reasons, L"mz_header_wiped");
            record->Suspicious = true;
        }
        if (probe.PeSignatureWiped)
        {
            AddUniqueText(&record->Reasons, L"pe_signature_wiped");
            record->Suspicious = true;
        }
        if (probe.ELfanewMismatch)
        {
            AddUniqueText(&record->Reasons, L"e_lfanew_mismatch");
            record->Suspicious = true;
        }

        if (probe.AddressOfEntryPoint == 0)
        {
            // Resource-only DLLs and data images legitimately have no entry.
            record->EntryPointValid = true;
        }
        else
        {
            uint64_t entryPoint = 0;
            record->EntryPointValid =
                probe.SizeOfImage != 0 &&
                probe.AddressOfEntryPoint < probe.SizeOfImage &&
                TryAdd(
                    record->Base,
                    probe.AddressOfEntryPoint,
                    &entryPoint);
            if (record->EntryPointValid)
            {
                record->EntryPointVa = entryPoint;
            }
            else
            {
                AddUniqueText(
                    &record->Reasons,
                    L"entry_point_outside_image");
                record->Suspicious = true;
            }
        }
    }

    void MergeVadIntoMappedRecord(
        const ProcessVadRecord& vad,
        ProcessMappedPeRecord* record)
    {
        if (record == nullptr)
        {
            return;
        }
        if (record->Base == 0)
        {
            record->Base = vad.StartAddress;
        }
        record->VadVisible = true;
        record->VadAddress = vad.VadAddress;
        record->VadStart = vad.StartAddress;
        record->VadEnd = vad.EndAddress;
        record->VadSize = vad.Size;
        record->AllocationProtection = vad.ProtectionText;
        record->EffectiveProtection = vad.EffectiveProtectionText;
        record->PrivateMapping =
            vad.HasPrivateMemory && vad.PrivateMemory;
        record->ImageBacked =
            record->ImageBacked ||
            vad.EffectiveImageMapping ||
            (vad.HasSubsection &&
             !(vad.HasPrivateMemory && vad.PrivateMemory));
        record->VirtualImageMapping =
            record->VirtualImageMapping ||
            vad.EffectiveImageMapping;
        record->Executable = vad.EffectiveProtectionComplete
            ? vad.EffectiveExecutableBytes != 0
            : vad.Executable;
        record->WritableExecutable = vad.EffectiveProtectionComplete
            ? vad.EffectiveWritableExecutableBytes != 0
            : vad.WritableExecutable;
        if (record->Base == vad.StartAddress)
        {
            record->HeaderProbeAttempted =
                record->HeaderProbeAttempted || vad.PeProbeAttempted;
            record->HeaderProbeReadSucceeded =
                record->HeaderProbeReadSucceeded ||
                vad.PeProbeReadSucceeded;
        }
        AddUniqueText(&record->Sources, L"vad");
        if (vad.EffectiveImageMapping)
        {
            AddUniqueText(
                &record->Sources,
                L"virtual_query_image");
        }
        if (vad.PeHeaderFound && record->Base == vad.StartAddress)
        {
            ApplyPeProbeToMappedRecord(vad.PeProbe, record);
        }
    }

    bool QueryMappedPath(
        HANDLE process,
        uint64_t address,
        std::wstring* path)
    {
        if (process == nullptr ||
            process == INVALID_HANDLE_VALUE ||
            address == 0 ||
            path == nullptr)
        {
            return false;
        }

        for (DWORD capacity = 512; capacity <= 32768; capacity *= 2)
        {
            std::vector<wchar_t> buffer(capacity, L'\0');
            const DWORD copied = K32GetMappedFileNameW(
                process,
                reinterpret_cast<LPVOID>(address),
                buffer.data(),
                capacity);
            if (copied == 0)
            {
                return false;
            }
            if (copied < capacity - 1)
            {
                path->assign(buffer.data(), copied);
                return true;
            }
        }
        return false;
    }

    void FinalizeMappedPeRecord(ProcessMappedPeRecord* record)
    {
        if (record == nullptr)
        {
            return;
        }
        if (record->ImageName.empty())
        {
            if (!record->ImagePath.empty())
            {
                record->ImageName = PathLeafLocal(record->ImagePath);
            }
            else if (!record->MappedPath.empty())
            {
                record->ImageName = PathLeafLocal(record->MappedPath);
            }
        }

        if (record->MemoryHeaderVisible &&
            !record->LoaderVisible)
        {
            if (record->PrivateMapping)
            {
                AddUniqueText(
                    &record->Reasons,
                    L"private_pe_without_loader_entry");
                record->Suspicious = true;
            }
            else
            {
                AddUniqueText(
                    &record->Reasons,
                    L"mapped_pe_without_loader_entry");
            }
        }
        else if (record->VirtualImageMapping &&
                 !record->LoaderVisible)
        {
            AddUniqueText(
                &record->Reasons,
                L"image_mapping_without_loader_entry");
        }
        if (record->LoaderVisible && !record->VadVisible)
        {
            AddUniqueText(
                &record->Reasons,
                L"loader_entry_without_vad_view");
        }
        if (record->LoaderVisible &&
            record->HeaderProbeReadSucceeded &&
            !record->MemoryHeaderVisible)
        {
            AddUniqueText(
                &record->Reasons,
                L"loader_entry_without_pe_header");
            record->Suspicious = true;
        }
        if (record->WritableExecutable)
        {
            AddUniqueText(
                &record->Reasons,
                L"writable_executable_mapping");
            record->Suspicious = true;
        }
    }

    bool VadBasePageCommitted(const ProcessVadRecord& record)
    {
        if (record.EffectiveProtectionComplete)
        {
            const auto range = std::find_if(
                record.EffectiveProtectionRanges.begin(),
                record.EffectiveProtectionRanges.end(),
                [&record](const ProcessVadProtectionRange& candidate)
                {
                    return candidate.StartAddress <=
                            record.StartAddress &&
                        record.StartAddress <= candidate.EndAddress;
                });
            return range != record.EffectiveProtectionRanges.end() &&
                range->Committed;
        }

        // Kernel-only / inaccessible process handles have no VirtualQueryEx
        // cross-view. Keep the conservative legacy candidates in that case.
        return record.CommitCharge != 0 ||
            record.Executable ||
            record.HasSubsection;
    }

    bool PathLooksLikePeImage(const std::wstring& path)
    {
        const std::wstring lowered = ToLowerLocal(path);
        static const wchar_t* extensions[] =
        {
            L".exe", L".dll", L".sys", L".ocx", L".cpl",
            L".scr", L".efi", L".mui", L".mun"
        };
        for (const wchar_t* extension : extensions)
        {
            if (lowered.size() >= std::wcslen(extension) &&
                lowered.compare(
                    lowered.size() - std::wcslen(extension),
                    std::wcslen(extension),
                    extension) == 0)
            {
                return true;
            }
        }
        return false;
    }

    bool ThreadTraversalHitNodeLimit(
        uint64_t threadsVisited,
        uint64_t current,
        uint64_t listHead)
    {
        return threadsVisited >= kMaxThreads &&
            current != listHead;
    }
}

bool ProcessTriageEffectiveProtectionSelfTest()
{
    ProcessTriageTarget kernelOnly = {};
    kernelOnly.ProcessId = 4;
    kernelOnly.ImageName = L"System";
    if (!IsKernelOnlyProcessTarget(kernelOnly))
    {
        return false;
    }
    kernelOnly.ProcessId = 1234;
    kernelOnly.ImageName = L"ordinary.exe";
    if (IsKernelOnlyProcessTarget(kernelOnly))
    {
        return false;
    }
    kernelOnly.ImageName = L"Registry";
    kernelOnly.HasPeb = true;
    kernelOnly.Peb = 0;
    if (!IsKernelOnlyProcessTarget(kernelOnly))
    {
        return false;
    }
    kernelOnly.Peb = 0x1000;
    if (IsKernelOnlyProcessTarget(kernelOnly))
    {
        return false;
    }

    std::vector<ProcessVadProtectionRange> ranges;
    ProcessVadProtectionRange first = {};
    first.StartAddress = 0x1000;
    first.EndAddress = 0x1fff;
    first.Protection = PAGE_EXECUTE_READ;
    first.Committed = true;
    first.Executable = true;
    if (!AppendEffectiveProtectionRange(&ranges, first))
    {
        return false;
    }

    ProcessVadProtectionRange adjacent = first;
    adjacent.StartAddress = 0x2000;
    adjacent.EndAddress = 0x2fff;
    if (!AppendEffectiveProtectionRange(&ranges, adjacent) ||
        ranges.size() != 1 ||
        ranges[0].StartAddress != 0x1000 ||
        ranges[0].EndAddress != 0x2fff)
    {
        return false;
    }

    ProcessVadProtectionRange writable = {};
    writable.StartAddress = 0x4000;
    writable.EndAddress = 0x4fff;
    writable.Protection = PAGE_EXECUTE_READWRITE;
    writable.Committed = true;
    writable.Executable = true;
    writable.Writable = true;
    writable.WritableExecutable = true;
    if (!AppendEffectiveProtectionRange(&ranges, writable))
    {
        return false;
    }

    ProcessVadRecord record = {};
    record.EffectiveProtectionRanges = ranges;
    if (FindEffectiveProtectionForAddress(record, 0x1000) == nullptr ||
        FindEffectiveProtectionForAddress(record, 0x2fff) == nullptr ||
        FindEffectiveProtectionForAddress(record, 0x3000) != nullptr ||
        FindEffectiveProtectionForAddress(record, 0x4fff) == nullptr ||
        FindEffectiveProtectionForAddress(record, 0x5000) != nullptr)
    {
        return false;
    }

    std::vector<ProcessVadProtectionRange> capped;
    capped.reserve(kMaxEffectiveProtectionRangesPerVad);
    for (size_t index = 0; index < kMaxEffectiveProtectionRangesPerVad; ++index)
    {
        ProcessVadProtectionRange range = first;
        range.StartAddress = static_cast<uint64_t>(index) * 0x2000;
        range.EndAddress = range.StartAddress + 0xfff;
        if (!AppendEffectiveProtectionRange(&capped, range))
        {
            return false;
        }
    }
    ProcessVadProtectionRange overflow = first;
    overflow.StartAddress =
        static_cast<uint64_t>(kMaxEffectiveProtectionRangesPerVad) * 0x2000;
    overflow.EndAddress = overflow.StartAddress + 0xfff;
    if (AppendEffectiveProtectionRange(&capped, overflow))
    {
        return false;
    }

    HANDLE currentProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        GetCurrentProcessId());
    FILETIME createTime = {};
    FILETIME exitTime = {};
    FILETIME kernelTime = {};
    FILETIME userTime = {};
    if (currentProcess == nullptr ||
        !GetProcessTimes(
            currentProcess,
            &createTime,
            &exitTime,
            &kernelTime,
            &userTime))
    {
        if (currentProcess != nullptr)
        {
            CloseHandle(currentProcess);
        }
        return false;
    }
    ULARGE_INTEGER observedCreate = {};
    observedCreate.LowPart = createTime.dwLowDateTime;
    observedCreate.HighPart = createTime.dwHighDateTime;
    ProcessTriageTarget currentTarget = {};
    currentTarget.ProcessId = GetCurrentProcessId();
    currentTarget.Eprocess = 1;
    currentTarget.HasCreateTime = true;
    currentTarget.CreateTime = observedCreate.QuadPart;
    const bool exactHandleAccepted =
        ProcessHandleMatchesTriageTarget(
            currentProcess,
            currentTarget);
    ++currentTarget.CreateTime;
    const bool wrongHandleRejected =
        !ProcessHandleMatchesTriageTarget(
            currentProcess,
            currentTarget);
    CloseHandle(currentProcess);
    if (!exactHandleAccepted ||
        !wrongHandleRejected)
    {
        return false;
    }

    const uint64_t listHead = 0xffff800000001000ull;
    const uint64_t anotherEntry = 0xffff800000002000ull;
    return !ThreadTraversalHitNodeLimit(
               kMaxThreads,
               listHead,
               listHead) &&
        ThreadTraversalHitNodeLimit(
            kMaxThreads,
            anotherEntry,
            listHead);
}

bool ProcessTriageVadTraversalSelfTest()
{
    const uint64_t root = 0xffff800000001000ull;
    const uint64_t unreadable =
        0xffff800000002000ull;
    const uint64_t right = 0xffff800000003000ull;
    const uint64_t leftLeaf =
        0xffff800000004000ull;
    const uint64_t rightLeaf =
        0xffff800000005000ull;
    const std::map<uint64_t, std::pair<uint64_t, uint64_t>> tree =
    {
        {root, {unreadable, right}},
        {unreadable, {leftLeaf, rightLeaf}},
        {right, {0, 0}},
        {leftLeaf, {0, 0}},
        {rightLeaf, {0, 0}}
    };

    std::vector<uint64_t> recordsVisited;
    std::vector<std::wstring> warnings;
    const VadTraversalOutcome outcome = TraverseVadNodes(
        root,
        32,
        [&tree](
            uint64_t node,
            uint64_t* left,
            uint64_t* rightChild,
            std::wstring* error)
        {
            const auto found = tree.find(node);
            if (found == tree.end() ||
                left == nullptr ||
                rightChild == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"fixture child missing";
                }
                return false;
            }
            *left = found->second.first;
            *rightChild = found->second.second;
            return true;
        },
        [&recordsVisited, unreadable](
            uint64_t node,
            uint64_t,
            uint64_t,
            std::wstring* error)
        {
            recordsVisited.push_back(node);
            if (node == unreadable)
            {
                if (error != nullptr)
                {
                    *error = L"fixture metadata unreadable";
                }
                return false;
            }
            return true;
        },
        &warnings);
    if (outcome.NodesVisited != tree.size() ||
        outcome.CoverageReliable ||
        outcome.HitLimit ||
        recordsVisited.size() != tree.size() ||
        std::find(
            recordsVisited.begin(),
            recordsVisited.end(),
            leftLeaf) == recordsVisited.end() ||
        std::find(
            recordsVisited.begin(),
            recordsVisited.end(),
            rightLeaf) == recordsVisited.end())
    {
        return false;
    }

    std::vector<uint64_t> partialChildRecords;
    std::vector<std::wstring> partialChildWarnings;
    const VadTraversalOutcome partialChild =
        TraverseVadNodes(
            root,
            32,
            [root, right](
                uint64_t node,
                uint64_t* left,
                uint64_t* rightChild,
                std::wstring* error)
            {
                *left = 0;
                *rightChild = node == root ? right : 0;
                if (node == root)
                {
                    if (error != nullptr)
                    {
                        *error = L"fixture left child unreadable";
                    }
                    return false;
                }
                return true;
            },
            [&partialChildRecords](
                uint64_t node,
                uint64_t,
                uint64_t,
                std::wstring*)
            {
                partialChildRecords.push_back(node);
                return true;
            },
            &partialChildWarnings);
    if (partialChild.NodesVisited != 2 ||
        partialChild.CoverageReliable ||
        partialChild.HitLimit ||
        std::find(
            partialChildRecords.begin(),
            partialChildRecords.end(),
            right) == partialChildRecords.end())
    {
        return false;
    }

    std::vector<std::wstring> limitWarnings;
    const VadTraversalOutcome limited = TraverseVadNodes(
        root,
        1,
        [&tree](
            uint64_t node,
            uint64_t* left,
            uint64_t* rightChild,
            std::wstring*)
        {
            const auto found = tree.find(node);
            if (found == tree.end())
            {
                return false;
            }
            *left = found->second.first;
            *rightChild = found->second.second;
            return true;
        },
        [](uint64_t, uint64_t, uint64_t, std::wstring*)
        {
            return true;
        },
        &limitWarnings);
    return limited.NodesVisited == 1 &&
        limited.HitLimit &&
        !limited.CoverageReliable;
}

bool ProcessTriageVadFilterSelfTest()
{
    ProcessVadRecord imageCow = {};
    imageCow.Executable = true;
    imageCow.CopyOnWriteExecutable = true;
    imageCow.HasPrivateMemory = true;
    imageCow.PrivateMemory = false;

    ProcessVadRecord privateRx = {};
    privateRx.StartAddress = 0x1000;
    privateRx.Executable = true;
    privateRx.HasPrivateMemory = true;
    privateRx.PrivateMemory = true;

    ProcessVadRecord privateRwx = privateRx;
    privateRwx.StartAddress = 0x2000;
    privateRwx.Writable = true;
    privateRwx.WritableExecutable = true;

    ProcessVadRecord privatePe = privateRx;
    privatePe.StartAddress = 0x3000;
    privatePe.Executable = false;
    privatePe.PeHeaderFound = true;

    ProcessVadScanOptions scan = {};
    scan.InjectionScan = true;
    if (VadMatchesOptions(imageCow, scan) ||
        !VadMatchesOptions(privateRx, scan) ||
        !VadMatchesOptions(privateRwx, scan) ||
        !VadMatchesOptions(privatePe, scan))
    {
        return false;
    }

    ProcessVadScanOptions wx = {};
    wx.WxOnly = true;
    if (VadMatchesOptions(privateRx, wx) ||
        !VadMatchesOptions(privateRwx, wx))
    {
        return false;
    }

    scan.Limit = 1;
    ProcessVadScanResult result = {};
    AccumulateMatchingVadRecord(privateRx, scan, &result);
    AccumulateMatchingVadRecord(privateRwx, scan, &result);
    AccumulateMatchingVadRecord(privatePe, scan, &result);
    if (result.MatchingRecords != 3 ||
        result.Records.size() != 1 ||
        !result.Truncated)
    {
        return false;
    }

    ProcessVadScanOptions hiddenOptions = {};
    hiddenOptions.Limit = 1;
    ProcessVadScanResult hiddenResult = {};
    PteLeafMapping firstHidden = {};
    firstHidden.StartAddress = 0x1000;
    firstHidden.EndAddress = 0x1fff;
    firstHidden.PageSize = kPageSize;
    firstHidden.Executable = true;
    firstHidden.UserAccessible = true;
    AppendHiddenPteRecord(
        hiddenOptions,
        firstHidden,
        firstHidden.StartAddress,
        firstHidden.EndAddress,
        &hiddenResult);
    PteLeafMapping secondHidden = firstHidden;
    secondHidden.StartAddress = 0x3000;
    secondHidden.EndAddress = 0x3fff;
    AppendHiddenPteRecord(
        hiddenOptions,
        secondHidden,
        secondHidden.StartAddress,
        secondHidden.EndAddress,
        &hiddenResult);
    if (hiddenResult.HiddenPteRanges != 2 ||
        hiddenResult.HiddenPteRecords.size() != 2 ||
        hiddenResult.HiddenPteTruncated)
    {
        return false;
    }
    ApplyHiddenPteOutputLimit(
        hiddenOptions,
        &hiddenResult);
    if (hiddenResult.HiddenPteRanges != 2 ||
        hiddenResult.HiddenPteRecords.size() != 1 ||
        hiddenResult.HiddenPteTruncated ||
        !hiddenResult.Truncated)
    {
        return false;
    }

    ProcessVadScanOptions mismatchOptions = {};
    mismatchOptions.HiddenPteExecutableOnly = true;
    ProcessVadScanResult mismatchResult = {};
    std::vector<VadInterval> rwIntervals;
    VadInterval rwVad = {};
    rwVad.StartAddress = 0x10000;
    rwVad.EndAddress = 0x11fff;
    rwVad.EffectiveProtectionComplete = true;
    rwVad.EffectiveExecutable = false;
    rwIntervals.push_back(rwVad);
    PteLeafMapping execPte = {};
    execPte.StartAddress = 0x10000;
    execPte.EndAddress = 0x10fff;
    execPte.PageSize = kPageSize;
    execPte.Executable = true;
    execPte.UserAccessible = true;
    size_t mismatchCursor = 0;
    ReportHiddenPteGaps(
        mismatchOptions,
        rwIntervals,
        execPte,
        &mismatchCursor,
        &mismatchResult);
    if (mismatchResult.HiddenPteRecords.size() != 1 ||
        mismatchResult.HiddenPteRecords[0].Notes != L"pte_exec_vad_rw" ||
        mismatchResult.HiddenPteRecords[0].StartAddress != 0x10000 ||
        mismatchResult.HiddenPteRecords[0].EndAddress != 0x10fff)
    {
        return false;
    }

    ProcessVadScanResult mixedResult = {};
    std::vector<VadInterval> mixedIntervals;
    VadInterval rxRange = {};
    rxRange.StartAddress = 0x20000;
    rxRange.EndAddress = 0x20fff;
    rxRange.EffectiveProtectionComplete = true;
    rxRange.EffectiveExecutable = true;
    VadInterval rwRange = {};
    rwRange.StartAddress = 0x21000;
    rwRange.EndAddress = 0x21fff;
    rwRange.EffectiveProtectionComplete = true;
    rwRange.EffectiveExecutable = false;
    mixedIntervals.push_back(rxRange);
    mixedIntervals.push_back(rwRange);
    PteLeafMapping mixedPte = {};
    mixedPte.StartAddress = 0x20000;
    mixedPte.EndAddress = 0x21fff;
    mixedPte.PageSize = kPageSize;
    mixedPte.Executable = true;
    mixedPte.UserAccessible = true;
    size_t mixedCursor = 0;
    ReportHiddenPteGaps(
        mismatchOptions,
        mixedIntervals,
        mixedPte,
        &mixedCursor,
        &mixedResult);
    if (mixedResult.HiddenPteRecords.size() != 1 ||
        mixedResult.HiddenPteRecords[0].Notes != L"pte_exec_vad_rw" ||
        mixedResult.HiddenPteRecords[0].StartAddress != 0x21000 ||
        mixedResult.HiddenPteRecords[0].EndAddress != 0x21fff)
    {
        return false;
    }

    ProcessVadScanResult pplResult = {};
    std::vector<VadInterval> pplIntervals;
    VadInterval pplRw = {};
    pplRw.StartAddress = 0x30000;
    pplRw.EndAddress = 0x30fff;
    pplRw.EffectiveProtectionComplete = false;
    pplRw.EffectiveExecutable = false;
    pplRw.HasVadProtection = true;
    pplRw.VadProtectionExecutable = false;
    pplIntervals.push_back(pplRw);
    PteLeafMapping pplPte = {};
    pplPte.StartAddress = 0x30000;
    pplPte.EndAddress = 0x30fff;
    pplPte.PageSize = kPageSize;
    pplPte.Executable = true;
    pplPte.UserAccessible = true;
    size_t pplCursor = 0;
    ReportHiddenPteGaps(
        mismatchOptions,
        pplIntervals,
        pplPte,
        &pplCursor,
        &pplResult);
    return pplResult.HiddenPteRecords.size() == 1 &&
        pplResult.HiddenPteRecords[0].Notes == L"pte_exec_vad_rw" &&
        pplResult.HiddenPteRecords[0].StartAddress == 0x30000 &&
        pplResult.HiddenPteRecords[0].EndAddress == 0x30fff;
}

bool ProcessTriageMappedPeSelfTest()
{
    ProcessVadRecord vad = {};
    vad.VadAddress = 0xffff800000001000ull;
    vad.StartAddress = 0x0000000010000000ull;
    vad.EndAddress = 0x000000001001ffffull;
    vad.Size = 0x20000;
    vad.HasPrivateMemory = true;
    vad.PrivateMemory = true;
    vad.Executable = true;
    vad.ProtectionText = L"PAGE_EXECUTE_READ";
    vad.PeProbeAttempted = true;
    vad.PeProbeReadSucceeded = true;
    vad.PeHeaderFound = true;
    vad.PeProbe.IsPe = true;
    vad.PeProbe.Is64Bit = true;
    vad.PeProbe.Machine = IMAGE_FILE_MACHINE_AMD64;
    vad.PeProbe.NumberOfSections = 3;
    vad.PeProbe.SizeOfHeaders = 0x400;
    vad.PeProbe.SizeOfImage = 0x20000;
    vad.PeProbe.AddressOfEntryPoint = 0x1234;
    vad.PeProbe.ImageBase = 0x140000000ull;
    ProcessVadProtectionRange baseRange = {};
    baseRange.StartAddress = vad.StartAddress;
    baseRange.EndAddress = vad.EndAddress;
    baseRange.Committed = true;
    vad.EffectiveProtectionComplete = true;
    vad.EffectiveProtectionRanges.push_back(baseRange);
    if (!VadBasePageCommitted(vad) ||
        !PathLooksLikePeImage(
            L"\\Device\\HarddiskVolume3\\Windows\\System32\\fixture.dll") ||
        PathLooksLikePeImage(L"C:\\fixture.dat"))
    {
        return false;
    }

    ProcessVadRecord reservedBase = vad;
    reservedBase.EffectiveProtectionRanges[0].Committed = false;
    if (VadBasePageCommitted(reservedBase))
    {
        return false;
    }

    ProcessMappedPeRecord memoryOnly = {};
    memoryOnly.Base = vad.StartAddress;
    MergeVadIntoMappedRecord(vad, &memoryOnly);
    FinalizeMappedPeRecord(&memoryOnly);
    if (!memoryOnly.MemoryHeaderVisible ||
        !memoryOnly.EntryPointValid ||
        memoryOnly.EntryPointVa != vad.StartAddress + 0x1234 ||
        !memoryOnly.Suspicious ||
        std::find(
            memoryOnly.Reasons.begin(),
            memoryOnly.Reasons.end(),
            L"private_pe_without_loader_entry") ==
            memoryOnly.Reasons.end())
    {
        return false;
    }

    ProcessMappedPeRecord loaderVisible = {};
    loaderVisible.Base = vad.StartAddress;
    loaderVisible.LoaderVisible = true;
    loaderVisible.ImagePath = L"C:\\Windows\\System32\\fixture.dll";
    AddUniqueText(&loaderVisible.Sources, L"loader");
    MergeVadIntoMappedRecord(vad, &loaderVisible);
    MergeVadIntoMappedRecord(vad, &loaderVisible);
    FinalizeMappedPeRecord(&loaderVisible);
    if (loaderVisible.Suspicious ||
        loaderVisible.ImageName != L"fixture.dll" ||
        loaderVisible.Sources.size() != 3 ||
        std::find(
            loaderVisible.Reasons.begin(),
            loaderVisible.Reasons.end(),
            L"private_pe_without_loader_entry") !=
            loaderVisible.Reasons.end())
    {
        return false;
    }

    ProcessMappedPeRecord invalidEntry = {};
    invalidEntry.Base = 0x20000000;
    PeHeaderProbe invalidProbe = vad.PeProbe;
    invalidProbe.AddressOfEntryPoint = 0x30000;
    ApplyPeProbeToMappedRecord(invalidProbe, &invalidEntry);
    if (invalidEntry.EntryPointValid ||
        !invalidEntry.Suspicious ||
        std::find(
            invalidEntry.Reasons.begin(),
            invalidEntry.Reasons.end(),
            L"entry_point_outside_image") ==
            invalidEntry.Reasons.end())
    {
        return false;
    }

    ProcessVadRecord imageVad = vad;
    imageVad.HasPrivateMemory = true;
    imageVad.PrivateMemory = false;
    imageVad.PeHeaderFound = false;
    imageVad.PeProbe = {};
    imageVad.EffectiveImageMapping = true;
    ProcessMappedPeRecord imageWithoutHeader = {};
    imageWithoutHeader.Base = imageVad.StartAddress;
    MergeVadIntoMappedRecord(
        imageVad,
        &imageWithoutHeader);
    FinalizeMappedPeRecord(&imageWithoutHeader);
    if (!imageWithoutHeader.VirtualImageMapping ||
        !imageWithoutHeader.ImageBacked ||
        imageWithoutHeader.Suspicious ||
        std::find(
            imageWithoutHeader.Sources.begin(),
            imageWithoutHeader.Sources.end(),
            L"virtual_query_image") ==
            imageWithoutHeader.Sources.end() ||
        std::find(
            imageWithoutHeader.Reasons.begin(),
            imageWithoutHeader.Reasons.end(),
            L"image_mapping_without_loader_entry") ==
            imageWithoutHeader.Reasons.end())
    {
        return false;
    }

    std::vector<ProcessMappedPeRecord> records;
    records.push_back(loaderVisible);
    if (FindMappedPeByBase(&records, vad.StartAddress) == nullptr ||
        FindMappedPeByBase(&records, 0x9999) != nullptr)
    {
        return false;
    }
    const std::vector<ProcessVadRecord> vads = {vad};
    return FindVadContainingBase(vads, vad.StartAddress + 0x1000) ==
        &vads[0];
}

ProcessTriageScanner::ProcessTriageScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool ProcessTriageScanner::ScanVad(
    const ProcessVadScanOptions& options,
    ProcessVadScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid VAD result output";
            }
            break;
        }

        *result = ProcessVadScanResult{};
        result->Target = options.Target;
        result->InjectionScan = options.InjectionScan;
        const bool kernelOnly =
            IsKernelOnlyProcessTarget(options.Target);
        result->EffectiveProtectionCoverageComplete =
            kernelOnly;
        const bool requiresEffectiveCoverage =
            !kernelOnly &&
            (options.ExecOnly ||
             options.WxOnly ||
             options.InjectionScan ||
             options.ProbeAllPe ||
             options.ProbePe ||
             options.ScanHiddenPtes);

        VadLayout layout = {};
        if (!ResolveVadLayout(symbols_, &layout, error))
        {
            break;
        }

        result->Warnings.insert(result->Warnings.end(), layout.Warnings.begin(), layout.Warnings.end());
        result->LayoutSource = L"PDB/DIA";
        result->ProtectionResolved = layout.HasProtection;
        result->PrivateMemoryResolved = layout.HasPrivateMemory;
        if (!layout.HasProtection)
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"coverage incomplete: VAD Protection field unresolved; executable/W+X classification is unavailable (not a clean empty exec set)");
        }
        if (!layout.HasPrivateMemory)
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"coverage incomplete: VAD PrivateMemory field unresolved; private-exec/PE probes are unavailable (not a clean empty private set)");
        }
        if ((options.ExecOnly ||
             options.WxOnly ||
             options.InjectionScan ||
             options.ProbeAllPe) &&
            !layout.HasProtection)
        {
            result->Warnings.push_back(L"executable/W+X filters will match no records while Protection is unresolved");
        }
        if ((options.PrivateOnly ||
             options.PeOnly ||
             options.ProbePe ||
             options.ProbeAllPe ||
             options.InjectionScan) &&
            !layout.HasPrivateMemory)
        {
            result->Warnings.push_back(L"private/PE filters and PE probes will match no records while PrivateMemory is unresolved");
        }

        std::vector<VadInterval> vadIntervals;
        uint64_t rootPointerAddress = 0;
        if (!TryAdd(options.Target.Eprocess, layout.VadRoot.Offset, &rootPointerAddress))
        {
            if (error != nullptr)
            {
                *error = L"EPROCESS.VadRoot address overflow";
            }
            break;
        }
        if (layout.HasRtlRoot && !TryAdd(rootPointerAddress, layout.RtlRoot.Offset, &rootPointerAddress))
        {
            if (error != nullptr)
            {
                *error = L"EPROCESS.VadRoot.Root address overflow";
            }
            break;
        }

        uint64_t root = 0;
        if (!ReadKernelPointer(device_, rootPointerAddress, &root, error))
        {
            break;
        }

        if (root == 0)
        {
            if (!kernelOnly)
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"coverage incomplete: user-process VAD root is empty");
            }
            if (options.ScanHiddenPtes)
            {
                if (options.RequireVadCoverageForHiddenPtes)
                {
                    result->Warnings.push_back(L"hidden PTE scan skipped: VAD root is empty");
                }
                else
                {
                    AddKnownVadlessUserMappings(&vadIntervals);
                    NormalizeVadIntervals(&vadIntervals);
                    ScanHiddenVadPtes(device_, options, vadIntervals, result);
                    ApplyHiddenPteOutputLimit(options, result);
                }
            }
            ok = true;
            break;
        }

        uint64_t dtb = TargetUserDtb(options.Target);
        HANDLE processQuery = nullptr;
        if (options.Target.ProcessId != 0 &&
            options.Target.HasCreateTime)
        {
            processQuery = OpenProcess(
                PROCESS_QUERY_INFORMATION,
                FALSE,
                options.Target.ProcessId);
            if (processQuery != nullptr)
            {
                if (!ProcessHandleMatchesTriageTarget(
                        processQuery,
                        options.Target))
                {
                    CloseHandle(processQuery);
                    processQuery = nullptr;
                }
            }
        }
        result->EffectiveProtectionCoverageComplete =
            kernelOnly || processQuery != nullptr;
        const VadTraversalOutcome traversal = TraverseVadNodes(
            root,
            kMaxVadNodes,
            [this, &layout](
                uint64_t node,
                uint64_t* left,
                uint64_t* right,
                std::wstring* readError)
            {
                return ReadVadChildPointers(
                    device_,
                    layout,
                    node,
                    left,
                    right,
                    readError);
            },
            [this,
             &layout,
              &options,
              &vadIntervals,
              processQuery,
              kernelOnly,
              dtb,
             result](
                uint64_t node,
                uint64_t left,
                uint64_t right,
                std::wstring* readError)
            {
                ProcessVadRecord record = {};
                if (!ReadVadRecord(
                        device_,
                        layout,
                        node,
                        left,
                        right,
                        &record,
                        readError))
                {
                    return false;
                }

                const bool vadProtectKnown = record.HasProtection;
                const bool vadProtectExec =
                    record.HasProtection && record.Executable;
                EnrichVadEffectiveProtection(processQuery, &record);
                if (!kernelOnly &&
                    !record.EffectiveProtectionComplete)
                {
                    result->EffectiveProtectionCoverageComplete =
                        false;
                }
                if (record.EffectiveProtectionComplete &&
                    !record.EffectiveProtectionRanges.empty())
                {
                    // Split mixed RX/RW VADs so PTE-X under an RW subrange
                    // is visible. A whole-VAD EffectiveExecutableBytes>0
                    // flag would hide those pages.
                    for (const ProcessVadProtectionRange& range :
                         record.EffectiveProtectionRanges)
                    {
                        VadInterval interval = {};
                        interval.StartAddress = range.StartAddress;
                        interval.EndAddress = range.EndAddress;
                        interval.EffectiveProtectionComplete = true;
                        interval.EffectiveExecutable =
                            range.Committed && range.Executable;
                        interval.HasVadProtection = vadProtectKnown;
                        interval.VadProtectionExecutable = vadProtectExec;
                        vadIntervals.push_back(interval);
                    }
                }
                else
                {
                    VadInterval interval = {};
                    interval.StartAddress = record.StartAddress;
                    interval.EndAddress = record.EndAddress;
                    interval.EffectiveProtectionComplete =
                        record.EffectiveProtectionComplete;
                    interval.EffectiveExecutable =
                        record.EffectiveExecutableBytes > 0;
                    interval.HasVadProtection = vadProtectKnown;
                    interval.VadProtectionExecutable = vadProtectExec;
                    vadIntervals.push_back(interval);
                }

                if (record.Executable)
                {
                    ++result->ExecutableCount;
                }
                if (record.Executable &&
                    record.HasPrivateMemory &&
                    record.PrivateMemory)
                {
                    ++result->PrivateExecutableCount;
                }
                if (record.WritableExecutable)
                {
                    ++result->WxCount;
                }

                const bool legacyPrivatePeProbe =
                    (options.ProbePe || options.PeOnly) &&
                    record.HasPrivateMemory &&
                    record.PrivateMemory;
                // NtMapViewOfSection / SEC_IMAGE implants are not
                // PrivateMemory. Probe executable or subsection VADs when
                // kmon already asked for PE probes, without walking every
                // committed mapping (ProbeAllPe).
                const bool sectionPeProbe =
                    (options.ProbePe || options.PeOnly) &&
                    (!record.HasPrivateMemory || !record.PrivateMemory) &&
                    (record.Executable ||
                        record.WritableExecutable ||
                        record.HasSubsection) &&
                    VadBasePageCommitted(record);
                // A manual mapper may initially leave an image RW or even R;
                // include committed VADs as well as executable and subsection-
                // backed mappings. Pure reservations cannot contain a mapped
                // image and are excluded to avoid meaningless read failures.
                const bool mappedPeProbe =
                    options.ProbeAllPe &&
                    VadBasePageCommitted(record);
                if ((legacyPrivatePeProbe || sectionPeProbe || mappedPeProbe) &&
                    record.StartAddress != 0 &&
                    record.Size >= kPageSize &&
                    (dtb != 0 ||
                     HasExactProcessIdentity(options.Target)))
                {
                    std::vector<uint8_t> firstPage;
                    std::wstring ignored;
                    record.PeProbeAttempted = true;
                    if (ReadTargetProcessMemory(
                            device_,
                            options.Target,
                            dtb,
                            record.StartAddress,
                            static_cast<uint32_t>(kPageSize),
                            &firstPage,
                            &ignored))
                    {
                        record.PeProbeReadSucceeded = true;
                        if (ProbeForPeHeader(
                                firstPage.data(),
                                firstPage.size(),
                                &record.PeProbe))
                        {
                            record.PeHeaderFound =
                                record.PeProbe.IsPe;
                            record.PeHeaderSuspicious =
                                record.PeProbe.MzWiped ||
                                record.PeProbe.PeSignatureWiped ||
                                record.PeProbe.ELfanewMismatch;
                        }
                    }
                }

                if (record.PeHeaderFound)
                {
                    ++result->PeLikeCount;
                }

                ClassifyVad(&record);
                const uint64_t executableBytes =
                    record.EffectiveProtectionComplete
                        ? record.EffectiveExecutableBytes
                        : (record.Executable ? record.Size : 0);
                const bool suspicious =
                    record.WritableExecutable ||
                    (record.Executable &&
                     record.HasPrivateMemory &&
                     record.PrivateMemory) ||
                    record.PeHeaderFound ||
                    (executableBytes >= kLargeVadThreshold &&
                     record.HasPrivateMemory &&
                     record.PrivateMemory);
                if (suspicious)
                {
                    ++result->SuspiciousCount;
                }

                ++result->TotalRecords;
                AccumulateMatchingVadRecord(
                    record,
                    options,
                    result);
                return true;
            },
            &result->Warnings);
        result->NodesVisited = traversal.NodesVisited;
        const bool vadTraversalHitLimit = traversal.HitLimit;
        const bool vadCoverageReliable = traversal.CoverageReliable;
        if (processQuery != nullptr)
        {
            CloseHandle(processQuery);
            processQuery = nullptr;
        }

        if (vadTraversalHitLimit)
        {
            result->Truncated = true;
            result->Warnings.push_back(L"VAD traversal hit the node limit");
        }

        if (!vadCoverageReliable)
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"coverage incomplete: VAD traversal had unreadable/poisoned nodes, cycles, or a node-limit stop");
        }

        if (requiresEffectiveCoverage &&
            !result->EffectiveProtectionCoverageComplete)
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"coverage incomplete: one or more VADs lack a complete exact-process VirtualQueryEx view");
        }

        if (options.ScanHiddenPtes)
        {
            if (vadTraversalHitLimit)
            {
                result->Warnings.push_back(L"hidden PTE scan is lower confidence because VAD coverage hit the traversal limit");
            }
            if (options.RequireVadCoverageForHiddenPtes && (!vadCoverageReliable || vadIntervals.empty()))
            {
                result->Warnings.push_back(L"hidden PTE scan skipped: VAD coverage is incomplete");
            }
            else
            {
                AddKnownVadlessUserMappings(&vadIntervals);
                NormalizeVadIntervals(&vadIntervals);
                ScanHiddenVadPtes(device_, options, vadIntervals, result);
                ApplyHiddenPteOutputLimit(options, result);
            }
        }

        if (result->HiddenPteTruncated)
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"coverage incomplete: hidden PTE scan hit the record limit");
        }

        ok = true;
    } while (false);

    return ok;
}

bool ProcessTriageScanner::ScanMappedPe(
    const ProcessMappedPeScanOptions& options,
    ProcessMappedPeScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid mapped PE result output";
            }
            break;
        }
        *result = ProcessMappedPeScanResult{};
        result->Target = options.Target;

        if (options.Target.Eprocess == 0)
        {
            if (error != nullptr)
            {
                *error = L"mapped PE scan requires a resolved EPROCESS";
            }
            break;
        }

        ProcessVadScanOptions vadOptions = {};
        vadOptions.Target = options.Target;
        vadOptions.ProbeAllPe = true;
        ProcessVadScanResult vadResult = {};
        std::wstring vadError;
        if (!ScanVad(vadOptions, &vadResult, &vadError))
        {
            if (error != nullptr)
            {
                *error = L"mapped PE VAD scan failed: " + vadError;
            }
            break;
        }

        result->VadNodesVisited = vadResult.NodesVisited;
        result->VadRecords = vadResult.TotalRecords;
        result->VadCoverageComplete =
            vadResult.CoverageComplete &&
            vadResult.EffectiveProtectionCoverageComplete &&
            !vadResult.Truncated;
        result->HeaderProbeCoverageComplete =
            result->VadCoverageComplete;
        result->Warnings = vadResult.Warnings;

        uint64_t failedVadHeaderProbes = 0;
        for (const ProcessVadRecord& vad : vadResult.Records)
        {
            const bool probeEligible =
                VadBasePageCommitted(vad);
            if (probeEligible &&
                (!vad.PeProbeAttempted ||
                 !vad.PeProbeReadSucceeded))
            {
                ++failedVadHeaderProbes;
                result->HeaderProbeCoverageComplete = false;
            }

            if (!vad.PeHeaderFound)
            {
                continue;
            }

            ProcessMappedPeRecord record = {};
            record.Base = vad.StartAddress;
            MergeVadIntoMappedRecord(vad, &record);
            result->Records.push_back(std::move(record));
        }
        if (failedVadHeaderProbes != 0)
        {
            result->Warnings.push_back(
                L"mapped PE header probe could not read " +
                std::to_wstring(failedVadHeaderProbes) +
                L" committed/executable/section-backed VAD base(s)");
        }

        const bool kernelOnly =
            IsKernelOnlyProcessTarget(options.Target);
        std::vector<ProcessUserModuleRange> modules;
        if (kernelOnly)
        {
            result->LoaderCoverageComplete = true;
        }
        else if (options.Target.ProcessId == 0)
        {
            result->Warnings.push_back(
                L"loader module enumeration unavailable: target PID is unresolved");
        }
        else
        {
            HANDLE identityHandle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                options.Target.ProcessId);
            const bool identityMatched =
                identityHandle != nullptr &&
                ProcessHandleMatchesTriageTarget(
                    identityHandle,
                    options.Target);
            if (!identityMatched)
            {
                result->Warnings.push_back(
                    L"loader module enumeration skipped: exact target identity is no longer active");
            }
            else
            {
                std::wstring moduleWarning;
                result->LoaderCoverageComplete =
                    EnumerateUserModules(
                        options.Target.ProcessId,
                        &modules,
                        &moduleWarning);
                if (result->LoaderCoverageComplete &&
                    !ProcessHandleMatchesTriageTarget(
                        identityHandle,
                        options.Target))
                {
                    modules.clear();
                    result->LoaderCoverageComplete = false;
                    moduleWarning =
                        L"target exited while loader modules were enumerated";
                }
                if (!result->LoaderCoverageComplete)
                {
                    result->Warnings.push_back(
                        moduleWarning.empty()
                            ? L"loader module enumeration failed"
                            : moduleWarning);
                }
            }
            if (identityHandle != nullptr)
            {
                CloseHandle(identityHandle);
            }
        }
        result->LoaderRecords = modules.size();

        const uint64_t dtb = TargetUserDtb(options.Target);
        for (const ProcessUserModuleRange& module : modules)
        {
            ProcessMappedPeRecord* record =
                FindMappedPeByBase(&result->Records, module.Base);
            if (record == nullptr)
            {
                ProcessMappedPeRecord created = {};
                created.Base = module.Base;
                result->Records.push_back(std::move(created));
                record = &result->Records.back();
            }

            record->LoaderVisible = true;
            record->LoaderSize = module.Size;
            record->ImageName = module.ImageName;
            record->ImagePath = module.ImagePath;
            AddUniqueText(&record->Sources, L"loader");

            const ProcessVadRecord* containingVad =
                FindVadContainingBase(vadResult.Records, module.Base);
            if (containingVad != nullptr)
            {
                MergeVadIntoMappedRecord(*containingVad, record);
            }

            if (!record->HeaderProbeReadSucceeded)
            {
                record->HeaderProbeAttempted = true;
                std::vector<uint8_t> firstPage;
                std::wstring readError;
                if (ReadTargetProcessMemory(
                        device_,
                        options.Target,
                        dtb,
                        module.Base,
                        static_cast<uint32_t>(kPageSize),
                        &firstPage,
                        &readError))
                {
                    record->HeaderProbeReadSucceeded = true;
                    PeHeaderProbe probe = {};
                    if (ProbeForPeHeader(
                            firstPage.data(),
                            firstPage.size(),
                            &probe))
                    {
                        ApplyPeProbeToMappedRecord(probe, record);
                    }
                }
                else
                {
                    result->HeaderProbeCoverageComplete = false;
                    result->Warnings.push_back(
                        L"loader module header read failed at " +
                        Hex(module.Base, 16) +
                        (module.ImageName.empty()
                            ? L""
                            : L" (" + module.ImageName + L")") +
                        (readError.empty()
                            ? L""
                            : L": " + readError));
                }
            }
        }

        HANDLE process = nullptr;
        if (kernelOnly)
        {
            result->MappedPathCoverageComplete = true;
        }
        else if (options.Target.ProcessId != 0 &&
                 options.Target.HasCreateTime)
        {
            process = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                options.Target.ProcessId);
            if (process != nullptr &&
                ProcessHandleMatchesTriageTarget(
                    process,
                    options.Target))
            {
                result->MappedPathCoverageComplete = true;
            }
            else
            {
                if (process != nullptr)
                {
                    CloseHandle(process);
                    process = nullptr;
                }
                result->Warnings.push_back(
                    L"mapped-file path view unavailable for the exact target identity");
            }
        }
        else
        {
            result->Warnings.push_back(
                L"mapped-file path view unavailable: exact PID/create-time identity is unresolved");
        }

        // Query every VAD base, not only records already found through a PE
        // header or loader entry. This retains loader-invisible SEC_IMAGE and
        // mapped PE files whose header page is intentionally decommitted.
        uint64_t imageMappingPathFailures = 0;
        if (process != nullptr)
        {
            for (const ProcessVadRecord& vad : vadResult.Records)
            {
                std::wstring mappedPath;
                const bool mappedPathFound =
                    QueryMappedPath(
                        process,
                        vad.StartAddress,
                        &mappedPath);
                const bool imageMapping =
                    vad.EffectiveImageMapping;
                const bool pathIdentifiesPe =
                    mappedPathFound &&
                    PathLooksLikePeImage(mappedPath);
                if (!imageMapping && !pathIdentifiesPe)
                {
                    continue;
                }

                ProcessMappedPeRecord* record =
                    FindMappedPeByBase(
                        &result->Records,
                        vad.StartAddress);
                if (record == nullptr)
                {
                    ProcessMappedPeRecord created = {};
                    created.Base = vad.StartAddress;
                    result->Records.push_back(std::move(created));
                    record = &result->Records.back();
                }
                MergeVadIntoMappedRecord(vad, record);
                if (mappedPathFound)
                {
                    record->MappedPath = mappedPath;
                    record->MappedPathVisible = true;
                    AddUniqueText(
                        &record->Sources,
                        L"mapped_path");
                }
            }
        }
        for (ProcessMappedPeRecord& record : result->Records)
        {
            if (process != nullptr &&
                !record.MappedPathVisible)
            {
                std::wstring mappedPath;
                if (QueryMappedPath(process, record.Base, &mappedPath))
                {
                    record.MappedPath = mappedPath;
                    record.MappedPathVisible = true;
                    AddUniqueText(&record.Sources, L"mapped_path");
                }
            }
            if (record.VirtualImageMapping &&
                !record.MappedPathVisible)
            {
                ++imageMappingPathFailures;
                result->MappedPathCoverageComplete = false;
            }
            FinalizeMappedPeRecord(&record);
        }
        if (imageMappingPathFailures != 0)
        {
            result->Warnings.push_back(
                L"mapped-file path query failed for " +
                std::to_wstring(imageMappingPathFailures) +
                L" MEM_IMAGE VAD base(s)");
        }
        if (process != nullptr)
        {
            CloseHandle(process);
            process = nullptr;
        }

        std::sort(
            result->Records.begin(),
            result->Records.end(),
            [](const ProcessMappedPeRecord& left,
               const ProcessMappedPeRecord& right)
            {
                return left.Base < right.Base;
            });

        result->CandidateMappings = result->Records.size();
        for (const ProcessMappedPeRecord& record : result->Records)
        {
            if (record.MemoryHeaderVisible)
            {
                ++result->HeaderVisibleRecords;
            }
            if (record.LoaderVisible)
            {
                ++result->LoaderVisibleRecords;
            }
            if (record.MemoryHeaderVisible &&
                !record.LoaderVisible)
            {
                ++result->MemoryOnlyRecords;
            }
            if (record.PrivateMapping)
            {
                ++result->PrivateRecords;
            }
            if (record.Suspicious)
            {
                ++result->SuspiciousRecords;
            }
        }

        result->CoverageComplete =
            result->VadCoverageComplete &&
            result->LoaderCoverageComplete &&
            result->HeaderProbeCoverageComplete &&
            result->MappedPathCoverageComplete;
        result->Incomplete = !result->CoverageComplete;

        if (options.Limit != 0 &&
            result->Records.size() > options.Limit)
        {
            result->Records.resize(options.Limit);
            result->Truncated = true;
        }

        ok = true;
    } while (false);

    return ok;
}

bool ProcessTriageScanner::ScanThreads(
    const ProcessThreadScanOptions& options,
    ProcessThreadScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid thread result output";
            }
            break;
        }

        *result = ProcessThreadScanResult{};
        result->Target = options.Target;

        ThreadLayout layout = {};
        if (!ResolveThreadLayout(symbols_, &layout, options.IncludeApc, error))
        {
            break;
        }

        result->Warnings.insert(result->Warnings.end(), layout.Warnings.begin(), layout.Warnings.end());
        result->LayoutSource = L"PDB/DIA";
        const bool suspensionLayoutComplete =
            layout.HasSuspendCount &&
            layout.HasFreezeCount;
        if ((!layout.HasStartAddress &&
             !layout.HasWin32StartAddress) ||
            (options.IncludeApc &&
             (!layout.HasApcState ||
              !layout.HasApcListHead ||
              !layout.HasKapcLayout)))
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
        }

        std::vector<ProcessUserModuleRange> userModules =
            options.UserModules;
        bool userModuleCoverageComplete =
            options.UserModuleEnumerationComplete ||
            IsKernelOnlyProcessTarget(options.Target);
        std::wstring moduleWarning;
        if (!userModuleCoverageComplete)
        {
            std::vector<ProcessUserModuleRange> toolhelpModules;
            if (EnumerateUserModules(
                    options.Target.ProcessId,
                    &toolhelpModules,
                    &moduleWarning))
            {
                MergeUserModuleRanges(
                    &userModules,
                    toolhelpModules);
                userModuleCoverageComplete = true;
            }
            else
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
                if (!moduleWarning.empty())
                {
                    result->Warnings.push_back(
                        moduleWarning);
                }
            }
        }

        std::vector<ProcessVadRecord> vadRecords;
        ProcessVadScanResult vadResult = {};
        ProcessVadScanOptions vadOptions = {};
        vadOptions.Target = options.Target;
        // Stack provenance needs the same PE/header classification used by
        // hunt VAD triage.  Without it, a stack reference to a private
        // PE-like RX page is indistinguishable from an ordinary JIT page.
        vadOptions.ProbePe = options.IncludeStacks;
        if (ScanVad(vadOptions, &vadResult, nullptr))
        {
            vadRecords = vadResult.Records;
            if (vadResult.Truncated ||
                vadResult.Incomplete ||
                !vadResult.CoverageComplete)
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"VAD correlation coverage is incomplete for thread classification");
            }
        }
        else
        {
            result->Warnings.push_back(L"VAD correlation unavailable for thread-start classification");
            result->Incomplete = true;
            result->CoverageComplete = false;
        }

        uint64_t userDtb = TargetUserDtb(options.Target);

        uint64_t listHead = 0;
        if (!TryAdd(options.Target.Eprocess, layout.ThreadListHead.Offset, &listHead))
        {
            if (error != nullptr)
            {
                *error = L"ThreadListHead address overflow";
            }
            break;
        }

        uint64_t current = 0;
        uint64_t headBlink = 0;
        if (!ReadListEntry(device_, listHead, &current, &headBlink, error))
        {
            break;
        }
        if (!IsKernelAddress(current) ||
            !IsKernelAddress(headBlink) ||
            ((current == listHead) !=
             (headBlink == listHead)))
        {
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"thread list head links are invalid or inconsistent");
            ok = true;
            break;
        }

        std::vector<uint64_t> visited;
        uint64_t previous = listHead;
        bool threadListLinkFailure = false;
        while (current != 0 && current != listHead && result->ThreadsVisited < kMaxThreads)
        {
            if (!IsKernelAddress(current))
            {
                result->Warnings.push_back(L"thread list entry is not kernel-canonical: " + Hex(current, 16));
                result->Incomplete = true;
                result->CoverageComplete = false;
                threadListLinkFailure = true;
                break;
            }

            if (std::find(visited.begin(), visited.end(), current) != visited.end())
            {
                result->Warnings.push_back(L"thread list cycle detected at " + Hex(current, 16));
                result->Incomplete = true;
                result->CoverageComplete = false;
                threadListLinkFailure = true;
                break;
            }
            visited.push_back(current);

            uint64_t ethread = 0;
            if (!TrySub(current, layout.ThreadListEntry.Offset, &ethread))
            {
                result->Warnings.push_back(L"ETHREAD address underflow at " + Hex(current, 16));
                result->Incomplete = true;
                result->CoverageComplete = false;
                threadListLinkFailure = true;
                break;
            }

            ProcessThreadRecord record = {};
            record.Ethread = ethread;
            record.ListEntry = current;

            uint64_t value = 0;
            if (layout.HasUniqueThread && ReadFieldInteger(device_, ethread, layout.UniqueThread, sizeof(uint64_t), &value, nullptr))
            {
                record.ThreadId = value;
                record.HasThreadId = true;
            }
            if (layout.HasStartAddress && ReadFieldInteger(device_, ethread, layout.StartAddress, sizeof(uint64_t), &value, nullptr))
            {
                record.StartAddress = value;
                record.HasStartAddress = true;
                AnnotateUserOrKernelAddress(symbols_, userModules, value, &record.StartModule, &record.StartSymbol);
            }
            if (layout.HasWin32StartAddress && ReadFieldInteger(device_, ethread, layout.Win32StartAddress, sizeof(uint64_t), &value, nullptr))
            {
                record.Win32StartAddress = value;
                record.HasWin32StartAddress = true;
                AnnotateUserOrKernelAddress(symbols_, userModules, value, &record.Win32StartModule, nullptr);
            }
            ReadOptionalPointerField(device_, ethread, layout.Teb, layout.HasTeb, &record.Teb, &record.HasTeb);
            ReadOptionalPointerField(device_, ethread, layout.StackBase, layout.HasStackBase, &record.StackBase, &record.HasStackBounds);
            bool hasStackLimit = false;
            ReadOptionalPointerField(device_, ethread, layout.StackLimit, layout.HasStackLimit, &record.StackLimit, &hasStackLimit);
            record.HasStackBounds = record.HasStackBounds && hasStackLimit;

            if (layout.HasSuspendCount &&
                ReadFieldInteger(
                    device_,
                    ethread,
                    layout.SuspendCount,
                    sizeof(uint8_t),
                    &value,
                    nullptr))
            {
                record.SuspendCount =
                    static_cast<uint32_t>(value);
                record.HasSuspendCount = true;
            }
            if (layout.HasFreezeCount &&
                ReadFieldInteger(
                    device_,
                    ethread,
                    layout.FreezeCount,
                    sizeof(uint8_t),
                    &value,
                    nullptr))
            {
                record.FreezeCount =
                    static_cast<uint32_t>(value);
                record.HasFreezeCount = true;
            }
            const bool suspensionStateResolved =
                suspensionLayoutComplete &&
                record.HasSuspendCount &&
                record.HasFreezeCount;
            if (suspensionStateResolved)
            {
                ++result->SuspensionStateResolvedCount;
                if (record.SuspendCount != 0 ||
                    record.FreezeCount != 0)
                {
                    ++result->SuspendedThreadCount;
                }
            }

            if (options.IncludeStacks &&
                (userDtb != 0 ||
                 HasExactProcessIdentity(options.Target)))
            {
                if (ReadUserStackBoundsFromTeb(
                        device_,
                        options.Target,
                        userDtb,
                        &record))
                {
                    ScanUserStackReferences(
                        device_,
                        options.Target,
                        userModules,
                        userModuleCoverageComplete,
                        vadRecords,
                        userDtb,
                        &record);
                    result->StackReferenceCount += record.StackReferences.size();
                }
            }

            uint64_t classifyAddress = record.HasWin32StartAddress && record.Win32StartAddress != 0
                ? record.Win32StartAddress
                : record.StartAddress;
            const ProcessUserModuleRange* module = FindUserModule(userModules, classifyAddress);
            record.StartInUserModule = module != nullptr;
            const ProcessVadRecord* containingVad = FindVadForAddress(vadRecords, classifyAddress);
            if (containingVad != nullptr)
            {
                record.VadClassification = containingVad->Classification;
                record.StartInPrivateExecVad =
                    VadAddressIsExecutable(*containingVad, classifyAddress) &&
                    containingVad->HasPrivateMemory &&
                    containingVad->PrivateMemory;
                record.StartInWxVad =
                    VadAddressIsWritableExecutable(
                        *containingVad,
                        classifyAddress);
            }

            if (IsUserAddress(classifyAddress))
            {
                if (userModuleCoverageComplete &&
                    !record.StartInUserModule)
                {
                    record.SuspiciousStart = true;
                    record.Notes += L"user start is outside enumerated modules";
                }
                if (record.StartInPrivateExecVad || record.StartInWxVad)
                {
                    record.SuspiciousStart = true;
                    if (!record.Notes.empty())
                    {
                        record.Notes += L"; ";
                    }
                    record.Notes += L"user start lands in suspicious VAD";
                }
            }
            else if (classifyAddress != 0 && !IsKernelAddress(classifyAddress))
            {
                record.SuspiciousStart = true;
                record.Notes += L"start address is not canonical";
            }

            if (options.IncludeApc && layout.HasApcState && layout.HasApcListHead)
            {
                uint64_t apcState = 0;
                if (TryAdd(ethread, layout.ApcState.Offset, &apcState))
                {
                    uint64_t base = 0;
                    uint64_t userHead = 0;
                    if (!TryAdd(
                            apcState,
                            layout.ApcListHead.Offset,
                            &base) ||
                        !TryAdd(
                            base,
                            sizeof(uint64_t) * 2,
                            &userHead))
                    {
                        result->Incomplete = true;
                        result->CoverageComplete = false;
                        result->Warnings.push_back(
                            L"APC queue head address overflow for thread " +
                            Hex(ethread, 16));
                    }
                    else
                    {
                    record.ApcQueues.push_back(ReadApcQueue(
                        device_,
                        symbols_,
                        userModules,
                        userModuleCoverageComplete,
                        vadRecords,
                        layout,
                        base,
                        L"kernel",
                        false));
                    record.ApcQueues.push_back(ReadApcQueue(
                        device_,
                        symbols_,
                        userModules,
                        userModuleCoverageComplete,
                        vadRecords,
                        layout,
                        userHead,
                        L"user",
                        true));
                    for (const ProcessApcQueueRecord& queue : record.ApcQueues)
                    {
                        if (queue.NonEmpty)
                        {
                            ++result->ApcNonEmptyCount;
                        }
                        if (queue.Incomplete || queue.Truncated)
                        {
                            result->Incomplete = true;
                            result->CoverageComplete = false;
                            result->Warnings.push_back(
                                L"thread " + Hex(ethread, 16) +
                                L" " + queue.Name +
                                L" APC queue incomplete: " +
                                queue.Notes);
                        }
                    }
                    }
                }
                else
                {
                    result->Incomplete = true;
                    result->CoverageComplete = false;
                    result->Warnings.push_back(
                        L"APC state address overflow for thread " +
                        Hex(ethread, 16));
                }
            }

            if (record.SuspiciousStart)
            {
                ++result->SuspiciousStartCount;
            }

            if (options.Limit == 0 || result->Records.size() < options.Limit)
            {
                result->Records.push_back(record);
            }
            else
            {
                result->Truncated = true;
            }

            ++result->MatchingRecords;
            ++result->ThreadsVisited;

            uint64_t next = 0;
            uint64_t blink = 0;
            if (!ReadListEntry(device_, current, &next, &blink, nullptr))
            {
                result->Warnings.push_back(L"failed to read next thread list entry at " + Hex(current, 16));
                result->Incomplete = true;
                result->CoverageComplete = false;
                threadListLinkFailure = true;
                break;
            }
            if (blink != previous)
            {
                result->Warnings.push_back(
                    L"thread list backward link is inconsistent at " +
                    Hex(current, 16));
                result->Incomplete = true;
                result->CoverageComplete = false;
                threadListLinkFailure = true;
                break;
            }
            previous = current;
            current = next;
        }

        if (!threadListLinkFailure)
        {
            if (current == 0)
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"thread list terminated at a null link");
            }
            else if (current == listHead &&
                     previous != headBlink)
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"thread list tail changed during traversal");
            }
        }

        const bool threadTraversalHitNodeLimit =
            ThreadTraversalHitNodeLimit(
                result->ThreadsVisited,
                current,
                listHead);
        if (threadTraversalHitNodeLimit)
        {
            result->Truncated = true;
            result->Incomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(L"thread traversal hit the node limit");
        }

        result->InventoryComplete =
            !threadListLinkFailure &&
            !threadTraversalHitNodeLimit &&
            current == listHead &&
            previous == headBlink;
        result->SuspensionStateCoverageComplete =
            suspensionLayoutComplete &&
            result->InventoryComplete &&
            !result->Truncated &&
            result->SuspensionStateResolvedCount ==
                result->ThreadsVisited;
        if (!result->SuspensionStateCoverageComplete)
        {
            result->Warnings.push_back(
                L"thread suspend/freeze state coverage is incomplete");
            if (options.RequireSuspensionCoverage)
            {
                result->Incomplete = true;
                result->CoverageComplete = false;
            }
        }

        if (result->Incomplete)
        {
            result->CoverageComplete = false;
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildProcessVadJson(const ProcessVadScanResult& result)
{
    std::wstringstream json;
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.vad.v1\",\n";
    json << L"  \"mode\":\""
         << (result.InjectionScan ? L"scan" : L"list")
         << L"\",\n";
    json << L"  \"target\":{\"pid\":" << result.Target.ProcessId
         << L",\"image\":\"" << JsonEscape(result.Target.ImageName)
         << L"\",\"eprocess\":\"" << Hex(result.Target.Eprocess, 16) << L"\"},\n";
    json << L"  \"summary\":{\"nodes_visited\":" << result.NodesVisited
         << L",\"total_records\":" << result.TotalRecords
         << L",\"matching_records\":" << result.MatchingRecords
         << L",\"executable\":" << result.ExecutableCount
         << L",\"private_executable\":" << result.PrivateExecutableCount
         << L",\"wx\":" << result.WxCount
         << L",\"pe_like\":" << result.PeLikeCount
         << L",\"suspicious\":" << result.SuspiciousCount
         << L",\"hidden_pte_ranges\":" << result.HiddenPteRanges
         << L",\"hidden_pte_bytes\":" << result.HiddenPteBytes
         << L",\"pte_leaf_mappings\":" << result.PteLeafMappings
         << L",\"page_table_pages_read\":" << result.PageTablePagesRead
         << L",\"page_table_read_failures\":" << result.PageTableReadFailures
         << L",\"injection_scan\":" << (result.InjectionScan ? L"true" : L"false")
         << L",\"hidden_pte_scan_enabled\":" << (result.HiddenPteScanEnabled ? L"true" : L"false")
         << L",\"hidden_pte_truncated\":" << (result.HiddenPteTruncated ? L"true" : L"false")
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false")
         << L",\"protection_resolved\":" << (result.ProtectionResolved ? L"true" : L"false")
         << L",\"private_memory_resolved\":" << (result.PrivateMemoryResolved ? L"true" : L"false")
         << L",\"effective_protection_coverage_complete\":" << (result.EffectiveProtectionCoverageComplete ? L"true" : L"false")
         << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false")
         << L",\"incomplete\":" << (result.Incomplete ? L"true" : L"false") << L"},\n";
    json << L"  \"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << JsonEscape(result.Warnings[i]) << L"\"";
    }
    json << L"],\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ProcessVadRecord& r = result.Records[i];
        json << L"    {\"vad\":\"" << Hex(r.VadAddress, 16)
             << L"\",\"node\":\"" << Hex(r.NodeAddress, 16)
             << L"\",\"start\":\"" << Hex(r.StartAddress, 16)
             << L"\",\"end\":\"" << Hex(r.EndAddress, 16)
             << L"\",\"size\":" << r.Size
             << L",\"protection\":\"" << JsonEscape(r.ProtectionText)
             << L"\",\"executable\":" << (r.Executable ? L"true" : L"false")
             << L",\"writable\":" << (r.Writable ? L"true" : L"false")
             << L",\"writable_executable\":" << (r.WritableExecutable ? L"true" : L"false")
             << L",\"copy_on_write\":" << (r.CopyOnWrite ? L"true" : L"false")
             << L",\"copy_on_write_executable\":" << (r.CopyOnWriteExecutable ? L"true" : L"false")
             << L",\"effective_protection_queried\":" << (r.EffectiveProtectionQueried ? L"true" : L"false")
             << L",\"effective_protection_complete\":" << (r.EffectiveProtectionComplete ? L"true" : L"false")
             << L",\"effective_image_mapping\":" << (r.EffectiveImageMapping ? L"true" : L"false")
             << L",\"effective_protection\":\"" << JsonEscape(r.EffectiveProtectionText)
             << L"\",\"effective_committed_bytes\":" << r.EffectiveCommittedBytes
             << L",\"effective_executable_bytes\":" << r.EffectiveExecutableBytes
             << L",\"effective_writable_bytes\":" << r.EffectiveWritableBytes
             << L",\"effective_copy_on_write_bytes\":" << r.EffectiveCopyOnWriteBytes
             << L",\"effective_wx_bytes\":" << r.EffectiveWritableExecutableBytes
             << L",\"effective_x_cow_bytes\":" << r.EffectiveCopyOnWriteExecutableBytes
             << L",\"private\":" << (r.HasPrivateMemory && r.PrivateMemory ? L"true" : L"false")
              << L",\"commit_charge\":" << r.CommitCharge
              << L",\"pe_probe_attempted\":" << (r.PeProbeAttempted ? L"true" : L"false")
              << L",\"pe_probe_read_succeeded\":" << (r.PeProbeReadSucceeded ? L"true" : L"false")
              << L",\"pe_like\":" << (r.PeHeaderFound ? L"true" : L"false")
              << L",\"pe_suspicious\":" << (r.PeHeaderSuspicious ? L"true" : L"false")
             << L",\"classification\":\"" << JsonEscape(r.Classification)
             << L"\"}";
        if (i + 1 != result.Records.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ],\n";
    json << L"  \"hidden_pte_records\":[\n";
    for (size_t i = 0; i < result.HiddenPteRecords.size(); ++i)
    {
        const ProcessHiddenVadPteRecord& r = result.HiddenPteRecords[i];
        json << L"    {\"start\":\"" << Hex(r.StartAddress, 16)
             << L"\",\"end\":\"" << Hex(r.EndAddress, 16)
             << L"\",\"size\":" << r.Size
             << L",\"page_size\":" << r.PageSize
             << L",\"page_count\":" << r.PageCount
             << L",\"physical\":\"" << Hex(r.PhysicalAddress, 16)
             << L"\",\"leaf_entry_address\":\"" << Hex(r.LeafEntryAddress, 16)
             << L"\",\"leaf_entry\":\"" << Hex(r.LeafEntry, 16)
             << L"\",\"writable\":" << (r.Writable ? L"true" : L"false")
             << L",\"executable\":" << (r.Executable ? L"true" : L"false")
             << L",\"user_accessible\":" << (r.UserAccessible ? L"true" : L"false")
             << L",\"large_page\":" << (r.LargePage ? L"true" : L"false")
             << L",\"notes\":\"" << JsonEscape(r.Notes)
             << L"\"}";
        if (i + 1 != result.HiddenPteRecords.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";
    return json.str();
}

std::wstring BuildProcessMappedPeJson(
    const ProcessMappedPeScanResult& result)
{
    std::wstringstream json;
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.process-pe.v1\",\n";
    json << L"  \"target\":{\"pid\":" << result.Target.ProcessId
         << L",\"image\":\"" << JsonEscape(result.Target.ImageName)
         << L"\",\"eprocess\":\"" << Hex(result.Target.Eprocess, 16)
         << L"\"},\n";
    json << L"  \"summary\":{\"vad_nodes_visited\":"
         << result.VadNodesVisited
         << L",\"vad_records\":" << result.VadRecords
         << L",\"loader_records\":" << result.LoaderRecords
         << L",\"candidate_mappings\":" << result.CandidateMappings
         << L",\"header_visible\":" << result.HeaderVisibleRecords
         << L",\"loader_visible\":" << result.LoaderVisibleRecords
         << L",\"memory_only\":" << result.MemoryOnlyRecords
         << L",\"private\":" << result.PrivateRecords
         << L",\"suspicious\":" << result.SuspiciousRecords
         << L",\"vad_coverage_complete\":"
         << (result.VadCoverageComplete ? L"true" : L"false")
         << L",\"loader_coverage_complete\":"
         << (result.LoaderCoverageComplete ? L"true" : L"false")
         << L",\"header_probe_coverage_complete\":"
         << (result.HeaderProbeCoverageComplete ? L"true" : L"false")
         << L",\"mapped_path_coverage_complete\":"
         << (result.MappedPathCoverageComplete ? L"true" : L"false")
         << L",\"coverage_complete\":"
         << (result.CoverageComplete ? L"true" : L"false")
         << L",\"incomplete\":"
         << (result.Incomplete ? L"true" : L"false")
         << L",\"truncated\":"
         << (result.Truncated ? L"true" : L"false")
         << L"},\n";
    json << L"  \"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << JsonEscape(result.Warnings[i]) << L"\"";
    }
    json << L"],\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ProcessMappedPeRecord& record = result.Records[i];
        json << L"    {\"base\":\"" << Hex(record.Base, 16)
             << L"\",\"loader_size\":" << record.LoaderSize
             << L",\"vad\":\"" << Hex(record.VadAddress, 16)
             << L"\",\"vad_start\":\"" << Hex(record.VadStart, 16)
             << L"\",\"vad_end\":\"" << Hex(record.VadEnd, 16)
             << L"\",\"vad_size\":" << record.VadSize
             << L",\"header_image_size\":" << record.HeaderImageSize
             << L",\"preferred_image_base\":\""
             << Hex(record.PreferredImageBase, 16)
             << L"\",\"entry_point_rva\":" << record.EntryPointRva
             << L",\"entry_point_va\":\"" << Hex(record.EntryPointVa, 16)
             << L"\",\"entry_point_valid\":"
             << (record.EntryPointValid ? L"true" : L"false")
             << L",\"size_of_headers\":" << record.SizeOfHeaders
             << L",\"timestamp\":" << record.TimeDateStamp
             << L",\"machine\":" << record.Machine
             << L",\"sections\":" << record.NumberOfSections
             << L",\"image\":\"" << JsonEscape(record.ImageName)
             << L"\",\"loader_path\":\"" << JsonEscape(record.ImagePath)
             << L"\",\"mapped_path\":\"" << JsonEscape(record.MappedPath)
             << L"\",\"allocation_protection\":\""
             << JsonEscape(record.AllocationProtection)
             << L"\",\"effective_protection\":\""
             << JsonEscape(record.EffectiveProtection)
             << L"\",\"loader_visible\":"
             << (record.LoaderVisible ? L"true" : L"false")
             << L",\"vad_visible\":"
             << (record.VadVisible ? L"true" : L"false")
             << L",\"header_probe_attempted\":"
             << (record.HeaderProbeAttempted ? L"true" : L"false")
             << L",\"header_probe_read_succeeded\":"
             << (record.HeaderProbeReadSucceeded ? L"true" : L"false")
             << L",\"memory_header_visible\":"
             << (record.MemoryHeaderVisible ? L"true" : L"false")
             << L",\"mapped_path_visible\":"
             << (record.MappedPathVisible ? L"true" : L"false")
             << L",\"virtual_image_mapping\":"
             << (record.VirtualImageMapping ? L"true" : L"false")
             << L",\"private_mapping\":"
             << (record.PrivateMapping ? L"true" : L"false")
             << L",\"image_backed\":"
             << (record.ImageBacked ? L"true" : L"false")
             << L",\"executable\":"
             << (record.Executable ? L"true" : L"false")
             << L",\"writable_executable\":"
             << (record.WritableExecutable ? L"true" : L"false")
             << L",\"is_64_bit\":"
             << (record.Is64Bit ? L"true" : L"false")
             << L",\"mz_wiped\":"
             << (record.MzWiped ? L"true" : L"false")
             << L",\"pe_signature_wiped\":"
             << (record.PeSignatureWiped ? L"true" : L"false")
             << L",\"e_lfanew_mismatch\":"
             << (record.ELfanewMismatch ? L"true" : L"false")
             << L",\"suspicious\":"
             << (record.Suspicious ? L"true" : L"false")
             << L",\"sources\":[";
        for (size_t source = 0; source < record.Sources.size(); ++source)
        {
            if (source != 0)
            {
                json << L",";
            }
            json << L"\"" << JsonEscape(record.Sources[source]) << L"\"";
        }
        json << L"],\"reasons\":[";
        for (size_t reason = 0; reason < record.Reasons.size(); ++reason)
        {
            if (reason != 0)
            {
                json << L",";
            }
            json << L"\"" << JsonEscape(record.Reasons[reason]) << L"\"";
        }
        json << L"]}";
        if (i + 1 != result.Records.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";
    return json.str();
}

std::wstring BuildProcessThreadsJson(const ProcessThreadScanResult& result)
{
    std::wstringstream json;
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.threads.v1\",\n";
    json << L"  \"target\":{\"pid\":" << result.Target.ProcessId
         << L",\"image\":\"" << JsonEscape(result.Target.ImageName)
         << L"\",\"eprocess\":\"" << Hex(result.Target.Eprocess, 16) << L"\"},\n";
    json << L"  \"summary\":{\"threads_visited\":" << result.ThreadsVisited
         << L",\"records\":" << result.MatchingRecords
         << L",\"suspicious_start\":" << result.SuspiciousStartCount
         << L",\"suspension_state_resolved\":" << result.SuspensionStateResolvedCount
         << L",\"suspended_threads\":" << result.SuspendedThreadCount
         << L",\"nonempty_apc_queues\":" << result.ApcNonEmptyCount
         << L",\"stack_references\":" << result.StackReferenceCount
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false")
         << L",\"incomplete\":" << (result.Incomplete ? L"true" : L"false")
         << L",\"inventory_complete\":" << (result.InventoryComplete ? L"true" : L"false")
         << L",\"suspension_state_coverage_complete\":" << (result.SuspensionStateCoverageComplete ? L"true" : L"false")
         << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false")
         << L"},\n";
    json << L"  \"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << JsonEscape(result.Warnings[i]) << L"\"";
    }
    json << L"],\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ProcessThreadRecord& r = result.Records[i];
        json << L"    {\"ethread\":\"" << Hex(r.Ethread, 16)
             << L"\",\"tid\":" << r.ThreadId
             << L",\"start\":\"" << Hex(r.StartAddress, 16)
             << L"\",\"win32_start\":\"" << Hex(r.Win32StartAddress, 16)
             << L"\",\"teb\":\"" << Hex(r.Teb, 16)
             << L"\",\"stack_base\":\"" << Hex(r.StackBase, 16)
             << L"\",\"stack_limit\":\"" << Hex(r.StackLimit, 16)
             << L"\",\"user_stack_base\":\"" << Hex(r.UserStackBase, 16)
             << L"\",\"user_stack_limit\":\"" << Hex(r.UserStackLimit, 16)
             << L"\",\"suspend_count\":" << r.SuspendCount
             << L",\"freeze_count\":" << r.FreezeCount
             << L",\"has_suspend_count\":" << (r.HasSuspendCount ? L"true" : L"false")
             << L",\"has_freeze_count\":" << (r.HasFreezeCount ? L"true" : L"false")
             << L",\"start_module\":\"" << JsonEscape(r.StartModule)
             << L"\",\"win32_start_module\":\"" << JsonEscape(r.Win32StartModule)
             << L"\",\"vad\":\"" << JsonEscape(r.VadClassification)
             << L"\",\"suspicious_start\":" << (r.SuspiciousStart ? L"true" : L"false")
             << L",\"notes\":\"" << JsonEscape(r.Notes)
             << L"\",\"apc_queues\":[";
        for (size_t q = 0; q < r.ApcQueues.size(); ++q)
        {
            const ProcessApcQueueRecord& queue = r.ApcQueues[q];
            if (q != 0)
            {
                json << L",";
            }
            json << L"{\"name\":\"" << JsonEscape(queue.Name)
                 << L"\",\"head\":\"" << Hex(queue.HeadAddress, 16)
                 << L"\",\"nonempty\":" << (queue.NonEmpty ? L"true" : L"false")
                 << L",\"entries_scanned\":" << queue.EntriesScanned
                 << L",\"truncated\":" << (queue.Truncated ? L"true" : L"false")
                 << L",\"incomplete\":" << (queue.Incomplete ? L"true" : L"false")
                 << L",\"notes\":\"" << JsonEscape(queue.Notes)
                 << L"\""
                 << L",\"entries\":[";
            for (size_t e = 0; e < queue.Entries.size(); ++e)
            {
                const ProcessApcEntryRecord& entry = queue.Entries[e];
                if (e != 0)
                {
                    json << L",";
                }
                json << L"{\"kapc\":\"" << Hex(entry.KapcAddress, 16)
                     << L"\",\"kernel_routine\":\"" << Hex(entry.KernelRoutine, 16)
                     << L"\",\"normal_routine\":\"" << Hex(entry.NormalRoutine, 16)
                     << L"\",\"normal_context\":\"" << Hex(entry.NormalContext, 16)
                     << L"\",\"system_argument1\":\"" << Hex(entry.SystemArgument1, 16)
                     << L"\",\"system_argument2\":\"" << Hex(entry.SystemArgument2, 16)
                     << L"\",\"normal_routine_vad\":\"" << JsonEscape(entry.NormalRoutineVadClassification)
                     << L"\",\"normal_routine_private_exec\":" << (entry.NormalRoutineInPrivateExecVad ? L"true" : L"false")
                     << L",\"normal_routine_wx\":" << (entry.NormalRoutineInWxVad ? L"true" : L"false")
                     << L",\"user_routine\":\"" << Hex(entry.UserRoutine, 16)
                     << L"\",\"user_routine_source\":\"" << JsonEscape(entry.UserRoutineSource)
                     << L"\",\"user_routine_module\":\"" << JsonEscape(entry.UserRoutineModule)
                     << L"\",\"user_routine_vad\":\"" << JsonEscape(entry.UserRoutineVadClassification)
                     << L"\",\"user_routine_private_exec\":" << (entry.UserRoutineInPrivateExecVad ? L"true" : L"false")
                     << L",\"user_routine_wx\":" << (entry.UserRoutineInWxVad ? L"true" : L"false")
                     << L",\"suspicious\":" << (entry.Suspicious ? L"true" : L"false")
                     << L"}";
            }
            json << L"]}";
        }
        json << L"],\"stack_references\":[";
        for (size_t s = 0; s < r.StackReferences.size(); ++s)
        {
            const ProcessStackReferenceRecord& ref = r.StackReferences[s];
            if (s != 0)
            {
                json << L",";
            }
            json << L"{\"stack\":\"" << Hex(ref.StackAddress, 16)
                 << L"\",\"value\":\"" << Hex(ref.Value, 16)
                 << L"\",\"module\":\"" << JsonEscape(ref.ValueModule)
                 << L"\",\"vad\":\"" << JsonEscape(ref.VadClassification)
                 << L"\",\"module_enum_available\":" << (ref.UserModuleEnumerationAvailable ? L"true" : L"false")
                 << L",\"outside_modules\":" << (ref.ValueOutsideUserModules ? L"true" : L"false")
                 << L",\"private_exec\":" << (ref.ValueInPrivateExecVad ? L"true" : L"false")
                 << L",\"wx\":" << (ref.ValueInWxVad ? L"true" : L"false")
                 << L",\"notes\":\"" << JsonEscape(ref.Notes)
                 << L"\"}";
        }
        json << L"]}";
        if (i + 1 != result.Records.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";
    return json.str();
}
