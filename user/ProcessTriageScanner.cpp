#include "ProcessTriageScanner.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>

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

    bool IsKernelAddress(uint64_t address)
    {
        return address >= kKernelAddressMin;
    }

    bool IsUserAddress(uint64_t address)
    {
        return address != 0 && address <= kUserAddressMax;
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
        return p == 4 || p == 5 || p == 6 || p == 7;
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

    void AppendHiddenPteRecord(
        const ProcessVadScanOptions& options,
        const PteLeafMapping& mapping,
        uint64_t startAddress,
        uint64_t endAddress,
        ProcessVadScanResult* result)
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
            record.Notes = L"present_pte_without_vad";

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

            uint32_t recordLimit = options.HiddenPteLimit != 0
                ? options.HiddenPteLimit
                : (options.Limit != 0 ? options.Limit : kDefaultHiddenPteRecordLimit);
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
                if (interval.StartAddress > uncoveredStart)
                {
                    AppendHiddenPteRecord(
                        options,
                        mapping,
                        uncoveredStart,
                        std::min(mapping.EndAddress, interval.StartAddress - 1ull),
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
        } while (false);
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

        do
        {
            if (modules == nullptr)
            {
                break;
            }

            modules->clear();
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning = L"user module enumeration failed: CreateToolhelp32Snapshot gle=" + std::to_wstring(GetLastError());
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
                CloseHandle(snapshot);
                break;
            }

            do
            {
                ProcessUserModuleRange module = {};
                module.Base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                module.Size = static_cast<uint64_t>(entry.modBaseSize);
                module.ImageName = entry.szModule;
                module.ImagePath = entry.szExePath;
                modules->push_back(module);
                entry.dwSize = sizeof(entry);
            } while (Module32NextW(snapshot, &entry));

            CloseHandle(snapshot);
            ok = true;
        } while (false);

        return ok;
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

    bool ReadProcessU64ByDtb(DeviceClient& device, uint64_t dtb, uint64_t address, uint64_t* value)
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
            if (!ReadProcessMemoryByDtb(device, dtb, address, sizeof(uint64_t), &bytes, &ignored) ||
                bytes.size() != sizeof(uint64_t))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadUserStackBoundsFromTeb(DeviceClient& device, uint64_t dtb, ProcessThreadRecord* record)
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
                if (!ReadProcessU64ByDtb(device, dtb, record->Teb + 0x08, &stackBase) ||
                    !ReadProcessU64ByDtb(device, dtb, record->Teb + 0x10, &stackLimit))
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
            if (vad == nullptr || !vad->Executable)
            {
                break;
            }

            const ProcessUserModuleRange* module = FindUserModule(modules, value);
            bool privateExec = vad->HasPrivateMemory && vad->PrivateMemory && vad->Executable;
            bool wx = vad->Executable && vad->Writable;
            bool userModuleEnumerationAvailable = !modules.empty();
            bool executableOutsideModule = userModuleEnumerationAvailable && module == nullptr;
            if (!privateExec && !wx && !executableOutsideModule)
            {
                break;
            }

            ProcessStackReferenceRecord ref = {};
            ref.StackAddress = stackAddress;
            ref.Value = value;
            ref.UserModuleEnumerationAvailable = userModuleEnumerationAvailable;
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
        const std::vector<ProcessUserModuleRange>& modules,
        const std::vector<ProcessVadRecord>& vadRecords,
        uint64_t dtb,
        ProcessThreadRecord* record)
    {
        do
        {
            if (record == nullptr ||
                !record->HasUserStackBounds ||
                dtb == 0 ||
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
                if (ReadProcessMemoryByDtb(device, dtb, current, chunkSize, &bytes, &ignored))
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

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadVadRecord(
        DeviceClient& device,
        const VadLayout& layout,
        uint64_t nodeAddress,
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
            if (!TrySub(nodeAddress, layout.VadNode.Offset, &record->VadAddress))
            {
                if (error != nullptr)
                {
                    *error = L"VAD node address underflow";
                }
                break;
            }

            uint64_t leftAddress = 0;
            uint64_t rightAddress = 0;
            if (!TryAdd(nodeAddress, layout.Left.Offset, &leftAddress) ||
                !TryAdd(nodeAddress, layout.Right.Offset, &rightAddress))
            {
                if (error != nullptr)
                {
                    *error = L"VAD child pointer address overflow";
                }
                break;
            }

            if (!ReadKernelPointer(device, leftAddress, &record->Left, error) ||
                !ReadKernelPointer(device, rightAddress, &record->Right, error))
            {
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
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool VadMatchesOptions(const ProcessVadRecord& record, const ProcessVadScanOptions& options)
    {
        bool matched = true;

        do
        {
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

            if (options.WxOnly && !(record.Executable && record.Writable))
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
            if (record->Executable && record->Writable)
            {
                tags.push_back(L"W+X");
            }
            if (record->HasPrivateMemory && record->PrivateMemory)
            {
                tags.push_back(L"private");
            }
            if (record->HasPrivateMemory && record->PrivateMemory && record->Executable)
            {
                tags.push_back(L"private-exec");
            }
            if (record->Size >= kLargeVadThreshold && record->Executable && record->HasPrivateMemory && record->PrivateMemory)
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

            if (!layout->HasUniqueThread)
            {
                layout->Warnings.push_back(L"_ETHREAD.Cid.UniqueThread not found; thread IDs may be unavailable");
            }
            if (!layout->HasStartAddress && !layout->HasWin32StartAddress)
            {
                layout->Warnings.push_back(L"thread start address fields not found");
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
            if (ReadFieldInteger(device, record->KapcAddress, layout.KapcKernelRoutine, sizeof(uint64_t), &value, nullptr))
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

            if (ReadFieldInteger(device, record->KapcAddress, layout.KapcNormalRoutine, sizeof(uint64_t), &value, nullptr))
            {
                record->NormalRoutine = value;
                record->HasNormalRoutine = true;
                AnnotateUserOrKernelAddress(symbols, modules, value, &record->NormalRoutineModule, nullptr);
                if (value != 0 &&
                    userQueue &&
                    IsUserAddress(value) &&
                    !modules.empty() &&
                    FindUserModule(modules, value) == nullptr)
                {
                    record->Suspicious = true;
                    if (!record->Notes.empty())
                    {
                        record->Notes += L"; ";
                    }
                    record->Notes += L"user APC normal routine is outside enumerated user modules";
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

            ok = true;
        } while (false);

        return ok;
    }

    ProcessApcQueueRecord ReadApcQueue(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<ProcessUserModuleRange>& modules,
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
                break;
            }

            queue.Present = true;
            queue.NonEmpty = queue.Flink != 0 && queue.Flink != headAddress;
            if (!queue.NonEmpty)
            {
                break;
            }

            uint64_t current = queue.Flink;
            std::vector<uint64_t> visited;
            while (current != 0 && current != headAddress && queue.EntriesScanned < kMaxApcEntriesPerQueue)
            {
                if (!IsKernelAddress(current) ||
                    std::find(visited.begin(), visited.end(), current) != visited.end())
                {
                    break;
                }

                visited.push_back(current);
                ProcessApcEntryRecord entry = {};
                if (ReadApcEntry(device, symbols, modules, layout, current, userQueue, &entry))
                {
                    queue.Entries.push_back(entry);
                }

                uint64_t next = 0;
                uint64_t blink = 0;
                if (!ReadListEntry(device, current, &next, &blink, nullptr))
                {
                    break;
                }

                current = next;
                ++queue.EntriesScanned;
            }

            if (queue.EntriesScanned >= kMaxApcEntriesPerQueue)
            {
                queue.Truncated = true;
            }
        } while (false);

        return queue;
    }
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

        VadLayout layout = {};
        if (!ResolveVadLayout(symbols_, &layout, error))
        {
            break;
        }

        result->Warnings.insert(result->Warnings.end(), layout.Warnings.begin(), layout.Warnings.end());
        result->LayoutSource = L"PDB/DIA";
        if ((options.ExecOnly || options.WxOnly) && !layout.HasProtection)
        {
            result->Warnings.push_back(L"VAD protection field is unavailable; executable/W+X filters may return no records");
        }
        if ((options.PrivateOnly || options.PeOnly) && !layout.HasPrivateMemory)
        {
            result->Warnings.push_back(L"VAD private-memory field is unavailable; private/PE filters may return no records");
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
                }
            }
            ok = true;
            break;
        }

        std::vector<uint64_t> stack;
        std::vector<uint64_t> visited;
        stack.push_back(root);

        uint64_t dtb = TargetUserDtb(options.Target);
        bool vadTraversalHitLimit = false;
        bool vadCoverageReliable = true;
        while (!stack.empty() && result->NodesVisited < kMaxVadNodes)
        {
            uint64_t node = stack.back();
            stack.pop_back();

            if (node == 0)
            {
                continue;
            }

            if (!IsKernelAddress(node))
            {
                result->Warnings.push_back(L"VAD node is not kernel-canonical: " + Hex(node, 16));
                vadCoverageReliable = false;
                continue;
            }

            if (std::find(visited.begin(), visited.end(), node) != visited.end())
            {
                result->Warnings.push_back(L"VAD cycle detected at " + Hex(node, 16));
                vadCoverageReliable = false;
                continue;
            }
            visited.push_back(node);
            ++result->NodesVisited;

            ProcessVadRecord record = {};
            std::wstring readError;
            if (!ReadVadRecord(device_, layout, node, &record, &readError))
            {
                result->Warnings.push_back(L"failed to read VAD node " + Hex(node, 16) + L": " + readError);
                vadCoverageReliable = false;
                continue;
            }

            vadIntervals.push_back({record.StartAddress, record.EndAddress});

            if (record.Right != 0)
            {
                stack.push_back(record.Right);
            }
            if (record.Left != 0)
            {
                stack.push_back(record.Left);
            }

            if (record.Executable)
            {
                ++result->ExecutableCount;
            }
            if (record.Executable && record.HasPrivateMemory && record.PrivateMemory)
            {
                ++result->PrivateExecutableCount;
            }
            if (record.Executable && record.Writable)
            {
                ++result->WxCount;
            }

            if ((options.ProbePe || options.PeOnly) &&
                record.HasPrivateMemory &&
                record.PrivateMemory &&
                record.StartAddress != 0 &&
                record.Size >= kPageSize &&
                dtb != 0)
            {
                std::vector<uint8_t> firstPage;
                std::wstring ignored;
                record.PeProbeAttempted = true;
                if (ReadProcessMemoryByDtb(device_, dtb, record.StartAddress, static_cast<uint32_t>(kPageSize), &firstPage, &ignored))
                {
                    if (ProbeForPeHeader(firstPage.data(), firstPage.size(), &record.PeProbe))
                    {
                        record.PeHeaderFound = record.PeProbe.IsPe;
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
            bool suspicious =
                (record.Executable && record.Writable) ||
                (record.Executable && record.HasPrivateMemory && record.PrivateMemory) ||
                record.PeHeaderFound ||
                (record.Size >= kLargeVadThreshold && record.Executable && record.HasPrivateMemory && record.PrivateMemory);
            if (suspicious)
            {
                ++result->SuspiciousCount;
            }

            ++result->TotalRecords;
            if (VadMatchesOptions(record, options))
            {
                if (options.Limit == 0 || result->Records.size() < options.Limit)
                {
                    result->Records.push_back(record);
                }
                else
                {
                    result->Truncated = true;
                }
                ++result->MatchingRecords;
            }
        }

        if (result->NodesVisited >= kMaxVadNodes)
        {
            vadTraversalHitLimit = true;
            vadCoverageReliable = false;
            result->Truncated = true;
            result->Warnings.push_back(L"VAD traversal hit the node limit");
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
            }
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

        std::vector<ProcessUserModuleRange> userModules;
        std::wstring moduleWarning;
        if (!EnumerateUserModules(options.Target.ProcessId, &userModules, &moduleWarning) && !moduleWarning.empty())
        {
            result->Warnings.push_back(moduleWarning);
        }

        std::vector<ProcessVadRecord> vadRecords;
        ProcessVadScanResult vadResult = {};
        ProcessVadScanOptions vadOptions = {};
        vadOptions.Target = options.Target;
        if (ScanVad(vadOptions, &vadResult, nullptr))
        {
            vadRecords = vadResult.Records;
        }
        else
        {
            result->Warnings.push_back(L"VAD correlation unavailable for thread-start classification");
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

        std::vector<uint64_t> visited;
        while (current != 0 && current != listHead && result->ThreadsVisited < kMaxThreads)
        {
            if (!IsKernelAddress(current))
            {
                result->Warnings.push_back(L"thread list entry is not kernel-canonical: " + Hex(current, 16));
                break;
            }

            if (std::find(visited.begin(), visited.end(), current) != visited.end())
            {
                result->Warnings.push_back(L"thread list cycle detected at " + Hex(current, 16));
                break;
            }
            visited.push_back(current);

            uint64_t ethread = 0;
            if (!TrySub(current, layout.ThreadListEntry.Offset, &ethread))
            {
                result->Warnings.push_back(L"ETHREAD address underflow at " + Hex(current, 16));
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

            if (options.IncludeStacks && userDtb != 0)
            {
                if (ReadUserStackBoundsFromTeb(device_, userDtb, &record))
                {
                    ScanUserStackReferences(device_, userModules, vadRecords, userDtb, &record);
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
                    containingVad->Executable &&
                    containingVad->HasPrivateMemory &&
                    containingVad->PrivateMemory;
                record.StartInWxVad = containingVad->Executable && containingVad->Writable;
            }

            if (IsUserAddress(classifyAddress))
            {
                if (!userModules.empty() && !record.StartInUserModule)
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
                    uint64_t base = apcState + layout.ApcListHead.Offset;
                    record.ApcQueues.push_back(ReadApcQueue(device_, symbols_, userModules, layout, base, L"kernel", false));
                    record.ApcQueues.push_back(ReadApcQueue(device_, symbols_, userModules, layout, base + sizeof(uint64_t) * 2, L"user", true));
                    for (const ProcessApcQueueRecord& queue : record.ApcQueues)
                    {
                        if (queue.NonEmpty)
                        {
                            ++result->ApcNonEmptyCount;
                        }
                    }
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
                break;
            }
            current = next;
        }

        if (result->ThreadsVisited >= kMaxThreads)
        {
            result->Truncated = true;
            result->Warnings.push_back(L"thread traversal hit the node limit");
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
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},\n";
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
             << L",\"private\":" << (r.HasPrivateMemory && r.PrivateMemory ? L"true" : L"false")
             << L",\"commit_charge\":" << r.CommitCharge
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
         << L",\"nonempty_apc_queues\":" << result.ApcNonEmptyCount
         << L",\"stack_references\":" << result.StackReferenceCount
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},\n";
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
             << L"\",\"start_module\":\"" << JsonEscape(r.StartModule)
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
                     << L"\",\"suspicious\":" << (entry.Suspicious ? L"true" : L"false")
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
                 << L"\",\"private_exec\":" << (ref.ValueInPrivateExecVad ? L"true" : L"false")
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
