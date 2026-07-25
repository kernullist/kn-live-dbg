#include "IntegrityScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxRawRead = 0x10000;
    constexpr uint32_t kDefaultDirectoryBuckets = 37;
    constexpr uint32_t kMaxDirectoryBuckets = 256;
    constexpr uint32_t kMaxDirectoryEntriesPerBucket = 4096;
    constexpr uint32_t kMaxDriverObjects = 8192;

    static const uint8_t kObpInfoMaskToOffset[64] =
    {
        0x00, 0x20, 0x20, 0x40, 0x10, 0x30, 0x30, 0x50,
        0x10, 0x30, 0x30, 0x50, 0x20, 0x40, 0x40, 0x60,
        0x10, 0x30, 0x30, 0x50, 0x20, 0x40, 0x40, 0x60,
        0x20, 0x40, 0x40, 0x60, 0x30, 0x50, 0x50, 0x70,
        0x10, 0x30, 0x30, 0x50, 0x20, 0x40, 0x40, 0x60,
        0x20, 0x40, 0x40, 0x60, 0x30, 0x50, 0x50, 0x70,
        0x20, 0x40, 0x40, 0x60, 0x30, 0x50, 0x50, 0x70,
        0x30, 0x50, 0x50, 0x70, 0x40, 0x60, 0x60, 0x80
    };

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    bool ContainsNoCaseLocal(const std::wstring& haystack, const std::wstring& needle)
    {
        bool found = false;

        do
        {
            if (needle.empty())
            {
                found = true;
                break;
            }

            std::wstring h = ToLowerCopy(haystack);
            std::wstring n = ToLowerCopy(needle);
            found = h.find(n) != std::wstring::npos;
        } while (false);

        return found;
    }

    bool EqualsNoCaseLocal(const std::wstring& a, const std::wstring& b)
    {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || left > (~0ull - right))
            {
                break;
            }

            *result = left + right;
            ok = true;
        } while (false);

        return ok;
    }

    bool TrySub(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || left < right)
            {
                break;
            }

            *result = left - right;
            ok = true;
        } while (false);

        return ok;
    }

    bool IsPowerOfTwo32(uint32_t value)
    {
        return value != 0 && (value & (value - 1)) == 0;
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
                if (ch >= 0 && ch < 0x20)
                {
                    std::wstringstream stream;
                    stream << L"\\u"
                           << std::hex << std::setw(4) << std::setfill(L'0')
                           << static_cast<unsigned int>(ch);
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

    void AddUnique(std::vector<std::wstring>* values, const std::wstring& value)
    {
        do
        {
            if (values == nullptr || value.empty())
            {
                break;
            }

            if (std::find(values->begin(), values->end(), value) == values->end())
            {
                values->push_back(value);
            }
        } while (false);
    }

    void AppendNote(std::wstring* notes, const std::wstring& note)
    {
        do
        {
            if (notes == nullptr || note.empty())
            {
                break;
            }

            if (!notes->empty())
            {
                *notes += L"; ";
            }
            *notes += note;
        } while (false);
    }

    void AddRecordReason(ModuleIntegrityRecord* record, const std::wstring& code, const std::wstring& note)
    {
        do
        {
            if (record == nullptr)
            {
                break;
            }

            record->Suspicious = true;
            AddUnique(&record->ReasonCodes, code);
            AppendNote(&record->Notes, note);
        } while (false);
    }

    void AddRecordInfo(ModuleIntegrityRecord* record, const std::wstring& code, const std::wstring& note)
    {
        do
        {
            (void)note;

            if (record == nullptr)
            {
                break;
            }

            AddUnique(&record->InfoCodes, code);
        } while (false);
    }

    void AddSectionReason(ModuleIntegritySectionRecord* section, const std::wstring& code, const std::wstring& note)
    {
        do
        {
            if (section == nullptr)
            {
                break;
            }

            section->Suspicious = true;
            AddUnique(&section->ReasonCodes, code);
            AppendNote(&section->Notes, note);
        } while (false);
    }

    std::wstring SectionName(const IMAGE_SECTION_HEADER& section)
    {
        std::wstring name;

        for (size_t index = 0; index < sizeof(section.Name); ++index)
        {
            uint8_t ch = section.Name[index];
            if (ch == 0)
            {
                break;
            }
            if (ch >= 0x20 && ch <= 0x7e)
            {
                name.push_back(static_cast<wchar_t>(ch));
            }
            else
            {
                name.push_back(L'.');
            }
        }

        return name;
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
            if (bytes == nullptr || length == 0 || length > kMaxRawRead)
            {
                if (error != nullptr)
                {
                    *error = L"invalid read size";
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

    size_t FieldWidth(const TypeFieldInfo& field, size_t fallback)
    {
        size_t width = fallback;

        if (field.Length > 0 && field.Length <= sizeof(uint64_t))
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
            uint64_t address = 0;
            if (!TryAdd(base, field.Offset, &address))
            {
                if (error != nullptr)
                {
                    *error = L"field address overflow";
                }
                break;
            }

            if (!ReadKernelInteger(device, address, FieldWidth(field, fallbackWidth), value, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool FindField(SymbolEngine& symbols, const std::wstring& typeName, const std::vector<std::wstring>& names, TypeFieldInfo* field)
    {
        bool found = false;
        TypeLayoutInfo layout = {};

        do
        {
            if (field == nullptr || !symbols.GetTypeLayout(typeName, &layout, nullptr))
            {
                break;
            }

            for (const std::wstring& name : names)
            {
                for (const TypeFieldInfo& candidate : layout.Fields)
                {
                    if (EqualsNoCaseLocal(candidate.Name, name))
                    {
                        *field = candidate;
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

    const KernelModuleInfo* FindModuleForAddress(const std::vector<KernelModuleInfo>& modules, uint64_t address)
    {
        const KernelModuleInfo* found = nullptr;

        for (const KernelModuleInfo& module : modules)
        {
            uint64_t end = 0;
            if (!TryAdd(module.Base, module.Size, &end))
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

    bool ModuleMatches(const KernelModuleInfo& module, const std::wstring& filter)
    {
        bool matched = false;

        do
        {
            std::wstring trimmed = ToLowerCopy(filter);
            if (trimmed.empty() || trimmed == L"all")
            {
                matched = true;
                break;
            }

            matched = ContainsNoCaseLocal(module.ImageName, filter) || ContainsNoCaseLocal(module.ImagePath, filter);
        } while (false);

        return matched;
    }

    uint64_t SectionVirtualSpan(const IMAGE_SECTION_HEADER& section)
    {
        uint64_t span = section.Misc.VirtualSize;

        if (span == 0)
        {
            span = section.SizeOfRawData;
        }

        return span;
    }

    void AnnotatePointer(SymbolEngine& symbols, uint64_t address, std::wstring* moduleName, std::wstring* symbolName)
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

            const KernelModuleInfo* module = FindModuleForAddress(symbols.Modules(), address);
            if (module != nullptr && moduleName != nullptr)
            {
                *moduleName = module->ImageName;
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, nullptr) && symbolName != nullptr)
            {
                std::wstringstream stream;
                stream << nearest;
                if (displacement != 0)
                {
                    stream << L"+0x" << std::hex << displacement;
                }
                *symbolName = stream.str();
            }
        } while (false);
    }

    struct ModulePageAttributes
    {
        bool Queried = false;
        bool Readable = false;
        bool Writable = false;
        bool Executable = false;
        bool LargePage = false;
        uint32_t PagingLevels = 0;
        std::wstring Error;
    };

    bool QueryEffectivePageAttributes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        ModulePageAttributes* attributes)
    {
        bool ok = false;

        do
        {
            if (attributes == nullptr || address == 0)
            {
                break;
            }

            *attributes = ModulePageAttributes{};
            PhysicalTranslationInfo translation = {};
            uint32_t queryLength = length == 0 ? 1 : length;
            if (queryLength > 0x1000)
            {
                queryLength = 0x1000;
            }

            if (!device.TranslateVirtual(0, address, queryLength, &translation, &attributes->Error))
            {
                break;
            }

            attributes->Queried = true;
            attributes->LargePage = (translation.Flags & KNDBG_TRANSLATE_FLAG_LARGE_PAGE) != 0;
            attributes->PagingLevels = translation.PagingLevels;

            const bool la57 = (translation.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
            const uint64_t levels[5] =
            {
                translation.Pml5e,
                translation.Pml4e,
                translation.Pdpte,
                translation.Pde,
                translation.Pte
            };
            const size_t startIndex = la57 ? 0 : 1;
            size_t walkCount = translation.PagingLevels;
            if (walkCount > 5)
            {
                walkCount = 5;
            }

            bool present = walkCount > 0;
            bool canWrite = walkCount > 0;
            bool canExecute = walkCount > 0;
            for (size_t step = 0; step < walkCount; ++step)
            {
                size_t levelIndex = startIndex + step;
                if (levelIndex >= 5)
                {
                    break;
                }

                uint64_t entry = levels[levelIndex];
                if ((entry & 1ull) == 0)
                {
                    present = false;
                }
                if ((entry & 2ull) == 0)
                {
                    canWrite = false;
                }
                if ((entry & (1ull << 63)) != 0)
                {
                    canExecute = false;
                }
                if ((levelIndex == 2 || levelIndex == 3) && (entry & (1ull << 7)) != 0)
                {
                    break;
                }
            }

            attributes->Readable = present;
            attributes->Writable = present && canWrite;
            attributes->Executable = present && canExecute;
            ok = true;
        } while (false);

        return ok;
    }

    bool DriverMatches(const std::wstring& name, const std::wstring& path, const std::wstring& filter)
    {
        bool matched = false;

        do
        {
            std::wstring lowered = ToLowerCopy(filter);
            if (lowered.empty() || lowered == L"all")
            {
                matched = true;
                break;
            }

            matched = ContainsNoCaseLocal(name, filter) || ContainsNoCaseLocal(path, filter);
        } while (false);

        return matched;
    }

    bool IsKernelModuleName(const std::wstring& moduleName)
    {
        std::wstring name = ToLowerCopy(moduleName);
        return name == L"ntoskrnl.exe" ||
            name == L"ntkrnlmp.exe" ||
            name == L"ntkrnlpa.exe" ||
            name == L"ntkrnlup.exe" ||
            name == L"nt";
    }

    const wchar_t* MajorFunctionName(uint32_t index)
    {
        static const wchar_t* names[] =
        {
            L"CREATE",
            L"CREATE_NAMED_PIPE",
            L"CLOSE",
            L"READ",
            L"WRITE",
            L"QUERY_INFORMATION",
            L"SET_INFORMATION",
            L"QUERY_EA",
            L"SET_EA",
            L"FLUSH_BUFFERS",
            L"QUERY_VOLUME_INFORMATION",
            L"SET_VOLUME_INFORMATION",
            L"DIRECTORY_CONTROL",
            L"FILE_SYSTEM_CONTROL",
            L"DEVICE_CONTROL",
            L"INTERNAL_DEVICE_CONTROL",
            L"SHUTDOWN",
            L"LOCK_CONTROL",
            L"CLEANUP",
            L"CREATE_MAILSLOT",
            L"QUERY_SECURITY",
            L"SET_SECURITY",
            L"POWER",
            L"SYSTEM_CONTROL",
            L"DEVICE_CHANGE",
            L"QUERY_QUOTA",
            L"SET_QUOTA",
            L"PNP"
        };

        if (index < _countof(names))
        {
            return names[index];
        }

        return L"UNKNOWN";
    }

    class ObjectWalkContext
    {
    public:
        ObjectWalkContext(DeviceClient& device, SymbolEngine& symbols) :
            device_(device),
            symbols_(symbols)
        {
        }

        bool ReadU8(uint64_t address, uint8_t* value)
        {
            uint64_t raw = 0;
            bool ok = ReadKernelInteger(device_, address, sizeof(uint8_t), &raw, nullptr);
            if (ok && value != nullptr)
            {
                *value = static_cast<uint8_t>(raw);
            }
            return ok;
        }

        bool ReadU16(uint64_t address, uint16_t* value)
        {
            uint64_t raw = 0;
            bool ok = ReadKernelInteger(device_, address, sizeof(uint16_t), &raw, nullptr);
            if (ok && value != nullptr)
            {
                *value = static_cast<uint16_t>(raw);
            }
            return ok;
        }

        bool ReadU64(uint64_t address, uint64_t* value)
        {
            return ReadKernelInteger(device_, address, sizeof(uint64_t), value, nullptr);
        }

        bool ReadUnicodeStringAt(uint64_t address, std::wstring* value)
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
                if (!ReadU16(address, &length))
                {
                    break;
                }
                uint64_t bufferField = 0;
                if (!TryAdd(address, 8, &bufferField) ||
                    !ReadU64(bufferField, &buffer))
                {
                    break;
                }
                if (length == 0 || buffer == 0)
                {
                    ok = true;
                    break;
                }
                if (length > 2048)
                {
                    length = 2048;
                }

                std::vector<uint8_t> bytes;
                if (!ReadKernelBytes(device_, buffer, length, &bytes, nullptr))
                {
                    break;
                }

                value->assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / sizeof(wchar_t));
                ok = true;
            } while (false);

            return ok;
        }

        bool FindField(const std::wstring& typeName, const std::vector<std::wstring>& names, TypeFieldInfo* field)
        {
            return ::FindField(symbols_, typeName, names, field);
        }

        bool ResolveSymbol(const std::wstring& name, uint64_t* address)
        {
            return symbols_.ResolveSymbol(name, address, nullptr);
        }

    private:
        DeviceClient& device_;
        SymbolEngine& symbols_;
    };

    struct ObjectTypeRecord
    {
        std::wstring Name;
        uint64_t Address = 0;
        uint8_t Index = 0;
    };

    struct ObjectHeaderLayout
    {
        TypeFieldInfo TypeIndex = {};
        TypeFieldInfo InfoMask = {};
        TypeFieldInfo Body = {};
    };

    struct DirectoryLayout
    {
        TypeFieldInfo HashBuckets = {};
        uint32_t BucketCount = kDefaultDirectoryBuckets;
    };

    struct DirectoryEntryLayout
    {
        TypeFieldInfo ChainLink = {};
        TypeFieldInfo Object = {};
    };

    bool ResolveObjectHeaderLayout(ObjectWalkContext& ctx, ObjectHeaderLayout* layout)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_HEADER", {L"TypeIndex"}, &layout->TypeIndex) ||
                !ctx.FindField(L"nt!_OBJECT_HEADER", {L"InfoMask"}, &layout->InfoMask) ||
                !ctx.FindField(L"nt!_OBJECT_HEADER", {L"Body"}, &layout->Body))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveDirectoryLayouts(ObjectWalkContext& ctx, DirectoryLayout* dir, DirectoryEntryLayout* entry)
    {
        bool ok = false;

        do
        {
            if (dir == nullptr || entry == nullptr)
            {
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_DIRECTORY", {L"HashBuckets"}, &dir->HashBuckets) ||
                !ctx.FindField(L"nt!_OBJECT_DIRECTORY_ENTRY", {L"ChainLink"}, &entry->ChainLink) ||
                !ctx.FindField(L"nt!_OBJECT_DIRECTORY_ENTRY", {L"Object"}, &entry->Object))
            {
                break;
            }

            uint32_t count = static_cast<uint32_t>(dir->HashBuckets.Length / sizeof(uint64_t));
            if (count == 0)
            {
                count = kDefaultDirectoryBuckets;
            }
            if (count > kMaxDirectoryBuckets)
            {
                count = kMaxDirectoryBuckets;
            }
            dir->BucketCount = count;
            ok = true;
        } while (false);

        return ok;
    }

    bool ComputeObjectHeader(const ObjectHeaderLayout& layout, uint64_t body, uint64_t* header)
    {
        return TrySub(body, layout.Body.Offset, header);
    }

    uint8_t DecodeTypeIndex(uint8_t raw, uint64_t headerAddress, uint8_t cookie, bool hasCookie)
    {
        if (!hasCookie)
        {
            return raw;
        }

        return static_cast<uint8_t>(raw ^ cookie ^ static_cast<uint8_t>((headerAddress >> 8) & 0xffu));
    }

    bool ReadObHeaderCookie(ObjectWalkContext& ctx, uint8_t* cookie, bool* hasCookie)
    {
        bool ok = false;

        do
        {
            if (cookie == nullptr || hasCookie == nullptr)
            {
                break;
            }

            *cookie = 0;
            *hasCookie = false;
            uint64_t address = 0;
            if (!ctx.ResolveSymbol(L"nt!ObHeaderCookie", &address))
            {
                ok = true;
                break;
            }

            if (!ctx.ReadU8(address, cookie))
            {
                ok = true;
                break;
            }

            *hasCookie = true;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadObjectName(ObjectWalkContext& ctx, const ObjectHeaderLayout& layout, uint64_t header, std::wstring* name)
    {
        bool ok = false;

        do
        {
            if (name == nullptr)
            {
                break;
            }

            name->clear();
            uint8_t infoMask = 0;
            uint64_t infoMaskAddress = 0;
            if (!TryAdd(header, layout.InfoMask.Offset, &infoMaskAddress) ||
                !ctx.ReadU8(infoMaskAddress, &infoMask))
            {
                break;
            }

            if ((infoMask & 0x02u) == 0)
            {
                ok = true;
                break;
            }

            uint8_t offset = kObpInfoMaskToOffset[infoMask & 0x3fu];
            uint64_t nameInfo = 0;
            if (!TrySub(header, offset, &nameInfo))
            {
                break;
            }

            TypeFieldInfo nameField = {};
            if (!ctx.FindField(L"nt!_OBJECT_HEADER_NAME_INFO", {L"Name"}, &nameField))
            {
                ok = true;
                break;
            }

            uint64_t unicodeAddress = 0;
            if (!TryAdd(nameInfo, nameField.Offset, &unicodeAddress))
            {
                break;
            }

            ctx.ReadUnicodeStringAt(unicodeAddress, name);
            ok = true;
        } while (false);

        return ok;
    }

    bool DiscoverObjectTypes(ObjectWalkContext& ctx, std::vector<ObjectTypeRecord>* types, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (types == nullptr)
            {
                break;
            }

            uint64_t table = 0;
            if (!ctx.ResolveSymbol(L"nt!ObTypeIndexTable", &table) &&
                !ctx.ResolveSymbol(L"nt!ObpTypeIndexTable", &table))
            {
                if (error != nullptr)
                {
                    *error = L"ObTypeIndexTable was not resolved";
                }
                break;
            }

            TypeFieldInfo nameField = {};
            if (!ctx.FindField(L"nt!_OBJECT_TYPE", {L"Name", L"TypeName"}, &nameField))
            {
                if (error != nullptr)
                {
                    *error = L"_OBJECT_TYPE.Name was not resolved";
                }
                break;
            }

            for (uint32_t index = 0; index < 256; ++index)
            {
                uint64_t slot = 0;
                if (!TryAdd(table, static_cast<uint64_t>(index) * sizeof(uint64_t), &slot))
                {
                    break;
                }

                uint64_t typeAddress = 0;
                if (!ctx.ReadU64(slot, &typeAddress))
                {
                    break;
                }
                if (typeAddress == 0 || !IsKernelAddress(typeAddress))
                {
                    continue;
                }

                std::wstring name;
                uint64_t nameAddress = 0;
                if (!TryAdd(typeAddress, nameField.Offset, &nameAddress) ||
                    !ctx.ReadUnicodeStringAt(nameAddress, &name) ||
                    name.empty())
                {
                    continue;
                }

                ObjectTypeRecord record = {};
                record.Name = name;
                record.Address = typeAddress;
                record.Index = static_cast<uint8_t>(index);
                types->push_back(record);
            }

            ok = !types->empty();
            if (!ok && error != nullptr)
            {
                *error = L"no object types were enumerated";
            }
        } while (false);

        return ok;
    }

    const ObjectTypeRecord* FindObjectType(const std::vector<ObjectTypeRecord>& types, const std::wstring& name)
    {
        const ObjectTypeRecord* found = nullptr;

        for (const ObjectTypeRecord& record : types)
        {
            if (EqualsNoCaseLocal(record.Name, name))
            {
                found = &record;
                break;
            }
        }

        return found;
    }

    bool ResolveRootDirectory(ObjectWalkContext& ctx, uint64_t* rootBody)
    {
        bool ok = false;

        do
        {
            if (rootBody == nullptr)
            {
                break;
            }

            uint64_t symbolAddress = 0;
            if (!ctx.ResolveSymbol(L"nt!ObpRootDirectoryObject", &symbolAddress))
            {
                break;
            }

            uint64_t body = 0;
            if (!ctx.ReadU64(symbolAddress, &body))
            {
                break;
            }

            if (!IsKernelAddress(body))
            {
                break;
            }

            *rootBody = body;
            ok = true;
        } while (false);

        return ok;
    }

    struct DirectoryObjectRecord
    {
        uint64_t Body = 0;
        std::wstring Name;
        std::wstring Path;
        uint8_t TypeIndex = 0;
    };

    bool EnumerateDirectory(
        ObjectWalkContext& ctx,
        const ObjectHeaderLayout& headerLayout,
        const DirectoryLayout& dirLayout,
        const DirectoryEntryLayout& entryLayout,
        uint64_t directoryBody,
        uint8_t cookie,
        bool hasCookie,
        const std::wstring& currentPath,
        std::vector<DirectoryObjectRecord>* records)
    {
        bool ok = false;

        do
        {
            if (records == nullptr || directoryBody == 0 || !IsKernelAddress(directoryBody))
            {
                break;
            }

            uint64_t bucketsBase = 0;
            if (!TryAdd(directoryBody, dirLayout.HashBuckets.Offset, &bucketsBase))
            {
                break;
            }

            for (uint32_t bucket = 0; bucket < dirLayout.BucketCount; ++bucket)
            {
                uint64_t bucketAddress = 0;
                if (!TryAdd(bucketsBase, static_cast<uint64_t>(bucket) * sizeof(uint64_t), &bucketAddress))
                {
                    break;
                }

                uint64_t entry = 0;
                if (!ctx.ReadU64(bucketAddress, &entry))
                {
                    continue;
                }

                uint32_t count = 0;
                while (entry != 0 && IsKernelAddress(entry) && count < kMaxDirectoryEntriesPerBucket)
                {
                    ++count;

                    uint64_t objectFieldAddress = 0;
                    uint64_t objectBody = 0;
                    if (TryAdd(entry, entryLayout.Object.Offset, &objectFieldAddress) &&
                        ctx.ReadU64(objectFieldAddress, &objectBody) &&
                        objectBody != 0 &&
                        IsKernelAddress(objectBody))
                    {
                        uint64_t header = 0;
                        uint8_t rawType = 0;
                        uint64_t typeIndexAddress = 0;
                        if (ComputeObjectHeader(headerLayout, objectBody, &header) &&
                            TryAdd(header, headerLayout.TypeIndex.Offset, &typeIndexAddress) &&
                            ctx.ReadU8(typeIndexAddress, &rawType))
                        {
                            std::wstring name;
                            ReadObjectName(ctx, headerLayout, header, &name);

                            DirectoryObjectRecord record = {};
                            record.Body = objectBody;
                            record.Name = name;
                            record.Path = currentPath;
                            if (!record.Path.empty() && record.Path.back() != L'\\')
                            {
                                record.Path.push_back(L'\\');
                            }
                            record.Path += name;
                            record.TypeIndex = DecodeTypeIndex(rawType, header, cookie, hasCookie);
                            records->push_back(record);
                        }
                    }

                    uint64_t nextFieldAddress = 0;
                    uint64_t next = 0;
                    if (!TryAdd(entry, entryLayout.ChainLink.Offset, &nextFieldAddress) ||
                        !ctx.ReadU64(nextFieldAddress, &next))
                    {
                        break;
                    }
                    entry = next;
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool FindDriverDirectory(
        ObjectWalkContext& ctx,
        const ObjectHeaderLayout& headerLayout,
        const DirectoryLayout& dirLayout,
        const DirectoryEntryLayout& entryLayout,
        uint8_t directoryTypeIndex,
        uint8_t cookie,
        bool hasCookie,
        uint64_t* driverDirectory,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (driverDirectory == nullptr)
            {
                break;
            }

            uint64_t root = 0;
            if (!ResolveRootDirectory(ctx, &root))
            {
                if (error != nullptr)
                {
                    *error = L"ObpRootDirectoryObject was not resolved";
                }
                break;
            }

            std::vector<DirectoryObjectRecord> rootRecords;
            if (!EnumerateDirectory(
                    ctx,
                    headerLayout,
                    dirLayout,
                    entryLayout,
                    root,
                    cookie,
                    hasCookie,
                    L"\\",
                    &rootRecords))
            {
                if (error != nullptr)
                {
                    *error = L"failed to enumerate root object directory";
                }
                break;
            }

            for (const DirectoryObjectRecord& record : rootRecords)
            {
                if (record.TypeIndex == directoryTypeIndex && EqualsNoCaseLocal(record.Name, L"Driver"))
                {
                    *driverDirectory = record.Body;
                    ok = true;
                    break;
                }
            }

            if (!ok && error != nullptr)
            {
                *error = L"\\Driver directory was not found";
            }
        } while (false);

        return ok;
    }

    bool ReadDriverRecord(
        DeviceClient& device,
        SymbolEngine& symbols,
        const DirectoryObjectRecord& object,
        const TypeFieldInfo& driverStartField,
        const TypeFieldInfo& driverSizeField,
        const TypeFieldInfo& driverSectionField,
        const TypeFieldInfo& deviceObjectField,
        const TypeFieldInfo& fastIoField,
        const TypeFieldInfo& unloadField,
        const TypeFieldInfo& majorFunctionField,
        DriverIntegrityRecord* record)
    {
        bool ok = false;

        do
        {
            if (record == nullptr)
            {
                break;
            }

            *record = DriverIntegrityRecord{};
            record->Name = object.Name;
            record->DirectoryPath = object.Path;
            record->DriverObject = object.Body;

            uint64_t value = 0;
            if (ReadFieldInteger(device, object.Body, driverStartField, sizeof(uint64_t), &value, nullptr))
            {
                record->DriverStart = value;
                record->HasDriverStart = value != 0;
            }
            if (ReadFieldInteger(device, object.Body, driverSizeField, sizeof(uint32_t), &value, nullptr))
            {
                record->DriverSize = value;
            }
            ReadFieldInteger(device, object.Body, driverSectionField, sizeof(uint64_t), &record->DriverSection, nullptr);
            ReadFieldInteger(device, object.Body, deviceObjectField, sizeof(uint64_t), &record->DeviceObject, nullptr);
            ReadFieldInteger(device, object.Body, fastIoField, sizeof(uint64_t), &record->FastIoDispatch, nullptr);
            ReadFieldInteger(device, object.Body, unloadField, sizeof(uint64_t), &record->DriverUnload, nullptr);

            const KernelModuleInfo* owner = nullptr;
            if (record->DriverStart != 0)
            {
                owner = FindModuleForAddress(symbols.Modules(), record->DriverStart);
                if (owner != nullptr)
                {
                    record->OwningModule = owner->ImageName;
                }
            }

            uint32_t dispatchCount = static_cast<uint32_t>(majorFunctionField.Length / sizeof(uint64_t));
            if (dispatchCount == 0 || dispatchCount > 32)
            {
                dispatchCount = 28;
            }

            uint64_t dispatchBase = 0;
            if (!TryAdd(object.Body, majorFunctionField.Offset, &dispatchBase))
            {
                record->Suspicious = true;
                record->Notes = L"MajorFunction field address overflow";
                ok = true;
                break;
            }

            for (uint32_t index = 0; index < dispatchCount; ++index)
            {
                uint64_t dispatchAddress = 0;
                if (!TryAdd(dispatchBase, static_cast<uint64_t>(index) * sizeof(uint64_t), &dispatchAddress))
                {
                    record->Suspicious = true;
                    record->Notes = L"MajorFunction entry address overflow";
                    break;
                }

                uint64_t function = 0;
                if (!ReadKernelInteger(device, dispatchAddress, sizeof(uint64_t), &function, nullptr))
                {
                    continue;
                }

                DriverDispatchRecord dispatch = {};
                dispatch.Index = index;
                dispatch.Name = MajorFunctionName(index);
                dispatch.Function = function;
                AnnotatePointer(symbols, function, &dispatch.ModuleName, &dispatch.SymbolName);
                dispatch.InLoadedModule = FindModuleForAddress(symbols.Modules(), function) != nullptr;

                uint64_t ownerStart = record->DriverStart;
                uint64_t ownerSize = record->DriverSize;
                if ((ownerStart == 0 || ownerSize == 0) && owner != nullptr)
                {
                    ownerStart = owner->Base;
                    ownerSize = owner->Size;
                }
                uint64_t ownerEnd = 0;
                dispatch.InOwningImage =
                    ownerStart != 0 &&
                    ownerSize != 0 &&
                    TryAdd(ownerStart, ownerSize, &ownerEnd) &&
                    function >= ownerStart &&
                    function < ownerEnd;

                if (function != 0 && !dispatch.InLoadedModule)
                {
                    dispatch.Suspicious = true;
                    dispatch.Notes = L"dispatch pointer is outside loaded kernel modules";
                }
                else if (function != 0 &&
                         !dispatch.InOwningImage &&
                         !dispatch.ModuleName.empty() &&
                         !IsKernelModuleName(dispatch.ModuleName))
                {
                    dispatch.Suspicious = true;
                    dispatch.Notes = L"dispatch pointer targets another non-kernel module";
                }

                if (dispatch.Suspicious)
                {
                    ++record->SuspiciousDispatchCount;
                    record->Suspicious = true;
                }

                record->Dispatch.push_back(dispatch);
            }

            if (record->HasDriverStart && owner == nullptr)
            {
                record->Suspicious = true;
                record->Notes = L"DriverStart is outside loaded module ranges";
            }

            ok = true;
        } while (false);

        return ok;
    }
}

IntegrityScanner::IntegrityScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool IntegrityScanner::ScanModules(const ModuleIntegrityOptions& options, ModuleIntegrityResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid module integrity result output";
            }
            break;
        }

        *result = ModuleIntegrityResult{};
        if (symbols_.Modules().empty())
        {
            if (!symbols_.LoadKernelModules(error))
            {
                break;
            }
        }

        for (const KernelModuleInfo& module : symbols_.Modules())
        {
            ++result->ModulesScanned;
            if (!ModuleMatches(module, options.ModuleFilter))
            {
                continue;
            }

            ++result->MatchingModules;
            ModuleIntegrityRecord record = {};
            record.ImageName = module.ImageName;
            record.ImagePath = module.ImagePath;
            record.Base = module.Base;
            record.Size = module.Size;

            std::vector<uint8_t> headerBytes;
            std::wstring readError;
            uint32_t readLength = 0x1000;
            if (module.Size != 0 && module.Size < readLength)
            {
                readLength = module.Size;
            }
            if (!ReadKernelBytes(device_, module.Base, readLength, &headerBytes, &readError))
            {
                AddRecordReason(&record, L"header_unreadable", L"header read failed: " + readError);
                record.MismatchEvidence = true;
            }
            else if (headerBytes.size() < sizeof(IMAGE_DOS_HEADER))
            {
                record.HeaderRead = true;
                AddRecordReason(&record, L"header_too_small", L"header read is smaller than IMAGE_DOS_HEADER");
                record.MismatchEvidence = true;
            }
            else
            {
                record.HeaderRead = true;
                const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headerBytes.data());
                record.MzOk = dos->e_magic == IMAGE_DOS_SIGNATURE;
                if (!record.MzOk)
                {
                    AddRecordReason(&record, L"invalid_mz", L"MZ signature mismatch");
                    record.MismatchEvidence = true;
                }
                else if (dos->e_lfanew < 0)
                {
                    AddRecordReason(&record, L"invalid_e_lfanew", L"negative e_lfanew");
                    record.MismatchEvidence = true;
                }
                else
                {
                    uint64_t ntOffset = static_cast<uint64_t>(dos->e_lfanew);
                    uint64_t fileHeaderOffset = 0;
                    uint64_t optionalHeaderOffset = 0;
                    if (!TryAdd(ntOffset, sizeof(uint32_t), &fileHeaderOffset) ||
                        !TryAdd(fileHeaderOffset, sizeof(IMAGE_FILE_HEADER), &optionalHeaderOffset))
                    {
                        AddRecordReason(&record, L"invalid_e_lfanew", L"NT header offset overflow");
                        record.MismatchEvidence = true;
                    }
                    else if (optionalHeaderOffset > headerBytes.size() ||
                             headerBytes.size() - static_cast<size_t>(ntOffset) < sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
                    {
                        AddRecordReason(&record, L"nt_header_outside_read", L"NT header outside readable header bytes");
                        record.MismatchEvidence = true;
                    }
                    else
                    {
                        const uint8_t* ntBytes = headerBytes.data() + ntOffset;
                        const uint32_t signature = *reinterpret_cast<const uint32_t*>(ntBytes);
                        record.PeOk = signature == IMAGE_NT_SIGNATURE;
                        if (!record.PeOk)
                        {
                            AddRecordReason(&record, L"invalid_pe_signature", L"PE signature mismatch");
                            record.MismatchEvidence = true;
                        }
                        else
                        {
                            const IMAGE_FILE_HEADER* fileHeader =
                                reinterpret_cast<const IMAGE_FILE_HEADER*>(headerBytes.data() + fileHeaderOffset);
                            record.Machine = fileHeader->Machine;
                            record.NumberOfSections = fileHeader->NumberOfSections;
                            const uint16_t optionalHeaderSize = fileHeader->SizeOfOptionalHeader;

                            if (record.Machine != IMAGE_FILE_MACHINE_AMD64)
                            {
                                AddRecordReason(&record, L"unexpected_machine", L"unexpected PE machine type");
                                record.MismatchEvidence = true;
                            }
                            if (record.NumberOfSections == 0 || record.NumberOfSections > 96)
                            {
                                AddRecordReason(&record, L"suspicious_section_count", L"suspicious section count");
                                record.MismatchEvidence = true;
                            }
                            if (optionalHeaderSize < sizeof(IMAGE_OPTIONAL_HEADER64))
                            {
                                AddRecordReason(&record, L"optional_header_too_small", L"optional header is smaller than IMAGE_OPTIONAL_HEADER64");
                                record.MismatchEvidence = true;
                            }

                            uint64_t optionalEnd = 0;
                            if (!TryAdd(optionalHeaderOffset, optionalHeaderSize, &optionalEnd) ||
                                optionalEnd > headerBytes.size())
                            {
                                AddRecordReason(&record, L"optional_header_outside_read", L"optional header outside readable header bytes");
                                record.MismatchEvidence = true;
                            }
                            else if (optionalHeaderSize >= sizeof(IMAGE_OPTIONAL_HEADER64))
                            {
                                const IMAGE_OPTIONAL_HEADER64* optional =
                                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(headerBytes.data() + optionalHeaderOffset);
                                record.OptionalHeaderMagic = optional->Magic;
                                record.SizeOfImage = optional->SizeOfImage;
                                record.SizeOfHeaders = optional->SizeOfHeaders;
                                record.SectionAlignment = optional->SectionAlignment;
                                record.FileAlignment = optional->FileAlignment;
                                record.NumberOfRvaAndSizes = optional->NumberOfRvaAndSizes;
                                record.PreferredImageBase = optional->ImageBase;
                                record.OptionalHeaderOk = optional->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

                                if (!record.OptionalHeaderOk)
                                {
                                    AddRecordReason(&record, L"unexpected_optional_header_magic", L"unexpected optional header magic");
                                    record.MismatchEvidence = true;
                                }
                                if (record.SizeOfImage == 0)
                                {
                                    AddRecordReason(&record, L"zero_size_of_image", L"PE SizeOfImage is zero");
                                    record.MismatchEvidence = true;
                                }
                                if (record.SizeOfHeaders == 0)
                                {
                                    AddRecordReason(&record, L"zero_size_of_headers", L"PE SizeOfHeaders is zero");
                                    record.MismatchEvidence = true;
                                }
                                if (record.SizeOfImage != 0 && record.SizeOfHeaders > record.SizeOfImage)
                                {
                                    AddRecordReason(&record, L"headers_outside_image", L"SizeOfHeaders exceeds SizeOfImage");
                                    record.MismatchEvidence = true;
                                }
                                if (record.SectionAlignment == 0)
                                {
                                    AddRecordReason(&record, L"zero_section_alignment", L"SectionAlignment is zero");
                                    record.MismatchEvidence = true;
                                }
                                else if (!IsPowerOfTwo32(record.SectionAlignment))
                                {
                                    AddRecordReason(&record, L"invalid_section_alignment", L"SectionAlignment is not a power of two");
                                    record.MismatchEvidence = true;
                                }
                                if (record.FileAlignment == 0)
                                {
                                    AddRecordReason(&record, L"zero_file_alignment", L"FileAlignment is zero");
                                    record.MismatchEvidence = true;
                                }
                                else if (!IsPowerOfTwo32(record.FileAlignment) ||
                                         record.FileAlignment < 0x200 ||
                                         record.FileAlignment > 0x10000)
                                {
                                    AddRecordReason(&record, L"invalid_file_alignment", L"FileAlignment is outside the PE alignment range");
                                    record.MismatchEvidence = true;
                                }
                                if (record.SectionAlignment != 0 &&
                                    record.FileAlignment != 0 &&
                                    record.SectionAlignment < record.FileAlignment)
                                {
                                    AddRecordReason(&record, L"section_alignment_lt_file_alignment", L"SectionAlignment is smaller than FileAlignment");
                                    record.MismatchEvidence = true;
                                }
                                if (record.PreferredImageBase != 0 && record.PreferredImageBase != module.Base)
                                {
                                    record.ImageBaseMismatch = true;
                                    AddRecordInfo(&record, L"image_base_relocated", L"preferred ImageBase differs from loaded base");
                                }
                                if (record.SizeOfImage != 0 && module.Size != 0)
                                {
                                    uint32_t delta = record.SizeOfImage > module.Size
                                        ? record.SizeOfImage - module.Size
                                        : module.Size - record.SizeOfImage;
                                    if (delta > 0x1000)
                                    {
                                        record.SizeMismatch = true;
                                        record.MismatchEvidence = true;
                                        AddRecordReason(&record, L"size_of_image_mismatch", L"module list size differs from PE SizeOfImage");
                                    }
                                }

                                const uint32_t directoryCount =
                                    record.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES
                                        ? record.NumberOfRvaAndSizes
                                        : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
                                for (uint32_t directoryIndex = 0; directoryIndex < directoryCount; ++directoryIndex)
                                {
                                    if (directoryIndex == IMAGE_DIRECTORY_ENTRY_SECURITY)
                                    {
                                        continue;
                                    }

                                    const IMAGE_DATA_DIRECTORY& directory = optional->DataDirectory[directoryIndex];
                                    if (directory.Size != 0 && directory.VirtualAddress == 0)
                                    {
                                        AddRecordReason(&record, L"data_directory_zero_rva", L"non-empty data directory has zero RVA");
                                        record.MismatchEvidence = true;
                                        break;
                                    }

                                    if (directory.VirtualAddress == 0 || directory.Size == 0 || record.SizeOfImage == 0)
                                    {
                                        continue;
                                    }

                                    uint64_t directoryEnd = 0;
                                    if (!TryAdd(directory.VirtualAddress, directory.Size, &directoryEnd) ||
                                        directory.VirtualAddress >= record.SizeOfImage ||
                                        directoryEnd > record.SizeOfImage)
                                    {
                                        AddRecordReason(&record, L"data_directory_outside_image", L"data directory extends outside SizeOfImage");
                                        record.MismatchEvidence = true;
                                        break;
                                    }
                                }
                            }

                            uint64_t sectionTable = 0;
                            uint64_t sectionBytes = 0;
                            uint64_t sectionEnd = 0;
                            if (TryAdd(optionalHeaderOffset, optionalHeaderSize, &sectionTable) &&
                                TryAdd(static_cast<uint64_t>(record.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), 0, &sectionBytes) &&
                                TryAdd(sectionTable, sectionBytes, &sectionEnd))
                            {
                                uint64_t desiredRead = sectionEnd;
                                if (record.SizeOfHeaders != 0 && record.SizeOfHeaders > desiredRead)
                                {
                                    desiredRead = record.SizeOfHeaders;
                                }
                                if (desiredRead > headerBytes.size() && desiredRead <= kMaxRawRead)
                                {
                                    if (module.Size != 0 && desiredRead > module.Size)
                                    {
                                        desiredRead = module.Size;
                                    }
                                    if (desiredRead > headerBytes.size() && desiredRead <= kMaxRawRead)
                                    {
                                        std::vector<uint8_t> largerHeader;
                                        std::wstring largerReadError;
                                        if (ReadKernelBytes(device_, module.Base, static_cast<uint32_t>(desiredRead), &largerHeader, &largerReadError))
                                        {
                                            headerBytes.swap(largerHeader);
                                        }
                                        else
                                        {
                                            result->Warnings.push_back(record.ImageName + L": extended header read failed: " + largerReadError);
                                        }
                                    }
                                }
                            }

                            if (!TryAdd(optionalHeaderOffset, optionalHeaderSize, &sectionTable) ||
                                !TryAdd(static_cast<uint64_t>(record.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), 0, &sectionBytes) ||
                                !TryAdd(sectionTable, sectionBytes, &sectionEnd) ||
                                record.NumberOfSections == 0 ||
                                record.NumberOfSections > 96 ||
                                sectionEnd > headerBytes.size())
                            {
                                AddRecordReason(&record, L"section_table_unavailable", L"section table is outside readable header bytes");
                                record.MismatchEvidence = true;
                            }
                            else
                            {
                                record.SectionTableOk = true;
                                const IMAGE_SECTION_HEADER* sections =
                                    reinterpret_cast<const IMAGE_SECTION_HEADER*>(headerBytes.data() + sectionTable);

                                for (uint16_t i = 0; i < record.NumberOfSections; ++i)
                                {
                                    ModuleIntegritySectionRecord section = {};
                                    section.Name = SectionName(sections[i]);
                                    section.VirtualAddress = sections[i].VirtualAddress;
                                    section.VirtualSize = sections[i].Misc.VirtualSize;
                                    section.RawSize = sections[i].SizeOfRawData;
                                    section.PointerToRawData = sections[i].PointerToRawData;
                                    section.Characteristics = sections[i].Characteristics;
                                    section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                                    section.Writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                                    section.Readable = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;

                                    const uint64_t span = SectionVirtualSpan(sections[i]);
                                    uint64_t sectionEndRva = 0;
                                    if (span == 0 && section.Executable)
                                    {
                                        section.MismatchEvidence = true;
                                        AddSectionReason(&section, L"zero_size_executable_section", L"executable section has zero virtual/raw size");
                                    }
                                    if (span != 0 &&
                                        (!TryAdd(section.VirtualAddress, span, &sectionEndRva) ||
                                         (record.SizeOfImage != 0 && sectionEndRva > record.SizeOfImage)))
                                    {
                                        section.RangeValid = false;
                                        section.MismatchEvidence = true;
                                        AddSectionReason(&section, L"section_range_outside_image", L"section virtual range is outside SizeOfImage");
                                    }

                                    if (section.Executable && section.Writable)
                                    {
                                        section.WxEvidence = true;
                                        AddSectionReason(&section, L"static_wx_section", L"section characteristics are W+X");
                                    }

                                    if ((section.Executable || EqualsNoCaseLocal(section.Name, L".text")) &&
                                        span != 0 &&
                                        section.RangeValid)
                                    {
                                        uint64_t sectionAddress = 0;
                                        if (!TryAdd(module.Base, section.VirtualAddress, &sectionAddress))
                                        {
                                            section.MismatchEvidence = true;
                                            AddSectionReason(&section, L"section_rva_overflow", L"section RVA overflow");
                                        }
                                        else
                                        {
                                            ModulePageAttributes firstProbe = {};
                                            if (QueryEffectivePageAttributes(device_, sectionAddress, 1, &firstProbe))
                                            {
                                                section.FirstPageQueried = true;
                                                section.FirstPageReadable = firstProbe.Readable;
                                                section.FirstPageWritable = firstProbe.Writable;
                                                section.FirstPageExecutable = firstProbe.Executable;
                                                section.FirstPageLargePage = firstProbe.LargePage;
                                                section.FirstPagePagingLevels = firstProbe.PagingLevels;
                                                section.PageAttributesQueried = true;
                                                section.EffectiveReadable = section.EffectiveReadable || firstProbe.Readable;
                                                section.EffectiveWritable = section.EffectiveWritable || firstProbe.Writable;
                                                section.EffectiveExecutable = section.EffectiveExecutable || firstProbe.Executable;
                                                if (firstProbe.Writable && firstProbe.Executable)
                                                {
                                                    section.WxEvidence = true;
                                                    AddSectionReason(&section, L"effective_wx_page", L"first executable page is effective W+X");
                                                }
                                            }
                                            else
                                            {
                                                section.FirstPageQueryFailed = true;
                                                section.PageAttributeQueryFailed = true;
                                                section.PageAttributeError = firstProbe.Error;
                                                if (section.Executable)
                                                {
                                                    section.MismatchEvidence = true;
                                                    AddSectionReason(&section, L"exec_first_page_query_failed", L"first executable page translation failed");
                                                }
                                            }

                                            if (span > 0x1000)
                                            {
                                                uint64_t lastAddress = 0;
                                                if (!TryAdd(sectionAddress, span - 1, &lastAddress))
                                                {
                                                    section.MismatchEvidence = true;
                                                    AddSectionReason(&section, L"section_last_page_overflow", L"section last page address overflow");
                                                }
                                                else
                                                {
                                                    ModulePageAttributes lastProbe = {};
                                                    if (QueryEffectivePageAttributes(device_, lastAddress, 1, &lastProbe))
                                                    {
                                                        section.LastPageQueried = true;
                                                        section.LastPageReadable = lastProbe.Readable;
                                                        section.LastPageWritable = lastProbe.Writable;
                                                        section.LastPageExecutable = lastProbe.Executable;
                                                        section.LastPageLargePage = lastProbe.LargePage;
                                                        section.LastPagePagingLevels = lastProbe.PagingLevels;
                                                        section.PageAttributesQueried = true;
                                                        section.EffectiveReadable = section.EffectiveReadable || lastProbe.Readable;
                                                        section.EffectiveWritable = section.EffectiveWritable || lastProbe.Writable;
                                                        section.EffectiveExecutable = section.EffectiveExecutable || lastProbe.Executable;
                                                        if (lastProbe.Writable && lastProbe.Executable)
                                                        {
                                                            section.WxEvidence = true;
                                                            AddSectionReason(&section, L"effective_wx_page", L"last executable page is effective W+X");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        section.LastPageQueryFailed = true;
                                                        section.PageAttributeQueryFailed = true;
                                                        if (section.PageAttributeError.empty())
                                                        {
                                                            section.PageAttributeError = lastProbe.Error;
                                                        }
                                                        if (section.Executable)
                                                        {
                                                            section.MismatchEvidence = true;
                                                            AddSectionReason(&section, L"exec_last_page_query_failed", L"last executable page translation failed");
                                                        }
                                                    }
                                                }
                                            }

                                            // Sample interior pages so inline hooks past the first
                                            // page and before the last page are not invisible.
                                            constexpr uint64_t kIntegrityPageSize = 0x1000ull;
                                            constexpr uint32_t kMaxMidPageSamples = 8u;
                                            if (span > (kIntegrityPageSize * 2ull))
                                            {
                                                const uint64_t pageCount = span / kIntegrityPageSize;
                                                if (pageCount > 2ull)
                                                {
                                                    const uint64_t interiorPages = pageCount - 2ull;
                                                    const uint32_t sampleCount =
                                                        interiorPages < kMaxMidPageSamples
                                                            ? static_cast<uint32_t>(interiorPages)
                                                            : kMaxMidPageSamples;
                                                    for (uint32_t sample = 0; sample < sampleCount; ++sample)
                                                    {
                                                        uint64_t pageIndex = 1ull;
                                                        if (sampleCount == 1)
                                                        {
                                                            pageIndex = 1ull + (interiorPages / 2ull);
                                                        }
                                                        else
                                                        {
                                                            pageIndex = 1ull +
                                                                ((static_cast<uint64_t>(sample) * (interiorPages - 1ull)) /
                                                                 static_cast<uint64_t>(sampleCount - 1u));
                                                        }

                                                        uint64_t midOffset = 0;
                                                        uint64_t midAddress = 0;
                                                        if (!TryAdd(0, pageIndex * kIntegrityPageSize, &midOffset) ||
                                                            !TryAdd(sectionAddress, midOffset, &midAddress) ||
                                                            midOffset >= span)
                                                        {
                                                            continue;
                                                        }

                                                        ModulePageAttributes midProbe = {};
                                                        if (QueryEffectivePageAttributes(device_, midAddress, 1, &midProbe))
                                                        {
                                                            ++section.MidPagesQueried;
                                                            section.PageAttributesQueried = true;
                                                            section.EffectiveReadable =
                                                                section.EffectiveReadable || midProbe.Readable;
                                                            section.EffectiveWritable =
                                                                section.EffectiveWritable || midProbe.Writable;
                                                            section.EffectiveExecutable =
                                                                section.EffectiveExecutable || midProbe.Executable;
                                                            if (midProbe.Writable && midProbe.Executable)
                                                            {
                                                                ++section.MidPagesWx;
                                                                section.WxEvidence = true;
                                                                if (section.MidPagesWx == 1)
                                                                {
                                                                    AddSectionReason(
                                                                        &section,
                                                                        L"effective_wx_mid_page",
                                                                        L"interior executable page is effective W+X");
                                                                }
                                                            }
                                                        }
                                                        else
                                                        {
                                                            ++section.MidPagesQueryFailed;
                                                            section.PageAttributeQueryFailed = true;
                                                            if (section.PageAttributeError.empty())
                                                            {
                                                                section.PageAttributeError = midProbe.Error;
                                                            }
                                                            if (section.Executable)
                                                            {
                                                                section.MismatchEvidence = true;
                                                                AddSectionReason(
                                                                    &section,
                                                                    L"exec_mid_page_query_failed",
                                                                    L"interior executable page translation failed");
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Optional live-vs-disk page compare for executable sections.
                                    if (options.CompareDiskPages &&
                                        section.Executable &&
                                        section.RangeValid &&
                                        section.PointerToRawData != 0 &&
                                        section.RawSize != 0 &&
                                        !record.ImagePath.empty())
                                    {
                                        section.DiskCompareAttempted = true;
                                        const uint32_t pageCount =
                                            options.DiskPagesPerSection == 0 ? 2u : options.DiskPagesPerSection;
                                        HANDLE file = CreateFileW(
                                            record.ImagePath.c_str(),
                                            GENERIC_READ,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL,
                                            nullptr);
                                        if (file == INVALID_HANDLE_VALUE)
                                        {
                                            section.DiskCompareFailed = true;
                                            AddSectionReason(
                                                &section,
                                                L"disk_open_failed",
                                                L"could not open module image on disk for page compare");
                                        }
                                        else
                                        {
                                            for (uint32_t pageIndex = 0; pageIndex < pageCount; ++pageIndex)
                                            {
                                                uint32_t pageRvaOffset = 0;
                                                if (pageIndex == 0)
                                                {
                                                    pageRvaOffset = 0;
                                                }
                                                else if (span > 0x1000)
                                                {
                                                    pageRvaOffset = static_cast<uint32_t>(
                                                        ((span / 0x1000) / 2) * 0x1000);
                                                    if (pageRvaOffset >= span)
                                                    {
                                                        pageRvaOffset = 0x1000;
                                                    }
                                                }
                                                else
                                                {
                                                    break;
                                                }

                                                if (pageRvaOffset >= section.RawSize)
                                                {
                                                    break;
                                                }

                                                const uint32_t fileOffset = section.PointerToRawData + pageRvaOffset;
                                                const uint32_t readLen = static_cast<uint32_t>(
                                                    (section.RawSize - pageRvaOffset) < 0x1000
                                                        ? (section.RawSize - pageRvaOffset)
                                                        : 0x1000);
                                                if (readLen == 0)
                                                {
                                                    break;
                                                }

                                                LARGE_INTEGER seek = {};
                                                seek.QuadPart = static_cast<LONGLONG>(fileOffset);
                                                if (!SetFilePointerEx(file, seek, nullptr, FILE_BEGIN))
                                                {
                                                    section.DiskCompareFailed = true;
                                                    AddSectionReason(
                                                        &section,
                                                        L"disk_seek_failed",
                                                        L"disk page seek failed");
                                                    break;
                                                }

                                                std::vector<uint8_t> diskPage(readLen);
                                                DWORD got = 0;
                                                if (!ReadFile(file, diskPage.data(), readLen, &got, nullptr) ||
                                                    got != readLen)
                                                {
                                                    section.DiskCompareFailed = true;
                                                    AddSectionReason(
                                                        &section,
                                                        L"disk_read_failed",
                                                        L"disk page read failed");
                                                    break;
                                                }

                                                uint64_t liveAddress = 0;
                                                if (!TryAdd(module.Base, section.VirtualAddress, &liveAddress) ||
                                                    !TryAdd(liveAddress, pageRvaOffset, &liveAddress))
                                                {
                                                    section.DiskCompareFailed = true;
                                                    break;
                                                }

                                                std::vector<uint8_t> livePage;
                                                std::wstring liveError;
                                                if (!device_.ReadMemory(liveAddress, readLen, &livePage, &liveError) ||
                                                    livePage.size() != readLen)
                                                {
                                                    section.DiskCompareFailed = true;
                                                    AddSectionReason(
                                                        &section,
                                                        L"live_read_failed",
                                                        L"live page read failed during disk compare");
                                                    break;
                                                }

                                                if (memcmp(livePage.data(), diskPage.data(), readLen) != 0)
                                                {
                                                    section.DiskCompareMismatch = true;
                                                    section.MismatchEvidence = true;
                                                    AddSectionReason(
                                                        &section,
                                                        L"disk_live_page_mismatch",
                                                        L"live executable page differs from on-disk PE raw data");
                                                    break;
                                                }

                                                section.DiskCompareMatched = true;
                                            }
                                            CloseHandle(file);
                                        }
                                    }

                                    if (section.Suspicious)
                                    {
                                        AddUnique(&record.ReasonCodes, L"section_anomaly");
                                        record.Suspicious = true;
                                    }
                                    if (section.WxEvidence)
                                    {
                                        record.WxEvidence = true;
                                    }
                                    if (section.MismatchEvidence)
                                    {
                                        record.MismatchEvidence = true;
                                    }
                                    record.Sections.push_back(section);
                                }

                                std::vector<size_t> order;
                                for (size_t sectionIndex = 0; sectionIndex < record.Sections.size(); ++sectionIndex)
                                {
                                    const uint64_t span = record.Sections[sectionIndex].VirtualSize != 0
                                        ? record.Sections[sectionIndex].VirtualSize
                                        : record.Sections[sectionIndex].RawSize;
                                    if (span != 0 && record.Sections[sectionIndex].RangeValid)
                                    {
                                        order.push_back(sectionIndex);
                                    }
                                }
                                std::sort(
                                    order.begin(),
                                    order.end(),
                                    [&record](size_t left, size_t right)
                                    {
                                        return record.Sections[left].VirtualAddress < record.Sections[right].VirtualAddress;
                                    });

                                uint64_t previousEnd = 0;
                                bool hasPrevious = false;
                                for (size_t sectionIndex : order)
                                {
                                    const uint64_t span = record.Sections[sectionIndex].VirtualSize != 0
                                        ? record.Sections[sectionIndex].VirtualSize
                                        : record.Sections[sectionIndex].RawSize;
                                    uint64_t currentEnd = 0;
                                    if (!TryAdd(record.Sections[sectionIndex].VirtualAddress, span, &currentEnd))
                                    {
                                        continue;
                                    }
                                    if (hasPrevious && record.Sections[sectionIndex].VirtualAddress < previousEnd)
                                    {
                                        record.Sections[sectionIndex].OverlapsPrevious = true;
                                        record.Sections[sectionIndex].MismatchEvidence = true;
                                        AddSectionReason(&record.Sections[sectionIndex], L"overlapping_section_range", L"section virtual range overlaps a previous section");
                                        record.Suspicious = true;
                                        record.MismatchEvidence = true;
                                        AddUnique(&record.ReasonCodes, L"section_anomaly");
                                    }
                                    if (!hasPrevious || currentEnd > previousEnd)
                                    {
                                        previousEnd = currentEnd;
                                        hasPrevious = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (record.MismatchEvidence)
            {
                AddUnique(&record.ReasonCodes, L"module_mismatch");
            }
            if (record.WxEvidence)
            {
                AddUnique(&record.ReasonCodes, L"module_wx");
            }
            if (record.Suspicious)
            {
                ++result->SuspiciousModules;
            }
            if (record.WxEvidence)
            {
                ++result->WxModules;
            }
            if (record.MismatchEvidence)
            {
                ++result->MismatchModules;
            }

            const bool passesWx = !options.WxOnly || record.WxEvidence;
            const bool passesMismatch = !options.MismatchOnly || record.MismatchEvidence;
            if (passesWx && passesMismatch)
            {
                ++result->ReportedModules;
                if (options.Limit != 0 && result->Records.size() >= options.Limit)
                {
                    result->Truncated = true;
                    continue;
                }

                result->Records.push_back(record);
            }
        }

        ok = true;
    } while (false);

    return ok;
}

bool IntegrityScanner::ScanDrivers(const DriverIntegrityOptions& options, DriverIntegrityResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid driver integrity result output";
            }
            break;
        }

        *result = DriverIntegrityResult{};
        if (symbols_.Modules().empty())
        {
            if (!symbols_.LoadKernelModules(error))
            {
                break;
            }
        }

        ObjectWalkContext ctx(device_, symbols_);
        ObjectHeaderLayout headerLayout = {};
        DirectoryLayout dirLayout = {};
        DirectoryEntryLayout entryLayout = {};
        if (!ResolveObjectHeaderLayout(ctx, &headerLayout) ||
            !ResolveDirectoryLayouts(ctx, &dirLayout, &entryLayout))
        {
            if (error != nullptr)
            {
                *error = L"object directory layouts were not resolved";
            }
            break;
        }

        std::vector<ObjectTypeRecord> types;
        if (!DiscoverObjectTypes(ctx, &types, error))
        {
            break;
        }

        const ObjectTypeRecord* directoryType = FindObjectType(types, L"Directory");
        const ObjectTypeRecord* driverType = FindObjectType(types, L"Driver");
        if (directoryType == nullptr || driverType == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Directory or Driver object type was not found";
            }
            break;
        }

        uint8_t cookie = 0;
        bool hasCookie = false;
        ReadObHeaderCookie(ctx, &cookie, &hasCookie);
        if (!hasCookie)
        {
            result->Warnings.push_back(L"ObHeaderCookie not available; using raw object type indices");
        }

        uint64_t driverDirectory = 0;
        if (!FindDriverDirectory(
                ctx,
                headerLayout,
                dirLayout,
                entryLayout,
                directoryType->Index,
                cookie,
                hasCookie,
                &driverDirectory,
                error))
        {
            break;
        }

        std::vector<DirectoryObjectRecord> objects;
        if (!EnumerateDirectory(
                ctx,
                headerLayout,
                dirLayout,
                entryLayout,
                driverDirectory,
                cookie,
                hasCookie,
                L"\\Driver",
                &objects))
        {
            if (error != nullptr)
            {
                *error = L"failed to enumerate \\Driver";
            }
            break;
        }

        TypeFieldInfo driverStart = {};
        TypeFieldInfo driverSize = {};
        TypeFieldInfo driverSection = {};
        TypeFieldInfo deviceObject = {};
        TypeFieldInfo fastIoDispatch = {};
        TypeFieldInfo driverUnload = {};
        TypeFieldInfo majorFunction = {};
        if (!FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"DriverStart"}, &driverStart) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"DriverSize"}, &driverSize) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"DriverSection"}, &driverSection) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"DeviceObject"}, &deviceObject) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"FastIoDispatch"}, &fastIoDispatch) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"DriverUnload"}, &driverUnload) ||
            !FindField(symbols_, L"nt!_DRIVER_OBJECT", {L"MajorFunction"}, &majorFunction))
        {
            if (error != nullptr)
            {
                *error = L"_DRIVER_OBJECT field layout was not resolved";
            }
            break;
        }

        for (const DirectoryObjectRecord& object : objects)
        {
            if (object.TypeIndex != driverType->Index)
            {
                continue;
            }

            ++result->DriversScanned;
            if (!DriverMatches(object.Name, object.Path, options.DriverFilter))
            {
                continue;
            }

            if (options.Limit != 0 && result->Records.size() >= options.Limit)
            {
                result->Truncated = true;
                break;
            }

            if (result->DriversScanned >= kMaxDriverObjects)
            {
                result->Warnings.push_back(L"driver object scan hit safety limit");
                result->Truncated = true;
                break;
            }

            ++result->MatchingDrivers;
            DriverIntegrityRecord record = {};
            if (ReadDriverRecord(
                    device_,
                    symbols_,
                    object,
                    driverStart,
                    driverSize,
                    driverSection,
                    deviceObject,
                    fastIoDispatch,
                    driverUnload,
                    majorFunction,
                    &record))
            {
                if (record.Suspicious)
                {
                    ++result->SuspiciousDrivers;
                }
                result->Records.push_back(record);
            }
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildModuleIntegrityJson(const ModuleIntegrityResult& result)
{
    std::wstringstream json;
    auto writeStringArray = [&json](const std::vector<std::wstring>& values)
    {
        json << L"[";
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                json << L",";
            }
            json << L"\"" << JsonEscape(values[index]) << L"\"";
        }
        json << L"]";
    };

    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.module-integrity.v1\",\n";
    json << L"  \"summary\":{\"modules_scanned\":" << result.ModulesScanned
         << L",\"matching_modules\":" << result.MatchingModules
         << L",\"reported_modules\":" << result.ReportedModules
         << L",\"suspicious_modules\":" << result.SuspiciousModules
         << L",\"wx_modules\":" << result.WxModules
         << L",\"mismatch_modules\":" << result.MismatchModules
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},\n";
    json << L"  \"warnings\":";
    writeStringArray(result.Warnings);
    json << L",\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ModuleIntegrityRecord& record = result.Records[i];
        json << L"    {\"image\":\"" << JsonEscape(record.ImageName)
             << L"\",\"path\":\"" << JsonEscape(record.ImagePath)
             << L"\",\"base\":\"" << Hex(record.Base, 16)
             << L"\",\"size\":" << record.Size
             << L",\"header\":{\"read\":" << (record.HeaderRead ? L"true" : L"false")
             << L",\"mz_ok\":" << (record.MzOk ? L"true" : L"false")
             << L",\"pe_ok\":" << (record.PeOk ? L"true" : L"false")
             << L",\"optional_header_ok\":" << (record.OptionalHeaderOk ? L"true" : L"false")
             << L",\"section_table_ok\":" << (record.SectionTableOk ? L"true" : L"false")
             << L",\"machine\":\"" << Hex(record.Machine, 4)
             << L"\",\"optional_magic\":\"" << Hex(record.OptionalHeaderMagic, 4)
             << L"\",\"preferred_image_base\":\"" << Hex(record.PreferredImageBase, 16)
             << L"\",\"size_of_image\":" << record.SizeOfImage
             << L",\"size_of_headers\":" << record.SizeOfHeaders
             << L",\"section_alignment\":" << record.SectionAlignment
             << L",\"file_alignment\":" << record.FileAlignment
             << L",\"number_of_rva_and_sizes\":" << record.NumberOfRvaAndSizes
             << L",\"number_of_sections\":" << record.NumberOfSections
             << L"}"
             << L",\"size_mismatch\":" << (record.SizeMismatch ? L"true" : L"false")
             << L",\"image_base_relocated\":" << (record.ImageBaseMismatch ? L"true" : L"false")
             << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false")
             << L",\"wx_evidence\":" << (record.WxEvidence ? L"true" : L"false")
             << L",\"mismatch_evidence\":" << (record.MismatchEvidence ? L"true" : L"false")
             << L",\"reason_codes\":";
        writeStringArray(record.ReasonCodes);
        json << L",\"info_codes\":";
        writeStringArray(record.InfoCodes);
        json << L",\"notes\":\"" << JsonEscape(record.Notes)
             << L"\",\"sections\":[";
        for (size_t s = 0; s < record.Sections.size(); ++s)
        {
            const ModuleIntegritySectionRecord& section = record.Sections[s];
            if (s != 0)
            {
                json << L",";
            }
            json << L"{\"name\":\"" << JsonEscape(section.Name)
                 << L"\",\"rva\":\"" << Hex(section.VirtualAddress)
                 << L"\",\"virtual_size\":" << section.VirtualSize
                 << L",\"raw_size\":" << section.RawSize
                 << L",\"characteristics\":\"" << Hex(section.Characteristics, 8)
                 << L"\",\"executable\":" << (section.Executable ? L"true" : L"false")
                 << L",\"writable\":" << (section.Writable ? L"true" : L"false")
                 << L",\"readable\":" << (section.Readable ? L"true" : L"false")
                 << L",\"range_valid\":" << (section.RangeValid ? L"true" : L"false")
                 << L",\"overlaps_previous\":" << (section.OverlapsPrevious ? L"true" : L"false")
                 << L",\"effective_writable\":" << (section.EffectiveWritable ? L"true" : L"false")
                 << L",\"effective_executable\":" << (section.EffectiveExecutable ? L"true" : L"false")
                 << L",\"effective_readable\":" << (section.EffectiveReadable ? L"true" : L"false")
                 << L",\"page_attributes_queried\":" << (section.PageAttributesQueried ? L"true" : L"false")
                 << L",\"page_attribute_query_failed\":" << (section.PageAttributeQueryFailed ? L"true" : L"false")
                 << L",\"first_page\":{\"queried\":" << (section.FirstPageQueried ? L"true" : L"false")
                 << L",\"query_failed\":" << (section.FirstPageQueryFailed ? L"true" : L"false")
                 << L",\"readable\":" << (section.FirstPageReadable ? L"true" : L"false")
                 << L",\"writable\":" << (section.FirstPageWritable ? L"true" : L"false")
                 << L",\"executable\":" << (section.FirstPageExecutable ? L"true" : L"false")
                 << L",\"large_page\":" << (section.FirstPageLargePage ? L"true" : L"false")
                 << L",\"paging_levels\":" << section.FirstPagePagingLevels << L"}"
                 << L",\"last_page\":{\"queried\":" << (section.LastPageQueried ? L"true" : L"false")
                 << L",\"query_failed\":" << (section.LastPageQueryFailed ? L"true" : L"false")
                 << L",\"readable\":" << (section.LastPageReadable ? L"true" : L"false")
                 << L",\"writable\":" << (section.LastPageWritable ? L"true" : L"false")
                 << L",\"executable\":" << (section.LastPageExecutable ? L"true" : L"false")
                 << L",\"large_page\":" << (section.LastPageLargePage ? L"true" : L"false")
                 << L",\"paging_levels\":" << section.LastPagePagingLevels << L"}"
                 << L",\"suspicious\":" << (section.Suspicious ? L"true" : L"false")
                 << L",\"wx_evidence\":" << (section.WxEvidence ? L"true" : L"false")
                 << L",\"mismatch_evidence\":" << (section.MismatchEvidence ? L"true" : L"false")
                 << L",\"page_attribute_error\":\"" << JsonEscape(section.PageAttributeError)
                 << L"\",\"reason_codes\":";
            writeStringArray(section.ReasonCodes);
            json << L",\"notes\":\"" << JsonEscape(section.Notes) << L"\"}";
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

std::wstring BuildDriverIntegrityJson(const DriverIntegrityResult& result)
{
    std::wstringstream json;
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.driver-integrity.v1\",\n";
    json << L"  \"summary\":{\"drivers_scanned\":" << result.DriversScanned
         << L",\"matching_drivers\":" << result.MatchingDrivers
         << L",\"suspicious_drivers\":" << result.SuspiciousDrivers
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const DriverIntegrityRecord& record = result.Records[i];
        json << L"    {\"name\":\"" << JsonEscape(record.Name)
             << L"\",\"object\":\"" << Hex(record.DriverObject, 16)
             << L"\",\"driver_start\":\"" << Hex(record.DriverStart, 16)
             << L"\",\"driver_size\":" << record.DriverSize
             << L",\"owning_module\":\"" << JsonEscape(record.OwningModule)
             << L"\",\"suspicious\":" << (record.Suspicious ? L"true" : L"false")
             << L",\"suspicious_dispatch_count\":" << record.SuspiciousDispatchCount
             << L",\"dispatch\":[";
        for (size_t d = 0; d < record.Dispatch.size(); ++d)
        {
            const DriverDispatchRecord& dispatch = record.Dispatch[d];
            if (d != 0)
            {
                json << L",";
            }
            json << L"{\"index\":" << dispatch.Index
                 << L",\"name\":\"" << JsonEscape(dispatch.Name)
                 << L"\",\"function\":\"" << Hex(dispatch.Function, 16)
                 << L"\",\"module\":\"" << JsonEscape(dispatch.ModuleName)
                 << L"\",\"symbol\":\"" << JsonEscape(dispatch.SymbolName)
                 << L"\",\"suspicious\":" << (dispatch.Suspicious ? L"true" : L"false")
                 << L"}";
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
