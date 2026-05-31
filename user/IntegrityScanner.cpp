#include "IntegrityScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <unordered_set>

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
                result.push_back(ch);
                break;
            }
        }

        return result;
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

    bool QueryEffectivePageAttributes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        bool* writable,
        bool* executable)
    {
        bool ok = false;

        do
        {
            if (writable == nullptr || executable == nullptr || address == 0)
            {
                break;
            }

            PhysicalTranslationInfo translation = {};
            std::wstring ignored;
            uint32_t queryLength = length == 0 ? 1 : length;
            if (queryLength > 0x1000)
            {
                queryLength = 0x1000;
            }

            if (!device.TranslateVirtual(0, address, queryLength, &translation, &ignored))
            {
                break;
            }

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

            *writable = present && canWrite;
            *executable = present && canExecute;
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

            if (options.Limit != 0 && result->Records.size() >= options.Limit)
            {
                result->Truncated = true;
                break;
            }

            ++result->MatchingModules;
            ModuleIntegrityRecord record = {};
            record.ImageName = module.ImageName;
            record.ImagePath = module.ImagePath;
            record.Base = module.Base;
            record.Size = module.Size;

            std::vector<uint8_t> headerBytes;
            std::wstring readError;
            if (!ReadKernelBytes(device_, module.Base, 0x1000, &headerBytes, &readError))
            {
                record.Notes = L"header read failed: " + readError;
                record.Suspicious = true;
                result->Records.push_back(record);
                ++result->SuspiciousModules;
                continue;
            }

            record.HeaderRead = true;
            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headerBytes.data());
            record.MzOk = dos->e_magic == IMAGE_DOS_SIGNATURE;
            if (!record.MzOk || dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > headerBytes.size())
            {
                record.Notes = L"invalid or unreadable PE DOS/NT header";
                record.Suspicious = true;
                result->Records.push_back(record);
                ++result->SuspiciousModules;
                continue;
            }

            const uint8_t* ntBytes = headerBytes.data() + dos->e_lfanew;
            const IMAGE_NT_HEADERS64* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntBytes);
            record.PeOk = nt64->Signature == IMAGE_NT_SIGNATURE;
            if (!record.PeOk)
            {
                record.Notes = L"PE signature mismatch";
                record.Suspicious = true;
                result->Records.push_back(record);
                ++result->SuspiciousModules;
                continue;
            }

            record.NumberOfSections = nt64->FileHeader.NumberOfSections;
            record.SizeOfImage = nt64->OptionalHeader.SizeOfImage;
            if (record.SizeOfImage != 0 && module.Size != 0)
            {
                uint32_t delta = record.SizeOfImage > module.Size
                    ? record.SizeOfImage - module.Size
                    : module.Size - record.SizeOfImage;
                if (delta > 0x1000)
                {
                    record.SizeMismatch = true;
                    record.Notes = L"module list size differs from PE SizeOfImage";
                }
            }

            size_t sectionTable = static_cast<size_t>(dos->e_lfanew) +
                sizeof(uint32_t) +
                sizeof(IMAGE_FILE_HEADER) +
                nt64->FileHeader.SizeOfOptionalHeader;
            size_t sectionBytes = static_cast<size_t>(record.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (record.NumberOfSections > 96 || sectionTable > headerBytes.size() || sectionBytes > headerBytes.size() - sectionTable)
            {
                record.Notes += record.Notes.empty() ? L"section table unavailable" : L"; section table unavailable";
            }
            else
            {
                const IMAGE_SECTION_HEADER* sections =
                    reinterpret_cast<const IMAGE_SECTION_HEADER*>(headerBytes.data() + sectionTable);
                for (uint16_t i = 0; i < record.NumberOfSections; ++i)
                {
                    ModuleIntegritySectionRecord section = {};
                    section.Name = SectionName(sections[i]);
                    section.VirtualAddress = sections[i].VirtualAddress;
                    section.VirtualSize = sections[i].Misc.VirtualSize;
                    section.RawSize = sections[i].SizeOfRawData;
                    section.Characteristics = sections[i].Characteristics;
                    section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                    section.Writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

                    if (section.Executable && section.Writable)
                    {
                        section.Suspicious = true;
                        section.Notes = L"section characteristics are W+X";
                    }

                    if (section.Executable || EqualsNoCaseLocal(section.Name, L".text"))
                    {
                        uint64_t sectionAddress = 0;
                        bool writable = false;
                        bool executable = false;
                        if (!TryAdd(module.Base, section.VirtualAddress, &sectionAddress))
                        {
                            section.Suspicious = true;
                            section.Notes += section.Notes.empty() ? L"section RVA overflow" : L"; section RVA overflow";
                        }
                        else if (QueryEffectivePageAttributes(
                                     device_,
                                     sectionAddress,
                                     section.VirtualSize == 0 ? 1 : section.VirtualSize,
                                     &writable,
                                     &executable))
                        {
                            section.PageAttributesQueried = true;
                            section.EffectiveWritable = writable;
                            section.EffectiveExecutable = executable;
                            if (writable && executable)
                            {
                                section.Suspicious = true;
                                section.Notes += section.Notes.empty() ? L"page attributes are W+X" : L"; page attributes are W+X";
                            }
                        }
                    }

                    if (section.Suspicious)
                    {
                        record.Suspicious = true;
                    }
                    record.Sections.push_back(section);
                }
            }

            if (record.SizeMismatch)
            {
                record.Suspicious = true;
            }

            if (record.Suspicious)
            {
                ++result->SuspiciousModules;
            }
            result->Records.push_back(record);
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
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.module-integrity.v1\",\n";
    json << L"  \"summary\":{\"modules_scanned\":" << result.ModulesScanned
         << L",\"matching_modules\":" << result.MatchingModules
         << L",\"suspicious_modules\":" << result.SuspiciousModules
         << L",\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},\n";
    json << L"  \"records\":[\n";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ModuleIntegrityRecord& record = result.Records[i];
        json << L"    {\"image\":\"" << JsonEscape(record.ImageName)
             << L"\",\"base\":\"" << Hex(record.Base, 16)
             << L"\",\"size\":" << record.Size
             << L",\"size_of_image\":" << record.SizeOfImage
             << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false")
             << L",\"notes\":\"" << JsonEscape(record.Notes)
             << L"\",\"sections\":[";
        for (size_t s = 0; s < record.Sections.size(); ++s)
        {
            const ModuleIntegritySectionRecord& section = record.Sections[s];
            if (s != 0)
            {
                json << L",";
            }
            json << L"{\"name\":\"" << JsonEscape(section.Name)
                 << L"\",\"va\":\"" << Hex(section.VirtualAddress)
                 << L"\",\"executable\":" << (section.Executable ? L"true" : L"false")
                 << L",\"writable\":" << (section.Writable ? L"true" : L"false")
                 << L",\"effective_writable\":" << (section.EffectiveWritable ? L"true" : L"false")
                 << L",\"effective_executable\":" << (section.EffectiveExecutable ? L"true" : L"false")
                 << L",\"suspicious\":" << (section.Suspicious ? L"true" : L"false")
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
