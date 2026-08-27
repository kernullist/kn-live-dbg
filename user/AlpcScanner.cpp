#include "AlpcScanner.h"
#include "McpJson.h"

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <map>
#include <sstream>
#include <unordered_set>
#include <utility>

namespace
{
    constexpr uint64_t kKernelSpaceMin       = 0xffff800000000000ull;
    constexpr uint32_t kMaxListIterations    = 0x10000;
    constexpr uint32_t kMaxDirectoryDepth    = 16;
    constexpr uint32_t kDefaultHashBuckets   = 37;
    constexpr uint32_t kMaxHashBuckets       = 256;
    constexpr uint32_t kMaxDirEntriesPerBkt  = 4096;
    constexpr uint32_t kMaxRawBytesPerRead   = 0x1000;
    constexpr size_t   kMaxRecordCap         = 0x10000;

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

    bool ContainsNoCase(const std::wstring& haystack, const std::wstring& needle)
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
            if (h.find(n) != std::wstring::npos)
            {
                found = true;
            }
        } while (false);

        return found;
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

    bool TrySubtract(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }

            if (left < right)
            {
                break;
            }

            *result = left - right;
            ok = true;
        } while (false);

        return ok;
    }

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    struct TypeFieldDescriptor
    {
        TypeFieldInfo Info = {};
        bool Resolved = false;
    };

    class AlpcContext
    {
    public:
        AlpcContext(DeviceClient& device, SymbolEngine& symbols) :
            device_(device),
            symbols_(symbols)
        {
        }

        DeviceClient& Device()
        {
            return device_;
        }

        SymbolEngine& Symbols()
        {
            return symbols_;
        }

        bool ReadBytes(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (bytes == nullptr || length == 0 || length > kMaxRawBytesPerRead)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid read length";
                    }
                    break;
                }

                if (!device_.ReadMemory(address, length, bytes, error))
                {
                    break;
                }

                if (bytes->size() != length)
                {
                    if (error != nullptr)
                    {
                        *error = L"Short kernel read";
                    }
                    break;
                }

                ok = true;
            } while (false);

            return ok;
        }

        bool ReadU8(uint64_t address, uint8_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid u8 output";
                    }
                    break;
                }

                std::vector<uint8_t> bytes;
                if (!ReadBytes(address, sizeof(uint8_t), &bytes, error))
                {
                    break;
                }

                *value = bytes[0];
                ok = true;
            } while (false);

            return ok;
        }

        bool ReadU16(uint64_t address, uint16_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid u16 output";
                    }
                    break;
                }

                std::vector<uint8_t> bytes;
                if (!ReadBytes(address, sizeof(uint16_t), &bytes, error))
                {
                    break;
                }

                memcpy(value, bytes.data(), sizeof(uint16_t));
                ok = true;
            } while (false);

            return ok;
        }

        bool ReadU32(uint64_t address, uint32_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid u32 output";
                    }
                    break;
                }

                std::vector<uint8_t> bytes;
                if (!ReadBytes(address, sizeof(uint32_t), &bytes, error))
                {
                    break;
                }

                memcpy(value, bytes.data(), sizeof(uint32_t));
                ok = true;
            } while (false);

            return ok;
        }

        bool ReadU64(uint64_t address, uint64_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid u64 output";
                    }
                    break;
                }

                std::vector<uint8_t> bytes;
                if (!ReadBytes(address, sizeof(uint64_t), &bytes, error))
                {
                    break;
                }

                memcpy(value, bytes.data(), sizeof(uint64_t));
                ok = true;
            } while (false);

            return ok;
        }

        bool ResolveSymbol(const std::wstring& name, uint64_t* address, std::wstring* error)
        {
            return symbols_.ResolveSymbol(name, address, error);
        }

        bool GetLayout(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (layout == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid layout output";
                    }
                    break;
                }

                auto cached = layouts_.find(typeName);
                if (cached != layouts_.end())
                {
                    *layout = cached->second;
                    ok = true;
                    break;
                }

                TypeLayoutInfo localLayout = {};
                if (!symbols_.GetTypeLayout(typeName, &localLayout, error))
                {
                    break;
                }

                layouts_.emplace(typeName, localLayout);
                *layout = std::move(localLayout);
                ok = true;
            } while (false);

            return ok;
        }

        bool FindField(
            const std::wstring& typeName,
            const std::vector<std::wstring>& fieldNames,
            TypeFieldInfo* field,
            std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (field == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid field output";
                    }
                    break;
                }

                TypeLayoutInfo layout = {};
                if (!GetLayout(typeName, &layout, error))
                {
                    break;
                }

                for (const std::wstring& fieldName : fieldNames)
                {
                    auto found = std::find_if(layout.Fields.begin(), layout.Fields.end(), [&](const TypeFieldInfo& candidate)
                    {
                        return _wcsicmp(candidate.Name.c_str(), fieldName.c_str()) == 0;
                    });

                    if (found != layout.Fields.end())
                    {
                        *field = *found;
                        ok = true;
                        break;
                    }
                }

                if (!ok && error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"Field was not found in " << typeName;
                    *error = stream.str();
                }
            } while (false);

            return ok;
        }

        bool ReadFieldU64(uint64_t base, const TypeFieldInfo& field, uint64_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid field output";
                    }
                    break;
                }

                uint64_t fieldAddress = 0;
                if (!TryAdd(base, field.Offset, &fieldAddress))
                {
                    if (error != nullptr)
                    {
                        *error = L"Field address overflow";
                    }
                    break;
                }

                if (!ReadU64(fieldAddress, value, error))
                {
                    break;
                }

                ok = true;
            } while (false);

            return ok;
        }

        bool ReadFieldU32(uint64_t base, const TypeFieldInfo& field, uint32_t* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid field output";
                    }
                    break;
                }

                uint64_t fieldAddress = 0;
                if (!TryAdd(base, field.Offset, &fieldAddress))
                {
                    if (error != nullptr)
                    {
                        *error = L"Field address overflow";
                    }
                    break;
                }

                if (!ReadU32(fieldAddress, value, error))
                {
                    break;
                }

                ok = true;
            } while (false);

            return ok;
        }

        bool ReadUnicodeStringAt(uint64_t address, std::wstring* value, std::wstring* error)
        {
            bool ok = false;

            do
            {
                if (value == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid string output";
                    }
                    break;
                }

                uint16_t length16 = 0;
                if (!ReadU16(address, &length16, error))
                {
                    break;
                }

                uint64_t bufferFieldAddress = 0;
                if (!TryAdd(address, 8, &bufferFieldAddress))
                {
                    if (error != nullptr)
                    {
                        *error = L"UNICODE_STRING buffer field overflow";
                    }
                    break;
                }

                uint64_t bufferValue = 0;
                if (!ReadU64(bufferFieldAddress, &bufferValue, error))
                {
                    break;
                }

                if (length16 == 0 || bufferValue == 0)
                {
                    value->clear();
                    ok = true;
                    break;
                }

                uint32_t length = length16;
                if (length > 2048)
                {
                    length = 2048;
                }

                std::vector<uint8_t> bytes;
                if (!ReadBytes(bufferValue, length, &bytes, error))
                {
                    break;
                }

                value->assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / sizeof(wchar_t));
                ok = true;
            } while (false);

            return ok;
        }

    private:
        DeviceClient& device_;
        SymbolEngine& symbols_;
        std::map<std::wstring, TypeLayoutInfo> layouts_;
    };

    struct ObjectTypeRecord
    {
        std::wstring Name;
        uint64_t Address = 0;
        uint8_t  Index = 0;
    };

    bool DiscoverObjectTypes(
        AlpcContext& ctx,
        std::vector<ObjectTypeRecord>* records,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (records == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid records output";
                }
                break;
            }

            uint64_t tableAddress = 0;
            std::wstring localError;
            const std::wstring symbolNames[] =
            {
                L"nt!ObTypeIndexTable",
                L"nt!ObpTypeIndexTable"
            };

            bool symbolFound = false;
            for (const std::wstring& symbol : symbolNames)
            {
                if (ctx.ResolveSymbol(symbol, &tableAddress, &localError))
                {
                    symbolFound = true;
                    break;
                }
            }

            if (!symbolFound)
            {
                if (error != nullptr)
                {
                    *error = L"ObTypeIndexTable symbol not found: " + localError;
                }
                break;
            }

            TypeFieldInfo nameField = {};
            if (!ctx.FindField(L"nt!_OBJECT_TYPE", {L"Name", L"TypeName"}, &nameField, error))
            {
                break;
            }

            for (uint32_t index = 0; index < 256; ++index)
            {
                uint64_t slotAddress = 0;
                if (!TryAdd(tableAddress, static_cast<uint64_t>(index) * sizeof(uint64_t), &slotAddress))
                {
                    break;
                }

                uint64_t typeAddress = 0;
                if (!ctx.ReadU64(slotAddress, &typeAddress, nullptr))
                {
                    break;
                }

                if (typeAddress == 0 || !IsKernelAddress(typeAddress))
                {
                    continue;
                }

                bool duplicate = false;
                for (const ObjectTypeRecord& existing : *records)
                {
                    if (existing.Address == typeAddress)
                    {
                        duplicate = true;
                        break;
                    }
                }

                if (duplicate)
                {
                    continue;
                }

                uint64_t nameAddress = 0;
                if (!TryAdd(typeAddress, nameField.Offset, &nameAddress))
                {
                    continue;
                }

                std::wstring typeName;
                if (!ctx.ReadUnicodeStringAt(nameAddress, &typeName, nullptr))
                {
                    continue;
                }

                if (typeName.empty())
                {
                    continue;
                }

                ObjectTypeRecord record = {};
                record.Name = std::move(typeName);
                record.Address = typeAddress;
                record.Index = static_cast<uint8_t>(index);
                records->push_back(std::move(record));
            }

            ok = !records->empty();
            if (!ok && error != nullptr)
            {
                *error = L"No valid object types were enumerated";
            }
        } while (false);

        return ok;
    }

    const ObjectTypeRecord* FindObjectTypeByName(
        const std::vector<ObjectTypeRecord>& records,
        const std::wstring& target)
    {
        const ObjectTypeRecord* found = nullptr;

        for (const ObjectTypeRecord& record : records)
        {
            if (_wcsicmp(record.Name.c_str(), target.c_str()) == 0)
            {
                found = &record;
                break;
            }
        }

        return found;
    }

    bool ReadObHeaderCookie(AlpcContext& ctx, uint8_t* cookie, bool* hasCookie)
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
            if (!ctx.ResolveSymbol(L"nt!ObHeaderCookie", &address, nullptr))
            {
                break;
            }

            if (!ctx.ReadU8(address, cookie, nullptr))
            {
                break;
            }

            *hasCookie = true;
            ok = true;
        } while (false);

        return ok;
    }

    struct ObjectHeaderLayout
    {
        TypeFieldInfo TypeIndex = {};
        TypeFieldInfo InfoMask = {};
        TypeFieldInfo Body = {};
        bool Resolved = false;
    };

    bool ResolveObjectHeaderLayout(AlpcContext& ctx, ObjectHeaderLayout* layout, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid header layout output";
                }
                break;
            }

            if (layout->Resolved)
            {
                ok = true;
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_HEADER", {L"TypeIndex"}, &layout->TypeIndex, error))
            {
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_HEADER", {L"InfoMask"}, &layout->InfoMask, error))
            {
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_HEADER", {L"Body"}, &layout->Body, error))
            {
                break;
            }

            layout->Resolved = true;
            ok = true;
        } while (false);

        return ok;
    }

    bool ComputeObjectHeader(
        const ObjectHeaderLayout& layout,
        uint64_t body,
        uint64_t* header)
    {
        bool ok = false;

        do
        {
            if (header == nullptr)
            {
                break;
            }

            if (!TrySubtract(body, layout.Body.Offset, header))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    uint8_t DecodeTypeIndex(uint8_t raw, uint64_t headerAddress, uint8_t cookie, bool hasCookie)
    {
        if (!hasCookie)
        {
            return raw;
        }

        uint8_t headerHigh = static_cast<uint8_t>((headerAddress >> 8) & 0xffu);
        return static_cast<uint8_t>(raw ^ cookie ^ headerHigh);
    }

    bool ReadObjectName(
        AlpcContext& ctx,
        const ObjectHeaderLayout& layout,
        uint64_t header,
        std::wstring* name,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (name == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid name output";
                }
                break;
            }

            name->clear();

            uint64_t infoMaskAddress = 0;
            if (!TryAdd(header, layout.InfoMask.Offset, &infoMaskAddress))
            {
                break;
            }

            uint8_t infoMask = 0;
            if (!ctx.ReadU8(infoMaskAddress, &infoMask, nullptr))
            {
                break;
            }

            if ((infoMask & 0x02u) == 0)
            {
                ok = true;
                break;
            }

            uint8_t maskedIndex = static_cast<uint8_t>(infoMask & 0x3fu);
            uint8_t offset = kObpInfoMaskToOffset[maskedIndex];
            uint64_t nameInfoAddress = 0;
            if (!TrySubtract(header, offset, &nameInfoAddress))
            {
                break;
            }

            TypeFieldInfo nameField = {};
            if (!ctx.FindField(L"nt!_OBJECT_HEADER_NAME_INFO", {L"Name"}, &nameField, nullptr))
            {
                ok = true;
                break;
            }

            uint64_t unicodeAddress = 0;
            if (!TryAdd(nameInfoAddress, nameField.Offset, &unicodeAddress))
            {
                break;
            }

            ctx.ReadUnicodeStringAt(unicodeAddress, name, nullptr);
            ok = true;
        } while (false);

        return ok;
    }

    struct DirectoryLayout
    {
        TypeFieldInfo HashBuckets = {};
        uint32_t BucketCount = kDefaultHashBuckets;
        bool Resolved = false;
    };

    struct DirectoryEntryLayout
    {
        TypeFieldInfo ChainLink = {};
        TypeFieldInfo Object = {};
        bool Resolved = false;
    };

    bool ResolveDirectoryLayouts(
        AlpcContext& ctx,
        DirectoryLayout* dir,
        DirectoryEntryLayout* entry,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (dir == nullptr || entry == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid directory layout output";
                }
                break;
            }

            if (dir->Resolved && entry->Resolved)
            {
                ok = true;
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_DIRECTORY", {L"HashBuckets"}, &dir->HashBuckets, error))
            {
                break;
            }

            uint32_t bucketCount = static_cast<uint32_t>(dir->HashBuckets.Length / sizeof(uint64_t));
            if (bucketCount == 0)
            {
                bucketCount = kDefaultHashBuckets;
            }
            if (bucketCount > kMaxHashBuckets)
            {
                bucketCount = kMaxHashBuckets;
            }
            dir->BucketCount = bucketCount;

            if (!ctx.FindField(L"nt!_OBJECT_DIRECTORY_ENTRY", {L"ChainLink"}, &entry->ChainLink, error))
            {
                break;
            }

            if (!ctx.FindField(L"nt!_OBJECT_DIRECTORY_ENTRY", {L"Object"}, &entry->Object, error))
            {
                break;
            }

            dir->Resolved = true;
            entry->Resolved = true;
            ok = true;
        } while (false);

        return ok;
    }

    struct AlpcPortLayout
    {
        TypeFieldInfo OwnerProcess = {};
        TypeFieldInfo ConnectionPort = {};
        TypeFieldInfo CommunicationInfo = {};
        TypeFieldInfo MainQueue = {};
        TypeFieldInfo PendingQueue = {};
        TypeFieldInfo LargeMessageQueue = {};
        TypeFieldInfo CanceledQueue = {};
        TypeFieldInfo WaitQueue = {};
        TypeFieldInfo Flags = {};
        bool HasOwnerProcess = false;
        bool HasConnectionPort = false;
        bool HasCommunicationInfo = false;
        bool HasMainQueue = false;
        bool HasPendingQueue = false;
        bool HasLargeMessageQueue = false;
        bool HasCanceledQueue = false;
        bool HasWaitQueue = false;
        bool HasFlags = false;
        bool Resolved = false;
    };

    void ResolveAlpcPortLayout(AlpcContext& ctx, AlpcPortLayout* layout)
    {
        if (layout == nullptr || layout->Resolved)
        {
            return;
        }

        layout->HasOwnerProcess = ctx.FindField(L"nt!_ALPC_PORT", {L"OwnerProcess"}, &layout->OwnerProcess, nullptr);
        layout->HasConnectionPort = ctx.FindField(L"nt!_ALPC_PORT", {L"ConnectionPort"}, &layout->ConnectionPort, nullptr);
        layout->HasCommunicationInfo = ctx.FindField(L"nt!_ALPC_PORT", {L"CommunicationInfo"}, &layout->CommunicationInfo, nullptr);
        layout->HasMainQueue = ctx.FindField(L"nt!_ALPC_PORT", {L"MainQueue"}, &layout->MainQueue, nullptr);
        layout->HasPendingQueue = ctx.FindField(L"nt!_ALPC_PORT", {L"PendingQueue"}, &layout->PendingQueue, nullptr);
        layout->HasLargeMessageQueue = ctx.FindField(L"nt!_ALPC_PORT", {L"LargeMessageQueue"}, &layout->LargeMessageQueue, nullptr);
        layout->HasCanceledQueue = ctx.FindField(L"nt!_ALPC_PORT", {L"CanceledQueue"}, &layout->CanceledQueue, nullptr);
        layout->HasWaitQueue = ctx.FindField(L"nt!_ALPC_PORT", {L"WaitQueue"}, &layout->WaitQueue, nullptr);
        layout->HasFlags = ctx.FindField(L"nt!_ALPC_PORT", {L"u1", L"Flags", L"PortAttributes"}, &layout->Flags, nullptr);
        layout->Resolved = true;
    }

    struct CommInfoLayout
    {
        TypeFieldInfo ConnectionPort = {};
        TypeFieldInfo ServerCommunicationPort = {};
        TypeFieldInfo ClientCommunicationPort = {};
        bool HasConnectionPort = false;
        bool HasServerCommunicationPort = false;
        bool HasClientCommunicationPort = false;
        bool Resolved = false;
    };

    void ResolveCommInfoLayout(AlpcContext& ctx, CommInfoLayout* layout)
    {
        if (layout == nullptr || layout->Resolved)
        {
            return;
        }

        layout->HasConnectionPort = ctx.FindField(L"nt!_ALPC_COMMUNICATION_INFO", {L"ConnectionPort"}, &layout->ConnectionPort, nullptr);
        layout->HasServerCommunicationPort = ctx.FindField(L"nt!_ALPC_COMMUNICATION_INFO", {L"ServerCommunicationPort"}, &layout->ServerCommunicationPort, nullptr);
        layout->HasClientCommunicationPort = ctx.FindField(L"nt!_ALPC_COMMUNICATION_INFO", {L"ClientCommunicationPort"}, &layout->ClientCommunicationPort, nullptr);
        layout->Resolved = true;
    }

    struct EprocessLayout
    {
        TypeFieldInfo UniqueProcessId = {};
        TypeFieldInfo ImageFileName = {};
        bool HasUniqueProcessId = false;
        bool HasImageFileName = false;
        bool Resolved = false;
    };

    void ResolveEprocessLayout(AlpcContext& ctx, EprocessLayout* layout)
    {
        if (layout == nullptr || layout->Resolved)
        {
            return;
        }

        layout->HasUniqueProcessId = ctx.FindField(L"nt!_EPROCESS", {L"UniqueProcessId"}, &layout->UniqueProcessId, nullptr);
        layout->HasImageFileName = ctx.FindField(L"nt!_EPROCESS", {L"ImageFileName"}, &layout->ImageFileName, nullptr);
        layout->Resolved = true;
    }

    std::wstring ReadImageFileName(AlpcContext& ctx, uint64_t eprocess, const TypeFieldInfo& field)
    {
        std::wstring result;

        do
        {
            if (eprocess == 0 || !field.Name.size())
            {
                break;
            }

            uint64_t fieldAddress = 0;
            if (!TryAdd(eprocess, field.Offset, &fieldAddress))
            {
                break;
            }

            size_t length = static_cast<size_t>(field.Length);
            if (length == 0 || length > 64)
            {
                length = 16;
            }

            std::vector<uint8_t> bytes;
            if (!ctx.ReadBytes(fieldAddress, static_cast<uint32_t>(length), &bytes, nullptr))
            {
                break;
            }

            std::wstring name;
            for (uint8_t byte : bytes)
            {
                if (byte == 0)
                {
                    break;
                }

                if (byte >= 0x20 && byte < 0x7f)
                {
                    name.push_back(static_cast<wchar_t>(byte));
                }
                else
                {
                    name.push_back(L'?');
                }
            }

            result = name;
        } while (false);

        return result;
    }

    bool CountListEntries(
        AlpcContext& ctx,
        uint64_t headAddress,
        uint32_t* count)
    {
        bool ok = false;

        do
        {
            if (count == nullptr)
            {
                break;
            }

            *count = 0;

            uint64_t flink = 0;
            if (!ctx.ReadU64(headAddress, &flink, nullptr))
            {
                break;
            }

            if (flink == 0)
            {
                ok = true;
                break;
            }

            uint64_t current = flink;
            uint32_t iter = 0;
            while (current != headAddress && iter < kMaxListIterations)
            {
                if (!IsKernelAddress(current))
                {
                    break;
                }

                uint64_t next = 0;
                if (!ctx.ReadU64(current, &next, nullptr))
                {
                    break;
                }

                ++iter;
                if (next == 0)
                {
                    break;
                }

                current = next;
            }

            *count = iter;
            ok = true;
        } while (false);

        return ok;
    }

    bool CollectPort(
        AlpcContext& ctx,
        const AlpcPortLayout& portLayout,
        const CommInfoLayout& commLayout,
        const EprocessLayout& eprocessLayout,
        uint64_t portAddress,
        AlpcPortRecord* record,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (record == nullptr || portAddress == 0 || !IsKernelAddress(portAddress))
            {
                if (warning != nullptr)
                {
                    *warning = L"Invalid port address";
                }
                break;
            }

            record->Address = portAddress;

            if (portLayout.HasOwnerProcess)
            {
                uint64_t owner = 0;
                if (ctx.ReadFieldU64(portAddress, portLayout.OwnerProcess, &owner, nullptr) && IsKernelAddress(owner))
                {
                    record->OwnerProcess = owner;
                    record->HasOwnerProcess = true;
                }
            }

            if (portLayout.HasConnectionPort)
            {
                uint64_t connectionPort = 0;
                if (ctx.ReadFieldU64(portAddress, portLayout.ConnectionPort, &connectionPort, nullptr))
                {
                    if (IsKernelAddress(connectionPort))
                    {
                        record->ConnectionPort = connectionPort;
                        record->HasConnectionPort = true;
                        if (connectionPort == portAddress)
                        {
                            record->IsConnectionPort = true;
                        }
                    }
                }
            }

            if (portLayout.HasCommunicationInfo)
            {
                uint64_t commInfo = 0;
                if (ctx.ReadFieldU64(portAddress, portLayout.CommunicationInfo, &commInfo, nullptr))
                {
                    if (IsKernelAddress(commInfo))
                    {
                        record->CommunicationInfo = commInfo;
                        record->HasCommunicationInfo = true;

                        if (commLayout.HasConnectionPort)
                        {
                            uint64_t commConn = 0;
                            if (ctx.ReadFieldU64(commInfo, commLayout.ConnectionPort, &commConn, nullptr) && IsKernelAddress(commConn))
                            {
                                if (record->ConnectionPort == 0)
                                {
                                    record->ConnectionPort = commConn;
                                    record->HasConnectionPort = true;
                                }
                                if (commConn == portAddress)
                                {
                                    record->IsConnectionPort = true;
                                }
                            }
                        }

                        if (commLayout.HasServerCommunicationPort)
                        {
                            uint64_t server = 0;
                            if (ctx.ReadFieldU64(commInfo, commLayout.ServerCommunicationPort, &server, nullptr) && IsKernelAddress(server))
                            {
                                record->ServerCommunicationPort = server;
                                if (server == portAddress)
                                {
                                    record->IsServerCommunicationPort = true;
                                }
                            }
                        }

                        if (commLayout.HasClientCommunicationPort)
                        {
                            uint64_t client = 0;
                            if (ctx.ReadFieldU64(commInfo, commLayout.ClientCommunicationPort, &client, nullptr) && IsKernelAddress(client))
                            {
                                record->ClientCommunicationPort = client;
                                if (client == portAddress)
                                {
                                    record->IsClientCommunicationPort = true;
                                }
                            }
                        }
                    }
                }
            }

            if (portLayout.HasFlags)
            {
                uint32_t flags = 0;
                if (ctx.ReadFieldU32(portAddress, portLayout.Flags, &flags, nullptr))
                {
                    record->Flags = flags;
                }
            }

            if (record->HasOwnerProcess && eprocessLayout.Resolved)
            {
                if (eprocessLayout.HasUniqueProcessId)
                {
                    uint64_t pid = 0;
                    if (ctx.ReadFieldU64(record->OwnerProcess, eprocessLayout.UniqueProcessId, &pid, nullptr))
                    {
                        record->OwnerProcessId = pid;
                    }
                }

                if (eprocessLayout.HasImageFileName)
                {
                    record->OwnerImageName = ReadImageFileName(ctx, record->OwnerProcess, eprocessLayout.ImageFileName);
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveQueueListHead(
        uint64_t portAddress,
        const TypeFieldInfo& field,
        uint64_t* head)
    {
        bool ok = false;

        do
        {
            if (head == nullptr)
            {
                break;
            }

            uint64_t base = 0;
            if (!TryAdd(portAddress, field.Offset, &base))
            {
                break;
            }

            uint64_t adjusted = base;
            std::wstring typeName = ToLowerCopy(field.TypeName);
            if (typeName.find(L"_kqueue") != std::wstring::npos ||
                typeName.find(L"kqueue") != std::wstring::npos)
            {
                if (!TryAdd(base, 0x18ull, &adjusted))
                {
                    break;
                }
            }

            *head = adjusted;
            ok = true;
        } while (false);

        return ok;
    }

    void PopulateQueueCounts(
        AlpcContext& ctx,
        const AlpcPortLayout& portLayout,
        AlpcPortRecord* record)
    {
        if (record == nullptr)
        {
            return;
        }

        bool anyQueue = false;

        if (portLayout.HasMainQueue)
        {
            uint64_t headAddr = 0;
            if (ResolveQueueListHead(record->Address, portLayout.MainQueue, &headAddr) &&
                CountListEntries(ctx, headAddr, &record->MainQueueLength))
            {
                anyQueue = true;
            }
        }

        if (portLayout.HasPendingQueue)
        {
            uint64_t headAddr = 0;
            if (ResolveQueueListHead(record->Address, portLayout.PendingQueue, &headAddr) &&
                CountListEntries(ctx, headAddr, &record->PendingQueueLength))
            {
                anyQueue = true;
            }
        }

        if (portLayout.HasLargeMessageQueue)
        {
            uint64_t headAddr = 0;
            if (ResolveQueueListHead(record->Address, portLayout.LargeMessageQueue, &headAddr) &&
                CountListEntries(ctx, headAddr, &record->LargeMessageQueueLength))
            {
                anyQueue = true;
            }
        }

        if (portLayout.HasCanceledQueue)
        {
            uint64_t headAddr = 0;
            if (ResolveQueueListHead(record->Address, portLayout.CanceledQueue, &headAddr) &&
                CountListEntries(ctx, headAddr, &record->CanceledQueueLength))
            {
                anyQueue = true;
            }
        }

        if (portLayout.HasWaitQueue)
        {
            uint64_t headAddr = 0;
            if (ResolveQueueListHead(record->Address, portLayout.WaitQueue, &headAddr) &&
                CountListEntries(ctx, headAddr, &record->WaitQueueLength))
            {
                anyQueue = true;
            }
        }

        if (anyQueue)
        {
            record->HasQueueData = true;
        }
    }


    bool WalkDirectory(
        AlpcContext& ctx,
        const ObjectHeaderLayout& headerLayout,
        const DirectoryLayout& dirLayout,
        const DirectoryEntryLayout& entryLayout,
        uint64_t directoryBody,
        uint8_t cookie,
        bool hasCookie,
        uint8_t alpcTypeIndex,
        uint8_t directoryTypeIndex,
        const std::wstring& currentPath,
        std::vector<AlpcPortRecord>* records,
        std::vector<std::pair<uint64_t, std::wstring>>* foundPorts,
        std::unordered_set<uint64_t>* foundPortSet,
        std::vector<std::wstring>* warnings,
        std::unordered_set<uint64_t>* visited,
        uint32_t depth)
    {
        bool ok = false;

        do
        {
            (void)records;

            if (directoryBody == 0 || !IsKernelAddress(directoryBody))
            {
                break;
            }

            if (visited != nullptr)
            {
                if (visited->find(directoryBody) != visited->end())
                {
                    ok = true;
                    break;
                }
                visited->insert(directoryBody);
            }

            if (depth >= kMaxDirectoryDepth)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"Directory recursion depth limit reached at " + currentPath);
                }
                ok = true;
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
                if (!ctx.ReadU64(bucketAddress, &entry, nullptr))
                {
                    continue;
                }

                uint32_t chainCount = 0;
                while (entry != 0 && IsKernelAddress(entry) && chainCount < kMaxDirEntriesPerBkt)
                {
                    ++chainCount;

                    uint64_t objectFieldAddress = 0;
                    if (!TryAdd(entry, entryLayout.Object.Offset, &objectFieldAddress))
                    {
                        break;
                    }

                    uint64_t objectBody = 0;
                    if (!ctx.ReadU64(objectFieldAddress, &objectBody, nullptr))
                    {
                        break;
                    }

                    if (objectBody != 0 && IsKernelAddress(objectBody))
                    {
                        uint64_t objectHeader = 0;
                        if (ComputeObjectHeader(headerLayout, objectBody, &objectHeader))
                        {
                            uint64_t typeIndexAddress = 0;
                            uint8_t rawType = 0;
                            if (TryAdd(objectHeader, headerLayout.TypeIndex.Offset, &typeIndexAddress) &&
                                ctx.ReadU8(typeIndexAddress, &rawType, nullptr))
                            {
                                uint8_t decoded = DecodeTypeIndex(rawType, objectHeader, cookie, hasCookie);

                                std::wstring entryName;
                                ReadObjectName(ctx, headerLayout, objectHeader, &entryName, nullptr);

                                if (decoded == alpcTypeIndex)
                                {
                                    if (foundPorts != nullptr && foundPortSet != nullptr &&
                                        foundPortSet->find(objectBody) == foundPortSet->end())
                                    {
                                        std::wstring fullName = currentPath;
                                        if (!fullName.empty() && fullName.back() != L'\\')
                                        {
                                            fullName.push_back(L'\\');
                                        }
                                        fullName.append(entryName);
                                        foundPorts->emplace_back(objectBody, fullName);
                                        foundPortSet->insert(objectBody);
                                    }
                                }
                                else if (decoded == directoryTypeIndex)
                                {
                                    std::wstring nextPath = currentPath;
                                    if (!nextPath.empty() && nextPath.back() != L'\\')
                                    {
                                        nextPath.push_back(L'\\');
                                    }
                                    nextPath.append(entryName);

                                    WalkDirectory(
                                        ctx,
                                        headerLayout,
                                        dirLayout,
                                        entryLayout,
                                        objectBody,
                                        cookie,
                                        hasCookie,
                                        alpcTypeIndex,
                                        directoryTypeIndex,
                                        nextPath,
                                        records,
                                        foundPorts,
                                        foundPortSet,
                                        warnings,
                                        visited,
                                        depth + 1);
                                }
                            }
                        }
                    }

                    uint64_t chainLinkAddress = 0;
                    if (!TryAdd(entry, entryLayout.ChainLink.Offset, &chainLinkAddress))
                    {
                        break;
                    }

                    uint64_t nextEntry = 0;
                    if (!ctx.ReadU64(chainLinkAddress, &nextEntry, nullptr))
                    {
                        break;
                    }

                    entry = nextEntry;
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveObpRootDirectory(AlpcContext& ctx, uint64_t* directoryBody, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (directoryBody == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid root directory output";
                }
                break;
            }

            uint64_t symbolAddress = 0;
            std::wstring localError;
            if (!ctx.ResolveSymbol(L"nt!ObpRootDirectoryObject", &symbolAddress, &localError))
            {
                if (error != nullptr)
                {
                    *error = L"nt!ObpRootDirectoryObject not resolved: " + localError;
                }
                break;
            }

            uint64_t directory = 0;
            if (!ctx.ReadU64(symbolAddress, &directory, error))
            {
                break;
            }

            if (directory == 0 || !IsKernelAddress(directory))
            {
                if (error != nullptr)
                {
                    *error = L"ObpRootDirectoryObject points to invalid kernel address";
                }
                break;
            }

            *directoryBody = directory;
            ok = true;
        } while (false);

        return ok;
    }
}

AlpcScanner::AlpcScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool AlpcScanner::Scan(const Options& options, AlpcScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid scan result output";
            }
            break;
        }

        result->Records.clear();
        result->Warnings.clear();
        result->AlpcPortTypeAddress = 0;
        result->AlpcPortTypeIndex = 0;
        result->TypeIndexResolved = false;

        AlpcContext ctx(device_, symbols_);

        ObjectHeaderLayout headerLayout = {};
        if (!ResolveObjectHeaderLayout(ctx, &headerLayout, error))
        {
            break;
        }

        DirectoryLayout dirLayout = {};
        DirectoryEntryLayout entryLayout = {};
        if (!ResolveDirectoryLayouts(ctx, &dirLayout, &entryLayout, error))
        {
            break;
        }

        std::vector<ObjectTypeRecord> objectTypes;
        if (!DiscoverObjectTypes(ctx, &objectTypes, error))
        {
            break;
        }

        const ObjectTypeRecord* alpcType = FindObjectTypeByName(objectTypes, L"ALPC Port");
        if (alpcType == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"ALPC Port type not found in ObTypeIndexTable";
            }
            break;
        }

        const ObjectTypeRecord* directoryType = FindObjectTypeByName(objectTypes, L"Directory");
        if (directoryType == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Directory type not found in ObTypeIndexTable";
            }
            break;
        }

        result->AlpcPortTypeAddress = alpcType->Address;
        result->AlpcPortTypeIndex = alpcType->Index;
        result->TypeIndexResolved = true;

        uint8_t cookie = 0;
        bool hasCookie = false;
        ReadObHeaderCookie(ctx, &cookie, &hasCookie);
        if (!hasCookie)
        {
            result->Warnings.push_back(L"nt!ObHeaderCookie not present; falling back to legacy type-index decoding (no XOR cookie applied)");
        }

        uint64_t rootDirectory = 0;
        if (!ResolveObpRootDirectory(ctx, &rootDirectory, error))
        {
            break;
        }

        AlpcPortLayout portLayout = {};
        ResolveAlpcPortLayout(ctx, &portLayout);

        CommInfoLayout commLayout = {};
        ResolveCommInfoLayout(ctx, &commLayout);

        EprocessLayout eprocessLayout = {};
        ResolveEprocessLayout(ctx, &eprocessLayout);

        if (!portLayout.HasOwnerProcess)
        {
            result->Warnings.push_back(L"_ALPC_PORT.OwnerProcess not present in PDB; owner annotation omitted");
        }
        if (!portLayout.HasCommunicationInfo)
        {
            result->Warnings.push_back(L"_ALPC_PORT.CommunicationInfo not present in PDB; port pairing omitted");
        }

        std::vector<std::pair<uint64_t, std::wstring>> foundPorts;
        foundPorts.reserve(1024);

        if (options.Target == Scope::Port || options.Target == Scope::Queues)
        {
            if (!options.HasAddress)
            {
                if (error != nullptr)
                {
                    *error = L"!alpc " +
                        std::wstring(options.Target == Scope::Port ? L"port" : L"queues") +
                        L" requires an address";
                }
                break;
            }

            foundPorts.emplace_back(options.Address, std::wstring());
        }
        else
        {
            std::unordered_set<uint64_t> visited;
            std::unordered_set<uint64_t> foundPortSet;
            WalkDirectory(
                ctx,
                headerLayout,
                dirLayout,
                entryLayout,
                rootDirectory,
                cookie,
                hasCookie,
                alpcType->Index,
                directoryType->Index,
                L"\\",
                &result->Records,
                &foundPorts,
                &foundPortSet,
                &result->Warnings,
                &visited,
                0);
        }

        if (foundPorts.size() > kMaxRecordCap)
        {
            result->Warnings.push_back(L"ALPC port enumeration capped");
            foundPorts.resize(kMaxRecordCap);
        }

        std::unordered_set<uint64_t> namedSet;
        for (const auto& entry : foundPorts)
        {
            namedSet.insert(entry.first);
        }

        std::vector<AlpcPortRecord> initialRecords;
        initialRecords.reserve(foundPorts.size());

        for (const auto& entry : foundPorts)
        {
            AlpcPortRecord record = {};
            record.DirectoryPath = entry.second;
            record.IsNamedDirectoryPort = !entry.second.empty();
            record.TypeIndex = alpcType->Index;

            std::wstring localWarning;
            if (!CollectPort(ctx, portLayout, commLayout, eprocessLayout, entry.first, &record, &localWarning))
            {
                if (!localWarning.empty())
                {
                    result->Warnings.push_back(localWarning);
                }
                continue;
            }

            if (!record.DirectoryPath.empty())
            {
                size_t lastSep = record.DirectoryPath.find_last_of(L"\\/");
                if (lastSep != std::wstring::npos && lastSep + 1 < record.DirectoryPath.size())
                {
                    record.Name = record.DirectoryPath.substr(lastSep + 1);
                }
                else if (record.DirectoryPath != L"\\")
                {
                    record.Name = record.DirectoryPath;
                }
            }
            record.IsNamedDirectoryPort = !record.Name.empty();

            initialRecords.push_back(std::move(record));
        }

        if (options.Target == Scope::Ports || options.Target == Scope::Connections)
        {
            std::unordered_set<uint64_t> additionalSet;
            std::vector<AlpcPortRecord> derivedRecords;

            for (const AlpcPortRecord& record : initialRecords)
            {
                auto addCandidate = [&](uint64_t addr)
                {
                    if (addr == 0 || !IsKernelAddress(addr))
                    {
                        return;
                    }
                    if (namedSet.find(addr) != namedSet.end())
                    {
                        return;
                    }
                    if (additionalSet.find(addr) != additionalSet.end())
                    {
                        return;
                    }
                    additionalSet.insert(addr);

                    AlpcPortRecord linked = {};
                    linked.TypeIndex = alpcType->Index;
                    std::wstring localWarning;
                    if (CollectPort(ctx, portLayout, commLayout, eprocessLayout, addr, &linked, &localWarning))
                    {
                        derivedRecords.push_back(std::move(linked));
                    }
                    else if (!localWarning.empty())
                    {
                        result->Warnings.push_back(localWarning);
                    }
                };

                addCandidate(record.ConnectionPort);
                addCandidate(record.ServerCommunicationPort);
                addCandidate(record.ClientCommunicationPort);
            }

            for (AlpcPortRecord& derived : derivedRecords)
            {
                initialRecords.push_back(std::move(derived));
            }
        }

        if (options.Target == Scope::Queues || options.Target == Scope::Port)
        {
            for (AlpcPortRecord& record : initialRecords)
            {
                PopulateQueueCounts(ctx, portLayout, &record);
            }
        }

        for (AlpcPortRecord& record : initialRecords)
        {
            if (!options.NameFilter.empty())
            {
                bool nameMatch = ContainsNoCase(record.Name, options.NameFilter) ||
                    ContainsNoCase(record.DirectoryPath, options.NameFilter);
                if (!nameMatch)
                {
                    continue;
                }
            }

            if (options.HasPidFilter)
            {
                if (!record.HasOwnerProcess || record.OwnerProcessId != options.PidFilter)
                {
                    continue;
                }
            }

            if (options.Target == Scope::Port && record.Address != options.Address)
            {
                continue;
            }

            if (options.Target == Scope::Queues && record.Address != options.Address)
            {
                continue;
            }

            result->Records.push_back(std::move(record));
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring AlpcJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildAlpcJson(const AlpcScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.alpc.v1\",\"count\":";
    out += std::to_wstring(result.Records.size());
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const AlpcPortRecord& record = result.Records[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"address\":" + mcpjson::Quote(AlpcJsonHex(record.Address));
        if (!record.Name.empty())
        {
            out += L",\"name\":" + mcpjson::Quote(record.Name);
        }
        if (!record.DirectoryPath.empty())
        {
            out += L",\"directoryPath\":" + mcpjson::Quote(record.DirectoryPath);
        }
        if (!record.OwnerImageName.empty())
        {
            out += L",\"ownerImageName\":" + mcpjson::Quote(record.OwnerImageName);
        }
        if (record.HasOwnerProcess)
        {
            out += L",\"ownerProcess\":" + mcpjson::Quote(AlpcJsonHex(record.OwnerProcess));
        }
        out += L",\"ownerProcessId\":" + std::to_wstring(record.OwnerProcessId);
        if (record.HasConnectionPort)
        {
            out += L",\"connectionPort\":" + mcpjson::Quote(AlpcJsonHex(record.ConnectionPort));
        }
        out += L",\"serverCommunicationPort\":" + mcpjson::Quote(AlpcJsonHex(record.ServerCommunicationPort));
        out += L",\"clientCommunicationPort\":" + mcpjson::Quote(AlpcJsonHex(record.ClientCommunicationPort));
        if (record.HasQueueData)
        {
            out += L",\"mainQueueLength\":" + std::to_wstring(record.MainQueueLength);
            out += L",\"pendingQueueLength\":" + std::to_wstring(record.PendingQueueLength);
            out += L",\"largeMessageQueueLength\":" + std::to_wstring(record.LargeMessageQueueLength);
            out += L",\"canceledQueueLength\":" + std::to_wstring(record.CanceledQueueLength);
            out += L",\"waitQueueLength\":" + std::to_wstring(record.WaitQueueLength);
        }
        out += L",\"flags\":" + std::to_wstring(record.Flags);
        out += L",\"typeIndex\":" + std::to_wstring(static_cast<uint32_t>(record.TypeIndex));
        out += L",\"isConnectionPort\":";
        out += record.IsConnectionPort ? L"true" : L"false";
        out += L",\"isServerCommunicationPort\":";
        out += record.IsServerCommunicationPort ? L"true" : L"false";
        out += L",\"isClientCommunicationPort\":";
        out += record.IsClientCommunicationPort ? L"true" : L"false";
        out += L",\"isNamedDirectoryPort\":";
        out += record.IsNamedDirectoryPort ? L"true" : L"false";
        if (!record.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        }
        out += L"}";
    }

    out += L"],\"alpcPortTypeAddress\":" + mcpjson::Quote(AlpcJsonHex(result.AlpcPortTypeAddress));
    out += L",\"alpcPortTypeIndex\":" + std::to_wstring(result.AlpcPortTypeIndex);
    out += L",\"typeIndexResolved\":";
    out += result.TypeIndexResolved ? L"true" : L"false";

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
