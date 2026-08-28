#include "CallbackScanner.h"
#include "LeftoverCommon.h"
#include "McpJson.h"
#include "MinifilterIrpScanner.h"
#include "../shared/KnLiveDbgIoctl.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>

struct ListEntryValue
{
    uint64_t Flink = 0;
    uint64_t Blink = 0;
};

struct ObjectTypeTarget
{
    std::wstring Name;
    std::wstring Source;
    uint64_t Address = 0;
    uint32_t TypeIndex = 0xffffffffu;
};

struct CallbackRoot
{
    std::wstring Name;
    std::wstring Source;
    uint64_t Address = 0;
};

struct ObjectCallbackLayout
{
    std::wstring ItemType;
    TypeFieldInfo ObjectCallbackList = {};
    TypeFieldInfo ItemList = {};
    TypeFieldInfo Operations = {};
    TypeFieldInfo CallbackEntry = {};
    TypeFieldInfo PreOperation = {};
    TypeFieldInfo PostOperation = {};
    bool UsedSyntheticItemType = false;
    bool UsedSyntheticFields = false;
};

struct ExCallbackBlockLayout
{
    TypeFieldInfo Function = {};
    TypeFieldInfo Context = {};
    bool UsedSyntheticFields = false;
};

struct RegistryCallbackLayout
{
    std::wstring BlockType;
    TypeFieldInfo ListEntry = {};
    TypeFieldInfo PreCallback = {};
    TypeFieldInfo PostCallback = {};
    TypeFieldInfo Context = {};
    TypeFieldInfo Cookie = {};
    TypeFieldInfo Altitude = {};
    bool UsedSyntheticFields = false;
};

class CallbackScanContext
{
public:
    CallbackScanContext(DeviceClient& device, SymbolEngine& symbols) :
        device_(device),
        symbols_(symbols)
    {
    }

    bool ReadBytes(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid read request";
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

    bool ReadListEntry(uint64_t address, ListEntryValue* value, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid list entry output";
                }
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadBytes(address, sizeof(uint64_t) * 2, &bytes, error))
            {
                break;
            }

            memcpy(&value->Flink, bytes.data(), sizeof(uint64_t));
            memcpy(&value->Blink, bytes.data() + sizeof(uint64_t), sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadFieldU64(
        uint64_t base,
        const std::wstring& typeName,
        const std::vector<std::wstring>& fieldNames,
        uint64_t* value,
        TypeFieldInfo* matchedField,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid field value output";
                }
                break;
            }

            TypeFieldInfo field = {};
            if (!FindField(typeName, fieldNames, &field, error))
            {
                break;
            }

            uint32_t width = static_cast<uint32_t>(field.Length);
            if (field.ChildTag == KNDBG_SYMTAG_POINTER_TYPE)
            {
                width = sizeof(uint64_t);
            }

            if (width == 0 || width > sizeof(uint64_t))
            {
                width = sizeof(uint64_t);
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

            std::vector<uint8_t> bytes;
            if (!ReadBytes(fieldAddress, width, &bytes, error))
            {
                break;
            }

            uint64_t localValue = 0;
            memcpy(&localValue, bytes.data(), width);
            *value = localValue;

            if (matchedField != nullptr)
            {
                *matchedField = field;
            }

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

    bool FindFieldInTypes(
        const std::vector<std::wstring>& typeNames,
        const std::vector<std::wstring>& fieldNames,
        std::wstring* matchedType,
        TypeFieldInfo* field,
        std::wstring* error)
    {
        bool ok = false;
        std::wstring lastError;

        do
        {
            for (const std::wstring& typeName : typeNames)
            {
                TypeFieldInfo candidate = {};
                std::wstring localError;
                if (FindField(typeName, fieldNames, &candidate, &localError))
                {
                    if (matchedType != nullptr)
                    {
                        *matchedType = typeName;
                    }
                    if (field != nullptr)
                    {
                        *field = candidate;
                    }
                    ok = true;
                    break;
                }

                lastError = localError;
            }

            if (!ok && error != nullptr)
            {
                *error = lastError.empty() ? L"Field was not found" : lastError;
            }
        } while (false);

        return ok;
    }

    bool ReadFieldU64InTypes(
        uint64_t base,
        const std::vector<std::wstring>& typeNames,
        const std::vector<std::wstring>& fieldNames,
        std::wstring* matchedType,
        uint64_t* value,
        TypeFieldInfo* matchedField,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            std::wstring typeName;
            TypeFieldInfo field = {};
            if (!FindFieldInTypes(typeNames, fieldNames, &typeName, &field, error))
            {
                break;
            }

            uint32_t width = static_cast<uint32_t>(field.Length);
            if (field.ChildTag == KNDBG_SYMTAG_POINTER_TYPE)
            {
                width = sizeof(uint64_t);
            }

            if (width == 0 || width > sizeof(uint64_t))
            {
                width = sizeof(uint64_t);
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

            std::vector<uint8_t> bytes;
            if (!ReadBytes(fieldAddress, width, &bytes, error))
            {
                break;
            }

            uint64_t localValue = 0;
            memcpy(&localValue, bytes.data(), width);
            if (value != nullptr)
            {
                *value = localValue;
            }
            if (matchedType != nullptr)
            {
                *matchedType = typeName;
            }
            if (matchedField != nullptr)
            {
                *matchedField = field;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadUnicodeString(uint64_t address, std::wstring* value, std::wstring* error)
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

            uint64_t lengthValue = 0;
            uint64_t bufferValue = 0;
            TypeFieldInfo lengthField = {};
            TypeFieldInfo bufferField = {};
            std::wstring localError;

            if (FindField(L"nt!_UNICODE_STRING", {L"Length"}, &lengthField, &localError) &&
                FindField(L"nt!_UNICODE_STRING", {L"Buffer"}, &bufferField, &localError))
            {
                if (!ReadFieldU64(address, L"nt!_UNICODE_STRING", {L"Length"}, &lengthValue, nullptr, error))
                {
                    break;
                }

                if (!ReadFieldU64(address, L"nt!_UNICODE_STRING", {L"Buffer"}, &bufferValue, nullptr, error))
                {
                    break;
                }
            }
            else
            {
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
                        *error = L"UNICODE_STRING buffer field address overflow";
                    }
                    break;
                }

                if (!ReadU64(bufferFieldAddress, &bufferValue, error))
                {
                    break;
                }

                lengthValue = length16;
            }

            if (lengthValue == 0 || bufferValue == 0)
            {
                value->clear();
                ok = true;
                break;
            }

            if (lengthValue > 4096)
            {
                lengthValue = 4096;
            }

            std::vector<uint8_t> bytes;
            if (!ReadBytes(bufferValue, static_cast<uint32_t>(lengthValue), &bytes, error))
            {
                break;
            }

            value->assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadFieldUnicodeString(
        uint64_t base,
        const std::wstring& typeName,
        const std::vector<std::wstring>& fieldNames,
        std::wstring* value,
        TypeFieldInfo* matchedField,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid unicode field output";
                }
                break;
            }

            TypeFieldInfo field = {};
            if (!FindField(typeName, fieldNames, &field, error))
            {
                break;
            }

            uint64_t fieldAddress = 0;
            if (!TryAdd(base, field.Offset, &fieldAddress))
            {
                if (error != nullptr)
                {
                    *error = L"Unicode field address overflow";
                }
                break;
            }

            if (!ReadUnicodeString(fieldAddress, value, error))
            {
                break;
            }

            if (matchedField != nullptr)
            {
                *matchedField = field;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveSymbolAddress(const std::wstring& symbolName, uint64_t* address, std::wstring* error)
    {
        return symbols_.ResolveSymbol(symbolName, address, error);
    }

    bool EnumerateSymbols(
        const std::wstring& mask,
        size_t limit,
        std::vector<SymbolMatchInfo>* matches,
        std::wstring* error)
    {
        return symbols_.EnumerateSymbols(mask, limit, matches, error);
    }

    bool ResolveGlobalPointer(const std::wstring& symbolName, uint64_t* pointerValue, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (pointerValue == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid pointer output";
                }
                break;
            }

            uint64_t symbolAddress = 0;
            if (!ResolveSymbolAddress(symbolName, &symbolAddress, error))
            {
                break;
            }

            if (!ReadU64(symbolAddress, pointerValue, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadObjectTypeName(uint64_t objectTypeAddress, std::wstring* name, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (name == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid object type name output";
                }
                break;
            }

            TypeFieldInfo nameField = {};
            if (!FindField(L"nt!_OBJECT_TYPE", {L"Name", L"TypeName"}, &nameField, error))
            {
                break;
            }

            uint64_t nameAddress = 0;
            if (!TryAdd(objectTypeAddress, nameField.Offset, &nameAddress))
            {
                if (error != nullptr)
                {
                    *error = L"Object type name address overflow";
                }
                break;
            }

            if (!ReadUnicodeString(nameAddress, name, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool DiscoverObjectTypes(std::vector<ObjectTypeTarget>* targets, std::wstring* error)
    {
        bool ok = false;
        std::vector<std::wstring> warnings;

        do
        {
            if (targets == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid object type target output";
                }
                break;
            }

            targets->clear();

            const std::wstring tableSymbols[] =
            {
                L"nt!ObTypeIndexTable",
                L"nt!ObpTypeIndexTable"
            };

            for (const std::wstring& tableSymbol : tableSymbols)
            {
                std::wstring localError;
                if (DiscoverObjectTypesFromIndexTable(tableSymbol, targets, &localError))
                {
                    ok = true;
                    break;
                }

                warnings.push_back(tableSymbol + L": " + localError);
            }

            if (!ok && error != nullptr)
            {
                std::wstring message;
                for (const std::wstring& warning : warnings)
                {
                    if (!message.empty())
                    {
                        message += L"; ";
                    }
                    message += warning;
                }

                *error = message.empty() ? L"Object type discovery failed" : message;
            }
        } while (false);

        return ok;
    }

    void AnnotateAddress(uint64_t address, std::wstring* moduleName, std::wstring* symbolName)
    {
        if (moduleName != nullptr)
        {
            moduleName->clear();
        }
        if (symbolName != nullptr)
        {
            symbolName->clear();
        }

        do
        {
            if (address == 0)
            {
                break;
            }

            std::wstring owned;
            if (FindModuleNameForAddress(address, &owned) && moduleName != nullptr)
            {
                *moduleName = owned;
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols_.FindNearestSymbol(address, &nearest, &displacement, &ignored))
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

    bool IsKernelPointer(uint64_t value) const
    {
        return value >= 0xffff800000000000ull;
    }

    bool IsKernelImagePointer(uint64_t value) const
    {
        bool result = false;

        do
        {
            if (value == 0)
            {
                break;
            }

            result = FindModuleNameForAddress(value, nullptr);
        } while (false);

        return result;
    }

    uint64_t DecodeFastRef(uint64_t value) const
    {
        return value & ~0xfull;
    }

    bool GetTypeLayoutInfo(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error)
    {
        return GetLayout(typeName, layout, error);
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result) const
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

    bool TrySubtract(uint64_t left, uint64_t right, uint64_t* result) const
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

private:
    bool DiscoverObjectTypesFromIndexTable(
        const std::wstring& tableSymbol,
        std::vector<ObjectTypeTarget>* targets,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (targets == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Invalid object type target output";
                }
                break;
            }

            uint64_t tableAddress = 0;
            if (!ResolveSymbolAddress(tableSymbol, &tableAddress, error))
            {
                break;
            }

            TypeFieldInfo nameField = {};
            if (!FindField(L"nt!_OBJECT_TYPE", {L"Name", L"TypeName"}, &nameField, error))
            {
                break;
            }

            std::vector<ObjectTypeTarget> found;
            for (uint32_t index = 0; index < 256; ++index)
            {
                uint64_t slotAddress = 0;
                if (!TryAdd(tableAddress, static_cast<uint64_t>(index) * sizeof(uint64_t), &slotAddress))
                {
                    break;
                }

                uint64_t objectTypeAddress = 0;
                std::wstring readError;
                if (!ReadU64(slotAddress, &objectTypeAddress, &readError))
                {
                    break;
                }

                if (objectTypeAddress == 0 || !IsKernelPointer(objectTypeAddress))
                {
                    continue;
                }

                bool duplicate = false;
                for (const ObjectTypeTarget& existing : found)
                {
                    if (existing.Address == objectTypeAddress)
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
                if (!TryAdd(objectTypeAddress, nameField.Offset, &nameAddress))
                {
                    continue;
                }

                std::wstring typeName;
                if (!ReadUnicodeString(nameAddress, &typeName, nullptr))
                {
                    continue;
                }

                if (typeName.empty())
                {
                    continue;
                }

                std::wstringstream source;
                source << tableSymbol << L"[0x" << std::hex << index << L"]";

                ObjectTypeTarget target = {};
                target.Name = typeName;
                target.Source = source.str();
                target.Address = objectTypeAddress;
                target.TypeIndex = index;
                found.push_back(target);
            }

            if (found.empty())
            {
                if (error != nullptr)
                {
                    *error = L"No valid object types were found";
                }
                break;
            }

            *targets = std::move(found);
            ok = true;
        } while (false);

        return ok;
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

            auto found = layouts_.find(typeName);
            if (found != layouts_.end())
            {
                *layout = found->second;
                ok = true;
                break;
            }

            TypeLayoutInfo localLayout = {};
            if (!symbols_.GetTypeLayout(typeName, &localLayout, error))
            {
                break;
            }

            layouts_[typeName] = localLayout;
            *layout = localLayout;
            ok = true;
        } while (false);

        return ok;
    }

    bool FindModuleNameForAddress(uint64_t address, std::wstring* name) const
    {
        bool found = false;
        const std::vector<KernelModuleInfo> modules = symbols_.CopyModules();
        for (const KernelModuleInfo& module : modules)
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }

            if (address >= module.Base && address < end)
            {
                if (name != nullptr)
                {
                    *name = module.ImageName;
                }
                found = true;
                break;
            }
        }

        return found;
    }

    DeviceClient& device_;
    SymbolEngine& symbols_;
    std::map<std::wstring, TypeLayoutInfo> layouts_;
};

static TypeFieldInfo MakeSyntheticField(
    const std::wstring& name,
    const std::wstring& typeName,
    ULONG offset,
    ULONG64 length,
    DWORD childTag)
{
    TypeFieldInfo field = {};

    field.Name = name;
    field.TypeName = typeName;
    field.Offset = offset;
    field.Length = length;
    field.ChildTag = childTag;

    return field;
}

static bool ReadFieldValueByDescriptor(
    CallbackScanContext& context,
    uint64_t base,
    const TypeFieldInfo& field,
    uint64_t* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid field value output";
            }
            break;
        }

        uint32_t width = static_cast<uint32_t>(field.Length);
        if (field.ChildTag == KNDBG_SYMTAG_POINTER_TYPE)
        {
            width = sizeof(uint64_t);
        }

        if (width == 0 || width > sizeof(uint64_t))
        {
            width = sizeof(uint64_t);
        }

        uint64_t fieldAddress = 0;
        if (!context.TryAdd(base, field.Offset, &fieldAddress))
        {
            if (error != nullptr)
            {
                *error = L"Field address overflow";
            }
            break;
        }

        std::vector<uint8_t> bytes;
        if (!context.ReadBytes(fieldAddress, width, &bytes, error))
        {
            break;
        }

        uint64_t localValue = 0;
        memcpy(&localValue, bytes.data(), width);
        *value = localValue;
        ok = true;
    } while (false);

    return ok;
}

static bool ReadUnicodeStringCandidate(
    CallbackScanContext& context,
    uint64_t address,
    std::wstring* value,
    std::wstring* error)
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

        uint16_t length = 0;
        uint16_t maximumLength = 0;
        uint64_t buffer = 0;
        uint64_t maximumLengthAddress = 0;
        uint64_t bufferAddress = 0;
        if (!context.ReadU16(address, &length, error))
        {
            break;
        }

        if (!context.TryAdd(address, sizeof(uint16_t), &maximumLengthAddress) ||
            !context.TryAdd(address, 8, &bufferAddress))
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING candidate address overflow";
            }
            break;
        }

        if (!context.ReadU16(maximumLengthAddress, &maximumLength, error))
        {
            break;
        }

        if (!context.ReadU64(bufferAddress, &buffer, error))
        {
            break;
        }

        if (length == 0 || (length & 1) != 0 || length > 1024)
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING candidate has an invalid length";
            }
            break;
        }

        if (maximumLength < length || maximumLength > 4096)
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING candidate has an invalid maximum length";
            }
            break;
        }

        if (!context.IsKernelPointer(buffer))
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING candidate buffer is not a kernel pointer";
            }
            break;
        }

        if (!context.ReadUnicodeString(address, value, error))
        {
            break;
        }

        if (value->empty())
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING candidate is empty";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ReadObjectCallbackRegistrationMetadata(
    CallbackScanContext& context,
    uint64_t callbackEntry,
    uint64_t* registrationContext,
    std::wstring* altitude)
{
    bool ok = false;

    do
    {
        if (registrationContext != nullptr)
        {
            *registrationContext = 0;
        }

        if (altitude != nullptr)
        {
            altitude->clear();
        }

        if (callbackEntry == 0 || !context.IsKernelPointer(callbackEntry))
        {
            break;
        }

        std::wstring matchedType;
        TypeFieldInfo altitudeField = {};
        TypeFieldInfo contextField = {};
        const std::vector<std::wstring> registrationTypes =
        {
            L"nt!_CALLBACK_ENTRY",
            L"nt!_OB_CALLBACK_REGISTRATION",
            L"nt!_OBJECT_CALLBACK_REGISTRATION"
        };

        if (context.FindFieldInTypes(registrationTypes, {L"RegistrationContext"}, &matchedType, &contextField, nullptr))
        {
            uint64_t contextValue = 0;
            if (context.ReadFieldU64(callbackEntry, matchedType, {L"RegistrationContext"}, &contextValue, nullptr, nullptr))
            {
                if (registrationContext != nullptr)
                {
                    *registrationContext = contextValue;
                }
            }
        }

        if (context.FindFieldInTypes(registrationTypes, {L"Altitude"}, &matchedType, &altitudeField, nullptr))
        {
            std::wstring pdbAltitude;
            uint64_t altitudeAddress = 0;
            if (context.TryAdd(callbackEntry, altitudeField.Offset, &altitudeAddress) &&
                context.ReadUnicodeString(altitudeAddress, &pdbAltitude, nullptr))
            {
                if (altitude != nullptr)
                {
                    *altitude = pdbAltitude;
                }
                ok = true;
                break;
            }
        }

        struct Candidate
        {
            uint64_t AltitudeOffset;
            uint64_t ContextOffset;
        };

        const Candidate candidates[] =
        {
            {0x8, 0x18},
            {0x10, 0x8}
        };

        for (const Candidate& candidate : candidates)
        {
            std::wstring candidateAltitude;
            uint64_t altitudeAddress = 0;
            if (!context.TryAdd(callbackEntry, candidate.AltitudeOffset, &altitudeAddress))
            {
                continue;
            }

            if (!ReadUnicodeStringCandidate(context, altitudeAddress, &candidateAltitude, nullptr))
            {
                continue;
            }

            uint64_t contextValue = 0;
            uint64_t contextAddress = 0;
            if (context.TryAdd(callbackEntry, candidate.ContextOffset, &contextAddress))
            {
                context.ReadU64(contextAddress, &contextValue, nullptr);
            }

            if (registrationContext != nullptr)
            {
                *registrationContext = contextValue;
            }
            if (altitude != nullptr)
            {
                *altitude = candidateAltitude;
            }

            ok = true;
            break;
        }
    } while (false);

    return ok;
}

static bool ValidateObjectCallbackItemFields(
    CallbackScanContext& context,
    uint64_t callbackEntry,
    uint64_t preOperation,
    uint64_t postOperation,
    uint64_t operations,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (callbackEntry == 0 || !context.IsKernelPointer(callbackEntry))
        {
            if (error != nullptr)
            {
                *error = L"Object callback item CallbackEntry is not a kernel pointer";
            }
            break;
        }

        if (preOperation != 0 && !context.IsKernelPointer(preOperation))
        {
            if (error != nullptr)
            {
                *error = L"Object callback item PreOperation is not a kernel pointer";
            }
            break;
        }

        if (postOperation != 0 && !context.IsKernelPointer(postOperation))
        {
            if (error != nullptr)
            {
                *error = L"Object callback item PostOperation is not a kernel pointer";
            }
            break;
        }

        if (operations == 0 || (operations & ~0x3ull) != 0)
        {
            if (error != nullptr)
            {
                *error = L"Object callback item Operations value is invalid";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ResolveOptionalObjectCallbackItemField(
    CallbackScanContext& context,
    const ObjectCallbackLayout& layout,
    const std::vector<std::wstring>& fieldNames,
    const TypeFieldInfo& fallback,
    TypeFieldInfo* field,
    bool* usedFallback)
{
    bool ok = false;

    do
    {
        if (field == nullptr)
        {
            break;
        }

        if (!layout.UsedSyntheticItemType &&
            context.FindField(layout.ItemType, fieldNames, field, nullptr))
        {
            if (usedFallback != nullptr)
            {
                *usedFallback = false;
            }
            ok = true;
            break;
        }

        *field = fallback;
        if (usedFallback != nullptr)
        {
            *usedFallback = true;
        }
        ok = true;
    } while (false);

    return ok;
}

static bool BuildObjectCallbackLayout(
    CallbackScanContext& context,
    ObjectCallbackLayout* layout,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid object callback layout output";
            }
            break;
        }

        *layout = {};

        if (!context.FindField(L"nt!_OBJECT_TYPE", {L"CallbackList"}, &layout->ObjectCallbackList, error))
        {
            break;
        }

        const std::vector<std::wstring> itemTypes =
        {
            L"nt!_CALLBACK_ENTRY_ITEM",
            L"nt!_OB_CALLBACK_ENTRY_ITEM",
            L"nt!_OB_CALLBACK_ENTRY"
        };

        if (!context.FindFieldInTypes(
                itemTypes,
                {L"EntryItemList", L"CallbackList", L"ListEntry", L"List"},
                &layout->ItemType,
                &layout->ItemList,
                nullptr))
        {
            layout->ItemType = L"nt!_OB_CALLBACK_ENTRY(fallback)";
            layout->ItemList = MakeSyntheticField(L"EntryItemList", L"nt!_LIST_ENTRY", 0x0, 0x10, 0);
            layout->UsedSyntheticItemType = true;
            layout->UsedSyntheticFields = true;
        }

        TypeFieldInfo operationsFallback = MakeSyntheticField(L"Operations", L"unsigned long", 0x10, sizeof(uint32_t), 0);
        TypeFieldInfo callbackEntryFallback = MakeSyntheticField(L"CallbackEntry", L"void*", 0x18, sizeof(uint64_t), KNDBG_SYMTAG_POINTER_TYPE);
        TypeFieldInfo preFallback = MakeSyntheticField(L"PreOperation", L"void*", 0x28, sizeof(uint64_t), KNDBG_SYMTAG_POINTER_TYPE);
        TypeFieldInfo postFallback = MakeSyntheticField(L"PostOperation", L"void*", 0x30, sizeof(uint64_t), KNDBG_SYMTAG_POINTER_TYPE);
        bool usedFallback = false;
        bool usedAnyFallback = layout->UsedSyntheticFields;

        ResolveOptionalObjectCallbackItemField(
            context,
            *layout,
            {L"Operations"},
            operationsFallback,
            &layout->Operations,
            &usedFallback);
        usedAnyFallback = usedAnyFallback || usedFallback;
        ResolveOptionalObjectCallbackItemField(
            context,
            *layout,
            {L"CallbackEntry", L"Registration", L"Entry"},
            callbackEntryFallback,
            &layout->CallbackEntry,
            &usedFallback);
        usedAnyFallback = usedAnyFallback || usedFallback;
        ResolveOptionalObjectCallbackItemField(
            context,
            *layout,
            {L"PreOperation", L"PreCallback"},
            preFallback,
            &layout->PreOperation,
            &usedFallback);
        usedAnyFallback = usedAnyFallback || usedFallback;
        ResolveOptionalObjectCallbackItemField(
            context,
            *layout,
            {L"PostOperation", L"PostCallback"},
            postFallback,
            &layout->PostOperation,
            &usedFallback);
        usedAnyFallback = usedAnyFallback || usedFallback;
        layout->UsedSyntheticFields = usedAnyFallback;

        ok = true;
    } while (false);

    return ok;
}

static bool BuildExCallbackBlockLayout(
    CallbackScanContext& context,
    ExCallbackBlockLayout* layout,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid EX callback block layout output";
            }
            break;
        }

        *layout = {};
        (void)context;

        layout->Function = MakeSyntheticField(
            L"Function",
            L"void*",
            0x8,
            sizeof(uint64_t),
            KNDBG_SYMTAG_POINTER_TYPE);
        layout->Context = MakeSyntheticField(
            L"Context",
            L"void*",
            0x10,
            sizeof(uint64_t),
            KNDBG_SYMTAG_POINTER_TYPE);
        layout->UsedSyntheticFields = true;
        ok = true;
    } while (false);

    return ok;
}

static bool BuildRegistryCallbackLayouts(
    CallbackScanContext& context,
    std::vector<RegistryCallbackLayout>* layouts,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layouts == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid registry callback layout output";
            }
            break;
        }

        layouts->clear();
        (void)context;

        RegistryCallbackLayout syntheticCurrent = {};
        syntheticCurrent.BlockType = L"x64::_CM_CALLBACK_CONTEXT_BLOCK";
        syntheticCurrent.ListEntry = MakeSyntheticField(
            L"CallbackListEntry",
            L"_LIST_ENTRY",
            0x0,
            sizeof(uint64_t) * 2,
            KNDBG_SYMTAG_UDT);
        syntheticCurrent.Cookie = MakeSyntheticField(
            L"Cookie",
            L"uint64_t",
            0x10,
            sizeof(uint64_t),
            KNDBG_SYMTAG_BASE_TYPE);
        syntheticCurrent.Context = MakeSyntheticField(
            L"Context",
            L"void*",
            0x18,
            sizeof(uint64_t),
            KNDBG_SYMTAG_POINTER_TYPE);
        syntheticCurrent.PreCallback = MakeSyntheticField(
            L"Function",
            L"void*",
            0x20,
            sizeof(uint64_t),
            KNDBG_SYMTAG_POINTER_TYPE);
        syntheticCurrent.Altitude = MakeSyntheticField(
            L"Altitude",
            L"_UNICODE_STRING",
            0x28,
            sizeof(uint64_t) * 2,
            KNDBG_SYMTAG_UDT);
        syntheticCurrent.UsedSyntheticFields = true;
        layouts->push_back(syntheticCurrent);

        RegistryCallbackLayout syntheticLegacy = syntheticCurrent;
        syntheticLegacy.PreCallback.Offset = 0x10;
        syntheticLegacy.Context.Offset = 0x18;
        syntheticLegacy.Cookie.Offset = 0x20;
        syntheticLegacy.Altitude.Offset = 0x28;
        layouts->push_back(syntheticLegacy);

        ok = !layouts->empty();
    } while (false);

    return ok;
}

static std::wstring ToLowerLocal(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    return result;
}

static std::wstring JoinWarnings(const std::vector<std::wstring>& warnings)
{
    std::wstring result;

    for (const std::wstring& warning : warnings)
    {
        if (!result.empty())
        {
            result += L"; ";
        }

        result += warning;
    }

    return result;
}

static bool HasObjectTypeTargetAddress(const std::vector<ObjectTypeTarget>& targets, uint64_t address)
{
    bool found = false;

    for (const ObjectTypeTarget& target : targets)
    {
        if (target.Address == address)
        {
            found = true;
            break;
        }
    }

    return found;
}

static bool AddObjectTypeTargetIfUnique(std::vector<ObjectTypeTarget>* targets, const ObjectTypeTarget& target)
{
    bool added = false;

    do
    {
        if (targets == nullptr || target.Address == 0)
        {
            break;
        }

        if (HasObjectTypeTargetAddress(*targets, target.Address))
        {
            break;
        }

        targets->push_back(target);
        added = true;
    } while (false);

    return added;
}

static bool HasCallbackRootAddress(const std::vector<CallbackRoot>& roots, uint64_t address)
{
    bool found = false;

    for (const CallbackRoot& root : roots)
    {
        if (root.Address == address)
        {
            found = true;
            break;
        }
    }

    return found;
}

static bool AddCallbackRootIfUnique(std::vector<CallbackRoot>* roots, const CallbackRoot& root)
{
    bool added = false;

    do
    {
        if (roots == nullptr || root.Address == 0)
        {
            break;
        }

        if (HasCallbackRootAddress(*roots, root.Address))
        {
            break;
        }

        roots->push_back(root);
        added = true;
    } while (false);

    return added;
}

static bool SourceMatchesSymbolName(const std::wstring& source, const std::wstring& symbolName)
{
    bool matches = false;

    do
    {
        std::wstring leaf = source;
        size_t bang = leaf.find_last_of(L'!');
        if (bang != std::wstring::npos)
        {
            leaf = leaf.substr(bang + 1);
        }

        std::wstring normalizedSource = ToLowerLocal(leaf);
        std::wstring normalizedSymbol = ToLowerLocal(symbolName);

        if (normalizedSource == normalizedSymbol)
        {
            matches = true;
        }
    } while (false);

    return matches;
}

static void AddResolvedCallbackRoot(
    CallbackScanContext& context,
    const std::wstring& symbolName,
    std::vector<CallbackRoot>* roots,
    std::vector<std::wstring>* warnings)
{
    do
    {
        if (roots == nullptr)
        {
            break;
        }

        uint64_t address = 0;
        std::wstring error;
        if (!context.ResolveSymbolAddress(symbolName, &address, &error))
        {
            if (warnings != nullptr)
            {
                warnings->push_back(symbolName + L": " + error);
            }
            break;
        }

        CallbackRoot root = {};
        root.Name = symbolName;
        root.Source = symbolName;
        root.Address = address;
        AddCallbackRootIfUnique(roots, root);
    } while (false);
}

static void AddEnumeratedCallbackRoots(
    CallbackScanContext& context,
    const std::vector<std::wstring>& masks,
    size_t limit,
    std::vector<CallbackRoot>* roots,
    std::vector<std::wstring>* warnings)
{
    do
    {
        if (roots == nullptr)
        {
            break;
        }

        for (const std::wstring& mask : masks)
        {
            std::vector<SymbolMatchInfo> matches;
            std::wstring error;
            if (!context.EnumerateSymbols(mask, limit, &matches, &error))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(mask + L": " + error);
                }
                continue;
            }

            for (const SymbolMatchInfo& match : matches)
            {
                if (match.Address == 0)
                {
                    continue;
                }

                CallbackRoot root = {};
                root.Name = match.Name.empty() ? mask : match.Name;
                root.Source = root.Name;
                root.Address = match.Address;
                AddCallbackRootIfUnique(roots, root);
            }
        }
    } while (false);
}

static bool ScanExCallbackTableRoot(
    CallbackScanContext& context,
    const CallbackRoot& root,
    const ExCallbackBlockLayout& layout,
    const std::wstring& kind,
    const std::wstring& target,
    const std::wstring& fallbackNote,
    bool allowEmpty,
    KernelCallbackScanResult* result,
    uint32_t* recordCount,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr || recordCount == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid callback table output";
            }
            break;
        }

        *recordCount = 0;
        std::vector<KernelCallbackRecord> records;
        uint32_t nonZeroSlots = 0;
        bool tableReadOk = true;

        for (uint32_t slot = 0; slot < 64; ++slot)
        {
            uint64_t slotAddress = 0;
            if (!context.TryAdd(root.Address, static_cast<uint64_t>(slot) * sizeof(uint64_t), &slotAddress))
            {
                if (error != nullptr)
                {
                    *error = L"Callback table slot address overflow";
                }
                tableReadOk = false;
                break;
            }

            uint64_t rawValue = 0;
            std::wstring readError;
            if (!context.ReadU64(slotAddress, &rawValue, &readError))
            {
                if (error != nullptr)
                {
                    *error = readError;
                }
                tableReadOk = false;
                break;
            }

            if (rawValue == 0)
            {
                continue;
            }

            ++nonZeroSlots;

            uint64_t blockAddress = context.DecodeFastRef(rawValue);
            if (blockAddress == 0 || !context.IsKernelPointer(blockAddress))
            {
                continue;
            }

            uint64_t functionAddressField = 0;
            if (!context.TryAdd(blockAddress, layout.Function.Offset, &functionAddressField))
            {
                continue;
            }

            uint64_t functionAddress = 0;
            if (!context.ReadU64(functionAddressField, &functionAddress, &readError))
            {
                continue;
            }

            if (!context.IsKernelPointer(functionAddress))
            {
                continue;
            }

            uint64_t callbackContext = 0;
            uint64_t contextAddressField = 0;
            if (context.TryAdd(blockAddress, layout.Context.Offset, &contextAddressField))
            {
                context.ReadU64(contextAddressField, &callbackContext, nullptr);
            }

            KernelCallbackRecord record = {};
            record.Kind = kind;
            record.Target = target;
            record.Slot = slot;
            record.RootAddress = root.Address;
            record.RootSource = root.Source;
            record.RawValue = rawValue;
            record.CallbackBlock = blockAddress;
            record.Function = functionAddress;
            record.FunctionSlot = functionAddressField;
            record.Context = callbackContext;
            if (layout.UsedSyntheticFields)
            {
                record.Notes = fallbackNote;
            }
            context.AnnotateAddress(record.Function, &record.FunctionModule, &record.FunctionSymbol);
            if (context.IsKernelImagePointer(record.Context))
            {
                context.AnnotateAddress(record.Context, &record.ContextModule, &record.ContextSymbol);
            }
            records.push_back(record);
        }

        if (!tableReadOk)
        {
            break;
        }

        if (!allowEmpty && records.empty())
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"No valid " << kind << L" callback blocks at " << root.Source
                       << L" nonZeroSlots=" << nonZeroSlots;
                *error = stream.str();
            }
            break;
        }

        result->Records.insert(result->Records.end(), records.begin(), records.end());
        *recordCount = static_cast<uint32_t>(records.size());
        ok = true;
    } while (false);

    return ok;
}

static bool ScanRegistryCallbackListRoot(
    CallbackScanContext& context,
    const CallbackRoot& root,
    const RegistryCallbackLayout& layout,
    bool allowEmpty,
    KernelCallbackScanResult* result,
    uint32_t* recordCount,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr || recordCount == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid registry callback list output";
            }
            break;
        }

        *recordCount = 0;
        ListEntryValue head = {};
        if (!context.ReadListEntry(root.Address, &head, error))
        {
            break;
        }

        if (head.Flink == 0 || head.Blink == 0)
        {
            if (error != nullptr)
            {
                *error = L"Registry callback list head is null";
            }
            break;
        }

        bool emptyList = head.Flink == root.Address && head.Blink == root.Address;
        if (emptyList)
        {
            if (!allowEmpty)
            {
                if (error != nullptr)
                {
                    *error = L"Registry callback list candidate is empty";
                }
                break;
            }

            ok = true;
            break;
        }

        if (!context.IsKernelPointer(head.Flink) || !context.IsKernelPointer(head.Blink))
        {
            if (error != nullptr)
            {
                *error = L"Registry callback list head does not contain kernel links";
            }
            break;
        }

        std::vector<KernelCallbackRecord> records;
        uint64_t current = head.Flink;
        bool listWalkOk = true;
        for (uint32_t index = 0; index < 512 && current != 0 && current != root.Address; ++index)
        {
            if (!context.IsKernelPointer(current))
            {
                listWalkOk = false;
                if (error != nullptr)
                {
                    *error = L"Registry callback list entry is not a kernel pointer";
                }
                break;
            }

            ListEntryValue entryLinks = {};
            std::wstring readError;
            if (!context.ReadListEntry(current, &entryLinks, &readError))
            {
                listWalkOk = false;
                if (error != nullptr)
                {
                    *error = readError;
                }
                break;
            }

            uint64_t blockAddress = 0;
            if (!context.TrySubtract(current, layout.ListEntry.Offset, &blockAddress))
            {
                listWalkOk = false;
                if (error != nullptr)
                {
                    *error = L"Registry callback block address underflow";
                }
                break;
            }

            uint64_t preCallback = 0;
            uint64_t postCallback = 0;
            uint64_t callbackContext = 0;
            uint64_t cookie = 0;

            if (layout.PreCallback.Length != 0)
            {
                ReadFieldValueByDescriptor(context, blockAddress, layout.PreCallback, &preCallback, nullptr);
                // Keep outside-module kernel pointers: they are the primary Cm
                // hook signal (pool shellcode, manual-map drivers). Only drop
                // non-canonical / non-kernel garbage so list noise does not
                // become fake records. Do NOT require IsKernelImagePointer.
                if (preCallback != 0 && !context.IsKernelPointer(preCallback))
                {
                    preCallback = 0;
                }
            }

            if (layout.PostCallback.Length != 0)
            {
                ReadFieldValueByDescriptor(context, blockAddress, layout.PostCallback, &postCallback, nullptr);
                if (postCallback != 0 && !context.IsKernelPointer(postCallback))
                {
                    postCallback = 0;
                }
            }

            if (layout.Context.Length != 0)
            {
                ReadFieldValueByDescriptor(context, blockAddress, layout.Context, &callbackContext, nullptr);
            }

            if (layout.Cookie.Length != 0)
            {
                ReadFieldValueByDescriptor(context, blockAddress, layout.Cookie, &cookie, nullptr);
            }

            std::wstring altitude;
            if (layout.Altitude.Length != 0)
            {
                uint64_t altitudeAddress = 0;
                if (context.TryAdd(blockAddress, layout.Altitude.Offset, &altitudeAddress))
                {
                    context.ReadUnicodeString(altitudeAddress, &altitude, nullptr);
                }
            }

            if (preCallback != 0 || postCallback != 0)
            {
                KernelCallbackRecord record = {};
                record.Kind = L"registry";
                record.Target = L"registry";
                record.Slot = index;
                record.RootAddress = root.Address;
                record.RootSource = root.Source;
                record.ListEntry = current;
                record.Entry = blockAddress;
                record.Function = preCallback;
                record.PostFunction = postCallback;
                if (layout.PreCallback.Length != 0)
                {
                    context.TryAdd(blockAddress, layout.PreCallback.Offset, &record.FunctionSlot);
                }
                if (layout.PostCallback.Length != 0)
                {
                    context.TryAdd(blockAddress, layout.PostCallback.Offset, &record.PostFunctionSlot);
                }
                record.Context = callbackContext;
                record.Cookie = cookie;
                record.Altitude = altitude;
                if (layout.UsedSyntheticFields)
                {
                    record.Notes = L"x64 fallback registry callback block layout";
                }
                context.AnnotateAddress(record.Function, &record.FunctionModule, &record.FunctionSymbol);
                context.AnnotateAddress(record.PostFunction, &record.PostFunctionModule, &record.PostFunctionSymbol);
                if (context.IsKernelImagePointer(record.Context))
                {
                    context.AnnotateAddress(record.Context, &record.ContextModule, &record.ContextSymbol);
                }

                // Surface outside-module pre/post as explicit notes so console
                // and JSON consumers treat them as high-signal hooks, not noise.
                const bool preOutsideModule =
                    record.Function != 0 && record.FunctionModule.empty();
                const bool postOutsideModule =
                    record.PostFunction != 0 && record.PostFunctionModule.empty();
                if (preOutsideModule || postOutsideModule)
                {
                    std::wstring outsideNote = L"function outside loaded modules";
                    if (preOutsideModule && postOutsideModule)
                    {
                        outsideNote = L"pre/post outside loaded modules";
                    }
                    else if (postOutsideModule)
                    {
                        outsideNote = L"post outside loaded modules";
                    }
                    else
                    {
                        outsideNote = L"pre outside loaded modules";
                    }

                    if (record.Notes.empty())
                    {
                        record.Notes = outsideNote;
                    }
                    else
                    {
                        record.Notes += L"; ";
                        record.Notes += outsideNote;
                    }
                }

                records.push_back(record);
            }

            current = entryLinks.Flink;
        }

        if (!listWalkOk)
        {
            break;
        }

        if (records.empty())
        {
            if (error != nullptr)
            {
                *error = L"No valid registry callback blocks were found";
            }
            break;
        }

        result->Records.insert(result->Records.end(), records.begin(), records.end());
        *recordCount = static_cast<uint32_t>(records.size());
        ok = true;
    } while (false);

    return ok;
}

struct MinifilterLayout
{
    std::wstring GlobalsType;
    std::wstring FrameType;
    std::wstring FilterType;
    std::wstring ObjectType;
    std::wstring ResourceListType;
    std::wstring OperationType;
    TypeFieldInfo GlobalsFrameList = {};
    TypeFieldInfo ResourceListEntry = {};
    TypeFieldInfo FrameLinks = {};
    TypeFieldInfo FrameId = {};
    TypeFieldInfo FrameRegisteredFilters = {};
    TypeFieldInfo FilterBase = {};
    TypeFieldInfo FilterName = {};
    TypeFieldInfo FilterAltitude = {};
    TypeFieldInfo FilterFlags = {};
    TypeFieldInfo FilterDriverObject = {};
    TypeFieldInfo FilterOperations = {};
    TypeFieldInfo ObjectPrimaryLink = {};
    TypeFieldInfo OperationMajorFunction = {};
    TypeFieldInfo OperationFlags = {};
    TypeFieldInfo OperationPre = {};
    TypeFieldInfo OperationPost = {};
    ULONG64 OperationSize = 0;
};

static bool AddOffset(CallbackScanContext& context, uint64_t base, ULONG offset, uint64_t* address, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!context.TryAdd(base, offset, address))
        {
            if (error != nullptr)
            {
                *error = L"Address overflow";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool BuildMinifilterLayout(CallbackScanContext& context, MinifilterLayout* layout, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid minifilter layout output";
            }
            break;
        }

        std::vector<std::wstring> globalsTypes =
        {
            L"fltmgr!_GLOBALS"
        };

        std::vector<std::wstring> frameTypes =
        {
            L"fltmgr!_FLTP_FRAME",
            L"_FLTP_FRAME"
        };

        std::vector<std::wstring> filterTypes =
        {
            L"fltmgr!_FLT_FILTER",
            L"_FLT_FILTER"
        };

        std::vector<std::wstring> objectTypes =
        {
            L"fltmgr!_FLT_OBJECT",
            L"_FLT_OBJECT"
        };

        std::vector<std::wstring> resourceListTypes =
        {
            L"fltmgr!_FLT_RESOURCE_LIST_HEAD",
            L"_FLT_RESOURCE_LIST_HEAD"
        };

        std::vector<std::wstring> operationTypes =
        {
            L"fltmgr!_FLT_OPERATION_REGISTRATION",
            L"_FLT_OPERATION_REGISTRATION"
        };

        if (!context.FindFieldInTypes(globalsTypes, {L"FrameList"}, &layout->GlobalsType, &layout->GlobalsFrameList, error))
        {
            break;
        }

        if (!context.FindFieldInTypes(resourceListTypes, {L"rList", L"List", L"ListHead"}, &layout->ResourceListType, &layout->ResourceListEntry, error))
        {
            break;
        }

        if (!context.FindFieldInTypes(frameTypes, {L"Links"}, &layout->FrameType, &layout->FrameLinks, error))
        {
            break;
        }

        if (!context.FindField(layout->FrameType, {L"FrameID", L"FrameId"}, &layout->FrameId, error))
        {
            break;
        }

        if (!context.FindField(layout->FrameType, {L"RegisteredFilters", L"FilterList"}, &layout->FrameRegisteredFilters, error))
        {
            break;
        }

        if (!context.FindFieldInTypes(filterTypes, {L"Base"}, &layout->FilterType, &layout->FilterBase, error))
        {
            break;
        }

        if (!context.FindField(layout->FilterType, {L"Name"}, &layout->FilterName, error))
        {
            break;
        }

        if (!context.FindField(layout->FilterType, {L"DefaultAltitude", L"Altitude"}, &layout->FilterAltitude, error))
        {
            break;
        }

        if (!context.FindField(layout->FilterType, {L"Flags"}, &layout->FilterFlags, error))
        {
            break;
        }

        if (!context.FindField(layout->FilterType, {L"DriverObject"}, &layout->FilterDriverObject, error))
        {
            break;
        }

        if (!context.FindField(layout->FilterType, {L"Operations"}, &layout->FilterOperations, error))
        {
            break;
        }

        if (!context.FindFieldInTypes(objectTypes, {L"PrimaryLink", L"Links"}, &layout->ObjectType, &layout->ObjectPrimaryLink, error))
        {
            break;
        }

        if (!context.FindFieldInTypes(operationTypes, {L"MajorFunction"}, &layout->OperationType, &layout->OperationMajorFunction, error))
        {
            break;
        }

        if (!context.FindField(layout->OperationType, {L"Flags"}, &layout->OperationFlags, error))
        {
            break;
        }

        if (!context.FindField(layout->OperationType, {L"PreOperation"}, &layout->OperationPre, error))
        {
            break;
        }

        if (!context.FindField(layout->OperationType, {L"PostOperation"}, &layout->OperationPost, error))
        {
            break;
        }

        TypeLayoutInfo operationLayout = {};
        if (!context.GetTypeLayoutInfo(layout->OperationType, &operationLayout, error))
        {
            break;
        }

        layout->OperationSize = operationLayout.Size;
        if (layout->OperationSize < 24 || layout->OperationSize > 512)
        {
            if (error != nullptr)
            {
                *error = L"Unexpected minifilter operation registration size";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static std::wstring MiniMajorFunctionName(uint32_t majorFunction)
{
    std::wstring name;

    switch (majorFunction)
    {
    case 0x00:
        name = L"IRP_MJ_CREATE";
        break;
    case 0x01:
        name = L"IRP_MJ_CREATE_NAMED_PIPE";
        break;
    case 0x02:
        name = L"IRP_MJ_CLOSE";
        break;
    case 0x03:
        name = L"IRP_MJ_READ";
        break;
    case 0x04:
        name = L"IRP_MJ_WRITE";
        break;
    case 0x05:
        name = L"IRP_MJ_QUERY_INFORMATION";
        break;
    case 0x06:
        name = L"IRP_MJ_SET_INFORMATION";
        break;
    case 0x07:
        name = L"IRP_MJ_QUERY_EA";
        break;
    case 0x08:
        name = L"IRP_MJ_SET_EA";
        break;
    case 0x09:
        name = L"IRP_MJ_FLUSH_BUFFERS";
        break;
    case 0x0a:
        name = L"IRP_MJ_QUERY_VOLUME_INFORMATION";
        break;
    case 0x0b:
        name = L"IRP_MJ_SET_VOLUME_INFORMATION";
        break;
    case 0x0c:
        name = L"IRP_MJ_DIRECTORY_CONTROL";
        break;
    case 0x0d:
        name = L"IRP_MJ_FILE_SYSTEM_CONTROL";
        break;
    case 0x0e:
        name = L"IRP_MJ_DEVICE_CONTROL";
        break;
    case 0x0f:
        name = L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
        break;
    case 0x10:
        name = L"IRP_MJ_SHUTDOWN";
        break;
    case 0x11:
        name = L"IRP_MJ_LOCK_CONTROL";
        break;
    case 0x12:
        name = L"IRP_MJ_CLEANUP";
        break;
    case 0x13:
        name = L"IRP_MJ_CREATE_MAILSLOT";
        break;
    case 0x14:
        name = L"IRP_MJ_QUERY_SECURITY";
        break;
    case 0x15:
        name = L"IRP_MJ_SET_SECURITY";
        break;
    case 0x16:
        name = L"IRP_MJ_POWER";
        break;
    case 0x17:
        name = L"IRP_MJ_SYSTEM_CONTROL";
        break;
    case 0x18:
        name = L"IRP_MJ_DEVICE_CHANGE";
        break;
    case 0x19:
        name = L"IRP_MJ_QUERY_QUOTA";
        break;
    case 0x1a:
        name = L"IRP_MJ_SET_QUOTA";
        break;
    case 0x1b:
        name = L"IRP_MJ_PNP";
        break;
    case 0x80:
        name = L"IRP_MJ_OPERATION_END";
        break;
    default:
        {
            std::wstringstream stream;
            stream << L"IRP_MJ_0x" << std::hex << majorFunction;
            name = stream.str();
        }
        break;
    }

    return name;
}

static void FillMinifilterRecordBase(
    KernelCallbackRecord* record,
    const CallbackRoot& root,
    uint64_t frameAddress,
    uint32_t frameId,
    uint64_t filterAddress,
    const std::wstring& filterName,
    const std::wstring& altitude,
    uint32_t filterFlags,
    uint64_t driverObject)
{
    do
    {
        if (record == nullptr)
        {
            break;
        }

        record->Kind = L"minifilter";
        record->Target = filterName.empty() ? L"<unnamed>" : filterName;
        record->FilterName = record->Target;
        record->Altitude = altitude;
        record->RootAddress = root.Address;
        record->RootSource = root.Source;
        record->Filter = filterAddress;
        record->Frame = frameAddress;
        record->FrameId = frameId;
        record->FilterFlags = filterFlags;
        record->DriverObject = driverObject;
    } while (false);
}

static bool EmitMinifilterRoutineRecord(
    CallbackScanContext& context,
    const CallbackRoot& root,
    uint64_t frameAddress,
    uint32_t frameId,
    uint64_t filterAddress,
    const std::wstring& filterName,
    const std::wstring& altitude,
    uint32_t filterFlags,
    uint64_t driverObject,
    const std::wstring& callbackName,
    const TypeFieldInfo& field,
    uint64_t function,
    KernelCallbackScanResult* result)
{
    bool emitted = false;

    do
    {
        if (result == nullptr || function == 0 || !context.IsKernelPointer(function))
        {
            break;
        }

        uint64_t fieldAddress = 0;
        if (!context.TryAdd(filterAddress, field.Offset, &fieldAddress))
        {
            break;
        }

        KernelCallbackRecord record = {};
        FillMinifilterRecordBase(
            &record,
            root,
            frameAddress,
            frameId,
            filterAddress,
            filterName,
            altitude,
            filterFlags,
            driverObject);
        record.CallbackName = callbackName;
        record.Entry = fieldAddress;
        record.Function = function;
        context.AnnotateAddress(record.Function, &record.FunctionModule, &record.FunctionSymbol);
        result->Records.push_back(record);
        emitted = true;
    } while (false);

    return emitted;
}

static bool TryReadFieldAsU32(
    CallbackScanContext& context,
    uint64_t base,
    const std::wstring& typeName,
    const std::vector<std::wstring>& fieldNames,
    uint32_t* value)
{
    bool ok = false;
    uint64_t raw = 0;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        *value = 0;
        if (!context.ReadFieldU64(base, typeName, fieldNames, &raw, nullptr, nullptr))
        {
            break;
        }

        *value = static_cast<uint32_t>(raw);
        ok = true;
    } while (false);

    return ok;
}

static uint32_t ReadFieldAsU32(
    CallbackScanContext& context,
    uint64_t base,
    const std::wstring& typeName,
    const std::vector<std::wstring>& fieldNames)
{
    uint32_t value = 0;
    TryReadFieldAsU32(context, base, typeName, fieldNames, &value);

    return value;
}

static bool ScanMinifilterOperationArray(
    CallbackScanContext& context,
    const CallbackRoot& root,
    const MinifilterLayout& layout,
    uint64_t frameAddress,
    uint32_t frameId,
    uint64_t filterAddress,
    const std::wstring& filterName,
    const std::wstring& altitude,
    uint32_t filterFlags,
    uint64_t driverObject,
    uint64_t operationsAddress,
    KernelCallbackScanResult* result,
    uint32_t* emittedCount)
{
    bool ok = false;

    do
    {
        if (emittedCount == nullptr)
        {
            break;
        }

        *emittedCount = 0;
        if (result == nullptr || operationsAddress == 0 || !context.IsKernelPointer(operationsAddress))
        {
            ok = true;
            break;
        }

        for (uint32_t index = 0; index < 256; ++index)
        {
            uint64_t entryAddress = 0;
            if (!context.TryAdd(operationsAddress, static_cast<uint64_t>(index) * layout.OperationSize, &entryAddress))
            {
                break;
            }

            uint32_t majorFunction = 0;
            if (!TryReadFieldAsU32(
                    context,
                    entryAddress,
                    layout.OperationType,
                    {L"MajorFunction"},
                    &majorFunction))
            {
                break;
            }

            if (majorFunction == 0x80)
            {
                break;
            }

            uint64_t preOperation = 0;
            uint64_t postOperation = 0;
            uint64_t flags = 0;
            context.ReadFieldU64(entryAddress, layout.OperationType, {L"PreOperation"}, &preOperation, nullptr, nullptr);
            context.ReadFieldU64(entryAddress, layout.OperationType, {L"PostOperation"}, &postOperation, nullptr, nullptr);
            context.ReadFieldU64(entryAddress, layout.OperationType, {L"Flags"}, &flags, nullptr, nullptr);

            bool preValid = preOperation != 0 && context.IsKernelPointer(preOperation);
            bool postValid = postOperation != 0 && context.IsKernelPointer(postOperation);
            if (!preValid)
            {
                preOperation = 0;
            }

            if (!postValid)
            {
                postOperation = 0;
            }

            if (!preValid && !postValid)
            {
                if (majorFunction > 0x1b)
                {
                    break;
                }

                continue;
            }

            KernelCallbackRecord record = {};
            FillMinifilterRecordBase(
                &record,
                root,
                frameAddress,
                frameId,
                filterAddress,
                filterName,
                altitude,
                filterFlags,
                driverObject);
            record.CallbackName = MiniMajorFunctionName(majorFunction);
            record.Slot = index;
            record.Entry = entryAddress;
            record.MajorFunction = majorFunction;
            record.CallbackFlags = static_cast<uint32_t>(flags);
            record.Function = preOperation;
            record.PostFunction = postOperation;
            AddOffset(context, entryAddress, layout.OperationPre.Offset, &record.FunctionSlot, nullptr);
            AddOffset(context, entryAddress, layout.OperationPost.Offset, &record.PostFunctionSlot, nullptr);
            context.AnnotateAddress(record.Function, &record.FunctionModule, &record.FunctionSymbol);
            context.AnnotateAddress(record.PostFunction, &record.PostFunctionModule, &record.PostFunctionSymbol);
            result->Records.push_back(record);
            ++(*emittedCount);
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ScanMinifilterGlobalsRoot(
    CallbackScanContext& context,
    const CallbackRoot& root,
    const MinifilterLayout& layout,
    KernelCallbackScanResult* result,
    uint32_t* emittedCount,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr || emittedCount == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid minifilter scan output";
            }
            break;
        }

        *emittedCount = 0;
        uint64_t frameListAddress = 0;
        uint64_t frameListHeadAddress = 0;
        if (!AddOffset(context, root.Address, layout.GlobalsFrameList.Offset, &frameListAddress, error) ||
            !AddOffset(context, frameListAddress, layout.ResourceListEntry.Offset, &frameListHeadAddress, error))
        {
            break;
        }

        ListEntryValue frameHead = {};
        if (!context.ReadListEntry(frameListHeadAddress, &frameHead, error))
        {
            break;
        }

        if (frameHead.Flink == 0 || frameHead.Blink == 0)
        {
            if (error != nullptr)
            {
                *error = L"Minifilter frame list head is null";
            }
            break;
        }

        if (frameHead.Flink == frameListHeadAddress && frameHead.Blink == frameListHeadAddress)
        {
            if (error != nullptr)
            {
                *error = L"Minifilter frame list is empty";
            }
            break;
        }

        if (!context.IsKernelPointer(frameHead.Flink) || !context.IsKernelPointer(frameHead.Blink))
        {
            if (error != nullptr)
            {
                *error = L"Minifilter frame list head does not contain kernel links";
            }
            break;
        }

        bool exactFltGlobals = SourceMatchesSymbolName(root.Source, L"FltGlobals");
        uint64_t frameLink = frameHead.Flink;
        for (uint32_t frameIndex = 0; frameIndex < 32 && frameLink != 0 && frameLink != frameListHeadAddress; ++frameIndex)
        {
            if (!context.IsKernelPointer(frameLink))
            {
                break;
            }

            ListEntryValue frameLinks = {};
            if (!context.ReadListEntry(frameLink, &frameLinks, nullptr))
            {
                break;
            }

            uint64_t frameAddress = 0;
            if (!context.TrySubtract(frameLink, layout.FrameLinks.Offset, &frameAddress))
            {
                break;
            }

            uint32_t frameId = ReadFieldAsU32(context, frameAddress, layout.FrameType, {L"FrameID", L"FrameId"});
            uint64_t registeredFiltersAddress = 0;
            uint64_t filterListHeadAddress = 0;
            if (!AddOffset(context, frameAddress, layout.FrameRegisteredFilters.Offset, &registeredFiltersAddress, nullptr) ||
                !AddOffset(context, registeredFiltersAddress, layout.ResourceListEntry.Offset, &filterListHeadAddress, nullptr))
            {
                frameLink = frameLinks.Flink;
                continue;
            }

            ListEntryValue filterHead = {};
            if (!context.ReadListEntry(filterListHeadAddress, &filterHead, nullptr))
            {
                frameLink = frameLinks.Flink;
                continue;
            }

            uint64_t filterLink = filterHead.Flink;
            for (uint32_t filterIndex = 0; filterIndex < 512 && filterLink != 0 && filterLink != filterListHeadAddress; ++filterIndex)
            {
                if (!context.IsKernelPointer(filterLink))
                {
                    break;
                }

                ListEntryValue filterLinks = {};
                if (!context.ReadListEntry(filterLink, &filterLinks, nullptr))
                {
                    break;
                }

                uint64_t primaryLinkOffset = static_cast<uint64_t>(layout.FilterBase.Offset) + layout.ObjectPrimaryLink.Offset;
                uint64_t filterAddress = 0;
                if (!context.TrySubtract(filterLink, primaryLinkOffset, &filterAddress) ||
                    !context.IsKernelPointer(filterAddress))
                {
                    filterLink = filterLinks.Flink;
                    continue;
                }

                std::wstring filterName;
                std::wstring altitude;
                context.ReadFieldUnicodeString(filterAddress, layout.FilterType, {L"Name"}, &filterName, nullptr, nullptr);
                context.ReadFieldUnicodeString(filterAddress, layout.FilterType, {L"DefaultAltitude", L"Altitude"}, &altitude, nullptr, nullptr);

                uint32_t filterFlags = ReadFieldAsU32(context, filterAddress, layout.FilterType, {L"Flags"});
                uint64_t driverObject = 0;
                uint64_t operations = 0;
                context.ReadFieldU64(filterAddress, layout.FilterType, {L"DriverObject"}, &driverObject, nullptr, nullptr);
                context.ReadFieldU64(filterAddress, layout.FilterType, {L"Operations"}, &operations, nullptr, nullptr);

                uint32_t beforeFilterCount = *emittedCount;
                const std::wstring routineNames[] =
                {
                    L"FilterUnload",
                    L"InstanceSetup",
                    L"InstanceQueryTeardown",
                    L"InstanceTeardownStart",
                    L"InstanceTeardownComplete",
                    L"PreVolumeMount",
                    L"PostVolumeMount",
                    L"GenerateFileName",
                    L"NormalizeNameComponent",
                    L"NormalizeNameComponentEx",
                    L"NormalizeContextCleanup",
                    L"KtmNotification",
                    L"SectionNotification"
                };

                for (const std::wstring& routineName : routineNames)
                {
                    TypeFieldInfo routineField = {};
                    uint64_t routineAddress = 0;
                    if (!context.ReadFieldU64(filterAddress, layout.FilterType, {routineName}, &routineAddress, &routineField, nullptr))
                    {
                        continue;
                    }

                    if (EmitMinifilterRoutineRecord(
                            context,
                            root,
                            frameAddress,
                            frameId,
                            filterAddress,
                            filterName,
                            altitude,
                            filterFlags,
                            driverObject,
                            routineName,
                            routineField,
                            routineAddress,
                            result))
                    {
                        ++(*emittedCount);
                    }
                }

                uint32_t operationEmitted = 0;
                ScanMinifilterOperationArray(
                    context,
                    root,
                    layout,
                    frameAddress,
                    frameId,
                    filterAddress,
                    filterName,
                    altitude,
                    filterFlags,
                    driverObject,
                    operations,
                    result,
                    &operationEmitted);
                *emittedCount += operationEmitted;

                if (*emittedCount == beforeFilterCount && exactFltGlobals)
                {
                    KernelCallbackRecord record = {};
                    FillMinifilterRecordBase(
                        &record,
                        root,
                        frameAddress,
                        frameId,
                        filterAddress,
                        filterName,
                        altitude,
                        filterFlags,
                        driverObject);
                    record.CallbackName = L"registered";
                    record.Notes = L"no callback routines found";
                    result->Records.push_back(record);
                    ++(*emittedCount);
                }

                filterLink = filterLinks.Flink;
            }

            frameLink = frameLinks.Flink;
        }

        if (*emittedCount == 0)
        {
            if (error != nullptr)
            {
                *error = L"No minifilter records were found";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

KernelCallbackScanner::KernelCallbackScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool KernelCallbackScanner::Scan(const std::wstring& scope, KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid callback scan output";
            }
            break;
        }

        result->Records.clear();
        result->Warnings.clear();
        result->Incomplete = false;
        result->PoisonedEntryCount = 0;

        std::wstring normalized = ToLowerLocal(scope.empty() ? L"all" : scope);
        bool scanAll = normalized == L"all";
        bool scanOb = scanAll || normalized == L"object";
        bool scanRegistry = scanAll || normalized == L"registry";
        bool scanProcess = scanAll || normalized == L"process";
        bool scanThread = scanAll || normalized == L"thread";
        bool scanImageLoad = scanAll || normalized == L"imageload";
        bool scanMini = scanAll || normalized == L"minifilter";

        if (!scanOb && !scanRegistry && !scanProcess && !scanThread && !scanImageLoad && !scanMini)
        {
            if (error != nullptr)
            {
                *error = L"usage: !callbacks [all|object|registry|process|thread|imageload|minifilter]";
            }
            break;
        }

        bool anyScannerSucceeded = false;
        uint32_t surfacesRequested = 0;
        uint32_t surfacesFailed = 0;
        std::wstring localError;

        auto runSurface = [&](const wchar_t* name, bool (KernelCallbackScanner::*scanner)(KernelCallbackScanResult*, std::wstring*))
        {
            ++surfacesRequested;
            localError.clear();
            if ((this->*scanner)(result, &localError))
            {
                anyScannerSucceeded = true;
            }
            else
            {
                ++surfacesFailed;
                // A failed surface must never look like clean empty coverage when
                // another surface still returned records.
                result->Incomplete = true;
                result->Warnings.push_back(std::wstring(name) + L": " + localError);
            }
        };

        if (scanOb)
        {
            runSurface(L"ob", &KernelCallbackScanner::ScanObjectCallbacks);
        }
        if (scanRegistry)
        {
            runSurface(L"registry", &KernelCallbackScanner::ScanRegistryCallbacks);
        }
        if (scanProcess)
        {
            runSurface(L"process", &KernelCallbackScanner::ScanProcessCallbacks);
        }
        if (scanThread)
        {
            runSurface(L"thread", &KernelCallbackScanner::ScanThreadCallbacks);
        }
        if (scanImageLoad)
        {
            runSurface(L"imageload", &KernelCallbackScanner::ScanImageLoadCallbacks);
        }
        if (scanMini)
        {
            runSurface(L"minifilter", &KernelCallbackScanner::ScanMinifilterCallbacks);
        }

        if (!anyScannerSucceeded)
        {
            result->Incomplete = true;
            if (error != nullptr)
            {
                *error = JoinWarnings(result->Warnings);
            }
            break;
        }

        if (surfacesFailed != 0)
        {
            result->Warnings.push_back(
                L"callback coverage incomplete: " + std::to_wstring(surfacesFailed) +
                L" of " + std::to_wstring(surfacesRequested) +
                L" requested surface(s) failed; remaining records are partial");
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring CallbacksJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildCallbacksJson(const KernelCallbackScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.callbacks.v1\",\"count\":";
    out += std::to_wstring(result.Records.size());
    out += L",\"incomplete\":";
    out += result.Incomplete ? L"true" : L"false";
    out += L",\"poisonedEntryCount\":";
    out += std::to_wstring(result.PoisonedEntryCount);
    out += L",\"coverageComplete\":";
    out += (!result.Incomplete) ? L"true" : L"false";
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const KernelCallbackRecord& record = result.Records[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"kind\":" + mcpjson::Quote(record.Kind);
        out += L",\"target\":" + mcpjson::Quote(record.Target);
        if (!record.Altitude.empty())
        {
            out += L",\"altitude\":" + mcpjson::Quote(record.Altitude);
        }
        if (!record.CallbackName.empty())
        {
            out += L",\"callbackName\":" + mcpjson::Quote(record.CallbackName);
        }
        if (!record.FilterName.empty())
        {
            out += L",\"filterName\":" + mcpjson::Quote(record.FilterName);
        }
        out += L",\"function\":" + mcpjson::Quote(CallbacksJsonHex(record.Function));
        out += L",\"functionModule\":" + mcpjson::Quote(record.FunctionModule);
        out += L",\"functionSymbol\":" + mcpjson::Quote(record.FunctionSymbol);
        if (record.FunctionSlot != 0)
        {
            out += L",\"functionSlot\":" + mcpjson::Quote(CallbacksJsonHex(record.FunctionSlot));
        }
        if (record.PostFunction != 0)
        {
            out += L",\"postFunction\":" + mcpjson::Quote(CallbacksJsonHex(record.PostFunction));
            out += L",\"postFunctionModule\":" + mcpjson::Quote(record.PostFunctionModule);
            out += L",\"postFunctionSymbol\":" + mcpjson::Quote(record.PostFunctionSymbol);
        }
        if (record.PostFunctionSlot != 0)
        {
            out += L",\"postFunctionSlot\":" + mcpjson::Quote(CallbacksJsonHex(record.PostFunctionSlot));
        }
        if (record.Poisoned)
        {
            out += L",\"poisoned\":true";
        }
        if (record.SessionDisabled)
        {
            out += L",\"sessionDisabled\":true";
        }
        if (record.Context != 0)
        {
            out += L",\"context\":" + mcpjson::Quote(CallbacksJsonHex(record.Context));
            out += L",\"contextModule\":" + mcpjson::Quote(record.ContextModule);
            out += L",\"contextSymbol\":" + mcpjson::Quote(record.ContextSymbol);
        }
        if (record.DriverObject != 0)
        {
            out += L",\"driverObject\":" + mcpjson::Quote(CallbacksJsonHex(record.DriverObject));
        }
        if (record.ObjectType != 0)
        {
            out += L",\"objectType\":" + mcpjson::Quote(CallbacksJsonHex(record.ObjectType));
            out += L",\"objectTypeSource\":" + mcpjson::Quote(record.ObjectTypeSource);
        }
        if (!record.RootSource.empty())
        {
            out += L",\"rootSource\":" + mcpjson::Quote(record.RootSource);
        }
        if (record.RootAddress != 0)
        {
            out += L",\"rootAddress\":" + mcpjson::Quote(CallbacksJsonHex(record.RootAddress));
        }
        if (record.Filter != 0)
        {
            out += L",\"filter\":" + mcpjson::Quote(CallbacksJsonHex(record.Filter));
        }
        if (record.MajorFunction != 0xffffffffu)
        {
            out += L",\"majorFunction\":" + std::to_wstring(record.MajorFunction);
        }
        if (record.Operations != 0)
        {
            out += L",\"operations\":" + std::to_wstring(record.Operations);
        }
        if (!record.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        }
        // Owning pre and/or post lands outside every loaded kernel module:
        // primary Cm/Ob hook signal for triage (pool shellcode, manual map).
        const bool preUnbacked = record.Function != 0 && record.FunctionModule.empty();
        const bool postUnbacked = record.PostFunction != 0 && record.PostFunctionModule.empty();
        const bool unbacked = preUnbacked || postUnbacked;
        out += L",\"functionUnbacked\":";
        out += unbacked ? L"true" : L"false";
        out += L",\"preFunctionUnbacked\":";
        out += preUnbacked ? L"true" : L"false";
        out += L",\"postFunctionUnbacked\":";
        out += postUnbacked ? L"true" : L"false";
        out += L"}";
    }

    out += L"],\"warnings\":[";
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

bool KernelCallbackScanner::ScanProcessCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid process callback scan output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        ExCallbackBlockLayout layout = {};
        if (!BuildExCallbackBlockLayout(context, &layout, error))
        {
            break;
        }

        std::vector<CallbackRoot> roots;
        std::vector<std::wstring> warnings;
        AddEnumeratedCallbackRoots(
            context,
            {
                L"nt!PspCreateProcessNotifyRoutine",
                L"nt!*CreateProcess*Notify*Routine*",
                L"nt!Psp*Process*Notify*Routine*"
            },
            128,
            &roots,
            &warnings);
        AddResolvedCallbackRoot(context, L"nt!PspCreateProcessNotifyRoutine", &roots, &warnings);

        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        bool any = false;
        for (const CallbackRoot& root : roots)
        {
            uint32_t recordCount = 0;
            std::wstring localError;
            bool allowEmpty = SourceMatchesSymbolName(root.Source, L"PspCreateProcessNotifyRoutine");
            if (ScanExCallbackTableRoot(
                    context,
                    root,
                    layout,
                    L"process",
                    L"create-process",
                    L"x64 fallback process callback block layout",
                    allowEmpty,
                    result,
                    &recordCount,
                    &localError))
            {
                any = true;
                break;
            }

            warnings.push_back(root.Source + L": " + localError);
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanThreadCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid thread callback scan output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        ExCallbackBlockLayout layout = {};
        if (!BuildExCallbackBlockLayout(context, &layout, error))
        {
            break;
        }

        std::vector<CallbackRoot> roots;
        std::vector<std::wstring> warnings;
        AddEnumeratedCallbackRoots(
            context,
            {
                L"nt!PspCreateThreadNotifyRoutine",
                L"nt!*CreateThread*Notify*Routine*",
                L"nt!Psp*Thread*Notify*Routine*"
            },
            128,
            &roots,
            &warnings);
        AddResolvedCallbackRoot(context, L"nt!PspCreateThreadNotifyRoutine", &roots, &warnings);

        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        bool any = false;
        for (const CallbackRoot& root : roots)
        {
            uint32_t recordCount = 0;
            std::wstring localError;
            bool allowEmpty = SourceMatchesSymbolName(root.Source, L"PspCreateThreadNotifyRoutine");
            if (ScanExCallbackTableRoot(
                    context,
                    root,
                    layout,
                    L"thread",
                    L"create-thread",
                    L"x64 fallback thread callback block layout",
                    allowEmpty,
                    result,
                    &recordCount,
                    &localError))
            {
                any = true;
                break;
            }

            warnings.push_back(root.Source + L": " + localError);
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanImageLoadCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid image-load callback scan output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        ExCallbackBlockLayout layout = {};
        if (!BuildExCallbackBlockLayout(context, &layout, error))
        {
            break;
        }

        std::vector<CallbackRoot> roots;
        std::vector<std::wstring> warnings;
        AddEnumeratedCallbackRoots(
            context,
            {
                L"nt!PspLoadImageNotifyRoutine",
                L"nt!*LoadImage*Notify*Routine*",
                L"nt!Psp*Image*Notify*Routine*"
            },
            128,
            &roots,
            &warnings);
        AddResolvedCallbackRoot(context, L"nt!PspLoadImageNotifyRoutine", &roots, &warnings);

        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        bool any = false;
        for (const CallbackRoot& root : roots)
        {
            uint32_t recordCount = 0;
            std::wstring localError;
            bool allowEmpty = SourceMatchesSymbolName(root.Source, L"PspLoadImageNotifyRoutine");
            if (ScanExCallbackTableRoot(
                    context,
                    root,
                    layout,
                    L"imageload",
                    L"load-image",
                    L"x64 fallback image-load callback block layout",
                    allowEmpty,
                    result,
                    &recordCount,
                    &localError))
            {
                any = true;
                break;
            }

            warnings.push_back(root.Source + L": " + localError);
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanRegistryCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid registry callback scan output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        std::vector<RegistryCallbackLayout> layouts;
        if (!BuildRegistryCallbackLayouts(context, &layouts, error))
        {
            break;
        }

        std::vector<CallbackRoot> roots;
        std::vector<std::wstring> warnings;
        AddEnumeratedCallbackRoots(
            context,
            {
                L"nt!CmpCallbackListHead",
                L"nt!Cmp*Callback*List*",
                L"nt!*Registry*Callback*List*",
                L"nt!*CallbackListHead*"
            },
            128,
            &roots,
            &warnings);
        AddResolvedCallbackRoot(context, L"nt!CmpCallbackListHead", &roots, &warnings);

        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        bool any = false;
        for (const CallbackRoot& root : roots)
        {
            for (const RegistryCallbackLayout& layout : layouts)
            {
                uint32_t recordCount = 0;
                std::wstring localError;
                bool allowEmpty = SourceMatchesSymbolName(root.Source, L"CmpCallbackListHead");
                if (ScanRegistryCallbackListRoot(
                        context,
                        root,
                        layout,
                        allowEmpty,
                        result,
                        &recordCount,
                        &localError))
                {
                    any = true;
                    break;
                }

                warnings.push_back(root.Source + L" " + layout.BlockType + L": " + localError);
            }

            if (any)
            {
                break;
            }
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanMinifilterCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid minifilter callback scan output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        MinifilterLayout layout = {};
        if (!BuildMinifilterLayout(context, &layout, error))
        {
            break;
        }

        std::vector<CallbackRoot> roots;
        std::vector<std::wstring> warnings;
        AddEnumeratedCallbackRoots(
            context,
            {
                L"fltmgr!FltGlobals",
                L"fltmgr!*Globals*"
            },
            64,
            &roots,
            &warnings);
        AddResolvedCallbackRoot(context, L"fltmgr!FltGlobals", &roots, &warnings);

        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        bool any = false;
        for (const CallbackRoot& root : roots)
        {
            uint32_t recordCount = 0;
            std::wstring localError;
            if (ScanMinifilterGlobalsRoot(context, root, layout, result, &recordCount, &localError))
            {
                any = true;
                break;
            }

            warnings.push_back(root.Source + L": " + localError);
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanObjectCallbacks(KernelCallbackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid object callback scan output";
            }
            break;
        }

        std::vector<std::wstring> warnings;
        CallbackScanContext context(device_, symbols_);
        std::vector<ObjectTypeTarget> targets;
        std::wstring discoveryError;
        if (!context.DiscoverObjectTypes(&targets, &discoveryError))
        {
            warnings.push_back(L"type discovery: " + discoveryError);
        }

        struct KnownObjectType
        {
            const wchar_t* Target;
            const wchar_t* SymbolName;
        };

        const KnownObjectType knownTypes[] =
        {
            {L"Process", L"nt!PsProcessType"},
            {L"Thread", L"nt!PsThreadType"},
            {L"Desktop", L"nt!ExDesktopObjectType"}
        };

        for (const KnownObjectType& knownType : knownTypes)
        {
            uint64_t objectTypeAddress = 0;
            std::wstring localError;
            if (!context.ResolveGlobalPointer(knownType.SymbolName, &objectTypeAddress, &localError))
            {
                if (targets.empty())
                {
                    warnings.push_back(std::wstring(knownType.Target) + L": " + localError);
                }
                continue;
            }

            if (!context.IsKernelPointer(objectTypeAddress))
            {
                if (targets.empty())
                {
                    warnings.push_back(std::wstring(knownType.Target) + L": object type pointer is not a kernel pointer");
                }
                continue;
            }

            std::wstring targetName = knownType.Target;
            context.ReadObjectTypeName(objectTypeAddress, &targetName, nullptr);

            ObjectTypeTarget target = {};
            target.Name = targetName.empty() ? knownType.Target : targetName;
            target.Source = knownType.SymbolName;
            target.Address = objectTypeAddress;
            AddObjectTypeTargetIfUnique(&targets, target);
        }

        if (targets.empty())
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        ObjectCallbackLayout objectLayout = {};
        std::wstring preflightError;
        if (!BuildObjectCallbackLayout(context, &objectLayout, &preflightError))
        {
            if (error != nullptr)
            {
                *error = L"object callback layout: " + preflightError;
            }
            break;
        }

        if (!objectLayout.UsedSyntheticItemType && objectLayout.UsedSyntheticFields)
        {
            result->Warnings.push_back(
                L"ob object callback item PDB layout is partial; using fallback offsets for missing fields");
        }

        bool any = false;
        for (const ObjectTypeTarget& target : targets)
        {
            std::wstring localError;
            if (ScanObjectTypeCallbacks(
                    target.Name,
                    target.Address,
                    target.TypeIndex,
                    target.Source,
                    result,
                    &localError))
            {
                any = true;
            }
            else
            {
                warnings.push_back(target.Name + L": " + localError);
            }
        }

        if (!any)
        {
            if (error != nullptr)
            {
                *error = JoinWarnings(warnings);
            }
            break;
        }

        for (const std::wstring& warning : warnings)
        {
            result->Warnings.push_back(L"ob " + warning);
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScanner::ScanObjectTypeCallbacks(
    const std::wstring& target,
    uint64_t objectTypeAddress,
    uint32_t objectTypeIndex,
    const std::wstring& objectTypeSource,
    KernelCallbackScanResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid object callback target output";
            }
            break;
        }

        CallbackScanContext context(device_, symbols_);
        if (!context.IsKernelPointer(objectTypeAddress))
        {
            if (error != nullptr)
            {
                *error = L"Object type pointer is not a kernel pointer";
            }
            break;
        }

        ObjectCallbackLayout layout = {};
        if (!BuildObjectCallbackLayout(context, &layout, error))
        {
            break;
        }

        uint64_t headAddress = 0;
        if (!context.TryAdd(objectTypeAddress, layout.ObjectCallbackList.Offset, &headAddress))
        {
            if (error != nullptr)
            {
                *error = L"Object callback list address overflow";
            }
            break;
        }

        ListEntryValue head = {};
        if (!context.ReadListEntry(headAddress, &head, error))
        {
            break;
        }

        if (head.Flink == 0 || head.Blink == 0)
        {
            if (error != nullptr)
            {
                *error = L"Object callback list head is null";
            }
            break;
        }

        if (head.Flink == headAddress && head.Blink == headAddress)
        {
            ok = true;
            break;
        }

        if (!context.IsKernelPointer(head.Flink) || !context.IsKernelPointer(head.Blink))
        {
            if (error != nullptr)
            {
                *error = L"Object callback list head does not contain kernel links";
            }
            break;
        }

        uint64_t current = head.Flink;
        bool walkIncomplete = false;
        uint32_t poisonedEntries = 0;
        for (uint32_t index = 0; index < 512 && current != 0 && current != headAddress; ++index)
        {
            if (!context.IsKernelPointer(current))
            {
                // Cannot recover Flink from a non-kernel link. Keep prior
                // records and report incomplete coverage instead of failing
                // the whole object-type walk.
                walkIncomplete = true;
                result->Warnings.push_back(
                    L"ob " + target + L": non-kernel list entry at slot " + std::to_wstring(index) +
                    L"; remaining callbacks not walked");
                break;
            }

            ListEntryValue entryLinks = {};
            std::wstring readError;
            if (!context.ReadListEntry(current, &entryLinks, &readError))
            {
                walkIncomplete = true;
                result->Warnings.push_back(
                    L"ob " + target + L": list entry read failed at slot " + std::to_wstring(index) +
                    L": " + readError + L"; remaining callbacks not walked");
                break;
            }

            uint64_t itemAddress = 0;
            if (!context.TrySubtract(current, layout.ItemList.Offset, &itemAddress))
            {
                walkIncomplete = true;
                ++poisonedEntries;
                result->Warnings.push_back(
                    L"ob " + target + L": item address underflow at slot " + std::to_wstring(index) +
                    L" (continuing walk)");
                current = entryLinks.Flink;
                continue;
            }

            uint64_t preOperation = 0;
            uint64_t postOperation = 0;
            uint64_t callbackEntry = 0;
            uint64_t operations = 0;
            uint64_t registrationContext = 0;

            ReadFieldValueByDescriptor(context, itemAddress, layout.PreOperation, &preOperation, nullptr);
            ReadFieldValueByDescriptor(context, itemAddress, layout.PostOperation, &postOperation, nullptr);
            ReadFieldValueByDescriptor(context, itemAddress, layout.CallbackEntry, &callbackEntry, nullptr);
            ReadFieldValueByDescriptor(context, itemAddress, layout.Operations, &operations, nullptr);

            if (preOperation != 0 || postOperation != 0)
            {
                std::wstring validationError;
                const bool fieldsValid = ValidateObjectCallbackItemFields(
                    context,
                    callbackEntry,
                    preOperation,
                    postOperation,
                    operations,
                    &validationError);

                std::wstring altitude;
                if (fieldsValid)
                {
                    ReadObjectCallbackRegistrationMetadata(
                        context,
                        callbackEntry,
                        &registrationContext,
                        &altitude);
                }

                KernelCallbackRecord record = {};
                record.Kind = L"ob";
                record.Target = target;
                record.Slot = index;
                record.ObjectType = objectTypeAddress;
                record.ObjectTypeIndex = objectTypeIndex;
                record.ObjectTypeSource = objectTypeSource;
                record.ListEntry = current;
                record.Entry = itemAddress;
                record.CallbackEntry = callbackEntry;
                record.Function = preOperation;
                record.PostFunction = postOperation;
                record.Context = registrationContext;
                record.Operations = static_cast<uint32_t>(operations);
                record.Altitude = altitude;
                context.TryAdd(itemAddress, layout.PreOperation.Offset, &record.FunctionSlot);
                context.TryAdd(itemAddress, layout.PostOperation.Offset, &record.PostFunctionSlot);
                record.Poisoned = !fieldsValid;
                if (!layout.UsedSyntheticItemType && layout.UsedSyntheticFields)
                {
                    record.Notes = L"partial fallback object callback item fields";
                }

                if (!fieldsValid)
                {
                    // Poison / decoy entries used to abort the walk and hide
                    // every later real callback. Keep the entry as evidence
                    // and continue so subsequent hooks remain visible.
                    walkIncomplete = true;
                    ++poisonedEntries;
                    std::wstring poisonNote =
                        L"poisoned/invalid object callback item: " + validationError;
                    if (record.Notes.empty())
                    {
                        record.Notes = poisonNote;
                    }
                    else
                    {
                        record.Notes += L"; ";
                        record.Notes += poisonNote;
                    }
                }

                context.AnnotateAddress(record.Function, &record.FunctionModule, &record.FunctionSymbol);
                context.AnnotateAddress(record.PostFunction, &record.PostFunctionModule, &record.PostFunctionSymbol);
                if (fieldsValid && context.IsKernelImagePointer(record.Context))
                {
                    context.AnnotateAddress(record.Context, &record.ContextModule, &record.ContextSymbol);
                }
                result->Records.push_back(record);
            }

            current = entryLinks.Flink;
        }

        if (current != 0 && current != headAddress)
        {
            // Hit the 512-entry cap without returning to the head.
            walkIncomplete = true;
            result->Warnings.push_back(
                L"ob " + target + L": callback list walk hit entry cap without returning to head");
        }

        if (walkIncomplete)
        {
            result->Incomplete = true;
            if (poisonedEntries != 0)
            {
                result->PoisonedEntryCount += poisonedEntries;
                result->Warnings.push_back(
                    L"ob " + target + L": walked past " + std::to_wstring(poisonedEntries) +
                    L" poisoned/invalid item(s); list coverage may be partial");
            }
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::mutex g_CallbackBackupLock;

    bool CallbackPointerOwnedByModule(
        const std::wstring& pointerModule,
        uint64_t pointer,
        const std::wstring& moduleFilter);

    struct CallbackPointerBackup
    {
        uint64_t Original = 0;
        std::wstring ModuleFilter;
        std::wstring OwnerModule;
    };

    std::map<uint64_t, CallbackPointerBackup> g_CallbackPointerBackups;

    std::wstring CallbackTrimCopy(const std::wstring& value)
    {
        size_t start = 0;
        while (start < value.size() && iswspace(value[start]) != 0)
        {
            ++start;
        }

        size_t end = value.size();
        while (end > start && iswspace(value[end - 1]) != 0)
        {
            --end;
        }

        return value.substr(start, end - start);
    }

    std::wstring CallbackComparableModuleNameLocal(const std::wstring& value, bool removeExtension)
    {
        std::wstring comparable;
        do
        {
            std::wstring text = CallbackTrimCopy(value);
            if (text.empty())
            {
                break;
            }

            if (text.size() >= 2 &&
                ((text.front() == L'"' && text.back() == L'"') ||
                 (text.front() == L'\'' && text.back() == L'\'')))
            {
                text = text.substr(1, text.size() - 2);
            }

            const size_t bang = text.find(L'!');
            if (bang != std::wstring::npos)
            {
                text = text.substr(0, bang);
            }

            const size_t slash = text.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                text = text.substr(slash + 1);
            }

            text = ToLowerLocal(text);
            if (removeExtension)
            {
                const size_t dot = text.find_last_of(L'.');
                if (dot != std::wstring::npos)
                {
                    text = text.substr(0, dot);
                }
            }

            comparable = text;
        } while (false);

        return comparable;
    }

    bool CallbackModuleTextMatchesLocal(const std::wstring& moduleText, const std::wstring& moduleFilter)
    {
        bool matched = false;
        do
        {
            const std::wstring filterBase = CallbackComparableModuleNameLocal(moduleFilter, false);
            if (filterBase.empty())
            {
                matched = true;
                break;
            }

            const std::wstring moduleBase = CallbackComparableModuleNameLocal(moduleText, false);
            if (moduleBase.empty())
            {
                break;
            }

            if (moduleBase == filterBase)
            {
                matched = true;
                break;
            }

            const std::wstring filterStem = CallbackComparableModuleNameLocal(moduleFilter, true);
            const std::wstring moduleStem = CallbackComparableModuleNameLocal(moduleText, true);
            if (!filterStem.empty() && moduleStem == filterStem)
            {
                matched = true;
            }
        } while (false);

        return matched;
    }

    bool CallbackWriteModeEnabled(DeviceClient& device, std::wstring* error)
    {
        bool enabled = false;
        DriverSessionStatus session = {};
        if (!device.QuerySessionStatus(&session, error))
        {
            return false;
        }

        enabled = (session.Flags & KNDBG_SESSION_FLAG_WRITE_ENABLED) != 0;
        if (!enabled && error != nullptr)
        {
            *error = L"write mode is off; run 'write on' before changing kernel callbacks";
        }

        return enabled;
    }

    bool WriteCallbackPointer(
        DeviceClient& device,
        uint64_t address,
        uint64_t value,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (value == 0)
            {
                if (error != nullptr)
                {
                    *error = L"refusing to write NULL into a callback slot (kCFG 0x139)";
                }
                break;
            }

            if (!LeftoverIsKernelCanonical(address) || !LeftoverIsKernelCanonical(value))
            {
                if (error != nullptr)
                {
                    *error = L"refusing non-canonical callback pointer write at " +
                             LeftoverFormatHex(address, 16);
                }
                break;
            }

            std::vector<uint8_t> bytes(sizeof(uint64_t));
            memcpy(bytes.data(), &value, sizeof(uint64_t));
            if (!device.WriteMemory(address, bytes, error))
            {
                break;
            }

            uint64_t readBack = 0;
            if (!LeftoverReadU64(device, address, &readBack, error))
            {
                break;
            }

            if (readBack != value)
            {
                if (error != nullptr)
                {
                    *error = L"write verify failed at " + LeftoverFormatHex(address, 16) +
                             L" expected=" + LeftoverFormatHex(value, 16) +
                             L" read=" + LeftoverFormatHex(readBack, 16);
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool BackupModuleMatches(const std::wstring& stored, const std::wstring& requested)
    {
        bool matched = false;
        do
        {
            if (CallbackTrimCopy(requested).empty())
            {
                matched = true;
                break;
            }

            if (CallbackModuleTextMatchesLocal(stored, requested) ||
                CallbackModuleTextMatchesLocal(requested, stored))
            {
                matched = true;
            }
        } while (false);

        return matched;
    }

    bool RememberCallbackBackup(
        uint64_t slotAddress,
        uint64_t original,
        const std::wstring& moduleFilter,
        const std::wstring& ownerModule)
    {
        bool stored = false;
        do
        {
            if (slotAddress == 0 || original == 0)
            {
                break;
            }

            std::lock_guard<std::mutex> guard(g_CallbackBackupLock);
            if (g_CallbackPointerBackups.find(slotAddress) == g_CallbackPointerBackups.end())
            {
                CallbackPointerBackup backup = {};
                backup.Original = original;
                backup.ModuleFilter = moduleFilter;
                backup.OwnerModule = ownerModule;
                g_CallbackPointerBackups[slotAddress] = backup;
            }
            stored = true;
        } while (false);

        return stored;
    }

    bool LookupCallbackBackupForModule(
        uint64_t slotAddress,
        const std::wstring& moduleFilter,
        uint64_t* original)
    {
        bool found = false;
        do
        {
            if (slotAddress == 0)
            {
                break;
            }

            std::lock_guard<std::mutex> guard(g_CallbackBackupLock);
            auto existing = g_CallbackPointerBackups.find(slotAddress);
            if (existing == g_CallbackPointerBackups.end())
            {
                break;
            }

            if (!BackupModuleMatches(existing->second.ModuleFilter, moduleFilter))
            {
                break;
            }

            if (original != nullptr)
            {
                *original = existing->second.Original;
            }
            found = true;
        } while (false);

        return found;
    }

    bool RecordHasBackupForModule(const KernelCallbackRecord& record, const std::wstring& moduleFilter)
    {
        return LookupCallbackBackupForModule(record.FunctionSlot, moduleFilter, nullptr) ||
            LookupCallbackBackupForModule(record.PostFunctionSlot, moduleFilter, nullptr);
    }

    bool MinifilterNameIsUnnamed(const std::wstring& name)
    {
        const std::wstring lowered = ToLowerLocal(CallbackTrimCopy(name));
        return lowered.empty() || lowered == L"<unnamed>";
    }

    bool RecordOwnedForWrite(const KernelCallbackRecord& record, const std::wstring& moduleFilter)
    {
        bool owned = false;
        do
        {
            if (record.Poisoned)
            {
                break;
            }

            if (record.Kind == L"minifilter")
            {
                if (!MinifilterNameIsUnnamed(record.FilterName))
                {
                    owned = CallbackModuleTextMatchesLocal(record.FilterName, moduleFilter);
                    break;
                }

                owned = CallbackPointerOwnedByModule(record.FunctionModule, record.Function, moduleFilter) ||
                    CallbackPointerOwnedByModule(record.PostFunctionModule, record.PostFunction, moduleFilter);
                break;
            }

            owned = CallbackPointerOwnedByModule(record.FunctionModule, record.Function, moduleFilter) ||
                CallbackPointerOwnedByModule(record.PostFunctionModule, record.PostFunction, moduleFilter);
        } while (false);

        return owned;
    }

    void OverlaySessionDisabledRecords(std::vector<KernelCallbackRecord>* records)
    {
        do
        {
            if (records == nullptr)
            {
                break;
            }

            for (KernelCallbackRecord& record : *records)
            {
                std::wstring originalOwner;
                {
                    std::lock_guard<std::mutex> guard(g_CallbackBackupLock);
                    auto pre = g_CallbackPointerBackups.find(record.FunctionSlot);
                    if (pre != g_CallbackPointerBackups.end())
                    {
                        originalOwner = pre->second.OwnerModule;
                    }
                    else
                    {
                        auto post = g_CallbackPointerBackups.find(record.PostFunctionSlot);
                        if (post != g_CallbackPointerBackups.end())
                        {
                            originalOwner = post->second.OwnerModule;
                        }
                    }
                }

                if (originalOwner.empty() &&
                    !RecordHasBackupForModule(record, std::wstring()))
                {
                    continue;
                }

                record.SessionDisabled = true;
                std::wstring note = L"disabled this session (function pointer replaced with CFG nop thunk)";
                if (!originalOwner.empty())
                {
                    note += L"; original module=";
                    note += originalOwner;
                }
                if (record.Notes.empty())
                {
                    record.Notes = note;
                }
                else if (record.Notes.find(L"disabled this session") == std::wstring::npos)
                {
                    record.Notes += L"; ";
                    record.Notes += note;
                }
            }
        } while (false);
    }

    bool CallbackPointerOwnedByModule(
        const std::wstring& pointerModule,
        uint64_t pointer,
        const std::wstring& moduleFilter)
    {
        bool owned = false;
        do
        {
            if (pointer == 0)
            {
                break;
            }

            if (CallbackModuleTextMatchesLocal(pointerModule, moduleFilter))
            {
                owned = true;
            }
        } while (false);

        return owned;
    }

    void AppendCallbackSetChange(
        KernelCallbackSetResult* result,
        const KernelCallbackPointerChange& change)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            ++result->Attempted;
            if (change.Changed)
            {
                ++result->Changed;
            }
            else if (change.Skipped)
            {
                ++result->Skipped;
            }

            result->Changes.push_back(change);
        } while (false);
    }

    bool PatchOwnedCallbackPointer(
        DeviceClient& device,
        const KernelCallbackRecord& record,
        const std::wstring& which,
        uint64_t slotAddress,
        uint64_t scannedValue,
        const std::wstring& pointerModule,
        const std::wstring& moduleFilter,
        KernelCallbackSetAction action,
        uint64_t returnZeroThunk,
        KernelCallbackSetResult* result)
    {
        bool ok = false;
        do
        {
            if (result == nullptr)
            {
                break;
            }

            uint64_t backupOriginal = 0;
            const bool haveBackup = LookupCallbackBackupForModule(
                slotAddress,
                moduleFilter,
                &backupOriginal);
            const bool currentlyOwned = CallbackPointerOwnedByModule(
                pointerModule,
                scannedValue,
                moduleFilter);
            if (!currentlyOwned && !haveBackup)
            {
                ok = true;
                break;
            }

            KernelCallbackPointerChange change = {};
            change.Kind = record.Kind;
            change.Target = record.Target;
            change.Which = which;
            change.Module = pointerModule;
            change.SlotAddress = slotAddress;
            change.Before = scannedValue;

            if (record.Poisoned)
            {
                change.Skipped = true;
                change.Notes = L"poisoned object callback item; refusing write";
                AppendCallbackSetChange(result, change);
                result->Failures.push_back(record.Kind + L" " + which + L": poisoned item");
                ++result->Failed;
                ok = true;
                break;
            }

            if (slotAddress == 0 || !LeftoverIsKernelCanonical(slotAddress))
            {
                change.Skipped = true;
                change.Notes = L"callback pointer slot is missing";
                AppendCallbackSetChange(result, change);
                result->Failures.push_back(record.Kind + L" " + which + L": missing slot");
                ++result->Failed;
                ok = true;
                break;
            }

            uint64_t live = 0;
            std::wstring readError;
            if (!LeftoverReadU64(device, slotAddress, &live, &readError))
            {
                change.Skipped = true;
                change.Notes = L"failed to read live pointer: " + readError;
                AppendCallbackSetChange(result, change);
                result->Failures.push_back(record.Kind + L" " + which + L": " + readError);
                ++result->Failed;
                ok = true;
                break;
            }

            change.Before = live;
            if (live == 0)
            {
                change.Skipped = true;
                change.Notes = L"empty slot; never write NULL or fill a vacant callback";
                AppendCallbackSetChange(result, change);
                ok = true;
                break;
            }

            const bool liveIsNop = (returnZeroThunk != 0 && live == returnZeroThunk) ||
                IsMinifilterNopThunkAddress(live);

            if (action == KernelCallbackSetAction::Disable)
            {
                if (liveIsNop)
                {
                    change.After = live;
                    change.Skipped = true;
                    change.Notes = haveBackup
                        ? L"already replaced with return-0 thunk"
                        : L"already a CFG nop thunk; no original pointer to save";
                    AppendCallbackSetChange(result, change);
                    ok = true;
                    break;
                }

                if (!currentlyOwned)
                {
                    if (haveBackup)
                    {
                        change.Skipped = true;
                        change.Notes = L"session backup exists but live pointer is not this module or a nop thunk";
                        AppendCallbackSetChange(result, change);
                        result->Failures.push_back(record.Kind + L" " + which + L": unexpected live pointer");
                        ++result->Failed;
                    }
                    ok = true;
                    break;
                }

                if (live != scannedValue)
                {
                    change.Skipped = true;
                    change.Notes = L"live pointer changed since scan; refusing stale write";
                    AppendCallbackSetChange(result, change);
                    result->Failures.push_back(record.Kind + L" " + which + L": stale slot");
                    ++result->Failed;
                    ok = true;
                    break;
                }

                RememberCallbackBackup(slotAddress, live, moduleFilter, pointerModule);
                std::wstring writeError;
                if (!WriteCallbackPointer(device, slotAddress, returnZeroThunk, &writeError))
                {
                    change.Skipped = true;
                    change.Notes = writeError;
                    AppendCallbackSetChange(result, change);
                    result->Failures.push_back(record.Kind + L" " + which + L": " + writeError);
                    ++result->Failed;
                    ok = true;
                    break;
                }

                change.After = returnZeroThunk;
                change.Changed = true;
                change.Notes = L"patched to CFG return-0 thunk";
                AppendCallbackSetChange(result, change);
                ok = true;
                break;
            }

            if (!haveBackup || backupOriginal == 0)
            {
                change.Skipped = true;
                change.Notes = L"no same-session backup";
                AppendCallbackSetChange(result, change);
                ok = true;
                break;
            }

            change.UsedBackup = true;
            if (live == backupOriginal)
            {
                change.After = live;
                change.Skipped = true;
                change.Notes = L"already restored from this session";
                AppendCallbackSetChange(result, change);
                ok = true;
                break;
            }

            if (!liveIsNop)
            {
                change.Skipped = true;
                change.Notes = L"live pointer is not the session thunk; refusing to clobber";
                AppendCallbackSetChange(result, change);
                result->Failures.push_back(record.Kind + L" " + which + L": unexpected live pointer");
                ++result->Failed;
                ok = true;
                break;
            }

            std::wstring writeError;
            if (!WriteCallbackPointer(device, slotAddress, backupOriginal, &writeError))
            {
                change.Skipped = true;
                change.Notes = writeError;
                AppendCallbackSetChange(result, change);
                result->Failures.push_back(record.Kind + L" " + which + L": " + writeError);
                ++result->Failed;
                ok = true;
                break;
            }

            change.After = backupOriginal;
            change.Changed = true;
            change.Notes = L"restored same-session original";
            AppendCallbackSetChange(result, change);
            ok = true;
        } while (false);

        return ok;
    }

    void MergeMinifilterBatch(
        const MinifilterIrpBatchResult& batch,
        KernelCallbackSetResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            result->MinifilterLiveNodesChanged += batch.LiveNodesChanged;
            result->MinifilterLiveNodesFailed += batch.LiveNodesFailed;
            result->Failed += batch.Failed;
            for (const std::wstring& failure : batch.Failures)
            {
                result->Failures.push_back(L"minifilter: " + failure);
            }

            for (const MinifilterIrpChange& irpChange : batch.Changes)
            {
                if (irpChange.PreChanged)
                {
                    KernelCallbackPointerChange change = {};
                    change.Kind = L"minifilter";
                    change.Target = irpChange.FilterName;
                    change.Which = irpChange.Before.MajorName + L" pre";
                    change.Module = irpChange.Before.PreModule;
                    change.Before = irpChange.Before.Pre;
                    change.After = irpChange.After.Pre;
                    change.Changed = true;
                    change.UsedBackup = irpChange.UsedBackup;
                    change.Notes = L"FLT_FILTER.Operations + live CallbackNodes";
                    AppendCallbackSetChange(result, change);
                }

                if (irpChange.PostChanged)
                {
                    KernelCallbackPointerChange change = {};
                    change.Kind = L"minifilter";
                    change.Target = irpChange.FilterName;
                    change.Which = irpChange.Before.MajorName + L" post";
                    change.Module = irpChange.Before.PostModule;
                    change.Before = irpChange.Before.Post;
                    change.After = irpChange.After.Post;
                    change.Changed = true;
                    change.UsedBackup = irpChange.UsedBackup;
                    change.Notes = L"FLT_FILTER.Operations + live CallbackNodes";
                    AppendCallbackSetChange(result, change);
                }

                if (!irpChange.PreChanged && !irpChange.PostChanged && irpChange.LiveNodesChanged > 0)
                {
                    KernelCallbackPointerChange change = {};
                    change.Kind = L"minifilter";
                    change.Target = irpChange.FilterName;
                    change.Which = irpChange.Before.MajorName;
                    change.Changed = true;
                    change.UsedBackup = irpChange.UsedBackup;
                    change.Notes = L"live CallbackNodes patched";
                    AppendCallbackSetChange(result, change);
                }
            }

            result->Skipped += batch.Skipped;
        } while (false);
    }
}

bool KernelCallbackRecordMatchesModule(const KernelCallbackRecord& record, const std::wstring& moduleFilter)
{
    bool matched = false;
    do
    {
        if (CallbackTrimCopy(moduleFilter).empty())
        {
            matched = true;
            break;
        }

        if (CallbackModuleTextMatchesLocal(record.FunctionModule, moduleFilter) ||
            CallbackModuleTextMatchesLocal(record.PostFunctionModule, moduleFilter))
        {
            matched = true;
            break;
        }

        if (record.Kind == L"minifilter" &&
            CallbackModuleTextMatchesLocal(record.FilterName, moduleFilter))
        {
            matched = true;
            break;
        }

        if (RecordHasBackupForModule(record, moduleFilter))
        {
            matched = true;
        }
    } while (false);

    return matched;
}

bool KernelCallbackRecordMatchesModuleForWrite(const KernelCallbackRecord& record, const std::wstring& moduleFilter)
{
    return RecordOwnedForWrite(record, moduleFilter);
}

bool KernelCallbackRecordHasSessionBackup(const KernelCallbackRecord& record, const std::wstring& moduleFilter)
{
    return RecordHasBackupForModule(record, moduleFilter);
}

void OverlayCallbackSessionDisabled(KernelCallbackScanResult* result)
{
    do
    {
        if (result == nullptr)
        {
            break;
        }

        OverlaySessionDisabledRecords(&result->Records);
    } while (false);
}

bool IsCallbackWriteAction(const std::wstring& text)
{
    bool result = false;
    const std::wstring lowered = ToLowerLocal(text);
    if (lowered == L"disable" ||
        lowered == L"enable" ||
        lowered == L"disable-all" ||
        lowered == L"enable-all")
    {
        result = true;
    }

    return result;
}

std::wstring BuildCallbackSetJson(const KernelCallbackSetResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.callbacks-set.v1\"";
    out += L",\"action\":" + mcpjson::Quote(result.Action);
    out += L",\"scope\":" + mcpjson::Quote(result.Scope);
    out += L",\"module\":" + mcpjson::Quote(result.Module);
    out += L",\"attempted\":" + std::to_wstring(result.Attempted);
    out += L",\"changed\":" + std::to_wstring(result.Changed);
    out += L",\"skipped\":" + std::to_wstring(result.Skipped);
    out += L",\"failed\":" + std::to_wstring(result.Failed);
    out += L",\"minifilterLiveNodesChanged\":" + std::to_wstring(result.MinifilterLiveNodesChanged);
    out += L",\"minifilterLiveNodesFailed\":" + std::to_wstring(result.MinifilterLiveNodesFailed);
    out += L",\"changes\":[";
    for (size_t index = 0; index < result.Changes.size(); ++index)
    {
        const KernelCallbackPointerChange& change = result.Changes[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"kind\":" + mcpjson::Quote(change.Kind);
        out += L",\"target\":" + mcpjson::Quote(change.Target);
        out += L",\"which\":" + mcpjson::Quote(change.Which);
        out += L",\"module\":" + mcpjson::Quote(change.Module);
        out += L",\"slot\":" + mcpjson::Quote(CallbacksJsonHex(change.SlotAddress));
        out += L",\"before\":" + mcpjson::Quote(CallbacksJsonHex(change.Before));
        out += L",\"after\":" + mcpjson::Quote(CallbacksJsonHex(change.After));
        out += L",\"changed\":";
        out += change.Changed ? L"true" : L"false";
        out += L",\"usedBackup\":";
        out += change.UsedBackup ? L"true" : L"false";
        out += L",\"skipped\":";
        out += change.Skipped ? L"true" : L"false";
        if (!change.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(change.Notes);
        }
        out += L"}";
    }

    out += L"],\"failures\":[";
    for (size_t index = 0; index < result.Failures.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Failures[index]);
    }

    out += L"],\"warnings\":[";
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

bool KernelCallbackScanner::SetModuleCallbacks(
    const std::wstring& scope,
    const std::wstring& moduleFilter,
    KernelCallbackSetAction action,
    KernelCallbackSetResult* result,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"callback set output is null";
            }
            break;
        }

        *result = KernelCallbackSetResult{};
        result->Action = (action == KernelCallbackSetAction::Disable) ? L"disable" : L"enable";
        result->Scope = scope.empty() ? L"all" : ToLowerLocal(scope);
        result->Module = CallbackTrimCopy(moduleFilter);
        if (result->Module.empty())
        {
            if (error != nullptr)
            {
                *error = L"module is required; refusing to change every registered callback";
            }
            break;
        }

        if (!device_.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"!callbacks disable/enable requires the KnLiveDbg.sys device to be open";
            }
            break;
        }

        if (!CallbackWriteModeEnabled(device_, error))
        {
            break;
        }

        KernelCallbackScanResult scan = {};
        if (!Scan(result->Scope, &scan, error))
        {
            break;
        }

        OverlayCallbackSessionDisabled(&scan);
        result->Warnings = scan.Warnings;
        std::vector<KernelCallbackRecord> owned;
        owned.reserve(scan.Records.size());
        for (const KernelCallbackRecord& record : scan.Records)
        {
            if (record.Poisoned)
            {
                continue;
            }

            const bool writeOwned = RecordOwnedForWrite(record, result->Module);
            const bool backupOwned = RecordHasBackupForModule(record, result->Module);
            if (writeOwned || backupOwned)
            {
                owned.push_back(record);
            }
        }

        if (owned.empty())
        {
            if (error != nullptr)
            {
                *error = L"no " + result->Scope + L" callbacks owned by " + result->Module;
            }
            break;
        }

        uint64_t preThunk = 0;
        uint64_t postThunk = 0;
        bool needPointerThunk = false;
        for (const KernelCallbackRecord& record : owned)
        {
            if (record.Kind != L"minifilter")
            {
                needPointerThunk = true;
                break;
            }
        }

        if (needPointerThunk &&
            !ResolveMinifilterNopThunks(device_, symbols_, &preThunk, &postThunk, error))
        {
            break;
        }

        if (needPointerThunk && (postThunk == 0 || postThunk == preThunk))
        {
            if (error != nullptr)
            {
                *error = L"no CFG-valid return-0 thunk for Ob/Cm/Ps callbacks; "
                         L"rebuild KnLiveDbg.sys for KnDbgMinifilterPostCallbackNop";
            }
            break;
        }

        std::set<uint64_t> minifilterSeen;
        bool anyMinifilterAttempted = false;
        for (const KernelCallbackRecord& record : owned)
        {
            if (record.Kind != L"minifilter")
            {
                continue;
            }

            if (record.Filter == 0 || minifilterSeen.find(record.Filter) != minifilterSeen.end())
            {
                continue;
            }

            minifilterSeen.insert(record.Filter);
            anyMinifilterAttempted = true;
            MinifilterIrpScanner irpScanner(device_, symbols_);
            MinifilterIrpBatchResult batch = {};
            MinifilterIrpScanResult irpScan = {};
            std::wstring irpError;
            const std::wstring specifier = LeftoverFormatHex(record.Filter, 16);
            const MinifilterIrpAction irpAction =
                (action == KernelCallbackSetAction::Disable)
                    ? MinifilterIrpAction::Disable
                    : MinifilterIrpAction::Enable;
            if (!irpScanner.SetAllIrps(
                    specifier,
                    irpAction,
                    MinifilterIrpWhich::Both,
                    &batch,
                    &irpScan,
                    &irpError))
            {
                const bool enableWithoutBackup =
                    action == KernelCallbackSetAction::Enable &&
                    (irpError.find(L"no saved IRP handlers") != std::wstring::npos ||
                     irpError.find(L"only works after") != std::wstring::npos);
                if (enableWithoutBackup)
                {
                    KernelCallbackPointerChange skip = {};
                    skip.Kind = L"minifilter";
                    skip.Target = record.FilterName;
                    skip.Which = L"all";
                    skip.Skipped = true;
                    skip.Notes = irpError;
                    AppendCallbackSetChange(result, skip);
                    continue;
                }

                result->Failures.push_back(
                    L"minifilter " +
                    (record.FilterName.empty() ? specifier : record.FilterName) +
                    L": " + irpError);
                ++result->Failed;
                continue;
            }

            MergeMinifilterBatch(batch, result);
        }

        for (const KernelCallbackRecord& record : owned)
        {
            if (record.Kind == L"minifilter")
            {
                continue;
            }

            const wchar_t* primaryWhich = L"pre";
            if (record.Kind == L"process" ||
                record.Kind == L"thread" ||
                record.Kind == L"imageload")
            {
                primaryWhich = L"function";
            }

            PatchOwnedCallbackPointer(
                device_,
                record,
                primaryWhich,
                record.FunctionSlot,
                record.Function,
                record.FunctionModule,
                result->Module,
                action,
                postThunk,
                result);
            PatchOwnedCallbackPointer(
                device_,
                record,
                L"post",
                record.PostFunctionSlot,
                record.PostFunction,
                record.PostFunctionModule,
                result->Module,
                action,
                postThunk,
                result);
        }

        if (action == KernelCallbackSetAction::Enable &&
            result->Changed == 0 &&
            result->Attempted == result->Skipped &&
            !anyMinifilterAttempted)
        {
            bool anyBackup = false;
            for (const KernelCallbackRecord& record : owned)
            {
                if (RecordHasBackupForModule(record, result->Module))
                {
                    anyBackup = true;
                    break;
                }
            }

            if (!anyBackup)
            {
                if (error != nullptr)
                {
                    *error = L"no saved " + result->Scope + L" callbacks for " + result->Module +
                             L"; enable only works after a disable in this session";
                }
                break;
            }
        }

        if (result->Changed == 0 && result->Failed != 0)
        {
            if (error != nullptr)
            {
                *error = L"failed to change any " + result->Scope + L" callback owned by " + result->Module;
                if (!result->Failures.empty())
                {
                    *error += L" (" + result->Failures.front() + L")";
                }
            }
            break;
        }

        if (result->Changed == 0 && result->Skipped == 0)
        {
            if (error != nullptr)
            {
                *error = L"no writable " + result->Scope + L" callback slots owned by " + result->Module;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelCallbackScannerSelfTest()
{
    bool ok = true;
    do
    {
        if (!IsCallbackWriteAction(L"disable") ||
            !IsCallbackWriteAction(L"ENABLE-ALL") ||
            IsCallbackWriteAction(L"object") ||
            IsCallbackWriteAction(L"list"))
        {
            ok = false;
            break;
        }

        KernelCallbackRecord wdProcess = {};
        wdProcess.Kind = L"process";
        wdProcess.Function = 0xfffff80000001000ull;
        wdProcess.FunctionModule = L"WdFilter.sys";
        KernelCallbackRecord ntThread = {};
        ntThread.Kind = L"thread";
        ntThread.Function = 0xfffff80000002000ull;
        ntThread.FunctionModule = L"ntoskrnl.exe";
        KernelCallbackRecord wdFilter = {};
        wdFilter.Kind = L"minifilter";
        wdFilter.FilterName = L"WdFilter";
        wdFilter.FunctionModule = L"FLTMGR.SYS";
        if (!KernelCallbackRecordMatchesModule(wdProcess, L"wdfilter") ||
            !KernelCallbackRecordMatchesModule(wdProcess, L"WdFilter.sys") ||
            KernelCallbackRecordMatchesModule(ntThread, L"WdFilter") ||
            !KernelCallbackRecordMatchesModule(wdFilter, L"WdFilter") ||
            KernelCallbackRecordMatchesModule(wdProcess, L"fltmgr"))
        {
            ok = false;
            break;
        }

        if (!KernelCallbackRecordMatchesModuleForWrite(wdFilter, L"WdFilter") ||
            KernelCallbackRecordMatchesModuleForWrite(wdFilter, L"fltmgr") ||
            KernelCallbackRecordMatchesModuleForWrite(ntThread, L"WdFilter") ||
            !KernelCallbackRecordMatchesModule(wdFilter, L"fltmgr"))
        {
            ok = false;
            break;
        }

        KernelCallbackRecord unnamedFilter = {};
        unnamedFilter.Kind = L"minifilter";
        unnamedFilter.FilterName = L"<unnamed>";
        unnamedFilter.Function = 0xfffff80000004000ull;
        unnamedFilter.FunctionModule = L"WdFilter.sys";
        if (!KernelCallbackRecordMatchesModuleForWrite(unnamedFilter, L"WdFilter") ||
            KernelCallbackRecordMatchesModuleForWrite(unnamedFilter, L"fltmgr"))
        {
            ok = false;
            break;
        }

        KernelCallbackSetResult setResult = {};
        setResult.Action = L"disable";
        setResult.Scope = L"object";
        setResult.Module = L"WdFilter";
        setResult.Changed = 2;
        KernelCallbackPointerChange change = {};
        change.Kind = L"ob";
        change.Target = L"Process";
        change.Which = L"pre";
        change.Changed = true;
        setResult.Changes.push_back(change);
        const std::wstring json = BuildCallbackSetJson(setResult);
        if (json.find(L"kn-live-dbg.callbacks-set.v1") == std::wstring::npos ||
            json.find(L"\"changed\":2") == std::wstring::npos ||
            json.find(L"\"scope\":\"object\"") == std::wstring::npos)
        {
            ok = false;
            break;
        }

        KernelCallbackScanResult scan = {};
        KernelCallbackRecord poisoned = {};
        poisoned.Kind = L"ob";
        poisoned.Function = 0xfffff80000003000ull;
        poisoned.FunctionModule = L"WdFilter.sys";
        poisoned.Poisoned = true;
        scan.Records.push_back(wdProcess);
        scan.Records.push_back(poisoned);
        poisoned.SessionDisabled = true;
        scan.Records.back().SessionDisabled = true;
        const std::wstring listJson = BuildCallbacksJson(scan);
        if (listJson.find(L"\"poisoned\":true") == std::wstring::npos ||
            listJson.find(L"\"sessionDisabled\":true") == std::wstring::npos)
        {
            ok = false;
            break;
        }
    } while (false);

    return ok;
}
