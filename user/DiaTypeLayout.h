#pragma once

#include "SymbolEngine.h"
#include <dia2.h>
#include <wrl/client.h>

namespace dia_layout
{
    constexpr size_t MaxFields = 8192;
    constexpr uint64_t MaxTypeBytes = 16 * 1024 * 1024;

    inline std::wstring Name(IDiaSymbol* symbol)
    {
        BSTR value = nullptr;
        std::wstring result;
        if (symbol != nullptr && symbol->get_name(&value) == S_OK && value != nullptr && SysStringLen(value) <= 1024)
        {
            result.assign(value, SysStringLen(value));
        }
        SysFreeString(value);
        return result;
    }

    enum class MemberState
    {
        Valid,
        NotInstance,
        Unavailable
    };

    // Length remains bits for bitfields and bytes for ordinary members.
    // StorageLength is always bytes and is never a substitute for bit width.
    inline MemberState ReadMember(IDiaSymbol* data, uint64_t parentBytes, TypeFieldInfo* output,
        std::wstring (*describe)(IDiaSymbol*, ULONG) = nullptr)
    {
        using Microsoft::WRL::ComPtr;
        DWORD kind = 0, location = 0;
        LONG offset = 0;
        TypeFieldInfo field;
        ComPtr<IDiaSymbol> type;
        if (data == nullptr || output == nullptr || parentBytes == 0 || parentBytes > MaxTypeBytes ||
            data->get_dataKind(&kind) != S_OK)
        {
            return MemberState::Unavailable;
        }
        if (kind == DataIsStaticMember || kind == DataIsConstant)
        {
            return MemberState::NotInstance;
        }
        if (kind != DataIsMember || data->get_locationType(&location) != S_OK ||
            (location != LocIsThisRel && location != LocIsBitField) ||
            data->get_offset(&offset) != S_OK || offset < 0 ||
            data->get_type(&type) != S_OK || !type ||
            type->get_symTag(&field.ChildTag) != S_OK ||
            type->get_length(&field.StorageLength) != S_OK || field.StorageLength == 0 ||
            static_cast<uint64_t>(offset) > parentBytes || field.StorageLength > parentBytes - offset)
        {
            return MemberState::Unavailable;
        }
        field.Name = Name(data);
        if (field.Name.empty() || field.Name.size() > 1024 || field.Name.find(L'\0') != std::wstring::npos)
        {
            return MemberState::Unavailable;
        }
        field.Offset = static_cast<ULONG>(offset);
        field.Tag = SymTagData;
        field.TypeName = describe != nullptr ? describe(type.Get(), 0) : Name(type.Get());
        field.Length = field.StorageLength;
        field.IsBitField = location == LocIsBitField;
        if (field.IsBitField && (data->get_bitPosition(&field.BitPosition) != S_OK ||
            data->get_length(&field.Length) != S_OK || field.Length == 0 ||
            field.BitPosition >= field.StorageLength * 8 || field.Length > field.StorageLength * 8 - field.BitPosition))
        {
            return MemberState::Unavailable;
        }
        DWORD baseType = 0;
        const HRESULT baseStatus = type->get_baseType(&baseType);
        if (baseStatus == S_OK)
        {
            field.BaseType = baseType;
        }
        else if (field.ChildTag == SymTagBaseType)
        {
            return MemberState::Unavailable;
        }
        *output = std::move(field);
        return MemberState::Valid;
    }

    inline bool ReadLayout(IDiaSymbol* udt, TypeLayoutInfo* output,
        std::wstring (*describe)(IDiaSymbol*, ULONG) = nullptr)
    {
        using Microsoft::WRL::ComPtr;
        TypeLayoutInfo layout;
        ComPtr<IDiaEnumSymbols> members;
        LONG count = 0;
        DWORD tag = 0;
        if (udt == nullptr || output == nullptr || udt->get_symTag(&tag) != S_OK || tag != SymTagUDT ||
            udt->get_length(&layout.Size) != S_OK || layout.Size == 0 || layout.Size > MaxTypeBytes ||
            udt->findChildren(SymTagData, nullptr, nsNone, &members) != S_OK || !members ||
            members->get_Count(&count) != S_OK || count < 0 || static_cast<size_t>(count) > MaxFields)
        {
            return false;
        }
        layout.Name = Name(udt);
        for (LONG i = 0; i < count; ++i)
        {
            ComPtr<IDiaSymbol> data;
            ULONG fetched = 0;
            if (members->Next(1, &data, &fetched) != S_OK || fetched != 1 || !data)
            {
                return false;
            }
            TypeFieldInfo field;
            const auto state = ReadMember(data.Get(), layout.Size, &field, describe);
            if (state == MemberState::Valid)
            {
                layout.Fields.push_back(std::move(field));
            }
            else if (state == MemberState::Unavailable)
            {
                ++layout.UnavailableFields;
            }
        }
        ComPtr<IDiaSymbol> extra;
        ULONG fetched = 0;
        if (members->Next(1, &extra, &fetched) != S_FALSE || fetched != 0 || extra)
        {
            return false;
        }
        layout.FieldsComplete = layout.UnavailableFields == 0;
        *output = std::move(layout);
        return output->UnavailableFields == 0 || !output->Fields.empty();
    }
}
