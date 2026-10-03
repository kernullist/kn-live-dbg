#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <vector>

struct KmonImportSymbol
{
    std::string Name;
    uint16_t Ordinal = 0;
    bool ByOrdinal = false;
};

using KmonRvaReader = std::function<bool(uint32_t, uint32_t, std::vector<uint8_t>*)>;

inline bool KmonReadImportString(const KmonRvaReader& read, uint32_t rva, std::string* value)
{
    value->clear();
    for (uint32_t i = 0; i < 256 && rva <= UINT32_MAX - i; ++i)
    {
        std::vector<uint8_t> byte;
        if (!read(rva + i, 1, &byte) || byte.size() != 1)
        {
            return false;
        }
        if (byte[0] == 0)
        {
            return !value->empty();
        }
        if (byte[0] < 0x21 || byte[0] > 0x7e)
        {
            return false;
        }
        value->push_back(static_cast<char>(byte[0]));
    }
    return false;
}

// Resolve by the requested symbol, never by merely finding any forwarder.
inline bool KmonReadExport(const KmonRvaReader& read, uint32_t imageSize,
    uint32_t exportRva, uint32_t exportSize, const KmonImportSymbol& symbol,
    uint32_t* targetRva, std::string* forwarder)
{
    *targetRva = 0;
    forwarder->clear();
    std::vector<uint8_t> bytes;
    if (exportSize < sizeof(IMAGE_EXPORT_DIRECTORY) || exportRva >= imageSize ||
        exportSize > imageSize - exportRva ||
        !read(exportRva, sizeof(IMAGE_EXPORT_DIRECTORY), &bytes) || bytes.size() != sizeof(IMAGE_EXPORT_DIRECTORY))
    {
        return false;
    }
    IMAGE_EXPORT_DIRECTORY directory = {};
    std::memcpy(&directory, bytes.data(), sizeof(directory));
    if (directory.NumberOfFunctions == 0 || directory.NumberOfFunctions > 65536 || directory.NumberOfNames > 65536)
    {
        return false;
    }
    uint32_t ordinal = UINT32_MAX;
    if (symbol.ByOrdinal)
    {
        if (symbol.Ordinal < directory.Base)
        {
            return false;
        }
        ordinal = symbol.Ordinal - directory.Base;
    }
    else
    {
        // The PE name pointer table is lexically sorted.
        uint32_t low = 0;
        uint32_t high = directory.NumberOfNames;
        while (low < high)
        {
            const uint32_t middle = low + (high - low) / 2;
            if (directory.AddressOfNames > UINT32_MAX - middle * 4 ||
                !read(directory.AddressOfNames + middle * 4, 4, &bytes) || bytes.size() != 4)
            {
                return false;
            }
            uint32_t nameRva = 0;
            std::memcpy(&nameRva, bytes.data(), 4);
            std::string name;
            if (!KmonReadImportString(read, nameRva, &name))
            {
                return false;
            }
            const int comparison = name.compare(symbol.Name);
            if (comparison == 0)
            {
                if (directory.AddressOfNameOrdinals > UINT32_MAX - middle * 2 ||
                    !read(directory.AddressOfNameOrdinals + middle * 2, 2, &bytes) || bytes.size() != 2)
                {
                    return false;
                }
                uint16_t value = 0;
                std::memcpy(&value, bytes.data(), 2);
                ordinal = value;
                break;
            }
            if (comparison < 0)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }
    }
    if (ordinal >= directory.NumberOfFunctions || directory.AddressOfFunctions > UINT32_MAX - ordinal * 4 ||
        !read(directory.AddressOfFunctions + ordinal * 4, 4, &bytes) || bytes.size() != 4)
    {
        return false;
    }
    uint32_t rva = 0;
    std::memcpy(&rva, bytes.data(), 4);
    if (rva == 0 || rva >= imageSize)
    {
        return false;
    }
    if (rva >= exportRva && rva - exportRva < exportSize)
    {
        if (!KmonReadImportString(read, rva, forwarder) ||
            forwarder->size() + 1 > exportSize - (rva - exportRva))
        {
            return false;
        }
    }
    else
    {
        *targetRva = rva;
    }
    return true;
}

using KmonExportLookup = std::function<bool(const std::wstring&, const KmonImportSymbol&, uint64_t*, std::string*)>;

inline bool KmonResolveImportTarget(std::wstring module, KmonImportSymbol symbol,
    const KmonExportLookup& lookup, uint64_t* target)
{
    *target = 0;
    std::set<std::wstring> visited;
    for (size_t hop = 0; hop < 8; ++hop)
    {
        for (wchar_t& ch : module)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch += L'a' - L'A';
            }
        }
        if (module.find(L'.') == std::wstring::npos)
        {
            module += L".dll";
        }
        const std::wstring key = module + L":" + (symbol.ByOrdinal ? L"#" + std::to_wstring(symbol.Ordinal) :
            std::wstring(symbol.Name.begin(), symbol.Name.end()));
        if (!visited.insert(key).second)
        {
            return false;
        }
        uint64_t address = 0;
        std::string forwarder;
        if (!lookup(module, symbol, &address, &forwarder))
        {
            return false;
        }
        if (forwarder.empty())
        {
            *target = address;
            return address != 0;
        }
        const size_t split = forwarder.rfind('.');
        if (split == std::string::npos || split == 0 || split + 1 == forwarder.size())
        {
            return false;
        }
        module.assign(forwarder.begin(), forwarder.begin() + split);
        symbol = {};
        symbol.Name = forwarder.substr(split + 1);
        if (symbol.Name[0] == '#')
        {
            uint32_t ordinal = 0;
            if (symbol.Name.size() < 2 || symbol.Name.size() > 6)
            {
                return false;
            }
            for (size_t i = 1; i < symbol.Name.size(); ++i)
            {
                if (symbol.Name[i] < '0' || symbol.Name[i] > '9')
                {
                    return false;
                }
                ordinal = ordinal * 10 + symbol.Name[i] - '0';
            }
            if (ordinal > UINT16_MAX)
            {
                return false;
            }
            symbol.ByOrdinal = true;
            symbol.Ordinal = static_cast<uint16_t>(ordinal);
            symbol.Name.clear();
        }
    }
    return false;
}
