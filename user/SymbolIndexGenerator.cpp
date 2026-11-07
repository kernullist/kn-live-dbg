#include "SymbolIndex.h"
#include "DiaArtifactSession.h"
#include "ParserWorkerProcess.h"
#include <algorithm>

#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using Microsoft::WRL::ComPtr;
namespace
{
    std::wstring Text(BSTR value)
    {
        return value != nullptr && SysStringLen(value) <= 1024 ? std::wstring(value, SysStringLen(value)) : L"";
    }
    std::wstring Name(IDiaSymbol* symbol, bool undecorated)
    {
        BSTR value = nullptr;
        const auto status = undecorated ? symbol->get_undecoratedNameEx(0x1000, &value) : symbol->get_name(&value);
        auto result = status == S_OK ? Text(value) : L"";
        SysFreeString(value); return result;
    }
    std::wstring Guid(const GUID& guid)
    {
        wchar_t text[33]{};
        swprintf_s(text, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return text;
    }
    bool AddSymbol(IDiaSymbol* symbol, SymbolIndex* index, uint64_t* textBytes, uint32_t* failure)
    {
        DWORD tag = 0, rva = 0;
        if (symbol->get_symTag(&tag) != S_OK) { return false; }
        if (tag != SymTagFunction && tag != SymTagData && tag != SymTagPublicSymbol && tag != SymTagLabel && tag != SymTagThunk) { return true; }
        // Absolute constants and non-image locations have no image-relative address.
        if (symbol->get_relativeVirtualAddress(&rva) != S_OK) { return true; }
        IndexedSymbol row;
        row.Rva = rva; row.Tag = tag;
        row.LinkageName = Name(symbol, false);
        // Function/data get_name already carries the source scope. DIA can
        // ignore UNDNAME_NAME_ONLY for private functions and return a prototype.
        row.Name = tag == SymTagPublicSymbol ? Name(symbol, true) : row.LinkageName;
        if (row.Name.empty()) { row.Name = row.LinkageName; }
        if (row.LinkageName.empty()) { *failure = 23; return false; }
        row.Name = EscapeSymbolIndexName(row.Name);
        if (!SymbolIndexName(row.Name) || !SymbolIndexRawName(row.LinkageName)) { *failure = 20; return false; }
        if (row.Rva >= index->ImageSize) { *failure = 21; return false; }
        row.SizeKnown = symbol->get_length(&row.Bytes) == S_OK;
        if (!row.SizeKnown) { row.Bytes = 0; }
        if (row.Bytes > index->ImageSize - row.Rva) { *failure = 22; return false; }
        *textBytes += (row.Name.size() + row.LinkageName.size()) * sizeof(wchar_t) + sizeof(row);
        if (*textBytes > 64 * 1024 * 1024 || index->Symbols.size() >= SymbolIndexMaxRows * 2) { return false; }
        index->Symbols.push_back(std::move(row)); return true;
    }
    bool Symbols(DiaArtifactSession& session, SymbolIndex* index, uint64_t deadline, uint64_t* textBytes, uint32_t* failure)
    {
        ComPtr<IDiaEnumSymbolsByAddr> addresses;
        ComPtr<IDiaSymbol> symbol;
        if (session.Session->getSymbolsByAddr(&addresses) != S_OK || !addresses) { return false; }
        const auto first = addresses->symbolByAddr(1, 0, &symbol);
        if (first != S_OK && first != S_FALSE) { return false; }
        size_t visited = 0;
        while (symbol)
        {
            if (++visited > SymbolIndexMaxRows * 2 || GetTickCount64() >= deadline || !AddSymbol(symbol.Get(), index, textBytes, failure)) { return false; }
            symbol.Reset(); ULONG fetched = 0;
            const auto status = addresses->Next(1, &symbol, &fetched);
            if (status == S_FALSE && fetched == 0) { break; }
            if (status != S_OK || fetched != 1 || !symbol) { return false; }
        }
        // Public symbols preserve decorated aliases and RVA-zero image symbols
        // that are not necessarily selected by the address-ordered enumerator.
        ComPtr<IDiaEnumSymbols> publics;
        if (session.Global->findChildren(SymTagPublicSymbol, nullptr, nsNone, &publics) != S_OK || !publics) { return false; }
        for (size_t i = 0; i <= SymbolIndexMaxRows; ++i)
        {
            symbol.Reset(); ULONG fetched = 0;
            const auto status = publics->Next(1, &symbol, &fetched);
            if (status == S_FALSE && fetched == 0) { return true; }
            if (status != S_OK || fetched != 1 || !symbol || i == SymbolIndexMaxRows ||
                GetTickCount64() >= deadline || !AddSymbol(symbol.Get(), index, textBytes, failure)) { return false; }
        }
        return false;
    }
    bool Types(DiaArtifactSession& session, SymbolIndex* index, uint64_t deadline, uint64_t* textBytes)
    {
        // The global scope alone omits nested/local types which SymEnumTypes
        // exposed. Read the symbol table, retaining only named type metadata.
        ComPtr<IDiaEnumTables> tables;
        ComPtr<IDiaEnumSymbols> types;
        if (session.Session->getEnumTables(&tables) != S_OK || !tables) { return false; }
        for (size_t i = 0; i < 32 && !types; ++i)
        {
            ComPtr<IDiaTable> table; ULONG fetched = 0;
            if (GetTickCount64() >= deadline || tables->Next(1, &table, &fetched) != S_OK || fetched != 1 || !table) { return false; }
            const auto status = table.As(&types);
            if (status != S_OK && status != E_NOINTERFACE) { return false; }
        }
        if (!types) { return false; }
        for (size_t visited = 0; visited <= SymbolIndexMaxRows * 16; ++visited)
        {
            ComPtr<IDiaSymbol> symbol; ULONG fetched = 0;
            const auto status = types->Next(1, &symbol, &fetched);
            if (status == S_FALSE && fetched == 0) { return true; }
            if (status != S_OK || fetched != 1 || !symbol || visited == SymbolIndexMaxRows * 16 || GetTickCount64() >= deadline)
            { return false; }
            DWORD tag = 0;
            if (symbol->get_symTag(&tag) != S_OK) { return false; }
            if (tag != SymTagUDT && tag != SymTagEnum && tag != SymTagTypedef) { continue; }
            if (index->Types.size() == SymbolIndexMaxRows) { return false; }
            IndexedType row;
            DWORD providerId = 0;
            row.Name = Name(symbol.Get(), false);
            if (!SymbolIndexName(row.Name) || symbol->get_symIndexId(&providerId) != S_OK) { return false; }
            row.ProviderId = providerId;
            row.SizeKnown = symbol->get_length(&row.Bytes) == S_OK;
            // DIA typedef length can be unavailable even when the referred
            // type has a length. Follow only this bounded metadata chain.
            ComPtr<IDiaSymbol> current = symbol;
            for (size_t depth = 0; !row.SizeKnown && depth < 8; ++depth)
            {
                DWORD currentTag = 0; ComPtr<IDiaSymbol> referred;
                if (current->get_symTag(&currentTag) != S_OK || currentTag != SymTagTypedef ||
                    current->get_type(&referred) != S_OK || !referred) { break; }
                current = std::move(referred); row.SizeKnown = current->get_length(&row.Bytes) == S_OK;
            }
            if (!row.SizeKnown) { row.Bytes = 0; }
            *textBytes += row.Name.size() * sizeof(wchar_t) + sizeof(row);
            if (*textBytes > 64 * 1024 * 1024) { return false; }
            index->Types.push_back(std::move(row));
        }
        return false;
    }

}

bool GenerateSymbolIndexFromHandles(HANDLE image, HANDLE pdb, HANDLE provider, SymbolIndex* index, uint32_t* failure)
{
    uint32_t localFailure = 0;
    if (failure == nullptr) { failure = &localFailure; }
    *failure = 10;
    if (index == nullptr) { return false; }
    *index = {};
    DiaArtifactSession session;
    if (!session.Open(image, pdb, provider)) { return false; }
    SymbolIndex result;
    result.ImageSha256 = session.Image.Sha256; result.PdbSha256 = session.Pdb.Sha256; result.ProviderSha256 = session.Provider.Sha256;
    result.PdbGuid = Guid(session.Metadata.PdbGuid); result.PdbAge = session.Metadata.PdbAge;
    result.ImageSize = session.Metadata.SizeOfImage; result.Machine = session.Metadata.Machine;
    const auto deadline = GetTickCount64() + 30000;
    uint64_t bytes = 0;
    *failure = 11;
    if (!Symbols(session, &result, deadline, &bytes, failure)) { return false; }
    *failure = 12;
    if (!Types(session, &result, deadline, &bytes)) { return false; }
    std::sort(result.Symbols.begin(), result.Symbols.end(), IndexedSymbolLess);
    result.Symbols.erase(std::unique(result.Symbols.begin(), result.Symbols.end(), [](const auto& a, const auto& b)
        { return !IndexedSymbolLess(a, b) && !IndexedSymbolLess(b, a); }), result.Symbols.end());
    std::sort(result.Types.begin(), result.Types.end(), IndexedTypeLess);
    result.Types.erase(std::unique(result.Types.begin(), result.Types.end(), [](const auto& a, const auto& b)
        { return !IndexedTypeLess(a, b) && !IndexedTypeLess(b, a); }), result.Types.end());
    *failure = 13;
    if (!session.Unchanged() || !ValidateSymbolIndex(result)) { return false; }
    *index = std::move(result); *failure = 0; return true;
}
int RunSymbolIndexWorkerCommand(int argc, wchar_t** argv)
{
    if (argc != 5 || !IsRestrictedParserWorker()) { return 3; }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try
    {
        HANDLE files[3]{};
        for (size_t i = 0; i < 3; ++i)
        {
            const std::wstring text = argv[i + 2];
            if (text.empty() || text.size() > 20 || text.find_first_not_of(L"0123456789") != std::wstring::npos) { return 4; }
            uint64_t value = 0;
            for (const auto c : text)
            {
                if (value > (UINTPTR_MAX - (c - L'0')) / 10) { return 4; }
                value = value * 10 + (c - L'0');
            }
            if (value == 0 || value == UINTPTR_MAX) { return 4; }
            files[i] = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
        }
        SymbolIndex index; std::string output; uint32_t failure = 0;
        if (!GenerateSymbolIndexFromHandles(files[0], files[1], files[2], &index, &failure)) { return static_cast<int>(failure); }
        if (!EncodeSymbolIndex(index, &output)) { return 14; }
        size_t offset = 0;
        while (offset < output.size())
        {
            DWORD written = 0;
            const auto count = static_cast<DWORD>((std::min)(output.size() - offset, size_t{65536}));
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output.data() + offset, count, &written, nullptr) || written == 0) { return 6; }
            offset += written;
        }
        return 0;
    }
    catch (...) { return 7; }
}
