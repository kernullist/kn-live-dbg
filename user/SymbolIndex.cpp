#include "SymbolIndex.h"
#include "ContentHash.h"
#include "McpJson.h"
#include <algorithm>
#include <tuple>

namespace
{
    bool Hex(const std::wstring& text, size_t size)
    { return text.size() == size && text.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }
    bool Tag(uint32_t tag) { return tag == 5 || tag == 7 || tag == 9 || tag == 10 || tag == 27; }
    void Number(std::string& text, uint64_t value, size_t bytes)
    {
        for (size_t i = 0; i < bytes; ++i) { text += static_cast<char>(value & 255); value >>= 8; }
    }
    void Name(std::string& text, const std::wstring& value)
    {
        const auto utf8 = mcpjson::WideToUtf8(value);
        Number(text, utf8.size(), 4); text += utf8;
    }
    struct Reader
    {
        const std::string& Bytes;
        size_t Offset = 0;
        bool Number(uint64_t* value, size_t count)
        {
            *value = 0;
            if (count > 8 || Offset > Bytes.size() || count > Bytes.size() - Offset) { return false; }
            for (size_t i = 0; i < count; ++i) { *value |= static_cast<uint64_t>(static_cast<unsigned char>(Bytes[Offset++])) << (i * 8); }
            return true;
        }
        bool Number(uint32_t* value)
        {
            uint64_t number = 0;
            if (!Number(&number, 4)) { return false; }
            *value = static_cast<uint32_t>(number); return true;
        }
        bool Fixed(std::wstring* value, size_t count)
        {
            if (Offset > Bytes.size() || count > Bytes.size() - Offset) { return false; }
            value->assign(Bytes.begin() + Offset, Bytes.begin() + Offset + count); Offset += count;
            return Hex(*value, count);
        }
        bool Name(std::wstring* value, bool raw = false)
        {
            uint32_t count = 0;
            if (!Number(&count) || count == 0 || count > 4096 || count > Bytes.size() - Offset) { return false; }
            const auto utf8 = Bytes.substr(Offset, count); Offset += count;
            *value = mcpjson::Utf8ToWide(utf8);
            return (raw ? SymbolIndexRawName(*value) : SymbolIndexName(*value)) && mcpjson::WideToUtf8(*value) == utf8;
        }
    };
}

bool SymbolIndexName(const std::wstring& name)
{
    return !name.empty() && name.size() <= 1024 && mcpjson::SanitizeUtf16(name) == name &&
        std::none_of(name.begin(), name.end(), [](wchar_t c) { return c < 32 || (c >= 127 && c <= 159); });
}
bool SymbolIndexRawName(const std::wstring& name)
{
    return !name.empty() && name.size() <= 1024 && name.find(L'\0') == std::wstring::npos && mcpjson::SanitizeUtf16(name) == name;
}
std::wstring EscapeSymbolIndexName(const std::wstring& name)
{
    std::wstring result;
    for (const auto c : name)
    {
        if (c == L'\\') { result += L"\\\\"; }
        else if (c < 32 || (c >= 127 && c <= 159))
        {
            result += L"\\u";
            for (int shift = 12; shift >= 0; shift -= 4) { result += L"0123456789abcdef"[(static_cast<unsigned>(c) >> shift) & 15]; }
        }
        else { result += c; }
    }
    return result;
}
bool IndexedSymbolLess(const IndexedSymbol& a, const IndexedSymbol& b)
{
    return std::tie(a.Rva, a.Name, a.LinkageName, a.Tag, a.SizeKnown, a.Bytes) <
        std::tie(b.Rva, b.Name, b.LinkageName, b.Tag, b.SizeKnown, b.Bytes);
}
bool IndexedTypeLess(const IndexedType& a, const IndexedType& b)
{ return std::tie(a.Name, a.ProviderId, a.SizeKnown, a.Bytes) < std::tie(b.Name, b.ProviderId, b.SizeKnown, b.Bytes); }
bool ValidateSymbolIndex(const SymbolIndex& index)
{
    if (!Hex(index.ImageSha256, 64) || !Hex(index.PdbSha256, 64) || !Hex(index.ProviderSha256, 64) || !Hex(index.PdbGuid, 32) ||
        index.PdbAge == 0 || index.Machine != IMAGE_FILE_MACHINE_AMD64 || index.ImageSize == 0 ||
        index.Symbols.size() > SymbolIndexMaxRows || index.Types.size() > SymbolIndexMaxRows) { return false; }
    for (size_t i = 0; i < index.Symbols.size(); ++i)
    {
        const auto& row = index.Symbols[i];
        if (!SymbolIndexName(row.Name) || !SymbolIndexRawName(row.LinkageName) || !Tag(row.Tag) || row.Rva >= index.ImageSize ||
            (!row.SizeKnown && row.Bytes != 0) || row.Bytes > index.ImageSize - row.Rva ||
            (i != 0 && !IndexedSymbolLess(index.Symbols[i - 1], row))) { return false; }
    }
    for (size_t i = 0; i < index.Types.size(); ++i)
    {
        const auto& row = index.Types[i];
        if (!SymbolIndexName(row.Name) || (!row.SizeKnown && row.Bytes != 0) ||
            (i != 0 && !IndexedTypeLess(index.Types[i - 1], row))) { return false; }
    }
    return true;
}
bool EncodeSymbolIndex(const SymbolIndex& index, std::string* output)
{
    if (output == nullptr) { return false; }
    output->clear();
    if (!ValidateSymbolIndex(index)) { return false; }
    std::string bytes = "KNSYMIDX";
    Number(bytes, 1, 4); Number(bytes, index.ImageSize, 4); Number(bytes, index.PdbAge, 4); Number(bytes, index.Machine, 4);
    Number(bytes, index.Symbols.size(), 4); Number(bytes, index.Types.size(), 4);
    for (const auto* hash : {&index.ImageSha256, &index.PdbSha256, &index.ProviderSha256, &index.PdbGuid})
    { bytes += mcpjson::WideToUtf8(*hash); }
    for (const auto& row : index.Symbols)
    {
        Number(bytes, row.Rva, 4); Number(bytes, row.Tag, 4); Number(bytes, row.SizeKnown ? 1 : 0, 4); Number(bytes, row.Bytes, 8);
        Name(bytes, row.Name); Name(bytes, row.LinkageName);
        if (bytes.size() > SymbolIndexMaxBytes) { return false; }
    }
    for (const auto& row : index.Types)
    {
        Number(bytes, row.ProviderId, 4); Number(bytes, row.SizeKnown ? 1 : 0, 4); Number(bytes, row.Bytes, 8); Name(bytes, row.Name);
        if (bytes.size() > SymbolIndexMaxBytes) { return false; }
    }
    *output = std::move(bytes); return true;
}
bool DecodeSymbolIndex(const std::string& input, SymbolIndex* index)
{
    if (index == nullptr) { return false; }
    *index = {};
    if (input.size() < 256 || input.size() > SymbolIndexMaxBytes || input.compare(0, 8, "KNSYMIDX") != 0) { return false; }
    Reader read{input, 8};
    SymbolIndex parsed;
    uint32_t version = 0, symbols = 0, types = 0;
    if (!read.Number(&version) || version != 1 || !read.Number(&parsed.ImageSize) || !read.Number(&parsed.PdbAge) ||
        !read.Number(&parsed.Machine) || !read.Number(&symbols) || !read.Number(&types) ||
        symbols > SymbolIndexMaxRows || types > SymbolIndexMaxRows ||
        !read.Fixed(&parsed.ImageSha256, 64) || !read.Fixed(&parsed.PdbSha256, 64) ||
        !read.Fixed(&parsed.ProviderSha256, 64) || !read.Fixed(&parsed.PdbGuid, 32)) { return false; }
    // Check minimum framing before reserving attacker-supplied row counts.
    if (static_cast<uint64_t>(symbols) * 30 + static_cast<uint64_t>(types) * 21 > input.size() - read.Offset) { return false; }
    parsed.Symbols.reserve(symbols); parsed.Types.reserve(types);
    for (uint32_t i = 0; i < symbols; ++i)
    {
        IndexedSymbol row; uint32_t known = 0;
        if (!read.Number(&row.Rva) || !read.Number(&row.Tag) || !read.Number(&known) || known > 1 || !read.Number(&row.Bytes, 8) ||
            !read.Name(&row.Name) || !read.Name(&row.LinkageName, true)) { return false; }
        row.SizeKnown = known == 1; parsed.Symbols.push_back(std::move(row));
    }
    for (uint32_t i = 0; i < types; ++i)
    {
        IndexedType row; uint32_t known = 0;
        if (!read.Number(&row.ProviderId) || !read.Number(&known) || known > 1 || !read.Number(&row.Bytes, 8) || !read.Name(&row.Name))
        { return false; }
        row.SizeKnown = known == 1; parsed.Types.push_back(std::move(row));
    }
    if (read.Offset != input.size() || !ValidateSymbolIndex(parsed)) { return false; }
    ContentHash hash;
    if (!hash.Add(reinterpret_cast<const uint8_t*>(input.data()), input.size())) { return false; }
    parsed.IndexSha256 = hash.Finish();
    if (parsed.IndexSha256.empty()) { return false; }
    *index = std::move(parsed); return true;
}
