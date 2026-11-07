#include "BrokeredSymbolIndexes.h"
#include <algorithm>
#include <numeric>

bool BrokeredSymbolIndexes::Entry::Resolve(const std::wstring& name, uint32_t* rva, bool* ambiguous) const
{
    *rva = 0; *ambiguous = false;
    bool found = false;
    // A decorated name has precedence over an undecorated display alias.
    for (const bool raw : {true, false})
    {
        const auto& order = raw ? LinkageNames : Names;
        const auto text = [&](size_t i) -> const std::wstring& { return raw ? Index.Symbols[i].LinkageName : Index.Symbols[i].Name; };
        auto at = std::lower_bound(order.begin(), order.end(), name, [&](size_t i, const auto& query) { return text(i) < query; });
        for (; at != order.end() && text(*at) == name; ++at)
        {
            const auto address = Index.Symbols[*at].Rva;
            if (found && *rva != address) { *rva = 0; *ambiguous = true; return false; }
            *rva = address; found = true;
        }
        if (found) { return true; }
    }
    return false;
}
const IndexedSymbol* BrokeredSymbolIndexes::Entry::Nearest(uint32_t rva) const
{
    auto end = std::upper_bound(Index.Symbols.begin(), Index.Symbols.end(), rva,
        [](uint32_t query, const auto& row) { return query < row.Rva; });
    if (end == Index.Symbols.begin()) { return nullptr; }
    const auto address = (end - 1)->Rva;
    auto begin = std::lower_bound(Index.Symbols.begin(), end, address,
        [](const auto& row, uint32_t query) { return row.Rva < query; });
    const auto rank = [](uint32_t tag) { return tag == 5 ? 0 : tag == 7 ? 1 : tag == 10 ? 2 : 3; };
    return &*std::min_element(begin, end, [&](const auto& a, const auto& b) { return rank(a.Tag) < rank(b.Tag); });
}
void BrokeredSymbolIndexes::Clear() { entries_.clear(); bytes_ = 0; }
bool BrokeredSymbolIndexes::Contains(uint64_t module) const
{ return std::any_of(entries_.begin(), entries_.end(), [&](const auto& e) { return e.Module == module; }); }
std::shared_ptr<const BrokeredSymbolIndexes::Entry> BrokeredSymbolIndexes::Find(uint64_t module)
{
    const auto at = std::find_if(entries_.begin(), entries_.end(), [&](const auto& e) { return e.Module == module; });
    if (at == entries_.end()) { return {}; }
    entries_.splice(entries_.end(), entries_, at); return entries_.back().Value;
}
std::shared_ptr<const BrokeredSymbolIndexes::Entry> BrokeredSymbolIndexes::Insert(uint64_t module, SymbolIndex index)
{
    if (module == 0 || index.ImageSize > UINT64_MAX - module || !ValidateSymbolIndex(index) || maxModules_ == 0) { return {}; }
    auto value = std::make_shared<Entry>(); value->Index = std::move(index);
    const auto count = value->Index.Symbols.size();
    value->Names.resize(count); value->LinkageNames.resize(count);
    std::iota(value->Names.begin(), value->Names.end(), size_t{0}); value->LinkageNames = value->Names;
    const auto& symbols = value->Index.Symbols;
    std::sort(value->Names.begin(), value->Names.end(), [&](size_t a, size_t b) { return symbols[a].Name < symbols[b].Name; });
    std::sort(value->LinkageNames.begin(), value->LinkageNames.end(), [&](size_t a, size_t b) { return symbols[a].LinkageName < symbols[b].LinkageName; });
    // Account actual vector/string capacities, excluding allocator bookkeeping.
    // This is a retained metadata budget, not a whole-process heap bound.
    size_t bytes = sizeof(Entry) + sizeof(Cached) + value->Index.Symbols.capacity() * sizeof(IndexedSymbol) +
        value->Index.Types.capacity() * sizeof(IndexedType) + (value->Names.capacity() + value->LinkageNames.capacity()) * sizeof(size_t);
    const auto add = [&](const std::wstring& s) { bytes += (s.capacity() + 1) * sizeof(wchar_t); };
    for (const auto& s : symbols) { add(s.Name); add(s.LinkageName); }
    for (const auto& t : value->Index.Types) { add(t.Name); }
    for (const auto* s : {&value->Index.ImageSha256, &value->Index.PdbSha256, &value->Index.ProviderSha256, &value->Index.PdbGuid, &value->Index.IndexSha256}) { add(*s); }
    if (bytes > maxBytes_) { return {}; }
    // Allocate the list node before evicting valid entries.
    std::list<Cached> prepared; prepared.push_back({module, bytes, value});
    for (auto at = entries_.begin(); at != entries_.end();)
    {
        if (at->Module == module) { bytes_ -= at->Bytes; at = entries_.erase(at); }
        else { ++at; }
    }
    while (!entries_.empty() && (entries_.size() >= maxModules_ || bytes > maxBytes_ - bytes_))
    { bytes_ -= entries_.front().Bytes; entries_.pop_front(); }
    bytes_ += bytes; entries_.splice(entries_.end(), prepared); return value;
}
