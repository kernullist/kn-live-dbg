#pragma once
#include "SymbolIndex.h"
#include <list>
#include <memory>
#include <optional>

// Parent-owned metadata only. No provider calls or persistent parser IDs.
class BrokeredSymbolIndexes
{
public:
    struct Entry
    {
        SymbolIndex Index;
        std::vector<size_t> Names, LinkageNames;
        // Ambiguous distinct addresses fail; aliases at one RVA are allowed.
        bool Resolve(const std::wstring& name, uint32_t* rva, bool* ambiguous) const;
        const IndexedSymbol* Nearest(uint32_t rva) const;
    };
    explicit BrokeredSymbolIndexes(size_t maxBytes = 128 * 1024 * 1024, size_t maxModules = 16)
        : maxBytes_(maxBytes), maxModules_(maxModules) {}
    void Clear();
    bool Contains(uint64_t module) const;
    std::shared_ptr<const Entry> Find(uint64_t module);
    std::shared_ptr<const Entry> Insert(uint64_t module, SymbolIndex index);
    size_t Size() const { return entries_.size(); }
    size_t AccountedBytes() const { return bytes_; }
private:
    struct Cached { uint64_t Module; size_t Bytes; std::shared_ptr<Entry> Value; };
    std::list<Cached> entries_;
    size_t bytes_ = 0, maxBytes_, maxModules_;
};
