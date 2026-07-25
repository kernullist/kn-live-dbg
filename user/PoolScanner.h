#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct BigPoolEntryRecord
{
    uint64_t VirtualAddress = 0;
    uint64_t SizeInBytes = 0;
    uint32_t TagRaw = 0;
    std::wstring TagText;             // 4-char printable rendering, dots for non-printable bytes
    bool     NonPaged = false;
    // Optional attribute annotation (filled only when Options.AnnotateAttributes is true).
    bool     AttributesQueried = false;
    bool     IsReadable = false;
    bool     IsWritable = false;
    bool     IsExecutable = false;
    bool     IsLargePage = false;
    uint32_t PagingLevels = 0;
    uint64_t Pte = 0;
    uint32_t ProbedLength = 0;
};

// SystemPoolTagInformation (class 0x16) covers small+big pool usage by tag.
// It does not expose allocation VAs, but it closes the "big-pool-only tag
// blindness" for hunting high NonPagedUsed tags that never appear in big pool.
struct PoolTagStatRecord
{
    uint32_t TagRaw = 0;
    std::wstring TagText;
    uint64_t PagedAllocs = 0;
    uint64_t PagedFrees = 0;
    uint64_t PagedUsed = 0;
    uint64_t NonPagedAllocs = 0;
    uint64_t NonPagedFrees = 0;
    uint64_t NonPagedUsed = 0;
};

struct PoolScanResult
{
    std::vector<BigPoolEntryRecord> Entries;
    std::vector<PoolTagStatRecord> TagStats;
    uint64_t TotalEntries = 0;        // raw count from kernel before any filtering
    uint64_t NonPagedCount = 0;
    uint64_t PagedCount = 0;
    uint64_t MatchingCount = 0;       // entries kept after filtering
    uint64_t QueryBufferBytes = 0;
    uint32_t QueryRetries = 0;
    uint64_t TagStatCount = 0;
    std::vector<std::wstring> Diagnostics;
    std::vector<std::wstring> Warnings;
    bool     PrivilegeEnabled = false;
    bool     AttributesAttempted = false;
    // Entry address list is still big-pool-only; TagStats may still be present.
    bool     BigPoolAddressViewOnly = true;
    bool     PoolTagViewAvailable = false;
};

class PoolScanner
{
public:
    enum class Scope
    {
        Big,            // list big pool entries
        Find,           // alias of Big with required tag/address/size filter
        Tags            // SystemPoolTagInformation summary (small+big usage by tag)
    };

    enum class PagedFilter
    {
        Any,
        NonPagedOnly,
        PagedOnly
    };

    struct Options
    {
        Scope        Target = Scope::Big;
        PagedFilter  Paged = PagedFilter::NonPagedOnly;
        bool         HasTagFilter = false;
        uint32_t     TagFilter = 0;          // 4-byte LE tag value (ASCII chars)
        std::wstring TagFilterText;          // printable form for diagnostics
        bool         HasMinSize = false;
        uint64_t     MinSize = 0;
        bool         HasMaxSize = false;
        uint64_t     MaxSize = 0;
        bool         HasAddressFilter = false;
        uint64_t     AddressFilter = 0;
        bool         AnnotateAttributes = false;   // walk PTE / probe pages via DeviceClient
        bool         WxOnly = false;               // requires AnnotateAttributes and keeps only effective W+X entries
        bool         IncludePoolTagSummary = false; // also fill TagStats (or sole mode for Tags scope)
        uint32_t     LimitEntries = 0;             // 0 = unlimited
        uint32_t     LimitTagStats = 0;            // 0 = default top set
    };

    PoolScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, PoolScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildPoolJson(const PoolScanResult& result);

// Helpers reused from main.cpp printer.
std::wstring FormatPoolTag(uint32_t tagRaw);
bool ParsePoolTagText(const std::wstring& text, uint32_t* tagOut);
