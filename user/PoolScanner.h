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

struct PoolScanResult
{
    std::vector<BigPoolEntryRecord> Entries;
    uint64_t TotalEntries = 0;        // raw count from kernel before any filtering
    uint64_t NonPagedCount = 0;
    uint64_t PagedCount = 0;
    uint64_t MatchingCount = 0;       // entries kept after filtering
    uint64_t QueryBufferBytes = 0;
    uint32_t QueryRetries = 0;
    std::vector<std::wstring> Diagnostics;
    std::vector<std::wstring> Warnings;
    bool     PrivilegeEnabled = false;
    bool     AttributesAttempted = false;
};

class PoolScanner
{
public:
    enum class Scope
    {
        Big,            // list big pool entries
        Find            // alias of Big with required tag/address/size filter
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
        uint32_t     LimitEntries = 0;             // 0 = unlimited
    };

    PoolScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, PoolScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

// Helpers reused from main.cpp printer.
std::wstring FormatPoolTag(uint32_t tagRaw);
bool ParsePoolTagText(const std::wstring& text, uint32_t* tagOut);
