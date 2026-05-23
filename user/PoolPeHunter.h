#pragma once

#include "DeviceClient.h"
#include "MemoryDumper.h"

#include <cstdint>
#include <string>
#include <vector>

struct PoolPeHit
{
    uint64_t Address = 0;
    uint64_t SizeInBytes = 0;
    uint32_t TagRaw = 0;
    std::wstring TagText;
    bool     NonPaged = false;
    PeHeaderProbe Probe;
    std::wstring DumpedPath;          // populated when /dump produced a file
    bool     DumpSucceeded = false;
};

struct PoolPeHunterResult
{
    std::vector<PoolPeHit> Hits;
    uint64_t TotalEntries = 0;        // raw entries from kernel
    uint64_t NonPagedCount = 0;
    uint64_t PagedCount = 0;
    uint64_t Scanned = 0;             // entries passed to ProbeForPeHeader
    uint64_t ReadFailures = 0;        // entries whose head bytes could not be read
    uint64_t SuspiciousWipes = 0;     // hits where any signature was wiped
    uint64_t QueryBufferBytes = 0;
    uint32_t QueryRetries = 0;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> Diagnostics;
    bool     PrivilegeEnabled = false;
};

class PoolPeHunter
{
public:
    enum class PagedFilter
    {
        NonPagedOnly,
        PagedOnly,
        Any
    };

    struct Options
    {
        PagedFilter Paged = PagedFilter::NonPagedOnly;
        bool         HasTagFilter = false;
        uint32_t     TagFilter = 0;
        std::wstring TagFilterText;
        bool         HasMinSize = false;
        uint64_t     MinSize = 0x1000;     // PE images take at least one page
        bool         HasMaxSize = false;
        uint64_t     MaxSize = 0;
        uint32_t     LimitHits = 0;         // 0 = unlimited
        std::wstring DumpDirectory;         // optional: dump each hit
        bool         DumpEnabled = false;
        bool         OnlySuspicious = false; // only report hits with wiped signatures
    };

    PoolPeHunter(DeviceClient& device);

    bool Scan(const Options& options, PoolPeHunterResult* result, std::wstring* error);

private:
    DeviceClient& device_;
};
