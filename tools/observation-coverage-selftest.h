#pragma once

#include "../user/ObservationModel.h"
#include <array>

inline bool ObservationCoverageSelfTest()
{
    ObservationCoverage coverage;
    coverage.Attempted = true;
    coverage.InventoryAvailable = true;
    coverage.TraversalComplete = true;
    coverage.RequestedBytes = coverage.ComparedBytes = 32;
    if (coverage.Complete())
    {
        return false;
    }
    coverage.Compared = {{0x1000, 16}, {0x1000, 16}};
    uint64_t unique = 0;
    if (coverage.Complete() || !coverage.UniqueComparedBytes(&unique) || unique != 16)
    {
        return false;
    }
    coverage.Compared = {{0x1010, 16}, {0x1000, 16}};
    if (!coverage.CompleteFor({{0x1000, 32}}) || coverage.CompleteFor({{0x2000, 32}}))
    {
        return false;
    }
    coverage.Compared = {{0x1000, 16}, {0x1020, 16}};
    if (!coverage.Complete() || coverage.CompleteFor({{0x1000, 32}}))
    {
        return false;
    }
    coverage.RangesTruncated = true;
    if (coverage.Complete())
    {
        return false;
    }
    coverage.RangesTruncated = false;
    coverage.Failed = {{0x1000, 1}};
    if (coverage.Complete())
    {
        return false;
    }
    coverage.Failed.clear();
    coverage.Skipped = {{0x1000, 1}};
    if (coverage.Complete())
    {
        return false;
    }
    coverage.Skipped.clear();
    coverage.Compared = {{UINT64_MAX - 15, 32}};
    if (coverage.Complete() || coverage.UniqueComparedBytes(&unique))
    {
        return false;
    }

    std::vector<ObservationRange> ranges;
    bool truncated = false;
    AddObservationRange(&ranges, {UINT64_MAX - 15, 8}, &truncated);
    AddObservationRange(&ranges, {UINT64_MAX - 7, 8}, &truncated);
    if (!truncated || ranges.size() != 1 || ranges[0].Size != 8)
    {
        return false;
    }
    ranges = {{0x1020, 16}, {0x1000, 16}};
    truncated = false;
    AddObservationRange(&ranges, {0x1008, 32}, &truncated);
    if (truncated || ranges.size() != 1 || ranges[0].Address != 0x1000 || ranges[0].Size != 48)
    {
        return false;
    }
    if (!NormalizeObservationRanges(ranges, &ranges, &unique) || ranges.size() != 1 || unique != 48)
    {
        return false;
    }
    ranges.clear();
    for (uint64_t i = 0; i < 257; ++i)
    {
        AddObservationRange(&ranges, {i * 4, 1}, &truncated);
    }
    if (!truncated || ranges.size() != 256)
    {
        return false;
    }
    AddObservationRange(&ranges, {0, 1024}, &truncated);
    if (!truncated || ranges.size() != 1 || ranges[0].Size != 1024)
    {
        return false;
    }

    // A byte bitmap is independent of the interval merge implementation.
    uint32_t random = 0x12345678;
    for (unsigned trial = 0; trial < 128; ++trial)
    {
        std::array<bool, 128> bitmap{};
        ranges.clear();
        truncated = false;
        for (unsigned sample = 0; sample < 64; ++sample)
        {
            random = random * 1664525u + 1013904223u;
            const auto start = random % 112;
            random = random * 1664525u + 1013904223u;
            const auto length = 1 + random % 16;
            AddObservationRange(&ranges, {start, length}, &truncated);
            for (uint32_t i = start; i < start + length; ++i)
            {
                bitmap[i] = true;
            }
        }
        std::vector<ObservationRange> normalized;
        const auto expected = static_cast<uint64_t>(std::count(bitmap.begin(), bitmap.end(), true));
        if (truncated || !NormalizeObservationRanges(ranges, &normalized, &unique) || unique != expected)
        {
            return false;
        }
        for (uint64_t i = 0; i < bitmap.size(); ++i)
        {
            const bool contained = std::any_of(ranges.begin(), ranges.end(), [i](const auto& range)
            {
                return range.Contains(i);
            });
            if (contained != bitmap[static_cast<size_t>(i)])
            {
                return false;
            }
        }
    }
    return true;
}
