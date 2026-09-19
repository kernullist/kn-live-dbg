#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>

enum class CodeOwnership
{
    Unknown,
    OwnedUnverified,
    OwnedVerified,
    OwnedModified,
    UnownedExecutable,
    OwnedUnexpectedExecutable
};

inline const wchar_t* CodeOwnershipName(CodeOwnership state)
{
    switch (state)
    {
    case CodeOwnership::OwnedUnverified:
        return L"owned_unverified";
    case CodeOwnership::OwnedVerified:
        return L"owned_verified";
    case CodeOwnership::OwnedModified:
        return L"owned_modified";
    case CodeOwnership::UnownedExecutable:
        return L"unowned_executable";
    case CodeOwnership::OwnedUnexpectedExecutable:
        return L"owned_unexpected_executable";
    default:
        return L"unknown";
    }
}

struct ObservationIdentity
{
    std::wstring BootId;
    uint32_t ProcessId = 0;
    uint64_t CreateTime = 0;
    uint64_t Eprocess = 0;
    uint32_t SessionId = 0;
    bool SessionKnown = false;

    bool SameInstance(const ObservationIdentity& other) const
    {
        return !BootId.empty() && BootId == other.BootId && ProcessId == other.ProcessId &&
            (ProcessId == 0 || (CreateTime != 0 && CreateTime == other.CreateTime)) &&
            (Eprocess == 0 || other.Eprocess == 0 || Eprocess == other.Eprocess) &&
            (!SessionKnown || !other.SessionKnown || SessionId == other.SessionId);
    }
};

struct ObservationRange
{
    uint64_t Address = 0;
    uint64_t Size = 0;

    bool Contains(uint64_t address) const
    {
        return Size != 0 && Address <= UINT64_MAX - Size &&
            address >= Address && address - Address < Size;
    }

    bool Overlaps(const ObservationRange& other) const
    {
        return Size != 0 && other.Size != 0 && Address <= UINT64_MAX - Size &&
            other.Address <= UINT64_MAX - other.Size &&
            Address < other.Address + other.Size && other.Address < Address + Size;
    }
};

struct ObservationCoverage
{
    uint64_t RequestedBytes = 0;
    uint64_t ComparedBytes = 0;
    uint64_t FailedBytes = 0;
    uint64_t SkippedBytes = 0;
    uint64_t ResumeAddress = 0;
    uint64_t LostEvents = 0;
    bool Attempted = false;
    bool TraversalComplete = false;
    bool InventoryAvailable = false;
    std::wstring Reason = L"not_measured";
    std::vector<ObservationRange> Compared;
    std::vector<ObservationRange> Failed;
    std::vector<ObservationRange> Skipped;
    bool RangesTruncated = false;

    bool Complete() const
    {
        return Attempted && TraversalComplete && InventoryAvailable && LostEvents == 0 &&
            FailedBytes == 0 && SkippedBytes == 0 && RequestedBytes != 0 &&
            ComparedBytes == RequestedBytes;
    }

    const wchar_t* Status() const
    {
        return !Attempted ? L"unknown" : (Complete() ? L"complete" : L"partial");
    }
};

inline void AddObservationRange(std::vector<ObservationRange>* ranges, ObservationRange range, bool* truncated)
{
    if (range.Size == 0)
    {
        return;
    }
    if (!ranges->empty() && ranges->back().Address <= UINT64_MAX - ranges->back().Size &&
        ranges->back().Address + ranges->back().Size == range.Address)
    {
        ranges->back().Size += range.Size;
    }
    else if (ranges->size() < 256)
    {
        ranges->push_back(range);
    }
    else
    {
        *truncated = true;
    }
}

enum class ObservationRelation
{
    Object,
    Address,
    Content,
    PhysicalPage,
    Temporal
};

inline const wchar_t* ObservationRelationName(ObservationRelation relation)
{
    switch (relation)
    {
    case ObservationRelation::Object:
        return L"object";
    case ObservationRelation::Address:
        return L"address";
    case ObservationRelation::Content:
        return L"content";
    case ObservationRelation::PhysicalPage:
        return L"physical_page";
    default:
        return L"temporal";
    }
}

struct ObservationContext
{
    ObservationIdentity Identity;
    ObservationCoverage Coverage;
    uint64_t Timestamp = 0;
    uint64_t MonotonicMs = 0;
    uint64_t MappingGeneration = 0;
    uint64_t AllocationBase = 0;
    uint64_t Pfn = 0;
    bool PfnKnown = false;
    std::wstring Source;
    std::wstring DependencyGroup;
    std::wstring ReferenceSource;
    CodeOwnership Ownership = CodeOwnership::Unknown;
};

inline void AppendObservationEvidence(
    const ObservationContext& context, std::map<std::wstring, std::wstring>* evidence)
{
    if (evidence != nullptr)
    {
        // Existing producer-specific evidence takes precedence over defaults.
        evidence->emplace(L"observation_schema", L"kmon.observation.v1");
        evidence->emplace(L"boot_id", context.Identity.BootId.empty() ? L"unknown" : context.Identity.BootId);
        evidence->emplace(L"process_create_time", std::to_wstring(context.Identity.CreateTime));
        evidence->emplace(L"eprocess", std::to_wstring(context.Identity.Eprocess));
        evidence->emplace(L"session_id", context.Identity.SessionKnown ?
            std::to_wstring(context.Identity.SessionId) : L"unknown");
        evidence->emplace(L"observed_at", std::to_wstring(context.Timestamp));
        evidence->emplace(L"observed_tick_ms", std::to_wstring(context.MonotonicMs));
        evidence->emplace(L"source", context.Source.empty() ? L"unspecified" : context.Source);
        evidence->emplace(L"dependency_group", context.DependencyGroup.empty() ? L"unspecified" : context.DependencyGroup);
        evidence->emplace(L"mapping_generation", std::to_wstring(context.MappingGeneration));
        evidence->emplace(L"ownership", CodeOwnershipName(context.Ownership));
        evidence->emplace(L"reference_source", context.ReferenceSource.empty() ? L"unverified" : context.ReferenceSource);
        evidence->emplace(L"coverage_status", context.Coverage.Status());
        evidence->emplace(L"coverage_reason", context.Coverage.Reason);
        evidence->emplace(L"requested_bytes", std::to_wstring(context.Coverage.RequestedBytes));
        evidence->emplace(L"compared_bytes", std::to_wstring(context.Coverage.ComparedBytes));
        evidence->emplace(L"failed_bytes", std::to_wstring(context.Coverage.FailedBytes));
        evidence->emplace(L"skipped_bytes", std::to_wstring(context.Coverage.SkippedBytes));
        evidence->emplace(L"ranges_truncated", context.Coverage.RangesTruncated ? L"true" : L"false");
        const auto serializeRanges = [&](const wchar_t* key, const std::vector<ObservationRange>& ranges)
        {
            std::wstring text;
            for (const auto& range : ranges)
            {
                if (!text.empty())
                {
                    text += L",";
                }
                text += std::to_wstring(range.Address) + L":" + std::to_wstring(range.Size);
            }
            evidence->emplace(key, std::move(text));
        };
        serializeRanges(L"compared_ranges", context.Coverage.Compared);
        serializeRanges(L"failed_ranges", context.Coverage.Failed);
        serializeRanges(L"skipped_ranges", context.Coverage.Skipped);
        evidence->emplace(L"resume_address", std::to_wstring(context.Coverage.ResumeAddress));
        evidence->emplace(L"lost_events", std::to_wstring(context.Coverage.LostEvents));
    }
}

inline bool ObservationModelSelfTest()
{
    ObservationIdentity first;
    first.BootId = L"boot";
    first.ProcessId = 100;
    first.CreateTime = 1;
    ObservationIdentity reused = first;
    reused.CreateTime = 2;
    bool ok = first.SameInstance(first) && !first.SameInstance(reused);
    reused = first;
    reused.BootId.clear();
    ok = ok && !first.SameInstance(reused);
    ObservationCoverage coverage;
    ok = ok && !coverage.Complete();
    coverage.Attempted = true;
    coverage.InventoryAvailable = true;
    coverage.TraversalComplete = true;
    coverage.RequestedBytes = 4096;
    coverage.ComparedBytes = 256;
    ok = ok && !coverage.Complete();
    coverage.ComparedBytes = 4096;
    ok = ok && coverage.Complete();
    coverage.LostEvents = 1;
    ok = ok && !coverage.Complete();
    coverage.LostEvents = 0;
    coverage.FailedBytes = 1;
    ok = ok && !coverage.Complete();
    return ok;
}
