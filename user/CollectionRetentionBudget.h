#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

enum class CollectionPriority : std::size_t { First, Gap, Unknown, Routine, Empty };
struct ImageSourceRetention
{
    std::wstring ReportSha256, ClaimFileSha256, ReferenceSha256, RetainedCollectionId;
    uint64_t ActiveCopies = 0;
};
struct CollectionRetentionRoot
{
    CollectionPriority Priority = CollectionPriority::Unknown;
    uint64_t ClosureWritten = 0, RoutinePaths = 0, ExclusiveRoutineBytes = 0;
    ImageSourceRetention Source;
};
struct CollectionRetentionUsage { uint64_t Paths = 0, Bytes = 0; };
struct CollectionRetentionBudget
{
    uint64_t Observed = 0;
    std::array<CollectionRetentionUsage, 5> ByPriority{};
    CollectionRetentionUsage Ledgers;
};
struct EvidenceStoreInventory;
struct EvidenceStoreCollection;

CollectionPriority ReadImageTicketPriority(const std::wstring& json);
CollectionPriority ReadImageSourcePriority(const std::wstring& status, const std::wstring& result);
CollectionPriority ReadLedgerPriority(const std::wstring& json, const std::wstring& id, bool irp,
    uint64_t transactions, uint64_t sweeps, const std::array<uint64_t, 5>& imageTickets);
CollectionPriority CombineCollectionPriority(CollectionPriority a, CollectionPriority b);
void AccountCollectionRetention(EvidenceStoreInventory& store);
const EvidenceStoreCollection* SelectRoutineRetirement(const EvidenceStoreInventory& store, uint64_t target,
    uint64_t minimumAgeSeconds, uint64_t exclusiveByteLimit);
std::wstring CollectionRetentionBudgetJson(const EvidenceStoreInventory& store);
