#pragma once

#include "EvidenceInventory.h"
#include <map>
#include <set>

namespace inventory_closure
{
    // Up to 1,048,576 v1 ledgers can each report a full uint64_t count.
    class ExactTotal
    {
    public:
        void Add(uint64_t value)
        {
            High += value / Base;
            Low += value % Base;
            if (Low >= Base) { Low -= Base; ++High; }
        }

        std::wstring Decimal() const
        {
            const auto low = std::to_wstring(Low);
            return High ? std::to_wstring(High) + std::wstring(18 - low.size(), L'0') + low : low;
        }

    private:
        static constexpr uint64_t Base = 1000000000000000000ull;
        uint64_t High = 0, Low = 0;
    };

    class Publications
    {
    public:
        EvidenceInventoryClosureCounts Counts;

        void AddCase(const std::wstring& digest, const std::wstring& collection, size_t canonicalBytes)
        {
            ++Counts.CaseFiles;
            if (!CaseDigests.insert(digest).second) { return; }
            ++Counts.UniqueCases;
            if (collection.empty()) { ++Counts.UnattributedCases; }
            else
            {
                auto& row = Collections[collection];
                ++row.Cases;
                row.CanonicalBytes += canonicalBytes;
            }
        }

        void AddLedger(const std::wstring& digest, const EvidenceSessionSummary& ledger)
        {
            ++Counts.LedgerFiles;
            if (!LedgerDigests.insert(digest).second) { ++Counts.DuplicateLedgers; return; }
            auto& collection = Collections[ledger.CollectionId];
            if (collection.Ledger) { collection.Conflict = true; }
            else { collection.Ledger = ledger; }
        }

        template<typename Running>
        bool Finish(Running running)
        {
            ExactTotal admitted, failed, dropped;
            for (const auto& item : Collections)
            {
                if (!running()) { return false; }
                const auto& collection = item.second;
                if (collection.Conflict) { ++Counts.ConflictingCollections; continue; }
                if (!collection.Ledger) { ++Counts.CollectionsWithoutLedger; continue; }
                const auto& ledger = *collection.Ledger;
                ++Counts.UnambiguousCollections;
                admitted.Add(ledger.Admitted);
                failed.Add(ledger.Failed);
                dropped.Add(ledger.Dropped);
                // The canonical v1 parser bounds both written and bytes to 128 MiB per ledger.
                Counts.Written += ledger.Written;
                Counts.PublishedBytes += ledger.Bytes;
                Counts.ObservedCanonicalBytes += collection.CanonicalBytes;
                if (collection.CanonicalBytes != ledger.Bytes) { ++Counts.ByteMismatchCollections; }
                if (ledger.Written > collection.Cases) { Counts.MissingWritten += ledger.Written - collection.Cases; }
                else { Counts.UnexpectedCases += collection.Cases - ledger.Written; }
            }
            Counts.Admitted = admitted.Decimal();
            Counts.Failed = failed.Decimal();
            Counts.Dropped = dropped.Decimal();
            Counts.ClosureKnown = Counts.UnambiguousCollections != 0 && !Counts.ConflictingCollections &&
                !Counts.CollectionsWithoutLedger && !Counts.UnattributedCases && !Counts.MissingWritten &&
                !Counts.UnexpectedCases && !Counts.ByteMismatchCollections && !Counts.InvalidAtBuild && !Counts.ChangedOrMissing;
            return true;
        }

    private:
        struct Collection
        {
            uint64_t Cases = 0, CanonicalBytes = 0;
            std::optional<EvidenceSessionSummary> Ledger;
            bool Conflict = false;
        };
        std::set<std::wstring> CaseDigests, LedgerDigests;
        std::map<std::wstring, Collection> Collections;
    };
}
