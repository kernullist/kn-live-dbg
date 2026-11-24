#include "CollectionRetentionBudget.h"
#include "BoundedObservationJson.h"
#include "EvidenceStore.h"
#include <algorithm>
#include <map>
#include <tuple>
#include <vector>

using namespace bounded_observation_json;
namespace
{
    using Priority = CollectionPriority;
    constexpr const wchar_t* Names[] = {L"first_observation", L"observation_gap", L"unclassified", L"routine_only", L"empty"};
    constexpr size_t Index(Priority p) { return static_cast<size_t>(p); }

    // The image producer writes outer counters as numbers. IRP and all lane
    // counters use decimal strings. Accept only the producer's canonical form.
    bool Counter(const IndexedObject& obj, const wchar_t* key, bool quoted, uint64_t& value)
    {
        std::wstring raw;
        if (!obj.Raw(key, &raw)) { return false; }
        const auto digits = quoted ? obj.String(key) : raw;
        if (digits.empty() || digits.size() > 20 || (digits.size() > 1 && digits[0] == L'0')) { return false; }
        value = 0;
        for (const auto c : digits)
        {
            if (c < L'0' || c > L'9' || value > (UINT64_MAX - (c - L'0')) / 10) { return false; }
            value = value * 10 + (c - L'0');
        }
        return !quoted || raw == N(value);
    }
    Priority Lane(const std::wstring& name, bool irp)
    {
        if (name == (irp ? L"first_observed_state" : L"first_difference")) { return Priority::First; }
        if (name == L"observation_gap") { return Priority::Gap; }
        if (name == (irp ? L"repeat_or_empty" : L"repeat_or_clean")) { return Priority::Routine; }
        return Priority::Unknown;
    }
    bool Accumulate(uint64_t amount, uint64_t& sum)
    {
        if (amount > UINT64_MAX - sum) { return false; }
        sum += amount;
        return true;
    }
    std::wstring Usage(const CollectionRetentionUsage& usage)
    { return L"\"paths\":" + N(usage.Paths) + L",\"named_bytes\":" + N(usage.Bytes); }

    bool NumericIdBefore(const std::wstring& left, const std::wstring& right)
    { return left.size() < right.size() || (left.size() == right.size() && left < right); }

    void ClassifySourceCopies(EvidenceStoreInventory& store)
    {
        using Files = std::tuple<std::wstring, std::wstring, std::wstring>;
        std::map<Files, std::vector<EvidenceStoreCollection*>> groups;
        for (auto& c : store.Collections)
        {
            const auto& files = c.Retention.Source;
            if (!files.ReportSha256.empty())
                { groups[{files.ReportSha256, files.ClaimFileSha256, files.ReferenceSha256}].push_back(&c); }
        }
        for (const auto& group : groups)
        {
            const auto& copies = group.second;
            const auto* keeper = *std::min_element(copies.begin(), copies.end(), [](const auto* a, const auto* b)
                { return NumericIdBefore(a->Id, b->Id); });
            for (auto* copy : copies)
            {
                auto& root = copy->Retention;
                root.Source.RetainedCollectionId = keeper->Id;
                root.Source.ActiveCopies = copies.size();
                if (copy != keeper && root.Priority != Priority::Unknown) { root.Priority = Priority::Routine; }
            }
        }
    }

    std::wstring SourceCopyJson(const ImageSourceRetention& s)
    {
        if (s.RetainedCollectionId.empty()) { return {}; }
        const auto digest = [](const std::wstring& pin) { return pin.empty() ? L"null" : mcpjson::Quote(pin); };
        return L",\"source_copies\":{\"report_sha256\":" + mcpjson::Quote(s.ReportSha256) +
            L",\"claim_file_sha256\":" + digest(s.ClaimFileSha256) + L",\"reference_sha256\":" + digest(s.ReferenceSha256) +
            L",\"retained_collection_id\":" + mcpjson::Quote(s.RetainedCollectionId) +
            L",\"active_copies\":" + N(s.ActiveCopies) + L"}";
    }
}

CollectionPriority ReadImageTicketPriority(const std::wstring& json)
{
    IndexedObject ticket;
    std::wstring unkeyed;
    uint64_t keys = 0;
    if (!ticket.Parse(json) || ticket.String(L"scope") != L"recording_session" ||
        ticket.String(L"policy") != L"kn.image_retention_partition.v1" || !Counter(ticket, L"difference_keys", true, keys) ||
        !ticket.Raw(L"unkeyed_difference", &unkeyed) || (unkeyed != L"true" && unkeyed != L"false")) { return Priority::Unknown; }
    const auto kind = Lane(ticket.String(L"class"), false);
    if (kind == Priority::Routine && (keys || unkeyed == L"true")) { return Priority::Unknown; }
    return kind;
}

CollectionPriority ReadImageSourcePriority(const std::wstring& status, const std::wstring& result)
{
    if (status == L"failed" || status == L"interrupted") { return Priority::Gap; }
    IndexedObject page;
    uint64_t requested = 0, compared = 0, skipped = 0, failed = 0;
    if (status != L"recorded" || !page.Parse(result) ||
        !Counter(page, L"requested_bytes", true, requested) || !requested || requested > 4096 ||
        !Counter(page, L"compared_bytes", true, compared) || compared > requested ||
        !Counter(page, L"skipped_bytes", true, skipped) || skipped > requested - compared ||
        !Counter(page, L"failed_bytes", true, failed) || failed > requested - compared - skipped) { return Priority::Unknown; }
    bool full = compared == requested;
    constexpr std::pair<const wchar_t*, const wchar_t*> required[] = {
        {L"reference_qualified", L"true"}, {L"attempted", L"true"}, {L"inventory_available", L"true"},
        {L"traversal_complete", L"true"}, {L"ranges_truncated", L"false"}};
    for (const auto& [key, expected] : required)
    {
        std::wstring flag;
        if (!page.Raw(key, &flag) || (flag != L"true" && flag != L"false")) { return Priority::Unknown; }
        if (flag != expected) { full = false; }
    }
    const auto ownership = page.String(L"ownership");
    if (ownership == L"owned_unverified") { return Priority::Gap; }
    if (ownership != L"owned_verified" && ownership != L"owned_modified") { return Priority::Unknown; }
    return full ? Priority::First : Priority::Gap;
}

CollectionPriority ReadLedgerPriority(const std::wstring& json, const std::wstring& id, bool irp,
    uint64_t transactions, uint64_t sweeps, const std::array<uint64_t, 5>& tickets)
{
    IndexedObject ledger, partition;
    std::wstring saved;
    std::vector<std::wstring> rows;
    if (!ledger.Parse(json) || ledger.String(L"collection_id") != id || !ledger.Raw(L"retention", &saved) || !partition.Parse(saved) ||
        partition.String(L"schema") != (irp ? L"kn.irp_retention.v1" : L"kn.image_retention.v1") ||
        partition.String(L"policy") != (irp ? L"kn.irp_retention_partition.v1" : L"kn.image_retention_partition.v1") ||
        partition.String(L"scope") != L"recording_session" || !partition.Rows(L"classes", 3, &rows) || rows.size() != 3) { return Priority::Unknown; }
    std::array<bool, 5> seen{};
    uint64_t completions = 0;
    bool first = false, gap = false;
    for (const auto& row : rows)
    {
        IndexedObject lane;
        if (!lane.Parse(row)) { return Priority::Unknown; }
        const auto kind = Lane(lane.String(L"class"), irp);
        const auto index = Index(kind);
        uint64_t attempted = 0, admitted = 0, finished = 0, complete = 0, abandoned = 0, flight = 0;
        if (kind == Priority::Unknown || seen[index] || !Counter(lane, L"attempted", true, attempted) ||
            !Counter(lane, L"admitted", true, admitted) || !Counter(lane, L"finished", true, finished) ||
            !Counter(lane, L"complete", true, complete) || !Counter(lane, L"abandoned", true, abandoned) ||
            !Counter(lane, L"in_flight", true, flight) || attempted < admitted || admitted < finished || finished < complete ||
            abandoned > admitted - finished || flight != admitted - finished - abandoned || !Accumulate(complete, completions)) { return Priority::Unknown; }
        seen[index] = true;
        uint64_t denied = 0;
        const auto losses = [&](std::initializer_list<const wchar_t*> fields)
        {
            for (auto key : fields)
            {
                uint64_t count = 0;
                if (!Counter(lane, key, true, count) || !Accumulate(count, denied)) { return false; }
            }
            return true;
        };
        if (!losses({L"slot_denied", L"key_denied", L"preparation_denied"}) ||
            !(irp ? losses({L"memory_denied", L"unavailable", L"invalid"}) : losses({L"reference_denied"})) ||
            denied != attempted - admitted) { return Priority::Unknown; }
        first |= kind == Priority::First && attempted != 0;
        gap |= (kind == Priority::Gap && attempted != 0) || attempted != complete;
    }
    const auto matches = [&](const wchar_t* key, uint64_t expected)
    {
        uint64_t count = 0;
        if (!Counter(ledger, key, irp, count)) { return false; }
        gap |= count != expected;
        return true;
    };
    if (!matches(L"queued", transactions) || !matches(L"written", transactions) ||
        !matches(irp ? L"journal_captures_committed" : L"journal_read_batches_committed", transactions)) { return Priority::Unknown; }
    const auto zeros = [&](std::initializer_list<const wchar_t*> fields)
    {
        return std::all_of(fields.begin(), fields.end(), [&](const auto key) { return matches(key, 0); });
    };
    if (!zeros({L"failed", L"dropped", L"pending"}) ||
        (irp ? !zeros({L"unavailable", L"claims_unavailable", L"reserved_bytes", L"references_failed", L"journal_captures_failed"}) :
            !zeros({L"reference_blobs_failed", L"reference_reserved_bytes", L"reference_captures_missing", L"slice_recipes_failed",
                L"slice_recipes_unavailable", L"slice_claims_unavailable", L"sweep_claims_unavailable", L"sweep_manifests_failed",
                L"sweep_manifest_pending", L"sweep_manifest_admission_denied_slices", L"sweep_manifest_entry_drops", L"sweep_metadata_failures",
                L"journal_read_batches_failed", L"journal_sweeps_failed", L"journal_index_failures_before_closure", L"store_admission_failures"})))
        { return Priority::Unknown; }
    if (irp)
    {
        if (!matches(L"claims_written", transactions)) { return Priority::Unknown; }
    }
    else
    {
        if (!matches(L"slice_recipes_queued", transactions) || !matches(L"slice_recipes_written", transactions) ||
            !matches(L"slice_claims_written", transactions) || !matches(L"sweep_claims_written", sweeps) ||
            !matches(L"journal_sweeps_committed", sweeps) || !matches(L"sweeps_started", sweeps) ||
            !matches(L"sweep_terminals_observed", sweeps) || !matches(L"sweep_manifests_written", sweeps)) { return Priority::Unknown; }
        first |= tickets[Index(Priority::First)] != 0;
        gap |= tickets[Index(Priority::Gap)] != 0;
        if (!first && !gap && (tickets[Index(Priority::Unknown)] || tickets[Index(Priority::Routine)] != transactions ||
            (!transactions && sweeps))) { return Priority::Unknown; }
    }
    if (first) { return Priority::First; }
    if (gap || completions != transactions) { return Priority::Gap; }
    return transactions ? Priority::Routine : Priority::Empty;
}

CollectionPriority CombineCollectionPriority(CollectionPriority a, CollectionPriority b)
{ return (std::min)(a, b); }

void AccountCollectionRetention(EvidenceStoreInventory& store)
{
    ClassifySourceCopies(store);
    std::map<std::wstring, CollectionRetentionRoot*> roots;
    for (auto& c : store.Collections)
        { if (c.Recovery.Status == L"verified_prefix" && c.Recovery.Closed) { roots.emplace(c.Id, &c.Retention); } }
    for (const auto& a : store.Artifacts)
    {
        for (const auto& owner : a.Collections)
        {
            auto& p = roots.at(owner)->Priority;
            if (p == Priority::Empty && a.Retention != L"failure_ledger_protected") { p = Priority::Unknown; }
            if (a.IrpCatalog == L"inputs_incomplete" || a.IrpCatalog == L"not_captured") { p = CombineCollectionPriority(p, Priority::Gap); }
            else if (!a.IrpCatalog.empty() && a.IrpCatalog != L"resolved")
                { p = CombineCollectionPriority(p, Priority::Unknown); }
        }
    }
    for (const auto& a : store.Artifacts)
    {
        if (a.Collections.empty()) { continue; }
        auto* usage = &store.Budget.Ledgers;
        if (a.Retention != L"failure_ledger_protected")
        {
            auto priority = Priority::Empty;
            for (const auto& owner : a.Collections) { priority = CombineCollectionPriority(priority, roots.at(owner)->Priority); }
            usage = &store.Budget.ByPriority[Index(priority)];
            if (priority == Priority::Routine)
            {
                for (const auto& owner : a.Collections) { ++roots.at(owner)->RoutinePaths; }
                if (a.Collections.size() == 1) { roots.at(a.Collections.front())->ExclusiveRoutineBytes += a.Artifact.Bytes; }
            }
        }
        ++usage->Paths; usage->Bytes += a.Artifact.Bytes;
    }
}

const EvidenceStoreCollection* SelectRoutineRetirement(const EvidenceStoreInventory& store, uint64_t target, uint64_t age, uint64_t cap)
{
    if (!store.Budget.Observed || store.Budget.ByPriority[Index(Priority::Routine)].Bytes <= target) { return nullptr; }
    const EvidenceStoreCollection* best = nullptr;
    for (const auto& c : store.Collections)
    {
        const auto& r = c.Retention;
        if (c.Recovery.Status != L"verified_prefix" || !c.Recovery.Closed || r.Priority != Priority::Routine ||
            !r.ExclusiveRoutineBytes || r.ExclusiveRoutineBytes > cap || !r.ClosureWritten || store.Budget.Observed < r.ClosureWritten ||
            (store.Budget.Observed - r.ClosureWritten) / 10000000 < age) { continue; }
        if (!best || r.ClosureWritten < best->Retention.ClosureWritten || (r.ClosureWritten == best->Retention.ClosureWritten &&
            NumericIdBefore(c.Id, best->Id))) { best = &c; }
    }
    return best;
}

std::wstring CollectionRetentionBudgetJson(const EvidenceStoreInventory& store)
{
    if (!store.Budget.Observed)
        { return L"{\"schema\":\"kn.evidence_collection_retention.v1\",\"status\":\"unavailable\",\"classes\":[],\"roots\":[]}"; }
    std::wstring lanes = L"[", roots = L"[";
    for (size_t i = 0; i < store.Budget.ByPriority.size(); ++i)
    {
        if (i) { lanes += L","; }
        lanes += L"{\"class\":" + mcpjson::Quote(Names[i]) + L"," + Usage(store.Budget.ByPriority[i]) + L"}";
    }
    for (const auto& c : store.Collections)
    {
        if (c.Recovery.Status != L"verified_prefix" || !c.Recovery.Closed) { continue; }
        if (roots.size() > 1) { roots += L","; }
        const auto& r = c.Retention;
        roots += L"{\"collection_id\":" + mcpjson::Quote(c.Id) + L",\"class\":" + mcpjson::Quote(Names[Index(r.Priority)]) +
            L",\"closure_last_write_filetime\":" + N(r.ClosureWritten) + L",\"routine_paths\":" + N(r.RoutinePaths) +
            L",\"exclusive_routine_bytes\":" + N(r.ExclusiveRoutineBytes) + SourceCopyJson(r.Source) + L"}";
    }
    return L"{\"schema\":\"kn.evidence_collection_retention.v1\",\"status\":\"verified\",\"observed_filetime\":" + N(store.Budget.Observed) +
        L",\"classes\":" + lanes + L"],\"failure_ledgers\":{" + Usage(store.Budget.Ledgers) + L"},\"roots\":" + roots + L"]}";
}
