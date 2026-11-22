#include "EvidenceDisclosure.h"
#include "PendingIrpEvidence.h"
#include "PendingIrpClaims.h"
#include "BoundedObservationJson.h"
#include <optional>

using namespace bounded_observation_json;
namespace
{
    struct ClaimCounts
    {
        uint64_t Possible = 0, Emitted = 0, Omitted = 0;
        uint64_t Supported = 0, Contradicted = 0, Unfulfilled = 0, NotApplicable = 0;
    };
    struct IrpFacts
    {
        std::wstring Id;
        uint64_t Supplied = 0, Visited = 0, Inspected = 0, Requests = 0, Unstable = 0;
        bool Reference = false, Qualified = false, Complete = false;
        std::optional<ClaimCounts> Claims;
    };
    bool ReadCounts(const std::wstring& totals, const std::wstring& states, ClaimCounts& c)
    {
        return Number(totals, L"claims_possible", &c.Possible) && Number(totals, L"claims_emitted", &c.Emitted) &&
            Number(totals, L"claims_omitted", &c.Omitted) && Number(states, L"supported", &c.Supported) &&
            Number(states, L"contradicted", &c.Contradicted) && Number(states, L"unfulfilled", &c.Unfulfilled) &&
            Number(states, L"not_applicable", &c.NotApplicable);
    }
    std::wstring Json(const IrpFacts& f)
    {
        if (f.Id.size() != 32 || f.Id.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
            f.Supplied > 16384 || f.Visited > f.Supplied || f.Visited > 128 || f.Inspected > 256 ||
            (!f.Visited && f.Inspected) || f.Requests > f.Inspected || f.Unstable > 3 * f.Visited + f.Inspected ||
            (f.Qualified && !f.Reference) || (f.Complete && (!f.Qualified || f.Visited != f.Supplied))) { return {}; }
        std::wstring claims = L"null";
        if (f.Claims)
        {
            // Original registry v1 evaluates four predicates per request and three per retained stack entry.
            const auto& c = *f.Claims;
            if (c.Possible < 4 * f.Requests || c.Possible > (4 + 3 * 64) * f.Requests ||
                (c.Possible - 4 * f.Requests) % 3 != 0 || c.Emitted > PendingIrpClaimLimit || c.Emitted > c.Possible ||
                c.Omitted != c.Possible - c.Emitted || c.Supported > c.Emitted || c.Contradicted > c.Emitted ||
                c.Unfulfilled > c.Emitted || c.NotApplicable > c.Emitted ||
                c.Supported + c.Contradicted + c.Unfulfilled + c.NotApplicable != c.Emitted) { return {}; }
            claims = L"{\"claims_possible\":" + N(c.Possible) + L",\"claims_emitted\":" + N(c.Emitted) + L",\"claims_omitted\":" + N(c.Omitted) +
                L",\"supported\":" + N(c.Supported) + L",\"contradicted\":" + N(c.Contradicted) + L",\"unfulfilled\":" + N(c.Unfulfilled) +
                L",\"not_applicable\":" + N(c.NotApplicable) + L"}";
        }
        return L"{\"schema\":\"kn.minimized_irp_facts.v1\",\"policy\":\"kn.irp_counts_redaction.v1\",\"redaction_id\":" + mcpjson::Quote(f.Id) +
            L",\"scope\":\"supplied_thread_inventory\",\"supplied_threads\":" + N(f.Supplied) + L",\"threads_visited\":" + N(f.Visited) +
            L",\"irps_inspected\":" + N(f.Inspected) + L",\"requests_retained\":" + N(f.Requests) + L",\"unstable_observations\":" + N(f.Unstable) +
            L",\"reference_verified\":" + B(f.Reference) + L",\"qualified_replay\":" + B(f.Qualified) +
            L",\"complete_for_supplied_inventory\":" + B(f.Complete) + L",\"recorded_claims\":" + claims +
            L",\"time_scope\":\"historical_non_atomic\",\"global_inventory\":false,\"referenced_request_lifetime\":false,"
            L"\"execution_observed\":false,\"collector_authenticated\":false,\"maliciousness\":\"not_established\"}";
    }
}

std::wstring ProjectIrpDisclosure(const PendingIrpReplay& replay, const std::wstring& originalReport, const std::wstring& id)
{
    if (replay.Status != L"replayed" || !replay.SummaryMatched) { return {}; }
    IrpFacts f;
    f.Id = id; f.Supplied = replay.SuppliedThreads;
    const auto& r = replay.Recomputed;
    f.Visited = r.ThreadsVisited; f.Inspected = r.IrpsInspected; f.Requests = r.Requests.size(); f.Unstable = r.UnstableObservations;
    f.Reference = replay.ReferenceStatus == L"verified"; f.Qualified = replay.QualifiedObservation; f.Complete = r.CoverageComplete && f.Qualified;
    if (replay.OriginalClaimStatus == L"reproduced")
    {
        IndexedObject report;
        std::wstring states;
        if (originalReport.size() > PendingIrpClaimMaximumCharacters || !report.Parse(originalReport) ||
            report.String(L"evaluation_mode") != L"capture_time_policy" || report.String(L"capture_sha256") != replay.OriginalCaptureSha256 ||
            DisclosureTextSha256(originalReport) != replay.RecordedClaimSha256 || !report.Raw(L"counts", &states) ||
            !ReadCounts(report.Metadata({L"ledgers", L"policy_registry", L"claims"}), states, f.Claims.emplace())) { return {}; }
    }
    else if (replay.OriginalClaimStatus != L"not_recorded" || !originalReport.empty() || !replay.RecordedClaimSha256.empty()) { return {}; }
    return Json(f);
}

bool ParseMinimizedIrpFacts(const std::wstring& json, DisclosureFactsIdentity* identity)
{
    IndexedObject root;
    std::wstring counts;
    IrpFacts f;
    if (!identity || json.size() > 4096 || !root.Parse(json)) { return false; }
    f.Id = root.String(L"redaction_id");
    if (!Number(json, L"supplied_threads", &f.Supplied) || !Number(json, L"threads_visited", &f.Visited) ||
        !Number(json, L"irps_inspected", &f.Inspected) || !Number(json, L"requests_retained", &f.Requests) ||
        !Number(json, L"unstable_observations", &f.Unstable) || !Boolean(json, L"reference_verified", &f.Reference) ||
        !Boolean(json, L"qualified_replay", &f.Qualified) || !Boolean(json, L"complete_for_supplied_inventory", &f.Complete) ||
        !root.Raw(L"recorded_claims", &counts) || (counts != L"null" && !ReadCounts(counts, counts, f.Claims.emplace())) ||
        Json(f) != json) { return false; }
    *identity = {std::move(f.Id), DisclosureFamily::Irp, f.Claims.has_value()};
    return true;
}
