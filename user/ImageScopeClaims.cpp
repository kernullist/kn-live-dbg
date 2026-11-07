#include "ImageScopeClaims.h"
#include "ClaimPolicy.h"
#include "BoundedObservationJson.h"
#include <array>
#include <set>

using namespace bounded_observation_json;
using namespace claim_policy;
namespace
{
    bool Digest(const std::wstring& value) { return Evidence{value, L"/payload"}.Valid(); }
    std::wstring Ref(const std::wstring& digest, const std::wstring& pointer)
    { return L"{\"capture_sha256\":" + mcpjson::Quote(digest) + L",\"json_pointer\":" + mcpjson::Quote(pointer) + L"}"; }
    uint64_t Stored(const ObservationRoutedReadSet& reads)
    {
        uint64_t bytes = 0;
        for (const auto& receipt : reads.Attempts.Reads)
        { for (const auto& span : receipt.Result.Spans) { bytes += span.Bytes.size(); } }
        return bytes;
    }
    std::wstring Witness(const ImageSliceClaimEvidence& s)
    {
        if (s.FirstDifference.Size == 0) { return L"null"; }
        std::wstring reads = L"[";
        for (size_t i = 0; i < s.WitnessParserReads.size(); ++i)
        {
            if (i) { reads += L","; }
            reads += L"{\"parser_call\":" + Ref(s.RecipeSha256, L"/payload/target_reads/parser_reads/" + std::to_wstring(s.WitnessParserReads[i])) +
                L",\"returned_receipt\":" + Ref(s.RecipeSha256, L"/payload/target_reads/attempts/reads/" + std::to_wstring(s.WitnessReceipts[i] - 1)) + L"}";
        }
        return L"{\"selection\":\"first_stable_changed_range\",\"recipe_sha256\":" + mcpjson::Quote(s.RecipeSha256) +
            L",\"address\":" + N(s.FirstDifference.Address) + L",\"length\":" + N(s.FirstDifference.Size) +
            L",\"normalization\":" + Ref(s.RecipeSha256, L"/payload/normalization/" + std::to_wstring(s.DifferencePage)) +
            L",\"secondary_inputs\":" + (s.Secondary ? Ref(s.RecipeSha256, L"/payload/secondary_reads") : L"null") +
            L",\"original_reads\":" + reads + L"]}";
    }
    std::wstring Partition(const ImageSliceClaimEvidence& s)
    {
        const auto state = !s.Valid ? L"invalid" : !s.Requested ? L"not_attempted" :
            s.Compared == s.Requested ? L"complete" : L"partial";
        return L"{\"recipe_sha256\":" + mcpjson::Quote(s.RecipeSha256) + L",\"comparison_policy\":" + mcpjson::Quote(s.Policy) +
            L",\"relocation_base\":" + N(s.RelocationBase) + L",\"secondary_basis\":" + B(s.Secondary) +
            L",\"start_range\":" + N(s.StartRange) + L",\"range_count\":" + N(s.RangeCount) +
            L",\"status\":" + mcpjson::Quote(state) + L",\"requested_bytes\":" + N(s.Requested) +
            L",\"compared_bytes\":" + N(s.Compared) + L",\"skipped_bytes\":" + N(s.Skipped) +
            L",\"failed_bytes\":" + N(s.Failed) + L",\"unvisited_bytes\":" + N(s.Unvisited) +
            L",\"started_tick\":" + N(s.StartedTick) + L",\"ended_tick\":" + N(s.EndedTick) +
            L",\"replayed_ranges\":" + Ref(s.RecipeSha256, L"/payload/recorded_result") + L"}";
    }
    std::wstring Report(const std::wstring& digest, const std::vector<ImageSliceClaimEvidence>& slices,
        const ImageSweepManifest* manifest)
    {
        if (!Digest(digest) || slices.empty() || slices.size() > 2048) { return {}; }
        const bool sweep = manifest != nullptr;
        const auto& first = slices.front();
        bool valid = true, identities = true, allMatch = true;
        uint64_t requested = 0, traffic = 0, secondaryTraffic = 0, stored = 0, secondaryStored = 0, ranges = 0;
        uint64_t differences = 0, differenceRanges = 0, rawMissing = 0;
        size_t witnessIndex = slices.size();
        std::wstring partitions = L"[", members = L"[";
        std::set<uint32_t> schedule;
        for (size_t i = 0; i < slices.size(); ++i)
        {
            const auto& s = slices[i];
            if (!Digest(s.RecipeSha256) || !Digest(s.ReferenceSha256) ||
                s.ReferenceSha256 != first.ReferenceSha256 || s.ImageBase != first.ImageBase ||
                s.TargetId != first.TargetId || s.AddressSpaceId != first.AddressSpaceId ||
                (s.Policy != ImageSliceDirectPolicy && s.Policy != ImageSliceSecondaryPolicy)) { return {}; }
            if (sweep)
            {
                const auto& row = manifest->Slices[i];
                if (row.RecipeSha256 != s.RecipeSha256 || row.ReferenceSha256 != s.ReferenceSha256 ||
                    row.StartRange != s.StartRange || row.RangeCount != s.RangeCount ||
                    row.StartedTick != s.StartedTick || row.EndedTick != s.EndedTick || !row.RecipeWritten || !row.ReferenceWritten) { return {}; }
                if (!row.RawWritten) { ++rawMissing; }
            }
            for (uint32_t n = 0; n < s.RangeCount; ++n)
            { if (!schedule.insert(s.StartRange + n).second) { return {}; } }
            valid &= s.Valid; identities &= s.IdentityQualified; allMatch &= s.FullMatch;
            requested += s.Requested; ranges += s.RangeCount; traffic += s.TargetTraffic; secondaryTraffic += s.SecondaryTraffic;
            stored += s.TargetStored; secondaryStored += s.SecondaryStored;
            differences += s.StableDifferenceBytes; differenceRanges += s.StableDifferenceRanges;
            if (witnessIndex == slices.size() && s.FirstDifference.Size != 0) { witnessIndex = i; }
            if (i) { partitions += L","; members += L","; }
            partitions += Partition(s);
            members += sweep ? Ref(digest, L"/payload/slices/" + std::to_wstring(i)) : Ref(digest, L"/payload");
        }
        const uint64_t expected = sweep ? manifest->Sweep.ExpectedBytes : requested;
        const uint64_t totalRanges = sweep ? manifest->Sweep.TotalRanges : ranges;
        const uint64_t missing = sweep ? manifest->ObservedSlices - slices.size() : 0;
        if (requested > expected || ranges > totalRanges) { return {}; }
        const bool membership = !sweep || (manifest->TerminalObserved && manifest->TraversalComplete &&
            missing == 0 && ranges == totalRanges && requested == expected);
        allMatch &= membership && ranges != 0;
        const bool differs = witnessIndex != slices.size();
        const std::wstring policy = sweep ? L"kn.image_claim_policy.sweep.v1" : L"kn.image_claim_policy.slice.v1";
        const std::vector<Requirement> gates = {
            {L"verified_original_inputs", L"recover_and_replay_exact_original_artifacts_and_membership", L"offline_replay", true},
            {L"valid_per_policy_range_partitions", L"recompute_each_original_range_and_selected_receipt", L"offline_replay", true},
            {L"supported_recorded_comparison_policy", L"use_the_recorded_direct_or_secondary_comparison_policy", L"offline_replay", true}};
        std::array<Policy, 2> policies{{
            {sweep ? L"image_sweep_scheduled_ranges_match_reference" : L"image_slice_requested_ranges_match_reference", gates},
            {sweep ? L"image_sweep_contains_stable_difference" : L"image_slice_contains_stable_difference", gates}}};
        policies[0].Requires.insert(policies[0].Requires.end(), {
            {L"complete_scope_membership", L"retain_all_scheduled_ranges_and_the_terminal_observation", L"collect"},
            {L"all_range_identities_qualified", L"requalify_mapped_identity_and_each_recorded_normalization_basis", L"collect"},
            {L"full_scope_match", L"capture_missing_bytes_and_resolve_excluded_or_failed_comparisons", L"collect"}});
        policies[1].Requires.push_back({L"stable_difference_with_two_original_reads",
            L"capture_qualified_changed_bytes_and_a_separate_confirmation_receipt", L"collect"});
        const auto origin = Ref(digest, sweep ? L"/payload/slices" : L"/payload/target_reads");
        const Evidence root{digest, sweep ? L"/payload/slices" : L"/payload/target_reads"};
        const auto fact = [&](const wchar_t* id, bool met) { return Fact{id, met ? Observation::Met : Observation::Missing, root}; };
        std::wstring definitions = L"[", claims = L"[";
        for (size_t i = 0; i < policies.size(); ++i)
        {
            const auto& rule = policies[i];
            if (i) { definitions += L","; claims += L","; }
            definitions += L"{\"claim\":" + mcpjson::Quote(rule.Id) + L",\"requirements\":[";
            for (size_t j = 0; j < rule.Requires.size(); ++j)
            {
                const auto& r = rule.Requires[j];
                if (j) { definitions += L","; }
                definitions += L"{\"id\":" + mcpjson::Quote(r.Id) + L",\"gate\":" + B(r.Gate) +
                    L",\"next_observation\":" + mcpjson::Quote(r.NextObservation) + L",\"mode\":" + mcpjson::Quote(r.Mode) + L"}";
            }
            definitions += L"]}";
            std::vector<Fact> facts = {fact(L"verified_original_inputs", true), fact(L"valid_per_policy_range_partitions", valid),
                fact(L"supported_recorded_comparison_policy", true)};
            if (!i)
            {
                facts.push_back(fact(L"complete_scope_membership", membership && ranges != 0));
                facts.push_back(fact(L"all_range_identities_qualified", identities));
            }
            const bool positive = i ? differs : allMatch, negative = i ? allMatch : differs;
            facts.push_back({rule.Requires.back().Id, positive ? Observation::Met : negative ? Observation::Contrary : Observation::Missing,
                differs && sweep ? Evidence{digest, L"/payload/slices/" + std::to_wstring(witnessIndex)} : root});
            const auto evaluation = Evaluate(rule, facts);
            const auto factJson = [&](const std::vector<Fact>& values)
            {
                std::wstring out = L"[";
                for (const auto& value : values)
                {
                    if (out.size() > 1) { out += L","; }
                    out += L"{\"requirement\":" + mcpjson::Quote(value.RequirementId) + L",\"evidence\":" +
                        Ref(value.Origin.Sha256, value.Origin.Pointer) + L"}";
                }
                return out + L"]";
            };
            claims += L"{\"claim\":" + mcpjson::Quote(rule.Id) + L",\"status\":" + mcpjson::Quote(Name(evaluation.Status)) +
                L",\"issue\":" + mcpjson::Quote(evaluation.Issue) + L",\"scope_evidence\":" + origin +
                L",\"supports\":" + factJson(evaluation.Supports) + L",\"contradicts\":" + factJson(evaluation.Contradicts) +
                L",\"unfulfilled_requirements\":[";
            for (size_t j = 0; j < evaluation.Missing.size(); ++j)
            { if (j) { claims += L","; } claims += mcpjson::Quote(evaluation.Missing[j].Id); }
            claims += L"],\"not_applicable_basis\":null,\"next_best_observation\":";
            if (evaluation.Status == State::Unfulfilled && !evaluation.Missing.empty())
            {
                const auto& next = evaluation.Missing.front();
                claims += L"{\"resolves_requirement\":" + mcpjson::Quote(next.Id) + L",\"observation\":" + mcpjson::Quote(next.NextObservation) +
                    L",\"mode\":" + mcpjson::Quote(next.Mode) + L",\"budget\":\"source_policy_bounded\",\"automatic_execution\":false,"
                    L"\"alternative_hypotheses\":[\"missing_or_excluded_observation\",\"changed_mapping_or_normalization_basis\",\"transient_bytes\"],"
                    L"\"remaining_unknown\":[\"mapping_lifetime\",\"execution\",\"writer_identity\",\"maliciousness\"]}";
            }
            else { claims += L"null"; }
            claims += L"}";
        }
        const auto report = L"{\"schema\":\"kn.image_claim_report.v1\",\"registry\":\"kn.claim_registry.v1\",\"policy\":" + mcpjson::Quote(policy) +
            L",\"evaluation\":\"current_claim_policy_on_replayed_observations\",\"original_claim_policy_reproduced\":false,"
            L"\"capture_sha256\":" + mcpjson::Quote(digest) + L",\"reference_sha256\":" + mcpjson::Quote(first.ReferenceSha256) +
            L",\"scope\":" + mcpjson::Quote(sweep ? L"temporal_sweep_schedule" : L"executed_slice_ranges") +
            L",\"target_id\":" + mcpjson::Quote(first.TargetId) + L",\"address_space_id\":" + mcpjson::Quote(first.AddressSpaceId) +
            L",\"image_base\":" + N(first.ImageBase) + L",\"claim_count\":\"2\",\"report_complete\":true,"
            L"\"report_completeness_scope\":\"two_policies_and_all_recorded_policy_partitions\",\"policies\":" + definitions +
            L"],\"claims\":" + claims + L"],\"stable_difference_witness\":" + (differs ? Witness(slices[witnessIndex]) : L"null") +
            L",\"stable_difference_bytes\":" + N(differences) + L",\"stable_difference_ranges\":" + N(differenceRanges) +
            L",\"membership_refs\":" + members + L"],\"ledgers\":{\"discovery\":{\"scheduled_ranges\":" + N(totalRanges) +
            L",\"replayed_ranges\":" + N(ranges) + L",\"scheduled_bytes\":" + N(expected) + L",\"unscheduled_or_unvisited_bytes\":" + N(expected - requested) +
            L",\"retained_slices\":" + N(slices.size()) + L",\"missing_slice_entries\":" + N(missing) +
            L",\"membership_complete\":" + B(membership) + L",\"whole_host_inventory_complete\":false},"
            L"\"address\":{\"status\":\"per_original_policy_partitions\",\"combined_coverage_asserted\":false,\"partitions\":" + partitions +
            L"]},\"temporal\":{\"clock_domain\":\"collector_steady_clock_ms\",\"intervals_in_address_partitions\":true,"
            L"\"tail_unknown\":" + B(sweep && !manifest->TerminalObserved) + L",\"atomic_snapshot\":false,\"continuous_observation\":false,"
            L"\"event_loss_known\":false,\"mapping_lifetime_bound\":false},\"semantic\":{\"basis_in_address_partitions\":true,"
            L"\"all_range_identities_qualified\":" + B(identities) + L",\"function_equivalence_proven\":false,\"hotpatch_epoch\":\"unavailable\"},"
            L"\"persistence\":{\"recipe_and_reference_verified\":true,\"target_requested_read_bytes\":" + N(traffic) +
            L",\"secondary_requested_read_bytes\":" + N(secondaryTraffic) + L",\"target_stored_bytes_with_repeats\":" + N(stored) +
            L",\"secondary_stored_bytes_with_repeats\":" + N(secondaryStored) + L",\"raw_publication_failures\":" + (sweep ? N(rawMissing) : L"null") +
            L",\"claim_report_persistence\":\"not_established\",\"journal_membership_checked\":false},"
            L"\"replay\":{\"comparison_mode\":\"original_policy\",\"original_results_reproduced\":true,"
            L"\"current_claim_policy_evaluated\":true,\"original_claim_policy_reproduced\":false},"
            L"\"trust\":{\"target_identity_scope\":\"collector_declared\",\"collector_authenticated\":false,\"checksum_is_authentication\":false,"
            L"\"approved_reference\":false}},\"not_proven\":[\"atomic_snapshot\",\"mapping_lifetime\",\"execution\",\"writer_identity\","
            L"\"maliciousness\",\"authorized_change\",\"whole_image_integrity_at_one_time\",\"continuous_target_observation\"]}";
        return report.size() <= ImageScopeClaimMaximumCharacters ? report : L"";
    }
}

ImageSliceClaimEvidence AssessImageSliceClaims(const ImageSliceRecipe& p,
    const std::vector<ExecutablePageResult>& pages, const std::wstring& digest)
{
    ImageSliceClaimEvidence out;
    std::wstring actual;
    if (!mcpjson::GetString(ImageSliceRecipeJson(p), L"recipe_sha256", &actual) || actual != digest ||
        !Digest(digest) || pages.size() != p.Slice.PageCount || pages.size() > 4096) { return out; }
    out.RecipeSha256 = digest; out.ReferenceSha256 = p.ReferenceSha256; out.Policy = p.Policy;
    out.TargetId = p.TargetReads.Attempts.TargetId; out.AddressSpaceId = p.TargetReads.Attempts.AddressSpaceId;
    out.ImageBase = p.ImageBase; out.RelocationBase = p.Slice.RelocationBase;
    out.StartedTick = p.TargetReads.Attempts.StartedTick; out.EndedTick = p.TargetReads.Attempts.SnapshotTick;
    out.StartRange = p.Slice.StartRange; out.RangeCount = p.Slice.PageCount; out.Secondary = p.Slice.SecondaryNeeded;
    out.TargetTraffic = p.TargetReads.Attempts.ChargedBytes; out.SecondaryTraffic = p.Slice.SecondaryReads.Attempts.ChargedBytes;
    out.TargetStored = Stored(p.TargetReads); out.SecondaryStored = Stored(p.Slice.SecondaryReads);
    out.Valid = true; out.IdentityQualified = out.FullMatch = !pages.empty() && p.Slice.RejectionReason.empty();
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (size_t pageIndex = 0; pageIndex < pages.size(); ++pageIndex)
    {
        const auto& page = pages[pageIndex];
        const auto& c = page.Coverage;
        if (c.RequestedBytes == 0 || c.RequestedBytes > 4096 || p.ImageBase > UINT64_MAX - page.Rva ||
            p.ImageBase + page.Rva > UINT64_MAX - c.RequestedBytes) { out.Valid = false; break; }
        const auto start = p.ImageBase + page.Rva, length = c.RequestedBytes;
        ranges.push_back({start, start + length});
        std::vector<uint8_t> classes(static_cast<size_t>(length), 0), differences(static_cast<size_t>(length), 0);
        const auto mark = [&](const std::vector<ObservationRange>& values, uint8_t kind, bool changed)
        {
            if (values.size() > 4096) { return false; }
            const auto base = changed ? static_cast<uint64_t>(page.Rva) : start;
            for (const auto& r : values)
            {
                if (r.Size == 0 || r.Address < base || r.Address - base >= length || r.Size > length - (r.Address - base)) { return false; }
                for (uint64_t n = r.Address - base; n < r.Address - base + r.Size; ++n)
                {
                    auto& cell = changed ? differences[static_cast<size_t>(n)] : classes[static_cast<size_t>(n)];
                    if (cell != 0 || (changed && classes[static_cast<size_t>(n)] != 1)) { return false; }
                    cell = kind;
                }
            }
            return true;
        };
        bool valid = !c.RangesTruncated && mark(c.Compared, 1, false) && mark(c.Skipped, 2, false) &&
            mark(c.Failed, 3, false) && mark(page.Changes, 1, true);
        const auto count = [&](uint8_t value) { return static_cast<uint64_t>(std::count(classes.begin(), classes.end(), value)); };
        const auto compared = count(1), skipped = count(2), failed = count(3), unvisited = count(0);
        valid &= compared == c.ComparedBytes && skipped == c.SkippedBytes && failed == c.FailedBytes;
        const bool basis = page.RelocationBase == p.Slice.RelocationBase && page.SecondaryImageView == p.Slice.SecondaryNeeded;
        if (compared)
        {
            valid &= page.Expected.size() == length && page.Observed.size() == length && basis;
            for (size_t i = 0; valid && i < length; ++i)
            { valid &= (differences[i] != 0) == (classes[i] == 1 && page.Expected[i] != page.Observed[i]); }
        }
        else { valid &= page.Changes.empty(); }
        std::vector<size_t> matchingCalls;
        std::vector<uint64_t> receipts;
        for (size_t i = 0; valid && compared && i < p.TargetReads.ParserReads.size(); ++i)
        {
            const auto& call = p.TargetReads.ParserReads[i];
            if (!call.Accepted || call.Address != start || call.Length != length || call.ReturnedReceipt == 0 ||
                call.ReturnedReceipt > p.TargetReads.Attempts.Reads.size()) { continue; }
            const auto& read = p.TargetReads.Attempts.Reads[static_cast<size_t>(call.ReturnedReceipt - 1)].Result;
            if (read.State != ObservationReadState::Complete || read.CancellationObserved || read.OperationDeadlineExceeded) { continue; }
            std::vector<uint8_t> observed;
            for (const auto& span : read.Spans) { observed.insert(observed.end(), span.Bytes.begin(), span.Bytes.end()); }
            bool same = observed.size() == length;
            for (size_t n = 0; same && n < length; ++n) { same &= classes[n] != 1 || observed[n] == page.Observed[n]; }
            if (same && std::find(receipts.begin(), receipts.end(), call.ReturnedReceipt) == receipts.end())
            { matchingCalls.push_back(i); receipts.push_back(call.ReturnedReceipt); if (receipts.size() == 2) { break; } }
        }
        valid &= !compared || !matchingCalls.empty();
        const bool qualified = p.Slice.RejectionReason.empty() && c.InventoryAvailable && c.Attempted && c.LostEvents == 0;
        out.Valid &= valid; out.IdentityQualified &= qualified;
        out.FullMatch &= valid && qualified && basis && c.CompleteFor({{start, length}}) &&
            page.Ownership == CodeOwnership::OwnedVerified && page.Changes.empty() && !matchingCalls.empty();
        out.Requested += length; out.Compared += compared; out.Skipped += skipped; out.Failed += failed; out.Unvisited += unvisited;
        if (valid && qualified && basis && c.TraversalComplete && page.Ownership == CodeOwnership::OwnedModified &&
            !page.Changes.empty() && matchingCalls.size() >= 2)
        {
            for (const auto& r : page.Changes) { out.StableDifferenceBytes += r.Size; ++out.StableDifferenceRanges; }
            if (out.FirstDifference.Size == 0)
            {
                out.FirstDifference = {p.ImageBase + page.Changes.front().Address, page.Changes.front().Size};
                out.DifferencePage = pageIndex; out.WitnessParserReads = std::move(matchingCalls); out.WitnessReceipts = std::move(receipts);
            }
        }
    }
    std::sort(ranges.begin(), ranges.end());
    for (size_t i = 1; i < ranges.size(); ++i) { out.Valid &= ranges[i - 1].second <= ranges[i].first; }
    out.FullMatch &= out.Valid;
    return out;
}

std::wstring ImageSliceClaimAssessmentJson(const ImageSliceClaimEvidence& slice) noexcept
{
    try { return Report(slice.RecipeSha256, {slice}, nullptr); }
    catch (...) { return {}; }
}

std::wstring ImageSweepClaimAssessmentJson(const ImageSweepManifest& manifest,
    const std::wstring& digest, const std::vector<ImageSliceClaimEvidence>& slices) noexcept
{
    try
    {
        std::wstring actual;
        if (!mcpjson::GetString(ImageSweepManifestJson(manifest), L"manifest_sha256", &actual) || actual != digest ||
            manifest.Inconsistent || slices.size() != manifest.Slices.size() || slices.empty() ||
            slices.front().TargetId != manifest.Sweep.TargetId || slices.front().AddressSpaceId != manifest.Sweep.AddressSpaceId ||
            slices.front().ImageBase != manifest.Sweep.ImageBase) { return {}; }
        return Report(digest, slices, &manifest);
    }
    catch (...) { return {}; }
}
