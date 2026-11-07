#include "ImageProof.h"
#include "McpJson.h"
#include "ClaimPolicy.h"
#include <array>

namespace
{
    constexpr uint8_t Compared = 1, Skipped = 2, Failed = 4;

    bool Mark(const std::vector<ObservationRange>& ranges, uint64_t start, uint64_t length,
        uint8_t kind, std::vector<uint8_t>* mask)
    {
        if (ranges.size() > 4096)
        {
            return false;
        }
        for (const auto& range : ranges)
        {
            if (range.Size == 0 || range.Address < start || range.Address - start >= length ||
                range.Size > length - (range.Address - start))
            {
                return false;
            }
            for (uint64_t i = range.Address - start; i < range.Address - start + range.Size; ++i)
            {
                (*mask)[static_cast<size_t>(i)] |= kind;
            }
        }
        return true;
    }

    std::wstring N(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }

    std::wstring B(bool value)
    {
        return value ? L"true" : L"false";
    }

    std::wstring Strings(const std::vector<std::wstring>& values)
    {
        std::wstring json = L"[";
        for (const auto& value : values)
        {
            if (json.size() > 1)
            {
                json += L",";
            }
            json += mcpjson::Quote(value);
        }
        return json + L"]";
    }

    std::wstring Ranges(const std::vector<ObservationRange>& ranges)
    {
        std::wstring json = L"[";
        for (const auto& range : ranges)
        {
            if (json.size() > 1)
            {
                json += L",";
            }
            json += L"{\"address\":" + N(range.Address) + L",\"length\":" + N(range.Size) + L"}";
        }
        return json + L"]";
    }

    std::wstring ClaimJson(const ImageProofClaim& claim)
    {
        return L"{\"name\":" + mcpjson::Quote(claim.Name) + L",\"status\":" + mcpjson::Quote(claim.Status) +
            L",\"ranges\":" + Ranges(claim.Ranges) + L",\"supports\":" + Strings(claim.Supports) +
            L",\"contradicts\":" + Strings(claim.Contradicts) +
            L",\"unfulfilled_requirements\":" + Strings(claim.UnfulfilledRequirements) +
            L",\"next_best_observation\":" + Strings(claim.NextBestObservation) + L"}";
    }
}

ImageProofAssessment AssessImageProof(const ImageVerificationRecipe& recipe,
    const ExecutablePageResult& comparison, bool referenceQualified, bool currentReanalysis)
{
    ImageProofAssessment proof;
    proof.Matches.Name = L"recorded_range_matches_reference_policy";
    proof.Differs.Name = L"recorded_range_differs_reference_policy";
    proof.ReferenceQualified = referenceQualified;
    proof.CurrentReanalysis = currentReanalysis;
    // Reuse the bounded recipe admission contract, including sparse provenance.
    if (ImageRecipeJson(recipe).empty() || (!currentReanalysis && recipe.Policy != ImageRecipePolicy))
    {
        for (auto* claim : {&proof.Matches, &proof.Differs})
        {
            claim->UnfulfilledRequirements.push_back(L"valid_bounded_recipe_and_selected_policy");
            claim->NextBestObservation.push_back(L"recover_original_recipe_and_reference");
        }
        return proof;
    }
    const auto& coverage = comparison.Coverage;
    const uint64_t start = recipe.ImageBase + recipe.Rva;
    const auto length = recipe.Length;
    proof.RequestedBytes = length;
    std::vector<uint8_t> classified(length, 0), changed(length, 0), retained(length, 0);
    bool accounting = comparison.Rva == recipe.Rva && coverage.RequestedBytes == length &&
        !coverage.RangesTruncated && Mark(coverage.Compared, start, length, Compared, &classified) &&
        Mark(coverage.Skipped, start, length, Skipped, &classified) &&
        Mark(coverage.Failed, start, length, Failed, &classified);
    for (const auto kind : classified)
    {
        switch (kind)
        {
        case 0:
            ++proof.UnvisitedBytes;
            break;
        case Compared:
            ++proof.ComparedBytes;
            break;
        case Skipped:
            ++proof.SkippedBytes;
            break;
        case Failed:
            ++proof.FailedBytes;
            break;
        default:
            accounting = false;
            break;
        }
    }
    accounting = accounting && proof.ComparedBytes == coverage.ComparedBytes &&
        proof.SkippedBytes == coverage.SkippedBytes && proof.FailedBytes == coverage.FailedBytes;
    proof.AddressAccountingValid = accounting;
    bool bytesAgree = comparison.Changes.size() <= 4096 &&
        Mark(comparison.Changes, recipe.Rva, length, 1, &changed);
    if (proof.ComparedBytes != 0)
    {
        bytesAgree = bytesAgree && comparison.Expected.size() == length && comparison.Observed.size() == length;
        if (bytesAgree)
        {
            for (uint32_t i = 0; i < length; ++i)
            {
                const bool differs = classified[i] == Compared && comparison.Expected[i] != comparison.Observed[i];
                bytesAgree = bytesAgree && (changed[i] != 0) == differs;
            }
        }
    }
    else
    {
        bytesAgree = bytesAgree && comparison.Changes.empty();
    }
    // Materialize only validated absolute difference ranges. Stored changes are RVAs.
    if (accounting && bytesAgree)
    {
        for (uint32_t i = 0; i < length;)
        {
            if (changed[i] == 0)
            {
                ++i;
                continue;
            }
            const auto first = i++;
            while (i < length && changed[i] != 0)
            {
                ++i;
            }
            proof.ChangedRanges.push_back({start + first, i - first});
        }
    }
    proof.FirstAcquisitionTick = recipe.Reads.front().Result.StartedTick;
    proof.LastAcquisitionTick = recipe.Reads.back().Result.EndedTick;
    for (size_t index = 0; index < recipe.Reads.size(); ++index)
    {
        const auto& read = recipe.Reads[index];
        proof.RequestedReadBytes += read.Length;
        std::vector<uint8_t> available(length, 0), observed(length, 0);
        for (const auto& span : read.Result.Spans)
        {
            proof.RetainedReadBytes += span.Bytes.size();
            if (span.State != ObservationReadState::Complete)
            {
                continue;
            }
            const auto begin = (std::max)(start, span.Address);
            const auto end = (std::min)(start + length, span.Address + span.RequestedBytes);
            for (uint64_t address = begin; address < end; ++address)
            {
                const auto offset = static_cast<size_t>(address - start);
                retained[offset] = available[offset] = 1;
                observed[offset] = span.Bytes[static_cast<size_t>(address - span.Address)];
            }
        }
        bool supports = accounting && bytesAgree && proof.ComparedBytes != 0 && !read.Result.CancellationObserved &&
            read.Result.SourceId == recipe.SourceId && read.Result.Consistency == recipe.SourceConsistency;
        for (uint32_t i = 0; supports && i < length; ++i)
        {
            if (classified[i] == Compared)
            {
                supports = available[i] != 0 && observed[i] == comparison.Observed[i];
            }
        }
        if (supports)
        {
            proof.SupportingReadIndices.push_back(index);
        }
    }
    proof.UniqueTargetBytesRetained = std::count(retained.begin(), retained.end(), uint8_t{1});
    proof.InputConsistent = accounting && bytesAgree && (proof.ComparedBytes == 0 ||
        (!comparison.SecondaryImageView && comparison.RelocationBase == recipe.ImageBase &&
            !proof.SupportingReadIndices.empty()));
    const bool compared = proof.InputConsistent && referenceQualified && coverage.Attempted &&
        coverage.InventoryAvailable && coverage.TraversalComplete && coverage.LostEvents == 0;
    const bool matching = compared && coverage.CompleteFor({{start, length}}) &&
        comparison.Ownership == CodeOwnership::OwnedVerified && proof.ChangedRanges.empty() &&
        !proof.SupportingReadIndices.empty();
    const bool differs = compared && comparison.Ownership == CodeOwnership::OwnedModified &&
        !proof.ChangedRanges.empty() && proof.SupportingReadIndices.size() >= 2;

    for (auto* claim : {&proof.Matches, &proof.Differs})
    {
        if (referenceQualified)
        {
            claim->Supports.push_back(L"mapped_identity_qualified_by_selected_replay");
        }
        else
        {
            claim->UnfulfilledRequirements.push_back(L"qualified_mapped_image_identity");
            claim->NextBestObservation.push_back(L"capture_matching_image_identity_and_supported_relocation_basis");
        }
        if (proof.InputConsistent)
        {
            claim->Supports.push_back(L"unique_address_accounting_and_difference_bytes_agree");
        }
        else
        {
            claim->UnfulfilledRequirements.push_back(L"consistent_typed_comparison");
            claim->NextBestObservation.push_back(L"recompute_comparison_from_retained_inputs");
        }
        if (!compared)
        {
            claim->UnfulfilledRequirements.push_back(L"qualified_completed_comparison");
        }
    }
    if (matching)
    {
        proof.Matches.Status = L"supported";
        proof.Matches.Ranges.push_back({start, length});
        proof.Matches.Supports.push_back(L"all_requested_bytes_match_supported_reference_policy");
        proof.Differs.Status = L"contradicted";
        proof.Differs.Contradicts.push_back(L"complete_requested_range_matches_reference_policy");
    }
    else if (differs)
    {
        proof.Differs.Status = L"supported";
        proof.Differs.Ranges = proof.ChangedRanges;
        proof.Differs.Supports.push_back(L"difference_bytes_confirmed_by_two_recorded_reads");
        proof.Matches.Status = L"contradicted";
        proof.Matches.Contradicts.push_back(L"confirmed_difference_in_requested_range");
    }
    else
    {
        proof.Differs.UnfulfilledRequirements.push_back(L"stable_difference_bytes_in_two_recorded_reads");
        proof.Differs.NextBestObservation.push_back(L"capture_qualified_range_and_confirmation_read");
    }
    if (!matching && !differs)
    {
        proof.Matches.UnfulfilledRequirements.push_back(L"complete_requested_range_match");
        proof.Matches.NextBestObservation.push_back(L"capture_missing_bytes_or_add_exact_exclusion_policy_evidence");
    }
    return proof;
}

std::wstring ImageProofJson(const ImageVerificationRecipe& recipe, const ImageProofAssessment& proof)
{
    std::wstring recipeHash;
    mcpjson::GetString(ImageRecipeJson(recipe), L"recipe_sha256", &recipeHash);
    std::wstring references = L"[";
    for (const auto index : proof.SupportingReadIndices)
    {
        if (references.size() > 1)
        {
            references += L",";
        }
        references += mcpjson::Quote(L"recipe:" + recipeHash + L"#read:" + std::to_wstring(index));
    }
    references += L"]";
    std::wstring intervals = L"[";
    for (size_t i = 0; i < recipe.Reads.size(); ++i)
    {
        if (i != 0)
        {
            intervals += L",";
        }
        const auto& read = recipe.Reads[i];
        intervals += L"{\"read_index\":" + N(i) + L",\"started_tick\":" + N(read.Result.StartedTick) +
            L",\"ended_tick\":" + N(read.Result.EndedTick) + L"}";
    }
    intervals += L"]";
    const auto addressStatus = !proof.AddressAccountingValid ? L"invalid" :
        (proof.ComparedBytes == proof.RequestedBytes && proof.RequestedBytes != 0 ? L"complete" : L"partial");
    return L"{\"schema\":\"kn.image_proof.v1\",\"policy\":\"kn.image_proof.direct.v1\",\"input_consistent\":" +
        B(proof.InputConsistent) + L",\"source_id\":" + mcpjson::Quote(recipe.SourceId) +
        L",\"recipe_sha256\":" + mcpjson::Quote(recipeHash) + L",\"reference_sha256\":" + mcpjson::Quote(recipe.ReferenceSha256) +
        L",\"evidence_refs\":" + references + L",\"ledgers\":{\"discovery\":{\"scope\":\"explicit_requested_range\","
        L"\"whole_image_inventory_complete\":false},\"address\":{\"status\":" + mcpjson::Quote(addressStatus) +
        L",\"denominator\":\"requested_comparison_range\",\"requested_bytes\":" + N(proof.RequestedBytes) +
        L",\"compared_bytes\":" + N(proof.ComparedBytes) + L",\"skipped_bytes\":" + N(proof.SkippedBytes) +
        L",\"failed_bytes\":" + N(proof.FailedBytes) + L",\"unvisited_bytes\":" + N(proof.UnvisitedBytes) +
        L"},\"temporal\":{\"status\":\"acquisition_intervals_only\",\"clock_domain\":\"collector_steady_clock_ms\","
        L"\"source_consistency\":" + mcpjson::Quote(recipe.SourceConsistency) + L",\"continuous_observation\":false,"
        L"\"target_time_available\":false,\"first_tick\":" + N(proof.FirstAcquisitionTick) + L",\"last_tick\":" + N(proof.LastAcquisitionTick) +
        L",\"intervals\":" + intervals + L"},\"semantic\":{\"mapped_identity_qualified\":" + B(proof.ReferenceQualified) +
        L",\"comparison_policy\":" + mcpjson::Quote(ImageRecipePolicy) + L",\"hotpatch_epoch\":\"unavailable\","
        L"\"function_equivalence_proven\":false},\"persistence\":{\"scope\":\"retained_recipe_inputs\","
        L"\"reference_artifact_verified\":true,\"full_source_preserved\":false,\"requested_read_bytes\":" + N(proof.RequestedReadBytes) +
        L",\"retained_read_bytes_including_repeats\":" + N(proof.RetainedReadBytes) +
        L",\"unique_target_bytes_retained\":" + N(proof.UniqueTargetBytesRetained) +
        L"},\"replay\":{\"status\":" + mcpjson::Quote(proof.CurrentReanalysis ? L"current_policy_reanalysis" : L"original_result_reproduced") +
        L",\"recorded_policy\":" + mcpjson::Quote(recipe.Policy) + L",\"current_policy\":" + mcpjson::Quote(ImageRecipePolicy) +
        L"},\"trust\":{\"status\":\"unauthenticated_local_evidence\",\"collector_authenticated\":false,"
        L"\"approved_distribution\":false,\"security_domain\":\"unavailable\"}},\"claims\":[" + ClaimJson(proof.Matches) +
        L"," + ClaimJson(proof.Differs) + L"],\"not_proven\":[\"execution\",\"writer_identity\",\"maliciousness\","
        L"\"authorized_change\",\"whole_image_integrity\",\"continuous_target_observation\"]}";
}

std::wstring ImageClaimAssessmentJson(const ImageVerificationRecipe& recipe,
    const ExecutablePageResult& comparison, bool referenceQualified, bool currentReanalysis,
    const std::wstring& recipeSha256) noexcept
{
    using namespace claim_policy;
    try
    {
        std::wstring digest;
        const auto original = ImageRecipeJson(recipe);
        if (original.empty() || !mcpjson::GetString(original, L"recipe_sha256", &digest) ||
            digest != recipeSha256 || !Evidence{digest, L"/payload"}.Valid()) { return {}; }
        // Recompute from the selected replay's typed result, never imported claims.
        const auto proof = AssessImageProof(recipe, comparison, referenceQualified, currentReanalysis);
        const std::vector<Requirement> gates = {
            {L"retained_recipe_and_reference", L"recover_exact_recipe_and_content_addressed_reference", L"offline_replay", true},
            {L"selected_comparison_policy", L"select_an_implemented_comparison_policy_explicitly", L"offline_replay", true},
            {L"mapped_image_identity", L"capture_matching_mapped_identity_and_relocation_basis", L"collect", true},
            {L"typed_comparison_consistent", L"recompute_unique_address_accounting_and_original_byte_agreement", L"offline_replay", true},
            {L"completed_comparison_observations", L"capture_the_requested_comparison_without_lost_or_incomplete_observations", L"collect", true}};
        std::array<Policy, 2> policies{{
            {L"image_requested_range_matches_reference", gates},
            {L"image_compared_range_differs_reference", gates}}};
        policies[0].Requires.push_back({L"full_requested_range_match",
            L"capture_missing_bytes_or_qualify_exact_normalization_exclusions", L"collect"});
        policies[1].Requires.push_back({L"stable_difference_in_compared_range",
            L"capture_qualified_difference_bytes_and_a_separate_confirmation_read", L"collect"});
        const std::wstring reads = recipe.FormatVersion == 2 ? L"/payload/read_set/reads" : L"/payload/reads";
        const auto fact = [&](const wchar_t* id, bool met, const std::wstring& pointer)
        { return Fact{id, met ? Observation::Met : Observation::Missing, {digest, pointer}}; };
        const auto& coverage = comparison.Coverage;
        const std::vector<Fact> common = {
            fact(L"retained_recipe_and_reference", true, L"/payload/reference_sha256"),
            fact(L"selected_comparison_policy", currentReanalysis || recipe.Policy == ImageRecipePolicy, L"/payload"),
            fact(L"mapped_image_identity", proof.ReferenceQualified, reads),
            fact(L"typed_comparison_consistent", proof.InputConsistent, reads),
            fact(L"completed_comparison_observations", coverage.Attempted && coverage.InventoryAvailable &&
                coverage.TraversalComplete && coverage.LostEvents == 0, reads)};
        const auto ref = [](const Evidence& evidence)
        { return L"{\"capture_sha256\":" + mcpjson::Quote(evidence.Sha256) + L",\"json_pointer\":" + mcpjson::Quote(evidence.Pointer) + L"}"; };
        const auto facts = [&](const std::vector<Fact>& values)
        {
            std::wstring json = L"[";
            for (const auto& value : values)
            {
                if (json.size() > 1) { json += L","; }
                json += L"{\"requirement\":" + mcpjson::Quote(value.RequirementId) + L",\"evidence\":" + ref(value.Origin) + L"}";
            }
            return json + L"]";
        };
        std::wstring definitions = L"[", claims = L"[", readRefs = L"[";
        const bool matches = proof.Matches.Status == L"supported", differs = proof.Differs.Status == L"supported";
        for (size_t i = 0; i < policies.size(); ++i)
        {
            const auto& policy = policies[i];
            if (i) { definitions += L","; claims += L","; }
            definitions += L"{\"claim\":" + mcpjson::Quote(policy.Id) + L",\"requirements\":[";
            for (size_t j = 0; j < policy.Requires.size(); ++j)
            {
                const auto& requirement = policy.Requires[j];
                if (j) { definitions += L","; }
                definitions += L"{\"id\":" + mcpjson::Quote(requirement.Id) + L",\"gate\":" + B(requirement.Gate) +
                    L",\"next_observation\":" + mcpjson::Quote(requirement.NextObservation) + L",\"mode\":" + mcpjson::Quote(requirement.Mode) + L"}";
            }
            definitions += L"]}";
            const bool supported = i == 0 ? matches : differs, contradicted = i == 0 ? differs : matches;
            auto input = common;
            input.push_back({policy.Requires.back().Id, supported ? Observation::Met :
                (contradicted ? Observation::Contrary : Observation::Missing), {digest, reads}});
            const auto result = Evaluate(policy, input);
            const std::vector<ObservationRange> full = {{recipe.ImageBase + recipe.Rva, recipe.Length}};
            claims += L"{\"claim\":" + mcpjson::Quote(policy.Id) + L",\"status\":" + mcpjson::Quote(Name(result.Status)) +
                L",\"issue\":" + mcpjson::Quote(result.Issue) + L",\"supports\":" + facts(result.Supports) +
                L",\"contradicts\":" + facts(result.Contradicts) + L",\"supported_ranges\":" +
                (result.Status == State::Supported ? Ranges(i == 0 ? full : proof.ChangedRanges) : L"[]") +
                L",\"counterexample_ranges\":" + (result.Status == State::Contradicted ? Ranges(i == 0 ? proof.ChangedRanges : full) : L"[]") +
                L",\"unfulfilled_requirements\":[";
            for (size_t j = 0; j < result.Missing.size(); ++j)
            { if (j) { claims += L","; } claims += mcpjson::Quote(result.Missing[j].Id); }
            claims += L"],\"not_applicable_basis\":null,\"next_best_observation\":";
            if (result.Status == State::Unfulfilled && !result.Missing.empty())
            {
                const auto& next = result.Missing.front();
                claims += L"{\"resolves_requirement\":" + mcpjson::Quote(next.Id) + L",\"observation\":" + mcpjson::Quote(next.NextObservation) +
                    L",\"mode\":" + mcpjson::Quote(next.Mode) + L",\"budget\":\"source_policy_bounded\",\"automatic_execution\":false,"
                    L"\"remaining_unknown\":[\"execution\",\"writer_identity\",\"maliciousness\",\"continuous_target_observation\"]}";
            }
            else { claims += L"null"; }
            claims += L"}";
        }
        for (const auto index : proof.SupportingReadIndices)
        {
            if (readRefs.size() > 1) { readRefs += L","; }
            readRefs += ref({digest, reads + L"/" + std::to_wstring(index)});
        }
        // The seven dimensions come from this same freshly recomputed proof.
        // Parsing a local serialization does not accept a stored proof as input.
        std::wstring ledgers;
        if (!mcpjson::FindRawValue(ImageProofJson(recipe, proof), L"ledgers", &ledgers)) { return {}; }
        const auto report = L"{\"schema\":\"kn.image_claim_report.v1\",\"registry\":\"kn.claim_registry.v1\","
            L"\"policy\":\"kn.image_claim_policy.direct.v1\",\"evaluation\":\"current_claim_policy_on_replayed_observations\","
            L"\"original_claim_policy_reproduced\":false,\"recorded_normalization_reproduced\":" + B(!currentReanalysis) +
            L",\"claim_report_persistence\":\"not_established\",\"journal_membership_checked\":false,"
            L"\"capture_sha256\":" + mcpjson::Quote(digest) + L",\"reference_sha256\":" + mcpjson::Quote(recipe.ReferenceSha256) +
            L",\"source_id\":" + mcpjson::Quote(recipe.SourceId) + L",\"source_identity_scope\":\"collector_declared\","
            L"\"scope\":{\"image_base\":" + N(recipe.ImageBase) + L",\"rva\":" + N(recipe.Rva) + L",\"length\":" + N(recipe.Length) +
            L"},\"claim_count\":\"2\",\"report_complete\":true,\"report_completeness_scope\":\"two_direct_range_policies_only\","
            L"\"policies\":" + definitions + L"],\"claims\":" + claims + L"],\"supporting_read_refs\":" + readRefs +
            L"],\"ledgers\":" + ledgers + L",\"not_proven\":[\"execution\",\"writer_identity\",\"maliciousness\","
            L"\"authorized_change\",\"whole_image_integrity\",\"continuous_target_observation\",\"collector_authentication\"]}";
        return report.size() <= ImageClaimMaximumCharacters ? report : L"";
    }
    catch (...) { return {}; }
}
