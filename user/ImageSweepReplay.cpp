#include "ImageSweepManifest.h"
#include "ImageSweepReplayEvidence.h"
#include "ImageSliceRecipe.h"
#include "ObservationReadRoutingJson.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "AnalystSnapshot.h"
#include <filesystem>
#include <set>

using namespace bounded_observation_json;

namespace
{
    constexpr uint64_t MaximumInputs = 256ull * 1024 * 1024; // Raw and recipe session limits combined.
    std::wstring Field(const std::wstring& json, const wchar_t* name)
    {
        std::wstring text;
        mcpjson::GetString(json, name, &text);
        return text;
    }
    std::wstring Raw(const std::wstring& json, const wchar_t* name)
    {
        std::wstring text;
        mcpjson::FindRawValue(json, name, &text);
        return text;
    }
    bool BoundedRead(const std::filesystem::path& path, uint64_t& consumed, std::wstring* json)
    {
        if (!ReadAnalystSnapshot(path.wstring(), json, nullptr, ImageRecipeMaxBytes, nullptr, true)) { return false; }
        const auto bytes = mcpjson::WideToUtf8(*json).size();
        if (bytes > MaximumInputs - consumed) { return false; }
        consumed += bytes;
        return true;
    }
    bool RawMatches(const std::wstring& json, const ImageSweepManifest& m, const ImageSweepSlice& row, const ImageSliceRecipe& p)
    {
        if (!mcpjson::ValidateDocument(json) || Field(json, L"schema") != L"kn.image_reads.v3" ||
            Field(json, L"payload_sha256") != row.RawPayloadSha256) { return false; }
        const auto payload = Raw(json, L"payload");
        const auto reference = Raw(payload, L"reference");
        const auto bytes = mcpjson::WideToUtf8(payload);
        return ContentHash::Bytes(std::vector<uint8_t>(bytes.begin(), bytes.end())) == row.RawPayloadSha256 &&
            Field(payload, L"boot_id") == m.Sweep.Identity.BootId &&
            Field(payload, L"pid") == std::to_wstring(m.Sweep.Identity.ProcessId) &&
            Field(payload, L"creation_time") == std::to_wstring(m.Sweep.Identity.CreateTime) &&
            Field(payload, L"image_base") == std::to_wstring(m.Sweep.ImageBase) &&
            Field(reference, L"sha256") == p.ReferenceSha256 &&
            Field(reference, L"original_file_identity") == p.OriginalFileIdentity &&
            Field(reference, L"persistence") == L"committed" &&
            Raw(reference, L"content_rechecked") == L"true" && Raw(reference, L"content_stable") == L"true" &&
            Raw(payload, L"reads") == ObservationRoutedReadSetJson(p.TargetReads) &&
            Raw(payload, L"slice_inputs") == ImageSliceInputsJson(p.Slice);
    }
}

ImageRecipeReplay ReplayImageSweepManifest(const std::wstring& path, std::wstring* error,
    ImageSweepReplayEvidence* verifiedEvidence, const std::wstring& expectedManifestSha256)
{
    if (verifiedEvidence != nullptr) { *verifiedEvidence = {}; }
    ImageSweepReplayEvidence verified;
    ImageRecipeReplay result;
    result.Schema = L"kn.image_sweep_replay.v1";
    result.Mode = L"original_policy";
    result.CurrentPolicy.clear();
    if (error != nullptr) { *error = L"sweep membership or retained original inputs could not be verified"; }
    std::wstring json;
    ImageSweepManifest manifest;
    if (!ReadAnalystSnapshot(path, &json, error, ImageRecipeMaxBytes, nullptr, true) || !ParseImageSweepManifest(json, &manifest))
    {
        result.Status = L"manifest_unavailable_or_corrupt"; return result;
    }
    const auto& s = manifest.Sweep;
    result.ManifestSha256 = Field(json, L"manifest_sha256");
    if (!expectedManifestSha256.empty() && result.ManifestSha256 != expectedManifestSha256)
    {
        result.Status = L"manifest_identity_mismatch"; return result;
    }
    result.RecordedPolicy = result.CurrentPolicy = L"kn.executable_sweep.temporal.v1";
    result.RecordedResult = Raw(json, L"payload");
    if (manifest.Inconsistent || manifest.Slices.empty()) { result.Status = L"sweep_membership_inconsistent_or_empty"; return result; }
    const auto root = std::filesystem::path(path).parent_path().parent_path();
    uint64_t consumed = 0, requested = 0, compared = 0, excluded = 0, unreadable = 0, changed = 0, rawFailures = 0;
    bool qualified = true;
    std::wstring referenceHash, referenceIdentity, evidence = L"[";
    ReferenceArtifact reference;
    ExecutableSweep schedule;
    std::vector<bool> seen;
    std::set<uint64_t> readIds;
    for (const auto& row : manifest.Slices)
    {
        if (!readIds.insert(row.ReadSetId).second) { result.Status = L"duplicate_slice_artifact"; return result; }
        if (!row.RecipeWritten || !row.ReferenceWritten) { result.Status = L"slice_recipe_not_published"; return result; }
        const auto name = L"reads-" + s.CollectionId + L"-" + std::to_wstring(row.ReadSetId);
        const auto recipePath = root / L"image-reads" / (name + L".knslice");
        std::wstring recipeJson;
        ImageSliceRecipe p;
        if (!BoundedRead(recipePath, consumed, &recipeJson) || !ParseImageSliceRecipe(recipeJson, &p) ||
            Field(recipeJson, L"recipe_sha256") != row.RecipeSha256)
        {
            result.Status = L"slice_artifact_missing_corrupt_or_budget"; return result;
        }
        if (p.ImageBase != s.ImageBase || p.ReferenceSha256 != row.ReferenceSha256 ||
            p.TargetReads.Attempts.TargetId != s.TargetId || p.TargetReads.Attempts.AddressSpaceId != s.AddressSpaceId ||
            p.TargetReads.Attempts.StartedTick != row.StartedTick || p.TargetReads.Attempts.SnapshotTick != row.EndedTick ||
            p.Slice.StartRange != row.StartRange || p.Slice.PageCount != row.RangeCount)
        {
            result.Status = L"slice_membership_mismatch"; return result;
        }
        if (referenceHash.empty())
        {
            referenceHash = p.ReferenceSha256; referenceIdentity = p.OriginalFileIdentity;
            executable_image::DiskPeMetadata metadata;
            if (!reference.Open((root / L"image-references" / (referenceHash + L".knblob")).wstring(), error) ||
                reference.Sha256() != referenceHash || !executable_image::ReadDiskPeMetadata(reference.Path(), &metadata, error) ||
                metadata.Machine != IMAGE_FILE_MACHINE_AMD64 || metadata.OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                !schedule.Initialize(metadata) || schedule.Ranges.size() != s.TotalRanges ||
                schedule.Coverage.RequestedBytes != s.ExpectedBytes)
            {
                result.Status = L"sweep_reference_or_schedule_mismatch"; return result;
            }
            seen.assign(s.TotalRanges, false);
        }
        else if (referenceHash != p.ReferenceSha256 || referenceIdentity != p.OriginalFileIdentity)
        {
            result.Status = L"sweep_reference_identity_changed"; return result;
        }
        uint64_t sliceBytes = 0;
        for (uint32_t n = row.StartRange; n < row.StartRange + row.RangeCount; ++n)
        {
            if (seen[n]) { result.Status = L"overlapping_slice_ranges"; return result; }
            seen[n] = true;
            sliceBytes += schedule.Ranges[n].Size;
        }
        if (row.RawWritten)
        {
            std::wstring raw;
            if (!BoundedRead(root / L"image-reads" / (name + L".knreads"), consumed, &raw) || !RawMatches(raw, manifest, row, p))
            {
                result.Status = L"raw_artifact_missing_corrupt_or_mismatched"; return result;
            }
        }
        else { ++rawFailures; }
        // Reopening is bound by the returned digest, not by the pathname alone.
        // The shared reference exclusion lease remains held across every slice.
        ImageSweepReplayedSlice verifiedSlice;
        const auto replay = ReplayImageSliceRecipe(recipePath.wstring(), error, verifiedEvidence != nullptr ? &verifiedSlice.Pages : nullptr);
        uint64_t bytes = 0, equalOrDifferent = 0, skip = 0, fail = 0, differences = 0;
        bool sliceQualified = false;
        if (replay.Status != L"replayed" || replay.RecipeSha256 != row.RecipeSha256 ||
            !Number(replay.Proof, L"requested_bytes", &bytes) || bytes != sliceBytes ||
            !Number(replay.Proof, L"compared_bytes", &equalOrDifferent) || !Number(replay.Proof, L"excluded_bytes", &skip) ||
            !Number(replay.Proof, L"unreadable_bytes", &fail) || !Number(replay.Proof, L"changed_bytes", &differences) ||
            !Boolean(replay.Proof, L"target_reference_qualified", &sliceQualified) ||
            equalOrDifferent + skip + fail != bytes || differences > equalOrDifferent)
        {
            result.Status = L"slice_policy_replay_failed"; return result;
        }
        requested += bytes; compared += equalOrDifferent; excluded += skip; unreadable += fail; changed += differences;
        qualified &= sliceQualified;
        if (verifiedEvidence != nullptr)
        {
            verifiedSlice.Publication = row;
            verifiedSlice.Policy = p.Policy;
            verifiedSlice.TargetReferenceQualified = sliceQualified;
            verified.Slices.push_back(std::move(verifiedSlice));
        }
        if (evidence.size() > 1) { evidence += L","; }
        evidence += L"{\"ordinal\":" + N(row.Ordinal) + L",\"read_set_id\":" + N(row.ReadSetId) +
            L",\"recipe_sha256\":" + mcpjson::Quote(row.RecipeSha256) + L",\"policy\":" + mcpjson::Quote(p.Policy) +
            L",\"started_tick\":" + N(row.StartedTick) + L",\"ended_tick\":" + N(row.EndedTick) + L"}";
    }
    if (!reference.Unchanged()) { result.Status = L"reference_changed_during_sweep_replay"; return result; }
    const auto missing = manifest.ObservedSlices - manifest.Slices.size();
    const auto unobservedRanges = static_cast<uint64_t>(std::count(seen.begin(), seen.end(), false));
    const bool allRanges = unobservedRanges == 0 && requested == s.ExpectedBytes;
    const bool completeMembership = manifest.TerminalObserved && manifest.TraversalComplete && missing == 0 && allRanges;
    const bool completeComparison = completeMembership && qualified && compared == s.ExpectedBytes && excluded == 0 && unreadable == 0;
    std::wstring unmet;
    if (missing != 0) { unmet += L"\"all_slice_entries_retained\","; }
    if (!manifest.TerminalObserved || !manifest.TraversalComplete) { unmet += L"\"completed_sweep_terminal\","; }
    if (!allRanges) { unmet += L"\"all_scheduled_ranges_observed\","; }
    if (!qualified) { unmet += L"\"stable_target_reference_qualification\","; }
    if (excluded != 0 || unreadable != 0) { unmet += L"\"full_byte_comparison\","; }
    if (rawFailures != 0) { unmet += L"\"all_raw_archives_published\","; }
    result.CurrentResult = L"{\"recipes_replayed\":" + N(manifest.Slices.size()) + L",\"missing_entries\":" + N(missing) +
        L",\"tail_unknown\":" + B(!manifest.TerminalObserved) + L",\"unobserved_ranges\":" + N(unobservedRanges) +
        L",\"raw_publication_failures\":" + N(rawFailures) + L",\"all_scheduled_ranges_replayed\":" + B(allRanges) +
        L",\"membership_complete\":" + B(completeMembership) + L",\"comparison_complete\":" + B(completeComparison) + L"}";
    result.Proof = L"{\"schema\":\"kn.image_sweep_proof.v1\",\"manifest_sha256\":" + mcpjson::Quote(result.ManifestSha256) +
        L",\"scope\":\"temporal_sweep_ranges\",\"reference_level\":\"R-retained\",\"reference_sha256\":" + mcpjson::Quote(referenceHash) +
        L",\"whole_sweep_complete\":" + B(completeComparison && rawFailures == 0) +
        L",\"executable_ranges_match_retained_reference\":" + B(completeComparison && changed == 0) +
        L",\"expected_bytes\":" + N(s.ExpectedBytes) + L",\"requested_bytes\":" + N(requested) +
        L",\"compared_bytes\":" + N(compared) + L",\"matching_bytes\":" + N(compared - changed) +
        L",\"changed_bytes\":" + N(changed) + L",\"excluded_bytes\":" + N(excluded) + L",\"unreadable_bytes\":" + N(unreadable) +
        L",\"unobserved_bytes\":" + N(s.ExpectedBytes - requested) +
        L",\"observed_elapsed_ms\":" + N(manifest.LastEndedTick - s.StartedTick) + L",\"target_identity_scope\":\"collector_declared\"" +
        L",\"recipe_evidence\":" + evidence + L"],\"unfulfilled_requirements\":[" + unmet + L"\"approved_reference_provenance\","
        L"\"atomic_mapping_lifetime\",\"execution_observation\"],\"atomic_snapshot\":false,\"collector_authenticated\":false,\"execution_observed\":false}";
    result.Status = L"replayed";
    if (verifiedEvidence != nullptr)
    {
        verified.Manifest = std::move(manifest);
        verified.ManifestSha256 = result.ManifestSha256;
        verified.ReferenceSha256 = std::move(referenceHash);
        *verifiedEvidence = std::move(verified);
    }
    if (error != nullptr) { error->clear(); }
    return result;
}
