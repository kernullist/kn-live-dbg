#include "ImageScopeClaimPublication.h"
#include "ImageScopeClaims.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"

namespace
{
    std::wstring Field(const std::wstring& json, const wchar_t* name)
    { std::wstring value; mcpjson::GetString(json, name, &value); return value; }
    std::wstring Hash(const std::wstring& text)
    {
        if (mcpjson::SanitizeUtf16(text) != text) { return {}; }
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }
    bool Inputs(const std::wstring& artifact, const std::wstring& report, ImageScopeClaimPublication* out)
    {
        if (!out || artifact.size() > ImageRecipeMaxBytes || report.size() > ImageScopeClaimMaximumCharacters ||
            !mcpjson::ValidateDocument(report) || Field(report, L"schema") != L"kn.image_claim_report.v1" ||
            !bounded_observation_json::Text(Field(report, L"registry"), 128) ||
            !bounded_observation_json::Text(Field(report, L"policy"), 128)) { return false; }
        out->Sweep = Field(artifact, L"schema") == L"kn.image_sweep.v1";
        ImageSliceRecipe slice;
        ImageSweepManifest sweep;
        if (out->Sweep ? !ParseImageSweepManifest(artifact, &sweep) : !ParseImageSliceRecipe(artifact, &slice)) { return false; }
        if (Field(report, L"capture_sha256") != Field(artifact, out->Sweep ? L"manifest_sha256" : L"recipe_sha256") ||
            Field(report, L"scope") != (out->Sweep ? L"temporal_sweep_schedule" : L"executed_slice_ranges") ||
            Field(report, L"reference_sha256") != (out->Sweep ?
                (sweep.Slices.empty() ? L"" : sweep.Slices.front().ReferenceSha256) : slice.ReferenceSha256)) { return false; }
        out->ArtifactJson = artifact; out->ReportJson = report; out->ReportSha256 = Hash(report);
        out->Registry = Field(report, L"registry"); out->Policy = Field(report, L"policy");
        return !out->ReportSha256.empty();
    }
}

std::wstring ImageScopeClaimPublicationJson(const std::wstring& artifact, const std::wstring& report)
{
    ImageScopeClaimPublication parsed;
    if (!Inputs(artifact, report, &parsed)) { return {}; }
    const auto payload = L"{\"artifact\":" + artifact + L",\"recorded_claim\":" + report + L"}";
    const auto digest = Hash(payload);
    if (digest.empty()) { return {}; }
    const auto json = L"{\"schema\":" + mcpjson::Quote(ImageScopeClaimPublicationSchema) +
        L",\"publication_sha256\":" + mcpjson::Quote(digest) + L",\"payload\":" + payload + L"}";
    return mcpjson::WideToUtf8(json).size() <= ImageScopeClaimPublicationMaxBytes ? json : L"";
}

bool ParseImageScopeClaimPublication(const std::wstring& json, ImageScopeClaimPublication* publication)
{
    if (publication) { *publication = {}; }
    std::wstring payload, artifact, report;
    ImageScopeClaimPublication parsed;
    if (!publication || json.size() > ImageScopeClaimPublicationMaxBytes || !mcpjson::ValidateDocument(json) ||
        Field(json, L"schema") != ImageScopeClaimPublicationSchema ||
        !mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::FindRawValue(payload, L"artifact", &artifact) ||
        !mcpjson::FindRawValue(payload, L"recorded_claim", &report) || !Inputs(artifact, report, &parsed) ||
        ImageScopeClaimPublicationJson(artifact, report) != json) { return false; }
    parsed.Sha256 = Field(json, L"publication_sha256");
    *publication = std::move(parsed);
    return true;
}

bool UnwrapImageScopeClaimPublication(std::wstring* json, ImageScopeClaimPublication* publication)
{
    if (!json || !publication) { return false; }
    *publication = {};
    if (Field(*json, L"schema") != ImageScopeClaimPublicationSchema) { return true; }
    if (!ParseImageScopeClaimPublication(*json, publication)) { return false; }
    *json = publication->ArtifactJson;
    return true;
}

bool ReproduceImageScopeClaim(const ImageScopeClaimPublication& p, ImageRecipeReplay* r)
{
    if (!r || r->Status != L"replayed") { return false; }
    if (p.Sha256.empty()) { return true; } // Legacy: original claim was not recorded.
    r->ClaimPublicationSha256 = p.Sha256; r->RecordedClaimSha256 = p.ReportSha256;
    r->RecordedClaimRegistry = p.Registry; r->RecordedClaimPolicy = p.Policy;
    if (p.Registry != L"kn.claim_registry.v1" ||
        p.Policy != (p.Sweep ? L"kn.image_claim_policy.sweep.v1" : L"kn.image_claim_policy.slice.v1"))
    {
        r->Status = L"recorded_claim_policy_unavailable"; r->OriginalClaimStatus = L"policy_unavailable";
    }
    else if (r->ClaimAssessmentJson.empty() || r->ClaimAssessmentJson != p.ReportJson)
    {
        r->Status = L"recorded_claim_assessment_mismatch"; r->OriginalClaimStatus = L"assessment_mismatch";
    }
    else { r->OriginalClaimStatus = L"reproduced"; return true; }
    r->Proof.clear(); r->ClaimAssessmentJson.clear(); r->CurrentResult.clear();
    return false;
}
