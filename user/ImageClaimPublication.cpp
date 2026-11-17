#include "ImageClaimPublication.h"
#include "ImageProof.h"
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
    bool Inputs(const std::wstring& recipe, const std::wstring& report, ImageClaimPublication* out)
    {
        if (!out || recipe.size() > ImageRecipeMaxBytes || report.size() > ImageClaimMaximumCharacters ||
            !mcpjson::ValidateDocument(report) || !ParseImageRecipe(recipe, &out->Recipe, nullptr) ||
            Field(report, L"schema") != L"kn.image_claim_report.v1" ||
            Field(report, L"capture_sha256") != Field(recipe, L"recipe_sha256") ||
            Field(report, L"reference_sha256") != out->Recipe.ReferenceSha256 ||
            !bounded_observation_json::Text(Field(report, L"registry"), 128) ||
            !bounded_observation_json::Text(Field(report, L"policy"), 128)) { return false; }
        out->RecipeJson = recipe; out->ReportJson = report; out->ReportSha256 = Hash(report);
        out->Registry = Field(report, L"registry"); out->Policy = Field(report, L"policy");
        return !out->ReportSha256.empty();
    }
}

std::wstring ImageClaimPublicationJson(const std::wstring& recipe, const std::wstring& report)
{
    ImageClaimPublication parsed;
    if (!Inputs(recipe, report, &parsed)) { return {}; }
    const auto payload = L"{\"recipe\":" + recipe + L",\"recorded_claim\":" + report + L"}";
    const auto digest = Hash(payload);
    if (digest.empty()) { return {}; }
    const auto json = L"{\"schema\":" + mcpjson::Quote(ImageClaimPublicationSchema) +
        L",\"publication_sha256\":" + mcpjson::Quote(digest) + L",\"payload\":" + payload + L"}";
    return mcpjson::WideToUtf8(json).size() <= ImageClaimPublicationMaxBytes ? json : L"";
}

bool ParseImageClaimPublication(const std::wstring& json, ImageClaimPublication* publication, std::wstring* error)
{
    if (error) { *error = L"image claim publication is missing, corrupt, unbound or noncanonical"; }
    if (publication) { *publication = {}; }
    std::wstring payload, recipe, report;
    ImageClaimPublication parsed;
    if (!publication || json.size() > ImageClaimPublicationMaxBytes || !mcpjson::ValidateDocument(json) ||
        Field(json, L"schema") != ImageClaimPublicationSchema ||
        !mcpjson::FindRawValue(json, L"payload", &payload) ||
        !mcpjson::FindRawValue(payload, L"recipe", &recipe) || !mcpjson::FindRawValue(payload, L"recorded_claim", &report) ||
        !Inputs(recipe, report, &parsed) || ImageClaimPublicationJson(recipe, report) != json) { return false; }
    parsed.Sha256 = Field(json, L"publication_sha256");
    *publication = std::move(parsed);
    if (error) { error->clear(); }
    return true;
}
