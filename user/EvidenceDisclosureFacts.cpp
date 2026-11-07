#include "EvidenceDisclosure.h"
#include "ImageVerificationRecipe.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"

using namespace bounded_observation_json;
namespace
{
    bool Hex(const std::wstring& text, size_t length)
    {
        if (text.size() != length) { return false; }
        for (const auto c : text) { if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) { return false; } }
        return true;
    }
    std::wstring Raw(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value; mcpjson::FindRawValue(json, key, &value); return value;
    }
    std::wstring Field(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value; mcpjson::GetString(json, key, &value); return value;
    }
}
std::wstring DisclosureTextSha256(const std::wstring& text)
{
    if (mcpjson::SanitizeUtf16(text) != text) { return L""; }
    const auto bytes = mcpjson::WideToUtf8(text);
    ContentHash hash;
    return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
}
std::wstring NewDisclosureId()
{
    uint8_t bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { return L""; }
    std::wstring result;
    for (const auto c : bytes) { result += L"0123456789abcdef"[c >> 4]; result += L"0123456789abcdef"[c & 15]; }
    return result;
}
std::wstring MinimizedImageFactsJson(const MinimizedImageFacts& f)
{
    if (!Hex(f.Id, 32) || (f.Scope != L"explicit_range" && f.Scope != L"executed_slices" && f.Scope != L"temporal_sweep") ||
        (f.Extent == 0 && (f.Scope != L"executed_slices" || f.ReferenceQualified || f.ChangedKnown)) ||
        f.Compared > f.Extent || f.Excluded > f.Extent - f.Compared ||
        f.Unreadable > f.Extent - f.Compared - f.Excluded ||
        f.Unobserved != f.Extent - f.Compared - f.Excluded - f.Unreadable ||
        (f.ChangedKnown ? f.Changed > f.Compared : f.Changed != 0)) { return L""; }
    return L"{\"schema\":\"kn.minimized_image_facts.v1\",\"policy\":\"kn.image_counts_redaction.v1\",\"redaction_id\":" + mcpjson::Quote(f.Id) +
        L",\"scope\":" + mcpjson::Quote(f.Scope) + L",\"extent_bytes\":" + N(f.Extent) + L",\"compared_bytes\":" + N(f.Compared) +
        L",\"excluded_bytes\":" + N(f.Excluded) + L",\"unreadable_bytes\":" + N(f.Unreadable) + L",\"unobserved_bytes\":" + N(f.Unobserved) +
        L",\"changed_bytes\":" + (f.ChangedKnown ? N(f.Changed) : L"null") + L",\"reference_qualified\":" + B(f.ReferenceQualified) +
        L",\"reference_level\":\"retained_not_approved\",\"time_scope\":\"historical_non_atomic\",\"collector_authenticated\":false,"
        L"\"execution_observed\":false,\"maliciousness\":\"not_established\",\"omitted\":[\"raw_bytes\",\"addresses\",\"process_identity\","
        L"\"source_identity\",\"paths\",\"symbols\",\"artifact_hashes\",\"source_free_text\",\"acquisition_timestamps\"]}";
}
bool ParseMinimizedImageFacts(const std::wstring& json, MinimizedImageFacts* facts)
{
    if (!facts || json.size() > 4096 || !mcpjson::ValidateDocument(json)) { return false; }
    MinimizedImageFacts f;
    f.Id = Field(json, L"redaction_id"); f.Scope = Field(json, L"scope");
    if (!Number(json, L"extent_bytes", &f.Extent) || !Number(json, L"compared_bytes", &f.Compared) ||
        !Number(json, L"excluded_bytes", &f.Excluded) || !Number(json, L"unreadable_bytes", &f.Unreadable) ||
        !Number(json, L"unobserved_bytes", &f.Unobserved) || !Boolean(json, L"reference_qualified", &f.ReferenceQualified)) { return false; }
    f.ChangedKnown = Raw(json, L"changed_bytes") != L"null";
    if (f.ChangedKnown && !Number(json, L"changed_bytes", &f.Changed)) { return false; }
    if (MinimizedImageFactsJson(f) != json) { return false; }
    *facts = std::move(f); return true;
}
bool ProjectImageDisclosure(const ImageRecipeReplay& replay, const std::wstring& id, MinimizedImageFacts* facts)
{
    if (!facts || replay.Status != L"replayed" || replay.Mode != L"original_policy" ||
        replay.Proof.size() > ImageRecipeMaxBytes || !mcpjson::ValidateDocument(replay.Proof)) { return false; }
    MinimizedImageFacts f; f.Id = id;
    const auto& p = replay.Proof;
    const auto schema = Field(p, L"schema");
    if (schema == L"kn.image_slice_proof.v1" || schema == L"kn.image_sweep_proof.v1")
    {
        f.Scope = schema == L"kn.image_slice_proof.v1" ? L"executed_slices" : L"temporal_sweep";
        if (!Number(p, L"requested_bytes", &f.Extent) || !Number(p, L"compared_bytes", &f.Compared) ||
            !Number(p, L"excluded_bytes", &f.Excluded) || !Number(p, L"unreadable_bytes", &f.Unreadable) ||
            !Number(p, L"changed_bytes", &f.Changed)) { return false; }
        f.ChangedKnown = f.Compared != 0;
        if (f.Scope == L"temporal_sweep")
        {
            uint64_t expected = 0;
            if (!Number(p, L"unobserved_bytes", &f.Unobserved) || !Number(p, L"expected_bytes", &expected) ||
                expected < f.Extent || expected - f.Extent != f.Unobserved) { return false; }
            f.Extent = expected;
            std::vector<std::wstring> requirements;
            if (!Array(p, L"unfulfilled_requirements", 32, &requirements)) { return false; }
            f.ReferenceQualified = true;
            for (const auto& requirement : requirements)
            {
                if (requirement == L"\"stable_target_reference_qualification\"") { f.ReferenceQualified = false; }
            }
        }
        else if (!Boolean(p, L"target_reference_qualified", &f.ReferenceQualified)) { return false; }
    }
    else if (schema == L"kn.image_proof.v1")
    {
        f.Scope = L"explicit_range";
        const auto ledgers = Raw(p, L"ledgers"), address = Raw(ledgers, L"address"), semantic = Raw(ledgers, L"semantic");
        if (!Number(address, L"requested_bytes", &f.Extent) || !Number(address, L"compared_bytes", &f.Compared) ||
            !Number(address, L"skipped_bytes", &f.Excluded) || !Number(address, L"failed_bytes", &f.Unreadable) ||
            !Number(address, L"unvisited_bytes", &f.Unobserved) || !Boolean(semantic, L"mapped_identity_qualified", &f.ReferenceQualified)) { return false; }
        std::vector<std::wstring> claims;
        if (!Array(p, L"claims", 2, &claims) || claims.size() != 2) { return false; }
        for (const auto& claim : claims)
        {
            if (Field(claim, L"status") != L"supported") { continue; }
            const auto name = Field(claim, L"name");
            if (name == L"recorded_range_matches_reference_policy") { f.ChangedKnown = true; }
            else if (name == L"recorded_range_differs_reference_policy")
            {
                std::vector<std::wstring> ranges;
                if (!Array(claim, L"ranges", 4096, &ranges)) { return false; }
                for (const auto& range : ranges)
                {
                    uint64_t length = 0;
                    if (!Number(range, L"length", &length) || length == 0 || length > f.Compared - f.Changed) { return false; }
                    f.Changed += length;
                }
                f.ChangedKnown = !ranges.empty();
            }
        }
    }
    else { return false; }
    if (MinimizedImageFactsJson(f).empty()) { return false; }
    *facts = std::move(f); return true;
}
