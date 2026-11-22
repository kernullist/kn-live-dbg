#include "ImageArchiveDependencies.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "ImageClaimPublication.h"
#include "ImageScopeClaimPublication.h"
#include "ImageSweepManifest.h"

using bounded_observation_json::IndexedObject;

namespace
{
    bool Digest(const std::wstring& hash)
    {
        return hash.size() == 64 && hash.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }

    bool SealedPayload(const IndexedObject& root, const wchar_t* field, std::wstring& payload, std::wstring& digest)
    {
        digest = root.String(field);
        if (!Digest(digest) || !root.Raw(L"payload", &payload)) { return false; }
        const auto bytes = mcpjson::WideToUtf8(payload);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) && hash.Finish() == digest;
    }

    bool AddInput(ImageArchiveCatalog& catalog, const std::wstring& path, const std::wstring& hash,
        bool payloadDigest = false, uint64_t bytes = 0)
    {
        if (!Digest(hash)) { return false; }
        const auto added = catalog.Inputs.emplace(path, ImageArchiveInput{hash, bytes, payloadDigest});
        const auto& first = added.first->second;
        return first.Sha256 == hash && first.Bytes == bytes && first.PayloadDigest == payloadDigest;
    }

    bool AddReference(ImageArchiveCatalog& catalog, const std::wstring& hash, uint64_t bytes = 0)
    {
        return AddInput(catalog, L"image-references/" + hash + L".knblob", hash, false, bytes);
    }

    bool ReadReference(const IndexedObject& payload, const std::wstring& schema, ImageArchiveCatalog& catalog)
    {
        std::wstring raw;
        // v1 has no reference. The v3 writer can also record slice inputs without a reference.
        if (!payload.Raw(L"reference", &raw)) { return schema != L"kn.image_reads.v2"; }
        IndexedObject reference;
        if (schema == L"kn.image_reads.v1" || !reference.Parse(raw)) { return false; }
        const auto state = reference.String(L"persistence");
        if (state == L"failed" || state == L"not_captured" || state == L"not_attempted") { return true; }
        if (state != L"committed" || (reference.Raw(L"store", &raw) && reference.String(L"store") != L"image-references")) { return false; }
        uint64_t bytes = 0;
        if (reference.Raw(L"bytes", &raw))
        {
            if (raw.empty() || raw.size() > 8 || raw.find_first_not_of(L"0123456789") != std::wstring::npos) { return false; }
            for (const auto ch : raw) { bytes = bytes * 10 + (ch - L'0'); }
            if (!bytes || bytes > 64ull * 1024 * 1024) { return false; }
        }
        return AddReference(catalog, reference.String(L"sha256"), bytes);
    }

    bool SweepInputs(const std::wstring& json, const std::wstring& path, ImageArchiveCatalog& catalog, std::wstring& firstReference)
    {
        ImageSweepManifest manifest;
        if (!ParseImageSweepManifest(json, &manifest) || path != L"image-sweeps/sweep-" + manifest.Sweep.SweepId + L".knsweep")
            { return false; }
        catalog.SweepHasGap = !manifest.TerminalObserved || !manifest.TraversalComplete || manifest.Inconsistent ||
            manifest.Slices.empty() || manifest.ObservedSlices != manifest.Slices.size();
        if (!manifest.Slices.empty()) { firstReference = manifest.Slices.front().ReferenceSha256; }
        uint32_t nextRange = 0;
        for (const auto& row : manifest.Slices)
        {
            catalog.SweepHasGap |= !row.ReferenceWritten || !row.RawWritten || !row.RecipeWritten ||
                !row.RangeCount || row.StartRange != nextRange;
            nextRange = row.StartRange + row.RangeCount;
            const auto prefix = L"image-reads/reads-" + manifest.Sweep.CollectionId + L"-" + std::to_wstring(row.ReadSetId);
            if ((row.ReferenceWritten && !AddReference(catalog, row.ReferenceSha256)) ||
                (row.RawWritten && !AddInput(catalog, prefix + L".knreads", row.RawPayloadSha256, true)) ||
                (row.RecipeWritten && !AddInput(catalog, prefix + L".knslice", row.RecipeSha256, true))) { return false; }
        }
        catalog.SweepHasGap |= nextRange != manifest.Sweep.TotalRanges;
        return true;
    }
}

ImageArchiveKind ImageArchiveKindForPath(const std::wstring& path)
{
    const auto dot = path.rfind(L'.');
    if (dot == std::wstring::npos) { return ImageArchiveKind::None; }
    if (path.rfind(L"image-captures/", 0) == 0 && path.compare(dot, std::wstring::npos, L".kncapture") == 0) { return ImageArchiveKind::Capture; }
    if (path.rfind(L"image-sweeps/", 0) == 0 && path.compare(dot, std::wstring::npos, L".knsweep") == 0) { return ImageArchiveKind::Sweep; }
    if (path.rfind(L"image-reads/", 0) == 0)
    {
        if (path.compare(dot, std::wstring::npos, L".knreads") == 0) { return ImageArchiveKind::Reads; }
        if (path.compare(dot, std::wstring::npos, L".knslice") == 0) { return ImageArchiveKind::Slice; }
    }
    return ImageArchiveKind::None;
}

bool ReadImageArchiveCatalog(ImageArchiveKind kind, const EvidenceJournalMember& root,
    const std::wstring& json, ImageArchiveCatalog& catalog, bool includeReadTicket)
{
    IndexedObject record, claim;
    if (!record.Parse(json) || record.String(L"schema") != root.Schema) { return false; }
    const bool wrapped = root.Schema == ImageClaimPublicationSchema || root.Schema == ImageScopeClaimPublicationSchema;
    std::wstring inner;
    if (wrapped)
    {
        IndexedObject publication;
        std::wstring payload, seal, report;
        if ((root.Schema == ImageClaimPublicationSchema) != (kind == ImageArchiveKind::Capture) ||
            !SealedPayload(record, L"publication_sha256", payload, seal) || !publication.Parse(payload) ||
            !publication.Raw(kind == ImageArchiveKind::Capture ? L"recipe" : L"artifact", &inner) ||
            !publication.Raw(L"recorded_claim", &report) || !claim.Parse(report) || claim.String(L"schema") != L"kn.image_claim_report.v1" ||
            !record.Parse(inner)) { return false; }
    }
    const auto schema = record.String(L"schema");
    std::wstring reference;
    if (kind == ImageArchiveKind::Sweep)
    {
        if (schema != L"kn.image_sweep.v1" || !SweepInputs(wrapped ? inner : json, root.Path, catalog, reference)) { return false; }
        catalog.PayloadSha256 = record.String(L"manifest_sha256");
    }
    else
    {
        const bool reads = kind == ImageArchiveKind::Reads;
        if ((reads && schema != L"kn.image_reads.v1" && schema != L"kn.image_reads.v2" && schema != L"kn.image_reads.v3") ||
            (kind == ImageArchiveKind::Capture && schema != L"kn.image_recipe.v1" && schema != L"kn.image_recipe.v2" && schema != L"kn.image_recipe.v3") ||
            (kind == ImageArchiveKind::Slice && schema != L"kn.image_slice.v1" && schema != L"kn.image_slice.v2") || kind == ImageArchiveKind::None)
            { return false; }
        std::wstring raw;
        IndexedObject payload;
        if (!SealedPayload(record, reads ? L"payload_sha256" : L"recipe_sha256", raw, catalog.PayloadSha256) || !payload.Parse(raw)) { return false; }
        if (reads)
        {
            if (includeReadTicket && schema == L"kn.image_reads.v3") { payload.Raw(L"retention", &catalog.RetentionTicket); }
            return !wrapped && ReadReference(payload, schema, catalog);
        }
        reference = payload.String(L"reference_sha256");
        if (!AddReference(catalog, reference)) { return false; }
    }
    return !wrapped || (claim.String(L"capture_sha256") == catalog.PayloadSha256 && claim.String(L"reference_sha256") == reference &&
        (kind == ImageArchiveKind::Capture || claim.String(L"scope") ==
            (kind == ImageArchiveKind::Sweep ? L"temporal_sweep_schedule" : L"executed_slice_ranges")));
}

bool MatchesImageArchiveInput(const ImageArchiveInput& input, const EvidenceJournalMember& member, const std::wstring& payloadSha256)
{
    return input.Sha256 == (input.PayloadDigest ? payloadSha256 : member.Sha256) && (!input.Bytes || input.Bytes == member.Bytes);
}
