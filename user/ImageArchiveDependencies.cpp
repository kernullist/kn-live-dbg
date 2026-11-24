#include "ImageArchiveDependencies.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "ImageClaimPublication.h"
#include "ImageScopeClaimPublication.h"
#include "ImageSweepManifest.h"
#include "ProcessImageSourceReceipt.h"

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

    // A verified recipe digest identifies the stored image input. Separately
    // compare the outcome the capture report attributed to that operation.
    std::wstring SourceClaimBinding(const std::wstring& status, const std::wstring& source, const std::wstring& target,
        const std::wstring& operation, const std::wstring& policy, const std::wstring& consistency, const std::wstring& result)
    {
        using mcpjson::Quote;
        const auto bytes = mcpjson::WideToUtf8(L"[" + Quote(status) + L"," + Quote(source) + L"," + Quote(target) +
            L"," + Quote(operation) + L"," + Quote(policy) + L"," + Quote(consistency) + L"," + result + L"]");
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }

    bool SourceInputs(const std::wstring& page, const EvidenceJournalMember& root, ImageArchiveCatalog& catalog, bool inspectRetention)
    {
        const auto id = ImageSourceReportCollection(root.Path, root.Sha256);
        if (id.empty()) { return false; }
        ProcessImageCaptureReport report;
        if (root.Schema != L"kn.image_capture.v3" || ParseProcessImageCaptureReport(page, report)) { return false; }
        catalog.CaptureStatus = report.CaptureStatus;
        catalog.SourceStatus = report.SourceStatus;
        if (inspectRetention) { catalog.SourcePriority = ReadImageSourcePriority(report.CaptureStatus, report.Result); }
        if (!report.Published()) { return true; }
        catalog.SourceClaimBinding = SourceClaimBinding(report.CaptureStatus, report.SourceId, report.TargetId, report.OperationId,
            report.Policy, report.Consistency, report.Result);
        return !catalog.SourceClaimBinding.empty() && AddInput(catalog, ImageSourceCasePath(id, root.Sha256), report.RecipeSha256, true) &&
            AddReference(catalog, report.ReferenceSha256);
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

std::wstring ImageSourceSessionJson(const std::wstring& id, const std::vector<EvidenceJournalMember>& members,
    const std::wstring& captureStatus, const std::wstring& sourceStatus)
{
    using bounded_observation_json::N;
    using mcpjson::Quote;
    const EvidenceJournalMember* report = nullptr;
    uint64_t bytes = 0;
    for (const auto& m : members)
    {
        if (m.Schema == L"kn.image_capture.v3") { report = &m; }
        bytes += m.Bytes;
    }
    if (!report || (members.size() != 1 && members.size() != 3)) { return {}; }
    return L"{\"schema\":" + Quote(ImageSourceCollectionLedger) + L",\"collection_id\":" + Quote(id) +
        L",\"report_path\":" + Quote(report->Path) + L",\"report_sha256\":" + Quote(report->Sha256) +
        L",\"capture_status\":" + Quote(captureStatus) + L",\"source_status\":" + Quote(sourceStatus) +
        L",\"archived_attempts\":\"1\",\"archived_claims\":" + N(members.size() == 3 ? 1 : 0) +
        L",\"logical_referenced_bytes\":" + N(bytes) +
        L",\"denominator_scope\":\"one_supplied_capture_report\",\"collector_authenticated\":false}";
}

ImageArchiveKind ImageArchiveKindForPath(const std::wstring& path)
{
    const auto dot = path.rfind(L'.');
    if (dot == std::wstring::npos) { return ImageArchiveKind::None; }
    if (path.rfind(L"image-captures/", 0) == 0 && path.compare(dot, std::wstring::npos, L".knsource") == 0) { return ImageArchiveKind::SourceReport; }
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
    const std::wstring& json, ImageArchiveCatalog& catalog, bool inspectRetention)
{
    IndexedObject record, claim;
    if (kind == ImageArchiveKind::SourceReport) { return SourceInputs(json, root, catalog, inspectRetention); }
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
            if (inspectRetention && schema == L"kn.image_reads.v3") { payload.Raw(L"retention", &catalog.RetentionTicket); }
            return !wrapped && ReadReference(payload, schema, catalog);
        }
        if (kind == ImageArchiveKind::Capture && root.Path.rfind(L"image-captures/case-", 0) == 0)
        {
            IndexedObject readSet;
            std::wstring cancelled, result;
            if (!wrapped || schema != L"kn.image_recipe.v3" || !payload.Raw(L"read_set", &raw) || !readSet.Parse(raw) ||
                !readSet.Raw(L"cancelled", &cancelled) || (cancelled != L"false" && cancelled != L"true") ||
                !payload.Raw(L"recorded_result", &result)) { return false; }
            catalog.SourceClaimBinding = SourceClaimBinding(cancelled == L"true" ? L"interrupted" : L"recorded",
                payload.String(L"source_id"), readSet.String(L"target_id"), readSet.String(L"operation_id"),
                payload.String(L"policy"), payload.String(L"source_consistency"), result);
            if (catalog.SourceClaimBinding.empty()) { return false; }
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
