#include "ImageCaptureCollection.h"
#include "ImageClaimPublication.h"
#include "ReferenceArtifact.h"
#include "SchemaArtifact.h"
#include "EvidencePrivacy.h"
#include "EvidenceStore.h"
#include "BoundedObservationJson.h"
#include "EvidenceArtifactPublication.h"
#include <filesystem>

using namespace bounded_observation_json;
using namespace evidence_artifact_publication;
namespace fs = std::filesystem;
namespace
{
    std::wstring Ledger(const ImageCaptureCollection& r)
    {
        return L"{\"schema\":" + mcpjson::Quote(DirectImageCollectionLedger) + L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) +
            L",\"capture_path\":" + mcpjson::Quote(r.CapturePath) + L",\"capture_sha256\":" + mcpjson::Quote(r.CaptureSha256) +
            L",\"reference_sha256\":" + mcpjson::Quote(r.ReferenceSha256) + L",\"capture_bytes\":" + N(r.CaptureBytes) +
            L",\"reference_bytes\":" + N(r.ReferenceBytes) + L",\"archived_captures\":\"1\",\"logical_referenced_bytes\":" +
            N(r.CaptureBytes + r.ReferenceBytes) + L",\"original_claim_recorded\":" + B(r.OriginalClaimRecorded) +
            L",\"denominator_scope\":\"one_archived_capture\",\"original_live_attempts_known\":false,"
            L"\"semantic_replay_established\":false,\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
    }
}

ImageCaptureCollection JournalImageCapture(const std::wstring& caseDirectory, const std::wstring& privateStore,
    const std::wstring& collectionId, const std::function<void(const wchar_t*)>& observer)
{
    ImageCaptureCollection out;
    out.CollectionId = collectionId;
    const auto fail = [&](const wchar_t* issue) { out.Issue = issue; return out; };
    const auto stage = [&](const wchar_t* name) { if (observer) { observer(name); } };
    try
    {
        if (collectionId.empty() || collectionId.size() > 20 || collectionId.find_first_not_of(L"0123456789") != std::wstring::npos ||
            (collectionId.size() > 1 && collectionId.front() == L'0')) { return fail(L"invalid_collection_id"); }
        ReferenceArtifact capture, reference;
        if (!capture.Open((fs::path(caseDirectory) / L"recipe.knverify").wstring(), nullptr, DirectImageCaptureMaxBytes))
            { return fail(L"capture_unavailable"); }
        const auto& raw = capture.Bytes();
        const auto json = mcpjson::Utf8ToWide(std::string(raw.begin(), raw.end()));
        ImageVerificationRecipe recipe;
        ImageClaimPublication publication;
        std::wstring schema;
        if (!mcpjson::GetString(json, L"schema", &schema)) { return fail(L"capture_invalid"); }
        if (schema == ImageClaimPublicationSchema)
        {
            if (!ParseImageClaimPublication(json, &publication, nullptr)) { return fail(L"capture_invalid"); }
            recipe = publication.Recipe;
            out.OriginalClaimRecorded = true;
        }
        else if (!ParseImageRecipe(json, &recipe, nullptr)) { return fail(L"capture_invalid"); }
        if (!reference.Open((fs::path(caseDirectory) / (recipe.ReferenceSha256 + L".knblob")).wstring(), nullptr) ||
            reference.Sha256() != recipe.ReferenceSha256) { return fail(L"reference_missing_or_corrupt"); }
        out.CaptureSha256 = capture.Sha256(); out.CaptureBytes = raw.size();
        out.ReferenceSha256 = reference.Sha256(); out.ReferenceBytes = reference.Bytes().size();
        out.CapturePath = L"image-captures/capture-" + collectionId + L"-" + out.CaptureSha256 + L".kncapture";
        const auto referencePath = L"image-references/" + out.ReferenceSha256 + L".knblob";
        EvidencePrivacyGuard privacy;
        EvidencePrivacyReport protection;
        if (!privacy.Open(privateStore, false, &protection)) { return fail(L"private_store_unavailable"); }
        const fs::path root(protection.RootPath);
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(root.wstring(), false, &out.Issue)) { return out; }
        EvidenceJournal journal;
        if (!journal.Open(root.wstring(), collectionId, &out.Issue, EvidenceJournalPolicy::DirectImageV1,
            [&](HANDLE file) { return privacy.CheckFile(file); })) { return out; }
        if (!journal.State().DirectCapturePaths.empty() &&
            journal.State().DirectCapturePaths != std::vector<std::wstring>{out.CapturePath})
            { return fail(L"collection_contains_different_capture"); }
        out.CaptureCommitted = !journal.State().DirectCapturePaths.empty();
        out.Closed = journal.State().Closed; out.HeadSha256 = journal.State().HeadSha256;
        out.Status = L"incomplete";
        stage(L"session");
        auto references = PinFolder(root / L"image-references"), captures = PinFolder(root / L"image-captures");
        if (!references || !captures) { return fail(L"capture_store_directory_unavailable"); }
        std::unique_ptr<SchemaArtifact> referenceLease, captureLease, ledgerLease;
        if (!Retain(root / referencePath, reference.Bytes(), out.ReferenceSha256, privacy, &referenceLease, &out.ReferenceCreated))
            { return fail(L"reference_publication_or_verification_failed"); }
        stage(L"reference");
        if (!Retain(root / out.CapturePath, raw, out.CaptureSha256, privacy, &captureLease, &out.CaptureCreated))
            { return fail(L"capture_publication_or_verification_failed"); }
        stage(L"capture");
        if (!capture.Unchanged() || !reference.Unchanged()) { return fail(L"source_artifact_changed"); }
        EvidenceJournalTransaction transaction;
        transaction.Kind = L"image_capture"; transaction.Id = out.CaptureSha256;
        transaction.Members = {{out.CapturePath, out.CaptureSha256, schema, out.CaptureBytes},
            {referencePath, out.ReferenceSha256, L"raw.bytes", out.ReferenceBytes}};
        const auto committed = journal.Commit(transaction);
        out.CaptureCommitted = committed.Committed; out.HeadSha256 = journal.State().HeadSha256;
        if (!committed.Committed || !committed.Indexed) { out.Issue = committed.Issue; return out; }
        stage(L"capture_commit");
        const auto ledgerPath = L"image-captures/session-" + collectionId + L".kncaptureledger";
        const auto ledger = Ledger(out);
        const auto encoded = mcpjson::WideToUtf8(ledger);
        const std::vector<uint8_t> bytes(encoded.begin(), encoded.end());
        bool ledgerCreated = false;
        if (!Retain(root / ledgerPath, bytes, ContentHash::Bytes(bytes), privacy, &ledgerLease, &ledgerCreated))
            { return fail(L"ledger_publication_or_verification_failed"); }
        stage(L"ledger");
        EvidenceJournalTransaction closure;
        closure.Kind = L"closure"; closure.Id = L"0";
        closure.Members = {EvidenceJournalJsonMember(ledgerPath, ledger)};
        closure.Requires = {out.CapturePath, referencePath};
        const auto closed = journal.Commit(std::move(closure));
        out.Closed = journal.State().Closed; out.HeadSha256 = journal.State().HeadSha256;
        out.Indexed = closed.Committed && closed.Indexed;
        if (!out.Closed || !out.Indexed) { out.Issue = closed.Issue; return out; }
        out.Status = L"archived"; out.Issue.clear();
        stage(L"closed");
        return out;
    }
    catch (...) { return fail(L"capture_collection_exception"); }
}

std::wstring ImageCaptureCollectionJson(const ImageCaptureCollection& r)
{
    return L"{\"schema\":\"kn.image_capture_collection.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) +
        L",\"capture_path\":" + mcpjson::Quote(r.CapturePath) + L",\"capture_sha256\":" + mcpjson::Quote(r.CaptureSha256) +
        L",\"reference_sha256\":" + mcpjson::Quote(r.ReferenceSha256) + L",\"head_sha256\":" + mcpjson::Quote(r.HeadSha256) +
        L",\"capture_bytes\":" + N(r.CaptureBytes) + L",\"reference_bytes\":" + N(r.ReferenceBytes) +
        L",\"capture_committed\":" + B(r.CaptureCommitted) + L",\"closed\":" + B(r.Closed) + L",\"indexed\":" + B(r.Indexed) +
        L",\"capture_created\":" + B(r.CaptureCreated) + L",\"reference_created\":" + B(r.ReferenceCreated) +
        L",\"original_claim_recorded\":" + B(r.OriginalClaimRecorded) + L",\"denominator_scope\":\"current_archive_invocation\","
        L"\"source_directory_privacy_changed\":false,\"semantic_replay_established\":false,\"collector_authenticated\":false,"
        L"\"power_loss_durability_established\":false}";
}
