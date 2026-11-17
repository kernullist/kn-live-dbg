#include "ImageApprovalCollection.h"
#include "ImageAuthorizedChanges.h"
#include "ImageCaptureCollection.h"
#include "ImageClaimPublication.h"
#include "EvidenceArtifactPublication.h"
#include "EvidenceStore.h"
#include "BoundedObservationJson.h"
#include <filesystem>

using namespace bounded_observation_json;
using namespace evidence_artifact_publication;
namespace fs = std::filesystem;
namespace
{
    bool Digest(const std::wstring& value)
    { return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }
    bool Id(const std::wstring& value)
    { return !value.empty() && value.size() <= 20 && value.find_first_not_of(L"0123456789") == std::wstring::npos && (value.size() == 1 || value[0] != L'0'); }
    std::wstring S(const std::wstring& json, const wchar_t* key)
    { std::wstring out; mcpjson::GetString(json, key, &out); return out; }
    std::vector<uint8_t> Bytes(const std::wstring& json)
    { const auto utf8 = mcpjson::WideToUtf8(json); return {utf8.begin(), utf8.end()}; }
    bool Text(const ReferenceArtifact& artifact, std::wstring* json)
    {
        const auto& raw = artifact.Bytes();
        const std::string utf8(raw.begin(), raw.end());
        *json = mcpjson::Utf8ToWide(utf8);
        return mcpjson::WideToUtf8(*json) == utf8 && mcpjson::ValidateDocument(*json);
    }
    uint64_t Now()
    { FILETIME now{}; GetSystemTimeAsFileTime(&now); return (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime; }
    std::wstring CapturePath(const ImageApprovalPublication& p)
    { return L"image-captures/capture-" + p.CollectionId + L"-" + p.CaptureSha256 + L".kncapture"; }
    std::wstring ReferencePath(const ImageApprovalPublication& p)
    { return L"image-references/" + p.ReferenceSha256 + L".knblob"; }
    std::wstring PolicyPath(const ImageApprovalPublication& p)
    { return L"image-approvals/policy-" + p.PolicySha256 + L".knapproval"; }
    std::wstring ManifestPath(const ImageApprovalPublication& p)
    { return L"image-approvals/changes-" + p.ManifestSha256 + L".knchange"; }
    std::wstring ApprovalPath(const std::wstring& id)
    { return L"image-approvals/assessment-" + id + L".knapprovalcase"; }
    struct Source
    {
        ReferenceArtifact Capture, Reference;
        std::wstring Schema, ReplayInput, RecipeSha256, PublicationSha256;
        bool Open(const std::wstring& input)
        {
            const fs::path root(input);
            auto extension = root.extension().wstring();
            std::transform(extension.begin(), extension.end(), extension.begin(), towlower);
            const bool managed = extension == L".kncapture";
            if (!Capture.Open((managed ? root : root / L"recipe.knverify").wstring(), nullptr, DirectImageCaptureMaxBytes)) { return false; }
            std::wstring json;
            if (!Text(Capture, &json)) { return false; }
            Schema = S(json, L"schema");
            ImageVerificationRecipe recipe;
            if (Schema == ImageClaimPublicationSchema)
            {
                ImageClaimPublication publication;
                if (!ParseImageClaimPublication(json, &publication, nullptr)) { return false; }
                RecipeSha256 = S(publication.RecipeJson, L"recipe_sha256");
                PublicationSha256 = publication.Sha256;
                recipe = std::move(publication.Recipe);
            }
            else
            {
                if (!ParseImageRecipe(json, &recipe, nullptr)) { return false; }
                RecipeSha256 = S(json, L"recipe_sha256");
            }
            // Resolve the handle's concrete path once. Reusing the caller's
            // directory alias could assess a different capture after retargeting.
            const fs::path concrete(Capture.Path());
            ReplayInput = managed ? concrete.wstring() : concrete.parent_path().wstring();
            const auto directory = managed ? concrete.parent_path().parent_path() / L"image-references" : concrete.parent_path();
            return Reference.Open((directory / (recipe.ReferenceSha256 + L".knblob")).wstring(), nullptr) &&
                Reference.Sha256() == recipe.ReferenceSha256;
        }
        bool Unchanged() { return Capture.Unchanged() && Reference.Unchanged(); }
        bool MatchesAssessment(const std::wstring& assessment) const
        {
            std::wstring replay, claim;
            return mcpjson::FindRawValue(assessment, L"replay", &replay) &&
                mcpjson::FindRawValue(replay, L"original_claim_replay", &claim) &&
                S(replay, L"recipe_sha256") == RecipeSha256 && S(claim, L"publication_sha256") == PublicationSha256;
        }
    };
    bool Valid(const ImageApprovalPublication& p)
    {
        bool approved = false;
        uint64_t evaluated = 0;
        return Id(p.CollectionId) && Digest(p.CaptureSha256) && Digest(p.ReferenceSha256) && Digest(p.PolicySha256) &&
            Digest(p.ManifestSha256) && p.EvaluationFileTime && p.Assessment.size() <= ImageApprovalPublicationMaxBytes &&
            mcpjson::ValidateDocument(p.Assessment) && S(p.Assessment, L"schema") == L"kn.image_change_assessment.v1" &&
            S(p.Assessment, L"status") == L"assessed" && S(p.Assessment, L"issue").empty() &&
            S(p.Assessment, L"policy_anchor_sha256") == p.PolicySha256 && S(p.Assessment, L"policy_sha256") == p.PolicySha256 &&
            S(p.Assessment, L"manifest_sha256") == p.ManifestSha256 && S(p.Assessment, L"reference_sha256") == p.ReferenceSha256 &&
            S(p.Assessment, L"clock_basis") == L"caller_supplied_time" &&
            Number(p.Assessment, L"evaluation_filetime", &evaluated) && evaluated == p.EvaluationFileTime &&
            Boolean(p.Assessment, L"reference_approved", &approved) && approved;
    }
    std::wstring Ledger(const ImageApprovalCollection& r)
    {
        return L"{\"schema\":" + mcpjson::Quote(ImageApprovalCollectionLedger) + L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) +
            L",\"approval_path\":" + mcpjson::Quote(r.ApprovalPath) + L",\"approval_sha256\":" + mcpjson::Quote(r.ApprovalSha256) +
            L",\"capture_path\":" + mcpjson::Quote(r.CapturePath) + L",\"capture_sha256\":" + mcpjson::Quote(r.CaptureSha256) +
            L",\"reference_sha256\":" + mcpjson::Quote(r.ReferenceSha256) + L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) +
            L",\"manifest_sha256\":" + mcpjson::Quote(r.ManifestSha256) + L",\"archived_assessments\":\"1\",\"logical_referenced_bytes\":" +
            N(r.CaptureBytes + r.ReferenceBytes + r.PolicyBytes + r.ManifestBytes + r.ApprovalBytes) +
            L",\"denominator_scope\":\"one_archived_assessment\",\"original_live_attempts_known\":false,"
            L"\"collector_authenticated\":false,\"current_approval_established\":false,\"power_loss_durability_established\":false}";
    }
}

std::wstring ImageApprovalPublicationJson(const ImageApprovalPublication& p)
{
    if (!Valid(p)) { return {}; }
    const auto payload = L"{\"collection_id\":" + mcpjson::Quote(p.CollectionId) + L",\"capture_sha256\":" + mcpjson::Quote(p.CaptureSha256) +
        L",\"reference_sha256\":" + mcpjson::Quote(p.ReferenceSha256) + L",\"policy_sha256\":" + mcpjson::Quote(p.PolicySha256) +
        L",\"manifest_sha256\":" + mcpjson::Quote(p.ManifestSha256) + L",\"evaluation_filetime\":" + N(p.EvaluationFileTime) +
        L",\"assessment\":" + p.Assessment + L"}";
    const auto digest = ContentHash::Bytes(Bytes(payload));
    if (digest.empty()) { return {}; }
    const auto json = L"{\"schema\":" + mcpjson::Quote(ImageApprovalPublicationSchema) + L",\"publication_sha256\":" +
        mcpjson::Quote(digest) + L",\"payload\":" + payload + L"}";
    return Bytes(json).size() <= ImageApprovalPublicationMaxBytes ? json : L"";
}

bool ParseImageApprovalPublication(const std::wstring& json, ImageApprovalPublication* publication)
{
    if (publication) { *publication = {}; }
    if (!publication || json.size() > ImageApprovalPublicationMaxBytes || !mcpjson::ValidateDocument(json) ||
        S(json, L"schema") != ImageApprovalPublicationSchema) { return false; }
    std::wstring payload;
    ImageApprovalPublication p;
    if (!mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::FindRawValue(payload, L"assessment", &p.Assessment) ||
        !Number(payload, L"evaluation_filetime", &p.EvaluationFileTime)) { return false; }
    p.CollectionId = S(payload, L"collection_id"); p.CaptureSha256 = S(payload, L"capture_sha256");
    p.ReferenceSha256 = S(payload, L"reference_sha256"); p.PolicySha256 = S(payload, L"policy_sha256");
    p.ManifestSha256 = S(payload, L"manifest_sha256"); p.Sha256 = S(json, L"publication_sha256");
    if (ImageApprovalPublicationJson(p) != json) { return false; }
    *publication = std::move(p);
    return true;
}

ImageApprovalReplay ReplayImageApproval(const std::wstring& path, const std::wstring& anchor, bool current)
{
    ImageApprovalReplay out;
    std::wstring status = L"unavailable", issue, fresh;
    ImageApprovalPublication publication;
    ReferenceArtifact original, policy, manifest;
    Source source;
    bool anchorMatched = false;
    try
    {
        do
        {
            if (!Digest(anchor)) { issue = L"invalid_policy_anchor"; break; }
            std::wstring json;
            if (!original.Open(path, nullptr, ImageApprovalPublicationMaxBytes) || !Text(original, &json) ||
                !ParseImageApprovalPublication(json, &publication)) { issue = L"approval_root_unavailable_or_corrupt"; break; }
            if (publication.PolicySha256 != anchor) { issue = L"recorded_policy_anchor_mismatch"; break; }
            anchorMatched = true;
            const auto store = fs::path(original.Path()).parent_path().parent_path();
            if (!source.Open((store / CapturePath(publication)).wstring()) || source.Capture.Sha256() != publication.CaptureSha256 ||
                source.Reference.Sha256() != publication.ReferenceSha256) { issue = L"capture_or_reference_missing_or_corrupt"; break; }
            if (!policy.Open((store / PolicyPath(publication)).wstring(), nullptr, ImageApprovalInputMaxBytes) || policy.Sha256() != anchor ||
                !manifest.Open((store / ManifestPath(publication)).wstring(), nullptr, ImageApprovalInputMaxBytes) || manifest.Sha256() != publication.ManifestSha256)
                { issue = L"approval_inputs_missing_or_corrupt"; break; }
            const auto assessment = AssessAuthorizedImageChanges(source.ReplayInput, manifest.Path(), policy.Path(),
                anchor, current ? 0 : publication.EvaluationFileTime);
            fresh = assessment.Json;
            if (!original.Unchanged() || !source.Unchanged() || !policy.Unchanged() || !manifest.Unchanged())
                { issue = L"approval_replay_input_changed"; break; }
            if (!assessment.Assessed) { issue = current ? L"current_assessment_unavailable" : L"original_assessment_unavailable"; break; }
            if (!source.MatchesAssessment(fresh)) { issue = L"approval_replay_capture_mismatch"; break; }
            if (!current && fresh != publication.Assessment) { issue = L"recorded_assessment_mismatch"; break; }
            out.Succeeded = true;
            status = current ? L"reanalyzed" : L"reproduced";
        } while (false);
    }
    catch (...) { issue = L"approval_replay_exception"; }
    out.Json = L"{\"schema\":\"kn.image_approval_replay.v1\",\"status\":" + mcpjson::Quote(status) + L",\"issue\":" + mcpjson::Quote(issue) +
        L",\"mode\":" + mcpjson::Quote(current ? L"current_retained_policy" : L"original_assessment") +
        L",\"root_file_sha256\":" + mcpjson::Quote(original.Sha256()) + L",\"publication_sha256\":" + mcpjson::Quote(publication.Sha256) +
        L",\"policy_anchor_sha256\":" + mcpjson::Quote(anchor) + L",\"policy_anchor_matched\":" + B(anchorMatched) +
        L",\"original_assessment_reproduced\":" + B(out.Succeeded && !current) +
        L",\"recorded_assessment\":" + (publication.Assessment.empty() ? L"null" : publication.Assessment) +
        L",\"assessment\":" + (fresh.empty() ? L"null" : fresh) +
        L",\"journal_membership_checked\":false,\"collector_authenticated\":false,\"execution_observed\":false}";
    return out;
}

ImageApprovalCollection JournalImageApproval(const std::wstring& capturePath, const std::wstring& manifestPath,
    const std::wstring& policyPath, const std::wstring& anchor, const std::wstring& privateStore, const std::wstring& collectionId,
    uint64_t evaluationTime, const std::function<void(const wchar_t*)>& observer)
{
    ImageApprovalCollection out;
    out.CollectionId = collectionId;
    const auto fail = [&](const wchar_t* issue) { out.Issue = issue; return out; };
    const auto stage = [&](const wchar_t* name) { if (observer) { observer(name); } };
    try
    {
        if (!Id(collectionId) || !Digest(anchor)) { return fail(L"invalid_collection_id_or_policy_anchor"); }
        Source source;
        ReferenceArtifact policy, manifest;
        if (!source.Open(capturePath)) { return fail(L"capture_or_reference_unavailable"); }
        if (!policy.Open(policyPath, nullptr, ImageApprovalInputMaxBytes) || policy.Sha256() != anchor ||
            !manifest.Open(manifestPath, nullptr, ImageApprovalInputMaxBytes)) { return fail(L"approval_inputs_unavailable_or_unpinned"); }
        ImageApprovalPublication p;
        p.CollectionId = collectionId; p.CaptureSha256 = source.Capture.Sha256(); p.ReferenceSha256 = source.Reference.Sha256();
        p.PolicySha256 = policy.Sha256(); p.ManifestSha256 = manifest.Sha256();
        out.CapturePath = CapturePath(p); out.ApprovalPath = ApprovalPath(collectionId);
        out.CaptureSha256 = p.CaptureSha256; out.ReferenceSha256 = p.ReferenceSha256; out.PolicySha256 = p.PolicySha256; out.ManifestSha256 = p.ManifestSha256;
        out.CaptureBytes = source.Capture.Bytes().size(); out.ReferenceBytes = source.Reference.Bytes().size();
        out.PolicyBytes = policy.Bytes().size(); out.ManifestBytes = manifest.Bytes().size();
        EvidencePrivacyGuard privacy;
        EvidencePrivacyReport protection;
        if (!privacy.Open(privateStore, false, &protection)) { return fail(L"private_store_unavailable"); }
        const fs::path store(protection.RootPath);
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(store.wstring(), false, &out.Issue)) { return out; }
        EvidenceJournal journal;
        if (!journal.Open(store.wstring(), collectionId, &out.Issue, EvidenceJournalPolicy::ApprovedImageV1,
            [&](HANDLE file) { return privacy.CheckFile(file); })) { return out; }
        out.HeadSha256 = journal.State().HeadSha256; out.Status = L"incomplete";
        stage(L"session");
        auto references = PinFolder(store / L"image-references"), captures = PinFolder(store / L"image-captures"), approvals = PinFolder(store / L"image-approvals");
        if (!references || !captures || !approvals) { return fail(L"approval_store_directory_unavailable"); }
        ReferenceArtifact existing;
        std::wstring rootJson;
        if (GetFileAttributesW((store / out.ApprovalPath).c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            ImageApprovalPublication prior;
            if (!existing.Open((store / out.ApprovalPath).wstring(), nullptr, ImageApprovalPublicationMaxBytes) || !Text(existing, &rootJson) ||
                !ParseImageApprovalPublication(rootJson, &prior) || prior.CollectionId != p.CollectionId || prior.CaptureSha256 != p.CaptureSha256 ||
                prior.ReferenceSha256 != p.ReferenceSha256 || prior.PolicySha256 != p.PolicySha256 || prior.ManifestSha256 != p.ManifestSha256)
                { return fail(L"existing_approval_root_conflict"); }
            p = std::move(prior); out.HistoricalRootReused = true;
        }
        else
        {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) { return fail(L"approval_root_unavailable"); }
            p.EvaluationFileTime = evaluationTime ? evaluationTime : Now();
        }
        // A collection may already contain a different assessment. Its state
        // cannot be attributed to this invocation until all input hashes match.
        out.Committed = !journal.State().ApprovalPaths.empty(); out.Closed = journal.State().Closed;
        const auto evaluated = AssessAuthorizedImageChanges(source.ReplayInput, manifest.Path(), policy.Path(), anchor, p.EvaluationFileTime);
        if (!evaluated.Assessed || !source.MatchesAssessment(evaluated.Json) || (out.HistoricalRootReused && p.Assessment != evaluated.Json))
            { return fail(L"approval_assessment_unavailable_or_mismatched"); }
        p.Assessment = evaluated.Json;
        if (!out.HistoricalRootReused) { rootJson = ImageApprovalPublicationJson(p); }
        if (rootJson.empty()) { return fail(L"approval_publication_invalid"); }
        out.ApprovalSha256 = ContentHash::Bytes(Bytes(rootJson)); out.ApprovalBytes = Bytes(rootJson).size();
        std::vector<std::unique_ptr<SchemaArtifact>> leases;
        const auto retain = [&](const std::wstring& relative, const std::vector<uint8_t>& bytes, const std::wstring& hash)
        {
            std::unique_ptr<SchemaArtifact> lease;
            bool created = false;
            if (!Retain(store / relative, bytes, hash, privacy, &lease, &created)) { return false; }
            leases.push_back(std::move(lease)); return true;
        };
        if (!retain(ReferencePath(p), source.Reference.Bytes(), p.ReferenceSha256)) { return fail(L"reference_publication_failed"); }
        stage(L"reference");
        if (!retain(out.CapturePath, source.Capture.Bytes(), p.CaptureSha256)) { return fail(L"capture_publication_failed"); }
        stage(L"capture");
        if (!retain(PolicyPath(p), policy.Bytes(), p.PolicySha256)) { return fail(L"policy_publication_failed"); }
        stage(L"policy");
        if (!retain(ManifestPath(p), manifest.Bytes(), p.ManifestSha256)) { return fail(L"manifest_publication_failed"); }
        stage(L"manifest");
        if (!retain(out.ApprovalPath, Bytes(rootJson), out.ApprovalSha256)) { return fail(L"approval_publication_failed"); }
        stage(L"approval");
        if (!source.Unchanged() || !policy.Unchanged() || !manifest.Unchanged() || (out.HistoricalRootReused && !existing.Unchanged()))
            { return fail(L"source_artifact_changed"); }
        EvidenceJournalTransaction transaction;
        transaction.Kind = L"image_approval"; transaction.Id = out.ApprovalSha256;
        transaction.Members = {{out.CapturePath, p.CaptureSha256, source.Schema, out.CaptureBytes},
            {ReferencePath(p), p.ReferenceSha256, L"raw.bytes", out.ReferenceBytes},
            {PolicyPath(p), p.PolicySha256, L"kn.image_approval_policy.v1", out.PolicyBytes},
            {ManifestPath(p), p.ManifestSha256, L"kn.authorized_image_changes.v1", out.ManifestBytes},
            {out.ApprovalPath, out.ApprovalSha256, ImageApprovalPublicationSchema, out.ApprovalBytes}};
        const auto committed = journal.Commit(transaction);
        out.Committed = committed.Committed; out.HeadSha256 = journal.State().HeadSha256;
        if (!committed.Committed || !committed.Indexed) { out.Issue = committed.Issue; return out; }
        stage(L"approval_commit");
        const auto ledger = Ledger(out), ledgerPath = L"image-approvals/session-" + collectionId + L".knapprovalledger";
        if (!retain(ledgerPath, Bytes(ledger), ContentHash::Bytes(Bytes(ledger)))) { return fail(L"approval_ledger_publication_failed"); }
        stage(L"ledger");
        EvidenceJournalTransaction closure;
        closure.Kind = L"closure"; closure.Id = L"0"; closure.Members = {EvidenceJournalJsonMember(ledgerPath, ledger)};
        for (const auto& member : transaction.Members) { closure.Requires.push_back(member.Path); }
        const auto closed = journal.Commit(std::move(closure));
        out.Closed = journal.State().Closed; out.HeadSha256 = journal.State().HeadSha256; out.Indexed = closed.Committed && closed.Indexed;
        if (!out.Closed || !out.Indexed) { out.Issue = closed.Issue; return out; }
        out.Status = L"archived"; out.Issue.clear(); stage(L"closed");
        return out;
    }
    catch (...) { return fail(L"approval_collection_exception"); }
}

std::wstring ImageApprovalCollectionJson(const ImageApprovalCollection& r)
{
    return L"{\"schema\":\"kn.image_approval_collection.v1\",\"status\":" + mcpjson::Quote(r.Status) + L",\"issue\":" + mcpjson::Quote(r.Issue) +
        L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) + L",\"approval_path\":" + mcpjson::Quote(r.ApprovalPath) +
        L",\"capture_path\":" + mcpjson::Quote(r.CapturePath) + L",\"approval_sha256\":" + mcpjson::Quote(r.ApprovalSha256) +
        L",\"capture_sha256\":" + mcpjson::Quote(r.CaptureSha256) + L",\"reference_sha256\":" + mcpjson::Quote(r.ReferenceSha256) +
        L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) + L",\"manifest_sha256\":" + mcpjson::Quote(r.ManifestSha256) +
        L",\"head_sha256\":" + mcpjson::Quote(r.HeadSha256) + L",\"committed\":" + B(r.Committed) + L",\"closed\":" + B(r.Closed) +
        L",\"indexed\":" + B(r.Indexed) + L",\"historical_root_reused\":" + B(r.HistoricalRootReused) +
        L",\"denominator_scope\":\"current_archive_invocation\",\"source_privacy_changed\":false,\"current_approval_established\":false,"
        L"\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
}
