#include "ImageScopeApprovalCollection.h"
#include "ImageAuthorizedChanges.h"
#include "ImageScopeClaimPublication.h"
#include "ImageScopeReplayPaths.h"
#include "ImageSliceRecipe.h"
#include "ImageSweepManifest.h"
#include "EvidenceArtifactPublication.h"
#include "EvidenceJournal.h"
#include "EvidenceStore.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <set>

using namespace bounded_observation_json;
using namespace evidence_artifact_publication;
namespace fs = std::filesystem;
namespace
{
    bool Digest(const std::wstring& s) { return s.size() == 64 && s.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }
    bool Id(const std::wstring& s)
    { return !s.empty() && s.size() <= 20 && s.find_first_not_of(L"0123456789") == std::wstring::npos && (s.size() == 1 || s[0] != L'0'); }
    std::wstring S(const std::wstring& json, const wchar_t* key)
    { std::wstring value; mcpjson::GetString(json, key, &value); return value; }
    std::vector<uint8_t> Bytes(const std::wstring& text)
    { const auto utf8 = mcpjson::WideToUtf8(text); return {utf8.begin(), utf8.end()}; }
    std::wstring Hash(const std::wstring& text) { return ContentHash::Bytes(Bytes(text)); }
    bool Decode(const ReferenceArtifact& file, std::wstring* json)
    {
        const std::string bytes(file.Bytes().begin(), file.Bytes().end());
        *json = mcpjson::Utf8ToWide(bytes);
        return mcpjson::WideToUtf8(*json) == bytes && mcpjson::ValidateDocument(*json);
    }
    uint64_t Now() { FILETIME now{}; GetSystemTimeAsFileTime(&now); return (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime; }
    std::wstring RootName(bool sweep) { return sweep ? L"root.knsweep" : L"root.knslice"; }
    std::wstring InputPath(const std::wstring& hash) { return L"image-scope-inputs/" + hash + L".knscopeblob"; }
    std::wstring ReferencePath(const std::wstring& hash) { return L"image-references/" + hash + L".knblob"; }
    std::wstring PolicyPath(const std::wstring& hash) { return L"image-approvals/policy-" + hash + L".knapproval"; }
    std::wstring ManifestPath(const std::wstring& hash) { return L"image-approvals/changes-" + hash + L".knchange"; }
    std::wstring ApprovalPath(const std::wstring& id) { return L"image-approvals/scope-assessment-" + id + L".knscopeapproval"; }
    std::wstring LedgerPath(const std::wstring& id) { return L"image-approvals/scope-session-" + id + L".knscopeledger"; }
    bool InputName(const std::wstring& path, bool sweep)
    {
        if (path == RootName(sweep)) { return true; }
        const std::wstring prefix = L"image-reads/reads-";
        if (!sweep || path.rfind(prefix, 0) != 0 || path.size() > 80) { return false; }
        const auto dash = path.find(L'-', prefix.size()), dot = path.rfind(L'.');
        if (dash == std::wstring::npos || dot == std::wstring::npos || dot <= dash) { return false; }
        return Id(path.substr(prefix.size(), dash - prefix.size())) && Id(path.substr(dash + 1, dot - dash - 1)) &&
            (path.substr(dot) == L".knslice" || path.substr(dot) == L".knreads");
    }
    bool InputSchema(const std::wstring& schema)
    {
        return schema == L"kn.image_slice.v1" || schema == L"kn.image_slice.v2" || schema == L"kn.image_sweep.v1" ||
            schema == ImageScopeClaimPublicationSchema || schema == L"kn.image_reads.v3";
    }
    bool Same(const ImageScopeApprovalInput& a, const ImageScopeApprovalInput& b)
    { return a.LogicalPath == b.LogicalPath && a.Sha256 == b.Sha256 && a.Schema == b.Schema && a.Bytes == b.Bytes; }
    bool Same(const std::vector<ImageScopeApprovalInput>& a, const std::vector<ImageScopeApprovalInput>& b)
    { return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const auto& x, const auto& y) { return Same(x, y); }); }
    std::wstring InputsJson(const std::vector<ImageScopeApprovalInput>& inputs)
    {
        std::wstring out = L"[";
        for (const auto& entry : inputs)
        {
            if (out.size() > 1) { out += L","; }
            out += L"{\"logical_path\":" + mcpjson::Quote(entry.LogicalPath) + L",\"sha256\":" + mcpjson::Quote(entry.Sha256) +
                L",\"schema\":" + mcpjson::Quote(entry.Schema) + L",\"bytes\":" + N(entry.Bytes) + L"}";
        }
        return out + L"]";
    }
    bool Valid(const ImageScopeApprovalPublication& p)
    {
        if (!Id(p.CollectionId) || !Digest(p.RootSha256) || !Digest(p.ReferenceSha256) || !Digest(p.PolicySha256) ||
            !Digest(p.ManifestSha256) || !p.EvaluationFileTime || p.Inputs.empty() || p.Inputs.size() > ImageScopeApprovalMaximumInputs ||
            p.Assessment.size() > ImageApprovalPublicationMaxBytes || !mcpjson::ValidateDocument(p.Assessment)) { return false; }
        bool approved = false;
        uint64_t time = 0, total = 0;
        std::wstring previous;
        bool root = false;
        for (const auto& input : p.Inputs)
        {
            if (!InputName(input.LogicalPath, p.Sweep) || !Digest(input.Sha256) || !InputSchema(input.Schema) ||
                !input.Bytes || input.Bytes > ImageRecipeMaxBytes || input.Bytes > ImageScopeApprovalMaximumInputBytes - total ||
                (!previous.empty() && input.LogicalPath <= previous)) { return false; }
            if (input.LogicalPath == RootName(p.Sweep)) { root = input.Sha256 == p.RootSha256; }
            previous = input.LogicalPath; total += input.Bytes;
        }
        return root && (p.Sweep || p.Inputs.size() == 1) && S(p.Assessment, L"schema") == L"kn.image_scope_change_assessment.v1" &&
            S(p.Assessment, L"status") == L"assessed" && S(p.Assessment, L"root_file_sha256") == p.RootSha256 &&
            S(p.Assessment, L"reference_sha256") == p.ReferenceSha256 && S(p.Assessment, L"policy_anchor_sha256") == p.PolicySha256 &&
            S(p.Assessment, L"policy_sha256") == p.PolicySha256 && S(p.Assessment, L"manifest_sha256") == p.ManifestSha256 &&
            S(p.Assessment, L"scope") == (p.Sweep ? L"temporal_sweep_ranges" : L"recorded_slice_ranges") &&
            S(p.Assessment, L"clock_basis") == L"caller_supplied_time" && Number(p.Assessment, L"evaluation_filetime", &time) &&
            time == p.EvaluationFileTime && Boolean(p.Assessment, L"reference_approved", &approved) && approved;
    }
    struct Source
    {
        struct Input { ImageScopeApprovalInput Entry; std::unique_ptr<ReferenceArtifact> File; };
        std::vector<Input> Inputs;
        ReferenceArtifact Reference, ManagedRoot;
        bool Managed = false;
        ImageScopeReplayPaths Paths;
        std::wstring RootPath, RootHash;
        uint64_t InputBytes = 0;
        std::vector<ImageScopeApprovalInput> Entries() const
        {
            std::vector<ImageScopeApprovalInput> out;
            for (const auto& input : Inputs) { out.push_back(input.Entry); }
            return out;
        }
        bool Open(const std::wstring& path, const ImageScopeApprovalPublication* stored = nullptr, const fs::path& store = {})
        {
            auto extension = fs::path(path).extension().wstring();
            std::transform(extension.begin(), extension.end(), extension.begin(), towlower);
            if (!stored && extension == L".knscopeapproval")
            {
                std::wstring text;
                ImageScopeApprovalPublication prior;
                if (!ManagedRoot.Open(path, nullptr, ImageScopeApprovalPublicationMaxBytes) || !Decode(ManagedRoot, &text) ||
                    !ParseImageScopeApprovalPublication(text, &prior)) { return false; }
                Managed = true;
                const auto priorStore = fs::path(ManagedRoot.Path()).parent_path().parent_path();
                return Open((priorStore / InputPath(prior.RootSha256)).wstring(), &prior, priorStore);
            }
            auto root = std::make_unique<ReferenceArtifact>();
            if (!root->Open(path, nullptr, ImageRecipeMaxBytes)) { return false; }
            std::wstring json;
            if (!Decode(*root, &json)) { return false; }
            const auto rootSchema = S(json, L"schema");
            ImageScopeClaimPublication publication;
            if (!UnwrapImageScopeClaimPublication(&json, &publication)) { return false; }
            Paths.Sweep = S(json, L"schema") == L"kn.image_sweep.v1";
            ImageSliceRecipe slice;
            ImageSweepManifest sweep;
            if (Paths.Sweep ? !ParseImageSweepManifest(json, &sweep) : !ParseImageSliceRecipe(json, &slice)) { return false; }
            if (Paths.Sweep && (sweep.Slices.empty() || sweep.Slices.size() > 2048)) { return false; }
            RootPath = root->Path(); RootHash = root->Sha256();
            const fs::path source = fs::path(RootPath).parent_path().parent_path();
            if (stored && (stored->Sweep != Paths.Sweep || stored->RootSha256 != RootHash)) { return false; }
            const auto referenceHash = Paths.Sweep ? sweep.Slices.front().ReferenceSha256 : slice.ReferenceSha256;
            if (!Reference.Open(((stored ? store : source) / ReferencePath(referenceHash)).wstring(), nullptr) ||
                Reference.Sha256() != referenceHash || (stored && stored->ReferenceSha256 != referenceHash)) { return false; }
            Paths.Files.emplace(ReferencePath(referenceHash), Reference.Path());
            const auto rootName = RootName(Paths.Sweep);
            InputBytes = root->Bytes().size();
            Paths.Files.emplace(rootName, RootPath);
            Inputs.push_back({{rootName, RootHash, rootSchema, InputBytes}, std::move(root)});
            const auto add = [&](const std::wstring& logical)
            {
                fs::path inputPath = source / logical;
                if (stored)
                {
                    const auto found = std::lower_bound(stored->Inputs.begin(), stored->Inputs.end(), logical,
                        [](const auto& entry, const auto& key) { return entry.LogicalPath < key; });
                    if (found == stored->Inputs.end() || found->LogicalPath != logical) { return false; }
                    inputPath = store / InputPath(found->Sha256);
                }
                auto file = std::make_unique<ReferenceArtifact>();
                std::wstring text;
                if (Inputs.size() == ImageScopeApprovalMaximumInputs || !file->Open(inputPath.wstring(), nullptr, ImageRecipeMaxBytes) ||
                    !Decode(*file, &text) || file->Bytes().size() > ImageScopeApprovalMaximumInputBytes - InputBytes ||
                    !InputSchema(S(text, L"schema")) || !Paths.Files.emplace(logical, file->Path()).second) { return false; }
                InputBytes += file->Bytes().size();
                ImageScopeApprovalInput entry{logical, file->Sha256(), S(text, L"schema"), file->Bytes().size()};
                Inputs.push_back({std::move(entry), std::move(file)});
                return true;
            };
            if (Paths.Sweep)
            {
                for (const auto& row : sweep.Slices)
                {
                    if (!row.RecipeWritten || !row.ReferenceWritten) { return false; }
                    const auto name = L"image-reads/reads-" + sweep.Sweep.CollectionId + L"-" + std::to_wstring(row.ReadSetId);
                    if (!add(name + L".knslice") || (row.RawWritten && !add(name + L".knreads"))) { return false; }
                }
            }
            std::sort(Inputs.begin(), Inputs.end(), [](const auto& a, const auto& b) { return a.Entry.LogicalPath < b.Entry.LogicalPath; });
            return !stored || Same(Entries(), stored->Inputs);
        }
        bool Unchanged()
        { return (!Managed || ManagedRoot.Unchanged()) && Reference.Unchanged() &&
            std::all_of(Inputs.begin(), Inputs.end(), [](auto& input) { return input.File->Unchanged(); }); }
        ImageChangeAssessment Assess(const ReferenceArtifact& manifest, const ReferenceArtifact& policy, const std::wstring& anchor, uint64_t time)
        { return AssessAuthorizedImageScopeChanges(RootPath, manifest.Path(), policy.Path(), anchor, time, {}, &Paths); }
    };
}

std::wstring ImageScopeApprovalPublicationJson(const ImageScopeApprovalPublication& p)
{
    if (!Valid(p)) { return {}; }
    const auto payload = L"{\"collection_id\":" + mcpjson::Quote(p.CollectionId) + L",\"scope_kind\":" +
        mcpjson::Quote(p.Sweep ? L"sweep" : L"slice") + L",\"root_sha256\":" + mcpjson::Quote(p.RootSha256) +
        L",\"reference_sha256\":" + mcpjson::Quote(p.ReferenceSha256) + L",\"policy_sha256\":" + mcpjson::Quote(p.PolicySha256) +
        L",\"manifest_sha256\":" + mcpjson::Quote(p.ManifestSha256) + L",\"evaluation_filetime\":" + N(p.EvaluationFileTime) +
        L",\"inputs\":" + InputsJson(p.Inputs) + L",\"assessment\":" + p.Assessment + L"}";
    const auto json = L"{\"schema\":" + mcpjson::Quote(ImageScopeApprovalPublicationSchema) + L",\"publication_sha256\":" +
        mcpjson::Quote(Hash(payload)) + L",\"payload\":" + payload + L"}";
    return Bytes(json).size() <= ImageScopeApprovalPublicationMaxBytes ? json : L"";
}

bool ParseImageScopeApprovalPublication(const std::wstring& json, ImageScopeApprovalPublication* out)
{
    if (out) { *out = {}; }
    if (!out || json.size() > ImageScopeApprovalPublicationMaxBytes || !mcpjson::ValidateDocument(json) ||
        S(json, L"schema") != ImageScopeApprovalPublicationSchema) { return false; }
    std::wstring payload;
    if (!mcpjson::FindRawValue(json, L"payload", &payload)) { return false; }
    ImageScopeApprovalPublication p;
    p.CollectionId = S(payload, L"collection_id"); p.RootSha256 = S(payload, L"root_sha256");
    p.ReferenceSha256 = S(payload, L"reference_sha256"); p.PolicySha256 = S(payload, L"policy_sha256");
    p.ManifestSha256 = S(payload, L"manifest_sha256"); p.Sha256 = S(json, L"publication_sha256");
    const auto kind = S(payload, L"scope_kind");
    if (kind != L"sweep" && kind != L"slice") { return false; }
    p.Sweep = kind == L"sweep";
    std::vector<std::wstring> rows;
    if (!Number(payload, L"evaluation_filetime", &p.EvaluationFileTime) || !mcpjson::FindRawValue(payload, L"assessment", &p.Assessment) ||
        !Array(payload, L"inputs", ImageScopeApprovalMaximumInputs, &rows)) { return false; }
    for (const auto& row : rows)
    {
        ImageScopeApprovalInput input{S(row, L"logical_path"), S(row, L"sha256"), S(row, L"schema"), 0};
        if (!Number(row, L"bytes", &input.Bytes)) { return false; }
        p.Inputs.push_back(std::move(input));
    }
    if (ImageScopeApprovalPublicationJson(p) != json) { return false; }
    *out = std::move(p); return true;
}

ImageApprovalReplay ReplayImageScopeApproval(const std::wstring& path, const std::wstring& anchor, bool current)
{
    ImageApprovalReplay out;
    std::wstring status = L"unavailable", issue, fresh;
    ImageScopeApprovalPublication p;
    ReferenceArtifact original, policy, manifest;
    Source source;
    bool anchorMatched = false;
    try
    {
        do
        {
            if (!Digest(anchor)) { issue = L"invalid_policy_anchor"; break; }
            std::wstring json;
            if (!original.Open(path, nullptr, ImageScopeApprovalPublicationMaxBytes) || !Decode(original, &json) ||
                !ParseImageScopeApprovalPublication(json, &p)) { issue = L"scope_approval_root_unavailable_or_corrupt"; break; }
            if (p.PolicySha256 != anchor) { issue = L"recorded_policy_anchor_mismatch"; break; }
            anchorMatched = true;
            const auto store = fs::path(original.Path()).parent_path().parent_path();
            if (!source.Open((store / InputPath(p.RootSha256)).wstring(), &p, store)) { issue = L"scope_inputs_missing_or_corrupt"; break; }
            if (!policy.Open((store / PolicyPath(anchor)).wstring(), nullptr, ImageApprovalInputMaxBytes) || policy.Sha256() != anchor ||
                !manifest.Open((store / ManifestPath(p.ManifestSha256)).wstring(), nullptr, ImageApprovalInputMaxBytes) ||
                manifest.Sha256() != p.ManifestSha256) { issue = L"approval_inputs_missing_or_corrupt"; break; }
            const auto assessment = source.Assess(manifest, policy, anchor, current ? 0 : p.EvaluationFileTime);
            fresh = assessment.Json;
            if (!original.Unchanged() || !source.Unchanged() || !policy.Unchanged() || !manifest.Unchanged())
                { issue = L"approval_replay_input_changed"; break; }
            if (!assessment.Assessed) { issue = current ? L"current_assessment_unavailable" : L"original_assessment_unavailable"; break; }
            if (!current && fresh != p.Assessment) { issue = L"recorded_assessment_mismatch"; break; }
            out.Succeeded = true; status = current ? L"reanalyzed" : L"reproduced";
        } while (false);
    }
    catch (...) { issue = L"scope_approval_replay_exception"; }
    out.Json = L"{\"schema\":\"kn.image_scope_approval_replay.v1\",\"status\":" + mcpjson::Quote(status) + L",\"issue\":" + mcpjson::Quote(issue) +
        L",\"mode\":" + mcpjson::Quote(current ? L"current_retained_policy" : L"original_assessment") +
        L",\"root_file_sha256\":" + mcpjson::Quote(original.Sha256()) + L",\"publication_sha256\":" + mcpjson::Quote(p.Sha256) +
        L",\"policy_anchor_sha256\":" + mcpjson::Quote(anchor) + L",\"policy_anchor_matched\":" + B(anchorMatched) +
        L",\"original_assessment_reproduced\":" + B(out.Succeeded && !current) +
        L",\"recorded_assessment\":" + (p.Assessment.empty() ? L"null" : p.Assessment) +
        L",\"assessment\":" + (fresh.empty() ? L"null" : fresh) +
        L",\"journal_membership_checked\":false,\"collector_authenticated\":false,\"execution_observed\":false,\"atomic_snapshot\":false}";
    return out;
}

ImageScopeApprovalCollection JournalImageScopeApproval(const std::wstring& scopePath, const std::wstring& manifestPath,
    const std::wstring& policyPath, const std::wstring& anchor, const std::wstring& privateStore, const std::wstring& collectionId,
    uint64_t evaluationTime, const std::function<void(const wchar_t*)>& observer)
{
    ImageScopeApprovalCollection out;
    out.CollectionId = collectionId;
    const auto fail = [&](const wchar_t* issue) { out.Issue = issue; return out; };
    const auto stage = [&](const std::wstring& name) { if (observer) { observer(name.c_str()); } };
    try
    {
        if (!Id(collectionId) || !Digest(anchor)) { return fail(L"invalid_collection_id_or_policy_anchor"); }
        Source source;
        ReferenceArtifact policy, manifest;
        if (!source.Open(scopePath)) { return fail(L"scope_inputs_unavailable"); }
        if (!policy.Open(policyPath, nullptr, ImageApprovalInputMaxBytes) || policy.Sha256() != anchor ||
            !manifest.Open(manifestPath, nullptr, ImageApprovalInputMaxBytes)) { return fail(L"approval_inputs_unavailable_or_unpinned"); }
        stage(L"source");
        ImageScopeApprovalPublication p;
        p.CollectionId = collectionId; p.RootSha256 = source.RootHash; p.ReferenceSha256 = source.Reference.Sha256();
        p.PolicySha256 = policy.Sha256(); p.ManifestSha256 = manifest.Sha256(); p.Sweep = source.Paths.Sweep; p.Inputs = source.Entries();
        out.ApprovalPath = ApprovalPath(collectionId); out.RootSha256 = p.RootSha256; out.ReferenceSha256 = p.ReferenceSha256;
        out.PolicySha256 = p.PolicySha256; out.ManifestSha256 = p.ManifestSha256;
        out.InputCount = p.Inputs.size(); out.InputBytes = source.InputBytes; out.ReferenceBytes = source.Reference.Bytes().size();
        out.PolicyBytes = policy.Bytes().size(); out.ManifestBytes = manifest.Bytes().size();
        EvidencePrivacyGuard privacy;
        EvidencePrivacyReport protection;
        if (!privacy.Open(privateStore, false, &protection)) { return fail(L"private_store_unavailable"); }
        const fs::path store(protection.RootPath);
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(store.wstring(), false, &out.Issue)) { return out; }
        EvidenceJournal journal;
        if (!journal.Open(store.wstring(), collectionId, &out.Issue, EvidenceJournalPolicy::ApprovedImageScopeV1,
            [&](HANDLE file) { return privacy.CheckFile(file); })) { return out; }
        out.HeadSha256 = journal.State().HeadSha256; out.Status = L"incomplete";
        stage(L"session");
        auto references = PinFolder(store / L"image-references"), inputs = PinFolder(store / L"image-scope-inputs"),
            approvals = PinFolder(store / L"image-approvals");
        if (!references || !inputs || !approvals) { return fail(L"approval_store_directory_unavailable"); }
        ReferenceArtifact existing;
        std::wstring rootJson;
        if (GetFileAttributesW((store / out.ApprovalPath).c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            ImageScopeApprovalPublication prior;
            if (!existing.Open((store / out.ApprovalPath).wstring(), nullptr, ImageScopeApprovalPublicationMaxBytes) ||
                !Decode(existing, &rootJson) || !ParseImageScopeApprovalPublication(rootJson, &prior) ||
                prior.CollectionId != p.CollectionId || prior.Sweep != p.Sweep || prior.RootSha256 != p.RootSha256 ||
                prior.ReferenceSha256 != p.ReferenceSha256 || prior.PolicySha256 != p.PolicySha256 || prior.ManifestSha256 != p.ManifestSha256 ||
                !Same(prior.Inputs, p.Inputs)) { return fail(L"existing_approval_root_conflict"); }
            p = std::move(prior); out.HistoricalRootReused = true;
        }
        else
        {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) { return fail(L"approval_root_unavailable"); }
            p.EvaluationFileTime = evaluationTime ? evaluationTime : Now();
        }
        // Closed-state flags belong to this input set only after exact binding.
        out.Committed = !journal.State().ApprovalPaths.empty(); out.Closed = journal.State().Closed;
        const auto assessment = source.Assess(manifest, policy, anchor, p.EvaluationFileTime);
        if (!assessment.Assessed || (out.HistoricalRootReused && p.Assessment != assessment.Json))
            { return fail(L"approval_assessment_unavailable_or_mismatched"); }
        p.Assessment = assessment.Json;
        if (!out.HistoricalRootReused) { rootJson = ImageScopeApprovalPublicationJson(p); }
        if (rootJson.empty()) { return fail(L"approval_publication_invalid"); }
        out.ApprovalSha256 = Hash(rootJson); out.ApprovalBytes = Bytes(rootJson).size();
        std::vector<std::unique_ptr<SchemaArtifact>> leases;
        const auto retain = [&](const std::wstring& relative, const std::vector<uint8_t>& bytes, const std::wstring& hash)
        {
            std::unique_ptr<SchemaArtifact> lease;
            bool created = false;
            if (!Retain(store / relative, bytes, hash, privacy, &lease, &created)) { return false; }
            leases.push_back(std::move(lease)); return true;
        };
        EvidenceJournalTransaction transaction;
        transaction.Kind = L"image_scope_approval"; transaction.Id = out.ApprovalSha256;
        std::map<std::wstring, EvidenceJournalMember> members;
        for (const auto& input : source.Inputs)
        {
            const auto& e = input.Entry;
            const auto path = InputPath(e.Sha256);
            const auto found = members.find(path);
            if (found != members.end())
            {
                if (found->second.Bytes != e.Bytes || found->second.Schema != e.Schema) { return fail(L"conflicting_scope_input"); }
                continue;
            }
            if (!retain(path, input.File->Bytes(), e.Sha256)) { return fail(L"scope_input_publication_failed"); }
            members.emplace(path, EvidenceJournalMember{path, e.Sha256, e.Schema, e.Bytes});
            ++out.UniqueInputFiles; out.UniqueInputBytes += e.Bytes;
            stage(L"input-" + std::to_wstring(out.UniqueInputFiles));
        }
        if (!retain(ReferencePath(p.ReferenceSha256), source.Reference.Bytes(), p.ReferenceSha256)) { return fail(L"reference_publication_failed"); }
        stage(L"reference");
        if (!retain(PolicyPath(p.PolicySha256), policy.Bytes(), p.PolicySha256)) { return fail(L"policy_publication_failed"); }
        stage(L"policy");
        if (!retain(ManifestPath(p.ManifestSha256), manifest.Bytes(), p.ManifestSha256)) { return fail(L"manifest_publication_failed"); }
        stage(L"manifest");
        if (!retain(out.ApprovalPath, Bytes(rootJson), out.ApprovalSha256)) { return fail(L"approval_publication_failed"); }
        stage(L"approval");
        if (!source.Unchanged() || !policy.Unchanged() || !manifest.Unchanged() || (out.HistoricalRootReused && !existing.Unchanged()))
            { return fail(L"source_artifact_changed"); }
        for (const auto& member : members) { transaction.Members.push_back(member.second); }
        transaction.Members.push_back({ReferencePath(p.ReferenceSha256), p.ReferenceSha256, L"raw.bytes", out.ReferenceBytes});
        transaction.Members.push_back({PolicyPath(p.PolicySha256), p.PolicySha256, L"kn.image_approval_policy.v1", out.PolicyBytes});
        transaction.Members.push_back({ManifestPath(p.ManifestSha256), p.ManifestSha256, L"kn.authorized_image_changes.v1", out.ManifestBytes});
        transaction.Members.push_back({out.ApprovalPath, out.ApprovalSha256, ImageScopeApprovalPublicationSchema, out.ApprovalBytes});
        const auto committed = journal.Commit(transaction);
        out.Committed = committed.Committed; out.HeadSha256 = journal.State().HeadSha256;
        if (!committed.Committed || !committed.Indexed) { out.Issue = committed.Issue; return out; }
        stage(L"approval_commit");
        const auto ledgerPath = LedgerPath(collectionId);
        const auto ledger = L"{\"schema\":" + mcpjson::Quote(ImageScopeApprovalCollectionLedger) + L",\"collection_id\":" +
            mcpjson::Quote(collectionId) + L",\"archived_assessments\":\"1\",\"logical_inputs\":" + N(out.InputCount) +
            L",\"logical_input_bytes\":" + N(out.InputBytes) + L",\"unique_input_files\":" + N(out.UniqueInputFiles) +
            L",\"retained_member_bytes\":" + N(out.UniqueInputBytes + out.ReferenceBytes + out.PolicyBytes + out.ManifestBytes + out.ApprovalBytes) +
            L",\"original_inputs_retained\":true,\"atomic_snapshot\":false,\"power_loss_durability_established\":false}";
        if (!retain(ledgerPath, Bytes(ledger), Hash(ledger))) { return fail(L"approval_ledger_publication_failed"); }
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
    catch (...) { return fail(L"scope_approval_collection_exception"); }
}

std::wstring ImageScopeApprovalCollectionJson(const ImageScopeApprovalCollection& r)
{
    return L"{\"schema\":\"kn.image_scope_approval_collection.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) +
        L",\"approval_path\":" + mcpjson::Quote(r.ApprovalPath) + L",\"root_sha256\":" + mcpjson::Quote(r.RootSha256) +
        L",\"reference_sha256\":" + mcpjson::Quote(r.ReferenceSha256) + L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) +
        L",\"manifest_sha256\":" + mcpjson::Quote(r.ManifestSha256) + L",\"approval_sha256\":" + mcpjson::Quote(r.ApprovalSha256) +
        L",\"head_sha256\":" + mcpjson::Quote(r.HeadSha256) + L",\"logical_inputs\":" + N(r.InputCount) +
        L",\"logical_input_bytes\":" + N(r.InputBytes) + L",\"unique_input_files\":" + N(r.UniqueInputFiles) +
        L",\"unique_input_bytes\":" + N(r.UniqueInputBytes) + L",\"reference_bytes\":" + N(r.ReferenceBytes) +
        L",\"policy_bytes\":" + N(r.PolicyBytes) + L",\"manifest_bytes\":" + N(r.ManifestBytes) + L",\"approval_bytes\":" + N(r.ApprovalBytes) +
        L",\"committed\":" + B(r.Committed) + L",\"closed\":" + B(r.Closed) + L",\"indexed\":" + B(r.Indexed) +
        L",\"historical_root_reused\":" + B(r.HistoricalRootReused) +
        L",\"source_privacy_changed\":false,\"current_approval_established\":false,\"collector_authenticated\":false,"
        L"\"atomic_snapshot\":false,\"power_loss_durability_established\":false}";
}
