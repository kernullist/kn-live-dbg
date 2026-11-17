#include "ImageAuthorizedChanges.h"
#include "ImageVerificationRecipe.h"
#include "ReferenceArtifact.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <set>

namespace
{
    using namespace bounded_observation_json;
    constexpr size_t MaximumDocumentBytes = 64 * 1024, MaximumEntries = 128;
    constexpr const wchar_t* Basis = L"non_fixup_compared_bytes.v1";
    struct Change { uint32_t Rva = 0, Length = 0; std::wstring Before, After; };
    struct Manifest
    {
        std::wstring Image, Issuer, ComparisonPolicy, HashBasis;
        uint64_t Epoch = 0, From = 0, Until = 0;
        std::vector<Change> Changes;
    };
    struct Approval { std::wstring Image, ManifestHash, Issuer; };
    struct Policy
    {
        std::wstring Id;
        uint64_t Epoch = 0, From = 0, Until = 0;
        std::vector<Approval> Approvals;
    };
    std::wstring S(const std::wstring& json, const wchar_t* key)
    { std::wstring out; mcpjson::GetString(json, key, &out); return out; }
    bool Digest(const std::wstring& value)
    { return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }
    bool Identifier(const std::wstring& value)
    {
        return Text(value, 128) && std::all_of(value.begin(), value.end(), [](wchar_t c) { return c >= 32 && c != 127; });
    }
    bool Fields(const std::wstring& json, std::initializer_list<const wchar_t*> names)
    {
        IndexedObject object;
        if (!object.Parse(json) || object.Metadata(names) != L"{}") { return false; }
        std::wstring raw;
        for (const auto* name : names) { if (!object.Raw(name, &raw)) { return false; } }
        return true;
    }
    template<class T> bool Integer(const std::wstring& json, const wchar_t* name, T* out)
    {
        const auto text = S(json, name);
        return !text.empty() && (text.size() == 1 || text[0] != L'0') && Number(json, name, out);
    }
    bool Rows(const std::wstring& json, const wchar_t* key, std::vector<std::wstring>* out)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw) || raw.empty() || raw[0] != L'[') { return false; }
        size_t pos = 1;
        mcpjson::SkipWhitespace(raw, &pos);
        while (pos < raw.size() && raw[pos] != L']')
        {
            size_t end = 0;
            if (out->size() == MaximumEntries || !mcpjson::ScanValue(raw, pos, &end)) { return false; }
            out->push_back(raw.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(raw, &pos);
            if (pos < raw.size() && raw[pos] == L',') { ++pos; mcpjson::SkipWhitespace(raw, &pos); }
            else { break; }
        }
        return pos + 1 == raw.size() && raw[pos] == L']' && !out->empty();
    }
    bool Window(const std::wstring& json, uint64_t* epoch, uint64_t* from, uint64_t* until)
    {
        return Integer(json, L"policy_epoch", epoch) && *epoch && Integer(json, L"not_before_filetime", from) && *from &&
            Integer(json, L"not_after_filetime", until) && *until > *from;
    }
    bool Parse(const std::wstring& json, Manifest* out)
    {
        std::vector<std::wstring> rows;
        if (!Fields(json, {L"schema", L"image_sha256", L"issuer", L"policy_epoch", L"not_before_filetime",
            L"not_after_filetime", L"comparison_policy", L"hash_basis", L"changes"}) ||
            S(json, L"schema") != L"kn.authorized_image_changes.v1" ||
            !Window(json, &out->Epoch, &out->From, &out->Until) || !Rows(json, L"changes", &rows)) { return false; }
        out->Image = S(json, L"image_sha256"); out->Issuer = S(json, L"issuer");
        out->ComparisonPolicy = S(json, L"comparison_policy"); out->HashBasis = S(json, L"hash_basis");
        if (!Digest(out->Image) || !Identifier(out->Issuer) || !Identifier(out->ComparisonPolicy) || !Identifier(out->HashBasis)) { return false; }
        uint64_t end = 0;
        for (const auto& row : rows)
        {
            Change change;
            change.Before = S(row, L"before_sha256"); change.After = S(row, L"after_sha256");
            if (!Fields(row, {L"rva", L"length", L"before_sha256", L"after_sha256"}) ||
                !Integer(row, L"rva", &change.Rva) || !Integer(row, L"length", &change.Length) ||
                !change.Length || change.Length > 4096 || uint64_t(change.Rva) + change.Length > UINT32_MAX || change.Rva < end ||
                !Digest(change.Before) || !Digest(change.After) || change.Before == change.After) { return false; }
            end = uint64_t(change.Rva) + change.Length;
            out->Changes.push_back(std::move(change));
        }
        return true;
    }
    bool Parse(const std::wstring& json, Policy* out)
    {
        std::vector<std::wstring> rows;
        if (!Fields(json, {L"schema", L"policy_id", L"policy_epoch", L"not_before_filetime", L"not_after_filetime", L"approvals"}) ||
            S(json, L"schema") != L"kn.image_approval_policy.v1" || !Window(json, &out->Epoch, &out->From, &out->Until) ||
            !Rows(json, L"approvals", &rows) || !Identifier(out->Id = S(json, L"policy_id"))) { return false; }
        std::set<std::wstring> seen;
        for (const auto& row : rows)
        {
            Approval approval{S(row, L"image_sha256"), S(row, L"manifest_sha256"), S(row, L"issuer")};
            if (!Fields(row, {L"image_sha256", L"manifest_sha256", L"issuer"}) ||
                !Digest(approval.Image) || !Digest(approval.ManifestHash) || !Identifier(approval.Issuer) ||
                !seen.insert(approval.ManifestHash).second) { return false; }
            out->Approvals.push_back(std::move(approval));
        }
        return true;
    }
    bool Load(const std::wstring& path, ReferenceArtifact* artifact, std::wstring* json)
    {
        if (!artifact->Open(path, nullptr, MaximumDocumentBytes)) { return false; }
        const auto& bytes = artifact->Bytes();
        const std::string utf8(bytes.begin(), bytes.end());
        *json = mcpjson::Utf8ToWide(utf8);
        return mcpjson::WideToUtf8(*json) == utf8 && mcpjson::ValidateDocument(*json);
    }
    std::wstring HashRange(const std::vector<uint8_t>& bytes, size_t begin, size_t length)
    {
        ContentHash hash;
        return hash.Add(bytes.data() + begin, length) ? hash.Finish() : L"";
    }
    bool Mark(const std::vector<ObservationRange>& ranges, uint64_t start, uint32_t length, std::vector<uint8_t>* mask)
    {
        if (ranges.size() > 4096) { return false; }
        for (const auto& range : ranges)
        {
            if (!range.Size || range.Address < start || range.Address - start >= length || range.Size > length - (range.Address - start)) { return false; }
            for (size_t i = static_cast<size_t>(range.Address - start); i < range.Address - start + range.Size; ++i)
            { if ((*mask)[i]) { return false; } (*mask)[i] = 1; }
        }
        return true;
    }
    std::wstring Ranges(const std::vector<uint8_t>& mask, uint32_t rva)
    {
        std::wstring out = L"[";
        for (size_t i = 0; i < mask.size();)
        {
            if (!mask[i]) { ++i; continue; }
            const auto begin = i;
            while (i < mask.size() && mask[i]) { ++i; }
            if (out.size() > 1) { out += L","; }
            out += L"{\"rva\":" + N(rva + begin) + L",\"length\":" + N(i - begin) + L"}";
        }
        return out + L"]";
    }
}

ImageChangeAssessment AssessAuthorizedImageChanges(const std::wstring& capture, const std::wstring& manifestPath,
    const std::wstring& policyPath, const std::wstring& policySha256, uint64_t evaluationTime,
    const std::function<void(const wchar_t*)>& observer)
{
    ImageChangeAssessment result;
    std::wstring issue, referenceTrust = L"unavailable", decision = L"unavailable", rules = L"[]";
    std::wstring approvedRanges = L"[]", unexplainedRanges = L"[]";
    ReferenceArtifact manifestFile, policyFile;
    Manifest manifest;
    Policy policy;
    ImageRecipeReplay replay;
    DirectImageReplayEvidence evidence;
    uint64_t approved = 0, unexplained = 0;
    bool complete = false, referenceApproved = false, replayAttempted = false;
    const bool hostTime = evaluationTime == 0;
    if (hostTime)
    {
        FILETIME now{}; GetSystemTimeAsFileTime(&now);
        evaluationTime = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    }
    try
    {
        do
        {
            std::wstring json;
            if (!Digest(policySha256)) { issue = L"invalid_policy_anchor"; break; }
            if (!Load(policyPath, &policyFile, &json)) { issue = L"policy_unavailable_or_invalid_json"; break; }
            if (policyFile.Sha256() != policySha256) { issue = L"policy_anchor_mismatch"; break; }
            if (!Parse(json, &policy)) { issue = L"policy_invalid"; break; }
            if (!Load(manifestPath, &manifestFile, &json)) { issue = L"manifest_unavailable_or_invalid_json"; break; }
            if (!Parse(json, &manifest)) { issue = L"manifest_invalid"; break; }
            if (observer) { observer(L"approval_inputs_leased"); }
            const bool pinned = std::any_of(policy.Approvals.begin(), policy.Approvals.end(), [&](const auto& entry)
            { return entry.Image == manifest.Image && entry.ManifestHash == manifestFile.Sha256() && entry.Issuer == manifest.Issuer; });
            if (!pinned) { issue = L"manifest_not_approved"; break; }
            if (manifest.Epoch != policy.Epoch) { issue = L"policy_epoch_mismatch"; break; }
            if (manifest.ComparisonPolicy != ImageRecipePolicy || manifest.HashBasis != Basis)
            { issue = L"change_policy_unavailable"; break; }
            const auto validAt = [&](uint64_t time)
            { return time >= manifest.From && time < manifest.Until && time >= policy.From && time < policy.Until; };
            if (!validAt(evaluationTime)) { issue = L"approval_not_valid_at_evaluation"; break; }
            replayAttempted = true;
            replay = ReplayImageRecipe(capture, false, nullptr, &evidence);
            if (replay.Status != L"replayed" || evidence.Recipe.ReferenceSha256.empty()) { issue = L"original_direct_replay_unavailable"; break; }
            referenceTrust = L"R-retained";
            const auto& p = evidence.Recipe;
            const auto& c = evidence.Comparison;
            if (p.ReferenceSha256 != manifest.Image) { issue = L"reference_not_approved"; break; }
            if (p.CapturedFileTime > evaluationTime || !validAt(p.CapturedFileTime)) { issue = L"approval_not_valid_at_capture"; break; }
            if (!policyFile.Unchanged() || !manifestFile.Unchanged()) { issue = L"approval_inputs_changed"; break; }
            referenceApproved = true; referenceTrust = L"R-approved";
            std::vector<uint8_t> compared(p.Length), changed(p.Length), authorized(p.Length), unexplainedMask(p.Length);
            const bool accounted = evidence.ReferenceQualified && c.Rva == p.Rva && c.Coverage.RequestedBytes == p.Length &&
                !c.Coverage.RangesTruncated && c.Expected.size() == p.Length && c.Observed.size() == p.Length &&
                Mark(c.Coverage.Compared, p.ImageBase + p.Rva, p.Length, &compared) && Mark(c.Changes, p.Rva, p.Length, &changed) &&
                static_cast<uint64_t>(std::count(compared.begin(), compared.end(), 1)) == c.Coverage.ComparedBytes;
            bool bytesAgree = accounted;
            if (accounted)
            {
                for (size_t i = 0; i < p.Length; ++i)
                { bytesAgree = bytesAgree && bool(changed[i]) == bool(compared[i] && c.Expected[i] != c.Observed[i]); }
            }
            complete = bytesAgree && c.Coverage.Complete();
            rules = L"[";
            for (const auto& rule : manifest.Changes)
            {
                std::wstring state;
                const ObservationRange span{rule.Rva, rule.Length};
                if (rule.Rva < p.Rva || rule.Rva - p.Rva >= p.Length || rule.Length > p.Length - (rule.Rva - p.Rva))
                { state = L"outside_capture"; }
                else if (std::any_of(evidence.NormalizationRanges.begin(), evidence.NormalizationRanges.end(), [&](const auto& range) { return range.Overlaps(span); }))
                { state = L"normalization_overlap"; }
                else if (!bytesAgree || std::find(compared.begin() + (rule.Rva - p.Rva), compared.begin() + (rule.Rva - p.Rva + rule.Length), 0) != compared.begin() + (rule.Rva - p.Rva + rule.Length))
                { state = L"not_fully_compared"; }
                else
                {
                    const size_t offset = rule.Rva - p.Rva;
                    const auto before = HashRange(c.Expected, offset, rule.Length), after = HashRange(c.Observed, offset, rule.Length);
                    if (before != rule.Before) { state = L"before_hash_mismatch"; }
                    else if (after == rule.Before) { state = L"not_applied"; }
                    else if (after != rule.After) { state = L"after_hash_mismatch"; }
                    else
                    {
                        state = L"authorized";
                        for (size_t i = offset; i < offset + rule.Length; ++i) { authorized[i] = changed[i]; }
                    }
                }
                if (rules.size() > 1) { rules += L","; }
                rules += L"{\"rva\":" + N(rule.Rva) + L",\"length\":" + N(rule.Length) + L",\"state\":" + mcpjson::Quote(state) + L"}";
            }
            rules += L"]";
            if (bytesAgree)
            {
                for (size_t i = 0; i < p.Length; ++i)
                {
                    approved += authorized[i];
                    unexplainedMask[i] = changed[i] && !authorized[i];
                    unexplained += unexplainedMask[i];
                }
            }
            approvedRanges = Ranges(authorized, p.Rva); unexplainedRanges = Ranges(unexplainedMask, p.Rva);
            decision = unexplained ? L"unexplained_changes" : !complete ? L"incomplete_comparison" :
                approved ? L"all_observed_changes_authorized" : L"no_observed_change";
            result.Assessed = true;
        } while (false);
    }
    catch (const std::exception&) { issue = L"assessment_failed"; result.Assessed = false; referenceApproved = false; }
    if (!result.Assessed)
    {
        complete = false; approved = unexplained = 0; rules = approvedRanges = unexplainedRanges = L"[]";
        decision = L"unavailable";
        if (referenceTrust == L"R-approved") { referenceTrust = L"R-retained"; }
    }
    result.Json = L"{\"schema\":\"kn.image_change_assessment.v1\",\"status\":" + mcpjson::Quote(result.Assessed ? L"assessed" : L"unavailable") +
        L",\"issue\":" + mcpjson::Quote(issue) + L",\"scope\":\"one_recorded_direct_range\",\"approval_basis\":\"caller_pinned_exact_policy\"" +
        L",\"policy_anchor_sha256\":" + mcpjson::Quote(policySha256) + L",\"policy_sha256\":" + mcpjson::Quote(policyFile.Sha256()) +
        L",\"manifest_sha256\":" + mcpjson::Quote(manifestFile.Sha256()) + L",\"policy_id\":" + mcpjson::Quote(policy.Id) +
        L",\"policy_epoch\":" + N(policy.Epoch) + L",\"issuer\":" + mcpjson::Quote(manifest.Issuer) +
        L",\"reference_sha256\":" + mcpjson::Quote(evidence.Recipe.ReferenceSha256) + L",\"reference_trust\":" + mcpjson::Quote(referenceTrust) +
        L",\"reference_approved\":" + B(referenceApproved) + L",\"evaluation_filetime\":" + N(evaluationTime) +
        L",\"clock_basis\":" + mcpjson::Quote(hostTime ? L"host_wall_clock" : L"caller_supplied_time") +
        L",\"capture_filetime\":" + N(evidence.Recipe.CapturedFileTime) + L",\"decision\":" + mcpjson::Quote(decision) +
        L",\"comparison_complete\":" + B(complete) + L",\"authorized_changed_bytes\":" + N(approved) +
        L",\"unexplained_changed_bytes\":" + N(unexplained) + L",\"authorized_ranges\":" + approvedRanges +
        L",\"unexplained_ranges\":" + unexplainedRanges + L",\"rules\":" + rules +
        L",\"issuer_signature_verified\":false,\"collector_authenticated\":false,\"execution_observed\":false,\"current_image_state_known\":false" +
        L",\"replay\":" + (replayAttempted ? ImageRecipeReplayJson(replay) : L"null") + L"}";
    return result;
}
