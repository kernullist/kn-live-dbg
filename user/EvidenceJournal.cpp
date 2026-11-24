#include "EvidenceJournal.h"
#include "EvidenceStore.h"
#include "EvidenceStoreCatalog.h"
#include "EvidenceStoreFiles.h"
#include "EvidenceRetention.h"
#include "AnalystSnapshot.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "ImageScopeClaimPublication.h"
#include "PendingIrpEvidence.h"
#include "ImageCaptureCollection.h"
#include "ImageArchiveDependencies.h"
#include "ImageApprovalCollection.h"
#include "ImageScopeApprovalCollection.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>

using namespace bounded_observation_json;
namespace fs = std::filesystem;

namespace
{
    constexpr uint64_t MaxSegments = 8192, MaxPaths = 16384, MaxReferences = 65536;
    constexpr uint64_t MaxReadBytes = 1024ull * 1024 * 1024;
    using store_files::MaxJsonBytes;
    using store_files::MaxBlobBytes;
    using store_files::DeadlineMs;
    using store_files::MaxIrpBytes;
    constexpr uint64_t StoreMaxCollections = 1024, StoreMaxPaths = store_files::MaxEntries, StoreMaxReferences = 262144;
    constexpr uint64_t StoreMaxReadBytes = 8ull * 1024 * 1024 * 1024;
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    uint64_t FileTimeValue(FILETIME time);
    uint64_t CurrentFileTime();
    Handle Own(HANDLE handle) { return Handle(handle == INVALID_HANDLE_VALUE ? nullptr : handle, &CloseHandle); }
    using store_catalog::NativePath;
    std::wstring Hash(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }
    bool Digest(const std::wstring& value)
    {
        return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }
    bool Id(const std::wstring& value)
    {
        return !value.empty() && value.size() <= 20 && value.find_first_not_of(L"0123456789") == std::wstring::npos &&
            (value.size() == 1 || value.front() != L'0');
    }
    std::wstring SequenceName(uint64_t sequence)
    {
        const auto number = std::to_wstring(sequence);
        return std::wstring(20 - number.size(), L'0') + number + L".knjseg";
    }
    std::wstring Envelope(const wchar_t* schema, const std::wstring& payload)
    {
        return L"{\"schema\":" + mcpjson::Quote(schema) + L",\"payload_sha256\":" + mcpjson::Quote(Hash(payload)) +
            L",\"payload\":" + payload + L"}";
    }
    constexpr const wchar_t* SessionPolicies[] = {L"kn.image_collection_journal.v1", L"kn.image_irp_collection_journal.v2",
        L"kn.image_claim_irp_collection_journal.v3", L"kn.image_irp_claim_collection_journal.v4", DirectImageCollectionPolicy,
        ImageApprovalCollectionPolicy, ImageScopeApprovalCollectionPolicy, ImageSourceCollectionPolicy};
    std::wstring SessionJson(const std::wstring& id, size_t policy)
    {
        return Envelope(L"kn.evidence_session.v1", L"{\"collection_id\":" + mcpjson::Quote(id) +
            L",\"policy\":" + mcpjson::Quote(SessionPolicies[policy]) +
            L",\"hash_basis\":\"exact_file_bytes\","
            L"\"collector_authenticated\":false,\"target_coverage_established\":false}");
    }
    bool FailureLedger(const std::wstring& schema)
    {
        return schema == L"kn.image_read_session.v1" || schema == L"kn.irp_capture_session.v1" || schema == DirectImageCollectionLedger ||
            schema == ImageApprovalCollectionLedger || schema == ImageScopeApprovalCollectionLedger || schema == ImageSourceCollectionLedger;
    }
    bool IrpPath(const std::wstring& path) { return path.rfind(L"irp-", 0) == 0; }
    bool IrpCaptureSchema(const std::wstring& schema)
    { return schema == L"kn.irp_capture.v1" || schema == L"kn.irp_capture.v2" || schema == PendingIrpClaimPublicationSchema; }
    bool DirectPath(const std::wstring& path) { return path.rfind(L"image-captures/", 0) == 0; }
    bool ApprovalPath(const std::wstring& path) { return path.rfind(L"image-approvals/", 0) == 0; }
    bool ScopeInputPath(const std::wstring& path) { return path.rfind(L"image-scope-inputs/", 0) == 0; }
    bool ApprovalInputPath(const std::wstring& path)
    { return path.rfind(L"image-approvals/policy-", 0) == 0 || path.rfind(L"image-approvals/changes-", 0) == 0; }
    std::wstring MemberJson(const EvidenceJournalMember& m)
    {
        return L"{\"path\":" + mcpjson::Quote(m.Path) + L",\"sha256\":" + mcpjson::Quote(m.Sha256) +
            L",\"bytes\":" + N(m.Bytes) + L",\"schema\":" + mcpjson::Quote(m.Schema) + L"}";
    }
    bool Same(const EvidenceJournalMember& a, const EvidenceJournalMember& b)
    {
        return a.Path == b.Path && a.Sha256 == b.Sha256 && a.Bytes == b.Bytes && a.Schema == b.Schema;
    }
    constexpr const wchar_t* RetirementFile = L"retirement.knretirement";
    struct RetirementPolicy
    {
        std::wstring Id, Session, Head, Reason;
        uint64_t Age = 0, ExclusiveByteLimit = 0;
        bool RoutineBudget = false;
        uint64_t RoutineTarget = 0;
        std::wstring ReviewedCatalog, ReviewedArtifacts;
    };
    struct RetirementCount
    {
        uint64_t Paths = 0, Bytes = 0;
        void Add(uint64_t bytes) { ++Paths; Bytes += bytes; }
    };
    struct RetirementRecord
    {
        RetirementPolicy Policy;
        uint64_t Observed = 0, ClosureWritten = 0;
        std::wstring Catalog, Artifacts;
        RetirementCount Exclusive, Shared, Ledgers;
        uint64_t RoutineBefore = 0, RoutineAfter = 0;
    };
    std::wstring RetirementPolicyJson(const RetirementPolicy& p)
    {
        const std::wstring schema = p.RoutineBudget ? L"kn.evidence_retirement_policy.v2" : L"kn.evidence_retirement_policy.v1";
        return L"{\"schema\":" + mcpjson::Quote(schema) + L",\"collection_id\":" + mcpjson::Quote(p.Id) +
            L",\"session_sha256\":" + mcpjson::Quote(p.Session) + L",\"head_sha256\":" + mcpjson::Quote(p.Head) +
            L",\"reason\":" + mcpjson::Quote(p.Reason) + L",\"minimum_age_seconds\":" + N(p.Age) +
            L",\"exclusive_byte_limit\":" + N(p.ExclusiveByteLimit) + (p.RoutineBudget ?
                L",\"policy\":\"kn.retire_routine_excess.v1\",\"routine_named_byte_target\":" + N(p.RoutineTarget) +
                L",\"catalog_sha256\":" + mcpjson::Quote(p.ReviewedCatalog) + L",\"artifacts_sha256\":" + mcpjson::Quote(p.ReviewedArtifacts) : L"") + L"}";
    }
    bool ParseRetirementPolicy(const std::wstring& json, RetirementPolicy& p)
    {
        IndexedObject o;
        if (!o.Parse(json)) { return false; }
        p.Id = o.String(L"collection_id"); p.Head = o.String(L"head_sha256");
        p.Session = o.String(L"session_sha256"); p.Reason = o.String(L"reason");
        p.RoutineBudget = o.String(L"schema") == L"kn.evidence_retirement_policy.v2";
        if (p.RoutineBudget)
        {
            p.ReviewedCatalog = o.String(L"catalog_sha256"); p.ReviewedArtifacts = o.String(L"artifacts_sha256");
            if (!Digest(p.ReviewedCatalog) || !Digest(p.ReviewedArtifacts) || !Number(json, L"routine_named_byte_target", &p.RoutineTarget) ||
                p.RoutineTarget > StoreMaxReadBytes) { return false; }
        }
        return Id(p.Id) && Digest(p.Head) && Digest(p.Session) && Text(p.Reason, 512) &&
            Number(json, L"minimum_age_seconds", &p.Age) && p.Age <= 10ull * 366 * 86400 &&
            Number(json, L"exclusive_byte_limit", &p.ExclusiveByteLimit) && p.ExclusiveByteLimit <= MaxReadBytes &&
            RetirementPolicyJson(p) == json;
    }
    std::wstring RetirementCountJson(const RetirementCount& c)
    { return L"{\"paths\":" + N(c.Paths) + L",\"named_bytes\":" + N(c.Bytes) + L"}"; }
    std::wstring RetirementReceiptJson(const RetirementRecord& r)
    {
        return Envelope(r.Policy.RoutineBudget ? L"kn.evidence_retirement.v2" : L"kn.evidence_retirement.v1", L"{\"policy\":" + RetirementPolicyJson(r.Policy) +
            L",\"observed_filetime\":" + N(r.Observed) + L",\"closure_last_write_filetime\":" + N(r.ClosureWritten) +
            L",\"catalog_sha256\":" + mcpjson::Quote(r.Catalog) + L",\"artifacts_sha256\":" + mcpjson::Quote(r.Artifacts) +
            L",\"exclusive_nonledger\":" + RetirementCountJson(r.Exclusive) + L",\"shared_nonledger\":" + RetirementCountJson(r.Shared) +
            L",\"failure_ledgers\":" + RetirementCountJson(r.Ledgers) + (r.Policy.RoutineBudget ?
                L",\"routine_named_bytes_before\":" + N(r.RoutineBefore) + L",\"routine_named_bytes_after\":" + N(r.RoutineAfter) : L"") + L"}");
    }
    bool ParseRetirementRecord(const std::wstring& json, RetirementRecord& r)
    {
        IndexedObject envelope, body;
        std::wstring payload, policy;
        if (!envelope.Parse(json) || !envelope.Raw(L"payload", &payload) || !body.Parse(payload) ||
            !body.Raw(L"policy", &policy) || !ParseRetirementPolicy(policy, r.Policy)) { return false; }
        r.Catalog = body.String(L"catalog_sha256"); r.Artifacts = body.String(L"artifacts_sha256");
        const auto count = [&](const wchar_t* key, RetirementCount& c)
        {
            std::wstring raw;
            return body.Raw(key, &raw) && Number(raw, L"paths", &c.Paths) && c.Paths <= MaxPaths &&
                Number(raw, L"named_bytes", &c.Bytes) && c.Bytes <= MaxReadBytes && c.Paths <= c.Bytes &&
                (c.Paths != 0 || c.Bytes == 0);
        };
        return Digest(r.Catalog) && Digest(r.Artifacts) && Number(payload, L"observed_filetime", &r.Observed) &&
            Number(payload, L"closure_last_write_filetime", &r.ClosureWritten) && r.ClosureWritten != 0 &&
            r.Observed >= r.ClosureWritten && (r.Observed - r.ClosureWritten) / 10000000 >= r.Policy.Age &&
            count(L"exclusive_nonledger", r.Exclusive) && count(L"shared_nonledger", r.Shared) && count(L"failure_ledgers", r.Ledgers) &&
            r.Exclusive.Bytes <= r.Policy.ExclusiveByteLimit &&
            (!r.Policy.RoutineBudget || (r.Policy.ReviewedCatalog == r.Catalog && r.Policy.ReviewedArtifacts == r.Artifacts &&
                Number(payload, L"routine_named_bytes_before", &r.RoutineBefore) && Number(payload, L"routine_named_bytes_after", &r.RoutineAfter) &&
                r.RoutineBefore <= StoreMaxReadBytes && r.RoutineBefore > r.Policy.RoutineTarget && r.Exclusive.Bytes &&
                r.Exclusive.Bytes <= r.RoutineBefore && r.RoutineAfter == r.RoutineBefore - r.Exclusive.Bytes)) && RetirementReceiptJson(r) == json;
    }
    bool MemberValid(const EvidenceJournalMember& m, const std::wstring& id)
    {
        if (!Digest(m.Sha256) || m.Bytes == 0 || m.Path.size() > 180) { return false; }
        const auto reference = L"image-references/" + m.Sha256 + L".knblob";
        if (m.Path == reference) { return m.Schema == L"raw.bytes" && m.Bytes <= MaxBlobBytes; }
        if (m.Path == L"irp-reference-" + m.Sha256 + L".knblob")
            { return m.Schema == L"raw.bytes" && m.Bytes <= MaxBlobBytes; }
        if (m.Path == L"irp-" + id + L"-" + m.Sha256 + L".knirp")
            { return Id(id) && m.Bytes <= MaxIrpBytes && IrpCaptureSchema(m.Schema); }
        if (m.Path == L"image-captures/capture-" + id + L"-" + m.Sha256 + L".kncapture")
        {
            return Id(id) && m.Bytes <= DirectImageCaptureMaxBytes && (m.Schema == L"kn.image_recipe.v1" ||
                m.Schema == L"kn.image_recipe.v2" || m.Schema == L"kn.image_recipe.v3" || m.Schema == L"kn.image_claim_publication.v1");
        }
        if (m.Path == ImageSourceReportPath(id, m.Sha256)) { return Id(id) && m.Schema == L"kn.image_capture.v3" && m.Bytes <= DirectImageCaptureMaxBytes; }
        const auto casePrefix = L"image-captures/case-" + id + L"-";
        if (m.Path.rfind(casePrefix, 0) == 0)
        {
            const auto pin = m.Path.substr(casePrefix.size(), 64);
            return Id(id) && Digest(pin) && m.Path == ImageSourceCasePath(id, pin) &&
                m.Schema == L"kn.image_claim_publication.v1" && m.Bytes <= DirectImageCaptureMaxBytes;
        }
        if (m.Path == L"image-approvals/assessment-" + id + L".knapprovalcase")
            { return Id(id) && m.Schema == ImageApprovalPublicationSchema && m.Bytes <= ImageApprovalPublicationMaxBytes; }
        if (m.Path == L"image-approvals/scope-assessment-" + id + L".knscopeapproval")
            { return Id(id) && m.Schema == ImageScopeApprovalPublicationSchema && m.Bytes <= ImageScopeApprovalPublicationMaxBytes; }
        if (m.Path == L"image-scope-inputs/" + m.Sha256 + L".knscopeblob")
            { return m.Bytes <= MaxJsonBytes && (m.Schema == L"kn.image_slice.v1" || m.Schema == L"kn.image_slice.v2" ||
                m.Schema == L"kn.image_sweep.v1" || m.Schema == ImageScopeClaimPublicationSchema || m.Schema == L"kn.image_reads.v3"); }
        if (m.Path == L"image-approvals/policy-" + m.Sha256 + L".knapproval")
            { return m.Schema == L"kn.image_approval_policy.v1" && m.Bytes <= ImageApprovalInputMaxBytes; }
        if (m.Path == L"image-approvals/changes-" + m.Sha256 + L".knchange")
            { return m.Schema == L"kn.authorized_image_changes.v1" && m.Bytes <= ImageApprovalInputMaxBytes; }
        if (m.Bytes > MaxJsonBytes) { return false; }
        if (m.Path == ImageSourceSessionPath(id)) { return Id(id) && m.Schema == ImageSourceCollectionLedger; }
        if (m.Path == L"image-approvals/scope-session-" + id + L".knscopeledger") { return Id(id) && m.Schema == ImageScopeApprovalCollectionLedger; }
        if (m.Path == L"image-approvals/session-" + id + L".knapprovalledger") { return Id(id) && m.Schema == ImageApprovalCollectionLedger; }
        if (m.Path == L"image-captures/session-" + id + L".kncaptureledger") { return Id(id) && m.Schema == DirectImageCollectionLedger; }
        if (m.Path == L"irp-session-" + id + L".knirpledger") { return Id(id) && m.Schema == L"kn.irp_capture_session.v1"; }
        if (m.Path == L"image-reads/session-" + id + L".knreadledger") { return m.Schema == L"kn.image_read_session.v1"; }
        const auto slash = m.Path.find(L'/');
        const auto dot = m.Path.rfind(L'.');
        if (slash == std::wstring::npos || dot == std::wstring::npos || dot <= slash) { return false; }
        const auto folder = m.Path.substr(0, slash), name = m.Path.substr(slash + 1, dot - slash - 1), ext = m.Path.substr(dot);
        const auto prefix = (folder == L"image-reads" ? L"reads-" : L"sweep-") + id + L"-";
        if (name.rfind(prefix, 0) != 0 || !Id(name.substr(prefix.size()))) { return false; }
        if (folder == L"image-sweeps") { return ext == L".knsweep" &&
            (m.Schema == L"kn.image_sweep.v1" || m.Schema == ImageScopeClaimPublicationSchema); }
        return folder == L"image-reads" && ((ext == L".knslice" &&
            (m.Schema == L"kn.image_slice.v1" || m.Schema == L"kn.image_slice.v2" || m.Schema == ImageScopeClaimPublicationSchema)) || (ext == L".knreads" &&
            (m.Schema == L"kn.image_reads.v1" || m.Schema == L"kn.image_reads.v2" || m.Schema == L"kn.image_reads.v3")));
    }
    struct IrpReferenceCatalog
    {
        std::wstring Sha256;
        uint64_t Bytes = 0;
        bool Readable = false;
    };
    IrpReferenceCatalog ReadIrpReferenceCatalog(const std::wstring& schema, const std::wstring& json)
    {
        const auto matchesHash = [](const IndexedObject& object, const wchar_t* field, const std::wstring& bytes)
        {
            const auto expected = object.String(field);
            return Digest(expected) && Hash(bytes) == expected;
        };
        IndexedObject capture;
        if (!capture.Parse(json) || capture.String(L"schema") != schema) { return {}; }
        if (schema == PendingIrpClaimPublicationSchema)
        {
            IndexedObject publication, report;
            std::wstring payload, raw, claim;
            if (!capture.Raw(L"payload", &payload) || !matchesHash(capture, L"publication_sha256", payload) ||
                !publication.Parse(payload) || !publication.Raw(L"capture", &raw) || !publication.Raw(L"recorded_claim", &claim) ||
                !report.Parse(claim) || report.String(L"schema") != L"kn.irp_claim_report.v1" ||
                !matchesHash(report, L"capture_sha256", raw) || !capture.Parse(raw)) { return {}; }
        }
        const auto count = capture.String(L"reference_captured_bytes");
        if (capture.String(L"schema") != L"kn.irp_capture.v2" || !Id(count) || count.size() > 8) { return {}; }
        uint64_t bytes = 0;
        for (const auto digit : count) { bytes = bytes * 10 + (digit - L'0'); }
        if (bytes > MaxBlobBytes) { return {}; }
        if (!bytes) { return {L"", 0, true}; }
        std::vector<std::wstring> packages;
        if (!capture.Rows(L"schemas", 3, &packages) || packages.size() != 3) { return {}; }
        std::wstring hash;
        for (const auto& item : packages)
        {
            IndexedObject package, identity;
            std::wstring payload;
            if (!package.Parse(item) || package.String(L"schema") != L"kn.type_schema.v1" || !package.Raw(L"payload", &payload) ||
                !matchesHash(package, L"package_sha256", payload) || !identity.Parse(payload)) { return {}; }
            const auto image = identity.String(L"image_sha256");
            if (!Digest(image) || (!hash.empty() && hash != image)) { return {}; }
            hash = image;
        }
        return {std::move(hash), bytes, true};
    }

    // Publication catalogs bind physical originals. Assessment replay has its own entry point.
    using ApprovalInputs = std::map<std::wstring, EvidenceJournalMember>;
    bool ReadApprovalInputs(const EvidenceJournalMember& root, const std::wstring& id,
        const std::wstring& json, ApprovalInputs& inputs)
    {
        IndexedObject envelope, catalog, recorded;
        std::wstring payload, assessment;
        if (!envelope.Parse(json) || !envelope.Raw(L"payload", &payload)) { return false; }
        const auto seal = envelope.String(L"publication_sha256");
        if (!Digest(seal) || Hash(payload) != seal || !catalog.Parse(payload) || catalog.String(L"collection_id") != id ||
            !catalog.Raw(L"assessment", &assessment) || !recorded.Parse(assessment)) { return false; }
        const bool scoped = root.Schema == ImageScopeApprovalPublicationSchema;
        if (recorded.String(L"schema") != (scoped ? L"kn.image_scope_change_assessment.v1" : L"kn.image_change_assessment.v1"))
            { return false; }
        const auto commonHash = [&](const wchar_t* key)
        {
            const auto hash = catalog.String(key);
            return hash == recorded.String(key) ? hash : std::wstring{};
        };
        const auto declare = [&](const std::wstring& hash, const std::wstring& prefix, const wchar_t* suffix, const wchar_t* schema)
        {
            if (!Digest(hash)) { return false; }
            const auto path = prefix + hash + suffix;
            return inputs.emplace(path, EvidenceJournalMember{path, hash, schema, 0}).second;
        };
        const auto policy = commonHash(L"policy_sha256");
        if (policy != recorded.String(L"policy_anchor_sha256") ||
            !declare(commonHash(L"reference_sha256"), L"image-references/", L".knblob", L"raw.bytes") ||
            !declare(policy, L"image-approvals/policy-", L".knapproval", L"kn.image_approval_policy.v1") ||
            !declare(commonHash(L"manifest_sha256"), L"image-approvals/changes-", L".knchange", L"kn.authorized_image_changes.v1")) { return false; }
        if (root.Schema == ImageApprovalPublicationSchema)
            { return declare(catalog.String(L"capture_sha256"), L"image-captures/capture-" + id + L"-", L".kncapture", L""); }
        const auto kind = catalog.String(L"scope_kind"), rootHash = catalog.String(L"root_sha256");
        std::vector<std::wstring> rows;
        if (!scoped || (kind != L"slice" && kind != L"sweep") || rootHash != recorded.String(L"root_file_sha256") || !Digest(rootHash) ||
            !catalog.Rows(L"inputs", ImageScopeApprovalMaximumInputs, &rows) || (kind == L"slice" && rows.size() != 1)) { return false; }
        std::wstring previousName;
        uint64_t total = 0;
        bool hasRoot = false;
        for (const auto& row : rows)
        {
            IndexedObject entry;
            if (!entry.Parse(row)) { return false; }
            const auto name = entry.String(L"logical_path"), hash = entry.String(L"sha256");
            EvidenceJournalMember m{L"image-scope-inputs/" + hash + L".knscopeblob", hash, entry.String(L"schema"), 0};
            if (!IsImageScopeApprovalInputName(name, kind == L"sweep") || name <= previousName ||
                !Number(row, L"bytes", &m.Bytes) || !MemberValid(m, id) ||
                m.Bytes > ImageScopeApprovalMaximumInputBytes - total) { return false; }
            previousName = name; total += m.Bytes;
            const auto found = inputs.emplace(m.Path, m);
            if (!found.second && !Same(found.first->second, m)) { return false; }
            if (name == ImageScopeApprovalRootName(kind == L"sweep")) { hasRoot = hash == rootHash; }
        }
        return hasRoot;
    }
    bool MatchesApprovalInput(const EvidenceJournalMember& declaration, const EvidenceJournalMember& file)
    {
        return declaration.Path == file.Path && declaration.Sha256 == file.Sha256 &&
            (declaration.Schema.empty() || declaration.Schema == file.Schema) && (!declaration.Bytes || declaration.Bytes == file.Bytes);
    }
    struct Record
    {
        uint64_t Sequence = 0;
        std::wstring Previous, Hash;
        EvidenceJournalTransaction Transaction;
    };
    std::wstring TransactionJson(const EvidenceJournalTransaction& t)
    {
        std::wstring json = L"{\"kind\":" + mcpjson::Quote(t.Kind) + L",\"id\":" + mcpjson::Quote(t.Id) + L",\"members\":[";
        for (const auto& m : t.Members)
        {
            if (&m != &t.Members.front()) { json += L","; }
            json += MemberJson(m);
        }
        json += L"],\"requires\":[";
        for (const auto& path : t.Requires)
        {
            if (&path != &t.Requires.front()) { json += L","; }
            json += mcpjson::Quote(path);
        }
        return json + L"]}";
    }
    std::wstring RecordJson(const std::wstring& id, const Record& r)
    {
        return Envelope(L"kn.evidence_journal_segment.v1", L"{\"collection_id\":" + mcpjson::Quote(id) +
            L",\"sequence\":" + N(r.Sequence) + L",\"previous_sha256\":" + mcpjson::Quote(r.Previous) +
            L",\"transaction\":" + TransactionJson(r.Transaction) + L"}");
    }
    bool ParseRecord(const std::wstring& json, const std::wstring& id, Record* r)
    {
        std::wstring payload, transaction;
        std::vector<std::wstring> members, required;
        if (!mcpjson::ValidateDocument(json) || !mcpjson::FindRawValue(json, L"payload", &payload) ||
            !Number(payload, L"sequence", &r->Sequence) || !mcpjson::GetString(payload, L"previous_sha256", &r->Previous) ||
            !mcpjson::FindRawValue(payload, L"transaction", &transaction) ||
            !mcpjson::GetString(transaction, L"kind", &r->Transaction.Kind) || !mcpjson::GetString(transaction, L"id", &r->Transaction.Id) ||
            !Array(transaction, L"members", 8192, &members) || !Array(transaction, L"requires", 8192, &required)) { return false; }
        for (const auto& row : members)
        {
            EvidenceJournalMember m;
            if (!mcpjson::GetString(row, L"path", &m.Path) || !mcpjson::GetString(row, L"sha256", &m.Sha256) ||
                !mcpjson::GetString(row, L"schema", &m.Schema) || !Number(row, L"bytes", &m.Bytes)) { return false; }
            r->Transaction.Members.push_back(std::move(m));
        }
        for (const auto& raw : required)
        {
            std::wstring path;
            if (!mcpjson::GetString(L"{\"p\":" + raw + L"}", L"p", &path)) { return false; }
            r->Transaction.Requires.push_back(std::move(path));
        }
        if (RecordJson(id, *r) != json) { return false; }
        r->Hash = Hash(json);
        return true;
    }
}

struct EvidenceStoreLease::Impl
{
    Handle Lock{nullptr, &CloseHandle};
    std::vector<Handle> Directories;
};

EvidenceStoreLease::EvidenceStoreLease() : Data(std::make_unique<Impl>()) {}
EvidenceStoreLease::~EvidenceStoreLease() = default;

bool EvidenceStoreLease::Acquire(const std::wstring& root, bool exclusive, std::wstring* error, bool createRoot)
{
    if (Data->Lock) { if (error) { *error = L"store_lease_already_owned"; } return false; }
    const auto fail = [&](const wchar_t* issue)
    {
        Data->Lock.reset(); Data->Directories.clear();
        if (error) { *error = issue; }
        return false;
    };
    if (!Text(root, 30000)) { return fail(L"invalid_store_root"); }
    std::error_code ec;
    const auto absolute = fs::absolute(root, ec).lexically_normal();
    const auto text = absolute.wstring();
    if (ec || text.size() < 3 || text.size() > 30000 || text[1] != L':' || text.find(L':', 2) != std::wstring::npos)
        { return fail(L"store_requires_local_directory"); }
    auto current = absolute.root_path();
    std::vector<fs::path> paths{current};
    for (const auto& part : absolute.relative_path())
    {
        const auto name = part.wstring();
        if (!name.empty() && (name.back() == L'.' || name.back() == L' ')) { return fail(L"noncanonical_store_directory"); }
        current /= part; paths.push_back(current);
    }
    for (const auto& path : paths)
    {
        const auto native = NativePath(path);
        if (createRoot && !CreateDirectoryW(native.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS && path != absolute.root_path())
            { return fail(L"store_directory_creation_failed"); }
        auto handle = Own(CreateFileW(native.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!handle || !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            { return fail(L"store_directory_missing_or_reparse"); }
        Data->Directories.push_back(std::move(handle));
    }
    Data->Lock = Own(CreateFileW(NativePath(absolute / L"store.knstorelock").c_str(),
        exclusive ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, exclusive ? 0 : FILE_SHARE_READ,
        nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!Data->Lock) { return fail(GetLastError() == ERROR_SHARING_VIOLATION ? L"store_busy" : L"store_lock_unavailable"); }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    LARGE_INTEGER size{};
    if (GetFileType(Data->Lock.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(Data->Lock.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileSizeEx(Data->Lock.get(), &size) || size.QuadPart != 0) { Data->Lock.reset(); return fail(L"store_lock_invalid"); }
    if (error) { error->clear(); }
    return true;
}

struct EvidenceJournal::Impl
{
    struct VerifiedMembers
    {
        std::map<std::wstring, Handle> Files;
        std::map<std::wstring, std::wstring> ImagePayloads;
        std::wstring SourceLedger, SourceClaimBinding;
    };
    fs::path Root, Collection;
    EvidenceJournalRecovery Result;
    std::map<std::wstring, Handle> Directories, Files;
    Handle Lock{nullptr, &CloseHandle};
    std::unique_ptr<EvidenceStoreLease> StoreLease;
    std::map<std::wstring, std::pair<EvidenceJournalMember, Handle>>* SharedMembers = nullptr;
    std::map<std::wstring, IrpReferenceCatalog>* StoreIrpCatalogs = nullptr;
    uint64_t* SharedReadBytes = nullptr;
    uint64_t* SharedReferences = nullptr;
    const wchar_t* SharedBudgetIssue = nullptr;
    store_files::Snapshot* PhysicalSnapshot = nullptr;
    uint64_t ReadBudget = MaxReadBytes;
    std::map<std::wstring, EvidenceJournalMember> Members;
    std::map<std::wstring, std::wstring> ImagePayloads;
    std::map<std::wstring, uint64_t> ContentSizes;
    std::map<std::wstring, size_t> Transactions;
    std::vector<Record> Records;
    uint64_t References = 0, Started = GetTickCount64();
    bool Writable = false, Healthy = false;
    bool Typed = false;
    bool Claims = false;
    bool IrpClaims = false;
    bool Direct = false;
    bool Approved = false;
    bool ScopedApproval = false;
    bool SourceArchive = false;
    std::wstring ExpectedSourceLedger;
    bool RetirementSeen = false;
    bool InspectPriority = false, SweepHasGap = false;
    std::array<uint64_t, 5> ImageTickets{};
    CollectionPriority ImagePriority = CollectionPriority::Unknown, IrpPriority = CollectionPriority::Empty;
    std::function<bool(HANDLE)> AdmitOutput;

    bool Fail(const wchar_t* issue) { Result.Issue = issue; return false; }
    void Incomplete()
    {
        // Historical records have no verified original-file prefix until their
        // complete closed chain has been bound to the retirement receipt.
        if (RetirementSeen)
        {
            EvidenceJournalRecovery failed;
            failed.Issue = std::move(Result.Issue); failed.CollectionId = std::move(Result.CollectionId); failed.ReadBytes = Result.ReadBytes;
            Result = std::move(failed);
        }
        Result.Status = Result.CommittedSegments ? L"incomplete_prefix" : L"unavailable";
        Result.Closed = Result.CanResume = false;
    }
    bool Timely() { return GetTickCount64() - Started <= DeadlineMs || Fail(L"deadline_exhausted"); }
    bool PinDirectory(const fs::path& directory, bool create)
    {
        std::error_code error;
        auto absolute = fs::absolute(directory, error).lexically_normal();
        const auto text = absolute.wstring();
        if (error || text.size() < 3 || text.size() > 30000 || text[1] != L':' || text.find(L':', 2) != std::wstring::npos ||
            text.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(text) != text) { return Fail(L"nonlocal_directory"); }
        auto current = absolute.root_path();
        std::vector<fs::path> paths{current};
        for (const auto& part : absolute.relative_path())
        {
            const auto name = part.wstring();
            if (!name.empty() && (name.back() == L'.' || name.back() == L' ')) { return Fail(L"noncanonical_directory_component"); }
            current /= part; paths.push_back(current);
        }
        for (const auto& path : paths)
        {
            if (Directories.count(path.wstring())) { continue; }
            if (!Timely()) { return false; }
            const auto native = NativePath(path);
            if (create && !CreateDirectoryW(native.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS && path != absolute.root_path())
                { return Fail(L"directory_creation_failed"); }
            auto handle = Own(CreateFileW(native.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (!handle || !GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                { return Fail(L"directory_missing_or_reparse"); }
            Directories.emplace(path.wstring(), std::move(handle));
        }
        return true;
    }
    bool Read(const fs::path& path, uint64_t maximum, Handle* owner, std::wstring* digest, uint64_t* size, std::wstring* json = nullptr,
        DWORD additionalAccess = 0, const std::wstring* physicalName = nullptr)
    {
        if (!PinDirectory(path.parent_path(), false) || !Timely()) { return false; }
        auto file = Own(CreateFileW(NativePath(path).c_str(), GENERIC_READ | additionalAccess, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        LARGE_INTEGER length{};
        if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            !GetFileSizeEx(file.get(), &length) || length.QuadPart <= 0 || uint64_t(length.QuadPart) > maximum)
            { return Fail(L"file_missing_invalid_or_locked"); }
        if (AdmitOutput && !AdmitOutput(file.get())) { return Fail(L"private_file_admission_failed"); }
        *size = uint64_t(length.QuadPart);
        if (*size > ReadBudget - Result.ReadBytes)
        {
            if (ReadBudget == StoreMaxReadBytes) { SharedBudgetIssue = L"store_read_budget_exhausted"; return Fail(SharedBudgetIssue); }
            return Fail(L"read_budget_exhausted");
        }
        if (SharedReadBytes != nullptr && *size > StoreMaxReadBytes - *SharedReadBytes)
            { SharedBudgetIssue = L"store_read_budget_exhausted"; return Fail(SharedBudgetIssue); }
        store_files::Entry* entry = nullptr;
        std::wstring chunks;
        if (PhysicalSnapshot && physicalName)
        {
            entry = PhysicalSnapshot->Match(*physicalName, file.get());
            if (!entry) { return Fail(L"store_file_identity_mismatch"); }
            chunks = store_files::StartChunks(*size);
        }
        ContentHash hash;
        uint8_t buffer[store_files::BlockBytes];
        std::string bytes;
        if (json != nullptr) { bytes.reserve(static_cast<size_t>(*size)); }
        uint64_t remaining = *size;
        while (remaining)
        {
            const auto count = static_cast<DWORD>((std::min)(remaining, uint64_t(sizeof(buffer))));
            DWORD received = 0;
            if (!Timely()) { return false; }
            const bool read = ReadFile(file.get(), buffer, count, &received, nullptr) != FALSE;
            Result.ReadBytes += received;
            if (SharedReadBytes != nullptr) { *SharedReadBytes += received; }
            if (!read || received != count || !hash.Add(buffer, received)) { return Fail(L"file_read_failed_or_timed_out"); }
            if (entry && !store_files::AppendChunk(chunks, *size - remaining, buffer, received)) { return Fail(L"store_file_hash_failed"); }
            if (json != nullptr) { bytes.append(reinterpret_cast<const char*>(buffer), received); }
            remaining -= received;
        }
        *digest = hash.Finish();
        if (!Digest(*digest)) { return Fail(L"file_hash_failed"); }
        if (entry)
        {
            if (!entry->ObservedChunks.empty() && entry->ObservedChunks != chunks) { return Fail(L"store_file_bytes_changed"); }
            entry->ObservedChunks = std::move(chunks);
        }
        if (json != nullptr)
        {
            *json = mcpjson::Utf8ToWide(bytes);
            if (mcpjson::WideToUtf8(*json) != bytes || !mcpjson::ValidateDocument(*json)) { return Fail(L"invalid_json_bytes"); }
        }
        *owner = std::move(file);
        return true;
    }
    bool ValidateTransaction(const EvidenceJournalTransaction& t)
    {
        const bool irp = Typed && t.Kind == L"irp_capture", irpLedger = Typed && t.Kind == L"irp_ledger";
        const bool directCapture = Direct && t.Kind == L"image_capture";
        const bool approval = Approved && t.Kind == L"image_approval";
        const bool scopedApproval = ScopedApproval && t.Kind == L"image_scope_approval";
        const bool source = SourceArchive && t.Kind == L"image_source";
        const bool single = Direct || Approved || ScopedApproval || SourceArchive;
        if ((single ? (!directCapture && !approval && !scopedApproval && !source && t.Kind != L"closure") :
                (t.Kind != L"image_reads" && t.Kind != L"image_sweep" && t.Kind != L"closure" && !irp && !irpLedger)) ||
            (irp || directCapture || approval || scopedApproval || source ? !Digest(t.Id) : !Id(t.Id)) ||
            t.Members.empty() || t.Members.size() > 8192 || t.Requires.size() > 8192 ||
            t.Members.size() + t.Requires.size() > MaxReferences - References) { return Fail(L"invalid_transaction_or_reference_budget"); }
        if (SharedReferences != nullptr && t.Members.size() + t.Requires.size() > StoreMaxReferences - *SharedReferences)
            { SharedBudgetIssue = L"store_reference_budget_exhausted"; return Fail(SharedBudgetIssue); }
        if ((t.Kind == L"closure" && (t.Id != L"0" || t.Members.size() != 1 ||
                t.Members[0].Path != (SourceArchive ? ImageSourceSessionPath(Result.CollectionId) :
                    ScopedApproval ? L"image-approvals/scope-session-" + Result.CollectionId + L".knscopeledger" :
                    Approved ? L"image-approvals/session-" + Result.CollectionId + L".knapprovalledger" :
                    Direct ? L"image-captures/session-" + Result.CollectionId + L".kncaptureledger" :
                    L"image-reads/session-" + Result.CollectionId + L".knreadledger"))) ||
            (t.Kind == L"image_sweep" && (t.Members.size() != 1 || t.Members[0].Path !=
                L"image-sweeps/sweep-" + Result.CollectionId + L"-" + t.Id + L".knsweep"))) { return Fail(L"invalid_transaction_root"); }
        const auto irpLedgerPath = L"irp-session-" + Result.CollectionId + L".knirpledger";
        if (irp && (t.Members.size() > 2 || !t.Requires.empty() || Transactions.count(L"irp_ledger:0")))
            { return Fail(L"invalid_irp_transaction_or_after_ledger"); }
        if (irpLedger && (t.Id != L"0" || t.Members.size() != 1 || t.Members[0].Path != irpLedgerPath || !t.Requires.empty()))
            { return Fail(L"invalid_irp_ledger_root"); }
        if (Typed && t.Kind == L"closure")
        {
            const bool hasIrp = std::any_of(Records.begin(), Records.end(), [](const auto& r)
                { return r.Transaction.Kind == L"irp_capture" || r.Transaction.Kind == L"irp_ledger"; });
            if (hasIrp && (!Transactions.count(L"irp_ledger:0") ||
                std::find(t.Requires.begin(), t.Requires.end(), irpLedgerPath) == t.Requires.end()))
                { return Fail(L"irp_ledger_required_before_closure"); }
        }
        if (directCapture && (t.Members.size() != 2 || !t.Requires.empty() || !Records.empty()))
            { return Fail(L"one_direct_capture_required_per_collection"); }
        if (approval && (t.Members.size() != 5 || !t.Requires.empty() || !Records.empty()))
            { return Fail(L"one_approval_with_five_members_required"); }
        if (scopedApproval && (t.Members.size() < 5 || t.Members.size() > ImageScopeApprovalMaximumInputs + 4 ||
            !t.Requires.empty() || !Records.empty())) { return Fail(L"one_scoped_approval_with_original_inputs_required"); }
        if (source && (!Records.empty() || !t.Requires.empty() || (t.Members.size() != 1 && t.Members.size() != 3)))
            { return Fail(L"invalid_image_source_members"); }
        if (single && t.Kind == L"closure")
        {
            if (Records.size() != 1 || Records.front().Transaction.Kind != (SourceArchive ? L"image_source" : ScopedApproval ? L"image_scope_approval" : Approved ? L"image_approval" : L"image_capture"))
                { return Fail(L"direct_capture_required_before_closure"); }
            std::vector<std::wstring> required;
            for (const auto& member : Records.front().Transaction.Members) { required.push_back(member.Path); }
            if (t.Requires != required) { return Fail(L"direct_capture_dependencies_required"); }
        }
        std::wstring previous;
        size_t added = 0;
        bool irpRoot = false, directRoot = false, sourceRoot = false;
        bool approvalRoot = false, approvalCapture = false, approvalReference = false, approvalPolicy = false, approvalManifest = false;
        uint64_t scopeInputs = 0, scopeInputBytes = 0;
        for (const auto& m : t.Members)
        {
            if (!MemberValid(m, Result.CollectionId) || (!previous.empty() && m.Path <= previous)) { return Fail(L"invalid_or_duplicate_member"); }
            if (!Claims && !ScopedApproval && m.Schema == ImageScopeClaimPublicationSchema) { return Fail(L"claim_publication_requires_v3_policy"); }
            if (!IrpClaims && m.Schema == PendingIrpClaimPublicationSchema) { return Fail(L"irp_claim_publication_requires_v4_policy"); }
            if (!Direct && !Approved && !SourceArchive && DirectPath(m.Path)) { return Fail(L"direct_capture_policy_required"); }
            if (!Approved && !ScopedApproval && ApprovalPath(m.Path)) { return Fail(L"approval_collection_policy_required"); }
            if (!ScopedApproval && ScopeInputPath(m.Path)) { return Fail(L"scope_approval_collection_policy_required"); }
            if ((!irp && !irpLedger && IrpPath(m.Path)) || (irpLedger && m.Schema != L"kn.irp_capture_session.v1"))
                { return Fail(L"invalid_member_kind"); }
            if (irp)
            {
                if (m.Path == L"irp-" + Result.CollectionId + L"-" + t.Id + L".knirp" && m.Sha256 == t.Id &&
                    (m.Schema == L"kn.irp_capture.v1" || m.Schema == L"kn.irp_capture.v2" ||
                        m.Schema == PendingIrpClaimPublicationSchema)) { irpRoot = true; }
                else if (m.Schema != L"raw.bytes" || m.Path != L"irp-reference-" + m.Sha256 + L".knblob")
                    { return Fail(L"invalid_irp_transaction_member"); }
            }
            if (directCapture)
            {
                if (m.Path == L"image-captures/capture-" + Result.CollectionId + L"-" + t.Id + L".kncapture" && m.Sha256 == t.Id)
                    { directRoot = true; }
                else if (m.Schema != L"raw.bytes" || m.Path != L"image-references/" + m.Sha256 + L".knblob")
                    { return Fail(L"invalid_direct_capture_member"); }
            }
            if (source)
            {
                if (m.Path == ImageSourceReportPath(Result.CollectionId, t.Id) && m.Sha256 == t.Id) { sourceRoot = true; }
                else if (m.Path != ImageSourceCasePath(Result.CollectionId, t.Id) && m.Path != L"image-references/" + m.Sha256 + L".knblob")
                    { return Fail(L"invalid_image_source_member"); }
            }
            if (approval)
            {
                if (m.Path == L"image-approvals/assessment-" + Result.CollectionId + L".knapprovalcase" && m.Sha256 == t.Id)
                    { approvalRoot = true; }
                else if (m.Path == L"image-captures/capture-" + Result.CollectionId + L"-" + m.Sha256 + L".kncapture")
                    { approvalCapture = true; }
                else if (m.Path == L"image-references/" + m.Sha256 + L".knblob") { approvalReference = true; }
                else if (m.Path == L"image-approvals/policy-" + m.Sha256 + L".knapproval") { approvalPolicy = true; }
                else if (m.Path == L"image-approvals/changes-" + m.Sha256 + L".knchange") { approvalManifest = true; }
                else { return Fail(L"invalid_approval_transaction_member"); }
            }
            if (scopedApproval)
            {
                if (m.Path == L"image-approvals/scope-assessment-" + Result.CollectionId + L".knscopeapproval" && m.Sha256 == t.Id)
                    { approvalRoot = true; }
                else if (ScopeInputPath(m.Path))
                {
                    if (m.Bytes > ImageScopeApprovalMaximumInputBytes - scopeInputBytes) { return Fail(L"scope_input_byte_budget_exhausted"); }
                    ++scopeInputs; scopeInputBytes += m.Bytes;
                }
                else if (m.Path == L"image-references/" + m.Sha256 + L".knblob")
                    { if (approvalReference) { return Fail(L"duplicate_scope_reference"); } approvalReference = true; }
                else if (m.Path == L"image-approvals/policy-" + m.Sha256 + L".knapproval")
                    { if (approvalPolicy) { return Fail(L"duplicate_scope_policy"); } approvalPolicy = true; }
                else if (m.Path == L"image-approvals/changes-" + m.Sha256 + L".knchange")
                    { if (approvalManifest) { return Fail(L"duplicate_scope_manifest"); } approvalManifest = true; }
                else { return Fail(L"invalid_scope_approval_member"); }
            }
            if (t.Kind == L"image_reads" && m.Schema != L"raw.bytes" &&
                m.Path != L"image-reads/reads-" + Result.CollectionId + L"-" + t.Id + L".knreads" &&
                m.Path != L"image-reads/reads-" + Result.CollectionId + L"-" + t.Id + L".knslice") { return Fail(L"invalid_read_transaction_member"); }
            const auto found = Members.find(m.Path);
            if (found != Members.end() && !Same(found->second, m)) { return Fail(L"conflicting_committed_path"); }
            if (found == Members.end()) { ++added; }
            const auto content = ContentSizes.find(m.Sha256);
            if (content != ContentSizes.end() && content->second != m.Bytes) { return Fail(L"conflicting_content_size"); }
            previous = m.Path;
        }
        if (irp && !irpRoot) { return Fail(L"irp_capture_root_required"); }
        if (directCapture && !directRoot) { return Fail(L"direct_capture_root_required"); }
        if (source && !sourceRoot) { return Fail(L"image_source_report_required"); }
        if (approval && !(approvalRoot && approvalCapture && approvalReference && approvalPolicy && approvalManifest))
            { return Fail(L"approval_member_set_incomplete"); }
        if (scopedApproval && !(approvalRoot && scopeInputs && approvalReference && approvalPolicy && approvalManifest))
            { return Fail(L"scope_approval_member_set_incomplete"); }
        if (added > MaxPaths - Members.size()) { return Fail(L"member_budget_exhausted"); }
        previous.clear();
        for (const auto& path : t.Requires)
        {
            if ((!previous.empty() && path <= previous) || !Members.count(path)) { return Fail(L"dependency_not_committed_or_duplicate"); }
            previous = path;
        }
        return true;
    }
    bool VerifyImageCatalog(const EvidenceJournalTransaction& t, const EvidenceJournalMember& root,
        ImageArchiveKind kind, const std::wstring& json, VerifiedMembers& added)
    {
        ImageArchiveCatalog catalog;
        if (!ReadImageArchiveCatalog(kind, root, json, catalog, InspectPriority)) { return Fail(L"image_archive_catalog_invalid"); }
        if (kind == ImageArchiveKind::Sweep)
        {
            SweepHasGap |= catalog.SweepHasGap;
            for (const auto& input : catalog.Inputs)
            {
                const auto member = Members.find(input.first);
                const auto payload = ImagePayloads.find(input.first);
                if (member == Members.end() || !std::binary_search(t.Requires.begin(), t.Requires.end(), input.first) ||
                    !MatchesImageArchiveInput(input.second, member->second, payload == ImagePayloads.end() ? L"" : payload->second))
                    { return Fail(L"image_sweep_input_not_committed"); }
            }
            if (catalog.Inputs.size() != t.Requires.size()) { return Fail(L"image_sweep_dependency_set_mismatch"); }
        }
        else
        {
            for (const auto& input : catalog.Inputs)
            {
                const auto member = std::lower_bound(t.Members.begin(), t.Members.end(), input.first,
                    [](const auto& m, const auto& path) { return m.Path < path; });
                const auto payload = added.ImagePayloads.find(input.first);
                if (member == t.Members.end() || member->Path != input.first ||
                    !MatchesImageArchiveInput(input.second, *member, payload == added.ImagePayloads.end() ? L"" : payload->second))
                    { return Fail(L"image_reference_not_committed"); }
            }
        }
        if (InspectPriority && kind == ImageArchiveKind::Reads && t.Kind == L"image_reads")
        {
            auto priority = ReadImageTicketPriority(catalog.RetentionTicket);
            const auto slice = L"image-reads/reads-" + Result.CollectionId + L"-" + t.Id + L".knslice";
            if (priority == CollectionPriority::Routine && (catalog.Inputs.empty() || std::none_of(t.Members.begin(), t.Members.end(),
                [&](const auto& member) { return member.Path == slice; }))) { priority = CollectionPriority::Gap; }
            ++ImageTickets[static_cast<size_t>(priority)];
        }
        if (kind == ImageArchiveKind::SourceReport)
        {
            if (t.Kind != L"image_source" || catalog.Inputs.size() + 1 != t.Members.size() ||
                added.SourceClaimBinding != catalog.SourceClaimBinding) { return Fail(L"capture_report_dependencies_mismatch"); }
            added.SourceLedger = ImageSourceSessionJson(Result.CollectionId, t.Members, catalog.CaptureStatus, catalog.SourceStatus);
        }
        if (t.Kind == L"image_source" && kind == ImageArchiveKind::Capture) { added.SourceClaimBinding = std::move(catalog.SourceClaimBinding); }
        if (kind == ImageArchiveKind::Reads || kind == ImageArchiveKind::Slice || (t.Kind == L"image_source" && kind == ImageArchiveKind::Capture))
            { added.ImagePayloads.emplace(root.Path, std::move(catalog.PayloadSha256)); }
        return Timely();
    }
    bool VerifyMembers(const EvidenceJournalTransaction& t, VerifiedMembers* added, bool ledgersOnly = false)
    {
        for (const auto& m : t.Members)
        {
            if (ledgersOnly && !FailureLedger(m.Schema)) { continue; }
            const auto imageKind = ImageArchiveKindForPath(m.Path);
            if (Members.count(m.Path) && imageKind == ImageArchiveKind::None) { continue; } // Still pinned.
            if (SharedMembers != nullptr)
            {
                const auto found = SharedMembers->find(m.Path);
                if (found != SharedMembers->end())
                {
                    if (!Same(found->second.first, m)) { return Fail(L"store_member_conflict"); }
                    if (imageKind == ImageArchiveKind::None)
                    {
                        HANDLE duplicate = nullptr;
                        if (!DuplicateHandle(GetCurrentProcess(), found->second.second.get(), GetCurrentProcess(), &duplicate, 0, FALSE,
                            DUPLICATE_SAME_ACCESS)) { return Fail(L"store_lease_duplicate_failed"); }
                        added->Files.emplace(m.Path, Own(duplicate));
                        continue;
                    }
                }
                else if (SharedMembers->size() == StoreMaxPaths)
                    { SharedBudgetIssue = L"store_path_budget_exhausted"; return Fail(SharedBudgetIssue); }
            }
            Handle file{nullptr, &CloseHandle};
            std::wstring digest, json, schema;
            uint64_t size = 0;
            if (!Read(Root / m.Path, m.Bytes, &file, &digest, &size, m.Schema == L"raw.bytes" ? nullptr : &json, 0, &m.Path)) { return false; }
            if (digest != m.Sha256 || size != m.Bytes) { return Fail(L"member_hash_or_size_mismatch"); }
            if (m.Schema != L"raw.bytes" && (!mcpjson::GetString(json, L"schema", &schema) || schema != m.Schema))
                { return Fail(L"member_schema_mismatch"); }
            if (imageKind != ImageArchiveKind::None && !VerifyImageCatalog(t, m, imageKind, json, *added)) { return false; }
            if (!ledgersOnly && m.Schema == ImageSourceCollectionLedger && json != ExpectedSourceLedger)
                { return Fail(L"image_source_ledger_mismatch"); }
            if (InspectPriority && !ledgersOnly && (m.Schema == L"kn.image_read_session.v1" || m.Schema == L"kn.irp_capture_session.v1"))
            {
                const auto count = [&](const wchar_t* kind)
                    { return std::count_if(Records.begin(), Records.end(), [&](const auto& r) { return r.Transaction.Kind == kind; }); };
                const bool irp = m.Schema == L"kn.irp_capture_session.v1";
                (irp ? IrpPriority : ImagePriority) = ReadLedgerPriority(json, Result.CollectionId, irp,
                    count(irp ? L"irp_capture" : L"image_reads"), count(L"image_sweep"), ImageTickets);
            }
            if (StoreIrpCatalogs && IrpCaptureSchema(m.Schema)) { StoreIrpCatalogs->emplace(m.Path, ReadIrpReferenceCatalog(m.Schema, json)); }
            if (SharedMembers != nullptr)
            {
                HANDLE duplicate = nullptr;
                if (!DuplicateHandle(GetCurrentProcess(), file.get(), GetCurrentProcess(), &duplicate, 0, FALSE,
                    DUPLICATE_SAME_ACCESS)) { return Fail(L"store_lease_duplicate_failed"); }
                SharedMembers->emplace(m.Path, std::make_pair(m, Own(duplicate)));
            }
            added->Files.emplace(m.Path, std::move(file));
        }
        if (!ledgersOnly && (t.Kind == L"image_approval" || t.Kind == L"image_scope_approval"))
        {
            const bool scoped = t.Kind == L"image_scope_approval";
            const auto schema = scoped ? ImageScopeApprovalPublicationSchema : ImageApprovalPublicationSchema;
            const auto root = std::find_if(t.Members.begin(), t.Members.end(), [&](const auto& m) { return m.Schema == schema; });
            Handle lease{nullptr, &CloseHandle};
            std::wstring json, digest;
            uint64_t size = 0;
            if (root == t.Members.end() || !Read(Root / root->Path, root->Bytes, &lease, &digest, &size, &json) || digest != t.Id)
                { return Fail(scoped ? L"scope_approval_catalog_unavailable" : L"approval_catalog_unavailable"); }
            ApprovalInputs declared;
            if (!ReadApprovalInputs(*root, Result.CollectionId, json, declared))
                { return Fail(scoped ? L"scope_approval_catalog_invalid" : L"approval_catalog_invalid"); }
            for (const auto& input : declared)
            {
                const auto member = std::lower_bound(t.Members.begin(), t.Members.end(), input.first,
                    [](const auto& m, const auto& path) { return m.Path < path; });
                if (member == t.Members.end() || !MatchesApprovalInput(input.second, *member))
                    { return Fail(scoped ? L"scope_approval_input_not_committed" : L"approval_input_not_committed"); }
            }
            if (declared.size() + 1 != t.Members.size())
                { return Fail(scoped ? L"scope_approval_dependency_set_mismatch" : L"approval_dependency_set_mismatch"); }
        }
        return true;
    }
    void Accept(Record r, VerifiedMembers added)
    {
        // Publish counters only after all allocating state changes succeed.
        // Any exception poisons the instance; recovery still reports the last
        // fully verified prefix rather than half of the next transaction.
        auto accepted = Result;
        Files.merge(added.Files);
        ImagePayloads.merge(added.ImagePayloads);
        if (!added.SourceLedger.empty()) { ExpectedSourceLedger = std::move(added.SourceLedger); }
        for (const auto& m : r.Transaction.Members)
        {
            ++accepted.MemberReferences; accepted.LogicalBytes += m.Bytes;
            if (ContentSizes.emplace(m.Sha256, m.Bytes).second) { accepted.UniqueContentBytes += m.Bytes; }
            Members.emplace(m.Path, m);
            if (m.Path.rfind(L"image-sweeps/", 0) == 0 && (m.Schema == L"kn.image_sweep.v1" || m.Schema == ImageScopeClaimPublicationSchema))
                { accepted.SweepPaths.push_back(m.Path); }
            if ((r.Transaction.Kind == L"image_capture" || r.Transaction.Kind == L"image_approval") && DirectPath(m.Path))
                { accepted.DirectCapturePaths.push_back(m.Path); }
            if (r.Transaction.Kind == L"image_source")
            {
                if (m.Schema == L"kn.image_capture.v3") { accepted.SourceReportPath = m.Path; }
                else if (DirectPath(m.Path)) { accepted.DirectCapturePaths.push_back(m.Path); }
            }
            if (r.Transaction.Kind == L"image_approval" && m.Schema == ImageApprovalPublicationSchema) { accepted.ApprovalPaths.push_back(m.Path); }
            if (r.Transaction.Kind == L"image_scope_approval" && m.Schema == ImageScopeApprovalPublicationSchema) { accepted.ApprovalPaths.push_back(m.Path); }
        }
        References += r.Transaction.Members.size() + r.Transaction.Requires.size();
        Transactions.emplace(r.Transaction.Kind + L":" + r.Transaction.Id, Records.size());
        accepted.CommittedSegments = r.Sequence; accepted.HeadSha256 = r.Hash; accepted.UniquePaths = Members.size();
        accepted.Closed = r.Transaction.Kind == L"closure";
        Records.push_back(std::move(r));
        Result = std::move(accepted);
        if (SharedReferences != nullptr)
            { *SharedReferences += Records.back().Transaction.Members.size() + Records.back().Transaction.Requires.size(); }
    }
    bool Load(const std::wstring& artifactRoot, const std::wstring& id, bool create, bool coordinated = false,
        EvidenceJournalPolicy requested = EvidenceJournalPolicy::ImageV1)
    {
        if (!Id(id)) { return Fail(L"invalid_collection_id"); }
        if (!Text(artifactRoot, 30000)) { return Fail(L"invalid_artifact_root"); }
        Result.CollectionId = id;
        std::error_code error;
        Root = fs::absolute(artifactRoot, error).lexically_normal();
        Collection = Root / L"collections" / id;
        if (!coordinated)
        {
            StoreLease = std::make_unique<EvidenceStoreLease>();
            if (!StoreLease->Acquire(artifactRoot, false, &Result.Issue, create)) { return false; }
        }
        if (error || !PinDirectory(Collection, create)) { return false; }
        // A writer must not recreate even a missing lock or session in a retired collection.
        const auto receipt = Collection / RetirementFile;
        const auto receiptPath = NativePath(receipt);
        RetirementSeen = GetFileAttributesW(receiptPath.c_str()) != INVALID_FILE_ATTRIBUTES;
        if (!RetirementSeen && GetLastError() != ERROR_FILE_NOT_FOUND) { return Fail(L"collection_retirement_state_unavailable"); }
        if (RetirementSeen && create) { return Fail(L"collection_retired_or_retirement_unresolved"); }
        Lock = Own(CreateFileW(NativePath(Collection / L"writer.knjlock").c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            create ? OPEN_ALWAYS : OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!Lock || !GetFileInformationByHandleEx(Lock.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            { return Fail(L"collection_busy_or_lock_unavailable"); }
        const auto manifest = Collection / L"session.knsession";
        const auto policyIndex = static_cast<size_t>(requested);
        if (policyIndex >= std::size(SessionPolicies)) { return Fail(L"unknown_journal_policy"); }
        const auto session = SessionJson(id, policyIndex);
        const auto attrs = GetFileAttributesW(NativePath(manifest).c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES && create && GetLastError() == ERROR_FILE_NOT_FOUND &&
            !SaveObservationJson(NativePath(manifest), session, nullptr, AdmitOutput)) { return Fail(L"session_publication_failed"); }
        Handle lease{nullptr, &CloseHandle};
        uint64_t bytes = 0;
        std::wstring json, payload, policyName;
        if (!Read(manifest, 4096, &lease, &Result.SessionSha256, &bytes, &json) ||
            !mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::GetString(payload, L"policy", &policyName))
            { return Fail(L"session_missing_or_invalid"); }
        const auto found = std::find(std::begin(SessionPolicies), std::end(SessionPolicies), policyName);
        if (found == std::end(SessionPolicies) || (create ? json != session : json != SessionJson(id, found - std::begin(SessionPolicies))))
            { return Fail(L"session_missing_or_invalid"); }
        const auto policy = static_cast<EvidenceJournalPolicy>(found - std::begin(SessionPolicies));
        Direct = policy == EvidenceJournalPolicy::DirectImageV1;
        Approved = policy == EvidenceJournalPolicy::ApprovedImageV1;
        ScopedApproval = policy == EvidenceJournalPolicy::ApprovedImageScopeV1;
        SourceArchive = policy == EvidenceJournalPolicy::ImageSourceV1;
        IrpClaims = policy == EvidenceJournalPolicy::ImageAndIrpClaimsV4;
        Claims = IrpClaims || policy == EvidenceJournalPolicy::ImageClaimsAndIrpV3;
        Typed = Claims || policy == EvidenceJournalPolicy::ImageAndIrpV2;
        Files.emplace(L"@session", std::move(lease));
        Result.HeadSha256 = Result.SessionSha256;
        RetirementRecord retirement;
        std::wstring receiptHash;
        if (RetirementSeen)
        {
            if (!Read(receipt, 16384, &lease, &receiptHash, &bytes, &json) || !ParseRetirementRecord(json, retirement) ||
                retirement.Policy.Id != id || retirement.Policy.Session != Result.SessionSha256) { return Fail(L"invalid_collection_retirement"); }
            Files.emplace(L"@retirement", std::move(lease));
        }
        if (!PinDirectory(Collection / L"journal-segments", create)) { return false; }
        std::set<std::wstring> names;
        for (fs::directory_iterator it(NativePath(Collection / L"journal-segments"), error), end; !error && it != end; it.increment(error))
        {
            if (!Timely()) { return false; }
            const auto name = it->path().filename().wstring();
            if (name.find(L".knjseg.pending-") != std::wstring::npos) { ++Result.PendingFiles; }
            else if (it->path().extension() == L".knjseg")
            {
                if (names.size() == MaxSegments) { return Fail(L"segment_budget_exhausted"); }
                names.insert(name);
            }
            else { return Fail(L"unexpected_segment_entry"); }
            if (Result.PendingFiles > MaxSegments) { return Fail(L"pending_file_budget_exhausted"); }
        }
        if (error) { return Fail(L"segment_enumeration_failed"); }
        for (const auto& name : names)
        {
            if (Result.Closed) { return Fail(L"segment_after_closure"); }
            if (name != SequenceName(Records.size() + 1)) { return Fail(L"segment_gap_or_invalid_name"); }
            Record r;
            std::wstring digest;
            if (!Read(Collection / L"journal-segments" / name, MaxJsonBytes, &lease, &digest, &bytes, &json) ||
                !ParseRecord(json, id, &r) || r.Hash != digest || r.Sequence != Records.size() + 1 || r.Previous != Result.HeadSha256)
                { return Fail(L"segment_invalid_or_chain_mismatch"); }
            const auto key = r.Transaction.Kind + L":" + r.Transaction.Id;
            if (Transactions.count(key)) { return Fail(L"duplicate_transaction"); }
            VerifiedMembers added;
            if (!ValidateTransaction(r.Transaction) || !VerifyMembers(r.Transaction, &added, RetirementSeen)) { return false; }
            Files.emplace(L"@segment-" + std::to_wstring(r.Sequence), std::move(lease));
            Accept(std::move(r), std::move(added));
        }
        if (RetirementSeen)
        {
            RetirementCount originals, ledgers;
            for (const auto& item : Members)
                { (FailureLedger(item.second.Schema) ? ledgers : originals).Add(item.second.Bytes); }
            if (!Result.Closed || retirement.Policy.Head != Result.HeadSha256 ||
                originals.Paths != retirement.Exclusive.Paths + retirement.Shared.Paths || originals.Bytes != retirement.Exclusive.Bytes + retirement.Shared.Bytes ||
                ledgers.Paths != retirement.Ledgers.Paths || ledgers.Bytes != retirement.Ledgers.Bytes) { return Fail(L"retirement_closure_or_impact_mismatch"); }
            Result.RetirementSha256 = std::move(receiptHash);
            Result.SweepPaths.clear(); Result.DirectCapturePaths.clear(); Result.ApprovalPaths.clear();
            Result.SourceReportPath.clear();
        }
        Result.Status = RetirementSeen ? L"retired" : L"verified_prefix"; Result.Issue.clear(); Result.CanResume = !Result.Closed;
        Writable = create && Result.CanResume; Healthy = true;
        return true;
    }
    bool PutDerived(const fs::path& path, const std::wstring& json)
    {
        if (!PinDirectory(path.parent_path(), true)) { return false; }
        const auto key = L"@index-" + path.wstring();
        if (Files.count(key)) { ++Result.IndexReused; return true; }
        const auto attr = GetFileAttributesW(NativePath(path).c_str());
        const bool exists = attr != INVALID_FILE_ATTRIBUTES;
        if (!exists && (GetLastError() != ERROR_FILE_NOT_FOUND || !SaveObservationJson(NativePath(path), json, nullptr, AdmitOutput)))
            { return Fail(L"derived_index_publication_failed"); }
        Handle lease{nullptr, &CloseHandle};
        uint64_t size = 0;
        std::wstring digest, existing;
        if (!Read(path, MaxJsonBytes, &lease, &digest, &size, &existing) || existing != json) { return Fail(L"derived_index_collision"); }
        Files.emplace(key, std::move(lease)); // Pin verified chunks through head publication.
        if (exists)
        {
            ++Result.IndexReused;
        }
        else { ++Result.IndexCreated; }
        return true;
    }
    bool IndexRecord(const Record& r)
    {
        const auto json = Envelope(L"kn.evidence_journal_index_chunk.v1", L"{\"collection_id\":" + mcpjson::Quote(Result.CollectionId) +
            L",\"sequence\":" + N(r.Sequence) + L",\"segment_sha256\":" + mcpjson::Quote(r.Hash) +
            L",\"transaction\":" + TransactionJson(r.Transaction) + L"}");
        return PutDerived(Collection / L"indexes" / L"chunks" / (r.Hash + L".knjindex"), json);
    }
    bool IndexHead()
    {
        std::wstring chunks = L"[";
        for (const auto& r : Records)
        {
            if (chunks.size() > 1) { chunks += L","; }
            chunks += mcpjson::Quote(r.Hash);
        }
        const auto json = Envelope(L"kn.evidence_journal_index.v1", L"{\"collection_id\":" + mcpjson::Quote(Result.CollectionId) +
            L",\"session_sha256\":" + mcpjson::Quote(Result.SessionSha256) + L",\"head_sha256\":" + mcpjson::Quote(Result.HeadSha256) +
            L",\"committed_segments\":" + N(Result.CommittedSegments) + L",\"closed\":" + B(Result.Closed) +
            L",\"member_references\":" + N(Result.MemberReferences) + L",\"unique_paths\":" + N(Result.UniquePaths) +
            L",\"logical_bytes\":" + N(Result.LogicalBytes) + L",\"unique_content_bytes\":" + N(Result.UniqueContentBytes) +
            L",\"chunks\":" + chunks + L"]}");
        return PutDerived(Collection / L"indexes" / L"heads" / (Result.HeadSha256 + L".knjindex"), json);
    }
};

EvidenceJournal::EvidenceJournal() : Data(std::make_unique<Impl>()) {}
EvidenceJournal::~EvidenceJournal() = default;
const EvidenceJournalRecovery& EvidenceJournal::State() const { return Data->Result; }

bool EvidenceJournal::Open(const std::wstring& root, const std::wstring& id, std::wstring* error,
    EvidenceJournalPolicy policy, std::function<bool(HANDLE)> admitOutput)
{
    if (Data->Lock) { if (error) { *error = L"journal_already_open"; } return false; }
    bool ok = false;
    try
    {
        Data->AdmitOutput = std::move(admitOutput);
        ok = Data->Load(root, id, true, false, policy);
    }
    catch (...) { Data->Fail(L"journal_open_exception"); }
    if (error) { *error = Data->Result.Issue; }
    return ok;
}

bool EvidenceJournal::RestrictOutputs(std::function<bool(HANDLE)> admitOutput)
{
    try
    {
        Data->Started = GetTickCount64();
        if (!Data->Healthy || !admitOutput || !admitOutput(Data->Lock.get())) { return false; }
        for (const auto& file : Data->Files) { if (!Data->Timely() || !admitOutput(file.second.get())) { return false; } }
        Data->AdmitOutput = std::move(admitOutput);
        return true;
    }
    catch (...) { return false; }
}

EvidenceJournalCommit EvidenceJournal::Commit(EvidenceJournalTransaction t)
{
    EvidenceJournalCommit result;
    auto& d = *Data;
    d.Started = GetTickCount64();
    try
    {
        if (!d.Healthy) { result.Issue = L"journal_unavailable_reopen_required"; return result; }
        std::sort(t.Members.begin(), t.Members.end(), [](const auto& a, const auto& b) { return a.Path < b.Path; });
        std::sort(t.Requires.begin(), t.Requires.end());
        const auto found = d.Transactions.find(t.Kind + L":" + t.Id);
        if (found != d.Transactions.end())
        {
            const auto& prior = d.Records[found->second];
            if (TransactionJson(prior.Transaction) != TransactionJson(t)) { result.Issue = L"transaction_id_conflict"; return result; }
            result.Committed = result.AlreadyCommitted = true; result.Sequence = prior.Sequence;
            result.Indexed = d.IndexRecord(prior) && (!d.Result.Closed || d.IndexHead());
            if (!result.Indexed) { result.Issue = d.Result.Issue; }
            return result;
        }
        if (!d.Writable || d.Records.size() == MaxSegments) { result.Issue = L"journal_closed_unavailable_or_segment_budget"; return result; }
        if (!d.ValidateTransaction(t)) { result.Issue = d.Result.Issue; return result; }
        Impl::VerifiedMembers added;
        if (!d.VerifyMembers(t, &added)) { result.Issue = d.Result.Issue; return result; }
        Record record;
        record.Sequence = d.Records.size() + 1; record.Previous = d.Result.HeadSha256; record.Transaction = std::move(t);
        const auto json = RecordJson(d.Result.CollectionId, record);
        if (mcpjson::WideToUtf8(json).size() > MaxJsonBytes) { result.Issue = L"segment_byte_budget"; return result; }
        record.Hash = Hash(json);
        if (!Digest(record.Hash)) { result.Issue = L"segment_hash_failed"; return result; }
        // On a failure after publication, this instance is poisoned; reopen
        // verifies the record and supports an exact idempotent retry.
        d.Writable = d.Healthy = d.Result.CanResume = false;
        const auto path = d.Collection / L"journal-segments" / SequenceName(record.Sequence);
        if (!SaveObservationJson(NativePath(path), json, nullptr, d.AdmitOutput))
            { result.Issue = L"segment_publication_failed_reopen_required"; return result; }
        result.Sequence = record.Sequence;
        Handle lease{nullptr, &CloseHandle};
        std::wstring digest, observed;
        uint64_t size = 0;
        if (!d.Read(path, MaxJsonBytes, &lease, &digest, &size, &observed) || digest != record.Hash || observed != json)
            { result.Issue = L"published_segment_changed_reopen_required"; return result; }
        d.Files.emplace(L"@segment-" + std::to_wstring(record.Sequence), std::move(lease));
        d.Accept(std::move(record), std::move(added));
        result.Committed = true;
        d.Healthy = true;
        d.Writable = !d.Result.Closed; d.Result.CanResume = d.Writable;
        result.Indexed = d.IndexRecord(d.Records.back()) && (!d.Result.Closed || d.IndexHead());
        if (!result.Indexed) { result.Issue = d.Result.Issue; }
    }
    catch (...) { d.Writable = d.Healthy = false; d.Result.CanResume = false; result.Issue = L"journal_commit_exception_reopen_required"; }
    return result;
}

EvidenceJournalRecovery RecoverEvidenceJournal(const std::wstring& directory, bool rebuildIndex)
{
    EvidenceJournal journal;
    auto& d = *journal.Data;
    try
    {
        if (!Text(directory, 30000)) { d.Fail(L"invalid_collection_directory"); return d.Result; }
        auto path = fs::path(directory).lexically_normal();
        if (!path.has_filename()) { path = path.parent_path(); }
        if (path.parent_path().filename() != L"collections" || !Id(path.filename().wstring()))
            { d.Fail(L"invalid_collection_directory"); return d.Result; }
        const auto root = path.parent_path().parent_path();
        if (!d.Load(root.empty() ? L"." : root.wstring(), path.filename().wstring(), false))
        {
            d.Incomplete();
            return d.Result;
        }
        if (rebuildIndex)
        {
            if (d.RetirementSeen) { d.Result.IndexStatus = L"retired"; return d.Result; }
            d.Result.IndexStatus = L"building";
            for (const auto& r : d.Records)
            {
                if (!d.IndexRecord(r)) { d.Result.IndexStatus = L"failed"; return d.Result; }
            }
            d.Result.IndexStatus = d.IndexHead() ? L"ready" : L"failed";
        }
    }
    catch (...) { d.Fail(L"journal_recovery_exception"); d.Incomplete(); }
    return d.Result;
}

std::wstring EvidenceJournalRecoveryJson(const EvidenceJournalRecovery& r)
{
    std::wstring approvals = L"[";
    for (const auto& path : r.ApprovalPaths)
    {
        if (approvals.size() > 1) { approvals += L","; }
        approvals += mcpjson::Quote(path);
    }
    std::wstring captures = L"[";
    for (const auto& path : r.DirectCapturePaths)
    {
        if (captures.size() > 1) { captures += L","; }
        captures += mcpjson::Quote(path);
    }
    std::wstring sweeps = L"[";
    for (const auto& path : r.SweepPaths)
    {
        if (sweeps.size() > 1) { sweeps += L","; }
        sweeps += mcpjson::Quote(path);
    }
    return L"{\"schema\":\"kn.evidence_journal_recovery.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"collection_id\":" + mcpjson::Quote(r.CollectionId) +
        L",\"session_sha256\":" + mcpjson::Quote(r.SessionSha256) + L",\"head_sha256\":" + mcpjson::Quote(r.HeadSha256) +
        L",\"committed_segments\":" + N(r.CommittedSegments) + L",\"closed\":" + B(r.Closed) +
        L",\"tail_unknown\":" + B(!r.Closed) + L",\"can_resume\":" + B(r.CanResume) +
        L",\"member_references\":" + N(r.MemberReferences) + L",\"unique_paths\":" + N(r.UniquePaths) +
        L",\"logical_bytes\":" + N(r.LogicalBytes) + L",\"unique_content_bytes\":" + N(r.UniqueContentBytes) +
        L",\"duplicate_reference_bytes\":" + N(r.LogicalBytes - r.UniqueContentBytes) + L",\"read_bytes\":" + N(r.ReadBytes) +
        (r.SourceReportPath.empty() ? L"" : L",\"committed_source_report_path\":" + mcpjson::Quote(r.SourceReportPath)) +
        L",\"pending_segment_files\":" + N(r.PendingFiles) + L",\"index_status\":" + mcpjson::Quote(r.IndexStatus) +
        L",\"index_created\":" + N(r.IndexCreated) + L",\"index_reused\":" + N(r.IndexReused) +
        L",\"committed_sweep_paths\":" + sweeps + L"],\"committed_direct_capture_paths\":" + captures +
        L"],\"committed_approval_paths\":" + approvals + (r.RetirementSha256.empty() ? L"],\"denominator_scope\":\"verified_collection_prefix\"," :
            L"],\"retirement_sha256\":" + mcpjson::Quote(r.RetirementSha256) + L",\"denominator_scope\":\"retired_manifest_membership\",\"original_set_verified\":false,") +
        L"\"orphan_files_included\":false,\"target_coverage_established\":false,\"replay_established\":false,"
        L"\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
}

EvidenceJournalMember EvidenceJournalJsonMember(const std::wstring& path, const std::wstring& json)
{
    EvidenceJournalMember m;
    m.Path = path; m.Sha256 = Hash(json); m.Bytes = mcpjson::WideToUtf8(json).size();
    mcpjson::GetString(json, L"schema", &m.Schema);
    return m;
}

namespace
{
    std::wstring StoreCollectionJson(const EvidenceStoreCollection& c)
    {
        const auto& r = c.Recovery;
        // A bounded root receipt. Use journal recovery for the full sweep list.
        return L"{\"id\":" + mcpjson::Quote(c.Id) + L",\"status\":" + mcpjson::Quote(r.Status) +
            L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"session_sha256\":" + mcpjson::Quote(r.SessionSha256) +
            L",\"head_sha256\":" + mcpjson::Quote(r.HeadSha256) + L",\"committed_segments\":" + N(r.CommittedSegments) +
            L",\"closed\":" + B(r.Closed) + L",\"member_references\":" + N(r.MemberReferences) +
            L",\"unique_paths\":" + N(r.UniquePaths) + L",\"logical_bytes\":" + N(r.LogicalBytes) +
            L",\"unique_content_bytes\":" + N(r.UniqueContentBytes) + L",\"pending_files\":" + N(r.PendingFiles) +
            (r.RetirementSha256.empty() ? L"" : L",\"retirement_sha256\":" + mcpjson::Quote(r.RetirementSha256)) + L"}";
    }
    std::wstring StoreArtifactJson(const EvidenceStoreArtifact& a)
    {
        std::wstring owners = L"[";
        for (const auto& id : a.Collections)
        {
            if (owners.size() > 1) { owners += L","; }
            owners += mcpjson::Quote(id);
        }
        std::wstring approval;
        if (!a.ApprovalCatalog.empty()) { approval = L",\"approval_catalog\":" + mcpjson::Quote(a.ApprovalCatalog); }
        if (!a.ApprovalReferrers.empty())
        {
            approval += L",\"uncommitted_approval_referrers\":[";
            for (const auto& root : a.ApprovalReferrers)
            {
                if (&root != &a.ApprovalReferrers.front()) { approval += L","; }
                approval += L"{\"path\":" + mcpjson::Quote(root.Path) + L",\"sha256\":" + mcpjson::Quote(root.Sha256) +
                    L",\"input_matched\":" + B(root.InputMatched) + L"}";
            }
            approval += L"]";
        }
        std::wstring image;
        if (!a.ImageCatalog.empty()) { image = L",\"image_catalog\":" + mcpjson::Quote(a.ImageCatalog); }
        if (!a.ImageReferrers.empty())
        {
            image += L",\"uncommitted_image_referrers\":[";
            for (const auto& root : a.ImageReferrers)
            {
                if (&root != &a.ImageReferrers.front()) { image += L","; }
                image += L"{\"path\":" + mcpjson::Quote(root.Path) + L",\"sha256\":" + mcpjson::Quote(root.Sha256) +
                    L",\"expected_sha256\":" + mcpjson::Quote(root.ExpectedSha256) +
                    L",\"digest_basis\":" + mcpjson::Quote(root.PayloadDigest ? L"unwrapped_payload" : L"file_bytes") +
                    L",\"input_matched\":" + B(root.InputMatched) + L"}";
            }
            image += L"]";
        }
        std::wstring irp;
        if (!a.IrpCatalog.empty()) { irp = L",\"irp_catalog\":" + mcpjson::Quote(a.IrpCatalog); }
        if (!a.IrpReferrers.empty())
        {
            irp += L",\"irp_referrers\":[";
            for (const auto& root : a.IrpReferrers)
            {
                if (&root != &a.IrpReferrers.front()) { irp += L","; }
                irp += L"{\"path\":" + mcpjson::Quote(root.Path) + L",\"sha256\":" + mcpjson::Quote(root.Sha256) +
                    L",\"expected_bytes\":" + N(root.ExpectedBytes) + L",\"root_committed\":" + B(root.Committed) +
                    L",\"input_matched\":" + B(root.InputMatched) + L"}";
            }
            irp += L"]";
        }
        std::wstring retired;
        if (!a.RetiredCollections.empty())
        {
            retired = L",\"retired_collections\":[";
            for (const auto& id : a.RetiredCollections)
            {
                if (&id != &a.RetiredCollections.front()) { retired += L","; }
                retired += mcpjson::Quote(id);
            }
            retired += L"],\"retired_original_matched\":" + B(a.RetiredOriginalMatched);
        }
        return L"{\"artifact\":" + MemberJson(a.Artifact) + L",\"verified\":" + B(a.Verified) +
            L",\"journal_references\":" + N(a.JournalReferences) + L",\"collections\":" + owners +
            L"],\"retention\":" + mcpjson::Quote(a.Retention) + approval + image + irp + retired + L"}";
    }
    std::wstring LowerAscii(std::wstring value)
    {
        for (auto& ch : value) { if (ch >= L'A' && ch <= L'Z') { ch += L'a' - L'A'; } }
        return value;
    }
    std::wstring MemberCollection(const std::wstring& path)
    {
        const auto name = fs::path(path).filename().wstring();
        for (const std::wstring prefix : {L"scope-assessment-", L"scope-session-"})
        {
            const auto dot = name.rfind(L'.');
            if (ApprovalPath(path) && name.rfind(prefix, 0) == 0 && dot != std::wstring::npos && dot > prefix.size())
                { return name.substr(prefix.size(), dot - prefix.size()); }
        }
        if (path == name && name.rfind(L"irp-session-", 0) == 0 && fs::path(name).extension() == L".knirpledger")
            { return name.substr(12, name.size() - 12 - 12); }
        const auto first = name.find(L'-');
        const auto last = name.find_first_of(L"-.", first == std::wstring::npos ? 0 : first + 1);
        return first != std::wstring::npos && last != std::wstring::npos ? name.substr(first + 1, last - first - 1) : L"";
    }
}

struct EvidenceStoreAccess
{
    static EvidenceStoreInventory Inspect(const std::wstring& artifactRoot, const std::set<std::wstring>& deletionPaths,
        const std::function<void(const EvidenceStoreInventory&, const fs::path&, EvidenceJournal::Impl&)>& action,
        bool retention = false, const std::wstring& scanReceipt = {}, const std::wstring& fileReceipt = {},
        const std::function<void(const wchar_t*)>& observer = {});
    static bool ReadCollection(EvidenceJournal::Impl& reader, const fs::path& root, const std::wstring& id);
    static std::wstring ScanCatalog(const std::wstring& root, const EvidenceStorePageOptions& page, bool* ready,
        const std::function<void(const wchar_t*)>& observer);
    static EvidenceGcResult Collect(const std::wstring& root, const std::wstring& policyPath,
        const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts);
    static EvidenceRetirementResult Retire(const std::wstring& root, const std::wstring& policyPath,
        bool apply, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts);
};

bool EvidenceStoreAccess::ReadCollection(EvidenceJournal::Impl& reader, const fs::path& root, const std::wstring& id)
{
    try { if (reader.Load(root.wstring(), id, false, true)) { return true; } }
    catch (...) { reader.Fail(L"collection_inspection_exception"); }
    reader.Incomplete();
    return false;
}

std::wstring EvidenceStoreAccess::ScanCatalog(const std::wstring& rootPath, const EvidenceStorePageOptions& page, bool* ready,
    const std::function<void(const wchar_t*)>& observer)
{
    if (ready) { *ready = false; }
    const auto start = GetTickCount64();
    const auto report = [&](const wchar_t* status, const std::wstring& issue, const std::wstring& scope, size_t total, size_t offset,
        size_t count, uint64_t readBytes, const std::wstring& rows, const std::wstring& cursor, const std::wstring& receipt)
    {
        return L"{\"schema\":\"kn.store_catalog_scan.v1\",\"status\":" + mcpjson::Quote(status) + L",\"issue\":" + mcpjson::Quote(issue) +
            L",\"namespace_sha256\":" + mcpjson::Quote(scope) + L",\"namespace_entries\":" + (scope.empty() ? L"null" : N(total)) +
            L",\"collection_offset\":" + N(offset) + L",\"collections_scanned\":" + N(count) + L",\"read_bytes\":" + N(readBytes) +
            L",\"started_tick\":" + N(start) + L",\"ended_tick\":" + N(GetTickCount64()) + L",\"collections\":" + rows +
            L",\"next_scan_cursor\":" + mcpjson::Quote(cursor) + L",\"scan_receipt\":" + mcpjson::Quote(receipt) +
            L",\"global_membership_established\":false,\"deletion_authorized\":false,\"collector_authenticated\":false}";
    };
    const auto fail = [&](const std::wstring& issue, uint64_t readBytes = 0)
        { return report(L"unavailable", issue, L"", 0, 0, 0, readBytes, L"[]", L"", L""); };
    if (page.ScanFiles || page.Artifacts || page.Retention || !page.ScanReceipt.empty() || !page.FileReceipt.empty() || page.Limit > store_catalog::MaxWindow || page.Cursor.size() > 150)
        { return fail(L"invalid_store_scan_options"); }
    uint64_t bytes = 0;
    try
    {
        EvidenceStoreLease barrier;
        std::wstring issue;
        if (!barrier.Acquire(rootPath, true, &issue)) { return fail(issue); }
        const auto root = fs::absolute(rootPath).lexically_normal();
        const auto native = NativePath(root);
        store_catalog::Names names;
        if (!store_catalog::ReadNames(native, start, DeadlineMs, names, issue)) { return fail(issue); }
        size_t offset = 0;
        auto chain = store_catalog::FirstChain(names.Digest);
        if (!page.Cursor.empty() && !store_catalog::ParseToken(page.Cursor, false, names, offset, chain))
            { return fail(L"store_scan_cursor_mismatch"); }
        const size_t limit = page.Limit ? static_cast<size_t>(page.Limit) : 64;
        const size_t end = (std::min)(names.Entries.size(), offset + limit);
        std::wstring rows = L"[";
        uint64_t references = 0;
        for (size_t i = offset; i < end; ++i)
        {
            EvidenceJournal journal;
            auto& d = *journal.Data;
            d.Started = start; d.SharedReadBytes = &bytes; d.SharedReferences = &references;
            const auto& id = names.Entries[i];
            ReadCollection(d, root, id);
            if (d.SharedBudgetIssue) { return fail(d.SharedBudgetIssue, bytes); }
            if (GetTickCount64() - start > DeadlineMs) { return fail(L"deadline_exhausted", bytes); }
            const auto row = StoreCollectionJson({id, std::move(d.Result), {}});
            chain = store_catalog::AppendRow(chain, row);
            if (chain.empty()) { return fail(L"store_scan_hash_failed", bytes); }
            if (i != offset) { rows += L","; }
            rows += row;
            if (observer) { observer(L"collection_scanned"); }
        }
        store_catalog::Names after;
        if (!store_catalog::ReadNames(native, start, DeadlineMs, after, issue)) { return fail(issue, bytes); }
        if (after.Digest != names.Digest) { return fail(L"store_scan_namespace_changed", bytes); }
        const bool terminal = end == names.Entries.size();
        const auto token = store_catalog::Token(terminal, names.Digest, end, chain);
        if (token.empty()) { return fail(L"store_scan_hash_failed", bytes); }
        auto json = report(terminal ? L"complete" : L"more", L"", names.Digest, names.Entries.size(), offset, end - offset,
            bytes, rows + L"]", terminal ? L"" : token, terminal ? token : L"");
        if (ready) { *ready = true; }
        return json;
    }
    catch (...) { return fail(L"store_scan_exception", bytes); }
}

EvidenceStoreInventory EvidenceStoreAccess::Inspect(const std::wstring& artifactRoot, const std::set<std::wstring>& deletionPaths,
    const std::function<void(const EvidenceStoreInventory&, const fs::path&, EvidenceJournal::Impl&)>& action,
    bool retention, const std::wstring& scanReceipt, const std::wstring& fileReceipt, const std::function<void(const wchar_t*)>& observer)
{
    EvidenceStoreInventory out;
    out.StartedTick = GetTickCount64();
    const auto finish = [&]()
    {
        if (!out.ArtifactInventoryComplete)
        {
            out.RetiredUnobservedPaths += out.RetiredAbsentPaths;
            out.RetiredAbsentPaths = 0;
        }
        out.EndedTick = GetTickCount64();
        return out;
    };
    try
    {
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(artifactRoot, true, &out.Issue)) { return finish(); }
        const auto root = fs::absolute(artifactRoot).lexically_normal();
        const auto collections = root / L"collections";
        store_files::Snapshot physical;
        if (!fileReceipt.empty())
        {
            if (!physical.Open(NativePath(root), out.StartedTick, out.Issue)) { return finish(); }
            if (!physical.Accepts(fileReceipt)) { out.Issue = L"store_file_receipt_mismatch"; return finish(); }
        }
        EvidenceJournal namespaceOwner; // Keep catalog ancestors pinned through the entire inventory.
        std::error_code ec;
        std::set<std::wstring> ids;
        store_catalog::Names scanNames;
        std::wstring expectedChain, observedChain;
        const auto attributes = GetFileAttributesW(NativePath(collections).c_str());
        if (!scanReceipt.empty())
        {
            size_t count = 0;
            if (!store_catalog::ReadNames(NativePath(root), out.StartedTick, DeadlineMs, scanNames, out.Issue)) { return finish(); }
            if (!store_catalog::ParseToken(scanReceipt, true, scanNames, count, expectedChain))
                { out.Issue = L"store_scan_receipt_mismatch"; return finish(); }
            observedChain = store_catalog::FirstChain(scanNames.Digest);
            ids.insert(scanNames.Entries.begin(), scanNames.Entries.end());
        }
        else if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
                { out.Issue = L"collection_catalog_unavailable"; return finish(); }
        }
        else
        {
            // Keep a directory lease for enumeration; no content is inferred
            // from directory presence or derived index files.
            auto& owner = *namespaceOwner.Data;
            owner.Started = out.StartedTick;
            if (!owner.PinDirectory(collections, false)) { out.Issue = owner.Result.Issue; return finish(); }
            for (fs::directory_iterator it(NativePath(collections), ec), end; !ec && it != end; it.increment(ec))
            {
                if (GetTickCount64() - out.StartedTick > DeadlineMs || ids.size() == StoreMaxCollections)
                    { out.CollectionsObserved = ids.size(); out.Issue = L"store_catalog_budget_exhausted"; return finish(); }
                ids.insert(it->path().filename().wstring());
            }
            if (ec) { out.Issue = L"collection_catalog_enumeration_failed"; return finish(); }
        }
        out.CollectionsObserved = ids.size(); out.CatalogComplete = true;
        std::vector<std::unique_ptr<EvidenceJournal>> journals;
        std::map<std::wstring, std::pair<EvidenceJournalMember, Handle>> cache;
        std::map<std::wstring, EvidenceStoreArtifact> artifacts;
        struct RetiredPath { EvidenceJournalMember Original; std::vector<std::wstring> Collections; };
        std::map<std::wstring, RetiredPath> retiredPaths;
        std::map<std::wstring, uint64_t> contentSizes;
        std::map<std::wstring, IrpReferenceCatalog> irpCatalogs;
        uint64_t references = 0;
        for (const auto& id : ids)
        {
            auto journal = std::make_unique<EvidenceJournal>();
            auto& d = *journal->Data;
            d.InspectPriority = retention;
            d.PhysicalSnapshot = fileReceipt.empty() ? nullptr : &physical;
            d.Started = out.StartedTick;
            d.SharedMembers = &cache; d.SharedReadBytes = &out.ReadBytes; d.SharedReferences = &references;
            d.StoreIrpCatalogs = &irpCatalogs;
            const bool ok = ReadCollection(d, root, id);
            if ((!scanReceipt.empty() || !fileReceipt.empty()) && (d.SharedBudgetIssue || GetTickCount64() - out.StartedTick > DeadlineMs))
                { out.Issue = d.SharedBudgetIssue ? d.SharedBudgetIssue : L"deadline_exhausted"; return finish(); }
            if (!ok)
            {
                ++out.UnresolvedCollections;
            }
            else if (d.RetirementSeen) { ++out.RetiredCollections; }
            else if (d.Result.Closed) { ++out.ClosedCollections; }
            else { ++out.OpenCollections; }
            out.Collections.push_back({id, d.Result, {}});
            if (!scanReceipt.empty()) { observedChain = store_catalog::AppendRow(observedChain, StoreCollectionJson(out.Collections.back())); }
            if (retention && ok && d.Result.Closed && !d.RetirementSeen)
            {
                auto& info = out.Collections.back().Retention;
                info.Priority = CombineCollectionPriority(d.ImagePriority, d.IrpPriority);
                if (d.SweepHasGap) { info.Priority = CombineCollectionPriority(info.Priority, CollectionPriority::Gap); }
                const auto segment = d.Files.find(L"@segment-" + std::to_wstring(d.Result.CommittedSegments));
                FILETIME time{};
                if (segment != d.Files.end() && GetFileTime(segment->second.get(), nullptr, nullptr, &time))
                    { info.ClosureWritten = FileTimeValue(time); }
            }
            if (ok && d.RetirementSeen)
            {
                out.RetiredSegments += d.Result.CommittedSegments;
                out.RetiredMemberReferences += d.Result.MemberReferences; out.RetiredLogicalBytes += d.Result.LogicalBytes;
                for (const auto& member : d.Members)
                {
                    const auto inserted = retiredPaths.try_emplace(member.first, RetiredPath{member.second, {}});
                    if (retiredPaths.size() > StoreMaxPaths || !Same(inserted.first->second.Original, member.second))
                        { out.Issue = L"retired_path_conflict_or_budget"; return finish(); }
                    inserted.first->second.Collections.push_back(id);
                }
                journals.push_back(std::move(journal));
                continue;
            }
            out.CommittedSegments += d.Result.CommittedSegments;
            out.MemberReferences += d.Result.MemberReferences;
            out.LogicalReferenceBytes += d.Result.LogicalBytes;
            // Only accepted records belong to the prefix. An exception can
            // leave other implementation maps partially populated.
            std::set<std::wstring> seen;
            for (const auto& record : d.Records)
            {
                if (record.Sequence > d.Result.CommittedSegments) { break; }
                for (const auto& member : record.Transaction.Members)
                {
                    auto found = artifacts.find(member.Path);
                    if (found != artifacts.end() && !Same(found->second.Artifact, member))
                        { throw std::runtime_error("conflicting store path"); }
                    const auto content = contentSizes.find(member.Sha256);
                    if (content != contentSizes.end() && content->second != member.Bytes)
                        { throw std::runtime_error("conflicting store content size"); }
                    if (found == artifacts.end())
                    {
                        EvidenceStoreArtifact a;
                        a.Artifact = member; a.Verified = true;
                        const auto payload = d.ImagePayloads.find(member.Path);
                        if (payload != d.ImagePayloads.end()) { a.ImagePayloadSha256 = payload->second; }
                        a.Retention = member.Schema == L"raw.bytes" ? L"committed_reference_protected" :
                            FailureLedger(member.Schema) ? L"failure_ledger_protected" : L"committed_original_protected";
                        found = artifacts.emplace(member.Path, std::move(a)).first;
                        out.UniquePathBytes += member.Bytes;
                        if (contentSizes.emplace(member.Sha256, member.Bytes).second) { out.UniqueContentBytes += member.Bytes; }
                    }
                    ++found->second.JournalReferences;
                    if (seen.insert(member.Path).second)
                    {
                        ++out.CollectionPathReferences; out.CollectionPathBytes += member.Bytes;
                        found->second.Collections.push_back(id);
                    }
                }
            }
            journals.push_back(std::move(journal)); // Hold all exact original-file leases together.
        }
        if (!scanReceipt.empty() && (observedChain.empty() || observedChain != expectedChain))
            { out.Issue = L"store_scan_recovery_mismatch"; return finish(); }
        out.MembershipComplete = out.UnresolvedCollections == 0 && out.OpenCollections == 0;
        std::wstring catalog = L"[";
        for (const auto& collection : out.Collections)
        {
            if (catalog.size() > 1) { catalog += L","; }
            catalog += StoreCollectionJson(collection);
        }
        out.CatalogSha256 = Hash(catalog + L"]");

        EvidenceJournal physicalReader;
        auto& reader = *physicalReader.Data;
        reader.Started = out.StartedTick; reader.SharedReadBytes = &out.ReadBytes;
        if (!fileReceipt.empty()) { reader.PhysicalSnapshot = &physical; reader.ReadBudget = StoreMaxReadBytes; }
        bool physicalComplete = true;
        std::map<std::wstring, ApprovalInputs> approvalCatalogs;
        bool unreadableDirectApproval = false, unreadableScopedApproval = false;
        std::map<std::wstring, ImageArchiveCatalog> imageCatalogs;
        bool unknownImageReference = false, unknownSweepInputs = false, unknownSourceCases = false;
        std::set<std::wstring> observed;
        uint64_t rootEntries = 0;
        for (const auto folder : store_files::Folders)
        {
            const auto directory = root / folder;
            const auto attr = GetFileAttributesW(NativePath(directory).c_str());
            if (attr == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) { continue; }
            if (!reader.PinDirectory(directory, false)) { physicalComplete = false; out.Issue = reader.Result.Issue; continue; }
            ec.clear();
            for (fs::directory_iterator it(NativePath(directory), ec), end; !ec && it != end; it.increment(ec))
            {
                const auto name = LowerAscii(it->path().filename().wstring());
                const bool irpRoot = *folder == 0;
                if (irpRoot)
                {
                    if (++rootEntries > StoreMaxPaths || GetTickCount64() - out.StartedTick > DeadlineMs)
                        { physicalComplete = false; out.Issue = L"store_root_enumeration_budget_exhausted"; break; }
                    // Only the reserved IRP root namespace belongs to this inventory.
                    // Unknown names and pending files inside it remain protected.
                    if (!store_files::ReservedRootName(name)) { continue; }
                }
                if (out.ObservedArtifactFiles == StoreMaxPaths || GetTickCount64() - out.StartedTick > DeadlineMs)
                    { physicalComplete = false; out.Issue = L"store_artifact_budget_exhausted"; break; }
                ++out.ObservedArtifactFiles;
                const auto relative = irpRoot ? name : std::wstring(folder) + L"/" + name;
                if (!observed.insert(relative).second) { physicalComplete = false; ++out.UnmanagedEntries; continue; }
                auto found = artifacts.find(relative);
                if (found != artifacts.end()) { continue; } // Exact pinned file already checked through its journal.
                if (artifacts.size() == StoreMaxPaths)
                    { physicalComplete = false; out.Issue = L"store_path_budget_exhausted"; break; }
                EvidenceStoreArtifact a;
                a.Artifact.Path = relative;
                const auto extension = fs::path(relative).extension().wstring();
                const auto format = store_files::FileFormat(folder, extension);
                const bool blob = format.Blob;
                Handle lease{nullptr, &CloseHandle};
                std::wstring text;
                if (format.Maximum)
                {
                    const auto source = fileReceipt.empty() ? root / relative : directory / it->path().filename();
                    a.Verified = reader.Read(source, format.Maximum, &lease, &a.Artifact.Sha256, &a.Artifact.Bytes,
                        blob ? nullptr : &text, deletionPaths.count(relative) ? DELETE : 0, &relative);
                    if (blob) { a.Artifact.Schema = L"raw.bytes"; }
                    else { mcpjson::GetString(text, L"schema", &a.Artifact.Schema); }
                    a.Verified = a.Verified && (blob || ApprovalInputPath(relative) || ScopeInputPath(relative) || Id(MemberCollection(relative))) && MemberValid(a.Artifact, MemberCollection(relative));
                    if (a.Verified)
                    {
                        reader.Files.emplace(relative, std::move(lease));
                        if (IrpCaptureSchema(a.Artifact.Schema) && !irpCatalogs.count(relative))
                            { irpCatalogs.emplace(relative, ReadIrpReferenceCatalog(a.Artifact.Schema, text)); }
                        const auto imageKind = ImageArchiveKindForPath(relative);
                        if (imageKind != ImageArchiveKind::None)
                        {
                            ++out.UncommittedImageRoots;
                            ImageArchiveCatalog imageCatalog;
                            const bool decoded = ReadImageArchiveCatalog(imageKind, a.Artifact, text, imageCatalog);
                            if (!decoded || imageCatalog.Inputs.size() > StoreMaxReferences - references)
                            {
                                unknownImageReference = true;
                                if (imageKind == ImageArchiveKind::Sweep) { unknownSweepInputs = true; }
                                if (imageKind == ImageArchiveKind::SourceReport) { unknownSourceCases = true; }
                                if (!decoded) { ++out.UnreadableImageCatalogs; a.ImageCatalog = L"unreadable"; }
                                else
                                {
                                    physicalComplete = false; a.ImageCatalog = L"budget_exhausted";
                                    out.Issue = L"store_image_reference_budget_exhausted";
                                }
                            }
                            else
                            {
                                references += imageCatalog.Inputs.size();
                                a.ImagePayloadSha256 = std::move(imageCatalog.PayloadSha256);
                                imageCatalogs.emplace(relative, std::move(imageCatalog));
                            }
                        }
                        const bool scoped = a.Artifact.Schema == ImageScopeApprovalPublicationSchema;
                        if (scoped || a.Artifact.Schema == ImageApprovalPublicationSchema)
                        {
                            ++out.UncommittedApprovalRoots;
                            ApprovalInputs inputs;
                            const bool decoded = ReadApprovalInputs(a.Artifact, MemberCollection(relative), text, inputs);
                            if (!decoded || inputs.size() > StoreMaxReferences - references)
                            {
                                if (scoped) { unreadableScopedApproval = true; } else { unreadableDirectApproval = true; }
                                if (!decoded) { ++out.UnreadableApprovalCatalogs; a.ApprovalCatalog = L"unreadable"; }
                                else
                                {
                                    physicalComplete = false; a.ApprovalCatalog = L"budget_exhausted";
                                    out.Issue = L"store_approval_reference_budget_exhausted";
                                }
                            }
                            else
                            {
                                references += inputs.size();
                                approvalCatalogs.emplace(relative, std::move(inputs));
                            }
                        }
                    }
                }
                else { ++out.UnmanagedEntries; }
                ++out.UnattributedFiles;
                if (!a.Verified) { ++out.UnverifiedArtifactFiles; physicalComplete = false; }
                else { out.UnattributedBytes += a.Artifact.Bytes; }
                a.Retention = !a.Verified ? L"unverified_artifact_protected" :
                    FailureLedger(a.Artifact.Schema) ? L"failure_ledger_protected" : out.MembershipComplete ?
                    L"uncommitted_requires_policy" : L"unresolved_membership_protected";
                artifacts.emplace(relative, std::move(a));
            }
            if (ec) { physicalComplete = false; out.Issue = L"store_artifact_enumeration_failed"; }
        }
        for (const auto& catalogEntry : approvalCatalogs)
        {
            auto& publication = artifacts.at(catalogEntry.first);
            publication.ApprovalCatalog = L"resolved";
            for (const auto& input : catalogEntry.second)
            {
                const auto found = artifacts.find(input.first);
                if (found == artifacts.end())
                {
                    ++out.MissingApprovalInputs;
                    publication.ApprovalCatalog = L"inputs_incomplete";
                    continue;
                }
                auto& file = found->second;
                const bool matched = file.Verified && MatchesApprovalInput(input.second, file.Artifact);
                file.ApprovalReferrers.push_back({publication.Artifact.Path, publication.Artifact.Sha256, matched});
                if (!matched) { ++out.MismatchedApprovalInputs; publication.ApprovalCatalog = L"inputs_incomplete"; }
                if (file.Retention == L"uncommitted_requires_policy") { file.Retention = L"uncommitted_approval_input_protected"; }
            }
        }
        for (const auto& catalogEntry : imageCatalogs)
        {
            auto& publication = artifacts.at(catalogEntry.first);
            publication.ImageCatalog = L"resolved";
            for (const auto& input : catalogEntry.second.Inputs)
            {
                const auto found = artifacts.find(input.first);
                if (found == artifacts.end())
                {
                    ++out.MissingImageInputs; publication.ImageCatalog = L"inputs_incomplete";
                    continue;
                }
                auto& file = found->second;
                const bool matched = file.Verified && MatchesImageArchiveInput(input.second, file.Artifact, file.ImagePayloadSha256);
                if (!matched) { ++out.MismatchedImageInputs; publication.ImageCatalog = L"inputs_incomplete"; }
                file.ImageReferrers.push_back({publication.Artifact.Path, publication.Artifact.Sha256, input.second.Sha256,
                    input.second.PayloadDigest, matched});
            }
        }
        bool unknownIrpReference = false;
        for (const auto& entry : irpCatalogs)
        {
            const auto rootFile = artifacts.find(entry.first);
            if (rootFile == artifacts.end() || !rootFile->second.Verified) { continue; }
            auto& capture = rootFile->second;
            const auto& input = entry.second;
            ++out.IrpCaptureRoots;
            if (!input.Readable)
            {
                ++out.UnreadableIrpCatalogs; capture.IrpCatalog = L"unreadable"; unknownIrpReference = true;
                continue;
            }
            if (!input.Bytes) { capture.IrpCatalog = L"not_captured"; continue; }
            if (references == StoreMaxReferences)
            {
                capture.IrpCatalog = L"budget_exhausted"; physicalComplete = false; unknownIrpReference = true;
                out.Issue = L"store_irp_reference_budget_exhausted"; continue;
            }
            ++references;
            const auto found = artifacts.find(L"irp-reference-" + input.Sha256 + L".knblob");
            if (found == artifacts.end()) { ++out.MissingIrpReferences; capture.IrpCatalog = L"inputs_incomplete"; continue; }
            auto& file = found->second;
            const bool matched = file.Verified && file.Artifact.Sha256 == input.Sha256 && file.Artifact.Bytes == input.Bytes;
            if (!matched) { ++out.MismatchedIrpReferences; }
            capture.IrpCatalog = matched ? L"resolved" : L"inputs_incomplete";
            file.IrpReferrers.push_back({entry.first, capture.Artifact.Sha256, input.Bytes, capture.JournalReferences != 0, matched});
        }
        for (auto& pair : artifacts)
        {
            // An unreadable declaration cannot exclude any original in its input families.
            if (pair.second.Retention == L"uncommitted_requires_policy" && (unreadableDirectApproval || unreadableScopedApproval) &&
                (pair.first.rfind(L"image-references/", 0) == 0 || ApprovalInputPath(pair.first) ||
                    (unreadableDirectApproval && DirectPath(pair.first)) || (unreadableScopedApproval && ScopeInputPath(pair.first))))
                { pair.second.Retention = L"unresolved_approval_input_protected"; }
            if (pair.second.Retention == L"uncommitted_requires_policy")
            {
                if (!pair.second.IrpReferrers.empty()) { pair.second.Retention = L"irp_replay_reference_protected"; }
                else if (unknownIrpReference && pair.first.rfind(L"irp-reference-", 0) == 0)
                    { pair.second.Retention = L"unresolved_irp_reference_protected"; }
                else if (!pair.second.ImageReferrers.empty()) { pair.second.Retention = L"uncommitted_image_input_protected"; }
                else if ((unknownImageReference && pair.first.rfind(L"image-references/", 0) == 0) ||
                    (unknownSweepInputs && pair.first.rfind(L"image-reads/", 0) == 0) ||
                    (unknownSourceCases && pair.first.rfind(L"image-captures/case-", 0) == 0))
                    { pair.second.Retention = L"unresolved_image_input_protected"; }
            }
            if (pair.second.JournalReferences != 0 && !observed.count(pair.first))
                { physicalComplete = false; out.Issue = L"committed_path_missing_from_inventory"; }
        }
        out.RetiredDeclaredPaths = retiredPaths.size();
        uint64_t missingRetiredPaths = 0;
        for (auto& pair : retiredPaths)
        {
            const auto present = artifacts.find(pair.first);
            if (present == artifacts.end())
            {
                ++missingRetiredPaths;
                continue;
            }
            auto& a = present->second;
            a.RetiredCollections = std::move(pair.second.Collections);
            if (!a.Verified) { ++out.RetiredUnobservedPaths; continue; }
            a.RetiredOriginalMatched = Same(a.Artifact, pair.second.Original);
            if (!a.RetiredOriginalMatched)
            {
                ++out.RetiredChangedPaths;
                if (a.Retention == L"uncommitted_requires_policy") { a.Retention = L"retired_path_changed_protected"; }
            }
            else if (!a.JournalReferences)
            {
                ++out.RetiredOnlyFiles; out.RetiredOnlyBytes += a.Artifact.Bytes;
                --out.UnattributedFiles; out.UnattributedBytes -= a.Artifact.Bytes;
                if (a.Retention == L"uncommitted_requires_policy") { a.Retention = L"retired_requires_policy"; }
            }
        }
        if (artifacts.size() + missingRetiredPaths > StoreMaxPaths)
            { physicalComplete = false; out.Issue = L"store_retired_path_budget_exhausted"; }
        if (!fileReceipt.empty() && !physical.Verified(fileReceipt))
        {
            physicalComplete = false;
            if (out.Issue.empty()) { out.Issue = reader.SharedBudgetIssue ? reader.SharedBudgetIssue : L"store_file_bytes_mismatch"; }
        }
        out.ArtifactInventoryComplete = physicalComplete;
        ContentHash artifactHash;
        const auto hashText = [&](const std::wstring& text)
        {
            const auto bytes = mcpjson::WideToUtf8(text);
            if (!artifactHash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()))
                { throw std::runtime_error("store artifact hashing failed"); }
        };
        hashText(L"[");
        for (auto& pair : artifacts)
        {
            if (!out.Artifacts.empty()) { hashText(L","); }
            hashText(StoreArtifactJson(pair.second));
            out.Artifacts.push_back(std::move(pair.second));
        }
        hashText(L"]");
        out.ArtifactsSha256 = artifactHash.Finish();
        if (!Digest(out.CatalogSha256) || !Digest(out.ArtifactsSha256)) { throw std::runtime_error("store report hashing failed"); }
        if (!reader.Timely()) { out.ArtifactInventoryComplete = false; out.Issue = reader.Result.Issue; }
        if (out.ArtifactInventoryComplete) { out.RetiredAbsentPaths = missingRetiredPaths; }
        else { out.RetiredUnobservedPaths += missingRetiredPaths; }
        out.Status = out.MembershipComplete && out.ArtifactInventoryComplete ? L"verified" : L"partial";
        if (retention && out.Status == L"verified")
        {
            AccountCollectionRetention(out);
            if (!reader.Timely()) { out.Status = L"partial"; out.Issue = reader.Result.Issue; }
            else { out.Budget.Observed = CurrentFileTime(); }
        }
        if (out.Status == L"partial" && out.Issue.empty()) { out.Issue = L"unresolved_membership_or_artifacts"; }
        if (!fileReceipt.empty())
        {
            if (observer) { observer(L"file_inventory_hashed"); }
            store_files::Snapshot after;
            std::wstring issue;
            if (!after.Open(NativePath(root), out.StartedTick, issue) || after.Digest != physical.Digest)
            {
                out.Status = L"partial"; out.ArtifactInventoryComplete = false; out.Budget.Observed = 0;
                out.Issue = issue.empty() ? L"store_file_namespace_changed" : std::move(issue);
            }
        }
        if (!scanReceipt.empty())
        {
            // A collection may have appeared while the physical file namespace was being checked.
            store_catalog::Names after;
            std::wstring issue;
            if (!store_catalog::ReadNames(NativePath(root), out.StartedTick, DeadlineMs, after, issue) || after.Digest != scanNames.Digest)
            {
                out.Status = L"partial"; out.CatalogComplete = out.MembershipComplete = out.ArtifactInventoryComplete = false;
                out.Budget.Observed = 0;
                out.Issue = issue.empty() ? L"store_scan_namespace_changed" : std::move(issue);
            }
        }
        // A supplied receipt must verify under this lease before any policy is evaluated.
        if (action && (out.Status == L"verified" || (scanReceipt.empty() && fileReceipt.empty()))) { action(out, root, reader); }
    }
    catch (...) { out.Status = L"partial"; out.MembershipComplete = out.ArtifactInventoryComplete = false;
        out.Budget.Observed = 0; out.Issue = L"store_inspection_exception"; }
    return finish();
}

EvidenceStoreInventory InspectEvidenceStore(const std::wstring& artifactRoot, bool includeRetention)
{
    return EvidenceStoreAccess::Inspect(artifactRoot, {}, {}, includeRetention);
}

std::wstring EvidenceStoreInventoryJson(const EvidenceStoreInventory& r, bool includeArtifacts)
{
    EvidenceStorePageOptions page;
    page.Artifacts = includeArtifacts;
    return EvidenceStoreInventoryJson(r, page, nullptr);
}

namespace
{
    constexpr size_t StoreDetailUnits = 16 * 1024 * 1024;
    constexpr uint64_t StorePageMaxRows = 4096;
    std::wstring StoreCursor(const EvidenceStoreInventory& r, uint64_t offset)
    {
        if (!Digest(r.CatalogSha256) || !Digest(r.ArtifactsSha256)) { return {}; }
        const auto position = std::to_wstring(offset);
        const auto seal = Hash(L"kn.store_artifact_cursor.v1|" + r.CatalogSha256 + L"|" + r.ArtifactsSha256 + L"|" + position);
        return Digest(seal) ? L"kns1." + position + L"." + seal : L"";
    }
    bool StoreCursorOffset(const EvidenceStoreInventory& r, const std::wstring& cursor, size_t& offset)
    {
        const auto end = cursor.find(L'.', 5);
        if (cursor.rfind(L"kns1.", 0) != 0 || end == std::wstring::npos || end > 10) { return false; }
        const auto number = cursor.substr(5, end - 5);
        if (!Id(number)) { return false; }
        const auto value = std::stoul(number);
        if (!value || value >= r.Artifacts.size() || cursor != StoreCursor(r, value)) { return false; }
        offset = value;
        return true;
    }
}

namespace
{
    bool ReadReceiptOption(const std::vector<std::wstring>& flags, size_t& index, const std::wstring& key,
        std::wstring& catalog, std::wstring& files)
    {
        const bool physical = key == L"/file-receipt";
        auto& receipt = physical ? files : catalog;
        if (!receipt.empty() || ++index == flags.size()) { return false; }
        const auto& value = flags[index];
        if (value.empty() || value.size() > (physical ? 234u : 150u) || value.front() == L'/') { return false; }
        receipt = value;
        return true;
    }
}

bool ParseEvidenceRetentionOptions(const std::vector<std::wstring>& flags, bool retireCollection, EvidenceRetentionOptions& options)
{
    EvidenceRetentionOptions parsed;
    bool json = false;
    for (size_t i = 0; i < flags.size(); ++i)
    {
        const auto key = LowerAscii(flags[i]);
        if (key == L"/apply" && !parsed.Apply)
        {
            parsed.Apply = true;
            if (!retireCollection)
            {
                if (++i == flags.size() || !Id(flags[i])) { return false; }
                parsed.OperationId = flags[i];
            }
        }
        else if (key == L"/json" && !json) { json = true; }
        else if (key == L"/scan-receipt" || key == L"/file-receipt")
        {
            if (!ReadReceiptOption(flags, i, key, parsed.Receipts.Catalog, parsed.Receipts.Files)) { return false; }
        }
        else { return false; }
    }
    options = std::move(parsed);
    return true;
}

bool ParseEvidenceStorePageOptions(const std::vector<std::wstring>& options, EvidenceStorePageOptions* page)
{
    if (!page) { return false; }
    EvidenceStorePageOptions parsed;
    bool json = false;
    for (size_t i = 0; i < options.size(); ++i)
    {
        const auto key = LowerAscii(options[i]);
        if (key == L"/artifacts" && !parsed.Artifacts) { parsed.Artifacts = true; }
        else if (key == L"/retention" && !parsed.Retention) { parsed.Retention = true; }
        else if (key == L"/scan-catalog" && !parsed.ScanCatalog) { parsed.ScanCatalog = true; }
        else if (key == L"/scan-files" && !parsed.ScanFiles) { parsed.ScanFiles = true; }
        else if (key == L"/scan-receipt" || key == L"/file-receipt")
        {
            if (!ReadReceiptOption(options, i, key, parsed.ScanReceipt, parsed.FileReceipt)) { return false; }
        }
        else if (key == L"/json" && !json) { json = true; }
        else if (key == L"/limit" && !parsed.Limit && ++i < options.size())
        {
            const auto& number = options[i];
            if (number.size() > 4 || !Id(number)) { return false; }
            parsed.Limit = std::stoul(number);
            if (!parsed.Limit || parsed.Limit > StorePageMaxRows) { return false; }
        }
        else if (key == L"/cursor" && parsed.Cursor.empty() && ++i < options.size())
        {
            parsed.Cursor = options[i];
            if (parsed.Cursor.empty() || parsed.Cursor.size() > 234 || parsed.Cursor.front() == L'/') { return false; }
        }
        else { return false; }
    }
    if (parsed.ScanCatalog || parsed.ScanFiles)
    {
        if ((parsed.ScanCatalog && parsed.ScanFiles) || parsed.Artifacts || parsed.Retention || !parsed.ScanReceipt.empty() || !parsed.FileReceipt.empty() ||
            parsed.Limit > (parsed.ScanFiles ? store_files::MaxWindow : store_catalog::MaxWindow) || (parsed.ScanCatalog && parsed.Cursor.size() > 150)) { return false; }
    }
    else if (parsed.Cursor.size() > 80 || (!parsed.Artifacts && (parsed.Limit || !parsed.Cursor.empty()))) { return false; }
    *page = std::move(parsed);
    return true;
}

std::wstring QueryEvidenceStore(const std::wstring& root, const EvidenceStorePageOptions& page, bool* ready,
    const std::function<void(const wchar_t*)>& observer)
{
    if (page.ScanFiles) { return store_files::Scan(root, page, ready, observer); }
    if (page.ScanCatalog) { return EvidenceStoreAccess::ScanCatalog(root, page, ready, observer); }
    const auto inventory = EvidenceStoreAccess::Inspect(root, {}, {}, page.Retention, page.ScanReceipt, page.FileReceipt, observer);
    return EvidenceStoreInventoryJson(inventory, page, ready);
}

std::wstring EvidenceStoreInventoryJson(const EvidenceStoreInventory& r, const EvidenceStorePageOptions& page, bool* pageReady)
{
    std::wstring collections = L"[", artifacts = L"[";
    std::wstring pageStatus = L"not_requested", next;
    size_t offset = 0, emitted = 0;
    bool ready = r.Status == L"verified";
    for (const auto& c : r.Collections)
    {
        if (collections.size() > 1) { collections += L","; }
        collections += StoreCollectionJson(c);
    }
    if (page.Artifacts)
    {
        const bool validCursor = page.Cursor.empty() || (ready && StoreCursorOffset(r, page.Cursor, offset));
        pageStatus = ready ? L"complete" : L"incomplete_inventory";
        if (!validCursor)
        {
            if (ready) { pageStatus = L"cursor_mismatch"; }
            ready = false;
        }
        else
        {
            for (size_t i = offset; i < r.Artifacts.size() && (!page.Limit || emitted < page.Limit); ++i)
            {
                const auto row = StoreArtifactJson(r.Artifacts[i]);
                if (artifacts.size() + (emitted ? 1 : 0) + row.size() + 1 > StoreDetailUnits) { break; }
                if (emitted) { artifacts += L","; }
                artifacts += row;
                ++emitted;
            }
            if (ready && offset + emitted < r.Artifacts.size())
            {
                if (emitted) { next = StoreCursor(r, offset + emitted); }
                pageStatus = !emitted ? L"row_exceeds_budget" : next.empty() ? L"cursor_unavailable" : L"more";
                ready = !next.empty();
            }
        }
    }
    if (pageReady) { *pageReady = ready; }
    return L"{\"schema\":\"kn.evidence_store_inventory.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"scope\":\"image_and_irp_collection_namespace\","
        L"\"coordination\":\"participating_publishers\",\"retention_policy\":\"kn.retain_committed_and_unresolved.v1\","
        L"\"catalog_sha256\":" + mcpjson::Quote(r.CatalogSha256) + L",\"artifacts_sha256\":" + mcpjson::Quote(r.ArtifactsSha256) +
        L",\"started_tick\":" + N(r.StartedTick) + L",\"ended_tick\":" + N(r.EndedTick) +
        L",\"catalog_complete\":" + B(r.CatalogComplete) + L",\"membership_complete\":" + B(r.MembershipComplete) +
        L",\"artifact_inventory_complete\":" + B(r.ArtifactInventoryComplete) +
        L",\"collections_observed\":" + N(r.CollectionsObserved) + L",\"closed_collections\":" + N(r.ClosedCollections) +
        L",\"open_collections\":" + N(r.OpenCollections) + L",\"unresolved_collections\":" + N(r.UnresolvedCollections) +
        L",\"retired_collections\":" + N(r.RetiredCollections) + L",\"retired_segments\":" + N(r.RetiredSegments) +
        L",\"retired_member_references\":" + N(r.RetiredMemberReferences) + L",\"retired_logical_bytes\":" + N(r.RetiredLogicalBytes) +
        L",\"retired_declared_paths\":" + N(r.RetiredDeclaredPaths) + L",\"retired_absent_paths\":" + N(r.RetiredAbsentPaths) +
        L",\"retired_unobserved_paths\":" + N(r.RetiredUnobservedPaths) + L",\"retired_changed_paths\":" + N(r.RetiredChangedPaths) +
        L",\"retired_only_files\":" + N(r.RetiredOnlyFiles) +
        L",\"retired_only_named_bytes\":" + N(r.RetiredOnlyBytes) +
        L",\"committed_segments\":" + N(r.CommittedSegments) + L",\"member_references\":" + N(r.MemberReferences) +
        L",\"collection_path_references\":" + N(r.CollectionPathReferences) + L",\"logical_reference_bytes\":" + N(r.LogicalReferenceBytes) +
        L",\"collection_path_bytes\":" + N(r.CollectionPathBytes) + L",\"unique_path_bytes\":" + N(r.UniquePathBytes) +
        L",\"unique_content_bytes\":" + N(r.UniqueContentBytes) + L",\"observed_artifact_files\":" + N(r.ObservedArtifactFiles) +
        L",\"unverified_artifact_files\":" + N(r.UnverifiedArtifactFiles) + L",\"unmanaged_entries\":" + N(r.UnmanagedEntries) +
        L",\"unattributed_files\":" + N(r.UnattributedFiles) + L",\"verified_unattributed_bytes\":" + N(r.UnattributedBytes) +
        L",\"uncommitted_approval_roots\":" + N(r.UncommittedApprovalRoots) +
        L",\"unreadable_approval_catalogs\":" + N(r.UnreadableApprovalCatalogs) +
        L",\"missing_approval_inputs\":" + N(r.MissingApprovalInputs) + L",\"mismatched_approval_inputs\":" + N(r.MismatchedApprovalInputs) +
        L",\"uncommitted_image_roots\":" + N(r.UncommittedImageRoots) + L",\"unreadable_image_catalogs\":" + N(r.UnreadableImageCatalogs) +
        L",\"missing_image_inputs\":" + N(r.MissingImageInputs) + L",\"mismatched_image_inputs\":" + N(r.MismatchedImageInputs) +
        L",\"irp_capture_roots\":" + N(r.IrpCaptureRoots) + L",\"unreadable_irp_catalogs\":" + N(r.UnreadableIrpCatalogs) +
        L",\"missing_irp_references\":" + N(r.MissingIrpReferences) + L",\"mismatched_irp_references\":" + N(r.MismatchedIrpReferences) +
        L",\"read_bytes\":" + N(r.ReadBytes) + L",\"artifacts_included\":" + B(page.Artifacts) +
        L",\"artifact_rows_total\":" + N(r.Artifacts.size()) + L",\"artifact_rows_emitted\":" + N(emitted) +
        L",\"artifact_rows_omitted\":" + N(r.Artifacts.size() - emitted) +
        L",\"artifact_page_status\":" + mcpjson::Quote(pageStatus) + L",\"artifact_row_offset\":" + N(offset) +
        L",\"artifact_rows_remaining\":" + N(r.Artifacts.size() - offset - emitted) +
        L",\"next_artifact_cursor\":" + mcpjson::Quote(next) +
        (page.Retention ? L",\"collection_retention\":" + CollectionRetentionBudgetJson(r) : L"") +
        L",\"collections\":" + collections + L"],\"artifacts\":" + artifacts +
        L"],\"deletion_authorized\":false,\"disk_allocation_established\":false,\"target_coverage_established\":false,"
        L"\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
}

namespace
{
    constexpr uint64_t GcMaxBytes = 128ull * 1024 * 1024, GcMaxPolicyBytes = 128 * 1024;
    constexpr size_t GcMaxFiles = 128;
    uint64_t FileTimeValue(FILETIME time)
    {
        return (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    }
    uint64_t CurrentFileTime()
    {
        FILETIME time{}; GetSystemTimeAsFileTime(&time); return FileTimeValue(time);
    }
    bool GcIdentity(HANDLE file, std::wstring* identity, uint64_t* lastWrite, bool directory = false)
    {
        BY_HANDLE_FILE_INFORMATION info{};
        FILE_ID_INFO id{};
        if (!GetFileInformationByHandle(file, &info) || !GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) ||
            FileTimeValue(info.ftCreationTime) == 0 ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
            (!directory && (info.nNumberOfLinks != 1 || (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0))) { return false; }
        std::wstring fileId;
        bool nonzero = false;
        constexpr wchar_t digits[] = L"0123456789abcdef";
        for (const auto byte : id.FileId.Identifier)
        {
            nonzero |= byte != 0;
            fileId += digits[byte >> 4]; fileId += digits[byte & 15];
        }
        if (!nonzero) { return false; }
        *identity = std::to_wstring(id.VolumeSerialNumber) + L":" + fileId + L":" +
            std::to_wstring(FileTimeValue(info.ftCreationTime));
        *lastWrite = FileTimeValue(info.ftLastWriteTime);
        return directory || *lastWrite != 0;
    }
    bool GcPolicyValid(const EvidenceGcPolicy& p)
    {
        if (p.RetiredCollection.empty() ? !p.RetirementSha256.empty() : !Id(p.RetiredCollection) || !Digest(p.RetirementSha256)) { return false; }
        if (!Text(p.Reason, 512) || p.MinimumAgeSeconds > 10ull * 366 * 86400 ||
            p.ByteLimit == 0 || p.ByteLimit > GcMaxBytes || p.Members.empty() || p.Members.size() > GcMaxFiles) { return false; }
        std::wstring previous;
        uint64_t total = 0;
        for (const auto& m : p.Members)
        {
            if (!MemberValid(m, MemberCollection(m.Path)) || FailureLedger(m.Schema) ||
                (m.Schema != L"raw.bytes" && !ApprovalInputPath(m.Path) && !ScopeInputPath(m.Path) && !Id(MemberCollection(m.Path))) ||
                (!previous.empty() && m.Path <= previous) || m.Bytes > p.ByteLimit - total) { return false; }
            total += m.Bytes; previous = m.Path;
        }
        return true;
    }
    std::wstring GcOperationJson(const EvidenceGcResult& r, const EvidenceGcPolicy& p, uint64_t time, const std::wstring& catalog)
    {
        return Envelope(L"kn.evidence_gc_operation.v1", L"{\"operation_id\":" + mcpjson::Quote(r.OperationId) +
            L",\"root_identity\":" + mcpjson::Quote(r.RootIdentity) + L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) +
            L",\"created_filetime\":" + N(time) + L",\"initial_catalog_sha256\":" + mcpjson::Quote(catalog) +
            L",\"policy\":" + EvidenceGcPolicyJson(p) + L"}");
    }
    std::wstring GcEntryJson(const EvidenceGcResult& r, const EvidenceGcEntry& e, size_t ordinal,
        uint64_t time, const std::wstring& catalog, bool intent)
    {
        return Envelope(intent ? L"kn.evidence_gc_intent.v1" : L"kn.evidence_gc_receipt.v1",
            L"{\"operation_sha256\":" + mcpjson::Quote(r.OperationSha256) + L",\"ordinal\":" + N(ordinal) +
            L",\"artifact\":" + MemberJson(e.Artifact) + L",\"file_identity\":" + mcpjson::Quote(e.FileIdentity) +
            L",\"last_write_filetime\":" + N(e.LastWriteTime) + L",\"observed_filetime\":" + N(time) +
            L",\"catalog_sha256\":" + mcpjson::Quote(catalog) + L",\"state\":" + mcpjson::Quote(e.State) +
            L",\"issue\":" + mcpjson::Quote(e.Issue) + L",\"intent_sha256\":" + mcpjson::Quote(e.IntentSha256) + L"}");
    }
    bool ParseGcEntry(const std::wstring& json, const EvidenceGcResult& operation, size_t ordinal, bool intent,
        EvidenceGcEntry* entry)
    {
        std::wstring payload, catalog;
        uint64_t time = 0;
        if (!mcpjson::FindRawValue(json, L"payload", &payload) ||
            !mcpjson::GetString(payload, L"file_identity", &entry->FileIdentity) || !Text(entry->FileIdentity, 100) ||
            !Number(payload, L"last_write_filetime", &entry->LastWriteTime) ||
            !Number(payload, L"observed_filetime", &time) || time == 0 ||
            !mcpjson::GetString(payload, L"catalog_sha256", &catalog) || !Digest(catalog) ||
            !mcpjson::GetString(payload, L"state", &entry->State) ||
            !mcpjson::GetString(payload, L"issue", &entry->Issue) || !Text(entry->Issue, 256, true) ||
            !mcpjson::GetString(payload, L"intent_sha256", &entry->IntentSha256)) { return false; }
        if (intent)
        {
            if (entry->State != L"intent" || !entry->Issue.empty() || !entry->IntentSha256.empty()) { return false; }
        }
        else if (!Digest(entry->IntentSha256) || (entry->State != L"deleted_named_entry" && entry->State != L"delete_failed" &&
            entry->State != L"absent_after_intent" && entry->State != L"delete_outcome_unknown")) { return false; }
        return GcEntryJson(operation, *entry, ordinal, time, catalog, intent) == json;
    }
    struct GcFailure { std::wstring Issue; };
}

std::wstring EvidenceGcPolicyJson(const EvidenceGcPolicy& p)
{
    std::wstring members = L"[";
    for (const auto& m : p.Members)
    {
        if (members.size() > 1) { members += L","; }
        members += MemberJson(m);
    }
    const std::wstring prefix = p.RetiredCollection.empty() ? L"{\"schema\":\"kn.evidence_gc_policy.v1\",\"policy\":\"kn.gc_explicit_uncommitted.v1\"" :
        L"{\"schema\":\"kn.evidence_gc_policy.v2\",\"policy\":\"kn.gc_explicit_retired.v1\",\"retired_collection_id\":" +
        mcpjson::Quote(p.RetiredCollection) + L",\"retirement_sha256\":" + mcpjson::Quote(p.RetirementSha256);
    return prefix + L",\"reason\":" +
        mcpjson::Quote(p.Reason) + L",\"minimum_age_seconds\":" + N(p.MinimumAgeSeconds) + L",\"byte_limit\":" +
        N(p.ByteLimit) + L",\"members\":" + members + L"]}";
}

EvidenceRetirementResult EvidenceStoreAccess::Retire(const std::wstring& root, const std::wstring& policyPath,
    bool apply, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts)
{
    EvidenceRetirementResult result;
    result.Apply = apply;
    try
    {
        if (!Text(policyPath, 30000)) { result.Issue = L"invalid_retirement_policy_path"; return result; }
        EvidenceJournal policyOwner;
        Handle policyLease{nullptr, &CloseHandle};
        std::wstring json;
        uint64_t size = 0;
        RetirementRecord record;
        if (!policyOwner.Data->Read(fs::absolute(policyPath).lexically_normal(), 8192, &policyLease, &result.PolicySha256, &size, &json))
            { result.Issue = L"retirement_policy_unavailable"; return result; }
        if (!ParseRetirementPolicy(json, record.Policy)) { result.Issue = L"invalid_retirement_policy"; return result; }
        bool called = false;
        const auto snapshot = Inspect(root, {}, [&](const EvidenceStoreInventory& store, const fs::path& absolute, EvidenceJournal::Impl& reader)
        {
            called = true;
            try
            {
                const auto& policy = record.Policy;
                if (store.Status != L"verified") { result.Issue = L"retirement_requires_complete_closed_store"; return; }
                result.Status = L"denied";
                const auto found = std::find_if(store.Collections.begin(), store.Collections.end(), [&](const auto& c) { return c.Id == policy.Id; });
                if (found == store.Collections.end() || !found->Recovery.Closed || found->Recovery.SessionSha256 != policy.Session ||
                    found->Recovery.HeadSha256 != policy.Head) { result.Issue = L"retirement_root_mismatch"; return; }
                const auto folder = absolute / L"collections" / policy.Id;
                const auto receipt = folder / RetirementFile;
                Handle lease{nullptr, &CloseHandle};
                std::wstring stored, digest;
                if (!found->Recovery.RetirementSha256.empty())
                {
                    RetirementRecord previous;
                    if (!reader.Read(receipt, 16384, &lease, &digest, &size, &stored) || digest != found->Recovery.RetirementSha256 ||
                        !ParseRetirementRecord(stored, previous) || RetirementPolicyJson(previous.Policy) != json)
                        { result.Issue = L"collection_retirement_policy_conflict"; return; }
                    result.Record = std::move(stored); result.ReceiptSha256 = std::move(digest);
                    result.Status = L"retired"; result.Reused = true; return;
                }
                const auto closure = folder / L"journal-segments" / SequenceName(found->Recovery.CommittedSegments);
                WIN32_FILE_ATTRIBUTE_DATA attributes{};
                if (!GetFileAttributesExW(NativePath(closure).c_str(), GetFileExInfoStandard, &attributes))
                    { result.Issue = L"closure_timestamp_unavailable"; return; }
                record.ClosureWritten = FileTimeValue(attributes.ftLastWriteTime); record.Observed = CurrentFileTime();
                record.Catalog = store.CatalogSha256; record.Artifacts = store.ArtifactsSha256;
                for (const auto& a : store.Artifacts)
                {
                    if (std::binary_search(a.Collections.begin(), a.Collections.end(), policy.Id))
                    {
                        auto& count = FailureLedger(a.Artifact.Schema) ? record.Ledgers : a.Collections.size() == 1 ? record.Exclusive : record.Shared;
                        count.Add(a.Artifact.Bytes);
                    }
                }
                if (policy.RoutineBudget)
                {
                    if (policy.ReviewedCatalog != store.CatalogSha256 || policy.ReviewedArtifacts != store.ArtifactsSha256)
                        { result.Issue = L"routine_budget_inventory_changed"; return; }
                    if (found->Retention.Priority != CollectionPriority::Routine) { result.Issue = L"routine_budget_root_protected"; return; }
                    record.RoutineBefore = store.Budget.ByPriority[static_cast<size_t>(CollectionPriority::Routine)].Bytes;
                    if (record.RoutineBefore <= policy.RoutineTarget) { result.Issue = L"routine_budget_within_target"; return; }
                    if (SelectRoutineRetirement(store, policy.RoutineTarget, policy.Age, policy.ExclusiveByteLimit) != &*found ||
                        found->Retention.ClosureWritten != record.ClosureWritten || !record.Exclusive.Bytes ||
                        record.Exclusive.Bytes != found->Retention.ExclusiveRoutineBytes || record.Exclusive.Bytes > record.RoutineBefore)
                        { result.Issue = L"routine_budget_candidate_changed_or_ineligible"; return; }
                    record.RoutineAfter = record.RoutineBefore - record.Exclusive.Bytes;
                }
                result.Record = RetirementReceiptJson(record);
                if (!record.ClosureWritten || record.Observed < record.ClosureWritten ||
                    (record.Observed - record.ClosureWritten) / 10000000 < policy.Age) { result.Issue = L"closure_too_young_or_future"; return; }
                if (record.Exclusive.Bytes > policy.ExclusiveByteLimit) { result.Issue = L"retirement_exclusive_byte_limit"; return; }
                if (observer) { observer(L"retire_preflight"); }
                if (!apply) { result.Status = L"planned"; return; }
                result.Status = L"incomplete";
                if (!reader.Timely() || !SaveObservationJson(NativePath(receipt), result.Record, nullptr))
                    { result.Issue = L"retirement_publication_failed"; return; }
                if (observer) { observer(L"retire_published"); }
                if (!reader.Read(receipt, 16384, &lease, &digest, &size, &stored) || stored != result.Record)
                    { result.Issue = L"retirement_verification_failed"; return; }
                result.ReceiptSha256 = std::move(digest); result.Status = L"retired";
            }
            catch (...) { result.Status = L"incomplete"; result.Issue = L"retirement_execution_exception"; }
        }, record.Policy.RoutineBudget, receipts.Catalog, receipts.Files, observer);
        if (!called) { result.Issue = snapshot.Issue.empty() ? L"retirement_inventory_unavailable" : snapshot.Issue; }
    }
    catch (...) { result.Status = L"incomplete"; result.Issue = L"retirement_inspection_exception"; }
    return result;
}

EvidenceRetirementResult RetireEvidenceCollection(const std::wstring& root, const std::wstring& policyPath,
    bool apply, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts)
{ return EvidenceStoreAccess::Retire(root, policyPath, apply, observer, receipts); }

std::wstring EvidenceRetirementResultJson(const EvidenceRetirementResult& r)
{
    return L"{\"schema\":\"kn.evidence_retirement_result.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"apply\":" + B(r.Apply) + L",\"reused_receipt\":" + B(r.Reused) +
        L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) + L",\"receipt_sha256\":" + mcpjson::Quote(r.ReceiptSha256) +
        L",\"record\":" + (r.Record.empty() ? L"null" : r.Record) +
        L",\"deleted_this_call\":\"0\",\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
}

bool ParseEvidenceGcPolicy(const std::wstring& json, EvidenceGcPolicy* policy)
{
    EvidenceGcPolicy p;
    std::vector<std::wstring> members;
    if (policy == nullptr || json.size() > GcMaxPolicyBytes || !mcpjson::ValidateDocument(json) ||
        !mcpjson::GetString(json, L"reason", &p.Reason) || !Number(json, L"minimum_age_seconds", &p.MinimumAgeSeconds) ||
        !Number(json, L"byte_limit", &p.ByteLimit) || !Array(json, L"members", GcMaxFiles, &members)) { return false; }
    std::wstring schema;
    if (!mcpjson::GetString(json, L"schema", &schema)) { return false; }
    if (schema == L"kn.evidence_gc_policy.v2" &&
        (!mcpjson::GetString(json, L"retired_collection_id", &p.RetiredCollection) || !Id(p.RetiredCollection) ||
        !mcpjson::GetString(json, L"retirement_sha256", &p.RetirementSha256))) { return false; }
    for (const auto& row : members)
    {
        EvidenceJournalMember m;
        if (!mcpjson::GetString(row, L"path", &m.Path) || !mcpjson::GetString(row, L"sha256", &m.Sha256) ||
            !mcpjson::GetString(row, L"schema", &m.Schema) || !Number(row, L"bytes", &m.Bytes)) { return false; }
        p.Members.push_back(std::move(m));
    }
    if (!GcPolicyValid(p) || EvidenceGcPolicyJson(p) != json) { return false; }
    *policy = std::move(p);
    return true;
}

EvidenceGcResult EvidenceStoreAccess::Collect(const std::wstring& root, const std::wstring& policyPath,
    const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts)
{
    EvidenceGcResult result;
    result.OperationId = operationId; result.Apply = !operationId.empty();
    try
    {
        if (result.Apply && !Id(operationId)) { result.Issue = L"invalid_gc_operation_id"; return result; }
        if (!Text(policyPath, 30000)) { result.Issue = L"invalid_gc_policy_path"; return result; }
        EvidenceJournal policyOwner;
        auto& input = *policyOwner.Data;
        Handle policyLease{nullptr, &CloseHandle};
        std::wstring policyJson;
        uint64_t policyBytes = 0;
        if (!input.Read(fs::absolute(policyPath).lexically_normal(), GcMaxPolicyBytes, &policyLease,
            &result.PolicySha256, &policyBytes, &policyJson)) { result.Issue = L"gc_policy_unavailable"; return result; }
        EvidenceGcPolicy policy;
        if (!ParseEvidenceGcPolicy(policyJson, &policy)) { result.Issue = L"invalid_gc_policy"; return result; }
        result.RetiredCollection = policy.RetiredCollection; result.RetirementSha256 = policy.RetirementSha256;
        std::set<std::wstring> deletionPaths;
        for (const auto& member : policy.Members)
        {
            result.SelectedBytes += member.Bytes;
            if (result.Apply) { deletionPaths.insert(member.Path); }
        }
        bool called = false;
        const auto inventory = Inspect(root, deletionPaths, [&](const EvidenceStoreInventory& snapshot, const fs::path& absolute,
            EvidenceJournal::Impl& reader)
        {
            called = true;
            const auto stop = [](const wchar_t* issue) { throw GcFailure{issue}; };
            const auto stage = [&](const wchar_t* name) { if (observer) { observer(name); } };
            try
            {
                result.CatalogSha256 = snapshot.CatalogSha256; result.ArtifactsSha256 = snapshot.ArtifactsSha256;
                result.ObservedFileTime = CurrentFileTime();
                if (snapshot.Status != L"verified" || !snapshot.MembershipComplete || !snapshot.ArtifactInventoryComplete)
                    { stop(L"gc_requires_complete_closed_store"); }
                if (!policy.RetiredCollection.empty() && std::none_of(snapshot.Collections.begin(), snapshot.Collections.end(),
                    [&](const auto& c) { return c.Id == policy.RetiredCollection && c.Recovery.RetirementSha256 == policy.RetirementSha256; }))
                    { result.Status = L"denied"; result.Issue = L"gc_retirement_receipt_mismatch"; return; }
                auto directory = Own(CreateFileW(NativePath(absolute).c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                uint64_t ignored = 0;
                if (!directory || !GcIdentity(directory.get(), &result.RootIdentity, &ignored, true)) { stop(L"gc_root_identity_unavailable"); }
                const auto operation = absolute / L"retention" / operationId;
                const auto manifest = operation / L"operation.kngc";
                const auto exists = [&](const fs::path& path)
                {
                    const auto attr = GetFileAttributesW(NativePath(path).c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES) { return true; }
                    const auto error = GetLastError();
                    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { stop(L"gc_path_state_unavailable"); }
                    return false;
                };
                const auto readJson = [&](const fs::path& path, std::wstring* json, std::wstring* hash)
                {
                    Handle lease{nullptr, &CloseHandle}; uint64_t size = 0;
                    if (!reader.Read(path, MaxJsonBytes, &lease, hash, &size, json)) { stop(L"gc_audit_record_unavailable"); }
                    reader.Files.emplace(L"@gc-" + path.wstring(), std::move(lease));
                };
                const auto publish = [&](const fs::path& path, const std::wstring& json, std::wstring* hash)
                {
                    if (!reader.Timely() || !SaveObservationJson(NativePath(path), json, nullptr)) { stop(L"gc_audit_publication_failed"); }
                    std::wstring verified;
                    readJson(path, &verified, hash);
                    if (verified != json) { stop(L"gc_audit_verification_failed"); }
                };
                const bool resumed = result.Apply && exists(manifest);
                if (resumed)
                {
                    std::wstring json, payload, catalog;
                    uint64_t time = 0;
                    readJson(manifest, &json, &result.OperationSha256);
                    if (!mcpjson::FindRawValue(json, L"payload", &payload) || !Number(payload, L"created_filetime", &time) || time == 0 ||
                        !mcpjson::GetString(payload, L"initial_catalog_sha256", &catalog) || !Digest(catalog) ||
                        GcOperationJson(result, policy, time, catalog) != json) { stop(L"gc_operation_collision_or_policy_mismatch"); }
                }
                std::vector<bool> priorIntents;
                bool denied = false;
                for (size_t i = 0; i < policy.Members.size(); ++i)
                {
                    EvidenceGcEntry entry; entry.Artifact = policy.Members[i];
                    const auto prefix = operation / std::to_wstring(i + 1);
                    const auto intentPath = fs::path(prefix.wstring() + L".kngcintent");
                    const auto receiptPath = fs::path(prefix.wstring() + L".kngcreceipt");
                    const bool hasIntent = resumed && exists(intentPath);
                    priorIntents.push_back(hasIntent);
                    EvidenceGcEntry intent = entry;
                    if (hasIntent)
                    {
                        std::wstring json, digest;
                        readJson(intentPath, &json, &digest);
                        if (!ParseGcEntry(json, result, i + 1, true, &intent)) { stop(L"gc_intent_invalid"); }
                        intent.IntentSha256 = digest;
                    }
                    if (resumed && exists(receiptPath))
                    {
                        std::wstring json, digest;
                        readJson(receiptPath, &json, &digest);
                        if (!hasIntent || !ParseGcEntry(json, result, i + 1, false, &entry) ||
                            entry.IntentSha256 != intent.IntentSha256 || entry.FileIdentity != intent.FileIdentity ||
                            entry.LastWriteTime != intent.LastWriteTime) { stop(L"gc_receipt_invalid_or_unbound"); }
                        entry.ReceiptSha256 = digest; entry.ReusedReceipt = true;
                        result.Entries.push_back(std::move(entry));
                        continue;
                    }
                    const auto found = std::find_if(snapshot.Artifacts.begin(), snapshot.Artifacts.end(),
                        [&](const EvidenceStoreArtifact& row) { return row.Artifact.Path == entry.Artifact.Path; });
                    const auto file = reader.Files.find(entry.Artifact.Path);
                    entry.State = L"eligible";
                    if (found == snapshot.Artifacts.end())
                    {
                        if (hasIntent && !exists(absolute / entry.Artifact.Path))
                            { entry = intent; entry.State = L"absent_after_intent"; entry.Issue = L"deletion_actor_unknown"; }
                        else { entry.State = L"denied"; entry.Issue = L"selected_file_missing"; }
                    }
                    else if (found->Retention == L"uncommitted_approval_input_protected" || found->Retention == L"unresolved_approval_input_protected" ||
                        found->Retention == L"uncommitted_image_input_protected" || found->Retention == L"unresolved_image_input_protected" ||
                        found->Retention == L"irp_replay_reference_protected" || found->Retention == L"unresolved_irp_reference_protected")
                        { entry.State = L"denied"; entry.Issue = found->Retention; }
                    else if (!found->Verified || found->JournalReferences != 0 ||
                        (policy.RetiredCollection.empty() ? found->Retention != L"uncommitted_requires_policy" :
                            found->Retention != L"retired_requires_policy" || !found->RetiredOriginalMatched ||
                            !std::binary_search(found->RetiredCollections.begin(), found->RetiredCollections.end(), policy.RetiredCollection)))
                        { entry.State = L"denied"; entry.Issue = L"selected_file_protected"; }
                    else if (!Same(found->Artifact, entry.Artifact)) { entry.State = L"denied"; entry.Issue = L"selected_file_changed"; }
                    else if (file == reader.Files.end() || !GcIdentity(file->second.get(), &entry.FileIdentity, &entry.LastWriteTime))
                        { entry.State = L"denied"; entry.Issue = L"selected_identity_attributes_or_links_unavailable"; }
                    else if (result.ObservedFileTime < entry.LastWriteTime ||
                        (result.ObservedFileTime - entry.LastWriteTime) / 10000000 < policy.MinimumAgeSeconds)
                        { entry.State = L"denied"; entry.Issue = L"selected_file_too_young_or_future"; }
                    else if (hasIntent && (entry.FileIdentity != intent.FileIdentity || entry.LastWriteTime != intent.LastWriteTime))
                        { entry.State = L"denied"; entry.Issue = L"replacement_after_intent_preserved"; }
                    if (hasIntent) { entry.IntentSha256 = intent.IntentSha256; }
                    denied |= entry.State == L"denied";
                    result.Entries.push_back(std::move(entry));
                }
                stage(L"gc_preflight");
                if (denied) { result.Status = L"denied"; result.Issue = L"gc_selection_not_eligible"; return; }
                if (!result.Apply) { result.Status = L"planned"; return; }
                if (!resumed)
                {
                    if (!reader.PinDirectory(operation, true)) { stop(L"gc_operation_directory_unavailable"); }
                    // An interrupted manifest temporary is harmless; other unexplained records are not adopted.
                    std::error_code ec; size_t pending = 0;
                    for (fs::directory_iterator it(NativePath(operation), ec), end; !ec && it != end; it.increment(ec))
                    {
                        if (++pending > GcMaxFiles || it->path().filename().wstring().rfind(L"operation.kngc.pending-", 0) != 0)
                            { stop(L"gc_operation_directory_collision"); }
                    }
                    if (ec) { stop(L"gc_operation_directory_unavailable"); }
                    publish(manifest, GcOperationJson(result, policy, result.ObservedFileTime, result.CatalogSha256), &result.OperationSha256);
                }
                stage(L"gc_operation");
                for (size_t i = 0; i < result.Entries.size(); ++i)
                {
                    auto& entry = result.Entries[i];
                    if (entry.ReusedReceipt) { continue; }
                    if (!reader.Timely()) { stop(L"gc_deadline_exhausted"); }
                    const auto prefix = operation / std::to_wstring(i + 1);
                    if (!priorIntents[i])
                    {
                        auto intent = entry; intent.State = L"intent"; intent.Issue.clear(); intent.IntentSha256.clear();
                        publish(fs::path(prefix.wstring() + L".kngcintent"), GcEntryJson(result, intent, i + 1,
                            result.ObservedFileTime, result.CatalogSha256, true), &entry.IntentSha256);
                    }
                    stage(L"gc_intent");
                    if (entry.State == L"eligible")
                    {
                        if (!reader.Timely()) { stop(L"gc_deadline_exhausted_before_delete"); }
                        auto file = reader.Files.find(entry.Artifact.Path);
                        if (file == reader.Files.end()) { stop(L"gc_selected_lease_lost"); }
                        FILE_DISPOSITION_INFO disposition{TRUE};
                        if (!SetFileInformationByHandle(file->second.get(), FileDispositionInfo, &disposition, sizeof(disposition)))
                        {
                            entry.State = L"delete_failed"; entry.Issue = L"win32_" + std::to_wstring(GetLastError());
                        }
                        else
                        {
                            // Close the same verified DELETE-capable handle. Never reopen a path to delete it.
                            file->second.reset(); reader.Files.erase(file);
                            if (!exists(absolute / entry.Artifact.Path))
                            {
                                entry.State = L"deleted_named_entry"; entry.Issue.clear();
                                ++result.DeletedThisCall; result.DeletedBytesThisCall += entry.Artifact.Bytes;
                            }
                            else { entry.State = L"delete_outcome_unknown"; entry.Issue = L"name_present_after_disposition"; }
                        }
                    }
                    stage(L"gc_delete");
                    publish(fs::path(prefix.wstring() + L".kngcreceipt"), GcEntryJson(result, entry, i + 1,
                        CurrentFileTime(), result.CatalogSha256, false), &entry.ReceiptSha256);
                    stage(L"gc_receipt");
                }
                result.Status = std::all_of(result.Entries.begin(), result.Entries.end(), [](const EvidenceGcEntry& entry)
                    { return entry.State == L"deleted_named_entry"; }) ? L"completed" : L"completed_with_unresolved_outcomes";
            }
            catch (const GcFailure& failure) { result.Status = L"incomplete"; result.Issue = failure.Issue; }
            catch (...) { result.Status = L"incomplete"; result.Issue = L"gc_execution_exception"; }
        }, false, receipts.Catalog, receipts.Files, observer);
        if (!called) { result.Issue = inventory.Issue.empty() ? L"gc_inventory_unavailable" : inventory.Issue; }
    }
    catch (...) { result.Status = L"incomplete"; result.Issue = L"gc_inspection_exception"; }
    return result;
}

EvidenceGcResult CollectEvidenceStore(const std::wstring& root, const std::wstring& policyPath,
    const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer, const EvidenceStoreReceipts& receipts)
{
    return EvidenceStoreAccess::Collect(root, policyPath, operationId, observer, receipts);
}

std::wstring EvidenceGcResultJson(const EvidenceGcResult& r)
{
    std::wstring entries = L"[";
    for (const auto& entry : r.Entries)
    {
        if (entries.size() > 1) { entries += L","; }
        entries += L"{\"artifact\":" + MemberJson(entry.Artifact) + L",\"state\":" + mcpjson::Quote(entry.State) +
            L",\"issue\":" + mcpjson::Quote(entry.Issue) + L",\"file_identity\":" + mcpjson::Quote(entry.FileIdentity) +
            L",\"last_write_filetime\":" + N(entry.LastWriteTime) + L",\"intent_sha256\":" + mcpjson::Quote(entry.IntentSha256) +
            L",\"receipt_sha256\":" + mcpjson::Quote(entry.ReceiptSha256) + L",\"reused_receipt\":" + B(entry.ReusedReceipt) + L"}";
    }
    return L"{\"schema\":\"kn.evidence_gc_result.v1\",\"status\":" + mcpjson::Quote(r.Status) + L",\"issue\":" +
        mcpjson::Quote(r.Issue) + L",\"apply\":" + B(r.Apply) + L",\"operation_id\":" + mcpjson::Quote(r.OperationId) +
        L",\"root_identity\":" + mcpjson::Quote(r.RootIdentity) + L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) +
        L",\"operation_sha256\":" + mcpjson::Quote(r.OperationSha256) + L",\"preflight_catalog_sha256\":" + mcpjson::Quote(r.CatalogSha256) +
        L",\"preflight_artifacts_sha256\":" + mcpjson::Quote(r.ArtifactsSha256) + L",\"observed_filetime\":" + N(r.ObservedFileTime) +
        L",\"selected_bytes\":" + N(r.SelectedBytes) + L",\"deleted_this_call\":" + N(r.DeletedThisCall) +
        L",\"deleted_named_bytes_this_call\":" + N(r.DeletedBytesThisCall) + L",\"entries\":" + entries +
        (r.RetiredCollection.empty() ? L"],\"scope\":\"explicit_uncommitted_image_and_irp_artifacts\"" :
            L"],\"scope\":\"explicit_retired_collection_artifacts\",\"retired_collection_id\":" + mcpjson::Quote(r.RetiredCollection) +
            L",\"retirement_sha256\":" + mcpjson::Quote(r.RetirementSha256)) + L",\"coordination\":\"participating_publishers\","
        L"\"receipt_scope\":\"operation_history\",\"current_path_absence_established\":false,\"uncommitted_dependents_resolved\":false,"
        L"\"deletion_authority_after_return\":false,\"disk_reclamation_established\":false,\"collector_authenticated\":false,"
        L"\"power_loss_durability_established\":false}";
}
