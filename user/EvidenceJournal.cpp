#include "EvidenceJournal.h"
#include "AnalystSnapshot.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <set>

using namespace bounded_observation_json;
namespace fs = std::filesystem;

namespace
{
    constexpr uint64_t MaxSegments = 8192, MaxPaths = 16384, MaxReferences = 65536;
    constexpr uint64_t MaxReadBytes = 1024ull * 1024 * 1024, MaxJsonBytes = 2 * 1024 * 1024;
    constexpr uint64_t MaxBlobBytes = 64 * 1024 * 1024, DeadlineMs = 120000;
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    Handle Own(HANDLE handle) { return Handle(handle == INVALID_HANDLE_VALUE ? nullptr : handle, &CloseHandle); }
    // Only internally constructed, normalized local DOS paths reach this
    // helper, after PinDirectory rejects device/UNC/reparse components. Do not
    // depend on a host manifest or registry switch for temporary-file lengths.
    std::wstring NativePath(const fs::path& path)
    {
        auto preferred = path;
        preferred.make_preferred(); // Extended paths do not translate forward slashes.
        return L"\\\\?\\" + preferred.wstring();
    }
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
    std::wstring SessionJson(const std::wstring& id)
    {
        return Envelope(L"kn.evidence_session.v1", L"{\"collection_id\":" + mcpjson::Quote(id) +
            L",\"policy\":\"kn.image_collection_journal.v1\",\"hash_basis\":\"exact_file_bytes\","
            L"\"collector_authenticated\":false,\"target_coverage_established\":false}");
    }
    std::wstring MemberJson(const EvidenceJournalMember& m)
    {
        return L"{\"path\":" + mcpjson::Quote(m.Path) + L",\"sha256\":" + mcpjson::Quote(m.Sha256) +
            L",\"bytes\":" + N(m.Bytes) + L",\"schema\":" + mcpjson::Quote(m.Schema) + L"}";
    }
    bool Same(const EvidenceJournalMember& a, const EvidenceJournalMember& b)
    {
        return a.Path == b.Path && a.Sha256 == b.Sha256 && a.Bytes == b.Bytes && a.Schema == b.Schema;
    }
    bool MemberValid(const EvidenceJournalMember& m, const std::wstring& id)
    {
        if (!Digest(m.Sha256) || m.Bytes == 0 || m.Path.size() > 180) { return false; }
        const auto reference = L"image-references/" + m.Sha256 + L".knblob";
        if (m.Path == reference) { return m.Schema == L"raw.bytes" && m.Bytes <= MaxBlobBytes; }
        if (m.Bytes > MaxJsonBytes) { return false; }
        if (m.Path == L"image-reads/session-" + id + L".knreadledger") { return m.Schema == L"kn.image_read_session.v1"; }
        const auto slash = m.Path.find(L'/');
        const auto dot = m.Path.rfind(L'.');
        if (slash == std::wstring::npos || dot == std::wstring::npos || dot <= slash) { return false; }
        const auto folder = m.Path.substr(0, slash), name = m.Path.substr(slash + 1, dot - slash - 1), ext = m.Path.substr(dot);
        const auto prefix = (folder == L"image-reads" ? L"reads-" : L"sweep-") + id + L"-";
        if (name.rfind(prefix, 0) != 0 || !Id(name.substr(prefix.size()))) { return false; }
        if (folder == L"image-sweeps") { return ext == L".knsweep" && m.Schema == L"kn.image_sweep.v1"; }
        return folder == L"image-reads" && ((ext == L".knslice" &&
            (m.Schema == L"kn.image_slice.v1" || m.Schema == L"kn.image_slice.v2")) || (ext == L".knreads" &&
            (m.Schema == L"kn.image_reads.v1" || m.Schema == L"kn.image_reads.v2" || m.Schema == L"kn.image_reads.v3")));
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

struct EvidenceJournal::Impl
{
    fs::path Root, Collection;
    EvidenceJournalRecovery Result;
    std::map<std::wstring, Handle> Directories, Files;
    Handle Lock{nullptr, &CloseHandle};
    std::map<std::wstring, EvidenceJournalMember> Members;
    std::map<std::wstring, uint64_t> ContentSizes;
    std::map<std::wstring, size_t> Transactions;
    std::vector<Record> Records;
    uint64_t References = 0, Started = GetTickCount64();
    bool Writable = false, Healthy = false;

    bool Fail(const wchar_t* issue) { Result.Issue = issue; return false; }
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
    bool Read(const fs::path& path, uint64_t maximum, Handle* owner, std::wstring* digest, uint64_t* size, std::wstring* json = nullptr)
    {
        if (!PinDirectory(path.parent_path(), false) || !Timely()) { return false; }
        auto file = Own(CreateFileW(NativePath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        LARGE_INTEGER length{};
        if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            !GetFileSizeEx(file.get(), &length) || length.QuadPart <= 0 || uint64_t(length.QuadPart) > maximum)
            { return Fail(L"file_missing_invalid_or_locked"); }
        *size = uint64_t(length.QuadPart);
        if (*size > MaxReadBytes - Result.ReadBytes) { return Fail(L"read_budget_exhausted"); }
        ContentHash hash;
        uint8_t buffer[65536];
        std::string bytes;
        if (json != nullptr) { bytes.reserve(static_cast<size_t>(*size)); }
        uint64_t remaining = *size;
        while (remaining)
        {
            const auto count = static_cast<DWORD>((std::min)(remaining, uint64_t(sizeof(buffer))));
            DWORD received = 0;
            if (!Timely() || !ReadFile(file.get(), buffer, count, &received, nullptr) || received != count || !hash.Add(buffer, received))
                { return Fail(L"file_read_failed_or_timed_out"); }
            if (json != nullptr) { bytes.append(reinterpret_cast<const char*>(buffer), received); }
            remaining -= received; Result.ReadBytes += received;
        }
        *digest = hash.Finish();
        if (!Digest(*digest)) { return Fail(L"file_hash_failed"); }
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
        if ((t.Kind != L"image_reads" && t.Kind != L"image_sweep" && t.Kind != L"closure") || !Id(t.Id) ||
            t.Members.empty() || t.Members.size() > 8192 || t.Requires.size() > 8192 ||
            t.Members.size() + t.Requires.size() > MaxReferences - References) { return Fail(L"invalid_transaction_or_reference_budget"); }
        if ((t.Kind == L"closure" && (t.Id != L"0" || t.Members.size() != 1 ||
                t.Members[0].Path != L"image-reads/session-" + Result.CollectionId + L".knreadledger")) ||
            (t.Kind == L"image_sweep" && (t.Members.size() != 1 || t.Members[0].Path !=
                L"image-sweeps/sweep-" + Result.CollectionId + L"-" + t.Id + L".knsweep"))) { return Fail(L"invalid_transaction_root"); }
        std::wstring previous;
        size_t added = 0;
        for (const auto& m : t.Members)
        {
            if (!MemberValid(m, Result.CollectionId) || (!previous.empty() && m.Path <= previous)) { return Fail(L"invalid_or_duplicate_member"); }
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
        if (added > MaxPaths - Members.size()) { return Fail(L"member_budget_exhausted"); }
        previous.clear();
        for (const auto& path : t.Requires)
        {
            if ((!previous.empty() && path <= previous) || !Members.count(path)) { return Fail(L"dependency_not_committed_or_duplicate"); }
            previous = path;
        }
        return true;
    }
    bool VerifyMembers(const EvidenceJournalTransaction& t, std::map<std::wstring, Handle>* added)
    {
        for (const auto& m : t.Members)
        {
            if (Members.count(m.Path)) { continue; } // Still held under write/delete exclusion.
            Handle file{nullptr, &CloseHandle};
            std::wstring digest, json, schema;
            uint64_t size = 0;
            if (!Read(Root / m.Path, m.Bytes, &file, &digest, &size, m.Schema == L"raw.bytes" ? nullptr : &json)) { return false; }
            if (digest != m.Sha256 || size != m.Bytes) { return Fail(L"member_hash_or_size_mismatch"); }
            if (m.Schema != L"raw.bytes" && (!mcpjson::GetString(json, L"schema", &schema) || schema != m.Schema))
                { return Fail(L"member_schema_mismatch"); }
            added->emplace(m.Path, std::move(file));
        }
        return true;
    }
    void Accept(Record r, std::map<std::wstring, Handle> added)
    {
        // Publish counters only after all allocating state changes succeed.
        // Any exception poisons the instance; recovery still reports the last
        // fully verified prefix rather than half of the next transaction.
        auto accepted = Result;
        for (auto& item : added) { Files.emplace(item.first, std::move(item.second)); }
        for (const auto& m : r.Transaction.Members)
        {
            ++accepted.MemberReferences; accepted.LogicalBytes += m.Bytes;
            if (ContentSizes.emplace(m.Sha256, m.Bytes).second) { accepted.UniqueContentBytes += m.Bytes; }
            Members.emplace(m.Path, m);
            if (m.Schema == L"kn.image_sweep.v1") { accepted.SweepPaths.push_back(m.Path); }
        }
        References += r.Transaction.Members.size() + r.Transaction.Requires.size();
        Transactions.emplace(r.Transaction.Kind + L":" + r.Transaction.Id, Records.size());
        accepted.CommittedSegments = r.Sequence; accepted.HeadSha256 = r.Hash; accepted.UniquePaths = Members.size();
        accepted.Closed = r.Transaction.Kind == L"closure";
        Records.push_back(std::move(r));
        Result = std::move(accepted);
    }
    bool Load(const std::wstring& artifactRoot, const std::wstring& id, bool create)
    {
        if (!Id(id)) { return Fail(L"invalid_collection_id"); }
        if (!Text(artifactRoot, 30000)) { return Fail(L"invalid_artifact_root"); }
        Result.CollectionId = id;
        std::error_code error;
        Root = fs::absolute(artifactRoot, error).lexically_normal();
        Collection = Root / L"collections" / id;
        if (error || !PinDirectory(Collection, create)) { return false; }
        Lock = Own(CreateFileW(NativePath(Collection / L"writer.knjlock").c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            create ? OPEN_ALWAYS : OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!Lock || !GetFileInformationByHandleEx(Lock.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            { return Fail(L"collection_busy_or_lock_unavailable"); }
        const auto manifest = Collection / L"session.knsession";
        const auto session = SessionJson(id);
        const auto attrs = GetFileAttributesW(NativePath(manifest).c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES && create && GetLastError() == ERROR_FILE_NOT_FOUND &&
            !SaveObservationJson(NativePath(manifest), session, nullptr)) { return Fail(L"session_publication_failed"); }
        Handle lease{nullptr, &CloseHandle};
        uint64_t bytes = 0;
        std::wstring json;
        if (!Read(manifest, 4096, &lease, &Result.SessionSha256, &bytes, &json) || json != session)
            { return Fail(L"session_missing_or_invalid"); }
        Files.emplace(L"@session", std::move(lease));
        Result.HeadSha256 = Result.SessionSha256;
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
            std::map<std::wstring, Handle> added;
            if (!ValidateTransaction(r.Transaction) || !VerifyMembers(r.Transaction, &added)) { return false; }
            Files.emplace(L"@segment-" + std::to_wstring(r.Sequence), std::move(lease));
            Accept(std::move(r), std::move(added));
        }
        Result.Status = L"verified_prefix"; Result.Issue.clear(); Result.CanResume = !Result.Closed;
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
        if (!exists && (GetLastError() != ERROR_FILE_NOT_FOUND || !SaveObservationJson(NativePath(path), json, nullptr)))
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

bool EvidenceJournal::Open(const std::wstring& root, const std::wstring& id, std::wstring* error)
{
    if (Data->Lock) { if (error) { *error = L"journal_already_open"; } return false; }
    bool ok = false;
    try { ok = Data->Load(root, id, true); }
    catch (...) { Data->Fail(L"journal_open_exception"); }
    if (error) { *error = Data->Result.Issue; }
    return ok;
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
        std::map<std::wstring, Handle> added;
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
        if (!SaveObservationJson(NativePath(path), json, nullptr))
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
            d.Result.Status = d.Result.CommittedSegments ? L"incomplete_prefix" : L"unavailable";
            d.Result.CanResume = d.Result.Closed = false;
            return d.Result;
        }
        if (rebuildIndex)
        {
            d.Result.IndexStatus = L"building";
            for (const auto& r : d.Records)
            {
                if (!d.IndexRecord(r)) { d.Result.IndexStatus = L"failed"; return d.Result; }
            }
            d.Result.IndexStatus = d.IndexHead() ? L"ready" : L"failed";
        }
    }
    catch (...) { d.Result.Status = L"incomplete_prefix"; d.Result.CanResume = d.Result.Closed = false; d.Fail(L"journal_recovery_exception"); }
    return d.Result;
}

std::wstring EvidenceJournalRecoveryJson(const EvidenceJournalRecovery& r)
{
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
        L",\"pending_segment_files\":" + N(r.PendingFiles) + L",\"index_status\":" + mcpjson::Quote(r.IndexStatus) +
        L",\"index_created\":" + N(r.IndexCreated) + L",\"index_reused\":" + N(r.IndexReused) +
        L",\"committed_sweep_paths\":" + sweeps + L"],\"denominator_scope\":\"verified_collection_prefix\","
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
