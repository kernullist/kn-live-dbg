#include "EvidenceJournal.h"
#include "EvidenceStore.h"
#include "AnalystSnapshot.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
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
    constexpr uint64_t MaxReadBytes = 1024ull * 1024 * 1024, MaxJsonBytes = 2 * 1024 * 1024;
    constexpr uint64_t MaxBlobBytes = 64 * 1024 * 1024, DeadlineMs = 120000;
    constexpr uint64_t StoreMaxCollections = 1024, StoreMaxPaths = 65536, StoreMaxReferences = 262144;
    constexpr uint64_t StoreMaxReadBytes = 8ull * 1024 * 1024 * 1024;
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
    fs::path Root, Collection;
    EvidenceJournalRecovery Result;
    std::map<std::wstring, Handle> Directories, Files;
    Handle Lock{nullptr, &CloseHandle};
    std::unique_ptr<EvidenceStoreLease> StoreLease;
    std::map<std::wstring, std::pair<EvidenceJournalMember, Handle>>* SharedMembers = nullptr;
    uint64_t* SharedReadBytes = nullptr;
    uint64_t* SharedReferences = nullptr;
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
        if (SharedReadBytes != nullptr && *size > StoreMaxReadBytes - *SharedReadBytes) { return Fail(L"store_read_budget_exhausted"); }
        ContentHash hash;
        uint8_t buffer[65536];
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
            if (json != nullptr) { bytes.append(reinterpret_cast<const char*>(buffer), received); }
            remaining -= received;
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
        if (SharedReferences != nullptr && t.Members.size() + t.Requires.size() > StoreMaxReferences - *SharedReferences)
            { return Fail(L"store_reference_budget_exhausted"); }
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
            if (SharedMembers != nullptr)
            {
                const auto found = SharedMembers->find(m.Path);
                if (found != SharedMembers->end())
                {
                    if (!Same(found->second.first, m)) { return Fail(L"store_member_conflict"); }
                    HANDLE duplicate = nullptr;
                    if (!DuplicateHandle(GetCurrentProcess(), found->second.second.get(), GetCurrentProcess(), &duplicate, 0, FALSE,
                        DUPLICATE_SAME_ACCESS)) { return Fail(L"store_lease_duplicate_failed"); }
                    added->emplace(m.Path, Own(duplicate));
                    continue;
                }
                if (SharedMembers->size() == StoreMaxPaths) { return Fail(L"store_path_budget_exhausted"); }
            }
            Handle file{nullptr, &CloseHandle};
            std::wstring digest, json, schema;
            uint64_t size = 0;
            if (!Read(Root / m.Path, m.Bytes, &file, &digest, &size, m.Schema == L"raw.bytes" ? nullptr : &json)) { return false; }
            if (digest != m.Sha256 || size != m.Bytes) { return Fail(L"member_hash_or_size_mismatch"); }
            if (m.Schema != L"raw.bytes" && (!mcpjson::GetString(json, L"schema", &schema) || schema != m.Schema))
                { return Fail(L"member_schema_mismatch"); }
            if (SharedMembers != nullptr)
            {
                HANDLE duplicate = nullptr;
                if (!DuplicateHandle(GetCurrentProcess(), file.get(), GetCurrentProcess(), &duplicate, 0, FALSE,
                    DUPLICATE_SAME_ACCESS)) { return Fail(L"store_lease_duplicate_failed"); }
                SharedMembers->emplace(m.Path, std::make_pair(m, Own(duplicate)));
            }
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
        if (SharedReferences != nullptr)
            { *SharedReferences += Records.back().Transaction.Members.size() + Records.back().Transaction.Requires.size(); }
    }
    bool Load(const std::wstring& artifactRoot, const std::wstring& id, bool create, bool coordinated = false)
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
            L",\"unique_content_bytes\":" + N(r.UniqueContentBytes) + L",\"pending_files\":" + N(r.PendingFiles) + L"}";
    }
    std::wstring StoreArtifactJson(const EvidenceStoreArtifact& a)
    {
        std::wstring owners = L"[";
        for (const auto& id : a.Collections)
        {
            if (owners.size() > 1) { owners += L","; }
            owners += mcpjson::Quote(id);
        }
        return L"{\"artifact\":" + MemberJson(a.Artifact) + L",\"verified\":" + B(a.Verified) +
            L",\"journal_references\":" + N(a.JournalReferences) + L",\"collections\":" + owners +
            L"],\"retention\":" + mcpjson::Quote(a.Retention) + L"}";
    }
    std::wstring LowerAscii(std::wstring value)
    {
        for (auto& ch : value) { if (ch >= L'A' && ch <= L'Z') { ch += L'a' - L'A'; } }
        return value;
    }
    std::wstring MemberCollection(const std::wstring& path)
    {
        const auto name = fs::path(path).filename().wstring();
        const auto first = name.find(L'-');
        const auto last = name.find_first_of(L"-.", first == std::wstring::npos ? 0 : first + 1);
        return first != std::wstring::npos && last != std::wstring::npos ? name.substr(first + 1, last - first - 1) : L"";
    }
}

EvidenceStoreInventory InspectEvidenceStore(const std::wstring& artifactRoot)
{
    EvidenceStoreInventory out;
    out.StartedTick = GetTickCount64();
    const auto finish = [&]() { out.EndedTick = GetTickCount64(); return out; };
    try
    {
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(artifactRoot, true, &out.Issue)) { return finish(); }
        const auto root = fs::absolute(artifactRoot).lexically_normal();
        const auto collections = root / L"collections";
        EvidenceJournal namespaceOwner; // Keep catalog ancestors pinned through the entire inventory.
        std::error_code ec;
        std::set<std::wstring> ids;
        const auto attributes = GetFileAttributesW(NativePath(collections).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
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
        std::map<std::wstring, uint64_t> contentSizes;
        uint64_t references = 0;
        for (const auto& id : ids)
        {
            auto journal = std::make_unique<EvidenceJournal>();
            auto& d = *journal->Data;
            d.Started = out.StartedTick;
            d.SharedMembers = &cache; d.SharedReadBytes = &out.ReadBytes; d.SharedReferences = &references;
            bool ok = false;
            try { ok = d.Load(root.wstring(), id, false, true); }
            catch (...) { d.Fail(L"collection_inspection_exception"); }
            if (!ok)
            {
                d.Result.Status = d.Result.CommittedSegments ? L"incomplete_prefix" : L"unavailable";
                d.Result.Closed = d.Result.CanResume = false;
                ++out.UnresolvedCollections;
            }
            else if (d.Result.Closed) { ++out.ClosedCollections; }
            else { ++out.OpenCollections; }
            out.Collections.push_back({id, d.Result});
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
                        a.Retention = member.Schema == L"raw.bytes" ? L"committed_reference_protected" :
                            member.Schema == L"kn.image_read_session.v1" ? L"failure_ledger_protected" : L"committed_original_protected";
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
        bool physicalComplete = true;
        std::set<std::wstring> observed;
        for (const auto& folder : {L"image-reads", L"image-references", L"image-sweeps"})
        {
            const auto directory = root / folder;
            const auto attr = GetFileAttributesW(NativePath(directory).c_str());
            if (attr == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) { continue; }
            if (!reader.PinDirectory(directory, false)) { physicalComplete = false; out.Issue = reader.Result.Issue; continue; }
            ec.clear();
            for (fs::directory_iterator it(NativePath(directory), ec), end; !ec && it != end; it.increment(ec))
            {
                if (out.ObservedArtifactFiles == StoreMaxPaths || GetTickCount64() - out.StartedTick > DeadlineMs)
                    { physicalComplete = false; out.Issue = L"store_artifact_budget_exhausted"; break; }
                ++out.ObservedArtifactFiles;
                const auto relative = std::wstring(folder) + L"/" + LowerAscii(it->path().filename().wstring());
                if (!observed.insert(relative).second) { physicalComplete = false; ++out.UnmanagedEntries; continue; }
                auto found = artifacts.find(relative);
                if (found != artifacts.end()) { continue; } // Exact pinned file already checked through its journal.
                if (artifacts.size() == StoreMaxPaths)
                    { physicalComplete = false; out.Issue = L"store_path_budget_exhausted"; break; }
                EvidenceStoreArtifact a;
                a.Artifact.Path = relative;
                const auto extension = fs::path(relative).extension().wstring();
                const bool blob = extension == L".knblob" && std::wstring(folder) == L"image-references";
                const bool json = (std::wstring(folder) == L"image-reads" &&
                    (extension == L".knreads" || extension == L".knslice" || extension == L".knreadledger")) ||
                    (std::wstring(folder) == L"image-sweeps" && extension == L".knsweep");
                Handle lease{nullptr, &CloseHandle};
                std::wstring text;
                if (blob || json)
                {
                    a.Verified = reader.Read(root / relative, blob ? MaxBlobBytes : MaxJsonBytes, &lease,
                        &a.Artifact.Sha256, &a.Artifact.Bytes, json ? &text : nullptr);
                    if (blob) { a.Artifact.Schema = L"raw.bytes"; }
                    else { mcpjson::GetString(text, L"schema", &a.Artifact.Schema); }
                    a.Verified = a.Verified && (blob || Id(MemberCollection(relative))) && MemberValid(a.Artifact, MemberCollection(relative));
                    if (a.Verified) { reader.Files.emplace(relative, std::move(lease)); }
                }
                else { ++out.UnmanagedEntries; }
                ++out.UnattributedFiles;
                if (!a.Verified) { ++out.UnverifiedArtifactFiles; physicalComplete = false; }
                else { out.UnattributedBytes += a.Artifact.Bytes; }
                a.Retention = !a.Verified ? L"unverified_artifact_protected" :
                    a.Artifact.Schema == L"kn.image_read_session.v1" ? L"failure_ledger_protected" : out.MembershipComplete ?
                    L"uncommitted_requires_policy" : L"unresolved_membership_protected";
                artifacts.emplace(relative, std::move(a));
            }
            if (ec) { physicalComplete = false; out.Issue = L"store_artifact_enumeration_failed"; }
        }
        for (const auto& pair : artifacts)
        {
            if (pair.second.JournalReferences != 0 && !observed.count(pair.first))
                { physicalComplete = false; out.Issue = L"committed_path_missing_from_inventory"; }
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
        out.Status = out.MembershipComplete && out.ArtifactInventoryComplete ? L"verified" : L"partial";
        if (out.Status == L"partial" && out.Issue.empty()) { out.Issue = L"unresolved_membership_or_artifacts"; }
    }
    catch (...) { out.Status = L"partial"; out.MembershipComplete = out.ArtifactInventoryComplete = false; out.Issue = L"store_inspection_exception"; }
    return finish();
}

std::wstring EvidenceStoreInventoryJson(const EvidenceStoreInventory& r, bool includeArtifacts)
{
    std::wstring collections = L"[", artifacts = L"[";
    uint64_t emitted = 0;
    for (const auto& c : r.Collections)
    {
        if (collections.size() > 1) { collections += L","; }
        collections += StoreCollectionJson(c);
    }
    if (includeArtifacts)
    {
        for (const auto& a : r.Artifacts)
        {
            const auto row = StoreArtifactJson(a);
            // At most 16 Mi UTF-16 code units in this optional detail page.
            // The full canonical artifact digest and aggregate counts remain available.
            if (row.size() + artifacts.size() > 16 * 1024 * 1024) { break; }
            if (artifacts.size() > 1) { artifacts += L","; }
            artifacts += row; ++emitted;
        }
    }
    return L"{\"schema\":\"kn.evidence_store_inventory.v1\",\"status\":" + mcpjson::Quote(r.Status) +
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"scope\":\"image_collection_namespace\","
        L"\"coordination\":\"participating_publishers\",\"retention_policy\":\"kn.retain_committed_and_unresolved.v1\","
        L"\"catalog_sha256\":" + mcpjson::Quote(r.CatalogSha256) + L",\"artifacts_sha256\":" + mcpjson::Quote(r.ArtifactsSha256) +
        L",\"started_tick\":" + N(r.StartedTick) + L",\"ended_tick\":" + N(r.EndedTick) +
        L",\"catalog_complete\":" + B(r.CatalogComplete) + L",\"membership_complete\":" + B(r.MembershipComplete) +
        L",\"artifact_inventory_complete\":" + B(r.ArtifactInventoryComplete) +
        L",\"collections_observed\":" + N(r.CollectionsObserved) + L",\"closed_collections\":" + N(r.ClosedCollections) +
        L",\"open_collections\":" + N(r.OpenCollections) + L",\"unresolved_collections\":" + N(r.UnresolvedCollections) +
        L",\"committed_segments\":" + N(r.CommittedSegments) + L",\"member_references\":" + N(r.MemberReferences) +
        L",\"collection_path_references\":" + N(r.CollectionPathReferences) + L",\"logical_reference_bytes\":" + N(r.LogicalReferenceBytes) +
        L",\"collection_path_bytes\":" + N(r.CollectionPathBytes) + L",\"unique_path_bytes\":" + N(r.UniquePathBytes) +
        L",\"unique_content_bytes\":" + N(r.UniqueContentBytes) + L",\"observed_artifact_files\":" + N(r.ObservedArtifactFiles) +
        L",\"unverified_artifact_files\":" + N(r.UnverifiedArtifactFiles) + L",\"unmanaged_entries\":" + N(r.UnmanagedEntries) +
        L",\"unattributed_files\":" + N(r.UnattributedFiles) + L",\"verified_unattributed_bytes\":" + N(r.UnattributedBytes) +
        L",\"read_bytes\":" + N(r.ReadBytes) + L",\"artifacts_included\":" + B(includeArtifacts) +
        L",\"artifact_rows_total\":" + N(r.Artifacts.size()) + L",\"artifact_rows_emitted\":" + N(emitted) +
        L",\"artifact_rows_omitted\":" + N(r.Artifacts.size() - emitted) +
        L",\"collections\":" + collections + L"],\"artifacts\":" + artifacts +
        L"],\"deletion_authorized\":false,\"disk_allocation_established\":false,\"target_coverage_established\":false,"
        L"\"collector_authenticated\":false,\"power_loss_durability_established\":false}";
}
