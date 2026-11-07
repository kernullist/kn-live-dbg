#include "EvidenceJournal.h"
#include "EvidenceStore.h"
#include "EvidenceRetention.h"
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
    constexpr uint64_t MaxIrpBytes = 16 * 1024 * 1024;
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
    std::wstring SessionJson(const std::wstring& id, bool typed = false)
    {
        return Envelope(L"kn.evidence_session.v1", L"{\"collection_id\":" + mcpjson::Quote(id) +
            L",\"policy\":" + mcpjson::Quote(typed ? L"kn.image_irp_collection_journal.v2" : L"kn.image_collection_journal.v1") +
            L",\"hash_basis\":\"exact_file_bytes\","
            L"\"collector_authenticated\":false,\"target_coverage_established\":false}");
    }
    bool FailureLedger(const std::wstring& schema)
    {
        return schema == L"kn.image_read_session.v1" || schema == L"kn.irp_capture_session.v1";
    }
    bool IrpPath(const std::wstring& path) { return path.rfind(L"irp-", 0) == 0; }
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
        if (m.Path == L"irp-reference-" + m.Sha256 + L".knblob")
            { return m.Schema == L"raw.bytes" && m.Bytes <= MaxBlobBytes; }
        if (m.Path == L"irp-" + id + L"-" + m.Sha256 + L".knirp")
            { return Id(id) && m.Bytes <= MaxIrpBytes && (m.Schema == L"kn.irp_capture.v1" || m.Schema == L"kn.irp_capture.v2"); }
        if (m.Bytes > MaxJsonBytes) { return false; }
        if (m.Path == L"irp-session-" + id + L".knirpledger") { return Id(id) && m.Schema == L"kn.irp_capture_session.v1"; }
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
    bool Typed = false;
    std::function<bool(HANDLE)> AdmitOutput;

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
    bool Read(const fs::path& path, uint64_t maximum, Handle* owner, std::wstring* digest, uint64_t* size, std::wstring* json = nullptr,
        DWORD additionalAccess = 0)
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
        const bool irp = Typed && t.Kind == L"irp_capture", irpLedger = Typed && t.Kind == L"irp_ledger";
        if ((t.Kind != L"image_reads" && t.Kind != L"image_sweep" && t.Kind != L"closure" && !irp && !irpLedger) ||
            (irp ? !Digest(t.Id) : !Id(t.Id)) ||
            t.Members.empty() || t.Members.size() > 8192 || t.Requires.size() > 8192 ||
            t.Members.size() + t.Requires.size() > MaxReferences - References) { return Fail(L"invalid_transaction_or_reference_budget"); }
        if (SharedReferences != nullptr && t.Members.size() + t.Requires.size() > StoreMaxReferences - *SharedReferences)
            { return Fail(L"store_reference_budget_exhausted"); }
        if ((t.Kind == L"closure" && (t.Id != L"0" || t.Members.size() != 1 ||
                t.Members[0].Path != L"image-reads/session-" + Result.CollectionId + L".knreadledger")) ||
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
        std::wstring previous;
        size_t added = 0;
        bool irpRoot = false;
        for (const auto& m : t.Members)
        {
            if (!MemberValid(m, Result.CollectionId) || (!previous.empty() && m.Path <= previous)) { return Fail(L"invalid_or_duplicate_member"); }
            if ((!irp && !irpLedger && IrpPath(m.Path)) || (irpLedger && m.Schema != L"kn.irp_capture_session.v1"))
                { return Fail(L"invalid_member_kind"); }
            if (irp)
            {
                if (m.Path == L"irp-" + Result.CollectionId + L"-" + t.Id + L".knirp" && m.Sha256 == t.Id &&
                    (m.Schema == L"kn.irp_capture.v1" || m.Schema == L"kn.irp_capture.v2")) { irpRoot = true; }
                else if (m.Schema != L"raw.bytes" || m.Path != L"irp-reference-" + m.Sha256 + L".knblob")
                    { return Fail(L"invalid_irp_transaction_member"); }
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
        const auto session = SessionJson(id, Typed);
        const auto attrs = GetFileAttributesW(NativePath(manifest).c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES && create && GetLastError() == ERROR_FILE_NOT_FOUND &&
            !SaveObservationJson(NativePath(manifest), session, nullptr, AdmitOutput)) { return Fail(L"session_publication_failed"); }
        Handle lease{nullptr, &CloseHandle};
        uint64_t bytes = 0;
        std::wstring json;
        if (!Read(manifest, 4096, &lease, &Result.SessionSha256, &bytes, &json) ||
            (create ? json != session : (json != SessionJson(id) && json != SessionJson(id, true))))
            { return Fail(L"session_missing_or_invalid"); }
        Typed = json == SessionJson(id, true);
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
        Data->Typed = policy == EvidenceJournalPolicy::ImageAndIrpV2;
        Data->AdmitOutput = std::move(admitOutput);
        ok = Data->Load(root, id, true);
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
        const std::function<void(const EvidenceStoreInventory&, const fs::path&, EvidenceJournal::Impl&)>& action);
    static EvidenceGcResult Collect(const std::wstring& root, const std::wstring& policyPath,
        const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer);
};

EvidenceStoreInventory EvidenceStoreAccess::Inspect(const std::wstring& artifactRoot, const std::set<std::wstring>& deletionPaths,
    const std::function<void(const EvidenceStoreInventory&, const fs::path&, EvidenceJournal::Impl&)>& action)
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
        uint64_t rootEntries = 0;
        for (const auto& folder : {L"image-reads", L"image-references", L"image-sweeps", L""})
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
                    const auto ext = fs::path(name).extension().wstring();
                    // Only the reserved IRP root namespace belongs to this inventory.
                    // Unknown names and pending files inside it remain protected.
                    if (!IrpPath(name) && ext != L".knirp" && ext != L".knirpledger") { continue; }
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
                const bool blob = extension == L".knblob" && (std::wstring(folder) == L"image-references" || irpRoot);
                const bool json = (std::wstring(folder) == L"image-reads" &&
                    (extension == L".knreads" || extension == L".knslice" || extension == L".knreadledger")) ||
                    (std::wstring(folder) == L"image-sweeps" && extension == L".knsweep") ||
                    (irpRoot && (extension == L".knirp" || extension == L".knirpledger"));
                Handle lease{nullptr, &CloseHandle};
                std::wstring text;
                if (blob || json)
                {
                    a.Verified = reader.Read(root / relative, blob ? MaxBlobBytes : irpRoot && extension == L".knirp" ? MaxIrpBytes : MaxJsonBytes, &lease,
                        &a.Artifact.Sha256, &a.Artifact.Bytes, json ? &text : nullptr, deletionPaths.count(relative) ? DELETE : 0);
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
                    FailureLedger(a.Artifact.Schema) ? L"failure_ledger_protected" : out.MembershipComplete ?
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
        if (action) { action(out, root, reader); }
    }
    catch (...) { out.Status = L"partial"; out.MembershipComplete = out.ArtifactInventoryComplete = false; out.Issue = L"store_inspection_exception"; }
    return finish();
}

EvidenceStoreInventory InspectEvidenceStore(const std::wstring& artifactRoot)
{
    return EvidenceStoreAccess::Inspect(artifactRoot, {}, {});
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
        L",\"issue\":" + mcpjson::Quote(r.Issue) + L",\"scope\":\"image_and_irp_collection_namespace\","
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
        if (!Text(p.Reason, 512) || p.MinimumAgeSeconds > 10ull * 366 * 86400 ||
            p.ByteLimit == 0 || p.ByteLimit > GcMaxBytes || p.Members.empty() || p.Members.size() > GcMaxFiles) { return false; }
        std::wstring previous;
        uint64_t total = 0;
        for (const auto& m : p.Members)
        {
            if (!MemberValid(m, MemberCollection(m.Path)) || FailureLedger(m.Schema) ||
                (m.Schema != L"raw.bytes" && !Id(MemberCollection(m.Path))) ||
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
    return L"{\"schema\":\"kn.evidence_gc_policy.v1\",\"policy\":\"kn.gc_explicit_uncommitted.v1\",\"reason\":" +
        mcpjson::Quote(p.Reason) + L",\"minimum_age_seconds\":" + N(p.MinimumAgeSeconds) + L",\"byte_limit\":" +
        N(p.ByteLimit) + L",\"members\":" + members + L"]}";
}

bool ParseEvidenceGcPolicy(const std::wstring& json, EvidenceGcPolicy* policy)
{
    EvidenceGcPolicy p;
    std::vector<std::wstring> members;
    if (policy == nullptr || json.size() > GcMaxPolicyBytes || !mcpjson::ValidateDocument(json) ||
        !mcpjson::GetString(json, L"reason", &p.Reason) || !Number(json, L"minimum_age_seconds", &p.MinimumAgeSeconds) ||
        !Number(json, L"byte_limit", &p.ByteLimit) || !Array(json, L"members", GcMaxFiles, &members)) { return false; }
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
    const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer)
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
                    else if (!found->Verified || found->Retention != L"uncommitted_requires_policy" || found->JournalReferences != 0)
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
        });
        if (!called) { result.Issue = inventory.Issue.empty() ? L"gc_inventory_unavailable" : inventory.Issue; }
    }
    catch (...) { result.Status = L"incomplete"; result.Issue = L"gc_inspection_exception"; }
    return result;
}

EvidenceGcResult CollectEvidenceStore(const std::wstring& root, const std::wstring& policyPath,
    const std::wstring& operationId, const std::function<void(const wchar_t*)>& observer)
{
    return EvidenceStoreAccess::Collect(root, policyPath, operationId, observer);
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
        L"],\"scope\":\"explicit_uncommitted_image_and_irp_artifacts\",\"coordination\":\"participating_publishers\","
        L"\"receipt_scope\":\"operation_history\",\"current_path_absence_established\":false,\"uncommitted_dependents_resolved\":false,"
        L"\"deletion_authority_after_return\":false,\"disk_reclamation_established\":false,\"collector_authenticated\":false,"
        L"\"power_loss_durability_established\":false}";
}
