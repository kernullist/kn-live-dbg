#include "EvidenceStoreFiles.h"
#include "EvidenceStore.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "ImageApprovalCollection.h"
#include "ImageCaptureCollection.h"
#include "ImageScopeApprovalCollection.h"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace store_files
{
    namespace fs = std::filesystem;
    using bounded_observation_json::N;
    using mcpjson::Quote;
    using store_catalog::Handle;

    bool ReservedRootName(const std::wstring& name)
    {
        const auto ext = fs::path(name).extension().wstring();
        return name.rfind(L"irp-", 0) == 0 || ext == L".knirp" || ext == L".knirpledger";
    }

    Format FileFormat(const std::wstring& folder, const std::wstring& ext)
    {
        if ((folder.empty() || folder == L"image-references") && ext == L".knblob") { return {MaxBlobBytes, true}; }
        if (folder.empty() && ext == L".knirp") { return {MaxIrpBytes}; }
        if (folder == L"image-captures" && (ext == L".kncapture" || ext == L".knsource")) { return {DirectImageCaptureMaxBytes}; }
        if (folder == L"image-approvals")
        {
            if (ext == L".knscopeapproval") { return {ImageScopeApprovalPublicationMaxBytes}; }
            if (ext == L".knapprovalcase") { return {ImageApprovalPublicationMaxBytes}; }
            if (ext == L".knapproval" || ext == L".knchange") { return {ImageApprovalInputMaxBytes}; }
            if (ext == L".knapprovalledger" || ext == L".knscopeledger") { return {MaxJsonBytes}; }
        }
        if ((folder.empty() && ext == L".knirpledger") || (folder == L"image-captures" && (ext == L".kncaptureledger" || ext == L".knsourceledger")) ||
            (folder == L"image-reads" && (ext == L".knreads" || ext == L".knslice" || ext == L".knreadledger")) ||
            (folder == L"image-sweeps" && ext == L".knsweep") || (folder == L"image-scope-inputs" && ext == L".knscopeblob"))
            { return {MaxJsonBytes}; }
        return {};
    }

    namespace
    {
        bool Timely(uint64_t started) { return GetTickCount64() - started <= DeadlineMs; }
        std::wstring Hash(const std::wstring& text)
        {
            auto digest = store_catalog::Hash(text);
            if (!store_catalog::IsDigest(digest)) { throw std::runtime_error("store file hash failed"); }
            return digest;
        }
        bool Describe(HANDLE file, std::wstring& stamp, uint64_t& size, DWORD& attributes)
        {
            FILE_BASIC_INFO basic{};
            FILE_STANDARD_INFO standard{};
            const auto id = store_catalog::Identity(file, false);
            if (id.empty() || !GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) ||
                !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) || standard.EndOfFile.QuadPart < 0) { return false; }
            size = uint64_t(standard.EndOfFile.QuadPart);
            attributes = basic.FileAttributes;
            stamp = id + L":" + std::to_wstring(basic.LastWriteTime.QuadPart) + L":" + std::to_wstring(basic.ChangeTime.QuadPart) + L":" + std::to_wstring(size);
            return true;
        }

        struct Position
        {
            size_t Index = 0;
            uint64_t Offset = 0;
            std::wstring Rows, Chunks = L"-";
        };
        std::wstring FirstRow(const Snapshot& snapshot) { return Hash(L"kn.store_file_rows.v1|" + snapshot.Digest); }
        std::wstring CloseRow(const std::wstring& previous, const Entry& entry, const std::wstring& chunks)
        {
            return Hash(previous + L"|" + Quote(entry.Path) + L"|" + std::to_wstring(entry.Size) + L"|" +
                (entry.Gap.empty() ? chunks : L"gap:" + entry.Gap));
        }
        std::wstring Token(const Snapshot& snapshot, const Position& p, bool final)
        {
            const auto body = (final ? L"knfr1." : L"knfs1.") + std::to_wstring(p.Index) + L"." + std::to_wstring(p.Offset) +
                L"." + p.Rows + L"." + p.Chunks + L".";
            return body + Hash(L"kn.store_file_position.v1|" + snapshot.Digest + L"|" + body);
        }
        bool Number(const std::wstring& text, uint64_t& result)
        {
            if (text.empty() || text.size() > 10 || text.find_first_not_of(L"0123456789") != std::wstring::npos) { return false; }
            result = std::stoull(text);
            return std::to_wstring(result) == text;
        }
        bool Parse(const Snapshot& snapshot, const std::wstring& token, bool final, Position& p)
        {
            if (token.size() > 234 || token.rfind(final ? L"knfr1." : L"knfs1.", 0) != 0) { return false; }
            std::array<std::wstring, 4> fields;
            size_t start = 6;
            for (auto& field : fields)
            {
                const auto dot = token.find(L'.', start);
                if (dot == std::wstring::npos) { return false; }
                field = token.substr(start, dot - start);
                start = dot + 1;
            }
            uint64_t index = 0;
            if (!Number(fields[0], index) || !Number(fields[1], p.Offset) || !store_catalog::IsDigest(fields[2]) ||
                (p.Offset ? !store_catalog::IsDigest(fields[3]) : fields[3] != L"-") ||
                (final ? (index != snapshot.Entries.size() || p.Offset) : (index >= snapshot.Entries.size() || (!index && !p.Offset)))) { return false; }
            p.Index = static_cast<size_t>(index);
            if (p.Offset && (p.Offset % BlockBytes || p.Offset >= snapshot.Entries[p.Index].Size || !snapshot.Entries[p.Index].Gap.empty())) { return false; }
            p.Rows = std::move(fields[2]);
            p.Chunks = std::move(fields[3]);
            return token == Token(snapshot, p, final);
        }
    }

    bool Snapshot::Open(const fs::path& nativeRoot, uint64_t started, std::wstring& issue)
    {
        Directories.clear();
        Entries.clear();
        Digest.clear();
        const auto fail = [&](const wchar_t* why) { issue = why; return false; };
        ContentHash scope;
        const auto feed = [&](const std::wstring& text)
        {
            const auto utf8 = mcpjson::WideToUtf8(text);
            if (!scope.Add(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.size())) { throw std::runtime_error("store file namespace hash failed"); }
        };
        feed(L"kn.store_file_namespace.v1");
        for (const std::wstring folder : Folders)
        {
            const auto path = folder.empty() ? nativeRoot : nativeRoot / folder;
            auto dir = store_catalog::OpenAttributes(path, FILE_SHARE_READ | FILE_SHARE_WRITE);
            if (!dir)
            {
                const auto error = GetLastError();
                if (folder.empty() || (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)) { return fail(L"store_file_directory_unavailable"); }
                feed(L"|" + Quote(folder) + L"|absent");
                continue;
            }
            const auto id = store_catalog::Identity(dir.get(), true);
            if (id.empty()) { return fail(L"store_file_directory_unavailable"); }
            feed(L"|" + Quote(folder) + L"|" + id);
            Directories.push_back(std::move(dir));
            std::error_code ec;
            size_t rootEntries = 0;
            for (fs::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec))
            {
                if (!Timely(started) || (folder.empty() && ++rootEntries > MaxEntries)) { return fail(L"store_file_namespace_budget_exhausted"); }
                const auto name = it->path().filename().wstring();
                auto lower = name;
                for (auto& ch : lower) { if (ch >= L'A' && ch <= L'Z') { ch += L'a' - L'A'; } }
                if (folder.empty() && !ReservedRootName(lower)) { continue; }
                if (Entries.size() == MaxEntries) { return fail(L"store_file_namespace_budget_exhausted"); }
                if (!bounded_observation_json::Text(name, 255) || name.find_first_of(L":/\\") != std::wstring::npos)
                    { return fail(L"store_file_invalid_name"); }
                auto handle = store_catalog::OpenAttributes(it->path(), FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
                Entry e;
                DWORD attributes = 0;
                if (!Describe(handle.get(), e.Stamp, e.Size, attributes)) { return fail(L"store_file_identity_unavailable"); }
                e.Path = folder.empty() ? lower : folder + L"/" + lower;
                e.ExactPath = folder.empty() ? name : folder + L"/" + name;
                const auto format = FileFormat(folder, fs::path(lower).extension().wstring());
                if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) { e.Gap = L"nonregular_entry"; }
                else if (!format.Maximum) { e.Gap = L"unmanaged_format"; }
                else if (!e.Size || e.Size > format.Maximum) { e.Gap = L"file_size_outside_format"; }
                Entries.push_back(std::move(e));
            }
            if (ec) { return fail(L"store_file_enumeration_failed"); }
        }
        std::sort(Entries.begin(), Entries.end(), [](const Entry& a, const Entry& b) { return a.Path < b.Path; });
        for (size_t i = 0; i < Entries.size(); ++i)
        {
            const auto& e = Entries[i];
            if (i && Entries[i - 1].Path == e.Path) { return fail(L"store_file_name_collision"); }
            feed(L"|" + Quote(e.ExactPath) + L"|" + e.Stamp);
        }
        Digest = scope.Finish();
        return (store_catalog::IsDigest(Digest) && Timely(started)) || fail(L"store_file_namespace_unavailable");
    }

    Entry* Snapshot::Match(const std::wstring& path, HANDLE file)
    {
        const auto it = std::lower_bound(Entries.begin(), Entries.end(), path, [](const Entry& e, const std::wstring& key) { return e.Path < key; });
        std::wstring stamp;
        uint64_t size = 0;
        DWORD attributes = 0;
        if (it == Entries.end() || it->Path != path || !it->Gap.empty() || !Describe(file, stamp, size, attributes) || stamp != it->Stamp) { return nullptr; }
        return &*it;
    }

    bool Snapshot::Accepts(const std::wstring& receipt) const
    {
        Position p;
        return Parse(*this, receipt, true, p);
    }

    bool Snapshot::Verified(const std::wstring& receipt) const
    {
        Position p;
        p.Rows = FirstRow(*this);
        for (const auto& entry : Entries)
        {
            if (entry.Gap.empty() && !store_catalog::IsDigest(entry.ObservedChunks)) { return false; }
            p.Rows = CloseRow(p.Rows, entry, entry.ObservedChunks);
        }
        p.Index = Entries.size();
        return Token(*this, p, true) == receipt;
    }

    std::wstring StartChunks(uint64_t size) { return Hash(L"kn.store_file_chunks.v1|" + std::to_wstring(size)); }

    bool AppendChunk(std::wstring& chain, uint64_t offset, const uint8_t* bytes, DWORD count, std::wstring* digest)
    {
        ContentHash block;
        if (!block.Add(bytes, count)) { return false; }
        auto value = block.Finish();
        if (!store_catalog::IsDigest(value)) { return false; }
        chain = Hash(chain + L"|" + std::to_wstring(offset) + L"|" + std::to_wstring(count) + L"|" + value);
        if (digest) { *digest = std::move(value); }
        return true;
    }

    std::wstring Scan(const std::wstring& root, const EvidenceStorePageOptions& page, bool* ready,
        const std::function<void(const wchar_t*)>& observer)
    {
        if (ready) { *ready = false; }
        const auto started = GetTickCount64();
        uint64_t bytes = 0;
        const auto report = [&](const wchar_t* status, const std::wstring& issue, const std::wstring& scope, size_t entries,
            const std::wstring& ranges, const std::wstring& next, const std::wstring& receipt)
        {
            return L"{\"schema\":\"kn.store_file_scan.v1\",\"status\":" + Quote(status) + L",\"issue\":" + Quote(issue) +
                L",\"file_namespace_sha256\":" + Quote(scope) + L",\"namespace_entries\":" + (scope.empty() ? L"null" : N(entries)) +
                L",\"block_bytes\":" + N(BlockBytes) + L",\"read_bytes\":" + N(bytes) + L",\"ranges\":" + ranges +
                L",\"next_file_cursor\":" + Quote(next) + L",\"file_receipt\":" + Quote(receipt) +
                L",\"global_membership_established\":false,\"deletion_authorized\":false,\"collector_authenticated\":false}";
        };
        const auto fail = [&](const std::wstring& issue) { return report(L"unavailable", issue, L"", 0, L"[]", L"", L""); };
        const auto& cursor = page.Cursor;
        const auto limit = page.Limit;
        if (page.ScanCatalog || page.Artifacts || page.Retention || !page.ScanReceipt.empty() || !page.FileReceipt.empty() || limit > MaxWindow || cursor.size() > 234) { return fail(L"invalid_store_file_options"); }
        try
        {
            EvidenceStoreLease lease;
            std::wstring issue;
            if (!lease.Acquire(root, true, &issue)) { return fail(issue); }
            const fs::path native = store_catalog::NativePath(fs::absolute(root).lexically_normal());
            Snapshot snapshot;
            if (!snapshot.Open(native, started, issue)) { return fail(issue); }
            Position p;
            p.Rows = FirstRow(snapshot);
            if (!cursor.empty() && !Parse(snapshot, cursor, false, p)) { return fail(L"store_file_cursor_mismatch"); }
            Handle file{nullptr, &CloseHandle};
            std::array<uint8_t, BlockBytes> buffer;
            std::wstring rows = L"[";
            const size_t units = static_cast<size_t>(limit ? limit : 64);
            for (size_t i = 0; i < units && p.Index < snapshot.Entries.size(); ++i)
            {
                const auto& e = snapshot.Entries[p.Index];
                if (!Timely(started)) { return fail(L"deadline_exhausted"); }
                if (i) { rows += L","; }
                rows += L"{\"path\":" + Quote(e.Path) + L",\"file_offset\":" + N(p.Offset);
                if (e.Gap.empty())
                {
                    if (!file)
                    {
                        auto path = native / fs::path(e.ExactPath).make_preferred();
                        auto raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                        if (raw == INVALID_HANDLE_VALUE) { return fail(L"store_file_read_unavailable"); }
                        file.reset(raw);
                        LARGE_INTEGER offset{};
                        offset.QuadPart = p.Offset;
                        if (!snapshot.Match(e.Path, file.get()) || !SetFilePointerEx(file.get(), offset, nullptr, FILE_BEGIN))
                            { return fail(L"store_file_identity_or_seek_failed"); }
                    }
                    if (!p.Offset) { p.Chunks = StartChunks(e.Size); }
                    const auto count = DWORD((std::min)(uint64_t(BlockBytes), e.Size - p.Offset));
                    DWORD received = 0;
                    const bool read = ReadFile(file.get(), buffer.data(), count, &received, nullptr) != FALSE;
                    bytes += received;
                    if (!read || count != received) { return fail(L"store_file_read_failed"); }
                    std::wstring digest;
                    if (!AppendChunk(p.Chunks, p.Offset, buffer.data(), count, &digest)) { return fail(L"store_file_hash_failed"); }
                    rows += L",\"bytes\":" + N(count) + L",\"block_sha256\":" + Quote(digest) + L",\"issue\":\"\"}";
                    p.Offset += count;
                    if (observer) { observer(L"file_block_read"); }
                    if (p.Offset < e.Size) { continue; }
                }
                else { rows += L",\"bytes\":\"0\",\"block_sha256\":\"\",\"issue\":" + Quote(e.Gap) + L"}"; }
                p.Rows = CloseRow(p.Rows, e, p.Chunks);
                ++p.Index;
                p.Offset = 0;
                p.Chunks = L"-";
                file.reset();
            }
            Snapshot after;
            if (!after.Open(native, started, issue)) { return fail(issue); }
            if (after.Digest != snapshot.Digest) { return fail(L"store_file_namespace_changed"); }
            const bool final = p.Index == snapshot.Entries.size();
            const auto token = Token(snapshot, p, final);
            auto json = report(final ? L"complete" : L"more", L"", snapshot.Digest, snapshot.Entries.size(), rows + L"]",
                final ? L"" : token, final ? token : L"");
            if (ready) { *ready = true; }
            return json;
        }
        catch (...) { return fail(L"store_file_scan_exception"); }
    }
}
