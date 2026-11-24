#include "EvidenceInventory.h"
#include "EvidenceInventoryClosure.h"
#include "EvidenceInventoryFiles.h"
#include "EvidenceInventoryVerification.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <filesystem>
#include <set>

namespace
{
    constexpr size_t ChunkEntries = EvidenceInventoryChunkEntries;
    constexpr size_t MaximumChunks = EvidenceInventoryMaxChunks;
    constexpr size_t ChunkBytes = 256 * 1024;
    constexpr size_t ManifestBytes = 2 * 1024 * 1024;

    struct Entry
    {
        std::wstring Name;
        std::wstring Digest;
        uint64_t Bytes = 0;
        bool Valid = false;
    };
    struct Chunk
    {
        std::wstring Digest;
        uint64_t Entries = 0;
    };
    struct Manifest
    {
        std::wstring DirectoryId;
        uint64_t Entries = 0;
        std::vector<Chunk> Chunks;
    };

    // Cache parsing only. Every pathname is opened and its bytes read again.
    class BundleReader
    {
    public:
        bool Read(const std::wstring& path, EvidenceBundle* bundle, std::wstring* digest,
            size_t maximumBytes, size_t* read, std::wstring* byteDigest = nullptr)
        {
            *bundle = {};
            digest->clear();
            std::wstring json, error;
            if (!ReadAnalystSnapshot(path, &json, &error,
                (std::min)(maximumBytes, EvidenceBundleMaxJsonBytes), read, true, byteDigest))
            {
                return false;
            }
            if (Digest.empty() || json != Json)
            {
                EvidenceBundle parsed;
                std::wstring parsedDigest;
                if (!ParseEvidenceBundle(json, &parsed, &error) ||
                    !mcpjson::GetString(json, L"payload_sha256", &parsedDigest))
                {
                    return false;
                }
                Json = std::move(json);
                CanonicalBytes = 0;
                Digest = std::move(parsedDigest);
                Bundle = std::move(parsed);
            }
            *bundle = Bundle;
            *digest = Digest;
            return true;
        }

        size_t CanonicalSize()
        {
            // ParseEvidenceBundle already required this exact historical serialization. The writer accounts for UTF-8 without a BOM.
            if (!CanonicalBytes) { CanonicalBytes = mcpjson::WideToUtf8(Json).size(); }
            return CanonicalBytes;
        }

    private:
        std::wstring Json;
        std::wstring Digest;
        EvidenceBundle Bundle;
        size_t CanonicalBytes = 0;
    };

    bool DirectoryPathValid(const std::wstring& path)
    {
        return !path.empty() && path.size() <= 30000 && path.find(L'\0') == std::wstring::npos &&
            mcpjson::SanitizeUtf16(path) == path && path.rfind(L"\\\\.\\", 0) != 0 &&
            path.rfind(L"\\\\?\\GLOBALROOT", 0) != 0;
    }

    std::wstring Hash(const std::wstring& value)
    {
        const auto utf8 = mcpjson::WideToUtf8(value);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.size()) ? hash.Finish() : L"";
    }

    std::wstring Number(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }

    struct Publication
    {
        std::wstring CaseCollection;
        EvidenceSessionSummary Ledger;
    };

    Entry ReadEntry(const std::filesystem::path& path, BundleReader& reader, std::wstring* byteDigest = nullptr,
        Publication* publication = nullptr, size_t maximumBytes = EvidenceBundleMaxJsonBytes)
    {
        Entry entry;
        entry.Name = path.filename().wstring();
        size_t read = 0;
        if (path.extension() == L".kncase")
        {
            EvidenceBundle bundle;
            entry.Valid = reader.Read(path.wstring(), &bundle, &entry.Digest, maximumBytes, &read, byteDigest);
            if (entry.Valid && publication) { publication->CaseCollection = std::move(bundle.CollectionId); }
        }
        else
        {
            std::wstring json, error;
            EvidenceSessionSummary session;
            if (ReadAnalystSnapshot(path.wstring(), &json, &error, (std::min<size_t>)(32768, maximumBytes),
                &read, true, byteDigest) && ParseEvidenceSession(json, &session))
            {
                entry.Digest = Hash(json);
                entry.Valid = entry.Digest.size() == 64;
                if (entry.Valid && publication) { publication->Ledger = std::move(session); }
            }
        }
        entry.Bytes = read;
        if (!entry.Valid) { entry.Digest.clear(); }
        return entry;
    }

    bool ParseNumber(const std::wstring& json, const wchar_t* name, uint64_t* value)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, name, &text))
        {
            return false;
        }
        text += L":";
        size_t at = 0;
        return KmonHuntCursorNumber(text, &at, value) && at == text.size();
    }

    bool Array(const std::wstring& json, const wchar_t* name, size_t maximum, std::vector<std::wstring>* rows)
    {
        std::wstring raw;
        rows->clear();
        if (!mcpjson::FindRawValue(json, name, &raw) || raw.size() < 2 || raw.front() != L'[' || raw.back() != L']')
        {
            return false;
        }
        size_t at = 1;
        while (at < raw.size() - 1)
        {
            size_t end = 0;
            if (rows->size() >= maximum || !mcpjson::ScanValue(raw, at, &end))
            {
                return false;
            }
            rows->push_back(raw.substr(at, end - at));
            at = end;
            if (at < raw.size() - 1 && raw[at++] != L',')
            {
                return false;
            }
        }
        return at == raw.size() - 1;
    }

    bool NameValid(const std::wstring& name)
    {
        if (name.empty() || name.size() > 255 || name.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos ||
            mcpjson::SanitizeUtf16(name) != name)
        {
            return false;
        }
        for (const wchar_t c : name)
        {
            if (c < 32)
            {
                return false;
            }
        }
        const auto extension = std::filesystem::path(name).extension();
        return extension == L".kncase" || extension == L".knledger";
    }

    std::wstring DirectoryId(const std::wstring& path)
    {
        std::wstring id;
        if (!DirectoryPathValid(path))
        {
            return id;
        }
        HANDLE directory = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (directory == INVALID_HANDLE_VALUE)
        {
            return id;
        }
        FILE_ID_INFO identity{};
        BY_HANDLE_FILE_INFORMATION information{};
        if (GetFileInformationByHandle(directory, &information) &&
            (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            GetFileInformationByHandleEx(directory, FileIdInfo, &identity, sizeof(identity)))
        {
            id = std::to_wstring(identity.VolumeSerialNumber) + L":";
            for (const auto byte : identity.FileId.Identifier)
            {
                id += L"0123456789abcdef"[byte >> 4];
                id += L"0123456789abcdef"[byte & 15];
            }
        }
        CloseHandle(directory);
        return id;
    }

    std::wstring ChunkJson(const std::vector<Entry>& entries)
    {
        std::wstring json = L"{\"schema\":\"kn.evidence_inventory_chunk.v1\",\"entries\":[";
        for (const auto& entry : entries)
        {
            if (&entry != &entries.front())
            {
                json += L",";
            }
            json += L"{\"name\":" + mcpjson::Quote(entry.Name) + L",\"digest\":" + mcpjson::Quote(entry.Digest) +
                L",\"bytes\":" + Number(entry.Bytes) + L",\"valid\":" + (entry.Valid ? L"true" : L"false") + L"}";
        }
        return json + L"]}";
    }

    std::wstring ManifestJson(const Manifest& manifest)
    {
        std::wstring json = L"{\"schema\":\"kn.evidence_inventory.v1\",\"capture\":\"non_atomic_directory_walk\",\"directory_id\":" +
            mcpjson::Quote(manifest.DirectoryId) + L",\"entries\":" + Number(manifest.Entries) + L",\"chunks\":[";
        for (const auto& chunk : manifest.Chunks)
        {
            if (&chunk != &manifest.Chunks.front())
            {
                json += L",";
            }
            json += L"{\"digest\":" + mcpjson::Quote(chunk.Digest) + L",\"entries\":" + Number(chunk.Entries) + L"}";
        }
        return json + L"]}";
    }

    bool ReadManifest(const std::wstring& directory, Manifest* manifest, std::wstring* digest)
    {
        std::wstring json, error;
        std::vector<std::wstring> rows;
        if (DirectoryId(directory).empty() || !ReadAnalystSnapshot((std::filesystem::path(directory) / L"manifest.knindex").wstring(),
            &json, &error, ManifestBytes, nullptr, true) || !mcpjson::ValidateDocument(json) ||
            !mcpjson::GetString(json, L"directory_id", &manifest->DirectoryId) || manifest->DirectoryId.empty() ||
            manifest->DirectoryId.size() > 64 || !ParseNumber(json, L"entries", &manifest->Entries) ||
            manifest->Entries > ChunkEntries * MaximumChunks || !Array(json, L"chunks", MaximumChunks, &rows))
        {
            return false;
        }
        uint64_t count = 0;
        for (const auto& row : rows)
        {
            Chunk chunk;
            if (!mcpjson::GetString(row, L"digest", &chunk.Digest) || !KmonHuntHash(chunk.Digest) ||
                !ParseNumber(row, L"entries", &chunk.Entries) || chunk.Entries == 0 || chunk.Entries > ChunkEntries ||
                (&row != &rows.back() && chunk.Entries != ChunkEntries))
            {
                return false;
            }
            count += chunk.Entries;
            manifest->Chunks.push_back(std::move(chunk));
        }
        *digest = Hash(json);
        return count == manifest->Entries && digest->size() == 64 && ManifestJson(*manifest) == json;
    }

    bool ReadChunk(const std::wstring& directory, const Chunk& chunk, std::vector<Entry>* entries, bool exactBytes = false)
    {
        entries->clear();
        std::wstring json, error, bytesDigest;
        std::vector<std::wstring> rows;
        if (!ReadAnalystSnapshot((std::filesystem::path(directory) / (chunk.Digest + L".knchunk")).wstring(),
            &json, &error, ChunkBytes, nullptr, true, exactBytes ? &bytesDigest : nullptr) ||
            (exactBytes && bytesDigest != chunk.Digest) || Hash(json) != chunk.Digest || !mcpjson::ValidateDocument(json) ||
            !Array(json, L"entries", ChunkEntries, &rows) || rows.size() != chunk.Entries)
        {
            return false;
        }
        for (const auto& row : rows)
        {
            Entry entry;
            std::wstring valid;
            if (!mcpjson::GetString(row, L"name", &entry.Name) || !NameValid(entry.Name) ||
                !mcpjson::GetString(row, L"digest", &entry.Digest) || !ParseNumber(row, L"bytes", &entry.Bytes) ||
                entry.Bytes > EvidenceBundleMaxJsonBytes || !mcpjson::FindRawValue(row, L"valid", &valid) ||
                (valid != L"true" && valid != L"false"))
            {
                return false;
            }
            entry.Valid = valid == L"true";
            if (entry.Valid ? (entry.Bytes == 0 || !KmonHuntHash(entry.Digest)) : !entry.Digest.empty())
            {
                return false;
            }
            entries->push_back(std::move(entry));
        }
        return ChunkJson(*entries) == json;
    }

    bool IsNamedOriginal(HANDLE file, const std::filesystem::path& path, const Entry& entry)
    {
        FILE_STANDARD_INFO standard{};
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!file || GetFileType(file) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) ||
            (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
            !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) ||
            standard.EndOfFile.QuadPart != static_cast<LONGLONG>(entry.Bytes)) { return false; }
        // A case alias or DOS short name does not establish a second directory entry.
        WIN32_FIND_DATAW found{};
        const auto search = FindFirstFileW((L"\\\\?\\" + path.native()).c_str(), &found);
        if (search == INVALID_HANDLE_VALUE) { return false; }
        FindClose(search);
        return entry.Name == found.cFileName;
    }

    class ResumableInventory
    {
    public:
        explicit ResumableInventory(const EvidenceInventoryBuildOptions& options) : Options(options)
        {
            Result.Resume = true;
            Result.VerifyEntryLimit = options.VerifyEntryLimit;
        }

        EvidenceInventoryBuildResult Run(const std::wstring& directory, const std::wstring& destination)
        {
            if (!inventory_files::LocalPath(directory, Source) || !inventory_files::LocalPath(destination, Output) ||
                Output == Output.root_path() || !Pins.Ancestors(Source) || !Pins.Ancestors(Output.parent_path()))
            {
                Fail(L"invalid_path");
                return Result;
            }
            Index.DirectoryId = DirectoryId(Source.wstring());
            std::wstring catalog;
            if (Index.DirectoryId.empty() || !Catalog(Names, catalog, Options.VerifyEntryLimit ? &Generations : nullptr))
            { return Result; }
            const auto extension = Output.extension();
            if ((extension == L".kncase" || extension == L".knledger") &&
                DirectoryId(Output.parent_path().wstring()) == Index.DirectoryId) { Fail(L"invalid_path"); return Result; }
            const bool created = CreateDirectoryW(Output.c_str(), nullptr) != FALSE;
            if (!created && GetLastError() != ERROR_ALREADY_EXISTS) { return Result; }
            if (!Pins.Directory(Output))
            {
                Fail(L"output_busy_or_unavailable");
                return Result;
            }
            const auto outputId = DirectoryId(Output.wstring());
            if (outputId.empty() || outputId == Index.DirectoryId) { Fail(L"invalid_path"); return Result; }
            const auto header = L"{\"schema\":\"kn.evidence_inventory_work.v1\",\"source_id\":" +
                mcpjson::Quote(Index.DirectoryId) + L",\"output_id\":" + mcpjson::Quote(outputId) +
                L",\"catalog_sha256\":" + mcpjson::Quote(catalog) + L",\"entries\":" + Number(Names.size()) + L"}";
            const auto marker = Output / L"build.knindex";
            const auto writer = Output / L"writer.knindex";
            const bool needWriter = inventory_files::Missing(writer);
            if (needWriter)
            {
                if (!inventory_files::Missing(marker)) { Fail(L"invalid_checkpoint"); return Result; }
                if (!UncommittedOutput()) { return Result; }
            }
            if (!Pins.Writer(writer, needWriter)) { Fail(L"output_busy_or_unavailable"); return Result; }
            const bool initializing = inventory_files::Missing(marker);
            if (initializing && !UncommittedOutput()) { return Result; }
            if (!MatchFile(marker, header, 2048, initializing, L"resume_scope_mismatch")) { return Result; }

            const auto manifest = Output / L"manifest.knindex";
            const bool finalExists = !inventory_files::Missing(manifest);
            auto previous = Hash(header);
            if (previous.empty()) { return Result; }
            size_t added = 0;
            for (size_t offset = 0; offset < Names.size(); offset += ChunkEntries)
            {
                if (!Running()) { return Result; }
                const auto count = (std::min)(ChunkEntries, Names.size() - offset);
                const auto checkpoint = Output / (L"window-" + std::to_wstring(offset) + L".knindex");
                std::vector<Entry> rows;
                std::wstring originals, document, digest;
                if (inventory_files::Missing(checkpoint))
                {
                    if (finalExists) { Fail(L"invalid_checkpoint"); return Result; }
                    if (added == Options.NewChunkLimit) { break; }
                    if (!OriginalWindow(offset, count, rows, originals)) { return Result; }
                    const auto data = ChunkJson(rows);
                    digest = Hash(data);
                    if (digest.empty() || !MatchFile(Output / (digest + L".knchunk"), data, ChunkBytes, true,
                        L"corrupt_inventory_chunk")) { return Result; }
                    document = Record(previous, offset, count, digest, originals);
                    if (!MatchFile(checkpoint, document, 2048, true, L"invalid_checkpoint")) { return Result; }
                    ++added;
                }
                else
                {
                    if (!LoadFile(checkpoint, 2048, document) ||
                        !mcpjson::GetString(document, L"chunk_sha256", &digest) || !KmonHuntHash(digest) ||
                        !mcpjson::GetString(document, L"originals_sha256", &originals) || !KmonHuntHash(originals) ||
                        document != Record(previous, offset, count, digest, originals))
                    { Fail(L"invalid_checkpoint"); return Result; }
                    if (!Pins.ReadFile(Output / (digest + L".knchunk")) ||
                        !ReadChunk(Output.wstring(), {digest, count}, &rows, true))
                    { Fail(L"corrupt_inventory_chunk"); return Result; }
                    for (size_t i = 0; i < count; ++i)
                    {
                        if (rows[i].Name != Names[offset + i]) { Fail(L"invalid_checkpoint"); return Result; }
                    }
                    Result.ReusedEntries += count;
                }
                previous = Hash(document);
                if (previous.empty()) { return Result; }
                Index.Chunks.push_back({digest, count});
                OriginalDigests.push_back(std::move(originals));
                for (const auto& row : rows) { if (!row.Valid) { ++Result.InvalidFiles; } }
                Result.Entries += count;
            }

            if (Result.Entries == Names.size())
            {
                const bool verified = Options.VerifyEntryLimit ? VerifyBounded(previous) : VerifyOriginals();
                if (!verified) { return Result; }
            }
            std::wstring current;
            std::vector<std::wstring> currentNames;
            if (!Catalog(currentNames, current)) { return Result; }
            if (current != catalog || currentNames != Names) { Fail(L"source_changed"); return Result; }
            if (!Running()) { return Result; }
            if (Result.Entries != Names.size()) { Result.Status = L"checkpointed"; return Result; }
            Index.Entries = Result.Entries;
            const auto json = ManifestJson(Index);
            const auto digest = Hash(json);
            if (digest.empty() || !MatchFile(manifest, json, ManifestBytes, !finalExists, L"manifest_mismatch")) { return Result; }
            Result.Status = L"ok";
            Result.Digest = digest;
            return Result;
        }

    private:
        bool Fail(const wchar_t* status) { Result.Status = status; return false; }

        bool Running()
        {
            if (Options.Cancellation && Options.Cancellation->load()) { return Fail(L"cancelled"); }
            if (GetTickCount64() - Started >= Options.DeadlineMs) { return Fail(L"deadline_exhausted"); }
            return true;
        }

        bool UncommittedOutput()
        {
            // A stop during the very first atomic marker write can leave its temporary file.
            // Start at zero only in an empty directory or beside these unpublished names.
            static const std::wstring prefix = L"build.knindex.pending-";
            std::error_code error;
            std::filesystem::directory_iterator iterator(Output, error), end;
            size_t traversed = 0;
            while (!error && iterator != end)
            {
                if (!Running()) { return false; }
                const auto path = iterator->path();
                const auto name = path.filename().wstring();
                if (++traversed > Options.MaximumEntries) { return Fail(L"budget_exhausted"); }
                if (name == L"writer.knindex") { iterator.increment(error); continue; }
                if (name.compare(0, prefix.size(), prefix) != 0)
                { return Fail(L"resume_marker_missing"); }
                size_t at = prefix.size();
                for (size_t part = 0; part < 3; ++part)
                {
                    const size_t begin = at;
                    while (at < name.size() && name[at] >= L'0' && name[at] <= L'9') { ++at; }
                    if (at == begin || at - begin > 20 || (part < 2 && (at == name.size() || name[at++] != L'-')))
                    { return Fail(L"resume_marker_missing"); }
                }
                // Pending files are never inputs. Inspect one literal handle at a time.
                auto pending = inventory_files::Open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
                BY_HANDLE_FILE_INFORMATION info{};
                if (at != name.size() || !pending || GetFileType(pending.get()) != FILE_TYPE_DISK ||
                    !GetFileInformationByHandle(pending.get(), &info) ||
                    (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
                    info.nFileSizeHigh != 0 || info.nFileSizeLow > 2048)
                { return Fail(L"resume_marker_missing"); }
                iterator.increment(error);
            }
            return !error || Fail(L"resume_marker_missing");
        }

        bool Catalog(std::vector<std::wstring>& names, std::wstring& digest,
            std::vector<inventory_files::Generation>* generations = nullptr)
        {
            constexpr size_t maximumNameChars = 16 * 1024 * 1024;
            auto directory = inventory_files::Open(Source, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE);
            FILE_BASIC_INFO before{}, after{};
            if (!directory || !GetFileInformationByHandleEx(directory.get(), FileBasicInfo, &before, sizeof(before)))
            { return Fail(L"source_unavailable"); }
            std::error_code error;
            size_t traversed = 0, chars = 0;
            std::filesystem::directory_iterator iterator(Source, error), end;
            while (!error && iterator != end)
            {
                if (!Running()) { return false; }
                if (++traversed > Options.MaximumEntries) { return Fail(L"budget_exhausted"); }
                const auto leaf = iterator->path().filename();
                const auto extension = leaf.extension();
                if (extension == L".kncase" || extension == L".knledger")
                {
                    if (!NameValid(leaf.native())) { return Fail(L"unsupported_file_name"); }
                    chars += leaf.native().size();
                    if (chars > maximumNameChars) { return Fail(L"budget_exhausted"); }
                    names.push_back(leaf.native());
                }
                iterator.increment(error);
            }
            if (error) { return Fail(L"source_unavailable"); }
            std::sort(names.begin(), names.end());
            if (std::adjacent_find(names.begin(), names.end()) != names.end()) { return Fail(L"source_changed"); }
            ContentHash hash;
            if (generations) { generations->reserve(names.size()); }
            for (const auto& name : names)
            {
                if (!Running()) { return false; }
                auto file = inventory_files::Open(Source / name, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
                inventory_files::Generation generation{};
                if (!inventory_files::ReadGeneration(file.get(), generation) || !inventory_files::AddGeneration(hash, name, generation))
                { return Fail(L"source_unavailable"); }
                if (generations) { generations->push_back(generation); }
            }
            if (!GetFileInformationByHandleEx(directory.get(), FileBasicInfo, &after, sizeof(after)))
            { return Fail(L"source_unavailable"); }
            if (before.ChangeTime.QuadPart != after.ChangeTime.QuadPart || before.LastWriteTime.QuadPart != after.LastWriteTime.QuadPart)
            { return Fail(L"source_changed"); }
            digest = hash.Finish();
            return !digest.empty() && Running();
        }

        bool OriginalWindow(size_t offset, size_t count, std::vector<Entry>& rows, std::wstring& originals)
        {
            std::wstring witnesses;
            for (size_t i = 0; i < count; ++i)
            {
                if (!Running()) { return false; }
                const auto path = Source / Names[offset + i];
                const size_t maximum = path.extension() == L".knledger" ? 32768 : EvidenceBundleMaxJsonBytes;
                if (Options.ReadBudget - Result.ReadBytes < maximum) { return Fail(L"budget_exhausted"); }
                std::wstring raw;
                rows.push_back(ReadEntry(path, Reader, &raw));
                const auto bytes = rows.back().Bytes;
                Result.ReadBytes += bytes;
                if (bytes != 0 && raw.size() != 64) { return Fail(L"source_read_incomplete"); }
                witnesses += raw + L"\n";
            }
            originals = Hash(witnesses);
            return !originals.empty();
        }

        bool VerifyOriginals()
        {
            size_t offset = 0;
            for (size_t i = 0; i < Index.Chunks.size(); ++i)
            {
                const auto& chunk = Index.Chunks[i];
                std::vector<Entry> rows;
                std::wstring digest;
                if (!OriginalWindow(offset, static_cast<size_t>(chunk.Entries), rows, digest)) { return false; }
                if (digest != OriginalDigests[i] || Hash(ChunkJson(rows)) != chunk.Digest) { return Fail(L"original_mismatch"); }
                offset += rows.size();
                Result.VerifiedEntries = offset;
            }
            return true;
        }

        std::filesystem::path VerificationPath(size_t through) const
        {
            return Output / (L"verify-" + std::to_wstring(through) + L".knindex");
        }

        bool RestoreVerification(const std::wstring& chain, std::wstring& witnesses)
        {
            // Each seal attests to the entire checked prefix. Only the greatest one is needed.
            WIN32_FIND_DATAW item{};
            const auto first = FindFirstFileW((Output / L"verify-*.knindex").c_str(), &item);
            if (first == INVALID_HANDLE_VALUE)
            { return GetLastError() == ERROR_FILE_NOT_FOUND || Fail(L"verification_unavailable"); }
            const std::unique_ptr<void, decltype(&FindClose)> search(first, &FindClose);
            size_t latest = 0;
            do
            {
                if (!Running()) { return false; }
                const std::wstring name = item.cFileName;
                if (name.size() < 16 || name.size() > 22 || name.compare(0, 7, L"verify-") ||
                    name.compare(name.size() - 8, 8, L".knindex")) { return Fail(L"invalid_verification_checkpoint"); }
                const auto digits = name.substr(7, name.size() - 15);
                if (digits.front() == L'0' || digits.find_first_not_of(L"0123456789") != digits.npos ||
                    (item.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
                { return Fail(L"invalid_verification_checkpoint"); }
                const auto through = static_cast<size_t>(std::stoul(digits));
                if (through > Names.size()) { return Fail(L"invalid_verification_checkpoint"); }
                latest = (std::max)(latest, through);
            }
            while (FindNextFileW(search.get(), &item));
            if (GetLastError() != ERROR_NO_MORE_FILES) { return Fail(L"verification_unavailable"); }
            std::wstring document;
            const auto partial = latest == Names.size() ? 0 : latest % ChunkEntries;
            if (!LoadFile(VerificationPath(latest), inventory_verification::MaxReceiptBytes, document) ||
                !Verification.Open(document, chain, latest, partial, witnesses))
            { return Fail(L"invalid_verification_checkpoint"); }
            Result.VerifiedEntries = Result.ReusedVerifiedEntries = latest;
            return true;
        }

        bool CheckOriginal(size_t at, const Entry& expected, std::wstring& witnesses)
        {
            const auto path = Source / Names[at];
            auto pin = inventory_files::Open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ);
            inventory_files::Generation actual{};
            if (!inventory_files::ReadGeneration(pin.get(), actual)) { return Fail(L"source_unavailable"); }
            if (!(actual == Generations[at])) { return Fail(L"source_changed"); }
            const uint64_t limit = path.extension() == L".knledger" ? 32768 : EvidenceBundleMaxJsonBytes;
            const auto size = static_cast<uint64_t>(actual.Size);
            const bool regular = !(actual.Basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
            if (regular && size <= limit && size > Options.ReadBudget - Result.ReadBytes) { return Fail(L"budget_exhausted"); }
            std::wstring raw;
            const auto row = ReadEntry(path, Reader, &raw);
            Result.ReadBytes += row.Bytes;
            if (row.Bytes && !KmonHuntHash(raw)) { return Fail(L"source_read_incomplete"); }
            if (!inventory_files::ReadGeneration(pin.get(), actual) || !(actual == Generations[at])) { return Fail(L"source_changed"); }
            if (row.Name != expected.Name || row.Valid != expected.Valid || row.Bytes != expected.Bytes || row.Digest != expected.Digest)
            { return Fail(L"original_mismatch"); }
            witnesses += raw + L"\n";
            return true;
        }

        bool VerifyBounded(const std::wstring& chain)
        {
            std::wstring witnesses;
            if (!RestoreVerification(chain, witnesses)) { return false; }
            size_t saved = Result.VerifiedEntries;
            const auto stop = (std::min)(Names.size(), saved + Options.VerifyEntryLimit);
            const auto save = [&]()
            {
                if (saved == Result.VerifiedEntries) { return true; }
                const auto proof = Verification.Seal(chain, Result.VerifiedEntries, witnesses);
                if (proof.empty()) { return Fail(L"verification_unavailable"); }
                if (!MatchFile(VerificationPath(Result.VerifiedEntries), proof, inventory_verification::MaxReceiptBytes,
                    true, L"invalid_verification_checkpoint")) { return false; }
                saved = Result.VerifiedEntries;
                return true;
            };
            while (Result.VerifiedEntries < stop)
            {
                const auto i = Result.VerifiedEntries / ChunkEntries;
                const auto& chunk = Index.Chunks[i];
                std::vector<Entry> rows;
                if (!ReadChunk(Output.wstring(), chunk, &rows, true)) { return Fail(L"corrupt_inventory_chunk"); }
                const auto end = i * ChunkEntries + rows.size();
                while (Result.VerifiedEntries < (std::min)(end, stop))
                {
                    const auto at = Result.VerifiedEntries;
                    if (!Running() || !CheckOriginal(at, rows[at % ChunkEntries], witnesses))
                    {
                        if (Result.Status != L"budget_exhausted" && Result.Status != L"deadline_exhausted") { return false; }
                        if (!save()) { return false; }
                        if (saved > Result.ReusedVerifiedEntries || Result.Entries > Result.ReusedEntries)
                        { return Fail(L"checkpointed"); }
                        return false;
                    }
                    if (at + 1 == end)
                    {
                        if (Hash(witnesses) != OriginalDigests[i]) { return Fail(L"original_mismatch"); }
                        witnesses.clear();
                    }
                    ++Result.VerifiedEntries;
                }
                if (!save()) { return false; }
            }
            return Result.VerifiedEntries == Names.size() || Fail(L"checkpointed");
        }

        bool LoadFile(const std::filesystem::path& path, size_t limit, std::wstring& json)
        {
            std::wstring raw, error;
            return Pins.ReadFile(path) && ReadAnalystSnapshot(path.wstring(), &json, &error, limit, nullptr, true, &raw) &&
                raw.size() == 64 && Hash(json) == raw;
        }

        bool MatchFile(const std::filesystem::path& path, const std::wstring& expected, size_t limit,
            bool canCreate, const wchar_t* status)
        {
            if (canCreate && inventory_files::Missing(path))
            {
                std::wstring error;
                if (mcpjson::WideToUtf8(expected).size() > limit) { return Fail(L"budget_exhausted"); }
                if (!SaveObservationJson(path.wstring(), expected, &error)) { return Fail(L"output_unavailable"); }
            }
            std::wstring actual;
            return (LoadFile(path, limit, actual) && actual == expected) || Fail(status);
        }

        static std::wstring Record(const std::wstring& previous, size_t offset, size_t count,
            const std::wstring& chunk, const std::wstring& originals)
        {
            return L"{\"schema\":\"kn.evidence_inventory_window.v1\",\"previous_sha256\":" + mcpjson::Quote(previous) +
                L",\"offset\":" + Number(offset) + L",\"entries\":" + Number(count) + L",\"chunk_sha256\":" +
                mcpjson::Quote(chunk) + L",\"originals_sha256\":" + mcpjson::Quote(originals) + L"}";
        }

        const EvidenceInventoryBuildOptions& Options;
        const uint64_t Started = GetTickCount64();
        EvidenceInventoryBuildResult Result;
        inventory_files::Pins Pins;
        inventory_verification::Signer Verification;
        std::filesystem::path Source, Output;
        std::vector<std::wstring> Names, OriginalDigests;
        std::vector<inventory_files::Generation> Generations;
        Manifest Index;
        BundleReader Reader;
    };
}

EvidenceInventoryBuildResult BuildEvidenceInventory(const std::wstring& directory,
    const std::wstring& newSnapshotDirectory, const EvidenceInventoryBuildOptions& options)
{
    EvidenceInventoryBuildResult result;
    result.Resume = options.Resume;
    result.VerifyEntryLimit = options.VerifyEntryLimit;
    if (options.Cancellation != nullptr && options.Cancellation->load())
    {
        result.Status = L"cancelled";
        return result;
    }
    if (options.MaximumEntries == 0 || options.MaximumEntries > ChunkEntries * MaximumChunks ||
        options.ReadBudget == 0 || options.ReadBudget > 8ull * 1024 * 1024 * 1024 ||
        options.DeadlineMs == 0 || options.DeadlineMs > 120000 ||
        (options.Resume && (options.NewChunkLimit == 0 || options.NewChunkLimit > MaximumChunks)) ||
        options.VerifyEntryLimit > EvidenceInventoryMaxEntries || (!options.Resume && options.VerifyEntryLimit))
    {
        result.Status = L"invalid_budget";
        return result;
    }
    if (!DirectoryPathValid(directory) || !DirectoryPathValid(newSnapshotDirectory))
    {
        result.Status = L"invalid_path";
        return result;
    }
    if (options.Resume) { return ResumableInventory(options).Run(directory, newSnapshotDirectory); }
    Manifest manifest;
    manifest.DirectoryId = DirectoryId(directory);
    std::error_code error;
    std::filesystem::directory_iterator iterator(directory, error), end;
    if (manifest.DirectoryId.empty() || error)
    {
        return result;
    }
    if (!CreateDirectoryW(newSnapshotDirectory.c_str(), nullptr))
    {
        result.Status = L"output_exists_or_unavailable";
        return result;
    }
    const auto outputId = DirectoryId(newSnapshotDirectory);
    if (outputId.empty())
    {
        return result;
    }
    const uint64_t started = GetTickCount64();
    size_t traversed = 0;
    std::vector<Entry> entries;
    BundleReader reader;
    const auto publishChunk = [&]()
    {
        const auto json = ChunkJson(entries);
        const auto digest = Hash(json);
        std::wstring failure;
        if (digest.size() != 64 || json.size() > ChunkBytes || DirectoryId(newSnapshotDirectory) != outputId ||
            !SaveObservationJson((std::filesystem::path(newSnapshotDirectory) / (digest + L".knchunk")).wstring(), json, &failure))
        {
            return false;
        }
        manifest.Chunks.push_back({digest, entries.size()});
        entries.clear();
        return true;
    };
    while (iterator != end)
    {
        if (options.Cancellation != nullptr && options.Cancellation->load())
        {
            result.Status = L"cancelled";
            return result;
        }
        if (++traversed > options.MaximumEntries)
        {
            result.Status = L"budget_exhausted";
            return result;
        }
        if (GetTickCount64() - started >= options.DeadlineMs)
        {
            result.Status = L"deadline_exhausted";
            return result;
        }
        const auto path = iterator->path();
        const auto extension = path.extension();
        if (extension == L".kncase" || extension == L".knledger")
        {
            if (!NameValid(path.filename().wstring()))
            {
                result.Status = L"unsupported_file_name";
                return result;
            }
            if (options.ReadBudget - result.ReadBytes < EvidenceBundleMaxJsonBytes)
            {
                result.Status = L"budget_exhausted";
                return result;
            }
            auto entry = ReadEntry(path, reader);
            result.ReadBytes += entry.Bytes;
            if (!entry.Valid) { ++result.InvalidFiles; }
            entries.push_back(std::move(entry));
            ++result.Entries;
            if (entries.size() == ChunkEntries && !publishChunk())
            {
                return result;
            }
        }
        iterator.increment(error);
        if (error)
        {
            return result;
        }
    }
    if (!entries.empty() && !publishChunk())
    {
        return result;
    }
    manifest.Entries = result.Entries;
    const auto json = ManifestJson(manifest);
    result.Digest = Hash(json);
    std::wstring failure;
    if ((options.Cancellation != nullptr && options.Cancellation->load()) || GetTickCount64() - started >= options.DeadlineMs)
    {
        result.Status = options.Cancellation != nullptr && options.Cancellation->load() ? L"cancelled" : L"deadline_exhausted";
        result.Digest.clear();
        return result;
    }
    if (result.Digest.size() != 64 || DirectoryId(directory) != manifest.DirectoryId || DirectoryId(newSnapshotDirectory) != outputId ||
        !SaveObservationJson((std::filesystem::path(newSnapshotDirectory) / L"manifest.knindex").wstring(), json, &failure))
    {
        result.Digest.clear();
        return result;
    }
    result.Status = L"ok";
    return result;
}

EvidenceInventoryClosureResult InspectEvidenceInventoryClosure(const std::wstring& directory, const std::wstring& snapshot,
    const EvidenceInventoryClosureOptions& options)
{
    EvidenceInventoryClosureResult result;
    if (!options.ReadBudget || !options.DeadlineMs) { result.Status = L"invalid_budget"; return result; }
    const auto started = GetTickCount64();
    const auto running = [&]() {
        if (options.Cancellation && options.Cancellation->load()) { result.Status = L"cancelled"; return false; }
        if (GetTickCount64() - started >= options.DeadlineMs) { result.Status = L"deadline_exhausted"; return false; }
        return true;
    };
    if (!running()) { return result; }
    std::filesystem::path source, index;
    inventory_files::Pins pins;
    if (!DirectoryPathValid(directory) || !DirectoryPathValid(snapshot) || !inventory_files::LocalPath(directory, source) ||
        !inventory_files::LocalPath(snapshot, index) || !pins.Ancestors(source) || !pins.Ancestors(index))
    { result.Status = L"invalid_path"; return result; }

    const std::wstring literalIndex = L"\\\\?\\" + index.native();
    const std::wstring literalSource = L"\\\\?\\" + source.native();
    Manifest manifest;
    if (!pins.ReadFile(index / L"manifest.knindex") || !ReadManifest(literalIndex, &manifest, &result.SnapshotDigest))
    { result.SnapshotDigest.clear(); result.Status = L"invalid_inventory"; return result; }
    result.SnapshotEntries = manifest.Entries;
    if (DirectoryId(literalSource) != manifest.DirectoryId) { result.Status = L"source_directory_changed"; return result; }

    std::set<std::wstring> names;
    BundleReader reader;
    inventory_closure::Publications publications;
    std::vector<Entry> entries;
    for (const auto& chunk : manifest.Chunks)
    {
        if (!running()) { return result; }
        if (!ReadChunk(literalIndex, chunk, &entries)) { result.Status = L"corrupt_inventory_chunk"; return result; }
        for (const auto& entry : entries)
        {
            if (!running()) { return result; }
            if (!names.insert(entry.Name).second) { result.Status = L"duplicate_inventory_name"; return result; }
            if (!entry.Valid) { ++publications.Counts.InvalidAtBuild; ++result.InspectedFiles; continue; }
            const auto path = source / entry.Name;
            auto pin = inventory_files::Open(path, GENERIC_READ, FILE_SHARE_READ);
            if (!IsNamedOriginal(pin.get(), path, entry)) { ++publications.Counts.ChangedOrMissing; ++result.InspectedFiles; continue; }
            if (entry.Bytes > options.ReadBudget - result.ReadBytes) { result.Status = L"budget_exhausted"; return result; }
            Publication original;
            const auto actual = ReadEntry(std::filesystem::path(literalSource) / entry.Name, reader, nullptr, &original, static_cast<size_t>(entry.Bytes));
            result.ReadBytes += actual.Bytes;
            ++result.InspectedFiles;
            if (!actual.Valid || actual.Bytes != entry.Bytes || actual.Digest != entry.Digest) { ++publications.Counts.ChangedOrMissing; }
            else if (path.extension() == L".kncase")
            {
                const auto canonicalBytes = reader.CanonicalSize();
                if (!canonicalBytes) { result.Status = L"source_unavailable"; return result; }
                publications.AddCase(actual.Digest, original.CaseCollection, canonicalBytes);
            }
            else { publications.AddLedger(actual.Digest, original.Ledger); }
        }
    }
    if (!publications.Finish(running) || !running()) { return result; }
    result.Assessment = std::move(publications.Counts);
    result.Status = result.Assessment->ClosureKnown ? L"ok" : L"partial_inventory";
    return result;
}

std::wstring EvidenceInventoryClosureJson(const EvidenceInventoryClosureResult& result)
{
    std::wstring assessment = L"null";
    if (result.Assessment)
    {
        const auto& a = *result.Assessment;
        assessment = L"{\"publication_closure_known\":" + std::wstring(a.ClosureKnown ? L"true" : L"false") +
            L",\"invalid_at_build\":" + Number(a.InvalidAtBuild) + L",\"changed_or_missing\":" + Number(a.ChangedOrMissing) +
            L",\"case_files\":" + Number(a.CaseFiles) + L",\"unique_bundles\":" + Number(a.UniqueCases) +
            L",\"duplicate_case_files\":" + Number(a.CaseFiles - a.UniqueCases) + L",\"unattributed_bundles\":" + Number(a.UnattributedCases) +
            L",\"ledger_files\":" + Number(a.LedgerFiles) + L",\"duplicate_ledger_files\":" + Number(a.DuplicateLedgers) +
            L",\"collections_without_ledger\":" + Number(a.CollectionsWithoutLedger) + L",\"conflicting_collections\":" + Number(a.ConflictingCollections) +
            L",\"unambiguous_ledger_totals\":{\"collections\":" + Number(a.UnambiguousCollections) + L",\"admitted\":" + mcpjson::Quote(a.Admitted) +
            L",\"written\":" + Number(a.Written) + L",\"failed\":" + mcpjson::Quote(a.Failed) + L",\"dropped\":" + mcpjson::Quote(a.Dropped) +
            L",\"reported_bytes\":" + Number(a.PublishedBytes) + L",\"observed_canonical_bytes\":" + Number(a.ObservedCanonicalBytes) +
            L",\"byte_mismatch_collections\":" + Number(a.ByteMismatchCollections) + L",\"unavailable_written_bundles\":" + Number(a.MissingWritten) +
            L",\"unexpected_bundles\":" + Number(a.UnexpectedCases) + L"}}";
    }
    return L"{\"schema\":\"kn.evidence_inventory_closure.v1\",\"scope\":\"all_snapshot_members\",\"observation\":\"non_atomic_original_reread\","
        L"\"collector_authenticated\":false,\"status\":" + mcpjson::Quote(result.Status) + L",\"snapshot_sha256\":" +
        (result.SnapshotDigest.empty() ? L"null" : mcpjson::Quote(result.SnapshotDigest)) + L",\"snapshot_entries\":" +
        (result.SnapshotDigest.empty() ? L"null" : Number(result.SnapshotEntries)) + L",\"inspected_files\":" + Number(result.InspectedFiles) +
        L",\"read_bytes\":" + Number(result.ReadBytes) + L",\"assessment\":" + assessment + L"}";
}

std::wstring EvidenceInventoryBuildJson(const EvidenceInventoryBuildResult& result)
{
    const auto schema = result.Resume ? L"kn.evidence_inventory_build_resume.v1" : L"kn.evidence_inventory_build.v1";
    std::wstring progress;
    if (result.Resume)
    {
        progress = L",\"reused_entries\":" + Number(result.ReusedEntries) + L",\"verified_entries\":" + Number(result.VerifiedEntries);
        if (result.VerifyEntryLimit)
        {
            progress += L",\"verify_entry_limit\":" + Number(result.VerifyEntryLimit) +
                L",\"reused_verified_entries\":" + Number(result.ReusedVerifiedEntries);
        }
    }
    return L"{\"schema\":" + mcpjson::Quote(schema) + L",\"status\":" + mcpjson::Quote(result.Status) +
        L",\"snapshot_digest\":" + mcpjson::Quote(result.Digest) + L",\"entries\":" + Number(result.Entries) +
        L",\"invalid_files\":" + Number(result.InvalidFiles) + L",\"read_bytes\":" + Number(result.ReadBytes) +
        progress + L",\"source_capture_atomic\":false,\"collector_authenticated\":false}";
}

EvidenceQueryResult QueryEvidenceInventory(const std::wstring& directory, const KmonHuntFilter& filter,
    const KmonHuntQueryOptions& options, const EvidenceInventoryOptions& inventory)
{
    EvidenceQueryResult result;
    result.UsesSnapshot = true;
    result.InventoryComplete = false;
    result.PublicationClosureEvaluated = false;
    result.Limit = options.Limit;
    if (options.Limit == 0 || options.Limit > 256 || options.Cursor.size() > 1200 || inventory.Cursor.size() > 1200 ||
        filter.Role.size() > 128 || filter.Role.find(L'\0') != std::wstring::npos ||
        inventory.WindowFiles == 0 || inventory.WindowFiles > 4096 ||
        inventory.ReadBudget < EvidenceBundleMaxJsonBytes || inventory.ReadBudget > 64 * 1024 * 1024)
    {
        result.Status = L"invalid_query";
        return result;
    }
    Manifest manifest;
    if (!ReadManifest(inventory.Path, &manifest, &result.SnapshotDigest))
    {
        result.Status = L"invalid_inventory";
        return result;
    }
    if (DirectoryId(directory) != manifest.DirectoryId)
    {
        result.Status = L"source_directory_changed";
        return result;
    }
    result.SnapshotEntries = static_cast<size_t>(manifest.Entries);
    const auto scope = KmonHuntQueryScope(filter, options.Limit) + L":" + std::to_wstring(inventory.WindowFiles) +
        L":" + std::to_wstring(inventory.ReadBudget);
    const auto inventoryToken = [&](uint64_t offset)
    {
        return L"i1:" + result.SnapshotDigest + L":" + std::to_wstring(offset) + L":" + scope;
    };
    uint64_t start = 0;
    if (!inventory.Cursor.empty())
    {
        size_t at = 68;
        if (inventory.Cursor.size() < 69 || inventory.Cursor.compare(0, 3, L"i1:") != 0 || inventory.Cursor[67] != L':' ||
            !KmonHuntCursorNumber(inventory.Cursor, &at, &start) || inventory.Cursor.substr(at) != scope ||
            (start >= manifest.Entries && !(start == 0 && manifest.Entries == 0)))
        {
            result.Status = L"invalid_inventory_cursor";
            return result;
        }
        if (inventory.Cursor.substr(3, 64) != result.SnapshotDigest)
        {
            result.Status = L"stale_inventory_cursor";
            return result;
        }
        if (inventory.Cursor != inventoryToken(start))
        {
            result.Status = L"invalid_inventory_cursor";
            return result;
        }
    }
    result.InventoryOffset = static_cast<size_t>(start);
    result.InventoryCursor = inventoryToken(start);
    std::vector<Entry> entries;
    size_t cachedChunk = SIZE_MAX;
    size_t bytes = 0;
    uint64_t next = start;
    std::vector<EvidenceCaseSummary> matches;
    BundleReader reader;
    std::set<std::wstring> seen, sessions;
    std::map<std::wstring, uint64_t> present;
    std::wstring window = result.InventoryCursor + L"\n";
    while (next < manifest.Entries && result.InspectedFiles < inventory.WindowFiles)
    {
        const auto index = static_cast<size_t>(next / ChunkEntries);
        if (index != cachedChunk)
        {
            if (!ReadChunk(inventory.Path, manifest.Chunks[index], &entries))
            {
                result.Status = L"corrupt_inventory_chunk";
                return result;
            }
            cachedChunk = index;
        }
        const auto& entry = entries[static_cast<size_t>(next % ChunkEntries)];
        if (entry.Valid && entry.Bytes > inventory.ReadBudget - bytes)
        {
            break;
        }
        ++next;
        ++result.InspectedFiles;
        window += mcpjson::Quote(entry.Name) + L":" + entry.Digest + L":";
        if (!entry.Valid)
        {
            ++result.InvalidFiles;
            window += L"recorded_invalid\n";
            continue;
        }
        const auto path = std::filesystem::path(directory) / entry.Name;
        size_t read = 0;
        std::wstring failure, digest;
        if (path.extension() == L".knledger")
        {
            std::wstring json;
            EvidenceSessionSummary session;
            const bool valid = ReadAnalystSnapshot(path.wstring(), &json, &failure,
                (std::min<size_t>)(32768, inventory.ReadBudget - bytes), &read, true) &&
                read == entry.Bytes && ParseEvidenceSession(json, &session) && Hash(json) == entry.Digest;
            bytes += read;
            window += valid ? L"valid\n" : L"changed_or_missing\n";
            if (!valid || !sessions.insert(session.CollectionId).second)
            {
                ++result.InvalidFiles;
            }
            else
            {
                result.Sessions.push_back(std::move(session));
            }
            continue;
        }
        EvidenceBundle bundle;
        const bool valid = reader.Read(path.wstring(), &bundle, &digest,
            inventory.ReadBudget - bytes, &read) && read == entry.Bytes && digest == entry.Digest;
        bytes += read;
        window += valid ? L"valid\n" : L"changed_or_missing\n";
        if (!valid)
        {
            ++result.InvalidFiles;
            continue;
        }
        ++result.ImportedFiles;
        if (!seen.insert(digest).second)
        {
            ++result.DuplicateFiles;
            continue;
        }
        ++present[bundle.CollectionId];
        if (filter.Matches(bundle.Receipt.Reference))
        {
            matches.push_back({entry.Name, digest, bundle.CollectionId, bundle.Receipt, EvidenceReadSetComplete(bundle)});
        }
    }
    if (DirectoryId(directory) != manifest.DirectoryId)
    {
        result.Status = L"source_directory_changed";
        return result;
    }
    result.InventoryComplete = start == 0 && next == manifest.Entries;
    result.ReadBytes = bytes;
    result.PublicationClosureEvaluated = result.InventoryComplete;
    if (result.PublicationClosureEvaluated)
    {
        for (const auto& collection : present)
        {
            if (collection.first.empty() || sessions.count(collection.first) == 0)
            {
                ++result.UnclosedCollections;
            }
        }
        for (const auto& session : result.Sessions)
        {
            const auto count = present[session.CollectionId];
            if (session.Written > count)
            {
                result.UnavailableWrittenBundles += session.Written - count;
            }
            if (session.Written < count)
            {
                ++result.InvalidFiles;
            }
        }
    }
    result.InventoryDigest = Hash(window + std::to_wstring(next));
    if (result.InventoryDigest.size() != 64)
    {
        result.Status = L"unavailable";
        return result;
    }
    result.Matched = matches.size();
    const auto resultToken = [&](uint64_t offset)
    {
        return L"s1:" + result.InventoryDigest + L":" + std::to_wstring(offset) + L":" + scope;
    };
    if (!options.Cursor.empty())
    {
        uint64_t offset = 0;
        size_t at = 68;
        if (options.Cursor.size() < 69 || options.Cursor.compare(0, 3, L"s1:") != 0 || options.Cursor[67] != L':' ||
            !KmonHuntCursorNumber(options.Cursor, &at, &offset) || offset == 0 || offset > inventory.WindowFiles ||
            options.Cursor.substr(at) != scope)
        {
            result.Status = L"invalid_cursor";
            return result;
        }
        if (options.Cursor.substr(3, 64) != result.InventoryDigest)
        {
            result.Status = L"stale_cursor";
            return result;
        }
        if (options.Cursor != resultToken(offset))
        {
            result.Status = L"invalid_cursor";
            return result;
        }
        if (offset >= matches.size())
        {
            result.Status = L"invalid_cursor";
            return result;
        }
        result.Offset = static_cast<size_t>(offset);
    }
    const auto last = (std::min)(matches.size(), result.Offset + result.Limit);
    result.Cases.assign(matches.begin() + result.Offset, matches.begin() + last);
    if (last < matches.size())
    {
        result.NextCursor = resultToken(last);
    }
    else if (next < manifest.Entries)
    {
        result.NextInventoryCursor = inventoryToken(next);
    }
    if (!result.InventoryComplete || result.InvalidFiles != 0 || result.UnavailableWrittenBundles != 0)
    {
        result.Status = L"partial_inventory";
    }
    return result;
}
