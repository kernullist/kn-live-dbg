#include "EvidenceInventory.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <filesystem>
#include <set>

namespace
{
    constexpr size_t ChunkEntries = 128;
    constexpr size_t MaximumChunks = 8192;
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
            size_t maximumBytes, size_t* read)
        {
            *bundle = {};
            digest->clear();
            std::wstring json, error;
            if (!ReadAnalystSnapshot(path, &json, &error,
                (std::min)(maximumBytes, EvidenceBundleMaxJsonBytes), read, true))
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
                Digest = std::move(parsedDigest);
                Bundle = std::move(parsed);
            }
            *bundle = Bundle;
            *digest = Digest;
            return true;
        }

    private:
        std::wstring Json;
        std::wstring Digest;
        EvidenceBundle Bundle;
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

    bool ReadChunk(const std::wstring& directory, const Chunk& chunk, std::vector<Entry>* entries)
    {
        entries->clear();
        std::wstring json, error;
        std::vector<std::wstring> rows;
        if (!ReadAnalystSnapshot((std::filesystem::path(directory) / (chunk.Digest + L".knchunk")).wstring(),
            &json, &error, ChunkBytes, nullptr, true) || Hash(json) != chunk.Digest || !mcpjson::ValidateDocument(json) ||
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
}

EvidenceInventoryBuildResult BuildEvidenceInventory(const std::wstring& directory,
    const std::wstring& newSnapshotDirectory, const EvidenceInventoryBuildOptions& options)
{
    EvidenceInventoryBuildResult result;
    if (options.Cancellation != nullptr && options.Cancellation->load())
    {
        result.Status = L"cancelled";
        return result;
    }
    if (options.MaximumEntries == 0 || options.MaximumEntries > ChunkEntries * MaximumChunks ||
        options.ReadBudget == 0 || options.ReadBudget > 8ull * 1024 * 1024 * 1024 ||
        options.DeadlineMs == 0 || options.DeadlineMs > 120000)
    {
        result.Status = L"invalid_budget";
        return result;
    }
    if (!DirectoryPathValid(directory) || !DirectoryPathValid(newSnapshotDirectory))
    {
        result.Status = L"invalid_path";
        return result;
    }
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
            Entry entry;
            entry.Name = path.filename().wstring();
            if (!NameValid(entry.Name))
            {
                result.Status = L"unsupported_file_name";
                return result;
            }
            if (options.ReadBudget - result.ReadBytes < EvidenceBundleMaxJsonBytes)
            {
                result.Status = L"budget_exhausted";
                return result;
            }
            size_t read = 0;
            std::wstring failure;
            if (extension == L".kncase")
            {
                EvidenceBundle bundle;
                entry.Valid = reader.Read(path.wstring(), &bundle, &entry.Digest, EvidenceBundleMaxJsonBytes, &read);
            }
            else
            {
                std::wstring json;
                EvidenceSessionSummary session;
                entry.Valid = ReadAnalystSnapshot(path.wstring(), &json, &failure, 32768, &read, true) && ParseEvidenceSession(json, &session);
                if (entry.Valid)
                {
                    entry.Digest = Hash(json);
                    entry.Valid = entry.Digest.size() == 64;
                }
            }
            entry.Bytes = read;
            result.ReadBytes += read;
            if (!entry.Valid)
            {
                entry.Digest.clear();
                ++result.InvalidFiles;
            }
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

std::wstring EvidenceInventoryBuildJson(const EvidenceInventoryBuildResult& result)
{
    return L"{\"schema\":\"kn.evidence_inventory_build.v1\",\"status\":" + mcpjson::Quote(result.Status) +
        L",\"snapshot_digest\":" + mcpjson::Quote(result.Digest) + L",\"entries\":" + Number(result.Entries) +
        L",\"invalid_files\":" + Number(result.InvalidFiles) + L",\"read_bytes\":" + Number(result.ReadBytes) +
        L",\"source_capture_atomic\":false,\"collector_authenticated\":false}";
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
