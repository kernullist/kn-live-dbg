#pragma once

#include "../user/EvidenceInventory.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include <filesystem>
#include <set>

namespace evidence_inventory_test
{
    inline std::wstring HashJson(const std::wstring& json)
    {
        const auto bytes = mcpjson::WideToUtf8(json);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }

    template<typename Check>
    void Run(Check check, const std::wstring& root, const EvidenceBundle& fixture)
    {
        const auto source = root + L"\\indexed-source";
        const auto snapshot = root + L"\\indexed-snapshot";
        std::wstring error;
        check(CreateDirectoryW(source.c_str(), nullptr) != FALSE, "snapshot source directory created");
        for (uint32_t i = 0; i < 6; ++i)
        {
            auto item = fixture;
            item.Receipt.Reference.Context.Identity.ProcessId = 100 + i;
            check(SaveEvidenceBundle(source + L"\\case-" + std::to_wstring(i) + L".kncase", item, &error), "snapshot source receipt published");
        }
        const auto built = BuildEvidenceInventory(source, snapshot);
        check(built.Status == L"ok" && built.Entries == 6 && built.InvalidFiles == 0 && built.Digest.size() == 64,
            "bounded snapshot published with content-bound chunks");
        check(BuildEvidenceInventory(source, snapshot).Status == L"output_exists_or_unavailable",
            "snapshot builder never overwrites an existing destination");
        const auto nulOutput = root + L"\\nul-path-index";
        check(BuildEvidenceInventory(source, nulOutput + std::wstring(1, L'\0') + L"suffix").Status == L"invalid_path" &&
            GetFileAttributesW(nulOutput.c_str()) == INVALID_FILE_ATTRIBUTES,
            "embedded NUL is rejected before creating a different directory");
        EvidenceInventoryOptions inventory;
        inventory.Path = snapshot;
        inventory.WindowFiles = 3;
        KmonHuntQueryOptions options;
        options.Limit = 2;
        const auto first = QueryEvidenceDirectory(source, {}, options, inventory);
        check(first.Status == L"partial_inventory" && first.Cases.size() == 2 && first.InspectedFiles == 3 &&
            !first.NextCursor.empty() && first.NextInventoryCursor.empty() && !first.PublicationClosureEvaluated,
            "result pagination precedes inventory continuation without inventing global closure");
        inventory.Cursor = first.InventoryCursor;
        options.Cursor = first.NextCursor;
        const auto second = QueryEvidenceDirectory(source, {}, options, inventory);
        check(second.Cases.size() == 1 && second.NextCursor.empty() && !second.NextInventoryCursor.empty(),
            "drained result page exposes the next inventory window");
        inventory.Cursor = second.NextInventoryCursor;
        options.Cursor.clear();
        const auto third = QueryEvidenceDirectory(source, {}, options, inventory);
        options.Cursor = third.NextCursor;
        const auto fourth = QueryEvidenceDirectory(source, {}, options, inventory);
        std::set<uint32_t> pids;
        for (const auto* page : {&first, &second, &third, &fourth})
        {
            for (const auto& row : page->Cases)
            {
                pids.insert(row.Receipt.Reference.Context.Identity.ProcessId);
            }
        }
        check(pids == std::set<uint32_t>{100, 101, 102, 103, 104, 105} && fourth.NextCursor.empty() &&
            fourth.NextInventoryCursor.empty() && fourth.InventoryOffset == 3,
            "independent result and inventory cursors traverse each declared member");
        check(QueryEvidenceDirectory(root, {}, {}, inventory).Status == L"source_directory_changed",
            "snapshot cannot be applied to a different directory identity");
        options.Limit = 1;
        check(QueryEvidenceDirectory(source, {}, options, inventory).Status == L"invalid_inventory_cursor",
            "inventory continuation is bound to its query scope and window budget");
        inventory.Cursor.clear();
        options = {};
        auto added = fixture;
        added.Receipt.Reference.Context.Identity.ProcessId = 999;
        check(SaveEvidenceBundle(source + L"\\added.kncase", added, &error), "post-snapshot publication created");
        inventory.WindowFiles = 4096;
        const auto unchanged = QueryEvidenceDirectory(source, {}, options, inventory);
        check(unchanged.InventoryComplete && unchanged.Matched == 6 && unchanged.SnapshotDigest == built.Digest,
            "source additions do not silently alter snapshot membership");
        const auto rebuiltPath = root + L"\\indexed-new-generation";
        check(BuildEvidenceInventory(source, rebuiltPath).Entries == 7, "new snapshot includes later publications");
        inventory.Path = rebuiltPath;
        inventory.WindowFiles = 3;
        inventory.Cursor = second.NextInventoryCursor;
        options.Limit = 2;
        check(QueryEvidenceDirectory(source, {}, options, inventory).Status == L"stale_inventory_cursor",
            "inventory cursor cannot move between snapshot generations");
        inventory.Path = snapshot;
        inventory.Cursor = first.InventoryCursor;
        options.Cursor = first.NextCursor;
        const auto removedPath = source + L"\\" + first.Cases[0].FileName;
        check(DeleteFileW(removedPath.c_str()) != FALSE, "owned changed-inventory control removed");
        check(QueryEvidenceDirectory(source, {}, options, inventory).Status == L"stale_cursor",
            "missing source bytes invalidate a current-window result cursor");
        options.Cursor.clear();
        const auto missing = QueryEvidenceDirectory(source, {}, options, inventory);
        check(missing.InvalidFiles == 1 && missing.Status == L"partial_inventory",
            "missing captured members remain explicit gaps");

        std::atomic<bool> cancel{true};
        EvidenceInventoryBuildOptions buildOptions;
        buildOptions.Cancellation = &cancel;
        const auto cancelledPath = root + L"\\cancelled-index";
        check(BuildEvidenceInventory(source, cancelledPath, buildOptions).Status == L"cancelled" &&
            GetFileAttributesW(cancelledPath.c_str()) == INVALID_FILE_ATTRIBUTES,
            "pre-cancelled snapshot creation has no output side effect");

        const auto large = root + L"\\large-index-source";
        const auto largeIndex = root + L"\\large-index-snapshot";
        check(CreateDirectoryW(large.c_str(), nullptr) != FALSE, "large inventory source created");
        bool copies = true;
        const auto original = source + L"\\added.kncase";
        for (uint32_t i = 0; i < 4101; ++i)
        {
            const auto destination = large + L"\\member-" + std::to_wstring(i) + L".kncase";
            copies = CopyFileW(original.c_str(), destination.c_str(), TRUE) != FALSE && copies;
        }
        check(copies, "large inventory fixture exceeds legacy enumeration cap");
        const auto largeBuilt = BuildEvidenceInventory(large, largeIndex);
        check(largeBuilt.Status == L"ok" && largeBuilt.Entries == 4101, "snapshot retains files beyond legacy directory cap");
        inventory = {};
        inventory.Path = largeIndex;
        const auto largeFirst = QueryEvidenceDirectory(large, {}, {}, inventory);
        inventory.Cursor = largeFirst.NextInventoryCursor;
        const auto largeLast = QueryEvidenceDirectory(large, {}, {}, inventory);
        check(largeFirst.InspectedFiles == 4096 && largeLast.InspectedFiles == 5 &&
            largeFirst.NextCursor.empty() && !largeFirst.NextInventoryCursor.empty() && largeLast.NextInventoryCursor.empty() &&
            largeFirst.DuplicateFiles + largeLast.DuplicateFiles == 4099,
            "inventory continuation reaches every file beyond 4096 with window-scoped deduplication");

        const auto byteSource = root + L"\\byte-budget-source";
        const auto byteIndex = root + L"\\byte-budget-index";
        check(CreateDirectoryW(byteSource.c_str(), nullptr) != FALSE, "byte budget source created");
        auto full = fixture;
        for (size_t i = full.Spans.size(); i < EvidenceBundleMaxSpans; ++i)
        {
            full.Spans.push_back({0x20000 + i * 4096, 4096, L"target_page", L"valid", std::vector<uint8_t>(4096, 0x90)});
        }
        bool fullSaved = SaveEvidenceBundle(byteSource + L"\\first.kncase", full, &error);
        fullSaved = CopyFileW((byteSource + L"\\first.kncase").c_str(), (byteSource + L"\\second.kncase").c_str(), TRUE) != FALSE && fullSaved;
        fullSaved = CopyFileW((byteSource + L"\\first.kncase").c_str(), (byteSource + L"\\third.kncase").c_str(), TRUE) != FALSE && fullSaved;
        check(fullSaved && BuildEvidenceInventory(byteSource, byteIndex).Status == L"ok", "large byte-budget members published");
        inventory = {};
        inventory.Path = byteIndex;
        inventory.ReadBudget = EvidenceBundleMaxJsonBytes;
        const auto byteFirst = QueryEvidenceDirectory(byteSource, {}, {}, inventory);
        inventory.Cursor = byteFirst.NextInventoryCursor;
        const auto byteSecond = QueryEvidenceDirectory(byteSource, {}, {}, inventory);
        inventory.Cursor = byteSecond.NextInventoryCursor;
        const auto byteThird = QueryEvidenceDirectory(byteSource, {}, {}, inventory);
        check(byteFirst.InspectedFiles == 1 && byteSecond.InspectedFiles == 1 && byteThird.InspectedFiles == 1 &&
            byteFirst.ReadBytes <= inventory.ReadBudget && byteSecond.ReadBytes <= inventory.ReadBudget &&
            byteThird.ReadBytes <= inventory.ReadBudget && !byteFirst.NextInventoryCursor.empty() &&
            !byteSecond.NextInventoryCursor.empty() && byteThird.NextInventoryCursor.empty(),
            "byte exhaustion resumes at the first unread member without exceeding the read budget");

        buildOptions = {};
        buildOptions.MaximumEntries = 128;
        const auto incomplete = root + L"\\incomplete-index";
        check(BuildEvidenceInventory(large, incomplete, buildOptions).Status == L"budget_exhausted" &&
            GetFileAttributesW((incomplete + L"\\manifest.knindex").c_str()) == INVALID_FILE_ATTRIBUTES,
            "budget interruption never publishes a final manifest");
        inventory.Path = incomplete;
        inventory.Cursor.clear();
        check(QueryEvidenceDirectory(large, {}, {}, inventory).Status == L"invalid_inventory",
            "completed chunks without a manifest cannot become a valid partial snapshot");

        // The attacker can reseal both hashes; basenames remain a separate boundary.
        std::wstring originalManifest, originalChunks, firstChunk, firstDigest;
        bool forgedReady = ReadAnalystSnapshot(snapshot + L"\\manifest.knindex", &originalManifest, &error) &&
            mcpjson::FindRawValue(originalManifest, L"chunks", &originalChunks);
        size_t firstEnd = 0;
        forgedReady = forgedReady && mcpjson::ScanValue(originalChunks, 1, &firstEnd) &&
            mcpjson::GetString(originalChunks.substr(1, firstEnd - 1), L"digest", &firstDigest) &&
            ReadAnalystSnapshot(snapshot + L"\\" + firstDigest + L".knchunk", &firstChunk, &error);
        const auto nameAt = firstChunk.find(L"\"name\":");
        size_t nameEnd = 0;
        forgedReady = forgedReady && nameAt != std::wstring::npos && mcpjson::ScanValue(firstChunk, nameAt + 7, &nameEnd);
        if (forgedReady)
        {
            firstChunk.replace(nameAt + 7, nameEnd - nameAt - 7, mcpjson::Quote(L"..\\outside.kncase"));
            const auto forgedDigest = HashJson(firstChunk);
            const auto digestAt = originalManifest.find(firstDigest);
            const auto forged = root + L"\\forged-index";
            forgedReady = digestAt != std::wstring::npos && CreateDirectoryW(forged.c_str(), nullptr) != FALSE;
            if (forgedReady)
            {
                originalManifest.replace(digestAt, firstDigest.size(), forgedDigest);
                forgedReady = SaveObservationJson(forged + L"\\" + forgedDigest + L".knchunk", firstChunk, &error) &&
                    SaveObservationJson(forged + L"\\manifest.knindex", originalManifest, &error);
                inventory = {};
                inventory.Path = forged;
                const auto rejected = QueryEvidenceDirectory(source, {}, {}, inventory);
                check(forgedReady && rejected.Status == L"corrupt_inventory_chunk" && rejected.Cases.empty() &&
                    rejected.ImportedFiles == 0, "resealed path traversal cannot escape the source directory");
            }
        }
        check(forgedReady, "resealed hostile snapshot constructed");

        std::wstring manifest;
        check(ReadAnalystSnapshot(largeIndex + L"\\manifest.knindex", &manifest, &error), "read immutable manifest for corruption control");
        std::wstring chunks;
        mcpjson::FindRawValue(manifest, L"chunks", &chunks);
        const auto objectBegin = chunks.find(L'{');
        size_t objectEnd = 0;
        std::wstring chunkHash;
        if (objectBegin != std::wstring::npos && mcpjson::ScanValue(chunks, objectBegin, &objectEnd))
        {
            mcpjson::GetString(chunks.substr(objectBegin, objectEnd - objectBegin), L"digest", &chunkHash);
        }
        check(chunkHash.size() == 64 && DeleteFileW((largeIndex + L"\\" + chunkHash + L".knchunk").c_str()) != FALSE,
            "owned chunk removed for missing-index control");
        inventory.Path = largeIndex;
        inventory.Cursor.clear();
        const auto broken = QueryEvidenceDirectory(large, {}, {}, inventory);
        check(broken.Status == L"corrupt_inventory_chunk" && broken.Cases.empty() && broken.NextInventoryCursor.empty(),
            "missing inventory chunk fails without silently skipping records");
    }
}
