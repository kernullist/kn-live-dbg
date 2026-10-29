#include "../user/EvidenceBundle.h"
#include "../user/EvidenceInvestigation.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include "../user/McpJson.h"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool ok, const char* name)
    {
        if (ok) { ++Passed; }
        else { ++Failed; std::cerr << "[evidence.selftest] FAIL " << name << "\n"; }
    }
    EvidenceBundle Fixture()
    {
        EvidenceBundle b;
        b.Acquisition = L"synthetic_fixture";
        b.CaptureStartedMs = 100;
        b.CaptureEndedMs = 105;
        b.ReferenceConsistent = true;
        auto& r = b.Receipt.Reference;
        r.Id = 1;
        r.Context.Identity.BootId = L"fixture_boot";
        r.Context.Identity.ProcessId = 55;
        r.Context.Identity.CreateTime = 50;
        r.Context.MonotonicMs = 105;
        r.Context.ArrivalMonotonicMs = 110;
        r.Context.ArrivalSequence = 1;
        r.Context.Source = L"fixture";
        r.Context.DependencyGroup = L"fixture_memory";
        r.Context.Ownership = CodeOwnership::UnownedExecutable;
        r.Context.MappingGeneration = 1;
        r.Context.Coverage.Attempted = true;
        r.Context.Coverage.RequestedBytes = 32;
        r.Context.Coverage.ComparedBytes = 32;
        r.Context.Coverage.Compared = {{0x11000, 32}};
        r.Address = r.Root = 0x11000;
        r.Slot = 0x12000;
        r.Role = L"tls_callback";
        r.SlotStable = true;
        b.Receipt.Disposition = L"current";
        std::vector<uint8_t> head(32, 0x90), slot(8);
        head[0] = 0xc3;
        std::memcpy(slot.data(), &r.Address, 8);
        b.Spans.push_back({r.Address, 32, L"target_head", L"valid", head});
        b.Spans.push_back({r.Slot, 8, L"pointer_slot", L"valid", slot});
        return b;
    }
    std::wstring Reseal(std::wstring json, const std::wstring& from, const std::wstring& to)
    {
        std::wstring payload;
        mcpjson::FindRawValue(json, L"payload", &payload);
        const auto at = payload.find(from);
        if (at == std::wstring::npos) { return {}; }
        payload.replace(at, from.size(), to);
        const auto utf8 = mcpjson::WideToUtf8(payload);
        ContentHash hash;
        hash.Add(reinterpret_cast<const uint8_t*>(utf8.data()), utf8.size());
        return L"{\"schema\":\"kmon.bundle.v1\",\"payload_sha256\":" + mcpjson::Quote(hash.Finish()) + L",\"payload\":" + payload + L"}";
    }
    void Tests(const std::wstring& directory)
    {
        auto b = Fixture();
        EvidenceBundle parsed;
        std::wstring error;
        const auto json = EvidenceBundleJson(b);
        Check(!json.empty() && ParseEvidenceBundle(json, &parsed, &error) && EvidenceBundleJson(parsed) == json,
            "receipt raw bytes coverage and provenance round trip exactly");
        std::vector<uint8_t> bytes;
        Check(EvidenceReadSetComplete(parsed) && EvidenceRead(parsed, 0x11000, 32, &bytes) && bytes[0] == 0xc3,
            "raw read set reconstructs original target bytes");
        Check(!EvidenceRead(parsed, 0x11010, 32, &bytes) && bytes.empty(), "missing bytes are not zero filled");
        Check(!EvidenceRead(parsed, UINT64_MAX - 4, 8, &bytes) && !EvidenceRead(parsed, 0x11000, 4097, &bytes),
            "offline reads reject overflow and oversized requests");
        for (size_t cut : {size_t{0}, size_t{1}, json.size() / 2, json.size() - 1})
        {
            Check(!ParseEvidenceBundle(json.substr(0, cut), &parsed, &error) && parsed.Spans.empty(),
                "truncated publication cannot expose partial success");
        }
        auto corrupt = json;
        corrupt[corrupt.find(L"c390")] = L'd';
        Check(!ParseEvidenceBundle(corrupt, &parsed, &error), "changed raw bytes fail payload hash");
        for (const auto& edit : std::vector<std::pair<std::wstring, std::wstring>>{
            {L"\"span_count\":\"2\"", L"\"span_count\":\"1\""},
            {L"\"read_set_complete\":true", L"\"read_set_complete\":false"},
            {L"\"schema\":\"kmon.evidence.v1\"", L"\"schema\":\"kmon.evidence.v2\""},
            {L"\"requested\":\"32\"", L"\"requested\":\"31\""},
            {L"\"arrival_sequence\":\"1\"", L"\"arrival_sequence\":\"0\""},
            {L"\"id\":1", L"\"id\":0"},
            {L"\"arrival_ms\":\"110\"", L"\"arrival_ms\":\"101\""},
            {L"\"arrival_ms\":\"110\"", L"\"arrival_ms\":\"30106\""},
            {L"\"execution_observed\":false", L"\"execution_observed\":true"},
            {L"\"bytes_hex\":\"c390", L"\"bytes_hex\":\"d390"},
            {L"\"role\":\"target_head\"", L"\"path\":\"../raw.bin\",\"role\":\"target_head\""},
            {L"\"boot_id\":\"fixture_boot\"", L"\"boot_id\":\"\\ud800\""},
            {L"\"pid\":55", L"\"pid\":55,\"pid\":66"},
            {L"\"pid\":55", L"\"pid\":4294967296"}})
        {
            Check(!ParseEvidenceBundle(Reseal(json, edit.first, edit.second), &parsed, &error),
                "resealed inconsistent or noncanonical metadata rejected");
        }
        auto partial = b;
        partial.Spans[0].State = L"read_failed";
        partial.Spans[0].Bytes.clear();
        Check(ParseEvidenceBundle(EvidenceBundleJson(partial), &parsed, &error) && !EvidenceReadSetComplete(parsed) &&
            !EvidenceRead(parsed, 0x11000, 32, &bytes), "failed sparse span persists as explicit replay gap");
        partial = b;
        partial.CaptureTruncated = true;
        Check(!EvidenceReadSetComplete(partial), "capture budget cannot claim complete read set");
        auto historical = b;
        historical.Receipt.Reference.Id = 0;
        historical.Receipt.Disposition = L"historical_only";
        historical.Receipt.Reference.Context.ArrivalMonotonicMs = 40000;
        Check(ParseEvidenceBundle(EvidenceBundleJson(historical), &parsed, &error) &&
            parsed.Receipt.Reference.Context.MonotonicMs == 105,
            "delayed original evidence persists without rewriting its event time");
        partial = b;
        partial.Spans.push_back(partial.Spans[0]);
        partial.Spans.back().Bytes[0] ^= 1;
        Check(ParseEvidenceBundle(EvidenceBundleJson(partial), &parsed, &error) && !EvidenceReadSetComplete(parsed) &&
            !EvidenceRead(parsed, 0x11000, 32, &bytes), "contradictory overlapping reads remain partial");
        for (unsigned mode = 0; mode < 7; ++mode)
        {
            auto invalid = b;
            if (mode == 0) { invalid.Spans.resize(129, invalid.Spans[0]); }
            if (mode == 1) { invalid.Spans[0].Address = UINT64_MAX - 1; }
            if (mode == 2) { invalid.Spans[0].RequestedBytes = 4097; }
            if (mode == 3) { invalid.Spans[0].Bytes.pop_back(); }
            if (mode == 4) { invalid.Receipt.Reference.Context.Coverage.ComparedBytes = UINT64_MAX; }
            if (mode == 5) { invalid.Receipt.Reference.Context.Identity.CreateTime = 0; }
            if (mode == 6) { invalid.Receipt.Reference.Context.Identity.BootId = std::wstring(1, 0xd800); }
            Check(EvidenceBundleJson(invalid).empty(), "invalid or unbounded evidence cannot publish");
        }
        const auto path = directory + L"\\restart.kncase";
        Check(SaveEvidenceBundle(path, b, &error) && LoadEvidenceBundle(path, &parsed, &error) &&
            EvidenceBundleJson(parsed) == json, "new bundle durably published and read back");
        Check(!SaveEvidenceBundle(path, partial, &error) && LoadEvidenceBundle(path, &parsed, &error) &&
            EvidenceBundleJson(parsed) == json, "existing bundle preserved on publish collision");
        Check(!SaveEvidenceBundle(directory + L"\\bad.json", b, &error), "private file extension required");
        Check(!SaveEvidenceBundle(path + L":stream.kncase", b, &error), "alternate data stream output rejected");
        Check(!LoadEvidenceBundle(path + L".pending-test", &parsed, &error), "interrupted temporary files excluded");
        Check(!LoadEvidenceBundle(directory + L"\\missing.kncase", &parsed, &error), "missing artifact is unavailable");
        std::ofstream damaged(std::filesystem::path(directory + L"\\truncated.kncase"), std::ios::binary);
        damaged << "{\"schema\":\"kmon.bundle.v1\"";
        damaged.close();
        Check(!LoadEvidenceBundle(directory + L"\\truncated.kncase", &parsed, &error), "truncated on-disk artifact rejected");
        KmonHuntIndex hot(1);
        hot.Observe(b.Receipt.Reference);
        auto another = b.Receipt.Reference;
        ++another.Context.Identity.ProcessId;
        hot.Observe(another);
        Check(hot.Query(30106, {true, 55, L""}).Cases.empty() && LoadEvidenceBundle(path, &parsed, &error) &&
            EvidenceRead(parsed, 0x11000, 32, &bytes), "saved bytes survive hot expiry and eviction");
        size_t read = 123;
        Check(!LoadEvidenceBundle(path, &parsed, &error, nullptr, 16, &read) && read == 0 && parsed.Spans.empty(),
            "file byte budget checked on opened handle before allocation and read");
        auto session = b;
        session.CollectionId = L"fixture_collection";
        Check(ParseEvidenceBundle(EvidenceBundleJson(session), &parsed, &error) && parsed.CollectionId == session.CollectionId,
            "collection identity is additive to legacy bundles");
        const auto simple = ReplayEvidence(b);
        Check(simple.Gaps.empty() && simple.ReferenceReached && simple.Slot == L"points_to_recorded_root" &&
            simple.Chain.Hops.size() == 1, "offline reader reconstructs owned pointer and head bytes");
        const auto explanation = EvidenceReplayJson(b, simple, L"fixture_digest");
        Check(explanation.find(L"\"execution_observed\":false") != std::wstring::npos &&
            explanation.find(L"\"image_verification_replayed\":false") != std::wstring::npos &&
            explanation.find(L"execution_telemetry_for_execution_claims") != std::wstring::npos,
            "why keeps execution and image verification requirements explicit");
        auto transfer = b;
        transfer.Spans[0].Bytes[0] = 0xe9;
        const int32_t delta = 0x2000 - 5;
        std::memcpy(transfer.Spans[0].Bytes.data() + 1, &delta, 4);
        transfer.Spans.push_back({0x13000, 32, L"target_head", L"valid", b.Spans[0].Bytes});
        const auto chain = ReplayEvidence(transfer);
        Check(chain.Gaps.empty() && chain.Chain.Hops.size() == 2 && chain.Chain.Hops[0].Target == 0x13000,
            "static transfer is decoded from original bytes after reload");
        transfer.Spans.pop_back();
        Check(!ReplayEvidence(transfer).Gaps.empty(), "missing transfer destination stays partial");
        transfer = b;
        transfer.Spans[1].Bytes[0] ^= 1;
        Check(!ReplayEvidence(transfer).ReferenceReached && !ReplayEvidence(transfer).Gaps.empty(),
            "changed slot does not reconstruct recorded target");
        transfer = b;
        transfer.Spans[0].Bytes[0] = 0xff;
        transfer.Spans[0].Bytes[1] = 0xe0;
        Check(ReplayEvidence(transfer).Chain.Termination == L"unresolved_indirect" && !ReplayEvidence(transfer).Gaps.empty(),
            "dynamic transfer remains unresolved rather than guessed");
        auto page = b;
        std::vector<uint8_t> raw(4096, 0x90);
        raw[0] = 0xc3;
        page.Spans.push_back({0x11000, 4096, L"target_page", L"valid", raw});
        page.Receipt.Reference.PageComparable = true;
        page.Receipt.Reference.PageSha256 = ContentHash::Bytes(raw);
        Check(ReplayEvidence(page).PageDigest == L"matches_stored_digest", "stored page digest recalculated from raw bytes");
        page.Receipt.Reference.PageSha256[0] = page.Receipt.Reference.PageSha256[0] == L'a' ? L'b' : L'a';
        Check(ReplayEvidence(page).PageDigest == L"digest_mismatch" && !ReplayEvidence(page).Gaps.empty(),
            "metadata digest mismatch remains visible even with a resealed envelope");

        const auto inventory = directory + L"\\inventory";
        Check(CreateDirectoryW(inventory.c_str(), nullptr) != FALSE, "private query fixture directory created");
        for (uint32_t n = 0; n < 300; ++n)
        {
            auto item = b;
            item.Receipt.Reference.Context.Identity.ProcessId = 1000 + n;
            auto name = std::to_wstring(n);
            name.insert(0, 3 - name.size(), L'0');
            Check(SaveEvidenceBundle(inventory + L"\\ref-" + name + L".kncase", item, &error), "bounded inventory fixture saved");
        }
        const auto targeted = QueryEvidenceDirectory(inventory, {true, 1299, L"tls_callback"});
        Check(targeted.Status == L"ok" && targeted.Matched == 1 && targeted.Cases.size() == 1 &&
            targeted.Cases[0].Receipt.Reference.Context.Identity.ProcessId == 1299, "historical target beyond global 256 cap remains queryable");
        const auto initial = QueryEvidenceDirectory(inventory);
        Check(EvidenceQueryJson(initial, {}).find(L"\"publication_closure_known\":false") != std::wstring::npos,
            "legacy inventory without a closure ledger stays unconfirmed");
        const auto tail = QueryEvidenceDirectory(inventory, {}, {256, initial.NextCursor});
        Check(initial.Matched == 300 && initial.Cases.size() == 256 && tail.Cases.size() == 44 && tail.Offset == 256 &&
            tail.NextCursor.empty(), "inventory continuation covers entire retained historical scope");
        Check(QueryEvidenceDirectory(inventory, {true, 1299, L""}, {256, initial.NextCursor}).Status == L"invalid_cursor",
            "historical cursor bound to filter scope");
        Check(QueryEvidenceDirectory(directory + L"\\absent").Status == L"unavailable", "missing inventory is not an empty success");
        Check(QueryEvidenceDirectory(inventory, {}, {0, {}}).Status == L"invalid_query", "invalid historical limit rejected");
        Check(CopyFileW((inventory + L"\\ref-000.kncase").c_str(), (inventory + L"\\duplicate.kncase").c_str(), TRUE) != FALSE,
            "duplicate fixture created");
        const auto duplicate = QueryEvidenceDirectory(inventory);
        Check(duplicate.Matched == 300 && duplicate.DuplicateFiles == 1, "copied evidence deduplicates by payload identity");
        Check(QueryEvidenceDirectory(inventory, {}, {256, initial.NextCursor}).Status == L"stale_cursor",
            "changed inventory cannot silently continue old page membership");
        Check(CopyFileW((directory + L"\\truncated.kncase").c_str(), (inventory + L"\\broken.kncase").c_str(), TRUE) != FALSE,
            "corrupt inventory fixture created");
        const auto incomplete = QueryEvidenceDirectory(inventory);
        Check(incomplete.Status == L"partial_inventory" && incomplete.InvalidFiles == 1 && incomplete.Matched == 300 &&
            EvidenceQueryJson(incomplete, {}).find(L"\"collection_complete\":false") != std::wstring::npos,
            "corrupt files remain counted as unknown scope");
        const auto closed = directory + L"\\closed";
        Check(CreateDirectoryW(closed.c_str(), nullptr) != FALSE, "closure fixture directory created");
        Check(SaveEvidenceBundle(closed + L"\\case.kncase", session, &error), "collection-tagged receipt saved");
        EvidenceSessionSummary ledger{session.CollectionId, 1, 1, 0, 2, 4096};
        EvidenceSessionSummary parsedLedger;
        const auto ledgerJson = EvidenceSessionJson(ledger);
        Check(ParseEvidenceSession(ledgerJson, &parsedLedger) && parsedLedger.Dropped == 2,
            "closure preserves publication loss separately from committed records");
        Check(SaveObservationJson(closed + L"\\session.knledger", ledgerJson, &error), "closure ledger atomically saved");
        const auto completeInventory = QueryEvidenceDirectory(closed);
        Check(completeInventory.Status == L"ok" && completeInventory.UnclosedCollections == 0 &&
            completeInventory.Sessions.size() == 1 && completeInventory.UnavailableWrittenBundles == 0 &&
            EvidenceQueryJson(completeInventory, {}).find(L"\"publication_closure_known\":true") != std::wstring::npos,
            "closed collection reconciles existing published bundles");
        Check(DeleteFileW((closed + L"\\case.kncase").c_str()) != FALSE, "owned missing-bundle control removed");
        const auto missing = QueryEvidenceDirectory(closed);
        Check(missing.Status == L"partial_inventory" && missing.UnavailableWrittenBundles == 1 && missing.Matched == 0,
            "deleted published bytes cannot become a clean empty collection");
        const auto empty = directory + L"\\empty";
        Check(CreateDirectoryW(empty.c_str(), nullptr) != FALSE &&
            EvidenceQueryJson(QueryEvidenceDirectory(empty), {}).find(L"\"publication_closure_known\":false") != std::wstring::npos,
            "empty directory without any session cannot establish publication closure");
        ledger.Written = 2;
        Check(EvidenceSessionJson(ledger).empty(), "closure cannot report more writes than admissions");
        ledger = {L"test", UINT64_MAX, UINT64_MAX, 0, 0, 1};
        Check(EvidenceSessionJson(ledger).empty(), "impossible closure counts cannot overflow missing-byte accounting");
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring(argv[1]) == L"--read")
    {
        EvidenceBundle bundle;
        std::wstring error;
        std::vector<uint8_t> bytes;
        return LoadEvidenceBundle(argv[2], &bundle, &error) && EvidenceRead(bundle, 0x11000, 32, &bytes) &&
            bytes[0] == 0xc3 ? 0 : 2;
    }
    if (argc == 3 && std::wstring(argv[1]) == L"--publish")
    {
        auto bundle = Fixture();
        for (size_t i = 2; i < EvidenceBundleMaxSpans; ++i)
        {
            bundle.Spans.push_back({0x20000 + i * 4096, 4096, L"target_page", L"valid", std::vector<uint8_t>(4096, 0x90)});
        }
        std::wstring error;
        return SaveEvidenceBundle(argv[2], bundle, &error) ? 0 : 2;
    }
    if (argc != 2) { return 2; }
    Tests(argv[1]);
    std::cout << "[evidence.selftest] passed=" << Passed << " failed=" << Failed << " corpus=synthetic\n";
    return Failed == 0 ? 0 : 1;
}
