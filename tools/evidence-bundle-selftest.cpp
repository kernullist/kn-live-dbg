#include "../user/EvidenceBundle.h"
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
