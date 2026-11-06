#include "../user/EvidenceJournal.h"
#include "../user/EvidenceStore.h"
#include "../user/EvidenceRetention.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include "../user/McpJson.h"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;
namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool ok, const char* name)
    {
        if (ok) { ++Passed; }
        else { ++Failed; std::cerr << "[journal.selftest] FAIL " << name << '\n'; }
    }
    bool Write(const fs::path& path, const std::vector<uint8_t>& bytes)
    {
        fs::create_directories(path.parent_path());
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return file.good();
    }
    void Stage(const std::wstring& selected, const wchar_t* current)
    {
        if (selected == current)
        {
            std::wcout << L"[journal.stage] " << current << std::endl;
            std::string input;
            std::getline(std::cin, input); // Parent observes this exact stage before terminating us.
            ExitProcess(91); // No continuation if the parent closes its pipe unexpectedly.
        }
    }
    const std::vector<uint8_t> Blob{0x4d, 0x5a, 0, 0, 0x7f}; // Non-executable storage fixture.
    EvidenceJournalMember BlobMember()
    {
        const auto digest = ContentHash::Bytes(Blob);
        return {L"image-references/" + digest + L".knblob", digest, L"raw.bytes", Blob.size()};
    }
    EvidenceJournalTransaction Batch(const fs::path& root, const std::wstring& id, const std::wstring& stage = L"", const std::wstring& collection = L"7")
    {
        EvidenceJournalTransaction t;
        t.Kind = L"image_reads"; t.Id = id;
        const auto blob = BlobMember();
        if (!fs::exists(root / blob.Path)) { Check(Write(root / blob.Path, Blob), "publish-owned-reference"); }
        t.Members.push_back(blob);
        Stage(stage, L"raw");
        const auto prefix = L"image-reads/reads-" + collection + L"-" + id;
        for (const auto& suffix : {L".knreads", L".knslice"})
        {
            const auto schema = std::wstring(suffix) == L".knreads" ? L"kn.image_reads.v3" : L"kn.image_slice.v2";
            const auto json = L"{\"schema\":" + mcpjson::Quote(schema) + L",\"fixture_id\":" + mcpjson::Quote(id) + L"}";
            fs::create_directories(root / L"image-reads");
            Check(SaveObservationJson((root / (prefix + suffix)).wstring(), json, nullptr), "publish-owned-json");
            t.Members.push_back(EvidenceJournalJsonMember(prefix + suffix, json));
            Stage(stage, std::wstring(suffix) == L".knreads" ? L"readset" : L"recipe");
        }
        return t;
    }
    EvidenceJournalTransaction Sweep(const fs::path& root, const std::wstring& collection = L"7")
    {
        EvidenceJournalTransaction t;
        t.Kind = L"image_sweep"; t.Id = L"1";
        const std::wstring json = L"{\"schema\":\"kn.image_sweep.v1\",\"fixture\":\"membership_only_not_replay\"}";
        fs::create_directories(root / L"image-sweeps");
        const auto path = L"image-sweeps/sweep-" + collection + L"-1.knsweep";
        Check(SaveObservationJson((root / path).wstring(), json, nullptr), "publish-owned-sweep-root");
        t.Members.push_back(EvidenceJournalJsonMember(path, json));
        t.Requires = {BlobMember().Path, L"image-reads/reads-" + collection + L"-1.knreads", L"image-reads/reads-" + collection + L"-1.knslice"};
        return t;
    }
    EvidenceJournalTransaction Closure(const fs::path& root, const std::wstring& collection = L"7")
    {
        EvidenceJournalTransaction t;
        t.Kind = L"closure"; t.Id = L"0";
        const std::wstring json = L"{\"schema\":\"kn.image_read_session.v1\",\"queued\":1,\"written\":1}";
        fs::create_directories(root / L"image-reads");
        const auto path = L"image-reads/session-" + collection + L".knreadledger";
        Check(SaveObservationJson((root / path).wstring(), json, nullptr), "publish-owned-closure-ledger");
        t.Members.push_back(EvidenceJournalJsonMember(path, json));
        return t;
    }
    int Produce(const fs::path& root, const std::wstring& stage, const std::wstring& collection = L"7", bool repeat = false)
    {
        EvidenceJournal journal;
        std::wstring error;
        if (!journal.Open(root.wstring(), collection, &error)) { return 1; }
        Stage(stage, L"session");
        auto batch = Batch(root, L"1", stage, collection);
        if (stage == L"journal_before_index")
        {
            Check(Write(root / L"collections/7/indexes", {0x78}), "owned-index-blocker");
        }
        const auto commit = journal.Commit(batch);
        Check(commit.Committed && (stage == L"journal_before_index" ? !commit.Indexed : commit.Indexed), "commit-original-files-before-index");
        Stage(stage, L"journal_before_index");
        Stage(stage, L"index");
        if (repeat) { Check(journal.Commit(Batch(root, L"2", L"", collection)).Committed, "repeat-reference-within-collection"); }
        auto sweep = Sweep(root, collection);
        Stage(stage, L"sweep_file");
        Check(journal.Commit(sweep).Committed, "commit-dependent-sweep");
        Stage(stage, L"sweep_commit");
        auto closure = Closure(root, collection);
        Stage(stage, L"ledger_file");
        Check(journal.Commit(closure).Committed && journal.State().Closed, "commit-closure");
        Stage(stage, L"closure");
        return Failed ? 1 : 0;
    }
    void Tests(const fs::path& root)
    {
        fs::create_directories(root);
        std::wstring error;
        EvidenceJournalTransaction original;
        {
            EvidenceJournal invalid;
            Check(!invalid.Open(root.wstring() + std::wstring(L"\0ignored", 8), L"7", &error) && error == L"invalid_artifact_root",
                "embedded-null-denied-before-path-resolution");
        }
        {
            EvidenceJournal journal;
            Check(journal.Open(root.wstring(), L"7", &error), "create-session");
            Check(InspectEvidenceStore(root.wstring()).Issue == L"store_busy", "store-inspection-excludes-live-journal");
            Check(RecoverEvidenceJournal((root / L"collections/7").wstring()).Issue == L"collection_busy_or_lock_unavailable",
                "recovery-does-not-mislabel-active-writer-as-final");
            EvidenceJournal competitor;
            Check(!competitor.Open(root.wstring(), L"7", &error), "second-writer-denied");
            original = Batch(root, L"1");
            auto invalid = original;
            invalid.Members[0].Path = L"image-references/../outside.knblob";
            Check(!journal.Commit(invalid).Committed, "reject-parent-path");
            invalid = original; invalid.Members[1].Sha256[0] = invalid.Members[1].Sha256[0] == L'0' ? L'1' : L'0';
            Check(!journal.Commit(invalid).Committed, "reject-original-hash-mismatch");
            invalid = original; invalid.Members[1].Schema = L"kn.image_reads.v1";
            Check(!journal.Commit(invalid).Committed, "reject-artifact-schema-mismatch");
            invalid = original; invalid.Members[1].Bytes += 1;
            Check(!journal.Commit(invalid).Committed, "reject-physical-size-mismatch");
            invalid = original; invalid.Requires.push_back(L"image-reads/reads-7-9.knreads");
            Check(!journal.Commit(invalid).Committed, "reject-uncommitted-dependency");
            invalid = original; invalid.Members.push_back(invalid.Members[0]);
            Check(!journal.Commit(invalid).Committed, "reject-duplicate-member");
            Check(journal.State().CommittedSegments == 0, "failures-publish-no-records");
            const auto first = journal.Commit(original);
            Check(first.Committed && first.Indexed && first.Sequence == 1, "first-commit");
            Check(!DeleteFileW((root / BlobMember().Path).c_str()) && GetLastError() == ERROR_SHARING_VIOLATION,
                "committed-reference-lease-survives-caller");
            Check(!DeleteFileW((root / L"collections/7/journal-segments/00000000000000000001.knjseg").c_str()) &&
                GetLastError() == ERROR_SHARING_VIOLATION, "committed-segment-lease");
            const auto repeated = journal.Commit(original);
            Check(repeated.Committed && repeated.AlreadyCommitted && journal.State().CommittedSegments == 1, "exact-retry-does-not-duplicate");
            invalid = original; invalid.Members.pop_back();
            Check(!journal.Commit(invalid).Committed, "conflicting-id-rejected");
            Check(journal.Commit(Batch(root, L"2")).Committed, "repeated-reference-member");
        }
        const auto prefix = RecoverEvidenceJournal((root / L"collections/7").wstring());
        Check(prefix.Status == L"verified_prefix" && !prefix.Closed && prefix.CanResume && prefix.CommittedSegments == 2 &&
            prefix.UniquePaths == 5 && prefix.MemberReferences == 6 && prefix.LogicalBytes - prefix.UniqueContentBytes == Blob.size(),
            "recovery-restores-exact-collection-dedup-denominators");
        {
            EvidenceJournal resumed;
            Check(resumed.Open(root.wstring(), L"7", &error), "restart-resumes-verified-prefix");
            Check(resumed.Commit(original).AlreadyCommitted, "restart-exact-retry");
            Check(resumed.Commit(Sweep(root)).Committed, "restart-appends-dependent-sweep");
            auto closure = Closure(root);
            const auto closed = resumed.Commit(closure);
            Check(closed.Committed && closed.Indexed && resumed.State().Closed && !resumed.State().CanResume, "closure-is-a-committed-record");
            Check(resumed.Commit(closure).AlreadyCommitted, "closure-idempotent-retry");
            auto next = original; next.Id = L"3";
            Check(!resumed.Commit(next).Committed, "append-after-closure-denied");
        }
        auto final = RecoverEvidenceJournal((root / L"collections/7").wstring(), true);
        Check(RecoverEvidenceJournal((root / L"collections/7").wstring() + std::wstring(L"\0ignored", 8)).Issue ==
            L"invalid_collection_directory", "recovery-rejects-null-suffixed-valid-directory");
        Check(final.Status == L"verified_prefix" && final.Closed && final.CommittedSegments == 4 && final.UniquePaths == 7 &&
            final.MemberReferences == 8 && final.SweepPaths.size() == 1 && final.IndexStatus == L"ready" && final.IndexReused == 5 &&
            final.IndexCreated == 0, "closed-recovery-and-index-reuse");
        Check(Write(root / L"image-reads/reads-7-99.knreads", {0x7b, 0x7d}), "publish-orphan");
        final = RecoverEvidenceJournal((root / L"collections/7").wstring());
        Check(final.UniquePaths == 7 && final.CommittedSegments == 4, "orphan-file-never-becomes-collection-member");
        std::wcout << EvidenceJournalRecoveryJson(final) << '\n';
        {
            EvidenceStoreLease barrier, failed;
            Check(barrier.Acquire(root.wstring(), true, &error), "exclusive-store-barrier-after-journal-release");
            Check(!failed.Acquire(root.wstring(), false, &error) && error == L"store_busy", "publisher-excluded-before-files");
            Check(!barrier.Acquire(root.wstring(), true, &error) && error == L"store_lease_already_owned" &&
                InspectEvidenceStore(root.wstring()).Issue == L"store_busy", "failed-reacquire-keeps-original-lease");
        }
        EvidenceStoreLease invalid;
        Check(!invalid.Acquire(root.wstring() + std::wstring(L"\0tail", 5), false, &error) && error == L"invalid_store_root",
            "store-rejects-null-root");
        Check(InspectEvidenceStore(root.wstring()).Status == L"partial", "invalid-orphan-keeps-store-partial");
        {
            EvidenceStoreInventory bounded;
            EvidenceStoreArtifact artifact;
            artifact.Artifact = BlobMember(); artifact.Verified = true;
            artifact.Retention = L"committed_reference_protected";
            artifact.Collections = {L"12345678901234567890"};
            bounded.Artifacts.assign(65536, artifact);
            const auto json = EvidenceStoreInventoryJson(bounded, true);
            std::wstring omitted;
            Check(json.size() < 16 * 1024 * 1024 + 4096 && mcpjson::ValidateDocument(json) &&
                mcpjson::GetString(json, L"artifact_rows_omitted", &omitted) && std::stoull(omitted) > 0,
                "bounded-detail-output-reports-omitted-artifacts");
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if ((argc == 5 || argc == 6) && std::wstring(argv[1]) == L"--gc")
        {
            const std::wstring stage = argc == 6 ? argv[5] : L"";
            const auto result = CollectEvidenceStore(argv[2], argv[3], std::wstring(argv[4]) == L"-" ? L"" : argv[4],
                [&](const wchar_t* current) { Stage(stage, current); });
            std::wcout << EvidenceGcResultJson(result) << '\n';
            return result.Status == L"planned" || result.Status == L"completed" ? 0 : 1;
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--store")
        {
            const auto result = InspectEvidenceStore(argv[2]);
            std::wcout << EvidenceStoreInventoryJson(result, true) << '\n';
            return result.Status == L"verified" ? 0 : 1;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--store-hold")
        {
            EvidenceStoreLease lease;
            std::wstring error;
            if (!lease.Acquire(argv[2], std::wstring(argv[3]) == L"exclusive", &error, true)) { return 1; }
            Stage(L"store_held", L"store_held");
            return 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--produce-collection") { return Produce(argv[2], L"", argv[3], true); }
        if (argc >= 3 && std::wstring(argv[1]) == L"--recover")
        {
            const auto r = RecoverEvidenceJournal(argv[2], argc == 4 && std::wstring(argv[3]) == L"--index");
            std::wcout << EvidenceJournalRecoveryJson(r) << '\n';
            return r.Status == L"verified_prefix" && r.IndexStatus != L"failed" ? 0 : 1;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--produce") { return Produce(argv[2], argv[3]); }
        if (argc == 3 && std::wstring(argv[1]) == L"--resume")
        {
            EvidenceJournal journal;
            std::wstring error;
            if (!journal.Open(argv[2], L"7", &error)) { return 1; }
            // A fresh transaction uses files not included in any previous record.
            auto next = Batch(argv[2], L"99");
            const auto result = journal.Commit(next);
            std::wcout << L"{\"committed\":" << (result.Committed ? L"true" : L"false") << L",\"sequence\":\"" << result.Sequence << L"\"}\n";
            return result.Committed ? 0 : 1;
        }
        if (argc != 2) { return 2; }
        Tests(argv[1]);
        std::cout << "[journal.selftest] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed ? 1 : 0;
    }
    catch (const std::exception& e) { std::cerr << "[journal.selftest] exception=" << e.what() << '\n'; return 1; }
}
