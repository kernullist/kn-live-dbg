#include "../user/EvidenceJournal.h"
#include "../user/ImageSweepManifest.h"
#include "../user/EvidenceStore.h"
#include "../user/EvidenceRetention.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include "../user/McpJson.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <map>
#include <set>

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
    std::wstring BatchPayload(const std::wstring& id, bool slice)
    {
        const auto ref = mcpjson::Quote(BlobMember().Sha256);
        return L"{\"fixture_id\":" + mcpjson::Quote(id) + (slice ? L",\"reference_sha256\":" + ref + L"}" :
            L",\"reference\":{\"sha256\":" + ref + L",\"persistence\":\"committed\",\"bytes\":" + std::to_wstring(Blob.size()) + L"}}");
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
            const bool slice = std::wstring(suffix) == L".knslice";
            const auto payload = BatchPayload(id, slice);
            const auto json = L"{\"schema\":" + mcpjson::Quote(slice ? L"kn.image_slice.v2" : L"kn.image_reads.v3") +
                (slice ? L",\"recipe_sha256\":" : L",\"payload_sha256\":") + mcpjson::Quote(EvidenceJournalJsonMember(L"", payload).Sha256) +
                L",\"payload\":" + payload + L"}";
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
        ImageSweepManifest manifest;
        auto& sweep = manifest.Sweep;
        sweep.CollectionId = collection; sweep.SweepId = collection + L"-1"; sweep.Image = L"owned";
        sweep.TargetId = L"fixture"; sweep.AddressSpaceId = L"owned-space"; sweep.Identity.BootId = L"owned-boot";
        sweep.ImageBase = 4096; sweep.ExpectedBytes = 1; sweep.TotalRanges = 1; sweep.StartedFileTime = 1;
        manifest.ObservedSlices = 1; manifest.EndReason = L"fixture"; manifest.LastEndedTick = 1;
        ImageSweepSlice row;
        row.Ordinal = row.ReadSetId = row.ObservedFileTime = row.EndedTick = 1; row.RangeCount = 1; row.Reason = L"fixture";
        row.ReferenceWritten = row.RawWritten = row.RecipeWritten = true; row.ReferenceSha256 = BlobMember().Sha256;
        row.RawPayloadSha256 = EvidenceJournalJsonMember(L"", BatchPayload(L"1", false)).Sha256;
        row.RecipeSha256 = EvidenceJournalJsonMember(L"", BatchPayload(L"1", true)).Sha256;
        manifest.Slices.push_back(std::move(row));
        const auto json = ImageSweepManifestJson(manifest);
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
    EvidenceJournalTransaction Irp(const fs::path& root, const std::wstring& collection, const std::wstring& stage = L"",
        size_t padding = 0)
    {
        EvidenceJournalTransaction t;
        t.Kind = L"irp_capture";
        auto blob = BlobMember();
        blob.Path = L"irp-reference-" + blob.Sha256 + L".knblob";
        if (!fs::exists(root / blob.Path)) { Check(Write(root / blob.Path, Blob), "publish-owned-irp-reference"); }
        t.Members.push_back(blob);
        Stage(stage, L"irp_reference");
        const auto identity = L"{\"image_sha256\":" + mcpjson::Quote(blob.Sha256) + L"}";
        const auto package = L"{\"schema\":\"kn.type_schema.v1\",\"package_sha256\":" +
            mcpjson::Quote(EvidenceJournalJsonMember(L"", identity).Sha256) + L",\"payload\":" + identity + L"}";
        const auto json = L"{\"schema\":\"kn.irp_capture.v2\",\"fixture\":\"membership_only_not_replay\",\"reference_captured_bytes\":" +
            mcpjson::Quote(std::to_wstring(blob.Bytes)) + L",\"schemas\":[" + package + L"," + package + L"," + package + L"],\"padding\":\"" +
            std::wstring(padding, L'x') + L"\"}";
        auto member = EvidenceJournalJsonMember(L"", json);
        t.Id = member.Sha256;
        member.Path = L"irp-" + collection + L"-" + t.Id + L".knirp";
        if (!fs::exists(root / member.Path)) { Check(SaveObservationJson((root / member.Path).wstring(), json, nullptr), "publish-owned-irp-capture"); }
        t.Members.push_back(member);
        Stage(stage, L"irp_capture");
        return t;
    }
    int CommitPublishedScopes(const fs::path& root, const std::wstring& stage, const std::wstring& version)
    {
        EvidenceJournal journal;
        std::wstring error;
        const auto policy = version == L"3" ? EvidenceJournalPolicy::ImageClaimsAndIrpV3 :
            version == L"2" ? EvidenceJournalPolicy::ImageAndIrpV2 : EvidenceJournalPolicy::ImageV1;
        if (!journal.Open(root.wstring(), L"7", &error, policy)) { return 1; }
        Stage(stage, L"scope_files");
        std::vector<EvidenceJournalMember> references;
        for (const auto& entry : fs::directory_iterator(root / L"image-references"))
        {
            if (entry.path().extension() != L".knblob") { continue; }
            references.push_back({L"image-references/" + entry.path().filename().wstring(), ContentHash::File(entry.path().wstring()),
                L"raw.bytes", fs::file_size(entry.path())});
        }
        std::map<std::wstring, EvidenceJournalTransaction> batches;
        std::set<std::wstring> dependencies;
        for (const auto& entry : fs::directory_iterator(root / L"image-reads"))
        {
            const auto name = entry.path().stem().wstring(), ext = entry.path().extension().wstring();
            if (name.rfind(L"reads-7-", 0) != 0 || (ext != L".knslice" && ext != L".knreads")) { continue; }
            std::wstring json;
            if (!ReadAnalystSnapshot(entry.path().wstring(), &json, nullptr, 2 * 1024 * 1024, nullptr, true)) { return 1; }
            const auto id = name.substr(8);
            auto& batch = batches[id]; batch.Kind = L"image_reads"; batch.Id = id;
            batch.Members.push_back(EvidenceJournalJsonMember(L"image-reads/" + entry.path().filename().wstring(), json));
        }
        for (auto& item : batches)
        {
            auto& batch = item.second;
            batch.Members.insert(batch.Members.end(), references.begin(), references.end());
            if (!journal.Commit(batch).Committed) { return 1; }
            for (const auto& member : batch.Members) { dependencies.insert(member.Path); }
        }
        Stage(stage, L"scope_reads");
        std::wstring manifest;
        const std::wstring path = L"image-sweeps/sweep-7-1.knsweep";
        if (!ReadAnalystSnapshot((root / path).wstring(), &manifest, nullptr, 2 * 1024 * 1024, nullptr, true)) { return 1; }
        EvidenceJournalTransaction sweep;
        sweep.Kind = L"image_sweep"; sweep.Id = L"1";
        sweep.Members.push_back(EvidenceJournalJsonMember(path, manifest));
        sweep.Requires.assign(dependencies.begin(), dependencies.end());
        if (!journal.Commit(sweep).Committed) { return 1; }
        Stage(stage, L"scope_sweep");
        if (!journal.Commit(Closure(root)).Committed) { return 1; }
        Stage(stage, L"scope_closed");
        return 0;
    }
    EvidenceJournalTransaction IrpLedger(const fs::path& root, const std::wstring& collection)
    {
        EvidenceJournalTransaction t;
        t.Kind = L"irp_ledger"; t.Id = L"0";
        const std::wstring json = L"{\"schema\":\"kn.irp_capture_session.v1\",\"fixture\":\"includes_failures\"}";
        const auto path = L"irp-session-" + collection + L".knirpledger";
        Check(SaveObservationJson((root / path).wstring(), json, nullptr), "publish-owned-irp-ledger");
        t.Members.push_back(EvidenceJournalJsonMember(path, json));
        return t;
    }
    int ProduceIrp(const fs::path& root, const std::wstring& collection, const std::wstring& stage)
    {
        EvidenceJournal journal;
        std::wstring error;
        if (!journal.Open(root.wstring(), collection, &error, EvidenceJournalPolicy::ImageAndIrpV2)) { return 1; }
        Stage(stage, L"irp_session");
        const auto capture = Irp(root, collection, stage);
        Check(journal.Commit(capture).Committed, "commit-irp-capture-and-reference");
        Stage(stage, L"irp_commit");
        const auto ledger = IrpLedger(root, collection);
        Stage(stage, L"irp_ledger_file");
        Check(journal.Commit(ledger).Committed, "commit-irp-ledger");
        Stage(stage, L"irp_ledger_commit");
        auto closure = Closure(root, collection);
        closure.Requires.push_back(ledger.Members[0].Path);
        Stage(stage, L"irp_closure_file");
        Check(journal.Commit(closure).Committed && journal.State().Closed, "close-after-irp-ledger");
        Stage(stage, L"irp_closed");
        return Failed ? 1 : 0;
    }
    int CommitPublishedIrp(const fs::path& root, const std::wstring& stage, const std::wstring& version)
    {
        const auto policy = version == L"4" ? EvidenceJournalPolicy::ImageAndIrpClaimsV4 :
            version == L"3" ? EvidenceJournalPolicy::ImageClaimsAndIrpV3 :
            version == L"2" ? EvidenceJournalPolicy::ImageAndIrpV2 : EvidenceJournalPolicy::ImageV1;
        EvidenceJournal journal;
        std::wstring error;
        if (!journal.Open(root.wstring(), L"7", &error, policy)) { return 1; }
        EvidenceJournalTransaction transaction;
        transaction.Kind = L"irp_capture";
        for (const auto& entry : fs::directory_iterator(root))
        {
            const auto name = entry.path().filename().wstring();
            if (entry.path().extension() == L".knirp")
            {
                std::wstring json;
                if (!ReadAnalystSnapshot(entry.path().wstring(), &json, nullptr, 16 * 1024 * 1024, nullptr, true)) { return 1; }
                auto member = EvidenceJournalJsonMember(name, json);
                transaction.Id = member.Sha256;
                transaction.Members.push_back(std::move(member));
            }
            else if (name.rfind(L"irp-reference-", 0) == 0 && entry.path().extension() == L".knblob")
            {
                transaction.Members.push_back({name, ContentHash::File(entry.path().wstring()), L"raw.bytes", fs::file_size(entry.path())});
            }
        }
        Stage(stage, L"irp_claim_files");
        if (!journal.Commit(transaction).Committed) { return 1; }
        Stage(stage, L"irp_claim_commit");
        const auto ledger = IrpLedger(root, L"7");
        if (!journal.Commit(ledger).Committed) { return 1; }
        Stage(stage, L"irp_claim_ledger");
        auto closure = Closure(root);
        closure.Requires.push_back(ledger.Members[0].Path);
        if (!journal.Commit(closure).Committed) { return 1; }
        Stage(stage, L"irp_claim_closed");
        return 0;
    }
    void TypedTests(const fs::path& root)
    {
        fs::create_directories(root);
        std::wstring error;
        {
            EvidenceJournal legacy;
            Check(legacy.Open((root / L"legacy").wstring(), L"7", &error), "legacy-session-policy");
            Check(!legacy.Commit(Irp(root / L"legacy", L"7")).Committed, "legacy-policy-rejects-irp-kind");
        }
        const auto typed = root / L"typed";
        {
            EvidenceJournal journal;
            Check(journal.Open(typed.wstring(), L"7", &error, EvidenceJournalPolicy::ImageAndIrpV2), "typed-session-policy");
            const auto capture = Irp(typed, L"7", L"", 2 * 1024 * 1024);
            auto invalid = capture;
            invalid.Members.pop_back();
            Check(!journal.Commit(invalid).Committed, "irp-root-required");
            invalid = capture; invalid.Id = std::wstring(64, L'0');
            Check(!journal.Commit(invalid).Committed, "irp-id-is-exact-capture-hash");
            invalid = capture; invalid.Members.back().Bytes = 16 * 1024 * 1024 + 1;
            Check(!journal.Commit(invalid).Committed, "irp-specific-byte-limit");
            invalid = capture; invalid.Members.back().Path = L"irp-8-" + invalid.Id + L".knirp";
            Check(!journal.Commit(invalid).Committed, "irp-foreign-collection-rejected");
            invalid = capture; invalid.Members.front() = BlobMember();
            Check(!journal.Commit(invalid).Committed, "image-reference-in-irp-kind-rejected");
            Check(journal.Commit(capture).Committed, "irp-over-two-MiB-within-typed-limit");
            Check(journal.Commit(capture).AlreadyCommitted, "irp-idempotent-exact-transaction");
            unsigned checkedFiles = 0;
            Check(!journal.RestrictOutputs([&](HANDLE) { return ++checkedFiles == 1; }) && checkedFiles == 2,
                "joining-private-journal-checks-existing-pinned-files");
            Check(journal.RestrictOutputs([](HANDLE) { return true; }), "successful-output-admission-installed");
            auto closure = Closure(typed);
            Check(!journal.Commit(closure).Committed, "typed-closure-requires-irp-ledger");
            auto ledger = IrpLedger(typed, L"7");
            Check(journal.Commit(ledger).Committed, "irp-final-ledger-committed");
            Check(!journal.Commit(Irp(typed, L"7")).Committed, "new-irp-after-ledger-rejected");
            Check(!journal.Commit(closure).Committed, "closure-must-name-ledger-dependency");
            closure.Requires.push_back(ledger.Members[0].Path);
            Check(journal.Commit(closure).Committed, "typed-closure-with-ledger-dependency");
        }
        Check(RecoverEvidenceJournal((typed / L"collections/7").wstring(), true).Closed, "recover-typed-journal-and-index");
        {
            EvidenceJournal legacy;
            Check(!legacy.Open(typed.wstring(), L"7", &error), "cannot-reopen-typed-session-as-legacy");
        }
        {
            const auto admitted = root / L"admission";
            EvidenceJournal journal;
            unsigned calls = 0;
            const auto emptyFile = [&](HANDLE file)
            {
                LARGE_INTEGER size{};
                ++calls;
                return GetFileSizeEx(file, &size) && size.QuadPart == 0;
            };
            Check(!journal.Open(admitted.wstring(), L"7", &error, EvidenceJournalPolicy::ImageAndIrpV2, emptyFile) &&
                calls == 2 && error == L"session_missing_or_invalid", "admission-before-write-and-on-verified-read");
        }
        for (bool throws : {false, true})
        {
            const auto denied = root / (throws ? L"throw" : L"deny");
            fs::create_directories(denied);
            Check(!SaveObservationJson((denied / L"test.json").wstring(), L"{}", nullptr, [&](HANDLE)
                { if (throws) { throw std::runtime_error("owned admission exception"); } return false; }) &&
                fs::is_empty(denied), "failed-output-admission-leaves-no-pending-file");
        }
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
            auto omitted = original;
            omitted.Members.erase(omitted.Members.begin());
            Check(journal.Commit(omitted).Issue == L"image_reference_not_committed", "declared-read-reference-must-be-in-batch");
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
            const auto sweep = Sweep(root);
            auto omitted = sweep;
            omitted.Requires.pop_back();
            Check(resumed.Commit(omitted).Issue == L"image_sweep_input_not_committed", "sweep-requires-every-written-input");
            auto extra = sweep;
            extra.Requires.push_back(L"image-reads/reads-7-2.knreads");
            Check(resumed.Commit(extra).Issue == L"image_sweep_dependency_set_mismatch", "sweep-rejects-unrelated-committed-input");
            Check(resumed.Commit(sweep).Committed, "restart-appends-dependent-sweep");
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
            bounded.Status = L"verified";
            bounded.CatalogSha256 = bounded.ArtifactsSha256 = artifact.Artifact.Sha256;
            const auto json = EvidenceStoreInventoryJson(bounded, true);
            std::wstring omitted, cursor;
            Check(json.size() < 16 * 1024 * 1024 + 4096 && mcpjson::ValidateDocument(json) &&
                mcpjson::GetString(json, L"artifact_rows_omitted", &omitted) && std::stoull(omitted) > 0,
                "bounded-detail-output-reports-omitted-artifacts");
            bool ready = false;
            Check(mcpjson::GetString(json, L"next_artifact_cursor", &cursor) && !cursor.empty(), "size-limited-detail-offers-continuation");
            const auto tail = EvidenceStoreInventoryJson(bounded, {true, 0, cursor}, &ready);
            std::wstring count, state;
            Check(ready && mcpjson::GetString(tail, L"artifact_rows_emitted", &count) && count == omitted &&
                mcpjson::GetString(tail, L"artifact_page_status", &state) && state == L"complete", "default-detail-tail-covers-every-omitted-row");
        }
        {
            EvidenceStoreInventory oversized;
            oversized.Status = L"verified";
            EvidenceStoreArtifact artifact;
            artifact.Retention.assign(16 * 1024 * 1024, L'x');
            oversized.Artifacts.push_back(std::move(artifact));
            bool ready = true;
            const auto json = EvidenceStoreInventoryJson(oversized, {true, 1, {}}, &ready);
            std::wstring state, cursor;
            Check(!ready && mcpjson::GetString(json, L"artifact_page_status", &state) && state == L"row_exceeds_budget" &&
                mcpjson::GetString(json, L"next_artifact_cursor", &cursor) && cursor.empty(), "oversize-row-cannot-issue-a-nonadvancing-cursor");
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        if ((argc == 5 || argc == 6) && std::wstring(argv[1]) == L"--retire-collection")
        {
            const std::wstring stage = argc == 6 ? argv[5] : L"";
            const auto result = RetireEvidenceCollection(argv[2], argv[3], std::wstring(argv[4]) == L"apply",
                [&](const wchar_t* current) { Stage(stage, current); });
            std::cout << mcpjson::WideToUtf8(EvidenceRetirementResultJson(result)) << std::endl;
            if (!std::cout) { return 3; }
            return result.Status == L"planned" || result.Status == L"retired" ? 0 : 1;
        }
        if ((argc == 5 || argc == 6) && std::wstring(argv[1]) == L"--gc")
        {
            const std::wstring stage = argc == 6 ? argv[5] : L"";
            const auto result = CollectEvidenceStore(argv[2], argv[3], std::wstring(argv[4]) == L"-" ? L"" : argv[4],
                [&](const wchar_t* current) { Stage(stage, current); });
            std::wcout << EvidenceGcResultJson(result) << '\n';
            return result.Status == L"planned" || result.Status == L"completed" ? 0 : 1;
        }
        if (argc >= 3 && (std::wstring(argv[1]) == L"--store" || std::wstring(argv[1]) == L"--hold-scan"))
        {
            std::vector<std::wstring> flags(argv + 3, argv + argc);
            if (std::none_of(flags.begin(), flags.end(), [](const auto& flag) {
                return _wcsicmp(flag.c_str(), L"/scan-catalog") == 0 || _wcsicmp(flag.c_str(), L"/scan-files") == 0 || _wcsicmp(flag.c_str(), L"/artifacts") == 0;
            })) { flags.emplace_back(L"/artifacts"); }
            EvidenceStorePageOptions page;
            if (!ParseEvidenceStorePageOptions(flags, &page)) { return 2; }
            bool ready = false;
            bool hold = std::wstring(argv[1]) == L"--hold-scan";
            if (hold && !page.ScanCatalog && !page.ScanFiles && page.FileReceipt.empty()) { return 2; }
            const auto output = QueryEvidenceStore(argv[2], page, &ready, [&](const wchar_t* stage)
            {
                if (!hold) { return; }
                hold = false;
                std::cout << "[journal.stage] " << mcpjson::WideToUtf8(stage) << std::endl;
                std::string input;
                if (!std::getline(std::cin, input) || input != "continue") { ExitProcess(91); }
            });
            std::cout << mcpjson::WideToUtf8(output) << std::endl;
            if (!std::cout) { return 3; }
            return ready ? 0 : 1;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--store-hold")
        {
            EvidenceStoreLease lease;
            std::wstring error;
            if (!lease.Acquire(argv[2], std::wstring(argv[3]) == L"exclusive", &error, true)) { return 1; }
            Stage(L"store_held", L"store_held");
            return 0;
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--produce-catalog")
        {
            const fs::path root(argv[2]);
            if (!fs::create_directory(root)) { return 2; }
            for (unsigned n = 1; n <= 1025; ++n)
            {
                const auto id = std::to_wstring(n);
                if (n <= 2) { if (Produce(root, L"", id, true)) { return 1; } }
                else
                {
                    EvidenceJournal journal;
                    std::wstring issue;
                    if (!journal.Open(root.wstring(), id, &issue) || !journal.Commit(Closure(root, id)).Committed) { return 1; }
                }
            }
            return Failed ? 1 : 0;
        }
        if (argc == 4 && std::wstring(argv[1]) == L"--produce-collection") { return Produce(argv[2], L"", argv[3], true); }
        if (argc == 5 && std::wstring(argv[1]) == L"--produce-irp") { return ProduceIrp(argv[2], argv[3], argv[4]); }
        if (argc == 5 && std::wstring(argv[1]) == L"--commit-published") { return CommitPublishedScopes(argv[2], argv[3], argv[4]); }
        if (argc == 5 && std::wstring(argv[1]) == L"--commit-published-irp") { return CommitPublishedIrp(argv[2], argv[3], argv[4]); }
        if (argc >= 3 && std::wstring(argv[1]) == L"--recover")
        {
            const auto r = RecoverEvidenceJournal(argv[2], argc == 4 && std::wstring(argv[3]) == L"--index");
            std::wcout << EvidenceJournalRecoveryJson(r) << '\n';
            return (r.Status == L"verified_prefix" && r.IndexStatus != L"failed") ||
                (r.Status == L"retired" && r.IndexStatus == L"not_requested") ? 0 : 1;
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
        TypedTests(fs::path(argv[1]) / L"typed-controls");
        std::cout << "[journal.selftest] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed ? 1 : 0;
    }
    catch (const std::exception& e) { std::cerr << "[journal.selftest] exception=" << e.what() << '\n'; return 1; }
}
