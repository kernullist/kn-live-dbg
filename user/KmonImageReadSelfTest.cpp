#include "KernelMonitor.h"
#include "ObservationReadRoutingJson.h"
#include "ContentHash.h"
#include "ImageSliceRecipe.h"
#include "ImageScopeClaimPublication.h"
#include "ImageSweepGraph.h"
#include "EvidencePrivacy.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace
{
    constexpr uint64_t Base = 0x180000000ull;
    class Source final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::vector<uint8_t> Bytes;
        std::vector<std::pair<uint64_t, uint32_t>> Calls;
        bool Partial = false, Fail = false, Unstable = false;
        uint64_t FailAddress = 0;
        size_t PageReads = 0;
        explicit Source(const wchar_t* id)
        {
            Caps.SourceId = id;
            Caps.Consistency = L"synthetic_non_atomic";
            Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4);
            Caps.UserOnly = true;
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            Calls.emplace_back(request.Address, request.Length);
            ObservationReadResult result;
            result.NativeStatusDomain = L"win32";
            result.NativeStatus = Partial || Fail ? 299 : 0;
            if (Partial && request.Length > 16)
            {
                result.Spans = {{request.Address, 16, ObservationReadState::Complete, std::vector<uint8_t>(16, 0x41)},
                    {request.Address + 16, request.Length - 16, ObservationReadState::Failed, {}}};
            }
            else if (!Fail && request.Address != FailAddress && request.Address >= Base && request.Address - Base < Bytes.size() &&
                request.Length <= Bytes.size() - (request.Address - Base))
            {
                if (request.Address == Base + 0x1000 && ++PageReads == 2 && Unstable) { Bytes[0x1050] ^= 1; }
                const auto offset = static_cast<size_t>(request.Address - Base);
                result.Spans = {{request.Address, request.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(Bytes.begin() + offset, Bytes.begin() + offset + request.Length)}};
            }
            else { result.Spans = {{request.Address, request.Length, ObservationReadState::Failed, {}}}; }
            return result;
        }
    };

    std::vector<uint8_t> Fixture(std::vector<uint8_t>* memory)
    {
        std::vector<uint8_t> disk(0x1400);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.FileHeader.TimeDateStamp = 0x12345678;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.ImageBase = Base;
        nt.OptionalHeader.SizeOfImage = 0x2000;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.SectionAlignment = 0x1000;
        nt.OptionalHeader.FileAlignment = 0x200;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        IMAGE_SECTION_HEADER section{};
        std::memcpy(section.Name, ".text", 5);
        section.VirtualAddress = 0x1000;
        section.Misc.VirtualSize = section.SizeOfRawData = 0x1000;
        section.PointerToRawData = 0x400;
        section.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        std::memcpy(disk.data(), &dos, sizeof(dos));
        std::memcpy(disk.data() + 0x80, &nt, sizeof(nt));
        std::memcpy(disk.data() + 0x80 + sizeof(nt), &section, sizeof(section));
        std::fill(disk.begin() + 0x400, disk.end(), uint8_t{0x90});
        memory->assign(0x2000, 0);
        std::copy(disk.begin(), disk.begin() + 0x400, memory->begin());
        std::copy(disk.begin() + 0x400, disk.end(), memory->begin() + 0x1000);
        return disk;
    }
    bool Write(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
    {
        std::ofstream output(path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.close();
        return !output.fail();
    }
    std::wstring Raw(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value;
        mcpjson::FindRawValue(json, key, &value);
        return value;
    }
    std::wstring Text(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value;
        mcpjson::GetString(json, key, &value);
        return value;
    }
    std::vector<std::wstring> Array(const std::wstring& json, const wchar_t* key)
    {
        const auto raw = Raw(json, key);
        std::vector<std::wstring> rows;
        if (raw.empty() || raw.front() != L'[') { return rows; }
        for (size_t pos = 1, end = 0; pos < raw.size() && raw[pos] != L']'; pos = end + 1)
        {
            if (!mcpjson::ScanValue(raw, pos, &end)) { return {}; }
            rows.push_back(raw.substr(pos, end - pos));
            if (end == raw.size() || raw[end] != L',') { break; }
        }
        return rows;
    }
}

bool KmonImageReadIntegrationSelfTest()
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool passed, const char* name)
    {
        ++checks;
        if (!passed) { ++failures; std::fprintf(stderr, "[kmon.image_reads] FAIL %s\n", name); }
        return passed;
    };
    wchar_t temporary[MAX_PATH]{}, unique[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, temporary) || !GetTempFileNameW(temporary, L"knr", 0, unique)) { return false; }
    if (!DeleteFileW(unique) || !CreateDirectoryW(unique, nullptr)) { return false; }
    const std::filesystem::path root = std::filesystem::absolute(unique);
    try
    {
        const auto reference = root / L"fixture.exe";
        Source primary(L"synthetic:kmon:primary"), secondary(L"synthetic:kmon:secondary");
        primary.Partial = true;
        const auto disk = Fixture(&secondary.Bytes);
        if (!Write(reference, disk)) { throw std::runtime_error("fixture write failed"); }
        executable_image::DiskPeMetadata expectedReference;
        if (!executable_image::ReadDiskPeMetadata(reference.wstring(), &expectedReference, nullptr))
        {
            throw std::runtime_error("fixture metadata failed");
        }
        secondary.Bytes[0x1050] ^= 1;
        ObservationIdentity identity;
        identity.BootId = L"synthetic:boot"; identity.ProcessId = 42; identity.CreateTime = 1;
        ObservationReadRouting routing;
        routing.Primary = &primary;
        routing.Fallback = [&]() -> IObservationSource* { return &secondary; };
        routing.TargetId = L"synthetic:kmon:42:1";
        routing.AddressSpaceId = L"synthetic:kmon:42:1:user";
        routing.AllowFallback = true;
        const auto monitorOwner = std::make_unique<KernelMonitor>();
        auto& monitor = *monitorOwner;
        monitor.Options.LogDirectory = root.wstring();
        const auto verdict = monitor.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing);
        KernelMonitor::CapturedImageReads retained;
        if (!check(verdict == CodeOwnership::OwnedModified && monitor.CapturedImageReadSets.Pop(&retained),
            "actual-sweep-queues-original-modified-read-set")) { throw std::runtime_error("comparison failed"); }
        check(primary.Calls == secondary.Calls && secondary.PageReads == 2,
            "actual-page-comparison-and-stability-check-both-recorded");
        check(retained.HasReference && retained.Reference.Artifact != nullptr && retained.Reference.ContentRechecked &&
            retained.Reference.ContentStable && retained.Reference.Artifact->Bytes == disk &&
            retained.Reference.Artifact->Sha256 == ContentHash::Bytes(disk), "exact-reference-captured-and-rechecked-before-lease-release");
        ImageSliceRecipe slice;
        check(ParseImageSliceRecipe(retained.SliceJson, &slice) && slice.Slice.PageCount == 1 &&
            slice.Policy == ImageSliceDirectPolicy && monitor.ImageSlicesQueued.load() == 1,
            "actual-sweep-retains-original-routed-slice-recipe");
        const auto payload = Raw(retained.Json, L"payload");
        check(Text(Raw(payload, L"retention"), L"class") == L"first_difference",
            "actual-original-difference-uses-protected-admission-class");
        const auto routed = Raw(payload, L"reads");
        const auto attempts = Raw(routed, L"attempts");
        const auto reads = Array(attempts, L"reads"), parser = Array(routed, L"parser_reads");
        check(reads.size() == 2 * primary.Calls.size() && parser.size() == secondary.Calls.size(),
            "archive-denominator-includes-failed-and-selected-reads");
        bool linked = reads.size() == 2 * parser.size() && parser.size() == secondary.Calls.size();
        for (size_t i = 0; linked && i < parser.size(); ++i)
        {
            linked = Text(parser[i], L"primary_receipt") == std::to_wstring(2 * i + 1) &&
                Text(parser[i], L"returned_receipt") == std::to_wstring(2 * i + 2) &&
                Text(parser[i], L"address") == std::to_wstring(secondary.Calls[i].first) &&
                Text(parser[i], L"length") == std::to_wstring(secondary.Calls[i].second) && Raw(parser[i], L"accepted") == L"true" &&
                Raw(Raw(reads[2 * i], L"read"), L"native_status") == L"299" &&
                Text(Raw(reads[2 * i + 1], L"fallback"), L"from_receipt") == std::to_wstring(2 * i + 1);
            const auto spans = Array(Raw(reads[2 * i + 1], L"read"), L"spans");
            std::wstring expectedHex;
            const auto offset = static_cast<size_t>(secondary.Calls[i].first - Base);
            for (size_t j = 0; j < secondary.Calls[i].second; ++j)
            {
                const auto byte = secondary.Bytes[offset + j];
                expectedHex += L"0123456789abcdef"[byte >> 4];
                expectedHex += L"0123456789abcdef"[byte & 15];
            }
            linked &= spans.size() == 1 && Text(spans.front(), L"bytes_hex") == expectedHex;
        }
        check(linked, "parser-selection-matches-independent-source-call-log");
        bool findingLinked = false;
        for (const auto& event : monitor.Ring)
        {
            const auto id = event.Evidence.find(L"read_set_queued_id");
            const auto operation = event.Evidence.find(L"read_operation_id");
            findingLinked |= event.Kind == L"finding.code_modified" && id != event.Evidence.end() &&
                id->second == std::to_wstring(retained.Id) && operation != event.Evidence.end() &&
                operation->second == Text(attempts, L"operation_id");
        }
        check(findingLinked, "finding-links-original-operation-and-queued-archive");
        // No source bytes or reference survive until the writer starts.
        primary.Bytes.clear(); secondary.Bytes.clear();
        const auto calls = secondary.Calls.size();
        check(DeleteFileW(reference.c_str()) != FALSE, "reference-removable-after-original-comparison");
        {
            ExecutableSweep stale;
            stale.Initialize(expectedReference);
            stale.Coverage.ComparedBytes = 4096;
            stale.Pages[0x1000] = CodeOwnership::OwnedVerified;
            ExecutableSweepReference unavailable;
            unsigned targetReads = 0;
            const auto results = AdvanceExecutableSweep(reference.wstring(), expectedReference, Base,
                [&](uint64_t, size_t, std::vector<uint8_t>*) { ++targetReads; return false; }, 1, 1, &stale, 0, &unavailable);
            check(results.empty() && targetReads == 0 && stale.Pages.empty() && stale.Coverage.ComparedBytes == 0 &&
                !stale.Coverage.InventoryAvailable && unavailable.Artifact == nullptr &&
                unavailable.CaptureStatus == L"reference_unavailable_or_changed", "missing-reference-denies-target-read-and-clears-stale-coverage");
        }
        check(monitor.CapturedImageReadSets.Push(retained), "writer-receives-original-queued-json");
        retained.Retention.reset(); // Only the requeued item owns the queue reservation.
        monitor.WriterStopping.store(true);
        monitor.CaptureWriterLoop();
        const auto path = root / L"image-reads" / (L"reads-" + retained.CollectionId + L"-" + std::to_wstring(retained.Id) + L".knreads");
        std::wstring persisted;
        check(ReadAnalystSnapshot(path.wstring(), &persisted, nullptr) &&
            Raw(Raw(persisted, L"payload"), L"reads") == routed && Text(persisted, L"schema") == L"kn.image_reads.v3" &&
            secondary.Calls.size() == calls && monitor.ImageReadsWritten.load() == 1 && monitor.ImageReadsFailed.load() == 0 &&
            monitor.ImageReadsLedgerFailed.load() == 0 && monitor.CapturedImageReadSets.Size() == 0 && monitor.CaptureWriterDone.load(),
            "shutdown-writer-persists-originals-after-source-disappearance");
        const auto storedReference = Raw(Raw(persisted, L"payload"), L"reference");
        check(Text(storedReference, L"persistence") == L"committed" && Text(storedReference, L"sha256") == ContentHash::Bytes(disk) &&
            monitor.ImageReferenceBlobsCreated.load() == 1 && monitor.ImageReferenceBytes.load() == disk.size() &&
            ContentHash::File((root / L"image-references" / (ContentHash::Bytes(disk) + L".knblob")).wstring()) == ContentHash::Bytes(disk),
            "writer-commits-exact-original-reference-before-referring-archive");
        auto recipePath = path;
        recipePath.replace_extension(L".knslice");
        const auto replayed = ReplayImageRecipe(recipePath.wstring(), false, nullptr);
        check(replayed.Status == L"replayed" && replayed.CurrentResult == slice.RecordedResult &&
            !replayed.Proof.empty() && replayed.OriginalClaimStatus == L"reproduced" &&
            monitor.ImageSliceClaimsWritten.load() == 1 && monitor.ImageSliceClaimsUnavailable.load() == 0 &&
            monitor.ImageSlicesWritten.load() == 1 && secondary.Calls.size() == calls,
            "actual-kmon-slice-replays-after-target-and-original-reference-removal");
        const auto sweepPath = root / L"image-sweeps" / (L"sweep-" + (retained.Sweep ? retained.Sweep->Sweep.SweepId : L"missing") + L".knsweep");
        const auto sweepReplay = ReplayImageRecipe(sweepPath.wstring(), false, nullptr);
        check(sweepReplay.Status == L"replayed" && Text(sweepReplay.Proof, L"changed_bytes") == L"1" &&
            sweepReplay.OriginalClaimStatus == L"reproduced" && monitor.ImageSweepClaimsWritten.load() == 1 &&
            monitor.ImageSweepClaimsUnavailable.load() == 0 &&
            Raw(sweepReplay.Proof, L"whole_sweep_complete") == L"true" &&
            Raw(sweepReplay.Proof, L"executable_ranges_match_retained_reference") == L"false" &&
            monitor.ImageSweepManifestsWritten.load() == 1 && monitor.ImageSweepManifestPending.load() == 0,
            "actual-kmon-manifest-binds-original-raw-reference-and-recipe");
        const auto sweepGraph = BuildImageSweepGraph(sweepPath.wstring());
        EvidenceGraphQuery graphQuery;
        graphQuery.Depth = 8; graphQuery.Limit = 128;
        const auto graphPage = QueryEvidenceGraph(sweepGraph.Facts, graphQuery);
        check(sweepGraph.Facts.Status == L"materialized" && graphPage.Status == L"ok" &&
            sweepGraph.Assessment == sweepReplay.Proof &&
            std::count_if(graphPage.Nodes.begin(), graphPage.Nodes.end(), [](const auto& node)
                { return node.Kind == L"executable_range_comparison" && node.State == L"changed_bytes_established"; }) == 1,
            "actual-kmon-changed-range-graph-derives-from-replayed-originals");
        std::wstring sweepJson;
        {
            const auto deniedOwner = std::make_unique<KernelMonitor>();
            auto& denied = *deniedOwner;
            denied.Options.PrivateLogRequired = true;
            denied.Options.LogDirectory = (root / L"missing-private-root").wstring();
            check(!denied.EnsureLogOpenLocked() && !std::filesystem::exists(denied.Options.LogDirectory),
                "private-log-denies-uninitialized-root-without-creating-output");
        }
        for (const bool efs : {false, true})
        {
            const auto folder = root / (efs ? L"private-efs" : L"private-acl");
            const auto initialized = InitializeEvidencePrivateStore(folder.wstring(), efs);
            if (efs && initialized.Status != L"ready")
            {
                check(initialized.EfsRequired && initialized.Issue.find(L"efs_initialization_failed_") == 0 &&
                    !std::filesystem::exists(folder), "unavailable-EFS-is-explicit-without-fallback");
                std::fprintf(stderr, "[kmon.privacy] efs=unavailable\n");
                continue;
            }
            check(initialized.Status == L"ready", "private-root-initialized");
            const auto secureOwner = std::make_unique<KernelMonitor>();
            auto& secure = *secureOwner;
            secure.Options.LogDirectory = folder.wstring(); secure.Options.PrivateLogRequired = true;
            check(secure.EnsureLogOpenLocked() && secure.LogPrivacy && secure.LogPrivacy->CheckFile(secure.LogHandle),
                "actual-KMON-log-handle-satisfies-private-policy");
            const auto previousHandle = secure.LogHandle;
            std::wstring startError;
            secure.Active.store(true);
            check(!secure.Start({}, nullptr, nullptr, nullptr, nullptr, &startError) && secure.LogHandle == previousHandle && secure.LogPrivacy,
                "rejected-start-preserves-existing-private-session-guard");
            secure.Active.store(false);
            KmonEvent event; event.Kind = L"privacy.fixture"; event.Summary = L"owned test event";
            check(secure.WriteLogLine(event), "actual-private-JSONL-writer");
            secure.RotateLogLocked();
            check(secure.LogPrivacy && secure.EnsureLogOpenLocked() && secure.WriteLogLine(event), "rotation-retains-private-root-guard");
            Source owned(L"synthetic:kmon:privacy");
            const auto ownedDisk = Fixture(&owned.Bytes); owned.Bytes[0x1050] ^= 1;
            const auto ownedReference = folder / L"fixture.exe";
            check(Write(ownedReference, ownedDisk), "owned-private-reference");
            ObservationReadRouting route; route.Primary = &owned; route.TargetId = L"synthetic:privacy";
            route.AddressSpaceId = L"synthetic:privacy:user";
            check(secure.ScanExecutableImage(ownedReference.wstring(), Base, identity, {}, 16, &route) == CodeOwnership::OwnedModified,
                "private-store-actual-image-comparison");
            check(DeleteFileW(ownedReference.c_str()) != FALSE, "private-original-source-removed-before-persistence");
            owned.Bytes.clear();
            secure.WriterStopping.store(true); secure.CaptureWriterLoop();
            const auto collection = folder / L"collections" / std::to_wstring(secure.EvidenceCollectionEpoch.load());
            const auto recovery = RecoverEvidenceJournal(collection.wstring());
            check(secure.ImageReadsWritten.load() == 1 && secure.ImageReadsFailed.load() == 0 && recovery.Closed && recovery.SweepPaths.size() == 1,
                "private-raw-reference-recipe-and-closure-journal-committed");
            check(recovery.SweepPaths.size() == 1 && ReplayImageRecipe((folder / recovery.SweepPaths.front()).wstring(), false, nullptr).Status == L"replayed",
                "private-originals-replay-through-existing-reader-after-source-removal");
            std::wstring stopError;
            check(secure.Stop(&stopError) && !secure.LogPrivacy && secure.LogHandle == INVALID_HANDLE_VALUE,
                "stopped-private-session-releases-policy-root-and-log-handles");
            const auto privacy = InspectEvidencePrivacy(folder.wstring(), true);
            check(privacy.Status == L"ready" && privacy.AuditComplete && privacy.CheckedEntries >= 10 && privacy.EfsRequired == efs,
                "all-actual-KMON-descendants-inherit-selected-protection");
            const auto inventory = InspectEvidenceStore(folder.wstring());
            check(inventory.Status == L"verified" && inventory.MembershipComplete, "private-root-compatible-with-stopped-store-inventory");
            if (efs) { std::fprintf(stderr, "[kmon.privacy] efs=verified\n"); }
        }
        ImageSweepManifest sweepManifest;
        ImageScopeClaimPublication sweepPublication;
        check(ReadAnalystSnapshot(sweepPath.wstring(), &sweepJson, nullptr) &&
            UnwrapImageScopeClaimPublication(&sweepJson, &sweepPublication) && !sweepPublication.Sha256.empty() &&
            ParseImageSweepManifest(sweepJson, &sweepManifest),
            "actual-kmon-manifest-canonical-membership");
        {
            const auto missingOwner = std::make_unique<KernelMonitor>();
            auto& missing = *missingOwner;
            const auto destination = root / L"claim-missing-children";
            missing.Options.LogDirectory = destination.wstring();
            missing.PersistImageSweepManifest(sweepManifest);
            std::wstring legacy;
            ImageSweepManifest preserved;
            check(missing.ImageSweepManifestsWritten.load() == 1 && missing.ImageSweepClaimsWritten.load() == 0 &&
                missing.ImageSweepClaimsUnavailable.load() == 1 && missing.ImageJournalSweepsFailed.load() == 1 &&
                ReadAnalystSnapshot((destination / L"image-sweeps" / sweepPath.filename()).wstring(), &legacy, nullptr) &&
                ParseImageSweepManifest(legacy, &preserved), "missing-children-preserve-manifest-without-original-claim-or-collection-commit");
        }
        {
            const auto boundedOwner = std::make_unique<KernelMonitor>();
            auto& bounded = *boundedOwner;
            const auto destination = root / L"claim-recipe-budget";
            bounded.Options.LogDirectory = destination.wstring();
            const auto recipeBytes = mcpjson::WideToUtf8(retained.SliceJson).size();
            bounded.ImageRetention.Consume(ImageRetentionClass::Routine, ImageRetentionStream::Recipe, 32ull * 1024 * 1024 - recipeBytes);
            const auto id = bounded.QueueImageReadSet(slice.TargetReads, identity, L"synthetic", Base,
                &retained.Reference, retained.SliceJson, &slice.Slice);
            bounded.WriterStopping.store(true); bounded.CaptureWriterLoop();
            const auto file = destination / L"image-reads" / (L"reads-" + std::to_wstring(bounded.EvidenceCollectionEpoch.load()) +
                L"-" + std::to_wstring(id) + L".knslice");
            const auto replay = ReplayImageRecipe(file.wstring(), false, nullptr);
            check(bounded.ImageSlicesWritten.load() == 1 && bounded.ImageSliceClaimsWritten.load() == 0 &&
                bounded.ImageSliceClaimsUnavailable.load() == 1 && replay.Status == L"replayed" &&
                replay.OriginalClaimStatus == L"not_recorded" && secondary.Calls.size() == calls,
                "claim-budget-failure-preserves-original-recipe-without-new-target-reads");
        }
        for (unsigned mode = 0; mode < 2; ++mode)
        {
            const auto deniedOwner = std::make_unique<KernelMonitor>();
            auto& denied = *deniedOwner;
            const auto destination = root / (L"manifest-failure-" + std::to_wstring(mode));
            denied.Options.LogDirectory = destination.wstring();
            const auto manifestFile = destination / L"image-sweeps" / sweepPath.filename();
            if (mode == 0) { denied.ImageSweepManifestBytes.store(128ull * 1024 * 1024); }
            else
            {
                std::filesystem::create_directories(manifestFile.parent_path());
                check(Write(manifestFile, {0x7B, 0x7D}), "owned-manifest-collision");
            }
            denied.PersistImageSweepManifest(sweepManifest);
            check(denied.ImageSweepManifestsWritten.load() == 0 && denied.ImageSweepManifestsFailed.load() == 1 &&
                (mode == 0 ? !std::filesystem::exists(manifestFile) : ContentHash::File(manifestFile.wstring()) == ContentHash::Bytes({0x7B, 0x7D})),
                "manifest-publication-budget-or-collision-is-explicit-and-nondestructive");
            if (mode == 0)
            {
                bool budgetReported = false;
                for (const auto& event : denied.PipelineEvents.Drain(8))
                {
                    const auto failure = event.Evidence.find(L"failure");
                    budgetReported |= event.Kind == L"coverage.image_sweep_manifest" && failure != event.Evidence.end() &&
                        failure->second == L"invalid_manifest_or_session_byte_budget";
                }
                check(budgetReported, "successful-store-admission-preserves-manifest-budget-reason");
            }
        }
        check(!Raw(Raw(persisted, L"payload"), L"slice_inputs").empty(), "raw-archive-retains-slice-inputs-separately-from-recipe");
        const auto payloadBytes = mcpjson::WideToUtf8(Raw(persisted, L"payload"));
        check(ContentHash::Bytes(std::vector<uint8_t>(payloadBytes.begin(), payloadBytes.end())) == Text(persisted, L"payload_sha256"),
            "payload-content-hash-matches-persisted-bytes");
        std::wstring ledger;
        check(ReadAnalystSnapshot((root / L"image-reads" / (L"session-" + retained.CollectionId + L".knreadledger")).wstring(), &ledger, nullptr) &&
            Raw(ledger, L"queued") == L"1" && Raw(ledger, L"written") == L"1" && Raw(ledger, L"failed") == L"0" &&
            Raw(ledger, L"pending") == L"0" && Raw(ledger, L"dropped") == L"0" &&
            Raw(ledger, L"reference_blobs_created") == L"1" && Raw(ledger, L"reference_blobs_failed") == L"0" &&
            Raw(ledger, L"reference_bytes") == std::to_wstring(disk.size()) && Raw(ledger, L"reference_reserved_bytes") == L"0",
            "final-image-read-ledger-balances");
        check(Raw(ledger, L"slice_recipes_queued") == L"1" && Raw(ledger, L"slice_recipes_written") == L"1" &&
            Raw(ledger, L"slice_recipes_failed") == L"0" && Raw(ledger, L"slice_recipes_unavailable") == L"0",
            "final-slice-ledger-balances-publication-separately");
        const auto recovered = RecoverEvidenceJournal((root / L"collections" / retained.CollectionId).wstring(), true);
        check(recovered.Status == L"verified_prefix" && recovered.Closed && !recovered.CanResume &&
            recovered.CommittedSegments == 3 && recovered.UniquePaths == 5 && recovered.SweepPaths.size() == 1 &&
            recovered.IndexStatus == L"ready" && monitor.ImageJournalClosed.load() && monitor.ImageJournalCloseFailed.load() == 0 &&
            monitor.ImageJournalReadsCommitted.load() == 1 && monitor.ImageJournalSweepsCommitted.load() == 1 &&
            Raw(ledger, L"journal_read_batches_committed") == L"1" && Raw(ledger, L"journal_sweeps_committed") == L"1",
            "actual-kmon-original-files-and-closure-recover-from-committed-journal");
        check(recovered.SweepPaths.size() == 1 && ReplayImageRecipe((root / recovered.SweepPaths.front()).wstring(), false, nullptr).Proof ==
            sweepReplay.Proof, "recovered-collection-root-replays-original-comparison-after-source-removal");
        monitor.DrainPipelineEvents(true);
        bool final = false;
        for (const auto& event : monitor.Ring)
        {
            const auto value = event.Evidence.find(L"image_read_sets_written");
            final |= event.Kind == L"coverage.pipeline" && value != event.Evidence.end() && value->second == L"1";
        }
        check(final && Raw(monitor.HuntCasesJson({}), L"image_read_store").find(L"\"written\":1") != std::wstring::npos,
            "pipeline-and-hunt-report-separate-image-read-store");

        Fixture(&secondary.Bytes);
        check(Write(reference, disk), "restore-owned-reference");
        secondary.Calls.clear(); primary.Calls.clear(); secondary.PageReads = 0;
        const auto cleanOwner = std::make_unique<KernelMonitor>();
        auto& clean = *cleanOwner;
        clean.Options.LogDirectory = (root / L"clean").wstring();
        check(clean.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing) == CodeOwnership::OwnedVerified &&
            clean.ImageReadsQueued.load() == 1 && clean.ImageSlicesQueued.load() == 1, "clean-sweep-retains-original-matching-range-recipe");
        clean.WriterStopping.store(true); clean.CaptureWriterLoop();
        std::filesystem::path cleanRecipe;
        size_t cleanRecipeCount = 0;
        for (const auto& entry : std::filesystem::directory_iterator(root / L"clean" / L"image-reads"))
        {
            if (entry.path().extension() == L".knslice") { cleanRecipe = entry.path(); ++cleanRecipeCount; }
        }
        const auto cleanReplay = ReplayImageRecipe(cleanRecipe.wstring(), false, nullptr);
        check(cleanRecipeCount == 1 && cleanReplay.Status == L"replayed" && Text(cleanReplay.Proof, L"changed_bytes") == L"0" &&
            Text(cleanReplay.Proof, L"compared_bytes") == L"4096", "clean-original-slice-publishes-and-replays-complete-matching-range");
        {
            // Two actual KMON scheduling turns share one sweep, without a
            // second acquisition after either original comparison.
            auto twoDisk = disk;
            twoDisk.resize(0x2400, 0x90);
            uint32_t size = 0x3000;
            std::memcpy(twoDisk.data() + 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.SizeOfImage), &size, sizeof(size));
            size = 0x2000;
            const size_t section = 0x80 + sizeof(IMAGE_NT_HEADERS64);
            std::memcpy(twoDisk.data() + section + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize), &size, sizeof(size));
            std::memcpy(twoDisk.data() + section + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData), &size, sizeof(size));
            const auto twoPath = root / L"two-pages.exe";
            check(Write(twoPath, twoDisk), "multi-slice-owned-reference");
            secondary.Bytes.assign(0x3000, 0);
            std::copy(twoDisk.begin(), twoDisk.begin() + 0x400, secondary.Bytes.begin());
            std::copy(twoDisk.begin() + 0x400, twoDisk.end(), secondary.Bytes.begin() + 0x1000);
            secondary.PageReads = 0;
            const auto multipleOwner = std::make_unique<KernelMonitor>();
            auto& multiple = *multipleOwner;
            multiple.Options.LogDirectory = (root / L"multiple").wstring();
            const auto first = multiple.ScanExecutableImage(twoPath.wstring(), Base, identity, {}, 1, &routing);
            const auto second = multiple.ScanExecutableImage(twoPath.wstring(), Base, identity, {}, 1, &routing);
            const auto partialSweepOwner = std::make_unique<KernelMonitor>();
            auto& partialSweep = *partialSweepOwner;
            partialSweep.Options.LogDirectory = (root / L"partial-sweep").wstring();
            check(partialSweep.ScanExecutableImage(twoPath.wstring(), Base, identity, {}, 1, &routing) == CodeOwnership::OwnedUnverified &&
                partialSweep.ImageReadsQueued.load() == 1, "stop-control-observes-one-original-slice");
            const auto partialId = partialSweep.ImageWork.empty() ? L"" : partialSweep.ImageWork.begin()->second.RecordingSweep.SweepId;
            check(first == CodeOwnership::OwnedUnverified && second == CodeOwnership::OwnedVerified &&
                multiple.ImageReadsQueued.load() == 2 && DeleteFileW(twoPath.c_str()), "multi-slice-originals-retained-before-reference-removal");
            secondary.Bytes.clear();
            multiple.WriterStopping.store(true); multiple.CaptureWriterLoop();
            partialSweep.WriterStopping.store(true); partialSweep.CaptureWriterLoop();
            const auto partialReplay = ReplayImageRecipe((root / L"partial-sweep" / L"image-sweeps" /
                (L"sweep-" + partialId + L".knsweep")).wstring(), false, nullptr);
            check(partialReplay.Status == L"replayed" && Raw(partialReplay.CurrentResult, L"tail_unknown") == L"true" &&
                Raw(partialReplay.Proof, L"whole_sweep_complete") == L"false" &&
                Text(partialReplay.Proof, L"unobserved_bytes") == L"4096" && partialSweep.ImageSweepManifestPending.load() == 0,
                "actual-writer-stop-publishes-incomplete-sweep-with-unknown-tail");
            std::wstring partialLedger;
            check(ReadAnalystSnapshot((root / L"partial-sweep" / L"image-reads" /
                (L"session-" + std::to_wstring(partialSweep.EvidenceCollectionEpoch.load()) + L".knreadledger")).wstring(), &partialLedger, nullptr) &&
                Raw(partialLedger, L"sweeps_started") == L"1" && Raw(partialLedger, L"sweep_terminals_observed") == L"0" &&
                Raw(partialLedger, L"sweep_manifests_written") == L"1" && Raw(partialLedger, L"reference_reserved_bytes") == L"0",
                "stopped-incomplete-sweep-has-final-ledger-with-no-reference-reservation");
            const auto partialCollection = RecoverEvidenceJournal((root / L"partial-sweep" / L"collections" /
                std::to_wstring(partialSweep.EvidenceCollectionEpoch.load())).wstring());
            check(partialCollection.Closed && partialCollection.CommittedSegments == 3 && partialCollection.SweepPaths.size() == 1 &&
                Raw(partialReplay.Proof, L"whole_sweep_complete") == L"false",
                "journal-closure-does-not-turn-incomplete-target-observation-into-complete-sweep");
            const auto multiCollection = RecoverEvidenceJournal((root / L"multiple" / L"collections" /
                std::to_wstring(multiple.EvidenceCollectionEpoch.load())).wstring());
            check(multiCollection.Closed && multiCollection.CommittedSegments == 4 && multiCollection.UniquePaths == 7 &&
                multiCollection.MemberReferences == 8 && multiCollection.LogicalBytes - multiCollection.UniqueContentBytes == twoDisk.size(),
                "actual-multislice-journal-retains-reference-reuse-denominator");
            std::filesystem::path manifest;
            size_t manifests = 0;
            for (const auto& entry : std::filesystem::directory_iterator(root / L"multiple" / L"image-sweeps"))
            {
                if (entry.path().extension() == L".knsweep") { manifest = entry.path(); ++manifests; }
            }
            const auto multipleReplay = ReplayImageRecipe(manifest.wstring(), false, nullptr);
            check(manifests == 1 && multipleReplay.Status == L"replayed" &&
                Raw(multipleReplay.Proof, L"whole_sweep_complete") == L"true" &&
                Raw(multipleReplay.Proof, L"executable_ranges_match_retained_reference") == L"true" &&
                Text(multipleReplay.Proof, L"compared_bytes") == L"8192" &&
                multiple.ImageReferenceBlobsCreated.load() == 1 && multiple.ImageReferenceBlobsReused.load() == 1,
                "multi-slice-manifest-replays-complete-original-sweep-with-one-shared-reference");
            const auto multipleGraph = BuildImageSweepGraph(manifest.wstring());
            const auto multiplePage = QueryEvidenceGraph(multipleGraph.Facts, graphQuery);
            check(multiplePage.Status == L"ok" && multipleGraph.Assessment == multipleReplay.Proof &&
                std::count_if(multiplePage.Nodes.begin(), multiplePage.Nodes.end(), [](const auto& node)
                    { return node.Kind == L"executable_range_comparison" && node.State == L"matches_retained_reference"; }) == 2,
                "actual-kmon-multiple-slices-have-separate-qualified-range-graph-nodes");
        }
        Fixture(&secondary.Bytes);
        secondary.Bytes[0x1050] ^= 1; secondary.Unstable = true; secondary.PageReads = 0;
        const auto unstableOwner = std::make_unique<KernelMonitor>();
        auto& unstable = *unstableOwner;
        unstable.Options.LogDirectory = (root / L"unstable").wstring();
        check(unstable.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing) == CodeOwnership::OwnedUnverified &&
            unstable.ImageReadsQueued.load() == 1, "unstable-page-keeps-inconclusive-originals");
        secondary.Unstable = false; secondary.Fail = true;
        const auto failedOwner = std::make_unique<KernelMonitor>();
        auto& failed = *failedOwner;
        failed.Options.LogDirectory = (root / L"failed").wstring();
        check(failed.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing) == CodeOwnership::OwnedUnverified &&
            failed.ImageReadsQueued.load() == 1, "failed-identity-reads-are-retained");

        // Exercise the same publication queue with a small completed read set.
        secondary.Fail = false;
        auto operation = std::make_shared<ObservationReadOperation>(L"synthetic:store-controls", routing.TargetId, routing.AddressSpaceId);
        ObservationReadRouter router(routing, operation);
        std::vector<uint8_t> bytes;
        check(router.ReadExact(Base, 32, &bytes), "publication-control-original-read");
        const auto set = router.Snapshot();
        {
            const auto incompleteOwner = std::make_unique<KernelMonitor>();
            auto& incomplete = *incompleteOwner;
            incomplete.Options.LogDirectory = (root / L"incomplete-secondary").wstring();
            ExecutableSliceTrace trace;
            trace.Entered = trace.SecondaryNeeded = trace.SecondaryOpened = true;
            trace.SecondaryViewBase = Base;
            trace.SecondaryReads = set;
            trace.SecondaryReads.UnrecordedParserCalls = 1; // Raw evidence remains useful even when replay is denied.
            const auto id = incomplete.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference, L"", &trace);
            incomplete.WriterStopping.store(true); incomplete.CaptureWriterLoop();
            std::wstring archive;
            const auto file = root / L"incomplete-secondary" / L"image-reads" /
                (L"reads-" + std::to_wstring(incomplete.EvidenceCollectionEpoch.load()) + L"-" + std::to_wstring(id) + L".knreads");
            check(ReadAnalystSnapshot(file.wstring(), &archive, nullptr) &&
                Raw(Raw(Raw(archive, L"payload"), L"slice_inputs"), L"secondary_reads") == ObservationRoutedReadSetJson(trace.SecondaryReads) &&
                incomplete.ImageSlicesUnavailable.load() == 1 && incomplete.ImageSlicesWritten.load() == 0,
                "ineligible-secondary-inputs-still-survive-in-raw-archive");
        }
        {
            const auto blockedJournalOwner = std::make_unique<KernelMonitor>();
            auto& blockedJournal = *blockedJournalOwner;
            const auto folder = root / L"journal-unavailable";
            blockedJournal.Options.LogDirectory = folder.wstring();
            std::filesystem::create_directories(folder);
            check(Write(folder / L"collections", {0x78}), "owned-journal-directory-blocker");
            blockedJournal.QueueImageReadSet(set, identity, L"synthetic", Base);
            blockedJournal.WriterStopping.store(true); blockedJournal.CaptureWriterLoop();
            check(blockedJournal.ImageReadsWritten.load() == 1 && blockedJournal.ImageReadsFailed.load() == 0 &&
                blockedJournal.ImageReadsLedgerFailed.load() == 0 && blockedJournal.ImageJournalReadsCommitted.load() == 0 &&
                blockedJournal.ImageJournalReadsFailed.load() == 1 && !blockedJournal.ImageJournalClosed.load() &&
                blockedJournal.ImageJournalCloseFailed.load() == 1 && blockedJournal.ImageJournal == nullptr,
                "original-file-publication-is-distinct-from-failed-collection-commit-and-closure");
        }
        {
            const auto folder = root / L"store-busy";
            std::wstring issue;
            {
                EvidenceStoreLease audit;
                check(audit.Acquire(folder.wstring(), true, &issue, true), "owned-exclusive-store-barrier");
                const auto blockedOwner = std::make_unique<KernelMonitor>();
                auto& blocked = *blockedOwner;
                blocked.Options.LogDirectory = folder.wstring();
                blocked.QueueImageReadSet(set, identity, L"synthetic", Base);
                blocked.WriterStopping.store(true); blocked.CaptureWriterLoop();
                check(blocked.ImageReadsWritten.load() == 0 && blocked.ImageReadsFailed.load() == 1 &&
                    blocked.ImageReadsLedgerFailed.load() == 1 && blocked.ImageStoreAdmissionFailed.load() == 2 &&
                    blocked.ImageStoreLease == nullptr && !std::filesystem::exists(folder / L"image-reads"),
                    "store-barrier-denial-counted-without-original-file-publication");
                blocked.PersistImageSweepManifest(sweepManifest);
                check(blocked.ImageStoreAdmissionFailed.load() == 3 && blocked.ImageSweepManifestsFailed.load() == 1 &&
                    !std::filesystem::exists(folder / L"image-sweeps"), "store-barrier-also-precedes-sweep-publication");
            }
            const auto resumedOwner = std::make_unique<KernelMonitor>();
            auto& resumed = *resumedOwner;
            resumed.Options.LogDirectory = folder.wstring();
            resumed.QueueImageReadSet(set, identity, L"synthetic", Base);
            resumed.WriterStopping.store(true); resumed.CaptureWriterLoop();
            const auto inventory = InspectEvidenceStore(folder.wstring());
            check(inventory.Status == L"verified" && inventory.ClosedCollections == 1 && inventory.UnattributedFiles == 0 &&
                resumed.ImageStoreAdmissionFailed.load() == 0 && resumed.ImageStoreLease == nullptr,
                "actual-writer-closes-and-releases-store-for-exact-inventory");
        }
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            const auto blockedOwner = std::make_unique<KernelMonitor>();
            auto& blocked = *blockedOwner;
            const auto directory = root / (L"slice-failure-" + std::to_wstring(mode));
            blocked.Options.LogDirectory = directory.wstring();
            if (mode == 0) { blocked.ImageRetention.Consume(ImageRetentionClass::Routine, ImageRetentionStream::Recipe, 32ull * 1024 * 1024); }
            if (mode == 2) { blocked.ImageRetention.Consume(ImageRetentionClass::Routine, ImageRetentionStream::Reference, 64ull * 1024 * 1024); }
            const auto id = blocked.QueueImageReadSet(slice.TargetReads, identity, L"synthetic", Base,
                &retained.Reference, retained.SliceJson, &slice.Slice);
            const auto blockedSlicePath = directory / L"image-reads" /
                (L"reads-" + std::to_wstring(blocked.EvidenceCollectionEpoch.load()) + L"-" + std::to_wstring(id) + L".knslice");
            if (mode == 1)
            {
                std::filesystem::create_directories(blockedSlicePath.parent_path());
                check(Write(blockedSlicePath, {0x7B, 0x7D}), "create-owned-slice-collision");
            }
            blocked.WriterStopping.store(true); blocked.CaptureWriterLoop();
            check(blocked.ImageReadsWritten.load() == 1 && blocked.ImageSlicesQueued.load() == 1 &&
                blocked.ImageSlicesWritten.load() == 0 && blocked.ImageSlicesFailed.load() == 1 &&
                (mode == 1 ? ContentHash::File(blockedSlicePath.wstring()) == ContentHash::Bytes({0x7B, 0x7D}) : !std::filesystem::exists(blockedSlicePath)),
                "slice-publication-failure-does-not-erase-raw-evidence-or-replace-existing-file");
            std::wstring finalLedger;
            check(ReadAnalystSnapshot((directory / L"image-reads" /
                (L"session-" + std::to_wstring(blocked.EvidenceCollectionEpoch.load()) + L".knreadledger")).wstring(), &finalLedger, nullptr) &&
                Raw(finalLedger, L"slice_recipes_failed") == L"1" && Raw(finalLedger, L"reference_reserved_bytes") == L"0",
                "final-ledger-retains-slice-failure-and-releases-reference-reservation");
        }
        const auto pressureOwner = std::make_unique<KernelMonitor>();
        auto& pressure = *pressureOwner;
        pressure.Options.LogDirectory = (root / L"pressure").wstring();
        for (unsigned i = 0; i < 9; ++i) { pressure.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference); }
        check(pressure.ImageReadsQueued.load() == 2 && pressure.ImageReadsDropped.load() == 7 &&
            pressure.CapturedImageReadSets.Size() == 2, "queue-pressure-counts-rejected-original-set");
        pressure.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing);
        check(pressure.ImageSweepsStarted.load() == 1 && pressure.ImageSweepTerminalsObserved.load() == 1 &&
            pressure.ImageReadsDropped.load() == 8, "entirely-dropped-sweep-remains-in-session-denominators");
        pressure.WriterStopping.store(true); pressure.CaptureWriterLoop();
        check(pressure.ImageReadsWritten.load() == 2 && pressure.ImageReadsFailed.load() == 0 &&
            pressure.CapturedImageReadSets.Size() == 0, "shutdown-drains-full-image-read-queue");
        check(pressure.ImageReferenceBlobsCreated.load() == 1 && pressure.ImageReferenceBlobsReused.load() == 1 &&
            pressure.ImageReferenceBytes.load() == disk.size() && pressure.ImageRetention.ReferenceHeld() == 0,
            "slice-archives-share-one-content-addressed-reference-and-release-reservations");
        std::wstring pressureLedger;
        check(ReadAnalystSnapshot((root / L"pressure" / L"image-reads" /
            (L"session-" + std::to_wstring(pressure.EvidenceCollectionEpoch.load()) + L".knreadledger")).wstring(), &pressureLedger, nullptr) &&
            Raw(pressureLedger, L"sweeps_started") == L"1" && Raw(pressureLedger, L"sweep_terminals_observed") == L"1" &&
            Raw(pressureLedger, L"sweep_manifests_written") == L"0" && Raw(pressureLedger, L"dropped") == L"8",
            "final-ledger-exposes-sweep-with-no-retained-slices");
        {
            const auto priorityOwner = std::make_unique<KernelMonitor>();
            auto& priority = *priorityOwner;
            const auto folder = root / L"priority";
            priority.Options.LogDirectory = folder.wstring();
            priority.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference);
            priority.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference);
            auto gap = set;
            gap.UnrecordedParserCalls = 1;
            priority.QueueImageReadSet(gap, identity, L"synthetic", Base, &retained.Reference);
            priority.QueueImageReadSet(gap, identity, L"synthetic", Base, &retained.Reference);
            for (const auto stream : {ImageRetentionStream::Reads, ImageRetentionStream::Reference, ImageRetentionStream::Recipe})
            {
                check(priority.ImageRetention.Consume(ImageRetentionClass::Routine, stream,
                    priority.ImageRetention.Remaining(ImageRetentionClass::Routine, stream)), "exhaust-only-routine-file-budget");
            }
            secondary.Bytes[0x1050] ^= 1;
            check(priority.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing) == CodeOwnership::OwnedModified &&
                priority.ImageReadsQueued.load() == 5 && priority.ImageReadsDropped.load() == 0,
                "routine-and-gap-queue-pressure-cannot-consume-first-difference-reserve");
            priority.WriterStopping.store(true); priority.CaptureWriterLoop();
            std::wstring finalLedger;
            check(ReadAnalystSnapshot((folder / L"image-reads" / (L"session-" + std::to_wstring(priority.EvidenceCollectionEpoch.load()) +
                L".knreadledger")).wstring(), &finalLedger, nullptr), "priority-final-ledger-persisted-outside-data-budgets");
            const auto classes = Array(Raw(finalLedger, L"retention"), L"classes");
            check(classes.size() == 3 && Text(classes[0], L"complete") == L"1" && Text(classes[0], L"in_flight") == L"0" &&
                Text(classes[1], L"finished") == L"2" && Text(classes[2], L"finished") == L"2" &&
                Text(classes[2], L"complete") == L"0" && Raw(finalLedger, L"failed") == L"2" &&
                priority.ImageRetention.ReferenceHeld() == 0, "partition-outcomes-and-failure-denominators-survive-shutdown");
            bool replayedPriority = false;
            for (const auto& entry : std::filesystem::directory_iterator(folder / L"image-reads"))
            {
                if (entry.path().extension() == L".knslice")
                {
                    const auto replay = ReplayImageRecipe(entry.path().wstring(), false, nullptr);
                    replayedPriority |= replay.Status == L"replayed" && Text(replay.Proof, L"changed_bytes") == L"1";
                }
            }
            check(replayedPriority && InspectEvidenceStore(folder.wstring()).Status == L"verified",
                "protected-first-difference-is-journaled-and-replays-despite-routine-budget-exhaustion");
            secondary.Bytes[0x1050] ^= 1;
        }
        {
            const auto repeatedOwner = std::make_unique<KernelMonitor>();
            auto& repeated = *repeatedOwner;
            repeated.Options.LogDirectory = (root / L"priority-retry").wstring();
            secondary.Bytes[0x1050] ^= 1;
            auto target = identity;
            for (unsigned attempt = 0; attempt < 6; ++attempt)
            {
                if (attempt == 3) { secondary.Bytes[0x1051] ^= 1; }
                if (attempt == 4) { ++target.CreateTime; }
                if (attempt == 5) { repeated.ImageWork.clear(); }
                for (auto& work : repeated.ImageWork) { work.second.NextSweepDueMs = 0; }
                repeated.ScanExecutableImage(reference.wstring(), Base, target, {}, 16, &routing);
                KernelMonitor::CapturedImageReads item;
                check(repeated.CapturedImageReadSets.Pop(&item) && item.Retention &&
                    item.Retention->Class == (attempt == 2 ? ImageRetentionClass::Routine : ImageRetentionClass::FirstDifference),
                    "failed-first-retries-repeat-demotes-new-bytes-lifetime-or-work-episode-remain-first");
                if (attempt == 0)
                {
                    const auto collision = std::filesystem::path(repeated.Options.LogDirectory) / L"image-reads" /
                        (L"reads-" + item.CollectionId + L"-" + std::to_wstring(item.Id) + L".knreads");
                    std::filesystem::create_directories(collision.parent_path());
                    check(Write(collision, {0x51}), "owned-first-publication-failure");
                }
                repeated.PersistImageReadSet(item);
            }
            repeated.WriterStopping.store(true); repeated.CaptureWriterLoop();
            check(repeated.ImageReadsWritten.load() == 5 && repeated.ImageReadsFailed.load() == 1 &&
                repeated.ImageJournalReadsCommitted.load() == 6 && repeated.ImageRetention.ReferenceHeld() == 0,
                "partial-journal-batch-does-not-spend-first-difference-priority");
            secondary.Bytes[0x1050] ^= 1; secondary.Bytes[0x1051] ^= 1;
        }
        {
            const auto busyOwner = std::make_unique<KernelMonitor>();
            auto& busy = *busyOwner;
            const auto occupied = busy.ImageRetention.Acquire({}, 64ull * 1024 * 1024);
            check(busy.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference) == 0 &&
                busy.ImageReadsDropped.load() == 1 && busy.CapturedImageReadSets.Size() == 0 &&
                busy.ImageRetention.ReferenceHeld() == 64ull * 1024 * 1024, "reference-memory-pressure-is-counted-in-its-own-class");
        }
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            const auto missingOwner = std::make_unique<KernelMonitor>();
            auto& missing = *missingOwner;
            const auto folder = root / (L"reference-failure-" + std::to_wstring(mode));
            missing.Options.LogDirectory = folder.wstring();
            auto capture = retained.Reference;
            if (mode == 0) { missing.ImageRetention.Consume(ImageRetentionClass::Routine, ImageRetentionStream::Reference, 64ull * 1024 * 1024); }
            if (mode == 1)
            {
                std::filesystem::create_directories(folder / L"image-references");
                check(Write(folder / L"image-references" / (capture.Artifact->Sha256 + L".knblob"), {0x51}), "create-owned-corrupt-blob-control");
            }
            if (mode == 2) { capture = {}; capture.CaptureStatus = L"retention_unavailable"; }
            const auto id = missing.QueueImageReadSet(set, identity, L"synthetic", Base, &capture);
            missing.WriterStopping.store(true); missing.CaptureWriterLoop();
            std::wstring archive;
            const auto file = folder / L"image-reads" / (L"reads-" + std::to_wstring(missing.EvidenceCollectionEpoch.load()) +
                L"-" + std::to_wstring(id) + L".knreads");
            check(ReadAnalystSnapshot(file.wstring(), &archive, nullptr) && missing.ImageReadsWritten.load() == 1 &&
                Text(Raw(Raw(archive, L"payload"), L"reference"), L"persistence") == (mode == 2 ? L"not_captured" : L"failed") &&
                missing.ImageReferenceBlobsFailed.load() == (mode == 2 ? 0u : 1u) &&
                missing.ImageReferencesMissing.load() == (mode == 2 ? 1u : 0u), "reference-gaps-preserve-raw-archive-without-replay-claim");
            if (mode == 1)
            {
                check(ContentHash::File((folder / L"image-references" / (capture.Artifact->Sha256 + L".knblob")).wstring()) ==
                    ContentHash::Bytes({0x51}), "corrupt-existing-blob-is-never-replaced");
            }
        }
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            const auto rejectedOwner = std::make_unique<KernelMonitor>();
            auto& rejected = *rejectedOwner;
            rejected.Options.LogDirectory = mode == 1 ? reference.wstring() : (root / (L"rejected-" + std::to_wstring(mode))).wstring();
            if (mode == 0) { rejected.ImageRetention.Consume(ImageRetentionClass::Routine, ImageRetentionStream::Reads, 32ull * 1024 * 1024); }
            rejected.QueueImageReadSet(set, identity, L"synthetic", Base);
            std::filesystem::path collision;
            if (mode == 2)
            {
                KernelMonitor::CapturedImageReads item;
                if (!rejected.CapturedImageReadSets.Pop(&item)) { throw std::runtime_error("missing collision control"); }
                collision = std::filesystem::path(rejected.Options.LogDirectory) / L"image-reads" /
                    (L"reads-" + item.CollectionId + L"-" + std::to_wstring(item.Id) + L".knreads");
                std::filesystem::create_directories(collision.parent_path());
                check(Write(collision, {0x51}), "create-owned-output-collision");
                rejected.CapturedImageReadSets.Push(std::move(item));
            }
            rejected.WriterStopping.store(true); rejected.CaptureWriterLoop();
            check(rejected.ImageReadsWritten.load() == 0 && rejected.ImageReadsFailed.load() == 1 &&
                rejected.CapturedImageReadSets.Size() == 0 && rejected.ImageReadsLedgerFailed.load() == (mode == 1 ? 1u : 0u),
                "byte-budget-filesystem-and-collision-failures-are-counted");
            if (mode == 1)
            {
                bool reported = false;
                for (const auto& event : rejected.PipelineEvents.Drain(8))
                {
                    const auto reason = event.Evidence.find(L"failure");
                    const auto admission = event.Evidence.find(L"store_admission_failure");
                    reported |= event.Kind == L"coverage.image_reads" && reason != event.Evidence.end() &&
                        reason->second == L"read_set_directory_unavailable" && admission != event.Evidence.end() &&
                        (admission->second == L"store_directory_creation_failed" || admission->second == L"store_directory_missing_or_reparse");
                }
                check(reported, "directory-failure-is-not-reported-as-byte-budget");
            }
            if (mode == 2) { check(ContentHash::File(collision.wstring()) == ContentHash::Bytes({0x51}), "existing-output-preserved"); }
        }
        const auto oversizedOwner = std::make_unique<KernelMonitor>();
        auto& oversized = *oversizedOwner;
        check(oversized.QueueImageReadSet(set, identity, std::wstring(EvidenceBundleMaxJsonBytes, L'x'), Base) == 0 &&
            oversized.ImageReadsDropped.load() == 1 && oversized.CapturedImageReadSets.Size() == 0, "oversize-archive-rejected-before-queue");
        {
            const auto restartingOwner = std::make_unique<KernelMonitor>();
            auto& restarting = *restartingOwner;
            std::atomic<bool> observed{false}, stopping{false}, valid{true};
            std::atomic<uint64_t> queries{0};
            std::thread reader([&]
            {
                while (!stopping.load())
                {
                    const auto json = restarting.HuntCasesJson({});
                    const auto retention = Raw(Raw(json, L"image_read_store"), L"retention");
                    if (!mcpjson::ValidateDocument(json) || Text(retention, L"schema") != L"kn.image_retention.v1" ||
                        Array(retention, L"classes").size() != 3) { valid.store(false); }
                    queries.fetch_add(1); observed.store(true);
                }
            });
            while (!observed.load()) { std::this_thread::yield(); }
            for (unsigned i = 0; i < 100; ++i) { restarting.ResetPipeline(); }
            stopping.store(true); reader.join();
            check(valid.load() && queries.load() != 0 && restarting.ImageRetention.ReferenceHeld() == 0,
                "live-hunt-reader-overlaps-session-policy-reset-without-stale-state-access");
        }
    }
    catch (const std::exception&)
    {
        check(false, "integration-fixture-exception");
    }
    std::error_code ec;
    // This absolute directory was exclusively created by this invocation.
    std::filesystem::remove_all(root, ec);
    check(!ec && !std::filesystem::exists(root), "owned-fixture-and-pending-files-cleaned");
    std::fprintf(stderr, "[kmon.image_reads] checks=%u failed=%u\n", checks, failures);
    return failures == 0;
}

bool KmonImageSchedulingIntegrationSelfTest(std::wstring* diagnostics)
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool passed, const char* name)
    {
        ++checks;
        if (!passed) { ++failures; std::fprintf(stderr, "[image.scheduler] FAIL %s\n", name); }
        return passed;
    };
    wchar_t temporary[MAX_PATH]{}, unique[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, temporary) || !GetTempFileNameW(temporary, L"kni", 0, unique)) { return false; }
    if (!DeleteFileW(unique) || !CreateDirectoryW(unique, nullptr)) { return false; }
    const std::filesystem::path root = std::filesystem::absolute(unique);
    std::wstring pipeline = L"null", cancelled = L"null", unavailable = L"null", bounded = L"null", scenarios;
    try
    {
        // Actual production lookup, cursor, comparison and pipeline publication,
        // with owned reference files and a synthetic nonexecuting address space.
        Source source(L"synthetic:image-scheduler");
        auto disk = Fixture(&source.Bytes);
        disk.resize(0x2400, 0x90);
        uint32_t size = 0x3000;
        std::memcpy(disk.data() + 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.SizeOfImage), &size, sizeof(size));
        size = 0x2000;
        const size_t section = 0x80 + sizeof(IMAGE_NT_HEADERS64);
        std::memcpy(disk.data() + section + offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize), &size, sizeof(size));
        std::memcpy(disk.data() + section + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData), &size, sizeof(size));
        const auto load = [&]()
        {
            source.Bytes.assign(0x3000, 0);
            std::copy(disk.begin(), disk.begin() + 0x400, source.Bytes.begin());
            std::copy(disk.begin() + 0x400, disk.end(), source.Bytes.begin() + 0x1000);
        };
        load();
        const auto path = root / L"two-pages.exe";
        if (!check(Write(path, disk), "owned-two-page-reference")) { throw std::runtime_error("fixture"); }
        ObservationIdentity identity; identity.BootId = L"synthetic:image-scheduler:boot"; identity.ProcessId = 42; identity.CreateTime = 1;
        ObservationReadRouting routing;
        routing.Primary = &source; routing.TargetId = L"synthetic:42:1"; routing.AddressSpaceId = L"synthetic:42:1:user";
        const auto owner = std::make_unique<KernelMonitor>();
        auto& monitor = *owner;
        monitor.Options.LogDirectory = (root / L"capture").wstring();
        check(monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing) == CodeOwnership::OwnedUnverified,
            "first-slice-leaves-tail-unknown");
        auto& work = monitor.ImageWork.begin()->second;
        const auto first = work.Scheduling;
        check(first.Seen && first.Pending && first.Attempted && first.Successful && first.ParserAttempted && first.ExactRead &&
            !first.Traversed && !first.GapFree && work.Sweep.NextRange == 1, "successful-slice-is-not-successful-traversal");
        check(monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false) == CodeOwnership::OwnedVerified,
            "continuation-completes-original-cursor");
        const auto complete = work.Scheduling;
        check(complete.GapFree && !complete.Pending && complete.FirstSeen == first.FirstSeen && complete.LastSeen == first.LastSeen &&
            complete.LastGapFreeEpisode == work.RetentionEpisode, "continuation-preserves-discovery-and-closes-qualified-debt");
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing);
        check(work.Scheduling.LastAttempt == complete.LastAttempt && work.Scheduling.FirstSeen == complete.FirstSeen &&
            !work.Scheduling.Pending && monitor.ImageTimings.Snapshot().DeferredTurn.Samples == 1, "rediscovery-does-not-renew-attempt-or-revisit");
        work.NextSweepDueMs = 0;
        source.FailAddress = Base + 0x1000;
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.Scheduling.Pending && work.Scheduling.LastSuccess == complete.LastSuccess &&
            work.Scheduling.LastGapFree == complete.LastGapFree && work.Sweep.NextRange == 1, "failed-page-does-not-renew-success");
        source.FailAddress = 0;
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.Sweep.Coverage.TraversalComplete && !work.Sweep.Coverage.Complete() && work.Scheduling.Pending &&
            work.Scheduling.LastGapFree == complete.LastGapFree, "traversed-with-gap-keeps-observation-debt");
        // Replacing the reference must preserve history but separate episodes.
        const auto oldEpisode = work.RetentionEpisode;
        ++disk[0x80 + offsetof(IMAGE_NT_HEADERS64, FileHeader.TimeDateStamp)];
        load();
        check(Write(path, disk), "replace-owned-reference");
        work.LastReferenceCheckMs = 0; work.NextSweepDueMs = 0;
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.RetentionEpisode != oldEpisode && work.Scheduling.LastGapFreeEpisode == oldEpisode &&
            work.Scheduling.FirstSeen == first.FirstSeen && work.Scheduling.Pending && work.Sweep.NextRange == 1,
            "new-reference-cannot-inherit-old-episode-completion");
        monitor.StopRequested.store(true);
        const auto callsBeforeStop = source.Calls.size();
        const auto successBeforeStop = work.Scheduling.LastSuccess;
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.Scheduling.LastGapFreeEpisode == oldEpisode && work.Scheduling.Pending &&
            work.Scheduling.LastSuccess == successBeforeStop && source.Calls.size() == callsBeforeStop &&
            monitor.ImageTimings.Snapshot(true).SuccessfulTurn.Samples == 0 && monitor.ImageTimings.Snapshot(true).FailedTurn.Samples == 1,
            "shutdown-cancellation-cannot-renew-success-or-call-target");
        cancelled = monitor.ImageSchedulingJson(GetTickCount64());
        // Controlled fixture restart: cancellation invalidated the partial
        // cursor, so two newly acquired pages are required for this episode.
        monitor.StopRequested.store(false); work.NextSweepDueMs = 0;
        check(work.Sweep.NextRange == 0, "cancelled-identity-invalidates-partial-cursor");
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.Sweep.NextRange == 1 && work.Scheduling.Pending && work.Scheduling.LastGapFreeEpisode == oldEpisode,
            "first-recovery-slice-is-not-complete");
        monitor.ScanExecutableImage(path.wstring(), Base, identity, {}, 1, &routing, false);
        check(work.Scheduling.LastGapFreeEpisode == work.RetentionEpisode && !work.Scheduling.Pending,
            "new-episode-completes-only-after-entire-recovery-traversal");
        monitor.DrainPipelineEvents(true);
        for (const auto& event : monitor.Ring)
        {
            const auto found = event.Evidence.find(L"image_scheduling_json");
            if (event.Kind == L"coverage.pipeline" && found != event.Evidence.end()) { pipeline = found->second; }
        }
        check(pipeline != L"null" && mcpjson::ValidateDocument(pipeline) &&
            monitor.ImageTimings.Snapshot().FirstGapFreeAge.Samples == 1 &&
            monitor.ImageTimings.Snapshot().FirstExactReadAge.Samples == 1, "pipeline-publishes-once-only-discovery-milestones");

        const auto missingOwner = std::make_unique<KernelMonitor>();
        auto& missing = *missingOwner;
        const auto missingPath = root / L"missing.exe";
        missing.ScanExecutableImage(missingPath.wstring(), Base, identity, {}, 1);
        auto& absent = missing.ImageWork.begin()->second;
        const auto failedAt = absent.LastAttemptMs;
        const auto pendingAt = absent.Scheduling.PendingSince;
        check(absent.Scheduling.Attempted && !absent.Scheduling.Successful && !absent.Scheduling.ParserAttempted &&
            missing.SelectImageSweepWork(failedAt + 29999) == nullptr &&
            missing.SelectImageSweepWork(failedAt + 30000) == &absent, "failed-reference-retries-after-cooldown-without-rediscovery");
        missing.ScanExecutableImage(missingPath.wstring(), Base, identity, {}, 1);
        check(absent.LastAttemptMs == failedAt && absent.Scheduling.PendingSince == pendingAt,
            "cooldown-rediscovery-keeps-old-pending-and-attempt");
        unavailable = missing.ImageSchedulingJson(GetTickCount64());
        check(Write(missingPath, disk), "reference-appears-after-initial-failure");
        absent.LastAttemptMs = GetTickCount64() - 30000;
        const auto discoveryBeforeRetry = absent.Scheduling.LastSeen;
        check(missing.SelectImageSweepWork(GetTickCount64()) == &absent, "recovered-reference-selected-without-rediscovery");
        missing.ScanExecutableImage(missingPath.wstring(), Base, identity, {}, 1, &routing, false);
        check(absent.Loaded && absent.Sweep.NextRange == 1 && absent.Scheduling.Successful &&
            absent.Scheduling.LastSeen == discoveryBeforeRetry && absent.Scheduling.PendingSince == pendingAt,
            "actual-retry-loads-and-advances-original-pending-work");

        // Controlled time models exercise the production selector. Old failures
        // remain old while successful observations renew their own debt origin.
        for (unsigned scenario = 0; scenario < 3; ++scenario)
        {
            const auto scheduledOwner = std::make_unique<KernelMonitor>();
            auto& scheduled = *scheduledOwner;
            std::wstring operations;
            const auto append = [&](const std::wstring& row) { if (!operations.empty()) { operations += L","; } operations += row; };
            const auto put = [&](unsigned id, uint64_t generation, uint64_t now)
            {
                const auto key = std::to_wstring(id);
                scheduled.ImageWork.erase(key);
                KernelMonitor::ImageVerificationWork entry;
                entry.Loaded = true; entry.Base = 0x10000 + id * 4096;
                entry.Identity.BootId = L"synthetic:scheduling";
                entry.Identity.ProcessId = 100 + id % 3; entry.Identity.CreateTime = generation;
                entry.Path = L"synthetic-image-" + key;
                entry.Sweep.LastCompleteMs = 1;
                entry.Scheduling.Discover(now);
                scheduled.WatchPids.insert(entry.Identity.ProcessId);
                scheduled.ImageWork.emplace(key, std::move(entry));
                append(L"{\"op\":\"put\",\"id\":" + key + L",\"generation\":" + std::to_wstring(generation) + L",\"now\":" + std::to_wstring(now) + L"}");
            };
            for (unsigned id = 0; id < 6; ++id) { put(id, 1, 100 + id); }
            std::set<uint32_t> served;
            for (unsigned turn = 0; turn < 96; ++turn)
            {
                const uint64_t now = 100000 + turn;
                if (scenario == 1 && turn % 3 == 0) { put(6 + turn / 3, 1, now); }
                if (scenario == 2 && turn % 5 == 0) { put(1 + (turn / 5) % 5, 2 + turn / 5, now); }
                auto* selected = scheduled.SelectImageSweepWork(now);
                if (!check(selected != nullptr, "nonempty-selector-makes-progress")) { break; }
                const auto id = static_cast<unsigned>((selected->Base - 0x10000) / 4096);
                served.insert(selected->Identity.ProcessId);
                selected->LastSweepMs = now;
                selected->Scheduling.Begin(now);
                selected->Scheduling.Finish(now, id == 0 ? KmonImageAttemptOutcome::Gaps : KmonImageAttemptOutcome::Observed,
                    id != 0, id != 0, 1);
                append(L"{\"op\":\"select\",\"now\":" + std::to_wstring(now) + L",\"id\":" + std::to_wstring(id) + L"}");
            }
            check(served.size() == 3 && scheduled.ImageDebtPriorityTurns == 24 &&
                !scheduled.ImageWork.at(L"0").Scheduling.Successful, "permanent-old-failure-cannot-consume-ordinary-rotation");
            if (!scenarios.empty()) { scenarios += L","; }
            scenarios += L"{\"name\":" + mcpjson::Quote(scenario == 0 ? L"fixed" : scenario == 1 ? L"growing" : L"delete_reuse") +
                L",\"operations\":[" + operations + L"],\"report\":" + scheduled.ImageSchedulingJson(100096) + L"}";
        }

        const auto boundedOwner = std::make_unique<KernelMonitor>();
        auto& limited = *boundedOwner;
        for (unsigned i = 0; i < 70; ++i)
        {
            KernelMonitor::ImageVerificationWork entry;
            entry.Identity = identity; entry.Base = 0x10000 + i * 4096;
            entry.Path = i == 0 ? std::wstring(70000, L'x') : L"synthetic:bounded-" + std::to_wstring(i);
            entry.Scheduling.Discover(10 + i);
            limited.ImageWork.emplace(std::to_wstring(i), std::move(entry));
        }
        bounded = limited.ImageSchedulingJson(1000);
        check(Array(bounded, L"details").size() == 64 && Text(bounded, L"details_omitted") == L"6" &&
            Raw(bounded, L"details").size() <= 65538 && bounded.find(std::wstring(70000, L'x')) == std::wstring::npos,
            "bounded-json-omits-exact-long-scope-with-denominator");
        const auto invalid = limited.ImageSchedulingJson(0);
        check(Text(invalid, L"snapshot_invalid_clocks") == L"70" && Text(invalid, L"max_resident_observation_debt_ms") == L"0",
            "future-discovery-cannot-underflow-debt");

        KmonImageObservationDebt history;
        check(!history.Begin(0) && history.Discover(0) && history.Begin(1) &&
            history.Finish(2, KmonImageAttemptOutcome::Gaps, true, false, 1) && history.Traversed && !history.Successful &&
            !history.GapFree && history.Pending && history.DebtSince() == 0, "zero-clock-origin-and-gapped-traversal");
        check(history.Discover(10) && !history.Discover(9) && !history.Begin(9) && history.Begin(11) &&
            !history.Finish(10, KmonImageAttemptOutcome::Observed, true, true, 1) && !history.Successful,
            "invalid-clock-cannot-create-success");
        history.Finish(12, KmonImageAttemptOutcome::Observed, true, true, 1);
        history.Begin(13); history.Finish(14, KmonImageAttemptOutcome::Fault, true, true, 2);
        check(history.LastSuccess == 12 && history.LastTraversal == 12 && history.LastGapFree == 12 && history.Pending &&
            history.LastGapFreeEpisode == 1, "fault-cannot-renew-prior-completed-sweep");
        KmonImageTimings clocked;
        ExecutableSweepTiming invalidTiming; invalidTiming.InvalidBudgetClock = true;
        clocked.Turn(4, 5, invalidTiming, KmonImageAttemptOutcome::Gaps, false);
        clocked.Lookup(6, 5, false, false);
        check(clocked.Snapshot().InvalidClocks == 2 && clocked.Snapshot().FailedTurn.Samples == 0,
            "invalid-clock-samples-excluded");
        clocked.Reset();
        check(clocked.Snapshot().InvalidClocks == 0, "new-session-resets-owned-histograms");
    }
    catch (const std::exception&) { check(false, "owned-fixture-exception"); }
    std::error_code ec;
    // Exclusively created absolute fixture root; never a supplied directory.
    std::filesystem::remove_all(root, ec);
    check(!ec && !std::filesystem::exists(root), "owned-fixture-cleanup");
    if (diagnostics != nullptr)
    {
        *diagnostics = L"{\"schema\":\"kn.image_scheduler_test.v1\",\"corpus\":\"owned_files_synthetic_target_and_time\","
            L"\"driver_loaded\":false,\"passed\":" + std::wstring(failures == 0 ? L"true" : L"false") +
            L",\"checks\":" + std::to_wstring(checks) + L",\"pipeline\":" + pipeline + L",\"cancelled\":" + cancelled + L",\"unavailable\":" + unavailable +
            L",\"bounded\":" + bounded + L",\"scenarios\":[" + scenarios + L"]}";
    }
    std::fprintf(stderr, "[image.scheduler] checks=%u failed=%u\n", checks, failures);
    return failures == 0;
}

bool KmonPublicationSchedulingIntegrationSelfTest(std::wstring* diagnostics)
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* name)
    { ++checks; if (!ok) { ++failures; std::fprintf(stderr, "[publication.writer] FAIL %s\n", name); } return ok; };
    wchar_t temporary[MAX_PATH]{}, unique[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, temporary) || !GetTempFileNameW(temporary, L"knw", 0, unique)) { return false; }
    if (!DeleteFileW(unique) || !CreateDirectoryW(unique, nullptr)) { return false; }
    const std::filesystem::path root = std::filesystem::absolute(unique);
    std::wstring normal = L"null", stopped = L"null", receipts;
    try
    {
        const auto owner = std::make_unique<KernelMonitor>();
        auto& monitor = *owner;
        const auto store = root / L"private";
        if (!check(InitializeEvidencePrivateStore(store.wstring(), false).Initialized, "owned-private-store")) { throw std::runtime_error("store"); }
        monitor.Options.LogDirectory = store.wstring();
        Source source(L"synthetic:publication-writer");
        const auto disk = Fixture(&source.Bytes);
        const auto reference = root / L"reference.exe";
        if (!check(Write(reference, disk), "owned-reference")) { throw std::runtime_error("reference"); }
        ObservationIdentity synthetic; synthetic.BootId = L"synthetic:writer:boot"; synthetic.ProcessId = 42; synthetic.CreateTime = 1;
        ObservationReadRouting routing;
        routing.Primary = &source; routing.TargetId = L"synthetic:42:1"; routing.AddressSpaceId = L"synthetic:42:1:user";
        check(monitor.ScanExecutableImage(reference.wstring(), Base, synthetic, {}, 16, &routing) == CodeOwnership::OwnedVerified,
            "actual-image-acquisition-queued");

        auto* allocation = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        const auto release = [](uint8_t* memory) { if (memory) { VirtualFree(memory, 0, MEM_RELEASE); } };
        std::unique_ptr<uint8_t, decltype(release)> memory(allocation, release);
        if (allocation == nullptr) { throw std::runtime_error("memory"); }
        std::fill(allocation, allocation + 4096, uint8_t{0x31});
        const auto identity = ObserveProcessIdentity(GetCurrentProcessId(), GetCurrentProcess());
        check(monitor.QueueCapture(L"owned_writer_page", reinterpret_cast<uint64_t>(allocation), 4096, identity, 0, nullptr),
            "actual-native-page-admitted");
        monitor.CaptureStopping.store(true); monitor.CaptureLoop();
        check(monitor.CapturedPages.Size() == 1 && monitor.CaptureReadBytes.load() == 4096, "actual-page-acquisition-finished");
        ObservationContext context; context.Identity = identity;
        check(monitor.QueueCapturedBytes(L"owned_historical_bytes", reinterpret_cast<uint64_t>(allocation), context, {0x31, 0x31}) != 0,
            "opaque-existing-bytes-admitted-with-unknown-acquisition");

        EvidenceBundle bundle;
        bundle.Acquisition = L"local_user_reader";
        bundle.CaptureStartedMs = GetTickCount64();
        KmonHuntReference target;
        target.Context.Identity = identity; target.Context.MonotonicMs = GetTickCount64();
        target.Context.Timestamp = ObservationFileTime(); target.Context.Source = L"owned_writer_fixture";
        target.Context.DependencyGroup = L"owned_fixture_memory"; target.Context.Ownership = CodeOwnership::UnownedExecutable;
        target.Address = target.Root = reinterpret_cast<uint64_t>(allocation);
        const auto pointer = target.Address; target.Slot = reinterpret_cast<uint64_t>(&pointer);
        target.Role = L"manifest_vtable"; target.SlotStable = true;
        std::vector<uint8_t> head(32), slot(8); SIZE_T headRead = 0, slotRead = 0;
        check(ReadProcessMemory(GetCurrentProcess(), allocation, head.data(), head.size(), &headRead) && headRead == head.size() &&
            ReadProcessMemory(GetCurrentProcess(), &pointer, slot.data(), slot.size(), &slotRead) && slotRead == slot.size(), "owned-native-bundle-inputs");
        bundle.Spans = {{target.Address, 32, L"target_head", L"valid", head}, {target.Slot, 8, L"pointer_slot", L"valid", slot}};
        bundle.CaptureEndedMs = GetTickCount64(); bundle.ReferenceConsistent = true;
        check(monitor.HuntIndex.Observe(target, GetTickCount64(), &bundle.Receipt) != 0, "owned-bundle-receipt");
        check(monitor.QueueEvidenceBundle(bundle, {bundle.CaptureStartedMs, bundle.CaptureEndedMs, true}) != 0, "live-bundle-acquisition-window");
        auto artifact = std::make_shared<PendingIrpEvidenceArtifact>();
        const std::string raw = "{\"schema\":\"kn.irp_capture.v2\",\"owned_writer_fixture\":true}";
        artifact->Bytes.assign(raw.begin(), raw.end()); artifact->Sha256 = ContentHash::Bytes(artifact->Bytes);
        // This is a serialization/publication control, not a live IRP read.
        check(monitor.QueueIrpCapture(artifact), "synthetic-raw-irp-with-unknown-acquisition");
        check(DeleteFileW(reference.c_str()) != FALSE, "reference-source-removed-before-writer");
        memory.reset();
        const auto before = monitor.PublicationPending(GetTickCount64());
        check(before[0].Count == 1 && before[1].Count == 1 && before[2].Count == 1 && before[3].Count == 2,
            "all-four-production-queues-ready-before-writer");
        monitor.CaptureWriter = std::thread(&KernelMonitor::CaptureWriterLoop, &monitor);
        const auto deadline = GetTickCount64() + 10000;
        bool completed = false;
        do
        {
            uint64_t attempts = 0;
            for (size_t i = 0; i < 4; ++i) { attempts += monitor.PublicationTimings.Snapshot(static_cast<KmonPublicationFamily>(i)).Attempts; }
            completed = attempts == 5;
            if (!completed) { std::this_thread::yield(); }
        } while (!completed && GetTickCount64() < deadline);
        monitor.WriterStopping.store(true); monitor.CaptureWriter.join();
        check(completed && monitor.CaptureWriterDone.load(), "writer-completion-observed-before-stop");
        monitor.DrainPipelineEvents(true);
        for (const auto& event : monitor.Ring)
        {
            const auto summary = event.Evidence.find(L"publication_scheduling_json");
            if (summary != event.Evidence.end()) { normal = summary->second; }
            const auto receipt = event.Evidence.find(L"publication_timing_json");
            if (receipt != event.Evidence.end()) { if (!receipts.empty()) { receipts += L","; } receipts += receipt->second; }
        }
        check(normal != L"null" && Array(L"{\"rows\":[" + receipts + L"]}", L"rows").size() == 5,
            "actual-writer-publishes-summary-and-per-job-times");
        for (size_t i = 0; i < 4; ++i)
        {
            const auto count = monitor.PublicationTimings.Snapshot(static_cast<KmonPublicationFamily>(i));
            check(count.Attempts == (i == 3 ? 2u : 1u) && count.Complete == count.Attempts && count.Partial == 0 && count.Failed == 0 &&
                count.Files == count.Attempts && count.Journals == (i == 0 || i == 2 ? 1u : 0u) && count.InvalidClocks == 0,
                "family-specific-file-and-journal-completion");
        }
        check(monitor.PublicationTimings.Snapshot(KmonPublicationFamily::Page).UnknownAcquisition == 1 &&
            monitor.PublicationTimings.Snapshot(KmonPublicationFamily::Irp).UnknownAcquisition == 1 && monitor.CapturedFiles.size() == 2,
            "unknown-origins-remain-unknown-after-success");
        for (const auto& file : monitor.CapturedFiles)
        {
            std::ifstream input(file, std::ios::binary);
            const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
            check((bytes.size() == 4096 || bytes.size() == 2) && std::all_of(bytes.begin(), bytes.end(), [](uint8_t value) { return value == 0x31; }),
                "durable-page-bytes-survive-original-memory-removal");
        }

        const auto failedOwner = std::make_unique<KernelMonitor>();
        auto& failed = *failedOwner;
        const auto failureStore = root / L"partial";
        failed.StopRequested.store(true); // Partial startup has not joined producers yet.
        const auto emptyBeforeShutdown = failed.PublicationPending(GetTickCount64());
        check(std::all_of(emptyBeforeShutdown.begin(), emptyBeforeShutdown.end(), [](const auto& item) { return item.Count == 0; }) &&
            !failed.PublicationDrainComplete(), "stop-request-before-producer-join-cannot-close-empty-writer");
        std::filesystem::create_directories(failureStore);
        check(Write(failureStore / L"collections", {0x78}), "block-journal-with-owned-file");
        failed.Options.LogDirectory = failureStore.wstring();
        auto operation = std::make_shared<ObservationReadOperation>(L"synthetic:writer-gap", routing.TargetId, routing.AddressSpaceId);
        ObservationReadRouter router(routing, operation); std::vector<uint8_t> observed;
        check(router.ReadExact(Base, 32, &observed) && failed.QueueImageReadSet(router.Snapshot(), synthetic, L"synthetic", Base) != 0,
            "raw-image-queued-before-journal-failure");
        failed.CapturedBytes = 256ull * 1024 * 1024;
        check(failed.QueueCapturedBytes(L"owned_budget_failure", Base, context, {0x31}) != 0, "queue-page-before-budget-failure");
        failed.WriterStopping.store(true);
        check(!failed.PublicationDrainComplete(), "stale-empty-dispatch-snapshot-cannot-discard-final-enqueue");
        failed.CaptureWriterLoop();
        check(failed.PublicationDrainComplete(), "joined-producers-and-fresh-empty-queues-permit-close");
        const auto partial = failed.PublicationTimings.Snapshot(KmonPublicationFamily::Image, true);
        const auto rejected = failed.PublicationTimings.Snapshot(KmonPublicationFamily::Page, true);
        check(partial.Attempts == 1 && partial.Partial == 1 && partial.Files == 1 && partial.Journals == 0 && partial.Complete == 0,
            "raw-file-success-cannot-be-counted-as-journal-success");
        check(rejected.Failed == 1 && rejected.Files == 0 && rejected.Complete == 0 &&
            failed.PublicationTimings.Snapshot(KmonPublicationFamily::Page).Attempts == 0, "failed-shutdown-does-not-enter-normal-success");
        stopped = failed.PublicationTimings.Json(failed.PublicationPending(GetTickCount64()), GetTickCount64());
    }
    catch (const std::exception&) { check(false, "owned-publication-fixture-exception"); }
    std::error_code ec;
    // Exclusively created absolute root. No caller-supplied path is removed.
    std::filesystem::remove_all(root, ec);
    check(!ec && !std::filesystem::exists(root), "owned-publications-and-fixtures-cleaned");
    if (diagnostics != nullptr)
    {
        *diagnostics = L"{\"schema\":\"kn.publication_writer_test.v1\",\"driver_loaded\":false,"
            L"\"corpus\":\"owned_files_native_page_and_bundle_synthetic_image_and_irp\",\"passed\":" +
            std::wstring(failures == 0 ? L"true" : L"false") + L",\"checks\":" + std::to_wstring(checks) +
            L",\"normal\":" + normal + L",\"shutdown\":" + stopped + L",\"receipts\":[" + receipts + L"]}";
    }
    std::fprintf(stderr, "[publication.writer] checks=%u failed=%u\n", checks, failures);
    return failures == 0;
}
