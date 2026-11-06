#include "KernelMonitor.h"
#include "ObservationReadRoutingJson.h"
#include "ContentHash.h"
#include "ImageSliceRecipe.h"
#include "ImageSweepGraph.h"
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
            else if (!Fail && request.Address >= Base && request.Address - Base < Bytes.size() &&
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
        KernelMonitor monitor;
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
        retained.ReferenceCharge.reset(); // Only the requeued item owns the queue reservation.
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
            !replayed.Proof.empty() && monitor.ImageSlicesWritten.load() == 1 && secondary.Calls.size() == calls,
            "actual-kmon-slice-replays-after-target-and-original-reference-removal");
        const auto sweepPath = root / L"image-sweeps" / (L"sweep-" + (retained.Sweep ? retained.Sweep->Sweep.SweepId : L"missing") + L".knsweep");
        const auto sweepReplay = ReplayImageRecipe(sweepPath.wstring(), false, nullptr);
        check(sweepReplay.Status == L"replayed" && Text(sweepReplay.Proof, L"changed_bytes") == L"1" &&
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
        ImageSweepManifest sweepManifest;
        check(ReadAnalystSnapshot(sweepPath.wstring(), &sweepJson, nullptr) && ParseImageSweepManifest(sweepJson, &sweepManifest),
            "actual-kmon-manifest-canonical-membership");
        for (unsigned mode = 0; mode < 2; ++mode)
        {
            KernelMonitor denied;
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
        KernelMonitor clean;
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
            KernelMonitor multiple;
            multiple.Options.LogDirectory = (root / L"multiple").wstring();
            const auto first = multiple.ScanExecutableImage(twoPath.wstring(), Base, identity, {}, 1, &routing);
            const auto second = multiple.ScanExecutableImage(twoPath.wstring(), Base, identity, {}, 1, &routing);
            KernelMonitor partialSweep;
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
        KernelMonitor unstable;
        unstable.Options.LogDirectory = (root / L"unstable").wstring();
        check(unstable.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing) == CodeOwnership::OwnedUnverified &&
            unstable.ImageReadsQueued.load() == 1, "unstable-page-keeps-inconclusive-originals");
        secondary.Unstable = false; secondary.Fail = true;
        KernelMonitor failed;
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
            KernelMonitor incomplete;
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
            KernelMonitor blockedJournal;
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
                KernelMonitor blocked;
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
            KernelMonitor resumed;
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
            KernelMonitor blocked;
            const auto directory = root / (L"slice-failure-" + std::to_wstring(mode));
            blocked.Options.LogDirectory = directory.wstring();
            if (mode == 0) { blocked.ImageSliceBytes.store(128ull * 1024 * 1024); }
            if (mode == 2) { blocked.ImageReferenceBytes.store(128ull * 1024 * 1024); }
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
        KernelMonitor pressure;
        pressure.Options.LogDirectory = (root / L"pressure").wstring();
        for (unsigned i = 0; i < 9; ++i) { pressure.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference); }
        check(pressure.ImageReadsQueued.load() == 8 && pressure.ImageReadsDropped.load() == 1 &&
            pressure.CapturedImageReadSets.Size() == 8, "queue-pressure-counts-rejected-original-set");
        pressure.ScanExecutableImage(reference.wstring(), Base, identity, {}, 16, &routing);
        check(pressure.ImageSweepsStarted.load() == 1 && pressure.ImageSweepTerminalsObserved.load() == 1 &&
            pressure.ImageReadsDropped.load() == 2, "entirely-dropped-sweep-remains-in-session-denominators");
        pressure.WriterStopping.store(true); pressure.CaptureWriterLoop();
        check(pressure.ImageReadsWritten.load() == 8 && pressure.ImageReadsFailed.load() == 0 &&
            pressure.CapturedImageReadSets.Size() == 0, "shutdown-drains-full-image-read-queue");
        check(pressure.ImageReferenceBlobsCreated.load() == 1 && pressure.ImageReferenceBlobsReused.load() == 7 &&
            pressure.ImageReferenceBytes.load() == disk.size() && pressure.ImageReferenceReservedBytes->load() == 0,
            "slice-archives-share-one-content-addressed-reference-and-release-reservations");
        std::wstring pressureLedger;
        check(ReadAnalystSnapshot((root / L"pressure" / L"image-reads" /
            (L"session-" + std::to_wstring(pressure.EvidenceCollectionEpoch.load()) + L".knreadledger")).wstring(), &pressureLedger, nullptr) &&
            Raw(pressureLedger, L"sweeps_started") == L"1" && Raw(pressureLedger, L"sweep_terminals_observed") == L"1" &&
            Raw(pressureLedger, L"sweep_manifests_written") == L"0" && Raw(pressureLedger, L"dropped") == L"2",
            "final-ledger-exposes-sweep-with-no-retained-slices");
        {
            KernelMonitor busy;
            busy.ImageReferenceReservedBytes->store(128ull * 1024 * 1024);
            check(busy.QueueImageReadSet(set, identity, L"synthetic", Base, &retained.Reference) == 0 &&
                busy.ImageReadsDropped.load() == 1 && busy.CapturedImageReadSets.Size() == 0 &&
                busy.ImageReferenceReservedBytes->load() == 128ull * 1024 * 1024, "reference-queue-memory-budget-is-shared-and-fail-closed");
            busy.ImageReferenceReservedBytes->store(0);
        }
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            KernelMonitor missing;
            const auto folder = root / (L"reference-failure-" + std::to_wstring(mode));
            missing.Options.LogDirectory = folder.wstring();
            auto capture = retained.Reference;
            if (mode == 0) { missing.ImageReferenceBytes.store(128ull * 1024 * 1024); }
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
            KernelMonitor rejected;
            rejected.Options.LogDirectory = mode == 1 ? reference.wstring() : (root / (L"rejected-" + std::to_wstring(mode))).wstring();
            if (mode == 0) { rejected.ImageReadsBytes.store(128ull * 1024 * 1024); }
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
        KernelMonitor oversized;
        check(oversized.QueueImageReadSet(set, identity, std::wstring(EvidenceBundleMaxJsonBytes, L'x'), Base) == 0 &&
            oversized.ImageReadsDropped.load() == 1 && oversized.CapturedImageReadSets.Size() == 0, "oversize-archive-rejected-before-queue");
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
