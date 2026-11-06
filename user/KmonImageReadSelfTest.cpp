#include "KernelMonitor.h"
#include "ObservationReadRoutingJson.h"
#include "ContentHash.h"
#include "ImageSliceRecipe.h"
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
        pressure.WriterStopping.store(true); pressure.CaptureWriterLoop();
        check(pressure.ImageReadsWritten.load() == 8 && pressure.ImageReadsFailed.load() == 0 &&
            pressure.CapturedImageReadSets.Size() == 0, "shutdown-drains-full-image-read-queue");
        check(pressure.ImageReferenceBlobsCreated.load() == 1 && pressure.ImageReferenceBlobsReused.load() == 7 &&
            pressure.ImageReferenceBytes.load() == disk.size() && pressure.ImageReferenceReservedBytes->load() == 0,
            "slice-archives-share-one-content-addressed-reference-and-release-reservations");
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
                    reported |= event.Kind == L"coverage.image_reads" && reason != event.Evidence.end() &&
                        reason->second == L"read_set_directory_unavailable";
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
