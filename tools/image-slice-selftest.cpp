#include "../user/ImageSliceRecipe.h"
#include "../user/ImageSweepManifest.h"
#include "../user/ObservationReadRoutingJson.h"
#include "../user/ContentHash.h"
#include "../user/AnalystSnapshot.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>

namespace
{
    constexpr uint64_t Base = 0x180000000ull, Preferred = 0x140000000ull;
    unsigned Checks = 0, Failures = 0;
    void Check(bool pass, const char* name)
    {
        ++Checks;
        if (!pass) { ++Failures; std::cerr << "FAIL " << name << "\n"; }
    }
    bool Write(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        out.close();
        return !out.fail();
    }
    template<class T> void Put(std::vector<uint8_t>& data, size_t offset, const T& value)
    {
        if (offset > data.size() || sizeof(value) > data.size() - offset) { throw std::runtime_error("fixture bounds"); }
        std::memcpy(data.data() + offset, &value, sizeof(value));
    }
    std::vector<uint8_t> Fixture(std::vector<uint8_t>* memory)
    {
        std::vector<uint8_t> file(0x2800);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 2;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;
        nt.FileHeader.TimeDateStamp = 0x12345678;
        auto& h = nt.OptionalHeader;
        h.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        h.ImageBase = Preferred; h.SizeOfImage = 0x4000; h.SizeOfHeaders = 0x400;
        h.SectionAlignment = 0x1000; h.FileAlignment = 0x200;
        h.MajorOperatingSystemVersion = h.MajorSubsystemVersion = 6;
        h.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        h.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        h.SizeOfStackReserve = h.SizeOfHeapReserve = 1024 * 1024;
        h.SizeOfStackCommit = h.SizeOfHeapCommit = 4096;
        h.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        h.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x3000, 12};
        h.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {0x1100, 8};
        IMAGE_SECTION_HEADER sections[2]{};
        std::memcpy(sections[0].Name, ".code", 5);
        sections[0].VirtualAddress = 0x1000; sections[0].Misc.VirtualSize = sections[0].SizeOfRawData = 0x2000;
        sections[0].PointerToRawData = 0x400; sections[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        std::memcpy(sections[1].Name, ".reloc", 6);
        sections[1].VirtualAddress = 0x3000; sections[1].Misc.VirtualSize = 0x1000;
        sections[1].SizeOfRawData = 0x400; sections[1].PointerToRawData = 0x2400; sections[1].Characteristics = IMAGE_SCN_MEM_READ;
        Put(file, 0, dos); Put(file, 0x80, nt); Put(file, 0x80 + sizeof(nt), sections);
        std::fill(file.begin() + 0x400, file.begin() + 0x2400, uint8_t{0x90});
        Put(file, 0x420, Preferred + 0x1234);
        const IMAGE_BASE_RELOCATION block{0x1000, 12};
        Put(file, 0x2400, block); Put(file, 0x2408, uint16_t{0xA020}); Put(file, 0x240A, uint16_t{0});
        memory->assign(0x4000, 0);
        std::copy(file.begin(), file.begin() + 0x400, memory->begin());
        std::copy(file.begin() + 0x400, file.begin() + 0x2400, memory->begin() + 0x1000);
        std::copy(file.begin() + 0x2400, file.end(), memory->begin() + 0x3000);
        Put(*memory, 0x1020, Base + 0x1234);
        (*memory)[0x1100] ^= 1; // A known loader exclusion, never a code difference.
        return file;
    }
    class Source final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::vector<uint8_t> Bytes;
        bool Partial = false, Unstable = false, Unreadable = false, ChangeHeader = false;
        size_t Calls = 0, PageReads = 0;
        explicit Source(const wchar_t* id)
        {
            Caps.SourceId = id; Caps.Consistency = L"owned_synthetic_non_atomic";
            Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4); Caps.UserOnly = true;
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& q) override
        {
            ++Calls;
            ObservationReadResult r;
            r.NativeStatusDomain = L"win32"; r.NativeStatus = Partial || Unreadable ? 299 : 0;
            if (Partial)
            {
                r.Spans = {{q.Address, 1, ObservationReadState::Complete, {0x41}},
                    {q.Address + 1, q.Length - 1, ObservationReadState::Failed, {}}};
            }
            else if (!Unreadable && q.Address >= Base && q.Address - Base < Bytes.size() && q.Length <= Bytes.size() - (q.Address - Base))
            {
                if (q.Address == Base + 0x1000)
                {
                    if (++PageReads == 2 && Unstable) { Bytes[0x1050] ^= 1; }
                    if (ChangeHeader) { Bytes[0] = 0; }
                }
                const auto offset = static_cast<size_t>(q.Address - Base);
                r.Spans = {{q.Address, q.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(Bytes.begin() + offset, Bytes.begin() + offset + q.Length)}};
            }
            else { r.Spans = {{q.Address, q.Length, ObservationReadState::Failed, {}}}; }
            return r;
        }
    };
}

namespace
{
    void SweepTests(const std::filesystem::path& root)
    {
        for (const auto scenario : {L"sweep_clean", L"sweep_modified", L"sweep_excluded", L"sweep_gap", L"sweep_interrupted", L"sweep_secondary"})
        {
            const auto folder = root / scenario;
            std::filesystem::create_directories(folder / L"image-reads");
            std::filesystem::create_directories(folder / L"image-sweeps");
            const auto original = folder / L"original.exe";
            Source source(L"synthetic:sweep");
            auto disk = Fixture(&source.Bytes);
            if (std::wstring(scenario) != L"sweep_excluded")
            {
                const size_t offset = 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory) +
                    IMAGE_DIRECTORY_ENTRY_IAT * sizeof(IMAGE_DATA_DIRECTORY);
                Put(disk, offset, IMAGE_DATA_DIRECTORY{});
                Put(source.Bytes, offset, IMAGE_DATA_DIRECTORY{});
                source.Bytes[0x1100] = disk[0x500]; // The removed exclusion must not leave a hidden fixture change.
            }
            if (std::wstring(scenario) == L"sweep_modified") { source.Bytes[0x1050] ^= 1; }
            Check(Write(original, disk), "sweep-owned-reference");
            std::unique_ptr<void, decltype(&CloseHandle)> section(nullptr, &CloseHandle);
            std::unique_ptr<void, decltype(&UnmapViewOfFile)> view(nullptr, &UnmapViewOfFile);
            if (std::wstring(scenario) == L"sweep_secondary")
            {
                const auto handle = CreateFileW(original.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (handle == INVALID_HANDLE_VALUE) { throw std::runtime_error("sweep fixture image handle"); }
                section.reset(CreateFileMappingW(handle, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
                CloseHandle(handle);
                if (section) { view.reset(MapViewOfFile(section.get(), FILE_MAP_READ, 0, 0, 0)); }
                if (!view) { throw std::runtime_error("sweep fixture image view"); }
                for (const auto span : {std::pair<size_t, size_t>{0, 0x400}, {0x1000, 0x2000}})
                {
                    SIZE_T received = 0;
                    if (!ReadProcessMemory(GetCurrentProcess(), static_cast<const uint8_t*>(view.get()) + span.first,
                        source.Bytes.data() + span.first, span.second, &received) || received != span.second)
                    { throw std::runtime_error("sweep fixture mapped bytes"); }
                }
            }
            executable_image::DiskPeMetadata metadata;
            ExecutableSweep schedule;
            Check(executable_image::ReadDiskPeMetadata(original.wstring(), &metadata, nullptr) && schedule.Initialize(metadata), "sweep-schedule");
            ObservationReadRouting routing;
            routing.Primary = &source; routing.TargetId = L"synthetic:target"; routing.AddressSpaceId = L"synthetic:user";
            FILETIME time{}; GetSystemTimeAsFileTime(&time);
            ImageSweepIdentity identity;
            identity.CollectionId = L"7"; identity.SweepId = L"7-1"; identity.Image = original.wstring(); identity.ImageBase = Base;
            identity.Identity.BootId = L"synthetic:boot"; identity.Identity.ProcessId = 42; identity.Identity.CreateTime = 1;
            identity.TargetId = routing.TargetId; identity.AddressSpaceId = routing.AddressSpaceId;
            identity.TotalRanges = static_cast<uint32_t>(schedule.Ranges.size()); identity.ExpectedBytes = schedule.Coverage.RequestedBytes;
            identity.StartedTick = GetTickCount64(); identity.StartedFileTime = (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
            std::vector<ImageSweepContext> contexts;
            std::vector<std::wstring> recipes, rawPayloads;
            std::vector<ExecutableSweepReference> references;
            for (uint64_t index = 0; index < 2; ++index)
            {
                auto operation = std::make_shared<ObservationReadOperation>(L"sweep:" + std::to_wstring(index), routing.TargetId, routing.AddressSpaceId);
                ObservationReadRouter router(routing, operation);
                ExecutableSliceTrace trace;
                ExecutableSweepReference reference;
                const auto pages = AdvanceExecutableSweep(original.wstring(), metadata, Base,
                    [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes) { return router.ReadExact(address, length, bytes); },
                    1, GetTickCount64(), &schedule, 0, &reference, &trace);
                const auto reads = router.Snapshot();
                const auto json = CaptureImageSliceRecipeJson(metadata, Base, reference, trace, reads, pages);
                ImageSliceRecipe parsed;
                Check(ParseImageSliceRecipe(json, &parsed) && trace.StartRange == index && trace.PageCount == 1, "original-multi-slice-capture");
                ImageSweepContext context;
                context.Sweep = identity; context.Slice.Ordinal = index + 1; context.Slice.ReadSetId = index + 1;
                context.Slice.StartRange = trace.StartRange; context.Slice.RangeCount = trace.PageCount;
                context.Slice.StartedTick = reads.Attempts.StartedTick; context.Slice.EndedTick = reads.Attempts.SnapshotTick;
                context.Slice.ObservedFileTime = identity.StartedFileTime;
                context.Slice.Terminal = context.Slice.TraversalComplete = index == 1;
                context.Slice.Reason = schedule.Coverage.Reason;
                context.Slice.ReferenceSha256 = parsed.ReferenceSha256;
                context.Slice.ReferenceWritten = context.Slice.RawWritten = context.Slice.RecipeWritten = true;
                mcpjson::GetString(json, L"recipe_sha256", &context.Slice.RecipeSha256);
                const auto payload = L"{\"image_base\":" + mcpjson::Quote(std::to_wstring(Base)) +
                    L",\"boot_id\":\"synthetic:boot\",\"pid\":\"42\",\"creation_time\":\"1\",\"reads\":" +
                    ObservationRoutedReadSetJson(reads) + L",\"slice_inputs\":" + ImageSliceInputsJson(trace) +
                    L",\"reference\":{\"sha256\":" + mcpjson::Quote(parsed.ReferenceSha256) +
                    L",\"original_file_identity\":" + mcpjson::Quote(parsed.OriginalFileIdentity) +
                    L",\"persistence\":\"committed\",\"content_rechecked\":true,\"content_stable\":true}}";
                const auto bytes = mcpjson::WideToUtf8(payload);
                context.Slice.RawPayloadSha256 = ContentHash::Bytes(std::vector<uint8_t>(bytes.begin(), bytes.end()));
                contexts.push_back(context); recipes.push_back(json); rawPayloads.push_back(payload); references.push_back(reference);
            }
            source.Bytes.clear();
            view.reset(); section.reset();
            Check(DeleteFileW(original.c_str()) != FALSE, "sweep-original-removed-before-publication");
            ImageSweepManifestStore store;
            std::optional<ImageSweepManifest> final;
            for (size_t index = 0; index < contexts.size(); ++index)
            {
                if ((std::wstring(scenario) == L"sweep_gap" && index == 0) ||
                    (std::wstring(scenario) == L"sweep_interrupted" && index == 1)) { continue; }
                std::unique_ptr<ReferenceArtifact> lease;
                bool created = false;
                Check(PublishReferenceBlob((folder / L"image-references").wstring(), *references[index].Artifact, UINT64_MAX,
                    &lease, &created, nullptr), "sweep-shared-reference-publication");
                const auto name = L"reads-7-" + std::to_wstring(index + 1);
                Check(SaveObservationJson((folder / L"image-reads" / (name + L".knslice")).wstring(), recipes[index], nullptr), "sweep-recipe-publication");
                const auto raw = L"{\"schema\":\"kn.image_reads.v3\",\"payload_sha256\":" +
                    mcpjson::Quote(contexts[index].Slice.RawPayloadSha256) + L",\"payload\":" + rawPayloads[index] + L"}";
                Check(SaveObservationJson((folder / L"image-reads" / (name + L".knreads")).wstring(), raw, nullptr), "sweep-raw-publication");
                final = store.Observe(contexts[index]);
            }
            if (!final) { final = store.TakeIncomplete(); }
            Check(final.has_value() && store.Pending() == 0 && store.RetainedEntries() == 0, "sweep-state-released-at-closure");
            if (!final) { continue; }
            const auto manifestPath = folder / L"image-sweeps" / L"sweep-7-1.knsweep";
            const auto json = ImageSweepManifestJson(*final);
            ImageSweepManifest parsed;
            Check(!json.empty() && ParseImageSweepManifest(json, &parsed) && SaveObservationJson(manifestPath.wstring(), json, nullptr), "sweep-canonical-publication");
            const auto replay = ReplayImageRecipe(manifestPath.wstring(), false, nullptr);
            if (replay.Status != L"replayed") { std::wcerr << scenario << L": " << replay.Status << L"\n"; }
            Check(replay.Status == L"replayed" && !replay.Proof.empty(), "sweep-replay-after-original-source-removal");
            Check(ReplayImageRecipe(manifestPath.wstring(), true, nullptr).Status == L"sweep_current_reanalysis_unavailable", "sweep-current-policy-is-explicitly-unavailable");
            Check(!SaveObservationJson(manifestPath.wstring(), L"{}", nullptr), "sweep-collision-never-replaces-root");
            if (std::wstring(scenario) == L"sweep_clean")
            {
                auto altered = parsed;
                altered.Slices.back().ReadSetId = altered.Slices.front().ReadSetId;
                const auto duplicate = folder / L"image-sweeps" / L"duplicate.knsweep";
                Check(SaveObservationJson(duplicate.wstring(), ImageSweepManifestJson(altered), nullptr) &&
                    ReplayImageRecipe(duplicate.wstring(), false, nullptr).Status == L"duplicate_slice_artifact", "duplicate-leaf-cannot-inflate-coverage");
                altered = parsed; altered.Slices.back().RecipeSha256.assign(64, L'a');
                const auto wrong = folder / L"image-sweeps" / L"wrong.knsweep";
                Check(SaveObservationJson(wrong.wstring(), ImageSweepManifestJson(altered), nullptr) &&
                    ReplayImageRecipe(wrong.wstring(), false, nullptr).Proof.empty(), "rehashed-root-cannot-substitute-a-recipe");
                altered = parsed; altered.Sweep.TargetId += L":other";
                const auto target = folder / L"image-sweeps" / L"other-target.knsweep";
                Check(SaveObservationJson(target.wstring(), ImageSweepManifestJson(altered), nullptr) &&
                    ReplayImageRecipe(target.wstring(), false, nullptr).Status == L"slice_membership_mismatch", "sweep-target-identity-binds-original-receipts");
            }
            // A tiny metadata budget must retain the missing-entry denominator.
            ImageSweepManifestStore bounded({1, 1, 1});
            Check(!bounded.Observe(contexts[0]).has_value(), "sweep-budget-first-entry-pending");
            const auto truncated = bounded.Observe(contexts[1]);
            Check(truncated && truncated->ObservedSlices == 2 && truncated->Slices.size() == 1 &&
                truncated->TerminalObserved && bounded.EntryDrops() == 1 && bounded.RetainedEntries() == 0,
                "sweep-metadata-budget-preserves-terminal-and-loss");
            ImageSweepManifestStore admission({0, 1, 1});
            Check(!admission.Observe(contexts[0]) && admission.AdmissionDeniedSlices() == 1 && admission.Pending() == 0,
                "sweep-active-group-admission-loss-counted");
            ImageSweepManifestStore contradictory;
            contradictory.Observe(contexts[0]);
            auto mismatched = contexts[1]; mismatched.Sweep.Identity.CreateTime += 1;
            const auto conflict = contradictory.Observe(mismatched);
            Check(conflict && conflict->Inconsistent && conflict->Slices.size() == 1 &&
                contradictory.EntryDrops() == 1, "conflicting-process-generation-cannot-join-sweep");
            auto invalid = parsed;
            invalid.LastEndedTick += 1;
            Check(ImageSweepManifestJson(invalid).empty(), "manifest-cannot-extend-last-retained-observation-time");
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring(argv[1]) == L"--replay")
    {
        const auto replay = ReplayImageRecipe(argv[2], false, nullptr);
        std::cout << mcpjson::WideToUtf8(ImageRecipeReplayJson(replay)) << "\n";
        return replay.Status == L"replayed" ? 0 : 1;
    }
    if (argc != 2) { return 2; }
    std::error_code ec;
    const auto root = std::filesystem::absolute(argv[1], ec);
    if (ec || !std::filesystem::create_directory(root, ec) || ec) { return 2; }
    try
    {
        for (const auto& name : {L"clean", L"modified", L"unstable", L"unreadable", L"guard", L"identity", L"continuation",
            L"secondary", L"secondary_verified", L"secondary_modified", L"secondary_unstable"})
        {
            const auto folder = root / name;
            std::filesystem::create_directories(folder / L"image-reads");
            const auto original = folder / L"original.exe";
            Source primary(L"synthetic:partial"), fallback(L"synthetic:memory");
            primary.Partial = true;
            const auto disk = Fixture(&fallback.Bytes);
            if (!Write(original, disk)) { throw std::runtime_error("fixture write failed"); }
            executable_image::DiskPeMetadata metadata;
            Check(executable_image::ReadDiskPeMetadata(original.wstring(), &metadata, nullptr), "read-independent-pe-fixture");
            const std::wstring scenario(name);
            const bool secondaryPositive = scenario.rfind(L"secondary_", 0) == 0;
            std::unique_ptr<void, decltype(&CloseHandle)> mappedSection(nullptr, &CloseHandle);
            std::unique_ptr<void, decltype(&UnmapViewOfFile)> mappedView(nullptr, &UnmapViewOfFile);
            if (secondaryPositive)
            {
                HANDLE file = CreateFileW(original.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (file == INVALID_HANDLE_VALUE) { throw std::runtime_error("fixture image handle"); }
                mappedSection.reset(CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr));
                CloseHandle(file);
                if (mappedSection) { mappedView.reset(MapViewOfFile(mappedSection.get(), FILE_MAP_READ, 0, 0, 0)); }
                if (!mappedView) { throw std::runtime_error("fixture image mapping"); }
                for (const auto& span : {std::pair<size_t, size_t>{0, 0x400}, {0x1000, 0x2000}})
                {
                    SIZE_T count = 0;
                    if (!ReadProcessMemory(GetCurrentProcess(), static_cast<const uint8_t*>(mappedView.get()) + span.first,
                        fallback.Bytes.data() + span.first, span.second, &count) || count != span.second) { throw std::runtime_error("fixture mapped bytes"); }
                }
                uint64_t headerBase = 0;
                std::memcpy(&headerBase, fallback.Bytes.data() + 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase), sizeof(headerBase));
                Check(headerBase != Preferred && headerBase != Base && headerBase != 0,
                    "actual-no-execute-section-provides-independent-third-base");
                if (scenario == L"secondary_modified" || scenario == L"secondary_unstable") { fallback.Bytes[0x1050] ^= 1; }
            }
            if (scenario == L"modified" || scenario == L"unstable") { fallback.Bytes[0x1050] ^= 1; }
            fallback.Unstable = scenario == L"unstable" || scenario == L"secondary_unstable";
            fallback.Unreadable = scenario == L"unreadable";
            fallback.ChangeHeader = scenario == L"identity";
            if (scenario == L"secondary") { Put(fallback.Bytes, 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase), uint64_t{0x160000000}); }
            ObservationReadRouting routing;
            routing.Primary = &primary; routing.Fallback = [&]() -> IObservationSource* { return &fallback; };
            routing.AllowFallback = true; routing.TargetId = L"synthetic:target"; routing.AddressSpaceId = L"synthetic:user";
            if (scenario == L"guard") { routing.AfterRead = [](uint64_t, size_t) { return false; }; }
            auto operation = std::make_shared<ObservationReadOperation>(L"slice:" + scenario, routing.TargetId, routing.AddressSpaceId);
            ObservationReadRouter router(routing, operation);
            ExecutableSweep sweep; Check(sweep.Initialize(metadata), "initialize-executable-range-schedule");
            if (scenario == L"continuation") { sweep.NextRange = 1; sweep.RelocationBase = Base; }
            ExecutableSweepReference reference;
            ExecutableSliceTrace trace;
            const auto pages = AdvanceExecutableSweep(original.wstring(), metadata, Base,
                [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes) { return router.ReadExact(address, length, bytes); },
                2, 1, &sweep, 0, &reference, &trace);
            const auto reads = router.Snapshot();
            mappedView.reset(); mappedSection.reset();
            Check(ValidObservationRoutedReadSet(reads), "original-routed-attempts-admitted");
            const auto json = CaptureImageSliceRecipeJson(metadata, Base, reference, trace, reads, pages);
            ImageSliceRecipe parsed;
            Check(!json.empty() && ParseImageSliceRecipe(json, &parsed), "capture-canonical-original-slice");
            if (json.empty()) { continue; }
            if (secondaryPositive)
            {
                Check(trace.SecondaryNeeded && trace.SecondaryOpened && trace.PageCount == 2 &&
                    !trace.SecondaryReads.ParserReads.empty() && pages[0].SecondaryImageView &&
                    pages[0].Ownership == (scenario == L"secondary_modified" ? CodeOwnership::OwnedModified : CodeOwnership::OwnedUnverified),
                    "actual-secondary-inputs-drive-comparison-with-explicit-iat-exclusion");
            }
            const auto calls = fallback.Calls;
            fallback.Bytes.clear(); primary.Bytes.clear();
            Check(DeleteFileW(original.c_str()) != FALSE, "remove-original-before-publication");
            std::unique_ptr<ReferenceArtifact> lease;
            bool created = false;
            Check(PublishReferenceBlob((folder / L"image-references").wstring(), *reference.Artifact, UINT64_MAX, &lease, &created, nullptr),
                "publish-retained-reference-after-source-removal");
            const auto path = folder / L"image-reads" / L"slice.knslice";
            Check(SaveObservationJson(path.wstring(), json, nullptr), "publish-original-slice");
            lease.reset();
            const auto replay = ReplayImageRecipe(path.wstring(), false, nullptr);
            if (replay.Status != L"replayed") { std::wcerr << L"replay " << name << L": " << replay.Status << L"\n"; }
            Check(replay.Status == L"replayed" && replay.CurrentResult == parsed.RecordedResult && !replay.Proof.empty() && fallback.Calls == calls,
                "same-policy-replay-without-target-or-original-reference");
            Check(!SaveObservationJson(path.wstring(), L"{}", nullptr), "existing-slice-never-replaced");
            Check(ReplayImageRecipe(path.wstring(), true, nullptr).Status == L"slice_current_reanalysis_unavailable", "current-policy-mode-not-silently-substituted");
            if (scenario == L"modified")
            {
                auto invalid = parsed;
                invalid.TargetReads.ParserReads.front().ReturnedReceipt = invalid.TargetReads.ParserReads.front().PrimaryReceipt;
                Check(ImageSliceRecipeJson(invalid).empty(), "partial-primary-cannot-replace-selected-fallback");
                invalid = parsed; invalid.TargetReads.Attempts.Reads[1].Request.FallbackFromReceipt = 0;
                Check(ImageSliceRecipeJson(invalid).empty(), "unlinked-fallback-denied");
                invalid = parsed; std::swap(invalid.TargetReads.ParserReads[0], invalid.TargetReads.ParserReads[1]);
                Check(ImageSliceRecipeJson(invalid).empty(), "reordered-parser-attempts-denied");
                invalid = parsed; invalid.TargetReads.Attempts.UnrecordedAttempts = 1;
                Check(ImageSliceRecipeJson(invalid).empty(), "unrecorded-original-attempt-denied");
                auto wrongArchitecture = metadata;
                wrongArchitecture.Machine = IMAGE_FILE_MACHINE_I386;
                Check(CaptureImageSliceRecipeJson(wrongArchitecture, Base, reference, trace, reads, pages).empty(),
                    "unsupported-architecture-does-not-publish-unreplayable-recipe");
                invalid = parsed; invalid.Normalization = L"[]";
                const auto altered = folder / L"image-reads" / L"normalization.knslice";
                Check(SaveObservationJson(altered.wstring(), ImageSliceRecipeJson(invalid), nullptr) &&
                    ReplayImageRecipe(altered.wstring(), false, nullptr).Status == L"normalization_mismatch", "rehash-does-not-authorize-other-normalization");
                invalid = parsed; invalid.RecordedResult = L"[]";
                const auto verdict = folder / L"image-reads" / L"verdict.knslice";
                Check(SaveObservationJson(verdict.wstring(), ImageSliceRecipeJson(invalid), nullptr) &&
                    ReplayImageRecipe(verdict.wstring(), false, nullptr).Status == L"recorded_result_mismatch", "stored-verdict-is-recomputed");
                const auto blob = folder / L"image-references" / (parsed.ReferenceSha256 + L".knblob");
                const auto moved = folder / L"moved.knblob";
                Check(MoveFileExW(blob.c_str(), moved.c_str(), 0) != FALSE &&
                    ReplayImageRecipe(path.wstring(), false, nullptr).Status == L"reference_missing_or_unreadable" &&
                    MoveFileExW(moved.c_str(), blob.c_str(), 0), "missing-reference-is-not-a-match");
            }
            if (scenario == L"secondary_modified")
            {
                auto invalid = parsed;
                invalid.Slice.SecondaryReads = {};
                Check(ImageSliceRecipeJson(invalid).empty(), "secondary-original-inputs-are-required");
                invalid = parsed;
                invalid.Slice.SecondaryReads.Attempts.TargetId = L"reference:another";
                Check(ImageSliceRecipeJson(invalid).empty(), "secondary-inputs-bind-exact-reference");
                invalid = parsed;
                invalid.Slice.SecondaryReads.Attempts.SnapshotTick = invalid.TargetReads.Attempts.SnapshotTick + 1;
                Check(ImageSliceRecipeJson(invalid).empty(), "secondary-observation-cannot-extend-outside-target-transaction");
                invalid = parsed;
                for (auto& receipt : invalid.Slice.SecondaryReads.Attempts.Reads)
                {
                    if (receipt.Request.Address == invalid.Slice.SecondaryViewBase + 0x1000)
                    {
                        receipt.Result.Spans[0].Bytes[0x20] ^= 1;
                        break;
                    }
                }
                const auto altered = folder / L"image-reads" / L"secondary-input.knslice";
                Check(SaveObservationJson(altered.wstring(), ImageSliceRecipeJson(invalid), nullptr) &&
                    ReplayImageRecipe(altered.wstring(), false, nullptr).Status != L"replayed",
                    "rehash-does-not-hide-conflicting-secondary-relocation-input");
            }
            std::cout << "{\"case\":" << mcpjson::WideToUtf8(mcpjson::Quote(scenario)) << ",\"secondary_opened\":" <<
                (trace.SecondaryOpened ? "true" : "false") << ",\"pages\":" << trace.PageCount << ",\"status\":" <<
                mcpjson::WideToUtf8(mcpjson::Quote(replay.Status)) << "}\n";
        }
        SweepTests(root);
    }
    catch (const std::exception&) { Check(false, "slice-fixture-exception"); }
    std::cerr << "Image slice checks=" << Checks << " failed=" << Failures << "\n";
    return Failures ? 1 : 0;
}
