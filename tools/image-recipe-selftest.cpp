#include "../user/ImageVerificationRecipe.h"
#include "../user/ImageProof.h"
#include "../user/ReferenceArtifact.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include "../user/MemoryDumper.h"
#include "../user/McpJson.h"
#include <mindumpdef.h>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool value, const char* name)
    {
        if (value)
        {
            ++Passed;
        }
        else
        {
            ++Failed;
            std::cerr << "[image.recipe] FAIL " << name << "\n";
        }
    }
    void Write(const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!out)
        {
            throw std::runtime_error("fixture write failed");
        }
    }
    void WriteRecipe(const std::filesystem::path& directory, const ImageVerificationRecipe& recipe)
    {
        const auto json = mcpjson::WideToUtf8(ImageRecipeJson(recipe));
        Check(!json.empty(), "mutated control remains a valid envelope");
        Write(directory / L"recipe.knverify", std::vector<uint8_t>(json.begin(), json.end()));
    }

    class Source final : public IObservationSource
    {
    public:
        static constexpr uint64_t Base = 0x180000000ull;
        std::vector<uint8_t> Memory = std::vector<uint8_t>(0x4000, 0);
        bool Unstable = false;
        bool Missing = false;
        bool ChangeHeaderBase = false;
        size_t PageReads = 0;
        size_t HeaderReads = 0;
        Source()
        {
            Caps.SourceId = L"owned-image-recipe-fixture";
            Caps.Consistency = L"synthetic_non_atomic";
            Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4);
        }
        const ObservationSourceCapabilities& Capabilities() const override
        {
            return Caps;
        }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            ObservationReadResult result;
            result.IdentityRevalidated = true;
            ObservationReadSpan span;
            span.Address = request.Address;
            span.RequestedBytes = request.Length;
            span.State = ObservationReadState::NotCaptured;
            if (request.Address >= Base && request.Address - Base < Memory.size() &&
                request.Length <= Memory.size() - (request.Address - Base))
            {
                if (request.Address == Base && ++HeaderReads == 2 && ChangeHeaderBase)
                {
                    const uint64_t changedBase = Base;
                    std::memcpy(Memory.data() + 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase), &changedBase, 8);
                }
                if (request.Address == Base + 0x1000)
                {
                    ++PageReads;
                    if (Unstable && PageReads == 2)
                    {
                        Memory[0x1150] ^= 1;
                    }
                    if (Missing)
                    {
                        span.State = ObservationReadState::Complete;
                        span.RequestedBytes = request.Length / 2;
                        span.Bytes.assign(Memory.begin() + 0x1000, Memory.begin() + 0x1000 + span.RequestedBytes);
                        result.Spans.push_back(span);
                        span.Address += span.RequestedBytes;
                        span.RequestedBytes = request.Length - span.RequestedBytes;
                        span.State = ObservationReadState::NotCaptured;
                        span.Bytes.clear();
                        result.Spans.push_back(span);
                        return result;
                    }
                }
                span.State = ObservationReadState::Complete;
                const auto start = static_cast<size_t>(request.Address - Base);
                span.Bytes.assign(Memory.begin() + start, Memory.begin() + start + request.Length);
            }
            result.Spans.push_back(std::move(span));
            return result;
        }
    private:
        ObservationSourceCapabilities Caps;
    };

    std::vector<uint8_t> Fixture(Source* source)
    {
        std::vector<uint8_t> disk(0x3400, 0);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        std::memcpy(disk.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 2;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.FileHeader.TimeDateStamp = 0x12345678;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.ImageBase = 0x140000000ull;
        nt.OptionalHeader.SizeOfImage = 0x4000;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
        nt.OptionalHeader.SectionAlignment = 0x1000;
        nt.OptionalHeader.FileAlignment = 0x200;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x3000, 12};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {0x1100, 8};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {0x3020, sizeof(IMAGE_DEBUG_DIRECTORY)};
        std::memcpy(disk.data() + 0x80, &nt, sizeof(nt));
        IMAGE_SECTION_HEADER sections[2]{};
        sections[0].VirtualAddress = 0x1000;
        sections[0].Misc.VirtualSize = sections[0].SizeOfRawData = 0x2000;
        sections[0].PointerToRawData = 0x400;
        sections[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        sections[1].VirtualAddress = 0x3000;
        sections[1].Misc.VirtualSize = sections[1].SizeOfRawData = 0x1000;
        sections[1].PointerToRawData = 0x2400;
        sections[1].Characteristics = IMAGE_SCN_MEM_READ;
        std::memcpy(disk.data() + 0x80 + sizeof(nt), sections, sizeof(sections));
        std::fill(disk.begin() + 0x400, disk.begin() + 0x2400, uint8_t{0x90});
        const uint64_t pointer = nt.OptionalHeader.ImageBase + 0x1111;
        std::memcpy(disk.data() + 0x13fc, &pointer, 8);
        const IMAGE_BASE_RELOCATION block{0x1000, 12};
        const uint16_t entry = 0xaffc;
        std::memcpy(disk.data() + 0x2400, &block, sizeof(block));
        std::memcpy(disk.data() + 0x2408, &entry, 2);
        IMAGE_DEBUG_DIRECTORY debug{};
        debug.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        debug.AddressOfRawData = 0x3040;
        debug.PointerToRawData = 0x2440;
        debug.SizeOfData = 40;
        std::memcpy(disk.data() + 0x2420, &debug, sizeof(debug));
        std::memcpy(disk.data() + 0x2440, "RSDS", 4);
        GUID guid{0x01020304, 0x0506, 0x0708, {9, 10, 11, 12, 13, 14, 15, 16}};
        const uint32_t age = 1;
        std::memcpy(disk.data() + 0x2444, &guid, sizeof(guid));
        std::memcpy(disk.data() + 0x2454, &age, 4);
        std::memcpy(disk.data() + 0x2458, "owned.pdb", 10);
        std::copy(disk.begin(), disk.begin() + 0x400, source->Memory.begin());
        for (const auto& section : sections)
        {
            std::memcpy(source->Memory.data() + section.VirtualAddress, disk.data() + section.PointerToRawData, section.SizeOfRawData);
        }
        const uint64_t relocated = Source::Base + 0x1111;
        std::memcpy(source->Memory.data() + 0x1ffc, &relocated, 8);
        return disk;
    }

    void Dump(const std::filesystem::path& path, const Source& source)
    {
        DUMP_HEADER64 header{};
        header.Signature = DUMP_SIGNATURE64;
        header.ValidDump = DUMP_VALID_DUMP64;
        header.MachineImageType = IMAGE_FILE_MACHINE_AMD64;
        header.DumpType = DUMP_TYPE_FULL;
        header.DirectoryTableBase = 0x1000;
        header.KdSecondaryVersion = 2;
        header.PhysicalMemoryBlock.NumberOfRuns = 2;
        header.PhysicalMemoryBlock.NumberOfPages = 8;
        header.PhysicalMemoryBlock.Run[0].BasePage = 1;
        header.PhysicalMemoryBlock.Run[0].PageCount = 4;
        header.PhysicalMemoryBlock.Run[1].BasePage = 16;
        header.PhysicalMemoryBlock.Run[1].PageCount = 4;
        const uint64_t cr4 = 1ull << 5;
        std::memcpy(header.ContextRecord + 0x4d0 + 0x10, &header.DirectoryTableBase, 8);
        std::memcpy(header.ContextRecord + 0x4d0 + 0x18, &cr4, 8);
        std::vector<uint8_t> bytes(0x2000 + 8 * 4096, 0);
        header.RequiredDumpSpace.QuadPart = static_cast<LONGLONG>(bytes.size());
        std::memcpy(bytes.data(), &header, sizeof(header));
        uint64_t table = 0x1000;
        for (unsigned level = 4; level > 1; --level)
        {
            const uint64_t index = (Source::Base >> (12 + (level - 1) * 9)) & 511;
            const uint64_t value = (table + 4096) | 3;
            std::memcpy(bytes.data() + 0x2000 + table - 0x1000 + index * 8, &value, 8);
            table += 4096;
        }
        for (size_t i = 0; i < 4; ++i)
        {
            const uint64_t value = (0x10000 + i * 4096) | 3;
            const uint64_t index = ((Source::Base >> 12) + i) & 511;
            std::memcpy(bytes.data() + 0x2000 + table - 0x1000 + index * 8, &value, 8);
        }
        std::memcpy(bytes.data() + 0x6000, source.Memory.data(), source.Memory.size());
        Write(path, bytes);
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring(argv[1]) == L"--replay")
    {
        std::wstring error;
        return ReplayImageRecipe(argv[2], false, &error).Status == L"replayed" ? 0 : 1;
    }
    if (argc == 3 && std::wstring(argv[1]) == L"--publish")
    {
        const std::filesystem::path root(argv[2]);
        Source source;
        auto bytes = Fixture(&source);
        bytes.resize(8 * 1024 * 1024, 0);
        const auto image = root / L"input.exe";
        Write(image, bytes);
        ImageVerificationRecipe recipe;
        std::wstring error;
        return CaptureImageRecipe(image.wstring(), source, Source::Base, 0x1000, 4096,
            (root / L"case").wstring(), &recipe, &error) ? 0 : 1;
    }
    if (argc != 2)
    {
        return 2;
    }
    const std::filesystem::path root(argv[1]);
    Source clean;
    const auto disk = Fixture(&clean);
    const auto image = root / L"owned-image.exe";
    Write(image, disk);
    Dump(root / L"owned.dmp", clean);
    std::wstring error;
    const auto capture = [&](const wchar_t* name, Source& source, uint32_t rva, ImageVerificationRecipe* p)
    {
        const auto directory = root / name;
        const bool captured = CaptureImageRecipe(image.wstring(), source, Source::Base, rva, 4096, directory.wstring(), p, &error);
        Check(captured, "capture publishes the exact reference and recipe");
        if (!captured)
        {
            std::wcerr << error << L"\n";
            return false;
        }
        const auto replay = ReplayImageRecipe(directory.wstring(), false, &error);
        Check(replay.Status == L"replayed" && replay.CurrentResult == p->RecordedResult, "ordered original-policy replay matches capture");
        return true;
    };
    ImageVerificationRecipe original;
    if (!capture(L"clean", clean, 0x2000, &original))
    {
        return 1;
    }
    Check(original.RecordedResult.find(L"owned_verified") != std::wstring::npos,
        "cross-page relocation is normalized using the retained raw image");
    Source changed = clean;
    changed.Memory[0x1150] ^= 1;
    ImageVerificationRecipe modified;
    if (!capture(L"modified", changed, 0x1000, &modified))
    {
        return 1;
    }
    Check(modified.RecordedResult.find(L"owned_modified") != std::wstring::npos &&
        modified.RecordedResult.find(L"\"skipped_bytes\":\"8\"") != std::wstring::npos && changed.PageReads == 2,
        "confirmed changed bytes and loader exclusions survive replay");
    executable_image::DiskPeMetadata metadata;
    Check(executable_image::ReadDiskPeMetadata(image.wstring(), &metadata, &error), "proof control reference parses");
    const auto compare = [&](Source& source, uint32_t rva)
    {
        const ObservationReader reader = [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes)
        {
            return ReadObservationExact(source, address, length, bytes);
        };
        return CompareExecutableRange(image.wstring(), metadata, Source::Base, rva, 4096, reader);
    };
    const auto cleanComparison = compare(clean, 0x2000);
    const auto changedComparison = compare(changed, 0x1000);
    const auto cleanProof = AssessImageProof(original, cleanComparison, true, false);
    Check(cleanProof.InputConsistent && cleanProof.Matches.Status == L"supported" &&
        cleanProof.Differs.Status == L"contradicted" && cleanProof.ComparedBytes == 4096 &&
        cleanProof.UniqueTargetBytesRetained == 4096, "complete normalized bytes support only the scoped match claim");
    const auto changedProof = AssessImageProof(modified, changedComparison, true, false);
    Check(changedProof.Differs.Status == L"supported" && changedProof.Matches.Status == L"contradicted" &&
        changedProof.SkippedBytes == 8 && changedProof.ChangedRanges.size() == 1 &&
        changedProof.ChangedRanges.front().Address == Source::Base + 0x1150 &&
        changedProof.SupportingReadIndices.size() == 2,
        "confirmed difference claims contain absolute changed ranges while preserving exclusions");
    Check(mcpjson::ValidateDocument(ImageProofJson(modified, changedProof)), "proof ledger emits valid JSON");
    auto invalidComparison = cleanComparison;
    invalidComparison.Coverage.Compared.push_back(invalidComparison.Coverage.Compared.front());
    invalidComparison.Coverage.ComparedBytes *= 2;
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "duplicate compared visits cannot inflate unique proof coverage");
    invalidComparison = cleanComparison;
    invalidComparison.Coverage.Compared.front().Address += 4096;
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "equal byte counts at different addresses do not prove this range");
    invalidComparison = cleanComparison;
    invalidComparison.Coverage.Failed.push_back({Source::Base + 0x2000, 1});
    invalidComparison.Coverage.FailedBytes = 1;
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "one byte cannot be both compared and failed in a proof ledger");
    invalidComparison = changedComparison;
    invalidComparison.Changes.front().Address += Source::Base;
    Check(!AssessImageProof(modified, invalidComparison, true, false).InputConsistent,
        "verifier RVA changes cannot be silently treated as absolute input ranges");
    invalidComparison = changedComparison;
    invalidComparison.Changes.push_back({0x1100, 1});
    Check(!AssessImageProof(modified, invalidComparison, true, false).InputConsistent,
        "excluded bytes cannot support a modified claim");
    invalidComparison = cleanComparison;
    invalidComparison.Observed.clear();
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "ownership labels without actual compared bytes do not support a claim");
    invalidComparison = cleanComparison;
    invalidComparison.Coverage.LostEvents = 1;
    Check(AssessImageProof(original, invalidComparison, true, false).Matches.Status == L"not_established",
        "lost evidence prevents a complete match claim");
    Check(AssessImageProof(original, cleanComparison, false, false).Matches.Status == L"not_established",
        "matching bytes without mapped identity qualification remain inconclusive");
    invalidComparison = cleanComparison;
    invalidComparison.RelocationBase += 0x10000;
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "a changed normalization base cannot satisfy the direct recipe proof");
    invalidComparison = cleanComparison;
    invalidComparison.SecondaryImageView = true;
    Check(!AssessImageProof(original, invalidComparison, true, false).InputConsistent,
        "a secondary view needs its own supported proof policy");
    auto unknownPolicy = original;
    unknownPolicy.Policy = L"unknown-original-policy";
    Check(AssessImageProof(unknownPolicy, cleanComparison, true, false).Matches.Status == L"not_established" &&
        AssessImageProof(unknownPolicy, cleanComparison, true, true).Matches.Status == L"supported",
        "unknown original policy requires explicit current reanalysis before proving a claim");
    auto missingConfirmation = modified;
    const auto confirmation = std::find_if(missingConfirmation.Reads.begin(), missingConfirmation.Reads.end(), [](const auto& read)
    {
        return read.Address == Source::Base + 0x1000 && read.Length == 4096;
    });
    Check(confirmation != missingConfirmation.Reads.end(), "confirmation control has an original range read");
    if (confirmation != missingConfirmation.Reads.end())
    {
        missingConfirmation.Reads.erase(confirmation);
    }
    Check(AssessImageProof(missingConfirmation, changedComparison, true, true).Differs.Status == L"not_established",
        "current reanalysis cannot invent a missing original confirmation read");
    auto wrongBytes = original;
    for (auto& read : wrongBytes.Reads)
    {
        if (read.Address == Source::Base + 0x2000)
        {
            read.Result.Spans.front().Bytes.front() ^= 1;
        }
    }
    Check(AssessImageProof(wrongBytes, cleanComparison, true, false).Matches.Status == L"not_established",
        "comparison bytes must be backed by a matching retained read");
    auto cancelledBytes = original;
    for (auto& read : cancelledBytes.Reads)
    {
        read.Result.CancellationObserved = true;
    }
    Check(AssessImageProof(cancelledBytes, cleanComparison, true, false).Matches.Status == L"not_established",
        "cancelled retained reads do not satisfy claim requirements");
    ImageVerificationRecipe loaded;
    const auto encoded = ImageRecipeJson(modified);
    Check(ParseImageRecipe(encoded, &loaded, &error) && ImageRecipeJson(loaded) == encoded, "canonical recipe round trip");
    Check(!ParseImageRecipe(encoded + L" ", &loaded, &error) && !ParseImageRecipe(encoded.substr(0, encoded.size() - 1), &loaded, &error),
        "noncanonical or truncated recipe rejected");
    Source unstable = clean;
    unstable.Memory[0x1150] ^= 1;
    unstable.Unstable = true;
    ImageVerificationRecipe unstableRecipe;
    Check(capture(L"unstable", unstable, 0x1000, &unstableRecipe) &&
        unstableRecipe.RecordedResult.find(L"live_bytes_unstable_or_unreadable") != std::wstring::npos,
        "different repeated reads remain distinct rather than collapsing to one snapshot");
    Source sparse = clean;
    sparse.Missing = true;
    ImageVerificationRecipe sparseRecipe;
    Check(capture(L"sparse", sparse, 0x1000, &sparseRecipe) &&
        std::any_of(sparseRecipe.Reads.begin(), sparseRecipe.Reads.end(), [](const auto& r)
        {
            return r.Result.State == ObservationReadState::Partial && r.Result.Spans.size() == 2 && !r.Result.Spans.front().Bytes.empty();
        }), "partial spans retain bytes and unavailable-state evidence");
    Source wrongPdb = clean;
    wrongPdb.Memory[0x3044] ^= 1;
    ImageVerificationRecipe wrongRecipe;
    Check(capture(L"wrong-pdb", wrongPdb, 0x1000, &wrongRecipe) &&
        wrongRecipe.RecordedResult.find(L"live_image_identity_mismatch") != std::wstring::npos,
        "wrong mapped PDB identity never becomes a qualified code comparison");
    Source alias = clean;
    const uint64_t ambiguous = 0x190000000ull;
    std::memcpy(alias.Memory.data() + 0x80 + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase), &ambiguous, 8);
    ImageVerificationRecipe aliasRecipe;
    Check(capture(L"alias", alias, 0x1000, &aliasRecipe) &&
        aliasRecipe.RecordedResult.find(L"live_image_relocation_base_ambiguous") != std::wstring::npos,
        "unproved secondary relocation basis remains unsupported");
    Source changedHeader;
    Fixture(&changedHeader);
    changedHeader.Memory[0x1150] ^= 1;
    changedHeader.ChangeHeaderBase = true;
    ImageVerificationRecipe changedHeaderRecipe;
    Check(capture(L"header-changed", changedHeader, 0x1000, &changedHeaderRecipe) &&
        changedHeaderRecipe.RecordedResult.find(L"image_identity_changed_during_compare") != std::wstring::npos &&
        changedHeaderRecipe.RecordedResult.find(L"owned_unverified") != std::wstring::npos,
        "individually allowed but changed header bases invalidate the comparison");
    const auto unstableAnalysis = ReplayImageRecipe((root / L"unstable").wstring(), true, &error);
    Check(unstableAnalysis.Status == L"reanalyzed" &&
        unstableAnalysis.CurrentResult.find(L"owned_unverified") != std::wstring::npos,
        "current reanalysis cannot merge conflicting repeated byte observations into a clean result");
    auto invalid = modified;
    invalid.Reads.front().Result.SourceId = L"different-source";
    Check(ImageRecipeJson(invalid).empty(), "complete reads cannot cross source identities");
    invalid = sparseRecipe;
    for (auto& read : invalid.Reads)
    {
        if (read.Result.State == ObservationReadState::Partial)
        {
            read.Result.SourceId = L"different-source";
        }
    }
    Check(ImageRecipeJson(invalid).empty(), "partial reads with retained bytes cannot cross source identities");
    invalid = sparseRecipe;
    for (auto& read : invalid.Reads)
    {
        if (read.Result.State == ObservationReadState::Partial)
        {
            read.Result.Consistency = L"different-consistency";
        }
    }
    Check(ImageRecipeJson(invalid).empty(), "partial reads with retained bytes cannot cross consistency models");
    invalid = modified;
    invalid.Reads.back().Result.StartedTick = 0;
    Check(ImageRecipeJson(invalid).empty(), "backward acquisition intervals are rejected");
    invalid = modified;
    invalid.Reads.front().Result.Spans.front().Bytes.clear();
    Check(ImageRecipeJson(invalid).empty(), "complete reads require their exact original bytes");
    invalid = modified;
    invalid.ImageBase = 0x0000800000000000ull;
    Check(ImageRecipeJson(invalid).empty(), "noncanonical image base cannot become a replayable typed claim");
    invalid = modified;
    invalid.Reads.front().Address = 0x0000800000000000ull;
    invalid.Reads.front().Result.Spans.front().Address = invalid.Reads.front().Address;
    Check(ImageRecipeJson(invalid).empty(), "complete raw spans must belong to the declared address width");
    const auto directory = root / L"modified";
    Check(!CaptureImageRecipe(image.wstring(), clean, Source::Base, 0x1000, 4096, directory.wstring(), &loaded, &error),
        "capture refuses an existing directory");
    auto rewritten = modified;
    rewritten.Policy = L"kn.executable_page.direct.unknown";
    WriteRecipe(directory, rewritten);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"original_policy_unavailable",
        "missing old policy does not silently select the current policy");
    auto reanalysis = ReplayImageRecipe(directory.wstring(), true, &error);
    Check(reanalysis.Status == L"reanalyzed" && reanalysis.CurrentResult == modified.RecordedResult,
        "explicit current reanalysis preserves the original result separately");
    rewritten = modified;
    rewritten.Reads.erase(rewritten.Reads.begin());
    WriteRecipe(directory, rewritten);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"recorded_read_set_mismatch",
        "missing ordered reads prevent an original-policy success");
    rewritten = modified;
    rewritten.Normalization = L"{}";
    WriteRecipe(directory, rewritten);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"normalization_mismatch",
        "altered normalization inputs are not trusted despite a recomputed envelope hash");
    rewritten = modified;
    rewritten.RecordedResult = L"{}";
    WriteRecipe(directory, rewritten);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"recorded_result_mismatch",
        "stored verdict is independently recomputed rather than echoed");
    WriteRecipe(directory, modified);
    Write(image, std::vector<uint8_t>{0, 1, 2});
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"replayed",
        "changing the original image path cannot change retained reference replay");
    Write(image, disk);
    const auto blob = directory / (modified.ReferenceSha256 + L".knblob");
    auto corrupt = disk;
    corrupt[0x500] ^= 1;
    Write(blob, corrupt);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"reference_corrupt",
        "corrupt reference bytes cannot reuse the recorded verdict");
    Write(blob, disk);
    const auto moved = directory / L"moved.knblob";
    std::filesystem::rename(blob, moved);
    Check(ReplayImageRecipe(directory.wstring(), false, &error).Status == L"reference_missing_or_unreadable",
        "missing exact reference is unavailable, not matching");
    std::filesystem::rename(moved, blob);
    ReferenceArtifact lease;
    Check(lease.Open(image.wstring(), &error) && lease.Bytes() == disk && lease.Unchanged(), "reference lease binds exact stable bytes");
    HANDLE writer = CreateFileW(image.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    Check(writer == INVALID_HANDLE_VALUE, "active reference lease denies replacement writes");
    if (writer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(writer);
    }
    Check(!PublishReferenceArtifact(blob.wstring(), disk, &error), "blob publication preserves an existing content path");
    Check(ReplayImageRecipe((root / L"absent").wstring(), false, &error).Status == L"recipe_unavailable_or_corrupt",
        "incomplete publication has no committed recipe");
    std::cout << "[image.recipe] passed=" << Passed << " failed=" << Failed << " corpus=synthetic\n";
    return Failed == 0 ? 0 : 1;
}
