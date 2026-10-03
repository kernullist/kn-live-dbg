#include "ExecutableImageVerifier.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>

using namespace executable_image;

namespace
{
    bool ReadExact(const ObservationReader& read, uint64_t base, uint64_t offset,
        size_t size, std::vector<uint8_t>* bytes)
    {
        return read && base <= UINT64_MAX - offset && base + offset <= UINT64_MAX - size &&
            read(base + offset, size, bytes) && bytes->size() == size;
    }

    bool NormalizeRange(const std::wstring& path, const DiskPeMetadata& metadata,
        uint64_t imageBase, uint32_t rva, uint32_t size, std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        do
        {
            if (bytes == nullptr || size == 0 || size > 4096 || rva >= metadata.SizeOfImage ||
                size > metadata.SizeOfImage - rva || !metadata.BaseRelocationTableComplete)
            {
                break;
            }
            std::map<uint32_t, std::vector<uint8_t>> pages;
            const auto get = [&](uint32_t address, uint32_t length, uint8_t* out)
            {
                for (uint32_t n = 0; n < length; ++n)
                {
                    const uint32_t pageRva = (address + n) & ~0xFFFu;
                    auto it = pages.find(pageRva);
                    if (it == pages.end())
                    {
                        std::vector<uint8_t> page;
                        if (!ReadDiskPageForRva(path, metadata, pageRva, &page, nullptr) || page.size() != 4096)
                        {
                            return false;
                        }
                        it = pages.emplace(pageRva, std::move(page)).first;
                    }
                    out[n] = it->second[(address + n) & 0xFFF];
                }
                return true;
            };
            bytes->resize(size);
            if (!get(rva, size, bytes->data()))
            {
                break;
            }
            const uint64_t delta = imageBase - metadata.ImageBase;
            bool valid = true;
            if (delta != 0)
            {
                if (!metadata.BaseRelocationTablePresent)
                {
                    break;
                }
                auto it = std::lower_bound(metadata.BaseRelocations.begin(), metadata.BaseRelocations.end(), rva,
                    [](const DiskPeBaseRelocation& relocation, uint32_t address)
                    {
                        return static_cast<uint64_t>(relocation.Rva) + relocation.Width <= address;
                    });
                for (; it != metadata.BaseRelocations.end() && it->Rva < static_cast<uint64_t>(rva) + size; ++it)
                {
                    if ((it->Width != 4 && it->Width != 8) || it->Width > metadata.SizeOfImage ||
                        it->Rva > metadata.SizeOfImage - it->Width)
                    {
                        valid = false;
                        break;
                    }
                    uint64_t value = 0;
                    if (!get(it->Rva, it->Width, reinterpret_cast<uint8_t*>(&value)))
                    {
                        valid = false;
                        break;
                    }
                    value += delta;
                    const uint32_t start = (std::max)(rva, it->Rva);
                    const uint32_t end = static_cast<uint32_t>((std::min)(
                        static_cast<uint64_t>(rva) + size, static_cast<uint64_t>(it->Rva) + it->Width));
                    std::memcpy(bytes->data() + start - rva,
                        reinterpret_cast<const uint8_t*>(&value) + start - it->Rva, end - start);
                }
            }
            ok = valid;
        } while (false);
        return ok;
    }
}

bool ExecutableSweep::Initialize(const DiskPeMetadata& metadata)
{
    *this = {};
    std::set<uint64_t> starts;
    for (const auto& section : metadata.Sections)
    {
        if (!section.Executable)
        {
            continue;
        }
        const uint64_t size = (std::max)(section.VirtualSize, section.SizeOfRawData);
        if (size == 0 || section.VirtualAddress >= metadata.SizeOfImage || size > metadata.SizeOfImage - section.VirtualAddress)
        {
            Ranges.clear();
            return false;
        }
        for (uint64_t offset = 0; offset < size;)
        {
            const uint64_t address = section.VirtualAddress + offset;
            const uint64_t count = (std::min)(size - offset, 4096 - (address & 4095));
            if (!starts.insert(address).second || Ranges.size() >= 262144)
            {
                Ranges.clear();
                return false;
            }
            Ranges.push_back({address, count});
            Coverage.RequestedBytes += count;
            offset += count;
        }
    }
    std::sort(Ranges.begin(), Ranges.end(), [](const ObservationRange& a, const ObservationRange& b)
    {
        return a.Address < b.Address;
    });
    for (size_t i = 1; i < Ranges.size(); ++i)
    {
        if (Ranges[i - 1].Address + Ranges[i - 1].Size > Ranges[i].Address)
        {
            Ranges.clear();
            return false;
        }
    }
    Coverage.InventoryAvailable = !Ranges.empty();
    Coverage.Reason = L"scheduled";
    return !Ranges.empty();
}

bool ReadNormalizedImageRange(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, uint32_t rva, uint32_t size, std::vector<uint8_t>* bytes)
{
    return NormalizeRange(path, metadata, imageBase, rva, size, bytes);
}

bool QualifyExecutableReference(const DiskPeMetadata& metadata, uint64_t imageBase,
    const ObservationReader& reader, std::wstring* reason)
{
    bool ok = false;
    bool mismatch = false;
    do
    {
        std::vector<uint8_t> bytes;
        if (!ReadExact(reader, imageBase, 0, sizeof(IMAGE_DOS_HEADER), &bytes))
        {
            break;
        }
        IMAGE_DOS_HEADER dos = {};
        std::memcpy(&dos, bytes.data(), sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 16 * 1024 * 1024)
        {
            mismatch = true;
            break;
        }
        if (!ReadExact(reader, imageBase, dos.e_lfanew, sizeof(IMAGE_NT_HEADERS64), &bytes))
        {
            break;
        }
        IMAGE_NT_HEADERS64 nt = {};
        std::memcpy(&nt, bytes.data(), sizeof(nt));
        if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != metadata.Machine ||
            nt.FileHeader.TimeDateStamp != metadata.TimeDateStamp || nt.OptionalHeader.Magic != metadata.OptionalMagic ||
            nt.FileHeader.NumberOfSections != metadata.Sections.size())
        {
            mismatch = true;
            break;
        }
        // SizeOfImage, CheckSum and AddressOfEntryPoint have the same PE32 offsets.
        if (nt.OptionalHeader.SizeOfImage != metadata.SizeOfImage ||
            nt.OptionalHeader.CheckSum != metadata.CheckSum || nt.OptionalHeader.AddressOfEntryPoint != metadata.EntryPointRva)
        {
            mismatch = true;
            break;
        }
        if (metadata.HasPdbIdentity)
        {
            if (!ReadExact(reader, imageBase, metadata.PdbRva, 24, &bytes))
            {
                break;
            }
            if (std::memcmp(bytes.data(), "RSDS", 4) != 0 ||
                std::memcmp(bytes.data() + 4, &metadata.PdbGuid, sizeof(GUID)) != 0 ||
                std::memcmp(bytes.data() + 20, &metadata.PdbAge, 4) != 0)
            {
                mismatch = true;
                break;
            }
        }
        ok = true;
    } while (false);
    if (reason != nullptr)
    {
        *reason = ok ? (metadata.HasPdbIdentity ? L"pe_and_pdb_identity_match" : L"pe_identity_match_no_pdb") :
            (mismatch ? L"live_image_identity_mismatch" : L"live_image_identity_unreadable");
    }
    return ok;
}

ExecutablePageResult CompareExecutableRange(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, uint32_t rva, uint32_t size, const ObservationReader& reader)
{
    ExecutablePageResult result;
    result.Rva = rva;
    result.Coverage.Attempted = true;
    result.Coverage.RequestedBytes = size;
    result.Coverage.Reason = L"reference_or_live_read_failed";
    const bool addressValid = imageBase <= UINT64_MAX - rva && imageBase + rva <= UINT64_MAX - size;
    do
    {
        if (!addressValid)
        {
            result.Coverage.Reason = L"invalid_address_range";
            break;
        }
        const auto section = FindDiskSectionForRva(metadata, rva);
        if (section == nullptr || !section->Executable || size == 0 || size > 4096 ||
            rva >= metadata.SizeOfImage || size > metadata.SizeOfImage - rva ||
            static_cast<uint64_t>(rva) + size > static_cast<uint64_t>(section->VirtualAddress) +
                (std::max)(section->VirtualSize, section->SizeOfRawData) ||
            !metadata.DynamicRelocationTableComplete)
        {
            break;
        }
        result.Coverage.InventoryAvailable = true;
        // INIT and other discardable sections have no persistent byte contract.
        if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
        {
            result.Coverage.SkippedBytes = size;
            result.Coverage.Skipped.push_back({imageBase + rva, size});
            result.Coverage.TraversalComplete = true;
            result.Coverage.Reason = L"discardable_section";
            break;
        }
        if (!NormalizeRange(path, metadata, imageBase, rva, size, &result.Expected) ||
            !ReadExact(reader, imageBase, rva, size, &result.Observed))
        {
            break;
        }
        std::vector<bool> mutableBytes(size, false);
        const auto mask = [&](const std::vector<DiskPeMutableRange>& ranges)
        {
            for (const auto& range : ranges)
            {
                const uint64_t start = (std::max<uint64_t>)(range.Rva, rva);
                const uint64_t end = (std::min<uint64_t>)(static_cast<uint64_t>(range.Rva) + range.Size,
                    static_cast<uint64_t>(rva) + size);
                for (uint64_t address = start; address < end; ++address)
                {
                    mutableBytes[static_cast<size_t>(address - rva)] = true;
                }
            }
        };
        mask(metadata.LoaderMutableRanges);
        mask(metadata.DynamicRelocationRanges);
        bool differs = false;
        for (uint32_t i = 0; i < size; ++i)
        {
            differs = differs || (!mutableBytes[i] && result.Expected[i] != result.Observed[i]);
        }
        if (differs)
        {
            std::vector<uint8_t> confirmed;
            bool stable = ReadExact(reader, imageBase, rva, size, &confirmed);
            for (uint32_t i = 0; stable && i < size; ++i)
            {
                stable = mutableBytes[i] || confirmed[i] == result.Observed[i];
            }
            if (!stable)
            {
                result.Coverage.Reason = L"live_bytes_unstable_or_unreadable";
                break;
            }
        }
        if (!DiskReferenceIdentityMatches(path, metadata))
        {
            result.Coverage.Reason = L"reference_changed_during_compare";
            break;
        }
        for (uint32_t i = 0; i < size; ++i)
        {
            if (mutableBytes[i])
            {
                ++result.Coverage.SkippedBytes;
                AddObservationRange(&result.Coverage.Skipped, {imageBase + rva + i, 1}, &result.Coverage.RangesTruncated);
                continue;
            }
            ++result.Coverage.ComparedBytes;
            AddObservationRange(&result.Coverage.Compared, {imageBase + rva + i, 1}, &result.Coverage.RangesTruncated);
            if (result.Expected[i] != result.Observed[i])
            {
                if (!result.Changes.empty() && result.Changes.back().Address + result.Changes.back().Size == rva + i)
                {
                    ++result.Changes.back().Size;
                }
                else
                {
                    result.Changes.push_back({static_cast<uint64_t>(rva) + i, 1});
                }
            }
        }
        result.Coverage.TraversalComplete = true;
        result.Coverage.Reason = result.Coverage.SkippedBytes != 0 ? L"loader_mutable_ranges_excluded" : L"compared";
        result.Ownership = !result.Changes.empty() ? CodeOwnership::OwnedModified :
            (result.Coverage.Complete() ? CodeOwnership::OwnedVerified : CodeOwnership::OwnedUnverified);
    } while (false);
    if (!result.Coverage.TraversalComplete)
    {
        result.Coverage.FailedBytes = size;
        if (addressValid)
        {
            result.Coverage.Failed.push_back({imageBase + rva, size});
        }
    }
    return result;
}

std::vector<ExecutablePageResult> AdvanceExecutableSweep(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, const ObservationReader& reader, size_t pageBudget, uint64_t nowMs, ExecutableSweep* sweep)
{
    std::vector<ExecutablePageResult> results;
    if (sweep == nullptr || sweep->Ranges.empty() || pageBudget == 0)
    {
        return results;
    }
    if (sweep->NextRange == sweep->Ranges.size())
    {
        const uint64_t requested = sweep->Coverage.RequestedBytes;
        sweep->Coverage = {};
        sweep->Coverage.RequestedBytes = requested;
        sweep->NextRange = 0;
        ++sweep->Cycle;
    }
    std::wstring reason;
    if (!QualifyExecutableReference(metadata, imageBase, reader, &reason))
    {
        const uint64_t requested = sweep->Coverage.RequestedBytes;
        sweep->Coverage = {};
        sweep->Coverage.RequestedBytes = requested;
        sweep->NextRange = 0;
        sweep->Pages.clear();
        ++sweep->Cycle;
        sweep->Coverage.Attempted = true;
        sweep->Coverage.InventoryAvailable = false;
        sweep->Coverage.Reason = reason;
        return results;
    }
    sweep->Coverage.Attempted = true;
    sweep->Coverage.InventoryAvailable = true;
    const size_t end = sweep->NextRange + (std::min)(pageBudget, sweep->Ranges.size() - sweep->NextRange);
    for (; sweep->NextRange < end; ++sweep->NextRange)
    {
        const auto& range = sweep->Ranges[sweep->NextRange];
        auto page = CompareExecutableRange(path, metadata, imageBase,
            static_cast<uint32_t>(range.Address), static_cast<uint32_t>(range.Size), reader);
        sweep->Pages[page.Rva] = page.Ownership;
        sweep->Coverage.ComparedBytes += page.Coverage.ComparedBytes;
        sweep->Coverage.FailedBytes += page.Coverage.FailedBytes;
        sweep->Coverage.SkippedBytes += page.Coverage.SkippedBytes;
        for (const auto& compared : page.Coverage.Compared)
        {
            AddObservationRange(&sweep->Coverage.Compared, compared, &sweep->Coverage.RangesTruncated);
        }
        for (const auto& failed : page.Coverage.Failed)
        {
            AddObservationRange(&sweep->Coverage.Failed, failed, &sweep->Coverage.RangesTruncated);
        }
        for (const auto& skipped : page.Coverage.Skipped)
        {
            AddObservationRange(&sweep->Coverage.Skipped, skipped, &sweep->Coverage.RangesTruncated);
        }
        sweep->Coverage.RangesTruncated = sweep->Coverage.RangesTruncated || page.Coverage.RangesTruncated;
        results.push_back(std::move(page));
    }
    const bool hasComparedBytes = std::any_of(results.begin(), results.end(), [](const ExecutablePageResult& page)
    {
        return page.Coverage.ComparedBytes != 0;
    });
    if (hasComparedBytes && !QualifyExecutableReference(metadata, imageBase, reader, &reason))
    {
        // The mapping may have changed after the initial identity read.
        for (auto& page : results)
        {
            const uint64_t requested = page.Coverage.RequestedBytes;
            page.Ownership = CodeOwnership::OwnedUnverified;
            page.Changes.clear();
            page.Coverage = {};
            page.Coverage.Attempted = true;
            page.Coverage.RequestedBytes = requested;
            page.Coverage.FailedBytes = requested;
            page.Coverage.Failed.push_back({imageBase + page.Rva, requested});
            page.Coverage.Reason = L"image_identity_changed_during_compare";
        }
        const uint64_t requested = sweep->Coverage.RequestedBytes;
        sweep->Coverage = {};
        sweep->Coverage.Attempted = true;
        sweep->Coverage.RequestedBytes = requested;
        sweep->Coverage.FailedBytes = requested;
        sweep->Coverage.Reason = L"image_identity_changed_during_compare";
        sweep->Pages.clear();
        sweep->NextRange = 0;
        ++sweep->Cycle;
        return results;
    }
    sweep->Coverage.TraversalComplete = sweep->NextRange == sweep->Ranges.size();
    sweep->Coverage.ResumeAddress = sweep->Coverage.TraversalComplete ? 0 : imageBase + sweep->Ranges[sweep->NextRange].Address;
    sweep->Coverage.Reason = sweep->Coverage.Complete() ? L"cycle_complete" :
        (sweep->Coverage.TraversalComplete ? L"cycle_complete_with_gaps" : L"page_budget");
    if (sweep->Coverage.TraversalComplete)
    {
        sweep->LastCompleteMs = nowMs;
    }
    return results;
}

bool ExecutableImageVerifierSelfTest()
{
    bool ok = false;
    wchar_t directory[MAX_PATH] = {};
    wchar_t path[MAX_PATH] = {};
    HANDLE file = INVALID_HANDLE_VALUE;
    do
    {
        if (GetTempPathW(MAX_PATH, directory) == 0 || GetTempFileNameW(directory, L"kmi", 0, path) == 0)
        {
            break;
        }
        std::vector<uint8_t> disk(0x4800, 0);
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        std::memcpy(disk.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt = {};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 3;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.FileHeader.TimeDateStamp = 0x12345678;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.ImageBase = 0x140000000ull;
        nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
        nt.OptionalHeader.SizeOfImage = 0x7000;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.SectionAlignment = 0x1000;
        nt.OptionalHeader.FileAlignment = 0x200;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x6000, 12};
        std::memcpy(disk.data() + 0x80, &nt, sizeof(nt));
        IMAGE_SECTION_HEADER sections[3] = {};
        sections[0].VirtualAddress = 0x1000;
        sections[0].Misc.VirtualSize = 0x3000;
        sections[0].SizeOfRawData = 0x3000;
        sections[0].PointerToRawData = 0x400;
        sections[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        sections[1].VirtualAddress = 0x5000;
        sections[1].Misc.VirtualSize = 0x1000;
        sections[1].SizeOfRawData = 0x1000;
        sections[1].PointerToRawData = 0x3400;
        sections[1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        sections[2].VirtualAddress = 0x6000;
        sections[2].Misc.VirtualSize = 0x1000;
        sections[2].SizeOfRawData = 0x400;
        sections[2].PointerToRawData = 0x4400;
        sections[2].Characteristics = IMAGE_SCN_MEM_READ;
        std::memcpy(disk.data() + 0x80 + sizeof(nt), sections, sizeof(sections));
        std::fill(disk.begin() + 0x400, disk.begin() + 0x4400, static_cast<uint8_t>(0x90));
        const uint64_t preferredPointer = nt.OptionalHeader.ImageBase + 0x1111;
        std::memcpy(disk.data() + 0x400 + 0xFFC, &preferredPointer, sizeof(preferredPointer));
        const IMAGE_BASE_RELOCATION reloc = {0x1000, 12};
        const uint16_t fixup = 0xAFFC;
        std::memcpy(disk.data() + 0x4400, &reloc, sizeof(reloc));
        std::memcpy(disk.data() + 0x4408, &fixup, sizeof(fixup));
        file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        if (file == INVALID_HANDLE_VALUE || !WriteFile(file, disk.data(), static_cast<DWORD>(disk.size()), &written, nullptr) ||
            written != disk.size())
        {
            break;
        }
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        DiskPeMetadata metadata;
        if (!ReadDiskPeMetadata(path, &metadata, nullptr) || !metadata.BaseRelocationTableComplete)
        {
            break;
        }
        constexpr uint64_t loadedBase = 0x180000000ull;
        std::vector<uint8_t> live(0x7000, 0);
        std::copy(disk.begin(), disk.begin() + 0x400, live.begin());
        for (const auto& section : sections)
        {
            std::memcpy(live.data() + section.VirtualAddress,
                disk.data() + section.PointerToRawData, section.SizeOfRawData);
        }
        const uint64_t relocated = loadedBase + 0x1111;
        std::memcpy(live.data() + 0x1FFC, &relocated, sizeof(relocated));
        uint64_t unreadable = 0;
        const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (address < loadedBase || address - loadedBase >= live.size() ||
                size > live.size() - (address - loadedBase) || address == unreadable)
            {
                return false;
            }
            bytes->assign(live.begin() + static_cast<size_t>(address - loadedBase),
                live.begin() + static_cast<size_t>(address - loadedBase) + size);
            return true;
        };
        ExecutableSweep sweep;
        if (!sweep.Initialize(metadata) || sweep.Ranges.size() != 4)
        {
            break;
        }
        bool clean = true;
        for (size_t pass = 0; pass < 4; ++pass)
        {
            const auto pages = AdvanceExecutableSweep(path, metadata, loadedBase, reader, 1, pass + 1, &sweep);
            clean = clean && pages.size() == 1 && pages[0].Ownership == CodeOwnership::OwnedVerified;
            if (pass != 3 && sweep.Coverage.Complete())
            {
                clean = false;
            }
        }
        if (!clean || !sweep.Coverage.Complete() || sweep.Coverage.ComparedBytes != 0x4000)
        {
            break;
        }
        live[0x3500] ^= 1;
        live[0x5FF0] ^= 1;
        const auto changed = AdvanceExecutableSweep(path, metadata, loadedBase, reader, 8, 5, &sweep);
        size_t changedPages = 0;
        for (const auto& page : changed)
        {
            if (page.Ownership == CodeOwnership::OwnedModified && !page.Changes.empty())
            {
                ++changedPages;
            }
        }
        if (changedPages != 2)
        {
            break;
        }
        bool reviewControls = true;
        const auto reviewCheck = [&](bool condition, const char* name)
        {
            if (!condition)
            {
                std::fprintf(stderr, "[kmon.review] FAIL %s\n", name);
                reviewControls = false;
            }
        };
        for (bool dynamic : {false, true})
        {
            auto mutableMetadata = metadata;
            auto& ranges = dynamic ? mutableMetadata.DynamicRelocationRanges : mutableMetadata.LoaderMutableRanges;
            ranges.push_back({0x3004, 1});
            size_t mutableReads = 0;
            const ObservationReader mutableReader = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
            {
                if (!reader(address, count, bytes))
                {
                    return false;
                }
                if (address == loadedBase + 0x3000)
                {
                    (*bytes)[4] ^= static_cast<uint8_t>(++mutableReads);
                }
                return true;
            };
            const auto stableChange = CompareExecutableRange(path, mutableMetadata, loadedBase, 0x3000, 4096, mutableReader);
            reviewCheck(stableChange.Ownership == CodeOwnership::OwnedModified && stableChange.Changes.size() == 1 &&
                stableChange.Changes[0].Address == 0x3500 && stableChange.Coverage.ComparedBytes == 4095 &&
                stableChange.Coverage.SkippedBytes == 1 && stableChange.Coverage.FailedBytes == 0,
                dynamic ? "dynamic mutation preserves stable code change" : "loader mutation preserves stable code change");
        }
        ExecutableSweep cleanReuse;
        cleanReuse.Initialize(metadata);
        const ObservationReader cleanReuseReader = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
        {
            const bool read = reader(address, count, bytes);
            if (read && address == loadedBase + 0x1000 && count == 4096)
            {
                live[0] = 0;
            }
            return read;
        };
        const auto reusedClean = AdvanceExecutableSweep(path, metadata, loadedBase, cleanReuseReader, 1, 6, &cleanReuse);
        live[0] = 'M';
        reviewCheck(reusedClean.size() == 1 && reusedClean[0].Ownership == CodeOwnership::OwnedUnverified &&
            !reusedClean[0].Coverage.Complete() && cleanReuse.Pages.empty(), "clean bytes do not validate a replaced image");

        const auto rewriteReference = [&](const std::vector<uint8_t>& bytes)
        {
            HANDLE output = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (output == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            DWORD count = 0;
            const bool writtenAll = WriteFile(output, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
                count == bytes.size();
            CloseHandle(output);
            return writtenAll;
        };
        bool replacedReference = false;
        auto replacedDisk = disk;
        replacedDisk[0x2900] ^= 1;
        const ObservationReader replaceReferenceReader = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
        {
            const bool read = reader(address, count, bytes);
            if (read && !replacedReference)
            {
                replacedReference = rewriteReference(replacedDisk);
            }
            return read;
        };
        const auto staleReference = CompareExecutableRange(path, metadata, loadedBase, 0x3000, 4096, replaceReferenceReader);
        reviewCheck(replacedReference && staleReference.Ownership == CodeOwnership::OwnedUnverified &&
            staleReference.Changes.empty(), "reference file changed during live read");
        if (!rewriteReference(disk) || !ReadDiskPeMetadata(path, &metadata, nullptr) || !reviewControls)
        {
            break;
        }
        // A loader or hotpatch transition must not become a stable difference.
        size_t changingReads = 0;
        const ObservationReader changingReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (!reader(address, size, bytes))
            {
                return false;
            }
            if (address == loadedBase + 0x1000 && ++changingReads == 1)
            {
                (*bytes)[0] ^= 1;
            }
            return true;
        };
        const auto transient = CompareExecutableRange(path, metadata, loadedBase, 0x1000, 4096, changingReader);
        if (transient.Ownership != CodeOwnership::OwnedUnverified || !transient.Changes.empty() ||
            transient.Coverage.Complete())
        {
            break;
        }
        auto discardable = metadata;
        discardable.Sections[0].Characteristics |= IMAGE_SCN_MEM_DISCARDABLE;
        const auto discarded = CompareExecutableRange(path, discardable, loadedBase, 0x3000, 4096, reader);
        if (discarded.Ownership != CodeOwnership::OwnedUnverified || !discarded.Changes.empty() ||
            discarded.Coverage.SkippedBytes != 4096 || discarded.Coverage.ComparedBytes != 0)
        {
            break;
        }
        const auto invalidDiscarded = CompareExecutableRange(path, discardable, UINT64_MAX - 0xFFF, 0x3000, 4096, reader);
        if (!invalidDiscarded.Coverage.Skipped.empty() || !invalidDiscarded.Coverage.Failed.empty() ||
            invalidDiscarded.Coverage.TraversalComplete || invalidDiscarded.Coverage.FailedBytes != 4096)
        {
            std::fprintf(stderr, "[kmon.review] FAIL discarded range address overflow\n");
            break;
        }
        // A second read failure cannot confirm the first mismatching read.
        size_t failedReads = 0;
        const ObservationReader failingReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            return ++failedReads == 1 && reader(address, size, bytes);
        };
        const auto unconfirmed = CompareExecutableRange(path, metadata, loadedBase, 0x3000, 4096, failingReader);
        if (unconfirmed.Ownership != CodeOwnership::OwnedUnverified || !unconfirmed.Changes.empty())
        {
            break;
        }
        unreadable = loadedBase + 0x2000;
        AdvanceExecutableSweep(path, metadata, loadedBase, reader, 8, 6, &sweep);
        if (sweep.Coverage.Complete() || sweep.Coverage.FailedBytes != 4096 || !sweep.Coverage.TraversalComplete)
        {
            break;
        }
        metadata.TimeDateStamp ^= 1;
        if (QualifyExecutableReference(metadata, loadedBase, reader, nullptr))
        {
            break;
        }
        metadata.TimeDateStamp ^= 1;
        unreadable = 0;
        sweep.Initialize(metadata);
        AdvanceExecutableSweep(path, metadata, loadedBase, reader, 1, 7, &sweep);
        metadata.TimeDateStamp ^= 1;
        AdvanceExecutableSweep(path, metadata, loadedBase, reader, 1, 8, &sweep);
        if (sweep.NextRange != 0 || sweep.Coverage.ComparedBytes != 0 || !sweep.Pages.empty())
        {
            break;
        }
        metadata.TimeDateStamp ^= 1;
        live[0x1010] ^= 1;
        const auto restarted = AdvanceExecutableSweep(path, metadata, loadedBase, reader, 1, 9, &sweep);
        if (restarted.size() != 1 || restarted[0].Rva != 0x1000 ||
            restarted[0].Ownership != CodeOwnership::OwnedModified)
        {
            break;
        }
        size_t readsBeforeReuse = 0;
        const ObservationReader reusedReader = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
        {
            if (!reader(address, count, bytes))
            {
                return false;
            }
            if (address == loadedBase + 0x1000 && ++readsBeforeReuse == 2)
            {
                live[0] = 0;
            }
            return true;
        };
        ExecutableSweep reusedSweep;
        reusedSweep.Initialize(metadata);
        const auto reused = AdvanceExecutableSweep(path, metadata, loadedBase, reusedReader, 1, 10, &reusedSweep);
        live[0] = 'M';
        if (reused.size() != 1 || reused[0].Ownership != CodeOwnership::OwnedUnverified ||
            !reused[0].Changes.empty() || reusedSweep.NextRange != 0 || !reusedSweep.Pages.empty())
        {
            break;
        }
        bool rejectedMalformed = true;
        for (size_t malformed = 0; malformed < 4; ++malformed)
        {
            auto invalid = disk;
            auto invalidNt = nt;
            auto invalidSection = sections[2];
            if (malformed == 0)
            {
                // A non-executable overlap must not overwrite expected code.
                invalidSection.VirtualAddress = 0x2000;
            }
            else if (malformed == 1)
            {
                invalidNt.OptionalHeader.SizeOfHeaders = 0x100;
            }
            else if (malformed == 2)
            {
                invalidSection.PointerToRawData = static_cast<DWORD>(disk.size());
            }
            else
            {
                invalidSection.VirtualAddress = 0x200;
            }
            std::memcpy(invalid.data() + 0x80, &invalidNt, sizeof(invalidNt));
            std::memcpy(invalid.data() + 0x80 + sizeof(nt) + 2 * sizeof(IMAGE_SECTION_HEADER),
                &invalidSection, sizeof(invalidSection));
            file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            const bool saved = file != INVALID_HANDLE_VALUE &&
                WriteFile(file, invalid.data(), static_cast<DWORD>(invalid.size()), &written, nullptr) && written == invalid.size();
            if (file != INVALID_HANDLE_VALUE)
            {
                CloseHandle(file);
                file = INVALID_HANDLE_VALUE;
            }
            DiskPeMetadata invalidMetadata;
            rejectedMalformed = saved && !ReadDiskPeMetadata(path, &invalidMetadata, nullptr) && rejectedMalformed;
        }
        if (!rejectedMalformed)
        {
            break;
        }
        ok = true;
    } while (false);
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (path[0] != 0)
    {
        DeleteFileW(path);
    }
    return ok;
}
