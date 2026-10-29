#include "ExecutableImageVerifier.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
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
        uint64_t imageBase, uint32_t rva, uint32_t size, std::vector<uint8_t>* bytes,
        HANDLE reference = INVALID_HANDLE_VALUE)
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
                for (uint32_t n = 0; n < length;)
                {
                    const uint32_t pageRva = (address + n) & ~0xFFFu;
                    auto it = pages.find(pageRva);
                    if (it == pages.end())
                    {
                        std::vector<uint8_t> page;
                        if (!ReadDiskPageForRva(path, metadata, pageRva, &page, nullptr, reference) || page.size() != 4096)
                        {
                            return false;
                        }
                        it = pages.emplace(pageRva, std::move(page)).first;
                    }
                    const auto offset = (address + n) & 0xFFF;
                    const auto count = (std::min)(length - n, 4096 - offset);
                    std::memcpy(out + n, it->second.data() + offset, count);
                    n += count;
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

static bool ReadExecutableIdentity(const DiskPeMetadata& metadata, uint64_t imageBase,
    const ObservationReader& reader, std::wstring* reason, uint64_t* headerBase)
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
        uint64_t livePreferredBase = nt.OptionalHeader.ImageBase;
        if (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            uint32_t base32 = 0;
            std::memcpy(&base32, bytes.data() + offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase), sizeof(base32));
            livePreferredBase = base32;
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
        *headerBase = livePreferredBase;
        ok = true;
    } while (false);
    if (reason != nullptr)
    {
        *reason = ok ? (metadata.HasPdbIdentity ? L"pe_and_pdb_identity_match" : L"pe_identity_match_no_pdb") :
            (mismatch ? L"live_image_identity_mismatch" : L"live_image_identity_unreadable");
    }
    return ok;
}

bool QualifyExecutableReference(const DiskPeMetadata& metadata, uint64_t imageBase,
    const ObservationReader& reader, std::wstring* reason, uint64_t* qualifiedHeaderBase)
{
    if (qualifiedHeaderBase != nullptr)
    {
        *qualifiedHeaderBase = 0;
    }
    uint64_t headerBase = 0;
    if (!ReadExecutableIdentity(metadata, imageBase, reader, reason, &headerBase)) { return false; }
    // A live header alone cannot establish a third relocation base. The full
    // sweep can corroborate it with an independent, file-bound image view.
    if (headerBase != metadata.ImageBase && headerBase != imageBase)
    {
        if (reason) { *reason = L"live_image_relocation_base_ambiguous"; }
        return false;
    }
    if (qualifiedHeaderBase != nullptr)
    {
        *qualifiedHeaderBase = headerBase;
    }
    return true;
}

namespace
{
    struct ReferenceImageView
    {
        HANDLE Section = nullptr;
        void* View = nullptr;
        uint32_t Size = 0;
        ~ReferenceImageView()
        {
            if (View) { UnmapViewOfFile(View); }
            if (Section) { CloseHandle(Section); }
        }
        bool Open(HANDLE file, uint32_t size)
        {
            Section = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
            if (!Section) { return false; }
            View = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
            Size = size;
            return View != nullptr;
        }
        uint64_t Base() const { return reinterpret_cast<uint64_t>(View); }
        bool Read(uint64_t address, size_t size, std::vector<uint8_t>* bytes) const
        {
            if (!View || address < Base() || address - Base() >= Size || size > Size - (address - Base())) { return false; }
            bytes->resize(size);
            SIZE_T count = 0;
            return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), bytes->data(), size, &count) && count == size;
        }
    };
}

static ExecutablePageResult CompareExecutableRangeWithFile(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, uint32_t rva, uint32_t size, const ObservationReader& reader, HANDLE reference,
    uint64_t relocationBase, const ReferenceImageView* referenceImage = nullptr)
{
    ExecutablePageResult result;
    result.Rva = rva;
    result.RelocationBase = relocationBase;
    result.SecondaryImageView = referenceImage != nullptr;
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
        if (!NormalizeRange(path, metadata, relocationBase, rva, size, &result.Expected, reference) ||
            !ReadExact(reader, imageBase, rva, size, &result.Observed))
        {
            break;
        }
        if (referenceImage)
        {
            // The local view comes from the already identity-checked handle,
            // with writes/deletes denied and no DLL initialization. Validate
            // every overlapping relocation byte against the disk calculation;
            // never infer a delta from the target bytes or mask a bad slot.
            std::vector<uint8_t> local;
            auto it = std::lower_bound(metadata.BaseRelocations.begin(), metadata.BaseRelocations.end(), rva,
                [](const DiskPeBaseRelocation& relocation, uint32_t address)
                {
                    return uint64_t(relocation.Rva) + relocation.Width <= address;
                });
            bool matched = true;
            for (; matched && it != metadata.BaseRelocations.end() && it->Rva < uint64_t(rva) + size; ++it)
            {
                if (local.empty() && !referenceImage->Read(referenceImage->Base() + rva, size, &local))
                {
                    matched = false;
                    break;
                }
                const uint32_t start = (std::max)(rva, it->Rva);
                const auto end = (std::min)(uint64_t(rva) + size, uint64_t(it->Rva) + it->Width);
                for (uint64_t address = start; address < end; ++address)
                {
                    matched &= local[static_cast<size_t>(address - rva)] == result.Expected[static_cast<size_t>(address - rva)];
                }
            }
            if (!matched)
            {
                result.Coverage.Reason = L"reference_image_relocation_unverified";
                break;
            }
        }
        // Most executable pages have neither loader-mutable bytes nor REL32
        // alternatives. An exact comparison needs no per-byte mask/range walk.
        // Keep normalization, live reads, and the final reference/image fences;
        // even equal bytes in an excluded range must stay unverified.
        const auto overlapsPage = [&](uint32_t start, uint32_t length)
        {
            return length != 0 && uint64_t(start) < uint64_t(rva) + size &&
                rva < uint64_t(start) + length;
        };
        const auto hasMutable = [&](const std::vector<DiskPeMutableRange>& ranges)
        {
            return std::any_of(ranges.begin(), ranges.end(), [&](const DiskPeMutableRange& range)
            { return overlapsPage(range.Rva, range.Size); });
        };
        if (!hasMutable(metadata.LoaderMutableRanges) && !hasMutable(metadata.DynamicRelocationRanges) &&
            std::none_of(metadata.Rel32Overrides.begin(), metadata.Rel32Overrides.end(),
                [&](const DiskPeRel32Override& fixup) { return overlapsPage(fixup.Rva, 4); }) &&
            result.Expected == result.Observed)
        {
            if (reference == INVALID_HANDLE_VALUE && !DiskReferenceIdentityMatches(path, metadata))
            {
                result.Coverage.Reason = L"reference_changed_during_compare";
                break;
            }
            result.Coverage.ComparedBytes = size;
            result.Coverage.Compared.push_back({imageBase + rva, size});
            result.Coverage.TraversalComplete = true;
            result.Coverage.Reason = L"compared";
            result.Ownership = CodeOwnership::OwnedVerified;
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
        for (const auto& fixup : metadata.Rel32Overrides)
        {
            if (metadata.Machine != IMAGE_FILE_MACHINE_AMD64 || fixup.Rva < rva ||
                uint64_t(fixup.Rva) + 4 > uint64_t(rva) + size || fixup.Targets.empty()) { continue; }
            const auto overlaps = [&](uint32_t start, uint32_t length)
            {
                return uint64_t(start) < uint64_t(fixup.Rva) + 4 && fixup.Rva < uint64_t(start) + length;
            };
            bool supported = true;
            for (const auto& range : metadata.LoaderMutableRanges) { supported &= !overlaps(range.Rva, range.Size); }
            for (const auto& relocation : metadata.BaseRelocations) { supported &= !overlaps(relocation.Rva, relocation.Width); }
            for (uint32_t target : fixup.Targets)
            {
                const auto destination = FindDiskSectionForRva(metadata, target);
                const int64_t displacement = int64_t(target) - fixup.Rva - 4;
                supported &= destination != nullptr && destination->Executable &&
                    (destination->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 &&
                    displacement >= INT32_MIN && displacement <= INT32_MAX;
            }
            int32_t diskDisplacement = 0;
            const auto offset = fixup.Rva - rva;
            std::memcpy(&diskDisplacement, result.Expected.data() + offset, 4);
            supported &= int64_t(fixup.Rva) + 4 + diskDisplacement == fixup.OriginalRva;
            if (!supported) { continue; }
            int32_t observedDisplacement = 0;
            std::memcpy(&observedDisplacement, result.Observed.data() + offset, 4);
            const int64_t target = int64_t(fixup.Rva) + 4 + observedDisplacement;
            // Accept only a complete, file-declared destination. Never mix
            // bytes from multiple alternatives or accept a generic in-image jump.
            if (target >= 0 && target <= UINT32_MAX &&
                std::find(fixup.Targets.begin(), fixup.Targets.end(), uint32_t(target)) != fixup.Targets.end())
            {
                std::memcpy(result.Expected.data() + offset, &observedDisplacement, 4);
            }
            for (uint32_t i = 0; i < 4; ++i) { mutableBytes[offset + i] = false; }
            result.Rel32ValidatedBytes += 4;
        }
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
        if (reference == INVALID_HANDLE_VALUE && !DiskReferenceIdentityMatches(path, metadata))
        {
            result.Coverage.Reason = L"reference_changed_during_compare";
            break;
        }
        for (uint32_t i = 0; i < size;)
        {
            const uint32_t start = i++;
            const bool skipped = mutableBytes[start];
            const bool changed = !skipped && result.Expected[start] != result.Observed[start];
            while (i < size && mutableBytes[i] == skipped &&
                (skipped || (result.Expected[i] != result.Observed[i]) == changed)) { ++i; }
            const auto count = i - start;
            if (skipped)
            {
                result.Coverage.SkippedBytes += count;
                AddObservationRange(&result.Coverage.Skipped, {imageBase + rva + start, count}, &result.Coverage.RangesTruncated);
                continue;
            }
            result.Coverage.ComparedBytes += count;
            AddObservationRange(&result.Coverage.Compared, {imageBase + rva + start, count}, &result.Coverage.RangesTruncated);
            if (changed)
            {
                result.Changes.push_back({static_cast<uint64_t>(rva) + start, count});
            }
        }
        result.Coverage.TraversalComplete = true;
        result.Coverage.Reason = result.Coverage.SkippedBytes != 0 ? L"loader_mutable_ranges_excluded" : L"compared";
        if (result.Rel32ValidatedBytes != 0 && result.Coverage.SkippedBytes == 0)
        {
            result.Coverage.Reason = L"compared_function_override_target_set";
        }
        result.Ownership = !result.Changes.empty() ? CodeOwnership::OwnedModified :
            (result.Coverage.CompleteFor({{imageBase + rva, size}}) ? CodeOwnership::OwnedVerified : CodeOwnership::OwnedUnverified);
    } while (false);
    if (!result.Coverage.TraversalComplete)
    {
        result.Rel32ValidatedBytes = 0;
        result.Coverage.FailedBytes = size;
        if (addressValid)
        {
            result.Coverage.Failed.push_back({imageBase + rva, size});
        }
    }
    return result;
}

ExecutablePageResult CompareExecutableRange(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, uint32_t rva, uint32_t size, const ObservationReader& reader)
{
    return CompareExecutableRangeWithFile(path, metadata, imageBase, rva, size, reader, INVALID_HANDLE_VALUE, imageBase);
}

std::vector<ExecutablePageResult> AdvanceExecutableSweep(const std::wstring& path, const DiskPeMetadata& metadata,
    uint64_t imageBase, const ObservationReader& reader, size_t pageBudget, uint64_t nowMs, ExecutableSweep* sweep,
    uint64_t budgetMs)
{
    const uint64_t started = GetTickCount64();
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
        sweep->Rel32ValidatedBytes = 0;
        ++sweep->Cycle;
    }
    const auto reject = [&](const std::wstring& reason)
    {
        const uint64_t requested = sweep->Coverage.RequestedBytes;
        sweep->Coverage = {};
        sweep->Coverage.RequestedBytes = requested;
        sweep->NextRange = 0;
        sweep->Pages.clear();
        sweep->Rel32ValidatedBytes = 0;
        sweep->RelocationBase = 0;
        sweep->SecondaryImageView = false;
        ++sweep->Cycle;
        sweep->Coverage.Attempted = true;
        sweep->Coverage.InventoryAvailable = false;
        sweep->Coverage.Reason = reason;
    };
    std::wstring reason;
    uint64_t headerBase = 0;
    if (!ReadExecutableIdentity(metadata, imageBase, reader, &reason, &headerBase))
    {
        reject(reason);
        return results;
    }
    sweep->Coverage.Attempted = true;
    sweep->Coverage.InventoryAvailable = true;
    const auto reference = CreateFileW(NormalizeReferencePath(path).c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    const std::unique_ptr<void, decltype(&CloseHandle)> referenceOwner(
        reference == INVALID_HANDLE_VALUE ? nullptr : reference, &CloseHandle);
    if (reference == INVALID_HANDLE_VALUE || !DiskFileIdentityMatches(reference, metadata))
    {
        sweep->Coverage.Reason = L"reference_unavailable_or_changed";
        return results;
    }
    ReferenceImageView localImage;
    const bool secondary = headerBase != metadata.ImageBase && headerBase != imageBase;
    uint64_t relocationBase = imageBase;
    const ObservationReader localReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
    {
        return localImage.Read(address, size, bytes);
    };
    if (secondary)
    {
        uint64_t localBase = 0;
        if (!localImage.Open(reference, metadata.SizeOfImage) ||
            !ReadExecutableIdentity(metadata, localImage.Base(), localReader, nullptr, &localBase) ||
            localBase != headerBase || localBase == 0 || (localBase & 0xFFFF) != 0 ||
            localBase > UINT64_MAX - metadata.SizeOfImage)
        {
            reject(L"live_image_relocation_base_ambiguous");
            return results;
        }
        relocationBase = localBase;
    }
    if (sweep->NextRange != 0 && (sweep->RelocationBase != relocationBase || sweep->SecondaryImageView != secondary))
    {
        reject(L"image_relocation_basis_changed");
        return results;
    }
    sweep->RelocationBase = relocationBase;
    sweep->SecondaryImageView = secondary;
    const size_t end = sweep->NextRange + (std::min)(pageBudget, sweep->Ranges.size() - sweep->NextRange);
    size_t publications = 0;
    bool publicationLimited = false;
    for (; sweep->NextRange < end; ++sweep->NextRange)
    {
        if (publications >= 64)
        {
            publicationLimited = true;
            break;
        }
        if (!results.empty() && budgetMs != 0 && GetTickCount64() - started >= budgetMs)
        {
            break;
        }
        const auto& range = sweep->Ranges[sweep->NextRange];
        auto page = CompareExecutableRangeWithFile(path, metadata, imageBase,
            static_cast<uint32_t>(range.Address), static_cast<uint32_t>(range.Size), reader, reference,
            relocationBase, secondary ? &localImage : nullptr);
        const bool coalesces = !results.empty() && page.Ownership == CodeOwnership::OwnedVerified &&
            page.Rel32ValidatedBytes == 0 && results.back().Ownership == CodeOwnership::OwnedVerified &&
            results.back().Rel32ValidatedBytes == 0 && (page.Rva >> 16) == (results.back().Rva >> 16) &&
            page.Rva == uint64_t(results.back().Rva) + results.back().Coverage.RequestedBytes;
        if (!coalesces) { ++publications; }
        sweep->Pages[page.Rva] = page.Ownership;
        sweep->Coverage.ComparedBytes += page.Coverage.ComparedBytes;
        sweep->Coverage.FailedBytes += page.Coverage.FailedBytes;
        sweep->Coverage.SkippedBytes += page.Coverage.SkippedBytes;
        sweep->Rel32ValidatedBytes += page.Rel32ValidatedBytes;
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
    const bool sameReference = DiskFileIdentityMatches(reference, metadata) && DiskReferenceIdentityMatches(path, metadata);
    uint64_t finalHeaderBase = 0, finalLocalBase = 0;
    const bool sameImage = !hasComparedBytes ||
        (ReadExecutableIdentity(metadata, imageBase, reader, &reason, &finalHeaderBase) && finalHeaderBase == headerBase &&
            (!secondary || (ReadExecutableIdentity(metadata, localImage.Base(), localReader, nullptr, &finalLocalBase) &&
                finalLocalBase == relocationBase)));
    if (!sameReference || !sameImage)
    {
        // The mapping may have changed after the initial identity read.
        for (auto& page : results)
        {
            const uint64_t requested = page.Coverage.RequestedBytes;
            page.Ownership = CodeOwnership::OwnedUnverified;
            page.Changes.clear();
            page.Rel32ValidatedBytes = 0;
            page.RelocationBase = 0;
            page.SecondaryImageView = false;
            page.Coverage = {};
            page.Coverage.Attempted = true;
            page.Coverage.RequestedBytes = requested;
            page.Coverage.FailedBytes = requested;
            page.Coverage.Failed.push_back({imageBase + page.Rva, requested});
            page.Coverage.Reason = sameReference ? L"image_identity_changed_during_compare" : L"reference_changed_during_compare";
        }
        const uint64_t requested = sweep->Coverage.RequestedBytes;
        sweep->Coverage = {};
        sweep->Coverage.Attempted = true;
        sweep->Coverage.RequestedBytes = requested;
        sweep->Coverage.FailedBytes = requested;
        sweep->Coverage.Reason = sameReference ? L"image_identity_changed_during_compare" : L"reference_changed_during_compare";
        sweep->Pages.clear();
        sweep->NextRange = 0;
        sweep->Rel32ValidatedBytes = 0;
        sweep->RelocationBase = 0;
        sweep->SecondaryImageView = false;
        ++sweep->Cycle;
        return results;
    }
    sweep->Coverage.TraversalComplete = sweep->NextRange == sweep->Ranges.size();
    sweep->Coverage.ResumeAddress = sweep->Coverage.TraversalComplete ? 0 : imageBase + sweep->Ranges[sweep->NextRange].Address;
    sweep->Coverage.Reason = sweep->Coverage.Complete() ? L"cycle_complete" :
        (sweep->Coverage.TraversalComplete ? L"cycle_complete_with_gaps" :
            (publicationLimited ? L"publication_budget" : (sweep->NextRange < end ? L"time_budget" : L"page_budget")));
    if (sweep->Coverage.TraversalComplete)
    {
        sweep->LastCompleteMs = nowMs;
        ++sweep->CompletedCycles;
        sweep->LastCompleteRel32ValidatedBytes = sweep->Rel32ValidatedBytes;
        sweep->LastCompleteCoverage = sweep->Coverage;
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
        const int32_t originalRel32 = 0x1300 - 0x1151 - 4;
        std::memcpy(disk.data() + 0x551, &originalRel32, 4);
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
        ExecutableSweep timed;
        timed.Initialize(metadata);
        const ObservationReader slowReader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (size == 4096) { Sleep(20); }
            return reader(address, size, bytes);
        };
        const auto firstTimed = AdvanceExecutableSweep(path, metadata, loadedBase, slowReader, 4, 10, &timed, 1);
        const bool paused = firstTimed.size() == 1 && timed.NextRange == 1 && timed.CompletedCycles == 0 &&
            timed.Coverage.Reason == L"time_budget" && !timed.Coverage.TraversalComplete;
        const auto tailTimed = AdvanceExecutableSweep(path, metadata, loadedBase, reader, 4, 11, &timed);
        if (!paused || tailTimed.size() != 3 || tailTimed.back().Rva != 0x5000 ||
            tailTimed.back().Ownership != CodeOwnership::OwnedModified || timed.CompletedCycles != 1 ||
            !timed.LastCompleteCoverage.Complete()) { break; }
        AdvanceExecutableSweep(path, metadata, loadedBase, reader, 1, 12, &timed);
        if (timed.Coverage.TraversalComplete || timed.NextRange != 1 || timed.CompletedCycles != 1 ||
            !timed.LastCompleteCoverage.Complete() || timed.LastCompleteMs != 11) { break; }
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
            ranges.push_back({0x2004, 1});
            const auto equalExcluded = CompareExecutableRange(path, mutableMetadata, loadedBase, 0x2000, 4096, reader);
            reviewCheck(equalExcluded.Ownership == CodeOwnership::OwnedUnverified &&
                equalExcluded.Coverage.ComparedBytes == 4095 && equalExcluded.Coverage.SkippedBytes == 1 &&
                equalExcluded.Changes.empty(), "equal mutable bytes remain excluded from exact comparison");
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
        {
            auto dynamic = metadata;
            dynamic.DynamicRelocationRanges.push_back({0x1151, 4});
            dynamic.Rel32Overrides.push_back({0x1151, 0x1300, {0x1300, 0x1400}});
            const auto compareTarget = [&](int32_t target)
            {
                const int32_t displacement = target - 0x1151 - 4;
                std::memcpy(live.data() + 0x1151, &displacement, 4);
                return CompareExecutableRange(path, dynamic, loadedBase, 0x1000, 4096, reader);
            };
            for (int32_t target : {0x1300, 0x1400})
            {
                const auto allowed = compareTarget(target);
                reviewCheck(allowed.Ownership == CodeOwnership::OwnedVerified && allowed.Rel32ValidatedBytes == 4 &&
                    allowed.Coverage.ComparedBytes == 4096 && allowed.Coverage.SkippedBytes == 0,
                    "REL32 original and declared alternate both compared");
            }
            for (int32_t target : {0x1401, 0x1700, -1, 0x7000})
            {
                const auto denied = compareTarget(target);
                reviewCheck(denied.Ownership == CodeOwnership::OwnedModified && denied.Rel32ValidatedBytes == 4 &&
                    !denied.Changes.empty(), "REL32 undeclared and out-of-image destinations detected");
            }
            size_t reads = 0;
            const ObservationReader changing = [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes)
            {
                if (!reader(address, length, bytes)) { return false; }
                if (address == loadedBase + 0x1000 && ++reads == 2) { (*bytes)[0x151] ^= 1; }
                return true;
            };
            const auto unstable = CompareExecutableRange(path, dynamic, loadedBase, 0x1000, 4096, changing);
            reviewCheck(unstable.Ownership == CodeOwnership::OwnedUnverified && unstable.Changes.empty() &&
                unstable.Rel32ValidatedBytes == 0, "REL32 mismatch must survive a stable second read");
            dynamic.Rel32Overrides[0].Targets.push_back(0x6000); // non-executable target
            const auto unsupported = compareTarget(0x1400);
            reviewCheck(unsupported.Coverage.SkippedBytes == 4 && unsupported.Rel32ValidatedBytes == 0,
                "REL32 unsupported target set remains excluded");
            const auto equalUnsupported = compareTarget(0x1300);
            reviewCheck(equalUnsupported.Ownership == CodeOwnership::OwnedUnverified &&
                equalUnsupported.Coverage.SkippedBytes == 4 && equalUnsupported.Coverage.ComparedBytes == 4092,
                "equal unsupported REL32 bytes remain excluded");
            std::memcpy(live.data() + 0x1151, &originalRel32, 4);

            std::vector<uint8_t> dvrt;
            const auto append = [&](const auto& value)
            {
                const auto bytes = reinterpret_cast<const uint8_t*>(&value);
                dvrt.insert(dvrt.end(), bytes, bytes + sizeof(value));
            };
            append(IMAGE_DYNAMIC_RELOCATION_TABLE{1, 80});
            append(IMAGE_DYNAMIC_RELOCATION64{IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE, 68});
            append(IMAGE_FUNCTION_OVERRIDE_HEADER{32});
            append(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION{0x1300, 0, 4, 12});
            append(uint32_t(0x1400)); append(IMAGE_BASE_RELOCATION{0x1000, 12});
            append(uint16_t(0x1151)); append(uint16_t(0));
            append(IMAGE_BDD_INFO{1, 24});
            append(IMAGE_BDD_DYNAMIC_RELOCATION{2, 1, 0});
            append(IMAGE_BDD_DYNAMIC_RELOCATION{1, 1, 0});
            append(IMAGE_BDD_DYNAMIC_RELOCATION{0, 0, 0});
            std::vector<DiskPeMutableRange> ranges;
            std::vector<DiskPeRel32Override> overrides;
            reviewCheck(ParseDynamicRelocationTable(dvrt, true, 0x7000, &ranges, &overrides) &&
                overrides.size() == 1 && overrides[0].Rva == 0x1151 && overrides[0].Targets == std::vector<uint32_t>({0x1300, 0x1400}),
                "DVRT retains qualified target alternatives");
            auto overlapping = dvrt;
            std::memcpy(overlapping.data() + 54, overlapping.data() + 52, 2);
            reviewCheck(!ParseDynamicRelocationTable(overlapping, true, 0x7000, &ranges, &overrides),
                "overlapping DVRT fixups rejected");
            {
                std::vector<uint8_t> repeated;
                const auto put = [&](const auto& value)
                {
                    const auto first = reinterpret_cast<const uint8_t*>(&value);
                    repeated.insert(repeated.end(), first, first + sizeof(value));
                };
                constexpr uint32_t records = 65, nodes = 1024;
                constexpr uint32_t payloadBytes = 4 + records * 32 + 8 + nodes * 8;
                put(IMAGE_DYNAMIC_RELOCATION_TABLE{1, 12 + payloadBytes});
                put(IMAGE_DYNAMIC_RELOCATION64{IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE, payloadBytes});
                put(IMAGE_FUNCTION_OVERRIDE_HEADER{records * 32});
                for (uint32_t i = 0; i < records; ++i)
                {
                    put(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION{0x1300, 0, 4, 12}); put(uint32_t(0x1400));
                    put(IMAGE_BASE_RELOCATION{0x1000, 12}); put(uint16_t(0x1000 + i * 4)); put(uint16_t(0));
                }
                put(IMAGE_BDD_INFO{1, nodes * 8});
                for (uint32_t i = 0; i < nodes; ++i) { put(IMAGE_BDD_DYNAMIC_RELOCATION{0, 0, 0}); }
                std::vector<DiskPeMutableRange> boundedRanges;
                std::vector<DiskPeRel32Override> boundedOverrides;
                reviewCheck(ParseDynamicRelocationTable(repeated, true, 0x7000, &boundedRanges, &boundedOverrides) &&
                    boundedOverrides.size() == 64 && boundedOverrides[0].Targets == std::vector<uint32_t>({0x1300}) &&
                    boundedRanges.size() == 1 && boundedRanges[0].Size == records * 4,
                    "shared BDD work is bounded; remaining operands stay excluded");
            }
            auto malformed = dvrt;
            malformed[64] = 0xFF; // first BDD edge beyond the node array
            overrides.clear();
            reviewCheck(ParseDynamicRelocationTable(malformed, true, 0x7000, &ranges, &overrides) && overrides.empty(),
                "malformed BDD cannot authorize excluded bytes");
            const uint32_t original = 0x1300;
            std::memcpy(dvrt.data() + 40, &original, 4);
            reviewCheck(ParseDynamicRelocationTable(dvrt, true, 0x7000, &ranges, &overrides) && overrides.empty(),
                "external-thunk sentinel remains excluded");
            dvrt.pop_back();
            reviewCheck(!ParseDynamicRelocationTable(dvrt, true, 0x7000, &ranges, &overrides), "truncated DVRT rejected");
        }
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
        {
            // Both a file-preferred header and a loader-updated header are
            // normal. A third base is an unverified secondary view, not a
            // positive code patch. Exercise both optional-header layouts.
            const auto savedLive = live;
            bool baseControls = true;
            for (bool pe32 : {false, true})
            {
                auto reference = metadata;
                auto header = nt;
                if (pe32)
                {
                    reference.OptionalMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
                    reference.ImageBase = 0x10000000;
                    header.OptionalHeader.Magic = reference.OptionalMagic;
                }
                std::memcpy(live.data() + dos.e_lfanew, &header, sizeof(header));
                const auto setBase = [&](uint64_t value)
                {
                    const size_t offset = pe32 ? offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase) :
                        offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase);
                    std::memcpy(live.data() + dos.e_lfanew + offset, &value, pe32 ? 4 : 8);
                };
                setBase(reference.ImageBase);
                baseControls = QualifyExecutableReference(reference, loadedBase, reader, nullptr) && baseControls;
                if (!pe32)
                {
                    setBase(loadedBase);
                    baseControls = QualifyExecutableReference(reference, loadedBase, reader, nullptr) && baseControls;
                }
                setBase(0x6e3e0000);
                std::wstring reason;
                ExecutableSweep secondary;
                secondary.Initialize(reference);
                const auto pages = AdvanceExecutableSweep(path, reference, loadedBase, reader, 1, 7, &secondary);
                if (QualifyExecutableReference(reference, loadedBase, reader, &reason) ||
                    reason != L"live_image_relocation_base_ambiguous" || !pages.empty() ||
                    secondary.Coverage.ComparedBytes != 0 || secondary.Coverage.Complete() ||
                    secondary.Coverage.Reason != reason) { baseControls = false; }
            }
            live = savedLive;
            if (!baseControls) { break; }
        }
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
        // A large all-modified image must not turn a throughput increase into
        // an unbounded finding/capture burst. Also verify cursor resumption.
        constexpr uint32_t manyPages = 96;
        auto largeNt = nt;
        largeNt.FileHeader.NumberOfSections = 1;
        largeNt.OptionalHeader.ImageBase = loadedBase;
        largeNt.OptionalHeader.SizeOfImage = (manyPages + 1) * 4096;
        largeNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {};
        auto largeSection = sections[0];
        largeSection.Misc.VirtualSize = largeSection.SizeOfRawData = manyPages * 4096;
        std::vector<uint8_t> largeDisk(0x400 + manyPages * 4096, 0x90);
        std::fill(largeDisk.begin(), largeDisk.begin() + 0x400, uint8_t(0));
        std::memcpy(largeDisk.data(), &dos, sizeof(dos));
        std::memcpy(largeDisk.data() + 0x80, &largeNt, sizeof(largeNt));
        std::memcpy(largeDisk.data() + 0x80 + sizeof(largeNt), &largeSection, sizeof(largeSection));
        if (!rewriteReference(largeDisk)) { break; }
        DiskPeMetadata largeMetadata;
        if (!ReadDiskPeMetadata(path, &largeMetadata, nullptr)) { break; }
        std::vector<uint8_t> largeLive(largeNt.OptionalHeader.SizeOfImage, 0x90);
        std::copy(largeDisk.begin(), largeDisk.begin() + 0x400, largeLive.begin());
        for (size_t i = 0; i < manyPages; ++i) { largeLive[(i + 1) * 4096] ^= 1; }
        bool writeBlocked = false;
        const ObservationReader largeReader = [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes)
        {
            if (address < loadedBase || address - loadedBase >= largeLive.size() ||
                length > largeLive.size() - (address - loadedBase)) { return false; }
            if (length == 4096)
            {
                HANDLE writer = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                writeBlocked = writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
                if (writer != INVALID_HANDLE_VALUE) { CloseHandle(writer); }
            }
            bytes->assign(largeLive.begin() + size_t(address - loadedBase), largeLive.begin() + size_t(address - loadedBase) + length);
            return true;
        };
        ExecutableSweep largeSweep;
        if (!largeSweep.Initialize(largeMetadata)) { break; }
        const auto burst = AdvanceExecutableSweep(path, largeMetadata, loadedBase, largeReader, 1024, 11, &largeSweep);
        if (burst.size() != 64 || largeSweep.NextRange != 64 || largeSweep.Coverage.Reason != L"publication_budget" ||
            !writeBlocked || !std::all_of(burst.begin(), burst.end(), [](const ExecutablePageResult& page)
            { return page.Ownership == CodeOwnership::OwnedModified; })) { break; }
        const auto rest = AdvanceExecutableSweep(path, largeMetadata, loadedBase, largeReader, 1024, 12, &largeSweep);
        if (rest.size() != 32 || !largeSweep.Coverage.Complete()) { break; }
        for (size_t i = 0; i < manyPages; ++i) { largeLive[(i + 1) * 4096] ^= 1; }
        const auto normal = AdvanceExecutableSweep(path, largeMetadata, loadedBase, largeReader, 1024, 13, &largeSweep);
        if (normal.size() != manyPages || !largeSweep.Coverage.Complete() ||
            !std::all_of(normal.begin(), normal.end(), [](const ExecutablePageResult& page)
                { return page.Ownership == CodeOwnership::OwnedVerified; })) { break; }
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
