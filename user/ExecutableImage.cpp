#include "ExecutableImage.h"

#include <cstring>
#include <limits>
#include <map>

namespace executable_image
{
    constexpr uint64_t kPageSize = 0x1000;
    constexpr size_t kMaxBaseRelocationEntries = 8 * 1024 * 1024;
    constexpr uint32_t kMaxBaseRelocationTableBytes = 64u * 1024u * 1024u;
    constexpr size_t kMaxDynamicRelocationRanges = 65536;
    constexpr uint32_t kComImageFlagsIlOnly = 1;

    static std::wstring NormalizeReferencePath(const std::wstring& path)
    {
        std::wstring result = path;
        if (_wcsnicmp(result.c_str(), L"\\SystemRoot\\", 12) == 0)
        {
            wchar_t windows[MAX_PATH] = {};
            if (GetWindowsDirectoryW(windows, MAX_PATH) != 0)
            {
                result = std::wstring(windows) + result.substr(11);
            }
        }
        else if (result.rfind(L"\\??\\", 0) == 0)
        {
            result = result.substr(4);
        }
        else if (_wcsnicmp(result.c_str(), L"\\Device\\", 8) == 0)
        {
            for (wchar_t drive = L'A'; drive <= L'Z'; ++drive)
            {
                wchar_t name[] = {drive, L':', 0};
                wchar_t target[32768] = {};
                if (QueryDosDeviceW(name, target, 32768) != 0)
                {
                    const size_t length = wcslen(target);
                    if (_wcsnicmp(result.c_str(), target, length) == 0 &&
                        result.size() > length && result[length] == L'\\')
                    {
                        result = std::wstring(name) + result.substr(length);
                        break;
                    }
                }
            }
        }
        return result;
    }

    bool ReadFileBytesAt(HANDLE file, uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || file == INVALID_HANDLE_VALUE || length == 0)
            {
                break;
            }

            LARGE_INTEGER distance = {};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN))
            {
                break;
            }

            bytes->assign(length, 0);
            DWORD read = 0;
            if (!ReadFile(file, bytes->data(), length, &read, nullptr))
            {
                break;
            }

            bytes->resize(read);
            ok = !bytes->empty();
        } while (false);

        return ok;
    }

    bool RvaToRawOffset(const DiskPeMetadata& metadata, uint32_t rva, uint64_t* rawOffset)
    {
        bool ok = false;

        do
        {
            if (rawOffset == nullptr)
            {
                break;
            }

            if (metadata.SizeOfHeaders != 0 && rva < metadata.SizeOfHeaders)
            {
                *rawOffset = rva;
                ok = true;
                break;
            }

            for (const DiskPeSection& section : metadata.Sections)
            {
                uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan == 0)
                {
                    continue;
                }

                uint64_t sectionStart = section.VirtualAddress;
                uint64_t sectionEnd = sectionStart + mappedSpan;
                if (sectionEnd < sectionStart ||
                    rva < sectionStart ||
                    rva >= sectionEnd)
                {
                    continue;
                }

                uint64_t rawSpan = section.SizeOfRawData;
                if (rawSpan > mappedSpan)
                {
                    rawSpan = mappedSpan;
                }

                uint64_t delta = static_cast<uint64_t>(rva) - sectionStart;
                if (delta >= rawSpan)
                {
                    break;
                }

                *rawOffset = static_cast<uint64_t>(section.PointerToRawData) + delta;
                ok = true;
                break;
            }
        } while (false);

        return ok;
    }

    const DiskPeSection* FindDiskSectionForRva(const DiskPeMetadata& metadata, uint32_t rva)
    {
        const DiskPeSection* found = nullptr;

        for (const DiskPeSection& section : metadata.Sections)
        {
            uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
            if (mappedSpan == 0)
            {
                continue;
            }

            uint64_t sectionStart = section.VirtualAddress;
            uint64_t sectionEnd = sectionStart + mappedSpan;
            if (sectionEnd < sectionStart)
            {
                continue;
            }

            if (rva >= sectionStart && rva < sectionEnd)
            {
                found = &section;
                break;
            }
        }

        return found;
    }

    bool ReadDiskBytesForRva(
        HANDLE file,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr ||
                file == INVALID_HANDLE_VALUE ||
                length == 0 ||
                rva >= metadata.SizeOfImage ||
                length > metadata.SizeOfImage - rva)
            {
                break;
            }

            bytes->clear();
            bytes->reserve(length);
            uint32_t currentRva = rva;
            uint32_t remaining = length;
            while (remaining != 0)
            {
                uint64_t rawOffset = 0;
                uint64_t available = 0;
                if (metadata.SizeOfHeaders != 0 &&
                    currentRva < metadata.SizeOfHeaders)
                {
                    rawOffset = currentRva;
                    available =
                        static_cast<uint64_t>(metadata.SizeOfHeaders) -
                        currentRva;
                }
                else
                {
                    for (const DiskPeSection& section : metadata.Sections)
                    {
                        const uint64_t sectionStart =
                            section.VirtualAddress;
                        const uint64_t rawSpan = section.SizeOfRawData;
                        const uint64_t sectionRawEnd =
                            sectionStart + rawSpan;
                        if (rawSpan == 0 ||
                            sectionRawEnd < sectionStart ||
                            currentRva < sectionStart ||
                            currentRva >= sectionRawEnd)
                        {
                            continue;
                        }

                        const uint64_t delta =
                            static_cast<uint64_t>(currentRva) -
                            sectionStart;
                        rawOffset =
                            static_cast<uint64_t>(
                                section.PointerToRawData) +
                            delta;
                        available = rawSpan - delta;
                        break;
                    }
                }
                if (available == 0)
                {
                    break;
                }

                const uint32_t chunk = static_cast<uint32_t>(
                    std::min<uint64_t>(available, remaining));
                std::vector<uint8_t> part;
                if (!ReadFileBytesAt(
                        file,
                        rawOffset,
                        chunk,
                        &part) ||
                    part.size() != chunk)
                {
                    break;
                }
                bytes->insert(
                    bytes->end(),
                    part.begin(),
                    part.end());
                currentRva += chunk;
                remaining -= chunk;
            }

            ok = remaining == 0 && bytes->size() == length;
        } while (false);

        if (!ok && bytes != nullptr)
        {
            bytes->clear();
        }
        return ok;
    }

    bool BytesAreAllZero(
        const std::vector<uint8_t>& bytes)
    {
        return std::all_of(
            bytes.begin(),
            bytes.end(),
            [](uint8_t value)
            {
                return value == 0;
            });
    }

    void PopulateRelocationPages(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t relocRva,
        uint32_t relocSize)
    {
        if (metadata == nullptr)
        {
            return;
        }

        metadata->BaseRelocationTablePresent =
            relocRva != 0 || relocSize != 0;
        if (!metadata->BaseRelocationTablePresent)
        {
            return;
        }

        bool complete =
            file != INVALID_HANDLE_VALUE &&
            relocRva != 0 &&
            relocSize >= sizeof(IMAGE_BASE_RELOCATION) &&
            relocSize <= kMaxBaseRelocationTableBytes &&
            relocRva < metadata->SizeOfImage &&
            relocSize <= metadata->SizeOfImage - relocRva;
        uint32_t parsed = 0;
        size_t relocationEntries = 0;
        while (complete && parsed < relocSize)
        {
            const uint32_t remaining = relocSize - parsed;
            if (remaining < sizeof(IMAGE_BASE_RELOCATION))
            {
                complete = false;
                break;
            }

            std::vector<uint8_t> blockHeader;
            if (!ReadDiskBytesForRva(
                    file,
                    *metadata,
                    relocRva + parsed,
                    sizeof(IMAGE_BASE_RELOCATION),
                    &blockHeader) ||
                blockHeader.size() < sizeof(IMAGE_BASE_RELOCATION))
            {
                complete = false;
                break;
            }

            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, blockHeader.data(), sizeof(block));
            if (block.VirtualAddress == 0 && block.SizeOfBlock == 0)
            {
                const uint32_t trailingBytes =
                    remaining -
                    static_cast<uint32_t>(
                        sizeof(IMAGE_BASE_RELOCATION));
                std::vector<uint8_t> terminatorPadding;
                if (trailingBytes != 0 &&
                    (!ReadDiskBytesForRva(
                         file,
                         *metadata,
                         relocRva +
                             parsed +
                             sizeof(IMAGE_BASE_RELOCATION),
                         trailingBytes,
                         &terminatorPadding) ||
                     terminatorPadding.size() != trailingBytes ||
                     !BytesAreAllZero(
                         terminatorPadding)))
                {
                    // A zero relocation header is an optional terminator, not
                    // permission to ignore arbitrary trailing table data.
                    complete = false;
                    break;
                }
                parsed = relocSize;
                break;
            }
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > remaining ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) %
                    sizeof(uint16_t)) != 0)
            {
                complete = false;
                break;
            }

            const uint32_t entryBytes =
                block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
            std::vector<uint8_t> entries;
            if (entryBytes != 0 &&
                (!ReadDiskBytesForRva(
                     file,
                     *metadata,
                     relocRva + parsed + sizeof(IMAGE_BASE_RELOCATION),
                     entryBytes,
                     &entries) ||
                 entries.size() < entryBytes))
            {
                complete = false;
                break;
            }

            const size_t entryCount = entryBytes / sizeof(uint16_t);
            for (size_t index = 0; index < entryCount; ++index)
            {
                uint16_t entry = 0;
                std::memcpy(
                    &entry,
                    entries.data() + index * sizeof(uint16_t),
                    sizeof(entry));
                const uint16_t type = entry >> 12;
                const uint16_t offset = entry & 0x0fffu;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                if (++relocationEntries > kMaxBaseRelocationEntries)
                {
                    complete = false;
                    break;
                }

                uint32_t fixupWidth = 0;
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    fixupWidth = sizeof(uint64_t);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    fixupWidth = sizeof(uint32_t);
                }
                else
                {
                    complete = false;
                    break;
                }

                const uint64_t fixupRva64 =
                    static_cast<uint64_t>(block.VirtualAddress) + offset;
                if (fixupRva64 >= metadata->SizeOfImage ||
                    fixupWidth > metadata->SizeOfImage - fixupRva64)
                {
                    complete = false;
                    break;
                }

                const uint32_t fixupRva =
                    static_cast<uint32_t>(fixupRva64);
                metadata->RelocationPages.insert(
                    fixupRva & 0xfffff000u);
                DiskPeBaseRelocation relocation = {};
                relocation.Rva = fixupRva;
                relocation.Width = fixupWidth;
                metadata->BaseRelocations.push_back(relocation);
                if (((fixupRva & 0xfffu) + fixupWidth) > 0x1000u)
                {
                    const uint64_t nextPage =
                        static_cast<uint64_t>(fixupRva & 0xfffff000u) +
                        0x1000u;
                    if (nextPage >= metadata->SizeOfImage ||
                        nextPage > std::numeric_limits<uint32_t>::max())
                    {
                        complete = false;
                        break;
                    }
                    metadata->RelocationPages.insert(
                        static_cast<uint32_t>(nextPage));
                    DiskPeMutableRange crossPage = {};
                    crossPage.Rva = fixupRva;
                    crossPage.Size = fixupWidth;
                    metadata->CrossPageRelocationRanges.push_back(
                        crossPage);
                }
            }
            if (!complete)
            {
                break;
            }

            parsed += block.SizeOfBlock;
        }

        metadata->BaseRelocationTableComplete =
            complete && parsed == relocSize;
        if (metadata->BaseRelocationTableComplete)
        {
            std::stable_sort(
                metadata->BaseRelocations.begin(),
                metadata->BaseRelocations.end(),
                [](const DiskPeBaseRelocation& left,
                   const DiskPeBaseRelocation& right)
                {
                    return left.Rva < right.Rva;
                });
            for (size_t i = 1; i < metadata->BaseRelocations.size(); ++i)
            {
                const auto& previous = metadata->BaseRelocations[i - 1];
                if (static_cast<uint64_t>(previous.Rva) + previous.Width > metadata->BaseRelocations[i].Rva)
                {
                    metadata->BaseRelocationTableComplete = false;
                    break;
                }
            }
        }
        else
        {
            metadata->RelocationPages.clear();
            metadata->BaseRelocations.clear();
            metadata->CrossPageRelocationRanges.clear();
        }
    }

    void AddLoaderMutableRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size)
    {
        if (ranges == nullptr || rva == 0 || size == 0)
        {
            return;
        }

        const uint64_t end = static_cast<uint64_t>(rva) + size;
        if (end >
            static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1ull)
        {
            return;
        }

        DiskPeMutableRange range = {};
        range.Rva = rva;
        range.Size = size;
        ranges->push_back(range);
    }

    void AddLoaderMutableDirectoryRanges(
        std::vector<DiskPeMutableRange>* ranges,
        const IMAGE_DATA_DIRECTORY* directories,
        uint32_t count)
    {
        do
        {
            if (ranges == nullptr || directories == nullptr)
            {
                break;
            }

            // The loader overwrites IAT slots. Import descriptors, delay-load
            // descriptors, TLS, and load-config structures are not themselves
            // blanket-mutable and masking their whole directories can hide an
            // executable-page patch.
            const uint32_t mutableDirectories[] =
            {
                IMAGE_DIRECTORY_ENTRY_IAT
            };

            for (uint32_t directoryIndex : mutableDirectories)
            {
                if (directoryIndex >= count)
                {
                    continue;
                }

                AddLoaderMutableRange(
                    ranges,
                    directories[directoryIndex].VirtualAddress,
                    directories[directoryIndex].Size);
            }
        } while (false);
    }

    bool AddDynamicRelocationRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size)
    {
        if (ranges == nullptr || size == 0)
        {
            return false;
        }

        const uint64_t end = static_cast<uint64_t>(rva) + size;
        if (end > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1ull)
        {
            return false;
        }

        for (const DiskPeMutableRange& existing : *ranges)
        {
            if (existing.Rva == rva && existing.Size == size)
            {
                return true;
            }
        }
        if (ranges->size() >= kMaxDynamicRelocationRanges)
        {
            return false;
        }

        DiskPeMutableRange range = {};
        range.Rva = rva;
        range.Size = size;
        ranges->push_back(range);
        return true;
    }

    bool ParseFunctionOverrideBaseRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (bytes == nullptr ||
            ranges == nullptr ||
            sizeOfImage == 0)
        {
            return false;
        }

        size_t cursor = 0;
        while (cursor < size)
        {
            if (size - cursor < sizeof(IMAGE_BASE_RELOCATION))
            {
                return false;
            }

            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, bytes + cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > size - cursor ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(uint16_t)) != 0)
            {
                return false;
            }

            const size_t entryBytes = block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
            const size_t entryCount = entryBytes / sizeof(uint16_t);
            for (size_t index = 0; index < entryCount; ++index)
            {
                uint16_t entry = 0;
                std::memcpy(
                    &entry,
                    bytes + cursor + sizeof(IMAGE_BASE_RELOCATION) + index * sizeof(entry),
                    sizeof(entry));

                const uint16_t type = static_cast<uint16_t>(entry >> 12);
                const uint16_t offset = static_cast<uint16_t>(entry & 0x0fffu);
                if (type == IMAGE_FUNCTION_OVERRIDE_INVALID)
                {
                    continue;
                }

                uint32_t width = 0;
                if (type == IMAGE_FUNCTION_OVERRIDE_X64_REL32 ||
                    type == IMAGE_FUNCTION_OVERRIDE_ARM64_BRANCH26)
                {
                    width = sizeof(uint32_t);
                }
                else
                {
                    // The SDK does not define the byte span of THUNK records.
                    // Fail closed instead of masking an assumed range.
                    return false;
                }

                const uint64_t fixupRva = static_cast<uint64_t>(block.VirtualAddress) + offset;
                if (fixupRva >= sizeOfImage ||
                    width > sizeOfImage - fixupRva ||
                    !AddDynamicRelocationRange(
                        ranges,
                        static_cast<uint32_t>(fixupRva),
                        width))
                {
                    return false;
                }
            }

            cursor += block.SizeOfBlock;
        }

        return cursor == size;
    }

    bool ParseFunctionOverrideDynamicRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (bytes == nullptr ||
            ranges == nullptr ||
            sizeOfImage == 0 ||
            size < sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER))
        {
            return false;
        }

        IMAGE_FUNCTION_OVERRIDE_HEADER header = {};
        std::memcpy(&header, bytes, sizeof(header));
        const size_t recordsStart = sizeof(header);
        if (header.FuncOverrideSize > size - recordsStart)
        {
            return false;
        }

        const size_t recordsEnd = recordsStart + header.FuncOverrideSize;
        size_t cursor = recordsStart;
        std::vector<uint32_t> bddOffsets;
        while (cursor < recordsEnd)
        {
            if (recordsEnd - cursor < sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION))
            {
                return false;
            }

            IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION record = {};
            std::memcpy(&record, bytes + cursor, sizeof(record));
            if (record.OriginalRva >= sizeOfImage ||
                (record.RvaSize % sizeof(uint32_t)) != 0)
            {
                return false;
            }
            bddOffsets.push_back(record.BDDOffset);

            const uint64_t recordSize =
                static_cast<uint64_t>(sizeof(record)) +
                record.RvaSize +
                record.BaseRelocSize;
            if (recordSize > recordsEnd - cursor)
            {
                return false;
            }

            const size_t rvaOffset =
                cursor + sizeof(record);
            const size_t rvaCount =
                record.RvaSize / sizeof(uint32_t);
            for (size_t index = 0;
                 index < rvaCount;
                 ++index)
            {
                uint32_t overrideRva = 0;
                std::memcpy(
                    &overrideRva,
                    bytes +
                        rvaOffset +
                        index * sizeof(uint32_t),
                    sizeof(overrideRva));
                if (overrideRva >= sizeOfImage)
                {
                    return false;
                }
            }

            const size_t relocOffset =
                cursor + sizeof(record) + static_cast<size_t>(record.RvaSize);
            if (!ParseFunctionOverrideBaseRelocations(
                    bytes + relocOffset,
                    record.BaseRelocSize,
                    sizeOfImage,
                    ranges))
            {
                return false;
            }

            cursor += static_cast<size_t>(recordSize);
        }

        if (cursor != recordsEnd)
        {
            return false;
        }

        // The remaining payload is a sequence of BDD records. Each override
        // points at the IMAGE_BDD_INFO that selects its active RVA. Current
        // Windows images can contain several contiguous BDDs, so validate the
        // complete sequence instead of treating the whole region as one BDD.
        if (size - recordsEnd < sizeof(IMAGE_BDD_INFO))
        {
            return false;
        }

        const size_t bddRegionSize = size - recordsEnd;
        std::sort(bddOffsets.begin(), bddOffsets.end());
        bddOffsets.erase(
            std::unique(bddOffsets.begin(), bddOffsets.end()),
            bddOffsets.end());
        if (bddOffsets.empty() || bddOffsets.front() != 0)
        {
            return false;
        }

        size_t expectedOffset = 0;
        for (uint32_t offset : bddOffsets)
        {
            if (offset != expectedOffset ||
                offset > bddRegionSize - sizeof(IMAGE_BDD_INFO))
            {
                return false;
            }

            IMAGE_BDD_INFO bdd = {};
            std::memcpy(
                &bdd,
                bytes + recordsEnd + offset,
                sizeof(bdd));
            if (bdd.Version != 1 ||
                (bdd.BDDSize % sizeof(IMAGE_BDD_DYNAMIC_RELOCATION)) != 0 ||
                bdd.BDDSize >
                    bddRegionSize - offset - sizeof(IMAGE_BDD_INFO))
            {
                return false;
            }

            expectedOffset =
                static_cast<size_t>(offset) +
                sizeof(IMAGE_BDD_INFO) +
                bdd.BDDSize;
        }

        return expectedOffset == bddRegionSize;
    }

    bool ParseDynamicRelocationTable(
        const std::vector<uint8_t>& bytes,
        bool pe64,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (ranges == nullptr ||
            sizeOfImage == 0 ||
            bytes.size() < sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE))
        {
            return false;
        }

        std::vector<DiskPeMutableRange> parsedRanges;
        IMAGE_DYNAMIC_RELOCATION_TABLE table = {};
        std::memcpy(&table, bytes.data(), sizeof(table));
        if (table.Version != 1 ||
            table.Size != bytes.size() - sizeof(table))
        {
            return false;
        }

        const size_t tableEnd = sizeof(table) + table.Size;
        size_t cursor = sizeof(table);
        while (cursor < tableEnd)
        {
            const size_t entryHeaderSize =
                pe64 ? sizeof(IMAGE_DYNAMIC_RELOCATION64) : sizeof(IMAGE_DYNAMIC_RELOCATION32);
            if (tableEnd - cursor < entryHeaderSize)
            {
                return false;
            }

            uint64_t symbol = 0;
            uint32_t payloadSize = 0;
            if (pe64)
            {
                IMAGE_DYNAMIC_RELOCATION64 entry = {};
                std::memcpy(&entry, bytes.data() + cursor, sizeof(entry));
                symbol = entry.Symbol;
                payloadSize = entry.BaseRelocSize;
            }
            else
            {
                IMAGE_DYNAMIC_RELOCATION32 entry = {};
                std::memcpy(&entry, bytes.data() + cursor, sizeof(entry));
                symbol = entry.Symbol;
                payloadSize = entry.BaseRelocSize;
            }

            if (payloadSize > tableEnd - cursor - entryHeaderSize)
            {
                return false;
            }

            const uint8_t* payload = bytes.data() + cursor + entryHeaderSize;
            if (symbol != IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE ||
                !ParseFunctionOverrideDynamicRelocations(
                    payload,
                    payloadSize,
                    sizeOfImage,
                    &parsedRanges))
            {
                // Other DVRT symbol formats use different record layouts.
                // Unknown records make the deep comparison incomplete; they
                // must never become a clean result through broad masking.
                return false;
            }

            cursor += entryHeaderSize + payloadSize;
        }

        if (cursor != tableEnd)
        {
            return false;
        }

        std::sort(
            parsedRanges.begin(),
            parsedRanges.end(),
            [](const DiskPeMutableRange& left, const DiskPeMutableRange& right)
            {
                if (left.Rva != right.Rva)
                {
                    return left.Rva < right.Rva;
                }
                return left.Size < right.Size;
            });
        std::vector<DiskPeMutableRange> normalized;
        normalized.reserve(parsedRanges.size());
        for (const DiskPeMutableRange& range : parsedRanges)
        {
            const uint64_t rangeEnd = static_cast<uint64_t>(range.Rva) + range.Size;
            if (normalized.empty())
            {
                normalized.push_back(range);
                continue;
            }

            DiskPeMutableRange& previous = normalized.back();
            const uint64_t previousEnd =
                static_cast<uint64_t>(previous.Rva) + previous.Size;
            if (range.Rva <= previousEnd)
            {
                const uint64_t mergedEnd = std::max(previousEnd, rangeEnd);
                const uint64_t mergedSize = mergedEnd - previous.Rva;
                if (mergedSize > std::numeric_limits<uint32_t>::max())
                {
                    return false;
                }
                previous.Size = static_cast<uint32_t>(mergedSize);
            }
            else
            {
                normalized.push_back(range);
            }
        }
        *ranges = std::move(normalized);
        return true;
    }

    void PopulateDynamicRelocationRanges(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t loadConfigRva,
        uint32_t loadConfigSize,
        bool pe64)
    {
        if (file == INVALID_HANDLE_VALUE ||
            metadata == nullptr ||
            loadConfigRva == 0 ||
            loadConfigSize < sizeof(uint32_t))
        {
            return;
        }

        const size_t structureSize =
            pe64 ? sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) : sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32);
        const uint32_t bytesToRead =
            static_cast<uint32_t>(std::min<size_t>(loadConfigSize, structureSize));
        std::vector<uint8_t> loadConfig;
        if (!ReadDiskBytesForRva(file, *metadata, loadConfigRva, bytesToRead, &loadConfig) ||
            loadConfig.size() < sizeof(uint32_t))
        {
            metadata->DynamicRelocationTablePresent = true;
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        uint32_t declaredSize = 0;
        std::memcpy(&declaredSize, loadConfig.data(), sizeof(declaredSize));
        const size_t available = std::min<size_t>(loadConfig.size(), declaredSize);
        uint64_t tableVa = 0;
        uint32_t tableOffset = 0;
        uint16_t tableSection = 0;

        if (pe64)
        {
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTable) + sizeof(uint64_t))
            {
                std::memcpy(
                    &tableVa,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTable),
                    sizeof(tableVa));
            }
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection) + sizeof(uint16_t))
            {
                std::memcpy(
                    &tableOffset,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset),
                    sizeof(tableOffset));
                std::memcpy(
                    &tableSection,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection),
                    sizeof(tableSection));
            }
        }
        else
        {
            uint32_t tableVa32 = 0;
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTable) + sizeof(uint32_t))
            {
                std::memcpy(
                    &tableVa32,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTable),
                    sizeof(tableVa32));
                tableVa = tableVa32;
            }
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableSection) + sizeof(uint16_t))
            {
                std::memcpy(
                    &tableOffset,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableOffset),
                    sizeof(tableOffset));
                std::memcpy(
                    &tableSection,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableSection),
                    sizeof(tableSection));
            }
        }

        uint32_t tableRva = 0;
        bool located = false;
        if (tableVa != 0 &&
            metadata->ImageBase != 0 &&
            tableVa >= metadata->ImageBase &&
            tableVa - metadata->ImageBase <= std::numeric_limits<uint32_t>::max())
        {
            tableRva = static_cast<uint32_t>(tableVa - metadata->ImageBase);
            located = true;
        }
        else if (tableSection != 0 &&
                 tableSection <= metadata->Sections.size())
        {
            const DiskPeSection& section = metadata->Sections[tableSection - 1];
            const uint64_t candidate = static_cast<uint64_t>(section.VirtualAddress) + tableOffset;
            const uint64_t sectionSpan = std::max(section.VirtualSize, section.SizeOfRawData);
            if (tableOffset < sectionSpan &&
                candidate <= std::numeric_limits<uint32_t>::max())
            {
                tableRva = static_cast<uint32_t>(candidate);
                located = true;
            }
        }

        if (!located)
        {
            // An older load-config can legitimately predate DVRT fields.
            if (tableVa == 0 && tableOffset == 0 && tableSection == 0)
            {
                return;
            }

            metadata->DynamicRelocationTablePresent = true;
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        metadata->DynamicRelocationTablePresent = true;
        std::vector<uint8_t> tableHeader;
        if (!ReadDiskBytesForRva(
                file,
                *metadata,
                tableRva,
                sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE),
                &tableHeader) ||
            tableHeader.size() < sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE))
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        IMAGE_DYNAMIC_RELOCATION_TABLE table = {};
        std::memcpy(&table, tableHeader.data(), sizeof(table));
        constexpr uint32_t kMaxDynamicRelocationTableBytes = 16u * 1024u * 1024u;
        if (table.Size > kMaxDynamicRelocationTableBytes)
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        const uint64_t totalSize = static_cast<uint64_t>(sizeof(table)) + table.Size;
        if (totalSize > std::numeric_limits<uint32_t>::max())
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        std::vector<uint8_t> tableBytes;
        if (!ReadDiskBytesForRva(
                file,
                *metadata,
                tableRva,
                static_cast<uint32_t>(totalSize),
                &tableBytes) ||
            tableBytes.size() != totalSize ||
            !ParseDynamicRelocationTable(
                tableBytes,
                pe64,
                metadata->SizeOfImage,
                &metadata->DynamicRelocationRanges))
        {
            metadata->DynamicRelocationTableComplete = false;
            metadata->DynamicRelocationRanges.clear();
            return;
        }

        for (const DiskPeMutableRange& range : metadata->DynamicRelocationRanges)
        {
            const uint64_t rangeEnd = static_cast<uint64_t>(range.Rva) + range.Size;
            if (metadata->SizeOfImage == 0 || rangeEnd > metadata->SizeOfImage)
            {
                metadata->DynamicRelocationTableComplete = false;
                metadata->DynamicRelocationRanges.clear();
                return;
            }
        }
    }

    bool ReadDiskPeMetadata(const std::wstring& rawPath, DiskPeMetadata* metadata, std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (metadata == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid PE metadata output";
                }
                break;
            }

            *metadata = {};
            std::wstring path = NormalizeReferencePath(rawPath);
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }

            std::vector<uint8_t> header;
            if (!ReadFileBytesAt(file, 0, 0x1000, &header) || header.size() < sizeof(IMAGE_DOS_HEADER))
            {
                if (error != nullptr)
                {
                    *error = L"read disk image header failed";
                }
                break;
            }

            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, header.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE ||
                dos.e_lfanew <= 0)
            {
                if (error != nullptr)
                {
                    *error = L"disk image is not a PE file";
                }
                break;
            }
            metadata->HasFileIdentity =
                GetFileInformationByHandle(
                    file,
                    &metadata->FileIdentity) != FALSE;
            metadata->HasFileBasicIdentity =
                GetFileInformationByHandleEx(
                    file,
                    FileBasicInfo,
                    &metadata->FileBasicIdentity,
                    sizeof(metadata->FileBasicIdentity)) != FALSE;

            size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
            constexpr size_t kMaximumPeHeaderSpan =
                16u * 1024u * 1024u;
            const size_t minimumNtBytes =
                sizeof(uint32_t) +
                sizeof(IMAGE_FILE_HEADER);
            if (ntOffset >
                    kMaximumPeHeaderSpan -
                        minimumNtBytes)
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image NT header offset exceeds the parser cap";
                }
                break;
            }
            const size_t minimumNtEnd =
                ntOffset + minimumNtBytes;
            if (minimumNtEnd > header.size() &&
                (!ReadFileBytesAt(
                     file,
                     0,
                     static_cast<uint32_t>(minimumNtEnd),
                     &header) ||
                 header.size() < minimumNtEnd))
            {
                if (error != nullptr)
                {
                    *error =
                        L"read disk image NT header failed";
                }
                break;
            }

            uint32_t signature = 0;
            std::memcpy(&signature, header.data() + ntOffset, sizeof(signature));
            if (signature != IMAGE_NT_SIGNATURE)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid NT signature";
                }
                break;
            }

            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                header.data() + ntOffset + sizeof(uint32_t),
                sizeof(fileHeader));
            metadata->TimeDateStamp = fileHeader.TimeDateStamp;
            metadata->Machine = fileHeader.Machine;
            const uint16_t numberOfSections = fileHeader.NumberOfSections;
            const uint16_t optionalHeaderSize = fileHeader.SizeOfOptionalHeader;
            size_t optionalOffset = ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
            constexpr uint16_t kMaximumPeSectionCount = 96;
            if (optionalHeaderSize < sizeof(uint16_t) ||
                numberOfSections == 0 ||
                numberOfSections > kMaximumPeSectionCount)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid optional-header or section count";
                }
                break;
            }

            size_t sectionOffset = optionalOffset + optionalHeaderSize;
            size_t required = sectionOffset + static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (required > kMaximumPeHeaderSpan)
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image section table exceeds the parser cap";
                }
                break;
            }
            if (required > header.size())
            {
                if (!ReadFileBytesAt(file, 0, static_cast<uint32_t>(required), &header) || header.size() < required)
                {
                    if (error != nullptr)
                    {
                        *error = L"read disk image section table failed";
                    }
                    break;
                }
            }

            uint32_t relocRva = 0;
            uint32_t relocSize = 0;
            uint32_t loadConfigRva = 0;
            uint32_t loadConfigSize = 0;
            uint32_t debugRva = 0;
            uint32_t debugSize = 0;
            uint32_t managedRva = 0;
            uint32_t managedSize = 0;
            bool pe64 = false;
            uint16_t magic = 0;
            std::memcpy(&magic, header.data() + optionalOffset, sizeof(magic));
            metadata->OptionalMagic = magic;
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                constexpr size_t kPe64FixedOptionalBytes =
                    offsetof(
                        IMAGE_OPTIONAL_HEADER64,
                        DataDirectory);
                if (optionalHeaderSize <
                    kPe64FixedOptionalBytes)
                {
                    if (error != nullptr)
                    {
                        *error = L"truncated PE32+ optional header";
                    }
                    break;
                }

                pe64 = true;
                IMAGE_OPTIONAL_HEADER64 optional = {};
                std::memcpy(
                    &optional,
                    header.data() + optionalOffset,
                    std::min<size_t>(
                        optionalHeaderSize,
                        sizeof(optional)));
                const size_t availableDirectories =
                    (optionalHeaderSize -
                     kPe64FixedOptionalBytes) /
                        sizeof(IMAGE_DATA_DIRECTORY);
                if (optional.NumberOfRvaAndSizes >
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
                    optional.NumberOfRvaAndSizes >
                        availableDirectories)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"PE32+ data-directory count exceeds the declared optional header";
                    }
                    break;
                }

                metadata->ImageBase = optional.ImageBase;
                metadata->EntryPointRva = optional.AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional.SizeOfHeaders;
                metadata->SizeOfImage = optional.SizeOfImage;
                metadata->CheckSum = optional.CheckSum;
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
                {
                    debugRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    debugSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }
                AddLoaderMutableDirectoryRanges(
                    &metadata->LoaderMutableRanges,
                    optional.DataDirectory,
                    optional.NumberOfRvaAndSizes);
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                {
                    loadConfigRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                    loadConfigSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                {
                    const IMAGE_DATA_DIRECTORY& managed =
                        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
                    managedRva = managed.VirtualAddress;
                    managedSize = managed.Size;
                }
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                constexpr size_t kPe32FixedOptionalBytes =
                    offsetof(
                        IMAGE_OPTIONAL_HEADER32,
                        DataDirectory);
                if (optionalHeaderSize <
                    kPe32FixedOptionalBytes)
                {
                    if (error != nullptr)
                    {
                        *error = L"truncated PE32 optional header";
                    }
                    break;
                }

                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(
                    &optional,
                    header.data() + optionalOffset,
                    std::min<size_t>(
                        optionalHeaderSize,
                        sizeof(optional)));
                const size_t availableDirectories =
                    (optionalHeaderSize -
                     kPe32FixedOptionalBytes) /
                        sizeof(IMAGE_DATA_DIRECTORY);
                if (optional.NumberOfRvaAndSizes >
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
                    optional.NumberOfRvaAndSizes >
                        availableDirectories)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"PE32 data-directory count exceeds the declared optional header";
                    }
                    break;
                }

                metadata->ImageBase = optional.ImageBase;
                metadata->EntryPointRva = optional.AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional.SizeOfHeaders;
                metadata->SizeOfImage = optional.SizeOfImage;
                metadata->CheckSum = optional.CheckSum;
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
                {
                    debugRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    debugSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }
                AddLoaderMutableDirectoryRanges(
                    &metadata->LoaderMutableRanges,
                    optional.DataDirectory,
                    optional.NumberOfRvaAndSizes);
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                {
                    loadConfigRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                    loadConfigSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                {
                    const IMAGE_DATA_DIRECTORY& managed =
                        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
                    managedRva = managed.VirtualAddress;
                    managedSize = managed.Size;
                }
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"unsupported PE optional header magic";
                }
                break;
            }

            const uint64_t fileSize = (static_cast<uint64_t>(metadata->FileIdentity.nFileSizeHigh) << 32) |
                metadata->FileIdentity.nFileSizeLow;
            if (metadata->SizeOfImage == 0 ||
                metadata->SizeOfHeaders < sectionOffset + static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER) ||
                metadata->SizeOfHeaders > metadata->SizeOfImage ||
                (metadata->HasFileIdentity && metadata->SizeOfHeaders > fileSize) ||
                (metadata->EntryPointRva != 0 &&
                 metadata->EntryPointRva >= metadata->SizeOfImage))
            {
                if (error != nullptr)
                {
                    *error = L"PE image/header/entrypoint bounds are invalid";
                }
                break;
            }

            bool directoryRangesValid = true;
            for (const DiskPeMutableRange& range : metadata->LoaderMutableRanges)
            {
                if (range.Rva >= metadata->SizeOfImage ||
                    range.Size > metadata->SizeOfImage - range.Rva)
                {
                    directoryRangesValid = false;
                    break;
                }
            }
            if (!directoryRangesValid)
            {
                if (error != nullptr)
                {
                    *error = L"PE loader-mutable data directory is outside the image";
                }
                break;
            }

            metadata->HasEntryPoint = metadata->EntryPointRva != 0;

            bool sectionRangesValid = true;
            for (uint16_t index = 0; index < numberOfSections; ++index)
            {
                IMAGE_SECTION_HEADER rawSection = {};
                std::memcpy(
                    &rawSection,
                    header.data() + sectionOffset + static_cast<size_t>(index) * sizeof(rawSection),
                    sizeof(rawSection));
                DiskPeSection section = {};
                char sectionName[9] = {};
                std::memcpy(sectionName, rawSection.Name, IMAGE_SIZEOF_SHORT_NAME);
                std::string narrowName(sectionName);
                section.Name.assign(narrowName.begin(), narrowName.end());
                section.VirtualAddress = rawSection.VirtualAddress;
                section.VirtualSize = rawSection.Misc.VirtualSize;
                section.PointerToRawData = rawSection.PointerToRawData;
                section.SizeOfRawData = rawSection.SizeOfRawData;
                section.Characteristics = rawSection.Characteristics;
                section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.Writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                const uint64_t mappedSpan =
                    std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan != 0 &&
                    (section.VirtualAddress < metadata->SizeOfHeaders ||
                     section.VirtualAddress >= metadata->SizeOfImage ||
                     mappedSpan >
                         static_cast<uint64_t>(metadata->SizeOfImage) -
                             section.VirtualAddress))
                {
                    sectionRangesValid = false;
                    break;
                }
                if (section.SizeOfRawData != 0 &&
                    (section.PointerToRawData < metadata->SizeOfHeaders ||
                        (metadata->HasFileIdentity &&
                            static_cast<uint64_t>(section.PointerToRawData) + section.SizeOfRawData > fileSize)))
                {
                    sectionRangesValid = false;
                    break;
                }
                for (const auto& previous : metadata->Sections)
                {
                    const uint64_t previousSpan = std::max(previous.VirtualSize, previous.SizeOfRawData);
                    if (mappedSpan != 0 && previousSpan != 0 &&
                        section.VirtualAddress < static_cast<uint64_t>(previous.VirtualAddress) + previousSpan &&
                        previous.VirtualAddress < static_cast<uint64_t>(section.VirtualAddress) + mappedSpan)
                    {
                        sectionRangesValid = false;
                        break;
                    }
                }
                if (!sectionRangesValid)
                {
                    break;
                }
                metadata->Sections.push_back(section);

                if (!metadata->HasExecutableSection &&
                    section.Executable)
                {
                    metadata->FirstExecutableSectionRva = section.VirtualAddress;
                    metadata->HasExecutableSection = true;
                }
            }
            if (!sectionRangesValid)
            {
                if (error != nullptr)
                {
                    *error = L"PE section ranges overlap or exceed image/file bounds";
                }
                break;
            }

            if (debugSize != 0 && debugSize <= 1024 * sizeof(IMAGE_DEBUG_DIRECTORY) &&
                (debugSize % sizeof(IMAGE_DEBUG_DIRECTORY)) == 0)
            {
                std::vector<uint8_t> debug;
                if (ReadDiskBytesForRva(file, *metadata, debugRva, debugSize, &debug))
                {
                    for (size_t offset = 0; offset < debug.size(); offset += sizeof(IMAGE_DEBUG_DIRECTORY))
                    {
                        IMAGE_DEBUG_DIRECTORY entry = {};
                        std::memcpy(&entry, debug.data() + offset, sizeof(entry));
                        std::vector<uint8_t> codeview;
                        if (entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && entry.SizeOfData >= 24 &&
                            ReadDiskBytesForRva(file, *metadata, entry.AddressOfRawData, 24, &codeview) &&
                            std::memcmp(codeview.data(), "RSDS", 4) == 0)
                        {
                            metadata->PdbRva = entry.AddressOfRawData;
                            std::memcpy(&metadata->PdbGuid, codeview.data() + 4, sizeof(GUID));
                            std::memcpy(&metadata->PdbAge, codeview.data() + 20, 4);
                            metadata->HasPdbIdentity = true;
                            break;
                        }
                    }
                }
            }

            if (managedRva != 0 &&
                managedSize >= sizeof(IMAGE_COR20_HEADER) &&
                static_cast<uint64_t>(managedRva) + managedSize <= metadata->SizeOfImage)
            {
                std::vector<uint8_t> corHeaderBytes;
                if (ReadDiskBytesForRva(
                        file,
                        *metadata,
                        managedRva,
                        sizeof(IMAGE_COR20_HEADER),
                        &corHeaderBytes) &&
                    corHeaderBytes.size() >= sizeof(IMAGE_COR20_HEADER))
                {
                    IMAGE_COR20_HEADER corHeader = {};
                    std::memcpy(
                        &corHeader,
                        corHeaderBytes.data(),
                        sizeof(corHeader));
                    if (corHeader.cb >= sizeof(IMAGE_COR20_HEADER) &&
                        corHeader.cb <= managedSize &&
                        corHeader.MetaData.VirtualAddress != 0 &&
                        corHeader.MetaData.Size >= sizeof(uint32_t) &&
                        static_cast<uint64_t>(corHeader.MetaData.VirtualAddress) +
                                corHeader.MetaData.Size <=
                            metadata->SizeOfImage)
                    {
                        std::vector<uint8_t> metadataSignatureBytes;
                        uint32_t metadataSignature = 0;
                        if (ReadDiskBytesForRva(
                                file,
                                *metadata,
                                corHeader.MetaData.VirtualAddress,
                                sizeof(metadataSignature),
                                &metadataSignatureBytes) &&
                            metadataSignatureBytes.size() >= sizeof(metadataSignature))
                        {
                            std::memcpy(
                                &metadataSignature,
                                metadataSignatureBytes.data(),
                                sizeof(metadataSignature));
                            metadata->ManagedImage =
                                metadataSignature == 0x424a5342u;
                            metadata->ManagedIlOnly =
                                metadata->ManagedImage &&
                                (corHeader.Flags & kComImageFlagsIlOnly) != 0;
                        }
                    }
                }
            }

            metadata->BaserelocRva = relocRva;
            metadata->BaserelocSize = relocSize;
            PopulateRelocationPages(file, metadata, relocRva, relocSize);
            PopulateDynamicRelocationRanges(
                file,
                metadata,
                loadConfigRva,
                loadConfigSize,
                pe64);

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool DiskReferenceIdentityMatches(const std::wstring& rawPath, const DiskPeMetadata& metadata)
    {
        const std::wstring path = NormalizeReferencePath(rawPath);
        HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const bool matches = DiskFileIdentityMatches(file, metadata);
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
        return matches;
    }

    bool DiskFileIdentityMatches(
        HANDLE file,
        const DiskPeMetadata& metadata)
    {
        if (file == INVALID_HANDLE_VALUE ||
            !metadata.HasFileIdentity)
        {
            return false;
        }

        BY_HANDLE_FILE_INFORMATION current = {};
        if (!GetFileInformationByHandle(
                file,
                &current))
        {
            return false;
        }

        const BY_HANDLE_FILE_INFORMATION& expected =
            metadata.FileIdentity;
        bool matches =
            current.dwVolumeSerialNumber ==
                expected.dwVolumeSerialNumber &&
            current.nFileIndexHigh ==
                expected.nFileIndexHigh &&
            current.nFileIndexLow ==
                expected.nFileIndexLow &&
            current.nFileSizeHigh ==
                expected.nFileSizeHigh &&
            current.nFileSizeLow ==
                expected.nFileSizeLow &&
            current.ftCreationTime.dwHighDateTime ==
                expected.ftCreationTime.dwHighDateTime &&
            current.ftCreationTime.dwLowDateTime ==
                expected.ftCreationTime.dwLowDateTime &&
            current.ftLastWriteTime.dwHighDateTime ==
                expected.ftLastWriteTime.dwHighDateTime &&
            current.ftLastWriteTime.dwLowDateTime ==
                expected.ftLastWriteTime.dwLowDateTime;
        if (!matches ||
            !metadata.HasFileBasicIdentity)
        {
            return matches;
        }

        FILE_BASIC_INFO currentBasic = {};
        return GetFileInformationByHandleEx(
                   file,
                   FileBasicInfo,
                   &currentBasic,
                   sizeof(currentBasic)) != FALSE &&
            currentBasic.CreationTime.QuadPart ==
                metadata.FileBasicIdentity.CreationTime.QuadPart &&
            currentBasic.LastWriteTime.QuadPart ==
                metadata.FileBasicIdentity.LastWriteTime.QuadPart &&
            currentBasic.ChangeTime.QuadPart ==
                metadata.FileBasicIdentity.ChangeTime.QuadPart;
    }

    bool ApplyBaseRelocationsToDiskPage(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        uint64_t imageDelta,
        std::vector<uint8_t>* pageBytes,
        std::vector<uint8_t>* nextPageBytes)
    {
        if (pageBytes == nullptr ||
            pageBytes->size() < kPageSize ||
            !metadata.BaseRelocationTableComplete ||
            metadata.BaseRelocations.empty())
        {
            return false;
        }

        const uint64_t pageStart = pageRva;
        const uint64_t pageEnd = pageStart + pageBytes->size();
        auto first = std::lower_bound(
            metadata.BaseRelocations.begin(),
            metadata.BaseRelocations.end(),
            pageStart,
            [](const DiskPeBaseRelocation& relocation, uint64_t address)
            {
                return static_cast<uint64_t>(relocation.Rva) +
                    relocation.Width <= address;
            });

        for (auto current = first;
             current != metadata.BaseRelocations.end() &&
                 current->Rva < pageEnd;
             ++current)
        {
            const uint64_t fixupStart = current->Rva;
            const uint64_t fixupEnd = fixupStart + current->Width;
            if (fixupEnd <= pageStart)
            {
                continue;
            }

            // A relocation beginning on the preceding page is masked at its
            // exact byte range after normalization; the preceding bytes are
            // not available here to reconstruct its full integer value.
            if (fixupStart < pageStart)
            {
                continue;
            }

            const size_t pageOffset =
                static_cast<size_t>(fixupStart - pageStart);
            if (pageOffset + current->Width <= pageBytes->size())
            {
                uint64_t value = 0;
                std::memcpy(
                    &value,
                    pageBytes->data() + pageOffset,
                    current->Width);
                value += imageDelta;
                std::memcpy(
                    pageBytes->data() + pageOffset,
                    &value,
                    current->Width);
                continue;
            }

            const size_t firstBytes = pageBytes->size() - pageOffset;
            const size_t secondBytes = current->Width - firstBytes;
            if (nextPageBytes == nullptr ||
                nextPageBytes->size() < secondBytes)
            {
                return false;
            }

            uint8_t raw[8] = {};
            std::memcpy(
                raw,
                pageBytes->data() + pageOffset,
                firstBytes);
            std::memcpy(
                raw + firstBytes,
                nextPageBytes->data(),
                secondBytes);
            uint64_t value = 0;
            std::memcpy(&value, raw, current->Width);
            value += imageDelta;
            std::memcpy(raw, &value, current->Width);
            std::memcpy(
                pageBytes->data() + pageOffset,
                raw,
                firstBytes);
            std::memcpy(
                nextPageBytes->data(),
                raw + firstBytes,
                secondBytes);
        }

        return true;
    }

    bool CopyRawBytesIntoMappedPage(
        HANDLE file,
        uint64_t rawOffset,
        uint64_t pageOffset,
        uint64_t length,
        std::vector<uint8_t>* page)
    {
        bool ok = false;

        do
        {
            if (page == nullptr || page->size() != kPageSize || pageOffset >= kPageSize)
            {
                break;
            }

            uint64_t cappedLength = length;
            if (pageOffset + cappedLength > kPageSize)
            {
                cappedLength = kPageSize - pageOffset;
            }

            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadFileBytesAt(file, rawOffset, static_cast<uint32_t>(cappedLength), &bytes))
            {
                break;
            }

            if (bytes.size() != cappedLength)
            {
                break;
            }

            std::copy(
                bytes.begin(),
                bytes.end(),
                page->begin() + static_cast<std::ptrdiff_t>(pageOffset));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadDiskPageForRva(
        const std::wstring& rawPath,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        std::vector<uint8_t>* page,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (page == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid disk page output";
                }
                break;
            }

            uint32_t pageRva = rva & 0xfffff000u;
            uint64_t pageStart = pageRva;
            uint64_t pageEnd = pageStart + kPageSize;
            bool mapped = false;
            bool copied = true;
            page->assign(static_cast<size_t>(kPageSize), 0);

            std::wstring path = NormalizeReferencePath(rawPath);
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_RANDOM_ACCESS,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }
            if (!DiskFileIdentityMatches(
                    file,
                    metadata))
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image changed after PE metadata capture";
                }
                break;
            }

            if (metadata.SizeOfHeaders != 0 && pageStart < metadata.SizeOfHeaders)
            {
                uint64_t copyEnd = metadata.SizeOfHeaders;
                if (copyEnd > pageEnd)
                {
                    copyEnd = pageEnd;
                }

                if (copyEnd > pageStart)
                {
                    mapped = true;
                    copied = CopyRawBytesIntoMappedPage(file, pageStart, 0, copyEnd - pageStart, page) && copied;
                }
            }

            for (const DiskPeSection& section : metadata.Sections)
            {
                uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan == 0)
                {
                    continue;
                }

                uint64_t sectionStart = section.VirtualAddress;
                uint64_t sectionEnd = sectionStart + mappedSpan;
                if (sectionEnd < sectionStart)
                {
                    continue;
                }

                uint64_t overlapStart = pageStart > sectionStart ? pageStart : sectionStart;
                uint64_t overlapEnd = pageEnd < sectionEnd ? pageEnd : sectionEnd;
                if (overlapEnd <= overlapStart)
                {
                    continue;
                }

                mapped = true;

                uint64_t rawSpan = section.SizeOfRawData;
                if (rawSpan > mappedSpan)
                {
                    rawSpan = mappedSpan;
                }

                uint64_t rawEnd = sectionStart + rawSpan;
                if (rawEnd < sectionStart || overlapStart >= rawEnd)
                {
                    continue;
                }

                uint64_t rawCopyEnd = overlapEnd < rawEnd ? overlapEnd : rawEnd;
                if (rawCopyEnd <= overlapStart)
                {
                    continue;
                }

                uint64_t rawOffset = static_cast<uint64_t>(section.PointerToRawData) + (overlapStart - sectionStart);
                uint64_t mappedOffset = overlapStart - pageStart;
                copied = CopyRawBytesIntoMappedPage(file, rawOffset, mappedOffset, rawCopyEnd - overlapStart, page) && copied;
            }

            if (!mapped)
            {
                if (error != nullptr)
                {
                    *error = L"RVA has no disk mapping";
                }
                break;
            }

            if (!copied)
            {
                if (error != nullptr)
                {
                    *error = L"read mapped disk image page failed";
                }
                break;
            }

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

}
