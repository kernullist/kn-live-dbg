#pragma once

#include "ExecutableImageVerifier.h"

#include <cstring>
#include <utility>

// These records describe references, not observed callback execution.
struct ExecutionSurfaceEntry
{
    uint32_t Index = 0;
    uint64_t Slot = 0;
    uint64_t Target = 0;
};

struct ExecutionSurfaceTable
{
    uint64_t ImageBase = 0;
    uint64_t RootSlot = 0;
    uint64_t Table = 0;
    uint32_t DirectoryRva = 0;
    uint32_t DirectorySize = 0;
    uint32_t PointerSize = 0;
    bool Present = false;
    bool Complete = false;
    bool Stable = false;
    std::wstring Status = L"unavailable";
    std::vector<ExecutionSurfaceEntry> Entries;
    std::vector<ObservationAnchor> Anchors;
};

namespace execution_surface
{
    inline bool UserRange(uint64_t address, size_t size, uint32_t width = 8)
    {
        const uint64_t end = width == 4 ? 0x100000000ull : 0x0000800000000000ull;
        return (width == 4 || width == 8) && address >= 0x10000 &&
            address < end && size != 0 && size <= end - address;
    }

    class ReadSet
    {
    public:
        explicit ReadSet(const ObservationReader& reader) : Reader(reader)
        {
        }

        bool Read(uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (!Reader || !UserRange(address, size) || size > 4096 || Reads.size() >= 520 ||
                !Reader(address, size, bytes) || bytes->size() != size)
            {
                return false;
            }
            Reads.push_back({address, *bytes});
            return true;
        }

        bool Pointer(uint64_t address, uint32_t width, uint64_t* value)
        {
            *value = 0;
            std::vector<uint8_t> bytes;
            if (!UserRange(address, width, width) || !Read(address, width, &bytes))
            {
                return false;
            }
            std::memcpy(value, bytes.data(), width);
            return true;
        }

        bool Stable() const
        {
            if (Reads.empty())
            {
                return false;
            }
            for (const auto& item : Reads)
            {
                std::vector<uint8_t> bytes;
                if (!Reader(item.Address, item.Bytes.size(), &bytes) || bytes != item.Bytes)
                {
                    return false;
                }
            }
            return true;
        }

        const std::vector<ObservationAnchor>& Captured() const
        {
            return Reads;
        }

    private:
        const ObservationReader& Reader;
        std::vector<ObservationAnchor> Reads;
    };

    inline ExecutionSurfaceTable Tls(uint64_t base, uint32_t mappedSize,
        const ObservationReader& reader, size_t limit = 64)
    {
        ExecutionSurfaceTable result;
        result.ImageBase = base;
        ReadSet reads(reader);
        do
        {
            if (limit == 0 || limit > 256 || mappedSize < sizeof(IMAGE_DOS_HEADER) || !UserRange(base, mappedSize))
            {
                result.Status = L"invalid_image_range_or_budget";
                break;
            }
            std::vector<uint8_t> bytes;
            IMAGE_DOS_HEADER dos = {};
            if (!reads.Read(base, sizeof(dos), &bytes))
            {
                break;
            }
            std::memcpy(&dos, bytes.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
                static_cast<uint32_t>(dos.e_lfanew) > mappedSize - (std::min<uint32_t>)(mappedSize, 24) ||
                dos.e_lfanew > 1024 * 1024)
            {
                result.Status = L"invalid_dos_header";
                break;
            }
            const uint64_t nt = base + static_cast<uint32_t>(dos.e_lfanew);
            if (!reads.Read(nt, 24, &bytes))
            {
                break;
            }
            uint32_t signature = 0;
            IMAGE_FILE_HEADER file = {};
            std::memcpy(&signature, bytes.data(), 4);
            std::memcpy(&file, bytes.data() + 4, sizeof(file));
            if (signature != IMAGE_NT_SIGNATURE || file.SizeOfOptionalHeader < 96 ||
                file.SizeOfOptionalHeader > 4096 || nt + 24 - base > mappedSize ||
                file.SizeOfOptionalHeader > mappedSize - (nt + 24 - base))
            {
                result.Status = L"invalid_nt_header";
                break;
            }
            if (!reads.Read(nt + 24, file.SizeOfOptionalHeader, &bytes))
            {
                break;
            }
            uint16_t magic = 0;
            uint32_t imageSize = 0;
            std::memcpy(&magic, bytes.data(), 2);
            std::memcpy(&imageSize, bytes.data() + 56, 4);
            const bool pe32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && file.Machine == IMAGE_FILE_MACHINE_I386;
            const bool pe64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && file.Machine == IMAGE_FILE_MACHINE_AMD64;
            result.PointerSize = pe32 ? 4 : (pe64 ? 8 : 0);
            const size_t directoryOffset = pe32 ? 96 : 112;
            if (result.PointerSize == 0 || bytes.size() < directoryOffset || imageSize == 0 ||
                imageSize > mappedSize || !UserRange(base, imageSize, result.PointerSize) ||
                nt + 24 + bytes.size() - base > imageSize)
            {
                result.Status = L"unsupported_or_invalid_optional_header";
                break;
            }
            uint32_t directories = 0;
            std::memcpy(&directories, bytes.data() + directoryOffset - 4, 4);
            if (directories > (bytes.size() - directoryOffset) / 8)
            {
                result.Status = L"directory_count_exceeds_optional_header";
                break;
            }
            if (directories <= IMAGE_DIRECTORY_ENTRY_TLS)
            {
                result.Complete = true;
                result.Status = L"absent";
                break;
            }
            const size_t tlsOffset = directoryOffset + IMAGE_DIRECTORY_ENTRY_TLS * 8;
            if (bytes.size() < tlsOffset + 8)
            {
                result.Status = L"truncated_tls_directory_entry";
                break;
            }
            std::memcpy(&result.DirectoryRva, bytes.data() + tlsOffset, 4);
            std::memcpy(&result.DirectorySize, bytes.data() + tlsOffset + 4, 4);
            if (result.DirectoryRva == 0 && result.DirectorySize == 0)
            {
                result.Complete = true;
                result.Status = L"absent";
                break;
            }
            result.Present = true;
            const uint32_t tlsSize = pe32 ? 24 : 40;
            if (result.DirectoryRva == 0 || result.DirectorySize < tlsSize || result.DirectoryRva >= imageSize ||
                result.DirectorySize > imageSize - result.DirectoryRva)
            {
                result.Status = L"invalid_tls_directory_range";
                break;
            }
            result.RootSlot = base + result.DirectoryRva + (pe32 ? 12 : 24);
            if (!reads.Read(base + result.DirectoryRva, tlsSize, &bytes))
            {
                result.Status = L"tls_directory_unreadable";
                break;
            }
            std::memcpy(&result.Table, bytes.data() + (pe32 ? 12 : 24), result.PointerSize);
            result.Anchors = reads.Captured();
            if (result.Table == 0)
            {
                result.Complete = true;
                result.Status = L"empty";
                break;
            }
            result.Status = L"callback_budget_reached";
            ObservationAnchor prefix;
            prefix.Address = result.Table;
            for (size_t i = 0; i <= limit; ++i)
            {
                if (!UserRange(result.Table, (i + 1) * result.PointerSize, result.PointerSize))
                {
                    result.Status = L"invalid_callback_table_range";
                    break;
                }
                const uint64_t slot = result.Table + i * result.PointerSize;
                uint64_t target = 0;
                if (!reads.Pointer(slot, result.PointerSize, &target))
                {
                    result.Status = L"callback_slot_unreadable";
                    break;
                }
                const size_t previousSize = prefix.Bytes.size();
                prefix.Bytes.resize(previousSize + result.PointerSize);
                std::memcpy(prefix.Bytes.data() + previousSize, &target, result.PointerSize);
                if (target == 0)
                {
                    result.Complete = true;
                    result.Status = L"enumerated";
                    break;
                }
                if (i == limit)
                {
                    break;
                }
                // Preserve invalid targets as evidence; consumers must validate before decoding.
                result.Entries.push_back({static_cast<uint32_t>(i), slot, target});
            }
            if (!prefix.Bytes.empty())
            {
                // Earlier NULL slots determine whether a later callback is still registered.
                result.Anchors.push_back(std::move(prefix));
            }
        }
        while (false);
        result.Stable = reads.Stable();
        if (!result.Stable && !result.Entries.empty())
        {
            result.Status = L"changed_or_unreadable_on_recheck";
        }
        return result;
    }

    inline ExecutionSurfaceTable KernelCallbacks(uint64_t rootSlot, const ObservationReader& reader, size_t limit = 64)
    {
        ExecutionSurfaceTable result;
        result.RootSlot = rootSlot;
        result.PointerSize = 8;
        ReadSet reads(reader);
        do
        {
            if (limit == 0 || limit > 256 || !reads.Pointer(rootSlot, 8, &result.Table))
            {
                result.Status = L"root_unreadable_or_invalid_budget";
                break;
            }
            result.Present = result.Table != 0;
            result.Anchors = reads.Captured();
            if (!result.Present)
            {
                result.Complete = true;
                result.Status = L"null_root";
                break;
            }
            result.Status = L"bounded_prefix_extent_unknown";
            for (size_t i = 0; i < limit; ++i)
            {
                if (!UserRange(result.Table, (i + 1) * 8))
                {
                    result.Status = L"invalid_table_range";
                    break;
                }
                uint64_t target = 0;
                const uint64_t slot = result.Table + i * 8;
                if (!reads.Pointer(slot, 8, &target))
                {
                    result.Status = L"prefix_unreadable";
                    break;
                }
                // Unlike TLS, this table has no qualified null-terminator contract.
                result.Entries.push_back({static_cast<uint32_t>(i), slot, target});
            }
        }
        while (false);
        result.Stable = reads.Stable();
        if (!result.Stable)
        {
            result.Status = L"changed_or_unreadable_on_recheck";
        }
        return result;
    }

    inline const wchar_t* CompareTls(const ExecutionSurfaceTable& live, const ExecutionSurfaceTable& baseline)
    {
        if (!live.Complete || !live.Stable || !baseline.Complete || !baseline.Stable ||
            live.ImageBase != baseline.ImageBase || live.PointerSize != baseline.PointerSize)
        {
            return L"unverified";
        }
        bool equal = live.Present == baseline.Present && live.DirectoryRva == baseline.DirectoryRva &&
            live.DirectorySize == baseline.DirectorySize && live.Table == baseline.Table &&
            live.Entries.size() == baseline.Entries.size();
        for (size_t i = 0; equal && i < live.Entries.size(); ++i)
        {
            equal = live.Entries[i].Target == baseline.Entries[i].Target;
        }
        return equal ? L"match" : L"mismatch";
    }
}
