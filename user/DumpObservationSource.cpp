#include "DumpObservationSource.h"
#include "MemoryDumper.h"
#include "KnLiveDbgPaging.h"

#include <Windows.h>
#include <mindumpdef.h>
#include <cstring>
#include <mutex>

namespace
{
    constexpr uint64_t PhysicalMask = 0x000ffffffffff000ull;
    constexpr uint64_t PageBytes = 4096;

    struct Run
    {
        uint64_t Base = 0;
        uint64_t Bytes = 0;
        uint64_t Offset = 0;
    };

    class DumpFile
    {
    public:
        ~DumpFile()
        {
            if (Handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Handle);
            }
        }

        bool Open(const std::wstring& path)
        {
            if (path.empty() || path.size() > 30000 || path.find(L'\0') != std::wstring::npos)
            {
                return false;
            }
            std::wstring folded = path;
            for (auto& c : folded)
            {
                if (c >= L'a' && c <= L'z')
                {
                    c -= L'a' - L'A';
                }
            }
            if (folded.rfind(L"\\\\.\\", 0) == 0 || folded.rfind(L"\\\\?\\GLOBALROOT", 0) == 0)
            {
                return false;
            }
            Handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (Handle == INVALID_HANDLE_VALUE || GetFileType(Handle) != FILE_TYPE_DISK ||
                !GetFileInformationByHandle(Handle, &Identity) ||
                (Identity.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            {
                return false;
            }
            Size = (uint64_t(Identity.nFileSizeHigh) << 32) | Identity.nFileSizeLow;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
            {
                return false;
            }
            static std::atomic<uint64_t> serial{0};
            Id = L"dump_handle:" + std::to_wstring(GetCurrentProcessId()) + L":" +
                std::to_wstring((uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime) + L":" +
                std::to_wstring(++serial);
            return true;
        }

        bool Unchanged() const
        {
            BY_HANDLE_FILE_INFORMATION now{};
            return GetFileInformationByHandle(Handle, &now) && now.dwVolumeSerialNumber == Identity.dwVolumeSerialNumber &&
                now.nFileIndexHigh == Identity.nFileIndexHigh && now.nFileIndexLow == Identity.nFileIndexLow &&
                now.nFileSizeHigh == Identity.nFileSizeHigh && now.nFileSizeLow == Identity.nFileSizeLow &&
                CompareFileTime(&now.ftLastWriteTime, &Identity.ftLastWriteTime) == 0;
        }

        ObservationReadState Read(uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes)
        {
            bytes->clear();
            std::lock_guard<std::mutex> lock(Mutex);
            if (!Unchanged())
            {
                return ObservationReadState::IdentityChanged;
            }
            if (length == 0 || offset > Size || length > Size - offset || offset > INT64_MAX)
            {
                return ObservationReadState::NotCaptured;
            }
            LARGE_INTEGER position{};
            position.QuadPart = static_cast<LONGLONG>(offset);
            DWORD copied = 0;
            bytes->resize(length);
            const bool read = SetFilePointerEx(Handle, position, nullptr, FILE_BEGIN) &&
                ReadFile(Handle, bytes->data(), length, &copied, nullptr) && copied == length;
            const bool same = Unchanged();
            if (!read || !same)
            {
                bytes->clear();
                return same ? ObservationReadState::Failed : ObservationReadState::IdentityChanged;
            }
            return ObservationReadState::Complete;
        }

        ObservationReadState Physical(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes)
        {
            bytes->clear();
            if (!Unchanged())
            {
                return ObservationReadState::IdentityChanged;
            }
            for (const auto& run : Runs)
            {
                if (address >= run.Base && address - run.Base < run.Bytes && length <= run.Bytes - (address - run.Base))
                {
                    return Read(run.Offset + address - run.Base, length, bytes);
                }
            }
            return Unchanged() ? ObservationReadState::NotCaptured : ObservationReadState::IdentityChanged;
        }

        uint64_t Size = 0;
        std::wstring Id;
        std::vector<Run> Runs;

    private:
        HANDLE Handle = INVALID_HANDLE_VALUE;
        BY_HANDLE_FILE_INFORMATION Identity{};
        std::mutex Mutex;
    };

    bool Probe(DumpObservationSource& source, uint64_t list)
    {
        if (!source.Capabilities().AddressSpace.KernelRange(list, 16) || (list & 7) != 0)
        {
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!ReadObservationExact(source, list, 16, &bytes))
        {
            return false;
        }
        uint64_t first = 0, last = 0;
        std::memcpy(&first, bytes.data(), 8);
        std::memcpy(&last, bytes.data() + 8, 8);
        if ((first & 7) != 0 || (last & 7) != 0 ||
            !source.Capabilities().AddressSpace.KernelRange(first, 16) ||
            !source.Capabilities().AddressSpace.KernelRange(last, 16))
        {
            return false;
        }
        if (!ReadObservationExact(source, first + 8, 8, &bytes))
        {
            return false;
        }
        uint64_t back = 0;
        std::memcpy(&back, bytes.data(), 8);
        if (back != list || !ReadObservationExact(source, last, 8, &bytes))
        {
            return false;
        }
        std::memcpy(&back, bytes.data(), 8);
        return back == list;
    }
}

DumpAddressTranslation TranslateDumpAddress(const DumpPhysicalReader& reader,
    uint64_t root, uint32_t pagingLevels, uint64_t address)
{
    DumpAddressTranslation result;
    const auto space = AddressSpaceDescriptor::FromPagingLevels(pagingLevels);
    if (!reader || !space.Canonical(address) ||
        (root & PhysicalMask) == 0 || (root & ~(PhysicalMask | 0xfffull)) != 0)
    {
        return result;
    }
    uint64_t table = root & PhysicalMask;
    for (uint32_t level = pagingLevels; level != 0; --level)
    {
        const uint32_t shift = 12 + 9 * (level - 1);
        const uint64_t index = (address >> shift) & 511;
        std::vector<uint8_t> bytes;
        result.State = reader(table + index * 8, 8, &bytes);
        if (result.State != ObservationReadState::Complete || bytes.size() != 8)
        {
            if (result.State == ObservationReadState::Complete)
            {
                result.State = ObservationReadState::Failed;
            }
            return result;
        }
        uint64_t entry = 0;
        std::memcpy(&entry, bytes.data(), 8);
        if ((entry & 1) == 0)
        {
            result.State = ObservationReadState::NotPresent;
            return result;
        }
        if (!KnDbgPresentPagingEntryValid(entry, level))
        {
            result.State = ObservationReadState::Unsupported;
            return result;
        }
        const bool leaf = level == 1 || ((level == 2 || level == 3) && (entry & 0x80) != 0);
        if (leaf)
        {
            result.MappingBytes = uint64_t(1) << shift;
            result.PhysicalAddress = (entry & PhysicalMask & ~(result.MappingBytes - 1)) + (address & (result.MappingBytes - 1));
            return result;
        }
        table = entry & PhysicalMask;
        if (table == 0)
        {
            result.State = ObservationReadState::Unsupported;
            return result;
        }
    }
    result.State = ObservationReadState::Unsupported;
    return result;
}

DumpObservationSource::DumpObservationSource(std::wstring sourceId, uint64_t root, uint32_t pagingLevels,
    DumpPhysicalReader reader) : Root(root), PagingLevels(pagingLevels), Reader(std::move(reader))
{
    Caps.SourceId = std::move(sourceId);
    Caps.Consistency = L"offline_dump";
    Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(pagingLevels);
    if ((pagingLevels != 4 && pagingLevels != 5) || !Reader)
    {
        Caps.SourceId.clear();
    }
}

const ObservationSourceCapabilities& DumpObservationSource::Capabilities() const
{
    return Caps;
}

ObservationReadResult DumpObservationSource::ReadSpans(const ObservationReadRequest& request)
{
    ObservationReadResult result;
    uint32_t done = 0;
    while (done < request.Length)
    {
        ObservationReadSpan span;
        span.Address = request.Address + done;
        span.RequestedBytes = (std::min)(request.Length - done, uint32_t(PageBytes - (span.Address & (PageBytes - 1))));
        if (request.Cancellation != nullptr && request.Cancellation->load())
        {
            span.State = ObservationReadState::Cancelled;
        }
        else
        {
            const auto translation = TranslateDumpAddress(Reader, Root, PagingLevels, span.Address);
            span.State = translation.State;
            if (span.State == ObservationReadState::Complete)
            {
                span.State = Reader(translation.PhysicalAddress, span.RequestedBytes, &span.Bytes);
            }
        }
        if (span.State != ObservationReadState::Complete)
        {
            span.Bytes.clear();
        }
        if (span.State == ObservationReadState::IdentityChanged)
        {
            result.Spans.clear();
            result.Spans.push_back({request.Address, request.Length, ObservationReadState::IdentityChanged, {}});
            return result;
        }
        done += span.RequestedBytes;
        result.Spans.push_back(std::move(span));
    }
    return result;
}

std::unique_ptr<IObservationSource> OpenDumpObservationSource(const std::wstring& path, std::wstring* error)
{
    std::wstring ignored;
    if (error == nullptr)
    {
        error = &ignored;
    }
    *error = L"unsupported or inaccessible dump file";
    auto file = std::make_shared<DumpFile>();
    std::vector<uint8_t> bytes;
    if (!file->Open(path) || file->Read(0, kCrashDumpHeaderBytes, &bytes) != ObservationReadState::Complete)
    {
        return {};
    }
    DUMP_HEADER64 header{};
    static_assert(sizeof(header) == kCrashDumpHeaderBytes, "dump header size");
    std::memcpy(&header, bytes.data(), sizeof(header));
    const auto& block = header.PhysicalMemoryBlock;
    if (header.Signature != DUMP_SIGNATURE64 || header.ValidDump != DUMP_VALID_DUMP64 ||
        header.MachineImageType != IMAGE_FILE_MACHINE_AMD64 || header.DumpType != DUMP_TYPE_FULL ||
        block.NumberOfRuns == 0 || block.NumberOfRuns > kCrashDumpMaxPhysicalRuns ||
        (header.DirectoryTableBase & PhysicalMask) == 0 || (header.DirectoryTableBase & ~(PhysicalMask | 0xfffull)) != 0)
    {
        return {};
    }
    uint64_t offset = kCrashDumpHeaderBytes, pages = 0;
    for (uint32_t i = 0; i < block.NumberOfRuns; ++i)
    {
        const auto& item = block.Run[i];
        if (item.PageCount == 0 || item.BasePage > (PhysicalMask >> 12) ||
            item.PageCount > (1ull << 40) - item.BasePage || item.PageCount > (file->Size - offset) / PageBytes)
        {
            *error = L"invalid, overlapping or truncated physical runs";
            return {};
        }
        const Run run{item.BasePage * PageBytes, item.PageCount * PageBytes, offset};
        for (const auto& prior : file->Runs)
        {
            if (run.Base < prior.Base + prior.Bytes && prior.Base < run.Base + run.Bytes)
            {
                *error = L"invalid, overlapping or truncated physical runs";
                return {};
            }
        }
        pages += item.PageCount;
        offset += run.Bytes;
        file->Runs.push_back(run);
    }
    if (pages != block.NumberOfPages)
    {
        *error = L"physical page count disagrees with run inventory";
        return {};
    }
    const DumpPhysicalReader reader = [file](uint64_t address, uint32_t length, std::vector<uint8_t>* out)
    {
        return file->Physical(address, length, out);
    };
    DumpObservationSource four(file->Id + L":probe4", header.DirectoryTableBase, 4, reader);
    DumpObservationSource five(file->Id + L":probe5", header.DirectoryTableBase, 5, reader);
    const bool probe4 = Probe(four, header.PsLoadedModuleList);
    const bool probe5 = Probe(five, header.PsLoadedModuleList);
    uint64_t cr3 = 0, cr4 = 0;
    if (header.KdSecondaryVersion == 2)
    {
        std::memcpy(&cr3, header.ContextRecord + 0x4d0 + 0x10, 8);
        std::memcpy(&cr4, header.ContextRecord + 0x4d0 + 0x18, 8);
    }
    const bool validCr4 = (cr4 & (1ull << 5)) != 0 && (cr4 >> 32) == 0;
    if (validCr4 && (cr3 & PhysicalMask) != 0 && (cr3 & PhysicalMask) != (header.DirectoryTableBase & PhysicalMask))
    {
        *error = L"dump CR3 disagrees with the declared address space";
        return {};
    }
    uint32_t levels = 0;
    if (validCr4)
    {
        levels = (cr4 & (1ull << 12)) != 0 ? 5 : 4;
        if ((levels == 4 && !probe4 && probe5) || (levels == 5 && !probe5 && probe4))
        {
            *error = L"dump CR4 disagrees with the captured page-table probe";
            return {};
        }
    }
    else if (probe4 != probe5)
    {
        levels = probe5 ? 5 : 4;
    }
    if (levels == 0 || !file->Unchanged())
    {
        *error = L"dump paging depth is unavailable, ambiguous or changed";
        return {};
    }
    error->clear();
    return std::make_unique<DumpObservationSource>(file->Id, header.DirectoryTableBase, levels, reader);
}
