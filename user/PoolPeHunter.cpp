#include "PoolPeHunter.h"
#include "LeftoverCommon.h"
#include "McpJson.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>
#include <iomanip>
#include <cstdio>

constexpr ULONG kSystemBigPoolInformation = 0x42;
constexpr ULONG kInitialQueryBytes = 0x10000;
constexpr ULONG kMaxQueryBytes     = 0x4000000;
constexpr ULONG kMaxQueryRetries   = 16;
constexpr uint32_t kHeadBytesToRead = 0x1000;   // 4 KB head sample for PE probe

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#endif

namespace
{
    typedef LONG NTSTATUS_LOCAL;

    typedef NTSTATUS_LOCAL (NTAPI* PfnNtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

#pragma pack(push, 8)
    typedef struct _SYSTEM_BIGPOOL_ENTRY_LOCAL
    {
        union
        {
            PVOID VirtualAddress;
            ULONG_PTR NonPaged : 1;
        };
        SIZE_T SizeInBytes;
        union
        {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
    } SYSTEM_BIGPOOL_ENTRY_LOCAL;

    typedef struct _SYSTEM_BIGPOOL_INFORMATION_LOCAL
    {
        ULONG Count;
        SYSTEM_BIGPOOL_ENTRY_LOCAL Entries[1];
    } SYSTEM_BIGPOOL_INFORMATION_LOCAL;
#pragma pack(pop)

    bool ValidatePoolPeEntries(const SYSTEM_BIGPOOL_ENTRY_LOCAL* entries, uint32_t count)
    {
        if (entries == nullptr && count != 0)
        {
            return false;
        }
        for (uint32_t index = 0; index < count; ++index)
        {
            const uint64_t address = reinterpret_cast<uint64_t>(entries[index].VirtualAddress) & ~1ull;
            if (!LeftoverValidateBigPoolRange(address, entries[index].SizeInBytes))
            {
                return false;
            }
        }
        return true;
    }

    bool PoolPeAddressExcluded(
        uint64_t address,
        const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
    {
        for (const auto& range : ranges)
        {
            if (address >= range.first && address < range.second)
            {
                return true;
            }
        }
        return false;
    }

    uint64_t PoolPePageOffset(uint64_t size, uint64_t round)
    {
        const uint64_t pages = size / kHeadBytesToRead + (size % kHeadBytesToRead != 0 ? 1 : 0);
        return pages == 0 ? 0 : (round % pages) * kHeadBytesToRead;
    }

    bool ProbePoolPeSample(const uint8_t* bytes, size_t length, uint64_t remaining, PeHeaderProbe* probe)
    {
        return ProbeForPeHeader(bytes, length, probe) && PeProbeLooksLikeImage(*probe, remaining);
    }

    class PoolPeEntryWindow
    {
    public:
        PoolPeEntryWindow(uint32_t count, const PoolPeHunter::Options& options) :
            Total(count),
            Next(options.ContinueScan && options.EntryOffset < count
                ? static_cast<uint32_t>(options.EntryOffset) : 0),
            Budget(count - Next),
            HitLimit(options.LimitHits),
            Bounded(options.ContinueScan)
        {
            if (Bounded && options.MaxEntries != 0)
            {
                Budget = (std::min)(Budget, options.MaxEntries);
            }
        }

        bool Take(size_t retainedHits, uint32_t* index)
        {
            bool selected = false;
            if (index != nullptr && Next < Total && Visited < Budget)
            {
                if (Bounded && HitLimit != 0 && retainedHits >= HitLimit)
                {
                    HitLimited = true;
                }
                else
                {
                    *index = Next++;
                    ++Visited;
                    selected = true;
                }
            }
            return selected;
        }

        uint64_t NextOffset() const
        {
            return Next < Total ? Next : 0;
        }

        uint32_t Total = 0;
        uint32_t Next = 0;
        uint32_t Budget = 0;
        uint32_t Visited = 0;
        uint32_t HitLimit = 0;
        bool Bounded = false;
        bool HitLimited = false;
    };

    bool EnableDebugPrivilege(std::wstring* warning)
    {
        bool ok = false;
        HANDLE token = nullptr;

        do
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                  &token))
            {
                if (warning != nullptr)
                {
                    *warning = L"OpenProcessToken failed (gle=" +
                               std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            LUID luid = {};
            if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
            {
                if (warning != nullptr)
                {
                    *warning = L"LookupPrivilegeValue(SeDebugPrivilege) failed (gle=" +
                               std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr))
            {
                if (warning != nullptr)
                {
                    *warning = L"AdjustTokenPrivileges(SeDebugPrivilege) failed (gle=" +
                               std::to_wstring(GetLastError()) + L")";
                }
                break;
            }
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                if (warning != nullptr)
                {
                    *warning = L"SeDebugPrivilege not assigned (not running elevated?)";
                }
                break;
            }
            ok = true;
        } while (false);

        if (token != nullptr)
        {
            CloseHandle(token);
        }
        return ok;
    }

    std::wstring FormatHex(uint64_t value, int width)
    {
        std::wstringstream ss;
        ss << std::hex << std::uppercase << std::setw(width) << std::setfill(L'0') << value;
        return ss.str();
    }

    std::wstring SanitiseTagForPath(const std::wstring& tag)
    {
        std::wstring out;
        out.reserve(tag.size());
        for (wchar_t ch : tag)
        {
            if ((ch >= L'A' && ch <= L'Z') ||
                (ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9'))
            {
                out.push_back(ch);
            }
            else
            {
                out.push_back(L'_');
            }
        }
        return out;
    }

    std::wstring FormatTagAscii(uint32_t tag)
    {
        std::wstring out;
        out.reserve(4);
        for (int i = 0; i < 4; ++i)
        {
            unsigned char ch = static_cast<unsigned char>((tag >> (i * 8)) & 0xff);
            if (ch >= 0x20 && ch <= 0x7E)
            {
                out.push_back(static_cast<wchar_t>(ch));
            }
            else
            {
                out.push_back(L'.');
            }
        }
        return out;
    }

    bool AppliesPagedFilter(PoolPeHunter::PagedFilter filter, bool nonPaged)
    {
        if (filter == PoolPeHunter::PagedFilter::NonPagedOnly && !nonPaged)
        {
            return false;
        }
        if (filter == PoolPeHunter::PagedFilter::PagedOnly && nonPaged)
        {
            return false;
        }
        return true;
    }

    bool EnsureDirectoryExists(const std::wstring& path)
    {
        if (path.empty())
        {
            return false;
        }
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES)
        {
            return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        }
        return CreateDirectoryW(path.c_str(), nullptr) != 0;
    }
}

PoolPeHunter::PoolPeHunter(DeviceClient& device)
    : device_(device)
{
}

bool PoolPeHunter::Scan(const Options& options, PoolPeHunterResult* result, std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"PoolPeHunter::Scan called without result buffer";
        }
        return false;
    }

    *result = PoolPeHunterResult{};
    result->BigPoolAddressViewOnly = true;
    result->Diagnostics.push_back(
        L"!pool pe address view is big-pool only (PoolBigPageTable); small-pool PE images are not enumerated by VA");

    bool ok = false;
    void* buffer = nullptr;

    do
    {
        std::wstring privWarn;
        if (EnableDebugPrivilege(&privWarn))
        {
            result->PrivilegeEnabled = true;
        }
        else if (!privWarn.empty())
        {
            result->Warnings.push_back(privWarn);
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"GetModuleHandle(ntdll.dll) failed";
            }
            break;
        }
        PfnNtQuerySystemInformation fn =
            reinterpret_cast<PfnNtQuerySystemInformation>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (fn == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"GetProcAddress(NtQuerySystemInformation) failed";
            }
            break;
        }

        ULONG bufferSize = kInitialQueryBytes;
        ULONG returnLength = 0;
        NTSTATUS_LOCAL status = 0;
        ULONG retries = 0;
        bool fetched = false;

        for (;;)
        {
            if (buffer != nullptr)
            {
                HeapFree(GetProcessHeap(), 0, buffer);
                buffer = nullptr;
            }
            buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
            if (buffer == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"HeapAlloc failed";
                }
                break;
            }
            returnLength = 0;
            status = fn(kSystemBigPoolInformation, buffer, bufferSize, &returnLength);
            if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
            {
                ULONG nextSize = (returnLength > bufferSize) ? returnLength : (bufferSize * 2);
                if (nextSize <= bufferSize)
                {
                    nextSize = bufferSize * 2;
                }
                if (nextSize > kMaxQueryBytes)
                {
                    if (error != nullptr)
                    {
                        *error = L"big pool buffer exceeded 64 MB ceiling";
                    }
                    break;
                }
                if (++retries > kMaxQueryRetries)
                {
                    if (error != nullptr)
                    {
                        *error = L"big pool query exceeded retry budget";
                    }
                    break;
                }
                bufferSize = nextSize;
                continue;
            }
            if (status < 0)
            {
                if (error != nullptr)
                {
                    std::wstringstream ss;
                    ss << L"NtQuerySystemInformation failed: 0x" << std::hex << status;
                    *error = ss.str() + L" (need SeDebugPrivilege / elevated)";
                }
                break;
            }
            fetched = true;
            break;
        }

        result->QueryBufferBytes = bufferSize;
        result->QueryRetries = retries;
        if (!fetched)
        {
            break;
        }

        const SIZE_T headerBytes = FIELD_OFFSET(SYSTEM_BIGPOOL_INFORMATION_LOCAL, Entries);
        if (!LeftoverValidateCountedBuffer(
                bufferSize, returnLength, headerBytes, sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL), 0))
        {
            if (error != nullptr)
            {
                *error = L"big pool response has an invalid returned buffer length";
            }
            break;
        }

        const SYSTEM_BIGPOOL_INFORMATION_LOCAL* info =
            reinterpret_cast<const SYSTEM_BIGPOOL_INFORMATION_LOCAL*>(buffer);
        const ULONG totalEntries = info->Count;
        result->TotalEntries = totalEntries;

        if (!LeftoverValidateCountedBuffer(
                bufferSize, returnLength, headerBytes, sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL), totalEntries))
        {
            if (error != nullptr)
            {
                *error = L"big pool entry count exceeds the returned buffer; PE scan deferred";
            }
            break;
        }
        const ULONG safeCount = totalEntries;
        if (!ValidatePoolPeEntries(info->Entries, safeCount))
        {
            if (error != nullptr)
            {
                *error = L"big pool contains an invalid allocation range; PE scan deferred";
            }
            break;
        }

        // Optionally ensure the dump directory exists up-front.
        if (options.DumpEnabled && !options.DumpDirectory.empty())
        {
            if (!EnsureDirectoryExists(options.DumpDirectory))
            {
                result->Warnings.push_back(L"dump directory could not be created: " +
                                            options.DumpDirectory);
            }
        }

        std::vector<uint32_t> order;
        PoolPeHunter::Options windowOptions = options;
        if (options.ScanInteriorPages && options.ContinueScan)
        {
            order.reserve(safeCount);
            for (uint32_t index = 0; index < safeCount; ++index)
            {
                order.push_back(index);
            }
            const auto allocationAddress = [info](uint32_t index)
            {
                return reinterpret_cast<uint64_t>(info->Entries[index].VirtualAddress) & ~1ull;
            };
            std::sort(order.begin(), order.end(), [&](uint32_t left, uint32_t right)
            {
                return allocationAddress(left) < allocationAddress(right);
            });
            const auto next = std::upper_bound(order.begin(), order.end(), options.AllocationAfter,
                [&](uint64_t address, uint32_t index)
                {
                    return address < allocationAddress(index);
                });
            windowOptions.EntryOffset = static_cast<uint64_t>(next - order.begin());
            if (next == order.end())
            {
                windowOptions.EntryOffset = 0;
            }
        }
        PoolPeEntryWindow window(safeCount, windowOptions);
        uint64_t lastAllocation = 0;
        uint32_t i = 0;
        while (window.Take(result->Hits.size(), &i))
        {
            const SYSTEM_BIGPOOL_ENTRY_LOCAL& src = info->Entries[order.empty() ? i : order[i]];
            ULONG_PTR raw = reinterpret_cast<ULONG_PTR>(src.VirtualAddress);
            bool nonPaged = (raw & 1ULL) != 0;
            ULONG_PTR address = raw & ~static_cast<ULONG_PTR>(1);
            lastAllocation = static_cast<uint64_t>(address);

            if (nonPaged)
            {
                ++result->NonPagedCount;
            }
            else
            {
                ++result->PagedCount;
            }

            if (PoolPeAddressExcluded(address, options.ExcludedAddressRanges))
            {
                continue;
            }

            if (!AppliesPagedFilter(options.Paged, nonPaged))
            {
                continue;
            }

            uint64_t entrySize = static_cast<uint64_t>(src.SizeInBytes);

            if (options.HasTagFilter && src.TagUlong != options.TagFilter)
            {
                continue;
            }
            if (options.HasMinSize && entrySize < options.MinSize)
            {
                continue;
            }
            if (options.HasMaxSize && entrySize > options.MaxSize)
            {
                continue;
            }

            // Paged allocations can disappear from the readable view between
            // the table snapshot and this probe; preserve partial coverage.
            const uint64_t pageOffset = options.ScanInteriorPages
                ? PoolPePageOffset(entrySize, options.InteriorPageRound) : 0;
            const uint64_t remaining = entrySize - pageOffset;
            result->InteriorCoveragePartial = result->InteriorCoveragePartial || entrySize > kHeadBytesToRead;
            uint32_t readLength = (remaining < kHeadBytesToRead)
                ? static_cast<uint32_t>(remaining)
                : kHeadBytesToRead;
            if (readLength < sizeof(IMAGE_DOS_HEADER))
            {
                continue;
            }

            std::vector<uint8_t> head;
            std::wstring readError;
            const bool headRead = device_.ReadMemory(
                static_cast<uint64_t>(address) + pageOffset, readLength, &head, &readError);
            if (!headRead || head.size() != readLength)
            {
                ++result->ReadFailures;
            }
            if (!headRead || head.size() < sizeof(IMAGE_DOS_HEADER))
            {
                continue;
            }

            ++result->Scanned;

            PeHeaderProbe probe;
            if (!ProbePoolPeSample(head.data(), head.size(), remaining, &probe))
            {
                continue;
            }

            bool wiped = probe.MzWiped || probe.PeSignatureWiped || probe.ELfanewMismatch;
            if (options.OnlySuspicious && !wiped)
            {
                continue;
            }

            // Check the hit limit BEFORE counting/pushing so that the summary
            // counts stay consistent with the displayed entries (hits ==
            // result->Hits.size(), suspicious == count of pushed wiped hits).
            if (options.LimitHits != 0 && result->Hits.size() >= options.LimitHits)
            {
                result->HitLimitReached = true;
                result->Diagnostics.push_back(L"hit limit reached; remaining entries elided");
                break;
            }

            if (wiped)
            {
                ++result->SuspiciousWipes;
            }

            PoolPeHit hit;
            hit.Address = static_cast<uint64_t>(address) + pageOffset;
            hit.AllocationBase = static_cast<uint64_t>(address);
            hit.AllocationSize = entrySize;
            hit.PageOffset = pageOffset;
            hit.SizeInBytes = remaining;
            hit.TagRaw = src.TagUlong;
            hit.TagText = FormatTagAscii(src.TagUlong);
            hit.NonPaged = nonPaged;
            hit.Probe = probe;

            // Optional file dump. We use DumpKernelPeToFile which performs the
            // same wiped-signature recovery used by the standalone dump-pe
            // command, so the resulting file is loadable in IDA/Ghidra even
            // when the in-memory MZ/PE bytes have been stripped.
            if (options.DumpEnabled && !options.DumpDirectory.empty())
            {
                std::wstring sanitizedTag = SanitiseTagForPath(hit.TagText);
                std::wstring filename = options.DumpDirectory;
                if (!filename.empty() &&
                    filename.back() != L'\\' && filename.back() != L'/')
                {
                    filename.push_back(L'\\');
                }
                filename += L"poolpe_";
                filename += sanitizedTag;
                filename += L"_";
                filename += FormatHex(hit.Address, 16);
                filename += L".bin";

                DumpPeResult dpr;
                std::wstring dumpError;
                if (DumpKernelPeToFile(device_, hit.Address, filename, &dpr, &dumpError))
                {
                    hit.DumpSucceeded = true;
                    hit.DumpedPath = filename;
                }
                else
                {
                    result->Warnings.push_back(L"failed to dump hit at " +
                                                FormatHex(hit.Address, 16) +
                                                L": " + dumpError);
                }
            }

            result->Hits.push_back(std::move(hit));
        }
        result->EntriesVisited = window.Visited;
        result->NextEntryOffset = window.NextOffset();
        result->NextAllocationAfter = window.NextOffset() == 0 ? 0 : lastAllocation;
        result->NextInteriorPageRound = options.InteriorPageRound;
        if (options.ScanInteriorPages && window.NextOffset() == 0 && safeCount != 0)
        {
            ++result->NextInteriorPageRound;
        }
        result->EntriesTruncated = window.Visited < safeCount;
        result->HitLimitReached = result->HitLimitReached || window.HitLimited;
        if (options.ContinueScan && result->EntriesTruncated)
        {
            result->Diagnostics.push_back(
                L"pool PE scan retained a bounded table window; next entry=" +
                std::to_wstring(result->NextEntryOffset));
        }

        if (result->ReadFailures != 0)
        {
            result->Warnings.push_back(
                L"pool PE candidate reads failed: " + std::to_wstring(result->ReadFailures) +
                L"; absence of hits is not complete coverage");
        }
        if (result->InteriorCoveragePartial)
        {
            result->Warnings.push_back(L"pool allocation bodies are sampled by page; interior continuation is required");
        }
        ok = true;
    } while (false);

    if (buffer != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    return ok;
}

bool PoolPeHunterSelfTest()
{
    bool ok = false;
    do
    {
        std::set<uint64_t> pageOffsets;
        for (uint64_t round = 0; round < 5; ++round)
        {
            pageOffsets.insert(PoolPePageOffset(0x4001, round));
        }
        if (pageOffsets.size() != 5 || *pageOffsets.rbegin() != 0x4000 ||
            PoolPePageOffset(0x4001, 5) != 0 || PoolPePageOffset(0, ~0ull) != 0 ||
            PoolPePageOffset(~0ull, ~0ull) >= ~0ull)
        {
            break;
        }
        // PE probing is independent of execute permissions, including NX
        // storage. Only the third interior page contains a valid image.
        std::vector<uint8_t> allocation(0x5000, 0);
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        IMAGE_NT_HEADERS64 nt = {};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.SizeOfImage = 0x2000;
        std::memcpy(allocation.data() + 0x3000, &dos, sizeof(dos));
        std::memcpy(allocation.data() + 0x3080, &nt, sizeof(nt));
        uint64_t imageOffset = ~0ull;
        size_t positivePages = 0;
        for (uint64_t round = 0; round < 5; ++round)
        {
            const uint64_t offset = PoolPePageOffset(allocation.size(), round);
            PeHeaderProbe probe = {};
            if (ProbePoolPeSample(allocation.data() + offset, 0x1000, allocation.size() - offset, &probe))
            {
                imageOffset = offset;
                ++positivePages;
            }
        }
        PeHeaderProbe malformed = {};
        if (imageOffset != 0x3000 || positivePages != 1 ||
            ProbePoolPeSample(allocation.data() + 0x3000, 0x40, 0x2000, &malformed) ||
            !ProbePoolPeSample(allocation.data() + 0x3000, 0x1000, 0x1000, &malformed))
        {
            break;
        }
        nt.OptionalHeader.SizeOfImage = 0x123;
        std::memcpy(allocation.data() + 0x3080, &nt, sizeof(nt));
        if (ProbePoolPeSample(allocation.data() + 0x3000, 0x1000, 0x2000, &malformed))
        {
            break;
        }
        constexpr uint64_t base = 0xFFFF800010000000ull;
        if (!LeftoverValidateBigPoolRange(base, 0x1000) ||
            LeftoverValidateBigPoolRange(0, 0x1000) ||
            LeftoverValidateBigPoolRange(0x10000, 0x1000) ||
            LeftoverValidateBigPoolRange(0xFFFF000000000000ull, 0x1000) ||
            LeftoverValidateBigPoolRange(base, 0) ||
            LeftoverValidateBigPoolRange((std::numeric_limits<uint64_t>::max)() - 0x7FF, 0x1000))
        {
            break;
        }
        std::vector<SYSTEM_BIGPOOL_ENTRY_LOCAL> entries(33);
        for (size_t index = 0; index < entries.size(); ++index)
        {
            entries[index].VirtualAddress = reinterpret_cast<PVOID>(base + index * 0x2000 + 1);
            entries[index].SizeInBytes = 0x1000;
        }
        if (!ValidatePoolPeEntries(entries.data(), static_cast<uint32_t>(entries.size())) ||
            !ValidatePoolPeEntries(nullptr, 0) || ValidatePoolPeEntries(nullptr, 1))
        {
            break;
        }
        entries.back().SizeInBytes = 0;
        if (ValidatePoolPeEntries(entries.data(), static_cast<uint32_t>(entries.size())))
        {
            break;
        }
        entries.back().SizeInBytes = 0x1000;

        PoolPeHunter::Options options;
        options.ContinueScan = true;
        options.MaxEntries = 4096;
        options.LimitHits = 32;
        std::set<uint32_t> observed;
        bool valid = true;
        for (uint32_t pass = 0; pass < 2; ++pass)
        {
            PoolPeEntryWindow window(static_cast<uint32_t>(entries.size()), options);
            size_t hits = 0;
            uint32_t index = 0;
            while (window.Take(hits, &index))
            {
                observed.insert(index);
                ++hits;
            }
            if ((pass == 0 && (hits != 32 || window.NextOffset() != 32 || !window.HitLimited)) ||
                (pass == 1 && (hits != 1 || window.NextOffset() != 0 || window.HitLimited)))
            {
                valid = false;
                break;
            }
            options.EntryOffset = window.NextOffset();
        }
        if (!valid || observed.size() != entries.size())
        {
            break;
        }

        // Loaded images are excluded before they can use the retained-hit
        // budget. The only orphan after 32 owned PE rows must be read now.
        options.EntryOffset = 0;
        options.ExcludedAddressRanges.emplace_back(base, base + 32 * 0x2000);
        PoolPeEntryWindow excluded(static_cast<uint32_t>(entries.size()), options);
        size_t orphanHits = 0;
        uint32_t index = 0;
        uint32_t lastOrphan = 0;
        while (excluded.Take(orphanHits, &index))
        {
            const uint64_t address = reinterpret_cast<uint64_t>(entries[index].VirtualAddress) & ~1ull;
            if (PoolPeAddressExcluded(address, options.ExcludedAddressRanges))
            {
                continue;
            }
            ++orphanHits;
            lastOrphan = index;
        }
        if (orphanHits != 1 || lastOrphan != 32 || excluded.Visited != 33 ||
            excluded.HitLimited || excluded.NextOffset() != 0)
        {
            break;
        }

        options.EntryOffset = 0;
        options.MaxEntries = 8;
        PoolPeEntryWindow budgeted(33, options);
        uint32_t visits = 0;
        while (budgeted.Take(0, &index))
        {
            ++visits;
        }
        if (visits != 8 || budgeted.NextOffset() != 8 || budgeted.HitLimited)
        {
            break;
        }
        options.EntryOffset = (std::numeric_limits<uint64_t>::max)();
        PoolPeEntryWindow resetOffset(33, options);
        if (!resetOffset.Take(0, &index) || index != 0)
        {
            break;
        }
        PoolPeEntryWindow empty(0, options);
        if (empty.Take(0, &index) || empty.NextOffset() != 0)
        {
            break;
        }

        // Standalone callers retain prefix ordering and the existing PE-hit
        // limit. Continuation-only fields must not alter their enumeration.
        options.ContinueScan = false;
        options.EntryOffset = 17;
        options.MaxEntries = 1;
        PoolPeEntryWindow standalone(33, options);
        visits = 0;
        while (standalone.Take(32, &index))
        {
            if (index != visits)
            {
                valid = false;
                break;
            }
            ++visits;
        }
        if (!valid || visits != 33 || standalone.HitLimited)
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}

namespace
{
    std::wstring PoolPeJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildPoolPeJson(const PoolPeHunterResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.pool-pe.v1\",\"count\":";
    out += std::to_wstring(result.Hits.size());
    out += L",\"totalEntries\":" + std::to_wstring(result.TotalEntries);
    out += L",\"scanned\":" + std::to_wstring(result.Scanned);
    out += L",\"readFailures\":" + std::to_wstring(result.ReadFailures);
    out += L",\"entriesVisited\":" + std::to_wstring(result.EntriesVisited);
    out += L",\"nextEntryOffset\":" + std::to_wstring(result.NextEntryOffset);
    out += L",\"nextAllocationAfter\":" + std::to_wstring(result.NextAllocationAfter);
    out += L",\"nextInteriorPageRound\":" + std::to_wstring(result.NextInteriorPageRound);
    out += L",\"interiorCoveragePartial\":" + std::wstring(result.InteriorCoveragePartial ? L"true" : L"false");
    out += L",\"entriesTruncated\":";
    out += result.EntriesTruncated ? L"true" : L"false";
    out += L",\"hitLimitReached\":";
    out += result.HitLimitReached ? L"true" : L"false";
    out += L",\"suspiciousWipes\":" + std::to_wstring(result.SuspiciousWipes);
    out += L",\"hits\":[";

    for (size_t index = 0; index < result.Hits.size(); ++index)
    {
        const PoolPeHit& hit = result.Hits[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"address\":" + mcpjson::Quote(PoolPeJsonHex(hit.Address));
        out += L",\"allocationBase\":" + mcpjson::Quote(PoolPeJsonHex(hit.AllocationBase));
        out += L",\"allocationSize\":" + std::to_wstring(hit.AllocationSize);
        out += L",\"pageOffset\":" + std::to_wstring(hit.PageOffset);
        out += L",\"sizeInBytes\":" + std::to_wstring(hit.SizeInBytes);
        out += L",\"tag\":" + mcpjson::Quote(hit.TagText);
        out += L",\"nonPaged\":";
        out += hit.NonPaged ? L"true" : L"false";

        const PeHeaderProbe& probe = hit.Probe;
        out += L",\"probe\":{\"isPe\":";
        out += probe.IsPe ? L"true" : L"false";
        out += L",\"mzWiped\":";
        out += probe.MzWiped ? L"true" : L"false";
        out += L",\"peSignatureWiped\":";
        out += probe.PeSignatureWiped ? L"true" : L"false";
        out += L",\"eLfanewMismatch\":";
        out += probe.ELfanewMismatch ? L"true" : L"false";
        out += L",\"is64Bit\":";
        out += probe.Is64Bit ? L"true" : L"false";
        out += L",\"machine\":" + std::to_wstring(static_cast<uint32_t>(probe.Machine));
        out += L",\"numberOfSections\":" + std::to_wstring(static_cast<uint32_t>(probe.NumberOfSections));
        out += L",\"sizeOfImage\":" + std::to_wstring(probe.SizeOfImage);
        out += L"}";

        if (!hit.DumpedPath.empty())
        {
            out += L",\"dumpedPath\":" + mcpjson::Quote(hit.DumpedPath);
        }
        out += L",\"dumpSucceeded\":";
        out += hit.DumpSucceeded ? L"true" : L"false";
        out += L"}";
    }

    out += L"],\"warnings\":[";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[index]);
    }

    out += L"],\"diagnostics\":[";
    for (size_t index = 0; index < result.Diagnostics.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Diagnostics[index]);
    }
    out += L"]}";

    return out;
}
