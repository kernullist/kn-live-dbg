#include "PoolScanner.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "McpJson.h"

#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <sstream>
#include <iomanip>

// Undocumented but stable across modern Windows builds.
// Confirmed working on Windows 10 1809+ and Windows 11 22H2/23H2/24H2.
constexpr ULONG kSystemBigPoolInformation = 0x42;
constexpr ULONG kSystemPoolTagInformation = 0x16;
constexpr ULONG kInitialQueryBytes = 0x10000;        // 64 KB
constexpr ULONG kMaxQueryBytes     = 0x4000000;      // 64 MB
constexpr ULONG kMaxQueryRetries   = 16;

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000L)
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
    } SYSTEM_BIGPOOL_ENTRY_LOCAL, *PSYSTEM_BIGPOOL_ENTRY_LOCAL;

    typedef struct _SYSTEM_BIGPOOL_INFORMATION_LOCAL
    {
        ULONG Count;
        SYSTEM_BIGPOOL_ENTRY_LOCAL Entries[1];
    } SYSTEM_BIGPOOL_INFORMATION_LOCAL, *PSYSTEM_BIGPOOL_INFORMATION_LOCAL;

    typedef struct _SYSTEM_POOLTAG_LOCAL
    {
        union
        {
            UCHAR Tag[4];
            ULONG TagUlong;
        };
        ULONG PagedAllocs;
        ULONG PagedFrees;
        SIZE_T PagedUsed;
        ULONG NonPagedAllocs;
        ULONG NonPagedFrees;
        SIZE_T NonPagedUsed;
    } SYSTEM_POOLTAG_LOCAL, *PSYSTEM_POOLTAG_LOCAL;

    typedef struct _SYSTEM_POOLTAG_INFORMATION_LOCAL
    {
        ULONG Count;
        SYSTEM_POOLTAG_LOCAL TagInfo[1];
    } SYSTEM_POOLTAG_INFORMATION_LOCAL, *PSYSTEM_POOLTAG_INFORMATION_LOCAL;
#pragma pack(pop)

    bool QuerySystemInfoBuffer(
        PfnNtQuerySystemInformation fn,
        ULONG infoClass,
        std::vector<uint8_t>* buffer,
        ULONG* returnLength,
        ULONG* retriesOut,
        std::wstring* error)
    {
        bool ok = false;
        void* raw = nullptr;

        do
        {
            if (fn == nullptr || buffer == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid system info query arguments";
                }
                break;
            }

            ULONG bufferSize = kInitialQueryBytes;
            ULONG returnLengthLocal = 0;
            ULONG retries = 0;
            bool fetched = false;
            NTSTATUS_LOCAL status = STATUS_SUCCESS;

            for (;;)
            {
                if (raw != nullptr)
                {
                    HeapFree(GetProcessHeap(), 0, raw);
                    raw = nullptr;
                }

                raw = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
                if (raw == nullptr)
                {
                    if (error != nullptr)
                    {
                        *error = L"HeapAlloc for system info buffer failed";
                    }
                    break;
                }

                returnLengthLocal = 0;
                status = fn(infoClass, raw, bufferSize, &returnLengthLocal);
                if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
                {
                    ULONG nextSize = (returnLengthLocal > bufferSize) ? returnLengthLocal : (bufferSize * 2);
                    if (nextSize <= bufferSize)
                    {
                        nextSize = bufferSize * 2;
                    }
                    if (nextSize > kMaxQueryBytes)
                    {
                        if (error != nullptr)
                        {
                            *error = L"system info buffer exceeded 64MB ceiling";
                        }
                        break;
                    }
                    if (++retries > kMaxQueryRetries)
                    {
                        if (error != nullptr)
                        {
                            *error = L"system info query exceeded retry budget";
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
                        wchar_t buf[32] = {};
                        swprintf_s(buf, L"0x%08X", static_cast<unsigned>(status));
                        *error = L"NtQuerySystemInformation failed: status=" + std::wstring(buf);
                    }
                    break;
                }

                fetched = true;
                break;
            }

            if (retriesOut != nullptr)
            {
                *retriesOut = retries;
            }
            if (returnLength != nullptr)
            {
                *returnLength = returnLengthLocal;
            }
            if (!fetched)
            {
                break;
            }

            buffer->assign(
                reinterpret_cast<uint8_t*>(raw),
                reinterpret_cast<uint8_t*>(raw) + returnLengthLocal);
            ok = true;
        } while (false);

        if (raw != nullptr)
        {
            HeapFree(GetProcessHeap(), 0, raw);
        }

        return ok;
    }

    bool CollectPoolTagStats(
        PfnNtQuerySystemInformation fn,
        const PoolScanner::Options& options,
        PoolScanResult* result,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::vector<uint8_t> buffer;
            ULONG returnLength = 0;
            ULONG retries = 0;
            std::wstring queryError;
            if (!QuerySystemInfoBuffer(
                    fn,
                    kSystemPoolTagInformation,
                    &buffer,
                    &returnLength,
                    &retries,
                    &queryError))
            {
                if (error != nullptr)
                {
                    *error = L"SystemPoolTagInformation: " + queryError;
                }
                break;
            }

            const SIZE_T headerBytes = FIELD_OFFSET(SYSTEM_POOLTAG_INFORMATION_LOCAL, TagInfo);
            if (returnLength < headerBytes)
            {
                if (error != nullptr)
                {
                    *error = L"pool tag buffer smaller than header";
                }
                break;
            }

            const SYSTEM_POOLTAG_INFORMATION_LOCAL* info =
                reinterpret_cast<const SYSTEM_POOLTAG_INFORMATION_LOCAL*>(buffer.data());
            const ULONG total = info->Count;
            result->TagStatCount = total;

            const SIZE_T expected =
                headerBytes + static_cast<SIZE_T>(total) * sizeof(SYSTEM_POOLTAG_LOCAL);
            const ULONG safeCount = static_cast<ULONG>(
                (expected > returnLength)
                    ? (returnLength - headerBytes) / sizeof(SYSTEM_POOLTAG_LOCAL)
                    : total);
            result->TagStatsSafeCount = safeCount;
            if (safeCount < total)
            {
                result->TagStatsBufferClamped = true;
                result->Warnings.push_back(
                    L"pool tag buffer clamped: kernel Count=" + std::to_wstring(total) +
                    L" but only " + std::to_wstring(safeCount) +
                    L" tag record(s) fit the returned buffer");
            }

            std::vector<PoolTagStatRecord> all;
            all.reserve(safeCount);
            for (ULONG i = 0; i < safeCount; ++i)
            {
                const SYSTEM_POOLTAG_LOCAL& src = info->TagInfo[i];
                if (options.HasTagFilter && src.TagUlong != options.TagFilter)
                {
                    continue;
                }

                PoolTagStatRecord rec = {};
                rec.TagRaw = src.TagUlong;
                {
                    std::wstring text;
                    text.reserve(4);
                    for (int bi = 0; bi < 4; ++bi)
                    {
                        unsigned char ch = static_cast<unsigned char>((src.TagUlong >> (bi * 8)) & 0xff);
                        text.push_back((ch >= 0x20 && ch <= 0x7E) ? static_cast<wchar_t>(ch) : L'.');
                    }
                    rec.TagText = text;
                }
                rec.PagedAllocs = src.PagedAllocs;
                rec.PagedFrees = src.PagedFrees;
                rec.PagedUsed = static_cast<uint64_t>(src.PagedUsed);
                rec.NonPagedAllocs = src.NonPagedAllocs;
                rec.NonPagedFrees = src.NonPagedFrees;
                rec.NonPagedUsed = static_cast<uint64_t>(src.NonPagedUsed);
                all.push_back(rec);
            }

            std::sort(
                all.begin(),
                all.end(),
                [](const PoolTagStatRecord& left, const PoolTagStatRecord& right)
                {
                    if (left.NonPagedUsed != right.NonPagedUsed)
                    {
                        return left.NonPagedUsed > right.NonPagedUsed;
                    }
                    return left.PagedUsed > right.PagedUsed;
                });

            // Matching count is post-filter / pre-truncate so JSON consumers can
            // tell top-N summaries apart from a complete matching set.
            result->TagStatsMatchingCount = all.size();

            // Tag filter requests must not be top-N truncated: the operator asked
            // for a specific tag and absence must mean "not present", not "not in top 64".
            const uint32_t limit =
                options.HasTagFilter
                    ? 0u
                    : (options.LimitTagStats != 0
                           ? options.LimitTagStats
                           : (options.LimitEntries != 0 ? options.LimitEntries : 64u));
            if (limit != 0 && all.size() > limit)
            {
                result->TagStatsTruncated = true;
                result->Warnings.push_back(
                    L"pool tag summary truncated to top " + std::to_wstring(limit) +
                    L" of " + std::to_wstring(all.size()) +
                    L" matching tag(s); missing tags are not proof of absence");
                all.resize(limit);
            }

            result->TagStatsReturned = all.size();
            result->TagStats = std::move(all);
            result->PoolTagViewAvailable = true;
            result->Diagnostics.push_back(
                L"pool tag view from SystemPoolTagInformation (covers small+big pool usage by tag; no per-allocation VA)");
            ok = true;
        } while (false);

        return ok;
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || left > (~0ull - right))
            {
                break;
            }

            *result = left + right;
            ok = true;
        } while (false);

        return ok;
    }

    bool EnableDebugPrivilege(std::wstring* warning)
    {
        bool result = false;
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

            DWORD gle = GetLastError();
            if (gle == ERROR_NOT_ALL_ASSIGNED)
            {
                if (warning != nullptr)
                {
                    *warning = L"SeDebugPrivilege not assigned (not running elevated?)";
                }
                break;
            }

            result = true;
        } while (false);

        if (token != nullptr)
        {
            CloseHandle(token);
        }

        return result;
    }

    PfnNtQuerySystemInformation ResolveNtQuerySystemInformation(std::wstring* error)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"GetModuleHandle(ntdll.dll) failed";
            }
            return nullptr;
        }

        PfnNtQuerySystemInformation fn =
            reinterpret_cast<PfnNtQuerySystemInformation>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));

        if (fn == nullptr && error != nullptr)
        {
            *error = L"GetProcAddress(NtQuerySystemInformation) failed";
        }

        return fn;
    }

    std::wstring StatusToHex(NTSTATUS_LOCAL status)
    {
        std::wstringstream ss;
        ss << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
           << static_cast<unsigned long>(status);
        return ss.str();
    }

    bool AppliesPagedFilter(PoolScanner::PagedFilter filter, bool nonPaged)
    {
        bool ok = true;

        do
        {
            if (filter == PoolScanner::PagedFilter::NonPagedOnly && !nonPaged)
            {
                ok = false;
                break;
            }

            if (filter == PoolScanner::PagedFilter::PagedOnly && nonPaged)
            {
                ok = false;
                break;
            }
        } while (false);

        return ok;
    }
}

std::wstring FormatPoolTag(uint32_t tagRaw)
{
    std::wstring text;
    text.reserve(4);

    for (int i = 0; i < 4; ++i)
    {
        unsigned char ch = static_cast<unsigned char>((tagRaw >> (i * 8)) & 0xff);
        if (ch >= 0x20 && ch <= 0x7E)
        {
            text.push_back(static_cast<wchar_t>(ch));
        }
        else
        {
            text.push_back(L'.');
        }
    }

    return text;
}

bool ParsePoolTagText(const std::wstring& text, uint32_t* tagOut)
{
    bool ok = false;

    do
    {
        if (tagOut == nullptr)
        {
            break;
        }

        if (text.empty() || text.size() > 4)
        {
            break;
        }

        // Pool tags are 4-byte little-endian. The kernel stores them exactly
        // as ExAllocatePoolWithTag's ULONG arg, so short C-literal tags like
        // 'SG' (0x4753) are zero-padded above the supplied chars rather than
        // space-padded. Mirror that here so partial filters match correctly.
        uint32_t value = 0;
        bool validChars = true;
        for (size_t i = 0; i < text.size(); ++i)
        {
            wchar_t wc = text[i];
            if (wc < 0x20 || wc > 0x7E)
            {
                validChars = false;
                break;
            }
            unsigned char ch = static_cast<unsigned char>(wc);
            value |= (static_cast<uint32_t>(ch) << (i * 8));
        }

        if (!validChars)
        {
            break;
        }

        *tagOut = value;
        ok = true;
    } while (false);

    return ok;
}

PoolScanner::PoolScanner(DeviceClient& device, SymbolEngine& symbols)
    : device_(device)
    , symbols_(symbols)
{
    (void)symbols_;
}

bool PoolScanner::Scan(const Options& options, PoolScanResult* result, std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"PoolScanner::Scan called without result buffer";
        }
        return false;
    }

    *result = PoolScanResult{};
    result->BigPoolAddressViewOnly = true;

    bool ok = false;
    void* buffer = nullptr;

    do
    {
        std::wstring privWarn;
        if (!EnableDebugPrivilege(&privWarn))
        {
            if (!privWarn.empty())
            {
                result->Warnings.push_back(privWarn);
            }
        }
        else
        {
            result->PrivilegeEnabled = true;
        }

        std::wstring resolveError;
        PfnNtQuerySystemInformation fn = ResolveNtQuerySystemInformation(&resolveError);
        if (fn == nullptr)
        {
            if (error != nullptr)
            {
                *error = resolveError;
            }
            break;
        }

        const bool tagsOnly = options.Target == PoolScanner::Scope::Tags;
        const bool wantTags =
            tagsOnly ||
            options.IncludePoolTagSummary;
        if (wantTags)
        {
            std::wstring tagError;
            if (!CollectPoolTagStats(fn, options, result, &tagError))
            {
                result->Warnings.push_back(
                    tagError.empty()
                        ? L"pool tag summary unavailable"
                        : tagError);
                if (tagsOnly)
                {
                    if (error != nullptr)
                    {
                        *error = tagError.empty() ? L"pool tag query failed" : tagError;
                    }
                    break;
                }
            }
            else if (tagsOnly)
            {
                result->Diagnostics.push_back(
                    L"address-level big pool enumeration skipped (tags scope); use !pool big/find for VAs");
                ok = true;
                break;
            }
        }

        result->Diagnostics.push_back(
            L"big pool address view only covers allocations tracked by PoolBigPageTable (>= page size); "
            L"use !pool tags for small+big pool tag usage");

        ULONG bufferSize = kInitialQueryBytes;
        ULONG returnLength = 0;
        NTSTATUS_LOCAL status = STATUS_SUCCESS;
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
                    *error = L"HeapAlloc for big pool buffer failed";
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
                        *error = L"big pool buffer exceeded 64MB ceiling";
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
                    *error = L"NtQuerySystemInformation(SystemBigPoolInformation) failed: " +
                             StatusToHex(status) +
                             L" (likely missing SeDebugPrivilege or not elevated)";
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
        if (returnLength < headerBytes)
        {
            if (error != nullptr)
            {
                *error = L"big pool buffer smaller than header; got " +
                         std::to_wstring(returnLength) + L" bytes";
            }
            break;
        }

        const SYSTEM_BIGPOOL_INFORMATION_LOCAL* info =
            reinterpret_cast<const SYSTEM_BIGPOOL_INFORMATION_LOCAL*>(buffer);
        const ULONG totalEntries = info->Count;
        result->TotalEntries = totalEntries;

        const SIZE_T expectedBytes = headerBytes +
            static_cast<SIZE_T>(totalEntries) * sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL);
        if (expectedBytes > returnLength)
        {
            result->Warnings.push_back(L"reported entry count exceeds returned buffer; clamping");
        }

        const ULONG safeCount = static_cast<ULONG>(
            (expectedBytes > returnLength)
                ? (returnLength - headerBytes) / sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL)
                : totalEntries);

        result->AttributesAttempted = options.AnnotateAttributes;

        for (ULONG i = 0; i < safeCount; ++i)
        {
            const SYSTEM_BIGPOOL_ENTRY_LOCAL& src = info->Entries[i];

            ULONG_PTR raw = reinterpret_cast<ULONG_PTR>(src.VirtualAddress);
            bool nonPaged = (raw & 1ULL) != 0;
            ULONG_PTR address = raw & ~static_cast<ULONG_PTR>(1);

            if (nonPaged)
            {
                ++result->NonPagedCount;
            }
            else
            {
                ++result->PagedCount;
            }

            if (!AppliesPagedFilter(options.Paged, nonPaged))
            {
                continue;
            }

            if (options.HasTagFilter && src.TagUlong != options.TagFilter)
            {
                continue;
            }

            uint64_t size = static_cast<uint64_t>(src.SizeInBytes);
            if (options.HasMinSize && size < options.MinSize)
            {
                continue;
            }
            if (options.HasMaxSize && size > options.MaxSize)
            {
                continue;
            }
            if (options.HasAddressFilter)
            {
                uint64_t target = options.AddressFilter;
                uint64_t entryEnd = 0;
                if (!TryAdd(static_cast<uint64_t>(address), size, &entryEnd))
                {
                    continue;
                }
                if (target < address || target >= entryEnd)
                {
                    continue;
                }
            }

            BigPoolEntryRecord rec;
            rec.VirtualAddress = static_cast<uint64_t>(address);
            rec.SizeInBytes = size;
            rec.TagRaw = src.TagUlong;
            rec.TagText = FormatPoolTag(src.TagUlong);
            rec.NonPaged = nonPaged;

            if (options.AnnotateAttributes && nonPaged && address != 0 && size > 0)
            {
                // Walk the page tables for the first page only. Effective W and
                // X require ANDing the relevant bits across every level we
                // traversed -- using only the leaf PTE would mis-report
                // mappings whose parent PDPTE/PDE clears W or sets NX.
                PhysicalTranslationInfo translation = {};
                std::wstring translateError;
                uint32_t translateLength = (size < 0x1000) ? static_cast<uint32_t>(size) : 0x1000;

                if (device_.TranslateVirtual(0,
                                             rec.VirtualAddress,
                                             translateLength,
                                             &translation,
                                             &translateError))
                {
                    rec.AttributesQueried = true;
                    rec.ProbedLength = translateLength;
                    rec.PagingLevels = translation.PagingLevels;
                    rec.Pte = translation.Pte;
                    rec.IsLargePage = (translation.Flags & KNDBG_TRANSLATE_FLAG_LARGE_PAGE) != 0;

                    const bool la57 = (translation.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
                    const uint64_t levelEntries[5] =
                    {
                        translation.Pml5e,
                        translation.Pml4e,
                        translation.Pdpte,
                        translation.Pde,
                        translation.Pte
                    };
                    const size_t startIndex = la57 ? 0 : 1;
                    size_t walkCount = translation.PagingLevels;
                    if (walkCount > 5)
                    {
                        walkCount = 5;
                    }

                    bool present = walkCount > 0;
                    bool writable = walkCount > 0;
                    bool executable = walkCount > 0;

                    for (size_t step = 0; step < walkCount; ++step)
                    {
                        size_t levelIdx = startIndex + step;
                        if (levelIdx >= 5)
                        {
                            break;
                        }
                        uint64_t pte = levelEntries[levelIdx];
                        if ((pte & 1ULL) == 0)
                        {
                            present = false;
                        }
                        if ((pte & 2ULL) == 0)
                        {
                            writable = false;
                        }
                        if ((pte & (1ULL << 63)) != 0)
                        {
                            executable = false;
                        }

                        // Large-page short-circuit: PS=1 at PDPTE (1 GB) or
                        // PDE (2 MB) marks the leaf. The unused PTE below
                        // is reported as zero by the driver and would
                        // erroneously clear Present/Writable. PS is bit 7 of
                        // PDPTE/PDE only -- bit 7 of PTE is the PAT bit.
                        if ((levelIdx == 2 || levelIdx == 3) &&
                            (pte & (1ULL << 7)) != 0)
                        {
                            break;
                        }
                    }

                    rec.IsReadable = present;
                    rec.IsWritable = present && writable;
                    rec.IsExecutable = present && executable;
                }
            }

            if (options.WxOnly)
            {
                if (!rec.AttributesQueried || !rec.IsWritable || !rec.IsExecutable)
                {
                    continue;
                }
            }

            if (options.LimitEntries != 0 && result->Entries.size() >= options.LimitEntries)
            {
                result->Diagnostics.push_back(L"output limit reached (/limit); remaining entries elided");
                break;
            }

            result->Entries.push_back(std::move(rec));
        }

        result->MatchingCount = result->Entries.size();
        ok = true;
    } while (false);

    if (buffer != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        buffer = nullptr;
    }

    return ok;
}

namespace
{
    std::wstring PoolJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildPoolJson(const PoolScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.pool.v1\",\"count\":";
    out += std::to_wstring(result.Entries.size());
    out += L",\"totalEntries\":" + std::to_wstring(result.TotalEntries);
    out += L",\"nonPagedCount\":" + std::to_wstring(result.NonPagedCount);
    out += L",\"pagedCount\":" + std::to_wstring(result.PagedCount);
    out += L",\"matchingCount\":" + std::to_wstring(result.MatchingCount);
    out += L",\"attributesAttempted\":";
    out += result.AttributesAttempted ? L"true" : L"false";
    out += L",\"bigPoolAddressViewOnly\":";
    out += result.BigPoolAddressViewOnly ? L"true" : L"false";
    out += L",\"poolTagViewAvailable\":";
    out += result.PoolTagViewAvailable ? L"true" : L"false";
    out += L",\"tagStatCount\":" + std::to_wstring(result.TagStatCount);
    out += L",\"tagStatsMatchingCount\":" + std::to_wstring(result.TagStatsMatchingCount);
    out += L",\"tagStatsReturned\":" + std::to_wstring(result.TagStatsReturned);
    out += L",\"tagStatsSafeCount\":" + std::to_wstring(result.TagStatsSafeCount);
    out += L",\"tagStatsTruncated\":";
    out += result.TagStatsTruncated ? L"true" : L"false";
    out += L",\"tagStatsBufferClamped\":";
    out += result.TagStatsBufferClamped ? L"true" : L"false";
    out += L",\"tagStats\":[";
    for (size_t ti = 0; ti < result.TagStats.size(); ++ti)
    {
        const PoolTagStatRecord& tag = result.TagStats[ti];
        if (ti > 0)
        {
            out += L",";
        }
        // tag = printable rendering ('.' for non-printable); tagRaw disambiguates collisions.
        out += L"{\"tag\":" + mcpjson::Quote(tag.TagText);
        out += L",\"tagRaw\":" + mcpjson::Quote(PoolJsonHex(tag.TagRaw));
        out += L",\"nonPagedUsed\":" + std::to_wstring(tag.NonPagedUsed);
        out += L",\"pagedUsed\":" + std::to_wstring(tag.PagedUsed);
        out += L",\"nonPagedAllocs\":" + std::to_wstring(tag.NonPagedAllocs);
        out += L",\"pagedAllocs\":" + std::to_wstring(tag.PagedAllocs);
        out += L"}";
    }
    out += L"],\"records\":[";

    for (size_t index = 0; index < result.Entries.size(); ++index)
    {
        const BigPoolEntryRecord& entry = result.Entries[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"virtualAddress\":" + mcpjson::Quote(PoolJsonHex(entry.VirtualAddress));
        out += L",\"sizeInBytes\":" + std::to_wstring(entry.SizeInBytes);
        out += L",\"tag\":" + mcpjson::Quote(entry.TagText);
        out += L",\"tagRaw\":" + mcpjson::Quote(PoolJsonHex(entry.TagRaw));
        out += L",\"nonPaged\":";
        out += entry.NonPaged ? L"true" : L"false";
        if (entry.AttributesQueried)
        {
            out += L",\"isReadable\":";
            out += entry.IsReadable ? L"true" : L"false";
            out += L",\"isWritable\":";
            out += entry.IsWritable ? L"true" : L"false";
            out += L",\"isExecutable\":";
            out += entry.IsExecutable ? L"true" : L"false";
            out += L",\"isLargePage\":";
            out += entry.IsLargePage ? L"true" : L"false";
            out += L",\"pagingLevels\":" + std::to_wstring(entry.PagingLevels);
            out += L",\"pte\":" + mcpjson::Quote(PoolJsonHex(entry.Pte));
            // Effective writable-and-executable is the primary triage signal:
            // a W+X big pool allocation is a classic manual-mapper / shellcode
            // staging surface, so surface it as its own boolean.
            out += L",\"wx\":";
            out += (entry.IsWritable && entry.IsExecutable) ? L"true" : L"false";
        }
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
