#include "PoolScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <sstream>
#include <iomanip>

// Undocumented but stable across modern Windows builds.
// Confirmed working on Windows 10 1809+ and Windows 11 22H2/23H2/24H2.
constexpr ULONG kSystemBigPoolInformation = 0x42;
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
#pragma pack(pop)

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
