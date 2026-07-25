#include "PoolPeHunter.h"
#include "McpJson.h"

#include <Windows.h>
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
        L"pool-scan-pe address view is big-pool only (PoolBigPageTable); small-pool PE images are not enumerated by VA");

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
        if (returnLength < headerBytes)
        {
            if (error != nullptr)
            {
                *error = L"big pool response smaller than header";
            }
            break;
        }

        const SYSTEM_BIGPOOL_INFORMATION_LOCAL* info =
            reinterpret_cast<const SYSTEM_BIGPOOL_INFORMATION_LOCAL*>(buffer);
        const ULONG totalEntries = info->Count;
        result->TotalEntries = totalEntries;

        const SIZE_T expectedBytes = headerBytes +
            static_cast<SIZE_T>(totalEntries) * sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL);
        const ULONG safeCount = static_cast<ULONG>(
            (expectedBytes > returnLength)
                ? (returnLength - headerBytes) / sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL)
                : totalEntries);

        if (expectedBytes > returnLength)
        {
            result->Warnings.push_back(L"reported entry count exceeds returned buffer; clamping");
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

            // Only NonPaged entries reliably support kernel-VA reads; allow Paged
            // when explicitly requested but skip on failure quietly.
            uint32_t readLength = (entrySize < kHeadBytesToRead)
                ? static_cast<uint32_t>(entrySize)
                : kHeadBytesToRead;
            if (readLength < sizeof(IMAGE_DOS_HEADER))
            {
                continue;
            }

            std::vector<uint8_t> head;
            std::wstring readError;
            if (!device_.ReadMemory(static_cast<uint64_t>(address), readLength, &head, &readError))
            {
                ++result->ReadFailures;
                continue;
            }

            ++result->Scanned;

            PeHeaderProbe probe;
            if (!ProbeForPeHeader(head.data(), head.size(), &probe))
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
                result->Diagnostics.push_back(L"hit limit reached; remaining entries elided");
                break;
            }

            if (wiped)
            {
                ++result->SuspiciousWipes;
            }

            PoolPeHit hit;
            hit.Address = static_cast<uint64_t>(address);
            hit.SizeInBytes = entrySize;
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

        ok = true;
    } while (false);

    if (buffer != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
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
