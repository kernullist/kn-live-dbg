#include "LeftoverCommon.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#endif

namespace
{
    constexpr ULONG kSystemBigPoolInformation = 0x42;
    constexpr ULONG kInitialQueryBytes = 0x10000;
    constexpr ULONG kMaxQueryBytes = 0x4000000;
    constexpr ULONG kMaxQueryRetries = 16;
    constexpr uint32_t kMaxVirtualRead = 0x2000;

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

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring out = value;
        for (wchar_t& ch : out)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return out;
    }

    bool EnableDebugPrivilege(std::wstring* warning)
    {
        bool ok = false;
        HANDLE token = nullptr;

        do
        {
            if (!OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &token))
            {
                if (warning != nullptr)
                {
                    *warning = L"OpenProcessToken failed";
                }
                break;
            }

            LUID luid = {};
            if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
            {
                if (warning != nullptr)
                {
                    *warning = L"LookupPrivilegeValue(SeDebugPrivilege) failed";
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
                    *warning = L"AdjustTokenPrivileges(SeDebugPrivilege) failed";
                }
                break;
            }
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                if (warning != nullptr)
                {
                    *warning = L"SeDebugPrivilege not assigned";
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
}

bool LeftoverTryAdd(uint64_t left, uint64_t right, uint64_t* result)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }
        if (left > (~0ull - right))
        {
            break;
        }
        *result = left + right;
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverIsKernelCanonical(uint64_t address)
{
    return address >= kLeftoverKernelMinLa48;
}

bool LeftoverIsLikelyUserAddress(uint64_t address)
{
    return address < 0x0000800000000000ull;
}

uint64_t LeftoverSignExtendVa(uint64_t address, bool la57)
{
    uint64_t result = address;

    do
    {
        if (la57)
        {
            if ((address & (1ull << 56)) != 0)
            {
                result |= 0xFF00000000000000ull;
            }
            else
            {
                result &= 0x01FFFFFFFFFFFFFFull;
            }
            break;
        }

        if ((address & (1ull << 47)) != 0)
        {
            result |= 0xFFFF000000000000ull;
        }
        else
        {
            result &= 0x0000FFFFFFFFFFFFull;
        }
    } while (false);

    return result;
}

bool LeftoverIsSessionSpace(uint64_t address)
{
    return address >= kLeftoverSessionSpaceMin && address < kLeftoverSessionSpaceEnd;
}

bool LeftoverProbePagePermissions(
    DeviceClient& device,
    uint64_t address,
    bool* present,
    bool* writable,
    bool* executable,
    uint64_t* physicalAddress)
{
    bool ok = false;

    do
    {
        if (present != nullptr)
        {
            *present = false;
        }
        if (writable != nullptr)
        {
            *writable = false;
        }
        if (executable != nullptr)
        {
            *executable = false;
        }
        if (physicalAddress != nullptr)
        {
            *physicalAddress = 0;
        }

        PhysicalTranslationInfo info = {};
        std::wstring translateError;
        if (!device.TranslateVirtual(0, address, 1, &info, &translateError))
        {
            break;
        }

        const bool la57 = (info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
        const uint64_t levels[5] = {
            info.Pml5e,
            info.Pml4e,
            info.Pdpte,
            info.Pde,
            info.Pte
        };
        const size_t startIndex = la57 ? 0 : 1;
        size_t walkCount = info.PagingLevels;
        if (walkCount > 5)
        {
            walkCount = 5;
        }

        bool mapped = walkCount > 0;
        bool writeOk = walkCount > 0;
        bool nxClear = walkCount > 0;
        for (size_t step = 0; step < walkCount; ++step)
        {
            const size_t levelIdx = startIndex + step;
            if (levelIdx >= 5)
            {
                break;
            }
            const uint64_t pte = levels[levelIdx];
            if ((pte & 1ull) == 0)
            {
                mapped = false;
            }
            if ((pte & (1ull << 1)) == 0)
            {
                writeOk = false;
            }
            if ((pte & (1ull << 63)) != 0)
            {
                nxClear = false;
            }
            if ((levelIdx == 2 || levelIdx == 3) && (pte & (1ull << 7)) != 0)
            {
                break;
            }
        }

        if (present != nullptr)
        {
            *present = mapped;
        }
        if (writable != nullptr)
        {
            *writable = mapped && writeOk;
        }
        if (executable != nullptr)
        {
            *executable = mapped && nxClear;
        }
        if (physicalAddress != nullptr)
        {
            *physicalAddress = info.PhysicalAddress;
        }
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverIsPageTableSelfMap(uint64_t address, uint64_t pteBase, bool la57)
{
    bool inside = false;

    do
    {
        if (pteBase == 0 || !LeftoverIsKernelCanonical(pteBase))
        {
            // Classic Win10 LA48 self-map window when MmPteBase is unresolved.
            if (!la57 &&
                address >= 0xFFFFF68000000000ull &&
                address < 0xFFFFF70000000000ull)
            {
                inside = true;
            }
            break;
        }

        // LA48 PTE array is 512 GB; LA57 is much larger. Use a conservative
        // window that still covers PDE/PPE/PXE layers above the PTE base.
        const uint64_t window = la57 ? (1ull << 48) : (1ull << 40);
        uint64_t end = 0;
        if (!LeftoverTryAdd(pteBase, window, &end))
        {
            break;
        }
        if (address >= pteBase && address < end)
        {
            inside = true;
        }
    } while (false);

    return inside;
}

uint64_t LeftoverDecodeVaFromPteAddress(uint64_t pteAddress, uint64_t pteBase, bool la57)
{
    uint64_t va = 0;

    do
    {
        if (pteAddress < pteBase)
        {
            break;
        }

        const uint64_t delta = pteAddress - pteBase;
        if ((delta & 7ull) != 0)
        {
            break;
        }
        if (delta > (la57 ? (1ull << 48) : (1ull << 40)))
        {
            break;
        }

        va = LeftoverSignExtendVa(delta << 9, la57);
    } while (false);

    return va;
}

bool LeftoverReadBytes(
    DeviceClient& device,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || length == 0 || length > kMaxVirtualRead)
        {
            if (error != nullptr)
            {
                *error = L"invalid leftover kernel read";
            }
            break;
        }
        if (!device.ReadMemory(address, length, bytes, error))
        {
            break;
        }
        if (bytes->size() != length)
        {
            if (error != nullptr)
            {
                *error = L"short leftover kernel read";
            }
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverReadU16(DeviceClient& device, uint64_t address, uint16_t* value, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }
        std::vector<uint8_t> bytes;
        if (!LeftoverReadBytes(device, address, sizeof(uint16_t), &bytes, error))
        {
            break;
        }
        memcpy(value, bytes.data(), sizeof(uint16_t));
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverReadU32(DeviceClient& device, uint64_t address, uint32_t* value, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }
        std::vector<uint8_t> bytes;
        if (!LeftoverReadBytes(device, address, sizeof(uint32_t), &bytes, error))
        {
            break;
        }
        memcpy(value, bytes.data(), sizeof(uint32_t));
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverReadU64(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }
        std::vector<uint8_t> bytes;
        if (!LeftoverReadBytes(device, address, sizeof(uint64_t), &bytes, error))
        {
            break;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverReadPhysicalPage(
    DeviceClient& device,
    uint64_t physicalAddress,
    std::vector<uint8_t>* page,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (page == nullptr)
        {
            break;
        }
        if ((physicalAddress & 0xFFFull) != 0)
        {
            if (error != nullptr)
            {
                *error = L"physical page address is not aligned";
            }
            break;
        }
        if (!device.ReadPhysical(physicalAddress, kLeftoverPageSize, page, error))
        {
            break;
        }
        if (page->size() != kLeftoverPageSize)
        {
            if (error != nullptr)
            {
                *error = L"short physical page read";
            }
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverLooksLikeUnicodeString(uint16_t length, uint16_t maximumLength, uint64_t buffer)
{
    bool ok = false;

    do
    {
        if ((length % 2) != 0 || (maximumLength % 2) != 0)
        {
            break;
        }
        if (maximumLength < length)
        {
            break;
        }
        if (maximumLength > kLeftoverMaxUnicodeBytes)
        {
            break;
        }
        if (length == 0)
        {
            ok = true;
            break;
        }
        if (!LeftoverIsKernelCanonical(buffer))
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

bool LeftoverReadUnicodeString(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint64_t address,
    std::wstring* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }
        value->clear();

        uint32_t lengthOffset = 0;
        uint32_t bufferOffset = 8;
        TypeFieldInfo lengthField = {};
        TypeFieldInfo bufferField = {};
        std::wstring ignored;
        if (symbols.FindField(L"nt!_UNICODE_STRING", L"Length", &lengthField, &ignored))
        {
            lengthOffset = lengthField.Offset;
        }
        if (symbols.FindField(L"nt!_UNICODE_STRING", L"Buffer", &bufferField, &ignored))
        {
            bufferOffset = bufferField.Offset;
        }

        uint64_t lengthAddress = 0;
        uint64_t bufferAddress = 0;
        if (!LeftoverTryAdd(address, lengthOffset, &lengthAddress) ||
            !LeftoverTryAdd(address, bufferOffset, &bufferAddress))
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING field address overflow";
            }
            break;
        }

        uint16_t length = 0;
        uint16_t maximumLength = 0;
        uint64_t buffer = 0;
        if (!LeftoverReadU16(device, lengthAddress, &length, error))
        {
            break;
        }
        uint64_t maxAddress = 0;
        if (LeftoverTryAdd(lengthAddress, sizeof(uint16_t), &maxAddress))
        {
            LeftoverReadU16(device, maxAddress, &maximumLength, nullptr);
        }
        if (!LeftoverReadU64(device, bufferAddress, &buffer, error))
        {
            break;
        }

        if (length == 0)
        {
            ok = true;
            break;
        }
        if (!LeftoverLooksLikeUnicodeString(length, maximumLength == 0 ? length : maximumLength, buffer))
        {
            if (error != nullptr)
            {
                *error = L"UNICODE_STRING fields are not plausible";
            }
            break;
        }

        uint32_t readBytes = length;
        if (readBytes > kLeftoverMaxUnicodeBytes)
        {
            readBytes = kLeftoverMaxUnicodeBytes;
        }

        std::vector<uint8_t> bytes;
        if (!LeftoverReadBytes(device, buffer, readBytes, &bytes, error))
        {
            break;
        }

        value->assign(
            reinterpret_cast<const wchar_t*>(bytes.data()),
            bytes.size() / sizeof(wchar_t));
        while (!value->empty() && (value->back() == L'\0' || value->back() < 0x20))
        {
            value->pop_back();
        }
        ok = true;
    } while (false);

    return ok;
}

void LeftoverBuildModuleRanges(
    const SymbolEngine& symbols,
    std::vector<LeftoverModuleRange>* ranges)
{
    if (ranges == nullptr)
    {
        return;
    }

    ranges->clear();
    ranges->reserve(symbols.Modules().size());
    for (const KernelModuleInfo& module : symbols.Modules())
    {
        uint64_t end = 0;
        if (module.Base == 0 || module.Size == 0)
        {
            continue;
        }
        if (!LeftoverTryAdd(module.Base, module.Size, &end))
        {
            continue;
        }

        LeftoverModuleRange range = {};
        range.Base = module.Base;
        range.End = end;
        range.Name = module.ImageName.empty() ? module.ImagePath : module.ImageName;
        ranges->push_back(range);
    }

    std::sort(
        ranges->begin(),
        ranges->end(),
        [](const LeftoverModuleRange& left, const LeftoverModuleRange& right)
        {
            return left.Base < right.Base;
        });
}

const LeftoverModuleRange* LeftoverFindModule(
    const std::vector<LeftoverModuleRange>& ranges,
    uint64_t address)
{
    const LeftoverModuleRange* found = nullptr;

    do
    {
        if (ranges.empty())
        {
            break;
        }

        size_t lo = 0;
        size_t hi = ranges.size();
        while (lo < hi)
        {
            const size_t mid = lo + ((hi - lo) / 2);
            if (address < ranges[mid].Base)
            {
                hi = mid;
            }
            else
            {
                lo = mid + 1;
            }
        }

        if (lo == 0)
        {
            break;
        }

        const LeftoverModuleRange& candidate = ranges[lo - 1];
        if (address >= candidate.Base && address < candidate.End)
        {
            found = &candidate;
        }
    } while (false);

    return found;
}

std::wstring LeftoverModuleBaseName(const std::wstring& pathOrName)
{
    std::wstring name = pathOrName;
    const size_t slash = name.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash + 1 < name.size())
    {
        name = name.substr(slash + 1);
    }
    return name;
}

bool LeftoverNamesMatch(const std::wstring& left, const std::wstring& right)
{
    return ToLowerCopy(LeftoverModuleBaseName(left)) ==
           ToLowerCopy(LeftoverModuleBaseName(right));
}

bool LeftoverLooksLikeDriverName(const std::wstring& name)
{
    bool ok = false;

    do
    {
        if (name.empty() || name.size() > 256)
        {
            break;
        }

        uint32_t printable = 0;
        bool hasDot = false;
        bool hasSlash = false;
        for (wchar_t ch : name)
        {
            if (ch == L'.')
            {
                hasDot = true;
            }
            if (ch == L'\\' || ch == L'/')
            {
                hasSlash = true;
            }
            if (ch < 0x20 || ch == 0x7F)
            {
                printable = 0;
                break;
            }
            ++printable;
        }
        if (printable == 0)
        {
            break;
        }

        const std::wstring base = ToLowerCopy(LeftoverModuleBaseName(name));
        const bool sysSuffix =
            base.size() > 4 &&
            base.compare(base.size() - 4, 4, L".sys") == 0;
        ok = sysSuffix || hasSlash || hasDot;
    } while (false);

    return ok;
}

bool LeftoverQueryBigPool(LeftoverBigPoolSnapshot* snapshot, std::wstring* error)
{
    bool ok = false;
    void* raw = nullptr;

    do
    {
        if (snapshot == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"big pool snapshot output is null";
            }
            break;
        }

        *snapshot = LeftoverBigPoolSnapshot{};
        std::wstring privWarn;
        if (EnableDebugPrivilege(&privWarn))
        {
            snapshot->PrivilegeEnabled = true;
        }
        else if (!privWarn.empty())
        {
            snapshot->Warnings.push_back(privWarn);
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"GetModuleHandleW(ntdll) failed";
            }
            break;
        }

        auto query = reinterpret_cast<PfnNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"NtQuerySystemInformation is unavailable";
            }
            break;
        }

        ULONG bufferSize = kInitialQueryBytes;
        ULONG retries = 0;
        bool fetched = false;
        ULONG returnLength = 0;
        NTSTATUS_LOCAL status = 0;

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
                    *error = L"HeapAlloc for SystemBigPoolInformation failed";
                }
                break;
            }

            returnLength = 0;
            status = query(kSystemBigPoolInformation, raw, bufferSize, &returnLength);
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
                        *error = L"SystemBigPoolInformation exceeded 64MB ceiling";
                    }
                    break;
                }
                if (++retries > kMaxQueryRetries)
                {
                    if (error != nullptr)
                    {
                        *error = L"SystemBigPoolInformation exceeded retry budget";
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
                    *error = L"NtQuerySystemInformation(SystemBigPoolInformation) failed: " +
                             std::wstring(buf);
                }
                break;
            }

            fetched = true;
            break;
        }

        if (!fetched)
        {
            break;
        }

        auto info = reinterpret_cast<SYSTEM_BIGPOOL_INFORMATION_LOCAL*>(raw);
        snapshot->TotalEntries = info->Count;
        snapshot->Entries.reserve(info->Count);
        const uint8_t* base = reinterpret_cast<const uint8_t*>(raw);
        const uint8_t* end = base + returnLength;
        const uint8_t* first = reinterpret_cast<const uint8_t*>(&info->Entries[0]);
        if (first > end)
        {
            if (error != nullptr)
            {
                *error = L"SystemBigPoolInformation buffer is truncated";
            }
            break;
        }

        const size_t maxEntries =
            static_cast<size_t>(end - first) / sizeof(SYSTEM_BIGPOOL_ENTRY_LOCAL);
        const ULONG count = (info->Count < maxEntries) ? info->Count : static_cast<ULONG>(maxEntries);
        for (ULONG index = 0; index < count; ++index)
        {
            const SYSTEM_BIGPOOL_ENTRY_LOCAL& src = info->Entries[index];
            LeftoverBigPoolEntry entry = {};
            const ULONG_PTR packed = reinterpret_cast<ULONG_PTR>(src.VirtualAddress);
            entry.NonPaged = (packed & 1u) != 0;
            entry.VirtualAddress = static_cast<uint64_t>(packed & ~static_cast<ULONG_PTR>(1));
            entry.SizeInBytes = src.SizeInBytes;
            entry.TagRaw = src.TagUlong;
            if (entry.VirtualAddress != 0 && entry.SizeInBytes != 0)
            {
                snapshot->Entries.push_back(entry);
            }
        }

        std::sort(
            snapshot->Entries.begin(),
            snapshot->Entries.end(),
            [](const LeftoverBigPoolEntry& left, const LeftoverBigPoolEntry& right)
            {
                return left.VirtualAddress < right.VirtualAddress;
            });
        snapshot->Queried = true;
        ok = true;
    } while (false);

    if (raw != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, raw);
    }

    return ok;
}

const LeftoverBigPoolEntry* LeftoverFindBigPool(
    const LeftoverBigPoolSnapshot& snapshot,
    uint64_t address)
{
    const LeftoverBigPoolEntry* found = nullptr;

    do
    {
        if (snapshot.Entries.empty())
        {
            break;
        }

        size_t lo = 0;
        size_t hi = snapshot.Entries.size();
        while (lo < hi)
        {
            const size_t mid = lo + ((hi - lo) / 2);
            if (address < snapshot.Entries[mid].VirtualAddress)
            {
                hi = mid;
            }
            else
            {
                lo = mid + 1;
            }
        }
        if (lo == 0)
        {
            break;
        }

        const LeftoverBigPoolEntry& candidate = snapshot.Entries[lo - 1];
        uint64_t end = 0;
        if (!LeftoverTryAdd(candidate.VirtualAddress, candidate.SizeInBytes, &end))
        {
            break;
        }
        if (address >= candidate.VirtualAddress && address < end)
        {
            found = &candidate;
        }
    } while (false);

    return found;
}

std::wstring LeftoverFormatHex(uint64_t value, int width)
{
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << std::setw(width) << std::setfill(L'0') << value;
    return stream.str();
}

std::wstring LeftoverFormatTag(uint32_t tagRaw)
{
    std::wstring text;
    text.reserve(4);
    for (int index = 0; index < 4; ++index)
    {
        const unsigned char ch = static_cast<unsigned char>((tagRaw >> (index * 8)) & 0xff);
        if (ch >= 0x20 && ch < 0x7f)
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

void LeftoverAppendNote(std::wstring* notes, const std::wstring& note)
{
    if (notes == nullptr || note.empty())
    {
        return;
    }
    if (notes->empty())
    {
        *notes = note;
    }
    else
    {
        *notes += L"; ";
        *notes += note;
    }
}

bool LeftoverCommonSelfTest()
{
    bool ok = true;

    do
    {
        uint64_t sum = 0;
        if (LeftoverTryAdd(1, 2, &sum) == false || sum != 3)
        {
            ok = false;
            break;
        }
        if (LeftoverTryAdd(~0ull, 1, &sum))
        {
            ok = false;
            break;
        }

        const uint64_t pteBase = 0xFFFFF68000000000ull;
        const uint64_t va = 0xFFFFF80012345000ull;
        const uint64_t va48 = va & 0x0000FFFFFFFFFFFFull;
        const uint64_t pteAddress = pteBase + ((va48 >> 12) * 8ull);
        const uint64_t decoded = LeftoverDecodeVaFromPteAddress(pteAddress, pteBase, false);
        if (decoded != va)
        {
            ok = false;
            break;
        }
        if (LeftoverDecodeVaFromPteAddress(pteBase + 1, pteBase, false) != 0)
        {
            ok = false;
            break;
        }
        if (!LeftoverIsPageTableSelfMap(pteBase + 0x1000, pteBase, false))
        {
            ok = false;
            break;
        }
        if (LeftoverIsPageTableSelfMap(0xFFFFF80000000000ull, pteBase, false))
        {
            ok = false;
            break;
        }
        if (!LeftoverIsSessionSpace(0xFFFFF90000100000ull) ||
            LeftoverIsSessionSpace(0xFFFFF80000000000ull))
        {
            ok = false;
            break;
        }

        std::vector<LeftoverModuleRange> ranges;
        LeftoverModuleRange first = {};
        first.Base = 0xFFFFF80000000000ull;
        first.End = 0xFFFFF80000200000ull;
        first.Name = L"ntoskrnl.exe";
        LeftoverModuleRange second = {};
        second.Base = 0xFFFFF80001000000ull;
        second.End = 0xFFFFF80001010000ull;
        second.Name = L"ci.dll";
        ranges.push_back(first);
        ranges.push_back(second);
        if (LeftoverFindModule(ranges, 0xFFFFF80000001000ull) == nullptr ||
            LeftoverFindModule(ranges, 0xFFFFF80001000010ull) == nullptr ||
            LeftoverFindModule(ranges, 0xFFFFF80000F00000ull) != nullptr)
        {
            ok = false;
            break;
        }

        if (!LeftoverNamesMatch(L"\\SystemRoot\\System32\\drivers\\Foo.SYS", L"foo.sys") ||
            !LeftoverLooksLikeDriverName(L"capcom.sys") ||
            LeftoverLooksLikeDriverName(L"\x01\x02"))
        {
            ok = false;
            break;
        }
        if (!LeftoverLooksLikeUnicodeString(10, 12, 0xFFFFF80000001000ull) ||
            LeftoverLooksLikeUnicodeString(11, 12, 0xFFFFF80000001000ull) ||
            LeftoverLooksLikeUnicodeString(10, 8, 0xFFFFF80000001000ull))
        {
            ok = false;
            break;
        }

        LeftoverBigPoolSnapshot pool = {};
        LeftoverBigPoolEntry entry = {};
        entry.VirtualAddress = 0xFFFFC08000000000ull;
        entry.SizeInBytes = 0x4000;
        entry.TagRaw = 0x546C6644;
        entry.NonPaged = true;
        pool.Entries.push_back(entry);
        if (LeftoverFindBigPool(pool, 0xFFFFC08000001000ull) == nullptr ||
            LeftoverFindBigPool(pool, 0xFFFFC08000004000ull) != nullptr)
        {
            ok = false;
            break;
        }
    } while (false);

    return ok;
}
