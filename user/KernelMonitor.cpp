#include "KernelMonitor.h"

#include "ByovdScanner.h"
#include "CallbackScanner.h"
#include "CrScanner.h"
#include "DpcTimerScanner.h"
#include "HalDispatchScanner.h"
#include "HiddenProcessScanner.h"
#include "HandleTableScanner.h"
#include "IdtScanner.h"
#include "InputStackScanner.h"
#include "IntegrityScanner.h"
#include "LeftoverCommon.h"
#include "MapperRemnantScanner.h"
#include "MinifilterIrpScanner.h"
#include "MsrScanner.h"
#include "NmiScanner.h"
#include "OrphanKernelPageScanner.h"
#include "PoolPeHunter.h"
#include "ProcessTriageScanner.h"
#include "SsdtScanner.h"
#include "VbsScanner.h"
#include "WfpCalloutScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <Softpub.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <utility>

namespace
{
    constexpr uint64_t kLogRotateBytes = 100ull * 1024ull * 1024ull;
    constexpr uint32_t kLogRotateCount = 5;
    constexpr size_t kPrintQueueCap = 1024;
    constexpr uint32_t kKpageScanIntervalMs = 20000;
    constexpr uint32_t kUserScanIntervalMs = 8000;
    constexpr uint32_t kMapperWatchWindowMs = 30000;
    constexpr uint32_t kMapperWatchMaxMs = 90000;
    constexpr uint32_t kMapperWatchIntervalMs = 400;
    constexpr uint32_t kMapperWatchKpageIntervalMs = 1500;
    constexpr uint32_t kMapperWatchEmitDebounceMs = 2000;
    constexpr uint16_t kImageFileMachineAmd64 = 0x8664;
    constexpr ULONG kProcessEnableLogging = 96;
    constexpr ULONG kProcessEnableReadWriteVmLogging = 87;

    std::wstring HexU64(uint64_t value)
    {
        wchar_t buf[32] = {};
        swprintf_s(buf, L"0x%llx", static_cast<unsigned long long>(value));
        return buf;
    }

    bool AddressOwnedByLoadedModule(SymbolEngine* symbols, uint64_t address)
    {
        bool owned = false;
        do
        {
            if (address == 0)
            {
                break;
            }
            // Empty module inventory must not mark every pointer unbacked.
            std::vector<KernelModuleInfo> modules;
            if (symbols != nullptr)
            {
                modules = symbols->CopyModules();
            }
            if (modules.empty())
            {
                owned = true;
                break;
            }
            for (const KernelModuleInfo& module : modules)
            {
                if (module.Base == 0 || module.Size == 0)
                {
                    continue;
                }
                const uint64_t size = static_cast<uint64_t>(module.Size);
                if (module.Base > (std::numeric_limits<uint64_t>::max)() - size)
                {
                    continue;
                }
                const uint64_t end = module.Base + size;
                if (address >= module.Base && address < end)
                {
                    owned = true;
                    break;
                }
            }
        } while (false);
        return owned;
    }

    uint64_t gLastKernelModuleReloadMs = 0;

    bool EnsureLoadedKernelModules(SymbolEngine* symbols, bool forceReload = false)
    {
        bool ok = false;
        do
        {
            if (symbols == nullptr)
            {
                break;
            }
            if (!symbols->CopyModules().empty())
            {
                if (!forceReload)
                {
                    ok = true;
                    break;
                }
                const uint64_t nowMs = GetTickCount64();
                if (gLastKernelModuleReloadMs != 0 &&
                    nowMs >= gLastKernelModuleReloadMs &&
                    (nowMs - gLastKernelModuleReloadMs) < 2000)
                {
                    ok = true;
                    break;
                }
            }
            std::wstring ignored;
            if (!symbols->LoadKernelModules(&ignored) || symbols->CopyModules().empty())
            {
                // EnumKernelModules failure does not clear modules_. Keep
                // the last good inventory instead of skipping every kmon
                // kernel scan until the next successful reload.
                if (!symbols->CopyModules().empty())
                {
                    ok = true;
                }
                break;
            }
            gLastKernelModuleReloadMs = GetTickCount64();
            ok = true;
        } while (false);
        return ok;
    }

    std::wstring ToLowerCopy(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch + (L'a' - L'A'));
            }
        }
        return value;
    }

    std::wstring MapperUnloadedFingerprint(const MapperUnloadedRecord& record)
    {
        return ToLowerCopy(record.Name) + L"@" + HexU64(record.StartAddress);
    }

    std::wstring MapperPiddbFingerprint(const MapperPiddbRecord& record)
    {
        return ToLowerCopy(record.DriverName) + L"@" + std::to_wstring(record.TimeDateStamp);
    }

    std::wstring MapperHashFingerprint(const MapperHashRecord& record)
    {
        return ToLowerCopy(record.DriverName);
    }

    std::wstring JsonEscape(const std::wstring& in)
    {
        std::wstring out;
        out.reserve(in.size() + 8);
        for (wchar_t c : in)
        {
            switch (c)
            {
                case L'"':
                    out += L"\\\"";
                    break;
                case L'\\':
                    out += L"\\\\";
                    break;
                case L'\n':
                    out += L"\\n";
                    break;
                case L'\r':
                    out += L"\\r";
                    break;
                case L'\t':
                    out += L"\\t";
                    break;
                default:
                    if (c < 0x20)
                    {
                        wchar_t esc[8] = {};
                        swprintf_s(esc, L"\\u%04x", static_cast<unsigned>(c));
                        out += esc;
                    }
                    else
                    {
                        out.push_back(c);
                    }
                    break;
            }
        }
        return out;
    }

    std::string WideToUtf8(const std::wstring& w)
    {
        if (w.empty() ||
            w.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        {
            return std::string();
        }
        int needed = WideCharToMultiByte(
            CP_UTF8,
            0,
            w.c_str(),
            static_cast<int>(w.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (needed <= 0)
        {
            return std::string();
        }
        std::string s(static_cast<size_t>(needed), '\0');
        const int converted = WideCharToMultiByte(
            CP_UTF8,
            0,
            w.c_str(),
            static_cast<int>(w.size()),
            &s[0],
            needed,
            nullptr,
            nullptr);
        if (converted != needed)
        {
            return std::string();
        }
        return s;
    }

    std::wstring TimestampUtcString(uint64_t fileTimeTicks)
    {
        FILETIME ft = {};
        ft.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFFull);
        ft.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);
        SYSTEMTIME st = {};
        if (!FileTimeToSystemTime(&ft, &st))
        {
            return L"1970-01-01T00:00:00.000Z";
        }
        wchar_t buf[64] = {};
        swprintf_s(
            buf,
            L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        return buf;
    }

    std::wstring ExeDirectory()
    {
        wchar_t buf[MAX_PATH] = {};
        DWORD len = GetModuleFileNameW(nullptr, buf, ARRAYSIZE(buf));
        if (len == 0 || len >= ARRAYSIZE(buf))
        {
            return L".";
        }
        std::wstring path(buf, len);
        size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return L".";
        }
        return path.substr(0, slash);
    }

    bool WatchTokenIsWildcard(const std::wstring& item)
    {
        return item == L"*" || item == L"*.sys" || item == L"*.exe";
    }

    struct KmonPeIdentity
    {
        uint32_t SizeOfImage = 0;
        uint32_t EntryPointRva = 0;
        uint32_t TimeDateStamp = 0;
        uint32_t CheckSum = 0;
        uint16_t Machine = 0;
        uint16_t NumberOfSections = 0;
        bool Is64 = false;
    };

    bool ParseKmonPeIdentity(const std::vector<uint8_t>& bytes, KmonPeIdentity* identity)
    {
        bool ok = false;
        do
        {
            if (identity == nullptr ||
                bytes.size() < sizeof(IMAGE_DOS_HEADER) + 4 + sizeof(IMAGE_FILE_HEADER) + 2)
            {
                break;
            }
            *identity = KmonPeIdentity{};
            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, bytes.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            {
                break;
            }
            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            if (ntOffset < sizeof(IMAGE_DOS_HEADER) ||
                static_cast<uint64_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER) + 2 > bytes.size())
            {
                break;
            }
            uint32_t signature = 0;
            std::memcpy(&signature, bytes.data() + ntOffset, sizeof(signature));
            if (signature != IMAGE_NT_SIGNATURE)
            {
                break;
            }
            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                bytes.data() + ntOffset + 4,
                sizeof(fileHeader));
            identity->TimeDateStamp = fileHeader.TimeDateStamp;
            identity->Machine = fileHeader.Machine;
            identity->NumberOfSections = fileHeader.NumberOfSections;
            const size_t optionalOffset =
                static_cast<size_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER);
            uint16_t magic = 0;
            std::memcpy(&magic, bytes.data() + optionalOffset, sizeof(magic));
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                if (optionalOffset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) + 4 > bytes.size())
                {
                    break;
                }
                IMAGE_OPTIONAL_HEADER64 optional = {};
                std::memcpy(
                    &optional,
                    bytes.data() + optionalOffset,
                    (std::min)(bytes.size() - optionalOffset, sizeof(optional)));
                identity->SizeOfImage = optional.SizeOfImage;
                identity->EntryPointRva = optional.AddressOfEntryPoint;
                identity->CheckSum = optional.CheckSum;
                identity->Is64 = true;
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                if (optionalOffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage) + 4 > bytes.size())
                {
                    break;
                }
                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(
                    &optional,
                    bytes.data() + optionalOffset,
                    (std::min)(bytes.size() - optionalOffset, sizeof(optional)));
                identity->SizeOfImage = optional.SizeOfImage;
                identity->EntryPointRva = optional.AddressOfEntryPoint;
                identity->CheckSum = optional.CheckSum;
                identity->Is64 = false;
            }
            else
            {
                break;
            }
            ok = identity->SizeOfImage != 0;
        } while (false);
        return ok;
    }

    struct KmonPeLayout
    {
        uint32_t SizeOfImage = 0;
        uint32_t EntryPointRva = 0;
        uint32_t TimeDateStamp = 0;
        uint32_t CheckSum = 0;
        uint16_t Machine = 0;
        uint16_t NumberOfSections = 0;
        uint64_t PreferredBase = 0;
        uint32_t ExecRva = 0;
        uint32_t ExecFileOffset = 0;
        uint32_t ExecSize = 0;
        uint32_t ExecVirtSize = 0;
        uint32_t RelocRva = 0;
        uint32_t RelocSize = 0;
        uint32_t ImportRva = 0;
        uint32_t ImportSize = 0;
        uint32_t DelayImportRva = 0;
        uint32_t DelayImportSize = 0;
        uint32_t ExportRva = 0;
        uint32_t ExportSize = 0;
        bool Is64 = false;
    };

    bool RvaToFileOffset(
        const std::vector<uint8_t>& headers,
        uint32_t rva,
        uint32_t* fileOffset)
    {
        bool ok = false;
        do
        {
            if (fileOffset == nullptr || headers.size() < sizeof(IMAGE_DOS_HEADER))
            {
                break;
            }
            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, headers.data(), sizeof(dos));
            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            if (static_cast<uint64_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER) > headers.size())
            {
                break;
            }
            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                headers.data() + ntOffset + 4,
                sizeof(fileHeader));
            const size_t sectionOffset =
                static_cast<size_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER) +
                fileHeader.SizeOfOptionalHeader;
            for (uint16_t i = 0; i < fileHeader.NumberOfSections; ++i)
            {
                const size_t off = sectionOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                if (off + sizeof(IMAGE_SECTION_HEADER) > headers.size())
                {
                    break;
                }
                IMAGE_SECTION_HEADER section = {};
                std::memcpy(&section, headers.data() + off, sizeof(section));
                const uint32_t sectionSpan =
                    (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
                if (rva >= section.VirtualAddress &&
                    static_cast<uint64_t>(rva) <
                        static_cast<uint64_t>(section.VirtualAddress) + sectionSpan)
                {
                    const uint32_t delta = rva - section.VirtualAddress;
                    if (section.SizeOfRawData == 0 || delta >= section.SizeOfRawData)
                    {
                        break;
                    }
                    if (section.PointerToRawData >
                        (std::numeric_limits<uint32_t>::max)() - delta)
                    {
                        break;
                    }
                    *fileOffset = section.PointerToRawData + delta;
                    ok = true;
                    break;
                }
            }
        } while (false);
        return ok;
    }

    bool ParseKmonPeLayout(const std::vector<uint8_t>& headers, KmonPeLayout* layout)
    {
        bool ok = false;
        do
        {
            if (layout == nullptr)
            {
                break;
            }
            *layout = KmonPeLayout{};
            KmonPeIdentity identity = {};
            if (!ParseKmonPeIdentity(headers, &identity))
            {
                break;
            }
            layout->SizeOfImage = identity.SizeOfImage;
            layout->EntryPointRva = identity.EntryPointRva;
            layout->TimeDateStamp = identity.TimeDateStamp;
            layout->CheckSum = identity.CheckSum;
            layout->Machine = identity.Machine;
            layout->NumberOfSections = identity.NumberOfSections;
            layout->Is64 = identity.Is64;

            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, headers.data(), sizeof(dos));
            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(&fileHeader, headers.data() + ntOffset + 4, sizeof(fileHeader));
            const size_t optionalOffset =
                static_cast<size_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER);
            uint16_t magic = 0;
            std::memcpy(&magic, headers.data() + optionalOffset, sizeof(magic));
            uint32_t relocRva = 0;
            uint32_t relocSize = 0;
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) <= headers.size())
            {
                IMAGE_OPTIONAL_HEADER64 optional = {};
                std::memcpy(&optional, headers.data() + optionalOffset, sizeof(optional));
                layout->PreferredBase = optional.ImageBase;
                layout->Is64 = true;
                relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                layout->ImportRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                layout->ImportSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                layout->DelayImportRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                layout->DelayImportSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
                layout->ExportRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                layout->ExportSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) <= headers.size())
            {
                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(&optional, headers.data() + optionalOffset, sizeof(optional));
                layout->PreferredBase = optional.ImageBase;
                relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                layout->ImportRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                layout->ImportSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                layout->DelayImportRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                layout->DelayImportSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
                layout->ExportRva =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                layout->ExportSize =
                    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            else
            {
                break;
            }
            layout->RelocRva = relocRva;
            layout->RelocSize = relocSize;

            const size_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
            for (uint16_t i = 0; i < fileHeader.NumberOfSections; ++i)
            {
                const size_t off = sectionOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                if (off + sizeof(IMAGE_SECTION_HEADER) > headers.size())
                {
                    break;
                }
                IMAGE_SECTION_HEADER section = {};
                std::memcpy(&section, headers.data() + off, sizeof(section));
                if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
                    (section.Characteristics & IMAGE_SCN_CNT_CODE) == 0)
                {
                    continue;
                }
                layout->ExecRva = section.VirtualAddress;
                layout->ExecFileOffset = section.PointerToRawData;
                uint32_t raw = section.SizeOfRawData;
                uint32_t virt = section.Misc.VirtualSize;
                layout->ExecVirtSize = (virt != 0) ? virt : raw;
                uint32_t n = raw;
                if (virt != 0 && virt < n)
                {
                    n = virt;
                }
                // First executable page. 0x400 left a hole at +0x400..+0xFFF
                // that exe_text_page (next page) does not cover.
                if (n > 0x1000)
                {
                    n = 0x1000;
                }
                layout->ExecSize = n;
                break;
            }
            ok = layout->SizeOfImage != 0;
        } while (false);
        return ok;
    }

    bool ParseFirstExecSection(
        const std::vector<uint8_t>& headers,
        uint32_t* rva,
        uint32_t* fileOffset,
        uint32_t* rawSize)
    {
        bool ok = false;
        do
        {
            if (rva == nullptr || fileOffset == nullptr || rawSize == nullptr)
            {
                break;
            }
            *rva = 0;
            *fileOffset = 0;
            *rawSize = 0;
            if (headers.size() < sizeof(IMAGE_DOS_HEADER))
            {
                break;
            }
            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, headers.data(), sizeof(dos));
            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            if (static_cast<uint64_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER) >
                headers.size())
            {
                break;
            }
            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                headers.data() + ntOffset + 4,
                sizeof(fileHeader));
            const size_t optionalOffset =
                static_cast<size_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER);
            uint16_t magic = 0;
            if (optionalOffset + sizeof(magic) > headers.size())
            {
                break;
            }
            std::memcpy(&magic, headers.data() + optionalOffset, sizeof(magic));
            if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                break;
            }
            const size_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
            for (uint16_t i = 0; i < fileHeader.NumberOfSections; ++i)
            {
                const size_t off =
                    sectionOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                if (off + sizeof(IMAGE_SECTION_HEADER) > headers.size())
                {
                    break;
                }
                IMAGE_SECTION_HEADER section = {};
                std::memcpy(&section, headers.data() + off, sizeof(section));
                if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
                    (section.Characteristics & IMAGE_SCN_CNT_CODE) == 0)
                {
                    continue;
                }
                uint32_t n = section.SizeOfRawData;
                if (section.Misc.VirtualSize != 0 && section.Misc.VirtualSize < n)
                {
                    n = section.Misc.VirtualSize;
                }
                if (n > 0x40000)
                {
                    n = 0x40000;
                }
                if (n < 16)
                {
                    break;
                }
                *rva = section.VirtualAddress;
                *fileOffset = section.PointerToRawData;
                *rawSize = n;
                ok = true;
                break;
            }
        } while (false);
        return ok;
    }

    void ApplyRelocsToSlice(
        std::vector<uint8_t>* slice,
        uint32_t sliceRva,
        uint64_t delta,
        const std::vector<uint8_t>& relocs,
        bool is64)
    {
        if (slice == nullptr || slice->empty() || relocs.size() < sizeof(IMAGE_BASE_RELOCATION) || delta == 0)
        {
            return;
        }
        size_t cursor = 0;
        while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= relocs.size())
        {
            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, relocs.data() + cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                cursor + block.SizeOfBlock > relocs.size())
            {
                break;
            }
            const uint32_t count =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            for (uint32_t i = 0; i < count; ++i)
            {
                uint16_t entry = 0;
                std::memcpy(
                    &entry,
                    relocs.data() + cursor + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(uint16_t),
                    sizeof(entry));
                const uint16_t type = static_cast<uint16_t>(entry >> 12);
                const uint16_t offset = static_cast<uint16_t>(entry & 0x0fff);
                if (offset > (std::numeric_limits<uint32_t>::max)() - block.VirtualAddress)
                {
                    continue;
                }
                const uint32_t rva = block.VirtualAddress + offset;
                if (slice->size() > (std::numeric_limits<uint32_t>::max)() ||
                    sliceRva > (std::numeric_limits<uint32_t>::max)() -
                        static_cast<uint32_t>(slice->size()) ||
                    rva < sliceRva ||
                    rva >= sliceRva + static_cast<uint32_t>(slice->size()))
                {
                    continue;
                }
                const uint32_t local = rva - sliceRva;
                if (type == IMAGE_REL_BASED_DIR64 && is64 && local + 8 <= slice->size())
                {
                    uint64_t value = 0;
                    std::memcpy(&value, slice->data() + local, 8);
                    value += delta;
                    std::memcpy(slice->data() + local, &value, 8);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW &&
                    !is64 &&
                    local + 4 <= slice->size())
                {
                    uint32_t value = 0;
                    std::memcpy(&value, slice->data() + local, 4);
                    value += static_cast<uint32_t>(delta);
                    std::memcpy(slice->data() + local, &value, 4);
                }
            }
            cursor += block.SizeOfBlock;
        }
    }

    bool ReadDiskRange(const std::wstring& path, uint32_t fileOffset, uint32_t length, std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        do
        {
            if (bytes == nullptr || path.empty() || length == 0 || length > 0x10000)
            {
                break;
            }
            handle = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                break;
            }
            LARGE_INTEGER pos = {};
            pos.QuadPart = fileOffset;
            if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN))
            {
                break;
            }
            bytes->assign(length, 0);
            DWORD read = 0;
            if (!ReadFile(handle, bytes->data(), length, &read, nullptr) ||
                read != length)
            {
                bytes->clear();
                break;
            }
            ok = true;
        } while (false);
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        return ok;
    }

    bool ReadDiskPeHead(const std::wstring& path, std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        do
        {
            if (bytes == nullptr || path.empty())
            {
                break;
            }
            handle = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                break;
            }
            bytes->assign(0x2000, 0);
            DWORD read = 0;
            if (!ReadFile(handle, bytes->data(), 0x2000, &read, nullptr) || read < sizeof(IMAGE_DOS_HEADER))
            {
                bytes->clear();
                break;
            }
            bytes->resize(read);
            ok = true;
        } while (false);
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        return ok;
    }

    bool ReadDiskFileRange(
        const std::wstring& path,
        uint32_t offset,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        do
        {
            if (bytes == nullptr || path.empty() || length == 0 || length > 0x40000)
            {
                break;
            }
            handle = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                break;
            }
            LARGE_INTEGER pos = {};
            pos.QuadPart = offset;
            if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN))
            {
                break;
            }
            bytes->assign(length, 0);
            DWORD read = 0;
            if (!ReadFile(handle, bytes->data(), length, &read, nullptr) || read == 0)
            {
                bytes->clear();
                break;
            }
            bytes->resize(read);
            ok = true;
        } while (false);
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        return ok;
    }

    bool PathLooksLikeWin32File(const std::wstring& path);

    bool KmonImageAuthenticodeValid(const std::wstring& path)
    {
        bool valid = false;
        do
        {
            if (path.empty() || !PathLooksLikeWin32File(path))
            {
                break;
            }
            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = path.c_str();
            WINTRUST_DATA data = {};
            data.cbStruct = sizeof(data);
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.pFile = &fileInfo;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
            valid = status == ERROR_SUCCESS;
        } while (false);
        return valid;
    }

    bool ExportNameLooksLikeGuardDispatch(const char* name)
    {
        if (name == nullptr || name[0] == '\0')
        {
            return false;
        }
        if (name[0] == '_')
        {
            ++name;
        }
        return _stricmp(name, "guard_dispatch_icall") == 0 ||
            _stricmp(name, "guard_dispatch_icall_nop") == 0;
    }

    uint32_t FindPeExportRvaByName(
        const std::wstring& path,
        const std::vector<uint8_t>& headers,
        const char* exportName)
    {
        uint32_t found = 0;
        do
        {
            KmonPeLayout layout = {};
            if (exportName == nullptr || !ParseKmonPeLayout(headers, &layout))
            {
                break;
            }
            if (layout.ExportRva == 0 || layout.ExportSize < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                break;
            }
            uint32_t fileOff = 0;
            if (!RvaToFileOffset(headers, layout.ExportRva, &fileOff))
            {
                break;
            }
            std::vector<uint8_t> expDir;
            if (!ReadDiskFileRange(
                    path,
                    fileOff,
                    (std::min)(layout.ExportSize, 0x10000u),
                    &expDir) ||
                expDir.size() < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                break;
            }
            IMAGE_EXPORT_DIRECTORY exports = {};
            std::memcpy(&exports, expDir.data(), sizeof(exports));
            if (exports.NumberOfNames == 0 || exports.NumberOfNames > 8192)
            {
                break;
            }
            uint32_t namesOff = 0;
            uint32_t ordsOff = 0;
            uint32_t funcsOff = 0;
            if (!RvaToFileOffset(headers, exports.AddressOfNames, &namesOff) ||
                !RvaToFileOffset(headers, exports.AddressOfNameOrdinals, &ordsOff) ||
                !RvaToFileOffset(headers, exports.AddressOfFunctions, &funcsOff))
            {
                break;
            }
            std::vector<uint8_t> names;
            std::vector<uint8_t> ords;
            std::vector<uint8_t> funcs;
            const uint32_t nameBytes = exports.NumberOfNames * 4;
            const uint32_t ordBytes = exports.NumberOfNames * 2;
            const uint32_t funcBytes = exports.NumberOfFunctions * 4;
            if (!ReadDiskFileRange(path, namesOff, nameBytes, &names) ||
                !ReadDiskFileRange(path, ordsOff, ordBytes, &ords) ||
                !ReadDiskFileRange(path, funcsOff, funcBytes, &funcs) ||
                names.size() < nameBytes ||
                ords.size() < ordBytes ||
                funcs.size() < funcBytes)
            {
                break;
            }
            for (uint32_t i = 0; i < exports.NumberOfNames; ++i)
            {
                uint32_t nameRva = 0;
                uint16_t ordinal = 0;
                std::memcpy(&nameRva, names.data() + i * 4, 4);
                std::memcpy(&ordinal, ords.data() + i * 2, 2);
                uint32_t nameFile = 0;
                if (!RvaToFileOffset(headers, nameRva, &nameFile))
                {
                    continue;
                }
                std::vector<uint8_t> nameBytesRead;
                if (!ReadDiskFileRange(path, nameFile, 64, &nameBytesRead) ||
                    nameBytesRead.empty())
                {
                    continue;
                }
                nameBytesRead.back() = 0;
                const char* name =
                    reinterpret_cast<const char*>(nameBytesRead.data());
                if (!ExportNameLooksLikeGuardDispatch(name) &&
                    _stricmp(name, exportName) != 0)
                {
                    continue;
                }
                if (static_cast<uint32_t>(ordinal) >= exports.NumberOfFunctions)
                {
                    continue;
                }
                uint32_t rva = 0;
                std::memcpy(&rva, funcs.data() + static_cast<size_t>(ordinal) * 4, 4);
                if (rva != 0 && rva < layout.SizeOfImage)
                {
                    found = rva;
                    break;
                }
            }
        } while (false);
        return found;
    }

    uint64_t QueryProcessCreateTicks(HANDLE process)
    {
        FILETIME created = {};
        FILETIME exited = {};
        FILETIME kernelTime = {};
        FILETIME userTime = {};
        if (process == nullptr ||
            !GetProcessTimes(process, &created, &exited, &kernelTime, &userTime))
        {
            return 0;
        }
        return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }

    uint64_t QueryEprocessCreateTime(
        DeviceClient* device,
        SymbolEngine* symbols,
        HANDLE process,
        uint64_t eprocess)
    {
        if (process != nullptr)
        {
            const uint64_t fromHandle = QueryProcessCreateTicks(process);
            if (fromHandle != 0)
            {
                return fromHandle;
            }
        }
        if (device == nullptr || symbols == nullptr || eprocess == 0 || !device->IsOpen())
        {
            return 0;
        }

        TypeFieldInfo createField = {};
        std::wstring ignored;
        if (!symbols->FindField(L"nt!_EPROCESS", L"CreateTime", &createField, &ignored) &&
            !symbols->FindField(L"_EPROCESS", L"CreateTime", &createField, &ignored))
        {
            return 0;
        }

        uint32_t length = sizeof(uint64_t);
        if (createField.Length != 0 && createField.Length <= 8)
        {
            length = static_cast<uint32_t>(createField.Length);
        }
        if (createField.Offset > (std::numeric_limits<uint64_t>::max)() - eprocess)
        {
            return 0;
        }

        std::vector<uint8_t> bytes;
        if (!device->ReadMemory(
                eprocess + static_cast<uint64_t>(createField.Offset),
                length,
                &bytes,
                &ignored) ||
            bytes.size() < length)
        {
            return 0;
        }

        uint64_t value = 0;
        std::memcpy(&value, bytes.data(), length);
        return value;
    }

    uint64_t QueryPidCreateTime(
        DeviceClient* device,
        SymbolEngine* symbols,
        HANDLE process,
        uint32_t pid)
    {
        if (process != nullptr)
        {
            const uint64_t fromHandle = QueryProcessCreateTicks(process);
            if (fromHandle != 0)
            {
                return fromHandle;
            }
        }
        if (device == nullptr || symbols == nullptr || pid <= 4 || !device->IsOpen())
        {
            return 0;
        }

        TypeFieldInfo dtbField = {};
        std::wstring ignored;
        if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
        {
            return 0;
        }

        ProcessAddressContext ctx = {};
        if (!device->ResolveProcess(
                pid,
                static_cast<uint32_t>(dtbField.Offset),
                0,
                &ctx,
                &ignored) ||
            ctx.Eprocess == 0)
        {
            return 0;
        }

        return QueryEprocessCreateTime(device, symbols, nullptr, ctx.Eprocess);
    }

    bool ReadProcessVirtualChecked(
        DeviceClient* device,
        SymbolEngine* symbols,
        HANDLE process,
        uint32_t pid,
        uint64_t eprocess,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        do
        {
            if (bytes == nullptr ||
                device == nullptr ||
                pid <= 4 ||
                eprocess == 0 ||
                address == 0 ||
                length == 0)
            {
                break;
            }
            const uint64_t createTime = QueryEprocessCreateTime(
                device,
                symbols,
                process,
                eprocess);
            if (createTime == 0)
            {
                break;
            }
            std::wstring ignored;
            ok = device->ReadProcessVirtual(
                pid,
                eprocess,
                createTime,
                address,
                length,
                bytes,
                &ignored);
        } while (false);
        return ok;
    }

    bool ReadProcessBytes(
        DeviceClient* device,
        SymbolEngine* symbols,
        HANDLE process,
        uint32_t pid,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        do
        {
            if (bytes == nullptr || pid <= 4 || address == 0 || length == 0 || length > 0x10000)
            {
                break;
            }
            if (process != nullptr)
            {
                bytes->assign(length, 0);
                SIZE_T read = 0;
                if (ReadProcessMemory(
                        process,
                        reinterpret_cast<LPCVOID>(address),
                        bytes->data(),
                        length,
                        &read) &&
                    read == length)
                {
                    ok = true;
                    break;
                }
            }
            if (device == nullptr || symbols == nullptr || !device->IsOpen())
            {
                break;
            }
            TypeFieldInfo dtbField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }
            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }
            ok = ReadProcessVirtualChecked(
                device,
                symbols,
                process,
                pid,
                ctx.Eprocess,
                address,
                length,
                bytes);
        } while (false);
        return ok;
    }

    bool QueryMappedImagePath(HANDLE process, uint64_t address, std::wstring* path)
    {
        bool ok = false;
        do
        {
            if (path != nullptr)
            {
                path->clear();
            }
            if (process == nullptr || address == 0 || path == nullptr)
            {
                break;
            }
            for (DWORD capacity = 512; capacity <= 32768; capacity *= 2)
            {
                std::vector<wchar_t> buffer(capacity, L'\0');
                const DWORD copied = GetMappedFileNameW(
                    process,
                    reinterpret_cast<LPVOID>(address),
                    buffer.data(),
                    capacity);
                if (copied == 0)
                {
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        continue;
                    }
                    break;
                }
                if (copied < capacity - 1)
                {
                    path->assign(buffer.data(), copied);
                    ok = true;
                    break;
                }
            }
        } while (false);
        return ok;
    }

    bool ReadProcessPeHead(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t address,
        std::vector<uint8_t>* bytes)
    {
        HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        const bool ok = ReadProcessBytes(device, symbols, process, pid, address, 0x400, bytes);
        if (process != nullptr)
        {
            CloseHandle(process);
        }
        return ok;
    }

    bool IsUserModeImageBase(uint64_t address)
    {
        return address >= 0x10000ull && address <= 0x00007FFFFFFEFFFFull;
    }

    bool QuerySectionBaseAddress(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t* imageBase)
    {
        bool ok = false;
        do
        {
            if (imageBase != nullptr)
            {
                *imageBase = 0;
            }
            if (imageBase == nullptr ||
                device == nullptr ||
                symbols == nullptr ||
                pid <= 4 ||
                !device->IsOpen())
            {
                break;
            }

            TypeFieldInfo dtbField = {};
            TypeFieldInfo sectionField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }
            if (!symbols->FindField(L"nt!_EPROCESS", L"SectionBaseAddress", &sectionField, &ignored) &&
                !symbols->FindField(L"_EPROCESS", L"SectionBaseAddress", &sectionField, &ignored))
            {
                break;
            }

            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }
            if (sectionField.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
            {
                break;
            }

            uint32_t length = sizeof(uint64_t);
            if (sectionField.Length != 0 && sectionField.Length <= 8)
            {
                length = static_cast<uint32_t>(sectionField.Length);
            }
            std::vector<uint8_t> bytes;
            if (!device->ReadMemory(
                    ctx.Eprocess + static_cast<uint64_t>(sectionField.Offset),
                    length,
                    &bytes,
                    &ignored) ||
                bytes.size() < length)
            {
                break;
            }

            uint64_t value = 0;
            std::memcpy(&value, bytes.data(), length);
            if (!IsUserModeImageBase(value))
            {
                break;
            }
            *imageBase = value;
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadKernelUnicodeString(
        DeviceClient* device,
        uint64_t address,
        std::wstring* value)
    {
        bool ok = false;
        do
        {
            if (value != nullptr)
            {
                value->clear();
            }
            if (device == nullptr || address == 0 || value == nullptr || !device->IsOpen())
            {
                break;
            }
            if (address < 0xFFFF800000000000ull)
            {
                break;
            }
            std::vector<uint8_t> header;
            std::wstring ignored;
            if (!device->ReadMemory(address, 16, &header, &ignored) || header.size() < 16)
            {
                break;
            }
            uint16_t length = 0;
            uint64_t buffer = 0;
            std::memcpy(&length, header.data(), sizeof(length));
            std::memcpy(&buffer, header.data() + 8, sizeof(buffer));
            if (length == 0)
            {
                ok = true;
                break;
            }
            if ((length & 1u) != 0)
            {
                --length;
            }
            if (length == 0 || length > 2048 ||
                buffer < 0xFFFF800000000000ull)
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!device->ReadMemory(buffer, length, &bytes, &ignored) ||
                bytes.size() < 2)
            {
                break;
            }
            value->assign(
                reinterpret_cast<const wchar_t*>(bytes.data()),
                bytes.size() / sizeof(wchar_t));
            ok = !value->empty();
        } while (false);
        return ok;
    }

    bool PathLooksLikeWin32File(const std::wstring& path)
    {
        bool ok = false;
        do
        {
            std::wstring n = path;
            for (wchar_t& ch : n)
            {
                if (ch == L'/')
                {
                    ch = L'\\';
                }
            }
            if (n.size() >= 7 &&
                n.compare(0, 4, L"\\\\?\\") == 0 &&
                ((n[4] >= L'A' && n[4] <= L'Z') ||
                    (n[4] >= L'a' && n[4] <= L'z')) &&
                n[5] == L':' &&
                n[6] == L'\\')
            {
                ok = true;
                break;
            }
            if (n.size() >= 3 &&
                ((n[0] >= L'A' && n[0] <= L'Z') ||
                    (n[0] >= L'a' && n[0] <= L'z')) &&
                n[1] == L':' &&
                n[2] == L'\\')
            {
                ok = true;
            }
        } while (false);
        return ok;
    }

    std::wstring Win32PathFromKernelImagePath(const std::wstring& path)
    {
        std::wstring result = path;
        do
        {
            if (path.empty())
            {
                break;
            }

            std::wstring n = path;
            for (wchar_t& ch : n)
            {
                if (ch == L'/')
                {
                    ch = L'\\';
                }
            }
            std::wstring lowered = ToLowerCopy(n);

            bool stripped = true;
            while (stripped)
            {
                stripped = false;
                const std::wstring prefixes[] = {
                    L"\\\\?\\",
                    L"\\\\.\\",
                    L"\\??\\",
                    L"\\dosdevices\\"
                };
                for (const std::wstring& prefix : prefixes)
                {
                    if (lowered.size() >= prefix.size() &&
                        lowered.compare(0, prefix.size(), prefix) == 0)
                    {
                        n.erase(0, prefix.size());
                        lowered.erase(0, prefix.size());
                        stripped = true;
                        break;
                    }
                }
            }

            if (PathLooksLikeWin32File(n))
            {
                result = n;
                break;
            }

            const std::wstring systemRootSlash = L"\\systemroot\\";
            if (lowered.size() >= systemRootSlash.size() &&
                lowered.compare(0, systemRootSlash.size(), systemRootSlash) == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(
                        windowsDirectory,
                        ARRAYSIZE(windowsDirectory)) != 0)
                {
                    result = std::wstring(windowsDirectory) +
                        n.substr(systemRootSlash.size() - 1);
                    break;
                }
            }

            if (lowered.size() >= 8 &&
                lowered.compare(0, 8, L"\\device\\") == 0)
            {
                wchar_t drive[] = L"A:";
                for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
                {
                    drive[0] = letter;
                    wchar_t target[1024] = {};
                    const DWORD length = QueryDosDeviceW(
                        drive,
                        target,
                        ARRAYSIZE(target));
                    if (length == 0)
                    {
                        continue;
                    }
                    std::wstring deviceName = ToLowerCopy(target);
                    for (wchar_t& ch : deviceName)
                    {
                        if (ch == L'/')
                        {
                            ch = L'\\';
                        }
                    }
                    while (deviceName.size() > 1 && deviceName.back() == L'\\')
                    {
                        deviceName.pop_back();
                    }
                    if (deviceName.empty())
                    {
                        continue;
                    }
                    if (lowered.compare(0, deviceName.size(), deviceName) == 0 &&
                        (lowered.size() == deviceName.size() ||
                            lowered[deviceName.size()] == L'\\'))
                    {
                        result = std::wstring(drive) + n.substr(deviceName.size());
                        break;
                    }
                }
                break;
            }

            if (lowered.size() >= 9 &&
                lowered.compare(0, 9, L"\\windows\\") == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(
                        windowsDirectory,
                        ARRAYSIZE(windowsDirectory)) != 0)
                {
                    std::wstring windowsPath = windowsDirectory;
                    if (windowsPath.size() >= 2 && windowsPath[1] == L':')
                    {
                        result = windowsPath.substr(0, 2) + n;
                    }
                }
                break;
            }

            const bool wellKnownRoot =
                (lowered.size() >= 7 &&
                    lowered.compare(0, 7, L"\\users\\") == 0) ||
                (lowered.size() >= 14 &&
                    lowered.compare(0, 14, L"\\program files") == 0) ||
                (lowered.size() >= 13 &&
                    lowered.compare(0, 13, L"\\programdata\\") == 0);
            if (wellKnownRoot)
            {
                wchar_t drive[] = L"A:";
                for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
                {
                    drive[0] = letter;
                    std::wstring candidate = std::wstring(drive) + n;
                    if (GetFileAttributesW(candidate.c_str()) !=
                        INVALID_FILE_ATTRIBUTES)
                    {
                        result = std::move(candidate);
                        break;
                    }
                }
            }
        } while (false);
        return result;
    }

    bool QueryKernelImagePath(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        std::wstring* path)
    {
        bool ok = false;
        do
        {
            if (path != nullptr)
            {
                path->clear();
            }
            if (path == nullptr ||
                device == nullptr ||
                symbols == nullptr ||
                pid <= 4 ||
                !device->IsOpen())
            {
                break;
            }

            TypeFieldInfo dtbField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }

            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }

            TypeFieldInfo nameField = {};
            uint64_t nameInfo = 0;
            if ((symbols->FindField(
                    L"nt!_EPROCESS",
                    L"SeAuditProcessCreationInfo.ImageFileName",
                    &nameField,
                    &ignored) ||
                symbols->FindField(
                    L"nt!_EPROCESS",
                    L"SeAuditProcessCreationInfo",
                    &nameField,
                    &ignored)) &&
                nameField.Offset <= (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
            {
                std::vector<uint8_t> pointerBytes;
                if (device->ReadMemory(
                        ctx.Eprocess + static_cast<uint64_t>(nameField.Offset),
                        sizeof(uint64_t),
                        &pointerBytes,
                        &ignored) &&
                    pointerBytes.size() >= sizeof(uint64_t))
                {
                    std::memcpy(&nameInfo, pointerBytes.data(), sizeof(nameInfo));
                }
            }
            if (nameInfo >= 0xFFFF800000000000ull &&
                ReadKernelUnicodeString(device, nameInfo, path) &&
                !path->empty())
            {
                ok = true;
                break;
            }

            TypeFieldInfo imageFile = {};
            TypeFieldInfo fileName = {};
            if (!symbols->FindField(L"nt!_EPROCESS", L"ImageFilePointer", &imageFile, &ignored) ||
                !symbols->FindField(L"nt!_FILE_OBJECT", L"FileName", &fileName, &ignored))
            {
                break;
            }
            if (imageFile.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
            {
                break;
            }
            std::vector<uint8_t> fileBytes;
            if (!device->ReadMemory(
                    ctx.Eprocess + static_cast<uint64_t>(imageFile.Offset),
                    sizeof(uint64_t),
                    &fileBytes,
                    &ignored) ||
                fileBytes.size() < sizeof(uint64_t))
            {
                break;
            }
            uint64_t fileObject = 0;
            std::memcpy(&fileObject, fileBytes.data(), sizeof(fileObject));
            if (fileObject < 0xFFFF800000000000ull ||
                fileName.Offset > (std::numeric_limits<uint64_t>::max)() - fileObject)
            {
                break;
            }
            ok = ReadKernelUnicodeString(
                device,
                fileObject + static_cast<uint64_t>(fileName.Offset),
                path) &&
                !path->empty();
        } while (false);
        if (ok && path != nullptr && !path->empty())
        {
            std::wstring win32 = Win32PathFromKernelImagePath(*path);
            if (PathLooksLikeWin32File(win32))
            {
                *path = std::move(win32);
            }
        }
        return ok;
    }

    bool QueryProcessIsWow64(
        HANDLE process,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        bool* wow64)
    {
        bool ok = false;
        do
        {
            if (wow64 == nullptr)
            {
                break;
            }
            *wow64 = false;
            if (process != nullptr)
            {
                BOOL flag = FALSE;
                if (IsWow64Process(process, &flag))
                {
                    *wow64 = flag != FALSE;
                    ok = true;
                    break;
                }
            }
            if (device == nullptr ||
                symbols == nullptr ||
                pid <= 4 ||
                !device->IsOpen())
            {
                break;
            }
            TypeFieldInfo dtbField = {};
            TypeFieldInfo wow64Field = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }
            if (!symbols->FindField(L"nt!_EPROCESS", L"Wow64Process", &wow64Field, &ignored))
            {
                break;
            }
            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }
            if (wow64Field.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
            {
                break;
            }
            std::vector<uint8_t> wowBytes;
            if (!device->ReadMemory(
                    ctx.Eprocess + static_cast<uint64_t>(wow64Field.Offset),
                    sizeof(uint64_t),
                    &wowBytes,
                    &ignored) ||
                wowBytes.size() < sizeof(uint64_t))
            {
                break;
            }
            uint64_t wow64Process = 0;
            std::memcpy(&wow64Process, wowBytes.data(), sizeof(wow64Process));
            *wow64 = wow64Process != 0;
            ok = true;
        } while (false);
        return ok;
    }

    bool QueryPebImageBase(
        HANDLE process,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t* imageBase)
    {
        bool ok = false;
        do
        {
            if (imageBase == nullptr || pid <= 4)
            {
                break;
            }
            *imageBase = 0;
            bool wow64Peb = false;

            if (process != nullptr)
            {
                BOOL wow64Flag = FALSE;
                if (IsWow64Process(process, &wow64Flag) && wow64Flag)
                {
                    wow64Peb = true;
                }
                using NtQueryInformationProcessFn =
                    LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                static NtQueryInformationProcessFn query = nullptr;
                static bool resolved = false;
                if (!resolved)
                {
                    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                    if (ntdll != nullptr)
                    {
                        query = reinterpret_cast<NtQueryInformationProcessFn>(
                            GetProcAddress(ntdll, "NtQueryInformationProcess"));
                    }
                    resolved = true;
                }
                struct KmonProcessBasicInformation
                {
                    PVOID Reserved1;
                    PVOID PebBaseAddress;
                    PVOID Reserved2[2];
                    ULONG_PTR UniqueProcessId;
                    PVOID Reserved3;
                };
                constexpr ULONG kProcessBasicInformation = 0;
                constexpr ULONG kProcessWow64Information = 26;
                ULONG returned = 0;
                ULONG_PTR peb32 = 0;
                if (query != nullptr &&
                    query(
                        process,
                        kProcessWow64Information,
                        &peb32,
                        sizeof(peb32),
                        &returned) >= 0 &&
                    peb32 != 0)
                {
                    wow64Peb = true;
                    std::vector<uint8_t> baseBytes;
                    if (ReadProcessBytes(
                            device,
                            symbols,
                            process,
                            pid,
                            static_cast<uint64_t>(peb32) + 0x08,
                            sizeof(uint32_t),
                            &baseBytes) &&
                        baseBytes.size() >= sizeof(uint32_t))
                    {
                        uint32_t base32 = 0;
                        std::memcpy(&base32, baseBytes.data(), sizeof(base32));
                        if (IsUserModeImageBase(base32))
                        {
                            *imageBase = base32;
                            ok = true;
                            break;
                        }
                    }
                }
                if (!wow64Peb)
                {
                    KmonProcessBasicInformation pbi = {};
                    returned = 0;
                    if (query != nullptr &&
                        query(
                            process,
                            kProcessBasicInformation,
                            &pbi,
                            sizeof(pbi),
                            &returned) >= 0 &&
                        pbi.PebBaseAddress != nullptr)
                    {
                        const uint64_t peb = reinterpret_cast<uint64_t>(pbi.PebBaseAddress);
                        std::vector<uint8_t> baseBytes;
                        if (IsUserModeImageBase(peb) &&
                            ReadProcessBytes(
                                device,
                                symbols,
                                process,
                                pid,
                                peb + 0x10,
                                sizeof(uint64_t),
                                &baseBytes) &&
                            baseBytes.size() >= sizeof(uint64_t))
                        {
                            uint64_t base = 0;
                            std::memcpy(&base, baseBytes.data(), sizeof(base));
                            if (IsUserModeImageBase(base))
                            {
                                *imageBase = base;
                                ok = true;
                                break;
                            }
                        }
                    }
                }
            }

            if (device == nullptr || symbols == nullptr || !device->IsOpen())
            {
                break;
            }
            TypeFieldInfo dtbField = {};
            TypeFieldInfo pebField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }
            if (!symbols->FindField(L"nt!_EPROCESS", L"Peb", &pebField, &ignored))
            {
                break;
            }
            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }
            TypeFieldInfo wow64Field = {};
            bool kernelWow64 = false;
            if (symbols->FindField(L"nt!_EPROCESS", L"Wow64Process", &wow64Field, &ignored))
            {
                std::vector<uint8_t> wowBytes;
                if (wow64Field.Offset <=
                        (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess &&
                    device->ReadMemory(
                        ctx.Eprocess + static_cast<uint64_t>(wow64Field.Offset),
                        sizeof(uint64_t),
                        &wowBytes,
                        &ignored) &&
                    wowBytes.size() >= sizeof(uint64_t))
                {
                    uint64_t wow64Process = 0;
                    std::memcpy(&wow64Process, wowBytes.data(), sizeof(wow64Process));
                    uint64_t peb32 = 0;
                    if (IsUserModeImageBase(wow64Process))
                    {
                        peb32 = wow64Process;
                    }
                    else if (wow64Process != 0)
                    {
                        std::vector<uint8_t> peb32Ptr;
                        if (device->ReadMemory(
                                wow64Process,
                                sizeof(uint64_t),
                                &peb32Ptr,
                                &ignored) &&
                            peb32Ptr.size() >= sizeof(uint64_t))
                        {
                            std::memcpy(&peb32, peb32Ptr.data(), sizeof(peb32));
                        }
                    }
                    if (peb32 != 0 && !IsUserModeImageBase(peb32))
                    {
                        peb32 = 0;
                    }
                    if (peb32 != 0)
                    {
                        kernelWow64 = true;
                        std::vector<uint8_t> base32Bytes;
                        if (ReadProcessVirtualChecked(
                                device,
                                symbols,
                                process,
                                pid,
                                ctx.Eprocess,
                                peb32 + 0x08,
                                sizeof(uint32_t),
                                &base32Bytes) &&
                            base32Bytes.size() >= sizeof(uint32_t))
                        {
                            uint32_t base32 = 0;
                            std::memcpy(&base32, base32Bytes.data(), sizeof(base32));
                            if (IsUserModeImageBase(base32))
                            {
                                *imageBase = base32;
                                ok = true;
                                break;
                            }
                        }
                    }
                    else if (wow64Process != 0)
                    {
                        kernelWow64 = true;
                    }
                }
            }
            if (kernelWow64 || wow64Peb)
            {
                break;
            }
            std::vector<uint8_t> pebPtr;
            if (pebField.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess ||
                !device->ReadMemory(
                    ctx.Eprocess + static_cast<uint64_t>(pebField.Offset),
                    sizeof(uint64_t),
                    &pebPtr,
                    &ignored) ||
                pebPtr.size() < sizeof(uint64_t))
            {
                break;
            }
            uint64_t peb = 0;
            std::memcpy(&peb, pebPtr.data(), sizeof(peb));
            if (peb == 0 || !IsUserModeImageBase(peb))
            {
                break;
            }
            std::vector<uint8_t> baseBytes;
            if (!ReadProcessVirtualChecked(
                    device,
                    symbols,
                    process,
                    pid,
                    ctx.Eprocess,
                    peb + 0x10,
                    sizeof(uint64_t),
                    &baseBytes) ||
                baseBytes.size() < sizeof(uint64_t))
            {
                break;
            }
            uint64_t base = 0;
            std::memcpy(&base, baseBytes.data(), sizeof(base));
            if (IsUserModeImageBase(base))
            {
                *imageBase = base;
                ok = true;
            }
        } while (false);
        return ok;
    }

    bool KmonExeRegionLooksPrivate(
        bool queried,
        bool committed,
        DWORD mbiType,
        bool kernelPrivate)
    {
        bool looksPrivate = false;
        do
        {
            if (kernelPrivate)
            {
                looksPrivate = true;
                break;
            }
            // VirtualQueryEx did not run. MEMORY_BASIC_INFORMATION is zeroed
            // and Type==0 is not MEM_IMAGE, so treating it as private would
            // hollow-flag every PPL / no-handle process.
            if (!queried)
            {
                break;
            }
            if (committed && mbiType != MEM_IMAGE)
            {
                looksPrivate = true;
            }
        } while (false);
        return looksPrivate;
    }

    bool KmonProtectIsRwx(DWORD protect)
    {
        return (protect & 0xffu) == PAGE_EXECUTE_READWRITE;
    }

    bool VadCoversUserAddress(const ProcessVadRecord& record, uint64_t address)
    {
        bool covers = false;
        do
        {
            if (address == 0 ||
                record.StartAddress == 0 ||
                record.EndAddress < record.StartAddress)
            {
                break;
            }
            if (address >= record.StartAddress && address <= record.EndAddress)
            {
                covers = true;
            }
        } while (false);
        return covers;
    }

    bool QueryKernelVadScan(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        ProcessVadScanResult* vadResult,
        bool* scanned,
        bool scanHiddenPtes,
        bool probePe)
    {
        bool ok = false;
        do
        {
            if (scanned != nullptr)
            {
                *scanned = false;
            }
            if (vadResult != nullptr)
            {
                *vadResult = ProcessVadScanResult{};
            }
            if (vadResult == nullptr ||
                device == nullptr ||
                symbols == nullptr ||
                pid <= 4 ||
                !device->IsOpen())
            {
                break;
            }

            TypeFieldInfo dtbField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }

            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }

            ProcessVadScanOptions options;
            options.Target.ProcessId = pid;
            options.Target.Eprocess = ctx.Eprocess;
            options.Target.DirectoryTableBase = ctx.DirectoryTableBase;
            options.Target.UserDirectoryTableBase = ctx.UserDirectoryTableBase;
            options.Target.CreateTime =
                QueryEprocessCreateTime(device, symbols, nullptr, ctx.Eprocess);
            options.Target.HasCreateTime = options.Target.CreateTime != 0;
            // Probe private and section-mapped VADs for MZ so header-intact
            // manual maps still classify when VirtualQueryEx is denied.
            options.ProbePe = probePe;
            // Full user page-table walks are expensive. Hidden PTEs follow
            // the caller's kernel-VAD gate (watched games, or builtin/PPL
            // hosts whose usermode walks already failed).
            options.ScanHiddenPtes = scanHiddenPtes;
            options.HiddenPteExecutableOnly = scanHiddenPtes;
            options.HiddenPteLimit = scanHiddenPtes ? 32u : 0u;

            ProcessTriageScanner scanner(*device, *symbols);
            if (!scanner.ScanVad(options, vadResult, &ignored))
            {
                break;
            }
            if (scanned != nullptr)
            {
                *scanned = true;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool QueryInstrumentationCallback(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t* callback)
    {
        bool ok = false;
        do
        {
            if (callback != nullptr)
            {
                *callback = 0;
            }
            if (callback == nullptr ||
                device == nullptr ||
                symbols == nullptr ||
                pid <= 4 ||
                !device->IsOpen())
            {
                break;
            }

            TypeFieldInfo dtbField = {};
            TypeFieldInfo icField = {};
            std::wstring ignored;
            if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
            {
                break;
            }
            if (!symbols->FindField(L"nt!_KPROCESS", L"InstrumentationCallback", &icField, &ignored) &&
                !symbols->FindField(L"nt!_EPROCESS", L"InstrumentationCallback", &icField, &ignored) &&
                !symbols->FindField(L"_KPROCESS", L"InstrumentationCallback", &icField, &ignored))
            {
                break;
            }
            if (icField.Offset > (std::numeric_limits<uint64_t>::max)() - sizeof(uint64_t))
            {
                break;
            }

            ProcessAddressContext ctx = {};
            if (!device->ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }
            if (icField.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!device->ReadMemory(
                    ctx.Eprocess + static_cast<uint64_t>(icField.Offset),
                    sizeof(uint64_t),
                    &bytes,
                    &ignored) ||
                bytes.size() < sizeof(uint64_t))
            {
                break;
            }
            uint64_t value = 0;
            std::memcpy(&value, bytes.data(), sizeof(value));
            *callback = value;
            ok = true;
        } while (false);
        return ok;
    }

    enum SliceCompare
    {
        SliceUnknown = 0,
        SliceMatch,
        SliceMismatch
    };

    bool LastRelocBlockVa(const std::vector<uint8_t>& relocs, uint32_t* lastVa)
    {
        bool any = false;
        if (lastVa != nullptr)
        {
            *lastVa = 0;
        }
        size_t cursor = 0;
        while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= relocs.size())
        {
            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, relocs.data() + cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                cursor + block.SizeOfBlock > relocs.size())
            {
                break;
            }
            if (lastVa != nullptr)
            {
                *lastVa = block.VirtualAddress;
            }
            any = true;
            cursor += block.SizeOfBlock;
        }
        return any;
    }

    bool ReadRelocDirectory(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& diskHeaders,
        const KmonPeLayout& layout,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t imageBase,
        std::vector<uint8_t>* relocs,
        bool* complete)
    {
        bool ok = false;
        if (relocs != nullptr)
        {
            relocs->clear();
        }
        if (complete != nullptr)
        {
            *complete = false;
        }
        do
        {
            if (relocs == nullptr || layout.RelocSize == 0 || layout.RelocRva == 0)
            {
                break;
            }
            constexpr uint32_t kMaxRelocBytes = 0x100000u;
            constexpr uint32_t kChunk = 0x10000u;
            const uint32_t toRead =
                (layout.RelocSize < kMaxRelocBytes) ? layout.RelocSize : kMaxRelocBytes;
            uint32_t relocFile = 0;
            const bool haveFile = RvaToFileOffset(diskHeaders, layout.RelocRva, &relocFile);
            relocs->reserve(toRead);
            uint32_t offset = 0;
            while (offset < toRead)
            {
                const uint32_t chunk = (std::min)(kChunk, toRead - offset);
                std::vector<uint8_t> part;
                bool got = false;
                if (haveFile &&
                    offset <= (std::numeric_limits<uint32_t>::max)() - relocFile)
                {
                    got = ReadDiskRange(imagePath, relocFile + offset, chunk, &part);
                }
                if (!got)
                {
                    if (imageBase == 0 ||
                        layout.RelocRva >
                            (std::numeric_limits<uint64_t>::max)() - imageBase)
                    {
                        break;
                    }
                    const uint64_t relocVa = imageBase + layout.RelocRva;
                    if (static_cast<uint64_t>(offset) >
                        (std::numeric_limits<uint64_t>::max)() - relocVa)
                    {
                        break;
                    }
                    got = ReadProcessBytes(
                        device,
                        symbols,
                        processHandle,
                        pid,
                        relocVa + offset,
                        chunk,
                        &part);
                }
                if (!got || part.size() < chunk)
                {
                    break;
                }
                relocs->insert(relocs->end(), part.begin(), part.end());
                offset += chunk;
            }
            if (relocs->empty())
            {
                break;
            }
            if (complete != nullptr)
            {
                *complete = (offset >= layout.RelocSize);
            }
            ok = true;
        } while (false);
        return ok;
    }

    SliceCompare RelocatedSliceCompare(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& diskHeaders,
        const KmonPeLayout& layout,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t imageBase,
        uint32_t rva,
        uint32_t fileOffset,
        uint32_t length,
        std::vector<uint8_t>* relocCache = nullptr,
        bool* relocCacheComplete = nullptr)
    {
        SliceCompare result = SliceUnknown;
        do
        {
            if (length < 16 || imageBase == 0 || fileOffset == 0)
            {
                break;
            }
            if (rva > (std::numeric_limits<uint64_t>::max)() - imageBase)
            {
                break;
            }
            std::vector<uint8_t> diskText;
            std::vector<uint8_t> liveText;
            if (!ReadDiskRange(imagePath, fileOffset, length, &diskText) ||
                !ReadProcessBytes(
                    device,
                    symbols,
                    processHandle,
                    pid,
                    imageBase + rva,
                    length,
                    &liveText) ||
                diskText.size() < 16 ||
                liveText.size() < 16)
            {
                break;
            }
            const uint64_t delta = imageBase - layout.PreferredBase;
            const bool aslr = layout.PreferredBase != 0 && imageBase != layout.PreferredBase;
            bool compared = !aslr;
            if (aslr && layout.RelocRva != 0 && layout.RelocSize != 0)
            {
                std::vector<uint8_t> localRelocs;
                const std::vector<uint8_t>* activeRelocs = nullptr;
                bool relocComplete = false;
                if (relocCache != nullptr && !relocCache->empty())
                {
                    // Reuse a reloc directory that the caller already loaded
                    // for this same image. Export prologue loops would
                    // otherwise reread the whole directory from disk for
                    // every single 24-byte slice.
                    activeRelocs = relocCache;
                    relocComplete = (relocCacheComplete != nullptr)
                        ? *relocCacheComplete
                        : false;
                }
                else if (ReadRelocDirectory(
                             imagePath,
                             diskHeaders,
                             layout,
                             processHandle,
                             device,
                             symbols,
                             pid,
                             imageBase,
                             &localRelocs,
                             &relocComplete))
                {
                    if (relocCache != nullptr)
                    {
                        *relocCache = localRelocs;
                        if (relocCacheComplete != nullptr)
                        {
                            *relocCacheComplete = relocComplete;
                        }
                    }
                    activeRelocs = &localRelocs;
                }
                if (activeRelocs != nullptr)
                {
                    uint32_t lastVa = 0;
                    const bool haveBlock = LastRelocBlockVa(*activeRelocs, &lastVa);
                    uint32_t sliceLastPage = rva & ~0xFFFu;
                    if (length != 0 &&
                        rva <= (std::numeric_limits<uint32_t>::max)() - (length - 1u))
                    {
                        sliceLastPage = (rva + length - 1u) & ~0xFFFu;
                    }
                    // Reloc blocks are sorted. A truncated prefix is only
                    // safe when it already extends past this slice, or the
                    // directory was read in full (no relocs on this page).
                    if (relocComplete || (haveBlock && lastVa >= sliceLastPage))
                    {
                        ApplyRelocsToSlice(
                            &diskText,
                            rva,
                            delta,
                            *activeRelocs,
                            layout.Is64);
                        compared = true;
                    }
                }
            }
            if (!compared)
            {
                break;
            }
            size_t n = (std::min)(diskText.size(), liveText.size());
            // A DIR64/HIGHLOW reloc that straddles the window end cannot be
            // applied; comparing those tail bytes FPs every ASLR'd image.
            // A slice smaller than 24 bytes cannot drop an 8-byte tail and
            // still compare 16 bytes, so ASLR'd tiny slices stay unknown.
            if (aslr)
            {
                if (n < 24)
                {
                    break;
                }
                n -= 8;
            }
            result = (std::memcmp(diskText.data(), liveText.data(), n) == 0)
                ? SliceMatch
                : SliceMismatch;
        } while (false);
        return result;
    }

    SliceCompare CompareLoadedModuleText(
        const std::wstring& imagePath,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t imageBase)
    {
        SliceCompare result = SliceUnknown;
        do
        {
            if (imageBase == 0 || !PathLooksLikeWin32File(imagePath))
            {
                break;
            }
            std::vector<uint8_t> headers;
            KmonPeLayout layout = {};
            if (!ReadDiskPeHead(imagePath, &headers) ||
                !ParseKmonPeLayout(headers, &layout) ||
                layout.ExecSize < 16 ||
                layout.ExecFileOffset == 0)
            {
                break;
            }
            result = RelocatedSliceCompare(
                imagePath,
                headers,
                layout,
                processHandle,
                device,
                symbols,
                pid,
                imageBase,
                layout.ExecRva,
                layout.ExecFileOffset,
                layout.ExecSize);
            if (result == SliceMismatch || result == SliceUnknown)
            {
                break;
            }
            if (layout.ExecVirtSize <= 0x1000)
            {
                break;
            }
            uint32_t samples[3] = {};
            uint32_t sampleCount = 0;
            auto addSample = [&](uint32_t pageRva)
            {
                if (pageRva <= layout.ExecRva || sampleCount >= 3)
                {
                    return;
                }
                for (uint32_t i = 0; i < sampleCount; ++i)
                {
                    if (samples[i] == pageRva)
                    {
                        return;
                    }
                }
                samples[sampleCount++] = pageRva;
            };
            if (layout.ExecRva <= (std::numeric_limits<uint32_t>::max)() - 0x1000)
            {
                addSample(layout.ExecRva + 0x1000);
            }
            if (layout.ExecVirtSize > 0x2000)
            {
                const uint32_t midOff = (layout.ExecVirtSize / 2) & ~0xFFFu;
                if (layout.ExecRva <= (std::numeric_limits<uint32_t>::max)() - midOff)
                {
                    addSample(layout.ExecRva + midOff);
                }
                if (layout.ExecVirtSize >= 0x100)
                {
                    const uint32_t lastOff = (layout.ExecVirtSize - 0x100) & ~0xFFFu;
                    if (layout.ExecRva <= (std::numeric_limits<uint32_t>::max)() - lastOff)
                    {
                        addSample(layout.ExecRva + lastOff);
                    }
                }
            }
            bool laterUnknown = false;
            for (uint32_t i = 0; i < sampleCount; ++i)
            {
                uint32_t laterFile = 0;
                if (!RvaToFileOffset(headers, samples[i], &laterFile))
                {
                    laterUnknown = true;
                    continue;
                }
                const SliceCompare laterCmp = RelocatedSliceCompare(
                    imagePath,
                    headers,
                    layout,
                    processHandle,
                    device,
                    symbols,
                    pid,
                    imageBase,
                    samples[i],
                    laterFile,
                    0x100);
                if (laterCmp == SliceMismatch)
                {
                    result = SliceMismatch;
                    laterUnknown = false;
                    break;
                }
                if (laterCmp == SliceUnknown)
                {
                    laterUnknown = true;
                }
            }
            if (result == SliceMatch && laterUnknown)
            {
                result = SliceUnknown;
            }
        } while (false);
        return result;
    }

    uint32_t CountNtExportPrologueMismatches(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& headers,
        const KmonPeLayout& layout,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t imageBase)
    {
        uint32_t mismatches = 0;
        do
        {
            if (imageBase == 0 ||
                headers.empty() ||
                layout.ExportRva == 0 ||
                layout.ExportSize < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                break;
            }
            uint32_t exportFile = 0;
            if (!RvaToFileOffset(headers, layout.ExportRva, &exportFile))
            {
                break;
            }
            std::vector<uint8_t> exportDir;
            if (!ReadDiskRange(
                    imagePath,
                    exportFile,
                    sizeof(IMAGE_EXPORT_DIRECTORY),
                    &exportDir) ||
                exportDir.size() < sizeof(IMAGE_EXPORT_DIRECTORY))
            {
                break;
            }
            IMAGE_EXPORT_DIRECTORY exports = {};
            std::memcpy(&exports, exportDir.data(), sizeof(exports));
            if (exports.NumberOfNames == 0 ||
                exports.NumberOfFunctions == 0 ||
                exports.AddressOfNames == 0 ||
                exports.AddressOfFunctions == 0 ||
                exports.AddressOfNameOrdinals == 0)
            {
                break;
            }
            constexpr uint32_t kMaxNames = 4096;
            const uint32_t nameCount =
                (exports.NumberOfNames < kMaxNames) ? exports.NumberOfNames : kMaxNames;
            const uint32_t funcCount =
                (exports.NumberOfFunctions < kMaxNames) ? exports.NumberOfFunctions : kMaxNames;
            uint32_t namesFile = 0;
            uint32_t ordsFile = 0;
            uint32_t funcsFile = 0;
            if (!RvaToFileOffset(headers, exports.AddressOfNames, &namesFile) ||
                !RvaToFileOffset(headers, exports.AddressOfNameOrdinals, &ordsFile) ||
                !RvaToFileOffset(headers, exports.AddressOfFunctions, &funcsFile))
            {
                break;
            }
            std::vector<uint8_t> namesTable;
            std::vector<uint8_t> ordsTable;
            std::vector<uint8_t> funcsTable;
            const uint32_t namesBytes = nameCount * 4u;
            const uint32_t ordsBytes = nameCount * 2u;
            const uint32_t funcsBytes = funcCount * 4u;
            if (!ReadDiskRange(imagePath, namesFile, namesBytes, &namesTable) ||
                namesTable.size() < namesBytes ||
                !ReadDiskRange(imagePath, ordsFile, ordsBytes, &ordsTable) ||
                ordsTable.size() < ordsBytes ||
                !ReadDiskRange(imagePath, funcsFile, funcsBytes, &funcsTable) ||
                funcsTable.size() < funcsBytes)
            {
                break;
            }
            // Export names are loaded for every index in two loops. Reading
            // each 64-byte name window from disk per index turns one module
            // scan into thousands of file open/close cycles. Load the span
            // that covers every name string once and fall back to a single
            // name read when a name sits outside that span.
            std::vector<uint8_t> nameBlob;
            uint32_t nameBlobFile = 0;
            bool haveNameBlob = false;
            do
            {
                uint32_t minRva = 0;
                uint32_t maxRva = 0;
                for (uint32_t i = 0; i < nameCount; ++i)
                {
                    uint32_t probeRva = 0;
                    std::memcpy(
                        &probeRva,
                        namesTable.data() + (i * 4u),
                        sizeof(probeRva));
                    if (probeRva == 0)
                    {
                        continue;
                    }
                    if (minRva == 0 || probeRva < minRva)
                    {
                        minRva = probeRva;
                    }
                    if (probeRva > maxRva)
                    {
                        maxRva = probeRva;
                    }
                }
                if (minRva == 0 || maxRva < minRva)
                {
                    break;
                }
                constexpr uint32_t kNameTail = 64;
                if (maxRva > (std::numeric_limits<uint32_t>::max)() - kNameTail)
                {
                    break;
                }
                const uint32_t blobRva = minRva;
                uint32_t blobSpan = (maxRva - minRva) + kNameTail;
                if (blobSpan > 0x10000)
                {
                    blobSpan = 0x10000;
                }
                uint32_t blobFile = 0;
                if (!RvaToFileOffset(headers, blobRva, &blobFile))
                {
                    break;
                }
                if (!ReadDiskRange(imagePath, blobFile, blobSpan, &nameBlob) ||
                    nameBlob.size() < blobSpan)
                {
                    nameBlob.clear();
                    break;
                }
                nameBlobFile = blobFile;
                haveNameBlob = true;
            } while (false);
            static const char* kPriority[] =
            {
                "NtProtectVirtualMemory",
                "NtProtectVirtualMemoryEx",
                "NtAllocateVirtualMemory",
                "NtAllocateVirtualMemoryEx",
                "NtReadVirtualMemory",
                "NtWriteVirtualMemory",
                "NtQueryVirtualMemory",
                "NtSetInformationVirtualMemory",
                "NtMapViewOfSection",
                "NtMapViewOfSectionEx",
                "NtUnmapViewOfSection",
                "NtUnmapViewOfSectionEx",
                "NtOpenProcess",
                "NtOpenThread",
                "NtCreateThreadEx",
                "NtCreateThread",
                "NtQueueApcThread",
                "NtQueueApcThreadEx",
                "NtQueueApcThreadEx2",
                "NtAlertResumeThread",
                "NtContinueEx",
                "NtSetContextThread",
                "NtGetContextThread",
                "NtSuspendThread",
                "NtResumeThread",
                "NtQueryInformationProcess",
                "NtSetInformationProcess",
                "NtQueryInformationThread",
                "NtDuplicateObject",
                "NtQuerySystemInformation",
                "NtSystemDebugControl",
                "NtCreateSection",
                "NtOpenSection",
                "NtCreateUserProcess",
                "NtUserSendInput",
                "NtUserGetAsyncKeyState",
                "NtUserGetRawInputData",
                "NtUserGetKeyState",
                "NtUserFindWindowEx",
                "NtGdiBitBlt"
            };
            constexpr uint32_t kMaxNtChecks = 128;
            constexpr uint32_t kPrologue = 24;
            uint32_t checked = 0;
            // Every prologue check below targets the same image, so one
            // reloc directory load is shared across all export checks.
            std::vector<uint8_t> relocCache;
            bool relocCacheComplete = false;
            const uint32_t exportBegin = layout.ExportRva;
            const uint32_t exportEnd = layout.ExportRva + layout.ExportSize;
            auto nameIsPriority = [&](const std::string& name) -> bool
            {
                for (const char* item : kPriority)
                {
                    if (name == item)
                    {
                        return true;
                    }
                }
                return false;
            };
            auto checkExport = [&](uint32_t funcRva) -> bool
            {
                if (funcRva == 0)
                {
                    return false;
                }
                if (funcRva >= exportBegin && funcRva < exportEnd)
                {
                    return false;
                }
                uint32_t funcFile = 0;
                if (!RvaToFileOffset(headers, funcRva, &funcFile))
                {
                    return false;
                }
                if (funcRva > (std::numeric_limits<uint64_t>::max)() - imageBase)
                {
                    return false;
                }
                const SliceCompare cmp = RelocatedSliceCompare(
                    imagePath,
                    headers,
                    layout,
                    processHandle,
                    device,
                    symbols,
                    pid,
                    imageBase,
                    funcRva,
                    funcFile,
                    kPrologue,
                    &relocCache,
                    &relocCacheComplete);
                if (cmp == SliceUnknown)
                {
                    return false;
                }
                ++checked;
                return cmp == SliceMismatch;
            };
            auto loadExportName = [&](uint32_t index, std::string* name) -> bool
            {
                if (name == nullptr || index >= nameCount)
                {
                    return false;
                }
                name->clear();
                uint32_t nameRva = 0;
                std::memcpy(&nameRva, namesTable.data() + (index * 4u), sizeof(nameRva));
                if (nameRva == 0)
                {
                    return false;
                }
                uint32_t nameFileOff = 0;
                if (!RvaToFileOffset(headers, nameRva, &nameFileOff))
                {
                    return false;
                }
                std::vector<uint8_t> nameBytes;
                bool haveNameBytes = false;
                if (haveNameBlob &&
                    nameFileOff >= nameBlobFile &&
                    nameFileOff - nameBlobFile + 64 <= nameBlob.size())
                {
                    const size_t blobLocal =
                        static_cast<size_t>(nameFileOff - nameBlobFile);
                    nameBytes.assign(
                        nameBlob.begin() + blobLocal,
                        nameBlob.begin() + blobLocal + 64);
                    haveNameBytes = true;
                }
                if (!haveNameBytes &&
                    !ReadDiskRange(imagePath, nameFileOff, 64, &nameBytes))
                {
                    return false;
                }
                if (nameBytes.empty())
                {
                    return false;
                }
                for (uint8_t byte : nameBytes)
                {
                    if (byte == 0)
                    {
                        break;
                    }
                    if (byte >= 0x20 && byte < 0x7f)
                    {
                        name->push_back(static_cast<char>(byte));
                    }
                }
                return !name->empty();
            };
            auto funcRvaAt = [&](uint32_t index, uint32_t* funcRva) -> bool
            {
                if (funcRva == nullptr || index >= nameCount)
                {
                    return false;
                }
                uint16_t ordinal = 0;
                std::memcpy(&ordinal, ordsTable.data() + (index * 2u), sizeof(ordinal));
                if (ordinal >= funcCount)
                {
                    return false;
                }
                std::memcpy(funcRva, funcsTable.data() + (ordinal * 4u), sizeof(uint32_t));
                return true;
            };
            for (uint32_t i = 0; i < nameCount && mismatches < 4; ++i)
            {
                std::string name;
                uint32_t funcRva = 0;
                if (!loadExportName(i, &name) || !nameIsPriority(name))
                {
                    continue;
                }
                if (!funcRvaAt(i, &funcRva))
                {
                    continue;
                }
                if (checkExport(funcRva))
                {
                    ++mismatches;
                }
            }
            for (uint32_t i = 0;
                i < nameCount && mismatches < 4 && checked < kMaxNtChecks;
                ++i)
            {
                std::string name;
                uint32_t funcRva = 0;
                if (!loadExportName(i, &name))
                {
                    continue;
                }
                if (name.size() < 2 ||
                    !((name[0] == 'N' && name[1] == 't') ||
                        (name[0] == 'Z' && name[1] == 'w')))
                {
                    continue;
                }
                if (nameIsPriority(name))
                {
                    continue;
                }
                if (!funcRvaAt(i, &funcRva))
                {
                    continue;
                }
                if (checkExport(funcRva))
                {
                    ++mismatches;
                }
            }
        } while (false);
        return mismatches;
    }

    bool CollectPeDllNameDirectory(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& headers,
        uint32_t dirRva,
        uint32_t dirSize,
        uint32_t nameFieldOffset,
        uint32_t descriptorSize,
        std::unordered_set<std::wstring>* names)
    {
        bool terminated = false;
        do
        {
            if (names == nullptr)
            {
                break;
            }
            if (dirRva == 0 || dirSize == 0)
            {
                terminated = true;
                break;
            }
            if (descriptorSize < 8 ||
                nameFieldOffset + 4 > descriptorSize ||
                dirSize < descriptorSize)
            {
                break;
            }
            uint32_t fileOff = 0;
            if (!RvaToFileOffset(headers, dirRva, &fileOff))
            {
                break;
            }
            constexpr uint32_t kMaxDirBytes = 64u * 1024u;
            const uint32_t toRead = (std::min)(dirSize, kMaxDirBytes);
            std::vector<uint8_t> table;
            if (!ReadDiskRange(imagePath, fileOff, toRead, &table) ||
                table.size() < descriptorSize)
            {
                break;
            }
            const uint32_t count = static_cast<uint32_t>(table.size() / descriptorSize);
            constexpr uint32_t kMaxDescriptors = 2048;
            for (uint32_t i = 0; i < count && i < kMaxDescriptors; ++i)
            {
                uint32_t nameRva = 0;
                std::memcpy(
                    &nameRva,
                    table.data() + (i * descriptorSize) + nameFieldOffset,
                    sizeof(nameRva));
                if (nameRva == 0)
                {
                    terminated = true;
                    break;
                }
                uint32_t nameFile = 0;
                if (!RvaToFileOffset(headers, nameRva, &nameFile))
                {
                    break;
                }
                std::vector<uint8_t> nameBytes;
                if (!ReadDiskRange(imagePath, nameFile, 256, &nameBytes) ||
                    nameBytes.empty())
                {
                    break;
                }
                std::wstring wide;
                for (uint8_t byte : nameBytes)
                {
                    if (byte == 0)
                    {
                        break;
                    }
                    if (byte >= 0x20 && byte < 0x7f)
                    {
                        wide.push_back(static_cast<wchar_t>(byte));
                    }
                }
                std::wstring base = KmonBasenameLower(wide);
                if (base.empty())
                {
                    break;
                }
                names->insert(std::move(base));
            }
        } while (false);
        return terminated;
    }

    void CollectImportedDllNames(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& headers,
        const KmonPeLayout& layout,
        std::unordered_set<std::wstring>* names)
    {
        if (names == nullptr)
        {
            return;
        }
        const bool importOk = CollectPeDllNameDirectory(
            imagePath,
            headers,
            layout.ImportRva,
            layout.ImportSize,
            12,
            20,
            names);
        const bool delayOk = CollectPeDllNameDirectory(
            imagePath,
            headers,
            layout.DelayImportRva,
            layout.DelayImportSize,
            4,
            32,
            names);
        if (!importOk || !delayOk)
        {
            // A truncated IAT/delay-import walk must not be used for
            // watched_dir_unimported; missing names would look like implants.
            names->clear();
        }
    }

    bool FindUserModuleForAddress(
        uint64_t address,
        const std::vector<std::wstring>& paths,
        const std::vector<std::pair<uint64_t, uint32_t>>& ranges,
        std::wstring* path)
    {
        bool found = false;
        do
        {
            if (path != nullptr)
            {
                path->clear();
            }
            if (address == 0)
            {
                break;
            }
            const size_t n = (paths.size() < ranges.size()) ? paths.size() : ranges.size();
            for (size_t i = 0; i < n; ++i)
            {
                const uint64_t base = ranges[i].first;
                const uint64_t size = ranges[i].second;
                if (base == 0 || size == 0)
                {
                    continue;
                }
                if (base > (std::numeric_limits<uint64_t>::max)() - size)
                {
                    continue;
                }
                if (address >= base && address < base + size)
                {
                    if (path != nullptr)
                    {
                        *path = paths[i];
                    }
                    found = true;
                    break;
                }
            }
        } while (false);
        return found;
    }

    bool ModulePathLooksInboxWindows(const std::wstring& path)
    {
        const std::wstring n = KmonNormalizeDriverPath(path);
        return n.find(L"\\windows\\system32\\") != std::wstring::npos ||
            n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
            n.find(L"\\windows\\winsxs\\") != std::wstring::npos;
    }

    bool KmonLooksLikeHookableSystemDll(const std::wstring& leaf);
    bool KmonLooksLikeGraphicsApiDll(const std::wstring& leaf);
    bool KmonLooksLikeOverlayRuntimeDll(const std::wstring& leaf);
    bool KmonLooksLikeKernelImportTarget(const std::wstring& leaf);
    uint32_t CountKernelImportStubs(
        const uint8_t* bytes,
        size_t size,
        uint64_t regionVa,
        const std::vector<KernelModuleInfo>& modules);
    uint32_t CollectCfgDataPtrSlotRvas(
        const uint8_t* text,
        size_t textSize,
        uint32_t textRva,
        uint32_t sizeOfImage,
        const std::unordered_set<uint32_t>& guardCallRvas,
        const std::unordered_set<uint32_t>& guardIatRvas,
        std::vector<uint32_t>* slotRvas,
        uint32_t maxSites);
    bool KmonVaLooksLikePagingOrFirmware(uint64_t va);
    bool KmonLooksLikeCfgHostModule(const std::wstring& leaf);
    bool ProtectHasExecute(DWORD protect);
    bool AddressInModuleRanges(
        uint64_t address,
        const std::vector<std::pair<uint64_t, uint32_t>>& ranges);
    std::wstring KmonDevicePathToWin32(const std::wstring& devicePath);
    bool KmonVadRecordLooksLikeCodeTarget(const ProcessVadRecord& record);
    const ProcessVadRecord* KmonFindCoveringVadRecord(
        const std::vector<ProcessVadRecord>* records,
        uint64_t address);

    void ScanLiveImportThunks(
        const std::wstring& imagePath,
        const std::vector<uint8_t>& headers,
        uint32_t dirRva,
        uint32_t dirSize,
        uint32_t nameFieldOffset,
        uint32_t iatFieldOffset,
        uint32_t descriptorSize,
        bool is64,
        uint64_t imageBase,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint32_t sizeOfImage,
        const std::vector<std::wstring>& modulePaths,
        const std::vector<std::pair<uint64_t, uint32_t>>& moduleRanges,
        uint32_t* hits)
    {
        do
        {
            if (hits == nullptr ||
                imageBase == 0 ||
                dirRva == 0 ||
                dirSize == 0 ||
                descriptorSize < 20 ||
                nameFieldOffset + 4 > descriptorSize ||
                iatFieldOffset + 4 > descriptorSize ||
                modulePaths.empty() ||
                moduleRanges.empty())
            {
                break;
            }
            uint32_t fileOff = 0;
            if (!RvaToFileOffset(headers, dirRva, &fileOff))
            {
                break;
            }
            constexpr uint32_t kMaxDirBytes = 64u * 1024u;
            const uint32_t toRead = (std::min)(dirSize, kMaxDirBytes);
            std::vector<uint8_t> table;
            if (!ReadDiskRange(imagePath, fileOff, toRead, &table) ||
                table.size() < descriptorSize)
            {
                break;
            }
            const uint32_t count = static_cast<uint32_t>(table.size() / descriptorSize);
            constexpr uint32_t kMaxDescriptors = 64;
            constexpr uint32_t kMaxThunks = 256;
            const uint32_t thunkSize = is64 ? 8u : 4u;
            for (uint32_t i = 0; i < count && i < kMaxDescriptors; ++i)
            {
                if (*hits >= 4)
                {
                    break;
                }
                uint32_t nameRva = 0;
                uint32_t iatRva = 0;
                std::memcpy(
                    &nameRva,
                    table.data() + (i * descriptorSize) + nameFieldOffset,
                    sizeof(nameRva));
                std::memcpy(
                    &iatRva,
                    table.data() + (i * descriptorSize) + iatFieldOffset,
                    sizeof(iatRva));
                if (nameRva == 0)
                {
                    break;
                }
                if (iatRva == 0)
                {
                    continue;
                }
                uint32_t nameFile = 0;
                if (!RvaToFileOffset(headers, nameRva, &nameFile))
                {
                    continue;
                }
                std::vector<uint8_t> nameBytes;
                if (!ReadDiskRange(imagePath, nameFile, 256, &nameBytes) ||
                    nameBytes.empty())
                {
                    continue;
                }
                std::wstring wide;
                for (uint8_t byte : nameBytes)
                {
                    if (byte == 0)
                    {
                        break;
                    }
                    if (byte >= 0x20 && byte < 0x7f)
                    {
                        wide.push_back(static_cast<wchar_t>(byte));
                    }
                }
                const std::wstring importLeaf = KmonBasenameLower(wide);
                if (importLeaf.empty())
                {
                    continue;
                }
                const bool apiSet =
                    importLeaf.find(L"api-ms-") == 0 ||
                    importLeaf.find(L"ext-ms-") == 0;
                bool importLoaded = apiSet;
                bool importLoadedInbox = false;
                const size_t moduleCount =
                    (modulePaths.size() < moduleRanges.size())
                        ? modulePaths.size()
                        : moduleRanges.size();
                for (size_t m = 0; m < moduleCount; ++m)
                {
                    if (KmonBasenameLower(modulePaths[m]) != importLeaf)
                    {
                        continue;
                    }
                    importLoaded = true;
                    if (ModulePathLooksInboxWindows(modulePaths[m]))
                    {
                        importLoadedInbox = true;
                    }
                }
                if (!importLoaded)
                {
                    continue;
                }
                uint64_t iatTableVa = 0;
                if (sizeOfImage != 0 &&
                    iatRva >= sizeOfImage &&
                    iatRva >= imageBase &&
                    iatRva < imageBase + sizeOfImage)
                {
                    iatTableVa = iatRva;
                }
                else if (iatRva > (std::numeric_limits<uint64_t>::max)() - imageBase)
                {
                    continue;
                }
                else
                {
                    iatTableVa = imageBase + iatRva;
                }
                for (uint32_t t = 0; t < kMaxThunks; ++t)
                {
                    if (*hits >= 4)
                    {
                        break;
                    }
                    const uint64_t thunkVa = iatTableVa +
                        (static_cast<uint64_t>(t) * thunkSize);
                    std::vector<uint8_t> live;
                    if (!ReadProcessBytes(
                            device,
                            symbols,
                            processHandle,
                            pid,
                            thunkVa,
                            thunkSize,
                            &live) ||
                        live.size() < thunkSize)
                    {
                        break;
                    }
                    uint64_t target = 0;
                    if (is64)
                    {
                        std::memcpy(&target, live.data(), sizeof(uint64_t));
                    }
                    else
                    {
                        uint32_t target32 = 0;
                        std::memcpy(&target32, live.data(), sizeof(target32));
                        target = target32;
                    }
                    if (target == 0)
                    {
                        break;
                    }
                    if ((is64 && (target & 0x8000000000000000ull) != 0) ||
                        (!is64 && (target & 0x80000000u) != 0))
                    {
                        continue;
                    }
                    if (!IsUserModeImageBase(target))
                    {
                        ++(*hits);
                        continue;
                    }
                    if (sizeOfImage != 0 &&
                        ((target >= imageBase &&
                            target < imageBase + sizeOfImage) ||
                            target < sizeOfImage))
                    {
                        continue;
                    }
                    std::wstring ownerPath;
                    if (!FindUserModuleForAddress(
                            target,
                            modulePaths,
                            moduleRanges,
                            &ownerPath))
                    {
                        ++(*hits);
                        continue;
                    }
                    const std::wstring ownerLeaf = KmonBasenameLower(ownerPath);
                    if (ownerLeaf == importLeaf)
                    {
                        continue;
                    }
                    if (apiSet && ModulePathLooksInboxWindows(ownerPath))
                    {
                        continue;
                    }
                    if (ModulePathLooksInboxWindows(ownerPath) &&
                        (importLoadedInbox ||
                            KmonLooksLikeHookableSystemDll(importLeaf)))
                    {
                        continue;
                    }
                    ++(*hits);
                }
            }
        } while (false);
    }

    void ScanLiveCallTablePointers(
        const std::vector<uint8_t>& headers,
        uint64_t imageBase,
        HANDLE processHandle,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        const std::vector<std::pair<uint64_t, uint32_t>>& moduleRanges,
        const std::vector<ProcessVadRecord>* kernelVads,
        uint32_t* hits)
    {
        do
        {
            if (hits == nullptr ||
                imageBase == 0 ||
                (processHandle == nullptr && kernelVads == nullptr) ||
                headers.size() < sizeof(IMAGE_DOS_HEADER))
            {
                break;
            }

            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, headers.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            {
                break;
            }
            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            if (static_cast<uint64_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER) >
                headers.size())
            {
                break;
            }
            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                headers.data() + ntOffset + 4,
                sizeof(fileHeader));
            const size_t optionalOffset =
                static_cast<size_t>(ntOffset) + 4 + sizeof(IMAGE_FILE_HEADER);
            if (optionalOffset + sizeof(uint16_t) > headers.size())
            {
                break;
            }
            uint16_t magic = 0;
            std::memcpy(&magic, headers.data() + optionalOffset, sizeof(magic));
            const uint32_t thunkSize =
                (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? 8u : 4u;
            uint32_t iatRva = 0;
            uint32_t iatSize = 0;
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) <= headers.size())
            {
                IMAGE_OPTIONAL_HEADER64 optional = {};
                std::memcpy(&optional, headers.data() + optionalOffset, sizeof(optional));
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
                {
                    iatRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                    iatSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                }
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) <= headers.size())
            {
                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(&optional, headers.data() + optionalOffset, sizeof(optional));
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
                {
                    iatRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                    iatSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
                }
            }
            const size_t sectionOffset =
                optionalOffset + fileHeader.SizeOfOptionalHeader;
            constexpr uint32_t kMaxSectionBytes = 0x10000u;
            constexpr uint32_t kMaxSections = 24;
            const uint16_t sectionLimit =
                (fileHeader.NumberOfSections < kMaxSections)
                    ? fileHeader.NumberOfSections
                    : static_cast<uint16_t>(kMaxSections);
            for (uint16_t i = 0; i < sectionLimit && *hits < 4; ++i)
            {
                const size_t off =
                    sectionOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                if (off + sizeof(IMAGE_SECTION_HEADER) > headers.size())
                {
                    break;
                }
                IMAGE_SECTION_HEADER section = {};
                std::memcpy(&section, headers.data() + off, sizeof(section));
                if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
                    (section.Characteristics & IMAGE_SCN_CNT_CODE) != 0 ||
                    (section.Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
                    (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
                {
                    continue;
                }
                char sectionName[9] = {};
                std::memcpy(sectionName, section.Name, 8);
                if (_stricmp(sectionName, ".reloc") == 0 ||
                    _stricmp(sectionName, ".rsrc") == 0 ||
                    _stricmp(sectionName, ".pdata") == 0 ||
                    _stricmp(sectionName, "INIT") == 0)
                {
                    continue;
                }
                const uint32_t span =
                    (section.Misc.VirtualSize != 0)
                        ? section.Misc.VirtualSize
                        : section.SizeOfRawData;
                if (span < thunkSize ||
                    section.VirtualAddress == 0 ||
                    imageBase > (std::numeric_limits<uint64_t>::max)() -
                        section.VirtualAddress)
                {
                    continue;
                }
                const uint32_t toRead = (std::min)(span, kMaxSectionBytes);
                std::vector<uint8_t> bytes;
                if (!ReadProcessBytes(
                        device,
                        symbols,
                        processHandle,
                        pid,
                        imageBase + section.VirtualAddress,
                        toRead,
                        &bytes) ||
                    bytes.size() < thunkSize)
                {
                    continue;
                }
                const size_t count = bytes.size() / thunkSize;
                for (size_t slot = 0; slot < count && *hits < 4; ++slot)
                {
                    const uint32_t slotRva =
                        section.VirtualAddress +
                        static_cast<uint32_t>(slot * thunkSize);
                    if (iatSize != 0 &&
                        slotRva >= iatRva &&
                        slotRva < iatRva + iatSize)
                    {
                        continue;
                    }
                    uint64_t target = 0;
                    if (thunkSize == 8)
                    {
                        std::memcpy(&target, bytes.data() + (slot * 8), 8);
                    }
                    else
                    {
                        uint32_t target32 = 0;
                        std::memcpy(&target32, bytes.data() + (slot * 4), 4);
                        target = target32;
                    }
                    if (target == 0 || !IsUserModeImageBase(target))
                    {
                        continue;
                    }
                    if (AddressInModuleRanges(target, moduleRanges))
                    {
                        continue;
                    }
                    MEMORY_BASIC_INFORMATION region = {};
                    if (processHandle != nullptr &&
                        VirtualQueryEx(
                            processHandle,
                            reinterpret_cast<LPCVOID>(target),
                            &region,
                            sizeof(region)) == sizeof(region))
                    {
                        if (region.State != MEM_COMMIT ||
                            !ProtectHasExecute(region.Protect))
                        {
                            continue;
                        }
                        if (region.Type != MEM_PRIVATE &&
                            region.Type != MEM_MAPPED)
                        {
                            continue;
                        }
                        ++(*hits);
                        continue;
                    }
                    // Handle stripped of PROCESS_QUERY_* (or absent): fall
                    // back to the kernel VAD view instead of dropping the
                    // slot as a false negative.
                    if (kernelVads == nullptr)
                    {
                        continue;
                    }
                    const ProcessVadRecord* vadRecord =
                        KmonFindCoveringVadRecord(kernelVads, target);
                    if (vadRecord == nullptr ||
                        !KmonVadRecordLooksLikeCodeTarget(*vadRecord))
                    {
                        continue;
                    }
                    ++(*hits);
                }
            }
        } while (false);
    }

    bool ProtectHasExecute(DWORD protect)
    {
        const DWORD p = protect & 0xff;
        return p == PAGE_EXECUTE ||
            p == PAGE_EXECUTE_READ ||
            p == PAGE_EXECUTE_READWRITE ||
            p == PAGE_EXECUTE_WRITECOPY;
    }

    bool AddressInModuleRanges(
        uint64_t address,
        const std::vector<std::pair<uint64_t, uint32_t>>& ranges)
    {
        bool found = false;
        for (const auto& range : ranges)
        {
            if (range.first == 0 || range.second == 0)
            {
                continue;
            }
            if (range.first > (std::numeric_limits<uint64_t>::max)() - range.second)
            {
                continue;
            }
            if (address >= range.first &&
                address < range.first + static_cast<uint64_t>(range.second))
            {
                found = true;
                break;
            }
        }
        return found;
    }

    // Kernel VAD section file names are NT device paths
    // (\Device\HarddiskVolume3\...). Map them onto drive letters so the
    // existing disk-read and path-classification helpers keep working;
    // keep the \\?\GLOBALROOT spelling when no DOS device matches.
    std::wstring KmonDevicePathToWin32(const std::wstring& devicePath)
    {
        if (devicePath.compare(0, 8, L"\\Device\\") != 0)
        {
            return devicePath;
        }
        {
            wchar_t drives[1024] = {};
            const DWORD driveLen =
                GetLogicalDriveStringsW(
                    ARRAYSIZE(drives) - 1,
                    drives);
            // A return equal to the buffer capacity means the list was
            // truncated; treat that as "no mapping" so those files keep
            // the GLOBALROOT spelling instead of a half-walked drive list.
            if (driveLen > 0 && driveLen < ARRAYSIZE(drives) - 1)
            {
                const wchar_t* cursor = drives;
                while (*cursor != L'\0')
                {
                    const std::wstring drive(cursor);
                    if (drive.size() >= 2)
                    {
                        wchar_t target[1024] = {};
                        const DWORD targetLen =
                            QueryDosDeviceW(
                                drive.substr(0, 2).c_str(),
                                target,
                                ARRAYSIZE(target) - 1);
                        if (targetLen > 0 && target[0] == L'\\')
                        {
                            const std::wstring deviceLower =
                                ToLowerCopy(devicePath);
                            const std::wstring targetLower =
                                ToLowerCopy(target);
                            // Prefix alone is not enough: HarddiskVolume30
                            // must not match a drive mapped to
                            // HarddiskVolume3, or the converted path eats
                            // the trailing digit.
                            const bool boundaryIsSeparator =
                                deviceLower.size() == targetLower.size() ||
                                deviceLower[targetLower.size()] == L'\\';
                            if (boundaryIsSeparator &&
                                deviceLower.compare(
                                    0,
                                    targetLower.size(),
                                    targetLower) == 0)
                            {
                                return drive.substr(0, 2) +
                                    devicePath.substr(targetLower.size());
                            }
                        }
                    }
                    cursor += drive.size() + 1;
                }
            }
        }
        return L"\\\\?\\GLOBALROOT" + devicePath;
    }

    // VirtualQueryEx analogue for handles stripped of PROCESS_QUERY_*:
    // a call-table slot target is interesting when a kernel VAD record
    // covers it, the VAD is executable, and the backing is private or a
    // data mapping rather than a module image (images are excluded by the
    // module-range check the caller already ran).
    bool KmonVadRecordLooksLikeCodeTarget(const ProcessVadRecord& record)
    {
        if (!record.Executable && !record.WritableExecutable)
        {
            return false;
        }
        if (record.HasPrivateMemory && record.PrivateMemory)
        {
            return record.CommitCharge != 0;
        }
        if (record.HasSubsection)
        {
            return record.SectionFileName.empty();
        }
        return false;
    }

    const ProcessVadRecord* KmonFindCoveringVadRecord(
        const std::vector<ProcessVadRecord>* records,
        uint64_t address)
    {
        if (records == nullptr)
        {
            return nullptr;
        }
        for (const ProcessVadRecord& record : *records)
        {
            if (VadCoversUserAddress(record, address))
            {
                return &record;
            }
        }
        return nullptr;
    }

    bool KmonOrphanRegionInteresting(
        const MEMORY_BASIC_INFORMATION& region,
        uint64_t exeRegion,
        const std::vector<std::pair<uint64_t, uint32_t>>& moduleRanges)
    {
        // LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE) maps a whole PE as one
        // read-only MEM_IMAGE allocation. Such benign resource views are module
        // list orphans with an MZ header, so only an executable region may
        // trigger the orphan MZ probe. Unlinked or manually mapped images keep
        // firing through their RX text sub-region at the same allocation base.
        const uint64_t alloc = reinterpret_cast<uint64_t>(region.AllocationBase);
        const bool mappedOrPrivate =
            region.Type == MEM_PRIVATE ||
            region.Type == MEM_IMAGE ||
            region.Type == MEM_MAPPED;
        return
            region.State == MEM_COMMIT &&
            region.RegionSize >= 0x1000 &&
            alloc != 0 &&
            alloc != exeRegion &&
            !AddressInModuleRanges(
                alloc,
                moduleRanges) &&
            mappedOrPrivate &&
            ProtectHasExecute(region.Protect);
    }
    bool CountPrivateCowImagePages(
        HANDLE process,
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        uint64_t imageBase,
        const uint32_t* rvas,
        uint32_t rvaCount,
        uint32_t* privateCount,
        uint32_t* validCount)
    {
        bool ok = false;
        do
        {
            if (privateCount == nullptr || validCount == nullptr)
            {
                break;
            }
            *privateCount = 0;
            *validCount = 0;
            if (process == nullptr || imageBase == 0 || rvas == nullptr || rvaCount == 0 || rvaCount > 8)
            {
                break;
            }
            PSAPI_WORKING_SET_EX_INFORMATION info[8] = {};
            bool overflow = false;
            for (uint32_t i = 0; i < rvaCount; ++i)
            {
                if (rvas[i] > (std::numeric_limits<uint64_t>::max)() - imageBase)
                {
                    overflow = true;
                    break;
                }
                const uint64_t page = (imageBase + rvas[i]) & ~0xFFFull;
                info[i].VirtualAddress = reinterpret_cast<PVOID>(page);
                std::vector<uint8_t> touch;
                ReadProcessBytes(device, symbols, process, pid, page, 8, &touch);
            }
            if (overflow)
            {
                break;
            }
            if (!QueryWorkingSetEx(
                    process,
                    info,
                    static_cast<DWORD>(sizeof(info[0]) * rvaCount)))
            {
                break;
            }
            uint32_t priv = 0;
            uint32_t valid = 0;
            for (uint32_t i = 0; i < rvaCount; ++i)
            {
                if (info[i].VirtualAttributes.Valid == 0)
                {
                    continue;
                }
                ++valid;
                if (info[i].VirtualAttributes.Shared == 0)
                {
                    ++priv;
                }
            }
            *privateCount = priv;
            *validCount = valid;
            ok = valid > 0;
        } while (false);
        return ok;
    }

    struct KmonUserTarget
    {
        uint32_t Pid = 0;
        std::wstring ImagePath;
        std::wstring Leaf;
        bool HighPriority = false;
        bool Interesting = false;
    };

    bool NameEqualsWatch(const std::wstring& baseLower, const std::vector<std::wstring>& watchLower)
    {
        bool matched = false;
        for (const std::wstring& item : watchLower)
        {
            if (item == L"*")
            {
                if (!baseLower.empty())
                {
                    matched = true;
                    break;
                }
                continue;
            }
            if (item == L"*.exe")
            {
                if (baseLower.size() >= 4 &&
                    baseLower.compare(baseLower.size() - 4, 4, L".exe") == 0)
                {
                    matched = true;
                    break;
                }
                continue;
            }
            if (item == L"*.sys")
            {
                if (baseLower.size() >= 4 &&
                    baseLower.compare(baseLower.size() - 4, 4, L".sys") == 0)
                {
                    matched = true;
                    break;
                }
                continue;
            }
            if (!baseLower.empty() && baseLower == item)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    bool QueryProcessImagePathByPid(uint32_t pid, std::wstring* path)
    {
        bool ok = false;
        HANDLE process = nullptr;
        do
        {
            if (path == nullptr || pid <= 4)
            {
                break;
            }
            path->clear();
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (process == nullptr)
            {
                break;
            }
            wchar_t buf[32768] = {};
            DWORD n = ARRAYSIZE(buf);
            if (!QueryFullProcessImageNameW(process, 0, buf, &n) || n == 0)
            {
                break;
            }
            path->assign(buf, n);
            ok = true;
        } while (false);
        if (process != nullptr)
        {
            CloseHandle(process);
        }
        return ok;
    }

    bool PathHasDirectorySeparator(const std::wstring& path)
    {
        return path.find_first_of(L"\\/") != std::wstring::npos;
    }

    bool KmonLooksLikeHijackDll(const std::wstring& leaf)
    {
        bool matched = false;
        static const wchar_t* names[] =
        {
            L"version.dll",
            L"winmm.dll",
            L"dwmapi.dll",
            L"d3d8.dll",
            L"d3d9.dll",
            L"d3d10.dll",
            L"d3d11.dll",
            L"d3d12.dll",
            L"dxgi.dll",
            L"msimg32.dll",
            L"lpk.dll",
            L"usp10.dll",
            L"cryptsp.dll",
            L"ntmarta.dll",
            L"wininet.dll",
            L"winhttp.dll",
            L"iphlpapi.dll",
            L"dbghelp.dll",
            L"dbgcore.dll",
            L"psapi.dll",
            L"imagehlp.dll",
            L"hid.dll",
            L"xinput1_3.dll",
            L"xinput1_4.dll",
            L"xinput9_1_0.dll",
            L"dinput8.dll",
            L"dsound.dll",
            L"wtsapi32.dll",
            L"userenv.dll",
            L"wsock32.dll",
            L"ws2_32.dll"
        };
        for (const wchar_t* name : names)
        {
            if (leaf == name)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    bool KmonLooksLikeHookableSystemDll(const std::wstring& leaf)
    {
        bool matched = false;
        static const wchar_t* names[] =
        {
            L"ntdll.dll",
            L"kernel32.dll",
            L"kernelbase.dll",
            L"user32.dll",
            L"win32u.dll",
            L"gdi32.dll",
            L"gdi32full.dll",
            L"ws2_32.dll",
            L"advapi32.dll",
            L"sechost.dll",
            L"rpcrt4.dll",
            L"bcrypt.dll",
            L"bcryptprimitives.dll",
            L"wow64.dll",
            L"wow64cpu.dll",
            L"wow64win.dll",
            L"dxgi.dll",
            L"d3d9.dll",
            L"d3d10.dll",
            L"d3d10_1.dll",
            L"d3d11.dll",
            L"d3d11on12.dll",
            L"d3d12.dll",
            L"d3d12core.dll",
            L"opengl32.dll",
            L"vulkan-1.dll"
        };
        for (const wchar_t* name : names)
        {
            if (leaf == name)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    bool KmonLooksLikeGraphicsApiDll(const std::wstring& leaf)
    {
        bool matched = false;
        static const wchar_t* names[] =
        {
            L"dxgi.dll",
            L"d3d9.dll",
            L"d3d10.dll",
            L"d3d10_1.dll",
            L"d3d11.dll",
            L"d3d11on12.dll",
            L"d3d12.dll",
            L"d3d12core.dll",
            L"opengl32.dll",
            L"vulkan-1.dll"
        };
        for (const wchar_t* name : names)
        {
            if (leaf == name)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    bool KmonLooksLikeOverlayRuntimeDll(const std::wstring& leaf)
    {
        return leaf.find(L"gameoverlayrenderer") != std::wstring::npos ||
            leaf.find(L"graphics-hook") != std::wstring::npos ||
            leaf.find(L"discordhook") != std::wstring::npos ||
            leaf.find(L"discord_hook") != std::wstring::npos ||
            leaf == L"rtsshooks.dll" ||
            leaf == L"rtsshooks64.dll";
    }

    bool KmonLooksLikeKernelImportTarget(const std::wstring& leaf)
    {
        return leaf == L"ntoskrnl.exe" ||
            leaf == L"ntkrnlmp.exe" ||
            leaf == L"hal.dll" ||
            (leaf.size() >= 3 && leaf.compare(0, 3, L"wdf") == 0);
    }

    uint32_t CountKernelImportStubs(
        const uint8_t* bytes,
        size_t size,
        uint64_t regionVa,
        const std::vector<KernelModuleInfo>& modules)
    {
        uint32_t hits = 0;
        if (bytes == nullptr || size < 14)
        {
            return 0;
        }

        auto targetIsKernelImport = [&](uint64_t target) -> bool
        {
            if (target < 0xFFFF800000000000ull)
            {
                return false;
            }
            for (const KernelModuleInfo& module : modules)
            {
                if (module.Base == 0 || module.Size == 0)
                {
                    continue;
                }
                if (target < module.Base)
                {
                    continue;
                }
                const uint64_t end = module.Base + module.Size;
                if (end < module.Base || target >= end)
                {
                    continue;
                }
                const std::wstring leaf = KmonBasenameLower(
                    module.ImageName.empty() ? module.ImagePath : module.ImageName);
                return KmonLooksLikeKernelImportTarget(leaf);
            }
            return false;
        };

        auto isIndirectBranchOpcode = [](uint8_t b) -> bool
        {
            return b == 0x25 || b == 0x15;
        };
        for (size_t i = 0; i + 6 <= size; ++i)
        {
            if (bytes[i] != 0xFF || !isIndirectBranchOpcode(bytes[i + 1]))
            {
                continue;
            }
            int32_t disp = 0;
            std::memcpy(&disp, bytes + i + 2, sizeof(disp));
            const uint64_t insnEnd = regionVa + static_cast<uint64_t>(i) + 6ull;
            const uint64_t slotVa = static_cast<uint64_t>(
                static_cast<int64_t>(insnEnd) + static_cast<int64_t>(disp));
            if (slotVa < regionVa)
            {
                continue;
            }
            const uint64_t slotOff = slotVa - regionVa;
            if (slotOff > size - 8)
            {
                continue;
            }
            uint64_t target = 0;
            std::memcpy(&target, bytes + slotOff, sizeof(target));
            if (target == 0)
            {
                continue;
            }
            if (target >= regionVa &&
                size > 0 &&
                target < regionVa + size)
            {
                continue;
            }
            if (targetIsKernelImport(target))
            {
                ++hits;
                i += 5;
            }
        }
        // Absolute-target thunks: mov rax, <imm64> followed within a few
        // bytes by jmp rax (FF E0) or call rax (FF D0). Mappers that skip
        // IAT-style slots resolve imports this way.
        for (size_t i = 0; i + 12 <= size; ++i)
        {
            if (bytes[i] != 0x48 || bytes[i + 1] != 0xB8)
            {
                continue;
            }
            uint64_t target = 0;
            std::memcpy(&target, bytes + i + 2, sizeof(target));
            if (target == 0)
            {
                continue;
            }
            if (target >= regionVa &&
                size > 0 &&
                target < regionVa + size)
            {
                continue;
            }
            bool branchesThroughRax = false;
            for (size_t j = i + 10; j + 1 < size && j <= i + 13; ++j)
            {
                if (bytes[j] == 0xFF &&
                    (bytes[j + 1] == 0xE0 || bytes[j + 1] == 0xD0))
                {
                    branchesThroughRax = true;
                    break;
                }
            }
            if (!branchesThroughRax)
            {
                continue;
            }
            if (targetIsKernelImport(target))
            {
                ++hits;
                i += 11;
            }
        }
        return hits;
    }

    bool KmonLooksLikeCfgHostModule(const std::wstring& leaf)
    {
        return leaf == L"ntoskrnl.exe" ||
            leaf == L"ntkrnlmp.exe" ||
            leaf == L"dxgkrnl.sys" ||
            leaf.compare(0, 6, L"win32k") == 0;
    }

    bool KmonVaLooksLikePagingOrFirmware(uint64_t va)
    {
        if (va < 0xFFFF800000000000ull)
        {
            return true;
        }
        if (va >= 0xFFFFF68000000000ull && va < 0xFFFFF70000000000ull)
        {
            return true;
        }
        if (va >= 0xFFFFF78000000000ull && va < 0xFFFFF80000000000ull)
        {
            return true;
        }
        if (va >= 0xFFFFF90000000000ull && va < 0xFFFFF98000000000ull)
        {
            return true;
        }
        return false;
    }

    uint32_t CollectCfgDataPtrSlotRvas(
        const uint8_t* text,
        size_t textSize,
        uint32_t textRva,
        uint32_t sizeOfImage,
        const std::unordered_set<uint32_t>& guardCallRvas,
        const std::unordered_set<uint32_t>& guardIatRvas,
        std::vector<uint32_t>* slotRvas,
        uint32_t maxSites)
    {
        uint32_t hits = 0;
        if (text == nullptr ||
            textSize < 12 ||
            slotRvas == nullptr ||
            maxSites == 0)
        {
            return 0;
        }
        slotRvas->clear();
        for (size_t i = 0; i + 12 <= textSize && hits < maxSites; ++i)
        {
            if (text[i] != 0x48 || text[i + 1] != 0x8B || text[i + 2] != 0x05)
            {
                continue;
            }
            int32_t disp = 0;
            std::memcpy(&disp, text + i + 3, sizeof(disp));
            const uint32_t movEnd = textRva + static_cast<uint32_t>(i) + 7u;
            const uint32_t slotRva = static_cast<uint32_t>(
                static_cast<int64_t>(movEnd) + disp);
            if (slotRva < 0x200 ||
                slotRva >= sizeOfImage ||
                (slotRva >= textRva &&
                    slotRva < textRva + static_cast<uint32_t>(textSize)))
            {
                continue;
            }
            bool matched = false;
            for (size_t k = 7; k + 5 <= 16 && i + k + 5 <= textSize; ++k)
            {
                const uint8_t op = text[i + k];
                if (op == 0x90 || op == 0xCC)
                {
                    continue;
                }
                if (op == 0xE8)
                {
                    int32_t callDisp = 0;
                    std::memcpy(&callDisp, text + i + k + 1, sizeof(callDisp));
                    const uint32_t callEnd =
                        textRva + static_cast<uint32_t>(i + k) + 5u;
                    const uint32_t dest = static_cast<uint32_t>(
                        static_cast<int64_t>(callEnd) + callDisp);
                    if (guardCallRvas.find(dest) != guardCallRvas.end())
                    {
                        matched = true;
                    }
                    break;
                }
                if (op == 0xFF && text[i + k + 1] == 0x15)
                {
                    int32_t iatDisp = 0;
                    std::memcpy(&iatDisp, text + i + k + 2, sizeof(iatDisp));
                    const uint32_t callEnd =
                        textRva + static_cast<uint32_t>(i + k) + 6u;
                    const uint32_t iatRva = static_cast<uint32_t>(
                        static_cast<int64_t>(callEnd) + iatDisp);
                    if (guardIatRvas.find(iatRva) != guardIatRvas.end())
                    {
                        matched = true;
                    }
                    break;
                }
                break;
            }
            if (!matched)
            {
                continue;
            }
            slotRvas->push_back(slotRva);
            ++hits;
            i += 6;
        }
        return hits;
    }

    void CollectGuardDispatchIatRvas(
        const std::wstring& path,
        const std::vector<uint8_t>& headers,
        const KmonPeLayout& layout,
        std::unordered_set<uint32_t>* iatRvas)
    {
        do
        {
            if (iatRvas == nullptr ||
                !layout.Is64 ||
                layout.ImportRva == 0 ||
                layout.ImportSize < sizeof(IMAGE_IMPORT_DESCRIPTOR))
            {
                break;
            }
            uint32_t fileOff = 0;
            if (!RvaToFileOffset(headers, layout.ImportRva, &fileOff))
            {
                break;
            }
            std::vector<uint8_t> table;
            const uint32_t toRead = (std::min)(layout.ImportSize, 0x10000u);
            if (!ReadDiskFileRange(path, fileOff, toRead, &table) ||
                table.size() < sizeof(IMAGE_IMPORT_DESCRIPTOR))
            {
                break;
            }
            const uint32_t count =
                static_cast<uint32_t>(table.size() / sizeof(IMAGE_IMPORT_DESCRIPTOR));
            for (uint32_t i = 0; i < count && i < 64; ++i)
            {
                IMAGE_IMPORT_DESCRIPTOR desc = {};
                std::memcpy(
                    &desc,
                    table.data() + (i * sizeof(IMAGE_IMPORT_DESCRIPTOR)),
                    sizeof(desc));
                if (desc.Name == 0)
                {
                    break;
                }
                uint32_t nameFile = 0;
                if (!RvaToFileOffset(headers, desc.Name, &nameFile))
                {
                    continue;
                }
                std::vector<uint8_t> nameBytes;
                if (!ReadDiskFileRange(path, nameFile, 64, &nameBytes) ||
                    nameBytes.empty())
                {
                    continue;
                }
                nameBytes.back() = 0;
                std::wstring wide;
                for (uint8_t byte : nameBytes)
                {
                    if (byte == 0)
                    {
                        break;
                    }
                    if (byte >= 0x20 && byte < 0x7f)
                    {
                        wide.push_back(static_cast<wchar_t>(byte));
                    }
                }
                const std::wstring leaf = KmonBasenameLower(wide);
                if (leaf != L"ntoskrnl.exe" && leaf != L"ntkrnlmp.exe")
                {
                    continue;
                }
                const uint32_t oft =
                    desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
                const uint32_t ft = desc.FirstThunk;
                if (oft == 0 || ft == 0)
                {
                    continue;
                }
                for (uint32_t t = 0; t < 512; ++t)
                {
                    uint32_t thunkFile = 0;
                    if (!RvaToFileOffset(headers, oft + t * 8u, &thunkFile))
                    {
                        break;
                    }
                    std::vector<uint8_t> thunkBytes;
                    if (!ReadDiskFileRange(path, thunkFile, 8, &thunkBytes) ||
                        thunkBytes.size() < 8)
                    {
                        break;
                    }
                    uint64_t thunk = 0;
                    std::memcpy(&thunk, thunkBytes.data(), sizeof(thunk));
                    if (thunk == 0)
                    {
                        break;
                    }
                    if ((thunk & IMAGE_ORDINAL_FLAG64) != 0)
                    {
                        continue;
                    }
                    uint32_t hintFile = 0;
                    if (!RvaToFileOffset(headers, static_cast<uint32_t>(thunk), &hintFile))
                    {
                        continue;
                    }
                    std::vector<uint8_t> hintName;
                    if (!ReadDiskFileRange(path, hintFile, 64, &hintName) ||
                        hintName.size() < 4)
                    {
                        continue;
                    }
                    hintName.back() = 0;
                    const char* importName =
                        reinterpret_cast<const char*>(hintName.data() + 2);
                    if (ExportNameLooksLikeGuardDispatch(importName))
                    {
                        iatRvas->insert(ft + t * 8u);
                    }
                }
            }
        } while (false);
    }

    bool KmonLooksLikeKnownRuntimePath(const std::wstring& normalized)
    {
        bool matched = false;
        static const wchar_t* fragments[] =
        {
            L"\\gameoverlayrenderer",
            L"\\discord\\",
            L"\\obs-studio\\",
            L"\\graphics-hook",
            L"\\nvidia corporation\\",
            L"\\easyanticheat",
            L"\\easy anti-cheat",
            L"\\battleye",
            L"\\beclient",
            L"\\faceit",
            L"\\vanguard"
        };
        for (const wchar_t* fragment : fragments)
        {
            if (normalized.find(fragment) != std::wstring::npos)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    void EnrichProcessImagePath(
        DeviceClient* device,
        SymbolEngine* symbols,
        uint32_t pid,
        std::wstring* path)
    {
        if (path == nullptr || pid <= 4)
        {
            return;
        }
        if (!PathLooksLikeWin32File(*path) && PathHasDirectorySeparator(*path))
        {
            std::wstring win32 = Win32PathFromKernelImagePath(*path);
            if (PathLooksLikeWin32File(win32))
            {
                *path = std::move(win32);
            }
        }
        if (PathLooksLikeWin32File(*path))
        {
            return;
        }
        std::wstring kernelPath;
        if (QueryKernelImagePath(device, symbols, pid, &kernelPath) &&
            PathHasDirectorySeparator(kernelPath))
        {
            *path = std::move(kernelPath);
        }
    }

    std::wstring KmonImageForClassify(uint32_t pid, const std::wstring& maybePath)
    {
        if (PathHasDirectorySeparator(maybePath))
        {
            return maybePath;
        }
        std::wstring resolved;
        if (QueryProcessImagePathByPid(pid, &resolved) && !resolved.empty())
        {
            return resolved;
        }
        return maybePath;
    }

    std::wstring FormatKmonJsonLine(const KmonEvent& event)
    {
        std::wstringstream line;
        line << L"{\"ts\":\"" << JsonEscape(TimestampUtcString(event.Timestamp)) << L"\""
             << L",\"seq\":" << event.Sequence
             << L",\"kind\":\"" << JsonEscape(event.Kind) << L"\""
             << L",\"pid\":" << event.ProcessId
             << L",\"target_pid\":" << event.TargetProcessId
             << L",\"image\":\"" << JsonEscape(event.Image) << L"\""
             << L",\"target_image\":\"" << JsonEscape(event.TargetImage) << L"\""
             << L",\"driver\":\"" << JsonEscape(event.Driver) << L"\""
             << L",\"task\":\"" << JsonEscape(event.Task) << L"\""
             << L",\"summary\":\"" << JsonEscape(event.Summary) << L"\"";
        if (!event.Evidence.empty())
        {
            line << L",\"evidence\":{";
            bool first = true;
            for (const auto& item : event.Evidence)
            {
                if (!first)
                {
                    line << L",";
                }
                first = false;
                line << L"\"" << JsonEscape(item.first) << L"\":\""
                     << JsonEscape(item.second) << L"\"";
            }
            line << L"}";
        }
        line << L"}\n";
        return line.str();
    }

    typedef LONG NTSTATUS;
    typedef NTSTATUS(NTAPI* NtSetInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG);

    bool TryEnableLoggingUsermode(
        uint32_t pid,
        uint32_t loggingFlags,
        uint32_t* infoClass = nullptr)
    {
        bool ok = false;
        HANDLE process = nullptr;

        do
        {
            if (infoClass != nullptr)
            {
                *infoClass = 0;
            }
            process = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
            if (process == nullptr)
            {
                break;
            }

            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                break;
            }

            auto setInfo = reinterpret_cast<NtSetInformationProcessFn>(
                GetProcAddress(ntdll, "NtSetInformationProcess"));
            if (setInfo == nullptr)
            {
                break;
            }

            ULONG flags = loggingFlags;
            ULONG classUsed = kProcessEnableLogging;
            NTSTATUS status = setInfo(
                process,
                kProcessEnableLogging,
                &flags,
                sizeof(flags));
            if (status < 0)
            {
                UCHAR smallFlags = static_cast<UCHAR>(loggingFlags & 0x3u);
                classUsed = kProcessEnableReadWriteVmLogging;
                status = setInfo(
                    process,
                    kProcessEnableReadWriteVmLogging,
                    &smallFlags,
                    sizeof(smallFlags));
            }
            if (status >= 0)
            {
                if (infoClass != nullptr)
                {
                    *infoClass = classUsed;
                }
                ok = true;
            }
        } while (false);

        if (process != nullptr)
        {
            CloseHandle(process);
        }

        return ok;
    }

    void DisableProcessLogging(DeviceClient* device, uint32_t pid)
    {
        if (pid <= 4)
        {
            return;
        }
        TryEnableLoggingUsermode(pid, 0);
        if (device == nullptr || !device->IsOpen())
        {
            return;
        }
        uint32_t applied = 0;
        uint32_t infoClass = 0;
        uint32_t ntStatus = 0;
        uint64_t eprocess = 0;
        std::wstring error;
        device->SetProcessLogging(
            pid,
            0,
            &applied,
            &infoClass,
            &ntStatus,
            &eprocess,
            &error,
            true);
    }

    bool CollectToolhelpPidsByName(
        const std::vector<std::wstring>& namesLower,
        std::vector<uint32_t>* pids)
    {
        if (pids == nullptr || namesLower.empty())
        {
            return true;
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (!Process32FirstW(snap, &entry))
        {
            CloseHandle(snap);
            return false;
        }
        BOOL more = TRUE;
        DWORD nextError = ERROR_SUCCESS;
        do
        {
            std::wstring base = KmonBasenameLower(entry.szExeFile);
            if (NameEqualsWatch(base, namesLower) && entry.th32ProcessID > 4)
            {
                pids->push_back(entry.th32ProcessID);
            }
            entry.dwSize = sizeof(entry);
            more = Process32NextW(snap, &entry);
            if (!more)
            {
                nextError = GetLastError();
            }
        } while (more);
        CloseHandle(snap);
        if (nextError != ERROR_NO_MORE_FILES &&
            nextError != ERROR_SUCCESS)
        {
            return false;
        }
        return true;
    }
}

std::wstring KmonBasenameLower(const std::wstring& path)
{
    if (path.empty())
    {
        return path;
    }
    size_t slash = path.find_last_of(L"\\/");
    std::wstring base = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    return ToLowerCopy(std::move(base));
}

std::wstring KmonNormalizeDriverPath(const std::wstring& path)
{
    std::wstring n = ToLowerCopy(path);
    for (wchar_t& ch : n)
    {
        if (ch == L'/')
        {
            ch = L'\\';
        }
    }

    const std::wstring prefixes[] = {
        L"\\\\?\\",
        L"\\\\.\\",
        L"\\??\\",
        L"\\dosdevices\\"
    };
    bool stripped = true;
    while (stripped)
    {
        stripped = false;
        for (const std::wstring& prefix : prefixes)
        {
            if (n.size() >= prefix.size() && n.compare(0, prefix.size(), prefix) == 0)
            {
                n.erase(0, prefix.size());
                stripped = true;
                break;
            }
        }
    }

    const std::wstring systemRootSlash = L"\\systemroot\\";
    const std::wstring systemRoot = L"systemroot\\";
    if (n.size() >= systemRootSlash.size() &&
        n.compare(0, systemRootSlash.size(), systemRootSlash) == 0)
    {
        n.replace(0, systemRootSlash.size(), L"\\windows\\");
    }
    else if (n.size() >= systemRoot.size() &&
        n.compare(0, systemRoot.size(), systemRoot) == 0)
    {
        n.replace(0, systemRoot.size(), L"\\windows\\");
    }

    // GetMappedFileNameW / some TI payloads yield
    // \Device\HarddiskVolumeN\Program Files\... . Treating the NT prefix as a
    // drop FPs every Program Files game as exe_mapped_path / inject.remote.
    const std::wstring harddisk = L"\\device\\harddiskvolume";
    if (n.size() > harddisk.size() && n.compare(0, harddisk.size(), harddisk) == 0)
    {
        size_t i = harddisk.size();
        while (i < n.size() && n[i] >= L'0' && n[i] <= L'9')
        {
            ++i;
        }
        if (i < n.size() && n[i] == L'\\')
        {
            n.erase(0, i);
        }
        else if (i == n.size())
        {
            n = L"\\";
        }
    }

    if (!n.empty() && n[0] != L'\\' && n.find(L":\\") != 1 &&
        n.find(L'\\') != std::wstring::npos)
    {
        n.insert(n.begin(), L'\\');
    }
    return n;
}

std::wstring KmonClassifyDriverPath(const std::wstring& path)
{
    std::wstring n = KmonNormalizeDriverPath(path);
    if (n.empty())
    {
        return L"unknown";
    }

    if (n.find(L"\\windows\\system32\\drivers\\") != std::wstring::npos ||
        n.find(L"\\windows\\system32\\driverstore\\") != std::wstring::npos ||
        n.find(L"\\windows\\winsxs\\") != std::wstring::npos ||
        n.find(L"\\windows\\system32\\codeintegrity\\") != std::wstring::npos)
    {
        return L"inbox";
    }

    if (n.find(L"\\users\\") != std::wstring::npos ||
        n.find(L"\\appdata\\") != std::wstring::npos ||
        n.find(L"\\windows\\temp\\") != std::wstring::npos ||
        n.find(L"\\programdata\\") != std::wstring::npos ||
        n.find(L"\\downloads\\") != std::wstring::npos ||
        n.find(L"$recycle.bin") != std::wstring::npos)
    {
        return L"drop";
    }

    // "\temp\" after the drop-dir checks so C:\Windows\foo.sys is not inbox,
    // but C:\Temp\x.sys still counts. Do not use a bare "\tmp\" match; it is
    // too wide.
    if (n.find(L"\\temp\\") != std::wstring::npos)
    {
        return L"drop";
    }

    // Volume-root drop: C:\cheat.sys or \cheat.sys
    size_t lastSlash = n.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos)
    {
        std::wstring parent = n.substr(0, lastSlash);
        if (parent.size() == 2 && parent[1] == L':')
        {
            return L"drop";
        }
        if (parent.empty())
        {
            return L"drop";
        }
    }

    if (n.find(L"\\program files") != std::wstring::npos)
    {
        return L"third_party";
    }

    if (n.find(L"\\device\\") != std::wstring::npos &&
        n.find(L"\\windows\\") == std::wstring::npos)
    {
        if (KmonPathLooksLikeSys(n) ||
            n.find(L"harddiskvolume") != std::wstring::npos ||
            n.find(L"\\users\\") != std::wstring::npos)
        {
            return L"drop";
        }
    }

    // win32k.sys lives in System32, not drivers. Still inbox.
    // SysWOW64 is the 32-bit OS tree, not a drop directory.
    if (n.find(L"\\windows\\system32\\") != std::wstring::npos ||
        n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
        n.find(L"\\windows\\sysnative\\") != std::wstring::npos ||
        n.find(L"\\windows\\microsoft.net\\") != std::wstring::npos ||
        n.find(L"\\windows\\assembly\\") != std::wstring::npos ||
        n.find(L"\\windows\\systemapps\\") != std::wstring::npos ||
        n.find(L"\\windows\\servicing\\") != std::wstring::npos)
    {
        return L"inbox";
    }

    // C:\Windows\cheat.sys is a classic masquerade drop, not inbox.
    if (n.find(L"\\windows\\") != std::wstring::npos)
    {
        return L"drop";
    }

    return L"unknown";
}

bool KmonDriverPathIsInbox(const std::wstring& path)
{
    return KmonClassifyDriverPath(path) == L"inbox";
}

bool KmonDriverPathHasFileDirectory(const std::wstring& path)
{
    std::wstring n = KmonNormalizeDriverPath(path);
    if (n.empty())
    {
        return false;
    }
    size_t slash = n.find_last_of(L'\\');
    if (slash == std::wstring::npos)
    {
        return false;
    }
    std::wstring parent = n.substr(0, slash);
    if (parent.empty())
    {
        return false;
    }
    if (parent == L"\\driver" || parent == L"\\device")
    {
        return false;
    }
    return true;
}

bool KmonIsWindowsBuiltinLeaf(const std::wstring& leaf)
{
    const std::wstring name = KmonBasenameLower(leaf);
    static const wchar_t* kLeaves[] = {
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"services.exe",
        L"lsass.exe",
        L"svchost.exe",
        L"spoolsv.exe",
        L"conhost.exe",
        L"dllhost.exe",
        L"rundll32.exe",
        L"regsvr32.exe",
        L"taskhostw.exe",
        L"runtimebroker.exe",
        L"explorer.exe",
        L"sihost.exe",
        L"searchindexer.exe",
        L"wmiprvse.exe",
        L"dwm.exe",
        L"fontdrvhost.exe",
        L"userinit.exe",
        L"smartscreen.exe",
        L"consent.exe",
        L"werfault.exe",
        L"msiexec.exe",
        L"mmc.exe",
        L"notepad.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"pwsh.exe",
        L"wscript.exe",
        L"cscript.exe",
        L"mshta.exe",
        L"hh.exe",
        L"wuauclt.exe",
        L"fodhelper.exe",
        L"computerdefaults.exe",
        L"taskmgr.exe",
        L"regedit.exe"
    };
    bool matched = false;
    for (const wchar_t* item : kLeaves)
    {
        if (name == item)
        {
            matched = true;
            break;
        }
    }
    return matched;
}

bool KmonWindowsBuiltinPathLooksInbox(const std::wstring& path)
{
    bool inbox = false;
    do
    {
        const std::wstring leaf = KmonBasenameLower(path);
        if (!KmonIsWindowsBuiltinLeaf(leaf))
        {
            break;
        }
        const std::wstring n = KmonNormalizeDriverPath(path);
        if (n.find(L"\\users\\") != std::wstring::npos ||
            n.find(L"\\appdata\\") != std::wstring::npos ||
            n.find(L"\\temp\\") != std::wstring::npos ||
            n.find(L"\\programdata\\") != std::wstring::npos)
        {
            break;
        }
        if (leaf == L"explorer.exe")
        {
            inbox = n.find(L"\\windows\\explorer.exe") != std::wstring::npos;
            break;
        }
        if (leaf == L"notepad.exe")
        {
            inbox = n.find(L"\\windows\\system32\\") != std::wstring::npos ||
                n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                n.find(L"\\windowsapps\\") != std::wstring::npos;
            break;
        }
        if (leaf == L"pwsh.exe")
        {
            inbox = n.find(L"\\windows\\system32\\") != std::wstring::npos ||
                n.find(L"\\program files\\powershell\\") != std::wstring::npos ||
                n.find(L"\\program files (x86)\\powershell\\") != std::wstring::npos;
            break;
        }
        if (leaf == L"wmiprvse.exe")
        {
            inbox = n.find(L"\\windows\\system32\\wbem\\") != std::wstring::npos ||
                n.find(L"\\windows\\syswow64\\wbem\\") != std::wstring::npos;
            break;
        }
        inbox = n.find(L"\\windows\\system32\\") != std::wstring::npos ||
            n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
            n.find(L"\\windows\\winsxs\\") != std::wstring::npos;
    } while (false);
    return inbox;
}

bool KmonPathLooksLikeSys(const std::wstring& path)
{
    std::wstring lower = ToLowerCopy(path);
    while (!lower.empty() &&
        (lower.back() == L'\0' || lower.back() == L' ' || lower.back() == L'.'))
    {
        lower.pop_back();
    }
    if (lower.size() < 4)
    {
        return false;
    }
    return lower.compare(lower.size() - 4, 4, L".sys") == 0;
}

bool KmonTaskLooksLikeDriverObjectLoad(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"driverobjectload") != std::wstring::npos ||
        lower.find(L"driver_object_load") != std::wstring::npos ||
        (lower.find(L"driverobject") != std::wstring::npos &&
            lower.find(L"unload") == std::wstring::npos &&
            lower.find(L"load") != std::wstring::npos);
}

bool KmonTaskLooksLikeDriverObjectUnload(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"driverobjectunload") != std::wstring::npos ||
        lower.find(L"driver_object_unload") != std::wstring::npos ||
        (lower.find(L"driverobject") != std::wstring::npos &&
            lower.find(L"unload") != std::wstring::npos);
}

bool KmonTaskLooksLikeDeviceObject(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"deviceobject") != std::wstring::npos ||
        lower.find(L"device_object") != std::wstring::npos;
}

bool KmonTaskLooksLikeRemoteInject(const std::wstring& task)
{
    // ReadVM / Suspend / Resume alone are not injection. Anti-cheat, overlays,
    // dumpers, and the OS itself remote-read constantly. Staging + write/APC
    // / context change is the inject surface.
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"allocvm") != std::wstring::npos ||
        lower.find(L"protectvm") != std::wstring::npos ||
        lower.find(L"mapview") != std::wstring::npos ||
        lower.find(L"queueuserapc") != std::wstring::npos ||
        lower.find(L"setthreadcontext") != std::wstring::npos ||
        lower.find(L"writevm") != std::wstring::npos;
}

bool KmonTaskLooksLikeRemoteInjectWrite(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"writevm") != std::wstring::npos ||
        lower.find(L"queueuserapc") != std::wstring::npos ||
        lower.find(L"setthreadcontext") != std::wstring::npos;
}

bool KmonTaskLooksLikeRemoteInjectMaterial(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return KmonTaskLooksLikeRemoteInjectWrite(task) ||
        lower.find(L"allocvm") != std::wstring::npos ||
        lower.find(L"protectvm") != std::wstring::npos ||
        lower.find(L"mapview") != std::wstring::npos;
}

std::wstring KmonExtractPayloadDriverName(const std::vector<TiPayloadField>& payload)
{
    std::wstring found;

    do
    {
        for (const TiPayloadField& field : payload)
        {
            if (field.Value.empty() || field.Value[0] == L'<')
            {
                continue;
            }

            std::wstring nameLower = ToLowerCopy(field.Name);
            std::wstring valueLower = ToLowerCopy(field.Value);
            const bool driverish =
                nameLower.find(L"driver") != std::wstring::npos ||
                nameLower.find(L"imagefilename") != std::wstring::npos ||
                nameLower.find(L"filename") != std::wstring::npos ||
                nameLower.find(L"device") != std::wstring::npos;
            const bool sysValue = KmonPathLooksLikeSys(field.Value);
            if (!driverish && !sysValue)
            {
                continue;
            }

            found = field.Value;
            if (sysValue || nameLower.find(L"driver") != std::wstring::npos)
            {
                break;
            }
        }
    } while (false);

    return found;
}

bool KmonClassifyTiEvent(const TiEventRecord& record, KmonEvent* out)
{
    bool classified = false;

    do
    {
        if (out == nullptr)
        {
            break;
        }

        *out = KmonEvent{};
        out->Timestamp = record.Timestamp;
        out->ProcessId = record.ProcessId;
        out->TargetProcessId = record.TargetProcessId;
        out->Image = record.ImagePath;
        out->TargetImage = record.TargetImageBase;
        out->Task = record.TaskName.empty()
            ? (L"Task" + std::to_wstring(record.TaskId))
            : record.TaskName;
        out->Driver = KmonExtractPayloadDriverName(record.Payload);
        const std::wstring pathClass = KmonClassifyDriverPath(out->Driver);
        if (!out->Driver.empty())
        {
            out->Evidence[L"path_class"] = pathClass;
        }

        if (KmonTaskLooksLikeDriverObjectLoad(out->Task))
        {
            if (out->Driver.empty())
            {
                out->Kind = L"driver.official_load";
                out->Evidence[L"path_class"] = L"unknown";
                out->Summary = L"DRIVER_OBJECT load with undecoded image path";
            }
            else if (pathClass == L"inbox")
            {
                out->Kind = L"driver.official_load";
                out->Summary = L"inbox DRIVER_OBJECT load " + out->Driver;
            }
            else if (pathClass == L"drop" ||
                pathClass == L"third_party" ||
                KmonDriverPathHasFileDirectory(out->Driver))
            {
                out->Kind = L"driver.drop_load";
                out->Summary = L"non-inbox DRIVER_OBJECT load " + out->Driver;
            }
            else
            {
                // Bare filename or \Driver/\Device object path. Hiding these
                // by default avoids acpi.sys / DeviceObject firehoses when
                // TDH yields a leaf name instead of a file path.
                out->Kind = L"driver.official_load";
                out->Summary = L"DRIVER_OBJECT load " + out->Driver;
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeDriverObjectUnload(out->Task))
        {
            out->Kind = L"driver.official_unload";
            out->Summary = L"DRIVER_OBJECT unload";
            if (!out->Driver.empty())
            {
                out->Summary += L" " + KmonBasenameLower(out->Driver);
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeDeviceObject(out->Task))
        {
            out->Kind = L"driver.device";
            out->Summary = L"DEVICE_OBJECT load/unload";
            if (!out->Driver.empty())
            {
                out->Summary += L" " + KmonBasenameLower(out->Driver);
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeRemoteInject(out->Task) &&
            record.TargetProcessId != 0 &&
            record.TargetProcessId != record.ProcessId)
        {
            out->Image = KmonImageForClassify(record.ProcessId, record.ImagePath);
            out->TargetImage = KmonImageForClassify(
                record.TargetProcessId,
                record.TargetImageBase);
            out->Kind = L"inject.remote";
            out->Summary = out->Task + L" pid=" + std::to_wstring(record.ProcessId) +
                L" -> pid=" + std::to_wstring(record.TargetProcessId);
            classified = true;
            break;
        }
    } while (false);

    return classified;
}

static bool EvidenceIsTrue(const std::map<std::wstring, std::wstring>& evidence, const std::wstring& key)
{
    auto it = evidence.find(key);
    return it != evidence.end() && it->second == L"true";
}

static bool KmonParseHexU64(const std::wstring& text, uint64_t* value)
{
    bool ok = false;

    do
    {
        if (value == nullptr || text.empty())
        {
            break;
        }

        const wchar_t* start = text.c_str();
        if (start[0] == L'0' && (start[1] == L'x' || start[1] == L'X'))
        {
            start += 2;
        }
        if (*start == L'\0')
        {
            break;
        }

        wchar_t* end = nullptr;
        unsigned long long parsed = wcstoull(start, &end, 16);
        if (end == start)
        {
            break;
        }

        *value = static_cast<uint64_t>(parsed);
        ok = true;
    } while (false);

    return ok;
}

static bool KmonEvidenceLooksKernelImageBase(const std::map<std::wstring, std::wstring>& evidence)
{
    auto it = evidence.find(L"image_base");
    if (it == evidence.end())
    {
        return false;
    }

    uint64_t va = 0;
    if (!KmonParseHexU64(it->second, &va) || va == 0)
    {
        return false;
    }

    // Bit 63 set is the x64 kernel half for both 48-bit and LA57 canonical VAs.
    return (va & 0x8000000000000000ull) != 0;
}

static void CopyImageNotifyEvidence(const TimelineEvent& event, KmonEvent* out)
{
    if (out == nullptr)
    {
        return;
    }

    const std::wstring keys[] = {
        L"image_base",
        L"image_size",
        L"file_object",
        L"system_mode",
        L"signature_level",
        L"signature_type",
        L"partial_map"
    };
    for (const std::wstring& key : keys)
    {
        auto it = event.Evidence.find(key);
        if (it != event.Evidence.end() && !it->second.empty())
        {
            out->Evidence[key] = it->second;
        }
    }
}

static void AppendImageNotifySummary(KmonEvent* out)
{
    if (out == nullptr)
    {
        return;
    }

    auto append = [&](const std::wstring& key, const std::wstring& label)
    {
        auto it = out->Evidence.find(key);
        if (it == out->Evidence.end() || it->second.empty())
        {
            return;
        }
        if (key == L"system_mode" && it->second == L"true")
        {
            out->Summary += L" km";
            return;
        }
        if (key == L"partial_map" && it->second == L"true")
        {
            out->Summary += L" partial";
            return;
        }
        out->Summary += L" " + label + L"=" + it->second;
    };
    append(L"image_base", L"base");
    append(L"image_size", L"size");
    append(L"signature_level", L"sig");
    append(L"system_mode", L"km");
    append(L"partial_map", L"partial");
}

bool KmonClassifyLiveEvent(const TimelineEvent& event, KmonEvent* out)
{
    bool classified = false;

    do
    {
        if (out == nullptr)
        {
            break;
        }

        *out = KmonEvent{};
        out->Timestamp = event.TimestampFileTime;
        out->ProcessId = event.ProcessId;
        out->TargetProcessId = event.TargetProcessId;
        out->Image = event.Entity;
        out->Task = event.Action;

        std::wstring action = ToLowerCopy(event.Action);
        const bool systemMode = EvidenceIsTrue(event.Evidence, L"system_mode");
        const bool kernelImageBase = KmonEvidenceLooksKernelImageBase(event.Evidence);
        const bool looksKernelImage =
            systemMode ||
            kernelImageBase ||
            event.ProcessId == 0 ||
            event.ProcessId == 4;
        const bool unnamedPlaceholder =
            event.Entity.empty() ||
            event.Entity.rfind(L"pid:", 0) == 0;
        if (action == L"image-load" && looksKernelImage)
        {
            if (unnamedPlaceholder &&
                !systemMode &&
                !kernelImageBase &&
                event.ProcessId != 0 &&
                event.ProcessId != 4)
            {
                break;
            }

            const std::wstring pathClass = unnamedPlaceholder
                ? std::wstring(L"unknown")
                : KmonClassifyDriverPath(event.Entity);
            const bool fileDrop =
                pathClass == L"drop" ||
                pathClass == L"third_party" ||
                (pathClass != L"inbox" && KmonDriverPathHasFileDirectory(event.Entity));
            if (!fileDrop &&
                pathClass != L"inbox" &&
                !KmonPathLooksLikeSys(event.Entity) &&
                !systemMode &&
                !kernelImageBase &&
                event.ProcessId != 0 &&
                event.ProcessId != 4)
            {
                break;
            }

            out->Driver = unnamedPlaceholder ? std::wstring() : event.Entity;
            out->Evidence[L"path_class"] = pathClass;
            out->Evidence[L"source"] = L"image_notify";
            CopyImageNotifyEvidence(event, out);
            if (fileDrop)
            {
                out->Kind = L"driver.drop_load";
                out->Summary = L"non-inbox kernel image load " +
                    (unnamedPlaceholder ? std::wstring(L"<unnamed>") : event.Entity);
                out->Evidence[L"followup"] = L"!pool pe /suspicious; !mapper; !kpage /pe";
            }
            else
            {
                out->Kind = L"driver.image_only";
                if (unnamedPlaceholder)
                {
                    out->Summary = L"unnamed kernel image load";
                }
                else if (pathClass == L"inbox")
                {
                    out->Summary = L"inbox kernel image load " + KmonBasenameLower(event.Entity);
                }
                else
                {
                    out->Summary = L"kernel image load " + KmonBasenameLower(event.Entity);
                }
            }
            AppendImageNotifySummary(out);
            classified = true;
            break;
        }

        if (action == L"process-create")
        {
            const std::wstring leaf = KmonBasenameLower(event.Entity);
            if (KmonIsWindowsBuiltinLeaf(leaf) &&
                !event.Entity.empty() &&
                PathHasDirectorySeparator(event.Entity) &&
                !KmonWindowsBuiltinPathLooksInbox(event.Entity))
            {
                out->Kind = L"process.masquerade";
                out->Summary = L"Windows-named process from a non-inbox path pid=" +
                    std::to_wstring(event.ProcessId) + L" " + event.Entity;
                out->Evidence[L"path_class"] = KmonClassifyDriverPath(event.Entity);
            }
            else
            {
                out->Kind = L"process.create";
                out->Summary = L"process create pid=" + std::to_wstring(event.ProcessId);
            }
            classified = true;
            break;
        }
    } while (false);

    return classified;
}

bool KmonWatchMatches(const KmonEvent& event, const KmonOptions& options)
{
    bool matched = false;

    do
    {
        if (event.Kind.empty())
        {
            break;
        }

        if (event.Kind == L"gap.kernel_rw" ||
            event.Kind == L"process.hidden" ||
            event.Kind == L"process.syscall_unnamed" ||
            event.Kind == L"driver.drop_load" ||
            event.Kind == L"driver.image_only" ||
            event.Kind == L"driver.short_lived" ||
            event.Kind == L"driver.mapped_residue" ||
            event.Kind == L"driver.handle" ||
            event.Kind == L"driver.ioctl" ||
            event.Kind == L"mapper.watch" ||
            event.Kind == L"hook.unbacked" ||
            event.Kind == L"hook.dataptr" ||
            event.Kind == L"inject.kernel_phys" ||
            event.Kind == L"integrity.ci" ||
            event.Kind == L"integrity.cr" ||
            event.Kind == L"process.masquerade" ||
            event.Kind == L"process.hollow" ||
            event.Kind == L"process.implant")
        {
            matched = true;
            break;
        }

        std::wstring driverBase = KmonBasenameLower(event.Driver);
        const bool namedDriver =
            !event.Driver.empty() && NameEqualsWatch(driverBase, options.WatchDrivers);
        std::wstring pathClass;
        auto pathIt = event.Evidence.find(L"path_class");
        if (pathIt != event.Evidence.end())
        {
            pathClass = pathIt->second;
        }

        if (event.Kind.rfind(L"driver.", 0) == 0)
        {
            // /driver is a highlight, not an exclusive filter. Unknown
            // drop/map/unload names must still surface.
            if (namedDriver)
            {
                matched = true;
                break;
            }
            if (options.VerboseDrivers)
            {
                matched = true;
                break;
            }
            // Empty payload paths are common when TDH leaves DriverName as
            // <struct>. Do not treat those as drops or the tail becomes a
            // DeviceObject/unload firehose. /driver * must not override this.
            if (event.Driver.empty())
            {
                break;
            }
            if (pathClass == L"inbox")
            {
                break;
            }
            if (event.Kind == L"driver.official_unload")
            {
                if (pathClass == L"drop" ||
                    pathClass == L"third_party" ||
                    KmonDriverPathHasFileDirectory(event.Driver))
                {
                    matched = true;
                }
                break;
            }
            if (event.Kind == L"driver.device")
            {
                if (KmonPathLooksLikeSys(event.Driver))
                {
                    matched = true;
                }
                break;
            }
            break;
        }

        if (event.Kind == L"inject.remote")
        {
            std::wstring caller = KmonBasenameLower(event.Image);
            std::wstring target = KmonBasenameLower(event.TargetImage);
            const std::wstring callerClass = KmonClassifyDriverPath(event.Image);
            const std::wstring targetClass = KmonClassifyDriverPath(event.TargetImage);
            const bool dropSide = callerClass == L"drop" || targetClass == L"drop";
            const bool unknownFileSide =
                (callerClass == L"unknown" &&
                    PathHasDirectorySeparator(event.Image)) ||
                (targetClass == L"unknown" &&
                    PathHasDirectorySeparator(event.TargetImage));
            const bool builtinSide =
                KmonIsWindowsBuiltinLeaf(caller) || KmonIsWindowsBuiltinLeaf(target);
            if ((dropSide || unknownFileSide) &&
                KmonTaskLooksLikeRemoteInject(event.Task))
            {
                matched = true;
                break;
            }
            if (builtinSide && KmonTaskLooksLikeRemoteInjectWrite(event.Task))
            {
                matched = true;
                break;
            }
            if (options.WatchPids.empty() && options.WatchNames.empty())
            {
                break;
            }
            bool watchCaller = NameEqualsWatch(caller, options.WatchNames);
            bool watchTarget = NameEqualsWatch(target, options.WatchNames);
            for (uint32_t pid : options.WatchPids)
            {
                if (pid == event.ProcessId)
                {
                    watchCaller = true;
                }
                if (pid == event.TargetProcessId)
                {
                    watchTarget = true;
                }
            }
            if (!watchCaller && !watchTarget)
            {
                break;
            }
            if (KmonTaskLooksLikeRemoteInjectMaterial(event.Task))
            {
                matched = true;
                break;
            }
            break;
        }

        if (event.Kind == L"loader.activity")
        {
            if (options.WatchPids.empty() && options.WatchNames.empty())
            {
                break;
            }
            std::wstring caller = KmonBasenameLower(event.Image);
            if (NameEqualsWatch(caller, options.WatchNames))
            {
                matched = true;
                break;
            }
            for (uint32_t pid : options.WatchPids)
            {
                if (pid == event.ProcessId || pid == event.TargetProcessId)
                {
                    matched = true;
                    break;
                }
            }
            break;
        }

        if (event.Kind == L"process.create")
        {
            if (options.WatchNames.empty() && options.WatchPids.empty())
            {
                break;
            }
            std::wstring base = KmonBasenameLower(event.Image);
            if (NameEqualsWatch(base, options.WatchNames))
            {
                matched = true;
                break;
            }
            for (uint32_t pid : options.WatchPids)
            {
                if (pid == event.ProcessId)
                {
                    matched = true;
                    break;
                }
            }
            break;
        }
    } while (false);

    return matched;
}

static std::wstring KmonEventPathClass(const KmonEvent& event)
{
    auto it = event.Evidence.find(L"path_class");
    if (it == event.Evidence.end())
    {
        return std::wstring();
    }
    return it->second;
}

static bool KmonPathClassLooksMapped(const std::wstring& pathClass, const std::wstring& driver)
{
    if (pathClass == L"drop" || pathClass == L"third_party")
    {
        return true;
    }
    if (pathClass != L"inbox" && KmonDriverPathHasFileDirectory(driver))
    {
        return true;
    }
    return false;
}

bool KmonDriverLoadArmsMapperWatch(const KmonEvent& event)
{
    if (event.Kind == L"driver.drop_load")
    {
        return true;
    }
    if (event.Kind == L"driver.image_only")
    {
        const std::wstring pathClass = KmonEventPathClass(event);
        if (pathClass == L"inbox")
        {
            return false;
        }
        if (event.Driver.empty())
        {
            return true;
        }
        return KmonPathClassLooksMapped(pathClass, event.Driver) ||
            pathClass == L"unknown";
    }
    if (event.Kind == L"driver.official_load")
    {
        return KmonPathClassLooksMapped(KmonEventPathClass(event), event.Driver);
    }
    return false;
}

bool KmonDriverUnloadArmsMapperWatch(const KmonEvent& event)
{
    if (event.Kind != L"driver.official_unload" && event.Kind != L"driver.short_lived")
    {
        return false;
    }
    return KmonPathClassLooksMapped(KmonEventPathClass(event), event.Driver);
}

KernelMonitor::KernelMonitor() = default;

KernelMonitor::~KernelMonitor()
{
    std::wstring ignored;
    Stop(&ignored);
}

bool KernelMonitor::IsActive() const
{
    return Active.load();
}

bool KernelMonitor::IsLiveOutputEnabled() const
{
    return LiveOutput.load();
}

void KernelMonitor::SetLiveOutput(bool enabled)
{
    LiveOutput.store(enabled);
}

KmonOptions KernelMonitor::CurrentOptions() const
{
    KmonOptions options;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        options = Options;
    }
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        options.WatchPids.assign(WatchPids.begin(), WatchPids.end());
        options.WatchNames = WatchNamesLower;
        options.WatchDrivers = WatchDriversLower;
    }
    return options;
}

std::vector<uint32_t> KernelMonitor::SnapshotWatchPids() const
{
    std::vector<uint32_t> pids;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        pids.assign(WatchPids.begin(), WatchPids.end());
    }
    return pids;
}

std::wstring KernelMonitor::SnapshotMapperWatchId() const
{
    std::lock_guard<std::mutex> watchLock(WatchMutex);
    return MapperWatchId;
}

std::vector<uint64_t> KernelMonitor::SnapshotResiduePfns() const
{
    std::lock_guard<std::mutex> watchLock(WatchMutex);
    return std::vector<uint64_t>(
        MapperWatchResiduePfns.begin(),
        MapperWatchResiduePfns.end());
}

void KernelMonitor::NoteMapperWatchResidue(
    const std::wstring& layer,
    uint64_t physicalAddress)
{
    const bool watchActive = IsMapperWatchActive();
    // Idle findings still register their PFN so !hunt can join them into
    // kernel_backed_user_window; the watch-scoped flags and the callers
    // that pass no physical address stay gated on an active watch.
    if (!watchActive && physicalAddress < 0x1000)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    if (watchActive &&
        (layer == L"kpage_code" ||
         layer == L"pool_code" ||
         layer == L"dataptr"))
    {
        MapperWatchHasResidue = true;
    }
    if (watchActive && layer == L"overlay_slot")
    {
        MapperWatchHasOverlaySlot = true;
    }
    if (physicalAddress >= 0x1000)
    {
        MapperWatchResiduePfns.insert(physicalAddress >> 12);
    }
}

void KernelMonitor::NoteWatchTiWriteIfNeeded(const KmonEvent& event)
{
    if (!IsMapperWatchActive())
    {
        return;
    }
    std::wstring lower = ToLowerCopy(event.Task);
    if (lower.find(L"writevm") == std::wstring::npos &&
        lower.find(L"protectvm") == std::wstring::npos)
    {
        lower = ToLowerCopy(event.Kind);
        if (lower.find(L"writevm") == std::wstring::npos &&
            lower.find(L"protectvm") == std::wstring::npos)
        {
            return;
        }
    }
    const uint32_t pid =
        event.TargetProcessId != 0 ? event.TargetProcessId : event.ProcessId;
    if (pid == 0)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    if (WatchPids.find(pid) != WatchPids.end())
    {
        MapperWatchTiWritePids.insert(pid);
    }
}

KmonStats KernelMonitor::SnapshotStats() const
{
    KmonStats stats;
    stats.EventsKept = EventsKept.load();
    stats.EventsDropped = EventsDropped.load();
    stats.EventsLogged = EventsLogged.load();
    stats.EventsWatchMatched = EventsWatchMatched.load();
    stats.TiIngested = TiIngested.load();
    stats.LiveIngested = LiveIngested.load();
    stats.HiddenScans = HiddenScans.load();
    stats.MapperScans = MapperScans.load();
    stats.PoolPeScans = PoolPeScans.load();
    stats.KpageScans = KpageScans.load();
    stats.HookScans = HookScans.load();
    stats.CpuHookScans = CpuHookScans.load();
    stats.UserHostilityScans = UserHostilityScans.load();
    stats.MapperWatchArmed = MapperWatchArmedCount.load();
    stats.MapperWatchScans = MapperWatchScans.load();
    {
        const uint64_t nowMs = GetTickCount64();
        const uint64_t until = MapperWatchUntilMs.load();
        if (until > nowMs)
        {
            stats.MapperWatchRemainMs = until - nowMs;
        }
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        stats.MapperWatchDriver = MapperWatchDriver;
        stats.MapperWatchId = MapperWatchId;
    }
    stats.LoggingEnabled = LoggingEnabledCount.load();
    stats.LoggingFailed = LoggingFailedCount.load();
    stats.LogBytesWritten = LogBytesWritten.load();
    stats.LogRotations = LogRotations.load();
    stats.StartTickMs = StartTickMs.load();
    stats.LastEventTickMs = LastEventTickMs.load();
    return stats;
}

bool KernelMonitor::Start(
    const KmonOptions& options,
    TiSubscriber* ti,
    TimelineStore* timeline,
    DeviceClient* device,
    SymbolEngine* symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (ti == nullptr || timeline == nullptr || device == nullptr || symbols == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"kmon requires TI, timeline, device, and symbols";
            }
            break;
        }

        {
            std::lock_guard<std::mutex> lock(StateMutex);
            if (Active.load())
            {
                if (error != nullptr)
                {
                    *error = L"kmon already active";
                }
                break;
            }

            KmonOptions previousOptions = Options;
            KmonOptions nextOptions = options;
            if (nextOptions.RingCapacity < 1024)
            {
                nextOptions.RingCapacity = 65536;
            }
            if (nextOptions.ThrottlePerSecond == 0)
            {
                nextOptions.ThrottlePerSecond = 50;
            }
            if (nextOptions.LogDirectory.empty())
            {
                nextOptions.LogDirectory = ExeDirectory();
            }
            if (nextOptions.HiddenScanIntervalMs < 1000)
            {
                nextOptions.HiddenScanIntervalMs = 5000;
            }
            if (nextOptions.MapperScanIntervalMs < 1000)
            {
                nextOptions.MapperScanIntervalMs = 8000;
            }

            {
                std::vector<std::wstring> names;
                names.reserve(nextOptions.WatchNames.size());
                for (const std::wstring& name : nextOptions.WatchNames)
                {
                    std::wstring token = KmonBasenameLower(name);
                    if (!token.empty())
                    {
                        names.push_back(std::move(token));
                    }
                }
                nextOptions.WatchNames = std::move(names);
            }
            {
                std::vector<std::wstring> drivers;
                drivers.reserve(nextOptions.WatchDrivers.size());
                for (const std::wstring& name : nextOptions.WatchDrivers)
                {
                    std::wstring token = KmonBasenameLower(name);
                    if (!token.empty())
                    {
                        drivers.push_back(std::move(token));
                    }
                }
                nextOptions.WatchDrivers = std::move(drivers);
            }

            // Open the log before replacing watches/ring so a failed start
            // does not drop the previous session or half-apply Options.
            Options = nextOptions;
            {
                std::lock_guard<std::mutex> logLock(LogMutex);
                CloseLogLocked();
                if (!EnsureLogOpenLocked())
                {
                    Options = previousOptions;
                    if (error != nullptr)
                    {
                        *error = L"could not open kmon log in " + nextOptions.LogDirectory;
                    }
                    LiveOutput.store(false);
                    break;
                }
            }

            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                WatchPids.clear();
                WatchExplicitPids.clear();
                WatchNamesLower = Options.WatchNames;
                WatchDriversLower = Options.WatchDrivers;
                WatchPromotedPids.clear();
                WatchPromotedCreated.clear();
                WatchChildPids.clear();
                WatchActivityTasks.clear();
                WatchKnownHandles.clear();
                WatchDeviceTypeKnown = false;
                IotraceActive = false;
                IotraceDriverName.clear();
                IotraceSeen.clear();
                IotraceSeenCapNoted = false;
                LoggingEnabledPids.clear();
                LoggingFailedPids.clear();
                RecentCreatePids.clear();
                EmittedUnnamedPids.clear();
                EmittedMapperKeys.clear();
                RecentLoads.clear();
                MapperWatchLast = MapperWatchFingerprint{};
                MapperWatchDriver.clear();
                MapperWatchId.clear();
                MapperWatchEmitTick.clear();
                MapperWatchHasResidue = false;
                MapperWatchHasOverlaySlot = false;
                MapperWatchTiWritePids.clear();
                MapperWatchResiduePfns.clear();
                CfgDataPtrSites.clear();
                CfgDataPtrNtosBase = 0;
                for (uint32_t pid : Options.WatchPids)
                {
                    WatchPids.insert(pid);
                    WatchExplicitPids.insert(pid);
                }
            }

            Ti = ti;
            Timeline = timeline;
            Device = device;
            Symbols = symbols;
            // Skip TI/live events that already arrived before this arm.
            // Cursor 0 re-dumps the ring on stop+start and on first start
            // after a standalone !ti session.
            TiCursorSequence = 0;
            LiveCursorEventId = 0;
            {
                std::vector<TiEventRecord> latestTi = ti->Recent(1, true);
                if (!latestTi.empty() && latestTi[0].Sequence != 0)
                {
                    TiCursorSequence = latestTi[0].Sequence;
                }
                const uint64_t nextLive = timeline->PeekNextEventId();
                if (nextLive > 1)
                {
                    LiveCursorEventId = nextLive - 1;
                }
            }
            NextHiddenScanTickMs = 0;
            NextMapperScanTickMs = 0;
            NextKpageScanTickMs = 0;
            NextUserScanTickMs = 0;
            MapperWatchUntilMs.store(0);
            MapperWatchOriginMs.store(0);
            MapperWatchDeepPfnPending.store(false);

            EventsKept.store(0);
            EventsDropped.store(0);
            EventsLogged.store(0);
            EventsWatchMatched.store(0);
            TiIngested.store(0);
            LiveIngested.store(0);
            HiddenScans.store(0);
            MapperScans.store(0);
            PoolPeScans.store(0);
            KpageScans.store(0);
            HookScans.store(0);
            CpuHookScans.store(0);
            UserHostilityScans.store(0);
            MapperWatchArmedCount.store(0);
            MapperWatchScans.store(0);
            LoggingEnabledCount.store(0);
            LoggingFailedCount.store(0);
            LogBytesWritten.store(0);
            LogRotations.store(0);
            StartTickMs.store(GetTickCount64());
            LastEventTickMs.store(0);
            ThrottleWindowStartMs.store(0);
            ThrottleWindowCount.store(0);
            ThrottleSuppressed.store(0);

            {
                std::lock_guard<std::mutex> ringLock(RingMutex);
                Ring.clear();
                NextSequence = 1;
            }
            {
                std::lock_guard<std::mutex> printLock(PrintMutex);
                PrintQueue.clear();
            }

            StopRequested.store(false);
            LiveOutput.store(Options.AttachLiveTail);
            Active.store(true);
            if (!Worker.joinable())
            {
                try
                {
                    Worker = std::thread(&KernelMonitor::WorkerLoop, this);
                }
                catch (...)
                {
                    Active.store(false);
                    LiveOutput.store(false);
                    {
                        std::lock_guard<std::mutex> logLock(LogMutex);
                        CloseLogLocked();
                    }
                    if (error != nullptr)
                    {
                        *error = L"could not start kmon worker thread";
                    }
                    break;
                }
            }
        }

        if (!Active.load() || StopRequested.load())
        {
            {
                std::lock_guard<std::mutex> logLock(LogMutex);
                CloseLogLocked();
            }
            if (error != nullptr && error->empty())
            {
                *error = L"kmon became inactive during start";
            }
            break;
        }

        EnableLoggingForWatchTargets();

        KmonEvent gap = {};
        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        gap.Timestamp = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        gap.Kind = L"gap.kernel_rw";
        gap.Summary =
            L"kernel MmCopyVirtualMemory / DeviceIoControl is not on ETW-TI; kmon samples callbacks, input stacks, SSDT/IDT, pool PE, and kpage";
        gap.Evidence[L"followup"] =
            L"!callbacks; !inputstack; !ssdt; !idt; !msrcheck; !driver integrity; !pool pe; !kpage /pe";
        RecordEvent(std::move(gap));

        if (!Active.load() || StopRequested.load())
        {
            {
                std::lock_guard<std::mutex> logLock(LogMutex);
                CloseLogLocked();
            }
            if (error != nullptr)
            {
                *error = L"kmon became inactive during start";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelMonitor::Stop(std::wstring* error)
{
    std::thread worker;
    DeviceClient* device = nullptr;
    std::vector<uint32_t> loggingPids;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        StopRequested.store(true);
        Active.store(false);
        LiveOutput.store(false);
        device = Device;
        if (Worker.joinable())
        {
            worker = std::move(Worker);
        }
        Ti = nullptr;
        Timeline = nullptr;
        Device = nullptr;
        Symbols = nullptr;
    }
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        loggingPids.reserve(LoggingEnabledPids.size());
        for (const auto& entry : LoggingEnabledPids)
        {
            loggingPids.push_back(entry.first);
        }
        LoggingEnabledPids.clear();
        LoggingFailedPids.clear();
        LoggingEnabledCount.store(0);
    }

    if (worker.joinable())
    {
        worker.join();
    }

    // Leaving an interposed dispatch in place after the session ends would
    // keep pointing at this process's IOCTL channel; disarm it now.
    DisarmIotrace(nullptr);

    for (uint32_t pid : loggingPids)
    {
        DisableProcessLogging(device, pid);
    }

    {
        std::lock_guard<std::mutex> logLock(LogMutex);
        CloseLogLocked();
    }

    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

void KernelMonitor::WorkerLoop()
{
    while (!StopRequested.load())
    {
        IngestLiveTimeline();
        IngestThreatIntel();
        DrainIotraceEvents();

        const uint64_t nowMs = GetTickCount64();
        const bool mapperWatch = IsMapperWatchActive();
        uint32_t hiddenInterval = 5000;
        uint32_t mapperInterval = 8000;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            hiddenInterval = Options.HiddenScanIntervalMs;
            mapperInterval = Options.MapperScanIntervalMs;
        }
        if (hiddenInterval < 1000)
        {
            hiddenInterval = 5000;
        }
        if (mapperInterval < 1000)
        {
            mapperInterval = 8000;
        }
        const uint32_t idleMapperInterval = mapperInterval;

        // First tick only schedules the scans. Walking PsActiveProcessHead
        // plus mapper leftovers stalls TI ingest at the exact moment a
        // short-lived drop is most likely to appear.
        if (NextHiddenScanTickMs == 0)
        {
            NextHiddenScanTickMs = nowMs + 1000;
        }
        else if (nowMs >= NextHiddenScanTickMs)
        {
            ScanHiddenProcesses();
            IngestLiveTimeline();
            IngestThreatIntel();
            NextHiddenScanTickMs = GetTickCount64() + hiddenInterval;
        }

        if (NextMapperScanTickMs == 0)
        {
            NextMapperScanTickMs = nowMs + 1000;
        }
        else if (nowMs >= NextMapperScanTickMs)
        {
            if (mapperWatch)
            {
                MapperWatchScans.fetch_add(1);
            }
            ScanMapperRemnants();
            IngestLiveTimeline();
            IngestThreatIntel();
            if (!StopRequested.load())
            {
                ScanPoolMappedImages();
            }
            IngestLiveTimeline();
            IngestThreatIntel();
            if (!StopRequested.load())
            {
                ScanUnbackedDriverObjects();
            }
            IngestLiveTimeline();
            IngestThreatIntel();
            if (!StopRequested.load())
            {
                ScanHookCallbacks();
            }
            IngestLiveTimeline();
            IngestThreatIntel();
            if (!StopRequested.load())
            {
                ScanHookInput();
            }
            NextMapperScanTickMs = GetTickCount64() +
                (IsMapperWatchActive() ? kMapperWatchIntervalMs : idleMapperInterval);
        }

        if (NextKpageScanTickMs == 0)
        {
            NextKpageScanTickMs = nowMs + 2000;
        }
        else if (nowMs >= NextKpageScanTickMs)
        {
            ScanCpuIntegrityHooks();
            IngestLiveTimeline();
            IngestThreatIntel();
            if (!StopRequested.load())
            {
                ScanOrphanMappedPages();
            }
            NextKpageScanTickMs = GetTickCount64() +
                (IsMapperWatchActive()
                    ? kMapperWatchKpageIntervalMs
                    : kKpageScanIntervalMs);
        }

        if (NextUserScanTickMs == 0)
        {
            NextUserScanTickMs = nowMs + 1500;
        }
        else if (nowMs >= NextUserScanTickMs)
        {
            PruneStalePromotedWatches();
            EnableLoggingForWatchTargets();
            ScanUserModeHostility();
            if (!StopRequested.load())
            {
                ScanWatchedHandleTables();
            }
            IngestLiveTimeline();
            IngestThreatIntel();
            NextUserScanTickMs = GetTickCount64() + kUserScanIntervalMs;
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(IsMapperWatchActive() ? 50 : 200));
    }
}

void KernelMonitor::IngestThreatIntel()
{
    TiSubscriber* ti = nullptr;
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        ti = Ti;
        device = Device;
        symbols = Symbols;
    }
    if (ti == nullptr || !ti->IsActive())
    {
        return;
    }

    std::vector<TiEventRecord> batch = ti->RecentAfterSequence(TiCursorSequence, 512);
    uint32_t activityEvents = 0;
    for (const TiEventRecord& record : batch)
    {
        if (record.Sequence != 0)
        {
            TiCursorSequence = record.Sequence;
        }
        TiIngested.fetch_add(1);

        KmonEvent classified = {};
        if (KmonClassifyTiEvent(record, &classified))
        {
            if (classified.Kind == L"driver.drop_load" ||
                classified.Kind == L"driver.official_load")
            {
                NoteDriverLoad(classified);
            }
            if (classified.Kind == L"driver.official_unload")
            {
                MaybeEmitShortLived(classified);
                if (KmonDriverUnloadArmsMapperWatch(classified))
                {
                    ArmMapperWatch(classified);
                }
            }
            if (classified.Kind == L"inject.remote")
            {
                auto resolveInjectImage = [&](uint32_t pid, std::wstring* image)
                {
                    if (image == nullptr || pid <= 4)
                    {
                        return;
                    }
                    if (PathLooksLikeWin32File(*image))
                    {
                        return;
                    }
                    if (PathHasDirectorySeparator(*image))
                    {
                        std::wstring win32 = Win32PathFromKernelImagePath(*image);
                        if (PathLooksLikeWin32File(win32))
                        {
                            *image = std::move(win32);
                            return;
                        }
                    }
                    std::wstring resolved;
                    if (QueryKernelImagePath(
                            device,
                            symbols,
                            pid,
                            &resolved) &&
                        PathHasDirectorySeparator(resolved))
                    {
                        *image = std::move(resolved);
                    }
                };
                resolveInjectImage(classified.TargetProcessId, &classified.TargetImage);
                resolveInjectImage(classified.ProcessId, &classified.Image);
            }
            RecordEvent(std::move(classified));
        }
        else if (activityEvents < 128)
        {
            // Unclassified TI tasks still describe what a watched loader
            // did (file/registry/VM/material tasks); keep a compact
            // first-seen-per-task trail instead of dropping them. This
            // also lets NoteWatchTiWriteIfNeeded see WriteVM/ProtectVM
            // tasks that classification rejected.
            const uint32_t callerPid =
                record.ProcessId != 0 ? record.ProcessId : record.TargetProcessId;
            const std::wstring task = record.TaskName.empty()
                ? (L"Task" + std::to_wstring(record.TaskId))
                : record.TaskName;
            if (NoteWatchActivityTask(callerPid, task))
            {
                KmonEvent activity = {};
                activity.Timestamp = record.Timestamp;
                activity.ProcessId = record.ProcessId;
                activity.TargetProcessId = record.TargetProcessId;
                activity.Image = record.ImagePath;
                activity.Task = task;
                activity.Kind = L"loader.activity";
                activity.Summary = task + L" pid=" + std::to_wstring(record.ProcessId);
                if (record.TargetProcessId != 0 &&
                    record.TargetProcessId != record.ProcessId)
                {
                    activity.Summary += L" -> pid=" +
                        std::to_wstring(record.TargetProcessId);
                }
                activity.Evidence[L"task"] = task;
                if (!record.OpcodeName.empty())
                {
                    activity.Evidence[L"opcode"] = record.OpcodeName;
                }
                if (record.TargetProcessId != 0)
                {
                    activity.Evidence[L"target_pid"] =
                        std::to_wstring(record.TargetProcessId);
                }
                if (record.ThreadId != 0)
                {
                    activity.Evidence[L"tid"] = std::to_wstring(record.ThreadId);
                }
                ++activityEvents;
                RecordEvent(std::move(activity));
            }
        }

        if (record.ProcessId > 4 && record.ImagePath.empty())
        {
            HANDLE unnamedProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                record.ProcessId);
            const uint64_t created = QueryPidCreateTime(
                device,
                symbols,
                unnamedProcess,
                record.ProcessId);
            if (unnamedProcess != nullptr)
            {
                CloseHandle(unnamedProcess);
            }
            bool claimed = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                const std::wstring unnamedKey =
                    L"unnamed:" + std::to_wstring(record.ProcessId) + L":" +
                    (created != 0 ? std::to_wstring(created) : std::wstring(L"gone"));
                claimed = EmittedMapperKeys.insert(unnamedKey).second;
                if (claimed)
                {
                    EmittedUnnamedPids.insert(record.ProcessId);
                }
            }
            if (claimed)
            {
                std::wstring kernelName;
                ResolveKernelImageName(record.ProcessId, &kernelName);
                KmonEvent unnamed = {};
                unnamed.Timestamp = record.Timestamp;
                unnamed.Kind = L"process.syscall_unnamed";
                unnamed.ProcessId = record.ProcessId;
                unnamed.Image = kernelName;
                unnamed.Task = record.TaskName;
                unnamed.Summary = L"TI pid=" + std::to_wstring(record.ProcessId) +
                    L" with empty OpenProcess image";
                if (!kernelName.empty())
                {
                    unnamed.Summary += L" kernel_name=" + kernelName;
                    unnamed.Evidence[L"kernel_image"] = kernelName;
                }
                RecordEvent(std::move(unnamed));
            }
        }
    }
}

void KernelMonitor::IngestLiveTimeline()
{
    TimelineStore* timeline = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        timeline = Timeline;
    }
    if (timeline == nullptr)
    {
        return;
    }

    // timeline clear() resets NextEventId to 1. A stale cursor then skips
    // every new live event for the rest of the session.
    if (LiveCursorEventId != 0 && timeline->PeekNextEventId() <= LiveCursorEventId)
    {
        LiveCursorEventId = 0;
    }

    std::vector<TimelineEvent> batch = timeline->RecentAfterEventId(LiveCursorEventId, 1024);
    for (const TimelineEvent& event : batch)
    {
        if (event.EventId > LiveCursorEventId)
        {
            LiveCursorEventId = event.EventId;
        }
        if (ToLowerCopy(event.Source) != L"kernel-live")
        {
            continue;
        }
        LiveIngested.fetch_add(1);

        KmonEvent classified = {};
        if (!KmonClassifyLiveEvent(event, &classified))
        {
            continue;
        }

        if (classified.Kind == L"process.create" ||
            classified.Kind == L"process.masquerade")
        {
            std::wstring base = KmonBasenameLower(classified.Image);
            uint32_t parentPid = 0;
            auto parentIt = event.Evidence.find(L"parent_pid");
            if (parentIt != event.Evidence.end())
            {
                parentPid = static_cast<uint32_t>(
                    std::wcstoul(parentIt->second.c_str(), nullptr, 10));
            }
            bool nameWatch = false;
            bool childWatch = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                nameWatch = NameEqualsWatch(base, WatchNamesLower) &&
                    classified.ProcessId > 4;
                if (nameWatch)
                {
                    WatchPromotedPids.insert(classified.ProcessId);
                    WatchPids.insert(classified.ProcessId);
                }
                // Descendants of a watched loader inherit the watch so the
                // 2nd stage gets hostility scans, VM logging, and the TI
                // activity trail even after the parent exits.
                childWatch =
                    !nameWatch &&
                    classified.ProcessId > 4 &&
                    parentPid != 0 &&
                    WatchPids.count(parentPid) != 0;
                if (childWatch)
                {
                    WatchPromotedPids.insert(classified.ProcessId);
                    WatchPids.insert(classified.ProcessId);
                    WatchChildPids[classified.ProcessId] = parentPid;
                }
                if (classified.ProcessId > 4)
                {
                    RecentCreatePids[classified.ProcessId] = GetTickCount64();
                    while (RecentCreatePids.size() > 512)
                    {
                        auto oldest = RecentCreatePids.begin();
                        for (auto it = RecentCreatePids.begin(); it != RecentCreatePids.end(); ++it)
                        {
                            if (it->second < oldest->second)
                            {
                                oldest = it;
                            }
                        }
                        RecentCreatePids.erase(oldest);
                    }
                }
            }
            if ((nameWatch || childWatch) && classified.ProcessId > 4)
            {
                EnableLoggingForPid(classified.ProcessId);
            }
            if (childWatch)
            {
                classified.Evidence[L"watch_source"] =
                    L"child_of:" + std::to_wstring(parentPid);
            }
        }

        if (classified.Kind == L"driver.drop_load" ||
            classified.Kind == L"driver.official_load" ||
            classified.Kind == L"driver.image_only")
        {
            NoteDriverLoad(classified);
        }

        RecordEvent(std::move(classified));
    }
}

void KernelMonitor::ScanHiddenProcesses()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        EmitUnique(
            L"process.hidden",
            L"scan_failed:hidden:device",
            std::wstring(),
            L"hiddenproc",
            L"hidden-process scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:hidden:device");
    if (!EnsureLoadedKernelModules(symbols, true))
    {
        EmitUnique(
            L"process.hidden",
            L"scan_failed:hidden:inventory",
            std::wstring(),
            L"hiddenproc",
            L"hidden-process scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:hidden:inventory");

    HiddenProcessScanner scanner(*device, *symbols);
    HiddenProcessScanResult result = {};
    std::wstring error;
    std::vector<uint32_t> extraPids;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        const uint64_t nowMs = GetTickCount64();
        for (auto it = RecentCreatePids.begin(); it != RecentCreatePids.end();)
        {
            if (nowMs - it->second > 120000)
            {
                it = RecentCreatePids.erase(it);
                continue;
            }
            extraPids.push_back(it->first);
            ++it;
        }
        extraPids.insert(extraPids.end(), WatchPids.begin(), WatchPids.end());
    }
    if (!scanner.Scan(&result, extraPids, &error))
    {
        EmitUnique(
            L"process.hidden",
            L"scan_failed:hidden",
            std::wstring(),
            L"hiddenproc",
            L"hidden-process scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    HiddenScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:hidden");
    if (result.CoverageComplete)
    {
        ClearEmittedKey(L"scan_failed:hidden:coverage");
    }
    else
    {
        std::wstring notes;
        for (const std::wstring& warning : result.Warnings)
        {
            if (!notes.empty())
            {
                notes += L"; ";
            }
            notes += warning;
            if (notes.size() > 768)
            {
                break;
            }
        }
        if (notes.empty())
        {
            notes = L"kernel, SPI, or Toolhelp inventory was incomplete";
        }
        EmitUnique(
            L"process.hidden",
            L"scan_failed:hidden:coverage",
            std::wstring(),
            L"hiddenproc",
            L"hidden-process coverage was incomplete; kernel-only and API-only findings stay fail-closed",
            notes);
    }

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    const uint64_t ts = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;

    for (const HiddenProcessRecord& record : result.Records)
    {
        if (!record.Suspicious)
        {
            continue;
        }

        const uint64_t created = (record.Eprocess != 0)
            ? QueryEprocessCreateTime(device, symbols, nullptr, record.Eprocess)
            : 0;
        bool already = false;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            const std::wstring hideKey =
                L"hidden:" + std::to_wstring(record.ProcessId) + L":" +
                HexU64(record.Eprocess) + L":" + std::to_wstring(created);
            already = !EmittedMapperKeys.insert(hideKey).second;
        }
        if (already)
        {
            continue;
        }

        KmonEvent event = {};
        event.Timestamp = ts;
        event.Kind = L"process.hidden";
        event.ProcessId = record.ProcessId;
        event.Image = record.ImageName;
        event.Summary = L"hidden process pid=" + std::to_wstring(record.ProcessId);
        if (!record.ImageName.empty())
        {
            event.Summary += L" " + record.ImageName;
        }
        event.Evidence[L"in_kernel"] = record.InKernelList ? L"true" : L"false";
        event.Evidence[L"in_spi"] = record.InSystemProcessInfo ? L"true" : L"false";
        event.Evidence[L"in_toolhelp"] = record.InToolhelp ? L"true" : L"false";
        event.Evidence[L"in_handles"] = record.InHandleOwners ? L"true" : L"false";
        event.Evidence[L"in_cid"] = record.InCidTable ? L"true" : L"false";
        event.Evidence[L"notes"] = record.Notes;
        event.Evidence[L"followup"] = L"!hiddenproc; !vad " + std::to_wstring(record.ProcessId);
        RecordEvent(std::move(event));
    }
}

void KernelMonitor::NoteDriverLoad(const KmonEvent& event)
{
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        RecentDriverLoad load = {};
        load.Base = KmonBasenameLower(event.Driver);
        load.Path = event.Driver;
        auto it = event.Evidence.find(L"path_class");
        if (it != event.Evidence.end())
        {
            load.PathClass = it->second;
        }
        load.Timestamp = event.Timestamp;
        RecentLoads.push_back(std::move(load));
        while (RecentLoads.size() > 64)
        {
            RecentLoads.pop_front();
        }
    }
    if (KmonDriverLoadArmsMapperWatch(event))
    {
        ArmMapperWatch(event);
    }
}

bool KernelMonitor::IsMapperWatchActive() const
{
    const uint64_t until = MapperWatchUntilMs.load();
    return until != 0 && GetTickCount64() < until;
}

void KernelMonitor::ArmMapperWatch(const KmonEvent& event)
{
    const uint64_t nowMs = GetTickCount64();
    const std::wstring base = KmonBasenameLower(event.Driver);
    bool emit = false;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        const uint64_t previous = MapperWatchUntilMs.load();
        const bool wasActive = previous != 0 && nowMs < previous;
        uint64_t origin = MapperWatchOriginMs.load();
        if (!wasActive)
        {
            origin = nowMs;
            MapperWatchOriginMs.store(origin);
            MapperWatchLast = MapperWatchFingerprint{};
            MapperWatchDeepPfnPending.store(true);
            MapperWatchId = std::to_wstring(origin) + L":" +
                (base.empty() ? L"<unnamed>" : base);
            MapperWatchHasResidue = false;
            MapperWatchHasOverlaySlot = false;
            MapperWatchTiWritePids.clear();
            MapperWatchResiduePfns.clear();
            for (auto it = EmittedMapperKeys.begin(); it != EmittedMapperKeys.end(); )
            {
                if (it->compare(0, 9, L"unloaded:") == 0 ||
                    it->compare(0, 6, L"piddb:") == 0 ||
                    it->compare(0, 5, L"hash:") == 0)
                {
                    it = EmittedMapperKeys.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
        uint64_t until = nowMs + kMapperWatchWindowMs;
        const uint64_t cap = origin + kMapperWatchMaxMs;
        if (until > cap)
        {
            until = cap;
        }
        if (until > previous)
        {
            MapperWatchUntilMs.store(until);
        }
        MapperWatchDriver = event.Driver.empty() ? base : event.Driver;
        uint64_t& lastEmit = MapperWatchEmitTick[base.empty() ? L"<unnamed>" : base];
        if (lastEmit == 0 || nowMs < lastEmit || (nowMs - lastEmit) >= kMapperWatchEmitDebounceMs)
        {
            lastEmit = nowMs;
            emit = true;
        }
    }
    NextMapperScanTickMs = 1;
    NextKpageScanTickMs = 1;
    MapperWatchArmedCount.fetch_add(1);

    if (!emit)
    {
        return;
    }

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    KmonEvent watch = {};
    watch.Timestamp = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    watch.Kind = L"mapper.watch";
    watch.Driver = event.Driver;
    watch.Task = event.Kind;
    watch.Summary = L"mapper watch 30s after " + event.Kind;
    if (!base.empty())
    {
        watch.Summary += L" " + base;
    }
    watch.Evidence[L"window_ms"] = std::to_wstring(kMapperWatchWindowMs);
    watch.Evidence[L"window_max_ms"] = std::to_wstring(kMapperWatchMaxMs);
    watch.Evidence[L"scan_ms"] = std::to_wstring(kMapperWatchIntervalMs);
    watch.Evidence[L"kpage_ms"] = std::to_wstring(kMapperWatchKpageIntervalMs);
    watch.Evidence[L"followup"] = L"!mapper all; !pool pe /suspicious; !kpage /pe /deep";
    watch.Evidence[L"watch_id"] = {};
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        watch.Evidence[L"watch_id"] = MapperWatchId;
    }
    auto pathIt = event.Evidence.find(L"path_class");
    if (pathIt != event.Evidence.end())
    {
        watch.Evidence[L"path_class"] = pathIt->second;
    }
    RecordEvent(std::move(watch));
}

void KernelMonitor::MaybeEmitShortLived(const KmonEvent& unloadEvent)
{
    constexpr uint64_t kWindow = 30ull * 10000000ull; // 30s FILETIME
    std::wstring base = KmonBasenameLower(unloadEvent.Driver);
    KmonEvent shortLived = {};
    bool emit = false;

    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        auto loadIsShortLivedCandidate = [](const RecentDriverLoad& load)
        {
            if (load.PathClass == L"inbox" || load.PathClass == L"unknown")
            {
                return !load.Path.empty() &&
                    load.PathClass != L"inbox" &&
                    KmonDriverPathHasFileDirectory(load.Path);
            }
            return load.PathClass == L"drop" || load.PathClass == L"third_party";
        };
        auto driverStem = [](const std::wstring& name)
        {
            std::wstring stem = KmonBasenameLower(name);
            if (stem.size() > 4 &&
                stem.compare(stem.size() - 4, 4, L".sys") == 0)
            {
                stem.resize(stem.size() - 4);
            }
            return stem;
        };
        const RecentDriverLoad* matchedLoad = nullptr;
        uint32_t unnamedHits = 0;
        const std::wstring unloadStem = driverStem(base);
        for (auto it = RecentLoads.rbegin(); it != RecentLoads.rend(); ++it)
        {
            if (unloadEvent.Timestamp < it->Timestamp)
            {
                continue;
            }
            uint64_t delta = unloadEvent.Timestamp - it->Timestamp;
            if (delta > kWindow)
            {
                break;
            }
            if (!loadIsShortLivedCandidate(*it))
            {
                continue;
            }
            if (base.empty())
            {
                if (it->PathClass != L"drop")
                {
                    continue;
                }
                ++unnamedHits;
                if (unnamedHits == 1)
                {
                    matchedLoad = &(*it);
                }
                else
                {
                    matchedLoad = nullptr;
                }
                continue;
            }
            if (it->Base.empty())
            {
                continue;
            }
            if (it->Base != base && driverStem(it->Base) != unloadStem)
            {
                continue;
            }
            matchedLoad = &(*it);
            unnamedHits = 1;
            break;
        }
        if (matchedLoad != nullptr && (base.empty() ? unnamedHits == 1 : true))
        {
            const RecentDriverLoad* it = matchedLoad;
            uint64_t delta = unloadEvent.Timestamp - it->Timestamp;
            shortLived.Timestamp = unloadEvent.Timestamp;
            shortLived.Kind = L"driver.short_lived";
            shortLived.Driver = unloadEvent.Driver.empty() ? it->Path : unloadEvent.Driver;
            shortLived.Task = unloadEvent.Task;
            shortLived.Summary = L"driver loaded and vanished within 30s " + it->Base;
            shortLived.Evidence[L"path_class"] = it->PathClass;
            shortLived.Evidence[L"load_ts"] = std::to_wstring(it->Timestamp);
            shortLived.Evidence[L"lifetime_100ns"] = std::to_wstring(delta);
            shortLived.Evidence[L"followup"] = L"!mapper; !kpage /pe; !pool pe /suspicious";
            emit = true;
        }
    }

    if (emit)
    {
        if (KmonDriverUnloadArmsMapperWatch(shortLived))
        {
            ArmMapperWatch(shortLived);
        }
        RecordEvent(std::move(shortLived));
    }
}

bool KernelMonitor::GetLiveTargets(DeviceClient** device, SymbolEngine** symbols) const
{
    bool ok = false;
    do
    {
        if (device == nullptr || symbols == nullptr)
        {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            *device = Device;
            *symbols = Symbols;
        }
        if (*device == nullptr || *symbols == nullptr || !(*device)->IsOpen())
        {
            break;
        }
        if (!EnsureLoadedKernelModules(*symbols, true) ||
            (*symbols)->CopyModules().empty())
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}

std::wstring KernelMonitor::MakeEmittedKey(const std::wstring& key, uint32_t processId) const
{
    std::wstring uniqueKey = key;
    if (processId <= 4)
    {
        return uniqueKey;
    }

    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> stateLock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        processId);
    const uint64_t created = QueryPidCreateTime(device, symbols, process, processId);
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    if (created != 0)
    {
        uniqueKey += L":" + std::to_wstring(created);
    }
    else
    {
        uniqueKey += L":gone";
    }
    return uniqueKey;
}

void KernelMonitor::EmitUnique(
    const std::wstring& kind,
    const std::wstring& key,
    const std::wstring& driver,
    const std::wstring& layer,
    const std::wstring& summary,
    const std::wstring& notes,
    uint32_t processId)
{
    bool claimed = false;
    {
        const std::wstring uniqueKey = MakeEmittedKey(key, processId);
        std::lock_guard<std::mutex> lock(WatchMutex);
        claimed = EmittedMapperKeys.insert(uniqueKey).second;
    }
    if (!claimed)
    {
        return;
    }

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);

    KmonEvent event = {};
    event.Timestamp = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    event.Kind = kind;
    event.ProcessId = processId;
    if (kind.rfind(L"process.", 0) == 0)
    {
        event.Image = driver;
    }
    else
    {
        event.Driver = driver;
    }
    event.Summary = summary;
    event.Evidence[L"layer"] = layer;
    if (!notes.empty())
    {
        event.Evidence[L"notes"] = notes;
    }
    if (kind.rfind(L"process.", 0) == 0)
    {
        event.Evidence[L"followup"] = processId != 0
            ? L"!hiddenproc; !vad " + std::to_wstring(processId)
            : L"!hiddenproc";
    }
    else
    {
        event.Evidence[L"followup"] =
            L"!callbacks; !inputstack; !ssdt; !idt; !msrcheck; !mapper; !kpage /pe; !pool pe";
    }
    RecordEvent(std::move(event));
}

void KernelMonitor::EmitMappedResidue(
    const std::wstring& key,
    const std::wstring& driver,
    const std::wstring& layer,
    const std::wstring& summary,
    const std::wstring& notes)
{
    EmitUnique(L"driver.mapped_residue", key, driver, layer, summary, notes);
}

void KernelMonitor::ClearEmittedKey(const std::wstring& key)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    EmittedMapperKeys.erase(key);
}

void KernelMonitor::ClearEmittedKeyForPid(const std::wstring& key, uint32_t processId)
{
    ClearEmittedKey(MakeEmittedKey(key, processId));
}

void KernelMonitor::ScanMapperRemnants()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        EmitMappedResidue(
            L"scan_failed:mapper:device",
            std::wstring(),
            L"mapper_scan",
            L"mapper remnant scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:mapper:device");
    if (!EnsureLoadedKernelModules(symbols, true))
    {
        EmitMappedResidue(
            L"scan_failed:mapper:inventory",
            std::wstring(),
            L"mapper_scan",
            L"mapper remnant scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:mapper:inventory");

    MapperRemnantScanner scanner(*device, *symbols);
    MapperScanOptions options;
    const bool mapperWatch = IsMapperWatchActive();
    options.Limit = mapperWatch ? 256 : 64;
    MapperScanResult result = {};
    std::wstring error;
    if (!scanner.Scan(options, &result, &error))
    {
        EmitMappedResidue(
            L"scan_failed:mapper",
            std::wstring(),
            L"mapper_scan",
            L"mapper remnant scan failed; live pool PE / kpage still run",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    MapperScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:mapper");
    if (!result.UnloadedComplete)
    {
        EmitMappedResidue(
            L"scan_failed:mapper:unloaded",
            std::wstring(),
            L"mapper_scan",
            L"MmUnloadedDrivers walk was incomplete",
            result.Warnings.empty()
                ? L"UnloadedComplete is false"
                : result.Warnings.front());
    }
    else
    {
        ClearEmittedKey(L"scan_failed:mapper:unloaded");
    }
    if (!result.PiddbComplete)
    {
        EmitMappedResidue(
            L"scan_failed:mapper:piddb",
            std::wstring(),
            L"mapper_scan",
            L"PiDDBCache walk was incomplete",
            L"PiddbComplete is false");
    }
    else
    {
        ClearEmittedKey(L"scan_failed:mapper:piddb");
    }
    if (!result.HashComplete)
    {
        EmitMappedResidue(
            L"scan_failed:mapper:hash",
            std::wstring(),
            L"mapper_scan",
            L"ci-hash walk was incomplete",
            L"HashComplete is false");
    }
    else
    {
        ClearEmittedKey(L"scan_failed:mapper:hash");
    }

    for (const MapperUnloadedRecord& record : result.Unloaded)
    {
        if (!record.Suspicious &&
            !(mapperWatch && record.StillExecutable && !record.OverlapsLoadedModule))
        {
            continue;
        }
        EmitMappedResidue(
            L"unloaded:" + ToLowerCopy(record.Name) + L":" + std::to_wstring(record.StartAddress),
            record.Name,
            L"MmUnloadedDrivers",
            L"mapper leftover MmUnloadedDrivers " + record.Name,
            record.Notes);
    }
    for (const MapperPiddbRecord& record : result.Piddb)
    {
        if (!record.Suspicious &&
            !(mapperWatch && !record.InLoadedModules && !record.Expected))
        {
            continue;
        }
        EmitMappedResidue(
            L"piddb:" + ToLowerCopy(record.DriverName) + L":" + std::to_wstring(record.TimeDateStamp),
            record.DriverName,
            L"PiDDBCache",
            L"mapper leftover PiDDBCache " + record.DriverName,
            record.Notes);
    }
    for (const MapperHashRecord& record : result.HashEntries)
    {
        if (!record.Suspicious &&
            !(mapperWatch && !record.InLoadedModules && !record.Expected))
        {
            continue;
        }
        EmitMappedResidue(
            L"hash:" + ToLowerCopy(record.DriverName) + L":" + record.Notes,
            record.DriverName,
            L"ci_hash",
            L"mapper leftover ci-hash " + record.DriverName,
            record.Notes);
    }

    if (mapperWatch &&
        result.UnloadedComplete &&
        result.PiddbComplete &&
        result.HashComplete)
    {
        MapperWatchFingerprint current = {};
        current.Complete = true;
        current.PiddbElementCount = result.PiddbElementCount;
        current.UnloadedSlotCount = result.UnloadedSlotCount;
        current.PiddbTruncated = result.Piddb.size() >= options.Limit;
        current.HashTruncated = result.HashEntries.size() >= options.Limit;
        for (const MapperUnloadedRecord& record : result.Unloaded)
        {
            current.Unloaded.insert(MapperUnloadedFingerprint(record));
        }
        for (const MapperPiddbRecord& record : result.Piddb)
        {
            current.Piddb.insert(MapperPiddbFingerprint(record));
        }
        for (const MapperHashRecord& record : result.HashEntries)
        {
            current.Hash.insert(MapperHashFingerprint(record));
        }

        MapperWatchFingerprint previous = {};
        std::wstring watchDriver;
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            previous = MapperWatchLast;
            MapperWatchLast = current;
            watchDriver = MapperWatchDriver;
        }
        if (previous.Complete)
        {
            auto emitCleared = [&](
                const std::unordered_set<std::wstring>& before,
                const std::unordered_set<std::wstring>& after,
                const std::wstring& layer,
                const std::wstring& keyPrefix)
            {
                for (const std::wstring& key : before)
                {
                    if (after.find(key) != after.end())
                    {
                        continue;
                    }
                    EmitMappedResidue(
                        keyPrefix + key,
                        key,
                        layer,
                        L"mapper watch: " + layer + L" entry vanished " + key,
                        L"entry present on the previous burst scan is gone");
                }
            };
            if (!previous.PiddbTruncated && !current.PiddbTruncated)
            {
                emitCleared(
                    previous.Piddb,
                    current.Piddb,
                    L"PiDDBCache_wipe",
                    L"piddb_cleared:");
            }
            if (!previous.HashTruncated && !current.HashTruncated)
            {
                emitCleared(
                    previous.Hash,
                    current.Hash,
                    L"ci_hash_wipe",
                    L"hash_cleared:");
            }
            if (previous.PiddbElementCount >= current.PiddbElementCount + 4)
            {
                EmitMappedResidue(
                    L"piddb_bulk_wipe:" + std::to_wstring(previous.PiddbElementCount),
                    watchDriver,
                    L"PiDDBCache_wipe",
                    L"mapper watch: PiDDB element count dropped " +
                        std::to_wstring(previous.PiddbElementCount) + L" -> " +
                        std::to_wstring(current.PiddbElementCount),
                    L"bulk PiDDB shrink during post-load mapper watch");
            }
        }
    }
}

void KernelMonitor::ScanPoolMappedImages()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || !device->IsOpen())
    {
        EmitMappedResidue(
            L"scan_failed:pool_pe:device",
            std::wstring(),
            L"pool_pe",
            L"pool PE scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:pool_pe:device");
    if (!EnsureLoadedKernelModules(symbols, true))
    {
        EmitMappedResidue(
            L"scan_failed:pool_pe:inventory",
            std::wstring(),
            L"pool_pe",
            L"pool PE scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:pool_pe:inventory");

    PoolPeHunter hunter(*device);
    PoolPeHunter::Options options;
    options.Paged = PoolPeHunter::PagedFilter::Any;
    options.LimitHits = IsMapperWatchActive() ? 128 : 32;
    PoolPeHunterResult result = {};
    std::wstring error;
    if (!hunter.Scan(options, &result, &error))
    {
        EmitMappedResidue(
            L"scan_failed:pool_pe",
            std::wstring(),
            L"pool_pe",
            L"pool PE scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    PoolPeScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:pool_pe");
    if (options.LimitHits != 0 && result.Hits.size() >= options.LimitHits)
    {
        EmitMappedResidue(
            L"scan_failed:pool_pe:truncated",
            std::wstring(),
            L"pool_pe",
            L"pool PE scan hit the hit cap; extra mapped images may be missed",
            L"LimitHits=" + std::to_wstring(options.LimitHits));
    }
    else
    {
        ClearEmittedKey(L"scan_failed:pool_pe:truncated");
    }

    for (const PoolPeHit& hit : result.Hits)
    {
        if (hit.Probe.Machine != 0 && hit.Probe.Machine != kImageFileMachineAmd64)
        {
            continue;
        }
        if (AddressOwnedByLoadedModule(symbols, hit.Address))
        {
            continue;
        }

        std::wstring notes = L"tag=" + hit.TagText +
            L" size=" + HexU64(hit.SizeInBytes) +
            L" sizeOfImage=" + HexU64(hit.Probe.SizeOfImage);
        if (hit.Probe.MzWiped || hit.Probe.PeSignatureWiped || hit.Probe.ELfanewMismatch)
        {
            notes += L" wiped";
            if (hit.Probe.MzWiped)
            {
                notes += L"+MZ";
            }
            if (hit.Probe.PeSignatureWiped)
            {
                notes += L"+PE";
            }
            if (hit.Probe.ELfanewMismatch)
            {
                notes += L"+e_lfanew";
            }
        }

        EmitMappedResidue(
            L"poolpe:" + HexU64(hit.Address),
            hit.TagText,
            L"pool_pe",
            L"mapped PE in pool " + HexU64(hit.Address) + L" tag=" + hit.TagText,
            notes);
    }
}

void KernelMonitor::ScanUnbackedDriverObjects()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        EmitMappedResidue(
            L"scan_failed:drvobj:device",
            std::wstring(),
            L"driver_object",
            L"unbacked DRIVER_OBJECT scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:drvobj:device");
    if (!EnsureLoadedKernelModules(symbols, true))
    {
        EmitMappedResidue(
            L"scan_failed:drvobj:inventory",
            std::wstring(),
            L"driver_object",
            L"unbacked DRIVER_OBJECT scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:drvobj:inventory");

    IntegrityScanner scanner(*device, *symbols);
    DriverIntegrityOptions options;
    DriverIntegrityResult result = {};
    std::wstring error;
    if (!scanner.ScanDrivers(options, &result, &error))
    {
        EmitMappedResidue(
            L"scan_failed:drvobj",
            std::wstring(),
            L"driver_object",
            L"unbacked DRIVER_OBJECT scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    ClearEmittedKey(L"scan_failed:drvobj");
    if (result.Truncated)
    {
        EmitMappedResidue(
            L"scan_failed:drvobj:truncated",
            std::wstring(),
            L"driver_object",
            L"DRIVER_OBJECT walk was truncated; extra unbacked starts may be missed",
            L"Truncated is true");
    }
    else
    {
        ClearEmittedKey(L"scan_failed:drvobj:truncated");
    }

    for (const DriverIntegrityRecord& record : result.Records)
    {
        const bool unbackedStart =
            record.HasDriverStart &&
            record.DriverStart != 0 &&
            record.OwningModule.empty() &&
            !AddressOwnedByLoadedModule(symbols, record.DriverStart);
        if (unbackedStart)
        {
            EmitMappedResidue(
                L"drvobj:" + HexU64(record.DriverObject),
                record.Name,
                L"driver_object",
                L"DRIVER_OBJECT " + record.Name + L" DriverStart " +
                    HexU64(record.DriverStart) + L" is outside PsLoadedModuleList",
                record.Notes);
            continue;
        }

        for (const DriverDispatchRecord& dispatch : record.Dispatch)
        {
            if (!dispatch.Suspicious || dispatch.Function == 0)
            {
                continue;
            }
            if (AddressOwnedByLoadedModule(symbols, dispatch.Function))
            {
                continue;
            }
            const std::wstring slotName = (dispatch.Index < 32)
                ? (L"MajorFunction[" + dispatch.Name + L"]")
                : dispatch.Name;
            EmitUnique(
                L"hook.unbacked",
                L"dispatch:" + HexU64(record.DriverObject) + L":" +
                    std::to_wstring(dispatch.Index),
                record.Name,
                L"dispatch",
                slotName + L" of " + record.Name +
                    L" points outside loaded modules " + HexU64(dispatch.Function),
                dispatch.Notes);
        }
    }
}

void KernelMonitor::ScanOrphanMappedPages()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        EmitMappedResidue(
            L"scan_failed:kpage:device",
            std::wstring(),
            L"orphan_page",
            L"orphan kpage scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:kpage:device");
    if (!EnsureLoadedKernelModules(symbols, true))
    {
        EmitMappedResidue(
            L"scan_failed:kpage:inventory",
            std::wstring(),
            L"orphan_page",
            L"orphan kpage scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:kpage:inventory");

    OrphanKernelPageScanner scanner(*device, *symbols);
    OrphanKernelPageOptions options;
    const bool mapperWatch = IsMapperWatchActive();
    bool deepPfn = false;
    if (mapperWatch && MapperWatchDeepPfnPending.exchange(false))
    {
        deepPfn = true;
    }
    options.DeepPfn = deepPfn;
    options.PeOnly = false;
    options.WxOnly = false;
    options.IncludeSession = true;
    options.Limit = mapperWatch ? 96 : 32;
    if (mapperWatch)
    {
        options.MaxTablePages = 65536;
    }
    OrphanKernelPageResult result = {};
    std::wstring error;
    if (!scanner.Scan(options, &result, &error))
    {
        if (deepPfn && IsMapperWatchActive())
        {
            MapperWatchDeepPfnPending.store(true);
        }
        EmitMappedResidue(
            L"scan_failed:kpage",
            std::wstring(),
            L"orphan_page",
            L"orphan kpage PE scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    KpageScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:kpage");
    if (!result.PageWalkComplete)
    {
        EmitMappedResidue(
            L"scan_failed:kpage:coverage",
            std::wstring(),
            L"orphan_page",
            L"orphan kpage walk was incomplete; extra mapped PE / W+X may be missed",
            L"PageWalkComplete is false");
    }
    else
    {
        ClearEmittedKey(L"scan_failed:kpage:coverage");
    }

    const std::vector<KernelModuleInfo> kernelModules = symbols->CopyModules();
    for (const OrphanKernelPageRegion& region : result.Regions)
    {
        if (region.Classification == L"mmio")
        {
            continue;
        }
        if (AddressOwnedByLoadedModule(symbols, region.Start))
        {
            continue;
        }

        const bool peHit = region.HasPe;
        const bool wxStub =
            !peHit &&
            region.Writable &&
            region.Executable &&
            region.Risk == L"high";
        // Session space is full of win32k scratch W+X; keep PE hits so a
        // session-mapped image still shows, but drop the W+X noise.
        if (region.SessionSpace && !peHit)
        {
            continue;
        }

        uint32_t stubHits = 0;
        const bool idlePoolCandidate =
            region.Executable &&
            !region.SessionSpace &&
            !peHit &&
            region.InBigPool &&
            region.PoolNonPaged;
        const bool stubCandidate =
            (mapperWatch &&
             region.Executable &&
             !region.SessionSpace &&
             !peHit) ||
            idlePoolCandidate;
        const bool idleScan = !mapperWatch && idlePoolCandidate;
        if (stubCandidate)
        {
            // Deeper samples: mappers place import thunks well past the
            // first page. NonPaged pool reads are reliable, so one bulk
            // read is enough for the slot-in-buffer heuristics.
            constexpr uint32_t kWatchStubSample = 0x4000;
            constexpr uint32_t kIdleStubSample = 0x2000;
            const uint32_t sampleCap = mapperWatch ? kWatchStubSample : kIdleStubSample;
            const uint32_t sampleLen =
                region.Size > sampleCap
                    ? sampleCap
                    : static_cast<uint32_t>(region.Size);
            if (sampleLen >= 14)
            {
                std::vector<uint8_t> sample;
                std::wstring ignored;
                if (device->ReadMemory(
                        region.Start,
                        sampleLen,
                        &sample,
                        &ignored) &&
                    sample.size() >= 14)
                {
                    stubHits = CountKernelImportStubs(
                        sample.data(),
                        sample.size(),
                        region.Start,
                        kernelModules);
                }
            }
        }
        // Idle scans only see non-paged big-pool code, so require one more
        // recognizable thunk to keep the noise floor down.
        const uint32_t stubThreshold = idleScan ? 3 : 2;
        const bool stubHit = stubHits >= stubThreshold;
        if (!peHit && !wxStub && !stubHit)
        {
            continue;
        }

        std::wstring notes = L"class=" + region.Classification +
            L" risk=" + region.Risk +
            L" size=" + HexU64(region.Size);
        if (stubCandidate)
        {
            notes += L" scan=";
            notes += idleScan ? L"idle" : L"watch";
        }
        if (region.PoolTag != 0)
        {
            notes += L" tag=" + LeftoverFormatTag(region.PoolTag);
        }
        if (!region.Notes.empty())
        {
            notes += L" " + region.Notes;
        }
        if (stubHits != 0)
        {
            notes += L" import_stubs=" + std::to_wstring(stubHits);
        }
        if (region.PhysicalAddress != 0)
        {
            notes += L" pfn=" + std::to_wstring(region.PhysicalAddress >> 12);
        }

        if (stubHit)
        {
            const wchar_t* layer = region.InBigPool ? L"pool_code" : L"kpage_code";
            NoteMapperWatchResidue(layer, region.PhysicalAddress);
            EmitMappedResidue(
                std::wstring(layer) + L":" + HexU64(region.Start),
                region.Classification,
                layer,
                (region.InBigPool
                    ? L"headerless pool executable import stubs "
                    : L"headerless kpage executable import stubs ") +
                    HexU64(region.Start),
                notes);
            continue;
        }

        EmitMappedResidue(
            L"kpage:" + HexU64(region.Start),
            region.Classification,
            peHit ? L"orphan_page" : L"orphan_wx",
            (peHit
                ? L"mapped PE outside loaded modules "
                : L"W+X kernel pages outside loaded modules ") + HexU64(region.Start),
            notes);
    }
}

void KernelMonitor::ScanHookCallbacks()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || !device->IsOpen())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:callbacks:device",
            std::wstring(),
            L"callback",
            L"callback scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:callbacks:device");
    if (!GetLiveTargets(&device, &symbols) || symbols->CopyModules().empty())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:callbacks:inventory",
            std::wstring(),
            L"callback",
            L"callback scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:callbacks:inventory");

    KernelCallbackScanner scanner(*device, *symbols);
    KernelCallbackScanResult result = {};
    std::wstring error;
    if (!scanner.Scan(L"all", &result, &error))
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:callbacks",
            std::wstring(),
            L"callback",
            L"callback scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    HookScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:callbacks");
    if (result.Incomplete)
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:callbacks:coverage",
            std::wstring(),
            L"callback",
            L"callback walk was incomplete; extra unbacked callbacks may be missed",
            result.Warnings.empty()
                ? L"Incomplete is true"
                : result.Warnings.front());
    }
    else
    {
        ClearEmittedKey(L"scan_failed:callbacks:coverage");
    }

    for (const KernelCallbackRecord& record : result.Records)
    {
        bool emittedUnbacked = false;
        auto emitCallbackIfUnbacked = [&](
            uint64_t fn,
            const std::wstring& moduleName,
            const wchar_t* which)
        {
            if (fn == 0 || AddressOwnedByLoadedModule(symbols, fn))
            {
                return;
            }
            std::wstring summary = L"unbacked " + record.Kind;
            if (which != nullptr && which[0] != L'\0')
            {
                summary += L" ";
                summary += which;
            }
            if (!record.Target.empty())
            {
                summary += L" ";
                summary += record.Target;
            }
            summary += L" callback ";
            summary += HexU64(fn);
            EmitUnique(
                L"hook.unbacked",
                L"cb:" + record.Kind + L":" + which + HexU64(fn),
                moduleName.empty() ? record.Kind : moduleName,
                L"callback",
                summary,
                record.Notes);
            emittedUnbacked = true;
        };
        emitCallbackIfUnbacked(record.Function, record.FunctionModule, L"");
        emitCallbackIfUnbacked(
            record.PostFunction,
            record.PostFunctionModule,
            L"post:");
        if (record.Poisoned && !emittedUnbacked)
        {
            EmitUnique(
                L"hook.unbacked",
                L"cb:" + record.Kind + L":poison:" + HexU64(record.Entry),
                record.FunctionModule.empty() ? record.Kind : record.FunctionModule,
                L"callback",
                L"poisoned " + record.Kind + L" callback entry " + HexU64(record.Entry),
                record.Notes);
        }
    }
}

void KernelMonitor::ScanHookInput()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || !device->IsOpen())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:input:device",
            std::wstring(),
            L"input",
            L"input stack scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:input:device");
    if (!GetLiveTargets(&device, &symbols) || symbols->CopyModules().empty())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:input:inventory",
            std::wstring(),
            L"input",
            L"input stack scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    ClearEmittedKey(L"scan_failed:input:inventory");

    InputStackScanner scanner(*device, *symbols);
    InputStackScanResult result = {};
    std::wstring error;
    if (!scanner.Scan(&result, &error))
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:input",
            std::wstring(),
            L"input",
            L"input stack scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    ClearEmittedKey(L"scan_failed:input");
    if (!result.CoverageComplete)
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:input:coverage",
            std::wstring(),
            L"input",
            L"input class driver walk was incomplete; attached filters may be missed",
            result.Warnings.empty()
                ? L"CoverageComplete is false"
                : result.Warnings.front());
    }
    else
    {
        ClearEmittedKey(L"scan_failed:input:coverage");
    }

    bool hitCap = false;
    uint32_t suspicious = 0;
    for (const InputStackRecord& record : result.Records)
    {
        uint32_t emitted = 0;
        for (const DeviceStackResult& stack : record.Driver.Stacks)
        {
            for (const DeviceObjectRecord& attached : stack.Stack)
            {
                const std::wstring ownerPath =
                    !attached.DriverModule.empty() ? attached.DriverModule : attached.DriverName;
                const std::wstring ownerClass = KmonClassifyDriverPath(ownerPath);
                const bool dropAttached =
                    ownerClass == L"drop" ||
                    (ownerClass == L"unknown" &&
                        KmonDriverPathHasFileDirectory(ownerPath));
                if (!attached.Suspicious && !dropAttached)
                {
                    continue;
                }
                ++suspicious;
                if (emitted >= 8)
                {
                    hitCap = true;
                    continue;
                }
                const uint64_t unbackedObject = attached.DriverObject != 0
                    ? attached.DriverObject
                    : attached.DeviceObject;
                const std::wstring notes = attached.Notes.empty()
                    ? record.Notes
                    : attached.Notes;
                EmitUnique(
                    L"hook.unbacked",
                    L"input:" + record.Role + L":" + HexU64(unbackedObject),
                    ownerPath.empty() ? record.DriverFilter : ownerPath,
                    L"input",
                    attached.Suspicious
                        ? (L"unbacked driver on " + record.Role + L" stack")
                        : (L"non-inbox driver on " + record.Role + L" stack"),
                    notes);
                ++emitted;
            }
        }
    }
    if (hitCap)
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:input:truncated",
            std::wstring(),
            L"input",
            L"input stack scan hit the emit cap; extra attached drivers may be missed",
            L"suspicious=" + std::to_wstring(suspicious));
    }
    else
    {
        ClearEmittedKey(L"scan_failed:input:truncated");
    }
}

void KernelMonitor::ScanCpuIntegrityHooks()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || !device->IsOpen())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:cpu:device",
            std::wstring(),
            L"cpu",
            L"cpu/integrity scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:cpu:device");
    if (!GetLiveTargets(&device, &symbols) || symbols->CopyModules().empty())
    {
        EmitUnique(
            L"hook.unbacked",
            L"scan_failed:cpu:inventory",
            std::wstring(),
            L"cpu",
            L"cpu/integrity scan skipped; kernel module inventory unavailable",
            L"LoadKernelModules failed or empty");
        return;
    }
    CpuHookScans.fetch_add(1);
    ClearEmittedKey(L"scan_failed:cpu:inventory");

    {
        SsdtScanner scanner(*device, *symbols);
        SsdtScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:ssdt");
            uint32_t emitted = 0;
            uint32_t suspicious = 0;
            for (const SsdtTable& table : result.Tables)
            {
                for (const SsdtEntry& entry : table.Entries)
                {
                    if (!entry.Suspicious)
                    {
                        continue;
                    }
                    ++suspicious;
                    if (emitted >= 16)
                    {
                        continue;
                    }
                    EmitUnique(
                        L"hook.unbacked",
                        L"ssdt:" + table.Name + L":" + std::to_wstring(entry.Index),
                        table.ExpectedModule,
                        L"ssdt",
                        L"SSDT " + table.Name + L"[" + std::to_wstring(entry.Index) +
                            L"] outside " + table.ExpectedModule + L" " + HexU64(entry.Routine),
                        entry.Notes);
                    ++emitted;
                }
            }
            if (suspicious > 16)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:ssdt:truncated",
                    std::wstring(),
                    L"ssdt",
                    L"SSDT scan hit the emit cap; extra hooked slots may be missed",
                    L"suspicious=" + std::to_wstring(suspicious));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:ssdt:truncated");
            }
            bool haveWin32k = false;
            for (const SsdtTable& table : result.Tables)
            {
                if (table.ExpectedModule.find(L"win32k") != std::wstring::npos)
                {
                    haveWin32k = true;
                    break;
                }
            }
            if (!haveWin32k)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:ssdt:shadow",
                    std::wstring(),
                    L"ssdt",
                    L"win32k SSDT was not resolved; shadow syscall hooks may be missed",
                    result.Warnings.empty()
                        ? L"KeServiceDescriptorTableShadow missing"
                        : result.Warnings.front());
            }
            else
            {
                ClearEmittedKey(L"scan_failed:ssdt:shadow");
            }
            bool tableReadFailed = false;
            for (const SsdtTable& table : result.Tables)
            {
                if (!table.Warning.empty() && table.Entries.empty())
                {
                    tableReadFailed = true;
                    break;
                }
            }
            if (tableReadFailed)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:ssdt:table",
                    std::wstring(),
                    L"ssdt",
                    L"an SSDT table could not be read; hooked slots in that table may be missed",
                    L"table Warning set with empty Entries");
            }
            else
            {
                ClearEmittedKey(L"scan_failed:ssdt:table");
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:ssdt",
                std::wstring(),
                L"ssdt",
                L"SSDT scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        IdtScanner scanner(*device, *symbols);
        IdtScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:idt");
            if (result.ProcessorCount > 1 &&
                result.ProcessorsCompared < result.ProcessorCount - 1)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:idt:coverage",
                    std::wstring(),
                    L"idt",
                    L"IDT cross-check missed one or more processors",
                    L"compared=" + std::to_wstring(result.ProcessorsCompared) +
                        L" cpus=" + std::to_wstring(result.ProcessorCount));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:idt:coverage");
            }
            uint32_t emitted = 0;
            uint32_t suspicious = 0;
            for (const IdtEntry& entry : result.Entries)
            {
                if (!entry.Present && !entry.Divergent)
                {
                    continue;
                }
                if (entry.Divergent)
                {
                    ++suspicious;
                    if (emitted < 16)
                    {
                        EmitUnique(
                            L"hook.unbacked",
                            L"idt:" + std::to_wstring(entry.Vector) + L":divergent",
                            entry.Module,
                            L"idt",
                            L"IDT vector " + std::to_wstring(entry.Vector) +
                                L" handler diverges across processors",
                            entry.Notes);
                        ++emitted;
                    }
                }
                if (!entry.Suspicious)
                {
                    continue;
                }
                if (AddressOwnedByLoadedModule(symbols, entry.Handler))
                {
                    continue;
                }
                ++suspicious;
                if (emitted >= 16)
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"idt:" + std::to_wstring(entry.Vector),
                    entry.Module,
                    L"idt",
                    L"IDT vector " + std::to_wstring(entry.Vector) +
                        L" handler outside modules " + HexU64(entry.Handler),
                    entry.Notes);
                ++emitted;
            }
            if (suspicious > 16)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:idt:truncated",
                    std::wstring(),
                    L"idt",
                    L"IDT scan hit the emit cap; extra hooked vectors may be missed",
                    L"suspicious=" + std::to_wstring(suspicious));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:idt:truncated");
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:idt",
                std::wstring(),
                L"idt",
                L"IDT scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        MsrScanner scanner(*device, *symbols);
        MsrScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:msr");
            bool msrCoverageHole = false;
            for (const MsrReading& reading : result.Readings)
            {
                const uint32_t sampled = static_cast<uint32_t>(reading.PerCpuValues.size());
                if (reading.ReadFailed ||
                    (result.ProcessorCount != 0 && sampled < result.ProcessorCount))
                {
                    msrCoverageHole = true;
                }
                if (!reading.Suspicious)
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"msr:" + reading.MsrName,
                    reading.OwningModule,
                    L"msr",
                    L"SYSCALL MSR " + reading.MsrName + L" is hooked or divergent",
                    reading.Notes);
            }
            if (msrCoverageHole)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:msr:coverage",
                    std::wstring(),
                    L"msr",
                    L"SYSCALL MSR sample missed one or more processors",
                    L"cpus=" + std::to_wstring(result.ProcessorCount));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:msr:coverage");
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:msr",
                std::wstring(),
                L"msr",
                L"MSR scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        CrScanner scanner(*device);
        CrScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:cr");
            const uint32_t sampled = result.Readings.empty()
                ? 0u
                : static_cast<uint32_t>(result.Readings.front().PerCpuValues.size());
            if (result.ProcessorCount != 0 && sampled < result.ProcessorCount)
            {
                EmitUnique(
                    L"integrity.cr",
                    L"scan_failed:cr:coverage",
                    std::wstring(),
                    L"cr",
                    L"control register sample missed one or more processors",
                    L"sampled=" + std::to_wstring(sampled) +
                        L" cpus=" + std::to_wstring(result.ProcessorCount));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:cr:coverage");
            }
            for (const CrReading& reading : result.Readings)
            {
                if (!reading.Suspicious)
                {
                    continue;
                }
                EmitUnique(
                    L"integrity.cr",
                    L"cr:" + reading.Name,
                    std::wstring(),
                    L"cr",
                    L"control register " + reading.Name + L" integrity anomaly",
                    reading.Notes);
            }
        }
        else
        {
            EmitUnique(
                L"integrity.cr",
                L"scan_failed:cr",
                std::wstring(),
                L"cr",
                L"CR scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        HalDispatchScanner scanner(*device, *symbols);
        HalDispatchScanner::Options options;
        HalDispatchScanResult result = {};
        std::wstring error;
        if (scanner.Scan(options, &result, &error))
        {
            ClearEmittedKey(L"scan_failed:hal");
            if (!result.CoverageComplete)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:hal:coverage",
                    std::wstring(),
                    L"hal",
                    L"HAL dispatch walk was incomplete; extra unbacked slots may be missed",
                    L"CoverageComplete is false");
            }
            else
            {
                ClearEmittedKey(L"scan_failed:hal:coverage");
            }
            for (const HalDispatchTable& table : result.Tables)
            {
                for (const HalDispatchSlot& slot : table.Slots)
                {
                    if (!slot.Suspicious)
                    {
                        continue;
                    }
                    if (AddressOwnedByLoadedModule(symbols, slot.Routine))
                    {
                        continue;
                    }
                    EmitUnique(
                        L"hook.unbacked",
                        L"hal:" + table.Name + L":" + std::to_wstring(slot.Index),
                        table.Name,
                        L"hal",
                        L"HAL " + table.Name + L"[" + slot.Name +
                            L"] outside loaded modules " + HexU64(slot.Routine),
                        slot.Notes);
                }
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:hal",
                std::wstring(),
                L"hal",
                L"HAL dispatch scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        NmiScanner scanner(*device, *symbols);
        NmiScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:nmi");
            if (result.Incomplete)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:nmi:coverage",
                    std::wstring(),
                    L"nmi",
                    L"NMI callback walk was incomplete; extra unbacked callbacks may be missed",
                    result.Warnings.empty()
                        ? L"Incomplete is true"
                        : result.Warnings.front());
            }
            else
            {
                ClearEmittedKey(L"scan_failed:nmi:coverage");
            }
            for (const NmiCallbackRecord& record : result.Callbacks)
            {
                if (!record.Suspicious)
                {
                    continue;
                }
                if (AddressOwnedByLoadedModule(symbols, record.Callback))
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"nmi:" + HexU64(record.Callback),
                    record.CallbackModule,
                    L"nmi",
                    L"NMI callback outside loaded modules " + HexU64(record.Callback),
                    record.Notes);
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:nmi",
                std::wstring(),
                L"nmi",
                L"NMI callback scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        DpcTimerScanner scanner(*device, *symbols);
        DpcTimerScanner::Options options;
        options.Target = DpcTimerScanner::Scope::All;
        options.Limit = 32;
        DpcTimerScanResult result = {};
        std::wstring error;
        if (scanner.Scan(options, &result, &error))
        {
            ClearEmittedKey(L"scan_failed:dpc");
            if (!result.DpcCoverageComplete || !result.TimerCoverageComplete)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:dpc:coverage",
                    std::wstring(),
                    L"dpc",
                    L"DPC/timer walk was incomplete; extra unbacked routines may be missed",
                    L"dpc_complete=" +
                        std::to_wstring(result.DpcCoverageComplete ? 1 : 0) +
                        L" timer_complete=" +
                        std::to_wstring(result.TimerCoverageComplete ? 1 : 0));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:dpc:coverage");
            }
            for (const DpcRoutineRecord& record : result.Dpcs)
            {
                if (!record.Suspicious)
                {
                    continue;
                }
                if (AddressOwnedByLoadedModule(symbols, record.Routine))
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"dpc:" + HexU64(record.Routine),
                    record.Module,
                    L"dpc",
                    L"DPC routine outside loaded modules " + HexU64(record.Routine),
                    record.Notes);
            }
            for (const TimerRoutineRecord& record : result.Timers)
            {
                if (!record.Suspicious)
                {
                    continue;
                }
                if (AddressOwnedByLoadedModule(symbols, record.Routine))
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"timer:" + HexU64(record.Routine),
                    record.Module,
                    L"timer",
                    L"timer DPC outside loaded modules " + HexU64(record.Routine),
                    record.Notes);
            }
            for (const WorkItemRecord& record : result.WorkItems)
            {
                if (!record.Suspicious)
                {
                    continue;
                }
                if (AddressOwnedByLoadedModule(symbols, record.Routine))
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"workitem:" + HexU64(record.Routine),
                    record.Module,
                    L"workitem",
                    L"work-item routine outside loaded modules " + HexU64(record.Routine),
                    record.Notes);
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:dpc",
                std::wstring(),
                L"dpc",
                L"DPC/timer/work-item scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        WfpCalloutScanner scanner(*device, *symbols);
        WfpCalloutScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:wfp");
            if (!result.CoverageComplete || result.Incomplete)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:wfp:coverage",
                    std::wstring(),
                    L"wfp",
                    L"WFP callout walk was incomplete; extra unbacked callouts may be missed",
                    result.Warnings.empty()
                        ? L"CoverageComplete is false"
                        : result.Warnings.front());
            }
            else
            {
                ClearEmittedKey(L"scan_failed:wfp:coverage");
            }
            uint32_t emitted = 0;
            uint32_t suspicious = 0;
            auto emitWfpIfUnbacked = [&](
                bool hookSuspicious,
                uint64_t fn,
                const WfpKernelCallout& callout,
                const wchar_t* which)
            {
                if (!hookSuspicious || fn == 0)
                {
                    return;
                }
                if (AddressOwnedByLoadedModule(symbols, fn))
                {
                    return;
                }
                ++suspicious;
                if (emitted >= 16)
                {
                    return;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"wfp:" + std::to_wstring(callout.CalloutId) + L":" + which,
                    callout.Name,
                    L"wfp",
                    L"WFP callout " + callout.Name + L" " + which +
                        L" outside modules " + HexU64(fn),
                    callout.Notes);
                ++emitted;
            };
            for (const WfpKernelCallout& callout : result.Callouts)
            {
                emitWfpIfUnbacked(
                    callout.ClassifySuspicious,
                    callout.ClassifyFn,
                    callout,
                    L"classify");
                emitWfpIfUnbacked(
                    callout.NotifySuspicious,
                    callout.NotifyFn,
                    callout,
                    L"notify");
                emitWfpIfUnbacked(
                    callout.FlowDeleteSuspicious,
                    callout.FlowDeleteFn,
                    callout,
                    L"flowdelete");
            }
            if (suspicious > 16)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:wfp:truncated",
                    std::wstring(),
                    L"wfp",
                    L"WFP scan hit the emit cap; extra unbacked callouts may be missed",
                    L"suspicious=" + std::to_wstring(suspicious));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:wfp:truncated");
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:wfp",
                std::wstring(),
                L"wfp",
                L"WFP callout scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        MinifilterIrpScanner scanner(*device, *symbols);
        MinifilterIrpScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            ClearEmittedKey(L"scan_failed:minifilter");
            if (!result.CoverageComplete)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:minifilter:coverage",
                    std::wstring(),
                    L"minifilter",
                    L"minifilter walk was incomplete; extra unbacked filters may be missed",
                    L"CoverageComplete is false");
            }
            else
            {
                ClearEmittedKey(L"scan_failed:minifilter:coverage");
            }
            uint32_t minifilterHits = 0;
            uint32_t minifilterEmitted = 0;
            for (const MinifilterFilterRecord& filter : result.Filters)
            {
                const bool startUnbacked =
                    filter.DriverStart != 0 &&
                    !AddressOwnedByLoadedModule(symbols, filter.DriverStart);
                if (startUnbacked)
                {
                    ++minifilterHits;
                    if (minifilterEmitted < 16)
                    {
                        EmitUnique(
                            L"hook.unbacked",
                            L"minifilter:" + HexU64(filter.Filter),
                            filter.Name,
                            L"minifilter",
                            L"minifilter " + filter.Name +
                                L" is not backed by a loaded module",
                            filter.Notes);
                        ++minifilterEmitted;
                    }
                }
                auto emitMinifilterFn = [&](
                    uint64_t fn,
                    const wchar_t* which,
                    const std::wstring& majorName)
                {
                    if (fn == 0 || AddressOwnedByLoadedModule(symbols, fn))
                    {
                        return;
                    }
                    ++minifilterHits;
                    if (minifilterEmitted >= 16)
                    {
                        return;
                    }
                    EmitUnique(
                        L"hook.unbacked",
                        L"minifilter:" + HexU64(filter.Filter) + L":" +
                            which + L":" + HexU64(fn),
                        filter.Name,
                        L"minifilter",
                        L"minifilter " + filter.Name + L" " + which +
                            L" callback outside loaded modules " + HexU64(fn),
                        majorName.empty() ? filter.Notes : (majorName + L" " + filter.Notes));
                    ++minifilterEmitted;
                };
                for (const MinifilterIrpSlot& slot : filter.OperationsTable)
                {
                    emitMinifilterFn(slot.Pre, L"pre", slot.MajorName);
                    emitMinifilterFn(slot.Post, L"post", slot.MajorName);
                }
                for (const MinifilterIrpSlot& slot : filter.LiveCallbackTable)
                {
                    emitMinifilterFn(slot.Pre, L"pre", slot.MajorName);
                    emitMinifilterFn(slot.Post, L"post", slot.MajorName);
                }
            }
            if (minifilterHits > 16)
            {
                EmitUnique(
                    L"hook.unbacked",
                    L"scan_failed:minifilter:truncated",
                    std::wstring(),
                    L"minifilter",
                    L"minifilter scan hit the emit cap; extra unbacked callbacks may be missed",
                    L"hits=" + std::to_wstring(minifilterHits));
            }
            else
            {
                ClearEmittedKey(L"scan_failed:minifilter:truncated");
            }
        }
        else
        {
            EmitUnique(
                L"hook.unbacked",
                L"scan_failed:minifilter",
                std::wstring(),
                L"minifilter",
                L"minifilter scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        VbsScanner scanner(*device, *symbols);
        VbsScanner::Options options;
        options.Target = VbsScanner::Scope::Ci;
        VbsScanResult result = {};
        std::wstring error;
        if (scanner.Scan(options, &result, &error) && result.CiOptions.Resolved)
        {
            ClearEmittedKey(L"scan_failed:ci");
            if (!result.CiOptions.CodeIntegrityEnabled)
            {
                EmitUnique(
                    L"integrity.ci",
                    L"integrity:ci_disabled",
                    std::wstring(),
                    L"ci",
                    L"kernel code integrity is disabled (DSE off)",
                    result.CiOptions.SymbolSource);
            }
            else
            {
                ClearEmittedKey(L"integrity:ci_disabled");
            }
            if (result.CiOptions.TestSign)
            {
                EmitUnique(
                    L"integrity.ci",
                    L"integrity:ci_testsign",
                    std::wstring(),
                    L"ci",
                    L"kernel test-signing is enabled (DSE test mode)",
                    result.CiOptions.SymbolSource);
            }
            else
            {
                ClearEmittedKey(L"integrity:ci_testsign");
            }
        }
        else
        {
            EmitUnique(
                L"integrity.ci",
                L"scan_failed:ci",
                std::wstring(),
                L"ci",
                L"CI options scan failed or unresolved",
                error.empty() ? L"CiOptions not resolved" : error);
        }
    }
    IngestLiveTimeline();
    IngestThreatIntel();
    if (StopRequested.load())
    {
        return;
    }

    {
        ByovdScanner scanner(*symbols, ExeDirectory());
        ByovdScanOptions options;
        options.AutoUpdate = false;
        options.EnableYara = false;
        options.CheckAuthenticode = false;
        ByovdScanResult result = {};
        std::wstring error;
        if (scanner.Scan(options, &result, &error))
        {
            ClearEmittedKey(L"scan_failed:byovd");
            for (const ByovdModuleRecord& record : result.Records)
            {
                if (record.Matches.empty())
                {
                    continue;
                }
                std::wstring notes = record.Matches.front().Reason;
                EmitMappedResidue(
                    L"byovd:" + KmonBasenameLower(record.ImageName),
                    record.ImageName,
                    L"byovd",
                    L"known-vulnerable driver loaded " + record.ImageName,
                    notes);
            }
        }
        else
        {
            EmitMappedResidue(
                L"scan_failed:byovd",
                std::wstring(),
                L"byovd",
                L"BYOVD catalog scan failed",
                error.empty() ? L"Scan returned false" : error);
        }
    }

    if (!StopRequested.load())
    {
        ScanHookDataPointers();
    }
}

void KernelMonitor::ScanHookDataPointers()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols) ||
        device == nullptr ||
        symbols == nullptr ||
        !device->IsOpen())
    {
        return;
    }
    const std::vector<KernelModuleInfo> modules = symbols->CopyModules();
    if (modules.empty())
    {
        return;
    }

    uint64_t ntosBase = 0;
    const KernelModuleInfo* ntosModule = nullptr;
    for (const KernelModuleInfo& module : modules)
    {
        const std::wstring leaf = KmonBasenameLower(
            module.ImageName.empty() ? module.ImagePath : module.ImageName);
        if (leaf == L"ntoskrnl.exe" || leaf == L"ntkrnlmp.exe")
        {
            ntosBase = module.Base;
            ntosModule = &module;
            break;
        }
    }
    if (ntosBase == 0 || ntosModule == nullptr)
    {
        return;
    }

    if (CfgDataPtrNtosBase != ntosBase)
    {
        CfgDataPtrSites.clear();
        CfgDataPtrNtosBase = ntosBase;
        std::unordered_set<uint32_t> ntosGuardRvas;
        if (ntosModule != nullptr)
        {
            std::wstring ntosPath = ntosModule->ImagePath;
            if (!PathLooksLikeWin32File(ntosPath))
            {
                ntosPath = Win32PathFromKernelImagePath(ntosPath);
            }
            std::vector<uint8_t> ntosHead;
            if (PathLooksLikeWin32File(ntosPath) &&
                ReadDiskPeHead(ntosPath, &ntosHead))
            {
                const uint32_t guardRva = FindPeExportRvaByName(
                    ntosPath,
                    ntosHead,
                    "guard_dispatch_icall");
                if (guardRva != 0)
                {
                    ntosGuardRvas.insert(guardRva);
                }
            }
        }

        for (const KernelModuleInfo& module : modules)
        {
            if (CfgDataPtrSites.size() >= 192)
            {
                break;
            }
            const std::wstring leaf = KmonBasenameLower(
                module.ImageName.empty() ? module.ImagePath : module.ImageName);
            if (!KmonLooksLikeCfgHostModule(leaf) ||
                module.Base == 0 ||
                module.Size == 0)
            {
                continue;
            }
            std::wstring diskPath = module.ImagePath;
            if (!PathLooksLikeWin32File(diskPath))
            {
                diskPath = Win32PathFromKernelImagePath(diskPath);
            }
            if (!PathLooksLikeWin32File(diskPath))
            {
                continue;
            }
            std::vector<uint8_t> headers;
            if (!ReadDiskPeHead(diskPath, &headers))
            {
                continue;
            }
            KmonPeLayout layout = {};
            if (!ParseKmonPeLayout(headers, &layout) || !layout.Is64)
            {
                continue;
            }
            uint32_t textRva = 0;
            uint32_t textFile = 0;
            uint32_t textSize = 0;
            if (!ParseFirstExecSection(headers, &textRva, &textFile, &textSize))
            {
                continue;
            }
            std::vector<uint8_t> text;
            if (!ReadDiskFileRange(diskPath, textFile, textSize, &text) ||
                text.size() < 16)
            {
                continue;
            }
            std::unordered_set<uint32_t> guardCall = ntosGuardRvas;
            std::unordered_set<uint32_t> guardIat;
            if (leaf != L"ntoskrnl.exe" && leaf != L"ntkrnlmp.exe")
            {
                CollectGuardDispatchIatRvas(diskPath, headers, layout, &guardIat);
                guardCall.clear();
            }
            if (guardCall.empty() && guardIat.empty())
            {
                continue;
            }
            std::vector<uint32_t> slotRvas;
            CollectCfgDataPtrSlotRvas(
                text.data(),
                text.size(),
                textRva,
                layout.SizeOfImage,
                guardCall,
                guardIat,
                &slotRvas,
                48);
            for (uint32_t slotRva : slotRvas)
            {
                if (CfgDataPtrSites.size() >= 192)
                {
                    break;
                }
                CfgDataPtrSite site = {};
                site.SlotVa = module.Base + slotRva;
                site.ModuleLeaf = leaf;
                CfgDataPtrSites.push_back(std::move(site));
            }
        }
    }

    uint32_t emitted = 0;
    for (const CfgDataPtrSite& site : CfgDataPtrSites)
    {
        if (emitted >= 4 || StopRequested.load())
        {
            break;
        }
        std::vector<uint8_t> live;
        std::wstring ignored;
        if (!device->ReadMemory(site.SlotVa, 8, &live, &ignored) ||
            live.size() < 8)
        {
            continue;
        }
        uint64_t target = 0;
        std::memcpy(&target, live.data(), sizeof(target));
        if (target == 0 ||
            KmonVaLooksLikePagingOrFirmware(target) ||
            AddressOwnedByLoadedModule(symbols, target))
        {
            continue;
        }
        NoteMapperWatchResidue(L"dataptr", 0);
        EmitUnique(
            L"hook.dataptr",
            L"dataptr:" + site.ModuleLeaf + L":" + HexU64(site.SlotVa),
            site.ModuleLeaf,
            L"dataptr",
            L"CFG dispatch slot outside loaded modules " + HexU64(target),
            L"slot=" + HexU64(site.SlotVa) + L" module=" + site.ModuleLeaf);
        ++emitted;
    }
}

void KernelMonitor::ScanUserModeHostility()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        EmitUnique(
            L"process.implant",
            L"scan_failed:userhostility",
            std::wstring(),
            L"user",
            L"user-mode hostility scan failed to snapshot processes",
            std::wstring());
        return;
    }
    UserHostilityScans.fetch_add(1);

    std::unordered_set<uint32_t> watchPids;
    std::vector<std::wstring> watchNames;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        watchPids = WatchPids;
        watchNames = WatchNamesLower;
    }

    std::vector<KmonUserTarget> targets;
    const uint32_t selfPid = GetCurrentProcessId();
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    BOOL more = FALSE;
    DWORD nextError = ERROR_SUCCESS;
    bool snapshotCapped = false;
    const bool firstOk = Process32FirstW(snap, &entry) != FALSE;
    if (firstOk)
    {
        more = TRUE;
        do
        {
            const uint32_t pid = entry.th32ProcessID;
            if (pid > 4 && pid != selfPid)
            {
                if (targets.size() >= 4096)
                {
                    snapshotCapped = true;
                }
                else
                {
                KmonUserTarget target;
                target.Pid = pid;
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (process != nullptr)
                {
                    std::vector<wchar_t> pathBuf(32768, L'\0');
                    DWORD pathLen = static_cast<DWORD>(pathBuf.size());
                    if (QueryFullProcessImageNameW(process, 0, pathBuf.data(), &pathLen) && pathLen > 0)
                    {
                        target.ImagePath.assign(pathBuf.data(), pathLen);
                    }
                    CloseHandle(process);
                }
                if (target.ImagePath.empty())
                {
                    target.ImagePath = entry.szExeFile;
                }
                EnrichProcessImagePath(device, symbols, pid, &target.ImagePath);
                target.Leaf = KmonBasenameLower(target.ImagePath);
                const std::wstring pathClass = KmonClassifyDriverPath(target.ImagePath);
                const bool watched =
                    NameEqualsWatch(target.Leaf, watchNames) ||
                    watchPids.count(pid) != 0;
                target.HighPriority =
                    KmonIsWindowsBuiltinLeaf(target.Leaf) ||
                    watched ||
                    pathClass == L"drop";
                target.Interesting =
                    target.HighPriority ||
                    pathClass == L"third_party" ||
                    pathClass == L"unknown";
                targets.push_back(std::move(target));
                }
            }
            entry.dwSize = sizeof(entry);
            more = Process32NextW(snap, &entry);
            if (!more)
            {
                nextError = GetLastError();
            }
        } while (more);
    }
    CloseHandle(snap);
    const bool walkIncomplete =
        !firstOk ||
        (nextError != ERROR_NO_MORE_FILES && nextError != ERROR_SUCCESS);

    {
        std::unordered_set<uint32_t> have;
        have.reserve(targets.size());
        for (const KmonUserTarget& item : targets)
        {
            have.insert(item.Pid);
        }
        for (uint32_t pid : watchPids)
        {
            if (pid <= 4 || pid == selfPid || have.count(pid) != 0)
            {
                continue;
            }
            if (targets.size() >= 4096)
            {
                break;
            }
            KmonUserTarget target;
            target.Pid = pid;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (process != nullptr)
            {
                std::vector<wchar_t> pathBuf(32768, L'\0');
                DWORD pathLen = static_cast<DWORD>(pathBuf.size());
                if (QueryFullProcessImageNameW(process, 0, pathBuf.data(), &pathLen) && pathLen > 0)
                {
                    target.ImagePath.assign(pathBuf.data(), pathLen);
                }
                CloseHandle(process);
            }
            EnrichProcessImagePath(device, symbols, pid, &target.ImagePath);
            target.Leaf = KmonBasenameLower(target.ImagePath);
            target.HighPriority = true;
            target.Interesting = true;
            targets.push_back(std::move(target));
        }
    }

    if (walkIncomplete)
    {
        EmitUnique(
            L"process.implant",
            L"scan_failed:userhostility",
            std::wstring(),
            L"user",
            L"user-mode hostility scan failed to enumerate processes",
            std::wstring());
        if (targets.empty())
        {
            return;
        }
    }
    else
    {
        ClearEmittedKey(L"scan_failed:userhostility");
    }

    auto highEnd = std::stable_partition(
        targets.begin(),
        targets.end(),
        [](const KmonUserTarget& item)
        {
            return item.HighPriority;
        });
    std::stable_partition(
        highEnd,
        targets.end(),
        [](const KmonUserTarget& item)
        {
            return item.Interesting;
        });

    constexpr uint32_t kMaxDeepScans = 1024;
    uint32_t scanned = 0;
    bool deepCapped = false;
    for (const KmonUserTarget& target : targets)
    {
        if (StopRequested.load())
        {
            break;
        }
        if (scanned >= kMaxDeepScans)
        {
            deepCapped = true;
            break;
        }
        ++scanned;
        if ((scanned % 16) == 0)
        {
            IngestLiveTimeline();
            IngestThreatIntel();
            if (StopRequested.load())
            {
                break;
            }
        }

        const uint32_t pid = target.Pid;
        const std::wstring& imagePath = target.ImagePath;
        const std::wstring& leaf = target.Leaf;
        const bool builtin = KmonIsWindowsBuiltinLeaf(leaf);
        const bool nameWatched = NameEqualsWatch(leaf, watchNames);
        const bool watched = nameWatched || watchPids.count(pid) != 0;
        const bool dropHost = KmonClassifyDriverPath(imagePath) == L"drop";
        const bool hostileHost = watched || builtin || dropHost;
        if (watched && pid > 4)
        {
            if (nameWatched)
            {
                PromoteNamedWatchPid(pid);
            }
            else
            {
                EnableLoggingForPid(pid);
            }
        }
        if (builtin &&
            PathHasDirectorySeparator(imagePath) &&
            !KmonWindowsBuiltinPathLooksInbox(imagePath))
        {
            EmitUnique(
                L"process.masquerade",
                L"masq:" + std::to_wstring(pid),
                imagePath,
                L"masquerade",
                L"Windows-named process from a non-inbox path pid=" +
                    std::to_wstring(pid) + L" " + imagePath,
                L"leaf=" + leaf,
                pid);
        }

            uint64_t moduleBase = 0;
            std::vector<std::wstring> modulePaths;
            std::vector<std::pair<uint64_t, uint32_t>> moduleRanges;
            HANDLE modSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid);
            size_t moduleCount = 0;
            constexpr size_t kMaxModuleRows = 1024;
            bool moduleWalkOk = false;
            if (modSnap != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32W moduleEntry = {};
                moduleEntry.dwSize = sizeof(moduleEntry);
                BOOL moreMod = FALSE;
                DWORD modError = ERROR_SUCCESS;
                if (Module32FirstW(modSnap, &moduleEntry))
                {
                    moreMod = TRUE;
                    do
                    {
                        ++moduleCount;
                        const std::wstring moduleLeaf = KmonBasenameLower(moduleEntry.szExePath);
                        const bool isExe =
                            moduleLeaf == leaf ||
                            KmonBasenameLower(moduleEntry.szModule) == leaf;
                        if (isExe && moduleBase == 0)
                        {
                            moduleBase = reinterpret_cast<uint64_t>(moduleEntry.modBaseAddr);
                        }
                        if (modulePaths.size() < kMaxModuleRows)
                        {
                            modulePaths.push_back(moduleEntry.szExePath);
                        }
                        if (moduleRanges.size() < kMaxModuleRows)
                        {
                            moduleRanges.push_back(std::make_pair(
                                reinterpret_cast<uint64_t>(moduleEntry.modBaseAddr),
                                moduleEntry.modBaseSize));
                        }
                        moduleEntry.dwSize = sizeof(moduleEntry);
                        moreMod = Module32NextW(modSnap, &moduleEntry);
                        if (!moreMod)
                        {
                            modError = GetLastError();
                        }
                    } while (moreMod);
                    moduleWalkOk =
                        moduleCount > 0 &&
                        moduleCount <= kMaxModuleRows &&
                        (modError == ERROR_NO_MORE_FILES ||
                            modError == ERROR_SUCCESS);
                }
                CloseHandle(modSnap);
            }
            const bool moduleInventoryComplete = moduleWalkOk;
            std::unordered_set<std::wstring> importedDlls;

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pid);
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                    FALSE,
                    pid);
            }
            const bool hasVmRead = processHandle != nullptr;
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            }
            bool wow64 = false;
            const bool wow64Known = QueryProcessIsWow64(
                processHandle,
                device,
                symbols,
                pid,
                &wow64);
            uint64_t pebImageBase = 0;
            QueryPebImageBase(processHandle, device, symbols, pid, &pebImageBase);
            uint64_t sectionBase = 0;
            if (pebImageBase == 0 && moduleBase == 0)
            {
                QuerySectionBaseAddress(device, symbols, pid, &sectionBase);
            }
            const uint64_t exeRegion = pebImageBase != 0
                ? pebImageBase
                : (moduleBase != 0 ? moduleBase : sectionBase);
            if (pebImageBase != 0 &&
                moduleBase != 0 &&
                pebImageBase != moduleBase)
            {
                EmitUnique(
                    L"process.hollow",
                    L"exe_peb_base:" + std::to_wstring(pid),
                    imagePath,
                    L"exe_peb_base",
                    L"PEB ImageBase does not match loader EXE base pid=" +
                        std::to_wstring(pid) + L" " + leaf,
                    L"peb=" + HexU64(pebImageBase) + L" ldr=" + HexU64(moduleBase),
                    pid);
            }
            MEMORY_BASIC_INFORMATION mbi = {};
            bool queried = false;
            if (exeRegion != 0 &&
                processHandle != nullptr &&
                VirtualQueryEx(
                    processHandle,
                    reinterpret_cast<LPCVOID>(exeRegion),
                    &mbi,
                    sizeof(mbi)) == sizeof(mbi))
            {
                queried = true;
            }
            ProcessVadScanResult kernelVad = {};
            ProcessVadRecord exeVad = {};
            bool kernelVadScanned = false;
            // VirtualQueryEx can succeed while Toolhelp module enumeration
            // fails (ObCallback / PPL). The usermode orphan walk needs a
            // module list, so those targets still need kernel private-VAD
            // PE probes. Hidden PTEs follow the same kernel-VAD gate so PPL
            // builtin hosts are covered when usermode walks cannot run.
            const bool needKernelPrivateImplants =
                (hostileHost) &&
                (!queried || !moduleInventoryComplete);
            const bool wantKernelVad = watched || dropHost || needKernelPrivateImplants;
            // Watched/drop hosts still need private-VAD PE probes when the
            // usermode module list is complete; header-intact and wiped
            // manual maps would otherwise hide behind the JIT skip.
            const bool probePrivatePe = wantKernelVad;
            const bool hasKernelVadScan =
                wantKernelVad &&
                QueryKernelVadScan(
                    device,
                    symbols,
                    pid,
                    &kernelVad,
                    &kernelVadScanned,
                    wantKernelVad,
                    probePrivatePe);
            const std::wstring vadFailKey =
                L"scan_failed:userhostility:vad:" + std::to_wstring(pid);
            if (wantKernelVad && !kernelVadScanned)
            {
                EmitUnique(
                    L"process.implant",
                    vadFailKey,
                    imagePath,
                    L"user",
                    L"kernel VAD scan failed for pid=" + std::to_wstring(pid) +
                        L" " + leaf,
                    L"PPL/no-handle EXE and private-exec coverage is absent",
                    pid);
            }
            else if (wantKernelVad &&
                (kernelVad.Incomplete ||
                    kernelVad.Truncated ||
                    kernelVad.HiddenPteTruncated))
            {
                EmitUnique(
                    L"process.implant",
                    vadFailKey,
                    imagePath,
                    L"user",
                    L"kernel VAD coverage was incomplete for pid=" +
                        std::to_wstring(pid) + L" " + leaf,
                    kernelVad.HiddenPteTruncated
                        ? L"hidden PTE walk truncated"
                        : (kernelVad.Truncated
                            ? L"VAD traversal truncated"
                            : L"VAD/PTE coverage incomplete"),
                    pid);
            }
            else if (wantKernelVad)
            {
                ClearEmittedKeyForPid(vadFailKey, pid);
            }
            // ObCallback handle stripping also blanks the Toolhelp module
            // list, which silently disables the IAT/export/vtable/text hook
            // scans below. Rebuild the inventory from kernel VAD records
            // (image-backed mappings keep their section file name) so those
            // scans keep running with kernel reads only. Toolhelp-based
            // completeness gates stay untouched.
            bool kernelModuleInventory = false;
            if (!moduleWalkOk && hasKernelVadScan)
            {
                for (const ProcessVadRecord& record : kernelVad.Records)
                {
                    if (modulePaths.size() >= kMaxModuleRows)
                    {
                        break;
                    }
                    if (record.HasPrivateMemory && record.PrivateMemory)
                    {
                        continue;
                    }
                    // Named data-file mappings (game assets, pagefile
                    // sections are nameless) also carry section file names;
                    // only PE-probed VADs are loader modules.
                    if (record.SectionFileName.empty() ||
                        !record.PeHeaderFound ||
                        record.Size < 0x1000 ||
                        record.Size > 0x10000000ull)
                    {
                        continue;
                    }
                    modulePaths.push_back(
                        KmonDevicePathToWin32(record.SectionFileName));
                    moduleRanges.push_back(std::make_pair(
                        record.StartAddress,
                        static_cast<uint32_t>(
                            (std::min<uint64_t>)(
                                record.Size,
                                0xFFFFFFFFull))));
                }
                kernelModuleInventory = !modulePaths.empty();
            }
            // A stripped or refused handle is itself hostility evidence
            // (ObRegisterCallbacks access-mask removal); say so once per
            // pid instead of silently switching to kernel-only mode. The
            // kernel VAD scan doubles as proof the process is alive, so
            // exit races do not fire this.
            const bool handleStripped =
                processHandle == nullptr || !hasVmRead;
            const std::wstring handleDeniedKey =
                L"handle_denied:" + std::to_wstring(pid);
            if (handleStripped &&
                (hostileHost || watched || dropHost) &&
                wantKernelVad &&
                kernelVadScanned)
            {
                EmitUnique(
                    L"process.implant",
                    handleDeniedKey,
                    imagePath,
                    L"user",
                    L"user handle to process was denied; kernel-only investigation active pid=" +
                        std::to_wstring(pid) + L" " + leaf,
                    std::wstring(L"requested=QUERY_INFORMATION|VM_READ ") +
                        (processHandle == nullptr
                            ? L"result=open_denied"
                            : L"result=vm_read_stripped"),
                    pid);
            }
            else
            {
                ClearEmittedKeyForPid(handleDeniedKey, pid);
            }
            bool hasKernelVad = false;
            if (hasKernelVadScan && exeRegion != 0)
            {
                for (const ProcessVadRecord& record : kernelVad.Records)
                {
                    if (VadCoversUserAddress(record, exeRegion))
                    {
                        exeVad = record;
                        hasKernelVad = true;
                        break;
                    }
                }
            }
            if (exeRegion != 0)
            {
                bool committed = queried && mbi.State == MEM_COMMIT;
                bool privateExe =
                    committed &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED);
                if (!queried && hasKernelVad)
                {
                    committed = true;
                    privateExe =
                        exeVad.HasPrivateMemory && exeVad.PrivateMemory;
                }

                bool wxExe = false;
                DWORD wxProtect = 0;
                if (queried && hostileHost && processHandle != nullptr)
                {
                    MEMORY_BASIC_INFORMATION walk = mbi;
                    const uint64_t allocBase = reinterpret_cast<uint64_t>(walk.AllocationBase);
                    for (int step = 0; step < 16; ++step)
                    {
                        const DWORD protect = walk.Protect & 0xff;
                        if (walk.State == MEM_COMMIT && protect == PAGE_EXECUTE_READWRITE)
                        {
                            wxExe = true;
                            wxProtect = protect;
                            break;
                        }
                        const uint64_t next =
                            reinterpret_cast<uint64_t>(walk.BaseAddress) + walk.RegionSize;
                        if (next <= reinterpret_cast<uint64_t>(walk.BaseAddress))
                        {
                            break;
                        }
                        if (VirtualQueryEx(
                                processHandle,
                                reinterpret_cast<LPCVOID>(next),
                                &walk,
                                sizeof(walk)) != sizeof(walk))
                        {
                            break;
                        }
                        if (reinterpret_cast<uint64_t>(walk.AllocationBase) != allocBase)
                        {
                            break;
                        }
                    }
                }

                if (!wxExe &&
                    hasKernelVad &&
                    hostileHost &&
                    exeVad.WritableExecutable)
                {
                    wxExe = true;
                    wxProtect = exeVad.Protection;
                }

                std::wstring mappedPath;
                bool mappedQueryOk = false;
                if (hasVmRead && processHandle != nullptr)
                {
                    mappedQueryOk = QueryMappedImagePath(processHandle, exeRegion, &mappedPath);
                }
                bool mappedFromKernelVad = false;
                if (mappedPath.empty() &&
                    hasKernelVad &&
                    !exeVad.SectionFileName.empty())
                {
                    // GetMappedFileNameW needs a VM_READ handle the target
                    // may strip; the kernel VAD already carries the section
                    // file name via ControlArea -> FILE_OBJECT.
                    mappedPath = KmonDevicePathToWin32(exeVad.SectionFileName);
                    mappedFromKernelVad = !mappedPath.empty();
                }

                if (queried && !committed)
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_unmapped:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_unmapped",
                        L"main EXE ImageBase is not committed pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"state=" + std::to_wstring(mbi.State),
                        pid);
                }
                else if (!queried &&
                    kernelVadScanned &&
                    !hasKernelVad &&
                    !kernelVad.Truncated &&
                    !kernelVad.Incomplete)
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_unmapped:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_unmapped",
                        L"main EXE ImageBase is not committed pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"kernel_vad_no_cover",
                        pid);
                }
                else if (KmonExeRegionLooksPrivate(
                    queried,
                    committed,
                    mbi.Type,
                    privateExe && hasKernelVad))
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_private:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_private",
                        L"main EXE region is not a file-backed image mapping pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        queried
                            ? (L"type=" + std::to_wstring(mbi.Type))
                            : (L"vad_private=" +
                                std::to_wstring(exeVad.PrivateMemory ? 1 : 0)),
                        pid);
                }
                else if (!mappedPath.empty())
                {
                    const std::wstring mappedLeaf = KmonBasenameLower(mappedPath);
                    const std::wstring imageClass = KmonClassifyDriverPath(imagePath);
                    const std::wstring mappedClass = KmonClassifyDriverPath(mappedPath);
                    const bool pathMismatch =
                        mappedLeaf != leaf ||
                        (imageClass != L"drop" && mappedClass == L"drop") ||
                        (builtin &&
                            KmonWindowsBuiltinPathLooksInbox(imagePath) &&
                            !KmonWindowsBuiltinPathLooksInbox(mappedPath));
                    if (pathMismatch)
                    {
                        EmitUnique(
                            L"process.hollow",
                            L"exe_mapped:" + std::to_wstring(pid),
                            imagePath,
                            L"exe_mapped_path",
                            L"main EXE mapping file does not match process image pid=" +
                                std::to_wstring(pid) + L" " + leaf,
                            L"mapped=" + mappedPath +
                                (mappedFromKernelVad
                                    ? L" mapped_source=kernel_vad"
                                    : std::wstring()),
                            pid);
                    }
                }
                else if (hasVmRead &&
                    committed &&
                    mbi.Type == MEM_IMAGE &&
                    !mappedQueryOk)
                {
                    const DWORD mappedErr = GetLastError();
                    if (mappedErr != ERROR_ACCESS_DENIED &&
                        mappedErr != ERROR_INSUFFICIENT_BUFFER)
                    {
                        EmitUnique(
                            L"process.hollow",
                            L"exe_unbacked:" + std::to_wstring(pid),
                            imagePath,
                            L"exe_unbacked",
                            L"main EXE image mapping has no file name pid=" +
                                std::to_wstring(pid) + L" " + leaf,
                            L"unbacked_image",
                            pid);
                    }
                }

                if (wxExe)
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_wx:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_wx",
                        L"main EXE is W+X pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"protect=" + std::to_wstring(wxProtect),
                        pid);
                }

                std::vector<uint8_t> live;
                const bool liveOk = ReadProcessBytes(
                    device,
                    symbols,
                    processHandle,
                    pid,
                    exeRegion,
                    0x400,
                    &live);
                const bool diskPathUsable = PathLooksLikeWin32File(imagePath);
                const bool diskExists = diskPathUsable &&
                    GetFileAttributesW(imagePath.c_str()) != INVALID_FILE_ATTRIBUTES;
                const bool liveMz =
                    liveOk && live.size() >= 2 && live[0] == 'M' && live[1] == 'Z';
                if (liveOk && live.size() >= 2 && !liveMz)
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_no_mz:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_no_mz",
                        L"main EXE ImageBase has no MZ header pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"base=" + HexU64(exeRegion),
                        pid);
                }
                else if (liveMz)
                {
                    if (!diskExists && diskPathUsable)
                    {
                        EmitUnique(
                            L"process.hollow",
                            L"ghost:" + std::to_wstring(pid),
                            imagePath,
                            L"ghost",
                            L"process image is mapped but missing on disk pid=" +
                                std::to_wstring(pid) + L" " + imagePath,
                            L"ghosting",
                            pid);
                    }
                    else if (diskExists)
                    {
                        std::vector<uint8_t> diskHeaders;
                        KmonPeLayout diskLayout = {};
                        KmonPeIdentity liveId = {};
                        const bool parsedDisk = ReadDiskPeHead(imagePath, &diskHeaders) &&
                            ParseKmonPeLayout(diskHeaders, &diskLayout);
                        if (parsedDisk && (watched || dropHost))
                        {
                            CollectImportedDllNames(
                                imagePath,
                                diskHeaders,
                                diskLayout,
                                &importedDlls);
                            const std::wstring iatFailKey =
                                L"scan_failed:userhostility:iat:" + std::to_wstring(pid);
                            if (!moduleInventoryComplete || modulePaths.empty())
                            {
                                EmitUnique(
                                    L"process.implant",
                                    iatFailKey,
                                    imagePath,
                                    L"user",
                                    L"IAT thunk scan skipped; module list is incomplete pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"delay-load and PPL hosts would false-positive",
                                    pid);
                            }
                            else
                            {
                                ClearEmittedKeyForPid(iatFailKey, pid);
                                uint32_t iatHits = 0;
                                ScanLiveImportThunks(
                                    imagePath,
                                    diskHeaders,
                                    diskLayout.ImportRva,
                                    diskLayout.ImportSize,
                                    12,
                                    16,
                                    20,
                                    diskLayout.Is64,
                                    exeRegion,
                                    processHandle,
                                    device,
                                    symbols,
                                    pid,
                                    diskLayout.SizeOfImage,
                                    modulePaths,
                                    moduleRanges,
                                    &iatHits);
                                ScanLiveImportThunks(
                                    imagePath,
                                    diskHeaders,
                                    diskLayout.DelayImportRva,
                                    diskLayout.DelayImportSize,
                                    4,
                                    12,
                                    32,
                                    diskLayout.Is64,
                                    exeRegion,
                                    processHandle,
                                    device,
                                    symbols,
                                    pid,
                                    diskLayout.SizeOfImage,
                                    modulePaths,
                                    moduleRanges,
                                    &iatHits);
                                if (iatHits > 0)
                                {
                                    EmitUnique(
                                        L"process.implant",
                                        L"iat_hook:" + std::to_wstring(pid),
                                        imagePath,
                                        L"iat_hook",
                                        L"IAT thunks leave their imported modules pid=" +
                                            std::to_wstring(pid) + L" " + leaf,
                                        L"hits=" + std::to_wstring(iatHits),
                                        pid);
                                }
                            }
                        }
                        const bool parsedLive = ParseKmonPeIdentity(live, &liveId);
                        const bool compareText = hostileHost ||
                            KmonWindowsBuiltinPathLooksInbox(imagePath);
                        if (compareText &&
                            parsedDisk &&
                            diskLayout.PreferredBase != 0 &&
                            exeRegion != diskLayout.PreferredBase &&
                            diskLayout.RelocRva == 0 &&
                            diskLayout.RelocSize == 0)
                        {
                            EmitUnique(
                                L"process.hollow",
                                L"exe_rebased_no_reloc:" + std::to_wstring(pid),
                                imagePath,
                                L"exe_rebased_no_reloc",
                                L"main EXE is rebased with no reloc directory pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"preferred=" + HexU64(diskLayout.PreferredBase) +
                                    L" live=" + HexU64(exeRegion),
                                pid);
                        }
                        const bool identityMismatch = parsedDisk && parsedLive &&
                            (diskLayout.SizeOfImage != liveId.SizeOfImage ||
                                diskLayout.EntryPointRva != liveId.EntryPointRva ||
                                (diskLayout.TimeDateStamp != 0 &&
                                    liveId.TimeDateStamp != 0 &&
                                    diskLayout.TimeDateStamp != liveId.TimeDateStamp) ||
                                (diskLayout.NumberOfSections != 0 &&
                                    liveId.NumberOfSections != 0 &&
                                    diskLayout.NumberOfSections != liveId.NumberOfSections));
                        if (wow64Known &&
                            parsedLive &&
                            liveId.Machine != 0 &&
                            ((wow64 && liveId.Is64) ||
                                (!wow64 && !liveId.Is64 &&
                                    liveId.Machine == IMAGE_FILE_MACHINE_I386)))
                        {
                            EmitUnique(
                                L"process.hollow",
                                L"exe_arch:" + std::to_wstring(pid),
                                imagePath,
                                L"exe_arch",
                                L"main EXE machine does not match process bitness pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"wow64=" + std::to_wstring(wow64 ? 1 : 0) +
                                    L" live64=" + std::to_wstring(liveId.Is64 ? 1 : 0) +
                                    L" machine=" + std::to_wstring(liveId.Machine),
                                pid);
                        }
                        if (compareText && identityMismatch)
                        {
                            EmitUnique(
                                L"process.hollow",
                                L"hollow:" + std::to_wstring(pid),
                                imagePath,
                                L"hollow",
                                L"in-memory PE identity does not match disk pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"disk_size=" + std::to_wstring(diskLayout.SizeOfImage) +
                                    L" live_size=" + std::to_wstring(liveId.SizeOfImage) +
                                    L" disk_ep=" + std::to_wstring(diskLayout.EntryPointRva) +
                                    L" live_ep=" + std::to_wstring(liveId.EntryPointRva) +
                                    L" disk_stamp=" + std::to_wstring(diskLayout.TimeDateStamp) +
                                    L" live_stamp=" + std::to_wstring(liveId.TimeDateStamp),
                                pid);
                        }
                        else if (compareText &&
                            parsedDisk &&
                            diskLayout.ExecSize >= 16 &&
                            diskLayout.ExecFileOffset != 0)
                        {
                            const SliceCompare textCmp = RelocatedSliceCompare(
                                imagePath,
                                diskHeaders,
                                diskLayout,
                                processHandle,
                                device,
                                symbols,
                                pid,
                                exeRegion,
                                diskLayout.ExecRva,
                                diskLayout.ExecFileOffset,
                                diskLayout.ExecSize);
                            if (textCmp == SliceMismatch)
                            {
                                EmitUnique(
                                    L"process.hollow",
                                    L"exe_text:" + std::to_wstring(pid),
                                    imagePath,
                                    L"exe_text",
                                    L"main EXE code bytes differ from disk pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"rva=" + std::to_wstring(diskLayout.ExecRva) +
                                        L" compared=" + std::to_wstring(diskLayout.ExecSize),
                                    pid);
                            }
                            else if (
                                textCmp == SliceUnknown &&
                                diskLayout.PreferredBase != 0 &&
                                exeRegion != diskLayout.PreferredBase &&
                                diskLayout.RelocRva != 0 &&
                                diskLayout.RelocSize != 0)
                            {
                                EmitUnique(
                                    L"process.implant",
                                    L"scan_failed:userhostility:reloc:" +
                                        std::to_wstring(pid),
                                    imagePath,
                                    L"user",
                                    L"relocated EXE text compare could not run pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"reloc bytes were not readable",
                                    pid);
                            }
                            else
                            {
                                ClearEmittedKeyForPid(
                                    L"scan_failed:userhostility:reloc:" +
                                        std::to_wstring(pid),
                                    pid);
                            }
                            if (textCmp != SliceMismatch &&
                                diskLayout.ExecVirtSize > 0x1000)
                            {
                                uint32_t samples[3] = {};
                                uint32_t sampleCount = 0;
                                auto addSampleEarly = [&](uint32_t pageRva)
                                {
                                    if (pageRva <= diskLayout.ExecRva ||
                                        sampleCount >= 3)
                                    {
                                        return;
                                    }
                                    for (uint32_t i = 0; i < sampleCount; ++i)
                                    {
                                        if (samples[i] == pageRva)
                                        {
                                            return;
                                        }
                                    }
                                    samples[sampleCount++] = pageRva;
                                };
                                if (diskLayout.ExecRva <=
                                    (std::numeric_limits<uint32_t>::max)() - 0x1000)
                                {
                                    addSampleEarly(diskLayout.ExecRva + 0x1000);
                                }
                                if (diskLayout.ExecVirtSize > 0x2000)
                                {
                                    const uint32_t midOff =
                                        (diskLayout.ExecVirtSize / 2) & ~0xFFFu;
                                    if (diskLayout.ExecRva <=
                                        (std::numeric_limits<uint32_t>::max)() - midOff)
                                    {
                                        addSampleEarly(diskLayout.ExecRva + midOff);
                                    }
                                    if (diskLayout.ExecVirtSize >= 0x100)
                                    {
                                        const uint32_t lastOff =
                                            (diskLayout.ExecVirtSize - 0x100) & ~0xFFFu;
                                        if (diskLayout.ExecRva <=
                                            (std::numeric_limits<uint32_t>::max)() - lastOff)
                                        {
                                            addSampleEarly(diskLayout.ExecRva + lastOff);
                                        }
                                    }
                                }
                                for (uint32_t i = 0; i < sampleCount; ++i)
                                {
                                    uint32_t laterFile = 0;
                                    if (!RvaToFileOffset(
                                            diskHeaders,
                                            samples[i],
                                            &laterFile) ||
                                        RelocatedSliceCompare(
                                            imagePath,
                                            diskHeaders,
                                            diskLayout,
                                            processHandle,
                                            device,
                                            symbols,
                                            pid,
                                            exeRegion,
                                            samples[i],
                                            laterFile,
                                            0x100) != SliceMismatch)
                                    {
                                        continue;
                                    }
                                    EmitUnique(
                                        L"process.hollow",
                                        L"exe_text_page:" + std::to_wstring(pid) + L":" +
                                            std::to_wstring(samples[i]),
                                        imagePath,
                                        L"exe_text_page",
                                        L"main EXE later code page differs from disk pid=" +
                                            std::to_wstring(pid) + L" " + leaf,
                                        L"rva=" + std::to_wstring(samples[i]),
                                        pid);
                                    break;
                                }
                            }
                        }
                        else if (compareText &&
                            parsedDisk &&
                            diskLayout.ExecVirtSize > 0x1000)
                        {
                            uint32_t samples[3] = {};
                            uint32_t sampleCount = 0;
                            auto addSample = [&](uint32_t pageRva)
                            {
                                if (pageRva <= diskLayout.ExecRva ||
                                    sampleCount >= 3)
                                {
                                    return;
                                }
                                for (uint32_t i = 0; i < sampleCount; ++i)
                                {
                                    if (samples[i] == pageRva)
                                    {
                                        return;
                                    }
                                }
                                samples[sampleCount++] = pageRva;
                            };
                            if (diskLayout.ExecRva <=
                                (std::numeric_limits<uint32_t>::max)() - 0x1000)
                            {
                                addSample(diskLayout.ExecRva + 0x1000);
                            }
                            if (diskLayout.ExecVirtSize > 0x2000)
                            {
                                const uint32_t midOff =
                                    (diskLayout.ExecVirtSize / 2) & ~0xFFFu;
                                if (diskLayout.ExecRva <=
                                    (std::numeric_limits<uint32_t>::max)() - midOff)
                                {
                                    addSample(diskLayout.ExecRva + midOff);
                                }
                                if (diskLayout.ExecVirtSize >= 0x100)
                                {
                                    const uint32_t lastOff =
                                        (diskLayout.ExecVirtSize - 0x100) & ~0xFFFu;
                                    if (diskLayout.ExecRva <=
                                        (std::numeric_limits<uint32_t>::max)() - lastOff)
                                    {
                                        addSample(diskLayout.ExecRva + lastOff);
                                    }
                                }
                            }
                            for (uint32_t i = 0; i < sampleCount; ++i)
                            {
                                uint32_t laterFile = 0;
                                if (!RvaToFileOffset(
                                        diskHeaders,
                                        samples[i],
                                        &laterFile) ||
                                    RelocatedSliceCompare(
                                        imagePath,
                                        diskHeaders,
                                        diskLayout,
                                        processHandle,
                                        device,
                                        symbols,
                                        pid,
                                        exeRegion,
                                        samples[i],
                                        laterFile,
                                        0x100) != SliceMismatch)
                                {
                                    continue;
                                }
                                EmitUnique(
                                    L"process.hollow",
                                    L"exe_text_page:" + std::to_wstring(pid) + L":" +
                                        std::to_wstring(samples[i]),
                                    imagePath,
                                    L"exe_text_page",
                                    L"main EXE later code page differs from disk pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"rva=" + std::to_wstring(samples[i]),
                                    pid);
                                break;
                            }
                        }
                        if (compareText &&
                            parsedDisk &&
                            diskLayout.EntryPointRva != 0 &&
                            (diskLayout.EntryPointRva < diskLayout.ExecRva ||
                                diskLayout.ExecSize >
                                    (std::numeric_limits<uint32_t>::max)() -
                                        diskLayout.ExecRva ||
                                diskLayout.EntryPointRva >=
                                    diskLayout.ExecRva + diskLayout.ExecSize))
                        {
                            uint32_t epFile = 0;
                            if (RvaToFileOffset(diskHeaders, diskLayout.EntryPointRva, &epFile) &&
                                RelocatedSliceCompare(
                                    imagePath,
                                    diskHeaders,
                                    diskLayout,
                                    processHandle,
                                    device,
                                    symbols,
                                    pid,
                                    exeRegion,
                                    diskLayout.EntryPointRva,
                                    epFile,
                                    0x80) == SliceMismatch)
                            {
                                EmitUnique(
                                    L"process.hollow",
                                    L"exe_ep:" + std::to_wstring(pid),
                                    imagePath,
                                    L"exe_ep",
                                    L"main EXE entry-point bytes differ from disk pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"ep=" + std::to_wstring(diskLayout.EntryPointRva),
                                    pid);
                            }
                        }
                        if (compareText &&
                            hasVmRead &&
                            committed &&
                            mbi.Type == MEM_IMAGE &&
                            parsedDisk &&
                            processHandle != nullptr)
                        {
                            uint32_t cowRvas[3] = {};
                            uint32_t cowN = 0;
                            if (diskLayout.ExecRva != 0)
                            {
                                cowRvas[cowN++] = diskLayout.ExecRva;
                            }
                            if (diskLayout.ExecVirtSize > 0x1000 &&
                                diskLayout.ExecRva <=
                                    (std::numeric_limits<uint32_t>::max)() - 0x1000)
                            {
                                cowRvas[cowN++] = diskLayout.ExecRva + 0x1000;
                            }
                            if (diskLayout.EntryPointRva != 0 &&
                                (cowN == 0 ||
                                    (diskLayout.EntryPointRva & ~0xFFFu) !=
                                        (cowRvas[0] & ~0xFFFu)))
                            {
                                cowRvas[cowN++] = diskLayout.EntryPointRva;
                            }
                            uint32_t privatePages = 0;
                            uint32_t validPages = 0;
                            if (cowN > 0 &&
                                CountPrivateCowImagePages(
                                    processHandle,
                                    device,
                                    symbols,
                                    pid,
                                    exeRegion,
                                    cowRvas,
                                    cowN,
                                    &privatePages,
                                    &validPages))
                            {
                                const bool cowHit =
                                    (validPages >= 2 && privatePages >= 2) ||
                                    (validPages == 1 &&
                                        privatePages == 1 &&
                                        diskLayout.ExecVirtSize <= 0x1000);
                                if (cowHit)
                                {
                                    EmitUnique(
                                        L"process.hollow",
                                        L"exe_cow:" + std::to_wstring(pid),
                                        imagePath,
                                        L"exe_cow",
                                        L"main EXE image pages are private COW pid=" +
                                            std::to_wstring(pid) + L" " + leaf,
                                        L"private=" + std::to_wstring(privatePages) +
                                            L" valid=" + std::to_wstring(validPages),
                                        pid);
                                }
                            }
                        }
                    }
                }
            }

            if (hasVmRead &&
                processHandle != nullptr &&
                moduleInventoryComplete &&
                !moduleRanges.empty())
            {
                uint64_t cursor = 0;
                uint32_t orphans = 0;
                int step = 0;
                for (; step < 4096 && orphans < 4; ++step)
                {
                    MEMORY_BASIC_INFORMATION region = {};
                    if (VirtualQueryEx(
                            processHandle,
                            reinterpret_cast<LPCVOID>(cursor),
                            &region,
                            sizeof(region)) != sizeof(region))
                    {
                        break;
                    }
                    const uint64_t alloc = reinterpret_cast<uint64_t>(region.AllocationBase);
                    const uint64_t next =
                        reinterpret_cast<uint64_t>(region.BaseAddress) + region.RegionSize;
                    const bool interesting =
                        KmonOrphanRegionInteresting(
                            region,
                            exeRegion,
                            moduleRanges);
                    if (interesting)
                    {
                        std::vector<uint8_t> head;
                        const bool gotHead = ReadProcessBytes(
                            device,
                            symbols,
                            processHandle,
                            pid,
                            alloc,
                            2,
                            &head);
                        const bool mz =
                            gotHead &&
                            head.size() >= 2 &&
                            head[0] == 'M' &&
                            head[1] == 'Z';
                        const bool rwx =
                            hostileHost &&
                            KmonProtectIsRwx(region.Protect);
                        if (mz)
                        {
                            std::wstring mappedOrphan;
                            if (region.Type == MEM_IMAGE || region.Type == MEM_MAPPED)
                            {
                                QueryMappedImagePath(processHandle, alloc, &mappedOrphan);
                            }
                            const wchar_t* layer = L"exe_orphan_private";
                            if (region.Type == MEM_IMAGE)
                            {
                                layer = L"exe_orphan_image";
                            }
                            else if (region.Type == MEM_MAPPED)
                            {
                                layer = L"exe_orphan_mapped";
                            }
                            EmitUnique(
                                L"process.hollow",
                                L"exe_orphan:" + std::to_wstring(pid) + L":" + HexU64(alloc),
                                imagePath,
                                layer,
                                L"extra PE mapping is not in the module list pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"base=" + HexU64(alloc) +
                                    L" type=" + std::to_wstring(region.Type) +
                                    (mappedOrphan.empty()
                                        ? std::wstring()
                                        : (L" mapped=" + mappedOrphan)),
                                pid);
                            ++orphans;
                        }
                        else if (rwx)
                        {
                            EmitUnique(
                                L"process.implant",
                                L"private_wx:" + std::to_wstring(pid) + L":" + HexU64(alloc),
                                imagePath,
                                L"private_wx",
                                L"private W+X region is not in the module list pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"base=" + HexU64(alloc) +
                                    L" size=" + std::to_wstring(
                                        static_cast<unsigned long long>(region.RegionSize)) +
                                    L" type=" + std::to_wstring(region.Type),
                                pid);
                            ++orphans;
                        }
                        else if (
                            hostileHost &&
                            region.Type == MEM_PRIVATE &&
                            ProtectHasExecute(region.Protect) &&
                            region.RegionSize <= 0x10000)
                        {
                            EmitUnique(
                                L"process.implant",
                                L"private_exec:" + std::to_wstring(pid) + L":" + HexU64(alloc),
                                imagePath,
                                L"private_exec",
                                L"private executable region is not in the module list pid=" +
                                    std::to_wstring(pid) + L" " + leaf,
                                L"base=" + HexU64(alloc) +
                                    L" size=" + std::to_wstring(
                                        static_cast<unsigned long long>(region.RegionSize)) +
                                    L" protect=" + std::to_wstring(region.Protect),
                                pid);
                            ++orphans;
                        }
                    }
                    if (next <= cursor)
                    {
                        break;
                    }
                    cursor = next;
                    if (cursor >= 0x00007FFFFFFEFFFFull)
                    {
                        break;
                    }
                }
                if (hostileHost && step >= 4096)
                {
                    EmitUnique(
                        L"process.implant",
                        L"scan_failed:userhostility:vmwalk:" + std::to_wstring(pid),
                        imagePath,
                        L"user",
                        L"usermode VAD walk hit the region cap pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"VirtualQueryEx stopped at 4096 regions",
                        pid);
                }
            }
            if (hasKernelVadScan && hostileHost)
            {
                uint32_t vadImplants = 0;
                // Usermode VirtualQueryEx reports MZ/RWX and small RX
                // orphans. Kernel private-VAD PE probes still run on
                // watched/drop hosts so wiped/header-intact maps are not
                // dropped when the module list is complete.
                const bool emitPrivateVadImplants = probePrivatePe;
                for (const ProcessVadRecord& record : kernelVad.Records)
                {
                    if (!emitPrivateVadImplants)
                    {
                        break;
                    }
                    if (vadImplants >= 4)
                    {
                        break;
                    }
                    if (record.Size < 0x1000 ||
                        VadCoversUserAddress(record, exeRegion))
                    {
                        continue;
                    }
                    const bool privateMem =
                        record.HasPrivateMemory && record.PrivateMemory;
                    if (!privateMem && !record.PeHeaderFound && !record.PeHeaderSuspicious)
                    {
                        continue;
                    }
                    const bool rwx = record.WritableExecutable;
                    const bool pe = record.PeHeaderFound;
                    const bool wiped = record.PeHeaderSuspicious;
                    // VAD Protection can stay RW after VirtualProtect to RX.
                    // Do not require record.Executable when the PE probe hit.
                    if (!record.Executable && !pe && !wiped)
                    {
                        continue;
                    }
                    if (!rwx && !pe && !wiped)
                    {
                        // Headerless private RX on games is dominated by JIT.
                        // Builtin and drop-path hosts should not have it.
                        if (!builtin && !dropHost)
                        {
                            continue;
                        }
                    }
                    const wchar_t* layer = wiped
                        ? L"private_exec_wiped"
                        : (pe
                            ? L"private_exec_pe"
                            : (rwx ? L"private_wx_vad" : L"private_exec_vad"));
                    EmitUnique(
                        L"process.implant",
                        std::wstring(layer) + L":" + std::to_wstring(pid) + L":" +
                            HexU64(record.StartAddress),
                        imagePath,
                        layer,
                        L"kernel VAD private executable region pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"base=" + HexU64(record.StartAddress) +
                            L" size=" + std::to_wstring(
                                static_cast<unsigned long long>(record.Size)) +
                            L" rwx=" + std::to_wstring(rwx ? 1 : 0) +
                            L" pe=" + std::to_wstring(pe ? 1 : 0) +
                            L" wiped=" + std::to_wstring(wiped ? 1 : 0),
                        pid);
                    ++vadImplants;
                }
                uint32_t hiddenPtes = 0;
                uint32_t vadRwPtes = 0;
                for (const ProcessHiddenVadPteRecord& pte : kernelVad.HiddenPteRecords)
                {
                    if (!pte.Executable || pte.Size < 0x1000)
                    {
                        continue;
                    }
                    if (exeRegion != 0 &&
                        exeRegion >= pte.StartAddress &&
                        exeRegion <= pte.EndAddress)
                    {
                        continue;
                    }
                    const bool vadRwPte =
                        pte.Notes.find(L"pte_exec_vad_rw") != std::wstring::npos;
                    if (vadRwPte)
                    {
                        if (vadRwPtes >= 4)
                        {
                            continue;
                        }
                    }
                    else if (hiddenPtes >= 4)
                    {
                        continue;
                    }
                    const wchar_t* layer = vadRwPte
                        ? L"pte_exec_vad_rw"
                        : L"hidden_exec_pte";
                    EmitUnique(
                        L"process.implant",
                        std::wstring(layer) + L":" + std::to_wstring(pid) + L":" +
                            HexU64(pte.StartAddress),
                        imagePath,
                        layer,
                        vadRwPte
                            ? (L"executable PTE is under a non-executable VAD pid=" +
                                std::to_wstring(pid) + L" " + leaf)
                            : (L"executable PTE is not covered by a VAD pid=" +
                                std::to_wstring(pid) + L" " + leaf),
                        L"base=" + HexU64(pte.StartAddress) +
                            L" size=" + std::to_wstring(
                                static_cast<unsigned long long>(pte.Size)),
                        pid);
                    if (vadRwPte)
                    {
                        ++vadRwPtes;
                    }
                    else
                    {
                        ++hiddenPtes;
                    }
                }
                if (IsMapperWatchActive() &&
                    watched &&
                    (hiddenPtes != 0 || vadRwPtes != 0))
                {
                    bool residue = false;
                    bool overlay = false;
                    bool tiWrite = false;
                    {
                        std::lock_guard<std::mutex> watchLock(WatchMutex);
                        residue = MapperWatchHasResidue;
                        overlay = MapperWatchHasOverlaySlot;
                        tiWrite = MapperWatchTiWritePids.find(pid) !=
                            MapperWatchTiWritePids.end();
                    }
                    if ((residue || overlay) && !tiWrite)
                    {
                        EmitUnique(
                            L"inject.kernel_phys",
                            L"kernel_phys:" + std::to_wstring(pid),
                            imagePath,
                            L"kernel_phys",
                            L"watched process gained hidden/protect-changed executable PTEs without TI WriteVM pid=" +
                                std::to_wstring(pid) + L" " + leaf,
                            L"hidden_ptes=" + std::to_wstring(hiddenPtes) +
                                L" vad_rw_ptes=" + std::to_wstring(vadRwPtes) +
                                L" residue=" + std::to_wstring(residue ? 1 : 0) +
                                L" overlay_slot=" + std::to_wstring(overlay ? 1 : 0),
                            pid);
                    }
                }
            }

            if (hostileHost)
            {
                uint64_t ic = 0;
                const std::wstring icFailKey =
                    L"scan_failed:instrumentation:" + std::to_wstring(pid);
                if (!QueryInstrumentationCallback(device, symbols, pid, &ic))
                {
                    EmitUnique(
                        L"hook.unbacked",
                        icFailKey,
                        imagePath,
                        L"instrumentation_callback",
                        L"InstrumentationCallback query failed for pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"KPROCESS field read failed",
                        pid);
                }
                else
                {
                    ClearEmittedKeyForPid(icFailKey, pid);
                    if (ic != 0)
                    {
                        bool haveOwnershipView = false;
                        bool owned = true;
                        const bool kernelIc = !IsUserModeImageBase(ic);
                        if (kernelIc)
                        {
                            haveOwnershipView = true;
                            owned = false;
                        }
                        else if (moduleInventoryComplete && !moduleRanges.empty())
                        {
                            haveOwnershipView = true;
                            owned = AddressInModuleRanges(ic, moduleRanges);
                        }
                        else if (hasKernelVadScan && !kernelVad.Records.empty())
                        {
                            haveOwnershipView = true;
                            owned = false;
                            bool covered = false;
                            for (const ProcessVadRecord& record : kernelVad.Records)
                            {
                                if (!VadCoversUserAddress(record, ic))
                                {
                                    continue;
                                }
                                covered = true;
                                owned = !(record.HasPrivateMemory && record.PrivateMemory);
                                break;
                            }
                            if (!covered)
                            {
                                owned = false;
                            }
                        }
                        if (haveOwnershipView && !owned)
                        {
                            EmitUnique(
                                L"hook.unbacked",
                                L"instrumentation:" + std::to_wstring(pid),
                                imagePath,
                                L"instrumentation_callback",
                                kernelIc
                                    ? (L"InstrumentationCallback is a kernel address pid=" +
                                        std::to_wstring(pid) + L" " + leaf)
                                    : (L"InstrumentationCallback is outside loaded modules pid=" +
                                        std::to_wstring(pid) + L" " + leaf),
                                L"callback=" + HexU64(ic),
                                pid);
                        }
                    }
                }
            }

            uint32_t implants = 0;
            uint32_t gameTextHits = 0;
            uint32_t systemTextHits = 0;
            const std::wstring moduleSourceNote =
                kernelModuleInventory
                    ? L" module_source=kernel_vad"
                    : std::wstring();
            const std::wstring imageDir = [&imagePath]() {
                std::wstring dir = ToLowerCopy(imagePath);
                for (wchar_t& ch : dir)
                {
                    if (ch == L'/')
                    {
                        ch = L'\\';
                    }
                }
                size_t slash = dir.find_last_of(L'\\');
                return (slash == std::wstring::npos) ? std::wstring() : dir.substr(0, slash + 1);
            }();
            for (size_t moduleIndex = 0; moduleIndex < modulePaths.size(); ++moduleIndex)
            {
                const std::wstring& modulePath = modulePaths[moduleIndex];
                const std::wstring moduleClass = KmonClassifyDriverPath(modulePath);
                const std::wstring n = KmonNormalizeDriverPath(modulePath);
                const bool windowsModule =
                    n.find(L"\\windows\\system32\\") != std::wstring::npos ||
                    n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                    n.find(L"\\windows\\winsxs\\") != std::wstring::npos;
                std::wstring moduleLower = ToLowerCopy(modulePath);
                for (wchar_t& ch : moduleLower)
                {
                    if (ch == L'/')
                    {
                        ch = L'\\';
                    }
                }
                const bool inImageDir =
                    imageDir.size() > 3 &&
                    moduleLower.find(imageDir) == 0;
                const std::wstring moduleLeaf = KmonBasenameLower(modulePath);
                const bool dropImplant =
                    moduleClass == L"drop" &&
                    moduleLeaf != leaf &&
                    hostileHost;
                const bool watchedUnimported =
                    (watched || dropHost) &&
                    !importedDlls.empty() &&
                    !windowsModule &&
                    inImageDir &&
                    (moduleClass == L"unknown" || moduleClass == L"third_party") &&
                    moduleLeaf != leaf &&
                    importedDlls.find(moduleLeaf) == importedDlls.end();
                const bool watchedDirHijack =
                    (watched || dropHost) &&
                    inImageDir &&
                    !windowsModule &&
                    moduleLeaf != leaf &&
                    KmonLooksLikeHijackDll(moduleLeaf);
                const bool watchedUnknown = (watched || dropHost) &&
                    !windowsModule &&
                    !inImageDir &&
                    moduleClass == L"unknown";
                const bool watchedForeignThirdParty =
                    (watched || dropHost) &&
                    !windowsModule &&
                    !inImageDir &&
                    moduleClass == L"third_party" &&
                    moduleLeaf != leaf &&
                    !KmonLooksLikeKnownRuntimePath(n);
                const bool builtinForeign = builtin &&
                    !windowsModule &&
                    !inImageDir &&
                    moduleClass != L"inbox" &&
                    moduleClass != L"third_party";
                const uint64_t loadedModuleBase =
                    (moduleIndex < moduleRanges.size())
                        ? moduleRanges[moduleIndex].first
                        : 0;
                const bool compareGameText =
                    (watched || dropHost) &&
                    !windowsModule &&
                    moduleLeaf != leaf &&
                    gameTextHits < 16 &&
                    loadedModuleBase != 0 &&
                    PathLooksLikeWin32File(modulePath);
                const bool compareSystemText =
                    (watched || dropHost) &&
                    windowsModule &&
                    KmonLooksLikeHookableSystemDll(moduleLeaf) &&
                    systemTextHits < 16 &&
                    loadedModuleBase != 0 &&
                    PathLooksLikeWin32File(modulePath);
                if (compareGameText || compareSystemText)
                {
                    if (compareGameText)
                    {
                        ++gameTextHits;
                    }
                    else
                    {
                        ++systemTextHits;
                    }
                    const std::wstring textFailKey =
                        L"scan_failed:userhostility:module_text:" +
                        std::to_wstring(pid) + L":" + moduleLeaf;
                    const SliceCompare textCmp = CompareLoadedModuleText(
                        modulePath,
                        processHandle,
                        device,
                        symbols,
                        pid,
                        loadedModuleBase);
                    if (textCmp == SliceMismatch)
                    {
                        EmitUnique(
                            L"process.implant",
                            L"module_text:" + std::to_wstring(pid) + L":" +
                                moduleLeaf,
                            imagePath,
                            L"module_text",
                                L"module code bytes differ from disk pid=" +
                                    std::to_wstring(pid) + L" " + leaf +
                                    L" module=" + moduleLeaf,
                                modulePath + moduleSourceNote,
                                pid);
                    }
                    else if (textCmp == SliceUnknown)
                    {
                        EmitUnique(
                            L"process.implant",
                            textFailKey,
                            imagePath,
                            L"user",
                            L"module text compare could not run pid=" +
                                std::to_wstring(pid) + L" " + leaf +
                                L" module=" + moduleLeaf,
                            L"disk or relocated bytes were not readable",
                            pid);
                    }
                    else
                    {
                        ClearEmittedKeyForPid(textFailKey, pid);
                    }
                    std::vector<uint8_t> moduleHeaders;
                    KmonPeLayout moduleLayout = {};
                    const bool parsedModule =
                        ReadDiskPeHead(modulePath, &moduleHeaders) &&
                        ParseKmonPeLayout(moduleHeaders, &moduleLayout);
                    if (parsedModule && compareSystemText)
                    {
                        const uint32_t exportHits = CountNtExportPrologueMismatches(
                            modulePath,
                            moduleHeaders,
                            moduleLayout,
                            processHandle,
                            device,
                            symbols,
                            pid,
                            loadedModuleBase);
                        if (exportHits > 0)
                        {
                            EmitUnique(
                                L"process.implant",
                                L"export_hook:" + std::to_wstring(pid) + L":" +
                                    moduleLeaf,
                                imagePath,
                                L"export_hook",
                                L"Nt/Zw export prologues differ from disk pid=" +
                                    std::to_wstring(pid) + L" " + leaf +
                                    L" module=" + moduleLeaf,
                                L"hits=" + std::to_wstring(exportHits) +
                                    moduleSourceNote,
                                pid);
                        }
                    }
                    const bool scanIatTables =
                        moduleInventoryComplete &&
                        !modulePaths.empty() &&
                        loadedModuleBase != 0 &&
                        (compareGameText ||
                            compareSystemText ||
                            ((watched || dropHost) && moduleLeaf == leaf));
                    const bool overlayLeaf = KmonLooksLikeOverlayRuntimeDll(moduleLeaf);
                    const bool scanVtables =
                        scanIatTables &&
                        (KmonLooksLikeGraphicsApiDll(moduleLeaf) || overlayLeaf);
                    if (parsedModule && scanIatTables)
                    {
                        uint32_t dllIatHits = 0;
                        ScanLiveImportThunks(
                            modulePath,
                            moduleHeaders,
                            moduleLayout.ImportRva,
                            moduleLayout.ImportSize,
                            12,
                            16,
                            20,
                            moduleLayout.Is64,
                            loadedModuleBase,
                            processHandle,
                            device,
                            symbols,
                            pid,
                            moduleLayout.SizeOfImage,
                            modulePaths,
                            moduleRanges,
                            &dllIatHits);
                        ScanLiveImportThunks(
                            modulePath,
                            moduleHeaders,
                            moduleLayout.DelayImportRva,
                            moduleLayout.DelayImportSize,
                            4,
                            12,
                            32,
                            moduleLayout.Is64,
                            loadedModuleBase,
                            processHandle,
                            device,
                            symbols,
                            pid,
                            moduleLayout.SizeOfImage,
                            modulePaths,
                            moduleRanges,
                            &dllIatHits);
                        if (dllIatHits > 0)
                        {
                            EmitUnique(
                                L"process.implant",
                                L"iat_hook:" + std::to_wstring(pid) + L":" +
                                    moduleLeaf,
                                imagePath,
                                L"iat_hook",
                            L"module IAT thunks leave imported modules pid=" +
                                std::to_wstring(pid) + L" " + leaf +
                                L" module=" + moduleLeaf,
                            L"hits=" + std::to_wstring(dllIatHits) +
                                moduleSourceNote,
                            pid);
                        }
                        if (scanVtables)
                        {
                            uint32_t tableHits = 0;
                            ScanLiveCallTablePointers(
                                moduleHeaders,
                                loadedModuleBase,
                                processHandle,
                                device,
                                symbols,
                                pid,
                                moduleRanges,
                                hasKernelVadScan ? &kernelVad.Records : nullptr,
                                &tableHits);
                            if (tableHits > 0)
                            {
                                if (overlayLeaf)
                                {
                                    NoteMapperWatchResidue(L"overlay_slot", 0);
                                }
                                EmitUnique(
                                    L"process.implant",
                                    (overlayLeaf ? L"overlay_slot:" : L"vtable_hook:") +
                                        std::to_wstring(pid) + L":" +
                                        moduleLeaf,
                                    imagePath,
                                    overlayLeaf ? L"overlay_slot" : L"vtable_hook",
                                    (overlayLeaf
                                        ? L"overlay call-table slots point at private executable memory pid="
                                        : L"module call-table slots point at private executable memory pid=") +
                                    std::to_wstring(pid) + L" " + leaf +
                                    L" module=" + moduleLeaf,
                                    L"hits=" + std::to_wstring(tableHits) +
                                        moduleSourceNote,
                                    pid);
                            }
                        }
                    }
                }
                if (implants >= 8)
                {
                    continue;
                }
                if (!dropImplant &&
                    !builtinForeign &&
                    !watchedUnknown &&
                    !watchedUnimported &&
                    !watchedDirHijack &&
                    !watchedForeignThirdParty)
                {
                    continue;
                }
                const wchar_t* implantLayer = dropImplant
                    ? L"drop_module"
                    : (watchedDirHijack
                        ? (KmonImageAuthenticodeValid(imagePath)
                            ? L"dll_proxy_host"
                            : L"watched_dir_hijack")
                        : (watchedUnimported
                            ? L"watched_dir_unimported"
                            : (watchedForeignThirdParty
                                ? L"watched_third_party_module"
                                : (watchedUnknown ? L"watched_unknown_module" : L"builtin_foreign_module"))));
                EmitUnique(
                    L"process.implant",
                    L"implant:" + std::to_wstring(pid) + L":" + KmonBasenameLower(modulePath),
                    imagePath,
                    implantLayer,
                    L"foreign module in pid=" + std::to_wstring(pid) + L" " + leaf +
                        L" module=" + KmonBasenameLower(modulePath),
                    modulePath,
                    pid);
                ++implants;
            }
            if (processHandle != nullptr)
            {
                CloseHandle(processHandle);
            }
    }

    if (!StopRequested.load() && (snapshotCapped || deepCapped))
    {
        EmitUnique(
            L"process.implant",
            L"scan_failed:userhostility:truncated",
            std::wstring(),
            L"user",
            L"user-mode hostility scan hit a process cap; extra hosts may be missed",
            snapshotCapped
                ? L"toolhelp snapshot capped at 4096"
                : L"deep scan capped at 1024");
    }
    else if (!StopRequested.load())
    {
        ClearEmittedKey(L"scan_failed:userhostility:truncated");
    }
}

void KernelMonitor::EnableLoggingForPid(uint32_t pid)
{
    if (pid <= 4 || !Active.load() || StopRequested.load())
    {
        return;
    }

    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }

    HANDLE query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    const uint64_t created = QueryPidCreateTime(device, symbols, query, pid);
    if (query != nullptr)
    {
        CloseHandle(query);
    }

    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        auto it = LoggingEnabledPids.find(pid);
        if (it != LoggingEnabledPids.end() &&
            created != 0 &&
            it->second == created)
        {
            return;
        }
    }

    uint32_t infoClass = 0;
    bool enabled = TryEnableLoggingUsermode(
        pid,
        KNDBG_PROCESS_LOG_DEFAULT,
        &infoClass);
    if (!enabled)
    {
        if (device == nullptr)
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
        }
        if (device != nullptr && device->IsOpen())
        {
            uint32_t applied = 0;
            uint32_t ntStatus = 0;
            uint64_t eprocess = 0;
            std::wstring error;
            enabled = device->SetProcessLogging(
                pid,
                KNDBG_PROCESS_LOG_DEFAULT,
                &applied,
                &infoClass,
                &ntStatus,
                &eprocess,
                &error);
            if (enabled && (ntStatus & 0x80000000u) != 0)
            {
                enabled = false;
            }
        }
    }

    const std::wstring loggingPartialKey =
        L"scan_failed:logging:partial:" + std::to_wstring(pid);
    const bool partialLogging =
        enabled &&
        infoClass == kProcessEnableReadWriteVmLogging;
    if (partialLogging)
    {
        EmitUnique(
            L"process.implant",
            loggingPartialKey,
            std::wstring(),
            L"logging",
            L"process logging fell back to ReadWriteVmLogging pid=" +
                std::to_wstring(pid),
            L"AllocVM/ProtectVM/APC/MapView may be silent",
            pid);
    }
    else
    {
        ClearEmittedKeyForPid(loggingPartialKey, pid);
    }

    if (enabled)
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        LoggingFailedPids.erase(pid);
        auto it = LoggingEnabledPids.find(pid);
        if (it == LoggingEnabledPids.end())
        {
            LoggingEnabledPids.emplace(pid, created);
            LoggingEnabledCount.fetch_add(1);
        }
        else
        {
            it->second = created;
        }
        if (created != 0 && WatchPromotedPids.count(pid) != 0)
        {
            WatchPromotedCreated[pid] = created;
        }
    }
    else
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        auto it = LoggingFailedPids.find(pid);
        if (it == LoggingFailedPids.end() || it->second != created)
        {
            LoggingFailedPids[pid] = created;
            LoggingFailedCount.fetch_add(1);
        }
    }
}

// Handle-table diff for watched pids: report new Device-typed handles as
// driver.handle so a loader acquiring a driver/device channel (BYOVD
// precondition) shows up on the tail. First pass per pid is a silent
// baseline; handle closes are not tracked.
void KernelMonitor::ScanWatchedHandleTables()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        return;
    }

    std::vector<uint32_t> pids;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        pids.assign(WatchPids.begin(), WatchPids.end());
    }
    if (pids.empty())
    {
        return;
    }
    std::sort(pids.begin(), pids.end());
    constexpr size_t kMaxWatchedHandleScans = 8;
    if (pids.size() > kMaxWatchedHandleScans)
    {
        pids.resize(kMaxWatchedHandleScans);
    }

    if (!WatchDeviceTypeKnown)
    {
        std::wstring typeError;
        uint32_t index = 0;
        if (!device->QueryDeviceObjectTypeIndex(&index, &typeError) ||
            index == 0)
        {
            EmitUnique(
                L"driver.handle",
                L"scan_failed:handles:type_index",
                std::wstring(),
                L"handle",
                L"device object type index could not be learned; driver.handle diffing is inactive",
                typeError.empty() ? L"QueryDeviceObjectTypeIndex failed" : typeError,
                0);
            return;
        }
        WatchDeviceTypeIndex = index;
        WatchDeviceTypeKnown = true;
        ClearEmittedKey(L"scan_failed:handles:type_index");
    }

    HandleTableScanner scanner(*device, *symbols);
    for (uint32_t pid : pids)
    {
        HandleTableScanOptions options = {};
        options.HasOwnerPid = true;
        options.OwnerPid = pid;
        options.ProcessHandlesOnly = false;
        options.CollectRecords = true;
        HandleTableScanResult result = {};
        std::wstring error;
        const std::wstring failKey =
            L"scan_failed:handles:" + std::to_wstring(pid);
        if (!scanner.Scan(options, &result, &error))
        {
            EmitUnique(
                L"driver.handle",
                failKey,
                std::wstring(),
                L"handle",
                L"handle-table scan failed for pid=" + std::to_wstring(pid),
                error.empty() ? L"Scan returned false" : error,
                pid);
            continue;
        }
        ClearEmittedKey(failKey);

        std::set<std::pair<uint64_t, uint64_t>> known;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            auto it = WatchKnownHandles.find(pid);
            if (it != WatchKnownHandles.end())
            {
                known = it->second;
            }
        }

        bool firstBaseline = known.empty();
        for (const HandleTableRecord& record : result.Records)
        {
            const std::pair<uint64_t, uint64_t> key(
                static_cast<uint64_t>(record.HandleValue),
                record.Object);
            if (known.find(key) != known.end())
            {
                continue;
            }
            known.insert(key);
            if (firstBaseline ||
                record.ObjectTypeIndex != WatchDeviceTypeIndex)
            {
                continue;
            }
            EmitUnique(
                L"driver.handle",
                L"driver_handle:" + std::to_wstring(pid) + L":" +
                    HexU64(record.HandleValue),
                std::wstring(),
                L"handle",
                L"watched process opened a device handle pid=" +
                    std::to_wstring(pid),
                L"handle=" + HexU64(record.HandleValue) +
                    L" object=" + HexU64(record.Object) +
                    L" access=" + HexU64(record.GrantedAccess),
                pid);
        }

        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            WatchKnownHandles[pid] = std::move(known);
        }
    }
}

// Iotrace control: the driver interposes the target's IRP_MJ_DEVICE_CONTROL
// and the worker loop drains the non-paged ring into driver.ioctl events
// (first seen per caller pid + ioctl code).
bool KernelMonitor::ArmIotrace(uint64_t driverObjectAddress, const std::wstring& driverName, std::wstring* error)
{
    bool ok = false;

    do
    {
        DeviceClient* device = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
        }
        if (device == nullptr || !device->IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"kernel device is not open";
            }
            break;
        }

        uint32_t armed = 0;
        std::wstring ioctlError;
        if (!device->ControlIotrace(
                KNDBG_IOTRACE_MODE_ARM,
                driverObjectAddress,
                &armed,
                nullptr,
                nullptr,
                &ioctlError))
        {
            if (error != nullptr)
            {
                *error = ioctlError;
            }
            break;
        }
        if (armed == 0)
        {
            if (error != nullptr)
            {
                *error = L"driver did not arm the interposition";
            }
            break;
        }

        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            IotraceActive = true;
            IotraceDriverName = driverName;
            IotraceSeen.clear();
            IotraceSeenCapNoted = false;
        }
        ok = true;
    } while (false);

    return ok;
}

bool KernelMonitor::DisarmIotrace(std::wstring* error)
{
    bool ok = false;

    do
    {
        DeviceClient* device = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
        }
        if (device == nullptr || !device->IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"kernel device is not open";
            }
            break;
        }

        DrainIotraceEvents();

        uint32_t armed = 0;
        std::wstring ioctlError;
        if (!device->ControlIotrace(
                KNDBG_IOTRACE_MODE_DISARM,
                0,
                &armed,
                nullptr,
                nullptr,
                &ioctlError))
        {
            if (error != nullptr)
            {
                *error = ioctlError;
            }
            break;
        }

        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            IotraceActive = false;
            IotraceDriverName.clear();
            IotraceSeen.clear();
            IotraceSeenCapNoted = false;
        }
        ok = true;
    } while (false);

    return ok;
}

bool KernelMonitor::IotraceArmed() const
{
    std::lock_guard<std::mutex> watchLock(WatchMutex);
    return IotraceActive;
}

void KernelMonitor::DrainIotraceEvents()
{
    DeviceClient* device = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
    }
    if (device == nullptr || !device->IsOpen())
    {
        return;
    }

    bool active = false;
    std::wstring driverName;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        active = IotraceActive;
        driverName = IotraceDriverName;
    }
    if (!active)
    {
        return;
    }

    std::vector<IotraceRecord> records;
    uint64_t dropped = 0;
    std::wstring error;
    if (!device->DrainIotrace(&records, &dropped, &error))
    {
        EmitUnique(
            L"driver.ioctl",
            L"scan_failed:iotrace:drain",
            driverName,
            L"iotrace",
            L"iotrace drain failed",
            error.empty() ? L"DrainIotrace returned false" : error,
            0);
        return;
    }
    ClearEmittedKey(L"scan_failed:iotrace:drain");

    constexpr size_t kMaxSeenEntries = 256;
    for (const IotraceRecord& record : records)
    {
        const std::pair<uint32_t, uint64_t> key(record.ProcessId, record.IoctlCode);
        bool firstSeen = false;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            if (IotraceSeen.size() < kMaxSeenEntries)
            {
                firstSeen = IotraceSeen.insert(key).second;
            }
        }
        if (!firstSeen)
        {
            continue;
        }

        const uint32_t function =
            static_cast<uint32_t>((record.IoctlCode >> 2) & 0xFFF);
        const uint32_t deviceType =
            static_cast<uint32_t>((record.IoctlCode >> 16) & 0xFFFF);
        const uint32_t method =
            static_cast<uint32_t>(record.IoctlCode & 0x3);
        EmitUnique(
            L"driver.ioctl",
            L"driver_ioctl:" + std::to_wstring(record.ProcessId) + L":" +
                HexU64(record.IoctlCode),
            driverName,
            L"iotrace",
            L"IOCTL to " + (driverName.empty() ? L"<target>" : driverName) +
                L" pid=" + std::to_wstring(record.ProcessId),
            L"ctl=" + HexU64(record.IoctlCode) +
                L" function=" + HexU64(function) +
                L" device_type=" + HexU64(deviceType) +
                L" method=" + std::to_wstring(method) +
                L" in=" + std::to_wstring(record.InputLength) +
                L" out=" + std::to_wstring(record.OutputLength),
            record.ProcessId);
    }

    bool noteCap = false;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        if (!IotraceSeenCapNoted && IotraceSeen.size() >= kMaxSeenEntries)
        {
            IotraceSeenCapNoted = true;
            noteCap = true;
        }
    }
    if (noteCap)
    {
        EmitUnique(
            L"driver.ioctl",
            L"iotrace_cap:" + driverName,
            driverName,
            L"iotrace",
            L"iotrace first-seen table hit its cap; later distinct IOCTLs are not printed",
            L"cap=256; interposition keeps running",
            0);
    }
    if (dropped != 0)
    {
        EmitUnique(
            L"driver.ioctl",
            L"iotrace_dropped:" + driverName,
            driverName,
            L"iotrace",
            L"iotrace ring dropped records; drain more often",
            L"dropped=" + std::to_wstring(dropped),
            0);
    }
}

// First-seen-per-task throttle for the loader.activity trail: true when
// pid is watched and this TI task name has not been recorded yet.
bool KernelMonitor::NoteWatchActivityTask(uint32_t pid, const std::wstring& task)
{
    bool record = false;

    do
    {
        if (pid <= 4 || task.empty())
        {
            break;
        }
        std::lock_guard<std::mutex> lock(WatchMutex);
        if (WatchPids.count(pid) == 0)
        {
            break;
        }
        std::unordered_set<std::wstring>& seen = WatchActivityTasks[pid];
        if (seen.size() >= 64)
        {
            break;
        }
        record = seen.insert(task).second;
    } while (false);

    return record;
}

void KernelMonitor::PruneStalePromotedWatches()
{
    std::vector<std::wstring> names;
    std::unordered_set<uint32_t> promoted;
    std::vector<uint32_t> childPids;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        names = WatchNamesLower;
        promoted = WatchPromotedPids;
        childPids.reserve(WatchChildPids.size());
        for (const auto& entry : WatchChildPids)
        {
            childPids.push_back(entry.first);
        }
    }
    bool prunePromoted = false;
    std::unordered_set<uint32_t> liveSet;
    if (!promoted.empty())
    {
        bool hasWildcard = false;
        for (const std::wstring& name : names)
        {
            if (WatchTokenIsWildcard(name))
            {
                hasWildcard = true;
                break;
            }
        }

        if (hasWildcard)
        {
            // /name * promotes every create. Keep promoted PIDs that are still
            // alive instead of re-enumerating the whole system.
            for (uint32_t pid : promoted)
            {
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (process != nullptr)
                {
                    liveSet.insert(pid);
                    CloseHandle(process);
                    continue;
                }
                if (GetLastError() != ERROR_INVALID_PARAMETER)
                {
                    liveSet.insert(pid);
                }
            }
            prunePromoted = true;
        }
        else
        {
            std::vector<uint32_t> live;
            if (CollectToolhelpPidsByName(names, &live))
            {
                liveSet.insert(live.begin(), live.end());
                prunePromoted = true;
            }
            else
            {
                for (uint32_t pid : promoted)
                {
                    HANDLE process = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE,
                        pid);
                    if (process != nullptr)
                    {
                        liveSet.insert(pid);
                        CloseHandle(process);
                        continue;
                    }
                    if (GetLastError() != ERROR_INVALID_PARAMETER)
                    {
                        liveSet.insert(pid);
                    }
                }
                prunePromoted = true;
            }
        }
    }

    // Children carry a different image name than the watch, so name
    // re-enumeration would drop them. Keep them on the wildcard-style
    // liveness rule (the create-time pin below still applies).
    for (uint32_t pid : childPids)
    {
        if (liveSet.count(pid) != 0)
        {
            continue;
        }
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process != nullptr)
        {
            liveSet.insert(pid);
            CloseHandle(process);
            continue;
        }
        if (GetLastError() != ERROR_INVALID_PARAMETER)
        {
            liveSet.insert(pid);
        }
    }

    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> stateLock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    std::unordered_map<uint32_t, uint64_t> promotedCreated;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        promotedCreated = WatchPromotedCreated;
    }
    for (uint32_t pid : promoted)
    {
        if (liveSet.count(pid) == 0)
        {
            continue;
        }
        auto createdIt = promotedCreated.find(pid);
        if (createdIt == promotedCreated.end() || createdIt->second == 0)
        {
            continue;
        }
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        const uint64_t created = QueryPidCreateTime(device, symbols, process, pid);
        if (process != nullptr)
        {
            CloseHandle(process);
        }
        if (created != 0 && created != createdIt->second)
        {
            liveSet.erase(pid);
        }
    }

    std::vector<uint32_t> logging;
    std::vector<uint32_t> droppedWatch;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        if (prunePromoted)
        {
            for (uint32_t pid : promoted)
            {
                if (liveSet.count(pid) != 0)
                {
                    continue;
                }
                if (WatchPromotedPids.erase(pid) == 0)
                {
                    continue;
                }
                WatchPromotedCreated.erase(pid);
                WatchChildPids.erase(pid);
                WatchActivityTasks.erase(pid);
                WatchKnownHandles.erase(pid);
                if (WatchExplicitPids.count(pid) == 0)
                {
                    WatchPids.erase(pid);
                    droppedWatch.push_back(pid);
                    if (LoggingEnabledPids.erase(pid) != 0 &&
                        LoggingEnabledCount.load() > 0)
                    {
                        LoggingEnabledCount.fetch_sub(1);
                    }
                    LoggingFailedPids.erase(pid);
                }
            }
        }
        std::unordered_set<uint32_t> ids;
        ids.reserve(LoggingEnabledPids.size() + LoggingFailedPids.size());
        for (const auto& entry : LoggingEnabledPids)
        {
            ids.insert(entry.first);
        }
        for (const auto& entry : LoggingFailedPids)
        {
            ids.insert(entry.first);
        }
        logging.assign(ids.begin(), ids.end());
    }

    for (uint32_t pid : droppedWatch)
    {
        DisableProcessLogging(device, pid);
    }

    for (uint32_t pid : logging)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        const DWORD openError = (process == nullptr) ? GetLastError() : ERROR_SUCCESS;
        const uint64_t created = QueryPidCreateTime(device, symbols, process, pid);
        if (process != nullptr)
        {
            CloseHandle(process);
        }

        std::lock_guard<std::mutex> lock(WatchMutex);
        auto it = LoggingEnabledPids.find(pid);
        if (it != LoggingEnabledPids.end())
        {
            if (created != 0)
            {
                if (it->second != 0 && created != it->second)
                {
                    LoggingEnabledPids.erase(it);
                    if (LoggingEnabledCount.load() > 0)
                    {
                        LoggingEnabledCount.fetch_sub(1);
                    }
                }
            }
            else if (process == nullptr && openError == ERROR_INVALID_PARAMETER)
            {
                LoggingEnabledPids.erase(it);
                if (LoggingEnabledCount.load() > 0)
                {
                    LoggingEnabledCount.fetch_sub(1);
                }
            }
        }
        auto failedIt = LoggingFailedPids.find(pid);
        if (failedIt == LoggingFailedPids.end())
        {
            continue;
        }
        if (created != 0)
        {
            if (failedIt->second != 0 && created != failedIt->second)
            {
                LoggingFailedPids.erase(failedIt);
            }
            continue;
        }
        if (process != nullptr || openError != ERROR_INVALID_PARAMETER)
        {
            continue;
        }
        LoggingFailedPids.erase(failedIt);
    }
}

void KernelMonitor::PromoteNamedWatchPid(uint32_t pid)
{
    if (pid <= 4)
    {
        return;
    }
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> stateLock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    const uint64_t created = QueryPidCreateTime(device, symbols, process, pid);
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        WatchPids.insert(pid);
        WatchPromotedPids.insert(pid);
        if (created != 0)
        {
            WatchPromotedCreated[pid] = created;
        }
    }
    EnableLoggingForPid(pid);
}

void KernelMonitor::EnableLoggingForWatchTargets()
{
    if (!Active.load() || StopRequested.load())
    {
        return;
    }

    std::vector<uint32_t> pids;
    std::vector<std::wstring> names;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        pids.assign(WatchPids.begin(), WatchPids.end());
        names = WatchNamesLower;
    }

    std::vector<uint32_t> namedPids;
    if (!names.empty() && !CollectToolhelpPidsByName(names, &namedPids))
    {
        namedPids.clear();
        EmitUnique(
            L"process.implant",
            L"scan_failed:userhostility:watchenum",
            std::wstring(),
            L"user",
            L"watch-name process enumeration failed; newly started watches may lack logging",
            L"CollectToolhelpPidsByName returned false");
    }
    else
    {
        ClearEmittedKey(L"scan_failed:userhostility:watchenum");
    }
    for (uint32_t pid : namedPids)
    {
        PromoteNamedWatchPid(pid);
    }

    for (uint32_t pid : pids)
    {
        EnableLoggingForPid(pid);
    }
}

bool KernelMonitor::ResolveKernelImageName(uint32_t pid, std::wstring* name)
{
    bool ok = false;

    do
    {
        if (name == nullptr)
        {
            break;
        }
        name->clear();

        DeviceClient* device = nullptr;
        SymbolEngine* symbols = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
            symbols = Symbols;
        }
        if (device == nullptr || symbols == nullptr || !device->IsOpen())
        {
            break;
        }

        if (symbols->CopyModules().empty())
        {
            std::wstring ignored;
            if (!symbols->LoadKernelModules(&ignored))
            {
                break;
            }
        }

        TypeFieldInfo dtbField = {};
        TypeFieldInfo imageField = {};
        std::wstring ignored;
        if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
        {
            break;
        }
        if (!symbols->FindField(L"nt!_EPROCESS", L"ImageFileName", &imageField, &ignored))
        {
            break;
        }

        ProcessAddressContext ctx = {};
        if (!device->ResolveProcess(pid, dtbField.Offset, 0, &ctx, &ignored) || ctx.Eprocess == 0)
        {
            break;
        }

        if (imageField.Offset > (std::numeric_limits<uint64_t>::max)() - ctx.Eprocess)
        {
            break;
        }
        uint64_t fieldAddr = ctx.Eprocess + static_cast<uint64_t>(imageField.Offset);
        uint32_t length = 16;
        if (imageField.Length != 0 && imageField.Length <= 16)
        {
            length = static_cast<uint32_t>(imageField.Length);
        }
        std::vector<uint8_t> bytes;
        if (!device->ReadMemory(fieldAddr, length, &bytes, &ignored) || bytes.empty())
        {
            break;
        }

        std::wstring decoded;
        for (uint8_t byte : bytes)
        {
            if (byte == 0)
            {
                break;
            }
            if (byte >= 0x20 && byte < 0x7f)
            {
                decoded.push_back(static_cast<wchar_t>(byte));
            }
        }
        *name = decoded;
        ok = !decoded.empty();
    } while (false);

    return ok;
}

void KernelMonitor::RecordEvent(KmonEvent&& event)
{
    NoteWatchTiWriteIfNeeded(event);

    KmonOptions options;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        options = Options;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            options.WatchPids.assign(WatchPids.begin(), WatchPids.end());
            options.WatchNames = WatchNamesLower;
            options.WatchDrivers = WatchDriversLower;
        }
    }

    if (!KmonWatchMatches(event, options))
    {
        return;
    }

    EventsWatchMatched.fetch_add(1);
    LastEventTickMs.store(GetTickCount64());

    if (event.Evidence.find(L"watch_id") == event.Evidence.end() &&
        IsMapperWatchActive())
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        if (!MapperWatchId.empty())
        {
            event.Evidence[L"watch_id"] = MapperWatchId;
        }
    }

    {
        std::lock_guard<std::mutex> ringLock(RingMutex);
        if (event.Sequence == 0)
        {
            event.Sequence = NextSequence++;
            if (NextSequence == 0)
            {
                NextSequence = 1;
            }
        }
        if (Ring.size() >= options.RingCapacity)
        {
            Ring.pop_front();
            EventsDropped.fetch_add(1);
        }
        Ring.push_back(event);
        EventsKept.fetch_add(1);
    }

    WriteLogLine(event);

    if (LiveOutput.load())
    {
        EnqueuePrint(std::move(event));
    }
}

bool KernelMonitor::WriteLogLine(const KmonEvent& event)
{
    bool ok = false;

    do
    {
        std::string utf8 = WideToUtf8(FormatKmonJsonLine(event));
        if (utf8.empty())
        {
            break;
        }
        std::lock_guard<std::mutex> logLock(LogMutex);
        if (LogHandle == INVALID_HANDLE_VALUE &&
            (!Active.load() || StopRequested.load()))
        {
            break;
        }
        if (!EnsureLogOpenLocked())
        {
            break;
        }
        if (LogCurrentBytes + utf8.size() >= LogRotateBytes)
        {
            RotateLogLocked();
            if (!EnsureLogOpenLocked())
            {
                break;
            }
        }

        if (utf8.size() > (std::numeric_limits<DWORD>::max)())
        {
            break;
        }
        DWORD written = 0;
        if (!WriteFile(
                LogHandle,
                utf8.data(),
                static_cast<DWORD>(utf8.size()),
                &written,
                nullptr) ||
            written != utf8.size())
        {
            break;
        }
        LogCurrentBytes += written;
        LogBytesWritten.fetch_add(written);
        EventsLogged.fetch_add(1);
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::EnqueuePrint(KmonEvent&& event)
{
    const uint32_t throttle = Options.ThrottlePerSecond;
    const uint64_t nowMs = GetTickCount64();
    const uint64_t windowStart = ThrottleWindowStartMs.load();
    if (windowStart == 0 || (nowMs - windowStart) >= 1000)
    {
        ThrottleWindowStartMs.store(nowMs);
        ThrottleWindowCount.store(0);
    }
    uint32_t inWindow = ThrottleWindowCount.fetch_add(1) + 1;
    if (inWindow > throttle)
    {
        ThrottleSuppressed.fetch_add(1);
        return;
    }

    std::lock_guard<std::mutex> printLock(PrintMutex);
    while (PrintQueue.size() >= kPrintQueueCap)
    {
        PrintQueue.pop_front();
        ThrottleSuppressed.fetch_add(1);
    }
    PrintQueue.push_back(std::move(event));
}

std::vector<KmonEvent> KernelMonitor::DrainPrintQueue(size_t maxCount)
{
    std::vector<KmonEvent> out;
    std::lock_guard<std::mutex> printLock(PrintMutex);
    while (!PrintQueue.empty() && (maxCount == 0 || out.size() < maxCount))
    {
        out.push_back(std::move(PrintQueue.front()));
        PrintQueue.pop_front();
    }
    return out;
}

uint64_t KernelMonitor::ConsumeThrottleSuppressedCount()
{
    return ThrottleSuppressed.exchange(0);
}

std::vector<KmonEvent> KernelMonitor::Recent(size_t maxCount, bool newestFirst) const
{
    std::vector<KmonEvent> out;
    std::lock_guard<std::mutex> lock(RingMutex);
    if (Ring.empty())
    {
        return out;
    }
    size_t total = (maxCount == 0 || maxCount > Ring.size()) ? Ring.size() : maxCount;
    if (newestFirst)
    {
        out.reserve(total);
        for (size_t i = 0; i < total; ++i)
        {
            out.push_back(Ring[Ring.size() - 1 - i]);
        }
    }
    else
    {
        size_t start = Ring.size() - total;
        out.reserve(total);
        for (size_t i = start; i < Ring.size(); ++i)
        {
            out.push_back(Ring[i]);
        }
    }
    return out;
}

bool KernelMonitor::SaveTo(const std::wstring& path, std::wstring* error) const
{
    bool ok = false;

    do
    {
        HANDLE handle = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"could not open output file";
            }
            break;
        }

        std::vector<KmonEvent> snapshot;
        {
            std::lock_guard<std::mutex> lock(RingMutex);
            snapshot.assign(Ring.begin(), Ring.end());
        }

        bool writeOk = true;
        for (const KmonEvent& event : snapshot)
        {
            std::string utf8 = WideToUtf8(FormatKmonJsonLine(event));
            if (utf8.empty() || utf8.size() > (std::numeric_limits<DWORD>::max)())
            {
                writeOk = false;
                break;
            }
            DWORD written = 0;
            if (!WriteFile(
                    handle,
                    utf8.data(),
                    static_cast<DWORD>(utf8.size()),
                    &written,
                    nullptr) ||
                written != utf8.size())
            {
                writeOk = false;
                break;
            }
        }
        CloseHandle(handle);
        if (!writeOk)
        {
            if (error != nullptr)
            {
                *error = L"write failed";
            }
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::Clear()
{
    {
        std::lock_guard<std::mutex> lock(RingMutex);
        Ring.clear();
    }
    {
        std::lock_guard<std::mutex> printLock(PrintMutex);
        PrintQueue.clear();
    }
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        EmittedMapperKeys.clear();
        EmittedUnnamedPids.clear();
        RecentLoads.clear();
        MapperWatchLast = MapperWatchFingerprint{};
        MapperWatchDriver.clear();
        MapperWatchId.clear();
        MapperWatchEmitTick.clear();
        MapperWatchHasResidue = false;
        MapperWatchHasOverlaySlot = false;
        MapperWatchTiWritePids.clear();
        MapperWatchResiduePfns.clear();
    }
    MapperWatchUntilMs.store(0);
    MapperWatchOriginMs.store(0);
    MapperWatchDeepPfnPending.store(false);
}

bool KernelMonitor::AddWatchPid(uint32_t pid)
{
    bool inserted = false;

    do
    {
        if (pid == 0)
        {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            WatchExplicitPids.insert(pid);
            inserted = WatchPids.insert(pid).second;
        }
        EnableLoggingForPid(pid);
    } while (false);

    return inserted;
}

bool KernelMonitor::RemoveWatchPid(uint32_t pid)
{
    bool removed = false;
    bool wasLogging = false;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        WatchExplicitPids.erase(pid);
        WatchPromotedPids.erase(pid);
        WatchPromotedCreated.erase(pid);
        WatchChildPids.erase(pid);
        WatchActivityTasks.erase(pid);
        removed = WatchPids.erase(pid) != 0;
        wasLogging = LoggingEnabledPids.erase(pid) != 0;
        LoggingFailedPids.erase(pid);
        if (wasLogging && LoggingEnabledCount.load() > 0)
        {
            LoggingEnabledCount.fetch_sub(1);
        }
    }
    if (wasLogging)
    {
        DeviceClient* device = nullptr;
        {
            std::lock_guard<std::mutex> stateLock(StateMutex);
            device = Device;
        }
        DisableProcessLogging(device, pid);
    }
    return removed;
}

bool KernelMonitor::AddWatchName(const std::wstring& imageBase)
{
    bool added = false;
    std::vector<uint32_t> pids;

    do
    {
        std::wstring lower = KmonBasenameLower(imageBase);
        if (lower.empty())
        {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            bool exists = false;
            for (const std::wstring& existing : WatchNamesLower)
            {
                if (existing == lower)
                {
                    exists = true;
                    break;
                }
            }
            if (exists)
            {
                break;
            }
            WatchNamesLower.push_back(lower);
            added = true;
        }
        CollectToolhelpPidsByName({ lower }, &pids);
        for (uint32_t pid : pids)
        {
            PromoteNamedWatchPid(pid);
        }
    } while (false);

    return added;
}

bool KernelMonitor::RemoveWatchName(const std::wstring& imageBase)
{
    std::wstring lower = KmonBasenameLower(imageBase);
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        auto it = std::remove(WatchNamesLower.begin(), WatchNamesLower.end(), lower);
        if (it == WatchNamesLower.end())
        {
            return false;
        }
        WatchNamesLower.erase(it, WatchNamesLower.end());
        removed = true;
    }
    PruneStalePromotedWatches();
    return removed;
}

bool KernelMonitor::AddWatchDriver(const std::wstring& driverBase)
{
    std::wstring lower = KmonBasenameLower(driverBase);
    if (lower.empty())
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    for (const std::wstring& existing : WatchDriversLower)
    {
        if (existing == lower)
        {
            return false;
        }
    }
    WatchDriversLower.push_back(lower);
    return true;
}

bool KernelMonitor::RemoveWatchDriver(const std::wstring& driverBase)
{
    std::wstring lower = KmonBasenameLower(driverBase);
    std::lock_guard<std::mutex> lock(WatchMutex);
    auto it = std::remove(WatchDriversLower.begin(), WatchDriversLower.end(), lower);
    if (it == WatchDriversLower.end())
    {
        return false;
    }
    WatchDriversLower.erase(it, WatchDriversLower.end());
    return true;
}

bool KernelMonitor::EnsureLogOpenLocked()
{
    bool ok = false;

    do
    {
        if (LogHandle != INVALID_HANDLE_VALUE)
        {
            ok = true;
            break;
        }

        CreateDirectoryW(Options.LogDirectory.c_str(), nullptr);
        LogActivePath = BuildLogFilePath(LogActiveRotation);
        LogHandle = CreateFileW(
            LogActivePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (LogHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }
        LogCurrentBytes = 0;
        LARGE_INTEGER size = {};
        if (GetFileSizeEx(LogHandle, &size) && size.QuadPart > 0)
        {
            LogCurrentBytes = static_cast<uint64_t>(size.QuadPart);
        }
        LARGE_INTEGER zero = {};
        if (!SetFilePointerEx(LogHandle, zero, nullptr, FILE_END))
        {
            CloseHandle(LogHandle);
            LogHandle = INVALID_HANDLE_VALUE;
            LogCurrentBytes = 0;
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::CloseLogLocked()
{
    if (LogHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(LogHandle);
        LogHandle = INVALID_HANDLE_VALUE;
    }
    LogCurrentBytes = 0;
}

void KernelMonitor::RotateLogLocked()
{
    CloseLogLocked();
    LogActiveRotation = (LogActiveRotation + 1) % static_cast<int>(LogRotateCount);
    LogCurrentBytes = 0;
    std::wstring next = BuildLogFilePath(LogActiveRotation);
    DeleteFileW(next.c_str());
    LogRotations.fetch_add(1);
}

std::wstring KernelMonitor::BuildLogFilePath(int rotationIndex) const
{
    return Options.LogDirectory + L"\\kmon-events." +
        std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(rotationIndex) + L".jsonl";
}

bool KernelMonitorArtifactSelfTest()
{
    bool ok = false;
    HANDLE childProc = nullptr;
    do
    {
        HMODULE self = GetModuleHandleW(nullptr);
        if (self == nullptr)
        {
            break;
        }
        uint8_t* base = reinterpret_cast<uint8_t*>(self);
        IMAGE_DOS_HEADER dos = {};
        std::memcpy(&dos, base, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos.e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }
        uint32_t execRva = 0x1000;
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            {
                execRva = section[i].VirtualAddress;
                break;
            }
        }

        const uint32_t pid = GetCurrentProcessId();
        HANDLE selfHandle = GetCurrentProcess();
        uint8_t* text = base + execRva;
        uint8_t saved[32] = {};
        std::memcpy(saved, text, sizeof(saved));
        uint8_t patch[32];
        std::memset(patch, 0x90, sizeof(patch));
        DWORD oldProtect = 0;
        if (!VirtualProtect(text, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            break;
        }
        std::memcpy(text, patch, sizeof(patch));
        FlushInstructionCache(GetCurrentProcess(), text, sizeof(patch));
        uint32_t rvas[1] = { execRva };
        uint32_t privatePages = 0;
        uint32_t validPages = 0;
        const bool cow = CountPrivateCowImagePages(
            selfHandle,
            nullptr,
            nullptr,
            pid,
            reinterpret_cast<uint64_t>(self),
            rvas,
            1,
            &privatePages,
            &validPages);
        std::memcpy(text, saved, sizeof(saved));
        FlushInstructionCache(GetCurrentProcess(), text, sizeof(saved));
        DWORD ignoredProtect = 0;
        VirtualProtect(text, sizeof(patch), oldProtect, &ignoredProtect);
        if (!cow || validPages == 0 || privatePages == 0)
        {
            break;
        }

        void* orphan = VirtualAlloc(
            nullptr,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (orphan == nullptr)
        {
            break;
        }
        uint8_t* orphanBytes = static_cast<uint8_t*>(orphan);
        orphanBytes[0] = 'M';
        orphanBytes[1] = 'Z';
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(orphan, &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.Type != MEM_PRIVATE)
        {
            VirtualFree(orphan, 0, MEM_RELEASE);
            break;
        }
        VirtualFree(orphan, 0, MEM_RELEASE);

        std::wstring mapped;
        if (!QueryMappedImagePath(
                selfHandle,
                reinterpret_cast<uint64_t>(self),
                &mapped) ||
            mapped.empty())
        {
            break;
        }

        std::wstring fixture = ExeDirectory() + L"\\tools\\KnLiveDbgKmonTarget.exe";
        if (GetFileAttributesW(fixture.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            fixture = ExeDirectory() + L"\\KnLiveDbgKmonTarget.exe";
        }
        if (GetFileAttributesW(fixture.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            uint32_t childExecRva = 0x1000;
            std::vector<uint8_t> fixtureHead;
            KmonPeLayout fixtureLayout = {};
            if (ReadDiskPeHead(fixture, &fixtureHead) &&
                ParseKmonPeLayout(fixtureHead, &fixtureLayout) &&
                fixtureLayout.ExecRva != 0)
            {
                childExecRva = fixtureLayout.ExecRva;
            }

            STARTUPINFOW si = {};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::wstring cmd = L"\"" + fixture + L"\" /child overwrite /seconds 8";
            std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
            cmdBuf.push_back(0);
            if (CreateProcessW(
                    fixture.c_str(),
                    cmdBuf.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &si,
                    &pi))
            {
                childProc = pi.hProcess;
                CloseHandle(pi.hThread);
                HANDLE inspect = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE,
                    pi.dwProcessId);
                if (inspect == nullptr)
                {
                    inspect = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        FALSE,
                        pi.dwProcessId);
                }
                if (inspect == nullptr)
                {
                    break;
                }
                uint64_t childBase = 0;
                QueryPebImageBase(inspect, nullptr, nullptr, pi.dwProcessId, &childBase);
                uint32_t childRva[1] = { childExecRva };
                uint32_t childPriv = 0;
                uint32_t childValid = 0;
                if (childBase != 0)
                {
                    for (int poll = 0; poll < 50; ++poll)
                    {
                        childPriv = 0;
                        childValid = 0;
                        CountPrivateCowImagePages(
                            inspect,
                            nullptr,
                            nullptr,
                            pi.dwProcessId,
                            childBase,
                            childRva,
                            1,
                            &childPriv,
                            &childValid);
                        if (childPriv > 0)
                        {
                            break;
                        }
                        if (WaitForSingleObject(childProc, 0) == WAIT_OBJECT_0)
                        {
                            break;
                        }
                        Sleep(100);
                    }
                }
                CloseHandle(inspect);
                // Working-set query can miss on a just-spawned child. Fail
                // when pages were visible and still shared after patch.
                if (childValid > 0 && childPriv == 0)
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }

        ok = true;
    } while (false);
    if (childProc != nullptr)
    {
        TerminateProcess(childProc, 0);
        WaitForSingleObject(childProc, 5000);
        CloseHandle(childProc);
    }
    return ok;
}

bool KernelMonitorSelfTest()
{
    bool ok = false;

    do
    {
        if (KmonBasenameLower(L"C:\\Windows\\cheat.SYS") != L"cheat.sys")
        {
            break;
        }
        if (!AddressOwnedByLoadedModule(nullptr, 0xFFFFF80000000000ull))
        {
            break;
        }
        if (KmonExeRegionLooksPrivate(false, true, 0, false) ||
            KmonExeRegionLooksPrivate(false, true, MEM_PRIVATE, false) ||
            !KmonExeRegionLooksPrivate(true, true, MEM_PRIVATE, false) ||
            KmonExeRegionLooksPrivate(true, true, MEM_IMAGE, false) ||
            !KmonExeRegionLooksPrivate(false, true, 0, true) ||
            !KmonProtectIsRwx(PAGE_EXECUTE_READWRITE) ||
            KmonProtectIsRwx(PAGE_EXECUTE_READ))
        {
            break;
        }
        MEMORY_BASIC_INFORMATION orphanRegion = {};
        orphanRegion.State = MEM_COMMIT;
        orphanRegion.RegionSize = 0x2000;
        orphanRegion.AllocationBase =
            reinterpret_cast<PVOID>(0x7ff000010000ull);
        orphanRegion.Type = MEM_IMAGE;
        orphanRegion.Protect = PAGE_READONLY;
        const std::vector<std::pair<uint64_t, uint32_t>> emptyRanges;
        const uint64_t otherImage = 0x7ff000000000ull;
        // LOAD_LIBRARY_AS_IMAGE_RESOURCE views are read-only orphan MEM_IMAGE
        // regions and must not reach the orphan MZ probe any more.
        if (KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        // Unlinked images keep firing through their RX text sub-region.
        orphanRegion.Protect = PAGE_EXECUTE_READ;
        if (!KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        // Manually mapped RWX image allocations keep firing.
        orphanRegion.Type = MEM_PRIVATE;
        orphanRegion.Protect = PAGE_EXECUTE_READWRITE;
        if (!KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        // Module-listed bases and the main EXE allocation never fire.
        std::vector<std::pair<uint64_t, uint32_t>> listedRanges;
        listedRanges.emplace_back(0x7ff000010000ull, 0x10000);
        if (KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                listedRanges) ||
            KmonOrphanRegionInteresting(
                orphanRegion,
                reinterpret_cast<uint64_t>(orphanRegion.AllocationBase),
                emptyRanges))
        {
            break;
        }
        // Reserved, tiny, or unbased regions never fire.
        orphanRegion.State = MEM_RESERVE;
        if (KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        orphanRegion.State = MEM_COMMIT;
        orphanRegion.RegionSize = 0xfff;
        if (KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        orphanRegion.RegionSize = 0x2000;
        orphanRegion.AllocationBase = nullptr;
        if (KmonOrphanRegionInteresting(
                orphanRegion,
                otherImage,
                emptyRanges))
        {
            break;
        }
        ProcessVadRecord cover = {};
        cover.StartAddress = 0x140000000ull;
        cover.EndAddress = 0x140001fffull;
        if (!VadCoversUserAddress(cover, 0x140000000ull) ||
            !VadCoversUserAddress(cover, 0x140001fffull) ||
            VadCoversUserAddress(cover, 0x140002000ull) ||
            VadCoversUserAddress(cover, 0))
        {
            break;
        }
        {
            // Device-path conversion: pass-through for non-device paths,
            // GLOBALROOT fallback for unknown devices, and a real DOS
            // device round-trip when the host has one.
            if (KmonDevicePathToWin32(L"c:\\game\\x.dll") != L"c:\\game\\x.dll")
            {
                break;
            }
            if (KmonDevicePathToWin32(L"\\Device\\KnDbgNoVolume\\x.dll") !=
                L"\\\\?\\GLOBALROOT\\Device\\KnDbgNoVolume\\x.dll")
            {
                break;
            }
            wchar_t dosTarget[512] = {};
            bool mappedRoundTrip = false;
            const DWORD driveLen = GetLogicalDriveStringsW(0, nullptr);
            if (driveLen > 0 && driveLen < 1024)
            {
                std::vector<wchar_t> drives(
                    static_cast<size_t>(driveLen) + 1, L'\0');
                if (GetLogicalDriveStringsW(
                        driveLen,
                        drives.data()) > 0)
                {
                    const wchar_t* cursor = drives.data();
                    while (*cursor != L'\0')
                    {
                        const std::wstring drive(cursor);
                        if (drive.size() >= 2 &&
                            QueryDosDeviceW(
                                drive.substr(0, 2).c_str(),
                                dosTarget,
                                ARRAYSIZE(dosTarget) - 1) > 0 &&
                            dosTarget[0] == L'\\')
                        {
                            const std::wstring built =
                                std::wstring(dosTarget) + L"\\KnDbg\\a.dll";
                            const std::wstring converted =
                                KmonDevicePathToWin32(built);
                            if (converted !=
                                drive.substr(0, 2) + L"\\KnDbg\\a.dll")
                            {
                                break;
                            }
                            // A device whose name extends the target with a
                            // digit (HarddiskVolume30 under a drive mapped
                            // to HarddiskVolume3) must not fold onto that
                            // drive with the digit eaten.
                            const std::wstring boundaryBuilt =
                                std::wstring(dosTarget) + L"0\\KnDbg\\b.dll";
                            if (KmonDevicePathToWin32(boundaryBuilt) ==
                                drive.substr(0, 2) + L"0\\KnDbg\\b.dll")
                            {
                                break;
                            }
                            mappedRoundTrip = true;
                            break;
                        }
                        cursor += drive.size() + 1;
                    }
                }
            }
            if (!mappedRoundTrip)
            {
                break;
            }
        }
        {
            // Kernel VAD code-target validation used when VirtualQueryEx
            // is unavailable.
            ProcessVadRecord shellcode = {};
            shellcode.StartAddress = 0x140000000ull;
            shellcode.EndAddress = 0x140000fffull;
            shellcode.Executable = true;
            shellcode.HasPrivateMemory = true;
            shellcode.PrivateMemory = true;
            shellcode.CommitCharge = 4;
            if (!KmonVadRecordLooksLikeCodeTarget(shellcode))
            {
                break;
            }
            shellcode.CommitCharge = 0;
            if (KmonVadRecordLooksLikeCodeTarget(shellcode))
            {
                break;
            }
            ProcessVadRecord dataMap = {};
            dataMap.StartAddress = 0x140100000ull;
            dataMap.EndAddress = 0x140100fffull;
            dataMap.Executable = true;
            dataMap.HasSubsection = true;
            if (!KmonVadRecordLooksLikeCodeTarget(dataMap))
            {
                break;
            }
            dataMap.SectionFileName = L"\\Device\\HarddiskVolume3\\game\\a.dll";
            if (KmonVadRecordLooksLikeCodeTarget(dataMap))
            {
                break;
            }
            dataMap.SectionFileName.clear();
            dataMap.Executable = false;
            if (KmonVadRecordLooksLikeCodeTarget(dataMap))
            {
                break;
            }
            shellcode.CommitCharge = 4;
            dataMap.Executable = true;
            const std::vector<ProcessVadRecord> vadList = { shellcode, dataMap };
            if (KmonFindCoveringVadRecord(&vadList, 0x140000000ull) == nullptr)
            {
                break;
            }
            if (KmonFindCoveringVadRecord(
                    &vadList,
                    0x150000000ull) != nullptr ||
                KmonFindCoveringVadRecord(nullptr, 0x140000000ull) != nullptr)
            {
                break;
            }
        }
        bool wow64Unknown = true;
        if (QueryProcessIsWow64(nullptr, nullptr, nullptr, 0, &wow64Unknown) ||
            wow64Unknown ||
            QueryProcessIsWow64(nullptr, nullptr, nullptr, 8, &wow64Unknown))
        {
            break;
        }
        if (QueryEprocessCreateTime(nullptr, nullptr, nullptr, 0) != 0)
        {
            break;
        }
        if (QueryPidCreateTime(nullptr, nullptr, nullptr, 0) != 0)
        {
            break;
        }
        if (!KmonPathLooksLikeSys(L"\\SystemRoot\\cheat.sys"))
        {
            break;
        }
        if (!KmonTaskLooksLikeDriverObjectLoad(L"KERNEL_THREATINT_TASK_DRIVEROBJECTLOAD"))
        {
            break;
        }
        if (!KmonTaskLooksLikeRemoteInject(L"WriteVM") ||
            KmonTaskLooksLikeRemoteInject(L"ReadVM") ||
            KmonTaskLooksLikeRemoteInject(L"Suspend") ||
            KmonTaskLooksLikeRemoteInject(L"Resume"))
        {
            break;
        }

        TiEventRecord driver = {};
        driver.ProcessId = 4;
        driver.TaskName = L"DriverObjectLoad";
        driver.ImagePath = L"System";
        TiPayloadField field = {};
        field.Name = L"DriverName";
        field.Value = L"\\??\\C:\\cheat.sys";
        driver.Payload.push_back(field);
        KmonEvent classified = {};
        if (!KmonClassifyTiEvent(driver, &classified) ||
            classified.Kind != L"driver.drop_load" ||
            KmonBasenameLower(classified.Driver) != L"cheat.sys" ||
            classified.Evidence[L"path_class"] != L"drop")
        {
            break;
        }

        if (KmonClassifyDriverPath(L"C:\\Windows\\System32\\drivers\\acpi.sys") != L"inbox" ||
            KmonClassifyDriverPath(L"C:\\Users\\a\\AppData\\Local\\Temp\\x.sys") != L"drop" ||
            KmonClassifyDriverPath(L"C:\\Windows\\cheat.sys") != L"drop" ||
            KmonClassifyDriverPath(L"C:\\Windows\\System32\\win32k.sys") != L"inbox" ||
            KmonClassifyDriverPath(L"C:\\Windows\\Temp\\x.sys") != L"drop")
        {
            break;
        }

        TiEventRecord unnamedLoad = {};
        unnamedLoad.ProcessId = 4;
        unnamedLoad.TaskName = L"DriverObjectLoad";
        unnamedLoad.ImagePath = L"System";
        if (!KmonClassifyTiEvent(unnamedLoad, &classified) ||
            classified.Kind != L"driver.official_load")
        {
            break;
        }
        KmonOptions emptyWatchForUnnamed;
        if (KmonWatchMatches(classified, emptyWatchForUnnamed))
        {
            break;
        }

        TiEventRecord inject = {};
        inject.ProcessId = 1000;
        inject.TargetProcessId = 2000;
        inject.TaskName = L"WriteVM";
        inject.ImagePath = L"C:\\cheat.exe";
        inject.TargetImageBase = L"game.exe";
        if (!KmonClassifyTiEvent(inject, &classified) || classified.Kind != L"inject.remote")
        {
            break;
        }

        TiEventRecord localAlloc = {};
        localAlloc.ProcessId = 1000;
        localAlloc.TargetProcessId = 1000;
        localAlloc.TaskName = L"AllocVM";
        if (KmonClassifyTiEvent(localAlloc, &classified))
        {
            break;
        }

        TiEventRecord remoteRead = {};
        remoteRead.ProcessId = 1000;
        remoteRead.TargetProcessId = 2000;
        remoteRead.TaskName = L"ReadVM";
        remoteRead.ImagePath = L"C:\\Users\\a\\AppData\\Local\\Temp\\x.exe";
        remoteRead.TargetImageBase = L"game.exe";
        if (KmonClassifyTiEvent(remoteRead, &classified))
        {
            break;
        }

        TimelineEvent liveInbox = {};
        liveInbox.Action = L"image-load";
        liveInbox.ProcessId = 0;
        liveInbox.Entity = L"\\SystemRoot\\System32\\drivers\\mapped.sys";
        liveInbox.Source = L"kernel-live";
        liveInbox.Evidence[L"image_base"] = L"0xfffff80012340000";
        liveInbox.Evidence[L"image_size"] = L"0x0000000000012000";
        liveInbox.Evidence[L"system_mode"] = L"true";
        liveInbox.Evidence[L"signature_level"] = L"windows";
        if (!KmonClassifyLiveEvent(liveInbox, &classified) ||
            classified.Kind != L"driver.image_only" ||
            classified.Summary.find(L"inbox") == std::wstring::npos ||
            classified.Evidence[L"image_base"] != L"0xfffff80012340000" ||
            classified.Evidence[L"signature_level"] != L"windows" ||
            classified.Summary.find(L"base=0xfffff80012340000") == std::wstring::npos ||
            !KmonWatchMatches(classified, emptyWatchForUnnamed))
        {
            break;
        }

        TimelineEvent liveSystemModeUnnamed = {};
        liveSystemModeUnnamed.Action = L"image-load";
        liveSystemModeUnnamed.ProcessId = 0;
        liveSystemModeUnnamed.Entity = L"pid:0";
        liveSystemModeUnnamed.Source = L"kernel-live";
        liveSystemModeUnnamed.Evidence[L"system_mode"] = L"true";
        liveSystemModeUnnamed.Evidence[L"image_base"] = L"0xfffff80099990000";
        if (!KmonClassifyLiveEvent(liveSystemModeUnnamed, &classified) ||
            classified.Kind != L"driver.image_only" ||
            classified.Summary.find(L"unnamed") == std::wstring::npos ||
            !KmonWatchMatches(classified, emptyWatchForUnnamed))
        {
            break;
        }

        TimelineEvent liveBareSys = {};
        liveBareSys.Action = L"image-load";
        liveBareSys.ProcessId = 0;
        liveBareSys.Entity = L"cheat.sys";
        liveBareSys.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(liveBareSys, &classified) ||
            classified.Kind != L"driver.image_only" ||
            classified.Summary.find(L"inbox") != std::wstring::npos)
        {
            break;
        }

        TimelineEvent liveDrop = {};
        liveDrop.Action = L"image-load";
        liveDrop.ProcessId = 0;
        liveDrop.Entity = L"\\??\\C:\\Users\\a\\AppData\\Local\\Temp\\mapped.sys";
        liveDrop.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(liveDrop, &classified) || classified.Kind != L"driver.drop_load")
        {
            break;
        }

        TimelineEvent livePid4Drop = {};
        livePid4Drop.Action = L"image-load";
        livePid4Drop.ProcessId = 4;
        livePid4Drop.Entity = L"\\??\\C:\\Temp\\mapped.sys";
        livePid4Drop.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(livePid4Drop, &classified) || classified.Kind != L"driver.drop_load")
        {
            break;
        }

        TimelineEvent liveUserPidDrop = {};
        liveUserPidDrop.Action = L"image-load";
        liveUserPidDrop.ProcessId = 1234;
        liveUserPidDrop.Entity = L"C:\\Temp\\mapped.sys";
        liveUserPidDrop.Source = L"kernel-live";
        if (KmonClassifyLiveEvent(liveUserPidDrop, &classified))
        {
            break;
        }

        TimelineEvent liveUserPidSysSystemMode = liveUserPidDrop;
        liveUserPidSysSystemMode.Evidence[L"system_mode"] = L"true";
        if (!KmonClassifyLiveEvent(liveUserPidSysSystemMode, &classified) ||
            classified.Kind != L"driver.drop_load")
        {
            break;
        }

        TimelineEvent liveUserPidKernelVa = {};
        liveUserPidKernelVa.Action = L"image-load";
        liveUserPidKernelVa.ProcessId = 1234;
        liveUserPidKernelVa.Entity = L"\\SystemRoot\\System32\\drivers\\acpi.sys";
        liveUserPidKernelVa.Source = L"kernel-live";
        liveUserPidKernelVa.Evidence[L"image_base"] = L"0xfffff80012340000";
        liveUserPidKernelVa.Evidence[L"image_size"] = L"0x0000000000012000";
        liveUserPidKernelVa.Evidence[L"signature_level"] = L"windows";
        if (!KmonClassifyLiveEvent(liveUserPidKernelVa, &classified) ||
            classified.Kind != L"driver.image_only" ||
            classified.Summary.find(L"inbox") == std::wstring::npos ||
            classified.Summary.find(L"base=0xfffff80012340000") == std::wstring::npos ||
            classified.Summary.find(L"sig=windows") == std::wstring::npos ||
            !KmonWatchMatches(classified, emptyWatchForUnnamed))
        {
            break;
        }

        TimelineEvent liveUserDll = {};
        liveUserDll.Action = L"image-load";
        liveUserDll.ProcessId = 1234;
        liveUserDll.Entity = L"C:\\Windows\\System32\\ntdll.dll";
        liveUserDll.Source = L"kernel-live";
        liveUserDll.Evidence[L"image_base"] = L"0x00007ff812340000";
        if (KmonClassifyLiveEvent(liveUserDll, &classified))
        {
            break;
        }

        KmonOptions exeWatch;
        exeWatch.WatchNames.push_back(L"*.exe");
        KmonEvent createExe = {};
        createExe.Kind = L"process.create";
        createExe.Image = L"game.exe";
        if (!KmonWatchMatches(createExe, exeWatch))
        {
            break;
        }
        createExe.Image = L"cheat.sys";
        if (KmonWatchMatches(createExe, exeWatch))
        {
            break;
        }

        KmonEvent mappedLive = {};
        mappedLive.Kind = L"driver.mapped_residue";
        mappedLive.Evidence[L"layer"] = L"pool_pe";
        if (!KmonWatchMatches(mappedLive, emptyWatchForUnnamed))
        {
            break;
        }
        KmonEvent hookEvent = {};
        hookEvent.Kind = L"hook.unbacked";
        hookEvent.Evidence[L"layer"] = L"callback";
        if (!KmonWatchMatches(hookEvent, emptyWatchForUnnamed))
        {
            break;
        }
        KmonEvent ciEvent = {};
        ciEvent.Kind = L"integrity.ci";
        if (!KmonWatchMatches(ciEvent, emptyWatchForUnnamed))
        {
            break;
        }

        KmonOptions emptyWatch;
        KmonEvent injectEvent = classified;
        injectEvent.Kind = L"inject.remote";
        injectEvent.ProcessId = 1000;
        injectEvent.TargetProcessId = 2000;
        injectEvent.Image = L"cheat.exe";
        injectEvent.TargetImage = L"game.exe";
        injectEvent.Task = L"WriteVM";
        if (KmonWatchMatches(injectEvent, emptyWatch))
        {
            break;
        }

        KmonOptions gameWatch;
        gameWatch.WatchNames.push_back(L"game.exe");
        if (!KmonWatchMatches(injectEvent, gameWatch))
        {
            break;
        }
        KmonEvent gameRead = injectEvent;
        gameRead.Task = L"ReadVM";
        if (KmonWatchMatches(gameRead, gameWatch) ||
            KmonWatchMatches(gameRead, emptyWatch))
        {
            break;
        }
        KmonEvent dropRead = injectEvent;
        dropRead.Image = L"C:\\Users\\a\\AppData\\Local\\Temp\\x.exe";
        dropRead.Task = L"ReadVM";
        if (KmonWatchMatches(dropRead, emptyWatch) ||
            KmonWatchMatches(dropRead, gameWatch))
        {
            break;
        }

        KmonEvent builtinInject = injectEvent;
        builtinInject.TargetImage = L"svchost.exe";
        builtinInject.Task = L"WriteVM";
        if (!KmonWatchMatches(builtinInject, emptyWatch))
        {
            break;
        }
        KmonEvent builtinRead = builtinInject;
        builtinRead.Task = L"ReadVM";
        if (KmonWatchMatches(builtinRead, emptyWatch))
        {
            break;
        }
        KmonEvent builtinAlloc = builtinInject;
        builtinAlloc.Task = L"AllocVM";
        if (KmonWatchMatches(builtinAlloc, emptyWatch))
        {
            break;
        }
        KmonOptions svchostWatch;
        svchostWatch.WatchNames.push_back(L"svchost.exe");
        if (KmonWatchMatches(builtinRead, svchostWatch))
        {
            break;
        }
        if (!KmonWatchMatches(builtinAlloc, svchostWatch))
        {
            break;
        }
        KmonEvent diskCheatInject = injectEvent;
        diskCheatInject.Image = L"D:\\cheats\\x.exe";
        diskCheatInject.TargetImage = L"game.exe";
        diskCheatInject.Task = L"WriteVM";
        if (!KmonWatchMatches(diskCheatInject, emptyWatch))
        {
            break;
        }
        KmonEvent dropInject = injectEvent;
        dropInject.Image = L"C:\\Users\\a\\AppData\\Local\\Temp\\x.exe";
        dropInject.Task = L"AllocVM";
        if (!KmonWatchMatches(dropInject, emptyWatch))
        {
            break;
        }
        if (!KmonIsWindowsBuiltinLeaf(L"svchost.exe") ||
            KmonIsWindowsBuiltinLeaf(L"game.exe") ||
            !KmonWindowsBuiltinPathLooksInbox(L"C:\\Windows\\System32\\svchost.exe") ||
            KmonWindowsBuiltinPathLooksInbox(L"C:\\Temp\\svchost.exe") ||
            !KmonWindowsBuiltinPathLooksInbox(
                L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe") ||
            KmonWindowsBuiltinPathLooksInbox(
                L"\\Device\\HarddiskVolume3\\Users\\a\\svchost.exe") ||
            KmonClassifyDriverPath(
                L"\\Device\\HarddiskVolume3\\Users\\a\\svchost.exe") != L"drop" ||
            KmonClassifyDriverPath(
                L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe") != L"inbox" ||
            KmonClassifyDriverPath(
                L"\\Device\\HarddiskVolume3\\Program Files\\Game\\game.exe") != L"third_party" ||
            KmonClassifyDriverPath(
                L"\\Device\\HarddiskVolume3\\cheat.sys") != L"drop" ||
            KmonClassifyDriverPath(
                L"\\Device\\HarddiskVolume3\\Games\\game.exe") != L"unknown" ||
            KmonClassifyDriverPath(L"C:\\Cheats\\x.dll") != L"unknown" ||
            KmonClassifyDriverPath(L"C:\\Windows\\SysWOW64\\ntdll.dll") != L"inbox" ||
            KmonClassifyDriverPath(
                L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll") != L"inbox" ||
            !KmonWindowsBuiltinPathLooksInbox(
                L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_1\\notepad.exe") ||
            KmonWindowsBuiltinPathLooksInbox(
                L"C:\\Users\\a\\AppData\\Local\\Temp\\kn-live-dbg-kmon\\notepad.exe") ||
            !KmonWindowsBuiltinPathLooksInbox(L"C:\\Program Files\\PowerShell\\7\\pwsh.exe"))
        {
            break;
        }

        KmonEvent programFilesInject = injectEvent;
        programFilesInject.Image =
            L"\\Device\\HarddiskVolume3\\Program Files\\Game\\game.exe";
        programFilesInject.TargetImage = L"game.exe";
        if (KmonWatchMatches(programFilesInject, emptyWatch))
        {
            break;
        }

        std::vector<uint8_t> pe(0x200, 0);
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        std::memcpy(pe.data(), &dos, sizeof(dos));
        uint32_t peSig = IMAGE_NT_SIGNATURE;
        std::memcpy(pe.data() + 0x80, &peSig, sizeof(peSig));
        IMAGE_FILE_HEADER fh = {};
        fh.Machine = IMAGE_FILE_MACHINE_AMD64;
        fh.NumberOfSections = 1;
        fh.TimeDateStamp = 0x12345678;
        fh.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        std::memcpy(pe.data() + 0x84, &fh, sizeof(fh));
        IMAGE_OPTIONAL_HEADER64 opt = {};
        opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt.AddressOfEntryPoint = 0x1000;
        opt.ImageBase = 0x140000000ull;
        opt.SizeOfImage = 0x2000;
        opt.CheckSum = 0xAABBCCDD;
        std::memcpy(pe.data() + 0x84 + sizeof(fh), &opt, sizeof(opt));
        KmonPeIdentity parsed = {};
        if (!ParseKmonPeIdentity(pe, &parsed) ||
            parsed.SizeOfImage != 0x2000 ||
            parsed.EntryPointRva != 0x1000 ||
            parsed.TimeDateStamp != 0x12345678 ||
            parsed.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            !parsed.Is64)
        {
            break;
        }
        KmonEvent masqEvent = {};
        masqEvent.Kind = L"process.masquerade";
        if (!KmonWatchMatches(masqEvent, emptyWatch))
        {
            break;
        }

        KmonEvent dropEvent = {};
        dropEvent.Kind = L"driver.drop_load";
        dropEvent.Driver = L"unknown-drop.sys";
        dropEvent.Evidence[L"path_class"] = L"drop";
        if (!KmonWatchMatches(dropEvent, emptyWatch) ||
            !KmonDriverLoadArmsMapperWatch(dropEvent))
        {
            break;
        }
        KmonEvent inboxImage = {};
        inboxImage.Kind = L"driver.image_only";
        inboxImage.Driver = L"C:\\Windows\\System32\\drivers\\acpi.sys";
        inboxImage.Evidence[L"path_class"] = L"inbox";
        if (!KmonWatchMatches(inboxImage, emptyWatch) ||
            KmonDriverLoadArmsMapperWatch(inboxImage))
        {
            break;
        }
        KmonEvent unnamedImage = {};
        unnamedImage.Kind = L"driver.image_only";
        unnamedImage.Evidence[L"path_class"] = L"unknown";
        KmonEvent dropImage = {};
        dropImage.Kind = L"driver.image_only";
        dropImage.Driver = L"C:\\Temp\\mapped.sys";
        dropImage.Evidence[L"path_class"] = L"drop";
        if (!KmonDriverLoadArmsMapperWatch(unnamedImage) ||
            !KmonDriverLoadArmsMapperWatch(dropImage))
        {
            break;
        }
        KmonEvent mapperWatchEvent = {};
        mapperWatchEvent.Kind = L"mapper.watch";
        mapperWatchEvent.Driver = L"unknown-drop.sys";
        if (!KmonWatchMatches(mapperWatchEvent, emptyWatch))
        {
            break;
        }
        KmonEvent dataptrEvent = {};
        dataptrEvent.Kind = L"hook.dataptr";
        KmonEvent kernelPhysEvent = {};
        kernelPhysEvent.Kind = L"inject.kernel_phys";
        if (!KmonWatchMatches(dataptrEvent, emptyWatch) ||
            !KmonWatchMatches(kernelPhysEvent, emptyWatch))
        {
            break;
        }
        KmonOptions driverWatch;
        driverWatch.WatchDrivers.push_back(L"other.sys");
        // /driver must not hide an unknown drop name.
        if (!KmonWatchMatches(dropEvent, driverWatch))
        {
            break;
        }

        KmonEvent inboxEvent = {};
        inboxEvent.Kind = L"driver.official_load";
        inboxEvent.Driver = L"C:\\Windows\\System32\\drivers\\acpi.sys";
        inboxEvent.Evidence[L"path_class"] = L"inbox";
        if (KmonWatchMatches(inboxEvent, emptyWatch) ||
            KmonDriverLoadArmsMapperWatch(inboxEvent))
        {
            break;
        }
        KmonEvent dropUnload = {};
        dropUnload.Kind = L"driver.official_unload";
        dropUnload.Driver = L"C:\\Users\\a\\AppData\\Local\\Temp\\x.sys";
        dropUnload.Evidence[L"path_class"] = L"drop";
        KmonEvent inboxUnload = inboxEvent;
        inboxUnload.Kind = L"driver.official_unload";
        if (!KmonDriverUnloadArmsMapperWatch(dropUnload) ||
            KmonDriverUnloadArmsMapperWatch(inboxUnload))
        {
            break;
        }
        KmonOptions verboseWatch;
        verboseWatch.VerboseDrivers = true;
        if (!KmonWatchMatches(inboxEvent, verboseWatch))
        {
            break;
        }
        driverWatch.WatchDrivers = { L"acpi.sys" };
        if (!KmonWatchMatches(inboxEvent, driverWatch))
        {
            break;
        }

        KmonEvent emptyDevice = {};
        emptyDevice.Kind = L"driver.device";
        if (KmonWatchMatches(emptyDevice, emptyWatch))
        {
            break;
        }

        KmonOptions starDriver;
        starDriver.WatchDrivers.push_back(L"*");
        if (KmonWatchMatches(emptyDevice, starDriver))
        {
            break;
        }

        if (KmonClassifyDriverPath(L"acpi.sys") != L"unknown" ||
            KmonClassifyDriverPath(L"\\Driver\\ACPI") != L"unknown" ||
            KmonClassifyDriverPath(L"D:\\cheats\\a.sys") != L"unknown" ||
            KmonClassifyDriverPath(L"C:\\cheat.sys") != L"drop")
        {
            break;
        }
        if (!KmonLooksLikeHijackDll(L"version.dll") ||
            !KmonLooksLikeHijackDll(L"winmm.dll") ||
            KmonLooksLikeHijackDll(L"game.dll") ||
            KmonLooksLikeHijackDll(L"vcruntime140.dll"))
        {
            break;
        }
        if (!KmonLooksLikeHookableSystemDll(L"ntdll.dll") ||
            !KmonLooksLikeHookableSystemDll(L"win32u.dll") ||
            !KmonLooksLikeHookableSystemDll(L"dxgi.dll") ||
            !KmonLooksLikeHookableSystemDll(L"d3d11.dll") ||
            KmonLooksLikeHookableSystemDll(L"game.dll") ||
            KmonLooksLikeHookableSystemDll(L"version.dll") ||
            !KmonLooksLikeGraphicsApiDll(L"dxgi.dll") ||
            !KmonLooksLikeGraphicsApiDll(L"d3d11.dll") ||
            KmonLooksLikeGraphicsApiDll(L"ntdll.dll") ||
            KmonLooksLikeGraphicsApiDll(L"game.dll") ||
            !KmonLooksLikeOverlayRuntimeDll(L"gameoverlayrenderer64.dll") ||
            !KmonLooksLikeOverlayRuntimeDll(L"graphics-hook64.dll") ||
            !KmonLooksLikeOverlayRuntimeDll(L"rtsshooks64.dll") ||
            KmonLooksLikeOverlayRuntimeDll(L"dxgi.dll") ||
            KmonLooksLikeOverlayRuntimeDll(L"ntdll.dll") ||
            !KmonLooksLikeCfgHostModule(L"ntoskrnl.exe") ||
            !KmonLooksLikeCfgHostModule(L"win32kfull.sys") ||
            !KmonLooksLikeCfgHostModule(L"dxgkrnl.sys") ||
            KmonLooksLikeCfgHostModule(L"acpi.sys") ||
            !KmonVaLooksLikePagingOrFirmware(0x00007FF800000000ull) ||
            !KmonVaLooksLikePagingOrFirmware(0xFFFFF68000000000ull) ||
            !KmonVaLooksLikePagingOrFirmware(0xFFFFF78000000000ull) ||
            KmonVaLooksLikePagingOrFirmware(0xFFFFF80000000000ull))
        {
            break;
        }
        if (!KmonLooksLikeKnownRuntimePath(
                L"c:\\program files (x86)\\steam\\gameoverlayrenderer64.dll") ||
            !KmonLooksLikeKnownRuntimePath(
                L"c:\\program files\\obs-studio\\graphics-hook64.dll") ||
            KmonLooksLikeKnownRuntimePath(
                L"c:\\program files\\randomcheat\\inject.dll"))
        {
            break;
        }
        if (KmonDriverPathHasFileDirectory(L"acpi.sys") ||
            KmonDriverPathHasFileDirectory(L"\\Driver\\ACPI") ||
            !KmonDriverPathHasFileDirectory(L"D:\\cheats\\a.sys"))
        {
            break;
        }

        TiEventRecord bareInbox = {};
        bareInbox.ProcessId = 4;
        bareInbox.TaskName = L"DriverObjectLoad";
        TiPayloadField bareField = {};
        bareField.Name = L"DriverName";
        bareField.Value = L"acpi.sys";
        bareInbox.Payload.push_back(bareField);
        if (!KmonClassifyTiEvent(bareInbox, &classified) ||
            classified.Kind != L"driver.official_load" ||
            KmonWatchMatches(classified, emptyWatch))
        {
            break;
        }

        TiEventRecord otherVolume = {};
        otherVolume.ProcessId = 4;
        otherVolume.TaskName = L"DriverObjectLoad";
        TiPayloadField otherField = {};
        otherField.Name = L"DriverName";
        otherField.Value = L"D:\\cheats\\a.sys";
        otherVolume.Payload.push_back(otherField);
        if (!KmonClassifyTiEvent(otherVolume, &classified) ||
            classified.Kind != L"driver.drop_load" ||
            !KmonWatchMatches(classified, emptyWatch))
        {
            break;
        }

        KmonOptions pathWatch;
        pathWatch.WatchNames.push_back(KmonBasenameLower(L"C:\\games\\game.exe"));
        if (!KmonWatchMatches(injectEvent, pathWatch))
        {
            break;
        }

        // loader.activity trails only surface for watched caller/target
        // pids or watched names, and never with an empty watch set.
        KmonEvent activity = {};
        activity.Kind = L"loader.activity";
        activity.ProcessId = 501;
        activity.Image = L"C:\\drops\\loader.exe";
        activity.Task = L"RegSet_value";
        if (KmonWatchMatches(activity, emptyWatch))
        {
            break;
        }
        KmonOptions pidWatch;
        pidWatch.WatchPids.push_back(501);
        if (!KmonWatchMatches(activity, pidWatch))
        {
            break;
        }
        KmonOptions nameWatch2;
        nameWatch2.WatchNames.push_back(L"loader.exe");
        if (!KmonWatchMatches(activity, nameWatch2))
        {
            break;
        }
        KmonEvent otherActivity = activity;
        otherActivity.ProcessId = 502;
        otherActivity.TargetProcessId = 501;
        if (!KmonWatchMatches(otherActivity, pidWatch))
        {
            break;
        }
        otherActivity.TargetProcessId = 0;
        if (KmonWatchMatches(otherActivity, pidWatch))
        {
            break;
        }

        // driver.handle / driver.ioctl always match: both are emitted only
        // for watched targets or an explicitly armed interposition.
        KmonEvent driverHandle = {};
        driverHandle.Kind = L"driver.handle";
        driverHandle.ProcessId = 601;
        if (!KmonWatchMatches(driverHandle, emptyWatch))
        {
            break;
        }
        KmonEvent driverIoctl = {};
        driverIoctl.Kind = L"driver.ioctl";
        driverIoctl.ProcessId = 601;
        if (!KmonWatchMatches(driverIoctl, emptyWatch))
        {
            break;
        }

        TimelineEvent slashMasq = {};
        slashMasq.Action = L"process-create";
        slashMasq.ProcessId = 4321;
        slashMasq.Entity = L"C:/Temp/svchost.exe";
        slashMasq.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(slashMasq, &classified) ||
            classified.Kind != L"process.masquerade")
        {
            break;
        }
        TimelineEvent slashInboxCreate = {};
        slashInboxCreate.Action = L"process-create";
        slashInboxCreate.ProcessId = 4322;
        slashInboxCreate.Entity = L"C:/Windows/System32/svchost.exe";
        slashInboxCreate.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(slashInboxCreate, &classified) ||
            classified.Kind != L"process.create")
        {
            break;
        }

        KmonEvent slashInject = injectEvent;
        slashInject.Image = L"C:/cheats/x.exe";
        slashInject.TargetImage = L"game.exe";
        slashInject.Task = L"WriteVM";
        if (!KmonWatchMatches(slashInject, emptyWatch))
        {
            break;
        }

        std::unordered_set<std::wstring> imported;
        KmonPeLayout importLayout = {};
        CollectImportedDllNames(L"", std::vector<uint8_t>(), importLayout, &imported);
        if (!imported.empty())
        {
            break;
        }
        uint32_t iatUnknown = 1;
        ScanLiveImportThunks(
            L"",
            std::vector<uint8_t>(),
            0,
            0,
            12,
            16,
            20,
            true,
            0,
            nullptr,
            nullptr,
            nullptr,
            8,
            0,
            std::vector<std::wstring>(),
            std::vector<std::pair<uint64_t, uint32_t>>(),
            &iatUnknown);
        if (iatUnknown != 1)
        {
            break;
        }
        iatUnknown = 0;
        ScanLiveImportThunks(
            L"",
            std::vector<uint8_t>(),
            0,
            0,
            12,
            16,
            20,
            true,
            0,
            nullptr,
            nullptr,
            nullptr,
            8,
            0,
            std::vector<std::wstring>(),
            std::vector<std::pair<uint64_t, uint32_t>>(),
            &iatUnknown);
        if (iatUnknown != 0)
        {
            break;
        }
        KmonPeLayout emptyExportLayout = {};
        if (CountNtExportPrologueMismatches(
                L"",
                std::vector<uint8_t>(),
                emptyExportLayout,
                nullptr,
                nullptr,
                nullptr,
                8,
                0) != 0)
        {
            break;
        }
        std::unordered_set<std::wstring> emptyDirNames;
        if (!CollectPeDllNameDirectory(
                L"",
                std::vector<uint8_t>(),
                0,
                0,
                12,
                20,
                &emptyDirNames) ||
            CollectPeDllNameDirectory(
                L"",
                std::vector<uint8_t>(),
                0x1000,
                4,
                12,
                20,
                &emptyDirNames))
        {
            break;
        }
        uint64_t sectionBaseUnknown = 1;
        if (QuerySectionBaseAddress(nullptr, nullptr, 8, &sectionBaseUnknown) ||
            sectionBaseUnknown != 0)
        {
            break;
        }
        std::wstring kernelPathUnknown = L"x";
        if (QueryKernelImagePath(nullptr, nullptr, 8, &kernelPathUnknown) ||
            !kernelPathUnknown.empty())
        {
            break;
        }
        if (!PathLooksLikeWin32File(L"C:\\Windows\\System32\\svchost.exe") ||
            !PathLooksLikeWin32File(L"c:/Windows/System32/svchost.exe") ||
            PathLooksLikeWin32File(L"svchost.exe") ||
            PathLooksLikeWin32File(
                L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe") ||
            PathLooksLikeWin32File(L"\\Windows\\System32\\svchost.exe"))
        {
            break;
        }
        if (Win32PathFromKernelImagePath(L"\\??\\C:\\Windows\\System32\\svchost.exe") !=
                L"C:\\Windows\\System32\\svchost.exe" ||
            Win32PathFromKernelImagePath(L"\\\\?\\C:\\Temp\\x.exe") !=
                L"C:\\Temp\\x.exe")
        {
            break;
        }
        {
            wchar_t windowsDirectory[MAX_PATH] = {};
            if (GetWindowsDirectoryW(
                    windowsDirectory,
                    ARRAYSIZE(windowsDirectory)) == 0)
            {
                break;
            }
            std::wstring windowsPath = windowsDirectory;
            if (windowsPath.size() < 2 || windowsPath[1] != L':')
            {
                break;
            }
            const std::wstring drive = windowsPath.substr(0, 2);
            if (Win32PathFromKernelImagePath(L"\\Windows\\System32\\svchost.exe") !=
                    (drive + L"\\Windows\\System32\\svchost.exe") ||
                Win32PathFromKernelImagePath(L"\\SystemRoot\\System32\\ntdll.dll") !=
                    (windowsPath + L"\\System32\\ntdll.dll"))
            {
                break;
            }
            {
                const std::wstring usersNt =
                    L"\\Users\\a\\AppData\\Local\\Temp\\x.exe";
                const std::wstring users = Win32PathFromKernelImagePath(usersNt);
                const std::wstring gameNt = L"\\Program Files\\Game\\game.exe";
                const std::wstring game = Win32PathFromKernelImagePath(gameNt);
                if ((users != usersNt && !PathLooksLikeWin32File(users)) ||
                    (game != gameNt && !PathLooksLikeWin32File(game)))
                {
                    break;
                }
            }
            std::wstring enrichNt = L"\\Windows\\System32\\svchost.exe";
            EnrichProcessImagePath(nullptr, nullptr, 8, &enrichNt);
            std::wstring enrichWin32 = drive + L"\\Windows\\System32\\notepad.exe";
            EnrichProcessImagePath(nullptr, nullptr, 8, &enrichWin32);
            if (enrichNt != (drive + L"\\Windows\\System32\\svchost.exe") ||
                enrichWin32 != (drive + L"\\Windows\\System32\\notepad.exe"))
            {
                break;
            }
        }
        {
            const std::wstring ntDevice =
                L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe";
            const std::wstring converted = Win32PathFromKernelImagePath(ntDevice);
            if (converted != ntDevice && !PathLooksLikeWin32File(converted))
            {
                break;
            }
        }
        uint64_t icUnknown = 1;
        if (QueryInstrumentationCallback(nullptr, nullptr, 8, &icUnknown) ||
            icUnknown != 0)
        {
            break;
        }
        {
            uint32_t lastVa = 1;
            if (LastRelocBlockVa(std::vector<uint8_t>(), &lastVa) || lastVa != 0)
            {
                break;
            }
            std::vector<uint8_t> relocBytes(
                sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t),
                0);
            IMAGE_BASE_RELOCATION block = {};
            block.VirtualAddress = 0x1000;
            block.SizeOfBlock =
                static_cast<DWORD>(sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t));
            std::memcpy(relocBytes.data(), &block, sizeof(block));
            uint16_t entry = static_cast<uint16_t>(IMAGE_REL_BASED_DIR64 << 12);
            std::memcpy(
                relocBytes.data() + sizeof(block),
                &entry,
                sizeof(entry));
            lastVa = 0;
            if (!LastRelocBlockVa(relocBytes, &lastVa) || lastVa != 0x1000)
            {
                break;
            }
            const uint32_t sliceLastEarly = 0x1000;
            const uint32_t sliceLastLate = 0x1FF000;
            if (lastVa < sliceLastEarly || lastVa >= sliceLastLate)
            {
                break;
            }
        }
        {
            std::vector<uint8_t> stubBuf(0x80, 0xCC);
            stubBuf[0] = 0xFF;
            stubBuf[1] = 0x25;
            const int32_t disp0 = 0x1A;
            std::memcpy(stubBuf.data() + 2, &disp0, sizeof(disp0));
            const uint64_t ntosTarget = 0xFFFFF80000001000ull;
            std::memcpy(stubBuf.data() + 0x20, &ntosTarget, sizeof(ntosTarget));
            stubBuf[0x10] = 0xFF;
            stubBuf[0x11] = 0x25;
            const int32_t disp1 = 0x12;
            std::memcpy(stubBuf.data() + 0x12, &disp1, sizeof(disp1));
            const uint64_t halTarget = 0xFFFFF80001000000ull;
            std::memcpy(stubBuf.data() + 0x28, &halTarget, sizeof(halTarget));
            KernelModuleInfo ntos = {};
            ntos.Base = 0xFFFFF80000000000ull;
            ntos.Size = 0x800000;
            ntos.ImageName = L"ntoskrnl.exe";
            KernelModuleInfo hal = {};
            hal.Base = 0xFFFFF80001000000ull;
            hal.Size = 0x100000;
            hal.ImageName = L"hal.dll";
            const std::vector<KernelModuleInfo> mods = { ntos, hal };
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) < 2)
            {
                break;
            }
            stubBuf[0x10] = 0xCC;
            stubBuf[0x11] = 0xCC;
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) >= 2)
            {
                break;
            }
            KernelModuleInfo userMod = {};
            userMod.Base = 0x140000000ull;
            userMod.Size = 0x1000;
            userMod.ImageName = L"game.exe";
            std::memcpy(stubBuf.data() + 0x20, &userMod.Base, sizeof(userMod.Base));
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    std::vector<KernelModuleInfo>{ userMod }) != 0)
            {
                break;
            }
            // FF 15 call [rip+disp] through an in-buffer slot must count
            // the same way the FF 25 jmp form does.
            stubBuf.assign(0x80, 0xCC);
            stubBuf[0] = 0xFF;
            stubBuf[1] = 0x15;
            const int32_t dispCall = 0x1A;
            std::memcpy(stubBuf.data() + 2, &dispCall, sizeof(dispCall));
            std::memcpy(stubBuf.data() + 0x20, &ntosTarget, sizeof(ntosTarget));
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) < 1)
            {
                break;
            }
            // Absolute thunk: mov rax, <imm64>; jmp rax.
            stubBuf.assign(0x80, 0xCC);
            stubBuf[0] = 0x48;
            stubBuf[1] = 0xB8;
            std::memcpy(stubBuf.data() + 2, &ntosTarget, sizeof(ntosTarget));
            stubBuf[10] = 0xFF;
            stubBuf[11] = 0xE0;
            stubBuf[0x20] = 0x48;
            stubBuf[0x21] = 0xB8;
            std::memcpy(stubBuf.data() + 0x22, &halTarget, sizeof(halTarget));
            stubBuf[0x2C] = 0xFF;
            stubBuf[0x2D] = 0xD0;
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) < 2)
            {
                break;
            }
            // Absolute thunk to a user-mode target must not count even with
            // the jmp rax tail present.
            stubBuf[0x22] = 0;
            stubBuf[0x23] = 0;
            stubBuf[0x24] = 0;
            stubBuf[0x25] = 0;
            stubBuf[0x26] = 0x01;
            stubBuf[0x27] = 0;
            stubBuf[0x28] = 0;
            stubBuf[0x29] = 0;
            stubBuf[0x2A] = 0;
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) >= 2)
            {
                break;
            }
            // mov rax, <kernel imm64> without a jmp/call rax tail is just a
            // pointer load, not an import thunk.
            stubBuf.assign(0x80, 0xCC);
            stubBuf[0] = 0x48;
            stubBuf[1] = 0xB8;
            std::memcpy(stubBuf.data() + 2, &ntosTarget, sizeof(ntosTarget));
            if (CountKernelImportStubs(
                    stubBuf.data(),
                    stubBuf.size(),
                    0xFFFFFA8000000000ull,
                    mods) != 0)
            {
                break;
            }
            uint8_t cfgText[32] = {};
            cfgText[0] = 0x48;
            cfgText[1] = 0x8B;
            cfgText[2] = 0x05;
            const int32_t slotDisp = static_cast<int32_t>(0x2000 - 7);
            std::memcpy(cfgText + 3, &slotDisp, sizeof(slotDisp));
            cfgText[7] = 0xE8;
            const int32_t callDisp = static_cast<int32_t>(0x5000 - 12);
            std::memcpy(cfgText + 8, &callDisp, sizeof(callDisp));
            std::unordered_set<uint32_t> guardCall = { 0x5000 };
            std::unordered_set<uint32_t> guardIat;
            std::vector<uint32_t> slotRvas;
            if (CollectCfgDataPtrSlotRvas(
                    cfgText,
                    sizeof(cfgText),
                    0,
                    0x3000,
                    guardCall,
                    guardIat,
                    &slotRvas,
                    8) != 1 ||
                slotRvas.size() != 1 ||
                slotRvas[0] != 0x2000)
            {
                break;
            }
            cfgText[7] = 0x90;
            slotRvas.clear();
            if (CollectCfgDataPtrSlotRvas(
                    cfgText,
                    sizeof(cfgText),
                    0,
                    0x3000,
                    guardCall,
                    guardIat,
                    &slotRvas,
                    8) != 0)
            {
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}
