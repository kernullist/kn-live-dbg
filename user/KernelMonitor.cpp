#include "KernelMonitor.h"

#include "ByovdScanner.h"
#include "CallbackScanner.h"
#include "CrScanner.h"
#include "DpcTimerScanner.h"
#include "HalDispatchScanner.h"
#include "HiddenProcessScanner.h"
#include "IdtScanner.h"
#include "InputStackScanner.h"
#include "IntegrityScanner.h"
#include "MapperRemnantScanner.h"
#include "MinifilterIrpScanner.h"
#include "MsrScanner.h"
#include "NmiScanner.h"
#include "OrphanKernelPageScanner.h"
#include "PoolPeHunter.h"
#include "SsdtScanner.h"
#include "VbsScanner.h"
#include "WfpCalloutScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <chrono>
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
            if (symbols == nullptr || symbols->Modules().empty())
            {
                owned = true;
                break;
            }
            for (const KernelModuleInfo& module : symbols->Modules())
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
            if (!symbols->Modules().empty())
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
            if (!symbols->LoadKernelModules(&ignored) || symbols->Modules().empty())
            {
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
        if (w.empty())
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
        WideCharToMultiByte(
            CP_UTF8,
            0,
            w.c_str(),
            static_cast<int>(w.size()),
            &s[0],
            needed,
            nullptr,
            nullptr);
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
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) <= headers.size())
            {
                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(&optional, headers.data() + optionalOffset, sizeof(optional));
                layout->PreferredBase = optional.ImageBase;
                relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
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
                if (n > 0x400)
                {
                    n = 0x400;
                }
                layout->ExecSize = n;
                break;
            }
            ok = layout->SizeOfImage != 0;
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
                const uint32_t rva = block.VirtualAddress + offset;
                if (rva < sliceRva || rva >= sliceRva + static_cast<uint32_t>(slice->size()))
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
                    read > 0)
                {
                    bytes->resize(read);
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
            ok = device->ReadProcessVirtual(
                pid,
                ctx.Eprocess,
                0,
                address,
                length,
                bytes,
                &ignored);
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
                        if (ReadProcessBytes(
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
                if (device->ReadMemory(
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
                    if (peb32 != 0)
                    {
                        kernelWow64 = true;
                        std::vector<uint8_t> base32Bytes;
                        if (device->ReadProcessVirtual(
                                pid,
                                ctx.Eprocess,
                                0,
                                peb32 + 0x08,
                                sizeof(uint32_t),
                                &base32Bytes,
                                &ignored) &&
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
            if (!device->ReadMemory(
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
            if (peb == 0)
            {
                break;
            }
            std::vector<uint8_t> baseBytes;
            if (!device->ReadProcessVirtual(
                    pid,
                    ctx.Eprocess,
                    0,
                    peb + 0x10,
                    sizeof(uint64_t),
                    &baseBytes,
                    &ignored) ||
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

    enum SliceCompare
    {
        SliceUnknown = 0,
        SliceMatch,
        SliceMismatch
    };

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
        uint32_t length)
    {
        SliceCompare result = SliceUnknown;
        do
        {
            if (length < 16 || imageBase == 0 || fileOffset == 0)
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
                uint32_t relocFile = 0;
                std::vector<uint8_t> relocs;
                if (RvaToFileOffset(diskHeaders, layout.RelocRva, &relocFile) &&
                    ReadDiskRange(
                        imagePath,
                        relocFile,
                        (std::min)(layout.RelocSize, 0x10000u),
                        &relocs))
                {
                    ApplyRelocsToSlice(
                        &diskText,
                        rva,
                        delta,
                        relocs,
                        layout.Is64);
                    compared = true;
                }
            }
            if (!compared)
            {
                break;
            }
            size_t n = (std::min)(diskText.size(), liveText.size());
            // A DIR64/HIGHLOW reloc that straddles the window end cannot be
            // applied; comparing those tail bytes FPs every ASLR'd image.
            if (n >= 24)
            {
                n -= 8;
            }
            result = (std::memcmp(diskText.data(), liveText.data(), n) == 0)
                ? SliceMatch
                : SliceMismatch;
        } while (false);
        return result;
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
            if (address >= range.first &&
                address < range.first + static_cast<uint64_t>(range.second))
            {
                found = true;
                break;
            }
        }
        return found;
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
            for (uint32_t i = 0; i < rvaCount; ++i)
            {
                const uint64_t page = (imageBase + rvas[i]) & ~0xFFFull;
                info[i].VirtualAddress = reinterpret_cast<PVOID>(page);
                std::vector<uint8_t> touch;
                ReadProcessBytes(device, symbols, process, pid, page, 8, &touch);
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

    std::wstring KmonImageForClassify(uint32_t pid, const std::wstring& maybePath)
    {
        if (maybePath.find(L'\\') != std::wstring::npos ||
            maybePath.find(L'/') != std::wstring::npos)
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

    bool TryEnableLoggingUsermode(uint32_t pid, uint32_t loggingFlags)
    {
        bool ok = false;
        HANDLE process = nullptr;

        do
        {
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
            NTSTATUS status = setInfo(
                process,
                kProcessEnableLogging,
                &flags,
                sizeof(flags));
            if (status < 0)
            {
                UCHAR smallFlags = static_cast<UCHAR>(loggingFlags & 0x3u);
                status = setInfo(
                    process,
                    kProcessEnableReadWriteVmLogging,
                    &smallFlags,
                    sizeof(smallFlags));
            }
            if (status >= 0)
            {
                ok = true;
            }
        } while (false);

        if (process != nullptr)
        {
            CloseHandle(process);
        }

        return ok;
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
        do
        {
            std::wstring base = KmonBasenameLower(entry.szExeFile);
            if (NameEqualsWatch(base, namesLower) && entry.th32ProcessID > 4)
            {
                pids->push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snap, &entry));
        CloseHandle(snap);
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
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"allocvm") != std::wstring::npos ||
        lower.find(L"protectvm") != std::wstring::npos ||
        lower.find(L"mapview") != std::wstring::npos ||
        lower.find(L"queueuserapc") != std::wstring::npos ||
        lower.find(L"setthreadcontext") != std::wstring::npos ||
        lower.find(L"writevm") != std::wstring::npos ||
        lower.find(L"readvm") != std::wstring::npos ||
        lower.find(L"suspend") != std::wstring::npos ||
        lower.find(L"resume") != std::wstring::npos;
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
        const bool looksKernelImage =
            event.ProcessId == 0 ||
            event.ProcessId == 4 ||
            KmonPathLooksLikeSys(event.Entity);
        if (action == L"image-load" && looksKernelImage && !event.Entity.empty())
        {
            const std::wstring pathClass = KmonClassifyDriverPath(event.Entity);
            const bool fileDrop =
                pathClass == L"drop" ||
                pathClass == L"third_party" ||
                (pathClass != L"inbox" && KmonDriverPathHasFileDirectory(event.Entity));
            if (!fileDrop &&
                pathClass != L"inbox" &&
                !KmonPathLooksLikeSys(event.Entity))
            {
                break;
            }

            out->Driver = event.Entity;
            out->Evidence[L"path_class"] = pathClass;
            out->Evidence[L"source"] = L"image_notify";
            if (fileDrop)
            {
                out->Kind = L"driver.drop_load";
                out->Summary = L"non-inbox kernel image load " + event.Entity;
                out->Evidence[L"followup"] = L"!pool pe /suspicious; !mapper; !kpage /pe";
            }
            else
            {
                out->Kind = L"driver.image_only";
                out->Summary = L"inbox kernel image load " + KmonBasenameLower(event.Entity);
            }
            classified = true;
            break;
        }

        if (action == L"process-create")
        {
            const std::wstring leaf = KmonBasenameLower(event.Entity);
            if (KmonIsWindowsBuiltinLeaf(leaf) &&
                !event.Entity.empty() &&
                event.Entity.find(L'\\') != std::wstring::npos &&
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
            event.Kind == L"driver.short_lived" ||
            event.Kind == L"driver.mapped_residue" ||
            event.Kind == L"hook.unbacked" ||
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
                (callerClass == L"unknown" && event.Image.find(L'\\') != std::wstring::npos) ||
                (targetClass == L"unknown" && event.TargetImage.find(L'\\') != std::wstring::npos);
            const bool builtinSide =
                KmonIsWindowsBuiltinLeaf(caller) || KmonIsWindowsBuiltinLeaf(target);
            if (dropSide || unknownFileSide)
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
            if (!KmonTaskLooksLikeRemoteInjectMaterial(event.Task))
            {
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
            if (matched)
            {
                break;
            }
            if (NameEqualsWatch(caller, options.WatchNames) ||
                NameEqualsWatch(target, options.WatchNames))
            {
                matched = true;
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
                LoggingEnabledPids.clear();
                RecentCreatePids.clear();
                EmittedUnnamedPids.clear();
                EmittedMapperKeys.clear();
                RecentLoads.clear();
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

        {
            std::lock_guard<std::mutex> lock(StateMutex);
            if (!Active.load())
            {
                if (error != nullptr)
                {
                    *error = L"kmon became inactive during start";
                }
                break;
            }
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

        ok = true;
    } while (false);

    return ok;
}

bool KernelMonitor::Stop(std::wstring* error)
{
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        StopRequested.store(true);
        Active.store(false);
        LiveOutput.store(false);
        if (Worker.joinable())
        {
            worker = std::move(Worker);
        }
        Ti = nullptr;
        Timeline = nullptr;
        Device = nullptr;
        Symbols = nullptr;
    }

    if (worker.joinable())
    {
        worker.join();
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

        const uint64_t nowMs = GetTickCount64();
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
            NextMapperScanTickMs = GetTickCount64() + mapperInterval;
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
            NextKpageScanTickMs = GetTickCount64() + kKpageScanIntervalMs;
        }

        if (NextUserScanTickMs == 0)
        {
            NextUserScanTickMs = nowMs + 1500;
        }
        else if (nowMs >= NextUserScanTickMs)
        {
            PruneStalePromotedWatches();
            ScanUserModeHostility();
            IngestLiveTimeline();
            IngestThreatIntel();
            NextUserScanTickMs = GetTickCount64() + kUserScanIntervalMs;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void KernelMonitor::IngestThreatIntel()
{
    TiSubscriber* ti = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        ti = Ti;
    }
    if (ti == nullptr || !ti->IsActive())
    {
        return;
    }

    std::vector<TiEventRecord> batch = ti->RecentAfterSequence(TiCursorSequence, 512);
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
            }
            RecordEvent(std::move(classified));
        }

        if (record.ProcessId > 4 && record.ImagePath.empty())
        {
            uint64_t created = 0;
            bool unnamedLive = false;
            HANDLE unnamedProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                record.ProcessId);
            if (unnamedProcess != nullptr)
            {
                unnamedLive = true;
                created = QueryProcessCreateTicks(unnamedProcess);
                CloseHandle(unnamedProcess);
            }
            bool claimed = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                const std::wstring unnamedKey =
                    L"unnamed:" + std::to_wstring(record.ProcessId) + L":" +
                    (unnamedLive ? std::to_wstring(created) : std::wstring(L"gone"));
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

    std::vector<TimelineEvent> batch = timeline->RecentAfterEventId(LiveCursorEventId, 256);
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
            bool nameWatch = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                nameWatch = NameEqualsWatch(base, WatchNamesLower);
                if (nameWatch)
                {
                    WatchPromotedPids.insert(classified.ProcessId);
                    WatchPids.insert(classified.ProcessId);
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
            if (nameWatch && classified.ProcessId > 4)
            {
                EnableLoggingForPid(classified.ProcessId);
            }
        }

        if (classified.Kind == L"driver.drop_load" ||
            classified.Kind == L"driver.official_load")
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
        return;
    }

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

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    const uint64_t ts = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;

    for (const HiddenProcessRecord& record : result.Records)
    {
        if (!record.Suspicious)
        {
            continue;
        }

        bool already = false;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            const std::wstring hideKey =
                L"hidden:" + std::to_wstring(record.ProcessId) + L":" + HexU64(record.Eprocess);
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
            (*symbols)->Modules().empty())
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
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
        std::wstring uniqueKey = key;
        if (processId > 4)
        {
            HANDLE process = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                processId);
            if (process != nullptr)
            {
                const uint64_t created = QueryProcessCreateTicks(process);
                CloseHandle(process);
                uniqueKey += L":" + std::to_wstring(created);
            }
            else
            {
                uniqueKey += L":gone";
            }
        }
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
        return;
    }

    MapperRemnantScanner scanner(*device, *symbols);
    MapperScanOptions options;
    options.Limit = 64;
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

    for (const MapperUnloadedRecord& record : result.Unloaded)
    {
        if (!record.Suspicious)
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
        if (!record.Suspicious)
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
        if (!record.Suspicious)
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
        return;
    }
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

    PoolPeHunter hunter(*device);
    PoolPeHunter::Options options;
    options.Paged = PoolPeHunter::PagedFilter::NonPagedOnly;
    options.LimitHits = 32;
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
            L"mapped PE in nonpaged pool " + HexU64(hit.Address) + L" tag=" + hit.TagText,
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
        return;
    }
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
            EmitUnique(
                L"hook.unbacked",
                L"dispatch:" + HexU64(record.DriverObject) + L":" +
                    std::to_wstring(dispatch.Index),
                record.Name,
                L"dispatch",
                L"MajorFunction[" + dispatch.Name + L"] of " + record.Name +
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
        return;
    }
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

    OrphanKernelPageScanner scanner(*device, *symbols);
    OrphanKernelPageOptions options;
    options.DeepPfn = false;
    options.PeOnly = false;
    options.WxOnly = false;
    options.IncludeSession = false;
    options.Limit = 32;
    OrphanKernelPageResult result = {};
    std::wstring error;
    if (!scanner.Scan(options, &result, &error))
    {
        EmitMappedResidue(
            L"scan_failed:kpage",
            std::wstring(),
            L"orphan_page",
            L"orphan kpage PE scan failed",
            error.empty() ? L"Scan returned false" : error);
        return;
    }
    KpageScans.fetch_add(1);

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
        if (!peHit && !wxStub)
        {
            continue;
        }

        std::wstring notes = L"class=" + region.Classification +
            L" risk=" + region.Risk +
            L" size=" + HexU64(region.Size);
        if (!region.Notes.empty())
        {
            notes += L" " + region.Notes;
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
    if (!GetLiveTargets(&device, &symbols) || symbols->Modules().empty())
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

    for (const KernelCallbackRecord& record : result.Records)
    {
        const bool preOutside =
            record.Function != 0 &&
            record.FunctionModule.empty() &&
            !AddressOwnedByLoadedModule(symbols, record.Function);
        const bool postOutside =
            record.PostFunction != 0 &&
            record.PostFunctionModule.empty() &&
            !AddressOwnedByLoadedModule(symbols, record.PostFunction);
        if (!preOutside && !postOutside && !record.Poisoned)
        {
            continue;
        }

        const uint64_t fn = preOutside ? record.Function : record.PostFunction;
        std::wstring summary = L"unbacked " + record.Kind;
        if (!record.Target.empty())
        {
            summary += L" " + record.Target;
        }
        summary += L" callback " + HexU64(fn != 0 ? fn : record.Function);
        EmitUnique(
            L"hook.unbacked",
            L"cb:" + record.Kind + L":" + HexU64(fn != 0 ? fn : record.Entry),
            record.FunctionModule.empty() ? record.Kind : record.FunctionModule,
            L"callback",
            summary,
            record.Notes);
    }
}

void KernelMonitor::ScanHookInput()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols) || symbols->Modules().empty())
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

    for (const InputStackRecord& record : result.Records)
    {
        uint32_t emitted = 0;
        for (const DeviceStackResult& stack : record.Driver.Stacks)
        {
            for (const DeviceObjectRecord& attached : stack.Stack)
            {
                if (!attached.Suspicious)
                {
                    continue;
                }
                if (emitted >= 8)
                {
                    break;
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
                    record.DriverFilter,
                    L"input",
                    L"unbacked driver on " + record.Role + L" stack",
                    notes);
                ++emitted;
            }
            if (emitted >= 8)
            {
                break;
            }
        }
    }
}

void KernelMonitor::ScanCpuIntegrityHooks()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols) || symbols->Modules().empty())
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

    {
        SsdtScanner scanner(*device, *symbols);
        SsdtScanResult result = {};
        std::wstring error;
        if (scanner.Scan(&result, &error))
        {
            uint32_t emitted = 0;
            for (const SsdtTable& table : result.Tables)
            {
                for (const SsdtEntry& entry : table.Entries)
                {
                    if (!entry.Suspicious)
                    {
                        continue;
                    }
                    if (emitted >= 16)
                    {
                        break;
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
            uint32_t emitted = 0;
            for (const IdtEntry& entry : result.Entries)
            {
                if (!entry.Suspicious || !entry.Present)
                {
                    continue;
                }
                if (emitted >= 16)
                {
                    break;
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
            for (const MsrReading& reading : result.Readings)
            {
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
            for (const HalDispatchTable& table : result.Tables)
            {
                for (const HalDispatchSlot& slot : table.Slots)
                {
                    if (!slot.Suspicious)
                    {
                        continue;
                    }
                    if (!slot.Module.empty() &&
                        AddressOwnedByLoadedModule(symbols, slot.Routine))
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
            for (const NmiCallbackRecord& record : result.Callbacks)
            {
                if (!record.Suspicious)
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
            for (const DpcRoutineRecord& record : result.Dpcs)
            {
                if (!record.Suspicious)
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
                EmitUnique(
                    L"hook.unbacked",
                    L"workitem:" + HexU64(record.Routine),
                    record.Module,
                    L"workitem",
                    L"work-item routine outside loaded modules " + HexU64(record.Routine),
                    record.Notes);
            }
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
            uint32_t emitted = 0;
            for (const WfpKernelCallout& callout : result.Callouts)
            {
                if (!callout.ClassifySuspicious &&
                    !callout.NotifySuspicious &&
                    !callout.FlowDeleteSuspicious)
                {
                    continue;
                }
                if (emitted >= 16)
                {
                    break;
                }
                const uint64_t fn = callout.ClassifySuspicious
                    ? callout.ClassifyFn
                    : (callout.NotifySuspicious ? callout.NotifyFn : callout.FlowDeleteFn);
                EmitUnique(
                    L"hook.unbacked",
                    L"wfp:" + std::to_wstring(callout.CalloutId),
                    callout.Name,
                    L"wfp",
                    L"WFP callout " + callout.Name + L" function outside modules " + HexU64(fn),
                    callout.Notes);
                ++emitted;
            }
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
            for (const MinifilterFilterRecord& filter : result.Filters)
            {
                if (filter.WellKnownInbox)
                {
                    continue;
                }
                if (filter.DriverStart == 0 ||
                    AddressOwnedByLoadedModule(symbols, filter.DriverStart))
                {
                    continue;
                }
                EmitUnique(
                    L"hook.unbacked",
                    L"minifilter:" + HexU64(filter.Filter),
                    filter.Name,
                    L"minifilter",
                    L"minifilter " + filter.Name + L" is not backed by a loaded module",
                    filter.Notes);
            }
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
    if (Process32FirstW(snap, &entry))
    {
        do
        {
            const uint32_t pid = entry.th32ProcessID;
            if (pid <= 4 || pid == selfPid)
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
            if (target.ImagePath.empty())
            {
                target.ImagePath = entry.szExeFile;
            }
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
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);

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
    for (const KmonUserTarget& target : targets)
    {
        if (StopRequested.load() || scanned >= kMaxDeepScans)
        {
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
        const bool watched =
            NameEqualsWatch(leaf, watchNames) ||
            watchPids.count(pid) != 0;
        if (watched && pid > 4)
        {
            EnableLoggingForPid(pid);
        }
        if (builtin &&
            imagePath.find(L'\\') != std::wstring::npos &&
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
            if (modSnap != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32W moduleEntry = {};
                moduleEntry.dwSize = sizeof(moduleEntry);
                if (Module32FirstW(modSnap, &moduleEntry))
                {
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
                    } while (Module32NextW(modSnap, &moduleEntry));
                }
                CloseHandle(modSnap);
            }
            const bool moduleInventoryComplete =
                moduleCount > 0 && moduleCount <= kMaxModuleRows;

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pid);
            const bool hasQueryInfo = processHandle != nullptr;
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
            BOOL wow64 = FALSE;
            bool wow64Known = false;
            if (processHandle != nullptr)
            {
                wow64Known = IsWow64Process(processHandle, &wow64) != FALSE;
            }
            uint64_t pebImageBase = 0;
            QueryPebImageBase(processHandle, device, symbols, pid, &pebImageBase);
            const uint64_t exeRegion = pebImageBase != 0 ? pebImageBase : moduleBase;
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
            if (exeRegion != 0)
            {
                MEMORY_BASIC_INFORMATION mbi = {};
                bool queried = false;
                if (processHandle != nullptr &&
                    VirtualQueryEx(
                        processHandle,
                        reinterpret_cast<LPCVOID>(exeRegion),
                        &mbi,
                        sizeof(mbi)) == sizeof(mbi))
                {
                    queried = true;
                }
                const bool committed = queried && mbi.State == MEM_COMMIT;
                const bool privateExe =
                    committed &&
                    (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED);

                bool wxExe = false;
                DWORD wxProtect = 0;
                if (queried && builtin && processHandle != nullptr)
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

                std::wstring mappedPath;
                bool mappedQueryOk = false;
                if (hasQueryInfo && hasVmRead && processHandle != nullptr)
                {
                    mappedQueryOk = QueryMappedImagePath(processHandle, exeRegion, &mappedPath);
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
                else if (privateExe || (committed && mbi.Type != MEM_IMAGE))
                {
                    EmitUnique(
                        L"process.hollow",
                        L"exe_private:" + std::to_wstring(pid),
                        imagePath,
                        L"exe_private",
                        L"main EXE region is not a file-backed image mapping pid=" +
                            std::to_wstring(pid) + L" " + leaf,
                        L"type=" + std::to_wstring(mbi.Type),
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
                            L"mapped=" + mappedPath,
                            pid);
                    }
                }
                else if (hasQueryInfo &&
                    hasVmRead &&
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
                        L"Windows builtin main EXE is W+X pid=" +
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
                const bool diskExists = !imagePath.empty() &&
                    imagePath.find(L'\\') != std::wstring::npos &&
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
                    if (!diskExists && imagePath.find(L'\\') != std::wstring::npos)
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
                        const bool parsedLive = ParseKmonPeIdentity(live, &liveId);
                        const bool compareText = builtin ||
                            KmonWindowsBuiltinPathLooksInbox(imagePath);
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
                            diskLayout.ExecFileOffset != 0 &&
                            RelocatedSliceCompare(
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
                                diskLayout.ExecSize) == SliceMismatch)
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
                        else if (compareText &&
                            parsedDisk &&
                            diskLayout.ExecVirtSize > 0x1000)
                        {
                            uint32_t laterRva = diskLayout.ExecRva + 0x1000;
                            uint32_t laterFile = 0;
                            if (RvaToFileOffset(diskHeaders, laterRva, &laterFile) &&
                                RelocatedSliceCompare(
                                    imagePath,
                                    diskHeaders,
                                    diskLayout,
                                    processHandle,
                                    device,
                                    symbols,
                                    pid,
                                    exeRegion,
                                    laterRva,
                                    laterFile,
                                    0x100) == SliceMismatch)
                            {
                                EmitUnique(
                                    L"process.hollow",
                                    L"exe_text_page:" + std::to_wstring(pid),
                                    imagePath,
                                    L"exe_text_page",
                                    L"main EXE later code page differs from disk pid=" +
                                        std::to_wstring(pid) + L" " + leaf,
                                    L"rva=" + std::to_wstring(laterRva),
                                    pid);
                            }
                        }
                        if (compareText &&
                            parsedDisk &&
                            diskLayout.EntryPointRva != 0 &&
                            (diskLayout.EntryPointRva < diskLayout.ExecRva ||
                                diskLayout.EntryPointRva >= diskLayout.ExecRva + diskLayout.ExecSize))
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
                            hasQueryInfo &&
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
                            if (diskLayout.ExecVirtSize > 0x1000)
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
                for (int step = 0; step < 4096 && orphans < 2; ++step)
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
                        region.State == MEM_COMMIT &&
                        region.RegionSize >= 0x1000 &&
                        alloc != 0 &&
                        alloc != exeRegion &&
                        !AddressInModuleRanges(alloc, moduleRanges) &&
                        (region.Type == MEM_PRIVATE || region.Type == MEM_IMAGE) &&
                        (ProtectHasExecute(region.Protect) || region.Type == MEM_IMAGE);
                    if (interesting)
                    {
                        std::vector<uint8_t> head;
                        if (ReadProcessBytes(
                                device,
                                symbols,
                                processHandle,
                                pid,
                                alloc,
                                2,
                                &head) &&
                            head.size() >= 2 &&
                            head[0] == 'M' &&
                            head[1] == 'Z')
                        {
                            std::wstring mappedOrphan;
                            if (region.Type == MEM_IMAGE)
                            {
                                QueryMappedImagePath(processHandle, alloc, &mappedOrphan);
                            }
                            if (region.Type == MEM_PRIVATE ||
                                region.Type == MEM_IMAGE)
                            {
                                EmitUnique(
                                    L"process.hollow",
                                    L"exe_orphan:" + std::to_wstring(pid) + L":" + HexU64(alloc),
                                    imagePath,
                                    region.Type == MEM_IMAGE ? L"exe_orphan_image" : L"exe_orphan_private",
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
            }
            if (processHandle != nullptr)
            {
                CloseHandle(processHandle);
            }

            uint32_t implants = 0;
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
            for (const std::wstring& modulePath : modulePaths)
            {
                if (implants >= 8)
                {
                    break;
                }
                const std::wstring moduleClass = KmonClassifyDriverPath(modulePath);
                const std::wstring n = KmonNormalizeDriverPath(modulePath);
                const bool windowsModule =
                    n.find(L"\\windows\\system32\\") != std::wstring::npos ||
                    n.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                    n.find(L"\\windows\\winsxs\\") != std::wstring::npos;
                const bool inImageDir =
                    !imageDir.empty() && ToLowerCopy(modulePath).find(imageDir) == 0;
                const bool dropImplant =
                    moduleClass == L"drop" && (builtin || watched);
                const bool builtinForeign = builtin &&
                    !windowsModule &&
                    !inImageDir &&
                    moduleClass != L"inbox" &&
                    moduleClass != L"third_party";
                if (!dropImplant && !builtinForeign)
                {
                    continue;
                }
                EmitUnique(
                    L"process.implant",
                    L"implant:" + std::to_wstring(pid) + L":" + KmonBasenameLower(modulePath),
                    imagePath,
                    dropImplant ? L"drop_module" : L"builtin_foreign_module",
                    L"foreign module in pid=" + std::to_wstring(pid) + L" " + leaf +
                        L" module=" + KmonBasenameLower(modulePath),
                    modulePath,
                    pid);
                ++implants;
            }
    }
}

void KernelMonitor::EnableLoggingForPid(uint32_t pid)
{
    if (pid <= 4)
    {
        return;
    }

    uint64_t created = 0;
    HANDLE query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (query != nullptr)
    {
        created = QueryProcessCreateTicks(query);
        CloseHandle(query);
    }

    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        auto it = LoggingEnabledPids.find(pid);
        if (it != LoggingEnabledPids.end())
        {
            if (created != 0 && it->second == created)
            {
                return;
            }
            if (created == 0 && it->second == 0)
            {
                return;
            }
        }
    }

    bool enabled = TryEnableLoggingUsermode(pid, KNDBG_PROCESS_LOG_DEFAULT);
    if (!enabled)
    {
        DeviceClient* device = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
        }
        if (device != nullptr && device->IsOpen())
        {
            uint32_t applied = 0;
            uint32_t infoClass = 0;
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
        }
    }

    if (enabled)
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
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
    }
    else
    {
        LoggingFailedCount.fetch_add(1);
    }
}

void KernelMonitor::PruneStalePromotedWatches()
{
    std::vector<std::wstring> names;
    std::unordered_set<uint32_t> promoted;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        names = WatchNamesLower;
        promoted = WatchPromotedPids;
    }
    if (promoted.empty())
    {
        return;
    }

    bool hasWildcard = false;
    for (const std::wstring& name : names)
    {
        if (WatchTokenIsWildcard(name))
        {
            hasWildcard = true;
            break;
        }
    }

    std::unordered_set<uint32_t> liveSet;
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
    }
    else
    {
        std::vector<uint32_t> live;
        if (!CollectToolhelpPidsByName(names, &live))
        {
            return;
        }
        liveSet.insert(live.begin(), live.end());
    }

    std::lock_guard<std::mutex> lock(WatchMutex);
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
        if (WatchExplicitPids.count(pid) == 0)
        {
            WatchPids.erase(pid);
        }
    }

    std::vector<uint32_t> logging;
    logging.reserve(LoggingEnabledPids.size());
    for (const auto& entry : LoggingEnabledPids)
    {
        logging.push_back(entry.first);
    }
    for (uint32_t pid : logging)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process != nullptr)
        {
            const uint64_t created = QueryProcessCreateTicks(process);
            CloseHandle(process);
            auto it = LoggingEnabledPids.find(pid);
            if (it != LoggingEnabledPids.end() &&
                created != 0 &&
                it->second != 0 &&
                created != it->second)
            {
                LoggingEnabledPids.erase(it);
                if (LoggingEnabledCount.load() > 0)
                {
                    LoggingEnabledCount.fetch_sub(1);
                }
            }
            continue;
        }
        if (GetLastError() != ERROR_INVALID_PARAMETER)
        {
            continue;
        }
        LoggingEnabledPids.erase(pid);
        if (LoggingEnabledCount.load() > 0)
        {
            LoggingEnabledCount.fetch_sub(1);
        }
    }
}

void KernelMonitor::EnableLoggingForWatchTargets()
{
    std::vector<uint32_t> pids;
    std::vector<std::wstring> names;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        pids.assign(WatchPids.begin(), WatchPids.end());
        names = WatchNamesLower;
    }

    std::vector<uint32_t> namedPids;
    CollectToolhelpPidsByName(names, &namedPids);
    pids.insert(pids.end(), namedPids.begin(), namedPids.end());

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

        if (symbols->Modules().empty())
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
        std::lock_guard<std::mutex> logLock(LogMutex);
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

        DWORD written = 0;
        if (!WriteFile(
                LogHandle,
                utf8.data(),
                static_cast<DWORD>(utf8.size()),
                &written,
                nullptr))
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
            DWORD written = 0;
            if (!WriteFile(handle, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr))
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
    }
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
    std::lock_guard<std::mutex> lock(WatchMutex);
    WatchExplicitPids.erase(pid);
    WatchPromotedPids.erase(pid);
    return WatchPids.erase(pid) != 0;
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
            {
                std::lock_guard<std::mutex> lock(WatchMutex);
                WatchPids.insert(pid);
                WatchPromotedPids.insert(pid);
            }
            EnableLoggingForPid(pid);
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
        LARGE_INTEGER size = {};
        if (GetFileSizeEx(LogHandle, &size))
        {
            LogCurrentBytes = static_cast<uint64_t>(size.QuadPart);
            SetFilePointer(LogHandle, 0, nullptr, FILE_END);
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
        if (!KmonPathLooksLikeSys(L"\\SystemRoot\\cheat.sys"))
        {
            break;
        }
        if (!KmonTaskLooksLikeDriverObjectLoad(L"KERNEL_THREATINT_TASK_DRIVEROBJECTLOAD"))
        {
            break;
        }
        if (!KmonTaskLooksLikeRemoteInject(L"WriteVM"))
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

        TimelineEvent liveInbox = {};
        liveInbox.Action = L"image-load";
        liveInbox.ProcessId = 0;
        liveInbox.Entity = L"\\SystemRoot\\System32\\drivers\\mapped.sys";
        liveInbox.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(liveInbox, &classified) || classified.Kind != L"driver.image_only")
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
        if (!KmonClassifyLiveEvent(liveUserPidDrop, &classified) ||
            classified.Kind != L"driver.drop_load")
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
        if (!KmonWatchMatches(dropEvent, emptyWatch))
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
        if (KmonWatchMatches(inboxEvent, emptyWatch))
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

        ok = true;
    } while (false);

    return ok;
}
