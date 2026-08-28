// Lab-only positive-control process for !kmon user-mode hostility.
// Operates on copies of this binary only. It does not resume a replaced
// image and does not target a third-party or inbox Windows process.

#include <Windows.h>
#include <Psapi.h>
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    constexpr uint32_t kHoldSecondsDefault = 45;

    using NtQueryInformationProcessFn =
        LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtUnmapViewOfSectionFn = LONG(NTAPI*)(HANDLE, PVOID);
    using NtCreateSectionFn =
        LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    using NtMapViewOfSectionFn = LONG(NTAPI*)(
        HANDLE,
        HANDLE,
        PVOID*,
        ULONG_PTR,
        SIZE_T,
        PLARGE_INTEGER,
        PSIZE_T,
        DWORD,
        ULONG,
        ULONG);

    struct ProcessBasicInformation
    {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    };

    std::wstring SelfPath()
    {
        wchar_t buf[32768] = {};
        DWORD n = GetModuleFileNameW(nullptr, buf, ARRAYSIZE(buf));
        if (n == 0)
        {
            return std::wstring();
        }
        return std::wstring(buf, n);
    }

    std::wstring FixtureDir()
    {
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(ARRAYSIZE(temp), temp);
        std::wstring dir = temp;
        dir += L"kn-live-dbg-kmon";
        CreateDirectoryW(dir.c_str(), nullptr);
        return dir;
    }

    std::wstring NotepadCopyPath()
    {
        return FixtureDir() + L"\\notepad.exe";
    }

    bool UnlinkPathNow(const std::wstring& path)
    {
        HANDLE file = CreateFileW(
            path.c_str(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            FILE_DISPOSITION_INFO_EX disp = {};
            disp.Flags = FILE_DISPOSITION_FLAG_DELETE |
                FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
            const BOOL posix = SetFileInformationByHandle(
                file,
                FileDispositionInfoEx,
                &disp,
                sizeof(disp));
            CloseHandle(file);
            if (posix && GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                return true;
            }
        }
        DeleteFileW(path.c_str());
        return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;
    }

    bool WritePidFile(uint32_t pid)
    {
        std::wstring path = FixtureDir() + L"\\artifact.pid";
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
            return false;
        }
        char line[64] = {};
        int n = sprintf_s(line, "%u\n", pid);
        DWORD written = 0;
        WriteFile(handle, line, static_cast<DWORD>(n), &written, nullptr);
        CloseHandle(handle);
        return true;
    }

    void Announce(uint32_t pid, const wchar_t* scenario)
    {
        WritePidFile(pid);
        std::wprintf(L"KMON_FIXTURE pid=%u scenario=%s image=%s\n",
            pid,
            scenario,
            SelfPath().c_str());
        std::fflush(stdout);
    }

    void HoldSeconds(uint32_t seconds)
    {
        if (seconds == 0)
        {
            Sleep(INFINITE);
            return;
        }
        Sleep(seconds * 1000);
    }

    HMODULE Ntdll()
    {
        return GetModuleHandleW(L"ntdll.dll");
    }

    template <typename T>
    T NtdllProc(const char* name)
    {
        HMODULE ntdll = Ntdll();
        if (ntdll == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<T>(GetProcAddress(ntdll, name));
    }

    uint8_t* ImageBase()
    {
        return reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    }

    bool ParseSelfExec(uint32_t* execRva, uint32_t* stampRva, uint32_t* execVirtSize = nullptr)
    {
        bool ok = false;
        do
        {
            if (execRva == nullptr)
            {
                break;
            }
            *execRva = 0x1000;
            if (stampRva != nullptr)
            {
                *stampRva = 0;
            }
            if (execVirtSize != nullptr)
            {
                *execVirtSize = 0;
            }
            uint8_t* base = ImageBase();
            if (base == nullptr || base[0] != 'M' || base[1] != 'Z')
            {
                break;
            }
            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, base, sizeof(dos));
            if (dos.e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos.e_lfanew > 0x1000)
            {
                break;
            }
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos.e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                break;
            }
            if (stampRva != nullptr)
            {
                *stampRva = static_cast<uint32_t>(
                    dos.e_lfanew + 4 + offsetof(IMAGE_FILE_HEADER, TimeDateStamp));
            }
            const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
            for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            {
                if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                {
                    *execRva = section[i].VirtualAddress;
                    if (execVirtSize != nullptr)
                    {
                        uint32_t virt = section[i].Misc.VirtualSize;
                        uint32_t raw = section[i].SizeOfRawData;
                        uint32_t committed = virt;
                        if (committed == 0 || (raw != 0 && raw < committed))
                        {
                            committed = raw;
                        }
                        *execVirtSize = committed;
                    }
                    ok = true;
                    break;
                }
            }
        } while (false);
        return ok;
    }

    bool PatchCurrentProcessBytes(uint8_t* address, const void* data, size_t length)
    {
        bool ok = false;
        DWORD oldProtect = 0;
        do
        {
            if (address == nullptr || data == nullptr || length == 0)
            {
                break;
            }
            if (!VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                break;
            }
            std::memcpy(address, data, length);
            FlushInstructionCache(GetCurrentProcess(), address, length);
            DWORD ignored = 0;
            VirtualProtect(address, length, oldProtect, &ignored);
            ok = true;
        } while (false);
        return ok;
    }

    bool ApplyOverwrite()
    {
        uint32_t execRva = 0x1000;
        uint32_t execVirt = 0;
        if (!ParseSelfExec(&execRva, nullptr, &execVirt))
        {
            return false;
        }
        uint8_t* text = ImageBase() + execRva;
        uint8_t patch[64];
        std::memset(patch, 0x90, sizeof(patch));
        if (!PatchCurrentProcessBytes(text, patch, sizeof(patch)))
        {
            return false;
        }
        if (execVirt > 0x1000)
        {
            const uint32_t remain = execVirt - 0x1000;
            const size_t n = (remain < sizeof(patch)) ? remain : sizeof(patch);
            if (n > 0 &&
                !PatchCurrentProcessBytes(text + 0x1000, patch, n) &&
                n == sizeof(patch))
            {
                return false;
            }
        }
        return true;
    }

    bool ApplyStamp()
    {
        uint32_t execRva = 0;
        uint32_t stampRva = 0;
        if (!ParseSelfExec(&execRva, &stampRva) || stampRva == 0)
        {
            return false;
        }
        uint32_t stamp = 0x44664466;
        return PatchCurrentProcessBytes(ImageBase() + stampRva, &stamp, sizeof(stamp));
    }

    bool ApplyNoMz()
    {
        uint8_t zeros[2] = { 0, 0 };
        return PatchCurrentProcessBytes(ImageBase(), zeros, sizeof(zeros));
    }

    bool ApplyOrphanPrivate()
    {
        void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (page == nullptr)
        {
            return false;
        }
        uint8_t* bytes = static_cast<uint8_t*>(page);
        std::memset(bytes, 0, 0x1000);
        bytes[0] = 'M';
        bytes[1] = 'Z';
        uint32_t pe = IMAGE_NT_SIGNATURE;
        std::memcpy(bytes + 0x80, &pe, sizeof(pe));
        DWORD old = 0;
        VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old);
        return true;
    }

    std::vector<uint8_t> MinimalPeImage()
    {
        std::vector<uint8_t> pe(0x400, 0);
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        std::memcpy(pe.data(), &dos, sizeof(dos));
        uint32_t sig = IMAGE_NT_SIGNATURE;
        std::memcpy(pe.data() + 0x80, &sig, sizeof(sig));
        IMAGE_FILE_HEADER fh = {};
        fh.Machine = IMAGE_FILE_MACHINE_AMD64;
        fh.NumberOfSections = 1;
        fh.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        fh.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
        std::memcpy(pe.data() + 0x84, &fh, sizeof(fh));
        IMAGE_OPTIONAL_HEADER64 opt = {};
        opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt.AddressOfEntryPoint = 0x200;
        opt.ImageBase = 0x180000000ull;
        opt.SectionAlignment = 0x1000;
        opt.FileAlignment = 0x200;
        opt.MajorSubsystemVersion = 6;
        opt.SizeOfImage = 0x2000;
        opt.SizeOfHeaders = 0x200;
        opt.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        opt.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        std::memcpy(pe.data() + 0x84 + sizeof(fh), &opt, sizeof(opt));
        IMAGE_SECTION_HEADER section = {};
        std::memcpy(section.Name, ".text\0\0", 8);
        section.Misc.VirtualSize = 0x200;
        section.VirtualAddress = 0x1000;
        section.SizeOfRawData = 0x200;
        section.PointerToRawData = 0x200;
        section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        const size_t sectionOff = 0x84 + sizeof(fh) + sizeof(IMAGE_OPTIONAL_HEADER64);
        if (sectionOff + sizeof(section) <= pe.size())
        {
            std::memcpy(pe.data() + sectionOff, &section, sizeof(section));
        }
        return pe;
    }

    bool ApplyOrphanImage()
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;
        HANDLE section = nullptr;
        do
        {
            std::wstring path = FixtureDir() + L"\\orphan.bin";
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }
            std::vector<uint8_t> pe = MinimalPeImage();
            DWORD written = 0;
            if (!WriteFile(file, pe.data(), static_cast<DWORD>(pe.size()), &written, nullptr))
            {
                break;
            }
            FILE_DISPOSITION_INFO disp = {};
            disp.DeleteFile = TRUE;
            SetFileInformationByHandle(file, FileDispositionInfo, &disp, sizeof(disp));

            auto createSection = NtdllProc<NtCreateSectionFn>("NtCreateSection");
            auto mapView = NtdllProc<NtMapViewOfSectionFn>("NtMapViewOfSection");
            if (createSection == nullptr || mapView == nullptr)
            {
                break;
            }
            LONG status = createSection(
                &section,
                SECTION_ALL_ACCESS,
                nullptr,
                nullptr,
                PAGE_EXECUTE_READ,
                SEC_IMAGE,
                file);
            if (status < 0 || section == nullptr)
            {
                break;
            }
            PVOID base = nullptr;
            SIZE_T view = 0;
            status = mapView(
                section,
                GetCurrentProcess(),
                &base,
                0,
                0,
                nullptr,
                &view,
                1,
                0,
                PAGE_EXECUTE_READ);
            if (status < 0 || base == nullptr)
            {
                break;
            }
            ok = true;
        } while (false);
        if (section != nullptr)
        {
            CloseHandle(section);
        }
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
        return ok;
    }

    bool CopySelfToNotepad(std::wstring* outPath)
    {
        bool ok = false;
        do
        {
            if (outPath == nullptr)
            {
                break;
            }
            std::wstring src = SelfPath();
            std::wstring dst = NotepadCopyPath();
            if (src.empty())
            {
                break;
            }
            for (int attempt = 0; attempt < 25; ++attempt)
            {
                DeleteFileW(dst.c_str());
                if (CopyFileW(src.c_str(), dst.c_str(), FALSE))
                {
                    *outPath = dst;
                    ok = true;
                    break;
                }
                Sleep(100);
            }
        } while (false);
        return ok;
    }

    bool SpawnChild(const std::wstring& image, const wchar_t* scenario, uint32_t seconds, uint32_t* pid)
    {
        bool ok = false;
        do
        {
            if (pid != nullptr)
            {
                *pid = 0;
            }
            std::wstring cmd = L"\"" + image + L"\" /child " + scenario +
                L" /seconds " + std::to_wstring(seconds);
            STARTUPINFOW si = {};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
            cmdBuf.push_back(0);
            if (!CreateProcessW(
                    image.c_str(),
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
                break;
            }
            CloseHandle(pi.hThread);
            // Child applies the scenario then holds. A fast exit means the
            // scenario failed. Keep this wait short so /seconds 1 is not
            // mistaken for a failed child.
            const DWORD wait = WaitForSingleObject(pi.hProcess, 200);
            if (wait == WAIT_OBJECT_0)
            {
                CloseHandle(pi.hProcess);
                break;
            }
            if (pid != nullptr)
            {
                *pid = pi.dwProcessId;
            }
            CloseHandle(pi.hProcess);
            ok = true;
        } while (false);
        return ok;
    }

    bool ReplaceMainImage(uint32_t seconds)
    {
        bool ok = false;
        HANDLE process = nullptr;
        HANDLE thread = nullptr;
        do
        {
            std::wstring image;
            if (!CopySelfToNotepad(&image))
            {
                std::fwprintf(stderr, L"copy self failed\n");
                break;
            }
            STARTUPINFOW si = {};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi = {};
            std::wstring cmd = L"\"" + image + L"\" /child hold /seconds " + std::to_wstring(seconds);
            std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
            cmdBuf.push_back(0);
            if (!CreateProcessW(
                    image.c_str(),
                    cmdBuf.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &si,
                    &pi))
            {
                std::fwprintf(stderr, L"CreateProcess suspended failed\n");
                break;
            }
            process = pi.hProcess;
            thread = pi.hThread;

            auto query = NtdllProc<NtQueryInformationProcessFn>("NtQueryInformationProcess");
            auto unmap = NtdllProc<NtUnmapViewOfSectionFn>("NtUnmapViewOfSection");
            if (query == nullptr || unmap == nullptr)
            {
                break;
            }
            ProcessBasicInformation pbi = {};
            ULONG ret = 0;
            if (query(process, 0, &pbi, sizeof(pbi), &ret) < 0 || pbi.PebBaseAddress == nullptr)
            {
                break;
            }
            uint64_t imageBase = 0;
            SIZE_T read = 0;
            if (!ReadProcessMemory(
                    process,
                    reinterpret_cast<uint8_t*>(pbi.PebBaseAddress) + 0x10,
                    &imageBase,
                    sizeof(imageBase),
                    &read) ||
                imageBase == 0)
            {
                break;
            }
            if (unmap(process, reinterpret_cast<PVOID>(imageBase)) < 0)
            {
                std::fwprintf(stderr, L"NtUnmapViewOfSection failed\n");
                break;
            }
            LPVOID fresh = VirtualAllocEx(
                process,
                reinterpret_cast<LPVOID>(imageBase),
                0x10000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            if (fresh == nullptr ||
                reinterpret_cast<uint64_t>(fresh) != imageBase)
            {
                std::fwprintf(stderr, L"VirtualAllocEx at ImageBase failed\n");
                break;
            }
            std::vector<uint8_t> pe(0x1000, 0);
            pe[0] = 'M';
            pe[1] = 'Z';
            uint32_t sig = IMAGE_NT_SIGNATURE;
            std::memcpy(pe.data() + 0x80, &sig, sizeof(sig));
            SIZE_T written = 0;
            if (!WriteProcessMemory(process, fresh, pe.data(), pe.size(), &written))
            {
                break;
            }
            // Leave the process suspended. This fixture never resumes.
            WritePidFile(pi.dwProcessId);
            std::wprintf(
                L"KMON_FIXTURE pid=%u scenario=replace-main image=%s\n",
                pi.dwProcessId,
                image.c_str());
            std::fflush(stdout);
            HoldSeconds(seconds);
            ok = true;
        } while (false);
        if (process != nullptr)
        {
            TerminateProcess(process, 0);
            WaitForSingleObject(process, 5000);
            CloseHandle(process);
        }
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
        return ok;
    }

    bool RunChild(const std::wstring& scenario, uint32_t seconds)
    {
        bool ok = false;
        if (scenario == L"overwrite")
        {
            ok = ApplyOverwrite();
        }
        else if (scenario == L"stamp")
        {
            ok = ApplyStamp();
        }
        else if (scenario == L"nomz")
        {
            ok = ApplyNoMz();
        }
        else if (scenario == L"orphan-private")
        {
            ok = ApplyOrphanPrivate();
        }
        else if (scenario == L"orphan-image")
        {
            ok = ApplyOrphanImage();
        }
        else if (scenario == L"hold" || scenario == L"masquerade" || scenario == L"ghost")
        {
            ok = true;
        }
        if (ok)
        {
            Announce(GetCurrentProcessId(), scenario.c_str());
            HoldSeconds(seconds);
        }
        return ok;
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::wstring scenario;
    bool child = false;
    uint32_t seconds = kHoldSecondsDefault;
    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];
        if (arg == L"/child" && i + 1 < argc)
        {
            child = true;
            scenario = argv[++i];
            continue;
        }
        if (arg == L"/seconds" && i + 1 < argc)
        {
            seconds = static_cast<uint32_t>(wcstoul(argv[++i], nullptr, 10));
            continue;
        }
        if (!arg.empty() && arg[0] == L'/')
        {
            scenario = arg.substr(1);
        }
    }

    if (scenario.empty() || scenario == L"help")
    {
        std::wprintf(L"KnLiveDbgKmonTarget lab fixture. Copies of this binary only.\n");
        std::wprintf(L"  /masquerade       temp notepad.exe copy (process.masquerade)\n");
        std::wprintf(L"  /overwrite        patch own .text (exe_cow / exe_text)\n");
        std::wprintf(L"  /stamp            patch PE TimeDateStamp (hollow)\n");
        std::wprintf(L"  /nomz             wipe MZ at ImageBase (exe_no_mz)\n");
        std::wprintf(L"  /orphan-private   private RX page with MZ (exe_orphan_private)\n");
        std::wprintf(L"  /orphan-image     delete-pending SEC_IMAGE map (exe_orphan_image)\n");
        std::wprintf(L"  /replace-main     suspended self-copy, unmap EXE, private MZ (exe_private)\n");
        std::wprintf(L"  /ghost            running image then delete the file (ghost)\n");
        std::wprintf(L"  /seconds N        hold time (default 45; 0 = until killed)\n");
        return 0;
    }

    if (child)
    {
        return RunChild(scenario, seconds) ? 0 : 1;
    }

    if (scenario == L"replace-main")
    {
        return ReplaceMainImage(seconds) ? 0 : 1;
    }

    std::wstring image;
    if (!CopySelfToNotepad(&image))
    {
        std::fwprintf(stderr, L"failed to copy fixture to %s\n", NotepadCopyPath().c_str());
        return 1;
    }

    uint32_t pid = 0;
    if (scenario == L"ghost")
    {
        if (!SpawnChild(image, L"ghost", seconds, &pid))
        {
            std::fwprintf(stderr, L"spawn failed\n");
            return 1;
        }
        bool unlinked = false;
        for (int attempt = 0; attempt < 25; ++attempt)
        {
            if (UnlinkPathNow(image))
            {
                unlinked = true;
                break;
            }
            Sleep(100);
        }
        if (!unlinked)
        {
            std::fwprintf(
                stderr,
                L"ghost: file still present (delete-pending). kmon ghost needs the path gone.\n");
            HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
            if (proc != nullptr)
            {
                TerminateProcess(proc, 0);
                WaitForSingleObject(proc, 5000);
                CloseHandle(proc);
            }
            return 1;
        }
        WritePidFile(pid);
        std::wprintf(L"KMON_FIXTURE pid=%u scenario=ghost image=%s\n", pid, image.c_str());
        std::fflush(stdout);
        HoldSeconds(seconds);
        HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (proc != nullptr)
        {
            TerminateProcess(proc, 0);
            WaitForSingleObject(proc, 5000);
            CloseHandle(proc);
        }
        return 0;
    }

    if (!SpawnChild(image, scenario.c_str(), seconds, &pid))
    {
        std::fwprintf(stderr, L"spawn failed\n");
        return 1;
    }
    WritePidFile(pid);
    std::wprintf(L"KMON_FIXTURE pid=%u scenario=%s image=%s\n",
        pid,
        scenario.c_str(),
        image.c_str());
    std::fflush(stdout);
    HoldSeconds(seconds);
    HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (proc != nullptr)
    {
        TerminateProcess(proc, 0);
        WaitForSingleObject(proc, 5000);
        CloseHandle(proc);
    }
    return 0;
}
