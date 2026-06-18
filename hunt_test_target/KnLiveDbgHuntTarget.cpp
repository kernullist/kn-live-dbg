#include <Windows.h>

#include <cstdint>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    constexpr SIZE_T kPageSize = 0x1000;
    constexpr DWORD kDefaultRunSeconds = 300;

    struct Options
    {
        bool PrivateExec = false;
        bool Rwx = false;
        bool PeLike = false;
        bool WipedPe = false;
        bool Thread = false;
        bool Apc = false;
        bool ModulePatch = false;
        bool Help = false;
        DWORD RunSeconds = kDefaultRunSeconds;
    };

    struct RegionRecord
    {
        void* Base = nullptr;
        SIZE_T Size = 0;
        std::wstring Name;
    };

    HANDLE g_StopEvent = nullptr;
    std::vector<RegionRecord> g_Regions;
    std::vector<HANDLE> g_Threads;

    std::wstring Hex(uint64_t value)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value;
        return stream.str();
    }

    std::wstring Win32ErrorText(const wchar_t* prefix)
    {
        DWORD error = GetLastError();
        std::wstringstream stream;
        stream << prefix << L" gle=" << error;
        return stream.str();
    }

    void PrintUsage()
    {
        std::wcout << L"KnLiveDbgHuntTarget command:\n";
        std::wcout << L"  KnLiveDbgHuntTarget.exe [/all] [/private-exec] [/rwx] [/pe-like] [/wiped-pe] [/thread] [/apc] [/module-patch] [/seconds n]\n";
        std::wcout << L"\n";
        std::wcout << L"notes:\n";
        std::wcout << L"  This is a lab-only positive-control target for !hunt.\n";
        std::wcout << L"  It mutates only its own process and never injects into another process.\n";
        std::wcout << L"  Run KnLiveDbg elevated in another console and execute: !hunt /deep /limit 80\n";
    }

    bool ParseUInt32(const wchar_t* text, DWORD* value)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || value == nullptr || text[0] == L'\0')
            {
                break;
            }

            wchar_t* end = nullptr;
            unsigned long parsed = std::wcstoul(text, &end, 10);
            if (end == text || *end != L'\0' || parsed > 0xfffffffful)
            {
                break;
            }

            *value = static_cast<DWORD>(parsed);
            ok = true;
        } while (false);

        return ok;
    }

    bool ParseOptions(int argc, wchar_t** argv, Options* options)
    {
        bool ok = false;

        do
        {
            if (options == nullptr)
            {
                break;
            }

            bool sawScenario = false;
            for (int index = 1; index < argc; ++index)
            {
                std::wstring arg = argv[index];
                if (arg == L"/?" || arg == L"-?" || arg == L"help" || arg == L"/help")
                {
                    options->Help = true;
                    ok = true;
                    break;
                }
                else if (arg == L"/all")
                {
                    options->PrivateExec = true;
                    options->Rwx = true;
                    options->PeLike = true;
                    options->WipedPe = true;
                    options->Thread = true;
                    options->Apc = true;
                    options->ModulePatch = true;
                    sawScenario = true;
                }
                else if (arg == L"/private-exec")
                {
                    options->PrivateExec = true;
                    sawScenario = true;
                }
                else if (arg == L"/rwx")
                {
                    options->Rwx = true;
                    sawScenario = true;
                }
                else if (arg == L"/pe-like")
                {
                    options->PeLike = true;
                    sawScenario = true;
                }
                else if (arg == L"/wiped-pe")
                {
                    options->WipedPe = true;
                    sawScenario = true;
                }
                else if (arg == L"/thread")
                {
                    options->Thread = true;
                    sawScenario = true;
                }
                else if (arg == L"/apc")
                {
                    options->Apc = true;
                    sawScenario = true;
                }
                else if (arg == L"/module-patch")
                {
                    options->ModulePatch = true;
                    sawScenario = true;
                }
                else if (arg == L"/seconds")
                {
                    if (index + 1 >= argc || !ParseUInt32(argv[index + 1], &options->RunSeconds))
                    {
                        std::wcerr << L"invalid /seconds value\n";
                        break;
                    }
                    ++index;
                }
                else
                {
                    std::wcerr << L"unknown option: " << arg << L"\n";
                    break;
                }

                if (index + 1 == argc)
                {
                    ok = true;
                }
            }

            if (argc == 1)
            {
                ok = true;
            }

            if (!ok)
            {
                break;
            }

            if (options->Help)
            {
                break;
            }

            if (!sawScenario)
            {
                options->PrivateExec = true;
                options->Rwx = true;
                options->PeLike = true;
                options->WipedPe = true;
                options->Thread = true;
                options->Apc = true;
                options->ModulePatch = true;
            }
        } while (false);

        return ok;
    }

    BOOL WINAPI ConsoleHandler(DWORD controlType)
    {
        if (controlType == CTRL_C_EVENT ||
            controlType == CTRL_BREAK_EVENT ||
            controlType == CTRL_CLOSE_EVENT)
        {
            if (g_StopEvent != nullptr)
            {
                SetEvent(g_StopEvent);
            }
            return TRUE;
        }

        return FALSE;
    }

    bool AddRegion(void* base, SIZE_T size, const std::wstring& name)
    {
        bool ok = false;

        do
        {
            if (base == nullptr || size == 0)
            {
                break;
            }

            RegionRecord record = {};
            record.Base = base;
            record.Size = size;
            record.Name = name;
            g_Regions.push_back(record);
            std::wcout << L"region " << name
                       << L" base=" << Hex(reinterpret_cast<uint64_t>(base))
                       << L" size=" << size << L"\n";
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadOwnImageHeaderPage(std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (bytes == nullptr)
            {
                break;
            }

            wchar_t path[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path))) == 0)
            {
                std::wcerr << Win32ErrorText(L"GetModuleFileNameW failed") << L"\n";
                break;
            }

            file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                std::wcerr << Win32ErrorText(L"CreateFileW self image failed") << L"\n";
                break;
            }

            bytes->assign(kPageSize, 0);
            DWORD read = 0;
            if (!ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &read, nullptr) || read < sizeof(IMAGE_DOS_HEADER))
            {
                std::wcerr << Win32ErrorText(L"ReadFile self image failed") << L"\n";
                break;
            }
            bytes->resize(read);
            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool AllocateBytes(const std::wstring& name, const std::vector<uint8_t>& bytes, DWORD finalProtect, void** baseOut)
    {
        bool ok = false;
        void* base = nullptr;

        do
        {
            if (baseOut == nullptr || bytes.empty())
            {
                break;
            }

            base = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"VirtualAlloc failed") << L"\n";
                break;
            }

            SIZE_T copySize = bytes.size() < kPageSize ? bytes.size() : kPageSize;
            std::memcpy(base, bytes.data(), copySize);

            DWORD oldProtect = 0;
            if (!VirtualProtect(base, kPageSize, finalProtect, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect failed") << L"\n";
                break;
            }

            FlushInstructionCache(GetCurrentProcess(), base, kPageSize);
            if (!AddRegion(base, kPageSize, name))
            {
                break;
            }

            *baseOut = base;
            ok = true;
        } while (false);

        if (!ok && base != nullptr)
        {
            VirtualFree(base, 0, MEM_RELEASE);
        }

        return ok;
    }

    bool CreatePrivateExecRegion()
    {
        std::vector<uint8_t> code(kPageSize, 0x90);
        code[0] = 0xc3;
        void* base = nullptr;
        return AllocateBytes(L"private-exec-rx", code, PAGE_EXECUTE_READ, &base);
    }

    bool CreateRwxRegion()
    {
        bool ok = false;
        void* base = nullptr;

        do
        {
            base = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"VirtualAlloc RWX failed") << L"\n";
                break;
            }

            std::memset(base, 0x90, kPageSize);
            static_cast<uint8_t*>(base)[0] = 0xc3;
            FlushInstructionCache(GetCurrentProcess(), base, kPageSize);
            if (!AddRegion(base, kPageSize, L"private-rwx"))
            {
                break;
            }

            ok = true;
        } while (false);

        if (!ok && base != nullptr)
        {
            VirtualFree(base, 0, MEM_RELEASE);
        }

        return ok;
    }

    bool CreatePeLikeRegion(bool wiped)
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> header;
            if (!ReadOwnImageHeaderPage(&header))
            {
                break;
            }

            if (wiped && header.size() >= sizeof(IMAGE_DOS_HEADER))
            {
                IMAGE_DOS_HEADER dos = {};
                std::memcpy(&dos, header.data(), sizeof(dos));
                header[0] = 0;
                header[1] = 0;
                if (dos.e_lfanew > 0 &&
                    static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t) <= header.size())
                {
                    std::memset(header.data() + dos.e_lfanew, 0, sizeof(uint32_t));
                }
            }

            void* base = nullptr;
            ok = AllocateBytes(wiped ? L"wiped-private-pe-rx" : L"private-pe-rx", header, PAGE_EXECUTE_READ, &base);
        } while (false);

        return ok;
    }

    bool BuildSleepLoopCode(std::vector<uint8_t>* code)
    {
        bool ok = false;

        do
        {
            if (code == nullptr)
            {
                break;
            }

            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (kernel32 == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetModuleHandleW kernel32 failed") << L"\n";
                break;
            }

            void* sleepAddress = reinterpret_cast<void*>(GetProcAddress(kernel32, "Sleep"));
            if (sleepAddress == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress Sleep failed") << L"\n";
                break;
            }

            code->clear();
            const uint8_t prefix[] =
            {
                0x48, 0x83, 0xec, 0x28,
                0xb9, 0xe8, 0x03, 0x00, 0x00,
                0x48, 0xb8
            };
            code->insert(code->end(), prefix, prefix + sizeof(prefix));

            uint64_t sleepValue = reinterpret_cast<uint64_t>(sleepAddress);
            for (size_t index = 0; index < sizeof(sleepValue); ++index)
            {
                code->push_back(static_cast<uint8_t>((sleepValue >> (index * 8)) & 0xff));
            }

            const uint8_t suffix[] =
            {
                0xff, 0xd0,
                0x48, 0x83, 0xc4, 0x28,
                0xeb, 0xe5
            };
            code->insert(code->end(), suffix, suffix + sizeof(suffix));
            code->resize(kPageSize, 0x90);
            ok = true;
        } while (false);

        return ok;
    }

    bool CreatePrivateThread()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> code;
            if (!BuildSleepLoopCode(&code))
            {
                break;
            }

            void* base = nullptr;
            if (!AllocateBytes(L"private-thread-start-rx", code, PAGE_EXECUTE_READ, &base))
            {
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(base),
                nullptr,
                0,
                &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread private start failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            std::wcout << L"thread private-start tid=" << threadId
                       << L" start=" << Hex(reinterpret_cast<uint64_t>(base)) << L"\n";
            ok = true;
        } while (false);

        return ok;
    }

    DWORD WINAPI NonAlertableSleeper(void*)
    {
        while (WaitForSingleObject(g_StopEvent, 1000) == WAIT_TIMEOUT)
        {
        }

        return 0;
    }

    bool QueuePrivateApc()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> code(kPageSize, 0x90);
            code[0] = 0xc3;

            void* base = nullptr;
            if (!AllocateBytes(L"private-apc-normal-routine-rx", code, PAGE_EXECUTE_READ, &base))
            {
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(nullptr, 0, NonAlertableSleeper, nullptr, 0, &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread APC sleeper failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(base), thread, 0) == 0)
            {
                std::wcerr << Win32ErrorText(L"QueueUserAPC failed") << L"\n";
                break;
            }

            std::wcout << L"apc queued tid=" << threadId
                       << L" normal=" << Hex(reinterpret_cast<uint64_t>(base)) << L"\n";
            ok = true;
        } while (false);

        return ok;
    }

    bool PatchLoadedFixtureDll()
    {
        bool ok = false;

        do
        {
            HMODULE module = LoadLibraryW(L"KnLiveDbgHuntTargetDll.dll");
            if (module == nullptr)
            {
                std::wcerr << Win32ErrorText(L"LoadLibraryW fixture DLL failed") << L"\n";
                std::wcerr << L"ensure KnLiveDbgHuntTargetDll.dll is next to this executable\n";
                break;
            }

            using ProbeFn = DWORD (WINAPI*)();
            ProbeFn probe = reinterpret_cast<ProbeFn>(GetProcAddress(module, "HuntTargetDllProbe"));
            if (probe == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress HuntTargetDllProbe failed") << L"\n";
                break;
            }

            DWORD before = probe();
            uint8_t* patch = reinterpret_cast<uint8_t*>(probe);
            DWORD oldProtect = 0;
            if (!VirtualProtect(patch, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect DLL patch failed") << L"\n";
                break;
            }

            for (size_t index = 0; index < 8; ++index)
            {
                patch[index] ^= 0x5a;
            }

            FlushInstructionCache(GetCurrentProcess(), patch, 16);
            DWORD ignored = 0;
            VirtualProtect(patch, 16, oldProtect, &ignored);

            std::wcout << L"module-patch dll=KnLiveDbgHuntTargetDll.dll"
                       << L" export=" << Hex(reinterpret_cast<uint64_t>(patch))
                       << L" probe_before=" << before << L"\n";
            ok = true;
        } while (false);

        return ok;
    }

    void PrintExpectedFindings(const Options& options)
    {
        std::wcout << L"\nexpected !hunt reason codes:\n";
        if (options.PrivateExec)
        {
            std::wcout << L"  private_executable_vad\n";
        }
        if (options.Rwx)
        {
            std::wcout << L"  wx_user_vad\n";
        }
        if (options.PeLike)
        {
            std::wcout << L"  private_pe_mapping, private_pe_without_loader_entry\n";
        }
        if (options.WipedPe)
        {
            std::wcout << L"  wiped_pe_header\n";
        }
        if (options.Thread)
        {
            std::wcout << L"  suspicious_thread_start\n";
        }
        if (options.Apc)
        {
            std::wcout << L"  suspicious_apc_routine\n";
        }
        if (options.ModulePatch)
        {
            std::wcout << L"  live_disk_exec_page_mismatch, module_text_mismatch or module_entrypoint_mismatch\n";
        }
        std::wcout << L"\n";
    }

    bool CreateScenarios(const Options& options)
    {
        bool ok = false;

        do
        {
            bool anyFailure = false;

            if (options.PrivateExec && !CreatePrivateExecRegion())
            {
                anyFailure = true;
            }
            if (options.Rwx && !CreateRwxRegion())
            {
                anyFailure = true;
            }
            if (options.PeLike && !CreatePeLikeRegion(false))
            {
                anyFailure = true;
            }
            if (options.WipedPe && !CreatePeLikeRegion(true))
            {
                anyFailure = true;
            }
            if (options.Thread && !CreatePrivateThread())
            {
                anyFailure = true;
            }
            if (options.Apc && !QueuePrivateApc())
            {
                anyFailure = true;
            }
            if (options.ModulePatch && !PatchLoadedFixtureDll())
            {
                anyFailure = true;
            }

            ok = !anyFailure;
        } while (false);

        return ok;
    }
}

int wmain(int argc, wchar_t** argv)
{
    int exitCode = 1;

    do
    {
        Options options = {};
        if (!ParseOptions(argc, argv, &options))
        {
            PrintUsage();
            break;
        }
        if (options.Help)
        {
            PrintUsage();
            exitCode = 0;
            break;
        }

        g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_StopEvent == nullptr)
        {
            std::wcerr << Win32ErrorText(L"CreateEventW failed") << L"\n";
            break;
        }

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        std::wcout << L"KnLiveDbgHuntTarget pid=" << GetCurrentProcessId() << L"\n";
        std::wcout << L"run_seconds=" << options.RunSeconds << L"\n";
        PrintExpectedFindings(options);

        if (!CreateScenarios(options))
        {
            std::wcerr << L"one or more scenarios failed to initialize\n";
            break;
        }

        std::wcout << L"target is ready\n";
        std::wcout << L"run: !hunt /deep /limit 80 /json .\\hunt-target.json\n";
        std::wcout << L"press Ctrl+C to stop this target\n";

        DWORD waitMs = INFINITE;
        if (options.RunSeconds != 0 && options.RunSeconds <= 0xffffffffu / 1000u)
        {
            waitMs = options.RunSeconds * 1000u;
        }
        WaitForSingleObject(g_StopEvent, waitMs);
        exitCode = 0;
    } while (false);

    if (g_StopEvent != nullptr)
    {
        SetEvent(g_StopEvent);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
    }

    for (HANDLE thread : g_Threads)
    {
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
    }

    return exitCode;
}
