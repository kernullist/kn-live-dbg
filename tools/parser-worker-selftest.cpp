#include "../user/ParserWorkerProcess.h"
#include <TlHelp32.h>
#include <sddl.h>
#include <iostream>
#include <thread>

namespace
{
    unsigned Passed = 0, Failed = 0;
#ifdef KN_PARSER_WORKER_ASAN
    constexpr DWORD ExpectedCrashExit = 1;
#else
    constexpr DWORD ExpectedCrashExit = EXCEPTION_ACCESS_VIOLATION;
#endif

    void Check(bool ok, const char* name)
    {
        if (ok)
        {
            ++Passed;
        }
        else
        {
            ++Failed;
            std::cerr << "[parser.worker] FAIL " << name << "\n";
        }
    }

    bool Write(const char* text, size_t size)
    {
        DWORD written = 0;
        return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, static_cast<DWORD>(size), &written, nullptr) && written == size;
    }

    int Child(int argc, wchar_t** argv)
    {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        if (argc < 3 || !IsRestrictedParserWorker())
        {
            return 90;
        }
        const std::wstring mode(argv[2]);
        if (mode == L"ok")
        {
            wchar_t marker[64]{};
            if (argc != 5 || std::wstring(argv[3]) != L"space and \"quote\" trailing\\" || std::wstring(argv[4]) != L"" ||
                GetEnvironmentVariableW(L"KNSCHEMA_TEST_MARKER", marker, static_cast<DWORD>(std::size(marker))) != 0)
            {
                return 91;
            }
            return Write("owned_worker_ok", 15) ? 0 : 92;
        }
        if (mode == L"hang")
        {
            if (argc == 4)
            {
                HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]);
                if (ready == nullptr || !SetEvent(ready))
                {
                    return 101;
                }
                CloseHandle(ready);
            }
            Sleep(INFINITE);
            return 93;
        }
        if (mode == L"crash")
        {
            RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, nullptr);
            return 94;
        }
        if (mode == L"exit")
        {
            Write("incomplete", 10);
            return 17;
        }
        if (mode == L"flood")
        {
            const std::string block(8192, 'x');
            while (Write(block.data(), block.size()))
            {
            }
            return 95;
        }
        if (mode == L"memory")
        {
            auto* memory = VirtualAlloc(nullptr, 1024ull * 1024 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (memory != nullptr)
            {
                VirtualFree(memory, 0, MEM_RELEASE);
                return 96;
            }
            return Write("memory_denied", 13) ? 0 : 97;
        }
        if (mode == L"spawn")
        {
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            PROCESS_INFORMATION process{};
            std::wstring command = L"\"" + std::wstring(argv[0]) + L"\" --child hang";
            const bool created = CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                nullptr, nullptr, &startup, &process) != FALSE;
            if (created)
            {
                TerminateProcess(process.hProcess, 98);
                WaitForSingleObject(process.hProcess, 5000);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                return 98;
            }
            return Write("spawn_denied", 12) ? 0 : 99;
        }
        if (mode == L"handle" && argc == 4)
        {
            const auto event = reinterpret_cast<HANDLE>(_wcstoui64(argv[3], nullptr, 10));
            SetEvent(event);
            return 0;
        }
        if (mode == L"parent-access" && argc == 4)
        {
            HANDLE parent = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                FALSE, wcstoul(argv[3], nullptr, 10));
            if (parent != nullptr)
            {
                CloseHandle(parent);
                return 102;
            }
            return Write("parent_write_denied", 19) ? 0 : 103;
        }
        return 100;
    }

    void ParentDeath(const std::wstring& executable)
    {
        const auto eventName = L"Local\\KnSchemaReady-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;AU)S:(ML;;NW;;;LW)",
            SDDL_REVISION_1, &descriptor, nullptr))
        {
            Check(false, "owned ready event security created");
            return;
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        HANDLE ready = CreateEventW(&security, TRUE, FALSE, eventName.c_str());
        LocalFree(descriptor);
        if (ready == nullptr)
        {
            Check(false, "owned ready event created");
            return;
        }
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION supervisor{};
        std::wstring command = L"\"" + executable + L"\" --supervise " + eventName;
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &supervisor))
        {
            Check(false, "owned supervisor starts");
            CloseHandle(ready);
            return;
        }
        Check(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0, "worker reaches restricted entry before parent interruption");
        HANDLE child = nullptr;
        const auto deadline = GetTickCount64() + 5000;
        while (child == nullptr && GetTickCount64() < deadline)
        {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                if (Process32FirstW(snapshot, &entry))
                {
                    do
                    {
                        if (entry.th32ParentProcessID == supervisor.dwProcessId)
                        {
                            child = OpenProcess(SYNCHRONIZE, FALSE, entry.th32ProcessID);
                            break;
                        }
                    }
                    while (Process32NextW(snapshot, &entry));
                }
                CloseHandle(snapshot);
            }
            if (child == nullptr)
            {
                Sleep(20);
            }
        }
        Check(child != nullptr, "owned worker observed under supervisor");
        Check(TerminateProcess(supervisor.hProcess, ERROR_PROCESS_ABORTED) != FALSE &&
            WaitForSingleObject(supervisor.hProcess, 5000) == WAIT_OBJECT_0, "owned supervisor interruption completes");
        if (child != nullptr)
        {
            Check(WaitForSingleObject(child, 5000) == WAIT_OBJECT_0, "atomic job membership cleans worker after parent death");
            CloseHandle(child);
        }
        CloseHandle(supervisor.hThread);
        CloseHandle(supervisor.hProcess);
        CloseHandle(ready);
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && std::wstring(argv[1]) == L"--child")
    {
        return Child(argc, argv);
    }
    wchar_t path[32768]{};
    const auto length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (length == 0 || length >= std::size(path))
    {
        return 2;
    }
    ParserWorkerRequest request;
    request.Executable.assign(path, length);
    if (argc == 3 && std::wstring(argv[1]) == L"--supervise")
    {
        request.Arguments = {L"--child", L"hang", argv[2]};
        RunParserWorker(request);
        return 0;
    }
    Check(!IsRestrictedParserWorker(), "ordinary parent is not an internal worker");
    SetEnvironmentVariableW(L"KNSCHEMA_TEST_MARKER", L"synthetic_parent_only");
    request.Arguments = {L"--child", L"ok", L"space and \"quote\" trailing\\", L""};
    auto result = RunParserWorker(request);
    if (result.Status != L"exited")
    {
        std::wcerr << L"[parser.worker] startup=" << result.Status << L" error=" << result.Error << L" exit=" << result.ExitCode << L"\n";
    }
    Check(result.Status == L"exited" && result.Output == "owned_worker_ok" && result.ProcessId != 0,
        "restricted private-desktop worker preserves argv and strips inherited environment");
    SetEnvironmentVariableW(L"KNSCHEMA_TEST_MARKER", nullptr);
    for (const auto* mode : {L"exit", L"crash", L"memory", L"spawn"})
    {
        request.Arguments = {L"--child", mode};
        result = RunParserWorker(request);
        std::wcout << L"[parser.worker.control] mode=" << mode << L" status=" << result.Status << L" exit=" << result.ExitCode << L"\n";
        if (std::wstring(mode) == L"exit" || std::wstring(mode) == L"crash")
        {
            Check(result.Status == L"worker_failed" && result.Output.empty() &&
                result.ExitCode == (std::wstring(mode) == L"exit" ? 17u : ExpectedCrashExit),
                "worker failure discards partial output and preserves parent");
        }
        else
        {
            Check(result.Status == L"exited" && result.Output == (std::wstring(mode) == L"memory" ? "memory_denied" : "spawn_denied"),
                "job denies excessive commit and descendant creation");
        }
    }
    request.Arguments = {L"--child", L"flood"};
    request.OutputLimit = 1024;
    result = RunParserWorker(request);
    Check(result.Status == L"output_limit" && result.Output.empty(), "output flood terminates without partial DTO");
    request.OutputLimit = 2 * 1024 * 1024;
    request.Arguments = {L"--child", L"hang"};
    request.TimeoutMs = 100;
    result = RunParserWorker(request);
    Check(result.Status == L"timeout" && result.Output.empty() && result.ElapsedMs < 6000, "noncooperative worker timeout completes");
    request.TimeoutMs = 60000;
    std::atomic<bool> cancel{false};
    request.Cancellation = &cancel;
    std::thread cancellation([&]()
    {
        Sleep(100);
        cancel = true;
    });
    result = RunParserWorker(request);
    cancellation.join();
    Check(result.Status == L"cancelled" && result.Output.empty(), "running worker cancellation completes");
    result = RunParserWorker(request);
    Check(result.Status == L"cancelled" && result.ProcessId == 0, "cancelled request creates no worker");
    request.Cancellation = nullptr;
    request.Arguments = {L"--child", L"parent-access", std::to_wstring(GetCurrentProcessId())};
    result = RunParserWorker(request);
    Check(result.Status == L"exited" && result.Output == "parent_write_denied", "restricted worker cannot open the parent for mutation");
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE sentinel = CreateEventW(&security, TRUE, FALSE, nullptr);
    request.Arguments = {L"--child", L"handle", std::to_wstring(reinterpret_cast<uintptr_t>(sentinel))};
    result = RunParserWorker(request);
    Check(sentinel != nullptr && result.Status == L"exited" && WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT,
        "unrelated inheritable handle is not inherited by worker");
    CloseHandle(sentinel);
    request.TimeoutMs = 60001;
    Check(RunParserWorker(request).Status == L"invalid_request", "excessive timeout rejected");
    request.TimeoutMs = 60000;
    request.OutputLimit = 0;
    Check(RunParserWorker(request).Status == L"invalid_request", "zero output budget rejected");
    request.OutputLimit = 2 * 1024 * 1024;
    request.Arguments = {std::wstring(32768, L'x')};
    Check(RunParserWorker(request).Status == L"invalid_request", "oversize command rejected");
    ParentDeath(request.Executable);
    std::cout << "[parser.worker] passed=" << Passed << " failed=" << Failed << "\n";
    return Failed == 0 ? 0 : 1;
}
