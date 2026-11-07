#include <WinSock2.h>
#include "../user/ParserWorkerProcess.h"
#include "parser-worker-network.h"
#include "parser-worker-profile.h"
#include "parser-worker-runtime.h"
#include <TlHelp32.h>
#include <sddl.h>
#include <objbase.h>
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

    void TrySignalUnlistedHandle(HANDLE handle)
    {
        // Invalid handle use can raise in the restricted worker. Only this
        // deliberate negative control accepts that specific exception.
        __try { SetEvent(handle); }
        __except (GetExceptionCode() == EXCEPTION_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
    }

    bool MinimalEnvironment()
    {
        const auto environment = GetEnvironmentStringsW();
        if (environment == nullptr) { return false; }
        const wchar_t* allowed[] = {L"LOCALAPPDATA", L"SystemRoot", L"TEMP", L"TMP", L"WINDIR"};
        bool valid = true, seen[5]{}; size_t count = 0;
        std::wstring local, temp, tmp;
        for (const auto* item = environment; *item != L'\0'; item += wcslen(item) + 1)
        {
            const std::wstring entry = item;
            const auto separator = entry.find(L'=');
            const auto name = entry.substr(0, separator);
            bool matched = false;
            for (size_t i = 0; i < std::size(allowed); ++i)
            {
                if (name == allowed[i] && !seen[i]) { seen[i] = true; matched = true; break; }
            }
            valid = valid && matched && separator != std::wstring::npos && separator + 1 < entry.size();
            if (separator != std::wstring::npos)
            {
                if (name == L"LOCALAPPDATA") { local = entry.substr(separator + 1); }
                if (name == L"TEMP") { temp = entry.substr(separator + 1); }
                if (name == L"TMP") { tmp = entry.substr(separator + 1); }
            }
            ++count;
        }
        FreeEnvironmentStringsW(environment);
        // Windows adds profile-local TEMP/TMP when creating an AppContainer.
        return valid && count == 5 && !local.empty() && temp == local + L"\\Temp" && tmp == temp;
    }

    int Child(int argc, wchar_t** argv)
    {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        if (argc < 3 || !IsRestrictedParserWorker())
        {
            return 90;
        }
        const std::wstring mode(argv[2]);
        if (mode == L"network") { return worker_network::Child(argc, argv); }
        if (mode == L"runtime-write")
        {
            wchar_t executable[32768]{};
            if (!GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)))) { return 116; }
            const std::wstring path = executable;
            const auto extra = path.substr(0, path.find_last_of(L'\\') + 1) + L"unapproved-" + std::to_wstring(GetCurrentProcessId()) + L".dll";
            const auto file = CreateFileW(extra.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            const auto error = GetLastError();
            if (file != INVALID_HANDLE_VALUE) { CloseHandle(file); return 117; }
            return error == ERROR_ACCESS_DENIED && Write("runtime_write_denied", 20) ? 0 : 118;
        }
        if (mode == L"ok")
        {
            wchar_t marker[64]{};
            if (argc != 5 || std::wstring(argv[3]) != L"space and \"quote\" trailing\\" || std::wstring(argv[4]) != L"" ||
                GetEnvironmentVariableW(L"KNSCHEMA_TEST_MARKER", marker, static_cast<DWORD>(std::size(marker))) != 0 || !MinimalEnvironment())
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
        if (mode == L"large-index")
        {
            const std::string block(65536, 'i');
            for (size_t i = 0; i < 48; ++i) { if (!Write(block.data(), block.size())) { return 96; } }
            return 0;
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
            TrySignalUnlistedHandle(event);
            return 0;
        }
        if ((mode == L"parent-access" || mode == L"peer-access") && argc == 4)
        {
            const std::vector<DWORD> rights = mode == L"peer-access" ? std::vector<DWORD>{PROCESS_VM_READ, PROCESS_DUP_HANDLE} :
                std::vector<DWORD>{PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_CREATE_THREAD};
            for (const auto access : rights)
            {
                HANDLE target = OpenProcess(access, FALSE, wcstoul(argv[3], nullptr, 10));
                if (target != nullptr) { CloseHandle(target); return 102; }
                if (GetLastError() != ERROR_ACCESS_DENIED) { return 119; }
            }
            const auto output = mode == L"peer-access" ? std::string("peer_read_denied") : std::string("parent_write_denied");
            return Write(output.data(), output.size()) ? 0 : 103;
        }
        return 100;
    }

    HANDLE ReadyEvent(std::wstring* name)
    {
        GUID guid{}; wchar_t text[40]{};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, text, 40)) { return nullptr; }
        *name = L"Local\\KnSchemaReady-" + std::wstring(text);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;AU)(A;;0x100002;;;AC)S:(ML;;NW;;;LW)",
            SDDL_REVISION_1, &descriptor, nullptr))
        {
            return nullptr;
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        HANDLE ready = CreateEventW(&security, TRUE, FALSE, name->c_str());
        LocalFree(descriptor);
        return ready;
    }

    void ParentDeath(const std::wstring& executable)
    {
        std::wstring eventName; HANDLE ready = ReadyEvent(&eventName);
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
        HANDLE waits[] = {ready, supervisor.hProcess};
        Check(WaitForMultipleObjects(2, waits, FALSE, 60000) == WAIT_OBJECT_0, "worker reaches restricted entry before parent interruption");
        HANDLE child = nullptr; DWORD childPid = 0;
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
                            childPid = entry.th32ProcessID;
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
        if (child != nullptr)
        {
            const auto readable = OpenProcess(PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, childPid);
            Check(readable != nullptr, "ordinary parent can inspect the live owned worker");
            if (readable != nullptr) { CloseHandle(readable); }
            ParserWorkerRequest peer; peer.Executable = executable;
            peer.Arguments = {L"--child", L"peer-access", std::to_wstring(childPid)};
            const auto result = RunParserWorker(peer);
            Check(result.Status == L"exited" && result.SandboxVerified && result.Output == "peer_read_denied",
                "distinct worker identity cannot read or duplicate peer handles");
        }
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
    if (argc == 2)
    {
        if (std::wstring(argv[1]) == L"--profile-owner") { return worker_profile::Owner(worker_profile::Kind::Profile); }
        if (std::wstring(argv[1]) == L"--receipt-owner") { return worker_profile::Owner(worker_profile::Kind::Receipt); }
        if (std::wstring(argv[1]) == L"--prepare-owner") { return worker_profile::Owner(worker_profile::Kind::Preparation); }
    }
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
    {
        worker_profile::Handle token;
        Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.Value) &&
            !parser_sandbox::TokenHasNoCapabilities(token.Value) && GetLastError() == ERROR_ACCESS_DENIED,
            "ordinary token is rejected with an explicit access-denied result");
        Check(!parser_sandbox::NetworkPolicyAllowsIsolation(nullptr) && GetLastError() == ERROR_INVALID_SID,
            "invalid network identity is rejected before policy queries");
        request.ProviderFileIndex = 0;
        const auto invalid = RunParserWorker(request);
        Check(invalid.Status == L"invalid_request" && invalid.ProcessId == 0, "out-of-range provider index creates no worker");
        request.ProviderFileIndex = SIZE_MAX;
    }
    SetEnvironmentVariableW(L"KNSCHEMA_TEST_MARKER", L"synthetic_parent_only");
    request.Arguments = {L"--child", L"ok", L"space and \"quote\" trailing\\", L""};
    auto result = RunParserWorker(request);
    if (result.Status != L"exited")
    {
        std::wcerr << L"[parser.worker] startup=" << result.Status << L" error=" << result.Error << L" exit=" << result.ExitCode << L"\n";
    }
    Check(result.Status == L"exited" && result.Output == "owned_worker_ok" && result.ProcessId != 0 && result.SandboxVerified,
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
    request.Arguments = {L"--child", L"large-index"};
    result = RunParserWorker(request);
    Check(result.Status == L"output_limit" && result.Output.empty(), "schema default still rejects a large symbol frame");
    request.OutputLimit = 32 * 1024 * 1024;
    result = RunParserWorker(request);
    Check(result.Status == L"exited" && result.Output == std::string(3 * 1024 * 1024, 'i'), "explicit symbol output budget carries a frame above two MiB");
    request.OutputLimit += 1;
    Check(RunParserWorker(request).Status == L"invalid_request", "symbol output ceiling rejects excessive allocation budget");
    request.OutputLimit = 2 * 1024 * 1024;
    std::wstring readyName; HANDLE ready = ReadyEvent(&readyName);
    Check(ready != nullptr, "owned execution readiness event");
    request.Arguments = {L"--child", L"hang", readyName};
    request.TimeoutMs = 5000;
    result = RunParserWorker(request);
    Check(result.Status == L"timeout" && result.Output.empty() && result.ElapsedMs < 11000 && result.SandboxVerified &&
        ready != nullptr && WaitForSingleObject(ready, 0) == WAIT_OBJECT_0, "observed noncooperative worker timeout completes");
    if (ready != nullptr) { ResetEvent(ready); }
    request.TimeoutMs = 60000;
    std::atomic<bool> cancel{false};
    request.Cancellation = &cancel;
    HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread running([&]() { result = RunParserWorker(request); SetEvent(completed); });
    HANDLE waits[] = {ready, completed};
    const bool observed = ready != nullptr && completed != nullptr && WaitForMultipleObjects(2, waits, FALSE, 60000) == WAIT_OBJECT_0;
    cancel = true; running.join();
    Check(observed && result.Status == L"cancelled" && result.Output.empty() && result.SandboxVerified, "observed running worker cancellation completes");
    if (completed != nullptr) { CloseHandle(completed); }
    if (ready != nullptr) { CloseHandle(ready); }
    result = RunParserWorker(request);
    Check(result.Status == L"cancelled" && result.ProcessId == 0, "cancelled request creates no worker");
    request.Cancellation = nullptr;
    request.Arguments = {L"--child", L"parent-access", std::to_wstring(GetCurrentProcessId())};
    result = RunParserWorker(request);
    Check(result.Status == L"exited" && result.Output == "parent_write_denied", "restricted worker cannot open the parent for mutation");
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE sentinel = CreateEventW(&security, TRUE, FALSE, nullptr);
    Check(sentinel != nullptr && SetEvent(sentinel) && WaitForSingleObject(sentinel, 0) == WAIT_OBJECT_0 && ResetEvent(sentinel),
        "owned sentinel signal positive control");
    request.Arguments = {L"--child", L"handle", std::to_wstring(reinterpret_cast<uintptr_t>(sentinel))};
    result = RunParserWorker(request);
    Check(sentinel != nullptr && result.Status == L"exited" && WaitForSingleObject(sentinel, 0) == WAIT_TIMEOUT,
        "unrelated inheritable handle is not inherited by worker");
    CloseHandle(sentinel);
    worker_runtime::WriteDenial(request.Executable, Check);
    request.TimeoutMs = 60001;
    Check(RunParserWorker(request).Status == L"invalid_request", "excessive timeout rejected");
    request.TimeoutMs = 60000;
    request.OutputLimit = 0;
    Check(RunParserWorker(request).Status == L"invalid_request", "zero output budget rejected");
    request.OutputLimit = 2 * 1024 * 1024;
    request.Arguments = {std::wstring(32768, L'x')};
    Check(RunParserWorker(request).Status == L"invalid_request", "oversize command rejected");
    ParentDeath(request.Executable);
    worker_network::Run(request.Executable, Check);
    worker_profile::Run(request.Executable, worker_profile::Kind::Profile, Check);
    worker_profile::Run(request.Executable, worker_profile::Kind::Receipt, Check);
    worker_profile::Run(request.Executable, worker_profile::Kind::Preparation, Check);
    worker_runtime::Run(request.Executable, Check);
    std::cout << "[parser.worker] passed=" << Passed << " failed=" << Failed << "\n";
    return Failed == 0 ? 0 : 1;
}
