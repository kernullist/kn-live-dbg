#include "../user/SchemaArtifact.h"
#include "../user/SchemaReadStream.h"
#include "../user/ExecutableImage.h"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <userenv.h>
#include <wrl/client.h>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

using Microsoft::WRL::ComPtr;
namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool ok, const char* name)
    { if (ok) { ++Passed; } else { ++Failed; std::cerr << "[approved.file] FAIL " << name << '\n'; } }
    struct Handle
    {
        HANDLE Value = nullptr;
        ~Handle() { if (Value != nullptr && Value != INVALID_HANDLE_VALUE) { CloseHandle(Value); } }
    };
    struct Profile
    {
        std::wstring Name; PSID Sid = nullptr;
        bool Create()
        {
            GUID guid{}; wchar_t text[40]{};
            if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, text, 40)) { return false; }
            Name = L"KnApprovedFileTest-" + std::wstring(text + 1, 36);
            return CreateAppContainerProfile(Name.c_str(), L"Owned approved-file test", L"Temporary test profile", nullptr, 0, &Sid) == S_OK;
        }
        bool Remove()
        {
            if (Sid == nullptr) { return true; }
            const bool ok = DeleteAppContainerProfile(Name.c_str()) == S_OK;
            if (ok) { FreeSid(Sid); Sid = nullptr; }
            return ok;
        }
        ~Profile() { Remove(); if (Sid != nullptr) { FreeSid(Sid); } }
    };
    bool GrantOwnedRuntime(const std::filesystem::path& file, PSID sid)
    {
        // Only the fresh validation directory's copied ASan runtime is changed.
        if (!std::filesystem::exists(file)) { return true; }
        PACL original = nullptr, updated = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (GetNamedSecurityInfoW(file.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
            &original, nullptr, &descriptor) != ERROR_SUCCESS) { return false; }
        EXPLICIT_ACCESSW grant{}; grant.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
        grant.grfAccessMode = GRANT_ACCESS; grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        grant.Trustee.ptstrName = static_cast<LPWSTR>(sid);
        const bool ok = SetEntriesInAclW(1, &grant, original, &updated) == ERROR_SUCCESS &&
            SetNamedSecurityInfoW(const_cast<LPWSTR>(file.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, updated, nullptr) == ERROR_SUCCESS;
        LocalFree(updated); LocalFree(descriptor); return ok;
    }
    std::wstring Quote(const std::wstring& value) { return L"\"" + value + L"\""; }
    int Child(HANDLE source, const std::wstring& path, const std::wstring& expectedHash)
    {
        Handle token; DWORD app = 0, returned = 0;
        Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.Value) &&
            GetTokenInformation(token.Value, TokenIsAppContainer, &app, sizeof(app), &returned) && app == 1,
            "actual AppContainer child");
        Handle named{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)};
        Check(named.Value == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "input path denied under child token");
        Handle reopened{approved_file::Open(source, approved_file::Access::Reopen)};
        Check(reopened.Value == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "reopen reproduces reduced-token rejection");
        SchemaArtifact artifact;
        Check(artifact.OpenHandle(source, 512ull * 1024 * 1024, approved_file::Access::Duplicate) && artifact.Sha256 == expectedHash,
            "approved inherited file hashes without a pathname grant");
        if (artifact.Handle() == INVALID_HANDLE_VALUE) { return 2; }
        DWORD flags = 0, written = 0;
        Check(GetHandleInformation(artifact.Handle(), &flags) && (flags & HANDLE_FLAG_INHERIT) == 0,
            "owned duplicate is not inheritable");
        Check(!WriteFile(artifact.Handle(), "x", 1, &written, nullptr) && written == 0 && !SetEndOfFile(artifact.Handle()),
            "read duplicate cannot write or truncate");
        ComPtr<IStream> first, second, clone;
        Check(SchemaReadStream::Create(source, &first, approved_file::Access::Duplicate) == S_OK &&
            SchemaReadStream::Create(source, &second, approved_file::Access::Duplicate) == S_OK && first && second &&
            first->Clone(&clone) == S_OK && clone, "separate streams and clone retain approved file object");
        if (!first || !second || !clone) { return 3; }
        std::atomic<bool> stop{false}; std::atomic<uint64_t> shifts{0};
        Handle requested{CreateEventW(nullptr, FALSE, FALSE, nullptr)}, ready{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
        if (ready.Value == nullptr || requested.Value == nullptr) { return 4; }
        SetEvent(requested.Value);
        std::thread spoiler([&]() {
            LARGE_INTEGER position{}; position.QuadPart = 113;
            while (!stop.load())
            {
                if (SetFilePointerEx(source, position, nullptr, FILE_BEGIN))
                {
                    ++shifts;
                    if (WaitForSingleObject(requested.Value, 0) == WAIT_OBJECT_0) { SetEvent(ready.Value); }
                }
                SwitchToThread();
            }
        });
        const bool started = WaitForSingleObject(ready.Value, 5000) == WAIT_OBJECT_0;
        const auto before = shifts.load(); bool same = started;
        for (unsigned i = 0; same && i < 1000; ++i)
        {
            // Demand observed writer progress between batches. A fast Release
            // reader must not finish before the writer gets another time slice.
            if (i % 100 == 0 && (!SetEvent(requested.Value) || WaitForSingleObject(ready.Value, 5000) != WAIT_OBJECT_0))
            { same = false; break; }
            for (auto* stream : {first.Get(), second.Get(), clone.Get()})
            {
                char magic[2]{}; ULONG read = 0; LARGE_INTEGER zero{};
                if (stream->Seek(zero, STREAM_SEEK_SET, nullptr) != S_OK || stream->Read(magic, 2, &read) != S_OK ||
                    read != 2 || magic[0] != 'M' || magic[1] != 'Z') { same = false; break; }
            }
            if (i % 100 == 0)
            {
                executable_image::DiskPeMetadata identity;
                if (!artifact.Unchanged() || !executable_image::ReadApprovedDiskPeIdentityHandle(source, &identity, nullptr) ||
                    !identity.HasPdbIdentity || identity.Machine != IMAGE_FILE_MACHINE_AMD64) { same = false; }
            }
        }
        const auto after = shifts.load(); stop = true; spoiler.join();
        Check(started && after > before, "external cursor changes synchronized between read batches");
        Check(same, "streams hashes and PE identity ignore concurrent implicit cursor changes");
        Check(artifact.Unchanged() && artifact.Sha256 == expectedHash, "input bytes remain unchanged");
        std::cout << "[approved.file.child] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed == 0 ? 0 : 1;
    }
    bool RunChild(const std::filesystem::path& executable, Profile& profile, HANDLE source,
        const std::filesystem::path& image, const std::wstring& hash)
    {
        Handle pipeRead, pipeWrite, input, job, process, thread;
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&pipeRead.Value, &pipeWrite.Value, &security, 0) ||
            !SetHandleInformation(pipeRead.Value, HANDLE_FLAG_INHERIT, 0) ||
            !SetHandleInformation(source, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) { return false; }
        input.Value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
        job.Value = CreateJobObjectW(nullptr, nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if (input.Value == INVALID_HANDLE_VALUE || !job.Value ||
            !SetInformationJobObject(job.Value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { return false; }
        SIZE_T bytes = 0; InitializeProcThreadAttributeList(nullptr, 3, 0, &bytes);
        std::vector<uint8_t> storage(bytes);
        const auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(list, 3, 0, &bytes)) { return false; }
        struct AttributeOwner { LPPROC_THREAD_ATTRIBUTE_LIST Value; ~AttributeOwner() { DeleteProcThreadAttributeList(Value); } } attributes{list};
        SECURITY_CAPABILITIES capabilities{}; capabilities.AppContainerSid = profile.Sid;
        HANDLE inherited[] = {source, input.Value, pipeWrite.Value};
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job.Value, sizeof(job.Value), nullptr, nullptr)) { return false; }
        PWSTR local = nullptr; wchar_t windows[MAX_PATH]{};
        if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) { return false; }
        const std::wstring localPath = local; CoTaskMemFree(local);
        if (!GetWindowsDirectoryW(windows, MAX_PATH)) { return false; }
        std::wstring environment = L"LOCALAPPDATA=" + localPath + L'\0' + L"SystemRoot=" + windows + L'\0' + L"WINDIR=" + windows + L'\0' + L'\0';
        std::wstring command = Quote(executable.wstring()) + L" --child " + std::to_wstring(reinterpret_cast<uintptr_t>(source)) +
            L" " + Quote(image.wstring()) + L" " + hash;
        STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = input.Value;
        startup.StartupInfo.hStdOutput = pipeWrite.Value; startup.StartupInfo.hStdError = pipeWrite.Value; startup.lpAttributeList = list;
        PROCESS_INFORMATION info{};
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, environment.data(), windows,
            &startup.StartupInfo, &info))
        { std::cerr << "[approved.file] spawn_error=" << GetLastError() << '\n'; return false; }
        process.Value = info.hProcess; thread.Value = info.hThread;
        CloseHandle(pipeWrite.Value); pipeWrite.Value = nullptr;
        if (WaitForSingleObject(process.Value, 30000) != WAIT_OBJECT_0)
        { TerminateJobObject(job.Value, ERROR_TIMEOUT); WaitForSingleObject(process.Value, 5000); return false; }
        DWORD exit = 1; GetExitCodeProcess(process.Value, &exit);
        char buffer[4096]{}; DWORD read = 0;
        while (ReadFile(pipeRead.Value, buffer, sizeof(buffer), &read, nullptr) && read != 0) { std::cout.write(buffer, read); }
        if (exit != 0) { std::cerr << "[approved.file] child_exit=" << exit << '\n'; }
        return exit == 0;
    }
}
int wmain(int argc, wchar_t** argv)
{
    if (argc == 5 && std::wstring(argv[1]) == L"--child")
    { return Child(reinterpret_cast<HANDLE>(_wcstoui64(argv[2], nullptr, 10)), argv[3], argv[4]); }
    if (argc != 2) { return 2; }
    const auto root = std::filesystem::absolute(argv[1]);
    wchar_t name[32768]{}; if (!GetModuleFileNameW(nullptr, name, 32768)) { return 2; }
    const auto image = root / L"fixture.exe";
    SchemaArtifact original;
    Check(original.Open(image.wstring(), 512ull * 1024 * 1024), "parent fixture lease");
    Profile profile; Check(profile.Create(), "owned temporary AppContainer profile");
    if (!profile.Sid || original.Handle() == INVALID_HANDLE_VALUE) { return 3; }
    Check(GrantOwnedRuntime(root / L"clang_rt.asan_dynamic-x86_64.dll", profile.Sid), "copied runtime executable access only");
    Check(RunChild(name, profile, original.Handle(), image, original.Sha256), "synchronous inherited handle controls");
    Handle async{CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr)};
    Handle completions{async.Value == INVALID_HANDLE_VALUE ? nullptr : CreateIoCompletionPort(async.Value, nullptr, 0x173, 1)};
    Check(completions.Value != nullptr, "owned completion port associated with inherited file object");
    if (completions.Value != nullptr)
    {
        Handle completed{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        OVERLAPPED baseline{}; baseline.hEvent = completed.Value;
        DWORD transferred = 0; char magic[2]{};
        bool read = completed.Value != nullptr && ReadFile(async.Value, magic, 2, &transferred, &baseline) != FALSE;
        if (!read && completed.Value != nullptr && GetLastError() == ERROR_IO_PENDING)
        { read = GetOverlappedResult(async.Value, &baseline, &transferred, TRUE) != FALSE; }
        ULONG_PTR key = 0; OVERLAPPED* packet = nullptr;
        Check(read && transferred == 2 && GetQueuedCompletionStatus(completions.Value, &transferred, &key, &packet, 1000) &&
            key == 0x173 && packet == &baseline, "ordinary overlapped read proves completion-port positive control");
    }
    Check(async.Value != INVALID_HANDLE_VALUE && RunChild(name, profile, async.Value, image, original.Sha256),
        "overlapped inherited handle controls");
    DWORD transferred = 0; ULONG_PTR key = 0; OVERLAPPED* packet = nullptr;
    Check(completions.Value != nullptr && !GetQueuedCompletionStatus(completions.Value, &transferred, &key, &packet, 0) &&
        GetLastError() == WAIT_TIMEOUT && packet == nullptr, "child reads never enqueue stack operations in the parent completion port");
    Handle directory{CreateFileW(root.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
    Handle device{CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr)};
    for (const auto invalid : {static_cast<HANDLE>(nullptr), INVALID_HANDLE_VALUE, directory.Value, device.Value})
    { Check(approved_file::Open(invalid, approved_file::Access::Duplicate) == INVALID_HANDLE_VALUE, "nonregular source rejected before duplication"); }
    DWORD read = 123; char byte = 0;
    Check(!approved_file::ReadAt(original.Handle(), UINT64_MAX, &byte, 1, &read) && read == 0 &&
        !approved_file::ReadAt(original.Handle(), INT64_MAX, &byte, 1, &read), "offset overflow denied");
    Check(profile.Remove(), "owned profile removed after workers exited");
    Check(original.Unchanged(), "parent artifact survived denied mutations");
    std::cout << "[approved.file] passed=" << Passed << " failed=" << Failed << '\n';
    return Failed == 0 ? 0 : 1;
}
