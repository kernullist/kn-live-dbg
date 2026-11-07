#pragma once

#include "../user/ParserWorkerSandbox.h"
#include "../user/ParserWorkerProcess.h"
#include <array>

namespace worker_profile
{
    enum class Kind { Profile, Receipt, Preparation };
    struct Handle
    {
        HANDLE Value = nullptr;
        ~Handle() { if (Value != nullptr && Value != INVALID_HANDLE_VALUE) { CloseHandle(Value); } }
    };
    inline std::wstring UserSid()
    {
        Handle token; DWORD bytes = 0;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.Value)) { return {}; }
        GetTokenInformation(token.Value, TokenUser, nullptr, 0, &bytes);
        if (bytes == 0 || bytes > 65536) { return {}; }
        std::vector<uint8_t> data(bytes);
        if (!GetTokenInformation(token.Value, TokenUser, data.data(), bytes, &bytes)) { return {}; }
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text)) { return {}; }
        std::wstring result = text; LocalFree(text); return result;
    }
    inline int Owner(Kind kind)
    {
        parser_sandbox::Profile profile;
        if (!profile.Create(UserSid())) { return 120; }
        std::wstring wideName = profile.Name;
        Handle pending;
        if (kind != Kind::Profile)
        {
            if (!profile.Remove()) { return 123; }
            wideName = parser_sandbox::OwnerKey(); PWSTR local = nullptr;
            if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &local))) { return 124; }
            std::filesystem::path path;
            if (kind == Kind::Receipt) { path = std::filesystem::path(local) / L"KnLiveDbgParserProfiles-v1" / (wideName + L".pending"); }
            else
            {
                const auto root = std::filesystem::path(local) / L"KnLiveDbgParserRuntime-v1";
                const auto directory = root / (L"prepare-" + wideName);
                PSECURITY_DESCRIPTOR descriptor = nullptr;
                const auto result = GetNamedSecurityInfoW(root.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, nullptr, nullptr, &descriptor);
                SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
                const bool created = result == ERROR_SUCCESS && CreateDirectoryW(directory.c_str(), &security);
                LocalFree(descriptor);
                if (!created) { CoTaskMemFree(local); return 127; }
                path = directory / L"worker.exe";
            }
            CoTaskMemFree(local);
            pending.Value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            DWORD written = 0; const wchar_t fragment = L'K';
            if (pending.Value == INVALID_HANDLE_VALUE || !WriteFile(pending.Value, &fragment, sizeof(fragment), &written, nullptr) ||
                written != sizeof(fragment) || !FlushFileBuffers(pending.Value)) { return 125; }
        }
        std::string name;
        for (const auto c : wideName) { if (c > 127) { return 126; } name.push_back(static_cast<char>(c)); }
        DWORD written = 0;
        if (name.size() != 63 || !WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), name.data(), 63, &written, nullptr) || written != 63) { return 121; }
        Sleep(INFINITE); return 122;
    }
    inline bool ReceiptByte(const std::filesystem::path& path, uint8_t* byte, bool write)
    {
        Handle file{CreateFileW(path.c_str(), GENERIC_READ | (write ? GENERIC_WRITE : 0), FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        FILE_ATTRIBUTE_TAG_INFO attributes{}; DWORD transferred = 0;
        if (file.Value == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(file.Value, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) { return false; }
        return write ? (WriteFile(file.Value, byte, 1, &transferred, nullptr) && transferred == 1 && FlushFileBuffers(file.Value)) :
            (ReadFile(file.Value, byte, 1, &transferred, nullptr) && transferred == 1);
    }
    struct ByteRestore
    {
        std::filesystem::path Path; uint8_t Original = 0; bool Changed = false;
        ~ByteRestore() { Restore(); }
        bool Restore()
        {
            if (!Changed) { return true; }
            if (!ReceiptByte(Path, &Original, true)) { return false; }
            Changed = false; return true;
        }
    };
    inline void Run(const std::wstring& executable, Kind kind, void(*check)(bool, const char*))
    {
        Handle pipeRead, pipeWrite, input, job, process, thread;
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&pipeRead.Value, &pipeWrite.Value, &security, 0) || !SetHandleInformation(pipeRead.Value, HANDLE_FLAG_INHERIT, 0))
        { check(false, "profile owner pipe setup"); return; }
        input.Value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
        job.Value = CreateJobObjectW(nullptr, nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if (input.Value == INVALID_HANDLE_VALUE || job.Value == nullptr ||
            !SetInformationJobObject(job.Value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        { check(false, "profile owner lifecycle setup"); return; }
        SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
        std::vector<uint8_t> storage(size);
        const auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(list, 2, 0, &size)) { check(false, "profile owner attribute setup"); return; }
        struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST Value; ~Attributes() { DeleteProcThreadAttributeList(Value); } } attributes{list};
        HANDLE inherited[] = {input.Value, pipeWrite.Value};
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job.Value, sizeof(job.Value), nullptr, nullptr))
        { check(false, "profile owner explicit inheritance"); return; }
        STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = input.Value;
        startup.StartupInfo.hStdOutput = pipeWrite.Value; startup.StartupInfo.hStdError = pipeWrite.Value; startup.lpAttributeList = list;
        PROCESS_INFORMATION created{}; std::wstring command = L"\"" + executable + L"\" " +
            (kind == Kind::Profile ? L"--profile-owner" : kind == Kind::Receipt ? L"--receipt-owner" : L"--prepare-owner");
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &created))
        { check(false, "owned profile creator starts"); return; }
        process.Value = created.hProcess; thread.Value = created.hThread;
        CloseHandle(pipeWrite.Value); pipeWrite.Value = nullptr;
        std::string announced; const auto deadline = GetTickCount64() + 30000;
        while (announced.size() < 63 && GetTickCount64() < deadline)
        {
            DWORD available = 0;
            if (!PeekNamedPipe(pipeRead.Value, nullptr, 0, nullptr, &available, nullptr)) { break; }
            if (available != 0)
            {
                char buffer[128]{}; DWORD read = 0;
                if (!ReadFile(pipeRead.Value, buffer, static_cast<DWORD>((std::min)(sizeof(buffer), static_cast<size_t>(available))), &read, nullptr)) { break; }
                announced.append(buffer, read); if (announced.size() > 63) { break; }
            }
            else if (WaitForSingleObject(process.Value, 10) != WAIT_TIMEOUT) { break; }
        }
        const std::wstring name(announced.begin(), announced.end());
        const bool validName = name.size() == 63 && name.rfind(L"KnP1-", 0) == 0 &&
            name.find_first_not_of(L"KnP-0123456789abcdefABCDEF") == std::wstring::npos;
        PWSTR local = nullptr;
        if (!validName || FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &local)))
        {
            check(false, "profile creation acknowledged before interruption");
            TerminateJobObject(job.Value, ERROR_PROCESS_ABORTED); WaitForSingleObject(process.Value, 5000);
            ParserWorkerRequest cleanup; cleanup.Executable = executable; cleanup.Arguments = {L"--child", L"ok", L"space and \"quote\" trailing\\", L""};
            RunParserWorker(cleanup); return;
        }
        const auto profilePath = kind == Kind::Preparation ?
            std::filesystem::path(local) / L"KnLiveDbgParserRuntime-v1" / (L"prepare-" + name) : std::filesystem::path(local) / L"Packages" / name;
        const auto receiptPath = kind == Kind::Preparation ? profilePath / L"worker.exe" :
            std::filesystem::path(local) / L"KnLiveDbgParserProfiles-v1" / (name + (kind == Kind::Receipt ? L".pending" : L".lease"));
        CoTaskMemFree(local);
        check((GetFileAttributesW(profilePath.c_str()) != INVALID_FILE_ATTRIBUTES) == (kind != Kind::Receipt) &&
            GetFileAttributesW(receiptPath.c_str()) != INVALID_FILE_ATTRIBUTES && WaitForSingleObject(process.Value, 0) == WAIT_TIMEOUT,
            "live owner has the expected complete or interrupted preparation");
        ParserWorkerRequest request; request.Executable = executable; request.Arguments = {L"--child", L"ok", L"space and \"quote\" trailing\\", L""};
        auto result = RunParserWorker(request);
        check(result.Status == L"exited" && result.SandboxVerified &&
            (GetFileAttributesW(profilePath.c_str()) != INVALID_FILE_ATTRIBUTES) == (kind != Kind::Receipt) &&
            GetFileAttributesW(receiptPath.c_str()) != INVALID_FILE_ATTRIBUTES, "recovery preserves a live owner's prepared resources");
        check(TerminateJobObject(job.Value, ERROR_PROCESS_ABORTED) && WaitForSingleObject(process.Value, 5000) == WAIT_OBJECT_0,
            "profile owner interruption completes without destructors");
        if (kind == Kind::Profile)
        {
            ByteRestore byte{receiptPath};
            const bool read = ReceiptByte(receiptPath, &byte.Original, false); uint8_t corrupt = byte.Original ^ 0x5a;
            byte.Changed = read && ReceiptByte(receiptPath, &corrupt, true);
            const auto rejected = RunParserWorker(request);
            check(byte.Changed && rejected.Status == L"sandbox_profile_failed" && rejected.ProcessId == 0 &&
                rejected.ProfileError == HRESULT_FROM_WIN32(ERROR_INVALID_DATA) && GetFileAttributesW(profilePath.c_str()) != INVALID_FILE_ATTRIBUTES,
                "corrupt published receipt fails closed without deleting its profile");
            check(byte.Restore(), "owned receipt byte restored after corruption control");
        }
        result = RunParserWorker(request);
        check(result.Status == L"exited" && (kind == Kind::Preparation || result.RecoveredProfileReceipts >= 1) &&
            GetFileAttributesW(profilePath.c_str()) == INVALID_FILE_ATTRIBUTES && GetFileAttributesW(receiptPath.c_str()) == INVALID_FILE_ATTRIBUTES,
            "next launch recovers dead owner profile receipt or incomplete code copy");
        // A failed assertion still leaves this owned test registration recoverable.
        if (kind == Kind::Profile && GetFileAttributesW(profilePath.c_str()) != INVALID_FILE_ATTRIBUTES) { DeleteAppContainerProfile(name.c_str()); }
        if (GetFileAttributesW(receiptPath.c_str()) != INVALID_FILE_ATTRIBUTES) { RunParserWorker(request); }
    }
}
