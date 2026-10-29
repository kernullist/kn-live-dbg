#include "ParserWorkerProcess.h"
#include <algorithm>
#include <objbase.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")

namespace
{
    constexpr SIZE_T MemoryLimit = 512ull * 1024 * 1024;
    constexpr DWORD JobFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    class Handle
    {
    public:
        HANDLE Value = nullptr;
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        ~Handle()
        {
            Reset();
        }
        void Reset(HANDLE next = nullptr)
        {
            if (Valid())
            {
                CloseHandle(Value);
            }
            Value = next;
        }
        bool Valid() const
        {
            return Value != nullptr && Value != INVALID_HANDLE_VALUE;
        }
    };

    struct Attributes
    {
        std::vector<uint8_t> Storage;
        LPPROC_THREAD_ATTRIBUTE_LIST List = nullptr;
        ~Attributes()
        {
            if (List != nullptr)
            {
                DeleteProcThreadAttributeList(List);
            }
        }
    };

    struct Desktop
    {
        HDESK Value = nullptr;
        ~Desktop()
        {
            if (Value != nullptr)
            {
                CloseDesktop(Value);
            }
        }
    };

    struct LocalMemory
    {
        HLOCAL Value = nullptr;
        ~LocalMemory()
        {
            LocalFree(Value);
        }
    };

    struct Child
    {
        Handle Process;
        Handle Thread;
        ~Child()
        {
            if (Process.Valid() && WaitForSingleObject(Process.Value, 0) != WAIT_OBJECT_0)
            {
                TerminateProcess(Process.Value, ERROR_PROCESS_ABORTED);
                WaitForSingleObject(Process.Value, 5000);
            }
        }
    };

    bool TokenData(HANDLE token, TOKEN_INFORMATION_CLASS kind, std::vector<uint8_t>* data)
    {
        DWORD bytes = 0;
        GetTokenInformation(token, kind, nullptr, 0, &bytes);
        if (bytes == 0 || bytes > 65536)
        {
            return false;
        }
        data->resize(bytes);
        return GetTokenInformation(token, kind, data->data(), bytes, &bytes) != FALSE;
    }

    bool RestrictedToken(Handle* token, std::wstring* userSid)
    {
        Handle original;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &original.Value))
        {
            return false;
        }
        std::vector<uint8_t> user;
        if (!TokenData(original.Value, TokenUser, &user))
        {
            return false;
        }
        const auto sid = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
        LocalMemory text;
        if (!ConvertSidToStringSidW(sid, reinterpret_cast<LPWSTR*>(&text.Value)))
        {
            return false;
        }
        *userSid = static_cast<const wchar_t*>(text.Value);
        uint8_t admin[SECURITY_MAX_SID_SIZE]{}, world[SECURITY_MAX_SID_SIZE]{},
            users[SECURITY_MAX_SID_SIZE]{}, authenticated[SECURITY_MAX_SID_SIZE]{}, low[SECURITY_MAX_SID_SIZE]{};
        const auto create = [](WELL_KNOWN_SID_TYPE kind, PSID value)
        {
            DWORD length = SECURITY_MAX_SID_SIZE;
            return CreateWellKnownSid(kind, nullptr, value, &length) != FALSE;
        };
        if (!create(WinBuiltinAdministratorsSid, admin) || !create(WinWorldSid, world) ||
            !create(WinBuiltinUsersSid, users) || !create(WinAuthenticatedUserSid, authenticated) ||
            !create(WinLowLabelSid, low))
        {
            return false;
        }
        SID_AND_ATTRIBUTES disabled{admin, 0};
        std::vector<SID_AND_ATTRIBUTES> restricted{{sid, 0}, {world, 0}, {users, 0}, {authenticated, 0}};
        std::vector<uint8_t> groups;
        if (!TokenData(original.Value, TokenGroups, &groups))
        {
            return false;
        }
        const auto* groupList = reinterpret_cast<TOKEN_GROUPS*>(groups.data());
        for (DWORD i = 0; i < groupList->GroupCount; ++i)
        {
            if ((groupList->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                restricted.push_back({groupList->Groups[i].Sid, 0});
            }
        }
        if (!CreateRestrictedToken(original.Value, DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr,
            static_cast<DWORD>(restricted.size()), restricted.data(), &token->Value))
        {
            return false;
        }
        TOKEN_MANDATORY_LABEL label{{low, SE_GROUP_INTEGRITY}};
        TOKEN_MANDATORY_POLICY policy{};
        DWORD policyBytes = 0;
        return SetTokenInformation(token->Value, TokenIntegrityLevel, &label,
            static_cast<DWORD>(sizeof(label) + GetLengthSid(low))) != FALSE &&
            GetTokenInformation(token->Value, TokenMandatoryPolicy, &policy, sizeof(policy), &policyBytes) != FALSE &&
            (policy.Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP) != 0;
    }

    bool PrivateDesktop(const std::wstring& userSid, Desktop* desktop, std::wstring* fullName)
    {
        GUID guid{};
        wchar_t unique[40]{}, station[256]{};
        DWORD bytes = 0;
        if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, unique, static_cast<int>(std::size(unique))) == 0 ||
            !GetUserObjectInformationW(GetProcessWindowStation(), UOI_NAME, station, sizeof(station), &bytes))
        {
            return false;
        }
        const auto name = std::wstring(L"KnSchema-") + unique;
        const auto sddl = L"D:P(A;;GA;;;" + userSid + L")(A;;GA;;;SY)S:(ML;;NW;;;LW)";
        LocalMemory descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
            reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.Value), nullptr))
        {
            return false;
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor.Value, FALSE};
        desktop->Value = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS |
            DESKTOP_WRITEOBJECTS, &security);
        if (desktop->Value == nullptr)
        {
            return false;
        }
        *fullName = std::wstring(station) + L"\\" + name;
        return true;
    }

    std::wstring Quote(const std::wstring& value)
    {
        std::wstring result = L"\"";
        size_t slashes = 0;
        for (const auto c : value)
        {
            if (c == L'\\')
            {
                ++slashes;
                continue;
            }
            result.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
            result += c;
            slashes = 0;
        }
        result.append(slashes * 2, L'\\');
        return result + L"\"";
    }
}

bool IsRestrictedParserWorker()
{
    Handle token;
    std::vector<uint8_t> label, privileges, groups;
    TOKEN_MANDATORY_POLICY policy{};
    BOOL assigned = FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    wchar_t desktop[256]{};
    DWORD bytes = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.Value) || !IsTokenRestricted(token.Value) ||
        !TokenData(token.Value, TokenIntegrityLevel, &label) || !TokenData(token.Value, TokenPrivileges, &privileges) ||
        !TokenData(token.Value, TokenGroups, &groups) ||
        !GetTokenInformation(token.Value, TokenMandatoryPolicy, &policy, sizeof(policy), &bytes) ||
        (policy.Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP) == 0 ||
        !IsProcessInJob(GetCurrentProcess(), nullptr, &assigned) || !assigned ||
        !QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr) ||
        (limits.BasicLimitInformation.LimitFlags & JobFlags) != JobFlags || limits.BasicLimitInformation.ActiveProcessLimit != 1 ||
        limits.ProcessMemoryLimit > MemoryLimit || limits.ProcessMemoryLimit == 0 ||
        !GetUserObjectInformationW(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, desktop, sizeof(desktop), &bytes) ||
        std::wstring(desktop).rfind(L"KnSchema-", 0) != 0)
    {
        return false;
    }
    LUID traverse{};
    uint8_t admin[SECURITY_MAX_SID_SIZE]{};
    DWORD size = sizeof(admin);
    if (!LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &traverse) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &size))
    {
        return false;
    }
    const auto* privilegeList = reinterpret_cast<TOKEN_PRIVILEGES*>(privileges.data());
    for (DWORD i = 0; i < privilegeList->PrivilegeCount; ++i)
    {
        const auto& luid = privilegeList->Privileges[i].Luid;
        if (luid.HighPart != traverse.HighPart || luid.LowPart != traverse.LowPart)
        {
            return false;
        }
    }
    const auto* groupList = reinterpret_cast<TOKEN_GROUPS*>(groups.data());
    for (DWORD i = 0; i < groupList->GroupCount; ++i)
    {
        if (EqualSid(groupList->Groups[i].Sid, admin) && (groupList->Groups[i].Attributes & SE_GROUP_ENABLED) != 0)
        {
            return false;
        }
    }
    const auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(label.data())->Label.Sid;
    return IsValidSid(sid) && *GetSidSubAuthorityCount(sid) != 0 &&
        *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1) <= SECURITY_MANDATORY_LOW_RID;
}

ParserWorkerResult RunParserWorker(const ParserWorkerRequest& request)
{
    ParserWorkerResult result;
    const auto started = GetTickCount64();
    Handle job, token, input, outputRead, outputWrite;
    Desktop desktop;
    HANDLE inherited[2]{}, jobs[1]{};
    Attributes attributes;
    Child child;
    const auto cancelled = [&]()
    {
        return request.Cancellation != nullptr && request.Cancellation->load();
    };
    do
    {
        if (request.Executable.empty() || request.Executable.size() > 30000 ||
            request.Executable.find(L'\0') != std::wstring::npos || request.TimeoutMs > 60000 ||
            request.OutputLimit == 0 || request.OutputLimit > 2 * 1024 * 1024)
        {
            result.Status = L"invalid_request";
            break;
        }
        if (cancelled() || request.TimeoutMs == 0)
        {
            result.Status = cancelled() ? L"cancelled" : L"timeout";
            break;
        }
        std::wstring command = Quote(request.Executable);
        bool valid = true;
        for (const auto& arg : request.Arguments)
        {
            if (arg.size() > 30000 || arg.find(L'\0') != std::wstring::npos)
            {
                valid = false;
                break;
            }
            command += L" " + Quote(arg);
            if (command.size() > 32766)
            {
                valid = false;
                break;
            }
        }
        if (!valid)
        {
            result.Status = L"invalid_request";
            break;
        }
        result.Status = L"token_configuration_failed";
        std::wstring userSid, desktopName;
        if (!RestrictedToken(&token, &userSid))
        {
            result.Error = GetLastError();
            break;
        }
        result.Status = L"desktop_configuration_failed";
        if (!PrivateDesktop(userSid, &desktop, &desktopName))
        {
            result.Error = GetLastError();
            break;
        }
        result.Status = L"pipe_configuration_failed";
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        if (!CreatePipe(&outputRead.Value, &outputWrite.Value, &security, 0) ||
            !SetHandleInformation(outputRead.Value, HANDLE_FLAG_INHERIT, 0))
        {
            result.Error = GetLastError();
            break;
        }
        input.Reset(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr));
        if (!input.Valid())
        {
            result.Error = GetLastError();
            break;
        }
        result.Status = L"job_configuration_failed";
        job.Reset(CreateJobObjectW(nullptr, nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JobFlags;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = MemoryLimit;
        if (!job.Valid() || !SetInformationJobObject(job.Value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        {
            result.Error = GetLastError();
            break;
        }
        result.Status = L"attribute_configuration_failed";
        SIZE_T attributeBytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &attributeBytes);
        if (attributeBytes == 0 || attributeBytes > 65536)
        {
            break;
        }
        attributes.Storage.resize(attributeBytes);
        auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.Storage.data());
        if (!InitializeProcThreadAttributeList(list, 2, 0, &attributeBytes))
        {
            result.Error = GetLastError();
            break;
        }
        attributes.List = list;
        inherited[0] = outputWrite.Value;
        inherited[1] = input.Value;
        jobs[0] = job.Value;
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) ||
            !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs, sizeof(jobs), nullptr, nullptr))
        {
            result.Error = GetLastError();
            break;
        }
        wchar_t windows[32768]{}, system[32768]{};
        const auto windowsLength = GetWindowsDirectoryW(windows, static_cast<UINT>(std::size(windows)));
        const auto systemLength = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
        if (windowsLength == 0 || windowsLength >= std::size(windows) || systemLength == 0 || systemLength >= std::size(system))
        {
            result.Status = L"environment_configuration_failed";
            break;
        }
        std::wstring environment = L"SystemRoot=" + std::wstring(windows) + L'\0' + L"WINDIR=" + windows + L'\0' + L'\0';
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_HIDE;
        startup.StartupInfo.lpDesktop = desktopName.data();
        startup.StartupInfo.hStdInput = input.Value;
        startup.StartupInfo.hStdOutput = outputWrite.Value;
        startup.StartupInfo.hStdError = outputWrite.Value;
        startup.lpAttributeList = list;
        PROCESS_INFORMATION info{};
        if (cancelled() || GetTickCount64() - started >= request.TimeoutMs)
        {
            result.Status = cancelled() ? L"cancelled" : L"timeout";
            break;
        }
        result.Status = L"spawn_failed";
        if (!CreateProcessAsUserW(token.Value, request.Executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.data(), system, &startup.StartupInfo, &info))
        {
            result.Error = GetLastError();
            break;
        }
        child.Process.Reset(info.hProcess);
        child.Thread.Reset(info.hThread);
        result.ProcessId = info.dwProcessId;
        outputWrite.Reset();
        if (cancelled() || GetTickCount64() - started >= request.TimeoutMs)
        {
            result.Status = cancelled() ? L"cancelled" : L"timeout";
            break;
        }
        if (ResumeThread(child.Thread.Value) == MAXDWORD)
        {
            result.Error = GetLastError();
            break;
        }
        for (;;)
        {
            if (cancelled() || GetTickCount64() - started >= request.TimeoutMs)
            {
                result.Status = cancelled() ? L"cancelled" : L"timeout";
                break;
            }
            DWORD available = 0;
            if (!PeekNamedPipe(outputRead.Value, nullptr, 0, nullptr, &available, nullptr) && GetLastError() != ERROR_BROKEN_PIPE)
            {
                result.Status = L"read_failed";
                result.Error = GetLastError();
                break;
            }
            if (available != 0)
            {
                if (result.Output.size() >= request.OutputLimit)
                {
                    result.Status = L"output_limit";
                    break;
                }
                char buffer[8192];
                const auto count = static_cast<DWORD>((std::min)({sizeof(buffer), static_cast<size_t>(available),
                    request.OutputLimit - result.Output.size()}));
                DWORD received = 0;
                if (!ReadFile(outputRead.Value, buffer, count, &received, nullptr) || received == 0)
                {
                    result.Status = L"read_failed";
                    result.Error = GetLastError();
                    break;
                }
                result.Output.append(buffer, received);
                continue;
            }
            const auto wait = WaitForSingleObject(child.Process.Value, 10);
            if (wait == WAIT_OBJECT_0)
            {
                DWORD remaining = 0;
                if (!PeekNamedPipe(outputRead.Value, nullptr, 0, nullptr, &remaining, nullptr) && GetLastError() != ERROR_BROKEN_PIPE)
                {
                    result.Status = L"read_failed";
                    result.Error = GetLastError();
                    break;
                }
                if (remaining != 0)
                {
                    continue;
                }
                result.Status = GetExitCodeProcess(child.Process.Value, &result.ExitCode) && result.ExitCode == ERROR_SUCCESS ?
                    L"exited" : L"worker_failed";
                break;
            }
            if (wait == WAIT_FAILED)
            {
                result.Status = L"wait_failed";
                result.Error = GetLastError();
                break;
            }
        }
    }
    while (false);
    if (child.Process.Valid() && WaitForSingleObject(child.Process.Value, 0) != WAIT_OBJECT_0)
    {
        TerminateJobObject(job.Value, ERROR_PROCESS_ABORTED);
        if (WaitForSingleObject(child.Process.Value, 5000) != WAIT_OBJECT_0)
        {
            result.Status = L"cleanup_pending";
        }
    }
    if (result.Status != L"exited")
    {
        result.Output.clear();
    }
    result.ElapsedMs = GetTickCount64() - started;
    return result;
}
