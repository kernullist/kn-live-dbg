// Owned in-process ETW recording for the signed capture statement integration test.
#include <Windows.h>
#include <evntrace.h>
#include <evntprov.h>
#include <objbase.h>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace
{
    struct Properties
    {
        EVENT_TRACE_PROPERTIES p{};
        wchar_t logger[1025]{}, file[1025]{};
        Properties()
        {
            p.Wnode.BufferSize = sizeof(*this);
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.Wnode.ClientContext = 1;
            p.LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC | EVENT_TRACE_FILE_MODE_SEQUENTIAL;
            p.LoggerNameOffset = offsetof(Properties, logger);
            p.LogFileNameOffset = offsetof(Properties, file);
        }
    };

    std::wstring Id(GUID& guid)
    {
        wchar_t text[39]{};
        if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, text, 39) != 39) { return {}; }
        std::wstring id(text + 1, 36);
        for (auto& c : id) { c = static_cast<wchar_t>(towlower(c)); }
        return id;
    }

    bool ProfilePrivilege(bool& enabled)
    {
        HANDLE token = nullptr;
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_PROFILE_NAME, &luid) ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { return false; }
        DWORD bytes = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &bytes);
        std::vector<unsigned char> buffer(bytes);
        const bool read = bytes && GetTokenInformation(token, TokenPrivileges, buffer.data(), bytes, &bytes);
        CloseHandle(token);
        if (!read) { return false; }
        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
        enabled = false;
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
        {
            const auto& p = privileges->Privileges[i];
            if (p.Luid.HighPart == luid.HighPart && p.Luid.LowPart == luid.LowPart)
            { enabled = (p.Attributes & SE_PRIVILEGE_ENABLED) != 0; }
        }
        return true;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) { return 2; }
    GUID session{}, provider{};
    const auto sessionId = Id(session), providerId = Id(provider);
    bool profilePrivilege = false;
    if (sessionId.empty() || providerId.empty() || !ProfilePrivilege(profilePrivilege)) { return 1; }
    const auto owned = std::filesystem::absolute(argv[1]) / sessionId;
    if (!CreateDirectoryW(owned.c_str(), nullptr)) { return 1; }
    const auto path = owned / L"capture.etl";
    Properties props;
    if (wcscpy_s(props.file, path.c_str())) { return 1; }
    props.p.Wnode.Guid = session;
    const auto name = L"KnLiveDbg-Statement-" + sessionId;
    REGHANDLE registration = 0;
    TRACEHANDLE handle = 0;
    ULONG status = EventRegister(&provider, nullptr, nullptr, &registration);
    if (status != ERROR_SUCCESS) { return 1; }
    status = StartTraceW(&handle, name.c_str(), &props.p);
    ULONG stop = ERROR_SUCCESS;
    if (status == ERROR_SUCCESS)
    {
        status = EnableTraceEx2(handle, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 5000, nullptr);
        if (!status && !EventProviderEnabled(registration, TRACE_LEVEL_INFORMATION, 0)) { status = ERROR_NOT_READY; }
        if (!status) { status = EventWriteString(registration, TRACE_LEVEL_INFORMATION, 0, L"KnLiveDbg owned capture statement test"); }
        Properties final;
        stop = ControlTraceW(handle, nullptr, &final.p, EVENT_TRACE_CONTROL_STOP);
    }
    const auto unregistered = EventUnregister(registration);
    if (status || stop || unregistered)
    {
        std::wcerr << L"ETW status " << status << L", stop " << stop << L", unregister " << unregistered << L"\n";
        return 1;
    }
    std::wcout << L"{\"session_id\":\"" << sessionId << L"\",\"provider_id\":\"" << providerId <<
        L"\",\"system_trace_enable_flags\":" << props.p.EnableFlags << L",\"se_system_profile_privilege_enabled\":" <<
        (profilePrivilege ? L"true" : L"false") << L"}\n";
    return 0;
}
