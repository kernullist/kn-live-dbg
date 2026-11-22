// Owned user-provider ETW recordings for the signed capture statement and rotation tests.
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
#include "etl-handoff-workload.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

namespace
{
    struct Properties
    {
        EVENT_TRACE_PROPERTIES p{};
        wchar_t logger[1025]{}, file[1025]{};
        explicit Properties(bool privateSession = true)
        {
            p.Wnode.BufferSize = sizeof(*this);
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.Wnode.ClientContext = 1;
            if (privateSession)
            {
                p.LogFileMode = EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC | EVENT_TRACE_FILE_MODE_SEQUENTIAL;
            }
            p.LoggerNameOffset = offsetof(Properties, logger);
            p.LogFileNameOffset = offsetof(Properties, file);
        }
    };

    std::wstring IdText(const GUID& guid)
    {
        wchar_t text[39]{};
        if (StringFromGUID2(guid, text, 39) != 39) { return {}; }
        std::wstring id(text + 1, 36);
        for (auto& c : id) { c = static_cast<wchar_t>(towlower(c)); }
        return id;
    }

    std::wstring Id(GUID& guid)
    {
        return SUCCEEDED(CoCreateGuid(&guid)) ? IdText(guid) : std::wstring{};
    }

    ULONG OwnerReceipt(const std::filesystem::path& path, GUID& session, bool write)
    {
        HANDLE file = CreateFileW(path.c_str(), write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ, nullptr,
            write ? CREATE_NEW : OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE) { return GetLastError(); }
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        LARGE_INTEGER size{};
        DWORD count = 0;
        ULONG status = ERROR_INVALID_DATA;
        if (GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
            !(attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        {
            if (write)
            {
                if (!WriteFile(file, &session, sizeof(session), &count, nullptr) || !FlushFileBuffers(file)) { status = GetLastError(); }
                else if (count == sizeof(session)) { status = ERROR_SUCCESS; }
            }
            else if (GetFileSizeEx(file, &size) && size.QuadPart == sizeof(session) &&
                ReadFile(file, &session, sizeof(session), &count, nullptr) && count == sizeof(session)) { status = ERROR_SUCCESS; }
        }
        CloseHandle(file);
        return status;
    }

    ULONG WriteRotationMarkers(TRACEHANDLE handle, const GUID& session, REGHANDLE registration, ULONG& increments)
    {
        constexpr const wchar_t* markers[] = {L"KnLiveDbg rotation member 1", L"KnLiveDbg rotation member 2", L"KnLiveDbg rotation member 3"};
        for (unsigned ordinal = 1; ordinal <= 3; ++ordinal)
        {
            for (unsigned i = 0; i < ordinal; ++i)
            {
                const auto status = EventWriteString(registration, TRACE_LEVEL_INFORMATION, 0, markers[ordinal - 1]);
                if (status) { return status; }
            }
            if (ordinal == 3) { break; }
            Properties flush(false), next(false);
            flush.p.Wnode.Guid = next.p.Wnode.Guid = session;
            ULONG status = ControlTraceW(handle, nullptr, &flush.p, EVENT_TRACE_CONTROL_FLUSH);
            if (!status) { status = ControlTraceW(handle, nullptr, &next.p, EVENT_TRACE_CONTROL_INCREMENT_FILE); }
            if (status) { return status; }
            ++increments;
        }
        return ERROR_SUCCESS;
    }

    ULONG CheckRotationStopped(const std::wstring& name, const GUID& session, bool& retried)
    {
        Properties query(false);
        auto status = ControlTraceW(0, name.c_str(), &query.p, EVENT_TRACE_CONTROL_QUERY);
        if (status == ERROR_SUCCESS && IsEqualGUID(query.p.Wnode.Guid, session))
        {
            retried = true;
            Properties stop(false);
            stop.p.Wnode.Guid = session;
            status = ControlTraceW(0, name.c_str(), &stop.p, EVENT_TRACE_CONTROL_STOP);
            if (status == ERROR_SUCCESS)
            {
                Properties finalQuery(false);
                finalQuery.p.Wnode.Guid = session;
                status = ControlTraceW(0, name.c_str(), &finalQuery.p, EVENT_TRACE_CONTROL_QUERY);
            }
        }
        return status;
    }

    int RecoverRotation(const std::filesystem::path& owned)
    {
        const auto attributes = GetFileAttributesW(owned.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) { return 1; }
        GUID session{};
        if (OwnerReceipt(owned / L"controller.knetlowner", session, false) || IsEqualGUID(session, GUID_NULL)) { return 1; }
        const auto id = IdText(session);
        if (id.empty() || owned.filename().wstring() != id) { return 1; }
        bool retried = false;
        const auto status = CheckRotationStopped(L"KnLiveDbg-Statement-" + id, session, retried);
        std::wcerr << L"Owned rotation cleanup query " << status << L", stop retried " << retried << L"\n";
        return status == ERROR_WMI_INSTANCE_NOT_FOUND ? 0 : 1;
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
    if (argc == 3 && std::wstring(argv[2]) == L"--recover-rotation") { return RecoverRotation(argv[1]); }
    const bool rotate = argc == 3 && std::wstring(argv[2]) == L"--rotate";
    const bool probeJoin = argc == 8 && std::wstring(argv[2]) == L"--handoff-join";
    const bool measure = probeJoin || (argc == 7 && std::wstring(argv[2]) == L"--handoff");
    handoff::Trial trial;
    if ((argc != 2 && !rotate && !measure) || (measure && !trial.settings.Parse(argv + 3))) { return 2; }
    trial.settings.probeJoin = probeJoin;
    if (probeJoin && !handoff::Config::Number(argv[7], 1000, trial.settings.callerDelayMs)) { return 2; }
    GUID session{}, provider{};
    const auto sessionId = Id(session);
    if (measure) { provider = handoff::Provider; }
    const auto providerId = measure ? IdText(provider) : Id(provider);
    bool profilePrivilege = false;
    if (sessionId.empty() || providerId.empty() || !ProfilePrivilege(profilePrivilege)) { return 1; }
    const auto owned = std::filesystem::absolute(argv[1]) / sessionId;
    if (!CreateDirectoryW(owned.c_str(), nullptr)) { return 1; }
    const auto path = owned / (rotate ? L"part-%d.etl" : L"capture.etl");
    const auto receipt = owned / L"controller.knetlowner";
    Properties props(!rotate);
    if (wcscpy_s(props.file, path.c_str())) { return 1; }
    props.p.Wnode.Guid = session;
    if (rotate)
    {
        props.p.LogFileMode = EVENT_TRACE_FILE_MODE_NEWFILE;
        props.p.MaximumFileSize = 8;
        props.p.BufferSize = 16;
    }
    const auto name = L"KnLiveDbg-Statement-" + sessionId;
    REGHANDLE registration = 0;
    TRACEHANDLE handle = 0;
    ULONG status = EventRegister(&provider, nullptr, nullptr, &registration);
    if (status != ERROR_SUCCESS) { return 1; }
    status = StartTraceW(&handle, name.c_str(), &props.p);
    const ULONG start = status;
    ULONG stop = ERROR_SUCCESS, increments = 0;
    Properties final(!rotate);
    final.p.Wnode.Guid = session;
    if (status == ERROR_SUCCESS)
    {
        if (rotate) { status = OwnerReceipt(receipt, session, true); }
        if (!status) { status = EnableTraceEx2(handle, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 5000, nullptr); }
        if (!status && !EventProviderEnabled(registration, TRACE_LEVEL_INFORMATION, 0)) { status = ERROR_NOT_READY; }
        if (!status)
        {
            status = measure ? trial.Run(registration) : rotate ? WriteRotationMarkers(handle, session, registration, increments) :
                EventWriteString(registration, TRACE_LEVEL_INFORMATION, 0, L"KnLiveDbg owned capture statement test");
        }
        stop = ControlTraceW(handle, nullptr, &final.p, EVENT_TRACE_CONTROL_STOP);
    }
    const auto unregistered = EventUnregister(registration);
    const bool checkCleanup = rotate && start == ERROR_SUCCESS;
    bool retried = false;
    const auto cleanup = checkCleanup ? CheckRotationStopped(name, session, retried) : ERROR_SUCCESS;
    if (status || stop || unregistered || (checkCleanup && cleanup != ERROR_WMI_INSTANCE_NOT_FOUND))
    {
        std::wcerr << L"ETW start " << start << L", status " << status << L", unregister " << unregistered;
        if (start == ERROR_SUCCESS) { std::wcerr << L", stop " << stop; }
        if (checkCleanup) { std::wcerr << L", cleanup query " << cleanup << L", stop retried " << retried; }
        std::wcerr << L"\n";
        return 1;
    }
    std::wcout << L"{\"session_id\":\"" << sessionId << L"\",\"provider_id\":\"" << providerId <<
        L"\",\"system_trace_enable_flags\":" << props.p.EnableFlags << L",\"se_system_profile_privilege_enabled\":" <<
        (profilePrivilege ? L"true" : L"false");
    if (measure)
    {
        trial.Json(IdText(trial.settings.activity));
        std::wcout << L",\"events_lost\":" << final.p.EventsLost << L",\"log_buffers_lost\":" << final.p.LogBuffersLost
            << L",\"buffers_written\":" << final.p.BuffersWritten;
    }
    if (rotate)
    {
        std::wcout << L",\"increments\":" << increments << L",\"stop_win32\":" << stop << L",\"events_lost\":" << final.p.EventsLost <<
            L",\"log_buffers_lost\":" << final.p.LogBuffersLost << L",\"cleanup_query_win32\":" << cleanup <<
            L",\"cleanup_stop_retried\":" << (retried ? L"true" : L"false");
    }
    std::wcout << L"}\n";
    return 0;
}
