#pragma once

#include "ObservationModel.h"
#include "ProcessHandleObservation.h"
#include <Windows.h>
#include <cstring>

inline uint64_t ObservationFileTime()
{
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}

inline const std::wstring& ObservationBootId()
{
    static const std::wstring bootId = []()
    {
        std::wstring result;
        using QueryFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        const auto module = GetModuleHandleW(L"ntdll.dll");
        const auto query = module == nullptr ? nullptr : reinterpret_cast<QueryFn>(
            GetProcAddress(module, "NtQuerySystemInformation"));
        uint8_t buffer[64] = {};
        ULONG returned = 0;
        if (query != nullptr && query(90, buffer, sizeof(buffer), &returned) >= 0 && returned >= sizeof(GUID))
        {
            const wchar_t* hex = L"0123456789abcdef";
            for (size_t i = 0; i < sizeof(GUID); ++i)
            {
                result.push_back(hex[buffer[i] >> 4]);
                result.push_back(hex[buffer[i] & 15]);
            }
        }
        return result;
    }();
    return bootId;
}

inline ObservationIdentity ObserveProcessIdentity(uint32_t pid, HANDLE process = nullptr)
{
    ObservationIdentity identity;
    identity.BootId = ObservationBootId();
    identity.ProcessId = pid;
    if (pid != 0)
    {
        ObservedProcessHandle owned(ControllerProcessHandles(), ProcessHandleSite::IdentityLookup, pid);
        ProcessHandleIdentity bound;
        if (process) { bound = ReadProcessHandleIdentity(process, pid); }
        else if (owned.Open(PROCESS_QUERY_LIMITED_INFORMATION)) { bound = owned.Acquisition().Bound; }
        if (bound.Pid == pid) { identity.CreateTime = bound.Created; }
        DWORD session = 0;
        identity.SessionKnown = identity.CreateTime != 0 && ProcessIdToSessionId(pid, &session) != FALSE;
        identity.SessionId = session;
    }
    return identity;
}
