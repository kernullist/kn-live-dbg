#pragma once

#include <Windows.h>
#include <string>

struct DriverStatus
{
    bool Installed = false;
    DWORD CurrentState = 0;
    std::wstring StateText;
};

struct DriverUnloadResult
{
    bool Installed = false;
    bool WasRunning = false;
    bool Deleted = false;
    std::wstring FinalState;
};

class DriverService
{
public:
    DriverService();
    DriverService(const wchar_t* serviceName, const wchar_t* displayName);
    ~DriverService();

    bool Query(DriverStatus* status, std::wstring* error);
    bool Install(const std::wstring& driverPath, std::wstring* error);
    bool InstallOrReplace(const std::wstring& driverPath, std::wstring* error);
    bool Start(std::wstring* error);
    bool Stop(std::wstring* error);
    bool StopAndDelete(DriverUnloadResult* result, std::wstring* error);
    bool Remove(std::wstring* error);
    bool EnsureLoaded(const std::wstring& driverPath, std::wstring* error);

private:
    bool OpenManager(DWORD access, std::wstring* error);
    bool OpenServiceHandle(DWORD access, std::wstring* error);
    bool OpenServiceHandle(DWORD access, DWORD* serviceError, std::wstring* error);
    bool QueryServiceState(DWORD* state, std::wstring* error);
    bool WaitForState(DWORD desiredState, DWORD timeoutMs, std::wstring* error);
    bool WaitUntilDeleted(DWORD timeoutMs, std::wstring* error);
    void CloseServiceHandle();
    void CloseManagerHandle();
    static bool IsServiceMissingError(DWORD error);
    static bool IsServiceMarkedForDeleteError(DWORD error);
    static std::wstring ServiceStateText(DWORD state);

    std::wstring serviceName_;
    std::wstring displayName_;
    SC_HANDLE manager_;
    SC_HANDLE service_;
};
