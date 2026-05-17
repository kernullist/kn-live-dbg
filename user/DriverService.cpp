#include "DriverService.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <sstream>
#include <vector>

static std::wstring Win32ErrorText(const wchar_t* prefix, DWORD error)
{
    wchar_t buffer[512] = {};
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        buffer,
        static_cast<DWORD>(_countof(buffer)),
        nullptr);

    std::wstringstream stream;
    stream << prefix << L": " << error << L" " << buffer;
    return stream.str();
}

static bool ResolveDriverPath(const std::wstring& driverPath, std::wstring* resolvedPath, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (resolvedPath == nullptr || driverPath.empty())
        {
            if (error != nullptr)
            {
                *error = L"Driver path is empty";
            }
            break;
        }

        DWORD required = GetFullPathNameW(driverPath.c_str(), 0, nullptr, nullptr);
        if (required == 0)
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"GetFullPathNameW failed", GetLastError());
            }
            break;
        }

        std::vector<wchar_t> buffer(required);
        DWORD copied = GetFullPathNameW(driverPath.c_str(), required, buffer.data(), nullptr);
        if (copied == 0 || copied >= required)
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"GetFullPathNameW failed", GetLastError());
            }
            break;
        }

        DWORD attributes = GetFileAttributesW(buffer.data());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"Driver image not found", GetLastError());
            }
            break;
        }

        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            if (error != nullptr)
            {
                *error = L"Driver path points to a directory";
            }
            break;
        }

        *resolvedPath = buffer.data();
        ok = true;
    } while (false);

    return ok;
}

DriverService::DriverService() :
    manager_(nullptr),
    service_(nullptr)
{
}

DriverService::~DriverService()
{
    CloseServiceHandle();
    CloseManagerHandle();
}

bool DriverService::IsServiceMissingError(DWORD error)
{
    return error == ERROR_SERVICE_DOES_NOT_EXIST;
}

bool DriverService::IsServiceMarkedForDeleteError(DWORD error)
{
    return error == ERROR_SERVICE_MARKED_FOR_DELETE;
}

std::wstring DriverService::ServiceStateText(DWORD state)
{
    std::wstring text;

    switch (state)
    {
    case SERVICE_STOPPED:
        text = L"stopped";
        break;
    case SERVICE_START_PENDING:
        text = L"start pending";
        break;
    case SERVICE_STOP_PENDING:
        text = L"stop pending";
        break;
    case SERVICE_RUNNING:
        text = L"running";
        break;
    case SERVICE_CONTINUE_PENDING:
        text = L"continue pending";
        break;
    case SERVICE_PAUSE_PENDING:
        text = L"pause pending";
        break;
    case SERVICE_PAUSED:
        text = L"paused";
        break;
    default:
        {
            std::wstringstream stream;
            stream << L"state " << state;
            text = stream.str();
        }
        break;
    }

    return text;
}

bool DriverService::OpenManager(DWORD access, std::wstring* error)
{
    bool ok = false;

    do
    {
        CloseServiceHandle();
        CloseManagerHandle();

        manager_ = OpenSCManagerW(nullptr, nullptr, access);
        if (manager_ == nullptr)
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"OpenSCManagerW failed", GetLastError());
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DriverService::OpenServiceHandle(DWORD access, std::wstring* error)
{
    return OpenServiceHandle(access, nullptr, error);
}

bool DriverService::OpenServiceHandle(DWORD access, DWORD* serviceError, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (serviceError != nullptr)
        {
            *serviceError = ERROR_SUCCESS;
        }

        if (!OpenManager(SC_MANAGER_CONNECT, error))
        {
            break;
        }

        service_ = OpenServiceW(manager_, KNDBG_SERVICE_NAME, access);
        if (service_ == nullptr)
        {
            DWORD lastError = GetLastError();
            if (serviceError != nullptr)
            {
                *serviceError = lastError;
            }
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"OpenServiceW failed", lastError);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DriverService::QueryServiceState(DWORD* state, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (state == nullptr || service_ == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid service query state";
            }
            break;
        }

        SERVICE_STATUS_PROCESS status = {};
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(
            service_,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded))
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"QueryServiceStatusEx failed", GetLastError());
            }
            break;
        }

        *state = status.dwCurrentState;
        ok = true;
    } while (false);

    return ok;
}

bool DriverService::WaitForState(DWORD desiredState, DWORD timeoutMs, std::wstring* error)
{
    bool ok = false;

    do
    {
        ULONGLONG deadline = GetTickCount64() + timeoutMs;
        DWORD state = 0;

        while (true)
        {
            if (!QueryServiceState(&state, error))
            {
                break;
            }

            if (state == desiredState)
            {
                ok = true;
                break;
            }

            if (GetTickCount64() >= deadline)
            {
                if (error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"Timed out waiting for service state "
                           << ServiceStateText(desiredState)
                           << L"; current state is "
                           << ServiceStateText(state);
                    *error = stream.str();
                }
                break;
            }

            Sleep(200);
        }
    } while (false);

    return ok;
}

bool DriverService::WaitUntilDeleted(DWORD timeoutMs, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (manager_ == nullptr)
        {
            if (!OpenManager(SC_MANAGER_CONNECT, error))
            {
                break;
            }
        }

        ULONGLONG deadline = GetTickCount64() + timeoutMs;

        while (true)
        {
            SC_HANDLE service = OpenServiceW(manager_, KNDBG_SERVICE_NAME, SERVICE_QUERY_STATUS);
            if (service == nullptr)
            {
                DWORD lastError = GetLastError();
                if (IsServiceMissingError(lastError))
                {
                    ok = true;
                    break;
                }

                if (!IsServiceMarkedForDeleteError(lastError))
                {
                    if (error != nullptr)
                    {
                        *error = Win32ErrorText(L"OpenServiceW failed while waiting for delete", lastError);
                    }
                    break;
                }
            }
            else
            {
                ::CloseServiceHandle(service);
            }

            if (GetTickCount64() >= deadline)
            {
                if (error != nullptr)
                {
                    *error = L"Timed out waiting for service deletion";
                }
                break;
            }

            Sleep(200);
        }
    } while (false);

    return ok;
}

void DriverService::CloseServiceHandle()
{
    if (service_ != nullptr)
    {
        ::CloseServiceHandle(service_);
        service_ = nullptr;
    }
}

void DriverService::CloseManagerHandle()
{
    if (manager_ != nullptr)
    {
        ::CloseServiceHandle(manager_);
        manager_ = nullptr;
    }
}

bool DriverService::Query(DriverStatus* status, std::wstring* error)
{
    bool ok = false;

    do
    {
        DriverStatus local = {};
        DWORD serviceError = ERROR_SUCCESS;
        if (!OpenServiceHandle(SERVICE_QUERY_STATUS, &serviceError, error))
        {
            if (IsServiceMissingError(serviceError))
            {
                local.Installed = false;
                local.StateText = L"not installed";
                if (error != nullptr)
                {
                    error->clear();
                }
                if (status != nullptr)
                {
                    *status = local;
                }
                ok = true;
            }
            else if (IsServiceMarkedForDeleteError(serviceError))
            {
                local.Installed = false;
                local.StateText = L"marked for delete";
                if (error != nullptr)
                {
                    error->clear();
                }
                if (status != nullptr)
                {
                    *status = local;
                }
                ok = true;
            }
            break;
        }

        DWORD state = 0;
        if (!QueryServiceState(&state, error))
        {
            break;
        }

        local.Installed = true;
        local.CurrentState = state;
        local.StateText = ServiceStateText(state);
        ok = true;

        if (status != nullptr)
        {
            *status = local;
        }
    } while (false);

    CloseServiceHandle();
    return ok;
}

bool DriverService::Install(const std::wstring& driverPath, std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring fullPath;
        if (!ResolveDriverPath(driverPath, &fullPath, error))
        {
            break;
        }

        if (!OpenManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE, error))
        {
            break;
        }

        service_ = OpenServiceW(
            manager_,
            KNDBG_SERVICE_NAME,
            SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);

        if (service_ != nullptr)
        {
            if (!ChangeServiceConfigW(
                service_,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                fullPath.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                KNDBG_DISPLAY_NAME))
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"ChangeServiceConfigW failed", GetLastError());
                }
                break;
            }

            ok = true;
            break;
        }

        DWORD openError = GetLastError();
        if (IsServiceMarkedForDeleteError(openError))
        {
            if (!WaitUntilDeleted(5000, error))
            {
                break;
            }
        }
        else if (!IsServiceMissingError(openError))
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"OpenServiceW failed", openError);
            }
            break;
        }

        CloseServiceHandle();
        service_ = CreateServiceW(
            manager_,
            KNDBG_SERVICE_NAME,
            KNDBG_DISPLAY_NAME,
            SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            fullPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (service_ == nullptr)
        {
            if (error != nullptr)
            {
                *error = Win32ErrorText(L"CreateServiceW failed", GetLastError());
            }
            break;
        }

        ok = true;
    } while (false);

    CloseServiceHandle();
    return ok;
}

bool DriverService::InstallOrReplace(const std::wstring& driverPath, std::wstring* error)
{
    return Install(driverPath, error);
}

bool DriverService::Start(std::wstring* error)
{
    bool ok = false;

    do
    {
        if (service_ == nullptr)
        {
            if (!OpenServiceHandle(SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP, error))
            {
                break;
            }
        }

        if (!StartServiceW(service_, 0, nullptr))
        {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_SERVICE_ALREADY_RUNNING)
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"StartServiceW failed", lastError);
                }
                break;
            }
        }

        if (!WaitForState(SERVICE_RUNNING, 5000, error))
        {
            break;
        }

        ok = true;
    } while (false);

    CloseServiceHandle();
    return ok;
}

bool DriverService::Stop(std::wstring* error)
{
    bool ok = false;

    do
    {
        DWORD serviceError = ERROR_SUCCESS;
        if (!OpenServiceHandle(SERVICE_STOP | SERVICE_QUERY_STATUS, &serviceError, error))
        {
            if (IsServiceMissingError(serviceError) || IsServiceMarkedForDeleteError(serviceError))
            {
                if (error != nullptr)
                {
                    error->clear();
                }
                ok = true;
            }
            break;
        }

        DWORD state = 0;
        if (!QueryServiceState(&state, error))
        {
            break;
        }

        if (state == SERVICE_STOPPED)
        {
            ok = true;
            break;
        }

        if (state == SERVICE_STOP_PENDING)
        {
            ok = WaitForState(SERVICE_STOPPED, 5000, error);
            break;
        }

        SERVICE_STATUS ignored = {};
        if (!ControlService(service_, SERVICE_CONTROL_STOP, &ignored))
        {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_SERVICE_NOT_ACTIVE)
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"ControlService stop failed", lastError);
                }
                break;
            }
        }

        if (!WaitForState(SERVICE_STOPPED, 5000, error))
        {
            break;
        }

        ok = true;
    } while (false);

    CloseServiceHandle();
    return ok;
}

bool DriverService::StopAndDelete(DriverUnloadResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        DriverUnloadResult local = {};
        DriverStatus status = {};
        if (!Query(&status, error))
        {
            break;
        }

        local.Installed = status.Installed;
        local.FinalState = status.StateText;
        if (!status.Installed)
        {
            local.Deleted = true;
            ok = true;
            if (result != nullptr)
            {
                *result = local;
            }
            break;
        }

        local.WasRunning = status.CurrentState != SERVICE_STOPPED;
        if (!Stop(error))
        {
            break;
        }

        DWORD serviceError = ERROR_SUCCESS;
        if (!OpenServiceHandle(DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS, &serviceError, error))
        {
            if (IsServiceMissingError(serviceError))
            {
                local.Deleted = true;
                local.FinalState = L"deleted";
                ok = true;
                if (error != nullptr)
                {
                    error->clear();
                }
            }
            else if (IsServiceMarkedForDeleteError(serviceError))
            {
                if (!WaitUntilDeleted(5000, error))
                {
                    break;
                }

                local.Deleted = true;
                local.FinalState = L"deleted";
                ok = true;
                if (error != nullptr)
                {
                    error->clear();
                }
            }

            if (result != nullptr)
            {
                *result = local;
            }
            break;
        }

        if (!DeleteService(service_))
        {
            DWORD lastError = GetLastError();
            if (IsServiceMissingError(lastError))
            {
                CloseServiceHandle();
                local.Deleted = true;
                local.FinalState = L"deleted";
                ok = true;
                if (error != nullptr)
                {
                    error->clear();
                }
                if (result != nullptr)
                {
                    *result = local;
                }
                break;
            }

            if (!IsServiceMarkedForDeleteError(lastError))
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"DeleteService failed", lastError);
                }
                break;
            }
        }

        CloseServiceHandle();
        if (!WaitUntilDeleted(5000, error))
        {
            break;
        }

        local.Deleted = true;
        local.FinalState = L"deleted";
        ok = true;

        if (result != nullptr)
        {
            *result = local;
        }
    } while (false);

    CloseServiceHandle();
    return ok;
}

bool DriverService::Remove(std::wstring* error)
{
    DriverUnloadResult ignored = {};
    return StopAndDelete(&ignored, error);
}

bool DriverService::EnsureLoaded(const std::wstring& driverPath, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!Install(driverPath, error))
        {
            break;
        }

        if (!Start(error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
