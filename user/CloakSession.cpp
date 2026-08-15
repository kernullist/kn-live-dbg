#include "CloakSession.h"

#include <Windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    constexpr size_t kMinLeafChars = 8;
    constexpr size_t kMaxLeafChars = 16;
    constexpr wchar_t kSessionFileName[] = L"cfg.dat";

    const wchar_t* kPrefixes[] = {
        L"Aux", L"Cap", L"Mon", L"Tel", L"Bus", L"Hub", L"Io", L"Dev"
    };
    const wchar_t kVowels[] = L"aeiou";
    const wchar_t kConsonants[] = L"bcdfghjklmnpqrstvwxz";

    const wchar_t* kSidecarNames[] = {
        L"dbghelp.dll",
        L"dbgeng.dll",
        L"DbgModel.dll",
        L"srcsrv.dll",
        L"symsrv.dll",
        L"msdia140.dll",
        L"symsrv.yes"
    };

    bool RandomBytes(void* buffer, ULONG length)
    {
        return BCryptGenRandom(
            nullptr,
            static_cast<PUCHAR>(buffer),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
    }

    uint32_t RandomU32()
    {
        uint32_t value = 0;
        if (!RandomBytes(&value, sizeof(value)))
        {
            value = GetTickCount() ^ GetCurrentProcessId();
        }
        return value;
    }

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return lowered;
    }

    bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right)
    {
        return ToLowerCopy(left) == ToLowerCopy(right);
    }

    bool IsReservedLeafName(const std::wstring& name)
    {
        const std::wstring lowered = ToLowerCopy(name);
        return lowered == L"con" ||
            lowered == L"prn" ||
            lowered == L"aux" ||
            lowered == L"nul" ||
            lowered == L"knlivedbg" ||
            lowered.rfind(L"com", 0) == 0 ||
            lowered.rfind(L"lpt", 0) == 0;
    }

    bool ServiceNameExists(const std::wstring& name)
    {
        bool exists = false;
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager == nullptr)
        {
            return false;
        }

        SC_HANDLE service = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_STATUS);
        if (service != nullptr)
        {
            exists = true;
            CloseServiceHandle(service);
        }
        else
        {
            exists = GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST;
        }

        CloseServiceHandle(manager);
        return exists;
    }

    std::wstring ParentDirectory(const std::wstring& path)
    {
        const size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return L".";
        }
        return path.substr(0, slash);
    }

    std::wstring FileNameOnly(const std::wstring& path)
    {
        const size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return path;
        }
        return path.substr(slash + 1);
    }

    bool GetSelfPath(std::wstring* path, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (path == nullptr)
            {
                break;
            }

            std::vector<wchar_t> buffer(MAX_PATH);
            DWORD copied = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (copied == 0)
            {
                if (error != nullptr)
                {
                    *error = L"GetModuleFileNameW failed";
                }
                break;
            }
            if (copied >= buffer.size())
            {
                if (error != nullptr)
                {
                    *error = L"module path is too long";
                }
                break;
            }

            *path = buffer.data();
            ok = true;
        } while (false);

        return ok;
    }

    bool CopyOneFile(const std::wstring& source, const std::wstring& dest, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (!CopyFileW(source.c_str(), dest.c_str(), FALSE))
            {
                if (error != nullptr)
                {
                    *error = L"CopyFileW failed for " + FileNameOnly(source) +
                        L" (gle=" + std::to_wstring(GetLastError()) + L")";
                }
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    std::wstring Quote(const std::wstring& value)
    {
        return L"\"" + value + L"\"";
    }

    void TryDeleteFile(const std::wstring& path)
    {
        if (path.empty())
        {
            return;
        }

        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(path.c_str()))
        {
            return;
        }

        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    void TryRemoveDirectory(const std::wstring& path)
    {
        if (!path.empty())
        {
            RemoveDirectoryW(path.c_str());
        }
    }

    bool WriteUtf8File(const std::wstring& path, const std::string& text, std::wstring* error)
    {
        bool ok = false;
        do
        {
            std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                if (error != nullptr)
                {
                    *error = L"failed to write cloak session file";
                }
                break;
            }
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (!out.good())
            {
                if (error != nullptr)
                {
                    *error = L"failed while writing cloak session file";
                }
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
        {
            return std::string();
        }

        const int needed = WideCharToMultiByte(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (needed <= 0)
        {
            return std::string();
        }

        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            out.data(),
            needed,
            nullptr,
            nullptr);
        return out;
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty())
        {
            return std::wstring();
        }

        const int needed = MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            nullptr,
            0);
        if (needed <= 0)
        {
            return std::wstring();
        }

        std::wstring out(static_cast<size_t>(needed), L'\0');
        MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            out.data(),
            needed);
        return out;
    }
}

bool IsValidCloakLeafName(const std::wstring& name)
{
    bool ok = false;

    do
    {
        if (name.size() < kMinLeafChars || name.size() > kMaxLeafChars)
        {
            break;
        }

        const wchar_t first = name[0];
        if (!((first >= L'A' && first <= L'Z') || (first >= L'a' && first <= L'z')))
        {
            break;
        }

        bool validChars = true;
        for (wchar_t ch : name)
        {
            const bool letter = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
            const bool digit = (ch >= L'0' && ch <= L'9');
            if (!letter && !digit)
            {
                validChars = false;
                break;
            }
        }
        if (!validChars || IsReservedLeafName(name))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring GenerateCloakLeafName()
{
    std::wstring name;

    do
    {
        const uint32_t prefixIndex = RandomU32() % static_cast<uint32_t>(std::size(kPrefixes));
        name = kPrefixes[prefixIndex];

        const uint32_t extra = 5 + (RandomU32() % 4);
        for (uint32_t index = 0; index < extra; ++index)
        {
            const bool vowel = (index % 2) == 0;
            if (vowel)
            {
                name.push_back(kVowels[RandomU32() % 5]);
            }
            else
            {
                name.push_back(kConsonants[RandomU32() % 20]);
            }
        }

        if (!IsValidCloakLeafName(name) || ServiceNameExists(name))
        {
            name.clear();
        }
    } while (false);

    return name;
}

bool ParseCloakArgs(int argc, const wchar_t* const* argv, CloakArgs* args)
{
    bool ok = false;

    do
    {
        if (args == nullptr)
        {
            break;
        }

        *args = CloakArgs{};
        for (int index = 1; index < argc; ++index)
        {
            std::wstring token = argv[index] != nullptr ? argv[index] : L"";
            std::wstring lowered = ToLowerCopy(token);
            if (lowered == L"--cloak")
            {
                if (args->Mode == CloakMode::None)
                {
                    args->Mode = CloakMode::Launch;
                }
                continue;
            }

            if (lowered == L"--cloak-resume")
            {
                if (index + 1 >= argc)
                {
                    break;
                }
                args->Mode = CloakMode::Resume;
                args->SessionPath = argv[index + 1];
                ++index;
                continue;
            }

            if (lowered == L"--cloak-cleanup")
            {
                args->Mode = CloakMode::Cleanup;
                if (index + 1 < argc && argv[index + 1][0] != L'-')
                {
                    args->SessionPath = argv[index + 1];
                    ++index;
                }
                continue;
            }
        }

        if (args->Mode == CloakMode::Resume && args->SessionPath.empty())
        {
            args->Mode = CloakMode::None;
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool BuildCloakSession(CloakSession* session, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (session == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid cloak session output";
            }
            break;
        }

        *session = CloakSession{};
        std::wstring originalExe;
        if (!GetSelfPath(&originalExe, error))
        {
            break;
        }

        std::wstring leaf;
        for (int attempt = 0; attempt < 16 && leaf.empty(); ++attempt)
        {
            leaf = GenerateCloakLeafName();
        }
        if (leaf.empty())
        {
            if (error != nullptr)
            {
                *error = L"failed to allocate a unique cloak service name";
            }
            break;
        }

        wchar_t tempDir[MAX_PATH] = {};
        const DWORD tempLen = GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir);
        if (tempLen == 0 || tempLen >= std::size(tempDir))
        {
            if (error != nullptr)
            {
                *error = L"GetTempPathW failed";
            }
            break;
        }

        std::wstring workDir = std::wstring(tempDir) + leaf;
        if (!CreateDirectoryW(workDir.c_str(), nullptr))
        {
            const DWORD lastError = GetLastError();
            if (lastError != ERROR_ALREADY_EXISTS)
            {
                if (error != nullptr)
                {
                    *error = L"CreateDirectoryW failed (gle=" + std::to_wstring(lastError) + L")";
                }
                break;
            }
        }

        const std::wstring exeDir = ParentDirectory(originalExe);
        const std::wstring copiedExe = workDir + L"\\" + leaf + L".exe";
        const std::wstring copiedSys = workDir + L"\\" + leaf + L".sys";
        const std::wstring sourceSys = exeDir + L"\\KnLiveDbg.sys";

        if (!CopyOneFile(originalExe, copiedExe, error))
        {
            break;
        }
        if (!CopyOneFile(sourceSys, copiedSys, error))
        {
            break;
        }

        session->CopiedSidecarFiles.clear();
        bool sidecarFailed = false;
        for (const wchar_t* sidecar : kSidecarNames)
        {
            const std::wstring source = exeDir + L"\\" + sidecar;
            if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                continue;
            }

            const std::wstring dest = workDir + L"\\" + sidecar;
            if (!CopyOneFile(source, dest, error))
            {
                sidecarFailed = true;
                break;
            }
            session->CopiedSidecarFiles.push_back(dest);
        }
        if (sidecarFailed)
        {
            break;
        }

        session->Id = leaf;
        session->ServiceName = leaf;
        session->DisplayName = leaf;
        session->DeviceNtName = L"\\Device\\" + leaf;
        session->SymbolicLinkName = L"\\DosDevices\\" + leaf;
        session->UserDeviceName = L"\\\\.\\" + leaf;
        session->WorkDirectory = workDir;
        session->CopiedExePath = copiedExe;
        session->CopiedSysPath = copiedSys;
        session->OriginalExePath = originalExe;
        session->SessionFilePath = workDir + L"\\" + kSessionFileName;
        ok = true;
    } while (false);

    return ok;
}

bool SaveCloakSession(const CloakSession& session, std::wstring* error)
{
    std::ostringstream stream;
    stream << "id=" << WideToUtf8(session.Id) << "\n";
    stream << "service=" << WideToUtf8(session.ServiceName) << "\n";
    stream << "display=" << WideToUtf8(session.DisplayName) << "\n";
    stream << "device=" << WideToUtf8(session.DeviceNtName) << "\n";
    stream << "dos=" << WideToUtf8(session.SymbolicLinkName) << "\n";
    stream << "user=" << WideToUtf8(session.UserDeviceName) << "\n";
    stream << "workdir=" << WideToUtf8(session.WorkDirectory) << "\n";
    stream << "exe=" << WideToUtf8(session.CopiedExePath) << "\n";
    stream << "sys=" << WideToUtf8(session.CopiedSysPath) << "\n";
    stream << "original=" << WideToUtf8(session.OriginalExePath) << "\n";
    for (const std::wstring& sidecar : session.CopiedSidecarFiles)
    {
        stream << "sidecar=" << WideToUtf8(sidecar) << "\n";
    }

    return WriteUtf8File(session.SessionFilePath, stream.str(), error);
}

bool LoadCloakSession(const std::wstring& path, CloakSession* session, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (session == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid cloak session output";
            }
            break;
        }

        *session = CloakSession{};
        std::ifstream in(path.c_str(), std::ios::binary);
        if (!in.is_open())
        {
            if (error != nullptr)
            {
                *error = L"failed to open cloak session file";
            }
            break;
        }

        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            const size_t eq = line.find('=');
            if (eq == std::string::npos || eq == 0)
            {
                continue;
            }

            const std::string key = line.substr(0, eq);
            const std::wstring value = Utf8ToWide(line.substr(eq + 1));
            if (key == "id")
            {
                session->Id = value;
            }
            else if (key == "service")
            {
                session->ServiceName = value;
            }
            else if (key == "display")
            {
                session->DisplayName = value;
            }
            else if (key == "device")
            {
                session->DeviceNtName = value;
            }
            else if (key == "dos")
            {
                session->SymbolicLinkName = value;
            }
            else if (key == "user")
            {
                session->UserDeviceName = value;
            }
            else if (key == "workdir")
            {
                session->WorkDirectory = value;
            }
            else if (key == "exe")
            {
                session->CopiedExePath = value;
            }
            else if (key == "sys")
            {
                session->CopiedSysPath = value;
            }
            else if (key == "original")
            {
                session->OriginalExePath = value;
            }
            else if (key == "sidecar")
            {
                session->CopiedSidecarFiles.push_back(value);
            }
        }

        session->SessionFilePath = path;
        if (!IsValidCloakLeafName(session->ServiceName) ||
            session->DeviceNtName.rfind(L"\\Device\\", 0) != 0 ||
            session->SymbolicLinkName.rfind(L"\\DosDevices\\", 0) != 0 ||
            session->UserDeviceName.rfind(L"\\\\.\\", 0) != 0 ||
            session->CopiedSysPath.empty() ||
            session->CopiedExePath.empty())
        {
            if (error != nullptr)
            {
                *error = L"cloak session file is incomplete or unsafe";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool WriteCloakServiceParameters(const CloakSession& session, std::wstring* error)
{
    bool ok = false;
    HKEY key = nullptr;

    do
    {
        const std::wstring path =
            L"SYSTEM\\CurrentControlSet\\Services\\" + session.ServiceName + L"\\Parameters";
        DWORD disposition = 0;
        const LSTATUS status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.c_str(),
            0,
            nullptr,
            0,
            KEY_SET_VALUE,
            nullptr,
            &key,
            &disposition);
        if (status != ERROR_SUCCESS)
        {
            if (error != nullptr)
            {
                *error = L"RegCreateKeyExW Parameters failed (gle=" +
                    std::to_wstring(static_cast<unsigned long>(status)) + L")";
            }
            break;
        }

        auto writeSz = [&](const wchar_t* name, const std::wstring& value) -> bool
        {
            const LSTATUS writeStatus = RegSetValueExW(
                key,
                name,
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(value.c_str()),
                static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
            return writeStatus == ERROR_SUCCESS;
        };

        if (!writeSz(L"DeviceName", session.DeviceNtName) ||
            !writeSz(L"SymbolicLink", session.SymbolicLinkName))
        {
            if (error != nullptr)
            {
                *error = L"RegSetValueExW cloak names failed";
            }
            break;
        }

        ok = true;
    } while (false);

    if (key != nullptr)
    {
        RegCloseKey(key);
    }

    return ok;
}

bool LaunchCloakChild(const CloakSession& session, int argc, const wchar_t* const* argv, std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring command = Quote(session.CopiedExePath) +
            L" --cloak-resume " + Quote(session.SessionFilePath);

        for (int index = 1; index < argc; ++index)
        {
            const std::wstring token = argv[index] != nullptr ? argv[index] : L"";
            const std::wstring lowered = ToLowerCopy(token);
            if (lowered == L"--cloak")
            {
                continue;
            }
            if (lowered == L"--cloak-resume" || lowered == L"--cloak-cleanup")
            {
                ++index;
                continue;
            }
            command += L" ";
            command += Quote(token);
        }

        std::vector<wchar_t> commandLine(command.begin(), command.end());
        commandLine.push_back(L'\0');

        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info = {};
        if (!CreateProcessW(
                session.CopiedExePath.c_str(),
                commandLine.data(),
                nullptr,
                nullptr,
                TRUE,
                0,
                nullptr,
                session.WorkDirectory.c_str(),
                &startup,
                &info))
        {
            if (error != nullptr)
            {
                *error = L"CreateProcessW cloak child failed (gle=" +
                    std::to_wstring(GetLastError()) + L")";
            }
            break;
        }

        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        ok = true;
    } while (false);

    return ok;
}

bool CleanupCloakArtifacts(const CloakSession& session, bool runningFromCopy, std::wstring* error)
{
    bool ok = true;
    (void)error;

    for (const std::wstring& sidecar : session.CopiedSidecarFiles)
    {
        TryDeleteFile(sidecar);
    }

    TryDeleteFile(session.CopiedSysPath);
    TryDeleteFile(session.SessionFilePath);

    if (!runningFromCopy)
    {
        TryDeleteFile(session.CopiedExePath);
        TryRemoveDirectory(session.WorkDirectory);
    }
    else
    {
        MoveFileExW(session.CopiedExePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        MoveFileExW(session.WorkDirectory.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    return ok;
}

int RunCloakCleanup(const std::wstring& sessionPath)
{
    int exitCode = 1;
    std::wstring error;

    do
    {
        if (sessionPath.empty())
        {
            std::wcerr << L"usage: --cloak-cleanup <session-file>\n";
            break;
        }

        CloakSession session = {};
        if (!LoadCloakSession(sessionPath, &session, &error))
        {
            std::wcerr << L"cloak cleanup failed: " << error << L"\n";
            break;
        }

        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager != nullptr)
        {
            SC_HANDLE service = OpenServiceW(
                manager,
                session.ServiceName.c_str(),
                SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (service != nullptr)
            {
                SERVICE_STATUS status = {};
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                DeleteService(service);
                CloseServiceHandle(service);
            }
            CloseServiceHandle(manager);
        }

        if (!CleanupCloakArtifacts(session, false, &error))
        {
            std::wcerr << L"cloak artifact cleanup failed: " << error << L"\n";
            break;
        }

        std::wcout << L"cloak session removed\n";
        exitCode = 0;
    } while (false);

    return exitCode;
}
