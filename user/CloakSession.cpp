#include "CloakSession.h"
#include "DriverService.h"

#include <Windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    constexpr size_t kMinLeafChars = 8;
    constexpr size_t kMaxLeafChars = 16;
    constexpr wchar_t kSessionFileName[] = L"cfg.dat";
    constexpr size_t kMaxSessionBytes = 64 * 1024;

    const wchar_t* kPrefixes[] = {
        L"Aux", L"Cap", L"Mon", L"Tel", L"Bus", L"Hub", L"Io", L"Dev"
    };
    const wchar_t kVowels[] = L"aeiou";
    const wchar_t kConsonants[] = L"bcdfghjklmnpqrstvwxz";

    const wchar_t* kSidecarNames[] = {
        L"dbghelp.dll",
        L"dbgeng.dll",
        L"dbgcore.dll",
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

    bool CanonicalDiskPath(const std::wstring& path, std::wstring* canonical, bool allowRelative = false)
    {
        if (path.empty() || path.size() > 32760 || path.find_first_of(L"\r\n\"") != std::wstring::npos ||
            path.find(L'\0') != std::wstring::npos || (!allowRelative &&
                (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/'))))
        {
            return false;
        }
        const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (needed == 0 || needed > 32768)
        {
            return false;
        }
        std::vector<wchar_t> buffer(needed);
        const DWORD copied = GetFullPathNameW(path.c_str(), needed, buffer.data(), nullptr);
        if (copied == 0 || copied >= needed)
        {
            return false;
        }
        canonical->assign(buffer.data(), copied);
        const auto& full = *canonical;
        return full.size() >= 3 && ((full[0] >= L'A' && full[0] <= L'Z') || (full[0] >= L'a' && full[0] <= L'z')) &&
            full[1] == L':' && full[2] == L'\\' && full.find(L':', 2) == std::wstring::npos;
    }

    bool SameDiskPath(const std::wstring& left, const std::wstring& right)
    {
        std::wstring a;
        std::wstring b;
        return CanonicalDiskPath(left, &a) && CanonicalDiskPath(right, &b) && EqualsIgnoreCase(a, b);
    }

    bool ValidateCloakSession(const CloakSession& session, std::wstring* error)
    {
        std::wstring directory;
        const auto& original = session.OriginalExePath;
        bool valid = IsValidCloakLeafName(session.Id) && session.ServiceName == session.Id &&
            session.DisplayName == session.Id && session.DeviceNtName == L"\\Device\\" + session.Id &&
            session.SymbolicLinkName == L"\\DosDevices\\" + session.Id &&
            session.UserDeviceName == L"\\\\.\\" + session.Id &&
            !original.empty() && original.find_first_of(L"\r\n\"") == std::wstring::npos &&
            original.find(L'\0') == std::wstring::npos &&
            CanonicalDiskPath(session.WorkDirectory, &directory) &&
            EqualsIgnoreCase(FileNameOnly(directory), session.Id) &&
            SameDiskPath(session.SessionFilePath, directory + L"\\" + kSessionFileName) &&
            SameDiskPath(session.CopiedExePath, directory + L"\\" + session.Id + L".exe") &&
            SameDiskPath(session.CopiedSysPath, directory + L"\\" + session.Id + L".sys");
        const DWORD attributes = GetFileAttributesW(directory.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0))
        {
            valid = false;
        }
        std::set<std::wstring> paths;
        for (const auto& sidecar : session.CopiedSidecarFiles)
        {
            const auto leaf = FileNameOnly(sidecar);
            const auto lower = ToLowerCopy(leaf);
            if (!SameDiskPath(sidecar, directory + L"\\" + leaf) ||
                !(CloakCopiesRuntimeSidecar(leaf) ||
                    (lower.size() > 4 && lower.substr(lower.size() - 4) == L".dll")) ||
                !paths.insert(lower).second)
            {
                valid = false;
            }
        }
        if (!valid && error != nullptr)
        {
            *error = L"cloak session identity or artifact paths are unsafe";
        }
        return valid;
    }

    bool ServiceMatchesSession(SC_HANDLE service, const CloakSession& session, std::wstring* error)
    {
        DWORD needed = 0;
        QueryServiceConfigW(service, nullptr, 0, &needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > 65536)
        {
            if (error != nullptr)
            {
                *error = L"could not query cloak service ownership";
            }
            return false;
        }
        std::vector<uint8_t> buffer(needed);
        auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (!QueryServiceConfigW(service, config, needed, &needed))
        {
            if (error != nullptr)
            {
                *error = L"could not read cloak service ownership";
            }
            return false;
        }
        std::wstring binary = config->lpBinaryPathName != nullptr ? config->lpBinaryPathName : L"";
        if (binary.size() >= 2 && binary.front() == L'"' && binary.back() == L'"')
        {
            binary = binary.substr(1, binary.size() - 2);
        }
        if (binary.rfind(L"\\??\\", 0) == 0)
        {
            binary.erase(0, 4);
        }
        const bool matches = config->dwServiceType == SERVICE_KERNEL_DRIVER &&
            SameDiskPath(binary, session.CopiedSysPath);
        if (!matches && error != nullptr)
        {
            *error = L"service name belongs to a different driver image";
        }
        return matches;
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
            if (!CopyFileW(source.c_str(), dest.c_str(), TRUE))
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
        std::wstring out = L"\"";
        for (wchar_t ch : value)
        {
            if (ch == L'"')
            {
                out += L"\\\"";
            }
            else
            {
                out += ch;
            }
        }
        out += L'"';
        return out;
    }

    bool CopySidecarsFromExeDir(
        const std::wstring& exeDir,
        const std::wstring& workDir,
        std::vector<std::wstring>* copied,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE findHandle = INVALID_HANDLE_VALUE;
        do
        {
            if (copied == nullptr)
            {
                break;
            }
            copied->clear();

            std::set<std::wstring> seen;
            WIN32_FIND_DATAW find = {};
            findHandle = FindFirstFileW((exeDir + L"\\*.dll").c_str(), &find);
            if (findHandle == INVALID_HANDLE_VALUE)
            {
                const DWORD findError = GetLastError();
                if (findError != ERROR_FILE_NOT_FOUND && findError != ERROR_PATH_NOT_FOUND)
                {
                    if (error != nullptr)
                    {
                        *error = L"FindFirstFileW sidecar dlls failed (gle=" +
                            std::to_wstring(findError) + L")";
                    }
                    break;
                }
            }
            else
            {
                bool globFailed = false;
                do
                {
                    if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    {
                        continue;
                    }
                    const std::wstring name = find.cFileName;
                    if (name.empty() || !seen.insert(ToLowerCopy(name)).second)
                    {
                        continue;
                    }
                    const std::wstring dest = workDir + L"\\" + name;
                    if (!CopyOneFile(exeDir + L"\\" + name, dest, error))
                    {
                        globFailed = true;
                        break;
                    }
                    copied->push_back(dest);
                } while (FindNextFileW(findHandle, &find));

                const DWORD globEnd = GetLastError();
                FindClose(findHandle);
                findHandle = INVALID_HANDLE_VALUE;
                if (globFailed)
                {
                    break;
                }
                if (globEnd != ERROR_NO_MORE_FILES && globEnd != ERROR_SUCCESS)
                {
                    if (error != nullptr)
                    {
                        *error = L"FindNextFileW sidecar dlls failed (gle=" +
                            std::to_wstring(globEnd) + L")";
                    }
                    break;
                }
            }

            bool listedFailed = false;
            for (const wchar_t* sidecar : kSidecarNames)
            {
                if (sidecar == nullptr)
                {
                    continue;
                }
                const std::wstring name = sidecar;
                const std::wstring source = exeDir + L"\\" + name;
                if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    continue;
                }
                if (!seen.insert(ToLowerCopy(name)).second)
                {
                    continue;
                }
                const std::wstring dest = workDir + L"\\" + name;
                if (!CopyOneFile(source, dest, error))
                {
                    listedFailed = true;
                    break;
                }
                copied->push_back(dest);
            }
            if (listedFailed)
            {
                break;
            }

            bool missingRequired = false;
            for (const wchar_t* sidecar : kSidecarNames)
            {
                if (sidecar == nullptr)
                {
                    continue;
                }
                const std::wstring source = exeDir + L"\\" + sidecar;
                if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    continue;
                }
                const std::wstring dest = workDir + L"\\" + sidecar;
                if (GetFileAttributesW(dest.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    if (error != nullptr)
                    {
                        *error = L"cloak sidecar missing after copy: " +
                            std::wstring(sidecar);
                    }
                    missingRequired = true;
                    break;
                }
            }
            if (missingRequired)
            {
                break;
            }

            ok = true;
        } while (false);

        if (findHandle != INVALID_HANDLE_VALUE)
        {
            FindClose(findHandle);
        }
        return ok;
    }

    bool TryDeleteFile(const std::wstring& path)
    {
        if (path.empty())
        {
            return true;
        }

        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            const DWORD error = GetLastError();
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }
        if ((attributes & FILE_ATTRIBUTE_READONLY) != 0)
        {
            SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
        }
        if (DeleteFileW(path.c_str()))
        {
            return true;
        }

        return MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
    }

    bool TryRemoveDirectory(const std::wstring& path)
    {
        if (path.empty() || RemoveDirectoryW(path.c_str()))
        {
            return true;
        }
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
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
            out.close();
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
            MB_ERR_INVALID_CHARS,
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
            MB_ERR_INVALID_CHARS,
            value.c_str(),
            static_cast<int>(value.size()),
            out.data(),
            needed);
        return out;
    }
}

bool CloakCopiesRuntimeSidecar(const std::wstring& fileName)
{
    bool found = false;
    const std::wstring wanted = ToLowerCopy(fileName);
    for (const wchar_t* sidecar : kSidecarNames)
    {
        if (sidecar != nullptr && ToLowerCopy(sidecar) == wanted)
        {
            found = true;
            break;
        }
    }
    return found;
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
                if (args->Mode != CloakMode::None)
                {
                    return false;
                }
                args->Mode = CloakMode::Launch;
                continue;
            }

            if (lowered == L"--cloak-resume")
            {
                if (args->Mode != CloakMode::None || index + 1 >= argc ||
                    argv[index + 1] == nullptr || argv[index + 1][0] == L'\0' || argv[index + 1][0] == L'-')
                {
                    return false;
                }
                args->Mode = CloakMode::Resume;
                args->SessionPath = argv[index + 1];
                ++index;
                continue;
            }

            if (lowered == L"--cloak-cleanup")
            {
                if (args->Mode != CloakMode::None || index + 1 >= argc ||
                    argv[index + 1] == nullptr || argv[index + 1][0] == L'\0' || argv[index + 1][0] == L'-')
                {
                    return false;
                }
                args->Mode = CloakMode::Cleanup;
                args->SessionPath = argv[index + 1];
                ++index;
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
            if (error != nullptr)
            {
                *error = L"CreateDirectoryW failed (gle=" + std::to_wstring(lastError) + L")";
            }
            break;
        }

        const std::wstring exeDir = ParentDirectory(originalExe);
        const std::wstring copiedExe = workDir + L"\\" + leaf + L".exe";
        const std::wstring copiedSys = workDir + L"\\" + leaf + L".sys";
        const std::wstring sourceSys = exeDir + L"\\KnLiveDbg.sys";

        // Record ownership before copying so the caller can clean up a partial build.
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
        if (!CopyOneFile(originalExe, copiedExe, error) ||
            !CopyOneFile(sourceSys, copiedSys, error) ||
            !CopySidecarsFromExeDir(exeDir, workDir, &session->CopiedSidecarFiles, error))
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

bool SaveCloakSession(const CloakSession& session, std::wstring* error)
{
    if (!ValidateCloakSession(session, error))
    {
        return false;
    }
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

    const auto contents = stream.str();
    if (contents.size() > kMaxSessionBytes)
    {
        if (error != nullptr)
        {
            *error = L"cloak session file exceeds its size limit";
        }
        return false;
    }
    return WriteUtf8File(session.SessionFilePath, contents, error);
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
        std::wstring resolvedPath;
        if (!CanonicalDiskPath(path, &resolvedPath, true))
        {
            if (error != nullptr)
            {
                *error = L"cloak session file requires a local disk path";
            }
            break;
        }
        std::ifstream in(resolvedPath.c_str(), std::ios::binary);
        if (!in.is_open())
        {
            if (error != nullptr)
            {
                *error = L"failed to open cloak session file";
            }
            break;
        }

        in.seekg(0, std::ios::end);
        const std::streamoff size = in.tellg();
        if (size <= 0 || static_cast<uint64_t>(size) > kMaxSessionBytes)
        {
            if (error != nullptr)
            {
                *error = L"cloak session file has an invalid size";
            }
            break;
        }
        in.seekg(0, std::ios::beg);
        std::string contents(static_cast<size_t>(size), '\0');
        if (!in.read(contents.data(), static_cast<std::streamsize>(contents.size())) ||
            in.peek() != std::char_traits<char>::eof())
        {
            if (error != nullptr)
            {
                *error = L"cloak session file changed or could not be read";
            }
            break;
        }
        std::istringstream input(contents);

        std::string line;
        std::set<std::string> fields;
        bool invalid = false;
        while (std::getline(input, line))
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            const size_t eq = line.find('=');
            if (eq == std::string::npos || eq == 0)
            {
                invalid = true;
                break;
            }

            const std::string key = line.substr(0, eq);
            const std::wstring value = Utf8ToWide(line.substr(eq + 1));
            if (value.empty() || value.find_first_of(L"\r\n") != std::wstring::npos ||
                value.find(L'\0') != std::wstring::npos || (key != "sidecar" && !fields.insert(key).second))
            {
                invalid = true;
                break;
            }
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
            else
            {
                invalid = true;
                break;
            }
        }

        session->SessionFilePath = resolvedPath;
        if (invalid || in.bad() || !ValidateCloakSession(*session, error))
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

bool ValidateCloakServiceOwnership(const CloakSession& session, std::wstring* error)
{
    if (!ValidateCloakSession(session, error))
    {
        return false;
    }
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"could not open service manager for cloak ownership check";
        }
        return false;
    }
    SC_HANDLE service = OpenServiceW(manager, session.ServiceName.c_str(), SERVICE_QUERY_CONFIG);
    const DWORD serviceError = service == nullptr ? GetLastError() : ERROR_SUCCESS;
    const bool serviceOwned = service != nullptr && ServiceMatchesSession(service, session, error);
    if (service != nullptr)
    {
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    if (!serviceOwned && serviceError != ERROR_SERVICE_DOES_NOT_EXIST)
    {
        if (error != nullptr && error->empty())
        {
            *error = L"cloak service ownership is not established";
        }
        return false;
    }
    return true;
}

bool WriteCloakServiceParameters(const CloakSession& session, std::wstring* error)
{
    bool ok = false;
    HKEY key = nullptr;

    do
    {
        if (!ValidateCloakServiceOwnership(session, error))
        {
            break;
        }
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
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_SHOWNORMAL;
        PROCESS_INFORMATION info = {};
        // A new console is required. The parent returns immediately so the
        // original EXE name leaves the process list; Windows Terminal then
        // closes the tab and kills inherited-console children.
        if (!CreateProcessW(
                session.CopiedExePath.c_str(),
                commandLine.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NEW_CONSOLE,
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

        const DWORD wait = WaitForSingleObject(info.hProcess, 2000);
        if (wait == WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            GetExitCodeProcess(info.hProcess, &exitCode);
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"cloak child exited immediately (code=0x" << std::hex
                       << static_cast<unsigned long>(exitCode) << L")";
                *error = stream.str();
            }
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
            break;
        }
        if (wait == WAIT_FAILED)
        {
            if (error != nullptr)
            {
                *error = L"WaitForSingleObject cloak child failed (gle=" +
                    std::to_wstring(GetLastError()) + L")";
            }
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
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
    if (!ValidateCloakSession(session, error))
    {
        return false;
    }
    bool ok = true;

    for (const std::wstring& sidecar : session.CopiedSidecarFiles)
    {
        ok = TryDeleteFile(sidecar) && ok;
    }

    ok = TryDeleteFile(session.CopiedSysPath) && ok;

    if (!runningFromCopy)
    {
        ok = TryDeleteFile(session.CopiedExePath) && ok;
    }
    else
    {
        ok = MoveFileExW(session.CopiedExePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE && ok;
        ok = MoveFileExW(session.WorkDirectory.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE && ok;
    }
    if (ok)
    {
        ok = TryDeleteFile(session.SessionFilePath);
        if (!runningFromCopy && ok)
        {
            ok = TryRemoveDirectory(session.WorkDirectory);
        }
    }
    if (!ok && error != nullptr)
    {
        *error = L"could not remove or schedule removal of all cloak artifacts";
    }

    return ok;
}

bool CloakSessionSelfTest()
{
    std::wstring current;
    if (!CanonicalDiskPath(L".", &current, true) || !SameDiskPath(current, current + L"\\."))
    {
        return false;
    }
    for (const auto mode : {L"--cloak-resume", L"--cloak-cleanup"})
    {
        CloakArgs args;
        const wchar_t* missing[] = {L"KnLiveDbg.exe", mode};
        if (ParseCloakArgs(2, missing, &args))
        {
            return false;
        }
        for (const auto path : {L"", L"--help", static_cast<const wchar_t*>(nullptr)})
        {
            const wchar_t* invalid[] = {L"KnLiveDbg.exe", mode, path};
            if (ParseCloakArgs(3, invalid, &args))
            {
                return false;
            }
        }
        const wchar_t* conflict[] = {L"KnLiveDbg.exe", L"--cloak", mode, L"C:\\temp\\cfg.dat"};
        if (ParseCloakArgs(4, conflict, &args))
        {
            return false;
        }
    }

    wchar_t temp[MAX_PATH] = {};
    wchar_t root[MAX_PATH] = {};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH || GetTempFileNameW(temp, L"knc", 0, root) == 0)
    {
        return false;
    }
    DeleteFileW(root);
    if (!CreateDirectoryW(root, nullptr))
    {
        return false;
    }
    CloakSession session;
    session.Id = L"AuxMonkari";
    session.ServiceName = session.Id;
    session.DisplayName = session.Id;
    session.DeviceNtName = L"\\Device\\" + session.Id;
    session.SymbolicLinkName = L"\\DosDevices\\" + session.Id;
    session.UserDeviceName = L"\\\\.\\" + session.Id;
    session.WorkDirectory = std::wstring(root) + L"\\" + session.Id;
    session.SessionFilePath = session.WorkDirectory + L"\\cfg.dat";
    session.CopiedExePath = session.WorkDirectory + L"\\" + session.Id + L".exe";
    session.CopiedSysPath = session.WorkDirectory + L"\\" + session.Id + L".sys";
    session.OriginalExePath = std::wstring(root) + L"\\original.exe";
    session.CopiedSidecarFiles = {session.WorkDirectory + L"\\dbghelp.dll"};
    const std::wstring outside = std::wstring(root) + L"\\outside.dll";
    bool ok = false;
    std::wstring error;
    do
    {
        if (!CreateDirectoryW(session.WorkDirectory.c_str(), nullptr) ||
            !WriteUtf8File(outside, "keep", &error) ||
            !WriteUtf8File(session.CopiedExePath, "fixture", &error) ||
            !WriteUtf8File(session.CopiedSysPath, "fixture", &error) ||
            !WriteUtf8File(session.CopiedSidecarFiles.front(), "fixture", &error) ||
            !SaveCloakSession(session, &error))
        {
            break;
        }
        CloakSession loaded;
        if (!LoadCloakSession(session.SessionFilePath, &loaded, &error) || loaded.Id != session.Id)
        {
            break;
        }
        bool mutationsRejected = true;
        for (const auto path : {outside, session.WorkDirectory + L"\\..\\outside.dll",
            session.WorkDirectory + L"\\dbghelp.dll:stream", session.CopiedExePath,
            session.WorkDirectory + L"\\dbghelp.dll" + std::wstring(1, L'\0')})
        {
            auto invalid = session;
            invalid.CopiedSidecarFiles = {path};
            mutationsRejected = !ValidateCloakSession(invalid, &error) &&
                !CleanupCloakArtifacts(invalid, false, &error) && mutationsRejected;
        }
        auto invalid = session;
        invalid.ServiceName = L"OtherSvc";
        mutationsRejected = !ValidateCloakSession(invalid, &error) && mutationsRejected;
        invalid = session;
        invalid.CopiedSysPath = outside;
        mutationsRejected = !ValidateCloakSession(invalid, &error) && mutationsRejected;
        auto networkSource = session;
        networkSource.OriginalExePath = L"\\\\fixture-host\\share\\KnLiveDbg.exe";
        mutationsRejected = ValidateCloakSession(networkSource, &error) && mutationsRejected;
        if (!mutationsRejected || GetFileAttributesW(outside.c_str()) == INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesW(session.CopiedExePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            break;
        }
        std::ifstream saved(session.SessionFilePath, std::ios::binary);
        const std::string valid((std::istreambuf_iterator<char>(saved)), std::istreambuf_iterator<char>());
        saved.close();
        for (const auto& contents : {valid + "service=OtherSvc\n", valid + "sidecar=\xff\n",
            valid + "unexpected=value\n", std::string(kMaxSessionBytes + 1, 'x')})
        {
            if (!WriteUtf8File(session.SessionFilePath, contents, &error) ||
                LoadCloakSession(session.SessionFilePath, &loaded, &error))
            {
                mutationsRejected = false;
            }
        }
        if (!mutationsRejected || !SaveCloakSession(session, &error) ||
            !CleanupCloakArtifacts(session, false, &error) ||
            GetFileAttributesW(session.WorkDirectory.c_str()) != INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesW(outside.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            break;
        }
        ok = true;
    }
    while (false);
    // These paths were created by this test; never clean up a parsed mutation.
    DeleteFileW(session.SessionFilePath.c_str());
    DeleteFileW(session.CopiedExePath.c_str());
    DeleteFileW(session.CopiedSysPath.c_str());
    DeleteFileW(session.CopiedSidecarFiles.front().c_str());
    RemoveDirectoryW(session.WorkDirectory.c_str());
    DeleteFileW(outside.c_str());
    RemoveDirectoryW(root);
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
        if (manager == nullptr)
        {
            std::wcerr << L"cloak cleanup failed: could not open service manager\n";
            break;
        }
        SC_HANDLE service = OpenServiceW(manager, session.ServiceName.c_str(), SERVICE_QUERY_CONFIG);
        const DWORD serviceError = service == nullptr ? GetLastError() : ERROR_SUCCESS;
        const bool serviceOwned = service != nullptr && ServiceMatchesSession(service, session, &error);
        if (service != nullptr)
        {
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
        if (!serviceOwned && serviceError != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            std::wcerr << L"cloak cleanup failed: service ownership is not established: " << error << L"\n";
            break;
        }
        if (serviceOwned)
        {
            DriverService ownedService(session.ServiceName.c_str(), session.DisplayName.c_str());
            DriverUnloadResult result;
            if (!ownedService.StopAndDelete(&result, &error))
            {
                std::wcerr << L"cloak cleanup failed: " << error << L"\n";
                break;
            }
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
