#include "ByovdScanner.h"

#include <Windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <unordered_map>

namespace
{
    constexpr uint64_t kCatalogMaxAgeSeconds = 24ull * 60ull * 60ull;
    constexpr uint32_t kHashReadChunk = 1024 * 1024;
    constexpr DWORD kUpdaterTimeoutMs = 5u * 60u * 1000u;
    constexpr DWORD kDefaultYaraTimeoutSeconds = 30u;

    struct VersionQuad
    {
        std::array<uint64_t, 4> Parts = {0, 0, 0, 0};
        bool Valid = false;
    };

    struct FileHashes
    {
        std::wstring Md5;
        std::wstring Sha1;
        std::wstring Sha256;
    };

    struct YaraScanProcessResult
    {
        std::vector<std::wstring> Lines;
        DWORD ExitCode = 0;
        bool TimedOut = false;
    };

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    std::wstring TrimCopy(const std::wstring& value)
    {
        size_t first = 0;
        while (first < value.size() && std::iswspace(value[first]))
        {
            ++first;
        }

        size_t last = value.size();
        while (last > first && std::iswspace(value[last - 1]))
        {
            --last;
        }

        return value.substr(first, last - first);
    }

    std::wstring FormatWin32Text(const wchar_t* prefix, DWORD error)
    {
        std::wstringstream stream;
        stream << prefix << L": " << error;
        return stream.str();
    }

    std::wstring JoinPath(const std::wstring& left, const std::wstring& right)
    {
        std::wstring result = left;

        if (!result.empty() && result.back() != L'\\' && result.back() != L'/')
        {
            result += L"\\";
        }
        result += right;

        return result;
    }

    bool FileExists(const std::wstring& path)
    {
        DWORD attr = GetFileAttributesW(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    bool DirectoryExists(const std::wstring& path)
    {
        DWORD attr = GetFileAttributesW(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    bool EnsureDirectory(const std::wstring& path, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (path.empty())
            {
                if (error != nullptr)
                {
                    *error = L"directory path is empty";
                }
                break;
            }

            if (DirectoryExists(path))
            {
                ok = true;
                break;
            }

            size_t slash = path.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                std::wstring parent = path.substr(0, slash);
                if (!parent.empty() && !DirectoryExists(parent))
                {
                    if (!EnsureDirectory(parent, error))
                    {
                        break;
                    }
                }
            }

            if (!CreateDirectoryW(path.c_str(), nullptr))
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_ALREADY_EXISTS)
                {
                    if (error != nullptr)
                    {
                        *error = FormatWin32Text(L"CreateDirectoryW failed", lastError);
                    }
                    break;
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    std::wstring GetCurrentDirectoryText()
    {
        std::wstring result;
        DWORD required = GetCurrentDirectoryW(0, nullptr);

        if (required != 0)
        {
            std::vector<wchar_t> buffer(required + 1, L'\0');
            DWORD written = GetCurrentDirectoryW(static_cast<DWORD>(buffer.size()), buffer.data());
            if (written != 0 && written < buffer.size())
            {
                result.assign(buffer.data(), written);
            }
        }

        return result;
    }

    std::wstring GetFullPathText(const std::wstring& path)
    {
        std::wstring result = path;
        DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);

        if (required != 0)
        {
            std::vector<wchar_t> buffer(required + 1, L'\0');
            DWORD written = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
            if (written != 0 && written < buffer.size())
            {
                result.assign(buffer.data(), written);
            }
        }

        return result;
    }

    std::wstring QuoteArgument(const std::wstring& value)
    {
        std::wstring result = L"\"";

        for (wchar_t ch : value)
        {
            if (ch == L'"')
            {
                result += L"\\\"";
            }
            else
            {
                result.push_back(ch);
            }
        }

        result += L"\"";
        return result;
    }

    bool ReadFileUtf8(const std::wstring& path, std::wstring* text, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (text == nullptr)
            {
                break;
            }

            std::ifstream file(path, std::ios::binary);
            if (!file)
            {
                if (error != nullptr)
                {
                    *error = L"failed to open text file: " + path;
                }
                break;
            }

            std::string bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (bytes.size() >= 3 &&
                static_cast<unsigned char>(bytes[0]) == 0xef &&
                static_cast<unsigned char>(bytes[1]) == 0xbb &&
                static_cast<unsigned char>(bytes[2]) == 0xbf)
            {
                bytes.erase(0, 3);
            }

            if (bytes.empty())
            {
                text->clear();
                ok = true;
                break;
            }

            int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (required <= 0)
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"MultiByteToWideChar failed", GetLastError());
                }
                break;
            }

            text->assign(static_cast<size_t>(required), L'\0');
            int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), &(*text)[0], required);
            if (written != required)
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"MultiByteToWideChar incomplete", GetLastError());
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    std::vector<std::wstring> SplitLines(const std::wstring& text)
    {
        std::vector<std::wstring> lines;
        std::wstringstream stream(text);
        std::wstring line;

        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            lines.push_back(line);
        }

        return lines;
    }

    std::wstring GetTempFilePathText(const wchar_t* prefix)
    {
        std::wstring result;
        wchar_t tempPath[MAX_PATH + 1] = {};
        wchar_t tempFile[MAX_PATH + 1] = {};

        do
        {
            DWORD pathLength = GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
            if (pathLength == 0 || pathLength >= std::size(tempPath))
            {
                break;
            }

            if (GetTempFileNameW(tempPath, prefix, 0, tempFile) == 0)
            {
                break;
            }

            result = tempFile;
        } while (false);

        return result;
    }

    std::vector<std::wstring> SplitTabs(const std::wstring& line)
    {
        std::vector<std::wstring> fields;
        size_t start = 0;

        for (;;)
        {
            size_t tab = line.find(L'\t', start);
            if (tab == std::wstring::npos)
            {
                fields.push_back(line.substr(start));
                break;
            }

            fields.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }

        return fields;
    }

    std::wstring HexBytes(const BYTE* bytes, DWORD count)
    {
        std::wstringstream stream;

        for (DWORD index = 0; index < count; ++index)
        {
            stream << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<unsigned int>(bytes[index]);
        }

        return stream.str();
    }

    bool ComputeFileHashes(const std::wstring& path, FileHashes* hashes, std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;
        HCRYPTPROV provider = 0;
        HCRYPTHASH md5 = 0;
        HCRYPTHASH sha1 = 0;
        HCRYPTHASH sha256 = 0;

        do
        {
            if (hashes == nullptr)
            {
                break;
            }

            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CreateFileW failed", GetLastError());
                }
                break;
            }

            if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CryptAcquireContextW failed", GetLastError());
                }
                break;
            }

            if (!CryptCreateHash(provider, CALG_MD5, 0, 0, &md5) ||
                !CryptCreateHash(provider, CALG_SHA1, 0, 0, &sha1) ||
                !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &sha256))
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CryptCreateHash failed", GetLastError());
                }
                break;
            }

            std::vector<BYTE> buffer(kHashReadChunk);
            DWORD read = 0;
            for (;;)
            {
                if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
                {
                    if (error != nullptr)
                    {
                        *error = FormatWin32Text(L"ReadFile failed", GetLastError());
                    }
                    break;
                }

                if (read == 0)
                {
                    ok = true;
                    break;
                }

                if (!CryptHashData(md5, buffer.data(), read, 0) ||
                    !CryptHashData(sha1, buffer.data(), read, 0) ||
                    !CryptHashData(sha256, buffer.data(), read, 0))
                {
                    if (error != nullptr)
                    {
                        *error = FormatWin32Text(L"CryptHashData failed", GetLastError());
                    }
                    ok = false;
                    break;
                }
            }

            if (!ok)
            {
                break;
            }

            BYTE md5Bytes[16] = {};
            BYTE sha1Bytes[20] = {};
            BYTE sha256Bytes[32] = {};
            DWORD md5Size = sizeof(md5Bytes);
            DWORD sha1Size = sizeof(sha1Bytes);
            DWORD sha256Size = sizeof(sha256Bytes);

            if (!CryptGetHashParam(md5, HP_HASHVAL, md5Bytes, &md5Size, 0) ||
                !CryptGetHashParam(sha1, HP_HASHVAL, sha1Bytes, &sha1Size, 0) ||
                !CryptGetHashParam(sha256, HP_HASHVAL, sha256Bytes, &sha256Size, 0))
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CryptGetHashParam failed", GetLastError());
                }
                ok = false;
                break;
            }

            hashes->Md5 = HexBytes(md5Bytes, md5Size);
            hashes->Sha1 = HexBytes(sha1Bytes, sha1Size);
            hashes->Sha256 = HexBytes(sha256Bytes, sha256Size);
        } while (false);

        if (md5 != 0)
        {
            CryptDestroyHash(md5);
        }
        if (sha1 != 0)
        {
            CryptDestroyHash(sha1);
        }
        if (sha256 != 0)
        {
            CryptDestroyHash(sha256);
        }
        if (provider != 0)
        {
            CryptReleaseContext(provider, 0);
        }
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    std::wstring BaseNameOfPath(const std::wstring& path)
    {
        size_t slash = path.find_last_of(L"\\/");

        if (slash == std::wstring::npos)
        {
            return path;
        }

        return path.substr(slash + 1);
    }

    bool SearchPathForExecutable(const std::wstring& name, std::wstring* path)
    {
        bool ok = false;

        do
        {
            if (path == nullptr || name.empty())
            {
                break;
            }

            DWORD required = SearchPathW(nullptr, name.c_str(), nullptr, 0, nullptr, nullptr);
            if (required == 0)
            {
                break;
            }

            std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1, L'\0');
            DWORD written = SearchPathW(
                nullptr,
                name.c_str(),
                nullptr,
                static_cast<DWORD>(buffer.size()),
                buffer.data(),
                nullptr);
            if (written == 0 || written >= buffer.size())
            {
                break;
            }

            *path = buffer.data();
            ok = FileExists(*path);
        } while (false);

        return ok;
    }

    std::wstring ResolveYaraExecutable(
        const std::wstring& configured,
        const std::wstring& executableDirectory)
    {
        std::wstring result;

        do
        {
            if (!configured.empty())
            {
                std::wstring configuredFullPath = GetFullPathText(configured);
                if (FileExists(configuredFullPath))
                {
                    result = configuredFullPath;
                    break;
                }

                if (configured.find_first_of(L"\\/") == std::wstring::npos &&
                    SearchPathForExecutable(configured, &result))
                {
                    break;
                }

                break;
            }

            std::vector<std::wstring> candidates;
            candidates.push_back(JoinPath(executableDirectory, L"yara64.exe"));
            candidates.push_back(JoinPath(executableDirectory, L"yara.exe"));
            candidates.push_back(JoinPath(JoinPath(executableDirectory, L"tools"), L"yara64.exe"));
            candidates.push_back(JoinPath(JoinPath(executableDirectory, L"tools"), L"yara.exe"));
            candidates.push_back(GetFullPathText(JoinPath(JoinPath(executableDirectory, L"..\\tools"), L"yara64.exe")));
            candidates.push_back(GetFullPathText(JoinPath(JoinPath(executableDirectory, L"..\\tools"), L"yara.exe")));
            candidates.push_back(JoinPath(JoinPath(GetCurrentDirectoryText(), L"tools"), L"yara64.exe"));
            candidates.push_back(JoinPath(JoinPath(GetCurrentDirectoryText(), L"tools"), L"yara.exe"));

            for (const std::wstring& candidate : candidates)
            {
                if (FileExists(candidate))
                {
                    result = candidate;
                    break;
                }
            }

            if (!result.empty())
            {
                break;
            }

            if (SearchPathForExecutable(L"yara64.exe", &result))
            {
                break;
            }
            if (SearchPathForExecutable(L"yara.exe", &result))
            {
                break;
            }
        } while (false);

        return result;
    }

    std::vector<std::wstring> EnumerateYaraRuleFiles(const std::wstring& yaraDirectory)
    {
        std::vector<std::wstring> files;
        WIN32_FIND_DATAW data = {};
        std::wstring pattern = JoinPath(yaraDirectory, L"*.yar");
        HANDLE find = FindFirstFileW(pattern.c_str(), &data);

        if (find != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    files.push_back(JoinPath(yaraDirectory, data.cFileName));
                }
            } while (FindNextFileW(find, &data));

            FindClose(find);
        }

        std::sort(files.begin(), files.end());
        return files;
    }

    bool RunYaraProcess(
        const std::wstring& yaraExecutable,
        const std::wstring& ruleFile,
        const std::wstring& targetPath,
        uint32_t timeoutSeconds,
        YaraScanProcessResult* processResult,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE output = INVALID_HANDLE_VALUE;
        std::wstring tempFile;

        do
        {
            if (processResult == nullptr)
            {
                break;
            }

            *processResult = YaraScanProcessResult{};
            if (yaraExecutable.empty() || ruleFile.empty() || targetPath.empty())
            {
                if (error != nullptr)
                {
                    *error = L"YARA executable, rule file, or target path is empty";
                }
                break;
            }

            tempFile = GetTempFilePathText(L"kny");
            if (tempFile.empty())
            {
                if (error != nullptr)
                {
                    *error = L"failed to allocate temporary YARA output file";
                }
                break;
            }

            SECURITY_ATTRIBUTES security = {};
            security.nLength = sizeof(security);
            security.bInheritHandle = TRUE;

            output = CreateFileW(
                tempFile.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                &security,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
                nullptr);
            if (output == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CreateFileW YARA output failed", GetLastError());
                }
                break;
            }

            STARTUPINFOW startup = {};
            PROCESS_INFORMATION process = {};
            startup.cb = sizeof(startup);
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup.hStdOutput = output;
            startup.hStdError = output;

            std::wstring commandLine = QuoteArgument(yaraExecutable)
                + L" "
                + QuoteArgument(ruleFile)
                + L" "
                + QuoteArgument(targetPath);
            std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
            mutableCommand.push_back(L'\0');

            if (!CreateProcessW(
                    nullptr,
                    mutableCommand.data(),
                    nullptr,
                    nullptr,
                    TRUE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &process))
            {
                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"CreateProcessW yara failed", GetLastError());
                }
                break;
            }

            DWORD effectiveTimeout = timeoutSeconds != 0 ? timeoutSeconds : kDefaultYaraTimeoutSeconds;
            DWORD waitResult = WaitForSingleObject(process.hProcess, effectiveTimeout * 1000u);
            if (waitResult == WAIT_TIMEOUT)
            {
                processResult->TimedOut = true;
                TerminateProcess(process.hProcess, WAIT_TIMEOUT);
                WaitForSingleObject(process.hProcess, 5000);
            }
            else if (waitResult == WAIT_FAILED)
            {
                DWORD lastError = GetLastError();
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);

                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"WaitForSingleObject YARA failed", lastError);
                }
                break;
            }
            else if (waitResult != WAIT_OBJECT_0)
            {
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);

                if (error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"WaitForSingleObject YARA returned unexpected status " << waitResult;
                    *error = stream.str();
                }
                break;
            }

            DWORD exitCode = 1;
            if (!GetExitCodeProcess(process.hProcess, &exitCode))
            {
                DWORD lastError = GetLastError();
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);

                if (error != nullptr)
                {
                    *error = FormatWin32Text(L"GetExitCodeProcess YARA failed", lastError);
                }
                break;
            }

            processResult->ExitCode = exitCode;
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(output);
            output = INVALID_HANDLE_VALUE;

            std::wstring outputText;
            std::wstring readError;
            if (!ReadFileUtf8(tempFile, &outputText, &readError))
            {
                if (error != nullptr)
                {
                    *error = readError;
                }
                break;
            }

            processResult->Lines = SplitLines(outputText);
            if (processResult->TimedOut)
            {
                if (error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"YARA scan timed out after " << effectiveTimeout << L" seconds";
                    *error = stream.str();
                }
                break;
            }

            if (exitCode != 0)
            {
                if (error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"YARA exited with code " << exitCode;
                    if (!outputText.empty())
                    {
                        stream << L": " << TrimCopy(outputText);
                    }
                    *error = stream.str();
                }
                break;
            }

            ok = true;
        } while (false);

        if (output != INVALID_HANDLE_VALUE)
        {
            CloseHandle(output);
        }
        if (!tempFile.empty())
        {
            DeleteFileW(tempFile.c_str());
        }

        return ok;
    }

    std::wstring YaraCategoryFromRuleFile(const std::wstring& ruleFile)
    {
        std::wstring baseName = ToLowerCopy(BaseNameOfPath(ruleFile));
        std::wstring category = L"loldrivers_yara";

        if (baseName.find(L"mal") != std::wstring::npos)
        {
            category = L"loldrivers_yara_malicious";
        }
        else if (baseName.find(L"vuln") != std::wstring::npos)
        {
            category = L"loldrivers_yara_vulnerable_strict";
        }

        return category;
    }

    std::wstring FirstToken(const std::wstring& line)
    {
        std::wstring token;
        std::wstring trimmed = TrimCopy(line);

        do
        {
            if (trimmed.empty())
            {
                break;
            }

            size_t space = trimmed.find_first_of(L" \t");
            token = space == std::wstring::npos ? trimmed : trimmed.substr(0, space);
        } while (false);

        return token;
    }

    bool IsYaraDiagnosticLine(const std::wstring& line)
    {
        std::wstring lower = ToLowerCopy(TrimCopy(line));
        bool diagnostic = false;

        if (lower.empty() ||
            lower.rfind(L"warning:", 0) == 0 ||
            lower.rfind(L"error:", 0) == 0 ||
            lower.find(L" could not ") != std::wstring::npos)
        {
            diagnostic = true;
        }

        return diagnostic;
    }

    std::wstring ResolveModuleDiskPath(const KernelModuleInfo& module)
    {
        std::wstring result = module.ImagePath;

        if (result.rfind(L"\\SystemRoot\\", 0) == 0)
        {
            wchar_t windowsPath[MAX_PATH] = {};
            if (GetWindowsDirectoryW(windowsPath, static_cast<UINT>(std::size(windowsPath))) != 0)
            {
                result = std::wstring(windowsPath) + result.substr(std::wstring(L"\\SystemRoot").size());
            }
        }
        else if (result.rfind(L"SystemRoot\\", 0) == 0)
        {
            wchar_t windowsPath[MAX_PATH] = {};
            if (GetWindowsDirectoryW(windowsPath, static_cast<UINT>(std::size(windowsPath))) != 0)
            {
                result = std::wstring(windowsPath) + result.substr(std::wstring(L"SystemRoot").size());
            }
        }
        else if (result.rfind(L"\\??\\", 0) == 0)
        {
            result = result.substr(4);
        }

        return result;
    }

    VersionQuad ParseVersion(const std::wstring& text)
    {
        VersionQuad version = {};
        std::wstring value = TrimCopy(text);
        size_t start = 0;
        size_t partIndex = 0;

        do
        {
            if (value.empty())
            {
                break;
            }

            for (;;)
            {
                if (partIndex >= version.Parts.size())
                {
                    break;
                }

                size_t dot = value.find(L'.', start);
                std::wstring part = dot == std::wstring::npos
                    ? value.substr(start)
                    : value.substr(start, dot - start);

                part = TrimCopy(part);
                if (part.empty())
                {
                    break;
                }

                uint64_t parsed = 0;
                bool digits = true;
                for (wchar_t ch : part)
                {
                    if (ch < L'0' || ch > L'9')
                    {
                        digits = false;
                        break;
                    }
                    parsed = (parsed * 10) + static_cast<uint64_t>(ch - L'0');
                }

                if (!digits)
                {
                    break;
                }

                version.Parts[partIndex] = parsed;
                ++partIndex;

                if (dot == std::wstring::npos)
                {
                    version.Valid = true;
                    break;
                }

                start = dot + 1;
            }
        } while (false);

        return version;
    }

    int CompareVersion(const VersionQuad& left, const VersionQuad& right)
    {
        int result = 0;

        for (size_t index = 0; index < left.Parts.size(); ++index)
        {
            if (left.Parts[index] < right.Parts[index])
            {
                result = -1;
                break;
            }
            if (left.Parts[index] > right.Parts[index])
            {
                result = 1;
                break;
            }
        }

        return result;
    }

    bool VersionInRange(const VersionQuad& value, const std::wstring& minimum, const std::wstring& maximum)
    {
        bool inRange = false;

        do
        {
            if (!value.Valid)
            {
                break;
            }

            VersionQuad minVersion = ParseVersion(minimum);
            VersionQuad maxVersion = ParseVersion(maximum);

            if (minVersion.Valid && CompareVersion(value, minVersion) < 0)
            {
                break;
            }
            if (maxVersion.Valid && CompareVersion(value, maxVersion) > 0)
            {
                break;
            }

            inRange = true;
        } while (false);

        return inRange;
    }

    std::wstring VersionToText(const VersionQuad& version)
    {
        std::wstringstream stream;
        stream << version.Parts[0] << L"."
               << version.Parts[1] << L"."
               << version.Parts[2] << L"."
               << version.Parts[3];
        return stream.str();
    }

    bool ReadFileVersion(const std::wstring& path, std::wstring* versionText)
    {
        bool ok = false;

        do
        {
            if (versionText == nullptr)
            {
                break;
            }

            DWORD handle = 0;
            DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
            if (size == 0)
            {
                break;
            }

            std::vector<BYTE> buffer(size);
            if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data()))
            {
                break;
            }

            VS_FIXEDFILEINFO* info = nullptr;
            UINT infoSize = 0;
            if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&info), &infoSize) ||
                info == nullptr ||
                infoSize < sizeof(VS_FIXEDFILEINFO) ||
                info->dwSignature != VS_FFI_SIGNATURE)
            {
                break;
            }

            VersionQuad version = {};
            version.Valid = true;
            version.Parts[0] = HIWORD(info->dwFileVersionMS);
            version.Parts[1] = LOWORD(info->dwFileVersionMS);
            version.Parts[2] = HIWORD(info->dwFileVersionLS);
            version.Parts[3] = LOWORD(info->dwFileVersionLS);
            *versionText = VersionToText(version);
            ok = true;
        } while (false);

        return ok;
    }

    void AddHashIndex(
        const std::vector<ByovdCatalogEntry>& entries,
        const std::wstring& matchType,
        std::unordered_map<std::wstring, std::vector<size_t>>* index)
    {
        do
        {
            if (index == nullptr)
            {
                break;
            }

            for (size_t i = 0; i < entries.size(); ++i)
            {
                if (entries[i].MatchType == matchType && !entries[i].Value.empty())
                {
                    (*index)[entries[i].Value].push_back(i);
                }
            }
        } while (false);
    }

    void AddHashMatches(
        const std::vector<ByovdCatalogEntry>& entries,
        const std::unordered_map<std::wstring, std::vector<size_t>>& index,
        const std::wstring& hash,
        const std::wstring& reason,
        ByovdModuleRecord* record,
        ByovdScanResult* result)
    {
        do
        {
            if (record == nullptr || result == nullptr || hash.empty())
            {
                break;
            }

            auto it = index.find(hash);
            if (it == index.end())
            {
                break;
            }

            for (size_t entryIndex : it->second)
            {
                ByovdMatch match = {};
                match.Entry = entries[entryIndex];
                match.Confidence = L"HIGH";
                match.Reason = reason;
                record->Matches.push_back(std::move(match));
                ++result->ExactMatches;
            }
        } while (false);
    }

    bool EntryIsFileVersionHint(const ByovdCatalogEntry& entry)
    {
        return entry.MatchType == L"file_version" && !entry.Name.empty();
    }

    void AddFileVersionMatches(
        const std::vector<ByovdCatalogEntry>& entries,
        const std::wstring& baseName,
        const std::wstring& fileVersion,
        ByovdModuleRecord* record,
        ByovdScanResult* result)
    {
        do
        {
            if (record == nullptr || result == nullptr || baseName.empty() || fileVersion.empty())
            {
                break;
            }

            VersionQuad version = ParseVersion(fileVersion);
            if (!version.Valid)
            {
                break;
            }

            std::wstring normalizedBase = ToLowerCopy(baseName);
            for (const ByovdCatalogEntry& entry : entries)
            {
                if (!EntryIsFileVersionHint(entry))
                {
                    continue;
                }

                if (ToLowerCopy(entry.Name) != normalizedBase)
                {
                    continue;
                }

                if (!VersionInRange(version, entry.MinimumVersion, entry.MaximumVersion))
                {
                    continue;
                }

                ByovdMatch match = {};
                match.Entry = entry;
                match.Confidence = L"MEDIUM";
                match.Reason = L"file name and version are inside a Microsoft blocklist file-attribute range";
                record->Matches.push_back(std::move(match));
                ++result->HintMatches;
            }
        } while (false);
    }

    std::wstring JsonEscape(const std::wstring& value)
    {
        std::wstring result;

        for (wchar_t ch : value)
        {
            switch (ch)
            {
            case L'\\':
                result += L"\\\\";
                break;
            case L'"':
                result += L"\\\"";
                break;
            case L'\n':
                result += L"\\n";
                break;
            case L'\r':
                result += L"\\r";
                break;
            case L'\t':
                result += L"\\t";
                break;
            default:
                result.push_back(ch);
                break;
            }
        }

        return result;
    }
}

ByovdScanner::ByovdScanner(SymbolEngine& symbols, const std::wstring& executableDirectory) :
    symbols_(symbols),
    executableDirectory_(executableDirectory)
{
    dataDirectory_ = JoinPath(JoinPath(executableDirectory_, L"data"), L"byovd");
    catalogPath_ = JoinPath(dataDirectory_, L"byovd_catalog.tsv");
    manifestPath_ = JoinPath(dataDirectory_, L"manifest.json");
}

const std::wstring& ByovdScanner::DataDirectory() const
{
    return dataDirectory_;
}

const std::wstring& ByovdScanner::CatalogPath() const
{
    return catalogPath_;
}

const std::wstring& ByovdScanner::ManifestPath() const
{
    return manifestPath_;
}

bool ByovdScanner::LoadCatalog(std::vector<ByovdCatalogEntry>* entries, std::wstring* error) const
{
    bool ok = false;

    do
    {
        if (entries == nullptr)
        {
            break;
        }

        entries->clear();
        std::wstring text;
        if (!ReadFileUtf8(catalogPath_, &text, error))
        {
            break;
        }

        std::wstringstream stream(text);
        std::wstring line;
        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            if (line.empty() || line[0] == L'#')
            {
                continue;
            }

            std::vector<std::wstring> fields = SplitTabs(line);
            if (fields.size() < 8)
            {
                continue;
            }

            ByovdCatalogEntry entry = {};
            entry.Source = ToLowerCopy(TrimCopy(fields[0]));
            entry.Category = ToLowerCopy(TrimCopy(fields[1]));
            entry.MatchType = ToLowerCopy(TrimCopy(fields[2]));
            entry.Value = ToLowerCopy(TrimCopy(fields[3]));
            entry.Name = ToLowerCopy(TrimCopy(fields[4]));
            entry.MinimumVersion = TrimCopy(fields[5]);
            entry.MaximumVersion = TrimCopy(fields[6]);
            entry.Description = TrimCopy(fields[7]);

            if (!entry.MatchType.empty() && (!entry.Value.empty() || !entry.Name.empty()))
            {
                entries->push_back(std::move(entry));
            }
        }

        ok = true;
    } while (false);

    return ok;
}

bool ByovdScanner::CatalogIsStale(uint64_t maxAgeSeconds, bool* stale, uint64_t* ageSeconds, std::wstring* error) const
{
    bool ok = false;

    do
    {
        if (stale == nullptr)
        {
            break;
        }

        *stale = true;
        if (ageSeconds != nullptr)
        {
            *ageSeconds = 0;
        }

        WIN32_FILE_ATTRIBUTE_DATA data = {};
        if (!GetFileAttributesExW(catalogPath_.c_str(), GetFileExInfoStandard, &data))
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
            {
                ok = true;
                break;
            }

            if (error != nullptr)
            {
                *error = FormatWin32Text(L"GetFileAttributesExW failed", lastError);
            }
            break;
        }

        FILETIME nowFileTime = {};
        GetSystemTimeAsFileTime(&nowFileTime);

        ULARGE_INTEGER now = {};
        ULARGE_INTEGER write = {};
        now.LowPart = nowFileTime.dwLowDateTime;
        now.HighPart = nowFileTime.dwHighDateTime;
        write.LowPart = data.ftLastWriteTime.dwLowDateTime;
        write.HighPart = data.ftLastWriteTime.dwHighDateTime;

        uint64_t seconds = 0;
        if (now.QuadPart >= write.QuadPart)
        {
            seconds = (now.QuadPart - write.QuadPart) / 10000000ull;
        }

        if (ageSeconds != nullptr)
        {
            *ageSeconds = seconds;
        }

        *stale = seconds > maxAgeSeconds;
        ok = true;
    } while (false);

    return ok;
}

bool ByovdScanner::RunUpdaterScript(bool force, std::vector<std::wstring>* messages, std::wstring* error) const
{
    bool ok = false;

    do
    {
        std::wstring localError;
        if (!EnsureDirectory(dataDirectory_, &localError))
        {
            if (error != nullptr)
            {
                *error = localError;
            }
            break;
        }

        std::vector<std::wstring> candidates;
        candidates.push_back(JoinPath(JoinPath(executableDirectory_, L"tools"), L"update-byovd-intel.ps1"));
        candidates.push_back(GetFullPathText(JoinPath(JoinPath(executableDirectory_, L"..\\tools"), L"update-byovd-intel.ps1")));
        candidates.push_back(GetFullPathText(JoinPath(JoinPath(executableDirectory_, L"..\\..\\tools"), L"update-byovd-intel.ps1")));
        candidates.push_back(JoinPath(JoinPath(GetCurrentDirectoryText(), L"tools"), L"update-byovd-intel.ps1"));

        std::wstring scriptPath;
        for (const std::wstring& candidate : candidates)
        {
            if (FileExists(candidate))
            {
                scriptPath = candidate;
                break;
            }
        }

        if (scriptPath.empty())
        {
            if (error != nullptr)
            {
                *error = L"update-byovd-intel.ps1 was not found near the executable or current directory";
            }
            break;
        }

        std::wstring commandLine = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
            + QuoteArgument(scriptPath)
            + L" -OutputDir "
            + QuoteArgument(dataDirectory_);
        if (force)
        {
            commandLine += L" -Force";
        }

        if (messages != nullptr)
        {
            messages->push_back(L"byovd update script=" + scriptPath);
            messages->push_back(L"byovd data=" + dataDirectory_);
        }

        STARTUPINFOW startup = {};
        PROCESS_INFORMATION process = {};
        startup.cb = sizeof(startup);

        std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
        mutableCommand.push_back(L'\0');

        if (!CreateProcessW(
                nullptr,
                mutableCommand.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                nullptr,
                &startup,
                &process))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Text(L"CreateProcessW powershell.exe failed", GetLastError());
            }
            break;
        }

        DWORD waitResult = WaitForSingleObject(process.hProcess, kUpdaterTimeoutMs);
        if (waitResult == WAIT_TIMEOUT)
        {
            TerminateProcess(process.hProcess, WAIT_TIMEOUT);
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);

            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"update-byovd-intel.ps1 timed out after "
                       << (kUpdaterTimeoutMs / 1000u) << L" seconds";
                *error = stream.str();
            }
            break;
        }
        if (waitResult == WAIT_FAILED)
        {
            DWORD lastError = GetLastError();
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);

            if (error != nullptr)
            {
                *error = FormatWin32Text(L"WaitForSingleObject failed", lastError);
            }
            break;
        }
        if (waitResult != WAIT_OBJECT_0)
        {
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);

            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"WaitForSingleObject returned unexpected status " << waitResult;
                *error = stream.str();
            }
            break;
        }

        DWORD exitCode = 1;
        if (!GetExitCodeProcess(process.hProcess, &exitCode))
        {
            DWORD lastError = GetLastError();
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);

            if (error != nullptr)
            {
                *error = FormatWin32Text(L"GetExitCodeProcess failed", lastError);
            }
            break;
        }

        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);

        if (exitCode != 0)
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"update-byovd-intel.ps1 failed with exit code " << exitCode;
                *error = stream.str();
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool ByovdScanner::UpdateCatalog(bool force, std::vector<std::wstring>* messages, std::wstring* error)
{
    return RunUpdaterScript(force, messages, error);
}

bool ByovdScanner::QueryCatalogStatus(ByovdCatalogStatus* status, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (status == nullptr)
        {
            break;
        }

        *status = ByovdCatalogStatus{};
        status->DataDirectory = dataDirectory_;
        status->CatalogPath = catalogPath_;
        status->ManifestPath = manifestPath_;
        status->YaraDirectory = JoinPath(dataDirectory_, L"yara");

        bool stale = true;
        uint64_t age = 0;
        if (!CatalogIsStale(kCatalogMaxAgeSeconds, &stale, &age, error))
        {
            break;
        }

        status->HasCatalog = FileExists(catalogPath_);
        status->Stale = stale;
        status->AgeSeconds = age;
        std::vector<std::wstring> yaraRules = EnumerateYaraRuleFiles(status->YaraDirectory);
        status->YaraRuleFileCount = yaraRules.size();
        status->HasYaraRules = !yaraRules.empty();

        if (status->HasCatalog)
        {
            std::vector<ByovdCatalogEntry> entries;
            if (!LoadCatalog(&entries, error))
            {
                break;
            }

            status->EntryCount = entries.size();
            for (const ByovdCatalogEntry& entry : entries)
            {
                ++status->SourceCounts[entry.Source];
                ++status->MatchTypeCounts[entry.MatchType];
            }
        }

        ok = true;
    } while (false);

    return ok;
}

bool ByovdScanner::Scan(const ByovdScanOptions& options, ByovdScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid BYOVD scan result output";
            }
            break;
        }

        *result = ByovdScanResult{};

        bool stale = true;
        uint64_t age = 0;
        std::wstring staleError;
        if (!CatalogIsStale(kCatalogMaxAgeSeconds, &stale, &age, &staleError))
        {
            result->Warnings.push_back(L"catalog age check failed: " + staleError);
        }

        if (options.ForceUpdate || (options.AutoUpdate && stale))
        {
            result->CatalogUpdateAttempted = true;
            std::wstring updateError;
            if (RunUpdaterScript(options.ForceUpdate, &result->Messages, &updateError))
            {
                result->CatalogUpdated = true;
            }
            else
            {
                result->Warnings.push_back(L"catalog update failed: " + updateError);
                if (!FileExists(catalogPath_))
                {
                    if (error != nullptr)
                    {
                        *error = L"BYOVD catalog is missing and update failed: " + updateError;
                    }
                    break;
                }
            }
        }
        else
        {
            std::wstringstream stream;
            stream << L"byovd catalog age=" << age << L"s";
            result->Messages.push_back(stream.str());
        }

        std::vector<ByovdCatalogEntry> entries;
        if (!LoadCatalog(&entries, error))
        {
            break;
        }

        if (entries.empty())
        {
            if (error != nullptr)
            {
                *error = L"BYOVD catalog is empty";
            }
            break;
        }

        if (symbols_.Modules().empty())
        {
            if (!symbols_.LoadKernelModules(error))
            {
                break;
            }
        }

        std::unordered_map<std::wstring, std::vector<size_t>> md5Index;
        std::unordered_map<std::wstring, std::vector<size_t>> sha1Index;
        std::unordered_map<std::wstring, std::vector<size_t>> sha256Index;
        AddHashIndex(entries, L"md5", &md5Index);
        AddHashIndex(entries, L"sha1", &sha1Index);
        AddHashIndex(entries, L"sha256", &sha256Index);

        std::wstring yaraExecutable;
        std::vector<std::wstring> yaraRuleFiles;
        if (options.EnableYara)
        {
            yaraRuleFiles = EnumerateYaraRuleFiles(JoinPath(dataDirectory_, L"yara"));
            result->YaraRuleFiles = yaraRuleFiles;
            yaraExecutable = ResolveYaraExecutable(options.YaraExecutable, executableDirectory_);
            result->YaraExecutable = yaraExecutable;

            if (yaraExecutable.empty())
            {
                if (!options.YaraExecutable.empty())
                {
                    result->Warnings.push_back(L"YARA requested but configured executable was not found: " + options.YaraExecutable);
                }
                else
                {
                    result->Warnings.push_back(L"YARA requested but yara64.exe/yara.exe was not found beside the executable, in tools, or on PATH");
                }
            }
            if (yaraRuleFiles.empty())
            {
                result->Warnings.push_back(L"YARA requested but no .yar files were found under " + JoinPath(dataDirectory_, L"yara"));
            }
            if (!yaraExecutable.empty() && !yaraRuleFiles.empty())
            {
                result->Messages.push_back(L"byovd yara executable=" + yaraExecutable);
                std::wstringstream stream;
                stream << L"byovd yara rules=" << yaraRuleFiles.size();
                result->Messages.push_back(stream.str());
            }
        }

        for (const KernelModuleInfo& module : symbols_.Modules())
        {
            ++result->ModulesScanned;

            ByovdModuleRecord record = {};
            record.ImageName = module.ImageName;
            record.ImagePath = module.ImagePath;
            record.DiskPath = ResolveModuleDiskPath(module);
            record.Base = module.Base;
            record.Size = module.Size;

            std::wstring hashError;
            FileHashes hashes = {};
            if (ComputeFileHashes(record.DiskPath, &hashes, &hashError))
            {
                record.FileHashed = true;
                record.Md5 = hashes.Md5;
                record.Sha1 = hashes.Sha1;
                record.Sha256 = hashes.Sha256;
                ++result->FilesHashed;

                AddHashMatches(entries, md5Index, record.Md5, L"exact MD5 sample hash match", &record, result);
                AddHashMatches(entries, sha1Index, record.Sha1, L"exact SHA1 sample hash match", &record, result);
                AddHashMatches(entries, sha256Index, record.Sha256, L"exact SHA256 sample hash match", &record, result);
            }
            else
            {
                record.Error = hashError;
                ++result->FileReadFailures;
            }

            if (!options.ExactOnly)
            {
                if (ReadFileVersion(record.DiskPath, &record.FileVersion))
                {
                    record.VersionRead = true;
                    AddFileVersionMatches(entries, BaseNameOfPath(record.DiskPath), record.FileVersion, &record, result);
                }
            }

            if (options.EnableYara && !yaraExecutable.empty() && !yaraRuleFiles.empty())
            {
                if (!FileExists(record.DiskPath))
                {
                    record.YaraError = L"disk image was not found";
                    ++result->YaraFailures;
                }
                else
                {
                    for (const std::wstring& ruleFile : yaraRuleFiles)
                    {
                        YaraScanProcessResult yara = {};
                        std::wstring yaraError;
                        record.YaraScanned = true;
                        ++result->YaraScans;
                        if (RunYaraProcess(
                                yaraExecutable,
                                ruleFile,
                                record.DiskPath,
                                options.YaraTimeoutSeconds,
                                &yara,
                                &yaraError))
                        {
                            for (const std::wstring& line : yara.Lines)
                            {
                                if (IsYaraDiagnosticLine(line))
                                {
                                    continue;
                                }

                                std::wstring ruleName = FirstToken(line);
                                if (ruleName.empty())
                                {
                                    continue;
                                }

                                ByovdMatch match = {};
                                match.Entry.Source = L"loldrivers_yara";
                                match.Entry.Category = YaraCategoryFromRuleFile(ruleFile);
                                match.Entry.MatchType = L"yara";
                                match.Entry.Value = ruleName;
                                match.Entry.Name = BaseNameOfPath(record.DiskPath);
                                match.Entry.Description = BaseNameOfPath(ruleFile);
                                match.Confidence = L"HIGH";
                                match.Reason = L"LOLDrivers YARA rule match";
                                record.Matches.push_back(std::move(match));
                                ++result->YaraMatches;
                            }
                        }
                        else
                        {
                            record.YaraError = yaraError;
                            ++result->YaraFailures;
                            if (yara.TimedOut)
                            {
                                record.YaraTimedOut = true;
                                ++result->YaraTimeouts;
                            }
                        }
                    }
                }
            }

            if (!record.Matches.empty())
            {
                ++result->MatchedModules;
            }

            if (!record.Matches.empty() || options.Verbose)
            {
                if (options.Limit != 0 && result->Records.size() >= options.Limit)
                {
                    result->Truncated = true;
                    continue;
                }

                result->Records.push_back(std::move(record));
            }
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildByovdScanJson(const ByovdScanResult& result)
{
    std::wstringstream stream;

    stream << L"{\"schema\":\"kn-live-dbg.byovd-scan.v1\",";
    stream << L"\"summary\":{";
    stream << L"\"modules_scanned\":" << result.ModulesScanned << L",";
    stream << L"\"files_hashed\":" << result.FilesHashed << L",";
    stream << L"\"file_read_failures\":" << result.FileReadFailures << L",";
    stream << L"\"matched_modules\":" << result.MatchedModules << L",";
    stream << L"\"exact_matches\":" << result.ExactMatches << L",";
    stream << L"\"hint_matches\":" << result.HintMatches << L",";
    stream << L"\"yara_scans\":" << result.YaraScans << L",";
    stream << L"\"yara_matches\":" << result.YaraMatches << L",";
    stream << L"\"yara_failures\":" << result.YaraFailures << L",";
    stream << L"\"yara_timeouts\":" << result.YaraTimeouts << L",";
    stream << L"\"catalog_updated\":" << (result.CatalogUpdated ? L"true" : L"false") << L",";
    stream << L"\"catalog_update_attempted\":" << (result.CatalogUpdateAttempted ? L"true" : L"false") << L",";
    stream << L"\"truncated\":" << (result.Truncated ? L"true" : L"false") << L"},";

    stream << L"\"yara\":{";
    stream << L"\"executable\":\"" << JsonEscape(result.YaraExecutable) << L"\",";
    stream << L"\"rule_files\":[";
    for (size_t i = 0; i < result.YaraRuleFiles.size(); ++i)
    {
        if (i != 0)
        {
            stream << L",";
        }
        stream << L"\"" << JsonEscape(result.YaraRuleFiles[i]) << L"\"";
    }
    stream << L"]},";

    stream << L"\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            stream << L",";
        }
        stream << L"\"" << JsonEscape(result.Warnings[i]) << L"\"";
    }
    stream << L"],";

    stream << L"\"records\":[";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const ByovdModuleRecord& record = result.Records[i];
        if (i != 0)
        {
            stream << L",";
        }

        stream << L"{";
        stream << L"\"image_name\":\"" << JsonEscape(record.ImageName) << L"\",";
        stream << L"\"image_path\":\"" << JsonEscape(record.ImagePath) << L"\",";
        stream << L"\"disk_path\":\"" << JsonEscape(record.DiskPath) << L"\",";
        stream << L"\"base\":" << record.Base << L",";
        stream << L"\"size\":" << record.Size << L",";
        stream << L"\"file_version\":\"" << JsonEscape(record.FileVersion) << L"\",";
        stream << L"\"md5\":\"" << JsonEscape(record.Md5) << L"\",";
        stream << L"\"sha1\":\"" << JsonEscape(record.Sha1) << L"\",";
        stream << L"\"sha256\":\"" << JsonEscape(record.Sha256) << L"\",";
        stream << L"\"error\":\"" << JsonEscape(record.Error) << L"\",";
        stream << L"\"yara_error\":\"" << JsonEscape(record.YaraError) << L"\",";
        stream << L"\"yara_scanned\":" << (record.YaraScanned ? L"true" : L"false") << L",";
        stream << L"\"yara_timed_out\":" << (record.YaraTimedOut ? L"true" : L"false") << L",";
        stream << L"\"matches\":[";
        for (size_t m = 0; m < record.Matches.size(); ++m)
        {
            const ByovdMatch& match = record.Matches[m];
            if (m != 0)
            {
                stream << L",";
            }

            stream << L"{";
            stream << L"\"source\":\"" << JsonEscape(match.Entry.Source) << L"\",";
            stream << L"\"category\":\"" << JsonEscape(match.Entry.Category) << L"\",";
            stream << L"\"match_type\":\"" << JsonEscape(match.Entry.MatchType) << L"\",";
            stream << L"\"value\":\"" << JsonEscape(match.Entry.Value) << L"\",";
            stream << L"\"name\":\"" << JsonEscape(match.Entry.Name) << L"\",";
            stream << L"\"minimum_version\":\"" << JsonEscape(match.Entry.MinimumVersion) << L"\",";
            stream << L"\"maximum_version\":\"" << JsonEscape(match.Entry.MaximumVersion) << L"\",";
            stream << L"\"description\":\"" << JsonEscape(match.Entry.Description) << L"\",";
            stream << L"\"confidence\":\"" << JsonEscape(match.Confidence) << L"\",";
            stream << L"\"reason\":\"" << JsonEscape(match.Reason) << L"\"}";
        }
        stream << L"]}";
    }
    stream << L"]}";

    return stream.str();
}
