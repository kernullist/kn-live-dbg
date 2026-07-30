#include <Windows.h>

#include <array>
#include <cstdint>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    constexpr wchar_t kFixturePrefix[] =
        L"KnLiveDbgBindFixture-";
    constexpr wchar_t kFileVirtualName[] =
        L"amsi.dll";
    constexpr wchar_t kFileBackingName[] =
        L"backing.dll";
    constexpr wchar_t kProcessVirtualName[] =
        L"MsSense.exe";
    constexpr wchar_t kProcessBackingName[] =
        L"ProcessBindingBacking.exe";

    using BfSetupFilterFn = HRESULT(WINAPI*)(
        HANDLE,
        ULONG,
        LPCWSTR,
        LPCWSTR,
        LPCWSTR*,
        ULONG);
    using BfRemoveMappingFn = HRESULT(WINAPI*)(
        HANDLE,
        LPCWSTR);

    struct BindFilterApi
    {
        HMODULE Module = nullptr;
        BfSetupFilterFn Setup = nullptr;
        BfRemoveMappingFn Remove = nullptr;

        ~BindFilterApi()
        {
            if (Module != nullptr)
            {
                FreeLibrary(Module);
                Module = nullptr;
            }
        }

        bool Load(std::wstring* error)
        {
            Module = LoadLibraryExW(
                L"bindfltapi.dll",
                nullptr,
                LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (Module == nullptr)
            {
                if (error != nullptr)
                {
                    *error =
                        L"bindfltapi.dll could not be loaded from System32";
                }
                return false;
            }

            Setup = reinterpret_cast<BfSetupFilterFn>(
                GetProcAddress(
                    Module,
                    "BfSetupFilter"));
            Remove = reinterpret_cast<BfRemoveMappingFn>(
                GetProcAddress(
                    Module,
                    "BfRemoveMapping"));
            if (Setup == nullptr ||
                Remove == nullptr)
            {
                if (error != nullptr)
                {
                    *error =
                        L"required Bind Filter API exports are unavailable";
                }
                return false;
            }
            return true;
        }
    };

    bool EqualInsensitive(
        const std::wstring& left,
        const std::wstring& right)
    {
        return CompareStringOrdinal(
                   left.c_str(),
                   static_cast<int>(left.size()),
                   right.c_str(),
                   static_cast<int>(right.size()),
                   TRUE) == CSTR_EQUAL;
    }

    void NormalizeSeparators(
        std::wstring* value)
    {
        if (value == nullptr)
        {
            return;
        }
        for (wchar_t& ch : *value)
        {
            if (ch == L'/')
            {
                ch = L'\\';
            }
        }
    }

    void TrimDirectorySeparator(
        std::wstring* value)
    {
        if (value == nullptr)
        {
            return;
        }
        while (value->size() > 3 &&
               value->back() == L'\\')
        {
            value->pop_back();
        }
    }

    bool FullPath(
        const std::wstring& input,
        std::wstring* output,
        std::wstring* error)
    {
        if (output == nullptr ||
            input.empty())
        {
            if (error != nullptr)
            {
                *error = L"path is empty";
            }
            return false;
        }

        const DWORD required =
            GetFullPathNameW(
                input.c_str(),
                0,
                nullptr,
                nullptr);
        if (required == 0 ||
            required > 32760)
        {
            if (error != nullptr)
            {
                *error =
                    L"path could not be normalized";
            }
            return false;
        }

        std::vector<wchar_t> buffer(
            static_cast<size_t>(required) + 1,
            L'\0');
        const DWORD written =
            GetFullPathNameW(
                input.c_str(),
                static_cast<DWORD>(buffer.size()),
                buffer.data(),
                nullptr);
        if (written == 0 ||
            written >= buffer.size())
        {
            if (error != nullptr)
            {
                *error =
                    L"path normalization returned an invalid length";
            }
            return false;
        }

        output->assign(
            buffer.data(),
            written);
        NormalizeSeparators(output);
        TrimDirectorySeparator(output);
        return true;
    }

    bool GetTemporaryRoot(
        std::wstring* output,
        std::wstring* error)
    {
        if (output == nullptr)
        {
            return false;
        }

        const DWORD required =
            GetTempPathW(
                0,
                nullptr);
        if (required == 0 ||
            required > 32760)
        {
            if (error != nullptr)
            {
                *error =
                    L"Windows temporary path is unavailable";
            }
            return false;
        }

        std::vector<wchar_t> buffer(
            static_cast<size_t>(required) + 1,
            L'\0');
        const DWORD written =
            GetTempPathW(
                static_cast<DWORD>(buffer.size()),
                buffer.data());
        if (written == 0 ||
            written >= buffer.size())
        {
            if (error != nullptr)
            {
                *error =
                    L"Windows temporary path returned an invalid length";
            }
            return false;
        }

        return FullPath(
            std::wstring(
                buffer.data(),
                written),
            output,
            error);
    }

    bool IsHexSuffix(
        const std::wstring& value)
    {
        if (value.size() != 32)
        {
            return false;
        }
        for (wchar_t ch : value)
        {
            if (!((ch >= L'0' && ch <= L'9') ||
                  (ch >= L'a' && ch <= L'f') ||
                  (ch >= L'A' && ch <= L'F')))
            {
                return false;
            }
        }
        return true;
    }

    bool ValidateFixtureDirectory(
        const std::wstring& input,
        bool requireExisting,
        std::wstring* normalized,
        std::wstring* error)
    {
        std::wstring full;
        std::wstring temporaryRoot;
        if (!FullPath(
                input,
                &full,
                error) ||
            !GetTemporaryRoot(
                &temporaryRoot,
                error))
        {
            return false;
        }

        if (full.size() < 3 ||
            !std::iswalpha(full[0]) ||
            full[1] != L':' ||
            full[2] != L'\\')
        {
            if (error != nullptr)
            {
                *error =
                    L"fixture directory must be on a local drive";
            }
            return false;
        }

        const size_t separator =
            full.find_last_of(L'\\');
        if (separator == std::wstring::npos ||
            separator + 1 >= full.size())
        {
            if (error != nullptr)
            {
                *error =
                    L"fixture directory has no leaf name";
            }
            return false;
        }

        const std::wstring parent =
            full.substr(0, separator);
        const std::wstring leaf =
            full.substr(separator + 1);
        const std::wstring prefix =
            kFixturePrefix;
        if (!EqualInsensitive(
                parent,
                temporaryRoot) ||
            leaf.size() !=
                prefix.size() + 32 ||
            _wcsnicmp(
                leaf.c_str(),
                prefix.c_str(),
                prefix.size()) != 0 ||
            !IsHexSuffix(
                leaf.substr(prefix.size())))
        {
            if (error != nullptr)
            {
                *error =
                    L"fixture directory must be a direct temporary child named KnLiveDbgBindFixture-<32 hex>";
            }
            return false;
        }

        if (requireExisting)
        {
            const DWORD attributes =
                GetFileAttributesW(full.c_str());
            if (attributes ==
                    INVALID_FILE_ATTRIBUTES ||
                (attributes &
                    FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (attributes &
                    FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                if (error != nullptr)
                {
                    *error =
                        L"fixture directory is missing, not a directory, or a reparse point";
                }
                return false;
            }
        }

        if (normalized != nullptr)
        {
            *normalized = full;
        }
        return true;
    }

    std::wstring ChildPath(
        const std::wstring& directory,
        const wchar_t* leaf)
    {
        return directory +
            L"\\" +
            leaf;
    }

    bool ValidateRegularFile(
        const std::wstring& path,
        std::wstring* error)
    {
        const DWORD attributes =
            GetFileAttributesW(path.c_str());
        if (attributes ==
                INVALID_FILE_ATTRIBUTES ||
            (attributes &
                FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            (attributes &
                FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            if (error != nullptr)
            {
                *error =
                    L"required fixture file is missing, a directory, or a reparse point: " +
                    path;
            }
            return false;
        }
        return true;
    }

    bool ReadFileIdentity(
        const std::wstring& path,
        BY_HANDLE_FILE_INFORMATION* information,
        std::wstring* error)
    {
        if (information == nullptr)
        {
            return false;
        }

        HANDLE file =
            CreateFileW(
                path.c_str(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ |
                    FILE_SHARE_WRITE |
                    FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error =
                    L"fixture file identity could not be opened: " +
                    path;
            }
            return false;
        }

        const BOOL ok =
            GetFileInformationByHandle(
                file,
                information);
        CloseHandle(file);
        if (!ok)
        {
            if (error != nullptr)
            {
                *error =
                    L"fixture file identity could not be read: " +
                    path;
            }
            return false;
        }
        return true;
    }

    bool AreSameFile(
        const std::wstring& left,
        const std::wstring& right,
        bool* same,
        std::wstring* error)
    {
        if (same == nullptr)
        {
            return false;
        }
        *same = false;

        BY_HANDLE_FILE_INFORMATION leftInfo = {};
        BY_HANDLE_FILE_INFORMATION rightInfo = {};
        if (!ReadFileIdentity(
                left,
                &leftInfo,
                error) ||
            !ReadFileIdentity(
                right,
                &rightInfo,
                error))
        {
            return false;
        }

        *same =
            leftInfo.dwVolumeSerialNumber ==
                rightInfo.dwVolumeSerialNumber &&
            leftInfo.nFileIndexHigh ==
                rightInfo.nFileIndexHigh &&
            leftInfo.nFileIndexLow ==
                rightInfo.nFileIndexLow;
        return true;
    }

    std::wstring HresultText(
        HRESULT value)
    {
        std::wstringstream stream;
        stream << L"0x"
               << std::hex
               << std::setw(8)
               << std::setfill(L'0')
               << static_cast<uint32_t>(value);
        return stream.str();
    }

    bool IsMissingMapping(
        HRESULT value)
    {
        return value ==
                HRESULT_FROM_WIN32(
                    ERROR_FILE_NOT_FOUND) ||
            value ==
                HRESULT_FROM_WIN32(
                    ERROR_PATH_NOT_FOUND) ||
            value ==
                HRESULT_FROM_WIN32(
                    ERROR_NOT_FOUND);
    }

    bool IsMappingOperationComplete(
        HRESULT value)
    {
        return value == S_OK;
    }

    bool IsMappingRemovalComplete(
        HRESULT value)
    {
        return IsMappingOperationComplete(value) ||
            IsMissingMapping(value);
    }

    bool LoadApi(
        BindFilterApi* api)
    {
        std::wstring error;
        if (api == nullptr ||
            !api->Load(&error))
        {
            std::wcerr
                << L"[bind-fixture] "
                << error
                << L"\n";
            return false;
        }
        return true;
    }

    bool ValidateApplyFiles(
        const std::wstring& directory)
    {
        const std::array<std::wstring, 4> paths =
        {
            ChildPath(
                directory,
                kFileVirtualName),
            ChildPath(
                directory,
                kFileBackingName),
            ChildPath(
                directory,
                kProcessVirtualName),
            ChildPath(
                directory,
                kProcessBackingName)
        };

        std::wstring error;
        for (const std::wstring& path : paths)
        {
            if (!ValidateRegularFile(
                    path,
                    &error))
            {
                std::wcerr
                    << L"[bind-fixture] "
                    << error
                    << L"\n";
                return false;
            }
        }

        bool same = false;
        if (!AreSameFile(
                paths[0],
                paths[1],
                &same,
                &error) ||
            same)
        {
            std::wcerr
                << L"[bind-fixture] file mapping endpoints "
                << (same
                        ? L"must be distinct"
                        : error)
                << L"\n";
            return false;
        }
        if (!AreSameFile(
                paths[2],
                paths[3],
                &same,
                &error) ||
            same)
        {
            std::wcerr
                << L"[bind-fixture] process mapping endpoints "
                << (same
                        ? L"must be distinct"
                        : error)
                << L"\n";
            return false;
        }
        return true;
    }

    int ApplyMappings(
        const std::wstring& inputDirectory)
    {
        std::wstring directory;
        std::wstring error;
        if (!ValidateFixtureDirectory(
                inputDirectory,
                true,
                &directory,
                &error))
        {
            std::wcerr
                << L"[bind-fixture] "
                << error
                << L"\n";
            return 2;
        }
        if (!ValidateApplyFiles(directory))
        {
            return 2;
        }

        BindFilterApi api;
        if (!LoadApi(&api))
        {
            return 3;
        }

        const std::wstring fileVirtual =
            ChildPath(
                directory,
                kFileVirtualName);
        const std::wstring fileBacking =
            ChildPath(
                directory,
                kFileBackingName);
        const std::wstring processVirtual =
            ChildPath(
                directory,
                kProcessVirtualName);
        const std::wstring processBacking =
            ChildPath(
                directory,
                kProcessBackingName);

        const HRESULT fileStatus =
            api.Setup(
                nullptr,
                0,
                fileVirtual.c_str(),
                fileBacking.c_str(),
                nullptr,
                0);
        if (!IsMappingOperationComplete(
                fileStatus))
        {
            std::wcerr
                << L"[bind-fixture] file mapping failed status="
                << HresultText(fileStatus)
                << L"\n";
            return 4;
        }

        const HRESULT processStatus =
            api.Setup(
                nullptr,
                0,
                processVirtual.c_str(),
                processBacking.c_str(),
                nullptr,
                0);
        if (!IsMappingOperationComplete(
                processStatus))
        {
            const HRESULT rollbackStatus =
                api.Remove(
                    nullptr,
                    fileVirtual.c_str());
            std::wcerr
                << L"[bind-fixture] process mapping failed status="
                << HresultText(processStatus)
                << L" rollback="
                << HresultText(rollbackStatus)
                << L"\n";
            return 5;
        }

        std::wcout
            << L"[bind-fixture] action=apply status=passed"
            << L" directory=\"" << directory << L"\""
            << L" file_virtual=\"" << fileVirtual << L"\""
            << L" file_backing=\"" << fileBacking << L"\""
            << L" process_virtual=\"" << processVirtual << L"\""
            << L" process_backing=\"" << processBacking << L"\""
            << L"\n";
        return 0;
    }

    int RemoveMappings(
        const std::wstring& inputDirectory)
    {
        std::wstring directory;
        std::wstring error;
        if (!ValidateFixtureDirectory(
                inputDirectory,
                false,
                &directory,
                &error))
        {
            std::wcerr
                << L"[bind-fixture] "
                << error
                << L"\n";
            return 2;
        }

        BindFilterApi api;
        if (!LoadApi(&api))
        {
            return 3;
        }

        const std::wstring processVirtual =
            ChildPath(
                directory,
                kProcessVirtualName);
        const std::wstring fileVirtual =
            ChildPath(
                directory,
                kFileVirtualName);
        const HRESULT processStatus =
            api.Remove(
                nullptr,
                processVirtual.c_str());
        const HRESULT fileStatus =
            api.Remove(
                nullptr,
                fileVirtual.c_str());
        const bool processOk =
            IsMappingRemovalComplete(
                processStatus);
        const bool fileOk =
            IsMappingRemovalComplete(
                fileStatus);

        std::wcout
            << L"[bind-fixture] action=remove"
            << L" process_status="
            << HresultText(processStatus)
            << L" file_status="
            << HresultText(fileStatus)
            << L" status="
            << (processOk && fileOk
                    ? L"passed"
                    : L"failed")
            << L"\n";
        return processOk && fileOk
            ? 0
            : 4;
    }

    int RunSelfTest()
    {
        std::wstring temporaryRoot;
        std::wstring error;
        if (!GetTemporaryRoot(
                &temporaryRoot,
                &error))
        {
            std::wcerr
                << L"[bind-fixture.selftest] "
                << error
                << L"\n";
            return 1;
        }

        const std::wstring suffix =
            L"0123456789abcdef0123456789abcdef";
        const std::wstring valid =
            ChildPath(
                temporaryRoot,
                (std::wstring(
                     kFixturePrefix) +
                 suffix).c_str());
        std::wstring normalized;
        if (!ValidateFixtureDirectory(
                valid,
                false,
                &normalized,
                &error) ||
            !EqualInsensitive(
                valid,
                normalized))
        {
            std::wcerr
                << L"[bind-fixture.selftest] valid shape rejected\n";
            return 1;
        }

        const std::array<std::wstring, 4> invalid =
        {
            L"C:\\Windows\\KnLiveDbgBindFixture-" +
                suffix,
            valid + L"\\nested",
            ChildPath(
                temporaryRoot,
                L"KnLiveDbgBindFixture-short"),
            ChildPath(
                temporaryRoot,
                L"KnLiveDbgBindFixture-0123456789abcdef0123456789abcdeg")
        };
        for (const std::wstring& candidate : invalid)
        {
            if (ValidateFixtureDirectory(
                    candidate,
                    false,
                    nullptr,
                    nullptr))
            {
                std::wcerr
                    << L"[bind-fixture.selftest] unsafe shape accepted: "
                    << candidate
                    << L"\n";
                return 1;
            }
        }

        BindFilterApi api;
        if (!LoadApi(&api))
        {
            return 1;
        }
        if (IsMappingOperationComplete(S_FALSE) ||
            IsMappingRemovalComplete(S_FALSE) ||
            !IsMappingOperationComplete(S_OK) ||
            !IsMappingRemovalComplete(
                HRESULT_FROM_WIN32(
                    ERROR_NOT_FOUND)))
        {
            std::wcerr
                << L"[bind-fixture.selftest] HRESULT completion boundary failed\n";
            return 1;
        }

        std::wcout
            << L"[bind-fixture.selftest] passed=10 failed=0"
            << L" temp_root=\"" << temporaryRoot << L"\""
            << L" api=bindfltapi.dll"
            << L"\n";
        return 0;
    }

    void PrintUsage()
    {
        std::wcerr
            << L"usage:\n"
            << L"  KnLiveDbgBindFixture.exe apply <fixture-directory>\n"
            << L"  KnLiveDbgBindFixture.exe remove <fixture-directory>\n"
            << L"  KnLiveDbgBindFixture.exe --self-test\n";
    }
}

int wmain(
    int argumentCount,
    wchar_t** arguments)
{
    if (argumentCount == 2 &&
        EqualInsensitive(
            arguments[1],
            L"--self-test"))
    {
        return RunSelfTest();
    }
    if (argumentCount != 3)
    {
        PrintUsage();
        return 1;
    }
    if (EqualInsensitive(
            arguments[1],
            L"apply"))
    {
        return ApplyMappings(arguments[2]);
    }
    if (EqualInsensitive(
            arguments[1],
            L"remove"))
    {
        return RemoveMappings(arguments[2]);
    }

    PrintUsage();
    return 1;
}
