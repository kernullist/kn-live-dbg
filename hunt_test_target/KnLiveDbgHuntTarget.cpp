#include <Windows.h>

#include <cstdint>
#include <cwchar>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    constexpr SIZE_T kPageSize = 0x1000;
    constexpr DWORD kDefaultRunSeconds = 300;
    constexpr SIZE_T kLargePrivateExecSize = 65ull * 1024ull * 1024ull;

    struct Options
    {
        bool PrivateExec = false;
        bool Rwx = false;
        bool LargePrivateExec = false;
        bool PeLike = false;
        bool WipedPe = false;
        bool Thread = false;
        bool Apc = false;
        bool ThreadlessStack = false;
        bool ModulePatch = false;
        bool ModulePatchLate = false;
        bool StompThread = false;
        bool StompApc = false;
        bool SectionImageMap = false;
        bool LockedBackedImage = false;
        bool SectionImageStomp = false;
        bool ImageRwxSection = false;
        bool LabBuiltinProfile = false;
        bool Baseline = false;
        bool Help = false;
        DWORD RunSeconds = kDefaultRunSeconds;
        std::wstring ManifestPath;
    };

    struct RegionRecord
    {
        void* Base = nullptr;
        SIZE_T Size = 0;
        std::wstring Name;
    };

    struct ScenarioRecord
    {
        std::wstring Name;
        std::wstring Artifact;
        uint64_t Address = 0;
        uint64_t Size = 0;
        std::vector<std::wstring> ExpectedReasons;
        std::wstring Notes;
    };

    struct MappedImageInfo
    {
        uint32_t SizeOfImage = 0;
        uint32_t FirstExecutableSectionRva = 0;
        std::wstring FirstExecutableSectionName;
        bool HasExecutableSection = false;
    };

    struct MappedImageRecord
    {
        void* Base = nullptr;
        SIZE_T Size = 0;
        HANDLE File = INVALID_HANDLE_VALUE;
        HANDLE Mapping = nullptr;
        std::wstring Path;
        bool DeleteOnCleanup = false;
        MappedImageInfo Info = {};
    };

    HANDLE g_StopEvent = nullptr;
    std::vector<RegionRecord> g_Regions;
    std::vector<HANDLE> g_Threads;
    std::vector<ScenarioRecord> g_Scenarios;
    std::vector<MappedImageRecord> g_MappedImages;
    HMODULE g_FixtureDll = nullptr;
    bool g_DefaultExportPatched = false;
    bool g_LateExportPatched = false;
    uint64_t g_DefaultPatchAddress = 0;
    uint64_t g_LatePatchAddress = 0;

    std::wstring Hex(uint64_t value)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value;
        return stream.str();
    }

    std::wstring Win32ErrorText(const wchar_t* prefix)
    {
        DWORD error = GetLastError();
        std::wstringstream stream;
        stream << prefix << L" gle=" << error;
        return stream.str();
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
            case L'\b':
                result += L"\\b";
                break;
            case L'\f':
                result += L"\\f";
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
                if (ch < 0x20)
                {
                    std::wstringstream stream;
                    stream << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0')
                           << static_cast<uint32_t>(ch);
                    result += stream.str();
                }
                else
                {
                    result.push_back(ch);
                }
                break;
            }
        }

        return result;
    }

    void AppendJsonStringArray(std::wstringstream& json, const std::vector<std::wstring>& values)
    {
        json << L"[";
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                json << L",";
            }
            json << L"\"" << JsonEscape(values[index]) << L"\"";
        }
        json << L"]";
    }

    bool WideToUtf8(const std::wstring& value, std::string* utf8)
    {
        bool ok = false;

        do
        {
            if (utf8 == nullptr)
            {
                break;
            }

            utf8->clear();
            if (value.empty())
            {
                ok = true;
                break;
            }

            int needed = WideCharToMultiByte(
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
                break;
            }

            utf8->resize(static_cast<size_t>(needed));
            int written = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                utf8->data(),
                needed,
                nullptr,
                nullptr);
            if (written != needed)
            {
                utf8->clear();
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool WriteUtf8TextFile(const std::wstring& path, const std::wstring& text)
    {
        bool ok = false;

        do
        {
            std::string pathUtf8;
            std::string textUtf8;
            if (!WideToUtf8(path, &pathUtf8) || !WideToUtf8(text, &textUtf8))
            {
                break;
            }

            std::ofstream file(pathUtf8, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!file.is_open())
            {
                break;
            }

            const unsigned char bom[] = { 0xef, 0xbb, 0xbf };
            file.write(reinterpret_cast<const char*>(bom), sizeof(bom));
            file.write(textUtf8.data(), static_cast<std::streamsize>(textUtf8.size()));
            ok = file.good();
        } while (false);

        return ok;
    }

    void AddScenario(
        const std::wstring& name,
        const std::wstring& artifact,
        uint64_t address,
        uint64_t size,
        std::initializer_list<const wchar_t*> expectedReasons,
        const std::wstring& notes)
    {
        ScenarioRecord record = {};
        record.Name = name;
        record.Artifact = artifact;
        record.Address = address;
        record.Size = size;
        record.Notes = notes;

        for (const wchar_t* reason : expectedReasons)
        {
            if (reason != nullptr)
            {
                record.ExpectedReasons.push_back(reason);
            }
        }

        g_Scenarios.push_back(record);
    }

    std::wstring BuildManifestJson(const Options& options)
    {
        std::wstringstream json;
        wchar_t imagePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, imagePath, static_cast<DWORD>(_countof(imagePath)));

        json << L"{\n";
        json << L"  \"schema\":\"kn-live-dbg.hunt-target-manifest.v1\",\n";
        json << L"  \"pid\":" << GetCurrentProcessId() << L",\n";
        json << L"  \"image_path\":\"" << JsonEscape(imagePath) << L"\",\n";
        json << L"  \"run_seconds\":" << options.RunSeconds << L",\n";
        json << L"  \"scenario_count\":" << g_Scenarios.size() << L",\n";
        json << L"  \"scenarios\":[\n";
        for (size_t index = 0; index < g_Scenarios.size(); ++index)
        {
            const ScenarioRecord& scenario = g_Scenarios[index];
            json << L"    {";
            json << L"\"name\":\"" << JsonEscape(scenario.Name) << L"\"";
            json << L",\"artifact\":\"" << JsonEscape(scenario.Artifact) << L"\"";
            json << L",\"address\":\"" << Hex(scenario.Address) << L"\"";
            json << L",\"size\":" << scenario.Size;
            json << L",\"expected_reasons\":";
            AppendJsonStringArray(json, scenario.ExpectedReasons);
            json << L",\"notes\":\"" << JsonEscape(scenario.Notes) << L"\"";
            json << L"}";
            if (index + 1 != g_Scenarios.size())
            {
                json << L",";
            }
            json << L"\n";
        }
        json << L"  ]\n";
        json << L"}\n";

        return json.str();
    }

    void PrintUsage()
    {
        std::wcout << L"KnLiveDbgHuntTarget command:\n";
        std::wcout << L"  KnLiveDbgHuntTarget.exe [/all] [/baseline] [/private-exec] [/rwx] [/large-private-exec] [/pe-like] [/wiped-pe] [/thread] [/apc] [/threadless-stack] [/module-patch] [/module-patch-late] [/stomp-thread] [/stomp-apc] [/section-image-map] [/locked-backed-image] [/section-image-stomp] [/image-rwx-section] [/lab-builtin-profile] [/manifest path] [/seconds n]\n";
        std::wcout << L"\n";
        std::wcout << L"notes:\n";
        std::wcout << L"  This is a lab-only positive-control target for !hunt.\n";
        std::wcout << L"  It mutates only its own process and never injects into another process.\n";
        std::wcout << L"  Run KnLiveDbg elevated in another console and execute: !hunt /deep /limit 120 /json .\\hunt-target.json\n";
    }

    bool ParseUInt32(const wchar_t* text, DWORD* value)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || value == nullptr || text[0] == L'\0')
            {
                break;
            }

            wchar_t* end = nullptr;
            unsigned long parsed = std::wcstoul(text, &end, 10);
            if (end == text || *end != L'\0' || parsed > 0xfffffffful)
            {
                break;
            }

            *value = static_cast<DWORD>(parsed);
            ok = true;
        } while (false);

        return ok;
    }

    bool ParseOptions(int argc, wchar_t** argv, Options* options)
    {
        bool ok = false;

        do
        {
            if (options == nullptr)
            {
                break;
            }

            bool sawScenario = false;
            for (int index = 1; index < argc; ++index)
            {
                std::wstring arg = argv[index];
                if (arg == L"/?" || arg == L"-?" || arg == L"help" || arg == L"/help")
                {
                    options->Help = true;
                    ok = true;
                    break;
                }
                else if (arg == L"/all")
                {
                    options->PrivateExec = true;
                    options->Rwx = true;
                    options->LargePrivateExec = true;
                    options->PeLike = true;
                    options->WipedPe = true;
                    options->Thread = true;
                    options->Apc = true;
                    options->ThreadlessStack = true;
                    options->ModulePatch = true;
                    options->ModulePatchLate = true;
                    options->StompThread = true;
                    options->StompApc = true;
                    options->SectionImageMap = true;
                    options->LockedBackedImage = true;
                    options->SectionImageStomp = true;
                    options->ImageRwxSection = true;
                    options->LabBuiltinProfile = true;
                    sawScenario = true;
                }
                else if (arg == L"/baseline")
                {
                    options->Baseline = true;
                    sawScenario = true;
                }
                else if (arg == L"/private-exec")
                {
                    options->PrivateExec = true;
                    sawScenario = true;
                }
                else if (arg == L"/rwx")
                {
                    options->Rwx = true;
                    sawScenario = true;
                }
                else if (arg == L"/large-private-exec")
                {
                    options->LargePrivateExec = true;
                    sawScenario = true;
                }
                else if (arg == L"/pe-like")
                {
                    options->PeLike = true;
                    sawScenario = true;
                }
                else if (arg == L"/wiped-pe")
                {
                    options->WipedPe = true;
                    sawScenario = true;
                }
                else if (arg == L"/thread")
                {
                    options->Thread = true;
                    sawScenario = true;
                }
                else if (arg == L"/apc")
                {
                    options->Apc = true;
                    sawScenario = true;
                }
                else if (arg == L"/threadless-stack")
                {
                    options->ThreadlessStack = true;
                    sawScenario = true;
                }
                else if (arg == L"/module-patch")
                {
                    options->ModulePatch = true;
                    sawScenario = true;
                }
                else if (arg == L"/module-patch-late")
                {
                    options->ModulePatchLate = true;
                    sawScenario = true;
                }
                else if (arg == L"/stomp-thread")
                {
                    options->StompThread = true;
                    sawScenario = true;
                }
                else if (arg == L"/stomp-apc")
                {
                    options->StompApc = true;
                    sawScenario = true;
                }
                else if (arg == L"/section-image-map")
                {
                    options->SectionImageMap = true;
                    sawScenario = true;
                }
                else if (arg == L"/locked-backed-image")
                {
                    options->LockedBackedImage = true;
                    sawScenario = true;
                }
                else if (arg == L"/section-image-stomp")
                {
                    options->SectionImageStomp = true;
                    sawScenario = true;
                }
                else if (arg == L"/image-rwx-section")
                {
                    options->ImageRwxSection = true;
                    sawScenario = true;
                }
                else if (arg == L"/lab-builtin-profile")
                {
                    options->LabBuiltinProfile = true;
                    sawScenario = true;
                }
                else if (arg == L"/manifest")
                {
                    if (index + 1 >= argc || argv[index + 1][0] == L'\0')
                    {
                        std::wcerr << L"invalid /manifest value\n";
                        break;
                    }
                    options->ManifestPath = argv[index + 1];
                    ++index;
                }
                else if (arg == L"/seconds")
                {
                    if (index + 1 >= argc || !ParseUInt32(argv[index + 1], &options->RunSeconds))
                    {
                        std::wcerr << L"invalid /seconds value\n";
                        break;
                    }
                    ++index;
                }
                else
                {
                    std::wcerr << L"unknown option: " << arg << L"\n";
                    break;
                }

                if (index + 1 == argc)
                {
                    ok = true;
                }
            }

            if (argc == 1)
            {
                ok = true;
            }

            if (!ok)
            {
                break;
            }

            if (options->Help)
            {
                break;
            }

            if (!sawScenario)
            {
                options->PrivateExec = true;
                options->Rwx = true;
                options->LargePrivateExec = true;
                options->PeLike = true;
                options->WipedPe = true;
                options->Thread = true;
                options->Apc = true;
                options->ThreadlessStack = true;
                options->ModulePatch = true;
                options->ModulePatchLate = true;
                options->StompThread = true;
                options->StompApc = true;
                options->SectionImageMap = true;
                options->LockedBackedImage = true;
                options->SectionImageStomp = true;
                options->ImageRwxSection = true;
                options->LabBuiltinProfile = false;
            }

            if (options->Baseline)
            {
                options->PrivateExec = false;
                options->Rwx = false;
                options->LargePrivateExec = false;
                options->PeLike = false;
                options->WipedPe = false;
                options->Thread = false;
                options->Apc = false;
                options->ThreadlessStack = false;
                options->ModulePatch = false;
                options->ModulePatchLate = false;
                options->StompThread = false;
                options->StompApc = false;
                options->SectionImageMap = false;
                options->LockedBackedImage = false;
                options->SectionImageStomp = false;
                options->ImageRwxSection = false;
                options->LabBuiltinProfile = false;
            }
        } while (false);

        return ok;
    }

    BOOL WINAPI ConsoleHandler(DWORD controlType)
    {
        if (controlType == CTRL_C_EVENT ||
            controlType == CTRL_BREAK_EVENT ||
            controlType == CTRL_CLOSE_EVENT)
        {
            if (g_StopEvent != nullptr)
            {
                SetEvent(g_StopEvent);
            }
            return TRUE;
        }

        return FALSE;
    }

    bool AddRegion(void* base, SIZE_T size, const std::wstring& name)
    {
        bool ok = false;

        do
        {
            if (base == nullptr || size == 0)
            {
                break;
            }

            RegionRecord record = {};
            record.Base = base;
            record.Size = size;
            record.Name = name;
            g_Regions.push_back(record);
            std::wcout << L"region " << name
                       << L" base=" << Hex(reinterpret_cast<uint64_t>(base))
                       << L" size=" << size << L"\n";
            ok = true;
        } while (false);

        return ok;
    }

    bool GetSelfDirectory(std::wstring* directory)
    {
        bool ok = false;

        do
        {
            if (directory == nullptr)
            {
                break;
            }

            std::vector<wchar_t> buffer(32768, L'\0');
            DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (length == 0 || length >= buffer.size())
            {
                std::wcerr << Win32ErrorText(L"GetModuleFileNameW self path failed") << L"\n";
                break;
            }

            std::wstring path(buffer.data(), length);
            size_t slash = path.find_last_of(L"\\/");
            if (slash == std::wstring::npos)
            {
                break;
            }

            *directory = path.substr(0, slash + 1);
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveFixtureDllPath(std::wstring* path)
    {
        bool ok = false;

        do
        {
            if (path == nullptr)
            {
                break;
            }

            std::wstring directory;
            if (!GetSelfDirectory(&directory))
            {
                break;
            }

            std::wstring candidate = directory + L"KnLiveDbgHuntTargetDll.dll";
            DWORD attributes = GetFileAttributesW(candidate.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                std::wcerr << L"fixture DLL not found: " << candidate << L"\n";
                break;
            }

            *path = candidate;
            ok = true;
        } while (false);

        return ok;
    }

    bool MakeTempFixtureCopy(const wchar_t* tag, std::wstring* path)
    {
        bool ok = false;
        static uint32_t s_TempCounter = 0;

        do
        {
            if (tag == nullptr || path == nullptr)
            {
                break;
            }

            std::wstring fixturePath;
            if (!ResolveFixtureDllPath(&fixturePath))
            {
                break;
            }

            wchar_t tempPath[MAX_PATH + 1] = {};
            DWORD tempLength = GetTempPathW(static_cast<DWORD>(_countof(tempPath)), tempPath);
            if (tempLength == 0 || tempLength >= _countof(tempPath))
            {
                std::wcerr << Win32ErrorText(L"GetTempPathW failed") << L"\n";
                break;
            }

            std::wstring tempDirectory(tempPath);
            for (uint32_t attempt = 0; attempt < 64; ++attempt)
            {
                std::wstringstream candidate;
                candidate << tempDirectory
                          << L"knhunt-"
                          << GetCurrentProcessId()
                          << L"-"
                          << tag
                          << L"-"
                          << GetTickCount64()
                          << L"-"
                          << s_TempCounter++
                          << L".dll";

                std::wstring candidatePath = candidate.str();
                if (CopyFileW(fixturePath.c_str(), candidatePath.c_str(), TRUE))
                {
                    *path = candidatePath;
                    ok = true;
                    break;
                }

                if (GetLastError() != ERROR_FILE_EXISTS)
                {
                    std::wcerr << Win32ErrorText(L"CopyFileW fixture temp copy failed") << L"\n";
                    break;
                }
            }
        } while (false);

        return ok;
    }

    bool ReadMappedImageInfo(void* base, MappedImageInfo* info)
    {
        bool ok = false;

        do
        {
            if (base == nullptr || info == nullptr)
            {
                break;
            }

            *info = {};
            uint8_t* image = static_cast<uint8_t*>(base);
            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0 ||
                dos->e_lfanew > 0x100000)
            {
                break;
            }

            uint8_t* ntBase = image + dos->e_lfanew;
            uint32_t signature = *reinterpret_cast<const uint32_t*>(ntBase);
            if (signature != IMAGE_NT_SIGNATURE)
            {
                break;
            }

            const IMAGE_FILE_HEADER* fileHeader =
                reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(uint32_t));
            uint8_t* optionalBase = ntBase + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
            uint16_t magic = *reinterpret_cast<const uint16_t*>(optionalBase);
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER64* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalBase);
                info->SizeOfImage = optional->SizeOfImage;
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER32* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalBase);
                info->SizeOfImage = optional->SizeOfImage;
            }
            else
            {
                break;
            }

            const IMAGE_SECTION_HEADER* sections =
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(optionalBase + fileHeader->SizeOfOptionalHeader);
            for (uint16_t index = 0; index < fileHeader->NumberOfSections; ++index)
            {
                if ((sections[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                {
                    continue;
                }

                char sectionName[9] = {};
                std::memcpy(sectionName, sections[index].Name, IMAGE_SIZEOF_SHORT_NAME);
                std::string narrowName(sectionName);
                info->FirstExecutableSectionName.assign(narrowName.begin(), narrowName.end());
                info->FirstExecutableSectionRva = sections[index].VirtualAddress;
                info->HasExecutableSection = true;
                break;
            }

            ok = info->SizeOfImage != 0;
        } while (false);

        return ok;
    }

    void ReleaseMappedImageRecord(MappedImageRecord* record)
    {
        if (record == nullptr)
        {
            return;
        }

        if (record->Base != nullptr)
        {
            UnmapViewOfFile(record->Base);
            record->Base = nullptr;
        }

        if (record->Mapping != nullptr)
        {
            CloseHandle(record->Mapping);
            record->Mapping = nullptr;
        }

        if (record->File != INVALID_HANDLE_VALUE)
        {
            CloseHandle(record->File);
            record->File = INVALID_HANDLE_VALUE;
        }

        if (record->DeleteOnCleanup && !record->Path.empty())
        {
            DeleteFileW(record->Path.c_str());
        }

        *record = {};
    }

    bool MapFixtureImageCopyEx(
        const wchar_t* tag,
        DWORD shareMode,
        bool keepFileOpen,
        MappedImageRecord* record)
    {
        bool ok = false;
        MappedImageRecord local = {};

        do
        {
            if (tag == nullptr || record == nullptr)
            {
                break;
            }

            if (!MakeTempFixtureCopy(tag, &local.Path))
            {
                break;
            }
            local.DeleteOnCleanup = true;

            local.File = CreateFileW(
                local.Path.c_str(),
                GENERIC_READ,
                shareMode,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (local.File == INVALID_HANDLE_VALUE)
            {
                std::wcerr << Win32ErrorText(L"CreateFileW mapped image copy failed") << L"\n";
                break;
            }

            local.Mapping = CreateFileMappingW(
                local.File,
                nullptr,
                PAGE_READONLY | SEC_IMAGE,
                0,
                0,
                nullptr);
            if (local.Mapping == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateFileMappingW SEC_IMAGE failed") << L"\n";
                break;
            }

            local.Base = MapViewOfFile(local.Mapping, FILE_MAP_READ, 0, 0, 0);
            if (local.Base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"MapViewOfFile SEC_IMAGE failed") << L"\n";
                break;
            }

            if (!ReadMappedImageInfo(local.Base, &local.Info))
            {
                std::wcerr << L"failed to parse mapped fixture image: " << local.Path << L"\n";
                break;
            }

            local.Size = local.Info.SizeOfImage;
            if (!keepFileOpen)
            {
                CloseHandle(local.File);
                local.File = INVALID_HANDLE_VALUE;
            }

            *record = local;
            ok = true;
        } while (false);

        if (!ok)
        {
            ReleaseMappedImageRecord(&local);
        }

        return ok;
    }

    bool MapFixtureImageCopy(const wchar_t* tag, MappedImageRecord* record)
    {
        return MapFixtureImageCopyEx(
            tag,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
            record);
    }

    bool PatchMappedImageExecPage(MappedImageRecord* record, uint64_t* patchAddress)
    {
        bool ok = false;

        do
        {
            if (record == nullptr || record->Base == nullptr || patchAddress == nullptr)
            {
                break;
            }

            if (!record->Info.HasExecutableSection)
            {
                std::wcerr << L"mapped fixture image has no executable section\n";
                break;
            }

            uint8_t* patch = static_cast<uint8_t*>(record->Base) + record->Info.FirstExecutableSectionRva;
            DWORD oldProtect = 0;
            if (!VirtualProtect(patch, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect mapped image stomp failed") << L"\n";
                break;
            }

            for (size_t index = 0; index < 8; ++index)
            {
                patch[index] ^= 0xa5;
            }

            FlushInstructionCache(GetCurrentProcess(), patch, 16);
            DWORD ignored = 0;
            VirtualProtect(patch, 16, oldProtect, &ignored);

            *patchAddress = reinterpret_cast<uint64_t>(patch);
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadOwnImageHeaderPage(std::vector<uint8_t>* bytes)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (bytes == nullptr)
            {
                break;
            }

            wchar_t path[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path))) == 0)
            {
                std::wcerr << Win32ErrorText(L"GetModuleFileNameW failed") << L"\n";
                break;
            }

            file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                std::wcerr << Win32ErrorText(L"CreateFileW self image failed") << L"\n";
                break;
            }

            bytes->assign(kPageSize, 0);
            DWORD read = 0;
            if (!ReadFile(file, bytes->data(), static_cast<DWORD>(bytes->size()), &read, nullptr) || read < sizeof(IMAGE_DOS_HEADER))
            {
                std::wcerr << Win32ErrorText(L"ReadFile self image failed") << L"\n";
                break;
            }
            bytes->resize(read);
            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool AllocateBytes(const std::wstring& name, const std::vector<uint8_t>& bytes, DWORD finalProtect, void** baseOut)
    {
        bool ok = false;
        void* base = nullptr;

        do
        {
            if (baseOut == nullptr || bytes.empty())
            {
                break;
            }

            base = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"VirtualAlloc failed") << L"\n";
                break;
            }

            SIZE_T copySize = bytes.size() < kPageSize ? bytes.size() : kPageSize;
            std::memcpy(base, bytes.data(), copySize);

            DWORD oldProtect = 0;
            if (!VirtualProtect(base, kPageSize, finalProtect, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect failed") << L"\n";
                break;
            }

            FlushInstructionCache(GetCurrentProcess(), base, kPageSize);
            if (!AddRegion(base, kPageSize, name))
            {
                break;
            }

            *baseOut = base;
            ok = true;
        } while (false);

        if (!ok && base != nullptr)
        {
            VirtualFree(base, 0, MEM_RELEASE);
        }

        return ok;
    }

    bool CreatePrivateExecRegion()
    {
        std::vector<uint8_t> code(kPageSize, 0x90);
        code[0] = 0xc3;
        void* base = nullptr;
        bool ok = AllocateBytes(L"private-exec-rx", code, PAGE_EXECUTE_READ, &base);
        if (ok)
        {
            AddScenario(
                L"private-exec",
                L"private executable RX page",
                reinterpret_cast<uint64_t>(base),
                kPageSize,
                {L"private_executable_vad"},
                L"single private RX page");
        }

        return ok;
    }

    bool CreateRwxRegion()
    {
        bool ok = false;
        void* base = nullptr;

        do
        {
            base = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"VirtualAlloc RWX failed") << L"\n";
                break;
            }

            std::memset(base, 0x90, kPageSize);
            static_cast<uint8_t*>(base)[0] = 0xc3;
            FlushInstructionCache(GetCurrentProcess(), base, kPageSize);
            if (!AddRegion(base, kPageSize, L"private-rwx"))
            {
                break;
            }

            AddScenario(
                L"rwx",
                L"private executable writable page",
                reinterpret_cast<uint64_t>(base),
                kPageSize,
                {L"wx_user_vad", L"private_executable_vad"},
                L"single private RWX page");
            ok = true;
        } while (false);

        if (!ok && base != nullptr)
        {
            VirtualFree(base, 0, MEM_RELEASE);
        }

        return ok;
    }

    bool CreateLargePrivateExecRegion()
    {
        bool ok = false;
        void* base = nullptr;

        do
        {
            base = VirtualAlloc(nullptr, kLargePrivateExecSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (base == nullptr)
            {
                std::wcerr << Win32ErrorText(L"VirtualAlloc large private exec failed") << L"\n";
                break;
            }

            std::memset(base, 0x90, kPageSize);
            static_cast<uint8_t*>(base)[0] = 0xc3;

            DWORD oldProtect = 0;
            if (!VirtualProtect(base, kLargePrivateExecSize, PAGE_EXECUTE_READ, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect large private exec failed") << L"\n";
                break;
            }

            FlushInstructionCache(GetCurrentProcess(), base, kPageSize);
            if (!AddRegion(base, kLargePrivateExecSize, L"large-private-exec-rx"))
            {
                break;
            }

            AddScenario(
                L"large-private-exec",
                L"large private executable RX region",
                reinterpret_cast<uint64_t>(base),
                kLargePrivateExecSize,
                {L"large_private_executable_vad", L"private_executable_vad"},
                L"region is larger than the hunt large private executable threshold");
            ok = true;
        } while (false);

        if (!ok && base != nullptr)
        {
            VirtualFree(base, 0, MEM_RELEASE);
        }

        return ok;
    }

    bool CreatePeLikeRegion(bool wiped)
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> header;
            if (!ReadOwnImageHeaderPage(&header))
            {
                break;
            }

            if (wiped && header.size() >= sizeof(IMAGE_DOS_HEADER))
            {
                IMAGE_DOS_HEADER dos = {};
                std::memcpy(&dos, header.data(), sizeof(dos));
                header[0] = 0;
                header[1] = 0;
                if (dos.e_lfanew > 0 &&
                    static_cast<size_t>(dos.e_lfanew) + sizeof(uint32_t) <= header.size())
                {
                    std::memset(header.data() + dos.e_lfanew, 0, sizeof(uint32_t));
                }
            }

            void* base = nullptr;
            ok = AllocateBytes(wiped ? L"wiped-private-pe-rx" : L"private-pe-rx", header, PAGE_EXECUTE_READ, &base);
            if (ok)
            {
                if (wiped)
                {
                    AddScenario(
                        L"wiped-pe",
                        L"wiped private PE-like executable page",
                        reinterpret_cast<uint64_t>(base),
                        kPageSize,
                        {L"wiped_pe_header", L"private_pe_mapping"},
                        L"PE header page has MZ and PE signatures wiped");
                }
                else
                {
                    AddScenario(
                        L"pe-like",
                        L"private PE-like executable page",
                        reinterpret_cast<uint64_t>(base),
                        kPageSize,
                        {L"private_pe_mapping", L"private_pe_without_loader_entry"},
                        L"first page is copied from this executable image header");
                }
            }
        } while (false);

        return ok;
    }

    bool BuildSleepLoopCode(std::vector<uint8_t>* code)
    {
        bool ok = false;

        do
        {
            if (code == nullptr)
            {
                break;
            }

            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (kernel32 == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetModuleHandleW kernel32 failed") << L"\n";
                break;
            }

            void* sleepAddress = reinterpret_cast<void*>(GetProcAddress(kernel32, "Sleep"));
            if (sleepAddress == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress Sleep failed") << L"\n";
                break;
            }

            code->clear();
            const uint8_t prefix[] =
            {
                0x48, 0x83, 0xec, 0x28,
                0xb9, 0xe8, 0x03, 0x00, 0x00,
                0x48, 0xb8
            };
            code->insert(code->end(), prefix, prefix + sizeof(prefix));

            uint64_t sleepValue = reinterpret_cast<uint64_t>(sleepAddress);
            for (size_t index = 0; index < sizeof(sleepValue); ++index)
            {
                code->push_back(static_cast<uint8_t>((sleepValue >> (index * 8)) & 0xff));
            }

            const uint8_t suffix[] =
            {
                0xff, 0xd0,
                0x48, 0x83, 0xc4, 0x28,
                0xeb, 0xe5
            };
            code->insert(code->end(), suffix, suffix + sizeof(suffix));
            code->resize(kPageSize, 0x90);
            ok = true;
        } while (false);

        return ok;
    }

    bool CreatePrivateThread()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> code;
            if (!BuildSleepLoopCode(&code))
            {
                break;
            }

            void* base = nullptr;
            if (!AllocateBytes(L"private-thread-start-rx", code, PAGE_EXECUTE_READ, &base))
            {
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(base),
                nullptr,
                0,
                &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread private start failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            std::wcout << L"thread private-start tid=" << threadId
                       << L" start=" << Hex(reinterpret_cast<uint64_t>(base)) << L"\n";
            AddScenario(
                L"thread",
                L"thread start inside private executable memory",
                reinterpret_cast<uint64_t>(base),
                kPageSize,
                {L"suspicious_thread_start", L"private_executable_vad"},
                L"thread start address is the private RX page");
            ok = true;
        } while (false);

        return ok;
    }

    DWORD WINAPI NonAlertableSleeper(void*)
    {
        while (WaitForSingleObject(g_StopEvent, 1000) == WAIT_TIMEOUT)
        {
        }

        return 0;
    }

    bool QueuePrivateApc()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> code(kPageSize, 0x90);
            code[0] = 0xc3;

            void* base = nullptr;
            if (!AllocateBytes(L"private-apc-normal-routine-rx", code, PAGE_EXECUTE_READ, &base))
            {
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(nullptr, 0, NonAlertableSleeper, nullptr, 0, &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread APC sleeper failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(base), thread, 0) == 0)
            {
                std::wcerr << Win32ErrorText(L"QueueUserAPC failed") << L"\n";
                break;
            }

            std::wcout << L"apc queued tid=" << threadId
                       << L" normal=" << Hex(reinterpret_cast<uint64_t>(base)) << L"\n";
            AddScenario(
                L"apc",
                L"queued APC normal routine inside private executable memory",
                reinterpret_cast<uint64_t>(base),
                kPageSize,
                {L"suspicious_apc_routine", L"private_executable_vad"},
                L"APC is queued to a non-alertable sleeper so the KAPC remains inspectable");
            ok = true;
        } while (false);

        return ok;
    }

    DWORD WINAPI StackReferenceSleeper(void* parameter)
    {
        volatile uintptr_t references[8] = {};
        references[0] = reinterpret_cast<uintptr_t>(parameter);

        while (WaitForSingleObject(g_StopEvent, 1000) == WAIT_TIMEOUT)
        {
            volatile uintptr_t keepAlive = references[0];
            if (keepAlive == 0)
            {
                break;
            }
        }

        return 0;
    }

    bool CreateThreadlessStackReference()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> code(kPageSize, 0x90);
            code[0] = 0xc3;

            void* base = nullptr;
            if (!AllocateBytes(L"threadless-stack-reference-rx", code, PAGE_EXECUTE_READ, &base))
            {
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(nullptr, 0, StackReferenceSleeper, base, 0, &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread stack-reference sleeper failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            std::wcout << L"threadless-stack tid=" << threadId
                       << L" referenced=" << Hex(reinterpret_cast<uint64_t>(base)) << L"\n";
            AddScenario(
                L"threadless-stack",
                L"normal thread stack references private executable memory",
                reinterpret_cast<uint64_t>(base),
                kPageSize,
                {L"private_executable_vad", L"stack_reference_to_executable_memory", L"stack_reference_to_private_executable_vad", L"stack_reference_to_user_executable_outside_module"},
                L"thread start remains in the target module while a stack slot preserves the private RX address");
            ok = true;
        } while (false);

        return ok;
    }

    bool LoadFixtureDll(HMODULE* module)
    {
        bool ok = false;

        do
        {
            if (module == nullptr)
            {
                break;
            }

            if (g_FixtureDll == nullptr)
            {
                g_FixtureDll = LoadLibraryW(L"KnLiveDbgHuntTargetDll.dll");
                if (g_FixtureDll == nullptr)
                {
                    std::wcerr << Win32ErrorText(L"LoadLibraryW fixture DLL failed") << L"\n";
                    std::wcerr << L"ensure KnLiveDbgHuntTargetDll.dll is next to this executable\n";
                    break;
                }
            }

            *module = g_FixtureDll;
            ok = true;
        } while (false);

        return ok;
    }

    bool IsWritableExecutableProtection(DWORD protect)
    {
        DWORD baseProtect = protect & 0xff;
        return baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    bool CreateImageRwxSection()
    {
        bool ok = false;

        do
        {
            HMODULE module = nullptr;
            if (!LoadFixtureDll(&module))
            {
                break;
            }

            void* anchor = reinterpret_cast<void*>(GetProcAddress(module, "HuntTargetDllRwxSectionAnchor"));
            if (anchor == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress RWX section anchor failed") << L"\n";
                break;
            }

            MEMORY_BASIC_INFORMATION info = {};
            if (VirtualQuery(anchor, &info, sizeof(info)) == 0)
            {
                std::wcerr << Win32ErrorText(L"VirtualQuery RWX section anchor failed") << L"\n";
                break;
            }

            if (!IsWritableExecutableProtection(info.Protect))
            {
                std::wcerr << L"fixture RWX section anchor is not mapped with writable executable protection\n";
                break;
            }

            std::wcout << L"image-rwx-section dll=KnLiveDbgHuntTargetDll.dll"
                       << L" anchor=" << Hex(reinterpret_cast<uint64_t>(anchor))
                       << L" protect=0x" << std::hex << info.Protect << std::dec
                       << L"\n";
            AddScenario(
                L"image-rwx-section",
                L"loaded fixture DLL section with default writable executable protection",
                reinterpret_cast<uint64_t>(anchor),
                16,
                {L"image_rwx_section_vad", L"mockingjay_rwx_section_candidate", L"wx_user_vad"},
                L"models Mockingjay-style reuse of an existing image-backed RWX section");
            ok = true;
        } while (false);

        return ok;
    }

    bool EnsureFixtureExportPatched(
        const char* exportName,
        const wchar_t* scenarioName,
        bool* patched,
        uint64_t* patchAddress)
    {
        bool ok = false;

        do
        {
            if (exportName == nullptr || scenarioName == nullptr || patched == nullptr || patchAddress == nullptr)
            {
                break;
            }

            if (*patched)
            {
                ok = true;
                break;
            }

            HMODULE module = nullptr;
            if (!LoadFixtureDll(&module))
            {
                break;
            }

            using ProbeFn = DWORD (WINAPI*)();
            ProbeFn probe = reinterpret_cast<ProbeFn>(GetProcAddress(module, exportName));
            if (probe == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress fixture export failed") << L"\n";
                break;
            }

            DWORD before = probe();
            uint8_t* patch = reinterpret_cast<uint8_t*>(probe);
            DWORD oldProtect = 0;
            if (!VirtualProtect(patch, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::wcerr << Win32ErrorText(L"VirtualProtect DLL patch failed") << L"\n";
                break;
            }

            for (size_t index = 0; index < 8; ++index)
            {
                patch[index] ^= 0x5a;
            }

            FlushInstructionCache(GetCurrentProcess(), patch, 16);
            DWORD ignored = 0;
            VirtualProtect(patch, 16, oldProtect, &ignored);

            std::wcout << scenarioName << L" dll=KnLiveDbgHuntTargetDll.dll"
                       << L" export=" << Hex(reinterpret_cast<uint64_t>(patch))
                       << L" probe_before=" << before << L"\n";
            *patched = true;
            *patchAddress = reinterpret_cast<uint64_t>(patch);
            ok = true;
        } while (false);

        return ok;
    }

    bool CreateModulePatch()
    {
        bool ok = false;

        do
        {
            if (!EnsureFixtureExportPatched(
                    "HuntTargetDllProbe",
                    L"module-patch",
                    &g_DefaultExportPatched,
                    &g_DefaultPatchAddress))
            {
                break;
            }

            AddScenario(
                L"module-patch",
                L"fixture DLL export bytes modified in process memory",
                g_DefaultPatchAddress,
                16,
                {L"live_disk_exec_page_mismatch", L"module_text_mismatch", L"module_stomping_evidence"},
                L"patches only this process mapping of the fixture DLL");
            ok = true;
        } while (false);

        return ok;
    }

    bool CreateModulePatchLate()
    {
        bool ok = false;

        do
        {
            if (!EnsureFixtureExportPatched(
                    "HuntTargetDllLateProbe",
                    L"module-patch-late",
                    &g_LateExportPatched,
                    &g_LatePatchAddress))
            {
                break;
            }

            AddScenario(
                L"module-patch-late",
                L"fixture DLL export in late executable section modified in process memory",
                g_LatePatchAddress,
                16,
                {L"live_disk_exec_page_mismatch", L"module_text_mismatch", L"module_stomping_evidence"},
                L"patches the .late executable section rather than the default export page");
            ok = true;
        } while (false);

        return ok;
    }

    bool CreateStompThread()
    {
        bool ok = false;

        do
        {
            if (!EnsureFixtureExportPatched(
                    "HuntTargetDllLateProbe",
                    L"module-patch-late",
                    &g_LateExportPatched,
                    &g_LatePatchAddress))
            {
                break;
            }

            HMODULE module = nullptr;
            if (!LoadFixtureDll(&module))
            {
                break;
            }

            using ThreadFn = DWORD (WINAPI*)(LPVOID);
            ThreadFn threadProc = reinterpret_cast<ThreadFn>(GetProcAddress(module, "HuntTargetDllLateThreadProc"));
            if (threadProc == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress HuntTargetDllLateThreadProc failed") << L"\n";
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(threadProc),
                nullptr,
                0,
                &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread stomp module start failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            std::wcout << L"stomp-thread tid=" << threadId
                       << L" start=" << Hex(reinterpret_cast<uint64_t>(threadProc))
                       << L" patched_page=" << Hex(g_LatePatchAddress & ~static_cast<uint64_t>(kPageSize - 1))
                       << L"\n";
            AddScenario(
                L"stomp-thread",
                L"thread start inside modified module executable page",
                reinterpret_cast<uint64_t>(threadProc),
                16,
                {L"live_disk_exec_page_mismatch", L"module_stomping_evidence", L"thread_start_in_modified_module_page"},
                L"thread entrypoint and patched export live in the same late executable page");
            ok = true;
        } while (false);

        return ok;
    }

    bool CreateStompApc()
    {
        bool ok = false;

        do
        {
            if (!EnsureFixtureExportPatched(
                    "HuntTargetDllLateProbe",
                    L"module-patch-late",
                    &g_LateExportPatched,
                    &g_LatePatchAddress))
            {
                break;
            }

            HMODULE module = nullptr;
            if (!LoadFixtureDll(&module))
            {
                break;
            }

            PAPCFUNC apcRoutine = reinterpret_cast<PAPCFUNC>(GetProcAddress(module, "HuntTargetDllLateApcRoutine"));
            if (apcRoutine == nullptr)
            {
                std::wcerr << Win32ErrorText(L"GetProcAddress HuntTargetDllLateApcRoutine failed") << L"\n";
                break;
            }

            DWORD threadId = 0;
            HANDLE thread = CreateThread(nullptr, 0, NonAlertableSleeper, nullptr, 0, &threadId);
            if (thread == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateThread stomp APC sleeper failed") << L"\n";
                break;
            }

            g_Threads.push_back(thread);
            if (QueueUserAPC(apcRoutine, thread, 0) == 0)
            {
                std::wcerr << Win32ErrorText(L"QueueUserAPC stomp module failed") << L"\n";
                break;
            }

            std::wcout << L"stomp-apc queued tid=" << threadId
                       << L" normal=" << Hex(reinterpret_cast<uint64_t>(apcRoutine))
                       << L" patched_page=" << Hex(g_LatePatchAddress & ~static_cast<uint64_t>(kPageSize - 1))
                       << L"\n";
            AddScenario(
                L"stomp-apc",
                L"queued APC normal routine inside modified module executable page",
                reinterpret_cast<uint64_t>(apcRoutine),
                16,
                {L"live_disk_exec_page_mismatch", L"module_stomping_evidence", L"apc_target_in_modified_module_page"},
                L"APC normal routine and patched export live in the same late executable page");
            ok = true;
        } while (false);

        return ok;
    }

    bool CreateSectionImageMap()
    {
        bool ok = false;
        MappedImageRecord record = {};

        do
        {
            if (!MapFixtureImageCopy(L"secimg", &record))
            {
                break;
            }

            std::wcout << L"section-image-map base=" << Hex(reinterpret_cast<uint64_t>(record.Base))
                       << L" size=" << record.Size
                       << L" path=" << record.Path << L"\n";
            AddScenario(
                L"section-image-map",
                L"SEC_IMAGE fixture copy mapped without loader participation",
                reinterpret_cast<uint64_t>(record.Base),
                record.Size,
                {L"section_image_without_loader_entry", L"vad_image_not_in_loader"},
                L"maps a copied fixture DLL as an image section without LoadLibrary");
            g_MappedImages.push_back(record);
            ok = true;
        } while (false);

        if (!ok)
        {
            ReleaseMappedImageRecord(&record);
        }

        return ok;
    }

    bool CreateLockedBackedImage()
    {
        bool ok = false;
        MappedImageRecord record = {};

        do
        {
            if (!MapFixtureImageCopyEx(L"lckimg", FILE_SHARE_DELETE, true, &record))
            {
                break;
            }

            std::wcout << L"locked-backed-image base=" << Hex(reinterpret_cast<uint64_t>(record.Base))
                       << L" size=" << record.Size
                       << L" locked_path=" << record.Path << L"\n";
            AddScenario(
                L"locked-backed-image",
                L"SEC_IMAGE fixture copy mapped while its backing file denies read sharing",
                reinterpret_cast<uint64_t>(record.Base),
                record.Size,
                {L"section_image_without_loader_entry", L"vad_image_not_in_loader", L"section_backing_inaccessible"},
                L"keeps the backing file handle open without FILE_SHARE_READ so scanner reopen fails");
            g_MappedImages.push_back(record);
            ok = true;
        } while (false);

        if (!ok)
        {
            ReleaseMappedImageRecord(&record);
        }

        return ok;
    }

    bool CreateSectionImageStomp()
    {
        bool ok = false;
        MappedImageRecord record = {};

        do
        {
            if (!MapFixtureImageCopy(L"stpimg", &record))
            {
                break;
            }

            uint64_t patchAddress = 0;
            if (!PatchMappedImageExecPage(&record, &patchAddress))
            {
                break;
            }

            std::wcout << L"section-image-stomp base=" << Hex(reinterpret_cast<uint64_t>(record.Base))
                       << L" patch=" << Hex(patchAddress)
                       << L" section=" << record.Info.FirstExecutableSectionName
                       << L" path=" << record.Path << L"\n";
            AddScenario(
                L"section-image-stomp",
                L"loader-invisible SEC_IMAGE mapping with a modified executable page",
                patchAddress,
                16,
                {L"section_image_without_loader_entry", L"vad_image_not_in_loader", L"live_disk_exec_page_mismatch", L"module_text_mismatch", L"module_stomping_evidence"},
                L"patches the mapped image section in memory without modifying the temp DLL on disk");
            g_MappedImages.push_back(record);
            ok = true;
        } while (false);

        if (!ok)
        {
            ReleaseMappedImageRecord(&record);
        }

        return ok;
    }

    void PrintExpectedFindings(const Options& options)
    {
        std::wcout << L"\nexpected !hunt reason codes:\n";
        if (options.Baseline)
        {
            std::wcout << L"  baseline mode: no positive-control artifacts\n";
        }
        if (options.PrivateExec)
        {
            std::wcout << L"  private_executable_vad\n";
        }
        if (options.Rwx)
        {
            std::wcout << L"  wx_user_vad, private_executable_vad\n";
        }
        if (options.LargePrivateExec)
        {
            std::wcout << L"  large_private_executable_vad, private_executable_vad\n";
        }
        if (options.PeLike)
        {
            std::wcout << L"  private_pe_mapping, private_pe_without_loader_entry\n";
        }
        if (options.WipedPe)
        {
            std::wcout << L"  wiped_pe_header\n";
        }
        if (options.Thread)
        {
            std::wcout << L"  suspicious_thread_start, private_executable_vad\n";
        }
        if (options.Apc)
        {
            std::wcout << L"  suspicious_apc_routine, private_executable_vad\n";
        }
        if (options.ThreadlessStack)
        {
            std::wcout << L"  private_executable_vad, stack_reference_to_executable_memory, "
                       << L"stack_reference_to_private_executable_vad, "
                       << L"stack_reference_to_user_executable_outside_module\n";
        }
        if (options.ModulePatch)
        {
            std::wcout << L"  live_disk_exec_page_mismatch, module_text_mismatch or module_entrypoint_mismatch\n";
        }
        if (options.ModulePatchLate)
        {
            std::wcout << L"  live_disk_exec_page_mismatch, module_text_mismatch, module_stomping_evidence\n";
        }
        if (options.StompThread)
        {
            std::wcout << L"  thread_start_in_modified_module_page, module_stomping_evidence\n";
        }
        if (options.StompApc)
        {
            std::wcout << L"  apc_target_in_modified_module_page, module_stomping_evidence\n";
        }
        if (options.SectionImageMap)
        {
            std::wcout << L"  section_image_without_loader_entry, vad_image_not_in_loader\n";
        }
        if (options.LockedBackedImage)
        {
            std::wcout << L"  section_backing_inaccessible, section_image_without_loader_entry, vad_image_not_in_loader\n";
        }
        if (options.SectionImageStomp)
        {
            std::wcout << L"  section_image_without_loader_entry, vad_image_not_in_loader, live_disk_exec_page_mismatch, module_stomping_evidence\n";
        }
        if (options.ImageRwxSection)
        {
            std::wcout << L"  image_rwx_section_vad, mockingjay_rwx_section_candidate, wx_user_vad\n";
        }
        if (options.LabBuiltinProfile)
        {
            std::wcout << L"  builtin_profile_path_mismatch, system_name_from_non_system_path, "
                       << L"builtin_process_non_windows_module, dll_load_in_builtin_process, "
                       << L"lab_builtin_profile_non_windows_module\n";
        }
        if (!options.ManifestPath.empty())
        {
            std::wcout << L"  manifest: " << options.ManifestPath << L"\n";
        }
        std::wcout << L"\n";
    }

    bool CreateScenarios(const Options& options)
    {
        bool ok = false;

        do
        {
            bool anyFailure = false;

            if (options.PrivateExec && !CreatePrivateExecRegion())
            {
                anyFailure = true;
            }
            if (options.Rwx && !CreateRwxRegion())
            {
                anyFailure = true;
            }
            if (options.LargePrivateExec && !CreateLargePrivateExecRegion())
            {
                anyFailure = true;
            }
            if (options.PeLike && !CreatePeLikeRegion(false))
            {
                anyFailure = true;
            }
            if (options.WipedPe && !CreatePeLikeRegion(true))
            {
                anyFailure = true;
            }
            if (options.Thread && !CreatePrivateThread())
            {
                anyFailure = true;
            }
            if (options.Apc && !QueuePrivateApc())
            {
                anyFailure = true;
            }
            if (options.ThreadlessStack && !CreateThreadlessStackReference())
            {
                anyFailure = true;
            }
            if (options.ModulePatch && !CreateModulePatch())
            {
                anyFailure = true;
            }
            if (options.ModulePatchLate && !CreateModulePatchLate())
            {
                anyFailure = true;
            }
            if (options.StompThread && !CreateStompThread())
            {
                anyFailure = true;
            }
            if (options.StompApc && !CreateStompApc())
            {
                anyFailure = true;
            }
            if (options.SectionImageMap && !CreateSectionImageMap())
            {
                anyFailure = true;
            }
            if (options.LockedBackedImage && !CreateLockedBackedImage())
            {
                anyFailure = true;
            }
            if (options.SectionImageStomp && !CreateSectionImageStomp())
            {
                anyFailure = true;
            }
            if (options.ImageRwxSection && !CreateImageRwxSection())
            {
                anyFailure = true;
            }
            if (options.LabBuiltinProfile)
            {
                HMODULE module = nullptr;
                if (!LoadFixtureDll(&module))
                {
                    anyFailure = true;
                    break;
                }

                AddScenario(
                    L"lab-builtin-profile",
                    L"test-only built-in process profile violation",
                    0,
                    0,
                    {L"builtin_profile_path_mismatch", L"system_name_from_non_system_path", L"builtin_process_non_windows_module", L"dll_load_in_builtin_process", L"lab_builtin_profile_non_windows_module"},
                    L"enabled by command line flag and loads the fixture DLL from the target directory");
            }

            ok = !anyFailure;
        } while (false);

        return ok;
    }

    void PrintScenarioSummary()
    {
        std::wcout << L"\ncreated scenarios=" << g_Scenarios.size() << L"\n";
        for (const ScenarioRecord& scenario : g_Scenarios)
        {
            std::wcout << L"  " << scenario.Name
                       << L" artifact=\"" << scenario.Artifact << L"\""
                       << L" address=" << Hex(scenario.Address)
                       << L" size=" << scenario.Size
                       << L"\n";
        }
        std::wcout << L"\n";
    }
}

int wmain(int argc, wchar_t** argv)
{
    int exitCode = 1;

    do
    {
        Options options = {};
        if (!ParseOptions(argc, argv, &options))
        {
            PrintUsage();
            break;
        }
        if (options.Help)
        {
            PrintUsage();
            exitCode = 0;
            break;
        }

        g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_StopEvent == nullptr)
        {
            std::wcerr << Win32ErrorText(L"CreateEventW failed") << L"\n";
            break;
        }

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        std::wcout << L"KnLiveDbgHuntTarget pid=" << GetCurrentProcessId() << L"\n";
        std::wcout << L"run_seconds=" << options.RunSeconds << L"\n";
        PrintExpectedFindings(options);

        if (!CreateScenarios(options))
        {
            std::wcerr << L"one or more scenarios failed to initialize\n";
            break;
        }

        PrintScenarioSummary();

        if (!options.ManifestPath.empty())
        {
            if (WriteUtf8TextFile(options.ManifestPath, BuildManifestJson(options)))
            {
                std::wcout << L"manifest written: " << options.ManifestPath << L"\n";
            }
            else
            {
                std::wcerr << L"manifest write failed: " << options.ManifestPath << L"\n";
                break;
            }
        }

        std::wcout << L"target is ready\n";
        std::wcout << L"run: !hunt /deep /limit 120 /json .\\hunt-target.json\n";
        std::wcout << L"press Ctrl+C to stop this target\n";

        DWORD waitMs = INFINITE;
        if (options.RunSeconds != 0 && options.RunSeconds <= 0xffffffffu / 1000u)
        {
            waitMs = options.RunSeconds * 1000u;
        }
        WaitForSingleObject(g_StopEvent, waitMs);
        exitCode = 0;
    } while (false);

    if (g_StopEvent != nullptr)
    {
        SetEvent(g_StopEvent);
    }

    for (MappedImageRecord& record : g_MappedImages)
    {
        ReleaseMappedImageRecord(&record);
    }
    g_MappedImages.clear();

    for (HANDLE thread : g_Threads)
    {
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
    }

    if (g_StopEvent != nullptr)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
    }

    return exitCode;
}
