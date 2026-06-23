#include <Windows.h>

#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <cstring>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#pragma section(".enigma", read, execute)
__declspec(allocate(".enigma")) volatile const unsigned char g_HuntTargetEnigmaSectionMarker[16] =
{
    0x45,
    0x4e,
    0x49,
    0x47,
    0x4d,
    0x41,
    0x2d,
    0x4b,
    0x4e,
    0x48,
    0x55,
    0x4e,
    0x54,
    0x2d,
    0x30,
    0x31
};

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
        bool EdrKillerSuffixName = false;
        bool OxideHarvestCli = false;
        bool EdrKillerDriverService = false;
        bool Baseline = false;
        bool Help = false;
        bool Interactive = false;
        DWORD ChildWaitParentPid = 0;
        DWORD RunSeconds = kDefaultRunSeconds;
        std::wstring ManifestPath;
        std::wstring StopEventName;
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
        DWORD ProcessId = 0;
        bool HasProcessId = false;
        std::vector<std::wstring> ExpectedReasons;
        std::vector<std::wstring> UnexpectedReasons;
        std::vector<std::wstring> ExpectedEvidenceKeys;
        std::vector<std::pair<std::wstring, std::wstring>> ExpectedEvidenceValues;
        std::wstring ExpectedClass;
        std::wstring ExpectedRisk;
        std::wstring ExpectedConfidence;
        std::wstring Notes;
    };

    struct ScenarioMenuItem
    {
        const wchar_t* OptionName;
        const wchar_t* Title;
        const wchar_t* Category;
        const wchar_t* Creates;
        const wchar_t* HuntExpectation;
        const wchar_t* OperatorNote;
        bool Options::* Flag;
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
    std::vector<HANDLE> g_ChildProcesses;
    std::vector<std::wstring> g_CreatedServices;
    std::vector<std::wstring> g_TempFiles;
    std::vector<std::wstring> g_TempDirectories;
    std::vector<ScenarioRecord> g_Scenarios;
    std::vector<MappedImageRecord> g_MappedImages;
    HMODULE g_FixtureDll = nullptr;
    bool g_DefaultExportPatched = false;
    bool g_LateExportPatched = false;
    uint64_t g_DefaultPatchAddress = 0;
    uint64_t g_LatePatchAddress = 0;

    const ScenarioMenuItem g_ScenarioMenuItems[] =
    {
        {
            L"/baseline",
            L"baseline negative control",
            L"baseline / negative control",
            L"no suspicious artifact",
            L"target should have no target-specific findings",
            L"use this before positive controls to check local noise",
            &Options::Baseline
        },
        {
            L"/private-exec",
            L"private executable VAD",
            L"mapped code / injection primitive",
            L"a private RX page owned by this process",
            L"hunt should report private executable memory",
            L"focused test for mapped code without thread evidence",
            &Options::PrivateExec
        },
        {
            L"/rwx",
            L"writable executable VAD",
            L"mapped code / injection primitive",
            L"a private RWX page owned by this process",
            L"hunt should report writable executable private memory",
            L"stronger than RX because write and execute are both present",
            &Options::Rwx
        },
        {
            L"/large-private-exec",
            L"large private executable VAD",
            L"mapped code / injection primitive",
            L"a large private RX region",
            L"hunt should report a large private executable region",
            L"useful for unpacker or manual-map staging heuristics",
            &Options::LargePrivateExec
        },
        {
            L"/pe-like",
            L"private PE-like mapping",
            L"mapped code / loader evasion",
            L"a private executable page that looks like a PE image",
            L"hunt should report a private PE mapping without loader state",
            L"does not create a real loader module entry",
            &Options::PeLike
        },
        {
            L"/wiped-pe",
            L"wiped private PE mapping",
            L"mapped code / loader evasion",
            L"a private PE-like page with wiped MZ and PE signatures",
            L"hunt should still recover PE-like evidence after header wiping",
            L"tests weak-header evasion, not another process",
            &Options::WipedPe
        },
        {
            L"/thread",
            L"thread start in private executable memory",
            L"execution from injected code",
            L"a live thread whose start address is private executable memory",
            L"hunt should connect the suspicious thread start to private code",
            L"use when validating thread-start correlation",
            &Options::Thread
        },
        {
            L"/apc",
            L"APC routine in private executable memory",
            L"execution from injected code",
            L"an APC normal routine pointing at private executable memory",
            L"hunt should connect APC target evidence to private code",
            L"use when validating queued APC correlation",
            &Options::Apc
        },
        {
            L"/threadless-stack",
            L"threadless stack reference",
            L"threadless mapped-code evidence",
            L"a normal thread stack that references private executable memory",
            L"hunt should report stack references to user executable memory",
            L"no suspicious thread start is required for this one",
            &Options::ThreadlessStack
        },
        {
            L"/module-patch",
            L"module text patch",
            L"module integrity / module stomping",
            L"a loaded fixture DLL export patched in memory",
            L"hunt should report live-vs-disk executable page mismatch",
            L"basic module text integrity positive control",
            &Options::ModulePatch
        },
        {
            L"/module-patch-late",
            L"late-section module text patch",
            L"module integrity / module stomping",
            L"a later executable section in the fixture DLL patched in memory",
            L"hunt should report module text mismatch and stomping evidence",
            L"targets non-entry executable section coverage",
            &Options::ModulePatchLate
        },
        {
            L"/stomp-thread",
            L"module stomping with thread start",
            L"module stomping execution",
            L"a modified module page used as a thread start address",
            L"hunt should connect thread execution to modified module code",
            L"good focused test for stomped module thread starts",
            &Options::StompThread
        },
        {
            L"/stomp-apc",
            L"module stomping with APC target",
            L"module stomping execution",
            L"an APC target inside a modified module executable page",
            L"hunt should connect APC execution to modified module code",
            L"good focused test for stomped module APC targets",
            &Options::StompApc
        },
        {
            L"/section-image-map",
            L"loader-invisible SEC_IMAGE mapping",
            L"loader-view evasion",
            L"a copied DLL mapped as SEC_IMAGE without LoadLibrary",
            L"hunt should report an image VAD missing from the loader list",
            L"tests cross-view module enumeration",
            &Options::SectionImageMap
        },
        {
            L"/locked-backed-image",
            L"locked backing file image mapping",
            L"loader-view evasion",
            L"a loader-invisible SEC_IMAGE whose backing file blocks read reopen",
            L"hunt should report missing loader entry and inaccessible backing",
            L"models anti-inspection file sharing tricks",
            &Options::LockedBackedImage
        },
        {
            L"/section-image-stomp",
            L"stomped loader-invisible SEC_IMAGE mapping",
            L"loader-view evasion + module stomping",
            L"a loader-invisible SEC_IMAGE mapping with modified executable code",
            L"hunt should report both loader-view evasion and module stomping",
            L"higher-signal than a clean SEC_IMAGE map",
            &Options::SectionImageStomp
        },
        {
            L"/image-rwx-section",
            L"image RWX section",
            L"module permission anomaly",
            L"a loaded image section with writable executable protection",
            L"hunt should report image RWX section evidence",
            L"models Mockingjay-style writable executable image sections",
            &Options::ImageRwxSection
        },
        {
            L"/edr-killer-suffix-name",
            L"known defense-evasion process-name fixtures",
            L"process identity / defense-evasion profile",
            L"benign child copies with Gentlemen-style process names and metadata",
            L"hunt should explain process masquerading and staging evidence",
            L"also creates negative-control child processes",
            &Options::EdrKillerSuffixName
        },
        {
            L"/oxideharvest-cli",
            L"credential-tool command-line fixture",
            L"process identity / credential-tool profile",
            L"a benign child copy with OxideHarvest-style command-line shape",
            L"hunt should explain credential-collection CLI evidence",
            L"also creates a name-only negative-control child process",
            &Options::OxideHarvestCli
        },
        {
            L"/edr-killer-driver-service",
            L"known defense-evasion driver-service fixtures",
            L"system artifact / driver-service IOC",
            L"temporary non-started SCM kernel-driver service entries",
            L"hunt should explain system-scoped driver-service IOC evidence",
            L"requires admin; non-admin readiness smoke expects this to skip",
            &Options::EdrKillerDriverService
        },
        {
            L"/lab-builtin-profile",
            L"built-in process impersonation lab profile",
            L"built-in process impersonation",
            L"an explicit lab-only built-in process profile violation",
            L"hunt should explain path and non-Windows module identity mismatch",
            L"intentionally gated by an explicit scenario selection",
            &Options::LabBuiltinProfile
        }
    };

    constexpr size_t kScenarioMenuItemCount =
        sizeof(g_ScenarioMenuItems) / sizeof(g_ScenarioMenuItems[0]);

    void TouchPackerSectionMarker()
    {
        volatile unsigned char value = g_HuntTargetEnigmaSectionMarker[0];
        UNREFERENCED_PARAMETER(value);
    }

    std::wstring Hex(uint64_t value)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value;
        return stream.str();
    }

    std::wstring Win32ErrorText(const wchar_t* prefix, DWORD error)
    {
        std::wstringstream stream;
        stream << prefix << L" gle=" << error;
        return stream.str();
    }

    std::wstring Win32ErrorText(const wchar_t* prefix)
    {
        return Win32ErrorText(prefix, GetLastError());
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

    void AppendJsonStringObject(
        std::wstringstream& json,
        const std::vector<std::pair<std::wstring, std::wstring>>& values)
    {
        json << L"{";
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                json << L",";
            }

            json << L"\"" << JsonEscape(values[index].first) << L"\":\""
                 << JsonEscape(values[index].second) << L"\"";
        }
        json << L"}";
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

    bool WriteUtf8TextFile(const std::wstring& path, const std::wstring& text, std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            std::string textUtf8;
            if (!WideToUtf8(text, &textUtf8))
            {
                if (error != nullptr)
                {
                    *error = L"UTF-8 manifest conversion failed";
                }
                break;
            }

            file = CreateFileW(
                path.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"CreateFileW manifest failed");
                }
                break;
            }

            const unsigned char bom[] = { 0xef, 0xbb, 0xbf };
            DWORD written = 0;
            if (!WriteFile(file, bom, static_cast<DWORD>(sizeof(bom)), &written, nullptr) ||
                written != sizeof(bom))
            {
                if (error != nullptr)
                {
                    *error = Win32ErrorText(L"WriteFile manifest BOM failed");
                }
                break;
            }

            size_t offset = 0;
            while (offset < textUtf8.size())
            {
                size_t remaining = textUtf8.size() - offset;
                DWORD chunk = remaining > 0x100000u
                    ? 0x100000u
                    : static_cast<DWORD>(remaining);
                written = 0;
                if (!WriteFile(file, textUtf8.data() + offset, chunk, &written, nullptr) ||
                    written == 0 ||
                    written > chunk)
                {
                    if (error != nullptr)
                    {
                        *error = Win32ErrorText(L"WriteFile manifest body failed");
                    }
                    break;
                }

                offset += written;
            }

            ok = offset == textUtf8.size();
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    std::wstring DirectoryFromPath(const std::wstring& path)
    {
        std::wstring directory;
        size_t slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            directory = path.substr(0, slash);
        }

        return directory;
    }

    bool DirectoryExists(const std::wstring& path)
    {
        DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    bool EnsureDirectoryTree(const std::wstring& directory, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (directory.empty())
            {
                ok = true;
                break;
            }

            DWORD attributes = GetFileAttributesW(directory.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES)
            {
                ok = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (!ok && error != nullptr)
                {
                    *error = L"path exists but is not a directory: " + directory;
                }
                break;
            }

            size_t slash = directory.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                std::wstring parent = directory.substr(0, slash);
                if (!parent.empty() && !DirectoryExists(parent))
                {
                    if (!EnsureDirectoryTree(parent, error))
                    {
                        break;
                    }
                }
            }

            if (!CreateDirectoryW(directory.c_str(), nullptr))
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_ALREADY_EXISTS)
                {
                    if (error != nullptr)
                    {
                        *error = Win32ErrorText(L"CreateDirectoryW manifest directory failed", lastError);
                    }
                    break;
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool WriteManifestFile(const std::wstring& path, const std::wstring& text, std::wstring* error)
    {
        bool ok = false;

        do
        {
            std::wstring directory = DirectoryFromPath(path);
            if (!EnsureDirectoryTree(directory, error))
            {
                break;
            }

            if (!WriteUtf8TextFile(path, text, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    void AddScenario(
        const std::wstring& name,
        const std::wstring& artifact,
        uint64_t address,
        uint64_t size,
        std::initializer_list<const wchar_t*> expectedReasons,
        const std::wstring& notes,
        DWORD processId = 0,
        std::initializer_list<const wchar_t*> expectedEvidenceKeys = {},
        std::initializer_list<std::pair<const wchar_t*, const wchar_t*>> expectedEvidenceValues = {},
        std::initializer_list<const wchar_t*> unexpectedReasons = {},
        bool includeProcessId = false,
        const wchar_t* expectedClass = nullptr,
        const wchar_t* expectedRisk = nullptr,
        const wchar_t* expectedConfidence = nullptr)
    {
        ScenarioRecord record = {};
        record.Name = name;
        record.Artifact = artifact;
        record.Address = address;
        record.Size = size;
        record.ProcessId = processId;
        record.HasProcessId = includeProcessId || processId != 0;
        record.Notes = notes;

        for (const wchar_t* reason : expectedReasons)
        {
            if (reason != nullptr)
            {
                record.ExpectedReasons.push_back(reason);
            }
        }

        for (const wchar_t* key : expectedEvidenceKeys)
        {
            if (key != nullptr)
            {
                record.ExpectedEvidenceKeys.push_back(key);
            }
        }

        for (const std::pair<const wchar_t*, const wchar_t*>& item : expectedEvidenceValues)
        {
            if (item.first != nullptr && item.second != nullptr)
            {
                record.ExpectedEvidenceValues.emplace_back(item.first, item.second);
            }
        }

        for (const wchar_t* reason : unexpectedReasons)
        {
            if (reason != nullptr)
            {
                record.UnexpectedReasons.push_back(reason);
            }
        }
        if (expectedClass != nullptr)
        {
            record.ExpectedClass = expectedClass;
        }
        if (expectedRisk != nullptr)
        {
            record.ExpectedRisk = expectedRisk;
        }
        if (expectedConfidence != nullptr)
        {
            record.ExpectedConfidence = expectedConfidence;
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
            if (scenario.HasProcessId)
            {
                json << L",\"pid\":" << scenario.ProcessId;
            }
            json << L",\"address\":\"" << Hex(scenario.Address) << L"\"";
            json << L",\"size\":" << scenario.Size;
            json << L",\"expected_reasons\":";
            AppendJsonStringArray(json, scenario.ExpectedReasons);
            json << L",\"unexpected_reasons\":";
            AppendJsonStringArray(json, scenario.UnexpectedReasons);
            json << L",\"expected_evidence_keys\":";
            AppendJsonStringArray(json, scenario.ExpectedEvidenceKeys);
            json << L",\"expected_evidence\":";
            AppendJsonStringObject(json, scenario.ExpectedEvidenceValues);
            if (!scenario.ExpectedClass.empty())
            {
                json << L",\"expected_class\":\"" << JsonEscape(scenario.ExpectedClass) << L"\"";
            }
            if (!scenario.ExpectedRisk.empty())
            {
                json << L",\"expected_risk\":\"" << JsonEscape(scenario.ExpectedRisk) << L"\"";
            }
            if (!scenario.ExpectedConfidence.empty())
            {
                json << L",\"expected_confidence\":\"" << JsonEscape(scenario.ExpectedConfidence) << L"\"";
            }
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

    void ClearScenarioOptions(Options* options)
    {
        if (options == nullptr)
        {
            return;
        }

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
        options->EdrKillerSuffixName = false;
        options->OxideHarvestCli = false;
        options->EdrKillerDriverService = false;
        options->LabBuiltinProfile = false;
        options->Baseline = false;
    }

    void EnableAllScenarioOptions(Options* options)
    {
        if (options == nullptr)
        {
            return;
        }

        ClearScenarioOptions(options);
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
        options->EdrKillerSuffixName = true;
        options->OxideHarvestCli = true;
        options->EdrKillerDriverService = true;
        options->LabBuiltinProfile = true;
    }

    bool EnableScenarioByMenuIndex(size_t menuIndex, Options* options)
    {
        bool ok = true;

        do
        {
            if (options == nullptr || menuIndex == 0 || menuIndex > kScenarioMenuItemCount)
            {
                ok = false;
                break;
            }

            const ScenarioMenuItem& item = g_ScenarioMenuItems[menuIndex - 1];
            (options->*(item.Flag)) = true;
        } while (false);

        return ok;
    }

    void PrintScenarioMenu()
    {
        std::wcout << L"\nAvailable hunt target experiments:\n";
        std::wcout << L"  Select a focused experiment. Each item explains what the target creates\n";
        std::wcout << L"  and what a successful !hunt run should conclude.\n\n";
        std::wcout << L"  0. /all - all positive-control experiments\n";
        std::wcout << L"     category: full sweep\n";
        std::wcout << L"     creates : every positive-control artifact listed below\n";
        std::wcout << L"     hunt    : broad validation across memory, module, identity, and service evidence\n";
        std::wcout << L"     note    : intentionally noisy; driver-service items require admin\n";
        for (size_t index = 0; index < kScenarioMenuItemCount; ++index)
        {
            const ScenarioMenuItem& item = g_ScenarioMenuItems[index];
            std::wcout << L"  " << (index + 1) << L". "
                       << item.Title << L" (" << item.OptionName << L")\n";
            std::wcout << L"     category: " << item.Category << L"\n";
            std::wcout << L"     creates : " << item.Creates << L"\n";
            std::wcout << L"     hunt    : " << item.HuntExpectation << L"\n";
            std::wcout << L"     note    : " << item.OperatorNote << L"\n";
        }
        std::wcout << L"\n";
    }

    void PrintUsage()
    {
        std::wcout << L"KnLiveDbgHuntTarget command:\n";
        std::wcout << L"  KnLiveDbgHuntTarget.exe [/all] [/baseline] [/private-exec] [/rwx] [/large-private-exec] [/pe-like] [/wiped-pe] [/thread] [/apc] [/threadless-stack] [/module-patch] [/module-patch-late] [/stomp-thread] [/stomp-apc] [/section-image-map] [/locked-backed-image] [/section-image-stomp] [/image-rwx-section] [/edr-killer-suffix-name] [/oxideharvest-cli] [/edr-killer-driver-service] [/lab-builtin-profile] [/manifest path] [/seconds n] [/stop-event name]\n";
        std::wcout << L"  KnLiveDbgHuntTarget.exe\n";
        std::wcout << L"\n";
        std::wcout << L"notes:\n";
        std::wcout << L"  This is a lab-only positive-control target for !hunt.\n";
        std::wcout << L"  It mutates only its own process and never injects into another process.\n";
        std::wcout << L"  Without a scenario flag, it opens the numbered experiment menu below.\n";
        std::wcout << L"  Menu selections accept one number, comma/space separated numbers, or ranges such as 2-6.\n";
        std::wcout << L"  /seconds 0 keeps the target alive until Ctrl+C.\n";
        std::wcout << L"  /stop-event waits for a named manual-reset event and exits cleanly when it is signaled.\n";
        std::wcout << L"  /manifest creates parent directories when needed.\n";
        std::wcout << L"  Run KnLiveDbg elevated in another console and execute: !hunt /deep /summary /json .\\hunt-target.json\n";
        PrintScenarioMenu();
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
                    EnableAllScenarioOptions(options);
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
                else if (arg == L"/edr-killer-suffix-name")
                {
                    options->EdrKillerSuffixName = true;
                    sawScenario = true;
                }
                else if (arg == L"/oxideharvest-cli")
                {
                    options->OxideHarvestCli = true;
                    sawScenario = true;
                }
                else if (arg == L"/edr-killer-driver-service")
                {
                    options->EdrKillerDriverService = true;
                    sawScenario = true;
                }
                else if (arg == L"/lab-builtin-profile")
                {
                    options->LabBuiltinProfile = true;
                    sawScenario = true;
                }
                else if (arg == L"/child-wait-parent")
                {
                    if (index + 1 >= argc || !ParseUInt32(argv[index + 1], &options->ChildWaitParentPid))
                    {
                        std::wcerr << L"invalid /child-wait-parent value\n";
                        break;
                    }
                    ++index;
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
                else if (arg == L"/stop-event")
                {
                    if (index + 1 >= argc || argv[index + 1][0] == L'\0')
                    {
                        std::wcerr << L"invalid /stop-event value\n";
                        break;
                    }
                    options->StopEventName = argv[index + 1];
                    ++index;
                }
                else if (arg == L"-i" || arg == L"-u" || arg == L"-p" || arg == L"-t" || arg == L"-o")
                {
                    if (index + 1 >= argc)
                    {
                        std::wcerr << L"invalid OxideHarvest fixture option value\n";
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

            if (!sawScenario && options->ChildWaitParentPid == 0)
            {
                options->Interactive = true;
            }

            if (options->Baseline)
            {
                ClearScenarioOptions(options);
                options->Baseline = true;
            }
        } while (false);

        return ok;
    }

    bool ParseMenuSelection(
        const std::wstring& line,
        std::vector<size_t>* selections,
        bool* quit)
    {
        bool ok = false;

        do
        {
            if (selections == nullptr || quit == nullptr)
            {
                break;
            }

            selections->clear();
            *quit = false;

            std::wstring normalized = line;
            for (wchar_t& ch : normalized)
            {
                if (ch == L',' ||
                    ch == L';' ||
                    ch == L'\t' ||
                    ch == L'\r' ||
                    ch == L'\n' ||
                    ch == L'\0' ||
                    ch == static_cast<wchar_t>(0xfeff))
                {
                    ch = L' ';
                }
            }

            std::wistringstream stream(normalized);
            std::wstring token;
            bool parseFailure = false;
            while (stream >> token)
            {
                std::wstring lowerToken;
                for (wchar_t ch : token)
                {
                    lowerToken.push_back(static_cast<wchar_t>(std::towlower(ch)));
                }

                if (lowerToken == L"q" || lowerToken == L"quit" || lowerToken == L"exit")
                {
                    *quit = true;
                    selections->clear();
                    ok = true;
                    break;
                }
                if (lowerToken == L"all")
                {
                    selections->push_back(0);
                    continue;
                }

                size_t dash = lowerToken.find(L'-');
                if (dash != std::wstring::npos)
                {
                    if (dash == 0 || dash + 1 == lowerToken.size())
                    {
                        parseFailure = true;
                        break;
                    }

                    std::wstring firstText = lowerToken.substr(0, dash);
                    std::wstring lastText = lowerToken.substr(dash + 1);
                    DWORD first = 0;
                    DWORD last = 0;
                    if (!ParseUInt32(firstText.c_str(), &first) ||
                        !ParseUInt32(lastText.c_str(), &last) ||
                        first > last ||
                        last > static_cast<DWORD>(kScenarioMenuItemCount))
                    {
                        parseFailure = true;
                        break;
                    }

                    for (DWORD value = first; value <= last; ++value)
                    {
                        selections->push_back(static_cast<size_t>(value));
                    }
                    continue;
                }

                DWORD value = 0;
                if (!ParseUInt32(lowerToken.c_str(), &value) ||
                    value > static_cast<DWORD>(kScenarioMenuItemCount))
                {
                    parseFailure = true;
                    break;
                }

                selections->push_back(static_cast<size_t>(value));
            }

            if (*quit)
            {
                break;
            }

            if (parseFailure)
            {
                selections->clear();
                break;
            }

            ok = !selections->empty();
        } while (false);

        return ok;
    }

    bool IsMenuIndexSelected(const std::vector<size_t>& selections, size_t menuIndex)
    {
        bool selected = false;

        for (size_t selection : selections)
        {
            if (selection == menuIndex)
            {
                selected = true;
                break;
            }
        }

        return selected;
    }

    bool IsScenarioMenuIndexEnabled(const Options& options, size_t menuIndex)
    {
        bool enabled = false;

        do
        {
            if (menuIndex == 0 || menuIndex > kScenarioMenuItemCount)
            {
                break;
            }

            const ScenarioMenuItem& item = g_ScenarioMenuItems[menuIndex - 1];
            enabled = (options.*(item.Flag));
        } while (false);

        return enabled;
    }

    void PrintSelectedScenarioOptions(const Options& options)
    {
        std::wcout << L"\nselected experiments:\n";
        for (size_t index = 1; index <= kScenarioMenuItemCount; ++index)
        {
            if (IsScenarioMenuIndexEnabled(options, index))
            {
                const ScenarioMenuItem& item = g_ScenarioMenuItems[index - 1];
                std::wcout << L"  " << index << L". "
                           << item.OptionName << L" - "
                           << item.Title << L"\n";
                std::wcout << L"     creates: " << item.Creates << L"\n";
                std::wcout << L"     hunt   : " << item.HuntExpectation << L"\n";
            }
        }
        std::wcout << L"\n";
    }

    bool PromptScenarioMenuSelection(Options* options, bool* canceled)
    {
        bool ok = false;

        do
        {
            if (options == nullptr || canceled == nullptr)
            {
                break;
            }

            *canceled = false;
            ClearScenarioOptions(options);
            PrintScenarioMenu();

            for (;;)
            {
                std::wcout << L"Select experiment number(s), 0/all for all, or q to exit: ";
                std::wcout.flush();

                std::wstring line;
                if (!std::getline(std::wcin, line))
                {
                    std::wcout << L"\nno selection; exiting\n";
                    *canceled = true;
                    ok = true;
                    break;
                }

                std::vector<size_t> selections;
                bool quit = false;
                if (!ParseMenuSelection(line, &selections, &quit))
                {
                    std::wcerr << L"invalid selection. Enter one number, comma/space separated numbers, a range, or q.\n";
                    continue;
                }

                if (quit)
                {
                    *canceled = true;
                    ok = true;
                    break;
                }

                bool allSelected = IsMenuIndexSelected(selections, 0);
                if (allSelected)
                {
                    EnableAllScenarioOptions(options);
                    PrintSelectedScenarioOptions(*options);
                    ok = true;
                    break;
                }

                bool baselineSelected = IsMenuIndexSelected(selections, 1);
                bool baselineCombined = false;
                if (baselineSelected)
                {
                    for (size_t selection : selections)
                    {
                        if (selection != 1)
                        {
                            baselineCombined = true;
                            break;
                        }
                    }
                }
                if (baselineCombined)
                {
                    std::wcerr << L"baseline cannot be combined with positive-control experiments.\n";
                    continue;
                }

                ClearScenarioOptions(options);
                bool enableFailure = false;
                for (size_t menuIndex : selections)
                {
                    if (!EnableScenarioByMenuIndex(menuIndex, options))
                    {
                        enableFailure = true;
                        break;
                    }
                }

                if (enableFailure)
                {
                    std::wcerr << L"invalid selection index.\n";
                    continue;
                }

                PrintSelectedScenarioOptions(*options);
                ok = true;
                break;
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

    bool GetSelfPath(std::wstring* path)
    {
        bool ok = false;

        do
        {
            if (path == nullptr)
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

            path->assign(buffer.data(), length);
            ok = true;
        } while (false);

        return ok;
    }

    bool MakeTempSelfCopy(
        const wchar_t* fileName,
        std::wstring* path,
        bool gentlemenCollection = true)
    {
        bool ok = false;

        do
        {
            if (fileName == nullptr || path == nullptr)
            {
                break;
            }

            std::wstring selfPath;
            if (!GetSelfPath(&selfPath))
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

            std::wstringstream directoryStream;
            directoryStream << tempPath
                            << L"knhunt-"
                            << GetCurrentProcessId()
                            << (gentlemenCollection ? L"-GentlemenCollection" : L"-WeakVendorControl");
            std::wstring directory = directoryStream.str();
            if (!CreateDirectoryW(directory.c_str(), nullptr) &&
                GetLastError() != ERROR_ALREADY_EXISTS)
            {
                std::wcerr << Win32ErrorText(L"CreateDirectoryW temp copy directory failed") << L"\n";
                break;
            }

            std::wstring candidate = directory + L"\\" + fileName;
            if (!CopyFileW(selfPath.c_str(), candidate.c_str(), FALSE))
            {
                std::wcerr << Win32ErrorText(L"CopyFileW self temp copy failed") << L"\n";
                break;
            }

            g_TempDirectories.push_back(directory);
            g_TempFiles.push_back(candidate);
            *path = candidate;
            ok = true;
        } while (false);

        return ok;
    }

    bool MakeTempSystem32Copy(
        const wchar_t* sourceFileName,
        const wchar_t* fileName,
        std::wstring* path,
        bool gentlemenCollection = true)
    {
        bool ok = false;

        do
        {
            if (sourceFileName == nullptr ||
                fileName == nullptr ||
                path == nullptr)
            {
                break;
            }

            wchar_t systemDirectory[MAX_PATH + 1] = {};
            UINT systemLength = GetSystemDirectoryW(systemDirectory, static_cast<UINT>(_countof(systemDirectory)));
            if (systemLength == 0 || systemLength >= _countof(systemDirectory))
            {
                std::wcerr << Win32ErrorText(L"GetSystemDirectoryW failed") << L"\n";
                break;
            }

            std::wstring sourcePath = std::wstring(systemDirectory) + L"\\" + sourceFileName;

            wchar_t tempPath[MAX_PATH + 1] = {};
            DWORD tempLength = GetTempPathW(static_cast<DWORD>(_countof(tempPath)), tempPath);
            if (tempLength == 0 || tempLength >= _countof(tempPath))
            {
                std::wcerr << Win32ErrorText(L"GetTempPathW failed") << L"\n";
                break;
            }

            std::wstringstream directoryStream;
            directoryStream << tempPath
                            << L"knhunt-"
                            << GetCurrentProcessId()
                            << (gentlemenCollection ? L"-GentlemenCollection" : L"-SystemCopyControl");
            std::wstring directory = directoryStream.str();
            if (!CreateDirectoryW(directory.c_str(), nullptr) &&
                GetLastError() != ERROR_ALREADY_EXISTS)
            {
                std::wcerr << Win32ErrorText(L"CreateDirectoryW temp system copy directory failed") << L"\n";
                break;
            }

            std::wstring candidate = directory + L"\\" + fileName;
            if (!CopyFileW(sourcePath.c_str(), candidate.c_str(), FALSE))
            {
                std::wcerr << Win32ErrorText(L"CopyFileW system temp copy failed") << L"\n";
                break;
            }

            g_TempDirectories.push_back(directory);
            g_TempFiles.push_back(candidate);
            *path = candidate;
            ok = true;
        } while (false);

        return ok;
    }

    bool WaitAsChildProcess(const Options& options)
    {
        bool ok = false;
        HANDLE parent = nullptr;

        do
        {
            DWORD waitMs = INFINITE;
            if (options.RunSeconds != 0 && options.RunSeconds <= 0xffffffffu / 1000u)
            {
                waitMs = options.RunSeconds * 1000u;
            }

            parent = OpenProcess(SYNCHRONIZE, FALSE, options.ChildWaitParentPid);
            if (parent == nullptr)
            {
                WaitForSingleObject(g_StopEvent, waitMs);
                ok = true;
                break;
            }

            HANDLE handles[2] = { g_StopEvent, parent };
            WaitForMultipleObjects(2, handles, FALSE, waitMs);
            ok = true;
        } while (false);

        if (parent != nullptr)
        {
            CloseHandle(parent);
        }

        return ok;
    }

    void DeleteCreatedDriverServices()
    {
        SC_HANDLE scm = nullptr;

        do
        {
            if (g_CreatedServices.empty())
            {
                break;
            }

            scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (scm == nullptr)
            {
                break;
            }

            for (const std::wstring& serviceName : g_CreatedServices)
            {
                SC_HANDLE service = OpenServiceW(
                    scm,
                    serviceName.c_str(),
                    SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
                if (service == nullptr)
                {
                    continue;
                }

                SERVICE_STATUS status = {};
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                DeleteService(service);
                CloseServiceHandle(service);
            }
        } while (false);

        if (scm != nullptr)
        {
            CloseServiceHandle(scm);
        }

        g_CreatedServices.clear();
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

    bool CreateEdrKillerSuffixNameChild(
        const Options& options,
        const wchar_t* fileName,
        const wchar_t* scenarioName,
        const wchar_t* notes,
        const wchar_t* expectedSuffixTail,
        const wchar_t* expectedSuffixComponents,
        const wchar_t* expectedProtectionHint,
        const wchar_t* expectedFakeSignature,
        const wchar_t* expectedFakeVersion)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            if (fileName == nullptr ||
                scenarioName == nullptr ||
                notes == nullptr ||
                expectedSuffixTail == nullptr ||
                expectedSuffixComponents == nullptr ||
                expectedProtectionHint == nullptr ||
                expectedFakeSignature == nullptr ||
                expectedFakeVersion == nullptr)
            {
                break;
            }

            std::wstring childPath;
            if (!MakeTempSelfCopy(fileName, &childPath))
            {
                break;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /baseline /child-wait-parent "
                    << GetCurrentProcessId()
                    << L" /seconds "
                    << options.RunSeconds;
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW EDR-killer suffix child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"edr-killer-suffix-name child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                scenarioName,
                std::wstring(L"benign child process named ") + fileName + L" like a Gentlemen suffix-normalized EDR-killer IOC",
                0,
                0,
                {L"gentlemen_edr_killer_process_name", L"gentlemen_suffix_normalized_process_name", L"gentlemen_collection_staging_path", L"edr_killer_version_info_impersonation_evidence", L"edr_killer_packer_section_evidence"},
                notes,
                processInfo.dwProcessId,
                {
                    L"image_metadata_path",
                    L"image_version_info_present",
                    L"image_file_version",
                    L"image_company_name",
                    L"image_product_name",
                    L"image_original_filename",
                    L"image_file_description",
                    L"image_version_info_impersonation_match",
                    L"image_signature_checked",
                    L"image_pe_metadata_read",
                    L"image_pe_section_count",
                    L"image_executable_section_names",
                    L"image_packer_section_hint",
                    L"image_packer_section_names",
                    L"gentlemen_suffix_tail",
                    L"gentlemen_suffix_components",
                    L"gentlemen_suffix_protection_hint",
                    L"gentlemen_suffix_fake_signature_expected",
                    L"gentlemen_suffix_fake_version_expected"
                },
                {
                    { L"image_version_info_present", L"true" },
                    { L"image_file_version", L"1.2.3.4" },
                    { L"image_company_name", L"Kaspersky Lab" },
                    { L"image_product_name", L"Kaspersky Anti-Virus" },
                    { L"image_original_filename", L"Kasps.exe" },
                    { L"image_file_description", L"KnLiveDbg hunt EDR-killer metadata fixture" },
                    { L"image_version_info_impersonation_match", L"kaspersky" },
                    { L"image_pe_metadata_read", L"true" },
                    { L"image_packer_section_hint", L"enigma" },
                    { L"image_packer_section_names", L".enigma" },
                    { L"gentlemen_suffix_tail", expectedSuffixTail },
                    { L"gentlemen_suffix_components", expectedSuffixComponents },
                    { L"gentlemen_suffix_protection_hint", expectedProtectionHint },
                    { L"gentlemen_suffix_fake_signature_expected", expectedFakeSignature },
                    { L"gentlemen_suffix_fake_version_expected", expectedFakeVersion }
                },
                {},
                false,
                L"edr_killer_process_profile",
                L"high",
                L"high");
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateEdrKillerExactNameChild(
        const Options& options,
        const wchar_t* fileName,
        const wchar_t* scenarioName,
        const wchar_t* notes)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            if (fileName == nullptr ||
                scenarioName == nullptr ||
                notes == nullptr)
            {
                break;
            }

            std::wstring childPath;
            if (!MakeTempSelfCopy(fileName, &childPath))
            {
                break;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /baseline /child-wait-parent "
                    << GetCurrentProcessId()
                    << L" /seconds "
                    << options.RunSeconds;
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW EDR-killer exact-name child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"edr-killer-exact-name child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                scenarioName,
                std::wstring(L"benign child process named ") + fileName + L" like an exact Gentlemen EDR-killer IOC",
                0,
                0,
                {L"gentlemen_edr_killer_process_name", L"gentlemen_collection_staging_path", L"edr_killer_version_info_impersonation_evidence", L"edr_killer_packer_section_evidence"},
                notes,
                processInfo.dwProcessId,
                {
                    L"image_metadata_path",
                    L"image_version_info_present",
                    L"image_file_version",
                    L"image_company_name",
                    L"image_product_name",
                    L"image_original_filename",
                    L"image_file_description",
                    L"image_version_info_impersonation_match",
                    L"image_signature_checked",
                    L"image_pe_metadata_read",
                    L"image_pe_section_count",
                    L"image_executable_section_names",
                    L"image_packer_section_hint",
                    L"image_packer_section_names"
                },
                {
                    { L"image_version_info_present", L"true" },
                    { L"image_file_version", L"1.2.3.4" },
                    { L"image_company_name", L"Kaspersky Lab" },
                    { L"image_product_name", L"Kaspersky Anti-Virus" },
                    { L"image_original_filename", L"Kasps.exe" },
                    { L"image_file_description", L"KnLiveDbg hunt EDR-killer metadata fixture" },
                    { L"image_version_info_impersonation_match", L"kaspersky" },
                    { L"image_pe_metadata_read", L"true" },
                    { L"image_packer_section_hint", L"enigma" },
                    { L"image_packer_section_names", L".enigma" }
                },
                {},
                false,
                L"edr_killer_process_profile",
                L"high",
                L"high");
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateWeakVendorStandaloneNegativeChild(const Options& options)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            std::wstring childPath;
            if (!MakeTempSelfCopy(L"Avast.exe", &childPath, false))
            {
                break;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /baseline /child-wait-parent "
                    << GetCurrentProcessId()
                    << L" /seconds "
                    << options.RunSeconds;
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW weak vendor negative child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"edr-killer-weak-vendor-negative child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                L"edr-killer-weak-vendor-standalone-negative",
                L"benign child process named Avast.exe outside GentlemenCollection",
                0,
                0,
                {},
                L"validates that weak vendor-impersonation names do not alert without staging or telemetry context",
                processInfo.dwProcessId,
                {},
                {},
                {
                    L"gentlemen_edr_killer_process_name",
                    L"security_vendor_impersonation_name",
                    L"gentlemen_suffix_normalized_process_name"
                });
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateGentlemenStagingOnlyNegativeChild(const Options& options)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            std::wstring childPath;
            if (!MakeTempSystem32Copy(L"cmd.exe", L"StageOnlyBenign.exe", &childPath, true))
            {
                break;
            }

            uint32_t pingCount = options.RunSeconds;
            if (pingCount < 2)
            {
                pingCount = 2;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /d /c \"ping 127.0.0.1 -n "
                    << pingCount
                    << L" > nul\"";
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW Gentlemen staging-only negative child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"edr-killer-staging-only-negative child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                L"edr-killer-gentlemen-staging-only-negative",
                L"benign cmd.exe copy launched from GentlemenCollection with an unknown filename",
                0,
                0,
                {},
                L"validates that GentlemenCollection staging alone does not create a process-profile finding without profile, metadata, or telemetry evidence",
                processInfo.dwProcessId,
                {},
                {},
                {
                    L"gentlemen_collection_staging_path",
                    L"gentlemen_edr_killer_process_name",
                    L"gentlemen_suffix_normalized_process_name",
                    L"security_vendor_impersonation_name",
                    L"edr_killer_version_info_impersonation_evidence",
                    L"edr_killer_icon_impersonation_evidence",
                    L"edr_killer_packer_section_evidence",
                    L"gentlemen_related_credential_tool_name",
                    L"oxideharvest_cli_shape"
                });
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateOxideHarvestCliProcess(const Options& options)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            std::wstring childPath;
            if (!MakeTempSelfCopy(L"buildx641.exe", &childPath, false))
            {
                break;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /baseline /child-wait-parent "
                    << GetCurrentProcessId()
                    << L" /seconds "
                    << options.RunSeconds
                    << L" -i hosts.txt -u lab-user -p lab-pass -t 4 -o creds.txt";
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW OxideHarvest CLI child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"oxideharvest-cli child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                L"oxideharvest-cli",
                L"benign child process named buildx641.exe with OxideHarvest-style CLI options",
                0,
                0,
                {
                    L"gentlemen_related_credential_tool_name",
                    L"oxideharvest_cli_shape"
                },
                L"validates buildx641.exe credential-tool IOC plus -i/-u/-p/-t/-o command-line shape",
                processInfo.dwProcessId,
                {
                    L"oxideharvest_cli_options"
                },
                {
                    { L"oxideharvest_cli_options", L"-i;-u;-p;-t;-o" }
                },
                {},
                false,
                L"gentlemen_related_tool",
                L"medium",
                L"high");
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateOxideHarvestNameOnlyNegativeProcess(const Options& options)
    {
        bool ok = false;
        PROCESS_INFORMATION processInfo = {};

        do
        {
            std::wstring childPath;
            if (!MakeTempSelfCopy(L"buildx64.exe", &childPath, false))
            {
                break;
            }

            std::wstringstream command;
            command << L"\""
                    << childPath
                    << L"\" /baseline /child-wait-parent "
                    << GetCurrentProcessId()
                    << L" /seconds "
                    << options.RunSeconds;
            std::wstring commandLine = command.str();

            STARTUPINFOW startup = {};
            startup.cb = sizeof(startup);
            if (!CreateProcessW(
                    childPath.c_str(),
                    commandLine.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    CREATE_NO_WINDOW,
                    nullptr,
                    nullptr,
                    &startup,
                    &processInfo))
            {
                std::wcerr << Win32ErrorText(L"CreateProcessW OxideHarvest name-only negative child failed") << L"\n";
                break;
            }

            if (processInfo.hThread != nullptr)
            {
                CloseHandle(processInfo.hThread);
                processInfo.hThread = nullptr;
            }

            g_ChildProcesses.push_back(processInfo.hProcess);
            processInfo.hProcess = nullptr;

            std::wcout << L"oxideharvest-name-only-negative child="
                       << childPath
                       << L" pid="
                       << processInfo.dwProcessId
                       << L"\n";
            AddScenario(
                L"oxideharvest-name-only-negative",
                L"benign child process named buildx64.exe without OxideHarvest-style CLI options",
                0,
                0,
                {},
                L"validates that OxideHarvest credential-tool names do not alert without CLI shape or staging context",
                processInfo.dwProcessId,
                {},
                {},
                {
                    L"gentlemen_related_credential_tool_name",
                    L"oxideharvest_cli_shape"
                });
            ok = true;
        } while (false);

        if (processInfo.hThread != nullptr)
        {
            CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            CloseHandle(processInfo.hProcess);
        }

        return ok;
    }

    bool CreateEdrKillerDriverServiceIoc()
    {
        bool ok = false;
        SC_HANDLE scm = nullptr;

        do
        {
            struct DriverServiceFixture
            {
                const wchar_t* FileName;
                const wchar_t* ExpectedLeaf;
                const wchar_t* ScenarioName;
                const wchar_t* Notes;
                const wchar_t* Family;
                const wchar_t* Tool;
                const wchar_t* StrongNameSignal;
            };

            static const DriverServiceFixture kFixtures[] =
            {
                {
                    L"eb.sys",
                    L"eb.sys",
                    L"edr-killer-driver-service-eb",
                    L"validates the GentleKiller Kaspersky custom rootkit driver IOC",
                    L"GentleKiller",
                    L"Kaspersky variant custom rootkit",
                    L"true"
                },
                {
                    L"NSecKrnl.sys",
                    L"nseckrnl.sys",
                    L"edr-killer-driver-service-nseckrnl",
                    L"validates the GentleKiller FACEIT NSecKrnl driver IOC",
                    L"GentleKiller",
                    L"NSecsoft NSecKrnl driver",
                    L"true"
                },
                {
                    L"VGK.sys",
                    L"vgk.sys",
                    L"edr-killer-driver-service-vgk",
                    L"validates the GentleKiller Valorant VGK driver IOC with staging context",
                    L"GentleKiller",
                    L"Tower of Fantasy AntiCheat driver",
                    L"false"
                },
                {
                    L"GameDriverX64.sys",
                    L"gamedriverx64.sys",
                    L"edr-killer-driver-service-gamedriverx64",
                    L"validates the GentleKiller Valorant GameDriverX64 driver IOC with staging context",
                    L"GentleKiller",
                    L"Tower of Fantasy AntiCheat driver",
                    L"false"
                },
                {
                    L"stpm_old.sys",
                    L"stpm_old.sys",
                    L"edr-killer-driver-service-stpm-old",
                    L"validates the GentleKiller Javelin old Safetica Process Monitor driver IOC",
                    L"GentleKiller",
                    L"Safetica Process Monitor driver",
                    L"true"
                },
                {
                    L"stpm_new.sys",
                    L"stpm_new.sys",
                    L"edr-killer-driver-service-stpm-new",
                    L"validates the GentleKiller Javelin Safetica Process Monitor driver IOC",
                    L"GentleKiller",
                    L"Safetica Process Monitor driver",
                    L"true"
                },
                {
                    L"dmx.sys",
                    L"dmx.sys",
                    L"edr-killer-driver-service-dmx",
                    L"validates the GentleKiller WatchDog Zemana driver IOC",
                    L"GentleKiller",
                    L"Zemana WatchDog driver",
                    L"true"
                },
                {
                    L"360NetMon_WFP.sys",
                    L"360netmon_wfp.sys",
                    L"edr-killer-driver-service-360netmon-wfp",
                    L"validates the GentleKiller Network Blocker Qihoo 360 WFP driver IOC with staging context",
                    L"GentleKiller",
                    L"Qihoo 360 network monitor driver",
                    L"false"
                },
                {
                    L"360NetMon.sys",
                    L"360netmon.sys",
                    L"edr-killer-driver-service-360netmon",
                    L"validates the GentleKiller Network Blocker Qihoo 360 driver IOC with staging context",
                    L"GentleKiller",
                    L"Qihoo 360 network monitor driver",
                    L"false"
                },
                {
                    L"IMFForceDelete",
                    L"imfforcedelete",
                    L"edr-killer-driver-service-imfforcedelete",
                    L"validates the GentleKiller Cleaner extensionless IMFForceDelete driver IOC",
                    L"GentleKiller",
                    L"IObit IMF ForceDelete filter driver",
                    L"true"
                },
                {
                    L"PoisonX",
                    L"poisonx",
                    L"edr-killer-driver-service-poisonx",
                    L"validates the GentleKiller G11 PoisonX extensionless rootkit IOC",
                    L"GentleKiller",
                    L"PoisonX rootkit",
                    L"true"
                },
                {
                    L"G11.sys",
                    L"g11.sys",
                    L"edr-killer-driver-service-g11",
                    L"validates the GentleKiller G11 PoisonX rootkit driver leaf",
                    L"GentleKiller",
                    L"PoisonX rootkit",
                    L"true"
                },
                {
                    L"googleApiUtil64.sys",
                    L"googleapiutil64.sys",
                    L"edr-killer-driver-service-googleapiutil64",
                    L"validates the HexKiller Baidu Antivirus BdApi driver IOC",
                    L"HexKiller",
                    L"Baidu Antivirus BdApi driver",
                    L"true"
                },
                {
                    L"ThrottleBlood.sys",
                    L"throttleblood.sys",
                    L"edr-killer-driver-service-throttleblood",
                    L"validates the ThrottleBlood TechPowerUp driver IOC",
                    L"ThrottleBlood",
                    L"ThrottleStop driver",
                    L"true"
                },
                {
                    L"havoc.sys",
                    L"havoc.sys",
                    L"edr-killer-driver-service-havoc",
                    L"validates the HavocKiller Huawei vulnerable driver IOC",
                    L"HavocKiller",
                    L"Huawei vulnerable driver",
                    L"true"
                }
            };

            scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
            if (scm == nullptr)
            {
                DWORD lastError = GetLastError();
                if (lastError == ERROR_ACCESS_DENIED)
                {
                    std::wcout << L"edr-killer-driver-service skipped: administrator rights required\n";
                    ok = true;
                }
                else
                {
                    std::wcerr << Win32ErrorText(L"OpenSCManagerW EDR-killer driver service failed", lastError) << L"\n";
                }
                break;
            }

            bool anyFailure = false;
            for (size_t index = 0; index < _countof(kFixtures); ++index)
            {
                const DriverServiceFixture& fixture = kFixtures[index];
                std::wstring strongNameSignal = fixture.StrongNameSignal != nullptr
                    ? fixture.StrongNameSignal
                    : L"false";
                bool strongName = strongNameSignal == L"true";
                const wchar_t* expectedRisk = strongName ? L"medium" : L"low";
                const wchar_t* expectedConfidence = strongName ? L"high" : L"medium";
                std::wstring driverPath;
                if (!MakeTempSelfCopy(fixture.FileName, &driverPath))
                {
                    anyFailure = true;
                    continue;
                }
                std::wstring serviceBinaryPath = driverPath;
                bool extensionlessDriverName = std::wcschr(fixture.FileName, L'.') == nullptr;
                if (extensionlessDriverName && ((index % 2) == 1))
                {
                    serviceBinaryPath = driverPath + L" /hunt-parser-check-unquoted-extensionless";
                }
                else if ((index % 2) == 0)
                {
                    serviceBinaryPath = L"\"" + driverPath + L"\" /hunt-parser-check";
                }

                std::wstringstream serviceNameStream;
                serviceNameStream << L"KnLiveDbgHuntTargetEdrSvc"
                                  << GetCurrentProcessId()
                                  << L"_"
                                  << index;
                std::wstring serviceName = serviceNameStream.str();
                std::wstring displayName = std::wstring(L"KnLiveDbg Hunt Target ") +
                    fixture.FileName +
                    L" IOC";

                SC_HANDLE service = CreateServiceW(
                    scm,
                    serviceName.c_str(),
                    displayName.c_str(),
                    SERVICE_QUERY_STATUS | DELETE,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_IGNORE,
                    serviceBinaryPath.c_str(),
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr);
                if (service == nullptr)
                {
                    DWORD lastError = GetLastError();
                    if (lastError == ERROR_ACCESS_DENIED)
                    {
                        std::wcout << L"edr-killer-driver-service skipped: administrator rights required\n";
                        ok = true;
                        break;
                    }
                    else
                    {
                        std::wcerr << Win32ErrorText(L"CreateServiceW EDR-killer driver service failed", lastError) << L"\n";
                    }
                    anyFailure = true;
                    continue;
                }

                g_CreatedServices.push_back(serviceName);

                std::wcout << L"edr-killer-driver-service service="
                           << serviceName
                           << L" binary="
                           << serviceBinaryPath
                           << L"\n";
                AddScenario(
                    fixture.ScenarioName,
                    std::wstring(L"non-started kernel-driver service configured with an ESET EDR-killer binary leaf ") + fixture.FileName,
                    0,
                    0,
                    {
                        L"driver_service_installed",
                        L"driver_service_binary_name_ioc",
                        L"gentlemen_edr_killer_driver_service",
                        L"driver_service_not_running",
                        L"gentlemen_collection_staging_path"
                    },
                    fixture.Notes,
                    0,
                    {
                        L"service_name",
                        L"binary_path",
                        L"expanded_binary_path",
                        L"binary_leaf",
                        L"matched_driver_leaf",
                        L"gentlemen_family",
                        L"gentlemen_tool",
                        L"gentlemen_ioc_driver",
                        L"strong_name_signal",
                        L"gentlemen_collection_path"
                    },
                    {
                        { L"binary_leaf", fixture.ExpectedLeaf },
                        { L"matched_driver_leaf", fixture.ExpectedLeaf },
                        { L"gentlemen_family", fixture.Family },
                        { L"gentlemen_tool", fixture.Tool },
                        { L"gentlemen_ioc_driver", fixture.ExpectedLeaf },
                        { L"strong_name_signal", strongNameSignal.c_str() },
                        { L"gentlemen_collection_path", L"true" }
                    },
                    {},
                    true,
                    L"edr_killer_driver_service",
                    expectedRisk,
                    expectedConfidence);
                if (!g_Scenarios.empty())
                {
                    g_Scenarios.back().ExpectedEvidenceValues.emplace_back(L"service_name", serviceName);
                    g_Scenarios.back().ExpectedEvidenceValues.emplace_back(L"binary_path", serviceBinaryPath);
                    g_Scenarios.back().ExpectedEvidenceValues.emplace_back(L"expanded_binary_path", serviceBinaryPath);
                    if (!strongName)
                    {
                        g_Scenarios.back().ExpectedReasons.push_back(L"name_only_requires_hash_or_staging_correlation");
                    }
                }

                CloseServiceHandle(service);
            }

            ok = !anyFailure;
        } while (false);

        if (scm != nullptr)
        {
            CloseServiceHandle(scm);
        }

        return ok;
    }

    bool CreateEdrKillerSuffixNameProcess(const Options& options)
    {
        bool ok = false;

        struct SuffixNameFixture
        {
            const wchar_t* FileName;
            const wchar_t* ScenarioName;
            const wchar_t* Notes;
            const wchar_t* ExpectedSuffixTail;
            const wchar_t* ExpectedSuffixComponents;
            const wchar_t* ExpectedProtectionHint;
            const wchar_t* ExpectedFakeSignature;
            const wchar_t* ExpectedFakeVersion;
        };

        static const SuffixNameFixture kFixtures[] =
        {
            {
                L"Kasps1.exe",
                L"edr-killer-suffix-name-kasps",
                L"copies this test target to a temp GentlemenCollection directory as Kasps1.exe and runs it in baseline child mode",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"KaspLight.exe",
                L"edr-killer-suffix-name-kasp",
                L"validates the Kasp<suffix> alias from the ESET GentleKiller table",
                L"light",
                L"light",
                L"none",
                L"true",
                L"true"
            },
            {
                L"FaceIT1.exe",
                L"edr-killer-suffix-name-faceit",
                L"validates exact FaceIT<suffix> IOC handling without losing suffix evidence",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"Valorant2.exe",
                L"edr-killer-suffix-name-valorant",
                L"validates exact Valorant<suffix> IOC handling without losing suffix evidence",
                L"2",
                L"2",
                L"themida",
                L"true",
                L"true"
            },
            {
                L"EAAntiCheatLight.exe",
                L"edr-killer-suffix-name-eaanticheat",
                L"validates exact EAAntiCheat<suffix> IOC handling",
                L"light",
                L"light",
                L"none",
                L"true",
                L"true"
            },
            {
                L"EASolo1Clear.exe",
                L"edr-killer-suffix-name-easolo",
                L"validates combined EASolo<suffix> tail handling",
                L"1clear",
                L"1;clear",
                L"mixed",
                L"mixed",
                L"mixed"
            },
            {
                L"EASolo2Light.exe",
                L"edr-killer-suffix-name-easolo-2light",
                L"validates combined EASolo<suffix> tail handling with Themida plus Light",
                L"2light",
                L"2;light",
                L"mixed",
                L"mixed",
                L"mixed"
            },
            {
                L"BitD1.exe",
                L"edr-killer-suffix-name-bitd",
                L"validates exact BitD<suffix> IOC handling",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"MB1.exe",
                L"edr-killer-suffix-name-mb",
                L"validates short MB<suffix> matching gated by GentlemenCollection context",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"G111.exe",
                L"edr-killer-suffix-name-g11",
                L"validates digit-ending G11<suffix> matching without stripping base digits",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"SymantecClear.exe",
                L"edr-killer-suffix-name-symantec",
                L"validates weak Symantec<suffix> vendor impersonation gated by staging context",
                L"clear",
                L"clear",
                L"none",
                L"false",
                L"false"
            },
            {
                L"Avast1.exe",
                L"edr-killer-suffix-name-avast",
                L"validates HexKiller Avast<suffix> handling gated by staging context",
                L"1",
                L"1",
                L"enigma",
                L"true",
                L"true"
            },
            {
                L"Sent2.exe",
                L"edr-killer-suffix-name-sent",
                L"validates ThrottleBlood Sent<suffix> handling",
                L"2",
                L"2",
                L"themida",
                L"true",
                L"true"
            },
            {
                L"SophosLight.exe",
                L"edr-killer-suffix-name-sophos",
                L"validates HavocKiller Sophos<suffix> handling gated by staging context",
                L"light",
                L"light",
                L"none",
                L"true",
                L"true"
            }
        };

        do
        {
            bool anyFailure = false;
            for (const SuffixNameFixture& fixture : kFixtures)
            {
                if (!CreateEdrKillerSuffixNameChild(
                        options,
                        fixture.FileName,
                        fixture.ScenarioName,
                        fixture.Notes,
                        fixture.ExpectedSuffixTail,
                        fixture.ExpectedSuffixComponents,
                        fixture.ExpectedProtectionHint,
                        fixture.ExpectedFakeSignature,
                        fixture.ExpectedFakeVersion))
                {
                    anyFailure = true;
                }
            }

            if (!CreateWeakVendorStandaloneNegativeChild(options))
            {
                anyFailure = true;
            }
            if (!CreateGentlemenStagingOnlyNegativeChild(options))
            {
                anyFailure = true;
            }
            if (!CreateEdrKillerExactNameChild(
                    options,
                    L"Deletor.exe",
                    L"edr-killer-exact-name-deletor",
                    L"validates the GentleKiller Cleaner exact Deletor.exe IOC"))
            {
                anyFailure = true;
            }
            if (!CreateEdrKillerExactNameChild(
                    options,
                    L"HwAudKiller.exe",
                    L"edr-killer-exact-name-hwaudkiller",
                    L"validates the HavocKiller exact HwAudKiller.exe IOC"))
            {
                anyFailure = true;
            }

            ok = !anyFailure;
        } while (false);

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
        if (options.EdrKillerSuffixName)
        {
            std::wcout << L"  gentlemen_edr_killer_process_name, gentlemen_suffix_normalized_process_name, "
                       << L"gentlemen_collection_staging_path, edr_killer_version_info_impersonation_evidence, "
                       << L"edr_killer_packer_section_evidence\n";
            std::wcout << L"  negative: GentlemenCollection path-only process has no EDR-killer process-profile reason\n";
        }
        if (options.OxideHarvestCli)
        {
            std::wcout << L"  gentlemen_related_credential_tool_name, oxideharvest_cli_shape\n";
        }
        if (options.EdrKillerDriverService)
        {
            std::wcout << L"  driver_service_installed, driver_service_binary_name_ioc, "
                       << L"gentlemen_edr_killer_driver_service, gentlemen_collection_staging_path\n";
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
            if (options.EdrKillerSuffixName && !CreateEdrKillerSuffixNameProcess(options))
            {
                anyFailure = true;
            }
            if (options.OxideHarvestCli && !CreateOxideHarvestCliProcess(options))
            {
                anyFailure = true;
            }
            if (options.OxideHarvestCli && !CreateOxideHarvestNameOnlyNegativeProcess(options))
            {
                anyFailure = true;
            }
            if (options.EdrKillerDriverService && !CreateEdrKillerDriverServiceIoc())
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
            DWORD displayPid = scenario.HasProcessId
                ? scenario.ProcessId
                : GetCurrentProcessId();
            std::wcout << L"  " << scenario.Name
                       << L" artifact=\"" << scenario.Artifact << L"\""
                       << L" pid=" << displayPid
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
    HANDLE externalStopEvent = nullptr;

    do
    {
        TouchPackerSectionMarker();

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
        if (options.Interactive)
        {
            bool canceled = false;
            if (!PromptScenarioMenuSelection(&options, &canceled))
            {
                break;
            }
            if (canceled)
            {
                exitCode = 0;
                break;
            }
        }

        g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_StopEvent == nullptr)
        {
            std::wcerr << Win32ErrorText(L"CreateEventW failed") << L"\n";
            break;
        }

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        if (!options.StopEventName.empty())
        {
            externalStopEvent = CreateEventW(
                nullptr,
                TRUE,
                FALSE,
                options.StopEventName.c_str());
            if (externalStopEvent == nullptr)
            {
                std::wcerr << Win32ErrorText(L"CreateEventW stop-event failed") << L"\n";
                break;
            }
        }

        std::wcout << L"KnLiveDbgHuntTarget pid=" << GetCurrentProcessId() << L"\n";
        std::wcout << L"run_seconds=" << options.RunSeconds << L"\n";
        if (!options.StopEventName.empty())
        {
            std::wcout << L"stop_event=" << options.StopEventName << L"\n";
        }
        if (options.ChildWaitParentPid != 0)
        {
            std::wcout << L"child_wait_parent=" << options.ChildWaitParentPid << L"\n";
            if (!WaitAsChildProcess(options))
            {
                break;
            }
            exitCode = 0;
            break;
        }

        PrintExpectedFindings(options);

        if (!CreateScenarios(options))
        {
            std::wcerr << L"one or more scenarios failed to initialize\n";
            break;
        }

        PrintScenarioSummary();

        if (!options.ManifestPath.empty())
        {
            std::wstring manifestError;
            if (WriteManifestFile(options.ManifestPath, BuildManifestJson(options), &manifestError))
            {
                std::wcout << L"manifest written: " << options.ManifestPath << L"\n";
            }
            else
            {
                std::wcerr << L"manifest write failed: " << options.ManifestPath;
                if (!manifestError.empty())
                {
                    std::wcerr << L" (" << manifestError << L")";
                }
                std::wcerr << L"\n";
                break;
            }
        }

        std::wcout << L"target is ready\n";
        std::wcout << L"run: !hunt /deep /summary /json .\\hunt-target.json\n";
        std::wcout << L"press Ctrl+C to stop this target\n";

        DWORD waitMs = INFINITE;
        if (options.RunSeconds != 0 && options.RunSeconds <= 0xffffffffu / 1000u)
        {
            waitMs = options.RunSeconds * 1000u;
        }
        HANDLE waitHandles[2] =
        {
            g_StopEvent,
            externalStopEvent
        };
        DWORD waitCount = externalStopEvent != nullptr ? 2u : 1u;
        WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs);
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

    for (HANDLE process : g_ChildProcesses)
    {
        if (process == nullptr)
        {
            continue;
        }

        if (WaitForSingleObject(process, 1500) == WAIT_TIMEOUT)
        {
            TerminateProcess(process, 0);
            WaitForSingleObject(process, 1500);
        }
        CloseHandle(process);
    }
    g_ChildProcesses.clear();

    DeleteCreatedDriverServices();

    for (const std::wstring& path : g_TempFiles)
    {
        DeleteFileW(path.c_str());
    }
    g_TempFiles.clear();

    for (const std::wstring& directory : g_TempDirectories)
    {
        RemoveDirectoryW(directory.c_str());
    }
    g_TempDirectories.clear();

    if (g_StopEvent != nullptr)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
    }
    if (externalStopEvent != nullptr)
    {
        CloseHandle(externalStopEvent);
        externalStopEvent = nullptr;
    }

    return exitCode;
}
