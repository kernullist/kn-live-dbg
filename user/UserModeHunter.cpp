#include "UserModeHunter.h"

#include "ByovdScanner.h"
#include "IntegrityScanner.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <WinTrust.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>

namespace
{
    constexpr uint32_t kSystemProcessInformation = 5;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xc0000004);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xc0000023);
    constexpr uint64_t kPageSize = 0x1000ull;
    constexpr uint64_t kLargePrivateExecThreshold = 64ull * 1024ull * 1024ull;
    constexpr uint32_t kMaxWeakPrivateExecFindingsPerProcess = 8;
    constexpr size_t kMaxPebStringBytes = 32768;
    constexpr size_t kMaxLdrModules = 1024;
    constexpr uint32_t kHuntHiddenPteRecordLimitPerProcess = 64;
    constexpr size_t kMaxDeepModuleComparisonsPerProcess = 96;
    constexpr size_t kMaxDeepPagesPerProcess = 512;
    constexpr size_t kMaxSampledExecPagesPerSection = 2;
    constexpr size_t kMaxStackReferenceFindingsPerProcess = 16;
    constexpr size_t kMaxDeepStackPointerSamplesPerProcess = 32768;
    constexpr uint64_t kMaxThreadStackScanBytes = 64ull * 1024ull;
    constexpr size_t kMaxBuiltinModuleProvenanceFindingsPerProcess = 8;
    constexpr size_t kMaxByovdMatchEvidence = 6;
    constexpr size_t kMaxDriverDispatchEvidence = 8;
    constexpr size_t kMaxTelemetryPayloadEvidence = 8;
    constexpr uint64_t kKernelAddressMin = 0xffff800000000000ull;

    struct HuntLocalUnicodeString
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct HuntSystemProcessInformation
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        HuntLocalUnicodeString ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
    };

    struct DeepStackPointerSample
    {
        uint64_t ThreadId = 0;
        uint64_t StackAddress = 0;
        uint64_t Value = 0;
    };

    struct DeepAddressRange
    {
        uint64_t Start = 0;
        uint64_t End = 0;
    };

    struct DeepStackReferenceCache
    {
        bool Built = false;
        bool LimitReached = false;
        std::vector<DeepStackPointerSample> Samples;
    };

    typedef LONG (NTAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

    struct ApiProcessRecord
    {
        uint32_t ProcessId = 0;
        uint32_t ParentProcessId = 0;
        bool HasParentProcessId = false;
        std::wstring ImageName;
    };

    struct DiskPeSection
    {
        std::wstring Name;
        uint32_t VirtualAddress = 0;
        uint32_t VirtualSize = 0;
        uint32_t PointerToRawData = 0;
        uint32_t SizeOfRawData = 0;
        uint32_t Characteristics = 0;
        bool Executable = false;
        bool Writable = false;
    };

    struct DiskPeMetadata
    {
        uint64_t ImageBase = 0;
        uint32_t EntryPointRva = 0;
        uint32_t FirstExecutableSectionRva = 0;
        uint32_t SizeOfHeaders = 0;
        uint32_t SizeOfImage = 0;
        bool HasEntryPoint = false;
        bool HasExecutableSection = false;
        std::vector<DiskPeSection> Sections;
        std::set<uint32_t> RelocationPages;
        std::set<uint32_t> LoaderMutablePages;
    };

    struct BuiltinProcessProfile
    {
        const wchar_t* ImageName;
        bool System32;
        bool SysWow64;
        bool WindowsRoot;
        bool SessionZeroOnly;
        const wchar_t* const* ParentNames;
        size_t ParentNameCount;
        bool SvchostCommandLine;
    };

    struct EdrKillerProcessProfile
    {
        const wchar_t* ImageName;
        const wchar_t* SuffixBase;
        const wchar_t* Family;
        const wchar_t* Tool;
        bool StrongNameSignal;
        bool CredentialTool;
        bool SuffixContextRequired;
    };

    struct EdrKillerDriverProfile
    {
        const wchar_t* ImageName;
        const wchar_t* Family;
        const wchar_t* Tool;
        bool StrongNameSignal;
    };

    struct DriverServiceRecord
    {
        std::wstring ServiceName;
        std::wstring DisplayName;
        std::wstring BinaryPath;
        std::wstring ExpandedBinaryPath;
        std::wstring BinaryLeaf;
        std::wstring StateText;
        std::wstring StartTypeText;
        DWORD ServiceType = 0;
        DWORD CurrentState = 0;
        DWORD StartType = 0;
        bool HasConfig = false;
        bool Running = false;
    };

    struct VersionTranslation
    {
        WORD Language;
        WORD CodePage;
    };

    struct ImageMetadataRecord
    {
        bool VersionInfoPresent = false;
        bool SignatureChecked = false;
        bool SignaturePresent = false;
        bool SignatureValid = false;
        bool IconResourcePresent = false;
        bool PeMetadataRead = false;
        LONG SignatureStatus = 0;
        uint32_t PeSectionCount = 0;
        std::wstring FilePath;
        std::wstring FileVersion;
        std::wstring CompanyName;
        std::wstring ProductName;
        std::wstring OriginalFilename;
        std::wstring FileDescription;
        std::wstring ExecutableSectionNames;
        std::wstring PackerSectionHint;
        std::wstring PackerSectionNames;
    };

    struct ThreatIntelCorrelationBucket
    {
        uint32_t ProcessId = 0;
        uint64_t Eprocess = 0;
        std::wstring ImageName;
        std::wstring ImagePath;
        std::wstring MatchedLeaf;
        const EdrKillerProcessProfile* Profile = nullptr;
        bool GentlemenStagingPath = false;
        bool SuffixNormalizedProfile = false;
        bool SuffixContextRequired = false;
        std::wstring NormalizedProfileBase;
        std::wstring SuffixTail;
        uint64_t DriverIoCount = 0;
        uint64_t ProcessImpairmentCount = 0;
        uint64_t SecurityProductImpairmentCount = 0;
        std::set<uint32_t> TargetProcessIds;
        std::set<std::wstring> SecurityProductTargetNames;
        HuntTelemetryEvent FirstDriverIoEvent;
        HuntTelemetryEvent FirstProcessImpairmentEvent;
        HuntTelemetryEvent FirstSecurityProductImpairmentEvent;
    };

    struct SectionBackingLayout
    {
        TypeFieldInfo SubsectionControlArea = {};
        TypeFieldInfo ControlAreaFilePointer = {};
        TypeFieldInfo ControlAreaImageFlag = {};
        TypeFieldInfo FileObjectFileName = {};
        bool HasSubsectionControlArea = false;
        bool HasControlAreaFilePointer = false;
        bool HasControlAreaImageFlag = false;
        bool HasFileObjectFileName = false;
        bool Resolved = false;
        std::vector<std::wstring> Warnings;
    };

    std::wstring HuntHex(uint64_t value, uint32_t width = 0)
    {
        std::wstringstream stream;
        stream << L"0x";
        if (width != 0)
        {
            stream << std::setw(static_cast<int>(width)) << std::setfill(L'0');
        }
        stream << std::hex << std::nouppercase << value;
        return stream.str();
    }

    std::wstring HuntJsonEscape(const std::wstring& value)
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

    std::wstring HuntToLower(const std::wstring& value)
    {
        std::wstring lowered = value;
        std::transform(
            lowered.begin(),
            lowered.end(),
            lowered.begin(),
            [](wchar_t ch)
            {
                return static_cast<wchar_t>(std::towlower(ch));
            });
        return lowered;
    }

    std::wstring NormalizePathText(const std::wstring& value)
    {
        std::wstring normalized = HuntToLower(value);
        std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
        return normalized;
    }

    std::wstring LeafName(const std::wstring& value)
    {
        std::wstring normalized = NormalizePathText(value);
        size_t slash = normalized.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < normalized.size())
        {
            return normalized.substr(slash + 1);
        }

        return normalized;
    }

    bool SameNonEmptyLeaf(const std::wstring& left, const std::wstring& right)
    {
        bool same = false;

        do
        {
            std::wstring leftLeaf = LeafName(left);
            std::wstring rightLeaf = LeafName(right);
            if (leftLeaf.empty() || rightLeaf.empty())
            {
                break;
            }

            same = leftLeaf == rightLeaf;
        } while (false);

        return same;
    }

    bool LeafHasAnySuffix(const std::wstring& path, const std::vector<std::wstring>& suffixes)
    {
        bool matched = false;

        do
        {
            std::wstring leaf = LeafName(path);
            if (leaf.empty())
            {
                break;
            }

            for (const std::wstring& suffix : suffixes)
            {
                if (leaf.size() >= suffix.size() &&
                    leaf.compare(leaf.size() - suffix.size(), suffix.size(), suffix) == 0)
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool LooksLikePeImagePath(const std::wstring& path)
    {
        return LeafHasAnySuffix(path, {L".exe", L".dll", L".sys", L".ocx", L".cpl", L".scr"});
    }

    bool EndsWithText(const std::wstring& value, const std::wstring& suffix)
    {
        bool matched = false;

        do
        {
            if (value.size() < suffix.size())
            {
                break;
            }

            matched = value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
        } while (false);

        return matched;
    }

    std::wstring StemWithoutExeExtension(const std::wstring& leaf)
    {
        std::wstring stem = HuntToLower(leaf);

        if (EndsWithText(stem, L".exe"))
        {
            stem.resize(stem.size() - 4);
        }

        return stem;
    }

    bool GentlemenSuffixTailIsValid(const std::wstring& tail)
    {
        bool valid = false;

        do
        {
            if (tail.empty())
            {
                break;
            }

            size_t offset = 0;
            while (offset < tail.size())
            {
                std::wstring remaining = tail.substr(offset);
                if (remaining.rfind(L"light", 0) == 0)
                {
                    offset += 5;
                }
                else if (remaining.rfind(L"clear", 0) == 0)
                {
                    offset += 5;
                }
                else if (tail[offset] == L'1' || tail[offset] == L'2')
                {
                    ++offset;
                }
                else
                {
                    break;
                }
            }

            valid = offset == tail.size();
        } while (false);

        return valid;
    }

    bool GentlemenSuffixPatternMatches(
        const std::wstring& leaf,
        const wchar_t* suffixBase,
        std::wstring* normalizedBase,
        std::wstring* suffixTail)
    {
        bool matched = false;

        do
        {
            if (suffixBase == nullptr || suffixBase[0] == L'\0')
            {
                break;
            }

            std::wstring stem = StemWithoutExeExtension(leaf);
            std::wstring base = HuntToLower(suffixBase);
            if (stem.size() <= base.size())
            {
                break;
            }

            if (stem.compare(0, base.size(), base) != 0)
            {
                break;
            }

            std::wstring tail = stem.substr(base.size());
            if (!GentlemenSuffixTailIsValid(tail))
            {
                break;
            }

            if (normalizedBase != nullptr)
            {
                *normalizedBase = base;
            }
            if (suffixTail != nullptr)
            {
                *suffixTail = tail;
            }
            matched = true;
        } while (false);

        return matched;
    }

    void AddGentlemenSuffixEvidence(
        const std::wstring& suffixTail,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (evidence == nullptr || suffixTail.empty())
            {
                break;
            }

            std::vector<std::wstring> components;
            bool hasEnigma = false;
            bool hasThemida = false;
            bool hasLight = false;
            bool hasClear = false;
            size_t offset = 0;
            while (offset < suffixTail.size())
            {
                std::wstring remaining = suffixTail.substr(offset);
                if (remaining.rfind(L"light", 0) == 0)
                {
                    components.push_back(L"light");
                    hasLight = true;
                    offset += 5;
                }
                else if (remaining.rfind(L"clear", 0) == 0)
                {
                    components.push_back(L"clear");
                    hasClear = true;
                    offset += 5;
                }
                else if (suffixTail[offset] == L'1')
                {
                    components.push_back(L"1");
                    hasEnigma = true;
                    ++offset;
                }
                else if (suffixTail[offset] == L'2')
                {
                    components.push_back(L"2");
                    hasThemida = true;
                    ++offset;
                }
                else
                {
                    break;
                }
            }

            std::wstring componentsText;
            for (size_t index = 0; index < components.size(); ++index)
            {
                if (index != 0)
                {
                    componentsText += L";";
                }
                componentsText += components[index];
            }

            (*evidence)[L"gentlemen_suffix_tail"] = suffixTail;
            (*evidence)[L"gentlemen_suffix_components"] = componentsText;
            uint32_t protectionClasses = 0;
            if (hasEnigma)
            {
                ++protectionClasses;
            }
            if (hasThemida)
            {
                ++protectionClasses;
            }
            if (hasLight || hasClear)
            {
                ++protectionClasses;
            }

            if (protectionClasses > 1)
            {
                (*evidence)[L"gentlemen_suffix_protection_hint"] = L"mixed";
            }
            else if (hasThemida)
            {
                (*evidence)[L"gentlemen_suffix_protection_hint"] = L"themida";
            }
            else if (hasEnigma)
            {
                (*evidence)[L"gentlemen_suffix_protection_hint"] = L"enigma";
            }
            else if (hasLight || hasClear)
            {
                (*evidence)[L"gentlemen_suffix_protection_hint"] = L"none";
            }
            else
            {
                (*evidence)[L"gentlemen_suffix_protection_hint"] = L"unknown";
            }

            if (hasClear && (hasEnigma || hasThemida || hasLight))
            {
                (*evidence)[L"gentlemen_suffix_fake_signature_expected"] = L"mixed";
                (*evidence)[L"gentlemen_suffix_fake_version_expected"] = L"mixed";
            }
            else if (hasClear)
            {
                (*evidence)[L"gentlemen_suffix_fake_signature_expected"] = L"false";
                (*evidence)[L"gentlemen_suffix_fake_version_expected"] = L"false";
            }
            else if (hasEnigma || hasThemida || hasLight)
            {
                (*evidence)[L"gentlemen_suffix_fake_signature_expected"] = L"true";
                (*evidence)[L"gentlemen_suffix_fake_version_expected"] = L"true";
            }
            else
            {
                (*evidence)[L"gentlemen_suffix_fake_signature_expected"] = L"unknown";
                (*evidence)[L"gentlemen_suffix_fake_version_expected"] = L"unknown";
            }
        } while (false);
    }

    const EdrKillerProcessProfile* FindEdrKillerProcessProfileByLeaf(
        const std::wstring& leaf,
        bool* suffixNormalized = nullptr,
        std::wstring* normalizedBase = nullptr,
        bool* suffixContextRequired = nullptr,
        std::wstring* suffixTail = nullptr)
    {
        const EdrKillerProcessProfile* profile = nullptr;

        static const EdrKillerProcessProfile kProfiles[] =
        {
            { L"kasps.exe", L"kasps", L"GentleKiller", L"Kaspersky variant", true, false, false },
            { L"kasp1.exe", L"kasp", L"GentleKiller", L"Kaspersky variant", true, false, false },
            { L"faceit1.exe", L"faceit", L"GentleKiller", L"FACEIT Anti-Cheat variant", true, false, false },
            { L"valorant2.exe", L"valorant", L"GentleKiller", L"Valorant variant", true, false, false },
            { L"easolo2light.exe", L"easolo", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"easolo1clear.exe", L"easolo", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"eaanticheatlight.exe", L"eaanticheat", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"bitd1.exe", L"bitd", L"GentleKiller", L"WatchDog variant", true, false, false },
            { L"mb2.exe", L"mb", L"GentleKiller", L"Network Blocker variant", true, false, true },
            { L"deletor.exe", nullptr, L"GentleKiller", L"Cleaner variant", true, false, false },
            { L"g11.exe", L"g11", L"GentleKiller", L"G11 variant", true, false, true },
            { L"symantec.exe", L"symantec", L"GentleKiller", L"G11 variant", false, false, false },
            { L"avast.exe", L"avast", L"HexKiller", L"HexKiller with Gentlemen evasion layer", false, false, false },
            { L"sent.exe", L"sent", L"ThrottleBlood", L"ThrottleBlood with Gentlemen evasion layer", true, false, false },
            { L"sophos.exe", L"sophos", L"HavocKiller", L"HavocKiller with Gentlemen evasion layer", false, false, false },
            { L"hwaudkiller.exe", L"hwaudkiller", L"HavocKiller", L"HavocKiller", true, false, false },
            { L"buildx641.exe", nullptr, L"OxideHarvest", L"credential stealer", true, true, false },
            { L"buildx64.exe", nullptr, L"OxideHarvest", L"credential stealer", true, true, false }
        };

        do
        {
            if (leaf.empty())
            {
                break;
            }

            if (suffixNormalized != nullptr)
            {
                *suffixNormalized = false;
            }
            if (normalizedBase != nullptr)
            {
                normalizedBase->clear();
            }
            if (suffixContextRequired != nullptr)
            {
                *suffixContextRequired = false;
            }
            if (suffixTail != nullptr)
            {
                suffixTail->clear();
            }

            for (const EdrKillerProcessProfile& item : kProfiles)
            {
                if (leaf == item.ImageName)
                {
                    profile = &item;
                    std::wstring candidateBase;
                    std::wstring candidateTail;
                    if (GentlemenSuffixPatternMatches(leaf, item.SuffixBase, &candidateBase, &candidateTail))
                    {
                        if (suffixNormalized != nullptr)
                        {
                            *suffixNormalized = true;
                        }
                        if (normalizedBase != nullptr)
                        {
                            *normalizedBase = candidateBase;
                        }
                        if (suffixContextRequired != nullptr)
                        {
                            *suffixContextRequired = item.SuffixContextRequired;
                        }
                        if (suffixTail != nullptr)
                        {
                            *suffixTail = candidateTail;
                        }
                    }
                    break;
                }
            }

            if (profile != nullptr)
            {
                break;
            }

            for (const EdrKillerProcessProfile& item : kProfiles)
            {
                if (item.CredentialTool)
                {
                    continue;
                }

                std::wstring candidateBase;
                std::wstring candidateTail;
                if (GentlemenSuffixPatternMatches(leaf, item.SuffixBase, &candidateBase, &candidateTail))
                {
                    profile = &item;
                    if (suffixNormalized != nullptr)
                    {
                        *suffixNormalized = true;
                    }
                    if (normalizedBase != nullptr)
                    {
                        *normalizedBase = candidateBase;
                    }
                    if (suffixContextRequired != nullptr)
                    {
                        *suffixContextRequired = item.SuffixContextRequired;
                    }
                    if (suffixTail != nullptr)
                    {
                        *suffixTail = candidateTail;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    const EdrKillerDriverProfile* FindEdrKillerDriverProfileByLeaf(const std::wstring& leaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        static const EdrKillerDriverProfile kProfiles[] =
        {
            { L"eb.sys", L"GentleKiller", L"Kaspersky variant custom rootkit", true },
            { L"nseckrnl.sys", L"GentleKiller", L"NSecsoft NSecKrnl driver", true },
            { L"vgk.sys", L"GentleKiller", L"Tower of Fantasy AntiCheat driver", false },
            { L"gamedriverx64.sys", L"GentleKiller", L"Tower of Fantasy AntiCheat driver", false },
            { L"stpm_old.sys", L"GentleKiller", L"Safetica Process Monitor driver", true },
            { L"stpm_new.sys", L"GentleKiller", L"Safetica Process Monitor driver", true },
            { L"dmx.sys", L"GentleKiller", L"Zemana WatchDog driver", true },
            { L"360netmon_wfp.sys", L"GentleKiller", L"Qihoo 360 network monitor driver", false },
            { L"360netmon.sys", L"GentleKiller", L"Qihoo 360 network monitor driver", false },
            { L"imfforcedelete", L"GentleKiller", L"IObit IMF ForceDelete filter driver", true },
            { L"g11.sys", L"GentleKiller", L"PoisonX rootkit", true },
            { L"googleapiutil64.sys", L"HexKiller", L"Baidu Antivirus BdApi driver", true },
            { L"throttleblood.sys", L"ThrottleBlood", L"ThrottleStop driver", true },
            { L"havoc.sys", L"HavocKiller", L"Huawei vulnerable driver", true }
        };

        do
        {
            if (leaf.empty())
            {
                break;
            }

            for (const EdrKillerDriverProfile& item : kProfiles)
            {
                if (leaf == item.ImageName)
                {
                    profile = &item;
                    break;
                }
            }
        } while (false);

        return profile;
    }

    bool PathContainsGentlemenCollection(const std::wstring& path)
    {
        return NormalizePathText(path).find(L"gentlemencollection") != std::wstring::npos;
    }

    std::wstring FirstCommandLineImage(const std::wstring& commandLine);

    const EdrKillerProcessProfile* FindEdrKillerProcessProfileForProcess(
        const HuntProcessRecord& process,
        std::wstring* matchedLeaf,
        bool* suffixNormalized = nullptr,
        std::wstring* normalizedBase = nullptr,
        bool* suffixContextRequired = nullptr,
        std::wstring* suffixTail = nullptr)
    {
        const EdrKillerProcessProfile* profile = nullptr;

        do
        {
            if (suffixNormalized != nullptr)
            {
                *suffixNormalized = false;
            }
            if (normalizedBase != nullptr)
            {
                normalizedBase->clear();
            }
            if (suffixContextRequired != nullptr)
            {
                *suffixContextRequired = false;
            }
            if (suffixTail != nullptr)
            {
                suffixTail->clear();
            }

            std::vector<std::wstring> candidates =
            {
                process.KernelImageName,
                process.ToolhelpImageName,
                process.SystemProcessImageName,
                process.ApiImagePath,
                process.PebImagePath,
                FirstCommandLineImage(process.PebCommandLine)
            };

            for (const std::wstring& candidate : candidates)
            {
                std::wstring leaf = LeafName(candidate);
                if (leaf.empty())
                {
                    continue;
                }

                bool localSuffixNormalized = false;
                std::wstring localNormalizedBase;
                bool localSuffixContextRequired = false;
                std::wstring localSuffixTail;
                profile = FindEdrKillerProcessProfileByLeaf(
                    leaf,
                    &localSuffixNormalized,
                    &localNormalizedBase,
                    &localSuffixContextRequired,
                    &localSuffixTail);
                if (profile != nullptr)
                {
                    if (matchedLeaf != nullptr)
                    {
                        *matchedLeaf = leaf;
                    }
                    if (suffixNormalized != nullptr)
                    {
                        *suffixNormalized = localSuffixNormalized;
                    }
                    if (normalizedBase != nullptr)
                    {
                        *normalizedBase = localNormalizedBase;
                    }
                    if (suffixContextRequired != nullptr)
                    {
                        *suffixContextRequired = localSuffixContextRequired;
                    }
                    if (suffixTail != nullptr)
                    {
                        *suffixTail = localSuffixTail;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    std::wstring FirstCommandLineImage(const std::wstring& commandLine)
    {
        std::wstring image;

        do
        {
            size_t begin = commandLine.find_first_not_of(L" \t\r\n");
            if (begin == std::wstring::npos)
            {
                break;
            }

            if (commandLine[begin] == L'"')
            {
                size_t end = commandLine.find(L'"', begin + 1);
                if (end != std::wstring::npos)
                {
                    image = commandLine.substr(begin + 1, end - begin - 1);
                }
                else
                {
                    image = commandLine.substr(begin + 1);
                }
                break;
            }

            size_t end = commandLine.find_first_of(L" \t\r\n", begin);
            if (end == std::wstring::npos)
            {
                image = commandLine.substr(begin);
            }
            else
            {
                image = commandLine.substr(begin, end - begin);
            }
        } while (false);

        return image;
    }

    std::vector<std::wstring> SplitCommandLineForHuntShape(const std::wstring& commandLine)
    {
        std::vector<std::wstring> arguments;

        do
        {
            if (commandLine.empty())
            {
                break;
            }

            std::wstring current;
            bool inQuotes = false;
            for (wchar_t ch : commandLine)
            {
                if (ch == L'"')
                {
                    inQuotes = !inQuotes;
                    continue;
                }

                if (!inQuotes && std::iswspace(ch) != 0)
                {
                    if (!current.empty())
                    {
                        arguments.push_back(current);
                        current.clear();
                    }
                    continue;
                }

                current.push_back(ch);
            }

            if (!current.empty())
            {
                arguments.push_back(current);
            }
        } while (false);

        return arguments;
    }

    bool OxideHarvestOptionTokenIsKnown(
        const std::wstring& argument,
        const wchar_t* const* options,
        size_t optionCount)
    {
        bool known = false;

        do
        {
            std::wstring lowered = HuntToLower(argument);
            for (size_t index = 0; index < optionCount; ++index)
            {
                if (options[index] == nullptr)
                {
                    continue;
                }

                std::wstring option = options[index];
                if (lowered == option ||
                    lowered.rfind(option + L"=", 0) == 0 ||
                    lowered.rfind(option + L":", 0) == 0)
                {
                    known = true;
                    break;
                }
            }
        } while (false);

        return known;
    }

    bool OxideHarvestOptionHasValue(
        const std::vector<std::wstring>& arguments,
        const std::wstring& option,
        const wchar_t* const* options,
        size_t optionCount)
    {
        bool matched = false;

        do
        {
            if (arguments.empty() || option.empty())
            {
                break;
            }

            std::wstring equalsPrefix = option + L"=";
            std::wstring colonPrefix = option + L":";
            for (size_t index = 0; index < arguments.size(); ++index)
            {
                std::wstring argument = HuntToLower(arguments[index]);
                if (argument == option)
                {
                    if (index + 1 >= arguments.size())
                    {
                        continue;
                    }

                    const std::wstring& value = arguments[index + 1];
                    if (!value.empty() &&
                        !OxideHarvestOptionTokenIsKnown(value, options, optionCount))
                    {
                        matched = true;
                        break;
                    }
                }
                else if (argument.rfind(equalsPrefix, 0) == 0 &&
                    argument.size() > equalsPrefix.size())
                {
                    matched = true;
                    break;
                }
                else if (argument.rfind(colonPrefix, 0) == 0 &&
                    argument.size() > colonPrefix.size())
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool OxideHarvestCommandLineShape(
        const std::wstring& commandLine,
        std::wstring* matchedOptions)
    {
        bool matched = false;

        static const wchar_t* kOptions[] =
        {
            L"-i",
            L"-u",
            L"-p",
            L"-t",
            L"-o"
        };

        do
        {
            std::vector<std::wstring> arguments = SplitCommandLineForHuntShape(commandLine);
            std::vector<std::wstring> values;
            for (const wchar_t* option : kOptions)
            {
                if (option == nullptr)
                {
                    continue;
                }

                if (OxideHarvestOptionHasValue(arguments, option, kOptions, _countof(kOptions)))
                {
                    values.push_back(option);
                }
            }

            if (matchedOptions != nullptr)
            {
                std::wstring text;
                for (size_t index = 0; index < values.size(); ++index)
                {
                    if (index != 0)
                    {
                        text += L";";
                    }
                    text += values[index];
                }
                *matchedOptions = text;
            }

            matched = values.size() == _countof(kOptions);
        } while (false);

        return matched;
    }

    std::wstring ExpandEnvironmentText(const std::wstring& value)
    {
        std::wstring expanded = value;

        do
        {
            if (value.empty())
            {
                break;
            }

            DWORD required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
            if (required == 0)
            {
                break;
            }

            std::vector<wchar_t> buffer(required + 1);
            DWORD written = ExpandEnvironmentStringsW(value.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
            if (written == 0 || written > buffer.size())
            {
                break;
            }

            expanded.assign(buffer.data());
        } while (false);

        return expanded;
    }

    std::wstring DriverServiceStateText(DWORD state)
    {
        std::wstring text = L"unknown";

        if (state == SERVICE_STOPPED)
        {
            text = L"stopped";
        }
        else if (state == SERVICE_START_PENDING)
        {
            text = L"start_pending";
        }
        else if (state == SERVICE_STOP_PENDING)
        {
            text = L"stop_pending";
        }
        else if (state == SERVICE_RUNNING)
        {
            text = L"running";
        }
        else if (state == SERVICE_CONTINUE_PENDING)
        {
            text = L"continue_pending";
        }
        else if (state == SERVICE_PAUSE_PENDING)
        {
            text = L"pause_pending";
        }
        else if (state == SERVICE_PAUSED)
        {
            text = L"paused";
        }

        return text;
    }

    std::wstring DriverServiceStartTypeText(DWORD startType)
    {
        std::wstring text = L"unknown";

        if (startType == SERVICE_BOOT_START)
        {
            text = L"boot";
        }
        else if (startType == SERVICE_SYSTEM_START)
        {
            text = L"system";
        }
        else if (startType == SERVICE_AUTO_START)
        {
            text = L"auto";
        }
        else if (startType == SERVICE_DEMAND_START)
        {
            text = L"demand";
        }
        else if (startType == SERVICE_DISABLED)
        {
            text = L"disabled";
        }

        return text;
    }

    std::wstring Win32FilePathFromMaybeNtPath(const std::wstring& path);
    std::wstring DosPathFromDevicePath(const std::wstring& path);

    std::wstring TrimServiceImagePathToken(std::wstring value)
    {
        do
        {
            size_t begin = value.find_first_not_of(L" \t\r\n");
            if (begin == std::wstring::npos)
            {
                value.clear();
                break;
            }

            size_t end = value.find_last_not_of(L" \t\r\n");
            value = value.substr(begin, end - begin + 1);

            if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
            {
                value = value.substr(1, value.size() - 2);
            }
        } while (false);

        return value;
    }

    std::wstring DriverServiceBinaryImagePath(const std::wstring& binaryPath)
    {
        std::wstring path;

        do
        {
            std::wstring trimmed = TrimServiceImagePathToken(binaryPath);
            if (trimmed.empty())
            {
                break;
            }

            std::wstring lowered = HuntToLower(trimmed);
            size_t sys = lowered.find(L".sys");
            if (sys != std::wstring::npos)
            {
                path = TrimServiceImagePathToken(trimmed.substr(0, sys + 4));
                break;
            }

            path = FirstCommandLineImage(trimmed);
            if (path.empty())
            {
                path = trimmed;
            }
        } while (false);

        return path;
    }

    std::wstring DriverServiceBinaryLeaf(const std::wstring& binaryPath)
    {
        std::wstring leaf;

        do
        {
            std::wstring path = DriverServiceBinaryImagePath(binaryPath);
            if (path.empty())
            {
                path = binaryPath;
            }

            path = ExpandEnvironmentText(path);
            path = Win32FilePathFromMaybeNtPath(path);
            path = DosPathFromDevicePath(path);
            leaf = LeafName(path);
        } while (false);

        return leaf;
    }

    bool QueryDriverServiceConfig(SC_HANDLE service, DriverServiceRecord* record)
    {
        bool ok = false;

        do
        {
            if (service == nullptr || record == nullptr)
            {
                break;
            }

            DWORD required = 0;
            QueryServiceConfigW(service, nullptr, 0, &required);
            DWORD error = GetLastError();
            if (required == 0 || error != ERROR_INSUFFICIENT_BUFFER)
            {
                break;
            }

            std::vector<BYTE> buffer(required);
            QUERY_SERVICE_CONFIGW* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
            if (!QueryServiceConfigW(service, config, static_cast<DWORD>(buffer.size()), &required))
            {
                break;
            }

            record->HasConfig = true;
            record->StartType = config->dwStartType;
            record->StartTypeText = DriverServiceStartTypeText(config->dwStartType);
            if (config->lpBinaryPathName != nullptr)
            {
                record->BinaryPath = config->lpBinaryPathName;
                record->ExpandedBinaryPath = ExpandEnvironmentText(record->BinaryPath);
                record->BinaryLeaf = DriverServiceBinaryLeaf(record->BinaryPath);
            }

            ok = true;
        } while (false);

        return ok;
    }

    void CollectDriverServices(std::vector<DriverServiceRecord>* records, std::vector<std::wstring>* warnings)
    {
        do
        {
            if (records == nullptr)
            {
                break;
            }

            SC_HANDLE scm = OpenSCManagerW(
                nullptr,
                nullptr,
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == nullptr)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"OpenSCManagerW failed for driver service enumeration: " + std::to_wstring(GetLastError()));
                }
                break;
            }

            DWORD bytesNeeded = 0;
            DWORD serviceCount = 0;
            DWORD resumeHandle = 0;
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                nullptr,
                0,
                &bytesNeeded,
                &serviceCount,
                &resumeHandle,
                nullptr);

            DWORD error = GetLastError();
            if (bytesNeeded == 0 || error != ERROR_MORE_DATA)
            {
                if (error != ERROR_SUCCESS && warnings != nullptr)
                {
                    warnings->push_back(L"EnumServicesStatusExW sizing failed: " + std::to_wstring(error));
                }
                CloseServiceHandle(scm);
                break;
            }

            std::vector<BYTE> buffer(bytesNeeded);
            resumeHandle = 0;
            if (!EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_DRIVER,
                    SERVICE_STATE_ALL,
                    buffer.data(),
                    static_cast<DWORD>(buffer.size()),
                    &bytesNeeded,
                    &serviceCount,
                    &resumeHandle,
                    nullptr))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"EnumServicesStatusExW failed: " + std::to_wstring(GetLastError()));
                }
                CloseServiceHandle(scm);
                break;
            }

            ENUM_SERVICE_STATUS_PROCESSW* services =
                reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for (DWORD index = 0; index < serviceCount; ++index)
            {
                DriverServiceRecord record = {};
                if (services[index].lpServiceName != nullptr)
                {
                    record.ServiceName = services[index].lpServiceName;
                }
                if (services[index].lpDisplayName != nullptr)
                {
                    record.DisplayName = services[index].lpDisplayName;
                }
                record.ServiceType = services[index].ServiceStatusProcess.dwServiceType;
                record.CurrentState = services[index].ServiceStatusProcess.dwCurrentState;
                record.StateText = DriverServiceStateText(record.CurrentState);
                record.Running = record.CurrentState == SERVICE_RUNNING;

                SC_HANDLE service = OpenServiceW(scm, record.ServiceName.c_str(), SERVICE_QUERY_CONFIG);
                if (service != nullptr)
                {
                    QueryDriverServiceConfig(service, &record);
                    CloseServiceHandle(service);
                }

                if (record.BinaryLeaf.empty())
                {
                    record.BinaryLeaf = LeafName(record.ServiceName);
                }

                records->push_back(std::move(record));
            }

            CloseServiceHandle(scm);
        } while (false);
    }

    uint32_t ConfidenceRank(const std::wstring& confidence)
    {
        uint32_t rank = 0;
        std::wstring lowered = HuntToLower(confidence);

        if (lowered == L"low")
        {
            rank = 1;
        }
        else if (lowered == L"medium")
        {
            rank = 2;
        }
        else if (lowered == L"high")
        {
            rank = 3;
        }

        return rank;
    }

    uint64_t TargetUserDtb(const SnapshotProcessRecord& process)
    {
        return process.UserDirectoryTableBase != 0
            ? process.UserDirectoryTableBase
            : process.DirectoryTableBase;
    }

    bool HasVerifiedUserAddressSpace(const SnapshotProcessRecord& process)
    {
        return process.ProcessId > 4 &&
            process.HasPeb &&
            process.Peb != 0 &&
            TargetUserDtb(process) != 0;
    }

    bool IsUserAddress(uint64_t value)
    {
        return value != 0 && value < 0x0000800000000000ull;
    }

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelAddressMin;
    }

    bool TryAdd(uint64_t base, uint64_t offset, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr || offset > std::numeric_limits<uint64_t>::max() - base)
            {
                break;
            }

            *result = base + offset;
            ok = true;
        } while (false);

        return ok;
    }

    uint64_t DecodeInteger(const uint8_t* bytes, size_t width)
    {
        uint64_t value = 0;

        for (size_t index = 0; index < width && index < sizeof(value); ++index)
        {
            value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
        }

        return value;
    }

    bool AddUnique(std::vector<std::wstring>* values, const std::wstring& value)
    {
        bool added = false;

        do
        {
            if (values == nullptr || value.empty())
            {
                break;
            }

            if (std::find(values->begin(), values->end(), value) != values->end())
            {
                break;
            }

            values->push_back(value);
            added = true;
        } while (false);

        return added;
    }

    std::wstring JoinWideValues(const std::vector<std::wstring>& values, const std::wstring& delimiter)
    {
        std::wstringstream stream;

        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0)
            {
                stream << delimiter;
            }
            stream << values[index];
        }

        return stream.str();
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || address == 0 || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid kernel read request";
                }
                break;
            }

            if (!device.ReadMemory(address, length, bytes, error))
            {
                break;
            }

            if (bytes->size() != length)
            {
                if (error != nullptr)
                {
                    *error = L"short kernel read";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelInteger(
        DeviceClient& device,
        uint64_t address,
        size_t width,
        uint64_t* value,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || width == 0 || width > sizeof(uint64_t))
            {
                if (error != nullptr)
                {
                    *error = L"invalid integer read";
                }
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, static_cast<uint32_t>(width), &bytes, error))
            {
                break;
            }

            *value = DecodeInteger(bytes.data(), width);
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelPointer(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
    {
        return ReadKernelInteger(device, address, sizeof(uint64_t), value, error);
    }

    size_t FieldStorageWidth(const TypeFieldInfo& field, size_t fallback)
    {
        size_t width = fallback;

        if (field.IsBitField)
        {
            uint64_t bitEnd = static_cast<uint64_t>(field.BitPosition) + field.Length;
            if (bitEnd <= 8)
            {
                width = 1;
            }
            else if (bitEnd <= 16)
            {
                width = 2;
            }
            else if (bitEnd <= 32)
            {
                width = 4;
            }
            else
            {
                width = 8;
            }
        }
        else if (field.Length > 0 && field.Length <= sizeof(uint64_t))
        {
            width = static_cast<size_t>(field.Length);
        }

        return width;
    }

    bool ReadFieldInteger(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        size_t fallbackWidth,
        uint64_t* value,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            uint64_t address = 0;
            if (!TryAdd(base, field.Offset, &address))
            {
                if (error != nullptr)
                {
                    *error = L"field address overflow";
                }
                break;
            }

            uint64_t raw = 0;
            if (!ReadKernelInteger(device, address, FieldStorageWidth(field, fallbackWidth), &raw, error))
            {
                break;
            }

            if (field.IsBitField)
            {
                if (field.Length == 0 || field.Length > 64 || field.BitPosition >= 64)
                {
                    if (error != nullptr)
                    {
                        *error = L"invalid bitfield metadata";
                    }
                    break;
                }

                uint64_t mask = field.Length == 64
                    ? std::numeric_limits<uint64_t>::max()
                    : ((1ull << field.Length) - 1ull);
                raw = (raw >> field.BitPosition) & mask;
            }

            *value = raw;
            ok = true;
        } while (false);

        return ok;
    }

    bool FieldNameEquals(const TypeFieldInfo& field, const std::wstring& name)
    {
        return _wcsicmp(field.Name.c_str(), name.c_str()) == 0;
    }

    bool FindFieldRecursiveById(
        SymbolEngine& symbols,
        uint64_t moduleBase,
        ULONG typeId,
        const std::wstring& typeName,
        const std::wstring& fieldName,
        uint64_t baseOffset,
        uint32_t depth,
        std::vector<ULONG>* visited,
        TypeFieldInfo* out)
    {
        bool found = false;

        do
        {
            if (out == nullptr || visited == nullptr || typeId == 0 || depth > 5)
            {
                break;
            }

            if (std::find(visited->begin(), visited->end(), typeId) != visited->end())
            {
                break;
            }
            visited->push_back(typeId);

            TypeLayoutInfo layout = {};
            std::wstring ignored;
            if (!symbols.GetTypeLayoutById(moduleBase, typeId, typeName, &layout, &ignored))
            {
                break;
            }

            for (const TypeFieldInfo& field : layout.Fields)
            {
                if (FieldNameEquals(field, fieldName))
                {
                    *out = field;
                    out->Offset = static_cast<ULONG>(baseOffset + field.Offset);
                    found = true;
                    break;
                }
            }

            if (found)
            {
                break;
            }

            for (const TypeFieldInfo& field : layout.Fields)
            {
                if (field.ChildTypeId == 0 || field.ChildTypeId == typeId)
                {
                    continue;
                }

                std::vector<ULONG> branchVisited = *visited;
                if (FindFieldRecursiveById(
                        symbols,
                        field.ModuleBase != 0 ? field.ModuleBase : moduleBase,
                        field.ChildTypeId,
                        field.TypeName,
                        fieldName,
                        baseOffset + field.Offset,
                        depth + 1,
                        &branchVisited,
                        out))
                {
                    found = true;
                    break;
                }
            }
        } while (false);

        return found;
    }

    bool FindFieldRecursive(
        SymbolEngine& symbols,
        const std::vector<std::wstring>& typeNames,
        const std::wstring& fieldName,
        TypeFieldInfo* out)
    {
        bool found = false;

        do
        {
            if (out == nullptr)
            {
                break;
            }

            for (const std::wstring& typeName : typeNames)
            {
                TypeLayoutInfo layout = {};
                std::wstring ignored;
                if (!symbols.GetTypeLayout(typeName, &layout, &ignored))
                {
                    continue;
                }

                for (const TypeFieldInfo& field : layout.Fields)
                {
                    if (FieldNameEquals(field, fieldName))
                    {
                        *out = field;
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    break;
                }

                for (const TypeFieldInfo& field : layout.Fields)
                {
                    if (field.ChildTypeId == 0)
                    {
                        continue;
                    }

                    std::vector<ULONG> visited;
                    if (FindFieldRecursiveById(
                            symbols,
                            field.ModuleBase != 0 ? field.ModuleBase : layout.ModuleBase,
                            field.ChildTypeId,
                            field.TypeName,
                            fieldName,
                            field.Offset,
                            1,
                            &visited,
                            out))
                    {
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    break;
                }
            }
        } while (false);

        return found;
    }

    std::wstring Win32FilePathFromMaybeNtPath(const std::wstring& path)
    {
        std::wstring result = path;

        do
        {
            if (result.size() > 4 && result.compare(0, 4, L"\\??\\") == 0)
            {
                result = result.substr(4);
                break;
            }

            std::wstring lowered = NormalizePathText(result);
            if (lowered.compare(0, 12, L"\\systemroot\\") == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(_countof(windowsDirectory))) != 0)
                {
                    result = std::wstring(windowsDirectory) + result.substr(11);
                }
                break;
            }

            if (lowered.compare(0, 9, L"\\windows\\") == 0)
            {
                wchar_t windowsDirectory[MAX_PATH] = {};
                if (GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(_countof(windowsDirectory))) != 0)
                {
                    std::wstring windowsPath = windowsDirectory;
                    if (windowsPath.size() >= 2 && windowsPath[1] == L':')
                    {
                        result = windowsPath.substr(0, 2) + result;
                    }
                }
                break;
            }

            if (lowered.compare(0, 4, L"\\\\?\\") == 0)
            {
                result = result.substr(4);
                break;
            }
        } while (false);

        return result;
    }

    std::wstring DosPathFromDevicePath(const std::wstring& path)
    {
        std::wstring result = path;

        do
        {
            std::wstring lowered = NormalizePathText(path);
            if (lowered.compare(0, 8, L"\\device\\") != 0)
            {
                break;
            }

            wchar_t drive[] = L"A:";
            for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
            {
                drive[0] = letter;
                wchar_t target[1024] = {};
                DWORD length = QueryDosDeviceW(drive, target, static_cast<DWORD>(_countof(target)));
                if (length == 0)
                {
                    continue;
                }

                std::wstring deviceName = NormalizePathText(target);
                if (deviceName.empty())
                {
                    continue;
                }

                if (lowered.compare(0, deviceName.size(), deviceName) == 0 &&
                    (lowered.size() == deviceName.size() || lowered[deviceName.size()] == L'\\'))
                {
                    result = std::wstring(drive) + path.substr(deviceName.size());
                    break;
                }
            }
        } while (false);

        return result;
    }

    std::wstring CanonicalPathForCompare(const std::wstring& path)
    {
        std::wstring result;

        do
        {
            if (path.empty())
            {
                break;
            }

            result = Win32FilePathFromMaybeNtPath(path);
            result = DosPathFromDevicePath(result);
            result = NormalizePathText(result);

            if (result.compare(0, 4, L"\\\\?\\") == 0)
            {
                result = result.substr(4);
            }
        } while (false);

        return result;
    }

    bool IsDriveQualifiedPath(const std::wstring& path)
    {
        return path.size() >= 3 &&
            ((path[0] >= L'a' && path[0] <= L'z') || (path[0] >= L'A' && path[0] <= L'Z')) &&
            path[1] == L':' &&
            path[2] == L'\\';
    }

    bool IsRootRelativePath(const std::wstring& path)
    {
        return path.size() >= 2 &&
            path[0] == L'\\' &&
            path[1] != L'\\';
    }

    bool SameCanonicalPathWithRootRelativeFallback(const std::wstring& left, const std::wstring& right)
    {
        bool same = false;

        do
        {
            if (left == right)
            {
                same = true;
                break;
            }

            if (IsRootRelativePath(left) && IsDriveQualifiedPath(right))
            {
                same = (right.substr(0, 2) + left) == right;
                break;
            }

            if (IsRootRelativePath(right) && IsDriveQualifiedPath(left))
            {
                same = left == (left.substr(0, 2) + right);
                break;
            }
        } while (false);

        return same;
    }

    std::wstring EnsureTrailingSlash(std::wstring path)
    {
        if (!path.empty() && path.back() != L'\\')
        {
            path.push_back(L'\\');
        }

        return path;
    }

    std::wstring WindowsDirectory()
    {
        std::wstring result;
        wchar_t buffer[MAX_PATH] = {};

        if (GetWindowsDirectoryW(buffer, static_cast<UINT>(_countof(buffer))) != 0)
        {
            result = buffer;
        }
        else
        {
            result = L"C:\\Windows";
        }

        return result;
    }

    std::wstring SystemDirectory()
    {
        std::wstring result;
        wchar_t buffer[MAX_PATH] = {};

        if (GetSystemDirectoryW(buffer, static_cast<UINT>(_countof(buffer))) != 0)
        {
            result = buffer;
        }
        else
        {
            result = WindowsDirectory() + L"\\System32";
        }

        return result;
    }

    std::wstring ExpectedSystem32Path(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(SystemDirectory()) + imageName;
    }

    std::wstring ExpectedSysWow64Path(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + L"SysWOW64\\" + imageName;
    }

    std::wstring ExpectedWindowsRootPath(const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + imageName;
    }

    bool SameCanonicalPath(const std::wstring& left, const std::wstring& right)
    {
        bool same = false;

        do
        {
            std::wstring l = CanonicalPathForCompare(left);
            std::wstring r = CanonicalPathForCompare(right);
            if (l.empty() || r.empty())
            {
                break;
            }

            same = SameCanonicalPathWithRootRelativeFallback(l, r);
        } while (false);

        return same;
    }

    bool MatchesAnyCanonicalPath(const std::wstring& actual, const std::vector<std::wstring>& expected)
    {
        bool matched = false;

        do
        {
            if (actual.empty())
            {
                break;
            }

            for (const std::wstring& path : expected)
            {
                if (SameCanonicalPath(actual, path))
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    const BuiltinProcessProfile* FindBuiltinProfileByLeaf(const std::wstring& leaf)
    {
        const BuiltinProcessProfile* profile = nullptr;

        static const wchar_t* kParentSmss[] = { L"smss.exe" };
        static const wchar_t* kParentWininit[] = { L"wininit.exe" };
        static const wchar_t* kParentServices[] = { L"services.exe" };
        static const BuiltinProcessProfile kProfiles[] =
        {
            { L"smss.exe", true, false, false, true, nullptr, 0, false },
            { L"csrss.exe", true, false, false, false, kParentSmss, _countof(kParentSmss), false },
            { L"wininit.exe", true, false, false, true, kParentSmss, _countof(kParentSmss), false },
            { L"winlogon.exe", true, false, false, false, kParentSmss, _countof(kParentSmss), false },
            { L"services.exe", true, false, false, true, kParentWininit, _countof(kParentWininit), false },
            { L"lsass.exe", true, false, false, true, kParentWininit, _countof(kParentWininit), false },
            { L"svchost.exe", true, false, false, false, kParentServices, _countof(kParentServices), true },
            { L"spoolsv.exe", true, false, false, true, kParentServices, _countof(kParentServices), false },
            { L"conhost.exe", true, false, false, false, nullptr, 0, false },
            { L"dllhost.exe", true, true, false, false, nullptr, 0, false },
            { L"rundll32.exe", true, true, false, false, nullptr, 0, false },
            { L"regsvr32.exe", true, true, false, false, nullptr, 0, false },
            { L"taskhostw.exe", true, false, false, false, nullptr, 0, false },
            { L"runtimebroker.exe", true, false, false, false, nullptr, 0, false },
            { L"explorer.exe", false, false, true, false, nullptr, 0, false },
            { L"sihost.exe", true, false, false, false, nullptr, 0, false },
            { L"searchindexer.exe", true, false, false, true, kParentServices, _countof(kParentServices), false },
            { L"wmiprvse.exe", true, false, false, false, nullptr, 0, false }
        };

        do
        {
            if (leaf.empty())
            {
                break;
            }

            for (const BuiltinProcessProfile& item : kProfiles)
            {
                if (leaf == item.ImageName)
                {
                    profile = &item;
                    break;
                }
            }
        } while (false);

        return profile;
    }

    bool IsHuntLabBuiltinProfile(const HuntProcessRecord& process)
    {
        bool matched = false;

        do
        {
            std::wstring commandLine = HuntToLower(process.PebCommandLine);
            if (commandLine.find(L"/lab-builtin-profile") == std::wstring::npos &&
                commandLine.find(L"/all") == std::wstring::npos)
            {
                break;
            }

            if (LeafName(process.ApiImagePath) == L"knlivedbghunttarget.exe" ||
                LeafName(process.PebImagePath) == L"knlivedbghunttarget.exe" ||
                LeafName(process.KernelImageName) == L"knlivedbghunttarget.exe")
            {
                matched = true;
            }
        } while (false);

        return matched;
    }

    bool IsSystemNameFromNonSystemPath(const std::wstring& imagePath)
    {
        bool suspicious = false;

        do
        {
            std::wstring leaf = LeafName(imagePath);
            if (leaf.empty())
            {
                break;
            }

            const BuiltinProcessProfile* profile = FindBuiltinProfileByLeaf(leaf);
            if (profile == nullptr)
            {
                break;
            }

            std::vector<std::wstring> expected;
            if (profile->System32)
            {
                expected.push_back(ExpectedSystem32Path(leaf));
            }
            if (profile->SysWow64)
            {
                expected.push_back(ExpectedSysWow64Path(leaf));
            }
            if (profile->WindowsRoot)
            {
                expected.push_back(ExpectedWindowsRootPath(leaf));
            }

            suspicious = !MatchesAnyCanonicalPath(imagePath, expected);
        } while (false);

        return suspicious;
    }

    uint64_t Fnv1a64(const std::vector<uint8_t>& bytes)
    {
        uint64_t hash = 14695981039346656037ull;

        for (uint8_t byte : bytes)
        {
            hash ^= static_cast<uint64_t>(byte);
            hash *= 1099511628211ull;
        }

        return hash;
    }

    size_t CountDifferentBytes(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right)
    {
        size_t count = 0;
        size_t common = std::min(left.size(), right.size());

        for (size_t index = 0; index < common; ++index)
        {
            if (left[index] != right[index])
            {
                ++count;
            }
        }

        count += left.size() > right.size() ? left.size() - right.size() : right.size() - left.size();
        return count;
    }

    bool ReadProcessMemoryByDtb(
        DeviceClient& device,
        uint64_t dtb,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || dtb == 0 || address == 0 || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid process memory read request";
                }
                break;
            }

            bytes->clear();
            bytes->reserve(length);

            uint64_t current = address;
            uint32_t remaining = length;
            while (remaining != 0)
            {
                PhysicalTranslationInfo translation = {};
                if (!device.TranslateVirtual(dtb, current, remaining, &translation, error))
                {
                    break;
                }

                if (translation.TranslatedLength == 0)
                {
                    if (error != nullptr)
                    {
                        *error = L"zero-length process translation";
                    }
                    break;
                }

                uint32_t chunk = translation.TranslatedLength;
                if (chunk > remaining)
                {
                    chunk = remaining;
                }

                std::vector<uint8_t> pageBytes;
                if (!device.ReadPhysical(translation.PhysicalAddress, chunk, &pageBytes, error) ||
                    pageBytes.size() != chunk)
                {
                    break;
                }

                bytes->insert(bytes->end(), pageBytes.begin(), pageBytes.end());
                current += chunk;
                remaining -= chunk;
            }

            ok = bytes->size() == length;
        } while (false);

        return ok;
    }

    bool ReadProcessU64(DeviceClient& device, const SnapshotProcessRecord& process, uint64_t address, uint64_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), address, sizeof(uint64_t), &bytes, &ignored))
            {
                break;
            }

            uint64_t result = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                result |= static_cast<uint64_t>(bytes[index]) << (index * 8);
            }

            *value = result;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadProcessU32(DeviceClient& device, const SnapshotProcessRecord& process, uint64_t address, uint32_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), address, sizeof(uint32_t), &bytes, &ignored))
            {
                break;
            }

            uint32_t result = 0;
            for (size_t index = 0; index < sizeof(uint32_t); ++index)
            {
                result |= static_cast<uint32_t>(bytes[index]) << (index * 8);
            }

            *value = result;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadRemoteUnicodeString(
        DeviceClient& device,
        const SnapshotProcessRecord& process,
        uint64_t unicodeStringAddress,
        size_t maxBytes,
        std::wstring* text)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || unicodeStringAddress == 0)
            {
                break;
            }

            text->clear();

            std::vector<uint8_t> bytes;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(device, TargetUserDtb(process), unicodeStringAddress, 16, &bytes, &ignored))
            {
                break;
            }

            uint16_t length = static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
            uint64_t buffer = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                buffer |= static_cast<uint64_t>(bytes[8 + index]) << (index * 8);
            }

            if (length == 0 || buffer == 0 || !IsUserAddress(buffer))
            {
                ok = true;
                break;
            }

            size_t cappedLength = std::min<size_t>(length, maxBytes);
            cappedLength &= ~static_cast<size_t>(1);
            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> stringBytes;
            if (!ReadProcessMemoryByDtb(
                    device,
                    TargetUserDtb(process),
                    buffer,
                    static_cast<uint32_t>(cappedLength),
                    &stringBytes,
                    &ignored))
            {
                break;
            }

            text->assign(
                reinterpret_cast<const wchar_t*>(stringBytes.data()),
                stringBytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelUnicodeString(
        DeviceClient& device,
        uint64_t unicodeStringAddress,
        size_t maxBytes,
        std::wstring* text,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (text == nullptr || unicodeStringAddress == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid kernel unicode string request";
                }
                break;
            }

            text->clear();

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, unicodeStringAddress, 16, &bytes, error))
            {
                break;
            }

            uint16_t length = static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
            uint64_t buffer = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                buffer |= static_cast<uint64_t>(bytes[8 + index]) << (index * 8);
            }

            if (length == 0 || buffer == 0)
            {
                ok = true;
                break;
            }

            if (!IsKernelAddress(buffer))
            {
                if (error != nullptr)
                {
                    *error = L"kernel unicode string buffer is not a kernel address";
                }
                break;
            }

            size_t cappedLength = std::min<size_t>(length, maxBytes);
            cappedLength &= ~static_cast<size_t>(1);
            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> stringBytes;
            if (!ReadKernelBytes(
                    device,
                    buffer,
                    static_cast<uint32_t>(cappedLength),
                    &stringBytes,
                    error))
            {
                break;
            }

            text->assign(
                reinterpret_cast<const wchar_t*>(stringBytes.data()),
                stringBytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveSectionBackingLayout(SymbolEngine& symbols, SectionBackingLayout* layout)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                break;
            }

            if (layout->Resolved)
            {
                ok = layout->HasSubsectionControlArea &&
                    layout->HasControlAreaFilePointer &&
                    layout->HasFileObjectFileName;
                break;
            }

            *layout = SectionBackingLayout{};
            layout->Resolved = true;
            layout->HasSubsectionControlArea =
                FindFieldRecursive(symbols, {L"nt!_SUBSECTION", L"_SUBSECTION"}, L"ControlArea", &layout->SubsectionControlArea);
            layout->HasControlAreaFilePointer =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"FilePointer", &layout->ControlAreaFilePointer);
            layout->HasControlAreaImageFlag =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"Image", &layout->ControlAreaImageFlag);
            layout->HasFileObjectFileName =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"FileName", &layout->FileObjectFileName);

            if (!layout->HasSubsectionControlArea)
            {
                layout->Warnings.push_back(L"_SUBSECTION.ControlArea field unavailable");
            }
            if (!layout->HasControlAreaFilePointer)
            {
                layout->Warnings.push_back(L"_CONTROL_AREA.FilePointer field unavailable");
            }
            if (!layout->HasFileObjectFileName)
            {
                layout->Warnings.push_back(L"_FILE_OBJECT.FileName field unavailable");
            }

            ok = layout->HasSubsectionControlArea &&
                layout->HasControlAreaFilePointer &&
                layout->HasFileObjectFileName;
        } while (false);

        return ok;
    }

    bool ResolveVadSectionBackingPath(
        DeviceClient& device,
        SymbolEngine& symbols,
        const ProcessVadRecord& vad,
        std::wstring* path,
        std::wstring* state,
        std::wstring* warning,
        bool* imageSection = nullptr)
    {
        bool ok = false;
        static SectionBackingLayout layout;

        do
        {
            if (path == nullptr || state == nullptr)
            {
                break;
            }

            path->clear();
            *state = L"unavailable";
            if (imageSection != nullptr)
            {
                *imageSection = false;
            }

            if (!vad.HasSubsection || vad.Subsection == 0)
            {
                *state = L"unbacked";
                ok = true;
                break;
            }

            if (!ResolveSectionBackingLayout(symbols, &layout))
            {
                if (warning != nullptr)
                {
                    *warning = L"section backing resolver unavailable: " + JoinWideValues(layout.Warnings, L"; ");
                }
                break;
            }

            uint64_t controlArea = 0;
            if (!ReadFieldInteger(device, vad.Subsection, layout.SubsectionControlArea, sizeof(uint64_t), &controlArea, warning) ||
                controlArea == 0 ||
                !IsKernelAddress(controlArea))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read VAD subsection control area";
                }
                break;
            }

            if (imageSection != nullptr && layout.HasControlAreaImageFlag)
            {
                uint64_t imageFlag = 0;
                std::wstring ignored;
                if (ReadFieldInteger(device, controlArea, layout.ControlAreaImageFlag, sizeof(uint32_t), &imageFlag, &ignored))
                {
                    *imageSection = imageFlag != 0;
                }
            }

            uint64_t fileFastRef = 0;
            if (!ReadFieldInteger(device, controlArea, layout.ControlAreaFilePointer, sizeof(uint64_t), &fileFastRef, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read control area file pointer";
                }
                break;
            }

            uint64_t fileObject = fileFastRef & ~0xfull;
            if (fileObject == 0)
            {
                *state = L"unbacked";
                ok = true;
                break;
            }

            if (!IsKernelAddress(fileObject))
            {
                if (warning != nullptr)
                {
                    *warning = L"control area file pointer is not a kernel address";
                }
                break;
            }

            uint64_t fileNameAddress = 0;
            if (!TryAdd(fileObject, layout.FileObjectFileName.Offset, &fileNameAddress))
            {
                if (warning != nullptr)
                {
                    *warning = L"FILE_OBJECT.FileName address overflow";
                }
                break;
            }

            std::wstring backingPath;
            if (!ReadKernelUnicodeString(device, fileNameAddress, kMaxPebStringBytes, &backingPath, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read FILE_OBJECT.FileName";
                }
                break;
            }

            *path = backingPath;
            *state = backingPath.empty() ? L"empty_file_name" : L"resolved";
            ok = true;
        } while (false);

        return ok;
    }

    void MergeModule(std::vector<HuntModuleRecord>* modules, const HuntModuleRecord& incoming)
    {
        do
        {
            if (modules == nullptr || incoming.Base == 0)
            {
                break;
            }

            HuntModuleRecord* target = nullptr;
            for (HuntModuleRecord& module : *modules)
            {
                if (module.Base == incoming.Base)
                {
                    target = &module;
                    break;
                }
            }

            if (target == nullptr)
            {
                modules->push_back(incoming);
                break;
            }

            if (target->Size == 0)
            {
                target->Size = incoming.Size;
            }
            if (target->Name.empty())
            {
                target->Name = incoming.Name;
            }
            if (target->Path.empty())
            {
                target->Path = incoming.Path;
            }

            target->ToolhelpSeen = target->ToolhelpSeen || incoming.ToolhelpSeen;
            target->LdrLoadSeen = target->LdrLoadSeen || incoming.LdrLoadSeen;
            target->LdrMemorySeen = target->LdrMemorySeen || incoming.LdrMemorySeen;
            target->LdrInitSeen = target->LdrInitSeen || incoming.LdrInitSeen;
            target->PrivatePeVadSeen = target->PrivatePeVadSeen || incoming.PrivatePeVadSeen;
            target->VadImageSeen = target->VadImageSeen || incoming.VadImageSeen;
            if (target->VadAddress == 0)
            {
                target->VadAddress = incoming.VadAddress;
            }
            if (target->VadBackingPath.empty())
            {
                target->VadBackingPath = incoming.VadBackingPath;
            }
            if (target->VadBackingState.empty())
            {
                target->VadBackingState = incoming.VadBackingState;
            }
        } while (false);
    }

    bool AddressInsideModule(const HuntModuleRecord& module, uint64_t address)
    {
        bool inside = false;

        do
        {
            uint64_t end = module.Base + module.Size;
            if (module.Size == 0 || end < module.Base)
            {
                break;
            }

            inside = address >= module.Base && address < end;
        } while (false);

        return inside;
    }

    bool ModuleHasLoaderView(const HuntModuleRecord& module)
    {
        return module.ToolhelpSeen || module.LdrLoadSeen || module.LdrMemorySeen || module.LdrInitSeen;
    }

    bool ModuleHasCoreLdrView(const HuntModuleRecord& module)
    {
        return module.LdrLoadSeen || module.LdrMemorySeen;
    }

    bool ProcessHasReliableCoreLdrView(const HuntProcessRecord& process)
    {
        return process.PebLdrLoadEnumerated && process.PebLdrMemoryEnumerated;
    }

    bool CanonicalPathUnderDirectory(const std::wstring& path, const std::wstring& directory)
    {
        bool matched = false;

        do
        {
            std::wstring canonicalPath = CanonicalPathForCompare(path);
            std::wstring canonicalDirectory = CanonicalPathForCompare(directory);
            if (canonicalPath.empty() || canonicalDirectory.empty())
            {
                break;
            }

            canonicalDirectory = EnsureTrailingSlash(canonicalDirectory);
            if (canonicalPath.size() <= canonicalDirectory.size())
            {
                break;
            }

            matched = canonicalPath.compare(0, canonicalDirectory.size(), canonicalDirectory) == 0;
        } while (false);

        return matched;
    }

    bool IsWindowsBackedModulePath(const std::wstring& path)
    {
        bool backed = false;

        do
        {
            if (path.empty())
            {
                break;
            }

            backed = CanonicalPathUnderDirectory(path, WindowsDirectory());
        } while (false);

        return backed;
    }

    bool ShouldAuditBuiltinModuleProvenance(const HuntProcessRecord& process)
    {
        bool audit = false;

        do
        {
            if (!process.BuiltinProfileMatched)
            {
                break;
            }

            if (process.BuiltinProfile == L"hunt_lab_builtin_profile")
            {
                audit = true;
                break;
            }

            static const wchar_t* kProfiles[] =
            {
                L"smss.exe",
                L"csrss.exe",
                L"wininit.exe",
                L"winlogon.exe",
                L"services.exe",
                L"lsass.exe",
                L"svchost.exe",
                L"spoolsv.exe",
                L"searchindexer.exe"
            };

            for (const wchar_t* profile : kProfiles)
            {
                if (process.BuiltinProfile == profile)
                {
                    audit = true;
                    break;
                }
            }
        } while (false);

        return audit;
    }

    bool LoaderModuleCoversAddress(
        const HuntProcessRecord& process,
        uint64_t address,
        const HuntModuleRecord* excluded)
    {
        bool covered = false;

        for (const HuntModuleRecord& module : process.Modules)
        {
            if (excluded != nullptr && &module == excluded)
            {
                continue;
            }

            if ((module.ToolhelpSeen || ModuleHasCoreLdrView(module)) && AddressInsideModule(module, address))
            {
                covered = true;
                break;
            }
        }

        return covered;
    }

    const HuntModuleRecord* FindLoaderModuleContainingAddress(
        const HuntProcessRecord& process,
        uint64_t address)
    {
        const HuntModuleRecord* found = nullptr;

        for (const HuntModuleRecord& module : process.Modules)
        {
            if ((module.ToolhelpSeen || ModuleHasCoreLdrView(module)) && AddressInsideModule(module, address))
            {
                found = &module;
                break;
            }
        }

        return found;
    }

    const ProcessVadRecord* FindVadContaining(const HuntProcessRecord& process, uint64_t address)
    {
        const ProcessVadRecord* found = nullptr;

        for (const ProcessVadRecord& vad : process.VadRecords)
        {
            if (address >= vad.StartAddress && address <= vad.EndAddress)
            {
                found = &vad;
                break;
            }
        }

        return found;
    }

    bool ReadFileBytesAt(HANDLE file, uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || file == INVALID_HANDLE_VALUE || length == 0)
            {
                break;
            }

            LARGE_INTEGER distance = {};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN))
            {
                break;
            }

            bytes->assign(length, 0);
            DWORD read = 0;
            if (!ReadFile(file, bytes->data(), length, &read, nullptr))
            {
                break;
            }

            bytes->resize(read);
            ok = !bytes->empty();
        } while (false);

        return ok;
    }

    bool RvaToRawOffset(const DiskPeMetadata& metadata, uint32_t rva, uint64_t* rawOffset)
    {
        bool ok = false;

        do
        {
            if (rawOffset == nullptr)
            {
                break;
            }

            if (metadata.SizeOfHeaders != 0 && rva < metadata.SizeOfHeaders)
            {
                *rawOffset = rva;
                ok = true;
                break;
            }

            for (const DiskPeSection& section : metadata.Sections)
            {
                uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan == 0)
                {
                    continue;
                }

                uint64_t sectionStart = section.VirtualAddress;
                uint64_t sectionEnd = sectionStart + mappedSpan;
                if (sectionEnd < sectionStart ||
                    rva < sectionStart ||
                    rva >= sectionEnd)
                {
                    continue;
                }

                uint64_t rawSpan = section.SizeOfRawData;
                if (rawSpan > mappedSpan)
                {
                    rawSpan = mappedSpan;
                }

                uint64_t delta = static_cast<uint64_t>(rva) - sectionStart;
                if (delta >= rawSpan)
                {
                    break;
                }

                *rawOffset = static_cast<uint64_t>(section.PointerToRawData) + delta;
                ok = true;
                break;
            }
        } while (false);

        return ok;
    }

    const DiskPeSection* FindDiskSectionForRva(const DiskPeMetadata& metadata, uint32_t rva)
    {
        const DiskPeSection* found = nullptr;

        for (const DiskPeSection& section : metadata.Sections)
        {
            uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
            if (mappedSpan == 0)
            {
                continue;
            }

            uint64_t sectionStart = section.VirtualAddress;
            uint64_t sectionEnd = sectionStart + mappedSpan;
            if (sectionEnd < sectionStart)
            {
                continue;
            }

            if (rva >= sectionStart && rva < sectionEnd)
            {
                found = &section;
                break;
            }
        }

        return found;
    }

    bool ReadDiskBytesForRva(
        HANDLE file,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0)
            {
                break;
            }

            uint64_t rawOffset = 0;
            if (!RvaToRawOffset(metadata, rva, &rawOffset))
            {
                break;
            }

            ok = ReadFileBytesAt(file, rawOffset, length, bytes);
        } while (false);

        return ok;
    }

    void PopulateRelocationPages(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t relocRva,
        uint32_t relocSize)
    {
        do
        {
            if (metadata == nullptr || file == INVALID_HANDLE_VALUE || relocRva == 0 || relocSize < sizeof(IMAGE_BASE_RELOCATION))
            {
                break;
            }

            uint32_t parsed = 0;
            while (parsed + sizeof(IMAGE_BASE_RELOCATION) <= relocSize)
            {
                std::vector<uint8_t> blockHeader;
                if (!ReadDiskBytesForRva(file, *metadata, relocRva + parsed, sizeof(IMAGE_BASE_RELOCATION), &blockHeader) ||
                    blockHeader.size() < sizeof(IMAGE_BASE_RELOCATION))
                {
                    break;
                }

                const IMAGE_BASE_RELOCATION* block =
                    reinterpret_cast<const IMAGE_BASE_RELOCATION*>(blockHeader.data());
                if (block->VirtualAddress == 0 ||
                    block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                    parsed + block->SizeOfBlock > relocSize)
                {
                    break;
                }

                uint32_t entryBytes = block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
                std::vector<uint8_t> entries;
                if (!ReadDiskBytesForRva(
                        file,
                        *metadata,
                        relocRva + parsed + sizeof(IMAGE_BASE_RELOCATION),
                        entryBytes,
                        &entries) ||
                    entries.size() < entryBytes)
                {
                    break;
                }

                size_t entryCount = entryBytes / sizeof(uint16_t);
                for (size_t index = 0; index < entryCount; ++index)
                {
                    uint16_t entry = 0;
                    std::memcpy(&entry, entries.data() + index * sizeof(uint16_t), sizeof(entry));
                    uint16_t type = entry >> 12;
                    uint16_t offset = entry & 0x0fffu;
                    if (type == IMAGE_REL_BASED_ABSOLUTE)
                    {
                        continue;
                    }

                    uint32_t fixupRva = block->VirtualAddress + offset;
                    metadata->RelocationPages.insert(fixupRva & 0xfffff000u);
                }

                parsed += block->SizeOfBlock;
            }
        } while (false);
    }

    void AddRvaRangePages(std::set<uint32_t>* pages, uint32_t rva, uint32_t size)
    {
        do
        {
            if (pages == nullptr || rva == 0 || size == 0)
            {
                break;
            }

            uint64_t start = rva & 0xfffff000u;
            uint64_t end = static_cast<uint64_t>(rva) + size;
            if (end < rva)
            {
                break;
            }

            for (uint64_t page = start; page < end; page += kPageSize)
            {
                if (page > std::numeric_limits<uint32_t>::max())
                {
                    break;
                }

                pages->insert(static_cast<uint32_t>(page));
            }
        } while (false);
    }

    void AddLoaderMutableDirectoryPages(
        std::set<uint32_t>* pages,
        const IMAGE_DATA_DIRECTORY* directories,
        uint32_t count)
    {
        do
        {
            if (pages == nullptr || directories == nullptr)
            {
                break;
            }

            const uint32_t mutableDirectories[] =
            {
                IMAGE_DIRECTORY_ENTRY_IMPORT,
                IMAGE_DIRECTORY_ENTRY_IAT,
                IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
                IMAGE_DIRECTORY_ENTRY_TLS,
                IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
            };

            for (uint32_t directoryIndex : mutableDirectories)
            {
                if (directoryIndex >= count)
                {
                    continue;
                }

                AddRvaRangePages(
                    pages,
                    directories[directoryIndex].VirtualAddress,
                    directories[directoryIndex].Size);
            }
        } while (false);
    }

    bool ReadDiskPeMetadata(const std::wstring& rawPath, DiskPeMetadata* metadata, std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (metadata == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid PE metadata output";
                }
                break;
            }

            *metadata = {};
            std::wstring path = Win32FilePathFromMaybeNtPath(rawPath);
            file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }

            std::vector<uint8_t> header;
            if (!ReadFileBytesAt(file, 0, 0x1000, &header) || header.size() < sizeof(IMAGE_DOS_HEADER))
            {
                if (error != nullptr)
                {
                    *error = L"read disk image header failed";
                }
                break;
            }

            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header.data());
            if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
                dos->e_lfanew <= 0 ||
                static_cast<size_t>(dos->e_lfanew) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > header.size())
            {
                if (error != nullptr)
                {
                    *error = L"disk image is not a PE file";
                }
                break;
            }

            size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
            uint32_t signature = *reinterpret_cast<const uint32_t*>(header.data() + ntOffset);
            if (signature != IMAGE_NT_SIGNATURE)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid NT signature";
                }
                break;
            }

            const IMAGE_FILE_HEADER* fileHeader =
                reinterpret_cast<const IMAGE_FILE_HEADER*>(header.data() + ntOffset + sizeof(uint32_t));
            size_t optionalOffset = ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
            size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
            size_t required = sectionOffset + static_cast<size_t>(fileHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (required > header.size())
            {
                if (!ReadFileBytesAt(file, 0, static_cast<uint32_t>(required), &header) || header.size() < required)
                {
                    if (error != nullptr)
                    {
                        *error = L"read disk image section table failed";
                    }
                    break;
                }
            }

            uint32_t relocRva = 0;
            uint32_t relocSize = 0;
            uint16_t magic = *reinterpret_cast<const uint16_t*>(header.data() + optionalOffset);
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER64* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(header.data() + optionalOffset);
                metadata->ImageBase = optional->ImageBase;
                metadata->EntryPointRva = optional->AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional->SizeOfHeaders;
                metadata->SizeOfImage = optional->SizeOfImage;
                AddLoaderMutableDirectoryPages(
                    &metadata->LoaderMutablePages,
                    optional->DataDirectory,
                    optional->NumberOfRvaAndSizes);
                if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                const IMAGE_OPTIONAL_HEADER32* optional =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(header.data() + optionalOffset);
                metadata->ImageBase = optional->ImageBase;
                metadata->EntryPointRva = optional->AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional->SizeOfHeaders;
                metadata->SizeOfImage = optional->SizeOfImage;
                AddLoaderMutableDirectoryPages(
                    &metadata->LoaderMutablePages,
                    optional->DataDirectory,
                    optional->NumberOfRvaAndSizes);
                if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"unsupported PE optional header magic";
                }
                break;
            }

            metadata->HasEntryPoint = metadata->EntryPointRva != 0;

            const IMAGE_SECTION_HEADER* sections =
                reinterpret_cast<const IMAGE_SECTION_HEADER*>(header.data() + sectionOffset);
            for (uint16_t index = 0; index < fileHeader->NumberOfSections; ++index)
            {
                DiskPeSection section = {};
                char sectionName[9] = {};
                std::memcpy(sectionName, sections[index].Name, IMAGE_SIZEOF_SHORT_NAME);
                std::string narrowName(sectionName);
                section.Name.assign(narrowName.begin(), narrowName.end());
                section.VirtualAddress = sections[index].VirtualAddress;
                section.VirtualSize = sections[index].Misc.VirtualSize;
                section.PointerToRawData = sections[index].PointerToRawData;
                section.SizeOfRawData = sections[index].SizeOfRawData;
                section.Characteristics = sections[index].Characteristics;
                section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.Writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                metadata->Sections.push_back(section);

                if (!metadata->HasExecutableSection &&
                    section.Executable)
                {
                    metadata->FirstExecutableSectionRva = section.VirtualAddress;
                    metadata->HasExecutableSection = true;
                }
            }

            PopulateRelocationPages(file, metadata, relocRva, relocSize);

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool CopyRawBytesIntoMappedPage(
        HANDLE file,
        uint64_t rawOffset,
        uint64_t pageOffset,
        uint64_t length,
        std::vector<uint8_t>* page)
    {
        bool ok = false;

        do
        {
            if (page == nullptr || page->size() != kPageSize || pageOffset >= kPageSize)
            {
                break;
            }

            uint64_t cappedLength = length;
            if (pageOffset + cappedLength > kPageSize)
            {
                cappedLength = kPageSize - pageOffset;
            }

            if (cappedLength == 0)
            {
                ok = true;
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadFileBytesAt(file, rawOffset, static_cast<uint32_t>(cappedLength), &bytes))
            {
                break;
            }

            if (bytes.size() != cappedLength)
            {
                break;
            }

            std::copy(
                bytes.begin(),
                bytes.end(),
                page->begin() + static_cast<std::ptrdiff_t>(pageOffset));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadDiskPageForRva(
        const std::wstring& rawPath,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        std::vector<uint8_t>* page,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (page == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid disk page output";
                }
                break;
            }

            uint32_t pageRva = rva & 0xfffff000u;
            uint64_t pageStart = pageRva;
            uint64_t pageEnd = pageStart + kPageSize;
            bool mapped = false;
            bool copied = true;
            page->assign(static_cast<size_t>(kPageSize), 0);

            std::wstring path = Win32FilePathFromMaybeNtPath(rawPath);
            file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }

            if (metadata.SizeOfHeaders != 0 && pageStart < metadata.SizeOfHeaders)
            {
                uint64_t copyEnd = metadata.SizeOfHeaders;
                if (copyEnd > pageEnd)
                {
                    copyEnd = pageEnd;
                }

                if (copyEnd > pageStart)
                {
                    mapped = true;
                    copied = CopyRawBytesIntoMappedPage(file, pageStart, 0, copyEnd - pageStart, page) && copied;
                }
            }

            for (const DiskPeSection& section : metadata.Sections)
            {
                uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan == 0)
                {
                    continue;
                }

                uint64_t sectionStart = section.VirtualAddress;
                uint64_t sectionEnd = sectionStart + mappedSpan;
                if (sectionEnd < sectionStart)
                {
                    continue;
                }

                uint64_t overlapStart = pageStart > sectionStart ? pageStart : sectionStart;
                uint64_t overlapEnd = pageEnd < sectionEnd ? pageEnd : sectionEnd;
                if (overlapEnd <= overlapStart)
                {
                    continue;
                }

                mapped = true;

                uint64_t rawSpan = section.SizeOfRawData;
                if (rawSpan > mappedSpan)
                {
                    rawSpan = mappedSpan;
                }

                uint64_t rawEnd = sectionStart + rawSpan;
                if (rawEnd < sectionStart || overlapStart >= rawEnd)
                {
                    continue;
                }

                uint64_t rawCopyEnd = overlapEnd < rawEnd ? overlapEnd : rawEnd;
                if (rawCopyEnd <= overlapStart)
                {
                    continue;
                }

                uint64_t rawOffset = static_cast<uint64_t>(section.PointerToRawData) + (overlapStart - sectionStart);
                uint64_t mappedOffset = overlapStart - pageStart;
                copied = CopyRawBytesIntoMappedPage(file, rawOffset, mappedOffset, rawCopyEnd - overlapStart, page) && copied;
            }

            if (!mapped)
            {
                if (error != nullptr)
                {
                    *error = L"RVA has no disk mapping";
                }
                break;
            }

            if (!copied)
            {
                if (error != nullptr)
                {
                    *error = L"read mapped disk image page failed";
                }
                break;
            }

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool CollectSystemProcessInformation(
        std::map<uint32_t, ApiProcessRecord>* processes,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();

            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation unavailable: ntdll not loaded";
                }
                break;
            }

            NtQuerySystemInformationFn query =
                reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (query == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation unavailable";
                }
                break;
            }

            ULONG length = 0x20000;
            std::vector<uint8_t> buffer;
            LONG status = 0;
            for (uint32_t attempt = 0; attempt < 8; ++attempt)
            {
                buffer.assign(length, 0);
                ULONG returned = 0;
                status = query(kSystemProcessInformation, buffer.data(), length, &returned);
                if (status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall)
                {
                    length = returned != 0 ? returned + 0x10000 : length * 2;
                    continue;
                }
                break;
            }

            if (status < 0)
            {
                if (warning != nullptr)
                {
                    *warning = L"NtQuerySystemInformation(SystemProcessInformation) failed status=" + HuntHex(static_cast<uint32_t>(status), 8);
                }
                break;
            }

            size_t offset = 0;
            while (offset + sizeof(HuntSystemProcessInformation) <= buffer.size())
            {
                const HuntSystemProcessInformation* spi =
                    reinterpret_cast<const HuntSystemProcessInformation*>(buffer.data() + offset);

                ApiProcessRecord record = {};
                record.ProcessId = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(spi->UniqueProcessId));
                record.ParentProcessId = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(spi->InheritedFromUniqueProcessId));
                record.HasParentProcessId = spi->InheritedFromUniqueProcessId != nullptr;
                if (spi->ImageName.Buffer != nullptr && spi->ImageName.Length != 0)
                {
                    record.ImageName.assign(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(wchar_t));
                }
                else if (record.ProcessId == 0)
                {
                    record.ImageName = L"Idle";
                }
                else if (record.ProcessId == 4)
                {
                    record.ImageName = L"System";
                }

                (*processes)[record.ProcessId] = record;

                if (spi->NextEntryOffset == 0)
                {
                    break;
                }

                offset += spi->NextEntryOffset;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CollectToolhelpProcesses(
        std::map<uint32_t, ApiProcessRecord>* processes,
        std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();
            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning = L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (!Process32FirstW(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning = L"Process32FirstW failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            do
            {
                ApiProcessRecord record = {};
                record.ProcessId = entry.th32ProcessID;
                record.ParentProcessId = entry.th32ParentProcessID;
                record.HasParentProcessId = true;
                record.ImageName = entry.szExeFile;
                (*processes)[record.ProcessId] = record;
                entry.dwSize = sizeof(entry);
            } while (Process32NextW(snapshot, &entry));

            ok = true;
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            CloseHandle(snapshot);
        }

        return ok;
    }

    void QueryProcessPublicDetails(HuntProcessRecord* process)
    {
        HANDLE handle = nullptr;

        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            DWORD sessionId = 0;
            if (ProcessIdToSessionId(process->ProcessId, &sessionId))
            {
                process->SessionId = sessionId;
                process->HasSessionId = true;
            }

            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process->ProcessId);
            if (handle == nullptr)
            {
                break;
            }

            std::vector<wchar_t> buffer(32768);
            DWORD length = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(handle, 0, buffer.data(), &length) && length != 0)
            {
                process->ApiImagePath.assign(buffer.data(), length);
            }
        } while (false);

        if (handle != nullptr)
        {
            CloseHandle(handle);
        }
    }

    bool CollectToolhelpModules(HuntProcessRecord* process, std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process->ProcessId);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning = L"toolhelp module snapshot failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (!Module32FirstW(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning = L"toolhelp module first failed gle=" + std::to_wstring(GetLastError());
                }
                break;
            }

            do
            {
                HuntModuleRecord module = {};
                module.Base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                module.Size = entry.modBaseSize;
                module.Name = entry.szModule;
                module.Path = entry.szExePath;
                module.ToolhelpSeen = true;
                MergeModule(&process->Modules, module);
                entry.dwSize = sizeof(entry);
            } while (Module32NextW(snapshot, &entry));

            process->ToolhelpModuleEnumerated = true;
            ok = true;
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            CloseHandle(snapshot);
        }

        return ok;
    }

    void CollectPebIdentity(DeviceClient& device, HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr ||
                !process->Kernel.HasPeb ||
                process->Kernel.Peb == 0 ||
                TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            uint64_t imageBase = 0;
            if (ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x10, &imageBase) &&
                IsUserAddress(imageBase))
            {
                process->PebImageBase = imageBase;
                process->HasPebImageBase = true;
            }
            else
            {
                AddUnique(&process->Warnings, L"PEB ImageBaseAddress read failed");
            }

            uint64_t parameters = 0;
            if (!ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x20, &parameters) ||
                parameters == 0 ||
                !IsUserAddress(parameters))
            {
                AddUnique(&process->Warnings, L"PEB process parameter pointer read failed");
                break;
            }

            if (!ReadRemoteUnicodeString(device, process->Kernel, parameters + 0x60, kMaxPebStringBytes, &process->PebImagePath))
            {
                AddUnique(&process->Warnings, L"PEB ImagePathName read failed");
            }

            if (!ReadRemoteUnicodeString(device, process->Kernel, parameters + 0x70, kMaxPebStringBytes, &process->PebCommandLine))
            {
                AddUnique(&process->Warnings, L"PEB CommandLine read failed");
            }
        } while (false);
    }

    bool WalkPebLdrList(
        DeviceClient& device,
        HuntProcessRecord* process,
        uint64_t listHead,
        uint64_t listEntryOffset,
        const std::wstring& source)
    {
        bool ok = false;

        do
        {
            if (process == nullptr || listHead == 0)
            {
                break;
            }

            uint64_t current = 0;
            if (!ReadProcessU64(device, process->Kernel, listHead, &current))
            {
                break;
            }

            ok = true;
            std::set<uint64_t> visited;
            size_t scanned = 0;
            while (current != 0 && current != listHead && scanned < kMaxLdrModules)
            {
                if (visited.find(current) != visited.end())
                {
                    AddUnique(&process->Warnings, L"PEB LDR list loop detected");
                    break;
                }

                visited.insert(current);
                uint64_t entryBase = current - listEntryOffset;
                HuntModuleRecord module = {};
                ReadProcessU64(device, process->Kernel, entryBase + 0x30, &module.Base);
                uint32_t size = 0;
                if (ReadProcessU32(device, process->Kernel, entryBase + 0x40, &size))
                {
                    module.Size = size;
                }
                ReadRemoteUnicodeString(device, process->Kernel, entryBase + 0x48, kMaxPebStringBytes, &module.Path);
                ReadRemoteUnicodeString(device, process->Kernel, entryBase + 0x58, kMaxPebStringBytes, &module.Name);

                if (source == L"load")
                {
                    module.LdrLoadSeen = true;
                }
                else if (source == L"memory")
                {
                    module.LdrMemorySeen = true;
                }
                else if (source == L"init")
                {
                    module.LdrInitSeen = true;
                }

                MergeModule(&process->Modules, module);

                uint64_t next = 0;
                if (!ReadProcessU64(device, process->Kernel, current, &next))
                {
                    break;
                }

                current = next;
                ++scanned;
            }

            if (scanned >= kMaxLdrModules)
            {
                AddUnique(&process->Warnings, L"PEB LDR list traversal hit the module limit");
            }
        } while (false);

        return ok;
    }

    void CollectPebLdrModules(DeviceClient& device, HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr ||
                !process->Kernel.HasPeb ||
                process->Kernel.Peb == 0 ||
                TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            uint64_t ldr = 0;
            if (!ReadProcessU64(device, process->Kernel, process->Kernel.Peb + 0x18, &ldr) ||
                ldr == 0 ||
                !IsUserAddress(ldr))
            {
                AddUnique(&process->Warnings, L"PEB Ldr pointer read failed");
                break;
            }

            bool loadSeen = WalkPebLdrList(device, process, ldr + 0x10, 0x00, L"load");
            bool memorySeen = WalkPebLdrList(device, process, ldr + 0x20, 0x10, L"memory");
            bool initSeen = WalkPebLdrList(device, process, ldr + 0x30, 0x20, L"init");
            process->PebLdrLoadEnumerated = loadSeen;
            process->PebLdrMemoryEnumerated = memorySeen;
            process->PebLdrInitEnumerated = initSeen;
            process->PebLdrEnumerated = loadSeen && memorySeen;
            if (!process->PebLdrEnumerated)
            {
                AddUnique(&process->Warnings, L"PEB LDR core list heads could not be read");
            }
        } while (false);
    }

    ProcessTriageTarget BuildTriageTarget(const SnapshotProcessRecord& process)
    {
        ProcessTriageTarget target = {};
        target.ProcessId = process.ProcessId;
        target.Eprocess = process.Eprocess;
        target.DirectoryTableBase = process.DirectoryTableBase;
        target.UserDirectoryTableBase = process.UserDirectoryTableBase;
        target.Peb = process.Peb;
        target.HasPeb = process.HasPeb;
        target.ImageName = process.ImageName;
        return target;
    }

    std::wstring BestProcessImageName(const HuntProcessRecord& process)
    {
        std::wstring image = process.KernelImageName;

        if (image.empty())
        {
            image = process.ToolhelpImageName;
        }
        if (image.empty())
        {
            image = process.SystemProcessImageName;
        }
        if (image.empty())
        {
            image = LeafName(process.ApiImagePath);
        }
        if (image.empty())
        {
            image = LeafName(process.PebImagePath);
        }

        return image;
    }

    std::wstring BestProcessImagePath(const HuntProcessRecord& process)
    {
        std::wstring path = process.ApiImagePath;

        if (path.empty())
        {
            path = process.PebImagePath;
        }
        if (path.empty())
        {
            path = process.DiskPath;
        }

        return path;
    }

    bool QueryVersionString(
        const std::vector<uint8_t>& buffer,
        WORD language,
        WORD codePage,
        const std::wstring& name,
        std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            wchar_t subBlock[128] = {};
            swprintf_s(
                subBlock,
                L"\\StringFileInfo\\%04x%04x\\%s",
                language,
                codePage,
                name.c_str());

            wchar_t* rawValue = nullptr;
            UINT rawSize = 0;
            if (!VerQueryValueW(
                    const_cast<uint8_t*>(buffer.data()),
                    subBlock,
                    reinterpret_cast<LPVOID*>(&rawValue),
                    &rawSize) ||
                rawValue == nullptr ||
                rawSize == 0)
            {
                break;
            }

            value->assign(rawValue);
            ok = true;
        } while (false);

        return ok;
    }

    void ReadVersionString(
        const std::vector<uint8_t>& buffer,
        const std::vector<VersionTranslation>& translations,
        const std::wstring& name,
        std::wstring* value)
    {
        do
        {
            if (value == nullptr)
            {
                break;
            }

            value->clear();
            for (const VersionTranslation& translation : translations)
            {
                if (QueryVersionString(buffer, translation.Language, translation.CodePage, name, value))
                {
                    break;
                }
            }

            if (!value->empty())
            {
                break;
            }

            static const VersionTranslation kFallbacks[] =
            {
                {0x0409, 1200},
                {0x0409, 1252}
            };

            for (const VersionTranslation& fallback : kFallbacks)
            {
                if (QueryVersionString(buffer, fallback.Language, fallback.CodePage, name, value))
                {
                    break;
                }
            }
        } while (false);
    }

    bool ReadImageVersionMetadata(const std::wstring& path, ImageMetadataRecord* metadata)
    {
        bool ok = false;

        do
        {
            if (metadata == nullptr || path.empty())
            {
                break;
            }

            DWORD handle = 0;
            DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
            if (size == 0)
            {
                break;
            }

            std::vector<uint8_t> buffer(size);
            if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data()))
            {
                break;
            }

            VS_FIXEDFILEINFO* info = nullptr;
            UINT infoSize = 0;
            if (VerQueryValueW(
                    buffer.data(),
                    L"\\",
                    reinterpret_cast<LPVOID*>(&info),
                    &infoSize) &&
                info != nullptr &&
                infoSize >= sizeof(VS_FIXEDFILEINFO) &&
                info->dwSignature == VS_FFI_SIGNATURE)
            {
                std::wstringstream version;
                version << HIWORD(info->dwFileVersionMS)
                        << L"."
                        << LOWORD(info->dwFileVersionMS)
                        << L"."
                        << HIWORD(info->dwFileVersionLS)
                        << L"."
                        << LOWORD(info->dwFileVersionLS);
                metadata->FileVersion = version.str();
            }

            std::vector<VersionTranslation> translations;
            VersionTranslation* translationData = nullptr;
            UINT translationSize = 0;
            if (VerQueryValueW(
                    buffer.data(),
                    L"\\VarFileInfo\\Translation",
                    reinterpret_cast<LPVOID*>(&translationData),
                    &translationSize) &&
                translationData != nullptr)
            {
                size_t count = translationSize / sizeof(VersionTranslation);
                for (size_t index = 0; index < count; ++index)
                {
                    translations.push_back(translationData[index]);
                }
            }

            ReadVersionString(buffer, translations, L"CompanyName", &metadata->CompanyName);
            ReadVersionString(buffer, translations, L"ProductName", &metadata->ProductName);
            ReadVersionString(buffer, translations, L"OriginalFilename", &metadata->OriginalFilename);
            ReadVersionString(buffer, translations, L"FileDescription", &metadata->FileDescription);
            metadata->VersionInfoPresent = true;
            ok = true;
        } while (false);

        return ok;
    }

    BOOL CALLBACK HuntIconResourceNameCallback(HMODULE, LPCWSTR, LPWSTR, LONG_PTR parameter)
    {
        if (parameter != 0)
        {
            bool* found = reinterpret_cast<bool*>(parameter);
            *found = true;
        }

        return FALSE;
    }

    bool ImageHasGroupIconResource(const std::wstring& path)
    {
        bool present = false;
        HMODULE module = nullptr;

        do
        {
            if (path.empty())
            {
                break;
            }

            module = LoadLibraryExW(
                path.c_str(),
                nullptr,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (module == nullptr)
            {
                break;
            }

            EnumResourceNamesW(
                module,
                RT_GROUP_ICON,
                HuntIconResourceNameCallback,
                reinterpret_cast<LONG_PTR>(&present));
        } while (false);

        if (module != nullptr)
        {
            FreeLibrary(module);
        }

        return present;
    }

    bool IsNoAuthenticodeSignatureStatus(LONG status)
    {
        return status == static_cast<LONG>(TRUST_E_NOSIGNATURE) ||
            status == static_cast<LONG>(TRUST_E_SUBJECT_FORM_UNKNOWN) ||
            status == static_cast<LONG>(TRUST_E_PROVIDER_UNKNOWN);
    }

    bool VerifyImageAuthenticodeSignature(const std::wstring& path, ImageMetadataRecord* metadata)
    {
        bool checked = false;
        HMODULE wintrust = nullptr;

        typedef LONG (WINAPI* WinVerifyTrustFn)(HWND, GUID*, LPVOID);

        do
        {
            if (metadata == nullptr || path.empty())
            {
                break;
            }

            wintrust = LoadLibraryW(L"wintrust.dll");
            if (wintrust == nullptr)
            {
                break;
            }

            WinVerifyTrustFn verify =
                reinterpret_cast<WinVerifyTrustFn>(GetProcAddress(wintrust, "WinVerifyTrust"));
            if (verify == nullptr)
            {
                break;
            }

            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = path.c_str();

            WINTRUST_DATA data = {};
            data.cbStruct = sizeof(data);
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.pFile = &fileInfo;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            GUID action =
            {
                0x00aac56b,
                0xcd44,
                0x11d0,
                {0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}
            };

            LONG status = verify(nullptr, &action, &data);
            metadata->SignatureStatus = status;
            metadata->SignatureChecked = true;
            metadata->SignatureValid = status == ERROR_SUCCESS;
            metadata->SignaturePresent = metadata->SignatureValid || !IsNoAuthenticodeSignatureStatus(status);
            checked = true;
        } while (false);

        if (wintrust != nullptr)
        {
            FreeLibrary(wintrust);
        }

        return checked;
    }

    std::wstring PackerFamilyFromSectionName(const std::wstring& name)
    {
        std::wstring family;

        do
        {
            std::wstring lowered = HuntToLower(name);
            if (lowered.find(L"themida") != std::wstring::npos ||
                lowered.find(L"winlice") != std::wstring::npos)
            {
                family = L"themida";
                break;
            }

            if (lowered.find(L"enigma") != std::wstring::npos)
            {
                family = L"enigma";
                break;
            }
        } while (false);

        return family;
    }

    void ReadImagePeSectionEvidence(const std::wstring& path, ImageMetadataRecord* metadata)
    {
        do
        {
            if (metadata == nullptr || path.empty())
            {
                break;
            }

            DiskPeMetadata pe = {};
            std::wstring ignored;
            if (!ReadDiskPeMetadata(path, &pe, &ignored))
            {
                break;
            }

            metadata->PeMetadataRead = true;
            metadata->PeSectionCount = static_cast<uint32_t>(pe.Sections.size());

            std::vector<std::wstring> executableNames;
            std::vector<std::wstring> packerNames;
            std::vector<std::wstring> packerFamilies;
            for (const DiskPeSection& section : pe.Sections)
            {
                if (section.Executable && !section.Name.empty())
                {
                    executableNames.push_back(section.Name);
                }

                std::wstring family = PackerFamilyFromSectionName(section.Name);
                if (!family.empty())
                {
                    if (!section.Name.empty())
                    {
                        packerNames.push_back(section.Name);
                    }
                    AddUnique(&packerFamilies, family);
                }
            }

            metadata->ExecutableSectionNames = JoinWideValues(executableNames, L";");
            metadata->PackerSectionNames = JoinWideValues(packerNames, L";");
            metadata->PackerSectionHint = JoinWideValues(packerFamilies, L";");
        } while (false);
    }

    bool ReadImageMetadataForPath(const std::wstring& rawPath, ImageMetadataRecord* metadata)
    {
        bool ok = false;

        do
        {
            if (metadata == nullptr || rawPath.empty())
            {
                break;
            }

            *metadata = ImageMetadataRecord{};
            std::wstring path = DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(rawPath));
            if (path.empty())
            {
                break;
            }

            DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                break;
            }

            metadata->FilePath = path;
            ReadImageVersionMetadata(path, metadata);
            VerifyImageAuthenticodeSignature(path, metadata);
            metadata->IconResourcePresent = ImageHasGroupIconResource(path);
            ReadImagePeSectionEvidence(path, metadata);
            ok = metadata->VersionInfoPresent ||
                metadata->SignatureChecked ||
                metadata->IconResourcePresent ||
                metadata->PeMetadataRead;
        } while (false);

        return ok;
    }

    void AddImageMetadataEvidence(
        const std::wstring& rawPath,
        bool addVersionIconReasons,
        std::vector<std::wstring>* reasons,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (reasons == nullptr || evidence == nullptr || rawPath.empty())
            {
                break;
            }

            ImageMetadataRecord metadata = {};
            if (!ReadImageMetadataForPath(rawPath, &metadata))
            {
                break;
            }

            (*evidence)[L"image_metadata_path"] = metadata.FilePath;
            (*evidence)[L"image_version_info_present"] = metadata.VersionInfoPresent ? L"true" : L"false";
            (*evidence)[L"image_file_version"] = metadata.FileVersion;
            (*evidence)[L"image_company_name"] = metadata.CompanyName;
            (*evidence)[L"image_product_name"] = metadata.ProductName;
            (*evidence)[L"image_original_filename"] = metadata.OriginalFilename;
            (*evidence)[L"image_file_description"] = metadata.FileDescription;
            (*evidence)[L"image_icon_resource_present"] = metadata.IconResourcePresent ? L"true" : L"false";
            (*evidence)[L"image_signature_checked"] = metadata.SignatureChecked ? L"true" : L"false";
            (*evidence)[L"image_signature_present"] = metadata.SignaturePresent ? L"true" : L"false";
            (*evidence)[L"image_signature_valid"] = metadata.SignatureValid ? L"true" : L"false";
            (*evidence)[L"image_signature_status"] = HuntHex(static_cast<uint32_t>(metadata.SignatureStatus), 8);
            (*evidence)[L"image_pe_metadata_read"] = metadata.PeMetadataRead ? L"true" : L"false";
            (*evidence)[L"image_pe_section_count"] = std::to_wstring(metadata.PeSectionCount);
            (*evidence)[L"image_executable_section_names"] = metadata.ExecutableSectionNames;
            (*evidence)[L"image_packer_section_hint"] = metadata.PackerSectionHint;
            (*evidence)[L"image_packer_section_names"] = metadata.PackerSectionNames;

            if (metadata.SignaturePresent && !metadata.SignatureValid)
            {
                AddUnique(reasons, L"edr_killer_invalid_code_signature");
            }
            if (addVersionIconReasons && metadata.VersionInfoPresent)
            {
                AddUnique(reasons, L"edr_killer_version_info_impersonation_evidence");
            }
            if (addVersionIconReasons && metadata.IconResourcePresent)
            {
                AddUnique(reasons, L"edr_killer_icon_impersonation_evidence");
            }
            if (addVersionIconReasons && !metadata.PackerSectionNames.empty())
            {
                AddUnique(reasons, L"edr_killer_packer_section_evidence");
            }
        } while (false);
    }

    std::vector<std::wstring> ExpectedPathsForBuiltinProfile(
        const BuiltinProcessProfile& profile,
        const std::wstring& leaf)
    {
        std::vector<std::wstring> expected;

        if (profile.System32)
        {
            expected.push_back(ExpectedSystem32Path(leaf));
        }
        if (profile.SysWow64)
        {
            expected.push_back(ExpectedSysWow64Path(leaf));
        }
        if (profile.WindowsRoot)
        {
            expected.push_back(ExpectedWindowsRootPath(leaf));
        }

        return expected;
    }

    void ApplyBuiltinProfile(HuntProcessRecord* process)
    {
        do
        {
            if (process == nullptr)
            {
                break;
            }

            process->BuiltinProfile.clear();
            process->BuiltinProfileMatched = false;
            process->BuiltinSignatureVerified = false;
            process->BuiltinProfileExpectedPaths.clear();
            process->BuiltinProfileViolations.clear();

            bool labProfile = IsHuntLabBuiltinProfile(*process);
            std::wstring leaf = LeafName(BestProcessImageName(*process));
            const BuiltinProcessProfile* profile = nullptr;
            if (!labProfile)
            {
                profile = FindBuiltinProfileByLeaf(leaf);
            }

            if (profile == nullptr && !labProfile)
            {
                break;
            }

            process->BuiltinProfileMatched = true;
            process->BuiltinProfile = labProfile ? L"hunt_lab_builtin_profile" : leaf;

            if (labProfile)
            {
                process->BuiltinProfileExpectedPaths.push_back(ExpectedSystem32Path(L"KnLiveDbgHuntTarget.exe"));
            }
            else
            {
                process->BuiltinProfileExpectedPaths = ExpectedPathsForBuiltinProfile(*profile, leaf);
            }

            std::wstring actualPath = BestProcessImagePath(*process);
            if (!actualPath.empty() &&
                !MatchesAnyCanonicalPath(actualPath, process->BuiltinProfileExpectedPaths))
            {
                AddUnique(&process->BuiltinProfileViolations, L"path_mismatch");
            }

            if (profile != nullptr && profile->SessionZeroOnly && process->HasSessionId && process->SessionId != 0)
            {
                AddUnique(&process->BuiltinProfileViolations, L"session_mismatch");
            }

            if (profile != nullptr &&
                profile->ParentNameCount != 0 &&
                !process->ParentImageName.empty())
            {
                std::wstring parentLeaf = LeafName(process->ParentImageName);
                bool parentMatched = false;
                for (size_t index = 0; index < profile->ParentNameCount; ++index)
                {
                    if (parentLeaf == profile->ParentNames[index])
                    {
                        parentMatched = true;
                        break;
                    }
                }

                if (!parentMatched)
                {
                    AddUnique(&process->BuiltinProfileViolations, L"parent_mismatch");
                }
            }

            if (profile != nullptr &&
                profile->SvchostCommandLine &&
                !process->PebCommandLine.empty())
            {
                std::wstring commandLine = HuntToLower(process->PebCommandLine);
                if (commandLine.find(L" -k ") == std::wstring::npos &&
                    commandLine.find(L" -k") == std::wstring::npos &&
                    commandLine.find(L"\t-k") == std::wstring::npos)
                {
                    AddUnique(&process->BuiltinProfileViolations, L"command_line_mismatch");
                }
            }
        } while (false);
    }

    void AddBuiltinEvidence(
        const HuntProcessRecord& process,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (evidence == nullptr || !process.BuiltinProfileMatched)
            {
                break;
            }

            (*evidence)[L"builtin_profile"] = process.BuiltinProfile;
            (*evidence)[L"builtin_profile_matched"] = L"true";
            (*evidence)[L"builtin_profile_expected_paths"] = JoinWideValues(process.BuiltinProfileExpectedPaths, L";");
            (*evidence)[L"builtin_profile_violations"] = JoinWideValues(process.BuiltinProfileViolations, L";");
        } while (false);
    }

    void AddBuiltinInjectionReasonIfNeeded(
        const HuntProcessRecord& process,
        std::vector<std::wstring>* reasons,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (!process.BuiltinProfileMatched || reasons == nullptr)
            {
                break;
            }

            AddUnique(reasons, L"builtin_process_injection_evidence");
            AddBuiltinEvidence(process, evidence);
        } while (false);
    }

    void AddFinding(
        HuntResult* result,
        const HuntProcessRecord& process,
        const std::wstring& risk,
        const std::wstring& confidence,
        const std::wstring& className,
        const std::wstring& title,
        uint64_t address,
        const std::wstring& moduleName,
        const std::vector<std::wstring>& reasons,
        const std::map<std::wstring, std::wstring>& evidence)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            HuntFinding finding = {};
            finding.Risk = SnapshotRiskNormalize(risk);
            finding.Confidence = confidence;
            finding.ClassName = className;
            finding.Title = title;
            finding.ProcessId = process.ProcessId;
            finding.Eprocess = process.Kernel.Eprocess;
            finding.Address = address;
            finding.ImageName = !process.KernelImageName.empty() ? process.KernelImageName : process.ToolhelpImageName;
            finding.ModuleName = moduleName;
            finding.ReasonCodes = reasons;
            finding.Evidence = evidence;

            std::wstring target = process.Kernel.Eprocess != 0
                ? HuntHex(process.Kernel.Eprocess, 16)
                : std::to_wstring(process.ProcessId);
            if (process.Kernel.Eprocess != 0)
            {
                finding.Followups.push_back(L"!vad " + target + L" /pe /hiddenpte /limit 40");
                finding.Followups.push_back(L"!threads " + target + L" /apc /stacks /limit 40");
            }
            if (address != 0)
            {
                finding.Followups.push_back(L"!address " + HuntHex(address, 16));
            }
            finding.Followups.push_back(L"!dml_proc " + std::to_wstring(process.ProcessId));

            result->Findings.push_back(std::move(finding));
        } while (false);
    }

    void AddSystemFinding(
        HuntResult* result,
        const std::wstring& risk,
        const std::wstring& confidence,
        const std::wstring& className,
        const std::wstring& title,
        uint64_t address,
        const std::wstring& moduleName,
        const std::vector<std::wstring>& reasons,
        const std::map<std::wstring, std::wstring>& evidence,
        const std::vector<std::wstring>& followups)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            HuntFinding finding = {};
            finding.Risk = SnapshotRiskNormalize(risk);
            finding.Confidence = confidence;
            finding.ClassName = className;
            finding.Title = title;
            finding.Address = address;
            finding.ModuleName = moduleName;
            finding.ReasonCodes = reasons;
            finding.Evidence = evidence;
            finding.Followups = followups;

            result->Findings.push_back(std::move(finding));
        } while (false);
    }

    std::wstring ByovdMatchEvidenceText(const std::vector<ByovdMatch>& matches)
    {
        std::vector<std::wstring> values;

        for (const ByovdMatch& match : matches)
        {
            if (values.size() >= kMaxByovdMatchEvidence)
            {
                break;
            }

            std::wstringstream stream;
            stream << match.Entry.Source
                   << L":"
                   << match.Entry.Category
                   << L":"
                   << match.Entry.MatchType;
            if (!match.Entry.Name.empty())
            {
                stream << L":"
                       << match.Entry.Name;
            }
            if (!match.Confidence.empty())
            {
                stream << L":"
                       << match.Confidence;
            }
            values.push_back(stream.str());
        }

        return JoinWideValues(values, L";");
    }

    bool HasHighConfidenceByovdMatch(const std::vector<ByovdMatch>& matches)
    {
        bool high = false;

        for (const ByovdMatch& match : matches)
        {
            if (ConfidenceRank(match.Confidence) >= ConfidenceRank(L"high"))
            {
                high = true;
                break;
            }
        }

        return high;
    }

    void AddProcessViewFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            if (process.ProcessId <= 4)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"active_process_links_seen"] = process.ActiveProcessLinksSeen ? L"true" : L"false";
            evidence[L"system_process_information_seen"] = process.SystemProcessInformationSeen ? L"true" : L"false";
            evidence[L"toolhelp_seen"] = process.ToolhelpProcessSeen ? L"true" : L"false";
            evidence[L"cid_table_seen"] = process.HasCidTableView ? (process.CidTableSeen ? L"true" : L"false") : L"null";
            evidence[L"eprocess"] = process.Kernel.Eprocess != 0 ? HuntHex(process.Kernel.Eprocess, 16) : L"0x0";
            evidence[L"image_name"] = !process.KernelImageName.empty() ? process.KernelImageName : process.ToolhelpImageName;

            if (process.ActiveProcessLinksSeen &&
                !process.SystemProcessInformationSeen &&
                !process.ToolhelpProcessSeen)
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_cross_view",
                    L"process is visible in ActiveProcessLinks but missing from user API views",
                    0,
                    L"",
                    {L"kernel_only_process", L"process_view_mismatch"},
                    evidence);
            }
            else if (!process.ActiveProcessLinksSeen &&
                     process.SystemProcessInformationSeen &&
                     process.ToolhelpProcessSeen)
            {
                evidence[L"snapshot_race_possible"] = L"true";
                AddFinding(
                    result,
                    process,
                    L"low",
                    L"low",
                    L"process_cross_view",
                    L"process is visible through user API views but missing from ActiveProcessLinks",
                    0,
                    L"",
                    {L"api_only_process", L"missing_from_active_process_links"},
                    evidence);
            }
            else if (process.ActiveProcessLinksSeen &&
                     (!process.SystemProcessInformationSeen || !process.ToolhelpProcessSeen))
            {
                evidence[L"snapshot_race_possible"] = L"true";
                AddFinding(
                    result,
                    process,
                    L"info",
                    L"low",
                    L"process_cross_view",
                    L"process has a partial cross-view mismatch",
                    0,
                    L"",
                    {L"process_view_mismatch"},
                    evidence);
            }
        } while (false);
    }

    void AddIdentityFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"eprocess_image"] = process.KernelImageName;
            evidence[L"system_process_image"] = process.SystemProcessImageName;
            evidence[L"toolhelp_image"] = process.ToolhelpImageName;
            evidence[L"api_image_path"] = process.ApiImagePath;
            if (process.HasPebImageBase)
            {
                evidence[L"peb_image_base"] = HuntHex(process.PebImageBase, 16);
            }
            evidence[L"peb_image_path"] = process.PebImagePath;
            evidence[L"peb_command_line"] = process.PebCommandLine;
            std::wstring commandImage = FirstCommandLineImage(process.PebCommandLine);
            evidence[L"peb_command_image"] = commandImage;
            if (process.HasParentProcessId)
            {
                evidence[L"parent_pid"] = std::to_wstring(process.ParentProcessId);
            }
            if (process.HasSessionId)
            {
                evidence[L"session_id"] = std::to_wstring(process.SessionId);
            }
            if (!process.ParentImageName.empty())
            {
                evidence[L"parent_image"] = process.ParentImageName;
            }
            AddBuiltinEvidence(process, &evidence);

            if (!process.KernelImageName.empty() &&
                !process.ApiImagePath.empty() &&
                !SameNonEmptyLeaf(process.KernelImageName, process.ApiImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_identity",
                    L"EPROCESS image name and resolved image path disagree",
                    0,
                    L"",
                    {L"image_name_mismatch", L"image_path_mismatch"},
                    evidence);
            }

            if (!process.KernelImageName.empty() &&
                !process.PebImagePath.empty() &&
                !SameNonEmptyLeaf(process.KernelImageName, process.PebImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"medium",
                    L"medium",
                    L"process_identity",
                    L"EPROCESS image name and PEB image path disagree",
                    0,
                    L"",
                    {L"image_name_mismatch", L"peb_image_path_mismatch"},
                    evidence);
            }

            if (!process.PebImagePath.empty() &&
                !commandImage.empty() &&
                !SameNonEmptyLeaf(process.PebImagePath, commandImage))
            {
                AddFinding(
                    result,
                    process,
                    L"low",
                    L"low",
                    L"process_identity",
                    L"PEB image path and command line first path disagree",
                    0,
                    L"",
                    {L"command_line_path_mismatch"},
                    evidence);
            }

            if (process.BuiltinProfileMatched && !process.BuiltinProfileViolations.empty())
            {
                std::vector<std::wstring> reasons;
                for (const std::wstring& violation : process.BuiltinProfileViolations)
                {
                    if (violation == L"path_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_path_mismatch");
                        AddUnique(&reasons, L"system_name_from_non_system_path");
                    }
                    else if (violation == L"parent_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_parent_mismatch");
                    }
                    else if (violation == L"session_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_session_mismatch");
                    }
                    else if (violation == L"command_line_mismatch")
                    {
                        AddUnique(&reasons, L"builtin_profile_command_line_mismatch");
                    }
                }

                if (!reasons.empty())
                {
                    AddFinding(
                        result,
                        process,
                        std::find(reasons.begin(), reasons.end(), L"builtin_profile_path_mismatch") != reasons.end() ? L"high" : L"medium",
                        L"medium",
                        L"process_masquerade",
                        L"process violates built-in Windows process profile",
                        0,
                        L"",
                        reasons,
                        evidence);
                }
            }

            if (!process.ApiImagePath.empty() && IsSystemNameFromNonSystemPath(process.ApiImagePath))
            {
                AddFinding(
                    result,
                    process,
                    L"high",
                    L"medium",
                    L"process_masquerade",
                    L"system process name is running from a non-system directory",
                    0,
                    L"",
                    {L"system_name_from_non_system_path"},
                    evidence);
            }
        } while (false);
    }

    void AddEdrKillerProcessProfileFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr || process.ProcessId <= 4)
            {
                break;
            }

            std::wstring imageName = BestProcessImageName(process);
            std::wstring imagePath = BestProcessImagePath(process);
            std::wstring matchedLeaf;
            bool suffixNormalized = false;
            std::wstring normalizedBase;
            bool suffixContextRequired = false;
            std::wstring suffixTail;
            const EdrKillerProcessProfile* profile =
                FindEdrKillerProcessProfileForProcess(
                    process,
                    &matchedLeaf,
                    &suffixNormalized,
                    &normalizedBase,
                    &suffixContextRequired,
                    &suffixTail);
            bool gentlemenStagingPath =
                PathContainsGentlemenCollection(imagePath) ||
                PathContainsGentlemenCollection(process.PebCommandLine);
            std::wstring oxideHarvestCliOptions;
            bool oxideHarvestCliShape = profile != nullptr &&
                profile->CredentialTool &&
                OxideHarvestCommandLineShape(process.PebCommandLine, &oxideHarvestCliOptions);
            if (profile == nullptr && !gentlemenStagingPath)
            {
                break;
            }
            if (suffixContextRequired && !gentlemenStagingPath)
            {
                break;
            }
            if (profile != nullptr && !profile->StrongNameSignal && !gentlemenStagingPath)
            {
                break;
            }
            if (profile != nullptr &&
                profile->CredentialTool &&
                !gentlemenStagingPath &&
                !oxideHarvestCliShape)
            {
                break;
            }

            std::vector<std::wstring> reasons;
            std::map<std::wstring, std::wstring> evidence;

            evidence[L"image_name"] = imageName;
            evidence[L"image_path"] = imagePath;
            evidence[L"peb_image_path"] = process.PebImagePath;
            evidence[L"peb_command_line"] = process.PebCommandLine;

            if (profile != nullptr)
            {
                AddUnique(&reasons, profile->CredentialTool
                    ? L"gentlemen_related_credential_tool_name"
                    : L"gentlemen_edr_killer_process_name");
                evidence[L"gentlemen_family"] = profile->Family;
                evidence[L"gentlemen_tool"] = profile->Tool;
                evidence[L"gentlemen_ioc_image"] = profile->ImageName;
                evidence[L"matched_image_leaf"] = matchedLeaf;
                evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";
                evidence[L"suffix_normalized_ioc"] = suffixNormalized ? L"true" : L"false";
                evidence[L"suffix_context_required"] = suffixContextRequired ? L"true" : L"false";
                if (suffixNormalized)
                {
                    AddUnique(&reasons, L"gentlemen_suffix_normalized_process_name");
                    evidence[L"normalized_ioc_base"] = normalizedBase;
                    AddGentlemenSuffixEvidence(suffixTail, &evidence);
                }
                if (!profile->StrongNameSignal)
                {
                    AddUnique(&reasons, L"security_vendor_impersonation_name");
                }
                if (profile->CredentialTool)
                {
                    if (oxideHarvestCliShape)
                    {
                        AddUnique(&reasons, L"oxideharvest_cli_shape");
                        evidence[L"oxideharvest_cli_options"] = oxideHarvestCliOptions;
                    }
                }
            }

            if (gentlemenStagingPath)
            {
                AddUnique(&reasons, L"gentlemen_collection_staging_path");
                evidence[L"gentlemen_collection_path"] = L"true";
            }

            AddImageMetadataEvidence(
                imagePath,
                profile != nullptr || gentlemenStagingPath,
                &reasons,
                &evidence);

            if (reasons.empty())
            {
                break;
            }

            std::wstring risk = L"low";
            std::wstring confidence = L"low";
            if (gentlemenStagingPath && profile != nullptr)
            {
                risk = L"high";
                confidence = L"high";
            }
            else if (profile != nullptr && profile->StrongNameSignal)
            {
                risk = L"medium";
                confidence = L"high";
            }
            else if (gentlemenStagingPath)
            {
                risk = L"medium";
                confidence = L"medium";
            }
            else
            {
                risk = L"low";
                confidence = L"medium";
            }

            AddFinding(
                result,
                process,
                risk,
                confidence,
                profile != nullptr && profile->CredentialTool ? L"gentlemen_related_tool" : L"edr_killer_process_profile",
                profile != nullptr && profile->CredentialTool
                    ? L"process name matches Gentlemen-related credential tooling"
                    : L"process matches Gentlemen EDR-killer masquerade profile",
                0,
                L"",
                reasons,
                evidence);
        } while (false);
    }

    bool HuntTextContainsAny(const std::wstring& text, const std::vector<std::wstring>& needles)
    {
        bool matched = false;

        do
        {
            if (text.empty())
            {
                break;
            }

            for (const std::wstring& needle : needles)
            {
                if (!needle.empty() && text.find(needle) != std::wstring::npos)
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool HuntIsProcessLeafChar(wchar_t ch)
    {
        return std::iswalnum(ch) != 0 ||
            ch == L'_' ||
            ch == L'-' ||
            ch == L'.';
    }

    bool HuntTextContainsDelimitedProcessLeaf(
        const std::wstring& text,
        const std::wstring& leaf)
    {
        bool matched = false;

        do
        {
            if (text.empty() || leaf.empty())
            {
                break;
            }

            size_t offset = 0;
            while (offset < text.size())
            {
                size_t found = text.find(leaf, offset);
                if (found == std::wstring::npos)
                {
                    break;
                }

                size_t end = found + leaf.size();
                bool leftDelimited = found == 0 || !HuntIsProcessLeafChar(text[found - 1]);
                bool rightDelimited = end >= text.size() || !HuntIsProcessLeafChar(text[end]);
                if (leftDelimited && rightDelimited)
                {
                    matched = true;
                    break;
                }

                offset = found + 1;
            }
        } while (false);

        return matched;
    }

    std::wstring ThreatIntelActionText(const HuntTelemetryEvent& event)
    {
        std::wstring text;

        text += event.TaskName;
        text += L" ";
        text += event.OpcodeName;
        text += L" ";
        text += event.TargetImageBase;
        text += L" ";
        text += event.RawPayloadHex;

        for (const HuntTelemetryField& field : event.Payload)
        {
            text += L" ";
            text += field.Name;
            text += L"=";
            text += field.Value;
        }

        return HuntToLower(text);
    }

    std::wstring ThreatIntelFullText(const HuntTelemetryEvent& event)
    {
        std::wstring text = ThreatIntelActionText(event);
        text += L" ";
        text += HuntToLower(event.ImagePath);
        return text;
    }

    std::wstring ThreatIntelPayloadEvidenceText(const HuntTelemetryEvent& event)
    {
        std::vector<std::wstring> values;

        for (const HuntTelemetryField& field : event.Payload)
        {
            if (values.size() >= kMaxTelemetryPayloadEvidence)
            {
                break;
            }

            values.push_back(field.Name + L"=" + field.Value);
        }

        if (values.empty() && !event.RawPayloadHex.empty())
        {
            values.push_back(L"raw=" + event.RawPayloadHex);
        }

        return JoinWideValues(values, L";");
    }

    std::wstring ThreatIntelTargetPidsText(const std::set<uint32_t>& targetPids)
    {
        std::vector<std::wstring> values;

        for (uint32_t pid : targetPids)
        {
            values.push_back(std::to_wstring(pid));
        }

        return JoinWideValues(values, L";");
    }

    std::wstring ThreatIntelSecurityProductTargetsText(const std::set<std::wstring>& targetNames)
    {
        std::vector<std::wstring> values;

        for (const std::wstring& name : targetNames)
        {
            values.push_back(name);
        }

        return JoinWideValues(values, L";");
    }

    bool ThreatIntelEventTargetsKnownSecurityProduct(
        const HuntTelemetryEvent& event,
        std::wstring* matchedTarget)
    {
        bool matched = false;

        static const wchar_t* kTargets[] =
        {
            L"acronis_agent.exe", L"backupandrecoveryagent.exe", L"managementagenthost.exe", L"mms.exe",
            L"alienvault-agent.exe", L"osqueryd.exe",
            L"afwserv.exe", L"aswengsrv.exe", L"aswidsagent.exe", L"aswtoolssvc.exe", L"avastsvc.exe", L"avastui.exe", L"bccavsvc.exe", L"wsc_proxy.exe",
            L"avgui.exe", L"avgsvc.exe", L"avgnt.exe", L"avgsvca.exe", L"avgtoolssvc.exe",
            L"binarydefenseagent.exe",
            L"arrakis3.exe", L"bdavscanner.exe", L"bdfstray.exe", L"bdfileserver.exe", L"bdlived2.exe", L"bdlogger.exe", L"bdscheduler.exe", L"bdstatistics.exe", L"bdagent.exe", L"bdemsrv.exe", L"bdntwrk.exe", L"bdredline.exe", L"bdregsvr2.exe", L"bdservicehost.exe",
            L"blumiraagent.exe",
            L"bromiumdaemon.exe", L"brdifxapi.exe",
            L"cb.exe", L"cbcomms.exe", L"cbdefense.exe", L"carbonsensor.exe", L"repmgr.exe",
            L"cfrutil.exe", L"ciscoampcefwdriver.exe", L"cisco_amp_connector.exe", L"immunet.exe",
            L"arwsrvc.exe", L"arcupdate.exe", L"csfalconcontainer.exe", L"csfalconservice.exe", L"csfalconui.exe", L"csfalcondataprotect.exe", L"csfalcondaterepair.exe", L"reprsvc.exe",
            L"cyneteps.exe", L"cynetms.exe", L"cynetsvc.exe",
            L"activeconsole.exe", L"cybereason.exe", L"cybereasonactiveprobe.exe", L"cybereasoncr.exe",
            L"cyveraconsole.exe", L"cyveraservice.exe", L"cyvragentsvc.exe", L"cyvrfsflt.exe",
            L"cylancesvc.exe",
            L"darktracetsa.exe",
            L"deepinstinct.exe", L"deepinstinctservice.exe", L"diagentservice.exe",
            L"a2guard.exe", L"a2service.exe",
            L"eamonm.exe", L"eamsi.exe", L"ecls.exe", L"efwd.exe", L"egui.exe", L"eguiproxy.exe", L"ekrn.exe", L"ekrnepfw.exe", L"eraagent.exe", L"eraagentsvc.exe",
            L"firesvc.exe", L"firetray.exe", L"fortitray.exe", L"fortiedr.exe", L"fw.exe",
            L"gddserver.exe", L"qhpisvr.exe", L"quhlpsvc.exe", L"sapissvc.exe",
            L"heimdalsecurityagent.exe",
            L"huntressagent.exe", L"huntressrmm.exe",
            L"avp.exe", L"avpsus.exe", L"avpui.exe", L"kavfs.exe", L"kavfsscs.exe", L"kavfswh.exe", L"kavfswp.exe", L"kavtray.exe", L"klactprx.exe", L"klcsldcl.exe", L"klcsweb.exe", L"klnagent.exe", L"klnagchk.exe", L"klscctl.exe", L"klserver.exe", L"klwtblfs.exe", L"kpf4ss.exe", L"ksde.exe", L"ksdeui.exe", L"vapm.exe",
            L"logprocessorservice.exe",
            L"agmservice.exe", L"agsservice.exe", L"masvc.exe", L"macmnsvc.exe", L"mcafeeagent.exe", L"mcshield.exe", L"mfeann.exe", L"mfevtps.exe", L"mfetp.exe", L"mfeepehost.exe", L"mfefire.exe", L"mfemactl.exe", L"mfemacsvc.exe", L"mfemgr.exe", L"mfemms.exe", L"mgntsvc.exe", L"modulecoreservice.exe", L"tepfsvc.exe",
            L"msascui.exe", L"msascuil.exe", L"mpdefendercoreservice.exe", L"msmpeng.exe", L"msmpsvc.exe", L"mssense.exe", L"msseces.exe", L"nissrv.exe", L"securityhealthservice.exe", L"securityhealthsystray.exe", L"sensecncproxy.exe", L"senseir.exe", L"sensendr.exe", L"sensesampleuploader.exe", L"smartscreen.exe", L"windefend.exe",
            L"morphisecservice.exe",
            L"ccapp.exe", L"ccsvchst.exe", L"ns.exe", L"nsservice.exe", L"nortonsecurity.exe", L"rtvscan.exe", L"sepmasterservice.exe", L"sepwscsvc64.exe", L"smc.exe", L"smcgui.exe", L"snac.exe", L"symcorpui.exe", L"symwsc.exe",
            L"ossec-agent.exe", L"wazuh-agent.exe",
            L"cortexservice.exe", L"trapsagent.exe", L"trapsd.exe", L"traps.exe",
            L"panda_url_filtering.exe", L"pavfnsvr.exe", L"pavsrv.exe", L"psanhost.exe", L"pselamsvc.exe", L"psuamain.exe", L"psuaservice.exe", L"pangps.exe",
            L"qualys-cloud-agent.exe", L"qualysagent.exe",
            L"ir_agent.exe", L"rapid7_endpoint.exe",
            L"redcanaryagent.exe",
            L"csaagent.exe", L"csaservice.exe", L"sangforagent.exe", L"sangforcsa.exe", L"sangforedr.exe", L"sangforinterface.exe", L"sangformonitor.exe", L"sangforprotect.exe", L"sangforservice.exe", L"sangfortray.exe", L"sangforud.exe",
            L"sentinel.exe", L"sentinelagent.exe", L"sentinelagentworker.exe", L"sentinelctl.exe", L"sentinelhelperservice.exe", L"sentinelmemoryscanner.exe", L"sentinelpowershellextension.exe", L"sentinelranger.exe", L"sentinelservicehost.exe", L"sentinelstaticengine.exe", L"sentinelstaticenginescanner.exe", L"sentinelui.exe",
            L"sonicwallclientprotectionservice.exe", L"swc_service.exe",
            L"hmpalert.exe", L"mcsagent.exe", L"mcsclient.exe", L"savapi.exe", L"savadminservice.exe", L"savservice.exe", L"sedservice.exe", L"sophosadsyncservice.exe", L"sophosclean.exe", L"sophoscleanm64.exe", L"sophosfimservice.exe", L"sophosfs.exe", L"sophoshealth.exe", L"sophoslivequeryservice.exe", L"sophosmtr.exe", L"sophosmtrextension.exe", L"sophosnetfilter.exe", L"sophosntpservice.exe", L"sophososquery.exe", L"sophososqueryextension.exe", L"sophos.policyevaluation.service.exe", L"sophossafestore64.exe", L"sophosui.exe", L"sophosupdatemgr.exe", L"sophosav.exe", L"sophossps.exe", L"sspservice.exe",
            L"taniumclient.exe", L"taniumcx.exe", L"tanclient.exe",
            L"threatlockerconsent.exe", L"threatlockerservice.exe", L"threatlockertray.exe",
            L"coreframeworkhost.exe", L"coreserviceshell.exe", L"ntrtscan.exe", L"ofcservice.exe", L"ofcddasvr.exe", L"pccntmon.exe", L"pccnt.exe", L"tisafe.exe", L"tisafesvc.exe", L"tmccsf.exe", L"tmicagentsetting.exe", L"tmbmsrv.exe", L"tm_netsrv.exe", L"tmlisten.exe", L"tmntsrv.exe", L"tmpfw.exe", L"tmproxy.exe", L"tmprefilter.exe", L"tmssclient.exe", L"tmsainstance64.exe", L"tmwscsvc.exe", L"voneagentconsole.exe", L"voneagentconsoletray.exe",
            L"vectoragent.exe", L"uptycsagent.exe",
            L"datadvantage.exe", L"varonisagent.exe",
            L"wlcsservice.exe",
            L"wrsa.exe", L"wrskyclient.exe", L"wrsvc.exe",
            L"sysmon.exe", L"sysmon64.exe",
            L"zlclient.exe"
        };

        do
        {
            std::wstring targetLeaf = LeafName(event.TargetImageBase);
            std::wstring text = ThreatIntelActionText(event);

            for (const wchar_t* target : kTargets)
            {
                if (target == nullptr || target[0] == L'\0')
                {
                    continue;
                }

                std::wstring targetName = HuntToLower(target);
                if (targetLeaf == targetName ||
                    (targetName.size() >= 8 && HuntTextContainsDelimitedProcessLeaf(text, targetName)))
                {
                    if (matchedTarget != nullptr)
                    {
                        *matchedTarget = targetName;
                    }
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool ThreatIntelEventLooksLikeDriverIo(const HuntTelemetryEvent& event)
    {
        bool matched = false;

        do
        {
            std::wstring text = ThreatIntelActionText(event);
            if (HuntTextContainsAny(
                    text,
                    {
                        L"deviceiocontrol",
                        L"ntdeviceiocontrolfile",
                        L"ioctl",
                        L"io_control",
                        L"i/o control",
                        L"irp_mj_device_control",
                        L"driverobject",
                        L"driver object",
                        L"deviceobject",
                        L"device object",
                        L"fileobject",
                        L"file object",
                        L"\\device\\"
                    }))
            {
                matched = true;
                break;
            }

            std::wstring task = HuntToLower(event.TaskName);
            if (task.find(L"driver") != std::wstring::npos ||
                task.find(L"device") != std::wstring::npos)
            {
                matched = true;
                break;
            }
        } while (false);

        return matched;
    }

    bool ThreatIntelEventLooksLikeProcessImpairment(const HuntTelemetryEvent& event)
    {
        bool matched = false;

        do
        {
            std::wstring text = ThreatIntelActionText(event);
            if (HuntTextContainsAny(
                    text,
                    {
                        L"terminateprocess",
                        L"ntterminateprocess",
                        L"zwterminateprocess",
                        L"process_terminate",
                        L"process terminate",
                        L"terminate process",
                        L"processdelete",
                        L"process delete",
                        L"processstop",
                        L"process stop"
                    }))
            {
                matched = true;
                break;
            }

            if (event.TargetProcessId != 0 &&
                HuntTextContainsAny(
                    text,
                    {
                        L"terminate",
                        L"openprocess",
                        L"process access",
                        L"desiredaccess"
                    }))
            {
                matched = true;
                break;
            }
        } while (false);

        return matched;
    }

    bool ThreatIntelProfileIsActionable(
        const EdrKillerProcessProfile* profile,
        bool gentlemenStagingPath)
    {
        bool actionable = false;

        do
        {
            if (profile != nullptr && profile->CredentialTool)
            {
                break;
            }

            if (gentlemenStagingPath)
            {
                actionable = true;
                break;
            }

            if (profile != nullptr && profile->StrongNameSignal)
            {
                actionable = true;
                break;
            }
        } while (false);

        return actionable;
    }

    void AddThreatIntelTelemetryFinding(
        HuntResult* result,
        const ThreatIntelCorrelationBucket& bucket,
        const HuntTelemetryEvent& sample,
        const std::wstring& className,
        const std::wstring& title,
        const std::wstring& risk,
        const std::wstring& confidence,
        const std::vector<std::wstring>& actionReasons,
        uint64_t actionCount)
    {
        do
        {
            if (result == nullptr || actionCount == 0)
            {
                break;
            }

            std::vector<std::wstring> reasons;
            if (bucket.Profile != nullptr)
            {
                AddUnique(&reasons, L"gentlemen_edr_killer_process_name");
            }
            if (bucket.GentlemenStagingPath)
            {
                AddUnique(&reasons, L"gentlemen_collection_staging_path");
            }
            if (bucket.SuffixNormalizedProfile)
            {
                AddUnique(&reasons, L"gentlemen_suffix_normalized_process_name");
            }
            for (const std::wstring& reason : actionReasons)
            {
                AddUnique(&reasons, reason);
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"caller_pid"] = std::to_wstring(bucket.ProcessId);
            evidence[L"caller_image"] = bucket.ImageName;
            evidence[L"caller_image_path"] = bucket.ImagePath;
            evidence[L"matched_image_leaf"] = bucket.MatchedLeaf;
            evidence[L"gentlemen_collection_path"] = bucket.GentlemenStagingPath ? L"true" : L"false";
            evidence[L"suffix_normalized_ioc"] = bucket.SuffixNormalizedProfile ? L"true" : L"false";
            evidence[L"suffix_context_required"] = bucket.SuffixContextRequired ? L"true" : L"false";
            evidence[L"normalized_ioc_base"] = bucket.NormalizedProfileBase;
            if (bucket.SuffixNormalizedProfile)
            {
                AddGentlemenSuffixEvidence(bucket.SuffixTail, &evidence);
            }
            evidence[L"ti_event_count"] = std::to_wstring(actionCount);
            evidence[L"ti_sample_timestamp"] = std::to_wstring(sample.Timestamp);
            evidence[L"ti_sample_task"] = sample.TaskName;
            evidence[L"ti_sample_task_id"] = std::to_wstring(sample.TaskId);
            evidence[L"ti_sample_opcode"] = sample.OpcodeName;
            evidence[L"ti_sample_opcode_id"] = std::to_wstring(sample.Opcode);
            evidence[L"ti_sample_payload"] = ThreatIntelPayloadEvidenceText(sample);
            evidence[L"target_pid_count"] = std::to_wstring(bucket.TargetProcessIds.size());
            evidence[L"target_pids"] = ThreatIntelTargetPidsText(bucket.TargetProcessIds);
            evidence[L"security_product_target_count"] = std::to_wstring(bucket.SecurityProductTargetNames.size());
            evidence[L"security_product_targets"] =
                ThreatIntelSecurityProductTargetsText(bucket.SecurityProductTargetNames);
            if (sample.TargetProcessId != 0)
            {
                evidence[L"sample_target_pid"] = std::to_wstring(sample.TargetProcessId);
                evidence[L"sample_target_image"] = sample.TargetImageBase;
            }
            if (bucket.Profile != nullptr)
            {
                evidence[L"gentlemen_family"] = bucket.Profile->Family;
                evidence[L"gentlemen_tool"] = bucket.Profile->Tool;
                evidence[L"gentlemen_ioc_image"] = bucket.Profile->ImageName;
                evidence[L"strong_name_signal"] = bucket.Profile->StrongNameSignal ? L"true" : L"false";
            }

            AddImageMetadataEvidence(
                bucket.ImagePath,
                bucket.Profile != nullptr ||
                    bucket.GentlemenStagingPath ||
                    bucket.SuffixNormalizedProfile,
                &reasons,
                &evidence);

            HuntFinding finding = {};
            finding.Risk = SnapshotRiskNormalize(risk);
            finding.Confidence = confidence;
            finding.ClassName = className;
            finding.Title = title;
            finding.ProcessId = bucket.ProcessId;
            finding.Eprocess = bucket.Eprocess;
            finding.ImageName = bucket.ImageName;
            finding.ReasonCodes = reasons;
            finding.Evidence = evidence;
            if (bucket.Eprocess != 0)
            {
                std::wstring target = HuntHex(bucket.Eprocess, 16);
                finding.Followups.push_back(L"!vad " + target + L" /pe /hiddenpte /limit 40");
                finding.Followups.push_back(L"!threads " + target + L" /apc /stacks /limit 40");
            }
            finding.Followups.push_back(L"!ti by pid " + std::to_wstring(bucket.ProcessId));
            if (className == L"edr_killer_driver_io_telemetry")
            {
                finding.Followups.push_back(L"!ti grep DeviceIoControl");
                finding.Followups.push_back(L"!driver integrity all /limit 200");
            }
            else
            {
                finding.Followups.push_back(L"!ti grep TerminateProcess");
                finding.Followups.push_back(L"!ti grep OpenProcess");
            }
            finding.Followups.push_back(L"!ti save .\\hunt-ti-events.jsonl");

            result->Findings.push_back(std::move(finding));
            ++result->ThreatIntelCorrelationCount;
        } while (false);
    }

    void AddThreatIntelCorrelationFindings(
        HuntResult* result,
        const std::map<uint32_t, HuntProcessRecord>& processes,
        const HuntOptions& options)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            result->ThreatIntelEventCount = options.ThreatIntelEvents.size();
            if (options.ThreatIntelEvents.empty())
            {
                break;
            }

            std::map<uint32_t, ThreatIntelCorrelationBucket> buckets;
            for (const HuntTelemetryEvent& event : options.ThreatIntelEvents)
            {
                if (event.ProcessId <= 4)
                {
                    continue;
                }

                bool driverIo = ThreatIntelEventLooksLikeDriverIo(event);
                bool processImpairment = ThreatIntelEventLooksLikeProcessImpairment(event);
                if (!driverIo && !processImpairment)
                {
                    continue;
                }
                std::wstring securityProductTarget;
                bool securityProductImpairment =
                    processImpairment &&
                    ThreatIntelEventTargetsKnownSecurityProduct(event, &securityProductTarget);

                const HuntProcessRecord* process = nullptr;
                auto processIt = processes.find(event.ProcessId);
                if (processIt != processes.end())
                {
                    process = &processIt->second;
                }

                std::wstring matchedLeaf;
                const EdrKillerProcessProfile* profile = nullptr;
                bool suffixNormalized = false;
                std::wstring normalizedBase;
                bool suffixContextRequired = false;
                std::wstring suffixTail;
                bool gentlemenStagingPath = PathContainsGentlemenCollection(event.ImagePath) ||
                    PathContainsGentlemenCollection(ThreatIntelFullText(event));

                if (process != nullptr)
                {
                    profile = FindEdrKillerProcessProfileForProcess(
                        *process,
                        &matchedLeaf,
                        &suffixNormalized,
                        &normalizedBase,
                        &suffixContextRequired,
                        &suffixTail);
                    gentlemenStagingPath = gentlemenStagingPath ||
                        PathContainsGentlemenCollection(BestProcessImagePath(*process)) ||
                        PathContainsGentlemenCollection(process->PebCommandLine);
                }

                if (profile == nullptr)
                {
                    matchedLeaf = LeafName(event.ImagePath);
                    profile = FindEdrKillerProcessProfileByLeaf(
                        matchedLeaf,
                        &suffixNormalized,
                        &normalizedBase,
                        &suffixContextRequired,
                        &suffixTail);
                }

                if (!ThreatIntelProfileIsActionable(profile, gentlemenStagingPath) &&
                    !securityProductImpairment)
                {
                    continue;
                }

                ThreatIntelCorrelationBucket& bucket = buckets[event.ProcessId];
                bucket.ProcessId = event.ProcessId;
                if (bucket.Profile == nullptr && profile != nullptr)
                {
                    bucket.Profile = profile;
                }
                bucket.GentlemenStagingPath = bucket.GentlemenStagingPath || gentlemenStagingPath;
                bucket.SuffixNormalizedProfile = bucket.SuffixNormalizedProfile || suffixNormalized;
                bucket.SuffixContextRequired = bucket.SuffixContextRequired || suffixContextRequired;
                if (bucket.NormalizedProfileBase.empty() && !normalizedBase.empty())
                {
                    bucket.NormalizedProfileBase = normalizedBase;
                }
                if (bucket.SuffixTail.empty() && !suffixTail.empty())
                {
                    bucket.SuffixTail = suffixTail;
                }
                if (!matchedLeaf.empty())
                {
                    bucket.MatchedLeaf = matchedLeaf;
                }
                if (!event.ImagePath.empty())
                {
                    bucket.ImagePath = event.ImagePath;
                }
                std::wstring eventImageName = LeafName(event.ImagePath);
                if (!eventImageName.empty())
                {
                    bucket.ImageName = eventImageName;
                }
                if (process != nullptr)
                {
                    bucket.Eprocess = process->Kernel.Eprocess;
                    std::wstring bestName = BestProcessImageName(*process);
                    if (!bestName.empty())
                    {
                        bucket.ImageName = bestName;
                    }
                    if (bucket.ImagePath.empty())
                    {
                        bucket.ImagePath = BestProcessImagePath(*process);
                    }
                }

                if (bucket.ImageName.empty())
                {
                    bucket.ImageName = L"<unknown>";
                }

                if (event.TargetProcessId != 0)
                {
                    bucket.TargetProcessIds.insert(event.TargetProcessId);
                }

                if (driverIo)
                {
                    ++bucket.DriverIoCount;
                    if (bucket.FirstDriverIoEvent.Timestamp == 0)
                    {
                        bucket.FirstDriverIoEvent = event;
                    }
                }

                if (processImpairment)
                {
                    ++bucket.ProcessImpairmentCount;
                    if (bucket.FirstProcessImpairmentEvent.Timestamp == 0)
                    {
                        bucket.FirstProcessImpairmentEvent = event;
                    }
                }

                if (securityProductImpairment)
                {
                    ++bucket.SecurityProductImpairmentCount;
                    if (!securityProductTarget.empty())
                    {
                        bucket.SecurityProductTargetNames.insert(securityProductTarget);
                    }
                    if (bucket.FirstSecurityProductImpairmentEvent.Timestamp == 0)
                    {
                        bucket.FirstSecurityProductImpairmentEvent = event;
                    }
                }
            }

            for (const auto& item : buckets)
            {
                const ThreatIntelCorrelationBucket& bucket = item.second;
                if (bucket.DriverIoCount != 0)
                {
                    AddThreatIntelTelemetryFinding(
                        result,
                        bucket,
                        bucket.FirstDriverIoEvent,
                        L"edr_killer_driver_io_telemetry",
                        L"Threat-Intelligence event correlates an EDR-killer profile with driver I/O",
                        bucket.GentlemenStagingPath ? L"high" : L"medium",
                        bucket.GentlemenStagingPath ? L"high" : L"medium",
                        {
                            L"ti_driver_io_event",
                            L"native_api_driver_control",
                            L"deviceiocontrol_or_driver_object_activity"
                        },
                        bucket.DriverIoCount);
                }

                if (bucket.ProcessImpairmentCount >= 2 || bucket.TargetProcessIds.size() >= 2)
                {
                    AddThreatIntelTelemetryFinding(
                        result,
                        bucket,
                        bucket.FirstProcessImpairmentEvent,
                        L"edr_killer_process_impairment_telemetry",
                        L"Threat-Intelligence events correlate an EDR-killer profile with process impairment",
                        bucket.GentlemenStagingPath ? L"high" : L"medium",
                        L"medium",
                        {
                            L"ti_process_impairment_event",
                            L"defense_impairment_telemetry",
                            L"repeated_process_control_activity"
                        },
                        bucket.ProcessImpairmentCount);
                }

                if (bucket.SecurityProductImpairmentCount >= 2 ||
                    bucket.SecurityProductTargetNames.size() >= 2)
                {
                    AddThreatIntelTelemetryFinding(
                        result,
                        bucket,
                        bucket.FirstSecurityProductImpairmentEvent,
                        L"edr_killer_security_product_impairment_telemetry",
                        L"Threat-Intelligence events show repeated control of known security-product processes",
                        bucket.GentlemenStagingPath ? L"high" : L"medium",
                        bucket.GentlemenStagingPath ? L"high" : L"medium",
                        {
                            L"ti_process_impairment_event",
                            L"defense_impairment_telemetry",
                            L"known_security_product_process_target",
                            L"gentlekiller_security_target_list"
                        },
                        bucket.SecurityProductImpairmentCount);
                }
            }
        } while (false);
    }

    bool CanOpenDiskImagePath(const std::wstring& rawPath)
    {
        bool openable = false;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (rawPath.empty())
            {
                break;
            }

            std::wstring openPath = DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(rawPath));
            file = CreateFileW(
                openPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }

            openable = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return openable;
    }

    void AddVadFindings(DeviceClient& device, SymbolEngine& symbols, HuntResult* result, HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr)
            {
                break;
            }

            uint32_t weakPrivateExecFindings = 0;
            bool weakPrivateExecLimitWarned = false;
            std::map<std::wstring, DiskPeMetadata> diskMetadataCache;
            for (const ProcessVadRecord& vad : process->VadRecords)
            {
                bool privateMemory = vad.HasPrivateMemory && vad.PrivateMemory;
                bool privateExecutable = vad.Executable && privateMemory;
                bool wx = vad.Executable && vad.Writable;
                bool largePrivateExecutable = privateExecutable && vad.Size >= kLargePrivateExecThreshold;
                bool privatePe = privateMemory && vad.PeHeaderFound;
                bool sectionBackedExecutable = vad.Executable &&
                    vad.HasSubsection &&
                    vad.Subsection != 0 &&
                    !privateMemory;
                const HuntModuleRecord* loaderOwner = sectionBackedExecutable
                    ? FindLoaderModuleContainingAddress(*process, vad.StartAddress)
                    : nullptr;
                bool loaderCovered = loaderOwner != nullptr;
                std::vector<std::wstring> imageSectionReasons;
                std::map<std::wstring, std::wstring> imageSectionEvidence;

                if (sectionBackedExecutable &&
                    loaderOwner != nullptr &&
                    !loaderOwner->Path.empty() &&
                    vad.StartAddress >= loaderOwner->Base &&
                    vad.StartAddress - loaderOwner->Base <= std::numeric_limits<uint32_t>::max())
                {
                    DiskPeMetadata metadata = {};
                    bool metadataReady = false;
                    std::wstring cacheKey = CanonicalPathForCompare(loaderOwner->Path);
                    if (cacheKey.empty())
                    {
                        cacheKey = loaderOwner->Path;
                    }

                    auto cached = diskMetadataCache.find(cacheKey);
                    if (cached != diskMetadataCache.end())
                    {
                        metadata = cached->second;
                        metadataReady = true;
                    }
                    else
                    {
                        std::wstring metadataError;
                        if (ReadDiskPeMetadata(loaderOwner->Path, &metadata, &metadataError))
                        {
                            diskMetadataCache[cacheKey] = metadata;
                            metadataReady = true;
                        }
                    }

                    if (metadataReady)
                    {
                        uint32_t rva = static_cast<uint32_t>(vad.StartAddress - loaderOwner->Base);
                        const DiskPeSection* section = FindDiskSectionForRva(metadata, rva);
                        if (section != nullptr)
                        {
                            bool liveWritableExecutable = vad.Executable && vad.Writable;
                            bool executePermissionDrift = vad.Executable && !section->Executable;
                            bool writePermissionDrift = liveWritableExecutable && section->Executable && !section->Writable;
                            bool defaultWritableExecutableSection = liveWritableExecutable && section->Executable && section->Writable;

                            if (executePermissionDrift)
                            {
                                AddUnique(&imageSectionReasons, L"image_section_execute_permission_drift");
                            }
                            if (writePermissionDrift)
                            {
                                AddUnique(&imageSectionReasons, L"image_section_write_permission_drift");
                            }
                            if (defaultWritableExecutableSection)
                            {
                                AddUnique(&imageSectionReasons, L"image_rwx_section_vad");
                                AddUnique(&imageSectionReasons, L"mockingjay_rwx_section_candidate");
                            }

                            if (!imageSectionReasons.empty())
                            {
                                imageSectionEvidence[L"owner_module"] = loaderOwner->Name;
                                imageSectionEvidence[L"owner_module_base"] = HuntHex(loaderOwner->Base, 16);
                                imageSectionEvidence[L"owner_module_path"] = loaderOwner->Path;
                                imageSectionEvidence[L"disk_section_name"] = section->Name;
                                imageSectionEvidence[L"disk_section_rva"] = HuntHex(section->VirtualAddress, 8);
                                imageSectionEvidence[L"disk_section_executable"] = section->Executable ? L"true" : L"false";
                                imageSectionEvidence[L"disk_section_writable"] = section->Writable ? L"true" : L"false";
                                imageSectionEvidence[L"vad_rva"] = HuntHex(rva, 8);
                                imageSectionEvidence[L"vad_executable"] = vad.Executable ? L"true" : L"false";
                                imageSectionEvidence[L"vad_writable"] = vad.Writable ? L"true" : L"false";
                            }
                        }
                    }
                }

                if (sectionBackedExecutable &&
                    !loaderCovered &&
                    process->PebLdrEnumerated &&
                    process->ToolhelpModuleEnumerated)
                {
                    std::wstring backingPath;
                    std::wstring backingState = L"unresolved";
                    std::wstring backingWarning;
                    bool imageSection = false;
                    bool backingOpenable = true;
                    if (ResolveVadSectionBackingPath(device, symbols, vad, &backingPath, &backingState, &backingWarning, &imageSection))
                    {
                        if (backingState == L"resolved" &&
                            !backingPath.empty() &&
                            !CanOpenDiskImagePath(backingPath))
                        {
                            backingState = L"inaccessible";
                            backingOpenable = false;
                        }
                    }
                    else if (!backingWarning.empty())
                    {
                        AddUnique(&process->Warnings, L"VAD section backing failed: " + backingWarning);
                    }

                    bool peLikeBackingName = LooksLikePeImagePath(backingPath);
                    if (imageSection || peLikeBackingName)
                    {
                        uint64_t moduleSize = vad.Size;
                        if (backingOpenable && !backingPath.empty())
                        {
                            DiskPeMetadata metadata = {};
                            std::wstring metadataError;
                            if (ReadDiskPeMetadata(backingPath, &metadata, &metadataError) && metadata.SizeOfImage != 0)
                            {
                                moduleSize = metadata.SizeOfImage;
                            }
                        }

                        HuntModuleRecord module = {};
                        module.Base = vad.StartAddress;
                        module.Size = moduleSize;
                        module.Name = backingPath.empty() ? L"section-image" : LeafName(backingPath);
                        module.Path = backingPath;
                        module.VadImageSeen = true;
                        module.VadAddress = vad.VadAddress;
                        module.VadBackingPath = backingPath;
                        module.VadBackingState = backingState;
                        MergeModule(&process->Modules, module);
                    }
                }

                bool imageSectionPermissionSuspicious = !imageSectionReasons.empty();
                if (!privateExecutable &&
                    !wx &&
                    !largePrivateExecutable &&
                    !privatePe &&
                    !vad.PeHeaderSuspicious &&
                    !imageSectionPermissionSuspicious)
                {
                    continue;
                }

                HuntModuleRecord module = {};
                if (privatePe)
                {
                    module.Base = vad.StartAddress;
                    module.Size = vad.PeProbe.SizeOfImage != 0 ? vad.PeProbe.SizeOfImage : vad.Size;
                    module.Name = L"private-pe";
                    module.PrivatePeVadSeen = true;
                    MergeModule(&process->Modules, module);
                }

                std::vector<std::wstring> reasons;
                if (privateExecutable)
                {
                    reasons.push_back(L"private_executable_vad");
                }
                if (wx)
                {
                    reasons.push_back(L"wx_user_vad");
                }
                if (largePrivateExecutable)
                {
                    reasons.push_back(L"large_private_executable_vad");
                }
                if (privatePe)
                {
                    reasons.push_back(L"private_pe_mapping");
                }
                if (vad.PeHeaderSuspicious)
                {
                    reasons.push_back(L"wiped_pe_header");
                }
                for (const std::wstring& reason : imageSectionReasons)
                {
                    AddUnique(&reasons, reason);
                }

                bool weakPrivateExecutableOnly = privateExecutable &&
                    !wx &&
                    !largePrivateExecutable &&
                    !privatePe &&
                    !vad.PeHeaderSuspicious &&
                    !process->BuiltinProfileMatched;
                if (weakPrivateExecutableOnly &&
                    weakPrivateExecFindings >= kMaxWeakPrivateExecFindingsPerProcess)
                {
                    if (!weakPrivateExecLimitWarned)
                    {
                        AddUnique(&process->Warnings, L"weak private executable VAD findings were capped");
                        weakPrivateExecLimitWarned = true;
                    }
                    continue;
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"vad"] = HuntHex(vad.VadAddress, 16);
                evidence[L"start"] = HuntHex(vad.StartAddress, 16);
                evidence[L"end"] = HuntHex(vad.EndAddress, 16);
                evidence[L"size"] = std::to_wstring(vad.Size);
                evidence[L"protection"] = vad.ProtectionText;
                evidence[L"private"] = privateMemory ? L"true" : L"false";
                evidence[L"pe_like"] = vad.PeHeaderFound ? L"true" : L"false";
                evidence[L"pe_suspicious"] = vad.PeHeaderSuspicious ? L"true" : L"false";
                evidence[L"classification"] = vad.Classification;
                for (const auto& item : imageSectionEvidence)
                {
                    evidence[item.first] = item.second;
                }
                if (vad.PeProbeAttempted)
                {
                    evidence[L"pe_mz_wiped"] = vad.PeProbe.MzWiped ? L"true" : L"false";
                    evidence[L"pe_signature_wiped"] = vad.PeProbe.PeSignatureWiped ? L"true" : L"false";
                    evidence[L"pe_elfanew_mismatch"] = vad.PeProbe.ELfanewMismatch ? L"true" : L"false";
                    evidence[L"pe_size_of_image"] = std::to_wstring(vad.PeProbe.SizeOfImage);
                }
                AddBuiltinInjectionReasonIfNeeded(*process, &reasons, &evidence);

                std::wstring risk = wx || vad.PeHeaderSuspicious || privatePe || process->BuiltinProfileMatched ? L"high" : L"medium";
                std::wstring confidence = privatePe || wx ? L"high" : L"medium";
                if (imageSectionPermissionSuspicious)
                {
                    if (std::find(
                            imageSectionReasons.begin(),
                            imageSectionReasons.end(),
                            L"image_section_execute_permission_drift") != imageSectionReasons.end() ||
                        std::find(
                            imageSectionReasons.begin(),
                            imageSectionReasons.end(),
                            L"image_section_write_permission_drift") != imageSectionReasons.end() ||
                        process->BuiltinProfileMatched)
                    {
                        risk = L"high";
                    }
                    else if (risk != L"high")
                    {
                        risk = L"medium";
                    }
                    confidence = L"high";
                }
                if (weakPrivateExecutableOnly)
                {
                    risk = L"low";
                    confidence = L"low";
                    evidence[L"weak_private_exec_only"] = L"true";
                    ++weakPrivateExecFindings;
                }

                AddFinding(
                    result,
                    *process,
                    risk,
                    confidence,
                    L"mapped_code",
                    L"suspicious executable user VAD",
                    vad.StartAddress,
                    L"",
                    reasons,
                    evidence);
            }

            for (const ProcessHiddenVadPteRecord& hidden : process->HiddenPteRecords)
            {
                std::vector<std::wstring> reasons;
                if (hidden.Executable)
                {
                    reasons.push_back(L"vadless_executable_pte");
                }
                if (hidden.Executable && hidden.Writable)
                {
                    reasons.push_back(L"vadless_wx_pte");
                }

                if (reasons.empty())
                {
                    continue;
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"start"] = HuntHex(hidden.StartAddress, 16);
                evidence[L"end"] = HuntHex(hidden.EndAddress, 16);
                evidence[L"size"] = std::to_wstring(hidden.Size);
                evidence[L"page_size"] = std::to_wstring(hidden.PageSize);
                evidence[L"page_count"] = std::to_wstring(hidden.PageCount);
                evidence[L"physical"] = HuntHex(hidden.PhysicalAddress, 16);
                evidence[L"leaf_entry"] = HuntHex(hidden.LeafEntry, 16);
                evidence[L"leaf_entry_address"] = HuntHex(hidden.LeafEntryAddress, 16);
                evidence[L"writable"] = hidden.Writable ? L"true" : L"false";
                evidence[L"executable"] = hidden.Executable ? L"true" : L"false";
                evidence[L"user_accessible"] = hidden.UserAccessible ? L"true" : L"false";
                AddBuiltinInjectionReasonIfNeeded(*process, &reasons, &evidence);

                AddFinding(
                    result,
                    *process,
                    L"high",
                    L"high",
                    L"vad_dkom",
                    L"present executable user PTE range is not covered by a VAD",
                    hidden.StartAddress,
                    L"",
                    reasons,
                    evidence);
            }
        } while (false);
    }

    void AddThreadFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            size_t stackReferenceFindings = 0;
            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (thread.SuspiciousStart)
                {
                    uint64_t findingAddress = thread.HasWin32StartAddress && thread.Win32StartAddress != 0
                        ? thread.Win32StartAddress
                        : thread.StartAddress;
                    std::wstring findingModule = thread.HasWin32StartAddress && !thread.Win32StartModule.empty()
                        ? thread.Win32StartModule
                        : thread.StartModule;

                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                    evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                    evidence[L"start"] = HuntHex(thread.StartAddress, 16);
                    evidence[L"win32_start"] = HuntHex(thread.Win32StartAddress, 16);
                    evidence[L"start_module"] = thread.StartModule;
                    evidence[L"win32_start_module"] = thread.Win32StartModule;
                    evidence[L"vad"] = thread.VadClassification;
                    evidence[L"start_in_private_exec_vad"] = thread.StartInPrivateExecVad ? L"true" : L"false";
                    evidence[L"start_in_wx_vad"] = thread.StartInWxVad ? L"true" : L"false";
                    evidence[L"notes"] = thread.Notes;

                    std::vector<std::wstring> reasons = {L"suspicious_thread_start"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                    std::wstring risk = thread.StartInPrivateExecVad || thread.StartInWxVad || process.BuiltinProfileMatched ? L"high" : L"medium";
                    AddFinding(
                        result,
                        process,
                        risk,
                        L"high",
                        L"thread_provenance",
                        L"thread start address is outside expected user module ownership",
                        findingAddress,
                        findingModule,
                        reasons,
                        evidence);
                }

                for (const ProcessStackReferenceRecord& ref : thread.StackReferences)
                {
                    if (!ref.Suspicious)
                    {
                        continue;
                    }

                    if (stackReferenceFindings >= kMaxStackReferenceFindingsPerProcess)
                    {
                        AddUnique(&result->Warnings, L"thread stack reference findings were capped for pid " + std::to_wstring(process.ProcessId));
                        break;
                    }

                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                    evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                    evidence[L"teb"] = HuntHex(thread.Teb, 16);
                    evidence[L"user_stack_base"] = HuntHex(thread.UserStackBase, 16);
                    evidence[L"user_stack_limit"] = HuntHex(thread.UserStackLimit, 16);
                    evidence[L"stack_address"] = HuntHex(ref.StackAddress, 16);
                    evidence[L"referenced_address"] = HuntHex(ref.Value, 16);
                    evidence[L"referenced_module"] = ref.ValueModule;
                    evidence[L"referenced_vad"] = ref.VadClassification;
                    evidence[L"user_module_enumeration_available"] = ref.UserModuleEnumerationAvailable ? L"true" : L"false";
                    evidence[L"referenced_private_exec_vad"] = ref.ValueInPrivateExecVad ? L"true" : L"false";
                    evidence[L"referenced_wx_vad"] = ref.ValueInWxVad ? L"true" : L"false";
                    evidence[L"referenced_in_user_module"] = ref.ValueInUserModule ? L"true" : L"false";
                    evidence[L"referenced_outside_user_modules"] = ref.ValueOutsideUserModules ? L"true" : L"false";
                    evidence[L"notes"] = ref.Notes;

                    std::vector<std::wstring> reasons = {L"stack_reference_to_executable_memory"};
                    if (ref.ValueInPrivateExecVad)
                    {
                        AddUnique(&reasons, L"stack_reference_to_private_executable_vad");
                    }
                    if (ref.ValueInWxVad)
                    {
                        AddUnique(&reasons, L"stack_reference_to_wx_vad");
                    }
                    if (ref.ValueOutsideUserModules)
                    {
                        AddUnique(&reasons, L"stack_reference_to_user_executable_outside_module");
                    }
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                    std::wstring risk = ref.ValueInPrivateExecVad || ref.ValueInWxVad || process.BuiltinProfileMatched ? L"high" : L"medium";
                    AddFinding(
                        result,
                        process,
                        risk,
                        L"medium",
                        L"thread_stack_provenance",
                        L"thread stack references suspicious executable memory",
                        ref.Value,
                        ref.ValueModule,
                        reasons,
                        evidence);
                    ++stackReferenceFindings;
                }

                for (const ProcessApcQueueRecord& queue : thread.ApcQueues)
                {
                    for (const ProcessApcEntryRecord& apc : queue.Entries)
                    {
                        if (!apc.Suspicious)
                        {
                            continue;
                        }

                        uint64_t findingAddress = apc.NormalRoutine != 0
                            ? apc.NormalRoutine
                            : apc.KernelRoutine;
                        std::wstring findingModule = apc.NormalRoutine != 0
                            ? apc.NormalRoutineModule
                            : apc.KernelRoutineModule;

                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                        evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                        evidence[L"queue"] = queue.Name;
                        evidence[L"kapc"] = HuntHex(apc.KapcAddress, 16);
                        evidence[L"kernel_routine"] = HuntHex(apc.KernelRoutine, 16);
                        evidence[L"normal_routine"] = HuntHex(apc.NormalRoutine, 16);
                        evidence[L"kernel_routine_module"] = apc.KernelRoutineModule;
                        evidence[L"normal_routine_module"] = apc.NormalRoutineModule;
                        evidence[L"notes"] = apc.Notes;

                        std::vector<std::wstring> reasons = {L"suspicious_apc_routine"};
                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                        AddFinding(
                            result,
                            process,
                            L"high",
                            L"medium",
                            L"apc_redirection",
                            L"queued APC has suspicious user or kernel routine provenance",
                            findingAddress,
                            findingModule,
                            reasons,
                            evidence);
                    }
                }
            }
        } while (false);
    }

    void AddModuleCrossViewFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const HuntModuleRecord& module : process.Modules)
            {
                bool coreLdrSeen = ModuleHasCoreLdrView(module);
                bool reliableCoreLdr = ProcessHasReliableCoreLdrView(process);
                std::map<std::wstring, std::wstring> evidence;
                evidence[L"base"] = HuntHex(module.Base, 16);
                evidence[L"size"] = std::to_wstring(module.Size);
                evidence[L"module_name"] = module.Name;
                evidence[L"module_path"] = module.Path;
                evidence[L"toolhelp_seen"] = module.ToolhelpSeen ? L"true" : L"false";
                evidence[L"ldr_load_seen"] = module.LdrLoadSeen ? L"true" : L"false";
                evidence[L"ldr_memory_seen"] = module.LdrMemorySeen ? L"true" : L"false";
                evidence[L"ldr_init_seen"] = module.LdrInitSeen ? L"true" : L"false";
                evidence[L"private_pe_vad_seen"] = module.PrivatePeVadSeen ? L"true" : L"false";
                evidence[L"vad_image_seen"] = module.VadImageSeen ? L"true" : L"false";
                if (module.VadAddress != 0)
                {
                    evidence[L"vad"] = HuntHex(module.VadAddress, 16);
                }
                evidence[L"vad_backing_path"] = module.VadBackingPath;
                evidence[L"vad_backing_state"] = module.VadBackingState;

                if (module.VadImageSeen && process.PebLdrEnumerated && process.ToolhelpModuleEnumerated)
                {
                    bool covered = LoaderModuleCoversAddress(process, module.Base, &module);
                    if (!covered)
                    {
                        bool backingWeakButOpenable = module.VadBackingState == L"resolved" &&
                            !module.VadBackingPath.empty();
                        std::vector<std::wstring> reasons = {L"section_image_without_loader_entry", L"vad_image_not_in_loader"};
                        if (module.VadBackingState == L"inaccessible")
                        {
                            reasons.push_back(L"section_backing_inaccessible");
                        }
                        else if (module.VadBackingState == L"empty_file_name" || module.VadBackingState == L"unbacked")
                        {
                            reasons.push_back(L"section_backing_missing");
                        }

                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                        AddFinding(
                            result,
                            process,
                            module.VadBackingState == L"inaccessible" ? L"high" : (backingWeakButOpenable ? L"low" : L"medium"),
                            backingWeakButOpenable ? L"medium" : (module.VadBackingPath.empty() ? L"medium" : L"high"),
                            L"module_cross_view",
                            L"section-backed executable image mapping is absent from loader module views",
                            module.Base,
                            module.Name,
                            reasons,
                            evidence);
                    }
                }

                if (module.PrivatePeVadSeen && process.PebLdrEnumerated && process.ToolhelpModuleEnumerated)
                {
                    bool covered = false;
                    for (const HuntModuleRecord& other : process.Modules)
                    {
                        if (&other == &module)
                        {
                            continue;
                        }

                        if ((other.ToolhelpSeen || other.LdrLoadSeen || other.LdrMemorySeen) &&
                            AddressInsideModule(other, module.Base))
                        {
                            covered = true;
                            break;
                        }
                    }

                    if (!covered)
                    {
                        std::vector<std::wstring> reasons = {L"private_pe_without_loader_entry"};
                        AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                        AddFinding(
                            result,
                            process,
                            L"high",
                            L"high",
                            L"manual_map",
                            L"private PE-like mapping is absent from loader module views",
                            module.Base,
                            module.Name,
                            reasons,
                            evidence);
                    }
                }

                if (process.PebLdrEnumerated &&
                    reliableCoreLdr &&
                    coreLdrSeen &&
                    !(module.LdrLoadSeen && module.LdrMemorySeen))
                {
                    std::vector<std::wstring> reasons = {L"partial_ldr_unlink"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                    AddFinding(
                        result,
                        process,
                        process.BuiltinProfileMatched ? L"high" : L"medium",
                        L"medium",
                        L"module_cross_view",
                        L"module is only partially present across PEB LDR lists",
                        module.Base,
                        module.Name,
                        reasons,
                        evidence);
                }

                if (process.ToolhelpModuleEnumerated &&
                    process.PebLdrEnumerated &&
                    reliableCoreLdr &&
                    module.ToolhelpSeen != coreLdrSeen &&
                    !module.PrivatePeVadSeen &&
                    (process.BuiltinProfileMatched || module.VadImageSeen))
                {
                    std::vector<std::wstring> reasons = {L"module_view_mismatch"};
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);
                    AddFinding(
                        result,
                        process,
                        process.BuiltinProfileMatched ? L"high" : L"medium",
                        L"medium",
                        L"module_cross_view",
                        L"module differs between Toolhelp and PEB loader views",
                        module.Base,
                        module.Name,
                        reasons,
                        evidence);
                }
            }
        } while (false);
    }

    bool IsMainImageModule(const HuntProcessRecord& process, const HuntModuleRecord& module)
    {
        bool isMain = false;

        do
        {
            if (process.HasPebImageBase &&
                module.Base == process.PebImageBase)
            {
                isMain = true;
                break;
            }

            if (!process.ApiImagePath.empty() && SameNonEmptyLeaf(process.ApiImagePath, module.Path))
            {
                isMain = true;
                break;
            }

            if (!process.PebImagePath.empty() && SameNonEmptyLeaf(process.PebImagePath, module.Path))
            {
                isMain = true;
                break;
            }

            std::wstring leaf = LeafName(module.Name);
            if (!process.KernelImageName.empty() &&
                !leaf.empty() &&
                leaf == LeafName(process.KernelImageName))
            {
                isMain = true;
                break;
            }
        } while (false);

        return isMain;
    }

    void AddBuiltinModuleProvenanceFindings(HuntResult* result, const HuntProcessRecord& process)
    {
        do
        {
            if (result == nullptr || !ShouldAuditBuiltinModuleProvenance(process))
            {
                break;
            }

            size_t findings = 0;
            for (const HuntModuleRecord& module : process.Modules)
            {
                if (findings >= kMaxBuiltinModuleProvenanceFindingsPerProcess)
                {
                    AddUnique(&result->Warnings, L"built-in module provenance findings were capped for pid " + std::to_wstring(process.ProcessId));
                    break;
                }

                if (module.Base == 0 ||
                    module.Size == 0 ||
                    module.Path.empty() ||
                    IsMainImageModule(process, module) ||
                    !(module.ToolhelpSeen || ModuleHasCoreLdrView(module)) ||
                    IsWindowsBackedModulePath(module.Path))
                {
                    continue;
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"module_base"] = HuntHex(module.Base, 16);
                evidence[L"module_size"] = std::to_wstring(module.Size);
                evidence[L"module_name"] = module.Name;
                evidence[L"module_path"] = module.Path;
                evidence[L"toolhelp_seen"] = module.ToolhelpSeen ? L"true" : L"false";
                evidence[L"ldr_load_seen"] = module.LdrLoadSeen ? L"true" : L"false";
                evidence[L"ldr_memory_seen"] = module.LdrMemorySeen ? L"true" : L"false";
                evidence[L"ldr_init_seen"] = module.LdrInitSeen ? L"true" : L"false";
                evidence[L"windows_backed_module_path"] = L"false";

                std::vector<std::wstring> reasons =
                {
                    L"builtin_process_non_windows_module",
                    L"dll_load_in_builtin_process"
                };
                if (process.BuiltinProfile == L"hunt_lab_builtin_profile")
                {
                    AddUnique(&reasons, L"lab_builtin_profile_non_windows_module");
                }
                AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

                AddFinding(
                    result,
                    process,
                    process.BuiltinProfileViolations.empty() ? L"medium" : L"high",
                    L"medium",
                    L"builtin_module_provenance",
                    L"built-in Windows process loaded a module from a non-Windows path",
                    module.Base,
                    module.Name,
                    reasons,
                    evidence);
                ++findings;
            }
        } while (false);
    }

    void AddMainImageVadFinding(
        DeviceClient& device,
        SymbolEngine& symbols,
        HuntResult* result,
        HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr)
            {
                break;
            }

            for (const HuntModuleRecord& module : process->Modules)
            {
                if (!module.ToolhelpSeen || !IsMainImageModule(*process, module))
                {
                    continue;
                }

                process->MainImageBase = module.Base;
                process->MainImageSize = module.Size;
                process->DiskPath = module.Path;

                const ProcessVadRecord* vad = FindVadContaining(*process, module.Base);
                if (vad == nullptr)
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"disk_path"] = module.Path;
                    if (process->HasPebImageBase)
                    {
                        evidence[L"peb_image_base"] = HuntHex(process->PebImageBase, 16);
                    }
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"medium",
                        L"process_image_integrity",
                        L"main image module base is not covered by a VAD record",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked"},
                        evidence);
                    break;
                }

                process->MainImageVad = vad->VadAddress;

                std::wstring backingWarning;
                std::wstring backingPath;
                std::wstring backingState;
                if (ResolveVadSectionBackingPath(device, symbols, *vad, &backingPath, &backingState, &backingWarning))
                {
                    process->SectionBackingPath = backingPath;
                    process->SectionBackingState = backingState;
                }
                else
                {
                    process->SectionBackingState = L"unavailable";
                    if (!backingWarning.empty())
                    {
                        AddUnique(&process->Warnings, L"main image section backing unresolved: " + backingWarning);
                    }
                }

                if (process->SectionBackingState == L"unbacked")
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"disk_path"] = module.Path;
                    evidence[L"section_backing_state"] = process->SectionBackingState;
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"medium",
                        L"process_image_integrity",
                        L"main image VAD has no section file backing",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked"},
                        evidence);
                }
                else if (!process->SectionBackingPath.empty())
                {
                    bool diskOpen = CanOpenDiskImagePath(process->SectionBackingPath);
                    if (!diskOpen &&
                        !module.Path.empty() &&
                        SameCanonicalPath(process->SectionBackingPath, module.Path))
                    {
                        diskOpen = CanOpenDiskImagePath(module.Path);
                    }

                    if (!diskOpen)
                    {
                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                        evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                        evidence[L"disk_path"] = module.Path;
                        evidence[L"section_backing_path"] = process->SectionBackingPath;
                        evidence[L"section_backing_state"] = L"inaccessible";
                        process->SectionBackingState = L"inaccessible";
                        AddFinding(
                            result,
                            *process,
                            L"medium",
                            L"medium",
                            L"process_image_integrity",
                            L"main image section backing file cannot be opened",
                            module.Base,
                            module.Name,
                            {L"section_backing_inaccessible"},
                            evidence);
                    }

                    if (!module.Path.empty() &&
                        !SameCanonicalPath(process->SectionBackingPath, module.Path))
                    {
                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                        evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                        evidence[L"disk_path"] = module.Path;
                        evidence[L"section_backing_path"] = process->SectionBackingPath;
                        evidence[L"section_backing_state"] = process->SectionBackingState;
                        AddFinding(
                            result,
                            *process,
                            L"high",
                            L"medium",
                            L"process_image_integrity",
                            L"main image section backing path differs from process image path",
                            module.Base,
                            module.Name,
                            {L"section_path_mismatch"},
                            evidence);
                    }
                }

                if (vad->HasPrivateMemory && vad->PrivateMemory)
                {
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"disk_path"] = module.Path;
                    evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"section_backing_path"] = process->SectionBackingPath;
                    evidence[L"section_backing_state"] = process->SectionBackingState;
                    if (process->HasPebImageBase)
                    {
                        evidence[L"peb_image_base"] = HuntHex(process->PebImageBase, 16);
                    }
                    evidence[L"vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"vad_start"] = HuntHex(vad->StartAddress, 16);
                    evidence[L"vad_end"] = HuntHex(vad->EndAddress, 16);
                    evidence[L"vad_private"] = L"true";
                    AddFinding(
                        result,
                        *process,
                        L"high",
                        L"high",
                        L"process_image_integrity",
                        L"main image module is backed by private memory",
                        module.Base,
                        module.Name,
                        {L"main_image_private_or_unbacked", L"process_hollowing_evidence"},
                        evidence);
                    break;
                }
            }
        } while (false);
    }

    void AppendDeepTargetRange(std::vector<DeepAddressRange>* ranges, uint64_t start, uint64_t end)
    {
        do
        {
            if (ranges == nullptr || start == 0 || end <= start)
            {
                break;
            }

            DeepAddressRange range = {};
            range.Start = start;
            range.End = end;
            ranges->push_back(range);
        } while (false);
    }

    void BuildDeepTargetRanges(const HuntProcessRecord& process, std::vector<DeepAddressRange>* ranges)
    {
        do
        {
            if (ranges == nullptr)
            {
                break;
            }

            ranges->clear();
            ranges->reserve(process.Modules.size() + process.VadRecords.size());

            for (const HuntModuleRecord& module : process.Modules)
            {
                uint64_t end = 0;
                if (module.Size != 0 && TryAdd(module.Base, module.Size, &end))
                {
                    AppendDeepTargetRange(ranges, module.Base, end);
                }
            }

            for (const ProcessVadRecord& vad : process.VadRecords)
            {
                if (!vad.Executable)
                {
                    continue;
                }

                uint64_t end = vad.EndAddress == std::numeric_limits<uint64_t>::max()
                    ? std::numeric_limits<uint64_t>::max()
                    : vad.EndAddress + 1;
                AppendDeepTargetRange(ranges, vad.StartAddress, end);
            }

            std::sort(
                ranges->begin(),
                ranges->end(),
                [](const DeepAddressRange& left, const DeepAddressRange& right)
                {
                    if (left.Start != right.Start)
                    {
                        return left.Start < right.Start;
                    }
                    return left.End < right.End;
                });

            std::vector<DeepAddressRange> merged;
            merged.reserve(ranges->size());
            for (const DeepAddressRange& range : *ranges)
            {
                if (merged.empty() || range.Start > merged.back().End)
                {
                    merged.push_back(range);
                    continue;
                }

                if (range.End > merged.back().End)
                {
                    merged.back().End = range.End;
                }
            }

            *ranges = std::move(merged);
        } while (false);
    }

    bool ValueInsideDeepTargetRanges(const std::vector<DeepAddressRange>& ranges, uint64_t value)
    {
        bool inside = false;

        do
        {
            if (!IsUserAddress(value) || ranges.empty())
            {
                break;
            }

            size_t left = 0;
            size_t right = ranges.size();
            while (left < right)
            {
                size_t middle = left + ((right - left) / 2);
                const DeepAddressRange& range = ranges[middle];
                if (value < range.Start)
                {
                    right = middle;
                }
                else if (value >= range.End)
                {
                    left = middle + 1;
                }
                else
                {
                    inside = true;
                    break;
                }
            }
        } while (false);

        return inside;
    }

    void BuildDeepStackReferenceCache(
        DeviceClient& device,
        const HuntProcessRecord& process,
        DeepStackReferenceCache* cache)
    {
        do
        {
            if (cache == nullptr || cache->Built)
            {
                break;
            }

            cache->Built = true;
            cache->Samples.clear();
            cache->LimitReached = false;

            uint64_t dtb = TargetUserDtb(process.Kernel);
            if (dtb == 0)
            {
                break;
            }

            std::vector<DeepAddressRange> targetRanges;
            BuildDeepTargetRanges(process, &targetRanges);
            if (targetRanges.empty())
            {
                break;
            }

            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (!thread.HasUserStackBounds ||
                    thread.UserStackBase <= thread.UserStackLimit)
                {
                    continue;
                }

                uint64_t scanEnd = thread.UserStackBase;
                uint64_t scanStart = thread.UserStackLimit;
                if (scanEnd - scanStart > kMaxThreadStackScanBytes)
                {
                    scanStart = scanEnd - kMaxThreadStackScanBytes;
                }
                if ((scanStart & 0x7ull) != 0)
                {
                    scanStart = (scanStart + 0x7ull) & ~0x7ull;
                }
                if (scanEnd < sizeof(uint64_t))
                {
                    continue;
                }

                uint64_t current = scanStart;
                while (current <= scanEnd - sizeof(uint64_t) && !cache->LimitReached)
                {
                    uint64_t nextPage = (current & ~(kPageSize - 1ull)) + kPageSize;
                    uint64_t chunkEnd = nextPage < scanEnd ? nextPage : scanEnd;
                    if (chunkEnd <= current)
                    {
                        break;
                    }

                    std::vector<uint8_t> bytes;
                    std::wstring ignored;
                    uint32_t chunkSize = static_cast<uint32_t>(chunkEnd - current);
                    if (ReadProcessMemoryByDtb(device, dtb, current, chunkSize, &bytes, &ignored))
                    {
                        for (size_t offset = 0;
                             offset + sizeof(uint64_t) <= bytes.size() && !cache->LimitReached;
                             offset += sizeof(uint64_t))
                        {
                            uint64_t value = 0;
                            memcpy(&value, bytes.data() + offset, sizeof(uint64_t));
                            if (!ValueInsideDeepTargetRanges(targetRanges, value))
                            {
                                continue;
                            }

                            DeepStackPointerSample sample = {};
                            sample.ThreadId = thread.ThreadId;
                            sample.StackAddress = current + offset;
                            sample.Value = value;
                            cache->Samples.push_back(sample);
                            if (cache->Samples.size() >= kMaxDeepStackPointerSamplesPerProcess)
                            {
                                cache->LimitReached = true;
                            }
                        }
                    }

                    current = chunkEnd;
                    if ((current & 0x7ull) != 0)
                    {
                        current = (current + 0x7ull) & ~0x7ull;
                    }
                }

                if (cache->LimitReached)
                {
                    break;
                }
            }
        } while (false);
    }

    void FindStackReferencesToRange(
        const DeepStackReferenceCache& cache,
        uint64_t rangeStart,
        uint64_t rangeEnd,
        std::vector<std::wstring>* threadIds,
        std::vector<std::wstring>* stackSlots)
    {
        do
        {
            if (threadIds == nullptr ||
                stackSlots == nullptr ||
                rangeStart >= rangeEnd)
            {
                break;
            }

            for (const DeepStackPointerSample& sample : cache.Samples)
            {
                if (stackSlots->size() >= kMaxStackReferenceFindingsPerProcess)
                {
                    break;
                }

                if (sample.Value >= rangeStart && sample.Value < rangeEnd)
                {
                    AddUnique(threadIds, std::to_wstring(sample.ThreadId));
                    stackSlots->push_back(HuntHex(sample.StackAddress, 16) + L"=" + HuntHex(sample.Value, 16));
                }
            }
        } while (false);
    }

    void AddDeepPageCompareFinding(
        DeviceClient& device,
        HuntResult* result,
        const HuntProcessRecord& process,
        const HuntModuleRecord& module,
        const std::wstring& pageName,
        const std::wstring& sectionName,
        uint32_t rva,
        const std::vector<uint8_t>& livePage,
        const std::vector<uint8_t>& diskPage,
        DeepStackReferenceCache* stackCache)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"module_base"] = HuntHex(module.Base, 16);
            evidence[L"module_size"] = std::to_wstring(module.Size);
            evidence[L"module_name"] = module.Name;
            evidence[L"module_path"] = module.Path;
            evidence[L"disk_path"] = module.Path;
            evidence[L"page"] = pageName;
            evidence[L"section_name"] = sectionName;
            evidence[L"rva"] = HuntHex(rva, 8);
            evidence[L"live_hash"] = HuntHex(Fnv1a64(livePage), 16);
            evidence[L"disk_hash"] = HuntHex(Fnv1a64(diskPage), 16);
            evidence[L"live_bytes"] = std::to_wstring(livePage.size());
            evidence[L"disk_bytes"] = std::to_wstring(diskPage.size());
            evidence[L"diff_bytes"] = std::to_wstring(CountDifferentBytes(livePage, diskPage));
            evidence[L"modified_page_owner"] = module.Name;

            bool mainImage = IsMainImageModule(process, module);
            std::vector<std::wstring> reasons;
            if (mainImage)
            {
                reasons.push_back(L"disk_live_image_mismatch");
                evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                evidence[L"main_image_vad"] = process.MainImageVad != 0 ? HuntHex(process.MainImageVad, 16) : L"";
                evidence[L"section_backing_path"] = process.SectionBackingPath;
                evidence[L"section_backing_state"] = process.SectionBackingState;
                if (pageName == L"entrypoint")
                {
                    reasons.push_back(L"main_image_entrypoint_mismatch");
                }
                else
                {
                    reasons.push_back(L"main_image_hash_mismatch");
                }

                if (process.SectionBackingState == L"unbacked" ||
                    process.SectionBackingState == L"inaccessible" ||
                    process.SectionBackingState == L"empty_file_name")
                {
                    reasons.push_back(L"process_doppelganging_evidence");
                }
                else if (!process.SectionBackingPath.empty() &&
                         !module.Path.empty() &&
                         !SameCanonicalPath(process.SectionBackingPath, module.Path))
                {
                    reasons.push_back(L"section_path_mismatch");
                    reasons.push_back(L"process_doppelganging_evidence");
                }
            }
            else
            {
                reasons.push_back(L"live_disk_exec_page_mismatch");
                reasons.push_back(L"module_stomping_evidence");
                if (pageName == L"entrypoint")
                {
                    reasons.push_back(L"module_entrypoint_mismatch");
                }
                else
                {
                    reasons.push_back(L"module_text_mismatch");
                }
            }

            uint64_t pageStart = 0;
            uint64_t pageEnd = 0;
            if (!TryAdd(module.Base, rva, &pageStart) ||
                !TryAdd(pageStart, kPageSize, &pageEnd))
            {
                break;
            }
            std::vector<std::wstring> threadIds;
            std::vector<std::wstring> apcThreadIds;
            std::vector<std::wstring> stackThreadIds;
            std::vector<std::wstring> stackReferences;
            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (thread.HasStartAddress &&
                    thread.StartAddress >= pageStart &&
                    thread.StartAddress < pageEnd)
                {
                    AddUnique(&threadIds, std::to_wstring(thread.ThreadId));
                }
                if (thread.HasWin32StartAddress &&
                    thread.Win32StartAddress >= pageStart &&
                    thread.Win32StartAddress < pageEnd)
                {
                    AddUnique(&threadIds, std::to_wstring(thread.ThreadId));
                }

                for (const ProcessApcQueueRecord& queue : thread.ApcQueues)
                {
                    for (const ProcessApcEntryRecord& apc : queue.Entries)
                    {
                        if (apc.NormalRoutine >= pageStart &&
                            apc.NormalRoutine < pageEnd)
                        {
                            AddUnique(&apcThreadIds, std::to_wstring(thread.ThreadId));
                        }
                    }
                }
            }
            if (stackCache != nullptr)
            {
                BuildDeepStackReferenceCache(device, process, stackCache);
                FindStackReferencesToRange(*stackCache, pageStart, pageEnd, &stackThreadIds, &stackReferences);
                evidence[L"stack_reference_cache_samples"] = std::to_wstring(stackCache->Samples.size());
                evidence[L"stack_reference_cache_limited"] = stackCache->LimitReached ? L"true" : L"false";
            }

            evidence[L"thread_start_count"] = std::to_wstring(threadIds.size());
            evidence[L"apc_target_count"] = std::to_wstring(apcThreadIds.size());
            evidence[L"stack_reference_count"] = std::to_wstring(stackReferences.size());
            evidence[L"thread_ids"] = JoinWideValues(threadIds, L";");
            evidence[L"apc_thread_ids"] = JoinWideValues(apcThreadIds, L";");
            evidence[L"stack_thread_ids"] = JoinWideValues(stackThreadIds, L";");
            evidence[L"stack_references"] = JoinWideValues(stackReferences, L";");

            if (!threadIds.empty())
            {
                AddUnique(&reasons, L"thread_start_in_modified_module_page");
            }
            if (!apcThreadIds.empty())
            {
                AddUnique(&reasons, L"apc_target_in_modified_module_page");
            }
            if (!stackReferences.empty())
            {
                AddUnique(&reasons, L"thread_stack_references_modified_module_page");
            }
            AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence);

            bool executionOnPage = !threadIds.empty() || !apcThreadIds.empty() || !stackReferences.empty();
            bool doppelganging = mainImage &&
                std::find(reasons.begin(), reasons.end(), L"process_doppelganging_evidence") != reasons.end();
            std::wstring risk = mainImage || executionOnPage || process.BuiltinProfileMatched ? L"high" : L"medium";
            std::wstring confidence = executionOnPage || doppelganging ? L"high" : L"medium";

            AddFinding(
                result,
                process,
                risk,
                confidence,
                doppelganging ? L"process_doppelganging" : (mainImage ? L"process_image_integrity" : L"module_stomping"),
                mainImage ? L"live main image page differs from disk" : L"live module executable page differs from disk",
                pageStart,
                module.Name,
                reasons,
                evidence);
        } while (false);
    }

    bool PageHasExpectedRelocationDelta(
        const HuntModuleRecord& module,
        const DiskPeMetadata& metadata,
        uint32_t pageRva)
    {
        bool relocated = false;

        do
        {
            if (metadata.ImageBase == 0 ||
                module.Base == 0 ||
                module.Base == metadata.ImageBase)
            {
                break;
            }

            relocated = metadata.RelocationPages.find(pageRva) != metadata.RelocationPages.end();
        } while (false);

        return relocated;
    }

    bool PageHasExpectedLoaderMutableData(const DiskPeMetadata& metadata, uint32_t pageRva)
    {
        return metadata.LoaderMutablePages.find(pageRva) != metadata.LoaderMutablePages.end();
    }

    void CompareModulePage(
        DeviceClient& device,
        HuntResult* result,
        const HuntProcessRecord& process,
        const HuntModuleRecord& module,
        const DiskPeMetadata& metadata,
        const std::wstring& pageName,
        const std::wstring& sectionName,
        uint32_t rva,
        DeepStackReferenceCache* stackCache)
    {
        do
        {
            uint32_t pageRva = rva & 0xfffff000u;
            if (PageHasExpectedRelocationDelta(module, metadata, pageRva))
            {
                break;
            }

            if (PageHasExpectedLoaderMutableData(metadata, pageRva))
            {
                break;
            }

            std::vector<uint8_t> livePage;
            std::wstring ignored;
            if (!ReadProcessMemoryByDtb(
                    device,
                    TargetUserDtb(process.Kernel),
                    module.Base + pageRva,
                    static_cast<uint32_t>(kPageSize),
                    &livePage,
                    &ignored))
            {
                break;
            }

            std::vector<uint8_t> diskPage;
            if (!ReadDiskPageForRva(module.Path, metadata, pageRva, &diskPage, &ignored))
            {
                break;
            }

            if (livePage.size() != diskPage.size())
            {
                size_t shorter = std::min(livePage.size(), diskPage.size());
                livePage.resize(shorter);
                diskPage.resize(shorter);
            }

            if (!livePage.empty() && livePage != diskPage)
            {
                AddDeepPageCompareFinding(
                    device,
                    result,
                    process,
                    module,
                    pageName,
                    sectionName,
                    pageRva,
                    livePage,
                    diskPage,
                    stackCache);
            }
        } while (false);
    }

    void AddDeepImageIntegrityFindings(DeviceClient& device, HuntResult* result, HuntProcessRecord* process)
    {
        do
        {
            if (result == nullptr || process == nullptr || TargetUserDtb(process->Kernel) == 0)
            {
                break;
            }

            size_t compared = 0;
            size_t pagesCompared = 0;
            DeepStackReferenceCache stackReferenceCache = {};
            std::vector<const HuntModuleRecord*> modules;
            modules.reserve(process->Modules.size());
            for (const HuntModuleRecord& module : process->Modules)
            {
                modules.push_back(&module);
            }

            std::stable_sort(
                modules.begin(),
                modules.end(),
                [process](const HuntModuleRecord* left, const HuntModuleRecord* right)
                {
                    auto priority = [process](const HuntModuleRecord* module)
                    {
                        if (module == nullptr)
                        {
                            return 4;
                        }
                        if (module->VadImageSeen)
                        {
                            return 0;
                        }
                        if (IsMainImageModule(*process, *module))
                        {
                            return 1;
                        }
                        if (ModuleHasLoaderView(*module))
                        {
                            return 2;
                        }
                        return 3;
                    };

                    return priority(left) < priority(right);
                });

            for (const HuntModuleRecord* modulePtr : modules)
            {
                if (modulePtr == nullptr)
                {
                    continue;
                }

                const HuntModuleRecord& module = *modulePtr;
                if (compared >= kMaxDeepModuleComparisonsPerProcess)
                {
                    AddUnique(&process->Warnings, L"deep module comparison limit reached");
                    break;
                }

                if (module.Base == 0 || module.Path.empty() || module.PrivatePeVadSeen)
                {
                    continue;
                }

                DiskPeMetadata metadata = {};
                std::wstring metadataError;
                if (!ReadDiskPeMetadata(module.Path, &metadata, &metadataError))
                {
                    continue;
                }

                bool mainImage = IsMainImageModule(*process, module);
                bool compareFullExecutableSections = process->BuiltinProfileMatched || mainImage;
                std::set<uint32_t> comparedPageRvas;
                if (metadata.HasEntryPoint)
                {
                    uint32_t pageRva = metadata.EntryPointRva & 0xfffff000u;
                    if (pagesCompared < kMaxDeepPagesPerProcess)
                    {
                        CompareModulePage(
                            device,
                            result,
                            *process,
                            module,
                            metadata,
                            L"entrypoint",
                            L"",
                            metadata.EntryPointRva,
                            &stackReferenceCache);
                        comparedPageRvas.insert(pageRva);
                        ++pagesCompared;
                    }
                }

                for (const DiskPeSection& section : metadata.Sections)
                {
                    if (!section.Executable)
                    {
                        continue;
                    }

                    uint64_t mappedSpan = std::max(section.VirtualSize, section.SizeOfRawData);
                    if (mappedSpan == 0)
                    {
                        continue;
                    }

                    uint64_t sectionStart = section.VirtualAddress;
                    uint64_t sectionEnd = sectionStart + mappedSpan;
                    if (sectionEnd < sectionStart)
                    {
                        continue;
                    }

                    size_t sectionPagesCompared = 0;
                    for (uint64_t pageRva64 = sectionStart & ~0xfffull;
                         pageRva64 < sectionEnd;
                         pageRva64 += kPageSize)
                    {
                        if (pagesCompared >= kMaxDeepPagesPerProcess)
                        {
                            AddUnique(&process->Warnings, L"deep executable page comparison limit reached");
                            break;
                        }

                        if (!compareFullExecutableSections &&
                            sectionPagesCompared >= kMaxSampledExecPagesPerSection)
                        {
                            AddUnique(&process->Warnings, L"deep module comparison sampled non-builtin executable sections");
                            break;
                        }

                        if (pageRva64 > std::numeric_limits<uint32_t>::max())
                        {
                            break;
                        }

                        uint32_t pageRva = static_cast<uint32_t>(pageRva64);
                        if (comparedPageRvas.find(pageRva) != comparedPageRvas.end())
                        {
                            continue;
                        }

                        CompareModulePage(
                            device,
                            result,
                            *process,
                            module,
                            metadata,
                            L"executable_section",
                            section.Name,
                            pageRva,
                            &stackReferenceCache);
                        comparedPageRvas.insert(pageRva);
                        ++sectionPagesCompared;
                        ++pagesCompared;
                    }
                }

                ++compared;
            }

            if (stackReferenceCache.LimitReached)
            {
                AddUnique(&process->Warnings, L"deep stack reference cache hit the per-process sample limit");
            }
        } while (false);
    }

    const EdrKillerDriverProfile* FindDriverProfileForModuleRecord(
        const ByovdModuleRecord& record,
        std::wstring* matchedLeaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        do
        {
            std::vector<std::wstring> candidates =
            {
                record.ImageName,
                record.ImagePath,
                record.DiskPath
            };

            for (const std::wstring& candidate : candidates)
            {
                std::wstring leaf = LeafName(candidate);
                if (leaf.empty())
                {
                    continue;
                }

                profile = FindEdrKillerDriverProfileByLeaf(leaf);
                if (profile != nullptr)
                {
                    if (matchedLeaf != nullptr)
                    {
                        *matchedLeaf = leaf;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    const EdrKillerDriverProfile* FindDriverProfileForKernelModule(
        const KernelModuleInfo& module,
        std::wstring* matchedLeaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        do
        {
            std::vector<std::wstring> candidates =
            {
                module.ImageName,
                module.ImagePath
            };

            for (const std::wstring& candidate : candidates)
            {
                std::wstring leaf = LeafName(candidate);
                if (leaf.empty())
                {
                    continue;
                }

                profile = FindEdrKillerDriverProfileByLeaf(leaf);
                if (profile != nullptr)
                {
                    if (matchedLeaf != nullptr)
                    {
                        *matchedLeaf = leaf;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    const EdrKillerDriverProfile* FindDriverProfileForIntegrityRecord(
        const DriverIntegrityRecord& record,
        std::wstring* matchedLeaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        do
        {
            std::vector<std::wstring> candidates =
            {
                record.Name,
                record.DirectoryPath,
                record.OwningModule
            };

            for (const std::wstring& candidate : candidates)
            {
                std::wstring leaf = LeafName(candidate);
                if (leaf.empty())
                {
                    continue;
                }

                profile = FindEdrKillerDriverProfileByLeaf(leaf);
                if (profile != nullptr)
                {
                    if (matchedLeaf != nullptr)
                    {
                        *matchedLeaf = leaf;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    void AddByovdHuntFindings(
        HuntResult* result,
        const ByovdScanResult& byovd,
        std::set<std::wstring>* emittedLeaves)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const ByovdModuleRecord& record : byovd.Records)
            {
                if (record.Matches.empty())
                {
                    continue;
                }

                std::wstring matchedLeaf;
                const EdrKillerDriverProfile* profile = FindDriverProfileForModuleRecord(record, &matchedLeaf);
                if (!matchedLeaf.empty() && emittedLeaves != nullptr)
                {
                    emittedLeaves->insert(matchedLeaf);
                }

                std::vector<std::wstring> reasons =
                {
                    L"byovd_catalog_match",
                    L"loaded_vulnerable_or_malicious_driver"
                };
                if (profile != nullptr)
                {
                    AddUnique(&reasons, L"gentlemen_edr_killer_driver_name");
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"driver_image_name"] = record.ImageName;
                evidence[L"driver_image_path"] = record.ImagePath;
                evidence[L"driver_disk_path"] = record.DiskPath;
                evidence[L"driver_base"] = HuntHex(record.Base, 16);
                evidence[L"driver_size"] = std::to_wstring(record.Size);
                evidence[L"file_hashed"] = record.FileHashed ? L"true" : L"false";
                evidence[L"md5"] = record.Md5;
                evidence[L"sha1"] = record.Sha1;
                evidence[L"sha256"] = record.Sha256;
                evidence[L"match_count"] = std::to_wstring(record.Matches.size());
                evidence[L"matches"] = ByovdMatchEvidenceText(record.Matches);
                if (profile != nullptr)
                {
                    evidence[L"gentlemen_family"] = profile->Family;
                    evidence[L"gentlemen_tool"] = profile->Tool;
                    evidence[L"gentlemen_ioc_driver"] = profile->ImageName;
                    evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";
                }

                std::vector<std::wstring> followups =
                {
                    L"!byovd scan /no-update /limit 40",
                    L"!driver integrity all /limit 200"
                };

                AddSystemFinding(
                    result,
                    HasHighConfidenceByovdMatch(record.Matches) ? L"high" : L"medium",
                    HasHighConfidenceByovdMatch(record.Matches) ? L"high" : L"medium",
                    L"edr_killer_driver",
                    L"loaded kernel driver matches BYOVD intelligence",
                    record.Base,
                    !record.ImageName.empty() ? record.ImageName : matchedLeaf,
                    reasons,
                    evidence,
                    followups);
            }
        } while (false);
    }

    void AddGentlemenDriverNameFindings(
        HuntResult* result,
        const std::vector<KernelModuleInfo>& modules,
        const std::set<std::wstring>& emittedLeaves)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const KernelModuleInfo& module : modules)
            {
                std::wstring matchedLeaf;
                const EdrKillerDriverProfile* profile = FindDriverProfileForKernelModule(module, &matchedLeaf);
                if (profile == nullptr || matchedLeaf.empty())
                {
                    continue;
                }

                if (emittedLeaves.find(matchedLeaf) != emittedLeaves.end())
                {
                    continue;
                }
                if (!profile->StrongNameSignal)
                {
                    continue;
                }

                std::vector<std::wstring> reasons =
                {
                    L"gentlemen_edr_killer_driver_name",
                    L"loaded_driver_name_ioc"
                };

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"driver_image_name"] = module.ImageName;
                evidence[L"driver_image_path"] = module.ImagePath;
                evidence[L"driver_base"] = HuntHex(module.Base, 16);
                evidence[L"driver_size"] = std::to_wstring(module.Size);
                evidence[L"gentlemen_family"] = profile->Family;
                evidence[L"gentlemen_tool"] = profile->Tool;
                evidence[L"gentlemen_ioc_driver"] = profile->ImageName;
                evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";

                std::vector<std::wstring> followups =
                {
                    L"!byovd scan /no-update /exact /limit 40",
                    L"!driver integrity all /limit 200"
                };

                AddSystemFinding(
                    result,
                    profile->StrongNameSignal ? L"medium" : L"low",
                    profile->StrongNameSignal ? L"medium" : L"low",
                    L"edr_killer_driver_profile",
                    L"loaded kernel driver name matches Gentlemen EDR-killer driver IOC",
                    module.Base,
                    module.ImageName,
                    reasons,
                    evidence,
                    followups);
            }
        } while (false);
    }

    const EdrKillerDriverProfile* FindDriverProfileForServiceRecord(
        const DriverServiceRecord& record,
        std::wstring* matchedLeaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        do
        {
            std::vector<std::wstring> candidates =
            {
                record.BinaryLeaf,
                record.BinaryPath,
                record.ExpandedBinaryPath,
                record.ServiceName,
                record.DisplayName
            };

            for (const std::wstring& candidate : candidates)
            {
                std::wstring leaf = LeafName(candidate);
                if (leaf.empty())
                {
                    continue;
                }

                profile = FindEdrKillerDriverProfileByLeaf(leaf);
                if (profile != nullptr)
                {
                    if (matchedLeaf != nullptr)
                    {
                        *matchedLeaf = leaf;
                    }
                    break;
                }
            }
        } while (false);

        return profile;
    }

    void AddDriverServiceHuntFindings(HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::vector<DriverServiceRecord> services;
            std::vector<std::wstring> warnings;
            CollectDriverServices(&services, &warnings);
            result->DriverServiceCount = services.size();

            for (const std::wstring& warning : warnings)
            {
                AddUnique(&result->Warnings, L"driver service scan warning: " + warning);
            }

            for (const DriverServiceRecord& service : services)
            {
                std::wstring matchedLeaf;
                const EdrKillerDriverProfile* profile =
                    FindDriverProfileForServiceRecord(service, &matchedLeaf);
                if (profile == nullptr)
                {
                    continue;
                }

                ++result->EdrKillerDriverServiceCount;

                std::vector<std::wstring> reasons =
                {
                    L"driver_service_installed",
                    L"driver_service_binary_name_ioc",
                    L"gentlemen_edr_killer_driver_service"
                };
                if (service.Running)
                {
                    AddUnique(&reasons, L"driver_service_running");
                }
                else
                {
                    AddUnique(&reasons, L"driver_service_not_running");
                }
                if (!profile->StrongNameSignal)
                {
                    AddUnique(&reasons, L"name_only_requires_hash_or_service_correlation");
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"service_name"] = service.ServiceName;
                evidence[L"display_name"] = service.DisplayName;
                evidence[L"service_type"] = HuntHex(service.ServiceType, 8);
                evidence[L"state"] = service.StateText;
                evidence[L"start_type"] = service.StartTypeText;
                evidence[L"binary_path"] = service.BinaryPath;
                evidence[L"expanded_binary_path"] = service.ExpandedBinaryPath;
                evidence[L"binary_leaf"] = service.BinaryLeaf;
                evidence[L"matched_driver_leaf"] = matchedLeaf;
                evidence[L"has_config"] = service.HasConfig ? L"true" : L"false";
                evidence[L"gentlemen_family"] = profile->Family;
                evidence[L"gentlemen_tool"] = profile->Tool;
                evidence[L"gentlemen_ioc_driver"] = profile->ImageName;
                evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";

                std::vector<std::wstring> followups =
                {
                    L"sc.exe qc " + service.ServiceName,
                    L"sc.exe query " + service.ServiceName,
                    L"!byovd scan /no-update /exact /limit 40",
                    L"!driver integrity all /limit 200"
                };

                std::wstring risk = L"low";
                std::wstring confidence = L"low";
                if (profile->StrongNameSignal && service.Running)
                {
                    risk = L"high";
                    confidence = L"high";
                }
                else if (profile->StrongNameSignal)
                {
                    risk = L"medium";
                    confidence = L"high";
                }
                else if (service.Running)
                {
                    risk = L"medium";
                    confidence = L"medium";
                }

                AddSystemFinding(
                    result,
                    risk,
                    confidence,
                    L"edr_killer_driver_service",
                    L"driver service matches Gentlemen EDR-killer driver IOC",
                    0,
                    matchedLeaf,
                    reasons,
                    evidence,
                    followups);
            }
        } while (false);
    }

    std::wstring SuspiciousDispatchEvidenceText(const DriverIntegrityRecord& record)
    {
        std::vector<std::wstring> values;

        for (const DriverDispatchRecord& dispatch : record.Dispatch)
        {
            if (!dispatch.Suspicious)
            {
                continue;
            }

            if (values.size() >= kMaxDriverDispatchEvidence)
            {
                break;
            }

            std::wstringstream stream;
            stream << dispatch.Name
                   << L"="
                   << HuntHex(dispatch.Function, 16);
            if (!dispatch.ModuleName.empty())
            {
                stream << L":"
                       << dispatch.ModuleName;
            }
            if (!dispatch.Notes.empty())
            {
                stream << L":"
                       << dispatch.Notes;
            }
            values.push_back(stream.str());
        }

        return JoinWideValues(values, L";");
    }

    void AddDriverIntegrityHuntFindings(
        HuntResult* result,
        const DriverIntegrityResult& driverIntegrity)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const DriverIntegrityRecord& record : driverIntegrity.Records)
            {
                if (!record.Suspicious)
                {
                    continue;
                }

                std::wstring matchedLeaf;
                const EdrKillerDriverProfile* profile =
                    FindDriverProfileForIntegrityRecord(record, &matchedLeaf);

                std::vector<std::wstring> reasons =
                {
                    L"driver_object_integrity_anomaly"
                };
                if (record.SuspiciousDispatchCount != 0)
                {
                    AddUnique(&reasons, L"driver_dispatch_pointer_anomaly");
                }
                if (record.HasDriverStart && record.OwningModule.empty())
                {
                    AddUnique(&reasons, L"driver_start_outside_loaded_module");
                }
                if (profile != nullptr)
                {
                    AddUnique(&reasons, L"gentlemen_edr_killer_driver_name");
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"driver_name"] = record.Name;
                evidence[L"driver_directory"] = record.DirectoryPath;
                evidence[L"driver_object"] = HuntHex(record.DriverObject, 16);
                evidence[L"driver_start"] = HuntHex(record.DriverStart, 16);
                evidence[L"driver_size"] = std::to_wstring(record.DriverSize);
                evidence[L"driver_section"] = HuntHex(record.DriverSection, 16);
                evidence[L"owning_module"] = record.OwningModule;
                evidence[L"suspicious_dispatch_count"] = std::to_wstring(record.SuspiciousDispatchCount);
                evidence[L"suspicious_dispatch"] = SuspiciousDispatchEvidenceText(record);
                evidence[L"notes"] = record.Notes;
                if (profile != nullptr)
                {
                    evidence[L"gentlemen_family"] = profile->Family;
                    evidence[L"gentlemen_tool"] = profile->Tool;
                    evidence[L"gentlemen_ioc_driver"] = profile->ImageName;
                    evidence[L"matched_driver_leaf"] = matchedLeaf;
                    evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";
                }

                std::vector<std::wstring> followups =
                {
                    L"!driver integrity " + record.Name + L" /limit 80",
                    L"!ssdt",
                    L"callbacks all"
                };

                AddSystemFinding(
                    result,
                    L"high",
                    L"medium",
                    L"kernel_driver_integrity",
                    L"driver object dispatch or start pointer integrity anomaly",
                    record.DriverObject,
                    record.Name,
                    reasons,
                    evidence,
                    followups);
            }
        } while (false);
    }

    void AddKernelDriverHuntFindings(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::wstring& executableDirectory,
        HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::set<std::wstring> emittedLeaves;

            ByovdScanner byovdScanner(symbols, executableDirectory);
            ByovdScanOptions byovdOptions = {};
            byovdOptions.AutoUpdate = false;
            byovdOptions.ForceUpdate = false;
            byovdOptions.ExactOnly = true;
            byovdOptions.EnableYara = false;
            byovdOptions.Verbose = false;
            byovdOptions.Limit = 0;

            ByovdScanResult byovd = {};
            std::wstring error;
            if (byovdScanner.Scan(byovdOptions, &byovd, &error))
            {
                result->KernelModuleCount = byovd.ModulesScanned;
                result->ByovdMatchedDriverCount = byovd.MatchedModules;
                for (const std::wstring& warning : byovd.Warnings)
                {
                    AddUnique(&result->Warnings, L"BYOVD scan warning: " + warning);
                }
                AddByovdHuntFindings(result, byovd, &emittedLeaves);
            }
            else
            {
                AddUnique(&result->Warnings, L"deep BYOVD scan failed: " + error);
            }

            if (symbols.Modules().empty())
            {
                error.clear();
                if (!symbols.LoadKernelModules(&error))
                {
                    AddUnique(&result->Warnings, L"kernel module list unavailable for EDR-killer driver name scan: " + error);
                }
            }

            if (!symbols.Modules().empty())
            {
                if (result->KernelModuleCount == 0)
                {
                    result->KernelModuleCount = symbols.Modules().size();
                }
                AddGentlemenDriverNameFindings(result, symbols.Modules(), emittedLeaves);
            }

            AddDriverServiceHuntFindings(result);

            IntegrityScanner integrityScanner(device, symbols);
            DriverIntegrityOptions integrityOptions = {};
            integrityOptions.Limit = 0;

            DriverIntegrityResult driverIntegrity = {};
            error.clear();
            if (integrityScanner.ScanDrivers(integrityOptions, &driverIntegrity, &error))
            {
                result->DriverObjectCount = driverIntegrity.DriversScanned;
                result->SuspiciousDriverObjectCount = driverIntegrity.SuspiciousDrivers;
                for (const std::wstring& warning : driverIntegrity.Warnings)
                {
                    AddUnique(&result->Warnings, L"driver integrity warning: " + warning);
                }
                AddDriverIntegrityHuntFindings(result, driverIntegrity);
            }
            else
            {
                AddUnique(&result->Warnings, L"deep driver integrity scan failed: " + error);
            }
        } while (false);
    }

    void SortAndCountFindings(HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            std::sort(
                result->Findings.begin(),
                result->Findings.end(),
                [](const HuntFinding& left, const HuntFinding& right)
                {
                    uint32_t leftRisk = SnapshotRiskRank(left.Risk);
                    uint32_t rightRisk = SnapshotRiskRank(right.Risk);
                    if (leftRisk != rightRisk)
                    {
                        return leftRisk > rightRisk;
                    }

                    uint32_t leftConfidence = ConfidenceRank(left.Confidence);
                    uint32_t rightConfidence = ConfidenceRank(right.Confidence);
                    if (leftConfidence != rightConfidence)
                    {
                        return leftConfidence > rightConfidence;
                    }

                    if (left.ProcessId != right.ProcessId)
                    {
                        return left.ProcessId < right.ProcessId;
                    }

                    return left.Address < right.Address;
                });

            result->HighFindings = 0;
            result->MediumFindings = 0;
            result->LowFindings = 0;
            result->InfoFindings = 0;
            for (const HuntFinding& finding : result->Findings)
            {
                std::wstring risk = SnapshotRiskNormalize(finding.Risk);
                if (risk == L"high")
                {
                    ++result->HighFindings;
                }
                else if (risk == L"medium")
                {
                    ++result->MediumFindings;
                }
                else if (risk == L"low")
                {
                    ++result->LowFindings;
                }
                else
                {
                    ++result->InfoFindings;
                }
            }
        } while (false);
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
            json << L"\"" << HuntJsonEscape(values[index]) << L"\"";
        }
        json << L"]";
    }
}

std::wstring HuntModeToText(HuntMode mode)
{
    std::wstring text = L"default";

    if (mode == HuntMode::Quick)
    {
        text = L"quick";
    }
    else if (mode == HuntMode::Deep)
    {
        text = L"deep";
    }

    return text;
}

UserModeHunter::UserModeHunter(
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& executableDirectory) :
    device_(device),
    symbols_(symbols),
    executableDirectory_(executableDirectory)
{
}

bool UserModeHunter::Scan(const HuntOptions& options, HuntResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid hunt result output";
            }
            break;
        }

        *result = {};
        result->Schema = L"kn-live-dbg.hunt.v1";
        result->TimestampUtc = SnapshotCurrentUtcTimestamp();
        result->ModeText = HuntModeToText(options.Mode);
        result->ThreatIntelActive = options.ThreatIntelActive;
        result->ThreatIntelAvailable = options.ThreatIntelAvailable || !options.ThreatIntelEvents.empty();
        result->Warnings.push_back(L"PspCidTable process-object cross-view is not implemented; cid_table_seen is null");
        result->Warnings.push_back(L"builtin process signer verification is not implemented; publisher evidence unavailable");

        std::map<uint32_t, HuntProcessRecord> processes;
        for (const SnapshotProcessRecord& process : options.Processes)
        {
            HuntProcessRecord record = {};
            record.Kernel = process;
            record.ProcessId = process.ProcessId;
            record.ActiveProcessLinksSeen = true;
            record.KernelImageName = process.ImageName;
            processes[record.ProcessId] = record;
        }

        result->KernelProcessCount = processes.size();

        std::map<uint32_t, ApiProcessRecord> systemProcesses;
        std::wstring warning;
        if (CollectSystemProcessInformation(&systemProcesses, &warning))
        {
            result->SystemProcessInfoCount = systemProcesses.size();
            for (const auto& item : systemProcesses)
            {
                HuntProcessRecord& record = processes[item.first];
                record.ProcessId = item.first;
                record.SystemProcessInformationSeen = true;
                record.SystemProcessImageName = item.second.ImageName;
                if (item.second.HasParentProcessId)
                {
                    record.ParentProcessId = item.second.ParentProcessId;
                    record.HasParentProcessId = true;
                }
            }
        }
        else if (!warning.empty())
        {
            result->Warnings.push_back(warning);
        }

        std::map<uint32_t, ApiProcessRecord> toolhelpProcesses;
        warning.clear();
        if (CollectToolhelpProcesses(&toolhelpProcesses, &warning))
        {
            result->ToolhelpProcessCount = toolhelpProcesses.size();
            for (const auto& item : toolhelpProcesses)
            {
                HuntProcessRecord& record = processes[item.first];
                record.ProcessId = item.first;
                record.ToolhelpProcessSeen = true;
                record.ToolhelpImageName = item.second.ImageName;
                if (item.second.HasParentProcessId)
                {
                    record.ParentProcessId = item.second.ParentProcessId;
                    record.HasParentProcessId = true;
                }
            }
        }
        else if (!warning.empty())
        {
            result->Warnings.push_back(warning);
        }

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (process.HasParentProcessId)
            {
                auto parent = processes.find(process.ParentProcessId);
                if (parent != processes.end())
                {
                    process.ParentImageName = BestProcessImageName(parent->second);
                }
            }
        }

        ProcessTriageScanner triage(device_, symbols_);

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (process.ProcessId == 0 && process.Kernel.ProcessId == 0)
            {
                process.Kernel.ProcessId = process.ProcessId;
            }

            QueryProcessPublicDetails(&process);
            AddProcessViewFindings(result, process);

            if (process.ActiveProcessLinksSeen && process.Kernel.Eprocess != 0)
            {
                CollectPebIdentity(device_, &process);
                ApplyBuiltinProfile(&process);
                CollectPebLdrModules(device_, &process);

                warning.clear();
                if (!CollectToolhelpModules(&process, &warning) && !warning.empty())
                {
                    AddUnique(&process.Warnings, warning);
                }

                ProcessVadScanOptions vadOptions = {};
                vadOptions.Target = BuildTriageTarget(process.Kernel);
                vadOptions.ProbePe = true;
                vadOptions.ScanHiddenPtes =
                    options.Mode != HuntMode::Quick &&
                    HasVerifiedUserAddressSpace(process.Kernel);
                vadOptions.HiddenPteExecutableOnly = true;
                vadOptions.RequireVadCoverageForHiddenPtes = true;
                vadOptions.HiddenPteLimit = kHuntHiddenPteRecordLimitPerProcess;

                ProcessVadScanResult vadResult = {};
                std::wstring scanError;
                if (triage.ScanVad(vadOptions, &vadResult, &scanError))
                {
                    process.VadRecords = std::move(vadResult.Records);
                    process.HiddenPteRecords = std::move(vadResult.HiddenPteRecords);
                    process.VadNodesVisited = vadResult.NodesVisited;
                    process.ExecutableVadCount = vadResult.ExecutableCount;
                    process.PrivateExecutableVadCount = vadResult.PrivateExecutableCount;
                    process.WxVadCount = vadResult.WxCount;
                    process.PeLikeVadCount = vadResult.PeLikeCount;
                    process.HiddenPteRanges = vadResult.HiddenPteRanges;
                    process.HiddenPteBytes = vadResult.HiddenPteBytes;
                    process.Warnings.insert(process.Warnings.end(), vadResult.Warnings.begin(), vadResult.Warnings.end());
                    if (vadResult.HiddenPteTruncated)
                    {
                        AddUnique(&process.Warnings, L"hidden PTE scan hit the hunt per-process record limit");
                    }
                    result->VadRecordCount += vadResult.TotalRecords;
                    result->HiddenPteRangeCount += vadResult.HiddenPteRanges;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"VAD scan failed: " + scanError);
                }

                ProcessThreadScanOptions threadOptions = {};
                threadOptions.Target = BuildTriageTarget(process.Kernel);
                threadOptions.IncludeApc = true;
                threadOptions.IncludeStacks = options.Mode == HuntMode::Deep;

                ProcessThreadScanResult threadResult = {};
                scanError.clear();
                if (triage.ScanThreads(threadOptions, &threadResult, &scanError))
                {
                    process.ThreadRecords = std::move(threadResult.Records);
                    process.ThreadsVisited = threadResult.ThreadsVisited;
                    process.SuspiciousThreadStarts = threadResult.SuspiciousStartCount;
                    process.NonEmptyApcQueues = threadResult.ApcNonEmptyCount;
                    process.StackReferenceCount = threadResult.StackReferenceCount;
                    process.Warnings.insert(process.Warnings.end(), threadResult.Warnings.begin(), threadResult.Warnings.end());
                    result->ThreadRecordCount += threadResult.MatchingRecords;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"thread scan failed: " + scanError);
                }

                AddIdentityFindings(result, process);
                AddEdrKillerProcessProfileFindings(result, process);
                AddVadFindings(device_, symbols_, result, &process);
                AddThreadFindings(result, process);
                AddModuleCrossViewFindings(result, process);
                AddBuiltinModuleProvenanceFindings(result, process);
                AddMainImageVadFinding(device_, symbols_, result, &process);

                if (options.Mode == HuntMode::Deep)
                {
                    AddDeepImageIntegrityFindings(device_, result, &process);
                }

                ++result->ScannedProcessCount;
            }
            else
            {
                ApplyBuiltinProfile(&process);
                AddIdentityFindings(result, process);
                AddEdrKillerProcessProfileFindings(result, process);
            }

            result->ModuleRecordCount += process.Modules.size();
        }

        if (options.Mode == HuntMode::Deep)
        {
            AddKernelDriverHuntFindings(device_, symbols_, executableDirectory_, result);
        }

        AddThreatIntelCorrelationFindings(result, processes, options);

        result->Processes.reserve(processes.size());
        for (auto& item : processes)
        {
            result->Processes.push_back(std::move(item.second));
        }

        SortAndCountFindings(result);
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHuntJson(const HuntResult& result)
{
    std::wstringstream json;

    json << L"{\n";
    json << L"  \"schema\":\"" << HuntJsonEscape(result.Schema) << L"\",\n";
    json << L"  \"timestamp_utc\":\"" << HuntJsonEscape(result.TimestampUtc) << L"\",\n";
    json << L"  \"mode\":\"" << HuntJsonEscape(result.ModeText) << L"\",\n";
    json << L"  \"summary\":{";
    json << L"\"kernel_processes\":" << result.KernelProcessCount;
    json << L",\"system_process_information_processes\":" << result.SystemProcessInfoCount;
    json << L",\"toolhelp_processes\":" << result.ToolhelpProcessCount;
    json << L",\"scanned_processes\":" << result.ScannedProcessCount;
    json << L",\"findings\":" << result.Findings.size();
    json << L",\"high\":" << result.HighFindings;
    json << L",\"medium\":" << result.MediumFindings;
    json << L",\"low\":" << result.LowFindings;
    json << L",\"info\":" << result.InfoFindings;
    json << L",\"vad_records\":" << result.VadRecordCount;
    json << L",\"hidden_pte_ranges\":" << result.HiddenPteRangeCount;
    json << L",\"thread_records\":" << result.ThreadRecordCount;
    json << L",\"module_records\":" << result.ModuleRecordCount;
    json << L",\"kernel_modules\":" << result.KernelModuleCount;
    json << L",\"byovd_matched_drivers\":" << result.ByovdMatchedDriverCount;
    json << L",\"driver_objects\":" << result.DriverObjectCount;
    json << L",\"suspicious_driver_objects\":" << result.SuspiciousDriverObjectCount;
    json << L",\"driver_services\":" << result.DriverServiceCount;
    json << L",\"edr_killer_driver_services\":" << result.EdrKillerDriverServiceCount;
    json << L",\"threat_intel_active\":" << (result.ThreatIntelActive ? L"true" : L"false");
    json << L",\"threat_intel_available\":" << (result.ThreatIntelAvailable ? L"true" : L"false");
    json << L",\"threat_intel_events\":" << result.ThreatIntelEventCount;
    json << L",\"threat_intel_correlations\":" << result.ThreatIntelCorrelationCount;
    json << L"},\n";

    json << L"  \"warnings\":";
    AppendJsonStringArray(json, result.Warnings);
    json << L",\n";

    json << L"  \"findings\":[\n";
    for (size_t index = 0; index < result.Findings.size(); ++index)
    {
        const HuntFinding& finding = result.Findings[index];
        json << L"    {";
        json << L"\"risk\":\"" << HuntJsonEscape(finding.Risk) << L"\"";
        json << L",\"confidence\":\"" << HuntJsonEscape(finding.Confidence) << L"\"";
        json << L",\"class\":\"" << HuntJsonEscape(finding.ClassName) << L"\"";
        json << L",\"title\":\"" << HuntJsonEscape(finding.Title) << L"\"";
        json << L",\"pid\":" << finding.ProcessId;
        json << L",\"eprocess\":\"" << HuntHex(finding.Eprocess, 16) << L"\"";
        json << L",\"address\":\"" << HuntHex(finding.Address, 16) << L"\"";
        json << L",\"image\":\"" << HuntJsonEscape(finding.ImageName) << L"\"";
        json << L",\"module\":\"" << HuntJsonEscape(finding.ModuleName) << L"\"";
        json << L",\"reasons\":";
        AppendJsonStringArray(json, finding.ReasonCodes);
        json << L",\"evidence\":{";
        size_t evidenceIndex = 0;
        for (const auto& item : finding.Evidence)
        {
            if (evidenceIndex != 0)
            {
                json << L",";
            }
            json << L"\"" << HuntJsonEscape(item.first) << L"\":\"" << HuntJsonEscape(item.second) << L"\"";
            ++evidenceIndex;
        }
        json << L"},\"followups\":";
        AppendJsonStringArray(json, finding.Followups);
        json << L"}";
        if (index + 1 != result.Findings.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ],\n";

    json << L"  \"processes\":[\n";
    for (size_t index = 0; index < result.Processes.size(); ++index)
    {
        const HuntProcessRecord& process = result.Processes[index];
        json << L"    {";
        json << L"\"pid\":" << process.ProcessId;
        json << L",\"eprocess\":\"" << HuntHex(process.Kernel.Eprocess, 16) << L"\"";
        json << L",\"active_process_links_seen\":" << (process.ActiveProcessLinksSeen ? L"true" : L"false");
        json << L",\"system_process_information_seen\":" << (process.SystemProcessInformationSeen ? L"true" : L"false");
        json << L",\"toolhelp_seen\":" << (process.ToolhelpProcessSeen ? L"true" : L"false");
        json << L",\"cid_table_seen\":";
        if (process.HasCidTableView)
        {
            json << (process.CidTableSeen ? L"true" : L"false");
        }
        else
        {
            json << L"null";
        }
        json << L",\"image_name\":\"" << HuntJsonEscape(process.KernelImageName) << L"\"";
        json << L",\"system_process_image\":\"" << HuntJsonEscape(process.SystemProcessImageName) << L"\"";
        json << L",\"toolhelp_image\":\"" << HuntJsonEscape(process.ToolhelpImageName) << L"\"";
        json << L",\"api_image_path\":\"" << HuntJsonEscape(process.ApiImagePath) << L"\"";
        json << L",\"peb_image_base\":";
        if (process.HasPebImageBase)
        {
            json << L"\"" << HuntHex(process.PebImageBase, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"peb_image_path\":\"" << HuntJsonEscape(process.PebImagePath) << L"\"";
        json << L",\"peb_command_line\":\"" << HuntJsonEscape(process.PebCommandLine) << L"\"";
        json << L",\"parent_image\":\"" << HuntJsonEscape(process.ParentImageName) << L"\"";
        json << L",\"builtin_profile\":\"" << HuntJsonEscape(process.BuiltinProfile) << L"\"";
        json << L",\"builtin_profile_matched\":" << (process.BuiltinProfileMatched ? L"true" : L"false");
        json << L",\"builtin_profile_expected_paths\":";
        AppendJsonStringArray(json, process.BuiltinProfileExpectedPaths);
        json << L",\"builtin_profile_violations\":";
        AppendJsonStringArray(json, process.BuiltinProfileViolations);
        json << L",\"builtin_signature_verified\":" << (process.BuiltinSignatureVerified ? L"true" : L"false");
        json << L",\"peb_ldr_core_enumerated\":" << (process.PebLdrEnumerated ? L"true" : L"false");
        json << L",\"peb_ldr_load_enumerated\":" << (process.PebLdrLoadEnumerated ? L"true" : L"false");
        json << L",\"peb_ldr_memory_enumerated\":" << (process.PebLdrMemoryEnumerated ? L"true" : L"false");
        json << L",\"peb_ldr_init_enumerated\":" << (process.PebLdrInitEnumerated ? L"true" : L"false");
        json << L",\"main_image_base\":";
        if (process.MainImageBase != 0)
        {
            json << L"\"" << HuntHex(process.MainImageBase, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"main_image_size\":" << process.MainImageSize;
        json << L",\"main_image_vad\":";
        if (process.MainImageVad != 0)
        {
            json << L"\"" << HuntHex(process.MainImageVad, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"section_backing_path\":\"" << HuntJsonEscape(process.SectionBackingPath) << L"\"";
        json << L",\"section_backing_state\":\"" << HuntJsonEscape(process.SectionBackingState) << L"\"";
        json << L",\"disk_path\":\"" << HuntJsonEscape(process.DiskPath) << L"\"";
        json << L",\"parent_pid\":";
        if (process.HasParentProcessId)
        {
            json << process.ParentProcessId;
        }
        else
        {
            json << L"null";
        }
        json << L",\"session_id\":";
        if (process.HasSessionId)
        {
            json << process.SessionId;
        }
        else
        {
            json << L"null";
        }
        json << L",\"counts\":{";
        json << L"\"vad_records\":" << process.VadRecords.size();
        json << L",\"hidden_pte_records\":" << process.HiddenPteRecords.size();
        json << L",\"threads\":" << process.ThreadRecords.size();
        json << L",\"modules\":" << process.Modules.size();
        json << L",\"private_executable_vads\":" << process.PrivateExecutableVadCount;
        json << L",\"wx_vads\":" << process.WxVadCount;
        json << L",\"pe_like_vads\":" << process.PeLikeVadCount;
        json << L",\"hidden_pte_ranges\":" << process.HiddenPteRanges;
        json << L",\"suspicious_thread_starts\":" << process.SuspiciousThreadStarts;
        json << L",\"stack_references\":" << process.StackReferenceCount;
        json << L"},\"warnings\":";
        AppendJsonStringArray(json, process.Warnings);
        json << L"}";
        if (index + 1 != result.Processes.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";

    return json.str();
}
