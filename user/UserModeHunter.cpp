#include "UserModeHunter.h"

#include "BindFilterScanner.h"
#include "ByovdScanner.h"
#include "CloudFileScanner.h"
#include "IntegrityScanner.h"
#include "QosPolicyScanner.h"
#include "WfpScanner.h"
#include "Zydis.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <ShlObj.h>
#include <WinTrust.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwchar>
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
    constexpr uint32_t kMaxGenericWxFindingsPerProcess = 8;
    constexpr size_t kEprocessImageNameMaxChars = 15;
    constexpr size_t kMaxPebStringBytes = 32768;
    constexpr size_t kMaxLdrModules = 1024;
    constexpr uint32_t kHuntHiddenPteRecordLimitPerProcess = 64;
    constexpr uint32_t kHuntTriageStabilityAttempts = 3;
    // A full process-CID scan is bounded independently of attacker-controlled
    // handle-table metadata. Exceeding this is incomplete coverage, never a
    // clean result. 262,144 live CID slots is well above normal workstation
    // and server concurrency while keeping worst-case IOCTL work finite.
    constexpr uint32_t kMaxCidProcessProbeCount = 262144;
    constexpr uint32_t kCidAnchorCodeBytes = 0x200;
    constexpr uint32_t kCidAnchorMaxInstructions = 96;
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
    // Large Microsoft images legitimately carry several million base-reloc
    // entries. Keep a separate allocation guard, but do not reject those
    // images merely because the table is larger than older desktop binaries.
    constexpr size_t kMaxBaseRelocationEntries = 8 * 1024 * 1024;
    constexpr uint32_t kMaxBaseRelocationTableBytes = 64u * 1024u * 1024u;
    constexpr size_t kMaxDynamicRelocationRanges = 65536;
    constexpr uint64_t kUserAddressMax = 0x00ffffffffffffffull;
    constexpr uint64_t kKernelAddressMin = 0xffff800000000000ull;
    constexpr uint32_t kComImageFlagsIlOnly = 0x00000001u;

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
        // The documented x64 SYSTEM_PROCESS_INFORMATION prefix is 0x100
        // bytes. The variable SYSTEM_THREAD_INFORMATION array begins
        // immediately after it.
        BYTE ReservedAfterParentProcessId[0xa0];
    };

    struct HuntSystemThreadInformation
    {
        LARGE_INTEGER Reserved1[3];
        ULONG Reserved2;
        PVOID StartAddress;
        PVOID UniqueProcess;
        PVOID UniqueThread;
        LONG Priority;
        LONG BasePriority;
        ULONG Reserved3;
        ULONG ThreadState;
        ULONG WaitReason;
    };

    static_assert(
        sizeof(HuntSystemProcessInformation) == 0x100,
        "x64 SYSTEM_PROCESS_INFORMATION prefix changed");
    static_assert(
        sizeof(HuntSystemThreadInformation) == 0x50,
        "x64 SYSTEM_THREAD_INFORMATION layout changed");

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

    struct ScopedHuntHandle
    {
        explicit ScopedHuntHandle(HANDLE value = nullptr) :
            Value(value)
        {
        }

        ~ScopedHuntHandle()
        {
            if (Value != nullptr &&
                Value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Value);
            }
        }

        ScopedHuntHandle(const ScopedHuntHandle&) = delete;
        ScopedHuntHandle& operator=(const ScopedHuntHandle&) = delete;

        HANDLE Value = nullptr;
    };

    typedef LONG (NTAPI* NtQuerySystemInformationFn)(ULONG, PVOID, ULONG, PULONG);

    struct ApiProcessRecord
    {
        uint32_t ProcessId = 0;
        uint32_t ParentProcessId = 0;
        bool HasParentProcessId = false;
        std::wstring ImageName;
    };

    struct ApiThreadRecord
    {
        uint32_t ThreadId = 0;
        uint32_t ProcessId = 0;
    };

    bool IsReservedCidZeroThread(
        uint64_t threadId,
        uint64_t processId)
    {
        // The PID 0 Idle pseudo-process can expose one or more CPU idle
        // records with CLIENT_ID {0, 0}. Handle-table slot zero is reserved,
        // so these records have no allocatable PspCidTable counterpart.
        return threadId == 0 && processId == 0;
    }

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

    struct DiskPeMutableRange
    {
        uint32_t Rva = 0;
        uint32_t Size = 0;
    };

    struct DiskPeBaseRelocation
    {
        uint32_t Rva = 0;
        uint32_t Width = 0;
    };

    struct DiskPeMetadata
    {
        BY_HANDLE_FILE_INFORMATION FileIdentity = {};
        FILE_BASIC_INFO FileBasicIdentity = {};
        bool HasFileIdentity = false;
        bool HasFileBasicIdentity = false;
        uint64_t ImageBase = 0;
        uint32_t EntryPointRva = 0;
        uint32_t FirstExecutableSectionRva = 0;
        uint32_t SizeOfHeaders = 0;
        uint32_t SizeOfImage = 0;
        bool HasEntryPoint = false;
        bool HasExecutableSection = false;
        bool ManagedImage = false;
        bool ManagedIlOnly = false;
        std::vector<DiskPeSection> Sections;
        std::set<uint32_t> RelocationPages;
        std::vector<DiskPeBaseRelocation> BaseRelocations;
        std::vector<DiskPeMutableRange> CrossPageRelocationRanges;
        std::vector<DiskPeMutableRange> LoaderMutableRanges;
        std::vector<DiskPeMutableRange> DynamicRelocationRanges;
        uint32_t BaserelocRva = 0;
        uint32_t BaserelocSize = 0;
        bool BaseRelocationTablePresent = false;
        bool BaseRelocationTableComplete = true;
        bool DynamicRelocationTablePresent = false;
        bool DynamicRelocationTableComplete = true;
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

    struct EsetFileSha1Ioc
    {
        const wchar_t* Sha1;
        const wchar_t* FileName;
        const wchar_t* Family;
        const wchar_t* Tool;
        bool ProcessImage;
        bool DriverImage;
        bool CredentialTool;
    };

    struct FileSha1CacheEntry
    {
        bool Success = false;
        std::wstring Path;
        std::wstring Sha1;
        std::wstring Error;
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

    bool VerifyImageAuthenticodeSignature(
        const std::wstring& path,
        ImageMetadataRecord* metadata);

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
        TypeFieldInfo FileObjectSectionObjectPointer = {};
        TypeFieldInfo FileObjectDeletePending = {};
        TypeFieldInfo FileObjectWriteAccess = {};
        TypeFieldInfo FileObjectDeleteAccess = {};
        TypeFieldInfo FileObjectSharedWrite = {};
        TypeFieldInfo FileObjectSharedDelete = {};
        TypeFieldInfo FileObjectFlags = {};
        TypeFieldInfo SectionObjectPointersImageSectionObject = {};
        TypeFieldInfo SectionObjectPointersDataSectionObject = {};
        bool HasSubsectionControlArea = false;
        bool HasControlAreaFilePointer = false;
        bool HasControlAreaImageFlag = false;
        bool HasFileObjectFileName = false;
        bool HasFileObjectSectionObjectPointer = false;
        bool HasFileObjectDeletePending = false;
        bool HasFileObjectWriteAccess = false;
        bool HasFileObjectDeleteAccess = false;
        bool HasFileObjectSharedWrite = false;
        bool HasFileObjectSharedDelete = false;
        bool HasFileObjectFlags = false;
        bool HasSectionObjectPointersImageSectionObject = false;
        bool HasSectionObjectPointersDataSectionObject = false;
        bool Resolved = false;
        std::vector<std::wstring> Warnings;
    };

    struct MainSectionObjectLayout
    {
        TypeFieldInfo EprocessSectionObject = {};
        TypeFieldInfo SectionObjectSegment = {};
        TypeFieldInfo SegmentControlArea = {};
        TypeFieldInfo ControlAreaSegment = {};
        TypeFieldInfo ControlAreaFilePointer = {};
        TypeFieldInfo ControlAreaImageFlag = {};
        TypeFieldInfo FileObjectFileName = {};
        TypeFieldInfo FileObjectSectionObjectPointer = {};
        TypeFieldInfo FileObjectDeletePending = {};
        TypeFieldInfo FileObjectWriteAccess = {};
        TypeFieldInfo FileObjectDeleteAccess = {};
        TypeFieldInfo FileObjectSharedWrite = {};
        TypeFieldInfo FileObjectSharedDelete = {};
        TypeFieldInfo FileObjectFlags = {};
        TypeFieldInfo SectionObjectPointersImageSectionObject = {};
        TypeFieldInfo SectionObjectPointersDataSectionObject = {};
        bool HasEprocessSectionObject = false;
        bool HasSectionObjectSegment = false;
        bool HasSegmentControlArea = false;
        bool HasControlAreaSegment = false;
        bool HasControlAreaFilePointer = false;
        bool HasControlAreaImageFlag = false;
        bool HasFileObjectFileName = false;
        bool HasFileObjectSectionObjectPointer = false;
        bool HasFileObjectDeletePending = false;
        bool HasFileObjectWriteAccess = false;
        bool HasFileObjectDeleteAccess = false;
        bool HasFileObjectSharedWrite = false;
        bool HasFileObjectSharedDelete = false;
        bool HasFileObjectFlags = false;
        bool HasSectionObjectPointersImageSectionObject = false;
        bool HasSectionObjectPointersDataSectionObject = false;
        bool Resolved = false;
        std::vector<std::wstring> Warnings;
    };

    struct ControlAreaBackingDetails
    {
        std::wstring Path;
        std::wstring State = L"unavailable";
        uint64_t ControlArea = 0;
        uint64_t FileFastRef = 0;
        uint64_t FileObject = 0;
        uint64_t SectionObjectPointers = 0;
        uint64_t ImageSectionObject = 0;
        uint64_t DataSectionObject = 0;
        uint32_t FileFlags = 0;
        bool HasFileFlags = false;
        bool HasDeletePending = false;
        bool DeletePending = false;
        bool HasWriteAccess = false;
        bool WriteAccess = false;
        bool HasDeleteAccess = false;
        bool DeleteAccess = false;
        bool HasSharedWrite = false;
        bool SharedWrite = false;
        bool HasSharedDelete = false;
        bool SharedDelete = false;
        bool HasSectionObjectPointers = false;
        bool HasImageSectionObject = false;
        bool HasDataSectionObject = false;
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

    std::wstring StripExeExtensionFromLeaf(const std::wstring& leaf)
    {
        std::wstring stripped = leaf;

        do
        {
            constexpr size_t extensionLength = 4;
            if (stripped.size() <= extensionLength)
            {
                break;
            }

            if (stripped.compare(stripped.size() - extensionLength, extensionLength, L".exe") == 0)
            {
                stripped.resize(stripped.size() - extensionLength);
            }
        } while (false);

        return stripped;
    }

    bool SameLeafOrEprocessImageNamePrefix(const std::wstring& eprocessImageName, const std::wstring& imagePath)
    {
        bool same = false;

        do
        {
            std::wstring eprocessLeaf = LeafName(eprocessImageName);
            std::wstring pathLeaf = LeafName(imagePath);
            if (eprocessLeaf.empty() || pathLeaf.empty())
            {
                break;
            }

            if (eprocessLeaf == pathLeaf)
            {
                same = true;
                break;
            }

            std::wstring pathStem = StripExeExtensionFromLeaf(pathLeaf);
            if (eprocessLeaf == pathStem)
            {
                same = true;
                break;
            }

            bool plausibleTruncatedEprocessName =
                eprocessLeaf.size() >= 12 ||
                eprocessLeaf.size() == kEprocessImageNameMaxChars ||
                eprocessLeaf.back() == L'.';
            if (plausibleTruncatedEprocessName &&
                ((pathLeaf.size() > eprocessLeaf.size() &&
                  pathLeaf.compare(0, eprocessLeaf.size(), eprocessLeaf) == 0) ||
                 (pathStem.size() > eprocessLeaf.size() &&
                  pathStem.compare(0, eprocessLeaf.size(), eprocessLeaf) == 0)))
            {
                same = true;
                break;
            }
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
            { L"hwaudkiller.exe", nullptr, L"HavocKiller", L"HavocKiller", true, false, false },
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

    const EdrKillerDriverProfile* EdrKillerDriverProfiles(size_t* count)
    {
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
            { L"poisonx", L"GentleKiller", L"PoisonX rootkit", true },
            { L"poisonx.sys", L"GentleKiller", L"PoisonX rootkit", true },
            { L"g11.sys", L"GentleKiller", L"PoisonX rootkit", true },
            { L"googleapiutil64.sys", L"HexKiller", L"Baidu Antivirus BdApi driver", true },
            { L"throttleblood.sys", L"ThrottleBlood", L"ThrottleStop driver", true },
            { L"havoc.sys", L"HavocKiller", L"Huawei vulnerable driver", true }
        };

        if (count != nullptr)
        {
            *count = _countof(kProfiles);
        }

        return kProfiles;
    }

    const EdrKillerDriverProfile* FindEdrKillerDriverProfileByLeaf(const std::wstring& leaf)
    {
        const EdrKillerDriverProfile* profile = nullptr;

        do
        {
            if (leaf.empty())
            {
                break;
            }

            size_t profileCount = 0;
            const EdrKillerDriverProfile* profiles = EdrKillerDriverProfiles(&profileCount);
            for (size_t index = 0; index < profileCount; ++index)
            {
                const EdrKillerDriverProfile& item = profiles[index];
                if (leaf == item.ImageName)
                {
                    profile = &item;
                    break;
                }
            }
        } while (false);

        return profile;
    }

    const EsetFileSha1Ioc* FindEsetFileSha1Ioc(
        const std::wstring& sha1,
        bool processImage,
        bool driverImage)
    {
        const EsetFileSha1Ioc* ioc = nullptr;

        static const EsetFileSha1Ioc kIocs[] =
        {
            { L"8ae6bd18b129061f63642531f1b684cf0383c75d", L"Kasps.exe", L"GentleKiller", L"Kaspersky variant", true, false, false },
            { L"ba914fe77b177b45799403b16dd14765c510a074", L"eb.sys", L"GentleKiller", L"Kaspersky variant custom rootkit", false, true, false },
            { L"d605994fc72a2bb59b5cfb1624a1b9170eca73a2", L"FaceIT1.exe", L"GentleKiller", L"FACEIT Anti-Cheat variant", true, false, false },
            { L"b0b912a3fd1c05d72080848ec4c92880004021a1", L"nseckrnl.sys", L"GentleKiller", L"NSecsoft NSecKrnl driver", false, true, false },
            { L"5aa3124e5c4921e5edfc60133b5d71da21b07da3", L"Valorant2.exe", L"GentleKiller", L"Valorant variant", true, false, false },
            { L"7556ae58c215b8245a43f764f0676c7a8f0fdd1a", L"vgk.sys", L"GentleKiller", L"Tower of Fantasy AntiCheat driver", false, true, false },
            { L"331879f5eec8892bbd896f90bdbb1bad0bf63bd6", L"EASolo2Light.exe", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"f11aebccb9a86a7e2e653f90baec697f233c255f", L"EASOLO1clear.exe", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"ef9cd06683159397f099caa244e94e6eaad96eba", L"EAAntiCheatLight.exe", L"GentleKiller", L"Javelin variant", true, false, false },
            { L"711ef221526997039e804a18db9647c91680bbe2", L"stpm_old.sys", L"GentleKiller", L"Safetica Process Monitor driver", false, true, false },
            { L"68fec379f2ae76c3d2ce913f7be650cea1d06990", L"stpm_new.sys", L"GentleKiller", L"Safetica Process Monitor driver", false, true, false },
            { L"a11ee9cdc59e5caa59aefd27b30d104f3ad68e62", L"BitD1.exe", L"GentleKiller", L"WatchDog variant", true, false, false },
            { L"96f0dbf52aed0afd43e44500116b04b674f7358e", L"dmx.sys", L"GentleKiller", L"Zemana WatchDog driver", false, true, false },
            { L"2f86898528c6cab3540c486a9bfaa0c029b73950", L"MB2.exe", L"GentleKiller", L"Network Blocker variant", true, false, false },
            { L"9ad51ad97c01e97ab59214116740785e0f6320a8", L"360netmon_wfp.sys", L"GentleKiller", L"Qihoo 360 network monitor driver", false, true, false },
            { L"a19117175dbc9ba4d23b5dce8415e299a2e32192", L"Deletor.exe", L"GentleKiller", L"Cleaner variant", true, false, false },
            { L"12500f6c87ce62712a0ed6652c57468d15c14223", L"IMFForceDelete", L"GentleKiller", L"IObit IMF ForceDelete filter driver", false, true, false },
            { L"d29670e684e40ddc89b47010c37cbc96737035b6", L"Symantec.exe", L"GentleKiller", L"G11 variant", true, false, false },
            { L"56bee9df5833a637f5c54d5911df98b0812fe643", L"G11.sys", L"GentleKiller", L"PoisonX rootkit", false, true, false },
            { L"cf4d74df17a91b4a36a2911b22afec5d8fa93a01", L"Avast.exe", L"HexKiller", L"HexKiller with Gentlemen evasion layer", true, false, false },
            { L"ec296f9501ad71e430810cb5cdc38d954d4ba536", L"googleApiUtil64.sys", L"HexKiller", L"Baidu Antivirus BdApi driver", false, true, false },
            { L"7131b377e96016dc1911020c9f95b1b4d042d7b4", L"Sent.exe", L"ThrottleBlood", L"ThrottleBlood with Gentlemen evasion layer", true, false, false },
            { L"82ed942a52cdcf120a8919730e00ba37619661a3", L"ThrottleBlood.sys", L"ThrottleBlood", L"ThrottleStop driver", false, true, false },
            { L"f0537cbb773ae12100b36731e7c39f5a9d852b14", L"Sophos.exe", L"HavocKiller", L"HavocKiller with Gentlemen evasion layer", true, false, false },
            { L"1fa071303fb846308571e64727501fb98b1c2be6", L"havoc.sys", L"HavocKiller", L"Huawei vulnerable driver", false, true, false },
            { L"a5cf917ec4a7dfbdfa43621398604805d860c718", L"buildx641.exe", L"OxideHarvest", L"credential stealer", true, false, true },
            { L"d4b19141102015d436321e6f26976e98183cfd27", L"buildx64.exe", L"OxideHarvest", L"credential stealer", true, false, true }
        };

        do
        {
            std::wstring normalizedSha1 = HuntToLower(sha1);
            if (normalizedSha1.empty())
            {
                break;
            }

            for (const EsetFileSha1Ioc& item : kIocs)
            {
                if (normalizedSha1 != item.Sha1)
                {
                    continue;
                }
                if (processImage && !item.ProcessImage)
                {
                    continue;
                }
                if (driverImage && !item.DriverImage)
                {
                    continue;
                }

                ioc = &item;
                break;
            }
        } while (false);

        return ioc;
    }

    bool PathContainsGentlemenCollection(const std::wstring& path)
    {
        const std::wstring normalized = NormalizePathText(path);
        const std::wstring component = L"gentlemencollection";
        size_t offset = 0;
        while (offset < normalized.size())
        {
            const size_t match = normalized.find(component, offset);
            if (match == std::wstring::npos)
            {
                break;
            }

            const size_t after = match + component.size();
            bool fixturePrefixBoundary = false;
            if (match != 0 &&
                normalized[match - 1] == L'-')
            {
                const size_t slash =
                    normalized.rfind(
                        L'\\',
                        match - 1);
                const size_t componentStart =
                    slash == std::wstring::npos
                        ? 0
                        : slash + 1;
                const std::wstring prefix =
                    normalized.substr(
                        componentStart,
                        match - componentStart);
                constexpr wchar_t fixturePrefix[] =
                    L"knhunt-";
                constexpr size_t fixturePrefixLength =
                    _countof(fixturePrefix) - 1;
                fixturePrefixBoundary =
                    prefix.size() >
                        fixturePrefixLength + 1 &&
                    prefix.compare(
                        0,
                        fixturePrefixLength,
                        fixturePrefix) == 0 &&
                    prefix.back() == L'-' &&
                    std::all_of(
                        prefix.begin() +
                            fixturePrefixLength,
                        prefix.end() - 1,
                        [](wchar_t ch)
                        {
                            return iswdigit(ch) != 0;
                        });
            }
            const bool prefixBoundary =
                match == 0 ||
                normalized[match - 1] == L'\\' ||
                fixturePrefixBoundary ||
                normalized[match - 1] == L'"' ||
                iswspace(normalized[match - 1]) != 0;
            const bool suffixBoundary =
                after == normalized.size() ||
                normalized[after] == L'\\' ||
                normalized[after] == L'"' ||
                iswspace(normalized[after]) != 0;
            if (prefixBoundary && suffixBoundary)
            {
                return true;
            }
            offset = match + 1;
        }

        return false;
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
            std::wstring normalized = commandLine;
            std::replace(normalized.begin(), normalized.end(), L'\0', L' ');

            size_t begin = normalized.find_first_not_of(L" \t\r\n");
            if (begin == std::wstring::npos)
            {
                break;
            }

            // Some native processes expose an argument-only PEB command line.
            // It has no image token to compare with ImagePathName.
            if (normalized[begin] == L'/' || normalized[begin] == L'-')
            {
                break;
            }

            if (normalized[begin] == L'"')
            {
                size_t end = normalized.find(L'"', begin + 1);
                if (end != std::wstring::npos)
                {
                    image = normalized.substr(begin + 1, end - begin - 1);
                }
                else
                {
                    image = normalized.substr(begin + 1);
                }
                break;
            }

            size_t end = normalized.find_first_of(L" \t\r\n", begin);
            if (end == std::wstring::npos)
            {
                image = normalized.substr(begin);
            }
            else
            {
                image = normalized.substr(begin, end - begin);
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

                if (!inQuotes && (ch == L'\0' || std::iswspace(ch) != 0))
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
                        value[0] != L'-' &&
                        value[0] != L'/' &&
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

    std::wstring WindowsDirectory();
    std::wstring ProgramDataDirectory();
    std::wstring ProgramFilesDirectory();

    bool StableDriverServiceEnvironmentValue(
        const std::wstring& variable,
        std::wstring* replacement)
    {
        if (replacement == nullptr)
        {
            return false;
        }
        replacement->clear();

        const std::wstring lowered = HuntToLower(variable);
        if (lowered == L"systemroot" ||
            lowered == L"windir")
        {
            *replacement = WindowsDirectory();
        }
        else if (lowered == L"systemdrive")
        {
            const std::wstring windows = WindowsDirectory();
            if (windows.size() < 2 ||
                windows[1] != L':')
            {
                return false;
            }
            *replacement = windows.substr(0, 2);
        }
        else if (lowered == L"programdata" ||
                 lowered == L"allusersprofile")
        {
            *replacement = ProgramDataDirectory();
        }
        else if (lowered == L"programfiles" ||
                 lowered == L"programw6432")
        {
            *replacement = ProgramFilesDirectory();
        }
        else
        {
            return false;
        }

        return !replacement->empty();
    }

    std::wstring ExpandEnvironmentText(const std::wstring& value)
    {
        std::wstring expanded;

        do
        {
            if (value.empty())
            {
                break;
            }

            size_t cursor = 0;
            bool replaced = false;
            while (cursor < value.size())
            {
                const size_t open = value.find(L'%', cursor);
                if (open == std::wstring::npos)
                {
                    expanded.append(value, cursor, std::wstring::npos);
                    break;
                }
                expanded.append(value, cursor, open - cursor);

                const size_t close = value.find(L'%', open + 1);
                if (close == std::wstring::npos ||
                    close == open + 1)
                {
                    expanded = value;
                    replaced = false;
                    break;
                }

                std::wstring replacement;
                if (!StableDriverServiceEnvironmentValue(
                        value.substr(
                            open + 1,
                            close - open - 1),
                        &replacement))
                {
                    // QueryServiceConfigW describes a machine service.  Never
                    // resolve an arbitrary token from the invoking user's
                    // environment, since that can point hashing/correlation at
                    // a different file than SCM or the kernel would use.
                    expanded = value;
                    replaced = false;
                    break;
                }
                expanded += replacement;
                replaced = true;
                cursor = close + 1;
            }

            if (!replaced)
            {
                expanded = value;
            }
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

    std::wstring TrimServiceImagePathWhitespace(std::wstring value)
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
        } while (false);

        return value;
    }

    std::wstring TrimServiceImagePathToken(std::wstring value)
    {
        do
        {
            value = TrimServiceImagePathWhitespace(value);
            if (value.empty())
            {
                break;
            }

            if (!value.empty() && value.front() == L'"')
            {
                value.erase(value.begin());
            }
            if (!value.empty() && value.back() == L'"')
            {
                value.pop_back();
            }
        } while (false);

        return value;
    }

    bool IsServiceImagePathLeafPrefixBoundary(wchar_t value)
    {
        return value == L'\\' ||
            value == L'/' ||
            value == L'"' ||
            value == L' ' ||
            value == L'\t' ||
            value == L'\r' ||
            value == L'\n';
    }

    bool IsServiceImagePathLeafSuffixBoundary(wchar_t value)
    {
        return value == L'"' ||
            value == L' ' ||
            value == L'\t' ||
            value == L'\r' ||
            value == L'\n';
    }

    size_t FindDriverServiceSysExtensionEnd(const std::wstring& lowered)
    {
        size_t searchOffset = 0;
        while (searchOffset < lowered.size())
        {
            const size_t match = lowered.find(L".sys", searchOffset);
            if (match == std::wstring::npos)
            {
                break;
            }

            const size_t after = match + 4;
            if (after == lowered.size() ||
                IsServiceImagePathLeafSuffixBoundary(lowered[after]))
            {
                return after;
            }
            searchOffset = match + 1;
        }

        return std::wstring::npos;
    }

    std::wstring DriverServiceKnownExtensionlessImagePath(const std::wstring& value)
    {
        std::wstring path;

        do
        {
            std::wstring trimmed = TrimServiceImagePathWhitespace(value);
            if (trimmed.empty())
            {
                break;
            }

            std::wstring lowered = HuntToLower(trimmed);
            size_t profileCount = 0;
            const EdrKillerDriverProfile* profiles = EdrKillerDriverProfiles(&profileCount);
            for (size_t index = 0; index < profileCount; ++index)
            {
                const EdrKillerDriverProfile& profile = profiles[index];
                std::wstring leaf = HuntToLower(profile.ImageName != nullptr ? profile.ImageName : L"");
                if (leaf.empty() ||
                    leaf.find(L'.') != std::wstring::npos)
                {
                    continue;
                }

                size_t searchOffset = 0;
                while (searchOffset < lowered.size())
                {
                    size_t match = lowered.find(leaf, searchOffset);
                    if (match == std::wstring::npos)
                    {
                        break;
                    }

                    size_t after = match + leaf.size();
                    bool prefixOk = match == 0 ||
                        IsServiceImagePathLeafPrefixBoundary(lowered[match - 1]);
                    bool suffixOk = after >= lowered.size() ||
                        IsServiceImagePathLeafSuffixBoundary(lowered[after]);
                    if (prefixOk && suffixOk)
                    {
                        path = TrimServiceImagePathToken(trimmed.substr(0, after));
                        break;
                    }

                    searchOffset = match + 1;
                }

                if (!path.empty())
                {
                    break;
                }
            }
        } while (false);

        return path;
    }

    std::wstring DriverServiceBinaryImagePath(const std::wstring& binaryPath)
    {
        std::wstring path;

        do
        {
            std::wstring trimmed = TrimServiceImagePathWhitespace(binaryPath);
            if (trimmed.empty())
            {
                break;
            }

            if (trimmed.front() == L'"')
            {
                size_t endQuote = trimmed.find(L'"', 1);
                if (endQuote != std::wstring::npos)
                {
                    path = TrimServiceImagePathToken(trimmed.substr(1, endQuote - 1));
                    break;
                }

                trimmed.erase(trimmed.begin());
                trimmed = TrimServiceImagePathWhitespace(trimmed);
                if (trimmed.empty())
                {
                    break;
                }
            }

            trimmed = TrimServiceImagePathToken(trimmed);
            std::wstring lowered = HuntToLower(trimmed);
            size_t sysEnd = FindDriverServiceSysExtensionEnd(lowered);
            if (sysEnd != std::wstring::npos)
            {
                path = TrimServiceImagePathToken(trimmed.substr(0, sysEnd));
                break;
            }

            path = DriverServiceKnownExtensionlessImagePath(trimmed);
            if (!path.empty())
            {
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
            SetLastError(ERROR_SUCCESS);
            const BOOL sizingSucceeded =
                QueryServiceConfigW(service, nullptr, 0, &required);
            const DWORD error = GetLastError();
            if (sizingSucceeded ||
                required == 0 ||
                error != ERROR_INSUFFICIENT_BUFFER)
            {
                break;
            }

            std::vector<uint64_t> buffer(
                (static_cast<size_t>(required) + sizeof(uint64_t) - 1) /
                sizeof(uint64_t));
            QUERY_SERVICE_CONFIGW* config =
                reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
            const DWORD bufferBytes = static_cast<DWORD>(
                buffer.size() * sizeof(uint64_t));
            if (!QueryServiceConfigW(
                    service,
                    config,
                    bufferBytes,
                    &required))
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

    bool CollectDriverServices(
        std::vector<DriverServiceRecord>* records,
        std::vector<std::wstring>* warnings)
    {
        bool complete = false;
        uint32_t configFailureCount = 0;
        std::vector<std::wstring> configFailureSamples;
        do
        {
            if (records == nullptr)
            {
                break;
            }
            records->clear();

            SC_HANDLE scm = OpenSCManagerW(
                nullptr,
                nullptr,
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == nullptr)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"OpenSCManagerW failed for driver service enumeration: " +
                        std::to_wstring(GetLastError()));
                }
                break;
            }

            constexpr DWORD kServiceEnumerationBufferBytes =
                256u * 1024u;
            constexpr uint32_t kMaximumServiceEnumerationPages = 1024;
            std::vector<uint64_t> buffer(
                (kServiceEnumerationBufferBytes +
                 sizeof(uint64_t) - 1) /
                sizeof(uint64_t));
            DWORD resumeHandle = 0;
            std::set<std::wstring> seenServices;
            for (uint32_t page = 0;
                 page < kMaximumServiceEnumerationPages;
                 ++page)
            {
                const DWORD previousResumeHandle = resumeHandle;
                DWORD bytesNeeded = 0;
                DWORD serviceCount = 0;
                const BOOL enumerated = EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_DRIVER,
                    SERVICE_STATE_ALL,
                    reinterpret_cast<LPBYTE>(buffer.data()),
                    static_cast<DWORD>(
                        buffer.size() * sizeof(uint64_t)),
                    &bytesNeeded,
                    &serviceCount,
                    &resumeHandle,
                    nullptr);
                const DWORD enumerationError =
                    enumerated ? ERROR_SUCCESS : GetLastError();

                const size_t maximumRecords =
                    (buffer.size() * sizeof(uint64_t)) /
                    sizeof(ENUM_SERVICE_STATUS_PROCESSW);
                if (serviceCount > maximumRecords)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"EnumServicesStatusExW returned an invalid service count");
                    }
                    break;
                }

                ENUM_SERVICE_STATUS_PROCESSW* services =
                    reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(
                        buffer.data());
                for (DWORD index = 0; index < serviceCount; ++index)
                {
                    DriverServiceRecord record = {};
                    if (services[index].lpServiceName != nullptr)
                    {
                        record.ServiceName =
                            services[index].lpServiceName;
                    }
                    if (record.ServiceName.empty() ||
                        !seenServices.insert(
                            HuntToLower(record.ServiceName)).second)
                    {
                        continue;
                    }
                    if (services[index].lpDisplayName != nullptr)
                    {
                        record.DisplayName =
                            services[index].lpDisplayName;
                    }
                    record.ServiceType =
                        services[index].ServiceStatusProcess.dwServiceType;
                    record.CurrentState =
                        services[index].ServiceStatusProcess.dwCurrentState;
                    record.StateText =
                        DriverServiceStateText(record.CurrentState);
                    record.Running =
                        record.CurrentState == SERVICE_RUNNING;

                    SC_HANDLE service = OpenServiceW(
                        scm,
                        record.ServiceName.c_str(),
                        SERVICE_QUERY_CONFIG);
                    if (service != nullptr)
                    {
                        if (!QueryDriverServiceConfig(service, &record))
                        {
                            ++configFailureCount;
                            if (configFailureSamples.size() < 5)
                            {
                                configFailureSamples.push_back(
                                    record.ServiceName);
                            }
                        }
                        CloseServiceHandle(service);
                    }
                    else
                    {
                        ++configFailureCount;
                        if (configFailureSamples.size() < 5)
                        {
                            configFailureSamples.push_back(
                                record.ServiceName);
                        }
                    }

                    if (record.BinaryLeaf.empty())
                    {
                        record.BinaryLeaf =
                            LeafName(record.ServiceName);
                    }
                    records->push_back(std::move(record));
                }

                if (enumerated)
                {
                    complete = true;
                    break;
                }
                if (enumerationError != ERROR_MORE_DATA)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"EnumServicesStatusExW failed: " +
                            std::to_wstring(enumerationError));
                    }
                    break;
                }
                if (serviceCount == 0 ||
                    resumeHandle == 0 ||
                    resumeHandle == previousResumeHandle)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"EnumServicesStatusExW made no progress while more data remained");
                    }
                    break;
                }
            }

            if (!complete &&
                warnings != nullptr &&
                resumeHandle != 0)
            {
                warnings->push_back(
                    L"driver service enumeration did not reach the final page");
            }
            if (configFailureCount != 0)
            {
                complete = false;
                if (warnings != nullptr)
                {
                    std::wstring warning =
                        L"driver service configuration unavailable for " +
                        std::to_wstring(configFailureCount) +
                        L" service(s)";
                    if (!configFailureSamples.empty())
                    {
                        warning += L": ";
                        for (size_t index = 0;
                             index < configFailureSamples.size();
                             ++index)
                        {
                            if (index != 0)
                            {
                                warning += L", ";
                            }
                            warning += configFailureSamples[index];
                        }
                    }
                    warnings->push_back(warning);
                }
            }
            CloseServiceHandle(scm);
        } while (false);

        return complete;
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

    bool HasExactProcessIdentity(
        const SnapshotProcessRecord& process)
    {
        return process.ProcessId != 0 &&
            process.Eprocess != 0 &&
            process.HasCreateTime &&
            process.CreateTime != 0;
    }

    bool HasVerifiedUserAddressSpace(const SnapshotProcessRecord& process)
    {
        return process.ProcessId > 4 &&
            process.HasPeb &&
            process.Peb != 0 &&
            TargetUserDtb(process) != 0;
    }

    bool IsTerminatingProcessSnapshot(const SnapshotProcessRecord& process)
    {
        return (process.HasExitTime && process.ExitTime != 0) ||
            (process.HasActiveThreads && process.ActiveThreads == 0);
    }

    bool IsUserAddress(uint64_t value)
    {
        // LA57 user half (2^56-1). Matches process-triage / e* user VA policy.
        return value != 0 && value <= kUserAddressMax;
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

    bool ContainsWideValue(const std::vector<std::wstring>& values, const std::wstring& value)
    {
        return std::find(values.begin(), values.end(), value) != values.end();
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
                if (field.Length == 0 ||
                    field.Length > 64 ||
                    field.BitPosition >= 64 ||
                    field.Length > 64 - field.BitPosition)
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

    std::wstring ProgramDataDirectory()
    {
        PWSTR knownPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(
                FOLDERID_ProgramData,
                KF_FLAG_DEFAULT,
                nullptr,
                &knownPath)) &&
            knownPath != nullptr)
        {
            std::wstring result = knownPath;
            CoTaskMemFree(knownPath);
            return result;
        }
        if (knownPath != nullptr)
        {
            CoTaskMemFree(knownPath);
        }

        std::wstring windows = WindowsDirectory();
        if (windows.size() >= 2 && windows[1] == L':')
        {
            return windows.substr(0, 2) + L"\\ProgramData";
        }
        return L"C:\\ProgramData";
    }

    std::wstring ProgramFilesDirectory()
    {
        PWSTR knownPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(
                FOLDERID_ProgramFiles,
                KF_FLAG_DEFAULT,
                nullptr,
                &knownPath)) &&
            knownPath != nullptr)
        {
            std::wstring result = knownPath;
            CoTaskMemFree(knownPath);
            return result;
        }
        if (knownPath != nullptr)
        {
            CoTaskMemFree(knownPath);
        }

        // Do not let a caller-controlled environment variable redefine a
        // trusted provenance root.  The known-folder API is authoritative;
        // its conservative fallback is anchored to the Windows volume.
        const std::wstring windows = WindowsDirectory();
        if (windows.size() >= 2 && windows[1] == L':')
        {
            return windows.substr(0, 2) + L"\\Program Files";
        }
        return L"C:\\Program Files";
    }

    std::wstring ProgramFilesX86Directory()
    {
        PWSTR knownPath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(
                FOLDERID_ProgramFilesX86,
                KF_FLAG_DEFAULT,
                nullptr,
                &knownPath)) &&
            knownPath != nullptr)
        {
            std::wstring result = knownPath;
            CoTaskMemFree(knownPath);
            return result;
        }
        if (knownPath != nullptr)
        {
            CoTaskMemFree(knownPath);
        }

        const std::wstring windows =
            WindowsDirectory();
        if (windows.size() >= 2 &&
            windows[1] == L':')
        {
            return windows.substr(0, 2) +
                L"\\Program Files (x86)";
        }
        return L"C:\\Program Files (x86)";
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

    std::wstring ExpectedSystem32SubdirPath(const std::wstring& subdir, const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + L"System32\\" + EnsureTrailingSlash(subdir) + imageName;
    }

    std::wstring ExpectedSysWow64SubdirPath(const std::wstring& subdir, const std::wstring& imageName)
    {
        return EnsureTrailingSlash(WindowsDirectory()) + L"SysWOW64\\" + EnsureTrailingSlash(subdir) + imageName;
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

    std::wstring OpenPathForResolvedBacking(
        const std::wstring& backingPath,
        const std::wstring& driveHintPath)
    {
        std::wstring openPath =
            DosPathFromDevicePath(
                Win32FilePathFromMaybeNtPath(
                    backingPath));
        if (!IsRootRelativePath(openPath) ||
            driveHintPath.empty())
        {
            return openPath;
        }

        const std::wstring hintPath =
            DosPathFromDevicePath(
                Win32FilePathFromMaybeNtPath(
                    driveHintPath));
        if (!IsDriveQualifiedPath(hintPath) ||
            !SameCanonicalPath(
                openPath,
                hintPath))
        {
            return openPath;
        }

        // FILE_OBJECT.FileName commonly omits its volume. Use a loader/API
        // path only as the drive selector after the complete root-relative
        // suffix agrees; this avoids accidentally opening the current drive.
        return hintPath;
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

    void AddSpecialBuiltinExpectedPaths(const std::wstring& leaf, std::vector<std::wstring>* expected)
    {
        do
        {
            if (expected == nullptr)
            {
                break;
            }

            if (leaf == L"wmiprvse.exe")
            {
                expected->push_back(ExpectedSystem32SubdirPath(L"wbem", leaf));
                expected->push_back(ExpectedSysWow64SubdirPath(L"wbem", leaf));
            }
        } while (false);
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
            AddSpecialBuiltinExpectedPaths(leaf, &expected);

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

    bool ReadHuntProcessMemory(
        DeviceClient& device,
        const SnapshotProcessRecord& process,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        if (HasExactProcessIdentity(process))
        {
            // Never fall back to a captured DTB after an exact-identity read
            // fails: the process may have exited or the PID may have been
            // reused, in which case the old address space is stale evidence.
            return device.ReadProcessVirtual(
                process.ProcessId,
                process.Eprocess,
                process.CreateTime,
                address,
                length,
                bytes,
                error);
        }

        return ReadProcessMemoryByDtb(
            device,
            TargetUserDtb(process),
            address,
            length,
            bytes,
            error);
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
            if (!ReadHuntProcessMemory(
                    device,
                    process,
                    address,
                    sizeof(uint64_t),
                    &bytes,
                    &ignored))
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
            if (!ReadHuntProcessMemory(
                    device,
                    process,
                    address,
                    sizeof(uint32_t),
                    &bytes,
                    &ignored))
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
            if (!ReadHuntProcessMemory(
                    device,
                    process,
                    unicodeStringAddress,
                    16,
                    &bytes,
                    &ignored))
            {
                break;
            }

            uint16_t length = static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
            uint16_t maximumLength = static_cast<uint16_t>(
                bytes[2] |
                (static_cast<uint16_t>(bytes[3]) << 8));
            uint64_t buffer = 0;
            for (size_t index = 0; index < sizeof(uint64_t); ++index)
            {
                buffer |= static_cast<uint64_t>(bytes[8 + index]) << (index * 8);
            }

            if ((length % sizeof(wchar_t)) != 0 ||
                (maximumLength % sizeof(wchar_t)) != 0 ||
                maximumLength < length)
            {
                break;
            }
            if (length == 0)
            {
                ok = true;
                break;
            }
            if (buffer == 0 ||
                !IsUserAddress(buffer) ||
                static_cast<uint64_t>(length - 1) >
                    kUserAddressMax - buffer)
            {
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
            if (!ReadHuntProcessMemory(
                    device,
                    process,
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
            layout->HasFileObjectSectionObjectPointer =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SectionObjectPointer", &layout->FileObjectSectionObjectPointer);
            layout->HasFileObjectDeletePending =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"DeletePending", &layout->FileObjectDeletePending);
            layout->HasFileObjectWriteAccess =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"WriteAccess", &layout->FileObjectWriteAccess);
            layout->HasFileObjectDeleteAccess =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"DeleteAccess", &layout->FileObjectDeleteAccess);
            layout->HasFileObjectSharedWrite =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SharedWrite", &layout->FileObjectSharedWrite);
            layout->HasFileObjectSharedDelete =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SharedDelete", &layout->FileObjectSharedDelete);
            layout->HasFileObjectFlags =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"Flags", &layout->FileObjectFlags);
            layout->HasSectionObjectPointersImageSectionObject =
                FindFieldRecursive(symbols, {L"nt!_SECTION_OBJECT_POINTERS", L"_SECTION_OBJECT_POINTERS"}, L"ImageSectionObject", &layout->SectionObjectPointersImageSectionObject);
            layout->HasSectionObjectPointersDataSectionObject =
                FindFieldRecursive(symbols, {L"nt!_SECTION_OBJECT_POINTERS", L"_SECTION_OBJECT_POINTERS"}, L"DataSectionObject", &layout->SectionObjectPointersDataSectionObject);

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

    bool ResolveMainSectionObjectLayout(SymbolEngine& symbols, MainSectionObjectLayout* layout)
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
                ok = layout->HasEprocessSectionObject &&
                    layout->HasSegmentControlArea &&
                    (layout->HasSectionObjectSegment ||
                     layout->HasControlAreaSegment) &&
                    layout->HasControlAreaFilePointer &&
                    layout->HasFileObjectFileName;
                break;
            }

            *layout = MainSectionObjectLayout{};
            layout->Resolved = true;
            layout->HasEprocessSectionObject =
                FindFieldRecursive(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"SectionObject", &layout->EprocessSectionObject);
            layout->HasSectionObjectSegment =
                FindFieldRecursive(symbols, {L"nt!_SECTION_OBJECT", L"_SECTION_OBJECT", L"nt!_SECTION", L"_SECTION"}, L"Segment", &layout->SectionObjectSegment);
            layout->HasSegmentControlArea =
                FindFieldRecursive(symbols, {L"nt!_SEGMENT", L"_SEGMENT"}, L"ControlArea", &layout->SegmentControlArea);
            layout->HasControlAreaSegment =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"Segment", &layout->ControlAreaSegment);
            layout->HasControlAreaFilePointer =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"FilePointer", &layout->ControlAreaFilePointer);
            layout->HasControlAreaImageFlag =
                FindFieldRecursive(symbols, {L"nt!_CONTROL_AREA", L"_CONTROL_AREA"}, L"Image", &layout->ControlAreaImageFlag);
            layout->HasFileObjectFileName =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"FileName", &layout->FileObjectFileName);
            layout->HasFileObjectSectionObjectPointer =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SectionObjectPointer", &layout->FileObjectSectionObjectPointer);
            layout->HasFileObjectDeletePending =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"DeletePending", &layout->FileObjectDeletePending);
            layout->HasFileObjectWriteAccess =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"WriteAccess", &layout->FileObjectWriteAccess);
            layout->HasFileObjectDeleteAccess =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"DeleteAccess", &layout->FileObjectDeleteAccess);
            layout->HasFileObjectSharedWrite =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SharedWrite", &layout->FileObjectSharedWrite);
            layout->HasFileObjectSharedDelete =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"SharedDelete", &layout->FileObjectSharedDelete);
            layout->HasFileObjectFlags =
                FindFieldRecursive(symbols, {L"nt!_FILE_OBJECT", L"_FILE_OBJECT"}, L"Flags", &layout->FileObjectFlags);
            layout->HasSectionObjectPointersImageSectionObject =
                FindFieldRecursive(symbols, {L"nt!_SECTION_OBJECT_POINTERS", L"_SECTION_OBJECT_POINTERS"}, L"ImageSectionObject", &layout->SectionObjectPointersImageSectionObject);
            layout->HasSectionObjectPointersDataSectionObject =
                FindFieldRecursive(symbols, {L"nt!_SECTION_OBJECT_POINTERS", L"_SECTION_OBJECT_POINTERS"}, L"DataSectionObject", &layout->SectionObjectPointersDataSectionObject);

            if (!layout->HasEprocessSectionObject)
            {
                layout->Warnings.push_back(L"_EPROCESS.SectionObject field unavailable");
            }
            if (!layout->HasSectionObjectSegment &&
                !layout->HasControlAreaSegment)
            {
                layout->Warnings.push_back(
                    L"neither _SECTION_OBJECT.Segment nor "
                    L"_CONTROL_AREA.Segment is available");
            }
            if (!layout->HasSegmentControlArea)
            {
                layout->Warnings.push_back(L"_SEGMENT.ControlArea field unavailable");
            }
            if (!layout->HasControlAreaFilePointer)
            {
                layout->Warnings.push_back(L"_CONTROL_AREA.FilePointer field unavailable");
            }
            if (!layout->HasFileObjectFileName)
            {
                layout->Warnings.push_back(L"_FILE_OBJECT.FileName field unavailable");
            }

            ok = layout->HasEprocessSectionObject &&
                layout->HasSegmentControlArea &&
                (layout->HasSectionObjectSegment ||
                 layout->HasControlAreaSegment) &&
                layout->HasControlAreaFilePointer &&
                layout->HasFileObjectFileName;
        } while (false);

        return ok;
    }

    void ReadOptionalKernelBooleanField(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        bool hasField,
        bool* hasValue,
        bool* value)
    {
        do
        {
            if (hasValue == nullptr || value == nullptr)
            {
                break;
            }

            *hasValue = false;
            *value = false;
            if (!hasField || base == 0)
            {
                break;
            }

            uint64_t raw = 0;
            std::wstring ignored;
            if (!ReadFieldInteger(device, base, field, sizeof(uint8_t), &raw, &ignored))
            {
                break;
            }

            *hasValue = true;
            *value = raw != 0;
        } while (false);
    }

    void ReadOptionalKernelIntegerField(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        bool hasField,
        size_t fallbackWidth,
        bool* hasValue,
        uint64_t* value)
    {
        do
        {
            if (hasValue == nullptr || value == nullptr)
            {
                break;
            }

            *hasValue = false;
            *value = 0;
            if (!hasField || base == 0)
            {
                break;
            }

            std::wstring ignored;
            if (!ReadFieldInteger(device, base, field, fallbackWidth, value, &ignored))
            {
                break;
            }

            *hasValue = true;
        } while (false);
    }

    bool ResolveControlAreaBackingDetails(
        DeviceClient& device,
        uint64_t controlArea,
        const TypeFieldInfo& controlAreaFilePointer,
        const TypeFieldInfo& fileObjectFileName,
        const TypeFieldInfo* fileObjectSectionObjectPointer,
        bool hasFileObjectSectionObjectPointer,
        const TypeFieldInfo* fileObjectDeletePending,
        bool hasFileObjectDeletePending,
        const TypeFieldInfo* fileObjectWriteAccess,
        bool hasFileObjectWriteAccess,
        const TypeFieldInfo* fileObjectDeleteAccess,
        bool hasFileObjectDeleteAccess,
        const TypeFieldInfo* fileObjectSharedWrite,
        bool hasFileObjectSharedWrite,
        const TypeFieldInfo* fileObjectSharedDelete,
        bool hasFileObjectSharedDelete,
        const TypeFieldInfo* fileObjectFlags,
        bool hasFileObjectFlags,
        const TypeFieldInfo* sectionObjectPointersImageSectionObject,
        bool hasSectionObjectPointersImageSectionObject,
        const TypeFieldInfo* sectionObjectPointersDataSectionObject,
        bool hasSectionObjectPointersDataSectionObject,
        ControlAreaBackingDetails* details,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (details == nullptr)
            {
                break;
            }

            *details = ControlAreaBackingDetails{};
            details->ControlArea = controlArea;
            details->State = L"unavailable";

            uint64_t fileFastRef = 0;
            if (!ReadFieldInteger(device, controlArea, controlAreaFilePointer, sizeof(uint64_t), &fileFastRef, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read control area file pointer";
                }
                break;
            }

            details->FileFastRef = fileFastRef;
            uint64_t fileObject = fileFastRef & ~0xfull;
            details->FileObject = fileObject;
            if (fileObject == 0)
            {
                details->State = L"unbacked";
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

            uint64_t sectionObjectPointers = 0;
            bool hasSectionObjectPointers = false;
            if (fileObjectSectionObjectPointer != nullptr)
            {
                ReadOptionalKernelIntegerField(
                    device,
                    fileObject,
                    *fileObjectSectionObjectPointer,
                    hasFileObjectSectionObjectPointer,
                    sizeof(uint64_t),
                    &hasSectionObjectPointers,
                    &sectionObjectPointers);
            }

            details->HasSectionObjectPointers = hasSectionObjectPointers;
            details->SectionObjectPointers = sectionObjectPointers;
            if (hasSectionObjectPointers &&
                sectionObjectPointers != 0 &&
                IsKernelAddress(sectionObjectPointers))
            {
                uint64_t imageSectionObject = 0;
                bool hasImageSectionObject = false;
                if (sectionObjectPointersImageSectionObject != nullptr)
                {
                    ReadOptionalKernelIntegerField(
                        device,
                        sectionObjectPointers,
                        *sectionObjectPointersImageSectionObject,
                        hasSectionObjectPointersImageSectionObject,
                        sizeof(uint64_t),
                        &hasImageSectionObject,
                        &imageSectionObject);
                }

                uint64_t dataSectionObject = 0;
                bool hasDataSectionObject = false;
                if (sectionObjectPointersDataSectionObject != nullptr)
                {
                    ReadOptionalKernelIntegerField(
                        device,
                        sectionObjectPointers,
                        *sectionObjectPointersDataSectionObject,
                        hasSectionObjectPointersDataSectionObject,
                        sizeof(uint64_t),
                        &hasDataSectionObject,
                        &dataSectionObject);
                }

                details->HasImageSectionObject = hasImageSectionObject;
                details->ImageSectionObject = imageSectionObject;
                details->HasDataSectionObject = hasDataSectionObject;
                details->DataSectionObject = dataSectionObject;
            }

            if (fileObjectDeletePending != nullptr)
            {
                ReadOptionalKernelBooleanField(
                    device,
                    fileObject,
                    *fileObjectDeletePending,
                    hasFileObjectDeletePending,
                    &details->HasDeletePending,
                    &details->DeletePending);
            }
            if (fileObjectWriteAccess != nullptr)
            {
                ReadOptionalKernelBooleanField(
                    device,
                    fileObject,
                    *fileObjectWriteAccess,
                    hasFileObjectWriteAccess,
                    &details->HasWriteAccess,
                    &details->WriteAccess);
            }
            if (fileObjectDeleteAccess != nullptr)
            {
                ReadOptionalKernelBooleanField(
                    device,
                    fileObject,
                    *fileObjectDeleteAccess,
                    hasFileObjectDeleteAccess,
                    &details->HasDeleteAccess,
                    &details->DeleteAccess);
            }
            if (fileObjectSharedWrite != nullptr)
            {
                ReadOptionalKernelBooleanField(
                    device,
                    fileObject,
                    *fileObjectSharedWrite,
                    hasFileObjectSharedWrite,
                    &details->HasSharedWrite,
                    &details->SharedWrite);
            }
            if (fileObjectSharedDelete != nullptr)
            {
                ReadOptionalKernelBooleanField(
                    device,
                    fileObject,
                    *fileObjectSharedDelete,
                    hasFileObjectSharedDelete,
                    &details->HasSharedDelete,
                    &details->SharedDelete);
            }
            if (fileObjectFlags != nullptr)
            {
                uint64_t fileFlags = 0;
                bool hasFileFlags = false;
                ReadOptionalKernelIntegerField(
                    device,
                    fileObject,
                    *fileObjectFlags,
                    hasFileObjectFlags,
                    sizeof(uint32_t),
                    &hasFileFlags,
                    &fileFlags);
                details->HasFileFlags = hasFileFlags;
                details->FileFlags = static_cast<uint32_t>(fileFlags);
            }

            uint64_t fileNameAddress = 0;
            if (!TryAdd(fileObject, fileObjectFileName.Offset, &fileNameAddress))
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

            details->Path = backingPath;
            details->State = backingPath.empty() ? L"empty_file_name" : L"resolved";
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveControlAreaBackingPath(
        DeviceClient& device,
        uint64_t controlArea,
        const TypeFieldInfo& controlAreaFilePointer,
        const TypeFieldInfo& fileObjectFileName,
        std::wstring* path,
        std::wstring* state,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (path == nullptr || state == nullptr)
            {
                break;
            }

            ControlAreaBackingDetails details;
            ok = ResolveControlAreaBackingDetails(
                device,
                controlArea,
                controlAreaFilePointer,
                fileObjectFileName,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                nullptr,
                false,
                &details,
                warning);
            if (ok)
            {
                *path = details.Path;
                *state = details.State;
            }
        } while (false);

        return ok;
    }

    bool ValidateMainSectionLinkCandidate(
        DeviceClient& device,
        const MainSectionObjectLayout& layout,
        uint64_t candidate,
        bool candidateIsControlArea,
        uint64_t* segment,
        uint64_t* controlArea)
    {
        if (segment == nullptr ||
            controlArea == nullptr ||
            !layout.HasSegmentControlArea ||
            !layout.HasControlAreaSegment ||
            !IsKernelAddress(candidate) ||
            (candidate & 0x7ull) != 0)
        {
            return false;
        }

        uint64_t localSegment = 0;
        uint64_t localControlArea = 0;
        std::wstring ignored;
        if (candidateIsControlArea)
        {
            localControlArea = candidate;
            if (!ReadFieldInteger(
                    device,
                    localControlArea,
                    layout.ControlAreaSegment,
                    sizeof(uint64_t),
                    &localSegment,
                    &ignored))
            {
                return false;
            }
        }
        else
        {
            localSegment = candidate;
            if (!ReadFieldInteger(
                    device,
                    localSegment,
                    layout.SegmentControlArea,
                    sizeof(uint64_t),
                    &localControlArea,
                    &ignored))
            {
                return false;
            }
        }
        if (!IsKernelAddress(localSegment) ||
            !IsKernelAddress(localControlArea) ||
            (localSegment & 0x7ull) != 0 ||
            (localControlArea & 0x7ull) != 0)
        {
            return false;
        }

        uint64_t controlAreaFromSegment = 0;
        uint64_t segmentFromControlArea = 0;
        if (!ReadFieldInteger(
                device,
                localSegment,
                layout.SegmentControlArea,
                sizeof(uint64_t),
                &controlAreaFromSegment,
                &ignored) ||
            !ReadFieldInteger(
                device,
                localControlArea,
                layout.ControlAreaSegment,
                sizeof(uint64_t),
                &segmentFromControlArea,
                &ignored) ||
            controlAreaFromSegment != localControlArea ||
            segmentFromControlArea != localSegment)
        {
            return false;
        }

        std::wstring candidatePath;
        std::wstring candidateState;
        if (!ResolveControlAreaBackingPath(
                device,
                localControlArea,
                layout.ControlAreaFilePointer,
                layout.FileObjectFileName,
                &candidatePath,
                &candidateState,
                &ignored) ||
            candidateState != L"resolved" ||
            candidatePath.empty())
        {
            return false;
        }

        *segment = localSegment;
        *controlArea = localControlArea;
        return true;
    }

    bool DiscoverMainSectionLink(
        DeviceClient& device,
        uint64_t sectionObject,
        const MainSectionObjectLayout& layout,
        uint64_t* segment,
        uint64_t* controlArea,
        std::wstring* warning)
    {
        if (segment == nullptr ||
            controlArea == nullptr ||
            !IsKernelAddress(sectionObject))
        {
            return false;
        }
        *segment = 0;
        *controlArea = 0;

        constexpr uint32_t kSectionLinkScanBytes =
            0x40;
        bool found = false;
        for (uint32_t offset = 0;
             offset < kSectionLinkScanBytes;
             offset += sizeof(uint64_t))
        {
            uint64_t address = 0;
            if (!TryAdd(
                    sectionObject,
                    offset,
                    &address))
            {
                break;
            }

            uint64_t candidate = 0;
            std::wstring ignored;
            if (!ReadKernelPointer(
                    device,
                    address,
                    &candidate,
                    &ignored))
            {
                continue;
            }

            for (const bool candidateIsControlArea :
                 {true, false})
            {
                uint64_t candidateSegment = 0;
                uint64_t candidateControlArea = 0;
                if (!ValidateMainSectionLinkCandidate(
                        device,
                        layout,
                        candidate,
                        candidateIsControlArea,
                        &candidateSegment,
                        &candidateControlArea))
                {
                    continue;
                }
                if (found &&
                    (*segment != candidateSegment ||
                     *controlArea !=
                         candidateControlArea))
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"section object link discovery is ambiguous";
                    }
                    return false;
                }

                *segment = candidateSegment;
                *controlArea =
                    candidateControlArea;
                found = true;
            }
        }

        if (!found && warning != nullptr)
        {
            *warning =
                L"section object has no validated "
                L"segment/control-area backlink in its "
                L"bounded link region";
        }
        return found;
    }

    bool ResolveVadSectionBackingPath(
        DeviceClient& device,
        SymbolEngine& symbols,
        const ProcessVadRecord& vad,
        std::wstring* path,
        std::wstring* state,
        std::wstring* warning,
        bool* imageSection = nullptr,
        uint64_t* controlAreaOut = nullptr,
        ControlAreaBackingDetails* details = nullptr)
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
            if (warning != nullptr)
            {
                warning->clear();
            }
            if (imageSection != nullptr)
            {
                *imageSection = false;
            }
            if (controlAreaOut != nullptr)
            {
                *controlAreaOut = 0;
            }
            if (details != nullptr)
            {
                *details = ControlAreaBackingDetails{};
            }

            if (!vad.HasSubsection || vad.Subsection == 0)
            {
                *state = L"unbacked";
                if (details != nullptr)
                {
                    details->State = L"unbacked";
                }
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
            if (controlAreaOut != nullptr)
            {
                *controlAreaOut = controlArea;
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

            if (details != nullptr)
            {
                ok = ResolveControlAreaBackingDetails(
                    device,
                    controlArea,
                    layout.ControlAreaFilePointer,
                    layout.FileObjectFileName,
                    &layout.FileObjectSectionObjectPointer,
                    layout.HasFileObjectSectionObjectPointer,
                    &layout.FileObjectDeletePending,
                    layout.HasFileObjectDeletePending,
                    &layout.FileObjectWriteAccess,
                    layout.HasFileObjectWriteAccess,
                    &layout.FileObjectDeleteAccess,
                    layout.HasFileObjectDeleteAccess,
                    &layout.FileObjectSharedWrite,
                    layout.HasFileObjectSharedWrite,
                    &layout.FileObjectSharedDelete,
                    layout.HasFileObjectSharedDelete,
                    &layout.FileObjectFlags,
                    layout.HasFileObjectFlags,
                    &layout.SectionObjectPointersImageSectionObject,
                    layout.HasSectionObjectPointersImageSectionObject,
                    &layout.SectionObjectPointersDataSectionObject,
                    layout.HasSectionObjectPointersDataSectionObject,
                    details,
                    warning);
                if (ok)
                {
                    *path = details->Path;
                    *state = details->State;
                }
            }
            else
            {
                ok = ResolveControlAreaBackingPath(
                    device,
                    controlArea,
                    layout.ControlAreaFilePointer,
                    layout.FileObjectFileName,
                    path,
                    state,
                    warning);
            }
        } while (false);

        return ok;
    }

    bool ResolveEprocessMainSectionBackingPath(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t eprocess,
        std::wstring* path,
        std::wstring* state,
        uint64_t* sectionObject,
        uint64_t* segment,
        uint64_t* controlArea,
        std::wstring* warning,
        bool* imageSection = nullptr,
        ControlAreaBackingDetails* details = nullptr)
    {
        bool ok = false;
        static MainSectionObjectLayout layout;

        do
        {
            if (path == nullptr || state == nullptr)
            {
                break;
            }

            path->clear();
            *state = L"unavailable";
            if (warning != nullptr)
            {
                warning->clear();
            }
            if (sectionObject != nullptr)
            {
                *sectionObject = 0;
            }
            if (segment != nullptr)
            {
                *segment = 0;
            }
            if (controlArea != nullptr)
            {
                *controlArea = 0;
            }
            if (imageSection != nullptr)
            {
                *imageSection = false;
            }
            if (details != nullptr)
            {
                *details = ControlAreaBackingDetails{};
            }

            if (eprocess == 0 || !IsKernelAddress(eprocess))
            {
                if (warning != nullptr)
                {
                    *warning = L"EPROCESS address is unavailable";
                }
                break;
            }

            if (!ResolveMainSectionObjectLayout(symbols, &layout))
            {
                if (warning != nullptr)
                {
                    *warning = L"main section object resolver unavailable: " + JoinWideValues(layout.Warnings, L"; ");
                }
                break;
            }

            uint64_t localSectionObject = 0;
            if (!ReadFieldInteger(device, eprocess, layout.EprocessSectionObject, sizeof(uint64_t), &localSectionObject, warning))
            {
                if (warning != nullptr && warning->empty())
                {
                    *warning = L"failed to read EPROCESS section object";
                }
                break;
            }
            if (sectionObject != nullptr)
            {
                *sectionObject = localSectionObject;
            }
            if (localSectionObject == 0)
            {
                *state = L"no_section_object";
                if (details != nullptr)
                {
                    details->State = L"no_section_object";
                }
                ok = true;
                break;
            }
            if (!IsKernelAddress(localSectionObject))
            {
                if (warning != nullptr)
                {
                    *warning = L"EPROCESS section object is not a kernel address";
                }
                break;
            }

            uint64_t localSegment = 0;
            uint64_t localControlArea = 0;
            if (layout.HasSectionObjectSegment)
            {
                if (!ReadFieldInteger(
                        device,
                        localSectionObject,
                        layout.SectionObjectSegment,
                        sizeof(uint64_t),
                        &localSegment,
                        warning))
                {
                    if (warning != nullptr &&
                        warning->empty())
                    {
                        *warning =
                            L"failed to read section object segment";
                    }
                    break;
                }
                if (localSegment == 0)
                {
                    *state = L"no_segment";
                    if (details != nullptr)
                    {
                        details->State = L"no_segment";
                    }
                    ok = true;
                    break;
                }
                if (!IsKernelAddress(localSegment))
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"section object segment is not a kernel address";
                    }
                    break;
                }

                if (!ReadFieldInteger(
                        device,
                        localSegment,
                        layout.SegmentControlArea,
                        sizeof(uint64_t),
                        &localControlArea,
                        warning))
                {
                    if (warning != nullptr &&
                        warning->empty())
                    {
                        *warning =
                            L"failed to read segment control area";
                    }
                    break;
                }
                if (localControlArea == 0)
                {
                    *state = L"no_control_area";
                    if (details != nullptr)
                    {
                        details->State =
                            L"no_control_area";
                    }
                    ok = true;
                    break;
                }
            }
            else if (!DiscoverMainSectionLink(
                         device,
                         localSectionObject,
                         layout,
                         &localSegment,
                         &localControlArea,
                         warning))
            {
                break;
            }

            if (!IsKernelAddress(localSegment) ||
                !IsKernelAddress(localControlArea))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"main section link contains a non-kernel address";
                }
                break;
            }
            if (segment != nullptr)
            {
                *segment = localSegment;
            }
            if (controlArea != nullptr)
            {
                *controlArea = localControlArea;
            }

            if (imageSection != nullptr && layout.HasControlAreaImageFlag)
            {
                uint64_t imageFlag = 0;
                std::wstring ignored;
                if (ReadFieldInteger(device, localControlArea, layout.ControlAreaImageFlag, sizeof(uint32_t), &imageFlag, &ignored))
                {
                    *imageSection = imageFlag != 0;
                }
            }

            if (details != nullptr)
            {
                ok = ResolveControlAreaBackingDetails(
                    device,
                    localControlArea,
                    layout.ControlAreaFilePointer,
                    layout.FileObjectFileName,
                    &layout.FileObjectSectionObjectPointer,
                    layout.HasFileObjectSectionObjectPointer,
                    &layout.FileObjectDeletePending,
                    layout.HasFileObjectDeletePending,
                    &layout.FileObjectWriteAccess,
                    layout.HasFileObjectWriteAccess,
                    &layout.FileObjectDeleteAccess,
                    layout.HasFileObjectDeleteAccess,
                    &layout.FileObjectSharedWrite,
                    layout.HasFileObjectSharedWrite,
                    &layout.FileObjectSharedDelete,
                    layout.HasFileObjectSharedDelete,
                    &layout.FileObjectFlags,
                    layout.HasFileObjectFlags,
                    &layout.SectionObjectPointersImageSectionObject,
                    layout.HasSectionObjectPointersImageSectionObject,
                    &layout.SectionObjectPointersDataSectionObject,
                    layout.HasSectionObjectPointersDataSectionObject,
                    details,
                    warning);
                if (ok)
                {
                    *path = details->Path;
                    *state = details->State;
                }
            }
            else
            {
                ok = ResolveControlAreaBackingPath(
                    device,
                    localControlArea,
                    layout.ControlAreaFilePointer,
                    layout.FileObjectFileName,
                    path,
                    state,
                    warning);
            }
        } while (false);

        return ok;
    }

    void AddControlAreaBackingEvidence(
        const std::wstring& prefix,
        const ControlAreaBackingDetails& details,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (evidence == nullptr || prefix.empty())
            {
                break;
            }

            (*evidence)[prefix + L"_state"] = details.State;
            (*evidence)[prefix + L"_path"] = details.Path;
            (*evidence)[prefix + L"_control_area"] = HuntHex(details.ControlArea, 16);
            (*evidence)[prefix + L"_file_object"] = HuntHex(details.FileObject, 16);
            (*evidence)[prefix + L"_file_fast_ref"] = HuntHex(details.FileFastRef, 16);
            if (details.HasSectionObjectPointers)
            {
                (*evidence)[prefix + L"_section_object_pointers"] = HuntHex(details.SectionObjectPointers, 16);
            }
            if (details.HasImageSectionObject)
            {
                (*evidence)[prefix + L"_image_section_object"] = HuntHex(details.ImageSectionObject, 16);
            }
            if (details.HasDataSectionObject)
            {
                (*evidence)[prefix + L"_data_section_object"] = HuntHex(details.DataSectionObject, 16);
            }
            if (details.HasFileFlags)
            {
                (*evidence)[prefix + L"_file_flags"] = HuntHex(details.FileFlags, 8);
            }
            if (details.HasDeletePending)
            {
                (*evidence)[prefix + L"_delete_pending"] = details.DeletePending ? L"true" : L"false";
            }
            if (details.HasWriteAccess)
            {
                (*evidence)[prefix + L"_write_access"] = details.WriteAccess ? L"true" : L"false";
            }
            if (details.HasDeleteAccess)
            {
                (*evidence)[prefix + L"_delete_access"] = details.DeleteAccess ? L"true" : L"false";
            }
            if (details.HasSharedWrite)
            {
                (*evidence)[prefix + L"_shared_write"] = details.SharedWrite ? L"true" : L"false";
            }
            if (details.HasSharedDelete)
            {
                (*evidence)[prefix + L"_shared_delete"] = details.SharedDelete ? L"true" : L"false";
            }
        } while (false);
    }

    bool ControlAreaBackingHasSuspiciousFileAccess(const ControlAreaBackingDetails& details)
    {
        return (details.HasWriteAccess && details.WriteAccess) ||
            (details.HasDeleteAccess && details.DeleteAccess);
    }

    bool ControlAreaBackingHasImageSectionPointerMismatch(const ControlAreaBackingDetails& details)
    {
        return details.HasImageSectionObject &&
            details.ImageSectionObject != 0 &&
            IsKernelAddress(details.ImageSectionObject) &&
            details.ControlArea != 0 &&
            IsKernelAddress(details.ControlArea) &&
            details.ImageSectionObject != details.ControlArea;
    }

    void AddProcessTamperingPrimitiveReasons(
        const std::wstring& prefix,
        const ControlAreaBackingDetails& details,
        std::vector<std::wstring>* reasons)
    {
        do
        {
            if (reasons == nullptr)
            {
                break;
            }

            if (details.HasDeletePending && details.DeletePending)
            {
                AddUnique(reasons, prefix + L"_file_delete_pending");
            }
            if (ControlAreaBackingHasSuspiciousFileAccess(details))
            {
                AddUnique(reasons, prefix + L"_file_write_or_delete_access");
            }
            if (ControlAreaBackingHasImageSectionPointerMismatch(details))
            {
                AddUnique(reasons, prefix + L"_file_section_object_pointer_mismatch");
            }
        } while (false);
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
            target->VadSectionSeen =
                target->VadSectionSeen ||
                incoming.VadSectionSeen;
            target->VadBackingManagedImage =
                target->VadBackingManagedImage || incoming.VadBackingManagedImage;
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

            // Kernel FILE_OBJECT names are commonly root-relative
            // ("\Windows\..."), while Win32 directory APIs return a drive
            // qualified path.  Compare them on the directory's drive instead
            // of treating the same file as a different provenance.
            if (IsRootRelativePath(canonicalPath) && IsDriveQualifiedPath(canonicalDirectory))
            {
                canonicalPath = canonicalDirectory.substr(0, 2) + canonicalPath;
            }
            else if (IsRootRelativePath(canonicalDirectory) && IsDriveQualifiedPath(canonicalPath))
            {
                canonicalDirectory = canonicalPath.substr(0, 2) + canonicalDirectory;
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

    bool ProcessNativePebShowsWow64(
        const HuntProcessRecord& process)
    {
        static const std::set<std::wstring> kWow64RuntimeModules = {
            L"wow64.dll",
            L"wow64cpu.dll",
            L"wow64win.dll"
        };
        for (const auto& candidate : process.Modules)
        {
            if (!ModuleHasCoreLdrView(candidate))
            {
                continue;
            }

            const std::wstring leaf = LeafName(
                candidate.Path.empty() ? candidate.Name : candidate.Path);
            if (kWow64RuntimeModules.find(leaf) != kWow64RuntimeModules.end())
            {
                return true;
            }
        }
        return false;
    }

    bool ProcessHasCompleteUserModuleInventory(
        const HuntProcessRecord& process)
    {
        return ProcessHasReliableCoreLdrView(process) &&
            (!ProcessNativePebShowsWow64(process) ||
             process.ToolhelpModuleEnumerated);
    }

    bool ProcessHasManagedRuntimeModule(const HuntProcessRecord& process)
    {
        if (!process.PebLdrEnumerated)
        {
            return false;
        }

        static const std::set<std::wstring> kManagedRuntimeModules = {
            L"clr.dll",
            L"coreclr.dll",
            L"mscorwks.dll",
            L"mono-2.0-bdwgc.dll",
            L"monosgen-2.0.dll"
        };
        const bool nativePebShowsWow64 =
            ProcessNativePebShowsWow64(process);

        for (const auto& candidate : process.Modules)
        {
            const bool nativeLdrSeen =
                candidate.LdrLoadSeen ||
                candidate.LdrMemorySeen ||
                candidate.LdrInitSeen;
            // A 64-bit reader sees the native PEB lists of a WOW64 process,
            // while Toolhelp exposes its 32-bit loader list. Accept that
            // second loader view only when the native PEB independently
            // proves this is a WOW64 host and Toolhelp completed.
            const bool wow64ToolhelpLdrSeen =
                nativePebShowsWow64 &&
                process.ToolhelpModuleEnumerated &&
                candidate.ToolhelpSeen;
            if (!nativeLdrSeen && !wow64ToolhelpLdrSeen)
            {
                continue;
            }

            std::wstring leaf = LeafName(
                candidate.Path.empty() ? candidate.Name : candidate.Path);
            if (kManagedRuntimeModules.find(leaf) != kManagedRuntimeModules.end())
            {
                return true;
            }
        }

        return false;
    }

    bool IsExpectedManagedLoaderlessMapping(
        const HuntProcessRecord& process,
        const HuntModuleRecord& module)
    {
        // CLR maps managed assemblies as SEC_IMAGE but does not have to insert
        // them into the native PEB loader lists.  That invariant is independent
        // of install path.  Require both a validated CLR metadata header in the
        // backing PE and a CLR runtime observed through a completed loader
        // view. WOW64's 32-bit list is represented by Toolhelp only after its
        // native PEB independently proves the WOW64 host; a forged COM
        // directory alone must not disable the detector.
        return module.VadBackingManagedImage &&
            module.VadBackingState == L"resolved" &&
            !module.VadBackingPath.empty() &&
            ProcessHasManagedRuntimeModule(process);
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

            backed =
                CanonicalPathUnderDirectory(path, WindowsDirectory()) ||
                CanonicalPathUnderDirectory(
                    path,
                    EnsureTrailingSlash(ProgramDataDirectory()) +
                        L"Microsoft\\Windows Defender\\Platform");
        } while (false);

        return backed;
    }

    bool IsMicrosoftWindowsAppRuntimeModulePathShape(
        const std::wstring& windowsAppsDirectory,
        const std::wstring& path)
    {
        if (!CanonicalPathUnderDirectory(
                path,
                windowsAppsDirectory))
        {
            return false;
        }

        const std::wstring canonicalPath =
            CanonicalPathForCompare(path);
        std::wstring canonicalRoot =
            EnsureTrailingSlash(
                CanonicalPathForCompare(
                    windowsAppsDirectory));
        if (canonicalPath.size() <= canonicalRoot.size())
        {
            return false;
        }

        const std::wstring relative =
            canonicalPath.substr(canonicalRoot.size());
        const size_t separator = relative.find(L'\\');
        if (separator == std::wstring::npos ||
            separator == 0)
        {
            return false;
        }

        const std::wstring packageDirectory =
            relative.substr(0, separator);
        constexpr wchar_t kPackagePrefix[] =
            L"microsoft.windowsappruntime.";
        constexpr wchar_t kMicrosoftPublisherId[] =
            L"__8wekyb3d8bbwe";
        if (packageDirectory.rfind(kPackagePrefix, 0) != 0 ||
            packageDirectory.size() <=
                _countof(kMicrosoftPublisherId) - 1 ||
            packageDirectory.compare(
                packageDirectory.size() -
                    (_countof(kMicrosoftPublisherId) - 1),
                _countof(kMicrosoftPublisherId) - 1,
                kMicrosoftPublisherId) != 0)
        {
            return false;
        }

        static const std::set<std::wstring> kExpectedModules =
        {
            L"windowsappruntime.deploymentextensions.onecore.dll",
            L"windowsappsdk.appxdeploymentextensions.desktop.dll"
        };
        return kExpectedModules.find(
            LeafName(canonicalPath)) !=
            kExpectedModules.end();
    }

    bool IsTrustedMicrosoftWindowsAppRuntimeModule(
        const std::wstring& path)
    {
        const std::wstring windowsApps =
            EnsureTrailingSlash(ProgramFilesDirectory()) +
            L"WindowsApps";
        if (!IsMicrosoftWindowsAppRuntimeModulePathShape(
                windowsApps,
                path))
        {
            return false;
        }

        ImageMetadataRecord metadata = {};
        return VerifyImageAuthenticodeSignature(
                   DosPathFromDevicePath(
                       Win32FilePathFromMaybeNtPath(path)),
                   &metadata) &&
            metadata.SignatureChecked &&
            metadata.SignatureValid;
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
            if (bytes == nullptr ||
                file == INVALID_HANDLE_VALUE ||
                length == 0 ||
                rva >= metadata.SizeOfImage ||
                length > metadata.SizeOfImage - rva)
            {
                break;
            }

            bytes->clear();
            bytes->reserve(length);
            uint32_t currentRva = rva;
            uint32_t remaining = length;
            while (remaining != 0)
            {
                uint64_t rawOffset = 0;
                uint64_t available = 0;
                if (metadata.SizeOfHeaders != 0 &&
                    currentRva < metadata.SizeOfHeaders)
                {
                    rawOffset = currentRva;
                    available =
                        static_cast<uint64_t>(metadata.SizeOfHeaders) -
                        currentRva;
                }
                else
                {
                    for (const DiskPeSection& section : metadata.Sections)
                    {
                        const uint64_t sectionStart =
                            section.VirtualAddress;
                        const uint64_t rawSpan = section.SizeOfRawData;
                        const uint64_t sectionRawEnd =
                            sectionStart + rawSpan;
                        if (rawSpan == 0 ||
                            sectionRawEnd < sectionStart ||
                            currentRva < sectionStart ||
                            currentRva >= sectionRawEnd)
                        {
                            continue;
                        }

                        const uint64_t delta =
                            static_cast<uint64_t>(currentRva) -
                            sectionStart;
                        rawOffset =
                            static_cast<uint64_t>(
                                section.PointerToRawData) +
                            delta;
                        available = rawSpan - delta;
                        break;
                    }
                }
                if (available == 0)
                {
                    break;
                }

                const uint32_t chunk = static_cast<uint32_t>(
                    std::min<uint64_t>(available, remaining));
                std::vector<uint8_t> part;
                if (!ReadFileBytesAt(
                        file,
                        rawOffset,
                        chunk,
                        &part) ||
                    part.size() != chunk)
                {
                    break;
                }
                bytes->insert(
                    bytes->end(),
                    part.begin(),
                    part.end());
                currentRva += chunk;
                remaining -= chunk;
            }

            ok = remaining == 0 && bytes->size() == length;
        } while (false);

        if (!ok && bytes != nullptr)
        {
            bytes->clear();
        }
        return ok;
    }

    bool BytesAreAllZero(
        const std::vector<uint8_t>& bytes)
    {
        return std::all_of(
            bytes.begin(),
            bytes.end(),
            [](uint8_t value)
            {
                return value == 0;
            });
    }

    void PopulateRelocationPages(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t relocRva,
        uint32_t relocSize)
    {
        if (metadata == nullptr)
        {
            return;
        }

        metadata->BaseRelocationTablePresent =
            relocRva != 0 || relocSize != 0;
        if (!metadata->BaseRelocationTablePresent)
        {
            return;
        }

        bool complete =
            file != INVALID_HANDLE_VALUE &&
            relocRva != 0 &&
            relocSize >= sizeof(IMAGE_BASE_RELOCATION) &&
            relocSize <= kMaxBaseRelocationTableBytes &&
            relocRva < metadata->SizeOfImage &&
            relocSize <= metadata->SizeOfImage - relocRva;
        uint32_t parsed = 0;
        size_t relocationEntries = 0;
        while (complete && parsed < relocSize)
        {
            const uint32_t remaining = relocSize - parsed;
            if (remaining < sizeof(IMAGE_BASE_RELOCATION))
            {
                complete = false;
                break;
            }

            std::vector<uint8_t> blockHeader;
            if (!ReadDiskBytesForRva(
                    file,
                    *metadata,
                    relocRva + parsed,
                    sizeof(IMAGE_BASE_RELOCATION),
                    &blockHeader) ||
                blockHeader.size() < sizeof(IMAGE_BASE_RELOCATION))
            {
                complete = false;
                break;
            }

            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, blockHeader.data(), sizeof(block));
            if (block.VirtualAddress == 0 && block.SizeOfBlock == 0)
            {
                const uint32_t trailingBytes =
                    remaining -
                    static_cast<uint32_t>(
                        sizeof(IMAGE_BASE_RELOCATION));
                std::vector<uint8_t> terminatorPadding;
                if (trailingBytes != 0 &&
                    (!ReadDiskBytesForRva(
                         file,
                         *metadata,
                         relocRva +
                             parsed +
                             sizeof(IMAGE_BASE_RELOCATION),
                         trailingBytes,
                         &terminatorPadding) ||
                     terminatorPadding.size() != trailingBytes ||
                     !BytesAreAllZero(
                         terminatorPadding)))
                {
                    // A zero relocation header is an optional terminator, not
                    // permission to ignore arbitrary trailing table data.
                    complete = false;
                    break;
                }
                parsed = relocSize;
                break;
            }
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > remaining ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) %
                    sizeof(uint16_t)) != 0)
            {
                complete = false;
                break;
            }

            const uint32_t entryBytes =
                block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
            std::vector<uint8_t> entries;
            if (entryBytes != 0 &&
                (!ReadDiskBytesForRva(
                     file,
                     *metadata,
                     relocRva + parsed + sizeof(IMAGE_BASE_RELOCATION),
                     entryBytes,
                     &entries) ||
                 entries.size() < entryBytes))
            {
                complete = false;
                break;
            }

            const size_t entryCount = entryBytes / sizeof(uint16_t);
            for (size_t index = 0; index < entryCount; ++index)
            {
                uint16_t entry = 0;
                std::memcpy(
                    &entry,
                    entries.data() + index * sizeof(uint16_t),
                    sizeof(entry));
                const uint16_t type = entry >> 12;
                const uint16_t offset = entry & 0x0fffu;
                if (type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                if (++relocationEntries > kMaxBaseRelocationEntries)
                {
                    complete = false;
                    break;
                }

                uint32_t fixupWidth = 0;
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    fixupWidth = sizeof(uint64_t);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    fixupWidth = sizeof(uint32_t);
                }
                else
                {
                    complete = false;
                    break;
                }

                const uint64_t fixupRva64 =
                    static_cast<uint64_t>(block.VirtualAddress) + offset;
                if (fixupRva64 >= metadata->SizeOfImage ||
                    fixupWidth > metadata->SizeOfImage - fixupRva64)
                {
                    complete = false;
                    break;
                }

                const uint32_t fixupRva =
                    static_cast<uint32_t>(fixupRva64);
                metadata->RelocationPages.insert(
                    fixupRva & 0xfffff000u);
                DiskPeBaseRelocation relocation = {};
                relocation.Rva = fixupRva;
                relocation.Width = fixupWidth;
                metadata->BaseRelocations.push_back(relocation);
                if (((fixupRva & 0xfffu) + fixupWidth) > 0x1000u)
                {
                    const uint64_t nextPage =
                        static_cast<uint64_t>(fixupRva & 0xfffff000u) +
                        0x1000u;
                    if (nextPage >= metadata->SizeOfImage ||
                        nextPage > std::numeric_limits<uint32_t>::max())
                    {
                        complete = false;
                        break;
                    }
                    metadata->RelocationPages.insert(
                        static_cast<uint32_t>(nextPage));
                    DiskPeMutableRange crossPage = {};
                    crossPage.Rva = fixupRva;
                    crossPage.Size = fixupWidth;
                    metadata->CrossPageRelocationRanges.push_back(
                        crossPage);
                }
            }
            if (!complete)
            {
                break;
            }

            parsed += block.SizeOfBlock;
        }

        metadata->BaseRelocationTableComplete =
            complete && parsed == relocSize;
        if (metadata->BaseRelocationTableComplete)
        {
            std::stable_sort(
                metadata->BaseRelocations.begin(),
                metadata->BaseRelocations.end(),
                [](const DiskPeBaseRelocation& left,
                   const DiskPeBaseRelocation& right)
                {
                    return left.Rva < right.Rva;
                });
        }
        else
        {
            metadata->RelocationPages.clear();
            metadata->BaseRelocations.clear();
            metadata->CrossPageRelocationRanges.clear();
        }
    }

    void AddLoaderMutableRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size)
    {
        if (ranges == nullptr || rva == 0 || size == 0)
        {
            return;
        }

        const uint64_t end = static_cast<uint64_t>(rva) + size;
        if (end >
            static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1ull)
        {
            return;
        }

        DiskPeMutableRange range = {};
        range.Rva = rva;
        range.Size = size;
        ranges->push_back(range);
    }

    void AddLoaderMutableDirectoryRanges(
        std::vector<DiskPeMutableRange>* ranges,
        const IMAGE_DATA_DIRECTORY* directories,
        uint32_t count)
    {
        do
        {
            if (ranges == nullptr || directories == nullptr)
            {
                break;
            }

            // The loader overwrites IAT slots. Import descriptors, delay-load
            // descriptors, TLS, and load-config structures are not themselves
            // blanket-mutable and masking their whole directories can hide an
            // executable-page patch.
            const uint32_t mutableDirectories[] =
            {
                IMAGE_DIRECTORY_ENTRY_IAT
            };

            for (uint32_t directoryIndex : mutableDirectories)
            {
                if (directoryIndex >= count)
                {
                    continue;
                }

                AddLoaderMutableRange(
                    ranges,
                    directories[directoryIndex].VirtualAddress,
                    directories[directoryIndex].Size);
            }
        } while (false);
    }

    bool AddDynamicRelocationRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size)
    {
        if (ranges == nullptr || size == 0)
        {
            return false;
        }

        const uint64_t end = static_cast<uint64_t>(rva) + size;
        if (end > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1ull)
        {
            return false;
        }

        for (const DiskPeMutableRange& existing : *ranges)
        {
            if (existing.Rva == rva && existing.Size == size)
            {
                return true;
            }
        }
        if (ranges->size() >= kMaxDynamicRelocationRanges)
        {
            return false;
        }

        DiskPeMutableRange range = {};
        range.Rva = rva;
        range.Size = size;
        ranges->push_back(range);
        return true;
    }

    bool ParseFunctionOverrideBaseRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (bytes == nullptr ||
            ranges == nullptr ||
            sizeOfImage == 0)
        {
            return false;
        }

        size_t cursor = 0;
        while (cursor < size)
        {
            if (size - cursor < sizeof(IMAGE_BASE_RELOCATION))
            {
                return false;
            }

            IMAGE_BASE_RELOCATION block = {};
            std::memcpy(&block, bytes + cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                block.SizeOfBlock > size - cursor ||
                ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(uint16_t)) != 0)
            {
                return false;
            }

            const size_t entryBytes = block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
            const size_t entryCount = entryBytes / sizeof(uint16_t);
            for (size_t index = 0; index < entryCount; ++index)
            {
                uint16_t entry = 0;
                std::memcpy(
                    &entry,
                    bytes + cursor + sizeof(IMAGE_BASE_RELOCATION) + index * sizeof(entry),
                    sizeof(entry));

                const uint16_t type = static_cast<uint16_t>(entry >> 12);
                const uint16_t offset = static_cast<uint16_t>(entry & 0x0fffu);
                if (type == IMAGE_FUNCTION_OVERRIDE_INVALID)
                {
                    continue;
                }

                uint32_t width = 0;
                if (type == IMAGE_FUNCTION_OVERRIDE_X64_REL32 ||
                    type == IMAGE_FUNCTION_OVERRIDE_ARM64_BRANCH26)
                {
                    width = sizeof(uint32_t);
                }
                else
                {
                    // The SDK does not define the byte span of THUNK records.
                    // Fail closed instead of masking an assumed range.
                    return false;
                }

                const uint64_t fixupRva = static_cast<uint64_t>(block.VirtualAddress) + offset;
                if (fixupRva >= sizeOfImage ||
                    width > sizeOfImage - fixupRva ||
                    !AddDynamicRelocationRange(
                        ranges,
                        static_cast<uint32_t>(fixupRva),
                        width))
                {
                    return false;
                }
            }

            cursor += block.SizeOfBlock;
        }

        return cursor == size;
    }

    bool ParseFunctionOverrideDynamicRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (bytes == nullptr ||
            ranges == nullptr ||
            sizeOfImage == 0 ||
            size < sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER))
        {
            return false;
        }

        IMAGE_FUNCTION_OVERRIDE_HEADER header = {};
        std::memcpy(&header, bytes, sizeof(header));
        const size_t recordsStart = sizeof(header);
        if (header.FuncOverrideSize > size - recordsStart)
        {
            return false;
        }

        const size_t recordsEnd = recordsStart + header.FuncOverrideSize;
        size_t cursor = recordsStart;
        std::vector<uint32_t> bddOffsets;
        while (cursor < recordsEnd)
        {
            if (recordsEnd - cursor < sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION))
            {
                return false;
            }

            IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION record = {};
            std::memcpy(&record, bytes + cursor, sizeof(record));
            if (record.OriginalRva >= sizeOfImage ||
                (record.RvaSize % sizeof(uint32_t)) != 0)
            {
                return false;
            }
            bddOffsets.push_back(record.BDDOffset);

            const uint64_t recordSize =
                static_cast<uint64_t>(sizeof(record)) +
                record.RvaSize +
                record.BaseRelocSize;
            if (recordSize > recordsEnd - cursor)
            {
                return false;
            }

            const size_t rvaOffset =
                cursor + sizeof(record);
            const size_t rvaCount =
                record.RvaSize / sizeof(uint32_t);
            for (size_t index = 0;
                 index < rvaCount;
                 ++index)
            {
                uint32_t overrideRva = 0;
                std::memcpy(
                    &overrideRva,
                    bytes +
                        rvaOffset +
                        index * sizeof(uint32_t),
                    sizeof(overrideRva));
                if (overrideRva >= sizeOfImage)
                {
                    return false;
                }
            }

            const size_t relocOffset =
                cursor + sizeof(record) + static_cast<size_t>(record.RvaSize);
            if (!ParseFunctionOverrideBaseRelocations(
                    bytes + relocOffset,
                    record.BaseRelocSize,
                    sizeOfImage,
                    ranges))
            {
                return false;
            }

            cursor += static_cast<size_t>(recordSize);
        }

        if (cursor != recordsEnd)
        {
            return false;
        }

        // The remaining payload is a sequence of BDD records. Each override
        // points at the IMAGE_BDD_INFO that selects its active RVA. Current
        // Windows images can contain several contiguous BDDs, so validate the
        // complete sequence instead of treating the whole region as one BDD.
        if (size - recordsEnd < sizeof(IMAGE_BDD_INFO))
        {
            return false;
        }

        const size_t bddRegionSize = size - recordsEnd;
        std::sort(bddOffsets.begin(), bddOffsets.end());
        bddOffsets.erase(
            std::unique(bddOffsets.begin(), bddOffsets.end()),
            bddOffsets.end());
        if (bddOffsets.empty() || bddOffsets.front() != 0)
        {
            return false;
        }

        size_t expectedOffset = 0;
        for (uint32_t offset : bddOffsets)
        {
            if (offset != expectedOffset ||
                offset > bddRegionSize - sizeof(IMAGE_BDD_INFO))
            {
                return false;
            }

            IMAGE_BDD_INFO bdd = {};
            std::memcpy(
                &bdd,
                bytes + recordsEnd + offset,
                sizeof(bdd));
            if (bdd.Version != 1 ||
                (bdd.BDDSize % sizeof(IMAGE_BDD_DYNAMIC_RELOCATION)) != 0 ||
                bdd.BDDSize >
                    bddRegionSize - offset - sizeof(IMAGE_BDD_INFO))
            {
                return false;
            }

            expectedOffset =
                static_cast<size_t>(offset) +
                sizeof(IMAGE_BDD_INFO) +
                bdd.BDDSize;
        }

        return expectedOffset == bddRegionSize;
    }

    bool ParseDynamicRelocationTable(
        const std::vector<uint8_t>& bytes,
        bool pe64,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges)
    {
        if (ranges == nullptr ||
            sizeOfImage == 0 ||
            bytes.size() < sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE))
        {
            return false;
        }

        std::vector<DiskPeMutableRange> parsedRanges;
        IMAGE_DYNAMIC_RELOCATION_TABLE table = {};
        std::memcpy(&table, bytes.data(), sizeof(table));
        if (table.Version != 1 ||
            table.Size != bytes.size() - sizeof(table))
        {
            return false;
        }

        const size_t tableEnd = sizeof(table) + table.Size;
        size_t cursor = sizeof(table);
        while (cursor < tableEnd)
        {
            const size_t entryHeaderSize =
                pe64 ? sizeof(IMAGE_DYNAMIC_RELOCATION64) : sizeof(IMAGE_DYNAMIC_RELOCATION32);
            if (tableEnd - cursor < entryHeaderSize)
            {
                return false;
            }

            uint64_t symbol = 0;
            uint32_t payloadSize = 0;
            if (pe64)
            {
                IMAGE_DYNAMIC_RELOCATION64 entry = {};
                std::memcpy(&entry, bytes.data() + cursor, sizeof(entry));
                symbol = entry.Symbol;
                payloadSize = entry.BaseRelocSize;
            }
            else
            {
                IMAGE_DYNAMIC_RELOCATION32 entry = {};
                std::memcpy(&entry, bytes.data() + cursor, sizeof(entry));
                symbol = entry.Symbol;
                payloadSize = entry.BaseRelocSize;
            }

            if (payloadSize > tableEnd - cursor - entryHeaderSize)
            {
                return false;
            }

            const uint8_t* payload = bytes.data() + cursor + entryHeaderSize;
            if (symbol != IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE ||
                !ParseFunctionOverrideDynamicRelocations(
                    payload,
                    payloadSize,
                    sizeOfImage,
                    &parsedRanges))
            {
                // Other DVRT symbol formats use different record layouts.
                // Unknown records make the deep comparison incomplete; they
                // must never become a clean result through broad masking.
                return false;
            }

            cursor += entryHeaderSize + payloadSize;
        }

        if (cursor != tableEnd)
        {
            return false;
        }

        std::sort(
            parsedRanges.begin(),
            parsedRanges.end(),
            [](const DiskPeMutableRange& left, const DiskPeMutableRange& right)
            {
                if (left.Rva != right.Rva)
                {
                    return left.Rva < right.Rva;
                }
                return left.Size < right.Size;
            });
        std::vector<DiskPeMutableRange> normalized;
        normalized.reserve(parsedRanges.size());
        for (const DiskPeMutableRange& range : parsedRanges)
        {
            const uint64_t rangeEnd = static_cast<uint64_t>(range.Rva) + range.Size;
            if (normalized.empty())
            {
                normalized.push_back(range);
                continue;
            }

            DiskPeMutableRange& previous = normalized.back();
            const uint64_t previousEnd =
                static_cast<uint64_t>(previous.Rva) + previous.Size;
            if (range.Rva <= previousEnd)
            {
                const uint64_t mergedEnd = std::max(previousEnd, rangeEnd);
                const uint64_t mergedSize = mergedEnd - previous.Rva;
                if (mergedSize > std::numeric_limits<uint32_t>::max())
                {
                    return false;
                }
                previous.Size = static_cast<uint32_t>(mergedSize);
            }
            else
            {
                normalized.push_back(range);
            }
        }
        *ranges = std::move(normalized);
        return true;
    }

    void PopulateDynamicRelocationRanges(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t loadConfigRva,
        uint32_t loadConfigSize,
        bool pe64)
    {
        if (file == INVALID_HANDLE_VALUE ||
            metadata == nullptr ||
            loadConfigRva == 0 ||
            loadConfigSize < sizeof(uint32_t))
        {
            return;
        }

        const size_t structureSize =
            pe64 ? sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) : sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32);
        const uint32_t bytesToRead =
            static_cast<uint32_t>(std::min<size_t>(loadConfigSize, structureSize));
        std::vector<uint8_t> loadConfig;
        if (!ReadDiskBytesForRva(file, *metadata, loadConfigRva, bytesToRead, &loadConfig) ||
            loadConfig.size() < sizeof(uint32_t))
        {
            metadata->DynamicRelocationTablePresent = true;
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        uint32_t declaredSize = 0;
        std::memcpy(&declaredSize, loadConfig.data(), sizeof(declaredSize));
        const size_t available = std::min<size_t>(loadConfig.size(), declaredSize);
        uint64_t tableVa = 0;
        uint32_t tableOffset = 0;
        uint16_t tableSection = 0;

        if (pe64)
        {
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTable) + sizeof(uint64_t))
            {
                std::memcpy(
                    &tableVa,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTable),
                    sizeof(tableVa));
            }
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection) + sizeof(uint16_t))
            {
                std::memcpy(
                    &tableOffset,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset),
                    sizeof(tableOffset));
                std::memcpy(
                    &tableSection,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection),
                    sizeof(tableSection));
            }
        }
        else
        {
            uint32_t tableVa32 = 0;
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTable) + sizeof(uint32_t))
            {
                std::memcpy(
                    &tableVa32,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTable),
                    sizeof(tableVa32));
                tableVa = tableVa32;
            }
            if (available >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableSection) + sizeof(uint16_t))
            {
                std::memcpy(
                    &tableOffset,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableOffset),
                    sizeof(tableOffset));
                std::memcpy(
                    &tableSection,
                    loadConfig.data() + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, DynamicValueRelocTableSection),
                    sizeof(tableSection));
            }
        }

        uint32_t tableRva = 0;
        bool located = false;
        if (tableVa != 0 &&
            metadata->ImageBase != 0 &&
            tableVa >= metadata->ImageBase &&
            tableVa - metadata->ImageBase <= std::numeric_limits<uint32_t>::max())
        {
            tableRva = static_cast<uint32_t>(tableVa - metadata->ImageBase);
            located = true;
        }
        else if (tableSection != 0 &&
                 tableSection <= metadata->Sections.size())
        {
            const DiskPeSection& section = metadata->Sections[tableSection - 1];
            const uint64_t candidate = static_cast<uint64_t>(section.VirtualAddress) + tableOffset;
            const uint64_t sectionSpan = std::max(section.VirtualSize, section.SizeOfRawData);
            if (tableOffset < sectionSpan &&
                candidate <= std::numeric_limits<uint32_t>::max())
            {
                tableRva = static_cast<uint32_t>(candidate);
                located = true;
            }
        }

        if (!located)
        {
            // An older load-config can legitimately predate DVRT fields.
            if (tableVa == 0 && tableOffset == 0 && tableSection == 0)
            {
                return;
            }

            metadata->DynamicRelocationTablePresent = true;
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        metadata->DynamicRelocationTablePresent = true;
        std::vector<uint8_t> tableHeader;
        if (!ReadDiskBytesForRva(
                file,
                *metadata,
                tableRva,
                sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE),
                &tableHeader) ||
            tableHeader.size() < sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE))
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        IMAGE_DYNAMIC_RELOCATION_TABLE table = {};
        std::memcpy(&table, tableHeader.data(), sizeof(table));
        constexpr uint32_t kMaxDynamicRelocationTableBytes = 16u * 1024u * 1024u;
        if (table.Size > kMaxDynamicRelocationTableBytes)
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        const uint64_t totalSize = static_cast<uint64_t>(sizeof(table)) + table.Size;
        if (totalSize > std::numeric_limits<uint32_t>::max())
        {
            metadata->DynamicRelocationTableComplete = false;
            return;
        }

        std::vector<uint8_t> tableBytes;
        if (!ReadDiskBytesForRva(
                file,
                *metadata,
                tableRva,
                static_cast<uint32_t>(totalSize),
                &tableBytes) ||
            tableBytes.size() != totalSize ||
            !ParseDynamicRelocationTable(
                tableBytes,
                pe64,
                metadata->SizeOfImage,
                &metadata->DynamicRelocationRanges))
        {
            metadata->DynamicRelocationTableComplete = false;
            metadata->DynamicRelocationRanges.clear();
            return;
        }

        for (const DiskPeMutableRange& range : metadata->DynamicRelocationRanges)
        {
            const uint64_t rangeEnd = static_cast<uint64_t>(range.Rva) + range.Size;
            if (metadata->SizeOfImage == 0 || rangeEnd > metadata->SizeOfImage)
            {
                metadata->DynamicRelocationTableComplete = false;
                metadata->DynamicRelocationRanges.clear();
                return;
            }
        }
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
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
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

            IMAGE_DOS_HEADER dos = {};
            std::memcpy(&dos, header.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE ||
                dos.e_lfanew <= 0)
            {
                if (error != nullptr)
                {
                    *error = L"disk image is not a PE file";
                }
                break;
            }
            metadata->HasFileIdentity =
                GetFileInformationByHandle(
                    file,
                    &metadata->FileIdentity) != FALSE;
            metadata->HasFileBasicIdentity =
                GetFileInformationByHandleEx(
                    file,
                    FileBasicInfo,
                    &metadata->FileBasicIdentity,
                    sizeof(metadata->FileBasicIdentity)) != FALSE;

            size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
            constexpr size_t kMaximumPeHeaderSpan =
                16u * 1024u * 1024u;
            const size_t minimumNtBytes =
                sizeof(uint32_t) +
                sizeof(IMAGE_FILE_HEADER);
            if (ntOffset >
                    kMaximumPeHeaderSpan -
                        minimumNtBytes)
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image NT header offset exceeds the parser cap";
                }
                break;
            }
            const size_t minimumNtEnd =
                ntOffset + minimumNtBytes;
            if (minimumNtEnd > header.size() &&
                (!ReadFileBytesAt(
                     file,
                     0,
                     static_cast<uint32_t>(minimumNtEnd),
                     &header) ||
                 header.size() < minimumNtEnd))
            {
                if (error != nullptr)
                {
                    *error =
                        L"read disk image NT header failed";
                }
                break;
            }

            uint32_t signature = 0;
            std::memcpy(&signature, header.data() + ntOffset, sizeof(signature));
            if (signature != IMAGE_NT_SIGNATURE)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid NT signature";
                }
                break;
            }

            IMAGE_FILE_HEADER fileHeader = {};
            std::memcpy(
                &fileHeader,
                header.data() + ntOffset + sizeof(uint32_t),
                sizeof(fileHeader));
            const uint16_t numberOfSections = fileHeader.NumberOfSections;
            const uint16_t optionalHeaderSize = fileHeader.SizeOfOptionalHeader;
            size_t optionalOffset = ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
            constexpr uint16_t kMaximumPeSectionCount = 96;
            if (optionalHeaderSize < sizeof(uint16_t) ||
                numberOfSections == 0 ||
                numberOfSections > kMaximumPeSectionCount)
            {
                if (error != nullptr)
                {
                    *error = L"disk image has invalid optional-header or section count";
                }
                break;
            }

            size_t sectionOffset = optionalOffset + optionalHeaderSize;
            size_t required = sectionOffset + static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
            if (required > kMaximumPeHeaderSpan)
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image section table exceeds the parser cap";
                }
                break;
            }
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
            uint32_t loadConfigRva = 0;
            uint32_t loadConfigSize = 0;
            uint32_t managedRva = 0;
            uint32_t managedSize = 0;
            bool pe64 = false;
            uint16_t magic = 0;
            std::memcpy(&magic, header.data() + optionalOffset, sizeof(magic));
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                constexpr size_t kPe64FixedOptionalBytes =
                    offsetof(
                        IMAGE_OPTIONAL_HEADER64,
                        DataDirectory);
                if (optionalHeaderSize <
                    kPe64FixedOptionalBytes)
                {
                    if (error != nullptr)
                    {
                        *error = L"truncated PE32+ optional header";
                    }
                    break;
                }

                pe64 = true;
                IMAGE_OPTIONAL_HEADER64 optional = {};
                std::memcpy(
                    &optional,
                    header.data() + optionalOffset,
                    std::min<size_t>(
                        optionalHeaderSize,
                        sizeof(optional)));
                const size_t availableDirectories =
                    (optionalHeaderSize -
                     kPe64FixedOptionalBytes) /
                        sizeof(IMAGE_DATA_DIRECTORY);
                if (optional.NumberOfRvaAndSizes >
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
                    optional.NumberOfRvaAndSizes >
                        availableDirectories)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"PE32+ data-directory count exceeds the declared optional header";
                    }
                    break;
                }

                metadata->ImageBase = optional.ImageBase;
                metadata->EntryPointRva = optional.AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional.SizeOfHeaders;
                metadata->SizeOfImage = optional.SizeOfImage;
                AddLoaderMutableDirectoryRanges(
                    &metadata->LoaderMutableRanges,
                    optional.DataDirectory,
                    optional.NumberOfRvaAndSizes);
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                {
                    loadConfigRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                    loadConfigSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                {
                    const IMAGE_DATA_DIRECTORY& managed =
                        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
                    managedRva = managed.VirtualAddress;
                    managedSize = managed.Size;
                }
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                constexpr size_t kPe32FixedOptionalBytes =
                    offsetof(
                        IMAGE_OPTIONAL_HEADER32,
                        DataDirectory);
                if (optionalHeaderSize <
                    kPe32FixedOptionalBytes)
                {
                    if (error != nullptr)
                    {
                        *error = L"truncated PE32 optional header";
                    }
                    break;
                }

                IMAGE_OPTIONAL_HEADER32 optional = {};
                std::memcpy(
                    &optional,
                    header.data() + optionalOffset,
                    std::min<size_t>(
                        optionalHeaderSize,
                        sizeof(optional)));
                const size_t availableDirectories =
                    (optionalHeaderSize -
                     kPe32FixedOptionalBytes) /
                        sizeof(IMAGE_DATA_DIRECTORY);
                if (optional.NumberOfRvaAndSizes >
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
                    optional.NumberOfRvaAndSizes >
                        availableDirectories)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"PE32 data-directory count exceeds the declared optional header";
                    }
                    break;
                }

                metadata->ImageBase = optional.ImageBase;
                metadata->EntryPointRva = optional.AddressOfEntryPoint;
                metadata->SizeOfHeaders = optional.SizeOfHeaders;
                metadata->SizeOfImage = optional.SizeOfImage;
                AddLoaderMutableDirectoryRanges(
                    &metadata->LoaderMutableRanges,
                    optional.DataDirectory,
                    optional.NumberOfRvaAndSizes);
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                {
                    relocRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    relocSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                {
                    loadConfigRva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
                    loadConfigSize = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                }
                if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
                {
                    const IMAGE_DATA_DIRECTORY& managed =
                        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
                    managedRva = managed.VirtualAddress;
                    managedSize = managed.Size;
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

            if (metadata->SizeOfImage == 0 ||
                metadata->SizeOfHeaders > metadata->SizeOfImage ||
                (metadata->EntryPointRva != 0 &&
                 metadata->EntryPointRva >= metadata->SizeOfImage))
            {
                if (error != nullptr)
                {
                    *error = L"PE image/header/entrypoint bounds are invalid";
                }
                break;
            }

            bool directoryRangesValid = true;
            for (const DiskPeMutableRange& range : metadata->LoaderMutableRanges)
            {
                if (range.Rva >= metadata->SizeOfImage ||
                    range.Size > metadata->SizeOfImage - range.Rva)
                {
                    directoryRangesValid = false;
                    break;
                }
            }
            if (!directoryRangesValid)
            {
                if (error != nullptr)
                {
                    *error = L"PE loader-mutable data directory is outside the image";
                }
                break;
            }

            metadata->HasEntryPoint = metadata->EntryPointRva != 0;

            bool sectionRangesValid = true;
            for (uint16_t index = 0; index < numberOfSections; ++index)
            {
                IMAGE_SECTION_HEADER rawSection = {};
                std::memcpy(
                    &rawSection,
                    header.data() + sectionOffset + static_cast<size_t>(index) * sizeof(rawSection),
                    sizeof(rawSection));
                DiskPeSection section = {};
                char sectionName[9] = {};
                std::memcpy(sectionName, rawSection.Name, IMAGE_SIZEOF_SHORT_NAME);
                std::string narrowName(sectionName);
                section.Name.assign(narrowName.begin(), narrowName.end());
                section.VirtualAddress = rawSection.VirtualAddress;
                section.VirtualSize = rawSection.Misc.VirtualSize;
                section.PointerToRawData = rawSection.PointerToRawData;
                section.SizeOfRawData = rawSection.SizeOfRawData;
                section.Characteristics = rawSection.Characteristics;
                section.Executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                section.Writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                const uint64_t mappedSpan =
                    std::max(section.VirtualSize, section.SizeOfRawData);
                if (mappedSpan != 0 &&
                    (section.VirtualAddress >= metadata->SizeOfImage ||
                     mappedSpan >
                         static_cast<uint64_t>(metadata->SizeOfImage) -
                             section.VirtualAddress))
                {
                    sectionRangesValid = false;
                    break;
                }
                metadata->Sections.push_back(section);

                if (!metadata->HasExecutableSection &&
                    section.Executable)
                {
                    metadata->FirstExecutableSectionRva = section.VirtualAddress;
                    metadata->HasExecutableSection = true;
                }
            }
            if (!sectionRangesValid)
            {
                if (error != nullptr)
                {
                    *error = L"PE section range is outside the image";
                }
                break;
            }

            if (managedRva != 0 &&
                managedSize >= sizeof(IMAGE_COR20_HEADER) &&
                static_cast<uint64_t>(managedRva) + managedSize <= metadata->SizeOfImage)
            {
                std::vector<uint8_t> corHeaderBytes;
                if (ReadDiskBytesForRva(
                        file,
                        *metadata,
                        managedRva,
                        sizeof(IMAGE_COR20_HEADER),
                        &corHeaderBytes) &&
                    corHeaderBytes.size() >= sizeof(IMAGE_COR20_HEADER))
                {
                    IMAGE_COR20_HEADER corHeader = {};
                    std::memcpy(
                        &corHeader,
                        corHeaderBytes.data(),
                        sizeof(corHeader));
                    if (corHeader.cb >= sizeof(IMAGE_COR20_HEADER) &&
                        corHeader.cb <= managedSize &&
                        corHeader.MetaData.VirtualAddress != 0 &&
                        corHeader.MetaData.Size >= sizeof(uint32_t) &&
                        static_cast<uint64_t>(corHeader.MetaData.VirtualAddress) +
                                corHeader.MetaData.Size <=
                            metadata->SizeOfImage)
                    {
                        std::vector<uint8_t> metadataSignatureBytes;
                        uint32_t metadataSignature = 0;
                        if (ReadDiskBytesForRva(
                                file,
                                *metadata,
                                corHeader.MetaData.VirtualAddress,
                                sizeof(metadataSignature),
                                &metadataSignatureBytes) &&
                            metadataSignatureBytes.size() >= sizeof(metadataSignature))
                        {
                            std::memcpy(
                                &metadataSignature,
                                metadataSignatureBytes.data(),
                                sizeof(metadataSignature));
                            metadata->ManagedImage =
                                metadataSignature == 0x424a5342u;
                            metadata->ManagedIlOnly =
                                metadata->ManagedImage &&
                                (corHeader.Flags & kComImageFlagsIlOnly) != 0;
                        }
                    }
                }
            }

            metadata->BaserelocRva = relocRva;
            metadata->BaserelocSize = relocSize;
            PopulateRelocationPages(file, metadata, relocRva, relocSize);
            PopulateDynamicRelocationRanges(
                file,
                metadata,
                loadConfigRva,
                loadConfigSize,
                pe64);

            ok = true;
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok;
    }

    bool DiskFileIdentityMatches(
        HANDLE file,
        const DiskPeMetadata& metadata)
    {
        if (file == INVALID_HANDLE_VALUE ||
            !metadata.HasFileIdentity)
        {
            return false;
        }

        BY_HANDLE_FILE_INFORMATION current = {};
        if (!GetFileInformationByHandle(
                file,
                &current))
        {
            return false;
        }

        const BY_HANDLE_FILE_INFORMATION& expected =
            metadata.FileIdentity;
        bool matches =
            current.dwVolumeSerialNumber ==
                expected.dwVolumeSerialNumber &&
            current.nFileIndexHigh ==
                expected.nFileIndexHigh &&
            current.nFileIndexLow ==
                expected.nFileIndexLow &&
            current.nFileSizeHigh ==
                expected.nFileSizeHigh &&
            current.nFileSizeLow ==
                expected.nFileSizeLow &&
            current.ftCreationTime.dwHighDateTime ==
                expected.ftCreationTime.dwHighDateTime &&
            current.ftCreationTime.dwLowDateTime ==
                expected.ftCreationTime.dwLowDateTime &&
            current.ftLastWriteTime.dwHighDateTime ==
                expected.ftLastWriteTime.dwHighDateTime &&
            current.ftLastWriteTime.dwLowDateTime ==
                expected.ftLastWriteTime.dwLowDateTime;
        if (!matches ||
            !metadata.HasFileBasicIdentity)
        {
            return matches;
        }

        FILE_BASIC_INFO currentBasic = {};
        return GetFileInformationByHandleEx(
                   file,
                   FileBasicInfo,
                   &currentBasic,
                   sizeof(currentBasic)) != FALSE &&
            currentBasic.CreationTime.QuadPart ==
                metadata.FileBasicIdentity.CreationTime.QuadPart &&
            currentBasic.LastWriteTime.QuadPart ==
                metadata.FileBasicIdentity.LastWriteTime.QuadPart &&
            currentBasic.ChangeTime.QuadPart ==
                metadata.FileBasicIdentity.ChangeTime.QuadPart;
    }

    bool ApplyBaseRelocationsToDiskPage(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        uint64_t imageDelta,
        std::vector<uint8_t>* pageBytes,
        std::vector<uint8_t>* nextPageBytes)
    {
        if (pageBytes == nullptr ||
            pageBytes->size() < kPageSize ||
            !metadata.BaseRelocationTableComplete ||
            metadata.BaseRelocations.empty())
        {
            return false;
        }

        const uint64_t pageStart = pageRva;
        const uint64_t pageEnd = pageStart + pageBytes->size();
        auto first = std::lower_bound(
            metadata.BaseRelocations.begin(),
            metadata.BaseRelocations.end(),
            pageStart,
            [](const DiskPeBaseRelocation& relocation, uint64_t address)
            {
                return static_cast<uint64_t>(relocation.Rva) +
                    relocation.Width <= address;
            });

        for (auto current = first;
             current != metadata.BaseRelocations.end() &&
                 current->Rva < pageEnd;
             ++current)
        {
            const uint64_t fixupStart = current->Rva;
            const uint64_t fixupEnd = fixupStart + current->Width;
            if (fixupEnd <= pageStart)
            {
                continue;
            }

            // A relocation beginning on the preceding page is masked at its
            // exact byte range after normalization; the preceding bytes are
            // not available here to reconstruct its full integer value.
            if (fixupStart < pageStart)
            {
                continue;
            }

            const size_t pageOffset =
                static_cast<size_t>(fixupStart - pageStart);
            if (pageOffset + current->Width <= pageBytes->size())
            {
                uint64_t value = 0;
                std::memcpy(
                    &value,
                    pageBytes->data() + pageOffset,
                    current->Width);
                value += imageDelta;
                std::memcpy(
                    pageBytes->data() + pageOffset,
                    &value,
                    current->Width);
                continue;
            }

            const size_t firstBytes = pageBytes->size() - pageOffset;
            const size_t secondBytes = current->Width - firstBytes;
            if (nextPageBytes == nullptr ||
                nextPageBytes->size() < secondBytes)
            {
                return false;
            }

            uint8_t raw[8] = {};
            std::memcpy(
                raw,
                pageBytes->data() + pageOffset,
                firstBytes);
            std::memcpy(
                raw + firstBytes,
                nextPageBytes->data(),
                secondBytes);
            uint64_t value = 0;
            std::memcpy(&value, raw, current->Width);
            value += imageDelta;
            std::memcpy(raw, &value, current->Width);
            std::memcpy(
                pageBytes->data() + pageOffset,
                raw,
                firstBytes);
            std::memcpy(
                nextPageBytes->data(),
                raw + firstBytes,
                secondBytes);
        }

        return true;
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
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_RANDOM_ACCESS,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"open disk image failed";
                }
                break;
            }
            if (!DiskFileIdentityMatches(
                    file,
                    metadata))
            {
                if (error != nullptr)
                {
                    *error =
                        L"disk image changed after PE metadata capture";
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
        std::wstring* warning,
        std::map<uint32_t, ApiThreadRecord>* threads = nullptr)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr)
            {
                break;
            }

            processes->clear();
            if (threads != nullptr)
            {
                threads->clear();
            }

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
            ULONG returnedLength = 0;
            constexpr uint64_t kMaximumProcessInformationBytes =
                256ull * 1024ull * 1024ull;
            for (uint32_t attempt = 0; attempt < 8; ++attempt)
            {
                buffer.assign(length, 0);
                returnedLength = 0;
                status = query(
                    kSystemProcessInformation,
                    buffer.data(),
                    length,
                    &returnedLength);
                if (status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall)
                {
                    const uint64_t reported =
                        static_cast<uint64_t>(returnedLength) + 0x10000ull;
                    const uint64_t doubled =
                        static_cast<uint64_t>(length) * 2ull;
                    const uint64_t requested =
                        std::max(reported, doubled);
                    if (requested > kMaximumProcessInformationBytes ||
                        requested > std::numeric_limits<ULONG>::max())
                    {
                        break;
                    }
                    length = static_cast<ULONG>(requested);
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

            if (returnedLength == 0 ||
                returnedLength > buffer.size())
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"NtQuerySystemInformation returned an invalid process buffer length";
                }
                break;
            }

            const size_t validLength =
                static_cast<size_t>(returnedLength);
            const uintptr_t bufferStart =
                reinterpret_cast<uintptr_t>(buffer.data());
            if (validLength >
                std::numeric_limits<uintptr_t>::max() - bufferStart)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"NtQuerySystemInformation process buffer address overflow";
                }
                break;
            }
            const uintptr_t bufferEnd = bufferStart + validLength;

            size_t offset = 0;
            bool malformed = false;
            bool terminalEntrySeen = false;
            while (offset <= validLength &&
                   sizeof(HuntSystemProcessInformation) <=
                       validLength - offset)
            {
                const HuntSystemProcessInformation* spi =
                    reinterpret_cast<const HuntSystemProcessInformation*>(buffer.data() + offset);

                const size_t entryLength =
                    spi->NextEntryOffset != 0
                        ? static_cast<size_t>(
                              spi->NextEntryOffset)
                        : validLength - offset;
                if (entryLength <
                        sizeof(HuntSystemProcessInformation) ||
                    entryLength > validLength - offset ||
                    spi->NumberOfThreads >
                        (entryLength -
                         sizeof(HuntSystemProcessInformation)) /
                            sizeof(
                                HuntSystemThreadInformation))
                {
                    malformed = true;
                    break;
                }

                ApiProcessRecord record = {};
                const uintptr_t processId =
                    reinterpret_cast<uintptr_t>(
                        spi->UniqueProcessId);
                const uintptr_t parentProcessId =
                    reinterpret_cast<uintptr_t>(
                        spi->InheritedFromUniqueProcessId);
                if (processId >
                        std::numeric_limits<uint32_t>::max() ||
                    parentProcessId >
                        std::numeric_limits<uint32_t>::max())
                {
                    malformed = true;
                    break;
                }
                record.ProcessId =
                    static_cast<uint32_t>(processId);
                record.ParentProcessId =
                    static_cast<uint32_t>(parentProcessId);
                record.HasParentProcessId = spi->InheritedFromUniqueProcessId != nullptr;
                if ((spi->ImageName.Length % sizeof(wchar_t)) != 0 ||
                    spi->ImageName.MaximumLength <
                        spi->ImageName.Length ||
                    (spi->ImageName.Length != 0 &&
                     spi->ImageName.Buffer == nullptr))
                {
                    malformed = true;
                    break;
                }
                if (spi->ImageName.Buffer != nullptr &&
                    spi->ImageName.Length != 0)
                {
                    const uintptr_t imageStart =
                        reinterpret_cast<uintptr_t>(
                            spi->ImageName.Buffer);
                    const size_t imageBytes =
                        spi->ImageName.Length;
                    if (imageStart < bufferStart ||
                        imageStart > bufferEnd ||
                        imageBytes >
                            static_cast<size_t>(
                                bufferEnd - imageStart))
                    {
                        malformed = true;
                        break;
                    }
                    record.ImageName.assign(
                        spi->ImageName.Buffer,
                        imageBytes / sizeof(wchar_t));
                }
                else if (record.ProcessId == 0)
                {
                    record.ImageName = L"Idle";
                }
                else if (record.ProcessId == 4)
                {
                    record.ImageName = L"System";
                }

                if (threads != nullptr)
                {
                    const HuntSystemThreadInformation*
                        threadArray =
                            reinterpret_cast<
                                const HuntSystemThreadInformation*>(
                                reinterpret_cast<
                                    const uint8_t*>(spi) +
                                sizeof(
                                    HuntSystemProcessInformation));
                    for (ULONG threadIndex = 0;
                         threadIndex < spi->NumberOfThreads;
                         ++threadIndex)
                    {
                        const uintptr_t threadId =
                            reinterpret_cast<uintptr_t>(
                                threadArray[threadIndex].
                                    UniqueThread);
                        const uintptr_t ownerProcessId =
                            reinterpret_cast<uintptr_t>(
                                threadArray[threadIndex].
                                    UniqueProcess);
                        if (IsReservedCidZeroThread(
                                threadId,
                                ownerProcessId) &&
                            processId == 0)
                        {
                            continue;
                        }
                        if (threadId == 0 ||
                            threadId >
                                std::numeric_limits<
                                    uint32_t>::max() ||
                            ownerProcessId >
                                std::numeric_limits<
                                    uint32_t>::max() ||
                            ownerProcessId != processId)
                        {
                            malformed = true;
                            break;
                        }

                        ApiThreadRecord thread = {};
                        thread.ThreadId =
                            static_cast<uint32_t>(threadId);
                        thread.ProcessId =
                            static_cast<uint32_t>(
                                ownerProcessId);
                        if (threads->size() >=
                                kMaxCidProcessProbeCount ||
                            !threads->emplace(
                                thread.ThreadId,
                                thread).second)
                        {
                            malformed = true;
                            break;
                        }
                    }
                    if (malformed)
                    {
                        break;
                    }
                }

                if (!processes->emplace(
                        record.ProcessId,
                        std::move(record)).second)
                {
                    malformed = true;
                    break;
                }

                if (spi->NextEntryOffset == 0)
                {
                    terminalEntrySeen = true;
                    break;
                }

                const size_t nextOffset =
                    spi->NextEntryOffset;
                if (nextOffset <
                        sizeof(HuntSystemProcessInformation) ||
                    (nextOffset % alignof(void*)) != 0 ||
                    nextOffset > validLength - offset)
                {
                    malformed = true;
                    break;
                }
                offset += nextOffset;
            }

            if (malformed || !terminalEntrySeen)
            {
                processes->clear();
                if (threads != nullptr)
                {
                    threads->clear();
                }
                if (warning != nullptr)
                {
                    *warning =
                        L"NtQuerySystemInformation returned a malformed process inventory";
                }
                break;
            }

            ok = true;
        } while (false);

        if (!ok)
        {
            if (processes != nullptr)
            {
                processes->clear();
            }
            if (threads != nullptr)
            {
                threads->clear();
            }
        }
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

            for (;;)
            {
                ApiProcessRecord record = {};
                record.ProcessId = entry.th32ProcessID;
                record.ParentProcessId = entry.th32ParentProcessID;
                record.HasParentProcessId = true;
                record.ImageName = entry.szExeFile;
                if (!processes->emplace(
                        record.ProcessId,
                        std::move(record)).second)
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"Toolhelp returned a duplicate process identifier";
                    }
                    break;
                }
                entry.dwSize = sizeof(entry);
                if (Process32NextW(snapshot, &entry))
                {
                    continue;
                }

                const DWORD enumerationError = GetLastError();
                if (enumerationError == ERROR_NO_MORE_FILES)
                {
                    ok = true;
                }
                else if (warning != nullptr)
                {
                    *warning =
                        L"Process32NextW failed gle=" +
                        std::to_wstring(enumerationError);
                }
                break;
            }
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            if (snapshot != nullptr)
            {
                CloseHandle(snapshot);
            }
        }

        if (!ok && processes != nullptr)
        {
            processes->clear();
        }
        return ok;
    }

    bool CollectToolhelpThreads(
        std::map<uint32_t, ApiThreadRecord>* threads,
        std::wstring* warning)
    {
        bool ok = false;
        HANDLE snapshot = INVALID_HANDLE_VALUE;

        do
        {
            if (threads == nullptr)
            {
                break;
            }

            threads->clear();
            snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD,
                0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed gle=" +
                        std::to_wstring(GetLastError());
                }
                break;
            }

            THREADENTRY32 entry = {};
            entry.dwSize = sizeof(entry);
            if (!Thread32First(snapshot, &entry))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"Thread32First failed gle=" +
                        std::to_wstring(GetLastError());
                }
                break;
            }

            for (;;)
            {
                const bool reservedCidZeroThread =
                    IsReservedCidZeroThread(
                        entry.th32ThreadID,
                        entry.th32OwnerProcessID);
                if (entry.th32ThreadID == 0 &&
                    !reservedCidZeroThread)
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"Toolhelp returned a zero thread identifier";
                    }
                    break;
                }

                if (!reservedCidZeroThread)
                {
                    ApiThreadRecord record = {};
                    record.ThreadId = entry.th32ThreadID;
                    record.ProcessId =
                        entry.th32OwnerProcessID;
                    if (threads->size() >=
                            kMaxCidProcessProbeCount ||
                        !threads->emplace(
                            record.ThreadId,
                            record).second)
                    {
                        if (warning != nullptr)
                        {
                            *warning =
                                threads->size() >=
                                        kMaxCidProcessProbeCount
                                    ? L"Toolhelp thread inventory exceeded the bounded CID/thread budget"
                                    : L"Toolhelp returned a duplicate thread identifier";
                        }
                        break;
                    }
                }

                entry.dwSize = sizeof(entry);
                if (Thread32Next(snapshot, &entry))
                {
                    continue;
                }

                const DWORD enumerationError =
                    GetLastError();
                if (enumerationError ==
                    ERROR_NO_MORE_FILES)
                {
                    ok = true;
                }
                else if (warning != nullptr)
                {
                    *warning =
                        L"Thread32Next failed gle=" +
                        std::to_wstring(
                            enumerationError);
                }
                break;
            }
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            if (snapshot != nullptr)
            {
                CloseHandle(snapshot);
            }
        }
        if (!ok && threads != nullptr)
        {
            threads->clear();
        }
        return ok;
    }

    bool ProcessHandleMatchesSnapshot(
        HANDLE handle,
        const SnapshotProcessRecord& snapshot,
        bool* lifecycleChanged)
    {
        if (lifecycleChanged != nullptr)
        {
            *lifecycleChanged = false;
        }
        if (handle == nullptr ||
            handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        FILETIME createTime = {};
        FILETIME exitTime = {};
        FILETIME kernelTime = {};
        FILETIME userTime = {};
        if (!GetProcessTimes(
                handle,
                &createTime,
                &exitTime,
                &kernelTime,
                &userTime))
        {
            return false;
        }

        DWORD exitCode = 0;
        if (!GetExitCodeProcess(handle, &exitCode))
        {
            return false;
        }

        ULARGE_INTEGER observedCreate = {};
        observedCreate.LowPart = createTime.dwLowDateTime;
        observedCreate.HighPart = createTime.dwHighDateTime;

        const bool changed =
            exitCode != STILL_ACTIVE ||
            (snapshot.HasCreateTime &&
             (snapshot.CreateTime == 0 ||
              observedCreate.QuadPart != snapshot.CreateTime));
        if (changed && lifecycleChanged != nullptr)
        {
            *lifecycleChanged = true;
        }
        return !changed;
    }

    void QueryProcessPublicDetails(
        HuntProcessRecord* process,
        bool* lifecycleChanged)
    {
        HANDLE handle = nullptr;

        if (lifecycleChanged != nullptr)
        {
            *lifecycleChanged = false;
        }
        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            DWORD sessionId = 0;
            const bool sessionIdAvailable =
                ProcessIdToSessionId(
                    process->ProcessId,
                    &sessionId) != FALSE;

            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process->ProcessId);
            if (handle == nullptr)
            {
                const DWORD openError = GetLastError();
                if (HasExactProcessIdentity(process->Kernel) &&
                    (openError == ERROR_INVALID_PARAMETER ||
                     openError == ERROR_INVALID_HANDLE ||
                     openError == ERROR_NOT_FOUND) &&
                    lifecycleChanged != nullptr)
                {
                    *lifecycleChanged = true;
                }
                break;
            }

            bool handleLifecycleChanged = false;
            if (!ProcessHandleMatchesSnapshot(
                    handle,
                    process->Kernel,
                    &handleLifecycleChanged))
            {
                if (handleLifecycleChanged &&
                    lifecycleChanged != nullptr)
                {
                    *lifecycleChanged = true;
                }
                break;
            }

            if (sessionIdAvailable)
            {
                process->SessionId = sessionId;
                process->HasSessionId = true;
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
        DWORD snapshotError = ERROR_SUCCESS;

        do
        {
            if (process == nullptr || process->ProcessId == 0)
            {
                break;
            }

            // The Toolhelp contract explicitly permits transient
            // ERROR_BAD_LENGTH while loader lists are changing. Treating the
            // first one as permanent makes WOW64 inventories unnecessarily
            // flaky.
            constexpr size_t kMaxModuleSnapshotAttempts = 8;
            for (size_t attempt = 0;
                 attempt < kMaxModuleSnapshotAttempts;
                 ++attempt)
            {
                snapshot = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                    process->ProcessId);
                if (snapshot != INVALID_HANDLE_VALUE)
                {
                    break;
                }

                snapshotError = GetLastError();
                if (snapshotError != ERROR_BAD_LENGTH)
                {
                    break;
                }
                SwitchToThread();
            }
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"toolhelp module snapshot failed gle=" +
                        std::to_wstring(snapshotError);
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

            for (;;)
            {
                HuntModuleRecord module = {};
                module.Base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                module.Size = entry.modBaseSize;
                module.Name = entry.szModule;
                module.Path = entry.szExePath;
                module.ToolhelpSeen = true;
                MergeModule(&process->Modules, module);
                entry.dwSize = sizeof(entry);
                if (Module32NextW(snapshot, &entry))
                {
                    continue;
                }

                const DWORD enumerationError = GetLastError();
                if (enumerationError == ERROR_NO_MORE_FILES)
                {
                    process->ToolhelpModuleEnumerated = true;
                    ok = true;
                }
                else if (warning != nullptr)
                {
                    *warning =
                        L"toolhelp module enumeration failed gle=" +
                        std::to_wstring(enumerationError);
                }
                break;
            }
        } while (false);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            if (snapshot != nullptr)
            {
                CloseHandle(snapshot);
            }
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
                (TargetUserDtb(process->Kernel) == 0 &&
                 !HasExactProcessIdentity(process->Kernel)))
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
                AddUnique(
                    &process->Warnings,
                    L"PEB LDR " + source + L" list head read failed");
                break;
            }

            std::set<uint64_t> visited;
            size_t scanned = 0;
            bool traversalFailed = false;
            while (current != 0 && current != listHead && scanned < kMaxLdrModules)
            {
                if (!IsUserAddress(current) || current < listEntryOffset)
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR " + source + L" list contains an invalid entry pointer");
                    traversalFailed = true;
                    break;
                }
                if (visited.find(current) != visited.end())
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR " + source + L" list loop detected");
                    traversalFailed = true;
                    break;
                }

                visited.insert(current);
                uint64_t entryBase = current - listEntryOffset;
                HuntModuleRecord module = {};
                if (!ReadProcessU64(device, process->Kernel, entryBase + 0x30, &module.Base) ||
                    !IsUserAddress(module.Base))
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR " + source + L" module base read failed");
                    traversalFailed = true;
                    break;
                }

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

                uint64_t next = 0;
                if (!ReadProcessU64(device, process->Kernel, current, &next))
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR " + source + L" list link read failed");
                    traversalFailed = true;
                    break;
                }
                if (next != listHead && !IsUserAddress(next))
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR " + source + L" list contains an invalid next pointer");
                    traversalFailed = true;
                    break;
                }

                MergeModule(&process->Modules, module);
                current = next;
                ++scanned;
            }

            if (scanned >= kMaxLdrModules)
            {
                AddUnique(
                    &process->Warnings,
                    L"PEB LDR " + source + L" list traversal hit the module limit");
                traversalFailed = true;
            }
            if (current == 0)
            {
                AddUnique(
                    &process->Warnings,
                    L"PEB LDR " + source + L" list terminated at a null link");
                traversalFailed = true;
            }

            if (!traversalFailed && current == listHead)
            {
                ok = true;
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
                (TargetUserDtb(process->Kernel) == 0 &&
                 !HasExactProcessIdentity(process->Kernel)))
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

            std::vector<std::wstring> lastWarnings;
            for (uint32_t attempt = 1; attempt <= kHuntTriageStabilityAttempts; ++attempt)
            {
                HuntProcessRecord snapshot = {};
                snapshot.Kernel = process->Kernel;
                snapshot.ProcessId = process->ProcessId;

                bool loadSeen = WalkPebLdrList(device, &snapshot, ldr + 0x10, 0x00, L"load");
                bool memorySeen = WalkPebLdrList(device, &snapshot, ldr + 0x20, 0x10, L"memory");
                bool initSeen = WalkPebLdrList(device, &snapshot, ldr + 0x30, 0x20, L"init");
                lastWarnings = snapshot.Warnings;
                if (!loadSeen || !memorySeen)
                {
                    continue;
                }

                if (!initSeen)
                {
                    for (HuntModuleRecord& module : snapshot.Modules)
                    {
                        module.LdrInitSeen = false;
                    }
                }

                for (const HuntModuleRecord& module : snapshot.Modules)
                {
                    MergeModule(&process->Modules, module);
                }
                process->Warnings.insert(
                    process->Warnings.end(),
                    snapshot.Warnings.begin(),
                    snapshot.Warnings.end());
                process->PebLdrLoadEnumerated = true;
                process->PebLdrMemoryEnumerated = true;
                process->PebLdrInitEnumerated = initSeen;
                process->PebLdrEnumerated = true;
                if (attempt > 1)
                {
                    AddUnique(
                        &process->Warnings,
                        L"PEB LDR core list collection stabilized after " +
                            std::to_wstring(attempt) + L" attempts");
                }
                break;
            }

            if (!process->PebLdrEnumerated)
            {
                process->Warnings.insert(
                    process->Warnings.end(),
                    lastWarnings.begin(),
                    lastWarnings.end());
                AddUnique(
                    &process->Warnings,
                    L"PEB LDR core list collection remained incomplete after retries");
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
        target.CreateTime = process.CreateTime;
        target.HasCreateTime = process.HasCreateTime;
        target.ImageName = process.ImageName;
        return target;
    }

    bool SameHiddenPteEvidence(
        const std::vector<ProcessHiddenVadPteRecord>& left,
        const std::vector<ProcessHiddenVadPteRecord>& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }

        for (size_t index = 0; index < left.size(); ++index)
        {
            const ProcessHiddenVadPteRecord& a = left[index];
            const ProcessHiddenVadPteRecord& b = right[index];
            if (a.StartAddress != b.StartAddress ||
                a.EndAddress != b.EndAddress ||
                a.PageSize != b.PageSize ||
                a.Writable != b.Writable ||
                a.Executable != b.Executable ||
                a.UserAccessible != b.UserAccessible)
            {
                return false;
            }
        }

        return true;
    }

    bool VadScanHasTransientSnapshotFailure(const ProcessVadScanResult& result)
    {
        if (result.PageTableReadFailures != 0 || result.HiddenPteTruncated)
        {
            return true;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            if (warning.find(L"VAD node is not kernel-canonical") != std::wstring::npos ||
                warning.find(L"failed to read VAD node") != std::wstring::npos ||
                warning.find(L"VAD cycle detected") != std::wstring::npos ||
                warning.find(L"VAD root is empty") != std::wstring::npos ||
                warning.find(L"page-table walk had read failures") != std::wstring::npos)
            {
                return true;
            }
        }

        return false;
    }

    void SuppressUnconfirmedHiddenPteEvidence(ProcessVadScanResult* result)
    {
        if (result == nullptr)
        {
            return;
        }

        result->HiddenPteRecords.clear();
        result->HiddenPteRanges = 0;
        result->HiddenPteBytes = 0;
        result->HiddenPteExecutableCount = 0;
        result->HiddenPteWxCount = 0;
        result->HiddenPteTruncated = false;
        result->Incomplete = true;
        result->CoverageComplete = false;
        result->Warnings.push_back(
            L"hidden PTE evidence suppressed because it was not stable across fresh scans");
    }

    bool ScanVadForHunt(
        ProcessTriageScanner& triage,
        const ProcessVadScanOptions& options,
        ProcessVadScanResult* result,
        uint32_t* attemptsUsed,
        std::wstring* error)
    {
        bool anySuccess = false;
        std::vector<ProcessHiddenVadPteRecord> previousHidden;
        std::wstring lastError;

        if (attemptsUsed != nullptr)
        {
            *attemptsUsed = 0;
        }

        for (uint32_t attempt = 1; attempt <= kHuntTriageStabilityAttempts; ++attempt)
        {
            if (attemptsUsed != nullptr)
            {
                *attemptsUsed = attempt;
            }

            ProcessVadScanResult candidate = {};
            std::wstring scanError;
            if (!triage.ScanVad(options, &candidate, &scanError))
            {
                lastError = scanError;
                continue;
            }

            anySuccess = true;
            bool transientFailure = VadScanHasTransientSnapshotFailure(candidate);
            bool hiddenStable =
                !candidate.HiddenPteRecords.empty() &&
                !previousHidden.empty() &&
                SameHiddenPteEvidence(previousHidden, candidate.HiddenPteRecords);

            *result = std::move(candidate);
            if (!transientFailure && result->HiddenPteRecords.empty())
            {
                if (attempt > 1)
                {
                    result->Warnings.push_back(
                        L"VAD/page-table collection stabilized after " + std::to_wstring(attempt) + L" attempts");
                }
                return true;
            }
            if (!transientFailure && hiddenStable)
            {
                result->Warnings.push_back(
                    L"hidden PTE evidence confirmed across fresh scans");
                return true;
            }

            if (!transientFailure && !result->HiddenPteRecords.empty())
            {
                previousHidden = result->HiddenPteRecords;
            }
            else
            {
                previousHidden.clear();
            }
        }

        if (anySuccess)
        {
            if (!result->HiddenPteRecords.empty())
            {
                SuppressUnconfirmedHiddenPteEvidence(result);
            }
            return true;
        }

        if (error != nullptr)
        {
            *error = lastError;
        }
        return false;
    }

    bool SameThreadSuspensionEvidence(
        const ProcessThreadScanResult& left,
        const ProcessThreadScanResult& right)
    {
        if (!left.SuspensionStateCoverageComplete ||
            !right.SuspensionStateCoverageComplete ||
            left.ThreadsVisited == 0 ||
            left.ThreadsVisited !=
                right.ThreadsVisited ||
            left.Records.size() !=
                left.ThreadsVisited ||
            right.Records.size() !=
                right.ThreadsVisited)
        {
            return false;
        }

        std::map<
            uint64_t,
            std::pair<uint32_t, uint32_t>>
            expected;
        for (const ProcessThreadRecord& record :
             left.Records)
        {
            if (record.Ethread == 0 ||
                !record.HasSuspendCount ||
                !record.HasFreezeCount ||
                !expected.emplace(
                    record.Ethread,
                    std::make_pair(
                        record.SuspendCount,
                        record.FreezeCount)).second)
            {
                return false;
            }
        }
        for (const ProcessThreadRecord& record :
             right.Records)
        {
            const auto item =
                expected.find(record.Ethread);
            if (item == expected.end() ||
                !record.HasSuspendCount ||
                !record.HasFreezeCount ||
                item->second.first !=
                    record.SuspendCount ||
                item->second.second !=
                    record.FreezeCount)
            {
                return false;
            }
            expected.erase(item);
        }
        return expected.empty();
    }

    bool ScanThreadsForHunt(
        ProcessTriageScanner& triage,
        const ProcessThreadScanOptions& options,
        ProcessThreadScanResult* result,
        uint32_t* attemptsUsed,
        std::wstring* error)
    {
        bool anySuccess = false;
        std::wstring lastError;
        ProcessThreadScanResult
            previousSuspended = {};
        bool hasPreviousSuspended = false;

        if (attemptsUsed != nullptr)
        {
            *attemptsUsed = 0;
        }

        for (uint32_t attempt = 1; attempt <= kHuntTriageStabilityAttempts; ++attempt)
        {
            if (attemptsUsed != nullptr)
            {
                *attemptsUsed = attempt;
            }

            ProcessThreadScanResult candidate = {};
            std::wstring scanError;
            if (!triage.ScanThreads(options, &candidate, &scanError))
            {
                lastError = scanError;
                continue;
            }

            anySuccess = true;
            const bool collectionComplete =
                !candidate.Truncated &&
                !candidate.Incomplete &&
                candidate.CoverageComplete;
            const bool allThreadsSuspended =
                options.RequireSuspensionCoverage &&
                collectionComplete &&
                candidate.ThreadsVisited != 0 &&
                candidate.SuspendedThreadCount ==
                    candidate.ThreadsVisited;
            if (allThreadsSuspended)
            {
                if (hasPreviousSuspended &&
                    SameThreadSuspensionEvidence(
                        previousSuspended,
                        candidate))
                {
                    candidate.Warnings.push_back(
                        L"all-thread suspend/freeze evidence confirmed across fresh scans");
                    *result = std::move(candidate);
                    return true;
                }

                previousSuspended = candidate;
                hasPreviousSuspended = true;
                *result = std::move(candidate);
                continue;
            }

            *result = std::move(candidate);
            if (collectionComplete)
            {
                if (attempt > 1)
                {
                    result->Warnings.push_back(
                        L"thread collection stabilized after " + std::to_wstring(attempt) + L" attempts");
                }
                return true;
            }
        }

        if (anySuccess)
        {
            if (options.RequireSuspensionCoverage &&
                !result->Truncated &&
                !result->Incomplete &&
                result->CoverageComplete &&
                result->ThreadsVisited != 0 &&
                result->SuspendedThreadCount ==
                    result->ThreadsVisited)
            {
                result->
                    SuspensionStateCoverageComplete =
                        false;
                result->Incomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"all-thread suspend/freeze evidence was not stable across fresh scans");
            }
            return true;
        }

        if (error != nullptr)
        {
            *error = lastError;
        }
        return false;
    }

    std::wstring BestProcessImageName(const HuntProcessRecord& process)
    {
        std::wstring image = process.KernelImageName;

        if (!image.empty())
        {
            std::wstring apiLeaf = LeafName(process.ApiImagePath);
            if (!apiLeaf.empty() && SameLeafOrEprocessImageNamePrefix(image, apiLeaf))
            {
                image = apiLeaf;
            }
            else
            {
                std::wstring pebLeaf = LeafName(process.PebImagePath);
                if (!pebLeaf.empty() && SameLeafOrEprocessImageNamePrefix(image, pebLeaf))
                {
                    image = pebLeaf;
                }
            }
        }
        if (image.empty())
        {
            image = LeafName(process.ApiImagePath);
        }
        if (image.empty())
        {
            image = LeafName(process.PebImagePath);
        }
        if (image.empty())
        {
            image = process.ToolhelpImageName;
        }
        if (image.empty())
        {
            image = process.SystemProcessImageName;
        }

        return image;
    }

    bool CommandLineImageIsComparable(
        const std::wstring& image)
    {
        // CreateProcess can resolve an extensionless bare token such as
        // "ping" through PATH/PATHEXT.  Treating that token as a literal
        // image leaf produces ping vs ping.exe false positives.
        return LeafHasAnySuffix(
            image,
            {
                L".exe",
                L".com",
                L".scr"
            });
    }

    bool IsWindowsTerminalExecutionAliasShape(
        const std::wstring& pebImagePath,
        const std::wstring& apiImagePath,
        const std::wstring& commandImage)
    {
        if (LeafName(commandImage) != L"wt.exe" ||
            LeafName(pebImagePath) !=
                L"windowsterminal.exe" ||
            apiImagePath.empty() ||
            !SameCanonicalPath(
                pebImagePath,
                apiImagePath))
        {
            return false;
        }

        const std::wstring windowsAppsRoot =
            EnsureTrailingSlash(
                CanonicalPathForCompare(
                    EnsureTrailingSlash(
                        ProgramFilesDirectory()) +
                    L"WindowsApps"));
        const std::wstring imagePath =
            CanonicalPathForCompare(
                pebImagePath);
        if (windowsAppsRoot.empty() ||
            imagePath.size() <=
                windowsAppsRoot.size() ||
            imagePath.compare(
                0,
                windowsAppsRoot.size(),
                windowsAppsRoot) != 0)
        {
            return false;
        }

        const std::wstring relative =
            imagePath.substr(
                windowsAppsRoot.size());
        const size_t separator =
            relative.find(L'\\');
        if (separator == std::wstring::npos ||
            relative.substr(separator + 1) !=
                L"windowsterminal.exe")
        {
            return false;
        }

        const std::wstring packageDirectory =
            relative.substr(0, separator);
        const bool knownPackage =
            packageDirectory.compare(
                0,
                std::wcslen(
                    L"microsoft.windowsterminal_"),
                L"microsoft.windowsterminal_") ==
                0 ||
            packageDirectory.compare(
                0,
                std::wcslen(
                    L"microsoft.windowsterminalpreview_"),
                L"microsoft.windowsterminalpreview_") ==
                0;
        constexpr wchar_t kMicrosoftPublisherId[] =
            L"_8wekyb3d8bbwe";
        return knownPackage &&
            packageDirectory.size() >
                std::wcslen(
                    kMicrosoftPublisherId) &&
            packageDirectory.compare(
                packageDirectory.size() -
                    std::wcslen(
                        kMicrosoftPublisherId),
                std::wcslen(
                    kMicrosoftPublisherId),
                kMicrosoftPublisherId) == 0;
    }

    bool IsTrustedWindowsTerminalExecutionAlias(
        const HuntProcessRecord& process,
        const std::wstring& commandImage)
    {
        if (!IsWindowsTerminalExecutionAliasShape(
                process.PebImagePath,
                process.ApiImagePath,
                commandImage))
        {
            return false;
        }

        ImageMetadataRecord metadata = {};
        return VerifyImageAuthenticodeSignature(
                   process.PebImagePath,
                   &metadata) &&
            metadata.SignatureChecked &&
            metadata.SignatureValid;
    }

    bool CanUseParentProcessIdentity(
        const HuntProcessRecord& child,
        const HuntProcessRecord& parent)
    {
        return !parent.KernelImageName.empty() &&
            child.Kernel.HasCreateTime &&
            child.Kernel.CreateTime != 0 &&
            parent.Kernel.HasCreateTime &&
            parent.Kernel.CreateTime != 0 &&
            parent.Kernel.CreateTime <=
                child.Kernel.CreateTime;
    }

    bool HasUnresolvedApiOnlyProcessView(
        const HuntProcessRecord& process)
    {
        return process.ProcessId > 4 &&
            !process.ActiveProcessLinksSeen &&
            (process.SystemProcessInformationSeen ||
             process.ToolhelpProcessSeen) &&
            !process.ActiveProcessLinksStableUnlinked;
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

    std::wstring HuntHexBytesLower(const BYTE* bytes, DWORD count)
    {
        std::wstringstream stream;
        stream << std::hex << std::setfill(L'0');

        for (DWORD index = 0; index < count; ++index)
        {
            stream << std::setw(2) << static_cast<unsigned int>(bytes[index]);
        }

        return stream.str();
    }

    bool ComputeFileSha1ForPath(
        const std::wstring& rawPath,
        FileSha1CacheEntry* entry)
    {
        bool ok = false;
        HANDLE file = INVALID_HANDLE_VALUE;
        HCRYPTPROV provider = 0;
        HCRYPTHASH hash = 0;

        do
        {
            if (entry == nullptr || rawPath.empty())
            {
                break;
            }

            std::wstring path = DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(rawPath));
            if (path.empty())
            {
                entry->Error = L"path normalization failed";
                break;
            }

            DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                entry->Error = L"file is not accessible";
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
                entry->Error = L"CreateFileW failed gle=" + std::to_wstring(GetLastError());
                break;
            }

            if (!CryptAcquireContextW(
                    &provider,
                    nullptr,
                    nullptr,
                    PROV_RSA_AES,
                    CRYPT_VERIFYCONTEXT))
            {
                entry->Error = L"CryptAcquireContextW failed gle=" + std::to_wstring(GetLastError());
                break;
            }

            if (!CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash))
            {
                entry->Error = L"CryptCreateHash failed gle=" + std::to_wstring(GetLastError());
                break;
            }

            std::vector<BYTE> buffer(1024 * 1024);
            for (;;)
            {
                DWORD read = 0;
                if (!ReadFile(
                        file,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        &read,
                        nullptr))
                {
                    entry->Error = L"ReadFile failed gle=" + std::to_wstring(GetLastError());
                    break;
                }

                if (read == 0)
                {
                    ok = true;
                    break;
                }

                if (!CryptHashData(hash, buffer.data(), read, 0))
                {
                    entry->Error = L"CryptHashData failed gle=" + std::to_wstring(GetLastError());
                    break;
                }
            }

            if (!ok)
            {
                break;
            }

            BYTE sha1[20] = {};
            DWORD sha1Size = sizeof(sha1);
            if (!CryptGetHashParam(hash, HP_HASHVAL, sha1, &sha1Size, 0))
            {
                entry->Error = L"CryptGetHashParam failed gle=" + std::to_wstring(GetLastError());
                ok = false;
                break;
            }

            entry->Path = path;
            entry->Sha1 = HuntHexBytesLower(sha1, sha1Size);
            entry->Success = true;
        } while (false);

        if (hash != 0)
        {
            CryptDestroyHash(hash);
        }
        if (provider != 0)
        {
            CryptReleaseContext(provider, 0);
        }
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return ok && entry->Success;
    }

    bool GetCachedFileSha1(
        const std::wstring& rawPath,
        std::map<std::wstring, FileSha1CacheEntry>* cache,
        FileSha1CacheEntry* entry)
    {
        bool ok = false;

        do
        {
            if (entry == nullptr || rawPath.empty())
            {
                break;
            }

            std::wstring normalizedPath =
                NormalizePathText(DosPathFromDevicePath(Win32FilePathFromMaybeNtPath(rawPath)));
            if (normalizedPath.empty())
            {
                break;
            }

            if (cache != nullptr)
            {
                auto existing = cache->find(normalizedPath);
                if (existing != cache->end())
                {
                    *entry = existing->second;
                    ok = entry->Success;
                    break;
                }
            }

            FileSha1CacheEntry computed = {};
            ComputeFileSha1ForPath(rawPath, &computed);
            if (cache != nullptr)
            {
                (*cache)[normalizedPath] = computed;
            }

            *entry = computed;
            ok = entry->Success;
        } while (false);

        return ok;
    }

    void AddEsetFileHashEvidence(
        const EsetFileSha1Ioc& ioc,
        const std::wstring& filePath,
        const std::wstring& sha1,
        std::vector<std::wstring>* reasons,
        std::map<std::wstring, std::wstring>* evidence)
    {
        do
        {
            if (reasons == nullptr || evidence == nullptr)
            {
                break;
            }

            AddUnique(reasons, L"eset_exact_file_sha1_ioc");
            if (ioc.CredentialTool)
            {
                AddUnique(reasons, L"oxideharvest_exact_file_sha1_ioc");
            }
            else
            {
                AddUnique(reasons, L"edr_killer_exact_file_sha1_ioc");
            }

            (*evidence)[L"file_hash_path"] = filePath;
            (*evidence)[L"file_sha1"] = sha1;
            (*evidence)[L"eset_ioc_sha1"] = ioc.Sha1;
            (*evidence)[L"eset_ioc_filename"] = ioc.FileName;
            (*evidence)[L"eset_ioc_family"] = ioc.Family;
            (*evidence)[L"eset_ioc_tool"] = ioc.Tool;
            (*evidence)[L"eset_ioc_credential_tool"] = ioc.CredentialTool ? L"true" : L"false";
        } while (false);
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

    bool ImageVersionInfoLooksLikeSecurityVendorImpersonation(
        const ImageMetadataRecord& metadata,
        std::wstring* matchedNeedle)
    {
        bool matched = false;

        do
        {
            if (matchedNeedle != nullptr)
            {
                matchedNeedle->clear();
            }

            std::wstring text = HuntToLower(
                metadata.CompanyName +
                L" " +
                metadata.ProductName +
                L" " +
                metadata.OriginalFilename +
                L" " +
                metadata.FileDescription);
            if (text.empty())
            {
                break;
            }

            static const wchar_t* kSecurityVendorNeedles[] =
            {
                L"kaspersky",
                L"faceit",
                L"valorant",
                L"riot",
                L"ea anti-cheat",
                L"ea anticheat",
                L"electronic arts",
                L"bitdefender",
                L"malwarebytes",
                L"symantec",
                L"norton",
                L"broadcom",
                L"avast",
                L"avg antivirus",
                L"sentinelone",
                L"sentinel agent",
                L"sophos",
                L"anti-virus",
                L"antivirus",
                L"anti-cheat",
                L"anticheat",
                L"endpoint protection"
            };

            for (const wchar_t* needle : kSecurityVendorNeedles)
            {
                if (needle == nullptr || needle[0] == L'\0')
                {
                    continue;
                }

                if (text.find(needle) != std::wstring::npos)
                {
                    matched = true;
                    if (matchedNeedle != nullptr)
                    {
                        *matchedNeedle = needle;
                    }
                    break;
                }
            }
        } while (false);

        return matched;
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
        bool addEvasionReasons,
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

            if (addEvasionReasons && metadata.SignaturePresent && !metadata.SignatureValid)
            {
                AddUnique(reasons, L"edr_killer_invalid_code_signature");
            }
            std::wstring versionImpersonationMatch;
            bool versionImpersonation =
                addEvasionReasons &&
                metadata.VersionInfoPresent &&
                ImageVersionInfoLooksLikeSecurityVendorImpersonation(metadata, &versionImpersonationMatch);
            if (addEvasionReasons &&
                versionImpersonation)
            {
                AddUnique(reasons, L"edr_killer_version_info_impersonation_evidence");
                (*evidence)[L"image_version_info_impersonation_match"] = versionImpersonationMatch;
            }
            if (addEvasionReasons && metadata.IconResourcePresent && versionImpersonation)
            {
                AddUnique(reasons, L"edr_killer_icon_impersonation_evidence");
            }
            if (addEvasionReasons && !metadata.PackerSectionNames.empty())
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
        AddSpecialBuiltinExpectedPaths(leaf, &expected);

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
        std::map<std::wstring, std::wstring>* evidence,
        bool strongCodeEvidence = true)
    {
        do
        {
            if (!strongCodeEvidence || !process.BuiltinProfileMatched || reasons == nullptr)
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
            finding.ImageName = BestProcessImageName(process);
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

    struct CidAnchorReferenceSet
    {
        std::map<uint64_t, uint32_t> RipRelativeQwordLoads;
        uint32_t InstructionsDecoded = 0;
        bool ReachedReturn = false;
    };

    struct CidTableLayout
    {
        TypeFieldInfo NextHandleNeedingPool = {};
        TypeFieldInfo TableCode = {};
        uint64_t EntrySize = 0;
    };

    struct CidTableSnapshot
    {
        uint64_t AnchorAddress = 0;
        uint64_t TableAddress = 0;
        uint64_t TableCode = 0;
        uint32_t TableLevel = 0;
        uint32_t NextHandle = 0;
        uint32_t AllocatedLeafCount = 0;
        uint64_t AllocatedHandleCapacity = 0;
        std::vector<uint64_t> LeafPages;
    };

    struct CidEnumeratedProcess
    {
        ProcessAddressContext Context = {};
        uint64_t CreateTime = 0;
        uint64_t ExitTime = 0;
        uint64_t Peb = 0;
        uint32_t ActiveThreads = 0;
        bool HasCreateTime = false;
        bool HasExitTime = false;
        bool HasPeb = false;
        bool HasActiveThreads = false;
        std::wstring ImageName;
    };

    struct CidEprocessLayout
    {
        TypeFieldInfo UniqueProcessId = {};
        TypeFieldInfo CreateTime = {};
        TypeFieldInfo ImageFileName = {};
        TypeFieldInfo ExitTime = {};
        TypeFieldInfo ActiveThreads = {};
        TypeFieldInfo Peb = {};
        bool HasImageFileName = false;
        bool HasExitTime = false;
        bool HasActiveThreads = false;
        bool HasPeb = false;
    };

    struct CidDirectThread
    {
        uint32_t ThreadId = 0;
        uint32_t ProcessId = 0;
        uint64_t ObjectHeader = 0;
        uint64_t Ethread = 0;
        uint64_t Eprocess = 0;
        uint64_t CreateTime = 0;
        uint64_t ExitTime = 0;
        bool HasCreateTime = false;
        bool HasExitTime = false;
        bool Terminated = false;
    };

    struct CidDirectProcess
    {
        uint32_t ProcessId = 0;
        uint64_t ObjectHeader = 0;
        CidEnumeratedProcess Process = {};
    };

    struct CidDirectLayout
    {
        TypeFieldInfo ObjectPointerBits = {};
        TypeFieldInfo ObjectHeaderTypeIndex = {};
        TypeFieldInfo ObjectHeaderBody = {};
        TypeFieldInfo ObjectTypeIndex = {};
        TypeFieldInfo EprocessPcb = {};
        TypeFieldInfo EprocessThreadListHead = {};
        TypeFieldInfo KprocessThreadListHead = {};
        TypeFieldInfo EthreadTcb = {};
        TypeFieldInfo EthreadUniqueThread = {};
        TypeFieldInfo EthreadUniqueProcess = {};
        TypeFieldInfo EthreadCreateTime = {};
        TypeFieldInfo EthreadExitTime = {};
        TypeFieldInfo EthreadTerminated = {};
        TypeFieldInfo EthreadThreadListEntry = {};
        TypeFieldInfo KthreadProcess = {};
        TypeFieldInfo KthreadThreadListEntry = {};
        uint64_t ObHeaderCookieAddress = 0;
        uint64_t ObTypeIndexTableAddress = 0;
        uint64_t PsProcessTypeAddress = 0;
        uint64_t PsThreadTypeAddress = 0;
    };

    struct CidDirectEnumerationResult
    {
        bool Complete = false;
        bool Stable = false;
        CidTableSnapshot Snapshot = {};
        uint64_t NonEmptyEntryCount = 0;
        uint64_t UnclassifiedEntryCount = 0;
        uint64_t ReadFailureCount = 0;
        std::map<uint32_t, CidDirectProcess> Processes;
        std::map<uint32_t, CidDirectThread> Threads;
        std::wstring Summary;
    };

    struct CidProcessEnumerationResult
    {
        bool Complete = false;
        bool AnchorResolved = false;
        bool Stable = false;
        CidTableSnapshot Snapshot = {};
        uint64_t ProbeCount = 0;
        uint64_t ProcessCount = 0;
        uint64_t DiscoveredProcessCount = 0;
        uint64_t ProbeFailureCount = 0;
        uint64_t MembershipIncompleteCount = 0;
        std::wstring Summary;
    };

    bool ExtractCidAnchorReferences(
        uint64_t functionAddress,
        const std::vector<uint8_t>& code,
        CidAnchorReferenceSet* references)
    {
        bool ok = false;

        do
        {
            if (references == nullptr ||
                !IsKernelAddress(functionAddress) ||
                code.empty())
            {
                break;
            }

            *references = {};
            size_t offset = 0;
            uint64_t pc = functionAddress;
            while (offset < code.size() &&
                   references->InstructionsDecoded <
                       kCidAnchorMaxInstructions)
            {
                ZydisDisassembledInstruction instruction = {};
                const ZyanStatus status =
                    ZydisDisassembleIntel(
                        ZYDIS_MACHINE_MODE_LONG_64,
                        pc,
                        code.data() + offset,
                        code.size() - offset,
                        &instruction);
                if (!ZYAN_SUCCESS(status) ||
                    instruction.info.length == 0 ||
                    instruction.info.length > 15 ||
                    offset + instruction.info.length >
                        code.size())
                {
                    break;
                }

                ++references->InstructionsDecoded;
                if (instruction.info.mnemonic ==
                        ZYDIS_MNEMONIC_MOV &&
                    instruction.info.operand_count >= 2 &&
                    instruction.operands[0].type ==
                        ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    for (uint8_t operandIndex = 1;
                         operandIndex <
                             instruction.info.operand_count;
                         ++operandIndex)
                    {
                        const ZydisDecodedOperand& operand =
                            instruction.operands[operandIndex];
                        if (operand.type !=
                                ZYDIS_OPERAND_TYPE_MEMORY ||
                            operand.mem.base !=
                                ZYDIS_REGISTER_RIP ||
                            !operand.mem.disp.has_displacement ||
                            operand.size != 64)
                        {
                            continue;
                        }

                        const int64_t displacement =
                            operand.mem.disp.value;
                        const uint64_t target =
                            pc +
                            instruction.info.length +
                            static_cast<uint64_t>(
                                displacement);
                        if (IsKernelAddress(target))
                        {
                            ++references->
                                RipRelativeQwordLoads[
                                    target];
                        }
                    }
                }

                const ZydisMnemonic mnemonic =
                    instruction.info.mnemonic;
                offset += instruction.info.length;
                pc += instruction.info.length;
                if (mnemonic == ZYDIS_MNEMONIC_RET)
                {
                    references->ReachedReturn = true;
                    break;
                }
                if (mnemonic == ZYDIS_MNEMONIC_UD2 ||
                    mnemonic == ZYDIS_MNEMONIC_HLT)
                {
                    break;
                }
            }

            ok =
                references->ReachedReturn &&
                references->InstructionsDecoded != 0;
        } while (false);

        return ok;
    }

    bool AddressInsideKernelModule(
        const std::vector<KernelModuleInfo>& modules,
        uint64_t address,
        const std::wstring& requiredLeaf)
    {
        bool inside = false;
        const std::wstring loweredRequired =
            HuntToLower(requiredLeaf);

        for (const KernelModuleInfo& module : modules)
        {
            if (module.Base == 0 || module.Size == 0)
            {
                continue;
            }

            const std::wstring leaf =
                HuntToLower(LeafName(module.ImageName));
            const bool kernelAlias =
                loweredRequired == L"ntoskrnl.exe" &&
                (leaf == L"ntoskrnl.exe" ||
                 leaf == L"ntkrnlmp.exe" ||
                 leaf == L"ntkrnlpa.exe" ||
                 leaf == L"ntkrpamp.exe");
            if (!loweredRequired.empty() &&
                leaf != loweredRequired &&
                !kernelAlias)
            {
                continue;
            }

            uint64_t end = 0;
            if (TryAdd(module.Base, module.Size, &end) &&
                address >= module.Base &&
                address < end)
            {
                inside = true;
                break;
            }
        }

        return inside;
    }

    bool ResolveCidTableLayout(
        SymbolEngine& symbols,
        CidTableLayout* layout,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: invalid layout output";
                }
                break;
            }

            *layout = {};
            std::wstring error;
            if (!symbols.FindField(
                    L"nt!_HANDLE_TABLE",
                    L"NextHandleNeedingPool",
                    &layout->NextHandleNeedingPool,
                    &error) ||
                !symbols.FindField(
                    L"nt!_HANDLE_TABLE",
                    L"TableCode",
                    &layout->TableCode,
                    &error))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: _HANDLE_TABLE fields unavailable: " +
                        error;
                }
                break;
            }

            TypeLayoutInfo entryLayout = {};
            if (!symbols.GetTypeLayout(
                    L"nt!_HANDLE_TABLE_ENTRY",
                    &entryLayout,
                    &error))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: _HANDLE_TABLE_ENTRY unavailable: " +
                        error;
                }
                break;
            }

            if (layout->NextHandleNeedingPool.Offset >
                    0x1000 ||
                FieldStorageWidth(
                    layout->NextHandleNeedingPool,
                    sizeof(uint32_t)) !=
                    sizeof(uint32_t) ||
                layout->TableCode.Offset > 0x1000 ||
                FieldStorageWidth(
                    layout->TableCode,
                    sizeof(uint64_t)) !=
                    sizeof(uint64_t) ||
                entryLayout.Size < 8 ||
                entryLayout.Size > 64 ||
                (kPageSize % entryLayout.Size) != 0)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: handle-table layout is outside bounded x64 expectations";
                }
                break;
            }

            layout->EntrySize = entryLayout.Size;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadCidPointerPage(
        DeviceClient& device,
        uint64_t address,
        std::vector<uint64_t>* pointers)
    {
        if (pointers == nullptr ||
            !IsKernelAddress(address) ||
            (address & (kPageSize - 1)) != 0)
        {
            return false;
        }

        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(
                device,
                address,
                static_cast<uint32_t>(kPageSize),
                &bytes,
                nullptr) ||
            bytes.size() != kPageSize)
        {
            return false;
        }

        pointers->assign(
            kPageSize / sizeof(uint64_t),
            0);
        for (size_t index = 0;
             index < pointers->size();
             ++index)
        {
            std::memcpy(
                &(*pointers)[index],
                bytes.data() +
                    index * sizeof(uint64_t),
                sizeof(uint64_t));
        }
        return true;
    }

    bool CollectContiguousCidPointerPrefix(
        const std::vector<uint64_t>& pointers,
        std::vector<uint64_t>* allocated)
    {
        if (allocated == nullptr)
        {
            return false;
        }

        allocated->clear();
        bool sawZero = false;
        for (uint64_t pointer : pointers)
        {
            if (pointer == 0)
            {
                sawZero = true;
                continue;
            }
            if (sawZero)
            {
                allocated->clear();
                return false;
            }
            allocated->push_back(pointer);
        }
        return !allocated->empty();
    }

    bool ResolveCidAllocatedLeafPages(
        DeviceClient& device,
        uint64_t tableBase,
        uint32_t tableLevel,
        uint64_t entrySize,
        std::vector<uint64_t>* leafPages,
        uint64_t* handleCapacity,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (leafPages == nullptr ||
                handleCapacity == nullptr ||
                !IsKernelAddress(tableBase) ||
                (tableBase & (kPageSize - 1)) != 0 ||
                entrySize == 0 ||
                (kPageSize % entrySize) != 0 ||
                tableLevel > 2)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: invalid handle-table allocation topology input";
                }
                break;
            }

            leafPages->clear();
            *handleCapacity = 0;
            const uint64_t leafEntries =
                kPageSize / entrySize;
            const uint64_t maxLeafPages =
                kMaxCidProcessProbeCount /
                leafEntries;
            if (maxLeafPages == 0)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: handle-table entry geometry exceeds probe budget";
                }
                break;
            }

            std::set<uint64_t> allocatedPages;
            allocatedPages.insert(tableBase);
            auto appendLeaf =
                [&](uint64_t page) -> bool
                {
                    if (!IsKernelAddress(page) ||
                        (page & (kPageSize - 1)) != 0 ||
                        leafPages->size() >=
                            maxLeafPages ||
                        !allocatedPages.insert(page).
                            second)
                    {
                        return false;
                    }
                    leafPages->push_back(page);
                    return true;
                };

            if (tableLevel == 0)
            {
                leafPages->push_back(tableBase);
            }
            else
            {
                std::vector<uint64_t> rootPointers;
                if (!ReadCidPointerPage(
                        device,
                        tableBase,
                        &rootPointers))
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"cid full enumeration: root pointer page is unreadable";
                    }
                    break;
                }

                std::vector<uint64_t>
                    rootAllocated;
                if (!CollectContiguousCidPointerPrefix(
                        rootPointers,
                        &rootAllocated))
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"cid full enumeration: empty or non-contiguous root allocation topology";
                    }
                    break;
                }

                if (tableLevel == 1)
                {
                    bool childrenValid = true;
                    for (size_t index = 0;
                         index < rootAllocated.size();
                         ++index)
                    {
                        if (!appendLeaf(
                                rootAllocated[index]))
                        {
                            childrenValid = false;
                            break;
                        }
                    }
                    if (!childrenValid)
                    {
                        if (warning != nullptr)
                        {
                            *warning =
                                L"cid full enumeration: invalid or over-budget leaf allocation topology";
                        }
                        break;
                    }
                }
                else
                {
                    bool topologyValid = true;
                    for (size_t rootIndex = 0;
                         rootIndex <
                                 rootAllocated.size() &&
                         topologyValid;
                         ++rootIndex)
                    {
                        const uint64_t middlePage =
                            rootAllocated[rootIndex];
                        if (!IsKernelAddress(
                                middlePage) ||
                            (middlePage &
                             (kPageSize - 1)) != 0 ||
                            !allocatedPages.insert(
                                middlePage).second)
                        {
                            topologyValid = false;
                            break;
                        }

                        std::vector<uint64_t>
                            middlePointers;
                        if (!ReadCidPointerPage(
                                device,
                                middlePage,
                                &middlePointers))
                        {
                            topologyValid = false;
                            break;
                        }

                        std::vector<uint64_t>
                            middleAllocated;
                        if (!CollectContiguousCidPointerPrefix(
                                middlePointers,
                                &middleAllocated) ||
                            (rootIndex + 1 <
                                 rootAllocated.size() &&
                             middleAllocated.size() !=
                                 middlePointers.size()))
                        {
                            topologyValid = false;
                            break;
                        }

                        for (size_t middleIndex = 0;
                             middleIndex <
                                 middleAllocated.size();
                             ++middleIndex)
                        {
                            if (!appendLeaf(
                                    middleAllocated[
                                        middleIndex]))
                            {
                                topologyValid =
                                    false;
                                break;
                            }
                        }
                    }
                    if (!topologyValid)
                    {
                        if (warning != nullptr)
                        {
                            *warning =
                                L"cid full enumeration: invalid, sparse, duplicate, unreadable, or over-budget level-2 allocation topology";
                        }
                        break;
                    }
                }
            }

            if (leafPages->empty() ||
                leafPages->size() >
                    std::numeric_limits<uint32_t>::max() ||
                leafEntries >
                    std::numeric_limits<uint64_t>::max() /
                        leafPages->size() /
                        4ull)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: allocated leaf capacity overflow";
                }
                break;
            }

            *handleCapacity =
                leafPages->size() *
                leafEntries *
                4ull;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadCidTableSnapshot(
        DeviceClient& device,
        const CidTableLayout& layout,
        uint64_t anchorAddress,
        uint32_t highestKnownPid,
        CidTableSnapshot* snapshot,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (snapshot == nullptr ||
                !IsKernelAddress(anchorAddress))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: invalid anchor candidate";
                }
                break;
            }

            *snapshot = {};
            snapshot->AnchorAddress = anchorAddress;
            if (!ReadKernelPointer(
                    device,
                    anchorAddress,
                    &snapshot->TableAddress,
                    nullptr) ||
                !IsKernelAddress(snapshot->TableAddress))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: candidate does not reference a kernel handle table";
                }
                break;
            }

            uint64_t nextAddress = 0;
            uint64_t tableCodeAddress = 0;
            uint64_t nextHandle = 0;
            if (!TryAdd(
                    snapshot->TableAddress,
                    layout.NextHandleNeedingPool.Offset,
                    &nextAddress) ||
                !TryAdd(
                    snapshot->TableAddress,
                    layout.TableCode.Offset,
                    &tableCodeAddress) ||
                !ReadKernelInteger(
                    device,
                    nextAddress,
                    sizeof(uint32_t),
                    &nextHandle,
                    nullptr) ||
                !ReadKernelInteger(
                    device,
                    tableCodeAddress,
                    sizeof(uint64_t),
                    &snapshot->TableCode,
                    nullptr))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: handle-table metadata read failed";
                }
                break;
            }

            if (nextHandle > std::numeric_limits<uint32_t>::max())
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: NextHandleNeedingPool overflow";
                }
                break;
            }
            snapshot->NextHandle =
                static_cast<uint32_t>(nextHandle);
            snapshot->TableLevel =
                static_cast<uint32_t>(
                    snapshot->TableCode & 0x3ull);

            const uint64_t tableBase =
                snapshot->TableCode & ~0x7ull;
            const uint64_t probeCount =
                snapshot->NextHandle / 4u;
            if (snapshot->NextHandle < 8 ||
                (snapshot->NextHandle & 0x3u) != 0 ||
                probeCount > kMaxCidProcessProbeCount ||
                highestKnownPid >= snapshot->NextHandle ||
                (snapshot->TableCode & 0x7ull) > 2 ||
                !IsKernelAddress(tableBase) ||
                (tableBase & (kPageSize - 1)) != 0)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: candidate metadata failed bounds, level, or known-PID validation";
                }
                break;
            }

            if (!ResolveCidAllocatedLeafPages(
                    device,
                    tableBase,
                    snapshot->TableLevel,
                    layout.EntrySize,
                    &snapshot->LeafPages,
                    &snapshot->
                        AllocatedHandleCapacity,
                    warning))
            {
                break;
            }
            snapshot->AllocatedLeafCount =
                static_cast<uint32_t>(
                    snapshot->LeafPages.size());
            if (snapshot->
                    AllocatedHandleCapacity !=
                snapshot->NextHandle)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: NextHandleNeedingPool disagrees with the independently walked allocated-leaf capacity";
                }
                break;
            }

            const uint64_t leafEntries =
                kPageSize / layout.EntrySize;
            const uint64_t pointerEntries =
                kPageSize / sizeof(uint64_t);
            const uint64_t levelZeroCapacity =
                leafEntries * 4ull;
            const uint64_t levelOneCapacity =
                leafEntries * pointerEntries * 4ull;
            if ((snapshot->TableLevel == 0 &&
                 snapshot->NextHandle >
                     levelZeroCapacity) ||
                (snapshot->TableLevel == 1 &&
                 snapshot->NextHandle >
                     levelOneCapacity))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: table level cannot cover NextHandleNeedingPool";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveCidTableAnchor(
        DeviceClient& device,
        SymbolEngine& symbols,
        const CidTableLayout& layout,
        uint32_t highestKnownPid,
        CidTableSnapshot* snapshot,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (snapshot == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: invalid anchor snapshot output";
                }
                break;
            }

            std::set<uint64_t> directCandidates;
            uint64_t directSymbol = 0;
            if (symbols.ResolveSymbol(
                    L"nt!PspCidTable",
                    &directSymbol,
                    nullptr) &&
                IsKernelAddress(directSymbol))
            {
                directCandidates.insert(directSymbol);
            }

            uint64_t processLookup = 0;
            uint64_t threadLookup = 0;
            std::set<uint64_t> codeCandidates;
            if (symbols.ResolveSymbol(
                    L"nt!PsLookupProcessByProcessId",
                    &processLookup,
                    nullptr) &&
                symbols.ResolveSymbol(
                    L"nt!PsLookupThreadByThreadId",
                    &threadLookup,
                    nullptr))
            {
                std::vector<uint8_t> processCode;
                std::vector<uint8_t> threadCode;
                CidAnchorReferenceSet processReferences = {};
                CidAnchorReferenceSet threadReferences = {};
                if (ReadKernelBytes(
                        device,
                        processLookup,
                        kCidAnchorCodeBytes,
                        &processCode,
                        nullptr) &&
                    ReadKernelBytes(
                        device,
                        threadLookup,
                        kCidAnchorCodeBytes,
                        &threadCode,
                        nullptr) &&
                    ExtractCidAnchorReferences(
                        processLookup,
                        processCode,
                        &processReferences) &&
                    ExtractCidAnchorReferences(
                        threadLookup,
                        threadCode,
                        &threadReferences))
                {
                    for (const auto& processReference :
                         processReferences.RipRelativeQwordLoads)
                    {
                        const auto threadReference =
                            threadReferences.
                                RipRelativeQwordLoads.find(
                                    processReference.first);
                        if (processReference.second >= 2 &&
                            threadReference !=
                                threadReferences.
                                    RipRelativeQwordLoads.end() &&
                            threadReference->second >= 2)
                        {
                            codeCandidates.insert(
                                processReference.first);
                        }
                    }
                }
            }

            if (!directCandidates.empty() &&
                !codeCandidates.empty() &&
                directCandidates != codeCandidates)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: direct symbol and dual-function anchor disagree";
                }
                break;
            }

            std::set<uint64_t> candidates =
                !codeCandidates.empty()
                    ? codeCandidates
                    : directCandidates;
            std::vector<CidTableSnapshot> valid;
            for (uint64_t candidate : candidates)
            {
                if (!AddressInsideKernelModule(
                        symbols.Modules(),
                        candidate,
                        L"ntoskrnl.exe"))
                {
                    continue;
                }

                CidTableSnapshot candidateSnapshot = {};
                if (ReadCidTableSnapshot(
                        device,
                        layout,
                        candidate,
                        highestKnownPid,
                        &candidateSnapshot,
                        nullptr))
                {
                    valid.push_back(candidateSnapshot);
                }
            }

            if (valid.size() != 1)
            {
                if (warning != nullptr)
                {
                    *warning =
                        valid.empty()
                            ? L"cid full enumeration: no validated PspCidTable anchor"
                            : L"cid full enumeration: multiple validated PspCidTable anchors";
                }
                break;
            }

            *snapshot = valid.front();
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadCidProcessField(
        DeviceClient& device,
        uint64_t eprocess,
        const TypeFieldInfo& field,
        size_t fallbackWidth,
        uint64_t* value)
    {
        uint64_t address = 0;
        return
            TryAdd(eprocess, field.Offset, &address) &&
            ReadKernelInteger(
                device,
                address,
                FieldStorageWidth(
                    field,
                    fallbackWidth),
                value,
                nullptr);
    }

    std::wstring ReadCidProcessImageName(
        DeviceClient& device,
        uint64_t eprocess,
        const TypeFieldInfo& field)
    {
        std::wstring image;
        uint64_t address = 0;
        size_t length =
            field.Length == 0 ||
                    field.Length >
                        kEprocessImageNameMaxChars
                ? kEprocessImageNameMaxChars
                : static_cast<size_t>(field.Length);
        std::vector<uint8_t> bytes;
        if (!TryAdd(eprocess, field.Offset, &address) ||
            !ReadKernelBytes(
                device,
                address,
                static_cast<uint32_t>(length),
                &bytes,
                nullptr))
        {
            return image;
        }

        for (uint8_t value : bytes)
        {
            if (value == 0)
            {
                break;
            }
            if (value < 0x20 || value > 0x7e)
            {
                image.clear();
                break;
            }
            image.push_back(
                static_cast<wchar_t>(value));
        }
        return image;
    }

    bool ResolveCidEprocessLayout(
        SymbolEngine& symbols,
        CidEprocessLayout* layout,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: invalid EPROCESS layout output";
                }
                break;
            }

            *layout = {};
            std::wstring error;
            if (!(symbols.FindField(
                      L"nt!_EPROCESS",
                      L"UniqueProcessId",
                      &layout->UniqueProcessId,
                      &error) ||
                  FindFieldRecursive(
                      symbols,
                      {L"nt!_EPROCESS",
                       L"_EPROCESS"},
                      L"UniqueProcessId",
                      &layout->UniqueProcessId)) ||
                !(symbols.FindField(
                      L"nt!_EPROCESS",
                      L"CreateTime",
                      &layout->CreateTime,
                      &error) ||
                  FindFieldRecursive(
                      symbols,
                      {L"nt!_EPROCESS",
                       L"_EPROCESS"},
                      L"CreateTime",
                      &layout->CreateTime)))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: required EPROCESS identity fields unavailable: " +
                        error;
                }
                break;
            }

            if (layout->UniqueProcessId.Offset >
                    0x4000 ||
                layout->CreateTime.Offset >
                    0x4000 ||
                FieldStorageWidth(
                    layout->UniqueProcessId,
                    sizeof(uint64_t)) >
                    sizeof(uint64_t) ||
                FieldStorageWidth(
                    layout->CreateTime,
                    sizeof(uint64_t)) !=
                    sizeof(uint64_t))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: EPROCESS identity layout is outside bounded expectations";
                }
                break;
            }

            layout->HasImageFileName =
                symbols.FindField(
                    L"nt!_EPROCESS",
                    L"ImageFileName",
                    &layout->ImageFileName,
                    nullptr) ||
                FindFieldRecursive(
                    symbols,
                    {L"nt!_EPROCESS",
                     L"_EPROCESS"},
                    L"ImageFileName",
                    &layout->ImageFileName);
            layout->HasExitTime =
                symbols.FindField(
                    L"nt!_EPROCESS",
                    L"ExitTime",
                    &layout->ExitTime,
                    nullptr) ||
                FindFieldRecursive(
                    symbols,
                    {L"nt!_EPROCESS",
                     L"_EPROCESS"},
                    L"ExitTime",
                    &layout->ExitTime);
            layout->HasActiveThreads =
                symbols.FindField(
                    L"nt!_EPROCESS",
                    L"ActiveThreads",
                    &layout->ActiveThreads,
                    nullptr) ||
                FindFieldRecursive(
                    symbols,
                    {L"nt!_EPROCESS",
                     L"_EPROCESS"},
                    L"ActiveThreads",
                    &layout->ActiveThreads);
            layout->HasPeb =
                symbols.FindField(
                    L"nt!_EPROCESS",
                    L"Peb",
                    &layout->Peb,
                    nullptr) ||
                FindFieldRecursive(
                    symbols,
                    {L"nt!_EPROCESS",
                     L"_EPROCESS"},
                     L"Peb",
                     &layout->Peb);

            if (!layout->HasExitTime ||
                !layout->HasActiveThreads ||
                layout->ExitTime.Offset >
                    0x4000 ||
                layout->ActiveThreads.Offset >
                    0x4000 ||
                FieldStorageWidth(
                    layout->ExitTime,
                    sizeof(uint64_t)) !=
                    sizeof(uint64_t) ||
                FieldStorageWidth(
                    layout->ActiveThreads,
                    sizeof(uint32_t)) !=
                    sizeof(uint32_t))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid full enumeration: required EPROCESS lifecycle fields are unavailable or outside bounded expectations";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CaptureCidEnumeratedProcess(
        DeviceClient& device,
        const CidEprocessLayout& layout,
        uint32_t processId,
        const ProcessAddressContext& context,
        CidEnumeratedProcess* process)
    {
        bool ok = false;

        do
        {
            if (process == nullptr ||
                processId == 0 ||
                context.ProcessId != processId ||
                !IsKernelAddress(context.Eprocess) ||
                context.DirectoryTableBase == 0)
            {
                break;
            }

            *process = {};
            process->Context = context;

            uint64_t kernelProcessId = 0;
            if (!ReadCidProcessField(
                    device,
                    context.Eprocess,
                    layout.UniqueProcessId,
                    sizeof(uint64_t),
                    &kernelProcessId) ||
                kernelProcessId != processId)
            {
                break;
            }

            process->HasCreateTime =
                ReadCidProcessField(
                    device,
                    context.Eprocess,
                    layout.CreateTime,
                    sizeof(uint64_t),
                    &process->CreateTime);
            if (!process->HasCreateTime ||
                (processId > 4 &&
                 process->CreateTime == 0))
            {
                break;
            }

            if (layout.HasImageFileName &&
                layout.ImageFileName.Offset <=
                    0x4000)
            {
                process->ImageName =
                    ReadCidProcessImageName(
                        device,
                        context.Eprocess,
                        layout.ImageFileName);
            }
            if (layout.HasExitTime &&
                layout.ExitTime.Offset <= 0x4000)
            {
                process->HasExitTime =
                    ReadCidProcessField(
                        device,
                        context.Eprocess,
                        layout.ExitTime,
                        sizeof(uint64_t),
                        &process->ExitTime);
            }
            if (layout.HasActiveThreads &&
                layout.ActiveThreads.Offset <=
                    0x4000)
            {
                uint64_t activeThreads = 0;
                process->HasActiveThreads =
                    ReadCidProcessField(
                        device,
                        context.Eprocess,
                        layout.ActiveThreads,
                        sizeof(uint32_t),
                        &activeThreads);
                if (process->HasActiveThreads)
                {
                    process->ActiveThreads =
                        static_cast<uint32_t>(
                            activeThreads);
                }
            }
            if (layout.HasPeb &&
                layout.Peb.Offset <= 0x4000)
            {
                process->HasPeb =
                    ReadCidProcessField(
                        device,
                        context.Eprocess,
                        layout.Peb,
                        sizeof(uint64_t),
                    &process->Peb);
            }

            if (!process->HasExitTime ||
                !process->HasActiveThreads)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CidTableSnapshotsEqual(
        const CidTableSnapshot& left,
        const CidTableSnapshot& right)
    {
        return
            left.AnchorAddress == right.AnchorAddress &&
            left.TableAddress == right.TableAddress &&
            left.TableCode == right.TableCode &&
            left.TableLevel == right.TableLevel &&
            left.NextHandle == right.NextHandle &&
            left.AllocatedLeafCount ==
                right.AllocatedLeafCount &&
            left.AllocatedHandleCapacity ==
                right.AllocatedHandleCapacity &&
            left.LeafPages == right.LeafPages;
    }

    bool ResolveCidDirectLayout(
        SymbolEngine& symbols,
        CidDirectLayout* layout,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (layout == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct enumeration: invalid layout output";
                }
                break;
            }

            *layout = {};
            std::wstring error;
            if (!symbols.FindField(
                    L"nt!_HANDLE_TABLE_ENTRY",
                    L"ObjectPointerBits",
                    &layout->ObjectPointerBits,
                    &error) ||
                !symbols.FindField(
                    L"nt!_OBJECT_HEADER",
                    L"TypeIndex",
                    &layout->ObjectHeaderTypeIndex,
                    &error) ||
                !symbols.FindField(
                    L"nt!_OBJECT_HEADER",
                    L"Body",
                    &layout->ObjectHeaderBody,
                    &error) ||
                !symbols.FindField(
                    L"nt!_OBJECT_TYPE",
                    L"Index",
                    &layout->ObjectTypeIndex,
                    &error) ||
                !symbols.FindField(
                    L"nt!_EPROCESS",
                    L"Pcb",
                    &layout->EprocessPcb,
                    &error) ||
                !symbols.FindField(
                    L"nt!_EPROCESS",
                    L"ThreadListHead",
                    &layout->EprocessThreadListHead,
                    &error) ||
                !symbols.FindField(
                    L"nt!_KPROCESS",
                    L"ThreadListHead",
                    &layout->KprocessThreadListHead,
                    &error) ||
                !symbols.FindField(
                    L"nt!_ETHREAD",
                    L"Tcb",
                    &layout->EthreadTcb,
                    &error) ||
                !FindFieldRecursive(
                    symbols,
                    {L"nt!_ETHREAD", L"_ETHREAD"},
                    L"UniqueThread",
                    &layout->EthreadUniqueThread) ||
                !FindFieldRecursive(
                    symbols,
                    {L"nt!_ETHREAD", L"_ETHREAD"},
                    L"UniqueProcess",
                    &layout->EthreadUniqueProcess) ||
                !symbols.FindField(
                    L"nt!_ETHREAD",
                    L"CreateTime",
                    &layout->EthreadCreateTime,
                    &error) ||
                !symbols.FindField(
                    L"nt!_ETHREAD",
                    L"ExitTime",
                    &layout->EthreadExitTime,
                    &error) ||
                !symbols.FindField(
                    L"nt!_ETHREAD",
                    L"Terminated",
                    &layout->EthreadTerminated,
                    &error) ||
                !symbols.FindField(
                    L"nt!_ETHREAD",
                    L"ThreadListEntry",
                    &layout->EthreadThreadListEntry,
                    &error) ||
                !symbols.FindField(
                    L"nt!_KTHREAD",
                    L"Process",
                    &layout->KthreadProcess,
                    &error) ||
                !symbols.FindField(
                    L"nt!_KTHREAD",
                    L"ThreadListEntry",
                    &layout->KthreadThreadListEntry,
                    &error) ||
                !symbols.ResolveSymbol(
                    L"nt!ObHeaderCookie",
                    &layout->ObHeaderCookieAddress,
                    &error) ||
                !symbols.ResolveSymbol(
                    L"nt!ObTypeIndexTable",
                    &layout->ObTypeIndexTableAddress,
                    &error) ||
                !symbols.ResolveSymbol(
                    L"nt!PsProcessType",
                    &layout->PsProcessTypeAddress,
                    &error) ||
                !symbols.ResolveSymbol(
                    L"nt!PsThreadType",
                    &layout->PsThreadTypeAddress,
                    &error))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct enumeration: required PDB field or object-type symbol unavailable: " +
                        error;
                }
                break;
            }

            const TypeFieldInfo* boundedFields[] = {
                &layout->ObjectHeaderTypeIndex,
                &layout->ObjectHeaderBody,
                &layout->ObjectTypeIndex,
                &layout->EprocessThreadListHead,
                &layout->KprocessThreadListHead,
                &layout->EthreadUniqueThread,
                &layout->EthreadUniqueProcess,
                &layout->EthreadCreateTime,
                &layout->EthreadExitTime,
                &layout->EthreadTerminated,
                &layout->EthreadThreadListEntry,
                &layout->KthreadProcess,
                &layout->KthreadThreadListEntry
            };
            bool fieldsBounded = true;
            for (const TypeFieldInfo* field :
                 boundedFields)
            {
                if (field == nullptr ||
                    field->Offset > 0x4000)
                {
                    fieldsBounded = false;
                    break;
                }
            }

            if (!layout->ObjectPointerBits.IsBitField ||
                layout->ObjectPointerBits.Length != 44 ||
                layout->ObjectPointerBits.BitPosition >
                    64 -
                        layout->ObjectPointerBits.Length ||
                layout->ObjectHeaderBody.Offset < 0x20 ||
                layout->ObjectHeaderBody.Offset > 0x100 ||
                (layout->ObjectHeaderBody.Offset &
                 0xfull) != 0 ||
                layout->EprocessPcb.Offset != 0 ||
                layout->EthreadTcb.Offset != 0 ||
                !layout->EthreadTerminated.IsBitField ||
                layout->EthreadTerminated.Length != 1 ||
                !fieldsBounded ||
                !IsKernelAddress(
                    layout->ObHeaderCookieAddress) ||
                !IsKernelAddress(
                    layout->ObTypeIndexTableAddress) ||
                !IsKernelAddress(
                    layout->PsProcessTypeAddress) ||
                !IsKernelAddress(
                    layout->PsThreadTypeAddress))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct enumeration: PDB geometry is outside bounded x64 object expectations";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool DecodeCidObjectAddresses(
        uint64_t objectPointerBits,
        uint64_t objectHeaderBodyOffset,
        uint64_t* objectHeader,
        uint64_t* objectBody)
    {
        if (objectHeader == nullptr ||
            objectBody == nullptr ||
            objectPointerBits == 0 ||
            objectPointerBits >= (1ull << 44) ||
            objectHeaderBodyOffset < 0x10 ||
            objectHeaderBodyOffset > 0x100 ||
            (objectHeaderBodyOffset & 0xfull) != 0)
        {
            return false;
        }

        uint64_t body = objectPointerBits << 4;
        if ((body & (1ull << 47)) != 0)
        {
            body |= 0xffff000000000000ull;
        }
        if (!IsKernelAddress(body) ||
            (body & 0xfull) != 0 ||
            body < objectHeaderBodyOffset)
        {
            return false;
        }

        const uint64_t header =
            body - objectHeaderBodyOffset;
        if (!IsKernelAddress(header) ||
            (header & 0xfull) != 0)
        {
            return false;
        }

        *objectHeader = header;
        *objectBody = body;
        return true;
    }

    bool ExtractCidObjectPointerBits(
        const std::vector<uint8_t>& page,
        uint64_t entrySize,
        uint64_t entryIndex,
        const TypeFieldInfo& field,
        uint64_t* objectPointerBits)
    {
        if (objectPointerBits == nullptr ||
            entrySize == 0 ||
            entryIndex >= kPageSize / entrySize ||
            !field.IsBitField ||
            field.Length == 0 ||
            field.Length > 64 ||
            field.BitPosition >= 64 ||
            field.Length >
                64 - field.BitPosition)
        {
            return false;
        }

        const size_t width =
            FieldStorageWidth(field, sizeof(uint64_t));
        const uint64_t entryOffset =
            entryIndex * entrySize;
        const uint64_t fieldOffset =
            entryOffset + field.Offset;
        if (width == 0 ||
            width > sizeof(uint64_t) ||
            fieldOffset > page.size() ||
            width > page.size() - fieldOffset)
        {
            return false;
        }

        uint64_t raw = DecodeInteger(
            page.data() +
                static_cast<size_t>(fieldOffset),
            width);
        const uint64_t mask =
            field.Length == 64
                ? std::numeric_limits<uint64_t>::max()
                : ((1ull << field.Length) - 1ull);
        *objectPointerBits =
            (raw >> field.BitPosition) & mask;
        return true;
    }

    bool ReadCidPointerBitSnapshot(
        DeviceClient& device,
        const CidTableLayout& tableLayout,
        const CidDirectLayout& directLayout,
        const CidTableSnapshot& snapshot,
        std::vector<uint64_t>* pointerBits,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (pointerBits == nullptr ||
                tableLayout.EntrySize == 0 ||
                snapshot.NextHandle < 8 ||
                snapshot.LeafPages.empty())
            {
                break;
            }

            const uint64_t entriesPerLeaf =
                kPageSize / tableLayout.EntrySize;
            const uint64_t expectedEntries =
                snapshot.NextHandle / 4ull;
            if (entriesPerLeaf == 0 ||
                snapshot.LeafPages.size() >
                    std::numeric_limits<uint64_t>::max() /
                        entriesPerLeaf ||
                snapshot.LeafPages.size() *
                        entriesPerLeaf !=
                    expectedEntries)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct enumeration: leaf geometry does not cover the validated handle range";
                }
                break;
            }

            pointerBits->clear();
            pointerBits->reserve(
                static_cast<size_t>(expectedEntries));
            bool readComplete = true;
            for (uint64_t leafPage :
                 snapshot.LeafPages)
            {
                std::vector<uint8_t> page;
                if (!ReadKernelBytes(
                        device,
                        leafPage,
                        static_cast<uint32_t>(
                            kPageSize),
                        &page,
                        nullptr) ||
                    page.size() != kPageSize)
                {
                    readComplete = false;
                    break;
                }

                for (uint64_t entryIndex = 0;
                     entryIndex < entriesPerLeaf;
                     ++entryIndex)
                {
                    uint64_t bits = 0;
                    if (!ExtractCidObjectPointerBits(
                            page,
                            tableLayout.EntrySize,
                            entryIndex,
                            directLayout.
                                ObjectPointerBits,
                            &bits))
                    {
                        readComplete = false;
                        break;
                    }
                    pointerBits->push_back(bits);
                }
                if (!readComplete)
                {
                    break;
                }
            }

            if (!readComplete ||
                pointerBits->size() !=
                    expectedEntries)
            {
                pointerBits->clear();
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct enumeration: allocated entry-page read or bitfield extraction failed";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadCidEntryObjectPointerBits(
        DeviceClient& device,
        const CidTableLayout& tableLayout,
        const CidDirectLayout& directLayout,
        const CidTableSnapshot& snapshot,
        uint64_t slot,
        uint64_t* objectPointerBits)
    {
        if (objectPointerBits == nullptr ||
            tableLayout.EntrySize == 0)
        {
            return false;
        }

        const uint64_t entriesPerLeaf =
            kPageSize / tableLayout.EntrySize;
        if (entriesPerLeaf == 0)
        {
            return false;
        }
        const uint64_t leafIndex =
            slot / entriesPerLeaf;
        const uint64_t entryIndex =
            slot % entriesPerLeaf;
        if (leafIndex >= snapshot.LeafPages.size() ||
            entryIndex >
                std::numeric_limits<uint64_t>::max() /
                    tableLayout.EntrySize)
        {
            return false;
        }

        uint64_t entryAddress = 0;
        if (!TryAdd(
                snapshot.LeafPages[
                    static_cast<size_t>(leafIndex)],
                entryIndex * tableLayout.EntrySize,
                &entryAddress) ||
            !IsKernelAddress(entryAddress))
        {
            return false;
        }

        uint64_t bits = 0;
        if (!ReadFieldInteger(
                device,
                entryAddress,
                directLayout.ObjectPointerBits,
                sizeof(uint64_t),
                &bits,
                nullptr) ||
            bits >= (1ull << 44))
        {
            return false;
        }

        *objectPointerBits = bits;
        return true;
    }

    bool CidPointerSnapshotHasAllocatableSlots(
        const std::vector<uint64_t>& pointerBits)
    {
        // Handle value zero is reserved. Its table entry is also used for
        // free-list bookkeeping and is not required to contain zero object
        // bits on current kernels. Only slots 1..N map to valid CID values.
        return pointerBits.size() > 1;
    }

    enum class CidDirectObjectType
    {
        Unknown,
        Process,
        Thread
    };

    bool ResolveCidDirectObjectType(
        DeviceClient& device,
        const CidDirectLayout& layout,
        uint8_t headerCookie,
        uint64_t processType,
        uint64_t threadType,
        uint64_t objectHeader,
        CidDirectObjectType* objectType)
    {
        bool ok = false;

        do
        {
            if (objectType == nullptr ||
                !IsKernelAddress(objectHeader) ||
                !IsKernelAddress(processType) ||
                !IsKernelAddress(threadType) ||
                processType == threadType)
            {
                break;
            }
            *objectType = CidDirectObjectType::Unknown;

            uint64_t encodedTypeIndex = 0;
            if (!ReadFieldInteger(
                    device,
                    objectHeader,
                    layout.ObjectHeaderTypeIndex,
                    sizeof(uint8_t),
                    &encodedTypeIndex,
                    nullptr) ||
                encodedTypeIndex >
                    std::numeric_limits<uint8_t>::max())
            {
                break;
            }

            const uint8_t decodedTypeIndex =
                static_cast<uint8_t>(
                    encodedTypeIndex) ^
                headerCookie ^
                static_cast<uint8_t>(
                    objectHeader >> 8);
            if (decodedTypeIndex == 0)
            {
                break;
            }

            uint64_t typeEntryAddress = 0;
            uint64_t typePointer = 0;
            if (!TryAdd(
                    layout.ObTypeIndexTableAddress,
                    static_cast<uint64_t>(
                        decodedTypeIndex) *
                        sizeof(uint64_t),
                    &typeEntryAddress) ||
                !ReadKernelPointer(
                    device,
                    typeEntryAddress,
                    &typePointer,
                    nullptr) ||
                !IsKernelAddress(typePointer))
            {
                break;
            }

            uint64_t objectTypeIndex = 0;
            if (!ReadFieldInteger(
                    device,
                    typePointer,
                    layout.ObjectTypeIndex,
                    sizeof(uint8_t),
                    &objectTypeIndex,
                    nullptr) ||
                objectTypeIndex !=
                    decodedTypeIndex)
            {
                break;
            }

            if (typePointer == processType)
            {
                *objectType =
                    CidDirectObjectType::Process;
            }
            else if (typePointer == threadType)
            {
                *objectType =
                    CidDirectObjectType::Thread;
            }
            else
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CidDirectThreadIdentityFieldsPlausible(
        uint32_t expectedThreadId,
        uint64_t observedThreadId,
        uint64_t observedProcessId,
        uint64_t ownerProcess,
        uint64_t createTime,
        uint64_t terminated)
    {
        return
            observedThreadId == expectedThreadId &&
            (expectedThreadId != 0 ||
             observedProcessId == 0) &&
            observedProcessId <=
                std::numeric_limits<uint32_t>::max() &&
            IsKernelAddress(ownerProcess) &&
            (createTime != 0 || observedProcessId == 0) &&
            terminated <= 1;
    }

    uint64_t CidThreadExitTimeForState(
        uint64_t rawExitTime,
        uint64_t terminated)
    {
        return terminated != 0 ? rawExitTime : 0;
    }

    bool CaptureCidDirectThread(
        DeviceClient& device,
        const CidDirectLayout& layout,
        const CidEprocessLayout& processLayout,
        uint32_t threadId,
        uint64_t objectHeader,
        uint64_t ethread,
        CidDirectThread* thread)
    {
        bool ok = false;

        do
        {
            if (thread == nullptr ||
                (objectHeader != 0 &&
                 !IsKernelAddress(objectHeader)) ||
                !IsKernelAddress(ethread))
            {
                break;
            }
            *thread = {};

            uint64_t observedThreadId = 0;
            uint64_t observedProcessId = 0;
            uint64_t ownerProcess = 0;
            uint64_t createTime = 0;
            uint64_t exitTime = 0;
            uint64_t terminated = 0;
            if (!ReadFieldInteger(
                    device,
                    ethread,
                    layout.EthreadUniqueThread,
                    sizeof(uint64_t),
                    &observedThreadId,
                    nullptr) ||
                !ReadFieldInteger(
                    device,
                    ethread,
                    layout.EthreadUniqueProcess,
                    sizeof(uint64_t),
                    &observedProcessId,
                    nullptr) ||
                !ReadFieldInteger(
                    device,
                    ethread,
                    layout.KthreadProcess,
                    sizeof(uint64_t),
                    &ownerProcess,
                    nullptr) ||
                !ReadFieldInteger(
                    device,
                    ethread,
                    layout.EthreadCreateTime,
                    sizeof(uint64_t),
                    &createTime,
                    nullptr) ||
                !ReadFieldInteger(
                    device,
                    ethread,
                    layout.EthreadExitTime,
                    sizeof(uint64_t),
                    &exitTime,
                    nullptr) ||
                !ReadFieldInteger(
                    device,
                    ethread,
                    layout.EthreadTerminated,
                    sizeof(uint32_t),
                    &terminated,
                    nullptr) ||
                !CidDirectThreadIdentityFieldsPlausible(
                    threadId,
                    observedThreadId,
                    observedProcessId,
                    ownerProcess,
                    createTime,
                    terminated))
            {
                break;
            }

            uint64_t ownerProcessId = 0;
            if (!ReadFieldInteger(
                    device,
                    ownerProcess,
                    processLayout.UniqueProcessId,
                    sizeof(uint64_t),
                    &ownerProcessId,
                    nullptr) ||
                ownerProcessId != observedProcessId)
            {
                break;
            }

            thread->ThreadId = threadId;
            thread->ProcessId =
                static_cast<uint32_t>(
                    observedProcessId);
            thread->ObjectHeader = objectHeader;
            thread->Ethread = ethread;
            thread->Eprocess = ownerProcess;
            thread->CreateTime = createTime;
            // ETHREAD overlays ExitTime with live-thread bookkeeping on
            // current kernels. The value has exit-time semantics only after
            // the Terminated bit is set.
            thread->ExitTime =
                CidThreadExitTimeForState(
                    exitTime,
                    terminated);
            thread->HasCreateTime = true;
            thread->HasExitTime = true;
            thread->Terminated = terminated != 0;
            ok = true;
        } while (false);

        return ok;
    }

    bool CaptureCidProcessAtAddress(
        DeviceClient& device,
        const CidEprocessLayout& processLayout,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        uint32_t processId,
        uint64_t eprocess,
        CidEnumeratedProcess* process)
    {
        bool ok = false;

        do
        {
            if (process == nullptr ||
                processId == 0 ||
                directoryTableBaseOffset == 0 ||
                directoryTableBaseOffset > 0x4000 ||
                userDirectoryTableBaseOffset > 0x4000 ||
                !IsKernelAddress(eprocess))
            {
                break;
            }

            ProcessAddressContext context = {};
            context.ProcessId = processId;
            context.Eprocess = eprocess;
            uint64_t dtbAddress = 0;
            if (!TryAdd(
                    eprocess,
                    directoryTableBaseOffset,
                    &dtbAddress) ||
                !ReadKernelInteger(
                    device,
                    dtbAddress,
                    sizeof(uint64_t),
                    &context.DirectoryTableBase,
                    nullptr))
            {
                break;
            }
            context.DirectoryTableBase &=
                0x000ffffffffff000ull;
            if (context.DirectoryTableBase == 0)
            {
                break;
            }

            if (userDirectoryTableBaseOffset != 0)
            {
                uint64_t userDtbAddress = 0;
                if (!TryAdd(
                        eprocess,
                        userDirectoryTableBaseOffset,
                        &userDtbAddress) ||
                    !ReadKernelInteger(
                        device,
                        userDtbAddress,
                        sizeof(uint64_t),
                        &context.
                            UserDirectoryTableBase,
                        nullptr))
                {
                    break;
                }
                context.UserDirectoryTableBase &=
                    0x000ffffffffff000ull;
            }

            if (!CaptureCidEnumeratedProcess(
                    device,
                    processLayout,
                    processId,
                    context,
                    process))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CaptureCidDirectProcess(
        DeviceClient& device,
        const CidEprocessLayout& processLayout,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        uint32_t processId,
        uint64_t objectHeader,
        uint64_t eprocess,
        CidDirectProcess* process)
    {
        if (process == nullptr ||
            !IsKernelAddress(objectHeader))
        {
            return false;
        }

        CidEnumeratedProcess captured = {};
        if (!CaptureCidProcessAtAddress(
                device,
                processLayout,
                directoryTableBaseOffset,
                userDirectoryTableBaseOffset,
                processId,
                eprocess,
                &captured))
        {
            return false;
        }

        process->ProcessId = processId;
        process->ObjectHeader = objectHeader;
        process->Process = std::move(captured);
        return true;
    }

    bool ApplyCidTableDirectObjectView(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        uint32_t highestKnownPid,
        CidDirectEnumerationResult* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }
            *result = {};

            CidTableLayout tableLayout = {};
            if (!ResolveCidTableLayout(
                    symbols,
                    &tableLayout,
                    &result->Summary))
            {
                break;
            }

            CidEprocessLayout processLayout = {};
            if (!ResolveCidEprocessLayout(
                    symbols,
                    &processLayout,
                    &result->Summary))
            {
                break;
            }

            CidDirectLayout directLayout = {};
            if (!ResolveCidDirectLayout(
                    symbols,
                    &directLayout,
                    &result->Summary))
            {
                break;
            }
            if (directLayout.ObjectPointerBits.Offset >
                    tableLayout.EntrySize ||
                FieldStorageWidth(
                    directLayout.ObjectPointerBits,
                    sizeof(uint64_t)) >
                    tableLayout.EntrySize -
                        directLayout.
                            ObjectPointerBits.Offset)
            {
                result->Summary =
                    L"cid direct enumeration: ObjectPointerBits exceeds the PDB entry geometry";
                break;
            }

            uint64_t headerCookie = 0;
            uint64_t processType = 0;
            uint64_t threadType = 0;
            if (!ReadKernelInteger(
                    device,
                    directLayout.ObHeaderCookieAddress,
                    sizeof(uint8_t),
                    &headerCookie,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    directLayout.PsProcessTypeAddress,
                    &processType,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    directLayout.PsThreadTypeAddress,
                    &threadType,
                    nullptr) ||
                headerCookie >
                    std::numeric_limits<uint8_t>::max() ||
                !IsKernelAddress(processType) ||
                !IsKernelAddress(threadType) ||
                processType == threadType)
            {
                result->Summary =
                    L"cid direct enumeration: object-header cookie or Process/Thread object types are unavailable";
                break;
            }

            constexpr uint32_t kSnapshotAttempts = 3;
            for (uint32_t attempt = 0;
                 attempt < kSnapshotAttempts;
                 ++attempt)
            {
                result->Processes.clear();
                result->Threads.clear();
                result->NonEmptyEntryCount = 0;
                result->UnclassifiedEntryCount = 0;
                result->ReadFailureCount = 0;

                CidTableSnapshot before = {};
                if (!ResolveCidTableAnchor(
                        device,
                        symbols,
                        tableLayout,
                        highestKnownPid,
                        &before,
                        &result->Summary))
                {
                    break;
                }

                std::vector<uint64_t> firstBits;
                if (!ReadCidPointerBitSnapshot(
                        device,
                        tableLayout,
                        directLayout,
                        before,
                        &firstBits,
                        &result->Summary))
                {
                    ++result->ReadFailureCount;
                    continue;
                }

                CidTableSnapshot after = {};
                if (!ReadCidTableSnapshot(
                        device,
                        tableLayout,
                        before.AnchorAddress,
                        highestKnownPid,
                        &after,
                        nullptr) ||
                    !CidTableSnapshotsEqual(
                        before,
                        after))
                {
                    result->Summary =
                        L"cid direct enumeration: allocation topology changed during entry-page capture; retrying";
                    continue;
                }

                bool decoded =
                    CidPointerSnapshotHasAllocatableSlots(
                        firstBits);
                std::wstring decodeFailure;
                const auto setDecodeFailure =
                    [&decodeFailure](
                        uint32_t cid,
                        const std::wstring& stage,
                        uint64_t value)
                    {
                        if (!decodeFailure.empty())
                        {
                            return;
                        }
                        decodeFailure =
                            L"cid=" +
                            std::to_wstring(cid) +
                            L" stage=" + stage +
                            L" value=" +
                            HuntHex(value, 16);
                    };
                if (!decoded)
                {
                    ++result->ReadFailureCount;
                    result->Summary =
                        L"cid direct enumeration: pointer snapshot contains no allocatable CID slots";
                }
                for (size_t slot = 1;
                     decoded && slot < firstBits.size();
                     ++slot)
                {
                    const uint64_t pointerBits =
                        firstBits[slot];
                    if (pointerBits == 0)
                    {
                        continue;
                    }
                    ++result->NonEmptyEntryCount;

                    if (slot >
                        std::numeric_limits<uint32_t>::
                            max() /
                            4ull)
                    {
                        decoded = false;
                        ++result->
                            UnclassifiedEntryCount;
                        setDecodeFailure(
                            0,
                            L"slot_overflow",
                            slot);
                        break;
                    }
                    const uint32_t cid =
                        static_cast<uint32_t>(
                            slot * 4ull);

                    uint64_t objectHeader = 0;
                    uint64_t objectBody = 0;
                    CidDirectObjectType objectType =
                        CidDirectObjectType::Unknown;
                    if (!DecodeCidObjectAddresses(
                            pointerBits,
                            directLayout.
                                ObjectHeaderBody.Offset,
                            &objectHeader,
                            &objectBody))
                    {
                        decoded = false;
                        ++result->
                            UnclassifiedEntryCount;
                        setDecodeFailure(
                            cid,
                            L"pointer_decode",
                            pointerBits);
                        continue;
                    }
                    if (!ResolveCidDirectObjectType(
                            device,
                            directLayout,
                            static_cast<uint8_t>(
                                headerCookie),
                            processType,
                            threadType,
                            objectHeader,
                            &objectType))
                    {
                        decoded = false;
                        ++result->
                            UnclassifiedEntryCount;
                        setDecodeFailure(
                            cid,
                            L"object_type",
                            objectHeader);
                        continue;
                    }

                    bool objectCaptured = false;
                    if (objectType ==
                        CidDirectObjectType::Process)
                    {
                        CidDirectProcess process = {};
                        objectCaptured =
                            CaptureCidDirectProcess(
                                device,
                                processLayout,
                                directoryTableBaseOffset,
                                userDirectoryTableBaseOffset,
                                cid,
                                objectHeader,
                                objectBody,
                                &process) &&
                            result->Processes.emplace(
                                cid,
                                std::move(process)).
                                second;
                    }
                    else
                    {
                        CidDirectThread thread = {};
                        objectCaptured =
                            CaptureCidDirectThread(
                                device,
                                directLayout,
                                processLayout,
                                cid,
                                objectHeader,
                                objectBody,
                                &thread) &&
                            result->Threads.emplace(
                                cid,
                                std::move(thread)).
                                second;
                    }

                    uint64_t currentPointerBits = 0;
                    if (!objectCaptured ||
                        !ReadCidEntryObjectPointerBits(
                            device,
                            tableLayout,
                            directLayout,
                            after,
                            slot,
                            &currentPointerBits) ||
                        currentPointerBits != pointerBits)
                    {
                        if (objectType ==
                            CidDirectObjectType::Process)
                        {
                            result->Processes.erase(cid);
                        }
                        else
                        {
                            result->Threads.erase(cid);
                        }
                        decoded = false;
                        ++result->
                            UnclassifiedEntryCount;
                        setDecodeFailure(
                            cid,
                            !objectCaptured
                                ? (objectType ==
                                           CidDirectObjectType::Process
                                       ? L"process_identity_capture"
                                       : L"thread_identity_capture")
                                : L"entry_revalidation",
                            objectBody);
                    }
                }

                CidTableSnapshot verifiedAfter = {};
                if (decoded &&
                    (!ReadCidTableSnapshot(
                         device,
                         tableLayout,
                         after.AnchorAddress,
                         highestKnownPid,
                         &verifiedAfter,
                         nullptr) ||
                     !CidTableSnapshotsEqual(
                         after,
                         verifiedAfter)))
                {
                    decoded = false;
                    ++result->ReadFailureCount;
                    result->Summary =
                        L"cid direct enumeration: allocation topology changed while object bodies were being decoded; retrying";
                }

                if (!decoded ||
                    result->UnclassifiedEntryCount != 0 ||
                    result->Processes.empty() ||
                    result->Threads.empty() ||
                    result->Processes.find(4) ==
                        result->Processes.end() ||
                    result->Processes.size() +
                            result->Threads.size() !=
                        result->NonEmptyEntryCount)
                {
                    result->Summary =
                        L"cid direct enumeration: one or more stable non-empty entries could not be typed and identity-validated; retrying" +
                        (decodeFailure.empty()
                             ? L""
                             : L"; first_failure=" +
                                   decodeFailure);
                    continue;
                }

                result->Snapshot = verifiedAfter;
                result->Stable = true;
                result->Complete = true;
                result->Summary =
                    L"cid direct enumeration: entries=" +
                    std::to_wstring(
                        result->NonEmptyEntryCount) +
                    L" processes=" +
                    std::to_wstring(
                        result->Processes.size()) +
                    L" threads=" +
                    std::to_wstring(
                        result->Threads.size());
                ok = true;
                break;
            }
        } while (false);

        return ok;
    }

    bool MergeCidDirectProcessView(
        const CidDirectEnumerationResult& direct,
        std::map<uint32_t, HuntProcessRecord>* processes,
        uint64_t* discoveredProcesses,
        std::wstring* warning)
    {
        bool ok = false;

        if (discoveredProcesses != nullptr)
        {
            *discoveredProcesses = 0;
        }
        if (warning != nullptr)
        {
            warning->clear();
        }

        do
        {
            if (!direct.Complete ||
                !direct.Stable ||
                processes == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct process merge: direct entry enumeration is incomplete";
                }
                break;
            }

            // Validate every pre-existing identity before mutating any record.
            // A late mismatch must not leave an earlier PID partially merged.
            bool identitiesConsistent = true;
            for (const auto& item : direct.Processes)
            {
                const auto existing =
                    processes->find(item.first);
                if (existing == processes->end())
                {
                    continue;
                }

                const HuntProcessRecord& process =
                    existing->second;
                const CidDirectProcess& cid =
                    item.second;
                if ((process.Kernel.Eprocess != 0 &&
                     process.Kernel.Eprocess !=
                         cid.Process.Context.Eprocess) ||
                    (process.Kernel.HasCreateTime &&
                     process.Kernel.CreateTime !=
                         cid.Process.CreateTime))
                {
                    identitiesConsistent = false;
                    break;
                }
            }
            if (!identitiesConsistent)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid direct process merge: one or more seeded identities disagreed";
                }
                break;
            }

            for (const auto& item : direct.Processes)
            {
                const uint32_t processId = item.first;
                const CidDirectProcess& cid =
                    item.second;
                auto existing =
                    processes->find(processId);
                const bool discovered =
                    existing == processes->end();
                if (discovered)
                {
                    HuntProcessRecord record = {};
                    record.ProcessId = processId;
                    existing = processes->emplace(
                        processId,
                        std::move(record)).first;
                    if (discoveredProcesses != nullptr)
                    {
                        ++(*discoveredProcesses);
                    }
                }

                HuntProcessRecord& process =
                    existing->second;
                const bool lookupSeen =
                    process.CidTableSeen;

                process.ProcessId = processId;
                process.HasCidTableView = true;
                process.CidTableEnumerated = true;
                process.CidTableSeen = true;
                process.CidDirectEntrySeen = true;
                process.CidLookupDirectAgreed =
                    lookupSeen &&
                    (process.Kernel.Eprocess == 0 ||
                     process.Kernel.Eprocess ==
                         cid.Process.Context.Eprocess);
                process.CidTableDiscovered =
                    process.CidTableDiscovered ||
                    discovered;
                process.Kernel.ProcessId = processId;
                process.Kernel.Eprocess =
                    cid.Process.Context.Eprocess;
                process.Kernel.DirectoryTableBase =
                    cid.Process.Context.DirectoryTableBase;
                process.Kernel.UserDirectoryTableBase =
                    cid.Process.Context.
                        UserDirectoryTableBase;
                process.Kernel.CreateTime =
                    cid.Process.CreateTime;
                process.Kernel.HasCreateTime =
                    cid.Process.HasCreateTime;
                process.Kernel.ExitTime =
                    cid.Process.ExitTime;
                process.Kernel.HasExitTime =
                    cid.Process.HasExitTime;
                process.Kernel.ActiveThreads =
                    cid.Process.ActiveThreads;
                process.Kernel.HasActiveThreads =
                    cid.Process.HasActiveThreads;
                process.Kernel.Peb = cid.Process.Peb;
                process.Kernel.HasPeb =
                    cid.Process.HasPeb;
                if (!cid.Process.ImageName.empty())
                {
                    process.Kernel.ImageName =
                        cid.Process.ImageName;
                    process.KernelImageName =
                        cid.Process.ImageName;
                }
                if (!lookupSeen)
                {
                    AddUnique(
                        &process.Warnings,
                        L"direct typed CID entry was not returned by the exported process lookup view");
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    uint64_t MarkPostTriageProcessArrivals(
        const std::set<uint32_t>& preTriageProcessIds,
        const CidDirectEnumerationResult& direct,
        std::map<uint32_t, HuntProcessRecord>* processes)
    {
        if (processes == nullptr)
        {
            return 0;
        }

        uint64_t marked = 0;
        for (const auto& item : direct.Processes)
        {
            if (preTriageProcessIds.find(item.first) !=
                preTriageProcessIds.end())
            {
                continue;
            }
            auto late = processes->find(item.first);
            if (late == processes->end())
            {
                continue;
            }
            late->second.LifecycleChangedBeforeTriage =
                true;
            AddUnique(
                &late->second.Warnings,
                L"process appeared after the bounded per-process triage cutoff; current thread views were validated and full process triage is deferred to a subsequent hunt");
            ++marked;
        }
        return marked;
    }

    bool CidThreadIdentityEqual(
        const CidDirectThread& left,
        const CidDirectThread& right)
    {
        return
            left.ThreadId == right.ThreadId &&
            left.ProcessId == right.ProcessId &&
            left.Ethread == right.Ethread &&
            left.Eprocess == right.Eprocess &&
            left.CreateTime == right.CreateTime;
    }

    bool CidThreadMapsEqual(
        const std::map<uint32_t, CidDirectThread>& left,
        const std::map<uint32_t, CidDirectThread>& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }

        auto leftItem = left.begin();
        auto rightItem = right.begin();
        for (; leftItem != left.end();
             ++leftItem, ++rightItem)
        {
            if (leftItem->first != rightItem->first ||
                !CidThreadIdentityEqual(
                    leftItem->second,
                    rightItem->second) ||
                leftItem->second.ExitTime !=
                    rightItem->second.ExitTime ||
                leftItem->second.Terminated !=
                    rightItem->second.Terminated)
            {
                return false;
            }
        }
        return true;
    }

    bool CollectCidThreadListOnce(
        DeviceClient& device,
        const CidDirectLayout& layout,
        const CidEprocessLayout& processLayout,
        uint32_t processId,
        uint64_t eprocess,
        bool schedulerList,
        std::map<uint32_t, CidDirectThread>* threads,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (threads == nullptr ||
                !IsKernelAddress(eprocess))
            {
                break;
            }
            threads->clear();

            const uint64_t headOffset =
                schedulerList
                    ? layout.KprocessThreadListHead.Offset
                    : layout.EprocessThreadListHead.Offset;
            const uint64_t entryOffset =
                schedulerList
                    ? layout.KthreadThreadListEntry.Offset
                    : layout.EthreadThreadListEntry.Offset;
            uint64_t listHead = 0;
            if (!TryAdd(
                    eprocess,
                    headOffset,
                    &listHead) ||
                !IsKernelAddress(listHead) ||
                entryOffset > 0x4000)
            {
                break;
            }

            uint64_t headBlinkAddress = 0;
            uint64_t headFlink = 0;
            uint64_t headBlink = 0;
            if (!TryAdd(
                    listHead,
                    sizeof(uint64_t),
                    &headBlinkAddress) ||
                !ReadKernelPointer(
                    device,
                    listHead,
                    &headFlink,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    headBlinkAddress,
                    &headBlink,
                    nullptr) ||
                !IsKernelAddress(headFlink) ||
                !IsKernelAddress(headBlink))
            {
                if (warning != nullptr)
                {
                    *warning =
                        schedulerList
                            ? L"scheduler thread-list head is unreadable"
                            : L"executive thread-list head is unreadable";
                }
                break;
            }

            if ((headFlink == listHead) !=
                (headBlink == listHead))
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"thread-list empty-state links disagree";
                }
                break;
            }

            std::set<uint64_t> visited;
            uint64_t current = headFlink;
            uint64_t previous = listHead;
            bool complete = false;
            while (current != listHead &&
                   visited.size() <
                       kMaxCidProcessProbeCount)
            {
                if (!IsKernelAddress(current) ||
                    current < entryOffset ||
                    !visited.insert(current).second)
                {
                    break;
                }

                uint64_t blinkAddress = 0;
                uint64_t next = 0;
                uint64_t blink = 0;
                if (!TryAdd(
                        current,
                        sizeof(uint64_t),
                        &blinkAddress) ||
                    !ReadKernelPointer(
                        device,
                        current,
                        &next,
                        nullptr) ||
                    !ReadKernelPointer(
                        device,
                        blinkAddress,
                        &blink,
                        nullptr) ||
                    !IsKernelAddress(next) ||
                    blink != previous)
                {
                    break;
                }

                const uint64_t ethread =
                    current - entryOffset;
                uint64_t threadId = 0;
                if (!ReadFieldInteger(
                        device,
                        ethread,
                        layout.EthreadUniqueThread,
                        sizeof(uint64_t),
                        &threadId,
                        nullptr) ||
                    threadId >
                        std::numeric_limits<
                            uint32_t>::max())
                {
                    break;
                }

                CidDirectThread thread = {};
                if (!CaptureCidDirectThread(
                        device,
                        layout,
                        processLayout,
                        static_cast<uint32_t>(
                            threadId),
                        0,
                         ethread,
                         &thread) ||
                    thread.ProcessId != processId ||
                    thread.Eprocess != eprocess)
                {
                    break;
                }
                const bool reservedCidZeroThread =
                    IsReservedCidZeroThread(
                        thread.ThreadId,
                        thread.ProcessId);
                if (!reservedCidZeroThread &&
                    !threads->emplace(
                        thread.ThreadId,
                        std::move(thread)).second)
                {
                    break;
                }

                previous = current;
                current = next;
            }
            if (current == listHead &&
                previous == headBlink)
            {
                complete = true;
            }
            if (!complete)
            {
                threads->clear();
                if (warning != nullptr)
                {
                    *warning =
                        schedulerList
                            ? L"scheduler thread-list walk was cyclic, inconsistent, unreadable, or over budget"
                            : L"executive thread-list walk was cyclic, inconsistent, unreadable, or over budget";
                }
                break;
            }

            uint64_t finalFlink = 0;
            uint64_t finalBlink = 0;
            if (!ReadKernelPointer(
                    device,
                    listHead,
                    &finalFlink,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    headBlinkAddress,
                    &finalBlink,
                    nullptr) ||
                finalFlink != headFlink ||
                finalBlink != headBlink)
            {
                threads->clear();
                if (warning != nullptr)
                {
                    *warning =
                        L"thread-list head changed during walk";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CollectStableCidThreadList(
        DeviceClient& device,
        const CidDirectLayout& layout,
        const CidEprocessLayout& processLayout,
        uint32_t processId,
        uint64_t eprocess,
        bool schedulerList,
        std::map<uint32_t, CidDirectThread>* threads,
        std::wstring* warning)
    {
        if (threads == nullptr)
        {
            return false;
        }

        constexpr uint32_t kAttempts = 3;
        for (uint32_t attempt = 0;
             attempt < kAttempts;
             ++attempt)
        {
            std::map<uint32_t, CidDirectThread> first;
            std::map<uint32_t, CidDirectThread> second;
            if (CollectCidThreadListOnce(
                    device,
                    layout,
                    processLayout,
                    processId,
                    eprocess,
                    schedulerList,
                    &first,
                    nullptr) &&
                CollectCidThreadListOnce(
                    device,
                    layout,
                    processLayout,
                    processId,
                    eprocess,
                    schedulerList,
                    &second,
                    nullptr) &&
                CidThreadMapsEqual(first, second))
            {
                *threads = std::move(second);
                return true;
            }
            SwitchToThread();
        }

        threads->clear();
        if (warning != nullptr)
        {
            *warning =
                schedulerList
                    ? L"scheduler thread list did not stabilize after retries"
                    : L"executive thread list did not stabilize after retries";
        }
        return false;
    }

    struct CidThreadViewSnapshot
    {
        bool Complete = false;
        std::map<uint32_t, ApiThreadRecord>
            SystemThreads;
        std::map<uint32_t, ApiThreadRecord>
            ToolhelpThreads;
        std::map<uint32_t, CidDirectThread>
            ExecutiveThreads;
        std::map<uint32_t, CidDirectThread>
            SchedulerThreads;
        std::wstring Warning;
    };

    bool CanUseSeededProcessAsThreadOwner(
        const HuntProcessRecord& process,
        bool currentApiOwnerSeen)
    {
        return
            currentApiOwnerSeen &&
            !process.LifecycleChangedBeforeTriage &&
            !IsTerminatingProcessSnapshot(
                process.Kernel) &&
            process.Kernel.Eprocess != 0;
    }

    bool CollectCidThreadKernelViews(
        DeviceClient& device,
        const CidDirectLayout& layout,
        const CidEprocessLayout& processLayout,
        const CidDirectEnumerationResult& direct,
        const std::map<uint32_t, HuntProcessRecord>&
            processes,
        const std::set<uint32_t>& currentApiOwnerIds,
        std::map<uint32_t, CidDirectThread>*
            executiveThreads,
        std::map<uint32_t, CidDirectThread>*
            schedulerThreads,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (executiveThreads == nullptr ||
                schedulerThreads == nullptr ||
                !direct.Complete)
            {
                break;
            }
            executiveThreads->clear();
            schedulerThreads->clear();

            std::map<uint32_t, uint64_t> owners;
            bool ownersValid = true;
            bool ownersOverBudget = false;
            for (const auto& item : direct.Threads)
            {
                const CidDirectThread& thread =
                    item.second;
                if (owners.find(thread.ProcessId) ==
                        owners.end() &&
                    owners.size() >=
                        kMaxCidProcessProbeCount)
                {
                    ownersValid = false;
                    ownersOverBudget = true;
                    break;
                }
                const auto inserted = owners.emplace(
                    thread.ProcessId,
                    thread.Eprocess);
                if (!inserted.second &&
                    inserted.first->second !=
                        thread.Eprocess)
                {
                    ownersValid = false;
                    break;
                }
            }
            if (!ownersValid)
            {
                if (warning != nullptr)
                {
                    *warning =
                        ownersOverBudget
                            ? L"thread owner inventory exceeded the bounded CID/thread budget"
                            : L"thread CID owners disagree on EPROCESS identity";
                }
                break;
            }

            for (const auto& item : direct.Processes)
            {
                const uint64_t eprocess =
                    item.second.Process.Context.Eprocess;
                if ((owners.find(item.first) ==
                         owners.end() &&
                     owners.size() >=
                         kMaxCidProcessProbeCount) ||
                    !IsKernelAddress(eprocess))
                {
                    ownersValid = false;
                    ownersOverBudget =
                        owners.size() >=
                        kMaxCidProcessProbeCount;
                    break;
                }
                const auto inserted = owners.emplace(
                    item.first,
                    eprocess);
                if (!inserted.second &&
                    inserted.first->second != eprocess)
                {
                    ownersValid = false;
                    break;
                }
            }
            if (!ownersValid)
            {
                if (warning != nullptr)
                {
                    *warning =
                        ownersOverBudget
                            ? L"direct process and thread owner inventory exceeded the bounded CID/thread budget"
                            : L"direct process and thread CID owners disagree on EPROCESS identity";
                }
                break;
            }

            for (const auto& item : processes)
            {
                const HuntProcessRecord& process =
                    item.second;
                if (CanUseSeededProcessAsThreadOwner(
                        process,
                        currentApiOwnerIds.find(
                            item.first) !=
                            currentApiOwnerIds.end()))
                {
                    if (owners.find(item.first) ==
                            owners.end() &&
                        owners.size() >=
                            kMaxCidProcessProbeCount)
                    {
                        ownersValid = false;
                        ownersOverBudget = true;
                        break;
                    }
                    const auto inserted =
                        owners.emplace(
                            item.first,
                            process.Kernel.Eprocess);
                    if (!inserted.second &&
                        inserted.first->second !=
                            process.Kernel.Eprocess)
                    {
                        ownersValid = false;
                        break;
                    }
                }
            }
            if (!ownersValid || owners.empty())
            {
                if (warning != nullptr)
                {
                    *warning =
                        ownersOverBudget
                            ? L"thread owner inventory exceeded the bounded CID/thread budget"
                            : L"thread owner process identities are incomplete or inconsistent";
                }
                break;
            }

            bool listsComplete = true;
            for (const auto& owner : owners)
            {
                std::map<uint32_t, CidDirectThread>
                    executive;
                std::map<uint32_t, CidDirectThread>
                    scheduler;
                std::wstring localWarning;
                if (!CollectStableCidThreadList(
                        device,
                        layout,
                        processLayout,
                        owner.first,
                        owner.second,
                        false,
                        &executive,
                        &localWarning) ||
                    !CollectStableCidThreadList(
                        device,
                        layout,
                        processLayout,
                        owner.first,
                        owner.second,
                        true,
                        &scheduler,
                        &localWarning))
                {
                    listsComplete = false;
                    if (warning != nullptr)
                    {
                        *warning =
                            L"thread list collection failed for pid=" +
                            std::to_wstring(
                                owner.first) +
                            L": " +
                            localWarning;
                    }
                    break;
                }

                if (executive.size() >
                        kMaxCidProcessProbeCount -
                            executiveThreads->size() ||
                    scheduler.size() >
                        kMaxCidProcessProbeCount -
                            schedulerThreads->size())
                {
                    listsComplete = false;
                    if (warning != nullptr)
                    {
                        *warning =
                            L"aggregate kernel thread-list inventory exceeded the bounded CID/thread budget";
                    }
                    break;
                }

                for (auto& thread : executive)
                {
                    if (!executiveThreads->emplace(
                            thread.first,
                            std::move(thread.second)).
                            second)
                    {
                        listsComplete = false;
                        break;
                    }
                }
                for (auto& thread : scheduler)
                {
                    if (!schedulerThreads->emplace(
                            thread.first,
                            std::move(thread.second)).
                            second)
                    {
                        listsComplete = false;
                        break;
                    }
                }
                if (!listsComplete)
                {
                    if (warning != nullptr &&
                        warning->empty())
                    {
                        *warning =
                            L"duplicate thread identifier across owner process lists";
                    }
                    break;
                }
            }
            if (!listsComplete)
            {
                executiveThreads->clear();
                schedulerThreads->clear();
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CollectCidThreadViewSnapshot(
        DeviceClient& device,
        const CidDirectLayout& layout,
        const CidEprocessLayout& processLayout,
        const CidDirectEnumerationResult& direct,
        const std::map<uint32_t, HuntProcessRecord>&
            processes,
        CidThreadViewSnapshot* snapshot)
    {
        bool ok = false;

        do
        {
            if (snapshot == nullptr)
            {
                break;
            }
            *snapshot = {};

            std::map<uint32_t, ApiProcessRecord>
                systemProcesses;
            std::wstring systemWarning;
            std::wstring toolhelpWarning;
            if (!CollectSystemProcessInformation(
                    &systemProcesses,
                    &systemWarning,
                    &snapshot->SystemThreads) ||
                !CollectToolhelpThreads(
                    &snapshot->ToolhelpThreads,
                    &toolhelpWarning))
            {
                snapshot->Warning =
                    L"thread API snapshot failed: system=" +
                    systemWarning +
                    L" toolhelp=" +
                    toolhelpWarning;
                break;
            }

            std::set<uint32_t> currentApiOwnerIds;
            for (const auto& item : systemProcesses)
            {
                currentApiOwnerIds.insert(item.first);
            }
            for (const auto& item :
                 snapshot->ToolhelpThreads)
            {
                currentApiOwnerIds.insert(
                    item.second.ProcessId);
            }

            if (!CollectCidThreadKernelViews(
                    device,
                    layout,
                    processLayout,
                    direct,
                    processes,
                    currentApiOwnerIds,
                    &snapshot->ExecutiveThreads,
                    &snapshot->SchedulerThreads,
                    &snapshot->Warning))
            {
                break;
            }

            snapshot->Complete = true;
            ok = true;
        } while (false);

        return ok;
    }

    enum class CidViewPresence
    {
        StableAbsent,
        StableSeen,
        Unstable
    };

    CidViewPresence GetStableCidKernelPresence(
        const std::map<uint32_t, CidDirectThread>& first,
        const std::map<uint32_t, CidDirectThread>& second,
        uint32_t threadId,
        const CidDirectThread** current)
    {
        if (current != nullptr)
        {
            *current = nullptr;
        }
        const auto firstItem = first.find(threadId);
        const auto secondItem = second.find(threadId);
        if (firstItem == first.end() &&
            secondItem == second.end())
        {
            return CidViewPresence::StableAbsent;
        }
        if (firstItem == first.end() ||
            secondItem == second.end() ||
            !CidThreadIdentityEqual(
                firstItem->second,
                secondItem->second))
        {
            return CidViewPresence::Unstable;
        }
        if (current != nullptr)
        {
            *current = &secondItem->second;
        }
        return CidViewPresence::StableSeen;
    }

    CidViewPresence GetStableCidApiPresence(
        const std::map<uint32_t, ApiThreadRecord>& first,
        const std::map<uint32_t, ApiThreadRecord>& second,
        uint32_t threadId,
        uint32_t processId)
    {
        const auto firstItem = first.find(threadId);
        const auto secondItem = second.find(threadId);
        if (firstItem == first.end() &&
            secondItem == second.end())
        {
            return CidViewPresence::StableAbsent;
        }
        if (firstItem == first.end() ||
            secondItem == second.end() ||
            firstItem->second.ProcessId != processId ||
            secondItem->second.ProcessId != processId)
        {
            return CidViewPresence::Unstable;
        }
        return CidViewPresence::StableSeen;
    }

    const wchar_t* CidViewPresenceText(
        CidViewPresence presence)
    {
        switch (presence)
        {
        case CidViewPresence::StableAbsent:
            return L"stable_absent";
        case CidViewPresence::StableSeen:
            return L"stable_seen";
        default:
            return L"unstable";
        }
    }

    enum class CidThreadCrossViewDecision
    {
        None,
        DirectOnly,
        MissingFromCid,
        ExecutiveUnlinked,
        SchedulerUnlinked,
        ApiHidden,
        ApiOnly,
        OwnerProcessMissing
    };

    bool CidSeenKernelIdentityAgrees(
        CidViewPresence presence,
        const CidDirectThread* view,
        const CidDirectThread* source)
    {
        if (presence != CidViewPresence::StableSeen)
        {
            return true;
        }
        return view != nullptr &&
            source != nullptr &&
            CidThreadIdentityEqual(*view, *source);
    }

    bool IsCoherentCidThreadLifecycleTransition(
        bool hasChangingPresence,
        bool currentKernelIdentitiesAgree,
        bool apiProcessIdsDisagree)
    {
        return
            hasChangingPresence &&
            currentKernelIdentitiesAgree &&
            !apiProcessIdsDisagree;
    }

    CidThreadCrossViewDecision
    ClassifyCidThreadCrossView(
        bool kernelIdentityRevalidated,
        bool apiIdentityRevalidated,
        bool viewsRevalidated,
        bool hasLifecycle,
        bool terminated,
        uint64_t exitTime,
        CidViewPresence direct,
        CidViewPresence executive,
        CidViewPresence scheduler,
        CidViewPresence system,
        CidViewPresence toolhelp)
    {
        const bool liveKernelIdentity =
            kernelIdentityRevalidated &&
            viewsRevalidated &&
            hasLifecycle &&
            !terminated &&
            exitTime == 0;
        if (liveKernelIdentity)
        {
            if (direct == CidViewPresence::StableSeen &&
                executive == CidViewPresence::StableAbsent &&
                scheduler == CidViewPresence::StableAbsent &&
                system == CidViewPresence::StableAbsent &&
                toolhelp == CidViewPresence::StableAbsent)
            {
                return CidThreadCrossViewDecision::DirectOnly;
            }
            if (direct == CidViewPresence::StableAbsent &&
                executive == CidViewPresence::StableSeen &&
                scheduler == CidViewPresence::StableSeen &&
                system == CidViewPresence::StableSeen &&
                toolhelp == CidViewPresence::StableSeen)
            {
                return CidThreadCrossViewDecision::MissingFromCid;
            }
            if (direct == CidViewPresence::StableSeen &&
                executive == CidViewPresence::StableAbsent &&
                scheduler == CidViewPresence::StableSeen &&
                system == CidViewPresence::StableSeen &&
                toolhelp == CidViewPresence::StableSeen)
            {
                return CidThreadCrossViewDecision::ExecutiveUnlinked;
            }
            if (direct == CidViewPresence::StableSeen &&
                executive == CidViewPresence::StableSeen &&
                scheduler == CidViewPresence::StableAbsent &&
                system == CidViewPresence::StableSeen &&
                toolhelp == CidViewPresence::StableSeen)
            {
                return CidThreadCrossViewDecision::SchedulerUnlinked;
            }
            if (direct == CidViewPresence::StableSeen &&
                executive == CidViewPresence::StableSeen &&
                scheduler == CidViewPresence::StableSeen &&
                system == CidViewPresence::StableAbsent &&
                toolhelp == CidViewPresence::StableAbsent)
            {
                return CidThreadCrossViewDecision::ApiHidden;
            }
        }

        if (!kernelIdentityRevalidated &&
            apiIdentityRevalidated &&
            viewsRevalidated &&
            direct == CidViewPresence::StableAbsent &&
            executive == CidViewPresence::StableAbsent &&
            scheduler == CidViewPresence::StableAbsent &&
            system == CidViewPresence::StableSeen &&
            toolhelp == CidViewPresence::StableSeen)
        {
            return CidThreadCrossViewDecision::ApiOnly;
        }

        return CidThreadCrossViewDecision::None;
    }

    bool ApplyCidThreadCrossView(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        std::map<uint32_t, HuntProcessRecord>* processes,
        HuntResult* huntResult,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr ||
                huntResult == nullptr ||
                directoryTableBaseOffset == 0)
            {
                break;
            }

            uint32_t highestKnownPid = 0;
            for (const auto& item : *processes)
            {
                highestKnownPid =
                    (std::max)(
                        highestKnownPid,
                        item.first);
            }

            CidEprocessLayout processLayout = {};
            CidDirectLayout directLayout = {};
            std::wstring localWarning;
            if (!ResolveCidEprocessLayout(
                    symbols,
                    &processLayout,
                    &localWarning) ||
                !ResolveCidDirectLayout(
                    symbols,
                    &directLayout,
                    &localWarning))
            {
                if (warning != nullptr)
                {
                    *warning = localWarning;
                }
                break;
            }

            CidDirectEnumerationResult firstDirect = {};
            CidThreadViewSnapshot firstViews = {};
            CidDirectEnumerationResult secondDirect = {};
            CidThreadViewSnapshot secondViews = {};
            std::wstring captureFailure;
            bool captureComplete = false;
            constexpr uint32_t kCaptureAttempts = 3;
            for (uint32_t attempt = 0;
                 attempt < kCaptureAttempts;
                 ++attempt)
            {
                firstDirect = {};
                firstViews = {};
                secondDirect = {};
                secondViews = {};
                captureFailure.clear();

                if (!ApplyCidTableDirectObjectView(
                        device,
                        symbols,
                        directoryTableBaseOffset,
                        userDirectoryTableBaseOffset,
                        highestKnownPid,
                        &firstDirect))
                {
                    captureFailure = firstDirect.Summary;
                }
                else if (!CollectCidThreadViewSnapshot(
                             device,
                             directLayout,
                             processLayout,
                             firstDirect,
                             *processes,
                             &firstViews))
                {
                    captureFailure = firstViews.Warning;
                }
                else if (!ApplyCidTableDirectObjectView(
                             device,
                             symbols,
                             directoryTableBaseOffset,
                             userDirectoryTableBaseOffset,
                             highestKnownPid,
                             &secondDirect))
                {
                    captureFailure = secondDirect.Summary;
                }
                else if (!CollectCidThreadViewSnapshot(
                             device,
                             directLayout,
                             processLayout,
                             secondDirect,
                             *processes,
                             &secondViews))
                {
                    captureFailure = secondViews.Warning;
                }
                else
                {
                    captureComplete = true;
                    break;
                }

                if (attempt + 1 < kCaptureAttempts)
                {
                    SwitchToThread();
                }
            }
            if (!captureComplete)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"thread cross-view capture did not stabilize after retries: " +
                        captureFailure;
                }
                break;
            }

            std::set<uint32_t> preTriageProcessIds;
            for (const auto& item : *processes)
            {
                preTriageProcessIds.insert(item.first);
            }
            uint64_t lateProcesses = 0;
            if (!MergeCidDirectProcessView(
                    secondDirect,
                    processes,
                    &lateProcesses,
                    &localWarning))
            {
                if (warning != nullptr)
                {
                    *warning = localWarning;
                }
                break;
            }
            if (MarkPostTriageProcessArrivals(
                    preTriageProcessIds,
                    secondDirect,
                    processes) != lateProcesses)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"thread CID cross-view could not account for every post-triage process arrival";
                }
                break;
            }

            huntResult->CidTableAnchorAddress =
                secondDirect.Snapshot.AnchorAddress;
            huntResult->CidTableAddress =
                secondDirect.Snapshot.TableAddress;
            huntResult->CidTableCode =
                secondDirect.Snapshot.TableCode;
            huntResult->CidTableLevel =
                secondDirect.Snapshot.TableLevel;
            huntResult->CidTableNextHandle =
                secondDirect.Snapshot.NextHandle;
            huntResult->CidTableAllocatedLeafCount =
                secondDirect.Snapshot.
                    AllocatedLeafCount;
            huntResult->
                CidTableAllocatedHandleCapacity =
                    secondDirect.Snapshot.
                        AllocatedHandleCapacity;
            huntResult->CidTableDirectEntryCount =
                secondDirect.NonEmptyEntryCount;
            huntResult->CidTableDirectProcessCount =
                secondDirect.Processes.size();
            huntResult->CidTableDirectThreadCount =
                secondDirect.Threads.size();
            huntResult->CidTableUnclassifiedEntryCount =
                secondDirect.UnclassifiedEntryCount;
            huntResult->SystemProcessInfoThreadCount =
                secondViews.SystemThreads.size();
            huntResult->ToolhelpThreadCount =
                secondViews.ToolhelpThreads.size();
            huntResult->CidThreads.clear();

            std::set<uint32_t> threadIds;
            const auto addKeys =
                [&threadIds](const auto& values)
                {
                    for (const auto& item : values)
                    {
                        threadIds.insert(item.first);
                    }
                };
            addKeys(firstDirect.Threads);
            addKeys(secondDirect.Threads);
            addKeys(firstViews.ExecutiveThreads);
            addKeys(secondViews.ExecutiveThreads);
            addKeys(firstViews.SchedulerThreads);
            addKeys(secondViews.SchedulerThreads);
            addKeys(firstViews.SystemThreads);
            addKeys(secondViews.SystemThreads);
            addKeys(firstViews.ToolhelpThreads);
            addKeys(secondViews.ToolhelpThreads);
            if (threadIds.size() >
                kMaxCidProcessProbeCount)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"thread cross-view union exceeded the bounded CID/thread budget";
                }
                break;
            }

            bool crossViewComplete = true;
            uint64_t persistentMisses = 0;
            uint64_t findings = 0;
            for (uint32_t threadId : threadIds)
            {
                const CidDirectThread* directThread =
                    nullptr;
                const CidDirectThread* executiveThread =
                    nullptr;
                const CidDirectThread* schedulerThread =
                    nullptr;
                const CidViewPresence directPresence =
                    GetStableCidKernelPresence(
                        firstDirect.Threads,
                        secondDirect.Threads,
                        threadId,
                        &directThread);

                const auto currentDirect =
                    secondDirect.Threads.find(threadId);
                const auto currentExecutive =
                    secondViews.ExecutiveThreads.find(
                        threadId);
                const auto currentScheduler =
                    secondViews.SchedulerThreads.find(
                        threadId);
                const auto currentSystem =
                    secondViews.SystemThreads.find(
                        threadId);
                const auto currentToolhelp =
                    secondViews.ToolhelpThreads.find(
                        threadId);
                const bool anyCurrentView =
                    currentDirect !=
                        secondDirect.Threads.end() ||
                    currentExecutive !=
                        secondViews.ExecutiveThreads.end() ||
                    currentScheduler !=
                        secondViews.SchedulerThreads.end() ||
                    currentSystem !=
                        secondViews.SystemThreads.end() ||
                    currentToolhelp !=
                        secondViews.ToolhelpThreads.end();
                if (!anyCurrentView)
                {
                    // The thread disappeared from every current view. It
                    // cannot affect the second-snapshot inventory and is a
                    // normal lifecycle transition, not incomplete coverage.
                    continue;
                }
                const CidDirectThread* source = nullptr;
                if (currentDirect !=
                    secondDirect.Threads.end())
                {
                    source = &currentDirect->second;
                }
                else if (currentExecutive !=
                         secondViews.ExecutiveThreads.end())
                {
                    source =
                        &currentExecutive->second;
                }
                else if (currentScheduler !=
                         secondViews.SchedulerThreads.end())
                {
                    source =
                        &currentScheduler->second;
                }

                uint32_t sourceProcessId = 0;
                bool sourceProcessIdResolved = false;
                bool apiProcessIdsDisagree = false;
                if (source != nullptr)
                {
                    sourceProcessId = source->ProcessId;
                    sourceProcessIdResolved = true;
                }
                else
                {
                    if (currentSystem !=
                        secondViews.SystemThreads.end())
                    {
                        sourceProcessId =
                            currentSystem->second.ProcessId;
                        sourceProcessIdResolved = true;
                    }
                    if (currentToolhelp !=
                        secondViews.ToolhelpThreads.end())
                    {
                        if (sourceProcessIdResolved &&
                            sourceProcessId !=
                                currentToolhelp->second.
                                    ProcessId)
                        {
                            apiProcessIdsDisagree = true;
                        }
                        else
                        {
                            sourceProcessId =
                                currentToolhelp->second.
                                    ProcessId;
                            sourceProcessIdResolved = true;
                        }
                    }
                }
                if (!sourceProcessIdResolved)
                {
                    crossViewComplete = false;
                    continue;
                }

                const CidViewPresence executivePresence =
                    GetStableCidKernelPresence(
                        firstViews.ExecutiveThreads,
                        secondViews.ExecutiveThreads,
                        threadId,
                        &executiveThread);
                const CidViewPresence schedulerPresence =
                    GetStableCidKernelPresence(
                        firstViews.SchedulerThreads,
                        secondViews.SchedulerThreads,
                        threadId,
                        &schedulerThread);
                const CidViewPresence systemPresence =
                    GetStableCidApiPresence(
                        firstViews.SystemThreads,
                        secondViews.SystemThreads,
                        threadId,
                        sourceProcessId);
                const CidViewPresence toolhelpPresence =
                    GetStableCidApiPresence(
                        firstViews.ToolhelpThreads,
                        secondViews.ToolhelpThreads,
                        threadId,
                        sourceProcessId);
                const bool currentKernelIdentitiesAgree =
                    (source != nullptr &&
                     (currentDirect ==
                          secondDirect.Threads.end() ||
                      CidThreadIdentityEqual(
                          currentDirect->second,
                          *source)) &&
                     (currentExecutive ==
                          secondViews.ExecutiveThreads.end() ||
                      CidThreadIdentityEqual(
                          currentExecutive->second,
                          *source)) &&
                     (currentScheduler ==
                          secondViews.SchedulerThreads.end() ||
                      CidThreadIdentityEqual(
                          currentScheduler->second,
                          *source))) ||
                    (source == nullptr &&
                     currentDirect ==
                         secondDirect.Threads.end() &&
                     currentExecutive ==
                         secondViews.ExecutiveThreads.end() &&
                     currentScheduler ==
                         secondViews.SchedulerThreads.end());
                const bool hasChangingPresence =
                    directPresence ==
                        CidViewPresence::Unstable ||
                    executivePresence ==
                        CidViewPresence::Unstable ||
                    schedulerPresence ==
                        CidViewPresence::Unstable ||
                    systemPresence ==
                        CidViewPresence::Unstable ||
                    toolhelpPresence ==
                        CidViewPresence::Unstable;
                const bool coherentLifecycleTransition =
                    IsCoherentCidThreadLifecycleTransition(
                        hasChangingPresence,
                        currentKernelIdentitiesAgree,
                        apiProcessIdsDisagree);

                HuntCidThreadRecord record = {};
                record.ThreadId = threadId;
                record.ProcessId = sourceProcessId;
                if (source != nullptr)
                {
                    record.ObjectHeader =
                        source->ObjectHeader;
                    record.Ethread = source->Ethread;
                    record.Eprocess = source->Eprocess;
                    record.CreateTime = source->CreateTime;
                    record.ExitTime = source->ExitTime;
                    record.HasCreateTime =
                        source->HasCreateTime;
                    record.HasExitTime =
                        source->HasExitTime;
                    record.Terminated =
                        source->Terminated;
                }
                record.DirectCidSeen =
                    currentDirect !=
                        secondDirect.Threads.end();
                record.ExecutiveThreadListSeen =
                    currentExecutive !=
                        secondViews.ExecutiveThreads.end();
                record.SchedulerThreadListSeen =
                    currentScheduler !=
                        secondViews.SchedulerThreads.end();
                record.SystemProcessInformationSeen =
                    currentSystem !=
                        secondViews.SystemThreads.end() &&
                    currentSystem->second.ProcessId ==
                        sourceProcessId;
                record.ToolhelpThreadSeen =
                    currentToolhelp !=
                        secondViews.ToolhelpThreads.end() &&
                    currentToolhelp->second.ProcessId ==
                        sourceProcessId;
                const bool kernelIdentitiesAgree =
                    currentKernelIdentitiesAgree &&
                    CidSeenKernelIdentityAgrees(
                        directPresence,
                        directThread,
                        source) &&
                    CidSeenKernelIdentityAgrees(
                        executivePresence,
                        executiveThread,
                        source) &&
                    CidSeenKernelIdentityAgrees(
                        schedulerPresence,
                        schedulerThread,
                        source);
                const bool kernelIdentityRevalidated =
                    source != nullptr &&
                    kernelIdentitiesAgree &&
                    ((directPresence ==
                          CidViewPresence::StableSeen ||
                     executivePresence ==
                          CidViewPresence::StableSeen ||
                     schedulerPresence ==
                          CidViewPresence::StableSeen) ||
                     coherentLifecycleTransition);
                const bool apiIdentityRevalidated =
                    source == nullptr &&
                    !apiProcessIdsDisagree &&
                    ((systemPresence ==
                          CidViewPresence::StableSeen &&
                      toolhelpPresence ==
                          CidViewPresence::StableSeen) ||
                     coherentLifecycleTransition);
                record.IdentityRevalidated =
                    kernelIdentityRevalidated ||
                    apiIdentityRevalidated;
                record.ViewsRevalidated =
                    ((directPresence !=
                          CidViewPresence::Unstable &&
                     executivePresence !=
                          CidViewPresence::Unstable &&
                     schedulerPresence !=
                          CidViewPresence::Unstable &&
                     systemPresence !=
                          CidViewPresence::Unstable &&
                     toolhelpPresence !=
                          CidViewPresence::Unstable) ||
                     coherentLifecycleTransition) &&
                    kernelIdentitiesAgree &&
                    !apiProcessIdsDisagree;
                record.LifecycleChanged =
                    coherentLifecycleTransition ||
                    !record.ViewsRevalidated ||
                    !record.IdentityRevalidated ||
                    (source != nullptr &&
                     (source->Terminated ||
                      source->ExitTime != 0));

                if (!record.ViewsRevalidated ||
                    (source == nullptr &&
                     !apiIdentityRevalidated))
                {
                    crossViewComplete = false;
                    record.Warnings.push_back(
                        !record.ViewsRevalidated
                            ? (kernelIdentitiesAgree
                                   ? L"one or more thread views or API owner identities changed while the thread was being revalidated"
                                   : L"stable thread views disagreed on ETHREAD, EPROCESS, or create-time identity")
                            : L"API-only thread identity was not confirmed by both user API views");
                }

                const HuntProcessRecord* owner = nullptr;
                auto ownerItem =
                    processes->find(sourceProcessId);
                if (ownerItem != processes->end() &&
                    (source == nullptr ||
                     ownerItem->second.Kernel.Eprocess ==
                         source->Eprocess))
                {
                    owner = &ownerItem->second;
                }

                CidThreadCrossViewDecision decision =
                    ClassifyCidThreadCrossView(
                        kernelIdentityRevalidated,
                        apiIdentityRevalidated,
                        record.ViewsRevalidated,
                        source != nullptr &&
                            source->HasExitTime,
                        source != nullptr &&
                            source->Terminated,
                        source != nullptr
                            ? source->ExitTime
                            : 0,
                        directPresence,
                        executivePresence,
                        schedulerPresence,
                        systemPresence,
                        toolhelpPresence);
                if (decision ==
                        CidThreadCrossViewDecision::None &&
                    ownerItem == processes->end() &&
                    source != nullptr &&
                    sourceProcessId != 0 &&
                    kernelIdentityRevalidated &&
                    record.ViewsRevalidated &&
                    source->HasExitTime &&
                    source->ExitTime == 0 &&
                    !source->Terminated &&
                    directPresence ==
                        CidViewPresence::StableSeen &&
                    executivePresence ==
                        CidViewPresence::StableSeen &&
                    schedulerPresence ==
                        CidViewPresence::StableSeen &&
                    systemPresence ==
                        CidViewPresence::StableSeen &&
                    toolhelpPresence ==
                        CidViewPresence::StableSeen)
                {
                    CidEnumeratedProcess recovered = {};
                    if (CaptureCidProcessAtAddress(
                            device,
                            processLayout,
                            directoryTableBaseOffset,
                            userDirectoryTableBaseOffset,
                            sourceProcessId,
                            source->Eprocess,
                            &recovered) &&
                        recovered.HasExitTime &&
                        recovered.ExitTime == 0 &&
                        recovered.HasActiveThreads &&
                        recovered.ActiveThreads != 0)
                    {
                        HuntProcessRecord recoveredOwner = {};
                        recoveredOwner.ProcessId =
                            sourceProcessId;
                        recoveredOwner.Kernel.ProcessId =
                            sourceProcessId;
                        recoveredOwner.Kernel.Eprocess =
                            recovered.Context.Eprocess;
                        recoveredOwner.Kernel.
                            DirectoryTableBase =
                                recovered.Context.
                                    DirectoryTableBase;
                        recoveredOwner.Kernel.
                            UserDirectoryTableBase =
                                recovered.Context.
                                    UserDirectoryTableBase;
                        recoveredOwner.Kernel.CreateTime =
                            recovered.CreateTime;
                        recoveredOwner.Kernel.HasCreateTime =
                            recovered.HasCreateTime;
                        recoveredOwner.Kernel.ExitTime =
                            recovered.ExitTime;
                        recoveredOwner.Kernel.HasExitTime =
                            recovered.HasExitTime;
                        recoveredOwner.Kernel.ActiveThreads =
                            recovered.ActiveThreads;
                        recoveredOwner.Kernel.
                            HasActiveThreads =
                                recovered.HasActiveThreads;
                        recoveredOwner.Kernel.Peb =
                            recovered.Peb;
                        recoveredOwner.Kernel.HasPeb =
                            recovered.HasPeb;
                        recoveredOwner.Kernel.ImageName =
                            recovered.ImageName;
                        recoveredOwner.KernelImageName =
                            recovered.ImageName;
                        recoveredOwner.HasCidTableView = true;
                        recoveredOwner.CidTableEnumerated =
                            true;
                        recoveredOwner.CidTableSeen = false;
                        recoveredOwner.CidIdentityRevalidated =
                            true;
                        recoveredOwner.AddressContextRefreshed =
                            true;
                        recoveredOwner.Warnings.push_back(
                            L"live EPROCESS was recovered only through stable thread ownership after its process CID and aggregate process views were absent");
                        ownerItem = processes->emplace(
                            sourceProcessId,
                            std::move(recoveredOwner)).first;
                        owner = &ownerItem->second;
                        decision =
                            CidThreadCrossViewDecision::
                                OwnerProcessMissing;
                        huntResult->
                            ProcessInventoryIncomplete =
                                true;
                        huntResult->
                            ProcessTriageCoverageIncomplete =
                                true;
                        huntResult->CoverageComplete = false;
                    }
                    else
                    {
                        crossViewComplete = false;
                        record.Warnings.push_back(
                            L"thread owner process was absent and its live EPROCESS lifecycle could not be revalidated");
                    }
                }

                const bool ownerIdentityMismatch =
                    source != nullptr &&
                    ownerItem != processes->end() &&
                    ownerItem->second.Kernel.Eprocess !=
                        source->Eprocess;
                if (sourceProcessId != 0 &&
                    decision !=
                        CidThreadCrossViewDecision::None &&
                    owner == nullptr &&
                    (source == nullptr ||
                     ownerIdentityMismatch))
                {
                    crossViewComplete = false;
                    record.Warnings.push_back(
                        L"thread owner process identity was unavailable or disagreed");
                    decision =
                        CidThreadCrossViewDecision::None;
                }
                else if (sourceProcessId != 0 &&
                         decision !=
                             CidThreadCrossViewDecision::None &&
                         owner == nullptr &&
                         source != nullptr)
                {
                    record.Warnings.push_back(
                        L"thread owner process is absent from the aggregate process inventory");
                    huntResult->ProcessInventoryIncomplete =
                        true;
                    huntResult->
                        ProcessTriageCoverageIncomplete =
                            true;
                    huntResult->CoverageComplete = false;
                }

                std::wstring risk;
                std::wstring confidence;
                std::wstring title;
                if (decision ==
                    CidThreadCrossViewDecision::DirectOnly)
                {
                    risk = L"high";
                    confidence = L"high";
                    title =
                        L"live thread is present only in the direct CID entry view";
                    record.Reasons = {
                        L"cid_only_thread",
                        L"missing_from_executive_thread_list",
                        L"missing_from_scheduler_thread_list",
                        L"missing_from_user_api_views",
                        L"possible_thread_dkom"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::
                             MissingFromCid)
                {
                    risk = L"high";
                    confidence = L"high";
                    title =
                        L"live thread is missing from the direct CID entry view";
                    record.Reasons = {
                        L"thread_missing_from_cid_table",
                        L"executive_scheduler_lists_agree",
                        L"user_api_views_agree",
                        L"possible_cid_entry_dkom"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::
                             ExecutiveUnlinked)
                {
                    risk = L"medium";
                    confidence = L"high";
                    title =
                        L"live thread is unlinked from the executive process thread list";
                    record.Reasons = {
                        L"executive_thread_list_unlink",
                        L"cid_scheduler_api_views_agree"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::
                             SchedulerUnlinked)
                {
                    risk = L"medium";
                    confidence = L"high";
                    title =
                        L"live thread is unlinked from the scheduler process thread list";
                    record.Reasons = {
                        L"scheduler_thread_list_unlink",
                        L"cid_executive_api_views_agree"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::ApiHidden)
                {
                    risk = L"medium";
                    confidence = L"high";
                    title =
                        L"live kernel thread is absent from both user API views";
                    record.Reasons = {
                        L"thread_hidden_from_user_api_views",
                        L"cid_executive_scheduler_views_agree"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::ApiOnly)
                {
                    risk = L"medium";
                    confidence = L"medium";
                    title =
                        L"thread is persistently visible to both user APIs but absent from CID and kernel thread lists";
                    record.Reasons = {
                        L"thread_api_only",
                        L"missing_from_direct_cid",
                        L"missing_from_executive_thread_list",
                        L"missing_from_scheduler_thread_list",
                        L"possible_api_injection_or_kernel_unlink"
                    };
                }
                else if (decision ==
                         CidThreadCrossViewDecision::
                             OwnerProcessMissing)
                {
                    risk = L"high";
                    confidence = L"high";
                    title =
                        L"live process is recoverable only through stable thread ownership";
                    record.Reasons = {
                        L"thread_owner_process_missing",
                        L"process_missing_from_direct_cid",
                        L"process_missing_from_aggregate_inventory",
                        L"cid_executive_scheduler_thread_views_agree",
                        L"user_thread_api_views_agree",
                        L"possible_process_cid_dkom"
                    };
                }

                if (!title.empty())
                {
                    if (owner == nullptr &&
                        source != nullptr &&
                        sourceProcessId != 0)
                    {
                        AddUnique(
                            &record.Reasons,
                            L"owner_process_inventory_missing");
                    }
                    std::map<std::wstring,
                             std::wstring>
                        evidence;
                    evidence[L"thread_id"] =
                        std::to_wstring(
                            record.ThreadId);
                    evidence[L"process_id"] =
                        std::to_wstring(
                            record.ProcessId);
                    evidence[L"ethread"] =
                        HuntHex(record.Ethread, 16);
                    evidence[L"eprocess"] =
                        HuntHex(record.Eprocess, 16);
                    evidence[L"create_time"] =
                        record.HasCreateTime
                            ? HuntHex(
                                  record.CreateTime,
                                  16)
                            : L"unavailable";
                    evidence[L"direct_cid"] =
                        CidViewPresenceText(
                            directPresence);
                    evidence[L"executive_list"] =
                        CidViewPresenceText(
                            executivePresence);
                    evidence[L"scheduler_list"] =
                        CidViewPresenceText(
                            schedulerPresence);
                    evidence[L"system_process_information"] =
                        CidViewPresenceText(
                            systemPresence);
                    evidence[L"toolhelp"] =
                        CidViewPresenceText(
                            toolhelpPresence);
                    evidence[L"identity_revalidated"] =
                        record.IdentityRevalidated
                            ? L"true"
                            : L"false";

                    bool findingAdded = false;
                    if (owner != nullptr)
                    {
                        AddFinding(
                            huntResult,
                            *owner,
                            risk,
                            confidence,
                            L"thread_cross_view",
                            title,
                            record.Ethread,
                            L"",
                            record.Reasons,
                            evidence);
                        findingAdded = true;
                    }
                    else if (source != nullptr ||
                             record.ProcessId == 0)
                    {
                        AddSystemFinding(
                            huntResult,
                            risk,
                            confidence,
                            L"thread_cross_view",
                            title,
                            record.Ethread,
                            L"",
                            record.Reasons,
                            evidence,
                            {L"!threads 0 /apc /stacks /limit 40"});
                        findingAdded = true;
                    }

                    if (findingAdded)
                    {
                        ++persistentMisses;
                        ++findings;
                        record.Suspicious = true;
                    }
                }

                huntResult->CidThreads.push_back(
                    std::move(record));
            }

            huntResult->CidTableDirectEntryEnumeration =
                true;
            huntResult->CidTableFullThreadEnumeration =
                true;
            huntResult->
                CidTableThreadCrossViewComplete =
                    crossViewComplete;
            huntResult->CidTableThreadFindingCount =
                findings;
            huntResult->
                CidTablePersistentThreadViewMissCount =
                    persistentMisses;
            if (!crossViewComplete)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"thread CID cross-view incomplete: one or more stable thread identities had a changing or missing comparison view";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    enum class ActiveProcessLinkMembership
    {
        Unknown,
        Linked,
        StableUnlinked
    };

    bool ActiveProcessLinksNeighborsConsistent(
        uint64_t entryAddress,
        uint64_t flink,
        uint64_t blink,
        uint64_t flinkBlink,
        uint64_t blinkFlink)
    {
        return IsKernelAddress(entryAddress) &&
            IsKernelAddress(flink) &&
            IsKernelAddress(blink) &&
            flink != entryAddress &&
            blink != entryAddress &&
            flinkBlink == entryAddress &&
            blinkFlink == entryAddress;
    }

    ActiveProcessLinkMembership RevalidateActiveProcessLinks(
        DeviceClient& device,
        uint64_t eprocess,
        uint32_t activeProcessLinksOffset)
    {
        if (!IsKernelAddress(eprocess) ||
            activeProcessLinksOffset == 0 ||
            activeProcessLinksOffset > 0x4000)
        {
            return ActiveProcessLinkMembership::Unknown;
        }

        uint64_t entryAddress = 0;
        if (!TryAdd(
                eprocess,
                activeProcessLinksOffset,
                &entryAddress) ||
            !IsKernelAddress(entryAddress))
        {
            return ActiveProcessLinkMembership::Unknown;
        }

        constexpr size_t kAttempts = 3;
        size_t conclusiveUnlinked = 0;
        for (size_t attempt = 0;
             attempt < kAttempts;
             ++attempt)
        {
            uint64_t entryBlinkAddress = 0;
            if (!TryAdd(
                    entryAddress,
                    sizeof(uint64_t),
                    &entryBlinkAddress))
            {
                return ActiveProcessLinkMembership::Unknown;
            }
            uint64_t flink = 0;
            uint64_t blink = 0;
            if (!ReadKernelPointer(
                    device,
                    entryAddress,
                    &flink,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    entryBlinkAddress,
                    &blink,
                    nullptr))
            {
                continue;
            }

            if (!IsKernelAddress(flink) ||
                !IsKernelAddress(blink) ||
                flink == entryAddress ||
                blink == entryAddress)
            {
                ++conclusiveUnlinked;
                continue;
            }

            uint64_t flinkBlink = 0;
            uint64_t blinkFlink = 0;
            uint64_t flinkBlinkAddress = 0;
            if (!TryAdd(
                    flink,
                    sizeof(uint64_t),
                    &flinkBlinkAddress) ||
                !ReadKernelPointer(
                    device,
                    flinkBlinkAddress,
                    &flinkBlink,
                    nullptr) ||
                !ReadKernelPointer(
                    device,
                    blink,
                    &blinkFlink,
                    nullptr))
            {
                continue;
            }
            if (ActiveProcessLinksNeighborsConsistent(
                    entryAddress,
                    flink,
                    blink,
                    flinkBlink,
                    blinkFlink))
            {
                return ActiveProcessLinkMembership::Linked;
            }

            ++conclusiveUnlinked;
        }

        return conclusiveUnlinked == kAttempts
            ? ActiveProcessLinkMembership::StableUnlinked
            : ActiveProcessLinkMembership::Unknown;
    }

    bool ApplyCidTableFullProcessView(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        uint32_t activeProcessLinksOffset,
        std::map<uint32_t, HuntProcessRecord>* processes,
        CidProcessEnumerationResult* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }
            *result = {};

            if (processes == nullptr ||
                directoryTableBaseOffset == 0 ||
                directoryTableBaseOffset > 0x4000 ||
                userDirectoryTableBaseOffset > 0x4000)
            {
                result->Summary =
                    L"cid full enumeration unavailable: invalid process layout or map";
                break;
            }

            CidTableLayout tableLayout = {};
            if (!ResolveCidTableLayout(
                    symbols,
                    &tableLayout,
                    &result->Summary))
            {
                break;
            }

            CidEprocessLayout processLayout = {};
            if (!ResolveCidEprocessLayout(
                    symbols,
                    &processLayout,
                    &result->Summary))
            {
                break;
            }

            uint32_t highestKnownPid = 0;
            for (const auto& item : *processes)
            {
                highestKnownPid =
                    (std::max)(
                        highestKnownPid,
                        item.first);
            }

            std::map<uint32_t, CidEnumeratedProcess>
                enumerated;
            CidTableSnapshot stableSnapshot = {};
            bool stable = false;
            uint64_t persistentFailures = 0;
            constexpr uint32_t kSnapshotAttempts = 2;
            for (uint32_t snapshotAttempt = 0;
                 snapshotAttempt < kSnapshotAttempts;
                 ++snapshotAttempt)
            {
                enumerated.clear();
                persistentFailures = 0;

                CidTableSnapshot before = {};
                if (!ResolveCidTableAnchor(
                        device,
                        symbols,
                        tableLayout,
                        highestKnownPid,
                        &before,
                        &result->Summary))
                {
                    break;
                }
                result->AnchorResolved = true;
                result->Snapshot = before;

                std::vector<uint32_t> retryIds;
                for (uint32_t processId = 4;
                     processId < before.NextHandle;
                     processId += 4)
                {
                    ++result->ProbeCount;
                    ProcessAddressContext context = {};
                    std::wstring resolveError;
                    DWORD deviceError = ERROR_SUCCESS;
                    if (device.ResolveProcess(
                            processId,
                            directoryTableBaseOffset,
                            userDirectoryTableBaseOffset,
                            &context,
                            &resolveError,
                            &deviceError))
                    {
                        CidEnumeratedProcess process = {};
                        if (CaptureCidEnumeratedProcess(
                                device,
                                processLayout,
                                processId,
                                context,
                                &process))
                        {
                            enumerated[processId] =
                                std::move(process);
                        }
                        else
                        {
                            retryIds.push_back(
                                processId);
                        }
                    }
                    else if (deviceError !=
                            ERROR_INVALID_PARAMETER)
                    {
                        // The driver maps STATUS_INVALID_CID to
                        // ERROR_INVALID_PARAMETER. Every other failure can
                        // represent an unreadable live EPROCESS and must be
                        // retried rather than treated as an empty slot.
                        retryIds.push_back(processId);
                    }
                }

                constexpr uint32_t kRetryAttempts = 2;
                for (uint32_t retryAttempt = 0;
                     retryAttempt < kRetryAttempts &&
                     !retryIds.empty();
                     ++retryAttempt)
                {
                    std::vector<uint32_t> nextRetry;
                    for (uint32_t processId : retryIds)
                    {
                        ++result->ProbeCount;
                        ProcessAddressContext context = {};
                        std::wstring resolveError;
                        DWORD deviceError = ERROR_SUCCESS;
                        if (device.ResolveProcess(
                                processId,
                                directoryTableBaseOffset,
                                userDirectoryTableBaseOffset,
                                &context,
                                &resolveError,
                                &deviceError))
                        {
                            CidEnumeratedProcess process = {};
                            if (CaptureCidEnumeratedProcess(
                                    device,
                                    processLayout,
                                    processId,
                                    context,
                                    &process))
                            {
                                enumerated[processId] =
                                    std::move(process);
                            }
                            else
                            {
                                nextRetry.push_back(
                                    processId);
                            }
                        }
                        else if (deviceError !=
                                 ERROR_INVALID_PARAMETER)
                        {
                            nextRetry.push_back(processId);
                        }
                    }
                    retryIds = std::move(nextRetry);
                }
                persistentFailures = retryIds.size();

                CidTableSnapshot after = {};
                if (!ReadCidTableSnapshot(
                        device,
                        tableLayout,
                        before.AnchorAddress,
                        highestKnownPid,
                        &after,
                        nullptr))
                {
                    result->Summary =
                        L"cid full enumeration: post-scan handle-table snapshot failed validation";
                    continue;
                }

                if (before.AnchorAddress ==
                        after.AnchorAddress &&
                    before.TableAddress ==
                        after.TableAddress &&
                    before.TableCode ==
                        after.TableCode &&
                    before.NextHandle ==
                        after.NextHandle &&
                    before.AllocatedLeafCount ==
                        after.AllocatedLeafCount &&
                    before.AllocatedHandleCapacity ==
                        after.AllocatedHandleCapacity &&
                    before.LeafPages ==
                        after.LeafPages)
                {
                    if (persistentFailures == 0)
                    {
                        stable = true;
                        stableSnapshot = after;
                        break;
                    }
                    result->Summary =
                        L"cid full enumeration: stable table retained unreadable CID probes; retrying the complete range";
                    continue;
                }

                result->Summary =
                    L"cid full enumeration: handle table changed during scan; retrying";
            }

            result->Stable = stable;
            result->ProbeFailureCount =
                persistentFailures;
            if (!stable)
            {
                if (result->Summary.empty())
                {
                    result->Summary =
                        L"cid full enumeration: no stable handle-table snapshot";
                }
                break;
            }
            if (persistentFailures != 0)
            {
                result->Summary =
                    L"cid full enumeration incomplete: " +
                    std::to_wstring(
                        persistentFailures) +
                    L" CID probes remained unreadable after retries";
                break;
            }
            if (enumerated.find(4) ==
                    enumerated.end())
            {
                result->Summary =
                    L"cid full enumeration incomplete: stable sweep did not recover the System process";
                break;
            }

            result->Snapshot = stableSnapshot;
            result->ProcessCount = enumerated.size();

            for (auto& item : *processes)
            {
                HuntProcessRecord& process =
                    item.second;
                if (item.first != 0)
                {
                    process.HasCidTableView = true;
                    process.CidTableEnumerated = true;
                    process.CidTableSeen = false;
                }
            }

            for (const auto& item : enumerated)
            {
                const uint32_t processId = item.first;
                const CidEnumeratedProcess& cid =
                    item.second;
                auto existing =
                    processes->find(processId);
                const bool discovered =
                    existing == processes->end();
                if (discovered)
                {
                    HuntProcessRecord record = {};
                    record.ProcessId = processId;
                    existing =
                        processes->emplace(
                            processId,
                            std::move(record)).first;
                    ++result->
                        DiscoveredProcessCount;
                }

                HuntProcessRecord& process =
                    existing->second;
                process.ProcessId = processId;
                process.HasCidTableView = true;
                process.CidTableEnumerated = true;

                if ((process.Kernel.Eprocess != 0 &&
                     process.Kernel.Eprocess !=
                         cid.Context.Eprocess) ||
                    (process.Kernel.HasCreateTime &&
                     process.Kernel.CreateTime !=
                         cid.CreateTime))
                {
                    process.LifecycleChangedBeforeTriage =
                        true;
                    AddUnique(
                        &process.Warnings,
                        L"PID identity changed between the seed views and full CID enumeration");
                    continue;
                }

                process.CidTableSeen = true;
                process.CidTableDiscovered =
                    process.CidTableDiscovered ||
                    discovered;
                process.Kernel.ProcessId = processId;
                process.Kernel.Eprocess =
                    cid.Context.Eprocess;
                process.Kernel.DirectoryTableBase =
                    cid.Context.DirectoryTableBase;
                process.Kernel.UserDirectoryTableBase =
                    cid.Context.UserDirectoryTableBase;
                process.Kernel.CreateTime =
                    cid.CreateTime;
                process.Kernel.HasCreateTime =
                    cid.HasCreateTime;
                process.Kernel.ExitTime =
                    cid.ExitTime;
                process.Kernel.HasExitTime =
                    cid.HasExitTime;
                process.Kernel.ActiveThreads =
                    cid.ActiveThreads;
                process.Kernel.HasActiveThreads =
                    cid.HasActiveThreads;
                process.Kernel.Peb = cid.Peb;
                process.Kernel.HasPeb = cid.HasPeb;
                if (!cid.ImageName.empty())
                {
                    process.Kernel.ImageName =
                        cid.ImageName;
                    process.KernelImageName =
                        cid.ImageName;
                }

                if (!IsTerminatingProcessSnapshot(
                        process.Kernel))
                {
                    const ActiveProcessLinkMembership
                        membership =
                            RevalidateActiveProcessLinks(
                                device,
                                cid.Context.Eprocess,
                                activeProcessLinksOffset);
                    if (membership ==
                        ActiveProcessLinkMembership::Linked)
                    {
                        process.ActiveProcessLinksSeen =
                            true;
                        process.ActiveProcessLinksRevalidated =
                            true;
                        process.ActiveProcessLinksStableUnlinked =
                            false;
                    }
                    else if (membership ==
                             ActiveProcessLinkMembership::
                                 StableUnlinked)
                    {
                        process.ActiveProcessLinksSeen =
                            false;
                        process.ActiveProcessLinksRevalidated =
                            true;
                        process.ActiveProcessLinksStableUnlinked =
                            true;
                    }
                    else
                    {
                        ++result->
                            MembershipIncompleteCount;
                        AddUnique(
                            &process.Warnings,
                            L"full-CID process ActiveProcessLinks membership could not be revalidated");
                    }
                }
            }

            result->Complete = true;
            result->Summary =
                L"cid full process enumeration: anchor=" +
                HuntHex(
                    stableSnapshot.AnchorAddress,
                    16) +
                L" table=" +
                HuntHex(
                    stableSnapshot.TableAddress,
                    16) +
                L" level=" +
                std::to_wstring(
                    stableSnapshot.TableLevel) +
                L" next_handle=" +
                HuntHex(
                    stableSnapshot.NextHandle,
                    8) +
                L" probes=" +
                std::to_wstring(
                    result->ProbeCount) +
                L" processes=" +
                std::to_wstring(
                    result->ProcessCount) +
                L" newly_discovered=" +
                std::to_wstring(
                    result->DiscoveredProcessCount) +
                L" membership_incomplete=" +
                std::to_wstring(
                    result->MembershipIncompleteCount);
            ok = true;
        } while (false);

        return ok;
    }

    bool RevalidateCidApiProcessViews(
        DeviceClient& device,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        std::map<uint32_t, HuntProcessRecord>* processes,
        uint64_t* persistentApiMisses,
        std::wstring* warning)
    {
        bool ok = false;

        do
        {
            if (processes == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid API revalidation: invalid process map";
                }
                break;
            }
            if (persistentApiMisses != nullptr)
            {
                *persistentApiMisses = 0;
            }

            std::map<uint32_t, ApiProcessRecord>
                systemProcesses;
            std::map<uint32_t, ApiProcessRecord>
                toolhelpProcesses;
            std::wstring systemWarning;
            std::wstring toolhelpWarning;
            const bool systemOk =
                CollectSystemProcessInformation(
                    &systemProcesses,
                    &systemWarning);
            const bool toolhelpOk =
                CollectToolhelpProcesses(
                    &toolhelpProcesses,
                    &toolhelpWarning);
            if (!systemOk || !toolhelpOk)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid API revalidation incomplete: system=" +
                        (systemOk ? L"ok" : systemWarning) +
                        L" toolhelp=" +
                        (toolhelpOk ? L"ok" : toolhelpWarning);
                }
                break;
            }

            for (auto& item : *processes)
            {
                HuntProcessRecord& process =
                    item.second;
                if (!process.CidTableEnumerated)
                {
                    continue;
                }

                process.CidApiViewsRevalidated = true;
                const auto system =
                    systemProcesses.find(item.first);
                if (system !=
                    systemProcesses.end())
                {
                    process.SystemProcessInformationSeen =
                        true;
                    if (process.SystemProcessImageName.empty())
                    {
                        process.SystemProcessImageName =
                            system->second.ImageName;
                    }
                }

                const auto toolhelp =
                    toolhelpProcesses.find(item.first);
                if (toolhelp !=
                    toolhelpProcesses.end())
                {
                    process.ToolhelpProcessSeen = true;
                    if (process.ToolhelpImageName.empty())
                    {
                        process.ToolhelpImageName =
                            toolhelp->second.ImageName;
                    }
                }
            }

            std::vector<uint32_t> unresolved;
            uint64_t unexpectedFailures = 0;
            for (auto& item : *processes)
            {
                HuntProcessRecord& process =
                    item.second;
                if (!process.CidTableEnumerated ||
                    process.CidTableSeen ||
                    (systemProcesses.find(item.first) ==
                         systemProcesses.end() &&
                     toolhelpProcesses.find(item.first) ==
                         toolhelpProcesses.end()))
                {
                    continue;
                }

                bool resolved = false;
                bool identityChanged = false;
                bool unexpectedFailure = false;
                constexpr uint32_t kAttempts = 3;
                for (uint32_t attempt = 0;
                     attempt < kAttempts;
                     ++attempt)
                {
                    ProcessAddressContext context = {};
                    std::wstring resolveError;
                    DWORD deviceError = ERROR_SUCCESS;
                    if (device.ResolveProcess(
                            item.first,
                            directoryTableBaseOffset,
                            userDirectoryTableBaseOffset,
                            &context,
                            &resolveError,
                            &deviceError))
                    {
                        if (process.Kernel.Eprocess != 0 &&
                            process.Kernel.Eprocess !=
                                context.Eprocess)
                        {
                            process.
                                LifecycleChangedBeforeTriage =
                                    true;
                            identityChanged = true;
                            AddUnique(
                                &process.Warnings,
                                L"PID identity changed during post-sweep CID/API reconciliation");
                        }
                        else
                        {
                            process.CidTableSeen = true;
                            process.Kernel.ProcessId =
                                item.first;
                            process.Kernel.Eprocess =
                                context.Eprocess;
                            process.Kernel.
                                DirectoryTableBase =
                                    context.
                                        DirectoryTableBase;
                            process.Kernel.
                                UserDirectoryTableBase =
                                    context.
                                        UserDirectoryTableBase;
                        }
                        resolved = true;
                        break;
                    }
                    if (deviceError !=
                        ERROR_INVALID_PARAMETER)
                    {
                        unexpectedFailure = true;
                    }
                    SwitchToThread();
                }
                if (!resolved && !identityChanged)
                {
                    unresolved.push_back(item.first);
                    if (unexpectedFailure)
                    {
                        ++unexpectedFailures;
                    }
                }
            }

            if (!unresolved.empty())
            {
                std::map<uint32_t, ApiProcessRecord>
                    secondSystem;
                std::map<uint32_t, ApiProcessRecord>
                    secondToolhelp;
                std::wstring secondSystemWarning;
                std::wstring secondToolhelpWarning;
                if (!CollectSystemProcessInformation(
                        &secondSystem,
                        &secondSystemWarning) ||
                    !CollectToolhelpProcesses(
                        &secondToolhelp,
                        &secondToolhelpWarning))
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"cid API revalidation incomplete: second process snapshots failed";
                    }
                    break;
                }

                uint64_t persistent = 0;
                for (uint32_t processId : unresolved)
                {
                    auto process =
                        processes->find(processId);
                    if (process ==
                        processes->end())
                    {
                        continue;
                    }
                    const bool stillVisible =
                        secondSystem.find(processId) !=
                            secondSystem.end() ||
                        secondToolhelp.find(processId) !=
                            secondToolhelp.end();
                    if (!stillVisible ||
                        IsTerminatingProcessSnapshot(
                            process->second.Kernel))
                    {
                        continue;
                    }

                    ++persistent;
                    AddUnique(
                        &process->second.Warnings,
                        L"live API-visible process remained absent from the full process-CID lookup surface");
                }
                if (persistentApiMisses != nullptr)
                {
                    *persistentApiMisses =
                        persistent;
                }
                if (persistent != 0 ||
                    unexpectedFailures != 0)
                {
                    if (warning != nullptr)
                    {
                        *warning =
                            L"cid API revalidation incomplete: persistent_api_without_cid=" +
                            std::to_wstring(persistent) +
                            L" unexpected_lookup_failures=" +
                            std::to_wstring(
                                unexpectedFailures);
                    }
                    break;
                }
            }
            else if (unexpectedFailures != 0)
            {
                if (warning != nullptr)
                {
                    *warning =
                        L"cid API revalidation incomplete: unexpected_lookup_failures=" +
                        std::to_wstring(
                            unexpectedFailures);
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    // Known-PID CID lookup via driver ResolveProcess (PsLookupProcessByProcessId).
    // This is NOT a full PspCidTable enumeration: PIDs absent from the starting
    // process map are never discovered. Only annotates HasCidTableView /
    // CidTableSeen and may fill missing EPROCESS/DTB when lookup works.
    bool ApplyCidTableLookupView(
        DeviceClient& device,
        SymbolEngine& symbols,
        std::map<uint32_t, HuntProcessRecord>* processes,
        std::wstring* warning,
        uint32_t* directoryTableBaseOffset,
        uint32_t* userDirectoryTableBaseOffset,
        uint32_t* activeProcessLinksOffsetOutput,
        uint32_t* createTimeOffsetOutput)
    {
        bool ok = false;

        do
        {
            if (directoryTableBaseOffset != nullptr)
            {
                *directoryTableBaseOffset = 0;
            }
            if (userDirectoryTableBaseOffset != nullptr)
            {
                *userDirectoryTableBaseOffset = 0;
            }
            if (activeProcessLinksOffsetOutput != nullptr)
            {
                *activeProcessLinksOffsetOutput = 0;
            }
            if (createTimeOffsetOutput != nullptr)
            {
                *createTimeOffsetOutput = 0;
            }

            if (processes == nullptr)
            {
                if (warning != nullptr)
                {
                    *warning = L"cid known-pid lookup: invalid process map";
                }
                break;
            }

            if (!device.IsOpen())
            {
                if (warning != nullptr)
                {
                    *warning = L"cid known-pid lookup unavailable: driver device is not open";
                }
                break;
            }

            if (symbols.Modules().empty())
            {
                std::wstring loadError;
                if (!symbols.LoadKernelModules(&loadError))
                {
                    if (warning != nullptr)
                    {
                        *warning = L"cid known-pid lookup unavailable: " + loadError;
                    }
                    break;
                }
            }

            TypeFieldInfo dtbField = {};
            std::wstring fieldError;
            if (!symbols.FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &fieldError))
            {
                // Nested path used on some PDB views.
                if (!symbols.FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &fieldError) &&
                    !FindFieldRecursive(
                        symbols,
                        {L"nt!_EPROCESS", L"_EPROCESS", L"nt!_KPROCESS", L"_KPROCESS"},
                        L"DirectoryTableBase",
                        &dtbField))
                {
                    if (warning != nullptr)
                    {
                        *warning = L"cid known-pid lookup unavailable: DirectoryTableBase offset unresolved: " + fieldError;
                    }
                    break;
                }
            }

            if (dtbField.Offset == 0 || dtbField.Offset > 0x4000)
            {
                if (warning != nullptr)
                {
                    *warning = L"cid known-pid lookup unavailable: DirectoryTableBase offset out of range";
                }
                break;
            }

            TypeFieldInfo userDtbField = {};
            uint32_t userDtbOffset = 0;
            if (symbols.FindField(L"nt!_KPROCESS", L"UserDirectoryTableBase", &userDtbField, nullptr) ||
                FindFieldRecursive(
                    symbols,
                    {L"nt!_EPROCESS", L"_EPROCESS", L"nt!_KPROCESS", L"_KPROCESS"},
                    L"UserDirectoryTableBase",
                    &userDtbField))
            {
                if (userDtbField.Offset != 0 && userDtbField.Offset <= 0x4000)
                {
                    userDtbOffset = static_cast<uint32_t>(userDtbField.Offset);
                }
            }

            TypeFieldInfo activeLinksField = {};
            uint32_t activeLinksOffset = 0;
            if ((symbols.FindField(
                     L"nt!_EPROCESS",
                     L"ActiveProcessLinks",
                     &activeLinksField,
                     nullptr) ||
                 FindFieldRecursive(
                     symbols,
                     {L"nt!_EPROCESS", L"_EPROCESS"},
                     L"ActiveProcessLinks",
                     &activeLinksField)) &&
                activeLinksField.Offset != 0 &&
                activeLinksField.Offset <= 0x4000)
            {
                activeLinksOffset =
                    static_cast<uint32_t>(
                        activeLinksField.Offset);
            }

            TypeFieldInfo createTimeField = {};
            uint32_t createTimeOffset = 0;
            if ((symbols.FindField(
                     L"nt!_EPROCESS",
                     L"CreateTime",
                     &createTimeField,
                     nullptr) ||
                 FindFieldRecursive(
                     symbols,
                     {L"nt!_EPROCESS", L"_EPROCESS"},
                     L"CreateTime",
                     &createTimeField)) &&
                createTimeField.Offset != 0 &&
                createTimeField.Offset <= 0x4000)
            {
                createTimeOffset =
                    static_cast<uint32_t>(
                        createTimeField.Offset);
            }

            if (directoryTableBaseOffset != nullptr)
            {
                *directoryTableBaseOffset = static_cast<uint32_t>(dtbField.Offset);
            }
            if (userDirectoryTableBaseOffset != nullptr)
            {
                *userDirectoryTableBaseOffset = userDtbOffset;
            }
            if (activeProcessLinksOffsetOutput != nullptr)
            {
                *activeProcessLinksOffsetOutput =
                    activeLinksOffset;
            }
            if (createTimeOffsetOutput != nullptr)
            {
                *createTimeOffsetOutput =
                    createTimeOffset;
            }

            uint32_t lookedUp = 0;
            uint32_t present = 0;
            uint32_t linksRecovered = 0;
            uint32_t linksStableUnlinked = 0;
            uint32_t linksUnknown = 0;
            uint32_t identitiesRecovered = 0;
            for (auto& item : *processes)
            {
                const uint32_t pid = item.first;
                if (pid == 0)
                {
                    continue;
                }

                HuntProcessRecord& process = item.second;
                process.HasCidTableView = true;
                ++lookedUp;

                ProcessAddressContext ctx = {};
                std::wstring resolveError;
                if (device.ResolveProcess(
                        pid,
                        static_cast<uint32_t>(dtbField.Offset),
                        userDtbOffset,
                        &ctx,
                        &resolveError))
                {
                    process.CidTableSeen = true;
                    ++present;
                    // Fill missing kernel identity without overwriting a
                    // stronger ActiveProcessLinks inventory record.
                    if (process.Kernel.Eprocess == 0)
                    {
                        process.Kernel.Eprocess = ctx.Eprocess;
                    }
                    if (process.Kernel.ProcessId == 0)
                    {
                        process.Kernel.ProcessId = pid;
                    }
                    if (process.Kernel.DirectoryTableBase == 0 && ctx.DirectoryTableBase != 0)
                    {
                        process.Kernel.DirectoryTableBase = ctx.DirectoryTableBase;
                    }
                    if (process.Kernel.UserDirectoryTableBase == 0 && ctx.UserDirectoryTableBase != 0)
                    {
                        process.Kernel.UserDirectoryTableBase = ctx.UserDirectoryTableBase;
                    }
                    if (!process.Kernel.HasCreateTime &&
                        createTimeOffset != 0)
                    {
                        uint64_t createTimeAddress = 0;
                        uint64_t createTime = 0;
                        if (TryAdd(
                                ctx.Eprocess,
                                createTimeOffset,
                                &createTimeAddress) &&
                            ReadKernelInteger(
                                device,
                                createTimeAddress,
                                sizeof(uint64_t),
                                &createTime,
                                nullptr) &&
                            createTime != 0)
                        {
                            process.Kernel.CreateTime =
                                createTime;
                            process.Kernel.HasCreateTime = true;
                            ++identitiesRecovered;
                        }
                    }

                    if (!process.ActiveProcessLinksSeen)
                    {
                        const ActiveProcessLinkMembership membership =
                            RevalidateActiveProcessLinks(
                                device,
                                ctx.Eprocess,
                                activeLinksOffset);
                        if (membership ==
                            ActiveProcessLinkMembership::Linked)
                        {
                            process.ActiveProcessLinksSeen = true;
                            process.ActiveProcessLinksRevalidated = true;
                            ++linksRecovered;
                        }
                        else if (membership ==
                                 ActiveProcessLinkMembership::StableUnlinked)
                        {
                            process.ActiveProcessLinksRevalidated = true;
                            process.ActiveProcessLinksStableUnlinked = true;
                            ++linksStableUnlinked;
                        }
                        else
                        {
                            AddUnique(
                                &process.Warnings,
                                L"post-inventory ActiveProcessLinks membership could not be revalidated; temporal mismatch evidence was not escalated");
                            ++linksUnknown;
                        }
                    }
                }
                else
                {
                    process.CidTableSeen = false;
                }
            }

            if (warning != nullptr)
            {
                *warning =
                    L"cid known-pid lookup (not full PspCidTable enumeration): looked_up=" +
                    std::to_wstring(lookedUp) +
                    L" present=" + std::to_wstring(present) +
                    L" links_recovered=" +
                    std::to_wstring(linksRecovered) +
                    L" links_stable_unlinked=" +
                    std::to_wstring(linksStableUnlinked) +
                    L" links_unknown=" +
                    std::to_wstring(linksUnknown) +
                    L" identities_recovered=" +
                    std::to_wstring(identitiesRecovered) +
                    L" via PsLookupProcessByProcessId; PIDs absent from other views are not discovered";
            }
            ok = lookedUp != 0;
        } while (false);

        return ok;
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
            evidence[L"active_process_links_revalidated"] =
                process.ActiveProcessLinksRevalidated
                    ? L"true"
                    : L"false";
            evidence[L"active_process_links_stable_unlinked"] =
                process.ActiveProcessLinksStableUnlinked
                    ? L"true"
                    : L"false";
            evidence[L"cid_table_enumerated"] =
                process.CidTableEnumerated
                    ? L"true"
                    : L"false";
            evidence[L"cid_table_discovered"] =
                process.CidTableDiscovered
                    ? L"true"
                    : L"false";
            evidence[L"cid_direct_entry_seen"] =
                process.CidDirectEntrySeen
                    ? L"true"
                    : L"false";
            evidence[L"cid_lookup_direct_agreed"] =
                process.CidLookupDirectAgreed
                    ? L"true"
                    : L"false";
            evidence[L"cid_api_views_revalidated"] =
                process.CidApiViewsRevalidated
                    ? L"true"
                    : L"false";
            evidence[L"cid_identity_revalidated"] =
                process.CidIdentityRevalidated
                    ? L"true"
                    : L"false";
            evidence[L"eprocess"] = process.Kernel.Eprocess != 0 ? HuntHex(process.Kernel.Eprocess, 16) : L"0x0";
            evidence[L"image_name"] = !process.KernelImageName.empty() ? process.KernelImageName : process.ToolhelpImageName;

            if (process.CidTableDiscovered &&
                process.CidTableEnumerated &&
                process.HasCidTableView &&
                process.CidTableSeen &&
                process.Kernel.HasExitTime &&
                process.Kernel.ExitTime == 0 &&
                process.Kernel.HasActiveThreads &&
                process.Kernel.ActiveThreads != 0 &&
                !process.ActiveProcessLinksSeen &&
                !process.SystemProcessInformationSeen &&
                !process.ToolhelpProcessSeen &&
                process.ActiveProcessLinksRevalidated &&
                process.ActiveProcessLinksStableUnlinked &&
                process.CidApiViewsRevalidated &&
                process.CidIdentityRevalidated)
            {
                evidence[L"cid_view"] =
                    L"full_process_enumeration";
                evidence[L"snapshot_race_possible"] =
                    L"false";
                AddFinding(
                    result,
                    process,
                    L"high",
                    L"high",
                    L"process_cross_view",
                    L"process is present only in the full CID-table process view",
                    0,
                    L"",
                    {L"cid_only_process",
                     L"missing_from_active_process_links",
                     L"missing_from_user_api_views",
                     L"possible_full_process_dkom"},
                    evidence);
            }
            else if (process.ActiveProcessLinksSeen &&
                !process.SystemProcessInformationSeen &&
                !process.ToolhelpProcessSeen)
            {
                // Lookup-only: confirms an already-known PID is still in CID,
                // not an independent hidden-process discovery surface.
                bool cidTableConfirmsHidden =
                    process.HasCidTableView &&
                    process.CidTableSeen;
                evidence[L"cid_view"] =
                    process.CidTableEnumerated
                        ? L"full_process_enumeration"
                        : L"known_pid_lookup";
                evidence[L"snapshot_race_possible"] = cidTableConfirmsHidden ? L"false" : L"true";
                if (!cidTableConfirmsHidden)
                {
                    evidence[L"weak_cross_view_only"] = L"true";
                }

                AddFinding(
                    result,
                    process,
                    cidTableConfirmsHidden ? L"medium" : L"low",
                    cidTableConfirmsHidden ? L"medium" : L"low",
                    L"process_cross_view",
                    L"process is visible in ActiveProcessLinks but missing from user API views",
                    0,
                    L"",
                    {L"kernel_only_process", L"process_view_mismatch"},
                    evidence);
            }
            else if (!process.ActiveProcessLinksSeen &&
                     (process.SystemProcessInformationSeen || process.ToolhelpProcessSeen) &&
                     process.ActiveProcessLinksRevalidated &&
                     process.ActiveProcessLinksStableUnlinked)
            {
                const bool cidConfirms =
                    process.HasCidTableView && process.CidTableSeen;
                evidence[L"cid_view"] =
                    process.CidTableEnumerated
                        ? L"full_process_enumeration"
                        : L"known_pid_lookup";
                evidence[L"snapshot_race_possible"] = cidConfirms ? L"false" : L"true";
                if (cidConfirms)
                {
                    evidence[L"cid_lookup"] = L"present";
                }
                std::vector<std::wstring> reasons = {
                    L"api_only_process",
                    L"missing_from_active_process_links"};
                if (cidConfirms)
                {
                    reasons.push_back(L"cid_known_pid_present");
                    reasons.push_back(L"possible_activeprocesslinks_unlink");
                }
                AddFinding(
                    result,
                    process,
                    cidConfirms ? L"medium" : L"low",
                    cidConfirms ? L"medium" : L"low",
                    L"process_cross_view",
                    cidConfirms
                        ? L"process is visible to user APIs and known-PID CID lookup but missing from ActiveProcessLinks"
                        : L"process is visible through user API views but missing from ActiveProcessLinks",
                    0,
                    L"",
                    reasons,
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
                !SameLeafOrEprocessImageNamePrefix(process.KernelImageName, process.ApiImagePath))
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
                !SameLeafOrEprocessImageNamePrefix(process.KernelImageName, process.PebImagePath))
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
                CommandLineImageIsComparable(
                    commandImage) &&
                !SameNonEmptyLeaf(
                    process.PebImagePath,
                    commandImage) &&
                !IsTrustedWindowsTerminalExecutionAlias(
                    process,
                    commandImage))
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

            std::vector<std::wstring> metadataReasons;
            AddImageMetadataEvidence(
                imagePath,
                profile != nullptr || gentlemenStagingPath,
                &metadataReasons,
                &evidence);
            bool metadataEvasionEvidence =
                ContainsWideValue(metadataReasons, L"edr_killer_invalid_code_signature") ||
                ContainsWideValue(metadataReasons, L"edr_killer_version_info_impersonation_evidence") ||
                ContainsWideValue(metadataReasons, L"edr_killer_icon_impersonation_evidence") ||
                ContainsWideValue(metadataReasons, L"edr_killer_packer_section_evidence");
            if (profile == nullptr &&
                gentlemenStagingPath &&
                !metadataEvasionEvidence)
            {
                break;
            }
            for (const std::wstring& metadataReason : metadataReasons)
            {
                AddUnique(&reasons, metadataReason);
            }

            if (gentlemenStagingPath)
            {
                AddUnique(&reasons, L"gentlemen_collection_staging_path");
                evidence[L"gentlemen_collection_path"] = L"true";
            }

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

    void AddEsetFileHashProcessFinding(
        HuntResult* result,
        const HuntProcessRecord& process,
        std::map<std::wstring, FileSha1CacheEntry>* fileSha1Cache)
    {
        do
        {
            if (result == nullptr || process.ProcessId <= 4)
            {
                break;
            }

            std::wstring imagePath = BestProcessImagePath(process);
            if (imagePath.empty())
            {
                break;
            }

            FileSha1CacheEntry hash = {};
            if (!GetCachedFileSha1(imagePath, fileSha1Cache, &hash))
            {
                break;
            }

            const EsetFileSha1Ioc* ioc = FindEsetFileSha1Ioc(hash.Sha1, true, false);
            if (ioc == nullptr)
            {
                break;
            }

            std::vector<std::wstring> reasons;
            std::map<std::wstring, std::wstring> evidence;
            evidence[L"image_name"] = BestProcessImageName(process);
            evidence[L"image_path"] = imagePath;
            evidence[L"peb_image_path"] = process.PebImagePath;
            evidence[L"peb_command_line"] = process.PebCommandLine;
            AddEsetFileHashEvidence(*ioc, hash.Path, hash.Sha1, &reasons, &evidence);

            if (PathContainsGentlemenCollection(imagePath) ||
                PathContainsGentlemenCollection(process.PebCommandLine))
            {
                AddUnique(&reasons, L"gentlemen_collection_staging_path");
                evidence[L"gentlemen_collection_path"] = L"true";
            }

            AddFinding(
                result,
                process,
                L"high",
                L"high",
                ioc->CredentialTool ? L"oxideharvest_file_ioc" : L"edr_killer_file_ioc",
                ioc->CredentialTool
                    ? L"process image matches ESET OxideHarvest SHA1 IOC"
                    : L"process image matches ESET Gentlemen EDR-killer SHA1 IOC",
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

    bool HuntTextTargetsKnownSecurityProduct(
        const std::wstring& text,
        std::wstring* matchedTarget)
    {
        HuntTelemetryEvent event = {};
        event.TargetImageBase = text;
        event.TaskName = text;
        event.Payload.push_back({L"text", text});
        return ThreatIntelEventTargetsKnownSecurityProduct(event, matchedTarget);
    }

    bool HuntTextTargetsKnownAntiCheat(
        const std::wstring& text,
        std::wstring* matchedTarget)
    {
        bool matched = false;

        static const wchar_t* kTargets[] =
        {
            L"vgc.exe",
            L"vgk.sys",
            L"riotclientservices.exe",
            L"easyanticheat.exe",
            L"easyanticheat_eos.exe",
            L"eac_launcher.exe",
            L"eaanticheat.exe",
            L"eaanticheat.gameservice.exe",
            L"eaanticheatlight.exe",
            L"beservice.exe",
            L"battleye.exe",
            L"belauncher.exe",
            L"bedaisy.sys",
            L"faceitclient.exe",
            L"faceitservice.exe",
            L"faceit.sys",
            L"equ8.exe",
            L"equ8_service.exe",
            L"xigncode3.exe",
            L"xigncode3.sys",
            L"xhunter1.sys",
            L"mhyprot2.sys",
            L"ace.exe",
            L"ace-base.sys",
            L"ace-guard.sys",
            L"tessafe.sys",
            L"tensafe.sys",
            L"gamedriverx64.sys"
        };

        do
        {
            std::wstring lowered = HuntToLower(text);
            std::wstring leaf = LeafName(text);

            for (const wchar_t* target : kTargets)
            {
                if (target == nullptr || target[0] == L'\0')
                {
                    continue;
                }

                std::wstring targetName = HuntToLower(target);
                if (leaf == targetName ||
                    HuntTextContainsDelimitedProcessLeaf(lowered, targetName))
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

    bool WfpFilterIsDisabled(const WfpRecord& record)
    {
        return HuntToLower(record.FlagsText).find(L"disabled") != std::wstring::npos;
    }

    bool WfpFilterBlocksTraffic(const WfpRecord& record)
    {
        std::wstring action = HuntToLower(record.ActionText);
        return action == L"block" || action == L"bitmaskblock";
    }

    bool WfpFilterHasHighWeight(const WfpRecord& record)
    {
        std::wstring weight = HuntToLower(record.WeightText);
        return weight.find(L"ffffffffffffffff") != std::wstring::npos ||
            weight.find(L"0xffffffffffffffff") != std::wstring::npos;
    }

    std::wstring WfpRecordTargetText(const WfpRecord& record)
    {
        std::wstring text;
        text += record.AppIdText;
        text += L" ";
        text += record.ConditionsText;
        text += L" ";
        text += record.Name;
        text += L" ";
        text += record.Description;
        text += L" ";
        text += record.ProviderName;
        text += L" ";
        text += record.ProviderService;
        text += L" ";
        text += record.SubLayerName;
        return text;
    }

    bool AddWfpFilterRecordFinding(
        HuntResult* result,
        const WfpRecord& record)
    {
        if (result == nullptr ||
            record.Kind != L"wfp.filter" ||
            WfpFilterIsDisabled(record) ||
            !WfpFilterBlocksTraffic(record))
        {
            return false;
        }

        const std::wstring appTarget =
            record.HasAppIdCondition
                ? record.AppIdText
                : L"";
        const std::wstring fullTargetText =
            WfpRecordTargetText(record);
        std::wstring securityTarget;
        std::wstring antiCheatTarget;
        const bool appTargetsSecurityProduct =
            !appTarget.empty() &&
            HuntTextTargetsKnownSecurityProduct(
                appTarget,
                &securityTarget);
        const bool appTargetsAntiCheat =
            !appTarget.empty() &&
            HuntTextTargetsKnownAntiCheat(
                appTarget,
                &antiCheatTarget);
        const bool textTargetsSecurityProduct =
            !appTargetsSecurityProduct &&
            HuntTextTargetsKnownSecurityProduct(
                fullTargetText,
                &securityTarget);
        const bool textTargetsAntiCheat =
            !appTargetsAntiCheat &&
            HuntTextTargetsKnownAntiCheat(
                fullTargetText,
                &antiCheatTarget);
        const bool targetsSecurityProduct =
            appTargetsSecurityProduct ||
            textTargetsSecurityProduct;
        const bool targetsAntiCheat =
            appTargetsAntiCheat ||
            textTargetsAntiCheat;
        if (!targetsSecurityProduct &&
            !targetsAntiCheat)
        {
            return false;
        }

        const bool appIdBacked =
            appTargetsSecurityProduct ||
            appTargetsAntiCheat;
        const std::wstring loweredFlags =
            HuntToLower(record.FlagsText);
        std::vector<std::wstring> reasons;
        if (targetsSecurityProduct)
        {
            AddUnique(
                &reasons,
                L"wfp_security_product_block_filter");
        }
        if (targetsAntiCheat)
        {
            AddUnique(
                &reasons,
                L"wfp_anticheat_block_filter");
        }
        if (appIdBacked)
        {
            AddUnique(
                &reasons,
                L"wfp_appid_block_condition");
        }
        if (loweredFlags.find(
                L"persistent") !=
            std::wstring::npos)
        {
            AddUnique(
                &reasons,
                L"wfp_persistent_block_filter");
        }
        if (loweredFlags.find(
                L"clearactionright") !=
            std::wstring::npos)
        {
            AddUnique(
                &reasons,
                L"wfp_clear_action_right_block");
        }
        if (WfpFilterHasHighWeight(record))
        {
            AddUnique(
                &reasons,
                L"wfp_high_weight_block_filter");
        }
        AddUnique(
            &reasons,
            L"security_tool_communication_blocking");

        std::map<std::wstring, std::wstring>
            evidence;
        evidence[L"filter_id"] =
            std::to_wstring(record.Id);
        evidence[L"filter_key"] =
            record.Key;
        evidence[L"filter_name"] =
            record.Name;
        evidence[L"filter_description"] =
            record.Description;
        evidence[L"action"] =
            record.ActionText;
        evidence[L"weight"] =
            record.WeightText;
        evidence[L"flags"] =
            record.FlagsText;
        evidence[L"layer"] =
            record.LayerName;
        evidence[L"layer_key"] =
            record.LayerKey;
        evidence[L"sublayer"] =
            record.SubLayerName;
        evidence[L"sublayer_key"] =
            record.SubLayerKey;
        evidence[L"provider"] =
            record.ProviderName;
        evidence[L"provider_service"] =
            record.ProviderService;
        evidence[L"provider_key"] =
            record.ProviderKey;
        evidence[L"app_id"] =
            record.AppIdText;
        evidence[L"conditions"] =
            record.ConditionsText;
        evidence[L"target_source"] =
            appIdBacked
                ? L"app_id_condition"
                : L"filter_metadata";
        evidence[L"matched_security_target"] =
            securityTarget;
        evidence[L"matched_anticheat_target"] =
            antiCheatTarget;

        const bool hardBlock =
            appIdBacked &&
            (loweredFlags.find(
                 L"persistent") !=
                 std::wstring::npos ||
             loweredFlags.find(
                 L"clearactionright") !=
                 std::wstring::npos ||
             WfpFilterHasHighWeight(record));
        std::vector<std::wstring> followups;
        if (!record.LayerName.empty())
        {
            followups.push_back(
                L"!wfp filters /layer " +
                record.LayerName);
        }
        if (!record.ProviderName.empty())
        {
            followups.push_back(
                L"!wfp filters /provider " +
                record.ProviderName);
        }

        AddSystemFinding(
            result,
            hardBlock ? L"high" : L"medium",
            appIdBacked ? L"high" : L"medium",
            L"network_filter_tampering",
            L"WFP block filter targets security or anti-cheat process communication",
            0,
            L"",
            reasons,
            evidence,
            followups);
        ++result->SuspiciousWfpFilterCount;
        return true;
    }

    void AddWfpHuntFindings(HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            WfpScanner scanner;
            WfpScanner::Options options = {};
            options.Target = WfpScanner::Scope::Filters;

            WfpScanResult scan = {};
            std::wstring error;
            const bool scanSucceeded =
                scanner.Scan(
                    options,
                    &scan,
                    &error);
            result->WfpFilterCount =
                scan.Records.size();
            for (const std::wstring& warning :
                 scan.Warnings)
            {
                AddUnique(
                    &result->Warnings,
                    L"WFP filter warning: " +
                        warning);
            }
            if (!scanSucceeded ||
                !scan.Warnings.empty())
            {
                result->WfpFilterCoverageIncomplete =
                    true;
                result->CoverageComplete = false;
                AddUnique(
                    &result->Warnings,
                    error.empty()
                        ? L"WFP filter scan failed or incomplete"
                        : L"WFP filter scan failed or incomplete: " +
                              error);
                if (!scanSucceeded)
                {
                    break;
                }
            }

            for (const WfpRecord& record :
                 scan.Records)
            {
                AddWfpFilterRecordFinding(
                    result,
                    record);
            }
        } while (false);
    }

    bool AddQosPolicyRecordFinding(
        HuntResult* result,
        const QosPolicyRecord& record)
    {
        if (result == nullptr ||
            !QosPolicyHasSevereThrottle(record))
        {
            return false;
        }

        std::wstring securityTarget;
        if (!HuntTextTargetsKnownSecurityProduct(
                record.AppPathName,
                &securityTarget))
        {
            return false;
        }

        const bool nearZeroThrottle =
            record.ThrottleRateBitsPerSecond <=
                1024ull * 8ull;
        std::map<std::wstring, std::wstring> evidence;
        evidence[L"policy_name"] = record.Name;
        evidence[L"instance_id"] = record.InstanceId;
        evidence[L"owner"] = record.Owner;
        evidence[L"app_path"] = record.AppPathName;
        evidence[L"security_product_target"] =
            securityTarget;
        evidence[L"throttle_rate_bytes_per_second"] =
            std::to_wstring(
                record.ThrottleRateBitsPerSecond /
                    8ull);
        evidence[L"throttle_rate_bits_per_second"] =
            std::to_wstring(
                record.ThrottleRateBitsPerSecond);
        evidence[L"near_zero_throttle"] =
            nearZeroThrottle ? L"true" : L"false";
        evidence[L"active_store"] =
            record.FromActiveStore
                ? L"true"
                : L"false";
        evidence[L"network_profile"] =
            std::to_wstring(record.NetworkProfile);
        evidence[L"precedence"] =
            std::to_wstring(record.Precedence);

        AddSystemFinding(
            result,
            nearZeroThrottle ? L"high" : L"medium",
            L"high",
            L"network_policy_tampering",
            L"QoS policy severely throttles a known security-product process",
            0,
            L"pacer.sys",
            {
                L"qos_security_product_throttle_policy",
                L"security_tool_communication_throttling",
                L"edrchoker_state"
            },
            evidence,
            {
                L"Get-NetQosPolicy -PolicyStore ActiveStore",
                L"Get-NetQosPolicy"
            });
        ++result->SuspiciousQosPolicyCount;
        return true;
    }

    void AddQosPolicyHuntFindings(HuntResult* result)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            QosPolicyScanner scanner;
            QosPolicyScanResult scan = {};
            std::wstring error;
            const bool scanSucceeded =
                scanner.Scan(&scan, &error);
            for (const std::wstring& warning :
                 scan.Warnings)
            {
                AddUnique(
                    &result->Warnings,
                    L"QoS policy warning: " +
                        warning);
            }
            if (!scanSucceeded ||
                !scan.CoverageComplete)
            {
                result->QosPolicyCoverageIncomplete =
                    true;
                result->CoverageComplete = false;
                AddUnique(
                    &result->Warnings,
                    error.empty()
                        ? L"QoS policy scan failed or incomplete"
                        : L"QoS policy scan failed or incomplete: " +
                              error);
                break;
            }

            result->QosPolicyCount =
                scan.Records.size();
            for (const QosPolicyRecord& record :
                 scan.Records)
            {
                AddQosPolicyRecordFinding(result, record);
            }
        } while (false);
    }

    std::wstring NormalizeBindFilterPath(
        const std::wstring& value)
    {
        std::wstring normalized = HuntToLower(value);
        std::replace(
            normalized.begin(),
            normalized.end(),
            L'/',
            L'\\');
        while (normalized.size() > 3 &&
               normalized.back() == L'\\')
        {
            normalized.pop_back();
        }
        return normalized;
    }

    std::vector<std::wstring>
    BindFilterPathSegments(
        const std::wstring& value)
    {
        const std::wstring path =
            NormalizeBindFilterPath(value);
        std::vector<std::wstring> segments;
        size_t start = 0;
        while (start <= path.size())
        {
            const size_t separator =
                path.find(L'\\', start);
            const size_t end =
                separator == std::wstring::npos
                    ? path.size()
                    : separator;
            const std::wstring segment =
                path.substr(start, end - start);
            if (!segment.empty() &&
                segment != L".")
            {
                if (segment == L"..")
                {
                    if (!segments.empty() &&
                        segments.back() != L"..")
                    {
                        segments.pop_back();
                    }
                    else
                    {
                        segments.push_back(segment);
                    }
                }
                else
                {
                    segments.push_back(segment);
                }
            }

            if (separator == std::wstring::npos)
            {
                break;
            }
            start = separator + 1;
        }
        return segments;
    }

    std::wstring BindFilterDevicePathInVolume(
        const BindFilterMappingRecord& record,
        const std::wstring& path)
    {
        if (record.VolumeRoot.size() >= 2 &&
            record.VolumeRoot[1] == L':')
        {
            wchar_t drive[] =
            {
                record.VolumeRoot[0],
                L':',
                L'\0'
            };
            wchar_t targets[1024] = {};
            const DWORD length = QueryDosDeviceW(
                drive,
                targets,
                static_cast<DWORD>(
                    _countof(targets)));
            if (length != 0)
            {
                const std::wstring normalizedPath =
                    NormalizeBindFilterPath(path);
                const wchar_t* target = targets;
                while (*target != L'\0')
                {
                    const size_t targetLength =
                        std::wcslen(target);
                    const std::wstring normalizedTarget =
                        NormalizeBindFilterPath(target);
                    if (normalizedPath.compare(
                            0,
                            normalizedTarget.size(),
                            normalizedTarget) == 0 &&
                        (normalizedPath.size() ==
                             normalizedTarget.size() ||
                         normalizedPath[
                             normalizedTarget.size()] ==
                             L'\\'))
                    {
                        return std::wstring(drive) +
                            path.substr(targetLength);
                    }
                    target += targetLength + 1;
                }
            }
        }
        return DosPathFromDevicePath(path);
    }

    std::wstring BindFilterPathInVolume(
        const BindFilterMappingRecord& record,
        const std::wstring& value)
    {
        std::wstring path = value;
        std::replace(
            path.begin(),
            path.end(),
            L'/',
            L'\\');

        const std::wstring normalized =
            NormalizeBindFilterPath(path);
        if (normalized.compare(
                0,
                8,
                L"\\device\\") == 0)
        {
            // BindFlt can return native device paths even when queried for a
            // DOS volume. Convert mapped devices, but never reinterpret an
            // unresolved "\Device\..." name as volume-root-relative.
            return BindFilterDevicePathInVolume(
                record,
                path);
        }
        if (normalized.compare(
                0,
                4,
                L"\\??\\") == 0 ||
            normalized.compare(
                0,
                4,
                L"\\\\?\\") == 0)
        {
            path = DosPathFromDevicePath(
                Win32FilePathFromMaybeNtPath(path));
        }
        if (!IsRootRelativePath(path) ||
            record.VolumeRoot.empty())
        {
            return path;
        }

        return EnsureTrailingSlash(
                   record.VolumeRoot) +
            path.substr(1);
    }

    bool BindFilterPathUnderDirectory(
        const std::wstring& value,
        const std::wstring& directory)
    {
        std::vector<std::wstring> path =
            BindFilterPathSegments(
                CanonicalPathForCompare(value));
        std::vector<std::wstring> base =
            BindFilterPathSegments(
                CanonicalPathForCompare(directory));
        if (path.empty() ||
            base.empty())
        {
            return false;
        }

        size_t pathStart = 0;
        size_t baseStart = 0;
        if (path[0] != base[0])
        {
            const bool pathDrive =
                path[0].size() == 2 &&
                path[0][1] == L':';
            const bool baseDrive =
                base[0].size() == 2 &&
                base[0][1] == L':';
            if (pathDrive && !baseDrive)
            {
                pathStart = 1;
            }
            else if (!pathDrive && baseDrive)
            {
                baseStart = 1;
            }
        }

        const size_t pathCount =
            path.size() - pathStart;
        const size_t baseCount =
            base.size() - baseStart;
        if (pathCount <= baseCount)
        {
            return false;
        }
        for (size_t index = 0;
             index < baseCount;
             ++index)
        {
            if (path[pathStart + index] !=
                base[baseStart + index])
            {
                return false;
            }
        }
        return true;
    }

    bool BindFilterPathIsProtected(
        const std::wstring& value)
    {
        return BindFilterPathUnderDirectory(
                   value,
                   EnsureTrailingSlash(
                       WindowsDirectory()) +
                       L"System32") ||
            BindFilterPathUnderDirectory(
                value,
                EnsureTrailingSlash(
                    WindowsDirectory()) +
                    L"SysWOW64") ||
            BindFilterPathUnderDirectory(
                value,
                ProgramFilesDirectory()) ||
            BindFilterPathUnderDirectory(
                value,
                ProgramFilesX86Directory());
    }

    bool BindFilterPathIsWindowsSystem(
        const std::wstring& value)
    {
        return BindFilterPathUnderDirectory(
                   value,
                   EnsureTrailingSlash(
                       WindowsDirectory()) +
                       L"System32") ||
            BindFilterPathUnderDirectory(
                value,
                EnsureTrailingSlash(
                    WindowsDirectory()) +
                    L"SysWOW64");
    }

    bool BindFilterPathIsUserControlledShape(
        const std::wstring& value)
    {
        const std::vector<std::wstring> segments =
            BindFilterPathSegments(
                CanonicalPathForCompare(value));
        if (segments.empty())
        {
            return false;
        }

        size_t rootIndex = 0;
        if (segments[0].size() == 2 &&
            segments[0][1] == L':')
        {
            rootIndex = 1;
        }
        if (rootIndex >= segments.size())
        {
            return false;
        }

        const std::wstring& root =
            segments[rootIndex];
        if (root == L"users" ||
            root == L"programdata" ||
            root == L"temp")
        {
            return segments.size() >
                rootIndex + 1;
        }

        return root == L"windows" &&
            segments.size() > rootIndex + 2 &&
            segments[rootIndex + 1] == L"temp";
    }

    bool BindFilterPathIsSensitiveArtifact(
        const std::wstring& value)
    {
        const std::wstring leaf =
            LeafName(value);
        return leaf == L"amsi.dll" ||
            (leaf.size() > 5 &&
             leaf.compare(
                 leaf.size() - 5,
                 5,
                 L".evtx") == 0);
    }

    bool BindFilterPathIsExecutableImage(
        const std::wstring& value)
    {
        const std::wstring leaf = LeafName(value);
        static const wchar_t* kExtensions[] =
        {
            L".exe",
            L".dll",
            L".sys"
        };
        for (const wchar_t* extension : kExtensions)
        {
            const size_t length =
                std::wcslen(extension);
            if (leaf.size() > length &&
                leaf.compare(
                    leaf.size() - length,
                    length,
                    extension) == 0)
            {
                return true;
            }
        }
        return false;
    }

    bool BindFilterPathIsProcessImage(
        const std::wstring& value)
    {
        const std::wstring leaf = LeafName(value);
        return leaf.size() > 4 &&
            leaf.compare(
                leaf.size() - 4,
                4,
                L".exe") == 0;
    }

    bool BindFilterPairIsProcessBindingCandidate(
        const BindFilterMappingRecord& record,
        const std::wstring& target)
    {
        const std::wstring sourcePath =
            BindFilterPathInVolume(
                record,
                record.VirtualRoot);
        const std::wstring targetPath =
            BindFilterPathInVolume(
                record,
                target);
        if (!BindFilterPathIsProcessImage(
                sourcePath) ||
            !BindFilterPathIsProcessImage(
                targetPath) ||
            SameCanonicalPath(
                sourcePath,
                targetPath) ||
            LeafName(sourcePath) ==
                LeafName(targetPath))
        {
            return false;
        }

        std::wstring securityTarget;
        const bool securityPath =
            HuntTextTargetsKnownSecurityProduct(
                sourcePath + L" " +
                    targetPath,
                &securityTarget);
        const bool trustBoundary =
            (BindFilterPathIsProtected(
                 sourcePath) &&
             BindFilterPathIsUserControlledShape(
                 targetPath)) ||
            (BindFilterPathIsUserControlledShape(
                 sourcePath) &&
             BindFilterPathIsProtected(
                 targetPath));
        return BindFilterPathIsWindowsSystem(
                   sourcePath) ||
            BindFilterPathIsWindowsSystem(
                targetPath) ||
            securityPath ||
            trustBoundary;
    }

    std::vector<std::wstring>
    BindFilterVisibleSourceViews(
        const HuntProcessRecord& process,
        const std::wstring& source)
    {
        std::vector<std::wstring> views;
        if (SameCanonicalPath(
                process.ApiImagePath,
                source))
        {
            views.push_back(L"api_image_path");
        }
        if (SameCanonicalPath(
                process.PebImagePath,
                source))
        {
            views.push_back(L"peb_image_path");
        }
        if (SameCanonicalPath(
                process.DiskPath,
                source))
        {
            views.push_back(L"disk_path");
        }
        return views;
    }

    bool BindFilterMappingHasInverse(
        const BindFilterMappingRecord& record,
        const std::vector<BindFilterMappingRecord>&
            records)
    {
        const std::wstring resolvedSource =
            NormalizeBindFilterPath(
                BindFilterPathInVolume(
                    record,
                    record.VirtualRoot));
        for (const std::wstring& target :
             record.TargetRoots)
        {
            const std::wstring resolvedTarget =
                NormalizeBindFilterPath(
                    BindFilterPathInVolume(
                        record,
                        target));
            for (const BindFilterMappingRecord& candidate :
                 records)
            {
                const std::wstring candidateSource =
                    NormalizeBindFilterPath(
                        BindFilterPathInVolume(
                            candidate,
                            candidate.VirtualRoot));
                if (candidateSource !=
                    resolvedTarget)
                {
                    continue;
                }
                for (const std::wstring& candidateTarget :
                     candidate.TargetRoots)
                {
                    if (NormalizeBindFilterPath(
                            BindFilterPathInVolume(
                                candidate,
                                candidateTarget)) ==
                        resolvedSource)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    bool AddBindFilterMappingRecordFinding(
        HuntResult* result,
        const BindFilterMappingRecord& record,
        const std::vector<BindFilterMappingRecord>&
            records)
    {
        if (result == nullptr ||
            record.VirtualRoot.empty() ||
            record.TargetRoots.empty())
        {
            return false;
        }

        std::wstring joinedTargets =
            JoinWideValues(record.TargetRoots, L";");
        const std::wstring resolvedSource =
            BindFilterPathInVolume(
                record,
                record.VirtualRoot);
        std::vector<std::wstring>
            resolvedTargets;
        resolvedTargets.reserve(
            record.TargetRoots.size());
        for (const std::wstring& target :
             record.TargetRoots)
        {
            resolvedTargets.push_back(
                BindFilterPathInVolume(
                    record,
                    target));
        }
        const std::wstring joinedResolvedTargets =
            JoinWideValues(
                resolvedTargets,
                L";");
        std::wstring securityTarget;
        const bool securityPath =
            HuntTextTargetsKnownSecurityProduct(
                resolvedSource + L" " +
                    joinedResolvedTargets,
                &securityTarget);
        bool sensitiveArtifact =
            BindFilterPathIsSensitiveArtifact(
                resolvedSource);
        bool forwardTrustBoundary = false;
        bool reverseTrustBoundary = false;
        bool protectedFileRedirect = false;
        bool inverseProtectedFileRedirect = false;
        for (const std::wstring& target :
             resolvedTargets)
        {
            sensitiveArtifact =
                sensitiveArtifact ||
                BindFilterPathIsSensitiveArtifact(
                    target);
            forwardTrustBoundary =
                forwardTrustBoundary ||
                (BindFilterPathIsProtected(
                     resolvedSource) &&
                 BindFilterPathIsUserControlledShape(
                     target));
            reverseTrustBoundary =
                reverseTrustBoundary ||
                (BindFilterPathIsUserControlledShape(
                     resolvedSource) &&
                 BindFilterPathIsProtected(target));
            const bool distinctPath =
                NormalizeBindFilterPath(
                    resolvedSource) !=
                NormalizeBindFilterPath(target);
            const bool distinctImageLeaf =
                LeafName(record.VirtualRoot) !=
                LeafName(target);
            protectedFileRedirect =
                protectedFileRedirect ||
                (distinctPath &&
                 distinctImageLeaf &&
                 BindFilterPathIsWindowsSystem(
                     resolvedSource) &&
                 BindFilterPathIsExecutableImage(
                     resolvedSource) &&
                 BindFilterPathIsExecutableImage(
                     target));
            inverseProtectedFileRedirect =
                inverseProtectedFileRedirect ||
                (distinctPath &&
                 distinctImageLeaf &&
                 !BindFilterPathIsWindowsSystem(
                     resolvedSource) &&
                 BindFilterPathIsExecutableImage(
                     resolvedSource) &&
                 BindFilterPathIsWindowsSystem(target) &&
                 BindFilterPathIsExecutableImage(
                     target));
        }
        const bool inversePair =
            BindFilterMappingHasInverse(
                record,
                records);
        if (!securityPath &&
            !sensitiveArtifact &&
            !forwardTrustBoundary &&
            !reverseTrustBoundary &&
            !protectedFileRedirect &&
            !inverseProtectedFileRedirect &&
            !inversePair)
        {
            return false;
        }

        std::vector<std::wstring> reasons =
        {
            L"bindflt_active_global_mapping"
        };
        if (securityPath)
        {
            AddUnique(
                &reasons,
                L"bind_link_security_product_path");
        }
        if (sensitiveArtifact)
        {
            AddUnique(
                &reasons,
                L"bind_link_security_artifact_path");
        }
        if (forwardTrustBoundary)
        {
            AddUnique(
                &reasons,
                L"bind_link_protected_to_user_path");
        }
        if (reverseTrustBoundary)
        {
            AddUnique(
                &reasons,
                L"bind_link_inverse_trust_mapping");
        }
        if (protectedFileRedirect)
        {
            AddUnique(
                &reasons,
                L"bind_link_protected_image_redirect");
        }
        if (inverseProtectedFileRedirect)
        {
            AddUnique(
                &reasons,
                L"bind_link_inverse_image_redirect");
        }
        if (inversePair)
        {
            AddUnique(
                &reasons,
                L"bind_link_inverse_pair");
        }

        std::map<std::wstring, std::wstring> evidence;
        evidence[L"volume_root"] = record.VolumeRoot;
        evidence[L"virtual_root"] =
            record.VirtualRoot;
        evidence[L"resolved_virtual_root"] =
            resolvedSource;
        evidence[L"target_roots"] =
            joinedTargets;
        evidence[L"resolved_target_roots"] =
            joinedResolvedTargets;
        evidence[L"target_count"] =
            std::to_wstring(record.TargetRoots.size());
        evidence[L"mapping_flags"] =
            HuntHex(record.Flags, 8);
        evidence[L"reparse_on_files"] =
            (record.Flags & 0x8u) != 0
                ? L"true"
                : L"false";
        evidence[L"security_product_target"] =
            securityTarget;
        evidence[L"global_mapping"] = L"true";
        evidence[L"silo_mapping_coverage"] =
            L"unsupported";

        const bool decisive =
            securityPath ||
            sensitiveArtifact ||
            forwardTrustBoundary ||
            protectedFileRedirect ||
            inversePair;
        AddSystemFinding(
            result,
            decisive ? L"high" : L"medium",
            decisive ? L"high" : L"medium",
            L"filesystem_virtualization_tampering",
            L"active Bind Filter mapping crosses a security-sensitive path boundary",
            0,
            L"bindflt.sys",
            reasons,
            evidence,
            {
                L"!hunt /deep /details",
                L"inspect bindflt mapping source and backing file identities"
            });
        ++result->SuspiciousBindFilterMappingCount;
        return true;
    }

    void AddBindFilterProcessBindingFindings(
        HuntResult* result,
        const std::vector<BindFilterMappingRecord>&
            records,
        const std::map<uint32_t, HuntProcessRecord>&
            processes)
    {
        if (result == nullptr)
        {
            return;
        }

        std::set<std::wstring> emitted;
        for (const BindFilterMappingRecord& record :
             records)
        {
            for (const std::wstring& target :
                 record.TargetRoots)
            {
                const std::wstring resolvedSource =
                    BindFilterPathInVolume(
                        record,
                        record.VirtualRoot);
                const std::wstring resolvedTarget =
                    BindFilterPathInVolume(
                        record,
                        target);
                if (!BindFilterPairIsProcessBindingCandidate(
                        record,
                        target))
                {
                    continue;
                }

                for (const auto& processItem :
                     processes)
                {
                    const HuntProcessRecord& process =
                        processItem.second;
                    const std::vector<std::wstring>
                        sourceViews =
                            BindFilterVisibleSourceViews(
                                process,
                                resolvedSource);
                    if (sourceViews.empty())
                    {
                        continue;
                    }

                    const bool mainSectionResolved =
                        process.MainSectionBackingState ==
                            L"resolved" &&
                        !process.MainSectionBackingPath.empty();
                    const bool vadSectionResolved =
                        process.SectionBackingState ==
                            L"resolved" &&
                        !process.SectionBackingPath.empty();
                    if (!mainSectionResolved ||
                        !vadSectionResolved)
                    {
                        result->
                            BindFilterProcessCorrelationCoverageIncomplete =
                                true;
                        result->CoverageComplete = false;
                        AddUnique(
                            &result->Warnings,
                            L"bindflt Process-Binding correlation incomplete: a candidate mapping matched a visible process image path, but both independent image-backing views were not resolved");
                        continue;
                    }

                    if (!SameCanonicalPath(
                            process.MainSectionBackingPath,
                            resolvedTarget) ||
                        !SameCanonicalPath(
                            process.SectionBackingPath,
                            resolvedTarget) ||
                        !SameCanonicalPath(
                            process.MainSectionBackingPath,
                            process.SectionBackingPath))
                    {
                        continue;
                    }

                    const std::wstring key =
                        std::to_wstring(
                            process.ProcessId) +
                        L"|" +
                        CanonicalPathForCompare(
                            resolvedSource) +
                        L"|" +
                        CanonicalPathForCompare(
                            resolvedTarget);
                    if (!emitted.insert(key).second)
                    {
                        continue;
                    }

                    std::wstring securityTarget;
                    HuntTextTargetsKnownSecurityProduct(
                        resolvedSource + L" " +
                            resolvedTarget,
                        &securityTarget);
                    std::map<std::wstring, std::wstring>
                        evidence;
                    evidence[L"volume_root"] =
                        record.VolumeRoot;
                    evidence[L"virtual_root"] =
                        record.VirtualRoot;
                    evidence[L"resolved_virtual_root"] =
                        resolvedSource;
                    evidence[L"matched_target_root"] =
                        target;
                    evidence[L"resolved_target_root"] =
                        resolvedTarget;
                    evidence[L"mapping_flags"] =
                        HuntHex(record.Flags, 8);
                    evidence[L"global_mapping"] = L"true";
                    evidence[L"visible_source_views"] =
                        JoinWideValues(sourceViews, L";");
                    evidence[L"api_image_path"] =
                        process.ApiImagePath;
                    evidence[L"peb_image_path"] =
                        process.PebImagePath;
                    evidence[L"disk_path"] =
                        process.DiskPath;
                    evidence[L"main_section_backing_path"] =
                        process.MainSectionBackingPath;
                    evidence[L"main_section_backing_state"] =
                        process.MainSectionBackingState;
                    evidence[L"section_backing_path"] =
                        process.SectionBackingPath;
                    evidence[L"section_backing_state"] =
                        process.SectionBackingState;
                    evidence[L"main_section_object"] =
                        HuntHex(
                            process.MainSectionObject,
                            16);
                    evidence[L"main_section_segment"] =
                        HuntHex(
                            process.MainSectionSegment,
                            16);
                    evidence[L"main_section_control_area"] =
                        HuntHex(
                            process.MainSectionControlArea,
                            16);
                    evidence[L"security_product_target"] =
                        securityTarget;
                    evidence[
                        L"independent_backing_views_agree"] =
                            L"true";
                    evidence[L"silo_mapping_coverage"] =
                        L"unsupported";

                    AddFinding(
                        result,
                        process,
                        L"high",
                        L"high",
                        L"filesystem_virtualization_tampering",
                        L"active Bind Filter mapping makes the visible process image path differ from its actual image backing",
                        process.MainImageBase,
                        LeafName(resolvedSource),
                        {
                            L"bindflt_active_global_mapping",
                            L"bind_link_process_binding_state",
                            L"bind_link_process_backing_correlation"
                        },
                        evidence);
                    ++result->
                        BindFilterProcessBindingCount;
                }
            }
        }
    }

    void AddBindFilterHuntFindings(
        HuntResult* result,
        const std::map<uint32_t, HuntProcessRecord>&
            processes)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            result->BindFilterSiloCoverageUnsupported =
                true;
            BindFilterScanner scanner;
            BindFilterScanResult scan = {};
            std::wstring error;
            bool scanStarted =
                scanner.ScanGlobal(&scan, &error);
            result->BindFilterMappingCount =
                scan.Records.size();
            for (const std::wstring& warning :
                 scan.Warnings)
            {
                AddUnique(
                    &result->Warnings,
                    L"bindflt mapping warning: " +
                        warning);
            }
            if (!scanStarted ||
                !scan.GlobalCoverageComplete)
            {
                result->BindFilterGlobalCoverageIncomplete =
                    true;
                result->CoverageComplete = false;
                AddUnique(
                    &result->Warnings,
                    L"bindflt global mapping scan failed or incomplete: " +
                        error);
                break;
            }

            for (const BindFilterMappingRecord& record :
                 scan.Records)
            {
                AddBindFilterMappingRecordFinding(
                    result,
                    record,
                    scan.Records);
            }
            AddBindFilterProcessBindingFindings(
                result,
                scan.Records,
            processes);
        } while (false);
    }

    struct CloudFileMappingDecision
    {
        bool IsPlaceholder = false;
        bool EmitFinding = false;
        bool MetadataCoverageIncomplete = false;
        bool ProtectionCoverageIncomplete = false;
        std::wstring Risk;
        std::wstring Confidence;
        std::wstring Title;
        std::vector<std::wstring> Reasons;
    };

    bool IsDeepImageMismatchReason(
        const std::wstring& reason)
    {
        return
            reason ==
                L"disk_live_image_mismatch" ||
            reason ==
                L"main_image_entrypoint_mismatch" ||
            reason ==
                L"main_image_hash_mismatch" ||
            reason ==
                L"live_disk_exec_page_mismatch" ||
            reason ==
                L"module_entrypoint_mismatch" ||
            reason ==
                L"module_text_mismatch";
    }

    bool FindDeepImageMismatchForModule(
        const HuntResult& result,
        const HuntProcessRecord& process,
        const HuntModuleRecord& module,
        std::vector<std::wstring>* reasons,
        uint64_t* address)
    {
        uint64_t moduleEnd = 0;
        if (module.Base == 0 ||
            module.Size == 0 ||
            !TryAdd(
                module.Base,
                module.Size,
                &moduleEnd))
        {
            return false;
        }

        bool matched = false;
        for (const HuntFinding& finding :
             result.Findings)
        {
            if (finding.ProcessId !=
                    process.ProcessId ||
                finding.Address <
                    module.Base ||
                finding.Address >=
                    moduleEnd)
            {
                continue;
            }

            for (const std::wstring& reason :
                 finding.ReasonCodes)
            {
                if (!IsDeepImageMismatchReason(
                        reason))
                {
                    continue;
                }

                matched = true;
                if (reasons != nullptr)
                {
                    AddUnique(
                        reasons,
                        reason);
                }
                if (address != nullptr &&
                    *address == 0)
                {
                    *address =
                        finding.Address;
                }
            }
        }
        return matched;
    }

    CloudFileMappingDecision
    EvaluateCloudFileMapping(
        const CloudFilePlaceholderRecord& placeholder,
        bool hasProtection,
        uint8_t protection,
        bool hasDeepMismatch,
        const std::vector<std::wstring>&
            mismatchReasons)
    {
        CloudFileMappingDecision decision = {};
        if (!placeholder.IsCloudPlaceholder)
        {
            return decision;
        }

        if (!placeholder.MetadataCoverageComplete ||
            !placeholder.PlaceholderStateAvailable ||
            !placeholder.PlaceholderInfoAvailable)
        {
            decision.MetadataCoverageIncomplete =
                true;
            return decision;
        }

        constexpr uint32_t kPlaceholderState =
            0x00000001;
        if ((placeholder.PlaceholderState &
             kPlaceholderState) == 0)
        {
            return decision;
        }

        decision.IsPlaceholder = true;
        const bool protectedProcess =
            hasProtection &&
            (protection & 0x7u) != 0;
        const bool modified =
            placeholder.ModifiedDataSize > 0;

        if (hasDeepMismatch)
        {
            decision.EmitFinding = true;
            decision.Risk = L"high";
            decision.Confidence = L"high";
            decision.Title =
                L"Cloud Files executable placeholder has correlated live-versus-disk image divergence";
            decision.Reasons =
            {
                L"cloudfiles_executable_placeholder_mapping",
                L"cloudfiles_ffi_live_disk_mismatch"
            };
            for (const std::wstring& reason :
                 mismatchReasons)
            {
                AddUnique(
                    &decision.Reasons,
                    reason);
            }
        }
        else if (protectedProcess)
        {
            decision.EmitFinding = true;
            decision.Risk = L"high";
            decision.Confidence = L"high";
            decision.Title =
                L"protected process maps an executable Cloud Files placeholder";
            decision.Reasons =
            {
                L"cloudfiles_executable_placeholder_mapping",
                L"cloudfiles_ffi_ppl_image_mapping"
            };
        }
        else if (modified)
        {
            decision.EmitFinding = true;
            decision.Risk = L"medium";
            decision.Confidence = L"high";
            decision.Title =
                L"mapped Cloud Files executable placeholder reports modified data";
            decision.Reasons =
            {
                L"cloudfiles_executable_placeholder_mapping",
                L"cloudfiles_placeholder_modified_data"
            };
        }
        else if (!hasProtection)
        {
            // An in-sync, unmodified placeholder is a clean negative only when
            // the process protection gate is known not to be PP/PPL.
            decision.ProtectionCoverageIncomplete =
                true;
        }

        if (decision.EmitFinding &&
            protectedProcess)
        {
            AddUnique(
                &decision.Reasons,
                L"cloudfiles_ffi_ppl_image_mapping");
        }
        if (decision.EmitFinding &&
            modified)
        {
            AddUnique(
                &decision.Reasons,
                L"cloudfiles_placeholder_modified_data");
        }
        return decision;
    }

    bool IsCloudFileImageCandidate(
        const HuntModuleRecord& module)
    {
        return module.VadSectionSeen &&
            module.VadBackingState == L"resolved" &&
            !module.VadBackingPath.empty() &&
            module.Base != 0 &&
            module.Size != 0;
    }

    void AddCloudFileHuntFindings(
        HuntResult* result,
        const std::map<uint32_t, HuntProcessRecord>&
            processes)
    {
        if (result == nullptr)
        {
            return;
        }

        struct CachedPlaceholder
        {
            bool QuerySucceeded = false;
            std::wstring QueryError;
            CloudFilePlaceholderRecord Record;
        };

        CloudFileScanner scanner;
        std::map<std::wstring, CachedPlaceholder>
            cache;
        std::set<std::wstring> observed;
        std::set<std::wstring> emitted;
        bool queryFailureWarningAdded = false;
        bool inspectionFailureWarningAdded = false;

        for (const auto& processItem :
             processes)
        {
            const HuntProcessRecord& process =
                processItem.second;
            for (const HuntModuleRecord& module :
                 process.Modules)
            {
                if (!IsCloudFileImageCandidate(
                        module))
                {
                    continue;
                }

                const std::wstring openPath =
                    OpenPathForResolvedBacking(
                        module.VadBackingPath,
                        module.Path);
                const std::wstring cacheKey =
                    CanonicalPathForCompare(
                        openPath);
                if (cacheKey.empty())
                {
                    continue;
                }

                auto inserted =
                    cache.emplace(
                        cacheKey,
                        CachedPlaceholder{});
                CachedPlaceholder& cached =
                    inserted.first->second;
                if (inserted.second)
                {
                    cached.QuerySucceeded =
                        scanner.QueryPlaceholder(
                            openPath,
                            &cached.Record,
                            &cached.QueryError);
                }
                if (!cached.QuerySucceeded)
                {
                    result->
                        CloudFilePlaceholderCoverageIncomplete =
                            true;
                    result->CoverageComplete = false;
                    if (!queryFailureWarningAdded)
                    {
                        AddUnique(
                            &result->Warnings,
                            L"Cloud Files image inspection failed for " +
                                module.VadBackingPath +
                                L": " +
                                (cached.QueryError.empty()
                                     ? L"attribute query unavailable"
                                     : cached.QueryError));
                        queryFailureWarningAdded = true;
                    }
                    continue;
                }
                if (!cached.Record.
                        PlaceholderInspectionComplete)
                {
                    result->
                        CloudFilePlaceholderCoverageIncomplete =
                            true;
                    result->CoverageComplete = false;
                    if (!inspectionFailureWarningAdded)
                    {
                        AddUnique(
                            &result->Warnings,
                            L"Cloud Files placeholder classification incomplete for " +
                                module.VadBackingPath +
                                L": " +
                                (cached.Record.Warning.empty()
                                     ? L"CfGetPlaceholderInfo did not produce an authoritative result"
                                     : cached.Record.Warning));
                        inspectionFailureWarningAdded =
                            true;
                    }
                    continue;
                }
                if (!cached.Record.IsCloudPlaceholder)
                {
                    continue;
                }

                std::vector<std::wstring>
                    mismatchReasons;
                uint64_t mismatchAddress = 0;
                const bool hasDeepMismatch =
                    FindDeepImageMismatchForModule(
                        *result,
                        process,
                        module,
                        &mismatchReasons,
                        &mismatchAddress);
                const CloudFileMappingDecision
                    decision =
                        EvaluateCloudFileMapping(
                            cached.Record,
                            process.HasProtection,
                            process.Protection,
                            hasDeepMismatch,
                            mismatchReasons);

                if (decision.MetadataCoverageIncomplete)
                {
                    result->
                        CloudFilePlaceholderCoverageIncomplete =
                            true;
                    result->CoverageComplete = false;
                    AddUnique(
                        &result->Warnings,
                        L"Cloud Files image correlation incomplete for " +
                            module.VadBackingPath +
                            L": " +
                            (cached.Record.Warning.empty()
                                 ? L"placeholder metadata unavailable"
                                 : cached.Record.Warning));
                    continue;
                }

                if (!decision.IsPlaceholder)
                {
                    continue;
                }

                const std::wstring observationKey =
                    std::to_wstring(
                        process.ProcessId) +
                    L"|" +
                    HuntHex(
                        module.Base,
                        16) +
                    L"|" +
                    cacheKey;
                if (!observed.insert(
                        observationKey).second)
                {
                    continue;
                }

                ++result->
                    CloudFilePlaceholderImageCount;
                HuntCloudFileImageRecord observation = {};
                observation.ProcessId =
                    process.ProcessId;
                observation.ModuleBase =
                    module.Base;
                observation.ModuleSize =
                    module.Size;
                observation.ImageName =
                    BestProcessImageName(process);
                observation.ModuleName =
                    module.Name.empty()
                        ? LeafName(
                              module.VadBackingPath)
                        : module.Name;
                observation.VadBackingPath =
                    module.VadBackingPath;
                observation.NormalizedBackingPath =
                    openPath;
                observation.FileAttributes =
                    cached.Record.FileAttributes;
                observation.ReparseTag =
                    cached.Record.ReparseTag;
                observation.PlaceholderState =
                    cached.Record.PlaceholderState;
                observation.PinState =
                    cached.Record.PinState;
                observation.InSyncState =
                    cached.Record.InSyncState;
                observation.PlaceholderInfoQueryStatus =
                    cached.Record.
                        PlaceholderInfoQueryStatus;
                observation.OnDiskDataSize =
                    cached.Record.OnDiskDataSize;
                observation.ValidatedDataSize =
                    cached.Record.ValidatedDataSize;
                observation.ModifiedDataSize =
                    cached.Record.ModifiedDataSize;
                observation.PropertiesSize =
                    cached.Record.PropertiesSize;
                observation.FileIdentityLength =
                    cached.Record.FileIdentityLength;
                observation.CloudReparseTagObserved =
                    cached.Record.CloudReparseTag;
                observation.
                    PlaceholderInfoIdentificationFallbackUsed =
                        cached.Record.
                            PlaceholderInfoIdentificationFallbackUsed;
                observation.ProcessProtectionResolved =
                    process.HasProtection;
                observation.ProcessProtection =
                    process.Protection;
                observation.DeepMismatchCorrelated =
                    hasDeepMismatch;
                observation.Suspicious =
                    decision.EmitFinding;
                observation.Reasons =
                    decision.Reasons;
                result->CloudFileImages.push_back(
                    std::move(observation));

                if (decision.ProtectionCoverageIncomplete)
                {
                    result->
                        CloudFileProtectionCorrelationIncomplete =
                            true;
                    result->CoverageComplete = false;
                    AddUnique(
                        &result->Warnings,
                        L"Cloud Files PP/PPL correlation incomplete: _EPROCESS.Protection was unavailable for pid " +
                            std::to_wstring(
                                process.ProcessId));
                }
                if (!decision.EmitFinding)
                {
                    continue;
                }

                const std::wstring emitKey =
                    observationKey;
                if (!emitted.insert(
                        emitKey).second)
                {
                    continue;
                }

                std::map<std::wstring, std::wstring>
                    evidence;
                evidence[L"mapped_image_kind"] =
                    L"SEC_IMAGE";
                evidence[L"metadata_read_mode"] =
                    L"FILE_READ_ATTRIBUTES";
                evidence[L"vad_backing_path"] =
                    module.VadBackingPath;
                evidence[L"normalized_backing_path"] =
                    openPath;
                evidence[L"module_base"] =
                    HuntHex(
                        module.Base,
                        16);
                evidence[L"module_size"] =
                    std::to_wstring(
                        module.Size);
                evidence[L"file_attributes"] =
                    HuntHex(
                        cached.Record.FileAttributes,
                        8);
                evidence[L"reparse_tag"] =
                    HuntHex(
                        cached.Record.ReparseTag,
                        8);
                evidence[L"cloud_reparse_tag_observed"] =
                    cached.Record.CloudReparseTag
                        ? L"true"
                        : L"false";
                evidence[L"fsctl_reparse_tag_fallback_used"] =
                    cached.Record.FsctlReparseTagFallbackUsed
                        ? L"true"
                        : L"false";
                evidence[L"fsctl_reparse_tag_query_error"] =
                    std::to_wstring(
                        cached.Record.
                            FsctlReparseTagQueryError);
                evidence[L"placeholder_info_identification_fallback_used"] =
                    cached.Record.
                            PlaceholderInfoIdentificationFallbackUsed
                        ? L"true"
                        : L"false";
                evidence[L"placeholder_info_query_status"] =
                    HuntHex(
                        cached.Record.
                            PlaceholderInfoQueryStatus,
                        8);
                evidence[L"placeholder_state"] =
                    HuntHex(
                        cached.Record.PlaceholderState,
                        8);
                evidence[L"on_disk_data_size"] =
                    std::to_wstring(
                        cached.Record.OnDiskDataSize);
                evidence[L"validated_data_size"] =
                    std::to_wstring(
                        cached.Record.ValidatedDataSize);
                evidence[L"modified_data_size"] =
                    std::to_wstring(
                        cached.Record.ModifiedDataSize);
                evidence[L"properties_size"] =
                    std::to_wstring(
                        cached.Record.PropertiesSize);
                evidence[L"pin_state"] =
                    std::to_wstring(
                        cached.Record.PinState);
                evidence[L"in_sync_state"] =
                    std::to_wstring(
                        cached.Record.InSyncState);
                evidence[L"file_id"] =
                    HuntHex(
                        static_cast<uint64_t>(
                            cached.Record.FileId),
                        16);
                evidence[L"sync_root_file_id"] =
                    HuntHex(
                        static_cast<uint64_t>(
                            cached.Record.SyncRootFileId),
                        16);
                evidence[L"file_identity_length"] =
                    std::to_wstring(
                        cached.Record.FileIdentityLength);
                evidence[L"process_protection_resolved"] =
                    process.HasProtection
                        ? L"true"
                        : L"false";
                if (process.HasProtection)
                {
                    evidence[L"protection_raw"] =
                        HuntHex(
                            process.Protection,
                            2);
                    evidence[L"protection_type"] =
                        std::to_wstring(
                            process.Protection &
                            0x7u);
                    evidence[L"protection_audit"] =
                        std::to_wstring(
                            (process.Protection >>
                             3) &
                            0x1u);
                    evidence[L"protection_signer"] =
                        std::to_wstring(
                            (process.Protection >>
                             4) &
                            0xfu);
                }
                evidence[L"deep_mismatch_correlated"] =
                    hasDeepMismatch
                        ? L"true"
                        : L"false";
                evidence[L"deep_mismatch_reasons"] =
                    JoinWideValues(
                        mismatchReasons,
                        L";");

                AddFinding(
                    result,
                    process,
                    decision.Risk,
                    decision.Confidence,
                    L"cloudfiles_false_file_immutability",
                    decision.Title,
                    mismatchAddress != 0
                        ? mismatchAddress
                        : module.Base,
                    module.Name.empty()
                        ? LeafName(
                              module.VadBackingPath)
                        : module.Name,
                    decision.Reasons,
                    evidence);
                ++result->
                    SuspiciousCloudFileImageCount;
            }
        }
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
                        L"process stop",
                        L"allocvm",
                        L"allocatevirtualmemory",
                        L"ntallocatevirtualmemory",
                        L"protectvm",
                        L"protectvirtualmemory",
                        L"ntprotectvirtualmemory",
                        L"writevm",
                        L"writevirtualmemory",
                        L"ntwritevirtualmemory",
                        L"readvm",
                        L"readvirtualmemory",
                        L"ntreadvirtualmemory",
                        L"mapview",
                        L"mapviewofsection",
                        L"ntmapviewofsection",
                        L"queueuserapc",
                        L"ntqueueapcthread",
                        L"setthreadcontext",
                        L"ntsetcontextthread",
                        L"createremotethread",
                        L"suspend",
                        L"resume",
                        L"thread control",
                        L"thread_control"
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
            if (options.ThreatIntelEventsDropped != 0)
            {
                result->ThreatIntelCorrelationIncomplete = true;
                result->CoverageComplete = false;
                result->Warnings.push_back(
                    L"threat_intel correlation incomplete: TI ring dropped " +
                    std::to_wstring(options.ThreatIntelEventsDropped) +
                    L" event(s); correlation coverage is partial");
            }
            if (options.ThreatIntelEvents.empty())
            {
                // Zero events from an active/available, non-dropping ring is a
                // valid clean observation.  Only absence of the collection
                // surface makes deep correlation incomplete.
                if (options.Mode == HuntMode::Deep &&
                    !options.ThreatIntelActive &&
                    !options.ThreatIntelAvailable)
                {
                    result->ThreatIntelCorrelationIncomplete = true;
                    result->CoverageComplete = false;
                    result->Warnings.push_back(
                        L"threat_intel correlation incomplete: deep mode without active !ti session or supplied events; TI behavioral correlation skipped");
                }
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

    bool ResolveHuntProcessProtectionField(
        SymbolEngine& symbols,
        TypeFieldInfo* field)
    {
        if (field == nullptr)
        {
            return false;
        }

        std::wstring error;
        if (symbols.FindField(
                L"nt!_EPROCESS",
                L"Protection",
                field,
                &error))
        {
            return true;
        }

        error.clear();
        return symbols.FindField(
            L"_EPROCESS",
            L"Protection",
            field,
            &error);
    }

    bool ReadHuntProcessProtection(
        DeviceClient& device,
        const TypeFieldInfo& field,
        HuntProcessRecord* process)
    {
        if (process == nullptr ||
            process->Kernel.Eprocess == 0 ||
            process->Kernel.Eprocess >
                std::numeric_limits<uint64_t>::max() -
                    field.Offset)
        {
            return false;
        }

        std::vector<uint8_t> bytes;
        std::wstring error;
        if (!device.ReadMemory(
                process->Kernel.Eprocess +
                    field.Offset,
                sizeof(uint8_t),
                &bytes,
                &error) ||
            bytes.size() != sizeof(uint8_t))
        {
            return false;
        }

        process->HasProtection = true;
        process->Protection = bytes[0];
        return true;
    }

    bool AddressInsideInclusiveRange(uint64_t address, uint64_t start, uint64_t end)
    {
        return address != 0 && end >= start && address >= start && address <= end;
    }

    const ProcessVadProtectionRange* FindVadEffectiveProtection(
        const ProcessVadRecord& vad,
        uint64_t address)
    {
        auto after = std::upper_bound(
            vad.EffectiveProtectionRanges.begin(),
            vad.EffectiveProtectionRanges.end(),
            address,
            [](uint64_t value, const ProcessVadProtectionRange& range)
            {
                return value < range.StartAddress;
            });
        if (after == vad.EffectiveProtectionRanges.begin())
        {
            return nullptr;
        }

        --after;
        return AddressInsideInclusiveRange(
            address,
            after->StartAddress,
            after->EndAddress)
            ? &*after
            : nullptr;
    }

    bool VadAddressIsExecutable(const ProcessVadRecord& vad, uint64_t address)
    {
        if (!vad.EffectiveProtectionComplete)
        {
            return vad.Executable;
        }

        const ProcessVadProtectionRange* range =
            FindVadEffectiveProtection(vad, address);
        return range != nullptr && range->Committed && range->Executable;
    }

    bool VadAddressIsWritableExecutable(const ProcessVadRecord& vad, uint64_t address)
    {
        if (!vad.EffectiveProtectionComplete)
        {
            return vad.WritableExecutable;
        }

        const ProcessVadProtectionRange* range =
            FindVadEffectiveProtection(vad, address);
        return range != nullptr &&
            range->Committed &&
            range->WritableExecutable;
    }

    bool VadRangeHasExecutionEvidence(
        const HuntProcessRecord& process,
        const ProcessVadRecord& vad,
        uint64_t rangeStart,
        uint64_t rangeEnd,
        bool includeStackReferences,
        bool requireWritableExecutable);

    bool VadHasExecutionEvidence(
        const HuntProcessRecord& process,
        const ProcessVadRecord& vad,
        bool includeStackReferences,
        bool requireWritableExecutable)
    {
        return VadRangeHasExecutionEvidence(
            process,
            vad,
            vad.StartAddress,
            vad.EndAddress,
            includeStackReferences,
            requireWritableExecutable);
    }

    bool VadRangeHasExecutionEvidence(
        const HuntProcessRecord& process,
        const ProcessVadRecord& vad,
        uint64_t rangeStart,
        uint64_t rangeEnd,
        bool includeStackReferences,
        bool requireWritableExecutable)
    {
        bool observed = false;
        auto matchesProtection =
            [&vad, rangeStart, rangeEnd, requireWritableExecutable](
                uint64_t address)
        {
            if (!AddressInsideInclusiveRange(address, rangeStart, rangeEnd))
            {
                return false;
            }
            if (!AddressInsideInclusiveRange(
                    address,
                    vad.StartAddress,
                    vad.EndAddress))
            {
                return false;
            }

            return requireWritableExecutable
                ? VadAddressIsWritableExecutable(vad, address)
                : VadAddressIsExecutable(vad, address);
        };

        do
        {
            for (const ProcessThreadRecord& thread : process.ThreadRecords)
            {
                if (thread.HasStartAddress &&
                    matchesProtection(thread.StartAddress))
                {
                    observed = true;
                    break;
                }
                if (thread.HasWin32StartAddress &&
                    matchesProtection(thread.Win32StartAddress))
                {
                    observed = true;
                    break;
                }

                for (const ProcessApcQueueRecord& queue : thread.ApcQueues)
                {
                    for (const ProcessApcEntryRecord& apc : queue.Entries)
                    {
                        if (matchesProtection(apc.NormalRoutine) ||
                            matchesProtection(apc.UserRoutine) ||
                            matchesProtection(apc.KernelRoutine))
                        {
                            observed = true;
                            break;
                        }
                    }

                    if (observed)
                    {
                        break;
                    }
                }

                if (observed)
                {
                    break;
                }

                if (!includeStackReferences)
                {
                    continue;
                }

                for (const ProcessStackReferenceRecord& ref : thread.StackReferences)
                {
                    if (matchesProtection(ref.Value))
                    {
                        observed = true;
                        break;
                    }
                }

                if (observed)
                {
                    break;
                }
            }
        } while (false);

        return observed;
    }

    bool ShouldSkipExpectedManagedLoaderlessDeepComparison(
        const HuntProcessRecord& process,
        const HuntModuleRecord& module)
    {
        if (!IsExpectedManagedLoaderlessMapping(
                process,
                module))
        {
            return false;
        }

        const ProcessVadRecord* vad =
            FindVadContaining(process, module.Base);
        return vad != nullptr &&
            !VadHasExecutionEvidence(
                process,
                *vad,
                false,
                false);
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
            uint32_t genericWxFindings = 0;
            bool genericWxLimitWarned = false;
            std::map<std::wstring, DiskPeMetadata> diskMetadataCache;
            for (const ProcessVadRecord& vad : process->VadRecords)
            {
                bool privateMemory = vad.HasPrivateMemory && vad.PrivateMemory;
                bool privateExecutable = vad.Executable && privateMemory;
                bool wx = vad.WritableExecutable;
                bool executableCopyOnWrite = vad.CopyOnWriteExecutable;
                uint64_t executableBytes = vad.EffectiveProtectionComplete
                    ? vad.EffectiveExecutableBytes
                    : (vad.Executable ? vad.Size : 0);
                bool largePrivateExecutable =
                    privateMemory &&
                    executableBytes >= kLargePrivateExecThreshold;
                bool privatePe = privateMemory && vad.Executable && vad.PeHeaderFound;
                bool executablePrivatePeSuspicious =
                    privateMemory && vad.Executable && vad.PeHeaderSuspicious;
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
                        const uint64_t vadRva64 = vad.StartAddress - loaderOwner->Base;
                        const uint64_t vadEndRva64 =
                            vad.Size <= std::numeric_limits<uint64_t>::max() - vadRva64
                                ? vadRva64 + vad.Size
                                : std::numeric_limits<uint64_t>::max();
                        const bool vadRvaRangeValid =
                            vadRva64 <= std::numeric_limits<uint32_t>::max() &&
                            vadEndRva64 <=
                                static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1ull;
                        const uint32_t vadRva = vadRvaRangeValid
                            ? static_cast<uint32_t>(vadRva64)
                            : 0;
                        const uint64_t ownerEnd =
                            loaderOwner->Size <=
                                    std::numeric_limits<uint64_t>::max() - loaderOwner->Base
                                ? loaderOwner->Base + loaderOwner->Size
                                : std::numeric_limits<uint64_t>::max();
                        const DiskPeSection* evidenceSection = nullptr;
                        uint32_t evidenceRva = 0;
                        uint64_t evidenceEndRva = 0;
                        uint64_t evidenceLiveStart = 0;
                        uint64_t evidenceLiveEnd = 0;
                        uint32_t evidenceLiveProtection = 0;

                        auto assessLiveRange =
                            [&](uint64_t liveStart,
                                uint64_t liveEnd,
                                uint32_t liveProtection,
                                bool liveExecutable,
                                bool liveWritableExecutable,
                                bool liveCopyOnWriteExecutable)
                        {
                            if (liveEnd < liveStart ||
                                liveEnd < loaderOwner->Base ||
                                liveStart >= ownerEnd)
                            {
                                return;
                            }

                            liveStart = std::max(liveStart, loaderOwner->Base);
                            liveEnd = std::min(liveEnd, ownerEnd - 1);
                            const uint64_t liveRvaStart =
                                liveStart - loaderOwner->Base;
                            const uint64_t liveRvaEnd =
                                liveEnd - loaderOwner->Base + 1;
                            if (liveRvaStart > std::numeric_limits<uint32_t>::max() ||
                                liveRvaEnd >
                                    static_cast<uint64_t>(
                                        std::numeric_limits<uint32_t>::max()) +
                                        1ull)
                            {
                                return;
                            }

                            for (const DiskPeSection& section : metadata.Sections)
                            {
                                const uint64_t sectionStart = section.VirtualAddress;
                                const uint64_t sectionSpan =
                                    std::max(section.VirtualSize, section.SizeOfRawData);
                                const uint64_t sectionEnd = sectionStart + sectionSpan;
                                if (sectionSpan == 0 ||
                                    sectionEnd < sectionStart ||
                                    liveRvaEnd <= sectionStart ||
                                    liveRvaStart >= sectionEnd)
                                {
                                    continue;
                                }

                                const uint64_t overlapStart =
                                    std::max(liveRvaStart, sectionStart);
                                const uint64_t overlapEnd =
                                    std::min(liveRvaEnd, sectionEnd);
                                const uint64_t overlapLiveStart =
                                    loaderOwner->Base + overlapStart;
                                const uint64_t overlapLiveEndExclusive =
                                    loaderOwner->Base + overlapEnd;
                                if (overlapLiveStart < loaderOwner->Base ||
                                    overlapLiveEndExclusive <=
                                        overlapLiveStart)
                                {
                                    continue;
                                }
                                const bool permissionRangeExecutionObserved =
                                    VadRangeHasExecutionEvidence(
                                        *process,
                                        vad,
                                        overlapLiveStart,
                                        overlapLiveEndExclusive - 1,
                                        false,
                                        false);
                                const bool executePermissionDrift =
                                    liveExecutable &&
                                    !section.Executable &&
                                    permissionRangeExecutionObserved;
                                const bool writePermissionDrift =
                                    liveWritableExecutable &&
                                    section.Executable &&
                                    !section.Writable &&
                                    permissionRangeExecutionObserved;
                                const bool defaultWritableExecutableSection =
                                    (liveWritableExecutable ||
                                     liveCopyOnWriteExecutable) &&
                                    section.Executable &&
                                    section.Writable;
                                const bool entrypointWritePermissionDrift =
                                    liveWritableExecutable &&
                                    section.Executable &&
                                    !section.Writable &&
                                    permissionRangeExecutionObserved &&
                                    metadata.HasEntryPoint &&
                                    metadata.EntryPointRva >= overlapStart &&
                                    metadata.EntryPointRva < overlapEnd;

                                if (!executePermissionDrift &&
                                    !writePermissionDrift &&
                                    !defaultWritableExecutableSection &&
                                    !entrypointWritePermissionDrift)
                                {
                                    continue;
                                }

                                if (evidenceSection == nullptr)
                                {
                                    evidenceSection = &section;
                                    evidenceRva =
                                        static_cast<uint32_t>(overlapStart);
                                    evidenceEndRva = overlapEnd;
                                    evidenceLiveStart = liveStart;
                                    evidenceLiveEnd = liveEnd;
                                    evidenceLiveProtection = liveProtection;
                                    imageSectionEvidence[
                                        L"permission_range_execution_observed"] =
                                        permissionRangeExecutionObserved
                                            ? L"true"
                                            : L"false";
                                }

                                if (executePermissionDrift)
                                {
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"image_section_execute_permission_drift");
                                }
                                if (writePermissionDrift)
                                {
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"image_section_write_permission_drift");
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"module_stomping_permission_evidence");
                                }
                                if (entrypointWritePermissionDrift)
                                {
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"module_entrypoint_write_permission_drift");
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"module_stomping_permission_evidence");
                                }
                                if (defaultWritableExecutableSection)
                                {
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"image_rwx_section_vad");
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"mockingjay_rwx_section_candidate");
                                    AddUnique(
                                        &imageSectionReasons,
                                        L"module_stomping_permission_evidence");
                                }
                            }
                        };

                        if (vad.EffectiveProtectionComplete)
                        {
                            for (const ProcessVadProtectionRange& range :
                                 vad.EffectiveProtectionRanges)
                            {
                                if (!range.Committed)
                                {
                                    continue;
                                }
                                assessLiveRange(
                                    range.StartAddress,
                                    range.EndAddress,
                                    range.Protection,
                                    range.Executable,
                                    range.WritableExecutable,
                                    range.CopyOnWriteExecutable);
                            }
                        }
                        else if (vadRvaRangeValid)
                        {
                            const DiskPeSection* section =
                                FindDiskSectionForRva(metadata, vadRva);
                            if (section != nullptr)
                            {
                                const uint64_t sectionEnd =
                                    static_cast<uint64_t>(section->VirtualAddress) +
                                    std::max(
                                        section->VirtualSize,
                                        section->SizeOfRawData);
                                // Without an address-granular VirtualQueryEx
                                // view, only compare a VAD wholly contained in
                                // one section. Aggregated VAD flags must not be
                                // attributed to every section in an image.
                                if (vadEndRva64 <= sectionEnd)
                                {
                                    assessLiveRange(
                                        vad.StartAddress,
                                        vad.EndAddress,
                                        vad.Protection,
                                        vad.Executable,
                                        vad.WritableExecutable,
                                        vad.CopyOnWriteExecutable);
                                }
                            }
                        }

                        if (evidenceSection != nullptr)
                        {
                            const bool entrypointInsideVad =
                                vadRvaRangeValid &&
                                metadata.HasEntryPoint &&
                                metadata.EntryPointRva >= vadRva64 &&
                                metadata.EntryPointRva < vadEndRva64;
                            const bool firstExecutableSectionInsideVad =
                                vadRvaRangeValid &&
                                metadata.HasExecutableSection &&
                                metadata.FirstExecutableSectionRva >= vadRva64 &&
                                metadata.FirstExecutableSectionRva < vadEndRva64;
                            imageSectionEvidence[L"owner_module"] = loaderOwner->Name;
                            imageSectionEvidence[L"owner_module_base"] = HuntHex(loaderOwner->Base, 16);
                            imageSectionEvidence[L"owner_module_path"] = loaderOwner->Path;
                            imageSectionEvidence[L"disk_section_name"] = evidenceSection->Name;
                            imageSectionEvidence[L"disk_section_rva"] = HuntHex(evidenceSection->VirtualAddress, 8);
                            imageSectionEvidence[L"disk_section_executable"] = evidenceSection->Executable ? L"true" : L"false";
                            imageSectionEvidence[L"disk_section_writable"] = evidenceSection->Writable ? L"true" : L"false";
                            imageSectionEvidence[L"vad_rva"] = HuntHex(vadRva64, 8);
                            imageSectionEvidence[L"vad_end_rva"] = HuntHex(vadEndRva64, 8);
                            imageSectionEvidence[L"compared_rva"] = HuntHex(evidenceRva, 8);
                            imageSectionEvidence[L"compared_end_rva"] = HuntHex(evidenceEndRva, 8);
                            imageSectionEvidence[L"live_range_start"] = HuntHex(evidenceLiveStart, 16);
                            imageSectionEvidence[L"live_range_end"] = HuntHex(evidenceLiveEnd, 16);
                            imageSectionEvidence[L"live_range_protection"] = HuntHex(evidenceLiveProtection, 8);
                            imageSectionEvidence[L"entrypoint_inside_vad"] = entrypointInsideVad ? L"true" : L"false";
                            imageSectionEvidence[L"first_executable_section_inside_vad"] = firstExecutableSectionInsideVad ? L"true" : L"false";
                            imageSectionEvidence[L"vad_executable"] = vad.Executable ? L"true" : L"false";
                            imageSectionEvidence[L"vad_writable"] = vad.Writable ? L"true" : L"false";
                            imageSectionEvidence[L"vad_copy_on_write"] = vad.CopyOnWrite ? L"true" : L"false";
                        }
                    }
                }

                if (sectionBackedExecutable)
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
                            !CanOpenDiskImagePath(
                                OpenPathForResolvedBacking(
                                    backingPath,
                                    loaderOwner == nullptr
                                        ? L""
                                        : loaderOwner->Path)))
                        {
                            backingState = L"inaccessible";
                            backingOpenable = false;
                        }
                    }
                    else if (!loaderCovered &&
                             ProcessHasCompleteUserModuleInventory(
                                 *process) &&
                             !backingWarning.empty())
                    {
                        AddUnique(&process->Warnings, L"VAD section backing failed: " + backingWarning);
                    }

                    bool peLikeBackingName = LooksLikePeImagePath(backingPath);
                    if (imageSection || peLikeBackingName)
                    {
                        uint64_t moduleSize =
                            loaderOwner != nullptr &&
                                loaderOwner->Size != 0
                                ? loaderOwner->Size
                                : vad.Size;
                        bool managedImage = false;
                        if (!loaderCovered &&
                            backingOpenable &&
                            !backingPath.empty())
                        {
                            DiskPeMetadata metadata = {};
                            std::wstring metadataError;
                            if (ReadDiskPeMetadata(backingPath, &metadata, &metadataError) && metadata.SizeOfImage != 0)
                            {
                                moduleSize = metadata.SizeOfImage;
                                managedImage = metadata.ManagedImage;
                            }
                        }

                        HuntModuleRecord module = {};
                        module.Base =
                            loaderOwner == nullptr
                                ? vad.StartAddress
                                : loaderOwner->Base;
                        module.Size = moduleSize;
                        module.Name = backingPath.empty() ? L"section-image" : LeafName(backingPath);
                        module.Path = backingPath;
                        // VadImageSeen retains its original cross-view
                        // meaning: a VAD image not covered by a loader view.
                        // VadSectionSeen tracks every independently resolved
                        // SEC_IMAGE mapping for Cloud Files inspection.
                        module.VadImageSeen =
                            !loaderCovered;
                        module.VadSectionSeen = true;
                        module.VadBackingManagedImage = managedImage;
                        module.VadAddress = vad.VadAddress;
                        module.VadBackingPath = backingPath;
                        module.VadBackingState = backingState;
                        MergeModule(&process->Modules, module);
                    }
                }

                bool imageSectionPermissionSuspicious = !imageSectionReasons.empty();
                bool imageExecutePermissionDrift =
                    std::find(
                        imageSectionReasons.begin(),
                        imageSectionReasons.end(),
                        L"image_section_execute_permission_drift") != imageSectionReasons.end();
                bool imageWritePermissionDrift =
                    std::find(
                        imageSectionReasons.begin(),
                        imageSectionReasons.end(),
                        L"image_section_write_permission_drift") != imageSectionReasons.end();
                bool moduleStompingPermissionEvidence =
                    std::find(
                        imageSectionReasons.begin(),
                        imageSectionReasons.end(),
                        L"module_stomping_permission_evidence") != imageSectionReasons.end();
                bool defaultImageRwxSection =
                    std::find(
                        imageSectionReasons.begin(),
                        imageSectionReasons.end(),
                        L"image_rwx_section_vad") != imageSectionReasons.end();
                bool strongVadEvidence =
                    largePrivateExecutable ||
                    privatePe ||
                    executablePrivatePeSuspicious ||
                    imageExecutePermissionDrift ||
                    imageWritePermissionDrift ||
                    moduleStompingPermissionEvidence ||
                    defaultImageRwxSection;
                // Raw stack slots routinely contain legitimate JIT and
                // emulator return addresses.  Treat them as execution
                // corroboration only after the VAD already has PE/header,
                // large-region, or image-permission evidence.  Thread starts
                // and queued APC routines remain strong enough on their own.
                bool executionObserved = VadHasExecutionEvidence(
                    *process,
                    vad,
                    strongVadEvidence,
                    false);
                bool genericWxOnly = wx && !strongVadEvidence;
                bool weakPrivateExecutableOnly = privateExecutable && !wx && !strongVadEvidence;
                bool writableExecutableExecutionObserved =
                    genericWxOnly &&
                    VadHasExecutionEvidence(
                        *process,
                        vad,
                        false,
                        true);
                bool relevantExecutionObserved =
                    genericWxOnly
                        ? writableExecutableExecutionObserved
                        : executionObserved;
                bool identityCorroborated =
                    process->BuiltinProfileMatched &&
                    !process->BuiltinProfileViolations.empty();
                if (!privateExecutable &&
                    !wx &&
                    !largePrivateExecutable &&
                    !privatePe &&
                    !executablePrivatePeSuspicious &&
                    !imageSectionPermissionSuspicious)
                {
                    continue;
                }

                // Private RX and W+X regions are normal runtime primitives for
                // JIT engines, antimalware emulators, and other dynamic-code
                // hosts.  Preserve them in the per-process VAD counters and
                // raw !vad surface, but do not promote the primitive alone to
                // a hunt finding.  Thread/APC correlation, stack correlation
                // on stronger code provenance, PE/header evidence, large
                // size, image permission drift, or a violated built-in
                // identity profile still promotes the region below.
                if ((genericWxOnly || weakPrivateExecutableOnly) &&
                    !relevantExecutionObserved &&
                    !identityCorroborated)
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
                    if (ProcessHasCompleteUserModuleInventory(
                            *process))
                    {
                        AddUnique(
                            &reasons,
                            L"private_pe_without_loader_entry");
                    }
                }
                if (executablePrivatePeSuspicious)
                {
                    reasons.push_back(L"wiped_pe_header");
                }
                for (const std::wstring& reason : imageSectionReasons)
                {
                    AddUnique(&reasons, reason);
                }
                if (defaultImageRwxSection)
                {
                    AddUnique(&reasons, L"wx_user_vad");
                }

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
                if (genericWxOnly &&
                    genericWxFindings >= kMaxGenericWxFindingsPerProcess)
                {
                    if (!genericWxLimitWarned)
                    {
                        AddUnique(&process->Warnings, L"generic W+X executable VAD findings were capped");
                        genericWxLimitWarned = true;
                    }
                    continue;
                }

                std::map<std::wstring, std::wstring> evidence;
                evidence[L"vad"] = HuntHex(vad.VadAddress, 16);
                evidence[L"start"] = HuntHex(vad.StartAddress, 16);
                evidence[L"end"] = HuntHex(vad.EndAddress, 16);
                evidence[L"size"] = std::to_wstring(vad.Size);
                evidence[L"protection"] = vad.ProtectionText;
                evidence[L"effective_protection_queried"] =
                    vad.EffectiveProtectionQueried ? L"true" : L"false";
                evidence[L"effective_protection_complete"] =
                    vad.EffectiveProtectionComplete ? L"true" : L"false";
                if (vad.EffectiveProtectionQueried)
                {
                    evidence[L"effective_protection"] = vad.EffectiveProtectionText;
                    evidence[L"effective_committed_bytes"] =
                        std::to_wstring(vad.EffectiveCommittedBytes);
                    evidence[L"effective_executable_bytes"] =
                        std::to_wstring(vad.EffectiveExecutableBytes);
                    evidence[L"effective_writable_bytes"] =
                        std::to_wstring(vad.EffectiveWritableBytes);
                    evidence[L"effective_copy_on_write_bytes"] =
                        std::to_wstring(vad.EffectiveCopyOnWriteBytes);
                    evidence[L"effective_wx_bytes"] =
                        std::to_wstring(vad.EffectiveWritableExecutableBytes);
                    evidence[L"effective_x_cow_bytes"] =
                        std::to_wstring(vad.EffectiveCopyOnWriteExecutableBytes);
                }
                evidence[L"private"] = privateMemory ? L"true" : L"false";
                evidence[L"copy_on_write"] = executableCopyOnWrite ? L"true" : L"false";
                evidence[L"pe_like"] = vad.PeHeaderFound ? L"true" : L"false";
                evidence[L"pe_suspicious"] = vad.PeHeaderSuspicious ? L"true" : L"false";
                evidence[L"classification"] = vad.Classification;
                for (const auto& item : imageSectionEvidence)
                {
                    evidence[item.first] = item.second;
                }
                evidence[L"strong_code_provenance"] = strongVadEvidence ? L"true" : L"false";
                evidence[L"execution_observed"] = relevantExecutionObserved ? L"true" : L"false";
                evidence[L"wx_execution_observed"] =
                    writableExecutableExecutionObserved ? L"true" : L"false";
                if (vad.PeProbeAttempted)
                {
                    evidence[L"pe_mz_wiped"] = vad.PeProbe.MzWiped ? L"true" : L"false";
                    evidence[L"pe_signature_wiped"] = vad.PeProbe.PeSignatureWiped ? L"true" : L"false";
                    evidence[L"pe_elfanew_mismatch"] = vad.PeProbe.ELfanewMismatch ? L"true" : L"false";
                    evidence[L"pe_size_of_image"] = std::to_wstring(vad.PeProbe.SizeOfImage);
                }
                AddBuiltinInjectionReasonIfNeeded(
                    *process,
                    &reasons,
                    &evidence,
                    strongVadEvidence || identityCorroborated);

                std::wstring risk = L"medium";
                std::wstring confidence = L"medium";
                bool peBackedPrivateCode = privatePe || executablePrivatePeSuspicious;
                if (largePrivateExecutable ||
                    imageExecutePermissionDrift ||
                    imageWritePermissionDrift ||
                    (peBackedPrivateCode && executionObserved))
                {
                    risk = L"high";
                    confidence = L"high";
                }
                else if (peBackedPrivateCode)
                {
                    risk = L"low";
                    confidence = L"medium";
                    evidence[L"private_pe_without_execution_observed"] = L"true";
                }
                if (imageSectionPermissionSuspicious)
                {
                    if (imageExecutePermissionDrift ||
                        imageWritePermissionDrift ||
                        moduleStompingPermissionEvidence ||
                        (process->BuiltinProfileMatched && !process->BuiltinProfileViolations.empty()))
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
                    evidence[L"generic_executable_memory_only"] = L"true";
                    evidence[L"weak_private_exec_only"] = L"true";
                    ++weakPrivateExecFindings;
                }
                if (genericWxOnly)
                {
                    risk = L"low";
                    confidence = L"low";
                    evidence[L"generic_executable_memory_only"] = L"true";
                    evidence[L"generic_wx_only"] = L"true";
                    ++genericWxFindings;
                }

                std::wstring className = imageSectionPermissionSuspicious ? L"module_stomping" : L"mapped_code";
                std::wstring title = imageSectionPermissionSuspicious
                    ? L"loaded image section has suspicious executable permissions"
                    : L"suspicious executable user VAD";

                AddFinding(
                    result,
                    *process,
                    risk,
                    confidence,
                    className,
                    title,
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

    bool VadClassificationHasStrongCodeEvidence(const std::wstring& classification)
    {
        bool strong = false;

        do
        {
            if (classification.find(L"PE") != std::wstring::npos ||
                classification.find(L"large-private-exec") != std::wstring::npos)
            {
                strong = true;
                break;
            }
        } while (false);

        return strong;
    }

    bool HasNonCanonicalKernelApcRoutine(
        const ProcessApcEntryRecord& apc)
    {
        return apc.HasKernelRoutine &&
            apc.KernelRoutine != 0 &&
            !IsKernelAddress(apc.KernelRoutine);
    }

    uint64_t SelectApcFindingAddress(
        const ProcessApcEntryRecord& apc)
    {
        if (HasNonCanonicalKernelApcRoutine(apc))
        {
            return apc.KernelRoutine;
        }
        if (apc.UserRoutine != 0)
        {
            return apc.UserRoutine;
        }
        return apc.NormalRoutine != 0
            ? apc.NormalRoutine
            : apc.KernelRoutine;
    }

    std::wstring SelectApcFindingModule(
        const ProcessApcEntryRecord& apc)
    {
        if (HasNonCanonicalKernelApcRoutine(apc))
        {
            return apc.KernelRoutineModule;
        }
        if (apc.UserRoutine != 0)
        {
            return apc.UserRoutineModule;
        }
        return apc.NormalRoutine != 0
            ? apc.NormalRoutineModule
            : apc.KernelRoutineModule;
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
                    if (thread.StartInPrivateExecVad)
                    {
                        AddUnique(&reasons, L"private_executable_vad");
                    }
                    if (thread.StartInWxVad)
                    {
                        AddUnique(&reasons, L"wx_user_vad");
                    }
                    bool strongThreadEvidence = VadClassificationHasStrongCodeEvidence(thread.VadClassification);
                    bool identityCorroborated =
                        process.BuiltinProfileMatched &&
                        !process.BuiltinProfileViolations.empty();
                    bool noncanonicalStart =
                        findingAddress != 0 &&
                        !IsUserAddress(findingAddress) &&
                        !IsKernelAddress(findingAddress);
                    if (!thread.StartInPrivateExecVad &&
                        !thread.StartInWxVad &&
                        !strongThreadEvidence &&
                        !identityCorroborated &&
                        !noncanonicalStart)
                    {
                        // A loader-view miss alone is weak on WOW64 and other
                        // processes whose user module walk can be partial.
                        // Keep it in raw thread telemetry, but require exact
                        // suspicious page provenance or another corroborator
                        // before promoting it to a hunt finding.
                        continue;
                    }
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence, strongThreadEvidence);

                    std::wstring risk = strongThreadEvidence ? L"high" : L"low";
                    std::wstring confidence = strongThreadEvidence ? L"high" : L"low";
                    AddFinding(
                        result,
                        process,
                        risk,
                        confidence,
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
                    bool strongStackEvidence = VadClassificationHasStrongCodeEvidence(ref.VadClassification);
                    bool identityCorroborated =
                        process.BuiltinProfileMatched &&
                        !process.BuiltinProfileViolations.empty();
                    if (!strongStackEvidence && !identityCorroborated)
                    {
                        // Preserve the raw stack-reference record and counters,
                        // but a pointer to ordinary JIT/dynamic code is not an
                        // anomaly without stronger provenance.
                        continue;
                    }
                    AddBuiltinInjectionReasonIfNeeded(
                        process,
                        &reasons,
                        &evidence,
                        strongStackEvidence || identityCorroborated);

                    std::wstring risk = strongStackEvidence || identityCorroborated ? L"high" : L"low";
                    std::wstring confidence = strongStackEvidence ? L"high" : L"medium";
                    AddFinding(
                        result,
                        process,
                        risk,
                        confidence,
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

                        const bool nonCanonicalKernelRoutine =
                            HasNonCanonicalKernelApcRoutine(apc);
                        uint64_t findingAddress =
                            SelectApcFindingAddress(apc);
                        std::wstring findingModule =
                            SelectApcFindingModule(apc);

                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"ethread"] = HuntHex(thread.Ethread, 16);
                        evidence[L"tid"] = std::to_wstring(thread.ThreadId);
                        evidence[L"queue"] = queue.Name;
                        evidence[L"kapc"] = HuntHex(apc.KapcAddress, 16);
                        evidence[L"kernel_routine"] = HuntHex(apc.KernelRoutine, 16);
                        evidence[L"normal_routine"] = HuntHex(apc.NormalRoutine, 16);
                        evidence[L"normal_context"] = HuntHex(apc.NormalContext, 16);
                        evidence[L"system_argument1"] = HuntHex(apc.SystemArgument1, 16);
                        evidence[L"system_argument2"] = HuntHex(apc.SystemArgument2, 16);
                        evidence[L"kernel_routine_module"] = apc.KernelRoutineModule;
                        evidence[L"normal_routine_module"] = apc.NormalRoutineModule;
                        evidence[L"normal_routine_vad"] =
                            apc.NormalRoutineVadClassification;
                        evidence[L"normal_routine_private_exec"] =
                            apc.NormalRoutineInPrivateExecVad ? L"true" : L"false";
                        evidence[L"normal_routine_wx"] =
                            apc.NormalRoutineInWxVad ? L"true" : L"false";
                        evidence[L"user_routine"] = HuntHex(apc.UserRoutine, 16);
                        evidence[L"user_routine_source"] = apc.UserRoutineSource;
                        evidence[L"user_routine_module"] = apc.UserRoutineModule;
                        evidence[L"user_routine_vad"] =
                            apc.UserRoutineVadClassification;
                        evidence[L"user_routine_private_exec"] =
                            apc.UserRoutineInPrivateExecVad ? L"true" : L"false";
                        evidence[L"user_routine_wx"] =
                            apc.UserRoutineInWxVad ? L"true" : L"false";
                        evidence[L"notes"] = apc.Notes;

                        std::vector<std::wstring> reasons = {L"suspicious_apc_routine"};
                        if (nonCanonicalKernelRoutine)
                        {
                            AddUnique(
                                &reasons,
                                L"noncanonical_kernel_routine");
                        }
                        if (apc.UserRoutineInPrivateExecVad)
                        {
                            AddUnique(&reasons, L"private_executable_vad");
                        }
                        if (apc.UserRoutineInWxVad)
                        {
                            AddUnique(&reasons, L"wx_user_vad");
                        }
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

            std::wstring securityTarget;
            if (!process.ThreadInventoryComplete ||
                !process.ThreadSuspensionStateCoverageComplete ||
                process.ThreadsVisited == 0 ||
                process.ThreadRecords.size() !=
                    process.ThreadsVisited ||
                process.SuspensionStateResolvedThreads !=
                    process.ThreadsVisited ||
                process.SuspendedThreads !=
                    process.ThreadsVisited ||
                process.ThreadRecords.empty() ||
                !HuntTextTargetsKnownSecurityProduct(
                    BestProcessImageName(process),
                    &securityTarget))
            {
                break;
            }

            uint64_t resolvedThreads = 0;
            uint64_t suspendedThreads = 0;
            uint64_t suspendCountThreads = 0;
            uint64_t freezeCountThreads = 0;
            std::vector<std::wstring> suspendedThreadIds;
            std::set<uint64_t> observedEthreads;
            bool uniqueThreadEvidence = true;
            for (const ProcessThreadRecord& thread :
                 process.ThreadRecords)
            {
                if (thread.Ethread == 0 ||
                    !observedEthreads.insert(
                        thread.Ethread).second ||
                    !thread.HasSuspendCount ||
                    !thread.HasFreezeCount)
                {
                    uniqueThreadEvidence = false;
                    continue;
                }

                ++resolvedThreads;
                const bool suspendActive =
                    thread.HasSuspendCount &&
                    thread.SuspendCount != 0;
                const bool freezeActive =
                    thread.HasFreezeCount &&
                    thread.FreezeCount != 0;
                if (suspendActive)
                {
                    ++suspendCountThreads;
                }
                if (freezeActive)
                {
                    ++freezeCountThreads;
                }
                if (suspendActive || freezeActive)
                {
                    ++suspendedThreads;
                    suspendedThreadIds.push_back(
                        thread.HasThreadId
                            ? std::to_wstring(thread.ThreadId)
                            : HuntHex(thread.Ethread, 16));
                }
            }

            const uint64_t observedThreads =
                process.ThreadRecords.size();
            if (!uniqueThreadEvidence ||
                resolvedThreads != observedThreads ||
                suspendedThreads != observedThreads)
            {
                break;
            }

            std::map<std::wstring, std::wstring> evidence;
            evidence[L"security_product_target"] =
                securityTarget;
            evidence[L"thread_inventory_complete"] =
                L"true";
            evidence[L"suspension_state_coverage_complete"] =
                L"true";
            evidence[L"observed_threads"] =
                std::to_wstring(observedThreads);
            evidence[L"suspension_state_resolved_threads"] =
                std::to_wstring(resolvedThreads);
            evidence[L"suspended_threads"] =
                std::to_wstring(suspendedThreads);
            evidence[L"suspend_count_nonzero_threads"] =
                std::to_wstring(suspendCountThreads);
            evidence[L"freeze_count_nonzero_threads"] =
                std::to_wstring(freezeCountThreads);
            evidence[L"suspended_thread_ids"] =
                JoinWideValues(suspendedThreadIds, L";");

            AddFinding(
                result,
                process,
                L"high",
                L"high",
                L"security_tool_impairment",
                L"all observed threads of a known security process are suspended or frozen",
                0,
                L"",
                {
                    L"security_product_process_suspended",
                    L"all_observed_threads_suspended",
                    L"edr_freeze_state"
                },
                evidence);
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
                evidence[L"vad_backing_managed_image"] = module.VadBackingManagedImage ? L"true" : L"false";
                bool expectedManagedMapping = IsExpectedManagedLoaderlessMapping(process, module);
                evidence[L"vad_backing_expected_managed_mapping"] =
                    expectedManagedMapping ? L"true" : L"false";

                if (module.VadImageSeen &&
                    ProcessHasCompleteUserModuleInventory(
                        process))
                {
                    bool covered = LoaderModuleCoversAddress(process, module.Base, &module);
                    if (!covered && !expectedManagedMapping)
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

                if (module.PrivatePeVadSeen &&
                    ProcessHasCompleteUserModuleInventory(
                        process))
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
                    bool builtinProfileViolated = process.BuiltinProfileMatched && !process.BuiltinProfileViolations.empty();
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence, builtinProfileViolated);
                    AddFinding(
                        result,
                        process,
                        builtinProfileViolated ? L"high" : L"medium",
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
                    (module.VadImageSeen || !process.BuiltinProfileViolations.empty()))
                {
                    std::vector<std::wstring> reasons = {L"module_view_mismatch"};
                    bool builtinProfileViolated = process.BuiltinProfileMatched && !process.BuiltinProfileViolations.empty();
                    AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence, builtinProfileViolated || module.VadImageSeen);
                    AddFinding(
                        result,
                        process,
                        builtinProfileViolated ? L"high" : L"medium",
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
                    IsWindowsBackedModulePath(module.Path) ||
                    IsTrustedMicrosoftWindowsAppRuntimeModule(
                        module.Path))
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
                bool builtinProfileViolated =
                    process.BuiltinProfileMatched &&
                    !process.BuiltinProfileViolations.empty();
                AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence, builtinProfileViolated);

                AddFinding(
                    result,
                    process,
                    builtinProfileViolated ? L"high" : L"low",
                    builtinProfileViolated ? L"medium" : L"low",
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
                uint64_t vadControlArea = 0;
                ControlAreaBackingDetails vadBackingDetails;
                if (ResolveVadSectionBackingPath(
                        device,
                        symbols,
                        *vad,
                        &backingPath,
                        &backingState,
                        &backingWarning,
                        nullptr,
                        &vadControlArea,
                        &vadBackingDetails))
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

                std::wstring mainSectionWarning;
                std::wstring mainSectionPath;
                std::wstring mainSectionState;
                uint64_t mainSectionObject = 0;
                uint64_t mainSectionSegment = 0;
                uint64_t mainSectionControlArea = 0;
                ControlAreaBackingDetails mainSectionDetails;
                if (ResolveEprocessMainSectionBackingPath(
                        device,
                        symbols,
                        process->Kernel.Eprocess,
                        &mainSectionPath,
                        &mainSectionState,
                        &mainSectionObject,
                        &mainSectionSegment,
                        &mainSectionControlArea,
                        &mainSectionWarning,
                        nullptr,
                        &mainSectionDetails))
                {
                    process->MainSectionObject = mainSectionObject;
                    process->MainSectionSegment = mainSectionSegment;
                    process->MainSectionControlArea = mainSectionControlArea;
                    process->MainSectionBackingPath = mainSectionPath;
                    process->MainSectionBackingState = mainSectionState;
                }
                else if (!mainSectionWarning.empty())
                {
                    AddUnique(&process->Warnings, L"EPROCESS main section backing unresolved: " + mainSectionWarning);
                }

                if (process->MainSectionBackingState == L"resolved" &&
                    !process->MainSectionBackingPath.empty())
                {
                    std::vector<std::wstring> reasons;
                    bool mainSectionDiffersFromVad = process->SectionBackingState == L"resolved" &&
                        !process->SectionBackingPath.empty() &&
                        !SameCanonicalPath(process->MainSectionBackingPath, process->SectionBackingPath);
                    bool mainSectionDiffersFromModule = !module.Path.empty() &&
                        !SameCanonicalPath(process->MainSectionBackingPath, module.Path);
                    bool mainSectionDiffersFromPeb = !process->PebImagePath.empty() &&
                        !SameCanonicalPath(process->MainSectionBackingPath, process->PebImagePath);
                    bool mainSectionDiffersFromApi = !process->ApiImagePath.empty() &&
                        !SameCanonicalPath(process->MainSectionBackingPath, process->ApiImagePath);

                    if (mainSectionDiffersFromVad)
                    {
                        AddUnique(&reasons, L"main_section_object_vad_backing_mismatch");
                    }
                    if (mainSectionDiffersFromModule)
                    {
                        AddUnique(&reasons, L"main_section_object_process_path_mismatch");
                    }
                    if (mainSectionDiffersFromPeb)
                    {
                        AddUnique(&reasons, L"main_section_object_peb_path_mismatch");
                    }
                    if (mainSectionDiffersFromApi)
                    {
                        AddUnique(&reasons, L"main_section_object_api_path_mismatch");
                    }

                    if (!reasons.empty())
                    {
                        AddUnique(&reasons, L"kernel_main_section_swap_evidence");
                        std::map<std::wstring, std::wstring> evidence;
                        evidence[L"eprocess"] = HuntHex(process->Kernel.Eprocess, 16);
                        evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                        evidence[L"main_image_size"] = std::to_wstring(module.Size);
                        evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                        evidence[L"disk_path"] = module.Path;
                        evidence[L"api_image_path"] = process->ApiImagePath;
                        evidence[L"peb_image_path"] = process->PebImagePath;
                        evidence[L"vad_section_backing_path"] = process->SectionBackingPath;
                        evidence[L"vad_section_backing_state"] = process->SectionBackingState;
                        evidence[L"main_section_object"] = HuntHex(process->MainSectionObject, 16);
                        evidence[L"main_section_segment"] = HuntHex(process->MainSectionSegment, 16);
                        evidence[L"main_section_control_area"] = HuntHex(process->MainSectionControlArea, 16);
                        evidence[L"main_section_backing_path"] = process->MainSectionBackingPath;
                        evidence[L"main_section_backing_state"] = process->MainSectionBackingState;

                        AddFinding(
                            result,
                            *process,
                            (mainSectionDiffersFromVad || mainSectionDiffersFromModule) ? L"high" : L"medium",
                            (mainSectionDiffersFromVad || mainSectionDiffersFromModule) ? L"high" : L"medium",
                            L"process_image_integrity",
                            L"EPROCESS main section object backing differs from process image views",
                            module.Base,
                            module.Name,
                            reasons,
                            evidence);
                    }
                }

                std::vector<std::wstring> primitiveReasons;
                AddProcessTamperingPrimitiveReasons(
                    L"main_image_vad",
                    vadBackingDetails,
                    &primitiveReasons);
                AddProcessTamperingPrimitiveReasons(
                    L"main_section_object",
                    mainSectionDetails,
                    &primitiveReasons);
                bool vadPrimitiveHigh =
                    (vadBackingDetails.HasDeletePending && vadBackingDetails.DeletePending) ||
                    ControlAreaBackingHasImageSectionPointerMismatch(vadBackingDetails);
                bool mainSectionPrimitiveHigh =
                    (mainSectionDetails.HasDeletePending && mainSectionDetails.DeletePending) ||
                    ControlAreaBackingHasImageSectionPointerMismatch(mainSectionDetails);
                bool primitiveAccessOnly =
                    !primitiveReasons.empty() &&
                    !vadPrimitiveHigh &&
                    !mainSectionPrimitiveHigh;
                if (!primitiveReasons.empty())
                {
                    AddUnique(&primitiveReasons, L"process_tampering_primitive_evidence");
                    std::map<std::wstring, std::wstring> evidence;
                    evidence[L"eprocess"] = HuntHex(process->Kernel.Eprocess, 16);
                    evidence[L"main_image_base"] = HuntHex(module.Base, 16);
                    evidence[L"main_image_size"] = std::to_wstring(module.Size);
                    evidence[L"main_image_vad"] = HuntHex(vad->VadAddress, 16);
                    evidence[L"vad_control_area"] = HuntHex(vadControlArea, 16);
                    evidence[L"disk_path"] = module.Path;
                    evidence[L"api_image_path"] = process->ApiImagePath;
                    evidence[L"peb_image_path"] = process->PebImagePath;
                    AddControlAreaBackingEvidence(L"main_image_vad", vadBackingDetails, &evidence);
                    AddControlAreaBackingEvidence(L"main_section_object", mainSectionDetails, &evidence);

                    AddFinding(
                        result,
                        *process,
                        primitiveAccessOnly ? L"medium" : L"high",
                        primitiveAccessOnly ? L"medium" : L"high",
                        L"process_image_integrity",
                        L"main image section backing exposes process tampering primitive evidence",
                        module.Base,
                        module.Name,
                        primitiveReasons,
                        evidence);
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
            const bool exactIdentityAvailable =
                HasExactProcessIdentity(process.Kernel);
            if (dtb == 0 &&
                !exactIdentityAvailable)
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
                    if (ReadHuntProcessMemory(
                            device,
                            process.Kernel,
                            current,
                            chunkSize,
                            &bytes,
                            &ignored))
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
                        const uint64_t apcTargets[] =
                        {
                            apc.UserRoutine,
                            apc.NormalRoutine,
                            apc.KernelRoutine
                        };
                        bool targetInPage = false;
                        for (uint64_t apcTarget : apcTargets)
                        {
                            if (apcTarget >= pageStart &&
                                apcTarget < pageEnd)
                            {
                                targetInPage = true;
                                break;
                            }
                        }
                        if (targetInPage)
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

            bool executionOnPage = !threadIds.empty() || !apcThreadIds.empty() || !stackReferences.empty();
            bool doppelganging = mainImage &&
                std::find(reasons.begin(), reasons.end(), L"process_doppelganging_evidence") != reasons.end();
            bool builtinProfileViolated = process.BuiltinProfileMatched && !process.BuiltinProfileViolations.empty();
            AddBuiltinInjectionReasonIfNeeded(process, &reasons, &evidence, executionOnPage || doppelganging || builtinProfileViolated);
            std::wstring risk = mainImage || executionOnPage || builtinProfileViolated ? L"high" : L"medium";
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
            if (metadata.ManagedIlOnly ||
                metadata.ImageBase == 0 ||
                module.Base == 0 ||
                module.Base == metadata.ImageBase)
            {
                break;
            }

            relocated = metadata.RelocationPages.find(pageRva) != metadata.RelocationPages.end();
        } while (false);

        return relocated;
    }

    void MaskMutableRangeBytes(
        const DiskPeMutableRange& range,
        uint64_t pageStart,
        uint64_t pageEnd,
        std::vector<uint8_t>* livePage,
        std::vector<uint8_t>* diskPage)
    {
        const uint64_t rangeStart = range.Rva;
        const uint64_t rangeEnd = rangeStart + range.Size;
        const uint64_t overlapStart = std::max(pageStart, rangeStart);
        const uint64_t overlapEnd = std::min(pageEnd, rangeEnd);
        if (overlapStart >= overlapEnd)
        {
            return;
        }

        const size_t offset = static_cast<size_t>(overlapStart - pageStart);
        const size_t length = static_cast<size_t>(overlapEnd - overlapStart);
        std::fill(
            livePage->begin() + offset,
            livePage->begin() + offset + length,
            static_cast<uint8_t>(0));
        std::fill(
            diskPage->begin() + offset,
            diskPage->begin() + offset + length,
            static_cast<uint8_t>(0));
    }

    void MaskExpectedLoaderMutableBytes(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        std::vector<uint8_t>* livePage,
        std::vector<uint8_t>* diskPage)
    {
        if (livePage == nullptr || diskPage == nullptr)
        {
            return;
        }

        const uint64_t pageStart = pageRva;
        const uint64_t pageEnd =
            pageStart + std::min(livePage->size(), diskPage->size());
        for (const DiskPeMutableRange& range : metadata.LoaderMutableRanges)
        {
            MaskMutableRangeBytes(
                range,
                pageStart,
                pageEnd,
                livePage,
                diskPage);
        }
    }

    void MaskExpectedCrossPageRelocationBytes(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        std::vector<uint8_t>* livePage,
        std::vector<uint8_t>* diskPage)
    {
        if (livePage == nullptr || diskPage == nullptr)
        {
            return;
        }

        const uint64_t pageStart = pageRva;
        const uint64_t pageEnd =
            pageStart + std::min(livePage->size(), diskPage->size());
        for (const DiskPeMutableRange& range :
             metadata.CrossPageRelocationRanges)
        {
            // The page where the relocation starts is fully normalized using
            // bytes from the following page, so preserve it for comparison.
            // Only the continuation bytes on the following page lack the
            // preceding bytes needed to reconstruct the integer.
            if (range.Rva >= pageStart)
            {
                continue;
            }
            MaskMutableRangeBytes(
                range,
                pageStart,
                pageEnd,
                livePage,
                diskPage);
        }
    }

    void MaskExpectedDynamicRelocationBytes(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        std::vector<uint8_t>* livePage,
        std::vector<uint8_t>* diskPage)
    {
        if (livePage == nullptr || diskPage == nullptr)
        {
            return;
        }

        const uint64_t pageStart = pageRva;
        const uint64_t pageEnd = pageStart + std::min(livePage->size(), diskPage->size());
        auto first = std::lower_bound(
            metadata.DynamicRelocationRanges.begin(),
            metadata.DynamicRelocationRanges.end(),
            pageStart,
            [](const DiskPeMutableRange& range, uint64_t address)
            {
                return static_cast<uint64_t>(range.Rva) + range.Size <= address;
            });
        for (auto current = first;
             current != metadata.DynamicRelocationRanges.end() &&
                 current->Rva < pageEnd;
             ++current)
        {
            MaskMutableRangeBytes(
                *current,
                pageStart,
                pageEnd,
                livePage,
                diskPage);
        }
    }

    bool DeepProcessLifecycleChanged(
        const HuntProcessRecord& process)
    {
        if (process.ProcessId == 0 ||
            !process.Kernel.HasCreateTime)
        {
            return false;
        }

        HANDLE handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            process.ProcessId);
        if (handle == nullptr)
        {
            const DWORD error = GetLastError();
            return error == ERROR_INVALID_PARAMETER ||
                error == ERROR_INVALID_HANDLE ||
                error == ERROR_NOT_FOUND;
        }

        bool lifecycleChanged = false;
        const bool matched =
            ProcessHandleMatchesSnapshot(
                handle,
                process.Kernel,
                &lifecycleChanged);
        CloseHandle(handle);
        return !matched && lifecycleChanged;
    }

    HANDLE OpenVerifiedDeepProcessReadHandle(
        const HuntProcessRecord& process,
        bool* lifecycleChanged)
    {
        if (lifecycleChanged != nullptr)
        {
            *lifecycleChanged = false;
        }
        if (process.ProcessId == 0 ||
            !process.Kernel.HasCreateTime)
        {
            return nullptr;
        }

        HANDLE handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            process.ProcessId);
        if (handle == nullptr)
        {
            return nullptr;
        }

        bool handleLifecycleChanged = false;
        if (!ProcessHandleMatchesSnapshot(
                handle,
                process.Kernel,
                &handleLifecycleChanged))
        {
            if (handleLifecycleChanged &&
                lifecycleChanged != nullptr)
            {
                *lifecycleChanged = true;
            }
            CloseHandle(handle);
            return nullptr;
        }

        return handle;
    }

    bool ReadDeepProcessPage(
        DeviceClient& device,
        HANDLE processRead,
        const HuntProcessRecord& process,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        std::wstring userReadError;
        if (processRead != nullptr &&
            processRead != INVALID_HANDLE_VALUE &&
            bytes != nullptr)
        {
            bytes->assign(length, 0);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(
                    processRead,
                    reinterpret_cast<LPCVOID>(
                        static_cast<uintptr_t>(address)),
                    bytes->data(),
                    length,
                    &bytesRead) &&
                bytesRead == length)
            {
                return true;
            }

            userReadError =
                L"ReadProcessMemory failed gle=" +
                std::to_wstring(GetLastError()) +
                L" bytes=" +
                std::to_wstring(bytesRead);
            bytes->clear();
        }

        std::wstring driverProcessReadError;
        const bool exactIdentityAvailable =
            HasExactProcessIdentity(process.Kernel);
        if (exactIdentityAvailable &&
            device.ReadProcessVirtual(
                process.ProcessId,
                process.Kernel.Eprocess,
                process.Kernel.HasCreateTime
                    ? process.Kernel.CreateTime
                    : 0,
                address,
                length,
                bytes,
                &driverProcessReadError))
        {
            return true;
        }

        if (error != nullptr)
        {
            *error = userReadError;
            if (!exactIdentityAvailable)
            {
                if (!error->empty())
                {
                    *error += L"; ";
                }
                *error +=
                    L"exact process identity is unavailable";
            }
            if (!driverProcessReadError.empty())
            {
                if (!error->empty())
                {
                    *error += L"; ";
                }
                *error +=
                    L"driver process read: " +
                    driverProcessReadError;
            }
        }
        return false;
    }

    bool MarkDeepComparisonFailure(
        HuntResult* result,
        HuntProcessRecord* process,
        const HuntModuleRecord& module,
        const std::wstring& detail,
        const std::wstring& error)
    {
        if (result == nullptr || process == nullptr)
        {
            return false;
        }

        if (DeepProcessLifecycleChanged(*process))
        {
            process->LifecycleChangedBeforeTriage = true;
            AddUnique(
                &process->Warnings,
                L"process ended or PID was reused during deep image comparison; remaining stale evidence was skipped");
            return true;
        }

        result->DeepImageComparisonCoverageIncomplete = true;
        result->CoverageComplete = false;
        std::wstring warning =
            (module.Name.empty() ? module.Path : module.Name) +
            L": " +
            detail;
        if (!error.empty())
        {
            warning += L" (" + error + L")";
        }
        AddUnique(&process->Warnings, warning);
        return false;
    }

    void CompareModulePage(
        DeviceClient& device,
        HuntResult* result,
        HuntProcessRecord* process,
        HANDLE processRead,
        const HuntModuleRecord& module,
        const DiskPeMetadata& metadata,
        const std::wstring& pageName,
        const std::wstring& sectionName,
        uint32_t rva,
        DeepStackReferenceCache* stackCache)
    {
        do
        {
            if (result == nullptr || process == nullptr)
            {
                break;
            }

            uint32_t pageRva = rva & 0xfffff000u;
            std::vector<uint8_t> livePage;
            std::wstring readError;
            if (module.Base >
                    std::numeric_limits<uint64_t>::max() -
                        pageRva ||
                !ReadDeepProcessPage(
                    device,
                    processRead,
                    *process,
                    module.Base + pageRva,
                    static_cast<uint32_t>(kPageSize),
                    &livePage,
                    &readError))
            {
                MarkDeepComparisonFailure(
                    result,
                    process,
                    module,
                    L"deep live page read failed at rva=0x" +
                        HuntHex(pageRva, 8),
                    readError);
                break;
            }

            std::vector<uint8_t> diskPage;
            readError.clear();
            if (!ReadDiskPageForRva(
                    module.Path,
                    metadata,
                    pageRva,
                    &diskPage,
                    &readError))
            {
                MarkDeepComparisonFailure(
                    result,
                    process,
                    module,
                    L"deep disk page read failed at rva=0x" +
                        HuntHex(pageRva, 8),
                    readError);
                break;
            }

            if (PageHasExpectedRelocationDelta(module, metadata, pageRva) &&
                metadata.ImageBase != 0 &&
                module.Base != metadata.ImageBase)
            {
                const uint64_t imageDelta = module.Base - metadata.ImageBase;
                std::vector<uint8_t> diskNextPage;
                std::wstring nextIgnored;
                if (pageRva <=
                    std::numeric_limits<uint32_t>::max() -
                        static_cast<uint32_t>(kPageSize))
                {
                    ReadDiskPageForRva(
                        module.Path,
                        metadata,
                        pageRva + static_cast<uint32_t>(kPageSize),
                        &diskNextPage,
                        &nextIgnored);
                }
                if (!ApplyBaseRelocationsToDiskPage(
                        metadata,
                        pageRva,
                        imageDelta,
                        &diskPage,
                        diskNextPage.empty() ? nullptr : &diskNextPage))
                {
                    // Reloc normalize failed: do not skip the page as "expected
                    // delta" (that hid live patches). Treat as incomplete coverage.
                    MarkDeepComparisonFailure(
                        result,
                        process,
                        module,
                        L"deep page compare reloc normalize failed at rva=0x" +
                            HuntHex(pageRva, 8),
                        L"");
                    break;
                }
            }

            if (livePage.size() != diskPage.size())
            {
                MarkDeepComparisonFailure(
                    result,
                    process,
                    module,
                    L"deep page read returned inconsistent lengths at rva=0x" +
                        HuntHex(pageRva, 8),
                    L"");
                break;
            }

            MaskExpectedLoaderMutableBytes(
                metadata,
                pageRva,
                &livePage,
                &diskPage);
            if (!metadata.ManagedIlOnly)
            {
                MaskExpectedCrossPageRelocationBytes(
                    metadata,
                    pageRva,
                    &livePage,
                    &diskPage);
            }
            MaskExpectedDynamicRelocationBytes(
                metadata,
                pageRva,
                &livePage,
                &diskPage);

            if (!livePage.empty() && livePage != diskPage)
            {
                AddDeepPageCompareFinding(
                    device,
                    result,
                    *process,
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
            if (result == nullptr ||
                process == nullptr ||
                (TargetUserDtb(process->Kernel) == 0 &&
                 !HasExactProcessIdentity(process->Kernel)))
            {
                break;
            }

            size_t compared = 0;
            size_t pagesCompared = 0;
            DeepStackReferenceCache stackReferenceCache = {};
            bool lifecycleChanged = false;
            ScopedHuntHandle processRead(
                OpenVerifiedDeepProcessReadHandle(
                    *process,
                    &lifecycleChanged));
            if (lifecycleChanged)
            {
                process->LifecycleChangedBeforeTriage = true;
                AddUnique(
                    &process->Warnings,
                    L"process ended or PID was reused before deep image comparison; stale evidence was skipped");
                break;
            }

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
                        if (IsMainImageModule(*process, *module))
                        {
                            return 0;
                        }
                        if (module->VadImageSeen)
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
                if (ShouldSkipExpectedManagedLoaderlessDeepComparison(
                        *process,
                        module))
                {
                    continue;
                }

                DiskPeMetadata metadata = {};
                std::wstring metadataError;
                if (!ReadDiskPeMetadata(module.Path, &metadata, &metadataError))
                {
                    if (MarkDeepComparisonFailure(
                            result,
                            process,
                            module,
                            L"deep disk PE metadata read failed",
                            metadataError))
                    {
                        return;
                    }
                    continue;
                }
                if (metadata.BaseRelocationTablePresent &&
                    !metadata.BaseRelocationTableComplete)
                {
                    result->DeepImageComparisonCoverageIncomplete = true;
                    result->CoverageComplete = false;
                    AddUnique(
                        &process->Warnings,
                        module.Name + L": malformed base relocation table");
                    continue;
                }
                if (metadata.DynamicRelocationTablePresent &&
                    !metadata.DynamicRelocationTableComplete)
                {
                    result->DeepImageComparisonCoverageIncomplete = true;
                    result->CoverageComplete = false;
                    AddUnique(
                        &process->Warnings,
                        module.Name + L": unsupported or malformed dynamic relocation table");
                    continue;
                }

                bool mainImage = IsMainImageModule(*process, module);
                bool compareFullExecutableSections = mainImage || !process->BuiltinProfileViolations.empty();
                std::set<uint32_t> comparedPageRvas;
                if (metadata.HasEntryPoint)
                {
                    uint32_t pageRva = metadata.EntryPointRva & 0xfffff000u;
                    if (pagesCompared < kMaxDeepPagesPerProcess)
                    {
                        CompareModulePage(
                            device,
                            result,
                            process,
                            processRead.Value,
                            module,
                            metadata,
                            L"entrypoint",
                            L"",
                            metadata.EntryPointRva,
                            &stackReferenceCache);
                        if (process->LifecycleChangedBeforeTriage)
                        {
                            return;
                        }
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
                            process,
                            processRead.Value,
                            module,
                            metadata,
                            L"executable_section",
                            section.Name,
                            pageRva,
                            &stackReferenceCache);
                        if (process->LifecycleChangedBeforeTriage)
                        {
                            return;
                        }
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

    void AddEsetLoadedDriverHashHuntFindings(HuntResult* result, const ByovdScanResult& byovd)
    {
        do
        {
            if (result == nullptr)
            {
                break;
            }

            for (const ByovdModuleRecord& record : byovd.Records)
            {
                if (!record.FileHashed || record.Sha1.empty())
                {
                    continue;
                }

                const EsetFileSha1Ioc* ioc = FindEsetFileSha1Ioc(record.Sha1, false, true);
                if (ioc == nullptr)
                {
                    continue;
                }

                std::vector<std::wstring> reasons =
                {
                    L"loaded_driver_file_hash_ioc"
                };
                std::map<std::wstring, std::wstring> evidence;
                evidence[L"driver_image_name"] = record.ImageName;
                evidence[L"driver_image_path"] = record.ImagePath;
                evidence[L"driver_disk_path"] = record.DiskPath;
                evidence[L"driver_base"] = HuntHex(record.Base, 16);
                evidence[L"driver_size"] = std::to_wstring(record.Size);
                AddEsetFileHashEvidence(*ioc, record.DiskPath, record.Sha1, &reasons, &evidence);

                std::vector<std::wstring> followups =
                {
                    L"!byovd scan /no-update /exact /limit 40",
                    L"!driver integrity all /limit 200"
                };

                AddSystemFinding(
                    result,
                    L"high",
                    L"high",
                    L"edr_killer_driver_file_ioc",
                    L"loaded kernel driver matches ESET Gentlemen EDR-killer SHA1 IOC",
                    record.Base,
                    !record.ImageName.empty() ? record.ImageName : ioc->FileName,
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

    bool DriverServiceHasGentlemenStagingContext(const DriverServiceRecord& record)
    {
        return PathContainsGentlemenCollection(record.BinaryPath) ||
            PathContainsGentlemenCollection(record.ExpandedBinaryPath) ||
            PathContainsGentlemenCollection(record.ServiceName) ||
            PathContainsGentlemenCollection(record.DisplayName);
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
            const bool serviceCoverageComplete =
                CollectDriverServices(&services, &warnings);
            result->DriverServiceCount = services.size();
            if (!serviceCoverageComplete)
            {
                result->DriverServiceCoverageIncomplete = true;
                result->CoverageComplete = false;
            }

            for (const std::wstring& warning : warnings)
            {
                AddUnique(&result->Warnings, L"driver service scan warning: " + warning);
            }

            std::map<std::wstring, FileSha1CacheEntry> serviceSha1Cache;
            for (const DriverServiceRecord& service : services)
            {
                std::wstring matchedLeaf;
                const EdrKillerDriverProfile* profile =
                    FindDriverProfileForServiceRecord(service, &matchedLeaf);

                FileSha1CacheEntry serviceHash = {};
                const EsetFileSha1Ioc* hashIoc = nullptr;
                std::wstring serviceImagePath = DriverServiceBinaryImagePath(
                    !service.ExpandedBinaryPath.empty() ? service.ExpandedBinaryPath : service.BinaryPath);
                if (!serviceImagePath.empty() &&
                    GetCachedFileSha1(serviceImagePath, &serviceSha1Cache, &serviceHash))
                {
                    hashIoc = FindEsetFileSha1Ioc(serviceHash.Sha1, false, true);
                }

                if (profile == nullptr && hashIoc == nullptr)
                {
                    continue;
                }

                bool gentlemenStagingPath = DriverServiceHasGentlemenStagingContext(service);
                if (profile != nullptr &&
                    !profile->StrongNameSignal &&
                    !gentlemenStagingPath &&
                    hashIoc == nullptr)
                {
                    continue;
                }

                ++result->EdrKillerDriverServiceCount;

                std::vector<std::wstring> reasons =
                {
                    L"driver_service_installed"
                };
                if (profile != nullptr)
                {
                    AddUnique(&reasons, L"driver_service_binary_name_ioc");
                    AddUnique(&reasons, L"gentlemen_edr_killer_driver_service");
                }
                if (service.Running)
                {
                    AddUnique(&reasons, L"driver_service_running");
                }
                else
                {
                    AddUnique(&reasons, L"driver_service_not_running");
                }
                if (profile != nullptr && !profile->StrongNameSignal)
                {
                    AddUnique(&reasons, L"name_only_requires_hash_or_staging_correlation");
                }
                if (gentlemenStagingPath)
                {
                    AddUnique(&reasons, L"gentlemen_collection_staging_path");
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
                evidence[L"gentlemen_collection_path"] = gentlemenStagingPath ? L"true" : L"false";
                if (profile != nullptr)
                {
                    evidence[L"gentlemen_family"] = profile->Family;
                    evidence[L"gentlemen_tool"] = profile->Tool;
                    evidence[L"gentlemen_ioc_driver"] = profile->ImageName;
                    evidence[L"strong_name_signal"] = profile->StrongNameSignal ? L"true" : L"false";
                }
                if (hashIoc != nullptr)
                {
                    AddUnique(&reasons, L"gentlemen_edr_killer_driver_service");
                    AddUnique(&reasons, L"driver_service_file_hash_ioc");
                    AddEsetFileHashEvidence(*hashIoc, serviceHash.Path, serviceHash.Sha1, &reasons, &evidence);
                }

                std::vector<std::wstring> followups =
                {
                    L"sc.exe qc " + service.ServiceName,
                    L"sc.exe query " + service.ServiceName,
                    L"!byovd scan /no-update /exact /limit 40",
                    L"!driver integrity all /limit 200"
                };

                std::wstring risk = L"low";
                std::wstring confidence = L"low";
                if (hashIoc != nullptr)
                {
                    risk = L"high";
                    confidence = L"high";
                }
                else if (profile != nullptr && profile->StrongNameSignal && service.Running)
                {
                    risk = L"high";
                    confidence = L"high";
                }
                else if (profile != nullptr && profile->StrongNameSignal)
                {
                    risk = L"medium";
                    confidence = L"high";
                }
                else if (gentlemenStagingPath && service.Running)
                {
                    risk = L"medium";
                    confidence = L"medium";
                }
                else if (gentlemenStagingPath)
                {
                    risk = L"low";
                    confidence = L"medium";
                }

                AddSystemFinding(
                    result,
                    risk,
                    confidence,
                    L"edr_killer_driver_service",
                    L"driver service matches Gentlemen EDR-killer driver IOC",
                    0,
                    !matchedLeaf.empty() ? matchedLeaf : service.BinaryLeaf,
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
                AddEsetLoadedDriverHashHuntFindings(result, byovd);
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

    bool HuntReasonStartsWith(const std::wstring& reason, const std::wstring& prefix)
    {
        return reason.rfind(prefix, 0) == 0;
    }

    bool IsOperatorHighSignalReason(const std::wstring& reason)
    {
        bool matched = false;
        std::wstring lowered = HuntToLower(reason);

        do
        {
            if (HuntReasonStartsWith(lowered, L"gentlemen_") ||
                HuntReasonStartsWith(lowered, L"gentlekiller_") ||
                HuntReasonStartsWith(lowered, L"oxideharvest_") ||
                HuntReasonStartsWith(lowered, L"edr_killer_") ||
                HuntReasonStartsWith(lowered, L"eset_") ||
                HuntReasonStartsWith(lowered, L"byovd_"))
            {
                matched = true;
                break;
            }

            if (lowered == L"driver_service_binary_name_ioc" ||
                lowered == L"driver_service_installed" ||
                lowered == L"driver_service_running" ||
                lowered == L"known_security_product_process_target" ||
                lowered == L"loaded_driver_name_ioc" ||
                lowered == L"process_tampering_primitive_evidence" ||
                lowered == L"main_image_vad_file_delete_pending" ||
                lowered == L"main_section_object_file_delete_pending" ||
                lowered == L"main_image_vad_file_section_object_pointer_mismatch" ||
                lowered == L"main_section_object_file_section_object_pointer_mismatch" ||
                lowered == L"module_stomping_permission_evidence" ||
                lowered == L"module_entrypoint_write_permission_drift" ||
                lowered == L"security_tool_communication_blocking" ||
                lowered == L"security_tool_communication_throttling" ||
                lowered == L"qos_security_product_throttle_policy" ||
                lowered == L"edrchoker_state" ||
                lowered == L"bindflt_active_global_mapping" ||
                lowered == L"bind_link_security_product_path" ||
                lowered == L"bind_link_security_artifact_path" ||
                lowered == L"bind_link_protected_to_user_path" ||
                lowered == L"bind_link_inverse_trust_mapping" ||
                lowered == L"bind_link_protected_image_redirect" ||
                lowered == L"bind_link_inverse_image_redirect" ||
                lowered == L"bind_link_process_binding_state" ||
                lowered == L"bind_link_process_backing_correlation" ||
                lowered == L"bind_link_inverse_pair" ||
                lowered == L"cloudfiles_executable_placeholder_mapping" ||
                lowered == L"cloudfiles_ffi_ppl_image_mapping" ||
                lowered == L"cloudfiles_placeholder_modified_data" ||
                lowered == L"cloudfiles_ffi_live_disk_mismatch" ||
                lowered == L"wfp_security_product_block_filter" ||
                lowered == L"wfp_anticheat_block_filter" ||
                lowered == L"wfp_appid_block_condition")
            {
                matched = true;
                break;
            }
        } while (false);

        return matched;
    }

    bool HasOperatorHighSignalReason(const HuntFinding& finding)
    {
        bool matched = false;

        for (const std::wstring& reason : finding.ReasonCodes)
        {
            if (IsOperatorHighSignalReason(reason))
            {
                matched = true;
                break;
            }
        }

        return matched;
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
                    bool leftHighSignal = HasOperatorHighSignalReason(left);
                    bool rightHighSignal = HasOperatorHighSignalReason(right);
                    if (leftHighSignal != rightHighSignal)
                    {
                        return leftHighSignal;
                    }

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

std::wstring HuntFirstCommandLineImage(const std::wstring& commandLine)
{
    return FirstCommandLineImage(commandLine);
}

bool HuntProcessLifecycleSelfTest()
{
    const uint64_t entry =
        kKernelAddressMin + 0x1000;
    const uint64_t flink =
        kKernelAddressMin + 0x2000;
    const uint64_t blink =
        kKernelAddressMin + 0x3000;
    if (!ActiveProcessLinksNeighborsConsistent(
            entry,
            flink,
            blink,
            entry,
            entry) ||
        ActiveProcessLinksNeighborsConsistent(
            entry,
            entry,
            blink,
            entry,
            entry) ||
        ActiveProcessLinksNeighborsConsistent(
            entry,
            flink,
            blink,
            entry + sizeof(uint64_t),
            entry))
    {
        return false;
    }

    HuntProcessRecord apiPreferred = {};
    apiPreferred.ToolhelpImageName = L"stale.exe";
    apiPreferred.SystemProcessImageName = L"stale-system.exe";
    apiPreferred.ApiImagePath = L"C:\\verified\\current.exe";
    if (BestProcessImageName(apiPreferred) !=
        L"current.exe")
    {
        return false;
    }

    HuntProcessRecord child = {};
    HuntProcessRecord parent = {};
    child.Kernel.HasCreateTime = true;
    child.Kernel.CreateTime = 200;
    parent.Kernel.HasCreateTime = true;
    parent.Kernel.CreateTime = 100;
    parent.KernelImageName = L"parent.exe";
    if (!CanUseParentProcessIdentity(
            child,
            parent))
    {
        return false;
    }
    parent.Kernel.CreateTime = 300;
    if (CanUseParentProcessIdentity(
            child,
            parent))
    {
        return false;
    }

    HuntProcessRecord idle = {};
    idle.ProcessId = 0;
    idle.SystemProcessInformationSeen = true;
    idle.ToolhelpProcessSeen = true;
    if (HasUnresolvedApiOnlyProcessView(idle))
    {
        return false;
    }
    HuntProcessRecord apiOnly = idle;
    apiOnly.ProcessId = 100;
    if (!HasUnresolvedApiOnlyProcessView(apiOnly))
    {
        return false;
    }
    apiOnly.ActiveProcessLinksStableUnlinked = true;
    if (HasUnresolvedApiOnlyProcessView(apiOnly))
    {
        return false;
    }

    if (!CommandLineImageIsComparable(
            L"C:\\Windows\\System32\\ping.exe") ||
        !CommandLineImageIsComparable(
            L"tool.com") ||
        CommandLineImageIsComparable(
            L"ping") ||
        CommandLineImageIsComparable(
            L"C:\\Windows\\System32\\ping"))
    {
        return false;
    }
    const std::wstring terminalImage =
        EnsureTrailingSlash(
            ProgramFilesDirectory()) +
        L"WindowsApps\\Microsoft.WindowsTerminal_1.24.1.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe";
    if (!IsWindowsTerminalExecutionAliasShape(
            terminalImage,
            terminalImage,
            L"wt.exe") ||
        IsWindowsTerminalExecutionAliasShape(
            terminalImage,
            terminalImage,
            L"cmd.exe") ||
        IsWindowsTerminalExecutionAliasShape(
            terminalImage,
            L"C:\\Temp\\WindowsTerminal.exe",
            L"wt.exe") ||
        IsWindowsTerminalExecutionAliasShape(
            EnsureTrailingSlash(
                ProgramFilesDirectory()) +
                L"WindowsApps\\Microsoft.WindowsTerminal_1.24.1.0_x64__attacker\\WindowsTerminal.exe",
            EnsureTrailingSlash(
                ProgramFilesDirectory()) +
                L"WindowsApps\\Microsoft.WindowsTerminal_1.24.1.0_x64__attacker\\WindowsTerminal.exe",
            L"wt.exe"))
    {
        return false;
    }

    bool ok = false;
    FILETIME createTime = {};
    FILETIME exitTime = {};
    FILETIME kernelTime = {};
    FILETIME userTime = {};
    HANDLE currentProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        GetCurrentProcessId());
    do
    {
        if (currentProcess == nullptr ||
            !GetProcessTimes(
                currentProcess,
                &createTime,
                &exitTime,
                &kernelTime,
                &userTime))
        {
            break;
        }

        ULARGE_INTEGER observedCreate = {};
        observedCreate.LowPart = createTime.dwLowDateTime;
        observedCreate.HighPart = createTime.dwHighDateTime;
        if (observedCreate.QuadPart == 0)
        {
            break;
        }

        SnapshotProcessRecord exact = {};
        exact.ProcessId = GetCurrentProcessId();
        exact.CreateTime = observedCreate.QuadPart;
        exact.HasCreateTime = true;
        bool lifecycleChanged = true;
        if (!ProcessHandleMatchesSnapshot(
                currentProcess,
                exact,
                &lifecycleChanged) ||
            lifecycleChanged)
        {
            break;
        }

        SnapshotProcessRecord wrong = exact;
        wrong.CreateTime =
            observedCreate.QuadPart ==
                std::numeric_limits<uint64_t>::max()
            ? observedCreate.QuadPart - 1
            : observedCreate.QuadPart + 1;
        lifecycleChanged = false;
        if (ProcessHandleMatchesSnapshot(
                currentProcess,
                wrong,
                &lifecycleChanged) ||
            !lifecycleChanged)
        {
            break;
        }

        SnapshotProcessRecord noExactIdentity = {};
        lifecycleChanged = true;
        ok = ProcessHandleMatchesSnapshot(
                currentProcess,
                noExactIdentity,
                &lifecycleChanged) &&
            !lifecycleChanged;
    } while (false);

    if (currentProcess != nullptr)
    {
        CloseHandle(currentProcess);
    }
    return ok;
}

bool HuntCidTableAnchorSelfTest()
{
    const uint64_t processBase =
        kKernelAddressMin + 0x100000;
    const uint64_t threadBase =
        kKernelAddressMin + 0x200000;
    const uint64_t sharedAnchor =
        kKernelAddressMin + 0x500000;
    const uint64_t processDecoy =
        kKernelAddressMin + 0x600000;
    const uint64_t threadDecoy =
        kKernelAddressMin + 0x700000;

    auto appendRipLoad =
        [](std::vector<uint8_t>* code,
           uint64_t base,
           uint8_t modRm,
           uint64_t target) -> bool
        {
            if (code == nullptr)
            {
                return false;
            }
            const uint64_t pc =
                base + code->size();
            const int64_t displacement =
                static_cast<int64_t>(target) -
                static_cast<int64_t>(pc + 7);
            if (displacement <
                    std::numeric_limits<int32_t>::min() ||
                displacement >
                    std::numeric_limits<int32_t>::max())
            {
                return false;
            }

            const int32_t disp32 =
                static_cast<int32_t>(displacement);
            code->push_back(0x48);
            code->push_back(0x8b);
            code->push_back(modRm);
            for (size_t index = 0;
                 index < sizeof(disp32);
                 ++index)
            {
                code->push_back(
                    static_cast<uint8_t>(
                        (static_cast<uint32_t>(disp32) >>
                         (index * 8)) &
                        0xffu));
            }
            return true;
        };

    std::vector<uint8_t> processCode;
    std::vector<uint8_t> threadCode;
    if (!appendRipLoad(
            &processCode,
            processBase,
            0x05,
            sharedAnchor) ||
        !appendRipLoad(
            &processCode,
            processBase,
            0x0d,
            sharedAnchor) ||
        !appendRipLoad(
            &processCode,
            processBase,
            0x15,
            processDecoy) ||
        !appendRipLoad(
            &threadCode,
            threadBase,
            0x05,
            sharedAnchor) ||
        !appendRipLoad(
            &threadCode,
            threadBase,
            0x0d,
            sharedAnchor) ||
        !appendRipLoad(
            &threadCode,
            threadBase,
            0x15,
            threadDecoy))
    {
        return false;
    }
    processCode.push_back(0xc3);
    threadCode.push_back(0xc3);

    CidAnchorReferenceSet processReferences = {};
    CidAnchorReferenceSet threadReferences = {};
    if (!ExtractCidAnchorReferences(
            processBase,
            processCode,
            &processReferences) ||
        !ExtractCidAnchorReferences(
            threadBase,
            threadCode,
            &threadReferences) ||
        processReferences.
                RipRelativeQwordLoads[
                    sharedAnchor] != 2 ||
        threadReferences.
                RipRelativeQwordLoads[
                    sharedAnchor] != 2 ||
        processReferences.
                RipRelativeQwordLoads[
                    processDecoy] != 1 ||
        threadReferences.
                RipRelativeQwordLoads[
                    threadDecoy] != 1)
    {
        return false;
    }

    std::set<uint64_t> commonRepeated;
    for (const auto& processReference :
         processReferences.RipRelativeQwordLoads)
    {
        const auto threadReference =
            threadReferences.
                RipRelativeQwordLoads.find(
                    processReference.first);
        if (processReference.second >= 2 &&
            threadReference !=
                threadReferences.
                    RipRelativeQwordLoads.end() &&
            threadReference->second >= 2)
        {
            commonRepeated.insert(
                processReference.first);
        }
    }
    if (commonRepeated.size() != 1 ||
        *commonRepeated.begin() != sharedAnchor)
    {
        return false;
    }

    std::vector<uint8_t> truncated = processCode;
    truncated.pop_back();
    CidAnchorReferenceSet incomplete = {};
    if (ExtractCidAnchorReferences(
            processBase,
            truncated,
            &incomplete))
    {
        return false;
    }

    const uint64_t topologyPage0 =
        kKernelAddressMin + 0xa00000;
    const uint64_t topologyPage1 =
        topologyPage0 + kPageSize;
    std::vector<uint64_t> contiguousPointers =
        {topologyPage0,
         topologyPage1,
         0,
         0};
    std::vector<uint64_t> allocatedPointers;
    if (!CollectContiguousCidPointerPrefix(
            contiguousPointers,
            &allocatedPointers) ||
        allocatedPointers.size() != 2 ||
        allocatedPointers[0] != topologyPage0 ||
        allocatedPointers[1] != topologyPage1)
    {
        return false;
    }
    std::vector<uint64_t> sparsePointers =
        {topologyPage0,
         0,
         topologyPage1,
         0};
    if (CollectContiguousCidPointerPrefix(
            sparsePointers,
            &allocatedPointers) ||
        !allocatedPointers.empty())
    {
        return false;
    }
    std::vector<uint64_t> emptyPointers(4, 0);
    if (CollectContiguousCidPointerPrefix(
            emptyPointers,
            &allocatedPointers))
    {
        return false;
    }

    const uint64_t syntheticObjectBody =
        kKernelAddressMin + 0xb00000;
    const uint64_t syntheticPointerBits =
        (syntheticObjectBody &
         0x0000ffffffffffffull) >>
        4;
    uint64_t decodedObjectHeader = 0;
    uint64_t decodedObjectBody = 0;
    constexpr uint64_t syntheticBodyOffset = 0x30;
    if (!DecodeCidObjectAddresses(
            syntheticPointerBits,
            syntheticBodyOffset,
            &decodedObjectHeader,
            &decodedObjectBody) ||
        decodedObjectBody !=
            syntheticObjectBody ||
        decodedObjectHeader !=
            syntheticObjectBody -
                syntheticBodyOffset ||
        DecodeCidObjectAddresses(
            0,
            syntheticBodyOffset,
            &decodedObjectHeader,
            &decodedObjectBody) ||
        DecodeCidObjectAddresses(
            1ull << 44,
            syntheticBodyOffset,
            &decodedObjectHeader,
            &decodedObjectBody) ||
        DecodeCidObjectAddresses(
            0x1000,
            syntheticBodyOffset,
            &decodedObjectHeader,
            &decodedObjectBody))
    {
        return false;
    }
    if (!CidDirectThreadIdentityFieldsPlausible(
            32,
            32,
            0,
            syntheticObjectBody,
            0,
            0) ||
        !CidDirectThreadIdentityFieldsPlausible(
            36,
            36,
            4,
            syntheticObjectBody,
            1,
            0) ||
        CidDirectThreadIdentityFieldsPlausible(
            36,
            36,
            4,
            syntheticObjectBody,
            0,
            0) ||
        CidDirectThreadIdentityFieldsPlausible(
            36,
            40,
            4,
            syntheticObjectBody,
            1,
            0) ||
        CidDirectThreadIdentityFieldsPlausible(
            36,
            36,
            4,
            syntheticObjectBody,
            1,
            2) ||
        !CidDirectThreadIdentityFieldsPlausible(
            0,
            0,
            0,
            syntheticObjectBody,
            0,
            0) ||
        CidDirectThreadIdentityFieldsPlausible(
            0,
            0,
            4,
            syntheticObjectBody,
            1,
            0) ||
        CidThreadExitTimeForState(
            syntheticObjectBody,
            0) != 0 ||
        CidThreadExitTimeForState(
            syntheticObjectBody,
            1) != syntheticObjectBody ||
        !IsReservedCidZeroThread(0, 0) ||
        IsReservedCidZeroThread(0, 4) ||
        IsReservedCidZeroThread(4, 0))
    {
        return false;
    }

    TypeFieldInfo objectPointerBits = {};
    objectPointerBits.Offset = 0;
    objectPointerBits.Length = 44;
    objectPointerBits.BitPosition = 20;
    objectPointerBits.IsBitField = true;
    constexpr uint64_t syntheticEntrySize = 16;
    constexpr uint64_t syntheticEntryIndex = 7;
    std::vector<uint8_t> syntheticEntryPage(
        kPageSize,
        0);
    const uint64_t syntheticRawEntry =
        syntheticPointerBits << 20;
    std::memcpy(
        syntheticEntryPage.data() +
            syntheticEntryIndex *
                syntheticEntrySize,
        &syntheticRawEntry,
        sizeof(syntheticRawEntry));
    uint64_t extractedPointerBits = 0;
    if (!ExtractCidObjectPointerBits(
            syntheticEntryPage,
            syntheticEntrySize,
            syntheticEntryIndex,
            objectPointerBits,
            &extractedPointerBits) ||
        extractedPointerBits !=
            syntheticPointerBits ||
        ExtractCidObjectPointerBits(
            syntheticEntryPage,
            syntheticEntrySize,
            kPageSize /
                syntheticEntrySize,
            objectPointerBits,
            &extractedPointerBits))
    {
        return false;
    }
    std::vector<uint8_t> truncatedEntryPage(
        syntheticEntryPage.begin(),
        syntheticEntryPage.begin() +
            syntheticEntryIndex *
                syntheticEntrySize);
    if (ExtractCidObjectPointerBits(
            truncatedEntryPage,
            syntheticEntrySize,
            syntheticEntryIndex,
            objectPointerBits,
            &extractedPointerBits))
    {
        return false;
    }
    if (!CidPointerSnapshotHasAllocatableSlots(
            {0xfffull, syntheticPointerBits}) ||
        CidPointerSnapshotHasAllocatableSlots(
            {0xfffull}))
    {
        return false;
    }

    CidDirectEnumerationResult mergeDirect = {};
    mergeDirect.Complete = true;
    mergeDirect.Stable = true;
    CidDirectProcess mergeFirst = {};
    mergeFirst.ProcessId = 0x101;
    mergeFirst.Process.Context.Eprocess =
        kKernelAddressMin + 0xe00000;
    mergeFirst.Process.CreateTime = 0x111;
    mergeFirst.Process.HasCreateTime = true;
    CidDirectProcess mergeSecond = {};
    mergeSecond.ProcessId = 0x202;
    mergeSecond.Process.Context.Eprocess =
        kKernelAddressMin + 0xf00000;
    mergeSecond.Process.CreateTime = 0x222;
    mergeSecond.Process.HasCreateTime = true;
    mergeDirect.Processes.emplace(
        mergeFirst.ProcessId,
        mergeFirst);
    mergeDirect.Processes.emplace(
        mergeSecond.ProcessId,
        mergeSecond);

    HuntProcessRecord seededFirst = {};
    seededFirst.ProcessId = mergeFirst.ProcessId;
    seededFirst.Kernel.Eprocess =
        mergeFirst.Process.Context.Eprocess;
    seededFirst.Kernel.CreateTime =
        mergeFirst.Process.CreateTime;
    seededFirst.Kernel.HasCreateTime = true;
    HuntProcessRecord seededSecond = {};
    seededSecond.ProcessId = mergeSecond.ProcessId;
    seededSecond.Kernel.Eprocess =
        mergeSecond.Process.Context.Eprocess + 0x1000;
    seededSecond.Kernel.CreateTime =
        mergeSecond.Process.CreateTime;
    seededSecond.Kernel.HasCreateTime = true;
    std::map<uint32_t, HuntProcessRecord>
        mergeProcesses = {
            {seededFirst.ProcessId, seededFirst},
            {seededSecond.ProcessId, seededSecond}};
    uint64_t mergeDiscovered = 99;
    std::wstring mergeWarning = L"stale";
    if (MergeCidDirectProcessView(
            mergeDirect,
            &mergeProcesses,
            &mergeDiscovered,
            &mergeWarning) ||
        mergeDiscovered != 0 ||
        mergeWarning !=
            L"cid direct process merge: one or more seeded identities disagreed" ||
        mergeProcesses[seededFirst.ProcessId].
            HasCidTableView ||
        mergeProcesses[seededSecond.ProcessId].
            LifecycleChangedBeforeTriage ||
        !mergeProcesses[seededFirst.ProcessId].
            Warnings.empty() ||
        !mergeProcesses[seededSecond.ProcessId].
            Warnings.empty())
    {
        return false;
    }
    mergeProcesses[seededSecond.ProcessId].
        Kernel.Eprocess =
            mergeSecond.Process.Context.Eprocess;
    if (!MergeCidDirectProcessView(
            mergeDirect,
            &mergeProcesses,
            &mergeDiscovered,
            &mergeWarning) ||
        mergeDiscovered != 0 ||
        !mergeWarning.empty() ||
        !mergeProcesses[seededFirst.ProcessId].
            HasCidTableView ||
        !mergeProcesses[seededSecond.ProcessId].
            HasCidTableView)
    {
        return false;
    }

    CidDirectThread identity = {};
    identity.ThreadId = 100;
    identity.ProcessId = 200;
    identity.Ethread =
        kKernelAddressMin + 0xc00000;
    identity.Eprocess =
        kKernelAddressMin + 0xd00000;
    identity.CreateTime = 300;
    identity.ExitTime = 0;
    identity.HasCreateTime = true;
    identity.HasExitTime = true;
    std::map<uint32_t, CidDirectThread>
        firstKernelView = {{identity.ThreadId, identity}};
    std::map<uint32_t, CidDirectThread>
        secondKernelView = firstKernelView;
    const CidDirectThread* currentIdentity = nullptr;
    if (GetStableCidKernelPresence(
            firstKernelView,
            secondKernelView,
            identity.ThreadId,
            &currentIdentity) !=
            CidViewPresence::StableSeen ||
        currentIdentity == nullptr ||
        !CidThreadIdentityEqual(
            *currentIdentity,
            identity))
    {
        return false;
    }
    secondKernelView[identity.ThreadId].Ethread +=
        0x1000;
    if (GetStableCidKernelPresence(
            firstKernelView,
            secondKernelView,
            identity.ThreadId,
            &currentIdentity) !=
            CidViewPresence::Unstable ||
        CidSeenKernelIdentityAgrees(
            CidViewPresence::StableSeen,
            &secondKernelView[identity.ThreadId],
            &identity))
    {
        return false;
    }
    firstKernelView.clear();
    secondKernelView.clear();
    if (GetStableCidKernelPresence(
            firstKernelView,
            secondKernelView,
            identity.ThreadId,
            &currentIdentity) !=
            CidViewPresence::StableAbsent ||
        !CidSeenKernelIdentityAgrees(
            CidViewPresence::StableAbsent,
            nullptr,
            &identity))
    {
        return false;
    }

    const CidViewPresence seen =
        CidViewPresence::StableSeen;
    const CidViewPresence absent =
        CidViewPresence::StableAbsent;
    const CidViewPresence unstable =
        CidViewPresence::Unstable;
    if (!IsCoherentCidThreadLifecycleTransition(
            true,
            true,
            false) ||
        IsCoherentCidThreadLifecycleTransition(
            false,
            true,
            false) ||
        IsCoherentCidThreadLifecycleTransition(
            true,
            false,
            false) ||
        IsCoherentCidThreadLifecycleTransition(
            true,
            true,
            true))
    {
        return false;
    }
    const auto classify =
        [](bool kernelIdentity,
           bool apiIdentity,
           bool views,
           bool lifecycle,
           bool terminated,
           uint64_t exitTime,
           CidViewPresence direct,
           CidViewPresence executive,
           CidViewPresence scheduler,
           CidViewPresence system,
           CidViewPresence toolhelp)
        {
            return ClassifyCidThreadCrossView(
                kernelIdentity,
                apiIdentity,
                views,
                lifecycle,
                terminated,
                exitTime,
                direct,
                executive,
                scheduler,
                system,
                toolhelp);
        };
    if (classify(
            true, false, true, true, false, 0,
            seen, absent, absent, absent, absent) !=
            CidThreadCrossViewDecision::DirectOnly ||
        classify(
            true, false, true, true, false, 0,
            absent, seen, seen, seen, seen) !=
            CidThreadCrossViewDecision::MissingFromCid ||
        classify(
            true, false, true, true, false, 0,
            seen, absent, seen, seen, seen) !=
            CidThreadCrossViewDecision::ExecutiveUnlinked ||
        classify(
            true, false, true, true, false, 0,
            seen, seen, absent, seen, seen) !=
            CidThreadCrossViewDecision::SchedulerUnlinked ||
        classify(
            true, false, true, true, false, 0,
            seen, seen, seen, absent, absent) !=
            CidThreadCrossViewDecision::ApiHidden ||
        classify(
            false, true, true, false, false, 0,
            absent, absent, absent, seen, seen) !=
            CidThreadCrossViewDecision::ApiOnly ||
        classify(
            true, false, true, true, true, 0,
            seen, absent, absent, absent, absent) !=
            CidThreadCrossViewDecision::None ||
        classify(
            true, false, true, true, false, 1,
            seen, absent, absent, absent, absent) !=
            CidThreadCrossViewDecision::None ||
        classify(
            true, false, false, true, false, 0,
            seen, absent, absent, absent, absent) !=
            CidThreadCrossViewDecision::None ||
        classify(
            true, false, true, true, false, 0,
            unstable, absent, absent, absent, absent) !=
            CidThreadCrossViewDecision::None ||
        classify(
            false, false, true, false, false, 0,
            absent, absent, absent, seen, seen) !=
            CidThreadCrossViewDecision::None)
    {
        return false;
    }

    HuntProcessRecord cidOnly = {};
    cidOnly.ProcessId = 4242;
    cidOnly.Kernel.ProcessId = 4242;
    cidOnly.Kernel.Eprocess =
        kKernelAddressMin + 0x900000;
    cidOnly.Kernel.HasCreateTime = true;
    cidOnly.Kernel.CreateTime = 1;
    cidOnly.Kernel.HasExitTime = true;
    cidOnly.Kernel.ExitTime = 0;
    cidOnly.Kernel.HasActiveThreads = true;
    cidOnly.Kernel.ActiveThreads = 1;
    cidOnly.HasCidTableView = true;
    cidOnly.CidTableSeen = true;
    cidOnly.CidTableEnumerated = true;
    cidOnly.CidTableDiscovered = true;
    cidOnly.CidApiViewsRevalidated = true;
    cidOnly.CidIdentityRevalidated = true;
    cidOnly.ActiveProcessLinksRevalidated = true;
    cidOnly.ActiveProcessLinksStableUnlinked = true;
    if (!CanUseSeededProcessAsThreadOwner(
            cidOnly,
            true) ||
        CanUseSeededProcessAsThreadOwner(
            cidOnly,
            false))
    {
        return false;
    }
    constexpr uint32_t lateProcessId = 4244;
    std::set<uint32_t> preTriageProcessIds = {
        cidOnly.ProcessId};
    CidDirectEnumerationResult arrivalView = {};
    arrivalView.Processes.emplace(
        cidOnly.ProcessId,
        CidDirectProcess{});
    arrivalView.Processes.emplace(
        lateProcessId,
        CidDirectProcess{});
    std::map<uint32_t, HuntProcessRecord>
        arrivalProcesses;
    arrivalProcesses.emplace(
        cidOnly.ProcessId,
        cidOnly);
    HuntProcessRecord lateProcess = {};
    lateProcess.ProcessId = lateProcessId;
    arrivalProcesses.emplace(
        lateProcessId,
        std::move(lateProcess));
    if (MarkPostTriageProcessArrivals(
            preTriageProcessIds,
            arrivalView,
            &arrivalProcesses) != 1 ||
        arrivalProcesses[cidOnly.ProcessId].
            LifecycleChangedBeforeTriage ||
        !arrivalProcesses[lateProcessId].
            LifecycleChangedBeforeTriage ||
        arrivalProcesses[lateProcessId].
            Warnings.empty())
    {
        return false;
    }

    HuntResult positive = {};
    AddProcessViewFindings(
        &positive,
        cidOnly);
    if (positive.Findings.size() != 1 ||
        positive.Findings[0].Risk != L"high" ||
        positive.Findings[0].Confidence != L"high" ||
        !ContainsWideValue(
            positive.Findings[0].ReasonCodes,
            L"cid_only_process"))
    {
        return false;
    }

    HuntProcessRecord raceControl = cidOnly;
    raceControl.CidIdentityRevalidated = false;
    raceControl.LifecycleChangedBeforeTriage = true;
    if (CanUseSeededProcessAsThreadOwner(
            raceControl,
            true))
    {
        return false;
    }
    HuntResult raceNegative = {};
    AddProcessViewFindings(
        &raceNegative,
        raceControl);
    if (!raceNegative.Findings.empty())
    {
        return false;
    }

    HuntProcessRecord visibleControl = cidOnly;
    visibleControl.ActiveProcessLinksSeen = true;
    visibleControl.SystemProcessInformationSeen = true;
    visibleControl.ToolhelpProcessSeen = true;
    HuntResult visibleNegative = {};
    AddProcessViewFindings(
        &visibleNegative,
        visibleControl);
    if (!visibleNegative.Findings.empty())
    {
        return false;
    }

    HuntResult cidJsonResult = {};
    cidJsonResult.CidTableFullEnumeration = true;
    cidJsonResult.CidTableFullProcessEnumeration = true;
    cidJsonResult.CidTableDirectEntryEnumeration = true;
    cidJsonResult.CidTableFullThreadEnumeration = true;
    cidJsonResult.CidTableThreadCrossViewComplete = true;
    cidJsonResult.SystemProcessInfoThreadCount = 10;
    cidJsonResult.ToolhelpThreadCount = 10;
    cidJsonResult.CidTableDirectEntryCount = 3;
    cidJsonResult.CidTableDirectProcessCount = 2;
    cidJsonResult.CidTableDirectThreadCount = 1;
    HuntCidThreadRecord cidThreadJson = {};
    cidThreadJson.ThreadId = identity.ThreadId;
    cidThreadJson.ProcessId = identity.ProcessId;
    cidThreadJson.ObjectHeader =
        decodedObjectHeader;
    cidThreadJson.Ethread = identity.Ethread;
    cidThreadJson.Eprocess = identity.Eprocess;
    cidThreadJson.CreateTime = identity.CreateTime;
    cidThreadJson.ExitTime = identity.ExitTime;
    cidThreadJson.HasCreateTime = true;
    cidThreadJson.HasExitTime = true;
    cidThreadJson.DirectCidSeen = true;
    cidThreadJson.ExecutiveThreadListSeen = true;
    cidThreadJson.SchedulerThreadListSeen = true;
    cidThreadJson.SystemProcessInformationSeen = true;
    cidThreadJson.ToolhelpThreadSeen = true;
    cidThreadJson.IdentityRevalidated = true;
    cidThreadJson.ViewsRevalidated = true;
    cidJsonResult.CidThreads.push_back(cidThreadJson);
    const std::wstring cidJson =
        BuildHuntJson(cidJsonResult);
    return
        cidJson.find(
            L"\"cid_table_full_enumeration\":true") !=
            std::wstring::npos &&
        cidJson.find(
            L"\"cid_table_direct_entry_enumeration\":true") !=
            std::wstring::npos &&
        cidJson.find(
            L"\"cid_table_direct_threads\":1") !=
            std::wstring::npos &&
        cidJson.find(
            L"\"cid_threads\":[") !=
            std::wstring::npos &&
        cidJson.find(
            L"\"tid\":100") !=
            std::wstring::npos &&
        cidJson.find(
            L"\"identity_revalidated\":true") !=
            std::wstring::npos;
}

bool HuntDiskPeBoundsSelfTest()
{
    wchar_t tempDirectory[MAX_PATH + 1] = {};
    DWORD tempLength = GetTempPathW(
        static_cast<DWORD>(_countof(tempDirectory)),
        tempDirectory);
    if (tempLength == 0 || tempLength >= _countof(tempDirectory))
    {
        return false;
    }

    wchar_t tempPath[MAX_PATH + 1] = {};
    if (GetTempFileNameW(tempDirectory, L"kpe", 0, tempPath) == 0)
    {
        return false;
    }

    auto writeImage =
        [&](const std::vector<uint8_t>& bytes) -> bool
        {
            if (bytes.empty() ||
                bytes.size() > std::numeric_limits<DWORD>::max())
            {
                return false;
            }

            HANDLE file = CreateFileW(
                tempPath,
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_TEMPORARY,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            DWORD written = 0;
            const DWORD byteCount =
                static_cast<DWORD>(bytes.size());
            const bool writeOk =
                WriteFile(
                    file,
                    bytes.data(),
                    byteCount,
                    &written,
                    nullptr) != FALSE &&
                written == byteCount;
            CloseHandle(file);
            return writeOk;
        };

    bool malformedRejected = false;
    std::vector<uint8_t> malformedBytes(0x1000, 0);
    IMAGE_DOS_HEADER malformedDos = {};
    malformedDos.e_magic = IMAGE_DOS_SIGNATURE;
    malformedDos.e_lfanew = static_cast<LONG>(
        malformedBytes.size() -
        sizeof(uint32_t) -
        sizeof(IMAGE_FILE_HEADER));
    std::memcpy(
        malformedBytes.data(),
        &malformedDos,
        sizeof(malformedDos));

    const size_t malformedNtOffset =
        static_cast<size_t>(malformedDos.e_lfanew);
    const uint32_t signature = IMAGE_NT_SIGNATURE;
    std::memcpy(
        malformedBytes.data() + malformedNtOffset,
        &signature,
        sizeof(signature));
    IMAGE_FILE_HEADER malformedFileHeader = {};
    std::memcpy(
        malformedBytes.data() +
            malformedNtOffset +
            sizeof(signature),
        &malformedFileHeader,
        sizeof(malformedFileHeader));

    if (writeImage(malformedBytes))
    {
        DiskPeMetadata metadata = {};
        std::wstring error;
        malformedRejected =
            !ReadDiskPeMetadata(tempPath, &metadata, &error);
    }

    constexpr size_t kExtendedNtOffset = 0x1800;
    constexpr size_t kFixedOptionalBytes =
        offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    const size_t optionalOffset =
        kExtendedNtOffset +
        sizeof(uint32_t) +
        sizeof(IMAGE_FILE_HEADER);
    const size_t sectionOffset =
        optionalOffset + kFixedOptionalBytes;
    std::vector<uint8_t> validBytes(
        std::max<size_t>(
            0x2000,
            sectionOffset + sizeof(IMAGE_SECTION_HEADER)),
        0);

    IMAGE_DOS_HEADER validDos = {};
    validDos.e_magic = IMAGE_DOS_SIGNATURE;
    validDos.e_lfanew =
        static_cast<LONG>(kExtendedNtOffset);
    std::memcpy(
        validBytes.data(),
        &validDos,
        sizeof(validDos));
    std::memcpy(
        validBytes.data() + kExtendedNtOffset,
        &signature,
        sizeof(signature));

    IMAGE_FILE_HEADER validFileHeader = {};
    validFileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    validFileHeader.NumberOfSections = 1;
    validFileHeader.SizeOfOptionalHeader =
        static_cast<WORD>(kFixedOptionalBytes);
    validFileHeader.Characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE |
        IMAGE_FILE_LARGE_ADDRESS_AWARE;
    std::memcpy(
        validBytes.data() +
            kExtendedNtOffset +
            sizeof(signature),
        &validFileHeader,
        sizeof(validFileHeader));

    IMAGE_OPTIONAL_HEADER64 validOptional = {};
    validOptional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    validOptional.AddressOfEntryPoint = 0x2000;
    validOptional.ImageBase = 0x140000000ull;
    validOptional.SectionAlignment = 0x1000;
    validOptional.FileAlignment = 0x200;
    validOptional.SizeOfImage = 0x3000;
    validOptional.SizeOfHeaders = 0x2000;
    validOptional.NumberOfRvaAndSizes = 0;
    std::memcpy(
        validBytes.data() + optionalOffset,
        &validOptional,
        kFixedOptionalBytes);

    IMAGE_SECTION_HEADER validSection = {};
    const char textName[] = ".text";
    std::memcpy(
        validSection.Name,
        textName,
        sizeof(textName) - 1);
    validSection.Misc.VirtualSize = 0x1000;
    validSection.VirtualAddress = 0x2000;
    validSection.Characteristics =
        IMAGE_SCN_CNT_CODE |
        IMAGE_SCN_MEM_EXECUTE |
        IMAGE_SCN_MEM_READ;
    std::memcpy(
        validBytes.data() + sectionOffset,
        &validSection,
        sizeof(validSection));

    bool extendedHeaderAccepted = false;
    DiskPeMetadata capturedMetadata = {};
    if (writeImage(validBytes))
    {
        std::wstring error;
        extendedHeaderAccepted =
            ReadDiskPeMetadata(
                tempPath,
                &capturedMetadata,
                &error) &&
            capturedMetadata.HasFileIdentity &&
            capturedMetadata.ImageBase == validOptional.ImageBase &&
            capturedMetadata.EntryPointRva ==
                validOptional.AddressOfEntryPoint &&
            capturedMetadata.SizeOfImage == validOptional.SizeOfImage &&
            capturedMetadata.SizeOfHeaders ==
                validOptional.SizeOfHeaders &&
            capturedMetadata.HasEntryPoint &&
            capturedMetadata.HasExecutableSection &&
            capturedMetadata.FirstExecutableSectionRva ==
                validSection.VirtualAddress &&
            capturedMetadata.Sections.size() == 1;
    }

    bool undeclaredDirectoryRejected = false;
    bool changedFileRejected = false;
    validOptional.NumberOfRvaAndSizes = 1;
    std::memcpy(
        validBytes.data() + optionalOffset,
        &validOptional,
        kFixedOptionalBytes);
    // Make the stale-metadata check deterministic even on filesystems whose
    // last-write timestamp does not advance between two immediate writes.
    validBytes.push_back(0);
    if (writeImage(validBytes))
    {
        std::vector<uint8_t> stalePage;
        std::wstring staleError;
        changedFileRejected =
            !ReadDiskPageForRva(
                tempPath,
                capturedMetadata,
                0,
                &stalePage,
                &staleError);

        DiskPeMetadata metadata = {};
        std::wstring error;
        undeclaredDirectoryRejected =
            !ReadDiskPeMetadata(tempPath, &metadata, &error);
    }

    DeleteFileW(tempPath);
    return
        malformedRejected &&
        extendedHeaderAccepted &&
        changedFileRejected &&
        undeclaredDirectoryRejected;
}

bool HuntBaseRelocationMaskSelfTest()
{
    if (!BytesAreAllZero({0, 0, 0, 0}) ||
        BytesAreAllZero({0, 0, 1, 0}))
    {
        return false;
    }

    IMAGE_DATA_DIRECTORY directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};
    directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1000, 0x40};
    directories[IMAGE_DIRECTORY_ENTRY_IAT] = {0x2000, 0x80};
    directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = {0x3000, 0x40};
    directories[IMAGE_DIRECTORY_ENTRY_TLS] = {0x4000, 0x40};
    directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = {0x5000, 0x40};
    std::vector<DiskPeMutableRange> loaderMutableRanges;
    AddLoaderMutableDirectoryRanges(
        &loaderMutableRanges,
        directories,
        _countof(directories));
    if (loaderMutableRanges.size() != 1 ||
        loaderMutableRanges[0].Rva != 0x2000 ||
        loaderMutableRanges[0].Size != 0x80)
    {
        return false;
    }

    DiskPeMetadata metadata = {};
    metadata.BaseRelocationTablePresent = true;
    metadata.BaseRelocationTableComplete = true;
    metadata.BaseRelocations =
    {
        {0x1010, sizeof(uint64_t)},
        {0x1ffc, sizeof(uint64_t)},
        {0x2008, sizeof(uint32_t)}
    };
    metadata.CrossPageRelocationRanges =
    {
        {0x1ffc, sizeof(uint64_t)}
    };
    metadata.ImageBase = 0x10000000ull;
    metadata.RelocationPages.insert(0x1000);
    HuntModuleRecord relocatedModule = {};
    relocatedModule.Base = 0x20000000ull;
    if (!PageHasExpectedRelocationDelta(
            relocatedModule,
            metadata,
            0x1000))
    {
        return false;
    }
    metadata.ManagedIlOnly = true;
    if (PageHasExpectedRelocationDelta(
            relocatedModule,
            metadata,
            0x1000))
    {
        return false;
    }
    metadata.ManagedIlOnly = false;

    std::vector<uint8_t> firstPage(
        static_cast<size_t>(kPageSize),
        0);
    std::vector<uint8_t> secondPage(
        static_cast<size_t>(kPageSize),
        0);
    const uint64_t firstValue = 0x0000000012345000ull;
    const uint64_t crossValue = 0x0000000076543000ull;
    const uint32_t secondValue = 0x12345000u;
    std::memcpy(
        firstPage.data() + 0x10,
        &firstValue,
        sizeof(firstValue));
    std::memcpy(
        firstPage.data() + 0xffc,
        &crossValue,
        sizeof(uint32_t));
    std::memcpy(
        secondPage.data(),
        reinterpret_cast<const uint8_t*>(&crossValue) +
            sizeof(uint32_t),
        sizeof(uint32_t));
    std::memcpy(
        secondPage.data() + 0x8,
        &secondValue,
        sizeof(secondValue));

    if (!ApplyBaseRelocationsToDiskPage(
            metadata,
            0x1000,
            0x2000,
            &firstPage,
            &secondPage))
    {
        return false;
    }

    uint64_t relocatedFirst = 0;
    uint8_t relocatedCrossBytes[sizeof(uint64_t)] = {};
    uint64_t relocatedCross = 0;
    std::memcpy(
        &relocatedFirst,
        firstPage.data() + 0x10,
        sizeof(relocatedFirst));
    std::memcpy(
        relocatedCrossBytes,
        firstPage.data() + 0xffc,
        sizeof(uint32_t));
    std::memcpy(
        relocatedCrossBytes + sizeof(uint32_t),
        secondPage.data(),
        sizeof(uint32_t));
    std::memcpy(
        &relocatedCross,
        relocatedCrossBytes,
        sizeof(relocatedCross));
    if (relocatedFirst != firstValue + 0x2000 ||
        relocatedCross != crossValue + 0x2000)
    {
        return false;
    }

    if (!ApplyBaseRelocationsToDiskPage(
            metadata,
            0x2000,
            0x2000,
            &secondPage,
            nullptr))
    {
        return false;
    }
    uint32_t relocatedSecond = 0;
    std::memcpy(
        &relocatedSecond,
        secondPage.data() + 0x8,
        sizeof(relocatedSecond));
    if (relocatedSecond != secondValue + 0x2000)
    {
        return false;
    }

    std::vector<uint8_t> live(
        static_cast<size_t>(kPageSize),
        0);
    std::vector<uint8_t> disk(
        static_cast<size_t>(kPageSize),
        0);
    live[0xffb] = 0x7f;
    live[0xffc] = 0x11;
    disk[0xffb] = 0x7f;
    MaskExpectedCrossPageRelocationBytes(
        metadata,
        0x1000,
        &live,
        &disk);
    if (live[0xffb] != 0x7f ||
        live[0xffc] != 0x11 ||
        live == disk)
    {
        return false;
    }
    live[0] = 0x22;
    disk[0] = 0x33;
    MaskExpectedCrossPageRelocationBytes(
        metadata,
        0x2000,
        &live,
        &disk);
    if (live[0] != 0 ||
        disk[0] != 0)
    {
        return false;
    }

    metadata.BaseRelocationTableComplete = false;
    const std::vector<uint8_t> before = firstPage;
    return !ApplyBaseRelocationsToDiskPage(
               metadata,
               0x1000,
               0x1000,
               &firstPage,
               &secondPage) &&
        firstPage == before;
}

bool HuntDynamicRelocationMaskSelfTest()
{
    std::vector<uint8_t> table;
    auto append16 = [&table](uint16_t value)
    {
        const size_t offset = table.size();
        table.resize(offset + sizeof(value));
        std::memcpy(table.data() + offset, &value, sizeof(value));
    };
    auto append32 = [&table](uint32_t value)
    {
        const size_t offset = table.size();
        table.resize(offset + sizeof(value));
        std::memcpy(table.data() + offset, &value, sizeof(value));
    };
    auto append64 = [&table](uint64_t value)
    {
        const size_t offset = table.size();
        table.resize(offset + sizeof(value));
        std::memcpy(table.data() + offset, &value, sizeof(value));
    };

    append32(1); // IMAGE_DYNAMIC_RELOCATION_TABLE.Version
    append32(0); // Size is back-filled below.
    append64(IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE);
    append32(0x84); // Entry payload size.
    append32(0x40); // Two function override records.
    append32(0x8340); // Original RVA.
    append32(0); // BDD offset.
    append32(sizeof(uint32_t)); // One overriding RVA.
    append32(0x0c); // One 12-byte relocation block.
    append32(0x8340); // Overriding RVA.
    append32(0x9000); // Fixup page RVA.
    append32(0x0c); // Block size.
    append16(static_cast<uint16_t>((IMAGE_FUNCTION_OVERRIDE_X64_REL32 << 12) | 0x11));
    append16(0); // Four-byte block padding.
    append32(0x8440); // Original RVA.
    append32(0x20); // Second BDD offset.
    append32(sizeof(uint32_t)); // One overriding RVA.
    append32(0x0c); // One 12-byte relocation block.
    append32(0x8440); // Overriding RVA.
    append32(0xa000); // Fixup page RVA.
    append32(0x0c); // Block size.
    append16(static_cast<uint16_t>((IMAGE_FUNCTION_OVERRIDE_X64_REL32 << 12) | 0x21));
    append16(0); // Four-byte block padding.
    append32(1); // BDD version.
    append32(0x18); // Three IMAGE_BDD_DYNAMIC_RELOCATION nodes.
    for (size_t index = 0; index < 3; ++index)
    {
        append16(0);
        append16(0);
        append32(0);
    }
    append32(1); // Second BDD version.
    append32(0x18); // Three IMAGE_BDD_DYNAMIC_RELOCATION nodes.
    for (size_t index = 0; index < 3; ++index)
    {
        append16(0);
        append16(0);
        append32(0);
    }

    const uint32_t tablePayloadSize =
        static_cast<uint32_t>(table.size() - sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE));
    std::memcpy(table.data() + sizeof(uint32_t), &tablePayloadSize, sizeof(tablePayloadSize));

    DiskPeMetadata metadata = {};
    if (!ParseDynamicRelocationTable(
            table,
            true,
            0x20000,
            &metadata.DynamicRelocationRanges) ||
        metadata.DynamicRelocationRanges.size() != 2 ||
        metadata.DynamicRelocationRanges[0].Rva != 0x9011 ||
        metadata.DynamicRelocationRanges[0].Size != sizeof(uint32_t) ||
        metadata.DynamicRelocationRanges[1].Rva != 0xa021 ||
        metadata.DynamicRelocationRanges[1].Size != sizeof(uint32_t))
    {
        return false;
    }

    std::vector<uint8_t> live(static_cast<size_t>(kPageSize), 0);
    std::vector<uint8_t> disk(static_cast<size_t>(kPageSize), 0);
    live[0x11] = 0x11;
    live[0x12] = 0x22;
    live[0x13] = 0x33;
    live[0x14] = 0x44;
    MaskExpectedDynamicRelocationBytes(metadata, 0x9000, &live, &disk);
    if (live != disk)
    {
        return false;
    }

    live[0x20] = 0x7f;
    MaskExpectedDynamicRelocationBytes(metadata, 0x9000, &live, &disk);
    if (live == disk)
    {
        return false;
    }

    const size_t entryOffset = sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE);
    const size_t payloadOffset = entryOffset + sizeof(IMAGE_DYNAMIC_RELOCATION64);
    const size_t recordOffset = payloadOffset + sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER);
    constexpr uint32_t kTestImageSize = 0x20000;

    std::vector<uint8_t> invalidOriginalRva = table;
    std::memcpy(
        invalidOriginalRva.data() +
            recordOffset +
            offsetof(
                IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION,
                OriginalRva),
        &kTestImageSize,
        sizeof(kTestImageSize));
    std::vector<DiskPeMutableRange> transactionalRanges =
    {
        {0x1234, sizeof(uint32_t)}
    };
    if (ParseDynamicRelocationTable(
            invalidOriginalRva,
            true,
            kTestImageSize,
            &transactionalRanges) ||
        transactionalRanges.size() != 1 ||
        transactionalRanges[0].Rva != 0x1234 ||
        transactionalRanges[0].Size != sizeof(uint32_t))
    {
        return false;
    }

    std::vector<uint8_t> invalidOverrideRva = table;
    std::memcpy(
        invalidOverrideRva.data() +
            recordOffset +
            sizeof(
                IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION),
        &kTestImageSize,
        sizeof(kTestImageSize));
    std::vector<DiskPeMutableRange> invalidOverrideRanges;
    if (ParseDynamicRelocationTable(
            invalidOverrideRva,
            true,
            kTestImageSize,
            &invalidOverrideRanges))
    {
        return false;
    }

    std::vector<uint8_t> invalidBddOffset = table;
    const uint32_t outOfBoundsBddOffset = 0xffffffffu;
    std::memcpy(
        invalidBddOffset.data() +
            recordOffset +
            offsetof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION, BDDOffset),
        &outOfBoundsBddOffset,
        sizeof(outOfBoundsBddOffset));
    std::vector<DiskPeMutableRange> invalidBddOffsetRanges;
    if (ParseDynamicRelocationTable(
            invalidBddOffset,
            true,
            kTestImageSize,
            &invalidBddOffsetRanges))
    {
        return false;
    }

    std::vector<uint8_t> invalidBddSize = table;
    const size_t bddSizeOffset =
        invalidBddSize.size() -
        3 * sizeof(IMAGE_BDD_DYNAMIC_RELOCATION) -
        sizeof(uint32_t);
    const uint32_t shortBddSize =
        2 * static_cast<uint32_t>(sizeof(IMAGE_BDD_DYNAMIC_RELOCATION));
    std::memcpy(
        invalidBddSize.data() + bddSizeOffset,
        &shortBddSize,
        sizeof(shortBddSize));
    std::vector<DiskPeMutableRange> invalidBddSizeRanges;
    if (ParseDynamicRelocationTable(
            invalidBddSize,
            true,
            kTestImageSize,
            &invalidBddSizeRanges))
    {
        return false;
    }

    table.pop_back();
    std::vector<DiskPeMutableRange> truncatedRanges;
    return !ParseDynamicRelocationTable(
        table,
        true,
        kTestImageSize,
        &truncatedRanges);
}

bool HuntEffectiveVadProtectionSelfTest()
{
    ProcessVadRecord vad = {};
    vad.StartAddress = 0x1000;
    vad.EndAddress = 0x2fff;
    vad.Executable = true;
    vad.WritableExecutable = true;
    vad.EffectiveProtectionComplete = true;

    ProcessVadProtectionRange rx = {};
    rx.StartAddress = 0x1000;
    rx.EndAddress = 0x1fff;
    rx.Committed = true;
    rx.Executable = true;
    vad.EffectiveProtectionRanges.push_back(rx);

    ProcessVadProtectionRange wx = {};
    wx.StartAddress = 0x2000;
    wx.EndAddress = 0x2fff;
    wx.Committed = true;
    wx.Executable = true;
    wx.Writable = true;
    wx.WritableExecutable = true;
    vad.EffectiveProtectionRanges.push_back(wx);

    HuntProcessRecord process = {};
    ProcessThreadRecord thread = {};
    thread.HasStartAddress = true;
    thread.StartAddress = 0x1100;
    process.ThreadRecords.push_back(thread);

    if (!VadAddressIsExecutable(vad, 0x1100) ||
        VadAddressIsWritableExecutable(vad, 0x1100) ||
        VadHasExecutionEvidence(process, vad, false, true))
    {
        return false;
    }

    process.ThreadRecords[0].StartAddress = 0x2100;
    if (!VadAddressIsWritableExecutable(vad, 0x2100) ||
        !VadHasExecutionEvidence(process, vad, false, true) ||
        VadRangeHasExecutionEvidence(
            process,
            vad,
            0x1000,
            0x1fff,
            false,
            false) ||
        !VadRangeHasExecutionEvidence(
            process,
            vad,
            0x2000,
            0x2fff,
            false,
            true))
    {
        return false;
    }

    vad.EffectiveProtectionComplete = false;
    if (!VadAddressIsWritableExecutable(vad, 0x1100))
    {
        return false;
    }

    ProcessApcEntryRecord kernelApc = {};
    kernelApc.HasKernelRoutine = true;
    kernelApc.KernelRoutine = 0x1234;
    kernelApc.KernelRoutineModule = L"invalid-kernel";
    kernelApc.NormalRoutine = 0x00007fff00001000ull;
    kernelApc.NormalRoutineModule = L"normal.dll";
    if (SelectApcFindingAddress(kernelApc) !=
            kernelApc.KernelRoutine ||
        SelectApcFindingModule(kernelApc) !=
            kernelApc.KernelRoutineModule)
    {
        return false;
    }

    ProcessApcEntryRecord userApc = {};
    userApc.HasKernelRoutine = true;
    userApc.KernelRoutine = 0xfffff80000001000ull;
    userApc.UserRoutine = 0x00007fff00002000ull;
    userApc.UserRoutineModule = L"user.dll";
    return SelectApcFindingAddress(userApc) ==
            userApc.UserRoutine &&
        SelectApcFindingModule(userApc) ==
            userApc.UserRoutineModule;
}

bool HuntEdrKillerProfileSelfTest()
{
    const std::wstring windowsApps =
        L"C:\\Program Files\\WindowsApps";
    if (!IsMicrosoftWindowsAppRuntimeModulePathShape(
            windowsApps,
            L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsAppRuntime.1.8_8000.1.0_x64__8wekyb3d8bbwe\\WindowsAppRuntime.DeploymentExtensions.OneCore.dll") ||
        !IsMicrosoftWindowsAppRuntimeModulePathShape(
            windowsApps,
            L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsAppRuntime.2_2.3.1.0_x64__8wekyb3d8bbwe\\WindowsAppSdk.AppxDeploymentExtensions.Desktop.dll") ||
        IsMicrosoftWindowsAppRuntimeModulePathShape(
            windowsApps,
            L"C:\\Program Files\\WindowsAppsBackup\\Microsoft.WindowsAppRuntime.1.8_8000.1.0_x64__8wekyb3d8bbwe\\WindowsAppRuntime.DeploymentExtensions.OneCore.dll") ||
        IsMicrosoftWindowsAppRuntimeModulePathShape(
            windowsApps,
            L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsAppRuntime.1.8_8000.1.0_x64__thirdparty\\WindowsAppRuntime.DeploymentExtensions.OneCore.dll") ||
        IsMicrosoftWindowsAppRuntimeModulePathShape(
            windowsApps,
            L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsAppRuntime.1.8_8000.1.0_x64__8wekyb3d8bbwe\\evil.dll"))
    {
        return false;
    }

    std::wstring oxideOptions;
    if (!OxideHarvestCommandLineShape(
            L"buildx64.exe -i in -u user -p pass -t target -o out",
            &oxideOptions) ||
        OxideHarvestCommandLineShape(
            L"buildx64.exe -i -x value -u user -p pass -t target -o out",
            &oxideOptions) ||
        OxideHarvestCommandLineShape(
            L"buildx64.exe -i /x -u user -p pass -t target -o out",
            &oxideOptions))
    {
        return false;
    }

    if (!PathContainsGentlemenCollection(
            L"C:\\Temp\\GentlemenCollection\\Kasps1.exe") ||
        !PathContainsGentlemenCollection(
            L"\"C:\\Temp\\GentlemenCollection\\Kasps1.exe\" -x") ||
        !PathContainsGentlemenCollection(
            L"C:\\Temp\\knhunt-123-GentlemenCollection\\Kasps1.exe") ||
        PathContainsGentlemenCollection(
            L"C:\\Temp\\GentlemenCollectionBackup\\Kasps1.exe") ||
        PathContainsGentlemenCollection(
            L"C:\\Temp\\Not-GentlemenCollection\\Kasps1.exe") ||
        PathContainsGentlemenCollection(
            L"C:\\Temp\\knhunt-x-GentlemenCollection\\Kasps1.exe") ||
        PathContainsGentlemenCollection(
            L"C:\\Temp\\xGentlemenCollection\\Kasps1.exe") ||
        PathContainsGentlemenCollection(
            L"C:\\Temp\\GentlemenCollection.exe"))
    {
        return false;
    }

    if (DriverServiceBinaryImagePath(
            L"C:\\Temp\\folder.sys\\vgk.sys -arg") !=
            L"C:\\Temp\\folder.sys\\vgk.sys" ||
        DriverServiceBinaryImagePath(
            L"\"C:\\Program Files\\Driver\\vgk.sys\" -arg") !=
            L"C:\\Program Files\\Driver\\vgk.sys" ||
        LeafName(DriverServiceBinaryImagePath(
            L"C:\\Temp\\vgk.sysbackup\\legit.exe")) !=
            L"legit.exe" ||
        LeafName(DriverServiceBinaryImagePath(
            L"\\??\\C:\\Temp\\GentlemenCollection\\PoisonX /x")) !=
            L"poisonx")
    {
        return false;
    }

    const std::wstring stableSystemDriver =
        WindowsDirectory() +
        L"\\System32\\drivers\\example.sys";
    if (ExpandEnvironmentText(
            L"%SystemRoot%\\System32\\drivers\\example.sys") !=
            stableSystemDriver ||
        ExpandEnvironmentText(
            L"%TEMP%\\GentlemenCollection\\example.sys") !=
            L"%TEMP%\\GentlemenCollection\\example.sys")
    {
        return false;
    }

    const EdrKillerProcessProfile* weak =
        FindEdrKillerProcessProfileByLeaf(L"avast.exe");
    bool suffixNormalized = false;
    bool suffixContextRequired = false;
    const EdrKillerProcessProfile* compact =
        FindEdrKillerProcessProfileByLeaf(
            L"mb2clear.exe",
            &suffixNormalized,
            nullptr,
            &suffixContextRequired,
            nullptr);
    return weak != nullptr &&
        !weak->StrongNameSignal &&
        compact != nullptr &&
        suffixNormalized &&
        suffixContextRequired;
}

bool HuntSecurityProcessFreezeSelfTest()
{
    auto makeThread =
        [](uint64_t tid, uint32_t suspendCount)
        {
            ProcessThreadRecord thread = {};
            thread.ThreadId = tid;
            thread.HasThreadId = true;
            thread.SuspendCount = suspendCount;
            thread.HasSuspendCount = true;
            thread.FreezeCount = 0;
            thread.HasFreezeCount = true;
            return thread;
        };

    HuntProcessRecord securityProcess = {};
    securityProcess.ProcessId = 4321;
    securityProcess.KernelImageName = L"MsMpEng.exe";
    securityProcess.ThreadInventoryComplete = true;
    securityProcess.ThreadSuspensionStateCoverageComplete =
        true;
    securityProcess.ThreadRecords =
        {makeThread(10, 1), makeThread(11, 2)};
    securityProcess.ThreadRecords[0].Ethread = 0xffff800000001000ull;
    securityProcess.ThreadRecords[1].Ethread = 0xffff800000002000ull;
    securityProcess.ThreadsVisited =
        securityProcess.ThreadRecords.size();
    securityProcess.SuspensionStateResolvedThreads =
        securityProcess.ThreadRecords.size();
    securityProcess.SuspendedThreads =
        securityProcess.ThreadRecords.size();

    HuntResult positive = {};
    AddThreadFindings(&positive, securityProcess);
    if (positive.Findings.size() != 1 ||
        positive.Findings[0].ClassName !=
            L"security_tool_impairment" ||
        positive.Findings[0].Risk != L"high" ||
        positive.Findings[0].Confidence != L"high" ||
        std::find(
            positive.Findings[0].ReasonCodes.begin(),
            positive.Findings[0].ReasonCodes.end(),
            L"all_observed_threads_suspended") ==
            positive.Findings[0].ReasonCodes.end() ||
        positive.Findings[0].Evidence[
            L"suspended_threads"] != L"2")
    {
        return false;
    }

    HuntProcessRecord mixed = securityProcess;
    mixed.ThreadRecords[1].SuspendCount = 0;
    HuntResult mixedResult = {};
    AddThreadFindings(&mixedResult, mixed);
    if (!mixedResult.Findings.empty())
    {
        return false;
    }

    HuntProcessRecord unknown = securityProcess;
    unknown.KernelImageName = L"business-agent.exe";
    HuntResult unknownResult = {};
    AddThreadFindings(&unknownResult, unknown);
    if (!unknownResult.Findings.empty())
    {
        return false;
    }

    HuntProcessRecord incomplete = securityProcess;
    incomplete.ThreadInventoryComplete = false;
    HuntResult incompleteResult = {};
    AddThreadFindings(&incompleteResult, incomplete);
    if (!incompleteResult.Findings.empty())
    {
        return false;
    }

    HuntProcessRecord unresolved = securityProcess;
    unresolved.ThreadRecords[1].HasFreezeCount = false;
    HuntResult unresolvedResult = {};
    AddThreadFindings(&unresolvedResult, unresolved);
    if (!unresolvedResult.Findings.empty())
    {
        return false;
    }

    ProcessThreadScanResult stableLeft = {};
    stableLeft.Records = securityProcess.ThreadRecords;
    stableLeft.ThreadsVisited = stableLeft.Records.size();
    stableLeft.SuspensionStateCoverageComplete = true;
    ProcessThreadScanResult stableRight = stableLeft;
    if (!SameThreadSuspensionEvidence(
            stableLeft,
            stableRight))
    {
        return false;
    }

    stableRight.Records[1].SuspendCount = 3;
    if (SameThreadSuspensionEvidence(
            stableLeft,
            stableRight))
    {
        return false;
    }

    stableRight = stableLeft;
    stableRight.Records[1].Ethread =
        0xffff800000003000ull;
    if (SameThreadSuspensionEvidence(
            stableLeft,
            stableRight))
    {
        return false;
    }

    stableRight = stableLeft;
    stableRight.Records[1].Ethread =
        stableRight.Records[0].Ethread;
    if (SameThreadSuspensionEvidence(
            stableLeft,
            stableRight))
    {
        return false;
    }

    HuntProcessRecord duplicate =
        securityProcess;
    duplicate.ThreadRecords[1].Ethread =
        duplicate.ThreadRecords[0].Ethread;
    HuntResult duplicateResult = {};
    AddThreadFindings(
        &duplicateResult,
        duplicate);
    if (!duplicateResult.Findings.empty())
    {
        return false;
    }

    stableRight = stableLeft;
    stableRight.SuspensionStateCoverageComplete =
        false;
    return !SameThreadSuspensionEvidence(
        stableLeft,
        stableRight);
}

bool HuntWfpPolicySelfTest()
{
    WfpRecord malicious = {};
    malicious.Kind = L"wfp.filter";
    malicious.Id = 4242;
    malicious.Key =
        L"{00000000-0000-0000-0000-000000000042}";
    malicious.Name = L"kn-test-security-block";
    malicious.ActionText = L"Block";
    malicious.FlagsText =
        L"persistent|clearActionRight";
    malicious.WeightText =
        L"0xffffffffffffffff";
    malicious.LayerName =
        L"FWPM_LAYER_ALE_AUTH_CONNECT_V4";
    malicious.ProviderName =
        L"kn-test-provider";
    malicious.HasAppIdCondition = true;
    malicious.AppIdText =
        L"\\device\\harddiskvolume3\\mssense.exe";

    HuntResult positive = {};
    if (!AddWfpFilterRecordFinding(
            &positive,
            malicious) ||
        positive.Findings.size() != 1 ||
        positive.SuspiciousWfpFilterCount != 1 ||
        positive.Findings[0].Risk != L"high" ||
        positive.Findings[0].Confidence != L"high" ||
        positive.Findings[0].ClassName !=
            L"network_filter_tampering" ||
        positive.Findings[0].Evidence[
            L"target_source"] !=
            L"app_id_condition")
    {
        return false;
    }

    const std::vector<std::wstring>& reasons =
        positive.Findings[0].ReasonCodes;
    static const wchar_t* kExpectedReasons[] =
    {
        L"wfp_security_product_block_filter",
        L"wfp_appid_block_condition",
        L"wfp_persistent_block_filter",
        L"wfp_clear_action_right_block",
        L"wfp_high_weight_block_filter",
        L"security_tool_communication_blocking"
    };
    for (const wchar_t* expected :
         kExpectedReasons)
    {
        if (std::find(
                reasons.begin(),
                reasons.end(),
                expected) == reasons.end())
        {
            return false;
        }
    }

    WfpRecord bitmaskBlock = malicious;
    bitmaskBlock.ActionText = L"BitmaskBlock";
    bitmaskBlock.FlagsText.clear();
    bitmaskBlock.WeightText = L"1";
    HuntResult bitmaskResult = {};
    if (!AddWfpFilterRecordFinding(
            &bitmaskResult,
            bitmaskBlock) ||
        bitmaskResult.Findings.size() != 1)
    {
        return false;
    }

    WfpRecord permit = malicious;
    permit.ActionText = L"Permit";
    HuntResult permitResult = {};
    if (AddWfpFilterRecordFinding(
            &permitResult,
            permit) ||
        !permitResult.Findings.empty())
    {
        return false;
    }

    WfpRecord disabled = malicious;
    disabled.FlagsText = L"persistent|disabled";
    HuntResult disabledResult = {};
    if (AddWfpFilterRecordFinding(
            &disabledResult,
            disabled) ||
        !disabledResult.Findings.empty())
    {
        return false;
    }

    WfpRecord unrelated = malicious;
    unrelated.AppIdText =
        L"\\device\\harddiskvolume3\\notepad.exe";
    HuntResult unrelatedResult = {};
    if (AddWfpFilterRecordFinding(
            &unrelatedResult,
            unrelated) ||
        !unrelatedResult.Findings.empty())
    {
        return false;
    }

    HuntResult incomplete = {};
    incomplete.WfpFilterCoverageIncomplete = true;
    incomplete.CoverageComplete = false;
    return BuildHuntJson(incomplete).find(
               L"\"wfp_filter_coverage_incomplete\":true") !=
        std::wstring::npos;
}

bool HuntQosPolicySelfTest()
{
    QosPolicyRecord malicious = {};
    malicious.Name = L"kn-test-throttle";
    malicious.InstanceId =
        L"{00000000-0000-0000-0000-000000000000}"
        L"\\kn-test-throttle";
    malicious.AppPathName = L"MsSense.exe";
    malicious.HasThrottleRate = true;
    malicious.ThrottleRateBitsPerSecond = 64;
    malicious.FromActiveStore = true;

    HuntResult positive = {};
    if (!AddQosPolicyRecordFinding(
            &positive,
            malicious) ||
        positive.Findings.size() != 1 ||
        positive.SuspiciousQosPolicyCount != 1 ||
        positive.Findings[0].Risk != L"high" ||
        positive.Findings[0].Confidence != L"high" ||
        positive.Findings[0].ClassName !=
            L"network_policy_tampering" ||
        positive.Findings[0].Evidence[
            L"active_store"] != L"true" ||
        positive.Findings[0].Evidence[
            L"throttle_rate_bits_per_second"] != L"64" ||
        positive.Findings[0].Evidence[
            L"throttle_rate_bytes_per_second"] != L"8")
    {
        return false;
    }

    QosPolicyRecord unrelated = malicious;
    unrelated.AppPathName = L"OneDrive.exe";
    HuntResult unrelatedResult = {};
    if (AddQosPolicyRecordFinding(
            &unrelatedResult,
            unrelated) ||
        !unrelatedResult.Findings.empty())
    {
        return false;
    }

    QosPolicyRecord ordinaryRate = malicious;
    ordinaryRate.ThrottleRateBitsPerSecond =
        1024ull * 1024ull * 8ull;
    HuntResult ordinaryRateResult = {};
    if (AddQosPolicyRecordFinding(
            &ordinaryRateResult,
            ordinaryRate) ||
        !ordinaryRateResult.Findings.empty())
    {
        return false;
    }

    QosPolicyRecord missingAction = malicious;
    missingAction.HasThrottleRate = false;
    HuntResult missingActionResult = {};
    return !AddQosPolicyRecordFinding(
               &missingActionResult,
               missingAction) &&
        missingActionResult.Findings.empty();
}

bool HuntBindFilterMappingSelfTest()
{
    if (!BindFilterPathIsUserControlledShape(
            L"C:\\Users\\Public\\payload.exe") ||
        !BindFilterPathIsUserControlledShape(
            L"C:\\ProgramData\\payload.exe") ||
        !BindFilterPathIsUserControlledShape(
            L"C:\\Temp\\payload.exe") ||
        !BindFilterPathIsUserControlledShape(
            L"C:\\Windows\\Temp\\payload.exe") ||
        BindFilterPathIsUserControlledShape(
            L"C:\\Program Files\\Vendor\\Temp\\payload.exe") ||
        !BindFilterPathIsProtected(
            L"C:\\Windows\\System32\\amsi.dll") ||
        BindFilterPathIsProtected(
            L"C:\\Windows\\System32Evil\\payload.dll") ||
        BindFilterPathIsProtected(
            L"C:\\Windows\\System32\\..\\Temp\\payload.dll") ||
        BindFilterPathIsProtected(
            L"C:\\Program Files Evil\\payload.dll") ||
        BindFilterPathIsProtected(
            L"C:\\Temp\\Windows\\System32\\payload.dll") ||
        BindFilterPathIsProtected(
            L"C:\\Temp\\Program Files\\payload.dll") ||
        BindFilterPathIsWindowsSystem(
            L"C:\\Windows\\System32\\..\\Temp\\payload.exe"))
    {
        return false;
    }

    BindFilterMappingRecord malicious = {};
    malicious.VolumeRoot = L"C:\\";
    malicious.VirtualRoot =
        L"C:\\Windows\\System32\\amsi.dll";
    malicious.TargetRoots =
        {L"C:\\Users\\Public\\amsi.dll"};
    malicious.Flags = 0x8;
    std::vector<BindFilterMappingRecord> records =
        {malicious};

    HuntResult positive = {};
    if (!AddBindFilterMappingRecordFinding(
            &positive,
            malicious,
            records) ||
        positive.Findings.size() != 1 ||
        positive.SuspiciousBindFilterMappingCount !=
            1 ||
        positive.Findings[0].Risk != L"high" ||
        positive.Findings[0].ClassName !=
            L"filesystem_virtualization_tampering" ||
        positive.Findings[0].Evidence[
            L"reparse_on_files"] != L"true")
    {
        return false;
    }

    BindFilterMappingRecord processBinding = {};
    processBinding.VolumeRoot = L"C:\\";
    processBinding.VirtualRoot =
        L"C:\\Windows\\System32\\winver.exe";
    processBinding.TargetRoots =
        {L"C:\\Windows\\System32\\cmd.exe"};
    HuntResult processBindingResult = {};
    if (!AddBindFilterMappingRecordFinding(
            &processBindingResult,
            processBinding,
            {processBinding}) ||
        processBindingResult.Findings.empty() ||
        std::find(
            processBindingResult.Findings[0].ReasonCodes.begin(),
            processBindingResult.Findings[0].ReasonCodes.end(),
            L"bind_link_protected_image_redirect") ==
            processBindingResult.Findings[0].ReasonCodes.end())
    {
        return false;
    }

    HuntProcessRecord boundProcess = {};
    boundProcess.ProcessId = 4242;
    boundProcess.ApiImagePath =
        processBinding.VirtualRoot;
    boundProcess.PebImagePath =
        processBinding.VirtualRoot;
    boundProcess.DiskPath =
        processBinding.VirtualRoot;
    boundProcess.MainImageBase = 0x140000000ull;
    boundProcess.MainSectionObject =
        0xffff800000001000ull;
    boundProcess.MainSectionSegment =
        0xffff800000002000ull;
    boundProcess.MainSectionControlArea =
        0xffff800000003000ull;
    boundProcess.MainSectionBackingPath =
        processBinding.TargetRoots[0];
    boundProcess.MainSectionBackingState =
        L"resolved";
    boundProcess.SectionBackingPath =
        processBinding.TargetRoots[0];
    boundProcess.SectionBackingState =
        L"resolved";
    std::map<uint32_t, HuntProcessRecord>
        boundProcesses =
        {
            {
                boundProcess.ProcessId,
                boundProcess
            }
        };
    HuntResult correlated = {};
    AddBindFilterProcessBindingFindings(
        &correlated,
        {processBinding},
        boundProcesses);
    if (correlated.Findings.size() != 1 ||
        correlated.BindFilterProcessBindingCount !=
            1 ||
        correlated.Findings[0].Risk != L"high" ||
        correlated.Findings[0].Confidence !=
            L"high" ||
        correlated.Findings[0].ProcessId !=
            boundProcess.ProcessId ||
        correlated.Findings[0].Evidence[
            L"independent_backing_views_agree"] !=
            L"true" ||
        std::find(
            correlated.Findings[0].ReasonCodes.begin(),
            correlated.Findings[0].ReasonCodes.end(),
            L"bind_link_process_binding_state") ==
            correlated.Findings[0].ReasonCodes.end() ||
        std::find(
            correlated.Findings[0].ReasonCodes.begin(),
            correlated.Findings[0].ReasonCodes.end(),
            L"bind_link_process_backing_correlation") ==
            correlated.Findings[0].ReasonCodes.end() ||
        BuildHuntJson(correlated).find(
            L"\"bindflt_process_bindings\":1") ==
            std::wstring::npos)
    {
        return false;
    }

    BindFilterMappingRecord rootRelativeBinding =
        processBinding;
    rootRelativeBinding.VirtualRoot =
        L"\\Windows\\System32\\winver.exe";
    rootRelativeBinding.TargetRoots =
        {L"\\Windows\\System32\\cmd.exe"};
    HuntResult rootRelativeCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &rootRelativeCorrelation,
        {rootRelativeBinding},
        boundProcesses);
    if (rootRelativeCorrelation.Findings.size() !=
            1 ||
        rootRelativeCorrelation.
                BindFilterProcessBindingCount !=
            1)
    {
        return false;
    }

    std::vector<wchar_t> cDeviceBuffer(
        1024,
        L'\0');
    if (QueryDosDeviceW(
            L"C:",
            cDeviceBuffer.data(),
            static_cast<DWORD>(
                cDeviceBuffer.size())) == 0)
    {
        return false;
    }
    const std::wstring cDevice =
        cDeviceBuffer.data();
    BindFilterMappingRecord devicePathBinding =
        processBinding;
    devicePathBinding.VirtualRoot =
        cDevice +
        L"\\Windows\\System32\\winver.exe";
    devicePathBinding.TargetRoots =
        {
            cDevice +
            L"\\Windows\\System32\\cmd.exe"
        };
    HuntResult devicePathCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &devicePathCorrelation,
        {devicePathBinding},
        boundProcesses);
    if (devicePathCorrelation.Findings.size() !=
            1 ||
        devicePathCorrelation.
                BindFilterProcessBindingCount !=
            1 ||
        devicePathCorrelation.Findings[0].Evidence[
            L"resolved_virtual_root"] !=
            processBinding.VirtualRoot ||
        devicePathCorrelation.Findings[0].Evidence[
            L"resolved_target_root"] !=
            processBinding.TargetRoots[0])
    {
        return false;
    }

    const std::wstring unmappedDevicePath =
        L"\\Device\\KnLiveDbgMissingVolume"
        L"\\Windows\\System32\\winver.exe";
    if (BindFilterPathInVolume(
            processBinding,
            unmappedDevicePath) !=
        unmappedDevicePath)
    {
        return false;
    }

    BindFilterMappingRecord crossVolumeBinding =
        rootRelativeBinding;
    crossVolumeBinding.VolumeRoot = L"D:\\";
    HuntResult crossVolumeCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &crossVolumeCorrelation,
        {crossVolumeBinding},
        boundProcesses);
    if (!crossVolumeCorrelation.Findings.empty() ||
        crossVolumeCorrelation.
                BindFilterProcessBindingCount !=
            0 ||
        !crossVolumeCorrelation.CoverageComplete)
    {
        return false;
    }

    HuntProcessRecord incompleteProcess =
        boundProcess;
    incompleteProcess.SectionBackingPath.clear();
    incompleteProcess.SectionBackingState =
        L"inaccessible";
    HuntResult incompleteCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &incompleteCorrelation,
        {processBinding},
        {
            {
                incompleteProcess.ProcessId,
                incompleteProcess
            }
        });
    if (!incompleteCorrelation.Findings.empty() ||
        incompleteCorrelation.BindFilterProcessBindingCount != 0 ||
        !incompleteCorrelation.BindFilterProcessCorrelationCoverageIncomplete ||
        incompleteCorrelation.CoverageComplete ||
        BuildHuntJson(incompleteCorrelation).find(
            L"\"bindflt_process_correlation_coverage_incomplete\":true") ==
            std::wstring::npos)
    {
        return false;
    }

    HuntProcessRecord conflictingProcess =
        boundProcess;
    conflictingProcess.SectionBackingPath =
        L"C:\\Windows\\System32\\notepad.exe";
    HuntResult conflictingCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &conflictingCorrelation,
        {processBinding},
        {
            {
                conflictingProcess.ProcessId,
                conflictingProcess
            }
        });
    if (!conflictingCorrelation.Findings.empty() ||
        conflictingCorrelation.BindFilterProcessBindingCount != 0 ||
        conflictingCorrelation.BindFilterProcessCorrelationCoverageIncomplete ||
        !conflictingCorrelation.CoverageComplete)
    {
        return false;
    }

    BindFilterMappingRecord benign = {};
    benign.VolumeRoot = L"C:\\";
    benign.VirtualRoot =
        L"C:\\Program Files\\WindowsApps\\PackageA";
    benign.TargetRoots =
        {L"C:\\Program Files\\WindowsApps\\PackageB"};
    HuntResult benignResult = {};
    if (AddBindFilterMappingRecordFinding(
            &benignResult,
            benign,
            {benign}) ||
        !benignResult.Findings.empty())
    {
        return false;
    }

    BindFilterMappingRecord programFilesImages = {};
    programFilesImages.VolumeRoot = L"C:\\";
    programFilesImages.VirtualRoot =
        L"C:\\Program Files\\Vendor\\Launcher.exe";
    programFilesImages.TargetRoots =
        {L"C:\\Program Files\\Vendor\\Helper.exe"};
    HuntResult programFilesImagesResult = {};
    if (AddBindFilterMappingRecordFinding(
            &programFilesImagesResult,
            programFilesImages,
            {programFilesImages}) ||
        !programFilesImagesResult.Findings.empty())
    {
        return false;
    }

    BindFilterMappingRecord nestedTempImages =
        programFilesImages;
    nestedTempImages.TargetRoots =
        {
            L"C:\\Program Files\\Vendor\\Temp\\Helper.exe"
        };
    HuntResult nestedTempImagesResult = {};
    if (AddBindFilterMappingRecordFinding(
            &nestedTempImagesResult,
            nestedTempImages,
            {nestedTempImages}) ||
        !nestedTempImagesResult.Findings.empty())
    {
        return false;
    }

    HuntProcessRecord programFilesProcess =
        boundProcess;
    programFilesProcess.ApiImagePath =
        programFilesImages.VirtualRoot;
    programFilesProcess.PebImagePath =
        programFilesImages.VirtualRoot;
    programFilesProcess.DiskPath =
        programFilesImages.VirtualRoot;
    programFilesProcess.MainSectionBackingPath =
        programFilesImages.TargetRoots[0];
    programFilesProcess.SectionBackingPath =
        programFilesImages.TargetRoots[0];
    HuntResult programFilesCorrelation = {};
    AddBindFilterProcessBindingFindings(
        &programFilesCorrelation,
        {programFilesImages},
        {
            {
                programFilesProcess.ProcessId,
                programFilesProcess
            }
        });
    if (!programFilesCorrelation.Findings.empty() ||
        programFilesCorrelation.BindFilterProcessBindingCount != 0 ||
        !programFilesCorrelation.CoverageComplete)
    {
        return false;
    }

    BindFilterMappingRecord sameImageServicing = {};
    sameImageServicing.VolumeRoot = L"C:\\";
    sameImageServicing.VirtualRoot =
        L"C:\\Windows\\System32\\ordinary.exe";
    sameImageServicing.TargetRoots =
        {L"C:\\Windows\\WinSxS\\ordinary.exe"};
    HuntResult sameImageServicingResult = {};
    if (AddBindFilterMappingRecordFinding(
            &sameImageServicingResult,
            sameImageServicing,
            {sameImageServicing}) ||
        !sameImageServicingResult.Findings.empty())
    {
        return false;
    }

    BindFilterMappingRecord inverse = {};
    inverse.VolumeRoot = L"C:\\";
    inverse.VirtualRoot =
        L"C:\\Users\\Public\\payload.exe";
    inverse.TargetRoots =
        {L"C:\\Windows\\System32\\winver.exe"};
    BindFilterMappingRecord forward = {};
    forward.VolumeRoot = L"C:\\";
    forward.VirtualRoot =
        L"C:\\Windows\\System32\\winver.exe";
    forward.TargetRoots =
        {L"C:\\Users\\Public\\payload.exe"};
    records = {inverse, forward};
    HuntResult inverseResult = {};
    if (!AddBindFilterMappingRecordFinding(
            &inverseResult,
            inverse,
            records) ||
        inverseResult.Findings.empty() ||
        std::find(
            inverseResult.Findings[0].ReasonCodes.begin(),
            inverseResult.Findings[0].ReasonCodes.end(),
            L"bind_link_inverse_pair") ==
            inverseResult.Findings[0].ReasonCodes.end())
    {
        return false;
    }

    BindFilterMappingRecord crossVolumeInverseA = {};
    crossVolumeInverseA.VolumeRoot = L"C:\\";
    crossVolumeInverseA.VirtualRoot =
        L"\\Lab\\source.exe";
    crossVolumeInverseA.TargetRoots =
        {L"\\Lab\\target.exe"};
    BindFilterMappingRecord crossVolumeInverseB = {};
    crossVolumeInverseB.VolumeRoot = L"D:\\";
    crossVolumeInverseB.VirtualRoot =
        L"\\Lab\\target.exe";
    crossVolumeInverseB.TargetRoots =
        {L"\\Lab\\source.exe"};
    if (BindFilterMappingHasInverse(
            crossVolumeInverseA,
            {
                crossVolumeInverseA,
                crossVolumeInverseB
            }))
    {
        return false;
    }

    BindFilterMappingRecord unrelated = {};
    unrelated.VolumeRoot = L"C:\\";
    unrelated.VirtualRoot =
        L"C:\\Lab\\source.txt";
    unrelated.TargetRoots =
        {L"C:\\Lab\\target.txt"};
    HuntResult unrelatedResult = {};
    return !AddBindFilterMappingRecordFinding(
               &unrelatedResult,
               unrelated,
               {unrelated}) &&
        unrelatedResult.Findings.empty();
}

bool HuntCloudFilePlaceholderSelfTest()
{
    const std::wstring rootRelativeBacking =
        L"\\fixture\\CloudFilesFixture.exe";
    if (OpenPathForResolvedBacking(
            rootRelativeBacking,
            L"C:\\fixture\\CloudFilesFixture.exe") !=
            L"C:\\fixture\\CloudFilesFixture.exe" ||
        OpenPathForResolvedBacking(
            rootRelativeBacking,
            L"D:\\other\\CloudFilesFixture.exe") !=
            rootRelativeBacking)
    {
        return false;
    }

    std::vector<HuntModuleRecord> mergedModules;
    HuntModuleRecord loaderModule = {};
    loaderModule.Base = 0x140000000;
    loaderModule.Size = 45056;
    loaderModule.Name = L"CloudFilesFixture.exe";
    loaderModule.Path =
        L"C:\\fixture\\CloudFilesFixture.exe";
    loaderModule.ToolhelpSeen = true;
    mergedModules.push_back(loaderModule);

    HuntModuleRecord vadModule = {};
    vadModule.Base = loaderModule.Base;
    vadModule.Size = loaderModule.Size;
    vadModule.VadSectionSeen = true;
    vadModule.VadAddress = 0xffff800000001000;
    vadModule.VadBackingPath =
        rootRelativeBacking;
    vadModule.VadBackingState = L"resolved";
    MergeModule(
        &mergedModules,
        vadModule);
    if (mergedModules.size() != 1 ||
        mergedModules[0].VadImageSeen ||
        !IsCloudFileImageCandidate(
            mergedModules[0]) ||
        OpenPathForResolvedBacking(
            mergedModules[0].VadBackingPath,
            mergedModules[0].Path) !=
            loaderModule.Path)
    {
        return false;
    }

    CloudFilePlaceholderRecord placeholder = {};
    placeholder.CloudReparseTag = true;
    placeholder.IsCloudPlaceholder = true;
    placeholder.PlaceholderStateAvailable = true;
    placeholder.PlaceholderInfoAvailable = true;
    placeholder.MetadataCoverageComplete = true;
    placeholder.PlaceholderState = 0x00000001;
    placeholder.InSyncState = 1;

    const CloudFileMappingDecision benign =
        EvaluateCloudFileMapping(
            placeholder,
            true,
            0,
            false,
            {});
    if (!benign.IsPlaceholder ||
        benign.EmitFinding ||
        benign.MetadataCoverageIncomplete ||
        benign.ProtectionCoverageIncomplete)
    {
        return false;
    }

    CloudFilePlaceholderRecord tagMasked =
        placeholder;
    tagMasked.CloudReparseTag = false;
    tagMasked.PlaceholderInfoIdentificationFallbackUsed =
        true;
    const CloudFileMappingDecision metadataIdentified =
        EvaluateCloudFileMapping(
            tagMasked,
            true,
            0,
            false,
            {});
    if (!metadataIdentified.IsPlaceholder ||
        metadataIdentified.EmitFinding ||
        metadataIdentified.MetadataCoverageIncomplete ||
        metadataIdentified.ProtectionCoverageIncomplete)
    {
        return false;
    }

    const CloudFileMappingDecision protectedImage =
        EvaluateCloudFileMapping(
            placeholder,
            true,
            0x31,
            false,
            {});
    if (!protectedImage.EmitFinding ||
        protectedImage.Risk != L"high" ||
        protectedImage.Confidence != L"high" ||
        std::find(
            protectedImage.Reasons.begin(),
            protectedImage.Reasons.end(),
            L"cloudfiles_ffi_ppl_image_mapping") ==
            protectedImage.Reasons.end())
    {
        return false;
    }

    CloudFilePlaceholderRecord modified =
        placeholder;
    modified.ModifiedDataSize = 4096;
    const CloudFileMappingDecision modifiedImage =
        EvaluateCloudFileMapping(
            modified,
            true,
            0,
            false,
            {});
    if (!modifiedImage.EmitFinding ||
        modifiedImage.Risk != L"medium" ||
        modifiedImage.Confidence != L"high" ||
        std::find(
            modifiedImage.Reasons.begin(),
            modifiedImage.Reasons.end(),
            L"cloudfiles_placeholder_modified_data") ==
            modifiedImage.Reasons.end())
    {
        return false;
    }

    const CloudFileMappingDecision mismatch =
        EvaluateCloudFileMapping(
            placeholder,
            false,
            0,
            true,
            {L"module_text_mismatch"});
    if (!mismatch.EmitFinding ||
        mismatch.ProtectionCoverageIncomplete ||
        std::find(
            mismatch.Reasons.begin(),
            mismatch.Reasons.end(),
            L"cloudfiles_ffi_live_disk_mismatch") ==
            mismatch.Reasons.end() ||
        std::find(
            mismatch.Reasons.begin(),
            mismatch.Reasons.end(),
            L"module_text_mismatch") ==
            mismatch.Reasons.end())
    {
        return false;
    }

    const CloudFileMappingDecision unresolvedProtection =
        EvaluateCloudFileMapping(
            placeholder,
            false,
            0,
            false,
            {});
    if (unresolvedProtection.EmitFinding ||
        !unresolvedProtection.ProtectionCoverageIncomplete)
    {
        return false;
    }

    CloudFilePlaceholderRecord incomplete =
        placeholder;
    incomplete.PlaceholderInfoAvailable = false;
    incomplete.MetadataCoverageComplete = false;
    const CloudFileMappingDecision incompleteMetadata =
        EvaluateCloudFileMapping(
            incomplete,
            true,
            0x31,
            false,
            {});
    if (incompleteMetadata.EmitFinding ||
        !incompleteMetadata.MetadataCoverageIncomplete)
    {
        return false;
    }

    CloudFilePlaceholderRecord syncRootOnly =
        placeholder;
    syncRootOnly.PlaceholderState = 0x00000002;
    const CloudFileMappingDecision notPlaceholder =
        EvaluateCloudFileMapping(
            syncRootOnly,
            true,
            0x31,
            false,
            {});
    if (notPlaceholder.IsPlaceholder ||
        notPlaceholder.EmitFinding)
    {
        return false;
    }

    HuntResult jsonResult = {};
    jsonResult.CloudFilePlaceholderImageCount = 3;
    jsonResult.SuspiciousCloudFileImageCount = 2;
    jsonResult.CloudFilePlaceholderCoverageIncomplete =
        true;
    jsonResult.CloudFileProtectionCorrelationIncomplete =
        true;
    HuntProcessRecord jsonProcess = {};
    jsonProcess.ProcessId = 42;
    jsonProcess.HasProtection = true;
    jsonProcess.Protection = 0x31;
    jsonResult.Processes.push_back(jsonProcess);
    HuntCloudFileImageRecord jsonCloud = {};
    jsonCloud.ProcessId = 42;
    jsonCloud.ModuleBase = 0x140000000;
    jsonCloud.ModuleSize = 45056;
    jsonCloud.ImageName = L"CloudFilesFixture.exe";
    jsonCloud.ModuleName = L"CloudFilesFixture.exe";
    jsonCloud.VadBackingPath =
        L"\\Device\\HarddiskVolume3\\CloudFilesFixture.exe";
    jsonCloud.NormalizedBackingPath =
        L"C:\\CloudFilesFixture.exe";
    jsonCloud.PlaceholderState = 1;
    jsonCloud.ModifiedDataSize = 33;
    jsonCloud.InSyncState = 0;
    jsonCloud.PlaceholderInfoIdentificationFallbackUsed =
        true;
    jsonCloud.ProcessProtectionResolved = true;
    jsonCloud.ProcessProtection = 0;
    jsonCloud.Suspicious = true;
    jsonCloud.Reasons =
    {
        L"cloudfiles_executable_placeholder_mapping",
        L"cloudfiles_placeholder_modified_data"
    };
    jsonResult.CloudFileImages.push_back(
        jsonCloud);
    const std::wstring json =
        BuildHuntJson(jsonResult);
    return json.find(
               L"\"cloudfiles_placeholder_images\":3") !=
            std::wstring::npos &&
        json.find(
            L"\"suspicious_cloudfiles_images\":2") !=
            std::wstring::npos &&
        json.find(
            L"\"cloudfiles_placeholder_coverage_incomplete\":true") !=
            std::wstring::npos &&
        json.find(
            L"\"cloudfiles_protection_correlation_incomplete\":true") !=
            std::wstring::npos &&
        json.find(
            L"\"cloudfiles_images\":[") !=
            std::wstring::npos &&
        json.find(
            L"\"modified_data_size\":33") !=
            std::wstring::npos &&
        json.find(
            L"\"suspicious\":true") !=
            std::wstring::npos &&
        json.find(
            L"\"cloudfiles_placeholder_modified_data\"") !=
            std::wstring::npos &&
        json.find(
            L"\"protection\":{\"raw\":\"0x31\",\"type\":1,\"audit\":0,\"signer\":3}") !=
            std::wstring::npos;
}

bool HuntManagedLoaderlessMappingSelfTest()
{
    HuntModuleRecord mapped = {};
    mapped.VadBackingManagedImage = true;
    mapped.VadBackingState = L"resolved";
    mapped.VadBackingPath = L"C:\\Temp\\managed.dll";

    HuntProcessRecord process = {};
    process.PebLdrEnumerated = true;
    if (IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    HuntModuleRecord runtime = {};
    runtime.Name = L"coreclr.dll";
    runtime.ToolhelpSeen = true;
    process.Modules.push_back(runtime);
    if (IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    process.Modules[0].LdrLoadSeen = true;
    if (!IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    process.Modules[0].LdrLoadSeen = false;
    HuntModuleRecord wow64 = {};
    wow64.Name = L"wow64.dll";
    wow64.LdrMemorySeen = true;
    process.Modules.push_back(wow64);
    process.ToolhelpModuleEnumerated = true;
    if (!IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    process.ToolhelpModuleEnumerated = false;
    if (IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }
    process.ToolhelpModuleEnumerated = true;

    process.PebLdrEnumerated = false;
    if (IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    process.PebLdrEnumerated = true;
    mapped.Base = 0x1000;
    mapped.Size = 0x2000;
    ProcessVadRecord mappedVad = {};
    mappedVad.StartAddress = mapped.Base;
    mappedVad.EndAddress =
        mapped.Base + mapped.Size - 1;
    mappedVad.Executable = true;
    process.VadRecords.push_back(mappedVad);
    mapped.VadBackingManagedImage = false;
    if (IsExpectedManagedLoaderlessMapping(process, mapped))
    {
        return false;
    }

    mapped.VadBackingManagedImage = true;
    if (!ShouldSkipExpectedManagedLoaderlessDeepComparison(
            process,
            mapped))
    {
        return false;
    }

    ProcessThreadRecord execution = {};
    execution.HasStartAddress = true;
    execution.StartAddress = mapped.Base + 0x100;
    process.ThreadRecords.push_back(execution);
    return !ShouldSkipExpectedManagedLoaderlessDeepComparison(
        process,
        mapped);
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
    if (error != nullptr)
    {
        error->clear();
    }

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
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
        }
        else
        {
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"SystemProcessInformation inventory failed without diagnostic detail");
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
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
        }
        else
        {
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
            result->Warnings.push_back(
                L"Toolhelp process inventory failed without diagnostic detail");
        }

        // Seed the legacy known-PID view first so older/unsupported builds
        // retain bounded evidence. Then derive and validate the CID-table
        // anchor from both exported CID lookup routines and probe every
        // process ID below the stable NextHandleNeedingPool bound.
        result->CidTableLookupOnly = true;
        result->CidTableFullEnumeration = false;
        result->CidTableFullProcessEnumeration =
            false;
        uint32_t processDtbOffset = 0;
        uint32_t processUserDtbOffset = 0;
        uint32_t processActiveLinksOffset = 0;
        uint32_t processCreateTimeOffset = 0;
        std::wstring cidLookupWarning;
        ApplyCidTableLookupView(
                device_,
                symbols_,
                &processes,
                &cidLookupWarning,
                &processDtbOffset,
                &processUserDtbOffset,
                &processActiveLinksOffset,
                &processCreateTimeOffset);

        CidProcessEnumerationResult cidEnumeration = {};
        if (ApplyCidTableFullProcessView(
                device_,
                symbols_,
                processDtbOffset,
                processUserDtbOffset,
                processActiveLinksOffset,
                &processes,
                &cidEnumeration))
        {
            result->CidTableLookupOnly = false;
            result->CidTableFullProcessEnumeration =
                true;
            result->CidTableAnchorAddress =
                cidEnumeration.Snapshot.AnchorAddress;
            result->CidTableAddress =
                cidEnumeration.Snapshot.TableAddress;
            result->CidTableCode =
                cidEnumeration.Snapshot.TableCode;
            result->CidTableLevel =
                cidEnumeration.Snapshot.TableLevel;
            result->CidTableNextHandle =
                cidEnumeration.Snapshot.NextHandle;
            result->CidTableAllocatedLeafCount =
                cidEnumeration.Snapshot.
                    AllocatedLeafCount;
            result->CidTableAllocatedHandleCapacity =
                cidEnumeration.Snapshot.
                    AllocatedHandleCapacity;
            result->CidTableProbeCount =
                cidEnumeration.ProbeCount;
            result->CidTableProcessCount =
                cidEnumeration.ProcessCount;
            result->CidTableDiscoveredProcessCount =
                cidEnumeration.DiscoveredProcessCount;
            result->CidTableProbeFailureCount =
                cidEnumeration.ProbeFailureCount;
            if (!cidEnumeration.Summary.empty())
            {
                result->Warnings.push_back(
                    cidEnumeration.Summary);
            }

            warning.clear();
            if (!RevalidateCidApiProcessViews(
                    device_,
                    processDtbOffset,
                    processUserDtbOffset,
                    &processes,
                    &result->
                        CidTablePersistentApiMissCount,
                    &warning))
            {
                if (!warning.empty())
                {
                    result->Warnings.push_back(
                        warning);
                }
                result->ProcessInventoryIncomplete =
                    true;
                result->CoverageComplete = false;
            }
            if (cidEnumeration.
                    MembershipIncompleteCount != 0)
            {
                result->ProcessInventoryIncomplete =
                    true;
                result->CoverageComplete = false;
            }
        }
        else
        {
            result->CidTableProbeCount =
                cidEnumeration.ProbeCount;
            result->CidTableProcessCount =
                cidEnumeration.ProcessCount;
            result->CidTableProbeFailureCount =
                cidEnumeration.ProbeFailureCount;
            if (!cidEnumeration.Summary.empty())
            {
                result->Warnings.push_back(
                    cidEnumeration.Summary);
            }
            if (!cidLookupWarning.empty())
            {
                result->Warnings.push_back(
                    cidLookupWarning);
            }
            result->Warnings.push_back(
                L"cid coverage incomplete: full bounded process-CID enumeration was not validated; "
                L"the fallback can inspect only PIDs seeded by other views");
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
        }

        uint32_t highestKnownPid = 0;
        for (const auto& item : processes)
        {
            highestKnownPid =
                (std::max)(
                    highestKnownPid,
                    item.first);
        }

        bool directProcessMergeComplete = false;
        CidDirectEnumerationResult directCidInitial = {};
        if (processDtbOffset != 0 &&
            ApplyCidTableDirectObjectView(
                device_,
                symbols_,
                processDtbOffset,
                processUserDtbOffset,
                highestKnownPid,
                &directCidInitial))
        {
            result->CidTableDirectEntryEnumeration =
                true;
            result->CidTableDirectEntryCount =
                directCidInitial.NonEmptyEntryCount;
            result->CidTableDirectProcessCount =
                directCidInitial.Processes.size();
            result->CidTableDirectThreadCount =
                directCidInitial.Threads.size();
            result->CidTableUnclassifiedEntryCount =
                directCidInitial.
                    UnclassifiedEntryCount;

            uint64_t directDiscovered = 0;
            warning.clear();
            if (!MergeCidDirectProcessView(
                    directCidInitial,
                    &processes,
                    &directDiscovered,
                    &warning))
            {
                if (!warning.empty())
                {
                    result->Warnings.push_back(
                        warning);
                }
                result->ProcessInventoryIncomplete =
                    true;
                result->CoverageComplete = false;
            }
            else
            {
                directProcessMergeComplete = true;
                result->CidTableDiscoveredProcessCount +=
                    directDiscovered;

                uint64_t directPersistentApiMisses = 0;
                warning.clear();
                if (!RevalidateCidApiProcessViews(
                        device_,
                        processDtbOffset,
                        processUserDtbOffset,
                        &processes,
                        &directPersistentApiMisses,
                        &warning))
                {
                    if (!warning.empty())
                    {
                        result->Warnings.push_back(
                            warning);
                    }
                    result->ProcessInventoryIncomplete =
                        true;
                    result->CoverageComplete = false;
                }
                result->CidTablePersistentApiMissCount =
                    (std::max)(
                        result->
                            CidTablePersistentApiMissCount,
                        directPersistentApiMisses);
            }

            if (!directCidInitial.Summary.empty())
            {
                result->Warnings.push_back(
                    directCidInitial.Summary);
            }
        }
        else
        {
            result->CidTableDirectEntryEnumeration =
                false;
            result->CidTableUnclassifiedEntryCount =
                directCidInitial.
                    UnclassifiedEntryCount;
            if (!directCidInitial.Summary.empty())
            {
                result->Warnings.push_back(
                    directCidInitial.Summary);
            }
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
        }

        CidEprocessLayout directRevalidationLayout = {};
        std::wstring directRevalidationWarning;
        const bool directRevalidationLayoutResolved =
            directProcessMergeComplete &&
            ResolveCidEprocessLayout(
                symbols_,
                &directRevalidationLayout,
                &directRevalidationWarning);
        if (directProcessMergeComplete &&
            !directRevalidationLayoutResolved)
        {
            directProcessMergeComplete = false;
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
            if (!directRevalidationWarning.empty())
            {
                result->Warnings.push_back(
                    directRevalidationWarning);
            }
        }

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (!process.HasParentProcessId)
            {
                continue;
            }

            const auto parent =
                processes.find(
                    process.ParentProcessId);
            if (parent != processes.end() &&
                CanUseParentProcessIdentity(
                    process,
                    parent->second))
            {
                process.ParentImageName =
                    BestProcessImageName(
                        parent->second);
            }
        }

        ProcessTriageScanner triage(device_, symbols_);
        std::map<std::wstring, FileSha1CacheEntry> processSha1Cache;
        TypeFieldInfo protectionField = {};
        const bool protectionFieldResolved =
            ResolveHuntProcessProtectionField(
                symbols_,
                &protectionField);

        for (auto& item : processes)
        {
            HuntProcessRecord& process = item.second;
            if (process.Kernel.ProcessId == 0)
            {
                process.Kernel.ProcessId = process.ProcessId;
            }

            if (process.ProcessId > 4 && processDtbOffset != 0)
            {
                ProcessAddressContext refreshed = {};
                std::wstring refreshError;
                bool refreshedFromDirectAddress = false;
                if (!device_.ResolveProcess(
                        process.ProcessId,
                        processDtbOffset,
                        processUserDtbOffset,
                        &refreshed,
                        &refreshError))
                {
                    CidEnumeratedProcess directRefreshed = {};
                    if (process.CidDirectEntrySeen &&
                        directRevalidationLayoutResolved &&
                        process.Kernel.Eprocess != 0 &&
                        process.Kernel.HasCreateTime &&
                        CaptureCidProcessAtAddress(
                            device_,
                            directRevalidationLayout,
                            processDtbOffset,
                            processUserDtbOffset,
                            process.ProcessId,
                            process.Kernel.Eprocess,
                            &directRefreshed) &&
                        directRefreshed.HasCreateTime &&
                        directRefreshed.CreateTime ==
                            process.Kernel.CreateTime)
                    {
                        refreshed =
                            directRefreshed.Context;
                        refreshedFromDirectAddress = true;
                        process.CidIdentityRevalidated =
                            true;
                        process.Kernel.HasExitTime =
                            directRefreshed.HasExitTime;
                        process.Kernel.ExitTime =
                            directRefreshed.ExitTime;
                        process.Kernel.HasActiveThreads =
                            directRefreshed.
                                HasActiveThreads;
                        process.Kernel.ActiveThreads =
                            directRefreshed.ActiveThreads;
                        process.Kernel.HasPeb =
                            directRefreshed.HasPeb;
                        process.Kernel.Peb =
                            directRefreshed.Peb;
                        if (!directRefreshed.
                                ImageName.empty())
                        {
                            process.Kernel.ImageName =
                                directRefreshed.ImageName;
                            process.KernelImageName =
                                directRefreshed.ImageName;
                        }
                        AddUnique(
                            &process.Warnings,
                            L"exported process lookup was unavailable; the direct CID EPROCESS identity and address context were revalidated without PsLookupProcessByProcessId");
                    }
                    else
                    {
                        process.
                            LifecycleChangedBeforeTriage =
                                true;
                        AddUnique(
                            &process.Warnings,
                            L"process identity could not be revalidated by either exported lookup or the direct CID EPROCESS address; stale evidence was skipped");
                        continue;
                    }
                }

                process.AddressContextRefreshed = true;
                if (process.Kernel.Eprocess != 0 &&
                    process.Kernel.Eprocess != refreshed.Eprocess)
                {
                    process.LifecycleChangedBeforeTriage = true;
                    AddUnique(
                        &process.Warnings,
                        L"PID was reused before deep triage; stale process identity was skipped");
                    continue;
                }

                process.Kernel.Eprocess = refreshed.Eprocess;
                process.Kernel.DirectoryTableBase = refreshed.DirectoryTableBase;
                process.Kernel.UserDirectoryTableBase = refreshed.UserDirectoryTableBase;

                if (process.CidTableDiscovered)
                {
                    uint64_t createTimeAddress = 0;
                    uint64_t currentCreateTime = 0;
                    if (!process.Kernel.HasCreateTime ||
                        processCreateTimeOffset == 0 ||
                        !TryAdd(
                            refreshed.Eprocess,
                            processCreateTimeOffset,
                            &createTimeAddress) ||
                        !ReadKernelInteger(
                            device_,
                            createTimeAddress,
                            sizeof(uint64_t),
                            &currentCreateTime,
                            nullptr) ||
                        currentCreateTime == 0 ||
                        currentCreateTime !=
                            process.Kernel.CreateTime)
                    {
                        process.LifecycleChangedBeforeTriage =
                            true;
                        AddUnique(
                            &process.Warnings,
                            L"full-CID process identity changed before post-view triage");
                        continue;
                    }
                    process.CidIdentityRevalidated =
                        true;

                    const ActiveProcessLinkMembership
                        membership =
                            RevalidateActiveProcessLinks(
                                device_,
                                refreshed.Eprocess,
                                processActiveLinksOffset);
                    if (membership ==
                        ActiveProcessLinkMembership::Linked)
                    {
                        process.ActiveProcessLinksSeen =
                            true;
                        process.ActiveProcessLinksRevalidated =
                            true;
                        process.ActiveProcessLinksStableUnlinked =
                            false;
                    }
                    else if (membership ==
                             ActiveProcessLinkMembership::
                                 StableUnlinked)
                    {
                        process.ActiveProcessLinksSeen =
                            false;
                        process.ActiveProcessLinksRevalidated =
                            true;
                        process.ActiveProcessLinksStableUnlinked =
                            true;
                    }
                    else
                    {
                        process.ActiveProcessLinksRevalidated =
                            false;
                        process.ActiveProcessLinksStableUnlinked =
                            false;
                        result->ProcessInventoryIncomplete =
                            true;
                        result->CoverageComplete = false;
                        AddUnique(
                            &process.Warnings,
                            L"full-CID process ActiveProcessLinks membership changed during post-view revalidation");
                    }
                }
                else if (refreshedFromDirectAddress)
                {
                    process.CidIdentityRevalidated = true;
                }
            }

            if (IsTerminatingProcessSnapshot(process.Kernel))
            {
                AddUnique(
                    &process.Warnings,
                    L"process was already terminating at kernel inventory capture; cross-view and deep triage skipped");
                continue;
            }

            bool publicLifecycleChanged = false;
            QueryProcessPublicDetails(
                &process,
                &publicLifecycleChanged);
            if (publicLifecycleChanged)
            {
                CidEnumeratedProcess directPublicRecheck = {};
                const bool directIdentityStillLive =
                    process.CidDirectEntrySeen &&
                    directRevalidationLayoutResolved &&
                    process.Kernel.Eprocess != 0 &&
                    process.Kernel.HasCreateTime &&
                    CaptureCidProcessAtAddress(
                        device_,
                        directRevalidationLayout,
                        processDtbOffset,
                        processUserDtbOffset,
                        process.ProcessId,
                        process.Kernel.Eprocess,
                        &directPublicRecheck) &&
                    directPublicRecheck.Context.Eprocess ==
                        process.Kernel.Eprocess &&
                    directPublicRecheck.HasCreateTime &&
                    directPublicRecheck.CreateTime ==
                        process.Kernel.CreateTime &&
                    directPublicRecheck.HasExitTime &&
                    directPublicRecheck.ExitTime == 0 &&
                    directPublicRecheck.HasActiveThreads &&
                    directPublicRecheck.ActiveThreads != 0;
                if (directIdentityStillLive)
                {
                    process.CidIdentityRevalidated = true;
                    process.Kernel.DirectoryTableBase =
                        directPublicRecheck.Context.
                            DirectoryTableBase;
                    process.Kernel.UserDirectoryTableBase =
                        directPublicRecheck.Context.
                            UserDirectoryTableBase;
                    process.Kernel.ExitTime =
                        directPublicRecheck.ExitTime;
                    process.Kernel.HasExitTime = true;
                    process.Kernel.ActiveThreads =
                        directPublicRecheck.ActiveThreads;
                    process.Kernel.HasActiveThreads = true;
                    AddUnique(
                        &process.Warnings,
                        L"public process-handle identity lookup disagreed with a fresh live direct-CID EPROCESS revalidation");
                }
                else
                {
                    process.LifecycleChangedBeforeTriage =
                        true;
                    AddUnique(
                        &process.Warnings,
                        L"process exited or its PID was reused before public identity triage; stale evidence was skipped");
                    continue;
                }
            }

            if (protectionFieldResolved)
            {
                ReadHuntProcessProtection(
                    device_,
                    protectionField,
                    &process);
            }

            if (HasUnresolvedApiOnlyProcessView(
                    process))
            {
                AddUnique(
                    &process.Warnings,
                    L"API-only process view was not a stable ActiveProcessLinks unlink; temporal mismatch finding was suppressed");
                result->ProcessInventoryIncomplete = true;
                result->CoverageComplete = false;
            }
            AddProcessViewFindings(result, process);

            // Deep triage needs EPROCESS. Prefer ActiveProcessLinks inventory;
            // also accept CID-recovered EPROCESS for API-only / unlinked processes
            // without disabling the original path for list-visible processes.
            if (process.Kernel.Eprocess != 0 &&
                (process.ActiveProcessLinksSeen || process.CidTableSeen) &&
                HasExactProcessIdentity(process.Kernel))
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
                if (ScanVadForHunt(
                        triage,
                        vadOptions,
                        &vadResult,
                        &process.VadScanAttempts,
                        &scanError))
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
                    process.PageTablePagesRead = vadResult.PageTablePagesRead;
                    process.PageTableReadFailures = vadResult.PageTableReadFailures;
                    process.PagingLevels = vadResult.PagingLevels;
                    process.Warnings.insert(process.Warnings.end(), vadResult.Warnings.begin(), vadResult.Warnings.end());
                    if (vadResult.HiddenPteTruncated ||
                        vadResult.Incomplete ||
                        !vadResult.CoverageComplete ||
                        vadResult.Truncated)
                    {
                        result->ProcessTriageCoverageIncomplete = true;
                        result->CoverageComplete = false;
                        if (vadResult.HiddenPteTruncated)
                        {
                            AddUnique(&process.Warnings, L"hidden PTE scan hit the hunt per-process record limit");
                        }
                        if (vadResult.Incomplete || !vadResult.CoverageComplete)
                        {
                            AddUnique(&process.Warnings, L"VAD coverage incomplete for this process");
                        }
                    }
                    result->VadRecordCount += vadResult.TotalRecords;
                    result->HiddenPteRangeCount += vadResult.HiddenPteRanges;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"VAD scan failed: " + scanError);
                    result->ProcessTriageCoverageIncomplete = true;
                    result->CoverageComplete = false;
                }

                ProcessThreadScanOptions threadOptions = {};
                threadOptions.Target = BuildTriageTarget(process.Kernel);
                for (const HuntModuleRecord& module :
                     process.Modules)
                {
                    if (module.Base == 0 ||
                        module.Size == 0 ||
                        !ModuleHasLoaderView(module))
                    {
                        continue;
                    }

                    ProcessUserModuleRange range = {};
                    range.Base = module.Base;
                    range.Size = module.Size;
                    range.ImageName = module.Name;
                    range.ImagePath = module.Path;
                    threadOptions.UserModules.push_back(
                        std::move(range));
                }
                threadOptions.UserModuleEnumerationComplete =
                    ProcessHasCompleteUserModuleInventory(
                        process);
                threadOptions.IncludeApc = true;
                threadOptions.IncludeStacks = options.Mode == HuntMode::Deep;
                threadOptions.RequireSuspensionCoverage =
                    HuntTextTargetsKnownSecurityProduct(
                        BestProcessImageName(process),
                        nullptr);

                ProcessThreadScanResult threadResult = {};
                scanError.clear();
                if (ScanThreadsForHunt(
                        triage,
                        threadOptions,
                        &threadResult,
                        &process.ThreadScanAttempts,
                        &scanError))
                {
                    process.ThreadRecords = std::move(threadResult.Records);
                    process.ThreadsVisited = threadResult.ThreadsVisited;
                    process.SuspensionStateResolvedThreads =
                        threadResult.SuspensionStateResolvedCount;
                    process.SuspendedThreads =
                        threadResult.SuspendedThreadCount;
                    process.SuspiciousThreadStarts = threadResult.SuspiciousStartCount;
                    process.NonEmptyApcQueues = threadResult.ApcNonEmptyCount;
                    process.StackReferenceCount = threadResult.StackReferenceCount;
                    process.ThreadInventoryComplete =
                        threadResult.InventoryComplete &&
                        !threadResult.Truncated;
                    process.ThreadSuspensionStateCoverageComplete =
                        threadResult.SuspensionStateCoverageComplete;
                    process.Warnings.insert(process.Warnings.end(), threadResult.Warnings.begin(), threadResult.Warnings.end());
                    if (threadResult.Truncated ||
                        threadResult.Incomplete ||
                        !threadResult.CoverageComplete)
                    {
                        result->ProcessTriageCoverageIncomplete = true;
                        result->CoverageComplete = false;
                        if (threadResult.Truncated)
                        {
                            AddUnique(&process.Warnings, L"thread scan truncated");
                        }
                        if (threadResult.Incomplete || !threadResult.CoverageComplete)
                        {
                            AddUnique(&process.Warnings, L"thread coverage incomplete for this process");
                        }
                    }
                    std::wstring securityTarget;
                    if (HuntTextTargetsKnownSecurityProduct(
                            BestProcessImageName(process),
                            &securityTarget) &&
                        (!process.ThreadInventoryComplete ||
                         !process.ThreadSuspensionStateCoverageComplete))
                    {
                        result->ProcessTriageCoverageIncomplete =
                            true;
                        result->CoverageComplete = false;
                        AddUnique(
                            &process.Warnings,
                            L"security-process suspend/freeze "
                            L"detection coverage incomplete");
                    }
                    result->ThreadRecordCount += threadResult.MatchingRecords;
                }
                else if (!scanError.empty())
                {
                    process.Warnings.push_back(L"thread scan failed: " + scanError);
                    result->ProcessTriageCoverageIncomplete = true;
                    result->CoverageComplete = false;
                }

                AddIdentityFindings(result, process);
                AddEdrKillerProcessProfileFindings(result, process);
                AddEsetFileHashProcessFinding(result, process, &processSha1Cache);
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
                if (process.Kernel.Eprocess != 0 &&
                    (process.ActiveProcessLinksSeen ||
                     process.CidTableSeen) &&
                    !HasExactProcessIdentity(process.Kernel))
                {
                    AddUnique(
                        &process.Warnings,
                        L"deep process triage skipped because exact PID, EPROCESS, and create-time identity was unavailable");
                    result->ProcessTriageCoverageIncomplete = true;
                    result->CoverageComplete = false;
                }
                ApplyBuiltinProfile(&process);
                AddIdentityFindings(result, process);
                AddEdrKillerProcessProfileFindings(result, process);
                AddEsetFileHashProcessFinding(result, process, &processSha1Cache);
            }

            result->ModuleRecordCount += process.Modules.size();
        }

        warning.clear();
        if (directProcessMergeComplete &&
            ApplyCidThreadCrossView(
                device_,
                symbols_,
                processDtbOffset,
                processUserDtbOffset,
                &processes,
                result,
                &warning))
        {
            result->CidTableLookupOnly = false;
            result->CidTableFullProcessEnumeration =
                true;
            result->CidTableFullEnumeration =
                result->CidTableDirectEntryEnumeration &&
                result->CidTableFullThreadEnumeration &&
                result->
                    CidTableThreadCrossViewComplete;
        }
        else
        {
            result->CidTableFullEnumeration = false;
            result->CidTableFullThreadEnumeration =
                false;
            result->CidTableThreadCrossViewComplete =
                false;
            result->ProcessInventoryIncomplete = true;
            result->CoverageComplete = false;
            if (!warning.empty())
            {
                result->Warnings.push_back(
                    warning);
            }
            else if (!directProcessMergeComplete)
            {
                result->Warnings.push_back(
                    L"thread CID cross-view unavailable because the direct process-CID merge was incomplete");
            }
        }

        if (options.Mode != HuntMode::Quick)
        {
            AddWfpHuntFindings(result);
            AddQosPolicyHuntFindings(result);
            AddBindFilterHuntFindings(
                result,
                processes);
            AddCloudFileHuntFindings(
                result,
                processes);
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
    json << L",\"system_process_information_threads\":" << result.SystemProcessInfoThreadCount;
    json << L",\"toolhelp_threads\":" << result.ToolhelpThreadCount;
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
    json << L",\"driver_service_coverage_incomplete\":"
         << (result.DriverServiceCoverageIncomplete ? L"true" : L"false");
    json << L",\"wfp_filters\":" << result.WfpFilterCount;
    json << L",\"suspicious_wfp_filters\":" << result.SuspiciousWfpFilterCount;
    json << L",\"wfp_filter_coverage_incomplete\":"
         << (result.WfpFilterCoverageIncomplete ? L"true" : L"false");
    json << L",\"qos_policies\":" << result.QosPolicyCount;
    json << L",\"suspicious_qos_policies\":" << result.SuspiciousQosPolicyCount;
    json << L",\"qos_policy_coverage_incomplete\":"
         << (result.QosPolicyCoverageIncomplete ? L"true" : L"false");
    json << L",\"bindflt_global_mappings\":"
         << result.BindFilterMappingCount;
    json << L",\"suspicious_bindflt_global_mappings\":"
         << result.SuspiciousBindFilterMappingCount;
    json << L",\"bindflt_process_bindings\":"
         << result.BindFilterProcessBindingCount;
    json << L",\"bindflt_global_coverage_incomplete\":"
         << (result.BindFilterGlobalCoverageIncomplete ? L"true" : L"false");
    json << L",\"bindflt_process_correlation_coverage_incomplete\":"
         << (result.BindFilterProcessCorrelationCoverageIncomplete ? L"true" : L"false");
    json << L",\"bindflt_silo_coverage_unsupported\":"
         << (result.BindFilterSiloCoverageUnsupported ? L"true" : L"false");
    json << L",\"cloudfiles_placeholder_images\":"
         << result.CloudFilePlaceholderImageCount;
    json << L",\"suspicious_cloudfiles_images\":"
         << result.SuspiciousCloudFileImageCount;
    json << L",\"cloudfiles_placeholder_coverage_incomplete\":"
         << (result.CloudFilePlaceholderCoverageIncomplete ? L"true" : L"false");
    json << L",\"cloudfiles_protection_correlation_incomplete\":"
         << (result.CloudFileProtectionCorrelationIncomplete ? L"true" : L"false");
    json << L",\"threat_intel_active\":" << (result.ThreatIntelActive ? L"true" : L"false");
    json << L",\"threat_intel_available\":" << (result.ThreatIntelAvailable ? L"true" : L"false");
    json << L",\"threat_intel_events\":" << result.ThreatIntelEventCount;
    json << L",\"threat_intel_correlations\":" << result.ThreatIntelCorrelationCount;
    json << L",\"threat_intel_correlation_incomplete\":" << (result.ThreatIntelCorrelationIncomplete ? L"true" : L"false");
    json << L",\"process_inventory_incomplete\":" << (result.ProcessInventoryIncomplete ? L"true" : L"false");
    json << L",\"cid_table_full_enumeration\":" << (result.CidTableFullEnumeration ? L"true" : L"false");
    json << L",\"cid_table_full_process_enumeration\":" << (result.CidTableFullProcessEnumeration ? L"true" : L"false");
    json << L",\"cid_table_direct_entry_enumeration\":" << (result.CidTableDirectEntryEnumeration ? L"true" : L"false");
    json << L",\"cid_table_full_thread_enumeration\":" << (result.CidTableFullThreadEnumeration ? L"true" : L"false");
    json << L",\"cid_table_thread_cross_view_complete\":" << (result.CidTableThreadCrossViewComplete ? L"true" : L"false");
    json << L",\"cid_table_lookup_only\":" << (result.CidTableLookupOnly ? L"true" : L"false");
    json << L",\"cid_table_anchor\":\"" << HuntHex(result.CidTableAnchorAddress, 16) << L"\"";
    json << L",\"cid_table_address\":\"" << HuntHex(result.CidTableAddress, 16) << L"\"";
    json << L",\"cid_table_code\":\"" << HuntHex(result.CidTableCode, 16) << L"\"";
    json << L",\"cid_table_level\":" << result.CidTableLevel;
    json << L",\"cid_table_next_handle\":" << result.CidTableNextHandle;
    json << L",\"cid_table_allocated_leaves\":" << result.CidTableAllocatedLeafCount;
    json << L",\"cid_table_allocated_handle_capacity\":" << result.CidTableAllocatedHandleCapacity;
    json << L",\"cid_table_probes\":" << result.CidTableProbeCount;
    json << L",\"cid_table_processes\":" << result.CidTableProcessCount;
    json << L",\"cid_table_discovered_processes\":" << result.CidTableDiscoveredProcessCount;
    json << L",\"cid_table_direct_entries\":" << result.CidTableDirectEntryCount;
    json << L",\"cid_table_direct_processes\":" << result.CidTableDirectProcessCount;
    json << L",\"cid_table_direct_threads\":" << result.CidTableDirectThreadCount;
    json << L",\"cid_table_unclassified_entries\":" << result.CidTableUnclassifiedEntryCount;
    json << L",\"cid_table_thread_findings\":" << result.CidTableThreadFindingCount;
    json << L",\"cid_table_persistent_thread_view_misses\":" << result.CidTablePersistentThreadViewMissCount;
    json << L",\"cid_table_probe_failures\":" << result.CidTableProbeFailureCount;
    json << L",\"cid_table_persistent_api_misses\":" << result.CidTablePersistentApiMissCount;
    json << L",\"process_triage_coverage_incomplete\":" << (result.ProcessTriageCoverageIncomplete ? L"true" : L"false");
    json << L",\"deep_image_comparison_coverage_incomplete\":"
         << (result.DeepImageComparisonCoverageIncomplete ? L"true" : L"false");
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
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

    json << L"  \"cloudfiles_images\":[\n";
    for (size_t index = 0;
         index < result.CloudFileImages.size();
         ++index)
    {
        const HuntCloudFileImageRecord& record =
            result.CloudFileImages[index];
        json << L"    {";
        json << L"\"pid\":" << record.ProcessId;
        json << L",\"module_base\":\""
             << HuntHex(record.ModuleBase, 16)
             << L"\"";
        json << L",\"module_size\":"
             << record.ModuleSize;
        json << L",\"image\":\""
             << HuntJsonEscape(record.ImageName)
             << L"\"";
        json << L",\"module\":\""
             << HuntJsonEscape(record.ModuleName)
             << L"\"";
        json << L",\"vad_backing_path\":\""
             << HuntJsonEscape(
                    record.VadBackingPath)
             << L"\"";
        json << L",\"normalized_backing_path\":\""
             << HuntJsonEscape(
                    record.NormalizedBackingPath)
             << L"\"";
        json << L",\"file_attributes\":\""
             << HuntHex(record.FileAttributes, 8)
             << L"\"";
        json << L",\"reparse_tag\":\""
             << HuntHex(record.ReparseTag, 8)
             << L"\"";
        json << L",\"cloud_reparse_tag_observed\":"
             << (record.CloudReparseTagObserved
                     ? L"true"
                     : L"false");
        json << L",\"placeholder_info_identification_fallback_used\":"
             << (record.
                         PlaceholderInfoIdentificationFallbackUsed
                     ? L"true"
                     : L"false");
        json << L",\"placeholder_info_query_status\":\""
             << HuntHex(
                    record.PlaceholderInfoQueryStatus,
                    8)
             << L"\"";
        json << L",\"placeholder_state\":\""
             << HuntHex(record.PlaceholderState, 8)
             << L"\"";
        json << L",\"on_disk_data_size\":"
             << record.OnDiskDataSize;
        json << L",\"validated_data_size\":"
             << record.ValidatedDataSize;
        json << L",\"modified_data_size\":"
             << record.ModifiedDataSize;
        json << L",\"properties_size\":"
             << record.PropertiesSize;
        json << L",\"pin_state\":"
             << record.PinState;
        json << L",\"in_sync_state\":"
             << record.InSyncState;
        json << L",\"file_identity_length\":"
             << record.FileIdentityLength;
        json << L",\"process_protection_resolved\":"
             << (record.ProcessProtectionResolved
                     ? L"true"
                     : L"false");
        json << L",\"process_protection\":";
        if (record.ProcessProtectionResolved)
        {
            json << L"\""
                 << HuntHex(
                        record.ProcessProtection,
                        2)
                 << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"deep_mismatch_correlated\":"
             << (record.DeepMismatchCorrelated
                     ? L"true"
                     : L"false");
        json << L",\"suspicious\":"
             << (record.Suspicious
                     ? L"true"
                     : L"false");
        json << L",\"reasons\":";
        AppendJsonStringArray(
            json,
            record.Reasons);
        json << L"}";
        if (index + 1 !=
            result.CloudFileImages.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ],\n";

    json << L"  \"cid_threads\":[\n";
    for (size_t index = 0;
         index < result.CidThreads.size();
         ++index)
    {
        const HuntCidThreadRecord& record =
            result.CidThreads[index];
        json << L"    {";
        json << L"\"tid\":" << record.ThreadId;
        json << L",\"pid\":" << record.ProcessId;
        json << L",\"object_header\":\""
             << HuntHex(record.ObjectHeader, 16)
             << L"\"";
        json << L",\"ethread\":\""
             << HuntHex(record.Ethread, 16)
             << L"\"";
        json << L",\"eprocess\":\""
             << HuntHex(record.Eprocess, 16)
             << L"\"";
        json << L",\"create_time\":";
        if (record.HasCreateTime)
        {
            json << L"\""
                 << HuntHex(record.CreateTime, 16)
                 << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"exit_time\":";
        if (record.HasExitTime)
        {
            json << L"\""
                 << HuntHex(record.ExitTime, 16)
                 << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"terminated\":"
             << (record.Terminated
                     ? L"true"
                     : L"false");
        json << L",\"direct_cid_seen\":"
             << (record.DirectCidSeen
                     ? L"true"
                     : L"false");
        json << L",\"executive_thread_list_seen\":"
             << (record.ExecutiveThreadListSeen
                     ? L"true"
                     : L"false");
        json << L",\"scheduler_thread_list_seen\":"
             << (record.SchedulerThreadListSeen
                     ? L"true"
                     : L"false");
        json << L",\"system_process_information_seen\":"
             << (record.SystemProcessInformationSeen
                     ? L"true"
                     : L"false");
        json << L",\"toolhelp_seen\":"
             << (record.ToolhelpThreadSeen
                     ? L"true"
                     : L"false");
        json << L",\"identity_revalidated\":"
             << (record.IdentityRevalidated
                     ? L"true"
                     : L"false");
        json << L",\"views_revalidated\":"
             << (record.ViewsRevalidated
                     ? L"true"
                     : L"false");
        json << L",\"lifecycle_changed\":"
             << (record.LifecycleChanged
                     ? L"true"
                     : L"false");
        json << L",\"suspicious\":"
             << (record.Suspicious
                     ? L"true"
                     : L"false");
        json << L",\"reasons\":";
        AppendJsonStringArray(json, record.Reasons);
        json << L",\"warnings\":";
        AppendJsonStringArray(json, record.Warnings);
        json << L"}";
        if (index + 1 != result.CidThreads.size())
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
        json << L",\"directory_table_base\":\"" << HuntHex(process.Kernel.DirectoryTableBase, 16) << L"\"";
        json << L",\"user_directory_table_base\":\"" << HuntHex(process.Kernel.UserDirectoryTableBase, 16) << L"\"";
        json << L",\"terminating_snapshot\":" << (IsTerminatingProcessSnapshot(process.Kernel) ? L"true" : L"false");
        json << L",\"active_threads\":";
        if (process.Kernel.HasActiveThreads)
        {
            json << process.Kernel.ActiveThreads;
        }
        else
        {
            json << L"null";
        }
        json << L",\"exit_time\":";
        if (process.Kernel.HasExitTime)
        {
            json << L"\"" << HuntHex(process.Kernel.ExitTime, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"active_process_links_seen\":" << (process.ActiveProcessLinksSeen ? L"true" : L"false");
        json << L",\"active_process_links_revalidated\":" << (process.ActiveProcessLinksRevalidated ? L"true" : L"false");
        json << L",\"active_process_links_stable_unlinked\":" << (process.ActiveProcessLinksStableUnlinked ? L"true" : L"false");
        json << L",\"system_process_information_seen\":" << (process.SystemProcessInformationSeen ? L"true" : L"false");
        json << L",\"toolhelp_seen\":" << (process.ToolhelpProcessSeen ? L"true" : L"false");
        json << L",\"address_context_refreshed\":" << (process.AddressContextRefreshed ? L"true" : L"false");
        json << L",\"lifecycle_changed_before_triage\":" << (process.LifecycleChangedBeforeTriage ? L"true" : L"false");
        json << L",\"protection\":";
        if (process.HasProtection)
        {
            json << L"{\"raw\":\""
                 << HuntHex(process.Protection, 2)
                 << L"\",\"type\":"
                 << (process.Protection & 0x7u)
                 << L",\"audit\":"
                 << ((process.Protection >> 3) & 0x1u)
                 << L",\"signer\":"
                 << ((process.Protection >> 4) & 0xfu)
                 << L"}";
        }
        else
        {
            json << L"null";
        }
        json << L",\"cid_table_seen\":";
        if (process.HasCidTableView)
        {
            json << (process.CidTableSeen ? L"true" : L"false");
        }
        else
        {
            json << L"null";
        }
        json << L",\"cid_table_enumerated\":" << (process.CidTableEnumerated ? L"true" : L"false");
        json << L",\"cid_table_discovered\":" << (process.CidTableDiscovered ? L"true" : L"false");
        json << L",\"cid_direct_entry_seen\":" << (process.CidDirectEntrySeen ? L"true" : L"false");
        json << L",\"cid_lookup_direct_agreed\":" << (process.CidLookupDirectAgreed ? L"true" : L"false");
        json << L",\"cid_api_views_revalidated\":" << (process.CidApiViewsRevalidated ? L"true" : L"false");
        json << L",\"cid_identity_revalidated\":" << (process.CidIdentityRevalidated ? L"true" : L"false");
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
        json << L",\"main_section_object\":";
        if (process.MainSectionObject != 0)
        {
            json << L"\"" << HuntHex(process.MainSectionObject, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"main_section_segment\":";
        if (process.MainSectionSegment != 0)
        {
            json << L"\"" << HuntHex(process.MainSectionSegment, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"main_section_control_area\":";
        if (process.MainSectionControlArea != 0)
        {
            json << L"\"" << HuntHex(process.MainSectionControlArea, 16) << L"\"";
        }
        else
        {
            json << L"null";
        }
        json << L",\"main_section_backing_path\":\"" << HuntJsonEscape(process.MainSectionBackingPath) << L"\"";
        json << L",\"main_section_backing_state\":\"" << HuntJsonEscape(process.MainSectionBackingState) << L"\"";
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
        json << L",\"page_table_pages_read\":" << process.PageTablePagesRead;
        json << L",\"page_table_read_failures\":" << process.PageTableReadFailures;
        json << L",\"paging_levels\":" << process.PagingLevels;
        json << L",\"vad_scan_attempts\":" << process.VadScanAttempts;
        json << L",\"thread_scan_attempts\":" << process.ThreadScanAttempts;
        json << L",\"thread_inventory_complete\":"
             << (process.ThreadInventoryComplete ? L"true" : L"false");
        json << L",\"thread_suspension_state_coverage_complete\":"
             << (process.ThreadSuspensionStateCoverageComplete ? L"true" : L"false");
        json << L",\"suspension_state_resolved_threads\":"
             << process.SuspensionStateResolvedThreads;
        json << L",\"suspended_threads\":"
             << process.SuspendedThreads;
        json << L",\"suspicious_thread_starts\":" << process.SuspiciousThreadStarts;
        json << L",\"nonempty_apc_queues\":" << process.NonEmptyApcQueues;
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
