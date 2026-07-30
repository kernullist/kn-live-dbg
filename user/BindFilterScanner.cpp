#include "BindFilterScanner.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <limits>
#include <set>
#include <sstream>
#include <utility>

namespace
{
    constexpr ULONG kGetMappingsVolume = 0x00000001;
    constexpr size_t kInitialBufferSize = 64ull * 1024ull;
    constexpr size_t kMaximumBufferSize = 16ull * 1024ull * 1024ull;

    struct BindMappingsTargetEntry
    {
        uint32_t TargetRootLength;
        uint32_t TargetRootOffset;
    };

    struct BindMappingsEntry
    {
        uint32_t VirtualRootLength;
        uint32_t VirtualRootOffset;
        uint32_t Flags;
        uint32_t NumberOfTargets;
        uint32_t TargetEntriesOffset;
    };

    struct BindMappingsInfo
    {
        uint32_t Size;
        LONG Status;
        uint32_t MappingCount;
    };

    struct BufferRange
    {
        size_t Offset = 0;
        size_t Length = 0;
    };

    static_assert(sizeof(BindMappingsTargetEntry) == 8);
    static_assert(sizeof(BindMappingsEntry) == 20);
    static_assert(sizeof(BindMappingsInfo) == 12);

    using BfGetMappingsFn = HRESULT(WINAPI*)(
        ULONG,
        HANDLE,
        LPCWSTR,
        PSID,
        PULONG,
        LPVOID);

    std::wstring HexStatus(
        const std::wstring& context,
        uint32_t value)
    {
        std::wstringstream stream;
        stream << context
               << L" (0x"
               << std::hex
               << value
               << L")";
        return stream.str();
    }

    std::wstring LowerCopy(const std::wstring& value)
    {
        std::wstring lowered = value;
        std::transform(
            lowered.begin(),
            lowered.end(),
            lowered.begin(),
            [](wchar_t ch)
            {
                return static_cast<wchar_t>(
                    std::towlower(ch));
            });
        return lowered;
    }

    bool CheckedRange(
        size_t offset,
        size_t length,
        size_t bufferSize)
    {
        return offset <= bufferSize &&
            length <= bufferSize - offset;
    }

    bool CheckedMultiply(
        size_t left,
        size_t right,
        size_t* product)
    {
        if (product == nullptr ||
            (left != 0 &&
             right >
                 std::numeric_limits<size_t>::max() /
                     left))
        {
            return false;
        }
        *product = left * right;
        return true;
    }

    bool RangesOverlap(
        const BufferRange& left,
        const BufferRange& right)
    {
        return left.Length != 0 &&
            right.Length != 0 &&
            left.Offset < right.Offset + right.Length &&
            right.Offset < left.Offset + left.Length;
    }

    bool RangeOverlapsStructure(
        size_t offset,
        size_t length,
        const std::vector<BufferRange>& structures)
    {
        const BufferRange candidate = {offset, length};
        return std::any_of(
            structures.begin(),
            structures.end(),
            [&](const BufferRange& structure)
            {
                return RangesOverlap(candidate, structure);
            });
    }

    bool ReadBufferText(
        const uint8_t* buffer,
        size_t bufferSize,
        uint32_t offset,
        uint32_t byteLength,
        const std::vector<BufferRange>& structures,
        std::wstring* value)
    {
        if (buffer == nullptr ||
            value == nullptr ||
            (byteLength % sizeof(wchar_t)) != 0 ||
            (byteLength != 0 &&
             (offset % alignof(wchar_t)) != 0) ||
            !CheckedRange(offset, byteLength, bufferSize) ||
            RangeOverlapsStructure(
                offset,
                byteLength,
                structures))
        {
            return false;
        }

        const size_t characterCount =
            byteLength / sizeof(wchar_t);
        value->assign(characterCount, L'\0');
        if (byteLength != 0)
        {
            std::memcpy(
                value->data(),
                buffer + offset,
                byteLength);
        }
        while (!value->empty() &&
               value->back() == L'\0')
        {
            value->pop_back();
        }
        if (std::find(
                value->begin(),
                value->end(),
                L'\0') != value->end())
        {
            value->clear();
            return false;
        }
        return true;
    }

    bool ParseMappingsBuffer(
        const uint8_t* buffer,
        size_t bufferSize,
        const std::wstring& volumeRoot,
        std::vector<BindFilterMappingRecord>* records,
        std::wstring* error)
    {
        if (buffer == nullptr ||
            records == nullptr ||
            bufferSize < sizeof(BindMappingsInfo))
        {
            if (error != nullptr)
            {
                *error =
                    L"bindflt mapping buffer is too small";
            }
            return false;
        }

        BindMappingsInfo info = {};
        std::memcpy(
            &info,
            buffer,
            sizeof(info));
        const size_t declaredSize =
            static_cast<size_t>(info.Size);
        if (declaredSize < sizeof(info) ||
            declaredSize > bufferSize)
        {
            if (error != nullptr)
            {
                *error =
                    L"bindflt mapping buffer size is invalid";
            }
            return false;
        }
        if (info.Status != 0)
        {
            if (error != nullptr)
            {
                *error = HexStatus(
                    L"bindflt mapping status failed",
                    static_cast<uint32_t>(
                        info.Status));
            }
            return false;
        }

        size_t entriesBytes = 0;
        if (!CheckedMultiply(
                info.MappingCount,
                sizeof(BindMappingsEntry),
                &entriesBytes) ||
            !CheckedRange(
                sizeof(info),
                entriesBytes,
                declaredSize))
        {
            if (error != nullptr)
            {
                *error =
                    L"bindflt mapping entry array is invalid";
            }
            return false;
        }

        std::vector<BindMappingsEntry> entries(
            info.MappingCount);
        std::vector<BufferRange> structures =
        {
            {
                0,
                sizeof(info) + entriesBytes
            }
        };
        for (uint32_t index = 0;
             index < info.MappingCount;
             ++index)
        {
            BindMappingsEntry& entry = entries[index];
            std::memcpy(
                &entry,
                buffer +
                    sizeof(info) +
                    index * sizeof(entry),
                sizeof(entry));

            size_t targetsBytes = 0;
            // The wire serializer appends this DWORD-based descriptor array
            // directly after an unpadded UTF-16 path. Read it with memcpy and
            // require only the two-byte alignment the protocol guarantees.
            if (!CheckedMultiply(
                    entry.NumberOfTargets,
                    sizeof(BindMappingsTargetEntry),
                &targetsBytes) ||
                (entry.NumberOfTargets != 0 &&
                 (entry.TargetEntriesOffset %
                  alignof(wchar_t)) != 0) ||
                !CheckedRange(
                    entry.TargetEntriesOffset,
                    targetsBytes,
                    declaredSize) ||
                RangeOverlapsStructure(
                    entry.TargetEntriesOffset,
                    targetsBytes,
                    structures))
            {
                if (error != nullptr)
                {
                    *error =
                        L"bindflt target entry array is invalid";
                }
                return false;
            }
            if (targetsBytes != 0)
            {
                structures.push_back(
                    {
                        entry.TargetEntriesOffset,
                        targetsBytes
                    });
            }
        }

        for (const BindMappingsEntry& entry :
             entries)
        {
            BindFilterMappingRecord record = {};
            record.VolumeRoot = volumeRoot;
            record.Flags = entry.Flags;
            if (!ReadBufferText(
                    buffer,
                    declaredSize,
                    entry.VirtualRootOffset,
                    entry.VirtualRootLength,
                    structures,
                    &record.VirtualRoot))
            {
                if (error != nullptr)
                {
                    *error =
                        L"bindflt virtual-root range is invalid";
                }
                return false;
            }

            for (uint32_t targetIndex = 0;
                 targetIndex < entry.NumberOfTargets;
                 ++targetIndex)
            {
                BindMappingsTargetEntry target = {};
                std::memcpy(
                    &target,
                    buffer +
                        entry.TargetEntriesOffset +
                        targetIndex * sizeof(target),
                    sizeof(target));
                std::wstring targetRoot;
                if (!ReadBufferText(
                        buffer,
                        declaredSize,
                        target.TargetRootOffset,
                        target.TargetRootLength,
                        structures,
                        &targetRoot))
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"bindflt target-root range is invalid";
                    }
                    return false;
                }
                record.TargetRoots.push_back(
                    std::move(targetRoot));
            }

            records->push_back(std::move(record));
        }
        return true;
    }

    bool IsRetriableBufferResult(
        HRESULT result,
        ULONG requestedSize,
        size_t currentSize)
    {
        return result ==
                HRESULT_FROM_WIN32(
                    ERROR_INSUFFICIENT_BUFFER) ||
            result ==
                HRESULT_FROM_WIN32(ERROR_MORE_DATA) ||
            requestedSize > currentSize;
    }

    bool ValidateReturnedMappingSize(
        ULONG returnedSize,
        size_t bufferSize,
        size_t* validatedSize)
    {
        if (validatedSize == nullptr ||
            returnedSize < sizeof(BindMappingsInfo) ||
            static_cast<size_t>(returnedSize) >
                bufferSize)
        {
            return false;
        }

        *validatedSize =
            static_cast<size_t>(returnedSize);
        return true;
    }

    bool QueryVolumeMappings(
        BfGetMappingsFn getMappings,
        const std::wstring& volumeRoot,
        std::vector<BindFilterMappingRecord>* records,
        std::wstring* error)
    {
        if (getMappings == nullptr ||
            records == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid bindflt query arguments";
            }
            return false;
        }

        std::vector<uint8_t> buffer(
            kInitialBufferSize,
            0);
        for (uint32_t attempt = 0;
             attempt < 8;
             ++attempt)
        {
            ULONG size =
                static_cast<ULONG>(buffer.size());
            std::fill(
                buffer.begin(),
                buffer.end(),
                uint8_t{0});
            HRESULT result = getMappings(
                kGetMappingsVolume,
                nullptr,
                volumeRoot.c_str(),
                nullptr,
                &size,
                buffer.data());

            BindMappingsInfo returnedInfo = {};
            bool hasReturnedInfo =
                buffer.size() >= sizeof(returnedInfo);
            if (hasReturnedInfo)
            {
                std::memcpy(
                    &returnedInfo,
                    buffer.data(),
                    sizeof(returnedInfo));
            }
            const bool statusNeedsMore =
                hasReturnedInfo &&
                (static_cast<uint32_t>(
                     returnedInfo.Status) ==
                     0xc0000023u ||
                 static_cast<uint32_t>(
                     returnedInfo.Status) ==
                     0x80000005u);
            if (IsRetriableBufferResult(
                    result,
                    size,
                    buffer.size()) ||
                (hasReturnedInfo &&
                 returnedInfo.Size > buffer.size()) ||
                statusNeedsMore)
            {
                size_t nextSize = std::max(
                    static_cast<size_t>(size),
                    buffer.size() * 2);
                if (hasReturnedInfo)
                {
                    nextSize = std::max(
                        nextSize,
                        static_cast<size_t>(
                            returnedInfo.Size));
                }
                if (nextSize > kMaximumBufferSize)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"bindflt mapping buffer exceeds limit";
                    }
                    return false;
                }
                buffer.assign(nextSize, 0);
                continue;
            }

            if (result != S_OK)
            {
                if (error != nullptr)
                {
                    *error = HexStatus(
                        L"BfGetMappings failed",
                        static_cast<uint32_t>(result));
                }
                return false;
            }

            size_t returnedSize = 0;
            if (!ValidateReturnedMappingSize(
                    size,
                    buffer.size(),
                    &returnedSize))
            {
                if (error != nullptr)
                {
                    *error =
                        L"BfGetMappings returned an invalid success size";
                }
                return false;
            }
            return ParseMappingsBuffer(
                buffer.data(),
                returnedSize,
                volumeRoot,
                records,
                error);
        }

        if (error != nullptr)
        {
            *error =
                L"bindflt mapping buffer retry limit reached";
        }
        return false;
    }

    bool IsDriveLetterRoot(
        const std::wstring& path)
    {
        return path.size() == 3 &&
            std::iswalpha(path[0]) != 0 &&
            path[1] == L':' &&
            path[2] == L'\\';
    }

    bool GetMountedPaths(
        const std::wstring& volumeName,
        std::vector<std::wstring>* paths,
        std::wstring* error)
    {
        if (paths == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid mounted-volume path output";
            }
            return false;
        }

        paths->clear();
        std::vector<wchar_t> buffer(512, L'\0');
        for (uint32_t attempt = 0;
             attempt < 8;
             ++attempt)
        {
            DWORD required = 0;
            std::fill(
                buffer.begin(),
                buffer.end(),
                L'\0');
            if (GetVolumePathNamesForVolumeNameW(
                    volumeName.c_str(),
                    buffer.data(),
                    static_cast<DWORD>(buffer.size()),
                    &required))
            {
                if (required == 0 ||
                    required > buffer.size() ||
                    buffer[required - 1] != L'\0')
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"GetVolumePathNamesForVolumeNameW returned a malformed length or terminator";
                    }
                    return false;
                }

                size_t offset = 0;
                bool hadPath = false;
                while (offset < required &&
                       buffer[offset] != L'\0')
                {
                    size_t end = offset;
                    while (end < required &&
                           buffer[end] != L'\0')
                    {
                        ++end;
                    }
                    if (end >= required)
                    {
                        if (error != nullptr)
                        {
                            *error =
                                L"GetVolumePathNamesForVolumeNameW returned an unterminated mount path";
                        }
                        paths->clear();
                        return false;
                    }
                    paths->emplace_back(
                        buffer.data() + offset,
                        end - offset);
                    hadPath = true;
                    offset = end + 1;
                }
                if (hadPath &&
                    offset >= required)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"GetVolumePathNamesForVolumeNameW omitted the multi-string terminator";
                    }
                    paths->clear();
                    return false;
                }
                return true;
            }

            const DWORD status = GetLastError();
            if (status != ERROR_MORE_DATA ||
                required <= buffer.size() ||
                required > 1024ull * 1024ull)
            {
                if (error != nullptr)
                {
                    *error = HexStatus(
                        L"GetVolumePathNamesForVolumeNameW failed",
                        status);
                }
                return false;
            }
            buffer.assign(required, L'\0');
        }

        if (error != nullptr)
        {
            *error =
                L"mounted-volume path retry limit reached";
        }
        return false;
    }

    std::vector<std::wstring> LocalVolumeRoots(
        bool* enumerationComplete,
        std::vector<std::wstring>* warnings,
        std::wstring* error)
    {
        std::vector<std::wstring> roots;
        if (enumerationComplete != nullptr)
        {
            *enumerationComplete = false;
        }

        wchar_t volumeName[MAX_PATH + 1] = {};
        HANDLE search = FindFirstVolumeW(
            volumeName,
            static_cast<DWORD>(
                _countof(volumeName)));
        if (search == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = HexStatus(
                    L"FindFirstVolumeW failed",
                    GetLastError());
            }
            return roots;
        }

        bool complete = true;
        std::set<std::wstring> seen;
        while (true)
        {
            const std::wstring volume(volumeName);
            std::vector<std::wstring> mountedPaths;
            std::wstring pathError;
            if (!GetMountedPaths(
                    volume,
                    &mountedPaths,
                    &pathError))
            {
                complete = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"volume " + volume + L": " +
                        pathError);
                }
            }
            else if (!mountedPaths.empty())
            {
                std::stable_sort(
                    mountedPaths.begin(),
                    mountedPaths.end(),
                    [](const std::wstring& left,
                       const std::wstring& right)
                    {
                        const bool leftDrive =
                            IsDriveLetterRoot(left);
                        const bool rightDrive =
                            IsDriveLetterRoot(right);
                        if (leftDrive != rightDrive)
                        {
                            return leftDrive;
                        }
                        return LowerCopy(left) <
                            LowerCopy(right);
                    });

                bool typeResolved = false;
                for (const std::wstring& path :
                     mountedPaths)
                {
                    const UINT driveType =
                        GetDriveTypeW(path.c_str());
                    if (driveType == DRIVE_UNKNOWN ||
                        driveType ==
                            DRIVE_NO_ROOT_DIR)
                    {
                        continue;
                    }

                    typeResolved = true;
                    bool eligible =
                        driveType == DRIVE_FIXED ||
                        driveType == DRIVE_RAMDISK;
                    if (driveType ==
                        DRIVE_REMOVABLE)
                    {
                        eligible =
                            GetVolumeInformationW(
                                path.c_str(),
                                nullptr,
                                0,
                                nullptr,
                                nullptr,
                                nullptr,
                                nullptr,
                                0) != FALSE;
                    }
                    if (!eligible)
                    {
                        continue;
                    }

                    const std::wstring key =
                        LowerCopy(path);
                    if (seen.insert(key).second)
                    {
                        roots.push_back(path);
                    }
                    break;
                }

                if (!typeResolved)
                {
                    complete = false;
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"volume " + volume +
                            L": mounted path drive type could not be resolved");
                    }
                }
            }

            if (FindNextVolumeW(
                    search,
                    volumeName,
                    static_cast<DWORD>(
                        _countof(volumeName))))
            {
                continue;
            }

            const DWORD status = GetLastError();
            if (status != ERROR_NO_MORE_FILES)
            {
                complete = false;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        HexStatus(
                            L"FindNextVolumeW failed",
                            status));
                }
            }
            break;
        }

        if (!FindVolumeClose(search))
        {
            complete = false;
            if (warnings != nullptr)
            {
                warnings->push_back(
                    HexStatus(
                        L"FindVolumeClose failed",
                        GetLastError()));
            }
        }

        std::sort(
            roots.begin(),
            roots.end(),
            [](const std::wstring& left,
               const std::wstring& right)
            {
                return LowerCopy(left) <
                    LowerCopy(right);
            });
        if (enumerationComplete != nullptr)
        {
            *enumerationComplete = complete;
        }
        return roots;
    }

    std::wstring MappingKey(
        const BindFilterMappingRecord& record)
    {
        std::wstring key =
            LowerCopy(record.VolumeRoot) +
            L"|" +
            LowerCopy(record.VirtualRoot) +
            L"|" +
            std::to_wstring(record.Flags);
        for (const std::wstring& target :
             record.TargetRoots)
        {
            key += L"|";
            key += LowerCopy(target);
        }
        return key;
    }
}

bool BindFilterScanner::ScanGlobal(
    BindFilterScanResult* result,
    std::wstring* error)
{
    if (error != nullptr)
    {
        error->clear();
    }
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error =
                L"invalid bindflt scan result output";
        }
        return false;
    }

    *result = BindFilterScanResult{};
    HMODULE module = LoadLibraryExW(
        L"bindfltapi.dll",
        nullptr,
        LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr)
    {
        if (error != nullptr)
        {
            *error = HexStatus(
                L"bindfltapi.dll is unavailable",
                GetLastError());
        }
        return false;
    }

    bool ok = false;
    do
    {
        BfGetMappingsFn getMappings =
            reinterpret_cast<BfGetMappingsFn>(
                GetProcAddress(
                    module,
                    "BfGetMappings"));
        if (getMappings == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"bindfltapi!BfGetMappings is unavailable";
            }
            break;
        }

        std::wstring volumeError;
        bool volumeEnumerationComplete = false;
        std::vector<std::wstring> roots =
            LocalVolumeRoots(
                &volumeEnumerationComplete,
                &result->Warnings,
                &volumeError);
        if (roots.empty())
        {
            if (error != nullptr)
            {
                *error = volumeError.empty()
                    ? L"no local volumes are available for bindflt enumeration"
                    : volumeError;
            }
            break;
        }

        bool anyCompleted = false;
        bool allCompleted =
            volumeEnumerationComplete;
        std::set<std::wstring> seen;
        for (const std::wstring& root : roots)
        {
            ++result->VolumesAttempted;
            std::vector<BindFilterMappingRecord>
                volumeRecords;
            std::wstring queryError;
            if (!QueryVolumeMappings(
                    getMappings,
                    root,
                    &volumeRecords,
                    &queryError))
            {
                allCompleted = false;
                result->Warnings.push_back(
                    L"volume " + root + L": " +
                    queryError);
                continue;
            }

            anyCompleted = true;
            ++result->VolumesCompleted;
            for (BindFilterMappingRecord& record :
                 volumeRecords)
            {
                std::wstring key = MappingKey(record);
                if (seen.insert(key).second)
                {
                    result->Records.push_back(
                        std::move(record));
                }
            }
        }

        std::sort(
            result->Records.begin(),
            result->Records.end(),
            [](const BindFilterMappingRecord& left,
               const BindFilterMappingRecord& right)
            {
                return MappingKey(left) <
                    MappingKey(right);
            });
        result->GlobalCoverageComplete =
            anyCompleted && allCompleted;
        ok = anyCompleted;
        if (!ok && error != nullptr)
        {
            *error =
                L"bindflt mapping enumeration failed for every local volume";
        }
    } while (false);

    FreeLibrary(module);
    return ok;
}

bool BindFilterScannerSelfTest()
{
    const std::wstring virtualRoot =
        L"C:\\Windows\\System32\\amsi.dllx";
    const std::wstring targetRoot =
        L"C:\\Temp\\amsi.dll";

    const size_t infoOffset = 0;
    const size_t entryOffset =
        sizeof(BindMappingsInfo);
    const size_t virtualOffset =
        entryOffset + sizeof(BindMappingsEntry);
    const size_t targetEntryOffset =
        virtualOffset +
        virtualRoot.size() * sizeof(wchar_t);
    const size_t targetOffset =
        targetEntryOffset +
        sizeof(BindMappingsTargetEntry);
    const size_t totalSize =
        targetOffset +
        targetRoot.size() * sizeof(wchar_t);
    std::vector<uint8_t> buffer(totalSize, 0);

    size_t validatedSize = 0;
    if (totalSize >
            std::numeric_limits<ULONG>::max() ||
        !ValidateReturnedMappingSize(
            static_cast<ULONG>(totalSize),
            buffer.size(),
            &validatedSize) ||
        validatedSize != totalSize ||
        ValidateReturnedMappingSize(
            0,
            buffer.size(),
            &validatedSize) ||
        ValidateReturnedMappingSize(
            static_cast<ULONG>(
                sizeof(BindMappingsInfo) - 1),
            buffer.size(),
            &validatedSize) ||
        ValidateReturnedMappingSize(
            static_cast<ULONG>(
                buffer.size() + 1),
            buffer.size(),
            &validatedSize))
    {
        return false;
    }

    // bindflt.sys writes target descriptors immediately after the UTF-16
    // virtual-root bytes. An odd character count therefore produces a valid
    // two-byte-aligned, but not four-byte-aligned, descriptor array.
    if ((targetEntryOffset % alignof(wchar_t)) != 0 ||
        (targetEntryOffset % alignof(uint32_t)) == 0)
    {
        return false;
    }

    BindMappingsInfo info = {};
    info.Size = static_cast<uint32_t>(totalSize);
    info.Status = 0;
    info.MappingCount = 1;
    std::memcpy(
        buffer.data() + infoOffset,
        &info,
        sizeof(info));

    BindMappingsEntry entry = {};
    entry.VirtualRootLength =
        static_cast<uint32_t>(
            virtualRoot.size() *
            sizeof(wchar_t));
    entry.VirtualRootOffset =
        static_cast<uint32_t>(virtualOffset);
    entry.Flags = 0x8;
    entry.NumberOfTargets = 1;
    entry.TargetEntriesOffset =
        static_cast<uint32_t>(targetEntryOffset);
    std::memcpy(
        buffer.data() + entryOffset,
        &entry,
        sizeof(entry));

    BindMappingsTargetEntry target = {};
    target.TargetRootLength =
        static_cast<uint32_t>(
            targetRoot.size() *
            sizeof(wchar_t));
    target.TargetRootOffset =
        static_cast<uint32_t>(targetOffset);
    std::memcpy(
        buffer.data() + targetEntryOffset,
        &target,
        sizeof(target));
    std::memcpy(
        buffer.data() + virtualOffset,
        virtualRoot.data(),
        virtualRoot.size() * sizeof(wchar_t));
    std::memcpy(
        buffer.data() + targetOffset,
        targetRoot.data(),
        targetRoot.size() * sizeof(wchar_t));

    std::vector<BindFilterMappingRecord> records;
    std::wstring error;
    if (!ParseMappingsBuffer(
            buffer.data(),
            buffer.size(),
            L"C:\\",
            &records,
            &error) ||
        records.size() != 1 ||
        records[0].VolumeRoot != L"C:\\" ||
        records[0].VirtualRoot != virtualRoot ||
        records[0].TargetRoots.size() != 1 ||
        records[0].TargetRoots[0] != targetRoot ||
        records[0].Flags != 0x8)
    {
        return false;
    }

    const auto parserRejects =
        [&]()
        {
            records.clear();
            error.clear();
            return !ParseMappingsBuffer(
                buffer.data(),
                buffer.size(),
                L"C:\\",
                &records,
                &error);
        };

    const wchar_t embeddedNull = L'\0';
    std::memcpy(
        buffer.data() +
            virtualOffset +
            sizeof(wchar_t),
        &embeddedNull,
        sizeof(embeddedNull));
    if (!parserRejects())
    {
        return false;
    }
    std::memcpy(
        buffer.data() + virtualOffset,
        virtualRoot.data(),
        virtualRoot.size() *
            sizeof(wchar_t));

    BindMappingsTargetEntry invalidTarget = target;
    invalidTarget.TargetRootOffset =
        static_cast<uint32_t>(buffer.size() + 2);
    std::memcpy(
        buffer.data() + targetEntryOffset,
        &invalidTarget,
        sizeof(invalidTarget));
    if (!parserRejects())
    {
        return false;
    }
    std::memcpy(
        buffer.data() + targetEntryOffset,
        &target,
        sizeof(target));

    BindMappingsInfo zeroSized = info;
    zeroSized.Size = 0;
    std::memcpy(
        buffer.data() + infoOffset,
        &zeroSized,
        sizeof(zeroSized));
    if (!parserRejects())
    {
        return false;
    }
    std::memcpy(
        buffer.data() + infoOffset,
        &info,
        sizeof(info));

    BindMappingsInfo informationalStatus =
        info;
    informationalStatus.Status = 1;
    std::memcpy(
        buffer.data() + infoOffset,
        &informationalStatus,
        sizeof(informationalStatus));
    if (!parserRejects())
    {
        return false;
    }
    std::memcpy(
        buffer.data() + infoOffset,
        &info,
        sizeof(info));

    BindMappingsEntry misalignedText = entry;
    misalignedText.VirtualRootOffset =
        static_cast<uint32_t>(virtualOffset + 1);
    std::memcpy(
        buffer.data() + entryOffset,
        &misalignedText,
        sizeof(misalignedText));
    if (!parserRejects())
    {
        return false;
    }

    BindMappingsEntry misalignedTargets = entry;
    ++misalignedTargets.TargetEntriesOffset;
    std::memcpy(
        buffer.data() + entryOffset,
        &misalignedTargets,
        sizeof(misalignedTargets));
    if (!parserRejects())
    {
        return false;
    }

    BindMappingsEntry overlappingText = entry;
    overlappingText.VirtualRootOffset = 0;
    overlappingText.VirtualRootLength =
        sizeof(wchar_t);
    std::memcpy(
        buffer.data() + entryOffset,
        &overlappingText,
        sizeof(overlappingText));
    if (!parserRejects())
    {
        return false;
    }

    BindMappingsEntry overlappingTargets = entry;
    overlappingTargets.TargetEntriesOffset =
        static_cast<uint32_t>(entryOffset);
    std::memcpy(
        buffer.data() + entryOffset,
        &overlappingTargets,
        sizeof(overlappingTargets));
    return parserRejects();
}
