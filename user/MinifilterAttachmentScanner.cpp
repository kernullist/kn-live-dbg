#include "MinifilterAttachmentScanner.h"

#include <Windows.h>
#include <fltuser.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

namespace
{
    constexpr size_t kInitialBufferBytes = 4096;
    constexpr size_t kMaximumBufferBytes = 1024 * 1024;
    constexpr size_t kMaximumVolumes = 1024;
    constexpr size_t kMaximumRecords = 16384;

    struct AlignedQueryBuffer
    {
        std::vector<uint64_t> Storage;
        size_t ByteSize = 0;

        bool Resize(size_t bytes)
        {
            if (bytes == 0 ||
                bytes > kMaximumBufferBytes ||
                bytes >
                    (std::numeric_limits<size_t>::max)() -
                        (sizeof(uint64_t) - 1))
            {
                return false;
            }

            ByteSize = bytes;
            Storage.resize(
                (bytes + sizeof(uint64_t) - 1) /
                sizeof(uint64_t));
            return true;
        }

        void* Data()
        {
            return Storage.data();
        }

        const uint8_t* Bytes() const
        {
            return reinterpret_cast<const uint8_t*>(
                Storage.data());
        }
    };

    std::wstring HexStatus(HRESULT status)
    {
        std::wstringstream stream;
        stream << L"0x"
               << std::hex
               << std::setw(8)
               << std::setfill(L'0')
               << static_cast<uint32_t>(status);
        return stream.str();
    }

    std::wstring NormalizeIdentityText(
        const std::wstring& value)
    {
        std::wstring normalized = value;
        while (!normalized.empty() &&
               normalized.back() == L'\0')
        {
            normalized.pop_back();
        }
        std::transform(
            normalized.begin(),
            normalized.end(),
            normalized.begin(),
            [](wchar_t ch)
            {
                return static_cast<wchar_t>(
                    towlower(ch));
            });
        return normalized;
    }

    std::wstring IdentityPart(
        const std::wstring& value)
    {
        const std::wstring normalized =
            NormalizeIdentityText(value);
        return std::to_wstring(normalized.size()) +
            L":" +
            normalized;
    }

    std::wstring RecordIdentity(
        const MinifilterAttachmentRecord& record)
    {
        return
            (record.IsMinifilter
                 ? L"minifilter:"
                 : L"legacy:") +
            IdentityPart(record.FilterName) +
            IdentityPart(record.InstanceName) +
            IdentityPart(record.VolumeName) +
            IdentityPart(record.Altitude);
    }

    template<typename Callback>
    bool InvokeGrowingBuffer(
        Callback&& callback,
        AlignedQueryBuffer* buffer,
        DWORD* bytesReturned,
        HRESULT* status,
        const std::wstring& context,
        std::wstring* error)
    {
        if (buffer == nullptr ||
            bytesReturned == nullptr ||
            status == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid Filter Manager query buffer";
            }
            return false;
        }

        size_t requested = kInitialBufferBytes;
        for (uint32_t attempt = 0;
             attempt < 16;
             ++attempt)
        {
            if (!buffer->Resize(requested))
            {
                if (error != nullptr)
                {
                    *error =
                        context +
                        L" exceeded the 1 MiB evidence cap";
                }
                return false;
            }

            *bytesReturned = 0;
            *status = callback(
                buffer->Data(),
                static_cast<DWORD>(
                    buffer->ByteSize),
                bytesReturned);
            if (*status !=
                HRESULT_FROM_WIN32(
                    ERROR_INSUFFICIENT_BUFFER))
            {
                if (SUCCEEDED(*status) &&
                    static_cast<size_t>(
                        *bytesReturned) >
                        buffer->ByteSize)
                {
                    if (error != nullptr)
                    {
                        *error =
                            context +
                            L" returned an oversized byte count";
                    }
                    return false;
                }
                return true;
            }

            size_t next =
                static_cast<size_t>(
                    *bytesReturned);
            if (next <= requested)
            {
                if (requested >
                    kMaximumBufferBytes / 2)
                {
                    if (error != nullptr)
                    {
                        *error =
                            context +
                            L" buffer growth exceeded the evidence cap";
                    }
                    return false;
                }
                next = requested * 2;
            }
            if (next > kMaximumBufferBytes)
            {
                if (error != nullptr)
                {
                    *error =
                        context +
                        L" requested more than the 1 MiB evidence cap";
                }
                return false;
            }
            requested = next;
        }

        if (error != nullptr)
        {
            *error =
                context +
                L" did not converge while growing the buffer";
        }
        return false;
    }

    bool CopyBoundedWideString(
        const uint8_t* entry,
        size_t entryBytes,
        uint16_t offset,
        uint16_t lengthBytes,
        std::wstring* value,
        std::wstring* error,
        const wchar_t* field)
    {
        if (entry == nullptr || value == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid aggregate instance string output";
            }
            return false;
        }
        if ((lengthBytes % sizeof(wchar_t)) != 0 ||
            (lengthBytes != 0 &&
             ((offset % alignof(wchar_t)) != 0 ||
              static_cast<size_t>(offset) <
                  sizeof(
                      INSTANCE_AGGREGATE_STANDARD_INFORMATION))) ||
            static_cast<size_t>(offset) >
                entryBytes ||
            static_cast<size_t>(lengthBytes) >
                entryBytes -
                    static_cast<size_t>(offset))
        {
            if (error != nullptr)
            {
                *error =
                    std::wstring(
                        L"invalid aggregate instance ") +
                    field +
                    L" range";
            }
            return false;
        }

        value->assign(
            static_cast<size_t>(lengthBytes) /
                sizeof(wchar_t),
            L'\0');
        if (lengthBytes != 0)
        {
            std::memcpy(
                value->data(),
                entry + offset,
                lengthBytes);
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
            if (error != nullptr)
            {
                *error =
                    std::wstring(
                        L"aggregate instance ") +
                    field +
                    L" contains an embedded NUL";
            }
            value->clear();
            return false;
        }
        return true;
    }

    struct AggregateStringRange
    {
        uint16_t Offset = 0;
        uint16_t Length = 0;
    };

    template<size_t Count>
    bool AggregateStringRangesDistinct(
        const std::array<
            AggregateStringRange,
            Count>& ranges)
    {
        for (size_t left = 0;
             left < ranges.size();
             ++left)
        {
            if (ranges[left].Length == 0)
            {
                continue;
            }
            const size_t leftStart =
                ranges[left].Offset;
            const size_t leftEnd =
                leftStart +
                ranges[left].Length;
            for (size_t right = left + 1;
                 right < ranges.size();
                 ++right)
            {
                if (ranges[right].Length == 0)
                {
                    continue;
                }
                const size_t rightStart =
                    ranges[right].Offset;
                const size_t rightEnd =
                    rightStart +
                        ranges[right].Length;
                if (leftStart < rightEnd &&
                    rightStart < leftEnd)
                {
                    return false;
                }
            }
        }
        return true;
    }

    bool ParseVolumeBasicInformation(
        const uint8_t* buffer,
        size_t bytes,
        std::wstring* volume,
        std::wstring* error)
    {
        constexpr size_t kNameOffset =
            offsetof(
                FILTER_VOLUME_BASIC_INFORMATION,
                FilterVolumeName);
        if (buffer == nullptr ||
            volume == nullptr ||
            bytes < kNameOffset)
        {
            if (error != nullptr)
            {
                *error =
                    L"truncated FilterVolumeBasicInformation";
            }
            return false;
        }

        FILTER_VOLUME_BASIC_INFORMATION header = {};
        const size_t headerBytes =
            (std::min)(
                sizeof(header),
                bytes);
        std::memcpy(
            &header,
            buffer,
            headerBytes);
        const size_t nameBytes =
            static_cast<size_t>(
                header.FilterVolumeNameLength);
        if ((nameBytes % sizeof(wchar_t)) != 0 ||
            nameBytes > bytes - kNameOffset)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid Filter Manager volume name range";
            }
            return false;
        }

        volume->assign(
            nameBytes / sizeof(wchar_t),
            L'\0');
        if (nameBytes != 0)
        {
            std::memcpy(
                volume->data(),
                buffer + kNameOffset,
                nameBytes);
        }
        while (!volume->empty() &&
               volume->back() == L'\0')
        {
            volume->pop_back();
        }
        if (volume->empty() ||
            std::find(
                volume->begin(),
                volume->end(),
                L'\0') != volume->end())
        {
            if (error != nullptr)
            {
                *error =
                    volume->empty()
                        ? L"Filter Manager returned an empty volume name"
                        : L"Filter Manager returned a volume name with an embedded NUL";
            }
            return false;
        }
        return true;
    }

    bool ParseAggregateInstanceBuffer(
        const uint8_t* buffer,
        size_t bytes,
        const std::wstring& enumeratedVolume,
        std::vector<MinifilterAttachmentRecord>* records,
        std::wstring* error)
    {
        if (buffer == nullptr ||
            records == nullptr ||
            bytes <
                sizeof(
                    INSTANCE_AGGREGATE_STANDARD_INFORMATION))
        {
            if (error != nullptr)
            {
                *error =
                    L"truncated aggregate instance buffer";
            }
            return false;
        }

        size_t offset = 0;
        while (offset < bytes)
        {
            const size_t remaining = bytes - offset;
            if (remaining <
                sizeof(
                    INSTANCE_AGGREGATE_STANDARD_INFORMATION))
            {
                if (error != nullptr)
                {
                    *error =
                        L"truncated aggregate instance entry";
                }
                return false;
            }

            INSTANCE_AGGREGATE_STANDARD_INFORMATION info = {};
            std::memcpy(
                &info,
                buffer + offset,
                sizeof(info));

            size_t entryBytes = remaining;
            if (info.NextEntryOffset != 0)
            {
                entryBytes =
                    static_cast<size_t>(
                        info.NextEntryOffset);
                if (entryBytes <
                        sizeof(info) ||
                    (entryBytes %
                        alignof(uint64_t)) != 0 ||
                    entryBytes > remaining)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"invalid aggregate instance NextEntryOffset";
                    }
                    return false;
                }
                if (entryBytes == remaining)
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"aggregate instance NextEntryOffset points beyond the final entry";
                    }
                    return false;
                }
            }

            const bool isMinifilter =
                (info.Flags &
                 FLTFL_IASI_IS_MINIFILTER) != 0;
            const bool isLegacy =
                (info.Flags &
                 FLTFL_IASI_IS_LEGACYFILTER) != 0;
            if (isMinifilter == isLegacy)
            {
                if (error != nullptr)
                {
                    *error =
                        L"aggregate instance type flags are ambiguous";
                }
                return false;
            }

            MinifilterAttachmentRecord record = {};
            record.IsMinifilter =
                isMinifilter;
            record.AggregateFlags =
                info.Flags;
            if (isMinifilter)
            {
                const auto& mini =
                    info.Type.MiniFilter;
                const std::array<
                    AggregateStringRange,
                    4> stringRanges =
                    {{
                        {
                            mini.InstanceNameBufferOffset,
                            mini.InstanceNameLength
                        },
                        {
                            mini.AltitudeBufferOffset,
                            mini.AltitudeLength
                        },
                        {
                            mini.VolumeNameBufferOffset,
                            mini.VolumeNameLength
                        },
                        {
                            mini.FilterNameBufferOffset,
                            mini.FilterNameLength
                        }
                    }};
                if (!AggregateStringRangesDistinct(
                        stringRanges))
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"aggregate minifilter instance string ranges overlap";
                    }
                    return false;
                }
                record.InstanceFlags =
                    mini.Flags;
                record.DetachedVolume =
                    (mini.Flags &
                     FLTFL_IASIM_DETACHED_VOLUME) !=
                    0;
                record.FrameId =
                    mini.FrameID;
                record.VolumeFileSystemType =
                    static_cast<uint32_t>(
                        mini.VolumeFileSystemType);
                record.SupportedFeatures =
                    mini.SupportedFeatures;
                if (!CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        mini.InstanceNameBufferOffset,
                        mini.InstanceNameLength,
                        &record.InstanceName,
                        error,
                        L"instance name") ||
                    !CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        mini.AltitudeBufferOffset,
                        mini.AltitudeLength,
                        &record.Altitude,
                        error,
                        L"altitude") ||
                    !CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        mini.VolumeNameBufferOffset,
                        mini.VolumeNameLength,
                        &record.VolumeName,
                        error,
                        L"volume name") ||
                    !CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        mini.FilterNameBufferOffset,
                        mini.FilterNameLength,
                        &record.FilterName,
                        error,
                        L"filter name"))
                {
                    return false;
                }
            }
            else
            {
                const auto& legacy =
                    info.Type.LegacyFilter;
                const std::array<
                    AggregateStringRange,
                    3> stringRanges =
                    {{
                        {
                            legacy.AltitudeBufferOffset,
                            legacy.AltitudeLength
                        },
                        {
                            legacy.VolumeNameBufferOffset,
                            legacy.VolumeNameLength
                        },
                        {
                            legacy.FilterNameBufferOffset,
                            legacy.FilterNameLength
                        }
                    }};
                if (!AggregateStringRangesDistinct(
                        stringRanges))
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"aggregate legacy instance string ranges overlap";
                    }
                    return false;
                }
                record.InstanceFlags =
                    legacy.Flags;
                record.DetachedVolume =
                    (legacy.Flags &
                     FLTFL_IASIL_DETACHED_VOLUME) !=
                    0;
                record.SupportedFeatures =
                    legacy.SupportedFeatures;
                if (!CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        legacy.AltitudeBufferOffset,
                        legacy.AltitudeLength,
                        &record.Altitude,
                        error,
                        L"legacy altitude") ||
                    !CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        legacy.VolumeNameBufferOffset,
                        legacy.VolumeNameLength,
                        &record.VolumeName,
                        error,
                        L"legacy volume name") ||
                    !CopyBoundedWideString(
                        buffer + offset,
                        entryBytes,
                        legacy.FilterNameBufferOffset,
                        legacy.FilterNameLength,
                        &record.FilterName,
                        error,
                        L"legacy filter name"))
                {
                    return false;
                }
            }

            if (record.VolumeName.empty())
            {
                record.VolumeName =
                    enumeratedVolume;
            }
            if (record.FilterName.empty() ||
                record.VolumeName.empty())
            {
                if (error != nullptr)
                {
                    *error =
                        L"aggregate instance lacks a stable filter or volume identity";
                }
                return false;
            }

            records->push_back(
                std::move(record));
            if (records->size() >
                kMaximumRecords)
            {
                if (error != nullptr)
                {
                    *error =
                        L"aggregate instance record cap exceeded";
                }
                return false;
            }

            if (info.NextEntryOffset == 0)
            {
                offset = bytes;
            }
            else
            {
                offset += entryBytes;
            }
        }
        return true;
    }

    bool EnumerateVolumes(
        std::vector<std::wstring>* volumes,
        std::wstring* error)
    {
        if (volumes == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid volume enumeration output";
            }
            return false;
        }

        HANDLE findHandle =
            INVALID_HANDLE_VALUE;
        const auto closeFindHandle =
            [&]()
            {
                if (findHandle !=
                        INVALID_HANDLE_VALUE &&
                    findHandle != nullptr)
                {
                    FilterVolumeFindClose(
                        findHandle);
                }
                findHandle =
                    INVALID_HANDLE_VALUE;
            };
        AlignedQueryBuffer buffer;
        DWORD returned = 0;
        HRESULT status = E_FAIL;
        auto first =
            [&](void* data,
                DWORD size,
                DWORD* bytesReturned)
            {
                closeFindHandle();
                return FilterVolumeFindFirst(
                    FilterVolumeBasicInformation,
                    data,
                    size,
                    bytesReturned,
                    &findHandle);
            };
        if (!InvokeGrowingBuffer(
                first,
                &buffer,
                &returned,
                &status,
                L"FilterVolumeFindFirst",
                error))
        {
            closeFindHandle();
            return false;
        }
        if (status ==
            HRESULT_FROM_WIN32(
                ERROR_NO_MORE_ITEMS))
        {
            closeFindHandle();
            if (error != nullptr)
            {
                *error =
                    L"Filter Manager returned no volumes";
            }
            return false;
        }
        if (status != S_OK ||
            findHandle ==
                INVALID_HANDLE_VALUE ||
            findHandle == nullptr)
        {
            closeFindHandle();
            if (error != nullptr)
            {
                *error =
                    L"FilterVolumeFindFirst failed: " +
                    HexStatus(status);
            }
            return false;
        }

        bool ok = true;
        std::set<std::wstring> seen;
        while (true)
        {
            std::wstring volume;
            std::wstring parseError;
            if (!ParseVolumeBasicInformation(
                    buffer.Bytes(),
                    returned,
                    &volume,
                    &parseError))
            {
                if (error != nullptr)
                {
                    *error = parseError;
                }
                ok = false;
                break;
            }

            const std::wstring key =
                NormalizeIdentityText(volume);
            if (!seen.insert(key).second)
            {
                if (error != nullptr)
                {
                    *error =
                        L"Filter Manager returned a duplicate volume identity: " +
                        key;
                }
                ok = false;
                break;
            }
            volumes->push_back(volume);
            if (volumes->size() >
                kMaximumVolumes)
            {
                if (error != nullptr)
                {
                    *error =
                        L"Filter Manager volume cap exceeded";
                }
                ok = false;
                break;
            }

            auto next =
                [&](void* data,
                    DWORD size,
                    DWORD* bytesReturned)
                {
                    return FilterVolumeFindNext(
                        findHandle,
                        FilterVolumeBasicInformation,
                        data,
                        size,
                        bytesReturned);
                };
            if (!InvokeGrowingBuffer(
                    next,
                    &buffer,
                    &returned,
                    &status,
                    L"FilterVolumeFindNext",
                    error))
            {
                ok = false;
                break;
            }
            if (status ==
                HRESULT_FROM_WIN32(
                    ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (status != S_OK)
            {
                if (error != nullptr)
                {
                    *error =
                        L"FilterVolumeFindNext failed: " +
                        HexStatus(status);
                }
                ok = false;
                break;
            }
        }

        closeFindHandle();
        return ok;
    }

    bool EnumerateVolumeInstances(
        const std::wstring& volume,
        std::vector<MinifilterAttachmentRecord>* records,
        std::wstring* error)
    {
        HANDLE findHandle =
            INVALID_HANDLE_VALUE;
        const auto closeFindHandle =
            [&]()
            {
                if (findHandle !=
                        INVALID_HANDLE_VALUE &&
                    findHandle != nullptr)
                {
                    FilterVolumeInstanceFindClose(
                        findHandle);
                }
                findHandle =
                    INVALID_HANDLE_VALUE;
            };
        AlignedQueryBuffer buffer;
        DWORD returned = 0;
        HRESULT status = E_FAIL;
        auto first =
            [&](void* data,
                DWORD size,
                DWORD* bytesReturned)
            {
                closeFindHandle();
                return FilterVolumeInstanceFindFirst(
                    volume.c_str(),
                    InstanceAggregateStandardInformation,
                    data,
                    size,
                    bytesReturned,
                    &findHandle);
            };
        if (!InvokeGrowingBuffer(
                first,
                &buffer,
                &returned,
                &status,
                L"FilterVolumeInstanceFindFirst",
                error))
        {
            closeFindHandle();
            return false;
        }
        if (status ==
            HRESULT_FROM_WIN32(
                ERROR_NO_MORE_ITEMS))
        {
            closeFindHandle();
            return true;
        }
        if (status != S_OK ||
            findHandle ==
                INVALID_HANDLE_VALUE ||
            findHandle == nullptr)
        {
            closeFindHandle();
            if (error != nullptr)
            {
                *error =
                    L"FilterVolumeInstanceFindFirst(" +
                    volume +
                    L") failed: " +
                    HexStatus(status);
            }
            return false;
        }

        bool ok = true;
        while (true)
        {
            std::wstring parseError;
            if (!ParseAggregateInstanceBuffer(
                    buffer.Bytes(),
                    returned,
                    volume,
                    records,
                    &parseError))
            {
                if (error != nullptr)
                {
                    *error =
                        L"Filter Manager instance parse failed for " +
                        volume +
                        L": " +
                        parseError;
                }
                ok = false;
                break;
            }

            auto next =
                [&](void* data,
                    DWORD size,
                    DWORD* bytesReturned)
                {
                    return
                        FilterVolumeInstanceFindNext(
                            findHandle,
                            InstanceAggregateStandardInformation,
                            data,
                            size,
                            bytesReturned);
                };
            if (!InvokeGrowingBuffer(
                    next,
                    &buffer,
                    &returned,
                    &status,
                    L"FilterVolumeInstanceFindNext",
                    error))
            {
                ok = false;
                break;
            }
            if (status ==
                HRESULT_FROM_WIN32(
                    ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (status != S_OK)
            {
                if (error != nullptr)
                {
                    *error =
                        L"FilterVolumeInstanceFindNext(" +
                        volume +
                        L") failed: " +
                        HexStatus(status);
                }
                ok = false;
                break;
            }
        }

        closeFindHandle();
        return ok;
    }

    uint16_t AppendWideString(
        std::vector<uint8_t>* buffer,
        const std::wstring& value)
    {
        if (buffer == nullptr ||
            value.size() >
                (std::numeric_limits<uint16_t>::max)() /
                    sizeof(wchar_t))
        {
            return 0;
        }
        const size_t bytes =
            value.size() *
            sizeof(wchar_t);
        if (buffer->size() >
                (std::numeric_limits<uint16_t>::max)() ||
            bytes >
                (std::numeric_limits<uint16_t>::max)() -
                    buffer->size())
        {
            return 0;
        }
        const uint16_t offset =
            static_cast<uint16_t>(
                buffer->size());
        buffer->resize(
            buffer->size() + bytes);
        if (bytes != 0)
        {
            std::memcpy(
                buffer->data() + offset,
                value.data(),
                bytes);
        }
        return offset;
    }
}

bool MinifilterAttachmentScanner::Scan(
    MinifilterAttachmentScanResult* result,
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
                L"invalid minifilter attachment scan output";
        }
        return false;
    }

    *result =
        MinifilterAttachmentScanResult{};
    std::wstring volumeError;
    if (!EnumerateVolumes(
            &result->Volumes,
            &volumeError))
    {
        if (error != nullptr)
        {
            *error = volumeError;
        }
        return false;
    }

    std::vector<MinifilterAttachmentRecord>
        collected;
    for (const std::wstring& volume :
         result->Volumes)
    {
        std::wstring localError;
        if (!EnumerateVolumeInstances(
                volume,
                &collected,
                &localError))
        {
            result->Incomplete = true;
            result->Warnings.push_back(
                localError.empty()
                    ? L"Filter Manager instance enumeration failed for " +
                          volume
                    : localError);
        }
    }

    std::set<std::wstring> seen;
    for (MinifilterAttachmentRecord& record :
         collected)
    {
        const std::wstring key =
            RecordIdentity(record);
        if (!seen.insert(key).second)
        {
            result->Incomplete = true;
            result->Warnings.push_back(
                L"duplicate Filter Manager attachment identity: " +
                key);
            continue;
        }
        result->Records.push_back(
            std::move(record));
    }
    return true;
}

bool MinifilterAttachmentScannerSelfTest()
{
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        info = {};
    info.Flags =
        FLTFL_IASI_IS_MINIFILTER;
    info.Type.MiniFilter.Flags =
        FLTFL_IASIM_DETACHED_VOLUME;
    info.Type.MiniFilter.FrameID = 2;
    info.Type.MiniFilter.VolumeFileSystemType =
        FLT_FSTYPE_NTFS;
    info.Type.MiniFilter.SupportedFeatures =
        0x0f;

    std::vector<uint8_t> buffer(
        sizeof(info),
        0);
    const std::wstring instance =
        L"WdFilter Instance";
    const std::wstring altitude =
        L"328010";
    const std::wstring volume =
        L"\\Device\\HarddiskVolume3";
    const std::wstring filter =
        L"WdFilter";

    info.Type.MiniFilter.InstanceNameBufferOffset =
        AppendWideString(
            &buffer,
            instance);
    info.Type.MiniFilter.InstanceNameLength =
        static_cast<uint16_t>(
            instance.size() *
            sizeof(wchar_t));
    info.Type.MiniFilter.AltitudeBufferOffset =
        AppendWideString(
            &buffer,
            altitude);
    info.Type.MiniFilter.AltitudeLength =
        static_cast<uint16_t>(
            altitude.size() *
            sizeof(wchar_t));
    info.Type.MiniFilter.VolumeNameBufferOffset =
        AppendWideString(
            &buffer,
            volume);
    info.Type.MiniFilter.VolumeNameLength =
        static_cast<uint16_t>(
            volume.size() *
            sizeof(wchar_t));
    info.Type.MiniFilter.FilterNameBufferOffset =
        AppendWideString(
            &buffer,
            filter);
    info.Type.MiniFilter.FilterNameLength =
        static_cast<uint16_t>(
            filter.size() *
            sizeof(wchar_t));
    std::memcpy(
        buffer.data(),
        &info,
        sizeof(info));

    std::vector<MinifilterAttachmentRecord>
        parsed;
    std::wstring error;
    if (!ParseAggregateInstanceBuffer(
            buffer.data(),
            buffer.size(),
            volume,
            &parsed,
            &error) ||
        parsed.size() != 1 ||
        !parsed[0].IsMinifilter ||
        !parsed[0].DetachedVolume ||
        parsed[0].FrameId != 2 ||
        parsed[0].VolumeFileSystemType !=
            static_cast<uint32_t>(
                FLT_FSTYPE_NTFS) ||
        parsed[0].SupportedFeatures != 0x0f ||
        parsed[0].FilterName != filter ||
        parsed[0].InstanceName != instance ||
        parsed[0].Altitude != altitude ||
        parsed[0].VolumeName != volume)
    {
        return false;
    }

    std::vector<uint8_t> embeddedNull =
        buffer;
    const wchar_t zero = L'\0';
    std::memcpy(
        embeddedNull.data() +
            info.Type.MiniFilter.
                InstanceNameBufferOffset +
            sizeof(wchar_t),
        &zero,
        sizeof(zero));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            embeddedNull.data(),
            embeddedNull.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> ambiguous =
        buffer;
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        ambiguousInfo = info;
    ambiguousInfo.Flags |=
        FLTFL_IASI_IS_LEGACYFILTER;
    std::memcpy(
        ambiguous.data(),
        &ambiguousInfo,
        sizeof(ambiguousInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            ambiguous.data(),
            ambiguous.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> outOfRange =
        buffer;
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        outOfRangeInfo = info;
    outOfRangeInfo.Type.MiniFilter.FilterNameBufferOffset =
        static_cast<uint16_t>(
            outOfRange.size() - 2);
    outOfRangeInfo.Type.MiniFilter.FilterNameLength =
        8;
    std::memcpy(
        outOfRange.data(),
        &outOfRangeInfo,
        sizeof(outOfRangeInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            outOfRange.data(),
            outOfRange.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> headerAlias =
        buffer;
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        headerAliasInfo = info;
    headerAliasInfo.Type.MiniFilter.FilterNameBufferOffset =
        static_cast<uint16_t>(
            offsetof(
                INSTANCE_AGGREGATE_STANDARD_INFORMATION,
                Type));
    std::memcpy(
        headerAlias.data(),
        &headerAliasInfo,
        sizeof(headerAliasInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            headerAlias.data(),
            headerAlias.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> overlappingStrings =
        buffer;
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        overlappingStringsInfo = info;
    overlappingStringsInfo.Type.MiniFilter.
        FilterNameBufferOffset =
            info.Type.MiniFilter.
                VolumeNameBufferOffset;
    overlappingStringsInfo.Type.MiniFilter.
        FilterNameLength =
            info.Type.MiniFilter.
                VolumeNameLength;
    std::memcpy(
        overlappingStrings.data(),
        &overlappingStringsInfo,
        sizeof(overlappingStringsInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            overlappingStrings.data(),
            overlappingStrings.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> badNext =
        buffer;
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        badNextInfo = info;
    badNextInfo.NextEntryOffset =
        static_cast<uint32_t>(
            sizeof(info) + 1);
    std::memcpy(
        badNext.data(),
        &badNextInfo,
        sizeof(badNextInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            badNext.data(),
            badNext.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    std::vector<uint8_t> danglingNext =
        buffer;
    danglingNext.resize(
        (danglingNext.size() +
         alignof(uint64_t) - 1) &
            ~(alignof(uint64_t) - 1),
        0);
    INSTANCE_AGGREGATE_STANDARD_INFORMATION
        danglingNextInfo = info;
    danglingNextInfo.NextEntryOffset =
        static_cast<uint32_t>(
            danglingNext.size());
    std::memcpy(
        danglingNext.data(),
        &danglingNextInfo,
        sizeof(danglingNextInfo));
    parsed.clear();
    if (ParseAggregateInstanceBuffer(
            danglingNext.data(),
            danglingNext.size(),
            volume,
            &parsed,
            &error))
    {
        return false;
    }

    const size_t volumeHeader =
        offsetof(
            FILTER_VOLUME_BASIC_INFORMATION,
            FilterVolumeName);
    std::vector<uint8_t> volumeBuffer(
        volumeHeader +
            volume.size() *
                sizeof(wchar_t),
        0);
    const uint16_t volumeLength =
        static_cast<uint16_t>(
            volume.size() *
            sizeof(wchar_t));
    std::memcpy(
        volumeBuffer.data(),
        &volumeLength,
        sizeof(volumeLength));
    std::memcpy(
        volumeBuffer.data() +
            volumeHeader,
        volume.data(),
        volumeLength);
    std::wstring parsedVolume;
    if (!ParseVolumeBasicInformation(
            volumeBuffer.data(),
            volumeBuffer.size(),
            &parsedVolume,
            &error) ||
        parsedVolume != volume)
    {
        return false;
    }

    if (volume.size() < 3)
    {
        return false;
    }
    std::vector<uint8_t> embeddedNullVolume =
        volumeBuffer;
    const wchar_t embeddedVolumeNull = L'\0';
    std::memcpy(
        embeddedNullVolume.data() +
            volumeHeader +
            (volume.size() / 2) *
                sizeof(wchar_t),
        &embeddedVolumeNull,
        sizeof(embeddedVolumeNull));
    if (ParseVolumeBasicInformation(
            embeddedNullVolume.data(),
            embeddedNullVolume.size(),
            &parsedVolume,
            &error))
    {
        return false;
    }

    volumeBuffer[0] = 3;
    volumeBuffer[1] = 0;
    return !ParseVolumeBasicInformation(
        volumeBuffer.data(),
        volumeBuffer.size(),
        &parsedVolume,
        &error);
}
