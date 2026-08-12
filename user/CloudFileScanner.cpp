#include "CloudFileScanner.h"

#include <Windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <cfapi.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <vector>

namespace
{
    constexpr size_t kInitialPlaceholderInfoSize = 4096;
    constexpr size_t kMaximumPlaceholderInfoSize = 64 * 1024;

    using CfGetPlaceholderStateFromFileInfoFn =
        CF_PLACEHOLDER_STATE(WINAPI*)(
            LPCVOID,
            FILE_INFO_BY_HANDLE_CLASS);
    using CfGetPlaceholderInfoFn =
        HRESULT(WINAPI*)(
            HANDLE,
            CF_PLACEHOLDER_INFO_CLASS,
            PVOID,
            DWORD,
            PDWORD);

    struct CloudApi
    {
        HMODULE Module = nullptr;
        CfGetPlaceholderStateFromFileInfoFn
            GetPlaceholderStateFromFileInfo = nullptr;
        CfGetPlaceholderInfoFn GetPlaceholderInfo = nullptr;
    };

    enum class PlaceholderInfoQueryResult
    {
        Placeholder,
        NotPlaceholder,
        Incomplete
    };

    bool IsOrdinaryFilePlaceholderInfoStatus(
        uint32_t status)
    {
        return status == static_cast<uint32_t>(
                             HRESULT_FROM_WIN32(
                                 ERROR_INVALID_FUNCTION)) ||
            status == static_cast<uint32_t>(
                          HRESULT_FROM_WIN32(
                              ERROR_NOT_A_REPARSE_POINT));
    }

    bool HasAuthoritativeNonPlaceholderViews(
        const CloudFilePlaceholderRecord& record)
    {
        return record.FileAttributeTagInfoAvailable &&
            !record.CloudReparseTag &&
            (record.FileAttributes &
             FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            record.FsctlReparseTagQueryError ==
                ERROR_NOT_A_REPARSE_POINT &&
            IsOrdinaryFilePlaceholderInfoStatus(
                record.PlaceholderInfoQueryStatus);
    }

    struct ReparseDataHeader
    {
        uint32_t Tag;
        uint16_t DataLength;
        uint16_t Reserved;
    };

    static_assert(sizeof(ReparseDataHeader) == 8);

    bool CheckedRange(
        size_t offset,
        size_t length,
        size_t bufferSize)
    {
        return offset <= bufferSize &&
            length <= bufferSize - offset;
    }

    bool IsCloudReparseTag(uint32_t tag)
    {
        return
            (tag & ~static_cast<uint32_t>(
                       IO_REPARSE_TAG_CLOUD_MASK)) ==
            static_cast<uint32_t>(IO_REPARSE_TAG_CLOUD);
    }

    bool ParseReparseTagBuffer(
        const uint8_t* buffer,
        size_t returnedLength,
        uint32_t* tag)
    {
        if (buffer == nullptr ||
            tag == nullptr ||
            returnedLength <
                sizeof(ReparseDataHeader))
        {
            return false;
        }

        ReparseDataHeader header = {};
        std::memcpy(
            &header,
            buffer,
            sizeof(header));
        if (header.DataLength >
            returnedLength - sizeof(header))
        {
            return false;
        }

        *tag = header.Tag;
        return true;
    }

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

    const CloudApi& GetCloudApi()
    {
        static const CloudApi api = []()
        {
            CloudApi loaded = {};
            loaded.Module = LoadLibraryExW(
                L"cldapi.dll",
                nullptr,
                LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (loaded.Module == nullptr)
            {
                return loaded;
            }

            loaded.GetPlaceholderStateFromFileInfo =
                reinterpret_cast<
                    CfGetPlaceholderStateFromFileInfoFn>(
                    GetProcAddress(
                        loaded.Module,
                        "CfGetPlaceholderStateFromFileInfo"));
            loaded.GetPlaceholderInfo =
                reinterpret_cast<CfGetPlaceholderInfoFn>(
                    GetProcAddress(
                        loaded.Module,
                        "CfGetPlaceholderInfo"));
            return loaded;
        }();
        return api;
    }

    bool QueryReparseTagWithFsctl(
        const std::wstring& path,
        uint32_t* tag,
        uint32_t* queryError)
    {
        if (tag == nullptr ||
            queryError == nullptr)
        {
            return false;
        }

        *tag = 0;
        *queryError = ERROR_SUCCESS;
        HANDLE file = CreateFileW(
            path.c_str(),
            FILE_READ_ATTRIBUTES |
                FILE_READ_EA,
            FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            *queryError = GetLastError();
            return false;
        }

        std::vector<uint8_t> buffer(
            MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
            0);
        DWORD returned = 0;
        const bool queried =
            DeviceIoControl(
                file,
                FSCTL_GET_REPARSE_POINT,
                nullptr,
                0,
                buffer.data(),
                static_cast<DWORD>(
                    buffer.size()),
                &returned,
                nullptr) != FALSE;
        if (!queried)
        {
            *queryError = GetLastError();
        }
        CloseHandle(file);
        if (!queried)
        {
            return false;
        }

        if (!ParseReparseTagBuffer(
                buffer.data(),
                returned,
                tag))
        {
            *queryError = ERROR_INVALID_DATA;
            return false;
        }
        return true;
    }

    bool ParsePlaceholderStandardInfo(
        const std::vector<uint8_t>& buffer,
        size_t returnedLength,
        CloudFilePlaceholderRecord* record)
    {
        if (record == nullptr)
        {
            return false;
        }

        constexpr size_t identityOffset =
            offsetof(
                CF_PLACEHOLDER_STANDARD_INFO,
                FileIdentity);
        if (!CheckedRange(
                0,
                identityOffset,
                returnedLength) ||
            returnedLength > buffer.size())
        {
            return false;
        }

        CF_PLACEHOLDER_STANDARD_INFO standard = {};
        const size_t fixedCopy =
            (std::min)(
                sizeof(standard),
                returnedLength);
        std::memcpy(
            &standard,
            buffer.data(),
            fixedCopy);

        const size_t identityLength =
            standard.FileIdentityLength;
        if (!CheckedRange(
                identityOffset,
                identityLength,
                returnedLength) ||
            standard.OnDiskDataSize.QuadPart < 0 ||
            standard.ValidatedDataSize.QuadPart < 0 ||
            standard.ModifiedDataSize.QuadPart < 0 ||
            standard.PropertiesSize.QuadPart < 0)
        {
            return false;
        }

        record->OnDiskDataSize =
            standard.OnDiskDataSize.QuadPart;
        record->ValidatedDataSize =
            standard.ValidatedDataSize.QuadPart;
        record->ModifiedDataSize =
            standard.ModifiedDataSize.QuadPart;
        record->PropertiesSize =
            standard.PropertiesSize.QuadPart;
        record->PinState =
            static_cast<uint32_t>(
                standard.PinState);
        record->InSyncState =
            static_cast<uint32_t>(
                standard.InSyncState);
        record->FileId =
            standard.FileId.QuadPart;
        record->SyncRootFileId =
            standard.SyncRootFileId.QuadPart;
        record->FileIdentityLength =
            standard.FileIdentityLength;
        record->PlaceholderInfoAvailable = true;
        return true;
    }

    PlaceholderInfoQueryResult QueryStandardInfo(
        HANDLE file,
        const CloudApi& api,
        CloudFilePlaceholderRecord* record,
        std::wstring* error)
    {
        if (record == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid Cloud Files standard-info output";
            }
            return PlaceholderInfoQueryResult::Incomplete;
        }

        if (api.GetPlaceholderInfo == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"cldapi!CfGetPlaceholderInfo is unavailable";
            }
            record->PlaceholderInfoQueryStatus =
                static_cast<uint32_t>(
                    HRESULT_FROM_WIN32(
                        ERROR_PROC_NOT_FOUND));
            return PlaceholderInfoQueryResult::Incomplete;
        }

        size_t bufferSize =
            kInitialPlaceholderInfoSize;
        while (bufferSize <=
               kMaximumPlaceholderInfoSize)
        {
            std::vector<uint8_t> buffer(
                bufferSize,
                0);
            DWORD returnedLength = 0;
            const HRESULT status =
                api.GetPlaceholderInfo(
                    file,
                    CF_PLACEHOLDER_INFO_STANDARD,
                    buffer.data(),
                    static_cast<DWORD>(
                        buffer.size()),
                    &returnedLength);
            record->PlaceholderInfoQueryStatus =
                static_cast<uint32_t>(status);
            if (status == S_OK)
            {
                if (!ParsePlaceholderStandardInfo(
                        buffer,
                        returnedLength,
                        record))
                {
                    if (error != nullptr)
                    {
                        *error =
                            L"CfGetPlaceholderInfo returned malformed standard metadata";
                    }
                    return PlaceholderInfoQueryResult::Incomplete;
                }
                return PlaceholderInfoQueryResult::Placeholder;
            }

            constexpr HRESULT moreData =
                HRESULT_FROM_WIN32(
                    ERROR_MORE_DATA);
            constexpr HRESULT insufficient =
                HRESULT_FROM_WIN32(
                    ERROR_INSUFFICIENT_BUFFER);
            if (status != moreData &&
                status != insufficient)
            {
                if (status ==
                    HRESULT_FROM_WIN32(
                        ERROR_NOT_A_CLOUD_FILE))
                {
                    return PlaceholderInfoQueryResult::
                        NotPlaceholder;
                }
                if (error != nullptr)
                {
                    *error = HexStatus(
                        L"CfGetPlaceholderInfo failed",
                        static_cast<uint32_t>(
                            status));
                }
                return PlaceholderInfoQueryResult::Incomplete;
            }

            size_t nextSize =
                returnedLength >
                        bufferSize
                    ? static_cast<size_t>(
                          returnedLength)
                    : bufferSize * 2;
            if (nextSize <= bufferSize ||
                nextSize >
                    kMaximumPlaceholderInfoSize)
            {
                if (error != nullptr)
                {
                    *error =
                        L"CfGetPlaceholderInfo metadata exceeds the bounded buffer limit";
                }
                return PlaceholderInfoQueryResult::Incomplete;
            }
            bufferSize = nextSize;
        }

        if (error != nullptr)
        {
            *error =
                L"CfGetPlaceholderInfo exhausted the bounded buffer limit";
        }
        return PlaceholderInfoQueryResult::Incomplete;
    }
}

bool CloudFileScanner::QueryPlaceholder(
    const std::wstring& path,
    CloudFilePlaceholderRecord* record,
    std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        if (record == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"invalid Cloud Files placeholder output";
            }
            break;
        }

        *record = {};
        record->Path = path;
        if (path.empty())
        {
            if (error != nullptr)
            {
                *error =
                    L"empty Cloud Files placeholder path";
            }
            break;
        }

        file = CreateFileW(
            path.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = HexStatus(
                    L"could not open image for attribute-only Cloud Files inspection",
                    GetLastError());
            }
            break;
        }

        FILE_ATTRIBUTE_TAG_INFO tagInfo = {};
        if (!GetFileInformationByHandleEx(
                file,
                FileAttributeTagInfo,
                &tagInfo,
                sizeof(tagInfo)))
        {
            if (error != nullptr)
            {
                *error = HexStatus(
                    L"FileAttributeTagInfo query failed",
                    GetLastError());
            }
            break;
        }

        record->FileAttributeTagInfoAvailable =
            true;
        record->FileAttributes =
            tagInfo.FileAttributes;
        record->ReparseTag =
            tagInfo.ReparseTag;
        record->CloudReparseTag =
            IsCloudReparseTag(
                tagInfo.ReparseTag);
        ok = true;

        if (!record->CloudReparseTag)
        {
            uint32_t fsctlTag = 0;
            uint32_t fsctlError = ERROR_SUCCESS;
            if (QueryReparseTagWithFsctl(
                    path,
                    &fsctlTag,
                    &fsctlError) &&
                IsCloudReparseTag(
                    fsctlTag))
            {
                record->FsctlReparseTagFallbackUsed =
                    true;
                record->FileAttributes |=
                    FILE_ATTRIBUTE_REPARSE_POINT;
                record->ReparseTag = fsctlTag;
                record->CloudReparseTag = true;
                tagInfo.FileAttributes =
                    record->FileAttributes;
                tagInfo.ReparseTag = fsctlTag;
            }
            record->FsctlReparseTagQueryError =
                fsctlError;
        }

        const CloudApi& api =
            GetCloudApi();
        std::wstring warning;
        CF_PLACEHOLDER_STATE state =
            CF_PLACEHOLDER_STATE_INVALID;
        if (record->CloudReparseTag &&
            api.GetPlaceholderStateFromFileInfo !=
                nullptr)
        {
            state =
                api.GetPlaceholderStateFromFileInfo(
                    &tagInfo,
                    FileAttributeTagInfo);
        }
        if (state !=
            CF_PLACEHOLDER_STATE_INVALID)
        {
            record->PlaceholderState =
                static_cast<uint32_t>(
                    state);
            record->PlaceholderStateAvailable =
                true;
        }
        else if (record->CloudReparseTag)
        {
            warning =
                L"cldapi placeholder-state helpers rejected or could not inspect a Cloud reparse tag";
        }

        std::wstring infoError;
        const PlaceholderInfoQueryResult
            infoResult =
            QueryStandardInfo(
                file,
                api,
                record,
                &infoError);
        if (infoResult ==
            PlaceholderInfoQueryResult::Placeholder)
        {
            record->PlaceholderInspectionComplete =
                true;
            record->IsCloudPlaceholder = true;
            record->PlaceholderState |=
                static_cast<uint32_t>(
                    CF_PLACEHOLDER_STATE_PLACEHOLDER);
            record->PlaceholderStateAvailable =
                true;
            if (!record->CloudReparseTag)
            {
                record->
                    PlaceholderInfoIdentificationFallbackUsed =
                        true;
                warning =
                    L"FileAttributeTagInfo and FSCTL masked the Cloud Files reparse tag; CfGetPlaceholderInfo confirmed the placeholder";
            }
        }
        else if (infoResult ==
                 PlaceholderInfoQueryResult::
                     NotPlaceholder)
        {
            if (record->CloudReparseTag)
            {
                if (!warning.empty())
                {
                    warning += L"; ";
                }
                warning +=
                    L"CfGetPlaceholderInfo rejected a visible Cloud reparse tag";
            }
            else
            {
                record->PlaceholderInspectionComplete =
                    true;
            }
        }
        else
        {
            // CfGetPlaceholderInfo returns ERROR_INVALID_FUNCTION on ordinary
            // local NTFS files on current Windows builds.  Treat that as a
            // clean negative only when both FileAttributeTagInfo and an
            // independent FSCTL_GET_REPARSE_POINT query agree that this is not
            // a reparse point.  A visible Cloud tag or an indeterminate FSCTL
            // result must remain coverage-incomplete.
            if (HasAuthoritativeNonPlaceholderViews(
                    *record))
            {
                record->PlaceholderInspectionComplete =
                    true;
            }
            else
            {
                if (!warning.empty() &&
                    !infoError.empty())
                {
                    warning += L"; ";
                }
                warning += infoError;
            }
        }

        if (record->PlaceholderStateAvailable &&
            (record->PlaceholderState &
             static_cast<uint32_t>(
                 CF_PLACEHOLDER_STATE_PLACEHOLDER)) != 0)
        {
            record->IsCloudPlaceholder = true;
        }

        record->MetadataCoverageComplete =
            record->PlaceholderInspectionComplete;
        if (record->IsCloudPlaceholder)
        {
            record->MetadataCoverageComplete =
                record->MetadataCoverageComplete &&
                record->PlaceholderStateAvailable &&
                record->PlaceholderInfoAvailable;
        }
        record->Warning = warning;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    return ok;
}

bool CloudFileScannerSelfTest()
{
    CloudFilePlaceholderRecord defaultRecord;
    if (defaultRecord.MetadataCoverageComplete)
    {
        return false;
    }

    if (!IsCloudReparseTag(
            IO_REPARSE_TAG_CLOUD) ||
        IsCloudReparseTag(
            IO_REPARSE_TAG_WOF) ||
        IsCloudReparseTag(
            IO_REPARSE_TAG_SYMLINK))
    {
        return false;
    }

    CloudFilePlaceholderRecord ordinary = {};
    ordinary.FileAttributeTagInfoAvailable = true;
    ordinary.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
    ordinary.FsctlReparseTagQueryError =
        ERROR_NOT_A_REPARSE_POINT;
    ordinary.PlaceholderInfoQueryStatus =
        static_cast<uint32_t>(
            HRESULT_FROM_WIN32(
                ERROR_INVALID_FUNCTION));
    if (!HasAuthoritativeNonPlaceholderViews(
            ordinary))
    {
        return false;
    }

    CloudFilePlaceholderRecord cloudTagged =
        ordinary;
    cloudTagged.FileAttributes |=
        FILE_ATTRIBUTE_REPARSE_POINT;
    cloudTagged.CloudReparseTag = true;
    if (HasAuthoritativeNonPlaceholderViews(
            cloudTagged))
    {
        return false;
    }

    CloudFilePlaceholderRecord fsctlIndeterminate =
        ordinary;
    fsctlIndeterminate.FsctlReparseTagQueryError =
        ERROR_ACCESS_DENIED;
    if (HasAuthoritativeNonPlaceholderViews(
            fsctlIndeterminate))
    {
        return false;
    }

    for (uint32_t variant = 1;
         variant <= 0xf;
         ++variant)
    {
        const uint32_t tag =
            static_cast<uint32_t>(
                IO_REPARSE_TAG_CLOUD) |
            (variant << 12);
        if (!IsCloudReparseTag(tag))
        {
            return false;
        }
    }

    ReparseDataHeader reparseHeader = {};
    reparseHeader.Tag =
        static_cast<uint32_t>(
            IO_REPARSE_TAG_CLOUD);
    reparseHeader.DataLength = 3;
    std::vector<uint8_t> reparseBuffer(
        sizeof(reparseHeader) +
            reparseHeader.DataLength,
        0);
    std::memcpy(
        reparseBuffer.data(),
        &reparseHeader,
        sizeof(reparseHeader));
    uint32_t parsedTag = 0;
    if (!ParseReparseTagBuffer(
            reparseBuffer.data(),
            reparseBuffer.size(),
            &parsedTag) ||
        parsedTag != reparseHeader.Tag ||
        ParseReparseTagBuffer(
            reparseBuffer.data(),
            sizeof(uint32_t),
            &parsedTag))
    {
        return false;
    }

    ReparseDataHeader malformedHeader =
        reparseHeader;
    malformedHeader.DataLength = 4;
    std::memcpy(
        reparseBuffer.data(),
        &malformedHeader,
        sizeof(malformedHeader));
    if (ParseReparseTagBuffer(
            reparseBuffer.data(),
            reparseBuffer.size(),
            &parsedTag))
    {
        return false;
    }

    constexpr size_t identityOffset =
        offsetof(
            CF_PLACEHOLDER_STANDARD_INFO,
            FileIdentity);
    std::vector<uint8_t> valid(
        identityOffset + 3,
        0);
    CF_PLACEHOLDER_STANDARD_INFO standard = {};
    standard.OnDiskDataSize.QuadPart = 100;
    standard.ValidatedDataSize.QuadPart = 90;
    standard.ModifiedDataSize.QuadPart = 10;
    standard.PropertiesSize.QuadPart = 7;
    standard.PinState = CF_PIN_STATE_PINNED;
    standard.InSyncState =
        CF_IN_SYNC_STATE_NOT_IN_SYNC;
    standard.FileId.QuadPart = 0x1234;
    standard.SyncRootFileId.QuadPart =
        0x5678;
    standard.FileIdentityLength = 3;
    std::memcpy(
        valid.data(),
        &standard,
        identityOffset);
    valid[identityOffset] = 0xaa;
    valid[identityOffset + 1] = 0xbb;
    valid[identityOffset + 2] = 0xcc;

    CloudFilePlaceholderRecord parsed = {};
    if (!ParsePlaceholderStandardInfo(
            valid,
            valid.size(),
            &parsed) ||
        !parsed.PlaceholderInfoAvailable ||
        parsed.OnDiskDataSize != 100 ||
        parsed.ValidatedDataSize != 90 ||
        parsed.ModifiedDataSize != 10 ||
        parsed.PropertiesSize != 7 ||
        parsed.PinState !=
            CF_PIN_STATE_PINNED ||
        parsed.InSyncState !=
            CF_IN_SYNC_STATE_NOT_IN_SYNC ||
        parsed.FileId != 0x1234 ||
        parsed.SyncRootFileId != 0x5678 ||
        parsed.FileIdentityLength != 3)
    {
        return false;
    }

    constexpr uint32_t oversizedLength =
        std::numeric_limits<uint32_t>::max();
    std::memcpy(
        valid.data() +
            offsetof(
                CF_PLACEHOLDER_STANDARD_INFO,
                FileIdentityLength),
        &oversizedLength,
        sizeof(oversizedLength));
    CloudFilePlaceholderRecord oversized = {};
    if (ParsePlaceholderStandardInfo(
            valid,
            valid.size(),
            &oversized))
    {
        return false;
    }

    const uint32_t restoredLength = 3;
    std::memcpy(
        valid.data() +
            offsetof(
                CF_PLACEHOLDER_STANDARD_INFO,
                FileIdentityLength),
        &restoredLength,
        sizeof(restoredLength));
    CloudFilePlaceholderRecord truncated = {};
    return !ParsePlaceholderStandardInfo(
        valid,
        identityOffset + 2,
        &truncated);
}
