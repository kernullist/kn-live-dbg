#pragma once

#include <cstdint>
#include <string>

struct CloudFilePlaceholderRecord
{
    std::wstring Path;
    uint32_t FileAttributes = 0;
    uint32_t ReparseTag = 0;
    uint32_t PlaceholderState = 0;
    uint32_t PinState = 0;
    uint32_t InSyncState = 0;
    int64_t OnDiskDataSize = 0;
    int64_t ValidatedDataSize = 0;
    int64_t ModifiedDataSize = 0;
    int64_t PropertiesSize = 0;
    int64_t FileId = 0;
    int64_t SyncRootFileId = 0;
    uint32_t FileIdentityLength = 0;
    uint32_t FsctlReparseTagQueryError = 0;
    uint32_t PlaceholderInfoQueryStatus = 0;
    bool FileAttributeTagInfoAvailable = false;
    bool FsctlReparseTagFallbackUsed = false;
    bool CloudReparseTag = false;
    bool IsCloudPlaceholder = false;
    bool PlaceholderInfoIdentificationFallbackUsed = false;
    bool PlaceholderInspectionComplete = false;
    bool PlaceholderStateAvailable = false;
    bool PlaceholderInfoAvailable = false;
    bool MetadataCoverageComplete = false;
    std::wstring Warning;
};

class CloudFileScanner
{
public:
    // Opens for attributes only. This does not request file data; cldflt must
    // remain in the path so CfGetPlaceholderInfo can identify the placeholder
    // even when the ordinary attribute and FSCTL tag views are masked.
    bool QueryPlaceholder(
        const std::wstring& path,
        CloudFilePlaceholderRecord* record,
        std::wstring* error);
};

bool CloudFileScannerSelfTest();
