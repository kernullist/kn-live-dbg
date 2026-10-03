#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct MinifilterAttachmentRecord
{
    bool IsMinifilter = false;
    bool DetachedVolume = false;
    uint32_t AggregateFlags = 0;
    uint32_t InstanceFlags = 0;
    uint32_t FrameId = 0;
    uint32_t VolumeFileSystemType = 0;
    uint32_t SupportedFeatures = 0;
    std::wstring FilterName;
    std::wstring InstanceName;
    std::wstring Altitude;
    std::wstring VolumeName;
};

struct MinifilterAttachmentScanResult
{
    struct VolumeSnapshot
    {
        std::wstring Name;
        bool Complete = false;
        uint32_t RecordCount = 0;
    };
    std::vector<std::wstring> Volumes;
    std::vector<MinifilterAttachmentRecord> Records;
    std::vector<std::wstring> Warnings;
    std::vector<VolumeSnapshot> VolumeSnapshots;
    uint64_t SnapshotTickMs = 0;
    bool VolumeEnumerationComplete = false;
    bool SnapshotStable = false;
    bool CoverageComplete = false;
    bool Incomplete = false;
};

class MinifilterAttachmentScanner
{
public:
    // Uses the documented Filter Manager user-mode enumeration APIs. It does
    // not attach, detach, open file data, or mutate filter state.
    bool Scan(
        MinifilterAttachmentScanResult* result,
        std::wstring* error);
};

bool MinifilterAttachmentScannerSelfTest();
std::wstring MinifilterAttachmentIdentity(const MinifilterAttachmentRecord& record);
std::wstring MinifilterAttachmentStateKey(const MinifilterAttachmentRecord& record);
