#pragma once

#include "ObservationModel.h"
#include <map>
#include <optional>

// Membership in a temporal sweep, never an atomic mapping/code version.
struct ImageSweepIdentity
{
    std::wstring CollectionId, SweepId, Image, TargetId, AddressSpaceId;
    ObservationIdentity Identity;
    uint64_t ImageBase = 0, ExpectedBytes = 0, StartedTick = 0, StartedFileTime = 0;
    uint32_t TotalRanges = 0;
};

struct ImageSweepSlice
{
    uint64_t Ordinal = 0, ReadSetId = 0, StartedTick = 0, EndedTick = 0, ObservedFileTime = 0;
    uint32_t StartRange = 0, RangeCount = 0;
    bool Terminal = false, TraversalComplete = false;
    std::wstring Reason;
    std::wstring ReferenceSha256, RawPayloadSha256, RecipeSha256;
    bool ReferenceWritten = false, RawWritten = false, RecipeWritten = false;
};

struct ImageSweepContext
{
    ImageSweepIdentity Sweep;
    ImageSweepSlice Slice;
};

struct ImageSweepManifest
{
    ImageSweepIdentity Sweep;
    uint64_t ObservedSlices = 0, LastEndedTick = 0;
    bool TerminalObserved = false, TraversalComplete = false, Inconsistent = false;
    std::wstring EndReason;
    std::vector<ImageSweepSlice> Slices;
};

std::wstring ImageSweepManifestJson(const ImageSweepManifest& manifest);
bool ParseImageSweepManifest(const std::wstring& json, ImageSweepManifest* manifest);
struct ImageRecipeReplay;
struct ImageSweepReplayEvidence;
ImageRecipeReplay ReplayImageSweepManifest(const std::wstring& path, std::wstring* error,
    ImageSweepReplayEvidence* verifiedEvidence = nullptr, const std::wstring& expectedManifestSha256 = L"");

// Writer-owned bounded metadata; queue losses remain visible as ordinal gaps.
// No producer/writer shared mutable sweep state or original-file handles.
class ImageSweepManifestStore
{
public:
    struct Limits
    {
        size_t Groups = 128, Entries = 8192, EntriesPerGroup = 2048;
    };
    ImageSweepManifestStore() = default;
    explicit ImageSweepManifestStore(Limits limits) : Budget(limits) {}
    std::optional<ImageSweepManifest> Observe(const ImageSweepContext& context);
    std::optional<ImageSweepManifest> TakeIncomplete();
    size_t Pending() const { return Sweeps.size(); }
    size_t RetainedEntries() const { return Entries; }
    uint64_t AdmissionDeniedSlices() const { return AdmissionDenied; }
    uint64_t EntryDrops() const { return Dropped; }
private:
    Limits Budget;
    std::map<std::wstring, ImageSweepManifest> Sweeps;
    size_t Entries = 0;
    uint64_t AdmissionDenied = 0, Dropped = 0;
};
