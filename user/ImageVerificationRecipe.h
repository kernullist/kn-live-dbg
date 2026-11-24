#pragma once

#include "ExecutableImageVerifier.h"
#include "ObservationSource.h"
#include "RecordingObservationSource.h"
#include "ProcessMappingObservation.h"

namespace image_loader { struct Window; }

constexpr size_t ImageRecipeMaxBytes = 2 * 1024 * 1024;
constexpr size_t ImageRecipeMaxReads = 64;
constexpr uint64_t ImageRecipeReadBudget = 128 * 1024;
inline constexpr const wchar_t* ImageRecipePolicy = L"kn.executable_page.direct.v1";

struct ImageRecipeRead
{
    uint64_t Address = 0;
    uint32_t Length = 0;
    ObservationReadResult Result;
};

struct ImageVerificationRecipe
{
    uint32_t FormatVersion = 1;
    std::wstring Policy = ImageRecipePolicy;
    std::wstring ReferenceSha256;
    std::wstring OriginalReference;
    std::wstring OriginalFileIdentity;
    std::wstring SourceId;
    std::wstring SourceConsistency;
    uint64_t CapturedFileTime = 0;
    uint32_t VirtualAddressBits = 0;
    uint64_t ImageBase = 0;
    uint32_t Rva = 0;
    uint32_t Length = 0;
    std::wstring Normalization;
    std::wstring RecordedResult;
    std::vector<ImageRecipeRead> Reads;
    // v2 retains the original single-source operation. Reads is its validated
    // parser projection, never a second acquisition or an independent record.
    ObservationReadSet ReadSet;
    ImageProcessMappings Mappings; // v3 only; snapshots do not establish mapping lifetime.
};

struct ImageRecipeCaptureOptions
{
    std::wstring TargetId;
    std::wstring AddressSpaceId;
    bool AllowResidencyChanges = false;
    IProcessMappingObserver* MappingObserver = nullptr;
    ObservationOperationBudget Budget{ImageRecipeReadBudget, ImageRecipeMaxReads, ImageRecipeMaxReads, 65536, 5000};
    image_loader::Window* LoaderWindow = nullptr;
    std::wstring* PublishedRecipeSha256 = nullptr;
};

struct ImageRecipeReplay
{
    std::wstring Schema = L"kn.image_replay.v1";
    std::wstring Status = L"unavailable";
    std::wstring Mode;
    std::wstring RecordedPolicy;
    std::wstring CurrentPolicy = ImageRecipePolicy;
    std::wstring RecipeSha256;
    std::wstring ManifestSha256;
    std::wstring CurrentResult;
    std::wstring RecordedResult;
    std::wstring Proof;
    std::wstring ClaimAssessmentJson;
    std::wstring OriginalClaimStatus = L"not_recorded";
    std::wstring ClaimPublicationSha256, RecordedClaimSha256, RecordedClaimRegistry, RecordedClaimPolicy;
    bool CaptureInterrupted = false;
};

std::wstring ImageRecipeJson(const ImageVerificationRecipe& recipe);
bool ParseImageRecipe(const std::wstring& json, ImageVerificationRecipe* recipe, std::wstring* error);
bool CaptureImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, ImageVerificationRecipe* recipe,
    std::wstring* error, const std::atomic<bool>* cancellation = nullptr);
bool CaptureObservedImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, const ImageRecipeCaptureOptions& options,
    ImageVerificationRecipe* recipe, std::wstring* error, const std::atomic<bool>* cancellation = nullptr);
// Returned only after successful original direct replay, including original
// claim reproduction. The bytes are from that same evaluated operation.
struct DirectImageReplayEvidence
{
    ImageVerificationRecipe Recipe;
    ExecutablePageResult Comparison;
    std::vector<ObservationRange> NormalizationRanges; // RVA spans with fixups or exclusions.
    bool ReferenceQualified = false;
};
// Returns the retained bytes only if every overlapping observation agrees.
bool ConsistentImageRecipeBytes(const ImageVerificationRecipe& recipe, uint64_t address, size_t length,
    std::vector<uint8_t>* bytes);
ImageRecipeReplay ReplayImageRecipe(const std::wstring& directory, bool currentReanalysis, std::wstring* error,
    DirectImageReplayEvidence* evidence = nullptr, executable_image::DiskPeMetadata* originalMetadata = nullptr);
std::wstring ImageRecipeReplayJson(const ImageRecipeReplay& replay);
std::wstring ImageRecipeReplayJson(const ImageRecipeReplay& replay, bool includeCaptureOutcome);
