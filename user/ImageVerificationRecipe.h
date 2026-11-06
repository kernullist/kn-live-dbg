#pragma once

#include "ExecutableImageVerifier.h"
#include "ObservationSource.h"
#include "RecordingObservationSource.h"

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
};

struct ImageRecipeCaptureOptions
{
    std::wstring TargetId;
    std::wstring AddressSpaceId;
    bool AllowResidencyChanges = false;
    ObservationOperationBudget Budget{ImageRecipeReadBudget, ImageRecipeMaxReads, ImageRecipeMaxReads, 65536, 5000};
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
};

std::wstring ImageRecipeJson(const ImageVerificationRecipe& recipe);
bool ParseImageRecipe(const std::wstring& json, ImageVerificationRecipe* recipe, std::wstring* error);
bool CaptureImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, ImageVerificationRecipe* recipe,
    std::wstring* error, const std::atomic<bool>* cancellation = nullptr);
bool CaptureObservedImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, const ImageRecipeCaptureOptions& options,
    ImageVerificationRecipe* recipe, std::wstring* error, const std::atomic<bool>* cancellation = nullptr);
ImageRecipeReplay ReplayImageRecipe(const std::wstring& directory, bool currentReanalysis, std::wstring* error);
std::wstring ImageRecipeReplayJson(const ImageRecipeReplay& replay);
