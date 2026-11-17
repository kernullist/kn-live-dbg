#pragma once

#include "ImageVerificationRecipe.h"

inline constexpr const wchar_t* ImageSliceDirectPolicy = L"kn.executable_slice.direct.v1";
inline constexpr const wchar_t* ImageSliceSecondaryPolicy = L"kn.executable_slice.secondary.v1";

struct ImageSliceRecipe
{
    std::wstring Policy;
    std::wstring ReferenceSha256;
    std::wstring OriginalReference;
    std::wstring OriginalFileIdentity;
    uint64_t CapturedFileTime = 0;
    uint64_t ImageBase = 0;
    ExecutableSliceTrace Slice;
    ObservationRoutedReadSet TargetReads;
    std::wstring Normalization;
    std::wstring RecordedResult;
};

std::wstring ImageSliceRecipeJson(const ImageSliceRecipe& recipe);
std::wstring ImageSliceInputsJson(const ExecutableSliceTrace& slice);
bool ParseImageSliceRecipe(const std::wstring& json, ImageSliceRecipe* recipe);
std::wstring CaptureImageSliceRecipeJson(const executable_image::DiskPeMetadata& metadata, uint64_t imageBase,
    const ExecutableSweepReference& reference, const ExecutableSliceTrace& slice,
    const ObservationRoutedReadSet& reads, const std::vector<ExecutablePageResult>& pages);
// Evaluate only retained reads against the published reference, before the final root write.
std::wstring CaptureImageSliceClaimPublicationJson(const std::wstring& recipeJson,
    const std::wstring& referencePath, std::wstring* error);
// Optional typed results are populated only after all original inputs and results agree.
struct ImageSliceClaimEvidence;
struct ImageScopeReplayPaths;
struct ImageSliceReplayContext
{
    std::wstring ReferenceSha256;
    uint64_t ImageBase = 0, CapturedFileTime = 0;
    bool Valid = false, IdentityQualified = false, TargetIdentityFencePassed = false;
    std::vector<ObservationRange> NormalizationRanges; // RVA spans, from verified PE metadata.
};
ImageRecipeReplay ReplayImageSliceRecipe(const std::wstring& path, std::wstring* error,
    std::vector<ExecutablePageResult>* verifiedPages = nullptr, ImageSliceClaimEvidence* verifiedClaims = nullptr,
    ImageSliceReplayContext* verifiedContext = nullptr, const ImageScopeReplayPaths* retainedInputs = nullptr);
