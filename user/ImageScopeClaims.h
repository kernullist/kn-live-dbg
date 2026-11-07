#pragma once

#include "ImageSliceRecipe.h"
#include "ImageSweepManifest.h"

// Derived only from verified original-policy replay. No imported claim parser.
struct ImageSliceClaimEvidence
{
    std::wstring RecipeSha256, ReferenceSha256, Policy, TargetId, AddressSpaceId;
    uint64_t ImageBase = 0, RelocationBase = 0, StartedTick = 0, EndedTick = 0;
    uint32_t StartRange = 0, RangeCount = 0;
    bool Valid = false, IdentityQualified = false, FullMatch = false, Secondary = false;
    uint64_t Requested = 0, Compared = 0, Skipped = 0, Failed = 0, Unvisited = 0;
    uint64_t TargetTraffic = 0, SecondaryTraffic = 0, TargetStored = 0, SecondaryStored = 0;
    uint64_t StableDifferenceBytes = 0, StableDifferenceRanges = 0;
    ObservationRange FirstDifference;
    size_t DifferencePage = 0;
    std::vector<size_t> WitnessParserReads;
    std::vector<uint64_t> WitnessReceipts;
};

inline constexpr size_t ImageScopeClaimMaximumCharacters = 2 * 1024 * 1024;
ImageSliceClaimEvidence AssessImageSliceClaims(const ImageSliceRecipe& recipe,
    const std::vector<ExecutablePageResult>& pages, const std::wstring& digest);
std::wstring ImageSliceClaimAssessmentJson(const ImageSliceClaimEvidence& slice) noexcept;
// Every child must have been replayed and its digest matched to this manifest.
// Manifest membership binds recorded observations, never a mapping lifetime.
std::wstring ImageSweepClaimAssessmentJson(const ImageSweepManifest& manifest,
    const std::wstring& digest, const std::vector<ImageSliceClaimEvidence>& slices) noexcept;
