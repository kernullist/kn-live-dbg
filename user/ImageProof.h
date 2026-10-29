#pragma once

#include "ImageVerificationRecipe.h"

struct ImageProofClaim
{
    std::wstring Name;
    std::wstring Status = L"not_established";
    std::vector<ObservationRange> Ranges;
    std::vector<std::wstring> Supports;
    std::vector<std::wstring> Contradicts;
    std::vector<std::wstring> UnfulfilledRequirements;
    std::vector<std::wstring> NextBestObservation;
};

struct ImageProofAssessment
{
    bool InputConsistent = false;
    bool AddressAccountingValid = false;
    bool ReferenceQualified = false;
    bool CurrentReanalysis = false;
    uint64_t RequestedBytes = 0;
    uint64_t ComparedBytes = 0;
    uint64_t SkippedBytes = 0;
    uint64_t FailedBytes = 0;
    uint64_t UnvisitedBytes = 0;
    uint64_t RequestedReadBytes = 0;
    uint64_t RetainedReadBytes = 0;
    uint64_t UniqueTargetBytesRetained = 0;
    uint64_t FirstAcquisitionTick = 0;
    uint64_t LastAcquisitionTick = 0;
    std::vector<size_t> SupportingReadIndices;
    std::vector<ObservationRange> ChangedRanges;
    ImageProofClaim Matches;
    ImageProofClaim Differs;
};

// The caller must first verify the retained artifact and complete the selected replay.
// The assessment consumes a freshly computed typed comparison, never a stored verdict.
ImageProofAssessment AssessImageProof(const ImageVerificationRecipe& recipe,
    const ExecutablePageResult& comparison, bool referenceQualified, bool currentReanalysis);
std::wstring ImageProofJson(const ImageVerificationRecipe& recipe, const ImageProofAssessment& proof);
