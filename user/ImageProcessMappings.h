#pragma once

#include "ProcessMappingObservation.h"

struct ImageVerificationRecipe;
inline constexpr const wchar_t* ImageProcessMappingPolicy = L"kn.process_image_mapping.observed.v1";

std::wstring ImageProcessMappingsJson(const ImageProcessMappings& mappings);
bool ParseImageProcessMappings(const std::wstring& json, ImageProcessMappings* mappings);
bool ValidImageProcessMappings(const ImageVerificationRecipe& recipe);

struct ImageProcessMappingAssessment
{
    std::wstring Status = L"unavailable";
    uint64_t Observations = 0, Queries = 0, FailedObservations = 0, UncommittedQueries = 0;
    uint64_t RequestedBytes = 0, ObservedBytes = 0, ComparedPairs = 0, ConflictingPairs = 0;
    bool NativeImageMappingObserved = false;
};
ImageProcessMappingAssessment AssessImageProcessMappings(const ImageVerificationRecipe& recipe);
std::wstring ImageProcessMappingAssessmentJson(const ImageProcessMappingAssessment& assessment);
