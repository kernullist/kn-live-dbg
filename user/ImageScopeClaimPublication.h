#pragma once

#include "ImageVerificationRecipe.h"

inline constexpr const wchar_t* ImageScopeClaimPublicationSchema = L"kn.image_scope_claim_publication.v1";
// Shares the existing per-file and collection budgets; the complete root must fit.
inline constexpr size_t ImageScopeClaimPublicationMaxBytes = ImageRecipeMaxBytes;

struct ImageScopeClaimPublication
{
    std::wstring ArtifactJson, ReportJson, Sha256, ReportSha256, Registry, Policy;
    bool Sweep = false;
};

std::wstring ImageScopeClaimPublicationJson(const std::wstring& artifact, const std::wstring& report);
bool ParseImageScopeClaimPublication(const std::wstring& json, ImageScopeClaimPublication* publication);
// Unwrap only this schema. Legacy inputs are unchanged; malformed publications fail.
bool UnwrapImageScopeClaimPublication(std::wstring* json, ImageScopeClaimPublication* publication);
// Called only after original comparison replay. Failure clears all derived proof.
bool ReproduceImageScopeClaim(const ImageScopeClaimPublication& publication, ImageRecipeReplay* replay);
