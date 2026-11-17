#pragma once

#include "ImageVerificationRecipe.h"

inline constexpr size_t ImageClaimPublicationMaxBytes = 4 * 1024 * 1024;
inline constexpr const wchar_t* ImageClaimPublicationSchema = L"kn.image_claim_publication.v1";

// The final root embeds the unchanged v1/v2 recipe and the report evaluated at
// publication time. Its checksum binds both; it is not collector authentication.
struct ImageClaimPublication
{
    ImageVerificationRecipe Recipe;
    std::wstring RecipeJson, ReportJson, Sha256, ReportSha256, Registry, Policy;
};

std::wstring ImageClaimPublicationJson(const std::wstring& recipe, const std::wstring& report);
bool ParseImageClaimPublication(const std::wstring& json, ImageClaimPublication* publication, std::wstring* error);
