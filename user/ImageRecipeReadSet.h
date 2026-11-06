#pragma once

#include "ImageVerificationRecipe.h"

// Admission for the v2 single-source, ordered, completed operation format.
// Pending, abandoned, unrecorded, overrun, or fallback operations are not
// executable recipes. A generic read-set viewer may still retain those facts.
bool ValidImageRecipeReadSet(const ImageVerificationRecipe& recipe);
bool ParseImageRecipeReadSet(const std::wstring& json, ImageVerificationRecipe* recipe);
