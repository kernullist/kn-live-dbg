#pragma once

#include "ExecutableImageVerifier.h"

std::wstring ImageComparisonResultJson(const ExecutablePageResult& result, bool referenceQualified);
std::wstring ImageComparisonNormalizationJson(const executable_image::DiskPeMetadata& metadata,
    uint64_t relocationBase, uint32_t rva, uint32_t length, bool secondary = false);
