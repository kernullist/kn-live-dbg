#pragma once

#include "ImageSweepManifest.h"
#include "ExecutableImageVerifier.h"

struct ImageSweepReplayedSlice
{
    ImageSweepSlice Publication;
    std::wstring Policy;
    bool TargetReferenceQualified = false;
    std::vector<ExecutablePageResult> Pages;
};

// Projection of a successful replay, not a second acquisition or a stored verdict.
struct ImageSweepReplayEvidence
{
    ImageSweepManifest Manifest;
    std::wstring ManifestSha256, ReferenceSha256;
    std::vector<ImageSweepReplayedSlice> Slices;
};
