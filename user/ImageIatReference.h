#pragma once
#include <string>

struct DirectImageReplayEvidence;
struct ImageRecipeReplay;
class ReferenceArtifact;
namespace executable_image { struct DiskPeMetadata; }

// A named export supplies the instruction boundary. All inputs belong to the
// same reproduced original capture and its leased reference PE.
std::wstring ImageIatReferenceJson(const std::wstring& exportName, const DirectImageReplayEvidence& evidence,
    const ImageRecipeReplay& replay, const executable_image::DiskPeMetadata& pe, const ReferenceArtifact& reference,
    const std::wstring& claimFileSha256);
