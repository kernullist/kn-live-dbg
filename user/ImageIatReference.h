#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct DirectImageReplayEvidence;
struct ImageRecipeReplay;
class ReferenceArtifact;
namespace executable_image { struct DiskPeMetadata; }

struct ImageIatDeclaration
{
    uint32_t InstructionRva = 0, SlotRva = 0, DescriptorRva = 0, LookupRva = 0;
    std::wstring Module, Name;
    bool ByOrdinal = false;
    uint16_t Ordinal = 0;
    std::vector<uint8_t> Instruction;
};

// Confirm the original instruction through the caller's source before accepting
// the declared import. A returned diagnostic leaves the declaration empty.
using ImageIatInstructionCheck = std::function<const wchar_t*(uint32_t, const std::vector<uint8_t>&)>;
const wchar_t* InspectImageIatDeclaration(const std::wstring& exportName, const executable_image::DiskPeMetadata& pe,
    const std::vector<uint8_t>& reference, const ImageIatInstructionCheck& check, ImageIatDeclaration& declaration);

// A named export supplies the instruction boundary. All inputs belong to the
// same reproduced original capture and its leased reference PE.
std::wstring ImageIatReferenceJson(const std::wstring& exportName, const DirectImageReplayEvidence& evidence,
    const ImageRecipeReplay& replay, const executable_image::DiskPeMetadata& pe, const ReferenceArtifact& reference,
    const std::wstring& claimFileSha256);
