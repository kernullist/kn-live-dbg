#pragma once

#include "ExecutableImageVerifier.h"

#include <cstdint>
#include <string>
#include <vector>

struct GameObjectRule
{
    std::wstring Name;
    uint32_t RootRva = 0;
    uint32_t Size = 0;
    bool Indirect = false;
};

struct GameVptrRule
{
    uint32_t ObjectIndex = 0;
    uint32_t Offset = 0;
    uint32_t TableRva = 0;
    std::vector<ObservationRange> AllowedSlots;
};

struct GameBuildManifest
{
    std::wstring ImageSha256;
    std::wstring PdbSha256;
    GUID PdbGuid = {};
    uint32_t PdbAge = 0;
    uint32_t ImageSize = 0;
    uint16_t Machine = 0;
    std::vector<ObservationRange> ExecutableRanges;
    std::vector<executable_image::DiskPeBaseRelocation> Relocations;
    std::vector<GameObjectRule> Objects;
    std::vector<GameVptrRule> Vptrs;
};

struct GameObjectObservation
{
    uint32_t RuleIndex = 0;
    uint32_t SlotIndex = 0;
    uint64_t ObjectAddress = 0;
    uint64_t SlotAddress = 0;
    uint64_t Target = 0;
    bool IsVptr = false;
    bool Modified = false;
    bool Readable = false;
    std::wstring Reason;
};

bool ValidateGameManifest(const GameBuildManifest& manifest, std::wstring* error);
std::wstring SerializeGameManifest(const GameBuildManifest& manifest);
bool ParseGameManifest(const std::wstring& text, GameBuildManifest* manifest, std::wstring* error);
bool ReadGameManifest(const std::wstring& path, GameBuildManifest* manifest, std::wstring* error);
bool MatchGameManifest(const GameBuildManifest& manifest, const std::wstring& image,
    const executable_image::DiskPeMetadata& metadata, std::wstring* error);
std::vector<GameObjectObservation> VerifyGameObjects(const GameBuildManifest& manifest,
    uint64_t imageBase, const ObservationReader& reader, size_t budget, size_t* cursor);
bool GenerateGameManifest(const std::wstring& image, const std::wstring& pdb,
    const std::wstring& layout, const std::wstring& output, std::wstring* error);
int RunGameManifestCommand(int argc, wchar_t** argv);
bool GameBuildManifestSelfTest();
