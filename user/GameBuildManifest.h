#pragma once

#include "ExecutableImageVerifier.h"
#include "../shared/KnGameObjectLifetime.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct GameObjectLifetimeRule
{
    uint32_t SlotRva = 0;
    uint64_t ContainerId = 0;
};

struct GameObjectRule
{
    std::wstring Name;
    uint32_t RootRva = 0;
    uint32_t Size = 0;
    bool Indirect = false;
    std::optional<GameObjectLifetimeRule> Lifetime;
};

struct GameVptrRule
{
    uint32_t ObjectIndex = 0;
    uint32_t Offset = 0;
    uint32_t TableRva = 0;
    std::vector<ObservationRange> AllowedSlots;
    std::wstring SubobjectType;
    uint32_t SubobjectSize = 0;
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
    std::wstring FileSha256; // Exact input bytes when read from disk.
};

struct GameObjectLifetimeSample
{
    std::optional<uint64_t> BeginSequence;
    std::optional<KnGameObjectSlotV1> Record;
    std::optional<uint64_t> EndSequence;
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
    std::wstring LifetimeStatus = L"not_declared";
    GameObjectLifetimeSample Before, After;
    uint64_t ObserverBeginUptimeMs = 0, ObserverEndUptimeMs = 0;
};

bool ValidateGameManifest(const GameBuildManifest& manifest, std::wstring* error);
std::wstring SerializeGameManifest(const GameBuildManifest& manifest);
bool ParseGameManifest(const std::wstring& text, GameBuildManifest* manifest, std::wstring* error);
bool ReadGameManifestInput(const std::wstring& path, size_t limit, std::string& bytes);
bool ReadGameManifest(const std::wstring& path, GameBuildManifest* manifest, std::wstring* error);
bool MatchGameManifest(const GameBuildManifest& manifest, const std::wstring& image,
    const executable_image::DiskPeMetadata& metadata, std::wstring* error);
std::vector<GameObjectObservation> VerifyGameObjects(const GameBuildManifest& manifest,
    uint64_t imageBase, const ObservationReader& reader, size_t budget, size_t* cursor);
std::map<std::wstring, std::wstring> GameObjectLifetimeEvidence(const GameObjectRule& object,
    const GameVptrRule& rule, const GameObjectObservation& observation);
bool GenerateGameManifest(const std::wstring& image, const std::wstring& pdb,
    const std::wstring& layout, const std::wstring& output, std::wstring* error);
int RunGameManifestCommand(int argc, wchar_t** argv);
bool GameBuildManifestSelfTest();
bool KmonGameObjectPublicationSelfTest(std::wstring& error);
