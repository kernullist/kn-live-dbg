#include "GameBuildManifest.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

namespace
{
    bool Hex(const std::wstring& text, size_t length)
    {
        return text.size() == length && text.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }

    std::wstring GuidHex(const GUID& guid)
    {
        std::wstring result;
        const auto* bytes = reinterpret_cast<const uint8_t*>(&guid);
        for (size_t i = 0; i < sizeof(guid); ++i)
        {
            result.push_back(L"0123456789abcdef"[bytes[i] >> 4]);
            result.push_back(L"0123456789abcdef"[bytes[i] & 15]);
        }
        return result;
    }

    bool Within(uint64_t rva, uint64_t size, uint64_t limit)
    {
        return size != 0 && rva < limit && size <= limit - rva;
    }

    bool Executable(const GameBuildManifest& manifest, uint64_t rva, uint64_t size)
    {
        for (const auto& range : manifest.ExecutableRanges)
        {
            if (range.Contains(rva) && size <= range.Size - (rva - range.Address))
            {
                return true;
            }
        }
        return false;
    }

    bool Pointer(const ObservationReader& reader, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!reader || address > UINT64_MAX - sizeof(*value) ||
            !reader(address, sizeof(*value), &bytes) || bytes.size() != sizeof(*value))
        {
            return false;
        }
        std::memcpy(value, bytes.data(), sizeof(*value));
        return true;
    }
}

bool ValidateGameManifest(const GameBuildManifest& manifest, std::wstring* error)
{
    bool valid = false;
    do
    {
        if (!Hex(manifest.ImageSha256, 64) || !Hex(manifest.PdbSha256, 64) ||
            manifest.PdbAge == 0 || manifest.ImageSize == 0 || manifest.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            manifest.ExecutableRanges.empty() || manifest.ExecutableRanges.size() > 96 ||
            manifest.Relocations.size() > 1048576 || manifest.Objects.size() > 256 || manifest.Vptrs.size() > 1024)
        {
            break;
        }
        uint64_t end = 0;
        bool bounds = true;
        for (const auto& range : manifest.ExecutableRanges)
        {
            if (!Within(range.Address, range.Size, manifest.ImageSize) || range.Address < end)
            {
                bounds = false;
                break;
            }
            end = range.Address + range.Size;
        }
        end = 0;
        for (const auto& reloc : manifest.Relocations)
        {
            if (reloc.Width != 8 || !Within(reloc.Rva, reloc.Width, manifest.ImageSize) || reloc.Rva < end)
            {
                bounds = false;
                break;
            }
            end = static_cast<uint64_t>(reloc.Rva) + reloc.Width;
        }
        std::set<std::wstring> names;
        for (const auto& object : manifest.Objects)
        {
            if (object.Name.empty() || object.Name.size() > 128 ||
                object.Name.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != std::wstring::npos ||
                !names.insert(object.Name).second || object.Size < 8 || object.Size > 1024 * 1024 ||
                !Within(object.RootRva, object.Indirect ? 8 : object.Size, manifest.ImageSize))
            {
                bounds = false;
                break;
            }
        }
        std::set<std::pair<uint32_t, uint32_t>> vptrLocations;
        size_t slots = 0;
        for (const auto& rule : manifest.Vptrs)
        {
            slots += rule.AllowedSlots.size();
            if (rule.ObjectIndex >= manifest.Objects.size() || rule.AllowedSlots.empty() ||
                rule.AllowedSlots.size() > 1024 || slots > 16384 ||
                !Within(rule.Offset, 8, manifest.Objects[rule.ObjectIndex].Size) ||
                !Within(rule.TableRva, rule.AllowedSlots.size() * 8, manifest.ImageSize) ||
                !vptrLocations.insert({rule.ObjectIndex, rule.Offset}).second)
            {
                bounds = false;
                break;
            }
            for (const auto& range : rule.AllowedSlots)
            {
                if (!Within(range.Address, range.Size, manifest.ImageSize) || !Executable(manifest, range.Address, range.Size))
                {
                    bounds = false;
                    break;
                }
            }
        }
        valid = bounds;
    } while (false);
    if (error != nullptr)
    {
        *error = valid ? L"" : L"invalid manifest identity, bounds, ordering, limits, or vptr rules";
    }
    return valid;
}

std::wstring SerializeGameManifest(const GameBuildManifest& manifest)
{
    std::wostringstream out;
    out << L"KNDBG_GAME_MANIFEST 1\n" << std::hex;
    out << L"identity " << manifest.ImageSha256 << L' ' << manifest.PdbSha256 << L' ' << GuidHex(manifest.PdbGuid) << L' '
        << manifest.PdbAge << L' ' << manifest.ImageSize << L' ' << manifest.Machine << L'\n';
    out << L"exec " << manifest.ExecutableRanges.size() << L'\n';
    for (const auto& range : manifest.ExecutableRanges)
    {
        out << range.Address << L' ' << range.Size << L'\n';
    }
    out << L"reloc " << manifest.Relocations.size() << L'\n';
    for (const auto& relocation : manifest.Relocations)
    {
        out << relocation.Rva << L' ' << relocation.Width << L'\n';
    }
    out << L"objects " << manifest.Objects.size() << L'\n';
    for (const auto& object : manifest.Objects)
    {
        out << object.Name << L' ' << object.RootRva << L' ' << object.Size << L' ' << object.Indirect << L'\n';
    }
    out << L"vptrs " << manifest.Vptrs.size() << L'\n';
    for (const auto& vptr : manifest.Vptrs)
    {
        out << vptr.ObjectIndex << L' ' << vptr.Offset << L' ' << vptr.TableRva << L' ' << vptr.AllowedSlots.size() << L'\n';
        for (const auto& range : vptr.AllowedSlots)
        {
            out << range.Address << L' ' << range.Size << L'\n';
        }
    }
    out << L"end\n";
    return out.str();
}

bool ParseGameManifest(const std::wstring& text, GameBuildManifest* manifest, std::wstring* error)
{
    bool valid = false;
    do
    {
        if (manifest == nullptr || text.size() > 32 * 1024 * 1024 ||
            text.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ \t\r\n") != std::wstring::npos)
        {
            break;
        }
        GameBuildManifest parsed;
        std::wistringstream in(text);
        std::wstring token;
        uint32_t version = 0;
        if (!(in >> token >> version) || token != L"KNDBG_GAME_MANIFEST" || version != 1)
        {
            break;
        }
        in >> std::hex;
        std::wstring guid;
        uint32_t machine = 0;
        if (!(in >> token >> parsed.ImageSha256 >> parsed.PdbSha256 >> guid >> parsed.PdbAge >> parsed.ImageSize >> machine) ||
            token != L"identity" || !Hex(guid, 32) || machine > UINT16_MAX)
        {
            break;
        }
        parsed.Machine = static_cast<uint16_t>(machine);
        auto* guidBytes = reinterpret_cast<uint8_t*>(&parsed.PdbGuid);
        for (size_t i = 0; i < 16; ++i)
        {
            guidBytes[i] = static_cast<uint8_t>(wcstoul(guid.substr(i * 2, 2).c_str(), nullptr, 16));
        }
        size_t count = 0;
        if (!(in >> token >> count) || token != L"exec" || count > 96)
        {
            break;
        }
        parsed.ExecutableRanges.resize(count);
        for (auto& range : parsed.ExecutableRanges)
        {
            in >> range.Address >> range.Size;
        }
        if (!(in >> token >> count) || token != L"reloc" || count > 1048576)
        {
            break;
        }
        parsed.Relocations.resize(count);
        for (auto& relocation : parsed.Relocations)
        {
            in >> relocation.Rva >> relocation.Width;
        }
        if (!(in >> token >> count) || token != L"objects" || count > 256)
        {
            break;
        }
        parsed.Objects.resize(count);
        for (auto& object : parsed.Objects)
        {
            in >> object.Name >> object.RootRva >> object.Size >> object.Indirect;
        }
        if (!(in >> token >> count) || token != L"vptrs" || count > 1024)
        {
            break;
        }
        parsed.Vptrs.resize(count);
        size_t totalSlots = 0;
        for (auto& rule : parsed.Vptrs)
        {
            size_t slots = 0;
            if (!(in >> rule.ObjectIndex >> rule.Offset >> rule.TableRva >> slots) || slots > 1024 || totalSlots + slots > 16384)
            {
                in.setstate(std::ios::failbit);
                break;
            }
            totalSlots += slots;
            rule.AllowedSlots.resize(slots);
            for (auto& range : rule.AllowedSlots)
            {
                in >> range.Address >> range.Size;
            }
        }
        if (!(in >> token) || token != L"end" || !ValidateGameManifest(parsed, error))
        {
            break;
        }
        in >> std::ws;
        if (!in.eof())
        {
            break;
        }
        *manifest = std::move(parsed);
        valid = true;
    } while (false);
    if (!valid && error != nullptr)
    {
        *error = L"malformed or incompatible game manifest";
    }
    return valid;
}

bool ReadGameManifest(const std::wstring& path, GameBuildManifest* manifest, std::wstring* error)
{
    std::ifstream input(std::filesystem::path(path), std::ios::binary | std::ios::ate);
    if (!input || input.tellg() <= 0 || input.tellg() > 32 * 1024 * 1024)
    {
        if (error != nullptr)
        {
            *error = L"manifest could not be opened or exceeds 32 MiB";
        }
        return false;
    }
    std::string bytes(static_cast<size_t>(input.tellg()), '\0');
    input.seekg(0);
    input.read(bytes.data(), bytes.size());
    return input.good() && ParseGameManifest(mcpjson::Utf8ToWide(bytes), manifest, error);
}

bool MatchGameManifest(const GameBuildManifest& manifest, const std::wstring& image,
    const executable_image::DiskPeMetadata& metadata, std::wstring* error)
{
    bool match = ValidateGameManifest(manifest, error) && metadata.HasPdbIdentity &&
        metadata.SizeOfImage == manifest.ImageSize && metadata.Machine == manifest.Machine &&
        metadata.PdbAge == manifest.PdbAge && std::memcmp(&metadata.PdbGuid, &manifest.PdbGuid, sizeof(GUID)) == 0 &&
        metadata.BaseRelocationTableComplete && metadata.DynamicRelocationTableComplete &&
        metadata.BaseRelocations.size() == manifest.Relocations.size();
    std::vector<ObservationRange> ranges;
    for (const auto& section : metadata.Sections)
    {
        if (section.Executable)
        {
            ranges.push_back({section.VirtualAddress, (std::max)(section.VirtualSize, section.SizeOfRawData)});
        }
    }
    match = match && ranges.size() == manifest.ExecutableRanges.size();
    if (match)
    {
        for (size_t i = 0; i < ranges.size(); ++i)
        {
            match = match && ranges[i].Address == manifest.ExecutableRanges[i].Address && ranges[i].Size == manifest.ExecutableRanges[i].Size;
        }
        for (size_t i = 0; i < metadata.BaseRelocations.size(); ++i)
        {
            match = match && metadata.BaseRelocations[i].Rva == manifest.Relocations[i].Rva &&
                metadata.BaseRelocations[i].Width == manifest.Relocations[i].Width;
        }
    }
    match = match && ContentHash::File(image) == manifest.ImageSha256;
    if (!match && error != nullptr)
    {
        *error = L"image SHA256, PDB identity, executable ranges or relocation set does not match manifest";
    }
    return match;
}

std::vector<GameObjectObservation> VerifyGameObjects(const GameBuildManifest& manifest,
    uint64_t imageBase, const ObservationReader& reader, size_t budget, size_t* cursor)
{
    std::vector<GameObjectObservation> result;
    if (cursor == nullptr || manifest.Vptrs.empty() || imageBase > UINT64_MAX - manifest.ImageSize)
    {
        return result;
    }
    const size_t start = *cursor % manifest.Vptrs.size();
    for (size_t n = 0; n < (std::min)(budget, manifest.Vptrs.size()); ++n)
    {
        const size_t index = (start + n) % manifest.Vptrs.size();
        const auto& rule = manifest.Vptrs[index];
        if (rule.ObjectIndex >= manifest.Objects.size() || rule.AllowedSlots.size() > 1024)
        {
            break;
        }
        const auto& object = manifest.Objects[rule.ObjectIndex];
        if (!Within(rule.Offset, 8, object.Size) || !Within(object.RootRva, object.Indirect ? 8 : object.Size, manifest.ImageSize))
        {
            break;
        }
        GameObjectObservation observation;
        observation.IsVptr = true;
        observation.RuleIndex = static_cast<uint32_t>(index);
        observation.ObjectAddress = imageBase + object.RootRva;
        uint64_t rootBefore = observation.ObjectAddress;
        uint64_t vptr = 0;
        if ((object.Indirect && !Pointer(reader, imageBase + object.RootRva, &rootBefore)) ||
            rootBefore < 0x10000 || rootBefore >= 0x0000800000000000ull || rootBefore > UINT64_MAX - object.Size)
        {
            observation.Reason = L"object_root_unavailable";
            result.push_back(observation);
            continue;
        }
        observation.ObjectAddress = rootBefore;
        observation.SlotAddress = rootBefore + rule.Offset;
        if (!Pointer(reader, observation.SlotAddress, &vptr))
        {
            observation.Reason = L"vptr_unreadable";
            result.push_back(observation);
            continue;
        }
        observation.Readable = true;
        observation.Target = vptr;
        observation.Modified = vptr != imageBase + rule.TableRva;
        observation.Reason = observation.Modified ? L"vptr_differs_from_exact_build" : L"vptr_matches";
        const size_t groupStart = result.size();
        result.push_back(observation);
        if (vptr >= 0x10000 && vptr < 0x0000800000000000ull && vptr <= UINT64_MAX - rule.AllowedSlots.size() * 8)
        {
            for (size_t slot = 0; slot < rule.AllowedSlots.size(); ++slot)
            {
                auto entry = observation;
                entry.IsVptr = false;
                entry.SlotIndex = static_cast<uint32_t>(slot);
                entry.SlotAddress = vptr + slot * 8;
                entry.Target = 0;
                entry.Readable = Pointer(reader, entry.SlotAddress, &entry.Target);
                entry.Modified = entry.Readable && (entry.Target < imageBase ||
                    !rule.AllowedSlots[slot].Contains(entry.Target - imageBase));
                entry.Reason = !entry.Readable ? L"slot_unreadable" : (entry.Modified ? L"slot_outside_allowed_implementation" : L"slot_allowed");
                result.push_back(entry);
            }
        }
        uint64_t rootAfter = rootBefore;
        uint64_t vptrAfter = 0;
        const bool stable = (!object.Indirect || (Pointer(reader, imageBase + object.RootRva, &rootAfter) && rootAfter == rootBefore)) &&
            Pointer(reader, rootBefore + rule.Offset, &vptrAfter) && vptrAfter == vptr;
        if (!stable)
        {
            for (size_t i = groupStart; i < result.size(); ++i)
            {
                result[i].Modified = false;
                result[i].Readable = false;
                result[i].Reason = L"object_or_vptr_changed_during_read";
            }
        }
    }
    *cursor = (start + (std::min)(budget, manifest.Vptrs.size())) % manifest.Vptrs.size();
    return result;
}

bool GameBuildManifestSelfTest()
{
    GameBuildManifest manifest;
    manifest.ImageSha256 = std::wstring(64, L'a');
    manifest.PdbSha256 = std::wstring(64, L'b');
    manifest.PdbAge = 1;
    manifest.Machine = IMAGE_FILE_MACHINE_AMD64;
    manifest.ImageSize = 0x5000;
    manifest.ExecutableRanges.push_back({0x1000, 0x1000});
    manifest.Objects.push_back({L"object", 0x3000, 0x40, false});
    manifest.Vptrs.push_back({0, 0x20, 0x4000, {{0x1100, 0x40}}});
    GameBuildManifest copy;
    const auto text = SerializeGameManifest(manifest);
    bool ok = ParseGameManifest(text, &copy, nullptr) && copy.Vptrs[0].Offset == 0x20 &&
        !ParseGameManifest(text + L"extra", &copy, nullptr) &&
        !ParseGameManifest(text.substr(0, text.size() - 5), &copy, nullptr);
    auto invalid = manifest;
    invalid.Vptrs[0].ObjectIndex = 1;
    ok = ok && !ValidateGameManifest(invalid, nullptr);
    invalid = manifest;
    invalid.Vptrs[0].Offset = 0x3c;
    ok = ok && !ValidateGameManifest(invalid, nullptr);
    invalid = manifest;
    invalid.Vptrs[0].AllowedSlots[0] = {0x1100, UINT64_MAX};
    ok = ok && !ValidateGameManifest(invalid, nullptr);
    const uint64_t base = 0x140000000ull;
    std::map<uint64_t, uint64_t> memory = {{base + 0x3020, base + 0x4000}, {base + 0x4000, base + 0x1100}};
    const ObservationReader reader = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
    {
        const auto it = memory.find(address);
        if (count != 8 || it == memory.end())
        {
            return false;
        }
        bytes->resize(8);
        std::memcpy(bytes->data(), &it->second, 8);
        return true;
    };
    size_t cursor = 0;
    auto result = VerifyGameObjects(manifest, base, reader, 1, &cursor);
    ok = ok && result.size() == 2 && result.back().Readable && !result.back().Modified;
    memory[base + 0x4000] = base + 0x1800;
    result = VerifyGameObjects(manifest, base, reader, 1, &cursor);
    ok = ok && result.back().Modified;
    memory.erase(base + 0x3020);
    result = VerifyGameObjects(manifest, base, reader, 1, &cursor);
    return ok && !result.front().Readable && !result.front().Modified;
}
