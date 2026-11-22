#include "GameBuildManifest.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <memory>
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

    bool TypeName(const std::wstring& name)
    {
        if (name.empty() || name.size() > 128) { return false; }
        const auto letter = [](wchar_t c) { return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || c == L'_'; };
        bool first = true;
        for (size_t i = 0; i < name.size(); ++i)
        {
            const auto c = name[i];
            if (!first && c == L':' && i + 1 < name.size() && name[i+1] == L':') { ++i; first = true; continue; }
            if (!letter(c) && (first || c < L'0' || c > L'9')) { return false; }
            first = false;
        }
        return !first;
    }

    bool ValidLifetimeSlot(const GameBuildManifest& manifest, size_t index)
    {
        const auto& slot = *manifest.Objects[index].Lifetime;
        if (!slot.ContainerId || slot.SlotRva % alignof(KnGameObjectSlotV1) ||
            !Within(slot.SlotRva, sizeof(KnGameObjectSlotV1), manifest.ImageSize)) { return false; }
        const uint64_t end = static_cast<uint64_t>(slot.SlotRva) + sizeof(KnGameObjectSlotV1);
        const auto overlaps = [&](uint64_t rva, uint64_t size) { return rva < end && slot.SlotRva < rva + size; };
        for (size_t i = 0; i < manifest.Objects.size(); ++i)
        {
            const auto& object = manifest.Objects[i];
            if (overlaps(object.RootRva, object.Indirect ? 8 : object.Size) ||
                (i != index && object.Lifetime && overlaps(object.Lifetime->SlotRva, sizeof(KnGameObjectSlotV1)))) { return false; }
        }
        for (const auto& range : manifest.ExecutableRanges)
        {
            if (overlaps(range.Address, range.Size)) { return false; }
        }
        bool hasVptr = false;
        for (const auto& rule : manifest.Vptrs)
        {
            if (overlaps(rule.TableRva, rule.AllowedSlots.size() * uint64_t{8})) { return false; }
            hasVptr |= rule.ObjectIndex == index;
        }
        return hasVptr;
    }

    bool UserExtent(uint64_t address, uint64_t size)
    {
        return address >= 0x10000 && Within(address, size, 0x0000800000000000ull);
    }

    bool Pointer(const ObservationReader& reader, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!reader || !UserExtent(address, sizeof(*value)) ||
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
            const auto& object = manifest.Objects[rule.ObjectIndex];
            if (object.Lifetime ? (!TypeName(rule.SubobjectType) || rule.Offset % 8 || rule.SubobjectSize < 8 ||
                !Within(rule.Offset, rule.SubobjectSize, object.Size)) : (!rule.SubobjectType.empty() || rule.SubobjectSize != 0))
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
        for (size_t i = 0; bounds && i < manifest.Objects.size(); ++i)
        {
            if (manifest.Objects[i].Lifetime) { bounds = ValidLifetimeSlot(manifest, i); }
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
    const auto lifetimeCount = std::count_if(manifest.Objects.begin(), manifest.Objects.end(),
        [](const auto& object) { return object.Lifetime.has_value(); });
    out << L"KNDBG_GAME_MANIFEST " << (lifetimeCount ? 2 : 1) << L'\n' << std::hex;
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
    if (lifetimeCount)
    {
        out << L"lifetimes " << lifetimeCount << L'\n';
        for (size_t i = 0; i < manifest.Objects.size(); ++i)
        {
            const auto& slot = manifest.Objects[i].Lifetime;
            if (slot) { out << i << L' ' << slot->SlotRva << L' ' << slot->ContainerId << L'\n'; }
        }
        const auto count = std::count_if(manifest.Vptrs.begin(), manifest.Vptrs.end(),
            [](const auto& rule) { return !rule.SubobjectType.empty(); });
        out << L"subobjects " << count << L'\n';
        for (size_t i = 0; i < manifest.Vptrs.size(); ++i)
        {
            const auto& rule = manifest.Vptrs[i];
            if (!rule.SubobjectType.empty()) { out << i << L' ' << rule.SubobjectType << L' ' << rule.SubobjectSize << L'\n'; }
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
            text.find_first_not_of(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_: \t\r\n") != std::wstring::npos)
        {
            break;
        }
        GameBuildManifest parsed;
        std::wistringstream in(text);
        std::wstring token;
        uint32_t version = 0;
        if (!(in >> token >> version) || token != L"KNDBG_GAME_MANIFEST" || (version != 1 && version != 2))
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
        if (version == 2)
        {
            if (!(in >> token >> count) || token != L"lifetimes" || !count || count > parsed.Objects.size()) { break; }
            for (size_t i = 0; i < count; ++i)
            {
                size_t index = 0;
                GameObjectLifetimeRule slot;
                if (!(in >> index >> slot.SlotRva >> slot.ContainerId) || index >= parsed.Objects.size() || parsed.Objects[index].Lifetime)
                { in.setstate(std::ios::failbit); break; }
                parsed.Objects[index].Lifetime = slot;
            }
            if (!(in >> token >> count) || token != L"subobjects" || !count || count > parsed.Vptrs.size()) { break; }
            for (size_t i = 0; i < count; ++i)
            {
                size_t index = 0;
                if (!(in >> index) || index >= parsed.Vptrs.size() || !parsed.Vptrs[index].SubobjectType.empty())
                { in.setstate(std::ios::failbit); break; }
                in >> parsed.Vptrs[index].SubobjectType >> parsed.Vptrs[index].SubobjectSize;
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

bool ReadGameManifestInput(const std::wstring& path, size_t limit, std::string& bytes)
{
    const HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    const std::unique_ptr<void, decltype(&CloseHandle)> file(raw == INVALID_HANDLE_VALUE ? nullptr : raw, &CloseHandle);
    LARGE_INTEGER length{};
    if (!file || GetFileType(raw) != FILE_TYPE_DISK || !GetFileSizeEx(raw, &length) || length.QuadPart <= 0 ||
        static_cast<uint64_t>(length.QuadPart) > limit || length.QuadPart > 32 * 1024 * 1024) { return false; }
    std::string content(static_cast<size_t>(length.QuadPart), '\0');
    size_t at = 0;
    while (at < content.size())
    {
        DWORD read = 0;
        if (!ReadFile(raw, content.data() + at, static_cast<DWORD>(content.size() - at), &read, nullptr) || !read) { return false; }
        at += read;
    }
    bytes = std::move(content);
    return true;
}

bool ReadGameManifest(const std::wstring& path, GameBuildManifest* manifest, std::wstring* error)
{
    std::string bytes;
    if (!manifest || !ReadGameManifestInput(path, 32 * 1024 * 1024, bytes))
    {
        if (error) { *error = L"manifest requires a stable, nonempty input file of at most 32 MiB"; }
        return false;
    }
    GameBuildManifest parsed;
    ContentHash digest;
    if (!ParseGameManifest(mcpjson::Utf8ToWide(bytes), &parsed, error) ||
        !digest.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) || (parsed.FileSha256 = digest.Finish()).empty()) { return false; }
    *manifest = std::move(parsed);
    return true;
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
    for (const auto& object : manifest.Objects)
    {
        if (!match || !object.Lifetime) { continue; }
        const auto rva = object.Lifetime->SlotRva;
        match = std::count_if(metadata.Sections.begin(), metadata.Sections.end(), [&](const auto& section) {
            return section.Writable && !section.Executable && (section.Characteristics & IMAGE_SCN_MEM_READ) &&
                rva >= section.VirtualAddress && Within(rva - section.VirtualAddress, sizeof(KnGameObjectSlotV1), section.VirtualSize);
        }) == 1;
    }
    match = match && ContentHash::File(image) == manifest.ImageSha256;
    if (!match && error != nullptr)
    {
        *error = L"image SHA256, PDB identity, executable ranges or relocation set does not match manifest";
    }
    return match;
}

namespace
{
    const wchar_t* ReadPublication(const ObservationReader& reader, uint64_t address, GameObjectLifetimeSample& sample)
    {
        uint64_t sequence = 0;
        if (!UserExtent(address, sizeof(KnGameObjectSlotV1)) || !Pointer(reader, address, &sequence)) { return L"lifetime_unreadable"; }
        sample.BeginSequence = sequence;
        if (!sequence) { return L"lifetime_unpublished"; }
        if (sequence & 1) { return L"lifetime_updating"; }
        std::vector<uint8_t> bytes;
        if (!reader(address, sizeof(KnGameObjectSlotV1), &bytes) || bytes.size() != sizeof(KnGameObjectSlotV1)) { return L"lifetime_unreadable"; }
        auto& record = sample.Record.emplace();
        std::memcpy(&record, bytes.data(), sizeof(record));
        if (!Pointer(reader, address, &sequence)) { return L"lifetime_unreadable"; }
        sample.EndSequence = sequence;
        return (sequence != *sample.BeginSequence || sequence != record.Sequence) ? L"lifetime_changed_during_read" : nullptr;
    }

    const wchar_t* ActiveMember(const KnGameObjectSlotV1& slot, const GameObjectLifetimeRule& rule)
    {
        if (slot.ContainerId != rule.ContainerId) { return L"lifetime_wrong_container"; }
        switch (static_cast<KnGameObjectPhase>(slot.Phase))
        {
        case KnGameObjectPhase::Vacant: return L"lifetime_vacant";
        case KnGameObjectPhase::Constructing: return L"lifetime_constructing";
        case KnGameObjectPhase::Destroying: return L"lifetime_destroying";
        case KnGameObjectPhase::Collecting: return L"lifetime_collecting";
        case KnGameObjectPhase::Live: break;
        default: return L"lifetime_phase_unknown";
        }
        if (!slot.Generation) { return L"lifetime_generation_unknown"; }
        return UserExtent(slot.MemberAddress, 8) ? nullptr : L"lifetime_member_unavailable";
    }

    void InspectObject(const GameObjectRule& object, const GameVptrRule& rule, uint64_t imageBase,
        const ObservationReader& reader, const KnGameObjectSlotV1* member, GameObjectObservation observation,
        std::vector<GameObjectObservation>& result)
    {
        const uint64_t rootSlot = imageBase + object.RootRva;
        uint64_t root = rootSlot;
        if ((object.Indirect && !Pointer(reader, rootSlot, &root)) || !UserExtent(root, object.Size))
        {
            observation.Reason = L"object_root_unavailable";
            if (member) { observation.LifetimeStatus = L"lifetime_root_unconfirmed"; }
            result.push_back(std::move(observation));
            return;
        }
        observation.ObjectAddress = root;
        if (member && root != member->MemberAddress)
        {
            observation.Reason = observation.LifetimeStatus = L"lifetime_member_mismatch";
            result.push_back(std::move(observation));
            return;
        }
        observation.SlotAddress = root + rule.Offset;
        uint64_t vptr = 0;
        if (!Pointer(reader, observation.SlotAddress, &vptr))
        {
            observation.Reason = L"vptr_unreadable";
            if (member) { observation.LifetimeStatus = L"lifetime_root_unconfirmed"; }
            result.push_back(std::move(observation));
            return;
        }

        if (member) { observation.LifetimeStatus = L"reported_active_member"; }
        observation.Readable = true;
        observation.Target = vptr;
        observation.Modified = vptr != imageBase + rule.TableRva;
        observation.Reason = observation.Modified ? L"vptr_differs_from_exact_build" : L"vptr_matches";
        const size_t group = result.size();
        result.push_back(observation);
        if (UserExtent(vptr, rule.AllowedSlots.size() * uint64_t{8}))
        {
            for (size_t i = 0; i < rule.AllowedSlots.size(); ++i)
            {
                auto row = observation;
                row.IsVptr = false;
                row.SlotIndex = static_cast<uint32_t>(i);
                row.SlotAddress = vptr + i * 8;
                row.Target = 0;
                row.Readable = Pointer(reader, row.SlotAddress, &row.Target);
                row.Modified = row.Readable && (row.Target < imageBase || !rule.AllowedSlots[i].Contains(row.Target - imageBase));
                row.Reason = !row.Readable ? L"slot_unreadable" : (row.Modified ? L"slot_outside_allowed_implementation" : L"slot_allowed");
                result.push_back(std::move(row));
            }
        }
        uint64_t rootAfter = root, vptrAfter = 0;
        if ((object.Indirect && (!Pointer(reader, rootSlot, &rootAfter) || rootAfter != root)) ||
            !Pointer(reader, root + rule.Offset, &vptrAfter) || vptrAfter != vptr)
        {
            for (size_t i = group; i < result.size(); ++i)
            {
                result[i].Modified = result[i].Readable = false;
                result[i].Reason = L"object_or_vptr_changed_during_read";
                if (member) { result[i].LifetimeStatus = L"lifetime_root_or_vptr_changed"; }
            }
        }
    }
}

std::vector<GameObjectObservation> VerifyGameObjects(const GameBuildManifest& manifest,
    uint64_t imageBase, const ObservationReader& reader, size_t budget, size_t* cursor)
{
    std::vector<GameObjectObservation> result;
    if (cursor == nullptr || manifest.Vptrs.empty() || !UserExtent(imageBase, manifest.ImageSize)) { return result; }
    const size_t start = *cursor % manifest.Vptrs.size();
    const size_t count = (std::min)(budget, manifest.Vptrs.size());
    for (size_t n = 0; n < count; ++n)
    {
        const size_t index = (start + n) % manifest.Vptrs.size();
        const auto& rule = manifest.Vptrs[index];
        if (rule.ObjectIndex >= manifest.Objects.size() || rule.AllowedSlots.size() > 1024) { break; }
        const auto& object = manifest.Objects[rule.ObjectIndex];
        if (!Within(rule.Offset, 8, object.Size) || !Within(object.RootRva, object.Indirect ? 8 : object.Size, manifest.ImageSize)) { break; }
        GameObjectObservation observation;
        observation.IsVptr = true;
        observation.RuleIndex = static_cast<uint32_t>(index);
        if (!object.Lifetime)
        {
            observation.ObjectAddress = imageBase + object.RootRva;
            InspectObject(object, rule, imageBase, reader, nullptr, std::move(observation), result);
            continue;
        }

        const auto& lifetime = *object.Lifetime;
        if (!Within(lifetime.SlotRva, sizeof(KnGameObjectSlotV1), manifest.ImageSize)) { break; }
        const uint64_t address = imageBase + lifetime.SlotRva;
        GameObjectLifetimeSample before, after;
        const auto started = GetTickCount64();
        const auto* reason = ReadPublication(reader, address, before);
        if (!reason) { reason = ActiveMember(*before.Record, lifetime); }
        if (reason)
        {
            observation.Reason = observation.LifetimeStatus = reason;
            observation.ObserverBeginUptimeMs = started;
            observation.ObserverEndUptimeMs = GetTickCount64();
            observation.Before = std::move(before);
            result.push_back(std::move(observation));
            continue;
        }

        const size_t group = result.size();
        InspectObject(object, rule, imageBase, reader, &*before.Record, std::move(observation), result);
        reason = ReadPublication(reader, address, after);
        const auto finished = GetTickCount64();
        if (!reason && std::memcmp(&*before.Record, &*after.Record, sizeof(KnGameObjectSlotV1)) != 0)
        { reason = L"lifetime_changed_during_read"; }
        for (size_t i = group; i < result.size(); ++i)
        {
            auto& row = result[i];
            row.Before = before;
            row.After = after;
            row.ObserverBeginUptimeMs = started;
            row.ObserverEndUptimeMs = finished;
            if (reason)
            {
                row.Modified = row.Readable = false;
                row.Reason = row.LifetimeStatus = reason;
            }
        }
    }
    *cursor = (start + count) % manifest.Vptrs.size();
    return result;
}

std::map<std::wstring, std::wstring> GameObjectLifetimeEvidence(const GameObjectRule& object,
    const GameVptrRule& rule, const GameObjectObservation& observation)
{
    std::map<std::wstring, std::wstring> fields{{L"lifetime_status", observation.LifetimeStatus}};
    if (!object.Lifetime) { return fields; }
    fields[L"lifetime_source"] = L"game_reported_registry_slot_v1";
    fields[L"registry_slot_rva"] = std::to_wstring(object.Lifetime->SlotRva);
    fields[L"expected_container_id"] = std::to_wstring(object.Lifetime->ContainerId);
    fields[L"subobject_type"] = rule.SubobjectType;
    fields[L"subobject_size"] = std::to_wstring(rule.SubobjectSize);
    fields[L"vptr_role"] = rule.Offset ? L"secondary" : L"primary";
    if (observation.LifetimeStatus == L"reported_active_member")
    { fields[L"subobject_address"] = std::to_wstring(observation.ObjectAddress + rule.Offset); }
    const auto retain = [&](const std::wstring& prefix, const GameObjectLifetimeSample& sample)
    {
        if (sample.BeginSequence) { fields[prefix + L"sequence_begin"] = std::to_wstring(*sample.BeginSequence); }
        if (sample.Record)
        {
            fields[prefix + L"sequence"] = std::to_wstring(sample.Record->Sequence);
            fields[prefix + L"generation"] = std::to_wstring(sample.Record->Generation);
            fields[prefix + L"container_id"] = std::to_wstring(sample.Record->ContainerId);
            fields[prefix + L"member_address"] = std::to_wstring(sample.Record->MemberAddress);
            fields[prefix + L"phase"] = std::to_wstring(sample.Record->Phase);
        }
        if (sample.EndSequence) { fields[prefix + L"sequence_end"] = std::to_wstring(*sample.EndSequence); }
    };
    retain(L"before_", observation.Before);
    retain(L"after_", observation.After);
    return fields;
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
