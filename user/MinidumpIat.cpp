#include "MinidumpIat.h"
#include "ArtifactOutput.h"
#include "BoundedObservationJson.h"
#include "EtlReferenceBuild.h"
#include "ExecutableImageVerifier.h"
#include "ImageIatReference.h"
#include "RuntimeCapabilities.h"
#include "SavedEtlInput.h"
#include <DbgHelp.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <iterator>
#include <map>
#include <set>

namespace
{
    using bounded_observation_json::N;
    using mcpjson::Quote;
    constexpr uint64_t MaxDumpBytes = 8ull << 30;
    constexpr uint32_t MaxRanges = 262144, MaxModules = 4096, MaxStreams = 256;
    struct Extent { uint64_t Start = 0, End = 0; };
    struct Memory { uint64_t Address, Size, Offset; uint32_t Index; };
    struct Part { uint64_t Offset, Size; uint32_t Index; };
    enum class ByteState : size_t { Matched, Different, Missing, ReadError, Excluded, Count };
    using ByteCounts = std::array<uint32_t, static_cast<size_t>(ByteState::Count)>;
    struct DeclarationByte
    {
        uint64_t ReferenceOffset;
        ByteState State;
        const Memory* Source = nullptr;
        uint64_t FileOffset = 0;
        uint8_t Value = 0;
        DWORD Win32 = ERROR_SUCCESS;
    };
    using DeclarationBytes = std::map<uint32_t, DeclarationByte>;

    std::wstring ByteDigest(const uint8_t* bytes, size_t size)
    {
        ContentHash hash;
        return hash.Add(bytes, size) ? hash.Finish() : std::wstring{};
    }

    struct FieldComparison
    {
        ByteCounts Counts{};
        std::wstring Spans;

        bool Record(uint32_t offset, uint32_t length, ByteState state, const Memory* source = nullptr,
            uint64_t fileOffset = 0, const uint8_t* captured = nullptr, DWORD win32Status = ERROR_SUCCESS)
        {
            static constexpr const wchar_t* labels[]{L"matched", L"different", L"not_retained", L"read_error", L"loaded_iat"};
            const auto index = static_cast<size_t>(state);
            std::wstring row = L"{\"field_offset\":" + N(offset) + L",\"bytes\":" + N(length) + L",\"state\":" + Quote(labels[index]);
            if (source) { row += L",\"range_index\":" + N(source->Index) + L",\"file_offset\":" + N(fileOffset); }
            if (state == ByteState::ReadError) { row += L",\"win32_status\":" + N(win32Status); }
            if (captured)
            {
                const auto digest = ByteDigest(captured, length);
                if (digest.empty()) { return false; }
                row += L",\"captured_sha256\":" + Quote(digest);
            }
            Counts[index] += length;
            if (!Spans.empty()) { Spans += L","; }
            Spans += row + L"}";
            return true;
        }
    };
    bool Fits(uint64_t offset, uint64_t size, uint64_t limit) { return offset <= limit && size <= limit - offset; }
    bool ReadAt(const SchemaArtifact& file, uint64_t offset, void* data, uint32_t size)
    {
        DWORD read = 0;
        return Fits(offset, size, file.Bytes()) && approved_file::ReadAt(file.Handle(), offset, data, size, &read) && read == size;
    }
    bool Disjoint(std::vector<Extent>& spans)
    {
        std::sort(spans.begin(), spans.end(), [](const auto& a, const auto& b) { return a.Start < b.Start; });
        for (size_t i = 1; i < spans.size(); ++i) { if (spans[i].Start < spans[i - 1].End) { return false; } }
        return true;
    }

    class Minidump
    {
    public:
        explicit Minidump(const SchemaArtifact& file) : File(file) {}
        const wchar_t* Parse();
        bool Copy(uint64_t address, size_t length, std::vector<uint8_t>& bytes, std::vector<Part>* parts = nullptr) const;
        bool CompareLookup(uint64_t address, const uint8_t* expected, size_t& retained) const;
        void CompareDeclaration(uint64_t base, const std::vector<uint8_t>& reference, DeclarationBytes& locations) const;
        std::wstring ModuleJson(size_t index) const;
        bool SameBuild(const MINIDUMP_MODULE& module, const executable_image::DiskPeMetadata& pe) const;
        std::vector<MINIDUMP_MODULE> Modules;
        bool FullMemory = false;
        ULONG32 Timestamp = 0;
        std::wstring Pid = L"null", Created = L"null";
    private:
        template<class T> bool Value(uint64_t offset, T& out) const { return ReadAt(File, offset, &out, sizeof(out)); }
        const Memory* Locate(uint64_t address) const;
        const wchar_t* ReadModules(MINIDUMP_LOCATION_DESCRIPTOR table);
        const wchar_t* ReadMemory(MINIDUMP_LOCATION_DESCRIPTOR table);
        bool Reserve(uint64_t start, uint64_t size)
        {
            if (!Fits(start, size, File.Bytes())) { return false; }
            if (size) { Metadata.push_back({start, start + size}); }
            return true;
        }
        const SchemaArtifact& File;
        std::vector<Extent> Metadata;
        std::vector<Memory> Ranges;
    };

    const wchar_t* Minidump::Parse()
    {
        MINIDUMP_HEADER header{};
        if (!Value(0, header) || header.Signature != MINIDUMP_SIGNATURE ||
            LOWORD(header.Version) != MINIDUMP_VERSION) { return L"unsupported_minidump"; }
        if (!header.NumberOfStreams || header.NumberOfStreams > MaxStreams) { return L"invalid_stream_directory"; }
        const uint32_t directoryBytes = header.NumberOfStreams * sizeof(MINIDUMP_DIRECTORY);
        std::vector<MINIDUMP_DIRECTORY> entries(header.NumberOfStreams);
        if (!Reserve(0, sizeof(header)) || !Reserve(header.StreamDirectoryRva, directoryBytes) ||
            !ReadAt(File, header.StreamDirectoryRva, entries.data(), directoryBytes)) { return L"invalid_stream_directory"; }
        std::map<ULONG32, MINIDUMP_LOCATION_DESCRIPTOR> streams;
        for (const auto& item : entries)
        {
            if (!Reserve(item.Location.Rva, item.Location.DataSize)) { return L"invalid_stream_directory"; }
            switch (item.StreamType)
            {
            case SystemInfoStream: case ModuleListStream: case MemoryListStream: case Memory64ListStream: case MiscInfoStream:
                if (!streams.emplace(item.StreamType, item.Location).second) { return L"duplicate_stream"; }
            }
        }
        if (!Disjoint(Metadata)) { return L"overlapping_streams"; }
        const auto sys = streams.find(SystemInfoStream);
        MINIDUMP_SYSTEM_INFO system{};
        if (sys == streams.end() || sys->second.DataSize < sizeof(system) || !Value(sys->second.Rva, system) ||
            system.ProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) { return L"amd64_system_info_unavailable"; }
        Timestamp = header.TimeDateStamp;
        const auto misc = streams.find(MiscInfoStream);
        if (misc != streams.end())
        {
            MINIDUMP_MISC_INFO info{};
            if (misc->second.DataSize < sizeof(info) || !Value(misc->second.Rva, info) ||
                info.SizeOfInfo < sizeof(info) || info.SizeOfInfo > misc->second.DataSize) { return L"invalid_process_info"; }
            if (info.Flags1 & MINIDUMP_MISC1_PROCESS_ID) { Pid = N(info.ProcessId); }
            if (info.Flags1 & MINIDUMP_MISC1_PROCESS_TIMES) { Created = N(info.ProcessCreateTime); }
        }
        const auto mods = streams.find(ModuleListStream);
        if (mods == streams.end()) { return L"module_stream_missing"; }
        if (const auto issue = ReadModules(mods->second)) { return issue; }
        FullMemory = streams.count(Memory64ListStream) != 0;
        if (FullMemory && streams.count(MemoryListStream)) { return L"ambiguous_memory_stream"; }
        const auto memory = streams.find(FullMemory ? Memory64ListStream : MemoryListStream);
        return memory == streams.end() ? L"memory_stream_missing" : ReadMemory(memory->second);
    }

    const wchar_t* Minidump::ReadModules(MINIDUMP_LOCATION_DESCRIPTOR table)
    {
        uint32_t count = 0;
        if (table.DataSize < sizeof(count) || !Value(table.Rva, count) || !count || count > MaxModules ||
            sizeof(count) + sizeof(MINIDUMP_MODULE) * count != table.DataSize) { return L"invalid_module_list"; }
        Modules.resize(count);
        if (!ReadAt(File, uint64_t(table.Rva) + sizeof(count), Modules.data(), table.DataSize - sizeof(count)))
            { return L"invalid_module_list"; }
        std::vector<Extent> images;
        for (const auto& module : Modules)
        {
            uint32_t nameBytes = 0;
            if (!module.BaseOfImage || !module.SizeOfImage || !Fits(module.BaseOfImage, module.SizeOfImage, INT64_MAX) ||
                !module.ModuleNameRva || !Value(module.ModuleNameRva, nameBytes) || !nameBytes || nameBytes % 2 || nameBytes > 65534 ||
                !Reserve(module.ModuleNameRva, uint64_t(sizeof(nameBytes)) + nameBytes) ||
                !Reserve(module.CvRecord.Rva, module.CvRecord.DataSize) || !Reserve(module.MiscRecord.Rva, module.MiscRecord.DataSize))
                { return L"invalid_module_list"; }
            images.push_back({module.BaseOfImage, module.BaseOfImage + module.SizeOfImage});
        }
        return Disjoint(images) ? nullptr : L"overlapping_module_extents";
    }

    const wchar_t* Minidump::ReadMemory(MINIDUMP_LOCATION_DESCRIPTOR table)
    {
        constexpr size_t descriptorBytes = sizeof(MINIDUMP_MEMORY_DESCRIPTOR);
        static_assert(descriptorBytes == sizeof(MINIDUMP_MEMORY_DESCRIPTOR64));
        const uint32_t prefix = FullMemory ? 16 : 4;
        uint64_t count = 0, payload = 0;
        if (table.DataSize < prefix || !ReadAt(File, table.Rva, &count, FullMemory ? 8 : 4) || !count ||
            count > MaxRanges || prefix + descriptorBytes * count != table.DataSize ||
            (FullMemory && !Value(uint64_t(table.Rva) + 8, payload))) { return L"invalid_memory_list"; }
        std::vector<uint8_t> tableBytes(table.DataSize - prefix);
        if (!ReadAt(File, uint64_t(table.Rva) + prefix, tableBytes.data(), table.DataSize - prefix))
            { return L"invalid_memory_list"; }
        Ranges.reserve(static_cast<size_t>(count));
        std::vector<Extent> physical;
        for (uint32_t i = 0; i < count; ++i)
        {
            const auto* raw = tableBytes.data() + descriptorBytes * i;
            Memory span{0, 0, payload, i};
            if (FullMemory)
            {
                MINIDUMP_MEMORY_DESCRIPTOR64 descriptor{};
                std::memcpy(&descriptor, raw, sizeof(descriptor));
                span.Address = descriptor.StartOfMemoryRange; span.Size = descriptor.DataSize;
            }
            else
            {
                MINIDUMP_MEMORY_DESCRIPTOR descriptor{};
                std::memcpy(&descriptor, raw, sizeof(descriptor));
                span.Address = descriptor.StartOfMemoryRange; span.Size = descriptor.Memory.DataSize; span.Offset = descriptor.Memory.Rva;
            }
            if (!span.Size || !Fits(span.Address, span.Size, INT64_MAX) || !Fits(span.Offset, span.Size, File.Bytes()))
                { return L"invalid_memory_extent"; }
            if (FullMemory) { payload += span.Size; }
            physical.push_back({span.Offset, span.Offset + span.Size});
            Ranges.push_back(span);
        }
        std::sort(Ranges.begin(), Ranges.end(), [](const auto& a, const auto& b) { return a.Address < b.Address; });
        for (size_t i = 1; i < Ranges.size(); ++i)
        {
            if (Ranges[i].Address < Ranges[i - 1].Address + Ranges[i - 1].Size) { return L"overlapping_virtual_memory"; }
        }
        if (!Disjoint(physical)) { return L"aliased_memory_payload"; }
        if (!Disjoint(Metadata)) { return L"overlapping_module_metadata"; }
        size_t m = 0;
        for (const auto& area : physical)
        {
            while (m < Metadata.size() && Metadata[m].End <= area.Start) { ++m; }
            if (m < Metadata.size() && Metadata[m].Start < area.End) { return L"metadata_in_memory_payload"; }
        }
        return nullptr;
    }

    const Memory* Minidump::Locate(uint64_t address) const
    {
        auto it = std::upper_bound(Ranges.begin(), Ranges.end(), address,
            [](uint64_t key, const Memory& span) { return key < span.Address; });
        if (it == Ranges.begin()) { return nullptr; }
        --it;
        return address - it->Address < it->Size ? &*it : nullptr;
    }

    bool Minidump::Copy(uint64_t address, size_t length, std::vector<uint8_t>& bytes, std::vector<Part>* parts) const
    {
        bytes.clear();
        if (parts) { parts->clear(); }
        if (!length || length > 4096 || !Fits(address, length, INT64_MAX)) { return false; }
        std::vector<uint8_t> recovered(length);
        std::vector<Part> sources;
        for (size_t done = 0; done < length;)
        {
            const auto at = address + done;
            const auto* it = Locate(at);
            if (!it) { return false; }
            const auto delta = at - it->Address;
            const auto count = static_cast<uint32_t>((std::min<uint64_t>)(length - done, it->Size - delta));
            if (!ReadAt(File, it->Offset + delta, recovered.data() + done, count)) { return false; }
            if (parts) { sources.push_back({it->Offset + delta, count, it->Index}); }
            done += count;
        }
        bytes.swap(recovered);
        if (parts) { parts->swap(sources); }
        return true;
    }

    // DbgHelp can preserve a loaded IAT and its descriptor while omitting
    // the separate lookup table. Every lookup byte it did retain must agree.
    bool Minidump::CompareLookup(uint64_t address, const uint8_t* expected, size_t& retained) const
    {
        retained = 0;
        for (size_t i = 0; i < sizeof(uint64_t); ++i)
        {
            const auto* span = Locate(address + i);
            if (!span) { continue; }
            uint8_t saved = 0;
            if (!Value(span->Offset + (address + i - span->Address), saved) || saved != expected[i]) { return false; }
            ++retained;
        }
        return true;
    }

    void Minidump::CompareDeclaration(uint64_t base, const std::vector<uint8_t>& reference, DeclarationBytes& locations) const
    {
        // A pooled name can serve several fields. Read each selected RVA once,
        // keeping physical reads inside their original minidump descriptor.
        for (auto it = locations.begin(); it != locations.end();)
        {
            if (it->second.State == ByteState::Excluded) { ++it; continue; }
            const uint64_t address = base + it->first;
            const auto* source = Locate(address);
            if (!source) { ++it; continue; }
            const auto delta = address - source->Address;
            auto end = std::next(it);
            DWORD size = 1;
            while (end != locations.end() && end->first == uint64_t(it->first) + size &&
                size < source->Size - delta && end->second.State != ByteState::Excluded) { ++size; ++end; }
            std::vector<uint8_t> saved(size);
            DWORD received = 0;
            const uint64_t fileOffset = source->Offset + delta;
            const auto ok = approved_file::ReadAt(File.Handle(), fileOffset, saved.data(), size, &received);
            const auto error = ok ? ERROR_SUCCESS : GetLastError();
            for (DWORD i = 0; it != end; ++it, ++i)
            {
                auto& b = it->second;
                b.Source = source;
                b.FileOffset = fileOffset + i;
                if (i >= received) { b.State = ByteState::ReadError; b.Win32 = error; continue; }
                b.Value = saved[i];
                b.State = b.Value == reference[b.ReferenceOffset] ? ByteState::Matched : ByteState::Different;
            }
        }
    }

    bool Minidump::SameBuild(const MINIDUMP_MODULE& module, const executable_image::DiskPeMetadata& pe) const
    {
        uint8_t rsds[24]{};
        return module.SizeOfImage == pe.SizeOfImage && module.TimeDateStamp == pe.TimeDateStamp && module.CheckSum == pe.CheckSum &&
            module.CvRecord.DataSize >= sizeof(rsds) && ReadAt(File, module.CvRecord.Rva, rsds, sizeof(rsds)) &&
            !std::memcmp(rsds, "RSDS", 4) && !std::memcmp(rsds + 4, &pe.PdbGuid, sizeof(GUID)) && !std::memcmp(rsds + 20, &pe.PdbAge, 4);
    }

    std::wstring Minidump::ModuleJson(size_t index) const
    {
        const auto& m = Modules[index];
        uint32_t bytes = 0;
        if (!Value(m.ModuleNameRva, bytes) || !bytes || bytes > 65534 || bytes % sizeof(wchar_t)) { return {}; }
        std::wstring name(bytes / sizeof(wchar_t), L'\0');
        if (!ReadAt(File, uint64_t(m.ModuleNameRva) + sizeof(bytes), name.data(), bytes) ||
            name.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(name) != name) { return {}; }
        const auto separator = name.find_last_of(L"\\/");
        if (separator != std::wstring::npos) { name.erase(0, separator + 1); }
        if (name.empty()) { return {}; }
        return L"{\"module_list_index\":" + N(index) + L",\"basename\":" + Quote(name) + L",\"image_size\":" + N(m.SizeOfImage) +
            L",\"coff_timestamp\":" + N(m.TimeDateStamp) + L",\"checksum\":" + N(m.CheckSum) + L"}";
    }

    std::wstring PartsJson(const std::vector<Part>& parts)
    {
        std::wstring out = L"[";
        for (const auto& p : parts)
        {
            if (out.size() > 1) { out += L","; }
            out += L"{\"range_index\":" + N(p.Index) + L",\"file_offset\":" + N(p.Offset) + L",\"bytes\":" + N(p.Size) + L"}";
        }
        return out + L"]";
    }

    std::wstring DeclarationFields(const wchar_t* status, const wchar_t* reason, const std::wstring& evidence = {})
    {
        return L",\"claim\":\"saved_declaration_bytes_match_reference\",\"status\":" + Quote(status) +
            L",\"reason\":" + Quote(reason) + evidence;
    }

    std::wstring CountsJson(const ByteCounts& counts)
    {
        const auto [matched, different, missing, failed, excluded] = counts;
        return L"{\"requested_bytes\":" + N(matched + different + missing + failed + excluded) +
            L",\"captured_bytes\":" + N(matched + different) + L",\"matched_bytes\":" + N(matched) +
            L",\"different_bytes\":" + N(different) + L",\"missing_bytes\":" + N(missing) +
            L",\"read_error_bytes\":" + N(failed) + L",\"excluded_bytes\":" + N(excluded) + L"}";
    }

    struct DeclarationField
    {
        const wchar_t* Name;
        uint32_t Rva, Size;
        uint64_t FileOffset = 0;
    };

    const wchar_t* LocateDeclarationFields(const executable_image::DiskPeMetadata& pe, size_t fileSize, uint32_t slotRva,
        std::vector<DeclarationField>& fields, DeclarationBytes& locations)
    {
        const ObservationRange loadedSlot{slotRva, sizeof(uint64_t)};
        for (auto& field : fields)
        {
            if (!FileBackedRvaRange(pe, field.Rva, field.Size, field.FileOffset) || !Fits(field.FileOffset, field.Size, fileSize))
                { return L"reference_field_not_file_backed"; }
            const ObservationRange mapped{field.Rva, field.Size};
            size_t mappings = mapped.Overlaps({0, pe.SizeOfHeaders}) ? 1 : 0;
            for (const auto& section : pe.Sections)
            {
                if (mapped.Overlaps({section.VirtualAddress, (std::max)(section.VirtualSize, section.SizeOfRawData)})) { ++mappings; }
            }
            if (mappings != 1) { return L"ambiguous_reference_mapping"; }
            for (uint32_t i = 0; i < field.Size; ++i)
            {
                const auto state = loadedSlot.Contains(field.Rva + i) ? ByteState::Excluded : ByteState::Missing;
                const auto [it, inserted] = locations.emplace(field.Rva + i, DeclarationByte{field.FileOffset + i, state});
                if (!inserted && it->second.ReferenceOffset != field.FileOffset + i)
                    { return L"ambiguous_reference_mapping"; }
            }
        }
        return nullptr;
    }

    bool RenderFieldSpans(const DeclarationBytes& locations, const DeclarationField& field, FieldComparison& result)
    {
        for (uint32_t start = 0; start < field.Size;)
        {
            auto it = locations.find(field.Rva + start);
            const auto& first = it->second;
            const bool captured = first.State == ByteState::Matched || first.State == ByteState::Different;
            std::vector<uint8_t> bytes;
            uint32_t end = start;
            do
            {
                if (captured) { bytes.push_back(it->second.Value); }
                ++it; ++end;
            } while (end < field.Size && it->second.State == first.State && it->second.Source == first.Source &&
                it->second.Win32 == first.Win32);
            if (!result.Record(start, end - start, first.State, first.Source, first.FileOffset,
                captured ? bytes.data() : nullptr, first.Win32)) { return false; }
            start = end;
        }
        return true;
    }

    std::wstring CheckDeclaration(const Minidump& dump, size_t importer, const ImageIatDeclaration& entry,
        const executable_image::DiskPeMetadata& pe, const std::vector<uint8_t>& reference, const std::vector<Part>& instructionParts)
    {
        std::vector<DeclarationField> fields{
            {L"import_descriptor", entry.DescriptorRva, sizeof(IMAGE_IMPORT_DESCRIPTOR)},
            {L"dll_name", entry.ModuleNameRva, static_cast<uint32_t>(entry.Module.size() + 1)},
            {L"lookup_cell", entry.LookupRva, sizeof(uint64_t)}
        };
        if (!entry.ByOrdinal)
        {
            fields.push_back({L"hint_and_name", entry.HintNameRva, static_cast<uint32_t>(sizeof(uint16_t) + entry.Name.size() + 1)});
        }
        DeclarationBytes locations;
        if (const auto issue = LocateDeclarationFields(pe, reference.size(), entry.SlotRva, fields, locations))
            { return DeclarationFields(L"unfulfilled", issue); }
        dump.CompareDeclaration(dump.Modules[importer].BaseOfImage, reference, locations);
        ByteCounts total{};
        std::set<uint64_t> referenceOffsets;
        for (const auto& item : locations)
        {
            ++total[static_cast<size_t>(item.second.State)];
            referenceOffsets.insert(item.second.ReferenceOffset);
        }
        uint32_t fieldBytes = 0;
        std::wstring records;
        for (const auto& field : fields)
        {
            const auto* expected = reference.data() + field.FileOffset;
            const auto refHash = ByteDigest(expected, field.Size);
            if (refHash.empty()) { return DeclarationFields(L"unfulfilled", L"field_hash_unavailable"); }
            FieldComparison result;
            if (!RenderFieldSpans(locations, field, result)) { return DeclarationFields(L"unfulfilled", L"field_hash_unavailable"); }
            fieldBytes += field.Size;
            if (!records.empty()) { records += L","; }
            records += L"{\"field\":" + Quote(field.Name) + L",\"rva\":" + N(field.Rva) +
                L",\"reference_file_offset\":" + N(field.FileOffset) + L",\"reference_field_sha256\":" + Quote(refHash) +
                L",\"coverage\":" + CountsJson(result.Counts) + L",\"declaration_spans\":[" + result.Spans + L"]}";
        }
        const auto [matched, different, missing, failed, excluded] = total;
        const auto evidence = L",\"module_list_index\":" + N(importer) + L",\"iat_slot_rva\":" + N(entry.SlotRva) +
            L",\"instruction_rva\":" + N(entry.InstructionRva) + L",\"instruction_file_spans\":" + PartsJson(instructionParts) +
            L",\"reference_module\":" + Quote(entry.Module) + L",\"reference_import_name\":" + (entry.ByOrdinal ? L"null" : Quote(entry.Name)) +
            L",\"reference_ordinal\":" + (entry.ByOrdinal ? N(entry.Ordinal) : L"null") +
            L",\"field_bytes\":" + N(fieldBytes) + L",\"unique_reference_bytes\":" + N(referenceOffsets.size()) +
            L",\"coverage\":" + CountsJson(total) + L",\"declaration_fields\":[" + records + L"]";
        if (different) { return DeclarationFields(L"contradicted", L"captured_bytes_differ", evidence); }
        if (failed) { return DeclarationFields(L"unfulfilled", L"dump_read_failed", evidence); }
        if (excluded) { return DeclarationFields(L"unfulfilled", entry.LookupRva == entry.SlotRva ?
            L"lookup_replaced_by_loader" : L"declaration_uses_loaded_slot_bytes", evidence); }
        if (missing) { return DeclarationFields(L"unfulfilled", L"declaration_bytes_not_retained", evidence); }
        return DeclarationFields(L"supported", L"complete_byte_match", evidence);
    }

    bool OriginalInstruction(const executable_image::DiskPeMetadata& pe, uint32_t rva, size_t size)
    {
        if (!pe.BaseRelocationTableComplete || !pe.DynamicRelocationTableComplete) { return false; }
        const ObservationRange instruction{rva, size};
        const auto mutableRange = [&](const auto& range) { return instruction.Overlaps({range.Rva, range.Size}); };
        return std::none_of(pe.LoaderMutableRanges.begin(), pe.LoaderMutableRanges.end(), mutableRange) &&
            std::none_of(pe.DynamicRelocationRanges.begin(), pe.DynamicRelocationRanges.end(), mutableRange) &&
            std::none_of(pe.CrossPageRelocationRanges.begin(), pe.CrossPageRelocationRanges.end(), mutableRange) &&
            std::none_of(pe.BaseRelocations.begin(), pe.BaseRelocations.end(), [&](const auto& entry) {
                return instruction.Overlaps({entry.Rva, entry.Width}); }) &&
            std::none_of(pe.Rel32Overrides.begin(), pe.Rel32Overrides.end(), [&](const auto& entry) {
                return instruction.Overlaps({entry.Rva, 4}); });
    }

    bool DirectoriesMatch(const executable_image::DiskPeMetadata& pe, uint64_t base, const ObservationReader& read)
    {
        std::vector<uint8_t> bytes;
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 headers{};
        if (!read(base, sizeof(dos), &bytes)) { return false; }
        std::memcpy(&dos, bytes.data(), sizeof(dos));
        if (dos.e_lfanew <= 0 || !read(base + static_cast<uint32_t>(dos.e_lfanew), sizeof(headers), &bytes)) { return false; }
        std::memcpy(&headers, bytes.data(), sizeof(headers));
        const auto& optional = headers.OptionalHeader;
        if (headers.FileHeader.SizeOfOptionalHeader < offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            (IMAGE_DIRECTORY_ENTRY_IAT + 1) * sizeof(IMAGE_DATA_DIRECTORY) ||
            optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT || optional.SizeOfHeaders != pe.SizeOfHeaders) { return false; }
        for (const auto id : {IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_DEBUG})
        {
            const auto& expected = pe.DataDirectories[id];
            const auto& saved = optional.DataDirectory[id];
            if (saved.VirtualAddress != expected.VirtualAddress || saved.Size != expected.Size) { return false; }
        }
        return true;
    }

    const wchar_t* Observe(const SchemaArtifact& source, const SchemaArtifact& reference,
        const std::wstring& exportName, std::wstring& fields, std::wstring* declaration)
    {
        using namespace executable_image;
        DiskPeMetadata pe;
        if (!ReadDiskPeMetadataHandle(reference.Handle(), &pe, nullptr) || pe.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pe.OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || !pe.HasPdbIdentity) { return L"unsupported_reference_image"; }
        const auto build = etl_profile::ReadReferenceBuild(reference, pe);
        if (!build.valid || !IsEqualGUID(build.guid, pe.PdbGuid) || build.age != pe.PdbAge) { return L"reference_build_unavailable"; }
        std::vector<uint8_t> original(static_cast<size_t>(reference.Bytes()));
        if (!ReadAt(reference, 0, original.data(), static_cast<uint32_t>(original.size()))) { return L"reference_read_failed"; }
        Minidump dump(source);
        if (const auto reason = dump.Parse()) { return reason; }
        size_t importer = dump.Modules.size();
        for (size_t i = 0; i < dump.Modules.size(); ++i)
        {
            if (!dump.SameBuild(dump.Modules[i], pe)) { continue; }
            if (importer != dump.Modules.size()) { return L"ambiguous_importing_module"; }
            importer = i;
        }
        if (importer == dump.Modules.size()) { return L"importing_build_missing"; }
        const auto& module = dump.Modules[importer];
        const auto importerJson = dump.ModuleJson(importer);
        const auto read = [&](uint64_t va, size_t length, std::vector<uint8_t>* out) {
            return va >= module.BaseOfImage && Fits(va - module.BaseOfImage, length, module.SizeOfImage) &&
                dump.Copy(va, length, *out);
        };
        if (importerJson.empty() || !QualifyExecutableReference(pe, module.BaseOfImage, read, nullptr))
            { return L"captured_importer_identity_unqualified"; }
        if (!DirectoriesMatch(pe, module.BaseOfImage, read)) { return L"captured_image_directories_unqualified"; }
        std::vector<Part> instructionParts, slotParts;
        const auto check = [&](uint32_t rva, const std::vector<uint8_t>& bytes) -> const wchar_t* {
            std::vector<uint8_t> captured;
            return OriginalInstruction(pe, rva, bytes.size()) &&
                dump.Copy(module.BaseOfImage + rva, bytes.size(), captured, &instructionParts) && captured == bytes ?
                nullptr : L"instruction_bytes_unqualified";
        };
        ImageIatDeclaration entry;
        if (const auto reason = InspectImageIatDeclaration(exportName, pe, original, check, entry)) { return reason; }
        if (declaration) { *declaration = CheckDeclaration(dump, importer, entry, pe, original, instructionParts); }
        const auto matches = [&](uint32_t rva, uint32_t size) {
            uint64_t offset = 0;
            std::vector<uint8_t> captured;
            return FileBackedRvaRange(pe, rva, size, offset) && Fits(offset, size, original.size()) &&
                read(module.BaseOfImage + rva, size, &captured) && std::equal(captured.begin(), captured.end(), original.data() + offset);
        };
        if (!matches(entry.DescriptorRva, sizeof(IMAGE_IMPORT_DESCRIPTOR))) { return L"captured_import_descriptor_unqualified"; }
        const bool separate = entry.LookupRva != entry.SlotRva;
        const wchar_t* lookupBasis = L"shared_iat_reference_only";
        size_t lookupBytes = 0;
        if (separate)
        {
            uint64_t offset = 0;
            if (!FileBackedRvaRange(pe, entry.LookupRva, sizeof(uint64_t), offset) || !Fits(offset, sizeof(uint64_t), original.size()) ||
                !dump.CompareLookup(module.BaseOfImage + entry.LookupRva, original.data() + offset, lookupBytes))
                { return L"captured_import_lookup_unqualified"; }
            if (lookupBytes == sizeof(uint64_t)) { lookupBasis = L"separate_lookup_matched"; }
            else if (lookupBytes) { lookupBasis = L"separate_lookup_partially_retained"; }
            else { lookupBasis = L"separate_lookup_reference_only"; }
        }
        std::vector<uint8_t> slot;
        if (!dump.Copy(module.BaseOfImage + entry.SlotRva, sizeof(uint64_t), slot, &slotParts)) { return L"slot_bytes_unavailable"; }
        uint64_t value = 0;
        std::memcpy(&value, slot.data(), sizeof(value));
        const auto slotHash = ContentHash::Bytes(slot);
        if (slotHash.empty()) { return L"slot_hash_unavailable"; }
        const wchar_t* owner = value ? L"outside_reported_modules" : L"null_slot";
        std::wstring ownerJson = L"null";
        for (size_t i = 0; i < dump.Modules.size(); ++i)
        {
            const auto& target = dump.Modules[i];
            if (value < target.BaseOfImage || value - target.BaseOfImage >= target.SizeOfImage) { continue; }
            auto named = dump.ModuleJson(i);
            owner = named.empty() ? L"module_metadata_unavailable" : L"within_reported_module_extent";
            if (!named.empty()) { ownerJson = std::move(named); }
            break;
        }
        fields = L",\"status\":\"observed\",\"slot_value_observed\":true,\"memory_stream\":" +
            Quote(dump.FullMemory ? L"Memory64ListStream" : L"MemoryListStream") +
            L",\"dump_time_unix_seconds\":" + N(dump.Timestamp) + L",\"process_id\":" + dump.Pid +
            L",\"process_create_unix_seconds\":" + dump.Created + L",\"importer\":" + importerJson +
            L",\"instruction_rva\":" + N(entry.InstructionRva) + L",\"instruction_file_spans\":" + PartsJson(instructionParts) +
            L",\"iat_slot_rva\":" + N(entry.SlotRva) + L",\"import_descriptor_rva\":" + N(entry.DescriptorRva) +
            L",\"import_lookup_rva\":" + N(entry.LookupRva) + L",\"lookup_basis\":" + Quote(lookupBasis) +
            L",\"lookup_bytes_matched\":" + N(lookupBytes) +
            L",\"import_module\":" + Quote(entry.Module) + L",\"import_name\":" + (entry.ByOrdinal ? L"null" : Quote(entry.Name)) +
            L",\"import_ordinal\":" + (entry.ByOrdinal ? N(entry.Ordinal) : L"null") +
            L",\"slot_value_sha256\":" + Quote(slotHash) + L",\"slot_file_spans\":" + PartsJson(slotParts) +
            L",\"owner_status\":" + Quote(owner) + L",\"target_module\":" + ownerJson;
        return nullptr;
    }
}

int RunMinidumpIatCommand(const std::vector<std::wstring>& args, bool directJsonOutput)
{
    std::wstring dumpPin, refPin;
    const bool json = args.size() > 7 && !_wcsicmp(args.back().c_str(), L"/json");
    const auto operands = args.size() - (json ? 1 : 0);
    const bool checkDeclaration = operands == 8 && !_wcsicmp(args[7].c_str(), L"/declaration");
    const bool valid = (operands == 7 || checkDeclaration) &&
        !args[2].empty() && !args[4].empty() && etl_profile::NormalizeDigest(args[3], dumpPin) &&
        etl_profile::NormalizeDigest(args[5], refPin) && !args[6].empty() && args[6].size() <= 255 &&
        std::all_of(args[6].begin(), args[6].end(), [](wchar_t c) { return c >= 0x21 && c <= 0x7e; });
    const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    std::vector<DistinctArtifactInput> guards;
    const auto distinct = [&]() {
        if (GetFileType(sink) != FILE_TYPE_DISK) { return true; }
        for (size_t i = 2; i < args.size(); ++i)
        {
            if (valid && i != 2 && i != 4) { continue; }
            if (!guards.emplace_back().Hold(sink, args[i], true)) { return false; }
        }
        return true;
    };
    if (!distinct()) { return 2; }
    if (!valid)
    {
        std::wcerr << L"usage: !kmon dump-image-iat <user-minidump> <dump-sha256> <reference-pe> <pe-sha256> <export-name> [/declaration] [/json]\n";
        return 2;
    }
    etl_profile::SavedEtlInput dump, reference;
    std::wstring fields, declaration;
    const wchar_t* issue = nullptr;
    if (!dump.OpenForHandleReads(args[2], MaxDumpBytes) || dump.File.Sha256 != dumpPin) { issue = L"dump_pin_unavailable"; }
    else if (!reference.OpenForHandleReads(args[4], ReferenceArtifactMaxBytes) || reference.File.Sha256 != refPin ||
        !DistinctLocalFileHandles(dump.File.Handle(), reference.File.Handle())) { issue = L"reference_pin_unavailable"; }
    else
    {
        issue = Observe(dump.File, reference.File, args[6], fields, checkDeclaration ? &declaration : nullptr);
        if (!dump.Revalidated() || !reference.Revalidated())
        {
            issue = L"source_revalidation_failed";
            declaration.clear();
        }
    }
    if (issue) { fields = L",\"status\":\"unavailable\",\"slot_value_observed\":false,\"reason\":" + Quote(issue); }
    if (checkDeclaration)
    {
        if (issue && declaration.empty()) { declaration = DeclarationFields(L"unfulfilled", issue); }
        fields += L",\"declaration_check\":{\"schema\":\"kn.minidump_import_declaration.v1\",\"expected_dump_sha256\":" + Quote(dumpPin) +
            L",\"expected_reference_sha256\":" + Quote(refPin) + L",\"export\":" + Quote(args[6]) + declaration + L"}";
    }
    const auto output = L"{\"schema\":\"kn.minidump_iat_observation.v1\",\"source\":\"saved_user_minidump\",\"export\":" + Quote(args[6]) +
        L",\"expected_dump_sha256\":" + Quote(dumpPin) + L",\"expected_reference_sha256\":" + Quote(refPin) +
        L",\"collector_authenticated\":false,\"slot_reread\":false,\"execution_observed\":false,\"mapping_lifetime_bound\":false" +
        fields + L"}";
    if (!distinct()) { return 2; }
    if (directJsonOutput) { if (!WriteCapabilityJson(output)) { return 3; } }
    else { std::wcout << output << L"\n"; }
    return issue ? 1 : 0;
}
