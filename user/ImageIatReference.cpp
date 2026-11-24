#include "ImageIatReference.h"
#include "BoundedObservationJson.h"
#include "ImageProcessMappings.h"
#include "ImageVerificationRecipe.h"
#include "KmonImportResolver.h"

namespace
{
    using namespace executable_image;
    using bounded_observation_json::N;
    using mcpjson::Quote;

    bool Contains(uint64_t start, uint64_t size, uint64_t address, uint64_t length)
    {
        return length && length <= size && address >= start && address - start <= size - length;
    }

    template<class T> bool ReadValue(const KmonRvaReader& read, uint64_t rva, T& value)
    {
        std::vector<uint8_t> bytes;
        if (rva > UINT32_MAX || !read(static_cast<uint32_t>(rva), sizeof(T), &bytes)) { return false; }
        std::memcpy(&value, bytes.data(), sizeof(T));
        return true;
    }

    bool FileDirectory(const DiskPeMetadata& pe, const IMAGE_DATA_DIRECTORY& directory)
    {
        uint64_t offset = 0;
        return FileBackedRvaRange(pe, directory.VirtualAddress, directory.Size, offset);
    }

    bool UniqueExportName(const KmonRvaReader& read, uint32_t exportRva, const std::string& name)
    {
        IMAGE_EXPORT_DIRECTORY directory{};
        std::vector<uint8_t> names;
        if (name.empty() || !ReadValue(read, exportRva, directory) || !directory.NumberOfNames ||
            directory.NumberOfNames > 8192 || !read(directory.AddressOfNames, directory.NumberOfNames * 4, &names))
            { return false; }
        bool found = false;
        for (size_t i = 0; i < names.size(); i += 4)
        {
            uint32_t rva = 0;
            std::memcpy(&rva, names.data() + i, sizeof(rva));
            char first = 0;
            if (!ReadValue(read, rva, first)) { return false; }
            if (first != name.front()) { continue; }
            std::string candidate;
            if (!KmonReadImportString(read, rva, &candidate)) { return false; }
            if (candidate != name) { continue; }
            if (found) { return false; }
            found = true;
        }
        return found;
    }

    struct ImportEntry
    {
        uint32_t DescriptorRva = 0, LookupRva = 0;
        std::string Module;
        KmonImportSymbol Symbol;
    };

    // A directory interval alone includes zero terminators and can include padding.
    // Require one declared member of a terminated, file-backed import table.
    bool FindImport(const DiskPeMetadata& pe, const KmonRvaReader& read, uint32_t slot, ImportEntry& entry)
    {
        const auto& imports = pe.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        const auto& iat = pe.DataDirectories[IMAGE_DIRECTORY_ENTRY_IAT];
        if (!FileDirectory(pe, imports) || !FileDirectory(pe, iat) || slot % 8 || iat.VirtualAddress % 8 ||
            !Contains(iat.VirtualAddress, iat.Size, slot, 8)) { return false; }
        const size_t descriptors = imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        size_t remainingEntries = 16384;
        for (size_t i = 0; i < (std::min)(descriptors, size_t{512}); ++i)
        {
            const auto descriptorRva = imports.VirtualAddress + static_cast<uint32_t>(i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!ReadValue(read, descriptorRva, descriptor)) { return false; }
            if (!descriptor.Name && !descriptor.FirstThunk && !descriptor.OriginalFirstThunk &&
                !descriptor.TimeDateStamp && !descriptor.ForwarderChain) { return entry.DescriptorRva != 0; }
            if (!descriptor.Name || !descriptor.FirstThunk || descriptor.FirstThunk % 8) { return false; }
            const uint64_t lookup = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
            for (uint64_t offset = 0;; offset += 8)
            {
                const uint64_t cell = descriptor.FirstThunk + offset;
                uint64_t rawSlot = 0, symbol = 0;
                if (!remainingEntries || !Contains(iat.VirtualAddress, iat.Size, cell, 8) ||
                    !ReadValue(read, cell, rawSlot) || !ReadValue(read, lookup + offset, symbol)) { return false; }
                --remainingEntries;
                if (!rawSlot || !symbol)
                {
                    if (rawSlot != symbol) { return false; }
                    break;
                }
                if (cell != slot) { continue; }
                if (entry.DescriptorRva || (!descriptor.OriginalFirstThunk && descriptor.TimeDateStamp) ||
                    !KmonReadImportString(read, descriptor.Name, &entry.Module)) { return false; }
                entry.DescriptorRva = descriptorRva;
                entry.LookupRva = static_cast<uint32_t>(lookup + offset);
                if (IMAGE_SNAP_BY_ORDINAL64(symbol))
                {
                    if (symbol & ~(IMAGE_ORDINAL_FLAG64 | uint64_t{0xffff})) { return false; }
                    entry.Symbol.ByOrdinal = true;
                    entry.Symbol.Ordinal = static_cast<uint16_t>(IMAGE_ORDINAL64(symbol));
                }
                else
                {
                    uint16_t hint = 0;
                    if (symbol > INT32_MAX || !ReadValue(read, symbol, hint) ||
                        !KmonReadImportString(read, static_cast<uint32_t>(symbol + 2), &entry.Symbol.Name)) { return false; }
                }
            }
        }
        return false;
    }

    std::wstring ByteReceipts(const ImageVerificationRecipe& recipe, uint64_t address, size_t length,
        size_t& completeReads)
    {
        std::wstring rows;
        for (const auto& read : recipe.ReadSet.Reads)
        {
            const auto& q = read.Request;
            const auto& result = read.Result;
            if (!ObservationRange{q.Address, q.Length}.Overlaps({address, length})) { continue; }
            if (!read.SourceInvoked || !read.Completed || read.Abandoned || read.DeadlineExceeded ||
                result.State != ObservationReadState::Complete || !result.IdentityRevalidated ||
                result.SourceId != recipe.SourceId) { return {}; }
            if (!rows.empty()) { rows += L","; }
            rows += L"{\"sequence\":" + N(read.Sequence) + L",\"started_tick\":" + N(result.StartedTick) +
                L",\"ended_tick\":" + N(result.EndedTick) + L"}";
            if (Contains(q.Address, q.Length, address, length)) { ++completeReads; }
        }
        return completeReads ? L"[" + rows + L"]" : L"";
    }
}

const wchar_t* InspectImageIatDeclaration(const std::wstring& exportName, const executable_image::DiskPeMetadata& pe,
    const std::vector<uint8_t>& bytes, const ImageIatInstructionCheck& check, ImageIatDeclaration& declaration)
{
    declaration = {};
    const KmonRvaReader read = [&](uint32_t rva, uint32_t length, std::vector<uint8_t>* out)
    {
        uint64_t offset = 0;
        if (!FileBackedRvaRange(pe, rva, length, offset) || offset > bytes.size() || length > bytes.size() - offset)
            { return false; }
        out->assign(bytes.data() + offset, bytes.data() + offset + length);
        return true;
    };
    const auto& exports = pe.DataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uint32_t rva = 0;
    std::string forwarder;
    const KmonImportSymbol symbol{mcpjson::WideToUtf8(exportName)};
    if (pe.Machine != IMAGE_FILE_MACHINE_AMD64 || pe.OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        !FileDirectory(pe, exports) || !KmonReadExport(read, pe.SizeOfImage, exports.VirtualAddress, exports.Size,
            symbol, &rva, &forwarder) || !forwarder.empty() || !UniqueExportName(read, exports.VirtualAddress, symbol.Name))
        { return L"export_instruction_unavailable"; }
    const auto* section = FindDiskSectionForRva(pe, rva);
    std::vector<uint8_t> instruction;
    if (!section || !section->Executable || !read(rva, 1, &instruction)) { return L"export_instruction_unavailable"; }
    const size_t prefixBytes = instruction.front() == 0x48 ? 1 : 0;
    const uint32_t length = static_cast<uint32_t>(prefixBytes + 6);
    if (!read(rva, length, &instruction) || instruction[prefixBytes] != 0xff || instruction[prefixBytes + 1] != 0x25)
        { return L"unsupported_export_instruction"; }
    if (const auto reason = check(rva, instruction)) { return reason; }
    int32_t displacement = 0;
    std::memcpy(&displacement, instruction.data() + prefixBytes + 2, sizeof(displacement));
    const int64_t slot = static_cast<int64_t>(rva) + length + displacement;
    ImportEntry entry;
    if (slot <= 0 || slot > UINT32_MAX || !FindImport(pe, read, static_cast<uint32_t>(slot), entry))
        { return L"declared_import_slot_unavailable"; }
    declaration = {rva, static_cast<uint32_t>(slot), entry.DescriptorRva, entry.LookupRva,
        mcpjson::Utf8ToWide(entry.Module), mcpjson::Utf8ToWide(entry.Symbol.Name), entry.Symbol.ByOrdinal,
        entry.Symbol.Ordinal, std::move(instruction)};
    return nullptr;
}

std::wstring ImageIatReferenceJson(const std::wstring& exportName, const DirectImageReplayEvidence& evidence,
    const ImageRecipeReplay& replay, const executable_image::DiskPeMetadata& pe, const ReferenceArtifact& reference,
    const std::wstring& claimFileSha256)
{
    const auto& recipe = evidence.Recipe;
    const std::wstring prefix = L"{\"schema\":\"kn.image_iat_reference.v1\",\"export\":" + Quote(exportName) +
        L",\"recipe_sha256\":" + Quote(replay.RecipeSha256) + L",\"reference_sha256\":" + Quote(reference.Sha256()) +
        L",\"claim_publication_sha256\":" + Quote(replay.ClaimPublicationSha256) +
        L",\"claim_file_sha256\":" + Quote(claimFileSha256) +
        L",\"operation_id\":" + Quote(recipe.ReadSet.OperationId) + L",\"target_id\":" + Quote(recipe.ReadSet.TargetId) +
        L",\"address_space_id\":" + Quote(recipe.ReadSet.AddressSpaceId) +
        L",\"slot_value_evaluated\":false,\"execution_observed\":false,\"mapping_lifetime_bound\":false";
    const auto gap = [&](const wchar_t* reason)
    {
        return prefix + L",\"status\":\"unavailable\",\"reason\":" + Quote(reason) + L",\"relation\":null}";
    };
    if (replay.CaptureInterrupted || !evidence.ReferenceQualified || !AssessImageProcessMappings(recipe).NativeImageMappingObserved)
        { return gap(L"native_mapping_or_capture_unqualified"); }
    std::wstring receipts;
    size_t completeReads = 0;
    const auto check = [&](uint32_t rva, const std::vector<uint8_t>& instruction) -> const wchar_t*
    {
        const size_t length = instruction.size();
        if (!Contains(recipe.Rva, recipe.Length, rva, length) || recipe.ImageBase > UINT64_MAX - rva - length)
            { return L"instruction_outside_capture"; }
        const uint64_t address = recipe.ImageBase + rva;
        const auto& coverage = evidence.Comparison.Coverage;
        const auto covers = [&](const ObservationRange& range) { return Contains(range.Address, range.Size, address, length); };
        const auto overlaps = [&](const ObservationRange& range) { return range.Overlaps({rva, length}); };
        std::vector<uint8_t> observed;
        receipts = ByteReceipts(recipe, address, length, completeReads);
        if (receipts.empty() || coverage.RangesTruncated || std::none_of(coverage.Compared.begin(), coverage.Compared.end(), covers) ||
            std::any_of(evidence.NormalizationRanges.begin(), evidence.NormalizationRanges.end(), overlaps) ||
            !ConsistentImageRecipeBytes(recipe, address, length, &observed) || observed != instruction)
            { return L"instruction_bytes_unqualified"; }
        return nullptr;
    };
    ImageIatDeclaration entry;
    if (const auto reason = InspectImageIatDeclaration(exportName, pe, reference.Bytes(), check, entry)) { return gap(reason); }
    std::wstring hex;
    constexpr wchar_t digits[] = L"0123456789abcdef";
    for (const auto byte : entry.Instruction) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
    return prefix + L",\"status\":\"observed\",\"relation\":\"references\",\"basis\":\"export_instruction_to_declared_iat_slot\"" +
        L",\"image_base\":" + N(recipe.ImageBase) + L",\"instruction_rva\":" + N(entry.InstructionRva) +
        L",\"instruction_hex\":" + Quote(hex) + L",\"iat_slot_rva\":" + N(entry.SlotRva) +
        L",\"import_descriptor_rva\":" + N(entry.DescriptorRva) + L",\"import_lookup_rva\":" + N(entry.LookupRva) +
        L",\"import_module\":" + Quote(entry.Module) +
        L",\"import_name\":" + (entry.ByOrdinal ? L"null" : Quote(entry.Name)) +
        L",\"import_ordinal\":" + (entry.ByOrdinal ? N(entry.Ordinal) : L"null") +
        L",\"clock_domain\":\"collector_steady_clock_ms\",\"instruction_reread\":" +
        bounded_observation_json::B(completeReads > 1) + L",\"byte_receipts\":" + receipts + L"}";
}
