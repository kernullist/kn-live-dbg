#pragma once

#include "EtlReferenceBuild.h"

namespace etl_profile
{
    inline constexpr uint32_t MaxReferenceWindow = 32;

    struct ReferenceImage
    {
        SchemaArtifact file;
        executable_image::DiskPeMetadata pe;
        std::wstring leaf;
        ReferenceBuild build;
    };

    enum class FieldComparison { Unavailable, Equal, Different };

    inline FieldComparison CompareField(uint64_t recorded, uint64_t supplied, bool available)
    {
        if (!available) { return FieldComparison::Unavailable; }
        return recorded == supplied ? FieldComparison::Equal : FieldComparison::Different;
    }

    struct MergeFieldComparison
    {
        FieldComparison guid{}, age{}, stamp{};
    };

    inline MergeFieldComparison CompareMergeFields(const ReferenceImage& reference, const BuildPair& pair)
    {
        if (!pair.rsds) { return {}; }
        const auto& file = reference.build;
        auto guid = FieldComparison::Unavailable;
        if (file.valid) { guid = IsEqualGUID(pair.rsds->guid, file.guid) ? FieldComparison::Equal : FieldComparison::Different; }
        return {guid, CompareField(pair.rsds->age, file.age, file.valid),
            CompareField(pair.stamp, reference.pe.TimeDateStamp, BuildStampPresent(pair.stamp))};
    }

    struct ReferenceComparison
    {
        const wchar_t* relation = L"process_image_unavailable";
        FieldComparison name{}, size{}, stamp{}, checksum{};
        const wchar_t* defaultBase = L"unavailable";
        const wchar_t* location = L"uncompared";
        uint64_t offset = 0;
        uint32_t length = 0;
    };

    inline ReferenceComparison CompareReference(const ReferenceImage& reference, const ImageEvent* record,
        std::wstring_view recordedName, uint64_t rva, const BuildPair* build = nullptr)
    {
        ReferenceComparison result;
        if (!record) { return result; }
        const auto sep = recordedName.find_last_of(L"\\/");
        const auto leaf = recordedName.substr(sep == recordedName.npos ? 0 : sep + 1);
        const auto& pe = reference.pe;
        const bool sameLeaf = !leaf.empty() && !reference.leaf.empty() &&
            CompareStringOrdinal(leaf.data(), static_cast<int>(leaf.size()), reference.leaf.data(),
                static_cast<int>(reference.leaf.size()), TRUE) == CSTR_EQUAL;
        result.name = sameLeaf ? FieldComparison::Equal : FieldComparison::Different;
        result.size = CompareField(record->size, pe.SizeOfImage, true);
        result.stamp = CompareField(record->stamp, pe.TimeDateStamp, record->stamp != 0 && record->stamp != UINT32_MAX);
        result.checksum = CompareField(record->checksum, pe.CheckSum, record->checksum != 0);
        const bool diskBase = record->preferred == pe.ImageBase;
        const bool loadBase = record->preferred == record->base;
        if (record->preferred)
        {
            if (diskBase) { result.defaultBase = loadBase ? L"file_preferred_and_recorded_load" : L"file_preferred"; }
            else { result.defaultBase = loadBase ? L"recorded_load" : L"unexplained"; }
        }
        for (auto comparison : {result.name, result.size, result.stamp, result.checksum})
        {
            if (comparison == FieldComparison::Different) { result.relation = L"loader_field_conflict"; return result; }
        }
        if (build)
        {
            const auto fields = CompareMergeFields(reference, *build);
            if (fields.guid == FieldComparison::Unavailable) { result.relation = L"build_id_unavailable"; return result; }
            if (fields.guid == FieldComparison::Different || fields.age == FieldComparison::Different || fields.stamp == FieldComparison::Different)
            { result.relation = L"merge_build_conflict"; return result; }
        }
        else if (result.stamp == FieldComparison::Unavailable && result.checksum == FieldComparison::Unavailable)
        { result.relation = L"build_fields_unavailable"; return result; }

        if (record->preferred && !diskBase && !loadBase) { result.relation = L"default_base_unresolved"; return result; }
        result.relation = L"recorded_fields_agree";
        if (rva >= pe.SizeOfImage) { result.location = L"outside_image"; return result; }
        if (rva < pe.SizeOfHeaders) { result.location = L"pe_headers"; return result; }
        const auto localRva = static_cast<uint32_t>(rva);
        const auto* section = executable_image::FindDiskSectionForRva(pe, localRva);
        if (!section) { result.location = L"section_gap"; return result; }
        if (!section->Executable) { result.location = L"nonexecutable_section"; return result; }
        const auto delta = localRva - section->VirtualAddress;
        // Hash only bytes present in both declared extents. Raw alignment padding
        // and virtual zero-fill cannot supply a file-backed code window.
        const auto extent = (std::min)(section->VirtualSize, section->SizeOfRawData);
        if (delta >= extent || !executable_image::RvaToRawOffset(pe, localRva, &result.offset))
        { result.location = L"outside_file_backed_extent"; return result; }
        result.location = L"executable_file_bytes";
        result.length = (std::min)(MaxReferenceWindow, extent - delta);
        return result;
    }

    inline std::wstring ReferenceWindowHash(const ReferenceImage& reference, const ReferenceComparison& result)
    {
        std::array<uint8_t, MaxReferenceWindow> buffer{};
        DWORD received = 0;
        if (!result.length || result.length > buffer.size() || result.offset > reference.file.Bytes() ||
            result.length > reference.file.Bytes() - result.offset ||
            !approved_file::ReadAt(reference.file.Handle(), result.offset, buffer.data(), result.length, &received) ||
            received != result.length) { return {}; }
        ContentHash hash;
        return hash.Add(buffer.data(), result.length) ? hash.Finish() : std::wstring();
    }
}
