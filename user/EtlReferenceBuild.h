#pragma once

#include "EtlBuildEvidence.h"
#include "ExecutableImage.h"
#include "SchemaArtifact.h"

namespace etl_profile
{
    struct ReferenceBuild
    {
        const wchar_t* status = L"missing_codeview";
        GUID guid{};
        uint32_t age = 0;
        bool valid = false;
    };

    inline ReferenceBuild ReadReferenceBuild(const SchemaArtifact& file, const executable_image::DiskPeMetadata& pe)
    {
        const uint32_t size = pe.DebugDirectorySize;
        if (!size && !pe.DebugDirectoryRva) { return {}; }
        uint64_t dirOffset = 0;
        if (size % sizeof(IMAGE_DEBUG_DIRECTORY) || size > 1024 * sizeof(IMAGE_DEBUG_DIRECTORY) ||
            !FileBackedRvaRange(pe, pe.DebugDirectoryRva, size, dirOffset)) { return {L"invalid_debug_directory"}; }
        auto read = [&](uint64_t offset, void* data, uint32_t bytes) {
            DWORD received = 0;
            return offset <= file.Bytes() && bytes <= file.Bytes() - offset &&
                approved_file::ReadAt(file.Handle(), offset, data, bytes, &received) && received == bytes;
        };
        std::vector<IMAGE_DEBUG_DIRECTORY> entries(size / sizeof(IMAGE_DEBUG_DIRECTORY));
        if (!read(dirOffset, entries.data(), size)) { return {L"invalid_debug_directory"}; }
        const IMAGE_DEBUG_DIRECTORY* cv = nullptr;
        for (const auto& entry : entries)
        {
            if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW) { continue; }
            if (cv) { return {L"multiple_codeview_records"}; }
            cv = &entry;
        }
        if (!cv) { return {}; }
        if (cv->SizeOfData < 4 || cv->SizeOfData > 65536 || !cv->PointerToRawData) { return {L"invalid_codeview"}; }
        uint64_t mapped = 0;
        if (cv->AddressOfRawData && (!FileBackedRvaRange(pe, cv->AddressOfRawData, cv->SizeOfData, mapped) ||
            mapped != cv->PointerToRawData)) { return {L"invalid_codeview"}; }
        std::vector<uint8_t> bytes(cv->SizeOfData);
        if (!read(cv->PointerToRawData, bytes.data(), cv->SizeOfData)) { return {L"invalid_codeview"}; }
        if (std::memcmp(bytes.data(), "RSDS", 4)) { return {L"unsupported_codeview"}; }
        if (bytes.size() < 25 || bytes.back() != 0) { return {L"invalid_codeview"}; }
        const auto terminator = std::find(bytes.begin() + 24, bytes.end(), uint8_t{0});
        if (std::any_of(terminator, bytes.end(), [](uint8_t b) { return b != 0; })) { return {L"invalid_codeview"}; }
        ReferenceBuild result{L"unique_rsds"};
        std::memcpy(&result.guid, bytes.data() + 4, sizeof(GUID));
        std::memcpy(&result.age, bytes.data() + 20, 4);
        if (IsEqualGUID(result.guid, GUID{})) { return {L"empty_debug_id"}; }
        result.valid = true;
        return result;
    }
}
