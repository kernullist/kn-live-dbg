#pragma once

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

// Shared PE/reference parsing extracted from the hunt deep-image engine.
namespace executable_image
{
    struct DiskPeSection
    {
        std::wstring Name;
        uint32_t VirtualAddress = 0;
        uint32_t VirtualSize = 0;
        uint32_t PointerToRawData = 0;
        uint32_t SizeOfRawData = 0;
        uint32_t Characteristics = 0;
        bool Executable = false;
        bool Writable = false;
    };

    struct DiskPeMutableRange
    {
        uint32_t Rva = 0;
        uint32_t Size = 0;
    };

    struct DiskPeBaseRelocation
    {
        uint32_t Rva = 0;
        uint32_t Width = 0;
    };

    struct DiskPeMetadata
    {
        BY_HANDLE_FILE_INFORMATION FileIdentity = {};
        FILE_BASIC_INFO FileBasicIdentity = {};
        bool HasFileIdentity = false;
        bool HasFileBasicIdentity = false;
        uint64_t ImageBase = 0;
        uint32_t EntryPointRva = 0;
        uint32_t TimeDateStamp = 0;
        uint32_t CheckSum = 0;
        uint16_t Machine = 0;
        uint16_t OptionalMagic = 0;
        uint32_t PdbRva = 0;
        uint32_t PdbAge = 0;
        GUID PdbGuid = {};
        bool HasPdbIdentity = false;
        uint32_t FirstExecutableSectionRva = 0;
        uint32_t SizeOfHeaders = 0;
        uint32_t SizeOfImage = 0;
        bool HasEntryPoint = false;
        bool HasExecutableSection = false;
        bool ManagedImage = false;
        bool ManagedIlOnly = false;
        std::vector<DiskPeSection> Sections;
        std::set<uint32_t> RelocationPages;
        std::vector<DiskPeBaseRelocation> BaseRelocations;
        std::vector<DiskPeMutableRange> CrossPageRelocationRanges;
        std::vector<DiskPeMutableRange> LoaderMutableRanges;
        std::vector<DiskPeMutableRange> DynamicRelocationRanges;
        uint32_t BaserelocRva = 0;
        uint32_t BaserelocSize = 0;
        bool BaseRelocationTablePresent = false;
        bool BaseRelocationTableComplete = true;
        bool DynamicRelocationTablePresent = false;
        bool DynamicRelocationTableComplete = true;
    };

    bool ReadFileBytesAt(HANDLE file, uint64_t offset, uint32_t length, std::vector<uint8_t>* bytes);
    bool RvaToRawOffset(const DiskPeMetadata& metadata, uint32_t rva, uint64_t* rawOffset);
    const DiskPeSection* FindDiskSectionForRva(const DiskPeMetadata& metadata, uint32_t rva);
    bool ReadDiskBytesForRva(
        HANDLE file,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        uint32_t length,
        std::vector<uint8_t>* bytes);
    bool BytesAreAllZero(
        const std::vector<uint8_t>& bytes);
    void PopulateRelocationPages(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t relocRva,
        uint32_t relocSize);
    void AddLoaderMutableRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size);
    void AddLoaderMutableDirectoryRanges(
        std::vector<DiskPeMutableRange>* ranges,
        const IMAGE_DATA_DIRECTORY* directories,
        uint32_t count);
    bool AddDynamicRelocationRange(
        std::vector<DiskPeMutableRange>* ranges,
        uint32_t rva,
        uint32_t size);
    bool ParseFunctionOverrideBaseRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges);
    bool ParseFunctionOverrideDynamicRelocations(
        const uint8_t* bytes,
        size_t size,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges);
    bool ParseDynamicRelocationTable(
        const std::vector<uint8_t>& bytes,
        bool pe64,
        uint32_t sizeOfImage,
        std::vector<DiskPeMutableRange>* ranges);
    void PopulateDynamicRelocationRanges(
        HANDLE file,
        DiskPeMetadata* metadata,
        uint32_t loadConfigRva,
        uint32_t loadConfigSize,
        bool pe64);
    bool ReadDiskPeMetadata(const std::wstring& rawPath, DiskPeMetadata* metadata, std::wstring* error);
    bool DiskFileIdentityMatches(
        HANDLE file,
        const DiskPeMetadata& metadata);
    bool DiskReferenceIdentityMatches(const std::wstring& path, const DiskPeMetadata& metadata);
    bool ApplyBaseRelocationsToDiskPage(
        const DiskPeMetadata& metadata,
        uint32_t pageRva,
        uint64_t imageDelta,
        std::vector<uint8_t>* pageBytes,
        std::vector<uint8_t>* nextPageBytes);
    bool CopyRawBytesIntoMappedPage(
        HANDLE file,
        uint64_t rawOffset,
        uint64_t pageOffset,
        uint64_t length,
        std::vector<uint8_t>* page);
    bool ReadDiskPageForRva(
        const std::wstring& rawPath,
        const DiskPeMetadata& metadata,
        uint32_t rva,
        std::vector<uint8_t>* page,
        std::wstring* error);
}
