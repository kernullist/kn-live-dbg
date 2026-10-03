#pragma once

#include "ExecutableImage.h"

inline bool DeclaredExecutableImagePage(const executable_image::DiskPeMetadata& metadata, uint64_t pageRva)
{
    if (pageRva >= metadata.SizeOfImage)
    {
        return false;
    }
    for (const auto& section : metadata.Sections)
    {
        const uint64_t length = (std::max)(section.VirtualSize, section.SizeOfRawData);
        const uint64_t begin = section.VirtualAddress;
        if (section.Executable && length != 0 && begin < pageRva + 4096 && pageRva < begin + length)
        {
            return true;
        }
    }
    return false;
}

inline bool UnexpectedExecutableImageAddress(const executable_image::DiskPeMetadata& metadata, uint64_t rva)
{
    return rva < metadata.SizeOfImage && !DeclaredExecutableImagePage(metadata, rva & ~4095ull);
}
