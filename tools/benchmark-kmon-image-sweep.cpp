// Isolated comparison benchmark. Build with ExecutableImage.cpp and
// ExecutableImageVerifier.cpp, /O2 /std:c++17 /EHsc /DNOMINMAX /I user. No driver or code
// execution: the reader supplies bytes of a synthetic 32 MiB PE image.
#include "ExecutableImageVerifier.h"
#include <cstdio>
#include <cstring>

int main()
{
    constexpr uint32_t codeSize = 32 * 1024 * 1024, codeRva = 0x1000, rawOffset = 0x200;
    constexpr uint64_t base = 0x180000000ull;
    wchar_t directory[MAX_PATH]{}, path[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, directory) || !GetTempFileNameW(directory, L"kmb", 0, path)) { return 1; }
    const auto run = [&]() -> int
    {
        std::vector<uint8_t> disk(rawOffset + codeSize, 0x90);
        std::fill(disk.begin(), disk.begin() + rawOffset, 0);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        std::memcpy(disk.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.ImageBase = base;
        nt.OptionalHeader.AddressOfEntryPoint = codeRva;
        nt.OptionalHeader.SizeOfHeaders = rawOffset;
        nt.OptionalHeader.SizeOfImage = codeRva + codeSize;
        nt.OptionalHeader.SectionAlignment = 0x1000;
        nt.OptionalHeader.FileAlignment = rawOffset;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        std::memcpy(disk.data() + 0x80, &nt, sizeof(nt));
        IMAGE_SECTION_HEADER section{};
        section.VirtualAddress = codeRva;
        section.Misc.VirtualSize = section.SizeOfRawData = codeSize;
        section.PointerToRawData = rawOffset;
        section.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        std::memcpy(disk.data() + 0x80 + sizeof(nt), &section, sizeof(section));
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) { return 2; }
        DWORD written = 0;
        const bool saved = WriteFile(file, disk.data(), static_cast<DWORD>(disk.size()), &written, nullptr) && written == disk.size();
        CloseHandle(file);
        if (!saved) { return 3; }
        executable_image::DiskPeMetadata metadata;
        if (!executable_image::ReadDiskPeMetadata(path, &metadata, nullptr)) { return 4; }
        std::vector<uint8_t> live(codeRva + codeSize, 0);
        std::copy(disk.begin(), disk.begin() + rawOffset, live.begin());
        std::copy(disk.begin() + rawOffset, disk.end(), live.begin() + codeRva);
        LARGE_INTEGER frequency{}; QueryPerformanceFrequency(&frequency);
        for (size_t pass = 0; pass < 4; ++pass)
        {
            // Last pass has a one-byte modification at the far end of the image.
            if (pass == 3) { live.back() ^= 1; }
            size_t reads = 0, turns = 0, modified = 0;
            const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
            {
                ++reads;
                if (address < base || address - base >= live.size() || size > live.size() - (address - base)) { return false; }
                bytes->assign(live.begin() + size_t(address - base), live.begin() + size_t(address - base) + size);
                return true;
            };
            ExecutableSweep sweep;
            if (!sweep.Initialize(metadata)) { return 5; }
            LARGE_INTEGER begin{}, end{}; QueryPerformanceCounter(&begin);
            while (!sweep.Coverage.TraversalComplete && turns < 16384)
            {
                ++turns;
                const auto pages = AdvanceExecutableSweep(path, metadata, base, reader, 1024, GetTickCount64(), &sweep, 25);
                for (const auto& page : pages) { modified += page.Ownership == CodeOwnership::OwnedModified ? 1 : 0; }
            }
            QueryPerformanceCounter(&end);
            if (!sweep.Coverage.Complete() || sweep.Coverage.ComparedBytes != codeSize || modified != (pass == 3 ? 1u : 0u)) { return 6; }
            std::printf("{\"pass\":%zu,\"elapsed_ms\":%.3f,\"turns\":%zu,\"reads\":%zu,\"compared_bytes\":%llu,\"modified_pages\":%zu}\n",
                pass, 1000.0 * double(end.QuadPart - begin.QuadPart) / frequency.QuadPart,
                turns, reads, static_cast<unsigned long long>(sweep.Coverage.ComparedBytes), modified);
        }
        return 0;
    };
    const int result = run();
    DeleteFileW(path);
    return result;
}
