#pragma once

// Owned, inert PE32/PE32+ image views. No entry point, imports or executed code.
#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace secondary_image_fixture
{
    struct Image
    {
        std::wstring Path;
        HANDLE File = INVALID_HANDLE_VALUE;
        HANDLE Section = nullptr;
        void* Primary = nullptr;
        void* Secondary = nullptr;
        bool Created = false;
        bool Pe32 = false;
        uint64_t Preferred = 0;
        uint64_t Relocated = 0;
        uint32_t Width = 0;
        uint32_t HeaderBaseOffset = 0;
        uint32_t CrossRva = 0;
        static constexpr uint32_t CodeRva = 0x1200;
        static constexpr uint32_t SlotRva = 0x1100;

        Image() = default;
        Image(const Image&) = delete;
        Image& operator=(const Image&) = delete;
        ~Image()
        {
            if (Secondary) { UnmapViewOfFile(Secondary); }
            if (Primary) { UnmapViewOfFile(Primary); }
            if (Section) { CloseHandle(Section); }
            if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); }
            if (Created) { DeleteFileW(Path.c_str()); }
        }
        uint64_t Base() const { return reinterpret_cast<uint64_t>(Secondary); }
        uint64_t ReadWord(uint32_t rva) const
        {
            uint64_t value = 0;
            std::memcpy(&value, static_cast<const uint8_t*>(Secondary) + rva, Width);
            return value;
        }
        bool Write(uint32_t rva, const void* bytes, size_t length)
        {
            if (!Secondary || rva >= 0x4000 || length > 0x4000 - rva) { return false; }
            auto address = static_cast<uint8_t*>(Secondary) + rva;
            DWORD old = 0, ignored = 0;
            if (!VirtualProtect(address, length, PAGE_READWRITE, &old)) { return false; }
            std::memcpy(address, bytes, length);
            return VirtualProtect(address, length, old, &ignored) && std::memcmp(address, bytes, length) == 0;
        }
        bool Open(const std::wstring& path, bool pe32)
        {
            Path = path; Pe32 = pe32;
            Preferred = pe32 ? 0x10000000 : 0x180000000ull;
            Width = pe32 ? 4 : 8;
            CrossRva = pe32 ? 0x1FFE : 0x1FFC;
            HeaderBaseOffset = 0x80 + 24 + (pe32 ? 28 : 24);
            std::vector<uint8_t> disk(0x2600, 0);
            IMAGE_DOS_HEADER dos{};
            dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
            std::memcpy(disk.data(), &dos, sizeof(dos));
            const auto header = [&](auto& nt)
            {
                nt.Signature = IMAGE_NT_SIGNATURE;
                nt.FileHeader.Machine = pe32 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
                nt.FileHeader.NumberOfSections = 2;
                nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
                nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL |
                    (pe32 ? IMAGE_FILE_32BIT_MACHINE : IMAGE_FILE_LARGE_ADDRESS_AWARE);
                nt.FileHeader.TimeDateStamp = 0x53454356;
                nt.OptionalHeader.Magic = pe32 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC : IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                nt.OptionalHeader.ImageBase = static_cast<decltype(nt.OptionalHeader.ImageBase)>(Preferred);
                nt.OptionalHeader.SectionAlignment = 0x1000;
                nt.OptionalHeader.FileAlignment = 0x200;
                nt.OptionalHeader.SizeOfHeaders = 0x400;
                nt.OptionalHeader.SizeOfImage = 0x4000;
                nt.OptionalHeader.SizeOfCode = 0x2000;
                nt.OptionalHeader.MajorOperatingSystemVersion = 6;
                nt.OptionalHeader.MajorSubsystemVersion = 6;
                nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
                nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
                nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
                nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x3000, 12};
                std::memcpy(disk.data() + 0x80, &nt, sizeof(nt));
                return 0x80 + sizeof(nt);
            };
            IMAGE_NT_HEADERS32 nt32{};
            IMAGE_NT_HEADERS64 nt64{};
            const auto sectionsOffset = pe32 ? header(nt32) : header(nt64);
            IMAGE_SECTION_HEADER sections[2]{};
            std::memcpy(sections[0].Name, ".text", 5);
            sections[0].VirtualAddress = 0x1000;
            sections[0].Misc.VirtualSize = sections[0].SizeOfRawData = 0x2000;
            sections[0].PointerToRawData = 0x400;
            sections[0].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
            std::memcpy(sections[1].Name, ".reloc", 6);
            sections[1].VirtualAddress = 0x3000;
            sections[1].Misc.VirtualSize = sections[1].SizeOfRawData = 0x200;
            sections[1].PointerToRawData = 0x2400;
            sections[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
            std::memcpy(disk.data() + sectionsOffset, sections, sizeof(sections));
            std::fill(disk.begin() + 0x400, disk.begin() + 0x2400, uint8_t(0x90));
            const uint64_t pointer = Preferred + 0x1800;
            std::memcpy(disk.data() + SlotRva - 0xC00, &pointer, Width);
            std::memcpy(disk.data() + CrossRva - 0xC00, &pointer, Width);
            const IMAGE_BASE_RELOCATION block{0x1000, 12};
            const uint16_t type = pe32 ? 0x3000 : 0xA000;
            const uint16_t slots[] = {uint16_t(type | (SlotRva & 0xFFF)), uint16_t(type | (CrossRva & 0xFFF))};
            std::memcpy(disk.data() + 0x2400, &block, sizeof(block));
            std::memcpy(disk.data() + 0x2408, slots, sizeof(slots));
            File = CreateFileW(Path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (File == INVALID_HANDLE_VALUE) { return false; }
            Created = true;
            DWORD written = 0;
            const bool saved = WriteFile(File, disk.data(), DWORD(disk.size()), &written, nullptr) && written == disk.size();
            CloseHandle(File);
            File = INVALID_HANDLE_VALUE;
            if (!saved) { return false; }
            File = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (File == INVALID_HANDLE_VALUE) { return false; }
            Section = CreateFileMappingW(File, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
            if (!Section) { return false; }
            Primary = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
            Secondary = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
            if (!Primary || !Secondary) { return false; }
            Relocated = ReadWord(HeaderBaseOffset);
            return Relocated != Preferred && Relocated != Base() &&
                ReadWord(SlotRva) == Relocated + 0x1800 && ReadWord(CrossRva) == Relocated + 0x1800;
        }
    };
}
