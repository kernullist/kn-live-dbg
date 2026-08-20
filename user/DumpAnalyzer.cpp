#include "DumpAnalyzer.h"

#include "McpJson.h"
#include "MemoryDumper.h"

#include <Windows.h>
#include <mindumpdef.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>
#include <vector>

namespace
{
    constexpr uint64_t kPageSize = 0x1000ull;
    constexpr uint32_t kMaxDumpModules = 512;
    constexpr uint64_t kKernelSpaceMin4 = 0xffff800000000000ull;
    constexpr uint64_t kKernelSpaceMin5 = 0xff00000000000000ull;
    constexpr uint64_t kPtePhysMask = 0x000ffffffffff000ull;
    constexpr uint64_t kPdeLargePhysMask = 0x000fffffffffe00000ull;
    constexpr uint64_t kPdpteLargePhysMask = 0x000fffffffc0000000ull;
    constexpr uint64_t kCr4Pae = 1ull << 5;
    constexpr uint64_t kCr4La57 = 1ull << 12;
    constexpr uint32_t kDumpAmd64ContextBytes = 0x4D0;
    constexpr uint32_t kSpecialCr3Offset = 0x10;
    constexpr uint32_t kSpecialCr4Offset = 0x18;
    static_assert(
        kDumpAmd64ContextBytes + kSpecialCr4Offset + sizeof(uint64_t) <= DMP_CONTEXT_RECORD_SIZE_64,
        "CR4 must fit in DUMP_HEADER64.ContextRecord");

    std::wstring FourCcText(uint32_t value)
    {
        wchar_t text[5] = {};
        text[0] = static_cast<wchar_t>(value & 0xff);
        text[1] = static_cast<wchar_t>((value >> 8) & 0xff);
        text[2] = static_cast<wchar_t>((value >> 16) & 0xff);
        text[3] = static_cast<wchar_t>((value >> 24) & 0xff);
        return text;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    bool IsKernelCanonicalVa(uint64_t value, uint32_t pagingLevels)
    {
        if (pagingLevels >= 5)
        {
            return value >= kKernelSpaceMin5;
        }
        return value >= kKernelSpaceMin4;
    }

    bool IsCanonicalVa(uint64_t value, uint32_t pagingLevels)
    {
        bool canonical = false;
        do
        {
            if (pagingLevels >= 5)
            {
                const uint64_t high = value >> 57;
                const uint64_t sign = (value >> 56) & 1ull;
                canonical = (sign == 0) ? (high == 0) : (high == 0x7full);
                break;
            }
            const uint64_t high = value >> 48;
            const uint64_t sign = (value >> 47) & 1ull;
            canonical = (sign == 0) ? (high == 0) : (high == 0xffffull);
        } while (false);
        return canonical;
    }

    bool Cr4LooksValid(uint64_t cr4)
    {
        bool valid = false;
        do
        {
            if ((cr4 & kCr4Pae) == 0)
            {
                break;
            }
            if (cr4 == 0 || cr4 == ~0ull)
            {
                break;
            }
            if ((cr4 >> 32) != 0)
            {
                break;
            }
            valid = true;
        } while (false);
        return valid;
    }

    bool TryAddU64(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;
        do
        {
            if (result == nullptr || left > (~0ull - right))
            {
                break;
            }
            *result = left + right;
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadFileBytes(
        std::ifstream& file,
        uint64_t offset,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0)
            {
                break;
            }
            if (offset > static_cast<uint64_t>((std::numeric_limits<std::streamoff>::max)()))
            {
                break;
            }
            bytes->assign(length, 0);
            file.clear();
            file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
            if (!file)
            {
                break;
            }
            file.read(reinterpret_cast<char*>(bytes->data()), static_cast<std::streamsize>(length));
            if (file.gcount() != static_cast<std::streamsize>(length))
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool PhysicalToFileOffset(
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t physical,
        uint64_t* fileOffset,
        uint64_t* remaining)
    {
        bool ok = false;

        do
        {
            if (fileOffset == nullptr)
            {
                break;
            }
            for (const DumpPhysicalRun& run : runs)
            {
                if (physical < run.BaseAddress)
                {
                    continue;
                }
                const uint64_t delta = physical - run.BaseAddress;
                if (delta >= run.ByteCount)
                {
                    continue;
                }
                if (run.FileOffset > (~0ull - delta))
                {
                    continue;
                }
                *fileOffset = run.FileOffset + delta;
                if (remaining != nullptr)
                {
                    *remaining = run.ByteCount - delta;
                }
                ok = true;
                break;
            }
        } while (false);

        return ok;
    }

    bool ReadPhysicalBytes(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t physical,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            uint64_t fileOffset = 0;
            uint64_t remaining = 0;
            if (!PhysicalToFileOffset(runs, physical, &fileOffset, &remaining))
            {
                break;
            }
            if (length == 0 || remaining < length)
            {
                break;
            }
            if (!ReadFileBytes(file, fileOffset, length, bytes))
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool TranslateVa(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t dtb,
        uint64_t va,
        uint32_t pagingLevels,
        uint64_t* physical)
    {
        bool ok = false;

        do
        {
            if (physical == nullptr || (pagingLevels != 4 && pagingLevels != 5))
            {
                break;
            }
            if (!IsCanonicalVa(va, pagingLevels))
            {
                break;
            }

            const uint64_t cr3 = dtb & kPtePhysMask;
            if (cr3 == 0)
            {
                break;
            }
            const uint64_t pml5Index = (va >> 48) & 0x1ffull;
            const uint64_t pml4Index = (va >> 39) & 0x1ffull;
            const uint64_t pdptIndex = (va >> 30) & 0x1ffull;
            const uint64_t pdIndex = (va >> 21) & 0x1ffull;
            const uint64_t ptIndex = (va >> 12) & 0x1ffull;
            const uint64_t pageOffset = va & 0xfffull;

            auto readPte = [&](uint64_t tablePhysical, uint64_t index, uint64_t* entry) -> bool
            {
                if (entry == nullptr || index > 511ull)
                {
                    return false;
                }
                uint64_t entryPhys = 0;
                if (!TryAddU64(tablePhysical, index * 8ull, &entryPhys))
                {
                    return false;
                }
                std::vector<uint8_t> bytes;
                if (!ReadPhysicalBytes(file, runs, entryPhys, 8, &bytes) || bytes.size() != 8)
                {
                    return false;
                }
                memcpy(entry, bytes.data(), sizeof(uint64_t));
                return (*entry & 1ull) != 0;
            };

            uint64_t table = cr3;
            if (pagingLevels >= 5)
            {
                uint64_t pml5e = 0;
                if (!readPte(table, pml5Index, &pml5e))
                {
                    break;
                }
                table = pml5e & kPtePhysMask;
                if (table == 0)
                {
                    break;
                }
            }

            uint64_t pml4e = 0;
            uint64_t pdpte = 0;
            uint64_t pde = 0;
            uint64_t pte = 0;
            if (!readPte(table, pml4Index, &pml4e))
            {
                break;
            }
            table = pml4e & kPtePhysMask;
            if (table == 0)
            {
                break;
            }
            if (!readPte(table, pdptIndex, &pdpte))
            {
                break;
            }
            if ((pdpte & (1ull << 7)) != 0)
            {
                *physical = (pdpte & kPdpteLargePhysMask) + (va & 0x3fffffffull);
                ok = true;
                break;
            }
            table = pdpte & kPtePhysMask;
            if (table == 0)
            {
                break;
            }
            if (!readPte(table, pdIndex, &pde))
            {
                break;
            }
            if ((pde & (1ull << 7)) != 0)
            {
                *physical = (pde & kPdeLargePhysMask) + (va & 0x1fffffull);
                ok = true;
                break;
            }
            table = pde & kPtePhysMask;
            if (table == 0)
            {
                break;
            }
            if (!readPte(table, ptIndex, &pte))
            {
                break;
            }
            *physical = (pte & kPtePhysMask) + pageOffset;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadVirtualU64(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t dtb,
        uint64_t va,
        uint32_t pagingLevels,
        uint64_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }
            uint8_t raw[8] = {};
            uint32_t copied = 0;
            while (copied < 8)
            {
                uint64_t chunkVa = 0;
                if (!TryAddU64(va, copied, &chunkVa))
                {
                    break;
                }
                uint64_t physical = 0;
                if (!TranslateVa(file, runs, dtb, chunkVa, pagingLevels, &physical))
                {
                    break;
                }
                uint64_t fileOffset = 0;
                uint64_t remaining = 0;
                if (!PhysicalToFileOffset(runs, physical, &fileOffset, &remaining) || remaining == 0)
                {
                    break;
                }
                const uint32_t pageLeft = static_cast<uint32_t>(kPageSize - (physical & 0xfffull));
                uint32_t chunk = (std::min)(8u - copied, pageLeft);
                if (remaining < chunk)
                {
                    chunk = static_cast<uint32_t>(remaining);
                }
                if (chunk == 0)
                {
                    break;
                }
                std::vector<uint8_t> bytes;
                if (!ReadFileBytes(file, fileOffset, chunk, &bytes) || bytes.size() != chunk)
                {
                    break;
                }
                memcpy(raw + copied, bytes.data(), bytes.size());
                copied += chunk;
            }
            if (copied != 8)
            {
                break;
            }
            memcpy(value, raw, sizeof(uint64_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadVirtualUnicode(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t dtb,
        uint64_t va,
        uint32_t pagingLevels,
        std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }
            value->clear();
            uint64_t lengthWord = 0;
            uint64_t buffer = 0;
            uint64_t bufferFieldVa = 0;
            if (!TryAddU64(va, 8, &bufferFieldVa) ||
                !ReadVirtualU64(file, runs, dtb, va, pagingLevels, &lengthWord) ||
                !ReadVirtualU64(file, runs, dtb, bufferFieldVa, pagingLevels, &buffer))
            {
                break;
            }
            const uint16_t length = static_cast<uint16_t>(lengthWord & 0xffffull);
            if (length == 0 || buffer == 0)
            {
                ok = true;
                break;
            }
            uint32_t copy = length;
            if ((copy % 2u) != 0)
            {
                --copy;
            }
            if (copy == 0)
            {
                ok = true;
                break;
            }
            if (copy > 512)
            {
                copy = 512;
            }
            std::vector<uint8_t> raw(copy);
            uint32_t copied = 0;
            while (copied < copy)
            {
                uint64_t chunkVa = 0;
                if (!TryAddU64(buffer, copied, &chunkVa))
                {
                    break;
                }
                uint64_t physical = 0;
                if (!TranslateVa(file, runs, dtb, chunkVa, pagingLevels, &physical))
                {
                    break;
                }
                uint64_t fileOffset = 0;
                uint64_t remaining = 0;
                if (!PhysicalToFileOffset(runs, physical, &fileOffset, &remaining) || remaining == 0)
                {
                    break;
                }
                const uint32_t pageLeft = static_cast<uint32_t>(kPageSize - (physical & 0xfffull));
                uint32_t chunk = (std::min)(copy - copied, pageLeft);
                if (remaining < chunk)
                {
                    chunk = static_cast<uint32_t>(remaining);
                }
                if (chunk == 0)
                {
                    break;
                }
                std::vector<uint8_t> bytes;
                if (!ReadFileBytes(file, fileOffset, chunk, &bytes) || bytes.size() != chunk)
                {
                    break;
                }
                memcpy(raw.data() + copied, bytes.data(), bytes.size());
                copied += chunk;
            }
            if (copied >= 2)
            {
                const uint32_t even = copied - (copied % 2u);
                value->assign(
                    reinterpret_cast<const wchar_t*>(raw.data()),
                    even / sizeof(wchar_t));
                ok = true;
            }
        } while (false);

        return ok;
    }

    bool ProbePagingLevel(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t dtb,
        uint64_t listVa,
        uint32_t pagingLevels)
    {
        bool ok = false;

        do
        {
            if (listVa == 0 || dtb == 0)
            {
                break;
            }
            if (!IsCanonicalVa(listVa, pagingLevels) ||
                !IsKernelCanonicalVa(listVa, pagingLevels))
            {
                break;
            }
            uint64_t flink = 0;
            uint64_t blinkVa = 0;
            uint64_t blink = 0;
            if (!ReadVirtualU64(file, runs, dtb, listVa, pagingLevels, &flink) ||
                !TryAddU64(listVa, 8, &blinkVa) ||
                !ReadVirtualU64(file, runs, dtb, blinkVa, pagingLevels, &blink))
            {
                break;
            }
            if (flink == 0 ||
                blink == 0 ||
                !IsCanonicalVa(flink, pagingLevels) ||
                !IsKernelCanonicalVa(flink, pagingLevels) ||
                !IsCanonicalVa(blink, pagingLevels) ||
                !IsKernelCanonicalVa(blink, pagingLevels))
            {
                break;
            }
            uint64_t entryPhysical = 0;
            uint64_t blinkPhysical = 0;
            if (!TranslateVa(file, runs, dtb, flink, pagingLevels, &entryPhysical) ||
                !TranslateVa(file, runs, dtb, blink, pagingLevels, &blinkPhysical))
            {
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    void DetectDumpPagingLevels(
        std::ifstream& file,
        const std::vector<DumpPhysicalRun>& runs,
        uint64_t dtb,
        uint64_t listVa,
        uint64_t cr4,
        bool cr4Valid,
        uint32_t* pagingLevels,
        bool* la57Active,
        std::vector<std::wstring>* warnings)
    {
        do
        {
            if (pagingLevels == nullptr || la57Active == nullptr)
            {
                break;
            }

            uint32_t preferred = 4;
            if (cr4Valid && (cr4 & kCr4La57) != 0)
            {
                preferred = 5;
            }
            if (runs.empty() || dtb == 0 || listVa == 0)
            {
                *pagingLevels = preferred;
                *la57Active = (preferred >= 5);
                break;
            }

            const bool probePreferred = ProbePagingLevel(file, runs, dtb, listVa, preferred);
            const uint32_t other = (preferred == 5) ? 4u : 5u;
            const bool probeOther = ProbePagingLevel(file, runs, dtb, listVa, other);
            uint32_t chosen = preferred;

            if (probePreferred)
            {
                chosen = preferred;
            }
            else if (probeOther)
            {
                chosen = other;
                if (cr4Valid && warnings != nullptr)
                {
                    warnings->push_back(
                        L"CR4.LA57 disagreed with dump page-table probe; using probed paging depth");
                }
            }
            else if (cr4Valid)
            {
                chosen = preferred;
                if (listVa != 0 && warnings != nullptr)
                {
                    warnings->push_back(
                        L"dump page-table probe failed; using CR4 paging depth");
                }
            }
            else
            {
                chosen = 4;
                if (listVa != 0 && warnings != nullptr)
                {
                    warnings->push_back(
                        L"dump page-table probe failed for 4-level and 5-level; assuming 4-level paging");
                }
            }

            if (probePreferred && probeOther && warnings != nullptr)
            {
                warnings->push_back(
                    L"dump page tables probed successfully as both 4-level and 5-level; using CR4 or 4-level default");
            }

            *pagingLevels = chosen;
            *la57Active = (chosen >= 5);
        } while (false);
    }

    constexpr uint64_t kSelfTestListVa = 0xffff800000000000ull;
    constexpr uint64_t kSelfTestEntryVa = kSelfTestListVa + 0x100ull;
    constexpr uint64_t kSelfTestNameVa = kSelfTestListVa + 0x200ull;
    constexpr uint64_t kSelfTestDllBase = 0xfffff80000000000ull;
    constexpr uint32_t kKdSecondaryAmd64Context = 2;

    void WriteBytesAt(std::vector<uint8_t>* buffer, uint64_t offset, const void* data, size_t length)
    {
        do
        {
            if (buffer == nullptr || data == nullptr || length == 0)
            {
                break;
            }
            if (offset > buffer->size() || length > buffer->size() - offset)
            {
                break;
            }
            memcpy(buffer->data() + static_cast<size_t>(offset), data, length);
        } while (false);
    }

    void WriteU64At(std::vector<uint8_t>* buffer, uint64_t offset, uint64_t value)
    {
        WriteBytesAt(buffer, offset, &value, sizeof(value));
    }

    void WriteU16At(std::vector<uint8_t>* buffer, uint64_t offset, uint16_t value)
    {
        WriteBytesAt(buffer, offset, &value, sizeof(value));
    }

    void WritePte(std::vector<uint8_t>* payload, uint64_t tablePa, uint64_t index, uint64_t entry)
    {
        WriteU64At(payload, tablePa + index * 8ull, entry);
    }

    void FillModuleListPage(std::vector<uint8_t>* payload, uint64_t dataPa)
    {
        do
        {
            if (payload == nullptr)
            {
                break;
            }
            WriteU64At(payload, dataPa + 0x00, kSelfTestEntryVa);
            WriteU64At(payload, dataPa + 0x08, kSelfTestEntryVa);
            WriteU64At(payload, dataPa + 0x100, kSelfTestListVa);
            WriteU64At(payload, dataPa + 0x108, kSelfTestListVa);
            WriteU64At(payload, dataPa + 0x130, kSelfTestDllBase);
            WriteU64At(payload, dataPa + 0x140, 0x1000ull);
            WriteU16At(payload, dataPa + 0x148, 24);
            WriteU16At(payload, dataPa + 0x14a, 26);
            WriteU64At(payload, dataPa + 0x150, kSelfTestNameVa);
            WriteU16At(payload, dataPa + 0x158, 24);
            WriteU16At(payload, dataPa + 0x15a, 26);
            WriteU64At(payload, dataPa + 0x160, kSelfTestNameVa);
            const wchar_t name[] = L"ntoskrnl.exe";
            WriteBytesAt(payload, dataPa + 0x200, name, 12 * sizeof(wchar_t));
        } while (false);
    }

    struct DumpRunBlob
    {
        uint64_t BaseAddress = 0;
        std::vector<uint8_t> Bytes;
    };

    bool WriteSyntheticDumpFile(
        const std::wstring& path,
        uint64_t dtb,
        uint64_t psLoadedModuleList,
        uint64_t cr4,
        bool writeCr4,
        uint8_t kdSecondaryVersion,
        const std::vector<DumpRunBlob>& runs)
    {
        bool ok = false;

        do
        {
            if (runs.empty() || runs.size() > kCrashDumpMaxPhysicalRuns)
            {
                break;
            }

            DUMP_HEADER64 header = {};
            header.Signature = DUMP_SIGNATURE64;
            header.ValidDump = DUMP_VALID_DUMP64;
            header.MajorVersion = 15;
            header.DirectoryTableBase = dtb;
            header.PsLoadedModuleList = psLoadedModuleList;
            header.MachineImageType = IMAGE_FILE_MACHINE_AMD64;
            header.NumberProcessors = 1;
            header.DumpType = DUMP_TYPE_FULL;
            header.KdSecondaryVersion = kdSecondaryVersion;

            uint64_t pages = 0;
            bool runsValid = true;
            PHYSICAL_MEMORY_RUN64* runSlot = reinterpret_cast<PHYSICAL_MEMORY_RUN64*>(
                header.PhysicalMemoryBlockBuffer +
                FIELD_OFFSET(PHYSICAL_MEMORY_DESCRIPTOR64, Run));
            for (size_t i = 0; i < runs.size(); ++i)
            {
                if ((runs[i].BaseAddress % kPageSize) != 0 ||
                    runs[i].Bytes.empty() ||
                    (runs[i].Bytes.size() % kPageSize) != 0)
                {
                    runsValid = false;
                    break;
                }
                runSlot[i].BasePage = runs[i].BaseAddress / kPageSize;
                runSlot[i].PageCount = runs[i].Bytes.size() / kPageSize;
                pages += runSlot[i].PageCount;
            }
            if (!runsValid)
            {
                break;
            }
            header.PhysicalMemoryBlock.NumberOfRuns = static_cast<ULONG>(runs.size());
            header.PhysicalMemoryBlock.NumberOfPages = pages;
            header.RequiredDumpSpace.QuadPart =
                static_cast<LONGLONG>(kCrashDumpHeaderBytes + pages * kPageSize);
            if (writeCr4)
            {
                memcpy(
                    header.ContextRecord + kDumpAmd64ContextBytes + kSpecialCr3Offset,
                    &dtb,
                    sizeof(dtb));
                memcpy(
                    header.ContextRecord + kDumpAmd64ContextBytes + kSpecialCr4Offset,
                    &cr4,
                    sizeof(cr4));
            }

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out)
            {
                break;
            }
            out.write(reinterpret_cast<const char*>(&header), sizeof(header));
            for (const DumpRunBlob& run : runs)
            {
                out.write(
                    reinterpret_cast<const char*>(run.Bytes.data()),
                    static_cast<std::streamsize>(run.Bytes.size()));
            }
            if (!out)
            {
                break;
            }
            out.close();
            ok = true;
        } while (false);

        return ok;
    }

    void MapVaTo4k(
        std::vector<uint8_t>* payload,
        uint32_t pagingLevels,
        uint64_t pml5Pa,
        uint64_t pml4Pa,
        uint64_t pdptPa,
        uint64_t pdPa,
        uint64_t ptPa,
        uint64_t dataPa,
        uint64_t va)
    {
        do
        {
            if (payload == nullptr)
            {
                break;
            }
            const uint64_t presentRw = 0x3ull;
            if (pagingLevels >= 5)
            {
                WritePte(payload, pml5Pa, (va >> 48) & 0x1ffull, pml4Pa | presentRw);
            }
            WritePte(payload, pml4Pa, (va >> 39) & 0x1ffull, pdptPa | presentRw);
            WritePte(payload, pdptPa, (va >> 30) & 0x1ffull, pdPa | presentRw);
            WritePte(payload, pdPa, (va >> 21) & 0x1ffull, ptPa | presentRw);
            WritePte(payload, ptPa, (va >> 12) & 0x1ffull, dataPa | presentRw);
        } while (false);
    }

    struct ScopedTempDump
    {
        std::wstring Path;

        ~ScopedTempDump()
        {
            if (!Path.empty())
            {
                DeleteFileW(Path.c_str());
            }
        }
    };

    bool MakeTempDumpPath(std::wstring* path)
    {
        bool ok = false;
        do
        {
            if (path == nullptr)
            {
                break;
            }
            wchar_t dir[MAX_PATH] = {};
            const DWORD dirLen = GetTempPathW(MAX_PATH, dir);
            if (dirLen == 0 || dirLen >= MAX_PATH)
            {
                break;
            }
            wchar_t file[MAX_PATH] = {};
            static uint32_t stamp = 0;
            ++stamp;
            if (swprintf_s(
                    file,
                    L"%skn-pml5-%llu-%u-%u.dmp",
                    dir,
                    static_cast<unsigned long long>(GetTickCount64()),
                    GetCurrentProcessId(),
                    stamp) < 0)
            {
                break;
            }
            *path = file;
            ok = true;
        } while (false);
        return ok;
    }

    bool AnalyzePath(const std::wstring& path, DumpAnalyzeResult* result)
    {
        bool ok = false;
        do
        {
            if (result == nullptr)
            {
                break;
            }
            DumpAnalyzer analyzer(nullptr);
            std::wstring error;
            ok = analyzer.Analyze(path, result, &error);
        } while (false);
        return ok;
    }

    bool ModuleDumpMatches(
        const DumpAnalyzeResult& result,
        uint32_t pagingLevels,
        bool la57Active,
        bool cr4Valid)
    {
        bool ok = false;
        do
        {
            if (!result.HeaderValid ||
                result.PagingLevels != pagingLevels ||
                result.La57Active != la57Active ||
                result.Cr4Valid != cr4Valid ||
                !result.ModulesWalked ||
                result.Modules.size() != 1)
            {
                break;
            }
            if (result.Modules[0].DllBase != kSelfTestDllBase ||
                result.Modules[0].SizeOfImage != 0x1000u ||
                result.Modules[0].BaseName != L"ntoskrnl.exe")
            {
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool BuildModuleDumpRuns(uint32_t pagingLevels, std::vector<DumpRunBlob>* runs, uint64_t* dtb)
    {
        bool ok = false;
        do
        {
            if (runs == nullptr || dtb == nullptr || (pagingLevels != 4 && pagingLevels != 5))
            {
                break;
            }

            uint64_t nextPa = 0x1000;
            uint64_t pml5Pa = 0;
            if (pagingLevels >= 5)
            {
                pml5Pa = nextPa;
                nextPa += kPageSize;
            }
            const uint64_t pml4Pa = nextPa;
            nextPa += kPageSize;
            const uint64_t pdptPa = nextPa;
            nextPa += kPageSize;
            const uint64_t pdPa = nextPa;
            nextPa += kPageSize;
            const uint64_t ptPa = nextPa;
            nextPa += kPageSize;
            const uint64_t dataPa = nextPa;
            nextPa += kPageSize;

            DumpRunBlob run;
            run.BaseAddress = 0;
            run.Bytes.assign(static_cast<size_t>(nextPa), 0);
            MapVaTo4k(
                &run.Bytes,
                pagingLevels,
                pml5Pa,
                pml4Pa,
                pdptPa,
                pdPa,
                ptPa,
                dataPa,
                kSelfTestListVa);
            FillModuleListPage(&run.Bytes, dataPa);
            *dtb = (pagingLevels >= 5) ? pml5Pa : pml4Pa;
            runs->clear();
            runs->push_back(std::move(run));
            ok = true;
        } while (false);
        return ok;
    }

    std::vector<DumpPhysicalRun> RunsFromBlobs(const std::vector<DumpRunBlob>& blobs)
    {
        std::vector<DumpPhysicalRun> runs;
        uint64_t fileOffset = kCrashDumpHeaderBytes;
        for (size_t i = 0; i < blobs.size(); ++i)
        {
            DumpPhysicalRun run = {};
            run.Index = static_cast<uint32_t>(i);
            run.BaseAddress = blobs[i].BaseAddress;
            run.ByteCount = blobs[i].Bytes.size();
            run.BasePage = blobs[i].BaseAddress / kPageSize;
            run.PageCount = blobs[i].Bytes.size() / kPageSize;
            run.FileOffset = fileOffset;
            fileOffset += run.ByteCount;
            runs.push_back(run);
        }
        return runs;
    }

    bool RunDumpPagingWalkSelfTest()
    {
        bool ok = true;

        do
        {
            std::vector<DumpRunBlob> runs4;
            uint64_t dtb4 = 0;
            if (!BuildModuleDumpRuns(4, &runs4, &dtb4))
            {
                ok = false;
                break;
            }

            std::vector<DumpRunBlob> runs5;
            uint64_t dtb5 = 0;
            if (!BuildModuleDumpRuns(5, &runs5, &dtb5))
            {
                ok = false;
                break;
            }

            {
                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb4,
                        kSelfTestListVa,
                        kCr4Pae,
                        true,
                        kKdSecondaryAmd64Context,
                        runs4))
                {
                    ok = false;
                    break;
                }
                DumpAnalyzeResult result = {};
                if (!AnalyzePath(temp.Path, &result) ||
                    !ModuleDumpMatches(result, 4, false, true) ||
                    result.Cr4 != kCr4Pae)
                {
                    ok = false;
                }
            }

            {
                ScopedTempDump temp;
                const uint64_t cr4La57 = kCr4Pae | kCr4La57;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb5,
                        kSelfTestListVa,
                        cr4La57,
                        true,
                        kKdSecondaryAmd64Context,
                        runs5))
                {
                    ok = false;
                    break;
                }
                DumpAnalyzeResult result = {};
                if (!AnalyzePath(temp.Path, &result) ||
                    !ModuleDumpMatches(result, 5, true, true) ||
                    result.Cr4 != cr4La57)
                {
                    ok = false;
                }
            }

            {
                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb5,
                        kSelfTestListVa,
                        0,
                        false,
                        0,
                        runs5))
                {
                    ok = false;
                    break;
                }
                DumpAnalyzeResult result = {};
                if (!AnalyzePath(temp.Path, &result) ||
                    !ModuleDumpMatches(result, 5, true, false))
                {
                    ok = false;
                }
            }

            {
                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb4,
                        kSelfTestListVa,
                        0,
                        false,
                        0,
                        runs4))
                {
                    ok = false;
                    break;
                }
                DumpAnalyzeResult result = {};
                if (!AnalyzePath(temp.Path, &result) ||
                    !ModuleDumpMatches(result, 4, false, false))
                {
                    ok = false;
                }
            }

            {
                ScopedTempDump temp;
                const uint64_t wrongCr4 = kCr4Pae | kCr4La57;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb4,
                        kSelfTestListVa,
                        wrongCr4,
                        true,
                        kKdSecondaryAmd64Context,
                        runs4))
                {
                    ok = false;
                    break;
                }
                DumpAnalyzeResult result = {};
                if (!AnalyzePath(temp.Path, &result) ||
                    result.PagingLevels != 4 ||
                    result.La57Active ||
                    !result.ModulesWalked)
                {
                    ok = false;
                }
                else
                {
                    bool sawDisagree = false;
                    for (const std::wstring& warning : result.Warnings)
                    {
                        if (warning.find(L"disagreed") != std::wstring::npos)
                        {
                            sawDisagree = true;
                            break;
                        }
                    }
                    if (!sawDisagree)
                    {
                        ok = false;
                    }
                }
            }

            {
                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb4,
                        kSelfTestListVa,
                        kCr4Pae,
                        true,
                        kKdSecondaryAmd64Context,
                        runs4))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(runs4);
                uint64_t physical = 0;
                uint64_t value = 0;
                if (!file ||
                    !TranslateVa(file, phys, dtb4, kSelfTestListVa, 4, &physical) ||
                    physical != 0x5000ull ||
                    TranslateVa(file, phys, dtb4, kSelfTestListVa, 5, &physical) ||
                    TranslateVa(file, phys, dtb4, 0x0000800000000000ull, 4, &physical) ||
                    !ReadVirtualU64(file, phys, dtb4, kSelfTestEntryVa + 0x30, 4, &value) ||
                    value != kSelfTestDllBase)
                {
                    ok = false;
                }
                else
                {
                    std::vector<DumpPhysicalRun> truncated = phys;
                    truncated[0].ByteCount = 0x1804ull;
                    uint64_t truncatedPhysical = 0;
                    if (TranslateVa(
                            file,
                            truncated,
                            dtb4,
                            kSelfTestListVa,
                            4,
                            &truncatedPhysical))
                    {
                        ok = false;
                    }
                }
            }

            {
                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb5,
                        kSelfTestListVa,
                        kCr4Pae | kCr4La57,
                        true,
                        kKdSecondaryAmd64Context,
                        runs5))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(runs5);
                uint64_t physical = 0;
                if (!file ||
                    !TranslateVa(file, phys, dtb5, kSelfTestListVa, 5, &physical) ||
                    physical != 0x6000ull ||
                    TranslateVa(file, phys, dtb5, kSelfTestListVa, 4, &physical))
                {
                    ok = false;
                }
            }

            {
                std::vector<uint8_t> tables(0x4000, 0);
                const uint64_t pml4Pa = 0x1000;
                const uint64_t pdptPa = 0x2000;
                const uint64_t pdPa = 0x3000;
                const uint64_t largePa = 0x200000;
                const uint64_t presentPs = 0x81ull;
                WritePte(&tables, pml4Pa, (kSelfTestListVa >> 39) & 0x1ffull, pdptPa | 3ull);
                WritePte(&tables, pdptPa, (kSelfTestListVa >> 30) & 0x1ffull, pdPa | 3ull);
                WritePte(&tables, pdPa, (kSelfTestListVa >> 21) & 0x1ffull, largePa | presentPs);

                std::vector<uint8_t> leaf(kPageSize, 0);
                const uint64_t marker = 0x1122334455667788ull;
                const uint64_t va = kSelfTestListVa + 0x234ull;
                memcpy(leaf.data() + 0x234, &marker, sizeof(marker));

                DumpRunBlob tableRun;
                tableRun.BaseAddress = 0;
                tableRun.Bytes = std::move(tables);
                DumpRunBlob leafRun;
                leafRun.BaseAddress = largePa;
                leafRun.Bytes = std::move(leaf);
                std::vector<DumpRunBlob> blobs;
                blobs.push_back(std::move(tableRun));
                blobs.push_back(std::move(leafRun));

                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        pml4Pa,
                        kSelfTestListVa,
                        kCr4Pae,
                        true,
                        kKdSecondaryAmd64Context,
                        blobs))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(blobs);
                uint64_t physical = 0;
                uint64_t value = 0;
                if (!file ||
                    !TranslateVa(file, phys, pml4Pa, va, 4, &physical) ||
                    physical != (largePa + 0x234ull) ||
                    !ReadVirtualU64(file, phys, pml4Pa, va, 4, &value) ||
                    value != marker)
                {
                    ok = false;
                }
            }

            {
                std::vector<uint8_t> tables(0x5000, 0);
                const uint64_t pml5Pa = 0x1000;
                const uint64_t pml4Pa = 0x2000;
                const uint64_t pdptPa = 0x3000;
                const uint64_t pdPa = 0x4000;
                const uint64_t largePa = 0x200000;
                const uint64_t presentPs = 0x81ull;
                WritePte(&tables, pml5Pa, (kSelfTestListVa >> 48) & 0x1ffull, pml4Pa | 3ull);
                WritePte(&tables, pml4Pa, (kSelfTestListVa >> 39) & 0x1ffull, pdptPa | 3ull);
                WritePte(&tables, pdptPa, (kSelfTestListVa >> 30) & 0x1ffull, pdPa | 3ull);
                WritePte(&tables, pdPa, (kSelfTestListVa >> 21) & 0x1ffull, largePa | presentPs);

                std::vector<uint8_t> leaf(kPageSize, 0);
                const uint64_t marker = 0x99aabbccddeeff00ull;
                const uint64_t va = kSelfTestListVa + 0x234ull;
                memcpy(leaf.data() + 0x234, &marker, sizeof(marker));

                DumpRunBlob tableRun;
                tableRun.BaseAddress = 0;
                tableRun.Bytes = std::move(tables);
                DumpRunBlob leafRun;
                leafRun.BaseAddress = largePa;
                leafRun.Bytes = std::move(leaf);
                std::vector<DumpRunBlob> blobs;
                blobs.push_back(std::move(tableRun));
                blobs.push_back(std::move(leafRun));

                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        pml5Pa,
                        kSelfTestListVa,
                        kCr4Pae | kCr4La57,
                        true,
                        kKdSecondaryAmd64Context,
                        blobs))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(blobs);
                uint64_t physical = 0;
                uint64_t value = 0;
                if (!file ||
                    !TranslateVa(file, phys, pml5Pa, va, 5, &physical) ||
                    physical != (largePa + 0x234ull) ||
                    !ReadVirtualU64(file, phys, pml5Pa, va, 5, &value) ||
                    value != marker)
                {
                    ok = false;
                }
            }

            {
                std::vector<uint8_t> tables(0x3000, 0);
                const uint64_t pml4Pa = 0x1000;
                const uint64_t pdptPa = 0x2000;
                const uint64_t largePa = 0x40000000ull;
                const uint64_t presentPs = 0x81ull;
                WritePte(&tables, pml4Pa, (kSelfTestListVa >> 39) & 0x1ffull, pdptPa | 3ull);
                WritePte(&tables, pdptPa, (kSelfTestListVa >> 30) & 0x1ffull, largePa | presentPs);

                std::vector<uint8_t> leaf(kPageSize, 0);
                const uint64_t marker = 0xaabbccddeeff0011ull;
                const uint64_t va = kSelfTestListVa + 0x234ull;
                memcpy(leaf.data() + 0x234, &marker, sizeof(marker));

                DumpRunBlob tableRun;
                tableRun.BaseAddress = 0;
                tableRun.Bytes = std::move(tables);
                DumpRunBlob leafRun;
                leafRun.BaseAddress = largePa;
                leafRun.Bytes = std::move(leaf);
                std::vector<DumpRunBlob> blobs;
                blobs.push_back(std::move(tableRun));
                blobs.push_back(std::move(leafRun));

                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        pml4Pa,
                        kSelfTestListVa,
                        kCr4Pae,
                        true,
                        kKdSecondaryAmd64Context,
                        blobs))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(blobs);
                uint64_t physical = 0;
                uint64_t value = 0;
                if (!file ||
                    !TranslateVa(file, phys, pml4Pa, va, 4, &physical) ||
                    physical != (largePa + 0x234ull) ||
                    !ReadVirtualU64(file, phys, pml4Pa, va, 4, &value) ||
                    value != marker)
                {
                    ok = false;
                }
            }

            {
                std::vector<DumpRunBlob> runs;
                uint64_t dtb = 0;
                if (!BuildModuleDumpRuns(4, &runs, &dtb))
                {
                    ok = false;
                    break;
                }
                const uint64_t spanVa = kSelfTestListVa + 0xffcull;
                const uint64_t spanValue = 0xa1b2c3d4e5f60718ull;
                WritePte(&runs[0].Bytes, 0x4000ull, 1, 0x6000ull | 3ull);
                runs[0].Bytes.resize(0x7000, 0);
                memcpy(runs[0].Bytes.data() + 0x5ffc, &spanValue, 4);
                memcpy(runs[0].Bytes.data() + 0x6000, reinterpret_cast<const uint8_t*>(&spanValue) + 4, 4);

                ScopedTempDump temp;
                if (!MakeTempDumpPath(&temp.Path) ||
                    !WriteSyntheticDumpFile(
                        temp.Path,
                        dtb,
                        kSelfTestListVa,
                        kCr4Pae,
                        true,
                        kKdSecondaryAmd64Context,
                        runs))
                {
                    ok = false;
                    break;
                }
                std::ifstream file(temp.Path, std::ios::binary);
                const std::vector<DumpPhysicalRun> phys = RunsFromBlobs(runs);
                uint64_t value = 0;
                if (!file ||
                    !ReadVirtualU64(file, phys, dtb, spanVa, 4, &value) ||
                    value != spanValue)
                {
                    ok = false;
                }
            }
        } while (false);

        return ok;
    }
}

DumpAnalyzer::DumpAnalyzer(SymbolEngine* symbols) :
    symbols_(symbols)
{
}

bool DumpAnalyzer::Analyze(const std::wstring& path, DumpAnalyzeResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid dump-analyze result output";
            }
            break;
        }

        *result = DumpAnalyzeResult{};
        result->Path = path;
        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            if (error != nullptr)
            {
                *error = L"could not open dump file";
            }
            break;
        }

        file.seekg(0, std::ios::end);
        const std::streamoff endPos = file.tellg();
        if (endPos < 0)
        {
            if (error != nullptr)
            {
                *error = L"could not determine dump file size";
            }
            break;
        }
        result->FileSize = static_cast<uint64_t>(endPos);
        file.seekg(0, std::ios::beg);
        if (result->FileSize < kCrashDumpHeaderBytes)
        {
            if (error != nullptr)
            {
                *error = L"file is smaller than a DUMP_HEADER64 prefix";
            }
            break;
        }

        std::vector<uint8_t> headerBytes;
        if (!ReadFileBytes(file, 0, kCrashDumpHeaderBytes, &headerBytes))
        {
            if (error != nullptr)
            {
                *error = L"failed to read the 8 KB dump header";
            }
            break;
        }

        const DUMP_HEADER64* header = reinterpret_cast<const DUMP_HEADER64*>(headerBytes.data());
        result->Signature = FourCcText(header->Signature);
        result->ValidDump = FourCcText(header->ValidDump);
        result->MajorVersion = header->MajorVersion;
        result->MinorVersion = header->MinorVersion;
        result->DirectoryTableBase = header->DirectoryTableBase;
        result->PfnDataBase = header->PfnDataBase;
        result->PsLoadedModuleList = header->PsLoadedModuleList;
        result->PsActiveProcessHead = header->PsActiveProcessHead;
        result->KdDebuggerDataBlock = header->KdDebuggerDataBlock;
        result->MachineImageType = header->MachineImageType;
        result->NumberProcessors = header->NumberProcessors;
        result->BugCheckCode = header->BugCheckCode;
        result->BugCheckParameter1 = header->BugCheckParameter1;
        result->BugCheckParameter2 = header->BugCheckParameter2;
        result->BugCheckParameter3 = header->BugCheckParameter3;
        result->BugCheckParameter4 = header->BugCheckParameter4;
        result->DumpType = header->DumpType;
        if (header->Comment[0] != 0)
        {
            std::string comment(header->Comment, strnlen(header->Comment, sizeof(header->Comment)));
            result->Comment.assign(comment.begin(), comment.end());
        }

        if (result->Signature != L"PAGE" || result->ValidDump != L"DU64")
        {
            if (error != nullptr)
            {
                *error = L"dump signature is not PAGE/DU64";
            }
            break;
        }
        result->HeaderValid = true;

        if (header->KdSecondaryVersion == kKdSecondaryAmd64Context)
        {
            memcpy(
                &result->Cr4,
                header->ContextRecord + kDumpAmd64ContextBytes + kSpecialCr4Offset,
                sizeof(uint64_t));
            result->Cr4Valid = Cr4LooksValid(result->Cr4);
            if (result->Cr4Valid)
            {
                uint64_t specialCr3 = 0;
                memcpy(
                    &specialCr3,
                    header->ContextRecord + kDumpAmd64ContextBytes + kSpecialCr3Offset,
                    sizeof(specialCr3));
                const uint64_t special = specialCr3 & kPtePhysMask;
                const uint64_t headerDtb = result->DirectoryTableBase & kPtePhysMask;
                if (special != 0 && headerDtb != 0 && special != headerDtb)
                {
                    result->Cr4Valid = false;
                    result->Warnings.push_back(
                        L"KSPECIAL_REGISTERS.Cr3 does not match DirectoryTableBase; CR4.LA57 not trusted");
                }
            }
        }
        else if (header->KdSecondaryVersion != 0)
        {
            result->Warnings.push_back(
                L"dump KdSecondaryVersion is not 2 (AMD64 CONTEXT+KSPECIAL_REGISTERS); CR4.LA57 not trusted");
        }

        const PHYSICAL_MEMORY_DESCRIPTOR64* block = &header->PhysicalMemoryBlock;
        uint32_t runCount = block->NumberOfRuns;
        if (runCount > kCrashDumpMaxPhysicalRuns)
        {
            result->Warnings.push_back(L"PhysicalMemoryBlock.NumberOfRuns exceeds 42; truncated");
            runCount = kCrashDumpMaxPhysicalRuns;
        }
        result->NumberOfPages = block->NumberOfPages;
        uint64_t fileOffset = kCrashDumpHeaderBytes;
        for (uint32_t i = 0; i < runCount; ++i)
        {
            DumpPhysicalRun run = {};
            run.Index = i;
            run.BasePage = block->Run[i].BasePage;
            run.PageCount = block->Run[i].PageCount;
            if (run.BasePage > (~0ull / kPageSize) ||
                run.PageCount > (~0ull / kPageSize))
            {
                result->Warnings.push_back(L"physical run page range overflowed");
                break;
            }
            run.BaseAddress = run.BasePage * kPageSize;
            run.ByteCount = run.PageCount * kPageSize;
            run.FileOffset = fileOffset;
            if (fileOffset + run.ByteCount < fileOffset)
            {
                result->Warnings.push_back(L"physical run file-offset overflow");
                break;
            }
            fileOffset += run.ByteCount;
            result->Runs.push_back(run);
        }

        uint64_t dllBaseOffset = 0x30;
        uint64_t sizeOffset = 0x40;
        uint64_t baseNameOffset = 0x58;
        uint64_t fullNameOffset = 0x48;
        if (symbols_ != nullptr)
        {
            TypeFieldInfo field = {};
            std::wstring ignored;
            if (symbols_->FindField(L"nt!_KLDR_DATA_TABLE_ENTRY", L"DllBase", &field, &ignored))
            {
                dllBaseOffset = field.Offset;
            }
            else
            {
                result->Warnings.push_back(L"_KLDR_DATA_TABLE_ENTRY.DllBase used fallback offset 0x30");
            }
            if (symbols_->FindField(L"nt!_KLDR_DATA_TABLE_ENTRY", L"SizeOfImage", &field, &ignored))
            {
                sizeOffset = field.Offset;
            }
            if (symbols_->FindField(L"nt!_KLDR_DATA_TABLE_ENTRY", L"BaseDllName", &field, &ignored))
            {
                baseNameOffset = field.Offset;
            }
            if (symbols_->FindField(L"nt!_KLDR_DATA_TABLE_ENTRY", L"FullDllName", &field, &ignored))
            {
                fullNameOffset = field.Offset;
            }
        }
        else
        {
            result->Warnings.push_back(
                L"no symbol engine; KLDR_DATA_TABLE_ENTRY offsets are fallbacks");
        }

        const bool amd64Dump = (result->MachineImageType == 0 ||
            result->MachineImageType == IMAGE_FILE_MACHINE_AMD64);
        if (!amd64Dump)
        {
            result->Warnings.push_back(
                L"dump MachineImageType is not AMD64; VA translation skipped");
        }

        uint32_t pagingLevels = 4;
        bool la57Active = false;
        if (amd64Dump)
        {
            DetectDumpPagingLevels(
                file,
                result->Runs,
                result->DirectoryTableBase,
                result->PsLoadedModuleList,
                result->Cr4,
                result->Cr4Valid,
                &pagingLevels,
                &la57Active,
                &result->Warnings);
        }
        result->PagingLevels = pagingLevels;
        result->La57Active = la57Active;

        if (amd64Dump &&
            result->DirectoryTableBase != 0 &&
            result->PsLoadedModuleList != 0 &&
            IsCanonicalVa(result->PsLoadedModuleList, pagingLevels) &&
            IsKernelCanonicalVa(result->PsLoadedModuleList, pagingLevels))
        {
            uint64_t flink = 0;
            if (ReadVirtualU64(
                    file,
                    result->Runs,
                    result->DirectoryTableBase,
                    result->PsLoadedModuleList,
                    pagingLevels,
                    &flink) &&
                flink != 0)
            {
                uint64_t current = flink;
                uint32_t walked = 0;
                std::vector<uint64_t> seen;
                while (current != 0 &&
                    current != result->PsLoadedModuleList &&
                    IsCanonicalVa(current, pagingLevels) &&
                    IsKernelCanonicalVa(current, pagingLevels) &&
                    walked < kMaxDumpModules)
                {
                    bool cycle = false;
                    for (uint64_t existing : seen)
                    {
                        if (existing == current)
                        {
                            cycle = true;
                            break;
                        }
                    }
                    if (cycle)
                    {
                        result->Warnings.push_back(L"PsLoadedModuleList walk hit a cycle");
                        break;
                    }
                    seen.push_back(current);

                    DumpLoadedModuleRecord module = {};
                    module.Index = walked;
                    module.EntryAddress = current;
                    uint64_t fieldVa = 0;
                    if (TryAddU64(current, dllBaseOffset, &fieldVa))
                    {
                        ReadVirtualU64(
                            file,
                            result->Runs,
                            result->DirectoryTableBase,
                            fieldVa,
                            pagingLevels,
                            &module.DllBase);
                    }
                    uint64_t size = 0;
                    if (TryAddU64(current, sizeOffset, &fieldVa) &&
                        ReadVirtualU64(
                            file,
                            result->Runs,
                            result->DirectoryTableBase,
                            fieldVa,
                            pagingLevels,
                            &size))
                    {
                        module.SizeOfImage = static_cast<uint32_t>(size);
                    }
                    if (TryAddU64(current, baseNameOffset, &fieldVa))
                    {
                        ReadVirtualUnicode(
                            file,
                            result->Runs,
                            result->DirectoryTableBase,
                            fieldVa,
                            pagingLevels,
                            &module.BaseName);
                    }
                    if (TryAddU64(current, fullNameOffset, &fieldVa))
                    {
                        ReadVirtualUnicode(
                            file,
                            result->Runs,
                            result->DirectoryTableBase,
                            fieldVa,
                            pagingLevels,
                            &module.FullName);
                    }
                    result->Modules.push_back(module);
                    ++walked;

                    uint64_t next = 0;
                    if (!ReadVirtualU64(
                            file,
                            result->Runs,
                            result->DirectoryTableBase,
                            current,
                            pagingLevels,
                            &next) ||
                        next == current)
                    {
                        break;
                    }
                    current = next;
                }
                if (walked >= kMaxDumpModules &&
                    current != 0 &&
                    current != result->PsLoadedModuleList)
                {
                    result->Warnings.push_back(
                        L"PsLoadedModuleList walk hit the 512-module cap");
                }
                result->ModulesWalked = !result->Modules.empty();
            }
            else
            {
                result->Warnings.push_back(
                    L"PsLoadedModuleList could not be translated through the dump DTB");
            }
        }
        else if (amd64Dump &&
            result->DirectoryTableBase != 0 &&
            result->PsLoadedModuleList != 0)
        {
            result->Warnings.push_back(
                L"PsLoadedModuleList is not a canonical kernel VA for the detected paging depth");
        }

        result->CoverageComplete = result->HeaderValid && !result->Runs.empty();
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildDumpAnalyzeJson(const DumpAnalyzeResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.dump-analyze.v1\"";
    json << L",\"path\":\"" << mcpjson::Escape(result.Path) << L"\"";
    json << L",\"signature\":\"" << mcpjson::Escape(result.Signature) << L"\"";
    json << L",\"valid_dump\":\"" << mcpjson::Escape(result.ValidDump) << L"\"";
    json << L",\"header_valid\":" << (result.HeaderValid ? L"true" : L"false");
    json << L",\"dtb\":\"" << JsonHex(result.DirectoryTableBase) << L"\"";
    json << L",\"cr4\":\"" << JsonHex(result.Cr4) << L"\"";
    json << L",\"cr4_valid\":" << (result.Cr4Valid ? L"true" : L"false");
    json << L",\"paging_levels\":" << result.PagingLevels;
    json << L",\"la57_active\":" << (result.La57Active ? L"true" : L"false");
    json << L",\"bugcheck\":" << result.BugCheckCode;
    json << L",\"dump_type\":" << result.DumpType;
    json << L",\"pages\":" << result.NumberOfPages;
    json << L",\"runs\":" << result.Runs.size();
    json << L",\"modules\":" << result.Modules.size();
    json << L",\"modules_walked\":" << (result.ModulesWalked ? L"true" : L"false");
    json << L",\"module_list\":[";
    for (size_t i = 0; i < result.Modules.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"{\"base\":\"" << JsonHex(result.Modules[i].DllBase)
             << L"\",\"size\":" << result.Modules[i].SizeOfImage
             << L",\"name\":\"" << mcpjson::Escape(result.Modules[i].BaseName) << L"\"}";
    }
    json << L"],\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << mcpjson::Escape(result.Warnings[i]) << L"\"";
    }
    json << L"]}";
    return json.str();
}

bool DumpHeaderSignatureSelfTest()
{
    bool ok = false;

    do
    {
        if (FourCcText(DUMP_SIGNATURE64) != L"PAGE")
        {
            break;
        }
        if (FourCcText(DUMP_VALID_DUMP64) != L"DU64")
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

bool DumpPagingWalkSelfTest()
{
    return RunDumpPagingWalkSelfTest();
}
