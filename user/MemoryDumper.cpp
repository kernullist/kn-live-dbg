#include "MemoryDumper.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <intrin.h>
#include <mindumpdef.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <cstring>

namespace
{
    constexpr uint32_t kReadChunkBytes = 0x40000;          // 256 KB per IOCTL
    constexpr uint64_t kMaxRawDumpBytes = 0x40000000ull;   // 1 GB sanity cap
    constexpr uint32_t kInitialHeaderBytes = 0x1000;       // 4 KB initial header read
    constexpr uint32_t kMaxHeaderBytes = 0x10000;          // 64 KB upper bound on SizeOfHeaders
    constexpr uint64_t kMaxPeFileSize = 0x20000000ull;     // 512 MB output cap

    bool ReadKernelChunk(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* out,
        std::wstring* error)
    {
        return device.ReadMemory(
            address,
            length,
            out,
            error,
            KNDBG_READ_FLAG_ALLOW_MDL_FALLBACK);
    }

    // Read [address, address+length) into out, chunked. Returns false on first
    // failure unless zeroFillOnFailure is set, in which case the missing tail of
    // the chunk is zero-filled and the read continues. failedChunks is
    // incremented per incomplete chunk; bytesZeroFilled/bytesFromKernel track
    // actual byte counts (not chunk-size approximations).
    bool ReadKernelRange(
        DeviceClient& device,
        uint64_t address,
        uint64_t length,
        bool zeroFillOnFailure,
        std::vector<uint8_t>* out,
        uint32_t* chunksRead,
        uint32_t* chunksFailed,
        uint64_t* bytesFromKernel,
        uint64_t* bytesZeroFilled,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (out == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"ReadKernelRange called without output buffer";
                }
                break;
            }

            out->clear();
            if (bytesFromKernel != nullptr)
            {
                *bytesFromKernel = 0;
            }
            if (bytesZeroFilled != nullptr)
            {
                *bytesZeroFilled = 0;
            }

            if (length == 0)
            {
                ok = true;
                break;
            }

            if (length > kMaxRawDumpBytes)
            {
                if (error != nullptr)
                {
                    *error = L"requested length exceeds 1 GB sanity cap";
                }
                break;
            }

            out->resize(static_cast<size_t>(length), 0);

            uint64_t remaining = length;
            uint64_t offset = 0;
            bool aborted = false;

            while (remaining > 0)
            {
                uint32_t chunk = (remaining > kReadChunkBytes)
                    ? kReadChunkBytes
                    : static_cast<uint32_t>(remaining);

                std::vector<uint8_t> buf;
                std::wstring chunkErr;
                bool readOk = ReadKernelChunk(device,
                                              address + offset,
                                              chunk,
                                              &buf,
                                              &chunkErr);

                const uint32_t got = readOk
                    ? static_cast<uint32_t>(std::min<size_t>(buf.size(), chunk))
                    : 0;
                if (readOk && got < chunk)
                {
                    chunkErr = L"short read (expected " +
                               std::to_wstring(chunk) +
                               L" bytes, got " +
                               std::to_wstring(got) + L")";
                    // Keep the partial payload; only the tail is treated as
                    // missing. Without zerofill this still aborts.
                    if (got > 0)
                    {
                        std::memcpy(out->data() + offset, buf.data(), got);
                        if (bytesFromKernel != nullptr)
                        {
                            *bytesFromKernel += got;
                        }
                    }
                    readOk = false;
                }

                if (!readOk)
                {
                    if (chunksFailed != nullptr)
                    {
                        ++(*chunksFailed);
                    }

                    const uint32_t missing = chunk - got;
                    if (!zeroFillOnFailure)
                    {
                        if (error != nullptr)
                        {
                            std::wstringstream ss;
                            ss << L"ReadMemory failed at va=0x"
                               << std::hex << (address + offset)
                               << L" length=0x" << chunk
                               << L" got=0x" << got
                               << L": " << chunkErr;
                            *error = ss.str();
                        }
                        aborted = true;
                        break;
                    }

                    // Tail already zero from resize; count only missing bytes.
                    if (bytesZeroFilled != nullptr)
                    {
                        *bytesZeroFilled += missing;
                    }
                    offset += chunk;
                    remaining -= chunk;
                    continue;
                }

                if (chunksRead != nullptr)
                {
                    ++(*chunksRead);
                }

                std::memcpy(out->data() + offset, buf.data(), chunk);
                if (bytesFromKernel != nullptr)
                {
                    *bytesFromKernel += chunk;
                }
                offset += chunk;
                remaining -= chunk;
            }

            if (aborted)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool WriteBufferToFile(
        const std::wstring& path,
        const uint8_t* data,
        size_t length,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            std::ofstream out;
            out.open(path.c_str(), std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                if (error != nullptr)
                {
                    *error = L"failed to open output file for writing";
                }
                break;
            }

            if (length > 0)
            {
                out.write(reinterpret_cast<const char*>(data),
                          static_cast<std::streamsize>(length));
                if (!out.good())
                {
                    if (error != nullptr)
                    {
                        *error = L"failed while writing output bytes";
                    }
                    break;
                }
            }

            out.close();
            if (out.fail())
            {
                if (error != nullptr)
                {
                    *error = L"failed to close output file";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    std::wstring HexU32(uint32_t value)
    {
        std::wstringstream ss;
        ss << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << value;
        return ss.str();
    }

    // Plausibility test for "buf[offset] starts an IMAGE_NT_HEADERS instance".
    // Accepts both a present and a wiped Signature so that the caller can use
    // this for malware-erased headers. The remaining FileHeader/OptionalHeader
    // fields must look real.
    bool IsPlausibleNtHeader(const uint8_t* buf, uint32_t totalSize, uint32_t offset)
    {
        bool ok = false;

        do
        {
            // Need bytes up through OptionalHeader.Magic (offset 24 + 2).
            if (static_cast<uint64_t>(offset) + 26 > totalSize)
            {
                break;
            }

            uint32_t sig = 0;
            std::memcpy(&sig, buf + offset, sizeof(sig));
            if (sig != 0 && sig != IMAGE_NT_SIGNATURE)
            {
                break;
            }

            IMAGE_FILE_HEADER fh;
            std::memcpy(&fh, buf + offset + 4, sizeof(fh));
            if (fh.Machine == 0)
            {
                break;
            }
            if (fh.NumberOfSections == 0 || fh.NumberOfSections > 96)
            {
                break;
            }
            if (fh.SizeOfOptionalHeader != 0xF0 && fh.SizeOfOptionalHeader != 0xE0)
            {
                break;
            }

            uint16_t magic = 0;
            std::memcpy(&magic, buf + offset + 24, sizeof(magic));
            if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                break;
            }

            // Cross-check Magic against SizeOfOptionalHeader.
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && fh.SizeOfOptionalHeader != 0xF0)
            {
                break;
            }
            if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && fh.SizeOfOptionalHeader != 0xE0)
            {
                break;
            }

            const uint32_t ntSize = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                ? static_cast<uint32_t>(sizeof(IMAGE_NT_HEADERS64))
                : static_cast<uint32_t>(sizeof(IMAGE_NT_HEADERS32));
            if (static_cast<uint64_t>(offset) + ntSize > totalSize)
            {
                break;
            }

            // SizeOfHeaders / SizeOfImage sanity (these fields live further
            // into OptionalHeader; only check when fully in-buffer). The
            // 256 MB upper bound on SizeOfImage tightens phase-2 false
            // positives -- legitimate kernel/user modules are smaller than
            // that, while random kernel data is likely to set the high bits
            // of a DWORD interpreted as SizeOfImage.
            constexpr uint32_t kMaxPlausibleSizeOfImage = 0x10000000;  // 256 MB
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                if (static_cast<uint64_t>(offset) + sizeof(IMAGE_NT_HEADERS64) <= totalSize)
                {
                    IMAGE_NT_HEADERS64 nt;
                    std::memcpy(&nt, buf + offset, sizeof(nt));
                    if (nt.OptionalHeader.SizeOfHeaders == 0 ||
                        nt.OptionalHeader.SizeOfHeaders > 0x10000)
                    {
                        break;
                    }
                    if (nt.OptionalHeader.SizeOfImage <= nt.OptionalHeader.SizeOfHeaders)
                    {
                        break;
                    }
                    if (nt.OptionalHeader.SizeOfImage > kMaxPlausibleSizeOfImage)
                    {
                        break;
                    }
                }
            }
            else
            {
                if (static_cast<uint64_t>(offset) + sizeof(IMAGE_NT_HEADERS32) <= totalSize)
                {
                    IMAGE_NT_HEADERS32 nt;
                    std::memcpy(&nt, buf + offset, sizeof(nt));
                    if (nt.OptionalHeader.SizeOfHeaders == 0 ||
                        nt.OptionalHeader.SizeOfHeaders > 0x10000)
                    {
                        break;
                    }
                    if (nt.OptionalHeader.SizeOfImage <= nt.OptionalHeader.SizeOfHeaders)
                    {
                        break;
                    }
                    if (nt.OptionalHeader.SizeOfImage > kMaxPlausibleSizeOfImage)
                    {
                        break;
                    }
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    // Locates the IMAGE_NT_HEADERS offset within buf, repairing wiped MZ /
    // PE\0\0 / e_lfanew signatures in-place when the surrounding fields are
    // intact enough to identify the structure. Returns UINT32_MAX on failure.
    uint32_t LocateAndRestoreNtHeaders(std::vector<uint8_t>& buf, DumpPeResult* result)
    {
        uint32_t found = UINT32_MAX;

        do
        {
            if (buf.size() < sizeof(IMAGE_DOS_HEADER))
            {
                break;
            }

            const uint32_t scanCeiling = 0x1000;
            const uint32_t scanEnd = (buf.size() < scanCeiling)
                ? static_cast<uint32_t>(buf.size())
                : scanCeiling;

            IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());

            uint32_t candidate = UINT32_MAX;

            // Phase 1: trust e_lfanew if it points to something plausible. We
            // tolerate a wiped Signature here because IsPlausibleNtHeader
            // accepts a zero Signature alongside the canonical 0x00004550.
            LONG declared = dos->e_lfanew;
            if (declared > 0 && static_cast<uint32_t>(declared) + 26 <= scanEnd)
            {
                if (IsPlausibleNtHeader(buf.data(), scanEnd, static_cast<uint32_t>(declared)))
                {
                    candidate = static_cast<uint32_t>(declared);
                }
            }

            // Phase 2: scan from 0x40 looking for a plausible NT header. We
            // start at 0x40 because the entire DOS header is 0x40 bytes and
            // no legitimate PE places NT headers inside the DOS header proper.
            if (candidate == UINT32_MAX)
            {
                for (uint32_t off = 0x40; off + 26 <= scanEnd; off += 4)
                {
                    if (IsPlausibleNtHeader(buf.data(), scanEnd, off))
                    {
                        candidate = off;
                        break;
                    }
                }
            }

            if (candidate == UINT32_MAX)
            {
                break;
            }

            // Restore wiped fields directly into the in-memory header buffer
            // so the on-disk output ends up with valid signatures. Warnings
            // are emitted only on the first restoration so that a subsequent
            // re-read of the full SizeOfHeaders region (which may again
            // contain the wiped signatures) does not duplicate the message.
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                dos->e_magic = IMAGE_DOS_SIGNATURE;
                if (result != nullptr)
                {
                    if (!result->RestoredDosMagic)
                    {
                        result->Warnings.push_back(
                            L"DOS 'MZ' signature was wiped; restored at offset 0x0");
                    }
                    result->RestoredDosMagic = true;
                }
            }

            if (static_cast<uint32_t>(dos->e_lfanew) != candidate)
            {
                dos->e_lfanew = static_cast<LONG>(candidate);
                if (result != nullptr)
                {
                    if (!result->RestoredELfanew)
                    {
                        result->Warnings.push_back(
                            L"DOS e_lfanew was corrupted; recovered as " + HexU32(candidate));
                    }
                    result->RestoredELfanew = true;
                }
            }

            uint32_t sig = 0;
            std::memcpy(&sig, buf.data() + candidate, sizeof(sig));
            if (sig != IMAGE_NT_SIGNATURE)
            {
                uint32_t restored = IMAGE_NT_SIGNATURE;
                std::memcpy(buf.data() + candidate, &restored, sizeof(restored));
                if (result != nullptr)
                {
                    if (!result->RestoredPeSignature)
                    {
                        result->Warnings.push_back(
                            L"PE\\0\\0 signature was wiped; restored at " + HexU32(candidate));
                    }
                    result->RestoredPeSignature = true;
                }
            }

            if (result != nullptr)
            {
                result->RecoveredNtOffset = candidate;
            }

            found = candidate;
        } while (false);

        return found;
    }

    // Fill PeHeaderProbe metadata from the NT header at the given offset.
    // Caller has already validated plausibility via IsPlausibleNtHeader.
    void PopulateProbeFromNt(const uint8_t* buf, uint32_t totalSize, uint32_t ntOffset, PeHeaderProbe* probe)
    {
        if (probe == nullptr)
        {
            return;
        }

        probe->NtOffset = ntOffset;

        uint16_t magic = 0;
        std::memcpy(&magic, buf + ntOffset + 24, sizeof(magic));
        probe->Is64Bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

        IMAGE_FILE_HEADER fh = {};
        std::memcpy(&fh, buf + ntOffset + 4, sizeof(fh));
        probe->Machine = fh.Machine;
        probe->NumberOfSections = fh.NumberOfSections;
        probe->Characteristics = fh.Characteristics;
        probe->TimeDateStamp = fh.TimeDateStamp;

        if (probe->Is64Bit)
        {
            if (static_cast<uint64_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS64) <= totalSize)
            {
                IMAGE_NT_HEADERS64 nt = {};
                std::memcpy(&nt, buf + ntOffset, sizeof(nt));
                probe->SizeOfHeaders = nt.OptionalHeader.SizeOfHeaders;
                probe->AddressOfEntryPoint =
                    nt.OptionalHeader.AddressOfEntryPoint;
                probe->SizeOfImage = nt.OptionalHeader.SizeOfImage;
                probe->ImageBase = nt.OptionalHeader.ImageBase;
            }
        }
        else
        {
            if (static_cast<uint64_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS32) <= totalSize)
            {
                IMAGE_NT_HEADERS32 nt = {};
                std::memcpy(&nt, buf + ntOffset, sizeof(nt));
                probe->SizeOfHeaders = nt.OptionalHeader.SizeOfHeaders;
                probe->AddressOfEntryPoint =
                    nt.OptionalHeader.AddressOfEntryPoint;
                probe->SizeOfImage = nt.OptionalHeader.SizeOfImage;
                probe->ImageBase = nt.OptionalHeader.ImageBase;
            }
        }
    }

    std::wstring SectionNameToWstring(const unsigned char* name)
    {
        std::wstring result;
        result.reserve(8);
        for (int i = 0; i < 8; ++i)
        {
            unsigned char c = name[i];
            if (c == 0)
            {
                break;
            }
            if (c >= 0x20 && c <= 0x7E)
            {
                result.push_back(static_cast<wchar_t>(c));
            }
            else
            {
                result.push_back(L'?');
            }
        }
        return result;
    }
}

bool ProbeForPeHeader(const uint8_t* buffer, size_t length, PeHeaderProbe* result)
{
    if (result == nullptr)
    {
        return false;
    }

    *result = PeHeaderProbe{};

    if (buffer == nullptr || length < sizeof(IMAGE_DOS_HEADER))
    {
        return false;
    }

    const uint32_t scanCeiling = 0x1000;
    const uint32_t scanEnd = (length < scanCeiling)
        ? static_cast<uint32_t>(length)
        : scanCeiling;

    IMAGE_DOS_HEADER dos = {};
    std::memcpy(&dos, buffer, sizeof(dos));

    uint32_t candidate = UINT32_MAX;

    // Phase 1: e_lfanew direct
    LONG declared = dos.e_lfanew;
    if (declared > 0 && static_cast<uint32_t>(declared) + 26 <= scanEnd)
    {
        if (IsPlausibleNtHeader(buffer, scanEnd, static_cast<uint32_t>(declared)))
        {
            candidate = static_cast<uint32_t>(declared);
        }
    }

    // Phase 2: scan
    if (candidate == UINT32_MAX)
    {
        for (uint32_t off = 0x40; off + 26 <= scanEnd; off += 4)
        {
            if (IsPlausibleNtHeader(buffer, scanEnd, off))
            {
                candidate = off;
                break;
            }
        }
    }

    if (candidate == UINT32_MAX)
    {
        return false;
    }

    result->IsPe = true;
    result->MzWiped = (dos.e_magic != IMAGE_DOS_SIGNATURE);
    result->ELfanewMismatch = (static_cast<uint32_t>(dos.e_lfanew) != candidate);

    uint32_t sig = 0;
    std::memcpy(&sig, buffer + candidate, sizeof(sig));
    result->PeSignatureWiped = (sig != IMAGE_NT_SIGNATURE);

    PopulateProbeFromNt(buffer, scanEnd, candidate, result);

    return true;
}

bool ProbeForPageStartPeHeader(const uint8_t* buffer, size_t length, PeHeaderProbe* result)
{
    if (result == nullptr)
    {
        return false;
    }

    *result = PeHeaderProbe{};
    if (buffer == nullptr || length < sizeof(IMAGE_DOS_HEADER))
    {
        return false;
    }

    const uint32_t scanEnd = (length < 0x1000)
        ? static_cast<uint32_t>(length)
        : 0x1000;

    IMAGE_DOS_HEADER dos = {};
    std::memcpy(&dos, buffer, sizeof(dos));
    LONG declared = dos.e_lfanew;
    if (declared < 0x40 || static_cast<uint32_t>(declared) + 26 > scanEnd)
    {
        return false;
    }
    if (!IsPlausibleNtHeader(buffer, scanEnd, static_cast<uint32_t>(declared)))
    {
        return false;
    }

    IMAGE_FILE_HEADER fileHeader = {};
    std::memcpy(&fileHeader, buffer + declared + 4, sizeof(fileHeader));
    if (fileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        fileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        return false;
    }

    result->IsPe = true;
    result->MzWiped = (dos.e_magic != IMAGE_DOS_SIGNATURE);
    result->ELfanewMismatch = false;
    uint32_t sig = 0;
    std::memcpy(&sig, buffer + declared, sizeof(sig));
    result->PeSignatureWiped = (sig != IMAGE_NT_SIGNATURE);
    PopulateProbeFromNt(buffer, scanEnd, static_cast<uint32_t>(declared), result);
    return true;
}

bool DumpKernelRangeToFile(
    DeviceClient& device,
    uint64_t address,
    uint64_t length,
    const std::wstring& path,
    bool zeroFillOnFailure,
    DumpRawResult* result,
    std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"DumpKernelRangeToFile called without result buffer";
        }
        return false;
    }

    *result = DumpRawResult{};
    result->StartAddress = address;
    result->Length = length;
    result->BytesRequested = length;
    result->ZeroFilledOnFailure = zeroFillOnFailure;

    bool ok = false;

    do
    {
        std::vector<uint8_t> bytes;
        std::wstring readError;
        uint64_t kernelBytes = 0;
        uint64_t zeroBytes = 0;
        bool readOk = ReadKernelRange(device,
                                       address,
                                       length,
                                       zeroFillOnFailure,
                                       &bytes,
                                       &result->ChunksRead,
                                       &result->ChunksFailed,
                                       &kernelBytes,
                                       &zeroBytes,
                                       &readError);

        result->BytesRead = kernelBytes;
        result->BytesZeroFilled = zeroBytes;

        if (!readOk)
        {
            result->ShortRead = true;
            result->Complete = false;
            if (error != nullptr)
            {
                *error = readError +
                         L" (requested=0x" +
                         std::to_wstring(length) +
                         L" kernel_bytes=" +
                         std::to_wstring(kernelBytes) +
                         L" zero_bytes=" +
                         std::to_wstring(zeroBytes) +
                         L"; dump aborted before full transfer)";
            }
            break;
        }

        // With zerofill, output length always equals request; kernel vs zero
        // byte counts come from the actual per-chunk transfer, including short
        // reads that kept a partial payload and zero-filled only the tail.
        const uint64_t total = static_cast<uint64_t>(bytes.size());
        if (result->ChunksFailed > 0 || zeroBytes != 0)
        {
            result->ShortRead = true;
            result->Warnings.push_back(
                L"zero-filled " + std::to_wstring(result->ChunksFailed) +
                L" incomplete chunk(s); kernel_bytes=" + std::to_wstring(result->BytesRead) +
                L" zero_bytes=" + std::to_wstring(result->BytesZeroFilled) +
                L" requested=" + std::to_wstring(length));
        }

        if (total != length)
        {
            result->ShortRead = true;
            result->Warnings.push_back(
                L"output buffer size " + std::to_wstring(total) +
                L" differs from requested " + std::to_wstring(length));
        }

        std::wstring writeError;
        if (!WriteBufferToFile(path, bytes.data(), bytes.size(), &writeError))
        {
            if (error != nullptr)
            {
                *error = writeError +
                         L" (after reading kernel_bytes=" +
                         std::to_wstring(result->BytesRead) +
                         L" zero_bytes=" +
                         std::to_wstring(result->BytesZeroFilled) +
                         L")";
            }
            break;
        }

        result->BytesWritten = bytes.size();
        result->Complete = !result->ShortRead && result->BytesWritten == length;
        ok = true;
    } while (false);

    return ok;
}

bool DumpKernelPeToFile(
    DeviceClient& device,
    uint64_t address,
    const std::wstring& path,
    DumpPeResult* result,
    std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"DumpKernelPeToFile called without result buffer";
        }
        return false;
    }

    *result = DumpPeResult{};
    result->StartAddress = address;

    bool ok = false;
    uint32_t headerChunksRead = 0;
    uint32_t headerChunksFailed = 0;

    do
    {
        // Step 1: read the initial 4 KB to discover SizeOfHeaders, then
        // potentially re-read if SizeOfHeaders > 4 KB.
        std::vector<uint8_t> headerBytes;
        std::wstring readError;
        if (!ReadKernelRange(device,
                             address,
                             kInitialHeaderBytes,
                             false,
                             &headerBytes,
                             &headerChunksRead,
                             &headerChunksFailed,
                             nullptr,
                             nullptr,
                             &readError))
        {
            if (error != nullptr)
            {
                *error = L"failed to read PE header at base: " + readError;
            }
            break;
        }

        if (headerBytes.size() < sizeof(IMAGE_DOS_HEADER))
        {
            if (error != nullptr)
            {
                *error = L"buffer too small for IMAGE_DOS_HEADER";
            }
            break;
        }

        // Run the locator/recovery first. This restores wiped 'MZ', 'PE\\0\\0',
        // and/or corrupted e_lfanew in headerBytes when the remaining FileHeader
        // and OptionalHeader fields are coherent enough to identify the NT
        // header position (a common malware/loader-stomp pattern).
        uint32_t ntOffsetU = LocateAndRestoreNtHeaders(headerBytes, result);
        if (ntOffsetU == UINT32_MAX)
        {
            if (error != nullptr)
            {
                *error = L"could not locate IMAGE_NT_HEADERS even after attempting "
                         L"signature recovery; the headers may be fully wiped or "
                         L"the address does not point at a PE base";
            }
            break;
        }

        uint32_t ntOffset = ntOffsetU;

        const IMAGE_NT_HEADERS64* nt64 =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(headerBytes.data() + ntOffset);

        bool is64 = (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        bool is32 = (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        if (!is64 && !is32)
        {
            std::wstringstream ss;
            ss << L"unsupported OptionalHeader.Magic 0x"
               << std::hex << nt64->OptionalHeader.Magic;
            if (error != nullptr)
            {
                *error = ss.str();
            }
            break;
        }

        uint32_t sizeOfHeaders = 0;
        uint16_t numberOfSections = 0;
        uint64_t sizeOfImage = 0;
        uint64_t imageBase = 0;
        uint16_t machine = 0;
        uint32_t sectionTableOffset = 0;

        if (is64)
        {
            sizeOfHeaders = nt64->OptionalHeader.SizeOfHeaders;
            numberOfSections = nt64->FileHeader.NumberOfSections;
            sizeOfImage = nt64->OptionalHeader.SizeOfImage;
            imageBase = nt64->OptionalHeader.ImageBase;
            machine = nt64->FileHeader.Machine;
            sectionTableOffset = static_cast<uint32_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS64);
        }
        else
        {
            const IMAGE_NT_HEADERS32* nt32 =
                reinterpret_cast<const IMAGE_NT_HEADERS32*>(headerBytes.data() + ntOffset);
            sizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
            numberOfSections = nt32->FileHeader.NumberOfSections;
            sizeOfImage = nt32->OptionalHeader.SizeOfImage;
            imageBase = nt32->OptionalHeader.ImageBase;
            machine = nt32->FileHeader.Machine;
            sectionTableOffset = static_cast<uint32_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS32);
        }

        result->Is64Bit = is64;
        result->SizeOfHeaders = sizeOfHeaders;
        result->NumberOfSections = numberOfSections;
        result->Machine = machine;
        result->ImageBase = imageBase;
        result->SizeOfImage = sizeOfImage;

        // Keep in-memory OptionalHeader/reloc metadata as-is. After ASLR the
        // ImageBase field usually equals the dump VA and no longer matches the
        // on-disk preferred base; say so before offline tools mis-read it.
        result->Warnings.push_back(
            L"PE dump preserves in-memory headers (relocated ImageBase / loader patches); "
            L"this is not a pristine on-disk image copy");
        if (imageBase != 0 && imageBase != address)
        {
            wchar_t detail[192];
            swprintf_s(
                detail,
                L"OptionalHeader.ImageBase=0x%llx differs from dump VA=0x%llx; "
                L"relocation directory may still describe preferred-base fixups",
                static_cast<unsigned long long>(imageBase),
                static_cast<unsigned long long>(address));
            result->Warnings.push_back(detail);
        }

        if (sizeOfHeaders == 0 || sizeOfHeaders > kMaxHeaderBytes)
        {
            if (error != nullptr)
            {
                *error = L"SizeOfHeaders out of plausible range (got " +
                         std::to_wstring(sizeOfHeaders) + L")";
            }
            break;
        }

        if (numberOfSections == 0 || numberOfSections > 96)
        {
            if (error != nullptr)
            {
                *error = L"NumberOfSections out of plausible range (got " +
                         std::to_wstring(numberOfSections) + L")";
            }
            break;
        }

        // Re-read the entire header region if SizeOfHeaders > initial read.
        if (sizeOfHeaders > headerBytes.size())
        {
            std::wstring rereadError;
            if (!ReadKernelRange(device,
                                 address,
                                 sizeOfHeaders,
                                 false,
                                 &headerBytes,
                                 &headerChunksRead,
                                 &headerChunksFailed,
                                 nullptr,
                                 nullptr,
                                 &rereadError))
            {
                if (error != nullptr)
                {
                    *error = L"failed to re-read full PE header: " + rereadError;
                }
                break;
            }

            // Re-apply signature recovery to the freshly-read buffer. The
            // kernel-side memory may still contain wiped signatures, so we
            // patch the new buffer again to keep the eventual file output
            // consistent. The duplicate-warning guard in LocateAndRestoreNt
            // Headers suppresses warnings already reported on the 4 KB pass.
            uint32_t recoveredAgain = LocateAndRestoreNtHeaders(headerBytes, result);
            if (recoveredAgain == UINT32_MAX)
            {
                if (error != nullptr)
                {
                    *error = L"could not relocate NT headers in re-read buffer";
                }
                break;
            }

            // The cached sectionTableOffset / sizeOfHeaders / numberOfSections
            // / is64 fields all depend on the NT header sitting at the
            // originally-discovered offset. If the second pass somehow lands
            // on a different position (kernel memory mutated between IOCTLs,
            // or a phase-2 false positive moved on the re-read), abort rather
            // than write a structurally-inconsistent dump.
            if (recoveredAgain != ntOffset)
            {
                if (error != nullptr)
                {
                    *error = L"NT header position shifted between header reads (was " +
                             HexU32(ntOffset) + L", now " + HexU32(recoveredAgain) +
                             L"); aborting to avoid an inconsistent dump";
                }
                break;
            }
        }

        size_t sectionTableEnd =
            static_cast<size_t>(sectionTableOffset) +
            static_cast<size_t>(numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableEnd > headerBytes.size())
        {
            if (error != nullptr)
            {
                *error = L"section table extends beyond header buffer";
            }
            break;
        }

        const IMAGE_SECTION_HEADER* sections =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(headerBytes.data() + sectionTableOffset);

        // Compute output file size: max of (SizeOfHeaders, max(PointerToRawData + SizeOfRawData)).
        uint64_t outputFileSize = sizeOfHeaders;
        for (uint16_t i = 0; i < numberOfSections; ++i)
        {
            uint64_t end = static_cast<uint64_t>(sections[i].PointerToRawData) +
                           static_cast<uint64_t>(sections[i].SizeOfRawData);
            if (end > outputFileSize)
            {
                outputFileSize = end;
            }
        }

        if (outputFileSize == 0 || outputFileSize > kMaxPeFileSize)
        {
            if (error != nullptr)
            {
                *error = L"computed PE file size out of plausible range (got " +
                         std::to_wstring(outputFileSize) + L")";
            }
            break;
        }

        std::vector<uint8_t> output(static_cast<size_t>(outputFileSize), 0);

        // Copy the in-memory header (loader may have patched a few fields like
        // ImageBase relocation entries, but we keep the in-memory state).
        // For malformed PEs where SizeOfHeaders is smaller than the actual
        // section table end, bump the copy length so the section table makes
        // it into the on-disk image -- otherwise IDA/Ghidra will refuse to
        // parse the result. outputFileSize already includes max(SizeOfHeaders,
        // ...), so the output buffer is large enough.
        size_t headerCopyBytes = sizeOfHeaders;
        if (sectionTableEnd > headerCopyBytes)
        {
            headerCopyBytes = sectionTableEnd;
        }
        if (headerCopyBytes > headerBytes.size())
        {
            headerCopyBytes = headerBytes.size();
        }
        if (headerCopyBytes > output.size())
        {
            headerCopyBytes = output.size();
        }
        std::memcpy(output.data(), headerBytes.data(), headerCopyBytes);

        // For each section, read from address+VirtualAddress and write at
        // PointerToRawData. Failed reads (typically discarded INIT) are
        // zero-filled with a warning.
        for (uint16_t i = 0; i < numberOfSections; ++i)
        {
            DumpedSectionRecord rec;
            rec.Name = SectionNameToWstring(sections[i].Name);
            rec.VirtualAddress = sections[i].VirtualAddress;
            rec.VirtualSize = sections[i].Misc.VirtualSize;
            rec.SizeOfRawData = sections[i].SizeOfRawData;
            rec.PointerToRawData = sections[i].PointerToRawData;
            rec.Characteristics = sections[i].Characteristics;

            do
            {
                if (rec.SizeOfRawData == 0)
                {
                    break;
                }

                uint64_t fileEnd = static_cast<uint64_t>(rec.PointerToRawData) +
                                    static_cast<uint64_t>(rec.SizeOfRawData);
                if (fileEnd > output.size())
                {
                    result->Warnings.push_back(L"section '" + rec.Name +
                                                L"' file range extends past output size; truncated");
                    break;
                }

                // SizeOfImage clamp: don't read past the loaded image.
                uint64_t memEnd = static_cast<uint64_t>(rec.VirtualAddress) +
                                   static_cast<uint64_t>(rec.SizeOfRawData);
                if (sizeOfImage != 0 && memEnd > sizeOfImage)
                {
                    result->Warnings.push_back(L"section '" + rec.Name +
                                                L"' VA range exceeds SizeOfImage; skipped");
                    rec.ZeroFilled = true;
                    break;
                }

                std::vector<uint8_t> sectionBytes;
                std::wstring sectionErr;
                uint32_t sectionChunksRead = 0;
                uint32_t sectionChunksFailed = 0;

                bool readOk = ReadKernelRange(device,
                                              address + rec.VirtualAddress,
                                              rec.SizeOfRawData,
                                              false,
                                              &sectionBytes,
                                              &sectionChunksRead,
                                              &sectionChunksFailed,
                                              nullptr,
                                              nullptr,
                                              &sectionErr);

                if (!readOk)
                {
                    rec.ZeroFilled = true;
                    result->Warnings.push_back(L"failed to read section '" + rec.Name +
                                                L"': " + sectionErr +
                                                L" (zero-filled)");
                    break;
                }

                size_t copyBytes = sectionBytes.size();
                if (copyBytes > rec.SizeOfRawData)
                {
                    copyBytes = rec.SizeOfRawData;
                }

                std::memcpy(output.data() + rec.PointerToRawData,
                             sectionBytes.data(),
                             copyBytes);

                rec.ReadSucceeded = true;
                rec.BytesActuallyRead = static_cast<uint32_t>(copyBytes);
            } while (false);

            result->Sections.push_back(rec);
        }

        result->TotalFileSize = output.size();

        std::wstring writeError;
        if (!WriteBufferToFile(path, output.data(), output.size(), &writeError))
        {
            if (error != nullptr)
            {
                *error = writeError;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    constexpr uint32_t kPageSize = 0x1000;
    constexpr uint32_t kBugCheckLiveSystemDump = 0x161;
    constexpr uint32_t kSysDbgGetLiveKernelDump = 37;
    constexpr uint32_t kLiveDumpControlVersion1 = 1;
    constexpr uint32_t kLiveDumpControlVersion2 = 2;
    constexpr uint64_t kProgressStepBytes = 0x10000000ull; // 256 MB

    static_assert(sizeof(DUMP_HEADER64) == kCrashDumpHeaderBytes,
        "DUMP_HEADER64 must be the 8 KB complete-dump prefix");
    static_assert(offsetof(DUMP_HEADER64, PhysicalMemoryBlock) == 0x088,
        "PhysicalMemoryBlock offset");
    static_assert(offsetof(DUMP_HEADER64, ContextRecord) == 0x348,
        "ContextRecord offset");
    static_assert(offsetof(DUMP_HEADER64, Exception) == 0xF00,
        "Exception offset");
    static_assert(offsetof(DUMP_HEADER64, DumpType) == 0xF98,
        "DumpType must be 0xF98; 0xF94 is the pre-alignment slot WinDbg ignores");
    static_assert(offsetof(DUMP_HEADER64, RequiredDumpSpace) == 0xFA0,
        "RequiredDumpSpace offset");
    static_assert(offsetof(DUMP_HEADER64, SystemTime) == 0xFA8,
        "SystemTime offset");
    static_assert(offsetof(DUMP_HEADER64, Comment) == 0xFB0,
        "Comment offset");
    static_assert(offsetof(DUMP_HEADER64, BugCheckParameter1) == 0x40,
        "BugCheckParameter1 offset");
    static_assert(offsetof(DUMP_HEADER64, ProductType) == 0x1040,
        "ProductType offset");
    static_assert(offsetof(DUMP_HEADER64, SuiteMask) == 0x1044,
        "SuiteMask offset");
    static_assert(offsetof(DUMP_HEADER64, Attributes) == 0x1050,
        "Attributes offset");
    static_assert(offsetof(DUMP_HEADER64, KdSecondaryVersion) == 0x104D,
        "KdSecondaryVersion must be 0x104D");

    // WDBGEXTS.H: 0 = obsolete AMD64 CONTEXT_1, 2 = current CONTEXT.
    // Leaving this 0 makes WinDbg parse ContextRecord as the pre-Vista
    // layout, drop into kd:x86, and truncate KTHREAD to 32 bits.
    constexpr UCHAR kKdSecondaryVersionAmd64Context = 2;
    static_assert(offsetof(PHYSICAL_MEMORY_DESCRIPTOR64, NumberOfPages) == 8,
        "NumberOfPages is 8-byte aligned after NumberOfRuns");
    static_assert(offsetof(PHYSICAL_MEMORY_DESCRIPTOR64, Run) == 16,
        "first PHYSICAL_MEMORY_RUN64 starts at +16");
    static_assert(16 + (kCrashDumpMaxPhysicalRuns * 16) <= 700,
        "42 runs must fit in DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64");

    // DUMP_FILE_ATTRIBUTES bit layout from mindumpdef.h.
    constexpr uint32_t kDumpAttrLiveDumpGenerated = 1u << 4;
    constexpr uint32_t kDumpAttrFilterDumpFile = 1u << 6;
    constexpr uint32_t kDumpAttrProcessFilter =
        kDumpAttrLiveDumpGenerated | kDumpAttrFilterDumpFile;
    constexpr uint32_t kPageTableRootHalfBytes = 256u * 8u;

    constexpr uint32_t kKdbgOwnerTag = 0x4742444B; // 'KDBG'
    constexpr uint32_t kKdbgHeaderTagOffset = 0x10;
    constexpr uint32_t kKdbgHeaderSizeOffset = 0x14;
    // KDDEBUGGER_DATA64 fallbacks from wdbgexts.h (MSVC bitfield packing).
    constexpr uint32_t kKdbgSavedContextOffset = 0x28;
    constexpr uint32_t kKdbgSizePrcbOffset = 0x2B0;
    constexpr uint32_t kKdbgOffsetPrcbProcStateContext = 0x2BC;
    constexpr uint32_t kKdbgOffsetPrcbProcStateSpecialReg = 0x2F2;
    constexpr uint32_t kKdbgOffsetPrcbContext = 0x338;
    constexpr uint32_t kKdbgKernBaseOffset = 0x18;
    // WinDbg with KdSecondaryVersion=2 expects AMD64 CONTEXT (0x4D0) then
    // KSPECIAL_REGISTERS. Do not use sizeof(CONTEXT): a newer SDK CONTEXT
    // can grow and overwrite the special-register block.
    constexpr uint32_t kDumpAmd64ContextBytes = 0x4D0;
    static_assert(sizeof(CONTEXT) >= 0x4D0, "AMD64 CONTEXT shrank below dump layout");
    static_assert(kDumpAmd64ContextBytes + 0xF0 <= DMP_CONTEXT_RECORD_SIZE_64,
        "CONTEXT + KSPECIAL_REGISTERS must fit in ContextRecord[3000]");
    constexpr uint32_t kSpecialCr0Offset = 0x00;
    constexpr uint32_t kSpecialCr2Offset = 0x08;
    constexpr uint32_t kSpecialCr3Offset = 0x10;
    constexpr uint32_t kSpecialCr4Offset = 0x18;
    constexpr uint32_t kSpecialIdtrOffset = 0x60;
    constexpr uint32_t kSpecialCr8Offset = 0xA0;
    constexpr uint32_t kSpecialGsBaseOffset = 0xA8;
    constexpr uint32_t kSpecialGsSwapOffset = 0xB0;
    constexpr uint32_t kSpecialStarOffset = 0xB8;
    constexpr uint32_t kSpecialLstarOffset = 0xC0;
    constexpr uint32_t kSpecialCstarOffset = 0xC8;
    constexpr uint32_t kSpecialFmaskOffset = 0xD0;
    constexpr uint32_t kSpecialFsBaseOffset = 0xE0;
    constexpr uint32_t kSpecialRegistersBytes = 0xF0;
    constexpr uint32_t kKpcrSelfOffset = 0x18;
    constexpr uint32_t kKpcrCurrentPrcbOffset = 0x38;
    constexpr uint32_t kKprcbCurrentThreadFallback = 0x08;
    constexpr uint32_t kKprcbNextThreadFallback = 0x10;
    constexpr uint32_t kKprcbIdleThreadFallback = 0x18;

    bool IsKernelCanonicalVa(uint64_t address)
    {
        return address >= 0xff00000000000000ull;
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        std::wstring ignored;
        return device.ReadMemory(address, length, bytes, &ignored) &&
            bytes != nullptr &&
            bytes->size() >= length;
    }

    bool ReadKernelU32(DeviceClient& device, uint64_t address, uint32_t* value)
    {
        std::vector<uint8_t> bytes;
        if (value == nullptr || !ReadKernelBytes(device, address, sizeof(*value), &bytes))
        {
            return false;
        }

        std::memcpy(value, bytes.data(), sizeof(*value));
        return true;
    }

    bool ReadKernelU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (value == nullptr || !ReadKernelBytes(device, address, sizeof(*value), &bytes))
        {
            return false;
        }

        std::memcpy(value, bytes.data(), sizeof(*value));
        return true;
    }

    void WriteU64Raw(std::vector<uint8_t>* buffer, size_t offset, uint64_t value)
    {
        if (buffer != nullptr && offset + sizeof(value) <= buffer->size())
        {
            std::memcpy(buffer->data() + offset, &value, sizeof(value));
        }
    }

    bool ResolveOptionalSymbol(
        SymbolEngine& symbols,
        const wchar_t* name,
        uint64_t* address,
        std::vector<std::wstring>* warnings);
    bool WriteAll(HANDLE file, const void* data, DWORD length, std::wstring* error);
    uint64_t MaskDirectoryTableBase(uint64_t value);
    uint64_t RangeEnd(uint64_t base, uint64_t count);
    bool ReadFieldU64(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t object,
        const wchar_t* typeName,
        const wchar_t* fieldName,
        const uint32_t* fallbackOffset,
        uint64_t* value);
    uint64_t ResolveKpcrPrcb(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t kpcr);
    uint64_t ResolvePrcbIdleThread(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t prcb);
    bool SynthesizeIdleTrapFrame(
        HANDLE file,
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t directoryTableBase,
        uint64_t idleThread,
        uint64_t rip,
        uint64_t rsp,
        std::wstring* error);

    bool ModuleNameIsNt(const std::wstring& imageName)
    {
        return _wcsicmp(imageName.c_str(), L"ntoskrnl.exe") == 0 ||
            _wcsicmp(imageName.c_str(), L"ntkrnlmp.exe") == 0 ||
            _wcsicmp(imageName.c_str(), L"ntkrnlpa.exe") == 0 ||
            _wcsicmp(imageName.c_str(), L"ntkrpamp.exe") == 0;
    }

    const KernelModuleInfo* FindNtModule(SymbolEngine& symbols)
    {
        const KernelModuleInfo* nt = nullptr;
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            if (ModuleNameIsNt(module.ImageName))
            {
                nt = &module;
                break;
            }
        }

        return nt;
    }

    bool KdbgLooksPlausible(DeviceClient& device, uint64_t address, uint64_t ntBase)
    {
        bool ok = false;

        do
        {
            if (!IsKernelCanonicalVa(address))
            {
                break;
            }

            uint32_t tag = 0;
            uint32_t size = 0;
            uint64_t kernBase = 0;
            if (!ReadKernelU32(device, address + kKdbgHeaderTagOffset, &tag) ||
                !ReadKernelU32(device, address + kKdbgHeaderSizeOffset, &size) ||
                !ReadKernelU64(device, address + kKdbgKernBaseOffset, &kernBase))
            {
                break;
            }

            if (tag == kKdbgOwnerTag &&
                size >= 0x200 &&
                size <= 0x800)
            {
                ok = true;
                break;
            }

            // Encoded KDBG still has to sit in readable kernel memory. Accept
            // a symbol/list hit when the first 0x20 bytes can be read.
            if (ntBase != 0 &&
                IsKernelCanonicalVa(kernBase) &&
                (kernBase == ntBase || tag != 0 || size != 0))
            {
                ok = true;
            }
        } while (false);

        return ok;
    }

    bool ScanNtForUnencodedKdbg(
        DeviceClient& device,
        uint64_t ntBase,
        uint32_t ntSize,
        uint64_t* address)
    {
        bool ok = false;

        do
        {
            if (address == nullptr || ntBase == 0 || ntSize < 0x40)
            {
                break;
            }

            const uint32_t chunk = 0x10000;
            uint32_t offset = 0;
            while (offset + 0x20 < ntSize)
            {
                uint32_t want = chunk;
                if (want > ntSize - offset)
                {
                    want = ntSize - offset;
                }

                std::vector<uint8_t> bytes;
                if (!ReadKernelBytes(device, ntBase + offset, want, &bytes))
                {
                    offset += chunk;
                    continue;
                }

                const size_t limit = bytes.size() >= 0x20 ? (bytes.size() - 0x20) : 0;
                for (size_t index = 0; index + 4 <= bytes.size(); index += 8)
                {
                    if (index > limit)
                    {
                        break;
                    }

                    uint32_t tag = 0;
                    std::memcpy(&tag, bytes.data() + index, sizeof(tag));
                    if (tag != kKdbgOwnerTag)
                    {
                        continue;
                    }

                    if (index < kKdbgHeaderTagOffset)
                    {
                        continue;
                    }

                    const uint64_t candidate =
                        ntBase + offset + index - kKdbgHeaderTagOffset;
                    if (KdbgLooksPlausible(device, candidate, ntBase))
                    {
                        *address = candidate;
                        ok = true;
                        break;
                    }
                }

                if (ok)
                {
                    break;
                }

                offset += chunk;
            }
        } while (false);

        return ok;
    }

    uint64_t ResolveKdDebuggerDataBlock(
        DeviceClient& device,
        SymbolEngine& symbols,
        std::vector<std::wstring>* warnings)
    {
        uint64_t kdBlock = 0;
        const KernelModuleInfo* nt = FindNtModule(symbols);

        uint64_t symbolBlock = 0;
        if (ResolveOptionalSymbol(symbols, L"nt!KdDebuggerDataBlock", &symbolBlock, warnings) &&
            KdbgLooksPlausible(device, symbolBlock, nt != nullptr ? nt->Base : 0))
        {
            kdBlock = symbolBlock;
        }
        else if (symbolBlock != 0 && IsKernelCanonicalVa(symbolBlock))
        {
            // Public PDBs often give the right VA even when the block is
            // encoded and OwnerTag does not read back as 'KDBG'.
            kdBlock = symbolBlock;
        }

        if (kdBlock == 0)
        {
            uint64_t listHead = 0;
            ResolveOptionalSymbol(symbols, L"nt!KdpDebuggerDataListHead", &listHead, warnings);
            uint64_t flink = 0;
            if (listHead != 0 &&
                ReadKernelU64(device, listHead, &flink) &&
                IsKernelCanonicalVa(flink) &&
                flink != listHead)
            {
                kdBlock = flink;
            }
        }

        if (kdBlock == 0 && nt != nullptr)
        {
            uint64_t scanned = 0;
            if (ScanNtForUnencodedKdbg(device, nt->Base, nt->Size, &scanned))
            {
                kdBlock = scanned;
            }
        }

        if (kdBlock == 0 && warnings != nullptr)
        {
            warnings->push_back(
                L"KdDebuggerDataBlock was not resolved; WinDbg will not have KDBG offsets");
        }

        return kdBlock;
    }

    uint64_t Rol64(uint64_t value, unsigned bits)
    {
        return _rotl64(value, bits & 63);
    }

    uint64_t Ror64(uint64_t value, unsigned bits)
    {
        return _rotr64(value, bits & 63);
    }

    void TransformKdbgBlock(
        std::vector<uint8_t>* block,
        uint64_t waitNever,
        uint64_t waitAlways,
        uint64_t swapXor,
        bool decode)
    {
        if (block == nullptr || block->size() < 8)
        {
            return;
        }

        const unsigned rotate = static_cast<unsigned>(waitNever & 0xFFu);
        const size_t count = block->size() / sizeof(uint64_t);
        for (size_t index = 0; index < count; ++index)
        {
            uint64_t entry = 0;
            std::memcpy(&entry, block->data() + (index * sizeof(entry)), sizeof(entry));
            if (decode)
            {
                entry ^= waitNever;
                entry = Rol64(entry, rotate);
                entry ^= swapXor;
                entry = _byteswap_uint64(entry);
                entry ^= waitAlways;
            }
            else
            {
                entry ^= waitAlways;
                entry = _byteswap_uint64(entry);
                entry ^= swapXor;
                entry = Ror64(entry, rotate);
                entry ^= waitNever;
            }

            std::memcpy(block->data() + (index * sizeof(entry)), &entry, sizeof(entry));
        }
    }

    bool KdbgTagIsPlain(const std::vector<uint8_t>& block)
    {
        uint32_t tag = 0;
        if (block.size() < kKdbgHeaderTagOffset + sizeof(tag))
        {
            return false;
        }

        std::memcpy(&tag, block.data() + kKdbgHeaderTagOffset, sizeof(tag));
        return tag == kKdbgOwnerTag;
    }

    bool DecodeEncodedKdbg(
        std::vector<uint8_t>* block,
        uint64_t waitNever,
        uint64_t waitAlways,
        uint64_t encodedFlagAddress,
        uint64_t kdbgAddress)
    {
        bool ok = false;
        if (block == nullptr)
        {
            return ok;
        }

        const uint64_t candidates[] = {
            encodedFlagAddress | 0xffff000000000000ull,
            encodedFlagAddress,
            kdbgAddress | 0xffff000000000000ull,
            kdbgAddress
        };
        const std::vector<uint8_t> original = *block;
        for (uint64_t swapXor : candidates)
        {
            *block = original;
            TransformKdbgBlock(block, waitNever, waitAlways, swapXor, true);
            if (KdbgTagIsPlain(*block))
            {
                ok = true;
                break;
            }
        }

        if (!ok)
        {
            *block = original;
        }

        return ok;
    }

    uint32_t PlainKdbgSize(const std::vector<uint8_t>& block)
    {
        uint32_t size = 0;
        if (block.size() >= kKdbgHeaderSizeOffset + sizeof(size))
        {
            std::memcpy(&size, block.data() + kKdbgHeaderSizeOffset, sizeof(size));
        }

        if (size < 0x200 || size > 0x800 || size > block.size())
        {
            size = static_cast<uint32_t>((std::min)(block.size(), static_cast<size_t>(0x400)));
        }

        size &= ~7u;
        return size;
    }

    bool PhysicalToDumpOffset(
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t physicalAddress,
        uint64_t* dumpOffset)
    {
        bool ok = false;

        do
        {
            if (dumpOffset == nullptr)
            {
                break;
            }

            uint64_t cursor = kCrashDumpHeaderBytes;
            for (const PhysicalMemoryRange& range : ranges)
            {
                const uint64_t rangeEnd = RangeEnd(range.BaseAddress, range.ByteCount);
                if (physicalAddress >= range.BaseAddress && physicalAddress < rangeEnd)
                {
                    *dumpOffset = cursor + (physicalAddress - range.BaseAddress);
                    ok = true;
                    break;
                }

                cursor += range.ByteCount;
            }
        } while (false);

        return ok;
    }

    bool WriteDumpVirtualRange(
        HANDLE file,
        DeviceClient& device,
        uint64_t directoryTableBase,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t virtualAddress,
        const uint8_t* data,
        uint32_t length,
        std::wstring* error,
        const wchar_t* what = L"virtual")
    {
        bool ok = false;

        do
        {
            if (file == INVALID_HANDLE_VALUE || data == nullptr || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid dump-virtual patch request";
                }
                break;
            }

            const wchar_t* tag = (what != nullptr && what[0] != 0) ? what : L"virtual";
            uint32_t done = 0;
            bool failed = false;
            while (done < length)
            {
                PhysicalTranslationInfo translation = {};
                std::wstring translateError;
                if (!device.TranslateVirtual(
                        directoryTableBase,
                        virtualAddress + done,
                        length - done,
                        &translation,
                        &translateError) ||
                    translation.TranslatedLength == 0 ||
                    translation.PhysicalAddress == 0)
                {
                    if (error != nullptr)
                    {
                        std::wstringstream stream;
                        stream << tag << L" VA 0x" << std::hex << (virtualAddress + done)
                               << L" did not translate: " << translateError;
                        *error = stream.str();
                    }
                    failed = true;
                    break;
                }

                uint32_t chunk = translation.TranslatedLength;
                if (chunk > length - done)
                {
                    chunk = length - done;
                }

                uint64_t dumpOffset = 0;
                if (!PhysicalToDumpOffset(ranges, translation.PhysicalAddress, &dumpOffset))
                {
                    if (error != nullptr)
                    {
                        *error = std::wstring(tag) + L" physical page is outside dumped RAM runs";
                    }
                    failed = true;
                    break;
                }

                LARGE_INTEGER position = {};
                position.QuadPart = static_cast<LONGLONG>(dumpOffset);
                if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
                {
                    if (error != nullptr)
                    {
                        *error = L"SetFilePointerEx failed while patching KDBG";
                    }
                    failed = true;
                    break;
                }

                std::wstring writeError;
                if (!WriteAll(file, data + done, chunk, &writeError))
                {
                    if (error != nullptr)
                    {
                        *error = writeError;
                    }
                    failed = true;
                    break;
                }

                done += chunk;
            }

            if (!failed && done == length)
            {
                ok = true;
            }
        } while (false);

        return ok;
    }

    bool WriteDumpPhysicalBytes(
        HANDLE file,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t physicalAddress,
        const uint8_t* data,
        uint32_t length,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (file == INVALID_HANDLE_VALUE || data == nullptr || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid dump-physical patch request";
                }
                break;
            }

            uint64_t dumpOffset = 0;
            if (!PhysicalToDumpOffset(ranges, physicalAddress, &dumpOffset))
            {
                if (error != nullptr)
                {
                    *error = L"physical page is outside dumped RAM runs";
                }
                break;
            }

            uint64_t remainingInRun = 0;
            for (const PhysicalMemoryRange& range : ranges)
            {
                const uint64_t rangeEnd = RangeEnd(range.BaseAddress, range.ByteCount);
                if (physicalAddress >= range.BaseAddress && physicalAddress < rangeEnd)
                {
                    remainingInRun = rangeEnd - physicalAddress;
                    break;
                }
            }

            if (remainingInRun < length)
            {
                if (error != nullptr)
                {
                    *error = L"dump physical write crosses a run boundary";
                }
                break;
            }

            LARGE_INTEGER position = {};
            position.QuadPart = static_cast<LONGLONG>(dumpOffset);
            if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
            {
                if (error != nullptr)
                {
                    *error = L"SetFilePointerEx failed while patching dump page";
                }
                break;
            }

            if (!WriteAll(file, data, length, error))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadDumpPhysicalBytes(
        HANDLE file,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t physicalAddress,
        uint32_t length,
        void* data,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (file == INVALID_HANDLE_VALUE || data == nullptr || length == 0)
            {
                break;
            }

            uint64_t dumpOffset = 0;
            if (!PhysicalToDumpOffset(ranges, physicalAddress, &dumpOffset))
            {
                if (error != nullptr)
                {
                    *error = L"physical page is outside dumped RAM runs";
                }
                break;
            }

            uint64_t remainingInRun = 0;
            for (const PhysicalMemoryRange& range : ranges)
            {
                const uint64_t rangeEnd = RangeEnd(range.BaseAddress, range.ByteCount);
                if (physicalAddress >= range.BaseAddress && physicalAddress < rangeEnd)
                {
                    remainingInRun = rangeEnd - physicalAddress;
                    break;
                }
            }

            if (remainingInRun < length)
            {
                if (error != nullptr)
                {
                    *error = L"dump physical read crosses a run boundary";
                }
                break;
            }

            LARGE_INTEGER position = {};
            position.QuadPart = static_cast<LONGLONG>(dumpOffset);
            if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
            {
                if (error != nullptr)
                {
                    *error = L"SetFilePointerEx failed while reading dump page";
                }
                break;
            }

            DWORD got = 0;
            if (!ReadFile(file, data, length, &got, nullptr) || got != length)
            {
                if (error != nullptr)
                {
                    *error = L"ReadFile failed while reading dump page";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool TranslateToDumpPhysical(
        DeviceClient& device,
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint64_t* physicalAddress)
    {
        bool ok = false;

        do
        {
            if (physicalAddress == nullptr)
            {
                break;
            }

            *physicalAddress = 0;
            PhysicalTranslationInfo translation = {};
            if (device.TranslateVirtual(
                    directoryTableBase,
                    virtualAddress,
                    8,
                    &translation,
                    nullptr) &&
                translation.PhysicalAddress != 0 &&
                translation.TranslatedLength != 0)
            {
                *physicalAddress = translation.PhysicalAddress;
                ok = true;
                break;
            }

            if (device.TranslateVirtual(0, virtualAddress, 8, &translation, nullptr) &&
                translation.PhysicalAddress != 0 &&
                translation.TranslatedLength != 0)
            {
                *physicalAddress = translation.PhysicalAddress;
                ok = true;
            }
        } while (false);

        return ok;
    }

    bool PatchDumpHeaderContext(
        HANDLE file,
        uint64_t rip,
        uint64_t rsp,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (file == INVALID_HANDLE_VALUE || rip == 0)
            {
                break;
            }

            const uint16_t kernelCs = 0x10;
            const uint32_t flags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
            const struct
            {
                LONGLONG Offset;
                const void* Data;
                DWORD Length;
            } writes[] = {
                {
                    static_cast<LONGLONG>(
                        offsetof(DUMP_HEADER64, ContextRecord) + offsetof(CONTEXT, Rip)),
                    &rip,
                    sizeof(rip)
                },
                {
                    static_cast<LONGLONG>(
                        offsetof(DUMP_HEADER64, ContextRecord) + offsetof(CONTEXT, Rsp)),
                    &rsp,
                    sizeof(rsp)
                },
                {
                    static_cast<LONGLONG>(
                        offsetof(DUMP_HEADER64, ContextRecord) + offsetof(CONTEXT, SegCs)),
                    &kernelCs,
                    sizeof(kernelCs)
                },
                {
                    static_cast<LONGLONG>(
                        offsetof(DUMP_HEADER64, ContextRecord) + offsetof(CONTEXT, ContextFlags)),
                    &flags,
                    sizeof(flags)
                },
                {
                    static_cast<LONGLONG>(
                        offsetof(DUMP_HEADER64, Exception) + offsetof(EXCEPTION_RECORD64, ExceptionAddress)),
                    &rip,
                    sizeof(rip)
                }
            };

            bool failed = false;
            for (const auto& write : writes)
            {
                LARGE_INTEGER position = {};
                position.QuadPart = write.Offset;
                if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN) ||
                    !WriteAll(file, write.Data, write.Length, error))
                {
                    failed = true;
                    break;
                }
            }

            ok = !failed;
        } while (false);

        return ok;
    }

    bool PatchDumpFileContextRip(
        HANDLE file,
        DeviceClient& device,
        uint64_t directoryTableBase,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t contextVa,
        uint64_t replacementRip,
        bool requireContextShape,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;

        do
        {
            if (contextVa == 0 || replacementRip == 0)
            {
                break;
            }

            uint64_t physical = 0;
            if (!TranslateToDumpPhysical(device, directoryTableBase, contextVa, &physical))
            {
                if (warnings != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"dump-file CONTEXT VA 0x" << std::hex << contextVa
                           << L" did not translate";
                    warnings->push_back(stream.str());
                }
                break;
            }

            uint64_t ripPa = 0;
            if (!TranslateToDumpPhysical(
                    device,
                    directoryTableBase,
                    contextVa + offsetof(CONTEXT, Rip),
                    &ripPa))
            {
                const uint64_t pageOff = contextVa & (static_cast<uint64_t>(kPageSize) - 1ull);
                if (pageOff + offsetof(CONTEXT, Rip) + sizeof(uint64_t) > kPageSize)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"dump-file CONTEXT.Rip straddles a page and did not translate");
                    }
                    break;
                }

                ripPa = physical + offsetof(CONTEXT, Rip);
            }

            if (requireContextShape)
            {
                uint64_t flagsPa = 0;
                if (!TranslateToDumpPhysical(
                        device,
                        directoryTableBase,
                        contextVa + offsetof(CONTEXT, ContextFlags),
                        &flagsPa))
                {
                    const uint64_t pageOff = contextVa & (static_cast<uint64_t>(kPageSize) - 1ull);
                    if (pageOff + offsetof(CONTEXT, ContextFlags) + sizeof(uint32_t) > kPageSize)
                    {
                        break;
                    }

                    flagsPa = physical + offsetof(CONTEXT, ContextFlags);
                }

                uint32_t flags = 0;
                if (!ReadDumpPhysicalBytes(
                        file,
                        ranges,
                        flagsPa,
                        sizeof(flags),
                        &flags,
                        nullptr) ||
                    (flags & 0x100001ul) != 0x100001ul)
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(
                            L"dump-file target is not an AMD64 CONTEXT; Rip left unchanged");
                    }
                    break;
                }
            }

            uint64_t dumpRip = 0;
            std::wstring readError;
            if (!ReadDumpPhysicalBytes(
                    file,
                    ranges,
                    ripPa,
                    sizeof(dumpRip),
                    &dumpRip,
                    &readError))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"dump-file CONTEXT.Rip read failed: " + readError);
                }
                break;
            }

            if (dumpRip == replacementRip)
            {
                ok = true;
                break;
            }

            std::wstring writeError;
            if (!WriteDumpPhysicalBytes(
                    file,
                    ranges,
                    ripPa,
                    reinterpret_cast<const uint8_t*>(&replacementRip),
                    sizeof(replacementRip),
                    &writeError))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"dump-file CONTEXT.Rip write failed: " + writeError);
                }
                break;
            }

            if (warnings != nullptr)
            {
                std::wstringstream stream;
                stream << L"dump-file CONTEXT.Rip 0x" << std::hex << dumpRip
                       << L" -> 0x" << replacementRip;
                warnings->push_back(stream.str());
            }
            ok = true;
        } while (false);

        return ok;
    }

    void MergeKptiDirectoryRoot(
        std::vector<uint8_t>* kernelRoot,
        const std::vector<uint8_t>& userRoot)
    {
        if (kernelRoot == nullptr ||
            kernelRoot->size() < kPageSize ||
            userRoot.size() < kPageSize)
        {
            return;
        }

        // User half is entries 0..255, kernel half is 256..511. Same split
        // for PML4 (4-level) and PML5 (LA57). Copy only the user half into
        // the process kernel CR3 root so one DTB translates both halves.
        std::memcpy(kernelRoot->data(), userRoot.data(), kPageTableRootHalfBytes);
    }

    void AddPhysicalPageToRuns(
        uint64_t physicalAddress,
        std::vector<PhysicalMemoryRange>* ranges)
    {
        const uint64_t page = MaskDirectoryTableBase(physicalAddress);
        if (page == 0 || ranges == nullptr)
        {
            return;
        }

        PhysicalMemoryRange range = {};
        range.BaseAddress = page;
        range.ByteCount = kPageSize;
        ranges->push_back(range);
    }

    void AddTranslationPathToRuns(
        const PhysicalTranslationInfo& translation,
        std::vector<PhysicalMemoryRange>* ranges)
    {
        if (ranges == nullptr)
        {
            return;
        }

        // WinDbg walks the dumped DTB. A leaf PFN without its PT/PD pages
        // is invisible even when the data page itself is in the file.
        AddPhysicalPageToRuns(translation.Pml5eAddress, ranges);
        AddPhysicalPageToRuns(translation.Pml4eAddress, ranges);
        AddPhysicalPageToRuns(translation.PdpteAddress, ranges);
        AddPhysicalPageToRuns(translation.PdeAddress, ranges);
        AddPhysicalPageToRuns(translation.PteAddress, ranges);
        AddPhysicalPageToRuns(translation.PhysicalAddress, ranges);
    }

    bool AddTranslatedVirtualPage(
        DeviceClient& device,
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        std::vector<PhysicalMemoryRange>* ranges,
        std::vector<std::wstring>* warnings,
        const wchar_t* label,
        bool allowCurrentCr3 = false)
    {
        bool ok = false;

        do
        {
            if (ranges == nullptr || virtualAddress == 0)
            {
                break;
            }

            uint64_t dtb = MaskDirectoryTableBase(directoryTableBase);
            if (dtb == 0)
            {
                if (!allowCurrentCr3)
                {
                    break;
                }
            }

            PhysicalTranslationInfo translation = {};
            std::wstring translateError;
            if (!device.TranslateVirtual(
                    dtb,
                    virtualAddress,
                    8,
                    &translation,
                    &translateError) ||
                translation.TranslatedLength == 0 ||
                translation.PhysicalAddress == 0)
            {
                if (warnings != nullptr && label != nullptr)
                {
                    warnings->push_back(
                        std::wstring(L"could not pin ") + label + L": " + translateError);
                }
                break;
            }

            AddTranslationPathToRuns(translation, ranges);
            ok = true;
        } while (false);

        return ok;
    }

    bool AddTranslatedVirtualPageAnyCr3(
        DeviceClient& device,
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        std::vector<PhysicalMemoryRange>* ranges,
        std::vector<std::wstring>* warnings,
        const wchar_t* label)
    {
        if (AddTranslatedVirtualPage(
                device,
                directoryTableBase,
                virtualAddress,
                ranges,
                nullptr,
                nullptr))
        {
            return true;
        }

        return AddTranslatedVirtualPage(
            device,
            0,
            virtualAddress,
            ranges,
            warnings,
            label,
            true);
    }

    bool ReadVirtualThroughDtb(
        DeviceClient& device,
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0 || directoryTableBase == 0)
            {
                break;
            }

            bytes->assign(length, 0);
            uint32_t done = 0;
            bool failed = false;
            while (done < length)
            {
                PhysicalTranslationInfo translation = {};
                if (!device.TranslateVirtual(
                        MaskDirectoryTableBase(directoryTableBase),
                        virtualAddress + done,
                        length - done,
                        &translation,
                        nullptr) ||
                    translation.TranslatedLength == 0 ||
                    translation.PhysicalAddress == 0)
                {
                    failed = true;
                    break;
                }

                uint32_t chunk = translation.TranslatedLength;
                if (chunk > length - done)
                {
                    chunk = length - done;
                }

                std::vector<uint8_t> page;
                if (!device.ReadPhysical(translation.PhysicalAddress, chunk, &page, nullptr) ||
                    page.size() < chunk)
                {
                    failed = true;
                    break;
                }

                std::memcpy(bytes->data() + done, page.data(), chunk);
                done += chunk;
            }

            ok = !failed && done == length;
        } while (false);

        return ok;
    }

    bool IsUserModeVa(uint64_t address)
    {
        return address != 0 && !IsKernelCanonicalVa(address);
    }

    bool ParseUserUnicodeString64(
        const uint8_t* raw,
        size_t rawSize,
        uint64_t* buffer,
        uint32_t* byteLength)
    {
        bool ok = false;

        do
        {
            if (raw == nullptr || rawSize < 16 || buffer == nullptr || byteLength == nullptr)
            {
                break;
            }

            uint16_t length = 0;
            uint16_t maximumLength = 0;
            uint64_t pointer = 0;
            std::memcpy(&length, raw, sizeof(length));
            std::memcpy(&maximumLength, raw + 2, sizeof(maximumLength));
            std::memcpy(&pointer, raw + 8, sizeof(pointer));
            uint32_t bytes = length;
            if (bytes == 0)
            {
                bytes = maximumLength;
            }

            if (!IsUserModeVa(pointer) || bytes == 0 || bytes > 0x10000)
            {
                break;
            }

            *buffer = pointer;
            *byteLength = bytes;
            ok = true;
        } while (false);

        return ok;
    }

    HANDLE OpenTargetProcessReadHandle(uint32_t processId)
    {
        HANDLE process = nullptr;
        if (processId != 0)
        {
            const DWORD attempts[] = {
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                    PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
            };
            for (DWORD access : attempts)
            {
                process = OpenProcess(access, FALSE, processId);
                if (process != nullptr)
                {
                    break;
                }
            }
        }

        return process;
    }

    bool ForceUserPagePresent(HANDLE processHandle, uint64_t virtualAddress)
    {
        bool ok = false;

        do
        {
            if (processHandle == nullptr || virtualAddress == 0)
            {
                break;
            }

            const uintptr_t page = static_cast<uintptr_t>(virtualAddress & ~0xFFFull);
            uint8_t bytes[0x1000] = {};
            SIZE_T got = 0;
            PVOID writeVa = reinterpret_cast<LPVOID>(page);
            if (!ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(page),
                    bytes,
                    sizeof(bytes),
                    &got) ||
                got == 0)
            {
                if (!ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(virtualAddress)),
                        bytes,
                        8,
                        &got) ||
                    got == 0)
                {
                    break;
                }

                writeVa = reinterpret_cast<LPVOID>(static_cast<uintptr_t>(virtualAddress));
            }

            // Same-byte write first so a prototype/file-backed page becomes a
            // private hardware PTE. Locking before the write pins the old
            // shared page and then CoW replaces it.
            SIZE_T written = 0;
            WriteProcessMemory(processHandle, writeVa, bytes, got, &written);

            using NtLockVirtualMemoryFn = LONG (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
            static NtLockVirtualMemoryFn ntLockVirtualMemory = nullptr;
            static bool resolvedLock = false;
            if (!resolvedLock)
            {
                HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                if (ntdll != nullptr)
                {
                    ntLockVirtualMemory = reinterpret_cast<NtLockVirtualMemoryFn>(
                        GetProcAddress(ntdll, "NtLockVirtualMemory"));
                }
                resolvedLock = true;
            }

            if (ntLockVirtualMemory != nullptr)
            {
                PVOID lockBase = reinterpret_cast<PVOID>(page);
                SIZE_T lockSize = (got > 0 && writeVa == reinterpret_cast<LPVOID>(page))
                    ? got
                    : static_cast<SIZE_T>(kPageSize);
                ntLockVirtualMemory(processHandle, &lockBase, &lockSize, 1);
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadUserVirtualForDump(
        DeviceClient& device,
        HANDLE processHandle,
        uint32_t processId,
        uint64_t eprocess,
        uint64_t createTime,
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint32_t length,
        std::vector<uint8_t>* bytes)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0 || virtualAddress == 0)
            {
                break;
            }

            if (processHandle != nullptr)
            {
                bytes->assign(length, 0);
                SIZE_T got = 0;
                if (ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(virtualAddress)),
                        bytes->data(),
                        length,
                        &got) &&
                    got == length)
                {
                    ok = true;
                    break;
                }
            }

            if (processId != 0 && eprocess != 0 && createTime != 0)
            {
                std::vector<uint8_t> copied;
                if (device.ReadProcessVirtual(
                        processId,
                        eprocess,
                        createTime,
                        virtualAddress,
                        length,
                        &copied,
                        nullptr) &&
                    copied.size() >= length)
                {
                    *bytes = std::move(copied);
                    ok = true;
                    break;
                }
            }

            ok = ReadVirtualThroughDtb(device, directoryTableBase, virtualAddress, length, bytes);
        } while (false);

        return ok;
    }

    // ReadProcessMemory can copy file-backed bytes without installing a
    // hardware PTE. Lock + same-byte WriteProcessMemory force Present.
    bool FaultAndPinUserPage(
        DeviceClient& device,
        HANDLE processHandle,
        uint32_t processId,
        uint64_t eprocess,
        uint64_t createTime,
        uint64_t directoryTableBase,
        uint64_t alternateDtb,
        uint64_t virtualAddress,
        std::vector<PhysicalMemoryRange>* ranges)
    {
        bool ok = false;
        if (virtualAddress == 0 || ranges == nullptr)
        {
            return false;
        }

        if (processHandle != nullptr)
        {
            ForceUserPagePresent(processHandle, virtualAddress);
        }
        else if (processId != 0 && eprocess != 0 && createTime != 0)
        {
            std::vector<uint8_t> ignored;
            device.ReadProcessVirtual(
                processId,
                eprocess,
                createTime,
                virtualAddress,
                8,
                &ignored,
                nullptr);
        }

        ok = AddTranslatedVirtualPage(
            device,
            directoryTableBase,
            virtualAddress,
            ranges,
            nullptr,
            nullptr);
        if (!ok &&
            alternateDtb != 0 &&
            MaskDirectoryTableBase(alternateDtb) != MaskDirectoryTableBase(directoryTableBase))
        {
            ok = AddTranslatedVirtualPage(
                device,
                alternateDtb,
                virtualAddress,
                ranges,
                nullptr,
                nullptr);
        }

        if (!ok && processHandle != nullptr)
        {
            ForceUserPagePresent(processHandle, virtualAddress);
            ok = AddTranslatedVirtualPage(
                device,
                directoryTableBase,
                virtualAddress,
                ranges,
                nullptr,
                nullptr);
        }

        return ok;
    }

    void PinUserUnicodeStringPages(
        DeviceClient& device,
        HANDLE processHandle,
        uint32_t processId,
        uint64_t eprocess,
        uint64_t createTime,
        uint64_t directoryTableBase,
        uint64_t alternateDtb,
        uint64_t stringVa,
        std::vector<PhysicalMemoryRange>* ranges)
    {
        if (stringVa == 0 || directoryTableBase == 0 || ranges == nullptr)
        {
            return;
        }

        FaultAndPinUserPage(
            device,
            processHandle,
            processId,
            eprocess,
            createTime,
            directoryTableBase,
            alternateDtb,
            stringVa,
            ranges);

        std::vector<uint8_t> raw;
        if (!ReadUserVirtualForDump(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                directoryTableBase,
                stringVa,
                16,
                &raw) ||
            raw.size() < 16)
        {
            return;
        }

        uint64_t buffer = 0;
        uint32_t length = 0;
        uint16_t nameLength = 0;
        uint16_t nameMaximum = 0;
        std::memcpy(&nameLength, raw.data(), sizeof(nameLength));
        std::memcpy(&nameMaximum, raw.data() + 2, sizeof(nameMaximum));
        if (!ParseUserUnicodeString64(raw.data(), raw.size(), &buffer, &length))
        {
            std::memcpy(&buffer, raw.data() + 8, sizeof(buffer));
            if (!IsUserModeVa(buffer) ||
                (nameLength == 0 && nameMaximum == 0) ||
                nameMaximum > 0x10000)
            {
                return;
            }

            length = nameMaximum != 0 ? nameMaximum : nameLength;
            if (length == 0 || length > 0x10000)
            {
                return;
            }
        }

        FaultAndPinUserPage(
            device,
            processHandle,
            processId,
            eprocess,
            createTime,
            directoryTableBase,
            alternateDtb,
            buffer,
            ranges);
        FaultAndPinUserPage(
            device,
            processHandle,
            processId,
            eprocess,
            createTime,
            directoryTableBase,
            alternateDtb,
            buffer + static_cast<uint64_t>(length) - 1,
            ranges);
        if (nameMaximum > length && nameMaximum <= 0x10000)
        {
            FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                directoryTableBase,
                alternateDtb,
                buffer + static_cast<uint64_t>(nameMaximum) - 1,
                ranges);
        }
    }

    void PinProcessLdrNamePages(
        DeviceClient& device,
        SymbolEngine& symbols,
        HANDLE processHandle,
        uint32_t processId,
        uint64_t eprocess,
        uint64_t createTime,
        uint64_t userDtb,
        uint64_t kernelDtb,
        uint64_t peb,
        std::vector<PhysicalMemoryRange>* ranges,
        std::vector<std::wstring>* warnings)
    {
        do
        {
            if (userDtb == 0 || peb == 0 || ranges == nullptr)
            {
                break;
            }

            TypeFieldInfo ldrField = {};
            TypeFieldInfo imageBaseField = {};
            TypeFieldInfo listField = {};
            TypeFieldInfo linksField = {};
            TypeFieldInfo baseNameField = {};
            TypeFieldInfo fullNameField = {};
            if (!symbols.FindField(L"nt!_PEB", L"Ldr", &ldrField, nullptr) &&
                !symbols.FindField(L"_PEB", L"Ldr", &ldrField, nullptr))
            {
                ldrField.Offset = 0x18;
            }

            if (!symbols.FindField(L"nt!_PEB", L"ImageBaseAddress", &imageBaseField, nullptr) &&
                !symbols.FindField(L"_PEB", L"ImageBaseAddress", &imageBaseField, nullptr))
            {
                imageBaseField.Offset = 0x10;
            }

            if (!symbols.FindField(L"nt!_PEB_LDR_DATA", L"InLoadOrderModuleList", &listField, nullptr) &&
                !symbols.FindField(L"_PEB_LDR_DATA", L"InLoadOrderModuleList", &listField, nullptr))
            {
                listField.Offset = 0x10;
            }

            if (!symbols.FindField(
                    L"nt!_LDR_DATA_TABLE_ENTRY",
                    L"InLoadOrderLinks",
                    &linksField,
                    nullptr) &&
                !symbols.FindField(
                    L"_LDR_DATA_TABLE_ENTRY",
                    L"InLoadOrderLinks",
                    &linksField,
                    nullptr))
            {
                linksField.Offset = 0;
            }

            const bool haveBaseName =
                symbols.FindField(L"nt!_LDR_DATA_TABLE_ENTRY", L"BaseDllName", &baseNameField, nullptr) ||
                symbols.FindField(L"_LDR_DATA_TABLE_ENTRY", L"BaseDllName", &baseNameField, nullptr);
            const bool haveFullName =
                symbols.FindField(L"nt!_LDR_DATA_TABLE_ENTRY", L"FullDllName", &fullNameField, nullptr) ||
                symbols.FindField(L"_LDR_DATA_TABLE_ENTRY", L"FullDllName", &fullNameField, nullptr);
            if (!haveBaseName)
            {
                baseNameField.Offset = 0x58;
            }

            if (!haveFullName)
            {
                fullNameField.Offset = 0x48;
            }

            FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                kernelDtb,
                peb,
                ranges);
            FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                kernelDtb,
                peb + ldrField.Offset,
                ranges);

            std::vector<uint8_t> imageBaseBytes;
            if (ReadUserVirtualForDump(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    peb + imageBaseField.Offset,
                    8,
                    &imageBaseBytes) &&
                imageBaseBytes.size() >= 8)
            {
                uint64_t imageBase = 0;
                std::memcpy(&imageBase, imageBaseBytes.data(), sizeof(imageBase));
                if (IsUserModeVa(imageBase))
                {
                    FaultAndPinUserPage(
                        device,
                        processHandle,
                        processId,
                        eprocess,
                        createTime,
                        userDtb,
                        kernelDtb,
                        imageBase,
                        ranges);
                }
            }

            std::vector<uint8_t> pebBytes;
            if (!ReadUserVirtualForDump(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    peb + ldrField.Offset,
                    8,
                    &pebBytes))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"could not read PEB.Ldr to pin module names");
                }
                break;
            }

            uint64_t ldr = 0;
            std::memcpy(&ldr, pebBytes.data(), sizeof(ldr));
            if (!IsUserModeVa(ldr))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"PEB.Ldr is not a user-mode pointer");
                }
                break;
            }

            const bool ldrPinned = FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                kernelDtb,
                ldr,
                ranges);
            FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                kernelDtb,
                ldr + listField.Offset,
                ranges);
            FaultAndPinUserPage(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                kernelDtb,
                ldr + 0x80,
                ranges);
            const uint64_t listHead = ldr + listField.Offset;
            std::vector<uint8_t> headBytes;
            const bool ldrReadable = ReadUserVirtualForDump(
                device,
                processHandle,
                processId,
                eprocess,
                createTime,
                userDtb,
                listHead,
                8,
                &headBytes);
            if (!ldrReadable)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"PEB.Ldr page did not become present after fault-in");
                }
                break;
            }

            if (!ldrPinned && warnings != nullptr)
            {
                warnings->push_back(
                    L"PEB.Ldr bytes were readable but the PFN still did not translate");
            }

            uint64_t flink = 0;
            std::memcpy(&flink, headBytes.data(), sizeof(flink));
            uint32_t pinned = 0;
            uint64_t current = flink;
            for (uint32_t index = 0; index < 512; ++index)
            {
                if (current == 0 || current == listHead || !IsUserModeVa(current))
                {
                    break;
                }

                if (current < linksField.Offset)
                {
                    break;
                }

                const uint64_t entry = current - linksField.Offset;
                FaultAndPinUserPage(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    kernelDtb,
                    entry,
                    ranges);
                FaultAndPinUserPage(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    kernelDtb,
                    entry + 0x100,
                    ranges);
                PinUserUnicodeStringPages(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    kernelDtb,
                    entry + baseNameField.Offset,
                    ranges);
                PinUserUnicodeStringPages(
                    device,
                    processHandle,
                    processId,
                    eprocess,
                    createTime,
                    userDtb,
                    kernelDtb,
                    entry + fullNameField.Offset,
                    ranges);
                ++pinned;

                std::vector<uint8_t> nextBytes;
                if (!ReadUserVirtualForDump(
                        device,
                        processHandle,
                        processId,
                        eprocess,
                        createTime,
                        userDtb,
                        current,
                        8,
                        &nextBytes))
                {
                    break;
                }

                uint64_t next = 0;
                std::memcpy(&next, nextBytes.data(), sizeof(next));
                if (next == current)
                {
                    break;
                }

                current = next;
            }

            if (warnings != nullptr)
            {
                if (pinned > 0)
                {
                    warnings->push_back(
                        L"pinned PEB LDR names for " + std::to_wstring(pinned) + L" module(s)");
                }
                else
                {
                    warnings->push_back(
                        L"PEB.Ldr was readable but InLoadOrderModuleList walked 0 modules");
                }
            }
        } while (false);
    }

    bool ResolveLiveKpcr(
        DeviceClient& device,
        uint64_t* kpcr,
        uint64_t* kernelGsOut,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;

        do
        {
            if (kpcr == nullptr)
            {
                break;
            }

            *kpcr = 0;
            uint64_t gsBase = 0;
            uint64_t kernelGs = 0;
            uint32_t ignoredCpu = 0;
            std::wstring msrError;
            if (!device.ReadMsr(KNDBG_MSR_IA32_GS_BASE, 0, &gsBase, &ignoredCpu, &msrError) &&
                warnings != nullptr)
            {
                warnings->push_back(L"IA32_GS_BASE read failed: " + msrError);
            }
            device.ReadMsr(KNDBG_MSR_IA32_KERNEL_GS_BASE, 0, &kernelGs, &ignoredCpu, nullptr);
            if (kernelGsOut != nullptr)
            {
                *kernelGsOut = kernelGs;
            }

            uint64_t candidate = 0;
            if (IsKernelCanonicalVa(gsBase))
            {
                candidate = gsBase;
            }
            else if (IsKernelCanonicalVa(kernelGs))
            {
                candidate = kernelGs;
            }

            uint64_t self = 0;
            if (candidate != 0 &&
                ReadKernelU64(device, candidate + kKpcrSelfOffset, &self) &&
                self != candidate)
            {
                if (IsKernelCanonicalVa(kernelGs) &&
                    ReadKernelU64(device, kernelGs + kKpcrSelfOffset, &self) &&
                    self == kernelGs)
                {
                    candidate = kernelGs;
                }
                else
                {
                    if (warnings != nullptr)
                    {
                        warnings->push_back(L"GS_BASE did not validate as KPCR.Self");
                    }
                    candidate = 0;
                }
            }

            if (candidate == 0)
            {
                break;
            }

            *kpcr = candidate;
            ok = true;
        } while (false);

        return ok;
    }

    uint64_t FindFirstProcessThread(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t eprocess,
        std::vector<std::wstring>* warnings)
    {
        uint64_t thread = 0;

        do
        {
            if (eprocess == 0)
            {
                break;
            }

            TypeFieldInfo headField = {};
            TypeFieldInfo entryField = {};
            std::wstring headError;
            std::wstring entryError;
            bool haveList = false;
            // KPROCESS/KTHREAD is the unambiguous pair. EPROCESS.ThreadListHead
            // can resolve to the inherited KPROCESS field on flattened PDB
            // layouts; pairing that with ETHREAD.ThreadListEntry yields a
            // garbage CONTAINING_RECORD.
            if (symbols.FindField(L"nt!_KPROCESS", L"ThreadListHead", &headField, &headError) &&
                symbols.FindField(L"nt!_KTHREAD", L"ThreadListEntry", &entryField, &entryError))
            {
                haveList = true;
            }
            else if (
                symbols.FindField(L"nt!_EPROCESS", L"ThreadListHead", &headField, &headError) &&
                symbols.FindField(L"nt!_ETHREAD", L"ThreadListEntry", &entryField, &entryError) &&
                headField.Offset > 0x200)
            {
                haveList = true;
            }

            if (!haveList)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"process thread list offsets unavailable; WinDbg current process stays CPU0");
                }
                break;
            }

            uint32_t tebOffset = 0;
            TypeFieldInfo tebField = {};
            if (symbols.FindField(L"nt!_KTHREAD", L"Teb", &tebField, nullptr) &&
                tebField.Offset <= 0x4000)
            {
                tebOffset = tebField.Offset;
            }

            uint32_t processOffset = 0;
            TypeFieldInfo processField = {};
            if (symbols.FindField(L"nt!_KTHREAD", L"Process", &processField, nullptr) &&
                processField.Offset <= 0x4000)
            {
                processOffset = processField.Offset;
            }

            const uint64_t listHead = eprocess + headField.Offset;
            uint64_t flink = 0;
            if (!ReadKernelU64(device, listHead, &flink) ||
                flink == 0 ||
                flink == listHead)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"target process thread list is empty");
                }
                break;
            }

            uint64_t first = 0;
            uint64_t current = flink;
            for (uint32_t index = 0; index < 64; ++index)
            {
                if (current == 0 || current == listHead)
                {
                    break;
                }

                if (current < entryField.Offset)
                {
                    break;
                }

                const uint64_t candidate = current - entryField.Offset;
                if (!IsKernelCanonicalVa(candidate))
                {
                    break;
                }

                if (processOffset != 0)
                {
                    uint64_t owner = 0;
                    if (!ReadKernelU64(device, candidate + processOffset, &owner) ||
                        owner != eprocess)
                    {
                        uint64_t next = 0;
                        if (!ReadKernelU64(device, current, &next) || next == current)
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }
                }

                if (first == 0)
                {
                    first = candidate;
                }

                if (tebOffset != 0)
                {
                    uint64_t teb = 0;
                    if (ReadKernelU64(device, candidate + tebOffset, &teb) &&
                        teb != 0 &&
                        teb < 0x00FFFFFFFFFFFFFFull)
                    {
                        thread = candidate;
                        break;
                    }
                }

                uint64_t next = 0;
                if (!ReadKernelU64(device, current, &next) || next == current)
                {
                    break;
                }

                current = next;
            }

            if (thread == 0)
            {
                thread = first;
            }
        } while (false);

        return thread;
    }

    bool FindProcessThreadKernelTrap(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t eprocess,
        uint64_t* thread,
        uint64_t* rip,
        uint64_t* rsp)
    {
        bool ok = false;

        do
        {
            if (thread == nullptr || rip == nullptr || rsp == nullptr || eprocess == 0)
            {
                break;
            }

            *thread = 0;
            *rip = 0;
            *rsp = 0;

            TypeFieldInfo headField = {};
            TypeFieldInfo entryField = {};
            bool haveList = false;
            if (symbols.FindField(L"nt!_KPROCESS", L"ThreadListHead", &headField, nullptr) &&
                symbols.FindField(L"nt!_KTHREAD", L"ThreadListEntry", &entryField, nullptr))
            {
                haveList = true;
            }
            else if (
                symbols.FindField(L"nt!_EPROCESS", L"ThreadListHead", &headField, nullptr) &&
                symbols.FindField(L"nt!_ETHREAD", L"ThreadListEntry", &entryField, nullptr) &&
                headField.Offset > 0x200)
            {
                haveList = true;
            }

            if (!haveList)
            {
                break;
            }

            uint32_t tebOffset = 0;
            TypeFieldInfo tebField = {};
            if (symbols.FindField(L"nt!_KTHREAD", L"Teb", &tebField, nullptr) &&
                tebField.Offset <= 0x4000)
            {
                tebOffset = tebField.Offset;
            }

            uint32_t processOffset = 0;
            TypeFieldInfo processField = {};
            if (symbols.FindField(L"nt!_KTHREAD", L"Process", &processField, nullptr) &&
                processField.Offset <= 0x4000)
            {
                processOffset = processField.Offset;
            }

            TypeFieldInfo csField = {};
            TypeFieldInfo ripField = {};
            TypeFieldInfo rspField = {};
            if (!symbols.FindField(L"nt!_KTRAP_FRAME", L"Rip", &ripField, nullptr))
            {
                break;
            }

            if (!symbols.FindField(L"nt!_KTRAP_FRAME", L"Rsp", &rspField, nullptr) &&
                !symbols.FindField(L"nt!_KTRAP_FRAME", L"HardwareRsp", &rspField, nullptr))
            {
                break;
            }

            symbols.FindField(L"nt!_KTRAP_FRAME", L"SegCs", &csField, nullptr);

            const uint64_t listHead = eprocess + headField.Offset;
            uint64_t flink = 0;
            if (!ReadKernelU64(device, listHead, &flink) ||
                flink == 0 ||
                flink == listHead)
            {
                break;
            }

            uint64_t fallback = 0;
            uint64_t tebFallback = 0;
            uint64_t current = flink;
            for (uint32_t index = 0; index < 64; ++index)
            {
                if (current == 0 || current == listHead)
                {
                    break;
                }

                if (current < entryField.Offset)
                {
                    break;
                }

                const uint64_t candidate = current - entryField.Offset;
                if (!IsKernelCanonicalVa(candidate))
                {
                    break;
                }

                uint64_t next = 0;
                if (!ReadKernelU64(device, current, &next) || next == current)
                {
                    next = 0;
                }

                if (processOffset != 0)
                {
                    uint64_t owner = 0;
                    if (!ReadKernelU64(device, candidate + processOffset, &owner) ||
                        owner != eprocess)
                    {
                        if (next == 0)
                        {
                            break;
                        }

                        current = next;
                        continue;
                    }
                }

                if (fallback == 0)
                {
                    fallback = candidate;
                }

                if (tebOffset != 0 && tebFallback == 0)
                {
                    uint64_t teb = 0;
                    if (ReadKernelU64(device, candidate + tebOffset, &teb) &&
                        teb != 0 &&
                        teb < 0x00FFFFFFFFFFFFFFull)
                    {
                        tebFallback = candidate;
                    }
                }

                uint64_t trapFrame = 0;
                if (ReadFieldU64(
                        device,
                        symbols,
                        candidate,
                        L"nt!_KTHREAD",
                        L"TrapFrame",
                        nullptr,
                        &trapFrame) &&
                    IsKernelCanonicalVa(trapFrame))
                {
                    bool kernelCs = true;
                    if (!csField.Name.empty())
                    {
                        std::vector<uint8_t> csBytes;
                        if (ReadKernelBytes(
                                device,
                                trapFrame + csField.Offset,
                                sizeof(uint16_t),
                                &csBytes) &&
                            csBytes.size() >= sizeof(uint16_t))
                        {
                            uint16_t segCs = 0;
                            std::memcpy(&segCs, csBytes.data(), sizeof(segCs));
                            kernelCs = (segCs == 0x10);
                        }
                    }

                    uint64_t trapRip = 0;
                    uint64_t trapRsp = 0;
                    if (kernelCs &&
                        ReadKernelU64(device, trapFrame + ripField.Offset, &trapRip) &&
                        ReadKernelU64(device, trapFrame + rspField.Offset, &trapRsp) &&
                        IsKernelCanonicalVa(trapRip))
                    {
                        *thread = candidate;
                        *rip = trapRip;
                        *rsp = trapRsp;
                        ok = true;
                        break;
                    }
                }

                if (next == 0)
                {
                    break;
                }

                current = next;
            }

            if (!ok)
            {
                if (tebFallback != 0)
                {
                    *thread = tebFallback;
                }
                else
                {
                    *thread = fallback;
                }
            }
        } while (false);

        return ok;
    }

    bool ReadKdbgFieldU16(
        const std::vector<uint8_t>& block,
        SymbolEngine& symbols,
        const wchar_t* fieldName,
        uint16_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || fieldName == nullptr)
            {
                break;
            }

            TypeFieldInfo field = {};
            if (!symbols.FindField(L"nt!_KDDEBUGGER_DATA64", fieldName, &field, nullptr) &&
                !symbols.FindField(L"_KDDEBUGGER_DATA64", fieldName, &field, nullptr))
            {
                break;
            }

            if (field.Offset + sizeof(uint16_t) > block.size())
            {
                break;
            }

            std::memcpy(value, block.data() + field.Offset, sizeof(*value));
            ok = true;
        } while (false);

        return ok;
    }

    void FillKdbgPrcbOffsets(
        const std::vector<uint8_t>& kdbg,
        SymbolEngine& symbols,
        ProcessDumpWinDbgFixup* fixup)
    {
        if (fixup == nullptr || kdbg.empty())
        {
            return;
        }

        uint16_t contextOffset = 0;
        uint16_t pointerOffset = 0;
        uint16_t prcbSize = 0;
        uint16_t specialOffset = 0;
        if (!ReadKdbgFieldU16(kdbg, symbols, L"OffsetPrcbProcStateContext", &contextOffset) &&
            kdbg.size() >= kKdbgOffsetPrcbProcStateContext + sizeof(uint16_t))
        {
            std::memcpy(
                &contextOffset,
                kdbg.data() + kKdbgOffsetPrcbProcStateContext,
                sizeof(contextOffset));
        }
        if (contextOffset >= 0x40 &&
            contextOffset <= 0x20000 &&
            (contextOffset % 16u) == 0)
        {
            fixup->PrcbProcStateContextOffset = contextOffset;
        }

        if (!ReadKdbgFieldU16(kdbg, symbols, L"OffsetPrcbProcStateSpecialReg", &specialOffset) &&
            kdbg.size() >= kKdbgOffsetPrcbProcStateSpecialReg + sizeof(uint16_t))
        {
            std::memcpy(
                &specialOffset,
                kdbg.data() + kKdbgOffsetPrcbProcStateSpecialReg,
                sizeof(specialOffset));
        }
        if (specialOffset >= 0x40 &&
            specialOffset <= 0x20000 &&
            (specialOffset % 16u) == 0)
        {
            fixup->PrcbProcStateSpecialRegOffset = specialOffset;
        }

        if (!ReadKdbgFieldU16(kdbg, symbols, L"OffsetPrcbContext", &pointerOffset) &&
            kdbg.size() >= kKdbgOffsetPrcbContext + sizeof(uint16_t))
        {
            std::memcpy(
                &pointerOffset,
                kdbg.data() + kKdbgOffsetPrcbContext,
                sizeof(pointerOffset));
        }
        if (pointerOffset >= 0x8 &&
            pointerOffset <= 0x20000 &&
            (pointerOffset % 8u) == 0)
        {
            fixup->PrcbContextOffset = pointerOffset;
        }

        if (!ReadKdbgFieldU16(kdbg, symbols, L"SizePrcb", &prcbSize) &&
            kdbg.size() >= kKdbgSizePrcbOffset + sizeof(uint16_t))
        {
            std::memcpy(&prcbSize, kdbg.data() + kKdbgSizePrcbOffset, sizeof(prcbSize));
        }
        if (prcbSize >= 0x400)
        {
            fixup->PrcbSize = prcbSize;
        }

        if (kdbg.size() >= kKdbgSavedContextOffset + sizeof(uint64_t))
        {
            uint64_t savedContext = 0;
            std::memcpy(
                &savedContext,
                kdbg.data() + kKdbgSavedContextOffset,
                sizeof(savedContext));
            if (IsKernelCanonicalVa(savedContext))
            {
                fixup->SavedContext = savedContext;
            }
        }
    }

    bool ResolvePrcbProcessorStateAddresses(
        SymbolEngine& symbols,
        uint64_t prcb,
        uint32_t kdbgContextOffset,
        uint64_t* contextVa,
        uint64_t* specialVa)
    {
        bool ok = false;

        do
        {
            if (contextVa == nullptr || prcb == 0)
            {
                break;
            }

            *contextVa = 0;
            if (specialVa != nullptr)
            {
                *specialVa = 0;
            }

            TypeFieldInfo nestedField = {};
            TypeFieldInfo stateField = {};
            TypeFieldInfo frameField = {};
            uint64_t frame = 0;
            uint64_t special = 0;
            // WinDbg 10 uses KDBG.OffsetPrcbProcStateContext, not the PDB
            // field walk. Prefer that so the opening RIP write lands.
            if (kdbgContextOffset >= 0x40 && kdbgContextOffset <= 0x40000)
            {
                frame = prcb + kdbgContextOffset;
                if (kdbgContextOffset >= 0xF0)
                {
                    special = prcb + kdbgContextOffset - 0xF0;
                }
            }
            else if (symbols.FindField(
                    L"nt!_KPRCB",
                    L"ProcessorState.ContextFrame",
                    &nestedField,
                    nullptr) &&
                nestedField.Offset >= 0xF0)
            {
                frame = prcb + nestedField.Offset;
                special = prcb + nestedField.Offset - 0xF0;
            }
            else if (symbols.FindField(L"nt!_KPRCB", L"ProcessorState", &stateField, nullptr) &&
                     symbols.FindField(L"nt!_KPROCESSOR_STATE", L"ContextFrame", &frameField, nullptr))
            {
                frame = prcb + stateField.Offset + frameField.Offset;
                special = prcb + stateField.Offset;
            }
            else if (symbols.FindField(L"nt!_KPRCB", L"ProcessorState", &stateField, nullptr))
            {
                frame = prcb + stateField.Offset + 0xF0;
                special = prcb + stateField.Offset;
            }
            else
            {
                break;
            }

            if (frame == 0 || !IsKernelCanonicalVa(frame))
            {
                break;
            }

            *contextVa = frame;
            if (specialVa != nullptr && IsKernelCanonicalVa(special))
            {
                *specialVa = special;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool WriteDumpVirtualRangeAnyCr3(
        HANDLE file,
        DeviceClient& device,
        uint64_t directoryTableBase,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t virtualAddress,
        const uint8_t* data,
        uint32_t length,
        std::wstring* error,
        const wchar_t* what)
    {
        bool ok = false;
        std::wstring firstError;
        if (WriteDumpVirtualRange(
                file,
                device,
                directoryTableBase,
                ranges,
                virtualAddress,
                data,
                length,
                &firstError,
                what))
        {
            ok = true;
        }
        else if (WriteDumpVirtualRange(
                     file,
                     device,
                     0,
                     ranges,
                     virtualAddress,
                     data,
                     length,
                     error,
                     what))
        {
            ok = true;
        }
        else if (error != nullptr && error->empty())
        {
            *error = firstError;
        }

        return ok;
    }

    bool LooksLikeAmd64Context(DeviceClient& device, uint64_t contextVa)
    {
        bool ok = false;

        do
        {
            if (!IsKernelCanonicalVa(contextVa))
            {
                break;
            }

            std::vector<uint8_t> flagBytes;
            if (!ReadKernelBytes(
                    device,
                    contextVa + offsetof(CONTEXT, ContextFlags),
                    sizeof(uint32_t),
                    &flagBytes) ||
                flagBytes.size() < sizeof(uint32_t))
            {
                break;
            }

            uint32_t flags = 0;
            std::memcpy(&flags, flagBytes.data(), sizeof(flags));
            ok = (flags & 0x100001ul) == 0x100001ul;
        } while (false);

        return ok;
    }

    uint32_t QueryPrcbSizeCap(SymbolEngine& symbols, uint32_t kdbgPrcbSize)
    {
        TypeLayoutInfo prcbLayout = {};
        if (symbols.GetTypeLayout(L"nt!_KPRCB", &prcbLayout, nullptr) &&
            prcbLayout.Size >= 0x400 &&
            prcbLayout.Size <= 0x40000)
        {
            return static_cast<uint32_t>(prcbLayout.Size);
        }

        if (kdbgPrcbSize >= 0x400 && kdbgPrcbSize < 0xFFFF)
        {
            return kdbgPrcbSize;
        }

        return 0x40000;
    }

    bool WriteKernelDumpContext(
        HANDLE file,
        DeviceClient& device,
        uint64_t directoryTableBase,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t contextVa,
        uint64_t rip,
        uint64_t rsp,
        std::wstring* error,
        const wchar_t* what)
    {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
        context.MxCsr = 0x1F80;
        context.SegCs = 0x10;
        context.SegDs = 0x2B;
        context.SegEs = 0x2B;
        context.SegSs = 0x18;
        context.SegFs = 0x53;
        context.SegGs = 0x2B;
        context.EFlags = 0x2;
        context.Rip = rip;
        context.Rsp = rsp;
        return WriteDumpVirtualRangeAnyCr3(
            file,
            device,
            directoryTableBase,
            ranges,
            contextVa,
            reinterpret_cast<const uint8_t*>(&context),
            kDumpAmd64ContextBytes,
            error,
            what);
    }

    bool WritePrcbProcessorContext(
        HANDLE file,
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t directoryTableBase,
        uint64_t prcb,
        uint32_t kdbgContextOffset,
        uint32_t kdbgContextPointerOffset,
        uint32_t kdbgSpecialOffset,
        uint32_t kdbgPrcbSize,
        uint64_t rip,
        uint64_t rsp,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (prcb == 0 || rip == 0)
            {
                if (error != nullptr)
                {
                    *error = L"no KPRCB/RIP for ProcessorState patch";
                }
                break;
            }

            const uint32_t prcbCap = QueryPrcbSizeCap(symbols, kdbgPrcbSize);
            uint64_t candidates[2] = {};
            uint32_t candidateCount = 0;
            if (kdbgContextOffset >= 0x40 &&
                kdbgContextOffset <= 0x40000 &&
                kdbgContextOffset + kDumpAmd64ContextBytes <= prcbCap)
            {
                candidates[candidateCount++] = prcb + kdbgContextOffset;
            }

            uint64_t pdbContextVa = 0;
            uint64_t pdbSpecialVa = 0;
            if (ResolvePrcbProcessorStateAddresses(symbols, prcb, 0, &pdbContextVa, &pdbSpecialVa) &&
                pdbContextVa != 0)
            {
                bool already = false;
                for (uint32_t index = 0; index < candidateCount; ++index)
                {
                    if (candidates[index] == pdbContextVa)
                    {
                        already = true;
                        break;
                    }
                }
                if (!already && candidateCount < 2)
                {
                    candidates[candidateCount++] = pdbContextVa;
                }
            }

            std::wstring lastError;
            uint32_t wrote = 0;
            for (uint32_t index = 0; index < candidateCount; ++index)
            {
                std::wstring writeError;
                if (WriteKernelDumpContext(
                        file,
                        device,
                        directoryTableBase,
                        ranges,
                        candidates[index],
                        rip,
                        rsp,
                        &writeError,
                        L"KPRCB processor context"))
                {
                    ++wrote;
                }
                else
                {
                    lastError = writeError;
                }
            }

            if (kdbgContextPointerOffset >= 8 && kdbgContextPointerOffset <= 0x40000)
            {
                uint64_t pointed = 0;
                if (ReadKernelU64(device, prcb + kdbgContextPointerOffset, &pointed) &&
                    LooksLikeAmd64Context(device, pointed))
                {
                    bool already = false;
                    for (uint32_t index = 0; index < candidateCount; ++index)
                    {
                        if (candidates[index] == pointed)
                        {
                            already = true;
                            break;
                        }
                    }
                    if (!already)
                    {
                        std::wstring pointerError;
                        WriteKernelDumpContext(
                            file,
                            device,
                            directoryTableBase,
                            ranges,
                            pointed,
                            rip,
                            rsp,
                            &pointerError,
                            L"KPRCB.Context");
                    }
                }
            }

            uint64_t specialVa = 0;
            if (kdbgSpecialOffset >= 0x40 &&
                kdbgSpecialOffset <= 0x40000 &&
                kdbgSpecialOffset + kSpecialCr3Offset + sizeof(uint64_t) <= prcbCap)
            {
                specialVa = prcb + kdbgSpecialOffset;
            }
            else if (pdbSpecialVa != 0)
            {
                specialVa = pdbSpecialVa;
            }

            if (specialVa != 0)
            {
                const uint64_t specialCr3 = MaskDirectoryTableBase(directoryTableBase);
                std::wstring cr3Error;
                WriteDumpVirtualRangeAnyCr3(
                    file,
                    device,
                    directoryTableBase,
                    ranges,
                    specialVa + kSpecialCr3Offset,
                    reinterpret_cast<const uint8_t*>(&specialCr3),
                    sizeof(specialCr3),
                    &cr3Error,
                    L"KPRCB.ProcessorState.Cr3");
            }

            if (wrote == 0)
            {
                if (error != nullptr)
                {
                    *error = lastError.empty()
                        ? L"KPRCB.ProcessorState offset unavailable"
                        : lastError;
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool PatchPrcbLeftoverLiveDumpRip(
        HANDLE file,
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t directoryTableBase,
        uint64_t prcb,
        uint32_t kdbgContextOffset,
        uint64_t replacementRip,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;

        do
        {
            if (prcb == 0 || replacementRip == 0)
            {
                break;
            }

            uint64_t leftoverRip = 0;
            symbols.ResolveSymbol(L"nt!IopLiveDumpCollectPages", &leftoverRip, nullptr);
            if (!IsKernelCanonicalVa(leftoverRip))
            {
                break;
            }

            uint64_t ripVas[3] = {};
            uint32_t ripCount = 0;
            uint64_t kdbgContextVa = 0;
            if (ResolvePrcbProcessorStateAddresses(
                    symbols,
                    prcb,
                    kdbgContextOffset,
                    &kdbgContextVa,
                    nullptr) &&
                kdbgContextVa != 0)
            {
                ripVas[ripCount++] = kdbgContextVa + offsetof(CONTEXT, Rip);
            }

            uint64_t pdbContextVa = 0;
            if (kdbgContextOffset != 0 &&
                ResolvePrcbProcessorStateAddresses(symbols, prcb, 0, &pdbContextVa, nullptr) &&
                pdbContextVa != 0 &&
                pdbContextVa != kdbgContextVa)
            {
                ripVas[ripCount++] = pdbContextVa + offsetof(CONTEXT, Rip);
            }

            uint32_t patched = 0;
            for (uint32_t index = 0; index < ripCount; ++index)
            {
                uint64_t liveRip = 0;
                if (!ReadKernelU64(device, ripVas[index], &liveRip) ||
                    liveRip < leftoverRip ||
                    liveRip > leftoverRip + 0x800)
                {
                    continue;
                }

                std::wstring patchError;
                if (WriteDumpVirtualRangeAnyCr3(
                        file,
                        device,
                        directoryTableBase,
                        ranges,
                        ripVas[index],
                        reinterpret_cast<const uint8_t*>(&replacementRip),
                        sizeof(replacementRip),
                        &patchError,
                        L"ProcessorState.ContextFrame.Rip"))
                {
                    ++patched;
                }
            }

            const uint32_t prcbCap = QueryPrcbSizeCap(symbols, 0);
            const uint32_t scanBytes = prcbCap > 0x20000 ? 0x20000 : prcbCap;
            for (uint32_t pageOff = 0; pageOff < scanBytes; pageOff += kPageSize)
            {
                std::vector<uint8_t> page;
                if (!ReadKernelBytes(device, prcb + pageOff, kPageSize, &page) ||
                    page.size() < kPageSize)
                {
                    continue;
                }

                for (uint32_t inner = 0; inner + offsetof(CONTEXT, Rip) + 8 <= kPageSize; inner += 16)
                {
                    uint32_t flags = 0;
                    uint16_t segCs = 0;
                    uint64_t liveRip = 0;
                    std::memcpy(&flags, page.data() + inner + offsetof(CONTEXT, ContextFlags), sizeof(flags));
                    std::memcpy(&segCs, page.data() + inner + offsetof(CONTEXT, SegCs), sizeof(segCs));
                    std::memcpy(&liveRip, page.data() + inner + offsetof(CONTEXT, Rip), sizeof(liveRip));
                    if ((flags & 0x100001ul) != 0x100001ul ||
                        segCs != 0x10 ||
                        liveRip < leftoverRip ||
                        liveRip > leftoverRip + 0x800)
                    {
                        continue;
                    }

                    const uint64_t ripVa = prcb + pageOff + inner + offsetof(CONTEXT, Rip);
                    std::wstring scanError;
                    if (WriteDumpVirtualRangeAnyCr3(
                            file,
                            device,
                            directoryTableBase,
                            ranges,
                            ripVa,
                            reinterpret_cast<const uint8_t*>(&replacementRip),
                            sizeof(replacementRip),
                            &scanError,
                            L"KPRCB leftover CONTEXT.Rip"))
                    {
                        ++patched;
                    }
                }
            }

            if (patched > 0)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"replaced leftover IopLiveDumpCollectPages RIP in " +
                        std::to_wstring(patched) + L" CONTEXT slot(s)");
                }
                ok = true;
            }
        } while (false);

        return ok;
    }

    void ApplyProcessDumpWinDbgFixups(
        HANDLE file,
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<PhysicalMemoryRange>& ranges,
        const ProcessDumpWinDbgFixup& fixup,
        DumpKernelCrashResult* result)
    {
        do
        {
            if (result == nullptr || file == INVALID_HANDLE_VALUE)
            {
                break;
            }

            const uint64_t kernelDtb = MaskDirectoryTableBase(fixup.KernelDirectoryTableBase);
            const uint64_t userDtb = MaskDirectoryTableBase(fixup.UserDirectoryTableBase);
            result->CurrentThread = fixup.Thread;
            result->Wow64Target = fixup.Wow64;

            if (userDtb != 0 && kernelDtb != 0 && userDtb != kernelDtb)
            {
                std::vector<uint8_t> kernelRoot;
                std::vector<uint8_t> userRoot;
                std::wstring readError;
                if (device.ReadPhysical(kernelDtb, kPageSize, &kernelRoot, &readError) &&
                    device.ReadPhysical(userDtb, kPageSize, &userRoot, &readError) &&
                    kernelRoot.size() >= kPageSize &&
                    userRoot.size() >= kPageSize)
                {
                    MergeKptiDirectoryRoot(&kernelRoot, userRoot);
                    std::wstring patchError;
                    if (WriteDumpPhysicalBytes(
                            file,
                            ranges,
                            kernelDtb,
                            kernelRoot.data(),
                            kPageSize,
                            &patchError))
                    {
                        result->KptiRootMerged = true;
                    }
                    else
                    {
                        result->Warnings.push_back(
                            L"KPTI page-table root merge failed: " + patchError);
                    }
                }
                else
                {
                    result->Warnings.push_back(
                        L"could not read process CR3 roots for KPTI merge: " + readError);
                }
            }

            // WinDbg 10.0.29617 uses KPRCB.ProcessorState.ContextFrame, not
            // the header CONTEXT. Leave a live user TrapFrame on CurrentThread
            // and dbgeng still drops into kd:x86. Point CurrentThread at the
            // target process when we have a kernel trap, otherwise synthesize
            // a kernel KTRAP_FRAME on that thread. IdleThread is fallback.
            uint64_t kpcr = 0;
            if (!ResolveLiveKpcr(device, &kpcr, nullptr, &result->Warnings) || kpcr == 0)
            {
                result->Warnings.push_back(
                    L"could not resolve CPU0 KPCR to pin CurrentThread");
                break;
            }

            const uint64_t prcb = ResolveKpcrPrcb(device, symbols, kpcr);
            const uint64_t idleThread = ResolvePrcbIdleThread(device, symbols, prcb);
            uint64_t displayThread = 0;
            if (fixup.Thread != 0 && IsKernelCanonicalVa(fixup.Thread))
            {
                displayThread = fixup.Thread;
            }
            else
            {
                displayThread = idleThread;
            }

            if (displayThread == 0 || kernelDtb == 0)
            {
                result->Warnings.push_back(
                    L"no display thread for CPU0 CurrentThread");
                break;
            }

            if (fixup.HeaderRip != 0 &&
                (!fixup.HasKernelTrap || displayThread == idleThread))
            {
                std::wstring trapError;
                if (SynthesizeIdleTrapFrame(
                        file,
                        device,
                        symbols,
                        ranges,
                        kernelDtb,
                        displayThread,
                        fixup.HeaderRip,
                        fixup.HeaderRsp,
                        &trapError))
                {
                    result->TrapFrameSynthesized = true;
                }
                else if (displayThread != idleThread && idleThread != 0)
                {
                    result->Warnings.push_back(
                        L"target trap synthesize failed, falling back to IdleThread: " +
                        trapError);
                    displayThread = idleThread;
                    std::wstring idleTrapError;
                    if (SynthesizeIdleTrapFrame(
                            file,
                            device,
                            symbols,
                            ranges,
                            kernelDtb,
                            idleThread,
                            fixup.HeaderRip,
                            fixup.HeaderRsp,
                            &idleTrapError))
                    {
                        result->TrapFrameSynthesized = true;
                    }
                    else
                    {
                        result->Warnings.push_back(
                            L"IdleThread trap frame synthesize failed: " + idleTrapError);
                    }
                }
                else
                {
                    result->Warnings.push_back(
                        L"display-thread trap frame synthesize failed: " + trapError);
                }
            }

            uint32_t currentThreadOffset = kKprcbCurrentThreadFallback;
            TypeFieldInfo currentThreadField = {};
            if (symbols.FindField(L"nt!_KPRCB", L"CurrentThread", &currentThreadField, nullptr) &&
                currentThreadField.Offset <= 0x4000)
            {
                currentThreadOffset = currentThreadField.Offset;
            }

            uint32_t nextThreadOffset = kKprcbNextThreadFallback;
            TypeFieldInfo nextThreadField = {};
            if (symbols.FindField(L"nt!_KPRCB", L"NextThread", &nextThreadField, nullptr) &&
                nextThreadField.Offset <= 0x4000)
            {
                nextThreadOffset = nextThreadField.Offset;
            }

            const uint64_t displayVa = displayThread;
            const uint64_t zeroVa = 0;
            std::wstring patchError;
            if (!WriteDumpVirtualRangeAnyCr3(
                    file,
                    device,
                    kernelDtb,
                    ranges,
                    prcb + currentThreadOffset,
                    reinterpret_cast<const uint8_t*>(&displayVa),
                    sizeof(displayVa),
                    &patchError,
                    L"CurrentThread"))
            {
                result->Warnings.push_back(L"CurrentThread patch failed: " + patchError);
                break;
            }

            std::wstring nextError;
            if (!WriteDumpVirtualRangeAnyCr3(
                    file,
                    device,
                    kernelDtb,
                    ranges,
                    prcb + nextThreadOffset,
                    reinterpret_cast<const uint8_t*>(&zeroVa),
                    sizeof(zeroVa),
                    &nextError,
                    L"NextThread"))
            {
                result->Warnings.push_back(L"NextThread clear failed: " + nextError);
            }

            result->CurrentThread = displayThread;
            result->CurrentProcessPatched = true;
            if (fixup.PrcbProcStateContextOffset != 0)
            {
                std::wstringstream offsetStream;
                offsetStream << L"KDBG OffsetPrcbProcStateContext=0x" << std::hex
                             << fixup.PrcbProcStateContextOffset;
                if (fixup.PrcbContextOffset != 0)
                {
                    offsetStream << L" OffsetPrcbContext=0x" << fixup.PrcbContextOffset;
                }
                result->Warnings.push_back(offsetStream.str());
            }

            if (fixup.HeaderRip != 0)
            {
                std::wstring contextError;
                if (WritePrcbProcessorContext(
                        file,
                        device,
                        symbols,
                        ranges,
                        kernelDtb,
                        prcb,
                        fixup.PrcbProcStateContextOffset,
                        fixup.PrcbContextOffset,
                        fixup.PrcbProcStateSpecialRegOffset,
                        fixup.PrcbSize,
                        fixup.HeaderRip,
                        fixup.HeaderRsp,
                        &contextError))
                {
                    result->ProcessorStatePatched = true;
                }
                else
                {
                    result->Warnings.push_back(
                        L"KPRCB.ProcessorState patch failed: " + contextError);
                }

                if (PatchPrcbLeftoverLiveDumpRip(
                        file,
                        device,
                        symbols,
                        ranges,
                        kernelDtb,
                        prcb,
                        fixup.PrcbProcStateContextOffset,
                        fixup.HeaderRip,
                        &result->Warnings))
                {
                    result->ProcessorStatePatched = true;
                }

                uint64_t processorBlock = 0;
                if (symbols.ResolveSymbol(L"nt!KiProcessorBlock", &processorBlock, nullptr) &&
                    IsKernelCanonicalVa(processorBlock))
                {
                    uint64_t blockPrcb = 0;
                    if (ReadKernelU64(device, processorBlock, &blockPrcb) &&
                        IsKernelCanonicalVa(blockPrcb) &&
                        blockPrcb != prcb)
                    {
                        std::wstring blockError;
                        WritePrcbProcessorContext(
                            file,
                            device,
                            symbols,
                            ranges,
                            kernelDtb,
                            blockPrcb,
                            fixup.PrcbProcStateContextOffset,
                            fixup.PrcbContextOffset,
                            fixup.PrcbProcStateSpecialRegOffset,
                            fixup.PrcbSize,
                            fixup.HeaderRip,
                            fixup.HeaderRsp,
                            &blockError);
                        PatchPrcbLeftoverLiveDumpRip(
                            file,
                            device,
                            symbols,
                            ranges,
                            kernelDtb,
                            blockPrcb,
                            fixup.PrcbProcStateContextOffset,
                            fixup.HeaderRip,
                            &result->Warnings);
                    }
                }

                std::wstring headerError;
                if (!PatchDumpHeaderContext(
                        file,
                        fixup.HeaderRip,
                        fixup.HeaderRsp,
                        &headerError))
                {
                    result->Warnings.push_back(
                        L"dump header CONTEXT patch failed: " + headerError);
                }

                uint64_t fileContextVa = 0;
                ResolvePrcbProcessorStateAddresses(
                    symbols,
                    prcb,
                    fixup.PrcbProcStateContextOffset,
                    &fileContextVa,
                    nullptr);
                if (PatchDumpFileContextRip(
                        file,
                        device,
                        kernelDtb,
                        ranges,
                        fileContextVa,
                        fixup.HeaderRip,
                        false,
                        &result->Warnings))
                {
                    result->ProcessorStatePatched = true;
                }

                uint64_t pdbFileContextVa = 0;
                if (ResolvePrcbProcessorStateAddresses(
                        symbols,
                        prcb,
                        0,
                        &pdbFileContextVa,
                        nullptr) &&
                    pdbFileContextVa != 0 &&
                    pdbFileContextVa != fileContextVa)
                {
                    PatchDumpFileContextRip(
                        file,
                        device,
                        kernelDtb,
                        ranges,
                        pdbFileContextVa,
                        fixup.HeaderRip,
                        false,
                        &result->Warnings);
                }

                if (fixup.SavedContext != 0)
                {
                    PatchDumpFileContextRip(
                        file,
                        device,
                        kernelDtb,
                        ranges,
                        fixup.SavedContext,
                        fixup.HeaderRip,
                        true,
                        &result->Warnings);
                }
            }
        } while (false);
    }

    struct PreparedKdbg
    {
        uint64_t Address = 0;
        uint64_t EncodedFlagAddress = 0;
        std::vector<uint8_t> PlainBlock;
        bool WasEncoded = false;
        bool Ready = false;
    };

    PreparedKdbg PreparePlainKdbg(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t kdBlock,
        std::vector<std::wstring>* warnings)
    {
        PreparedKdbg prepared;
        prepared.Address = kdBlock;

        do
        {
            if (kdBlock == 0)
            {
                break;
            }

            std::vector<uint8_t> block;
            if (!ReadKernelBytes(device, kdBlock, 0x800, &block))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"failed to read KdDebuggerDataBlock for decode");
                }
                break;
            }

            if (KdbgTagIsPlain(block))
            {
                block.resize(PlainKdbgSize(block));
                prepared.PlainBlock = std::move(block);
                prepared.Ready = true;
                break;
            }

            uint64_t waitNever = 0;
            uint64_t waitAlways = 0;
            uint64_t encodedFlag = 0;
            ResolveOptionalSymbol(symbols, L"nt!KiWaitNever", &waitNever, warnings);
            ResolveOptionalSymbol(symbols, L"nt!KiWaitAlways", &waitAlways, warnings);
            ResolveOptionalSymbol(symbols, L"nt!KdpDataBlockEncoded", &encodedFlag, warnings);
            if (waitNever == 0 || waitAlways == 0 || encodedFlag == 0)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"KdDebuggerDataBlock is encoded and KiWaitNever/Always/KdpDataBlockEncoded were not all resolved");
                }
                break;
            }

            uint64_t neverValue = 0;
            uint64_t alwaysValue = 0;
            if (!ReadKernelU64(device, waitNever, &neverValue) ||
                !ReadKernelU64(device, waitAlways, &alwaysValue))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"failed to read KDBG decode keys");
                }
                break;
            }

            prepared.EncodedFlagAddress = encodedFlag;
            prepared.WasEncoded = true;
            if (!DecodeEncodedKdbg(&block, neverValue, alwaysValue, encodedFlag, kdBlock))
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"KdCopyDataBlock-style decode did not produce a KDBG owner tag");
                }
                break;
            }

            block.resize(PlainKdbgSize(block));
            prepared.PlainBlock = std::move(block);
            prepared.Ready = true;
        } while (false);

        return prepared;
    }

    bool PatchPlainKdbgIntoDump(
        HANDLE file,
        DeviceClient& device,
        uint64_t directoryTableBase,
        const std::vector<PhysicalMemoryRange>& ranges,
        const PreparedKdbg& prepared,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (!prepared.Ready || prepared.PlainBlock.empty())
            {
                if (error != nullptr)
                {
                    *error = L"no decoded KDBG available to patch";
                }
                break;
            }

            if (!WriteDumpVirtualRange(
                    file,
                    device,
                    directoryTableBase,
                    ranges,
                    prepared.Address,
                    prepared.PlainBlock.data(),
                    static_cast<uint32_t>(prepared.PlainBlock.size()),
                    error,
                    L"KDBG"))
            {
                break;
            }

            if (prepared.WasEncoded && prepared.EncodedFlagAddress != 0)
            {
                const uint8_t zero = 0;
                std::wstring flagError;
                if (!WriteDumpVirtualRange(
                        file,
                        device,
                        directoryTableBase,
                        ranges,
                        prepared.EncodedFlagAddress,
                        &zero,
                        1,
                        &flagError,
                        L"KdpDataBlockEncoded") &&
                    error != nullptr)
                {
                    *error = L"decoded KDBG was written but KdpDataBlockEncoded clear failed: " +
                        flagError;
                    break;
                }
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadFieldU64(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t object,
        const wchar_t* typeName,
        const wchar_t* fieldName,
        const uint32_t* fallbackOffset,
        uint64_t* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || object == 0)
            {
                break;
            }

            uint32_t offset = 0;
            bool haveOffset = false;
            TypeFieldInfo field = {};
            std::wstring ignored;
            if (symbols.FindField(typeName, fieldName, &field, &ignored) &&
                field.Offset <= 0x4000)
            {
                offset = field.Offset;
                haveOffset = true;
            }
            else if (fallbackOffset != nullptr)
            {
                offset = *fallbackOffset;
                haveOffset = true;
            }

            if (haveOffset && ReadKernelU64(device, object + offset, value))
            {
                ok = true;
            }
        } while (false);

        return ok;
    }

    uint64_t ReadCanonicalFieldU64(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t object,
        const wchar_t* typeName,
        const wchar_t* fieldName)
    {
        uint64_t value = 0;
        if (ReadFieldU64(device, symbols, object, typeName, fieldName, nullptr, &value) &&
            IsKernelCanonicalVa(value))
        {
            return value;
        }

        return 0;
    }

    uint64_t ResolveKpcrPrcb(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t kpcr)
    {
        uint64_t prcb = 0;
        if (kpcr == 0)
        {
            return 0;
        }

        if (!ReadFieldU64(
                device,
                symbols,
                kpcr,
                L"nt!_KPCR",
                L"CurrentPrcb",
                &kKpcrCurrentPrcbOffset,
                &prcb) ||
            !IsKernelCanonicalVa(prcb))
        {
            prcb = kpcr + 0x180;
        }

        return prcb;
    }

    uint64_t ResolvePrcbIdleThread(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t prcb)
    {
        uint64_t idle = 0;
        if (prcb == 0)
        {
            return 0;
        }

        if (!ReadFieldU64(
                device,
                symbols,
                prcb,
                L"nt!_KPRCB",
                L"IdleThread",
                &kKprcbIdleThreadFallback,
                &idle) ||
            !IsKernelCanonicalVa(idle))
        {
            idle = 0;
        }

        return idle;
    }

    bool PokeDumpStructField(
        std::vector<uint8_t>* block,
        const TypeFieldInfo& field,
        const void* value,
        size_t valueSize)
    {
        bool ok = false;

        do
        {
            if (block == nullptr || value == nullptr || valueSize == 0)
            {
                break;
            }

            if (field.Offset + valueSize > block->size())
            {
                break;
            }

            std::memcpy(block->data() + field.Offset, value, valueSize);
            ok = true;
        } while (false);

        return ok;
    }

    bool SynthesizeIdleTrapFrame(
        HANDLE file,
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::vector<PhysicalMemoryRange>& ranges,
        uint64_t directoryTableBase,
        uint64_t idleThread,
        uint64_t rip,
        uint64_t rsp,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (idleThread == 0 || rip == 0)
            {
                if (error != nullptr)
                {
                    *error = L"idle trap frame needs IdleThread and a kernel RIP";
                }
                break;
            }

            TypeLayoutInfo frameLayout = {};
            std::wstring layoutError;
            if (!symbols.GetTypeLayout(L"nt!_KTRAP_FRAME", &frameLayout, &layoutError) ||
                frameLayout.Size < 0x80 ||
                frameLayout.Size > 0x400)
            {
                if (error != nullptr)
                {
                    *error = L"nt!_KTRAP_FRAME layout unavailable: " + layoutError;
                }
                break;
            }

            TypeFieldInfo ripField = {};
            TypeFieldInfo rspField = {};
            TypeFieldInfo csField = {};
            TypeFieldInfo ssField = {};
            TypeFieldInfo flagsField = {};
            TypeFieldInfo trapField = {};
            for (const TypeFieldInfo& field : frameLayout.Fields)
            {
                if (_wcsicmp(field.Name.c_str(), L"Rip") == 0)
                {
                    ripField = field;
                }
                else if (_wcsicmp(field.Name.c_str(), L"Rsp") == 0 ||
                         _wcsicmp(field.Name.c_str(), L"HardwareRsp") == 0)
                {
                    rspField = field;
                }
                else if (_wcsicmp(field.Name.c_str(), L"SegCs") == 0)
                {
                    csField = field;
                }
                else if (_wcsicmp(field.Name.c_str(), L"SegSs") == 0)
                {
                    ssField = field;
                }
                else if (_wcsicmp(field.Name.c_str(), L"EFlags") == 0)
                {
                    flagsField = field;
                }
            }

            if (ripField.Name.empty())
            {
                symbols.FindField(L"nt!_KTRAP_FRAME", L"Rip", &ripField, nullptr);
            }

            if (rspField.Name.empty() &&
                !symbols.FindField(L"nt!_KTRAP_FRAME", L"Rsp", &rspField, nullptr))
            {
                symbols.FindField(L"nt!_KTRAP_FRAME", L"HardwareRsp", &rspField, nullptr);
            }

            if (csField.Name.empty())
            {
                symbols.FindField(L"nt!_KTRAP_FRAME", L"SegCs", &csField, nullptr);
            }

            if (csField.Name.empty())
            {
                csField.Name = L"SegCs";
                csField.Offset = 0x170;
            }

            if (flagsField.Name.empty())
            {
                flagsField.Name = L"EFlags";
                flagsField.Offset = 0x178;
            }

            if (!symbols.FindField(L"nt!_KTHREAD", L"TrapFrame", &trapField, nullptr) ||
                ripField.Name.empty() ||
                rspField.Name.empty())
            {
                if (error != nullptr)
                {
                    *error = L"TrapFrame/Rip/Rsp field offsets unavailable";
                }
                break;
            }

            uint64_t stack = ReadCanonicalFieldU64(
                device,
                symbols,
                idleThread,
                L"nt!_KTHREAD",
                L"KernelStack");
            if (stack == 0)
            {
                stack = ReadCanonicalFieldU64(
                    device,
                    symbols,
                    idleThread,
                    L"nt!_KTHREAD",
                    L"InitialStack");
            }

            if (stack < frameLayout.Size + 0x40)
            {
                if (error != nullptr)
                {
                    *error = L"IdleThread has no kernel stack for a trap frame";
                }
                break;
            }

            const uint64_t trapVa = (stack - frameLayout.Size - 0x20) & ~0xFull;
            std::vector<uint8_t> frame(static_cast<size_t>(frameLayout.Size), 0);
            const uint64_t frameRip = rip;
            const uint64_t frameRsp = rsp != 0 ? rsp : stack;
            const uint16_t kernelCs = 0x10;
            const uint32_t eflags = 0x2;
            if (!PokeDumpStructField(&frame, ripField, &frameRip, sizeof(frameRip)) ||
                !PokeDumpStructField(&frame, rspField, &frameRsp, sizeof(frameRsp)))
            {
                if (error != nullptr)
                {
                    *error = L"trap frame Rip/Rsp poke failed";
                }
                break;
            }

            const uint16_t kernelSs = 0x18;
            if (!PokeDumpStructField(&frame, csField, &kernelCs, sizeof(kernelCs)))
            {
                if (error != nullptr)
                {
                    *error = L"trap frame SegCs poke failed";
                }
                break;
            }

            PokeDumpStructField(&frame, flagsField, &eflags, sizeof(eflags));
            if (!ssField.Name.empty())
            {
                PokeDumpStructField(&frame, ssField, &kernelSs, sizeof(kernelSs));
            }

            if (!WriteDumpVirtualRange(
                    file,
                    device,
                    directoryTableBase,
                    ranges,
                    trapVa,
                    frame.data(),
                    static_cast<uint32_t>(frame.size()),
                    error,
                    L"KTRAP_FRAME"))
            {
                break;
            }

            if (!WriteDumpVirtualRange(
                    file,
                    device,
                    directoryTableBase,
                    ranges,
                    idleThread + trapField.Offset,
                    reinterpret_cast<const uint8_t*>(&trapVa),
                    sizeof(trapVa),
                    error,
                    L"KTHREAD.TrapFrame"))
            {
                break;
            }

            TypeFieldInfo previousMode = {};
            if (symbols.FindField(L"nt!_KTHREAD", L"PreviousMode", &previousMode, nullptr) &&
                previousMode.Offset <= 0x4000)
            {
                const uint8_t kernelMode = 0;
                std::wstring ignored;
                WriteDumpVirtualRange(
                    file,
                    device,
                    directoryTableBase,
                    ranges,
                    idleThread + previousMode.Offset,
                    &kernelMode,
                    sizeof(kernelMode),
                    &ignored,
                    L"KTHREAD.PreviousMode");
            }

            ok = true;
        } while (false);

        return ok;
    }

    void CaptureLiveProcessorContext(
        DeviceClient& device,
        SymbolEngine& symbols,
        const ControlRegisters& registers,
        std::vector<uint8_t>* contextRecord,
        std::vector<std::wstring>* warnings,
        uint64_t specialCr3Override = 0)
    {
        if (contextRecord == nullptr)
        {
            return;
        }

        contextRecord->assign(kDumpAmd64ContextBytes + kSpecialRegistersBytes, 0);

        CONTEXT context = {};
        // Do not set CONTEXT_FLOATING_POINT. MxCsr lives in the integer
        // header, but FltSave is zeros here. Claiming FP state makes dbgeng
        // mark the record "partially valid" and fall back to the current
        // thread's user/WOW64 context (kd:x86, 32-bit _ETHREAD).
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
        context.MxCsr = 0x1F80;
        context.FltSave.ControlWord = 0x027F;
        context.FltSave.TagWord = 0xFF;
        context.FltSave.MxCsr = 0x1F80;
        context.FltSave.MxCsr_Mask = 0xFFFF;
        context.SegCs = 0x10;
        context.SegDs = 0x2B;
        context.SegEs = 0x2B;
        context.SegSs = 0x18;
        context.SegFs = 0x53;
        context.SegGs = 0x2B;
        context.EFlags = 0x2;

        uint64_t kernelGs = 0;
        uint64_t fsBase = 0;
        uint64_t star = 0;
        uint64_t lstar = 0;
        uint64_t cstar = 0;
        uint64_t fmask = 0;
        uint32_t ignoredCpu = 0;
        device.ReadMsr(KNDBG_MSR_IA32_FS_BASE, 0, &fsBase, &ignoredCpu, nullptr);
        device.ReadMsr(KNDBG_MSR_IA32_STAR, 0, &star, &ignoredCpu, nullptr);
        device.ReadMsr(KNDBG_MSR_IA32_LSTAR, 0, &lstar, &ignoredCpu, nullptr);
        device.ReadMsr(KNDBG_MSR_IA32_CSTAR, 0, &cstar, &ignoredCpu, nullptr);
        device.ReadMsr(KNDBG_MSR_IA32_FMASK, 0, &fmask, &ignoredCpu, nullptr);

        uint64_t kpcr = 0;
        ResolveLiveKpcr(device, &kpcr, &kernelGs, warnings);

        uint64_t prcb = 0;
        uint64_t idleThread = 0;
        if (kpcr != 0)
        {
            prcb = ResolveKpcrPrcb(device, symbols, kpcr);
            idleThread = ResolvePrcbIdleThread(device, symbols, prcb);
        }

        // Header RIP/RSP come from IdleThread (always kernel). A live user
        // trap frame here is how dbgeng ended up in kd:x86 on native x64.
        if (idleThread != 0)
        {
            context.Rsp = ReadCanonicalFieldU64(
                device,
                symbols,
                idleThread,
                L"nt!_KTHREAD",
                L"KernelStack");
            if (context.Rsp == 0)
            {
                context.Rsp = ReadCanonicalFieldU64(
                    device,
                    symbols,
                    idleThread,
                    L"nt!_KTHREAD",
                    L"InitialStack");
            }
        }

        if (context.Rsp == 0 && prcb != 0)
        {
            context.Rsp = ReadCanonicalFieldU64(
                device,
                symbols,
                prcb,
                L"nt!_KPRCB",
                L"RspBase");
        }

        uint64_t idleLoop = 0;
        std::wstring idleLoopError;
        if (symbols.ResolveSymbol(L"nt!KiIdleLoop", &idleLoop, &idleLoopError) &&
            IsKernelCanonicalVa(idleLoop))
        {
            context.Rip = idleLoop;
        }

        if (context.Rip == 0 && IsKernelCanonicalVa(lstar))
        {
            context.Rip = lstar;
        }

        if (context.Rip == 0)
        {
            const KernelModuleInfo* nt = FindNtModule(symbols);
            if (nt != nullptr && IsKernelCanonicalVa(nt->Base))
            {
                context.Rip = nt->Base;
            }
        }

        const size_t contextBytes = (std::min)(sizeof(context), static_cast<size_t>(kDumpAmd64ContextBytes));
        std::memcpy(contextRecord->data(), &context, contextBytes);

        const uint64_t specialCr3 = specialCr3Override != 0
            ? MaskDirectoryTableBase(specialCr3Override)
            : registers.Cr3;
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCr0Offset, registers.Cr0);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCr2Offset, registers.Cr2);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCr3Offset, specialCr3);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCr4Offset, registers.Cr4);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCr8Offset, registers.Cr8);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialGsBaseOffset, kpcr);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialGsSwapOffset, kernelGs);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialStarOffset, star);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialLstarOffset, lstar);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialCstarOffset, cstar);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialFmaskOffset, fmask);
        WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialFsBaseOffset, fsBase);

        IdtInfo idt = {};
        if (device.ReadIdt(0, &idt, nullptr) && idt.Base != 0)
        {
            // KDESCRIPTOR: Pad[3], Limit, Base at +8.
            const uint16_t limit = static_cast<uint16_t>(idt.Limit);
            std::memcpy(
                contextRecord->data() + kDumpAmd64ContextBytes + kSpecialIdtrOffset + 6,
                &limit,
                sizeof(limit));
            WriteU64Raw(contextRecord, kDumpAmd64ContextBytes + kSpecialIdtrOffset + 8, idt.Base);
        }

        if (kpcr == 0 && warnings != nullptr)
        {
            warnings->push_back(
                L"processor GsBase/KPCR was not captured; WinDbg may have no current thread");
        }
    }

    uint64_t DecodeU64(const std::vector<uint8_t>& bytes)
    {
        uint64_t value = 0;
        if (bytes.size() >= sizeof(value))
        {
            std::memcpy(&value, bytes.data(), sizeof(value));
        }
        return value;
    }

    bool EnableSeDebugPrivilege(std::wstring* warning)
    {
        bool ok = false;
        HANDLE token = nullptr;

        do
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            {
                if (warning != nullptr)
                {
                    *warning = L"OpenProcessToken failed (gle=" +
                        std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            LUID luid = {};
            if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid))
            {
                if (warning != nullptr)
                {
                    *warning = L"LookupPrivilegeValue(SeDebugPrivilege) failed (gle=" +
                        std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            TOKEN_PRIVILEGES privileges = {};
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Luid = luid;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr))
            {
                if (warning != nullptr)
                {
                    *warning = L"AdjustTokenPrivileges(SeDebugPrivilege) failed (gle=" +
                        std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                if (warning != nullptr)
                {
                    *warning = L"SeDebugPrivilege not assigned (not running elevated?)";
                }
                break;
            }

            ok = true;
        } while (false);

        if (token != nullptr)
        {
            CloseHandle(token);
        }

        return ok;
    }

    void SortAndMergePhysicalRuns(std::vector<PhysicalMemoryRange>* runs);

    bool NormalizePhysicalRanges(
        std::vector<PhysicalMemoryRange>* ranges,
        uint64_t maxPayloadBytes,
        uint64_t* payloadBytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (ranges == nullptr || payloadBytes == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid physical-range output";
                }
                break;
            }

            SortAndMergePhysicalRuns(ranges);

            std::vector<PhysicalMemoryRange> normalized;
            uint64_t total = 0;
            bool failed = false;
            for (const PhysicalMemoryRange& range : *ranges)
            {
                if (range.ByteCount == 0)
                {
                    continue;
                }

                if ((range.BaseAddress & (kPageSize - 1ull)) != 0 ||
                    (range.ByteCount & (kPageSize - 1ull)) != 0)
                {
                    if (error != nullptr)
                    {
                        *error = L"physical range is not page-aligned";
                    }
                    failed = true;
                    break;
                }

                PhysicalMemoryRange kept = range;
                if (maxPayloadBytes != 0)
                {
                    if (total >= maxPayloadBytes)
                    {
                        break;
                    }

                    const uint64_t remaining = maxPayloadBytes - total;
                    if (kept.ByteCount > remaining)
                    {
                        kept.ByteCount = remaining & ~(static_cast<uint64_t>(kPageSize) - 1ull);
                    }

                    if (kept.ByteCount == 0)
                    {
                        break;
                    }
                }

                if (total > (std::numeric_limits<uint64_t>::max)() - kept.ByteCount)
                {
                    if (error != nullptr)
                    {
                        *error = L"physical range byte count overflow";
                    }
                    failed = true;
                    break;
                }

                total += kept.ByteCount;
                normalized.push_back(kept);
            }

            if (failed)
            {
                break;
            }

            if (normalized.empty())
            {
                if (error != nullptr)
                {
                    *error = (maxPayloadBytes != 0)
                        ? L"/max is smaller than one page or excludes every RAM run"
                        : L"no physical RAM ranges to dump";
                }
                break;
            }

            if (normalized.size() > kCrashDumpMaxPhysicalRuns)
            {
                if (error != nullptr)
                {
                    *error = L"complete dump header supports at most " +
                        std::to_wstring(kCrashDumpMaxPhysicalRuns) +
                        L" physical runs (got " + std::to_wstring(normalized.size()) +
                        L"); use /max to dump a prefix";
                }
                break;
            }

            *ranges = std::move(normalized);
            *payloadBytes = total;
            ok = true;
        } while (false);

        return ok;
    }

    uint64_t RangeEnd(uint64_t base, uint64_t count)
    {
        uint64_t end = base;
        if (count != 0)
        {
            if (base > (std::numeric_limits<uint64_t>::max)() - count)
            {
                end = (std::numeric_limits<uint64_t>::max)();
            }
            else
            {
                end = base + count;
            }
        }

        return end;
    }

    void SortAndMergePhysicalRuns(std::vector<PhysicalMemoryRange>* runs)
    {
        if (runs == nullptr)
        {
            return;
        }

        if (runs->size() < 2)
        {
            if (!runs->empty() && (*runs)[0].ByteCount == 0)
            {
                runs->clear();
            }
            return;
        }

        std::sort(
            runs->begin(),
            runs->end(),
            [](const PhysicalMemoryRange& left, const PhysicalMemoryRange& right)
            {
                return left.BaseAddress < right.BaseAddress;
            });

        std::vector<PhysicalMemoryRange> merged;
        merged.reserve(runs->size());
        for (const PhysicalMemoryRange& run : *runs)
        {
            if (run.ByteCount == 0)
            {
                continue;
            }

            if (merged.empty())
            {
                merged.push_back(run);
                continue;
            }

            PhysicalMemoryRange& last = merged.back();
            const uint64_t lastEnd = RangeEnd(last.BaseAddress, last.ByteCount);
            if (run.BaseAddress > lastEnd)
            {
                merged.push_back(run);
                continue;
            }

            const uint64_t runEnd = RangeEnd(run.BaseAddress, run.ByteCount);
            if (runEnd > lastEnd)
            {
                last.ByteCount = runEnd - last.BaseAddress;
            }
        }

        *runs = std::move(merged);
    }

    void CoalescePhysicalRunsToMax(
        std::vector<PhysicalMemoryRange>* runs,
        size_t maxRuns)
    {
        if (runs == nullptr)
        {
            return;
        }

        SortAndMergePhysicalRuns(runs);
        if (maxRuns == 0)
        {
            return;
        }

        while (runs->size() > maxRuns)
        {
            if (runs->size() < 2)
            {
                break;
            }

            size_t best = 0;
            uint64_t bestGap = (std::numeric_limits<uint64_t>::max)();
            for (size_t index = 0; index + 1 < runs->size(); ++index)
            {
                const uint64_t leftEnd =
                    RangeEnd((*runs)[index].BaseAddress, (*runs)[index].ByteCount);
                if (leftEnd > (*runs)[index + 1].BaseAddress)
                {
                    continue;
                }

                const uint64_t gap = (*runs)[index + 1].BaseAddress - leftEnd;
                if (gap < bestGap)
                {
                    bestGap = gap;
                    best = index;
                }
            }

            const uint64_t newEnd = RangeEnd(
                (*runs)[best + 1].BaseAddress,
                (*runs)[best + 1].ByteCount);
            if (newEnd < (*runs)[best].BaseAddress)
            {
                break;
            }

            (*runs)[best].ByteCount = newEnd - (*runs)[best].BaseAddress;
            runs->erase(runs->begin() + static_cast<std::ptrdiff_t>(best + 1));
        }
    }

    void IntersectPhysicalRunsWithAllowed(
        std::vector<PhysicalMemoryRange>* runs,
        const std::vector<PhysicalMemoryRange>& allowed)
    {
        if (runs == nullptr || runs->empty() || allowed.empty())
        {
            return;
        }

        SortAndMergePhysicalRuns(runs);
        std::vector<PhysicalMemoryRange> windows = allowed;
        SortAndMergePhysicalRuns(&windows);
        if (windows.empty())
        {
            return;
        }

        std::vector<PhysicalMemoryRange> clipped;
        clipped.reserve(runs->size());
        size_t windowIndex = 0;
        for (const PhysicalMemoryRange& run : *runs)
        {
            const uint64_t runEnd = RangeEnd(run.BaseAddress, run.ByteCount);
            while (windowIndex < windows.size() &&
                   RangeEnd(windows[windowIndex].BaseAddress, windows[windowIndex].ByteCount) <=
                       run.BaseAddress)
            {
                ++windowIndex;
            }

            for (size_t index = windowIndex; index < windows.size(); ++index)
            {
                const PhysicalMemoryRange& window = windows[index];
                if (window.BaseAddress >= runEnd)
                {
                    break;
                }

                const uint64_t start = (std::max)(run.BaseAddress, window.BaseAddress);
                const uint64_t end = (std::min)(
                    runEnd,
                    RangeEnd(window.BaseAddress, window.ByteCount));
                if (end <= start)
                {
                    continue;
                }

                PhysicalMemoryRange piece = {};
                piece.BaseAddress = start;
                piece.ByteCount = end - start;
                clipped.push_back(piece);
            }
        }

        *runs = std::move(clipped);
        SortAndMergePhysicalRuns(runs);
    }

    enum class PageTableHalf
    {
        Both = 0,
        User,
        Kernel
    };

    uint64_t MaskDirectoryTableBase(uint64_t value)
    {
        return value & 0x000FFFFFFFFFF000ull;
    }

    struct ProcessDumpWalkPlan
    {
        uint64_t HeaderDtb = 0;
        uint64_t PrimaryDtb = 0;
        PageTableHalf PrimaryHalf = PageTableHalf::Both;
        uint64_t SecondaryDtb = 0;
        PageTableHalf SecondaryHalf = PageTableHalf::Kernel;
    };

    // KPTI keeps user pages on UserDirectoryTableBase. Walking only the
    // kernel CR3 misses the process user address space. The dump header
    // still needs a kernel CR3 so WinDbg can translate nt/KDBG.
    ProcessDumpWalkPlan MakeProcessDumpWalkPlan(
        uint64_t kernelDtb,
        uint64_t userDtb,
        uint64_t liveKernelCr3)
    {
        ProcessDumpWalkPlan plan;
        const uint64_t kernel = MaskDirectoryTableBase(kernelDtb);
        const uint64_t user = MaskDirectoryTableBase(userDtb);
        const uint64_t live = MaskDirectoryTableBase(liveKernelCr3);

        if (user != 0 && kernel != 0 && user != kernel)
        {
            plan.PrimaryDtb = user;
            plan.PrimaryHalf = PageTableHalf::User;
            plan.SecondaryDtb = kernel;
            plan.SecondaryHalf = PageTableHalf::Kernel;
            plan.HeaderDtb = kernel;
        }
        else
        {
            const uint64_t dtb = kernel != 0 ? kernel : user;
            plan.PrimaryDtb = dtb;
            plan.PrimaryHalf = PageTableHalf::Both;
            plan.HeaderDtb = dtb;
            if (kernel == 0 && user != 0 && live != 0 && live != user)
            {
                plan.SecondaryDtb = live;
                plan.SecondaryHalf = PageTableHalf::Kernel;
                plan.HeaderDtb = live;
            }
        }

        return plan;
    }

    uint64_t CountPhysicalRunPages(const std::vector<PhysicalMemoryRange>& runs)
    {
        uint64_t pages = 0;
        for (const PhysicalMemoryRange& run : runs)
        {
            pages += run.ByteCount / kPageSize;
        }

        return pages;
    }

    uint64_t SumPhysicalRunBytes(const std::vector<PhysicalMemoryRange>& runs)
    {
        uint64_t total = 0;
        for (const PhysicalMemoryRange& run : runs)
        {
            if (total > (std::numeric_limits<uint64_t>::max)() - run.ByteCount)
            {
                return (std::numeric_limits<uint64_t>::max)();
            }

            total += run.ByteCount;
        }

        return total;
    }

    bool CollectResidentPhysicalRunsFromDtb(
        DeviceClient& device,
        uint64_t directoryTableBase,
        bool la57,
        PageTableHalf half,
        std::vector<PhysicalMemoryRange>* ranges,
        uint64_t* pageCount,
        uint32_t* skippedTables,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (ranges == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid page-table walk output";
                }
                break;
            }

            ranges->clear();
            if (pageCount != nullptr)
            {
                *pageCount = 0;
            }
            if (skippedTables != nullptr)
            {
                *skippedTables = 0;
            }

            const uint64_t dtb = MaskDirectoryTableBase(directoryTableBase);
            if (dtb == 0)
            {
                if (error != nullptr)
                {
                    *error = L"process directory table base is zero";
                }
                break;
            }

            const uint32_t levels = la57 ? 5u : 4u;
            const int shifts5[5] = { 48, 39, 30, 21, 12 };
            const int* shifts = la57 ? &shifts5[0] : &shifts5[1];
            constexpr uint64_t presentBit = 1ull;
            constexpr uint64_t largeBit = 1ull << 7;
            constexpr uint64_t prototypeBit = 1ull << 10;
            constexpr uint64_t transitionBit = 1ull << 11;
            constexpr uint64_t pfnMask = 0x000FFFFFFFFFF000ull;
            constexpr uint32_t maxTables = 2000000;
            constexpr uint32_t maxLeaves = 8000000;

            uint32_t rootBegin = 0;
            uint32_t rootEnd = 512;
            if (half == PageTableHalf::User)
            {
                rootEnd = 256;
            }
            else if (half == PageTableHalf::Kernel)
            {
                rootBegin = 256;
            }

            struct WalkFrame
            {
                uint64_t TablePa = 0;
                uint64_t VaBase = 0;
                uint32_t Level = 0;
                uint32_t NextIndex = 0;
                uint32_t IndexEnd = 512;
                bool HaveTable = false;
                std::vector<uint8_t> Entries;
            };

            std::vector<WalkFrame> stack;
            WalkFrame root = {};
            root.TablePa = dtb;
            root.NextIndex = rootBegin;
            root.IndexEnd = rootEnd;
            stack.push_back(root);

            std::vector<PhysicalMemoryRange> collected;
            collected.reserve(4096);
            std::set<uint64_t> visitedTables;
            uint32_t tables = 0;
            uint32_t leaves = 0;
            uint32_t skipped = 0;
            bool overflow = false;

            auto addRange = [&](uint64_t base, uint64_t bytes)
            {
                if (bytes == 0 || (bytes & (bytes - 1ull)) != 0)
                {
                    return;
                }

                const uint64_t aligned = base & ~(bytes - 1ull);
                PhysicalMemoryRange range = {};
                range.BaseAddress = aligned;
                range.ByteCount = bytes;
                collected.push_back(range);
            };

            while (!stack.empty() && !overflow)
            {
                WalkFrame& frame = stack.back();
                if (!frame.HaveTable)
                {
                    if (visitedTables.find(frame.TablePa) != visitedTables.end())
                    {
                        stack.pop_back();
                        continue;
                    }

                    if (tables >= maxTables)
                    {
                        overflow = true;
                        break;
                    }

                    std::wstring readError;
                    if (!device.ReadPhysical(frame.TablePa, 0x1000, &frame.Entries, &readError) ||
                        frame.Entries.size() < 0x1000)
                    {
                        ++skipped;
                        stack.pop_back();
                        continue;
                    }

                    visitedTables.insert(frame.TablePa);
                    addRange(frame.TablePa, 0x1000);
                    ++tables;
                    frame.HaveTable = true;
                }

                if (frame.NextIndex >= frame.IndexEnd)
                {
                    stack.pop_back();
                    continue;
                }

                const uint32_t index = frame.NextIndex++;
                uint64_t entry = 0;
                std::memcpy(&entry, frame.Entries.data() + (index * sizeof(entry)), sizeof(entry));
                if ((entry & presentBit) == 0)
                {
                    // Transition PTEs are still in RAM. Prototype PTEs store a
                    // proto-PTE VA, not a PFN, so they must not be collected.
                    const bool leafLevel = (frame.Level + 1u) == levels;
                    if (leafLevel &&
                        (entry & prototypeBit) == 0 &&
                        (entry & transitionBit) != 0)
                    {
                        const uint64_t transPa = entry & pfnMask;
                        if (transPa != 0)
                        {
                            if (leaves >= maxLeaves)
                            {
                                overflow = true;
                                break;
                            }

                            addRange(transPa, kPageSize);
                            ++leaves;
                        }
                    }
                    continue;
                }

                const uint64_t childPa = entry & pfnMask;
                const uint64_t childVa = frame.VaBase +
                    (static_cast<uint64_t>(index) << shifts[frame.Level]);
                const bool leafLevel = (frame.Level + 1u) == levels;
                const int levelShift = shifts[frame.Level];
                const bool largeOk = (levelShift == 30 || levelShift == 21);
                if (leafLevel || (largeOk && (entry & largeBit) != 0))
                {
                    if (leaves >= maxLeaves)
                    {
                        overflow = true;
                        break;
                    }

                    addRange(childPa, 1ull << levelShift);
                    ++leaves;
                    continue;
                }

                if (childPa == 0 ||
                    childPa == frame.TablePa ||
                    childPa == dtb ||
                    visitedTables.find(childPa) != visitedTables.end())
                {
                    continue;
                }

                WalkFrame child = {};
                child.TablePa = childPa;
                child.VaBase = childVa;
                child.Level = frame.Level + 1;
                stack.push_back(child);
            }

            if (skippedTables != nullptr)
            {
                *skippedTables = skipped;
            }

            if (overflow)
            {
                if (error != nullptr)
                {
                    *error = L"process page-table walk exceeded safety bounds";
                }
                break;
            }

            if (collected.empty())
            {
                if (error != nullptr)
                {
                    *error = L"process DTB walk found no resident pages";
                }
                break;
            }

            SortAndMergePhysicalRuns(&collected);
            *ranges = std::move(collected);
            if (pageCount != nullptr)
            {
                *pageCount = CountPhysicalRunPages(*ranges);
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveOptionalSymbol(
        SymbolEngine& symbols,
        const wchar_t* name,
        uint64_t* address,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;
        std::wstring resolveError;
        uint64_t resolved = 0;
        if (symbols.ResolveSymbol(name, &resolved, &resolveError) && resolved != 0)
        {
            *address = resolved;
            ok = true;
        }
        else if (warnings != nullptr)
        {
            warnings->push_back(std::wstring(name) + L" unresolved: " + resolveError);
        }

        return ok;
    }

    uint64_t ResolveKernelPointerTarget(
        DeviceClient& device,
        uint64_t symbolAddress)
    {
        uint64_t value = 0;
        std::vector<uint8_t> bytes;
        std::wstring ignored;
        if (device.ReadMemory(symbolAddress, sizeof(uint64_t), &bytes, &ignored) &&
            bytes.size() >= sizeof(uint64_t))
        {
            const uint64_t pointed = DecodeU64(bytes);
            if (IsKernelCanonicalVa(pointed))
            {
                value = pointed;
            }
        }

        return value;
    }

    bool WriteAll(HANDLE file, const void* data, DWORD length, std::wstring* error)
    {
        bool ok = false;

        do
        {
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            DWORD remaining = length;
            while (remaining > 0)
            {
                DWORD written = 0;
                if (!WriteFile(file, bytes, remaining, &written, nullptr) || written == 0)
                {
                    if (error != nullptr)
                    {
                        *error = L"WriteFile failed (gle=" +
                            std::to_wstring(GetLastError()) + L")";
                    }
                    break;
                }

                bytes += written;
                remaining -= written;
            }

            if (remaining != 0)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    const wchar_t* NtStatusName(long status)
    {
        const wchar_t* name = L"";
        switch (static_cast<unsigned long>(status))
        {
        case 0x00000000ul:
            name = L"STATUS_SUCCESS";
            break;
        case 0xC0000002ul:
            name = L"STATUS_NOT_IMPLEMENTED";
            break;
        case 0xC000000Dul:
            name = L"STATUS_INVALID_PARAMETER";
            break;
        case 0xC0000022ul:
            name = L"STATUS_ACCESS_DENIED";
            break;
        case 0xC0000061ul:
            name = L"STATUS_PRIVILEGE_NOT_HELD";
            break;
        case 0xC000009Aul:
            name = L"STATUS_INSUFFICIENT_RESOURCES";
            break;
        case 0xC0000004ul:
            name = L"STATUS_INFO_LENGTH_MISMATCH";
            break;
        case 0xC00000BBul:
            name = L"STATUS_NOT_SUPPORTED";
            break;
        case 0xC0000010ul:
            name = L"STATUS_INVALID_DEVICE_REQUEST";
            break;
        case 0xC0000354ul:
            name = L"STATUS_DEBUGGER_INACTIVE";
            break;
        default:
            break;
        }

        return name;
    }

    // SYSDBG_LIVEDUMP_CONTROL from phnt/ntexapi.h. Sizes are locked below.
    struct LiveDumpFlags
    {
        unsigned long UseDumpStorageStack : 1;
        unsigned long CompressMemoryPagesData : 1;
        unsigned long IncludeUserSpaceMemoryPages : 1;
        unsigned long AbortIfMemoryPressure : 1;
        unsigned long SelectiveDump : 1;
        unsigned long Reserved : 27;
    };

    struct LiveDumpAddPages
    {
        unsigned long HypervisorPages : 1;
        unsigned long NonEssentialHypervisorPages : 1;
        unsigned long Reserved : 30;
    };

    struct LiveDumpControlV1
    {
        unsigned long Version;
        unsigned long BugCheckCode;
        ULONG_PTR BugCheckParam1;
        ULONG_PTR BugCheckParam2;
        ULONG_PTR BugCheckParam3;
        ULONG_PTR BugCheckParam4;
        HANDLE DumpFileHandle;
        HANDLE CancelEventHandle;
        LiveDumpFlags Flags;
        LiveDumpAddPages AddPagesControl;
    };

    struct LiveDumpControlV2
    {
        LiveDumpControlV1 V1;
        void* SelectiveControl;
    };

    struct LiveDumpSelectiveControl
    {
        unsigned long Version;
        unsigned long Size;
        unsigned long long Flags;
        unsigned long long Reserved[4];
    };

    struct LiveDumpAttemptResult
    {
        long Status = static_cast<long>(0xC000000D);
        unsigned long VersionUsed = 0;
    };

    static_assert(sizeof(LiveDumpFlags) == 4, "live-dump flags must be one ULONG");
    static_assert(sizeof(LiveDumpAddPages) == 4, "live-dump add-pages must be one ULONG");
    static_assert(sizeof(LiveDumpControlV1) == 64, "SYSDBG_LIVEDUMP_CONTROL V1 is 64 bytes on x64");
    static_assert(sizeof(LiveDumpControlV2) == 72, "SYSDBG_LIVEDUMP_CONTROL V2 is 72 bytes on x64");
    static_assert(sizeof(LiveDumpSelectiveControl) == 48, "SYSDBG_LIVEDUMP_SELECTIVE_CONTROL is 48 bytes");
    static_assert(offsetof(LiveDumpControlV1, DumpFileHandle) == 40, "DumpFileHandle offset");
    static_assert(offsetof(LiveDumpControlV1, Flags) == 56, "Flags offset");
    static_assert(offsetof(LiveDumpControlV1, AddPagesControl) == 60, "AddPagesControl offset");
    static_assert(offsetof(LiveDumpControlV2, SelectiveControl) == 64, "SelectiveControl offset");

    bool IsLiveDumpVersionFallbackStatus(long status)
    {
        const unsigned long value = static_cast<unsigned long>(status);
        return value == 0xC0000004ul ||
            value == 0xC000000Dul ||
            value == 0xC0000059ul ||
            value == 0xC00000BBul;
    }

    bool IsLiveDumpIoFallbackStatus(long status)
    {
        const unsigned long value = static_cast<unsigned long>(status);
        return value == 0xC0000002ul ||
            value == 0xC0000004ul ||
            value == 0xC000000Dul ||
            value == 0xC0000010ul ||
            value == 0xC000009Aul ||
            value == 0xC00000BBul;
    }

    bool LiveDumpFileIsEmpty(HANDLE file)
    {
        LARGE_INTEGER size = {};
        return file != INVALID_HANDLE_VALUE &&
            GetFileSizeEx(file, &size) &&
            size.QuadPart == 0;
    }

    typedef long (WINAPI* NtSystemDebugControlFn)(
        unsigned long command,
        void* inputBuffer,
        unsigned long inputLength,
        void* outputBuffer,
        unsigned long outputLength,
        unsigned long* returnLength);

    void ResetLiveDumpFile(HANDLE file)
    {
        if (file != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER zero = {};
            SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
            SetEndOfFile(file);
        }
    }

    LiveDumpAttemptResult InvokeOsLiveDump(
        NtSystemDebugControlFn ntSystemDebugControl,
        HANDLE file,
        bool useDumpStorageStack,
        bool includeUserPages,
        bool compress,
        bool includeHypervisorPages)
    {
        LiveDumpAttemptResult attempt;

        do
        {
            LiveDumpSelectiveControl selective = {};
            selective.Version = 1;
            selective.Size = static_cast<unsigned long>(sizeof(selective));

            LiveDumpControlV2 control = {};
            control.V1.BugCheckCode = kBugCheckLiveSystemDump;
            control.V1.DumpFileHandle = file;
            control.V1.Flags.UseDumpStorageStack = useDumpStorageStack ? 1u : 0u;
            control.V1.Flags.CompressMemoryPagesData = compress ? 1u : 0u;
            control.V1.Flags.IncludeUserSpaceMemoryPages = includeUserPages ? 1u : 0u;
            control.V1.AddPagesControl.HypervisorPages = includeHypervisorPages ? 1u : 0u;
            // Win11 probes this when Version==2. A null pointer is
            // STATUS_INVALID_PARAMETER on some builds even if SelectiveDump=0.
            control.SelectiveControl = &selective;
            control.V1.Version = kLiveDumpControlVersion2;

            attempt.Status = ntSystemDebugControl(
                kSysDbgGetLiveKernelDump,
                &control,
                static_cast<unsigned long>(sizeof(control)),
                nullptr,
                0,
                nullptr);
            if (attempt.Status >= 0)
            {
                attempt.VersionUsed = kLiveDumpControlVersion2;
                break;
            }

            if (!IsLiveDumpVersionFallbackStatus(attempt.Status) ||
                !LiveDumpFileIsEmpty(file))
            {
                break;
            }

            ResetLiveDumpFile(file);
            control.V1.Version = kLiveDumpControlVersion1;
            control.SelectiveControl = nullptr;
            attempt.Status = ntSystemDebugControl(
                kSysDbgGetLiveKernelDump,
                &control.V1,
                static_cast<unsigned long>(sizeof(control.V1)),
                nullptr,
                0,
                nullptr);
            if (attempt.Status >= 0)
            {
                attempt.VersionUsed = kLiveDumpControlVersion1;
            }
        } while (false);

        return attempt;
    }
}

bool BuildCompleteDumpHeader(
    const std::vector<PhysicalMemoryRange>& ranges,
    const DumpKernelHeaderInfo& info,
    std::vector<uint8_t>* header,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (header == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid dump-header output";
            }
            break;
        }

        if (ranges.empty() || ranges.size() > kCrashDumpMaxPhysicalRuns)
        {
            if (error != nullptr)
            {
                *error = L"complete dump header supports 1.." +
                    std::to_wstring(kCrashDumpMaxPhysicalRuns) +
                    L" physical runs (got " + std::to_wstring(ranges.size()) + L")";
            }
            break;
        }

        uint64_t numberOfPages = 0;
        bool invalidRange = false;
        for (const PhysicalMemoryRange& range : ranges)
        {
            if (range.ByteCount == 0 ||
                (range.BaseAddress & (kPageSize - 1ull)) != 0 ||
                (range.ByteCount & (kPageSize - 1ull)) != 0)
            {
                invalidRange = true;
                break;
            }

            const uint64_t pages = range.ByteCount / kPageSize;
            if (numberOfPages > (std::numeric_limits<uint64_t>::max)() - pages)
            {
                invalidRange = true;
                break;
            }

            numberOfPages += pages;
        }

        if (invalidRange || numberOfPages == 0)
        {
            if (error != nullptr)
            {
                *error = L"physical runs must be non-empty page-aligned RAM ranges";
            }
            break;
        }

        if (numberOfPages > (std::numeric_limits<uint64_t>::max)() / kPageSize)
        {
            if (error != nullptr)
            {
                *error = L"physical run page count overflows dump payload size";
            }
            break;
        }

        const uint64_t payloadBytes = numberOfPages * kPageSize;
        if (payloadBytes > static_cast<uint64_t>((std::numeric_limits<int64_t>::max)()) -
                kCrashDumpHeaderBytes)
        {
            if (error != nullptr)
            {
                *error = L"required dump size does not fit in DUMP_HEADER64.RequiredDumpSpace";
            }
            break;
        }

        // Build through DUMP_HEADER64 so field offsets match what dbgeng
        // actually reads. A previous writer stored DumpType at 0xF94; WinDbg
        // reads it at 0xF98 and then treats RequiredDumpSpace's low dword as
        // an unknown dump type, so OpenDumpFile fails.
        DUMP_HEADER64 dump = {};
        dump.Signature = DUMP_SIGNATURE64;
        dump.ValidDump = DUMP_VALID_DUMP64;
        dump.MajorVersion = info.MajorVersion;
        dump.MinorVersion = info.MinorVersion;
        dump.DirectoryTableBase = info.DirectoryTableBase;
        dump.PfnDataBase = info.PfnDataBase;
        dump.PsLoadedModuleList = info.PsLoadedModuleList;
        dump.PsActiveProcessHead = info.PsActiveProcessHead;
        dump.MachineImageType = IMAGE_FILE_MACHINE_AMD64;
        dump.NumberProcessors = info.NumberProcessors == 0 ? 1u : info.NumberProcessors;
        dump.BugCheckCode = kBugCheckLiveSystemDump;
        dump.BugCheckParameter1 = info.BugCheckParameter1;
        dump.BugCheckParameter2 = info.BugCheckParameter2;
        const char versionUser[] = "KnLiveDbg";
        std::memcpy(dump.VersionUser, versionUser, sizeof(versionUser) - 1);
        dump.KdDebuggerDataBlock = info.KdDebuggerDataBlock;

        dump.PhysicalMemoryBlock.NumberOfRuns = static_cast<ULONG>(ranges.size());
        dump.PhysicalMemoryBlock.NumberOfPages = numberOfPages;
        PHYSICAL_MEMORY_RUN64* runs = reinterpret_cast<PHYSICAL_MEMORY_RUN64*>(
            dump.PhysicalMemoryBlockBuffer +
            FIELD_OFFSET(PHYSICAL_MEMORY_DESCRIPTOR64, Run));
        for (size_t index = 0; index < ranges.size(); ++index)
        {
            runs[index].BasePage = ranges[index].BaseAddress / kPageSize;
            runs[index].PageCount = ranges[index].ByteCount / kPageSize;
        }

        dump.DumpType = DUMP_TYPE_FULL;
        dump.RequiredDumpSpace.QuadPart =
            static_cast<LONGLONG>(kCrashDumpHeaderBytes + payloadBytes);

        FILETIME fileTime = {};
        GetSystemTimeAsFileTime(&fileTime);
        dump.SystemTime.LowPart = fileTime.dwLowDateTime;
        dump.SystemTime.HighPart = static_cast<LONG>(fileTime.dwHighDateTime);

        std::string comment = info.Comment.empty()
            ? "KnLiveDbg live complete dump (inconsistent)"
            : info.Comment;
        if (comment.size() >= sizeof(dump.Comment))
        {
            comment.resize(sizeof(dump.Comment) - 1);
        }
        std::memcpy(dump.Comment, comment.data(), comment.size());

        dump.ProductType = info.ProductType;
        dump.SuiteMask = info.SuiteMask;
        dump.KdSecondaryVersion = kKdSecondaryVersionAmd64Context;
        dump.Attributes.Attributes = info.DumpAttributes;
        if (!info.ContextRecord.empty())
        {
            const size_t copied = (std::min)(info.ContextRecord.size(), sizeof(dump.ContextRecord));
            std::memcpy(dump.ContextRecord, info.ContextRecord.data(), copied);
            if (info.ContextRecord.size() >= offsetof(CONTEXT, Rip) + sizeof(uint64_t))
            {
                uint64_t rip = 0;
                std::memcpy(&rip, info.ContextRecord.data() + offsetof(CONTEXT, Rip), sizeof(rip));
                if (rip != 0)
                {
                    dump.Exception.ExceptionCode = 0x80000003ul; // STATUS_BREAKPOINT
                    dump.Exception.ExceptionAddress = rip;
                }
            }
        }

        header->resize(sizeof(dump));
        std::memcpy(header->data(), &dump, sizeof(dump));
        ok = true;
    } while (false);

    return ok;
}

bool DumpPhysicalMemoryToCrashDump(
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& path,
    uint64_t maxPayloadBytes,
    bool abortOnReadFailure,
    DumpKernelCrashResult* result,
    std::wstring* error,
    const std::vector<PhysicalMemoryRange>* rangesOverride,
    uint64_t directoryTableBaseOverride,
    const char* commentOverride,
    const ProcessDumpWinDbgFixup* processFixup)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"DumpPhysicalMemoryToCrashDump called without result buffer";
            }
            break;
        }

        *result = DumpKernelCrashResult{};

        if (path.empty())
        {
            if (error != nullptr)
            {
                *error = L"dump-kernel requires an output path";
            }
            break;
        }

        std::vector<PhysicalMemoryRange> ranges;
        uint64_t reportedTotal = 0;
        std::wstring rangeError;
        if (rangesOverride != nullptr)
        {
            ranges = *rangesOverride;
        }
        else if (!device.GetPhysicalMemoryRanges(&ranges, &reportedTotal, &rangeError))
        {
            if (error != nullptr)
            {
                *error = rangeError;
            }
            break;
        }

        uint64_t payloadBytes = 0;
        if (!NormalizePhysicalRanges(&ranges, maxPayloadBytes, &payloadBytes, &rangeError))
        {
            if (error != nullptr)
            {
                *error = rangeError;
            }
            break;
        }

        result->RangeCount = static_cast<uint32_t>(ranges.size());
        result->PayloadBytes = payloadBytes;

        DumpKernelHeaderInfo info = {};
        info.NumberProcessors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (info.NumberProcessors == 0)
        {
            info.NumberProcessors = 1;
        }
        if (processFixup != nullptr)
        {
            // One processor context is enough for a process-filtered dump and
            // stops WinDbg walking KiProcessorBlock[1..] that we did not pin.
            info.NumberProcessors = 1;
            info.DumpAttributes = kDumpAttrProcessFilter;
            info.BugCheckParameter1 = processFixup->ProcessId;
            info.BugCheckParameter2 = processFixup->Eprocess;
        }
        info.MajorVersion = 15;
        info.ProductType = VER_NT_WORKSTATION;

        OSVERSIONINFOEXW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        using RtlGetVersionFn = LONG (WINAPI*)(OSVERSIONINFOW*);
        RtlGetVersionFn rtlGetVersion = ntdll == nullptr
            ? nullptr
            : reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
        if (rtlGetVersion != nullptr &&
            rtlGetVersion(reinterpret_cast<OSVERSIONINFOW*>(&version)) >= 0)
        {
            if (version.dwMajorVersion < 10)
            {
                info.MajorVersion = version.dwMajorVersion;
            }
            info.MinorVersion = version.dwBuildNumber;
            if (version.wProductType != 0)
            {
                info.ProductType = version.wProductType;
            }
            info.SuiteMask = version.wSuiteMask;
        }

        ControlRegisters registers = {};
        std::wstring crError;
        if (device.ReadControlRegisters(0, &registers, &crError))
        {
            info.DirectoryTableBase = directoryTableBaseOverride != 0
                ? directoryTableBaseOverride
                : registers.Cr3;
        }
        else
        {
            result->Warnings.push_back(L"CR3 read failed: " + crError);
            if (directoryTableBaseOverride != 0)
            {
                info.DirectoryTableBase = directoryTableBaseOverride;
            }
        }

        uint64_t pfnDatabase = 0;
        uint64_t loadedModules = 0;
        uint64_t activeProcesses = 0;
        info.KdDebuggerDataBlock =
            ResolveKdDebuggerDataBlock(device, symbols, &result->Warnings);
        ResolveOptionalSymbol(symbols, L"nt!MmPfnDatabase", &pfnDatabase, &result->Warnings);
        ResolveOptionalSymbol(symbols, L"nt!PsLoadedModuleList", &loadedModules, &result->Warnings);
        ResolveOptionalSymbol(symbols, L"nt!PsActiveProcessHead", &activeProcesses, &result->Warnings);
        if (loadedModules != 0)
        {
            info.PsLoadedModuleList = loadedModules;
        }
        if (activeProcesses != 0)
        {
            info.PsActiveProcessHead = activeProcesses;
        }
        if (pfnDatabase != 0)
        {
            info.PfnDataBase = ResolveKernelPointerTarget(device, pfnDatabase);
            if (info.PfnDataBase == 0)
            {
                result->Warnings.push_back(
                    L"nt!MmPfnDatabase did not dereference to a kernel pointer");
            }
        }

        if (commentOverride != nullptr && commentOverride[0] != 0)
        {
            info.Comment = commentOverride;
        }

        result->DirectoryTableBase = info.DirectoryTableBase;
        result->KdDebuggerDataBlock = info.KdDebuggerDataBlock;
        PreparedKdbg preparedKdbg = PreparePlainKdbg(
            device,
            symbols,
            info.KdDebuggerDataBlock,
            &result->Warnings);
        result->KdbgWasEncoded = preparedKdbg.WasEncoded;
        result->KdbgPlain = preparedKdbg.Ready && !preparedKdbg.WasEncoded;

        CaptureLiveProcessorContext(
            device,
            symbols,
            registers,
            &info.ContextRecord,
            &result->Warnings,
            info.DirectoryTableBase);

        if (info.ContextRecord.size() >= offsetof(CONTEXT, Rip) + sizeof(uint64_t))
        {
            std::memcpy(
                &result->ContextRip,
                info.ContextRecord.data() + offsetof(CONTEXT, Rip),
                sizeof(result->ContextRip));
            std::memcpy(
                &result->ContextRsp,
                info.ContextRecord.data() + offsetof(CONTEXT, Rsp),
                sizeof(result->ContextRsp));
            std::memcpy(
                &result->ContextFlags,
                info.ContextRecord.data() + offsetof(CONTEXT, ContextFlags),
                sizeof(result->ContextFlags));
        }

        if (result->ContextRip == 0 && IsKernelCanonicalVa(info.KdDebuggerDataBlock))
        {
            result->ContextRip = info.KdDebuggerDataBlock;
            if (info.ContextRecord.size() >= offsetof(CONTEXT, Rip) + sizeof(uint64_t))
            {
                std::memcpy(
                    info.ContextRecord.data() + offsetof(CONTEXT, Rip),
                    &result->ContextRip,
                    sizeof(result->ContextRip));
            }
        }

        ProcessDumpWinDbgFixup localFixup;
        const ProcessDumpWinDbgFixup* activeFixup = processFixup;
        if (processFixup != nullptr)
        {
            localFixup = *processFixup;
            if (preparedKdbg.Ready)
            {
                FillKdbgPrcbOffsets(preparedKdbg.PlainBlock, symbols, &localFixup);
            }
            if (localFixup.HasKernelTrap && localFixup.HeaderRip != 0)
            {
                result->ContextRip = localFixup.HeaderRip;
                if (localFixup.HeaderRsp != 0)
                {
                    result->ContextRsp = localFixup.HeaderRsp;
                }

                if (info.ContextRecord.size() >= offsetof(CONTEXT, Rip) + sizeof(uint64_t))
                {
                    std::memcpy(
                        info.ContextRecord.data() + offsetof(CONTEXT, Rip),
                        &result->ContextRip,
                        sizeof(result->ContextRip));
                }
                if (info.ContextRecord.size() >= offsetof(CONTEXT, Rsp) + sizeof(uint64_t) &&
                    result->ContextRsp != 0)
                {
                    std::memcpy(
                        info.ContextRecord.data() + offsetof(CONTEXT, Rsp),
                        &result->ContextRsp,
                        sizeof(result->ContextRsp));
                }
            }
            else
            {
                localFixup.HeaderRip = result->ContextRip;
                localFixup.HeaderRsp = result->ContextRsp;
            }
            activeFixup = &localFixup;
        }

        std::vector<uint8_t> header;
        std::wstring headerError;
        if (!BuildCompleteDumpHeader(ranges, info, &header, &headerError))
        {
            if (error != nullptr)
            {
                *error = headerError;
            }
            break;
        }

        file = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"failed to create dump file (gle=" +
                    std::to_wstring(GetLastError()) + L")";
            }
            break;
        }

        std::wstring writeError;
        if (!WriteAll(file, header.data(), static_cast<DWORD>(header.size()), &writeError))
        {
            if (error != nullptr)
            {
                *error = writeError;
            }
            break;
        }

        result->HeaderBytes = header.size();
        result->BytesWritten = header.size();

        const wchar_t* progressTag =
            rangesOverride != nullptr ? L"[dump-live]" : L"[dump-kernel]";
        std::wcout << progressTag << L" writing complete dump payload="
                   << (payloadBytes / (1024ull * 1024ull)) << L" MB"
                   << L" runs=" << ranges.size()
                   << L" path=" << path << L"\n";

        bool aborted = false;
        uint64_t nextProgress = kProgressStepBytes;
        std::vector<uint8_t> zeroChunk(kReadChunkBytes, 0);
        for (const PhysicalMemoryRange& range : ranges)
        {
            uint64_t remaining = range.ByteCount;
            uint64_t offset = 0;
            while (remaining > 0)
            {
                const uint32_t chunk = remaining > kReadChunkBytes
                    ? kReadChunkBytes
                    : static_cast<uint32_t>(remaining);

                std::vector<uint8_t> bytes;
                std::wstring readError;
                const bool readOk = device.ReadPhysical(
                    range.BaseAddress + offset,
                    chunk,
                    &bytes,
                    &readError);
                uint32_t got = 0;
                if (readOk)
                {
                    got = static_cast<uint32_t>((std::min)(bytes.size(), static_cast<size_t>(chunk)));
                }

                if (!readOk || got < chunk)
                {
                    ++result->ChunksFailed;
                    result->BytesZeroFilled += (chunk - got);
                    if (got > 0)
                    {
                        result->BytesRead += got;
                        if (!WriteAll(file, bytes.data(), got, &writeError))
                        {
                            if (error != nullptr)
                            {
                                *error = writeError;
                            }
                            aborted = true;
                            break;
                        }
                        result->BytesWritten += got;
                    }

                    if (abortOnReadFailure)
                    {
                        std::wstringstream stream;
                        stream << L"physical read failed at 0x" << std::hex
                               << (range.BaseAddress + offset) << L": "
                               << (readOk ? L"short read" : readError);
                        if (error != nullptr)
                        {
                            *error = stream.str();
                        }
                        aborted = true;
                        break;
                    }

                    if (!WriteAll(file, zeroChunk.data(), chunk - got, &writeError))
                    {
                        if (error != nullptr)
                        {
                            *error = writeError;
                        }
                        aborted = true;
                        break;
                    }
                    result->BytesWritten += (chunk - got);
                }
                else
                {
                    ++result->ChunksRead;
                    result->BytesRead += got;
                    if (!WriteAll(file, bytes.data(), got, &writeError))
                    {
                        if (error != nullptr)
                        {
                            *error = writeError;
                        }
                        aborted = true;
                        break;
                    }
                    result->BytesWritten += got;
                }

                offset += chunk;
                remaining -= chunk;

                const uint64_t copiedPayload = result->BytesWritten - result->HeaderBytes;
                if (copiedPayload >= nextProgress)
                {
                    const uint64_t copiedMb = copiedPayload / (1024ull * 1024ull);
                    const uint64_t totalMb = payloadBytes / (1024ull * 1024ull);
                    std::wcout << progressTag << L" copied=" << copiedMb << L" / " << totalMb
                               << L" MB failed_chunks=" << result->ChunksFailed << L"\n";
                    nextProgress += kProgressStepBytes;
                }
            }

            if (aborted)
            {
                break;
            }
        }

        if (aborted)
        {
            result->Complete = false;
            break;
        }

        result->Complete = result->ChunksFailed == 0 &&
            (result->BytesWritten == result->HeaderBytes + result->PayloadBytes);
        if (result->ChunksFailed > 0)
        {
            result->Warnings.push_back(
                L"zero-filled " + std::to_wstring(result->ChunksFailed) +
                L" incomplete physical chunk(s)");
        }

        if (preparedKdbg.Ready && preparedKdbg.WasEncoded)
        {
            std::wstring patchError;
            bool patched = PatchPlainKdbgIntoDump(
                file,
                device,
                info.DirectoryTableBase,
                ranges,
                preparedKdbg,
                &patchError);
            if (!patched && (info.DirectoryTableBase & (kPageSize - 1ull)) != 0)
            {
                patched = PatchPlainKdbgIntoDump(
                    file,
                    device,
                    info.DirectoryTableBase & ~(static_cast<uint64_t>(kPageSize) - 1ull),
                    ranges,
                    preparedKdbg,
                    &patchError);
            }
            if (!patched &&
                registers.Cr3 != 0 &&
                MaskDirectoryTableBase(registers.Cr3) !=
                    MaskDirectoryTableBase(info.DirectoryTableBase))
            {
                patched = PatchPlainKdbgIntoDump(
                    file,
                    device,
                    MaskDirectoryTableBase(registers.Cr3),
                    ranges,
                    preparedKdbg,
                    &patchError);
            }

            if (patched)
            {
                result->KdbgPlain = true;
            }
            else
            {
                result->Warnings.push_back(L"KDBG dump patch failed: " + patchError);
            }
        }

        if (activeFixup != nullptr)
        {
            ApplyProcessDumpWinDbgFixups(
                file,
                device,
                symbols,
                ranges,
                *activeFixup,
                result);
        }

        ok = true;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

bool DumpProcessVisibleMemoryToCrashDump(
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& path,
    uint32_t processId,
    uint64_t eprocess,
    uint64_t directoryTableBase,
    uint64_t userDirectoryTableBase,
    uint64_t peb,
    bool abortOnReadFailure,
    DumpKernelCrashResult* result,
    std::wstring* error)
{
    bool ok = false;
    HANDLE processHandle = nullptr;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"DumpProcessVisibleMemoryToCrashDump called without result buffer";
            }
            break;
        }

        ControlRegisters registers = {};
        std::wstring crError;
        bool la57 = false;
        bool havePagingMode = false;
        if (device.ReadControlRegisters(0, &registers, &crError))
        {
            la57 = (registers.Cr4 & (1ull << 12)) != 0;
            havePagingMode = true;
        }
        else
        {
            PhysicalTranslationInfo translation = {};
            const uint64_t probeDtb =
                directoryTableBase != 0 ? directoryTableBase : userDirectoryTableBase;
            if (device.TranslateVirtual(
                    probeDtb,
                    0xfffff80000000000ull,
                    8,
                    &translation,
                    nullptr))
            {
                la57 = (translation.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0;
                havePagingMode = true;
            }
        }

        if (!havePagingMode)
        {
            if (error != nullptr)
            {
                *error = L"cannot determine LA57/paging mode: " + crError;
            }
            break;
        }

        const ProcessDumpWalkPlan plan = MakeProcessDumpWalkPlan(
            directoryTableBase,
            userDirectoryTableBase,
            registers.Cr3);
        if (plan.PrimaryDtb == 0)
        {
            if (error != nullptr)
            {
                *error = L"process directory table base is zero";
            }
            break;
        }

        std::vector<std::wstring> walkWarnings;
        std::vector<PhysicalMemoryRange> ranges;
        uint32_t skippedTables = 0;
        std::wstring walkError;
        const bool walked = CollectResidentPhysicalRunsFromDtb(
            device,
            plan.PrimaryDtb,
            la57,
            plan.PrimaryHalf,
            &ranges,
            nullptr,
            &skippedTables,
            &walkError);
        if (!walked)
        {
            if (error != nullptr)
            {
                *error = walkError.empty()
                    ? L"process DTB walk failed"
                    : walkError;
            }
            break;
        }

        if (plan.SecondaryDtb != 0)
        {
            std::vector<PhysicalMemoryRange> kernelRanges;
            uint32_t kernelSkipped = 0;
            std::wstring kernelError;
            if (CollectResidentPhysicalRunsFromDtb(
                    device,
                    plan.SecondaryDtb,
                    la57,
                    plan.SecondaryHalf,
                    &kernelRanges,
                    nullptr,
                    &kernelSkipped,
                    &kernelError))
            {
                ranges.insert(ranges.end(), kernelRanges.begin(), kernelRanges.end());
                skippedTables += kernelSkipped;
            }
            else
            {
                walkWarnings.push_back(
                    L"kernel-half walk failed; dump may lack nt/KDBG: " + kernelError);
            }
        }
        else if (MaskDirectoryTableBase(directoryTableBase) == 0 &&
                 MaskDirectoryTableBase(userDirectoryTableBase) != 0)
        {
            walkWarnings.push_back(
                L"only user DTB was available; dump may lack kernel pages");
        }

        std::vector<PhysicalMemoryRange> ramRanges;
        uint64_t ramTotal = 0;
        std::wstring ramError;
        if (device.GetPhysicalMemoryRanges(&ramRanges, &ramTotal, &ramError) &&
            !ramRanges.empty())
        {
            IntersectPhysicalRunsWithAllowed(&ranges, ramRanges);
        }
        else
        {
            walkWarnings.push_back(
                L"could not clip process PFNs to RAM map: " + ramError);
        }

        ProcessDumpWinDbgFixup fixup = {};
        fixup.ProcessId = processId;
        fixup.Eprocess = eprocess;
        fixup.KernelDirectoryTableBase = plan.HeaderDtb;
        fixup.UserDirectoryTableBase = userDirectoryTableBase;
        fixup.Peb = peb;
        ReadFieldU64(
            device,
            symbols,
            eprocess,
            L"nt!_EPROCESS",
            L"CreateTime",
            nullptr,
            &fixup.CreateTime);
        uint64_t trapRip = 0;
        uint64_t trapRsp = 0;
        fixup.HasKernelTrap = FindProcessThreadKernelTrap(
            device,
            symbols,
            eprocess,
            &fixup.Thread,
            &trapRip,
            &trapRsp);
        if (fixup.HasKernelTrap)
        {
            fixup.HeaderRip = trapRip;
            fixup.HeaderRsp = trapRsp;
        }
        else if (fixup.Thread == 0)
        {
            fixup.Thread = FindFirstProcessThread(device, symbols, eprocess, &walkWarnings);
        }

        {
            const uint64_t earlyKdbg = ResolveKdDebuggerDataBlock(device, symbols, &walkWarnings);
            PreparedKdbg preparedOffsets = PreparePlainKdbg(device, symbols, earlyKdbg, &walkWarnings);
            if (preparedOffsets.Ready)
            {
                FillKdbgPrcbOffsets(preparedOffsets.PlainBlock, symbols, &fixup);
            }
        }

        uint64_t wow64Process = 0;
        if (ReadFieldU64(
                device,
                symbols,
                eprocess,
                L"nt!_EPROCESS",
                L"Wow64Process",
                nullptr,
                &wow64Process) &&
            wow64Process != 0)
        {
            fixup.Wow64 = true;
        }

        AddPhysicalPageToRuns(plan.HeaderDtb, &ranges);
        AddPhysicalPageToRuns(plan.PrimaryDtb, &ranges);
        AddPhysicalPageToRuns(plan.SecondaryDtb, &ranges);
        AddPhysicalPageToRuns(userDirectoryTableBase, &ranges);

        const uint64_t pinDtb = plan.HeaderDtb != 0 ? plan.HeaderDtb : plan.PrimaryDtb;
        const uint64_t userPinDtb =
            MaskDirectoryTableBase(userDirectoryTableBase) != 0
                ? userDirectoryTableBase
                : pinDtb;
        const uint64_t kdbg = ResolveKdDebuggerDataBlock(device, symbols, &walkWarnings);
        AddTranslatedVirtualPage(device, pinDtb, kdbg, &ranges, &walkWarnings, L"KDBG");
        AddTranslatedVirtualPage(device, pinDtb, eprocess, &ranges, &walkWarnings, L"EPROCESS");
        if (eprocess != 0)
        {
            AddTranslatedVirtualPage(device, pinDtb, eprocess + kPageSize, &ranges, nullptr, nullptr);
        }
        EnableSeDebugPrivilege(nullptr);
        processHandle = OpenTargetProcessReadHandle(processId);
        if (processHandle == nullptr && processId != 0)
        {
            walkWarnings.push_back(
                L"OpenProcess(VM_READ) failed; PEB.Ldr file-backed pages may stay unpaged (gle=" +
                std::to_wstring(GetLastError()) + L")");
        }

        AddTranslatedVirtualPage(device, pinDtb, fixup.Thread, &ranges, &walkWarnings, L"ETHREAD");
        if (fixup.Thread != 0)
        {
            AddTranslatedVirtualPage(device, pinDtb, fixup.Thread + kPageSize, &ranges, nullptr, nullptr);
            const uint64_t threadStack = ReadCanonicalFieldU64(
                device,
                symbols,
                fixup.Thread,
                L"nt!_KTHREAD",
                L"KernelStack");
            if (threadStack != 0)
            {
                AddTranslatedVirtualPage(device, pinDtb, threadStack, &ranges, nullptr, nullptr);
                AddTranslatedVirtualPage(
                    device,
                    pinDtb,
                    threadStack - 0x200,
                    &ranges,
                    &walkWarnings,
                    L"target thread stack");
                AddTranslatedVirtualPage(
                    device,
                    pinDtb,
                    threadStack - kPageSize,
                    &ranges,
                    nullptr,
                    nullptr);
            }

            uint64_t trapFrame = 0;
            if (ReadFieldU64(
                    device,
                    symbols,
                    fixup.Thread,
                    L"nt!_KTHREAD",
                    L"TrapFrame",
                    nullptr,
                    &trapFrame) &&
                IsKernelCanonicalVa(trapFrame))
            {
                AddTranslatedVirtualPage(
                    device,
                    pinDtb,
                    trapFrame,
                    &ranges,
                    &walkWarnings,
                    L"KTRAP_FRAME");
                AddTranslatedVirtualPage(
                    device,
                    pinDtb,
                    trapFrame + 0x180,
                    &ranges,
                    nullptr,
                    nullptr);
            }
        }
        AddTranslatedVirtualPage(device, userPinDtb, peb, &ranges, &walkWarnings, L"PEB");
        if (peb != 0)
        {
            AddTranslatedVirtualPage(device, userPinDtb, peb + kPageSize, &ranges, nullptr, nullptr);
            PinProcessLdrNamePages(
                device,
                symbols,
                processHandle,
                processId,
                eprocess,
                fixup.CreateTime,
                userPinDtb,
                pinDtb,
                peb,
                &ranges,
                &walkWarnings);
        }

        uint64_t kpcr = 0;
        if (ResolveLiveKpcr(device, &kpcr, nullptr, &walkWarnings) && kpcr != 0)
        {
            AddTranslatedVirtualPageAnyCr3(device, pinDtb, kpcr, &ranges, &walkWarnings, L"KPCR");
            AddTranslatedVirtualPageAnyCr3(device, pinDtb, kpcr + 0x180, &ranges, nullptr, nullptr);
            const uint64_t prcb = ResolveKpcrPrcb(device, symbols, kpcr);
            AddTranslatedVirtualPageAnyCr3(device, pinDtb, prcb, &ranges, &walkWarnings, L"KPRCB");

            uint64_t contextVa = 0;
            uint64_t specialVa = 0;
            ResolvePrcbProcessorStateAddresses(
                symbols,
                prcb,
                fixup.PrcbProcStateContextOffset,
                &contextVa,
                &specialVa);
            uint64_t prcbPinEnd = prcb + kPageSize;
            TypeLayoutInfo prcbLayout = {};
            if (symbols.GetTypeLayout(L"nt!_KPRCB", &prcbLayout, nullptr) &&
                prcbLayout.Size >= 0x400 &&
                prcbLayout.Size <= 0x40000)
            {
                prcbPinEnd = prcb + prcbLayout.Size;
            }
            if (contextVa >= prcb &&
                contextVa + kDumpAmd64ContextBytes > prcbPinEnd &&
                (contextVa - prcb) <= 0x40000)
            {
                prcbPinEnd = contextVa + kDumpAmd64ContextBytes;
            }
            if (specialVa >= prcb &&
                specialVa + 0xF0 > prcbPinEnd &&
                (specialVa - prcb) <= 0x40000)
            {
                prcbPinEnd = specialVa + 0xF0;
            }

            for (uint64_t prcbOff = 0; prcb + prcbOff < prcbPinEnd; prcbOff += kPageSize)
            {
                AddTranslatedVirtualPageAnyCr3(
                    device,
                    pinDtb,
                    prcb + prcbOff,
                    &ranges,
                    nullptr,
                    nullptr);
            }

            if (contextVa != 0)
            {
                AddTranslatedVirtualPageAnyCr3(
                    device,
                    pinDtb,
                    contextVa,
                    &ranges,
                    &walkWarnings,
                    L"ProcessorState.ContextFrame");
                AddTranslatedVirtualPageAnyCr3(
                    device,
                    pinDtb,
                    contextVa + (kDumpAmd64ContextBytes - 1),
                    &ranges,
                    nullptr,
                    nullptr);
                if (specialVa != 0)
                {
                    AddTranslatedVirtualPageAnyCr3(
                        device,
                        pinDtb,
                        specialVa,
                        &ranges,
                        nullptr,
                        nullptr);
                }
            }

            if (fixup.SavedContext != 0)
            {
                AddTranslatedVirtualPageAnyCr3(
                    device,
                    pinDtb,
                    fixup.SavedContext,
                    &ranges,
                    &walkWarnings,
                    L"KDBG.SavedContext");
                AddTranslatedVirtualPageAnyCr3(
                    device,
                    pinDtb,
                    fixup.SavedContext + (kDumpAmd64ContextBytes - 1),
                    &ranges,
                    nullptr,
                    nullptr);
            }

            if (fixup.PrcbContextOffset >= 8 && fixup.PrcbContextOffset <= 0x40000)
            {
                uint64_t pointedContext = 0;
                if (ReadKernelU64(device, prcb + fixup.PrcbContextOffset, &pointedContext) &&
                    IsKernelCanonicalVa(pointedContext))
                {
                    AddTranslatedVirtualPageAnyCr3(
                        device,
                        pinDtb,
                        pointedContext,
                        &ranges,
                        &walkWarnings,
                        L"KPRCB.Context");
                    AddTranslatedVirtualPageAnyCr3(
                        device,
                        pinDtb,
                        pointedContext + (kDumpAmd64ContextBytes - 1),
                        &ranges,
                        nullptr,
                        nullptr);
                }
            }

            const uint64_t idleThread = ResolvePrcbIdleThread(device, symbols, prcb);
            AddTranslatedVirtualPage(device, pinDtb, idleThread, &ranges, &walkWarnings, L"IdleThread");
            if (idleThread != 0)
            {
                AddTranslatedVirtualPage(device, pinDtb, idleThread + kPageSize, &ranges, nullptr, nullptr);
                const uint64_t idleStack = ReadCanonicalFieldU64(
                    device,
                    symbols,
                    idleThread,
                    L"nt!_KTHREAD",
                    L"KernelStack");
                if (idleStack != 0)
                {
                    AddTranslatedVirtualPage(
                        device,
                        pinDtb,
                        idleStack,
                        &ranges,
                        nullptr,
                        nullptr);
                    AddTranslatedVirtualPage(
                        device,
                        pinDtb,
                        idleStack - 0x200,
                        &ranges,
                        &walkWarnings,
                        L"IdleThread stack");
                    AddTranslatedVirtualPage(
                        device,
                        pinDtb,
                        idleStack - kPageSize,
                        &ranges,
                        nullptr,
                        nullptr);
                }
            }
        }

        uint64_t loadedModules = 0;
        if (ResolveOptionalSymbol(symbols, L"nt!PsLoadedModuleList", &loadedModules, &walkWarnings))
        {
            AddTranslatedVirtualPage(
                device,
                pinDtb,
                loadedModules,
                &ranges,
                &walkWarnings,
                L"PsLoadedModuleList");
        }

        const KernelModuleInfo* nt = FindNtModule(symbols);
        if (nt != nullptr)
        {
            AddTranslatedVirtualPage(
                device,
                pinDtb,
                nt->Base,
                &ranges,
                &walkWarnings,
                L"ntoskrnl image header");
        }

        if (!ramRanges.empty())
        {
            IntersectPhysicalRunsWithAllowed(&ranges, ramRanges);
        }

        if (ranges.empty())
        {
            if (error != nullptr)
            {
                *error = L"process DTB walk found no RAM-resident pages";
            }
            break;
        }

        const uint64_t exactBytes = SumPhysicalRunBytes(ranges);
        CoalescePhysicalRunsToMax(&ranges, kCrashDumpMaxPhysicalRuns);
        const uint64_t coalescedBytes = SumPhysicalRunBytes(ranges);
        const uint64_t extraBytes =
            coalescedBytes > exactBytes ? coalescedBytes - exactBytes : 0;
        const uint64_t pageCount = CountPhysicalRunPages(ranges);

        const uint64_t headerDtb = plan.HeaderDtb;
        std::wcout << L"[dump-live] process filter pid=" << processId
                   << L" eprocess=0x" << std::hex << eprocess
                   << L" dtb=0x" << headerDtb
                   << L" user_dtb=0x" << MaskDirectoryTableBase(userDirectoryTableBase)
                   << L" thread=0x" << fixup.Thread
                   << std::dec
                   << L" kernel_trap=" << (fixup.HasKernelTrap ? L"yes" : L"no")
                   << L" runs=" << ranges.size()
                   << L" pages=" << pageCount << L"\n";

        char comment[128] = {};
        _snprintf_s(
            comment,
            sizeof(comment),
            _TRUNCATE,
            "KnLiveDbg live dump pid=%u eprocess=0x%llx",
            processId,
            static_cast<unsigned long long>(eprocess));

        if (!DumpPhysicalMemoryToCrashDump(
                device,
                symbols,
                path,
                0,
                abortOnReadFailure,
                result,
                error,
                &ranges,
                headerDtb,
                comment,
                &fixup))
        {
            result->Warnings.insert(
                result->Warnings.end(),
                walkWarnings.begin(),
                walkWarnings.end());
            break;
        }

        result->Warnings.insert(
            result->Warnings.end(),
            walkWarnings.begin(),
            walkWarnings.end());
        if (skippedTables > 0)
        {
            result->Warnings.push_back(
                L"skipped " + std::to_wstring(skippedTables) +
                L" unreadable page-table page(s)");
        }
        if (extraBytes > 0)
        {
            std::wstringstream extraStream;
            extraStream << L"coalesced physical runs to 42 by including 0x" << std::hex
                        << extraBytes << L" extra RAM bytes from gaps";
            result->Warnings.push_back(extraStream.str());
        }

        ok = true;
    } while (false);

    if (processHandle != nullptr)
    {
        CloseHandle(processHandle);
    }

    return ok;
}

bool DumpOsLiveKernel(
    const std::wstring& path,
    bool includeUserPages,
    bool compress,
    bool includeHypervisorPages,
    DumpOsLiveResult* result,
    std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"DumpOsLiveKernel called without result buffer";
            }
            break;
        }

        *result = DumpOsLiveResult{};
        result->IncludedUserPages = includeUserPages;
        result->Compressed = compress;
        result->IncludedHypervisorPages = includeHypervisorPages;

        if (path.empty())
        {
            if (error != nullptr)
            {
                *error = L"dump-live requires an output path";
            }
            break;
        }

        std::wstring privilegeWarning;
        if (!EnableSeDebugPrivilege(&privilegeWarning))
        {
            if (error != nullptr)
            {
                *error = L"dump-live needs SeDebugPrivilege: " + privilegeWarning;
            }
            break;
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"ntdll.dll is not loaded";
            }
            break;
        }

        auto ntSystemDebugControl = reinterpret_cast<NtSystemDebugControlFn>(
            GetProcAddress(ntdll, "NtSystemDebugControl"));
        if (ntSystemDebugControl == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"NtSystemDebugControl is not exported";
            }
            break;
        }

        // Task Manager / crashdmp write through the dump storage stack.
        // That path requires a no-buffering, write-through handle. A cached
        // FILE_ATTRIBUTE_NORMAL handle can return STATUS_INVALID_PARAMETER or
        // leave a torn file that WinDbg rejects. Exclusive share stops a
        // reader from observing a half-written image.
        bool useDumpStorageStack = true;
        file = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            useDumpStorageStack = false;
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"failed to create live-dump file (gle=" +
                        std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            result->Warnings.push_back(
                L"opened without FILE_FLAG_NO_BUFFERING; dump storage stack disabled");
        }

        LiveDumpAttemptResult attempt = InvokeOsLiveDump(
            ntSystemDebugControl,
            file,
            useDumpStorageStack,
            includeUserPages,
            compress,
            includeHypervisorPages);

        // Dump-stack + no-buffering is the Task Manager path, but it is not
        // available on every volume. The old buffered handle still works
        // there; retry only when the first attempt wrote nothing.
        if (attempt.Status < 0 &&
            useDumpStorageStack &&
            LiveDumpFileIsEmpty(file) &&
            IsLiveDumpIoFallbackStatus(attempt.Status))
        {
            CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
            file = CreateFileW(
                path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                if (error != nullptr)
                {
                    *error = L"failed to reopen live-dump file without dump stack (gle=" +
                        std::to_wstring(GetLastError()) + L")";
                }
                break;
            }

            result->Warnings.push_back(
                L"dump storage stack rejected; retried without FILE_FLAG_NO_BUFFERING");
            attempt = InvokeOsLiveDump(
                ntSystemDebugControl,
                file,
                false,
                includeUserPages,
                compress,
                includeHypervisorPages);
        }

        result->Status = attempt.Status;
        result->ApiVersionUsed = attempt.VersionUsed;
        const long status = attempt.Status;

        FlushFileBuffers(file);
        LARGE_INTEGER fileSize = {};
        if (GetFileSizeEx(file, &fileSize) && fileSize.QuadPart > 0)
        {
            result->BytesWritten = static_cast<uint64_t>(fileSize.QuadPart);
        }

        if (status < 0)
        {
            std::wstringstream stream;
            stream << L"NtSystemDebugControl(SysDbgGetLiveKernelDump) failed ntstatus=0x"
                   << std::hex << std::uppercase
                   << static_cast<unsigned long>(status);
            const wchar_t* name = NtStatusName(status);
            if (name[0] != L'\0')
            {
                stream << L" (" << name << L")";
            }
            if (static_cast<unsigned long>(status) == 0xC0000354ul && includeUserPages)
            {
                stream << L". /user on this build needs a configured kernel debugger "
                       << L"(or Win11 22H2+ LivedumpProcessFiltering).";
            }
            else
            {
                stream << L". This OS path needs elevation, SeDebugPrivilege, and a Windows "
                       << L"build that allows live kernel dumps.";
            }
            if (error != nullptr)
            {
                *error = stream.str();
            }
            if (result->BytesWritten == 0)
            {
                CloseHandle(file);
                file = INVALID_HANDLE_VALUE;
                DeleteFileW(path.c_str());
            }
            break;
        }

        if (result->BytesWritten == 0)
        {
            if (error != nullptr)
            {
                *error = L"NtSystemDebugControl succeeded but the dump file is empty";
            }
            CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
            DeleteFileW(path.c_str());
            break;
        }

        ok = true;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

bool DumpOsLiveControlSelfTest()
{
    bool ok = false;

    do
    {
        unsigned long raw = 0;
        LiveDumpFlags flags = {};
        flags.UseDumpStorageStack = 1;
        std::memcpy(&raw, &flags, sizeof(raw));
        if (raw != 1ul)
        {
            break;
        }

        flags = {};
        flags.CompressMemoryPagesData = 1;
        std::memcpy(&raw, &flags, sizeof(raw));
        if (raw != 2ul)
        {
            break;
        }

        flags = {};
        flags.IncludeUserSpaceMemoryPages = 1;
        std::memcpy(&raw, &flags, sizeof(raw));
        if (raw != 4ul)
        {
            break;
        }

        flags = {};
        flags.UseDumpStorageStack = 1;
        flags.CompressMemoryPagesData = 1;
        flags.IncludeUserSpaceMemoryPages = 1;
        std::memcpy(&raw, &flags, sizeof(raw));
        if (raw != 7ul)
        {
            break;
        }

        LiveDumpAddPages pages = {};
        pages.HypervisorPages = 1;
        std::memcpy(&raw, &pages, sizeof(raw));
        if (raw != 1ul)
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DecodeKdbgSelfTest()
{
    bool ok = false;

    do
    {
        std::vector<uint8_t> plain(64, 0);
        const uint32_t tag = kKdbgOwnerTag;
        const uint32_t size = 0x380;
        const uint64_t kernBase = 0xfffff804afa00000ull;
        std::memcpy(plain.data() + kKdbgHeaderTagOffset, &tag, sizeof(tag));
        std::memcpy(plain.data() + kKdbgHeaderSizeOffset, &size, sizeof(size));
        std::memcpy(plain.data() + kKdbgKernBaseOffset, &kernBase, sizeof(kernBase));

        const uint64_t waitNever = 0x0123456789abcdefull;
        const uint64_t waitAlways = 0xfedcba9876543210ull;
        const uint64_t encodedFlag = 0xfffff80012340000ull;
        const uint64_t swapXor = encodedFlag | 0xffff000000000000ull;

        std::vector<uint8_t> encoded = plain;
        TransformKdbgBlock(&encoded, waitNever, waitAlways, swapXor, false);
        if (KdbgTagIsPlain(encoded))
        {
            break;
        }

        if (!DecodeEncodedKdbg(&encoded, waitNever, waitAlways, encodedFlag, 0xfffff804b0801070ull) ||
            encoded != plain)
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DumpLiveProcessFilterSelfTest()
{
    bool ok = false;

    do
    {
        std::vector<PhysicalMemoryRange> adjacent(3);
        adjacent[0].BaseAddress = 0x1000;
        adjacent[0].ByteCount = 0x1000;
        adjacent[1].BaseAddress = 0x2000;
        adjacent[1].ByteCount = 0x1000;
        adjacent[2].BaseAddress = 0x3000;
        adjacent[2].ByteCount = 0x1000;
        CoalescePhysicalRunsToMax(&adjacent, 42);
        if (adjacent.size() != 1 ||
            adjacent[0].BaseAddress != 0x1000 ||
            adjacent[0].ByteCount != 0x3000)
        {
            break;
        }

        std::vector<PhysicalMemoryRange> sparse(3);
        sparse[0].BaseAddress = 0x1000;
        sparse[0].ByteCount = 0x1000;
        sparse[1].BaseAddress = 0x100000;
        sparse[1].ByteCount = 0x1000;
        sparse[2].BaseAddress = 0x200000;
        sparse[2].ByteCount = 0x1000;
        CoalescePhysicalRunsToMax(&sparse, 2);
        if (sparse.size() != 2)
        {
            break;
        }

        std::vector<PhysicalMemoryRange> keep = sparse;
        CoalescePhysicalRunsToMax(&keep, 0);
        if (keep.size() != sparse.size())
        {
            break;
        }

        CoalescePhysicalRunsToMax(&keep, 1);
        if (keep.size() != 1)
        {
            break;
        }

        const ProcessDumpWalkPlan kpti = MakeProcessDumpWalkPlan(0x1aa000, 0x2bb000, 0x1aa000);
        if (kpti.PrimaryDtb != 0x2bb000 ||
            kpti.PrimaryHalf != PageTableHalf::User ||
            kpti.SecondaryDtb != 0x1aa000 ||
            kpti.SecondaryHalf != PageTableHalf::Kernel ||
            kpti.HeaderDtb != 0x1aa000)
        {
            break;
        }

        const ProcessDumpWalkPlan same = MakeProcessDumpWalkPlan(0x1aa001, 0x1aa002, 0x1aa000);
        if (same.PrimaryDtb != 0x1aa000 ||
            same.PrimaryHalf != PageTableHalf::Both ||
            same.SecondaryDtb != 0 ||
            same.HeaderDtb != 0x1aa000)
        {
            break;
        }

        const ProcessDumpWalkPlan userOnly = MakeProcessDumpWalkPlan(0, 0x2bb000, 0x1aa000);
        if (userOnly.PrimaryDtb != 0x2bb000 ||
            userOnly.PrimaryHalf != PageTableHalf::Both ||
            userOnly.SecondaryDtb != 0x1aa000 ||
            userOnly.HeaderDtb != 0x1aa000)
        {
            break;
        }

        std::vector<PhysicalMemoryRange> overlap(1);
        overlap[0].BaseAddress = 0x1000;
        overlap[0].ByteCount = 0x5000;
        std::vector<PhysicalMemoryRange> allowed(2);
        allowed[0].BaseAddress = 0;
        allowed[0].ByteCount = 0x3000;
        allowed[1].BaseAddress = 0x4000;
        allowed[1].ByteCount = 0x1000;
        IntersectPhysicalRunsWithAllowed(&overlap, allowed);
        if (overlap.size() != 2 ||
            overlap[0].BaseAddress != 0x1000 ||
            overlap[0].ByteCount != 0x2000 ||
            overlap[1].BaseAddress != 0x4000 ||
            overlap[1].ByteCount != 0x1000)
        {
            break;
        }

        std::vector<uint8_t> kernelRoot(0x1000, 0);
        std::vector<uint8_t> userRoot(0x1000, 0);
        for (uint32_t index = 0; index < 512; ++index)
        {
            const uint64_t userValue = 0x1000ull + index;
            const uint64_t kernelValue = 0x2000ull + index;
            std::memcpy(userRoot.data() + (index * 8), &userValue, sizeof(userValue));
            std::memcpy(kernelRoot.data() + (index * 8), &kernelValue, sizeof(kernelValue));
        }

        MergeKptiDirectoryRoot(&kernelRoot, userRoot);
        bool mergeOk = true;
        for (uint32_t index = 0; index < 512; ++index)
        {
            uint64_t value = 0;
            std::memcpy(&value, kernelRoot.data() + (index * 8), sizeof(value));
            const uint64_t expected = index < 256
                ? (0x1000ull + index)
                : (0x2000ull + index);
            if (value != expected)
            {
                mergeOk = false;
                break;
            }
        }

        if (!mergeOk)
        {
            break;
        }

        std::vector<uint8_t> pokeBlock(0x180, 0);
        TypeFieldInfo pokeCs = {};
        pokeCs.Name = L"SegCs";
        pokeCs.Offset = 0x170;
        const uint16_t pokeValue = 0x10;
        if (!PokeDumpStructField(&pokeBlock, pokeCs, &pokeValue, sizeof(pokeValue)))
        {
            break;
        }

        uint16_t poked = 0;
        std::memcpy(&poked, pokeBlock.data() + 0x170, sizeof(poked));
        if (poked != 0x10)
        {
            break;
        }

        uint8_t unicodeBlob[16] = {};
        const uint16_t nameBytes = 24;
        const uint64_t nameBuffer = 0x00000080011be4e8ull;
        std::memcpy(unicodeBlob, &nameBytes, sizeof(nameBytes));
        std::memcpy(unicodeBlob + 8, &nameBuffer, sizeof(nameBuffer));
        uint64_t parsedBuffer = 0;
        uint32_t parsedLength = 0;
        if (!ParseUserUnicodeString64(unicodeBlob, sizeof(unicodeBlob), &parsedBuffer, &parsedLength) ||
            parsedBuffer != nameBuffer ||
            parsedLength != 24)
        {
            break;
        }

        uint8_t kernelBlob[16] = {};
        const uint64_t kernelBuffer = 0xfffff80012340000ull;
        std::memcpy(kernelBlob + 8, &kernelBuffer, sizeof(kernelBuffer));
        std::memcpy(kernelBlob, &nameBytes, sizeof(nameBytes));
        if (ParseUserUnicodeString64(kernelBlob, sizeof(kernelBlob), &parsedBuffer, &parsedLength))
        {
            break;
        }

        std::vector<PhysicalMemoryRange> pathRuns;
        PhysicalTranslationInfo pathInfo = {};
        pathInfo.PteAddress = 0xABC000 + 0x18;
        pathInfo.PhysicalAddress = 0xDEF000 + 0x80;
        AddTranslationPathToRuns(pathInfo, &pathRuns);
        if (pathRuns.size() < 2 ||
            pathRuns[0].BaseAddress != 0xABC000 ||
            pathRuns[1].BaseAddress != 0xDEF000)
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
