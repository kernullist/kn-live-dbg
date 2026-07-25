#include "MemoryDumper.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <fstream>
#include <iomanip>
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
