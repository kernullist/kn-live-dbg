#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct DumpRawResult
{
    uint64_t StartAddress = 0;
    uint64_t Length = 0;              // requested length
    uint64_t BytesRequested = 0;
    uint64_t BytesRead = 0;           // bytes successfully read from kernel
    uint64_t BytesZeroFilled = 0;     // bytes synthesized on failure (if allowed)
    uint64_t BytesWritten = 0;        // bytes written to the output file
    uint32_t ChunksRead = 0;
    uint32_t ChunksFailed = 0;
    bool     ZeroFilledOnFailure = false;
    bool     Complete = false;        // full request satisfied without abort
    bool     ShortRead = false;       // any short/failed kernel chunk
    std::vector<std::wstring> Warnings;
};

struct DumpedSectionRecord
{
    std::wstring Name;
    uint32_t VirtualAddress = 0;     // RVA
    uint32_t VirtualSize = 0;
    uint32_t SizeOfRawData = 0;
    uint32_t PointerToRawData = 0;   // file offset
    uint32_t Characteristics = 0;
    bool     ReadSucceeded = false;
    bool     ZeroFilled = false;
    uint32_t BytesActuallyRead = 0;
};

struct DumpPeResult
{
    uint64_t StartAddress = 0;
    uint32_t SizeOfHeaders = 0;
    uint64_t TotalFileSize = 0;
    uint16_t NumberOfSections = 0;
    uint16_t Machine = 0;
    uint64_t ImageBase = 0;
    uint64_t SizeOfImage = 0;
    bool     Is64Bit = false;
    // Header recovery state. dump-pe restores wiped MZ/PE/e_lfanew when the
    // remaining header fields are intact enough to locate the NT headers.
    bool     RestoredDosMagic = false;
    bool     RestoredPeSignature = false;
    bool     RestoredELfanew = false;
    uint32_t RecoveredNtOffset = 0;
    std::vector<DumpedSectionRecord> Sections;
    std::vector<std::wstring> Warnings;
};

struct PeHeaderProbe
{
    bool     IsPe = false;
    uint32_t NtOffset = 0;
    bool     MzWiped = false;            // bytes 0..1 are not 'MZ'
    bool     PeSignatureWiped = false;   // dword at NtOffset is not 'PE\0\0'
    bool     ELfanewMismatch = false;    // DOS.e_lfanew disagrees with NtOffset
    bool     Is64Bit = false;
    uint16_t Machine = 0;
    uint16_t NumberOfSections = 0;
    uint16_t Characteristics = 0;
    uint32_t SizeOfHeaders = 0;
    uint32_t AddressOfEntryPoint = 0;
    uint32_t TimeDateStamp = 0;
    uint64_t SizeOfImage = 0;
    uint64_t ImageBase = 0;
};

// Non-mutating PE header probe over an arbitrary byte buffer. Returns true if
// a plausible IMAGE_NT_HEADERS instance is located (intact or recovered from
// wiped MZ/PE signatures), with the metadata and anomaly flags populated in
// PeHeaderProbe. Used by pool-scan-pe to flag PE images stashed in pool
// memory, including malware-style header-stripped variants.
bool ProbeForPeHeader(const uint8_t* buffer, size_t length, PeHeaderProbe* result);

// Dumps [address, address+length) verbatim to <path>. On read failure the
// current chunk is zero-filled (if zeroFillOnFailure is true) and the dump
// continues; otherwise the function returns false.
bool DumpKernelRangeToFile(
    DeviceClient& device,
    uint64_t address,
    uint64_t length,
    const std::wstring& path,
    bool zeroFillOnFailure,
    DumpRawResult* result,
    std::wstring* error);

// Interprets the region at <address> as an in-memory loaded PE image, rebuilds
// it back into on-disk form (section RVAs -> file PointerToRawData) and writes
// the result to <path>. Failed section reads are zero-filled (typical for
// discarded INIT sections) and recorded as warnings.
bool DumpKernelPeToFile(
    DeviceClient& device,
    uint64_t address,
    const std::wstring& path,
    DumpPeResult* result,
    std::wstring* error);

// WinDbg complete-dump header is a fixed 8 KB prefix.
constexpr uint32_t kCrashDumpHeaderBytes = 0x2000;
constexpr uint32_t kCrashDumpMaxPhysicalRuns = 42;

struct DumpKernelHeaderInfo
{
    uint64_t DirectoryTableBase = 0;
    uint64_t PfnDataBase = 0;
    uint64_t PsLoadedModuleList = 0;
    uint64_t PsActiveProcessHead = 0;
    uint64_t KdDebuggerDataBlock = 0;
    uint32_t MajorVersion = 0;
    uint32_t MinorVersion = 0;
    uint32_t NumberProcessors = 1;
    uint32_t ProductType = 1;
    uint32_t SuiteMask = 0;
    std::string Comment;
};

struct DumpKernelCrashResult
{
    uint64_t HeaderBytes = 0;
    uint64_t PayloadBytes = 0;
    uint64_t BytesRead = 0;
    uint64_t BytesZeroFilled = 0;
    uint64_t BytesWritten = 0;
    uint32_t RangeCount = 0;
    uint32_t ChunksRead = 0;
    uint32_t ChunksFailed = 0;
    bool Complete = false;
    std::vector<std::wstring> Warnings;
};

struct DumpOsLiveResult
{
    uint64_t BytesWritten = 0;
    uint32_t ApiVersionUsed = 0;
    long Status = 0;
    bool IncludedUserPages = false;
    bool Compressed = false;
    bool IncludedHypervisorPages = false;
    std::vector<std::wstring> Warnings;
};

// Builds a DUMP_HEADER64 complete-dump prefix. Exposed for self-tests.
bool BuildCompleteDumpHeader(
    const std::vector<PhysicalMemoryRange>& ranges,
    const DumpKernelHeaderInfo& info,
    std::vector<uint8_t>* header,
    std::wstring* error);

// Streams a WinDbg-openable complete dump: 8 KB header + physical RAM runs.
bool DumpPhysicalMemoryToCrashDump(
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& path,
    uint64_t maxPayloadBytes,
    bool abortOnReadFailure,
    DumpKernelCrashResult* result,
    std::wstring* error);

// Asks the OS to write a live kernel dump (NtSystemDebugControl).
bool DumpOsLiveKernel(
    const std::wstring& path,
    bool includeUserPages,
    bool compress,
    bool includeHypervisorPages,
    DumpOsLiveResult* result,
    std::wstring* error);
