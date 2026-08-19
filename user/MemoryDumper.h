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
// PeHeaderProbe. Used by !pool pe to flag PE images stashed in pool
// memory, including malware-style header-stripped variants.
bool ProbeForPeHeader(const uint8_t* buffer, size_t length, PeHeaderProbe* result);

// Page-start leftover probe. Uses DOS.e_lfanew only (no interior 4-byte NT
// scan). For kernel leftover pages a random FILE_HEADER in the page is not a
// mapped image. dump-pe / !pool pe keep the looser ProbeForPeHeader.
bool ProbeForPageStartPeHeader(const uint8_t* buffer, size_t length, PeHeaderProbe* result);

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
    uint64_t BugCheckParameter1 = 0;
    uint64_t BugCheckParameter2 = 0;
    uint32_t MajorVersion = 0;
    uint32_t MinorVersion = 0;
    uint32_t NumberProcessors = 1;
    uint32_t ProductType = 1;
    uint32_t SuiteMask = 0;
    uint32_t DumpAttributes = 0;
    std::string Comment;
    std::vector<uint8_t> ContextRecord;
};

struct DumpKernelCrashResult
{
    uint64_t HeaderBytes = 0;
    uint64_t PayloadBytes = 0;
    uint64_t BytesRead = 0;
    uint64_t BytesZeroFilled = 0;
    uint64_t BytesWritten = 0;
    uint64_t DirectoryTableBase = 0;
    uint64_t KdDebuggerDataBlock = 0;
    uint64_t CurrentThread = 0;
    uint64_t ContextRip = 0;
    uint64_t ContextRsp = 0;
    uint32_t ContextFlags = 0;
    uint32_t RangeCount = 0;
    uint32_t ChunksRead = 0;
    uint32_t ChunksFailed = 0;
    bool Complete = false;
    bool KdbgPlain = false;
    bool KdbgWasEncoded = false;
    bool KptiRootMerged = false;
    bool CurrentProcessPatched = false;
    bool ProcessorStatePatched = false;
    bool Wow64Target = false;
    bool TrapFrameSynthesized = false;
    std::vector<std::wstring> Warnings;
};

// Optional process-filter fixups for dump-live /user <pid|eprocess>.
// WinDbg treats DUMP_TYPE_FULL as a kernel dump and walks header DTB plus
// KPRCB.CurrentThread. KPTI leaves the process kernel CR3 user-half empty,
// so user VA translation fails unless the dumped root is merged.
struct ProcessDumpWinDbgFixup
{
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t KernelDirectoryTableBase = 0;
    uint64_t UserDirectoryTableBase = 0;
    uint64_t Peb = 0;
    uint64_t Thread = 0;
    uint64_t HeaderRip = 0;
    uint64_t HeaderRsp = 0;
    uint64_t CreateTime = 0;
    uint32_t PrcbProcStateContextOffset = 0;
    uint32_t PrcbProcStateSpecialRegOffset = 0;
    uint32_t PrcbContextOffset = 0;
    uint32_t PrcbSize = 0;
    uint64_t SavedContext = 0;
    bool Wow64 = false;
    bool HasKernelTrap = false;
};

struct DumpOsLiveResult
{
    uint64_t BytesWritten = 0;
    uint32_t ApiVersionUsed = 0;
    long Status = 0;
    bool IncludedUserPages = false;
    bool Compressed = false;
    bool IncludedHypervisorPages = false;
    bool ProcessFiltered = false;
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t DirectoryTableBase = 0;
    uint32_t RangeCount = 0;
    std::vector<std::wstring> Warnings;
};

// Builds a DUMP_HEADER64 complete-dump prefix. Exposed for self-tests.
bool BuildCompleteDumpHeader(
    const std::vector<PhysicalMemoryRange>& ranges,
    const DumpKernelHeaderInfo& info,
    std::vector<uint8_t>* header,
    std::wstring* error);

// Streams a WinDbg-openable complete dump: 8 KB header + physical RAM runs.
// rangesOverride, when non-null, replaces MmGetPhysicalMemoryRanges.
// directoryTableBaseOverride, when non-zero, is stored as DirectoryTableBase
// instead of CPU0 CR3. commentOverride replaces the default header comment.
// processFixup, when non-null, marks the dump as a filtered live dump,
// merges the KPTI user/kernel page-table root, overwrites CPU0
// ProcessorState.ContextFrame, and pins CurrentThread to a target
// thread that has a kernel trap or a synthesized kernel KTRAP_FRAME
// so dbgeng stays in AMD64 kernel context. IdleThread is the fallback.
bool DumpPhysicalMemoryToCrashDump(
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& path,
    uint64_t maxPayloadBytes,
    bool abortOnReadFailure,
    DumpKernelCrashResult* result,
    std::wstring* error,
    const std::vector<PhysicalMemoryRange>* rangesOverride = nullptr,
    uint64_t directoryTableBaseOverride = 0,
    const char* commentOverride = nullptr,
    const ProcessDumpWinDbgFixup* processFixup = nullptr);

// Walks the process DTB (user + kernel halves) and writes a complete dump of
// resident pages so WinDbg can see that process's user address space.
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
    std::wstring* error);

// Asks the OS to write a live kernel dump (NtSystemDebugControl).
bool DumpOsLiveKernel(
    const std::wstring& path,
    bool includeUserPages,
    bool compress,
    bool includeHypervisorPages,
    DumpOsLiveResult* result,
    std::wstring* error);

// Compile/runtime ABI check for SYSDBG_LIVEDUMP_CONTROL V1/V2. Self-test only.
bool DumpOsLiveControlSelfTest();

// Round-trip check for the Win8+ KdCopyDataBlock decoder. Self-test only.
bool DecodeKdbgSelfTest();

// Coalesce/merge checks for process-filtered live dumps. Self-test only.
bool DumpLiveProcessFilterSelfTest();
