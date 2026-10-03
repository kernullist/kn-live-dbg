#pragma once

#include "DeviceClient.h"
#include "LeftoverCommon.h"
#include "MemoryDumper.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct OrphanKernelPageRegion
{
    uint64_t Cr3 = 0;
    uint32_t RootProcessId = 0;
    uint64_t RootCreateTime = 0;
    uint64_t Start = 0;
    uint64_t End = 0;
    uint64_t Size = 0;
    uint64_t PhysicalAddress = 0;
    uint64_t MappingPageSize = 0x1000; // Hardware leaf size, even for a sampled window.
    uint64_t PoolAddress = 0;
    uint64_t PoolSize = 0;
    uint32_t PoolTag = 0;
    uint32_t PageCount = 0;
    bool Writable = false;
    bool Executable = true;
    bool LargePage = false;
    bool InBigPool = false;
    bool PoolNonPaged = false;
    bool SessionSpace = false;
    bool HasPe = false;
    uint64_t PeAddress = 0;
    bool FromPfn = false;
    PeHeaderProbe Pe = {};
    std::wstring Classification;
    std::wstring Risk;
    std::wstring Notes;
};

struct OrphanKernelPageRoot
{
    uint64_t Cr3 = 0;
    uint32_t ProcessId = 0;
    uint64_t CreateTime = 0;
};

struct OrphanKernelPageBodyCursor
{
    uint64_t PageAddress = 0;
    uint64_t PfnAddress = 0;
    uint64_t RegionOffset = 0;
    bool DeepPfn = false;
    uint64_t RegionAfter = 0;
    uint64_t WindowRound = 0;
};

struct OrphanKernelPageCursor
{
    OrphanKernelPageRoot Root;
    uint64_t PageAddress = 0;
    uint64_t PfnAddress = 0;
    uint64_t RegionOffset = 0;
    bool PfnPending = false;
    std::vector<OrphanKernelPageBodyCursor> BodyWindows;
};

struct OrphanKernelPageContinuation
{
    std::vector<OrphanKernelPageCursor> Roots;
    uint64_t RootAfter = 0;
};

struct OrphanKernelPageOptions
{
    bool DeepPfn = false;
    bool Incremental = false;
    uint64_t ResumeAddress = 0;
    bool WxOnly = false;
    bool PeOnly = false;
    bool IncludeSession = true;
    uint32_t Limit = 64;
    uint32_t MaxTablePages = 32768;
    uint32_t MaxPfnEntries = 0;
    uint32_t MaxRegionBytes = 0; // Zero preserves full-region command output.
    uint64_t RegionOffset = 0;  // Continuation across interleaved body windows.
    std::vector<OrphanKernelPageRoot> Roots;
    bool RootInventoryComplete = false;
    OrphanKernelPageContinuation* Continuation = nullptr;
    // Internal per-pass bounds are public for deterministic scanner fixtures.
    uint64_t PageStartAddress = 0;
    uint64_t PfnStartAddress = 0;
    bool UseAddressBodyCursor = false;
    uint64_t BodyRegionAfter = 0;
    uint64_t BodyWindowRound = 0;
};

struct OrphanKernelPageResult
{
    std::vector<OrphanKernelPageRegion> Regions;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> CoverageNotes;
    uint64_t Cr3 = 0;
    uint64_t PteBase = 0;
    uint64_t PfnDatabase = 0;
    uint32_t PagingLevels = 4;
    uint64_t TablePagesWalked = 0;
    uint64_t ResumeAddress = 0;
    uint64_t TableReadFailures = 0;
    uint64_t RegionsDropped = 0;
    bool TraversalFinished = false;
    uint64_t ExecutableLeaves = 0;
    uint64_t ModuleLeavesSkipped = 0;
    uint64_t SelfMapLeavesSkipped = 0;
    uint64_t RegionsCoalesced = 0;
    uint64_t PfnEntriesExamined = 0;
    uint64_t PfnHits = 0;
    uint64_t PfnReadFailures = 0;
    uint64_t PfnValidationFailures = 0;
    uint64_t SampleValidationFailures = 0;
    uint64_t RegionsDiscovered = 0;
    uint64_t NextRegionOffset = 0;
    uint64_t NextBodyRegionAfter = 0;
    uint64_t NextBodyWindowRound = 0;
    uint64_t NextPageAddress = 0;
    uint64_t NextPfnAddress = 0;
    uint64_t RootCount = 0;
    uint32_t RootProcessId = 0;
    uint64_t RootCreateTime = 0;
    bool RootInventoryComplete = false;
    bool ContinuationReset = false;
    bool BodyCursorEvicted = false;
    bool PfnContinuationPending = false;
    bool AlternateRoot = false;
    bool La57 = false;
    bool PageWalkComplete = false;
    bool PfnWalkAttempted = false;
    bool PfnWalkComplete = false;
    bool BigPoolQueried = false;
    bool RegionsTruncated = false;
    bool AnyHighRisk = false;
};

class OrphanKernelPageScanner
{
public:
    OrphanKernelPageScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(
        const OrphanKernelPageOptions& options,
        OrphanKernelPageResult* result,
        std::wstring* error);

private:
    bool WalkKernelPageTables(
        const OrphanKernelPageOptions& options,
        OrphanKernelPageResult* result,
        std::wstring* error);
    bool WalkPfnDatabase(
        const OrphanKernelPageOptions& options,
        OrphanKernelPageResult* result,
        std::wstring* error);
    void FinalizeRegions(
        const OrphanKernelPageOptions& options,
        OrphanKernelPageResult* result);

    DeviceClient& device_;
    SymbolEngine& symbols_;
    std::vector<LeftoverModuleRange> modules_;
    LeftoverBigPoolSnapshot pool_;
};

std::wstring BuildOrphanKernelPageJson(const OrphanKernelPageResult& result);
bool OrphanKernelPageSelfTest();
bool ReadOrphanRootIdentity(
    DeviceClient& device, SymbolEngine& symbols,
    const OrphanKernelPageRoot& expected, uint64_t* eprocess,
    std::wstring* error);

bool ReadOrphanRootMemory(
    DeviceClient& device, uint64_t cr3, uint64_t address, uint32_t length,
    std::vector<uint8_t>* bytes, std::wstring* error = nullptr,
    bool requireExecutable = false);
bool ProbeOrphanRootExecutable(
    DeviceClient& device, uint64_t cr3, uint64_t address, bool* executable);
