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
    uint64_t Start = 0;
    uint64_t End = 0;
    uint64_t Size = 0;
    uint64_t PhysicalAddress = 0;
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
    bool FromPfn = false;
    PeHeaderProbe Pe = {};
    std::wstring Classification;
    std::wstring Risk;
    std::wstring Notes;
};

struct OrphanKernelPageOptions
{
    bool DeepPfn = false;
    bool WxOnly = false;
    bool PeOnly = false;
    bool IncludeSession = true;
    uint32_t Limit = 64;
    uint32_t MaxTablePages = 32768;
    uint32_t MaxPfnEntries = 0;
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
    uint64_t ExecutableLeaves = 0;
    uint64_t ModuleLeavesSkipped = 0;
    uint64_t SelfMapLeavesSkipped = 0;
    uint64_t RegionsCoalesced = 0;
    uint64_t PfnEntriesExamined = 0;
    uint64_t PfnHits = 0;
    bool La57 = false;
    bool PageWalkComplete = false;
    bool PfnWalkAttempted = false;
    bool PfnWalkComplete = false;
    bool BigPoolQueried = false;
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
