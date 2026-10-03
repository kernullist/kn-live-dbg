#pragma once

#include "ExecutionSurfaceCore.h"

struct ExecutionSurfaceRow
{
    std::wstring Kind;
    std::wstring Name;
    std::wstring Status;
    std::wstring Baseline = L"not_applicable";
    std::wstring Owner;
    uint64_t ModuleBase = 0;
    uint64_t RootSlot = 0;
    uint64_t Table = 0;
    uint64_t Slot = 0;
    uint64_t Target = 0;
    uint64_t HandleValue = 0;
    uint64_t ProcessPeb = 0;
    uint32_t Index = 0;
    uint32_t PointerSize = 8;
    uint32_t Protection = 0;
    uint32_t MemoryType = 0;
    bool Stable = false;
    bool TableComplete = false;
    bool TablePresent = false;
    bool Executable = false;
    bool Unowned = false;
    std::vector<ObservationAnchor> Anchors;
};

struct ExecutionSurfaceOptions
{
    // Only a matching native PDB may supply this field offset.
    bool HasKernelCallbackOffset = false;
    uint32_t KernelCallbackOffset = 0;
    size_t ModuleStart = 0;
    size_t ModuleBudget = 512;
    uint64_t HandleStart = 0;
    size_t HandleBudget = 4096;
    uint64_t TimeBudgetMs = 2000;
    std::vector<std::pair<uint64_t, uint32_t>> ImageCandidates;
    std::function<bool()> Cancelled;
};

struct ExecutionSurfaceResult
{
    ObservationIdentity Identity;
    uint64_t ObservedAt = 0;
    uint64_t ObservedMs = 0;
    size_t NextModule = 0;
    uint64_t NextHandle = 0;
    bool IdentityStable = false;
    bool ModuleInventoryComplete = false;
    std::map<std::wstring, std::wstring> Coverage;
    std::vector<ExecutionSurfaceRow> Rows;
};

ExecutionSurfaceResult ScanExecutionSurfaces(uint32_t pid, const ExecutionSurfaceOptions& options = {});
bool QueryExecutionSurfacePeb(HANDLE process, uint32_t pid, uint64_t* peb);
std::wstring ExecutionSurfacesJson(const ExecutionSurfaceResult& result);
