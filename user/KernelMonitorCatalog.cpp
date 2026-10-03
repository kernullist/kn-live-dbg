#include "KernelMonitor.h"
#include "ProcessTriageScanner.h"

#include <Psapi.h>
#include <algorithm>

uint64_t KernelMonitor::ObserveExecutableRegion(ExecutableRegionObservation observation)
{
    if (observation.Context.Timestamp == 0)
    {
        observation.Context.Timestamp = ObservationFileTime();
    }
    if (observation.Context.MonotonicMs == 0)
    {
        observation.Context.MonotonicMs = GetTickCount64();
    }
    bool changed = false;
    const uint64_t generation = RegionCatalog.Observe(observation, &changed);
    observation.Context.MappingGeneration = generation;
    CatalogRecords.store(RegionCatalog.Snapshot().size());
    CatalogEvicted.store(RegionCatalog.Evicted);
    if (generation != 0 && changed)
    {
        KmonEvent event;
        event.Kind = L"coverage.region";
        event.ProcessId = observation.Context.Identity.ProcessId;
        event.Summary = L"executable region observation; execution and maliciousness are not established";
        event.Observation = observation.Context;
        event.Observation.MappingGeneration = generation;
        event.Evidence[L"base"] = std::to_wstring(observation.Range.Address);
        event.Evidence[L"size"] = std::to_wstring(observation.Range.Size);
        event.Evidence[L"writable"] = observation.Writable ? L"true" : L"false";
        event.Evidence[L"copy_on_write"] = observation.CopyOnWrite ? L"true" : L"false";
        event.Evidence[L"session_unverified"] = observation.SessionUnverified ? L"true" : L"false";
        event.Evidence[L"image_mapping"] = observation.ImageMapping ? L"true" : L"false";
        event.Evidence[L"backing_object"] = std::to_wstring(observation.BackingObject);
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"generation_basis"] = L"observed_identity_or_mapping_change; unseen_reuse_unknown";
        event.Evidence[L"source_count"] = std::to_wstring(RegionCatalog.Snapshot().at(generation).Sources.size());
        event.Evidence[L"dependency_group_count"] = std::to_wstring(RegionCatalog.Snapshot().at(generation).DependencyGroups.size());
        RecordEvent(std::move(event));
    }
    if (generation != 0 && !observation.ContentSha256.empty())
    {
        const auto& current = RegionCatalog.Snapshot().at(generation);
        size_t links = 0;
        for (const auto& pair : RegionCatalog.Snapshot())
        {
            const auto& other = pair.second;
            if (pair.first == generation || other.Latest.Context.Identity.ProcessId == observation.Context.Identity.ProcessId)
            {
                continue;
            }
            const auto relation = ExecutableRegionCatalog::Correlate(current, other);
            if (relation == ObservationRelation::Temporal)
            {
                continue;
            }
            KmonEvent event;
            event.Kind = L"coverage.region_link";
            event.ProcessId = observation.Context.Identity.ProcessId;
            event.TargetProcessId = other.Latest.Context.Identity.ProcessId;
            event.Observation = observation.Context;
            event.Summary = L"captured contents correspond across observed regions; causality is not established";
            event.Evidence[L"relationship"] = ObservationRelationName(relation);
            event.Evidence[L"from_generation"] = std::to_wstring(generation);
            event.Evidence[L"to_generation"] = std::to_wstring(other.Generation);
            event.Evidence[L"to_observed_ms"] = std::to_wstring(other.LastSeenMs);
            event.Evidence[L"content_sha256"] = observation.ContentSha256;
            event.Evidence[L"write_mechanism"] = L"unknown";
            event.Evidence[L"simultaneous_mapping"] = L"not_established";
            RecordEvent(std::move(event));
            if (++links == 16)
            {
                break;
            }
        }
    }
    return generation;
}

void KernelMonitor::ScanUserRegionCatalog(HANDLE process, const ObservationIdentity& identity,
    const ProcessVadScanResult& vad, const std::vector<std::pair<uint64_t, uint32_t>>& modules,
    bool inventoryComplete)
{
    if (identity.CreateTime == 0)
    {
        return;
    }
    const auto owner = [&](uint64_t address)
    {
        for (const auto& module : modules)
        {
            if (address >= module.first && address - module.first < module.second)
            {
                return CodeOwnership::OwnedUnverified;
            }
        }
        return inventoryComplete ? CodeOwnership::UnownedExecutable : CodeOwnership::Unknown;
    };
    const auto make = [&](uint64_t address, uint64_t size, const wchar_t* source)
    {
        ExecutableRegionObservation observation;
        observation.Context.Identity = identity;
        observation.Context.Source = source;
        observation.Context.DependencyGroup = L"process_memory_metadata";
        observation.Context.Ownership = owner(address);
        observation.Context.Coverage.Attempted = true;
        observation.Context.Coverage.InventoryAvailable = inventoryComplete;
        observation.Context.Coverage.Reason = L"mapping_metadata_only";
        observation.Range = {address, size};
        observation.Executable = true;
        return observation;
    };
    // Kernel records are usable only for the same process instance.
    if (vad.Target.HasCreateTime && vad.Target.CreateTime == identity.CreateTime)
    {
        KmonEvent coverage;
        coverage.Kind = L"coverage.user_pages";
        coverage.ProcessId = identity.ProcessId;
        coverage.Observation.Identity = identity;
        coverage.Observation.Source = L"kernel_user_pte";
        coverage.Summary = L"bounded user PTE pass; resume cursor is process-instance specific";
        coverage.Evidence[L"tables_read"] = std::to_wstring(vad.PageTablePagesRead);
        coverage.Evidence[L"read_failures"] = std::to_wstring(vad.PageTableReadFailures);
        coverage.Evidence[L"resume_address"] = std::to_wstring(vad.HiddenPteResumeAddress);
        coverage.Evidence[L"traversal_finished"] = vad.HiddenPteTraversalFinished ? L"true" : L"false";
        coverage.Evidence[L"budget_exhausted"] = vad.HiddenPteBudgetExhausted ? L"true" : L"false";
        coverage.Evidence[L"source_status"] = !vad.HiddenPteScanEnabled || vad.PagingLevels == 0 ? L"unavailable" :
            (vad.PageTableReadFailures != 0 ? L"failed" : (vad.HiddenPteTraversalFinished ? L"walk_complete" : L"partial"));
        RecordEvent(std::move(coverage));
        for (const auto& region : vad.Records)
        {
            if (!region.Executable)
            {
                continue;
            }
            auto observation = make(region.StartAddress, region.Size, L"kernel_vad");
            observation.Context.Identity.Eprocess = vad.Target.Eprocess;
            observation.Context.AllocationBase = region.StartAddress;
            observation.BackingObject = region.ControlArea;
            observation.Writable = region.Writable;
            observation.CopyOnWrite = region.CopyOnWrite;
            observation.ImageMapping = !region.PrivateMemory && !region.SectionFileName.empty();
            observation.Context.Coverage.Reason = vad.CoverageComplete && !vad.Incomplete ?
                L"vad_metadata_observed" : L"vad_inventory_partial";
            ObserveExecutableRegion(observation);
            if (observation.Context.Ownership != CodeOwnership::OwnedUnverified || process == nullptr || !inventoryComplete)
            {
                QueueExecutableRegionPages(observation, L"user_page_candidate");
            }
        }
        for (const auto& region : vad.HiddenPteRecords)
        {
            if (!region.Executable)
            {
                continue;
            }
            auto observation = make(region.StartAddress, region.Size, L"kernel_user_pte");
            observation.Context.DependencyGroup = L"page_tables";
            observation.Context.Identity.Eprocess = vad.Target.Eprocess;
            observation.Context.PfnKnown = region.PhysicalAddress != 0;
            observation.Context.Pfn = region.PhysicalAddress >> 12;
            observation.PageSize = region.PageSize;
            observation.Writable = region.Writable;
            observation.Context.Coverage.Reason = vad.HiddenPteTruncated ? L"pte_inventory_partial" : L"pte_mapping_observed";
            ObserveExecutableRegion(observation);
            QueueExecutableRegionPages(observation, L"user_hidden_pte_page");
        }
    }
    if (process == nullptr || !identity.SameInstance(ObserveProcessIdentity(identity.ProcessId, process)))
    {
        return;
    }
    auto& cursor = UserRegionCursors[{identity.ProcessId, identity.CreateTime}];
    const uint64_t startMs = GetTickCount64();
    for (size_t count = 0; count < 128 && GetTickCount64() - startMs < 20; ++count)
    {
        MEMORY_BASIC_INFORMATION region = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor), &region, sizeof(region)) != sizeof(region))
        {
            KmonEvent coverage;
            coverage.Kind = L"coverage.regions";
            coverage.ProcessId = identity.ProcessId;
            coverage.Observation.Identity = identity;
            coverage.Observation.Source = L"virtual_query";
            coverage.Observation.Coverage.Attempted = true;
            coverage.Observation.Coverage.TraversalComplete = GetLastError() == ERROR_INVALID_PARAMETER;
            coverage.Observation.Coverage.Reason = coverage.Observation.Coverage.TraversalComplete ?
                L"address_space_traversal_finished" : L"virtual_query_failed";
            coverage.Evidence[L"cursor"] = std::to_wstring(cursor);
            RecordEvent(std::move(coverage));
            cursor = 0;
            break;
        }
        const uint64_t base = reinterpret_cast<uint64_t>(region.BaseAddress);
        if (region.RegionSize == 0 || base > UINT64_MAX - region.RegionSize || base + region.RegionSize <= cursor)
        {
            cursor = 0;
            break;
        }
        cursor = base + region.RegionSize;
        const DWORD execute = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (region.State == MEM_COMMIT && (region.Protect & execute) != 0)
        {
            auto observation = make(base, region.RegionSize, L"virtual_query");
            observation.Context.AllocationBase = reinterpret_cast<uint64_t>(region.AllocationBase);
            observation.Writable = (region.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            observation.CopyOnWrite = (region.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
            observation.ImageMapping = region.Type == MEM_IMAGE;
            PSAPI_WORKING_SET_EX_INFORMATION workingSet = {};
            workingSet.VirtualAddress = region.BaseAddress;
            if (region.Type == MEM_IMAGE && QueryWorkingSetEx(process, &workingSet, sizeof(workingSet)) &&
                workingSet.VirtualAttributes.Valid && !workingSet.VirtualAttributes.Shared)
            {
                observation.CopyOnWrite = true;
            }
            const uint64_t generation = ObserveExecutableRegion(observation);
            QueueExecutableRegionPages(observation, observation.Context.Ownership == CodeOwnership::OwnedUnverified ?
                L"image_page_candidate" : L"user_page_candidate");
            if (generation != 0 && (observation.Context.Ownership == CodeOwnership::UnownedExecutable || observation.CopyOnWrite))
            {
                QueueCapture(L"user_exec_candidate", base, (std::min<uint64_t>)(region.RegionSize, 4096),
                    identity, ObservationFileTime(), nullptr, generation);
            }
        }
        else
        {
            RegionCatalog.RetireRange(identity, {base, region.RegionSize}, GetTickCount64());
        }
    }
}
