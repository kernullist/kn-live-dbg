#include "KernelMonitor.h"
#include "EtwScanner.h"
#include "FirmwareTableScanner.h"
#include "HiveScanner.h"
#include "ProcessTriageScanner.h"
#include "WfpCalloutScanner.h"
#include "KmonHuntingJson.h"

#include <cstring>

namespace
{
    bool ReadHuntField(DeviceClient& device, uint64_t object, uint64_t offset, uint64_t* value)
    {
        bool ok = false;
        if (offset < 0x10000 && object >= 0xFFFF800000000000ull && object <= UINT64_MAX - offset - 8)
        {
            std::vector<uint8_t> bytes;
            if (device.ReadMemory(object + offset, 8, &bytes, nullptr) && bytes.size() == 8)
            {
                std::memcpy(value, bytes.data(), 8);
                ok = true;
            }
        }
        return ok;
    }
}

std::vector<KmonHuntCase> KernelMonitor::HuntCases() const
{
    std::lock_guard<std::mutex> lock(HuntMutex);
    return HuntIndex.Cases(GetTickCount64());
}

void KernelMonitor::QueueExecutableRegionPages(const ExecutableRegionObservation& observation, const std::wstring& role)
{
    if (observation.Executable && !observation.SessionUnverified)
    {
        ExecutablePages.Observe(observation.Context.Identity, observation.Range,
            observation.Context.AllocationBase, role, GetTickCount64());
    }
}

void KernelMonitor::ScanExecutablePageCandidates()
{
    const uint64_t now = GetTickCount64();
    // Leave the reference queue available for callbacks and short-lived events.
    for (size_t count = 0; count < 8 && ExecutionReferences.size() < 64 && !StopRequested.load(); ++count)
    {
        KmonPageWork page;
        if (!ExecutablePages.Next(now, &page))
        {
            break;
        }
        QueueExecutionReference(page.Range.Address, 0, page.Role, page.Identity);
    }
    if (now >= NextPageCoverageTickMs)
    {
        NextPageCoverageTickMs = now + 5000;
        KmonEvent event;
        event.Kind = L"coverage.page_candidates";
        event.Observation.Source = L"executable_page_scheduler";
        event.Summary = L"bounded full-range page scheduling; scheduled pages are not successful reads";
        event.Evidence[L"ranges"] = std::to_wstring(ExecutablePages.Size());
        event.Evidence[L"pages_scheduled"] = std::to_wstring(ExecutablePages.PagesScheduled);
        event.Evidence[L"cycles_scheduled"] = std::to_wstring(ExecutablePages.CyclesScheduled);
        event.Evidence[L"ranges_evicted"] = std::to_wstring(ExecutablePages.Evicted);
        event.Evidence[L"ranges_expired"] = std::to_wstring(ExecutablePages.Expired);
        event.Evidence[L"ranges_rejected"] = std::to_wstring(ExecutablePages.Rejected);
        event.Evidence[L"ranges_deferred"] = std::to_wstring(ExecutablePages.Deferred);
        event.Evidence[L"reference_backpressure"] = ExecutionReferences.size() >= 64 ? L"true" : L"false";
        RecordEvent(std::move(event));
    }
}

std::wstring KernelMonitor::HuntCasesJson() const
{
    std::lock_guard<std::mutex> lock(HuntMutex);
    const uint64_t now = GetTickCount64();
    return KmonHuntCasesJson(HuntIndex.Cases(now), now, HuntIndex.Evicted, HuntIndex.Rejected);
}

void KernelMonitor::QueueObservedStack(const TiEventRecord& record)
{
    const auto identity = ObserveProcessIdentity(record.ProcessId);
    if (!KmonFreshStack(identity, record.Timestamp, ObservationFileTime()))
    {
        EmitUnique(L"coverage.references", L"scan_failed:stack:identity:" + std::to_wstring(record.ProcessId),
            L"", L"stack", L"historical stack identity or freshness unavailable", L"stack addresses retained in source event", record.ProcessId);
        return;
    }
    for (size_t i = 0; i < record.CallstackAddresses.size() && i < 8; ++i)
    {
        const uint64_t address = record.CallstackAddresses[i];
        if (address >= 0x10000 && address < 0x0000800000000000ull)
        {
            QueueExecutionReference(address, 0, L"etw_stack_return", identity, record.Timestamp);
        }
    }
}

void KernelMonitor::ScanUserExecutionSurfaces(HANDLE process, const ObservationIdentity& identity,
    const std::vector<std::pair<uint64_t, uint32_t>>& modules, bool inventoryComplete)
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (StopRequested.load() || !GetLiveTargets(&device, &symbols))
    {
        return;
    }
    KmonEvent coverage;
    coverage.Kind = L"coverage.user_references";
    coverage.ProcessId = identity.ProcessId;
    coverage.Observation.Identity = identity;
    coverage.Observation.Source = L"process_execution_metadata";
    coverage.Observation.DependencyGroup = L"kernel_process_metadata";
    coverage.Summary = L"bounded thread, APC and instrumentation reference collection";
    coverage.Evidence[L"source_status"] = L"unavailable";
    coverage.Evidence[L"execution_observed"] = L"false";
    do
    {
        if (identity.CreateTime == 0 || identity.BootId.empty() || process == nullptr ||
            !identity.SameInstance(ObserveProcessIdentity(identity.ProcessId, process)))
        {
            coverage.Evidence[L"reason"] = L"retained process identity unavailable";
            break;
        }
        TypeFieldInfo dtb = {}, create = {}, pcb = {};
        if (!symbols->FindField(L"nt!_EPROCESS", L"Pcb", &pcb, nullptr) ||
            !symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtb, nullptr) ||
            !symbols->FindField(L"nt!_EPROCESS", L"CreateTime", &create, nullptr) ||
            pcb.IsBitField || dtb.Length != sizeof(uint64_t) || dtb.IsBitField ||
            create.Length != sizeof(uint64_t) || create.IsBitField ||
            pcb.Offset >= 0x10000 || dtb.Offset >= 0x10000 || create.Offset >= 0x10000 ||
            pcb.Offset + dtb.Offset > 0x10000 - sizeof(uint64_t))
        {
            coverage.Evidence[L"reason"] = L"process PDB layout unavailable";
            break;
        }
        ProcessAddressContext context = {};
        uint64_t creation = 0;
        if (!device->ResolveProcess(identity.ProcessId, static_cast<uint32_t>(pcb.Offset + dtb.Offset),
                0, &context, nullptr) || !ReadHuntField(*device, context.Eprocess, create.Offset, &creation) ||
            creation != identity.CreateTime)
        {
            coverage.Evidence[L"reason"] = L"kernel and retained process identities disagree";
            break;
        }
        auto resolved = identity;
        resolved.Eprocess = context.Eprocess;
        coverage.Observation.Identity = resolved;
        uint64_t callback = 0;
        uint64_t callbackSlot = 0;
        TypeFieldInfo instrumentation = {};
        if (symbols->FindField(L"nt!_KPROCESS", L"InstrumentationCallback", &instrumentation, nullptr) &&
            instrumentation.Length == sizeof(uint64_t) && !instrumentation.IsBitField &&
            instrumentation.Offset < 0x10000 &&
            ReadHuntField(*device, context.Eprocess, pcb.Offset + instrumentation.Offset, &callback))
        {
            callbackSlot = context.Eprocess + pcb.Offset + instrumentation.Offset;
            coverage.Evidence[L"instrumentation"] = callback == 0 ? L"null" : L"observed";
        }
        else
        {
            coverage.Evidence[L"instrumentation"] = L"unavailable";
        }

        const auto key = std::make_pair(identity.ProcessId, identity.CreateTime);
        if (UserThreadCursors.size() >= 4096 && UserThreadCursors.count(key) == 0)
        {
            UserThreadCursors.erase(UserThreadCursors.begin());
        }
        ProcessThreadScanOptions options;
        options.Target.ProcessId = identity.ProcessId;
        options.Target.Eprocess = context.Eprocess;
        options.Target.DirectoryTableBase = context.DirectoryTableBase;
        options.Target.UserDirectoryTableBase = context.UserDirectoryTableBase;
        options.Target.CreateTime = identity.CreateTime;
        options.Target.HasCreateTime = true;
        options.UserModuleEnumerationComplete = inventoryComplete;
        for (const auto& module : modules)
        {
            ProcessUserModuleRange range;
            range.Base = module.first;
            range.Size = module.second;
            options.UserModules.push_back(std::move(range));
        }
        options.CorrelateVad = false;
        options.IncludeApc = true;
        options.DetailLimit = 32;
        options.SkipThreads = UserThreadCursors[key];
        options.TimeBudgetMs = 100;
        ProcessThreadScanResult result;
        std::wstring error;
        const bool ok = ProcessTriageScanner(*device, *symbols).ScanThreads(options, &result, &error);
        UserThreadCursors[key] = result.ResumeIndex;
        if (!ReadHuntField(*device, context.Eprocess, create.Offset, &creation) || creation != identity.CreateTime ||
            !identity.SameInstance(ObserveProcessIdentity(identity.ProcessId, process)))
        {
            coverage.Evidence[L"reason"] = L"process identity changed during collection";
            break;
        }
        size_t references = 0;
        const auto queueUser = [&](uint64_t target, uint64_t slot, const wchar_t* role)
        {
            if (!StopRequested.load() && references < 128 && target >= 0x10000 && target < 0x0000800000000000ull)
            {
                QueueExecutionReference(target, slot, role, resolved);
                ++references;
            }
        };
        queueUser(callback, callbackSlot, L"instrumentation_callback");
        for (const auto& thread : result.Records)
        {
            queueUser(thread.StartAddress, 0, L"thread_start");
            queueUser(thread.Win32StartAddress, 0, L"win32_thread_start");
            for (const auto& apcQueue : thread.ApcQueues)
            {
                for (const auto& apc : apcQueue.Entries)
                {
                    queueUser(apc.NormalRoutine, 0, L"queued_apc_normal");
                    queueUser(apc.UserRoutine, 0, L"queued_apc_user_candidate");
                }
            }
        }
        coverage.Evidence[L"source_status"] = ok ? L"partial" : L"failed";
        coverage.Evidence[L"thread_inventory_complete"] = result.InventoryComplete ? L"true" : L"false";
        coverage.Evidence[L"thread_records"] = std::to_wstring(result.Records.size());
        coverage.Evidence[L"reference_candidates"] = std::to_wstring(references);
        coverage.Evidence[L"reference_budget_reached"] = references == 128 ? L"true" : L"false";
        coverage.Evidence[L"resume_index"] = std::to_wstring(result.ResumeIndex);
        coverage.Evidence[L"scope"] = L"native x64 metadata; APCs may dequeue before code read; list positions can change";
        coverage.Evidence[L"error"] = error;
        for (size_t i = 0; i < result.Warnings.size() && i < 4; ++i)
        {
            coverage.Evidence[L"warning_" + std::to_wstring(i)] = result.Warnings[i];
        }
    } while (false);
    RecordEvent(std::move(coverage));
}

void KernelMonitor::ScanCommunicationSurfaces()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols))
    {
        return;
    }
    KmonEvent coverage;
    coverage.Kind = L"coverage.channel";
    coverage.Observation.Source = L"kernel_channel_inventory";
    coverage.Observation.DependencyGroup = L"kernel_registration_metadata";
    coverage.Evidence[L"execution_observed"] = L"false";
    coverage.Evidence[L"communication_observed"] = L"false";
    coverage.Evidence[L"snapshot_atomic"] = L"false";
    size_t observed = 0;
    size_t verified = 0;
    bool complete = false;
    bool layoutVerified = false;
    bool ok = false;
    std::wstring error;
    std::vector<std::wstring> warnings;
    const auto queue = [&](uint64_t target, uint64_t slot, const wchar_t* role, bool layout)
    {
        if (!StopRequested.load() && KmonChannelCandidate(target, slot, layout))
        {
            QueueExecutionReference(target, slot, role);
            ++verified;
        }
    };
    switch (ChannelScanCursor++ % 5)
    {
    case 0:
    {
        coverage.Task = L"firmware_table";
        FirmwareTableScanResult result;
        ok = FirmwareTableScanner(*device, *symbols).Scan(&result, &error);
        observed = result.Records.size();
        layoutVerified = !result.UsedFallbackLayout;
        complete = result.CoverageComplete;
        warnings = std::move(result.Warnings);
        for (const auto& row : result.Records)
        {
            queue(row.FirmwareTableHandler, row.HandlerSlot, L"firmware_table_handler", layoutVerified);
        }
        coverage.Evidence[L"scope"] = L"Windows provider registrations; UEFI/SMM not inspected";
        break;
    }
    case 1:
    {
        coverage.Task = L"registry_hive";
        HiveScanResult result;
        HiveScanner::Options options;
        options.Limit = 128;
        ok = HiveScanner(*device, *symbols).Scan(options, &result, &error);
        observed = result.Hives.size();
        layoutVerified = result.LayoutFromPdb;
        complete = result.CoverageComplete;
        warnings = std::move(result.Warnings);
        for (const auto& row : result.Hives)
        {
            queue(row.GetCellRoutine, row.GetCellSlot, L"hive_get_cell", layoutVerified);
            queue(row.ReleaseCellRoutine, row.ReleaseCellSlot, L"hive_release_cell", layoutVerified);
            queue(row.Allocate, row.AllocateSlot, L"hive_allocate", layoutVerified);
            queue(row.Free, row.FreeSlot, L"hive_free", layoutVerified);
        }
        break;
    }
    case 2:
    {
        coverage.Task = L"etw_logger";
        EtwScanResult result;
        EtwScanner::Options options;
        ok = EtwScanner(*device, *symbols).Scan(options, &result, &error);
        observed = result.Loggers.size();
        layoutVerified = result.LayoutFromPdb;
        warnings = std::move(result.Warnings);
        for (const auto& row : result.Loggers)
        {
            queue(row.GetCpuClockCallback, row.GetCpuClockCallbackSlot, L"etw_logger_clock",
                row.GetCpuClockCallbackSlot != 0);
        }
        // The scanner cannot prove a stable, exhaustive logger inventory.
        coverage.Evidence[L"scope"] = L"resolved logger slots; inventory completeness unknown";
        break;
    }
    case 3:
    {
        coverage.Task = L"etw_provider";
        EtwProviderScanResult result;
        EtwScanner::Options options;
        options.Limit = 32;
        ok = EtwScanner(*device, *symbols).ScanProviders(options, &result, &error);
        observed = result.Providers.size();
        warnings = std::move(result.Warnings);
        coverage.Evidence[L"scope"] = L"heuristic diagnostics; no validated callback layout";
        break;
    }
    default:
    {
        coverage.Task = L"wfp_callout";
        WfpCalloutScanResult result;
        ok = WfpCalloutScanner(*device, *symbols).Scan(&result, &error);
        observed = result.Callouts.size();
        warnings = std::move(result.Warnings);
        coverage.Evidence[L"candidate_layout"] = result.LayoutSource;
        coverage.Evidence[L"candidate_walk_complete"] = result.CoverageComplete ? L"true" : L"false";
        size_t candidates = 0;
        const size_t budget = (std::min<size_t>)(result.Callouts.size(), 42);
        for (size_t index = 0; index < budget; ++index)
        {
            const auto& callout = result.Callouts[(WfpCalloutCursor + index) % result.Callouts.size()];
            const std::pair<uint64_t, const wchar_t*> targets[] =
            {
                {callout.ClassifyFn, L"wfp_classify_candidate"},
                {callout.NotifyFn, L"wfp_notify_candidate"},
                {callout.FlowDeleteFn, L"wfp_flow_delete_candidate"}
            };
            for (const auto& target : targets)
            {
                if (target.first >= 0xFFFF800000000000ull && candidates < 128 && !StopRequested.load())
                {
                    QueueExecutionReference(target.first, 0, target.second);
                    ++candidates;
                }
            }
        }
        coverage.Evidence[L"unverified_pointer_candidates"] = std::to_wstring(candidates);
        WfpCalloutCursor = result.Callouts.empty() ? 0 : (WfpCalloutCursor + budget) % result.Callouts.size();
        coverage.Evidence[L"candidate_resume_index"] = std::to_wstring(WfpCalloutCursor);
        coverage.Evidence[L"scope"] = L"scored layout; code candidates only, callback semantics unverified";
        break;
    }
    }
    coverage.Summary = coverage.Task + L" passive channel inventory";
    coverage.Evidence[L"source_status"] = !ok ? L"failed" : (complete ? L"walk_complete" : L"partial");
    coverage.Evidence[L"layout"] = layoutVerified ? L"pdb" : L"fallback_or_unavailable";
    coverage.Evidence[L"observed_records"] = std::to_wstring(observed);
    coverage.Evidence[L"validated_reference_candidates"] = std::to_wstring(verified);
    coverage.Evidence[L"error"] = error;
    for (size_t i = 0; i < warnings.size() && i < 8; ++i)
    {
        coverage.Evidence[L"warning_" + std::to_wstring(i)] = warnings[i];
    }
    RecordEvent(std::move(coverage));
}
