#include "PendingIrpScanner.h"
#include "PendingIrpBinding.h"
#include "NativeObservationSource.h"
#include "SymbolEngine.h"
#include "ExecutableImage.h"

PendingIrpScanner::PendingIrpScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device), symbols_(symbols)
{
}

bool PendingIrpScanner::Scan(const std::vector<PendingIrpThreadInput>& threads,
    const PendingIrpScanOptions& options, PendingIrpScanResult* result, std::wstring* error)
{
    if (result == nullptr) { return false; }
    *result = {};
    NativeObservationSource source(device_);
    result->AddressSpace = source.Capabilities().AddressSpace;
    if ((options.Cancellation && options.Cancellation->load()) ||
        !result->AddressSpace.Valid() || source.Capabilities().SourceId.empty())
    {
        // Source admission precedes symbol acquisition, which may otherwise
        // start a worker or an authorized parent-side symbol download.
        result->ScanStartedTickMs = result->ScanFinishedTickMs = GetTickCount64();
        result->QualificationReason = options.Cancellation && options.Cancellation->load() ?
            L"irp_scan_cancelled_before_schema_acquisition" : L"native_irp_source_unavailable";
        if (error) { *error = result->QualificationReason; }
        return false;
    }
    TypeLayoutInfo thread, irp, stack;
    if (!symbols_.GetTypeLayout(L"nt!_ETHREAD", &thread, error) ||
        !symbols_.GetTypeLayout(L"nt!_IRP", &irp, error) ||
        !symbols_.GetTypeLayout(L"nt!_IO_STACK_LOCATION", &stack, error) ||
        thread.ModuleBase == 0 || thread.ModuleBase != irp.ModuleBase || thread.ModuleBase != stack.ModuleBase)
    {
        result->QualificationReason = L"same_module_irp_schemas_unavailable";
        if (error) { *error = result->QualificationReason; }
        return false;
    }
    PendingIrpSchemaBinding binding;
    binding.Schemas = {thread.SchemaPackage, irp.SchemaPackage, stack.SchemaPackage};
    binding.ImageBase = thread.ModuleBase;
    const auto modules = symbols_.Modules();
    for (const auto& module : modules)
    {
        if (module.Base == binding.ImageBase && thread.SchemaPackage && module.Size == thread.SchemaPackage->ImageSize)
        { binding.ImagePath = executable_image::NormalizeReferencePath(module.ImagePath); break; }
    }
    if (!CaptureBoundPendingIrps(source, binding, threads, options, result, error, options.Cancellation)) { return false; }
    for (auto& record : result->Records)
    {
        for (const auto& module : modules)
        {
            if (module.Size != 0 && record.CompletionRoutine >= module.Base && record.CompletionRoutine - module.Base < module.Size)
            { record.Module = module.ImageName; break; }
        }
        record.Suspicious = record.Module.empty();
        uint64_t displacement = 0;
        symbols_.FindNearestSymbol(record.CompletionRoutine, &record.Symbol, &displacement, nullptr);
    }
    result->Warnings.push_back(L"equal snapshots do not reference IRP lifetime or exclude address reuse; corroboration is required");
    if (!result->RuntimeQualified) { result->Warnings.push_back(result->QualificationReason); }
    if (!result->CoverageComplete)
    { result->Warnings.push_back(L"pending IRP snapshot is partial, changed, or bounded; unobserved completion paths remain unknown"); }
    return true;
}
