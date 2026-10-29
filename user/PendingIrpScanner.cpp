#include "PendingIrpScanner.h"
#include "PendingIrpReader.h"
#include "NativeObservationSource.h"
#include "SymbolEngine.h"

using pending_irp::IrpLayout;
using pending_irp::CollectPendingIrps;

namespace
{
    bool ResolveNestedField(SymbolEngine& symbols, const TypeLayoutInfo& layout,
        const std::vector<std::wstring>& path, size_t part, uint32_t accumulated,
        uint32_t expectedSize, uint32_t* offset, uint32_t anonymousDepth = 0)
    {
        if (part >= path.size() || layout.Size == 0 || layout.Size > 0x4000)
        {
            return false;
        }
        for (const TypeFieldInfo& field : layout.Fields)
        {
            if (field.IsBitField || field.Offset > layout.Size || field.Length > layout.Size - field.Offset)
            {
                continue;
            }
            const bool named = field.Name == path[part];
            const bool anonymous = field.Name.empty() || field.Name.find(L"<unnamed") != std::wstring::npos;
            if (!named && (!anonymous || anonymousDepth >= 3))
            {
                continue;
            }
            const uint32_t nextOffset = accumulated + field.Offset;
            if (named && part + 1 == path.size())
            {
                if (field.Length == expectedSize)
                {
                    *offset = nextOffset;
                    return true;
                }
                continue;
            }
            if (field.ChildTag != KNDBG_SYMTAG_UDT || field.ChildTypeId == 0)
            {
                continue;
            }
            TypeLayoutInfo child = {};
            if (symbols.GetTypeLayoutById(field.ModuleBase, field.ChildTypeId, field.TypeName, &child, nullptr) &&
                child.Size == field.Length &&
                ResolveNestedField(symbols, child, path, named ? part + 1 : part,
                    nextOffset, expectedSize, offset, named ? 0 : anonymousDepth + 1))
            {
                return true;
            }
        }
        return false;
    }

    bool BuildIrpLayout(SymbolEngine& symbols, IrpLayout* out)
    {
        TypeLayoutInfo thread = {};
        TypeLayoutInfo irp = {};
        TypeLayoutInfo stack = {};
        if (!symbols.GetTypeLayout(L"nt!_ETHREAD", &thread, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_IRP", &irp, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_IO_STACK_LOCATION", &stack, nullptr) ||
            thread.Size == 0 || thread.Size > 0x4000 || irp.Size == 0 || irp.Size > 0x1000 ||
            stack.Size == 0 || stack.Size > 0x1000)
        {
            return false;
        }
        out->ThreadSize = static_cast<uint32_t>(thread.Size);
        out->IrpSize = static_cast<uint32_t>(irp.Size);
        out->StackSize = static_cast<uint32_t>(stack.Size);
        const auto field = [&](const TypeLayoutInfo& type, std::vector<std::wstring> path, uint32_t size, uint32_t* offset)
        {
            return ResolveNestedField(symbols, type, path, 0, 0, size, offset);
        };
        field(irp, {L"Cancel"}, 1, &out->Cancel);
        field(irp, {L"PendingReturned"}, 1, &out->PendingReturned);
        field(irp, {L"IoStatus", L"Status"}, 4, &out->IoStatus);
        field(stack, {L"DeviceObject"}, 8, &out->DeviceObject);
        field(stack, {L"FileObject"}, 8, &out->FileObject);
        return field(thread, {L"IrpList"}, 16, &out->ThreadIrpList) &&
            field(thread, {L"Cid", L"UniqueProcess"}, 8, &out->ThreadPid) &&
            field(thread, {L"Cid", L"UniqueThread"}, 8, &out->ThreadTid) &&
            field(thread, {L"CreateTime"}, 8, &out->ThreadCreateTime) &&
            field(irp, {L"Type"}, 2, &out->IrpType) && field(irp, {L"Size"}, 2, &out->PacketSize) &&
            field(irp, {L"ThreadListEntry"}, 16, &out->ThreadListEntry) &&
            field(irp, {L"StackCount"}, 1, &out->StackCount) &&
            field(irp, {L"CurrentLocation"}, 1, &out->CurrentLocation) &&
            field(irp, {L"Tail", L"Overlay", L"CurrentStackLocation"}, 8, &out->CurrentStack) &&
            field(irp, {L"Tail", L"Overlay", L"Thread"}, 8, &out->OwningThread) &&
            field(stack, {L"MajorFunction"}, 1, &out->MajorFunction) &&
            field(stack, {L"MinorFunction"}, 1, &out->MinorFunction) &&
            field(stack, {L"Control"}, 1, &out->Control) &&
            field(stack, {L"CompletionRoutine"}, 8, &out->Completion) &&
            field(stack, {L"Context"}, 8, &out->Context);
    }

}

PendingIrpScanner::PendingIrpScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device), symbols_(symbols)
{
}

bool PendingIrpScanner::Scan(const std::vector<PendingIrpThreadInput>& threads,
    const PendingIrpScanOptions& options, PendingIrpScanResult* result, std::wstring* error)
{
    if (result == nullptr)
    {
        return false;
    }
    *result = PendingIrpScanResult{};
    result->ScanStartedTickMs = GetTickCount64();
    const auto space = device_.AddressSpace();
    if (!space.Valid())
    {
        if (error != nullptr)
        {
            *error = L"driver address-space capabilities unavailable";
        }
        return false;
    }
    IrpLayout layout;
    if (!BuildIrpLayout(symbols_, &layout))
    {
        if (error != nullptr)
        {
            *error = L"exact ETHREAD/IRP/IO_STACK_LOCATION PDB layout unavailable";
        }
        return false;
    }
    result->LayoutFromPdb = true;
    NativeObservationSource source(device_);
    auto read = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
    {
        return space.KernelRange(address, size) && ReadObservationRange(source, address, size, bytes, 0x20000, true);
    };
    CollectPendingIrps(read, layout, threads, options, result, space);
    result->ScanFinishedTickMs = GetTickCount64();
    const std::vector<KernelModuleInfo> modules = symbols_.Modules();
    for (PendingIrpCompletionRecord& record : result->Records)
    {
        for (const KernelModuleInfo& module : modules)
        {
            if (module.Size != 0 && record.CompletionRoutine >= module.Base &&
                record.CompletionRoutine - module.Base < module.Size)
            {
                record.Module = module.ImageName;
                break;
            }
        }
        record.Suspicious = record.Module.empty();
        uint64_t displacement = 0;
        symbols_.FindNearestSymbol(record.CompletionRoutine, &record.Symbol, &displacement, nullptr);
    }
    result->Warnings.push_back(L"equal snapshots do not reference IRP lifetime or exclude address reuse; corroboration is required");
    if (!result->CoverageComplete)
    {
        result->Warnings.push_back(L"pending IRP snapshot is partial, changed, or bounded; unobserved completion paths remain unknown");
    }
    return true;
}
