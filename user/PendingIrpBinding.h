#pragma once

#include "PendingIrpReader.h"
#include "TypeSchema.h"
#include "ObservationSource.h"
#include <array>

// Order is ETHREAD, IRP, IO_STACK_LOCATION. Only parent-accepted packages from
// SymbolEngine are supplied by the live scanner. Serialized provenance is not
// an authentication mechanism for an imported package.
struct PendingIrpSchemaBinding
{
    std::array<std::shared_ptr<const TypeSchemaPackage>, 3> Schemas;
    uint64_t ImageBase = 0;
    std::wstring ImagePath;
};

constexpr size_t PendingIrpEvidenceMaximumBytes = 16 * 1024 * 1024;

bool BuildPendingIrpLayout(const PendingIrpSchemaBinding& binding, pending_irp::IrpLayout* layout,
    std::wstring* error);

// Keeps the approved image lease through the scan. The actual source's loaded
// PE/RSDS identity is checked before and after the existing object invariants.
// Original ordered reads, schemas and bounded results are captured once.
bool CaptureBoundPendingIrps(IObservationSource& source, const PendingIrpSchemaBinding& binding,
    const std::vector<PendingIrpThreadInput>& threads, const PendingIrpScanOptions& options,
    PendingIrpScanResult* result, std::wstring* error, const std::atomic<bool>* cancellation = nullptr);
