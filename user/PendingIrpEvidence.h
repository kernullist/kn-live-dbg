#pragma once

#include "PendingIrpBinding.h"
#include "ExecutableImage.h"
#include "ObservationReadRouting.h"

// Inputs that do not come from parser byte reads. They are collector-declared,
// not independently authenticated by offline replay.
struct PendingIrpCaptureContext
{
    ObservationSourceCapabilities Source;
    bool ReferenceStable = false;
    bool FinalCancelled = false;
    bool FinalSourceSame = false;
    uint64_t ReferenceBytes = 0; // Zero means retention was unavailable.
};

// Stable recorded-state signatures exclude scan times, pagination and operation
// IDs. They bind the source contract and all three exact schema packages.
IrpRetentionRequest PendingIrpRetentionRequest(const PendingIrpSchemaBinding& binding,
    const PendingIrpScanResult& result, const PendingIrpCaptureContext& context) noexcept;

std::wstring PendingIrpCaptureJson(const PendingIrpSchemaBinding& binding,
    const executable_image::DiskPeMetadata& metadata, const std::vector<PendingIrpThreadInput>& threads,
    const PendingIrpScanOptions& options, const PendingIrpScanResult& result, const ObservationRoutedReadSet& reads,
    const std::wstring& before, const std::wstring& after, const PendingIrpCaptureContext& context);

struct PendingIrpReplay
{
    std::wstring Status = L"unavailable", Issue, CaptureSha256;
    std::wstring ReferenceStatus = L"not_checked";
    bool SummaryMatched = false;
    bool QualifiedObservation = false;
    std::wstring ClaimAssessmentJson;
    PendingIrpScanResult Recomputed;
};

// Opens only the bounded capture and its fixed content-addressed sibling image.
// No live source, symbol lookup, PDB parser, or source initialization is used.
PendingIrpReplay ReplayPendingIrpCapture(const std::wstring& path);
std::wstring PendingIrpReplayJson(const PendingIrpReplay& replay);
