#pragma once

#include "PendingIrpBinding.h"
#include "ObservationReadRouting.h"

struct PendingIrpCaptureContext;
enum class PendingIrpClaimMode { Capture, Replay };
constexpr size_t PendingIrpClaimLimit = 128;
constexpr size_t PendingIrpClaimMaximumCharacters = 128 * 1024;

// Internal adapter: call only after the bound collector or canonical replay has
// recomputed the result from the supplied reads. Booleans imported in isolation
// are not proof inputs. Interpret facts under the explicit current policy. This does
// not change the capture/replay policy or make imported source metadata trusted.
std::wstring PendingIrpClaimAssessmentJson(const PendingIrpSchemaBinding& binding,
    const std::vector<PendingIrpThreadInput>& threads, const PendingIrpScanOptions& options,
    const PendingIrpScanResult& result, const ObservationRoutedReadSet& reads,
    const PendingIrpCaptureContext& context, const std::wstring& captureSha256,
    PendingIrpClaimMode mode, bool referenceAvailable) noexcept;
