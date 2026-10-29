#pragma once

#include "AddressSpaceDescriptor.h"
#include <cstdint>

enum class NativeExecutionEvidenceKind : uint8_t
{
    PointerRegistration,
    ThreadStart,
    RawStackValue,
    QueuedApcRoutine,
    ApcArgument,
    CapturedThreadContext,
    SavedTrapContext,
    HardwareBreakpoint,
    Unknown
};

struct NativeExecutionEvidence
{
    NativeExecutionEvidenceKind Kind = NativeExecutionEvidenceKind::Unknown;
    uint32_t ProcessId = 0;
    uint64_t ProcessCreateTime = 0;
    uint32_t ThreadId = 0;
    uint64_t ThreadCreateTime = 0;
    uint64_t CaptureTime = 0;
    uint64_t Address = 0;
    uint32_t PointerBytes = 8;
    AddressSpaceDescriptor AddressSpace;
    bool ProcessIdentityStable = false;
};

struct ExecutionEvidenceAssessment
{
    const wchar_t* Level = L"unqualified";
    const wchar_t* Observation = L"unknown";
    const wchar_t* Reason = L"unsupported_source_kind";
    bool IdentityQualified = false;
    bool ThreadIdentityQualified = false;
    bool ReferenceObserved = false;
    bool ExecutionObserved = false;
    bool ActorAttributed = false;
};

// These native adapters supply references or saved metadata. No producer here
// supplies a CPU-qualified instruction sample, decoded trace, or write event.
inline ExecutionEvidenceAssessment AssessNativeExecutionEvidence(const NativeExecutionEvidence& input)
{
    ExecutionEvidenceAssessment result;
    bool metadata = false;
    switch (input.Kind)
    {
    case NativeExecutionEvidenceKind::PointerRegistration:
        result.Observation = L"registered_pointer";
        break;
    case NativeExecutionEvidenceKind::ThreadStart:
        result.Observation = L"thread_start_metadata";
        metadata = true;
        break;
    case NativeExecutionEvidenceKind::RawStackValue:
        result.Observation = L"raw_stack_value";
        metadata = true;
        break;
    case NativeExecutionEvidenceKind::QueuedApcRoutine:
        result.Observation = L"queued_apc_routine";
        metadata = true;
        break;
    case NativeExecutionEvidenceKind::ApcArgument:
        result.Observation = L"apc_argument_candidate";
        break;
    case NativeExecutionEvidenceKind::CapturedThreadContext:
        result.Observation = L"captured_thread_context";
        metadata = true;
        break;
    case NativeExecutionEvidenceKind::SavedTrapContext:
        result.Observation = L"saved_trap_context";
        metadata = true;
        break;
    case NativeExecutionEvidenceKind::HardwareBreakpoint:
        result.Observation = L"configured_debug_register";
        break;
    default:
        return result;
    }
    result.ReferenceObserved = input.Address != 0;
    result.IdentityQualified = input.ProcessId > 4 && input.ProcessCreateTime != 0 && input.ProcessIdentityStable;
    result.ThreadIdentityQualified = result.IdentityQualified && input.ThreadId != 0 && input.ThreadCreateTime != 0;
    if (!result.IdentityQualified)
    {
        result.Reason = L"process_identity_unavailable";
        return result;
    }
    if (!result.ReferenceObserved || !input.AddressSpace.UserRange(input.Address, 1) ||
        (input.PointerBytes != 4 && input.PointerBytes != 8) ||
        (input.PointerBytes == 4 && input.Address > UINT32_MAX))
    {
        result.Reason = L"address_or_architecture_unavailable";
        return result;
    }
    if (metadata && input.ThreadId == 0)
    {
        result.Reason = L"thread_metadata_unavailable";
        return result;
    }
    if (input.Kind == NativeExecutionEvidenceKind::CapturedThreadContext &&
        (!result.ThreadIdentityQualified || input.CaptureTime == 0 || input.CaptureTime < input.ThreadCreateTime))
    {
        result.Reason = L"captured_context_identity_or_time_unavailable";
        return result;
    }
    result.Level = metadata ? L"X1" : L"X0";
    result.Reason = metadata ? L"metadata_does_not_establish_execution" : L"reference_does_not_establish_execution";
    return result;
}
