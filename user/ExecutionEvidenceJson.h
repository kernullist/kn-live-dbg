#pragma once

#include "ExecutionEvidence.h"
#include "McpJson.h"

inline std::wstring NativeExecutionEvidenceJson(const NativeExecutionEvidence& input, const std::wstring& source)
{
    const auto assessment = AssessNativeExecutionEvidence(input);
    std::wstring out = L"{\"schema\":\"kn.execution_evidence.v1\",\"policy\":\"native-reference-levels-v1\"";
    out += L",\"source\":" + mcpjson::Quote(source);
    out += L",\"level\":" + mcpjson::Quote(assessment.Level);
    out += L",\"observation\":" + mcpjson::Quote(assessment.Observation);
    out += L",\"reason\":" + mcpjson::Quote(assessment.Reason);
    out += L",\"pid\":" + std::to_wstring(input.ProcessId);
    out += L",\"process_create_time\":" + mcpjson::Quote(std::to_wstring(input.ProcessCreateTime));
    out += L",\"tid\":" + std::to_wstring(input.ThreadId);
    out += L",\"time_format\":\"windows_filetime\"";
    out += L",\"thread_create_time\":" + (input.ThreadCreateTime == 0 ? std::wstring(L"null") :
        mcpjson::Quote(std::to_wstring(input.ThreadCreateTime)));
    out += L",\"context_capture_time\":" + (input.CaptureTime == 0 ? std::wstring(L"null") :
        mcpjson::Quote(std::to_wstring(input.CaptureTime)));
    out += L",\"address\":" + mcpjson::Quote(std::to_wstring(input.Address));
    out += L",\"pointer_bytes\":" + std::to_wstring(input.PointerBytes);
    out += L",\"virtual_address_bits\":" + std::to_wstring(input.AddressSpace.VirtualAddressBits);
    out += L",\"address_format_assumed\":" + std::wstring(input.AddressSpace.LegacyAssumed ? L"true" : L"false");
    out += L",\"process_identity_qualified\":" + std::wstring(assessment.IdentityQualified ? L"true" : L"false");
    out += L",\"thread_identity_qualified\":" + std::wstring(assessment.ThreadIdentityQualified ? L"true" : L"false");
    out += L",\"reference_observed\":" + std::wstring(assessment.ReferenceObserved ? L"true" : L"false");
    out += L",\"execution_observed\":false,\"actor_attributed\":false,\"cpu\":null,\"code_version\":null";
    out += L",\"control_flow_observed\":false,\"write_observed\":false,\"collector_authenticated\":false";
    out += L",\"execution_requirement\":\"separate_cpu_qualified_execution_source\"}";
    return out;
}
