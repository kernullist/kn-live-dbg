#include "../user/RuntimeCapabilities.h"

#include <iostream>

int main(int argc, char** argv)
{
    if (argc == 2 && std::string(argv[1]) == "--unicode-json")
    {
        RuntimeCapabilityProbe probe;
        probe.NativeReason = L"\ud55c\uae00 \U0001f512 \"quoted\"\n";
        return WriteCapabilityJson(RuntimeCapabilityProbeJson(probe)) ? 0 : 2;
    }
    unsigned checked = 0;
    unsigned failed = 0;
    const auto check = [&](bool success, const char* name)
    {
        ++checked;
        if (!success)
        {
            ++failed;
            std::cerr << "FAIL " << name << "\n";
        }
    };
    const auto available = [](const RuntimeCapabilityProbe* p, const wchar_t* backend, const wchar_t* impl = L"implemented")
    {
        return std::wstring(CapabilityAvailability(impl, backend, p));
    };
    ObservationReadResult read;
    read.State = ObservationReadState::Complete;
    read.IdentityRevalidated = true;
    check(CapabilityReadAccepted(read), "identity-qualified completed sample accepted");
    read.OperationDeadlineExceeded = true;
    check(!CapabilityReadAccepted(read), "completed overrun cannot grant sample availability");
    read.OperationDeadlineExceeded = false;
    read.CancellationObserved = true;
    check(!CapabilityReadAccepted(read), "cancelled sample cannot grant availability");
    read.CancellationObserved = false;
    read.IdentityRevalidated = false;
    check(!CapabilityReadAccepted(read), "sample requires identity qualification");
    read.IdentityRevalidated = true;
    read.State = ObservationReadState::Partial;
    check(!CapabilityReadAccepted(read), "partial sample is not accepted as complete");
    check(available(nullptr, L"native") == L"not_probed", "compiled native stays unprobed");
    check(available(nullptr, L"vmi", L"unsupported") == L"not_probed", "legacy compiled availability unchanged");
    RuntimeCapabilityProbe probe;
    check(available(&probe, L"native") == L"unavailable", "failed open");
    probe.NativeSourceOpened = true;
    check(available(&probe, L"native") == L"unavailable", "open is not ABI validation");
    probe.NativeContractPassed = true;
    check(available(&probe, L"native") == L"unavailable", "ABI is not session validation");
    probe.NativeSessionPassed = true;
    check(available(&probe, L"native") == L"partial", "connection is not scanner support");
    check(available(&probe, L"native", L"experimental") == L"partial", "connection does not qualify experimental interposition");
    check(available(&probe, L"native", L"unsupported") == L"unsupported", "native connection cannot enable VTL1");
    check(available(&probe, L"dump") == L"not_probed", "native connection cannot qualify dumps");
    check(available(&probe, L"process_handle") == L"unavailable", "separate process source required");
    probe.ProcessSourceOpened = true;
    check(available(&probe, L"process_handle") == L"unavailable", "process handle is not a sample");
    probe.ProcessReadPassed = true;
    check(available(&probe, L"process_handle") == L"unavailable", "read completion needs expected control bytes");
    probe.ProcessBytesMatched = true;
    check(available(&probe, L"process_handle") == L"available", "owned sample contract available");
    probe.ProcessSourceOpened = false;
    check(available(&probe, L"process_handle") == L"unavailable", "orphan sample cannot grant availability");
    check(available(&probe, L"vmi", L"unsupported") == L"unsupported", "sample cannot enable VMI");
    const auto stages = CapabilityProbeStagesJson(L"native", &probe);
    check(stages.find(L"\"sample_read\":\"not_probed\"") != std::wstring::npos, "native no sample recorded");
    check(stages.find(L"\"layout_qualified\":\"not_probed\"") != std::wstring::npos, "native no layout recorded");
    check(stages.find(L"\"environment_regression\":\"not_performed\"") != std::wstring::npos, "probe is not environment regression");
    probe.NativeReason = L"quote\" newline\n";
    const auto json = RuntimeCapabilityProbeJson(probe);
    check(json.find(L"quote\\\" newline\\n") != std::wstring::npos, "status explanation escaped");
    check(json.find(L"\"native_raw_status_available\":false") != std::wstring::npos, "wrapper errors not invented NTSTATUS");
    check(std::wstring(CapabilityAddressContract(L"process", L"cross_view", L"native")).find(L"selected_paths_only") != std::wstring::npos,
        "descriptor support scoped to migrated paths");
    check(std::wstring(CapabilityAddressContract(L"execution", L"classify_reference", L"native")).find(L"unvalidated") != std::wstring::npos,
        "legacy collectors do not inherit descriptor support");
    check(std::wstring(CapabilityAddressContract(L"image", L"capture_verification", L"process_handle")).find(L"cli_legacy_la48") != std::wstring::npos,
        "live image CLI does not pretend it queried the target paging mode");
    std::cout << "runtime capability policy controls: " << checked << " passed=" << checked - failed << " failed=" << failed << "\n";
    return failed == 0 ? 0 : 1;
}
