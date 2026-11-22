#include "../user/SourceCapabilities.h"

#include <iostream>
#include <sddl.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// The fixture applies its DACL only to the newly created controller process.
// The parent reads its identity through the process-creation handle.
static bool RunDeniedSelfProbe(const wchar_t* executable)
{
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --mode observe --capabilities --probe --allow-residency";
    STARTUPINFOEXW startup{};
    auto& io = startup.StartupInfo;
    io.cb = sizeof(startup);
    io.dwFlags = STARTF_USESTDHANDLES;
    io.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    io.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    io.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE inherited[] = {io.hStdInput, io.hStdOutput, io.hStdError};
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    if (!bytes) { return false; }
    std::vector<BYTE> attributes(bytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes)) { return false; }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PROCESS_INFORMATION child{};
    bool launched = false;
    if (UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) &&
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(D;;0x10;;;WD)(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, nullptr))
    {
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        launched = CreateProcessW(executable, command.data(), &security, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &io, &child) != FALSE;
        LocalFree(descriptor);
    }
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!launched) { return false; }
    DWORD wait = WaitForSingleObject(child.hProcess, 30000);
    if (wait != WAIT_OBJECT_0)
    {
        TerminateProcess(child.hProcess, 2);
        WaitForSingleObject(child.hProcess, 5000);
    }
    DWORD exitCode = 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    bool observed = GetExitCodeProcess(child.hProcess, &exitCode) && GetProcessTimes(child.hProcess, &created, &exited, &kernel, &user);
    bool threadClosed = CloseHandle(child.hThread) != FALSE;
    bool processClosed = CloseHandle(child.hProcess) != FALSE;
    if (!observed || wait != WAIT_OBJECT_0 || !threadClosed || !processClosed) { return false; }
    std::cerr << "child pid=" << child.dwProcessId << " created=" << ((uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime)
              << " exit=" << exitCode << "\n";
    return exitCode == 1;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring(argv[1]) == L"--deny-self-probe") { return RunDeniedSelfProbe(argv[2]) ? 0 : 2; }
    if (argc == 2 && std::wstring(argv[1]) == L"--native-connection-json")
    {
        RuntimeCapabilityProbe connected;
        connected.NativeProbeAttempted = true;
        connected.NativeSourceOpened = true;
        connected.NativeContractPassed = true;
        connected.NativeSessionPassed = true;
        return WriteCapabilityJson(SourceCapabilitiesJson(L"fixture", &connected)) ? 0 : 2;
    }
    if (argc == 2 && std::wstring(argv[1]) == L"--unicode-json")
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
    SavedEtlCapabilityProbe etl;
    check(std::wstring(etl.Availability(L"cpu_profile")) == L"unavailable" && etl.RecordsJson(L"cpu_profile") == L"null",
        "failed file probe has no record counts");
    auto& coverage = etl.Coverage.emplace();
    coverage.Accounting = etl_profile::BufferAccounting::Matched;
    coverage.Profile.Count(etl_profile::Match::Other, 1);
    coverage.Profile.Count(etl_profile::Match::Unsupported, 2);
    check(etl.StagesJson(L"cpu_profile").find(L"\"layout_qualified\":\"failed\"") != std::wstring::npos &&
        etl.RecordsJson(L"cpu_profile").find(L"unsupported_layout_only") != std::wstring::npos,
        "unsupported layout kept apart from absent family");
    coverage.Profile.Count(etl_profile::Match::Decoded, 3);
    coverage.Profile.Count(etl_profile::Match::Decoded, 6);
    check(coverage.Profile.FirstDecodedRecord == 3 && coverage.Profile.Decoded == 2 && coverage.Profile.Unsupported == 1 &&
        std::wstring(etl.Availability(L"cpu_profile")) == L"partial" &&
        etl.StagesJson(L"cpu_profile").find(L"\"layout_qualified\":\"partial\"") != std::wstring::npos,
        "mixed record layouts retain first witness and partial qualification");
    coverage.Switches.Count(etl_profile::Match::Decoded, 7);
    check(std::wstring(etl.Availability(L"context_switch")) == L"available" && !etl.Records(L"other"),
        "CPU layouts do not downgrade a decoded switch");
    for (auto* field : { &coverage.EventsLost, &coverage.BuffersLost, &coverage.LossMarkers })
    {
        *field = 1;
        check(std::wstring(etl.Availability(L"context_switch")) == L"partial", "recorded loss limits the file claim");
        *field = 0;
    }
    for (const auto accounting : { etl_profile::BufferAccounting::Unavailable, etl_profile::BufferAccounting::Fewer,
                                   etl_profile::BufferAccounting::More })
    {
        coverage.Accounting = accounting;
        check(std::wstring(etl.Availability(L"context_switch")) == L"partial", "unqualified buffer totals limit both families");
    }
    check(!etl.Covers(L"execution", L"cpu_profile", L"other") && !etl.Covers(L"other", L"cpu_profile", L"etl") &&
        !etl.Covers(L"execution", L"other", L"etl"), "saved probe cannot qualify neighboring contracts");

    RuntimeCapabilityProbe probe;
    check(available(&probe, L"native") == L"blocked_by_policy", "unsolicited native probe cannot grant availability");
    probe.NativeProbeAttempted = true;
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
    const auto reports = [&](const std::wstring& field) { return RuntimeCapabilityProbeJson(probe).find(field) != std::wstring::npos; };
    check(reports(L"\"native_close_succeeded\":null") && reports(L"\"probe_handles_closed\":false"), "opened device needs a close result");
    probe.NativeCloseAttempted = true;
    probe.NativeCloseError = ERROR_ACCESS_DENIED;
    check(reports(L"\"native_close_win32_status\":5") && reports(L"\"native_close_succeeded\":false") &&
        reports(L"\"probe_handles_closed\":false"), "failed device close preserved");
    probe.NativeCloseSucceeded = true;
    probe.NativeCloseError = ERROR_SUCCESS;
    probe.ProcessHandlesAcquired = 2;
    probe.ProcessHandlesClosed = 1;
    check(reports(L"\"probe_handles_closed\":false"), "unmatched process reference prevents closure claim");
    probe.ProcessHandlesClosed = 2;
    check(reports(L"\"native_close_win32_status\":0") && reports(L"\"probe_handles_closed\":true"), "all acquired references have successful closes");
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
