#include "CrashDumpDiagnosis.h"
#include "WheaRecord.h"
#include "WheaEvent.h"
#include "RebootEvent.h"
#include "RuntimeCapabilities.h"
#include "ArtifactOutput.h"

#include <DbgEng.h>
#include <DbgHelp.h>
#include <mindumpdef.h>
#include <wrl/client.h>

#include <array>
#include <iostream>
#include <optional>

namespace
{
    using Microsoft::WRL::ComPtr;
    using mcpjson::Quote;
    constexpr uint64_t MaxDumpBytes = 16ull << 30;
    constexpr ULONG MaxFrames = 32;
    std::wstring Prefix(unsigned version)
    {
        return L"{\"schema\":\"kn.crash_diagnosis.v" + std::to_wstring(version) + L"\",\"status\":";
    }

    std::wstring Hex(uint64_t value)
    {
        wchar_t buffer[24]{};
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return Quote(buffer);
    }

    const wchar_t* Bool(bool value) { return value ? L"true" : L"false"; }

    struct Engine
    {
        std::wstring calls, type = L"null", execution = L"null", selected = L"null", frames = L"null";
        std::optional<SavedCrashStop> stop;
        std::optional<bool> sameContext;
        bool initialStop = false;
        bool atLimit = false;
        bool topInModule = false;
        std::optional<bool> topMatches;

        bool Call(const wchar_t* name, HRESULT hr)
        {
            if (!calls.empty()) { calls += L","; }
            calls += Quote(name) + L":" + Hex(static_cast<ULONG>(hr));
            return hr == S_OK;
        }
    };

    std::wstring EngineVersion()
    {
        const auto dll = GetModuleHandleW(L"dbgeng.dll");
        const auto resource = dll ? FindResourceW(dll, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION) : nullptr;
        const auto loaded = resource ? LoadResource(dll, resource) : nullptr;
        const auto bytes = loaded ? LockResource(loaded) : nullptr;
        VS_FIXEDFILEINFO* info = nullptr;
        UINT size = 0;
        if (!bytes || !VerQueryValueW(bytes, L"\\", reinterpret_cast<void**>(&info), &size) ||
            size < sizeof(*info) || info->dwSignature != VS_FFI_SIGNATURE) { return L"null"; }
        return Quote(std::to_wstring(HIWORD(info->dwFileVersionMS)) + L"." + std::to_wstring(LOWORD(info->dwFileVersionMS)) +
            L"." + std::to_wstring(HIWORD(info->dwFileVersionLS)) + L"." + std::to_wstring(LOWORD(info->dwFileVersionLS)));
    }

    std::wstring Module(IDebugSymbols3& symbols, ULONG64 ip, bool& contained)
    {
        ULONG index = 0;
        ULONG64 base = 0;
        const HRESULT lookup = symbols.GetModuleByOffset(ip, 0, &index, &base);
        std::wstring result = L"{\"lookup_hr\":" + Hex(static_cast<ULONG>(lookup));
        if (lookup != S_OK) { return result + L",\"range\":null}"; }
        DEBUG_MODULE_PARAMETERS m{};
        const HRESULT query = symbols.GetModuleParameters(1, &base, 0, &m);
        result += L",\"parameters_hr\":" + Hex(static_cast<ULONG>(query));
        contained = query == S_OK && m.Base == base && !(m.Flags & DEBUG_MODULE_UNLOADED) &&
            ip >= base && ip - base < m.Size;
        if (!contained) { return result + L",\"range\":null}"; }
        wchar_t name[260]{};
        ULONG used = 0;
        const HRESULT named = symbols.GetModuleNameStringWide(DEBUG_MODNAME_MODULE, index, base, name,
            static_cast<ULONG>(std::size(name)), &used);
        const bool fullName = named == S_OK && used && used <= std::size(name) && name[used - 1] == L'\0';
        return result + L",\"name_hr\":" + Hex(static_cast<ULONG>(named)) + L",\"range\":{\"index\":" +
            std::to_wstring(index) + L",\"base\":" + Hex(base) + L",\"size\":" + std::to_wstring(m.Size) +
            L",\"name\":" + (fullName ? Quote(std::wstring(name, used - 1)) : L"null") + L"}}";
    }

    void ReadStack(IDebugControl& control, IDebugSymbols3& symbols, const CONTEXT& header, Engine& e)
    {
        std::array<DEBUG_STACK_FRAME, MaxFrames> frames{};
        ULONG used = 0;
        if (!e.Call(L"stack", control.GetStackTrace(0, 0, 0, frames.data(), MaxFrames, &used)) || used > MaxFrames) { return; }
        e.atLimit = used == MaxFrames;
        e.frames = L"[";
        for (ULONG i = 0; i < used; ++i)
        {
            const auto& f = frames[i];
            bool contained = false;
            auto module = Module(symbols, f.InstructionOffset, contained);
            if (i == 0)
            {
                e.topInModule = contained;
                if ((header.ContextFlags & 0x00ff0001u) == CONTEXT_CONTROL && header.Rip && header.Rsp &&
                    f.InstructionOffset && f.StackOffset)
                { e.topMatches = f.InstructionOffset == header.Rip && f.StackOffset == header.Rsp; }
            }
            if (i) { e.frames += L","; }
            e.frames += L"{\"ip\":" + Hex(f.InstructionOffset) + L",\"sp\":" + Hex(f.StackOffset) +
                L",\"return\":" + Hex(f.ReturnOffset) + L",\"virtual\":" + Bool(f.Virtual != FALSE) +
                L",\"module\":" + module + L"}";
        }
        e.frames += L"]";
    }

    void Inspect(HANDLE file, const CONTEXT& headerContext, bool hasContext, Engine& e,
        const SavedCrashStop& headerStop, bool ordinaryDump, WheaRecord* record, SavedCrashClock* clock)
    {
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        e.Call(L"com_initialize", initialized);
        if (FAILED(initialized)) { return; }
        struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
        ComPtr<IDebugClient4> client;
        ComPtr<IDebugControl> control;
        ComPtr<IDebugSymbols3> symbols;
        if (!e.Call(L"create", DebugCreate(__uuidof(IDebugClient4), reinterpret_cast<void**>(client.GetAddressOf()))) ||
            !e.Call(L"control", client.As(&control)) || !e.Call(L"symbols", client.As(&symbols))) { return; }

        constexpr ULONG policy = DEBUG_ENGOPT_DISALLOW_NETWORK_PATHS | DEBUG_ENGOPT_DISALLOW_SHELL_COMMANDS |
            DEBUG_ENGOPT_DISABLE_EXECUTION_COMMANDS | DEBUG_ENGOPT_DISABLE_MODULE_SYMBOL_LOAD |
            DEBUG_ENGOPT_DISALLOW_IMAGE_FILE_MAPPING | DEBUG_ENGOPT_DISABLE_MANAGED_SUPPORT | DEBUG_ENGOPT_DISABLESQM;
        constexpr ULONG symbolPolicy = SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_NO_PROMPTS |
            SYMOPT_DISABLE_SYMSRV_AUTODETECT | SYMOPT_DISABLE_SRVSTAR_ON_STARTUP;
        // With ambient symbol paths ignored, an empty initial search path can make
        // WaitForEvent reject a valid small dump. Bind both paths to a local OS directory.
        wchar_t system[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
        std::filesystem::path local;
        if (!length || length >= std::size(system) || !symbol_artifacts::LocalRoot(system, &local)) { return; }
        if (!e.Call(L"engine_policy", control->SetEngineOptions(policy)) ||
            !e.Call(L"symbol_policy", symbols->AddSymbolOptions(symbolPolicy)) ||
            !e.Call(L"symbol_path", symbols->SetSymbolPathWide(local.c_str())) ||
            !e.Call(L"image_path", symbols->SetImagePathWide(local.c_str()))) { return; }
        // DbgEng closes its input during teardown. Give it a dedicated open of the
        // same object; the original file and its digest remain available for the final check.
        HANDLE input = approved_file::Open(file, approved_file::Access::Reopen);
        if (input == INVALID_HANDLE_VALUE) { e.Call(L"reopen_input", HRESULT_FROM_WIN32(GetLastError())); return; }
        e.Call(L"reopen_input", S_OK);
        // Once handed off, even a rejected input may have been closed by the engine.
        // EndSession and this one-shot process own any remaining debugger input lifetime.
        const bool opened = e.Call(L"open_handle", client->OpenDumpFileWide(nullptr, reinterpret_cast<ULONG64>(input)));
        if (!opened) { e.Call(L"end_session", client->EndSession(DEBUG_END_PASSIVE)); return; }

        const bool event = e.Call(L"wait_event", control->WaitForEvent(0, 5000));
        ULONG kind = 0, qualifier = 0;
        if (e.Call(L"debuggee_type", control->GetDebuggeeType(&kind, &qualifier)))
        {
            e.type = L"{\"class\":" + std::to_wstring(kind) + L",\"qualifier\":" + std::to_wstring(qualifier) + L"}";
            if (kind == DEBUG_CLASS_KERNEL && (qualifier == DEBUG_KERNEL_SMALL_DUMP || qualifier == DEBUG_KERNEL_DUMP ||
                qualifier == DEBUG_KERNEL_FULL_DUMP || qualifier == DEBUG_KERNEL_ACTIVE_DUMP))
            {
                // An incomplete dump may still expose its stored tuple even when the initial stop is unavailable.
                SavedCrashStop s;
                if (e.Call(L"bugcheck", control->ReadBugCheckData(&s.code, &s.args[0], &s.args[1], &s.args[2], &s.args[3])))
                { e.stop = s; }
                ULONG status = 0;
                const bool state = e.Call(L"execution_status", control->GetExecutionStatus(&status));
                if (state) { e.execution = std::to_wstring(status); }
                e.initialStop = event && state && status == DEBUG_STATUS_BREAK;
                if (record && e.stop)
                {
                    if (!(*e.stop == headerStop)) { record->status = L"conflicting_stop_data"; }
                    else if (headerStop.code != 0x124) { record->status = L"different_stop_code"; }
                    else if (!ordinaryDump) { record->status = L"unqualified_dump_attributes"; }
                    else if (!e.initialStop) { record->status = L"initial_stop_unavailable"; }
                    else
                    {
                        InspectStopWheaRecord(*client.Get(), headerStop.args[0], headerStop.args[1],
                            headerStop.args[2], headerStop.args[3], *record);
                    }
                }
                if (e.initialStop)
                {
                    if (clock)
                    {
                        ComPtr<IDebugControl2> control2;
                        if (e.Call(L"clock_interface", client.As(&control2)))
                        {
                            ULONG seconds = 0;
                            if (e.Call(L"dump_time", control2->GetCurrentTimeDate(&seconds))) { clock->debuggerUnixSeconds = seconds; }
                            if (e.Call(L"dump_uptime", control2->GetCurrentSystemUpTime(&seconds))) { clock->debuggerUptimeSeconds = seconds; }
                        }
                    }
                    ComPtr<IDebugRegisters> registers;
                    ULONG64 ip = 0, sp = 0;
                    if (e.Call(L"registers", client.As(&registers)))
                    {
                        const bool gotIp = e.Call(L"instruction_offset", registers->GetInstructionOffset(&ip));
                        const bool gotSp = e.Call(L"stack_offset", registers->GetStackOffset(&sp));
                        e.selected = L"{\"ip\":" + (gotIp ? Hex(ip) : L"null") + L",\"sp\":" + (gotSp ? Hex(sp) : L"null") + L"}";
                        if (hasContext)
                        {
                            e.sameContext = CompareSavedCrashContext(headerContext.Rip, headerContext.Rsp,
                                gotIp ? std::optional{ip} : std::nullopt, gotSp ? std::optional{sp} : std::nullopt);
                        }
                    }
                    ReadStack(*control.Get(), *symbols.Get(), headerContext, e);
                }
            }
        }
        e.Call(L"end_session", client->EndSession(DEBUG_END_PASSIVE));
    }

    int Failure(unsigned version, const wchar_t* status)
    {
        return WriteCapabilityJson(Prefix(version) + Quote(status) + L",\"attributed_cause\":null}") ? 1 : 2;
    }

    bool IsDigest(const std::wstring& text)
    {
        return text.size() == 64 && text.find_first_not_of(L"0123456789abcdefABCDEF") == std::wstring::npos;
    }

    std::wstring LowerDigest(std::wstring digest)
    {
        std::transform(digest.begin(), digest.end(), digest.begin(), [](wchar_t c) {
            return c >= L'A' && c <= L'F' ? static_cast<wchar_t>(c + L'a' - L'A') : c; });
        return digest;
    }

    struct Options
    {
        bool whea = false, wheaEvent = false, compareTime = false, bootWindow = false;
        size_t rebootArg = 0;
        uint64_t recordId = 0, firstClockRecord = 0;
    };

    bool ReadOptions(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 3 || args[1] != L"--sha256" || !IsDigest(args[2])) { return false; }
        size_t i = 3;
        if (i < args.size() && args[i] == L"--whea")
        {
            options.whea = true;
            ++i;
            if (i < args.size() && args[i] == L"--event-xml")
            {
                if (args.size() - i < 4 || args[i + 2] != L"--event-sha256" || !IsDigest(args[i + 3])) { return false; }
                options.wheaEvent = true;
                i += 4;
            }
        }
        if (i == args.size()) { return true; }
        if (args.size() - i < 6 || args[i] != L"--reboot-log" || args[i + 2] != L"--log-sha256" ||
            !IsDigest(args[i + 3]) || args[i + 4] != L"--record-id" || !ParseEventRecordId(args[i + 5], options.recordId)) { return false; }
        options.rebootArg = i;
        i += 6;
        if (i == args.size()) { return true; }
        if (args[i++] != L"--compare-time") { return false; }
        options.compareTime = true;
        if (i == args.size()) { return true; }
        if (args.size() - i < 2 || args[i] != L"--clock-history-from" || !ParseEventRecordId(args[i + 1], options.firstClockRecord) ||
            !RebootClockHistory::ValidWindow(options.firstClockRecord, options.recordId)) { return false; }
        i += 2;
        if (i == args.size()) { return true; }
        options.bootWindow = args.size() - i == 1 && args[i] == L"--boot-window";
        return options.bootWindow;
    }
}

std::wstring SavedCrashStop::Json() const
{
    return L"{\"code\":" + Hex(code) + L",\"parameters\":[" + Hex(args[0]) + L"," + Hex(args[1]) +
        L"," + Hex(args[2]) + L"," + Hex(args[3]) + L"]}";
}

static int Diagnose(const std::vector<std::wstring>& args, const Options& options)
{
    const unsigned version = options.bootWindow ? 6 : options.firstClockRecord ? 5 : options.compareTime ? 4 : options.rebootArg ? 3 : options.whea ? 2 : 1;
    const auto expected = LowerDigest(args[2]);
    std::filesystem::path path;
    symbol_artifacts::Directories parents;
    SchemaArtifact source;
    if (!symbol_artifacts::LocalRoot(args[0], &path) || !parents.Pin(path.parent_path(), false) ||
        !source.Open(path.wstring(), MaxDumpBytes))
    {
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[0], [version] { return Failure(version, L"source_unavailable"); });
    }
    if (source.Sha256 != expected) { return Failure(version, L"digest_mismatch"); }
    DUMP_HEADER64 h{};
    DWORD got = 0;
    if (!approved_file::ReadAt(source.Handle(), 0, &h, sizeof(h), &got) || got != sizeof(h) ||
        h.Signature != DUMP_SIGNATURE64 || h.ValidDump != DUMP_VALID_DUMP64 ||
        h.MachineImageType != IMAGE_FILE_MACHINE_AMD64) { return Failure(version, L"unsupported_header"); }

    SavedCrashStop stop{h.BugCheckCode, {h.BugCheckParameter1, h.BugCheckParameter2, h.BugCheckParameter3, h.BugCheckParameter4}};
    CONTEXT context{};
    static_assert(sizeof(context) <= sizeof(h.ContextRecord));
    std::memcpy(&context, h.ContextRecord, sizeof(context));
    const bool hasContext = (context.ContextFlags & 0x00ff0001u) == CONTEXT_CONTROL && context.Rip && context.Rsp;
    const bool knownAttributes = (h.Attributes.Attributes & ~0x3ffu) == 0;
    Engine e;
    const bool ordinaryDump = knownAttributes && !h.Attributes.LiveDumpGeneratedDump && !h.Attributes.DumpIsGeneratedOffline;
    WheaRecord record;
    SavedCrashClock clock{h.SystemTime.QuadPart, h.SystemUpTime.QuadPart};
    Inspect(source.Handle(), context, hasContext, e, stop, ordinaryDump, options.whea ? &record : nullptr,
        options.compareTime ? &clock : nullptr);
    const auto event = options.wheaEvent ? CompareSavedWheaEvent(args[5], LowerDigest(args[7]), record) : WheaEventComparison{};
    const bool match = e.stop && *e.stop == stop;
    const bool stopEvidence = e.initialStop && ordinaryDump;
    std::optional<RebootEventComparison> reboot;
    std::optional<RebootTimeline> timeline;
    std::optional<RebootClockHistory> history;
    std::optional<RebootBootAssessment> boots;
    if (options.rebootArg)
    {
        const auto i = options.rebootArg;
        if (options.firstClockRecord) { history = RebootClockHistory{options.firstClockRecord, options.recordId}; }
        if (options.bootWindow) { history->boots.emplace(); }
        reboot = CompareSavedRebootEvent(args[i + 1], LowerDigest(args[i + 3]), options.recordId,
            match && stopEvidence && stop.code ? &stop : nullptr, options.compareTime, history ? &*history : nullptr);
        if (options.compareTime) { timeline = CompareRebootTime(clock, *reboot); }
        if (options.bootWindow) { boots = CompareRebootBootWindow(*history, *timeline, *reboot); }
    }
    if (!source.Unchanged()) { return Failure(version, L"source_changed_or_unreadable"); }
    const auto status = !e.stop ? L"header_only" : !match ? L"conflicting_stop_data" : L"matched_stop_data";
    std::wstring report = Prefix(version) + Quote(status) + L",\"dump_sha256\":" + Quote(source.Sha256) +
        L",\"bytes\":" + std::to_wstring(source.Bytes()) + L",\"source_authenticated\":false,\"header\":{\"machine\":" + Hex(h.MachineImageType) + L",\"type\":" + std::to_wstring(h.DumpType) +
        L",\"bugcheck\":" + stop.Json() + L",\"attribute_bits\":" + Hex(h.Attributes.Attributes) +
        L",\"live_dump\":" + (knownAttributes ? Bool(h.Attributes.LiveDumpGeneratedDump != 0) : L"null") +
        L",\"offline_generated\":" + (knownAttributes ? Bool(h.Attributes.DumpIsGeneratedOffline != 0) : L"null") +
        L",\"context_flags\":" + Hex(context.ContextFlags) +
        L",\"control_context\":" + (hasContext ? (L"{\"ip\":" + Hex(context.Rip) + L",\"sp\":" + Hex(context.Rsp) + L"}") : L"null") +
        L"},\"dbgeng\":{\"file_version\":" + EngineVersion() + L",\"calls\":{" + e.calls +
        L"},\"initial_stop\":" + Bool(e.initialStop) + L",\"target\":" + e.type + L",\"execution_status\":" + e.execution + L",\"bugcheck\":" +
        (e.stop ? e.stop->Json() : L"null") + L",\"selected_context\":" + e.selected +
        L",\"frames\":" + e.frames + L",\"frame_limit_reached\":" + Bool(e.atLimit) + L"}";
    if (options.whea) { report += L",\"whea_record\":" + record.Json(); }
    if (options.wheaEvent) { report += L",\"whea_event\":" + event.report; }
    if (reboot) { report += L",\"reboot_event\":" + reboot->Json(); }
    if (timeline) { report += L",\"reboot_timeline\":" + timeline->report; }
    if (history) { report += L",\"clock_history\":" + history->Json(); }
    if (boots) { report += L",\"boot_window\":" + boots->report; }
    report += L",\"assessment\":{\"header_context_matches_selected\":" +
        std::wstring(e.sameContext ? Bool(*e.sameContext) : L"null") +
        L",\"header_context_matches_stack_top\":" + (e.topMatches ? Bool(*e.topMatches) : L"null") +
        L",\"unwind_quality\":\"unverified\",\"host_crash_verified\":false,\"attributed_cause\":null,\"hypotheses\":[";
    const bool whea = match && stop.code == 0x124;
    const bool located = match && stop.code && e.sameContext.value_or(true) && e.topInModule && e.topMatches.value_or(false);
    report += L"{\"candidate\":\"whea_reported_condition\",\"state\":" +
        Quote(whea ? (stopEvidence ? L"supported_by_stop_tuple" : L"code_recorded_only") :
            (match && stop.code ? L"different_stop_code" : L"unresolved")) +
        L",\"support\":" + (whea ? L"[\"/header/bugcheck\",\"/dbgeng/bugcheck\"]" : L"[]") +
        L",\"contrary\":" + (match && stop.code && !whea ? L"[\"/header/bugcheck\",\"/dbgeng/bugcheck\"]" : L"[]") +
        L",\"next\":" + Quote(options.whea && record.status == L"linked" ? L"inspect_the_linked_whea_sections" :
            L"inspect_the_corresponding_whea_error_record") + L"},";
    if (options.whea) { report += record.Hypothesis() + L","; }
    if (options.wheaEvent) { report += event.Hypothesis() + L","; }
    if (reboot) { report += reboot->Hypothesis(timeline ? &*timeline : nullptr, boots ? &*boots : nullptr) + L","; }
    if (history) { report += history->Hypothesis() + L","; }
    report += L"{\"candidate\":\"component_present_at_stop\",\"state\":" +
        Quote(located ? L"mapped_frame_observed" : L"unresolved") +
        L",\"support\":" + (located ?
            L"[\"/header/control_context\",\"/dbgeng/frames/0\"]" : L"[]") +
        L",\"contrary\":" + (e.sameContext && !*e.sameContext ? L"[\"/header/control_context\",\"/dbgeng/selected_context\"]" :
            (e.topMatches && !*e.topMatches ? L"[\"/header/control_context\",\"/dbgeng/frames/0\"]" : L"[]")) +
        L",\"next\":\"verify_unwind_and_inspect_the_fault_context\"},";
    report += L"{\"candidate\":\"earlier_corruption\",\"state\":\"unresolved\",\"support\":[],\"contrary\":[],"
        L"\"next\":\"compare_prior_object_and_allocation_history\"}]}}";
    return WriteCapabilityJson(report) ? (match ? 0 : 1) : 2;
}

int RunCrashDumpDiagnosis(const std::vector<std::wstring>& args)
{
    Options options;
    const auto inputOption = [](const std::wstring& arg) { return arg == L"--event-xml" || arg == L"--reboot-log"; };
    if (!ReadOptions(args, options))
    {
        auto usage = [&] {
            return WriteWithDistinctInput(STD_ERROR_HANDLE, args.empty() ? L"" : args.front(), [] {
                std::wcerr << L"usage: KnLiveDbg.exe --crash-diagnose <local-kernel-dump> --sha256 <digest> "
                    L"[--whea [--event-xml <file> --event-sha256 <digest>]] "
                    L"[--reboot-log <local.evtx> --log-sha256 <digest> --record-id <decimal> [--compare-time [--clock-history-from <first-record-id> [--boot-window]]]]\n";
                return 2;
            });
        };
        if (GetFileType(GetStdHandle(STD_ERROR_HANDLE)) == FILE_TYPE_DISK &&
            (std::count(args.begin(), args.end(), L"--event-xml") > 1 || std::count(args.begin(), args.end(), L"--reboot-log") > 1))
        { return 2; }
        return WriteWithDistinctSelectedInputs(STD_ERROR_HANDLE, args, inputOption, usage);
    }
    const HANDLE sink = GetStdHandle(STD_OUTPUT_HANDLE);
    DistinctArtifactInput xmlInput, logInput;
    if (GetFileType(sink) == FILE_TYPE_DISK)
    {
        if (options.wheaEvent && !xmlInput.Hold(sink, args[5])) { return 2; }
        if (options.rebootArg && !logInput.Hold(sink, args[options.rebootArg + 1])) { return 2; }
    }
    return Diagnose(args, options);
}
