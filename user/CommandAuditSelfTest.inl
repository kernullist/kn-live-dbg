// Included after the command dispatcher to exercise the real entry points.
static int RunCommandAuditSelfTest()
{
    uint32_t passed = 0;
    uint32_t failed = 0;
    auto check = [&](bool condition, const std::wstring& name)
    {
        if (condition)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::wcerr << L"[commands.selftest] FAIL " << name << L"\n";
        }
    };
    DebuggerState state = {};
    state.NumberBase = 16;
    state.Backend = DebuggerState::BackendMode::DbgEng;
    DeviceClient device;
    DriverService service(L"KnLiveDbgCommandAuditUnused", L"KnLiveDbg command audit");
    SymbolEngine symbols;
    DbgEngBackend dbgeng;
    AiProviderRuntime ai;
    AiPlanState aiState = {};
    auto run = [&](const std::wstring& line)
    {
        std::wostringstream sink;
        std::wstreambuf* oldOut = std::wcout.rdbuf(sink.rdbuf());
        std::wstreambuf* oldErr = std::wcerr.rdbuf(sink.rdbuf());
        CommandExecutionResult result = ExecuteCommandWithTranscript(
            Split(line), line, L"selftest", state, dbgeng, device, service, symbols, ai, aiState, false);
        std::wcout.rdbuf(oldOut);
        std::wcerr.rdbuf(oldErr);
        return result;
    };

    // Exercise the API boundary as well as the documented bit meanings. A
    // failed/short query may leave plausible bytes behind; they are not evidence.
    {
        static ULONG mask = 0;
        static ULONG replyLength = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
        static ULONG structureLength = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
        static NTSTATUS replyStatus = 0;
        static bool contractOk = false;
        const codeintegrity::QueryFunction query = [](SYSTEM_INFORMATION_CLASS kind,
            PVOID buffer, ULONG size, PULONG returned) -> NTSTATUS
        {
            auto* information = static_cast<SYSTEM_CODEINTEGRITY_INFORMATION*>(buffer);
            contractOk = static_cast<int>(kind) == 103 && size == sizeof(*information) &&
                information->Length == sizeof(*information) && information->CodeIntegrityOptions == 0;
            information->Length = structureLength;
            information->CodeIntegrityOptions = mask;
            *returned = replyLength;
            return replyStatus;
        };
        // Order follows Microsoft's SYSTEM_CODEINTEGRITY_INFORMATION table.
        bool codeintegrity::State::* const flags[] = {
            &codeintegrity::State::CodeIntegrityEnabled, &codeintegrity::State::TestSign,
            &codeintegrity::State::UmciEnabled, &codeintegrity::State::UmciAuditMode,
            &codeintegrity::State::UmciExclusionPaths, &codeintegrity::State::TestBuild,
            &codeintegrity::State::PreproductionBuild, &codeintegrity::State::DebugMode,
            &codeintegrity::State::FlightBuild, &codeintegrity::State::FlightingEnabled,
            &codeintegrity::State::HvciEnabled, &codeintegrity::State::HvciAuditMode,
            &codeintegrity::State::HvciStrictMode, &codeintegrity::State::HvciIumEnabled
        };
        for (unsigned bit = 0; bit != 32; ++bit)
        {
            mask = ULONG(1) << bit;
            const auto observed = codeintegrity::Query(query);
            check(contractOk && observed.Resolved && observed.Raw == mask,
                L"CI query contract and raw bit " + std::to_wstring(bit));
            for (unsigned field = 0; field != _countof(flags); ++field)
            {
                check(observed.*flags[field] == (bit == field),
                    L"CI flag isolation " + std::to_wstring(bit) + L"/" + std::to_wstring(field));
            }
            check(observed.UnknownOptions == (bit >= 14 ? mask : 0), L"CI unknown bits retained");
        }
        mask = 0;
        const auto disabled = codeintegrity::Query(query);
        check(disabled.Resolved && !disabled.HvciEnabled && disabled.Raw == 0, L"CI known disabled state");
        mask = 0xffffffffu;
        const auto combined = codeintegrity::Query(query);
        for (const auto field : flags)
        {
            check(combined.*field, L"CI combined independent flags");
        }
        check(combined.UnknownOptions == 0xffffc000u, L"CI combined unknown options");
        const auto rejects = [&](const codeintegrity::State& observed, const wchar_t* name)
        {
            check(!observed.Resolved && observed.Raw == 0 && observed.UnknownOptions == 0 &&
                !observed.CodeIntegrityEnabled && !observed.HvciEnabled, name);
        };
        rejects(codeintegrity::Query(nullptr), L"CI missing API");
        replyStatus = static_cast<NTSTATUS>(0xc0000022u);
        const auto denied = codeintegrity::Query(query);
        rejects(denied, L"CI access denied with populated output");
        check(denied.NtStatus == 0xc0000022u && denied.QueryAvailable, L"CI failure diagnostics");
        replyStatus = 0;
        for (const ULONG length : {0ul, 4ul, 7ul, 9ul, 16ul})
        {
            replyLength = length;
            rejects(codeintegrity::Query(query), L"CI unexpected returned length");
        }
        replyLength = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
        structureLength = 0;
        rejects(codeintegrity::Query(query), L"CI unexpected structure length");
        structureLength = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);

        VbsScanResult evidence;
        evidence.CiOptions = denied;
        const auto unknownJson = BuildVbsJson(evidence);
        check(unknownJson.find(L"\"hvciEnabled\":null") != std::wstring::npos &&
            unknownJson.find(L"\"codeIntegrityEnabled\":null") != std::wstring::npos &&
            unknownJson.find(L"\"raw\":null") != std::wstring::npos &&
            unknownJson.find(L"\"vbsActive\":null") != std::wstring::npos,
            L"CI/VBS JSON unknown is not disabled");
        evidence.CiOptions = disabled;
        const auto disabledJson = BuildVbsJson(evidence);
        check(disabledJson.find(L"\"hvciEnabled\":false") != std::wstring::npos &&
            disabledJson.find(L"\"raw\":\"0x0\"") != std::wstring::npos,
            L"CI JSON known disabled");
        mask = 0x800; // Audit can be reported without the enabled bit.
        evidence.CiOptions = codeintegrity::Query(query);
        const auto auditJson = BuildVbsJson(evidence);
        check(auditJson.find(L"\"hvciAuditMode\":true") != std::wstring::npos &&
            auditJson.find(L"\"debugMode\":false") != std::wstring::npos,
            L"CI JSON audit/debug separation");
        check(FormatCiOptionsFlagText(evidence.CiOptions) == L"HVCI_AUDIT_MODE",
            L"CI console audit/debug separation");
        std::wostringstream ciOutput;
        auto* savedOut = std::wcout.rdbuf(ciOutput.rdbuf());
        PrintCiOptionsBlock(denied);
        PrintVbsCoreBlock(VbsScanResult{});
        evidence.CiOptions.UmciEnabled = true;
        evidence.CiOptions.UmciAuditMode = true;
        PrintCiPolicyBlock(evidence);
        std::wcout.rdbuf(savedOut);
        check(ciOutput.str().find(L"status=unknown") != std::wstring::npos &&
            ciOutput.str().find(L"hvci_enabled=unknown") != std::wstring::npos &&
            ciOutput.str().find(L"UMCI-audit") != std::wstring::npos,
            L"CI console unknown and audit posture");
        const auto liveCi = run(L"!ci options");
        check(liveCi.KeepRunning && liveCi.Output.find(codeintegrity::kSource) != std::wstring::npos &&
            liveCi.Error.find(L"requires the KnLiveDbg.sys") == std::wstring::npos,
            L"CI command does not require a driver or private symbols");
        check(!HasMicrosoftHypervisorHardwareLeaf(0x40000010, 0), L"large leaf range alone is not a Hyper-V interface");
        check(!HasMicrosoftHypervisorHardwareLeaf(0x40000006, 0x12345678), L"unknown hypervisor interface rejected");
        check(!HasMicrosoftHypervisorHardwareLeaf(0x40000005, 0x31237648), L"Hyper-V hardware leaf must exist");
        check(HasMicrosoftHypervisorHardwareLeaf(0x40000006, 0x31237648), L"Hv#1 interface hardware leaf");
        check(HasMicrosoftHypervisorHardwareLeaf(0x40000010, 0x31237648), L"vendor-neutral Hv#1 compatibility");
        check(unknownJson.find(L"\"hardwareFeatures\":null") != std::wstring::npos,
            L"unavailable hypervisor features are not a zero capability mask");

        // A changed type/meaning must not silently reuse the v1 wire contract.
        std::wstring schema;
        check(mcpjson::GetString(unknownJson, L"schema", &schema) && schema == L"kn-live-dbg.vbs.v2",
            L"VBS nullable API evidence has a new schema version");
        std::wstring ciJson;
        std::wstring legacy;
        check(mcpjson::FindRawValue(auditJson, L"ciOptions", &ciJson) &&
            !mcpjson::FindRawValue(ciJson, L"hvciEnforced", &legacy) &&
            !mcpjson::FindRawValue(ciJson, L"hvciDebugMode", &legacy),
            L"VBS v2 removes misleading legacy CI fields");
        evidence.HvlpVsmVtlCallVaResolved = true;
        evidence.HvlpVsmVtlCallVa = 0x1234; // Read succeeded, but this is not a VTL kernel pointer.
        const auto invalidPointerJson = BuildVbsJson(evidence);
        std::wstring active;
        std::wstring known;
        check(mcpjson::FindRawValue(invalidPointerJson, L"vbsActive", &active) && active == L"null" &&
            mcpjson::FindRawValue(invalidPointerJson, L"vbsActiveKnown", &known) && known == L"false",
            L"invalid nonzero VTL pointer is unknown, not disabled");
        ciOutput.str(L"");
        savedOut = std::wcout.rdbuf(ciOutput.rdbuf());
        PrintVbsCoreBlock(evidence);
        std::wcout.rdbuf(savedOut);
        check(ciOutput.str().find(L"vbs_active=unknown") != std::wstring::npos,
            L"invalid VTL pointer is also unknown in console");
        for (const uint64_t pointer : {0ull, 0x0000800000000000ull, 0xffff7fffffffffffull,
            0xffff800000001000ull})
        {
            evidence.HvlpVsmVtlCallVa = pointer;
            evidence.VbsActive = pointer == 0xffff800000001000ull;
            const auto json = BuildVbsJson(evidence);
            const wchar_t* expectedActive = pointer == 0 ? L"false" : (evidence.VbsActive ? L"true" : L"null");
            const wchar_t* expectedKnown = pointer == 0 || evidence.VbsActive ? L"true" : L"false";
            check(mcpjson::ValidateDocument(json) &&
                mcpjson::FindRawValue(json, L"vbsActive", &active) && active == expectedActive &&
                mcpjson::FindRawValue(json, L"vbsActiveKnown", &known) && known == expectedKnown,
                L"VBS pointer validity boundary " + std::to_wstring(pointer));
        }

        // Parse the full document and exact member types; substring matches can
        // accidentally succeed on nested or malformed output.
        const wchar_t* const jsonFlags[] = {L"codeIntegrityEnabled", L"testSign", L"umciEnabled",
            L"umciAuditMode", L"umciExclusionPaths", L"testBuild", L"preproductionBuild", L"debugMode",
            L"flightBuild", L"flightingEnabled", L"hvciEnabled", L"hvciAuditMode", L"hvciStrictMode",
            L"hvciIumEnabled"};
        for (const auto& ci : {denied, disabled, combined})
        {
            evidence = {};
            evidence.CiOptions = ci;
            const auto json = BuildVbsJson(evidence);
            check(mcpjson::ValidateDocument(json) && mcpjson::FindRawValue(json, L"ciOptions", &ciJson),
                L"CI JSON is structurally valid");
            for (const auto name : jsonFlags)
            {
                std::wstring value;
                const wchar_t* expected = !ci.Resolved ? L"null" : (ci.Raw == 0 ? L"false" : L"true");
                check(mcpjson::FindRawValue(ciJson, name, &value) && value == expected,
                    std::wstring(L"CI exact JSON member type ") + name);
            }
        }
        for (const ULONG auditMask : {0x400ul, 0x800ul, 0xc00ul})
        {
            mask = auditMask;
            evidence.CiOptions = codeintegrity::Query(query);
            const auto json = BuildVbsJson(evidence);
            std::wstring enabled;
            std::wstring audit;
            check(mcpjson::FindRawValue(json, L"ciOptions", &ciJson) &&
                mcpjson::FindRawValue(ciJson, L"hvciEnabled", &enabled) &&
                mcpjson::FindRawValue(ciJson, L"hvciAuditMode", &audit) &&
                enabled == (auditMask == 0x800 ? L"false" : L"true") &&
                audit == (auditMask == 0x400 ? L"false" : L"true"),
                L"HVCI enabled and audit are independent JSON observations");
        }
    }

    {
        static bool present = false;
        static uint32_t maximumLeaf = 0;
        static uint32_t signature = 0;
        static uint32_t features = 0;
        static const char* vendor = "Microsoft Hv";
        static std::vector<int> calls;
        const VbsCpuidQuery query = [](int* registers, int leaf)
        {
            calls.push_back(leaf);
            std::fill(registers, registers + 4, 0);
            if (leaf == 1)
            {
                registers[2] = present ? static_cast<int>(0x80000000u) : 0;
            }
            else if (leaf == 0x40000000)
            {
                registers[0] = static_cast<int>(maximumLeaf);
                memcpy(registers + 1, vendor, 12);
            }
            else if (leaf == 0x40000001)
            {
                registers[0] = static_cast<int>(signature);
            }
            else if (leaf == 0x40000006)
            {
                registers[0] = static_cast<int>(features);
            }
        };
        const auto observe = [&]() { calls.clear(); return QueryVbsHypervisorInfo(query); };
        auto observed = observe();
        check(!observed.HypervisorPresent && !observed.HvFeaturesValid && calls == std::vector<int>{1},
            L"CPUID stops before hypervisor leaves when presence bit is clear");
        present = true;
        for (const uint32_t limit : {0u, 0x40000000u})
        {
            maximumLeaf = limit;
            observed = observe();
            check(observed.HypervisorPresent && !observed.HvInterfaceQueried && !observed.HvFeaturesValid &&
                calls == std::vector<int>({1, 0x40000000}), L"CPUID does not query an absent interface leaf");
        }
        maximumLeaf = 0x40000010;
        signature = 0x12345678;
        observed = observe();
        check(observed.VendorSignature == L"Microsoft Hv" && observed.HvInterfaceQueried &&
            !observed.HvFeaturesValid && calls == std::vector<int>({1, 0x40000000, 0x40000001}),
            L"CPUID rejects non-Hv#1 even with a Microsoft vendor string and large range");
        signature = 0x31237648;
        maximumLeaf = 0x40000005;
        observed = observe();
        check(!observed.HvFeaturesValid && calls == std::vector<int>({1, 0x40000000, 0x40000001}),
            L"CPUID does not query hardware features outside the supported range");
        vendor = "VMwareVMware";
        for (const uint32_t limit : {0x40000006u, 0x40000010u})
        {
            maximumLeaf = limit;
            for (const uint32_t mask : {0u, 0x80000001u})
            {
                features = mask;
                observed = observe();
                check(observed.VendorSignature == L"VMwareVMware" && observed.HvFeaturesValid &&
                    observed.HvHardwareFeatures == mask &&
                    calls == std::vector<int>({1, 0x40000000, 0x40000001, 0x40000006}),
                    L"CPUID accepts vendor-neutral Hv#1 and preserves zero/high feature bits");
                VbsScanResult evidence;
                evidence.Hypervisor = observed;
                const auto json = BuildVbsJson(evidence);
                std::wstring hv;
                std::wstring raw;
                check(mcpjson::ValidateDocument(json) && mcpjson::FindRawValue(json, L"hypervisor", &hv) &&
                    mcpjson::FindRawValue(hv, L"hardwareFeatures", &raw) &&
                    raw == (mask == 0 ? L"\"0x0\"" : L"\"0x80000001\""),
                    L"CPUID supported feature mask is a JSON hex string, including zero");
            }
        }
        present = false;
        observed = observe();
        check(!observed.HypervisorPresent && !observed.HvInterfaceQueried && !observed.HvFeaturesValid &&
            observed.HvMaxLeaf == 0 && observed.HvHardwareFeatures == 0 && observed.VendorSignature.empty(),
            L"CPUID new observation does not retain previous capabilities");
    }

    for (const auto& info : CommandRegistry::Commands())
    {
        const std::wstring name = info.Name;
        const auto help = run(name + L" ?");
        check(help.KeepRunning && help.Error.empty() && !help.Output.empty(), L"help " + name);
        const auto nul = run(name + L" " + std::wstring(1, L'\0') + L"invalid");
        check(nul.KeepRunning && nul.Error.find(L"embedded NUL") != std::wstring::npos, L"NUL " + name);
        if (IsNativeOwnedCommand(NormalizeInputCommand(name)) && name != L"kd")
        {
            const auto quote = run(name + L" \"unterminated");
            check(quote.KeepRunning && quote.Error.find(L"unterminated quote") != std::wstring::npos, L"quote " + name);
        }
    }
    check(!device.IsOpen() && !dbgeng.IsReady(), L"registry sweep did not initialize an execution backend");
    {
        auto has = [](const std::vector<std::wstring>& args, const wchar_t* token)
        {
            const auto candidates = CollectCompletionCandidates(args);
            return std::find(candidates.begin(), candidates.end(), token) != candidates.end();
        };
        for (const auto& info : CommandRegistry::Commands())
        {
            check(BuildInteractiveCompletionCandidates({info.Name}) == CollectCompletionCandidates({info.Name}),
                L"local and remote completion agree: " + std::wstring(info.Name));
        }
        check(has({L"!kmon", L"start"}, L"/layout-ms") &&
            CompletionCandidateExists({L"!kmon", L"start"}, L"/layout-ms"), L"kmon layout interval completion");
        check(CompletionCandidateExists({L"!kmon", L"start"}, L"/manifest"), L"kmon manifest completion");
        check(CompletionCandidateExists({L"!kmon", L"cases"}, L"/role") &&
            CompletionCandidateExists({L"!kmon", L"layouts", L"/pid", L"55"}, L"/initial") &&
            CompletionCandidateExists({L"!kmon", L"surfaces", L"55"}, L"/handle-start"), L"kmon analyst completion");
        check(!has({L"!kmon", L"stop"}, L"/pid") && !has({L"!kmon"}, L"on"), L"kmon action boundaries");
        check(has({L"!kmon", L"iotrace", L"driver"}, L"on") &&
            !has({L"!kmon", L"iotrace"}, L"on"), L"iotrace driver precedes action");
        check(!has({L"!kmon", L"layouts"}, L"/initial"), L"initial layout requires a PID");
        check(!has({L"!ti", L"watch"}, L"/pid") && !has({L"!ti", L"recent"}, L"/ring"), L"TI leaf completion");
        check(has({L"!ti", L"add"}, L"/pid") && !has({L"!ti", L"add"}, L"/ring"), L"TI watch mutation options");
        check(!has({L"remote", L"on"}, L"/json") && !has({L"c"}, L"/process"), L"no generic invalid switches");
        check(CollectCompletionCandidates({L"unknown-command"}).empty(), L"unknown command has no options");
        check(has({L"!timeline", L"help"}, L"advanced") &&
            CompletionCandidateExists({L"!timeline", L"help"}, L"advanced"), L"nested timeline help discovery");
        check(has({L"ai", L"help"}, L"config") && has({L"help", L"ai", L"config"}, L"model"), L"nested AI help discovery");
        check(has({L"!diff", L"/domain"}, L"callbacks") &&
            !has({L"!diff"}, L"kpage"), L"diff domain values stay in their value slot");
        check(has({L"!diff"}, L"/memory") && has({L"!threads"}, L"/summary"), L"missing diff and thread options");
        check(has({L"!vad"}, L"/hidden") && has({L"dump-live"}, L"/hypervisor"), L"documented option aliases");
        check(!has({L"!driver", L"list"}, L"/dispatch") &&
            !has({L"!callbacks", L"object"}, L"disable"), L"scope-specific options");
        check(!has({L"!driver"}, L"/json") && !has({L"!module"}, L"/disk") &&
            has({L"!module", L"integrity"}, L"/disk"), L"integrity options require their action");
        DtRequest dtRequest = {};
        std::wstring dtError;
        check(ParseDtRequest({L"dt", L"-r2", L"-v", L"-b", L"nt!_EPROCESS"},
            state, symbols, &dtRequest, &dtError) && dtRequest.RecursionDepth == 2 &&
            dtRequest.Verbose && dtRequest.Bare && has({L"dt", L"-r2", L"-v"}, L"-b") &&
            !has({L"dt", L"-v", L"nt!_EPROCESS"}, L"-b"), L"type completion follows the actual flag parser");
        check(!has({L"!unloaded"}, L"piddb"), L"mapper alias keeps its fixed scope");
        check(!has({L"!kmon", L"start", L"/log"}, L"/pid") &&
            has({L"!kmon", L"start", L"/log", L"my logs"}, L"/pid"), L"option values are not options");
        for (const auto& input : {L"!kmon start /log \"my /pi", L"ai chat \"help !kmon /pi"})
        {
            std::wstring line = input;
            const std::wstring original = line;
            size_t cursor = line.size();
            bool listed = true;
            std::wstring listing;
            check(!ApplyTabCompletion(&line, &cursor, &listed, &listing) && line == original && !listed,
                L"Tab preserves quoted input");
        }
        std::wstring line = L"!kmon start /log \"my logs\" /lay";
        size_t cursor = line.size();
        bool listed = false;
        std::wstring listing;
        check(ApplyTabCompletion(&line, &cursor, &listed, &listing) &&
            line == L"!kmon start /log \"my logs\" /layout-ms ", L"Tab after a quoted option value");
        CompletionHint hint = {};
        check(FindCompletionTokenHint(L"!kmon", {L"!kmon", L"diff", L"before", L"after"}, L"/json", &hint) &&
            std::wstring(hint.Syntax) == L"/json", L"kmon diff JSON does not take a path");
        const auto topic = run(L"help ??");
        check(topic.Error.empty() && topic.Output.find(L"<expression>") != std::wstring::npos,
            L"expression help includes syntax");
        check(run(L"help !threads").Output.find(L"/summary") != std::wstring::npos, L"threads summary help");
        for (const auto& helpLine : {L"!kmon start help", L"!kmon iotrace driver help", L"!minifilter disable help",
            L"!callbacks disable help", L"!vad scan help", L"!wfp filters help", L"!timeline query help",
            L"!timeline live on help", L"remote on help", L"mcp on help", L"probe load help", L"write on help"})
        {
            const auto result = run(helpLine);
            check(result.KeepRunning && result.Error.empty() && !result.Output.empty() &&
                !device.IsOpen() && !dbgeng.IsReady(), L"scoped help is read-only: " + std::wstring(helpLine));
        }
        check(run(L"help dump-raw").Output.find(L"/pid") != std::wstring::npos &&
            run(L"help dump-pe").Output.find(L"/name") != std::wstring::npos, L"user process dump help");
        check(run(L"help !diff").Output.find(L"/memory") != std::wstring::npos &&
            run(L"help !snapshot").Output.find(L"/memory") != std::wstring::npos, L"memory-only snapshot help");
        const auto driverHelp = run(L"help !driver integrity");
        check(driverHelp.Output.find(L"dispatch_coverage_complete") != std::wstring::npos &&
            driverHelp.Output.find(L"fast_io_coverage_complete") != std::wstring::npos &&
            driverHelp.Output.find(L"summary.coverage_complete") != std::wstring::npos,
            L"driver help explains aggregate and per-driver coverage");
        const auto huntHelp = run(L"help !hunt");
        check(huntHelp.Output.find(L"summary.coverage_complete") != std::wstring::npos &&
            huntHelp.Output.find(L"does not start TI") != std::wstring::npos,
            L"hunt help distinguishes findings, coverage, and TI state");
        const auto kmonHelp = run(L"help !kmon start");
        check(kmonHelp.Output.find(L"four explicit watches") != std::wstring::npos &&
            kmonHelp.Output.find(L"two background slots") != std::wstring::npos,
            L"kmon help describes bounded watch scheduling");
        check(run(L"help dt").Output.find(L"already loaded CodeView/PDB") != std::wstring::npos &&
            run(L"help backend").Output.find(L"native-owned commands local") != std::wstring::npos,
            L"symbol lookup and backend help describe current routing");
    }
    const auto remoteStatus = run(L"remote status");
    check(remoteStatus.Error.empty() && remoteStatus.Output.find(L"remote server:") != std::wstring::npos &&
        !dbgeng.IsReady(), L"remote stays native in dbgeng mode");

    state.Backend = DebuggerState::BackendMode::Native;
    const auto layouts = run(L"!kmon layouts /json");
    check(layouts.Error.empty() && layouts.Output.find(L"kmon.layouts.v1") != std::wstring::npos &&
        layouts.Output.find(L"\"baseline_trusted\":false") != std::wstring::npos,
        L"layout inventory is readable without starting collectors");
    for (const auto& line : {L"!kmon layouts /pid 0", L"!kmon layouts /pid 4", L"!kmon layouts /pid -1",
        L"!kmon layouts /pid 4294967296", L"!kmon layouts /pid", L"!kmon layouts /initial",
        L"!kmon layouts /json /json", L"!kmon layouts /save /json", L"!kmon layouts /unknown",
        L"!kmon layouts /pid 5 /pid 6", L"!kmon layouts 55"})
    {
        check(run(line).Error.find(L"usage") != std::wstring::npos, L"layout invalid options rejected");
    }
    check(run(L"!kmon layouts /pid 55 /initial /json").Error.empty(), L"layout initial export option");
    check(IsWriteLikeCommandLine(L"!kmon layouts /pid 55 /save output.json") &&
        !IsWriteLikeCommandLine(L"!kmon layouts /pid 55 /json"), L"layout export write classification");
    for (const auto& value : {L"999", L"60001", L"-1", L"4294967296", L"x"})
    {
        KmonOptions options;
        std::wstring error;
        check(!ParseKmonStartArgs({L"/layout-ms", value}, 0, &options, &error), L"layout interval validation");
    }
    {
        KmonOptions options;
        std::wstring error;
        check(ParseKmonStartArgs({L"/layout-ms", L"1500"}, 0, &options, &error) && options.LayoutScanIntervalMs == 1500,
            L"layout interval accepted");
    }
    const auto huntCases = run(L"!kmon cases /json");
    check(huntCases.Error.empty() && huntCases.Output.find(L"kmon.hunt.v1") != std::wstring::npos &&
        huntCases.Output.find(L"\"communication_proven\":false") != std::wstring::npos,
        L"kmon cases JSON is available without a driver");
    for (const auto& line : {L"!kmon cases /json extra", L"!kmon cases /unknown", L"!kmon cases 0"})
    {
        const auto invalidCases = run(line);
        check(invalidCases.Error.find(L"usage") != std::wstring::npos, L"kmon cases rejects invalid arguments");
    }
    for (const auto& line : {L"!kmon cases /pid 0 /json", L"!kmon cases /role tls_callback /json",
        L"!kmon cases /pid 55 /role tls_callback /json"})
    {
        const auto result = run(line);
        check(result.Error.empty() && result.Output.find(L"kmon.hunt.v1") != std::wstring::npos,
            L"case filters accept valid options");
    }
    for (const auto& line : {L"!kmon cases /pid", L"!kmon cases /pid -1", L"!kmon cases /pid 4294967296",
        L"!kmon cases /pid 1 /pid 2", L"!kmon cases /json /json", L"!kmon cases /role /json",
        L"!kmon cases /save /json", L"!kmon surfaces", L"!kmon surfaces 0", L"!kmon surfaces 4",
        L"!kmon surfaces 4294967296", L"!kmon surfaces 55 /unknown", L"!kmon surfaces 55 /json /json",
        L"!kmon surfaces 55 /module-start 4096", L"!kmon surfaces 55 /handle-start -1",
        L"!kmon diff", L"!kmon diff x", L"!kmon diff x y /unknown", L"!kmon diff x y /json extra"})
    {
        const auto result = run(line);
        check(result.Error.find(L"usage") != std::wstring::npos, L"analyst command rejects invalid arguments before work");
    }
    check(IsWriteLikeCommandLine(L"!kmon cases /save x.json") &&
        IsWriteLikeCommandLine(L"!kmon surfaces 55 /SAVE x.json") &&
        !IsWriteLikeCommandLine(L"!kmon cases /pid 55 /json") &&
        !IsWriteLikeCommandLine(L"!kmon diff x.json y.json /json"), L"analyst file exports require write authorization");
    const auto ownSurfaces = run(L"!kmon surfaces " + std::to_wstring(GetCurrentProcessId()) + L" /json");
    check(ownSurfaces.Error.empty() && ownSurfaces.Output.find(L"kmon.surfaces.v1") != std::wstring::npos &&
        ownSurfaces.Output.find(L"\"execution_observed\":false") != std::wstring::npos && !device.IsOpen(),
        L"owned-process surfaces command works without opening a driver");
    for (const auto& line : std::vector<std::wstring>
        { L"q extra", L"qq extra", L"qd extra", L"quit extra", L"exit extra", L"unload extra",
          L"write on extra", L"setfield nt!TYPE 0 Field 1 extra", L"c 0 1 2 extra", L"query 0 1 extra",
          L"n 10 extra", L"sq true extra", L"backend auto extra", L"procctx clear extra" })
    {
        const auto result = run(line);
        check(result.KeepRunning && result.Error.find(L"invalid argument count") != std::wstring::npos, line);
    }
    check(state.NumberBase == 16 && !state.Quiet && state.Backend == DebuggerState::BackendMode::Native,
        L"rejected state changes are atomic");
    state.DbgEngRemoteKernel = true;
    state.DbgEngConnectOptions = L"preserved";
    check(!run(L"kdinit /remote").Error.empty() && state.DbgEngRemoteKernel &&
        state.DbgEngConnectOptions == L"preserved", L"invalid kdinit preserves connection state");
    const auto expression = run(L"? 0x10 + 2");
    check(expression.Error.empty() && expression.Output.find(L"= 18") != std::wstring::npos,
        L"expression consumes all tokens");
    check(!run(L"? 0x10 garbage").Error.empty(), L"expression rejects ignored suffix");
    check(commandinput::RawCommandTail(L"  kd .printf \"hello world\"") == L".printf \"hello world\"",
        L"raw dbgeng tail retains quotes");

    for (const auto& prefix : { L"mcp on ", L"remote on " })
    {
        for (const auto& suffix : { L"0", L"65536", L"123junk", L"-1", L"+1", L"--bind", L"--bind=",
            L"--bind --loopback", L"--unknown", L"123 124", L"--loopback --bind 0.0.0.0" })
        {
            const auto result = run(std::wstring(prefix) + suffix);
            check(!result.Error.empty() && result.Error.find(L"listener option") != std::wstring::npos,
                std::wstring(prefix) + suffix);
        }
    }
    commandinput::ListenerOptions listen;
    std::wstring error;
    check(commandinput::ParseListenerOptions({ L"51767", L"--loopback", L"--peer", L"127.0.0.1" },
        0, true, 1, &listen, &error) && listen.Port == 51767 && listen.BindAddress == L"127.0.0.1" &&
        listen.Peer == L"127.0.0.1", L"remote listener valid options");
    check(commandinput::ParseListenerOptions({ L"--allow-write", L"--bind=127.0.0.1" },
        0, false, 51766, &listen, &error) && listen.Port == 51766 && listen.AllowWrite,
        L"mcp listener valid options");

    uint64_t number = 7;
    uint32_t major = 99;
    for (const auto& token : { L"", L"0x", L"0n", L"IRP_MJ_", L"+0", L"-0", L"0x+0", L"0n-0" })
    {
        check(!ParseMinifilterIrpMajor(token, &major, &error), L"empty or signed IRP token cannot target CREATE");
    }
    check(ParseMinifilterIrpMajor(L"IRP_MJ_READ", &major, &error) && major == 3 &&
        ParseMinifilterIrpMajor(L"0xff", &major, &error) && major == 255, L"IRP symbolic and numeric compatibility");
    for (const auto& token : std::vector<std::wstring>
        { L"", L"-1", L"+1", L" 1", L"1 ", L"0n-1", L"0x+1", L"0x", L"0n", L"L", L"`",
          L"18446744073709551616", std::wstring(L"10\0ff", 5), L"\uff11" })
    {
        number = 7;
        check(!ParseUnsigned(token, 10, &number) && number == 7, L"unsigned rejects invalid input");
    }
    check(ParseUnsigned(L"0n18446744073709551615", 16, &number) && number == UINT64_MAX,
        L"unsigned decimal max");
    check(ParseUnsigned(L"Lffff`ffff`ffff`ffff", 16, &number) && number == UINT64_MAX,
        L"unsigned debugger hex max");
    check(ParseUnsigned(L"010", 0, &number) && number == 10, L"leading zero decimal");
    uint64_t seed = 1;
    for (size_t index = 0; index < 1000; ++index)
    {
        seed = seed * 6364136223846793005ull + 1;
        check(ParseUnsigned(std::to_wstring(seed), 10, &number) && number == seed,
            L"unsigned full-width decimal roundtrip");
    }
    size_t item = 0;
    check(!ParseDecimalIndex(L"-1", &item) && !ParseDecimalIndex(L"18446744073709551616", &item) &&
        ParseDecimalIndex(L"4294967296", &item) && item == 4294967296ull, L"decimal index does not saturate to ULONG_MAX");

    const bool remoteBefore = g_RemoteOriginActive.exchange(true);
    std::wstring input;
    bool cancelled = false;
    check(!ReadEnterPromptLine(&input, &cancelled, &error) && error == L"supply values on the command line",
        L"remote physical edit cannot block on console input");
    g_RemoteOriginActive.store(remoteBefore);

    for (const auto& json : std::vector<std::wstring>
        { LR"({"cmd":"q")", LR"({"cmd":"q"}garbage)", LR"({"cmd":"q",})",
          LR"({"cmd":"q" "x":1})", LR"({"cmd":"q","x":[1,]})", LR"({"cmd":"q","x":[1}})",
          LR"({"cmd":"q","x":NaN})", LR"({"cmd":"q","x":01})", LR"({"cmd":"q","x":1e})",
          LR"({"cmd":"q","x":trueX})", LR"({"cmd":"q","x":"\z"})", LR"({"cmd":"q","x":"\u00xz"})",
          LR"({"cmd":"q","cmd":"unload"})", LR"({"cmd":"q","\u0063md":"unload"})",
          std::wstring(66, L'[') + L"0" + std::wstring(66, L']') })
    {
        std::wstring raw;
        check(!mcpjson::ValidateDocument(json) && !mcpjson::FindRawValue(json, L"cmd", &raw),
            L"malformed or ambiguous JSON is rejected as a whole");
    }
    std::wstring text;
    check(ExtractJsonStringValue(LR"({"nested":{"cmd":"wrong"},"\u0063md":"\u0068elp"})", L"cmd", &text) &&
        text == L"help", L"JSON top-level lookup decodes unicode keys and values");
    check(!ExtractJsonStringValue(LR"({"nested":{"cmd":"wrong"}})", L"cmd", &text),
        L"nested command cannot shadow missing top-level field");
    check(mcpjson::ValidateDocument(LR"({"n":-1.25e+3,"a":[null,true,false,{"x":"\"\\\/\b\f\n\r\t\u1234"}]})"),
        L"JSON legal nested values");
    check(mcpjson::Utf8ToWide(std::string("\xc0\xaf", 2)).empty(), L"invalid UTF-8 is rejected");
    int64_t signedNumber = 0;
    check(knremote::GetNumberField(LR"({"v":-9223372036854775808})", L"v", &signedNumber) &&
        signedNumber == INT64_MIN && !knremote::GetNumberField(LR"({"v":9223372036854775808})", L"v", &signedNumber) &&
        !knremote::GetNumberField(LR"({"v":1.5})", L"v", &signedNumber), L"remote integer bounds and complete tokens");
    check(!knremote::ConstantTimeEqual(std::string("abcde") + std::string(256, '\0'), "abcde"),
        L"password length mismatch cannot wrap at 256 bytes");

    std::wstring bytes = L"90 0xCC ff";
    check(McpNormalizeByteList(&bytes, &error) && ToLower(bytes) == L"0x90 0xcc 0xff",
        L"MCP byte list has explicit hex radix");
    for (const auto& invalid : { L" ", L"0x", L"x", L"1x2", L"10000000000000000", L"\"90" })
    {
        bytes = invalid;
        check(!McpNormalizeByteList(&bytes, &error), L"MCP byte list rejects empty and malformed values");
    }
    for (const auto& json : { LR"({"address":"0","bytes":"90","width":"3"})",
        LR"({"address":"0","bytes":"90","process":123})", LR"({"address":"0","bytes":"90","proccess":"123"})",
        LR"({"address":"0","bytes":" "})" })
    {
        const auto result = DispatchMcpWriteTool(L"memory.write_virtual", json, state, dbgeng, device, service, symbols, ai, aiState);
        check(result.IsError, L"MCP invalid write options cannot reach execution");
    }
    check(!device.IsOpen() && !dbgeng.IsReady() && !g_McpServer.IsRunning() && !g_RemoteServer.IsRunning(),
        L"negative corpus left execution backends closed");

    check(commandinput::IsValidAddressRange(UINT64_MAX, 1) &&
        commandinput::IsValidAddressRange(UINT64_MAX - 15, 16) &&
        !commandinput::IsValidAddressRange(UINT64_MAX - 15, 17) &&
        !commandinput::IsValidAddressRange(0, 0), L"inclusive address range boundaries");
    check(PageBoundedReadChunk(UINT64_MAX, 0, 1) == 1 &&
        PageBoundedReadChunk(UINT64_MAX, 0, 2) == 0, L"page chunk refuses wraparound");
    MemoryReadView view;
    std::vector<uint8_t> data;
    ProcessAddressContext context = {};
    PhysicalTranslationInfo translation = {};
    check(!ReadSparseVirtualMemory(device, state, nullptr, UINT64_MAX, 2, &view, &error),
        L"sparse virtual rejects overflow");
    check(!ReadSparsePhysicalMemory(device, UINT64_MAX, 2, &view, &error), L"sparse physical rejects overflow");
    check(!ReadProcessVirtualMemory(device, context, 0, KNDBG_MAX_TRANSFER_SIZE + 1, &data, &error) &&
        error == L"Invalid process read request", L"process read rejects oversized allocation before IO");
    check(!ReadProcessVirtualMemory(device, context, UINT64_MAX, 2, &data, &error) &&
        error == L"Invalid process read request", L"process read rejects overflow before IO");
    check(!WriteProcessVirtualMemory(device, context, UINT64_MAX, { 1, 2 }, &error) &&
        error == L"Invalid process write request", L"process write rejects overflow before IO");
    check(!device.ReadMemory(UINT64_MAX, 2, &data, &error) && error.find(L"address overflow") != std::wstring::npos,
        L"device virtual read rejects overflow before IO");
    check(!device.WriteMemory(UINT64_MAX, { 1, 2 }, &error) && error.find(L"address overflow") != std::wstring::npos,
        L"device virtual write rejects overflow before IO");
    check(!device.ReadPhysical(UINT64_MAX, 2, &data, &error) && error.find(L"address overflow") != std::wstring::npos,
        L"device physical read rejects overflow before IO");
    check(!device.WritePhysical(UINT64_MAX, { 1, 2 }, &error) && error.find(L"address overflow") != std::wstring::npos,
        L"device physical write rejects overflow before IO");
    check(!device.TranslateVirtual(0, UINT64_MAX, 2, &translation, &error) &&
        error.find(L"address overflow") != std::wstring::npos, L"device translation rejects overflow before IO");

    for (const auto& tool : BuildMcpToolCatalogSnapshot())
    {
        check(!ValidateMcpToolArguments(tool.Name, LR"({"unknown_argument":true})", &error),
            L"catalog rejects unknown arguments: " + tool.Name);
        check(!ValidateMcpToolArguments(tool.Name, L"[]", &error), L"catalog requires object: " + tool.Name);
    }
    check(ValidateMcpToolArguments(L"memory.write_virtual", LR"({"address":"0","bytes":"90"})", &error),
        L"MCP required string fields accepted");
    check(!ValidateMcpToolArguments(L"memory.write_virtual", LR"({"address":"0"})", &error),
        L"MCP required field cannot be omitted");
    check(ValidateMcpToolArguments(L"process.describe", LR"({"fields":["pid","image"]})", &error) &&
        !ValidateMcpToolArguments(L"process.describe", LR"({"fields":["pid",1]})", &error),
        L"MCP field arrays enforce element type");
    check(ValidateMcpToolArguments(L"code.disasm", LR"({"address":"0","function":true})", &error) &&
        !ValidateMcpToolArguments(L"code.disasm", LR"({"address":"0","function":"true"})", &error),
        L"MCP boolean schema enforced");
    for (const auto& json : { LR"({"address":"0","function":{}})", LR"({"address":"0","count":"junk"})" })
    {
        McpEngineRequest request{ McpRequestKind::ToolCall, L"code.disasm", json };
        check(DispatchMcpRequest(request, state, dbgeng, device, service, symbols, ai, aiState).IsError,
            L"MCP invalid disassembly options fail visibly");
    }
    for (const auto& line : { L"!ti save x y", L"!kmon save x y", L"!timeline clear extra",
        L"!timeline reset extra", L"mcp status extra", L"remote status extra", L"log enable extra",
        L"probe unload extra", L"probe reset extra", L"!ci extra ignored" })
    {
        check(!run(line).Error.empty(), std::wstring(L"strict command arity: ") + line);
    }
    AiCommandProposal proposal = {};
    proposal.Command = L"eb 0 0x90";
    aiState.Commands.push_back(proposal);
    for (const auto& line : { L"ai write confirm extra", L"ai write 1 confirm extra", L"ai write 1 typo" })
    {
        check(run(line).Error.find(L"usage: ai write") != std::wstring::npos, L"AI confirmation must have exact shape");
    }
    check(run(L"ai write 1 confirm").Error.find(L"prewrite backup failed") != std::wstring::npos,
        L"AI write stops when backup fails");
    SymbolEngine disconnectedSymbols;
    ProcessAddressContext disconnectedContext = {};
    bool restorePhysical = false;
    bool hasRestoreContext = false;
    uint64_t restoreAddress = 0;
    uint64_t restoreSize = 0;
    const bool restoreResolved = ResolveWriteTargetForRestore(proposal.Command, state, device,
        disconnectedSymbols, &restorePhysical, &restoreAddress, &restoreSize,
        &disconnectedContext, &hasRestoreContext);
    const bool contextResolved = ResolveProcessAddressContext(device, disconnectedSymbols,
        KNDBG_SYSTEM_PROCESS_ID, &disconnectedContext, &error);
    check(!restoreResolved && !contextResolved && error == L"driver device is not open" &&
        !disconnectedSymbols.IsReady() && disconnectedSymbols.CopyModules().empty() &&
        !hasRestoreContext && !state.HasKernelProcessContext,
        L"disconnected restore and process resolution fail before symbol initialization");
    aiState.Commands.clear();
    check(BuildLogFileName() != BuildLogFileName(), L"rapid log toggles do not reuse a filename");
    check(!run(L"log invalid-action").Error.empty(), L"invalid log action is reported as an error");
    state.HasProcessContext = true;
    state.ProcessContext.ProcessId = 12345;
    check(run(L"|").Output.find(L"12345") != std::wstring::npos, L"process status reflects pinned context");
    state.HasProcessContext = false;
    state.ProcessContext = {};
    std::wcout << L"[commands.selftest] registered=" << CommandRegistry::Commands().size()
        << L" passed=" << passed << L" failed=" << failed << L"\n";
    return failed == 0 ? 0 : 1;
}
