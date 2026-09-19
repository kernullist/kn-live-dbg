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
    const auto remoteStatus = run(L"remote status");
    check(remoteStatus.Error.empty() && remoteStatus.Output.find(L"remote server:") != std::wstring::npos &&
        !dbgeng.IsReady(), L"remote stays native in dbgeng mode");

    state.Backend = DebuggerState::BackendMode::Native;
    const auto huntCases = run(L"!kmon cases /json");
    check(huntCases.Error.empty() && huntCases.Output.find(L"kmon.hunt.v1") != std::wstring::npos &&
        huntCases.Output.find(L"\"communication_proven\":false") != std::wstring::npos,
        L"kmon cases JSON is available without a driver");
    for (const auto& line : {L"!kmon cases /json extra", L"!kmon cases /unknown", L"!kmon cases 0"})
    {
        const auto invalidCases = run(line);
        check(invalidCases.Error.find(L"usage") != std::wstring::npos, L"kmon cases rejects invalid arguments");
    }
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
