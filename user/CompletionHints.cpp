#include "CompletionHints.h"

#include "AiModelCatalog.h"
#include "CommandRegistry.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

namespace
{
    std::wstring HintLower(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return lowered;
    }

    bool SameToken(const wchar_t* left, const std::wstring& right)
    {
        return left != nullptr && HintLower(left) == HintLower(right);
    }

    struct CompletionScopeTable
    {
        const wchar_t* Scope;
        const wchar_t* Syntax;
        const wchar_t* Summary;
        const CompletionHint* Tokens;
        size_t TokenCount;
    };

    struct CompletionCommandTable
    {
        const wchar_t* Command;
        const CompletionScopeTable* Scopes;
        size_t ScopeCount;
    };

    const CompletionHint kGenericTokens[] =
    {
        { L"help", nullptr, L"show detailed usage for this command" },
        { L"/json", L"/json <path>", L"write structured JSON to a file" },
        { L"/limit", L"/limit <n>", L"cap printed records" },
        { L"/process", L"/process <pid>", L"use that process DTB for the VA" },
        { L"/module", L"/module <name>", L"filter by owning module name or stem" },
        { L"/tag", L"/tag <ABCD>", L"filter by 4-character pool tag" },
        { L"/min", L"/min <bytes>", L"keep entries at least this size" },
        { L"/max", L"/max <bytes>", L"keep entries at most this size" },
        { L"/verbose", nullptr, L"print extra detail" },
        { L"/summary", nullptr, L"print aggregate counts only" },
        { L"all", nullptr, L"include every supported surface or target" },
    };

    const CompletionHint kHelpTokens[] =
    {
        { L"all", L"help all", L"include DbgEng-routed WinDbg commands in the summary" },
    };

    const CompletionHint kBackendTokens[] =
    {
        { L"auto", L"backend auto", L"native first; fall back to DbgEng for parser/stop-state" },
        { L"native", L"backend native", L"disable generic DbgEng fallback" },
        { L"dbgeng", L"backend dbgeng", L"send most non-session commands to IDebugControl" },
        { L"help", nullptr, L"show backend usage" },
    };

    const CompletionHint kKdinitTokens[] =
    {
        { L"/local", L"kdinit /local [options]", L"attach DbgEng to the local kernel" },
        { L"/remote", L"kdinit /remote <options>", L"attach DbgEng to a remote KD connection" },
        { L"help", nullptr, L"show kdinit usage" },
    };

    const CompletionHint kProbeTokens[] =
    {
        { L"status", L"probe status", L"show whether the positive-control probe driver is loaded" },
        { L"load", L"probe load [sys-path]", L"load KnLiveDbgProbe.sys from the EXE directory or a path" },
        { L"info", L"probe info", L"print probe VA/PA and firmware-table fixture state" },
        { L"reset", L"probe reset", L"reset probe allocations and fixture state" },
        { L"unload", L"probe unload", L"stop and delete the probe service" },
        { L"help", nullptr, L"show probe usage" },
    };

    const CompletionHint kMcpRootTokens[] =
    {
        { L"on", L"mcp on [port] [--allow-write] [--loopback] [--bind <addr>]", L"start MCP on 0.0.0.0; prompts for a session password" },
        { L"off", L"mcp off", L"stop the MCP server" },
        { L"status", L"mcp status", L"show listen address, password mode, and write-allow state" },
        { L"client-setup", L"mcp client-setup [all|claude|cursor|codex|grok|legacy]", L"print client config snippets" },
        { L"endpoint", L"mcp endpoint", L"show the live endpoint file path and summary" },
        { L"help", nullptr, L"show mcp usage" },
    };

    const CompletionHint kRemoteRootTokens[] =
    {
        { L"on", L"remote on [port] [--loopback] [--bind <ipv4>] [--peer <ipv4>]", L"start remote operator session on 0.0.0.0:51767" },
        { L"off", L"remote off", L"stop the remote listener" },
        { L"status", L"remote status", L"show listen address and peer" },
        { L"disconnect", L"remote disconnect", L"drop the current remote client" },
        { L"help", nullptr, L"show remote usage" },
    };

    const CompletionHint kRemoteOnTokens[] =
    {
        { L"--loopback", nullptr, L"listen on 127.0.0.1 only" },
        { L"--bind", L"--bind <ipv4>", L"0.0.0.0 (default) or a specific IPv4" },
        { L"--peer", L"--peer <ipv4>", L"accept only this client IPv4" },
        { L"help", nullptr, L"show remote on usage" },
    };

    const CompletionHint kMcpOnTokens[] =
    {
        { L"--allow-write", nullptr, L"enable write tools (test VM only)" },
        { L"--loopback", nullptr, L"listen on 127.0.0.1 only" },
        { L"--bind", L"--bind <addr>", L"0.0.0.0 (default, all adapters), loopback, or a specific IP" },
        { L"help", nullptr, L"show mcp on usage" },
    };

    const CompletionHint kMcpClientTokens[] =
    {
        { L"all", L"mcp client-setup all", L"print every supported client snippet" },
        { L"claude", L"mcp client-setup claude", L"Claude Desktop / Claude Code HTTP snippet" },
        { L"claude-code", L"mcp client-setup claude-code", L"Claude Code native HTTP snippet" },
        { L"claude-desktop", L"mcp client-setup claude-desktop", L"Claude Desktop stdio-bridge snippet" },
        { L"cursor", L"mcp client-setup cursor", L"Cursor native HTTP snippet" },
        { L"codex", L"mcp client-setup codex", L"Codex native HTTP snippet" },
        { L"grok", L"mcp client-setup grok", L"Grok native HTTP snippet" },
        { L"legacy", L"mcp client-setup legacy", L"stdio-bridge fallback snippet" },
        { L"help", nullptr, L"show client-setup usage" },
    };

    const CompletionHint kLogTokens[] =
    {
        { L"enable", L"log enable [path]", L"mirror console output to a log file" },
        { L"disable", L"log disable", L"stop file mirroring" },
        { L"status", L"log status", L"show whether logging is on and the path" },
        { L"help", nullptr, L"show log usage" },
    };

    const CompletionHint kWriteTokens[] =
    {
        { L"on", L"write on", L"open the native write gate" },
        { L"off", L"write off", L"close the native write gate" },
        { L"help", nullptr, L"show write-gate usage" },
    };

    const CompletionHint kProcctxTokens[] =
    {
        { L"status", L"procctx status", L"show the pinned process DTB context" },
        { L"clear", L"procctx clear", L"drop the pinned process context" },
        { L"help", nullptr, L"show procctx usage" },
    };

    const CompletionHint kSqTokens[] =
    {
        { L"true", L"sq true", L"suppress low-signal output" },
        { L"false", L"sq false", L"restore normal output" },
        { L"help", nullptr, L"show quiet-mode usage" },
    };

    const CompletionHint kNumberBaseTokens[] =
    {
        { L"10", L"n 10", L"parse unprefixed integers as decimal" },
        { L"16", L"n 16", L"parse unprefixed integers as hex (default)" },
        { L"help", nullptr, L"show number-base usage" },
    };

    const CompletionHint kPplTokens[] =
    {
        { L"on", L"set-ppl-antimalware on", L"set this process to PPL Antimalware (0x31)" },
        { L"off", L"set-ppl-antimalware off", L"clear the PPL Antimalware protection byte" },
        { L"status", L"set-ppl-antimalware status", L"print the current protection byte" },
        { L"help", nullptr, L"show PPL usage" },
    };

    const CompletionHint kProcessOptTokens[] =
    {
        { L"/process", L"/process <pid>", L"use that process DTB for the virtual address" },
        { L"help", nullptr, L"show usage" },
    };

    const CompletionHint kVtopTokens[] =
    {
        { L"/cr3", L"vtop /cr3 <dtb> <va> [length]", L"translate with an explicit directory-table base" },
        { L"/process", L"vtop /process <pid> <va> [length]", L"translate in that process context" },
        { L"help", nullptr, L"show vtop usage" },
    };

    const CompletionHint kDtTokens[] =
    {
        { L"-r", L"dt -r <type> [addr]", L"recurse one level of nested fields" },
        { L"-r1", L"dt -r1 <type> [addr]", L"recurse one level" },
        { L"-r2", L"dt -r2 <type> [addr]", L"recurse two levels" },
        { L"-r3", L"dt -r3 <type> [addr]", L"recurse three levels" },
        { L"-v", L"dt -v <type> [addr]", L"verbose field display" },
        { L"-b", L"dt -b <type> [addr]", L"show fields as bytes" },
        { L"help", nullptr, L"show dt/dtx usage" },
    };

    const CompletionHint kSearchTokens[] =
    {
        { L"-b", L"s -b <addr> <len> <bytes...>", L"search bytes" },
        { L"-w", L"s -w <addr> <len> <words...>", L"search 16-bit words" },
        { L"-d", L"s -d <addr> <len> <dwords...>", L"search 32-bit dwords" },
        { L"-q", L"s -q <addr> <len> <qwords...>", L"search 64-bit qwords" },
        { L"help", nullptr, L"show search usage" },
    };

    const CompletionHint kDumpRawTokens[] =
    {
        { L"/zerofill", L"dump-raw <addr> <len> <path> /zerofill", L"zero-fill failed chunks and continue" },
        { L"help", nullptr, L"show dump-raw usage" },
    };

    const CompletionHint kDumpKernelTokens[] =
    {
        { L"/max", L"dump-kernel <path> /max <bytes>", L"cap the amount of physical RAM copied" },
        { L"/strict", L"dump-kernel <path> /strict", L"fail instead of continuing past a bad run" },
        { L"help", nullptr, L"show dump-kernel usage" },
    };

    const CompletionHint kDumpLiveTokens[] =
    {
        { L"/user", L"dump-live <path> /user [pid|eprocess]", L"include that process user+kernel address space" },
        { L"/compress", L"dump-live <path> /compress", L"ask the OS for a compressed live dump" },
        { L"/hv", L"dump-live <path> /hv", L"include hypervisor pages when the OS supports it" },
        { L"help", nullptr, L"show dump-live usage" },
    };

    const CompletionHint kCallbackTokens[] =
    {
        { L"all", L"!callbacks all [module]", L"object, registry, process, thread, image-load, and minifilter" },
        { L"object", L"!callbacks object [module]", L"object-manager filters from _OBJECT_TYPE.CallbackList" },
        { L"registry", L"!callbacks registry [module]", L"Cm callbacks from CmpCallbackListHead candidates" },
        { L"process", L"!callbacks process [module]", L"PspCreateProcessNotifyRoutine blocks" },
        { L"thread", L"!callbacks thread [module]", L"PspCreateThreadNotifyRoutine blocks" },
        { L"imageload", L"!callbacks imageload [module]", L"PspLoadImageNotifyRoutine blocks" },
        { L"minifilter", L"!callbacks minifilter [module]", L"minifilter operations from fltmgr!FltGlobals" },
        { L"disable", L"!callbacks disable <scope> <module>", L"patch that module's callbacks to a CFG return-0 thunk" },
        { L"enable", L"!callbacks enable <scope> <module>", L"restore same-session callback backups" },
        { L"disable-all", L"!callbacks disable-all <module>", L"disable every callback type for that module" },
        { L"enable-all", L"!callbacks enable-all <module>", L"restore every same-session backup for that module" },
        { L"/module", L"!callbacks [scope] /module <module>", L"keep records owned by that module name or stem" },
        { L"help", nullptr, L"show !callbacks usage" },
    };

    const CompletionHint kCallbackWriteTokens[] =
    {
        { L"all", L"!callbacks disable all <module>", L"every callback type for that module" },
        { L"object", L"!callbacks disable object <module>", L"object-manager Pre/Post for that module" },
        { L"registry", L"!callbacks disable registry <module>", L"Cm callbacks for that module" },
        { L"process", L"!callbacks disable process <module>", L"process-notify for that module" },
        { L"thread", L"!callbacks disable thread <module>", L"thread-notify for that module" },
        { L"imageload", L"!callbacks disable imageload <module>", L"image-load notify for that module" },
        { L"minifilter", L"!callbacks disable minifilter <module>", L"minifilter IRPs via live CallbackNodes" },
        { L"/module", L"!callbacks disable|enable <scope> /module <module>", L"target module name or stem" },
        { L"help", nullptr, L"show !callbacks usage" },
    };

    const CompletionHint kCallbackWriteAllTokens[] =
    {
        { L"/module", L"!callbacks disable-all|enable-all /module <module>", L"target module name or stem" },
        { L"help", nullptr, L"show !callbacks usage" },
    };

    const CompletionHint kHuntTokens[] =
    {
        { L"/quick", L"!hunt /quick", L"skip hidden-PTE and disk-vs-live page comparison" },
        { L"/deep", L"!hunt /deep", L"add hidden-PTE, stomping, BYOVD hash, driver integrity, TI ring" },
        { L"/summary", L"!hunt /summary", L"conclusion and assessment only" },
        { L"/details", L"!hunt /details", L"render raw triage tables after the assessment" },
        { L"/limit", L"!hunt /limit <n>", L"cap per-finding detail (JSON stays full)" },
        { L"/json", L"!hunt /json <path>", L"write kn-live-dbg.hunt.v1 JSON" },
        { L"help", nullptr, L"show !hunt usage" },
    };

    const CompletionHint kVadTokens[] =
    {
        { L"scan", L"!vad scan <pid|eprocess>", L"injection / hidden-PTE / suspicious VAD scan" },
        { L"modules", L"!vad modules <pid|eprocess>", L"loader vs VAD module inventory" },
        { L"mappedpe", L"!vad mappedpe <pid|eprocess>", L"mapped PE inventory across loader/VAD/memory" },
        { L"/summary", nullptr, L"aggregate counts only" },
        { L"/exec", nullptr, L"keep executable VADs" },
        { L"/private", nullptr, L"keep private VADs" },
        { L"/wx", nullptr, L"keep effective W+X VADs" },
        { L"/pe", nullptr, L"keep PE-like VADs" },
        { L"/hiddenpte", nullptr, L"keep hidden-PTE / DKOM candidates" },
        { L"/scan", nullptr, L"same as the scan subcommand" },
        { L"/modules", nullptr, L"same as the modules subcommand" },
        { L"/mappedpe", nullptr, L"same as the mappedpe subcommand" },
        { L"/limit", L"/limit <n>", L"cap printed records" },
        { L"/json", L"/json <path>", L"write structured JSON" },
        { L"help", nullptr, L"show !vad usage" },
    };

    const CompletionHint kThreadsTokens[] =
    {
        { L"/summary", L"!threads <pid> /summary", L"print header and summary only" },
        { L"/apc", L"!threads <pid> /apc", L"include conservative APC-queue evidence" },
        { L"/stacks", L"!threads <pid> /stacks", L"include user-stack bounds and suspicious refs" },
        { L"/limit", L"/limit <n>", L"cap printed threads" },
        { L"/json", L"/json <path>", L"write structured JSON" },
        { L"help", nullptr, L"show !threads usage" },
    };

    const CompletionHint kSnapshotTokens[] =
    {
        { L"baseline", L"!snapshot baseline [/name <label>]", L"capture the in-memory same-boot baseline" },
        { L"save", L"!snapshot save <path> [/name <label>]", L"write JSON (and the Markdown report) to a path" },
        { L"show", L"!snapshot show [baseline|<path>]", L"print domains and warnings from a snapshot" },
        { L"/all", nullptr, L"explicit full domain set (already the default)" },
        { L"/name", L"/name <label>", L"label the snapshot" },
        { L"/domains", nullptr, L"list captured domains" },
        { L"/no-domains", nullptr, L"hide the domain list" },
        { L"/warnings", nullptr, L"print capture warnings" },
        { L"help", nullptr, L"show !snapshot usage" },
    };

    const CompletionHint kDiffTokens[] =
    {
        { L"baseline", L"!diff baseline", L"diff the live view against the in-memory baseline" },
        { L"/summary", nullptr, L"domain counts only" },
        { L"/details", nullptr, L"expand folded child records" },
        { L"/domain", L"/domain <name>", L"keep one snapshot domain" },
        { L"/risk", L"/risk high|all", L"filter by finding risk" },
        { L"/limit", L"/limit <n>", L"cap printed findings" },
        { L"help", nullptr, L"show !diff usage" },
    };

    const CompletionHint kWfpRootTokens[] =
    {
        { L"providers", L"!wfp providers", L"enumerate BFE providers" },
        { L"sublayers", L"!wfp sublayers", L"enumerate BFE sublayers" },
        { L"callouts", L"!wfp callouts [/module <name>]", L"user-mode callout registrations" },
        { L"kernelcallouts", L"!wfp kernelcallouts", L"kernel callout entries from netio" },
        { L"kernel-callouts", L"!wfp kernel-callouts", L"same as kernelcallouts" },
        { L"filters", L"!wfp filters [/layer] [/provider]", L"BFE filters" },
        { L"layers", L"!wfp layers", L"BFE layers" },
        { L"help", nullptr, L"show !wfp usage" },
    };

    const CompletionHint kWfpCalloutTokens[] =
    {
        { L"/module", L"/module <name|GUID>", L"keep callouts owned by that module" },
        { L"help", nullptr, L"show !wfp callouts usage" },
    };

    const CompletionHint kWfpFilterTokens[] =
    {
        { L"/layer", L"/layer <name|GUID>", L"keep filters on that layer" },
        { L"/provider", L"/provider <name|GUID>", L"keep filters from that provider" },
        { L"help", nullptr, L"show !wfp filters usage" },
    };

    const CompletionHint kAlpcRootTokens[] =
    {
        { L"ports", L"!alpc ports [/name] [/pid]", L"enumerate ALPC ports" },
        { L"port", L"!alpc port <address>", L"inspect one port object" },
        { L"connections", L"!alpc connections [/name] [/pid]", L"connection pairings" },
        { L"queues", L"!alpc queues <address>", L"queue depths for one port" },
        { L"help", nullptr, L"show !alpc usage" },
    };

    const CompletionHint kAlpcFilterTokens[] =
    {
        { L"/name", L"/name <pattern>", L"filter by port or image name" },
        { L"/pid", L"/pid <pid>", L"filter by owning PID" },
        { L"help", nullptr, L"show !alpc usage" },
    };

    const CompletionHint kByovdRootTokens[] =
    {
        { L"scan", L"!byovd scan [options]", L"hash loaded modules against the local catalog" },
        { L"update", L"!byovd update [/force]", L"refresh the Microsoft/LOLDrivers catalog" },
        { L"status", L"!byovd status", L"catalog age, source counts, YARA availability" },
        { L"fixture", L"!byovd fixture [status|load|unload|path]", L"benign name/version positive-control driver" },
        { L"/no-update", nullptr, L"do not refresh a stale catalog on this scan" },
        { L"/force-update", nullptr, L"refresh before scanning even if the catalog is fresh" },
        { L"/exact", nullptr, L"suppress name/version MEDIUM hints" },
        { L"/yara", nullptr, L"run operator-supplied yara64.exe against each image" },
        { L"/yara-path", L"/yara-path <exe>", L"pin the YARA executable" },
        { L"/yara-timeout", L"/yara-timeout <seconds>", L"per-driver per-rule timeout, default 30" },
        { L"/verbose", nullptr, L"also print clean modules and hash failures" },
        { L"/summary", nullptr, L"aggregate counts only" },
        { L"/limit", L"/limit <n>", L"cap printed records" },
        { L"/sign", nullptr, L"include Authenticode verification (default)" },
        { L"/no-sign", nullptr, L"skip Authenticode verification" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.byovd-scan.v1" },
        { L"help", nullptr, L"show !byovd usage" },
    };

    const CompletionHint kByovdFixtureTokens[] =
    {
        { L"status", L"!byovd fixture status", L"SCM state of the fixture service" },
        { L"load", L"!byovd fixture load [sys-path]", L"install and start amdryzenmasterdriver.sys" },
        { L"unload", L"!byovd fixture unload", L"stop and delete the fixture service" },
        { L"path", L"!byovd fixture path", L"print the default fixture .sys path" },
        { L"help", nullptr, L"show fixture usage" },
    };

    const CompletionHint kByovdUpdateTokens[] =
    {
        { L"/force", L"!byovd update /force", L"refresh even if the catalog is newer than 24h" },
        { L"help", nullptr, L"show update usage" },
    };

    const CompletionHint kCiTokens[] =
    {
        { L"options", L"!ci options", L"decode nt!g_CiOptions bits" },
        { L"policy", L"!ci policy", L"Code Integrity policy / HVCI related state" },
        { L"help", nullptr, L"show !ci usage" },
    };

    const CompletionHint kEtwRootTokens[] =
    {
        { L"loggers", L"!etw loggers", L"enumerate ETW logger instances" },
        { L"logger", L"!etw logger <index|name>", L"one logger by index or name substring" },
        { L"integrity", L"!etw integrity", L"ETW dispatch / hook integrity" },
        { L"providers", L"!etw providers [/limit <n>]", L"provider-registration candidates" },
        { L"ti-cross", L"!etw ti-cross", L"Threat-Intelligence reception cross-view" },
        { L"help", nullptr, L"show !etw usage" },
    };

    const CompletionHint kEtwProviderTokens[] =
    {
        { L"/limit", L"/limit <n>", L"cap printed providers" },
        { L"help", nullptr, L"show !etw providers usage" },
    };

    const CompletionHint kNmiTokens[] =
    {
        { L"callbacks", L"!nmi callbacks", L"walk nt!KiNmiCallbackListHead (this is the NMI scope)" },
        { L"help", nullptr, L"show !nmi usage" },
    };

    const CompletionHint kHalTokens[] =
    {
        { L"dispatch", L"!hal dispatch", L"nt!HalDispatchTable pointer ownership" },
        { L"private", L"!hal private", L"nt!HalPrivateDispatchTable pointer ownership" },
        { L"help", nullptr, L"show !hal usage" },
    };

    const CompletionHint kHiveTokens[] =
    {
        { L"list", L"!hive list", L"enumerate registry hives" },
        { L"cells", L"!hive cells", L"GetCellRoutine ownership per hive" },
        { L"help", nullptr, L"show !hive usage" },
    };

    const CompletionHint kTokenTokens[] =
    {
        { L"/all", L"!token /all [/limit <n>]", L"every readable process token" },
        { L"/limit", L"/limit <n>", L"cap printed tokens" },
        { L"/system", L"!token /system", L"System process token only" },
        { L"help", nullptr, L"show !token usage" },
    };

    const CompletionHint kDpcTokens[] =
    {
        { L"/verbose", nullptr, L"print every sampled routine, not only suspicious" },
        { L"/limit", L"/limit <n>", L"cap printed routines" },
        { L"help", nullptr, L"show usage" },
    };

    const CompletionHint kFwtableRootTokens[] =
    {
        { L"providers", L"!fwtable providers [/module <name>]", L"registered firmware table providers" },
        { L"provider", L"!fwtable provider <signature>", L"one provider by FourCC/hex signature" },
        { L"help", nullptr, L"show !fwtable usage" },
    };

    const CompletionHint kFwtableProviderTokens[] =
    {
        { L"/module", L"/module <name>", L"keep providers owned by that module" },
        { L"help", nullptr, L"show !fwtable providers usage" },
    };

    const CompletionHint kModuleTokens[] =
    {
        { L"integrity", L"!module integrity [module|all]", L"live PE header and executable-section checks" },
        { L"all", L"!module integrity all", L"scan every loaded kernel module" },
        { L"/summary", nullptr, L"aggregate findings only" },
        { L"/verbose", nullptr, L"print every executable/.text section" },
        { L"/headers", nullptr, L"print PE header evidence" },
        { L"/sections", nullptr, L"print the section table" },
        { L"/wx", nullptr, L"keep W+X section or page evidence" },
        { L"/mismatch", nullptr, L"keep header/size/section anomalies" },
        { L"/disk", nullptr, L"compare live executable pages to the on-disk PE" },
        { L"/iat", nullptr, L"walk the live IAT and flag thunks outside expected modules" },
        { L"/prologue", nullptr, L"disassemble AddressOfEntryPoint for trampoline / trap heads" },
        { L"/limit", L"/limit <n>", L"cap printed modules" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.module-integrity.v1" },
        { L"help", nullptr, L"show !module usage" },
    };

    const CompletionHint kDriverTokens[] =
    {
        { L"list", L"!driver list [driver|all]", L"enumerate \\Driver objects" },
        { L"object", L"!driver object <name|address>", L"inspect one DRIVER_OBJECT and its devices" },
        { L"integrity", L"!driver integrity [driver|all]", L"walk \\Driver and annotate MajorFunction[]" },
        { L"all", L"!driver integrity all", L"scan every driver object" },
        { L"/dispatch", nullptr, L"print MajorFunction[] with !drvobj" },
        { L"/devices", nullptr, L"walk DEVICE_OBJECT.NextDevice and attached stacks" },
        { L"/limit", L"/limit <n>", L"cap printed drivers" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.driver-integrity.v1" },
        { L"help", nullptr, L"show !driver usage" },
    };

    const CompletionHint kDrvobjTokens[] =
    {
        { L"/dispatch", nullptr, L"print MajorFunction[]" },
        { L"/devices", nullptr, L"walk NextDevice and attached stacks" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.drvobj.v1" },
        { L"help", nullptr, L"show !drvobj usage" },
    };

    const CompletionHint kDevstackTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.device-stack.v1" },
        { L"help", nullptr, L"show !devstack usage" },
    };

    const CompletionHint kHandlesTokens[] =
    {
        { L"/target", L"/target <pid>", L"keep process handles that point at that PID" },
        { L"/process", nullptr, L"keep process-type handles only (default)" },
        { L"/all", nullptr, L"include non-process handles" },
        { L"/suspicious", nullptr, L"keep non-system VM/DUP cross-process handles" },
        { L"/limit", L"/limit <n>", L"cap printed handles" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.handle-table.v1" },
        { L"help", nullptr, L"show !handles usage" },
    };

    const CompletionHint kHiddenProcTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.hidden-process.v1" },
        { L"help", nullptr, L"show !hiddenproc usage" },
    };

    const CompletionHint kWdFilterTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.wdfilter-runtime.v1" },
        { L"help", nullptr, L"show !wdfilter usage" },
    };

    const CompletionHint kInputStackTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.input-stack.v1" },
        { L"help", nullptr, L"show !inputstack usage" },
    };

    const CompletionHint kDmaTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.dma-posture.v1" },
        { L"help", nullptr, L"show !dma usage" },
    };

    const CompletionHint kHvTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.hv-posture.v1" },
        { L"help", nullptr, L"show !hv usage" },
    };

    const CompletionHint kDumpAnalyzeTokens[] =
    {
        { L"/json", L"/json <path>", L"write kn-live-dbg.dump-analyze.v1" },
        { L"help", nullptr, L"show dump-analyze usage" },
    };

    const CompletionHint kPoolRootTokens[] =
    {
        { L"big", L"!pool big [options]", L"enumerate nt!PoolBigPageTable allocations" },
        { L"find", L"!pool find /tag <TAG> [options]", L"filtered search; needs /tag, /addr, /min, /max, or /wx" },
        { L"tags", L"!pool tags [/tag] [/limit]", L"per-tag usage via SystemPoolTagInformation (no VA)" },
        { L"summary", L"!pool summary", L"totals only, no per-entry list" },
        { L"pe", L"!pool pe [options]", L"hunt intact or signature-wiped PE images in big pool" },
        { L"help", nullptr, L"show !pool usage" },
    };

    const CompletionHint kPoolListTokens[] =
    {
        { L"/tag", L"/tag <ABCD>", L"filter by 4-character pool tag" },
        { L"/tags", nullptr, L"also attach a top-tag summary to the VA list" },
        { L"/with-tags", nullptr, L"same as /tags" },
        { L"/min", L"/min <bytes>", L"keep entries at least this size" },
        { L"/max", L"/max <bytes>", L"keep entries at most this size" },
        { L"/addr", L"/addr <va>", L"keep the entry containing this VA" },
        { L"/limit", L"/limit <n>", L"stop after N printed entries" },
        { L"/nonpaged", nullptr, L"NonPaged only (default)" },
        { L"/paged", nullptr, L"Paged only" },
        { L"/any", nullptr, L"Paged and NonPaged" },
        { L"/annotate", nullptr, L"walk PTEs for R/W/X on each kept NonPaged entry" },
        { L"/wx", nullptr, L"implies /annotate; keep effective W+X NonPaged entries" },
        { L"help", nullptr, L"show !pool usage" },
    };

    const CompletionHint kPoolTagsTokens[] =
    {
        { L"/tag", L"/tag <ABCD>", L"filter the tag-usage table" },
        { L"/limit", L"/limit <n>", L"cap printed tags" },
        { L"help", nullptr, L"show !pool tags usage" },
    };

    const CompletionHint kPoolPeTokens[] =
    {
        { L"/tag", L"/tag <ABCD>", L"only scan that pool tag" },
        { L"/min", L"/min <bytes>", L"minimum allocation size, default 0x1000" },
        { L"/max", L"/max <bytes>", L"maximum allocation size" },
        { L"/limit", L"/limit <n>", L"stop after N PE hits" },
        { L"/nonpaged", nullptr, L"NonPaged only (default)" },
        { L"/paged", nullptr, L"Paged only" },
        { L"/any", nullptr, L"Paged and NonPaged" },
        { L"/suspicious", nullptr, L"keep hits whose MZ/PE/e_lfanew were wiped" },
        { L"/dump", L"/dump <directory>", L"write each PE via dump-pe (write-like for ai run)" },
        { L"help", nullptr, L"show !pool pe usage" },
    };

    const CompletionHint kPayloadTokens[] =
    {
        { L"scan", L"!payload scan [/limit] [/disasm] [/json]", L"collect off-module hook pointers, then trace each" },
        { L"/limit", L"/limit <n>", L"cap unique addresses (scan) or printed output" },
        { L"/disasm", L"/disasm <n>", L"instruction window size" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.payload.v1" },
        { L"help", nullptr, L"show !payload usage" },
    };

    const CompletionHint kMapperTokens[] =
    {
        { L"all", L"!mapper all", L"unload log + PiDDB + ci hash leftovers" },
        { L"unloaded", L"!mapper unloaded", L"nt!MmUnloadedDrivers only" },
        { L"piddb", L"!mapper piddb", L"nt!PiDDBCacheTable / PiDDBCacheList" },
        { L"cihash", L"!mapper cihash", L"ci!g_KernelHashBucketList" },
        { L"/limit", L"/limit <n>", L"cap printed leftover records" },
        { L"/json", L"/json <path>", L"write leftover JSON" },
        { L"help", nullptr, L"show !mapper usage" },
    };

    const CompletionHint kKpageTokens[] =
    {
        { L"/deep", nullptr, L"also walk nt!MmPfnDatabase (expensive, not default)" },
        { L"/wx", nullptr, L"keep effective W+X regions only" },
        { L"/pe", nullptr, L"keep page-start PE probe hits only" },
        { L"/session", nullptr, L"include session-space hits (default)" },
        { L"/nosession", nullptr, L"drop session-space hits" },
        { L"/limit", L"/limit <n>", L"cap printed regions (default 64)" },
        { L"/json", L"/json <path>", L"write kn-live-dbg.kpage.v1" },
        { L"help", nullptr, L"show !kpage usage" },
    };

    const CompletionHint kMinifilterRootTokens[] =
    {
        { L"list", L"!minifilter list", L"enumerate registered filters" },
        { L"show", L"!minifilter show <name|addr>", L"one filter and its IRP slots" },
        { L"irp", L"!minifilter irp <name|addr> <mj>", L"print one IRP pre/post slot" },
        { L"disable", L"!minifilter disable <name|addr> <mj|all>", L"NULL one or every slot (needs write on)" },
        { L"enable", L"!minifilter enable <name|addr> <mj|all>", L"restore a slot saved in this session" },
        { L"disable-all", L"!minifilter disable-all <name|addr>", L"NULL every registered slot" },
        { L"enable-all", L"!minifilter enable-all <name|addr>", L"restore every saved slot" },
        { L"/json", L"/json <path>", L"write structured JSON" },
        { L"help", nullptr, L"show !minifilter usage" },
    };

    const CompletionHint kMinifilterActionTokens[] =
    {
        { L"all", nullptr, L"every registered IRP major" },
        { L"/pre", nullptr, L"pre-operation callback only" },
        { L"/post", nullptr, L"post-operation callback only" },
        { L"/both", nullptr, L"pre and post (default)" },
        { L"/json", L"/json <path>", L"write structured JSON" },
        { L"IRP_MJ_CREATE", nullptr, L"create / open path" },
        { L"IRP_MJ_DIRECTORY_CONTROL", nullptr, L"directory query / notify" },
        { L"IRP_MJ_SET_INFORMATION", nullptr, L"set file information" },
        { L"help", nullptr, L"show !minifilter usage" },
    };

    const CompletionHint kWnfTokens[] =
    {
        { L"decode", L"!wnf decode <hash>", L"decode a WNF state-name hash" },
        { L"instances", L"!wnf instances", L"walk live name instances" },
        { L"instance", L"!wnf instance <hash|addr>", L"one instance by hash or entry address" },
        { L"data", L"!wnf data <hash|addr>", L"dump instance data" },
        { L"candidates", L"!wnf candidates", L"silo / table-head candidates" },
        { L"lists", L"!wnf lists", L"list-head findings" },
        { L"help", nullptr, L"show !wnf usage" },
    };

    const CompletionHint kKmonRootTokens[] =
    {
        { L"start", L"!kmon start [/name] [/verbose] [/background]", L"arm TI+live and stay on the tail (filename not required)" },
        { L"stop", L"!kmon stop", L"stop derived logging; leaves TI/live running" },
        { L"status", L"!kmon status", L"session counters and watch set" },
        { L"add", L"!kmon add /pid|/name|/driver <v>", L"extend inject.remote or highlight set" },
        { L"remove", L"!kmon remove /pid|/name|/driver <v>", L"drop a watch target" },
        { L"watch", L"!kmon watch", L"optional reattach after Esc; bare !kmon does this" },
        { L"recent", L"!kmon recent [N]", L"print last N derived events" },
        { L"save", L"!kmon save <path>", L"export derived ring as JSONL" },
        { L"clear", L"!kmon clear", L"empty the derived ring" },
        { L"help", nullptr, L"show !kmon usage" },
    };

    const CompletionHint kKmonOptTokens[] =
    {
        { L"/pid", L"/pid <PID>", L"optional; add inject.remote for this PID" },
        { L"/name", L"/name <image>", L"optional; add inject.remote for this image" },
        { L"/driver", L"/driver <sys>", L"highlight only; does not hide unknown drop names" },
        { L"/verbose", L"/verbose", L"also keep inbox System32\\drivers loads" },
        { L"/all-drivers", L"/all-drivers", L"alias for /verbose" },
        { L"/background", L"/background", L"arm only; do not occupy the prompt" },
        { L"/nowatch", L"/nowatch", L"alias for /background" },
        { L"/throttle", L"/throttle <N>", L"max TUI events per second" },
        { L"/log", L"/log <dir>", L"derived JSONL directory" },
        { L"help", nullptr, L"show !kmon option usage" },
    };

    const CompletionHint kTiRootTokens[] =
    {
        { L"start", L"!ti start [/pid] [/name] [/throttle] [/ring] [/log]", L"subscribe to TI ETW (needs PPL Antimalware)" },
        { L"stop", L"!ti stop", L"unsubscribe" },
        { L"status", L"!ti status", L"subscription and ring state" },
        { L"add", L"!ti add /pid <PID> | /name <image>", L"add a watch target" },
        { L"remove", L"!ti remove /pid <PID> | /name <image>", L"remove a watch target" },
        { L"watch", L"!ti watch", L"live tail until Ctrl+C" },
        { L"recent", L"!ti recent [N]", L"print the last N ring events" },
        { L"stats", L"!ti stats", L"histogram by task and process" },
        { L"by", L"!ti by pid <PID> | !ti by task <name>", L"filter the ring" },
        { L"grep", L"!ti grep <pattern>", L"case-insensitive substring search" },
        { L"save", L"!ti save <path>", L"export the ring as JSONL" },
        { L"clear", L"!ti clear", L"empty the in-memory ring" },
        { L"help", nullptr, L"show !ti usage" },
    };

    const CompletionHint kTiByTokens[] =
    {
        { L"pid", L"!ti by pid <PID>", L"keep ring events for that PID" },
        { L"task", L"!ti by task <name>", L"keep ring events whose task name matches" },
        { L"help", nullptr, L"show !ti by usage" },
    };

    const CompletionHint kTiOptTokens[] =
    {
        { L"/pid", L"/pid <PID>", L"watch or filter this PID (repeatable)" },
        { L"/name", L"/name <image>", L"watch or filter this image name (repeatable)" },
        { L"/throttle", L"/throttle <N>", L"max TUI events per second" },
        { L"/ring", L"/ring <N>", L"in-memory ring capacity" },
        { L"/log", L"/log <dir>", L"JSONL log directory" },
        { L"help", nullptr, L"show !ti option usage" },
    };

    const CompletionHint kTimelineRootTokens[] =
    {
        { L"dashboard", L"!timeline dashboard", L"write and open the HTML dashboard" },
        { L"reset", L"!timeline reset", L"clear the in-memory timeline" },
        { L"help", L"!timeline help [advanced]", L"compact usage, or advanced ingest/live/query" },
        { L"ingest", L"!timeline ingest ti|snapshot ...", L"advanced: pull TI ring or a snapshot (hidden from default Tab)" },
        { L"update", L"!timeline update [recent|all]", L"advanced: refresh recent evidence" },
        { L"live", L"!timeline live on|off|status", L"advanced: kernel live callbacks" },
        { L"query", L"!timeline query [filters]", L"advanced: list stored events" },
        { L"graph", L"!timeline graph [filters]", L"advanced: relationship graph" },
        { L"reconcile", L"!timeline reconcile snapshot ...", L"advanced: snapshot vs timeline" },
        { L"export", L"!timeline export <path> [/jsonl]", L"advanced: export the store" },
    };

    const CompletionHint kTimelineHelpTokens[] =
    {
        { L"advanced", L"!timeline help advanced", L"ingest, live, query, graph, reconcile, export" },
    };

    const CompletionHint kTimelineIngestTokens[] =
    {
        { L"ti", L"!timeline ingest ti [recent|all] [/limit]", L"copy TI ring records into the timeline" },
        { L"snapshot", L"!timeline ingest snapshot [baseline|<path>]", L"ingest a snapshot as timeline events" },
        { L"help", nullptr, L"show ingest usage" },
    };

    const CompletionHint kTimelineIngestTiTokens[] =
    {
        { L"recent", nullptr, L"only records newer than the last ingest cursor" },
        { L"all", nullptr, L"rescan the ring through the dedupe path" },
        { L"/limit", L"/limit <n>", L"cap ingested records" },
    };

    const CompletionHint kTimelineIngestSnapTokens[] =
    {
        { L"baseline", nullptr, L"use the in-memory snapshot baseline" },
    };

    const CompletionHint kTimelineUpdateTokens[] =
    {
        { L"recent", nullptr, L"refresh recent TI / snapshot / live evidence" },
        { L"all", nullptr, L"full refresh through the dedupe path" },
        { L"/limit", L"/limit <n>", L"cap ingested records" },
        { L"/snapshot", nullptr, L"include the in-memory snapshot" },
        { L"/live", nullptr, L"include queued live-callback atoms" },
        { L"help", nullptr, L"show update usage" },
    };

    const CompletionHint kTimelineLiveTokens[] =
    {
        { L"on", L"!timeline live on", L"enable kernel process/image/thread callbacks" },
        { L"off", L"!timeline live off", L"disable live callbacks" },
        { L"status", L"!timeline live status", L"collector health and ring pressure" },
        { L"start", L"!timeline live start", L"compatibility alias for on" },
        { L"stop", L"!timeline live stop", L"compatibility alias for off" },
        { L"clear", L"!timeline live clear", L"drop queued live atoms" },
        { L"drain", L"!timeline live drain", L"copy the kernel ring into the timeline now" },
        { L"/capacity", L"/capacity <n>", L"kernel ring capacity" },
        { L"/limit", L"/limit <n>", L"drain cap" },
        { L"help", nullptr, L"show live usage" },
    };

    const CompletionHint kTimelineQueryTokens[] =
    {
        { L"/source", L"/source <name>", L"filter by evidence source" },
        { L"/domain", L"/domain <name>", L"filter by domain" },
        { L"/pid", L"/pid <PID>", L"filter by PID" },
        { L"/limit", L"/limit <n>", L"cap printed events" },
        { L"/oldest", nullptr, L"oldest first" },
        { L"/newest", nullptr, L"newest first" },
    };

    const CompletionHint kTimelineGraphTokens[] =
    {
        { L"/source", L"/source <name>", L"filter by evidence source" },
        { L"/domain", L"/domain <name>", L"filter by domain" },
        { L"/image", L"/image <name>", L"filter by image name" },
        { L"/pid", L"/pid <PID>", L"filter by PID" },
        { L"/limit", L"/limit <n>", L"cap graph nodes" },
        { L"/oldest", nullptr, L"oldest first" },
        { L"/newest", nullptr, L"newest first" },
    };

    const CompletionHint kTimelineReconcileTokens[] =
    {
        { L"snapshot", L"!timeline reconcile snapshot [baseline|<path>]", L"compare a snapshot to the timeline" },
        { L"baseline", nullptr, L"use the in-memory snapshot baseline" },
        { L"/source", L"/source <name>", L"filter by source" },
        { L"/domain", L"/domain <name>", L"filter by domain" },
        { L"/pid", L"/pid <PID>", L"filter by PID" },
        { L"/limit", L"/limit <n>", L"cap printed rows" },
    };

    const CompletionHint kTimelineExportTokens[] =
    {
        { L"/jsonl", L"!timeline export <path> /jsonl", L"write JSONL instead of the default format" },
    };

    const CompletionHint kAiRootTokens[] =
    {
        { L"status", L"ai status", L"ready/blocked health and next setup step" },
        { L"help", L"ai help [subcommand]", L"AI usage" },
        { L"use", L"ai use <preset|model> [model]", L"pick a preset or cloud model and save .env" },
        { L"models", L"ai models [query|refresh]", L"list/search cloud models, or refresh OpenRouter" },
        { L"save", L"ai save", L"write provider/model to the EXE-dir .env" },
        { L"test", L"ai test [prompt]", L"smoke-check the selected provider/model" },
        { L"config", L"ai config [status|provider|policy|model|...]", L"advanced provider setup" },
        { L"providers", L"ai providers", L"compatibility: list providers" },
        { L"provider", L"ai provider <name>", L"compatibility: select a provider" },
        { L"policy", L"ai policy <allow-remote|local-only>", L"compatibility: remote policy" },
        { L"model", L"ai model <model>", L"compatibility: set the model" },
        { L"base-url", L"ai base-url <url>", L"compatibility: set the API base URL" },
        { L"effort", L"ai effort <minimal|low|medium|high|xhigh>", L"compatibility: reasoning effort" },
        { L"auth", L"ai auth", L"compatibility: show credential source" },
        { L"preview", L"ai preview <prompt>", L"compatibility: print the request locally" },
        { L"ask", L"ai ask <prompt>", L"compatibility: send a free-form request" },
        { L"chat", L"ai chat <goal> [/verbose]", L"natural-language tool picker; skips playbooks" },
        { L"plan", L"ai plan <prompt>", L"build a validated command plan" },
        { L"go", L"ai go", L"run a pending expensive local-tool plan" },
        { L"no", L"ai no", L"cancel a pending expensive local-tool plan" },
        { L"run", L"ai run [index|all]", L"execute planned read-only commands" },
        { L"write", L"ai write [index] [confirm]", L"preview or confirm a write-like plan step" },
        { L"explain", L"ai explain <read-only-command...>", L"run a command and explain the output" },
        { L"analyze", L"ai analyze <read-only-command...>", L"run a command and write an analysis report" },
        { L"annotate", L"ai annotate <u|uf> <addr>", L"annotate native disassembly" },
        { L"diagnose", L"ai diagnose <note>", L"diagnose a symbol/backend/type failure" },
        { L"playbook", L"ai playbook <callbacks|minifilter|object|address|driver|hidden|...>", L"load a repeatable read-only plan" },
        { L"transcript", L"ai transcript <path>", L"capture command stdout/stderr as JSONL" },
        { L"audit", L"ai audit <path>", L"record write-like command decisions" },
        { L"show", L"ai show [plan|pending|evidence]", L"print the loaded plan, pending tools, or last evidence" },
        { L"report", L"ai report <path>", L"write a Markdown session report" },
    };

    const CompletionHint kAiConfigTokens[] =
    {
        { L"status", L"ai config status", L"loaded .env, provider, policy, credentials" },
        { L"providers", L"ai config providers", L"list built-in providers" },
        { L"provider", L"ai config provider <name>", L"select the provider" },
        { L"policy", L"ai config policy <allow-remote|local-only|status>", L"allow or block HTTP providers" },
        { L"model", L"ai config model <model>", L"set model; Tab lists curated/live OpenRouter IDs" },
        { L"base-url", L"ai config base-url <url>", L"set the API base URL" },
        { L"effort", L"ai config effort <level>", L"reasoning effort" },
        { L"auth", L"ai config auth", L"credential source" },
        { L"test", L"ai config test [prompt]", L"tiny marker round-trip" },
        { L"help", nullptr, L"show ai config usage" },
    };

    const CompletionHint kAiUseTokens[] =
    {
        { L"cloud", L"ai use cloud", L"OpenRouter + Claude Opus 5" },
        { L"cheap", L"ai use cheap", L"OpenRouter + gpt-oss-120b" },
        { L"deepseek", L"ai use deepseek", L"DeepSeek native API" },
        { L"private", L"ai use private", L"local Codex CLI" },
        { L"chatgpt", L"ai use chatgpt", L"ChatGPT/Codex OAuth" },
        { L"off", L"ai use off", L"disable the model provider" },
        { L"help", nullptr, L"show ai use usage" },
    };

    const CompletionHint kAiModelsTokens[] =
    {
        { L"refresh", L"ai models refresh", L"fetch live OpenRouter model IDs" },
        { L"help", nullptr, L"show ai models usage" },
    };

    const CompletionHint kAiPlaybookTokens[] =
    {
        { L"callbacks", L"ai playbook callbacks [run|dry-run]", L"callback surface audit plan" },
        { L"minifilter", L"ai playbook minifilter [run|dry-run]", L"minifilter chain review plan" },
        { L"object", L"ai playbook object [run|dry-run]", L"object-manager callback review plan" },
        { L"address", L"ai playbook address <va> [run|dry-run]", L"one-address provenance plan" },
        { L"driver", L"ai playbook driver [module] [run|dry-run]", L"suspect-driver surface map" },
        { L"hidden", L"ai playbook hidden [run|dry-run]", L"hidden process cross-view plan" },
        { L"handles", L"ai playbook handles [run|dry-run]", L"process handle VM/DUP triage plan" },
        { L"leftover", L"ai playbook leftover [run|dry-run]", L"mapper leftover plus orphan pages" },
        { L"integrity", L"ai playbook integrity [run|dry-run]", L"module and driver integrity plan" },
        { L"vbs", L"ai playbook vbs [run|dry-run]", L"VBS/HVCI posture plan" },
        { L"dma", L"ai playbook dma [run|dry-run]", L"DMA and hypervisor posture plan" },
        { L"help", nullptr, L"show playbook usage" },
    };

    const CompletionHint kAiShowTokens[] =
    {
        { L"plan", L"ai show plan", L"print the loaded command plan" },
        { L"pending", L"ai show pending", L"print the pending expensive tool plan" },
        { L"evidence", L"ai show evidence", L"print the last captured tool or evidence output" },
        { L"help", nullptr, L"show ai show usage" },
    };

    const CompletionHint kHelpOnlyTokens[] =
    {
        { L"help", nullptr, L"show detailed usage" },
    };

    const CompletionHint kFwtableSigTokens[] =
    {
        { L"ACPI", L"!fwtable provider ACPI", L"ACPI firmware table provider" },
        { L"FIRM", L"!fwtable provider FIRM", L"raw firmware table provider" },
        { L"RSMB", L"!fwtable provider RSMB", L"SMBIOS firmware table provider" },
        { L"help", nullptr, L"show !fwtable provider usage" },
    };

    const CompletionHint kAiEvidenceTokens[] =
    {
        { L"!callbacks", L"ai explain|analyze !callbacks [scope]", L"callback / notify / filter inventory" },
        { L"dt", L"ai explain|analyze dt <type> [addr]", L"PDB type layout" },
        { L"dtx", L"ai explain|analyze dtx <type> [addr]", L"native type reader" },
        { L"u", L"ai explain|analyze u <addr|symbol>", L"native disassembly" },
        { L"uf", L"ai explain|analyze uf <addr|symbol>", L"function disassembly" },
        { L"ln", L"ai explain|analyze ln <addr|symbol>", L"nearest symbol" },
        { L"lm", L"ai explain|analyze lm", L"loaded module list" },
        { L"x", L"ai explain|analyze x <pattern>", L"examine symbols" },
        { L"vtop", L"ai explain|analyze vtop <va>", L"virtual to physical" },
        { L"!dml_proc", L"ai explain|analyze !dml_proc", L"process list" },
        { L"!hunt", L"ai explain|analyze !hunt", L"user-mode anomaly hunt" },
        { L"!vad", L"ai explain|analyze !vad", L"VAD / injection scan" },
        { L"!threads", L"ai explain|analyze !threads", L"thread / APC triage" },
        { L"!snapshot", L"ai explain|analyze !snapshot", L"same-boot baseline" },
        { L"!diff", L"ai explain|analyze !diff", L"snapshot comparison" },
        { L"!wfp", L"ai explain|analyze !wfp", L"WFP / BFE inventory" },
        { L"!alpc", L"ai explain|analyze !alpc", L"ALPC ports and queues" },
        { L"!vbs", L"ai explain|analyze !vbs", L"VBS / HVCI state" },
        { L"!ci", L"ai explain|analyze !ci", L"Code Integrity options" },
        { L"!securekernel", L"ai explain|analyze !securekernel", L"Secure Kernel / IUM" },
        { L"!etw", L"ai explain|analyze !etw", L"ETW loggers and integrity" },
        { L"!nmi", L"ai explain|analyze !nmi", L"NMI handler chain" },
        { L"!msrcheck", L"ai explain|analyze !msrcheck", L"SYSCALL MSR hooks" },
        { L"!cr", L"ai explain|analyze !cr", L"CR0/CR4 control registers" },
        { L"!ssdt", L"ai explain|analyze !ssdt", L"SSDT / shadow SSDT hooks" },
        { L"!idt", L"ai explain|analyze !idt", L"IDT handler hooks" },
        { L"!hal", L"ai explain|analyze !hal", L"HAL dispatch ownership" },
        { L"!hive", L"ai explain|analyze !hive", L"registry hive GetCellRoutine" },
        { L"!token", L"ai explain|analyze !token", L"token privilege triage" },
        { L"!dpc", L"ai explain|analyze !dpc", L"sampled DPC routines" },
        { L"!timer", L"ai explain|analyze !timer", L"kernel timer DPCs" },
        { L"!workitem", L"ai explain|analyze !workitem", L"best-effort work items" },
        { L"!fwtable", L"ai explain|analyze !fwtable", L"firmware table providers" },
        { L"!module", L"ai explain|analyze !module", L"module PE integrity" },
        { L"!driver", L"ai explain|analyze !driver", L"DRIVER_OBJECT dispatch" },
        { L"!pool", L"ai explain|analyze !pool", L"big-pool triage" },
        { L"!address", L"ai explain|analyze !address <va>", L"page-walk and owner" },
        { L"!wnf", L"ai explain|analyze !wnf", L"WNF state names" },
        { L"!handles", L"ai explain|analyze !handles", L"process handle VM/DUP triage" },
        { L"!hiddenproc", L"ai explain|analyze !hiddenproc", L"hidden process cross-view" },
        { L"!kmon", L"ai explain|analyze !kmon", L"unknown kernel drop/map/hidden tail" },
        { L"!wdfilter", L"ai explain|analyze !wdfilter", L"WdFilter RuntimeDriver leftovers" },
        { L"!inputstack", L"ai explain|analyze !inputstack", L"kbd/mou attached-device stacks" },
        { L"!dma", L"ai explain|analyze !dma", L"IOMMU and Kernel DMA Protection" },
        { L"!hv", L"ai explain|analyze !hv", L"hypervisor presence" },
        { L"!drvobj", L"ai explain|analyze !drvobj", L"DRIVER_OBJECT and device chain" },
        { L"!devstack", L"ai explain|analyze !devstack", L"DEVICE_OBJECT attached stack" },
        { L"!payload", L"ai explain|analyze !payload", L"hook-to-body leftover trace" },
        { L"!mapper", L"ai explain|analyze !mapper", L"unloaded-driver bookkeeping remnants" },
        { L"!kpage", L"ai explain|analyze !kpage", L"orphan executable kernel pages" },
        { L"!minifilter", L"ai explain|analyze !minifilter", L"minifilter IRP registrations" },
        { L"!byovd", L"ai explain|analyze !byovd", L"loaded BYOVD catalog scan" },
        { L"dump-analyze", L"ai explain|analyze dump-analyze <path>", L"offline dump header and PML4/PML5 walk" },
        { L"help", nullptr, L"show ai explain/analyze usage" },
    };

    const CompletionHint kAiAnnotateTokens[] =
    {
        { L"u", L"ai annotate u <addr|symbol>", L"annotate linear disassembly" },
        { L"uf", L"ai annotate uf <addr|symbol>", L"annotate a function" },
        { L"help", nullptr, L"show ai annotate usage" },
    };

    const CompletionHint kAiWriteTokens[] =
    {
        { L"1", L"ai write 1 [confirm]", L"preview or confirm plan item 1" },
        { L"confirm", L"ai write [index] confirm", L"execute the write; index optional when the plan has one write" },
        { L"help", nullptr, L"show ai write usage" },
    };

    const CompletionHint kAiRunTokens[] =
    {
        { L"1", L"ai run 1", L"run plan item 1" },
        { L"all", L"ai run all", L"run every remaining read-only plan step" },
        { L"help", nullptr, L"show ai run usage" },
    };

    const CompletionHint kAiPlaybookRunTokens[] =
    {
        { L"run", L"ai playbook <name> run", L"load the playbook and execute it" },
        { L"dry-run", L"ai playbook <name> dry-run", L"load the playbook without executing" },
        { L"help", nullptr, L"show playbook run usage" },
    };

    const CompletionHint kAiChatTokens[] =
    {
        { L"/verbose", nullptr, L"print extra planner detail" },
        { L"help", nullptr, L"show ai chat usage" },
    };

    const CompletionHint kAiProviderNameTokens[] =
    {
        { L"openai-codex-cli", nullptr, L"Codex CLI / local Codex auth" },
        { L"openai-codex-subscription", nullptr, L"ChatGPT Codex subscription HTTP" },
        { L"deepseek", nullptr, L"DeepSeek HTTP API" },
        { L"openrouter", nullptr, L"OpenRouter HTTP API" },
        { L"off", nullptr, L"disable the AI provider" },
        { L"help", nullptr, L"show provider usage" },
    };

    const CompletionHint kAiPolicyTokens[] =
    {
        { L"allow-remote", nullptr, L"allow HTTP providers" },
        { L"local-only", nullptr, L"block remote HTTP providers" },
        { L"status", nullptr, L"print the current remote policy" },
        { L"help", nullptr, L"show policy usage" },
    };

    const CompletionHint kAiEffortTokens[] =
    {
        { L"minimal", nullptr, L"lowest reasoning effort" },
        { L"low", nullptr, L"low reasoning effort" },
        { L"medium", nullptr, L"medium reasoning effort" },
        { L"high", nullptr, L"high reasoning effort" },
        { L"xhigh", nullptr, L"highest reasoning effort" },
        { L"help", nullptr, L"show effort usage" },
    };

    const CompletionHint kAiTranscriptTokens[] =
    {
        { L"status", L"ai transcript status", L"show transcript path and limits" },
        { L"off", L"ai transcript off", L"stop transcript capture" },
        { L"max", L"ai transcript max <n|off>", L"cap captured command output" },
        { L"redact", L"ai transcript redact on|off", L"toggle path/token redaction" },
        { L"help", nullptr, L"show transcript usage" },
    };

    const CompletionHint kAiTranscriptMaxTokens[] =
    {
        { L"off", nullptr, L"remove the capture-size cap" },
        { L"help", nullptr, L"show transcript max usage" },
    };

    const CompletionHint kAiTranscriptRedactTokens[] =
    {
        { L"on", nullptr, L"redact paths and tokens in the transcript" },
        { L"off", nullptr, L"store raw command text" },
        { L"help", nullptr, L"show transcript redact usage" },
    };

    const CompletionHint kAiAuditTokens[] =
    {
        { L"status", L"ai audit status", L"show the write-audit path" },
        { L"off", L"ai audit off", L"stop write-audit logging" },
        { L"help", nullptr, L"show audit usage" },
    };

    const CompletionHint kReloadTokens[] =
    {
        { L"/f", L".reload /f [module]", L"force a full symbol reload" },
        { L"help", nullptr, L"show .reload usage" },
    };

#define SCOPE(name, syntax, summary, table) \
    { name, syntax, summary, table, sizeof(table) / sizeof((table)[0]) }

    const CompletionScopeTable kHelpScopes[] =
    {
        SCOPE(L"", L"help [all|<command>]", L"command summary, or detailed usage for one family", kHelpTokens),
    };

    const CompletionScopeTable kBackendScopes[] =
    {
        SCOPE(L"", L"backend [auto|native|dbgeng]", L"native / DbgEng routing mode", kBackendTokens),
    };

    const CompletionScopeTable kKdinitScopes[] =
    {
        SCOPE(L"", L"kdinit [/local [opts]|/remote <opts>]", L"initialize the DbgEng backend", kKdinitTokens),
    };

    const CompletionScopeTable kProbeScopes[] =
    {
        SCOPE(L"", L"probe [status|load|info|reset|unload]", L"positive-control probe driver", kProbeTokens),
    };

    const CompletionScopeTable kMcpScopes[] =
    {
        SCOPE(L"", L"mcp on|off|status|client-setup|endpoint", L"native HTTP MCP server", kMcpRootTokens),
        SCOPE(L"on", L"mcp on [port] [--allow-write] [--loopback] [--bind]", L"start the MCP server", kMcpOnTokens),
        SCOPE(L"client-setup", L"mcp client-setup [all|claude|cursor|codex|grok|legacy]", L"client config snippets", kMcpClientTokens),
    };

    const CompletionScopeTable kRemoteScopes[] =
    {
        SCOPE(L"", L"remote on|off|status|disconnect", L"LAN operator session", kRemoteRootTokens),
        SCOPE(L"on", L"remote on [port] [--loopback] [--bind] [--peer]", L"start the remote listener", kRemoteOnTokens),
    };

    const CompletionScopeTable kLogScopes[] =
    {
        SCOPE(L"", L"log [enable|disable|status]", L"mirror console output to a file", kLogTokens),
    };

    const CompletionScopeTable kWriteScopes[] =
    {
        SCOPE(L"", L"write on|off", L"native write gate", kWriteTokens),
    };

    const CompletionScopeTable kProcctxScopes[] =
    {
        SCOPE(L"", L"procctx [status|clear|<pid>]", L"pin a default process DTB for d*/e*/vtop", kProcctxTokens),
    };

    const CompletionScopeTable kSqScopes[] =
    {
        SCOPE(L"", L"sq [true|false]", L"quiet mode", kSqTokens),
    };

    const CompletionScopeTable kNumberScopes[] =
    {
        SCOPE(L"", L"n [10|16]", L"unprefixed integer base", kNumberBaseTokens),
    };

    const CompletionScopeTable kPplScopes[] =
    {
        SCOPE(L"", L"set-ppl-antimalware [on|off|status]", L"PPL Antimalware on this process (TI prerequisite)", kPplTokens),
    };

    const CompletionScopeTable kDisplayScopes[] =
    {
        SCOPE(L"", L"d* [/process <pid>] <addr|symbol> [count]", L"display virtual memory (sparse ?? for unread bytes)", kProcessOptTokens),
    };

    const CompletionScopeTable kEnterScopes[] =
    {
        SCOPE(L"", L"e* [/process <pid>] <addr|symbol> <value...>", L"enter virtual memory (needs write on)", kProcessOptTokens),
    };

    const CompletionScopeTable kPhysicalDisplayScopes[] =
    {
        SCOPE(L"", L"!db|pdb <pa> [count]", L"display physical memory", kHelpOnlyTokens),
    };

    const CompletionScopeTable kPhysicalEnterScopes[] =
    {
        SCOPE(L"", L"!eb|peb <pa> <value...>", L"enter physical memory (needs write on)", kHelpOnlyTokens),
    };

    const CompletionScopeTable kVtopScopes[] =
    {
        SCOPE(L"", L"vtop [/cr3 <dtb>|/process <pid>] <va> [length]", L"virtual to physical translation", kVtopTokens),
    };

    const CompletionScopeTable kQueryScopes[] =
    {
        SCOPE(L"", L"query <addr|symbol> [length]", L"driver virtual-address range summary", kHelpOnlyTokens),
    };

    const CompletionScopeTable kDtScopes[] =
    {
        SCOPE(L"", L"dt|dtx [-rN] [-v] [-b] <type> [addr] [fields]", L"PDB type layout and live field values", kDtTokens),
    };

    const CompletionScopeTable kSearchScopes[] =
    {
        SCOPE(L"", L"s [-b|-w|-d|-q] <addr> <len> <value...>", L"search virtual memory", kSearchTokens),
    };

    const CompletionScopeTable kDumpRawScopes[] =
    {
        SCOPE(L"", L"dump-raw <addr> <len> <path> [/zerofill]", L"verbatim kernel VA dump through the driver", kDumpRawTokens),
    };

    const CompletionScopeTable kDumpPeScopes[] =
    {
        SCOPE(L"", L"dump-pe <addr> <path>", L"rebuild an on-disk PE from a live image", kHelpOnlyTokens),
    };

    const CompletionScopeTable kDumpKernelScopes[] =
    {
        SCOPE(L"", L"dump-kernel <path> [/max <bytes>] [/strict]", L"WinDbg complete dump from live physical RAM", kDumpKernelTokens),
    };

    const CompletionScopeTable kDumpLiveScopes[] =
    {
        SCOPE(L"", L"dump-live <path> [/user [pid]] [/compress] [/hv]", L"OS live dump via NtSystemDebugControl", kDumpLiveTokens),
    };

    const CompletionScopeTable kUnassembleScopes[] =
    {
        SCOPE(L"", L"u|uf [/process <pid>] <addr|symbol> [count]", L"native Zydis disassembly through the driver", kProcessOptTokens),
    };

    const CompletionScopeTable kCallbackScopes[] =
    {
        SCOPE(L"", L"!callbacks [all|object|registry|process|thread|imageload|minifilter] [module] | disable|enable <scope> <module>", L"list callbacks; disable/enable one module per type", kCallbackTokens),
        SCOPE(L"filter", L"!callbacks [scope] /module <module>", L"module-filtered callback listing", kCallbackTokens),
        SCOPE(L"write", L"!callbacks disable|enable <scope> <module>", L"per-type callback control (needs write on)", kCallbackWriteTokens),
        SCOPE(L"write-all", L"!callbacks disable-all|enable-all <module>", L"all callback types for one module (needs write on)", kCallbackWriteAllTokens),
    };

    const CompletionScopeTable kDmlProcScopes[] =
    {
        SCOPE(L"", L"!dml_proc [pid|name|eprocess]", L"walk _EPROCESS.ActiveProcessLinks", kHelpOnlyTokens),
    };

    const CompletionScopeTable kHuntScopes[] =
    {
        SCOPE(L"", L"!hunt [/quick|/deep|/summary|/details] [/limit] [/json]", L"whole-system user-mode anomaly hunt", kHuntTokens),
    };

    const CompletionScopeTable kVadScopes[] =
    {
        SCOPE(L"", L"!vad [scan|modules|mappedpe] <pid|image|eprocess> [options]", L"VAD walk, injection scan, hidden PTEs, mapped PE", kVadTokens),
    };

    const CompletionScopeTable kThreadsScopes[] =
    {
        SCOPE(L"", L"!threads <pid|image|eprocess> [/summary] [/apc] [/stacks] [/limit] [/json]", L"thread list, start addresses, APC evidence", kThreadsTokens),
    };

    const CompletionScopeTable kSnapshotScopes[] =
    {
        SCOPE(L"", L"!snapshot baseline|save|show [options]", L"same-boot evidence baseline", kSnapshotTokens),
    };

    const CompletionScopeTable kDiffScopes[] =
    {
        SCOPE(L"", L"!diff baseline|<old.json> <new.json> [options]", L"same-boot snapshot comparison", kDiffTokens),
    };

    const CompletionScopeTable kWfpScopes[] =
    {
        SCOPE(L"", L"!wfp [providers|sublayers|callouts|kernelcallouts|filters|layers]", L"WFP / BFE inventory", kWfpRootTokens),
        SCOPE(L"callouts", L"!wfp callouts [/module <name|GUID>]", L"user-mode callouts", kWfpCalloutTokens),
        SCOPE(L"filters", L"!wfp filters [/layer] [/provider]", L"BFE filters", kWfpFilterTokens),
    };

    const CompletionScopeTable kAlpcScopes[] =
    {
        SCOPE(L"", L"!alpc [ports|port|connections|queues] [options]", L"ALPC ports and queues", kAlpcRootTokens),
        SCOPE(L"filter", L"!alpc ports|connections [/name] [/pid]", L"filtered ALPC listing", kAlpcFilterTokens),
    };

    const CompletionScopeTable kByovdScopes[] =
    {
        SCOPE(L"", L"!byovd [scan|update|status|fixture] [options]", L"loaded BYOVD catalog scan", kByovdRootTokens),
        SCOPE(L"fixture", L"!byovd fixture [status|load|unload|path]", L"benign name/version fixture driver", kByovdFixtureTokens),
        SCOPE(L"update", L"!byovd update [/force]", L"refresh the local catalog", kByovdUpdateTokens),
        SCOPE(L"scan", L"!byovd scan [options]", L"hash loaded modules against the catalog", kByovdRootTokens),
    };

    const CompletionScopeTable kVbsScopes[] =
    {
        SCOPE(L"", L"!vbs", L"VBS / HVCI / MBEC / Secure Kernel state", kHelpOnlyTokens),
    };

    const CompletionScopeTable kSecureKernelScopes[] =
    {
        SCOPE(L"", L"!securekernel", L"Secure Kernel modules and IUM trustlets", kHelpOnlyTokens),
    };

    const CompletionScopeTable kCiScopes[] =
    {
        SCOPE(L"", L"!ci [options|policy]", L"Code Integrity options and policy", kCiTokens),
    };

    const CompletionScopeTable kEtwScopes[] =
    {
        SCOPE(L"", L"!etw [loggers|logger|integrity|providers|ti-cross]", L"ETW loggers, integrity, providers, TI cross-view", kEtwRootTokens),
        SCOPE(L"providers", L"!etw providers [/limit <n>]", L"provider-registration candidates", kEtwProviderTokens),
    };

    const CompletionScopeTable kNmiScopes[] =
    {
        SCOPE(L"", L"!nmi [callbacks]", L"NMI handler chain", kNmiTokens),
    };

    const CompletionScopeTable kMsrScopes[] =
    {
        SCOPE(L"", L"!msrcheck", L"SYSCALL MSRs / LSTAR hook check", kHelpOnlyTokens),
    };

    const CompletionScopeTable kCrScopes[] =
    {
        SCOPE(L"", L"!cr", L"CR0.WP / CR4 SMEP/SMAP / per-CPU divergence", kHelpOnlyTokens),
    };

    const CompletionScopeTable kSsdtScopes[] =
    {
        SCOPE(L"", L"!ssdt", L"native and win32k shadow SSDT hooks", kHelpOnlyTokens),
    };

    const CompletionScopeTable kIdtScopes[] =
    {
        SCOPE(L"", L"!idt", L"IDT handler hooks and per-CPU divergence", kHelpOnlyTokens),
    };

    const CompletionScopeTable kHalScopes[] =
    {
        SCOPE(L"", L"!hal [dispatch|private]", L"HAL dispatch table ownership", kHalTokens),
    };

    const CompletionScopeTable kHiveScopes[] =
    {
        SCOPE(L"", L"!hive [list|cells]", L"registry hive GetCellRoutine ownership", kHiveTokens),
    };

    const CompletionScopeTable kTokenScopes[] =
    {
        SCOPE(L"", L"!token <pid|image|eprocess> | !token /all", L"token privilege Present/Enabled triage", kTokenTokens),
    };

    const CompletionScopeTable kDpcScopes[] =
    {
        SCOPE(L"", L"!dpc [/verbose] [/limit]", L"sampled DPC deferred routines", kDpcTokens),
    };

    const CompletionScopeTable kTimerScopes[] =
    {
        SCOPE(L"", L"!timer [/verbose] [/limit]", L"kernel timer DPC routines", kDpcTokens),
    };

    const CompletionScopeTable kWorkitemScopes[] =
    {
        SCOPE(L"", L"!workitem [/verbose] [/limit]", L"best-effort work-item coverage (incomplete)", kDpcTokens),
    };

    const CompletionScopeTable kFwtableScopes[] =
    {
        SCOPE(L"", L"!fwtable [providers|provider <sig>]", L"firmware table provider registrations", kFwtableRootTokens),
        SCOPE(L"providers", L"!fwtable providers [/module <name>]", L"provider list with optional module filter", kFwtableProviderTokens),
        SCOPE(L"provider", L"!fwtable provider <ACPI|FIRM|RSMB|hex>", L"one provider by FourCC or hex signature", kFwtableSigTokens),
    };

    const CompletionScopeTable kModuleScopes[] =
    {
        SCOPE(L"", L"!module integrity [module|all] [options]", L"live kernel-module PE / W+X integrity", kModuleTokens),
    };

    const CompletionScopeTable kDriverScopes[] =
    {
        SCOPE(L"", L"!driver [list|object|integrity] [options]", L"DRIVER_OBJECT list, object, and dispatch integrity", kDriverTokens),
        SCOPE(L"list", L"!driver list [driver|all] [options]", L"enumerate \\Driver objects", kDriverTokens),
        SCOPE(L"object", L"!driver object <name|address> [options]", L"inspect one DRIVER_OBJECT", kDrvobjTokens),
        SCOPE(L"integrity", L"!driver integrity [driver|all] [options]", L"DRIVER_OBJECT dispatch integrity", kDriverTokens),
    };

    const CompletionScopeTable kDrvobjScopes[] =
    {
        SCOPE(L"", L"!drvobj <name|address> [/dispatch] [/devices] [/json]", L"inspect one DRIVER_OBJECT", kDrvobjTokens),
    };

    const CompletionScopeTable kDevstackScopes[] =
    {
        SCOPE(L"", L"!devstack <device-address|driver-name> [/json]", L"walk a DEVICE_OBJECT stack", kDevstackTokens),
    };

    const CompletionScopeTable kHandlesScopes[] =
    {
        SCOPE(L"", L"!handles [pid] [/target pid] [/process|/all] [/suspicious] [/limit] [/json]", L"process handle table triage", kHandlesTokens),
    };

    const CompletionScopeTable kHiddenProcScopes[] =
    {
        SCOPE(L"", L"!hiddenproc [/json]", L"cross-view hidden process", kHiddenProcTokens),
    };

    const CompletionScopeTable kWdFilterScopes[] =
    {
        SCOPE(L"", L"!wdfilter [/json]", L"WdFilter RuntimeDriver leftovers", kWdFilterTokens),
    };

    const CompletionScopeTable kInputStackScopes[] =
    {
        SCOPE(L"", L"!inputstack [/json]", L"keyboard/mouse device stacks", kInputStackTokens),
    };

    const CompletionScopeTable kDmaScopes[] =
    {
        SCOPE(L"", L"!dma [/json]", L"IOMMU / Kernel DMA Protection posture", kDmaTokens),
    };

    const CompletionScopeTable kHvScopes[] =
    {
        SCOPE(L"", L"!hv [/json]", L"hypervisor presence posture", kHvTokens),
    };

    const CompletionScopeTable kDumpAnalyzeScopes[] =
    {
        SCOPE(L"", L"dump-analyze <path> [/json]", L"parse DUMP_HEADER64 and walk modules (PML4 or LA57 PML5)", kDumpAnalyzeTokens),
    };

    const CompletionScopeTable kPoolScopes[] =
    {
        SCOPE(L"", L"!pool [big|find|tags|summary|pe] [options]", L"big-pool triage and staged PE hunt", kPoolRootTokens),
        SCOPE(L"list", L"!pool big|find [options]", L"PoolBigPageTable listing", kPoolListTokens),
        SCOPE(L"tags", L"!pool tags [/tag] [/limit]", L"per-tag usage (no VA)", kPoolTagsTokens),
        SCOPE(L"pe", L"!pool pe [/tag] [/min] [/max] [/limit] [/suspicious] [/dump]", L"intact or signature-wiped PE in big pool", kPoolPeTokens),
    };

    const CompletionScopeTable kAddressScopes[] =
    {
        SCOPE(L"", L"!address <va>", L"canonicality, page-walk, R/W/X, owner symbol", kHelpOnlyTokens),
    };

    const CompletionScopeTable kPayloadScopes[] =
    {
        SCOPE(L"", L"!payload <addr> | !payload scan [options]", L"hook-to-body leftover trace", kPayloadTokens),
    };

    const CompletionScopeTable kMapperScopes[] =
    {
        SCOPE(L"", L"!mapper [all|unloaded|piddb|cihash] [/limit] [/json]", L"bookkeeping remnants (unload / PiDDB / ci hash)", kMapperTokens),
    };

    const CompletionScopeTable kKpageScopes[] =
    {
        SCOPE(L"", L"!kpage [/deep] [/wx] [/pe] [/session|/nosession] [/limit] [/json]", L"orphan executable kernel pages", kKpageTokens),
    };

    const CompletionScopeTable kMinifilterScopes[] =
    {
        SCOPE(L"", L"!minifilter [list|show|irp|disable|enable|disable-all|enable-all]", L"list filters; enable/disable IRP slots", kMinifilterRootTokens),
        SCOPE(L"action", L"!minifilter disable|enable <name> <mj|all> [/pre|/post|/both]", L"IRP slot control (needs write on)", kMinifilterActionTokens),
    };

    const CompletionScopeTable kWnfScopes[] =
    {
        SCOPE(L"", L"!wnf [decode|instances|instance|data|candidates|lists]", L"WNF state names and live instances", kWnfTokens),
    };

    const CompletionScopeTable kKmonScopes[] =
    {
        SCOPE(L"", L"!kmon [start] | stop | status | recent | save", L"unknown kernel drop/map/hidden tail (no filename)", kKmonRootTokens),
        SCOPE(L"opts", L"!kmon [/name] [/verbose] [/background] [/driver] [/pid] [/log]", L"kmon start options", kKmonOptTokens),
    };

    const CompletionScopeTable kTiScopes[] =
    {
        SCOPE(L"", L"!ti start|stop|status|watch|recent|stats|by|grep|save|clear", L"Microsoft-Windows-Threat-Intelligence ETW", kTiRootTokens),
        SCOPE(L"by", L"!ti by pid <PID> | !ti by task <name>", L"filter the TI ring", kTiByTokens),
        SCOPE(L"opts", L"!ti start|add|remove [/pid] [/name] [/throttle] [/ring] [/log]", L"subscription and watch options", kTiOptTokens),
    };

    const CompletionScopeTable kTimelineScopes[] =
    {
        SCOPE(L"", L"!timeline | !timeline dashboard | !timeline reset | !timeline help", L"time-ordered TI/snapshot/live evidence", kTimelineRootTokens),
        SCOPE(L"help", L"!timeline help [advanced]", L"compact or advanced help", kTimelineHelpTokens),
        SCOPE(L"ingest", L"!timeline ingest ti|snapshot ...", L"pull TI or a snapshot into the store", kTimelineIngestTokens),
        SCOPE(L"ingest-ti", L"!timeline ingest ti [recent|all] [/limit]", L"TI ring ingest", kTimelineIngestTiTokens),
        SCOPE(L"ingest-snapshot", L"!timeline ingest snapshot [baseline|<path>]", L"snapshot ingest", kTimelineIngestSnapTokens),
        SCOPE(L"update", L"!timeline update [recent|all] [options]", L"refresh recent evidence", kTimelineUpdateTokens),
        SCOPE(L"live", L"!timeline live on|off|status|...", L"kernel live process/image/thread callbacks", kTimelineLiveTokens),
        SCOPE(L"query", L"!timeline query [filters]", L"list stored events", kTimelineQueryTokens),
        SCOPE(L"graph", L"!timeline graph [filters]", L"relationship graph", kTimelineGraphTokens),
        SCOPE(L"reconcile", L"!timeline reconcile snapshot ...", L"snapshot vs timeline", kTimelineReconcileTokens),
        SCOPE(L"export", L"!timeline export <path> [/jsonl]", L"export the store", kTimelineExportTokens),
    };

    const CompletionScopeTable kAiScopes[] =
    {
        SCOPE(L"", L"ai <goal> | ai chat <goal> | ai <subcommand> ...", L"intent router: local tools, playbooks, chat planner, and evidence analysis", kAiRootTokens),
        SCOPE(L"config", L"ai config [status|provider|policy|model|test|...]", L"advanced provider setup", kAiConfigTokens),
        SCOPE(L"config-provider", L"ai config provider <name|off>", L"select the AI provider", kAiProviderNameTokens),
        SCOPE(L"config-policy", L"ai config policy <allow-remote|local-only|status>", L"allow or block HTTP providers", kAiPolicyTokens),
        SCOPE(L"config-effort", L"ai config effort <minimal|low|medium|high|xhigh>", L"reasoning effort", kAiEffortTokens),
        SCOPE(L"config-model", L"ai config model <model>", L"set a cloud or native model id", kHelpOnlyTokens),
        SCOPE(L"use", L"ai use <preset|model> [model]", L"pick a preset or cloud model", kAiUseTokens),
        SCOPE(L"use-model", L"ai use <preset> <model>", L"override the preset model", kHelpOnlyTokens),
        SCOPE(L"models", L"ai models [query|refresh]", L"list or search cloud models", kAiModelsTokens),
        SCOPE(L"playbook", L"ai playbook <callbacks|minifilter|object|address|driver|hidden|...>", L"repeatable read-only plans", kAiPlaybookTokens),
        SCOPE(L"playbook-run", L"ai playbook <name> [run|dry-run]", L"execute or preview a playbook", kAiPlaybookRunTokens),
        SCOPE(L"chat", L"ai chat <goal> [/verbose]", L"natural-language catalog tool picker", kAiChatTokens),
        SCOPE(L"show", L"ai show [plan|pending|evidence]", L"loaded plan, pending tools, or last evidence", kAiShowTokens),
        SCOPE(L"leaf", L"ai <subcommand> [help]", L"subcommand help", kHelpOnlyTokens),
        SCOPE(L"evidence", L"ai explain|analyze <read-only-command...>", L"run a command and explain or analyze the output", kAiEvidenceTokens),
        SCOPE(L"annotate", L"ai annotate <u|uf> <addr|symbol>", L"annotate native disassembly", kAiAnnotateTokens),
        SCOPE(L"write", L"ai write [index] [confirm]", L"preview or confirm a write-like plan step", kAiWriteTokens),
        SCOPE(L"run", L"ai run [index|all]", L"execute planned read-only commands", kAiRunTokens),
        SCOPE(L"transcript", L"ai transcript <path>|status|off|max|redact", L"capture command stdout/stderr as JSONL", kAiTranscriptTokens),
        SCOPE(L"transcript-max", L"ai transcript max <n|off>", L"cap captured command output", kAiTranscriptMaxTokens),
        SCOPE(L"transcript-redact", L"ai transcript redact on|off", L"toggle path/token redaction", kAiTranscriptRedactTokens),
        SCOPE(L"audit", L"ai audit <path>|status|off", L"record write-like command decisions", kAiAuditTokens),
        SCOPE(L"provider", L"ai provider <name|off>", L"compatibility: select a provider", kAiProviderNameTokens),
        SCOPE(L"policy", L"ai policy <allow-remote|local-only|status>", L"compatibility: remote policy", kAiPolicyTokens),
        SCOPE(L"effort", L"ai effort <minimal|low|medium|high|xhigh>", L"compatibility: reasoning effort", kAiEffortTokens),
    };

    const CompletionScopeTable kClsScopes[] =
    {
        SCOPE(L"", L"cls", L"clear the console screen", kHelpOnlyTokens),
    };

    const CompletionScopeTable kHomeScopes[] =
    {
        SCOPE(L"", L"home", L"redraw the startup dashboard", kHelpOnlyTokens),
    };

    const CompletionScopeTable kDashboardScopes[] =
    {
        SCOPE(L"", L"dashboard", L"alias for home; redraw the startup dashboard", kHelpOnlyTokens),
    };

    const CompletionScopeTable kDrvstatusScopes[] =
    {
        SCOPE(L"", L"drvstatus", L"show service, owner, handle, and write-gate state", kHelpOnlyTokens),
    };

    const CompletionScopeTable kVersionScopes[] =
    {
        SCOPE(L"", L"version", L"show tool and driver version", kHelpOnlyTokens),
    };

    const CompletionScopeTable kVertargetScopes[] =
    {
        SCOPE(L"", L"vertarget", L"show local live target version", kHelpOnlyTokens),
    };

    const CompletionScopeTable kVercommandScopes[] =
    {
        SCOPE(L"", L"vercommand", L"show the process command line", kHelpOnlyTokens),
    };

    const CompletionScopeTable kUnloadScopes[] =
    {
        SCOPE(L"", L"unload", L"stop and delete the driver service", kHelpOnlyTokens),
    };

    const CompletionScopeTable kKdScopes[] =
    {
        SCOPE(L"", L"kd <command...>", L"execute a raw command through DbgEng", kHelpOnlyTokens),
    };

    const CompletionScopeTable kKddetachScopes[] =
    {
        SCOPE(L"", L"kddetach", L"end the DbgEng session", kHelpOnlyTokens),
    };

    const CompletionScopeTable kQuitScopes[] =
    {
        SCOPE(L"", L"q", L"quit and unload the driver service", kHelpOnlyTokens),
    };

    const CompletionScopeTable kQuitQqScopes[] =
    {
        SCOPE(L"", L"qq", L"quit and unload the driver service", kHelpOnlyTokens),
    };

    const CompletionScopeTable kQuitQdScopes[] =
    {
        SCOPE(L"", L"qd", L"quit and detach equivalent", kHelpOnlyTokens),
    };

    const CompletionScopeTable kCompareScopes[] =
    {
        SCOPE(L"", L"c <addr1> <addr2> <length>", L"compare two virtual ranges", kProcessOptTokens),
    };

    const CompletionScopeTable kFillScopes[] =
    {
        SCOPE(L"", L"f [/process <pid>] <addr> <len> <bytes...>", L"fill virtual memory (needs write on)", kProcessOptTokens),
    };

    const CompletionScopeTable kFillPtrScopes[] =
    {
        SCOPE(L"", L"fp [/process <pid>] <addr> <len> <pointers...>", L"fill pointer-sized virtual memory (needs write on)", kProcessOptTokens),
    };

    const CompletionScopeTable kMoveScopes[] =
    {
        SCOPE(L"", L"m [/process <pid>] <src> <dst> <length>", L"move a virtual range (needs write on)", kProcessOptTokens),
    };

    const CompletionScopeTable kSetFieldScopes[] =
    {
        SCOPE(L"", L"setfield <type> <addr|symbol> <field> <value>", L"write one structure field (needs write on)", kHelpOnlyTokens),
    };

    const CompletionScopeTable kLmScopes[] =
    {
        SCOPE(L"", L"lm [pattern]", L"list loaded kernel modules", kHelpOnlyTokens),
    };

    const CompletionScopeTable kLnScopes[] =
    {
        SCOPE(L"", L"ln <addr|symbol>", L"list nearest symbol", kHelpOnlyTokens),
    };

    const CompletionScopeTable kXScopes[] =
    {
        SCOPE(L"", L"x <pattern>", L"examine symbols", kHelpOnlyTokens),
    };

    const CompletionScopeTable kSympathScopes[] =
    {
        SCOPE(L"", L".sympath [path]", L"show or set the symbol path", kHelpOnlyTokens),
    };

    const CompletionScopeTable kSympathPlusScopes[] =
    {
        SCOPE(L"", L".sympath+ <path>", L"append to the symbol path", kHelpOnlyTokens),
    };

    const CompletionScopeTable kReloadScopes[] =
    {
        SCOPE(L"", L".reload [/f] [module]", L"reload kernel modules and symbols", kReloadTokens),
    };

    const CompletionScopeTable kTargetStatusScopes[] =
    {
        SCOPE(L"", L"||", L"single local live system status", kHelpOnlyTokens),
    };

    const CompletionScopeTable kTargetStatusSScopes[] =
    {
        SCOPE(L"", L"||s", L"show local live system status", kHelpOnlyTokens),
    };

    const CompletionScopeTable kProcessStatusScopes[] =
    {
        SCOPE(L"", L"|", L"show current local process context", kHelpOnlyTokens),
    };

    const CompletionScopeTable kEvalScopes[] =
    {
        SCOPE(L"", L"?? <expression>", L"evaluate an expression natively or through DbgEng", kHelpOnlyTokens),
    };

#define CMD(name, scopes) { name, scopes, sizeof(scopes) / sizeof((scopes)[0]) }

    const CompletionCommandTable kCommands[] =
    {
        CMD(L"help", kHelpScopes),
        CMD(L"backend", kBackendScopes),
        CMD(L"kdinit", kKdinitScopes),
        CMD(L"kddetach", kKddetachScopes),
        CMD(L"kd", kKdScopes),
        CMD(L"probe", kProbeScopes),
        CMD(L"mcp", kMcpScopes),
        CMD(L"remote", kRemoteScopes),
        CMD(L"log", kLogScopes),
        CMD(L"write", kWriteScopes),
        CMD(L"procctx", kProcctxScopes),
        CMD(L"sq", kSqScopes),
        CMD(L"n", kNumberScopes),
        CMD(L"set-ppl-antimalware", kPplScopes),
        CMD(L"cls", kClsScopes),
        CMD(L"home", kHomeScopes),
        CMD(L"dashboard", kDashboardScopes),
        CMD(L"drvstatus", kDrvstatusScopes),
        CMD(L"version", kVersionScopes),
        CMD(L"vertarget", kVertargetScopes),
        CMD(L"vercommand", kVercommandScopes),
        CMD(L"unload", kUnloadScopes),
        CMD(L"q", kQuitScopes),
        CMD(L"qq", kQuitQqScopes),
        CMD(L"qd", kQuitQdScopes),
        CMD(L"??", kEvalScopes),
        CMD(L"||", kTargetStatusScopes),
        CMD(L"||s", kTargetStatusSScopes),
        CMD(L"|", kProcessStatusScopes),
        CMD(L"d", kDisplayScopes),
        CMD(L"db", kDisplayScopes),
        CMD(L"dq", kDisplayScopes),
        CMD(L"dd", kDisplayScopes),
        CMD(L"dw", kDisplayScopes),
        CMD(L"da", kDisplayScopes),
        CMD(L"du", kDisplayScopes),
        CMD(L"ds", kDisplayScopes),
        CMD(L"dS", kDisplayScopes),
        CMD(L"dc", kDisplayScopes),
        CMD(L"df", kDisplayScopes),
        CMD(L"dp", kDisplayScopes),
        CMD(L"dyb", kDisplayScopes),
        CMD(L"dyd", kDisplayScopes),
        CMD(L"dda", kDisplayScopes),
        CMD(L"ddp", kDisplayScopes),
        CMD(L"ddu", kDisplayScopes),
        CMD(L"dpa", kDisplayScopes),
        CMD(L"dpp", kDisplayScopes),
        CMD(L"dpu", kDisplayScopes),
        CMD(L"dqa", kDisplayScopes),
        CMD(L"dqp", kDisplayScopes),
        CMD(L"dqu", kDisplayScopes),
        CMD(L"dds", kDisplayScopes),
        CMD(L"dps", kDisplayScopes),
        CMD(L"dqs", kDisplayScopes),
        CMD(L"e", kEnterScopes),
        CMD(L"eb", kEnterScopes),
        CMD(L"ed", kEnterScopes),
        CMD(L"eq", kEnterScopes),
        CMD(L"ew", kEnterScopes),
        CMD(L"ea", kEnterScopes),
        CMD(L"eu", kEnterScopes),
        CMD(L"ef", kEnterScopes),
        CMD(L"ep", kEnterScopes),
        CMD(L"eza", kEnterScopes),
        CMD(L"ezu", kEnterScopes),
        CMD(L"phys", kPhysicalDisplayScopes),
        CMD(L"pdb", kPhysicalDisplayScopes),
        CMD(L"pdw", kPhysicalDisplayScopes),
        CMD(L"pdd", kPhysicalDisplayScopes),
        CMD(L"pdq", kPhysicalDisplayScopes),
        CMD(L"!db", kPhysicalDisplayScopes),
        CMD(L"!dw", kPhysicalDisplayScopes),
        CMD(L"!dd", kPhysicalDisplayScopes),
        CMD(L"!dq", kPhysicalDisplayScopes),
        CMD(L"peb", kPhysicalEnterScopes),
        CMD(L"pew", kPhysicalEnterScopes),
        CMD(L"ped", kPhysicalEnterScopes),
        CMD(L"peq", kPhysicalEnterScopes),
        CMD(L"!eb", kPhysicalEnterScopes),
        CMD(L"!ew", kPhysicalEnterScopes),
        CMD(L"!ed", kPhysicalEnterScopes),
        CMD(L"!eq", kPhysicalEnterScopes),
        CMD(L"vtop", kVtopScopes),
        CMD(L"query", kQueryScopes),
        CMD(L"dt", kDtScopes),
        CMD(L"dtx", kDtScopes),
        CMD(L"s", kSearchScopes),
        CMD(L"setfield", kSetFieldScopes),
        CMD(L"c", kCompareScopes),
        CMD(L"f", kFillScopes),
        CMD(L"fp", kFillPtrScopes),
        CMD(L"m", kMoveScopes),
        CMD(L"lm", kLmScopes),
        CMD(L"ln", kLnScopes),
        CMD(L"x", kXScopes),
        CMD(L".sympath", kSympathScopes),
        CMD(L".sympath+", kSympathPlusScopes),
        CMD(L".reload", kReloadScopes),
        CMD(L"dump-raw", kDumpRawScopes),
        CMD(L"dump-pe", kDumpPeScopes),
        CMD(L"dump-kernel", kDumpKernelScopes),
        CMD(L"dump-live", kDumpLiveScopes),
        CMD(L"dump-analyze", kDumpAnalyzeScopes),
        CMD(L"u", kUnassembleScopes),
        CMD(L"uf", kUnassembleScopes),
        CMD(L"!callbacks", kCallbackScopes),
        CMD(L"!dml_proc", kDmlProcScopes),
        CMD(L"!hunt", kHuntScopes),
        CMD(L"!vad", kVadScopes),
        CMD(L"!threads", kThreadsScopes),
        CMD(L"!snapshot", kSnapshotScopes),
        CMD(L"!diff", kDiffScopes),
        CMD(L"!wfp", kWfpScopes),
        CMD(L"!alpc", kAlpcScopes),
        CMD(L"!byovd", kByovdScopes),
        CMD(L"!vbs", kVbsScopes),
        CMD(L"!ci", kCiScopes),
        CMD(L"!securekernel", kSecureKernelScopes),
        CMD(L"!etw", kEtwScopes),
        CMD(L"!nmi", kNmiScopes),
        CMD(L"!msrcheck", kMsrScopes),
        CMD(L"!cr", kCrScopes),
        CMD(L"!ssdt", kSsdtScopes),
        CMD(L"!idt", kIdtScopes),
        CMD(L"!hal", kHalScopes),
        CMD(L"!hive", kHiveScopes),
        CMD(L"!token", kTokenScopes),
        CMD(L"!dpc", kDpcScopes),
        CMD(L"!timer", kTimerScopes),
        CMD(L"!workitem", kWorkitemScopes),
        CMD(L"!fwtable", kFwtableScopes),
        CMD(L"!module", kModuleScopes),
        CMD(L"!driver", kDriverScopes),
        CMD(L"!drvobj", kDrvobjScopes),
        CMD(L"!devstack", kDevstackScopes),
        CMD(L"!handles", kHandlesScopes),
        CMD(L"!hiddenproc", kHiddenProcScopes),
        CMD(L"!wdfilter", kWdFilterScopes),
        CMD(L"!inputstack", kInputStackScopes),
        CMD(L"!dma", kDmaScopes),
        CMD(L"!hv", kHvScopes),
        CMD(L"!pool", kPoolScopes),
        CMD(L"!address", kAddressScopes),
        CMD(L"!payload", kPayloadScopes),
        CMD(L"!mapper", kMapperScopes),
        CMD(L"!kpage", kKpageScopes),
        CMD(L"!minifilter", kMinifilterScopes),
        CMD(L"!wnf", kWnfScopes),
        CMD(L"!ti", kTiScopes),
        CMD(L"!kmon", kKmonScopes),
        CMD(L"!timeline", kTimelineScopes),
        CMD(L"ai", kAiScopes),
    };

#undef CMD
#undef SCOPE

    const CompletionCommandTable* FindCommandTable(const std::wstring& command)
    {
        const std::wstring lowered = HintLower(command);
        for (size_t i = 0; i < sizeof(kCommands) / sizeof(kCommands[0]); ++i)
        {
            if (SameToken(kCommands[i].Command, lowered))
            {
                return &kCommands[i];
            }
        }

        return nullptr;
    }

    std::wstring SelectScopeKey(const std::wstring& command, const std::vector<std::wstring>& argsBefore)
    {
        std::wstring scope;
        if (argsBefore.size() < 2)
        {
            return scope;
        }

        const std::wstring first = HintLower(argsBefore[1]);
        const std::wstring second = argsBefore.size() >= 3 ? HintLower(argsBefore[2]) : std::wstring();

        if (command == L"!pool")
        {
            if (first == L"pe")
            {
                scope = L"pe";
            }
            else if (first == L"tags" || first == L"tag")
            {
                scope = L"tags";
            }
            else if (first == L"big" || first == L"bigpool" || first == L"find" || first == L"summary")
            {
                scope = L"list";
            }
        }
        else if (command == L"!byovd")
        {
            if (first == L"fixture")
            {
                scope = L"fixture";
            }
            else if (first == L"update")
            {
                scope = L"update";
            }
            else if (first == L"scan")
            {
                scope = L"scan";
            }
        }
        else if (command == L"!ti")
        {
            if (first == L"by")
            {
                scope = L"by";
            }
            else if (!first.empty() && first != L"help")
            {
                // watch/recent/stats/grep/save/clear also complete /pid /name /...
                scope = L"opts";
            }
        }
        else if (command == L"!kmon")
        {
            if (!first.empty() && first != L"help")
            {
                scope = L"opts";
            }
        }
        else if (command == L"!etw")
        {
            if (first == L"providers")
            {
                scope = L"providers";
            }
        }
        else if (command == L"!wfp")
        {
            if (first == L"callouts")
            {
                scope = L"callouts";
            }
            else if (first == L"filters")
            {
                scope = L"filters";
            }
        }
        else if (command == L"!alpc")
        {
            if (first == L"ports" || first == L"connections")
            {
                scope = L"filter";
            }
        }
        else if (command == L"!fwtable")
        {
            if (first == L"providers")
            {
                scope = L"providers";
            }
            else if (first == L"provider")
            {
                scope = L"provider";
            }
        }
        else if (command == L"!callbacks")
        {
            if (first == L"disable" || first == L"enable")
            {
                scope = L"write";
            }
            else if (first == L"disable-all" || first == L"enable-all")
            {
                scope = L"write-all";
            }
            else if (!first.empty() && first != L"help")
            {
                scope = L"filter";
            }
        }
        else if (command == L"!minifilter" || command == L"!fltmgr")
        {
            if (first == L"disable" || first == L"enable" || first == L"irp" ||
                first == L"show" || first == L"disable-all" || first == L"enable-all")
            {
                scope = L"action";
            }
        }
        else if (command == L"!timeline")
        {
            if (first == L"help")
            {
                scope = L"help";
            }
            else if (first == L"ingest")
            {
                if (second == L"ti")
                {
                    scope = L"ingest-ti";
                }
                else if (second == L"snapshot")
                {
                    scope = L"ingest-snapshot";
                }
                else
                {
                    scope = L"ingest";
                }
            }
            else if (first == L"update")
            {
                scope = L"update";
            }
            else if (first == L"live")
            {
                scope = L"live";
            }
            else if (first == L"query")
            {
                scope = L"query";
            }
            else if (first == L"graph")
            {
                scope = L"graph";
            }
            else if (first == L"reconcile")
            {
                scope = L"reconcile";
            }
            else if (first == L"export")
            {
                scope = L"export";
            }
        }
        else if (command == L"ai")
        {
            if (first == L"config")
            {
                if (second == L"provider")
                {
                    scope = L"config-provider";
                }
                else if (second == L"policy")
                {
                    scope = L"config-policy";
                }
                else if (second == L"effort")
                {
                    scope = L"config-effort";
                }
                else if (second == L"model")
                {
                    scope = L"config-model";
                }
                else
                {
                    scope = L"config";
                }
            }
            else if (first == L"use")
            {
                if (!second.empty() && second != L"help")
                {
                    scope = L"use-model";
                }
                else
                {
                    scope = L"use";
                }
            }
            else if (first == L"models")
            {
                scope = L"models";
            }
            else if (first == L"playbook")
            {
                if (!second.empty() && second != L"help")
                {
                    scope = L"playbook-run";
                }
                else
                {
                    scope = L"playbook";
                }
            }
            else if (first == L"explain" || first == L"analyze")
            {
                scope = L"evidence";
            }
            else if (first == L"annotate")
            {
                scope = L"annotate";
            }
            else if (first == L"chat")
            {
                scope = L"chat";
            }
            else if (first == L"write")
            {
                scope = L"write";
            }
            else if (first == L"run")
            {
                scope = L"run";
            }
            else if (first == L"show")
            {
                scope = L"show";
            }
            else if (first == L"go" ||
                     first == L"no" ||
                     first == L"status" ||
                     first == L"report" ||
                     first == L"diagnose" ||
                     first == L"auth" ||
                     first == L"preview" ||
                     first == L"ask" ||
                     first == L"plan" ||
                     first == L"model" ||
                     first == L"base-url" ||
                     first == L"providers" ||
                     first == L"save" ||
                     first == L"test")
            {
                scope = L"leaf";
            }
            else if (first == L"transcript")
            {
                if (second == L"max")
                {
                    scope = L"transcript-max";
                }
                else if (second == L"redact")
                {
                    scope = L"transcript-redact";
                }
                else
                {
                    scope = L"transcript";
                }
            }
            else if (first == L"audit")
            {
                scope = L"audit";
            }
            else if (first == L"provider")
            {
                scope = L"provider";
            }
            else if (first == L"policy")
            {
                scope = L"policy";
            }
            else if (first == L"effort")
            {
                scope = L"effort";
            }
        }
        else if (command == L"mcp")
        {
            if (first == L"on")
            {
                scope = L"on";
            }
            else if (first == L"client-setup" || first == L"setup" || first == L"connect")
            {
                scope = L"client-setup";
            }
        }
        else if (command == L"remote")
        {
            if (first == L"on")
            {
                scope = L"on";
            }
        }

        if (scope.empty() && !first.empty())
        {
            const CompletionCommandTable* table = FindCommandTable(command);
            if (table != nullptr)
            {
                for (size_t i = 0; i < table->ScopeCount; ++i)
                {
                    const wchar_t* name = table->Scopes[i].Scope;
                    if (name != nullptr && name[0] != L'\0' && SameToken(name, first))
                    {
                        scope = first;
                        break;
                    }
                }
            }
        }

        return scope;
    }

    const CompletionScopeTable* FindScopeTable(
        const CompletionCommandTable& table,
        const std::wstring& scopeKey)
    {
        const CompletionScopeTable* fallback = nullptr;
        for (size_t i = 0; i < table.ScopeCount; ++i)
        {
            const wchar_t* name = table.Scopes[i].Scope;
            if (name == nullptr || name[0] == L'\0')
            {
                fallback = &table.Scopes[i];
                if (scopeKey.empty())
                {
                    return fallback;
                }

                continue;
            }

            if (SameToken(name, scopeKey))
            {
                return &table.Scopes[i];
            }
        }

        return fallback;
    }

    bool FillHintFromTable(const CompletionHint* tokens, size_t count, const std::wstring& token, CompletionHint* hint)
    {
        bool found = false;
        for (size_t i = 0; i < count; ++i)
        {
            if (SameToken(tokens[i].Token, token))
            {
                *hint = tokens[i];
                found = true;
                break;
            }
        }

        return found;
    }

    bool FillFromRegistry(const std::wstring& token, CompletionCommandGuide* guide)
    {
        bool found = false;
        const CommandInfo* info = CommandRegistry::Find(token);
        if (info != nullptr)
        {
            guide->Command = info->Name;
            // Canonical is the resolved command name, not a usage string.
            guide->Syntax = info->Name;
            guide->Summary = info->Summary;
            found = true;
        }

        return found;
    }

    bool HintHasUsefulSyntax(const wchar_t* token, const wchar_t* syntax)
    {
        bool useful = false;
        if (syntax != nullptr && syntax[0] != L'\0')
        {
            if (token == nullptr || !SameToken(syntax, token))
            {
                useful = true;
            }
        }

        return useful;
    }

    std::wstring PadRight(const std::wstring& value, size_t width)
    {
        if (value.size() >= width)
        {
            return value;
        }

        return value + std::wstring(width - value.size(), L' ');
    }

    bool SyntaxFirstTokenIsFamily(const wchar_t* syntax)
    {
        bool family = false;
        if (syntax != nullptr)
        {
            for (const wchar_t* cursor = syntax; *cursor != L'\0' && *cursor != L' '; ++cursor)
            {
                if (*cursor == L'*' || *cursor == L'|')
                {
                    family = true;
                    break;
                }
            }
        }

        return family;
    }

    std::wstring SpecializeFamilySyntax(const std::wstring& name, const wchar_t* syntax)
    {
        std::wstring text;
        if (syntax != nullptr && syntax[0] != L'\0')
        {
            text = syntax;
            if (!name.empty() && SyntaxFirstTokenIsFamily(syntax))
            {
                size_t end = 0;
                while (end < text.size() && text[end] != L' ')
                {
                    ++end;
                }

                text = name + text.substr(end);
            }
        }

        return text;
    }

    std::wstring HintCanonicalCommand(const std::wstring& value)
    {
        std::wstring command = HintLower(value);
        const CommandInfo* info = CommandRegistry::Find(value);
        if (info != nullptr &&
            info->Support == CommandSupport::Alias &&
            info->Canonical != nullptr)
        {
            command = HintLower(info->Canonical);
        }

        return command;
    }

    bool FillTokenHintFromCommand(
        const std::wstring& command,
        const std::vector<std::wstring>& argsBefore,
        const std::wstring& token,
        CompletionHint* hint)
    {
        bool found = false;
        const CompletionCommandTable* table = FindCommandTable(command);
        if (table != nullptr)
        {
            const std::wstring scopeKey = SelectScopeKey(HintLower(command), argsBefore);
            const CompletionScopeTable* scope = FindScopeTable(*table, scopeKey);
            if (scope != nullptr &&
                FillHintFromTable(scope->Tokens, scope->TokenCount, token, hint))
            {
                found = true;
            }
            else if (!scopeKey.empty())
            {
                const CompletionScopeTable* root = FindScopeTable(*table, L"");
                if (root != nullptr &&
                    root != scope &&
                    FillHintFromTable(root->Tokens, root->TokenCount, token, hint))
                {
                    found = true;
                }
            }
        }

        if (!found && hint != nullptr && HintLower(command) == L"ai")
        {
            static thread_local std::wstring s_syntax;
            static thread_local std::wstring s_summary;
            if (AiModelCatalog::DescribeToken(token, &s_syntax, &s_summary) &&
                !s_summary.empty())
            {
                hint->Token = token.c_str();
                hint->Syntax = s_syntax.c_str();
                hint->Summary = s_summary.c_str();
                found = true;
            }
        }

        return found;
    }
}

bool FindCompletionCommandGuide(
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore,
    CompletionCommandGuide* guide)
{
    bool found = false;

    do
    {
        if (guide == nullptr)
        {
            break;
        }

        *guide = {};
        const CompletionCommandTable* table = FindCommandTable(command);
        if (table == nullptr)
        {
            found = FillFromRegistry(command, guide);
            break;
        }

        const std::wstring scopeKey = SelectScopeKey(HintLower(command), argsBefore);
        const CompletionScopeTable* scope = FindScopeTable(*table, scopeKey);
        if (scope == nullptr)
        {
            found = FillFromRegistry(command, guide);
            break;
        }

        guide->Command = table->Command;
        guide->Syntax = scope->Syntax;
        guide->Summary = scope->Summary;

        const bool rootScope = scope->Scope == nullptr || scope->Scope[0] == L'\0';
        if (rootScope)
        {
            const CommandInfo* info = CommandRegistry::Find(command);
            if (info != nullptr)
            {
                if (info->Name != nullptr)
                {
                    guide->Command = info->Name;
                }

                // Shared family tables (d*/e*/!db|pdb) would otherwise print the
                // same generic sentence for db, dq, and dd.
                if (SyntaxFirstTokenIsFamily(scope->Syntax) &&
                    info->Summary != nullptr &&
                    info->Summary[0] != L'\0')
                {
                    guide->Summary = info->Summary;
                }
            }
        }

        found = true;
    } while (false);

    return found;
}

bool FindCompletionTokenHint(
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore,
    const std::wstring& token,
    CompletionHint* hint)
{
    bool found = false;

    do
    {
        if (hint == nullptr || token.empty())
        {
            break;
        }

        *hint = {};
        if (command.empty() || command == L"help" || command == L"?")
        {
            CompletionCommandGuide guide = {};
            if (FindCompletionCommandGuide(token, {}, &guide))
            {
                hint->Token = guide.Command;
                hint->Syntax = guide.Syntax;
                hint->Summary = guide.Summary;
                found = true;
                break;
            }
        }

        if (FillTokenHintFromCommand(command, argsBefore, token, hint))
        {
            found = true;
            break;
        }

        // "ai explain !callbacks <tab>" offers callback scopes while the
        // current command is still ai. Walk trailing command tokens before
        // the generic /json|/limit|all fallback, which would mislabel "all".
        for (size_t index = argsBefore.size(); index > 1; --index)
        {
            const size_t nestedIndex = index - 1;
            const std::wstring nested = HintCanonicalCommand(argsBefore[nestedIndex]);
            if (FindCommandTable(nested) == nullptr)
            {
                continue;
            }

            std::vector<std::wstring> nestedArgs;
            for (size_t copy = nestedIndex; copy < argsBefore.size(); ++copy)
            {
                nestedArgs.push_back(argsBefore[copy]);
            }

            if (FillTokenHintFromCommand(nested, nestedArgs, token, hint))
            {
                found = true;
                break;
            }
        }

        if (found)
        {
            break;
        }

        if (FillHintFromTable(kGenericTokens, sizeof(kGenericTokens) / sizeof(kGenericTokens[0]), token, hint))
        {
            found = true;
            break;
        }
    } while (false);

    return found;
}

std::wstring BuildCompletionListing(
    const std::vector<std::wstring>& matches,
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore)
{
    std::wostringstream out;
    out << L"\n";

    CompletionCommandGuide guide = {};
    const bool hasGuide = !command.empty() &&
        FindCompletionCommandGuide(command, argsBefore, &guide);

    if (hasGuide)
    {
        if (guide.Command != nullptr && guide.Command[0] != L'\0')
        {
            out << guide.Command;
        }
        else
        {
            out << command;
        }

        if (guide.Summary != nullptr && guide.Summary[0] != L'\0')
        {
            out << L"  " << guide.Summary;
        }

        out << L"\n";
        const std::wstring usage = SpecializeFamilySyntax(command, guide.Syntax);
        if (HintHasUsefulSyntax(command.c_str(), usage.empty() ? nullptr : usage.c_str()))
        {
            out << L"usage: " << usage << L"\n";
        }

        out << L"\n";
    }

    const bool rootLike = command.empty() ||
        command == L"help" ||
        command == L"?";
    const bool compact = rootLike && matches.size() > 20;

    struct ListingRow
    {
        std::wstring Token;
        std::wstring Syntax;
        std::wstring Summary;
    };

    std::vector<ListingRow> rows;
    size_t tokenWidth = 8;

    for (const std::wstring& match : matches)
    {
        ListingRow row = {};
        row.Token = match;

        CompletionHint hint = {};
        if (FindCompletionTokenHint(command, argsBefore, match, &hint))
        {
            const std::wstring syntax = command.empty()
                ? SpecializeFamilySyntax(match, hint.Syntax)
                : (hint.Syntax != nullptr ? std::wstring(hint.Syntax) : std::wstring());
            if (!compact && HintHasUsefulSyntax(match.c_str(), syntax.empty() ? nullptr : syntax.c_str()))
            {
                row.Syntax = syntax;
            }

            if (hint.Summary != nullptr && hint.Summary[0] != L'\0')
            {
                row.Summary = hint.Summary;
            }
        }

        tokenWidth = (std::max)(tokenWidth, row.Token.size());
        rows.push_back(row);
    }

    if (tokenWidth > 24)
    {
        tokenWidth = 24;
    }

    for (const ListingRow& row : rows)
    {
        out << L"  " << PadRight(row.Token, tokenWidth);
        if (!row.Summary.empty())
        {
            out << L"  " << row.Summary;
        }

        out << L"\n";
        if (!row.Syntax.empty())
        {
            out << L"  " << PadRight(L"", tokenWidth) << L"  " << row.Syntax << L"\n";
        }
    }

    return out.str();
}

namespace
{
    void AddUniqueToken(std::vector<std::wstring>* out, const wchar_t* token)
    {
        do
        {
            if (out == nullptr || token == nullptr || token[0] == L'\0')
            {
                break;
            }

            std::wstring item = token;
            if (std::find(out->begin(), out->end(), item) == out->end())
            {
                out->push_back(item);
            }
        } while (false);
    }

    void AddHintTableTokens(
        std::vector<std::wstring>* out,
        const CompletionHint* tokens,
        size_t count)
    {
        if (out == nullptr || tokens == nullptr)
        {
            return;
        }

        for (size_t i = 0; i < count; ++i)
        {
            AddUniqueToken(out, tokens[i].Token);
        }
    }

    void AddScopeTokens(
        std::vector<std::wstring>* out,
        const std::wstring& command,
        const std::vector<std::wstring>& argsBefore)
    {
        const CompletionCommandTable* table = FindCommandTable(command);
        if (table == nullptr)
        {
            return;
        }

        const std::wstring scopeKey = SelectScopeKey(HintLower(command), argsBefore);
        const CompletionScopeTable* scope = FindScopeTable(*table, scopeKey);
        if (scope != nullptr)
        {
            AddHintTableTokens(out, scope->Tokens, scope->TokenCount);
        }
        if (!scopeKey.empty())
        {
            const CompletionScopeTable* root = FindScopeTable(*table, L"");
            if (root != nullptr && root != scope)
            {
                AddHintTableTokens(out, root->Tokens, root->TokenCount);
            }
        }
    }
}

std::vector<std::wstring> CollectCompletionCandidates(
    const std::vector<std::wstring>& argsBefore)
{
    std::vector<std::wstring> out;

    do
    {
        if (argsBefore.empty())
        {
            for (const CommandInfo& info : CommandRegistry::Commands())
            {
                AddUniqueToken(&out, info.Name);
            }
            break;
        }

        const std::wstring command = HintCanonicalCommand(argsBefore[0]);
        if (command == L"help" || command == L"?")
        {
            if (argsBefore.size() <= 1)
            {
                AddUniqueToken(&out, L"all");
                for (const CommandInfo& info : CommandRegistry::Commands())
                {
                    AddUniqueToken(&out, info.Name);
                }
            }
            else
            {
                std::vector<std::wstring> topic(argsBefore.begin() + 1, argsBefore.end());
                out = CollectCompletionCandidates(topic);
            }
            break;
        }

        AddScopeTokens(&out, command, argsBefore);

        for (size_t index = argsBefore.size(); index > 1; --index)
        {
            const size_t nestedIndex = index - 1;
            const std::wstring nested = HintCanonicalCommand(argsBefore[nestedIndex]);
            if (FindCommandTable(nested) == nullptr)
            {
                continue;
            }

            std::vector<std::wstring> nestedArgs;
            for (size_t copy = nestedIndex; copy < argsBefore.size(); ++copy)
            {
                nestedArgs.push_back(argsBefore[copy]);
            }
            AddScopeTokens(&out, nested, nestedArgs);
        }

        AddHintTableTokens(
            &out,
            kGenericTokens,
            sizeof(kGenericTokens) / sizeof(kGenericTokens[0]));

        if (command == L"ai")
        {
            for (const std::wstring& token : AiModelCatalog::ModelCompletionTokens())
            {
                AddUniqueToken(&out, token.c_str());
            }
        }
    } while (false);

    return out;
}

bool ApplyTabCompletion(
    std::wstring* line,
    size_t* cursor,
    bool* listed,
    std::wstring* listing)
{
    bool changed = false;

    do
    {
        if (listed != nullptr)
        {
            *listed = false;
        }
        if (listing != nullptr)
        {
            listing->clear();
        }
        if (line == nullptr || cursor == nullptr)
        {
            break;
        }
        if (*cursor > line->size())
        {
            *cursor = line->size();
        }

        size_t tokenStart = *cursor;
        size_t tokenEnd = *cursor;
        while (tokenStart > 0 && std::iswspace((*line)[tokenStart - 1]) == 0)
        {
            --tokenStart;
        }
        while (tokenEnd < line->size() && std::iswspace((*line)[tokenEnd]) == 0)
        {
            ++tokenEnd;
        }

        const std::wstring prefix = line->substr(tokenStart, *cursor - tokenStart);
        std::wstring left = line->substr(0, tokenStart);
        std::vector<std::wstring> argsBefore;
        std::wstring word;
        for (wchar_t ch : left)
        {
            if (ch == L' ' || ch == L'\t')
            {
                if (!word.empty())
                {
                    argsBefore.push_back(word);
                    word.clear();
                }
            }
            else
            {
                word.push_back(ch);
            }
        }
        if (!word.empty())
        {
            argsBefore.push_back(word);
        }

        const std::vector<std::wstring> candidates = CollectCompletionCandidates(argsBefore);
        std::vector<std::wstring> matches;
        const std::wstring prefixLower = HintLower(prefix);
        for (const std::wstring& item : candidates)
        {
            if (prefixLower.empty() || HintLower(item).rfind(prefixLower, 0) == 0)
            {
                matches.push_back(item);
            }
        }
        if (matches.empty())
        {
            break;
        }

        std::wstring replacement;
        bool appendSpace = false;
        if (matches.size() == 1)
        {
            replacement = matches[0];
            appendSpace = true;
        }
        else
        {
            replacement = matches[0];
            for (size_t i = 1; i < matches.size(); ++i)
            {
                size_t n = 0;
                while (n < replacement.size() &&
                       n < matches[i].size() &&
                       replacement[n] == matches[i][n])
                {
                    ++n;
                }
                replacement.resize(n);
            }
            if (HintLower(replacement).size() <= prefixLower.size())
            {
                std::wstring command;
                if (!argsBefore.empty())
                {
                    command = HintCanonicalCommand(argsBefore[0]);
                }
                if (listing != nullptr)
                {
                    *listing = BuildCompletionListing(matches, command, argsBefore);
                }
                if (listed != nullptr)
                {
                    *listed = true;
                }
                break;
            }
        }

        line->replace(tokenStart, tokenEnd - tokenStart, replacement);
        *cursor = tokenStart + replacement.size();
        if (appendSpace && *cursor == line->size())
        {
            line->insert(*cursor, L" ");
            ++(*cursor);
        }
        changed = true;
    } while (false);

    return changed;
}
