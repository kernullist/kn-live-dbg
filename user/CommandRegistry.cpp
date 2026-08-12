#include "CommandRegistry.h"

#include <algorithm>
#include <cwctype>
#include <iostream>
#include <string>
#include <vector>

static constexpr CommandRegistryColor kRegistryColorBlue = 0x0001;
static constexpr CommandRegistryColor kRegistryColorGreen = 0x0002;
static constexpr CommandRegistryColor kRegistryColorRed = 0x0004;
static constexpr CommandRegistryColor kRegistryColorIntensity = 0x0008;

static constexpr CommandRegistryColor kHelpColorDim = kRegistryColorBlue | kRegistryColorGreen;
static constexpr CommandRegistryColor kHelpColorTitle = kRegistryColorGreen | kRegistryColorIntensity;
static constexpr CommandRegistryColor kHelpColorAccent = kRegistryColorBlue | kRegistryColorGreen | kRegistryColorIntensity;
static constexpr CommandRegistryColor kHelpColorNative = kRegistryColorGreen | kRegistryColorIntensity;
static constexpr CommandRegistryColor kHelpColorAlias = kRegistryColorBlue | kRegistryColorGreen | kRegistryColorIntensity;
static constexpr CommandRegistryColor kHelpColorDbgEng = kRegistryColorRed | kRegistryColorGreen | kRegistryColorIntensity;
static constexpr CommandRegistryColor kHelpColorExtension = kRegistryColorBlue | kRegistryColorIntensity;

static CommandRegistryColorPrinter g_ColorPrinter = nullptr;

static void PrintRegistryColoredText(const std::wstring& text, CommandRegistryColor color)
{
    if (g_ColorPrinter != nullptr)
    {
        g_ColorPrinter(text, color);
    }
    else
    {
        std::wcout << text;
    }
}

static void PrintRegistryColoredText(const wchar_t* text, CommandRegistryColor color)
{
    if (text != nullptr)
    {
        PrintRegistryColoredText(std::wstring(text), color);
    }
}

static const wchar_t* SupportText(CommandSupport support)
{
    const wchar_t* text = L"native";

    if (support == CommandSupport::Alias)
    {
        text = L"alias";
    }
    else if (support == CommandSupport::DbgEng)
    {
        text = L"dbgeng";
    }
    else if (support == CommandSupport::Extension)
    {
        text = L"extension";
    }

    return text;
}

static CommandRegistryColor SupportColor(CommandSupport support)
{
    CommandRegistryColor color = kHelpColorNative;

    if (support == CommandSupport::Alias)
    {
        color = kHelpColorAlias;
    }
    else if (support == CommandSupport::DbgEng)
    {
        color = kHelpColorDbgEng;
    }
    else if (support == CommandSupport::Extension)
    {
        color = kHelpColorExtension;
    }

    return color;
}

static void PrintSupportTag(CommandSupport support)
{
    std::wcout << L"[";
    PrintRegistryColoredText(SupportText(support), SupportColor(support));
    std::wcout << L"]";
}

static std::wstring CommandSectionKey(const CommandInfo& info)
{
    std::wstring group = info.Group != nullptr ? info.Group : L"";
    std::wstring key = L"other";

    if (group == L"session" || group == L"version" || group == L"target")
    {
        key = L"session";
    }
    else if (group == L"symbols" || group == L"type")
    {
        key = L"symbols";
    }
    else if (group == L"memory" || group == L"search")
    {
        key = L"memory";
    }
    else if (group == L"kernel")
    {
        key = L"kernel";
    }
    else if (group == L"ai")
    {
        key = L"ai";
    }
    else if (group == L"expression")
    {
        key = L"expression";
    }
    else if (group == L"code")
    {
        key = L"code";
    }
    else if (group == L"script" || group == L"alias" || group == L"breakpoint" ||
             group == L"execution" || group == L"stack" || group == L"register" ||
             group == L"exception" || group == L"locals" || group == L"data-model" ||
             group == L"source" || group == L"selector" || group == L"port" ||
             group == L"control")
    {
        key = L"dbgeng";
    }

    return key;
}

struct CommandSummarySection
{
    const wchar_t* Key;
    const wchar_t* Title;
    const wchar_t* Description;
    CommandRegistryColor Color;
};

static const CommandSummarySection kCommandSummarySections[] =
{
    {
        L"session",
        L"Session, target, and backend",
        L"lifecycle, driver/service state, backend routing, target identity",
        kHelpColorTitle
    },
    {
        L"symbols",
        L"Symbols and types",
        L"module lists, symbol lookup, symbol paths, dt/dtx type inspection",
        kHelpColorAccent
    },
    {
        L"memory",
        L"Virtual and physical memory",
        L"read, write, search, fill, move, translate, dump, and process-context commands",
        kHelpColorNative
    },
    {
        L"kernel",
        L"Kernel inspection and security",
        L"callbacks, process/VAD/thread triage, integrity scanners, ETW, WNF, pool, BYOVD",
        kHelpColorDbgEng
    },
    {
        L"ai",
        L"AI assistance",
        L"provider config, command planning, evidence explanation, reports, transcript/audit",
        kHelpColorExtension
    },
    {
        L"code",
        L"Disassembly and code",
        L"native disassembly plus DbgEng code commands when help all is requested",
        kHelpColorAccent
    },
    {
        L"expression",
        L"Expressions",
        L"numeric or symbol expression evaluation and number-base control",
        kHelpColorTitle
    },
    {
        L"dbgeng",
        L"DbgEng and WinDbg stop-state",
        L"breakpoints, stepping, registers, stack, source, data model, scripts, aliases",
        kHelpColorDbgEng
    },
    {
        L"other",
        L"Other commands",
        L"miscellaneous registered commands",
        kHelpColorDim
    }
};

static const wchar_t* kRequiresDbgEng =
    L"routed to DbgEng for KD stop-state semantics";

static const wchar_t* kRequiresParser =
    L"routed to DbgEng for full WinDbg parser semantics";

void CommandRegistry::SetColorPrinter(CommandRegistryColorPrinter printer)
{
    g_ColorPrinter = printer;
}

static CommandInfo Make(const wchar_t* name, const wchar_t* canonical, const wchar_t* group, const wchar_t* summary, CommandSupport support)
{
    return CommandInfo{name, canonical, group, summary, support};
}

const std::vector<CommandInfo>& CommandRegistry::Commands()
{
    static const std::vector<CommandInfo> commands =
    {
        Make(L"cls", L"cls", L"session", L"clear the console screen", CommandSupport::Native),
        Make(L"$<", L"$<", L"script", kRequiresParser, CommandSupport::DbgEng),
        Make(L"$><", L"$><", L"script", kRequiresParser, CommandSupport::DbgEng),
        Make(L"$$<", L"$$<", L"script", kRequiresParser, CommandSupport::DbgEng),
        Make(L"$$><", L"$$><", L"script", kRequiresParser, CommandSupport::DbgEng),
        Make(L"$$>a<", L"$$>a<", L"script", kRequiresParser, CommandSupport::DbgEng),
        Make(L"?", L"?", L"expression", L"help or numeric/symbol expression evaluation", CommandSupport::Native),
        Make(L"??", L"??", L"expression", L"evaluate expression natively or through DbgEng", CommandSupport::Native),
        Make(L"#", L"#", L"search", kRequiresParser, CommandSupport::DbgEng),
        Make(L"||", L"||", L"target", L"single local live system status", CommandSupport::Native),
        Make(L"||s", L"||s", L"target", L"show local live system status", CommandSupport::Native),
        Make(L"|", L"|", L"target", L"show current local process context", CommandSupport::Native),
        Make(L"|s", L"|s", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~", L"~", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~e", L"~e", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~f", L"~f", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~u", L"~u", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~n", L"~n", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~m", L"~m", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"~s", L"~s", L"target", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"a", L"a", L"code", kRequiresParser, CommandSupport::DbgEng),
        Make(L"ad", L"ad", L"alias", kRequiresParser, CommandSupport::DbgEng),
        Make(L"ah", L"ah", L"alias", kRequiresParser, CommandSupport::DbgEng),
        Make(L"al", L"al", L"alias", kRequiresParser, CommandSupport::DbgEng),
        Make(L"as", L"as", L"alias", kRequiresParser, CommandSupport::DbgEng),
        Make(L"ba", L"ba", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bc", L"bc", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bd", L"bd", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"be", L"be", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bl", L"bl", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bp", L"bp", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bu", L"bu", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bm", L"bm", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"br", L"br", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bs", L"bs", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"bsc", L"bsc", L"breakpoint", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"c", L"c", L"memory", L"compare memory", CommandSupport::Native),
        Make(L"d", L"d", L"memory", L"display memory", CommandSupport::Native),
        Make(L"da", L"da", L"memory", L"display ASCII string", CommandSupport::Native),
        Make(L"db", L"db", L"memory", L"display bytes", CommandSupport::Native),
        Make(L"dc", L"dc", L"memory", L"display dwords and characters", CommandSupport::Native),
        Make(L"dd", L"dd", L"memory", L"display dwords", CommandSupport::Native),
        Make(L"dD", L"dD", L"memory", L"display double-width values through qword view", CommandSupport::Alias),
        Make(L"df", L"df", L"memory", L"display float values as raw dwords", CommandSupport::Native),
        Make(L"dp", L"dp", L"memory", L"display pointer-sized values", CommandSupport::Native),
        Make(L"dq", L"dq", L"memory", L"display qwords", CommandSupport::Native),
        Make(L"du", L"du", L"memory", L"display UTF-16 string", CommandSupport::Native),
        Make(L"dw", L"dw", L"memory", L"display words", CommandSupport::Native),
        Make(L"dW", L"dW", L"memory", L"display wide words", CommandSupport::Alias),
        Make(L"dyb", L"dyb", L"memory", L"display binary bytes", CommandSupport::Native),
        Make(L"dyd", L"dyd", L"memory", L"display binary dwords", CommandSupport::Native),
        Make(L"dda", L"dda", L"memory", L"display referenced memory", CommandSupport::Native),
        Make(L"ddp", L"ddp", L"memory", L"display referenced pointers", CommandSupport::Native),
        Make(L"ddu", L"ddu", L"memory", L"display referenced Unicode", CommandSupport::Native),
        Make(L"dpa", L"dpa", L"memory", L"display referenced ASCII", CommandSupport::Native),
        Make(L"dpp", L"dpp", L"memory", L"display referenced pointers", CommandSupport::Native),
        Make(L"dpu", L"dpu", L"memory", L"display referenced Unicode", CommandSupport::Native),
        Make(L"dqa", L"dqa", L"memory", L"display referenced ASCII", CommandSupport::Native),
        Make(L"dqp", L"dqp", L"memory", L"display referenced pointers", CommandSupport::Native),
        Make(L"dqu", L"dqu", L"memory", L"display referenced Unicode", CommandSupport::Native),
        Make(L"dds", L"dds", L"memory", L"display dwords and symbols", CommandSupport::Native),
        Make(L"dps", L"dps", L"memory", L"display pointers and symbols", CommandSupport::Native),
        Make(L"dqs", L"dqs", L"memory", L"display qwords and symbols", CommandSupport::Native),
        Make(L"phys", L"phys", L"memory", L"display physical bytes", CommandSupport::Native),
        Make(L"pdb", L"pdb", L"memory", L"display physical bytes", CommandSupport::Native),
        Make(L"pdw", L"pdw", L"memory", L"display physical words", CommandSupport::Native),
        Make(L"pdd", L"pdd", L"memory", L"display physical dwords", CommandSupport::Native),
        Make(L"pdq", L"pdq", L"memory", L"display physical qwords", CommandSupport::Native),
        Make(L"!db", L"!db", L"memory", L"display physical bytes", CommandSupport::Native),
        Make(L"!dw", L"!dw", L"memory", L"display physical words", CommandSupport::Native),
        Make(L"!dd", L"!dd", L"memory", L"display physical dwords", CommandSupport::Native),
        Make(L"!dq", L"!dq", L"memory", L"display physical qwords", CommandSupport::Native),
        Make(L"probe", L"probe", L"session", L"manage positive-control test driver", CommandSupport::Native),
        Make(L"procctx", L"procctx", L"memory", L"set process DTB context for vtop", CommandSupport::Native),
        Make(L"peb", L"peb", L"memory", L"enter physical byte values", CommandSupport::Native),
        Make(L"pew", L"pew", L"memory", L"enter physical word values", CommandSupport::Native),
        Make(L"ped", L"ped", L"memory", L"enter physical dword values", CommandSupport::Native),
        Make(L"peq", L"peq", L"memory", L"enter physical qword values", CommandSupport::Native),
        Make(L"!eb", L"!eb", L"memory", L"enter physical byte values", CommandSupport::Native),
        Make(L"!ew", L"!ew", L"memory", L"enter physical word values", CommandSupport::Native),
        Make(L"!ed", L"!ed", L"memory", L"enter physical dword values", CommandSupport::Native),
        Make(L"!eq", L"!eq", L"memory", L"enter physical qword values", CommandSupport::Native),
        Make(L"vtop", L"vtop", L"memory", L"translate virtual address to physical address", CommandSupport::Native),
        Make(L"dg", L"dg", L"selector", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"dl", L"dl", L"memory", kRequiresParser, CommandSupport::DbgEng),
        Make(L"ds", L"ds", L"memory", L"display counted string as ASCII", CommandSupport::Native),
        Make(L"dS", L"dS", L"memory", L"display counted string as UTF-16", CommandSupport::Alias),
        Make(L"dt", L"dt", L"type", L"display type fields or enumerate type patterns", CommandSupport::Native),
        Make(L"dtx", L"dtx", L"type", L"display type fields through native type reader", CommandSupport::Alias),
        Make(L"callbacks", L"callbacks", L"kernel", L"list callbacks: all|object|registry|process|thread|imageload|minifilter [module]", CommandSupport::Native),
        Make(L"!dml_proc", L"!dml_proc [pid|name]", L"kernel", L"list processes from EPROCESS ActiveProcessLinks, optionally filtered by PID or image-name substring", CommandSupport::Native),
        Make(L"!hunt", L"!hunt", L"kernel", L"scan all processes for masquerade, hidden mapped code, module stomping, and thread/APC evidence", CommandSupport::Native),
        Make(L"!vad", L"!vad [scan|modules|mappedpe] <pid|image|eprocess>", L"kernel", L"walk VADs, detect hidden executable/injected regions, or inventory loader/VAD/memory PE mappings", CommandSupport::Native),
        Make(L"!threads", L"!threads <pid|image|eprocess>", L"kernel", L"walk a process thread list and flag suspicious starts and APC evidence", CommandSupport::Native),
        Make(L"!snapshot", L"!snapshot", L"session", L"capture same-boot baseline evidence snapshots with automatic JSON and Markdown reports", CommandSupport::Native),
        Make(L"!diff", L"!diff", L"session", L"compare snapshots with new-focused same-boot evidence semantics", CommandSupport::Native),
        Make(L"!wfp", L"!wfp", L"kernel", L"enumerate Windows Filtering Platform objects via fwpuclnt.dll", CommandSupport::Native),
        Make(L"!alpc", L"!alpc", L"kernel", L"enumerate ALPC ports, connection pairings, and queue depths from kernel memory", CommandSupport::Native),
        Make(L"!byovd", L"!byovd", L"kernel", L"scan loaded kernel modules against local Microsoft and LOLDrivers BYOVD hash/YARA intelligence", CommandSupport::Native),
        Make(L"!vbs", L"!vbs", L"kernel", L"report VBS, HVCI, MBEC, Secure Kernel, and trustlet state from live kernel memory", CommandSupport::Native),
        Make(L"!ci", L"!ci", L"kernel", L"decode CiOptions bits and report Code Integrity policy state", CommandSupport::Native),
        Make(L"!securekernel", L"!securekernel", L"kernel", L"show Secure Kernel module presence and enumerate IUM trustlets", CommandSupport::Native),
        Make(L"!etw", L"!etw", L"kernel", L"enumerate ETW loggers, integrity, provider DKOM surface, and TI reception cross-view", CommandSupport::Native),
        Make(L"!nmi", L"!nmi", L"kernel", L"walk nt!KiNmiCallbackListHead and annotate registered NMI handlers", CommandSupport::Native),
        Make(L"!msrcheck", L"!msrcheck", L"kernel", L"read SYSCALL MSRs (LSTAR/CSTAR/STAR/FMASK/EFER) and flag entry-pointer hooks or per-CPU divergence", CommandSupport::Native),
        Make(L"!cr", L"!cr", L"kernel", L"read control registers (CR0/CR4/CR8) and flag CR0.WP-off, SMEP/SMAP-off, or per-CPU divergence", CommandSupport::Native),
        Make(L"!ssdt", L"!ssdt", L"kernel", L"walk the native and win32k shadow SSDT and flag service routines outside the expected kernel image", CommandSupport::Native),
        Make(L"!idt", L"!idt", L"kernel", L"walk the boot processor IDT and flag interrupt handlers outside loaded kernel modules", CommandSupport::Native),
        Make(L"!hal", L"!hal", L"kernel", L"check HalDispatchTable / HalPrivateDispatchTable function-pointer ownership", CommandSupport::Native),
        Make(L"!hive", L"!hive", L"kernel", L"walk registry hives and flag GetCellRoutine handlers outside ntoskrnl", CommandSupport::Native),
        Make(L"!token", L"!token", L"kernel", L"inspect process token privilege Present/Enabled masks and high-risk elevation evidence", CommandSupport::Native),
        Make(L"!dpc", L"!dpc", L"kernel", L"enumerate deferred procedure call routines and flag non-image callbacks", CommandSupport::Native),
        Make(L"!timer", L"!timer", L"kernel", L"enumerate kernel timer DPC routines and flag non-image callbacks", CommandSupport::Native),
        Make(L"!workitem", L"!workitem", L"kernel", L"best-effort work-item callback coverage (explicit incomplete on modern threadpools)", CommandSupport::Native),
        Make(L"!fwtable", L"!fwtable", L"kernel", L"walk firmware table provider registrations and annotate handler/DriverObject ownership", CommandSupport::Native),
        Make(L"!module", L"!module", L"kernel", L"check loaded kernel module PE headers and executable section page permissions for W+X integrity drift", CommandSupport::Native),
        Make(L"!driver", L"!driver", L"kernel", L"walk \\Driver objects and flag suspicious DRIVER_OBJECT dispatch targets", CommandSupport::Native),
        Make(L"!address", L"!address", L"memory", L"report canonicality, page-table walk (PML5..PTE), effective R/W/X/U, physical address, owning module and nearest symbol for a virtual address", CommandSupport::Native),
        Make(L"set-ppl-antimalware", L"set-ppl-antimalware", L"session", L"flip _EPROCESS.Protection on KnLiveDbg.exe so it runs as PPL Antimalware (prerequisite for Microsoft-Windows-Threat-Intelligence ETW)", CommandSupport::Native),
        Make(L"!ti", L"!ti", L"kernel", L"subscribe to Microsoft-Windows-Threat-Intelligence ETW; ring + JSONL log + watch filter (start/stop/status/watch/recent/stats/by/grep/save/clear/add/remove)", CommandSupport::Native),
        Make(L"!timeline", L"!timeline", L"session", L"ingest TI and snapshot evidence into a queryable user-mode timeline/graph store", CommandSupport::Native),
        Make(L"!pool", L"!pool", L"kernel", L"enumerate big pool allocations via NtQuerySystemInformation(SystemBigPoolInformation) and filter by tag/size/address/W+X with optional PTE annotation", CommandSupport::Native),
        Make(L"dump-raw", L"dump-raw", L"memory", L"dump a kernel virtual range to file verbatim via the driver ReadMemory IOCTL", CommandSupport::Native),
        Make(L"dump-pe", L"dump-pe", L"memory", L"reconstruct an on-disk PE image from an in-memory loaded kernel PE by walking the section table", CommandSupport::Native),
        Make(L"pool-scan-pe", L"pool-scan-pe", L"kernel", L"scan big pool allocations for hidden / signature-wiped PE images, surfacing reflective-load and unpacker stages", CommandSupport::Native),
        Make(L"!wnf", L"!wnf", L"kernel", L"decode Windows Notification Facility state names and walk live name instances", CommandSupport::Native),
        Make(L"dv", L"dv", L"locals", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"dx", L"dx", L"data-model", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"e", L"e", L"memory", L"enter byte values", CommandSupport::Native),
        Make(L"ea", L"ea", L"memory", L"enter ASCII string", CommandSupport::Native),
        Make(L"eb", L"eb", L"memory", L"enter byte values", CommandSupport::Native),
        Make(L"ed", L"ed", L"memory", L"enter dword values", CommandSupport::Native),
        Make(L"eD", L"eD", L"memory", L"enter double-width values through qword write", CommandSupport::Alias),
        Make(L"ef", L"ef", L"memory", L"enter float raw value", CommandSupport::Native),
        Make(L"ep", L"ep", L"memory", L"enter pointer-sized values", CommandSupport::Native),
        Make(L"eq", L"eq", L"memory", L"enter qword values", CommandSupport::Native),
        Make(L"eu", L"eu", L"memory", L"enter UTF-16 string", CommandSupport::Native),
        Make(L"ew", L"ew", L"memory", L"enter word values", CommandSupport::Native),
        Make(L"eza", L"eza", L"memory", L"enter zero-terminated ASCII string", CommandSupport::Native),
        Make(L"ezu", L"ezu", L"memory", L"enter zero-terminated UTF-16 string", CommandSupport::Native),
        Make(L"f", L"f", L"memory", L"fill memory", CommandSupport::Native),
        Make(L"fp", L"fp", L"memory", L"fill pointer-sized memory", CommandSupport::Native),
        Make(L"g", L"g", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"gc", L"gc", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"gh", L"gh", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"gn", L"gn", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"gN", L"gN", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"gu", L"gu", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ib", L"ib", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"iw", L"iw", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"id", L"id", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"j", L"j", L"control", kRequiresParser, CommandSupport::DbgEng),
        Make(L"k", L"k", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"kb", L"kb", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"kc", L"kc", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"kp", L"kp", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"kP", L"kP", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"kv", L"kv", L"stack", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"l+", L"l+", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"l-", L"l-", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ld", L"ld", L"symbols", L"reload kernel module symbols", CommandSupport::Alias),
        Make(L"lm", L"lm", L"symbols", L"list loaded modules", CommandSupport::Native),
        Make(L"ln", L"ln", L"symbols", L"list nearest symbol", CommandSupport::Native),
        Make(L"ls", L"ls", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lsa", L"lsa", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lsc", L"lsc", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lse", L"lse", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lsf", L"lsf", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lsf-", L"lsf-", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"lsp", L"lsp", L"source", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"m", L"m", L"memory", L"move memory", CommandSupport::Native),
        Make(L"n", L"n", L"expression", L"show or set number base", CommandSupport::Native),
        Make(L"ob", L"ob", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ow", L"ow", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"od", L"od", L"port", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"p", L"p", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"pa", L"pa", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"pc", L"pc", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"pct", L"pct", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ph", L"ph", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"pt", L"pt", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"q", L"q", L"session", L"quit", CommandSupport::Native),
        Make(L"qq", L"qq", L"session", L"quit", CommandSupport::Native),
        Make(L"qd", L"qd", L"session", L"quit and detach equivalent", CommandSupport::Native),
        Make(L"r", L"r", L"register", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"rdmsr", L"rdmsr", L"register", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"rm", L"rm", L"register", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"s", L"s", L"memory", L"search memory", CommandSupport::Native),
        Make(L"so", L"so", L"kernel", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sq", L"sq", L"session", L"set quiet mode", CommandSupport::Native),
        Make(L"ss", L"ss", L"symbols", kRequiresParser, CommandSupport::DbgEng),
        Make(L"sx", L"sx", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sxd", L"sxd", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sxe", L"sxe", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sxi", L"sxi", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sxn", L"sxn", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sxr", L"sxr", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"sx-", L"sx-", L"exception", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"t", L"t", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ta", L"ta", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"tb", L"tb", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"tc", L"tc", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"tct", L"tct", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"th", L"th", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"tt", L"tt", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"u", L"u", L"code", L"unassemble instructions", CommandSupport::Native),
        Make(L"uf", L"uf", L"code", L"unassemble function", CommandSupport::Native),
        Make(L"up", L"up", L"code", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ur", L"ur", L"code", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"ux", L"ux", L"code", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"vercommand", L"vercommand", L"version", L"show command line", CommandSupport::Native),
        Make(L"version", L"version", L"version", L"show tool and driver version", CommandSupport::Native),
        Make(L"vertarget", L"vertarget", L"version", L"show local live target version", CommandSupport::Native),
        Make(L"wrmsr", L"wrmsr", L"register", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"wt", L"wt", L"execution", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"x", L"x", L"symbols", L"examine symbols", CommandSupport::Native),
        Make(L"z", L"z", L"control", kRequiresParser, CommandSupport::DbgEng),
        Make(L".sympath", L".sympath", L"symbols", L"show or set symbol path", CommandSupport::Native),
        Make(L".sympath+", L".sympath+", L"symbols", L"append symbol path", CommandSupport::Native),
        Make(L".reload", L".reload", L"symbols", L"reload kernel modules and symbols", CommandSupport::Native),
        Make(L"sympath", L".sympath", L"symbols", L"show or set symbol path", CommandSupport::Alias),
        Make(L"reload", L".reload", L"symbols", L"reload kernel modules and symbols", CommandSupport::Alias),
        Make(L"modules", L"lm", L"symbols", L"list loaded modules", CommandSupport::Alias),
        Make(L"addr", L"ln", L"symbols", L"resolve address or symbol", CommandSupport::Alias),
        Make(L"ai", L"ai", L"ai", L"configure and query AI assistant providers", CommandSupport::Native),
        Make(L"backend", L"backend", L"session", L"show or set native/dbgeng/auto backend mode", CommandSupport::Native),
        Make(L"byovd", L"byovd", L"kernel", L"scan loaded kernel modules against local Microsoft and LOLDrivers BYOVD hash/YARA intelligence", CommandSupport::Native),
        Make(L"drvstatus", L"drvstatus", L"session", L"show service, owner, handle, and write-gate state", CommandSupport::Native),
        Make(L"mcp", L"mcp", L"session", L"MCP server: on/off/status/client-setup/endpoint (native HTTP; Desktop/legacy bridge fallback)", CommandSupport::Native),
        Make(L"kd", L"kd", L"session", L"execute a raw command through DbgEng", CommandSupport::Native),
        Make(L"kdinit", L"kdinit", L"session", L"initialize local-kernel DbgEng backend", CommandSupport::Native),
        Make(L"kddetach", L"kddetach", L"session", L"end DbgEng session", CommandSupport::Native),
        Make(L"query", L"query", L"memory", L"probe address readability", CommandSupport::Native),
        Make(L"write", L"write", L"memory", L"set native write gate", CommandSupport::Native),
        Make(L"setfield", L"setfield", L"type", L"write a structure field", CommandSupport::Native),
        Make(L"unload", L"unload", L"session", L"stop and delete service", CommandSupport::Native),
        Make(L"home", L"home", L"session", L"redraw startup dashboard", CommandSupport::Native),
        Make(L"log", L"log", L"session", L"mirror console output to a log file (log enable | log disable | log status)", CommandSupport::Native),
        Make(L"dashboard", L"home", L"session", L"redraw startup dashboard", CommandSupport::Alias),
        Make(L"help", L"help", L"session", L"show help", CommandSupport::Native),
        Make(L"exit", L"q", L"session", L"quit", CommandSupport::Alias),
        Make(L"quit", L"q", L"session", L"quit", CommandSupport::Alias)
    };

    return commands;
}

std::wstring CommandRegistry::Normalize(const std::wstring& command)
{
    std::wstring normalized = command;

    for (wchar_t& ch : normalized)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    if (normalized == L"dd" || normalized == L"dw" || normalized == L"ed" || normalized == L"ef")
    {
        return normalized;
    }

    return normalized;
}

const CommandInfo* CommandRegistry::Find(const std::wstring& command)
{
    const CommandInfo* found = nullptr;
    std::wstring normalized = Normalize(command);

    for (const CommandInfo& info : Commands())
    {
        if (std::wstring(info.Name) == command)
        {
            found = &info;
            break;
        }
    }

    if (found == nullptr)
    {
        for (const CommandInfo& info : Commands())
        {
            if (Normalize(info.Name) == normalized)
            {
                found = &info;
                break;
            }
        }
    }

    return found;
}

bool CommandRegistry::IsKnown(const std::wstring& command)
{
    bool known = false;

    do
    {
        if (!command.empty() && command[0] == L'!')
        {
            known = true;
            break;
        }

        if (!command.empty() && command[0] == L'.')
        {
            known = true;
            break;
        }

        known = Find(command) != nullptr;
    } while (false);

    return known;
}

void CommandRegistry::PrintSummary(bool includeDbgEng)
{
    size_t visibleCount = 0;
    size_t maxNameWidth = 0;

    for (const CommandInfo& info : Commands())
    {
        if (!includeDbgEng && info.Support == CommandSupport::DbgEng)
        {
            continue;
        }

        ++visibleCount;

        if (info.Name != nullptr)
        {
            maxNameWidth = std::max(maxNameWidth, std::wstring(info.Name).size());
        }
    }

    if (maxNameWidth < 12)
    {
        maxNameWidth = 12;
    }

    PrintRegistryColoredText(L"registered commands", kHelpColorTitle);
    std::wcout << L" (" << visibleCount << L")\n";
    std::wcout << L"  ";
    PrintSupportTag(CommandSupport::Native);
    std::wcout << L" KnLiveDbg implementation   ";
    PrintSupportTag(CommandSupport::Alias);
    std::wcout << L" local alias   ";
    PrintSupportTag(CommandSupport::DbgEng);
    std::wcout << L" DbgEng-routed\n";
    std::wcout << L"  detail: type ";
    PrintRegistryColoredText(L"help <command>", kHelpColorAccent);
    std::wcout << L" or ";
    PrintRegistryColoredText(L"<command> help", kHelpColorAccent);
    std::wcout << L" for command-family syntax\n";

    for (const CommandSummarySection& section : kCommandSummarySections)
    {
        size_t sectionCount = 0;

        for (const CommandInfo& info : Commands())
        {
            if (!includeDbgEng && info.Support == CommandSupport::DbgEng)
            {
                continue;
            }

            if (CommandSectionKey(info) == section.Key)
            {
                ++sectionCount;
            }
        }

        if (sectionCount == 0)
        {
            continue;
        }

        std::wcout << L"\n";
        PrintRegistryColoredText(section.Title, section.Color);
        std::wcout << L" (" << sectionCount << L")\n";
        std::wcout << L"  " << section.Description << L"\n";

        for (const CommandInfo& info : Commands())
        {
            if (!includeDbgEng && info.Support == CommandSupport::DbgEng)
            {
                continue;
            }

            if (CommandSectionKey(info) != section.Key)
            {
                continue;
            }

            std::wstring name = info.Name != nullptr ? info.Name : L"";
            std::wcout << L"  ";
            PrintRegistryColoredText(name, info.Support == CommandSupport::DbgEng ? kHelpColorDbgEng : kHelpColorAccent);

            if (name.size() < maxNameWidth)
            {
                std::wcout << std::wstring(maxNameWidth - name.size(), L' ');
            }

            std::wcout << L" ";
            PrintSupportTag(info.Support);

            if (info.Support == CommandSupport::Alias &&
                info.Canonical != nullptr &&
                std::wstring(info.Canonical) != name)
            {
                std::wcout << L" -> ";
                PrintRegistryColoredText(info.Canonical, kHelpColorAccent);
            }

            if (info.Summary != nullptr)
            {
                std::wcout << L"  " << info.Summary;
            }

            std::wcout << L"\n";
        }
    }

    if (includeDbgEng)
    {
        std::wcout << L"\n";
        PrintRegistryColoredText(L"Extension commands", kHelpColorDbgEng);
        std::wcout << L"\n  ";
        PrintRegistryColoredText(L"!<extension>", kHelpColorDbgEng);
        std::wcout << L" ";
        PrintSupportTag(CommandSupport::Extension);
        std::wcout << L"  routed to DbgEng extension host\n";
    }
}

void CommandRegistry::PrintCommandStatus(const std::wstring& command)
{
    do
    {
        if (!command.empty() && command[0] == L'!')
        {
            const CommandInfo* meta = Find(command);
            if (meta != nullptr && meta->Support != CommandSupport::DbgEng)
            {
                PrintRegistryColoredText(meta->Name, kHelpColorAccent);
                std::wcout << L": ";
                PrintSupportTag(meta->Support);
                std::wcout << L" " << meta->Summary << L"\n";
            }
            else
            {
                PrintRegistryColoredText(command, kHelpColorDbgEng);
                std::wcout << L": ";
                PrintSupportTag(CommandSupport::DbgEng);
                std::wcout << L" routed to DbgEng extension host in auto/dbgeng mode\n";
            }
            break;
        }

        if (!command.empty() && command[0] == L'.')
        {
            const CommandInfo* meta = Find(command);
            if (meta != nullptr)
            {
                PrintRegistryColoredText(meta->Name, kHelpColorAccent);
                std::wcout << L": ";
                PrintSupportTag(meta->Support);
                std::wcout << L" " << meta->Summary << L"\n";
            }
            else
            {
                PrintRegistryColoredText(command, kHelpColorDbgEng);
                std::wcout << L": ";
                PrintSupportTag(CommandSupport::DbgEng);
                std::wcout << L" routed to DbgEng meta-command handling in auto/dbgeng mode\n";
            }
            break;
        }

        const CommandInfo* info = Find(command);
        if (info == nullptr)
        {
            PrintRegistryColoredText(command, kHelpColorDim);
            std::wcout << L": unknown command\n";
            break;
        }

        PrintRegistryColoredText(info->Name, info->Support == CommandSupport::DbgEng ? kHelpColorDbgEng : kHelpColorAccent);
        std::wcout << L": ";
        PrintSupportTag(info->Support);

        if (info->Support == CommandSupport::Alias &&
            info->Canonical != nullptr &&
            std::wstring(info->Canonical) != std::wstring(info->Name))
        {
            std::wcout << L" -> ";
            PrintRegistryColoredText(info->Canonical, kHelpColorAccent);
        }

        std::wcout << L" " << info->Summary << L"\n";
    } while (false);
}
