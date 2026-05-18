#include "CommandRegistry.h"

#include <cwctype>
#include <iostream>

static const wchar_t* kRequiresDbgEng =
    L"routed to DbgEng for KD stop-state semantics";

static const wchar_t* kRequiresParser =
    L"routed to DbgEng for full WinDbg parser semantics";

static CommandInfo Make(const wchar_t* name, const wchar_t* canonical, const wchar_t* group, const wchar_t* summary, CommandSupport support)
{
    return CommandInfo{name, canonical, group, summary, support};
}

const std::vector<CommandInfo>& CommandRegistry::Commands()
{
    static const std::vector<CommandInfo> commands =
    {
        Make(L"enter", L"enter", L"session", L"repeat last command", CommandSupport::Native),
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
        Make(L"probe", L"probe", L"session", L"manage positive-control test driver", CommandSupport::Native),
        Make(L"procctx", L"procctx", L"memory", L"set process DTB context for vtop", CommandSupport::Native),
        Make(L"peb", L"peb", L"memory", L"enter physical byte values", CommandSupport::Native),
        Make(L"pew", L"pew", L"memory", L"enter physical word values", CommandSupport::Native),
        Make(L"ped", L"ped", L"memory", L"enter physical dword values", CommandSupport::Native),
        Make(L"peq", L"peq", L"memory", L"enter physical qword values", CommandSupport::Native),
        Make(L"vtop", L"vtop", L"memory", L"translate virtual address to physical address", CommandSupport::Native),
        Make(L"!vtop", L"!vtop", L"memory", L"translate virtual address to physical address", CommandSupport::Native),
        Make(L"dg", L"dg", L"selector", kRequiresDbgEng, CommandSupport::DbgEng),
        Make(L"dl", L"dl", L"memory", kRequiresParser, CommandSupport::DbgEng),
        Make(L"ds", L"ds", L"memory", L"display counted string as ASCII", CommandSupport::Native),
        Make(L"dS", L"dS", L"memory", L"display counted string as UTF-16", CommandSupport::Alias),
        Make(L"dt", L"dt", L"type", L"display type fields or enumerate type patterns", CommandSupport::Native),
        Make(L"dtx", L"dtx", L"type", L"display type fields through native type reader", CommandSupport::Alias),
        Make(L"callbacks", L"callbacks", L"kernel", L"list callbacks: all|ob|registry|process|minifilter|json", CommandSupport::Native),
        Make(L"kcallbacks", L"callbacks", L"kernel", L"alias for callbacks [scope]", CommandSupport::Alias),
        Make(L"cb", L"callbacks", L"kernel", L"alias for callbacks [scope]", CommandSupport::Alias),
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
        Make(L"kd", L"kd", L"session", L"execute a raw command through DbgEng", CommandSupport::Native),
        Make(L"kdinit", L"kdinit", L"session", L"initialize local-kernel DbgEng backend", CommandSupport::Native),
        Make(L"kddetach", L"kddetach", L"session", L"end DbgEng session", CommandSupport::Native),
        Make(L"query", L"query", L"memory", L"probe address readability", CommandSupport::Native),
        Make(L"write", L"write", L"memory", L"set native write gate", CommandSupport::Native),
        Make(L"setfield", L"setfield", L"type", L"write a structure field", CommandSupport::Native),
        Make(L"unload", L"unload", L"session", L"stop and delete service", CommandSupport::Native),
        Make(L"home", L"home", L"session", L"redraw startup dashboard", CommandSupport::Native),
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
    std::wcout << L"registered commands:\n";

    for (const CommandInfo& info : Commands())
    {
        if (!includeDbgEng && info.Support == CommandSupport::DbgEng)
        {
            continue;
        }

        const wchar_t* state = L"native";
        if (info.Support == CommandSupport::Alias)
        {
            state = L"alias";
        }
        else if (info.Support == CommandSupport::DbgEng)
        {
            state = L"dbgeng";
        }
        else if (info.Support == CommandSupport::Extension)
        {
            state = L"extension";
        }

        std::wcout << L"  " << info.Name << L" [" << state << L"] " << info.Summary << L"\n";
    }

    std::wcout << L"  !<extension> [dbgeng] routed to DbgEng extension host\n";
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
                std::wcout << meta->Name << L": native, " << meta->Summary << L"\n";
            }
            else
            {
                std::wcout << command << L": dbgeng, routed to DbgEng extension host in auto/dbgeng mode\n";
            }
            break;
        }

        if (!command.empty() && command[0] == L'.')
        {
            const CommandInfo* meta = Find(command);
            if (meta != nullptr)
            {
                std::wcout << meta->Name << L": native, " << meta->Summary << L"\n";
            }
            else
            {
                std::wcout << command << L": dbgeng, routed to DbgEng meta-command handling in auto/dbgeng mode\n";
            }
            break;
        }

        const CommandInfo* info = Find(command);
        if (info == nullptr)
        {
            std::wcout << command << L": unknown command\n";
            break;
        }

        const wchar_t* state = L"native";
        if (info->Support == CommandSupport::Alias)
        {
            state = L"alias";
        }
        else if (info->Support == CommandSupport::DbgEng)
        {
            state = L"dbgeng";
        }

        std::wcout << info->Name << L": " << state << L", " << info->Summary << L"\n";
    } while (false);
}
