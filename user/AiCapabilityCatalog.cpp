#include "AiCapabilityCatalog.h"

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <vector>

namespace
{
    std::wstring CatalogLower(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
        return lowered;
    }

    std::wstring CatalogTrim(const std::wstring& value)
    {
        size_t begin = 0;
        while (begin < value.size() && iswspace(value[begin]) != 0)
        {
            ++begin;
        }
        size_t end = value.size();
        while (end > begin && iswspace(value[end - 1]) != 0)
        {
            --end;
        }
        return value.substr(begin, end - begin);
    }

    bool ContainsNoCase(const std::wstring& text, const std::wstring& needle)
    {
        if (needle.empty())
        {
            return false;
        }
        return CatalogLower(text).find(CatalogLower(needle)) != std::wstring::npos;
    }

    bool StartsWithNoCase(const std::wstring& text, const std::wstring& prefix)
    {
        std::wstring lowered = CatalogTrim(CatalogLower(text));
        std::wstring needle = CatalogLower(prefix);
        if (lowered == needle)
        {
            return true;
        }
        return lowered.size() > needle.size() &&
            lowered.rfind(needle + L" ", 0) == 0;
    }

    void ReplaceAll(
        std::wstring* text,
        const std::wstring& from,
        const std::wstring& to)
    {
        do
        {
            if (text == nullptr || from.empty())
            {
                break;
            }
            const std::wstring loweredFrom = CatalogLower(from);
            size_t pos = 0;
            while (pos < text->size())
            {
                const std::wstring lowered = CatalogLower(*text);
                pos = lowered.find(loweredFrom, pos);
                if (pos == std::wstring::npos)
                {
                    break;
                }
                text->replace(pos, from.size(), to);
                pos += to.size();
            }
        } while (false);
    }

    bool HasImageOrDriverFile(const std::wstring& query)
    {
        return ContainsNoCase(query, L".sys") ||
            ContainsNoCase(query, L".exe") ||
            ContainsNoCase(query, L".dll") ||
            ContainsNoCase(query, L".drv");
    }

    bool AliasHitsQuery(const std::wstring& loweredQuery, const std::wstring& alias)
    {
        bool hit = false;
        do
        {
            const std::wstring needle = CatalogLower(CatalogTrim(alias));
            if (needle.empty())
            {
                break;
            }
            if (loweredQuery == needle)
            {
                hit = true;
                break;
            }
            if (loweredQuery.size() > needle.size() &&
                loweredQuery.rfind(needle + L" ", 0) == 0)
            {
                hit = true;
                break;
            }
            if (needle.find(L' ') != std::wstring::npos)
            {
                hit = loweredQuery.find(needle) != std::wstring::npos;
                break;
            }
            size_t pos = 0;
            while (pos < loweredQuery.size())
            {
                pos = loweredQuery.find(needle, pos);
                if (pos == std::wstring::npos)
                {
                    break;
                }
                const bool beforeOk = pos == 0 || iswalnum(loweredQuery[pos - 1]) == 0;
                const bool afterOk = pos + needle.size() == loweredQuery.size() ||
                    iswalnum(loweredQuery[pos + needle.size()]) == 0;
                if (beforeOk && afterOk)
                {
                    hit = true;
                    break;
                }
                ++pos;
            }
        } while (false);
        return hit;
    }

    std::vector<std::wstring> CatalogTokens(const std::wstring& query)
    {
        std::vector<std::wstring> tokens;
        std::wstring current;
        for (wchar_t ch : CatalogTrim(query))
        {
            if (iswspace(ch) != 0 || ch == L',' || ch == L';')
            {
                if (!current.empty())
                {
                    tokens.push_back(current);
                    current.clear();
                }
            }
            else
            {
                current.push_back(ch);
            }
        }
        if (!current.empty())
        {
            tokens.push_back(current);
        }
        return tokens;
    }

    bool TokenStartsWithNoCase(const std::wstring& token, const std::wstring& prefix)
    {
        const std::wstring lowered = CatalogLower(token);
        const std::wstring needle = CatalogLower(prefix);
        return !needle.empty() &&
            lowered.size() >= needle.size() &&
            lowered.compare(0, needle.size(), needle) == 0;
    }

    bool IsDisableActionToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        bool match = false;
        if (lowered == L"disabled" || lowered == L"disablement")
        {
            match = false;
        }
        else if (lowered == L"disable" ||
                 lowered == L"disable-all" ||
                 lowered == L"disableall")
        {
            match = true;
        }
        else if (TokenStartsWithNoCase(lowered, L"disable") && lowered.size() > 7)
        {
            match = true;
        }
        else if (TokenStartsWithNoCase(lowered, L"\xBE44\xD65C\xC131") ||
                 TokenStartsWithNoCase(lowered, L"\xBB34\xB825\xD654"))
        {
            match = true;
        }
        return match;
    }

    bool IsEnableActionToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        bool match = false;
        if (lowered == L"enabled" || lowered == L"enablement")
        {
            match = false;
        }
        else if (IsDisableActionToken(token))
        {
            match = false;
        }
        else if (lowered == L"enable" ||
                 lowered == L"enable-all" ||
                 lowered == L"enableall" ||
                 lowered == L"restore")
        {
            match = true;
        }
        else if (TokenStartsWithNoCase(lowered, L"enable") && lowered.size() > 6)
        {
            match = true;
        }
        else if (TokenStartsWithNoCase(lowered, L"\xD65C\xC131") ||
                 TokenStartsWithNoCase(lowered, L"\xBCF5\xC6D0"))
        {
            match = true;
        }
        return match;
    }

    bool IsMutationActionToken(const std::wstring& token)
    {
        return IsDisableActionToken(token) || IsEnableActionToken(token);
    }

    bool IsTiSurfaceToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        return lowered == L"ti" ||
            lowered == L"!ti" ||
            lowered == L"threat-intelligence" ||
            lowered == L"threatintelligence";
    }

    bool IsTimelineSurfaceToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        return lowered == L"timeline" || lowered == L"!timeline";
    }

    bool IsStartToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"start";
    }

    bool IsStopToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"stop";
    }

    bool IsOnToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"on";
    }

    bool IsOffToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"off";
    }

    bool IsLiveToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"live";
    }

    bool IsPplToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        return lowered == L"ppl" ||
            lowered == L"set-ppl" ||
            lowered == L"set-ppl-antimalware";
    }

    bool IsByovdToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        return lowered == L"byovd" || lowered == L"!byovd";
    }

    bool IsFixtureToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"fixture";
    }

    bool IsMcpToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"mcp";
    }

    bool IsProbeToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"probe";
    }

    bool IsWriteGateToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"write";
    }

    bool IsBackendToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"backend";
    }

    bool IsResetToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"reset";
    }

    bool IsClearToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"clear";
    }

    bool IsLoadToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"load";
    }

    bool IsUnloadToken(const std::wstring& token)
    {
        return CatalogLower(CatalogTrim(token)) == L"unload";
    }

    bool IsMutationReservedToken(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        static const wchar_t* words[] =
        {
            L"log", L"logging", L"backend", L"probe", L"transcript", L"audit",
            L"ti", L"!ti", L"timeline", L"!timeline", L"live", L"start", L"stop",
            L"on", L"off", L"status", L"session", L"ppl", L"set-ppl", L"set-ppl-antimalware",
            L"antimalware", L"byovd", L"!byovd", L"fixture", L"mcp", L"write", L"reset", L"clear",
            L"load", L"unload"
        };
        for (const wchar_t* word : words)
        {
            if (lowered == word)
            {
                return true;
            }
        }
        return false;
    }

    std::wstring ClassifyMutationSurface(const std::wstring& token)
    {
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        std::wstring surface;
        if (lowered == L"minifilter" ||
            lowered == L"minifilters" ||
            lowered == L"!minifilter" ||
            lowered == L"fltmgr" ||
            lowered == L"!fltmgr" ||
            lowered == L"\xBBF8\xB2C8\xD544\xD130")
        {
            surface = L"minifilter";
        }
        else if (lowered == L"irp" || lowered == L"irps")
        {
            surface = L"irp";
        }
        else if (lowered == L"object" ||
                 lowered == L"objects" ||
                 lowered == L"object-callbacks" ||
                 lowered == L"object-manager")
        {
            surface = L"object";
        }
        else if (lowered == L"registry" || lowered == L"cm")
        {
            surface = L"registry";
        }
        else if (lowered == L"process" || lowered == L"processes")
        {
            surface = L"process";
        }
        else if (lowered == L"thread" || lowered == L"threads")
        {
            surface = L"thread";
        }
        else if (lowered == L"imageload" ||
                 lowered == L"image-load" ||
                 lowered == L"image_load")
        {
            surface = L"imageload";
        }
        else if (lowered == L"callback" ||
                 lowered == L"callbacks" ||
                 lowered == L"!callbacks" ||
                 lowered == L"\xCF5C\xBC31")
        {
            surface = L"callbacks";
        }
        return surface;
    }

    bool IsMutationStopword(const std::wstring& token)
    {
        static const wchar_t* words[] =
        {
            L"the", L"a", L"an", L"of", L"for", L"to", L"from", L"with", L"in", L"on",
            L"and", L"or", L"please", L"me", L"my", L"this", L"that", L"those",
            L"all", L"every", L"each", L"both", L"pre", L"post",
            L"handler", L"handlers", L"registration", L"registrations",
            L"filter", L"filters", L"filesystem", L"fs", L"slot", L"slots",
            L"chain", L"module", L"driver", L"drivers", L"notify", L"notifications",
            L"show", L"list", L"enumerate", L"check",
            L"log", L"logging", L"backend", L"probe", L"transcript", L"audit",
            L"ti", L"timeline", L"live", L"start", L"stop", L"on", L"off", L"status",
            L"ppl", L"antimalware", L"fixture", L"byovd", L"mcp", L"write", L"reset", L"clear",
            L"load", L"unload",
            L"\xBAA8\xB450", L"\xC804\xBD80", L"\xD578\xB4E4\xB7EC", L"\xD574\xC918"
        };
        const std::wstring lowered = CatalogLower(CatalogTrim(token));
        for (const wchar_t* word : words)
        {
            if (lowered == CatalogLower(word))
            {
                return true;
            }
        }
        if (!lowered.empty() && lowered[0] == L'/')
        {
            return true;
        }
        return lowered.rfind(L"irp_mj", 0) == 0;
    }

    std::wstring StripDriverFileSuffix(const std::wstring& token)
    {
        std::wstring name = CatalogTrim(token);
        const std::wstring lowered = CatalogLower(name);
        static const wchar_t* suffixes[] = { L".sys", L".dll", L".drv", L".exe" };
        for (const wchar_t* suffix : suffixes)
        {
            const size_t suffixLen = std::wstring(suffix).size();
            if (lowered.size() > suffixLen &&
                lowered.compare(lowered.size() - suffixLen, suffixLen, suffix) == 0)
            {
                name = name.substr(0, name.size() - suffixLen);
                break;
            }
        }
        return name;
    }

    bool IsSafeMutationModule(const std::wstring& token)
    {
        bool ok = false;
        do
        {
            const std::wstring name = StripDriverFileSuffix(token);
            if (name.empty() || name.size() > 64)
            {
                break;
            }
            if (name.find_first_of(L"\"\\;|&<> \t\r\n") != std::wstring::npos)
            {
                break;
            }
            if (iswalnum(name[0]) == 0 && name[0] != L'_')
            {
                break;
            }
            bool valid = true;
            for (wchar_t ch : name)
            {
                if (iswalnum(ch) == 0 && ch != L'_' && ch != L'-' && ch != L'.')
                {
                    valid = false;
                    break;
                }
            }
            if (!valid)
            {
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    const AiCapabilityToolDef kTools[] =
    {
        { L"process.find", L"Find live processes by image, PID, or EPROCESS.", L"image, pid, eprocess", L"!dml_proc", AiCapabilityCost::Cheap },
        { L"process.describe", L"Print process fields (pid, image, eprocess, dtb, peb, parent, threads).", L"source like $0, or image/pid/eprocess; fields array", L"!dml_proc", AiCapabilityCost::Cheap },
        { L"type.describe", L"Dump a kernel structure with dt.", L"source/address/eprocess, type, fields array", L"dt", AiCapabilityCost::Cheap },
        { L"callbacks.list", L"List kernel callbacks.", L"scope all|object|registry|process|thread|imageload|minifilter, optional module", L"!callbacks", AiCapabilityCost::Cheap },
        { L"wfp.list", L"List WFP objects via BFE.", L"scope providers|sublayers|callouts|filters|layers, optional module/layer", L"!wfp", AiCapabilityCost::Cheap },
        { L"wfp.kernel_callouts", L"Resolve kernel-mode WFP classify/notify/flowDelete pointers.", L"{}", L"!wfp kernelcallouts", AiCapabilityCost::Cheap },
        { L"alpc.list", L"List ALPC ports and connections.", L"scope ports|connections, optional name, pid", L"!alpc", AiCapabilityCost::Cheap },
        { L"vad.list", L"List VADs, scan injected/hidden executable regions, or inventory mapped PEs.", L"image/pid/eprocess/source, mode list|scan|modules, exec/private/wx/pe/hiddenpte/summary, limit", L"!vad", AiCapabilityCost::Cheap },
        { L"threads.list", L"List process threads, start addresses, APC and stack evidence.", L"image/pid/eprocess/source, apc, stacks, limit", L"!threads", AiCapabilityCost::Cheap },
        { L"etw.integrity", L"Check ETW logger / GetCpuClock integrity.", L"{}", L"!etw integrity", AiCapabilityCost::Cheap },
        { L"etw.providers", L"Heuristic ETW provider registration surface.", L"{}", L"!etw providers", AiCapabilityCost::Cheap },
        { L"etw.ti_cross", L"Correlate TI subscription reception with silence/drop signals.", L"{}", L"!etw ti-cross", AiCapabilityCost::Cheap },
        { L"nmi.list", L"List registered NMI callbacks.", L"optional scope callbacks", L"!nmi", AiCapabilityCost::Cheap },
        { L"minifilter.list", L"List filesystem minifilters and IRP registrations.", L"optional filter/name", L"!minifilter", AiCapabilityCost::Cheap },
        { L"payload.inspect", L"Trace one kernel address: page walk, pool, PE, disassembly.", L"address/va/symbol", L"!payload", AiCapabilityCost::Cheap },
        { L"payload.scan", L"Sweep hook surfaces for unbacked pointers.", L"optional limit", L"!payload scan", AiCapabilityCost::Expensive },
        { L"mapper.list", L"Walk MmUnloadedDrivers, PiDDB, and ci hash leftovers.", L"optional scope all|unloaded|piddb|cihash, limit", L"!mapper", AiCapabilityCost::Cheap },
        { L"kpage.list", L"Find executable kernel pages outside loaded modules.", L"optional deep/wx/pe, limit. deep is expensive.", L"!kpage", AiCapabilityCost::ExpensiveIfDeep },
        { L"hal.scan", L"Check HalDispatchTable pointer ownership.", L"{}", L"!hal", AiCapabilityCost::Cheap },
        { L"hive.list", L"Walk registry hive GetCellRoutine ownership.", L"{}", L"!hive", AiCapabilityCost::Cheap },
        { L"token.inspect", L"Inspect process token privileges and TokenType/SessionId/integrity.", L"optional pid/image/eprocess, limit", L"!token", AiCapabilityCost::Cheap },
        { L"dpc.list", L"Enumerate sampled DPC routines.", L"{}", L"!dpc", AiCapabilityCost::Cheap },
        { L"timer.list", L"Enumerate timer DPC routines.", L"{}", L"!timer", AiCapabilityCost::Cheap },
        { L"fwtable.list", L"List firmware table providers without invoking handlers.", L"optional scope providers|provider, module, signature", L"!fwtable", AiCapabilityCost::Cheap },
        { L"pool.find", L"Find big pool entries.", L"optional tag,min,max,addr,limit,paged, annotate/wx booleans", L"!pool find", AiCapabilityCost::Cheap },
        { L"address.inspect", L"Inspect one virtual address: page walk, permissions, owner.", L"address/va/symbol", L"!address", AiCapabilityCost::Cheap },
        { L"wnf.decode", L"Decode one WNF state-name hash.", L"hash/state/state_name", L"!wnf decode", AiCapabilityCost::Cheap },
        { L"wnf.list", L"List live WNF instances/candidates/lists.", L"optional scope instances|candidates|lists", L"!wnf instances", AiCapabilityCost::Cheap },
        { L"ti.query", L"Query the Threat-Intelligence ring.", L"action recent|stats|by|grep; optional count,pid,task,pattern", L"!ti", AiCapabilityCost::Cheap },
        { L"timeline.status", L"Report in-memory evidence timeline status.", L"{}", L"!timeline", AiCapabilityCost::Cheap },
        { L"timeline.query", L"Query ingested timeline events.", L"optional source,domain,pid,limit,order", L"!timeline query", AiCapabilityCost::Cheap },
        { L"timeline.export", L"Return ingested timeline events as JSONL text.", L"optional source,domain,pid,limit,order", L"!timeline export", AiCapabilityCost::Cheap },
        { L"timeline.reconcile", L"Compare timeline events with a snapshot.", L"optional path/snapshot, source,domain,pid,limit", L"!timeline reconcile", AiCapabilityCost::Cheap },
        { L"graph.query", L"Derive a process/image graph from timeline events.", L"optional source,domain,image,pid,limit,order", L"!timeline graph", AiCapabilityCost::Cheap },
        { L"module.integrity", L"Inspect loaded module PE/section integrity, disk compare, IAT, prologue.", L"optional module/target, limit, summary/verbose/headers/sections/wx/mismatch/disk/iat/prologue", L"!module integrity", AiCapabilityCost::Cheap },
        { L"driver.integrity", L"Inspect DRIVER_OBJECT dispatch targets.", L"optional driver/target, limit", L"!driver integrity", AiCapabilityCost::Cheap },
        { L"driver.object", L"Inspect one DRIVER_OBJECT and its device/attached stacks.", L"driver/name/target/address", L"!drvobj", AiCapabilityCost::Cheap },
        { L"device.stack", L"Walk a DEVICE_OBJECT AttachedDevice/AttachedTo stack.", L"address/va/device", L"!devstack", AiCapabilityCost::Cheap },
        { L"handles.list", L"Enumerate process handles and flag VM/DUP cross-process access.", L"optional pid, target, limit", L"!handles", AiCapabilityCost::Cheap },
        { L"hiddenproc.list", L"Cross-view hidden processes: ActiveProcessLinks vs SPI vs Toolhelp vs handle owners.", L"{}", L"!hiddenproc", AiCapabilityCost::Cheap },
        { L"wdfilter.list", L"Walk WdFilter RuntimeDriver leftovers after a mapper unloads.", L"{}", L"!wdfilter", AiCapabilityCost::Cheap },
        { L"inputstack.list", L"Walk keyboard/mouse class attached-device stacks.", L"{}", L"!inputstack", AiCapabilityCost::Cheap },
        { L"dma.posture", L"Report IOMMU firmware, Kernel DMA Protection, and removable PCI buses.", L"{}", L"!dma", AiCapabilityCost::Cheap },
        { L"hv.posture", L"Report hypervisor presence from CPUID, CR4.VMXE, and timing. No FEATURE_CONTROL.", L"{}", L"!hv", AiCapabilityCost::Cheap },
        { L"dump.analyze", L"Parse a dump-kernel DUMP_HEADER64 and walk modules with PML4 or LA57 PML5.", L"path or file", L"dump-analyze", AiCapabilityCost::Cheap },
        { L"ssdt.scan", L"Detect SSDT / shadow-SSDT syscall hooks.", L"{}", L"!ssdt", AiCapabilityCost::Cheap },
        { L"idt.scan", L"Detect IDT interrupt-gate hooks and per-CPU divergence.", L"{}", L"!idt", AiCapabilityCost::Cheap },
        { L"cr.scan", L"Check CR0.WP, SMEP/SMAP, and per-CPU CR divergence.", L"{}", L"!cr", AiCapabilityCost::Cheap },
        { L"msr.check", L"Check SYSCALL MSRs for hooked entries and per-CPU divergence.", L"{}", L"!msrcheck", AiCapabilityCost::Cheap },
        { L"vbs.scan", L"Report VBS/HVCI, CI options, hypervisor, Secure Kernel, and trustlets.", L"{}", L"!vbs", AiCapabilityCost::Cheap },
        { L"byovd.scan", L"Scan loaded modules against the local BYOVD catalog (no network).", L"{}", L"!byovd scan", AiCapabilityCost::Cheap },
        { L"byovd.status", L"Show local BYOVD catalog age and source counts.", L"{}", L"!byovd status", AiCapabilityCost::Cheap },
        { L"pool.scan_pe", L"Hunt intact or signature-wiped PE images in big pool.", L"optional tag, limit, suspicious", L"!pool pe", AiCapabilityCost::Cheap },
        { L"hunt.run", L"Whole-system user-mode anomaly hunt.", L"optional mode quick or deep", L"!hunt", AiCapabilityCost::Expensive },
        { L"snapshot.capture", L"Capture a same-boot evidence baseline in memory.", L"optional name", L"!snapshot baseline", AiCapabilityCost::Expensive },
        { L"snapshot.show", L"Show the current baseline or a snapshot JSON file.", L"optional source/path, domains, warnings", L"!snapshot show", AiCapabilityCost::Cheap },
        { L"snapshot.diff", L"Diff the session baseline against a live capture or two files.", L"optional old,new,domain,risk,limit,summary", L"!diff baseline", AiCapabilityCost::Cheap },
        { L"memory.read_virtual", L"Read bytes at a virtual address.", L"address/va/symbol, optional width 1|2|4|8, count, process", L"db", AiCapabilityCost::Cheap },
        { L"memory.read_physical", L"Read bytes at a physical address.", L"physical_address, optional width, count", L"!db", AiCapabilityCost::Cheap },
        { L"memory.search", L"Search a virtual range for an integer value.", L"address, length, value, optional width", L"s", AiCapabilityCost::Cheap },
        { L"memory.translate", L"Translate a virtual address to physical (vtop).", L"address/va/symbol, optional process/cr3, length", L"vtop", AiCapabilityCost::Cheap },
        { L"memory.probe", L"Test whether an address is readable/writable.", L"address/va/symbol, optional length", L"query", AiCapabilityCost::Cheap },
        { L"memory.read_pointers", L"Dump a pointer table with nearest symbols.", L"address/va/symbol, optional width 4|8, count", L"dps", AiCapabilityCost::Cheap },
        { L"memory.compare", L"Compare two virtual ranges and report mismatches.", L"address1, address2, length", L"c", AiCapabilityCost::Cheap },
        { L"symbol.search", L"Enumerate symbols by wildcard.", L"mask such as nt!Etw*, optional limit", L"x", AiCapabilityCost::Cheap },
        { L"assistant.answer", L"Use when none of the local tools fit. Do not mix with other steps.", L"{}", L"", AiCapabilityCost::Cheap }
    };

    const AiPlaybookStepDef kPlaybookCallbacks[] =
    {
        { L"callbacks.list", L"{\"scope\":\"all\"}" }
    };
    const AiPlaybookStepDef kPlaybookObject[] =
    {
        { L"callbacks.list", L"{\"scope\":\"object\"}" }
    };
    const AiPlaybookStepDef kPlaybookMinifilter[] =
    {
        { L"minifilter.list", L"{}" }
    };
    const AiPlaybookStepDef kPlaybookHidden[] =
    {
        { L"hiddenproc.list", L"{}" }
    };
    const AiPlaybookStepDef kPlaybookHandles[] =
    {
        { L"handles.list", L"{}" }
    };
    const AiPlaybookStepDef kPlaybookLeftover[] =
    {
        { L"mapper.list", L"{\"scope\":\"all\"}" },
        { L"kpage.list", L"{}" }
    };
    const AiPlaybookStepDef kPlaybookIntegrity[] =
    {
        { L"module.integrity", L"{\"target\":\"all\",\"summary\":\"true\"}" },
        { L"driver.integrity", L"{\"target\":\"all\"}" }
    };
    const AiPlaybookStepDef kPlaybookVbs[] =
    {
        { L"vbs.scan", L"{}" }
    };
    const AiPlaybookStepDef kPlaybookAddress[] =
    {
        { L"address.inspect", L"{\"address\":\"$address\"}" }
    };
    const AiPlaybookStepDef kPlaybookDma[] =
    {
        { L"dma.posture", L"{}" },
        { L"hv.posture", L"{}" }
    };

    const AiPlaybookDef kPlaybooks[] =
    {
        { L"callbacks", L"callbacks|callback audit|\xCF5C\xBC31|\xCF5C\xBC31 \xC804\xC218\xC870\xC0AC|\xCF5C\xBC31 \xC870\xC0AC", L"Enumerate every kernel callback surface.", kPlaybookCallbacks, 1, false },
        { L"object", L"object callbacks|object-callbacks", L"Enumerate object-manager callbacks.", kPlaybookObject, 1, false },
        { L"minifilter", L"minifilter|\xBBF8\xB2C8\xD544\xD130", L"List filesystem minifilter IRP registrations.", kPlaybookMinifilter, 1, false },
        { L"hidden", L"hidden process|hiddenproc|unlinked process|\xC228\xC740 \xD504\xB85C\xC138\xC2A4|\xC740\xB2C9 \xD504\xB85C\xC138\xC2A4|\xC228\xAE34 \xD504\xB85C\xC138\xC2A4", L"Cross-view hidden processes.", kPlaybookHidden, 1, false },
        { L"handles", L"handle table|cross-process handle|\xD578\xB4E4 \xD14C\xC774\xBE14|\xAD50\xCC28 \xD504\xB85C\xC138\xC2A4 \xD578\xB4E4|\xD578\xB4E4 \xC870\xC0AC", L"Triage process handles for VM/DUP access.", kPlaybookHandles, 1, false },
        { L"leftover", L"mapper leftover|unloaded driver remnant|unloaded mapper|kdmapper|\xB9E4\xD37C \xC794\xC5EC|\xC5B8\xB85C\xB4DC \xC794\xC5EC", L"Check mapper bookkeeping remnants and orphan pages.", kPlaybookLeftover, 2, false },
        { L"integrity", L"module integrity|driver integrity|\xBAA8\xB4C8 \xBB34\xACB0\xC131|\xB514\xC2A4\xD328\xCE58 \xBB34\xACB0\xC131", L"Scan module PE integrity and driver dispatch tables.", kPlaybookIntegrity, 2, false },
        { L"vbs", L"vbs status|hvci|secure kernel|\xBCF4\xC548\xCEE4\xB110|\xAC00\xC0C1\xD654 \xAE30\xBC18 \xBCF4\xC548", L"Report VBS/HVCI/Secure Kernel posture.", kPlaybookVbs, 1, false },
        { L"address", L"address inspect|this address|that address|\xC774 \xC8FC\xC18C|\xADF8 \xC8FC\xC18C|\xD398\xC774\xC9C0\xAD8C\xD55C|page permission|suspicious address", L"Inspect one virtual address.", kPlaybookAddress, 1, true },
        { L"dma", L"dma protection|hypervisor presence|dma \xBCF4\xD638|\xD558\xC774\xD37C\xBC14\xC774\xC800 \xC874\xC7AC", L"Report DMA and hypervisor posture.", kPlaybookDma, 2, false }
    };
}

const AiCapabilityToolDef* AiCapabilityTools(size_t* count)
{
    if (count != nullptr)
    {
        *count = sizeof(kTools) / sizeof(kTools[0]);
    }
    return kTools;
}

const AiCapabilityToolDef* FindAiCapabilityTool(const std::wstring& name)
{
    const std::wstring lowered = CatalogLower(name);
    const size_t count = sizeof(kTools) / sizeof(kTools[0]);
    for (size_t i = 0; i < count; ++i)
    {
        if (CatalogLower(kTools[i].Name) == lowered)
        {
            return &kTools[i];
        }
    }
    return nullptr;
}

bool IsAiCapabilityCatalogTool(const std::wstring& name)
{
    return FindAiCapabilityTool(name) != nullptr;
}

AiCapabilityCost GetAiCapabilityToolCost(const std::wstring& name)
{
    const AiCapabilityToolDef* tool = FindAiCapabilityTool(name);
    if (tool == nullptr)
    {
        return AiCapabilityCost::Cheap;
    }
    return tool->Cost;
}

const wchar_t* AiCapabilityCostLabel(AiCapabilityCost cost)
{
    const wchar_t* label = L"cheap";
    if (cost == AiCapabilityCost::Expensive)
    {
        label = L"expensive";
    }
    else if (cost == AiCapabilityCost::ExpensiveIfDeep)
    {
        label = L"expensive if deep";
    }
    return label;
}

const AiPlaybookDef* AiCapabilityPlaybooks(size_t* count)
{
    if (count != nullptr)
    {
        *count = sizeof(kPlaybooks) / sizeof(kPlaybooks[0]);
    }
    return kPlaybooks;
}

bool AiQueryHasMutationIntent(const std::wstring& query)
{
    bool found = false;
    bool hasTi = false;
    bool hasTimeline = false;
    bool hasLive = false;
    bool hasStart = false;
    bool hasStop = false;
    bool hasOn = false;
    bool hasOff = false;
    bool hasPpl = false;
    bool hasByovd = false;
    bool hasFixture = false;
    bool hasReset = false;
    bool hasClear = false;
    bool hasLoad = false;
    bool hasUnload = false;
    bool hasWriteGate = false;
    bool hasMcp = false;
    bool hasProbe = false;
    bool hasLog = false;
    const std::vector<std::wstring> tokens = CatalogTokens(query);
    for (const std::wstring& token : tokens)
    {
        if (IsMutationActionToken(token))
        {
            found = true;
            break;
        }
        if (IsTiSurfaceToken(token))
        {
            hasTi = true;
        }
        if (IsTimelineSurfaceToken(token))
        {
            hasTimeline = true;
        }
        if (IsLiveToken(token))
        {
            hasLive = true;
        }
        if (IsStartToken(token))
        {
            hasStart = true;
        }
        if (IsStopToken(token))
        {
            hasStop = true;
        }
        if (IsOnToken(token))
        {
            hasOn = true;
        }
        if (IsOffToken(token))
        {
            hasOff = true;
        }
        if (IsPplToken(token))
        {
            hasPpl = true;
        }
        if (IsByovdToken(token))
        {
            hasByovd = true;
        }
        if (IsFixtureToken(token))
        {
            hasFixture = true;
        }
        if (IsResetToken(token))
        {
            hasReset = true;
        }
        if (IsClearToken(token))
        {
            hasClear = true;
        }
        if (IsLoadToken(token))
        {
            hasLoad = true;
        }
        if (IsUnloadToken(token))
        {
            hasUnload = true;
        }
        if (IsWriteGateToken(token))
        {
            hasWriteGate = true;
        }
        if (IsMcpToken(token))
        {
            hasMcp = true;
        }
        if (IsProbeToken(token))
        {
            hasProbe = true;
        }
        if (CatalogLower(CatalogTrim(token)) == L"log" ||
            CatalogLower(CatalogTrim(token)) == L"logging")
        {
            hasLog = true;
        }
    }
    if (!found)
    {
        if (hasTi && (hasStart || hasStop || hasClear))
        {
            found = true;
        }
        else if (hasTimeline && hasLive && (hasOn || hasOff || hasStart || hasStop))
        {
            found = true;
        }
        else if (hasTimeline && (hasReset || hasClear) && !hasLive)
        {
            found = true;
        }
        else if (hasPpl && (hasOn || hasOff || hasStart || hasStop))
        {
            found = true;
        }
        else if ((hasByovd || hasFixture) && (hasLoad || hasUnload))
        {
            found = true;
        }
        else if (hasWriteGate && (hasOn || hasOff))
        {
            found = true;
        }
        else if (hasMcp && (hasOn || hasOff || hasStart || hasStop))
        {
            found = true;
        }
        else if (hasProbe && (hasLoad || hasUnload))
        {
            found = true;
        }
        else if (hasLog && (hasOn || hasOff || hasStart || hasStop))
        {
            found = true;
        }
    }
    return found;
}

bool TryBuildAiMutationCommand(
    const std::wstring& query,
    std::wstring* command,
    std::wstring* purpose,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (command == nullptr || purpose == nullptr)
        {
            break;
        }

        command->clear();
        purpose->clear();

        const std::vector<std::wstring> tokens = CatalogTokens(query);
        std::wstring action;
        bool hasMinifilter = false;
        bool hasCallbacks = false;
        bool hasIrp = false;
        bool hasTi = false;
        bool hasTimeline = false;
        bool hasLive = false;
        bool hasStart = false;
        bool hasStop = false;
        bool hasOn = false;
        bool hasOff = false;
        bool hasLog = false;
        bool hasPpl = false;
        bool hasByovd = false;
        bool hasFixture = false;
        bool hasMcp = false;
        bool hasProbe = false;
        bool hasWriteGate = false;
        bool hasBackend = false;
        bool hasReset = false;
        bool hasClear = false;
        bool hasLoad = false;
        bool hasUnload = false;
        bool conflict = false;
        std::wstring scope;
        std::vector<std::wstring> modules;

        for (const std::wstring& token : tokens)
        {
            if (IsDisableActionToken(token))
            {
                action = L"disable";
                continue;
            }
            if (IsEnableActionToken(token))
            {
                action = L"enable";
                continue;
            }
            if (IsTiSurfaceToken(token))
            {
                hasTi = true;
                continue;
            }
            if (IsTimelineSurfaceToken(token))
            {
                hasTimeline = true;
                continue;
            }
            if (IsLiveToken(token))
            {
                hasLive = true;
                continue;
            }
            if (IsStartToken(token))
            {
                hasStart = true;
                continue;
            }
            if (IsStopToken(token))
            {
                hasStop = true;
                continue;
            }
            if (IsOnToken(token))
            {
                hasOn = true;
                continue;
            }
            if (IsOffToken(token))
            {
                hasOff = true;
                continue;
            }
            if (CatalogLower(CatalogTrim(token)) == L"log" ||
                CatalogLower(CatalogTrim(token)) == L"logging")
            {
                hasLog = true;
                continue;
            }
            if (IsPplToken(token))
            {
                hasPpl = true;
                continue;
            }
            if (IsByovdToken(token))
            {
                hasByovd = true;
                continue;
            }
            if (IsFixtureToken(token))
            {
                hasFixture = true;
                continue;
            }
            if (IsMcpToken(token))
            {
                hasMcp = true;
                continue;
            }
            if (IsProbeToken(token))
            {
                hasProbe = true;
                continue;
            }
            if (IsWriteGateToken(token))
            {
                hasWriteGate = true;
                continue;
            }
            if (IsBackendToken(token))
            {
                hasBackend = true;
                continue;
            }
            if (IsResetToken(token))
            {
                hasReset = true;
                continue;
            }
            if (IsClearToken(token))
            {
                hasClear = true;
                continue;
            }
            if (IsLoadToken(token))
            {
                hasLoad = true;
                continue;
            }
            if (IsUnloadToken(token))
            {
                hasUnload = true;
                continue;
            }

            const std::wstring surface = ClassifyMutationSurface(token);
            if (surface == L"minifilter")
            {
                hasMinifilter = true;
                continue;
            }
            if (surface == L"irp")
            {
                hasIrp = true;
                continue;
            }
            if (surface == L"callbacks")
            {
                hasCallbacks = true;
                continue;
            }
            if (surface == L"object" ||
                surface == L"registry" ||
                surface == L"process" ||
                surface == L"thread" ||
                surface == L"imageload")
            {
                if (!scope.empty() && scope != surface)
                {
                    if (error != nullptr)
                    {
                        *error = L"name one callback surface only (object, registry, process, thread, imageload)";
                    }
                    conflict = true;
                    break;
                }
                scope = surface;
                continue;
            }

            if (IsMutationStopword(token) || IsMutationReservedToken(token))
            {
                continue;
            }
            if (!IsSafeMutationModule(token))
            {
                continue;
            }
            modules.push_back(StripDriverFileSuffix(token));
        }

        if (conflict)
        {
            break;
        }

        const bool isolatedSession =
            modules.empty() &&
            !hasMinifilter &&
            !hasCallbacks &&
            !hasIrp &&
            scope.empty();
        // Kernel/protection mutations first so "backend"/"write" words cannot steal them.
        if (isolatedSession && hasPpl)
        {
            const bool turningOff = hasOff || hasStop || action == L"disable";
            const bool turningOn = hasOn || hasStart || action == L"enable";
            if (!turningOff && !turningOn)
            {
                if (error != nullptr)
                {
                    *error = L"say `ai enable ppl` or `ai disable ppl`";
                }
                break;
            }
            *command = turningOff ? L"set-ppl-antimalware off" : L"set-ppl-antimalware on";
            *purpose = turningOff
                ? L"clear this process PPL Antimalware protection byte"
                : L"set this process to PPL Antimalware (TI prerequisite)";
            ok = true;
            break;
        }
        if (isolatedSession && (hasByovd || hasFixture) && (hasLoad || hasUnload || !action.empty()))
        {
            const bool unloading = hasUnload || action == L"disable" || hasStop;
            *command = unloading ? L"!byovd fixture unload" : L"!byovd fixture load";
            *purpose = unloading
                ? L"unload the bundled BYOVD fixture service"
                : L"load the bundled BYOVD fixture service";
            ok = true;
            break;
        }
        if (isolatedSession && hasTimeline && (hasReset || hasClear) && !hasLive)
        {
            *command = L"!timeline reset";
            *purpose = L"drop the in-memory timeline store";
            ok = true;
            break;
        }
        if (isolatedSession && hasTi && hasClear && !hasStart && !hasStop)
        {
            *command = L"!ti clear";
            *purpose = L"clear the in-memory Threat-Intelligence ring";
            ok = true;
            break;
        }

        // Do not let "timeline live" steal a module disable/enable goal.
        if (hasTimeline && hasLive && isolatedSession)
        {
            const bool turningOff = hasOff || hasStop || action == L"disable";
            const bool turningOn = hasOn || hasStart || action == L"enable";
            if (turningOff || turningOn)
            {
                *command = turningOff ? L"!timeline live off" : L"!timeline live on";
                *purpose = turningOff
                    ? L"disable kernel live timeline callbacks"
                    : L"enable kernel live timeline callbacks";
                ok = true;
                break;
            }
        }
        if (hasTi && isolatedSession && (hasStart || hasStop || !action.empty()) && !hasClear)
        {
            const bool turningOff = hasStop || action == L"disable";
            *command = turningOff ? L"!ti stop" : L"!ti start";
            *purpose = turningOff
                ? L"stop the Threat-Intelligence ETW subscription"
                : L"start the Threat-Intelligence ETW subscription";
            ok = true;
            break;
        }

        if (isolatedSession && hasLog &&
            (hasOn || hasOff || hasStart || hasStop || !action.empty()) &&
            !hasTi && !hasTimeline)
        {
            if (error != nullptr)
            {
                *error = L"session log control is `log enable` / `log disable`, not an ai write plan";
            }
            break;
        }
        if (isolatedSession && hasWriteGate && (hasOn || hasOff || !action.empty()))
        {
            if (error != nullptr)
            {
                *error = L"session write gate is `write on` / `write off`, not an ai write plan";
            }
            break;
        }
        if (isolatedSession && hasMcp && (hasOn || hasOff || hasStart || hasStop || !action.empty()))
        {
            if (error != nullptr)
            {
                *error = L"MCP server control is `mcp on` / `mcp off`, not an ai write plan";
            }
            break;
        }
        if (isolatedSession && hasProbe && (hasLoad || hasUnload || !action.empty()))
        {
            if (error != nullptr)
            {
                *error = L"probe service control is `probe load` / `probe unload`, not an ai write plan";
            }
            break;
        }
        if (isolatedSession && hasBackend && !hasPpl && !hasByovd && !hasTi && !hasTimeline)
        {
            if (error != nullptr)
            {
                *error = L"backend mode is `backend auto|native|dbgeng`, not an ai write plan";
            }
            break;
        }

        if (action.empty())
        {
            if (error != nullptr)
            {
                *error = L"disable/enable intent was not recognized";
            }
            break;
        }

        std::wstring surface;
        if (hasMinifilter || (hasIrp && scope.empty() && !hasCallbacks))
        {
            surface = L"minifilter";
        }
        else if (!scope.empty())
        {
            surface = scope;
        }
        else if (hasCallbacks || hasIrp)
        {
            surface = L"callbacks";
        }

        if (surface.empty())
        {
            if (error != nullptr)
            {
                *error = L"name a surface: minifilter, callbacks, object, registry, process, thread, or imageload";
            }
            break;
        }
        if (modules.size() != 1)
        {
            if (error != nullptr)
            {
                *error = L"name exactly one module (WdFilter, UnionFS, ...)";
            }
            break;
        }

        const std::wstring module = modules[0];
        const bool disabling = action == L"disable";
        if (surface == L"minifilter")
        {
            *command = std::wstring(L"!minifilter ") + (disabling ? L"disable-all " : L"enable-all ") + module;
            *purpose = disabling
                ? L"disable every registered IRP pre/post slot for that minifilter"
                : L"restore every same-session minifilter IRP backup for that filter";
        }
        else if (surface == L"callbacks")
        {
            *command = std::wstring(L"!callbacks ") + (disabling ? L"disable-all " : L"enable-all ") + module;
            *purpose = disabling
                ? L"disable every callback type owned by that module"
                : L"restore every same-session callback backup for that module";
        }
        else
        {
            *command = std::wstring(L"!callbacks ") + (disabling ? L"disable " : L"enable ") + surface + L" " + module;
            *purpose = disabling
                ? L"disable that module's callbacks on one surface"
                : L"restore that module's same-session backups on one surface";
        }

        ok = true;
    } while (false);

    return ok;
}

const AiPlaybookDef* FindAiPlaybook(const std::wstring& query)
{
    const AiPlaybookDef* best = nullptr;
    size_t bestLen = 0;
    const size_t count = sizeof(kPlaybooks) / sizeof(kPlaybooks[0]);
    const std::wstring lowered = CatalogLower(CatalogTrim(query));
    if (AiQueryHasMutationIntent(query))
    {
        return nullptr;
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (AliasHitsQuery(lowered, kPlaybooks[i].Name) &&
            std::wstring(kPlaybooks[i].Name).size() > bestLen)
        {
            best = &kPlaybooks[i];
            bestLen = std::wstring(kPlaybooks[i].Name).size();
        }
        std::wstring aliases = kPlaybooks[i].Aliases;
        size_t start = 0;
        while (start <= aliases.size())
        {
            size_t bar = aliases.find(L'|', start);
            if (bar == std::wstring::npos)
            {
                bar = aliases.size();
            }
            std::wstring alias = CatalogTrim(aliases.substr(start, bar - start));
            if (!alias.empty() &&
                AliasHitsQuery(lowered, alias) &&
                alias.size() > bestLen)
            {
                best = &kPlaybooks[i];
                bestLen = alias.size();
            }
            start = bar + 1;
        }
    }
    if (best != nullptr &&
        !best->NeedsAddress &&
        HasImageOrDriverFile(query))
    {
        best = nullptr;
    }
    return best;
}

std::wstring SubstituteAiPlaybookPlaceholders(
    const std::wstring& argsJson,
    const std::wstring& address)
{
    std::wstring out = argsJson;
    do
    {
        if (address.empty() ||
            address.find_first_of(L"\"\\\r\n") != std::wstring::npos)
        {
            break;
        }
        ReplaceAll(&out, L"$address", address);
    } while (false);
    return out;
}

std::wstring BuildAiCapabilityPlannerPrompt(
    const std::wstring& query,
    const std::wstring& sessionHints)
{
    std::wstringstream stream;
    stream << L"You are the KnLiveDbg tool router. Choose local read-only tools for the operator request.\n";
    stream << L"The operator request may be Korean or English.\n";
    stream << L"Return only one JSON object, with no Markdown fences and no prose before or after it.\n";
    stream << L"Schema:\n";
    stream << L"{\"schema\":\"kn-live-dbg.ai-capability-plan.v1\",\"summary\":\"short summary\",\"steps\":[";
    stream << L"{\"tool\":\"";
    const size_t count = sizeof(kTools) / sizeof(kTools[0]);
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            stream << L"|";
        }
        stream << kTools[i].Name;
    }
    stream << L"\",\"args\":{}}]}\n";
    stream << L"Available tools:\n";
    for (size_t i = 0; i < count; ++i)
    {
        stream << L"- " << kTools[i].Name << L": " << kTools[i].Description
               << L" Args: " << kTools[i].Args << L"\n";
    }
    stream << L"Rules:\n";
    stream << L"- Use only these tools. Do not emit debugger commands.\n";
    stream << L"- All scalar args must be JSON strings. Use fields as an array of strings. Do not invent fields.\n";
    stream << L"- Never emit raw kd commands, nested ai commands, writes, unload/shutdown, session mutation, command chaining, or multiline content.\n";
    stream << L"- For image-name process questions, first use process.find with image, then describe or type.describe source \"$0\".\n";
    stream << L"- For hidden or unlinked processes, use hiddenproc.list. Do not use hunt.run unless the operator asks for a whole-system hunt.\n";
    stream << L"- For VM/DUP cross-process handles, use handles.list.\n";
    stream << L"- For one DRIVER_OBJECT plus device stacks, use driver.object. For AttachedDevice walk, use device.stack.\n";
    stream << L"- For WdFilter RuntimeDriver leftovers, use wdfilter.list. For kbd/mou attached stacks, use inputstack.list.\n";
    stream << L"- For IOMMU/DMA posture, use dma.posture. For hypervisor presence without FEATURE_CONTROL, use hv.posture.\n";
    stream << L"- For a dump-kernel file, use dump.analyze with path.\n";
    stream << L"- For module IAT/prologue/disk compare, set iat/prologue/disk true on module.integrity.\n";
    stream << L"- Mapper-family detection is layered. loaded BYOVD: byovd.scan. bookkeeping remnants: mapper.list. orphan pages: kpage.list. hook-to-body: payload.scan. staged pool PE: pool.scan_pe.\n";
    stream << L"- Use kpage.list deep=true only when the operator asks for a PFN walk. hunt.run is expensive; use it only for whole-system hunts.\n";
    stream << L"- For session follow-ups such as that process / \xADF8 \xD504\xB85C\xC138\xC2A4 / \xC774 \xC8FC\xC18C, use the session hints below.\n";
    stream << L"- Keep the plan read-only and no more than three steps unless the request needs more. Max 6.\n";
    stream << L"- assistant.answer: use this when none of the local tools fit. Args: {}. Do not mix it with other steps.\n";
    if (!sessionHints.empty())
    {
        stream << L"Session hints:\n" << sessionHints << L"\n";
    }
    stream << L"Operator request:\n";
    stream << query << L"\n";
    return stream.str();
}

std::wstring ApplyAiSessionContext(
    const std::wstring& query,
    uint32_t lastPid,
    const std::wstring& lastImage,
    const std::wstring& lastAddress,
    const std::wstring& lastDumpPath)
{
    std::wstring out = query;
    std::wstring processText;
    if (!lastImage.empty())
    {
        processText = lastImage;
    }
    else if (lastPid != 0)
    {
        processText = L"pid " + std::to_wstring(lastPid);
    }

    if (!processText.empty())
    {
        ReplaceAll(&out, L"\xADF8 \xD504\xB85C\xC138\xC2A4", processText);
        ReplaceAll(&out, L"\xD574\xB2F9 \xD504\xB85C\xC138\xC2A4", processText);
        ReplaceAll(&out, L"that process", processText);
        ReplaceAll(&out, L"the process", processText);
    }
    if (!lastAddress.empty())
    {
        ReplaceAll(&out, L"\xC774 \xC8FC\xC18C", lastAddress);
        ReplaceAll(&out, L"\xADF8 \xC8FC\xC18C", lastAddress);
        ReplaceAll(&out, L"this address", lastAddress);
        ReplaceAll(&out, L"that address", lastAddress);
    }
    if (!lastDumpPath.empty())
    {
        ReplaceAll(&out, L"\xADF8 \xB364\xD504", lastDumpPath);
        ReplaceAll(&out, L"the dump", lastDumpPath);
        ReplaceAll(&out, L"this dump", lastDumpPath);
    }
    return out;
}

bool IsAiConceptualQuery(const std::wstring& query)
{
    static const wchar_t* prefixes[] =
    {
        L"what is",
        L"what are",
        L"why",
        L"explain why",
        L"explain what",
        L"\xBB34\xC5C7\xC778\xAC00",
        L"\xBB34\xC5C7\xC774\xC9C0",
        L"\xBB50\xC57C",
        L"\xBB50\xC9C0",
        L"\xBB34\xC2A8 \xC758\xBBF8",
        L"\xC65C"
    };
    for (const wchar_t* prefix : prefixes)
    {
        if (StartsWithNoCase(query, prefix))
        {
            return true;
        }
    }
    return false;
}

bool StripAiGoalOptions(std::wstring* query, bool* verbose)
{
    bool changed = false;
    do
    {
        if (query == nullptr || verbose == nullptr)
        {
            break;
        }
        *verbose = false;
        std::wstring source = CatalogTrim(*query);
        std::wstring kept;
        size_t pos = 0;
        while (pos < source.size())
        {
            while (pos < source.size() && iswspace(source[pos]) != 0)
            {
                ++pos;
            }
            if (pos >= source.size())
            {
                break;
            }
            size_t end = pos;
            while (end < source.size() && iswspace(source[end]) == 0)
            {
                ++end;
            }
            std::wstring token = source.substr(pos, end - pos);
            std::wstring lowered = CatalogLower(token);
            if (lowered == L"/verbose" || lowered == L"-verbose")
            {
                *verbose = true;
                changed = true;
            }
            else
            {
                if (!kept.empty())
                {
                    kept += L" ";
                }
                kept += token;
            }
            pos = end;
        }
        *query = kept;
    } while (false);
    return changed;
}

bool AiCapabilityCatalogSelfTest()
{
    bool ok = false;
    do
    {
        size_t count = 0;
        const AiCapabilityToolDef* tools = AiCapabilityTools(&count);
        if (tools == nullptr || count < 40)
        {
            break;
        }
        if (FindAiCapabilityTool(L"hiddenproc.list") == nullptr ||
            FindAiCapabilityTool(L"handles.list") == nullptr ||
            FindAiCapabilityTool(L"dump.analyze") == nullptr ||
            FindAiCapabilityTool(L"driver.object") == nullptr)
        {
            break;
        }
        if (GetAiCapabilityToolCost(L"hunt.run") != AiCapabilityCost::Expensive ||
            GetAiCapabilityToolCost(L"kpage.list") != AiCapabilityCost::ExpensiveIfDeep ||
            GetAiCapabilityToolCost(L"hiddenproc.list") != AiCapabilityCost::Cheap)
        {
            break;
        }
        std::wstring prompt = BuildAiCapabilityPlannerPrompt(L"find hidden processes", L"");
        if (prompt.find(L"hiddenproc.list") == std::wstring::npos ||
            prompt.find(L"dump.analyze") == std::wstring::npos ||
            prompt.find(L"disk/iat/prologue") == std::wstring::npos)
        {
            break;
        }
        const AiPlaybookDef* hidden = FindAiPlaybook(L"\xC228\xC740 \xD504\xB85C\xC138\xC2A4 \xCC3E\xC544\xC918");
        const AiPlaybookDef* callbacks = FindAiPlaybook(L"\xCF5C\xBC31 \xC804\xC218\xC870\xC0AC");
        if (hidden == nullptr || callbacks == nullptr)
        {
            break;
        }
        if (std::wstring(hidden->Name) != L"hidden" ||
            std::wstring(callbacks->Name) != L"callbacks")
        {
            break;
        }
        std::wstring rewritten = ApplyAiSessionContext(
            L"\xADF8 \xD504\xB85C\xC138\xC2A4 VAD scan",
            1234,
            L"game.exe",
            L"0xffff800000001000",
            L"");
        if (rewritten.find(L"game.exe") == std::wstring::npos)
        {
            break;
        }
        if (!IsAiConceptualQuery(L"why are W+X pages suspicious") ||
            !IsAiConceptualQuery(L"\xC65C W+X \xD398\xC774\xC9C0\xAC00 \xC758\xC2EC\xC2A4\xB7FD\xC9C0") ||
            IsAiConceptualQuery(L"find hidden processes") ||
            IsAiConceptualQuery(L"\xC228\xC740 \xD504\xB85C\xC138\xC2A4 \xCC3E\xC544\xC918"))
        {
            break;
        }
        const AiPlaybookDef* address = FindAiPlaybook(L"why is this address suspicious");
        if (address == nullptr || std::wstring(address->Name) != L"address")
        {
            break;
        }
        const AiPlaybookDef* vbs = FindAiPlaybook(L"vbs");
        const AiPlaybookDef* object = FindAiPlaybook(L"object callbacks");
        if (vbs == nullptr || std::wstring(vbs->Name) != L"vbs" ||
            object == nullptr || std::wstring(object->Name) != L"object")
        {
            break;
        }
        if (FindAiPlaybook(L"WdFilter.sys object callbacks") != nullptr)
        {
            break;
        }
        if (FindAiPlaybook(L"disable wdfilter minifilter") != nullptr ||
            FindAiPlaybook(L"minifilter") == nullptr)
        {
            break;
        }
        if (!AiQueryHasMutationIntent(L"disable wdfilter minifilter") ||
            AiQueryHasMutationIntent(L"show minifilter") ||
            AiQueryHasMutationIntent(L"why are callbacks disabled"))
        {
            break;
        }
        std::wstring mutationCommand;
        std::wstring mutationPurpose;
        std::wstring mutationError;
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter minifilter",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!minifilter disable-all wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"enable WdFilter.sys minifilter",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!minifilter enable-all WdFilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter object",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks disable object wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter callbacks",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks disable-all wdfilter")
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"disable minifilter",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"disable wdfilter",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"disable wdfilter timeline live",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"log disable",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter process",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks disable process wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"enable wdfilter thread",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks enable thread wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter registry",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks disable registry wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable wdfilter imageload",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!callbacks disable imageload wdfilter")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"start ti",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!ti start")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"stop ti",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!ti stop")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"timeline live off",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!timeline live off")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"enable timeline live",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!timeline live on")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable timeline live",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!timeline live off")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"enable ppl",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"set-ppl-antimalware on")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"enable ppl antimalware",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"set-ppl-antimalware on")
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"ppl",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"disable ppl",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"set-ppl-antimalware off")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"load byovd fixture",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!byovd fixture load")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"unload fixture",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!byovd fixture unload")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"reset timeline",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!timeline reset")
        {
            break;
        }
        if (!TryBuildAiMutationCommand(
                L"clear ti",
                &mutationCommand,
                &mutationPurpose,
                &mutationError) ||
            mutationCommand != L"!ti clear")
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"enable write",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (TryBuildAiMutationCommand(
                L"start mcp",
                &mutationCommand,
                &mutationPurpose,
                &mutationError))
        {
            break;
        }
        if (AiQueryHasMutationIntent(L"timeline query") ||
            AiQueryHasMutationIntent(L"!ti status"))
        {
            break;
        }
        std::wstring caseRewrite = ApplyAiSessionContext(
            L"The process VAD scan",
            1234,
            L"game.exe",
            L"",
            L"");
        if (caseRewrite.find(L"game.exe") == std::wstring::npos)
        {
            break;
        }
        std::wstring optionQuery = L"\xC228\xC740 \xD504\xB85C\xC138\xC2A4 /verbose";
        bool verbose = false;
        StripAiGoalOptions(&optionQuery, &verbose);
        if (!verbose || optionQuery.find(L"/verbose") != std::wstring::npos)
        {
            break;
        }
        bool unique = true;
        for (size_t i = 0; i < count && unique; ++i)
        {
            for (size_t j = i + 1; j < count; ++j)
            {
                if (CatalogLower(tools[i].Name) == CatalogLower(tools[j].Name))
                {
                    unique = false;
                    break;
                }
            }
        }
        if (!unique)
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}
