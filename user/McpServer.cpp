#define _CRT_RAND_S

#include "McpServer.h"
#include "McpJson.h"

#include <http.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#pragma comment(lib, "httpapi.lib")

// ---------------------------------------------------------------------------
// Static tool / resource / prompt catalog and transport helpers.
// ---------------------------------------------------------------------------

namespace
{
    const wchar_t* const kProtocolVersion = L"2025-06-18";
    const wchar_t* const kServerName = L"knlivedbg";
    const wchar_t* const kServerVersion = L"0.1.0";

    struct McpToolArg
    {
        const wchar_t* Name;
        const wchar_t* Type; // "string" or "boolean"
        bool Required;
    };

    struct McpToolDef
    {
        const wchar_t* Name;
        const wchar_t* Description;
        bool ReadOnly;
        const McpToolArg* Args;
        size_t ArgCount;
    };

    // Read-only tools: a strict projection of the in-tool AI capability catalog
    // (kn-live-dbg.ai-capability-plan.v1). The engine dispatch reuses the same
    // validator + executor, so these can never reach a command the planner
    // cannot. Arg names mirror the per-tool arg-key whitelist verbatim.
    const McpToolArg kArgsProcessFind[] = { {L"image", L"string", false}, {L"pid", L"string", false}, {L"eprocess", L"string", false} };
    const McpToolArg kArgsProcessDescribe[] = { {L"source", L"string", false}, {L"pid", L"string", false}, {L"eprocess", L"string", false}, {L"fields", L"array", false} };
    const McpToolArg kArgsTypeDescribe[] = { {L"source", L"string", false}, {L"address", L"string", false}, {L"type", L"string", false}, {L"fields", L"array", false} };
    const McpToolArg kArgsCallbacks[] = { {L"scope", L"string", false}, {L"module", L"string", false} };
    const McpToolArg kArgsWfp[] = { {L"scope", L"string", false}, {L"module", L"string", false}, {L"provider", L"string", false}, {L"layer", L"string", false} };
    const McpToolArg kArgsAlpc[] = { {L"scope", L"string", false}, {L"name", L"string", false}, {L"pid", L"string", false} };
    const McpToolArg kArgsVad[] = { {L"pid", L"string", false}, {L"image", L"string", false}, {L"eprocess", L"string", false}, {L"exec", L"boolean", false}, {L"private", L"boolean", false}, {L"wx", L"boolean", false}, {L"pe", L"boolean", false}, {L"hiddenpte", L"boolean", false}, {L"dkom", L"boolean", false}, {L"summary", L"boolean", false}, {L"limit", L"string", false} };
    const McpToolArg kArgsThreads[] = { {L"pid", L"string", false}, {L"image", L"string", false}, {L"eprocess", L"string", false}, {L"apc", L"boolean", false}, {L"stacks", L"boolean", false}, {L"limit", L"string", false} };
    const McpToolArg kArgsNmi[] = { {L"scope", L"string", false} };
    const McpToolArg kArgsFwtable[] = { {L"scope", L"string", false}, {L"module", L"string", false}, {L"provider", L"string", false}, {L"signature", L"string", false} };
    const McpToolArg kArgsPool[] = { {L"tag", L"string", false}, {L"min", L"string", false}, {L"max", L"string", false}, {L"addr", L"string", false}, {L"limit", L"string", false}, {L"paged", L"string", false}, {L"annotate", L"boolean", false}, {L"wx", L"boolean", false} };
    const McpToolArg kArgsAddress[] = { {L"address", L"string", false}, {L"va", L"string", false}, {L"symbol", L"string", false} };
    const McpToolArg kArgsWnfDecode[] = { {L"hash", L"string", false}, {L"state", L"string", false}, {L"state_name", L"string", false} };
    const McpToolArg kArgsWnfList[] = { {L"scope", L"string", false} };
    const McpToolArg kArgsTi[] = { {L"action", L"string", false}, {L"count", L"string", false}, {L"pid", L"string", false}, {L"task", L"string", false}, {L"pattern", L"string", false} };
    const McpToolArg kArgsModuleIntegrity[] = { {L"module", L"string", false}, {L"target", L"string", false}, {L"limit", L"string", false}, {L"summary", L"boolean", false}, {L"verbose", L"boolean", false}, {L"headers", L"boolean", false}, {L"sections", L"boolean", false}, {L"wx", L"boolean", false}, {L"mismatch", L"boolean", false} };
    const McpToolArg kArgsDriverIntegrity[] = { {L"driver", L"string", false}, {L"target", L"string", false}, {L"limit", L"string", false} };

    // Write tools: lab-mode only, registered when --allow-write. Engine routes
    // each through the existing write-safety pipeline (preflight read, backup,
    // post-write verify diff, write audit JSONL).
    const McpToolArg kArgsWriteVirtual[] = { {L"address", L"string", true}, {L"bytes", L"string", true}, {L"width", L"string", false}, {L"process", L"string", false} };
    const McpToolArg kArgsWritePhysical[] = { {L"physical_address", L"string", true}, {L"bytes", L"string", true} };
    const McpToolArg kArgsFill[] = { {L"address", L"string", true}, {L"length", L"string", true}, {L"pattern", L"string", true} };
    const McpToolArg kArgsMove[] = { {L"source", L"string", true}, {L"dest", L"string", true}, {L"length", L"string", true} };
    const McpToolArg kArgsSetField[] = { {L"address", L"string", true}, {L"type", L"string", true}, {L"field", L"string", true}, {L"value", L"string", true} };
    // Arbitrary-target PS_PROTECTION: pid (optional, defaults to self) + level.
    const McpToolArg kArgsSetProtection[] = { {L"pid", L"string", false}, {L"level", L"string", true} };
    // path is required: the handler has no default-path synthesis, so the schema
    // must demand it (matches DispatchMcpWriteTool, which errors without it).
    const McpToolArg kArgsDumpRaw[] = { {L"address", L"string", true}, {L"length", L"string", true}, {L"path", L"string", true} };
    const McpToolArg kArgsDumpPe[] = { {L"address", L"string", true}, {L"path", L"string", true} };

    // Read-only detection tools added by the catalog expansion (anti-cheat surface).
    const McpToolArg kArgsPoolScanPe[] = { {L"tag", L"string", false}, {L"limit", L"string", false}, {L"suspicious", L"boolean", false} };
    const McpToolArg kArgsHuntRun[] = { {L"mode", L"string", false} };
    const McpToolArg kArgsSnapshotCapture[] = { {L"name", L"string", false} };

    // Read-only memory / code / symbol inspection tools (close the read surface
    // so a model can confirm bytes and instructions without the WRITE dump.*).
    const McpToolArg kArgsMemoryReadVirtual[] = { {L"address", L"string", false}, {L"va", L"string", false}, {L"symbol", L"string", false}, {L"width", L"string", false}, {L"count", L"string", false}, {L"process", L"string", false} };
    const McpToolArg kArgsMemoryReadPhysical[] = { {L"physical_address", L"string", true}, {L"width", L"string", false}, {L"count", L"string", false} };
    const McpToolArg kArgsSymbolSearch[] = { {L"mask", L"string", true}, {L"limit", L"string", false} };
    const McpToolArg kArgsCodeDisasm[] = { {L"address", L"string", false}, {L"symbol", L"string", false}, {L"count", L"string", false}, {L"function", L"boolean", false} };
    const McpToolArg kArgsMemorySearch[] = { {L"address", L"string", true}, {L"length", L"string", true}, {L"value", L"string", true}, {L"width", L"string", false} };
    const McpToolArg kArgsMemoryTranslate[] = { {L"address", L"string", false}, {L"va", L"string", false}, {L"symbol", L"string", false}, {L"process", L"string", false}, {L"cr3", L"string", false}, {L"length", L"string", false} };
    const McpToolArg kArgsMemoryProbe[] = { {L"address", L"string", false}, {L"va", L"string", false}, {L"symbol", L"string", false}, {L"length", L"string", false} };
    const McpToolArg kArgsMemoryReadPointers[] = { {L"address", L"string", false}, {L"va", L"string", false}, {L"symbol", L"string", false}, {L"width", L"string", false}, {L"count", L"string", false} };
    const McpToolArg kArgsMemoryCompare[] = { {L"address1", L"string", true}, {L"address2", L"string", true}, {L"length", L"string", true} };
    const McpToolArg kArgsTiSubscribe[] = { {L"action", L"string", false} };
    const McpToolArg kArgsSnapshotDiff[] = { {L"old", L"string", false}, {L"new", L"string", false}, {L"domain", L"string", false}, {L"risk", L"string", false}, {L"limit", L"string", false}, {L"summary", L"boolean", false} };

#define MCP_ARG_TABLE(arr) arr, (sizeof(arr) / sizeof((arr)[0]))

    const McpToolDef kTools[] =
    {
        { L"process.find", L"Find live processes by image name, PID, or EPROCESS address.", true, MCP_ARG_TABLE(kArgsProcessFind) },
        { L"process.describe", L"Describe an _EPROCESS (PID, DTB, PEB, threads, parent).", true, MCP_ARG_TABLE(kArgsProcessDescribe) },
        { L"type.describe", L"Dump a kernel structure (dt) at an address or for a process.", true, MCP_ARG_TABLE(kArgsTypeDescribe) },
        { L"callbacks.list", L"Enumerate kernel callbacks (object/registry/process/thread/imageload/minifilter).", true, MCP_ARG_TABLE(kArgsCallbacks) },
        { L"wfp.list", L"Enumerate Windows Filtering Platform providers/sublayers/callouts/filters/layers.", true, MCP_ARG_TABLE(kArgsWfp) },
        { L"alpc.list", L"Enumerate ALPC ports and connections.", true, MCP_ARG_TABLE(kArgsAlpc) },
        { L"vad.list", L"Enumerate process VADs with optional W+X / private / hidden-PTE / DKOM checks.", true, MCP_ARG_TABLE(kArgsVad) },
        { L"threads.list", L"Enumerate process threads, start addresses, APC and stack evidence.", true, MCP_ARG_TABLE(kArgsThreads) },
        { L"etw.integrity", L"Check ETW logger / GetCpuClock integrity (InfinityHook).", true, nullptr, 0 },
        { L"nmi.list", L"Enumerate registered NMI callbacks.", true, MCP_ARG_TABLE(kArgsNmi) },
        { L"fwtable.list", L"Enumerate firmware table providers.", true, MCP_ARG_TABLE(kArgsFwtable) },
        { L"pool.find", L"Enumerate kernel big pool allocations (tag/size/addr/W+X filters).", true, MCP_ARG_TABLE(kArgsPool) },
        { L"address.inspect", L"Inspect a virtual address: page-table walk, permissions, owning module.", true, MCP_ARG_TABLE(kArgsAddress) },
        { L"wnf.decode", L"Decode a WNF state-name hash.", true, MCP_ARG_TABLE(kArgsWnfDecode) },
        { L"wnf.list", L"Enumerate live WNF instances / candidates / lists.", true, MCP_ARG_TABLE(kArgsWnfList) },
        { L"ti.query", L"Query the Threat-Intelligence ETW ring (recent/stats/by/grep).", true, MCP_ARG_TABLE(kArgsTi) },
        { L"module.integrity", L"Check loaded-module PE/section integrity and W+X evidence.", true, MCP_ARG_TABLE(kArgsModuleIntegrity) },
        { L"driver.integrity", L"Check DRIVER_OBJECT dispatch-table integrity.", true, MCP_ARG_TABLE(kArgsDriverIntegrity) },

        { L"ssdt.scan", L"Detect SSDT / shadow-SSDT syscall hooks (routines outside the expected kernel image).", true, nullptr, 0 },
        { L"idt.scan", L"Detect IDT interrupt-gate hooks and per-CPU handler divergence.", true, nullptr, 0 },
        { L"cr.scan", L"Check control registers (CR0.WP, SMEP/SMAP, per-CPU divergence).", true, nullptr, 0 },
        { L"msr.check", L"Check SYSCALL MSRs (LSTAR/CSTAR/STAR/FMASK/EFER) for hooks and per-CPU divergence.", true, nullptr, 0 },
        { L"vbs.scan", L"Report VBS/HVCI, Code Integrity options, hypervisor, Secure Kernel, and trustlets.", true, nullptr, 0 },
        { L"byovd.scan", L"Scan loaded kernel modules against the local BYOVD/LOLDrivers catalog (no network/subprocess).", true, nullptr, 0 },
        { L"pool.scan_pe", L"Hunt PE images (intact or signature-wiped) staged in kernel big pool.", true, MCP_ARG_TABLE(kArgsPoolScanPe) },
        { L"hunt.run", L"Whole-system user-mode anomaly hunt (injection, VAD/PTE, threads, APC, driver/WFP/TI).", true, MCP_ARG_TABLE(kArgsHuntRun) },
        { L"snapshot.capture", L"Capture a same-boot evidence baseline in memory (read kn://snapshot/current; no disk writes).", true, MCP_ARG_TABLE(kArgsSnapshotCapture) },

        { L"memory.read_virtual", L"Read bytes at a kernel/user virtual address (db/dq); returns hex with an unreadable-byte mask. width=1|2|4|8.", true, MCP_ARG_TABLE(kArgsMemoryReadVirtual) },
        { L"memory.read_physical", L"Read bytes at a physical address (!db/!dq); bypasses VA mappings. width=1|2|4|8.", true, MCP_ARG_TABLE(kArgsMemoryReadPhysical) },
        { L"memory.search", L"Search a virtual range for an integer value/pattern (s). width=1|2|4|8; returns match addresses (text).", true, MCP_ARG_TABLE(kArgsMemorySearch) },
        { L"memory.translate", L"Translate a virtual address to physical with page-table walk (vtop); supports per-process DTB (text).", true, MCP_ARG_TABLE(kArgsMemoryTranslate) },
        { L"memory.probe", L"Probe whether a virtual address is readable/writable (query) (text).", true, MCP_ARG_TABLE(kArgsMemoryProbe) },
        { L"memory.read_pointers", L"Dump a pointer table (dps/dds/dqs) with each slot resolved to its nearest symbol; for call tables/vtables/IAT (text). width=4|8.", true, MCP_ARG_TABLE(kArgsMemoryReadPointers) },
        { L"memory.compare", L"Compare two virtual ranges and report mismatch offsets (c); for inline-hook/patch detection (text).", true, MCP_ARG_TABLE(kArgsMemoryCompare) },
        { L"code.disasm", L"Disassemble instructions at an address or function (u/uf) (text).", true, MCP_ARG_TABLE(kArgsCodeDisasm) },
        { L"symbol.search", L"Enumerate symbols by wildcard (x module!mask) to resolve names to addresses.", true, MCP_ARG_TABLE(kArgsSymbolSearch) },
        { L"ti.subscribe", L"Control the Threat-Intelligence ETW subscription (action=start|stop|status); start/stop need --allow-write.", true, MCP_ARG_TABLE(kArgsTiSubscribe) },
        { L"snapshot.diff", L"Diff the in-memory baseline against a fresh live capture, or two snapshot files (!diff) (text).", true, MCP_ARG_TABLE(kArgsSnapshotDiff) },

        { L"memory.write_virtual", L"[WRITE] Write bytes to a kernel virtual address (e*).", false, MCP_ARG_TABLE(kArgsWriteVirtual) },
        { L"memory.write_physical", L"[WRITE] Write bytes to a physical address (pe*).", false, MCP_ARG_TABLE(kArgsWritePhysical) },
        { L"memory.fill", L"[WRITE] Fill a kernel range with a byte pattern.", false, MCP_ARG_TABLE(kArgsFill) },
        { L"memory.move", L"[WRITE] Copy a kernel range from source to dest.", false, MCP_ARG_TABLE(kArgsMove) },
        { L"type.set_field", L"[WRITE] Set a struct field at an address (setfield).", false, MCP_ARG_TABLE(kArgsSetField) },
        { L"process.set_protection", L"[WRITE] Set a process PS_PROTECTION. pid (optional, defaults to self); level=none|ppl-antimalware|ppl-lsa|ppl-windows|ppl-wintcb|pp-windows|pp-wintcb|pp-winsystem.", false, MCP_ARG_TABLE(kArgsSetProtection) },
        { L"dump.raw", L"[WRITE] Dump a kernel range to the given file path (path required; no traversal).", false, MCP_ARG_TABLE(kArgsDumpRaw) },
        { L"dump.pe", L"[WRITE] Reconstruct an on-disk PE image from memory to the given file path (path required).", false, MCP_ARG_TABLE(kArgsDumpPe) },
    };

    const size_t kToolCount = sizeof(kTools) / sizeof(kTools[0]);

    struct McpPromptDef
    {
        const wchar_t* Name;
        const wchar_t* Description;
        const wchar_t* Argument; // single optional argument name, or nullptr
        const wchar_t* Body;     // guidance text (the model expands it)
    };

    const McpPromptDef kPrompts[] =
    {
        { L"callback-audit", L"Audit kernel callback surfaces and flag out-of-module targets.", L"module",
          L"Enumerate callbacks.list across object, registry, process, thread, imageload, and minifilter scopes (optionally filtered to the given module). For each callback target that does not resolve to a loaded module or sits outside its owning image, run address.inspect and module.integrity. Keep raw evidence: callback address, nearest symbol, owning module, altitude. Do not propose any write." },
        { L"driver-surface-map", L"Map one driver's kernel footprint and attack surface.", L"driver",
          L"For the given driver, run driver.integrity, module.integrity, callbacks.list filtered to it, and wfp.list with a module filter. Summarize dispatch targets, owned callbacks, and WFP callouts. Keep raw addresses and symbols. Read-only." },
        { L"address-provenance", L"Determine what a kernel pointer is and whether it is legitimate.", L"address",
          L"For the given address: run address.inspect (page-table walk, permissions, owning module, nearest symbol), then pool.find with addr= the enclosing region, then module.integrity for the owner. State the provenance and any W+X or out-of-module evidence. Read-only." },
        { L"minifilter-review", L"Review minifilter callbacks for rogue filters.", nullptr,
          L"Run callbacks.list scope=minifilter, sort by altitude, and run module.integrity on each filter's owning driver. Flag unusual altitudes, missing names/unload routines, and out-of-module operation callbacks. Read-only." },
        { L"hunt-triage", L"Triage a process for user-mode injection / evasion.", L"pid",
          L"For the given PID: process.find, then vad.list with exec/private/wx/hiddenpte/dkom, threads.list with stacks, and ti.query by pid. Rank findings by severity and keep raw VAD/thread/TI evidence. Read-only." },
        { L"etw-infinityhook-check", L"Sweep for ETW/syscall tampering.", nullptr,
          L"Run etw.integrity and nmi.list. Correlate any flagged GetCpuClock or callback target with module ownership via address.inspect. Read-only." },
        { L"wfp-surface", L"Map the Windows Filtering Platform surface.", nullptr,
          L"Run wfp.list for providers, sublayers, callouts, filters, and layers. For kernel callout pointers, run address.inspect to confirm module ownership. Flag non-Microsoft owners. Read-only." },
    };

    const size_t kPromptCount = sizeof(kPrompts) / sizeof(kPrompts[0]);

    std::wstring RandomHex(size_t byteCount)
    {
        std::wstring out;
        out.reserve(byteCount * 2);
        for (size_t i = 0; i < byteCount; ++i)
        {
            unsigned int value = 0;
            if (rand_s(&value) != 0)
            {
                value = static_cast<unsigned int>(i * 2654435761u);
            }
            wchar_t pair[4];
            swprintf_s(pair, L"%02x", value & 0xFFu);
            out += pair;
        }
        return out;
    }

    // Trim surrounding whitespace and reject a token that is empty or carries
    // whitespace/control characters (which could corrupt the Authorization
    // header comparison). Returns the sanitized token, or empty if invalid.
    std::wstring SanitizeToken(const std::wstring& raw)
    {
        size_t begin = 0;
        size_t end = raw.size();
        while (begin < end && (raw[begin] == L' ' || raw[begin] == L'\t' || raw[begin] == L'\r' || raw[begin] == L'\n'))
        {
            ++begin;
        }
        while (end > begin && (raw[end - 1] == L' ' || raw[end - 1] == L'\t' || raw[end - 1] == L'\r' || raw[end - 1] == L'\n'))
        {
            --end;
        }
        std::wstring token = raw.substr(begin, end - begin);
        if (token.empty() || token.size() > 512)
        {
            return std::wstring();
        }
        for (wchar_t ch : token)
        {
            if (ch < 0x21 || ch > 0x7e)
            {
                // Restrict to printable ASCII without spaces; the minted token
                // is lowercase hex, and an operator-supplied token must be a
                // single safe header value.
                return std::wstring();
            }
        }
        return token;
    }

    std::wstring ReadEnvToken()
    {
        wchar_t buffer[1024];
        DWORD len = GetEnvironmentVariableW(L"KNLIVEDBG_TOKEN", buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
        if (len == 0 || len >= sizeof(buffer) / sizeof(buffer[0]))
        {
            return std::wstring();
        }
        return SanitizeToken(std::wstring(buffer, len));
    }

    std::wstring ReadTokenFile(const std::wstring& path)
    {
        if (path.empty())
        {
            return std::wstring();
        }
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return std::wstring();
        }
        char bytes[1024];
        DWORD read = 0;
        std::wstring token;
        if (ReadFile(file, bytes, sizeof(bytes) - 1, &read, nullptr) && read > 0)
        {
            bytes[read] = '\0';
            // The token is ASCII hex (or a printable ASCII operator token), so a
            // direct widen is sufficient.
            std::wstring wide;
            wide.reserve(read);
            for (DWORD i = 0; i < read; ++i)
            {
                wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(bytes[i])));
            }
            token = SanitizeToken(wide);
        }
        CloseHandle(file);
        return token;
    }

    bool WriteTokenFile(const std::wstring& path, const std::wstring& token)
    {
        if (path.empty())
        {
            return false;
        }
        size_t slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            CreateDirectoryW(path.substr(0, slash).c_str(), nullptr);
        }
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        std::string ascii;
        ascii.reserve(token.size());
        for (wchar_t ch : token)
        {
            ascii.push_back(static_cast<char>(ch & 0x7f));
        }
        DWORD written = 0;
        bool ok = WriteFile(file, ascii.data(), static_cast<DWORD>(ascii.size()), &written, nullptr) != 0;
        CloseHandle(file);
        return ok && written == ascii.size();
    }

    bool ConstantTimeEqual(const std::string& a, const std::string& b)
    {
        // Length difference is itself a signal, but we still iterate over the
        // expected length to avoid an early-out timing oracle on content.
        size_t maxLen = a.size() > b.size() ? a.size() : b.size();
        unsigned int diff = static_cast<unsigned int>(a.size() ^ b.size());
        for (size_t i = 0; i < maxLen; ++i)
        {
            unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
            unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
            diff |= static_cast<unsigned int>(ca ^ cb);
        }
        return diff == 0;
    }

    std::string KnownHeader(const HTTP_REQUEST* request, HTTP_HEADER_ID id)
    {
        const HTTP_KNOWN_HEADER& header = request->Headers.KnownHeaders[id];
        if (header.pRawValue != nullptr && header.RawValueLength > 0)
        {
            return std::string(header.pRawValue, header.RawValueLength);
        }
        return std::string();
    }

    bool EqualsAsciiNoCase(const char* a, size_t aLen, const char* b)
    {
        size_t bLen = strlen(b);
        if (aLen != bLen)
        {
            return false;
        }
        for (size_t i = 0; i < aLen; ++i)
        {
            char ca = a[i];
            char cb = b[i];
            if (ca >= 'A' && ca <= 'Z')
            {
                ca = static_cast<char>(ca - 'A' + 'a');
            }
            if (cb >= 'A' && cb <= 'Z')
            {
                cb = static_cast<char>(cb - 'A' + 'a');
            }
            if (ca != cb)
            {
                return false;
            }
        }
        return true;
    }

    bool UnknownHeader(const HTTP_REQUEST* request, const char* name, std::string* value)
    {
        for (USHORT i = 0; i < request->Headers.UnknownHeaderCount; ++i)
        {
            const HTTP_UNKNOWN_HEADER& header = request->Headers.pUnknownHeaders[i];
            if (header.pName != nullptr && EqualsAsciiNoCase(header.pName, header.NameLength, name))
            {
                if (header.pRawValue != nullptr && header.RawValueLength > 0)
                {
                    *value = std::string(header.pRawValue, header.RawValueLength);
                }
                else
                {
                    value->clear();
                }
                return true;
            }
        }
        return false;
    }

    // Strips a trailing :port from a host/authority token for comparison.
    std::string HostNameOnly(const std::string& host)
    {
        if (!host.empty() && host.front() == '[')
        {
            size_t close = host.find(']');
            if (close != std::string::npos)
            {
                return host.substr(0, close + 1);
            }
        }
        size_t colon = host.rfind(':');
        if (colon != std::string::npos)
        {
            return host.substr(0, colon);
        }
        return host;
    }

    bool IsLoopbackHost(const std::string& host)
    {
        std::string name = HostNameOnly(host);
        return name == "127.0.0.1" || name == "localhost" || name == "[::1]" || name == "::1";
    }

    bool IsAllowedOrigin(const std::string& origin)
    {
        // An absent Origin is fine (non-browser clients). A present Origin must
        // resolve to a loopback authority to defeat DNS-rebinding.
        size_t scheme = origin.find("://");
        if (scheme == std::string::npos)
        {
            return false;
        }
        std::string authority = origin.substr(scheme + 3);
        size_t slash = authority.find('/');
        if (slash != std::string::npos)
        {
            authority = authority.substr(0, slash);
        }
        return IsLoopbackHost(authority);
    }

    std::wstring BuildToolSchema(const McpToolDef& tool)
    {
        std::wstring schema = L"{\"type\":\"object\",\"properties\":{";
        std::wstring required;
        for (size_t i = 0; i < tool.ArgCount; ++i)
        {
            const McpToolArg& arg = tool.Args[i];
            if (i > 0)
            {
                schema += L",";
            }
            schema += mcpjson::Quote(arg.Name);
            if (wcscmp(arg.Type, L"array") == 0)
            {
                // Array-of-string parameter (e.g. a multi-field selector). The
                // engine parses it with ExtractJsonStringArrayValues, so the
                // advertised JSON Schema must say array, not string.
                schema += L":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}";
            }
            else
            {
                schema += L":{\"type\":";
                schema += mcpjson::Quote(arg.Type);
                schema += L"}";
            }
            if (arg.Required)
            {
                if (!required.empty())
                {
                    required += L",";
                }
                required += mcpjson::Quote(arg.Name);
            }
        }
        schema += L"},\"additionalProperties\":false";
        if (!required.empty())
        {
            schema += L",\"required\":[";
            schema += required;
            schema += L"]";
        }
        schema += L"}";
        return schema;
    }

    std::wstring BuildToolsList(bool allowWrite)
    {
        std::wstring out = L"{\"tools\":[";
        bool first = true;
        for (size_t i = 0; i < kToolCount; ++i)
        {
            const McpToolDef& tool = kTools[i];
            if (!tool.ReadOnly && !allowWrite)
            {
                continue;
            }
            if (!first)
            {
                out += L",";
            }
            first = false;
            out += L"{\"name\":";
            out += mcpjson::Quote(tool.Name);
            out += L",\"description\":";
            out += mcpjson::Quote(tool.Description);
            out += L",\"inputSchema\":";
            out += BuildToolSchema(tool);
            out += L",\"annotations\":{\"readOnlyHint\":";
            out += tool.ReadOnly ? L"true" : L"false";
            out += L",\"openWorldHint\":false";
            if (!tool.ReadOnly)
            {
                out += L",\"destructiveHint\":true";
            }
            out += L"}}";
        }
        out += L"]}";
        return out;
    }

    const McpToolDef* FindTool(const std::wstring& name)
    {
        for (size_t i = 0; i < kToolCount; ++i)
        {
            if (name == kTools[i].Name)
            {
                return &kTools[i];
            }
        }
        return nullptr;
    }

    std::wstring BuildResourcesList()
    {
        std::wstring out = L"{\"resources\":[";
        out += L"{\"uri\":\"kn://session/info\",\"name\":\"session-info\",\"description\":\"Driver session, ABI, ownership, write-arm state.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://capabilities\",\"name\":\"capabilities\",\"description\":\"Enabled MCP tools and their argument schemas.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://modules/kernel\",\"name\":\"kernel-modules\",\"description\":\"Loaded kernel module list (name/base/size) -- the name->address map.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://drivers/status\",\"name\":\"drivers-status\",\"description\":\"Driver service state plus single-controller session ownership.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://session/symbols\",\"name\":\"symbols\",\"description\":\"Symbol search path, loaded module count, and engine ready state.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://ti/stats\",\"name\":\"ti-stats\",\"description\":\"Threat-Intelligence ETW ring statistics and active state.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://snapshot/current\",\"name\":\"snapshot-baseline\",\"description\":\"Current in-memory snapshot baseline (kn-live-dbg.snapshot.v1), if captured.\",\"mimeType\":\"application/json\"},";
        out += L"{\"uri\":\"kn://audit/tail\",\"name\":\"audit-tail\",\"description\":\"Last 50 write-audit JSONL entries (when audit is enabled).\",\"mimeType\":\"application/json\"}";
        out += L"]}";
        return out;
    }

    std::wstring BuildCapabilitiesResource(bool allowWrite)
    {
        std::wstring out = L"{\"server\":";
        out += mcpjson::Quote(kServerName);
        out += L",\"writeEnabled\":";
        out += allowWrite ? L"true" : L"false";
        out += L",\"tools\":";
        out += BuildToolsList(allowWrite);
        out += L"}";
        return out;
    }

    std::wstring BuildPromptsList()
    {
        std::wstring out = L"{\"prompts\":[";
        for (size_t i = 0; i < kPromptCount; ++i)
        {
            const McpPromptDef& prompt = kPrompts[i];
            if (i > 0)
            {
                out += L",";
            }
            out += L"{\"name\":";
            out += mcpjson::Quote(prompt.Name);
            out += L",\"description\":";
            out += mcpjson::Quote(prompt.Description);
            if (prompt.Argument != nullptr)
            {
                out += L",\"arguments\":[{\"name\":";
                out += mcpjson::Quote(prompt.Argument);
                out += L",\"required\":false}]";
            }
            out += L"}";
        }
        out += L"]}";
        return out;
    }

    const McpPromptDef* FindPrompt(const std::wstring& name)
    {
        for (size_t i = 0; i < kPromptCount; ++i)
        {
            if (name == kPrompts[i].Name)
            {
                return &kPrompts[i];
            }
        }
        return nullptr;
    }

    std::wstring AuditTimestamp()
    {
        SYSTEMTIME st = {};
        GetSystemTime(&st);
        wchar_t buffer[40];
        swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return buffer;
    }

    // Extracts the remote port from the request's sockaddr without pulling in
    // winsock: sa_family is the first 2 bytes, the port follows at offset 2 in
    // network byte order for both AF_INET and AF_INET6.
    unsigned int AuditPeerPort(const HTTP_REQUEST* request)
    {
        const void* remote = request->Address.pRemoteAddress;
        if (remote == nullptr)
        {
            return 0;
        }
        const unsigned char* sa = reinterpret_cast<const unsigned char*>(remote);
        return (static_cast<unsigned int>(sa[2]) << 8) | static_cast<unsigned int>(sa[3]);
    }

    std::wstring RpcResult(const std::wstring& idRaw, const std::wstring& resultJson)
    {
        std::wstring id = idRaw.empty() ? std::wstring(L"null") : idRaw;
        return L"{\"jsonrpc\":\"2.0\",\"id\":" + id + L",\"result\":" + resultJson + L"}";
    }

    std::wstring RpcError(const std::wstring& idRaw, int code, const std::wstring& message)
    {
        std::wstring id = idRaw.empty() ? std::wstring(L"null") : idRaw;
        return L"{\"jsonrpc\":\"2.0\",\"id\":" + id + L",\"error\":{\"code\":" +
               std::to_wstring(code) + L",\"message\":" + mcpjson::Quote(message) + L"}}";
    }

    std::wstring BuildToolResult(const McpEngineResult& result)
    {
        // content[0].text MUST carry the exact data (serialized JSON when
        // structured, otherwise the captured text) so non-structured clients
        // are not lossy.
        std::wstring primaryText = result.StructuredJson.empty() ? result.Text : result.StructuredJson;
        std::wstring out = L"{\"content\":[{\"type\":\"text\",\"text\":";
        out += mcpjson::Quote(primaryText);
        out += L"}";
        if (!result.StructuredJson.empty() && !result.Text.empty())
        {
            out += L",{\"type\":\"text\",\"text\":";
            out += mcpjson::Quote(result.Text);
            out += L"}";
        }
        out += L"]";
        if (!result.StructuredJson.empty())
        {
            out += L",\"structuredContent\":";
            out += result.StructuredJson;
        }
        out += L",\"isError\":";
        out += result.IsError ? L"true" : L"false";
        out += L"}";
        return out;
    }
}

// ---------------------------------------------------------------------------
// McpServer
//
// The engine-thread dispatch lives in main.cpp: it drains jobs via TryPopJob()
// and fulfills each job's promise. The listener thread only enqueues + waits.
// ---------------------------------------------------------------------------

McpServer::McpServer()
{
}

McpServer::~McpServer()
{
    Stop();
}

bool McpServer::IsRunning() const
{
    return running_.load();
}

bool McpServer::AllowWrite() const
{
    return config_.AllowWrite;
}

bool McpServer::IsWriteTool(const std::wstring& name) const
{
    const McpToolDef* tool = FindTool(name);
    return tool != nullptr && !tool->ReadOnly;
}

uint16_t McpServer::Port() const
{
    return config_.Port;
}

std::wstring McpServer::Token() const
{
    return token_;
}

std::wstring McpServer::TokenSource() const
{
    return tokenSource_;
}

std::wstring McpServer::ResolveToken()
{
    // 1) explicit --token: use and persist (so later restarts without --token,
    //    and without an env var, reuse it from the file).
    std::wstring explicitToken = SanitizeToken(config_.TokenOverride);
    if (!explicitToken.empty())
    {
        WriteTokenFile(config_.TokenPath, explicitToken);
        tokenSource_ = L"override";
        return explicitToken;
    }

    // 2) KNLIVEDBG_TOKEN env: authoritative each run, not persisted (env wins).
    std::wstring envToken = ReadEnvToken();
    if (!envToken.empty())
    {
        tokenSource_ = L"env";
        return envToken;
    }

    // 3) persisted file: reuse unless an explicit rotation was requested.
    if (!config_.RotateToken)
    {
        std::wstring saved = ReadTokenFile(config_.TokenPath);
        if (!saved.empty())
        {
            tokenSource_ = L"reused";
            return saved;
        }
    }

    // 4) mint a fresh random token and persist it for the next restart.
    std::wstring fresh = RandomHex(32);
    WriteTokenFile(config_.TokenPath, fresh);
    tokenSource_ = L"new";
    return fresh;
}

std::wstring McpServer::AuditPath() const
{
    return config_.AuditPath;
}

void McpServer::AppendAuditLine(const std::wstring& line)
{
    if (config_.AuditPath.empty())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(auditMutex_);
    std::ofstream file(config_.AuditPath.c_str(), std::ios::app | std::ios::binary);
    if (file)
    {
        std::string utf8 = mcpjson::WideToUtf8(line);
        file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
        file.put('\n');
    }
}

HANDLE McpServer::JobReadyEvent() const
{
    return jobReadyEvent_;
}

std::shared_ptr<McpJob> McpServer::TryPopJob()
{
    std::shared_ptr<McpJob> job;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (!queue_.empty())
        {
            job = queue_.front();
            queue_.pop_front();
        }
    }
    return job;
}

bool McpServer::EnqueueAndWait(const McpEngineRequest& request, uint32_t timeoutMs, McpEngineResult* result)
{
    std::shared_ptr<McpJob> job = std::make_shared<McpJob>();
    job->Request = request;
    std::future<McpEngineResult> future = job->ResultPromise.get_future();

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (queue_.size() >= maxPending_)
        {
            return false;
        }
        queue_.push_back(job);
    }
    SetEvent(jobReadyEvent_);

    if (future.wait_for(std::chrono::milliseconds(timeoutMs)) != std::future_status::ready)
    {
        result->IsError = true;
        result->Text = L"engine timeout";
        return true;
    }

    *result = future.get();
    return true;
}

bool McpServer::Start(const McpServerConfig& config, std::wstring* error)
{
    bool ok = false;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    HTTP_SERVER_SESSION_ID serverSession = 0;
    HTTP_URL_GROUP_ID urlGroup = 0;

    do
    {
        if (running_.load())
        {
            if (error != nullptr)
            {
                *error = L"MCP server is already running";
            }
            break;
        }

        config_ = config;
        sessionId_.clear();
        stopRequested_.store(false);

        // Ensure the .kn-live-dbg directory exists (audit log + persisted token);
        // best-effort, logging/persistence are non-fatal.
        if (!config_.AuditPath.empty())
        {
            size_t slash = config_.AuditPath.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                CreateDirectoryW(config_.AuditPath.substr(0, slash).c_str(), nullptr);
            }
        }

        // Resolve a STABLE bearer token so a client registered once keeps
        // working across restarts (the dir above must exist first so a freshly
        // minted token can be persisted).
        token_ = ResolveToken();

        jobReadyEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (jobReadyEvent_ == nullptr || stopEvent_ == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"failed to create MCP synchronization events";
            }
            break;
        }

        ULONG status = HttpInitialize(version, HTTP_INITIALIZE_SERVER, nullptr);
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpInitialize failed: " + std::to_wstring(status);
            }
            break;
        }
        httpInitialized_ = true;

        status = HttpCreateServerSession(version, &serverSession, 0);
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpCreateServerSession failed: " + std::to_wstring(status);
            }
            break;
        }
        serverSessionId_ = reinterpret_cast<void*>(serverSession);

        status = HttpCreateUrlGroup(serverSession, &urlGroup, 0);
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpCreateUrlGroup failed: " + std::to_wstring(status);
            }
            break;
        }
        urlGroupId_ = reinterpret_cast<void*>(urlGroup);

        status = HttpCreateRequestQueue(version, nullptr, nullptr, 0, &requestQueue_);
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpCreateRequestQueue failed: " + std::to_wstring(status);
            }
            break;
        }

        HTTP_BINDING_INFO binding = {};
        binding.Flags.Present = 1;
        binding.RequestQueueHandle = requestQueue_;
        status = HttpSetUrlGroupProperty(urlGroup, HttpServerBindingProperty, &binding, sizeof(binding));
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpSetUrlGroupProperty failed: " + std::to_wstring(status);
            }
            break;
        }

        std::wstring url4 = L"http://127.0.0.1:" + std::to_wstring(config_.Port) + L"/mcp/";
        status = HttpAddUrlToUrlGroup(urlGroup, url4.c_str(), 0, 0);
        if (status != NO_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"HttpAddUrlToUrlGroup(127.0.0.1) failed: " + std::to_wstring(status) +
                         L" (port in use or insufficient rights)";
            }
            break;
        }

        // IPv6 loopback is best-effort; ignore failure so IPv4-only hosts work.
        std::wstring url6 = L"http://[::1]:" + std::to_wstring(config_.Port) + L"/mcp/";
        HttpAddUrlToUrlGroup(urlGroup, url6.c_str(), 0, 0);

        // Opt-in NETWORK exposure: also register the requested address so a
        // remote client (reachable IP) can connect directly over HTTP. Loopback
        // stays registered for local use. "0.0.0.0"/"*"/"+" => all interfaces.
        if (!config_.BindAddress.empty())
        {
            std::wstring host = config_.BindAddress;
            if (host == L"0.0.0.0" || host == L"*" || host == L"+")
            {
                host = L"+";
            }
            std::wstring urlRemote = L"http://" + host + L":" + std::to_wstring(config_.Port) + L"/mcp/";
            status = HttpAddUrlToUrlGroup(urlGroup, urlRemote.c_str(), 0, 0);
            if (status != NO_ERROR)
            {
                if (error != nullptr)
                {
                    *error = L"HttpAddUrlToUrlGroup(" + config_.BindAddress + L") failed: " + std::to_wstring(status) +
                             L" (port in use, address not local, or insufficient rights)";
                }
                break;
            }
        }

        running_.store(true);
        listener_ = std::thread(&McpServer::ListenerThreadMain, this);
        ok = true;
    } while (false);

    if (!ok)
    {
        Stop();
    }

    return ok;
}

void McpServer::RequestStop()
{
    stopRequested_.store(true);
    running_.store(false);
    if (stopEvent_ != nullptr)
    {
        SetEvent(stopEvent_);
    }
}

void McpServer::Stop()
{
    std::lock_guard<std::mutex> lock(stopMutex_);

    if (stopEvent_ != nullptr)
    {
        stopRequested_.store(true);
        SetEvent(stopEvent_);
    }

    running_.store(false);

    if (requestQueue_ != nullptr)
    {
        // Unblock a pending HttpReceiveHttpRequest.
        HttpShutdownRequestQueue(requestQueue_);
    }

    if (listener_.joinable())
    {
        listener_.join();
    }

    // Fail any jobs still queued so transport waiters unblock.
    {
        std::lock_guard<std::mutex> queueLock(queueMutex_);
        while (!queue_.empty())
        {
            std::shared_ptr<McpJob> job = queue_.front();
            queue_.pop_front();
            McpEngineResult result;
            result.IsError = true;
            result.Text = L"MCP server stopping";
            try
            {
                job->ResultPromise.set_value(result);
            }
            catch (...)
            {
            }
        }
    }

    if (urlGroupId_ != nullptr)
    {
        HttpCloseUrlGroup(reinterpret_cast<HTTP_URL_GROUP_ID>(urlGroupId_));
        urlGroupId_ = nullptr;
    }
    if (requestQueue_ != nullptr)
    {
        HttpCloseRequestQueue(requestQueue_);
        requestQueue_ = nullptr;
    }
    if (serverSessionId_ != nullptr)
    {
        HttpCloseServerSession(reinterpret_cast<HTTP_SERVER_SESSION_ID>(serverSessionId_));
        serverSessionId_ = nullptr;
    }
    if (httpInitialized_)
    {
        HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
        httpInitialized_ = false;
    }
    if (stopEvent_ != nullptr)
    {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
    if (jobReadyEvent_ != nullptr)
    {
        CloseHandle(jobReadyEvent_);
        jobReadyEvent_ = nullptr;
    }
}

void McpServer::ListenerThreadMain()
{
    std::vector<char> buffer(65536);

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr)
    {
        return;
    }

    // Sends an HTTP response with a JSON (or empty) body. ANSI strings are kept
    // local so they outlive the synchronous HttpSendHttpResponse call.
    auto sendResponse = [&](HTTP_REQUEST_ID requestId, USHORT statusCode, const char* reason, const std::wstring& bodyWide)
    {
        std::string body = mcpjson::WideToUtf8(bodyWide);
        std::string sessionAnsi = mcpjson::WideToUtf8(sessionId_);

        HTTP_RESPONSE response = {};
        response.StatusCode = statusCode;
        response.pReason = reason;
        response.ReasonLength = static_cast<USHORT>(strlen(reason));

        const char* contentType = "application/json";
        response.Headers.KnownHeaders[HttpHeaderContentType].pRawValue = contentType;
        response.Headers.KnownHeaders[HttpHeaderContentType].RawValueLength = static_cast<USHORT>(strlen(contentType));

        HTTP_UNKNOWN_HEADER unknownHeaders[1] = {};
        if (!sessionAnsi.empty())
        {
            unknownHeaders[0].pName = "Mcp-Session-Id";
            unknownHeaders[0].NameLength = static_cast<USHORT>(strlen("Mcp-Session-Id"));
            unknownHeaders[0].pRawValue = sessionAnsi.c_str();
            unknownHeaders[0].RawValueLength = static_cast<USHORT>(sessionAnsi.size());
            response.Headers.pUnknownHeaders = unknownHeaders;
            response.Headers.UnknownHeaderCount = 1;
        }

        HTTP_DATA_CHUNK chunk = {};
        if (!body.empty())
        {
            chunk.DataChunkType = HttpDataChunkFromMemory;
            chunk.FromMemory.pBuffer = const_cast<char*>(body.data());
            chunk.FromMemory.BufferLength = static_cast<ULONG>(body.size());
            response.EntityChunkCount = 1;
            response.pEntityChunks = &chunk;
        }

        ULONG bytesSent = 0;
        HttpSendHttpResponse(requestQueue_, requestId, 0, &response, nullptr, &bytesSent, nullptr, 0, nullptr, nullptr);
    };

    auto readBody = [&](HTTP_REQUEST_ID requestId) -> std::string
    {
        std::string body;
        char chunk[8192];
        for (;;)
        {
            ULONG got = 0;
            ULONG status = HttpReceiveRequestEntityBody(requestQueue_, requestId, 0, chunk, sizeof(chunk), &got, nullptr);
            if (status == NO_ERROR)
            {
                if (got > 0)
                {
                    body.append(chunk, got);
                }
                if (got == 0)
                {
                    break;
                }
                continue;
            }
            if (status == ERROR_HANDLE_EOF)
            {
                if (got > 0)
                {
                    body.append(chunk, got);
                }
                break;
            }
            break;
        }
        return body;
    };

    // Append one forensic JSONL record per data-bearing MCP request. Always on
    // while the server runs (independent of the operator's `ai audit` setting).
    auto writeAudit = [&](const HTTP_REQUEST* request, const std::wstring& method, const std::wstring& name,
                          const std::wstring& args, const std::wstring& decision, bool isError, size_t resultBytes)
    {
        std::wstring record = L"{\"ts\":" + mcpjson::Quote(AuditTimestamp());
        record += L",\"session\":" + mcpjson::Quote(sessionId_);
        record += L",\"peerPort\":" + std::to_wstring(AuditPeerPort(request));
        record += L",\"method\":" + mcpjson::Quote(method);
        if (!name.empty())
        {
            record += L",\"tool\":" + mcpjson::Quote(name);
        }
        if (!args.empty())
        {
            std::wstring trimmedArgs = args.size() > 512 ? (args.substr(0, 512) + L"...(truncated)") : args;
            record += L",\"args\":" + mcpjson::Quote(trimmedArgs);
        }
        record += L",\"decision\":" + mcpjson::Quote(decision);
        record += L",\"isError\":";
        record += isError ? L"true" : L"false";
        record += L",\"resultBytes\":" + std::to_wstring(resultBytes);
        record += L",\"writeArmed\":";
        record += config_.AllowWrite ? L"true" : L"false";
        record += L"}";
        AppendAuditLine(record);
    };

    auto processRequest = [&](const HTTP_REQUEST* request)
    {
        HTTP_REQUEST_ID requestId = request->RequestId;

        // Transport-layer gating before any JSON-RPC work.
        if (request->Verb != HttpVerbPOST)
        {
            sendResponse(requestId, 405, "Method Not Allowed", L"");
            return;
        }

        std::wstring path;
        if (request->CookedUrl.pAbsPath != nullptr && request->CookedUrl.AbsPathLength > 0)
        {
            path.assign(request->CookedUrl.pAbsPath, request->CookedUrl.AbsPathLength / sizeof(wchar_t));
        }
        if (path.rfind(L"/mcp", 0) != 0)
        {
            sendResponse(requestId, 404, "Not Found", L"");
            return;
        }

        // Loopback-only mode enforces a strict loopback Host (DNS-rebinding
        // defense). When network exposure is opted in (--bind), any Host is
        // accepted; the bearer token plus the Origin rejection below remain the
        // barrier (non-browser MCP clients send no Origin).
        std::string host = KnownHeader(request, HttpHeaderHost);
        if (config_.BindAddress.empty() && !IsLoopbackHost(host))
        {
            sendResponse(requestId, 403, "Forbidden", L"");
            return;
        }

        std::string origin;
        if (UnknownHeader(request, "origin", &origin) && !origin.empty() && !IsAllowedOrigin(origin))
        {
            sendResponse(requestId, 403, "Forbidden", L"");
            return;
        }

        std::string authorization = KnownHeader(request, HttpHeaderAuthorization);
        std::string expected = "Bearer " + mcpjson::WideToUtf8(token_);
        if (!ConstantTimeEqual(authorization, expected))
        {
            sendResponse(requestId, 401, "Unauthorized", L"");
            return;
        }

        std::string bodyUtf8 = readBody(requestId);
        std::wstring body = mcpjson::Utf8ToWide(bodyUtf8);

        std::wstring method;
        std::wstring idRaw;
        std::wstring params;
        mcpjson::GetString(body, L"method", &method);
        mcpjson::FindRawValue(body, L"id", &idRaw);
        if (!mcpjson::FindRawValue(body, L"params", &params))
        {
            params = L"{}";
        }

        if (method.empty())
        {
            sendResponse(requestId, 200, "OK", RpcError(idRaw, -32600, L"invalid request: missing method"));
            return;
        }

        // Notifications carry no id and expect no JSON-RPC response.
        if (method.rfind(L"notifications/", 0) == 0)
        {
            sendResponse(requestId, 202, "Accepted", L"");
            return;
        }

        if (method == L"initialize")
        {
            sessionId_ = RandomHex(16);
            std::wstring result =
                L"{\"protocolVersion\":" + mcpjson::Quote(kProtocolVersion) +
                L",\"capabilities\":{\"tools\":{\"listChanged\":false},\"resources\":{},\"prompts\":{}}" +
                L",\"serverInfo\":{\"name\":" + mcpjson::Quote(kServerName) +
                L",\"version\":" + mcpjson::Quote(kServerVersion) + L"}}";
            writeAudit(request, L"initialize", L"", L"", L"session-open", false, 0);
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, result));
            return;
        }

        if (method == L"ping")
        {
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, L"{}"));
            return;
        }

        // Every other method requires the single pinned session.
        if (sessionId_.empty())
        {
            sendResponse(requestId, 200, "OK", RpcError(idRaw, -32600, L"initialize required before this request"));
            return;
        }
        std::string clientSession;
        UnknownHeader(request, "mcp-session-id", &clientSession);
        if (mcpjson::Utf8ToWide(clientSession) != sessionId_)
        {
            sendResponse(requestId, 200, "OK", RpcError(idRaw, -32600, L"invalid or missing Mcp-Session-Id"));
            return;
        }

        if (method == L"tools/list")
        {
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, BuildToolsList(config_.AllowWrite)));
            return;
        }

        if (method == L"tools/call")
        {
            std::wstring name;
            mcpjson::GetString(params, L"name", &name);
            std::wstring argsRaw;
            if (!mcpjson::FindRawValue(params, L"arguments", &argsRaw) || argsRaw.empty())
            {
                argsRaw = L"{}";
            }

            const McpToolDef* tool = FindTool(name);
            if (tool == nullptr)
            {
                writeAudit(request, L"tools/call", name, argsRaw, L"unknown-tool", true, 0);
                sendResponse(requestId, 200, "OK", RpcError(idRaw, -32601, L"unknown tool: " + name));
                return;
            }

            McpEngineResult result;
            std::wstring decision = L"ok";
            if (!tool->ReadOnly && !config_.AllowWrite)
            {
                result.IsError = true;
                result.Text = L"writes are disabled; start the MCP server with --allow-write (lab mode)";
                decision = L"writes-disabled";
            }
            else
            {
                McpEngineRequest engineRequest;
                engineRequest.Kind = McpRequestKind::ToolCall;
                engineRequest.Name = name;
                engineRequest.ArgumentsJson = argsRaw;
                if (!EnqueueAndWait(engineRequest, 30000, &result))
                {
                    result.IsError = true;
                    result.Text = L"engine busy; retry shortly";
                    decision = L"engine-busy";
                }
                else if (result.IsError)
                {
                    decision = L"tool-error";
                }
            }

            writeAudit(request, L"tools/call", name, argsRaw, decision, result.IsError,
                       result.Text.size() + result.StructuredJson.size());
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, BuildToolResult(result)));
            return;
        }

        if (method == L"resources/list")
        {
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, BuildResourcesList()));
            return;
        }

        if (method == L"resources/read")
        {
            std::wstring uri;
            mcpjson::GetString(params, L"uri", &uri);

            std::wstring contentsText;
            if (uri == L"kn://capabilities")
            {
                // Static manifest; served transport-side without an engine hop.
                contentsText = BuildCapabilitiesResource(config_.AllowWrite);
            }
            else if (uri.rfind(L"kn://", 0) == 0)
            {
                // All other kn:// resources read live state; the engine thread
                // (DispatchMcpRequest) validates the URI and builds the JSON.
                McpEngineRequest engineRequest;
                engineRequest.Kind = McpRequestKind::ResourceRead;
                engineRequest.Name = uri;
                McpEngineResult result;
                if (!EnqueueAndWait(engineRequest, 30000, &result))
                {
                    writeAudit(request, L"resources/read", uri, L"", L"engine-busy", true, 0);
                    sendResponse(requestId, 200, "OK", RpcError(idRaw, -32603, L"engine busy"));
                    return;
                }
                if (result.IsError)
                {
                    writeAudit(request, L"resources/read", uri, L"", L"unknown-resource", true, 0);
                    std::wstring message = result.Text.empty() ? (L"unknown resource: " + uri) : result.Text;
                    sendResponse(requestId, 200, "OK", RpcError(idRaw, -32602, message));
                    return;
                }
                contentsText = result.StructuredJson.empty() ? result.Text : result.StructuredJson;
            }
            else
            {
                writeAudit(request, L"resources/read", uri, L"", L"unknown-resource", true, 0);
                sendResponse(requestId, 200, "OK", RpcError(idRaw, -32602, L"unknown resource: " + uri));
                return;
            }

            writeAudit(request, L"resources/read", uri, L"", L"ok", false, contentsText.size());
            std::wstring result = L"{\"contents\":[{\"uri\":" + mcpjson::Quote(uri) +
                L",\"mimeType\":\"application/json\",\"text\":" + mcpjson::Quote(contentsText) + L"}]}";
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, result));
            return;
        }

        if (method == L"prompts/list")
        {
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, BuildPromptsList()));
            return;
        }

        if (method == L"prompts/get")
        {
            std::wstring name;
            mcpjson::GetString(params, L"name", &name);
            std::wstring argsRaw;
            mcpjson::FindRawValue(params, L"arguments", &argsRaw);

            const McpPromptDef* prompt = FindPrompt(name);
            if (prompt == nullptr)
            {
                sendResponse(requestId, 200, "OK", RpcError(idRaw, -32602, L"unknown prompt: " + name));
                return;
            }

            std::wstring text = prompt->Body;
            if (prompt->Argument != nullptr && !argsRaw.empty())
            {
                std::wstring value;
                if (mcpjson::GetString(argsRaw, prompt->Argument, &value) && !value.empty())
                {
                    text += L"\n\nTarget ";
                    text += prompt->Argument;
                    text += L": ";
                    text += value;
                }
            }

            std::wstring result = L"{\"description\":" + mcpjson::Quote(prompt->Description) +
                L",\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":" +
                mcpjson::Quote(text) + L"}}]}";
            sendResponse(requestId, 200, "OK", RpcResult(idRaw, result));
            return;
        }

        sendResponse(requestId, 200, "OK", RpcError(idRaw, -32601, L"method not found: " + method));
    };

    while (!stopRequested_.load())
    {
        ResetEvent(overlapped.hEvent);
        HTTP_REQUEST* request = reinterpret_cast<HTTP_REQUEST*>(buffer.data());
        ZeroMemory(buffer.data(), buffer.size());

        ULONG status = HttpReceiveHttpRequest(
            requestQueue_,
            HTTP_NULL_ID,
            0,
            request,
            static_cast<ULONG>(buffer.size()),
            nullptr,
            &overlapped);

        if (status == ERROR_IO_PENDING)
        {
            HANDLE handles[2] = { overlapped.hEvent, stopEvent_ };
            DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (waitResult != WAIT_OBJECT_0)
            {
                // Stop requested while a receive is pending. Cancel it and wait
                // for the cancellation to complete so no kernel I/O still
                // references the overlapped/event when we close it.
                CancelIoEx(requestQueue_, &overlapped);
                DWORD drained = 0;
                GetOverlappedResult(requestQueue_, &overlapped, &drained, TRUE);
                break;
            }

            DWORD bytes = 0;
            if (!GetOverlappedResult(requestQueue_, &overlapped, &bytes, FALSE))
            {
                DWORD overlappedError = GetLastError();
                if (overlappedError == ERROR_OPERATION_ABORTED || stopRequested_.load())
                {
                    break;
                }
                continue;
            }
            status = NO_ERROR;
        }

        if (status == NO_ERROR)
        {
            processRequest(request);
            continue;
        }

        if (status == ERROR_MORE_DATA)
        {
            // Oversized headers for our fixed buffer; reject and move on.
            sendResponse(request->RequestId, 431, "Request Header Fields Too Large", L"");
            continue;
        }

        if (status == ERROR_OPERATION_ABORTED || stopRequested_.load())
        {
            break;
        }

        // Transient error: avoid a busy spin.
        Sleep(10);
    }

    CloseHandle(overlapped.hEvent);
}
