# MCP tool reference

Source: [McpServer.cpp](../user/McpServer.cpp), current main. The catalog has
**68 tools in read-only mode** and **12 additional write tools**.
`ti.subscribe` is listed in read-only mode, but its `start`/`stop` actions require
write permission. Read-only describes target mutation policy; it does not mean
no in-memory state, resource use, or audit output.

Use `tools/list` on the running server for the active schema. `*` marks required
arguments; arrays contain strings. Numeric values are strings where the schema
says `string`. Unknown keys, wrong types, missing required values, and invalid
ranges are rejected. [Setup](MCP_SETUP.md) / [한국어](MCP_SETUP.ko.md).

## Tools

| Tool | Mode | Arguments | Meaning |
| --- | --- | --- | --- |
| `operations.get` | Read | `operation_id*` | Query bounded operation outcome metadata without an engine hop or retry; see the [state contract](MCP_SERVER_DESIGN.md#execution-boundary). |
| `process.find` | Read | `image`: string, `pid`: string, `eprocess`: string | Find live processes by image name, PID, or EPROCESS address. |
| `process.describe` | Read | `source`: string, `pid`: string, `eprocess`: string, `fields`: array | Describe an _EPROCESS (PID, DTB, PEB, threads, parent). |
| `type.describe` | Read | `source`: string, `address`: string, `type`: string, `fields`: array | Dump a kernel structure (dt) at an address or for a process. |
| `callbacks.list` | Read | `scope`: string, `module`: string | Enumerate kernel callbacks (object/registry/process/thread/imageload/minifilter). |
| `wfp.list` | Read | `scope`: string, `module`: string, `provider`: string, `layer`: string | Enumerate Windows Filtering Platform providers/sublayers/callouts/filters/layers. |
| `wfp.kernel_callouts` | Read | None | Resolve kernel-mode WFP classify/notify/flowDelete callout pointers from netio.sys. |
| `alpc.list` | Read | `scope`: string, `name`: string, `pid`: string | Enumerate ALPC ports and connections. |
| `vad.list` | Read | `mode`: string, `pid`: string, `image`: string, `eprocess`: string, `exec`: boolean, `private`: boolean, `wx`: boolean, `pe`: boolean, `hiddenpte`: boolean, `dkom`: boolean, `summary`: boolean, `limit`: string | Enumerate VADs, scan a process for injected/hidden executable regions, or inventory loaded/mapped PEs (mode: list, scan, modules). |
| `threads.list` | Read | `pid`: string, `image`: string, `eprocess`: string, `apc`: boolean, `stacks`: boolean, `limit`: string | Enumerate process threads, start addresses, APC and stack evidence. |
| `etw.integrity` | Read | None | Check ETW logger / GetCpuClock integrity (InfinityHook). |
| `etw.providers` | Read | None | Heuristic/partial ETW provider registration surface and enable-callback ownership. |
| `etw.ti_cross` | Read | None | Correlate active Threat-Intelligence subscription reception with silence/drop signals. |
| `nmi.list` | Read | `scope`: string | Enumerate registered NMI callbacks. |
| `minifilter.list` | Read | `filter`: string, `name`: string | List filesystem minifilters and IRP pre/post registrations. |
| `payload.inspect` | Read | `address`: string, `va`: string, `symbol`: string | Trace one kernel address: page walk, big-pool lookup, PE probe, disassembly. |
| `payload.scan` | Read | `limit`: string | Sweep hook surfaces for unbacked pointers and trace each unique target. |
| `mapper.list` | Read | `scope`: string, `limit`: string | Walk MmUnloadedDrivers, PiDDBCacheTable, and ci hash-bucket leftovers. |
| `kpage.list` | Read | `deep`: boolean, `wx`: boolean, `pe`: boolean, `limit`: string | Find executable kernel pages outside loaded modules. deep=true enables the PFN pass. |
| `hal.scan` | Read | None | Check HalDispatchTable / HalPrivateDispatchTable function-pointer ownership. |
| `hive.list` | Read | None | Walk registry hive list and flag GetCellRoutine handlers outside ntoskrnl. |
| `token.inspect` | Read | `pid`: string, `image`: string, `eprocess`: string, `limit`: string | Inspect process token privilege Present/Enabled masks. |
| `dpc.list` | Read | None | Enumerate sampled DPC deferred routines and flag non-image callbacks. |
| `timer.list` | Read | None | Enumerate kernel timer DPC routines and flag non-image callbacks. |
| `fwtable.list` | Read | `scope`: string, `module`: string, `provider`: string, `signature`: string | Enumerate firmware table providers. |
| `pool.find` | Read | `tag`: string, `min`: string, `max`: string, `addr`: string, `limit`: string, `paged`: string, `annotate`: boolean, `wx`: boolean | Enumerate kernel big pool allocations (tag/size/addr/W+X filters). |
| `address.inspect` | Read | `address`: string, `va`: string, `symbol`: string | Inspect a virtual address: page-table walk, permissions, owning module. |
| `wnf.decode` | Read | `hash`: string, `state`: string, `state_name`: string | Decode a WNF state-name hash. |
| `wnf.list` | Read | `scope`: string | Enumerate live WNF instances / candidates / lists. |
| `ti.query` | Read | `action`: string, `count`: string, `pid`: string, `task`: string, `pattern`: string | Query the Threat-Intelligence ETW ring (recent/stats/by/grep). |
| `module.integrity` | Read | `module`: string, `target`: string, `limit`: string, `summary`: boolean, `verbose`: boolean, `headers`: boolean, `sections`: boolean, `wx`: boolean, `mismatch`: boolean, `disk`: boolean, `iat`: boolean, `prologue`: boolean | Check loaded-module PE/section integrity and W+X evidence. |
| `driver.integrity` | Read | `driver`: string, `target`: string, `limit`: string | Check DRIVER_OBJECT dispatch-table integrity. |
| `driver.object` | Read | `driver`: string, `name`: string, `target`: string, `address`: string | Inspect one DRIVER_OBJECT and its DEVICE_OBJECT / attached-device chain. |
| `device.stack` | Read | `address`: string, `va`: string, `device`: string | Walk a DEVICE_OBJECT AttachedDevice/AttachedTo stack. |
| `handles.list` | Read | `pid`: string, `target`: string, `limit`: string | Enumerate process handles and flag non-system VM/DUP access to another process. |
| `hiddenproc.list` | Read | None | Cross-view hidden processes: ActiveProcessLinks vs SPI vs Toolhelp vs handle owners. |
| `wdfilter.list` | Read | None | Walk WdFilter RuntimeDriver leftovers that survive after a mapper unloads. |
| `inputstack.list` | Read | None | Walk keyboard/mouse class device stacks and flag unknown attached drivers. |
| `dma.posture` | Read | None | Report IOMMU firmware tables, Kernel DMA Protection, and removable PCI bus posture. |
| `hv.posture` | Read | None | Report hypervisor presence from CPUID, CR4.VMXE, and CPUID timing without FEATURE_CONTROL. |
| `dump.analyze` | Read | `path`: string, `file`: string | Parse a dump-kernel DUMP_HEADER64, physical runs, and loaded modules (4-level or LA57 5-level VA walk). |
| `ssdt.scan` | Read | None | Detect SSDT / shadow-SSDT syscall hooks (routines outside the expected kernel image). |
| `idt.scan` | Read | None | Detect IDT interrupt-gate hooks and per-CPU handler divergence. |
| `cr.scan` | Read | None | Check control registers (CR0.WP, SMEP/SMAP, per-CPU divergence). |
| `msr.check` | Read | None | Check SYSCALL MSRs (LSTAR/CSTAR/STAR/FMASK/EFER) for hooks and per-CPU divergence. |
| `vbs.scan` | Read | None | Report VBS/HVCI, Code Integrity options, hypervisor, Secure Kernel, and trustlets. |
| `byovd.scan` | Read | None | Scan loaded kernel modules against the local BYOVD/LOLDrivers catalog (no network/subprocess). |
| `byovd.status` | Read | None | Report local BYOVD catalog age, source counts, and YARA rule availability. |
| `pool.scan_pe` | Read | `tag`: string, `limit`: string, `suspicious`: boolean | Hunt PE images (intact or signature-wiped) staged in kernel big pool. |
| `hunt.run` | Read | `mode`: string | Whole-system user-mode anomaly hunt (injection, VAD/PTE, threads, APC, driver/WFP/TI). |
| `snapshot.capture` | Read | `name`: string | Capture a same-boot evidence baseline in memory (read kn://snapshot/current; no disk writes). |
| `snapshot.show` | Read | `source`: string, `path`: string, `domains`: boolean, `warnings`: boolean | Show the current snapshot baseline or a snapshot JSON file; returns summary text plus structured JSON. |
| `timeline.status` | Read | None | Report the in-memory evidence timeline store status and counters. |
| `timeline.query` | Read | `source`: string, `domain`: string, `pid`: string, `limit`: string, `order`: string | Query the in-memory evidence timeline by source/domain/PID/limit. |
| `timeline.export` | Read | `source`: string, `domain`: string, `pid`: string, `limit`: string, `order`: string | Return in-memory timeline events as JSONL text without writing to disk. |
| `graph.query` | Read | `source`: string, `domain`: string, `image`: string, `pid`: string, `limit`: string, `order`: string | Derive a process/image/domain/source evidence graph from in-memory timeline events. |
| `timeline.reconcile` | Read | `path`: string, `snapshot`: string, `source`: string, `domain`: string, `pid`: string, `limit`: string | Compare ingested timeline evidence with a snapshot baseline or JSON file. |
| `memory.read_virtual` | Read | `address`: string, `va`: string, `symbol`: string, `width`: string, `count`: string, `process`: string | Read bytes at a kernel/user virtual address (db/dq); returns hex with an unreadable-byte mask. width=1\|2\|4\|8. |
| `memory.read_physical` | Read | `physical_address`*: string, `width`: string, `count`: string | Read bytes at a physical address (!db/!dq); bypasses VA mappings. width=1\|2\|4\|8. |
| `memory.search` | Read | `address`*: string, `length`*: string, `value`*: string, `width`: string | Search a virtual range for an integer value/pattern (s). width=1\|2\|4\|8; returns match addresses (text). |
| `memory.translate` | Read | `address`: string, `va`: string, `symbol`: string, `process`: string, `cr3`: string, `length`: string | Translate a virtual address to physical with page-table walk (vtop); supports per-process DTB (text). |
| `memory.probe` | Read | `address`: string, `va`: string, `symbol`: string, `length`: string | Probe whether a virtual address is readable/writable (query) (text). |
| `memory.read_pointers` | Read | `address`: string, `va`: string, `symbol`: string, `width`: string, `count`: string | Dump a pointer table (dps/dds/dqs) with each slot resolved to its nearest symbol; for call tables/vtables/IAT (text). width=4\|8. |
| `memory.compare` | Read | `address1`*: string, `address2`*: string, `length`*: string | Compare two virtual ranges and report mismatch offsets (c); for inline-hook/patch detection (text). |
| `code.disasm` | Read | `address`: string, `symbol`: string, `count`: string, `function`: boolean | Disassemble instructions at an address or function (u/uf) (text). |
| `symbol.search` | Read | `mask`*: string, `limit`: string | Enumerate symbols by wildcard (x module!mask) to resolve names to addresses. |
| `ti.subscribe` | Read | `action`: string | Control the Threat-Intelligence ETW subscription (action=start\|stop\|status); start/stop need --allow-write. |
| `snapshot.diff` | Read | `old`: string, `new`: string, `domain`: string, `risk`: string, `limit`: string, `summary`: boolean | Diff the in-memory baseline against a fresh live capture, or two snapshot files (!diff) (text). |
| `memory.write_virtual` | Write | `address`*: string, `bytes`*: string, `width`: string, `process`: string | Write bytes to a kernel virtual address (e*). |
| `memory.write_physical` | Write | `physical_address`*: string, `bytes`*: string | Write bytes to a physical address (pe*). |
| `memory.fill` | Write | `address`*: string, `length`*: string, `pattern`*: string | Fill a kernel range with a byte pattern. |
| `memory.move` | Write | `source`*: string, `dest`*: string, `length`*: string | Copy a kernel range from source to dest. |
| `type.set_field` | Write | `address`*: string, `type`*: string, `field`*: string, `value`*: string | Set a struct field at an address (setfield). |
| `minifilter.set_irp` | Write | `filter`*: string, `irp`*: string, `action`*: string, `which`: string | Cooperative CREATE pre/post control for KnLiveDbgMiniFilterFixture only. Provider-owned rundown and automatic restore on disconnect/process exit; no registered pointers change. External raw callback writes are unavailable. |
| `callbacks.set` | Write | `action`*: string, `module`*: string, `scope`: string | Cooperative control for KnLiveDbgMiniFilterFixture only, scope=minifilter\|all. Provider-owned rundown and automatic restore; external raw callback writes are unavailable. |
| `process.set_protection` | Write | `pid`: string, `level`*: string | Set a process PS_PROTECTION. pid (optional, defaults to self); level=none\|ppl-antimalware\|ppl-lsa\|ppl-windows\|ppl-wintcb\|pp-windows\|pp-wintcb\|pp-winsystem. |
| `ti.export` | Write | `path`*: string | Export the Threat-Intelligence ETW ring to a JSONL file. |
| `ti.clear` | Write | None | Clear the in-memory Threat-Intelligence ETW ring. |
| `dump.raw` | Write | `address`*: string, `length`*: string, `path`*: string, `zerofill`: boolean | Dump a kernel range to the given file path (path required; no traversal). |
| `dump.pe` | Write | `address`*: string, `path`*: string | Reconstruct an on-disk PE image from memory to the given file path (path required). |

`callbacks.set` and `minifilter.set_irp` support only the cooperative fixture's
CREATE bodies; they do not replace external registrations. `process.set_protection`
accepts an explicit PID and is not restricted to the controller process.
Some tools return structured JSON and others text. Uniform pagination, per-tool
output schemas, SSE progress and per-write elicitation are not implemented.

## Resources

| URI | Content |
| --- | --- |
| `kn://session/info` | Driver ABI, ownership and write state |
| `kn://capabilities` | Enabled tools and schemas |
| `kn://modules/kernel` | Loaded kernel module identity and ranges |
| `kn://drivers/status` | Service and controller status |
| `kn://session/symbols` | Symbol path and engine state |
| `kn://ti/stats` | TI ring and subscription state |
| `kn://snapshot/current` | Current in-memory baseline, when present |
| `kn://audit/tail` | Last 50 write-audit entries, when available |

Resources use `application/json`. Capturing a baseline or querying an empty ring
does not establish complete kernel coverage.

## Prompts

| Name | Optional argument | Purpose |
| --- | --- | --- |
| `callback-audit` | `module` | Inspect callbacks and target ownership |
| `driver-surface-map` | `driver` | Correlate a driver's registered surfaces |
| `address-provenance` | `address` | Inspect mapping, bytes and ownership |
| `minifilter-review` | None | Inspect filter callbacks |
| `hunt-triage` | `pid` | Process memory and execution evidence |
| `etw-infinityhook-check` | None | ETW/syscall-related integrity observations |
| `wfp-surface` | None | WFP registrations and candidate kernel targets |

Prompts are investigation guidance, not evidence that their hypotheses are true.
