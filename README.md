# Kn-Live-Dbg

Kn-Live-Dbg is a Windows kernel live-debugging experiment shaped after the useful part of LiveKD: the kernel driver exposes narrow memory primitives, while the user-mode console owns service lifecycle, symbol loading, type interpretation, and operator UX.

## Demo

https://github.com/user-attachments/assets/f3542a85-c960-46f2-a151-fdd23a8294a6

If the embedded video does not render, open the [README-sized demo](demo/kn-live-dbg-demo-readme.mp4) or the [full-resolution demo](demo/kn-live-dbg-demo.mp4).

### AI Command Demo

<video src="demo/kn-live-dbg-demo-ai.mp4" controls muted playsinline width="100%"></video>

If the AI command demo does not render inline, open [demo/kn-live-dbg-demo-ai.mp4](demo/kn-live-dbg-demo-ai.mp4).

## Scope and Signing Notice

This tool is built for defensive Windows security research, anti-cheat research, driver diagnostics, and controlled lab analysis. It is not designed to bypass Windows Code Integrity and does not include Code Integrity bypass functionality. To load the driver, use Windows test-signing mode with the test-signed build, or sign the driver with an appropriate production certificate such as an EV code-signing certificate for real deployment environments.

## Shape

```text
kn-live-dbg/
  shared/KnLiveDbgIoctl.h       stable user/kernel ABI
  shared/KnLiveDbgProbeIoctl.h  positive-control probe ABI
  driver/Driver.cpp             WDM driver with virtual/physical memory IOCTLs
  probe_driver/ProbeDriver.cpp  WDM positive-control test buffer driver
  minifilter_fixture_driver/    no-op minifilter detach/reattach positive control
  bind_fixture_controller/      temp-only QoS/Bind positive-control controller
  hunt_test_target/             lab-only !hunt positive-control process
  kmon_test_target/             lab-only !kmon user-mode hostility fixture
  user/*.cpp                    elevated TUI, SCM lifecycle, DbgHelp symbols
  tools/build.ps1               Release/Debug x64 build helper
  tools/release.ps1             build and zip release package helper
  tools/validate-timeline-selftest.ps1  driver-free timeline regression check
  tools/validate-console-surface.ps1    driver-free help/completion regression check
  tools/validate-remote-protocol.ps1    driver-free remote session protocol check
  research/evasion-research-ledger.json  source-to-detector claim ledger
```

## Current Capabilities

1. Installs or updates, starts, stops, waits on, and deletes `KnLiveDbg.sys` through SCM.
2. Creates `\\.\KnLiveDbg` with an Administrators/SYSTEM-only device DACL and validates ABI version.
3. Reads kernel virtual memory through `MmCopyMemory`.
4. Translates virtual addresses to physical addresses through an x64 page-table walk.
5. Reads physical memory through `MmCopyMemory`.
6. Writes physical memory with per-handle write mode enabled by default.
7. Writes kernel virtual memory with per-handle write mode enabled by default.
8. Enumerates loaded kernel modules with `NtQuerySystemInformation`.
9. Loads kernel symbols with `DbgHelp`; the EXE directory and its non-cache subdirectories are searched first, followed by `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols`, and the `nt` kernel PDB is downloaded/loaded into that EXE-local cache during startup by default.
10. Provides a WinDbg-compatible command registry for the official base command list.
11. Implements native live-memory support for memory, symbol, module, type, compare, fill, move, search, and explicit disassembly commands.
12. Routes stop-state, parser-heavy, extension, and meta commands through the DbgEng backend.
13. Provides an optional DbgEng backend for raw WinDbg command execution against the local kernel target.
14. Parses kernel PDB types to enumerate object-manager filters, registry callbacks, process/thread/image-load callbacks, and minifilter callbacks with function/module/context annotations.
15. Provides an initial AI assistant provider layer for advisory command planning and result interpretation through Codex CLI, ChatGPT/Codex OAuth, DeepSeek, and OpenRouter. Daily setup is `ai use <preset|model>` / `ai models` / `ai test`; OpenRouter defaults to `anthropic/claude-opus-5`, Tab completes curated frontier ids, and `ai models refresh` fetches the live OpenRouter catalog.
16. Enforces a single-controller device owner and exposes owner/write-mode state through `drvstatus`.
17. Resolves process DTBs from `_EPROCESS.Pcb.DirectoryTableBase` and optional `UserDirectoryTableBase` for process-aware `vtop`, `d*`, and `e*` commands; native `e*` writes default to the System process context (`pid 4`).
18. Detects active LA57 paging and reports whether translation used PML4 or PML5, including the physical address of each page-table entry that was walked.
19. Supports DbgEng local-kernel and remote-kernel attach modes through `kdinit /local` and `kdinit /remote`.
20. Falls back to DIA SDK type parsing when `DbgHelp` cannot provide enough UDT/field metadata.
21. Builds and manages `KnLiveDbgProbe.sys`, a positive-control test driver with known virtual/physical buffer addresses and a test firmware table provider registration.
22. Enumerates Windows Filtering Platform providers, sublayers, callouts, filters, and layers natively through the user-mode Base Filtering Engine (`fwpuclnt.dll`) with `!wfp`, including layer/provider/sublayer name resolution and decoded action/flag mnemonics.
23. Enumerates ALPC ports natively from live kernel memory with `!alpc`, recursively walking the Object Manager namespace from `nt!ObpRootDirectoryObject`, following `_ALPC_PORT.CommunicationInfo` to discover paired server/client ports, counting queue depths from `MainQueue`/`PendingQueue`/`LargeMessageQueue`/`CanceledQueue`/`WaitQueue`, and grouping records by `ConnectionPort` into client/server families.
24. Reports VBS, HVCI, Secure Kernel, and IUM trustlet status with `!vbs`, `!ci`, and `!securekernel` — decoding `nt!g_CiOptions` flag bits, reading `nt!HvlpVsmVtlCallVa` for VBS active state, scanning `PsLoadedModuleList` for `securekernel.exe`/`skci.dll`, querying CPUID leaves `0x40000000`/`0x40000006` for hypervisor identification, and walking `PsActiveProcessHead` with `_KPROCESS.SecureState` (or known trustlet image-name prefixes when the field is unavailable) for the trustlet list.
25. Detects InfinityHook-style ETW logger tampering with `!etw` and walks the registered NMI handler chain with `!nmi` — reading `nt!EtwpDebuggerData`'s 64 `WMI_LOGGER_CONTEXT*` slots for logger name and GetCpuClock annotation, walking `nt!KiNmiCallbackListHead` through the `KNMI_HANDLER_CALLBACK` singly-linked list, and flagging any callback or GetCpuClock target outside the loaded kernel modules.
26. Enumerates registered firmware table providers with `!fwtable` -- passively walking `nt!ExpFirmwareTableProviderListHead`, decoding `SYSTEM_FIRMWARE_TABLE_HANDLER`-style provider nodes, annotating ProviderSignature, handler module/symbol, and DriverObject owner/name/start/size, and flagging custom signatures, duplicate signatures, corrupt links, non-image handlers, unresolved DriverObject module ownership, and handler/DriverObject owner mismatches without invoking firmware handlers.
27. Checks live module and driver-object integrity with `!module integrity` and `!driver integrity` -- reading live PE headers/sections for loaded modules, validating PE/section invariants with reason codes, flagging static/effective W+X evidence or live SizeOfImage drift, walking `\Driver` objects through Object Manager metadata, and annotating `DRIVER_OBJECT.MajorFunction[]` dispatch targets with module/symbol ownership.
28. Scans loaded kernel modules for BYOVD risk with `!byovd` -- maintaining a local catalog from the Microsoft vulnerable driver blocklist plus LOLDrivers hash/YARA feeds, auto-refreshing it when older than 24 hours, hashing loaded module images on disk, optionally running LOLDrivers YARA rules through an operator-supplied `yara64.exe` / `yara.exe`, and reporting exact hash/YARA matches as `HIGH` confidence plus Microsoft file-name/version blocklist hints as `MEDIUM` confidence. A benign no-op fixture driver (`amdryzenmasterdriver.sys`) can be loaded with `!byovd fixture load` to exercise the Microsoft name/version positive-control path without shipping an actual vulnerable driver.
29. Enumerates the kernel big pool with `!pool big` / `!pool find` / `!pool summary` -- snapshotting `nt!PoolBigPageTable` through `NtQuerySystemInformation(SystemBigPoolInformation=0x42)`, filtering by 4-character tag (`/tag`), size band (`/min`/`/max`), containing virtual address (`/addr`), W+X page attributes (`/wx`), or paged/non-paged class, and optionally walking the PML5/PML4/PDPT/PD/PT hierarchy via the driver's `TranslateVirtual` IOCTL with `/annotate` to surface effective R/W/X permissions and `[W+X]` non-paged allocations as BYOVD/payload-staging signals.
30. Captures same-boot session baselines with `!snapshot` and compares them with `!diff` -- keeping the baseline in memory, auto-writing JSON plus Markdown under `.kn-live-dbg`, reporting added/escalated records plus coverage-gated callback removal and `_EPROCESS.Protection` changes, scanning VAD DKOM hidden-PTE evidence for every newly observed live process, and ordering pool findings so pool-PE suspects, pool-PE hits, W+X NonPaged allocations, and large NonPaged allocations surface first. A `kpage` domain records every executable kernel region outside loaded modules (PTE walk, pool-type and tag agnostic), so a before/after `!diff baseline /domain kpage /risk high` surfaces mapper code hidden in pool even without a PE header.
31. Dumps kernel memory to file with `dump-raw <address> <length> <path> [/zerofill]` -- chunked 256 KB reads through the driver IOCTL with optional zero-fill on per-chunk failure -- reconstructs on-disk PE images from running drivers/`ntoskrnl` with `dump-pe <address> <path>`, writes a WinDbg-openable complete dump with `dump-kernel <path>` (8 KB `DUMP_HEADER64` plus streamed physical RAM runs from `MmGetPhysicalMemoryRanges`), and asks Windows for an OS live kernel dump with `dump-live <path>` via `NtSystemDebugControl(SysDbgGetLiveKernelDump)`, or writes a WinDbg kernel complete dump of one process with `dump-live <path> /user <pid|eprocess>`. `dump-analyze <path>` is offline: it parses that `DUMP_HEADER64`, lists physical runs, and walks `PsLoadedModuleList` through 4-level or LA57 5-level paging. `dump-pe` parses the in-memory `IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS` (PE32 and PE32+), copies each section's `SizeOfRawData` bytes from `address + VirtualAddress` to file offset `PointerToRawData`, and zero-fills sections whose reads fail (discarded INIT, paged-out sections) so the dump remains valid for IDA/Ghidra inspection of relocations-applied, IAT-resolved, in-place-patched live images.
32. Hunts PE images stashed in big pool with `!pool pe` -- enumerates big pool entries via `NtQuerySystemInformation(SystemBigPoolInformation)` and runs the same plausibility-gated NT header detector used by `dump-pe` on each entry's first 4 KB, surfacing reflective-loaded modules, unpacker stages, and stomped driver replacements even when the operator has stripped `MZ` / `PE\0\0` / `e_lfanew` to evade signature scanners. Hits are tagged with `WIPED=[MZ,e_lfanew,PE]` markers and can be dumped to disk in one shot via `/dump <directory>` (reusing the dump-pe section walker + signature recovery).
33. Lists filesystem minifilters and can disable or restore one IRP pre/post handler, or every registered slot, with `!minifilter`. The walk uses `fltmgr!FltGlobals` and PDB `_FLT_OPERATION_REGISTRATION` offsets. `disable` writes NULL through the existing write IOCTL after saving the original pointers in this session; `enable` puts them back. `disable <name> all` and `disable-all` walk every slot. Inbox filters warn. No new driver IOCTL.
34. Traces leftover mapper payloads after the original driver image is gone, as separate layers. `!byovd` is loaded BYOVD. `!mapper` is bookkeeping remnants (`MmUnloadedDrivers` / PiDDB / ci hash); `leftover=0` is ledger-clean, not payload-absent. `!kpage` is orphan executable pages; `!kpage /deep` adds a capped PFN-database pass. `!payload` / `!payload scan` is hook-to-body. `!pool pe` is staged pool PE. None of these add driver IOCTLs.
35. Introspects a single virtual address with `!address <va>` -- reports canonicality, kernel vs user half, the live page-table walk (PML5/PML4/PDPTE/PDE/PTE values and addresses), effective R/W/X/U permissions ANDed across every traversed level, large-page detection, the resulting physical address and page offset, and the owning kernel module + nearest symbol. Auto-detects LA57 paging from the driver TranslateVirtual response and adjusts the kernel/user half-space split accordingly.
36. Elevates KnLiveDbg.exe to PPL Antimalware with `set-ppl-antimalware [on|off|status]` -- the driver writes `0x31` (PS_PROTECTION: PPL/Antimalware) into the calling process's `_EPROCESS.Protection` byte. Required prerequisite for subscribing to the Microsoft-Windows-Threat-Intelligence ETW provider, which gates events on the consumer being PPL Antimalware.
37. Subscribes to the Microsoft-Windows-Threat-Intelligence ETW provider with `!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]` -- creates an own ETW session (StartTraceW + EnableTraceEx2 + ProcessTrace), decodes payloads via TDH with a raw-hex fallback, captures every event into a 1M-event in-memory ring AND a JSONL log file (rotated 100MB x 10), and surfaces only watch-matched events to the TUI (throttled to 50/s). Lazy image-name matching catches processes that aren't running yet at subscribe time; first match auto-promotes the PID to the hot path. Subcommands cover live tail (`!ti watch`), ring stats and histograms (`!ti stats`), per-PID/per-task filtering (`!ti by pid` / `!ti by task`), substring grep (`!ti grep`), and forensic export (`!ti save`). KnLiveDbg.exe events are excluded by default to prevent self-feedback.
38. Decodes Windows Notification Facility (WNF) state names with `!wnf` and walks live `_WNF_NAME_INSTANCE` records via two code paths: the legacy `RTL_AVL_TABLE` traversal from `nt!ExpWnfSiloState` (Win10 / early Win11), and a modern LIST_ENTRY heuristic walker that enumerates instance chains hanging off silo-state structures on Win11 builds that have migrated WNF tracking away from `RTL_AVL_TABLE`. The decoder applies the documented `0x41C64E6DA3BC0074` XOR mask to surface Version/Lifetime/DataScope/PermanentData/Sequence/OwnerTag bit fields and optionally dumps the last-published `WNF_STATE_DATA` payload. Three diagnostic subcommands -- `!wnf candidates`, `!wnf lists`, and the runner-up list reporting in `!wnf instances` -- expose the silo discovery and list-shape detection for manual inspection when automatic mode picks the wrong chain.
39. Inspects the SYSCALL-configuration model-specific registers with `!msrcheck` -- reading `IA32_LSTAR`, `IA32_CSTAR`, `IA32_STAR`, `IA32_FMASK`, and `IA32_EFER` on every active processor through a new read-only `IOCTL_KNDBG_READ_MSR` driver primitive (ABI version 8; the driver permits only a fixed architectural MSR whitelist and pins per-CPU affinity so single-core hooks are visible). It flags `LSTAR` that does not equal `nt!KiSystemCall64`, any per-CPU divergence (the kernel programs these MSRs uniformly), and entry pointers outside the loaded kernel image as possible SYSCALL hooks, while decoding `STAR` selectors and `EFER` bits for inspection. This closes the previously blind SYSCALL-entry attack surface and establishes the read-only CPU-state IOCTL pattern reused by future control-register/IDT/SSDT checks.
40. Inspects the x64 control registers with `!cr` -- reading `CR0`, `CR4`, and `CR8` on every active processor through the read-only `IOCTL_KNDBG_READ_CONTROL_REGISTERS` primitive (ABI version 9; same per-CPU affinity-pinned pattern as `!msrcheck`). It flags `CR0.WP=0` (kernel write-protect disabled, a classic code-patching enabler) and any per-CPU divergence of `CR0`/`CR4` as suspicious, decodes the `CR4` mitigation bits (`SMEP`/`SMAP`/`UMIP`/`LA57`/`CET`/`PKE`), and surfaces `SMEP`/`SMAP` being disabled as a mitigation-weakened note (legacy CPUs may legitimately lack them).
41. Detects SSDT / shadow-SSDT syscall hooks with `!ssdt` -- walking the native `nt!KeServiceDescriptorTable` (`KiServiceTable`) and, when win32k modules are loaded, the win32k shadow table `nt!KeServiceDescriptorTableShadow[1]` from live kernel memory. Each service routine is decoded with the x64 encoding (`routine = KiServiceTable + (entry >> 4)`) and validated to reside in the expected kernel image -- ntoskrnl for the native table, a `win32k*` module for the shadow table. Routines outside the expected module, or outside every loaded kernel module, are flagged as syscall-hook evidence; clean tables print a one-line summary so only hooked entries are listed. No new driver IOCTL is required: the scanner reuses the existing memory-read primitive plus the PDB-first layout resolver for the `_KSERVICE_TABLE_DESCRIPTOR` Base/Limit fields.
42. Detects IDT (interrupt descriptor table) hooks with `!idt` -- reading the boot processor IDTR through the read-only `IOCTL_KNDBG_READ_IDT` primitive (ABI version 10; `__sidt` under the same per-CPU affinity-pinned pattern), walking the gate descriptors from live kernel memory, rebuilding each handler from its split offset fields (`OffsetLow | OffsetMiddle << 16 | OffsetHigh << 32`), and flagging any present gate whose handler falls outside every loaded kernel module as interrupt-hook evidence. It also cross-checks every active processor's IDT against the boot processor and flags per-CPU handler divergence as a single-core interrupt-hook signal. Clean tables print a one-line summary. The MSR/CR/IDT primitives read across all processor groups, so machines with more than 64 logical processors are covered.
43. Resolves kernel-mode WFP callout function pointers with `!wfp kernelcallouts` -- the user-mode Base Filtering Engine does not expose the classify/notify/flowDelete pointers, which are the actual hook surface for network filter drivers. The scanner anchors on the public symbol `netio!gWfpGlobal`, scores documented candidate callout-table layouts (e.g. array at `+0x198` with `0x50`-byte slots, or `+0x550` with `0x40`-byte slots; classify at `+0x10`) against live pointers -- the same guarded-fallback discipline used by the firmware-table and WNF scanners, with a bounded offset-scan fallback for build drift -- then walks the callout array, recovers each slot's classify/notify/flowDelete pointers, joins them to the user-mode callout metadata (name/layer/provider) by callout id, and flags any classify target outside every loaded kernel module. No new driver IOCTL is required (it reuses the existing memory-read primitive); netio.sys symbols and an open driver device are required, and the command reports cleanly when the layout cannot be located so offsets can be refined per build.
44. Maintains a bounded evidence timeline with `!timeline` -- the plain command is now the normal operator path: it asks whether to enable TI ETW and kernel live process/image/thread callbacks, starts the requested collection paths, then refreshes recent TI, snapshot baseline, and active live-callback evidence. Recent TI ingest uses a timestamp cursor and explicit advanced `all` mode remains available for deliberate ring rescans. TI events are enriched with task-name actions and triage risk (`info`/`warning`/`critical`) before graphing/dashboard rendering. `!timeline dashboard` opens the self-contained visual dashboard with in-page filters, live/auto-drain status, matched-rule cards, related-event focus, TI task selection, and a JSONL export button, while `!timeline reset` clears the in-memory timeline. Advanced compatibility commands remain under `!timeline help advanced`, including manual live callback controls for explicit status/off/clear/drain cases. The driver live channel stays thin and bounded; enrichment, graphing, reconciliation, dashboard rendering, and JSON live in user mode.
45. Detects EDRChoker-style Policy-based QoS throttling during default/deep `!hunt` scans by enumerating `MSFT_NetQosPolicySettingData` directly in `ROOT\StandardCimv2`, including nonpersistent `ActiveStore` policies. A high-confidence finding requires both a known security-product executable target and a present nonzero throttle of at most 64 KiB/s; near-zero throttles of at most 1 KiB/s are high risk. The JSON summary preserves total/suspicious policy counts and an explicit coverage-incomplete flag. This collector is independent of WFP filter enumeration because Pacer/QoS throttling does not require a WFP Block filter. The safe QoS/Bind E2E fixture creates a uniquely named 64-bit/s `ActiveStore` policy for its temporary `MsSense.exe` path and never targets an installed security product.
46. Enumerates active global Bind Filter mappings on every mounted local fixed/removable/RAM volume during default/deep `!hunt` by dynamically calling the system `bindfltapi!BfGetMappings` interface. Drive-letter and mounted-folder-only volumes are discovered through the volume GUID/mount-path APIs; a partial volume walk leaves global coverage incomplete. Root-relative mapping paths are anchored to the specific enumerated volume, preventing a mapping on another volume from correlating with the Windows volume. Exact mapping records are promoted only when they intersect a known security-product path, `amsi.dll`/event-log artifacts, an authoritative Windows/Program Files-to-user path boundary, its inverse, a Windows system-image redirect, or a same-volume two-way mapping pair. Global Process-Binding is promoted separately only when a running process exposes the mapping source through an exact API/PEB/module path match while both the `_EPROCESS.SectionObject` and main-image VAD independently resolve to the same mapped target. Missing either backing view sets an explicit correlation-coverage-incomplete state instead of producing clean proof. Buffer offsets, lengths, counts, structural regions, returned size, exact success statuses, and growth are fail-closed and size-bounded. `KnLiveDbgBindFixture.exe` is constrained to two fixed mappings under one direct `%TEMP%\KnLiveDbgBindFixture-<GUID>` child and cannot target Windows or installed-product paths; cleanup can remove those exact mappings even if fixture files were lost, and only `S_OK` or an already-missing mapping is accepted as complete. `tools\run-qos-bind-e2e.ps1` verifies redirected content and image hashes, keeps the copied benign backing process alive for one hunt, and independently validates exact mapping, PID, two-backing-view, policy, rate, and counter evidence before exact cleanup. JSON distinguishes global enumeration and Process-Binding correlation completeness from the remaining unsupported silo-scoped mapping query; a clean global result is not presented as Silo-Binding coverage.
47. Detects current-state CloudFiles False File Immutability evidence during default/deep `!hunt`. For each resolved SEC_IMAGE VAD backing, an attribute-only handle dynamically queries bounded `CF_PLACEHOLDER_STANDARD_INFO` metadata without requesting file data. The scanner recognizes the complete `IO_REPARSE_TAG_CLOUD` family when the tag is visible and records a bounded `FSCTL_GET_REPARSE_POINT` cross-view. Some current `cldflt` builds mask the tag from both views; successful `CfGetPlaceholderInfo` is therefore also an authoritative placeholder identity signal, with the fallback and failed FSCTL error preserved as evidence. A PP/PPL mapping or a placeholder correlated with an already-normalized deep executable live-versus-disk mismatch is high risk/high confidence; positive `ModifiedDataSize` on a mapped placeholder is medium risk/high confidence. An in-sync, unmodified, non-PP/PPL placeholder is a negative control. Missing CloudFiles metadata suppresses the derived claim; unresolved process protection cannot establish clean or PP/PPL evidence and is exposed as incomplete correlation, while independent modified-data or deep-mismatch evidence remains eligible. Every metadata-complete observation is retained in the additive `cloudfiles_images` JSON array with exact PID, module/VAD identity, raw state, protection correlation, decision, and reasons, including clean observations. This is current-state provenance detection, not a claim that rehydration history or file-generation history is reconstructed.
48. Captures Filter Manager volume and instance attachment state in every `!snapshot` through the documented `FltLib` enumeration APIs. Each bounded, strictly parsed record preserves filter, instance, altitude, volume, frame, filesystem, supported-feature, and raw attachment flags, including `FLTFL_IASIM_DETACHED_VOLUME`; failed or partial enumeration leaves explicit incomplete coverage instead of a clean result. Same-boot `!diff` promotes a stable attachment's attached-to-detached transition. It also reports a missing attachment only when attachment and callback coverage are complete, the same volume remains enumerated, and the same minifilter remains registered in the independent kernel callback view. A clean attachment for the same filter, volume, and altitude suppresses the removal signal even when the instance name changes; when altitude is unavailable, the instance name is the fallback discriminator. A different-altitude decoy attachment no longer masks removal. Static detached state, cross-boot comparison, filter unload, volume removal, and incomplete coverage remain non-findings. Imported snapshot JSON must keep attachment/volume/detached counters, coverage state, record tags, and evidence mutually consistent before removal logic can use it. The bundled no-op minifilter fixture and `tools\run-minifilter-detach-e2e.ps1` exercise the supported attach/detach/reattach path and independently validate the raw snapshots plus positive and recovery diffs. This closes the documented Filter Manager view of ABYSSWORKER-style detach behavior; it does not claim full arbitrary device-stack topology or causal attribution.
49. Quiet kernel surfaces (Phase 2): `!hal` checks PDB-described HalDispatchTable pointer fields; `!hive` walks PDB-described registry hive GetCellRoutine ownership with list-link validation; `!token` inspects process privilege Present/Enabled masks plus TokenType/SessionId/integrity SID and propagates incomplete coverage into `!hunt`; `!etw providers` emits unclassified heuristic diagnostics while `!etw ti-cross` treats silence alone as inconclusive; `!dpc` / `!timer` require PDB-bounded deferred-execution layouts, and `!workitem` explicitly remains incomplete. Snapshot domains include `hal`, `hive`, `dpc-timer`, and token fingerprints under `process-security`.
50. P0-P2 investigation scanners (no driver ABI change): `!drvobj` / `!devstack` walk DRIVER_OBJECT device stacks; `!module integrity` adds `/disk` `/iat` `/prologue`; `!handles` triages VM/DUP cross-process handles; `!hiddenproc` cross-views ActiveProcessLinks vs SPI vs Toolhelp vs handle owners; `!wdfilter` lists WdFilter RuntimeDriver leftovers; `!inputstack` flags unknown kbd/mou attached drivers; `!vad` annotates ControlArea/FILE_OBJECT section names; `!dma` reports IOMMU firmware and Kernel DMA Protection; `!hv` reports hypervisor presence without `IA32_FEATURE_CONTROL`; `dump-analyze` walks dump DTB with PML4 or PML5; `!byovd` Authenticode is on by default (`/no-sign` skips it).
51. `!kmon` (bare command or `!kmon start`) arms silent TI plus kernel live callbacks and stays on a live tail of unknown kernel drops/maps/hidden processes. A driver filename is not required. Every driver lifecycle event prints with no exception path -- `driver.drop_load`, `driver.official_load` / `driver.official_unload` / `driver.device` (inbox, undecoded, and bare object names included), post-arm `driver.image_only`, `driver.short_lived`, `driver.mapped_residue` (live pool PE, unbacked `DRIVER_OBJECT`, orphan kpage PE/W+X, headerless import-stub pool code during the watch and idle, BYOVD vehicle, plus `!mapper` leftovers), `hook.unbacked` (callback/input/dispatch/SSDT/IDT/MSR/HAL/WFP/DPC/minifilter routines outside `PsLoadedModuleList`; empty module inventory is fail-closed), `process.hidden` (ActiveProcessLinks vs SPI/Toolhelp vs handle owners vs CID), `process.masquerade` / `process.hollow` (PEB ImageBase EXE replace: unmapped/private/unbacked MEM_IMAGE, mapped-path, stamp/arch, builtin W+X, COW and reloc-aware `.text` vs disk for Windows builtins, extra PE, ghosting) / `process.implant`, `inject.remote` into/from Windows builtins or drop-path callers, and DSE-off / CR0.WP=0. Any driver load or unload arms the capped 30s mapper-watch burst. Watched names promote on the kernel process-create callback and descendants of watched pids are auto-watched (`watch_source=child_of`), unclassified TI tasks from watched pids leave a first-seen-per-task `loader.activity` trail, watched pids get an ~8s handle-table diff reporting new device handles as `driver.handle`, and `!kmon iotrace <driver> on|off|status` (ABI 17) opts into a lab-only interposition of one named driver's `IRP_MJ_DEVICE_CONTROL` printing `driver.ioctl` first-seen per pid and IOCTL code. `/name game.exe` adds overlay-style `inject.remote`; `/name *` watches every new process. `/background` (alias `/nowatch`) arms without occupying the prompt. `add`/`remove` require an already-collecting session. Esc/q detaches; `!kmon` again reattaches. Kernel `MmCopyVirtualMemory` is not on ETW-TI; the hook and pool-PE samples are the substitute. Lab fixture: `KnLiveDbgKmonTarget.exe` (`docs/KMON_TEST_TARGET.md`); driver-interaction design in `docs/DRIVER_INTERACTION_TRACKING_DESIGN.md`.
52. Optional LAN remote operator session: PC A runs `remote on` (default `0.0.0.0:51767`, session password 5-128 printable ASCII, process-managed firewall rule `knlivedbg-remote`); PC B runs `KnLiveDbg.exe --connect <ipv4>:51767` as a thin `knkd>` with the same Tab tables as the local TUI. Command output uses the same console colors as A; if B's stdout is a pipe or file, VT sequences are stripped. Engine, driver, symbols, and dumps stay on A. This is not `kdinit /remote`. See `docs/REMOTE_SETUP.md`.

## Design Notes

- `docs/ARCHITECTURE.md` describes the driver/user split and backend routing.
- `docs/WINDBG_COMMAND_COVERAGE.md` tracks native and DbgEng-routed WinDbg command coverage.
- `docs/AI_ASSISTED_WORKFLOWS.md` documents the implemented AI intent router, evidence analysis, command planning, write safety, playbooks, reporting, and operator examples.
- `docs/FEATURE_PLAN.md` tracks completed feature slices and remaining high-value work such as richer driver-object/device-stack inspection (`!drvobj`/`!devstack`), WNF stabilization, and probe fixtures.
- `docs/MCP_SERVER_DESIGN.md` covers the in-process MCP server design and security rationale; `docs/MCP_SETUP.md` is the operator guide for starting the server (`mcp on`, all-interface bind, session password) and connecting Claude Code/Desktop. Docs are English-first; Korean translations are the sibling `*.ko.md` files.
- `docs/REMOTE_SETUP.md` is the operator guide for the LAN `knkd>` session (`remote on` / `KnLiveDbg.exe --connect`). `docs/REMOTE_OPERATOR_SESSION.md` is the design. This is not `kdinit /remote`. `mcp on` and `remote on` cannot run at the same time.
- `docs/TIMELINE_COMMAND_USAGE.md` documents scenario-based `!timeline` usage for TI, snapshot reconciliation, kernel live callback collection, graphing, JSONL export, and reset workflows. The Korean mirror is `docs/TIMELINE_COMMAND_USAGE.ko.md`.
- `docs/KMON_TEST_TARGET.md` documents `KnLiveDbgKmonTarget.exe`, the lab-only `!kmon` user-mode hostility fixture. `docs/HUNT_TEST_TARGET.md` is the separate `!hunt` fixture.

## Build

Requirements:

1. Visual Studio 2022 17.11 or later (Community, Professional, or Enterprise) with MSBuild, MSVC v143 x64 tools, and the DIA SDK. Also add the individual **Windows Driver Kit** component (`Component.Microsoft.Windows.DriverKit`) so MSBuild has the `WindowsKernelModeDriver10.0` toolset. The WDK toolset additionally expects Spectre-mitigated MSVC x64 libraries and ATL Spectre libraries even though this repo disables Spectre mitigation on the driver projects.
2. Matching Windows 11 SDK **and** Windows Driver Kit for build **26100**. Every vcxproj pins `WindowsTargetPlatformVersion` to `10.0.26100.0`. Kernel headers (`Include\10.0.26100.0\km\ntddk.h`) come from the WDK, not from the user-mode SDK alone.
3. Use WDK **10.0.26100.6584** (winget id `Microsoft.WindowsWDK.10.0.26100`) with VS 2022. WDK 10.0.28000 is the VS 2026 kit: it does not register `WindowsKernelModeDriver10.0` on VS 2022, and its km headers land under `10.0.28000.0` rather than the pinned `10.0.26100.0` tree.
4. Normal PowerShell is enough. `tools\build.ps1` discovers MSBuild and the DIA SDK from installed Visual Studio instances through `vswhere`.
5. Vendored Zydis v4.1.1 amalgamated sources under `third_party\zydis\amalgamated` for native x64 disassembly.

Install onto an existing VS 2022 instance from an elevated prompt. Add the WDK Visual Studio component first; on VS 17.11+ that VSIX ships as an individual component, and the WDK bootstrapper's own VSIX checkbox is unreliable:

```powershell
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * `
    -requires Microsoft.Component.MSBuild `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe" modify `
    --installPath $vs `
    --add Component.Microsoft.Windows.DriverKit `
    --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre `
    --add Microsoft.VisualStudio.Component.VC.ATL.Spectre `
    --passive --norestart --force

winget install -e --id Microsoft.WindowsWDK.10.0.26100 --accept-package-agreements --accept-source-agreements
```

Confirm `...\MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0` and `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km\ntddk.h` exist before building.

Build:

```powershell
.\tools\build.ps1 -Configuration Release
```

Driver-free regression checks after a build:

```powershell
.\tools\validate-timeline-selftest.ps1 -Configuration Release
.\tools\validate-mcp-tool-catalog.ps1 -Configuration Release
.\tools\validate-console-surface.ps1 -Configuration Release
.\tools\validate-remote-protocol.ps1 -Configuration Release
.\tools\validate-hunt-clean-host-selftest.ps1
.\tools\analyze-hunt-clean-host-selftest.ps1
.\tools\validate-cloudfiles-hunt-e2e-selftest.ps1
.\tools\validate-minifilter-detach-e2e-selftest.ps1
.\x64\Release\KnLiveDbgBindFixture.exe --self-test
.\tools\validate-qos-bind-e2e-selftest.ps1
.\tools\validate-evasion-external-gate-selftest.ps1
.\tools\validate-evasion-research-ledger.ps1
.\tools\validate-evasion-research-ledger-selftest.ps1
```

The hunt clean-host self-test is driver-free. It proves that the whole-host
negative-control gate accepts a complete zero-finding hunt JSON and rejects
non-empty, incomplete, mistyped, or malformed evidence. The CloudFiles E2E
self-test independently proves the exact process/path attribution and
positive/negative contract without requiring a driver or sync root. The
minifilter E2E validator self-test uses synthetic snapshots and diff logs to
prove the same-boot, complete-coverage, exact-identity, persistent-filter and
recovery controls without loading a driver. The constrained Bind controller
self-test proves that only one direct GUID-named Windows temporary directory is
accepted, and the QoS/Bind validator corpus proves exact policy, path, PID,
dual-backing, counter, incomplete-coverage, and explicit Silo-unsupported
contracts without creating a policy or mapping.

Refresh the pinned Debugging Tools runtime from the newest complete local x64 set:

```powershell
.\tools\sync-debugging-tools-runtime.ps1
```

The driver projects use WDK `TestSign` for Debug and Release x64 builds. The build helper verifies that `KnLiveDbg.sys`, `KnLiveDbgProbe.sys`, `amdryzenmasterdriver.sys`, and `KnLiveDbgMiniFilterFixture.sys` have Authenticode signers and prints signature status/thumbprints after MSBuild completes.
Normal scripted builds reuse the highest current PE version found in `.build\version-state.json`, the existing output file, or an exact `vX.Y.Z` Git tag reachable from `HEAD`, and do not increment it. This keeps a clean checkout from restarting at `0.0.1` after releases have already been tagged. Use `.\tools\build.ps1 -Configuration Release -BumpVersion` only when a new build version should be minted; with no previous state, PE, or reachable version tag, the baseline is `0.0.0`, so the first bumped build stamps `0.0.1` into `KnLiveDbg.exe`, `KnLiveDbg.sys`, `KnLiveDbgProbe.sys`, `KnLiveDbgMiniFilterFixture.sys`, and `KnLiveDbgBindFixture.exe`. The BYOVD metadata fixture keeps its intentional fixed `1.0.0.0` version. The generated resource header is written under `.build\generated`, while `shared\KnLiveDbgVersion.h` remains a `0.0.0` fallback for direct Visual Studio builds that do not run the helper script.
The build helper also stages the pinned `vendor\debugging-tools\x64` runtime beside the EXE (`dbghelp.dll`, `dbgeng.dll`, `dbgcore.dll`, `DbgModel.dll`, `msdia140.dll`, `symsrv.dll`, `srcsrv.dll`, and `symsrv.yes`) so DbgHelp and DbgEng can use the Microsoft symbol server instead of falling back to the limited System32 runtime. If the vendor pair is missing, the script falls back to the locally installed Windows Kits Debugging Tools copy. DIA include/lib paths are passed to MSBuild from the discovered Visual Studio installation instead of relying on a fixed VS edition path. If `symsrv.dll` is staged but `symsrv.yes` is missing, the sync script, build script, and EXE startup path create `symsrv.yes` before symbol loading. Startup creates `<exe-dir>\symbols` and uses it as the downstream symbol store, so downloaded PDBs stay with the runnable EXE bundle rather than going to `C:\Symbols`. When `msdia140.dll` is staged, startup registers it automatically with `DllRegisterServer` before symbol initialization. The symbol engine also has a no-reg fallback that loads the staged `msdia*.dll` directly and creates `IDiaDataSource` through `DllGetClassObject`, so type fallback can still work when COM registration is unavailable.

Create a release zip:

```powershell
.\tools\release.ps1 -Configuration Release
```

The build helper copies `tools\update-byovd-intel.ps1` into `x64\<Configuration>\tools\` so direct build outputs can refresh the BYOVD catalog. The release helper runs a version-bumped build unless `-SkipBuild` or `-NoVersionBump` is supplied, then creates `release\KnLiveDbg-<version>-Release-x64.zip` containing the built EXE/SYS files, the BYOVD and minifilter positive-control fixture drivers, the constrained Bind fixture controller, staged Debugging Tools runtime, PDB/CER/CAT files when present, `README.md`, the vendored runtime manifest when present, the BYOVD updater, the clean-hunt runner/validator/analyzer, the CloudFiles, QoS/Bind, and minifilter fixture runners and validators, the aggregate elevated external gate and validator, and `kn-live-dbg-version.json`. YARA binaries are intentionally not packaged.

Expected outputs:

```text
x64\Release\KnLiveDbg.exe
x64\Release\KnLiveDbg.sys
x64\Release\KnLiveDbgProbe.sys
x64\Release\amdryzenmasterdriver.sys
x64\Release\KnLiveDbgMiniFilterFixture.sys
x64\Release\KnLiveDbgBindFixture.exe
x64\Release\dbghelp.dll
x64\Release\DbgModel.dll
x64\Release\symsrv.dll
```

## Run

Run from an elevated console:

```powershell
cd .\x64\Release
.\KnLiveDbg.exe
```

For a repeatable whole-host negative control from the repository root, use:

```powershell
.\tools\run-hunt-clean-host.ps1 -Mode Default -Count 3 -RequireClean
```

The runner requests elevation when needed, feeds `write off`, captures each
hunt JSON plus transcript under `.build\hunt-clean-host`, exits through the
normal driver lifecycle, and fails if the exact `KnLiveDbg` service remains.
`tools\validate-hunt-clean-host.ps1` can validate a saved JSON separately.
`tools\analyze-hunt-clean-host.ps1` accepts multiple saved JSON paths and groups
findings by a semantic fingerprint that ignores transient PID/address/path
differences, labeling fingerprints as deterministic or intermittent across
runs. It can emit both JSON and Markdown ledgers through `-OutputJson` and
`-OutputMarkdown`.
Deep mode expects usable Threat Intelligence events as part of complete
coverage; use `-Mode Deep -EnableThreatIntel -RequireClean` when that temporary
self-PPL/TI setup is acceptable. The runner enables writes only for
`set-ppl-antimalware`, then issues `write off` before `!hunt`.

`KnLiveDbg.exe --cloak` copies the EXE, `KnLiveDbg.sys`, and present debugger runtime DLLs into a per-session `%TEMP%\<name>\` directory under a generated service-like leaf name, then relaunches the copy as `--cloak-resume`. The child installs a demand-start kernel service with that name, writes `DeviceName` / `SymbolicLink` under the service `Parameters` key, and opens `\\.\<name>` instead of `\\.\KnLiveDbg`. The driver reads those values from `RegistryPath` and falls back to the compiled `KnLiveDbg` names when they are absent. `--cloak-cleanup <session-file>` stops a leftover service and deletes copies after a crash. This only hides the obvious strings (process, SCM, `\Device`, ImagePath). IOCTL numbers, the device GUID, the Authenticode signer, and `GET_VERSION` remain stable fingerprints.

The EXE expects `KnLiveDbg.sys` beside it. Keep the staged Debugging Tools DLLs beside the EXE as well when copying the tool to another directory; otherwise Windows may load `C:\Windows\System32\dbghelp.dll` without `symsrv.dll`, and startup can report `symType=0 (SymNone)` while trying to download the kernel PDB. If `symsrv.dll` is present but `symsrv.yes` is missing, startup creates `symsrv.yes` before calling DbgHelp so first-run symbol-server consent does not block noninteractive PDB downloads. Startup creates `<exe-dir>\symbols`, excludes that cache tree from plain local-directory scanning, and then uses `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols` as the default Microsoft symbol path. If `msdia140.dll` is present, startup registers DIA COM automatically before DbgHelp/DIA initialization; if registration is not available, DIA type fallback can still instantiate the staged DLL directly without registry state. It resolves the absolute driver path, updates an existing service config when present, creates the service when missing, starts it, and waits for `SERVICE_RUNNING`. Startup, single-instance acquisition, install/update, driver load, device open, ABI verification, automatic EXE-directory symbol path discovery, EXE-local symbol cache setup, symbol initialization, default `nt` kernel PDB download/load, probe load, and unload paths are printed as colored staged `[ .. ]`, `[ OK ]`, `[WARN]`, and `[FAIL]` rows. Only one `KnLiveDbg.exe` instance can run at a time; a second elevated process exits before touching SCM or the driver. On successful startup the console prints a colored welcome banner plus a dashboard with driver, write gate, backend, symbols, AI, probe, and quick-action hints before the `knkd>` prompt. `home` or `dashboard` redraws that screen. `q`, `quit`, `exit`, EOF, Ctrl+C, and `unload` close the device handle, stop the main driver, delete the service, and wait for deletion before exit. If the session loaded `KnLiveDbgProbe.sys` with `probe load`, that probe service is also stopped and deleted during process cleanup. Use `drvstatus` to inspect SCM state plus the active single-controller owner/write-mode state. Use `probe load` when you want the optional positive-control driver loaded from the same output directory.

Interactive command dispatch has a delayed progress watchdog. Silent commands that run longer than about one second print a colored `still running` status line with elapsed time, then a neutral `finished` line when control returns. Once a command starts producing stdout/stderr, the watchdog suppresses further progress rows so status text does not interleave with command output. Console color changes and direct progress writes are serialized so a progress row cannot leave the prompt/output color stuck.

The `knkd>` prompt supports Tab completion for registered commands and context-aware subcommands, plus Up/Down history recall for recent commands. The `--connect` client uses the same `CompletionHints` tables locally (`ApplyTabCompletion`), including `remote on --loopback` / `--bind` / `--peer`. When more than one match remains, the prompt prints an annotated list instead of a bare name grid: the parent command's description and full usage line, then each remaining token with its own syntax and summary. Root listings with many matches stay one line per command (`name` + summary). Examples include `!callbacks <Tab>` for callback scopes plus `disable`/`enable`/`disable-all`/`enable-all`, `!callbacks disable <Tab>` for per-type scopes, `!callbacks object /module<Tab>` for the module option, `!pool <Tab>` for `big`/`find`/`tags`/`pe`, `!pool pe <Tab>` for the staged-PE hunt options, `!diff /domain <Tab>` for the snapshot domains (kpage and pool first), `!kmon iotrace <Tab>` for the `on`/`off`/`status` interposition verbs, `!byovd <Tab>` for scan/update/fixture, `!dml_proc <Tab>` for help, `!timeline <Tab>` for the simple timeline surface, `!timeline help <Tab>` for advanced help discovery, `!minifilter <Tab>` for `list`/`show`/`irp`/`disable`/`enable`/`disable-all`/`enable-all`, `!minifilter disable <Tab>` for `all` and common `IRP_MJ_*` names, `ai <Tab>` for primary AI actions including `use`/`models`/`save`/`test`, `ai use <Tab>` for presets and frontier OpenRouter model IDs, `ai models <Tab>` for `refresh` plus curated IDs, `ai explain !callbacks <Tab>` for callback scopes, `ai config <Tab>` for provider setup, `ai config model <Tab>` for the same model catalog, `backend <Tab>`, `probe <Tab>`, `procctx <Tab>`, `write <Tab>`, `u <Tab>` for `/process`, and option completion such as `dt -<Tab>`, `vtop /<Tab>`, and `db /<Tab>`. Callback completion and parsing use only canonical scope names (`object`, `registry`, `process`, `thread`, `imageload`, `minifilter`) plus `all`, `disable`, `enable`, `disable-all`, `enable-all`, `/module`, and `help`; short aliases are intentionally not accepted. Help is available as both `help <command>` and `<command> help`; nested AI topics also support `ai <subcommand> help` or `ai help <subcommand>`. When a prefix is ambiguous, the prompt prints matching candidates and redraws the current input line without dispatching anything.

Native `<address|symbol>` parameters accept simple arithmetic before dispatching to memory, type, disassembly, translation, and AI-preview helpers. Examples include `dt nt!_PS_PROTECTION 0xffffb40c8c1540c0+5fa`, `dq nt!PsLoadedModuleList+10`, and `u nt!KiSystemCall64-20`.

Interactive output highlights high-signal categories and identifiers with console colors. Callback record tags such as `[ob]`, object type names, modules, symbols, translated physical addresses, module/symbol names, type names, field names, and dump line addresses are colored for scanning. Local log files, MCP capture, and AI transcripts stay plain text. A remote operator session embeds VT SGR in the captured stream so PC B can show the same colors; a pipe or file on B strips those sequences.

## TUI Commands

```text
help
help all
help <command>
<command> help
ai help <subcommand>
help !callbacks
!callbacks <scope> help
ai <subcommand> help
home
dashboard
cls
backend [auto|native|dbgeng]
kdinit [/local [connect-options]|/remote <connect-options>]
kd <windbg-command>
kddetach
version
drvstatus
mcp [on [port] [--allow-write] [--loopback] [--bind <addr>]|off|status|client-setup|endpoint]
remote [on [port] [--loopback] [--bind <ipv4>] [--peer <ipv4>]|off|status|disconnect]
log [enable|disable|status]
probe [status|load [sys-path]|info|reset|unload]
.sympath [path]
.sympath+ <path>
.reload
lm [filter]
x <module!mask>
ln <symbol|address>
addr <symbol|address>
query <address|symbol> [length]
vtop <address|symbol> [length]
vtop /cr3 <directory-table-base> <address|symbol> [length]
vtop /process <process-id> <address|symbol> [length]
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
d* /process <process-id> <address|symbol> [count]
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
phys, pdb, pdw, pdd, pdq
!db, !dw, !dd, !dq
procctx [status|clear|<process-id>]
u <address|symbol> [instruction-count]
uf <address|symbol> [max-instructions]
dt [-rN] [-v] [-b] <type|type-pattern> [address|symbol] [field-filter...]
dtx [-rN] [-v] [-b] <type|type-pattern> [address|symbol] [field-filter...]
!callbacks [all|object|registry|process|thread|imageload|minifilter] [module]
!callbacks [scope] /module <module>
!callbacks disable <scope> <module>
!callbacks enable <scope> <module>
!callbacks disable-all <module>
!callbacks enable-all <module>
!dml_proc [pid|name]
!hunt [/quick] [/deep] [/summary] [/details] [/limit <n>] [/json <path>]
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!vad scan <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad modules <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad mappedpe <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]
!wfp [providers|sublayers|callouts|filters|layers]
!wfp kernelcallouts
!wfp callouts /module <name|GUID>
!wfp filters /layer <name|GUID> /provider <name|GUID>
!alpc [ports|port|connections|queues] [/name <pattern>] [/pid <pid>]
!alpc port <address>
!alpc queues <address>
!vbs
!ci [options|policy]
!securekernel
!etw [loggers|logger <index|name>|integrity|providers|ti-cross]
!nmi [callbacks]
!msrcheck
!cr
!ssdt
!idt
!hal [dispatch|private]
!hive [list|cells]
!token <pid|image|eprocess> | !token /all [/limit <n>] [/system]
!dpc [/verbose] [/limit <n>]
!timer [/verbose] [/limit <n>]
!workitem [/verbose] [/limit <n>]
!fwtable [providers|provider <signature>]
!fwtable providers /module <name>
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections] [/wx] [/mismatch] [/disk] [/iat] [/prologue] [/limit <n>] [/json <path>]
!driver [list|object|integrity] [driver|all] [/dispatch] [/devices] [/limit <n>] [/json <path>]
!drvobj <name|address> [/dispatch] [/devices] [/json <path>]
!devstack <device-object-address> [/json <path>]
!handles [pid] [/target <pid>] [/process|/all] [/suspicious] [/limit <n>] [/json <path>]
!hiddenproc [/json <path>]
!wdfilter [/json <path>]
!inputstack [/json <path>]
!dma [/json <path>]
!hv [/json <path>]
!byovd [scan|update|status] [/no-update] [/force-update] [/exact] [/sign|/no-sign] [/yara] [/yara-path <exe>] [/yara-timeout <seconds>] [/verbose] [/summary] [/limit <n>] [/json <path>]
!byovd fixture [status|load [sys-path]|unload|path]
!pool [big|find|tags|summary|pe] [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/addr <va>] [/limit <n>] [/nonpaged|/paged|/any] [/annotate] [/wx] [/tags]
!pool pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>] [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]
!snapshot baseline [/all] [/name <label>]
!snapshot save <path> [/all] [/name <label>]
!snapshot show [baseline|<path>] [/domains] [/warnings]
!diff baseline [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
dump-raw <address> <length> <path> [/zerofill]
dump-pe <address> <path>
dump-kernel <path> [/max <bytes>] [/strict]
dump-analyze <path> [/json <path>]
dump-live <path> [/user [pid|eprocess]] [/compress] [/hv]
!payload <address|symbol> [/disasm <n>] [/json <path>]
!payload scan [/limit <n>] [/disasm <n>] [/json <path>]
!mapper [all|unloaded|piddb|cihash] [/limit <n>] [/json <path>]
!unloaded | !piddb | !cihash
!kpage [/deep] [/wx] [/pe] [/session|/nosession] [/limit <n>] [/json <path>]
!minifilter [list|show <name|addr>|irp <name|addr> <mj>|disable <name|addr> <mj|all>|enable <name|addr> <mj|all>|disable-all <name|addr>|enable-all <name|addr>] [/pre|/post|/both] [/json <path>]
!address <va>
set-ppl-antimalware [on|off|status]
!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]
!ti stop | status | watch | recent [N] | stats | by pid <PID> | by task <name> | grep <pattern> | save <path> | clear | add /pid|/name <v> | remove /pid|/name <v>
!kmon [start] [/name <image>] [/pid <PID>] [/driver <sys>] [/verbose] [/background|/nowatch] [/log <dir>]
!kmon stop | status | watch | recent [N] | save <path> | clear | add /pid|/name|/driver <v> | remove /pid|/name|/driver <v>
!kmon iotrace <driver-name> on|off|status   # lab-only IOCTL interposition (ABI 17)
!wnf [decode <hash>|instances|instance <hash|entry-address>|data <hash|entry-address>|candidates|lists]
ai <goal> [/verbose]
ai chat <goal> [/verbose]
ai status
ai use <preset|model> [model]
ai models [query|refresh]
ai test [prompt]
ai save
ai config [status|providers|provider|policy|model|base-url|effort|auth|test]
ai go
ai no
ai plan <prompt>
ai explain <read-only-command...>
ai show [plan|pending|evidence]
ai run [index|all]
ai write [index] [confirm]
ai report <path>
c <address1> <address2> <length>
s [-b|-w|-d|-q] <address> <length> <value...>
f <address> <length> <byte-pattern...>
m <source> <destination> <length>
write on|off
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
e* <address|symbol> [value...]          # defaults to System(pid 4) context
e* /process <process-id> <address|symbol> [value...]
peb, pew, ped, peq
!eb, !ew, !ed, !eq
pe* <physical-address> [value...]
setfield <type> <address|symbol> <field> <value>
unload
q, qq, qd, quit, exit
```

Help syntax notes:

- `help` shows native/TUI commands; `help all` also lists DbgEng-routed WinDbg commands.
- `help <command>` and `<command> help` print detailed command-family syntax.
- Count arguments are element counts for typed dumps, bytes for range lengths, and instruction counts for `u`/`uf`.
- `nt!` is treated as the loaded kernel image for symbols and PDB type names.
- `d*`, `e*`, and `vtop` support `/process <process-id>` for one command; `procctx <pid>` pins a default context.
- Virtual `e*` writes default to System(pid 4) context for kernel addresses and temporarily restore read-only leaf PTE write bits after patching. Each write is verified by reading the bytes back before the PTE is restored, and writes through a read-only large-page (2 MB/1 GB) mapping are refused rather than flipping a shared parent entry's write bit.
- API-key AI providers load `.env` only from the EXE directory. Prefer `ai use cloud` / `ai models` / `ai test`; `ai run` remains read-only and `ai write confirm` (or `ai write <index> confirm`) is required for write-like plans.

Example:

```text
knkd> reload
knkd> lm nt
knkd> x nt!*Process*
knkd> ln nt!PsLoadedModuleList
knkd> u nt!KiSystemCall64 8
knkd> uf nt!KiSystemCall64
knkd> dq nt!PsLoadedModuleList 4
knkd> vtop nt!PsLoadedModuleList
knkd> procctx 1234
knkd> db 0000012345678000 80
knkd> db /process 1234 0000012345678000 80
knkd> pdb <physical-address> 80
knkd> !db <physical-address> 80
knkd> !eb <physical-address>
knkd> !eq <physical-address> <value>
knkd> dt nt!_EPROCESS
knkd> dt -r1 nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks
knkd> !callbacks all
knkd> !callbacks object
knkd> !callbacks imageload
knkd> !callbacks minifilter
knkd> !callbacks all WdFilter.sys
knkd> !callbacks /module WdFilter.sys
knkd> write on
knkd> !callbacks disable object WdFilter
knkd> !callbacks disable-all WdFilter
knkd> !callbacks enable-all WdFilter
knkd> !dml_proc
knkd> !dml_proc 4
knkd> !dml_proc lsass
knkd> !wfp providers
knkd> !wfp callouts /module tcpip
knkd> !wfp kernelcallouts
knkd> !wfp filters /layer ALE_AUTH_CONNECT_V4
knkd> !wfp layers
knkd> !alpc ports
knkd> !alpc connections
knkd> !alpc ports /name OLE
knkd> !alpc queues ffff8a8400000000
knkd> !vbs
knkd> !ci options
knkd> !ci policy
knkd> !securekernel
knkd> !etw loggers
knkd> !etw logger "Circular Kernel Context Logger"
knkd> !etw integrity
knkd> !nmi callbacks
knkd> !msrcheck
knkd> !cr
knkd> !ssdt
knkd> !idt
knkd> !fwtable providers
knkd> !fwtable providers /module WdFilter
knkd> !fwtable provider ACPI
knkd> !module integrity ntoskrnl
knkd> !module integrity all /verbose /limit 20
knkd> !module integrity all /wx
knkd> !module integrity ntoskrnl /headers /sections
knkd> !driver integrity WdFilter
knkd> !pool big /annotate
knkd> !pool find /tag Wmem /annotate
knkd> !pool find /wx /limit 20
knkd> !pool find /min 0x10000 /annotate
knkd> !pool summary
knkd> !snapshot baseline /name clean-boot
knkd> !diff baseline
knkd> !diff baseline /domain pool /limit 20
knkd> dump-raw nt!KiSystemServiceUser 0x200 .\kiSystemServiceUser.bin
knkd> dump-pe nt .\ntoskrnl-live.exe
knkd> dump-pe Wdf01000 .\wdf01000-live.sys
knkd> !pool pe
knkd> !pool pe /suspicious /dump .\poolpe-hits
knkd> !payload scan
knkd> !payload fffffc0000123456
knkd> !mapper
knkd> !mapper unloaded
knkd> !kpage
knkd> !kpage /wx /pe /limit 20
knkd> !minifilter
knkd> !minifilter show UnionFS
knkd> !minifilter irp UnionFS IRP_MJ_CREATE
knkd> write on
knkd> !minifilter disable UnionFS CREATE
knkd> !minifilter disable UnionFS all
knkd> !minifilter disable-all UnionFS
knkd> !minifilter enable-all UnionFS
knkd> !minifilter enable UnionFS CREATE
knkd> !address nt!ExpWnfSiloState
knkd> !address 0xffffe78fcd778000
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name foo.exe /name bar.exe
knkd> !ti watch
knkd> !ti stats
knkd> !ti save .\ti-snapshot.jsonl
knkd> !wnf decode 0x41c64e6da3bc0075
knkd> !wnf instances
knkd> !wnf instance 0xfffff80300000000
knkd> !wnf data 0xfffff80300000000
knkd> ai use cloud
knkd> ai test
knkd> ai a.exe eprocess
knkd> ai pid 1234 dtb
knkd> ai !callbacks all WdFilter.sys
knkd> ai check VBS status
knkd> ai !ci options
knkd> ai show
knkd> ai run 1
knkd> ai report .\kn-ai-report.md
knkd> probe load
knkd> probe info
```

The registry also knows the standard execution, breakpoint, stack, register, source, exception, I/O port, and script commands. Native live-memory commands stay on the custom driver backend, while stop-state or parser-heavy commands are routed to DbgEng in `auto` or `dbgeng` mode.

Memory display commands use sparse reads. If part of a requested virtual or physical range cannot be read, the printable dump stays aligned and unknown bytes are shown as `??`, with wider unit displays using `0x????...` for unreadable units.

`u` and `uf` are explicit disassembly commands. `u` resolves an address or symbol, reads code bytes through the loaded driver, disassembles them with the vendored Zydis x64 decoder, and remembers the next offset for a following bare `u`; if the driver device is not open, it falls back to the DbgEng disassembly path. `uf` uses the same driver-backed Zydis path and linearly disassembles from the start address until a function terminal instruction such as `ret`, `iret`, `sysret`, `sysexit`, `hlt`, `ud2`, or `int3`, with an optional instruction cap.

## AI Assistant Providers

The `ai` command is an operator intent layer plus an advisory provider bridge. Prefer `ai <goal>` for day-to-day use: the TUI routes local process queries and playbooks first, runs exact read-only evidence commands with an explanation, and otherwise asks the model only to pick tools from the shared catalog. Use `ai chat <goal>` to skip playbooks and process shortcuts and send the request to the catalog tool planner. Exact read-only command lines after `ai chat` still run as evidence. `dump-kernel` / `dump-live` are not available through AI. Goals that already name a `.sys`/`.exe` file skip generic playbooks so the planner can keep the module filter. Cheap tools preview, run, and are explained. Expensive tools (`hunt.run`, `payload.scan`, `snapshot.capture`, `kpage.list` with `deep`) wait for `ai go`. Default `ai <goal>` no longer auto-builds a stored command plan; `ai plan` remains the explicit override. Every AI subcommand supports `ai help <sub>` / `ai <sub> help` and Tab completion, including nested `ai explain !vad` completion and help. It does not execute generated debugger commands automatically, and it does not hide write operations.

```text
ai <goal> [/verbose]
ai chat <goal> [/verbose]
ai status
ai use <preset|model> [model]
ai models [query|refresh]
ai test [prompt]
ai save
ai config [status]
ai config providers
ai config provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai config policy <allow-remote|local-only|status>
ai config model <model>
ai config base-url <url>
ai config effort <minimal|low|medium|high|xhigh>
ai config auth
ai config test [prompt]
ai go
ai no
ai plan <prompt>
ai explain <read-only-command...>
ai show [plan|pending|evidence]
ai run [index|all]
ai write [index] [confirm]
ai report <path>
```

Examples:

```text
ai use cloud
ai use grok
ai models
ai models refresh
ai test
ai a.exe pid
ai a.exe eprocess
ai a.exe process eprocess info
ai pid 1234 dtb
ai WdFilter.sys object callbacks
ai chat object callbacks
ai chat any inline ETW hook?
ai !callbacks all WdFilter.sys
ai dt nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks
ai uf nt!PspCreateProcessNotifyRoutine 128
ai check VBS status
ai 숨은 프로세스 찾아줘
ai 콜백 전수조사
ai go
ai show evidence
ai !ci options
```

See `docs/AI_ASSISTED_WORKFLOWS.md` for the full operator command example catalog, including process, callback, VBS/HVCI/CI, module integrity, driver integrity, WFP/ALPC, VAD/thread, ETW/NMI/pool/WNF/TI, auto-plan, advisory, and explicit override examples.

Provider configuration is loaded from `.env` beside `KnLiveDbg.exe` only. Repo-root and cwd `.env` files are ignored. Real process environment variables override `.env` values. Copy `.env.example` to the EXE directory as `.env` and fill in the API key. Daily setup:

1. `ai use cloud` -- OpenRouter + `anthropic/claude-opus-5` (frontier default as of 2026-08-24).
2. `ai use cheap` -- OpenRouter + `openai/gpt-oss-120b`.
3. `ai use grok` / `opus` / `gpt` -- aliases for current OpenRouter frontier ids (`x-ai/grok-4.6`, `anthropic/claude-opus-5`, `openai/gpt-5.6-sol`).
4. `ai use private` -- local `codex exec`; this process does not make HTTP model calls.
5. `ai use chatgpt` -- ChatGPT/Codex OAuth. This is not the same as the OpenRouter alias `gpt-5.5`.
6. `ai models` lists presets and the curated catalog. `ai models <query>` searches ids/names. `ai models refresh` fetches the live OpenRouter catalog into a process cache and adds top hits to Tab.
7. `ai test` smoke-checks the selected provider/model. `ai save` writes provider/model/policy without changing them.
8. `ai use` / `ai save` / `ai config provider|model|policy` merge those three keys into the EXE-dir `.env` through an atomic `.env.tmp` replace. API keys, `BASE_URL`, effort, and timeout are left untouched. `off` is stored as `KNLIVEDBG_AI_PROVIDER=off` with an empty model so a previous model cannot return.

`ai use` accepts one or two tokens. `ai use cloud x-ai/grok-4.6` keeps OpenRouter and overrides the model. Mixing providers (`ai use cloud deepseek-chat`, `ai use deepseek grok`) is rejected. Re-selecting the same provider does not reset a custom base URL. Tab on `ai use` / `ai config model` completes presets, aliases, and curated IDs; after `ai models refresh` it also completes live OpenRouter ids. Resolve order is preset, alias, exact id, unique tail (`gpt-5.6-sol` does not pick `...-sol-pro`), then unique substring.

The full preset table, alias table, curated id list, `.env` rules, and `local-only` behavior are in `docs/AI_ASSISTED_WORKFLOWS.md` under **Provider Presets and Model Catalog**.

```text
KNLIVEDBG_AI_PROVIDER=openrouter
KNLIVEDBG_AI_REMOTE_POLICY=allow-remote
KNLIVEDBG_AI_MODEL=anthropic/claude-opus-5
KNLIVEDBG_OPENROUTER_API_KEY=sk-or-...
```

Or:

```text
KNLIVEDBG_AI_PROVIDER=deepseek
KNLIVEDBG_AI_MODEL=deepseek-chat
KNLIVEDBG_DEEPSEEK_API_KEY=sk-...
```

Supported keys:

1. `KNLIVEDBG_AI_PROVIDER` selects `openai-codex-cli`, `openai-codex-subscription`, `deepseek`, `openrouter`, or `off`.
2. `KNLIVEDBG_AI_REMOTE_POLICY` selects `allow-remote` or `local-only`; `local-only` blocks HTTP complete and `ai models refresh` without clearing the selected provider. Use `ai use private` for local Codex CLI.
3. `KNLIVEDBG_AI_MODEL` overrides the provider default model. OpenRouter's default is `anthropic/claude-opus-5` when this key is unset.
4. `KNLIVEDBG_AI_BASE_URL` overrides the provider base URL. It is load-only unless edited by hand; `ai use` does not rewrite it when the provider stays the same.
5. `KNLIVEDBG_DEEPSEEK_API_KEY` or `DEEPSEEK_API_KEY` supplies the DeepSeek API key.
6. `KNLIVEDBG_OPENROUTER_API_KEY` or `OPENROUTER_API_KEY` supplies the OpenRouter API key.
7. `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, `KNLIVEDBG_CODEX_AUTH_FILE`, or `KERNFORGE_CODEX_AUTH_FILE` supplies ChatGPT/Codex OAuth credentials.
8. If no Codex auth file is configured, Kn Live Dbg checks `%USERPROFILE%\.kernforge\codex_auth.json` and `%USERPROFILE%\.codex\auth.json`.
9. `KNLIVEDBG_CODEX_CLI_PATH` overrides the `codex` executable used by `openai-codex-cli`.
10. `KNLIVEDBG_AI_REASONING_EFFORT` and `KNLIVEDBG_AI_TIMEOUT_SECONDS` are load-only optional overrides.

Run `codex login` outside Kn Live Dbg when ChatGPT/Codex OAuth credentials are missing or expired. `ai status` prints ready/blocked health and the next setup step. `ai test` / `ai config test` send a tiny marker request to the selected provider/model and print transport status, HTTP status when available, elapsed time, and whether the expected marker came back. Legacy direct forms such as `ai policy local-only`, `ai ask`, `ai preview`, `ai analyze !callbacks`, `ai annotate`, `ai diagnose`, `ai playbook`, `ai transcript`, and `ai audit` are still accepted for compatibility, but the main help surface groups daily setup under `ai use` / `ai models` and evidence analysis under `ai explain`.

For `ai <goal>`, local playbooks and process-field queries run first. `ai chat <goal>` skips those shortcuts and asks the selected provider to pick catalog tools. Exact read-only command lines after `ai chat` still run as evidence. `dump-kernel` / `dump-live` are not available through AI. When the model is used, it sees the operator prompt plus the shared capability catalog, not live memory contents. The catalog includes `process.find`, `process.describe`, `type.describe`, `callbacks.list`, `wfp.list`, `alpc.list`, `vad.list`, `threads.list`, `etw.integrity`, `nmi.list`, `minifilter.list`, `payload.inspect`, `payload.scan`, `mapper.list`, `kpage.list`, `fwtable.list`, `pool.find`, `address.inspect`, `wnf.decode`, `wnf.list`, `ti.query`, `module.integrity`, `driver.integrity`, `driver.object`, `handles.list`, `hiddenproc.list`, `wdfilter.list`, `inputstack.list`, `dma.posture`, `hv.posture`, and `dump.analyze`, so prompts such as `ai a.exe process eprocess info` can become a structured tool plan that finds the process through `_EPROCESS.ActiveProcessLinks` and prints PID, EPROCESS, DTB, PEB, or a `dt nt!_EPROCESS` view locally. Callback/WFP/ALPC prompts route through their native scanners with validated scope/filter args. Firmware table provider prompts route through the passive `!fwtable` scanner and never invoke firmware handlers. Requests that ask to list, show, recommend, or suggest commands route to the command planner first, so command-advice prompts do not run native scanners immediately. Process memory prompts route through `!vad` or `!threads`, including VAD DKOM prompts that set `hiddenpte=true` and run `!vad <target> /hiddenpte`. Integrity prompts such as `ai any inline ETW hook?`, `ai list NMI callbacks`, `ai list firmware table providers`, `ai show W+X pool allocations`, `ai why is nt!Foo suspicious?`, `ai decode this WNF state name 0x41c64e6da3bc0075`, `ai list live WNF instances`, `ai query recent TI WriteVM events`, `ai inspect module text integrity with headers and sections`, `ai find W+X kernel modules`, and `ai check driver dispatch integrity` route through the corresponding local read-only tool. Exact read-only commands after `ai`, such as `ai callbacks all WdFilter.sys`, `ai dt nt!_EPROCESS <address>`, `ai uf nt!Foo`, `ai !ci options`, `ai !vbs`, `ai !hiddenproc`, or `ai !fwtable providers`, are treated as evidence commands: Kn Live Dbg runs the command, captures stdout/stderr, and asks the selected model to explain the evidence. After local tools run, the model explains the captured output. `hunt.run`, `payload.scan`, `snapshot.capture`, and `kpage.list` with `deep=true` preview and wait for `ai go`. Default `ai <goal>` does not auto-build a `kn-live-dbg.ai-plan.v2` command plan. `module.integrity` accepts validated `target`/`module`/`name`, `limit`, `summary`, `verbose`, `headers`, `sections`, `wx`, `mismatch`, `disk`, `iat`, and `prologue` args before the local executor builds the native command. The capability parser rejects unknown tools, unknown fields, unsafe characters, invalid scalars, write-like actions, raw `kd`, nested `ai`, session mutation, unload/shutdown, and command chaining before any native handler is called. The compatibility local process resolver still runs when the provider is disabled.

`ai plan <prompt>` asks the selected model to return a strict `kn-live-dbg.ai-plan.v2` command proposal JSON object, validates proposed commands before storing them, and prints numbered commands with purpose, risk, backend, and expected-output notes. Empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected; write-like proposals are forced to require confirmation. Conceptual `what`/`why` questions stay advisory. `ai explain <read-only-command...>` is still available as an explicit evidence-analysis form; it preserves stdout/stderr, adds a deterministic output summary, then asks the selected model for analysis. It has tuned prompts for `callbacks`, `dt`/`dtx`, and `u`/`uf`, so the older `ai analyze callbacks` and `ai annotate` flows are now covered by the shorter explain form and by implicit `ai <read-only-command...>` routing.

`ai run [index|all]` executes only non-write, non-shutdown planned commands. If the plan has one read-only command, `ai run` with no index runs it. Write-like commands such as `e*`, `pe*`, `setfield`, `f`, `m`, `!callbacks disable*`, `!minifilter disable*`, and raw `kd` wrappers around write-like commands are blocked from `ai run`. `ai write` (or `ai write <index>`) prints a write preview with target class, byte count, backup/read-current command, restore-current command for small ranges, verification command, and safe read-only preflight output. `ai write confirm` (or `ai write <index> confirm`) re-runs the backup read, dispatches the write-like command, re-runs the verification command, and prints a deterministic before/after stdout/stderr diff for the verification command. Disable/enable goals such as `ai disable wdfilter minifilter` stage a write plan and do not mutate until that confirm path; a surface is required so `ai disable wdfilter` cannot silently disable every callback type. The same confirm path covers `ai enable ppl`, `ai load byovd fixture`, `ai reset timeline`, `ai start ti`, and exact write-like lines such as `ai dump-pe nt .\\ntos-live.exe`. Session commands (`write on`, `log enable`, `mcp on`, `probe load`, `backend`) are not staged. `ai transcript <path>` enables JSONL capture of AI events and command stdout/stderr, including backend mode, command class, write-like classification, stdout/stderr character counts, deterministic output summary, raw stdout/stderr, and keep-running state. `ai transcript max <bytes>` rotates long transcript files, `ai transcript redact on` redacts long hex addresses, `sk-...` style tokens, and HTTP `Bearer`/`Authorization` credentials from captured stdout/stderr, and `ai audit <path>` writes a separate JSONL record for every write-like command that executes through the normal dispatcher. `ai report <path>` exports a Markdown summary of the current AI session, transcript settings, write-audit path, and plan.

## DbgEng Backend

The default backend mode is `auto`:

1. Native memory/symbol/type commands run through the custom driver and `DbgHelp`.
2. Stop-state WinDbg commands, parser-heavy commands, `!extension` commands, and unknown `.meta` commands are routed to DbgEng after `kdinit` or lazy DbgEng initialization.
3. `backend dbgeng` sends commands directly to `IDebugControl::ExecuteWide`.
4. `backend native` disables automatic DbgEng routing.

Backend mode behavior:

| Mode | Command routing | Best fit | Notes |
| --- | --- | --- | --- |
| `auto` | Native commands use the driver/`DbgHelp` path; DbgEng-only, extension, and unknown meta commands are lazily routed to DbgEng. | Default interactive use. | Keeps live-memory features native while preserving access to WinDbg parser and stop-state commands. |
| `native` | Uses the native command handlers and blocks generic DbgEng fallback. | Driver-backed memory, symbol, type, callback, disassembly, and physical-memory work. | `!extension`, stack/register/breakpoint/execution/source/exception commands are reported as DbgEng-only instead of being executed. Explicit `u` and `uf` stay driver-backed when the device is open. |
| `dbgeng` | Sends most non-session commands directly to DbgEng raw execution. | WinDbg-compatible parser behavior. | Session commands, `!callbacks`, `!dml_proc`, `!vad`, `!threads`, `!wfp`, `!alpc`, `!vbs`, `!ci`, `!securekernel`, `!etw`, `!nmi`, `!payload`, `!mapper`, `!kpage`, `!minifilter`, `!fwtable`, `!module`, `!driver`, `!pool`, `!snapshot`, `!diff`, `!wnf`, `!address`, `dump-raw`, `dump-pe`, native physical bang commands, and explicit `u`/`uf` are still handled by the TUI before the raw DbgEng catch-all. |

`kd <command>` is an explicit raw DbgEng escape hatch and does not depend on the current backend mode.

Examples:

```text
knkd> kdinit
knkd> kdinit /remote net:port=50000,key=1.2.3.4
knkd> !dml_proc
knkd> backend dbgeng
knkd> k
knkd> backend auto
knkd> kddetach
```

DbgEng uses `IDebugClient5::AttachKernelWide(DEBUG_ATTACH_LOCAL_KERNEL, ...)` for local mode and `DEBUG_ATTACH_KERNEL_CONNECTION` for `kdinit /remote <connection-options>`. Local mode still follows the limits of Windows local kernel debugging; not every KD command has the same behavior as a remote break-in session. Use native `!dml_proc` when you need a process list without relying on DbgEng current process/thread state or extension exports.

`kdinit /remote` is not the LAN operator session. To use an already-running KnLiveDbg on another PC, see [Remote Operator Session](#remote-operator-session).

## Remote Operator Session

Use this when PC A already has elevated `KnLiveDbg.exe` (and the driver) and you want a `knkd>` on PC B on the same LAN. Full steps: `docs/REMOTE_SETUP.md`.

This is **not** `kdinit /remote` (DbgEng KD attach) and **not** MCP (`mcp on`, port 51766). `mcp on` and `remote on` cannot run at the same time.

```text
# PC A (elevated knkd>)
knkd> remote on
```

Bare `remote on` binds `0.0.0.0:51767`, prompts for a session password (**5-128** printable ASCII, no spaces, not saved), and adds inbound firewall rule `knlivedbg-remote`. `--loopback` stays on `127.0.0.1` with no firewall rule. `--peer <ipv4>` accepts only that client.

```powershell
# PC B (no elevation, same EXE, no driver)
.\KnLiveDbg.exe --connect 192.168.1.10:51767
```

B types the password **before** TCP connect. `--connect` runs before cloak, mutex, SCM, and `DeviceClient`. Tab on B uses the same completion tables as the local TUI. Command output is colored like A's console; a redirected pipe or file on B is plain text. `cls` and history are local. `disconnect` / `q` / `quit` / `exit` drop the TCP session; they do not unload A's driver.

B is denied session-lifetime and raw KD commands (`unload`, `mcp`, `kd`, `kdinit`, `backend`, `probe load`, ...). Writes otherwise match the local TUI. Address-only `e*`/`pe*` must include values on the line (`eb <addr> 90`). Dumps land on A's disk.

A's console while listening is a control plane: `off`, `status`, `disconnect`, `write off`, or `q`/`unload` to tear down the process.

Cleartext kernel-command traffic. Isolated lab only. Encrypt later with `ssh -L 51767:127.0.0.1:51767` and `remote on --loopback`.

## Native `dt`

Native `dt` now supports both type layout and value display:

```text
dt nt!_EPROCESS
dt nt!_EPROCESS <address>
dt -r1 nt!_EPROCESS <address>
dt -v nt!_EPROCESS <address> UniqueProcessId
dt nt!*EPROCESS*
dt nt!*
```

Supported options:

- `-r` or `-rN`: recursively expand nested UDT fields up to the requested depth.
- `-v`: print internal symbol tag/type id/length diagnostics.
- `-b`: bare output, omitting type names.

Field filters are case-insensitive substring filters applied to field names and type names.

Wildcard type patterns such as `dt nt!*EPROCESS*` and `dt nt!*` enumerate PDB types through `SymEnumTypesW` and apply the `*`/`?` filter in user mode. If DbgHelp cannot enumerate a loaded module's type stream, the symbol engine falls back to DIA UDT enumeration from either the loaded PDB path or the module image plus symbol path. Wildcard `dt` is list-only; use an exact type name when dumping fields or reading a value at an address.

The native symbol engine treats `nt` as the kernel-image alias and loads `ntoskrnl.exe`/`ntkrnl*` into DbgHelp under the `nt` module name, so commands such as `x nt!*`, `ln nt!PsLoadedModuleList`, and `dt nt!*` do not depend on the on-disk kernel image name.

Exact type layouts first try `SymGetTypeFromNameW`. If that lookup fails for an alias-qualified type such as `nt!_TP_POOL`, the symbol engine reuses `SymEnumTypesW` to find the exact type and dumps the layout by module base plus type id before trying DIA. The enumeration fallback matches module-qualified names, leaf names, and leading-underscore variants, so `nt!_OBJECT_TYPE`, `_OBJECT_TYPE`, `OBJECT_TYPE`, and enumerated `nt!_OBJECT_TYPE` spellings resolve to the same type. DIA fallback uses the same full-enumeration matcher and reports module/PDB/image details when a type is not found.

When `DbgHelp` cannot return a usable UDT layout, the symbol engine tries a DIA SDK fallback against the loaded PDB path or resolves the PDB from the module image plus symbol path. DIA creation first uses registered COM and then falls back to direct `DllGetClassObject` activation from the staged `msdia*.dll`, which makes registration failures distinct from real type lookup failures. The fallback is especially useful for field offsets, bit positions, and private type metadata used by callback scanning and `dt`; recursive expansion still prefers the normal `DbgHelp` type-id path when it is available.

## Native Process Listing

`!dml_proc` is implemented natively so it works even when the optional DbgEng backend does not have a current process/thread or cannot load WinDbg extension exports:

```text
!dml_proc [pid]
```

The command resolves PID 4 through the driver, uses PDB metadata for `_EPROCESS.ActiveProcessLinks`, then walks the active process list from live kernel memory. If a decimal PID argument is supplied, for example `!dml_proc 4`, only records whose process ID matches that value are printed; any other argument, for example `!dml_proc lsass`, is treated as a case-insensitive image-name substring filter and prints only matching processes. Output includes EPROCESS, PID, parent PID when available, active thread count, directory-table base, image name, and a ready-to-run `dt nt!_EPROCESS <address>` follow-up.

## No-Target User-Mode Hunt

`!hunt` scans live whole-system process state without requiring a target PID.
The default mode correlates process cross-view state, image path/profile evidence,
VAD-backed mapped code, module loader/VAD cross-view mismatches, thread/APC
execution provenance, WFP block filters that target security or anti-cheat
AppId conditions, and bounded stack references into suspicious executable
memory. `/quick` keeps the scan to cheaper process/VAD/module/thread signals,
while `/deep` adds executable live-vs-disk page comparison, hidden executable PTE
checks when VAD coverage is reliable, modified-page execution correlation, local
BYOVD exact-hash catalog matching, strong Gentlemen-style EDR-killer driver-name
IOC correlation, context-gated suffix-normalized Gentlemen EDR-killer
process-name matching, SCM driver-service IOC correlation, `_DRIVER_OBJECT`
dispatch/start integrity checks, and recent `!ti` ring correlation for strong
Gentlemen process/staging indicators that performed driver I/O or repeated
process-impairment activity. The TI correlation path also raises a behavioral
finding when one caller repeatedly controls or terminates known security-product
processes from the GentleKiller target list, even if the caller name was changed.
The current-state thread pass resolves PDB-backed `_ETHREAD.SuspendCount` and
`FreezeCount`; it reports `security_tool_impairment` only when the thread-list
inventory and suspend-state reads are complete, every observed thread of a
known security-product process is suspended or frozen, and the same per-ETHREAD
counts are reproduced by a second fresh scan. A single suspended
thread, a mixed runnable/suspended process, an unstable all-suspended sample,
an unknown process name, or partial
coverage remains raw telemetry rather than a finding.
The process/thread cross-view does not treat
`PsLookupProcessByProcessId` over already-known PIDs as a complete CID view. It
derives a candidate `PspCidTable` anchor only when the process and thread CID
lookup routines share the same repeated RIP-relative 64-bit load (or a direct
symbol agrees), validates PDB-resolved `_HANDLE_TABLE` geometry, and
independently walks every allocated level-0/1/2 entry page.
`NextHandleNeedingPool` must exactly equal the allocated-leaf capacity.
The direct pass extracts the PDB-described 44-bit
`_HANDLE_TABLE_ENTRY.ObjectPointerBits`, decodes the object header, validates
the encoded `TypeIndex` with `ObHeaderCookie` and `ObTypeIndexTable`, and accepts
only exact `PsProcessType` or `PsThreadType` objects. Allocation topology is
sampled before and after the pass, and each nonempty entry is reread immediately
after its object body is decoded; every accepted slot must be typed and its
PID/TID, owner, create time, exit state, and object address must validate. The
legacy exported-lookup sweep is retained as an additional
cross-view, but a failed or hooked `PsLookupProcessByProcessId` no longer
prevents direct EPROCESS-address revalidation.

Thread objects are compared twice against the direct CID entries,
`_EPROCESS.ThreadListHead`, `_KPROCESS.ThreadListHead`, the thread array in
`SystemProcessInformation`, and Toolhelp. Stable CID-only threads, threads
missing from CID while both kernel lists and APIs agree, individual executive
or scheduler list unlinks, and threads hidden from both APIs produce bounded
`thread_cross_view` findings. A live EPROCESS whose process record is absent
can also be recovered from a stable thread owner and reported instead of being
silently dropped. Coherent create/exit transitions are suppressed, while
identity disagreement, partial view drift, unreadable topology, or unclassified
entries clears aggregate coverage.

JSON exposes the direct entry/process/thread counts, unclassified count,
thread finding/persistent-miss counts, all completeness flags, and a
`cid_threads` evidence array. `cid_table_full_enumeration=true` is emitted only
when direct entry enumeration, full process and thread enumeration, and the
thread cross-view all complete. The clean-host gate requires those flags,
zero unclassified entries/findings/persistent misses, exact typed-entry count
agreement, and a revalidated record for every directly decoded thread.
Main-image integrity also cross-checks the EPROCESS main `SectionObject` backing
through `_SECTION_OBJECT.Segment -> _SEGMENT.ControlArea -> FilePointer` against
the main VAD section backing, Toolhelp main module path, PEB image path, and API
image path. If a kernel driver swaps the process main section to a different
normal image, the mismatch is reported as `kernel_main_section_swap_evidence`
instead of relying only on live-vs-disk page differences. The same resolver
reads backing `FILE_OBJECT` state (`DeletePending`, write/delete access, file
flags) and `SECTION_OBJECT_POINTERS.ImageSectionObject`, so primitive process
tampering evidence such as delete-pending image files, write/delete-capable main
image file objects, or file section-object pointer mismatches is surfaced as
`process_tampering_primitive_evidence`.
For resolved SEC_IMAGE VAD backing paths, default/deep mode also performs a
read-only Cloud Files provenance check. It opens for attributes only while
leaving `cldflt` in the path, recognizes the full Cloud reparse-tag family when
visible, and records a bounded FSCTL tag cross-view. Because current `cldflt`
builds can mask the tag from both attribute and FSCTL views, a successful
`CfGetPlaceholderInfo` query is also accepted as authoritative placeholder
identity; the JSON evidence distinguishes this metadata fallback from an
observed reparse tag. The scanner queries placeholder state plus
`OnDiskDataSize`, `ValidatedDataSize`,
`ModifiedDataSize`, pin/sync state, file identity length, file id, and sync-root
file id through dynamically resolved `cldapi` entry points. The rule emits
`cloudfiles_false_file_immutability` only for PP/PPL placeholder mappings,
mapped placeholders with modified-data state, or placeholders already
correlated with a normalized deep executable live-versus-disk mismatch. A
non-PP/PPL, in-sync, unmodified placeholder remains clean. JSON exposes
`cloudfiles_placeholder_images`, `suspicious_cloudfiles_images`,
`cloudfiles_placeholder_coverage_incomplete`, and
`cloudfiles_protection_correlation_incomplete`; unavailable metadata never
becomes a positive. The additive `cloudfiles_images` array preserves every
metadata-complete observation, including negative controls, with exact PID,
module/VAD paths, placeholder state and sizes, process protection, mismatch
correlation, the final suspicious decision, and its reasons. Its counts must
agree exactly with the summary. The current collector does not reconstruct
prior dehydrate/rehydrate callbacks or an immutable generation history.

Use the following safe, fully local live checks:

```powershell
.\tools\run-cloudfiles-placeholder-fixture.ps1 -Scenario InSyncNegative
.\tools\run-cloudfiles-placeholder-fixture.ps1 -Scenario ModifiedPositive
```

The fixture registers an `ALWAYS_FULL` sync root, converts a copied Windows
executable without dehydration, verifies the metadata contract, and briefly
maps it as an image. The modified case appends a harmless PE overlay before
launch and requires a positive `ModifiedDataSize`; it does not perform in-use
mutation or an FFI exploit. From an elevated PowerShell session, append
`-ValidateHunt` to run one Deep hunt while the exact fixture PID is alive and
validate the saved evidence automatically:

```powershell
.\tools\run-cloudfiles-placeholder-fixture.ps1 -Scenario InSyncNegative -HoldSeconds 1 -ValidateHunt
.\tools\run-cloudfiles-placeholder-fixture.ps1 -Scenario ModifiedPositive -HoldSeconds 1 -ValidateHunt
```

`tools\validate-cloudfiles-hunt-e2e.ps1` rejects missing or ambiguous
PID/path attribution, incomplete metadata/protection coverage, counter drift,
or a positive/negative decision that contradicts the raw observation. With
`-ValidateHunt`, the fixture writes
`cloudfiles-fixture-manifest.json` only after the process, sync root, and
temporary directory have been removed successfully.

### Safe QoS And Bind Filter E2E

The July 2026
[Bitdefender Bind Link research](https://businessinsights.bitdefender.com/bind-link-abuses-windows-feature-edr-evasion-technique)
shows why path identity alone is insufficient for File-, Process-, and
Silo-Binding. Use a disposable Windows test VM and an elevated PowerShell
session to exercise KNLiveDbg's current global File-/Process-Binding and QoS
coverage:

```powershell
.\tools\run-qos-bind-e2e.ps1 -Configuration Release
.\tools\validate-qos-bind-e2e-selftest.ps1
```

The runner does not bundle or invoke a general-purpose bind utility.
`KnLiveDbgBindFixture.exe` accepts only `apply` or `remove` for the fixed
`amsi.dll -> backing.dll` and
`MsSense.exe -> ProcessBindingBacking.exe` pairs under one direct
`%TEMP%\KnLiveDbgBindFixture-<32 hex>` child. It rejects other parents, nested
directories, reparse-point fixture roots/files, missing endpoints, and
same-file endpoints. The runner supplies harmless text files plus copied
Windows `where.exe`/`ping.exe` binaries, verifies the redirected content and
SHA-256 views, and briefly keeps the mapped copy of `ping.exe` alive.

The same run creates a uniquely named, nonpersistent 64-bit/s `ActiveStore`
QoS policy for only that temporary `MsSense.exe` path. It captures one Default
hunt and invokes `tools\validate-qos-bind-e2e.ps1`, which requires the exact
policy/rate/path finding, both exact global mappings, the exact live PID, and
two independently resolved backing paths that agree with the mapped target.
Relevant collection warnings, mistyped counters, incomplete QoS/global/process
coverage, and any attempt to claim Silo-Binding support are rejected.

Cleanup removes the exact QoS policy, exact PID, both mappings, and only the
GUID-named temporary directory. It verifies the original file contents and
image hash after removal, and writes a passed manifest only after cleanup
succeeds. This fixture does not construct a silo, inverse link, policy bypass,
or mapping against a real security product. `bindflt_silo_coverage_unsupported`
must remain `true`.

### Safe Minifilter Detach E2E

Use a disposable test-signing VM and an elevated PowerShell session to exercise
the Filter Manager attachment-loss detector:

```powershell
.\tools\run-minifilter-detach-e2e.ps1 -Configuration Release -Volume C:
.\tools\validate-minifilter-detach-e2e-selftest.ps1
```

`KnLiveDbgMiniFilterFixture.sys` is a test-signed, no-op minifilter. Automatic
attachment is suppressed. The runner creates only its exact demand-start test
service, attaches only `KnLiveDbgMiniFilterFixture.Instance` to the selected
local NTFS/ReFS volume, and registers only an `IRP_MJ_CREATE` pre-operation
callback that returns `FLT_PREOP_SUCCESS_NO_CALLBACK`. It has no device,
IOCTL, read/write transformation, or arbitrary detach primitive.

The runner uses the supported debugging attach/detach path to capture
attached, detached, and reattached snapshots. The detached snapshot must keep
both the exact Filter Manager volume and the independently enumerated
registered-minifilter callback view while the instance is absent. It then runs
an offline positive diff and a recovery diff.
`tools\validate-minifilter-detach-e2e.ps1` independently rejects cross-boot
input, incomplete attachment or callback coverage, raw-counter drift,
duplicate identities, filter unload, volume loss, a still-attached current
instance, a missing exact removal finding, or recovery that still reports the
fixture. The runner detaches, unloads, and deletes only its named fixture
service in `finally`; any cleanup failure is a failed run.

This is a safe observation fixture, not an implementation of the direct device
stack manipulation described in ABYSSWORKER research. A load failure is first
a test-signing, Secure Boot, HVCI, or local driver-policy result; it is not
detector evidence. The temporary altitude is used only by this debugging
fixture and an existing service, filter, instance, or altitude collision causes
the run to fail visibly.

### Evasion Research And Claim Ledger

`research\evasion-research-ledger.json` is the machine-readable boundary
between a published primitive and a KNLiveDbg support claim. Each technique
records primary sources, its observable, current `covered`, `partial`,
`missing`, or `out_of_scope` state, literal code anchors, positive and negative
controls, limitations, and the remaining release gate. A `covered` row cannot
carry a limitation, while an unsupported row cannot borrow implementation or
test evidence.

Run the structural and freshness gate, then its mutation suite:

```powershell
.\tools\validate-evasion-research-ledger.ps1 `
    -ReportPath .\.build\evasion-research-ledger-validation.json
.\tools\validate-evasion-research-ledger-selftest.ps1
```

The ledger intentionally expires after its configured review interval. The
validator also rejects stale source checks, non-primary or non-HTTPS sources,
dangling references, contradictory status/claim pairs, repository-path
escapes, missing literal anchors, unsafe validation commands, and a completion
set containing unsupported techniques. Passing this gate validates the
research-to-code traceability; it does not replace the elevated live evidence
below and never promotes `external_pending` to `satisfied`.
The current `pspcidtable-full-cross-view` row is deliberately `partial`: its
bounded process-CID implementation and corpus are present, while thread-CID
enumeration remains the next independent view. The clean-host validator
requires `cid_table_full_process_enumeration=true`, rejects the known-PID-only
fallback and whole-table overclaim, and cross-checks the reported anchor,
allocated leaves, handle capacity, probe count, process counts, and failures.

### Elevated External Evasion Gate

On a disposable test-signing VM, the remaining live acceptance gate can be run
as one ordered command:

```powershell
.\tools\run-evasion-external-gate.ps1 -Configuration Release -Volume C: -CleanRunCount 3
```

The runner requests elevation once, then executes the constrained QoS/global
File- and Process-Binding positive, CloudFiles in-sync negative and
modified-data positive, minifilter detach/reattach positive, and three Deep
clean-host runs with Threat Intelligence required. Each child completes its
exact cleanup before returning. The final clean-host run is last, so it also
checks for findings or incomplete coverage after every fixture has been
removed.

The gate writes `manifest.json` only after all child cleanup and explicit
process, service, and QoS-policy residue checks. It records SHA-256 hashes for
the child manifests and clean-host analysis, then invokes
`tools\validate-evasion-external-gate.ps1`. The independent validator requires
the exact artifact layout, both CloudFiles decisions, passed child cleanup,
at least three complete zero-finding Deep runs, active Threat Intelligence, and
the explicit `silo_binding_coverage_unsupported=true` limitation. Use
`tools\validate-evasion-external-gate-selftest.ps1` for driver-free positive
and mutation controls. `-NoElevation` is available for automation and fails
visibly without creating a passed manifest.

The ESET prose says the private GentleKiller list exceeds 400 processes; the
public Table 2 HTML currently exposes 274 unique lower-case image names, and the
validator pins that public, independently auditable set.
The hunt pass also carries the ESET-published SHA-1 file IoCs for GentleKiller,
HexKiller, ThrottleBlood, HavocKiller, and OxideHarvest. Process main images,
loaded driver images, and SCM driver-service binaries are hashed with caching
and promoted to high-confidence `eset_exact_file_sha1_ioc` findings on exact
matches, so renamed samples are still detected without relying on filename
masquerade alone.
Use `tools\validate-eset-hunt-iocs.ps1` to verify that the 27 public ESET file
IoCs remain present in the hunt source and connected to process, loaded-driver,
driver-service, high-signal, and documentation paths. The same check also
covers the ESET Table 3/4 process-profile suffix bases and driver-profile leaves.
When refreshing against the live article, save the ESET HTML and pass
`-ArticleHtml <path>`; the validator reconstructs split SHA-1 values from Table 5,
case-insensitive `.exe` process names from Table 2, and Table 3/4 process and driver indicators,
then requires exact set parity with the pinned source lists.
To fetch the current article directly, use `-ArticleUrl <url>`; by default it stores the HTML under
`.build\eset-article-current.html` before applying the same checks.
Process-profile findings include bounded on-disk metadata and suffix evidence
for the ESET evasion layer: Authenticode trust state, version strings, original
filename, file description, icon-resource presence, and the `1`/`2`/`Light`/
`Clear` suffix tail. Version-info and icon impersonation reason codes are gated
by vendor-like version metadata so a generic icon resource does not become a
standalone conclusion. Known Enigma/Themida PE section-name hints are recorded
as supporting packer evidence only after Gentlemen process/staging context
already exists. Weak vendor-impersonation process names are not promoted as
standalone findings unless stronger Gentlemen staging or telemetry context is
present. A `GentlemenCollection` path by itself is treated as supporting
staging context, not a standalone process-profile conclusion; unknown process
names in that path still need evasion metadata such as vendor-like version
information, an invalid copied signature, or packer-section evidence. The
related OxideHarvest credential-tool profile is gated by
Gentlemen staging context or the `-i`/`-u`/`-p`/`-t`/`-o` command-line shape
described by ESET when all required options have values.
Deep stack correlation uses
a per-process stack-pointer cache, so JSON findings for modified executable pages
include `stack_reference_cache_samples` and `stack_reference_cache_limited`
evidence instead of rereading every stack for every mismatched page. The `/deep`
BYOVD path is offline/reproducible and high-signal: it reuses the local catalog,
never runs the updater script from inside `!hunt`, and suppresses name/version
hints that require signer context. Weak ESET driver names are also suppressed in
the loaded-module name-only sweep unless hash, Gentlemen-staged service, or
integrity evidence supplies stronger context. Run `!byovd update` explicitly
when fresh driver intelligence is needed, or `!byovd scan` when broader hinting
is desired.
The SCM scan is also read-only and surfaces installed or running driver services
whose service name or configured binary path matches a strong EDR-killer driver
IOC, so a driver-service staging artifact can be found even before a module is
successfully loaded. Driver names that can collide with legitimate products are
not promoted from SCM name-only evidence unless the service path/name also has
Gentlemen staging context; hash, loaded-module, or driver-object evidence remain
the stronger confirmation paths for those weak names. If a configured service
binary hashes to an ESET file IoC, the service is reported even when its service
name and binary leaf have been changed. SCM `ImagePath` values are normalized
before hashing, including quoted paths, `\??\`/`\SystemRoot\` prefixes,
environment variables, extensionless EDR-killer driver leaves, and benign
trailing service arguments.
The live E2E fixture keeps its temporary kernel-driver services non-started so
it does not load throwaway drivers on the VM, but the readiness suite also
validates a synthetic `driver_service_running` service artifact to keep the
running-service high-risk branch covered.
The same readiness path validates synthetic exact-hash artifacts for a renamed
EDR-killer process, renamed OxideHarvest process, loaded driver, and driver
service so filename changes cannot silently break SHA-1 IOC coverage.
It also validates a synthetic metadata-evasion process-profile artifact for the
invalid-signature, vendor-version, icon, and packer evidence that ESET calls out
in the masquerading layer.
The security-product behavior-only path has its own synthetic artifact with
exact `security_product_target_count` and target-name evidence, so a renamed
caller only passes the contract when repeated Table 2 target activity is visible.
The TI correlation is best-effort and history-based: start `!ti` before the
workload when you need DeviceIoControl or native-API behavior to appear in the
same hunt report. Without a populated TI ring, `/deep` still runs the static and
kernel-object evidence layers and reports `ti_events=0`. The native-API
impairment path recognizes repeated `TerminateProcess`/`OpenProcess` activity
and sensitive cross-process TI tasks such as `AllocVM`, `ProtectVM`, `ReadVM`,
`WriteVM`, `MapView`, `QueueUserApc`, `SetThreadContext`, and
`Suspend`/`Resume`, but still requires an EDR-killer profile/staging context or
repeated hits against known GentleKiller security-product targets before it
emits a hunt finding. The renamed-caller path emits
raw JSON reasons `known_security_product_process_target` and
`gentlekiller_security_target_list`. Console triage renders those raw machine
codes as the generic high-signal label `security_product_process_targeting`, so
behavior-only target-list activity is visible even when the caller filename is
not one of the published EDR-killer names.
The WFP communication-blocking path is current-state based rather than
history-based. It enumerates BFE filters, decodes condition text and
`FWPM_CONDITION_ALE_APP_ID` byte blobs, and emits
`security_tool_communication_blocking` only when an enabled Block/BitmaskBlock
filter targets a known security-product or anti-cheat process through AppId or
strong filter metadata. Persistent, clear-action-right, and high-weight block
filters are preserved as supporting evidence in the same finding. A failed or
warning-bearing BFE filter enumeration sets
`wfp_filter_coverage_incomplete=true` and clears aggregate
`coverage_complete`, so zero WFP findings cannot be promoted to clean proof.
Console output is conclusion-first and short by default: `!hunt` prints
`[hunt.conclusion]`, `[hunt.assessment]`, and `[hunt.summary]`, then suppresses
raw detail. The assessment section prints the operator answer as
`subject`, `what`, `why`, and `next` for the highest-priority finding groups,
so the default screen explains which process or system surface did what and
which evidence supports that conclusion. Raw high-signal, top-process,
top-reason, and per-finding tables are hidden by default and appear only with
`/details` or `/limit n`. The high-signal table is reserved for decisive technique/evidence
labels such as
`known_defense_evasion_tool_name`, `known_defense_evasion_driver_service`,
`manipulated_version_info`, `packed_or_protected_section`,
`credential_collection_cli_shape`, `process_tampering_primitive_evidence`,
`module_stomping_permission_evidence`,
`security_tool_communication_blocking`, and published file-hash IOC labels, so rare
target-specific detections do not disappear behind generic anomaly counts. JSON
output still preserves the stable raw reason codes for validators and evidence
correlation. High-signal rows are ordered by operator triage priority before raw
frequency, so primary technique/IOC labels stay above supporting metadata
signals such as version-info manipulation or packer-section evidence.
The assessment grouping keeps process tampering, module stomping, mapped-code or
loader-view evasion, WFP communication blocking, and EDR/credential-tool
identity findings as separate operator conclusions instead of collapsing them
under one generic code-provenance bucket.
SCM and driver-service IOC findings are system-scoped rather than process-scoped;
the triage tables show them with `system_findings` so PID-less service evidence
is visible without expanding per-finding detail.
Use `/summary` when the console should force the concise answer-only view, while
`/json` still preserves the full finding set. `/details`
renders per-finding detail with the default cap, and `/limit` is parsed as a
decimal count and also enables raw triage tables plus detail rendering;
`/limit 0` renders every finding. Console warnings are capped as
well, and `/summary` suppresses repetitive per-process warning detail; use
`/json` for the full warning set. Normal image-backed
`EXECUTE_WRITECOPY` VADs are tracked as copy-on-write executable mappings, not
as generic W+X evidence. The kernel VAD protection is treated as the allocation
default; when `VirtualQueryEx` can cover the whole VAD, hunt records the current
committed permission subranges and correlates a thread, APC, or stack address
against the exact page that contains it. A small RWX page inside a larger image
VAD therefore does not make every thread in that VAD a W+X execution finding.
W+X hunt findings require an exact writable-executable current page or disk PE
section evidence that the image exposes a writable executable section.
Loader-owned image VADs are compared against disk PE section
characteristics, so execute/write permission drift over non-writable executable
sections, entrypoint write-capability, and Mockingjay-style writable executable
image sections are reported as module-stomping permission evidence. Generic W+X,
weak private executable, and PE-like private VAD-only findings are kept as low-confidence leads and capped per process
unless they are corroborated by large private executable regions, image-section
permission drift, loader/module cross-view evidence, or execution provenance.
Built-in Windows process injection context is added only for those stronger
code-provenance cases, not for baseline JIT or dynamic-code hygiene by itself.
`/json` creates missing parent directories before writing, so paths such as
`.build\hunt-live.json` work from a clean lab directory.
For an elevated ESET/Gentlemen end-to-end lab run on a VM that does not have
MSBuild or WDK installed, first create a prebuilt bundle from the development
machine:

```powershell
tools\make-eset-hunt-e2e-vm-bundle.ps1
```

The bundle contains `BUNDLE-INFO.json` with
`bundle_contract=eset-hunt-e2e-vm-bundle-v1`, the runner contract, file hashes,
the source git status, and the expected VM startup needles. After copying and
expanding `.build\eset-hunt-e2e-vm-bundle.zip` on the VM, run
`tools\run-eset-hunt-e2e.ps1` without `-Build`. In a source checkout that has
the full build toolchain, `tools\run-eset-hunt-e2e.ps1 -Build` is still the
one-command path.
The runner starts the EDR-killer/OxideHarvest and driver-service target
fixtures, drives `KnLiveDbg.exe` through redirected stdin, writes the hunt JSON,
validates the manifest with `tools\validate-hunt-target.ps1`, and gates the
console contract so the run must print `[hunt.conclusion]`, `[hunt.assessment]`,
the concise `[hunt.summary]`, and summary-mode detail suppression
notice. Pass `-ArticleUrl <url>` or `-ArticleHtml <path>` to the same
runner when the live proof should also refresh the current ESET article IoC
table and write `.build\eset-hunt-e2e\article-validator.log`; with
`-ArticleUrl`, the fetched HTML is kept in the same E2E artifact directory
unless an explicit `-ArticleOutPath` is supplied.
The runner prints `runner_contract=e2e-auto-knlivedbg-article-currentness-v2`,
`elevated=<bool>`, and `output_dir=<path>` near startup so copied VM bundles can
be distinguished from older target-only wrappers and non-elevated runs leave a
durable diagnostic in `runner.log`. The target fixture lifetime
defaults to 300 seconds, with `KnLiveDbg` capped at 180 seconds and a required
target-lifetime padding window, so the EDR-killer process and SCM service
artifacts remain alive throughout the scripted deep hunt instead of racing the
scanner timeout. After artifact validation, the runner signals a named
`/stop-event` so the target exits through its normal cleanup path and removes
temporary SCM services without waiting for the full target lifetime. The runner
also writes `.build\eset-hunt-e2e\runner.log` with the exact target arguments,
target PID, manifest-wait state, `KnLiveDbg` launch, validator step, and any
caught exception so VM runs that exit early can be diagnosed without relying
only on console scrollback. If the target exits before the 35-scenario manifest
is ready, the runner reports that condition immediately instead of waiting for
the manifest timeout. On any failure it prints the artifact paths and snapshots
live `KnLiveDbg` and `KnLiveDbgHuntTarget` processes.
It also prints the tails of the target, `KnLiveDbg`, and validator logs so the
artifact directory is enough to identify the failing stage.
If a VM run already produced the 35-scenario manifest but the wrapper exited
before launching `KnLiveDbg`, rerun the same script with `-ReuseExistingTarget`.
That mode preserves the existing manifest, regenerates only the hunt/console
artifacts, and continues from the scripted `KnLiveDbg` plus validator stage. Add
`-ExistingStopEventName <name>` when the original console printed the target's
`Local\KnLiveDbgHuntE2E-...` event name so the runner can signal cleanup after
validation.
The same proof can be re-checked from captured artifacts without recreating the
SCM services:

```powershell
tools\validate-eset-hunt-e2e-artifacts.ps1 -Manifest <manifest> -HuntJson <json> -Stdout <knlivedbg.stdout.log> -RunnerLog <runner.log> -RequireRunnerPassed
```

That validator checks the manifest, JSON summary, required
ESET/Gentlemen/OxideHarvest reason codes, the full 35-scenario ESET fixture
contract when validating end-to-end artifacts, negative controls for weak vendor
name, GentlemenCollection path-only staging, and OxideHarvest name-only cases,
console triage contract, and, when `-RunnerLog` is supplied, the live runner
contract, elevated execution, 35-scenario target-ready step, and scripted
`KnLiveDbg` launch. Add `-RequireRunnerPassed` when rechecking completed VM
artifacts so the runner's final `passed` marker is required too. The full E2E
contract has exactly 32 positive class/risk/confidence scenario contracts plus
three negative-control scenarios; the driver-service-only contract has exactly 15
positive contracts. The JSON summary must also report exactly 15 EDR-killer
driver-service findings.
For the full E2E contract, stdout must expose both process-profile assessment
evidence and the system-scoped `known defense-evasion driver service` evidence
phrase with the expected `driver_service_iocs` summary count, so PID-less SCM
findings remain visible to the operator. The readiness validator also builds a synthetic
35-scenario artifact set so this full contract is exercised even on non-elevated
development machines where SCM driver-service fixtures cannot be created live.
The raw JSON reason remains `gentlemen_edr_killer_driver_service`; only the
operator-facing console phrase is generalized.

## Native VAD And Thread Triage

`!vad` and `!threads` add read-only process memory triage without adding new kernel parsing logic:

```text
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!vad scan <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad modules <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad mappedpe <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]
```

Targets can be decimal PID, image name, or EPROCESS address. `!vad` resolves `_EPROCESS.VadRoot` through PDB/DIA type metadata, walks the complete balanced tree with bounded traversal and cycle detection, decodes VPN range, allocation/default protection, private-memory, commit, large/no-change, subsection, and PE-like first-page evidence when available, then enriches each VAD with current committed protection totals from `VirtualQueryEx`. Child links are queued before optional record metadata is decoded, so an unreadable or non-matching node cannot hide its descendants. `/exec`, `/private`, `/wx`, and `/pe` narrow only the emitted records; `/limit` caps output after the full tree has been counted. `/wx` means at least one currently writable-executable subrange when the effective query is complete, and `/pe` probes committed private VAD base pages with the same PE header detector used by pool PE hunting. `/hiddenpte` also walks the target process page tables from its DTB, subtracts the normalized VAD coverage plus known VAD-less OS shared mappings, and prints `[hidden-pte]` ranges where a present user PTE exists without VAD coverage, which is a DKOM-style hidden memory signal.

`!vad scan` is the injection-oriented preset. It combines private executable, W+X, intact or signature-wiped private PE, large private executable, and executable present-PTE-without-VAD evidence, and emits `kn-live-dbg.vad.v1` JSON with explicit traversal, PE-probe, effective-protection, and hidden-PTE coverage fields. `!vad modules` produces a complete cross-view PE inventory rather than relying on the loader list alone: it merges Toolhelp loader modules, every decoded VAD, `VirtualQueryEx` `MEM_IMAGE` identity, in-memory PE headers and entry points, and mapped-file paths by allocation base. Its `kn-live-dbg.process-pe.v1` JSON preserves each source, path/header/protection evidence, suspicious reasons, and independent coverage flags, including loader-invisible private/manual mappings and SEC_IMAGE mappings whose header page was decommitted or whose file has no PE-like extension. `!vad mappedpe` is a compatibility alias for `!vad modules`; `/scan`, `/modules`, and `/mappedpe` remain accepted after a legacy target.

The elevated positive-control gate exercises every VAD filter plus both new modes by PID and by EPROCESS, asserts full traversal and output-only `/limit` semantics, checks exact PID/EPROCESS result-set equality, and validates private RX/RWX, intact/wiped PE, large executable, hidden-PTE, and loader-invisible SEC_IMAGE scenarios:

```powershell
.\tools\validate-process-vad.ps1 -Configuration Release
```

`!threads` walks the process thread list, prints ETHREAD/TID/start/Win32StartAddress/TEB/module/VAD annotations, optionally includes user-stack bounds plus bounded stack references into suspicious executable memory, and `/apc` surfaces conservative APC queue evidence when ETHREAD/KAPC layouts are available. Address-to-VAD annotations use the exact current protection subrange when available. On current Windows user APCs whose `KAPC.NormalRoutine` is an `ntdll.dll` dispatcher, the scanner also checks the context/argument slots and promotes a caller callback only when it resolves to suspicious executable provenance; ordinary data arguments remain telemetry. Both commands support `/json <path>` with stable field names for diffing. Warnings are expected on PDB drift, protected process/module enumeration failures, partial reads, or APC layouts that cannot be interpreted confidently.

## Kernel Callback Scanner

`!callbacks` walks live kernel callback lists using kernel PDB type layouts and the native memory reader:

```text
!callbacks all
!callbacks object
!callbacks registry
!callbacks process
!callbacks thread
!callbacks imageload
!callbacks minifilter
!callbacks object WdFilter.sys
!callbacks minifilter UnionFS
write on
!callbacks disable object WdFilter
!callbacks disable process WdFilter.sys
!callbacks disable minifilter WdFilter
!callbacks disable-all WdFilter
!callbacks enable object WdFilter
!callbacks enable-all WdFilter
```

The scanner currently covers:

1. Object-manager filters from `_OBJECT_TYPE.CallbackList`. The scanner first discovers `_OBJECT_TYPE` objects through `ObTypeIndexTable` and `_OBJECT_TYPE.Name`, then falls back to `PsProcessType`, `PsThreadType`, and `ExDesktopObjectType` when the table is unavailable. Some public nt PDBs expose `_OBJECT_TYPE.CallbackList` but omit the private callback item type; in that expected public-symbol case the scanner uses a guarded x64 item-layout fallback, validates live list pointers, callback-entry pointers, operation masks, and callback routine pointers, and only reports a warning if the PDB exposes a partial/drifted item layout or the live validation fails.
2. Registry callbacks by enumerating and validating registry callback list-head candidates such as `CmpCallbackListHead`, then walking callback context entries with guarded x64 fallback layouts when public nt PDBs omit `_CM_CALLBACK_CONTEXT_BLOCK`.
3. Process creation callbacks by enumerating and validating create-process notify routine table candidates such as `PspCreateProcessNotifyRoutine`, then decoding callback routine blocks with a stable x64 fallback when public nt PDBs omit `_EX_CALLBACK_ROUTINE_BLOCK`. Process notify metadata is decoded into `notifyType`, for example `0x2` becomes `PsSetCreateProcessNotifyRoutineEx`.
4. Thread creation callbacks by enumerating and validating create-thread notify routine table candidates such as `PspCreateThreadNotifyRoutine`, then decoding callback routine blocks with the same stable x64 fallback.
5. Image load callbacks by enumerating and validating load-image notify routine table candidates such as `PspLoadImageNotifyRoutine`, then decoding callback routine blocks with the same stable x64 fallback.
6. Minifilter callbacks by discovering `fltmgr!FltGlobals`, validating the frame-list root, walking `FrameList`, each `_FLTP_FRAME.RegisteredFilters`, and each `_FLT_FILTER.Operations` registration array.

`disable`/`enable` require `write on` and a target module. They patch only that module's callbacks and never write NULL or unlink lists. Object/registry/process/thread/image-load slots are replaced with a CFG-valid return-0 thunk (`OB_PREOP_SUCCESS` / `STATUS_SUCCESS` / ignored VOID). Minifilter disable/enable reuses the existing `!minifilter` live `CallbackNodes` path: Pre returns `FLT_PREOP_SUCCESS_NO_CALLBACK` (1), Post returns `FLT_POSTOP_FINISHED_PROCESSING` (0). Original pointers stay in this session so `enable` can restore them; `enable` fails closed if this session never disabled that module. After disable, `!callbacks <scope> <module>` still lists those records with a `DISABLED` tag. `disable-all`/`enable-all` apply every scope. A module name is required. JSON schema `kn-live-dbg.callbacks-set.v1` is emitted for MCP `callbacks.set`.

Each record prints the discovered root address and source, callback function address, nearest symbol, owning module, object type name/index/address and discovery source for object callbacks, minifilter name/altitude/frame/driver object when present, callback/list block addresses, altitude when present, and registration/callback context pointer. Object callback rows use `object=<name>` in both the header and detail line so Process, Thread, Desktop, and other object-manager surfaces are visible without interpreting the raw `_OBJECT_TYPE` address. Image-load output uses `function` for the `PLOAD_IMAGE_NOTIFY_ROUTINE` owner and reports the decoded notify block plus raw encoded slot value. Minifilter output includes operation callbacks, filter unload, instance setup/teardown, name provider, KTM, section, and volume-mount routines when the target build exposes those fields. Add a module name after the callback scope, for example `!callbacks object WdFilter.sys` or `!callbacks minifilter UnionFS`, to print only records whose pre/function or post callback is owned by that module; the match is case-insensitive and treats `WdFilter` and `WdFilter.sys` as the same module stem. Registry callback routines are validated against loaded kernel image ranges before being emitted. Registration and callback context pointers are annotated with a module and nearest symbol only when they point into a loaded kernel image; process creation notify block context values are printed as `notifyType=<decoded-api> metadata=<hex>` because they are internal notify metadata, not callback module pointers. The implementation is PDB-driven where public or private type metadata exists; the expected public-PDB object-callback item fallback is validated against live pointers before records are emitted, while warnings are reserved for partial PDB layouts, structure drift, or failed validation.

## Windows Filtering Platform

`!wfp` enumerates Windows Filtering Platform objects natively through the user-mode Base Filtering Engine (`fwpuclnt.dll`) and does not require the kernel driver to be open:

```text
!wfp providers
!wfp sublayers
!wfp callouts
!wfp callouts /module tcpip
!wfp filters
!wfp filters /layer ALE_AUTH_CONNECT_V4
!wfp filters /provider WdFilter
!wfp layers
```

The scanner opens an engine handle with `FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine)`, builds in-memory provider, layer, and sublayer indexes from `FwpmProviderEnum0`, `FwpmLayerEnum0`, and `FwpmSubLayerEnum0`, then enumerates the requested scope through the matching `FwpmXxxCreateEnumHandle0` / `FwpmXxxEnum0` / `FwpmXxxDestroyEnumHandle0` cycle. Each page-sized batch is freed with `FwpmFreeMemory0` before the next page.

Output kinds and decoded fields:

1. `[wfp.provider]` shows provider key GUID, display name, decoded persistent/disabled flag mnemonics, optional service name, and optional description.
2. `[wfp.sublayer]` shows sublayer key GUID, display name, 16-bit weight, owning provider name plus service name when set, and persistent flag mnemonics.
3. `[wfp.callout]` shows callout key GUID, display name, runtime `calloutId`, applicable layer name and GUID, owning provider, and decoded persistent/usesProviderContext/registered flag mnemonics.
4. `[wfp.filter]` shows runtime `filterId`, filter key GUID, action type (`Block`, `Permit`, `CalloutTerminating`, `CalloutInspection`, `CalloutUnknown`, `Continue`, `None`, `NoneNoMatch`, `BitmaskPermit`, `BitmaskBlock`) with optional `calloutKey`, weight rendered from the underlying `FWP_VALUE0`, condition count, layer, sublayer, owning provider, and decoded filter flag mnemonics.
5. `[wfp.layer]` shows layer key GUID, layer name, 16-bit `layerId`, and decoded `kernel|builtin|classifyMostly|buffered` flag mnemonics.

`!wfp callouts /module <name|GUID>` filters callouts by the owning provider's service name (case-insensitive substring), display name, or `providerKey` GUID. `!wfp filters /layer <name|GUID>` filters filters by layer display-name substring or `layerKey` GUID, and `/provider` applies the same provider matching as `/module` for filters.

The user-mode `FWPM_CALLOUT0` shape does not include kernel-mode callout function pointers, so the BFE-backed `!wfp callouts` resolves callout ownership through `providerKey` → provider `serviceName` rather than by matching function pointers against loaded module ranges. The kernel-side classify/notify/flowDelete pointers are recovered separately by `!wfp kernelcallouts`, which walks the `netio.sys` callout table anchored on `netio!gWfpGlobal` (see the capability list); the user-mode `!wfp` scopes require only that the Base Filtering Engine (`BFE`) service is running.

`wfp.list` is also wired as a local AI capability tool. `ai <question>` planning can choose it with optional `scope` and `module`/`layer` arguments, and the executor runs it through the same shape validation used for plan commands.

## ALPC Port Enumeration

`!alpc` walks live kernel memory through `KnLiveDbg.sys` and PDB type metadata to enumerate ALPC ports, render server/client connection families, and count queue depths:

```text
!alpc ports
!alpc ports /name OLE
!alpc ports /pid 1234
!alpc port ffff8a8400000000
!alpc connections
!alpc queues ffff8a8400000000
```

Discovery flow:

1. `nt!ObTypeIndexTable` is enumerated to find the `ALPC Port` and `Directory` `_OBJECT_TYPE` instances and their type indices.
2. `nt!ObHeaderCookie` is resolved when present; on builds without it the scanner records a warning and falls back to raw `_OBJECT_HEADER.TypeIndex` comparisons.
3. `nt!ObpRootDirectoryObject` is read, then the scanner recurses through `_OBJECT_DIRECTORY.HashBuckets[]` with bounded depth and a visited-directory cycle guard, decoding each entry's `_OBJECT_HEADER.TypeIndex` with the per-object XOR formula (`raw ^ cookie ^ ((header_addr >> 8) & 0xff)`).
4. For each `ALPC Port` body the scanner reads `OwnerProcess`, `ConnectionPort`, `CommunicationInfo`, and `Flags` from PDB-resolved offsets, then follows `_ALPC_COMMUNICATION_INFO.ConnectionPort`, `ServerCommunicationPort`, and `ClientCommunicationPort` to surface paired server/client ports that are not themselves named in the directory tree.
5. Owner annotations resolve `_EPROCESS.UniqueProcessId` and `ImageFileName` for each port whose `OwnerProcess` lies in the kernel canonical range.

Subcommand behavior:

1. `!alpc ports` lists every discovered port with role tag (`connection`/`server`/`client`/`named`), name, owning process, `ConnectionPort`, and `CommunicationInfo` linkage. `/name <pattern>` filters by case-insensitive substring on port name or full directory path, and `/pid <pid>` filters by decimal owning-process PID.
2. `!alpc port <address>` prints the single port whose address matches and includes queue depths.
3. `!alpc connections` groups all discovered ports by `ConnectionPort` to render server/client family graphs, with an explicit `unpaired ports` section for ports that have no `ConnectionPort` set.
4. `!alpc queues <address>` performs bounded `_LIST_ENTRY` walks on `MainQueue`, `PendingQueue`, `LargeMessageQueue`, `CanceledQueue`, and `WaitQueue`. `_KQUEUE` fields (typically `WaitQueue`) are detected by PDB type name and the dispatcher header is skipped before list walking.

The scanner only enumerates ports reachable through the Object Manager directory tree and through `CommunicationInfo` chains hanging off those named ports. Anonymous client ports that never receive a connection through a named server port are intentionally not enumerated; documented handle-table walking is reserved for a later milestone.

`alpc.list` is also wired as a local AI capability tool. `ai <question>` planning can choose it with optional `scope` (`ports` or `connections`), `name` substring, and `pid` decimal arguments, and the executor runs it through the same shape validation used for plan commands.

## VBS / HVCI / Secure Kernel Status

`!vbs`, `!ci`, and `!securekernel` reuse `KnLiveDbg.sys` virtual reads and PDB type metadata to report the state of Virtualization-Based Security, HVCI, the Secure Kernel, and Isolated User Mode (IUM) trustlets:

```text
!vbs
!ci
!ci options
!ci policy
!securekernel
```

Data sources:

1. `nt!g_CiOptions` (or `ci!g_CiOptions`, or legacy `nt!CiOptions`) is read as a `UINT32` and decoded into `CODEINTEGRITY_OPTION_ENABLED`, `TESTSIGN`, `UMCI_ENABLED`, `UMCI_AUDITMODE_ENABLED`, `HVCI_ENFORCED`, `UMCI_EXCLUSIONPATHS_ENABLED`, `TEST_BUILD`, `PREPRODUCTION_BUILD`, `FLIGHT_BUILD`, `HVCI_STRICT_MODE`, and `HVCI_DEBUG_MODE`.
2. `nt!HvlpVsmVtlCallVa` (or the equivalent build-specific alias) is read as a pointer; a non-zero kernel-canonical value indicates VBS is active and the VTL call code page is mapped.
3. `nt!HvcallpVtlCallStub` (or the equivalent alias) is resolved as a secondary VBS marker.
4. `PsLoadedModuleList` is scanned for `securekernel.exe` and `skci.dll` to confirm Secure Kernel runtime presence.
5. User-mode `CPUID` is queried at leaf `0x40000000` (hypervisor vendor signature), and at leaf `0x40000006` when supported (raw implementation hardware features). MBEC enablement cannot be confirmed from user mode because it lives in `IA32_VMX_PROCBASED_CTLS2` bit 22; the report annotates that limitation and treats HVCI enforcement as a proxy.
6. `PsActiveProcessHead` is walked through `_EPROCESS.ActiveProcessLinks`. For each process, `_EPROCESS.SecureState` (or `_KPROCESS.SecureState` when the field is exposed through the embedded `Pcb`) is read; bit 0 (`SecureKernelInProcess`) flags IUM trustlets. When that field is not present in the loaded PDB, the scanner falls back to well-known trustlet image-name prefixes (`lsaiso`, `bioiso`, `securesystem`, `kdcustomization`) which already handle `_EPROCESS.ImageFileName` being truncated to 15 bytes.

Subcommand behavior:

1. `!vbs` prints a `[vbs.core]` summary line, the `[ci.options]` block with raw value and decoded mnemonics, the `[vbs.hypervisor]` block with vendor signature and CPUID leaf info, the `[securekernel.modules]` list, and the `[securekernel.trustlets]` list.
2. `!ci` (or `!ci options`) prints the `[ci.options]` and `[vbs.hypervisor]` blocks; `!ci policy` additionally prints a `[ci.policy]` summary noting that full WDAC policy blob discovery requires private CI internals.
3. `!securekernel` prints the `[securekernel.modules]` and `[securekernel.trustlets]` lists.

WDAC policy blob extraction is intentionally deferred; the doc-listed `CI!g_CiPolicies`/`CiValidateImageHeader` path requires private layouts that the scanner does not yet trust enough to commit to.

## ETW Logger Hooks And NMI Callbacks

`!etw` and `!nmi` provide self-check coverage for two surfaces commonly used by InfinityHook-style rootkits and NMI-based stack inspection drivers:

```text
!etw loggers
!etw logger 0
!etw logger "Circular Kernel Context Logger"
!nmi
!nmi callbacks
```

ETW logger flow (`!etw loggers` / `!etw logger`):

1. `nt!EtwpDebuggerData` is resolved through the loaded kernel PDB, and 64 `WMI_LOGGER_CONTEXT*` pointers are read from offset `0x10`.
2. For each non-null logger context, `_WMI_LOGGER_CONTEXT.LoggerName` (UNICODE_STRING) and `_WMI_LOGGER_CONTEXT.GetCpuClock` (function pointer) are read using PDB-resolved field offsets when the type is exposed, or fallback offsets `0x68` (LoggerName) and `0x28` (GetCpuClock) otherwise. A warning is emitted when the fallback path is taken because those offsets drift across builds.
3. Each `GetCpuClock` target is annotated with its owning module and nearest symbol. Pointers that do not land inside any loaded kernel module are flagged with `[SUSPICIOUS]`, which is the canonical InfinityHook indicator (`GetCpuClock` rewritten to point at attacker-controlled code outside `nt`/`hal`).
4. `!etw logger <index>` accepts a decimal slot index (0..63); `!etw logger <name-substring>` filters by case-insensitive substring on the logger name.

ETW integrity flow (`!etw integrity`):

1. The scanner resolves a fixed list of canonical kernel dispatch targets grouped into four categories:
   - **Core ETW dispatch**: `EtwpReserveTraceBuffer`, `EtwpReserveTraceBufferAtomic`, `EtwpLogKernelEvent`, `EtwpReleaseTraceBuffer`, `EtwpFinalizeTraceBuffer`, `EtwpCommitTraceBuffer`, `EtwSendTraceBuffer`, `EtwpEventDispatcher` (primary modern InfinityHook surface)
   - **Classic cycle-count surface**: `EtwpGetCycleCount`, `EtwpReceiveCycleCount` (older InfinityHook variants)
   - **PMC / HAL**: `HalpCollectPmcCounters`, `HalCollectPmcCounters`, `HalpProcessorPerfCounter`, `HalpInterruptHandle`
   - **Timing sources**: `KeQueryPerformanceCounter`, `KeQuerySystemTimePrecise`, `KeQueryInterruptTimePrecise`, `KeQueryUnbiasedInterruptTimePrecise`, `RtlGetSystemTimePrecise`, `HalpTimerQueryHostPerformanceCounter`
   - **Syscall path**: `KiSystemCall64`, `KiSystemCall64Shadow`, `KiSystemServiceUser` (broader rootkit surface that responds to the same prologue-tampering checks)

   Targets not present in the loaded PDB are reported as `status=unresolved` and skipped without failing the whole scan; this lets a single command sweep multiple build variants.
2. For each resolved target the scanner reads 0x100 bytes through `KnLiveDbg.sys` and decodes up to 16 instructions with the vendored Zydis decoder. The first 24 bytes are surfaced as `head=` hex for triage.
3. Five integrity checks run against the decoded prologue: (a) first-instruction unconditional `jmp` (classic trampoline), (b) first-instruction `int3`/`ud2` (debug-trap replacement), (c) `mov reg, imm64; jmp reg` indirect trampoline, (d) `push imm; ret` 32-bit-target trampoline, (e) any unconditional `call`/`jmp` in the first 16 instructions whose target lies in kernel canonical space but outside any loaded kernel module.
4. Each finding records the instruction index, offset, mnemonic, resolved target with module/symbol annotation, and a human-readable reason. The record status is `clean`, `SUSPICIOUS`, `unresolved`, `read-failed`, or `decode-failed`.
5. A single summary line reports the target count, clean / suspicious / unresolved totals before the per-target detail lines.

InfinityHook on modern Windows no longer lands on `WMI_LOGGER_CONTEXT.GetCpuClock` directly (that field carries a UINT32 mode tag dispatched by a switch statement in the kernel); the hook surface moved to the ETW/PMC dispatch functions themselves. `!etw integrity` covers that updated surface by reading those functions' actual instructions instead of relying on a single field value.

NMI callback flow:

1. `nt!KiNmiCallbackListHead` (with `nt!KiNmiCallbackList` as a fallback alias) is resolved through the loaded kernel PDB and read as a `PKNMI_HANDLER_CALLBACK`.
2. The singly-linked list is walked with bounded iteration and a visited-node cycle guard. Each `KNMI_HANDLER_CALLBACK` node has a fixed layout: `Next` at `0x00`, `Callback` at `0x08`, `Context` at `0x10`, `Handle` at `0x18`.
3. Each `Callback` is annotated with owning module and nearest symbol; targets outside any loaded kernel module are flagged with `[SUSPICIOUS]`.

Discovery is the entire point: any `!etw` GetCpuClock hit outside loaded modules, or any `!nmi` callback in an unfamiliar driver, is a follow-up lead for `u`/`uf` and `dt` triage.

## Firmware Table Providers

`!fwtable` enumerates provider nodes registered through `SystemRegisterFirmwareTableInformationHandler` without calling the registered callbacks:

```text
!fwtable providers
!fwtable providers /module WdFilter
!fwtable provider ACPI
```

Firmware table provider flow:

1. `nt!ExpFirmwareTableProviderListHead` is resolved through the loaded kernel PDB, with `nt!ExpFirmwareTableResource` reported when present.
2. The provider list is walked as `LIST_ENTRY` with a visited-node guard, maximum-entry cap, canonical-pointer checks, guarded reads, and Flink/Blink backlink validation.
3. Node decoding prefers private PDB type metadata when available. When private types are absent, fallback candidates are scored against live nodes; the normal public-symbol fallback is `SYSTEM_FIRMWARE_TABLE_HANDLER` fields first (`ProviderSignature +0x00`, `Register +0x04`, `FirmwareTableHandler +0x08`, `DriverObject +0x10`) with the list entry at `+0x18`.
4. Each record prints the provider signature as hex plus FourCC when printable, the handler address with owning module and nearest symbol, and the DriverObject name/start/size/owner module when `_DRIVER_OBJECT` fields are available.
5. Triage flags include nonstandard providers outside the ACPI/FIRM/RSMB baseline, duplicate signatures, null or nonkernel pointers, handlers outside loaded image ranges, handler/DriverObject owner mismatches, DriverStart values outside loaded modules, and corrupt list links.

Default operation is passive by design. `EnumSystemFirmwareTables`, `GetSystemFirmwareTable`, and `ZwQuerySystemInformation(SystemFirmwareTableInformation)` are not used by the scanner because those paths can execute an attacker-controlled handler registered by a cheat driver.

## Windows Notification Facility

`!wnf` exposes the documented WNF state-name encoding and best-effort live `_WNF_NAME_INSTANCE` walking:

```text
!wnf decode <state-name-hash>
!wnf instances
!wnf instance <state-name-hash|entry-address>
!wnf data <state-name-hash|entry-address>
```

Decoder (`!wnf decode`):

1. The 64-bit raw state-name value is XORed with the documented obfuscation key `0x41C64E6DA3BC0074`.
2. The decoded value's bit fields are parsed per Alex Ionescu's "Out-of-Sight" reference: `Version` (bits 0..3), `NameLifetime` (4..5; `WellKnown`/`Permanent`/`Persistent`/`Temporary`), `DataScope` (6..9; `System`/`Session`/`User`/`Process`/`Machine`/`PhysicalMachine`), `PermanentData` (bit 10), `Sequence` (bits 11..63), and for `WellKnown` lifetime the `OwnerTag` (bits 32..63) is additionally surfaced as a 4-character ASCII component identifier when the bytes are printable.
3. `decode` is standalone and always works on any build.

Live walking (`!wnf instances` / `!wnf instance` / `!wnf data`):

1. The scanner collects silo state candidates by trying the well-known globals `nt!ExpWnfSiloState`, `nt!ExpWnfState`, and `nt!ExpWnfProcess` first, then falling back to anchor-disassembly of `nt!NtQueryWnfStateData` and `nt!NtPublishWnfStateData` with two levels of indirect-call follow and dual interpretation (treat each RIP-relative reference as both a pointer dereference and an inline struct). The union of those candidates feeds both walking modes.
2. **Modern Win11 fast path (LIST_ENTRY heuristic walker)** runs first: for each silo candidate the scanner enumerates `LIST_ENTRY`-shaped heads in the first 0x800 bytes, walks every non-empty chain (bounded at 0x80 entries per list, 0x80 bytes captured per entry), and ranks each list by the number of UNIQUE state-name-shaped 64-bit values it yields after per-entry probe of byte offsets `0x10`..`0x38`. Kernel-canonical pointers and pure-zero slots are rejected explicitly to avoid sentinel/object-pointer pollution. The single most-diverse list is treated as the authoritative `_WNF_NAME_INSTANCE` chain; runner-up lists are surfaced as diagnostics so an operator can spot when the top-1 selection was wrong.
3. **Legacy `RTL_AVL_TABLE` path** is tried only when the LIST_ENTRY walker produces no records. The AVL table is located by trying `NameSet`/`NameSubscriptionTable`/`SubscriptionTable`/`NameInstanceTable`/`NameInstances` fields on `nt!_WNF_SUBSCRIPTION_TABLE`, `nt!_WNF_SILODRIVERSTATE`, and `nt!_WNF_PROCESS_CONTEXT` types from the loaded PDB. The walker performs iterative in-order traversal with bounded depth (64) and node count (16384). Each node's user data starts at offset `+0x20` (past `sizeof(_RTL_BALANCED_LINKS)`); the user data is a `_WNF_NAME_INSTANCE` whose `StateName`, `ChangeStamp`, `DataSize`, and `LastDataBlock` (or `StateData`/`DataBlock`) fields are read via PDB-resolved offsets.
4. `instance <hash|entry-address>` filters the walk to a matching state name or stable LIST_ENTRY-mode entry address. `data <hash|entry-address>` dumps up to 256 bytes of the last-published payload as a classic hex+ASCII view. The legacy AVL path follows PDB-resolved `LastDataBlock`/`StateData` fields, while the modern LIST_ENTRY path heuristically scans the first 0x200 bytes of the matched entry for a kernel-canonical pointer whose dereferenced header matches the documented `_WNF_DATA_BLOCK` shape (`DataSize`, `AllocatedSize`, `ChangeStamp`). If that heuristic fails, diagnostics print a per-pointer header census so the build-specific data slot can be inspected manually.
5. Each surfaced entry annotates the **owning process** recovered from the stable EPROCESS pointer at `node-0x30` of every chained node (entry-level metadata, 100% recovery across entries that carry at least one chained node). Per-entry chain decomposition is printed as `chained_nodes=N subscribers=X resolved=Y other_objects=Z tags={Ntfc:N Wnf:N Sect:N ...}` so an operator immediately sees how many real subscribers exist versus backing kernel objects. The `subscribers` count counts only true subscription tags (`Ntfc` / `Wnf ` / `WnfN`); `resolved` counts how many of any node yielded `pid=N image="..."`. The listing path (`!wnf instances`) emits only resolved subscriber lines per entry; single-entry views (`!wnf instance`, `!wnf data`) still print every node with prefix and body hex dumps so a build's record layout can be characterized. EPROCESS resolution uses a two-path acceptance: classical `_DISPATCHER_HEADER.Type == 0x03` fast-path, or shape-only validation of PDB-resolved `_EPROCESS.UniqueProcessId` (4-aligned, `0 < pid <= 0x100000`) AND `ImageFileName` (`>= 3` printable-ASCII chars). Candidates within `0x200` bytes of the chained node are rejected as same-chunk noise.
6. `log enable` / `log disable` mirrors the entire console session to a timestamped UTF-8 log file (`KnLiveDbg-YYYYMMDD-HHMMSS.log`) in the EXE directory. Useful for capturing voluminous `!wnf instances` output for offline analysis; console coloring is preserved live while the log file receives clean text.

Diagnostic subcommands for builds where automatic detection picks the wrong chain:

- `!wnf candidates` dumps the first 0x100 bytes of every silo-state candidate discovered by the anchor disassembly, with embedded state-name-shape counts and kernel-pointer slot counts per candidate. Use this to spot which candidate looks like the real silo state struct.
- `!wnf lists` walks every `LIST_ENTRY`-shaped head in each silo candidate, dumping each non-empty chain with hex+ASCII per entry and per-entry state-name probe annotations. Use this to identify which head holds the actual `_WNF_NAME_INSTANCE` chain.

When neither walking mode produces records the scanner emits a precise error naming the missing piece and reminds the operator that the `decode` subcommand still works as a complete standalone tool.

## Big Pool Tracking

`!pool` snapshots `nt!PoolBigPageTable` -- the kernel's per-build tracking table for big pool (>= one page) allocations -- and surfaces tag, size, paged/non-paged class, virtual address range, and, on request, the effective R/W/X attributes derived from a live page-table walk:

```text
!pool big                              list every NonPaged big pool entry
!pool big /tag Wmem /annotate          filter by tag and walk PTE for each entry
!pool find /wx /limit 20               hunt effective W+X NonPaged allocations
!pool find /min 0x10000 /annotate      hunt large NonPaged allocations
!pool find /addr 0xffffae8000123000    locate the entry containing a VA
!pool summary                          totals only (no per-entry listing)
```

How it works:

1. The scanner enables `SeDebugPrivilege` on the current token, resolves `ntdll!NtQuerySystemInformation`, and issues a buffer-growing `SystemBigPoolInformation` (class 0x42) query that doubles from 64 KB up to a 64 MB ceiling with at most 16 retries. The kernel returns a snapshot of `_SYSTEM_BIGPOOL_INFORMATION` whose entries pack the virtual address with the `NonPaged` flag in the low bit and report a 4-byte ASCII tag plus byte size.
2. Per-entry filters apply in order: paged class (`/nonpaged` default, `/paged`, or `/any`), 4-character tag (`/tag <ABCD>` with case-sensitive matching; partial tags zero-pad the upper bytes to mirror `ExAllocatePoolWithTag('SG')` literal encoding), size band (`/min`/`/max`), containing address (`/addr`), optional effective W+X filtering (`/wx`), and finally `/limit <n>` truncates the printed list while still counting all matches.
3. `/annotate` issues one `IOCTL_KNDBG_TRANSLATE_VIRTUAL` per kept entry. The driver walks PML5/PML4/PDPTE/PDE/PTE (auto-detecting LA57 via CR4 and reporting the level count) and the scanner ANDs the Writable bit and ORs the NX bit across every traversed level so that effective W/X is correct even when a parent table clears W or sets NX. Large-page short-circuit (`PS=1` at PDPTE or PDE) is honored; the output flags `LargePage` and any combined `[W+X]` non-paged page in red as a BYOVD/staging signal. `/wx` implies `/annotate` and applies `/limit` after the W+X attribute filter so early clean entries do not hide later hits.
4. `!pool summary` prints the totals -- raw `TotalEntries`, `NonPagedCount`, `PagedCount`, kept `MatchingCount`, buffer size finally accepted by the kernel, retry count, and a `(no SeDebugPrivilege)` warning when elevation failed -- without the per-entry listing.

Requirements and caveats:

- The host must be elevated. `NtQuerySystemInformation(SystemBigPoolInformation)` returns `STATUS_ACCESS_DENIED` without `SeDebugPrivilege`; the error path reports the NTSTATUS verbatim.
- Only big pool (>= one page) is tracked by `nt!PoolBigPageTable`. Smaller allocations served from per-CPU lookasides and the segment heap are not visible to this command.
- `/annotate` requires the `KnLiveDbg.sys` device to be open. The TUI auto-disables the flag with a warning when the device is not available. `/wx` requires the device because it cannot classify effective permissions without page-table translation.

## Session Baseline Diffing

`!snapshot` and `!diff` turn the existing native scanners into a same-boot evidence baseline workflow. `!snapshot baseline` captures process inventory plus the high-value domains, stores the baseline in memory, and writes JSON plus a Markdown snapshot report. `!diff baseline` captures a fresh current snapshot, compares it against the in-memory baseline, writes the current JSON plus Markdown reports, and prints a compact new/tamper-focused summary.

```text
!snapshot baseline [/all] [/name <label>]
!snapshot save <path> [/all] [/name <label>]
!snapshot show [baseline|<path>] [/domains] [/warnings]
!diff baseline [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
```

Default files are written under the EXE directory's `.kn-live-dbg\snapshots` and `.kn-live-dbg\reports` trees. The JSON schema is `kn-live-dbg.snapshot.v1`; reports are Markdown and are generated automatically for both baseline snapshots and diffs.

The diff is intentionally biased toward new or defense-relevant state changes:

1. Added records are shown when the identity was absent from the baseline and present in the current snapshot.
2. Escalations are shown when an existing identity becomes high-risk or a same-boot stable field changes, such as driver dispatch redirection, `_EPROCESS.Protection` downgrade/strip, a Filter Manager attachment changing from attached to detached, ETW GetCpuClock tampering, pool records gaining W+X/PE evidence, or VAD DKOM hidden-PTE evidence.
3. Removed records are not shown generally. The deliberate exceptions are a callback that disappears while its owner module remains loaded, a process-protection record that disappears while its process remains present, and a minifilter attachment that disappears while the same Filter Manager volume and independently enumerated registered minifilter remain present. They require same-boot comparison and complete current coverage for their domain. Process-security metadata/counts are cross-checked against the process inventory when snapshot JSON is imported. Semantic callback re-registration or a clean attachment for the same filter/volume and stable altitude (instance-name fallback only when altitude is absent) suppresses the corresponding removal signal.
4. Pool output is ordered as pool-PE suspect first, pool-PE hit second, W+X NonPaged third, then large NonPaged by descending size.
5. `!diff baseline` scans VAD DKOM hidden-PTE evidence for every process that is new since the baseline and still alive at diff time.
6. Low-risk child records implied by a newly added parent, such as a new driver's routine dispatch entries, are folded by default and counted as `hiddenChildren`; add `/details` to expand them.

The `/all` option is accepted for explicitness; the current native baseline captures the full implemented domain set by default: modules, drivers, callbacks, Filter Manager minifilter attachments and volumes, ETW, NMI, cpu-state (SYSCALL MSRs / control registers / SSDT / IDT), firmware-table providers, pool, pool-PE, kpage (executable kernel memory outside loaded modules via a PTE walk -- session space excluded, walk truncation surfaces as a domain warning), WFP, ALPC, WNF, VBS/CI, BYOVD, process inventory, and a separate `process-security` record for each readable `_EPROCESS.Protection` byte. Minifilter attachment capture uses read-only `FilterVolumeFind*` and `FilterVolumeInstanceFind*` calls; `--self-test minifilter-attachments-query` exposes the live enumeration contract and fails visibly when the token lacks the required access. BYOVD catalog auto-update is allowed for `!snapshot baseline` and `!snapshot save`, but `!diff baseline` reuses the local catalog in no-update mode and emits a warning if the catalog fingerprint differs between snapshots. YARA is not run by the snapshot path unless the standalone `!byovd scan /yara` command is used.

Typical clean-baseline flow:

```text
knkd> !snapshot baseline /name clean-boot
knkd> !snapshot show baseline /domains /warnings
... launch the workload (game + suspected loader) ...
knkd> !diff baseline /limit 20
knkd> !diff baseline /domain kpage /risk high
knkd> !diff baseline /domain pool /risk high /limit 30
```

The `/domain kpage` line is the mapper-hunting pair to `/domain pool`: it lists
executable kernel regions outside loaded modules, so headerless code hidden in
non-paged pool shows up as new records even when no pool-PE hit exists.

Native physical memory support is intentionally explicit:

```text
vtop nt!PsLoadedModuleList
vtop /cr3 <directory-table-base> <virtual-address> 100
vtop /process <process-id> <user-virtual-address> 100
procctx <process-id>
db <user-virtual-address> 80
db /process <process-id> <user-virtual-address> 80
pdb <physical-address> 80
pdq <physical-address> 10
!db <physical-address> 80
!dq <physical-address> 10
write off
!eb <physical-address>
peq <physical-address> <qword-value>
!eq <physical-address> <qword-value>
```

`vtop` uses the current CR3 when no directory-table base is supplied. `vtop /process` asks the driver to resolve the target EPROCESS, reads the DTB offsets from PDB type metadata, and walks that process address space. It prints whether the walk used PML4 or PML5, the physical address of each page-table entry that was read, and the leaf entry kind, physical address, and writable state. `procctx <pid>` stores the same process context for later user VA reads/writes. `d*` commands accept `/process <pid>` for one-shot process-aware access, while native `e*` virtual writes default to the System process context (`pid 4`) and accept `/process <pid>` when a process-specific user VA should be edited. If `e*` is invoked with only an address, the TUI enters a WinDbg-style one-line edit prompt that shows the current value, accepts replacement values, and cancels on an empty line, `.`, `q`, or `quit`. These paths translate each VA range before access. Reads use physical pages, translated user VA writes use physical writes through the selected process context, and kernel VA writes use the original virtual address after any required page-table write-enable step. When a translated leaf PTE/PDE/PDPTE is present but not writable, `e*` temporarily sets the write bit on that leaf entry, flushes the virtual address, performs the edit, restores the write bit to its original state, and flushes again. The driver walks x64 paging structures through physical reads, reports PML5E/PML4E/PDPTE/PDE/PTE entries when applicable, handles 4 KB, 2 MB, and 1 GB pages, and returns the number of contiguous bytes remaining in the translated page. Physical reads are available through both native names (`phys`, `pdb`, `pdw`, `pdd`, `pdq`) and WinDbg-style extension names (`!db`, `!dw`, `!dd`, `!dq`). Physical writes are available through both native names (`peb`, `pew`, `ped`, `peq`) and WinDbg-style extension names (`!eb`, `!ew`, `!ed`, `!eq`), and are routed through page-sized `MmMapIoSpaceEx` mappings with `MmGetVirtualForPhysical` fallback when Windows already has a direct mapping for the PFN. Address-only physical enter commands prompt with the current physical value before writing, matching the native `eb` edit flow. Write mode is enabled by default for each device handle; use `write off` when you want a read-only console session.

## Memory Dumps

Two file-emitting commands turn live kernel memory into on-disk artefacts for offline triage in IDA, Ghidra, or hex editors:

```text
dump-raw <address> <length> <path> [/zerofill]
dump-pe <address> <path>
dump-kernel <path> [/max <bytes>] [/strict]
dump-analyze <path> [/json <path>]
dump-live <path> [/user [pid|eprocess]] [/compress] [/hv]
```

`dump-raw` reads `<length>` bytes starting at `<address>` and writes them verbatim. The read is chunked into 256 KB IOCTL calls (matching the driver's read window). The default behaviour aborts on the first per-chunk failure and reports the failing VA; pass `/zerofill` to fall back to zero-filling the failed chunk and continuing -- useful when sweeping ranges that straddle unmapped or paged-out pages. The total request is capped at 1 GB as a sanity guard.

`dump-kernel` writes a WinDbg-openable complete dump: an 8 KB `DUMP_HEADER64` plus every RAM run returned by `MmGetPhysicalMemoryRanges`. Pages are streamed through `IOCTL_KNDBG_READ_PHYSICAL` (no whole-image buffer). Unreadable PFNs are zero-filled unless `/strict` is set. The system stays live, so the file is inconsistent by design. `/max` truncates the payload and the header together.

`dump-live` is the separate OS path when no process is named. It does not use KnLiveDbg.sys. It calls `NtSystemDebugControl(SysDbgGetLiveKernelDump)` after enabling `SeDebugPrivilege`, matching Task Manager live kernel dumps. Bare `/user` adds every process user page, `/compress` requests compression, and `/hv` asks for hypervisor pages. Builds or policies that disable live dumps fail closed with the NTSTATUS.

`dump-live <path> /user <pid|eprocess>` is a different writer. It needs KnLiveDbg.sys, walks that process user CR3 plus the kernel CR3, and writes a WinDbg `DUMP_HEADER64` complete dump of the resident pages. The file is a kernel dump (`PAGE`/`DU64`), not a user minidump (`MDMP`). On KPTI systems the dumped kernel CR3 root is merged with the user-half entries so one DirectoryTableBase translates both halves, KDBG/EPROCESS/PEB pages are pinned, and CPU0 `KPRCB.CurrentThread` is pointed at a thread of the target. Open it in WinDbg as a kernel dump; `.process /p /r <eprocess>` then `!peb` / `lm u` if the default context is still wrong.

`dump-pe` rebuilds an on-disk PE image from a kernel-loaded module. It:

1. Reads the first 4 KB at `<address>` and validates `IMAGE_DOS_HEADER.e_magic == 'MZ'`, follows `e_lfanew` to `IMAGE_NT_HEADERS`, and validates the `'PE\0\0'` signature. Both PE32 and PE32+ are supported; the scanner extracts `SizeOfHeaders`, `NumberOfSections`, `SizeOfImage`, `ImageBase`, and `Machine` from whichever optional header is present.
2. Re-reads the headers buffer if `SizeOfHeaders > 4 KB` (rare but possible on builds with hefty `IMAGE_DATA_DIRECTORY` payloads), then locates the `IMAGE_SECTION_HEADER[]` table and computes the output file size as `max(SizeOfHeaders, max_over_sections(PointerToRawData + SizeOfRawData))`.
3. Copies the in-memory headers verbatim to the output (preserving any loader patches), then for each section reads `SizeOfRawData` bytes from `<address> + VirtualAddress` and writes them at file offset `PointerToRawData`, reversing the loader's RVA-to-disk-offset expansion.
4. Sections whose reads fail (typically discarded `INIT` sections in KMDF drivers; sometimes paged-out `.pdata`/`.rdata`) are zero-filled and surfaced as `[ZERO-FILLED]` per-section warnings, so the final file remains a structurally-valid PE that IDA/Ghidra can still load.

**Header recovery**: malware modules (and some kernel-mode loaders) zero out the `MZ` and/or `PE\0\0` signatures, and sometimes the `e_lfanew` pointer too, to evade naive memory scanners. `dump-pe` recovers from this when the rest of the `IMAGE_FILE_HEADER` / `IMAGE_OPTIONAL_HEADER` is intact:

1. **MZ wiped**: if `e_lfanew` still points to a plausible NT header (Machine != 0, NumberOfSections in 1..96, OptionalHeader.Magic == `0x10b`/`0x20b`, SizeOfOptionalHeader matches the Magic), the scanner restores `IMAGE_DOS_SIGNATURE` at offset 0.
2. **PE\\0\\0 wiped**: if `e_lfanew` is correct but the 4-byte signature there is zero (or anything other than `0x00004550`), the scanner accepts the location if the trailing FileHeader/OptionalHeader still looks like a real PE and writes back the canonical `'PE\0\0'`.
3. **e_lfanew corrupted**: the scanner sweeps 4-byte-aligned offsets from `0x40` up to `0x1000`, looking for a region that passes the FileHeader+Magic plausibility test, then rewrites `e_lfanew` to point at the discovered offset (along with restoring `MZ` and `PE\0\0` if also wiped).
4. **DOS header partially or fully wiped, NT headers intact**: handled as a superset of cases 1+3.

Whatever was repaired is surfaced both as per-restore lines in `dump-pe warning:` and as a coloured `recovered=[MZ,e_lfanew,PE]` tag in the final summary line. If the NT headers themselves are also gone (no plausible FileHeader+Magic anywhere in the first 4 KB), the scanner reports `could not locate IMAGE_NT_HEADERS even after attempting signature recovery` rather than guessing.

```text
dump-raw nt!KiSystemServiceUser 0x200 .\kiSystemServiceUser.bin
dump-raw 0xffffae8000123000 0x10000 .\pool-region.bin /zerofill
dump-pe nt .\ntoskrnl-live.exe
dump-pe Wdf01000 .\wdf01000-live.sys
dump-kernel .\live-complete.dmp
dump-live .\os-live.dmp
dump-analyze .\live-complete.dmp
dump-analyze .\live-complete.dmp /json .\dump-analyze.json
```

`dump-analyze` is offline and does not need KnLiveDbg.sys. It parses the 8 KB `DUMP_HEADER64`, lists physical runs, and walks `PsLoadedModuleList` through the dump DTB. VA translation is 4-level (PML4) or 5-level (PML5/LA57): CR4.LA57 is read from `ContextRecord` when `KdSecondaryVersion=2`, then confirmed by probing the module-list page tables. Using a 5-level walk on a 4-level dump (or the reverse) would mis-index CR3, so the probe is required. Output includes `paging=`, `la57=`, and `cr4=`.

Caveats:

- The dumped PE reflects the live image state: relocations are applied (so RVAs in the file body point at `ImageBase + RVA` rather than zero-relative), the IAT slots hold resolved function pointers (not import descriptor RVAs), and any in-place patches by anti-malware, HVCI, or PatchGuard appear in the output. Use this for analysing the running image, not for repackaging an installable binary.
- Paths that contain whitespace are accepted when wrapped in double quotes -- `dump-pe nt "C:\Program Files\Dumps\ntoskrnl-live.exe"` works the same as `dump-pe nt .\ntoskrnl-live.exe`. The argument tokenizer recognises `"..."` as a literal region and supports mixed quoted/unquoted concatenation within a single token. Apostrophes are kept literal in unquoted paths (matching CMD/PowerShell convention) so names like `O'Brien\foo.sys` need no quoting.
- Both commands require the `KnLiveDbg.sys` driver device to be open. Symbol-based addresses (e.g., `nt`, `Wdf01000`, `nt!ExpWnfSiloState`) are resolved through the same symbol path as the rest of the TUI.

## Address Inspection

`!address <va>` is the WinDbg-style introspection for a single virtual address. It answers "what is this pointer, and what can be done to it" in one go:

```text
!address <va>
```

Output breakdown:

1. `[address]` -- canonicality (bits above 47 / 56 must all match), kernel vs user half, `[zero-page]` flag for the first 4 KB, `paging=LA57` when 5-level paging is active.
2. `[address.module]` (when the address falls inside a loaded kernel module range) -- image name, base, size, offset within the module, full image path.
3. `[address.symbol]` (when DbgHelp/DIA can resolve a nearest symbol) -- symbol name plus byte displacement.
4. `[address.translation]` -- live CR3, number of paging levels walked, page size, and per-level PML5E/PML4E/PDPTE/PDE/PTE values along with their physical addresses. Each entry is annotated `(P=W=U=PS=NX=)` so the operator can see exactly where access is gated.
5. `effective:` -- aggregated permissions across every walked level: present = AND of bit 0, writable = AND of bit 1, executable = AND of `(!NX)`, user-accessible = AND of bit 2. A `[W+X]` red tag fires when the page is both writable and executable in the effective state.
6. `[address.physical]` -- resulting physical address, byte offset inside the page, and the byte count guaranteed contiguous by the driver translation pass.

Examples:

```text
knkd> !address nt!ExpWnfSiloState
knkd> !address 0xffffe78fcd778000
knkd> !address WdFilter+0x1234
```

Symbolic forms (`nt!XXX`, `module+0xNN`, hex/decimal values, address expressions) are accepted through the same parser used elsewhere in the TUI. Non-canonical inputs short-circuit before TranslateVirtual and report a warning instead of issuing an IOCTL that would fail deterministically.

## Module And Driver Integrity

`!module integrity` and `!driver integrity` are read-only live integrity checks for common anti-cheat/rootkit surfaces:

```text
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections]
                  [/wx] [/mismatch] [/limit <n>] [/json <path>]
!driver [list|object|integrity] [driver|all] [/dispatch] [/devices] [/limit <n>] [/json <path>]
!drvobj <name|address> [/dispatch] [/devices] [/json <path>]
!devstack <device-object-address> [/json <path>]
!handles [pid] [/target <pid>] [/process|/all] [/suspicious] [/limit <n>] [/json <path>]
!hiddenproc [/json <path>]
!wdfilter [/json <path>]
!inputstack [/json <path>]
!dma [/json <path>]
!hv [/json <path>]
```

`!module integrity` reads loaded kernel module PE headers from live memory, validates PE signatures, optional-header bounds, `SizeOfImage`, `SizeOfHeaders`, alignments, data directories, and section ranges, then page-walks executable/`.text` section first/last pages to flag static or effective W+X evidence. Live-vs-disk comparison masks loader-owned mutable bytes, including supported Dynamic Value Relocation Table Function Override fixups, while malformed or unsupported fixup metadata fails closed. Console output stays compact by default; `/summary` suppresses records, `/verbose` shows every reported module and section, `/headers` prints PE header evidence, `/sections` prints all sections, `/wx` filters to W+X evidence, and `/mismatch` filters to size/header/section mismatch evidence. JSON output uses the stable `kn-live-dbg.module-integrity.v1` schema with summary counts, warnings, module reason codes, section reason codes, page-probe state, and notes for baseline diffing. `!driver integrity` walks `\Driver`, decodes `_DRIVER_OBJECT` fields from PDB/DIA metadata, annotates `MajorFunction[]` handlers with module/symbol ownership, and flags only dispatch pointers outside every loaded module; cross-module handlers inside a loaded image are retained as delegation telemetry.

Examples:

```text
knkd> !module integrity ntoskrnl
knkd> !module integrity all /summary
knkd> !module integrity all /wx /verbose
knkd> !module integrity ntoskrnl /headers /sections
knkd> !module integrity all /limit 20 /json .\module-integrity.json
knkd> !driver integrity WdFilter
knkd> !driver integrity all /json .\driver-integrity.json
```

## BYOVD Intelligence Scan

`!byovd` scans the currently loaded kernel module list against a local BYOVD catalog. The catalog is generated by `tools\update-byovd-intel.ps1` from the Microsoft vulnerable driver blocklist ZIP/XML plus LOLDrivers hash and YARA feeds. `!byovd scan` automatically refreshes the local catalog under `<exe-dir>\data\byovd` when it is missing or older than 24 hours; use `/no-update` to force offline/reproducible mode or `/force-update` to refresh before scanning.

```text
!byovd [scan] [/no-update] [/force-update] [/exact] [/verbose] [/summary]
              [/limit <n>] [/json <path>]
!byovd scan /yara [/yara-path <exe>] [/yara-timeout <seconds>]
!byovd update [/force]
!byovd status
!byovd fixture [status|load [sys-path]|unload|path]
```

The scanner hashes each loaded module image on disk with MD5/SHA1/SHA256. Exact hash matches against Microsoft or LOLDrivers entries are reported as `HIGH` confidence. Microsoft file-attribute rules are also matched by file name plus PE file version and reported as `MEDIUM` confidence. The scanner reads PE version-info vendor metadata and suppresses third-party file-attribute hints against Microsoft-owned OS binaries, but full WDAC signer/certificate constraints are not yet enforced in this slice. `/exact` suppresses those name/version hints when the operator wants hash-only evidence.

`/yara` additionally runs the downloaded LOLDrivers YARA files under `<exe-dir>\data\byovd\yara` against each loaded module image on disk. YARA execution uses an external `yara64.exe` / `yara.exe`, but release packages intentionally do not include YARA binaries. Install YARA separately, put it on `PATH`, or use `/yara-path <exe>` to pin a specific binary. KnLiveDbg also searches the EXE directory, `tools\`, development parent `tools\` directories, and the current working directory's `tools\` for operator-supplied binaries. `/yara-timeout <seconds>` caps each driver/rule invocation; the default is 30 seconds and accepted range is 1..600 seconds. YARA hits are emitted as `HIGH` confidence with `source=loldrivers_yara` and `match_type=yara`. JSON output uses `kn-live-dbg.byovd-scan.v1` and includes `summary.yara_*`, `yara.executable`, and `yara.rule_files`.
`summary.yara_scans` counts attempted YARA process invocations, while `summary.yara_failures` and `summary.yara_timeouts` split out failed or timed-out attempts.

`!byovd fixture load` installs and starts the bundled no-op fixture driver `amdryzenmasterdriver.sys`. The driver creates no device, exposes no IOCTLs, and only sets `DriverUnload`; its file name and fixed PE version `1.0.0.0` are intentionally chosen to satisfy a Microsoft vulnerable-driver file-attribute rule so the scanner should report a `MEDIUM` signer-unverified hit. This fixture is for testing the name/version path only. `HIGH` exact-hash testing should use a test-only local catalog entry for a benign sample hash, not a real vulnerable driver binary.

Positive-control flow:

```text
knkd> !byovd update
knkd> !byovd fixture load
knkd> !byovd scan /no-update /verbose
...
[byovd.hit] image=amdryzenmasterdriver.sys ... version=1.0.0.0 ...
  [byovd.match] confidence=MEDIUM source=microsoft_blocklist category=microsoft_file_attribute type=file_version name=amdryzenmasterdriver.sys versionRange=0.0.0.0..1.5.0.0
knkd> !byovd fixture unload
```

If the fixture fails to load before the scan, treat that as a platform policy result first: HVCI, Secure Boot, test-signing state, and the Windows vulnerable-driver blocklist can prevent a driver that intentionally matches a Microsoft blocklist rule from loading. In that case the scanner has no loaded module to report; use a test VM with the intended code-integrity policy, or validate the catalog/status path with `!byovd status` and updater tests.

Examples:

```text
knkd> !byovd
knkd> !byovd scan /exact
knkd> !byovd scan /yara
knkd> !byovd scan /yara /yara-path C:\Tools\YARA\yara64.exe /yara-timeout 15
knkd> !byovd scan /force-update /json .\byovd-scan.json
knkd> !byovd update
knkd> !byovd status
knkd> !byovd fixture load
knkd> !byovd scan
knkd> !byovd fixture unload
```

## Big Pool PE Hunting

`!pool pe` combines the big pool enumerator with the `dump-pe` plausibility-gated PE header detector to surface hidden / reflectively-loaded modules camped in `nt!PoolBigPageTable` allocations. The detector accepts both intact and signature-wiped PE headers, so the common malware pattern of zeroing `MZ` / `PE\0\0` / `e_lfanew` to evade scanners no longer hides the payload.

```text
!pool pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>]
             [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]
```

How it works:

1. Same enumeration path as `!pool`: enable `SeDebugPrivilege`, call `NtQuerySystemInformation(SystemBigPoolInformation=0x42)`, then iterate big pool entries after applying the paged-class, tag, and size filters.
2. For each kept entry, read the first 4 KB through the driver `ReadMemory` IOCTL on the safe `MmCopyMemory` path and run `ProbeForPeHeader`. The probe tries `e_lfanew` first; on miss it sweeps 4-byte-aligned offsets `0x40..0x1000` looking for a plausible `IMAGE_NT_HEADERS` (Machine != 0, NumberOfSections in `1..96`, SizeOfOptionalHeader `0xF0`/`0xE0`, OptionalHeader.Magic `0x10b`/`0x20b`, SizeOfHeaders in `(0, 0x10000]`, SizeOfImage in `(SizeOfHeaders, 256 MB)`).
3. Each hit is annotated with whether `MZ`, `PE\0\0`, and/or `e_lfanew` were wiped. Hits with any wipe are highlighted in red with a `WIPED=[MZ,e_lfanew,PE]` tag and also counted against `suspicious` in the summary line; intact-header PE images print in the regular `[pool-pe.hit]` form for completeness.
4. With `/dump <directory>`, each hit is written to disk through `DumpKernelPeToFile`, which performs the same signature-recovery and section walking as the standalone `dump-pe` command. The output filename pattern is `poolpe_<tag>_<address>.bin`; the directory is created if missing.

```text
[pool-pe.hit]     address=0xffffae8000123000 size=0x10000 tag=Wmem NonPaged nt=0x100 bits=64 machine=0x8664 sections=5 sizeOfImage=0xa000 imageBase=0x...
[pool-pe.suspect] address=0xffffae8000777000 size=0x18000 tag=Cdat NonPaged nt=0x108 bits=64 machine=0x8664 sections=6 sizeOfImage=0x14000 imageBase=0x0 WIPED=[MZ,e_lfanew,PE]
[pool-pe.summary] total=18324 nonpaged=5012 paged=13312 scanned=4988 readFail=4 hits=2 suspicious=1
```

Notes:

- The probe runs on the first 4 KB only -- enough to cover DOS header + NT header + section table for virtually every PE. Allocations smaller than `sizeof(IMAGE_DOS_HEADER)` are skipped.
- `/suspicious` collapses output to the wiped-header hits, which are the high-signal cases for malware hunting.
- `/dump` failures (e.g. truly torn-down sections inside the payload) leave a partial PE in the output file with `[ZERO-FILLED]` sections, mirroring `dump-pe` behaviour. The hit still appears in the scan output regardless.
- Default size floor is `0x1000` (one page) since PE images take at least one page. Override with `/min`/`/max` when chasing exotic layouts.

## Leftover mapper payloads

A kdmapper-style run is two objects. The signed exploit driver is loaded for
real, then usually unloaded and wiped from kernel ledgers. The payload is
copied into independent pages and was never a loaded module. `!mapper` only
sees ledger leftovers from the first object. `leftover=0` means the ledgers
look clean, not that the payload is gone.

| Layer | Command | Role |
|---|---|---|
| Loaded BYOVD | `!byovd` | Catch the signed exploit driver while it is still mapped |
| Bookkeeping remnants | `!mapper` | Incomplete PiDDB / `MmUnloadedDrivers` / ci-hash wipe |
| Orphan executable pages | `!kpage /pe` | Independent-page payload after the ledgers were cleaned |
| Hook-to-body | `!payload scan` | Callbacks/SSDT/IDT/... that still jump to those pages |
| Staged pool PE | `!pool pe` | Pool-backed PE (intact or MZ/PE wiped). Not independent pages |
| Temporal bookkeeping | `!snapshot` `leftover-mapper` | Same-boot add/drop of `!mapper` records only |

These commands follow that leftover without widening the driver:

```text
!payload <address|symbol> [/disasm <n>] [/json <path>]
!payload scan [/limit <n>] [/disasm <n>] [/json <path>]
!mapper [all|unloaded|piddb|cihash] [/limit <n>] [/json <path>]
!kpage [/deep] [/wx] [/pe] [/session|/nosession] [/limit <n>] [/json <path>]
```

1. `!payload <addr>` translates the VA, looks it up in `SystemBigPoolInformation`,
   probes for an intact or signature-wiped PE header, and disassembles the first
   instructions. Use this on a `<non-image>` hook pointer from `!callbacks`,
   `!ssdt`, `!idt`, `!nmi`, `!wfp`, or `!driver integrity`.
2. `!payload scan` collects those unbacked hook pointers first, then traces each
   unique address. A failed hook surface is a coverage warning, not a clean miss.
   Default `/limit` is 16 unique addresses. A quiet scan does not prove orphan
   pages are unused.
3. `!mapper` walks `nt!MmUnloadedDrivers`, `nt!PiDDBCacheTable`, and
   `ci!g_KernelHashBucketList`. This is the bookkeeping-remnant layer for a
   driver that was actually loaded. Range overlap with a live image is `REUSED`
   or `RELOAD`, not `STILL-X`. Names explained by the unload log or `dump_*`
   are `EXPECTED` and omitted from default output. Other missing names are
   `STALE`. Wiped names, a zero TimeDateStamp, or an unloaded range that is
   still present+executable and not reused are `SUSPICIOUS`. `!unloaded` /
   `!piddb` / `!cihash` are aliases. Missing symbols fail closed. Stock
   kdmapper ledger wipe is expected to print `leftover=0`.
4. `!kpage` walks the kernel half of the live CR3 page tables and reports
   executable leaves outside every loaded module. This is the orphan-page
   layer that can still see a wiped kdmapper payload. `/pe` keeps PE-like
   regions. `/deep` adds a capped `MmPfnDatabase` pass and is not the default.
   `!snapshot` stores `leftover-mapper` only; it does not run `!kpage`.

```text
knkd> !byovd scan
knkd> !mapper
knkd> !kpage /wx /pe
knkd> !payload scan
knkd> !pool pe /suspicious
knkd> !kpage /deep /nosession
```

## Minifilter IRP control

A helper minifilter can sit on `IRP_MJ_CREATE` / directory / set-info and
interfere with an anti-cheat file path. `!minifilter` walks
`fltmgr!FltGlobals` with PDB `_FLT_OPERATION_REGISTRATION` offsets and can
null one slot or every registered slot. No new driver IOCTL; writes go
through the existing virtual-write path after `write on`.

```text
!minifilter [list] [/json <path>]
!minifilter show <name|address> [/json <path>]
!minifilter irp <name|address> <IRP_MJ_*> [/json <path>]
!minifilter disable <name|address> <IRP_MJ_*|all> [/pre|/post|/both]
!minifilter enable <name|address> <IRP_MJ_*|all> [/pre|/post|/both]
!minifilter disable-all <name|address> [/pre|/post|/both]
!minifilter enable-all <name|address> [/pre|/post|/both]
```

1. `list` / `show` / `irp` are read-only. `!fltmgr` is an alias.
2. `disable` NULLs the selected Pre/Post and keeps the original pointers in
   this session. `enable` restores that backup only.
3. `disable <name> all`, `disable *`, `disable every`, `disable IRP_MJ_ALL`,
   and `disable-all` walk every registered slot. Already-null slots are
   skipped. A later slot failure does not undo earlier writes; the command
   fails only when nothing changed.
4. `enable-all` restores every same-session backup and skips slots this
   session never disabled. It fails closed when this session has no backup
   for that filter.
5. Ambiguous filter names fail closed. Inbox names such as `WdFilter` warn
   and are not blocked. Do not disable inbox filters on a production box.
6. JSON schemas are `kn-live-dbg.minifilter.v1`,
   `kn-live-dbg.minifilter-irp.v1`, and `kn-live-dbg.minifilter-irp-batch.v1`.
   MCP write tool is `minifilter.set_irp` with `irp=all` for the batch path.

```text
knkd> !minifilter
knkd> !minifilter show UnionFS
knkd> write on
knkd> !minifilter disable UnionFS all
knkd> !minifilter disable-all UnionFS
knkd> !minifilter enable-all UnionFS
```

## Threat-Intelligence ETW (`!ti`)

`!ti` subscribes to **Microsoft-Windows-Threat-Intelligence** (provider GUID `f4e1897c-bb5d-5668-f1d8-040f4d8dd344`), the kernel-side ETW provider that EDRs use for sensitive events: `VirtualAlloc` with W+X, cross-process `WriteVirtualMemory`, `QueueUserAPC`, `SetThreadContext`, image-load triggers, driver-object operations, and similar. The provider gates its events on the consumer being a **PPL Antimalware** process, so the typical flow is:

```text
knkd> write on                           # arm driver write mode (acknowledge gate)
knkd> set-ppl-antimalware                # flip self _EPROCESS.Protection to 0x31
knkd> !ti start /name foo.exe            # subscribe; live output only for foo.exe
knkd> !ti watch                          # live tail (Esc or Ctrl+C to detach)
```

Default behaviour is **silent forensic mode**: the in-memory ring (1M events, ~256 MB) and the JSONL log (`ti-events-<timestamp>-<ms>-<pid>.jsonl`, 100 MB rotation × 10) capture every received event, but nothing scrolls the TUI until either `/pid`/`/name` is supplied (which auto-promotes matching events to live output) or `!ti watch` is invoked. Note that `!ti watch` with **no** filter set turns into a firehose because the matcher treats "empty watch set" as "match everything" — add `/pid`/`/name` first on a busy system. Subscription is torn down automatically on hard exit (window close / logoff / system shutdown) via the console control handler, in addition to the normal dtor path on Ctrl+C and `exit`.

Architecture:

1. The subscriber creates an own ETW session via `StartTraceW` and enables the TI provider with `EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, MatchAnyKeyword=0)` so every task ID surfaces, including keyword-0 `AllocVM` events. Do not use `~0` / `0xFFFFFFFFFFFFFFFF` here: that mask skips keyword-0 tasks.
2. A worker thread runs `ProcessTrace` and receives events through `EventRecordCallback`. Per-PID image resolution is cached (16K-entry bounded) so the hot path does not churn `OpenProcess`/`QueryFullProcessImageNameW`.
3. Each event is decoded via TDH (`TdhGetEventInformation` + `TdhGetProperty`) with array indexing and struct-property guarding. Properties TDH cannot decode fall back to a raw-hex prefix in the JSONL `raw` field.
4. Events are pushed into the ring buffer (oldest-evicted-first when full) and written to the JSONL log. The log rotates by file size with index wrap and oldest-file deletion -- it never grows past `LogRotateBytes * LogRotateCount` on disk.
5. Live output uses a separate bounded queue with a per-second throttle counter; over-throttle events are dropped from the live queue but still hit ring + log, and a `[ti.throttle] suppressed N events` line surfaces in `!ti watch`.

Watch matching is lazy: image-name targets compare against the basename of `_EPROCESS.ImagePath`. Processes that did not exist at `!ti start` time are picked up as soon as their first event arrives; once matched, the PID is promoted into a fast O(1) set so subsequent events for the same process never re-scan the name list.

JSONL line schema (one event per line):

```json
{
  "ts": "2026-05-24T06:30:01.123Z",
  "pid": 4567, "tid": 7890,
  "image": "C:\\path\\to\\foo.exe",
  "task_id": 1, "task": "AllocVM",
  "opcode": 0, "level": 4, "keyword": "0x0",
  "version": 0,
  "payload": { "TargetProcessId": "1234", "BaseAddress": "0xffff...", "RegionSize": "4096", "ProtectionMask": "0x40" }
}
```

Subcommand reference:

- `!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]` -- begin subscription. Repeatable `/pid`/`/name`. Default throttle 50/s, ring 1M, log directory next to KnLiveDbg.exe.
- `!ti stop` -- end subscription. Ring and log files are retained.
- `!ti status` -- live counters: received / kept / dropped / self-excluded / watch-matched / logged / log-bytes / rotations.
- `!ti add /pid <PID>` or `!ti add /name <imageName>` -- extend watch set without restarting subscription.
- `!ti remove /pid <PID>` or `!ti remove /name <imageName>` -- drop watch target. Removing a name clears the promoted-PID set so it can be rebuilt lazily.
- `!ti watch` -- interactive live tail. Throttled at the configured rate. Press Esc, `q`, or Ctrl+C to detach. Live-output preference is restored after exit so a subscriber that started silent goes back to silent.
- `!ti recent [N]` -- print the last N events from the ring (default 50, capped at 10000).
- `!ti stats` -- histogram by task name and by image basename, computed in place without copying the ring.
- `!ti by pid <PID>` / `!ti by task <substr>` -- ring filter.
- `!ti grep <pattern>` -- case-insensitive substring match across image / task / payload field values.
- `!ti save <path>` -- export the current ring snapshot to JSONL. The snapshot is taken under the ring lock then the disk write happens unlocked so the ETW callback is not stalled.
- `!ti clear` -- empty the ring (does not stop subscription or close the log).

Notes:

- The driver's MDL probe-and-lock fallback (introduced in v0.0.6) is opt-in and now guarded by canonical-system-range plus resident-page preflight, so broad scanners do not page in arbitrary pointer candidates.
- KnLiveDbg.exe's own events are excluded by default to prevent feedback loops. The exclusion is keyed on the current process ID at subscribe time.
- The provider is verbose. On an active desktop, expect thousands of events per second. The ring + log capture everything; the TUI stays calm unless you opt in to live output.

### Usage Recipes

The full prerequisite chain runs the driver, makes the TUI a PPL Antimalware consumer, then subscribes to the provider:

```text
# from an elevated shell
sc query KnLiveDbg       # confirm the driver is loaded
KnLiveDbg.exe            # launches the TUI in this elevated shell

knkd> write on           # arm driver write mode (required by set-ppl-antimalware)
knkd> set-ppl-antimalware    # flip own _EPROCESS.Protection to 0x31
knkd> !ti start          # subscribe (silent forensic mode by default)
```

After this, every event lands in the in-memory ring (1M events) and the JSONL log under the EXE directory. **Capture is automatic once `!ti start` succeeds** -- you do not need `!ti watch` to record events. Use the recipes below depending on whether you want to observe events live, or just collect them for post-hoc analysis.

> **`!ti watch` is optional.** It is purely a real-time scroll of matching events to the TUI. The ring + log capture happens regardless. If you are setting up an unattended capture, or you intend to analyse the JSONL externally with jq/ripgrep, you never need to run watch.

#### 1) Silent forensic mode -- "log everything, scroll nothing"

```text
knkd> !ti start
[ti] subscribed to Microsoft-Windows-Threat-Intelligence (all tasks)
     log directory=...  ring=1048576 throttle=50/s
     watch: <none> (silent forensic mode; use '!ti watch' for live tail)

# ... run workload, do other commands, etc ...

knkd> !ti status
knkd> !ti recent 100
knkd> !ti stop
```

The TUI stays usable for other commands while the ring + log fill. Inspect the ring or the JSONL log offline.

#### 2) Watch a known PID

```text
knkd> !ti start /pid 1234
[ti] subscribed to Microsoft-Windows-Threat-Intelligence (all tasks)
     watch: pid=1234
     live output: enabled for matching events (throttled).

# events from pid 1234 stream live; press Esc to leave watch mode
```

Hex PIDs also accepted: `!ti start /pid 0x4D2` (same as 1234).

#### 3) Watch a name that has not started yet -- malware sandbox

```text
knkd> !ti start /name suspicious.exe
[ti] ...
     watch: name=suspicious.exe

# launch the sample in another terminal
> suspicious.exe

# events appear the moment the sample's first ETW event arrives.
# The match works because watch is lazy on the image basename, not the PID.
```

This is the typical sandbox flow: subscribe first, then detonate.

#### 4) Watch by name AND PID -- multiple targets

```text
knkd> !ti start /pid 1234 /name foo.exe /name bar.exe
```

Repeatable `/pid` and `/name`. PID matches go through an O(1) set; name matches scan the (small) name list once, then the matched PID is auto-promoted into the same fast set for subsequent events.

#### 5) Add or remove targets without restarting the subscription

```text
knkd> !ti start             # silent mode
knkd> !ti add /pid 5678     # later, decide to track 5678 live
knkd> !ti add /name dropper.exe
knkd> !ti remove /pid 5678
knkd> !ti remove /name dropper.exe
```

`add` automatically promotes events to the live queue (if live output is on). Removing a name clears the promoted-PID set so the lazy re-match rebuilds.

#### 6) (Optional) live tail an existing subscription

`!ti watch` is purely for real-time observation. It does not start or stop capture -- the ring and log are filling either way.

```text
knkd> !ti start             # silent, no targets, capture is already running
# ... time passes, you want to look at activity ...
knkd> !ti watch
[ti.watch] live tail engaged. press Ctrl+C or Esc to detach (subscription stays up).
[06:42:11.123] AllocVM      pid=4567 image=foo.exe {...}
[06:42:11.456] WriteVM      pid=4567 image=foo.exe {...}
...
[ti.throttle] suppressed 87 events in the last window
# press Esc -> live output preference restored to the pre-watch value
knkd> !ti status
```

`!ti watch` temporarily enables live output for every event (subject to throttle), and `Esc`/`q`/`Ctrl+C` restores the previous live-output setting. Silent subscribers go back to silent after watch exits.

If you never want live scroll, you never have to run `!ti watch`. Use `!ti recent`, `!ti by`, `!ti grep`, `!ti save`, or jq on the JSONL log instead.

#### 7) Reduce noise or expand cap -- throttle adjustment

```text
knkd> !ti start /name chrome.exe /throttle 200      # 200 events/s cap for chrome
knkd> !ti start /name chrome.exe /throttle 5        # very quiet, scannable by eye
```

The ring + log are unaffected; throttle only gates the live print queue.

#### 8) Bigger ring for long-running captures

```text
knkd> !ti start /ring 0x400000   # 4M events (~1 GB RAM)
```

`/ring` accepts hex or decimal. Default 1M (~256 MB). Each ring event holds wide-string fields so memory cost scales with the average payload size.

#### 9) Custom log directory

```text
knkd> !ti start /log "D:\hunts\session-001"
```

The directory is created on demand. Filenames are `ti-events-YYYYMMDD-HHMMSS-mmm-PID.jsonl` for the active file and `ti-events.<N>.jsonl` for rotated slots. Rotation wraps at 100 MB x 10 by default, deleting the oldest before overwriting.

#### 10) Query the ring after the fact

```text
knkd> !ti stop                       # stop subscription, ring + log are preserved
knkd> !ti recent 200                 # last 200 events, newest first
knkd> !ti stats                      # histogram by task and by image basename
knkd> !ti by pid 1234                # ring filter on a specific PID
knkd> !ti by task AllocVM            # ring filter (substring) on task name
knkd> !ti by task WriteVM            # cross-process write events
knkd> !ti by task ProtectVM          # protection-change events
knkd> !ti grep TargetProcessId       # case-insensitive grep across payload
knkd> !ti grep 0x140000              # look for image-base loads
```

`recent` is capped at 10 000 to keep the TUI responsive. `by` / `grep` cap at 200 matches per call.

#### 11) Export a snapshot to a separate file

```text
knkd> !ti save D:\hunts\session-001\snapshot.jsonl
[ti.save] wrote D:\hunts\session-001\snapshot.jsonl
```

The snapshot uses the same JSONL schema as the rotated log. Useful for capturing the current state without waiting for log rotation. Ring lock is released before the disk write so the ETW callback is not stalled.

#### 12) Clear the ring (start fresh without restarting subscription)

```text
knkd> !ti clear              # ring drained; log untouched
```

#### 13) Process injection hunt -- end-to-end

`/name target.exe` catches **both** sides: events the target itself fires AND cross-process operations (`VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`, `SetThreadContext`, ...) fired BY a loader against the target. The matcher walks the payload for `TargetProcessId`-like fields, resolves the basename of the referenced PID through the same cache the callback uses, and matches against `/name`. So you see "loader -> target" injections without having to know the loader's name in advance.

Two valid flows. Pick based on whether you want to watch events live or just collect a trace for offline analysis.

**A. Offline / unattended capture (no watch):**

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name target.exe          # capture begins; nothing scrolls

# in another terminal, run the loader:
> loader.exe target.exe

# back in the TUI, query the ring at any point. Live tail not required.
knkd> !ti status
knkd> !ti by task WriteVM         # cross-process writes into target.exe
knkd> !ti by task SetThreadContext
knkd> !ti by task QueueUserApc
knkd> !ti save .\injection-trace.jsonl
knkd> !ti stop
```

**B. Interactive triage (live watch):**

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name target.exe
knkd> !ti watch                            # live tail; same ring + log fills

# in another terminal, run the loader:
> loader.exe target.exe

# events scroll in the TUI as they fire. Press Esc to detach when done.
knkd> !ti by task WriteVM
knkd> !ti save .\injection-trace.jsonl
knkd> !ti stop
```

Both flows produce the same `injection-trace.jsonl` and the same ring contents. The JSONL has one line per event, jq/ripgrep friendly:

```bash
# from PowerShell / cmd:
type .\injection-trace.jsonl | findstr WriteVM
# or with jq if installed:
jq -c 'select(.task=="WriteVM") | {ts, pid, image, payload}' injection-trace.jsonl
```

#### 13.5) Game-cheat alloc into a victim -- cheatengine -> notepad

The classic ETW demo: open notepad, attach Cheat Engine to it, perform `VirtualAllocEx(notepadPid, ..., PAGE_EXECUTE_READWRITE)`.

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name notepad.exe
knkd> !ti watch                # optional; events also flow to the ring and log

# in a separate shell:
> notepad.exe
> cheatengine.exe -> attach to notepad -> allocate executable buffer

# expected event in the live tail (line wrapped here for readability):
[12:07:27.073] KERNEL_THREATINT_TASK_ALLOCVM
  pid=4892 tid=2968 image=cheatengine.exe
  -> target=notepad.exe(pid=8804)
  {CallingProcessId=4892, ..., TargetProcessId=8804,
   BaseAddress=0x..., RegionSize=4096, ProtectionMask=0x40, +5 more}
```

The header shows `image=cheatengine.exe -> target=notepad.exe(pid=8804)` because the matcher caught the target-side reference even though the ETW event itself fired from Cheat Engine's PID.

#### 14) Cross-process W+X allocation hunt (no watch needed)

```text
knkd> !ti start                       # silent, full capture, no live scroll
# ... run / wait for the suspicious workload ...
knkd> !ti by task AllocVM             # all VirtualAlloc-class events
knkd> !ti grep ProtectionMask=0x40    # PAGE_EXECUTE_READWRITE (RWX)
knkd> !ti save .\wx-trace.jsonl
```

This recipe explicitly skips `!ti watch` -- the silent ring fills in the background while you keep the TUI free for `!pool` / `!pool pe` to chase the resulting allocation in big pool.

#### 15) Cleanup at session end

```text
knkd> !ti stop                  # end ETW subscription, keeps ring + log
knkd> !ti save .\session.jsonl  # optional export
knkd> !ti clear                 # optional drop the ring (frees ~256 MB)
knkd> exit                      # destructor double-checks the session is torn down
```

`exit` (or process termination) also calls the subscriber destructor which invokes `Stop` if the session is still active, so a forgotten `!ti stop` is recovered automatically.

#### Useful task names for `by task` filtering

The provider exposes many task IDs; the most actionable for malware / cheat hunting are:

| Task name (substring OK) | What it captures |
|---|---|
| `AllocVM` | `NtAllocateVirtualMemory` (incl. cross-process via `pid != self`) |
| `ProtectVM` | `NtProtectVirtualMemory` (often the W+X pivot for shellcode) |
| `MapView` | `NtMapViewOfSection` |
| `WriteVM` | `NtWriteVirtualMemory` (classic cross-process injection) |
| `ReadVM` | `NtReadVirtualMemory` |
| `QueueUserApc` | Cross-thread / cross-process APC injection |
| `SetThreadContext` | RIP redirection on a remote thread |
| `Suspend` / `Resume` | Cross-process thread control |
| `Driver` | Driver-object operations |
| `LdrPreload` | LDR-data preload trigger |

Combine with `!ti by task <name>` for filtered ring listings or `!ti grep <name>` for fuzzier searches.

Cross-process events (`AllocVM`, `ProtectVM`, `WriteVM`, `ReadVM`, `MapView`, `QueueUserApc`, `SetThreadContext`, `Suspend`/`Resume`) carry a `TargetProcessId` payload field; `/name <victim>` matches them via the resolved target basename, so a loader injecting into `notepad.exe` is caught by `/name notepad.exe` even though the event fires from the loader's PID. The live-tail header surfaces this as `image=loader.exe -> target=notepad.exe(pid=...)`.

#### Common gotchas

- **Forgot `write on` before `set-ppl-antimalware`**: the driver IOCTL returns `STATUS_ACCESS_DENIED`. Fix: `write on` first.
- **Forgot `set-ppl-antimalware` before `!ti start`**: the pre-check refuses with a clear hint pointing at `set-ppl-antimalware`. Fix: run it, retry.
- **Tried to scroll the prompt while in `!ti watch`**: keystrokes are captured by the watch loop and swallowed. Press `Esc`/`q` first to detach.
- **Same name run multiple times**: each launch gets a new PID, name match auto-promotes each one. Use `!ti by pid <PID>` to disambiguate after the fact.
- **`/name not.exe` does not match `notepad.exe`**: name matching is exact basename, not substring. Use `!ti grep not` for substring search over the ring.
- **`!ti watch` with no filter floods the TUI**: empty watch set means "match everything", so on a busy system the throttle (50/s by default) is constantly engaged and the `[ti.throttle] suppressed N events` banner dominates. Add `/pid` or `/name` filters before watching, or raise the throttle with `/throttle`.
- **Forgot `!ti stop`?** The subscriber's destructor calls Stop on normal exit (`exit`, Ctrl+C), and the console control handler calls Stop on hard exit (window close, logoff, shutdown). A clean teardown happens in every path except `TerminateProcess`. After a TerminateProcess, recover with `logman stop KnLiveDbg-Ti -ets`.

## Kernel-cheat monitor (`!kmon`)

`!kmon` is a session on top of `!ti` and `!timeline live`. It does not open a second TI provider. The cheat `.sys` name is not an input. Bare `!kmon` (or `!kmon start`) arms collectors and stays on the live tail.

```text
knkd> write on
knkd> !kmon
```

Esc/q returns to `knkd>`; collection keeps running. `!kmon` again reattaches. `!kmon watch` is only a reattach alias. `/background` (alias `/nowatch`) arms without occupying the prompt. `!kmon stop` leaves TI and timeline live running.

Watch set:

- `add` / `remove` `/pid` `/name` `/driver` only while collecting. A pre-start `add` is refused.
- A later `!kmon` / `!kmon start` with `/pid` `/name` `/driver` extends watches rather than replacing the collector. `/verbose` and `/log` apply only on the first start.
- `/driver` is highlight-only and never hides unknown drop names.
- `/name game.exe` / `/pid` add overlay-style `inject.remote` (overlays/AC can be noisy). Builtin-to-builtin and drop-path inject already match without those flags.

Default output is not every normal action and not the TI firehose:

- Shown: `driver.drop_load`, `driver.short_lived`, `driver.mapped_residue` (`layer=pool_pe` / `driver_object` / `orphan_page` / `orphan_wx` / `byovd` plus leftovers), `hook.unbacked` (`layer=callback` / `input` / `dispatch` / `ssdt` / `idt` / `msr` / `hal` / `wfp` / `dpc` / `minifilter`), `process.hidden` (ActiveProcessLinks vs SPI/Toolhelp vs handle owners vs CID), `process.masquerade` (Windows-named image from a non-inbox path), `process.hollow` (PEB ImageBase EXE replace: `exe_unmapped` / `exe_private` / `exe_unbacked` / `exe_mapped_path` / `exe_wx` / `exe_no_mz` / `exe_arch` / `hollow` stamp-section, `exe_cow` / `exe_text` / `exe_text_page` / `exe_ep` for Windows builtins, `exe_peb_base`, extra PE `exe_orphan_private` / `exe_orphan_image`, `ghost`), `process.implant` (`drop_module` or `builtin_foreign_module`), `inject.remote` into/from Windows builtins or drop-path callers, `integrity.ci` (DSE off only), `integrity.cr`, `process.syscall_unnamed`, `gap.kernel_rw` once.
- Hidden: inbox `System32\drivers` loads, process create, local AllocVM, kernel `MmCopyVirtualMemory` / `DeviceIoControl`. Test-signing is not `integrity.ci`.
- Reloc-aware `.text`/EP vs disk and COW overwrite run only for Windows builtin leaves, because third-party games/AC packers otherwise firehose `exe_text`. Empty `PsLoadedModuleList` is fail-closed so hook/pool scans do not treat every pointer as unbacked.
- Extra PE outside the module list (`exe_orphan_private` / `exe_orphan_image`) needs an executable region. Read-only `LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE)` views left by icon/version readers are skipped; unlinked or manually mapped images still fire through their RX text sub-region.
- Scan cadence: hidden ~5s, mapper/hooks/pool PE ~8s, kpage/CPU hooks ~20s, user-mode hostility ~8s. The first ticks are delayed so TI ingest is not stalled at start.
- A quiet idle host is mostly silent after the start line. Game launch can print a handful of Program Files anti-cheat drivers (EAC/BE/Vanguard); that is expected.

Lab fixture `KnLiveDbgKmonTarget.exe` (`docs/KMON_TEST_TARGET.md`) only mutates copies of itself under `%TEMP%\kn-live-dbg-kmon\` (named `notepad.exe` so builtin layers fire). It does not inject into inbox `notepad.exe` / `svchost.exe` and never resumes a replaced image. `KnLiveDbg.exe --self-test console` includes `kmon-artifact-primitives` (no driver).

## Positive-Control Probe

`KnLiveDbgProbe.sys` is an optional test driver that exposes a deterministic 4 KB contiguous nonpaged buffer and registers a test firmware table provider with signature `KNFW`. It is intended for smoke tests of virtual reads, VA-to-PA translation, physical reads, physical writes, firmware-table provider detection, and restore flows without guessing at arbitrary kernel memory.

```text
probe load
probe status
probe info
db <probe-virtual-address> 40
pdb <probe-physical-address> 40
probe reset
probe unload
```

The buffer pattern is `(index * 13 + 0x5a) & 0xff`. `probe info` prints both the virtual and physical buffer addresses, firmware provider registration status, and example `db`/`pdb`/`!fwtable` commands. After `probe load`, `!fwtable provider KNFW` should report `KnLiveDbgProbe.sys` as a suspicious nonstandard provider; `probe unload` unregisters it.

## Operational Caveats

1. This is a live kernel memory tool. Bad writes can crash or corrupt the machine.
2. `MmCopyMemory` makes reads fault-tolerant, but it does not make all addresses meaningful.
3. Writes are enabled by default, can be disabled with `write off`, and still require an IOCTL acknowledgment magic.
4. Native VA-to-PA translation supports x64 4-level paging and active LA57 five-level paging, and reports which paging depth was used for each walk.
5. Physical memory writes can corrupt page tables, code, pool, device memory, or firmware-owned ranges.
6. Type dumping depends on matching PDBs and the local `DbgHelp`/DIA behavior.
7. Callback enumeration depends on internal kernel symbols and type names. Field drift is reported as a warning; Filter Manager callback decoding depends on matching `fltmgr` private type layouts.
8. Do not hard-code kernel structure offsets for production use; resolve them from symbols at runtime.
9. Live loading requires test-signing or another valid code integrity path.
10. Native mode intentionally differs from full WinDbg for commands that stop or control the target. Use `backend dbgeng` for DbgEng-backed command execution, and still expect local-kernel debugging limitations.
11. `!wfp` requires a healthy Base Filtering Engine (`BFE`) service for the user-mode `FwpmEngineOpen0` path; it does not enumerate WFP state from a hung BFE or a dead system, and it does not surface kernel-mode callout function pointers because the user-mode `FWPM_CALLOUT0` shape does not expose them.
12. `!alpc` enumerates only ports reachable through the Object Manager namespace and through `_ALPC_PORT.CommunicationInfo` linkage; anonymous client ports that never reach a named server port are not enumerated, and queue counts depend on PDB exposure of the per-port `MainQueue`/`PendingQueue`/`LargeMessageQueue`/`CanceledQueue`/`WaitQueue` fields. PDB drift in `_ALPC_PORT` may produce a warning and reduce the field set rather than aborting the scan.
13. `!vbs` / `!ci` / `!securekernel` rely on `nt!g_CiOptions`, `nt!HvlpVsmVtlCallVa`, and `_KPROCESS.SecureState`. The exact symbol names drift across Windows builds, the trustlet bit field is private PDB territory, and MBEC enablement requires kernel-only MSR reads. The report annotates each missing source as a warning and falls back to well-known trustlet image-name prefixes when the secure-state field cannot be resolved.
14. `!etw` falls back to documented offsets `0x68` (LoggerName) and `0x28` (GetCpuClock) when `_WMI_LOGGER_CONTEXT` is not exposed in the loaded PDB. Those offsets drift between Windows builds; a warning is emitted on the fallback path. `!nmi` requires `nt!KiNmiCallbackListHead` (or `nt!KiNmiCallbackList`) to be resolvable from the PDB; if both fail, signature-based extraction from `KeRegisterNmiCallback` is not yet implemented and the scanner reports the resolution failure as an error.
15. `!fwtable` requires `nt!ExpFirmwareTableProviderListHead` to be resolvable. If private provider-node types are absent, it scores guarded x64 fallback candidates against live nodes and normally selects the `SYSTEM_FIRMWARE_TABLE_HANDLER`-fields-first layout (`ProviderSignature +0x00`, `Register +0x04`, `FirmwareTableHandler +0x08`, `DriverObject +0x10`, `LIST_ENTRY +0x18`). It flags handler addresses outside loaded kernel images and DriverObject owners whose `DriverStart` is unreadable, null, or outside loaded modules. It intentionally does not probe table IDs or call `EnumSystemFirmwareTables` / `GetSystemFirmwareTable` by default because those paths can execute registered provider handlers.
16. `!wnf` live walking depends on the loaded PDB exposing `nt!ExpWnfSiloState` (or alias), an AVL-table field on `_WNF_SUBSCRIPTION_TABLE`/`_WNF_SILODRIVERSTATE`/`_WNF_PROCESS_CONTEXT`, and `_WNF_NAME_INSTANCE.StateName`. Modern Win10/11 PDBs sometimes withhold these private types; when missing, the scanner clearly identifies the missing piece and the `decode` subcommand remains fully functional. `!wnf data` follows `LastDataBlock` and probes common buffer offsets, so a returned payload should still be treated as advisory until the WNF state data layout for that specific build is verified.
17. On Windows builds where Microsoft has migrated WNF subscription tracking away from `RTL_AVL_TABLE` (or moved it into a per-process `_WNF_PROCESS_CONTEXT`), the legacy AVL chain returns zero candidates. The modern LIST_ENTRY heuristic walker handles these builds by enumerating `_WNF_NAME_INSTANCE` chains hanging off the silo state struct, scoring each list by the count of UNIQUE state-name-shaped values, and walking the top-ranked list. The `decode` subcommand remains a fully-working day-to-day utility regardless.
18. **`!wnf` state-name slot in LIST_ENTRY mode is currently transient -- known open issue.** On the modern Win11 layout the walker extracts state names from the first `0x000001030000XXXX` (WNF schema-marker) value found in `+0x10..+0x38` of each `_WNF_NAME_INSTANCE` entry. The 0x103 prefix is correct, but the specific slot we hit is not the canonical immutable state name: re-reading the same entry address returns different values across runs (even for `Permanent` lifetimes that should never change). The data block reference at `+0x88` and the entry address itself are stable; only the printed `state=` field drifts. Open follow-up: reverse-engineer the canonical state-name offset within the modern `_WNF_NAME_INSTANCE` layout (likely past `+0xC0`) and switch extraction to that fixed slot, which will also make symbolic-name DB lookups (Ionescu wnfdump etc.) actionable. Until that lands, prefer entry addresses for stable lookup and `!wnf data` for payload investigation.
19. `!wnf data` on the LIST_ENTRY path heuristically locates the `_WNF_DATA_BLOCK` descriptor by scanning the first `0x200` bytes of the matched entry for kernel-canonical pointers whose dereferenced 16-byte header matches the documented `_WNF_DATA_BLOCK` layout (`DataSize @ +0x00`, `AllocatedSize @ +0x04` with `DataSize <= AllocatedSize` and `AllocatedSize <= 0x1000`, `ChangeStamp @ +0x08` UINT64). The slot is consistently at entry `+0x88` on the Win11 builds tested so far, but the walker probes adaptively and emits a per-pointer census diagnostic when no candidate validates so operators can manually identify the slot on different builds. `AllocatedSize` is treated as the user-requested size (not pool-aligned), so no alignment assumption is enforced.
20. `!wnf` subscriber and owning-process resolution has converged on a working multi-layer view. Each `_WNF_NAME_INSTANCE` exposes a LIST_ENTRY chain at entry `+0x48`; field testing established that this chain is NOT a subscription-only list but a generic per-entry tracked-objects list mixing real WNF subscription records with other process-scope kernel objects (Section / NTFS / SeAt / AlVi / AlRe / PnpY / ObNm / CMNb / DCxx / APpt / DxgK / SLS / Ustm / PcwC / ClfA / SeSd / RvaL / ...). The walker (a) extracts each node's pool tag from `nodeBytes[+0x14]` (POOL_HEADER sits at `+0x10`), (b) classifies nodes by tag (`Ntfc` / `Wnf ` / `WnfN` = real subscriber; everything else = backing/related kernel object), (c) resolves the entry's stable owning EPROCESS from the prefix slot at `node-0x30` (100% recovery rate on entries with at least one chained node in field testing), and (d) attempts shape-only EPROCESS resolution for individual nodes via PDB-resolved `_EPROCESS.UniqueProcessId` (must be 4-aligned, `0 < pid <= 0x100000`) AND `ImageFileName` (must be `>= 3` printable-ASCII chars). Node candidates whose pointer falls within `0x200` bytes of the node itself are rejected to suppress same-chunk false positives. The listing path (`!wnf instances`) prints `chained_nodes=N subscribers=X resolved=Y other_objects=Z tags={Ntfc:N Wnf:N Sect:N ...}` per entry and emits only resolved subscriber lines underneath; single-entry views (`!wnf instance`, `!wnf data`) still print every chained node plus prefix/body hex dumps for deeper RE. Open follow-up: some `Ntfc` / `Wnf ` nodes still fail EPROCESS resolution because their per-record subscriber pointer lives outside the first `0x80` bytes -- the full `_WNF_NAME_SUBSCRIPTION` layout (DeliveryEvent / ContextPointer / callback target slots) is still to be reverse-engineered for `pid=N image="..."` to fire on those records too.
21. `!wnf` symbolic state-name lookup is not yet wired up. With the canonical state-name slot still under investigation (caveat 18), the printed `state=` field reflects whichever `0x000001030000XXXX` candidate the walker found in the entry head and is not yet stable across runs for the same logical state. Cross-referencing against published WNF state-name databases (e.g. Ionescu wnfdump, leaked LMK string tables) is therefore deferred until caveat 18 is closed. Once the canonical slot is locked down, the planned follow-up is to ship a static well-known-state-name table that decodes recognized state-names alongside the raw hash + lifetime/scope fields.
22. `remote on` is cleartext TCP on the lab LAN. Stolen password plus LAN reachability is kernel RW. Isolated segment only. This is not `kdinit /remote`.
