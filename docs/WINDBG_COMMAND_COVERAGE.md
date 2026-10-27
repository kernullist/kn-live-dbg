# WinDbg Command Coverage

This project follows the Microsoft WinDbg command reference as the command registry baseline.

Reference pages:

- `Commands`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
- `Local Kernel-Mode Debugging`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging

## Backend Rule

KnLiveDbg has a native live-memory backend alongside DbgEng routing. Commands fall into four groups:

1. Native
   - Can be implemented using the current driver, `DbgHelp`, and local system APIs.
   - Examples: virtual/physical memory display/write/search/compare/fill/move, VA-to-PA translation, module list, symbol lookup, type display, explicit disassembly commands.

2. DbgEng-routed
   - The command exists in the WinDbg command surface, but it needs debugger-engine parser or stop-state semantics.
   - In `auto` or `dbgeng` backend mode, these commands are routed to DbgEng.
   - Examples: execution control, breakpoints, stack walking, registers, source commands, exception commands, I/O port commands.

3. Extension commands
   - Registered native `!` scanners run locally before the extension fallback.
   - Unmatched `!<extension>` commands route to DbgEng in `auto` or `dbgeng` mode.

4. Meta-commands
   - Any unknown `.<command>` is recognized as a WinDbg meta-command.
   - The native backend implements `.sympath`, `.sympath+`, and `.reload`; other meta-commands are routed to DbgEng in `auto` or `dbgeng` mode.

## Backend Commands

```text
backend [auto|native|dbgeng]
kdinit [/local [connect-options]|/remote <connect-options>]
kd <windbg-command>
kddetach
remote [on [port] [--loopback] [--bind <ipv4>] [--peer <ipv4>]|off|status|disconnect]
home|dashboard
cls
probe [status|load [sys-path]|info|reset|unload]
ai [status|use|models|save|test|config|providers|provider|policy|model|base-url|effort|auth|preview|ask|plan|analyze|explain|annotate|diagnose|playbook|show|run|write|transcript|audit|report]
```

`auto` is the default. Native commands stay on the custom driver backend, while DbgEng-routed commands and extension/meta commands are sent to DbgEng when possible.

Backend mode differences:

| Mode | Native handlers | DbgEng fallback | Typical use |
| --- | --- | --- | --- |
| `auto` | Enabled for implemented live-memory commands. | Enabled for DbgEng-routed commands, `!extension` commands, and unknown `.meta` commands. | Normal mixed operation. |
| `native` | Enabled. | Disabled except for explicit raw escapes such as `kd`. | Verifying driver-backed behavior without accidental raw WinDbg execution. |
| `dbgeng` | All native-owned commands run before the raw DbgEng catch-all. | Other commands use `IDebugControl4::ExecuteWide`. | WinDbg parser, stop-state, extension, breakpoint, register, stack, source, trace, and exception commands. |

The `dbgeng` catch-all is **native-first**: any command owned by the TUI/driver path (`IsNativeOwnedCommand`) is never sent to DbgEng. That includes session control (`q`/`unload`/`write`/`probe`/`procctx`/`backend`/`kdinit`/`mcp`/`remote`/`ai`), native memory (`d*`/`e*`/`phys`/`pe*`/`vtop`/`f`/`m`/`setfield`/`u`/`uf`/`dt`), dumps (`dump-raw`/`dump-pe`), leftover detectors (`!payload`/`!mapper`/`!kpage`/`!pool pe`), PPL (`set-ppl-antimalware`), symbols (`lm`/`x`/`ln`/`.sympath`/`.reload`), and all native bang scanners (`!hunt`/`!ti`/`!timeline`/`!ssdt`/...). Only commands outside that set are raw-executed through DbgEng. `kd <windbg-command>` always executes a raw DbgEng command regardless of the selected backend mode.

## Input validation

The local console, `--connect` client, and remote completion
requests use the same candidate and annotation tables. Type flags can be combined
before the type; integrity options are offered after their required action.

The source registry and `--self-test commands` are the current command inventory.
The [validation summary](VALIDATION.md) records measured regression results.
Dispatch/help checks for DbgEng entries do not certify the external debugger
engine or target behavior.

Native parsing rejects embedded NULs, unterminated quotes, invalid numeric suffixes/signs, overflow, and extra arguments on fixed-arity commands before side effects. Numeric inputs retain their documented radix rules, including `0x`, `0n`, and debugger address separators where supported. Listener and `--connect` ports use decimal `1..65535`. Zero-length, overflowing, and over-limit memory transfers are rejected before allocation or IOCTL dispatch.

`?` and `??` evaluate the complete spaced expression. `kd <windbg-command>` preserves the original command tail and quotes for DbgEng. `remote` remains native-owned in every backend mode. Bare `|` displays the pinned `procctx` context.

## Native Commands

```text
?, ??, ||, ||s, |, .sympath, .sympath+, .reload
lm, ld, ln, x
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
vtop, procctx
phys, pdb, pdw, pdd, pdq, !db, !dw, !dd, !dq
peb, pew, ped, peq, !eb, !ew, !ed, !eq
dt, dtx
!callbacks
!dml_proc [pid|name]
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!vad scan <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad modules <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!vad mappedpe <pid|eprocess> [/summary] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/summary] [/apc] [/stacks] [/limit <n>] [/json <path>]
!wfp [providers|sublayers|callouts|kernelcallouts|filters|layers] [/module|/layer|/provider <value>]
!alpc [ports|port|connections|queues] [/name <pattern>] [/pid <pid>]
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
!token <pid|image|eprocess> | !token /all [/limit <n>] [/system]  (privileges plus TokenType/SessionId/integrity SID)
!dpc [/verbose] [/limit <n>]
!timer [/verbose] [/limit <n>]
!workitem [/verbose] [/limit <n>]
!fwtable [providers|provider <signature>]
!fwtable providers /module <name>
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections] [/wx] [/mismatch] [/disk] [/iat] [/prologue] [/limit <n>] [/json <path>]
!driver list [driver|all] [/limit <n>] [/json <path>]
!driver integrity [driver|all] [/limit <n>] [/json <path>]
!driver object <name|address> [/dispatch] [/devices] [/json <path>]
!drvobj <name|address> [/dispatch] [/devices] [/json <path>]
!devstack <device-object-address|driver-name> [/json <path>]
!handles [pid] [/target <pid>] [/process|/all] [/suspicious] [/limit <n>] [/json <path>]
!hiddenproc [/json <path>]
!wdfilter [/json <path>]
!inputstack [/json <path>]
!dma [/json <path>]
!hv [/json <path>]
!hunt [/quick] [/deep] [/summary] [/details] [/pid <PID>]... [/limit <n>] [/json <path>]
!byovd [scan|update|status] [/no-update] [/force-update] [/exact] [/sign|/no-sign] [/yara] [/yara-path <exe>] [/yara-timeout <seconds>] [/verbose] [/summary] [/limit <n>] [/json <path>]
!byovd fixture [status|load [sys-path]|unload|path]
!pool [big|find|tags|summary|pe] [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/addr <va>] [/limit <n>] [/nonpaged|/paged|/any] [/annotate] [/wx] [/tags]
!pool pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>] [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]
!snapshot baseline [/all] [/memory] [/name <label>]
!snapshot save <path> [/all] [/name <label>]
!snapshot show [baseline|<path>] [/domains|/no-domains] [/warnings]
!diff baseline [/memory] [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!diff <old.json> <new.json> [/memory] [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!timeline
!timeline dashboard
!timeline reset
!timeline help advanced
!timeline update [recent|all] [/limit <n>] [/snapshot] [/live]
!timeline status | clear
!timeline ingest ti [recent|all] [/limit <n>]
!timeline ingest snapshot [baseline|<path>]
!timeline live on|off|status|start|stop|clear|drain [/capacity <n>] [/limit <n>]
!timeline query [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>] [/oldest|/newest]
!timeline graph [/source <name>] [/domain <name>] [/pid <PID>] [/image <name>] [/limit <n>] [/oldest|/newest]
!timeline reconcile snapshot [baseline|<path>] [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>]
!timeline export <path> [/jsonl]
dump-raw <address> <length> <path> [/zerofill] [/pid N | /name <image>]
dump-pe <address> <path> [/pid N | /name <image>]
dump-kernel <path> [/max <bytes>] [/strict]
dump-live <path> [/user [pid|eprocess]] [/compress] [/hv]
dump-analyze <path> [/json <path>]
!payload <address|symbol> [/disasm <n>] [/json <path>]
!payload scan [/limit <n>] [/disasm <n>] [/json <path>]
!mapper [all|unloaded|piddb|cihash] [/limit <n>] [/json <path>]
!unloaded | !piddb | !cihash
!kpage [/deep] [/wx] [/pe] [/session|/nosession] [/limit <n>] [/json <path>]
!minifilter [list|show <name|addr>|irp <name|addr> <mj>] [/json <path>]
!minifilter disable|enable KnLiveDbgMiniFilterFixture CREATE [/pre|/post|/both]
!minifilter disable-all|enable-all KnLiveDbgMiniFilterFixture
!address <va>
set-ppl-antimalware [on|off|status]
!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]
!ti stop | status | watch | recent [N] | stats | by pid <PID> | by task <name> | grep <pattern> | save <path> | clear | add /pid|/name <v> | remove /pid|/name <v>
!kmon [start] [/name <image>] [/pid <PID>] [/driver <sys>] [/verbose|/all-drivers] [/background|/nowatch] [/log <dir>] [/manifest <path>] [/throttle <N>] [/layout-ms <1000..60000>]
!kmon stop | status | watch | recent [N] | save <path> | clear | add /pid|/name|/driver <v> | remove /pid|/name|/driver <v>
!kmon iotrace <driver> on | !kmon iotrace off|status
!kmon cases [/pid N] [/role name] [/json] [/save path]
!kmon surfaces <pid> [/json] [/save path] [/module-start <N>] [/handle-start <N>]
!kmon layouts [/pid N [/initial]] [/json] [/save path]
!kmon diff <before.json> <after.json> [/json]
!wnf [decode <hash>|instances|instance <hash|entry-address>|data <hash|entry-address>|candidates|lists]
help <command>, <command> help
!callbacks <scope> help
ai <subcommand> help, ai help <subcommand>
help syntax notes for native/dbgeng state tags, count units, /process/procctx, nt! kernel aliases, sparse ?? reads, and write context
u, uf
ai
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
c, f, fp, m, s
n, sq
log [enable|disable|status|on|off|start|stop]
version, vertarget, vercommand, drvstatus, home, dashboard, cls, probe
q, qq, qd
```

For scenario-based `!timeline` workflows, including TI, snapshot reconciliation, kernel live callback collection, graphing, export, and reset patterns, see `docs/TIMELINE_COMMAND_USAGE.md` and `docs/TIMELINE_COMMAND_USAGE.ko.md`.

## DbgEng-Routed Commands

```text
$<, $><, $$<, $$><, $$>a<
#, |s, ~, ~e, ~f, ~u, ~n, ~m, ~s
a, ad, ah, al, as
ba, bc, bd, be, bl, bp, bu, bm, br, bs, bsc
dg, dl, dv, dx
g, gc, gh, gn, gN, gu
ib, iw, id, ob, ow, od
j
k, kb, kc, kp, kP, kv
l+, l-, ls, lsa, lsc, lse, lsf, lsf-, lsp
p, pa, pc, pct, ph, pt
r, rdmsr, rm, wrmsr
so, ss, sx, sxd, sxe, sxi, sxn, sxr, sx-
t, ta, tb, tc, tct, th, tt, wt
up, ur, ux
z
```


## Interpretation and implementation

Use [the command guide](COMMAND_REFERENCE.md) for workflows, [architecture](ARCHITECTURE.md)
for source/lifetime contracts, and [validation status](VALIDATION.md) for measured
results. Help and completion are maintained in the command registry and dispatcher.

`!hunt` output includes `kernel_main_section_swap_evidence`,
`process_tampering_primitive_evidence`, `module_stomping_permission_evidence`,
and `security_tool_communication_blocking`. These describe different observed
conditions; names and permissions alone are not proof of process tampering.
ESET-published Gentlemen/OxideHarvest SHA-1 IoCs are exact-file evidence,
separate from name/path hints and the benign fixtures. See [hunt controls](HUNT_TEST_TARGET.md).

External callback pointer replacement is unavailable. `!callbacks` and
`!minifilter` mutation select only the cooperative fixture's supported CREATE
bodies; `all` does not expand that target. Experimental raw I/O interposition
has separate [lifetime limits](DRIVER_INTERACTION_TRACKING_DESIGN.md).
