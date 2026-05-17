# WinDbg Command Coverage

This project follows the Microsoft WinDbg command reference as the command registry baseline.

Reference pages:

- `Commands`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
- `Local Kernel-Mode Debugging`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging

## Backend Rule

KnLiveDbg currently has a native live-memory backend, not a KD transport backend. This means commands fall into three groups:

1. Native
   - Can be implemented using the current driver, `DbgHelp`, and local system APIs.
   - Examples: virtual/physical memory display/write/search/compare/fill/move, VA-to-PA translation, module list, symbol lookup, type display, explicit disassembly commands.

2. DbgEng-routed
   - The command exists in the WinDbg command surface, but it needs debugger-engine parser or stop-state semantics.
   - In `auto` or `dbgeng` backend mode, these commands are routed to DbgEng.
   - Examples: execution control, breakpoints, stack walking, registers, source commands, exception commands, I/O port commands.

3. Extension commands
   - Any `!<extension>` command is recognized as an extension command.
   - In `auto` or `dbgeng` backend mode, extension commands are routed to DbgEng.

4. Meta-commands
   - Any unknown `.<command>` is recognized as a WinDbg meta-command.
   - The native backend implements `.sympath`, `.sympath+`, and `.reload`; other meta-commands are routed to DbgEng in `auto` or `dbgeng` mode.

## Backend Commands

```text
backend [auto|native|dbgeng]
kdinit [connect-options]
kd <windbg-command>
kddetach
ai [status|providers|provider|model|baseurl|effort|auth|preview|ask|plan|show|run|write|transcript|report]
```

`auto` is the default. Native commands stay on the custom driver backend, while DbgEng-routed commands and extension/meta commands are sent to DbgEng when possible.

Backend mode differences:

| Mode | Native handlers | DbgEng fallback | Typical use |
| --- | --- | --- | --- |
| `auto` | Enabled for implemented live-memory commands. | Enabled for DbgEng-routed commands, `!extension` commands, and unknown `.meta` commands. | Normal mixed operation. |
| `native` | Enabled. | Disabled except for explicitly wired commands that intentionally use DbgEng internally, such as `u` and `uf`. | Verifying driver-backed behavior without accidental raw WinDbg execution. |
| `dbgeng` | Only session/TUI exceptions run before the raw DbgEng catch-all. | Enabled for most commands through `IDebugControl4::ExecuteWide`. | WinDbg parser, stop-state, extension, breakpoint, register, stack, source, trace, and exception commands. |

The `dbgeng` catch-all intentionally excludes `q`, `qq`, `qd`, `quit`, `exit`, `unload`, `drvstatus`, `callbacks`, `kcallbacks`, `cb`, and `ai` so shutdown, service control, status, native callback scanning, and AI provider control stay under the TUI. The explicit `u`/`uf` handler also runs before that catch-all. `kd <windbg-command>` always executes a raw DbgEng command regardless of the selected backend mode.

## Native Commands

```text
?, ||, ||s, |, .sympath, .sympath+, .reload
lm, ld, ln, x
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
vtop, !vtop
phys, pdb, pdw, pdd, pdq
peb, pew, ped, peq
dt, dtx
callbacks, kcallbacks, cb
u, uf
ai
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
c, f, fp, m, s
n, sq
version, vertarget, vercommand
q, qq, qd
```

## DbgEng-Routed Commands

```text
$<, $><, $$<, $$><, $$>a<
??, #, |s, ~, ~e, ~f, ~u, ~n, ~m, ~s
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

## Implementation Notes

1. `x nt!*Mask*` is handled by splitting `module!symbol-mask` and enumerating the matching loaded kernel module.
2. `ln` resolves the input as either a number or symbol, then asks `DbgHelp` for the nearest symbol.
3. `dps`, `dqs`, and `dds` annotate pointer-like values with nearest symbols when available.
4. `dpa`, `dpu`, `dqa`, and `dqu` read a pointer value first, then display the referenced string.
5. Write commands start enabled per handle; `write off` disables the driver gate and `write on` re-enables it.
6. Single transfer size is capped by `KNDBG_MAX_TRANSFER_SIZE`.
7. Native `dt` supports layout-only output, value output when an address is supplied, recursive UDT expansion with `-rN`, verbose diagnostics with `-v`, bare output with `-b`, and field filters.
8. `vtop` and native `!vtop` translate a virtual address to a physical address using the current CR3 or a supplied directory-table base.
9. `phys`, `pdb`, `pdw`, `pdd`, and `pdq` read physical memory; `peb`, `pew`, `ped`, and `peq` write physical memory through the same write gate as virtual writes.
10. `callbacks [all|ob|registry|process|minifilter]` parses kernel PDB type layouts and live memory to list object-manager filters, registry callbacks, process creation callbacks, and minifilter callbacks with module, symbol, altitude, context, root, and object/filter address annotations.
11. Object callback scanning discovers `_OBJECT_TYPE` objects from `ObTypeIndexTable` before walking each `_OBJECT_TYPE.CallbackList`, with documented type globals used only as fallback.
12. Registry and process callback scanning enumerate candidate root symbols and validate the expected list/table shape before emitting records.
13. Minifilter scanning discovers `fltmgr!FltGlobals`, validates the frame-list root, walks frames and registered filters, and reports operation, unload, instance, name provider, KTM, section, and volume-mount callbacks. Non-exact globals candidates must produce concrete callback records before they are accepted.
14. `u <address|symbol> [instruction-count]` uses `IDebugControl::DisassembleWide` directly, prints DbgEng-quality instruction text, caps explicit counts at 256 instructions, and remembers the next offset for a following bare `u`.
15. `uf <address|symbol>` is an explicit function-disassembly command routed through DbgEng so symbol-aware function boundary discovery stays consistent with WinDbg.
16. `ai plan <prompt>` stores model-proposed commands in a parsed in-memory plan. `ai run <index|all>` executes only non-write, non-shutdown planned commands through the normal TUI dispatcher.
17. `ai write <index> confirm` is required to dispatch planned write-like commands. `ai transcript <path>` captures AI events and command output as JSONL, and `ai report <path>` exports the current AI session summary.
