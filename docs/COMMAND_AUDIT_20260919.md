# Command audit: 2026-09-19

Base: `841d14893eb46654f8629d7e3c99ff5f6582de4d`.

The registry contains 261 entries: 151 native commands, 17 aliases and 93
DbgEng routes. Review covered native argument handling, aliases, shared
parsers, state changes, memory request boundaries, AI/MCP/remote dispatch,
file output and collector shutdown. Each registered entry is also exercised
through the real command dispatcher with help and embedded-NUL inputs.
Native commands receive an unterminated-quote regression, except `kd`, which
must preserve the debugger's raw syntax.

DbgEng routes were reviewed at the routing/forwarding boundary. Their external
implementation, extensions and stopped-target behavior were not executed in
this audit. The command corpus uses a closed driver device and an uninitialized
DbgEng backend. It does not install drivers or perform host memory mutations.

## Corrections

| Area | Failure and correction |
| --- | --- |
| Numeric parsing | Hidden signs, whitespace, embedded NUL and overflow could survive prefix stripping or CRT conversion. A shared bounded ASCII parser now rejects them without modifying the output on failure. Debugger radix prefixes and backtick separators remain supported. |
| IRP selection | Empty `0x`/`0n` and signed zero could select IRP 0. Minifilter numeric selection now requires digits. |
| Command syntax | Native unterminated quotes and NUL input are rejected before dispatch. Fixed-arity commands, collector actions, listener controls, JSON export commands and AI confirmation no longer ignore dangerous suffixes. |
| Expressions and routing | Expression evaluation now consumes all tokens; `kd` preserves quoted raw text; `remote` stays native in DbgEng mode; invalid `kdinit` syntax preserves the existing connection settings. |
| Memory ranges | Sparse reads, process memory operations and device requests reject zero/wrapping ranges. Allocation/transfer caps apply before reserve or IOCTL. Kernel translation rejects wrapping requests as well. |
| Listener options | Invalid, signed, truncated or duplicate ports and incomplete/unknown options fail before password input or listener startup. MCP and remote enforce mutual exclusion in both directions. |
| JSON | One complete, depth-bounded parser replaces substring extraction. It validates number/string/container grammar, decodes keys and rejects duplicate keys, nested-field substitution, trailing data and invalid UTF-8. |
| MCP schemas | Tool arguments follow the advertised key, required-field and type definitions, including arrays of strings. Invalid optional arguments cannot silently become defaults. |
| MCP writes | Hexadecimal byte lists are canonicalized independently of console radix. Empty patterns, invalid widths and malformed options fail before execution. Backup failure stops the write; verification errors are returned. |
| AI writes | Confirmation syntax must match exactly. Failed prewrite backup prevents execution. |
| MCP transport | Bodies are limited to 1 MiB and must finish successfully. JSON-RPC version/id and complete JSON are validated before dispatch. EOF does not consume the HTTP API's undefined byte-count output. |
| MCP queue | Timed-out pending requests are removed under the same mutex used by dequeue. Already-dispatched requests report an unknown outcome instead of claiming cancellation. Stop interrupts transport waiting without waiting for engine drain. |
| Remote queue | Pending control frames are consumed while waiting for the engine. Queued cancellation/disconnection removes the request; stop cannot deadlock behind a future that requires engine drain. |
| Remote errors/authentication | Command errors propagate as errors, including an error code when stdout is empty. Required protocol versions are checked. Constant-time password comparison retains the full length difference. |
| Collector lifetime | Quit/unload and normal cleanup stop collectors before closing the device or unloading drivers. Failed I/O-trace disarm retains the device for retry. Driver unload waits for active dispatch completion instead of freeing code after a retry limit. |
| Logging/status | Log filenames distinguish rapid toggles and processes. Wide file paths support non-ASCII executable directories. Log failures use stderr, and native process status reports the actual pinned context. |

The HTTP EOF handling follows the documented
[HttpReceiveRequestEntityBody contract](https://learn.microsoft.com/en-us/windows/win32/api/http/nf-http-httpreceiverequestentitybody).

## Validation

The review proceeded through shared parsing/lifetime checks, command-family
argument checks, then transport queue and shutdown checks. New findings were
fixed and their affected tests rerun. The closing diff review found no further
actionable issue in the reviewed paths; this is a bounded audit result, not a
proof that every command and operating-system interaction is bug-free.

| Check | Result |
| --- | --- |
| User executable, x64 Release and Debug | MSBuild passed |
| Driver, x64 Release and Debug | WDK 10.0.22621.0 build passed; signing disabled; isolated output directories |
| Registry/command integration | 261 entries; 1,988 checks passed in each configuration |
| Console / timeline / MCP catalog and queue | 524 / 28 / 75 checks passed in each configuration |
| Remote protocol, authentication, cancellation and queued stop | 52 checks passed in each configuration; local authenticated TCP fixture |
| Connection argv | 4 checks passed in each configuration |
| MCP HTTP | 9 checks passed in each configuration; includes exactly 1 MiB, over-limit rejection and subsequent recovery |
| Parser properties and malformed inputs | 275,002 checks passed in Release and Debug with AddressSanitizer and `/W4 /WX` |
| Independent JSON comparison | 20,008 generated/mutated documents matched Python's standard JSON parser with duplicate/nonfinite rejection; ASan-enabled C++ validator |
| Existing kmon core | All 7 groups passed with AddressSanitizer |
| Existing kmon manifest CLI | Native binary/PDB generation, secondary-vptr and mismatch controls passed |
| Whitespace validation | `git diff --check` passed |

Reproduce after building the requested configuration:

```powershell
.\x64\Release\KnLiveDbg.exe --self-test all
.\x64\Debug\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Sanitize
.\tools\validate-command-audit.ps1 -Configuration Debug -Sanitize
.\x64\Release\KnLiveDbg.exe --self-test mcp-http
.\x64\Debug\KnLiveDbg.exe --self-test mcp-http
.\tools\validate-kmon-core.ps1 -Sanitize
```

Run network fixtures sequentially: the remote fixture uses loopback port 51767
and the HTTP fixture uses loopback port 51768. The HTTP fixture requires rights
to register its temporary HTTP.sys URL. It is intentionally separate from
`--self-test all`. Neither fixture opens an external interface or adds a
firewall rule. `validate-command-audit.ps1` instruments the standalone parser
harness; its command integration invocation uses the normally built executable.

Kernel writes, callback/minifilter mutations, process-protection changes,
live collector load/unload races and real DbgEng targets still require the
appropriate isolated VM/hardware validation. In particular, waiting during
driver unload does not establish a general proof of safe arbitrary third-party
dispatch interposition. Those live paths were reviewed statically and compiled,
not reported as executed tests.

## Registry coverage

The inventory below records the complete audited registry. Entries sharing a
handler were reviewed together; scanner commands were traced from their options
through the existing scanner/device boundary. The automated registry sweep is
generated from `CommandRegistry::Commands()`, so later additions join the sweep.

| Registry group | Count | Commands |
| --- | ---: | --- |
| ai | 1 | `ai` |
| alias | 4 | `ad`, `ah`, `al`, `as` |
| breakpoint | 11 | `ba`, `bc`, `bd`, `be`, `bl`, `bp`, `bu`, `bm`, `br`, `bs`, `bsc` |
| code | 6 | `a`, `u`, `uf`, `up`, `ur`, `ux` |
| control | 2 | `j`, `z` |
| data-model | 1 | `dx` |
| exception | 7 | `sx`, `sxd`, `sxe`, `sxi`, `sxn`, `sxr`, `sx-` |
| execution | 20 | `g`, `gc`, `gh`, `gn`, `gN`, `gu`, `p`, `pa`, `pc`, `pct`, `ph`, `pt`, `t`, `ta`, `tb`, `tc`, `tct`, `th`, `tt`, `wt` |
| expression | 3 | `?`, `??`, `n` |
| kernel | 47 | `!callbacks`, `!dml_proc`, `!hunt`, `!vad`, `!threads`, `!wfp`, `!alpc`, `!byovd`, `!vbs`, `!ci`, `!securekernel`, `!etw`, `!nmi`, `!msrcheck`, `!cr`, `!ssdt`, `!idt`, `!hal`, `!hive`, `!token`, `!dpc`, `!timer`, `!workitem`, `!fwtable`, `!module`, `!driver`, `!drvobj`, `!devstack`, `!handles`, `!hiddenproc`, `!wdfilter`, `!inputstack`, `!dma`, `!hv`, `!ti`, `!kmon`, `!pool`, `!payload`, `!mapper`, `!kpage`, `!unloaded`, `!piddb`, `!cihash`, `!minifilter`, `!fltmgr`, `!wnf`, `so` |
| locals | 1 | `dv` |
| memory | 73 | `c`, `d`, `da`, `db`, `dc`, `dd`, `dD`, `df`, `dp`, `dq`, `du`, `dw`, `dW`, `dyb`, `dyd`, `dda`, `ddp`, `ddu`, `dpa`, `dpp`, `dpu`, `dqa`, `dqp`, `dqu`, `dds`, `dps`, `dqs`, `phys`, `pdb`, `pdw`, `pdd`, `pdq`, `!db`, `!dw`, `!dd`, `!dq`, `procctx`, `peb`, `pew`, `ped`, `peq`, `!eb`, `!ew`, `!ed`, `!eq`, `vtop`, `dl`, `ds`, `dS`, `dump-analyze`, `!address`, `dump-raw`, `dump-pe`, `dump-kernel`, `dump-live`, `e`, `ea`, `eb`, `ed`, `eD`, `ef`, `ep`, `eq`, `eu`, `ew`, `eza`, `ezu`, `f`, `fp`, `m`, `s`, `query`, `write` |
| port | 6 | `ib`, `iw`, `id`, `ob`, `ow`, `od` |
| register | 4 | `r`, `rdmsr`, `rm`, `wrmsr` |
| script | 5 | `$<`, `$><`, `$$<`, `$$><`, `$$>a<` |
| search | 1 | `#` |
| selector | 1 | `dg` |
| session | 24 | `cls`, `probe`, `!snapshot`, `!diff`, `set-ppl-antimalware`, `!timeline`, `q`, `qq`, `qd`, `sq`, `backend`, `drvstatus`, `mcp`, `remote`, `kd`, `kdinit`, `kddetach`, `unload`, `home`, `log`, `dashboard`, `help`, `exit`, `quit` |
| source | 9 | `l+`, `l-`, `ls`, `lsa`, `lsc`, `lse`, `lsf`, `lsf-`, `lsp` |
| stack | 6 | `k`, `kb`, `kc`, `kp`, `kP`, `kv` |
| symbols | 12 | `ld`, `lm`, `ln`, `ss`, `x`, `.sympath`, `.sympath+`, `.reload`, `sympath`, `reload`, `modules`, `addr` |
| target | 11 | `\|\|`, `\|\|s`, `\|`, `\|s`, `~`, `~e`, `~f`, `~u`, `~n`, `~m`, `~s` |
| type | 3 | `dt`, `dtx`, `setfield` |
| version | 3 | `vercommand`, `version`, `vertarget` |
