# Kn-Live-Dbg

Kn-Live-Dbg is a Windows x64 live-kernel debugger and security-research tool.
The driver supplies memory and telemetry primitives; the elevated console owns
symbols, scanners, evidence, and service lifecycle.

**Latest release: [v0.0.36](https://github.com/kernullist/kn-live-dbg/releases/tag/v0.0.36).**
Download the Release x64 ZIP and `SHA256SUMS.txt` together.
The [release notes](docs/RELEASE_NOTES_0.0.36.md) describe the shipped changes,
signer, validation, and limitations. The main user/kernel ABI is **17**.

The `main` branch also includes retained KMON evidence with driver-free offline
queries, replay and explanations, plus reference-scheduling and TI queue fixes.
These changes are newer than v0.0.36. See the [current guides](docs/README.md) and
[development validation](docs/VALIDATION.md#reference-watch-and-ti-queue-review-2026-10-29)
for their scope and remaining gaps.

## Start here

1. Extract the entire package on a Windows x64 lab machine configured to load
   its test-signed drivers. Keep the EXE, SYS files, and runtime DLLs together.
2. Run `KnLiveDbg.exe` elevated. Startup manages the main service and loads the
   kernel symbols into the EXE-local `symbols` cache.
3. At `knkd>`, use `help`, `help <command>`, or Tab completion. Native writes are
   enabled by default; use `write off` for a read-only interactive session.
4. Use `q` for normal shutdown and service cleanup. Save evidence before leaving.

```powershell
# Driver-free startup help and component checks
.\x64\Release\KnLiveDbg.exe --help all
.\x64\Release\KnLiveDbg.exe --self-test all

# Build from source with the installed SDK/WDK and signing configuration
.\tools\build.ps1 -Configuration Release
```

See [build and release instructions](docs/BUILD_AND_RELEASE.md) for prerequisites,
certificate selection, version stamping, and packaging. The distributed drivers
are test-signed lab artifacts; production trust depends on the target's Windows
code-integrity policy.

## Investigation surfaces

| Task | Entry points |
| --- | --- |
| Memory, symbols, and types | `d*`, `e*`, `vtop`, `procctx`, `dt`, `x`, `u`, `uf` |
| Processes and executable memory | `ps`, `!vad`, `!threads`, `!handles`, `!hiddenproc`, `!hunt` |
| Kernel modules and execution references | `!module`, `!driver`, `!callbacks`, `!minifilter`, `!ssdt`, `!idt`, `!msrcheck`, `!cr` |
| Additional kernel surfaces | `!wfp`, `!alpc`, `!wnf`, `!etw`, `!nmi`, `!fwtable`, `!hal`, `!hive`, `!dpc`, `!timer`, `!inputstack` |
| Driver and payload evidence | `!byovd`, `!mapper`, `!kpage`, `!pool`, `!payload`, `!address`, `!wdfilter` |
| Platform posture | `!vbs`, `!ci`, `!securekernel`, `!hv`, `!dma`, `!token` |
| Continuous collection | `!kmon`, `!ti`, `!timeline` |
| Baselines and dumps | `!snapshot`, `!diff`, `dump-kernel`, `dump-live`, `dump-analyze` |
| Optional backends and clients | `backend`, `kdinit`, `ai`, `mcp on`, `remote on`, `--connect` |

The [command guide](docs/COMMAND_REFERENCE.md) explains workflows and output;
[command coverage](docs/WINDBG_COMMAND_COVERAGE.md) distinguishes native commands
from DbgEng routing. Use the binary's help for the complete argument grammar.

## Evidence and limits

KMON records observations, investigation leads, collection health, and coverage
separately. Zero findings do not establish a clean host when reads, budgets,
capture, or image comparisons are incomplete. Code differences, signatures,
names, and executable memory are evidence, not standalone malware verdicts.
See [detection coverage](docs/KMON_DETECTION_COVERAGE.md) and
[validation status](docs/VALIDATION.md) for measured results and remaining gaps.

Callback control is limited to the cooperative `KnLiveDbgMiniFilterFixture`
CREATE bodies. Registered callback pointers remain unchanged. External callback
replacement is unavailable. Experimental `!kmon iotrace` is a separate raw
dispatch-interposition path with unresolved publication/unload lifetime limits;
the cooperative fixture tests do not establish its safety.

MCP and the human remote console use separate, mutually exclusive listeners.
Both transports are cleartext lab interfaces. MCP starts read-only; the human
remote session follows the local write policy. AI provider configuration does
not change these transport or kernel permissions.

## Documentation

The [documentation index](docs/README.md) links the current guides, source map,
test procedures, remaining work, and fixed-version historical evidence.

| Guide | Purpose |
| --- | --- |
| [Architecture](docs/ARCHITECTURE.md) | Implementation boundaries and lifetime contracts |
| [Manual test checklist](docs/MANUAL_TEST_CHECKLIST.md) | Repeatable component and live-host validation |
| [KMON fixture](docs/KMON_TEST_TARGET.md), [hunt fixture](docs/HUNT_TEST_TARGET.md) | Owned positive and negative controls |
| [MCP setup](docs/MCP_SETUP.md) · [한국어](docs/MCP_SETUP.ko.md) | Typed tools and client configuration |
| [Remote setup](docs/REMOTE_SETUP.md) · [한국어](docs/REMOTE_SETUP.ko.md) | Human console on another lab PC |
| [AI workflows](docs/AI_ASSISTED_WORKFLOWS.md) | Provider setup, read plans, and confirmed writes |
| [Timeline](docs/TIMELINE_COMMAND_USAGE.md) · [한국어](docs/TIMELINE_COMMAND_USAGE.ko.md) | Evidence queries and exports |

## Demo

https://github.com/user-attachments/assets/f3542a85-c960-46f2-a151-fdd23a8294a6

[Console demo](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/demo/kn-live-dbg-demo-readme.mp4) ·
[Full-resolution demo](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/demo/kn-live-dbg-demo.mp4) ·
[AI command demo](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/demo/kn-live-dbg-demo-ai.mp4)

## License and dependencies

See [LICENSE](LICENSE), the [vendored runtime manifest](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/vendor/debugging-tools/x64/MANIFEST.md),
and [Zydis notices](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/third_party/zydis/README.md).
