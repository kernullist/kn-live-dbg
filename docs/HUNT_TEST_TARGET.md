# KnLiveDbg Hunt Test Target

`KnLiveDbgHuntTarget.exe` is a lab-only positive-control process for validating
the no-target `!hunt` scanner. It creates suspicious but self-contained
artifacts inside its own process. It does not inject into another process and
does not bypass system protections.

## Build

The target is part of `kn-live-dbg.sln`:

```powershell
msbuild kn-live-dbg.sln /p:Configuration=Release /p:Platform=x64
```

Outputs:

```text
x64\Release\tools\KnLiveDbgHuntTarget.exe
x64\Release\tools\KnLiveDbgHuntTargetDll.dll
```

## Run

Start the target in a normal console:

```powershell
.\x64\Release\tools\KnLiveDbgHuntTarget.exe /all /seconds 300
```

Then run KnLiveDbg elevated in another console:

```text
!hunt /deep /limit 80 /json .\hunt-target.json
```

## Scenarios

| Option | Artifact | Expected `!hunt` reason codes |
| --- | --- | --- |
| `/private-exec` | Private executable RX page | `private_executable_vad` |
| `/rwx` | Private executable writable page | `wx_user_vad`, `private_executable_vad` |
| `/pe-like` | Private executable page copied from this EXE's PE header | `private_pe_mapping`, `private_pe_without_loader_entry` |
| `/wiped-pe` | PE-like private page with wiped `MZ` and `PE` signatures | `wiped_pe_header`, `private_pe_mapping` |
| `/thread` | Thread start address inside private executable memory | `suspicious_thread_start` |
| `/apc` | Queued APC normal routine inside private executable memory | `suspicious_apc_routine` |
| `/module-patch` | Loaded fixture DLL export bytes modified in this process | `live_disk_exec_page_mismatch`, `module_text_mismatch` or `module_entrypoint_mismatch` |

If no scenario option is supplied, the target enables all scenarios. `/seconds
0` keeps the target alive until Ctrl+C.

## Operator Notes

1. Use `/quick` only for smoke tests. Hidden-PTE and live-vs-disk module checks
   require default or `/deep` mode.
2. The module patch scenario modifies `KnLiveDbgHuntTargetDll.dll` only in the
   target process address space. The DLL file on disk is not modified.
3. Browser, .NET, and JIT-heavy systems may produce additional private
   executable findings. Filter by `image=KnLiveDbgHuntTarget.exe` or use the
   JSON output when validating reason codes.
4. The target is intentionally noisy. Do not run it as a clean-baseline
   process.
