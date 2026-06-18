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
.\x64\Release\tools\KnLiveDbgHuntTarget.exe /all /manifest .\hunt-target-manifest.json /seconds 300
```

Then run KnLiveDbg elevated in another console:

```text
!hunt /deep /limit 120 /json .\hunt-target.json
```

Validate the `!hunt` output against the target manifest:

```powershell
.\tools\validate-hunt-target.ps1 -Manifest .\hunt-target-manifest.json -HuntJson .\hunt-target.json
```

## Scenarios

| Option | Artifact | Expected `!hunt` reason codes |
| --- | --- | --- |
| `/baseline` | No positive-control artifacts | No target-specific findings in strict baseline validation |
| `/private-exec` | Private executable RX page | `private_executable_vad` |
| `/rwx` | Private executable writable page | `wx_user_vad`, `private_executable_vad` |
| `/large-private-exec` | Large private executable RX region | `large_private_executable_vad`, `private_executable_vad` |
| `/pe-like` | Private executable page copied from this EXE's PE header | `private_pe_mapping`, `private_pe_without_loader_entry` |
| `/wiped-pe` | PE-like private page with wiped `MZ` and `PE` signatures | `wiped_pe_header`, `private_pe_mapping` |
| `/thread` | Thread start address inside private executable memory | `suspicious_thread_start` |
| `/apc` | Queued APC normal routine inside private executable memory | `suspicious_apc_routine` |
| `/threadless-stack` | Normal module thread whose user stack references private executable memory | `stack_reference_to_executable_memory`, `stack_reference_to_private_executable_vad`, `stack_reference_to_user_executable_outside_module` |
| `/module-patch` | Loaded fixture DLL export bytes modified in this process | `live_disk_exec_page_mismatch`, `module_text_mismatch` or `module_entrypoint_mismatch` |
| `/module-patch-late` | Loaded fixture DLL export in a later executable section modified in this process | `live_disk_exec_page_mismatch`, `module_text_mismatch`, `module_stomping_evidence` |
| `/stomp-thread` | Thread start address inside a modified module executable page | `thread_start_in_modified_module_page`, `module_stomping_evidence` |
| `/stomp-apc` | Queued APC normal routine inside a modified module executable page | `apc_target_in_modified_module_page`, `module_stomping_evidence` |
| `/section-image-map` | Copied fixture DLL mapped as `SEC_IMAGE` without loader participation | `section_image_without_loader_entry`, `vad_image_not_in_loader` |
| `/locked-backed-image` | Loader-invisible `SEC_IMAGE` mapping whose backing file denies read sharing | `section_backing_inaccessible`, `section_image_without_loader_entry`, `vad_image_not_in_loader` |
| `/section-image-stomp` | Loader-invisible `SEC_IMAGE` mapping with a modified executable page | `section_image_without_loader_entry`, `vad_image_not_in_loader`, `live_disk_exec_page_mismatch`, `module_text_mismatch`, `module_stomping_evidence` |
| `/image-rwx-section` | Loaded fixture DLL section with default writable executable protection | `image_rwx_section_vad`, `mockingjay_rwx_section_candidate`, `wx_user_vad` |
| `/lab-builtin-profile` | Test-only built-in profile violation gated by an explicit lab flag and a non-Windows fixture DLL load | `builtin_profile_path_mismatch`, `system_name_from_non_system_path`, `builtin_process_non_windows_module`, `dll_load_in_builtin_process` |
| `/manifest <path>` | Writes a machine-readable scenario manifest | `kn-live-dbg.hunt-target-manifest.v1` |

`/all` enables every positive-control scenario, including the command-line
gated lab built-in profile. If no scenario option is supplied, the target
enables all memory/module/thread/APC/image-section scenarios but leaves the lab
built-in profile disabled because that profile intentionally requires an
explicit command-line marker. `/seconds 0` keeps the target alive until Ctrl+C.

## Manifest Validation

The target manifest records:

1. Target PID and image path.
2. Scenario name and artifact type.
3. Artifact address and size.
4. Expected `!hunt` reason codes.

`tools\validate-hunt-target.ps1` reads the manifest and `!hunt` JSON, filters
findings by the target PID, and fails if any expected reason code is missing.
Use `-Strict` with `/baseline` when validating that the target process itself
does not produce positive-control findings.
This is a reason-code coverage check; inspect the JSON evidence when validating
address ownership or page-level provenance.

## Image-Section Fixtures

The image-section scenarios use temporary copies of
`KnLiveDbgHuntTargetDll.dll` and keep all artifacts inside the current process:

1. `/section-image-map` creates a file-backed image VAD that is absent from
   Toolhelp and PEB loader views.
2. `/locked-backed-image` keeps the mapped image alive while an open backing
   file handle denies read sharing, forcing the scanner's backing-path reopen
   check to report `section_backing_inaccessible`.
3. `/section-image-stomp` modifies the mapped image's first executable section
   page in memory only, so deep live-vs-disk comparison can verify the hidden
   image mapping and module-stomping paths together.
4. `/image-rwx-section` loads the fixture DLL's purpose-built RWX image section
   and validates hunt coverage for Mockingjay-style reuse of writable executable
   code caves inside otherwise legitimate image mappings.

These cases are intentionally not cross-process injection samples. They are
positive controls for hunt invariants: VAD image ownership, loader cross-view
absence, backing-path accessibility, and live-vs-disk executable page mismatch.

## Known Fixture Gap

The target does not currently include a main-image live-vs-disk mismatch or
process-image replacement fixture. That scenario is intentionally left out
because safely replacing or mutating the process main image without resembling
an offensive hollowing/doppelganging sample needs a separate benign harness.
`!hunt` still emits `section_path_mismatch`, `section_backing_inaccessible`,
`disk_live_image_mismatch`, and `process_doppelganging_evidence` when live
system evidence supports those invariants. The `SEC_IMAGE` fixtures above cover
the same section/backing invariants for non-main image mappings.

## Operator Notes

1. Use `/quick` only for smoke tests. Hunt hidden-PTE findings are limited to
   executable user PTE ranges in processes with a verified user address space
   and reliable VAD coverage; live-vs-disk module checks require `/deep`.
2. The module patch and stomp scenarios modify `KnLiveDbgHuntTargetDll.dll`
   only in the target process address space. The DLL file on disk is not
   modified.
3. `/lab-builtin-profile` does not rename the process to a Windows built-in
   binary. It triggers a deterministic test-only profile in `!hunt` so profile
   path validation can be tested without impersonating protected Windows
   processes.
4. `/stomp-thread` and `/stomp-apc` intentionally put execution provenance on
   the same modified executable module page so `!hunt` can validate correlation
   rather than only byte mismatch.
5. Live-vs-disk executable page checks ignore pages that contain expected base
   relocation fixups for relocated images and PE directories that the Windows
   loader normally mutates, such as import/IAT, delay import, TLS, and load
   config pages. The stomp fixtures patch normal code bytes so they still
   produce module-stomping evidence.
6. `/locked-backed-image` uses share-mode denial rather than deleting the
   backing file because Windows normally blocks immediate deletion of an active
   image section with `ERROR_ACCESS_DENIED`.
7. Browser, .NET, and JIT-heavy systems may produce additional private
   executable findings. Weak private RX-only VADs are reported at lower
   risk/confidence and capped per process; filter by
   `image=KnLiveDbgHuntTarget.exe` or use the JSON output when validating
   reason codes.
8. Image-backed writable executable VAD findings include disk PE section
   evidence so operators can separate default RWX section exposure from live
   permission drift on normally RX or non-executable sections.
9. `/threadless-stack` keeps the thread start in normal module code but leaves
   a private executable address on the user stack. This validates the deep
   stack-reference correlation used for threadless and worker-callback style
   execution evidence without cross-process injection. The
   `stack_reference_to_user_executable_outside_module` reason is emitted only
   when user module enumeration succeeded for the target process.
10. Built-in module provenance findings are intentionally path-provenance
    signals. They are strongest for core Windows service profiles and should be
    reviewed with module signature and vendor context in real endpoint data.
11. `/deep` stack correlation uses a per-process stack-pointer cache instead of
    rereading every user stack for every modified executable page. The JSON
    evidence includes the cache sample count and whether the cache hit its
    per-process cap.
12. The target is intentionally noisy. Do not run it as a clean-baseline
    process.
