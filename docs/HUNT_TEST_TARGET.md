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

The manifest writer creates missing parent directories, so paths such as
`.\.build\hunt-live-manifest.json` work from a clean lab directory. Use
`/seconds 0` for live validation sessions where the target should stay alive
until Ctrl+C.

Then run KnLiveDbg elevated in another console:

```text
!hunt /deep /summary /json .\hunt-target.json
```

In the console summary, target-specific defense-evasion and credential-tool
detections should appear first in `[hunt.assessment]` and then in
`[hunt.high_signal]` even when generic VAD, thread, or module anomaly findings
dominate the count-based top tables. The assessment rows are intended to read as
operator conclusions with `who=`, `technique=`, `affected=`, and `evidence=`
fields, so a reviewer can see which process or system artifact used which
technique and what surface was manipulated before expanding raw findings. The
manifest and JSON validator use stable raw reason codes; console triage renders
those codes as generic technique/evidence labels such as
`known_defense_evasion_tool_name`, `known_defense_evasion_driver_service`,
`manipulated_version_info`, `packed_or_protected_section`, and
`credential_collection_cli_shape`.

`!hunt` also contains exact ESET SHA-1 IoCs for the public Gentlemen article.
Those hash findings require real matching files and are not synthesized by this
benign target; the target instead validates the surrounding name, suffix,
metadata, command-line, service, and module-stomping detection paths without
shipping malware bytes.
Run `tools\validate-eset-hunt-iocs.ps1` to check the static ESET IoC table and
its source/documentation wiring. When checking drift against a saved copy of the
live ESET article, pass `-ArticleHtml <path>`; the validator reconstructs split
Table 5 SHA-1 values, case-insensitive Table 2 `.exe` process names, and
Table 3/4 process and driver indicators before comparing them with the pinned
hunt source lists. Use `-ArticleUrl <url>` to fetch the article directly into
`.build\eset-article-current.html` and run the same currentness checks.

For the ESET/Gentlemen end-to-end path on a VM without MSBuild or WDK, create a
prebuilt bundle from the development machine first:

```powershell
.\tools\make-eset-hunt-e2e-vm-bundle.ps1
```

The generated `.build\eset-hunt-e2e-vm-bundle.zip` includes `BUNDLE-INFO.json`
with `bundle_contract=eset-hunt-e2e-vm-bundle-v1`, the runner contract, file
hashes, the source git status, and the expected VM startup needles. After
expanding the zip on the VM, run the scripted elevated workflow without
`-Build`:

```powershell
.\tools\run-eset-hunt-e2e.ps1
```

From a source checkout that has the full build toolchain, the one-command path
is still:

```powershell
.\tools\run-eset-hunt-e2e.ps1 -Build
```

The script starts the target with `/edr-killer-suffix-name`,
`/oxideharvest-cli`, and `/edr-killer-driver-service`, feeds
`!hunt /deep /summary /json` plus `exit` to `KnLiveDbg.exe` through redirected
stdin, then runs `tools\validate-hunt-target.ps1` against the generated
manifest and hunt JSON. It also checks the `!hunt /summary` console contract:
the conclusion, aggregate summary, high-signal table, top triage tables, and
detail-suppression line must be visible in stdout. Add `-ArticleUrl <url>` or
`-ArticleHtml <path>` when the same elevated run should also compare the current
ESET article tables against the pinned hunt IoCs; that check writes
`.build\eset-hunt-e2e\article-validator.log`. With `-ArticleUrl`, the downloaded
HTML is kept in the same E2E artifact directory unless `-ArticleOutPath` is
provided. The runner prints
`runner_contract=e2e-auto-knlivedbg-article-currentness-v2`, `elevated=<bool>`,
and `output_dir=<path>` near startup so a VM bundle with an older target-only
wrapper is easy to spot and non-elevated runs still leave a durable diagnostic
in `runner.log`. The runner keeps the target
fixture alive longer than the `KnLiveDbg` timeout by default (`/seconds 300` for
the target, 180 seconds for `KnLiveDbg`, plus a required padding guard), so a
slow deep hunt cannot race the fixture lifetime. It also passes a named
`/stop-event` to the target and signals it after artifact validation, allowing
the target to exit through its normal cleanup path without waiting for the full
target lifetime. It requires administrator rights because the driver-service
fixture creates temporary SCM `SERVICE_KERNEL_DRIVER` records. The runner writes
`.build\eset-hunt-e2e\runner.log` with the exact target arguments, target PID,
manifest-wait state, `KnLiveDbg` launch, validator step, and any caught
exception so VM runs that exit early can be diagnosed from artifacts instead of
console scrollback alone. If the target exits before the 35-scenario manifest is
ready, the runner reports that immediately instead of waiting for the manifest
timeout. On failure it also prints the artifact paths and snapshots live
`KnLiveDbg` and `KnLiveDbgHuntTarget` processes.
It also prints the tails of the target, `KnLiveDbg`, and validator logs so the
artifact directory identifies the failing stage.
If a VM run already produced the 35-scenario manifest but stopped before
`KnLiveDbg` launched, rerun the script with `-ReuseExistingTarget`. That mode
keeps the existing manifest, regenerates only the hunt/console artifacts, and
continues from the scripted `KnLiveDbg` plus validator stage. Add
`-ExistingStopEventName <name>` when the original console printed the
`Local\KnLiveDbgHuntE2E-...` event name so cleanup can still be signaled after
validation.

Captured elevated-run artifacts can be rechecked without recreating the SCM
services:

```powershell
.\tools\validate-eset-hunt-e2e-artifacts.ps1 -Manifest .\.build\eset-hunt-e2e\hunt-target-manifest.json -HuntJson .\.build\eset-hunt-e2e\hunt.json -Stdout .\.build\eset-hunt-e2e\knlivedbg.stdout.log -RunnerLog .\.build\eset-hunt-e2e\runner.log -RequireRunnerPassed
```

The artifact validator checks the full 35-scenario ESET fixture contract for
elevated runs, including every suffix/exact-name process fixture, every
driver-service fixture, and the weak-vendor, GentlemenCollection path-only, and
OxideHarvest name-only negative controls. The full contract has exactly 32
positive class/risk/confidence scenario contracts plus three negative-control
scenarios; the driver-service-only
contract has exactly 15 positive contracts. The JSON summary must also report
exactly 15 EDR-killer driver-service findings.
When `-RunnerLog` is supplied, the same validator also requires the v2 runner
contract, elevated execution, 35-scenario target-ready step, and scripted
`KnLiveDbg` launch evidence. Add `-RequireRunnerPassed` for completed captured
VM artifacts so the final `passed` marker is required as well.
It also requires stdout to show both the process-profile high-signal entry and
the system-scoped `known_defense_evasion_driver_service` console label with the
expected `system_findings` count, so PID-less SCM findings do not disappear from
the operator-facing summary. `tools\validate-hunt-readiness.ps1` also generates
a synthetic 35-scenario artifact set so this contract is exercised on
non-elevated development machines. The raw JSON reason remains
`gentlemen_edr_killer_driver_service`; only the operator-facing console label is
generalized.

Validate the `!hunt` output against the target manifest:

```powershell
.\tools\validate-hunt-target.ps1 -Manifest .\hunt-target-manifest.json -HuntJson .\hunt-target.json
```

## Scenarios

The table below lists raw JSON/manifest reason codes, not the generalized
operator-facing console labels.

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
| `/edr-killer-suffix-name` | Benign child copies launched from `GentlemenCollection` with ESET-style suffix/exact names and lab-only version/`.enigma` evidence, plus weak-name and path-only negative controls | `gentlemen_edr_killer_process_name`, `gentlemen_suffix_normalized_process_name`, `gentlemen_collection_staging_path`, `edr_killer_version_info_impersonation_evidence`, `edr_killer_packer_section_evidence` |
| `/oxideharvest-cli` | Benign child copy launched as `buildx641.exe` with OxideHarvest-style CLI options | `gentlemen_related_credential_tool_name`, `oxideharvest_cli_shape` |
| `/edr-killer-driver-service` | Non-started SCM kernel-driver services configured with ESET EDR-killer driver IOC leaves under staging context | `driver_service_installed`, `driver_service_binary_name_ioc`, `gentlemen_edr_killer_driver_service`, `driver_service_not_running`, `gentlemen_collection_staging_path` |
| `/lab-builtin-profile` | Test-only built-in profile violation gated by an explicit lab flag and a non-Windows fixture DLL load | `builtin_profile_path_mismatch`, `system_name_from_non_system_path`, `builtin_process_non_windows_module`, `dll_load_in_builtin_process` |
| `/manifest <path>` | Writes a machine-readable scenario manifest | `kn-live-dbg.hunt-target-manifest.v1` |

`/all` enables every positive-control scenario, including the command-line
gated lab built-in profile. If no scenario option is supplied, the target
enables all memory/module/thread/APC/image-section scenarios but leaves the lab
built-in profile disabled because that profile intentionally requires an
explicit command-line marker. `/seconds 0` keeps the target alive until Ctrl+C.
`/manifest` creates missing parent directories before writing the JSON file.

## Manifest Validation

The target manifest records:

1. Target PID and image path.
2. Scenario name and artifact type.
3. Artifact address and size.
4. Expected `!hunt` reason codes.
5. Unexpected `!hunt` reason codes that must not appear for negative controls.
6. Optional expected JSON evidence keys and exact evidence values.
7. Optional expected finding `class`, `risk`, and `confidence` values.

`tools\validate-hunt-target.ps1` reads the manifest and `!hunt` JSON, filters
findings by the target PID, or by a scenario-level `pid` when the manifest
records a child positive-control process or `pid=0` system finding, and fails
unless one finding satisfies all expected class/risk/confidence values, reason
codes, expected evidence keys, and exact expected evidence values for that
scenario. It also fails if a scenario-level `unexpected_reasons` entry appears
for that PID.
In console triage, `pid=0` service scenarios appear as system-scoped findings
and the high-signal/top-reason tables expose them through `system_findings`.
The validator summary prints both `target_findings` and `system_findings`, then
prints `matched_positive_scenarios` so PID-less SCM scenarios do not look empty
when every scenario matched successfully.
`tools\validate-hunt-readiness.ps1` always generates a synthetic
`.build\hunt-readiness-service-synthetic*.json` pair and validates the same
PID-less driver-service contract, so this check does not disappear on clean
worktrees that lack older `.build` artifacts. It also runs mutated-negative
checks that corrupt the synthetic finding `class`, `risk`, and `confidence`
fields and require `tools\validate-hunt-target.ps1` to reject each mutation.
Use `-Strict` with `/baseline` when validating that the target process itself
does not produce positive-control findings.
This is a reason-code plus bounded evidence-contract check; inspect the full
JSON evidence when validating address ownership or page-level provenance.

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

## EDR-Killer Name Fixture

`/edr-killer-suffix-name` copies the test target to a temporary
`GentlemenCollection` directory and launches benign baseline child processes
named after the ESET Table 3/4 suffix families: `Kasps1.exe`, `KaspLight.exe`,
`FaceIT1.exe`, `Valorant2.exe`, `EAAntiCheatLight.exe`,
`EASolo1Clear.exe`, `EASolo2Light.exe`, `BitD1.exe`, `MB1.exe`, `G111.exe`,
`SymantecClear.exe`, `Avast1.exe`, `Sent2.exe`, and `SophosLight.exe`. It also
launches exact-name controls for `Deletor.exe` and `HwAudKiller.exe`, covering
the Cleaner and HavocKiller exact filename paths in ESET Tables 3 and 4. This
validates the Gentlemen naming pattern described by ESET: known EDR-killer base
names may carry suffixes such as `1`, `2`, `Light`, or `Clear` to indicate
protection and impersonation choices, while some tools use exact filenames
without a suffix. The fixture covers regular aliases, exact already-suffixed
IoCs, short `MB<suffix>` names that require staging context, digit-ending
`G11<suffix>` names that must not be normalized by stripping base digits,
exact-name non-suffix IoCs, and weak vendor-impersonation names that are only
elevated when the `GentlemenCollection` staging context is present. The children
do not load a driver, perform injection, or modify another process; they only
create benign process-name and staging-path positive controls. The manifest
records the child PID on each scenario so the validator checks findings for the
child instead of the parent target PID. The target EXE carries lab-only version
metadata (`CompanyName=Kaspersky Lab`, `OriginalFilename=Kasps.exe`,
`ProductName=Kaspersky Anti-Virus`) so vendor-like metadata evidence such as
`image_version_info_present`, `image_company_name`, `image_original_filename`,
`image_version_info_impersonation_match`, `gentlemen_suffix_tail`,
`edr_killer_version_info_impersonation_evidence`, and lab-only `.enigma` PE
section evidence can be validated with exact expected values without using a
real EDR-killer binary.

The same mode also launches `Avast.exe` from a temp directory that does not
contain `GentlemenCollection`. Its manifest entry is a negative control: weak
vendor-impersonation names must not produce Gentlemen process-name findings
without staging or telemetry context.
It also copies the real Windows `cmd.exe` into a temporary
`GentlemenCollection` directory as `StageOnlyBenign.exe` and launches it with a
short wait command. That manifest entry is another negative control:
`GentlemenCollection` staging alone must not produce
`gentlemen_collection_staging_path`, process-profile, version/icon, packer, or
OxideHarvest reasons when the filename, metadata, and command line carry no
ESET/Gentlemen/OxideHarvest evidence.

## OxideHarvest Fixture

`/oxideharvest-cli` copies the target to a temporary directory as
`buildx641.exe` and launches it with the OxideHarvest-style options documented
by ESET: `-i`, `-u`, `-p`, `-t`, and `-o`, each with a value. The child remains
benign and runs in baseline wait mode; the command line exists only so `!hunt`
can validate that the credential-tool name IOC is accompanied by
`oxideharvest_cli_shape` and the exact `oxideharvest_cli_options` evidence
value. The same mode also launches a `buildx64.exe` child without those
options as a negative control, so the credential-tool name alone does not alert
outside Gentlemen staging context.

## EDR-Killer Driver-Service Fixture

`/edr-killer-driver-service` creates temporary SCM `SERVICE_KERNEL_DRIVER`
records whose binary paths cover the ESET Table 3/4 driver leaves:
`eb.sys`, `NSecKrnl.sys`, `VGK.sys`, `GameDriverX64.sys`, `stpm_old.sys`,
`stpm_new.sys`, `dmx.sys`, `360NetMon_WFP.sys`, `360NetMon.sys`,
extensionless `IMFForceDelete`, extensionless `PoisonX`, `G11.sys`,
`googleApiUtil64.sys`, `ThrottleBlood.sys`, and `havoc.sys`. This covers
GentleKiller, HexKiller, ThrottleBlood, and HavocKiller service-staging paths.
The fixture does not start the services and does not load a driver; it only
leaves service configuration records long enough for `!hunt /deep` to validate
the driver-service IOC path. Half of the records store the SCM `ImagePath` as a
quoted binary path with a trailing dummy argument, and one extensionless record
uses an unquoted trailing argument, so the hunter's service-path normalizer is
exercised for both `.sys` and extensionless driver leaves.
The service binaries are placed under a temporary `GentlemenCollection`
directory so weak legitimate-driver names remain gated by staging context in
the hunter and are expected to include
`name_only_requires_hash_or_staging_correlation`. The manifest records `pid=0`
for these system-level scenarios and exact `binary_path` /
`expanded_binary_path` evidence values, so `tools\validate-hunt-target.ps1`
checks both system findings and the original SCM `ImagePath` string instead of
the target process PID. Creating the services requires administrator rights; if
SCM access is denied, the target prints a skip message and omits the scenarios
from the manifest.
The live fixture deliberately keeps these temporary services non-started. The
readiness validator separately synthesizes a `driver_service_running` artifact
for a strong ESET driver IOC so the running-service high-risk branch remains
covered without loading a throwaway kernel driver.
It also synthesizes exact SHA-1 artifacts for renamed process, OxideHarvest,
loaded-driver, and driver-service cases so the hash-only IOC path is checked
without carrying real malicious samples.
Another synthetic readiness artifact covers the ESET metadata-evasion layer:
invalid copied signature, vendor-like version information, icon impersonation,
and packer section evidence. The live target does not manufacture a broken
signature, but the scanner contract and JSON validator still pin the reason
codes and evidence names.
A separate synthetic telemetry artifact pins the behavior-only renamed-caller
path by requiring `security_product_target_count=2` and concrete Table 2 target
names such as `msmpeng.exe;ekrn.exe`.

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
   executable findings. Weak private RX-only VADs and generic W+X VAD-only
   findings are reported at lower risk/confidence and capped per process.
   PE-like private VADs without observed thread/APC/stack execution are also
   low-risk leads; filter by `image=KnLiveDbgHuntTarget.exe` or use the JSON
   output when validating reason codes.
8. Image-backed `EXECUTE_WRITECOPY` VADs are treated as executable
   copy-on-write mappings rather than generic W+X evidence. Image-backed
   writable executable findings include disk PE section evidence so operators
   can separate default RWX section exposure from live permission drift on
   normally RX or non-executable sections.
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
13. `/edr-killer-suffix-name` creates temporary self-copies and child processes.
    Each child waits for the parent process or the configured `/seconds`
    timeout, and parent cleanup removes the temporary copies after the children
    exit.
