# KnLiveDbg kmon Test Target

`KnLiveDbgKmonTarget.exe` is a lab-only positive-control process for `!kmon`
user-mode hostility. It creates artifacts inside copies of **this** binary. It
does not inject into a third-party process, does not resume a replaced image,
and does not unlink processes from the kernel.

DKOM hide classification is covered by the existing `hidden-process-view-classification`
console self-test, not by this harness.

## Build

```powershell
.\tools\build.ps1 -Configuration Release
```

Build the solution (`kn-live-dbg.sln`), not the vcxproj alone. The solution
`OutDir` is:

```text
x64\Release\tools\KnLiveDbgKmonTarget.exe
```

A direct vcxproj build lands under `kmon_test_target\x64\Release\tools\` and
will miss the console self-test lookup next to `KnLiveDbg.exe`.

## Scenarios

Parent modes use `%TEMP%\kn-live-dbg-kmon\ordinary-kmon-target.exe`.
Only `/masquerade` uses `notepad.exe`, because its purpose is to exercise a
Windows-name/path mismatch. Watched main-image verification is independent of
the filename. Sequential runs retry `DeleteFile` + `CopyFile` while a previous
fixture copy is in use. `/seconds N` holds the artifact (default 45), and
`/seconds 0` holds until termination. Children use `CREATE_NO_WINDOW`.

`/replace-main` unmaps only at the original ImageBase, allocates the private
replacement at that same base, and does not resume the process. If
`VirtualAllocEx` cannot land at the original ImageBase, the scenario fails
instead of leaving PEB ImageBase unmapped.

| Flag | Artifact | Expected `process.hollow` / related layer |
|---|---|---|
| `/masquerade` | temp `notepad.exe` copy, no memory patch | `process.masquerade` |
| `/overwrite` | NOP patch on own `.text` (`0x90` sled over the section head, `kOverwritePatchBytes`), RX restored | `finding.code_modified`; COW is `coverage.image_cow` |
| `/overwrite-tail` | 16-byte change in the last page of the inert 1 MiB `.kntail` executable section, never called | `finding.code_modified` at the page containing the printed `KMON_TAIL rva` |
| `/stamp` | in-memory `TimeDateStamp` rewritten | `hollow` |
| `/nomz` | ImageBase MZ wiped | `exe_no_mz` |
| `/orphan-private` | `VirtualAlloc` RX page with MZ | `exe_orphan_private` |
| `/orphan-image` | delete-pending `SEC_IMAGE` map, not in the loader | `exe_orphan_image` |
| `/orphan-mapped-rx` | anonymous headerless `MEM_MAPPED` section with inert RX bytes, never executed | `mapped_exec` on an explicitly watched copy; no execution is inferred |
| `/mapped-readonly` | same section bytes with `PAGE_READONLY` | no executable-orphan finding (negative control) |
| `/replace-main` | suspended self-copy, EXE unmapped, private MZ, **never resumed** | `exe_private` |
| `/ghost` | running copy then delete the file | `ghost` |

`/ghost` needs `GetFileAttributesW` to fail with file/path not found. Access
denied remains a coverage gap. A delete-pending file
that is still visible is not `layer=ghost`; the fixture prints a warning in
that case.

`/orphan-image` still fires through its RX text sub-region. The orphan image
layer requires an executable region at the allocation base, so read-only
`LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE)` views left by icon/version
readers (single orphan `MEM_IMAGE` + `PAGE_READONLY` region) stay silent.
The fixture opens its own backing file with execute access before creating
`SEC_IMAGE`; omitting that access produces `STATUS_ACCESS_DENIED`. It also
requires a complete write and successful delete-pending disposition before
mapping. Its minimal PE has a valid `.text` entry RVA and is never executed.

Stdout line:

```text
KMON_FIXTURE pid=<pid> scenario=<name> image=<path>
```

PID is also written to `%TEMP%\kn-live-dbg-kmon\artifact.pid`. Every mode prints that line and writes that pid file; `/overwrite` announces before its destructive step because the `0x90` sled lands on the code that emits them, so a `/child overwrite` run still leaves the documented readiness signal.

All modes contain the same `.kntail` section. `hold` and `mapped-readonly` keep
it intact, providing normal tail bytes as well as the modified tail control.
`validate-kmon-live.ps1 -ImageSweepFixtures -RequireImageCompletion` adds the
tail scenario and requires full traversal without read failures of the fixture,
KERNEL32, KERNELBASE and ntdll in every scenario, plus complete byte comparison
of the fixture itself. Loader-mutable exclusions remain partial and are counted
separately. It uses completed sweep events,
not a zero queue depth or a sum of repeated page reads. Loader layout changes
already classified as observations are counted separately from findings; their
raw events remain in the evidence.

`/seconds` accepts decimal values from 0 through 4,294,967. Zero explicitly
requests an indefinite hold. Missing, malformed, negative, or larger values
fail before copying or modifying the fixture; milliseconds cannot wrap.

## Live `!kmon` pass

Elevated, driver loaded:

```text
write on
!kmon /name ordinary-kmon-target.exe /background
```

Other console:

```powershell
.\x64\Release\tools\KnLiveDbgKmonTarget.exe /overwrite /seconds 60
```

Then `!kmon` to attach the tail. Bounded user/image scans rotate through
targets; use `!kmon status` to inspect progress and overdue work. Repeat with `/stamp`, `/nomz`, `/orphan-private`,
`/orphan-image`, `/orphan-mapped-rx`, `/mapped-readonly`, `/replace-main`, `/ghost`, `/masquerade`.

`/replace-main` leaves a suspended process; the fixture terminates it when the
hold expires.

`add` / `remove` only work after collection is already running. `/verbose` and
`/log` apply only on the first start.

### Automated live matrix

From an elevated PowerShell, after building the solution:

```powershell
.\tools\validate-kmon-live.ps1 -ObserveSeconds 180 -ProbeDriver
# Also fail on collector/analysis/capture/persistence queue losses:
.\tools\validate-kmon-live.ps1 -ObserveSeconds 180 -ProbeDriver -RequireQueueHealth
```

The runner starts an actual `!kmon` session and six owned children: `hold`,
`mapped-readonly`, `overwrite`, `orphan-mapped-rx`, `orphan-private`, and
`orphan-image`. It checks emitted JSONL events, requires a user reference
observation for every child, and rejects findings on the two negative
controls. The image case must produce `exe_orphan_image` and must not be
mislabelled `private_exec_pe` or `private_exec_wiped`. `-ProbeDriver` additionally
loads the bundled probe and requires an observed driver lifecycle event.
It does not enable raw I/O interposition.

`-RequireQueueHealth` requires zero reported event loss, layout/reference drops,
capture/persistence/diagnostic/catalog queue drops, and reference cursor eviction.
Reference expiration is included in reference drops. Pending work and ordinary
read failures remain visible and are not claims of complete host coverage.

Evidence defaults to a fresh `.build\kmon-live\<timestamp>` directory. Use
`-OutputDirectory <new-directory>` to choose a location. The runner saves
console output, fixture PIDs, case/layout exports and `validation.json`,
including first detection times, executable hashes, final pipeline coverage
counters and cleanup results. Case/layout identities and every completed
capture's file length and SHA-256 are checked against their event records.
It refuses an existing KnLiveDbg service and keeps its creation-time process
handle across the console's PPL transition. A timeout, missing expected event,
early child exit or fallback service cleanup fails the run.

This is a bounded observation test. `-ObserveSeconds` controls the observation
window, not a detection deadline guarantee. Coverage, capture failures and
queue loss must still be examined in the logs; a passing fixture matrix is
not proof that the whole machine was scanned. Direct `/child` launches avoid
the parent modes' shared temporary executable, and readiness uses each
child's stdout rather than the shared `artifact.pid` file.

## Automated primitives

`KnLiveDbg.exe --self-test console` includes `kmon-artifact-primitives`:

1. A write to self `.text` makes `QueryWorkingSetEx` Shared=0 (`exe_cow`), then
   bytes are restored.
2. A private MZ page is `MEM_PRIVATE`.
3. `GetMappedFileNameW` returns a path for the current EXE mapping.
4. If the fixture EXE is next to `KnLiveDbg.exe` (or under `tools\`), a
   `/child overwrite` process shows private COW pages. The parent observes
   the sled in the child image before it judges the mapping, and the
   observed length comes from the fixture shared contract
   (`kmon_test_target/KmonTestTargetContract.h`) instead of a second
   hard-coded copy: a sled shorter than the contract fails this case rather
   than silently skipping the comparison.
5. When the fixture binary or process creation is unavailable the
   cross-process half is skipped with one explicit reason line naming which
   of the six conditions applied (fixture missing, `CreateProcessW` failed,
   `OpenProcess` refused, PEB ImageBase unreadable, contract sled never
   observed, child exited before the COW sample).

That gate does not require `write on` or `!kmon`. The standalone
`tools/validate-kmon-core.ps1` also compares an executable page in its own
ordinary-name EXE against the relocation-aware disk reference, changes a byte
in the middle of its second executable probe page, verifies the mismatch,
and restores it. See [verification and manifest usage](KMON_DETECTION_VERIFICATION.md)
for queue, short-lived capture, native PDB and mapping-reuse controls.

The independent `kmon-mapped-section-artifact` console gate creates a real
anonymous section, verifies `MEM_MAPPED` plus executable protection and readable
sample bytes with the production candidate helpers, changes it to read-only,
and verifies rejection. The bytes are never executed. This gate does not depend
on a process-name alias or on loading the driver.

`kmon-user-memory-regression` checks independent kernel-section identity,
unreadable samples, ghost/path failure distinctions, CoW page selection,
bounded process scheduling, and live thread-start query primitives. Neither
this gate nor launching a fixture proves that a running `!kmon` emitted an
event; that requires the live pass above.

## Not covered here

- Live DKOM `ActiveProcessLinks` unlink (needs a kernel fixture).
- Cross-process injection into a real inbox `notepad.exe` / `svchost.exe`.
- Game + anti-cheat idle FP soak (manual on the game machine).
- Kernel mapper / pool PE / unbacked hook positives (those stay on `!pool pe`,
  `!kpage`, `!mapper`, `!callbacks`).

The implemented observations, current research, and remaining gaps are listed
in [KMON_DETECTION_COVERAGE.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_DETECTION_COVERAGE.md).
