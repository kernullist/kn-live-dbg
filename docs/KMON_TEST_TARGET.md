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

Each parent mode copies the fixture to `%TEMP%\kn-live-dbg-kmon\notepad.exe` so
`KmonIsWindowsBuiltinLeaf` is true (reloc-aware `.text` / COW layers only run
for Windows builtin leaves). Sequential runs retry `DeleteFile` + `CopyFile`
when the previous copy is still in use. `/seconds N` holds the artifact
(default 45). `/seconds 0` holds until the process is killed. Child processes
use `CREATE_NO_WINDOW` so the parent stdout is a single `KMON_FIXTURE` line.

`/replace-main` unmaps only at the original ImageBase, allocates the private
replacement at that same base, and does not resume the process. If
`VirtualAllocEx` cannot land at the original ImageBase, the scenario fails
instead of leaving PEB ImageBase unmapped.

| Flag | Artifact | Expected `process.hollow` / related layer |
|---|---|---|
| `/masquerade` | temp `notepad.exe` copy, no memory patch | `process.masquerade` |
| `/overwrite` | NOP patch on own `.text`, RX restored | `exe_cow`, `exe_text` |
| `/stamp` | in-memory `TimeDateStamp` rewritten | `hollow` |
| `/nomz` | ImageBase MZ wiped | `exe_no_mz` |
| `/orphan-private` | `VirtualAlloc` RX page with MZ | `exe_orphan_private` |
| `/orphan-image` | delete-pending `SEC_IMAGE` map, not in the loader | `exe_orphan_image` |
| `/replace-main` | suspended self-copy, EXE unmapped, private MZ, **never resumed** | `exe_private` |
| `/ghost` | running copy then delete the file | `ghost` |

`/ghost` needs `GetFileAttributesW` to fail (path gone). A delete-pending file
that is still visible is not `layer=ghost`; the fixture prints a warning in
that case.

`/orphan-image` still fires through its RX text sub-region. The orphan image
layer requires an executable region at the allocation base, so read-only
`LoadLibraryEx(LOAD_LIBRARY_AS_IMAGE_RESOURCE)` views left by icon/version
readers (single orphan `MEM_IMAGE` + `PAGE_READONLY` region) stay silent.

Stdout line:

```text
KMON_FIXTURE pid=<pid> scenario=<name> image=<path>
```

PID is also written to `%TEMP%\kn-live-dbg-kmon\artifact.pid`.

## Live `!kmon` pass

Elevated, driver loaded:

```text
write on
!kmon /background
```

Other console:

```powershell
.\x64\Release\tools\KnLiveDbgKmonTarget.exe /overwrite /seconds 60
```

Then `!kmon` to attach the tail. User-mode hostility scans every ~8s (first
tick ~1.5s after start). Repeat with `/stamp`, `/nomz`, `/orphan-private`,
`/orphan-image`, `/replace-main`, `/ghost`, `/masquerade`.

`/replace-main` leaves a suspended process; the fixture terminates it when the
hold expires.

`add` / `remove` only work after collection is already running. `/verbose` and
`/log` apply only on the first start.

## Automated primitives

`KnLiveDbg.exe --self-test console` includes `kmon-artifact-primitives`:

1. A write to self `.text` makes `QueryWorkingSetEx` Shared=0 (`exe_cow`), then
   bytes are restored.
2. A private MZ page is `MEM_PRIVATE`.
3. `GetMappedFileNameW` returns a path for the current EXE mapping.
4. If the fixture EXE is next to `KnLiveDbg.exe` (or under `tools\`), a
   `/child overwrite` process shows private COW pages.

That gate does not require `write on` or `!kmon`. It does **not** assert that
an unmodified `KnLiveDbg.exe` `.text` matches disk: reloc-aware compare of the
TUI image is not a stable negative control, which is why live `exe_text` is
builtin-only.

## Not covered here

- Live DKOM `ActiveProcessLinks` unlink (needs a kernel fixture).
- Cross-process injection into a real inbox `notepad.exe` / `svchost.exe`.
- Game + anti-cheat idle FP soak (manual on the game machine).
- Kernel mapper / pool PE / unbacked hook positives (those stay on `!pool pe`,
  `!kpage`, `!mapper`, `!callbacks`).
