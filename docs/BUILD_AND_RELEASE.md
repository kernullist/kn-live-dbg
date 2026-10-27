# Build and release

The current release is **0.0.36**. Its release build used Visual Studio 2022,
the v143 toolchain, and matching SDK/WDK **10.0.26100.0**. These are the tested
inputs, not a claim that every other toolchain or Windows build is supported.

## Prerequisites

- Visual Studio 2022 or its Build Tools with MSBuild, MSVC x64, DIA SDK, and the
  `WindowsKernelModeDriver10.0` toolset. Install the WDK integration and required
  Spectre/ATL libraries if MSBuild reports them missing.
- A matching Windows SDK and WDK. The projects default to `10.0.26100.0`;
  check that its `km\ntddk.h` and x64 driver platform toolset exist.
- A WDK test-signing certificate with a private key accessible to the build
  account. Test-signing on a target host and certificate selection on the build
  host are separate requirements.
- Python 3.11+ x64 for release content checks and source-only lifecycle/evidence validators.
  AddressSanitizer gates also require the matching MSVC x64 ASan runtime.

`tools/build.ps1` discovers Visual Studio/MSBuild/DIA through installed instances.
It stages the [pinned runtime](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/vendor/README.md) beside the EXE, with a local
Windows Kits fallback if the vendor pair is absent. Refresh the pinned runtime
only intentionally with `tools/sync-debugging-tools-runtime.ps1`; its manifest
must match the files being distributed.

## Build

From the repository root:

```powershell
.\tools\build.ps1 -Configuration Release
.\tools\build.ps1 -Configuration Debug
```

Both build and release helpers accept `-WindowsTargetPlatformVersion` and
`-TestCertificateThumbprint`. For example, select the installed kit and your own
certificate explicitly:

```powershell
.\tools\build.ps1 -Configuration Release `
  -WindowsTargetPlatformVersion 10.0.26100.0 `
  -TestCertificateThumbprint <40-hex-thumbprint>
```

The certificate must be in `CurrentUser\My` with an accessible private key.
Selection does not modify trust stores. The helper checks driver signing
metadata after the build; a lab test signer is not production signature approval.
The v0.0.36 signer and compatibility details are in its
[release notes](RELEASE_NOTES_0.0.36.md), not a reusable signing credential.

Build before loading any owned fixture. Do not replace a SYS file while its
service is loaded or run competing fixture suites during a build.

## Versioning

Normal builds reuse the highest version from `.build/version-state.json`,
existing output, and exact reachable `vX.Y.Z` tags. `-BumpVersion` increments
the patch version deliberately; a checkout with none of those inputs starts
from `0.0.0`. The generated resource header lives under `.build/generated`.
Direct project builds without the helper retain the fallback in
`shared/KnLiveDbgVersion.h`.

The helper stamps the console, main driver, probe, minifilter fixture, and Bind
controller together. The BYOVD metadata fixture intentionally stays at
`1.0.0.0`. ABI versions are independent of PE/release versions: main 17,
probe 2, managed callback protocol 1, and pending-I/O protocol 7.

## Validate and package

Use the [manual checklist](MANUAL_TEST_CHECKLIST.md) for applicable component
and live-host tests. Record the binaries' hashes, host build, boot interval,
failed runs, coverage gaps, and cleanup results.

For a new release, choose the version from the current state and tags, create
the matching `docs/RELEASE_NOTES_<version>.md`, then build that version once:

```powershell
.\tools\build.ps1 -Configuration Release -BumpVersion
# Run the applicable validation on these exact binaries.
.\tools\release.ps1 -Configuration Release -SkipBuild
```

`release.ps1` normally builds and bumps. Use `-SkipBuild` to package already
validated output, or `-NoVersionBump` when a build without a new version is
intended. Do not accidentally bump again after validating a candidate.
The helper requires version-matching notes and validates the research ledger's
freshness and evidence contract; do not relax those checks to make packaging pass.

The helper creates `release/KnLiveDbg-<version>-Release-x64.zip`. Generate
`release/SHA256SUMS.txt` from the final ZIP before upload; the helper does not
refresh that checksum file. The ZIP includes public guides, runtime, binaries,
public certificates, and `kn-live-dbg-version.json` with
per-file sizes and SHA-256 hashes. Source-only race runners and local raw test
artifacts are not implied by the package contents.

Before upload, check ZIP integrity, every manifest hash/size, matching PE
versions, required DLLs/drivers/notes, packaged startup help, and absence of
private keys. Preserve the intentional BYOVD version exception.

Current packaging runs the offline content check before creating the ZIP
(`-PythonExecutable` selects a Python installation; the default is `python`).
It excludes private PDBs by default. PDBs can contain absolute
source paths and build-account details. For a reviewed internal diagnostic
package, use `-IncludePrivateSymbols`; this deliberately opts in to that metadata
and provides the types/source symbols omitted from the normal package. Earlier
published releases, including v0.0.36, included PDBs. This policy change does not
alter their existing assets.

The symbol opt-in permits PDB paths, while credential checks still apply. To
review an intentionally private symbol package manually, add
`--allow-private-symbols` to the content check below.

Only named project certificates, catalogs and optional PDBs are collected;
unrelated files in the build directory are ignored. Both ordinary inputs and
research-ledger anchors reject local-state directories, credential containers,
environment files other than `.env.example`, and raw logs/dumps. A `.cer` must
actually be a public X.509 certificate, not a renamed private-key container.

## Public-content check

Before staging or packaging source changes, run the offline check with Python
3.11+ from the source checkout:

```powershell
python tools/validate-public-content.py
# After staging, inspect the exact Git index as well:
python tools/validate-public-content.py --index
# Inspect all files in a prepared package, including ignored files:
python tools/validate-public-content.py --tree --root <staging-directory>
```

The default checks current tracked files and non-ignored untracked files. It
reports only locations/rule names, and exits nonzero on findings or unreadable
inputs. `--index` reads staged blobs even when working-tree bytes differ. Known
token/private-key patterns, credential files, and personal home paths are
checks, not proof that arbitrary text or media is safe. Review unknown password
formats, screenshots, videos, transcripts and captures separately. Public IoC
hashes, synthetic test credentials and public certificate thumbprints are not
private keys.

Keep `.env` variants, authentication state, private signing keys and raw host
captures outside publication inputs. Ignore rules do not protect already tracked
files or `git add -f`. Public certificates and signed PE files disclose signer
identity; review certificate subjects before signing and prefer a project-only
test identity when personal account attribution is unwanted. Do not edit signed
PE bytes to hide identity, since this invalidates the signature.

Removing a current-tree value does not erase older commits, tags, release assets
or downloaded copies. If a real credential is found, revoke/rotate it before
coordinating historical cleanup. Do not overwrite a published version silently.

## Publish

Use the previous release's notes structure, but state only results obtained for
the actual candidate or clearly identified historical binaries. Keep remaining
coverage and compatibility limits visible.

After committing the reviewed source and notes, create an annotated version tag
at that commit and push the branch and tag. Upload the ZIP and checksums as a
GitHub draft with the notes file. Verify the draft's tag, target commit, asset
names/sizes/digests, and body before publishing it as the latest release.
Finally verify the public release and downloadable checksum. Do not silently
replace an already published ZIP under the same version.
