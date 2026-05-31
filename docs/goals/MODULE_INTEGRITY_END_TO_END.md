# Module Integrity End-to-End Goal Spec

## Objective

Implement `!module integrity` as a production-quality, read-only kernel module integrity scanner for `kn-live-dbg`.

The feature must provide evidence-backed triage for loaded Windows kernel modules, with special focus on PE header integrity, executable section permissions, runtime page attributes, suspicious section layout drift, and module range anomalies.

## Repository Context

- Repository: `F:\kernullist\kn-live-dbg`
- Existing command: `!module integrity`
- Existing implementation area: `user/IntegrityScanner.*`, `user/main.cpp`, command registry, AI capability routing, and documentation.
- This task is to harden and complete the existing initial implementation, not to redesign the whole debugger.
- Keep the kernel driver narrow. Prefer user-mode parsing through existing read-only kernel memory reads and translation IOCTLs.
- All behavior must remain read-only.

## Command Surface

Preserve these forms:

```text
!module integrity
!module integrity all
!module integrity <module-substring>
!module integrity <module-substring> /limit <n>
!module integrity <module-substring> /json <path>
```

Add or complete these options where missing:

```text
/summary
/verbose
/headers
/sections
/wx
/mismatch
/json <path>
```

Expected option behavior:

- `/summary`: print only aggregate findings and warnings.
- `/verbose`: print all executable sections, not only suspicious sections.
- `/headers`: print detailed PE header evidence.
- `/sections`: print section-table details.
- `/wx`: show only modules or sections with effective W+X evidence.
- `/mismatch`: show only modules with size, header, section, or range anomalies.
- `/json <path>`: write stable UTF-8 JSON with all supported evidence.

## Module Enumeration

- Use the existing kernel module list from `SymbolEngine::Modules()` or the established module loading path.
- Match by image name or full image path substring, case-insensitive.
- Treat an empty filter and `all` as all modules.
- Report scanned, matched, suspicious, truncated, and warning counts accurately.
- Avoid false truncation accounting when `/limit` is applied.
- Do not let an unreadable or malformed module stop the whole scan.

## PE Header Validation

Read live module headers through the driver read path and validate at least:

- MZ signature.
- `e_lfanew` bounds.
- PE signature.
- machine type.
- optional header magic.
- section count.
- optional header size.
- `SizeOfImage`.
- `SizeOfHeaders`.
- `ImageBase`.
- `SectionAlignment`.
- `FileAlignment`.
- data-directory bounds where practical.

Detect and report:

- unreadable headers.
- malformed DOS header.
- invalid `e_lfanew`.
- invalid NT signature.
- unexpected optional header magic.
- suspicious section count.
- section table outside readable header range.
- module-list size versus PE `SizeOfImage` drift.
- preferred `ImageBase` versus loaded base mismatch as informational, not automatically malicious.

## Section Integrity

Parse section tables safely with overflow checks. For each section, capture:

- name.
- RVA.
- virtual size.
- raw size.
- characteristics.
- static executable, writable, and readable flags.
- whether runtime page attributes were queried.
- effective W/R/X page attributes for the probed page or pages.
- reason codes and notes.

Flag suspicious evidence:

- static W+X section characteristics.
- effective runtime W+X page permissions.
- executable section with invalid RVA or invalid range.
- section virtual range outside `SizeOfImage`.
- overlapping section virtual ranges.
- suspicious zero-size executable section.
- executable section whose first page cannot be translated/read when metadata says it should exist.

## Runtime Page Permission Probing

- Use `DeviceClient::TranslateVirtual` or existing address inspection helpers where appropriate.
- Compute effective W/X by combining all page-table levels.
- Preserve large-page handling.
- Probe at least the first page of executable sections.
- If practical without excessive overhead, probe the first and last page of executable sections or sample per-page for small sections.
- Clearly distinguish:
  - not queried.
  - query failed.
  - queried and safe.
  - queried and suspicious.
- Do not treat translation failure alone as malicious unless combined with other evidence.

## Robustness And Safety

- All address arithmetic must be overflow-checked.
- Never trust kernel-derived sizes, offsets, counts, or RVAs without bounds checks.
- Clamp large reads to existing safe transfer limits.
- Avoid crashes on corrupted PE headers, malformed section tables, invalid module ranges, or unreadable memory.
- Keep output deterministic and stable.
- Avoid excessive default output. Detailed output should require `/verbose`, `/headers`, `/sections`, or JSON.
- Keep the command strictly read-only. Do not add write IOCTLs, patching, unload, reload, or session mutation behavior.

## JSON Schema

Keep or introduce a stable schema named:

```text
kn-live-dbg.module-integrity.v1
```

JSON must include:

- schema.
- summary.
- warnings.
- records.
- per-module evidence.
- per-section evidence.
- suspicious reason codes.
- free-form notes only as supplemental text.

Requirements:

- Use machine-readable reason codes, not only free-form notes.
- Escape JSON correctly.
- Write valid UTF-8 JSON.
- Keep the schema stable and documented in code/docs.

## AI Capability Integration

Ensure `module.integrity` AI capability routes to the improved native command.

AI args to support:

- `target`
- `module`
- `name`
- `limit`
- `summary`
- `verbose`
- `headers`
- `sections`
- `wx`
- `mismatch`

Requirements:

- Validate every AI arg before execution.
- Reject unknown args.
- Preserve strict read-only routing.
- Reject raw debugger command generation, command chaining, nested `ai`, write-like actions, unload/shutdown/session mutation, multiline commands, and unsafe characters.
- Preserve existing AI capability tools and behavior.

## UX Requirements

- Update `!module` help text.
- Update completion candidates for new options.
- Make suspicious evidence visually clear.
- Keep normal default output concise.
- Support both quick operator triage and detailed forensic review.
- Ensure no in-command output uses non-ASCII comments or log strings.

## Documentation

Update:

- `README.md`
- `docs/AI_ASSISTED_WORKFLOWS.md`
- `docs/WINDBG_COMMAND_COVERAGE.md`
- `docs/ARCHITECTURE.md` if scanner flow changes.
- `docs/FEATURE_PLAN.md`

Add examples:

```text
!module integrity
!module integrity ntoskrnl /verbose
!module integrity all /wx
!module integrity WdFilter /headers /sections
!module integrity all /json .\module-integrity.json
ai inspect module text integrity
```

## Validation

Run:

```powershell
.\tools\build.ps1 -Configuration Debug
.\tools\build.ps1 -Configuration Release
git diff --check
```

Perform a self-review focused on:

- PE parsing bounds.
- integer overflow.
- live memory read failure paths.
- JSON validity.
- command option parsing.
- AI arg validation.
- false-positive risk.
- output stability.
- read-only enforcement.
- no regression to existing AI capability tools.

If a live driver session is available, smoke-test:

```text
!module integrity ntoskrnl
!module integrity all /limit 5
!module integrity all /json .\module-integrity.json
ai inspect module text integrity
```

## Code Style

- Follow the existing repository style.
- Default to C++.
- Comments and log/output strings must be ASCII-only.
- Opening braces must be on the next line.
- Closing braces must be on their own line.
- Always use braces for `if`, `else`, `for`, and `while`.
- `else` must be on its own line followed by `{` on the next line.
- Prefer single-exit `do { ... } while (false)` patterns where practical.
- Keep changes scoped to module integrity and directly required AI/docs wiring.

## Completion Criteria

The task is complete only when:

- `!module integrity` supports the required command surface.
- PE header and section validation are robust against malformed live memory.
- runtime W/X probing is evidence-based and overflow-safe.
- JSON output is valid and stable.
- AI routing supports the improved options with strict validation.
- docs reflect the actual behavior.
- Debug and Release builds pass.
- `git diff --check` passes, allowing existing CRLF normalization warnings.
- a self-review has been performed and any found bugs are fixed.
- no commit or push is made unless explicitly requested.
