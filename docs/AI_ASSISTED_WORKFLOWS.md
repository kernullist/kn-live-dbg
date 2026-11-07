# AI-assisted workflows

KnLiveDbg's `ai` command proposes investigation commands from operator text and
explains explicitly reviewed, minimized image facts. Captured stdout/stderr stays
local. The implementation is in `user/AiProvider.cpp`, `AiModelCatalog.cpp`,
`AiCapabilityCatalog.cpp`, and the main dispatcher. It does not change the
kernel, MCP or remote-console permission contracts.

## Configure a provider

```text
ai status
ai use <preset|model> [model]
ai models [query]
ai models refresh
ai test
ai save
```

| Preset | Configured transport | Code default |
| --- | --- | --- |
| `cloud` | OpenRouter HTTP | `anthropic/claude-opus-5` |
| `cheap` | OpenRouter HTTP | `openai/gpt-oss-120b` |
| `deepseek` | DeepSeek HTTP | `deepseek-chat` |
| `private` | External Codex CLI process | CLI configuration/default |
| `chatgpt` | Codex OAuth HTTP | `gpt-5.5` |
| `off` | Disabled | None |

These are defaults in this source version, not a current model-availability or
pricing recommendation. `ai models` shows built-in aliases and cached catalog
entries; `ai models refresh` queries OpenRouter for current IDs. Ambiguous names
must be narrowed. Provider/model mismatches and extra arguments are rejected.
`gpt` aliases select OpenRouter; `chatgpt` selects the OAuth transport.

The advanced interface is `ai config`: provider, policy, model, base URL, effort,
auth and tests. Use its help for arguments. Configuration is loaded only from
`.env` beside the EXE, with process environment variables taking precedence.
See [.env.example](../.env.example). `ai use`, `ai save`, and supported config
changes merge the provider/model/policy into that file while preserving other
keys. Base URL, effort and timeout can also be configured there. A save failure
does not roll back the changed in-memory session.

`allow-remote` is the default. `local-only` blocks this process's HTTP provider
calls and model refresh. It still permits the external CLI used by `private`;
that CLI can itself contact a remote service. The preset name and policy do not
guarantee offline inference or no network egress by child processes.

## Investigate

```text
ai explain !callbacks
ai explain !vbs
ai plan inspect suspicious callback ownership
ai run
ai run 1
ai playbook list
ai transcript C:\evidence\ai-session.jsonl
ai report C:\evidence\report.md
```

`ai <goal>` can route recognized read-only commands and local capability queries
to local evidence collection. Automatic raw-output explanations, including
`ai explain` and `ai analyze`, stop at the provider boundary until a supported
minimized package is prepared and approved. `ai ask` requests advisory text;
`ai chat` requests a catalog plan from the operator's text. Session-expanded
PID/image/address/dump hints and symbol paths are not appended to remote prompts.
Use explicit planning when you need to inspect proposed commands first.

Plans use `kn-live-dbg.ai-plan.v2` and include purpose, risk, backend expectation
and expected output. `ai run [index|all]` rejects write-like, shutdown/unload and
nested AI commands. An index can be omitted for a single read-only item.
Raw command wrapping or chaining cannot turn a mutation into an approved read.

Model explanations remain interpretations. Keep the underlying bytes, identity,
coverage, warnings and command output. A name, signature or model confidence
cannot turn an unread region into verified evidence.

## Review minimized image evidence

```text
KnLiveDbg.exe --offline !kmon redact-image C:\evidence\case C:\evidence\review-1 /json
KnLiveDbg.exe --offline !kmon disclosure C:\evidence\review-1 /json
ai share preview C:\evidence\review-1
ai share send <review-id-from-preview> confirm
ai share cancel
```

The source can be a recipe directory, `recipe.knverify`, `.knslice` or `.knsweep`.
Original-policy replay must succeed. The new private package requires EFS by
default; `/acl-only` explicitly selects ACL protection without encryption. The
derivative contains comparison counts, scope and fixed limitations. Original
paths, addresses, bytes, source text and hashes stay in the private local evidence
and linkage sidecar. An unread or unobserved range is never promoted to a match.

Preview displays the exact payload and system instructions, provider endpoint,
model and applicable OAuth refresh endpoint. It sends nothing and retains file
leases. Send requires the matching review ID, `confirm`, unchanged provider
settings/credentials and a committed private intent. Approval is used once, even
when dispatch or the response fails. The private outcome record distinguishes a
received completion from unknown delivery; a missing result leaves the intent
unresolved. Review again before making a new transfer decision. The OAuth path
may refresh and retry the same logical completion; exactly-once delivery and
recipient retention are not established.

Only HTTP providers with `allow-remote` support this evidence route. Remote console
approval, nested AI plans and external CLI evidence transfer are blocked. The
`private` preset remains an external CLI, not offline inference. Operator-authored
prompts are still intentionally sent to their selected provider; this does not
sanitize text pasted by an operator or confine other applications. The returned
explanation is advisory and never parsed as an executable plan. Packages and
transfer records remain private even after approval. See the
[architecture and trust limits](ARCHITECTURE.md#minimized-image-disclosure).

## Confirm a planned write

```text
ai write
ai write confirm
ai write 1 confirm
```

Preview without `confirm` shows the supported target/size/context, backup or
read-current, restore-current when possible, translation and verification plan.
Only `confirm` dispatches the planned mutation. The local driver write gate must
also permit it. Recognized writes perform preflight reads and compare before/after
verification output; unsupported or incomplete backups cannot promise restoration.
`[1]` in a plan is an item index, not another interactive menu.

## Records and limits

`ai transcript` records AI events and dispatched command output after it is
enabled. `ai transcript max` and `ai transcript redact` control rotation and
output redaction. `ai audit <path>` records write-like commands passing through
the normal dispatcher; MCP has its own automatic audit independent of this toggle.
Use each command's help for supported switches and persistence behavior.

Provider credentials and external service policy remain external dependencies.
Do not copy credentials into reports. Collected memory strings, paths and code
are analysis data, not authorization to expand a plan. A generated report is
not a replacement for the [validation evidence](VALIDATION.md) or its limitations.
