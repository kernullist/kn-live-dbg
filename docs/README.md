# Documentation

Current implementation baseline: **v0.0.36 / af8f2d0**. Documentation reviewed
against that source on **2026-10-27**. This review updates documentation; it is
not a new live-host test or release.

## Operation

| Guide | Contents |
| --- | --- |
| [Project README](../README.md) | Download, quick start, scope |
| [Build and release](BUILD_AND_RELEASE.md) | Toolchain, signing, versioning, package validation, public-content checks |
| [Command guide](COMMAND_REFERENCE.md) | Memory, scanners, snapshots, collection, dumps |
| [Command coverage](WINDBG_COMMAND_COVERAGE.md) | Native and DbgEng routing |
| [AI workflows](AI_ASSISTED_WORKFLOWS.md) | Configuration, plans, confirmation, logs |
| [MCP setup](MCP_SETUP.md) / [한국어](MCP_SETUP.ko.md) | HTTP setup, permissions, troubleshooting |
| [MCP catalog](MCP_TOOL_REFERENCE.md) | Tools, arguments, resources, prompts |
| [Remote setup](REMOTE_SETUP.md) / [한국어](REMOTE_SETUP.ko.md) | Human remote console |
| [Timeline](TIMELINE_COMMAND_USAGE.md) / [한국어](TIMELINE_COMMAND_USAGE.ko.md) | Ingestion, queries, comparison, exports |

## Detection and implementation

| Guide | Contents |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Source map, IOCTLs, concurrency, callback lifetime |
| [KMON coverage](KMON_DETECTION_COVERAGE.md) | Supported observation paths and limitations |
| [Code verification](KMON_DETECTION_VERIFICATION.md) | Identity, relocations, comparison and coverage fields |
| [Cross-domain hunting](KMON_CROSS_DOMAIN_HUNTING.md) | Relationships, capture, replay, comparison limits |
| [Analyst surfaces](KMON_ANALYST_SURFACES.md) | TLS, KCT, WorkerFactory and snapshot interpretation |
| [Process layouts](KMON_PROCESS_LAYOUTS.md) | Whole-process discovery, history, scheduling |
| [Driver interaction](DRIVER_INTERACTION_TRACKING_DESIGN.md) | Handles, IOCTL observations and lifetime limits |
| [MCP design](MCP_SERVER_DESIGN.md) / [한국어](MCP_SERVER_DESIGN.ko.md) | HTTP and engine contracts |
| [Remote design](REMOTE_OPERATOR_SESSION.md) | Framing, queue, disconnect and shutdown |
| [Remaining work](FEATURE_PLAN.md) | Open work, separated from implemented features |

## Validation and releases

- [Validation status](VALIDATION.md): release evidence, known gaps, and links to
  the original dated reports at v0.0.36. Those reports remain historical records
  in Git; their results are not refreshed by this documentation review.
- [Manual checklist](MANUAL_TEST_CHECKLIST.md): rerun instructions and acceptance
  criteria, including pending-I/O and runner-failure tests.
- [KMON test target](KMON_TEST_TARGET.md) and [hunt test target](HUNT_TEST_TARGET.md).
- [Research claim ledger](../research/evasion-research-ledger.json): source dates,
  evidence requirements, and limits. Documentation edits do not renew research
  freshness or satisfy external validation gates.
- Release notes: [0.0.36](RELEASE_NOTES_0.0.36.md),
  [0.0.35](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/RELEASE_NOTES_0.0.35.md),
  [0.0.34](https://github.com/kernullist/kn-live-dbg/blob/v0.0.34/docs/RELEASE_NOTES_0.0.34.md),
  [0.0.33](https://github.com/kernullist/kn-live-dbg/blob/v0.0.33/docs/RELEASE_NOTES_0.0.33.md).
  Published notes retain their release context.

Keep current usage in these guides, immutable test observations in versioned
evidence, and proposals in the remaining-work document. Avoid copying complete
command grammars or historical test totals into multiple guides.
