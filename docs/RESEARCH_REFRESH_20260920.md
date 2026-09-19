# Evasion research ledger refresh - 2026-09-20

The v0.0.33 release review revisited the 22 primary-source entries in [the research ledger](../research/evasion-research-ledger.json) and checked its eight discovery endpoints. The previous review date was 52 days old, beyond the existing 45-day packaging limit. That limit is unchanged.

This refresh checks source availability, published claims and their relation to the current implementation. It uses the research pages, paper abstracts, documented API contracts and pinned source excerpts listed below. It does not reproduce the papers' experiments or establish complete coverage of work published since the previous review. Research dates and historical validation results remain separate from this review date.

## Source checks

| Primary source | Finding retained in the ledger |
| --- | --- |
| [Bitdefender Bind Link research](https://www.bitdefender.com/en-gb/blog/businessinsights/bind-link-abuses-windows-feature-edr-evasion-technique) | File-, process- and silo-scoped redirection are distinct. Current global-map evidence does not establish silo coverage. |
| [Elastic Cloud Files / FFI](https://www.elastic.co/security-labs/threat-command/immutable-illusion) | Current file identity and trust do not reconstruct earlier backing-content changes. The article's patch-status discussion is dated February 2026. |
| [ESET EDR killers](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/) | Driver reuse, process suspension and communication impairment need separate evidence; a driver name alone does not identify an operator. |
| [Atomic Red Team T1685](https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1685/T1685.yaml) | QoS test GUID `7dd05b3e-0803-4852-9345-c494eb3e40fe` still describes per-application throttling to eight bits per second. The test was read, not executed. |
| [Elastic ABYSSWORKER](https://www.elastic.co/security-labs/threat-command/abyssworker) | Callback removal, dispatch replacement and filter interference remain relevant observation surfaces. |
| [SafeBreach PoolParty](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) | The eight variants use worker-factory and thread-pool queue structures. Resident code evidence alone does not enumerate those structures. |
| [SafeBreach Windows Downdate](https://www.safebreach.com/blog/update-on-windows-downdate-downgrade-attacks/) | Component rollback is a separate attestation problem. Its historical demonstrations are not a current Windows patch-status assertion. |
| [MITRE DET0577](https://attack.mitre.org/detectionstrategies/DET0577/) | KernelCallbackTable modification and subsequent GUI callback execution require dedicated observations. Page version 1.0, modified May 12, 2026. |
| [MITRE DET0467](https://attack.mitre.org/detectionstrategies/DET0467/) | TLS-directory modification and pre-entry execution need a dedicated baseline. Page version 1.0, modified May 12, 2026. |
| [BYOVD Detector paper](https://link.springer.com/article/10.1186/s42400-025-00434-w) | Symbolic dispatch reachability and read-result verification exceed artifact-catalog matching. |
| [NDSS 2026 BYOVD paper](https://www.ndss-symposium.org/wp-content/uploads/2026-s1491-paper.pdf) | The authors correlate originating requests with kernel execution using virtualization. These are the paper's results, not KnLiveDbg measurements. |
| [PsLookupProcessByProcessId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid) | A successful lookup returns a referenced opaque EPROCESS; documented failure semantics support a comparison surface. |
| [PsLookupThreadByThreadId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupthreadbythreadid) | A successful lookup returns a referenced ETHREAD. Internal layouts still require independent qualification. |
| [Pinned Volatility handle parser](https://github.com/volatilityfoundation/volatility3/blob/fffd844b8ed7df500e74115a0ee6f818e6afa59f/volatility3/framework/plugins/windows/handles.py) | TableCode level bits and recursive table-page traversal provide a structural reference, not a supported Windows ABI. |
| [Pinned ReactOS handle implementation](https://github.com/reactos/reactos/blob/c606fd79b1c879bad37e49a69e71986dfbc2052e/ntoskrnl/ex/handle.c) | Allocation bounds and level lookup provide a comparative reference; they do not authorize fixed Windows offsets. |
| [RX-INT, arXiv v1](https://arxiv.org/abs/2508.03879) | Event-driven observation and stateful memory hashing address gaps left by periodic scans. Its comparative results were not rerun here. |
| [LASE, arXiv v2](https://arxiv.org/abs/2505.06498) | Longitudinal kernel evidence serves a different purpose from a current-memory snapshot. |
| [Trace of the Times, arXiv v1](https://arxiv.org/abs/2503.02402) | Timing-distribution measurements are a separate detection method; KnLiveDbg does not implement this paper's calibrated timing detector. |
| [EvilEDR, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/alachkar) | Trusted response tooling can be repurposed. Local memory cannot establish remote operator authorization. |
| [Mandiant attestation-signed malware](https://cloud.google.com/blog/topics/threat-intelligence/hunting-attestation-signed-malware) | A Microsoft attestation signature does not establish benign runtime behavior. |
| [Microsoft Bindlink API](https://learn.microsoft.com/en-us/windows/win32/bindlink/) | Bind links redirect a virtual namespace to backing paths without creating physical entries at the virtual path. |
| [FilterVolumeInstanceFindFirst](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtervolumeinstancefindfirst) | The API exposes a documented volume-instance view; results depend on the requested information class. |

Elastic's article and discovery links now use their redirected `threat-command` locations. The pinned Volatility and ReactOS revisions are unchanged.

## Discovery checks and limits

| Endpoint | Observation on this review |
| --- | --- |
| [Bitdefender Business Insights](https://www.bitdefender.com/en-gb/blog/businessinsights/) | The initial index fetch succeeded, but follow-up retrieval timed out. The cited Bind Link article was readable. Index coverage is incomplete. |
| [Elastic Platform Internals](https://www.elastic.co/security-labs/threat-command/category/platform-internals) | The index includes the Cloud Files article and Linux-specific research. Linux-only entries were not added to this Windows ledger. |
| [ESET Research](https://www.welivesecurity.com/en/eset-research/) | The visible index includes SparroWocky and UEFI shim research. Index presence does not establish coverage of either family. |
| [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) | The visible index was checked; its dynamically loaded archive was not exhaustively traversed. |
| [MITRE updates](https://attack.mitre.org/resources/updates/) | The current index identifies v19.2, August 6, 2026, as a targeted Groups/Software update. DET0577 and DET0467 were checked separately. |
| [SafeBreach research hub](https://www.safebreach.com/breach-and-attack-simulation-research-and-news/) | The old `/resources/research/` endpoint was unavailable. The Labs page linked a working research hub, now recorded in the ledger. |
| [arXiv cs.CR recent](https://arxiv.org/list/cs.CR/recent) | The visible first page covers September 18 and 17 entries. This is not a complete search of the September corpus. |
| [Atomic Red Team T1685](https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1685/T1685.yaml) | The live file and the specific QoS test were checked. Upstream remains mutable. |

`last_checked_on` records a discovery attempt, including the limitations above. It is not a claim that an entire publisher archive was inspected.

## Implementation claims after review

The in-memory entry now points to executable-page inspection and executable-image verification as well as existing user-mode triage. Its old limitation understated resident headerless-code coverage. The replacement records the actual gaps: bounded scheduling, unreadable or unobserved ranges, and mappings that disappear between observations. The PoolParty entry likewise no longer implies that code must execute before memory inspection can notice it.

No technique status or release gate was promoted. Dedicated dormant thread-pool traversal, TLS/KernelCallbackTable baselines, unknown-driver semantic analysis, component rollback attestation and timing-distribution detection remain unsupported or backlog work as recorded in the ledger. Kernel/user case correlations remain evidence for investigation, not proof of a communication channel or complete game-cheat recall.
