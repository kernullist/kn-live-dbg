# Corpus evaluation contract

`tools/evaluate-corpus.py` evaluates imported case-level declarations. It does
not run a collector, open the referenced artifacts, authenticate ground truth,
or establish independent detection performance. The four evidence layers stay
separate: `synthetic`, `owned_fixture`, `authorized_sample`, and
`independent_comparison`. Reports contain no overall tool ranking or inferred
safety/compatibility result.

## Run the synthetic example

Python 3.11 and the standard library are sufficient. From the repository root:

```powershell
# Choose a new directory; existing example directories are not overwritten.
python tools/test-corpus-evaluator.py --example-directory .build/corpus-example
python tools/evaluate-corpus.py --corpus .build/corpus-example/corpus.json --results .build/corpus-example/results.json
```

The example has 14 synthetic cases, seven positive ground truths and two true
positives. End-to-end recall is **2/7**; observable-scope recall is **2/4**.
Unavailable, errored and missing positive cases remain in the first denominator.
Two cases share a declared independence group, so they are not presented as
independent samples. The fixture's hashes identify synthetic declarations, not
real collected binaries or detection evidence. All three schemas below are
private investigation data and the public-content scanner rejects their JSON
artifacts from source commits.

## Input schemas

Each input is strict UTF-8 JSON without a BOM, at most 8 MiB. Duplicate members,
non-finite constants, unknown/missing fields and unsupported schema versions
fail with exit code 2 and no report on stdout. Each identifier below is 1..128
ASCII letters/digits or `_.:-`, beginning with a letter/digit. Hashes are exactly
64 lowercase hexadecimal characters. Null is allowed only where specified.
Both inputs are read once; the report records their exact SHA-256 hashes.

The corpus root requires `schema="kn.benchmark_corpus.v1"`, `corpus_id`,
`cohort_id`, `environment` and `cases` (1..4096 entries).

| Environment field | Meaning |
| --- | --- |
| `target_id`, `snapshot_id` | Declared target and acquisition identity; use explicit synthetic IDs for fixtures |
| `os_build` | Identifier or null for unknown |
| `architecture` | `amd64`, `arm64`, `x86` or `unknown` |
| `hvci`, `vbs`, `verifier` | Boolean or null; never inferred from a passing parser test |

| Case field | Meaning |
| --- | --- |
| `id` | Unique case identifier |
| `family` | Declared family; not interchangeable with independent sample count |
| `independence_group` | Shared ID for correlated variants/repeats |
| `partition` | `development` or `heldout` |
| `layer` | One of the four evidence layers above |
| `task` | Exact comparison task, such as `image-range-mismatch` |
| `unit` | `case`, `entity`, `page`, `event` or `claim`; assertion counts are not a unit |
| `artifact_sha256`, `holes_sha256` | Declared source artifact and hole-map identities; empty-hole maps also need an identity |
| `truth` | `positive`, `negative` or `unknown` for this task, not a generic maliciousness label |
| `truth_ref_sha256` | Ground-truth reference hash; may be null only for unknown truth |

A family, independence group or identical source artifact may not cross the
development/heldout boundary. This rejects obvious leakage, including renamed
families sharing bytes; it cannot discover undeclared semantic relationships.
Different holes in the same artifact do not make separate heldout material.

The results root requires `schema="kn.benchmark_results.v1"`, `corpus_sha256`
(hash of the exact corpus file bytes), `run_id`, `tool`, and `assessments`.
`tool` requires `name`, `version`, `binary_sha256` and `config_sha256`. These are
declared identities; the evaluator does not inspect those files.

| Assessment field | Meaning |
| --- | --- |
| `case_id` | A known corpus case, at most once per run |
| `artifact_sha256`, `holes_sha256` | Must exactly match that case's declared scope |
| `outcome` | `positive`, `negative`, `abstain`, `unavailable` or `error` |
| `evidence_sha256` | Assessment evidence hash; may be null only for unavailable/error outcomes |
| `elapsed_us` | Reported unsigned 64-bit integer microseconds or null; booleans, fractions and numeric strings are rejected |

There may be zero assessments. Omitted cases become `missing`; extra case IDs
and duplicate assessments fail. Keep repeated runs in separate result files;
the evaluator does not choose the best repeat or merge them into independent
samples. Findings from another scope or another tool policy require a separately
adjudicated assessment, not automatic conversion into false positives.

## Report semantics

`kn.benchmark_report.v1` is UTF-8 JSON on stdout, capped at 16 MiB. A comparison
scope is `(layer, partition, task, unit)` within the declared cohort/environment.
At most 512 scopes are allowed. Each scope has aggregate and per-family counts;
there is no aggregation across different scopes or environments.

- `end_to_end_recall`: true positives / all declared positive ground truths,
  including abstentions, collection failures, errors and missing results.
- `observable_scope_recall`: true positives / positive ground truths whose
  outcome is positive, negative or abstain. Unavailable/error/missing outcomes
  are outside this denominator and remain visible in the outcome counts.
- `precision_known_truth`: true positives / positive predictions with known
  ground truth. Positive predictions with unknown truth are reported separately
  and are not silently declared correct or false.
- `false_positive_rate_observable`: false positives / observed negative ground
  truths, including abstentions. It does not claim a full-environment FPR.

Each ratio includes its numerator and denominator; a zero denominator produces
null, not zero or 100%. Unknown truth remains unscored and explicitly counted.
Latency summaries include any reported failed attempts and show known/unknown
counts, nearest-rank P50/P95/P99 and maximum, encoded as decimal microsecond
strings to preserve 64-bit values. These are imported timings, not measurements
made by this program; cases without timings do not become zero-latency samples.

Declared independence-group counts and correlated variants are shown. No
uncertainty interval is synthesized from unverified or correlated observations.
Actual independent sampling, uncertainty estimation, authorized corpora, live
collection overhead/safety and external-tool comparison remain separate work.
`ground_truth_authenticated`, `target_probed`, `artifacts_opened` and
`independent_detection_validation` are always false in this evaluator.
