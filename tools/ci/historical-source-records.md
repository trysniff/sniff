# Historical Source-Record Inventory

`audit_historical_source_records.py` inventories an existing, SHA-256-pinned
historical-v1 Actions ZIP and its pinned 600-candidate worksheet. It makes no
network requests, extracts nothing, and executes no repository source. Use the
assessment task commitment, not the worksheet's own task commitment.

```text
python tools/ci/audit_historical_source_records.py ARCHIVE WORKSHEET OUTPUT \
  --archive-sha256 ARCHIVE_SHA256 \
  --worksheet-sha256 WORKSHEET_SHA256 \
  --task-sha256 ASSESSMENT_TASK_SHA256
```

The output is create-new. Repeat the same invocation with `--verify-only` to
compare the saved inventory with a fresh derivation from the pinned bytes.
Only stored/deflated ZIP members are accepted; raw NUL names are rejected before
the ZIP reader's truncated filename can be used. Archive/member/expanded-size
bounds, normalized unique ZIP paths, contiguous
worksheet ranks, exact checkpoint/transaction assessments, all transaction file
digests and evidence bindings are required. Uncommitted files, missing records,
contradictory states and unknown evidence kinds fail instead of disappearing.
Source-inspection revisions must be distinct lowercase 40-digit Git hashes and
match the recorded discovery, selected commit, census and delta.

The mutually exclusive stages describe **saved records**, not reviewer coverage:

| Stage | Meaning |
| --- | --- |
| `failed_clone_probe_only` | Failed clone followed by an inaccessible probe; partial source access is unknown. |
| `empty_repository_recorded` | The producer recorded an accessible empty repository. |
| `complete_clone_recorded` | Complete repository discovery/commit metadata, without a source-inspection record. |
| `source_inspection_recorded` | Matching source census/delta revisions, without retained source snapshots. |
| `source_bytes_retained` | Source inspection plus hash-bound retained source files. |

The original historical-v1 runner tries a clone **before** its inaccessible
probe. A failed clone or missing retained source cannot establish no source
access. The inventory therefore always sets `source_access_absence_proven`,
`temporal_identity_proof_issued` and `benchmark_admission_performed` to false.
It neither identifies the historical repository entity nor proves creation
time, behavioral correctness, full temporal disjointness or global exposure
absence. It does not validate every semantic field of the original assessment.

Caller-supplied digests bind local bytes; they are not independent source
authentication or signed provenance. Authenticate and freeze those input
commitments separately. No admission schema or benchmark policy is changed.

Offline mutation tests are required by the CI archive-preflight job:

```text
python tools/ci/test_audit_historical_source_records.py
```
