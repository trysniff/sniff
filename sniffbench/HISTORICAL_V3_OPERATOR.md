# Historical-v3 Operator

This is a maintainer workflow for constructing the candidate-blind historical-v3
cohort. It is not a normal `sniff` scan. No real v3 candidate collection has
been run or authorized by this document.

All JSON paths below must be absolute. Keep the operator root outside the
source repository and retain it between invocations. A missing or mismatched
artifact fails the command; it does not restart with a new cohort.

## Post-August-7 Source Frames

The six [source-frame policies](historical-v3-source-frames/) were fixed before
collection or inspection of candidate identities. Each collects the entire
August 8-14, 2026 UTC period. SHA-256 of
`sniff-historical-v3-post-aug-2026-09-26-<language>` supplies the seed; its
first eight hexadecimal digits modulo seven select the starting day, and the
collector then rotates through all seven days. The seed changes ordering,
not inclusion. The policy fixes the GitHub API, all 168 hourly partitions,
filters, and immutable-ID ordering. Every admitted repository must have `created_at` strictly
after `2026-08-07T20:46:11Z`; a matching name is not identity proof.

After the policy commit is public and immutable, collect each language's
frame with `sniff benchmark collect-frame POLICY STATE_ROOT FRAME_CSV MANIFEST
--transport gh`. This explicit transport requires an authenticated GitHub CLI
(`gh`) in `PATH`; there is no automatic fallback to the Rust HTTP client.
Retain every raw page under its durable state root, then use
`sniff benchmark validate-frame MANIFEST STATE_ROOT FRAME_CSV` to replay it.
Use a different new state root and output pair for each policy; do not reroll
or select a replacement period after seeing yield. Collection uses the GitHub
API, not an LLM. These seven-day frames may still fail to supply the desired
number of real behavior-preserving slop cases. That remains an observed
benchmark limitation, not permission to change the frozen selection rule.

## Frozen Prior Identities

`prior-sources.json` points to the exact historical-v2 frame artifact and to
the original LF source artifacts used by that frame's exclusion manifest:

```json
{
  "artifact_root": "/absolute/frozen-v2-source-root",
  "frame": "/absolute/frozen-v2-frame/frame.json",
  "exclusions": "/absolute/frozen-v2-frame/exclusions.json",
  "selection": "/absolute/frozen-v2-frame/selection.json"
}
```

The four inputs are checked against the frozen file hashes. Exclusions are
rederived from the original source artifacts, and the fixed-slot selection is
replayed. A Windows checkout with converted CRLF fixture bytes is not the
original LF source artifact root. No handwritten repository-list input is
accepted.

```console
sniff benchmark historical-v3 seal-prior prior-sources.json prior-seal.json
```

## Protocol And Config

Prepare a draft protocol bound to that seal and the six completed source-frame
manifests, then seal it:

```console
sniff benchmark historical-v3 seal-protocol draft-protocol.json protocol.json
```

Before `collect`, the exact sealed protocol bytes and each source-frame policy
must be published at immutable, public GitHub commits. The operator checks
unauthenticated GitHub commit objects, exact protocol bytes, and the semantic
content of each policy. A self-hash or a branch URL is not sufficient. A proof
of those public responses is retained under the operator root for strict
offline replay.

The operator config JSON has these required fields:

| Field | Value |
| --- | --- |
| `protocol` | Absolute path to the sealed v3 protocol JSON. |
| `public_protocol_url` | Public `https://raw.githubusercontent.com/OWNER/REPO/COMMIT/PATH` URL for those exact bytes; `COMMIT` is a lowercase 40-character SHA. |
| `prior_identity_seal` | Absolute path to `prior-seal.json`. |
| `prior_sources` | The four-path object shown above. It is reverified on every load. |
| `source_frames` | Exactly six ordered objects, one per protocol language: Go, JavaScript, Kotlin, Python, Rust, TypeScript. Each has absolute `manifest`, `artifact_root`, and `frame` paths plus `public_policy_url` at an immutable public commit. |
| `operator_root` | Absolute path to a new, dedicated durable state directory. |
| `github_token_env` | Name of the environment variable holding a GitHub token for candidate collection, for example `GITHUB_TOKEN`. The public precommit proof itself is unauthenticated. |
| `docker_program` | Docker executable or absolute path used for sealed identical-test execution. |

```console
sniff benchmark historical-v3 init operator-config.json
sniff benchmark historical-v3 preflight operator-config.json
sniff benchmark historical-v3 collect operator-config.json
sniff benchmark historical-v3 status operator-config.json python
sniff benchmark historical-v3 run operator-config.json python --max-steps 8
```

`preflight` verifies the public immutable commitments and retains their proof
without collecting candidates or requiring a collection token. An existing
proof is replay-validated offline rather than silently replaced. `collect`
requires that proof and never fetches it implicitly; it resumes retained raw
pages and never calls a model. `status` is a read-only replay. `advance`
performs exactly one verified stage; `run` stops at
the current rank's human-review handoff, a terminal stop, or its step cap.
Operational failures keep the same rank open for retry.

## Independent Review

For a rank reported as `human_review`, prepare source-only worksheets, have
two independent humans complete them separately, then validate and audit both.
The CLI never fabricates their decisions.

```console
sniff benchmark historical-v3 prepare-review operator-config.json python
sniff benchmark historical-v3 validate-review operator-config.json python 1
sniff benchmark historical-v3 validate-review operator-config.json python 2
sniff benchmark historical-v3 audit-review operator-config.json python
sniff benchmark historical-v3 prepare-resolution operator-config.json python
sniff benchmark historical-v3 finalize-review operator-config.json python
```

If the reviewers disagree, an independent resolver must complete the prepared
resolution worksheet before finalization. The final label is bound to the
exact rank and replayed before processing the next one.
