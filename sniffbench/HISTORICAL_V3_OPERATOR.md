# Historical-v3 Operator

This is a maintainer workflow for constructing the candidate-blind historical-v3
cohort. It is not a normal `sniff` scan. No real v3 candidate collection has
been run or authorized by this document.

All JSON paths below must be absolute. Keep the operator root outside the
source repository and retain it between invocations. A missing or mismatched
artifact fails the command; it does not restart with a new cohort.

## Post-August-7 Source Frames

The six original [source-frame policies](historical-v3-source-frames/) were
fixed before collection or inspection of candidate identities. Each collects the entire
August 8-14, 2026 UTC period. SHA-256 of
`sniff-historical-v3-post-aug-2026-09-26-<language>` supplies the seed; its
first eight hexadecimal digits modulo seven select the starting day, and the
collector then rotates through all seven days. The seed changes ordering,
not inclusion. The original policies fix the GitHub API, all 168 hourly partitions,
filters, and immutable-ID ordering. Every admitted repository must have `created_at` strictly
after `2026-08-07T20:46:11Z`; a matching name is not identity proof.

The original JavaScript policy stopped when the August 12 04:00 UTC hour
reported 1,144 results, Python stopped when the August 12 01:00 UTC hour
reported 1,040, and TypeScript stopped when the August 12 05:00 UTC hour
reported 1,033. All exceed GitHub Search's 1,000-result completeness limit.
Their partial raw checkpoints remain retained, not accepted as frames. The separate
[JavaScript](historical-v3-source-frames/javascript-five-minute-policy.json),
[Python](historical-v3-source-frames/python-five-minute-policy.json),
and [TypeScript](historical-v3-source-frames/typescript-five-minute-policy.json)
five-minute amendments keep their original seven dates, seeds, languages,
filters, and repository ordering. Each partitions every hour into twelve
non-overlapping five-minute windows, not just the observed overflowing hour.
Their 2,016 query windows cover the same respective cohorts and bind the
original policy SHA-256 values. Each amended policy embeds its exact hourly
predecessor; collection and replay verify its hash and unchanged cohort fields.
Publish each amendment at an immutable public
commit before starting its new state root. If a five-minute window still
exceeds 1,000 results, stop; do not silently split it or switch dates. These
amendments were made after the observed hourly caps, not falsely represented
as pre-collection policies.

After the policy commit is public and immutable, collect each language's
frame with `sniff benchmark collect-frame POLICY STATE_ROOT FRAME_CSV MANIFEST --transport gh`.
This explicit transport requires an authenticated GitHub CLI
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
For a model-judged v7 protocol, publish the exact agent prompt at an immutable
public commit too. `preflight` pins its bytes and checks the protocol's approved
prompt SHA-256; missing or changed prompt bytes fail before candidate collection.

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
the current rank's authorized human- or agent-review handoff, a terminal stop,
or its step cap.
Operational failures keep the same rank open for retry.

## Independent Review

Human-only v6 and model-judged v7 are different protocol authorities. The
human commands below reject v7; the agent commands reject v6. Do not submit
agent judgments through a human worksheet or describe them as human gold.

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

For a v7 rank reported as `agent_review`, prepare the exact source-only
invocation, present its bytes separately to two fresh independent agents,
and retain each agent's exact JSON response in a plain file. The CLI does not
call a model provider. It validates and seals each raw response, checks the
agents and runs are distinct, and audits both source-bound decisions:

```console
sniff benchmark historical-v3 prepare-agent-review operator-config.json python
sniff benchmark historical-v3 submit-agent-review operator-config.json python 1 first-response.json
sniff benchmark historical-v3 submit-agent-review operator-config.json python 2 second-response.json
sniff benchmark historical-v3 audit-agent-review operator-config.json python
```

`prepare-agent-review` derives two fixed slot IDs from the sealed rank and
records them in `agent-assignment.json` before publishing the invocation.
The operator cannot choose or swap them after seeing responses. Create two
fresh agent runs and give each its assigned slot card. Record the actual
model run identity separately in each response's `run_id`; those identities
remain self-declared, not cryptographically authenticated. The slot ID is a
deterministic task pseudonym, not an agent identity credential. The command prints
paths to the shared `agent-invocation.json` and two
slot cards. The invocation contains the approved prompt, its SHA-256, and
the sealed source bundle. Present that invocation plus only the matching
slot card to each reviewer; the card states the assigned agent ID and binds
to the exact invocation bytes. Do not present the repository identity,
change metadata, Sniff output, or the other review. The two response files
must contain only the raw model JSON, not a paraphrase or an edited decision.
Submissions for one rank are single-writer; retry a concurrent-lock error after
the other submission completes rather than running both CLI writes at once.
Malformed or incomplete responses fail; there is no substitute verdict.
Agreement on a supported slop pattern may count as an accepted model-judged
case. Disagreement and uncertainty remain visible and count against the
review cap but not as accepted cases. Reviewer provenance fields are
self-declared; this workflow is model-judged development evidence, not
independent human gold or a measured Sniff precision score.
The v3 agent-review record requires the rank-derived assignment and slot cards.
Older v2 pilot records cannot be backfilled into this record or counted as
preassigned benchmark reviews.
