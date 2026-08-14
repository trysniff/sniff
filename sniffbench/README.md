# SniffBench

SniffBench is Sniff's reproducible evaluation protocol. Blind OSS source
selection, source sealing, independent method labeling, run import, and final
evaluation use create-new, hash-bound artifacts.

## Non-blind real evidence

Historical simplifications, research trajectories, and intentional clean
boundaries use a separate label-free provenance seal. Freeze this seal before
running Sniff or assigning labels:

[`non-blind-v1-selection-policy.json`](non-blind-v1-selection-policy.json)
fixes the source populations, quotas, ranking contracts, eligibility rules,
required research datasets, and no-fallback behavior before candidate
collection. The final seal hashes this exact policy artifact.

The historical-repository order is frozen separately in
[`non-blind-v1-history-worksheet.json`](non-blind-v1-history-worksheet.json).
It was generated before inspecting candidate histories and excludes every
repository in the blind source seal before ranking. Reproduce it from the exact
OpenSSF frame named by the policy without contacting an LLM provider:

```console
sniff benchmark prepare-non-blind-history \
  sniffbench/non-blind-v1-selection-policy.json projects.csv \
  sniffbench/blind-oss-v1-source-seal.json history-worksheet.json
```

The create-new output must contain 600 candidates, exclude 12 blind
repositories, and reproduce these commitments:

- Policy SHA-256: `43269a234b55ff406edf1893584418d0eefc3a79eada16764c2114fd7f88c44d`
- Frame SHA-256: `55b1de849d6d401bd6529a2806d587b53170cfbe7cdbc2ac5799ab65bf42807a`
- Blind source-seal SHA-256: `33bf6eaac53c3e58c6d4ff2f3ecf54321ef59b1c7f81a58f5e19790bb7b4f5a4`
- Task SHA-256: `e78e4640072de84ff176538939cd9544cf6aa5027edd0c2941f12233123f8160`
- Worksheet file SHA-256: `73fdbd7b9b49554a2dccb34fc1c19df0fcaa8f2b69e8b72be401cfc67f6dfe85`

[`non-blind-v1-history-assessment-protocol.json`](non-blind-v1-history-assessment-protocol.json)
freezes how those 600 repositories are assessed before any candidate history
is inspected. It fixes the default-branch snapshot, one-parent commit filter,
commit ranking, single-attempt rule, method and language census, simplification
floor, declared test-recipe order, sandbox execution, quota application, typed
exclusions, checkpoint completeness, and label separation. A failed ranked
commit closes its repository; it never causes SniffBench to choose a more
convenient commit.

Create the blank task-bound assessment ledger offline. This validates and hashes
the policy, worksheet, and protocol; it does not contact GitHub or an LLM
provider:

```console
sniff benchmark prepare-non-blind-history-assessment \
  sniffbench/non-blind-v1-selection-policy.json \
  sniffbench/non-blind-v1-history-worksheet.json \
  sniffbench/non-blind-v1-history-assessment-protocol.json \
  history-assessment.json
```

The blank ledger contains 600 repositories and six fixed language quotas. Its
task commitment is
`1b304d2a606498d9c2746d9622cf3b51568a9d825a63601c5bb78be11cfa4553`;
the pretty-printed file SHA-256 is
`fb5bc4f65f72cf4fb86fabde3520ea19427dfe7f8a7ddb1085fe00b83e48ec39`.

Execute the immutable ledger in bounded slices when the host cannot safely
finish all 600 repositories in one process. Every completed rank is published
transactionally under the state directory; rerunning the identical command
verifies and resumes that contiguous prefix. A partial slice does not write the
final ledger:

```console
sniff benchmark assess-non-blind-history \
  sniffbench/non-blind-v1-selection-policy.json \
  sniffbench/non-blind-v1-history-worksheet.json \
  sniffbench/non-blind-v1-history-assessment-protocol.json \
  history-assessment.json history-state completed-history-assessment.json \
  --max-new-ranks 25
```

The manual `SniffBench historical assessment` GitHub workflow provides the
same Linux-only bounded execution. Resume it with the preceding workflow run
ID so its hash-verified state artifact is restored before processing new ranks.

```console
sniff benchmark seal-non-blind-sources \
  non-blind-source-draft.json non-blind-source-seal.json
```

The seal also hashes a separately published selection-policy artifact, which
must exist before candidate source inspection. Every entry pins an HTTPS
upstream, an immutable 40- or 64-character revision,
the exact before/after source bytes, its license, and behavioral evidence such
as tests or build results. The command verifies every artifact and writes a
commitment-bound create-new seal. A final SniffBench v6 corpus must assign every
historical, research, and intentional-boundary case to one of these presealed
entries; synthetic and blind-OSS cases cannot claim that provenance.

Research provenance is not a label. SlopCodeBench trajectories and TRIM
original/minimized patches still require independent Sniff-ontology review.
Reference solutions, paper figures, aggregate metrics, and authored examples
must not be relabeled as observed agent slop. If exact trajectory artifacts are
not publicly available, that source is recorded as unavailable rather than
reconstructed or approximated.

Intentional clean boundaries use the same precommitted 600-repository
population as the historical assessment, not hand-picked examples.
[`non-blind-v1-intentional-boundary-protocol.json`](non-blind-v1-intentional-boundary-protocol.json)
was frozen before collecting exact symbol candidates. It binds the policy,
blind-source exclusion, repository population, eight category-specific
compiler/contract evidence rules, sixteen fixed slots, no-backfill behavior,
and independent source-only labeling contract. Validate it offline without a
model provider:

```console
sniff benchmark validate-intentional-protocol \
  sniffbench/non-blind-v1-selection-policy.json \
  sniffbench/non-blind-v1-history-worksheet.json \
  sniffbench/blind-oss-v1-source-seal.json \
  sniffbench/non-blind-v1-intentional-boundary-protocol.json
```

The protocol file SHA-256 is
`3e4bbeff8fd850fdb2808ab98609070075fbce99e522017c93605f71c14bd220`.

[`non-blind-v1-intentional-boundary-frame-task.json`](non-blind-v1-intentional-boundary-frame-task.json)
is the immutable blank execution task derived from those four bound inputs. It
contains all 600 repositories in exact population order and commits the narrow
set of terminal repository exclusions. Transport, rate-limit, tool,
checkout-integrity, indexer, and method-join failures are not exclusions: the
future collector must stop and resume rather than silently remove those
repositories. Reproduce and validate the task offline:

```console
sniff benchmark prepare-intentional-frame-task \
  sniffbench/non-blind-v1-selection-policy.json \
  sniffbench/non-blind-v1-history-worksheet.json \
  sniffbench/blind-oss-v1-source-seal.json \
  sniffbench/non-blind-v1-intentional-boundary-protocol.json \
  frame-task.json

sniff benchmark validate-intentional-frame-task \
  sniffbench/non-blind-v1-selection-policy.json \
  sniffbench/non-blind-v1-history-worksheet.json \
  sniffbench/blind-oss-v1-source-seal.json \
  sniffbench/non-blind-v1-intentional-boundary-protocol.json \
  frame-task.json
```

The frame task commitment is
`8bac634f0f0feb0a6634b41c26907c7116b7cb1427002b9f71b7803521c90114`.
Candidate collection has not started. Every repository in the task must receive
a hash-bound checkpoint, and paths or names may identify a symbol but can never
prove its category or intentional contract.

## Blind OSS v1

[`blind-oss-v1-policy.json`](blind-oss-v1-policy.json) was fixed before running
the source-ranking command or inspecting ranked candidates. It pins:

- The exact OpenSSF Scorecard project-list commit, Git blob, and SHA-256.
- Commit `10afa5d22d090d7ac02e4621d89de24d0a8fd926` as the public ranking seed.
  That commit implemented and published the selection contract before the
  candidate list was generated, preventing seed rerolls after inspection.
- Two repositories for each of Go, JavaScript, Kotlin, Python, Rust, and
  TypeScript.
- A complete 240-candidate assessment prefix.
- A production-method range of 50 through 250 methods per selected repository.

Two repositories per language prevent a language score from being determined by
one project's conventions while keeping independent exhaustive human review
feasible. The method range avoids both tiny examples and repositories too large
for careful method-by-method adjudication. It targets roughly 1,200 to 2,000
blind methods across 12 repositories.

Each repository fills the quota for its dominant eligible-method language.
Equal method counts use lexicographic language order as a deterministic
tie-break. Every candidate in the prefix must retain one canonical structured
fact payload and at least one raw HTTPS source payload. Hashes prove exactly
what was assessed; external facts remain independently reviewable claims rather
than becoming true merely because they were hashed.

Every accessible candidate is assessed at an immutable Git revision. Its
structured facts contain the complete per-language eligible-method census under
the published census contract, including candidates excluded for metadata,
method bounds, or a filled quota. An inaccessible candidate cannot claim a
revision or census, and an unsupported project shape remains explicitly
unresolved rather than receiving a guessed count.

The pinned frame is also audited before ranking. Empty rows are ignored;
malformed rows, invalid GitHub identities, and repeated identities are excluded
through a typed eligibility census. The worksheet commits each excluded row's
CSV line number and SHA-256, plus an aggregate SHA-256 over the ordered ledger.
This keeps stale frame records reproducible without publishing their raw values
or silently changing the sampling population.

The 72.9 MB sampling frame is not committed to this repository. Download the
immutable URL declared in the policy and verify its SHA-256 before preparing the
selection worksheet:

```console
sniff benchmark prepare-selection \
  sniffbench/blind-oss-v1-policy.json projects.csv selection-review.json
```

Assess the complete fixed prefix with resumable per-rank checkpoints. This uses
GitHub metadata and Git source only; it does not contact an LLM provider:

```console
sniff benchmark assess-selection \
  sniffbench/blind-oss-v1-policy.json projects.csv selection-review.json \
  selection-state checkouts selection-complete.json
```

Each completed rank is atomically persisted. Interrupted API requests and Git
clones use bounded retries, while rerunning the command resumes at the first
uncommitted rank. Only selected repositories are retained, as clean
self-contained checkouts at the assessed commit; excluded worktrees are removed.

No Sniff finding, benchmark label, or provider/model output is used during
source selection.

### Precommitted continuation

The complete first round is published as
[`blind-oss-v1-round1-assessment.json`](blind-oss-v1-round1-assessment.json),
with its independently derived outcome in
[`blind-oss-v1-round1-result.json`](blind-oss-v1-round1-result.json). The fixed
240-rank prefix filled both Go, JavaScript, Python, and TypeScript slots but no
Kotlin or Rust slots under the seal-compatible clean-checkout requirement.

Rather than replace the failed sample or hand-pick repositories, extension 1
keeps every round-one assessment byte-for-byte and continues the same ranking
through a single conservative endpoint of rank 1,440. The endpoint and the
hashes of the complete prior round were committed before rank 241 was generated
or inspected. The frame, seed, method bounds, language quotas, and ranking
contract are unchanged.

[`blind-oss-v1-extension-1-policy.json`](blind-oss-v1-extension-1-policy.json)
is the final hash-bound policy. Its companion draft demonstrates which values
were operator-chosen; `prepare-extension` derived the prior-round commitments:

```console
sniff benchmark prepare-extension \
  sniffbench/blind-oss-v1-extension-1-draft.json projects.csv \
  sniffbench/blind-oss-v1-round1-assessment.json \
  sniffbench/blind-oss-v1-extension-1-policy.json
```

Only after committing that final policy may the continuation worksheet be
generated with `extend-selection`. Sniff rejects changed inherited assessments,
criteria changes, skipped ranks, or use of a continuation policy through the
fresh `prepare-selection` path.

Extension 1 completed all 1,440 ranks. The exact assessment and independently
derived outcome are published as
[`blind-oss-v1-extension-1-assessment.json`](blind-oss-v1-extension-1-assessment.json)
and
[`blind-oss-v1-extension-1-result.json`](blind-oss-v1-extension-1-result.json).
The continuation filled both Rust slots but still produced no qualifying Kotlin
repository. Kotlin was detected in the frame, but the three Kotlin-dominant
projects had 54 methods without a license, 2 methods, and 36 methods.

This failed gate is retained rather than hidden or extended repeatedly. A future
Kotlin completion round must use a separately pinned, language-stratified source
frame whose construction and seed are committed before candidates are ranked.
It must preserve the ten selected repositories and cannot alter the existing
frame, method bounds, evidence, or exclusions.

### Precommitted Kotlin source frame

[`blind-oss-v1-kotlin-frame-1-policy.json`](blind-oss-v1-kotlin-frame-1-policy.json)
fixes the missing Kotlin population before any candidate repository identity is
collected or ranked. It queries public repositories that GitHub Search indexes
for Kotlin and whose immutable creation timestamp falls on one deterministically
selected day in the latest completed calendar quarter.

The date is not operator-picked. The first eight hexadecimal digits of the
already-published blind-oss-v1 ranking seed are interpreted as an unsigned
integer. Modulo the 91 days of 2026 Q2 produces offset 39 from 2026-04-01, so
the frozen day is 2026-05-10 UTC.

The collector searches each UTC hour independently with forks, archived
repositories, mirrors, and templates excluded. It retains every raw GitHub
response, rejects incomplete responses or any partition above GitHub Search's
1,000-result completeness limit, checks returned repository facts against the
query, and orders the final frame by immutable numeric GitHub repository ID.
There is no star, popularity, or model-derived filter.

GitHub's repository Search response also carries a nullable `language` summary
field. The first frozen collection proved that this field can be `null` even
when the same repository is returned for the precommitted `language:Kotlin`
query. Sniff therefore preserves that raw discrepancy but does not silently add
the mutable summary field as a post-collection filter. Kotlin dominance is
measured later from the immutable checked-out source by the existing complete
eligible-method census.

Collection is resumable through atomically published raw-page checkpoints. The
state directory must remain inside the manifest artifact root so every evidence
path is portable:

```console
sniff benchmark collect-frame \
  sniffbench/blind-oss-v1-kotlin-frame-1-policy.json \
  sniffbench/blind-oss-v1-kotlin-frame-1-raw \
  sniffbench/blind-oss-v1-kotlin-frame-1.csv \
  sniffbench/blind-oss-v1-kotlin-frame-1-manifest.json
```

An independent offline replay must reproduce the exact CSV from all committed
raw pages:

```console
sniff benchmark validate-frame \
  sniffbench/blind-oss-v1-kotlin-frame-1-manifest.json \
  sniffbench \
  sniffbench/blind-oss-v1-kotlin-frame-1.csv
```

The collected frame, manifest, and raw pages were committed separately before
the Kotlin ranking seed and complete assessment endpoint were precommitted.
This prevents inspecting identities before choosing either the ranking or its
endpoint.

The frozen frame contains 1,291 repositories and replays to SHA-256
`a293019c63666f7875e05d7637c02309a53971316aa5194d94430c1281d8a233`.
Its immutable source is commit
`cf6d6d02ab1a8efa6fc7855c69993581ca0e695a`, Git blob
`6dda7c37a4ca4bbf32fd654bbfa0503a886c390c`.

[`blind-oss-v1-kotlin-selection-1-policy.json`](blind-oss-v1-kotlin-selection-1-policy.json)
precommits assessment of all 1,291 rows, not an operator-selected prefix. Its
seed is derived from the frozen frame-manifest commitment and the already
audited ten-repository base component. This guarantees that an unfilled Kotlin
quota remains a public failure rather than triggering another endpoint choice.

[`blind-oss-v1-composite-policy.json`](blind-oss-v1-composite-policy.json)
precommits the ordered base and Kotlin components and exactly two repositories
for each of the six supported languages. It is committed before Kotlin rank 1
is generated or inspected.

### Frozen six-language source seal

The completed Kotlin assessment filled the two missing Kotlin slots without
changing the ten repositories selected by the base component. The composite
source seal contains exactly two repositories for each supported language and
an exhaustive census of 1,607 eligible production methods.

[`blind-oss-v1-source-seal.json`](blind-oss-v1-source-seal.json) is the public
manifest. The exact source, review context, licenses, selection ledgers, and
sampling frames are distributed as the
[`sniffbench-blind-oss-v1-source-seal.zip`](https://github.com/trysniff/sniff/releases/download/sniffbench-blind-oss-v1-source-seal/sniffbench-blind-oss-v1-source-seal.zip)
release asset rather than inside the installable Cargo crate. Its immutable
sizes, counts, and SHA-256 commitments are recorded in
[`blind-oss-v1-source-seal-result.json`](blind-oss-v1-source-seal-result.json).

After extracting the archive, verify the manifest and every referenced byte
without contacting GitHub or a model provider:

```console
sniff benchmark prepare-labels \
  blind-source-seal.json independent-review.json
```

This command validates the complete source seal before creating a source-only
worksheet. The worksheet contains no Sniff findings or hidden labels. At least
two experienced reviewers must complete independent copies, and a separate
resolver must adjudicate every disagreement before the blind corpus can be
frozen.

The prerelease also provides the deterministic blank worksheet as
`independent-review-template.json`. Its SHA-256 is
`5e241377c8ceadf143021f450155625c2b1df4ee928261d8e201bff11360458b`.
Reviewers must follow [`LABELING.md`](LABELING.md) and validate their completed
copy before submission:

```console
sniff benchmark validate-labels \
  blind-source-seal.json completed-review.json
```
