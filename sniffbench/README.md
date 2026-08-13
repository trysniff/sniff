# SniffBench

SniffBench is Sniff's reproducible evaluation protocol. Blind OSS source
selection, source sealing, independent method labeling, run import, and final
evaluation use create-new, hash-bound artifacts.

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
