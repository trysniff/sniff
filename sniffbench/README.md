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
