# SniffBench Blind Labeling Protocol

This protocol labels the frozen Blind OSS v1 source seal. Reviewers inspect
source and repository context only. They must not inspect Sniff output, prompts,
predictions, reports, hidden labels, or another reviewer's worksheet before
submitting their own completed worksheet.

## Reviewer eligibility

Each worksheet must be completed by an experienced software developer who:

- Is independent from Sniff's implementation and prompt development.
- Has not seen Sniff output for the sealed repositories.
- Reviews every one of the 1,607 methods and the relevant sealed context.
- Records their identity, experience, affiliation, and attestation truthfully.
- Makes their own decisions without coordinating labels with another reviewer.

Maintainers of a selected repository may review it, but must set `maintainer`
to `true`. Maintainer status is preserved in the final audit.

## Decision contract

Every method must receive exactly one `tier`:

- `slop`: unnecessary or misleading machinery with a clear, material burden.
- `kinda_slop`: evidenced unnecessary machinery whose burden is real but small
  or whose simplification confidence is lower.
- `clean`: no evidenced unnecessary or misleading machinery.
- `unresolved`: the sealed evidence is insufficient to decide safely.

`clean` and `unresolved` decisions use pattern `none`. Findings use exactly one
of these mechanism names:

- `residual_machinery`
- `duplicated_semantics`
- `parallel_reinvention`
- `ceremonial_logic`
- `needless_indirection`
- `speculative_defense`
- `band_aid_control_flow`
- `contract_fog`
- `test_mirroring`
- `test_subversion`
- `fictional_integration`
- `abandoned_compatibility`
- `responsibility_fragmentation`
- `misleading_completion`
- `unnecessary_state_complexity`
- `other`

Do not label bugs, security problems, style preferences, size, complexity,
architecture choices, generic maintainability concerns, or AI authorship unless
they are direct evidence of unnecessary or misleading implementation machinery.

## Required fields

For every decision:

- `intentional_boundary` must be `true` or `false`. It may be `true` only for a
  `clean` decision.
- `rationale` must state the source-grounded reason for the decision.

For `slop` and `kinda_slop`:

- `simplification` must describe a concrete smaller implementation.
- `behavioral_evidence` must explain why the simplification preserves the
  relevant behavior or contract.
- `missing_evidence` must be empty.

For `unresolved`:

- `missing_evidence` must name the evidence needed to decide.
- `simplification` and `related_method_ids` must be empty.

For `clean`:

- Finding, missing-evidence, and related-method fields must be empty.

When one slop case spans methods, every related method must list every other
member reciprocally. Related methods must belong to the same repository,
revision, and language and share the same tier, pattern, and boundary status.

## Workflow

1. Download and verify the source-seal archive from the
   `sniffbench-blind-oss-v1-source-seal` GitHub prerelease.
2. Work from a fresh copy of `independent-review-template.json`.
3. Complete the reviewer object and every method decision independently.
4. Validate the completed worksheet offline:

```console
sniff benchmark validate-labels \
  blind-source-seal.json completed-review.json
```

5. Submit the exact validated JSON file and its SHA-256.

Validation rechecks the complete source seal, immutable method census,
worksheet identity, reviewer eligibility, every decision field, and all
cross-method relationships. It does not contact GitHub or a model provider.

At least two distinct validated worksheets are required. Sniff preserves every
disagreement in the label audit; a separate experienced resolver adjudicates
disputes without changing either original worksheet.
