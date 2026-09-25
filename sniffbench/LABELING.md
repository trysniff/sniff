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
- `kinda_slop`: proven unnecessary machinery whose burden is real but minor.
- `clean`: no evidenced unnecessary or misleading machinery.
- `unresolved`: the sealed evidence is insufficient to decide safely.

Kinda Slop is proven but minor unnecessary friction; uncertainty is Unresolved.

> Protocol clarification (2026-09-25): an earlier guide allowed lower
> confidence to become `kinda_slop`. That contradicted the four-verdict
> contract. Insufficient evidence requires `unresolved`. The source seal and
> review template were not changed; no public reviewer commitment had been
> posted on [issue #36](https://github.com/trysniff/sniff/issues/36) at this
> correction.

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

1. Download the frozen [source-seal archive](https://github.com/trysniff/sniff/releases/download/sniffbench-blind-oss-v1-source-seal/sniffbench-blind-oss-v1-source-seal.zip).
   Its SHA-256 is `9cfca885c88ce7f8d2c7cc01114b6bc129acd5e2dfa432ef3b255858a51b65a9`,
   as committed in the [source-seal result](blind-oss-v1-source-seal-result.json).
   Verify the downloaded ZIP before extracting it: use `sha256sum` on Linux,
   `shasum -a 256` on macOS, or `Get-FileHash -Algorithm SHA256` in PowerShell,
   followed by the ZIP filename.
2. From the extracted directory containing `blind-source-seal.json`, validate
   the sealed source and create your own blank worksheet:

```console
sniff benchmark prepare-labels blind-source-seal.json in-progress-review.json
```

   The prerelease also contains `independent-review-template.json` (SHA-256
   `5e241377c8ceadf143021f450155625c2b1df4ee928261d8e201bff11360458b`).
   Use a fresh copy if you prefer the template; do not inspect another
   reviewer's worksheet.
3. Complete the reviewer object and every method decision independently.
4. Save at any time and check completed decisions plus remaining counts:

```console
sniff benchmark label-status blind-source-seal.json in-progress-review.json
```

5. Validate the completed worksheet offline:

```console
sniff benchmark validate-labels blind-source-seal.json completed-review.json
```

6. Compute the SHA-256 of the exact validated JSON file.
7. Post only the SHA-256 commitment and completion attestation. Do not reveal
   the worksheet while another reviewer is still labeling.
8. After at least two independent commitments are publicly recorded, reveal
   the exact worksheet. Its SHA-256 must match the earlier commitment.

Validation rechecks the complete source seal, immutable method census,
worksheet identity, reviewer eligibility, every decision field, and all
cross-method relationships. It does not contact GitHub or a model provider.

At least two distinct validated worksheets are required. Sniff preserves every
disagreement in the label audit; a separate experienced resolver adjudicates
disputes without changing either original worksheet.

## Public commit-reveal

The commitment phase prevents a later reviewer from seeing or copying an
earlier review while still allowing the complete process to be public and
auditable. A commitment comment must contain:

- Reviewer ID matching the completed worksheet.
- Worksheet SHA-256.
- Attestation that all 1,607 methods were completed and `validate-labels`
  passed before the commitment was posted.
- Attestation that no Sniff output or other reviewer's labels were inspected.

Do not include label counts, findings, rationales, excerpts, or the worksheet
during the commitment phase. After two valid commitments exist, both reviewers
may reveal their exact JSON files. A changed or non-matching reveal is rejected.
