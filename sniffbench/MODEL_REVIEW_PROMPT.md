# Model-Judged Source Review

Review the assigned methods from sealed source and relevant repository context.
Do not read Sniff output, another reviewer's decisions, change descriptions,
or prior labels. Start with a fresh context for each assigned shard. Record the
model identity and exact prompt SHA-256 in the raw submission.

For each method, answer one question: does the source contain unnecessary or
misleading machinery that a developer could simplify while preserving
observable behavior? Read the method and its callers, callees, contracts,
tests, and nearby conventions when relevant. Do not infer slop from method
length, naming, parameter count, or a static warning alone.

Use these tiers:

- `slop`: a concrete, material maintenance burden from needless machinery.
- `kinda_slop`: a concrete but small burden, or lower confidence in the safe
  simplification.
- `clean`: no evidenced needless machinery, including an intentional boundary.
- `unresolved`: the sealed context cannot support a safe judgment.

A correctness bug, missing error check, security issue, performance concern,
or unconventional style is not slop by itself. If the proposed fix changes
behavior rather than removing needless machinery, do not label it slop. For a
slop finding, give the smallest behavior-preserving simplification and an
exact quote from a sealed source artifact that demonstrates the friction.
Never invent a quote or infer that a public boundary is unnecessary without
checking its consumers. If context is missing, name it and use `unresolved`.

Return only JSON with a `reviewer` object and a `decisions` array. The reviewer
object records `reviewer_id`, `provider`, `model`, `model_version`, `run_id`,
`prompt_sha256`, `fresh_context`, `sniff_output_hidden`,
`other_reviews_hidden`, and `source_context_inspected`. Do not claim a true
attestation if it did not hold. Use `null` for `model_version` if the host
does not expose an exact revision; never guess it. Each decision records
`method_id`, `tier`,
`mechanism`, `evidence_artifact_path`, `exact_source_quote`, `rationale`,
`behavior_preserving_simplification`, and `missing_evidence`. Use an empty
simplification for `clean` or `unresolved`; provide a concrete one for `slop`
or `kinda_slop`. Use an empty missing-evidence array when none is missing.

This is a model-judged development review. It does not create a human gold
label or establish Sniff's precision.
