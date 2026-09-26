# Historical-v3 Agent Source Review

Review one sealed historical-v3 before/after source bundle. Read the complete
changed-method context, relevant callers and contracts in the bundle, and the
paired behavior-test evidence. Do not read repository identity, PR title or
description, change metadata, Sniff output, prior labels, or another agent's
decision. Start in a fresh context for each assigned review item.

Decide whether the before-state contains concrete, unnecessary or misleading
machinery and the after-state removes it without relocating it or changing
observable behavior. A bug fix, style difference, shorter code, or passing
tests alone is not proof of slop. A framework boundary, public API, test seam,
compatibility adapter, or retry policy may be intentional even if verbose.

Use `slop` only when the mechanism, simpler counterfactual, preserved public
surface, and behavior evidence are all supported by exact before and after
source citations. Use `clean` when the changed code does not establish
needless machinery, `intentional_boundary` when the apparent redundancy has
a demonstrated contract, `ambiguous` for conflicting evidence, and
`insufficient_context` when a required fact is absent. State what evidence is
missing rather than filling it in. Never invent a citation or claim a
behavior-preserving change based on intuition alone.

Return only JSON with a `reviewer` object and a `decision` object. Record the
declared provider, model, exact revision if exposed (`model_version: null`
otherwise), unique run ID, and SHA-256 of these exact prompt bytes. Set each
source-only isolation and inspection field to true only if it actually held.
Reviewer keys are `agent_id`, `provider`, `model`, `model_version`, `run_id`,
`prompt_sha256`, `fresh_context`, `sniff_output_hidden`,
`repository_identity_hidden`, `change_metadata_hidden`,
`other_reviews_hidden`, `complete_source_context_inspected`,
`behavior_evidence_inspected`, and `attestation`.
The decision must match the prepared historical-v3 source-review task's
`HistoricalV3ReviewDecision` fields, including verdict, pattern, mechanism,
counterfactual, evidence flags, rationale, missing evidence, and exact
citations. An agent judgment is model-judged development evidence, not an
independent human gold label or a Sniff precision score.

Decision keys: `verdict`, `pattern`, `other_pattern`, `mechanism`,
`before_contains_unnecessary_machinery`, `after_removes_that_machinery`,
`removal_not_relocated`, `simpler_counterfactual_matches`,
`public_surface_preserved`, `behavior_preserved`, `simpler_counterfactual`,
`boundary_justification`, `rationale`, `missing_evidence`, and `citations`.
For `slop`, choose a non-`none` pattern, state a concrete simpler
counterfactual, set all six evidence flags to true, and leave missing evidence
empty. For `clean` and `intentional_boundary`, use pattern `none`, mark
before-state unnecessary machinery false, public surface and behavior true,
and leave the other machinery flags null; an intentional boundary also needs
its exact contract justification. For an uncertain verdict, use pattern
`none`, list the missing evidence, and leave unsupported flags null.

Each citation has `side` (`base` or `merge`), `repository_path`,
`parser_unit_id`, `start_line`, `end_line`, and `quote`. Cite exact complete
lines from the sealed method source, ordered and unique; include both sides
when both are available. Use one of the published slop patterns, such as
`residual_machinery`, `duplicated_semantics`, `ceremonial_logic`,
`needless_indirection`, `contract_fog`, or `other`. Do not invent a pattern.
