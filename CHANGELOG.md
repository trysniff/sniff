# Changelog

All notable changes to Sniff will be documented here.

## 0.2.2 - 2026-08-05

- Preserve function-valued object properties when their owning object has repository consumers.
- Split malformed method batches and retry at smaller granularity before emitting `Unresolved`.
- Distinguish emitted response records from trusted resolved method verdicts in reports.
- Include exhausted validation attempts in token and cost totals.
- Recalibrate conservative runtime estimates from the measured Ky validation run.

## 0.2.1 - 2026-08-05

- Add offline `sniff doctor` checks and an explicit `doctor --probe` provider request.
- Add no-LLM `sniff --estimate` cost and runtime ranges with pre-scan confirmation.
- Support provider-specific payloads for DeepSeek, OpenAI, Anthropic, and OpenRouter-compatible endpoints.
- Share configured pricing between pre-scan estimates and final reports.
- Expand the public quickstart, provider examples, privacy warning, and measured dogfood proof.

## 0.2.0 - 2026-08-04

- Review every discovered method with separate intent and adversarial semantic passes.
- Require exact evidence, contract impact, dependency proof, and a behavior-preserving simplification for findings.
- Preserve unresolved contract questions as explicit non-successful analysis results.
- Add typed symbol and call resolution across Python, JavaScript, TypeScript, Rust, Go, and Kotlin.
- Add same-file method batching, bounded concurrency, prompt caching metrics, durable checkpoints, and targeted response repair.
- Add intent-based semantic gold cases and verified dogfood coverage for Bumpkin, Brandset, Pillit, and Sniff.
- Split analyzer dossiers, structural proofs, language contracts, method refinement, symbol resolution, and their tests into focused modules.
