# Sniff Technical Spec

## 1. Overview

Sniff is a Rust CLI that scans a repository for slop. It is intentionally exhaustive at scan time, but selective about what survives reporting.

Main pipeline:

```text
walker -> parser -> symbol graph -> callgraph -> scorer -> analyzer -> reporter
```

Static analysis supplies candidate signals and graph context. The LLM performs exhaustive semantic slop review, constrained to slop tiers and source evidence; it is not a security or bug detector.

## 2. Module Layout

Core modules:
- `src/main.rs` - entry point
- `src/cli.rs` - CLI orchestration
- `src/walker.rs` - file discovery, ignore rules, and fail-closed traversal
- `src/parser.rs` - file parsing facade, including checked production parsing
- `src/parser_impl/*` - language-specific parsers and helpers
- `src/languages/*` - language adapters
- `src/symbol_graph*.rs` - symbol resolution and reference graph
- `src/callgraph.rs` - reference counting and supporting signals
- `src/scorer.rs` - static slop scoring
- `src/signal_layers.rs` - duplication, churn, architecture, test-coupling, and provenance signals
- `src/analyzer.rs` - LLM prompting, evidence gating, verdict normalization
- `src/llm.rs` - HTTP client, retries, response parsing
- `src/llm_helpers.rs` - provider payload and response-shape helpers
- `src/reporter*.rs` - terminal and markdown report rendering
- `src/file_verdicts.rs` - file-level verdict aggregation
- `src/config.rs` / `src/config_loader.rs` - defaults and config loading
- `src/types.rs` - shared data contracts

## 3. Data Contracts

### `FindingTier`
- `Slop`
- `KindaSlop`
- `Clean`

### `MethodRecord`
Contains:
- method name
- file path
- source
- LOC
- parameter count
- start/end lines
- export status
- language
- nesting depth
- resolved references
- `real_ref_count`

### `FileRecord`
Contains:
- file path
- source
- language
- methods

### `StaticFlag`
Contains:
- `flag_type` (`method` or `file`)
- `file_path`
- `method_name`
- `reasons`
- `tier`
- `gate`
- `loc`
- `start_line`
- `end_line`

### `FileVerdict`
Contains:
- file path
- role label
- verdict tier
- top reasons
- flagged methods
- recommended action

### `LLMVerdict`
Contains:
- `verdict_type`
- `file_path`
- `method_name`
- `check_type`
- `smelly`
- `tier`
- `cohesive`
- `name_accurate`
- `reason`
- `loc`
- `start_line`
- `end_line`

### `RunStats`
Tracks:
- files scanned
- methods analyzed
- static counts
- AI counts split by `Slop` and `Kinda Slop`
- dead methods
- inline candidates
- input/output tokens
- estimated cost

## 4. Language Support

Sniff currently supports:
- Rust
- TypeScript
- JavaScript
- Python
- Go
- Kotlin

Language extraction is adapter-driven. Each adapter declares:
- function node types
- excluded parent types
- parameter node types
- nesting node types
- export detection mode
- generic names
- allowed names

Docs and generated surfaces are skipped entirely instead of being scored.
User-facing role labels follow the contract vocabulary: `core_library`, `cli_entrypoint`, `example`, `test`, `docs`, and `generated`.

## 5. Symbol Graph

Sniff builds a local symbol graph for path and reference resolution.

Responsibilities:
- resolve local definitions
- resolve imports/exports
- track references per file
- connect references to local or external symbols where possible

This graph is used by the callgraph and by language-specific resolution helpers.

## 6. Callgraph / Reference Counting

The callgraph pass is static and does not call the LLM.

It produces:
- orphaned export supporting signals
- overbuilt helper / low-reuse supporting signals
- per-method reference counts and call snippets

These signals feed the scorer and the analyzer prompt as context, but they are not treated as final slop verdicts by themselves.

## 6.5 Supporting Signal Layers

Sniff also runs repo-level supporting signal layers:
- duplication and near-duplicate method matching
- churn and revert-rate checks from git history when available
- architecture coherence checks from method shape and dependency fan-out
- test-coupling checks that look for implementation-mirroring tests
- low-confidence provenance markers such as generated-style comments

These are evidence layers, not standalone verdicts. They help Sniff stay exhaustive without collapsing everything into generic QA noise.

## 7. Scorer

The scorer is the first slop filter before the LLM.

Typical static signals:
- LOC above threshold
- parameter count above threshold
- nesting depth above threshold
- generic or vague names
- generic file names
- file-level size / cohesion issues derived from method-level friction first

Role-aware exceptions are applied before aggregation so intentional surfaces do not get judged like core library code.

Each static flag is tagged with a tier:
- `Slop` for clear cases
- `KindaSlop` for mild friction

## 8. Analyzer

The analyzer reviews:
- every eligible method unless `--only-files` is set
- every scanned file
- each method with its complete source, bounded surrounding-file context, and reference context
- each file with its complete non-test source (Rust `#[cfg(test)]` bodies are excluded)

The LLM prompt requires:
- `smelly`
- `tier`
- `evidence`
- `reason`

Validation rules:
- evidence must be an exact substring of the source
- a non-clean reason must match a recognized slop pattern
- unsupported evidence downgrades or removes the finding
- unsupported reasons are dropped
- the app prefers slop-shaped reasons, not bug-shaped speculation
- entrypoints, examples, scripts, and tests are treated as intentional by default unless the method itself is clearly slop
- LOC, parameter count, nesting, branch counts, and static signals are candidates, never sufficient evidence by themselves

Docs and generated files are skipped before LLM review. Source text is treated as untrusted evidence, not prompt instructions. The final user-facing output is a file verdict, not a raw method verdict list.

This keeps the model thorough while preventing hallucinated runtime bugs from dominating the report.

## 9. LLM Transport

`src/llm.rs` handles:
- endpoint selection
- payload construction
- auth headers
- retries
- response parsing

Behavior:
- retries up to 32 attempts per request by default, including transient transport, empty, and malformed responses; `SNIFF_LLM_MAX_ATTEMPTS` can tune this for local or CI runs
- supports OpenAI-style and Anthropic-style response envelopes
- extracts JSON from fenced blocks or embedded text
- repairs truncated JSON strings and trailing commas before schema/evidence validation
- uses a conservative consensus tie-breaker; unresolved disagreement does not become a slop finding
- fails the current review after retry exhaustion
- aborts the scan on the first failed required review
- never produces a partial AI report

Environment/config:
- `SNIFF_API_KEY`
- `SNIFF_ENDPOINT`
- `SNIFF_MODEL`

The endpoint comes from config or `.env`, not a hardcoded constant.

Invalid configuration, unreadable `.env` files, invalid scan targets, directory traversal errors, parser diagnostics, invalid UTF-8, parser task failures, and HTTP-client construction failures are fatal. A failed run removes any previous generated report and writes no replacement.

## 10. Reporting

The reporter merges:
- static flags
- LLM verdicts
- file verdicts
- stats

Output includes:
- a single verdict per file
- short reasons
- top offending methods
- one recommended action
- token/cost summary
- file-level verdict counts

Exit codes are part of the CLI contract: `0` is a completed clean report, `1` is a completed report containing Slop or Kinda Slop, and `2` is an execution failure. A finding report is not an AI or transport failure.

`Kinda Slop` is intentionally preserved in the report so mild friction does not get collapsed into either noise or silence.

## 11. Current Design Contract

The current contract is:

1. Static analysis finds candidates.
2. The LLM reviews those candidates thoroughly.
3. The app aggregates the evidence into one verdict per file.
4. The report stays focused on slop, not generic bugs.

That is the stable direction of the tool.
