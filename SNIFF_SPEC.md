# Sniff Spec

Sniff is a personal CLI for finding slop in codebases. It is not a security scanner, not a bug finder, and not a generic code-review bot. Its only job is to identify code that makes humans spend extra effort understanding, trusting, or changing it.

## Core Idea

Slop is code that is functionally correct but cognitively expensive.

Sniff focuses on patterns like:
- vague names
- overbuilt helpers as supporting signals
- dumping-ground files
- excessive nesting
- too many parameters
- overly large functions
- dead or orphaned exports as supporting signals
- code that hides intent behind generic plumbing
- duplicated code
- high churn or repeated rework
- modules with broad architecture fan-out
- tests that mirror production code too closely
- fixtures and corpus files are treated as intentional surfaces, not primary slop targets
- generated-style provenance markers

The goal is not to catch every possible flaw. The goal is to surface code that feels unnecessarily hard to reason about.

## What Sniff Is

- a slop finder
- exhaustive over the scanned repo
- exhaustive method and file review
- static signals provide candidates and context; the LLM performs the semantic slop judgment

## What Sniff Is Not

- not a security scanner
- not a diff/PR reviewer
- not a bug finder
- not a dashboard or SaaS product
- not a generic QA platform

Generated files and docs surfaces are skipped entirely.

## Slop Tiers

Sniff uses three tiers:

- `Slop`: clearly worth attention
- `Kinda Slop`: mild friction, small wrapper, weak naming, or low-value abstraction
- `Clean`: not worth flagging

`Kinda Slop` exists so the tool can stay honest about mild friction without pretending everything is a serious problem.

The shipped verdict is one file verdict per scanned file. Methods are evidence, not separate user-facing verdicts.

## Analysis Model

Sniff works in layers:

1. Walk the repo and collect supported files.
2. Parse files into methods, files, and symbols.
3. Build a symbol graph and reference counts.
4. Apply role-aware static scoring to produce candidate signals and context.
5. Review every eligible method and every scanned file with the LLM.
6. Aggregate source-backed AI judgments and supporting signals into one file verdict per file.

The LLM is the reasoning layer for slop, but its output is constrained. It may only return `Slop`, `Kinda Slop`, or `Clean`, and a non-clean result must include exact source evidence and a known slop-shaped reason. It must judge methods in their surrounding file context instead of treating LOC or branch counts as verdicts.

Role labels are user-facing and use the contract vocabulary: `core_library`, `cli_entrypoint`, `example`, `test`, `docs`, and `generated`.

## What Gets Checked

### Method-level
- function is too big
- too many parameters
- name is vague
- overbuilt helper
- wrapper adds no value
- excessive nesting
- comments that restate the code instead of explaining it

### File-level
- file does too much
- file name is vague or misleading
- file is a dumping ground
- method sizes vary wildly inside one file

### Cross-file / supporting
- duplication
- churn / revert pressure
- architecture fan-out
- test coupling
- generated-style provenance markers

### Static-only
- orphaned exports
- overbuilt helpers from callgraph/reference analysis
- duplication, churn, architecture fan-out, test coupling, and provenance markers

## Pipeline

```text
walker -> parser -> symbol graph -> scorer -> analyzer -> reporter
                    |
                    +-> callgraph/reference counter
```

## LLM Policy

The LLM is an exhaustive semantic reviewer, not a bug or security judge.

It reviews every eligible method and every scanned file. Each method and file is sent with complete source evidence, but a verdict only survives if:
- the model returns exact source evidence
- the reason matches a known slop pattern
- the code actually shows slop, not a speculative bug
- size, parameter, nesting, or static signals are not used as the sole evidence

If the evidence or reason does not survive validation, the finding is downgraded or removed.

The reason must also match Sniff's slop vocabulary, such as oversized functions, vague names, excessive parameters or nesting, overbuilt helpers, unnecessary wrappers, duplicated logic, tangled control flow, hidden intent, or files that mix unrelated responsibilities. Runtime bugs, security claims, and general suspicion are not accepted as slop reasons.

Branch and loop counts alone are not enough. A control-flow finding must explain the cognitive friction, such as tangled state transitions, duplicated decisions, unrelated paths, or intent hidden behind plumbing.

## CLI

```bash
sniff                # scan current directory
sniff <path>         # scan a repo or folder
sniff --verbose      # show clean items too
sniff --only-files   # skip method-level LLM review
```

For a clean Windows dogfood run, use `scripts/run_dogfood_clean.ps1`. It uses a fresh target dir and disables incremental compilation so stale build artifacts do not interfere with the integration suite.

## Configuration

Sniff reads configuration from:
- `sniff.config.toml`
- `.env`

Important env vars:
- `SNIFF_API_KEY`
- `SNIFF_ENDPOINT`
- `SNIFF_MODEL`
- `SNIFF_LLM_SAME_PROMPT_RETRIES`
- `SNIFF_LLM_MAX_ATTEMPTS`
- `SNIFF_LLM_CLIENT_TIMEOUT_SECS`
- `SNIFF_LLM_REQUEST_TIMEOUT_SECS`

## Output

The report includes one verdict per file:
- `clean`
- `kinda slop`
- `slop`

Each file entry should stay short:
- top reasons
- top offending methods named
- one recommended action
- AI coverage and missed-review count when the LLM path is enabled
- token/cost estimates

The report should help a human decide where the code is unusually hard to trust or understand.

If walking, parsing, configuration loading, AI review, or report writing fails, Sniff exits non-zero and does not leave a stale or partial report. The report belongs to the scanned repository root, including when the target is supplied as an external path.

Exit codes distinguish a completed finding report from a failed run: `0` means the completed report is clean, `1` means the report was completed and contains Slop or Kinda Slop findings, and `2` means the scan failed before producing a valid report.
