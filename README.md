<div align="center">
  <img src="assets/sniff-logo.png" alt="Sniff pig nose logo" width="152">
  <h1>Sniff</h1>
  <p><strong>Exhaustive, LLM-backed slop detection for real codebases.</strong></p>
  <p>
    <a href="https://crates.io/crates/sniff-cli"><img src="https://img.shields.io/crates/v/sniff-cli.svg" alt="crates.io version"></a>
    <a href="https://github.com/trysniff/sniff/actions/workflows/ci.yml"><img src="https://github.com/trysniff/sniff/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="AGPL-3.0 license"></a>
  </p>
</div>

Sniff reviews every eligible method with repository context to find slop:

> Unnecessary or misleading implementation machinery that superficially
> satisfies a task while transferring disproportionate comprehension,
> verification, or change burden to future developers.

It does not matter whether AI or a human wrote the code. Sniff is not an
AI-authorship detector, security scanner, bug finder, linter, generic
maintainability score, architecture-opinion engine, IDE, automatic refactoring
tool, or PR reviewer.

> [!WARNING]
> **A normal Sniff scan sends source code to the LLM endpoint you configure.**
> Check that provider's retention, training, region, and privacy policy before
> scanning private code. `sniff --estimate`, `sniff doctor`, and `sniff status`
> are offline;
> only `sniff doctor --probe` and normal or resumed scans contact the provider.

## Quickstart

Install [Rust](https://rustup.rs), then install the published crate:

```console
cargo install sniff-cli --locked
```

The first install compiles native dependencies and can take several minutes.
After installation, this setup takes about a minute:

```console
# In the repository you want to inspect, create .env with the three values below.
SNIFF_API_KEY=your-deepseek-key
SNIFF_ENDPOINT=https://api.deepseek.com
SNIFF_MODEL=deepseek-v4-flash

# Validate configuration and source discovery without contacting the model.
sniff doctor

# See method count, runtime range, and cost range without contacting the model.
sniff --estimate

# Inspect durable progress without contacting the model.
sniff status

# Start the exhaustive review. Expensive scans ask for confirmation first.
sniff

# Continue an interrupted scan without repeating completed reviews.
sniff resume

# Optionally pause after about $0.50 of cumulative estimated scan spend.
sniff --budget-usd 0.50
```

Sniff writes `sniff-report.md` at the scanned repository root. A successful run
reviews every eligible method; it never replaces failed AI reviews with a
static-only report.

Each completed method is appended to a durable journal. `sniff status [PATH]`
reads that journal without loading provider configuration or scanning source
files. `sniff resume [PATH]` requires an existing journal and continues the
scan; changed or invalidated work is reviewed again.

`--budget-usd` is a cumulative estimated limit for one scan. Sniff stops
admitting new paid review batches when the journaled estimate reaches the
limit, drains and persists already-running review batches, exits with code `3`, and
does not write an incomplete report. Continue with a higher limit, for example
`sniff resume --budget-usd 1.00`. Concurrent in-flight requests can finish
above the limit, and configured token rates may differ from the provider's
invoice, so this is a resumable admission control rather than an exact billing
cap.

## What A Finding Looks Like

This finding came from a completed scan, not a hand-written demo:

```text
[Slop][ai] duplicated decision paths

The condition appears to distinguish an optional-to-required transition, but
both paths return True. The branch communicates a distinction that does not
exist and makes the method harder to trust.

Exact evidence:
    if is_optional_param(old_token) and not is_optional_param(new_token):
        return True
    return True

Behavior-preserving simplification:
    return True
```

The evidence is exact, the friction is named, and the proposed simplification
does not change the callable contract, return behavior, or side effects.

The preview combines output from the offline fixture smoke test with the real
Bumpkin finding above.

![Sniff estimate and evidence-backed report preview](assets/report-preview.png)

## OSS Validation

Sniff is tested against pinned third-party repositories, and analyzer mistakes
are published alongside the fixes they forced. The current studies cover
[Ky (TypeScript)](case-studies/ky.md),
[Turbine (Kotlin)](case-studies/turbine.md),
[fd (Rust)](case-studies/fd.md),
[httpcore (Python)](case-studies/httpcore.md), and
[CertMagic (Go)](case-studies/certmagic.md).

See the [validation method and aggregate results](case-studies/README.md).
Zero findings means no slop satisfied Sniff's evidence contract; it is not a
claim that a repository is perfect.

## Cost Before Commitment

`sniff --estimate [PATH]` parses the repository locally and reports:

- supported files and methods
- language breakdown
- conservative input and output token ranges
- expected request and runtime ranges
- estimated cost using your configured provider rates

It makes **zero LLM requests**. A normal scan pauses before its first review
when the upper estimate crosses `$1`, two hours, or 2,000 methods. Interactive
runs ask for confirmation; automation must pass `--yes` explicitly. Override
the cost threshold with `SNIFF_CONFIRM_COST_USD`.

Measured dogfood run on 2026-08-02:

| Repository | Commit | Model | Coverage | Runtime | Estimated cost |
| --- | --- | --- | ---: | ---: | ---: |
| Bumpkin | `593a522` | `deepseek-v4-flash` | 1,222 / 1,222 methods | 1h 15m | $0.6912 |

That is one real run, not a universal benchmark. Provider latency, cache hits,
repository shape, retries, and response length all change runtime and cost.
The estimate uses configured rates; the final report is still an estimate, not
the provider's invoice.

## Provider Configuration

Sniff uses `SNIFF_API_KEY`, `SNIFF_ENDPOINT`, and `SNIFF_MODEL`. These examples
were checked against provider documentation on 2026-08-05. Prices and model
availability can change, so verify the linked provider page before a large run.

### DeepSeek

```dotenv
SNIFF_API_KEY=your-deepseek-key
SNIFF_ENDPOINT=https://api.deepseek.com
SNIFF_MODEL=deepseek-v4-flash
SNIFF_INPUT_COST_PER_MILLION=0.14
SNIFF_CACHED_INPUT_COST_PER_MILLION=0.0028
SNIFF_OUTPUT_COST_PER_MILLION=0.28
```

[DeepSeek models and current pricing](https://api-docs.deepseek.com/quick_start/pricing/)

### OpenAI

```dotenv
SNIFF_API_KEY=your-openai-key
SNIFF_ENDPOINT=https://api.openai.com/v1
SNIFF_MODEL=gpt-4.1-mini
SNIFF_INPUT_COST_PER_MILLION=0.40
SNIFF_CACHED_INPUT_COST_PER_MILLION=0.10
SNIFF_OUTPUT_COST_PER_MILLION=1.60
```

[OpenAI GPT-4.1 mini model and pricing](https://developers.openai.com/api/docs/models/gpt-4.1-mini)

### Anthropic

```dotenv
SNIFF_API_KEY=your-anthropic-key
SNIFF_ENDPOINT=https://api.anthropic.com
SNIFF_MODEL=claude-haiku-4-5-20251001
SNIFF_INPUT_COST_PER_MILLION=1.00
SNIFF_CACHED_INPUT_COST_PER_MILLION=0.10
SNIFF_OUTPUT_COST_PER_MILLION=5.00
```

[Anthropic models](https://platform.claude.com/docs/en/about-claude/models/overview)
and [Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing)

### OpenRouter

```dotenv
SNIFF_API_KEY=your-openrouter-key
SNIFF_ENDPOINT=https://openrouter.ai/api/v1
SNIFF_MODEL=anthropic/claude-haiku-4.5
SNIFF_INPUT_COST_PER_MILLION=1.00
SNIFF_CACHED_INPUT_COST_PER_MILLION=0.10
SNIFF_OUTPUT_COST_PER_MILLION=5.00
```

[OpenRouter's model page](https://openrouter.ai/anthropic/claude-haiku-4.5/api)
lists the current model slug, providers, data policies, and prices. Routing can
change the effective price, so configure the rates for the route you choose.

## Diagnose Setup

```console
sniff doctor [PATH]
```

`doctor` checks the target, `.env` loading, API key presence, endpoint syntax,
model, supported source discovery, and report permissions without contacting
the provider. To explicitly test authentication and response compatibility with
one small paid request:

```console
sniff doctor --probe [PATH]
```

The command labels that request as paid before sending it.

## Run

```console
sniff [PATH]
sniff --skip-dotenv [PATH]
sniff --yes [PATH]
```

Every eligible method is reviewed. Supported source languages are Rust, Python,
JavaScript, TypeScript, Go, and Kotlin.

Sniff runs up to four independent review pipelines concurrently and batches up
to eight same-file methods per request. Tune these with
`SNIFF_LLM_MAX_CONCURRENCY` and `SNIFF_LLM_METHOD_BATCH_SIZE`, each from `1` to
`8`. Methods from different files are never batched together.

Transient transport failures are retried up to 128 times within a 30-minute
budget by default. Malformed responses have a separate three-repair budget.
Tune these with `SNIFF_LLM_MAX_ATTEMPTS`, `SNIFF_LLM_RETRY_BUDGET_SECS`, and
`SNIFF_LLM_MAX_FORMAT_REPAIRS`. Fatal HTTP responses still fail immediately.

## Reliability Contract

Static analysis supplies repository evidence and graph context. The LLM reviews
every eligible method and returns `Slop`, `Kinda Slop`, `Clean`, or `Unresolved`.
A reported finding must include exact source evidence, a recognized slop-shaped
reason, contract impact, dependency proof, and a behavior-preserving
simplification.

Parsing, configuration, transport, response validation, incomplete coverage,
and report-writing failures are fatal. Sniff never emits a partial report as a
successful result. Every completed review is durably appended to a local journal
for safe resume; changed source, semantic context, or review contracts invalidate
stale entries.

Exit codes:

- `0`: complete report with no findings
- `1`: complete report containing `Slop` or `Kinda Slop`
- `2`: failed scan; no valid new report was produced

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo package --locked --target-dir target/package-check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Sniff is licensed under the GNU Affero General Public License, version 3. See
[LICENSE](LICENSE) and [TRADEMARKS.md](TRADEMARKS.md).
