# Sniff

Sniff is a slop finder. Its only purpose is to find code that makes humans
spend unnecessary effort understanding, trusting, or changing it.

It is not a security scanner, bug finder, or generic code-quality platform.

## Install

Install Rust from <https://rustup.rs>, then install Sniff from GitHub:

```powershell
cargo install sniff-cli
```

The `sniff` command is then available through Cargo's binary directory.

For local development, clone the repository and run `cargo install --path .
--locked` from its root.

## Configure

Sniff requires a funded LLM provider for normal scans. Put the configuration in
the repository being scanned, or export it in the environment:

```dotenv
SNIFF_API_KEY=your-key
SNIFF_ENDPOINT=https://provider.example/v1
SNIFF_MODEL=your-model
# Optional method/file pipelines in flight at once (1-8; default 4).
SNIFF_LLM_MAX_CONCURRENCY=4
# Optional same-file methods reviewed per model request (1-8; default 8).
SNIFF_LLM_METHOD_BATCH_SIZE=8
# Optional provider context window in tokens (default 128000).
SNIFF_LLM_CONTEXT_TOKENS=128000
# Optional direct character ceiling; overrides the derived context limit.
# SNIFF_LLM_MAX_PROMPT_CHARS=500000
# Optional cost-estimate rates, in USD per million tokens.
SNIFF_INPUT_COST_PER_MILLION=0.14
SNIFF_CACHED_INPUT_COST_PER_MILLION=0.0028
SNIFF_OUTPUT_COST_PER_MILLION=0.28
```

The endpoint and model are read from `SNIFF_ENDPOINT` and `SNIFF_MODEL`; Sniff
does not hardcode a provider. OpenAI-compatible endpoints use the chat
completion envelope. Endpoints whose URL contains `/anthropic` use the
Anthropic envelope. Optional repository thresholds and ignore rules belong in
`sniff.config.toml`. The report cost line uses the configured rates, which are
estimates rather than provider billing data.

## Run

Run the exhaustive method and file review from a repository root:

```powershell
sniff
sniff C:\path\to\repository
```

Useful flags:

```text
--with-file-reviews    add secondary file-level reviews; methods are always reviewed
--only-files           deprecated alias for --with-file-reviews
--skip-dotenv   do not load .env files
```

The normal scan writes `sniff-report.md` at the scanned repository root when
the target is outside the current directory. Scans of the current directory
continue to write it there. Supported source languages are Rust,
Python, JavaScript, TypeScript, Go, and Kotlin.

Transient transport failures are retried up to 128 times within a 30-minute
budget by default. Set `SNIFF_LLM_MAX_ATTEMPTS` and
`SNIFF_LLM_RETRY_BUDGET_SECS` to tune those limits. Malformed responses have a
separate three-repair budget, configurable with
`SNIFF_LLM_MAX_FORMAT_REPAIRS`; they cannot consume all transport retries.
Fatal HTTP responses such as an invalid endpoint status or insufficient balance
still fail immediately.

Sniff runs up to four independent review pipelines concurrently by default.
Set `SNIFF_LLM_MAX_CONCURRENCY` between `1` and `8` to tune throughput. Within
one file, Sniff reviews up to eight methods in a shared request so the containing
file is not retransmitted for every method. Set
`SNIFF_LLM_METHOD_BATCH_SIZE` between `1` and `8` to tune the batch. Every
method retains an independent intent pass, adversarial challenge, adjudication,
evidence boundary, verdict, and checkpoint entry; methods from different files
are never batched together. Evidence-heavy batches automatically shrink to fit
the configured context window. If a complete single-method prompt cannot fit,
Sniff fails before sending the request rather than truncating evidence.

## Reliability Contract

Sniff reviews every eligible method by default. Optional file-level reviews run
only with `--with-file-reviews`. Static analysis supplies context; the LLM makes
the semantic Slop, Kinda Slop, Clean, or Unresolved judgment. A finding must
contain exact source evidence and a recognized slop-shaped reason.

Parsing, configuration, transport, response validation, or report-writing
failures are fatal. Sniff retries malformed or transient responses, but never
falls back to a partial or static-only report. Runs leave the last completed
`sniff-report.md` unchanged on failure and retain fingerprinted review caches
for later runs. Changed source, model contracts, and retryable validation
failures are invalidated instead of being reused.

Exit codes are:

- `0`: completed report with no findings
- `1`: completed report containing Slop or Kinda Slop
- `2`: scan failure; no valid report was produced

## Development

Run the complete local verification suite:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## License

Sniff is licensed under the GNU Affero General Public License, version 3.
See [LICENSE](LICENSE) and [TRADEMARKS.md](TRADEMARKS.md).
