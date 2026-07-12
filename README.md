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
# Optional cost-estimate rates, in USD per million tokens.
SNIFF_INPUT_COST_PER_MILLION=0.14
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
--only-files    review files only; skips method-level LLM review
--skip-dotenv   do not load .env files
```

The normal scan writes `sniff-report.md` at the scanned repository root when
the target is outside the current directory. Scans of the current directory
continue to write it there. Supported source languages are Rust,
Python, JavaScript, TypeScript, Go, and Kotlin.

Transient or malformed model responses are retried up to 32 times by default.
Set `SNIFF_LLM_MAX_ATTEMPTS` to tune that limit; fatal HTTP responses such as
an invalid endpoint status or insufficient balance still fail immediately.

## Reliability Contract

Sniff reviews every eligible method and every scanned file by default. Static
analysis supplies context; the LLM makes the semantic Slop, Kinda Slop, or
Clean judgment. A non-clean result must contain exact source evidence and a
recognized slop-shaped reason.

Parsing, configuration, transport, response validation, or report-writing
failures are fatal. Sniff retries malformed or transient responses, but never
falls back to a partial or static-only report. A failed run removes any stale
`sniff-report.md` and writes no replacement.

Exit codes are:

- `0`: completed report with no findings
- `1`: completed report containing Slop or Kinda Slop
- `2`: scan failure; no valid report was produced

## Development

Run the complete local verification suite:

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## License

Sniff is licensed under the GNU Affero General Public License, version 3.
See [LICENSE](LICENSE) and [TRADEMARKS.md](TRADEMARKS.md).
