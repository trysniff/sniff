# Contributing to Sniff

Thank you for helping make Sniff a more trustworthy slop finder.

## Before You Start

Read the [README](README.md), [SECURITY.md](SECURITY.md), and
[TRADEMARKS.md](TRADEMARKS.md). Do not include API keys, `.env` files, private
source code, or generated `sniff-report.md` files in commits.

## Development Setup

Install stable Rust, then run the verification suite from the repository root:

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo package --locked
```

Use local mock endpoints and fixtures for analyzer tests. Do not add tests that
call a real paid model provider or require a secret.

## Analyzer Changes

Sniff is a slop finder, not a generic bug or security scanner. Changes to
classification, evidence, roles, prompts, parsing, retries, or report output
should include a focused regression or gold test. A finding must remain tied to
exact source evidence and a recognized slop reason.

When changing review orchestration, verify that every eligible method and file
still receives its required review and that failures cannot produce a partial
report.

## Pull Requests

- Keep each pull request focused on one change.
- Explain the user-visible behavior and the slop-detection impact.
- Add or update tests for behavior changes.
- Run the full local verification suite before opening the pull request.
- Do not bypass CI, force-push `main`, or commit generated reports.

For false-positive fixes, include the affected path, method or file, the old
finding, the exact source evidence, and why the new behavior is correct. Remove
secrets and private source before sharing examples.

## Commit Messages

Use short imperative messages, for example:

```text
Reject unsupported file-level evidence
```

## Questions and Discussions

Use a GitHub issue for reproducible behavior, false positives, or feature
proposals. Use the security process in [SECURITY.md](SECURITY.md) for
vulnerabilities and never disclose their details publicly.
