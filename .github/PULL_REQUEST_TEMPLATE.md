## Summary

<!-- What changed, and why? -->

## Slop-Finder Impact

- [ ] This does not change analyzer behavior.
- [ ] This changes analyzer behavior and includes regression or gold tests.
- [ ] This changes prompts, evidence rules, parsing, retries, or report output.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all --locked`
- [ ] `cargo package --locked --target-dir target/package-check`

## Checklist

- [ ] No secrets, `.env` files, private source, or generated reports are included.
- [ ] Documentation is updated when user-visible behavior changes.
- [ ] This PR does not weaken the no-partial-report failure policy.
