# fd: Rust Validation

## Scope

- Repository: [sharkdp/fd](https://github.com/sharkdp/fd)
- Target commit: [`41532d1`](https://github.com/sharkdp/fd/commit/41532d114e2ba565fb5367d606c111b29b96450c)
- Sniff version: `0.2.2`
- Accepted Sniff commit: `e530db0`
- Model: `deepseek-v4-flash`
- Endpoint: `https://api.deepseek.com/anthropic`
- Pre-run estimate: $0.09-$0.20 and 1-56 minutes
- Validation binary SHA-256: `963FC1D865F628EE746F690CA7EFFA908446630DB0751143571253E2F1563D0D`
- Files: 22
- Methods: 217

## Accepted Result

Sniff emitted 217 of 217 review records and resolved all 217 method verdicts.
It reported zero `Slop`, zero `Kinda Slop`, and zero unresolved reviews.

- Full baseline runtime: 12 minutes 48 seconds
- Targeted correction resume: 58 seconds
- Final verdict-set cost: $0.0975
- Tokens: 898,312 input, 126,128 output, 463,335 cached input

The initial run plus targeted correction cost $0.1194 in total. Only 34
invalidated method keys required paid re-review after the analyzer fix.

## Rejected Result

The first run incorrectly reported four Rust methods as dead:

- two `cfg`-selected implementations whose callers resolve to the active
  same-name implementation
- a receiver method called inside a `vec!` macro
- a command-line parser referenced by a proc-macro attribute

All four had concrete repository consumers. The report was rejected even
though the dead-code explanations sounded internally consistent.

## What Changed

Sniff's Rust analyzer now collects identifiers from macro and proc-macro
attribute token streams, resolves calls inside nested macro syntax, and fans a
real call out to mutually configured same-owner implementations. Exact
regression tests cover each construct.

## Conclusion

This study demonstrates why dead-code findings require semantic evidence beyond
plain symbol-name search. It does not claim to replace the Rust compiler or to
resolve every generated expansion from arbitrary procedural macros.
