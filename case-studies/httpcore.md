# httpcore: Python Validation

## Scope

- Repository: [encode/httpcore](https://github.com/encode/httpcore)
- Target commit: [`10a6582`](https://github.com/encode/httpcore/commit/10a658221deb38a4c5b16db55ab554b0bf731707)
- Sniff version: `0.2.2`
- Accepted Sniff commit: `bcdac72`
- Model: `deepseek-v4-flash`
- Endpoint: `https://api.deepseek.com/anthropic`
- Pre-run estimate: $0.13-$0.31 and 2-90 minutes
- Validation binary SHA-256: `A0CDF334B8FD890E7164A7C9D62ACF7DB724478AA277A55106E9AB3B137AA368`
- Files: 32
- Methods: 329

## Accepted Result

Sniff emitted 329 of 329 review records and resolved all 329 method verdicts.
It reported zero `Slop`, zero `Kinda Slop`, and zero unresolved reviews.

- Runtime across paid checkpoint segments: approximately 2 hours 2 minutes
- Final verdict-set cost: $0.2175
- Tokens: 2,468,986 input, 225,639 output, 1,394,255 cached input

One local supervisor timeout interrupted the run after roughly 68 minutes.
Sniff preserved the completed reviews and resumed from its checkpoint; it did
not emit or accept a partial report. Two later provider-balance failures
stopped at preflight and did not consume method-review tokens.

## Rejected Results

The model proposed seven dead-code removals, all of which the final analyzer
rejected:

- four `__iter__` implementations used through Python's iteration protocol
- three `__repr__` implementations used through Python's representation
  protocol

The proposals covered synchronous and asynchronous connection-pool stream
wrappers and byte-stream representations. Each explanation incorrectly
treated the absence of an explicit repository call edge as proof that the
method had no consumer. Python invokes these data-model methods implicitly, so
all seven proposals were false positives.

Adjudication: 0 confirmed, 0 defensible, 7 false positives, and 0
context-dependent proposals. None survived as a report finding.

## What Changed

Sniff now recognizes Python data-model methods as language protocol boundaries.
A private-unused proof cannot treat a supported dunder as dead merely because
the repository graph contains no direct `obj.__iter__()` or `obj.__repr__()`
call. Regression tests cover the protocol classification and final finding
gate.

## Conclusion

This study demonstrates exhaustive Python method review, durable recovery from
an interrupted run, and rejection of plausible but semantically invalid
dead-code claims. It does not prove that every framework callback, descriptor,
or dynamically installed Python method is already modeled.
