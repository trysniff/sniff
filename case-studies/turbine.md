# Turbine: Kotlin Validation

## Scope

- Repository: [cashapp/turbine](https://github.com/cashapp/turbine)
- Target commit: [`0fbb877`](https://github.com/cashapp/turbine/commit/0fbb8774aa6da2c4d524ab4cfb03dfd575613240)
- Sniff version: `0.2.2`
- Accepted Sniff runtime commit: `1ef4100`
- Model: `deepseek-v4-flash`
- Endpoint: `https://api.deepseek.com/anthropic`
- Pre-run estimate: $0.08-$0.19 and 1-56 minutes
- Files: 15
- Methods: 234

## Accepted Result

Sniff emitted 234 of 234 review records and resolved all 234 method verdicts.
It reported zero `Slop`, zero `Kinda Slop`, and zero unresolved reviews.

- Final correction resume: 11 minutes 3 seconds
- Final verdict-set cost: $0.0461
- Tokens: 858,952 input, 115,882 output, 777,216 cached input

The accepted run reused 232 clean checkpoint entries and re-reviewed the two
methods invalidated by the analyzer correction.

## Rejected Results

The first run incorrectly called two methods dead:

- `TurbineAssertionError.invoke`, which constructs the type through its
  companion object and private constructor pattern
- `stripCancellations`, which participates in Turbine's fluent cancellation
  filtering path

Later verification also caught a run made with a stale workspace binary. That
run was rejected rather than presented as proof.

The four validation iterations cost $0.2551 in total. The accepted report's
verdict set accounts for $0.0461 of that amount.

## What Changed

Sniff's Kotlin graph learned companion-object construction, private constructor
relationships, and fluent receiver chains. The validation workflow also began
recording the binary hash and runtime commit so a stale executable cannot be
mistaken for the code under test.

## Conclusion

This study demonstrates exhaustive Kotlin method coverage, checkpoint-safe
targeted correction, and artifact identity checks. It does not claim complete
semantic modeling of every Kotlin compiler plugin or generated-code pattern.
