# OSS Validation

These studies record Sniff runs against pinned, third-party repositories. They
are reliability evidence, not claims that the target projects are perfect.
A result with zero findings means that Sniff completed every eligible method
review and found no slop that satisfied its evidence contract.

## Method

Each study follows the same process:

1. Pin the target repository to a commit.
2. Run Sniff across every discovered method.
3. Inspect every `Slop`, `Kinda Slop`, and `Unresolved` result against source,
   callers, tests, registrations, protocols, macros, and build configuration.
4. Reject analyzer mistakes instead of accepting plausible-looking findings.
5. Add a general analyzer fix and regression test, then resume from the
   checkpoint.
6. Accept a run only when every eligible method has a trusted verdict.

## Completed Studies

| Language | Repository | Target commit | Methods | Trusted verdicts | Final findings | Final verdict-set cost |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| TypeScript | [Ky](ky.md) | `3419113` | 135 | 135 / 135 | 0 | $0.0507 |
| Kotlin | [Turbine](turbine.md) | `0fbb877` | 234 | 234 / 234 | 0 | $0.0461 |
| Rust | [fd](fd.md) | `41532d1` | 217 | 217 / 217 | 0 | $0.0975 |
| Python | [httpcore](httpcore.md) | `10a6582` | 329 | 329 / 329 | 0 | $0.2175 |
| Go | [CertMagic](certmagic.md) | `38cdd62` | 294 | 294 / 294 | 1 | $0.1622 |

Together these studies cover 1,209 methods. Every method received a trusted
verdict, and one of the 1,209 produced a confirmed finding. The accepted
reports represent $0.5740 of final verdict-set cost. Including rejected and
corrective iterations, the validation campaign cost approximately $1.0305.

## Reading The Numbers

The final verdict-set cost is calculated from the token usage represented by
the accepted report. It is not always the total cost of developing and
correcting Sniff: rejected experimental runs also consumed tokens. Each study
discloses those iterations separately.

Provider latency, cache behavior, retries, repository shape, and model choice
all affect runtime and cost. These measurements are reproducible observations
from pinned inputs, not universal benchmarks.
