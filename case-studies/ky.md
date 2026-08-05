# Ky: TypeScript Validation

## Scope

- Repository: [sindresorhus/ky](https://github.com/sindresorhus/ky)
- Target commit: [`3419113`](https://github.com/sindresorhus/ky/commit/3419113b48e034fdcf8fa6bd3be3da7b3d0d758f)
- Sniff version: `0.2.2`
- Accepted Sniff commit: `e2106ef`
- Files: 30
- Methods: 135

## Accepted Result

Sniff emitted 135 of 135 review records and resolved all 135 method verdicts.
It reported zero `Slop`, zero `Kinda Slop`, and zero unresolved reviews.

- Runtime: 42 minutes 8 seconds
- Final verdict-set cost: $0.0507
- Tokens: 924,313 input, 151,484 output, 882,944 cached input

This means no evidence-backed slop was found under the review contract. It
does not mean Ky contains no code that a maintainer might choose to change.

## Rejected Result

An earlier run reported the anonymous default `retry.delay` callback as dead
conceptual machinery and left 16 methods unresolved. The dead-code claim was
false: `normalizeRetryOptions` carries the callback into Ky's options and
`Ky.#calculateDelay()` invokes it in the request retry path.

The unresolved reviews exposed two separate reliability defects:

- malformed or empty batch responses were not repaired robustly enough
- public and externally consumable TypeScript symbols lacked sufficient
  boundary evidence for a trusted verdict

That rejected run cost $0.0581. It was not counted as a successful clean scan.

## What Changed

Sniff was changed to require stronger dependency proof before accepting a
dead-code verdict, preserve unresolved status when external use cannot be
excluded, and repair malformed batch responses without silently dropping
method coverage. Regression tests cover the failure classes.

## Conclusion

This study demonstrates exhaustive TypeScript review and honest failure on
insufficient evidence. It does not demonstrate that every TypeScript language
or framework construct is already modeled.
