# CertMagic: Go Validation

## Scope

- Repository: [caddyserver/certmagic](https://github.com/caddyserver/certmagic)
- Target commit: [`38cdd62`](https://github.com/caddyserver/certmagic/commit/38cdd6254bf2fc9c5e456aae41a93214e0e64514)
- Sniff version: `0.2.2`
- Accepted Sniff commit: `53852e1`
- Validation binary SHA-256: `5515C390977C281EBFB18D61FED2822D3A3C16377CFBD304AF96C491CAF4A23E`
- Files: 22
- Methods: 294

## Accepted Result

Sniff emitted 294 of 294 review records and resolved all 294 method verdicts.
It reported one `Slop`, zero `Kinda Slop`, and zero unresolved reviews.

- Baseline runtime: 30 minutes 44 seconds
- First targeted correction: 18 minutes 51 seconds
- Final targeted correction: 5 minutes 26 seconds
- Final verdict-set cost: $0.1622
- Tokens: 2,027,283 input, 206,045 output, 1,307,080 cached input

The baseline and two targeted corrections cost approximately $0.3297 in
total. The final correction added 63 checkpoint records and cost approximately
$0.0413; Sniff did not restart all 294 method reviews.

## Confirmed Finding

[`preferredDefaultCipherSuites`](https://github.com/caddyserver/certmagic/blob/38cdd6254bf2fc9c5e456aae41a93214e0e64514/crypto.go#L305)
is an unexported function with no repository caller, registration, callback,
test, or protocol role. Its only dependencies, `defaultCiphersPreferAES` and
`defaultCiphersPreferChaCha`, are private arrays referenced nowhere else.
Removing the function and those arrays eliminates a self-contained stale
cipher-selection cluster.

Adjudication: 1 confirmed, 0 defensible, 0 false positive, and 0
context-dependent findings in the accepted report.

The machine used for this study did not have the Go toolchain installed, so
the removal was not compile-tested. Confirmation is based on the closed
repository graph, an independent exact-identifier search, visibility, and
inspection of the complete source cluster. This limitation is material and is
recorded rather than hidden.

## Rejected Results

The baseline report was rejected because it falsely called three live methods
dead and left seven API or protocol surfaces unresolved:

- `permit` and `advance` are called through same-package receiver expressions.
- `httpRedirectHandler` is passed as an `http.HandlerFunc` callback.
- `maintainAssets` is started from the cache lifecycle and then recurs.
- `Dup` is imported by full Go module path and has build-tag alternatives.
- two exported certificate-cache APIs and `Stop` are public boundaries.
- `solverWrapper.Present`, `Wait`, and `CleanUp` implement guarded interfaces
  on a constructed owner.

After the first correction, `permit`, `advance`, `maintainAssets`, and `Dup`
still lacked complete graph evidence. That second report was also rejected.
Across the rejected reports, three proposed findings were false positives;
the seven unresolved reviews were context-dependent analyzer gaps, not
accepted findings.

## What Changed

Sniff now resolves Go receiver calls before treating the receiver name as a
package qualifier, records function values passed as callbacks, parses grouped
and aliased imports, maps full local imports through `go.mod`, and shares call
evidence across build-tag implementations. It also carries construction,
interface-guard, lifecycle, and public-boundary evidence into method dossiers.
Focused regressions and the complete Rust test suite cover these corrections.

## Conclusion

This study demonstrates an exhaustive Go review that retained a real private
dead-code finding while rejecting plausible false findings caused by callbacks,
receivers, module imports, interfaces, and build tags. It does not claim that
Sniff interprets arbitrary code generation or every runtime registration
framework.
