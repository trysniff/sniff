# Language Capabilities

This describes the current development source, not every previously published
crate or candidate. Use the documentation at your installed release's tag.
All six languages below are product targets. Unfinished capabilities remain
required work; they are not being reclassified as optional languages.

Sniff reviews every eligible AST method. That census is not a claim that a
compiler index proves every possible runtime consumer or build configuration.
A missing required indexer, unresolved required method join, or incomplete
method context fails the run rather than substituting a name-based graph.

## Source And Provider Baselines

| Language | Inventoried extensions | AST parser | Required pinned semantic provider |
| --- | --- | --- | --- |
| Python | `.py`, `.pyi` | RustPython | `scip-python` |
| JavaScript | `.js`, `.jsx` | Oxc | `scip-typescript` |
| TypeScript | `.ts`, `.tsx` | Oxc | `scip-typescript` |
| Rust | `.rs` | syn | `rust-analyzer` SCIP |
| Go | `.go` | tree-sitter | `scip-go` |
| Kotlin | `.kt`, `.kts` | tree-sitter | `scip-java` |

These extensions describe inventory acceptance, not a guarantee that every
project using them is indexable. In particular, `.mjs`, `.cjs`, `.mts`, and
`.cts` are not currently inventoried. Installed providers include Sniff's
pinned patches; an arbitrary executable with the same name is not equivalent.
Run `sniff indexers doctor <path>` to check the actual installation and runtime.

The supported cross-file fixture baseline covers Python, JS, TS, Rust, Go,
and Kotlin/JVM. Kotlin's current provider boundary does not qualify Android
or general KMP repositories. Recognized Android Gradle integrations fail
explicitly; this is not an Android-capable semantic indexer. Kotlin/JVM
success must not be presented as Android, native, or all-platform KMP coverage.

## Normal-Scan Evidence Matrix

The statuses deliberately distinguish verified fixture behavior from an IR
field that merely exists:

- **Baseline:** supported cross-file fixtures validate this path, not all constructs.
- **Reported:** retained when the provider emits the fact; emission and completeness are provider-dependent.
- **Source:** supplemental source/role context, not compiler-proven runtime registration.
- **Unproven:** normal scans do not establish complete evidence for this capability.

| Capability | Python | JavaScript | TypeScript | Rust | Go | Kotlin/JVM |
| --- | --- | --- | --- | --- | --- | --- |
| Definition identity and exact AST method join | Baseline | Baseline | Baseline | Baseline | Baseline | Baseline |
| Cross-file symbol references | Baseline | Baseline | Baseline | Baseline | Baseline | Baseline |
| Import symbol facts | Reported | Reported | Reported | Reported | Reported | Reported |
| Complete re-export/consumer closure | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Enclosing method/type ownership | Reported | Reported | Reported | Reported | Reported | Reported |
| Implementation and type relationships | Reported | Reported | Reported | Reported | Reported | Reported |
| Complete override/interface dispatch closure | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Exhaustive dynamic-call resolution | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Framework entrypoint context | Source | Source | Source | Source | Source | Source |
| Complete generated-code/macro coverage | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Variant-qualified normal scan | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Complete public-API/consumer boundaries | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |
| Typed discovered test-to-production links | Unproven | Unproven | Unproven | Unproven | Unproven | Unproven |

## What Unknown Means

Normal scan preflight currently executes unqualified compiler indexes. Separate
qualified execution exists for Go and JS/TS, but that is not yet normal-scan
build-matrix coverage. A default build is not proof that a method is unused in
another Cargo feature, Go build-tag/target combination, compiler project, or
Gradle configuration. Qualified indexes preserve their identity and dimensions
when rendered; that rendering does not establish that all required variants ran.

The method dossier retains provider-reported relationships for the exact method
and contract links for its immediate resolved enclosing symbol, including
direction, symbol identity, and related signatures. This is not a transitive
dispatch closure or proof that every implementing type has been discovered.
Unknown ownership remains unknown, with any reported raw target retained.

SCIP ingestion does not currently populate complete public/entrypoint surfaces
or discovered typed test-to-production links for normal scans. Missing entries
are explicitly unestablished evidence, not proof that exports or tests are
absent. Other source, test-reference, and role context can still be supplied;
it must not be confused with a complete compiler-resolved consumer graph.
Benchmark-only exposure ledgers do not fill these normal-scan gaps.

Known unsupported, ambiguous, dynamic, missing-definition, and external-contract
facts can be represented as unresolved edges. Their absence is not a guarantee
that all unknown constructs were discovered. Explicit compiler exclusions are
recorded separately from indexed methods; they are not quietly counted as
compiler-resolved coverage. A missing indexer or unsupported required construct
never triggers a weaker resolver.

## Evidence Scope

The baseline is exercised by the repository's cross-language dogfood tests and
`tests/semantic_gold_fixtures`, including exact compiler-to-method relationships.
The ingestion/join/renderer regressions also use explicitly synthetic SCIP
bytes; those tests are not real compiler-run or finding-accuracy measurements.

Passing those tests, reviewing every method, or verifying a native candidate's
packaging does not prove slop precision or recall on a new repository. Blind
comparative evaluation and final current-runtime release qualification remain
unfinished. Sniff must not claim to be the number-one slop finder without that
published evidence.
