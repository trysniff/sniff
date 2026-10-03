# Rust backend observations

`patches/rust-analyzer-observed-contexts.patch` applies to upstream
rust-analyzer commit `b54a82b321c9617c5cf0b07ac0f12c08f7bc5902`
(tag `2026-08-03`). Upstream rust-analyzer is MIT OR Apache-2.0 licensed;
the Sniff modifications are covered by this repository's AGPL-3.0-only license.

The patch adds opt-in SCIP flags:

```text
rust-analyzer scip . --output index.scip --sniff-project-model-output contexts.json
```

To select exactly one loaded backend crate root/name and its actual dependency
closure, provide both selectors:

```text
rust-analyzer scip . --output index.scip --sniff-project-model-output contexts.json --sniff-crate-root src/lib.rs --sniff-crate-name my_crate
```

The root must be inside the repository. Missing or ambiguous backend matches
fail; selection is not a name-based symbol resolver. Unrelated reverse-dependent
crates are removed before analysis snapshots, without rewriting retained inputs.

Both output destinations must be new files in existing directories. The command
refuses degraded primary/sysroot Cargo metadata, stitched sysroots, unavailable
toolchain/target information, and failed build-script context. Invalid SCIP
configuration is an error rather than a logged configuration default.

The sidecar records the backend's crate roots, editions, effective analysis cfg,
crate environments, dependency contexts, crate-level module files, parser errors,
and inactive source ranges. Macro-expansion ranges are counted as unmapped, not
promoted to original-source exclusions. Inline diagnostic traversal is not
repeated. Duplicate context identities fail rather than merging ambiguously.

Output files are staged and synced before no-clobber publication. The sidecar
is published last, only after SCIP publication succeeds. Its byte length and
TentHash checksum pair it with that SCIP output; **this is not a cryptographic
security seal**. A sidecar-publication failure can leave a complete SCIP file
and returns an error. It must not be treated as a completed observation pair.

## Selected Contexts

The sidecar uses schema 2 and contract
`sniff-rust-observed-crate-contexts-v2-not-world-admission`.
Selected mode independently traverses compiler-owned module/block maps,
body/signature/field expression stores, associated items and include calls.
Competing source associations fail rather than letting a first-module lookup
silently select one. Inline lexical scopes are not separate whole-file owners.
Missing backend module ownership also fails.

Selected-mode macro indexing retains every distinct supported descended
definition rather than only the first nonempty expansion. Global SCIP symbols
are qualified by each **definition's** retained backend crate context, including
referenced dependencies outside emitted documents. Remaining distinct-definition
symbol aliases fail. Local symbols retain SCIP's document-local semantics.
The sidecar records the selected root, each emitted document's owner and the
namespace-to-context mapping for global symbols. Namespace hashes distinguish
observed identities; they are not security seals or compiler-input closure proof.

Without both selectors, the exporter retains the unselected observation behavior
and marks occurrence-context selection unavailable. It does not claim coherent
selected occurrence facts from that mode.

## Explicit Limits

This is **not a qualified compiler-world producer** and is not enabled in
Sniff's normal scan or its released indexer bundles. No manifest URLs or binary
checksums are changed by adding this patch.

- `declared_world_domain_complete` and `input_closure_proven` are always false.
- Effective rust-analyzer cfg includes backend adjustments; it is not proof of
  literal rustc flags, every Cargo target, or every declared feature/target world.
- Context selection covers one uniquely selectable loaded backend crate and its
  dependencies, not an exhaustive declared Cargo target/feature/world domain.
- Block-local module-file coverage is explicitly incomplete. Module inventories
  and parser-error inventories cover observed crate-level module sources only.
- Diagnostics are queried only for crates rooted beneath the selected repository
  root, including any local or vendored dependencies there. Crates outside that
  root are explicitly marked as not queried.
- Upstream can attempt internal recovery during discovery; the loader rejects
  the degraded result. This does not prove absence of every recovery attempt.
- The sidecar can contain crate environment values. Keep it private unless
  independently checked for secrets. It is not a public benchmark artifact.

Do not interpret empty observations as Clean, complete coverage, a compiler
exclusion census, or permission to reuse compiler results. Complete declared-world
discovery, closure sealing, public/consumer facts, complete source inventories,
and sandboxed native qualification remain necessary before production admission.

## Qualification

The `Rust backend observations` workflow applies the patch to the exact pristine
upstream pin and compiles it with Rust 1.96.0 on Windows, macOS, and Linux. It
requires all eleven exporter tests, ten selected-context tests, the same-package
symbol-target regression and the stitched-sysroot rejection test, checks
that the binaries came from fresh compilation of that checkout, and runs
warning-denying Clippy. These are backend library tests, not Cargo workspace,
sandbox, release-bundle, or exhaustive-world proofs. They make no model calls.
