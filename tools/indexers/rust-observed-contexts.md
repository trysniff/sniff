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

Observation mode enables strict primary, rustc-source and sysroot Cargo metadata:
there is no `--no-deps` prefetch or failed-full-query substitution, no copied
lockfile, and each full metadata command requires `--locked`. Missing or failed
sysroot metadata cannot be replaced by a stitched graph. Explicit no-deps and
lockfile-redirection arguments or environment settings are rejected. Before
metadata execution, an effective Cargo configuration query using the same
program, working directory, invocation environment and config selectors must succeed;
resolver or config-env lockfile redirection is rejected too.
Strict observations also use Cargo for workspace-root, sysroot, target, cfg,
target-layout and required rustc-source library-directory queries. Query failures
are errors, not triggers for direct-rustc retries, host-target substitution or
an empty cfg/layout. Config selectors have consistent precedence; exactly one
target is required. A host target is used only after a successful effective-config
query establishes that no target was configured. The selected sysroot must match
the same target's Cargo compiler. Rust sources must already exist; no rustup
component installation or alternate source search is attempted.
Cargo feature and target options remain before the single rustc passthrough
delimiter, including when callers already supply compiler arguments.

Config/compiler-print queries set `RUSTC_BOOTSTRAP=1` for their unstable Cargo
interfaces; metadata does not receive that additional override. Ordinary upstream
mode retains its recovery branches. Strict mode is opt-in and does not bypass an
unsupported or failing selected Cargo toolchain.

Compiler cfg identifiers and string values use the pinned Rust lexer and literal
escaper. Target layouts use the pinned Rust ABI parser plus explicit validation
of the supported [LLVM layout components](https://llvm.org/docs/LangRef.html#data-layout)
that parser otherwise ignores. Unknown or unsupported layout extensions fail;
this is not a replacement for LLVM or a guarantee of every target extension.
Non-byte pointer sizes and index widths fail because the pinned ABI backend
rounds them to bytes; they are unsupported here, not necessarily invalid LLVM.
Cargo 1.96 rejects Unicode cfg keys internally even though rustc accepts them.
The cfg parser preserves those identifiers, but an actual Cargo query failure
still fails the observation without a direct-rustc workaround.

The sidecar records the backend's crate roots, editions, effective analysis cfg,
crate environments, dependency contexts, observed module files (including body
and block maps), included files, parser errors, and inactive source ranges.
The source inventory reuses the ownership traversal rather than enumerating only
crate-level modules. Include-call identities retain the backend's item, statement,
expression, type or pattern grammar. Raw included-source lexer/parser errors keep
original byte ranges; shebang prefixes are excluded with offsets preserved.
Expansion parser errors use the backend span mapping. Unmappable include parser
errors and failed include expansions have separate counters, not guessed source
ranges or silent absence. Macro-expansion inactive ranges are counted as unmapped, not
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
- File/parser inventories now cover observed body/block maps and include calls.
  `block_local_module_file_coverage_complete` remains false: this traversal does
  not prove exhaustive macro/source associations or declared-world coverage.
- Diagnostics are queried only for crates rooted beneath the selected repository
  root, including any local or vendored dependencies there. Crates outside that
  root are explicitly marked as not queried.
- The strict observed Cargo loader bypasses its legacy query-recovery branches;
  other upstream loaders still contain recovery. This does not seal effective
  configuration, compiler inputs or workspace files against concurrent changes.
- Some valid target-layout extensions are unsupported by the pinned backend and
  fail explicitly. Six built-in release-platform layout queries are tested, not
  native execution or exhaustive qualification of every Rust target.
- The sidecar can contain crate environment values. Keep it private unless
  independently checked for secrets. It is not a public benchmark artifact.

Do not interpret empty observations as Clean, complete coverage, a compiler
exclusion census, or permission to reuse compiler results. Complete declared-world
discovery, closure sealing, public/consumer facts, complete source inventories,
and sandboxed native qualification remain necessary before production admission.

## Qualification

The `Rust backend observations` workflow applies the patch to the exact pristine
upstream pin and compiles it with Rust 1.96.0 on Windows, macOS, and Linux. It
requires all eighteen exporter tests, ten selected-context tests, the same-package
symbol-target regression, three sysroot tests, seven strict metadata tests and
twenty strict discovery tests, checks
that the binaries came from fresh compilation of that checkout, and runs
warning-denying Clippy. The owned metadata fixtures execute offline Cargo queries
and cover failed full queries, argument/config redirection, failed config queries,
missing lockfiles, unchanged locked inputs and missing/failed sysroot metadata.
The strict discovery fixtures cover actual Cargo queries without executing the
owned panic-on-build build script, selector precedence, selected-target sysroot
mismatch, failed workspace/config/compiler queries, rustc-source query failure,
escaped/Unicode cfg parsing, invalid or unsupported target layouts, and compiler
passthrough with selected Cargo features/targets. Built-in layout queries
cover Windows/macOS/Linux x86_64 and aarch64 without compiling those targets.
The owned sysroot fixture uses minimal generated core sources with the real
compiler; it is not qualification of the installed standard library.
Source-inventory regressions cover block modules in bodies, signatures, fields
and discriminants, per-crate ownership, included-source syntax errors, all five
include fragment grammars, and lexer error ranges with and without shebangs.
These backend library tests are not third-party workspace, sandbox, release-bundle,
or exhaustive-world proofs. They make no model calls.
