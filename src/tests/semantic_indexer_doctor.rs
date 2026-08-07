use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};

#[test]
fn pinned_version_output_rejects_similar_versions() {
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    assert!(spec.accepts_version_output("0.6.6"));
    assert!(!spec.accepts_version_output("0.6.6-dev"));
    assert!(!spec.accepts_version_output("0.6.60"));
}

#[test]
fn rust_platform_failure_is_explicit() {
    match pinned_indexer(SemanticIndexerKind::Rust) {
        Ok(spec) => assert!(spec.version.starts_with("2026-08-03")),
        Err(error) => assert!(error.contains("has no pinned asset")),
    }
}
