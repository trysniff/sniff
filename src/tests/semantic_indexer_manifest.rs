use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, SemanticIndexerKind, VersionOutput, pinned_indexer,
    required_indexers,
};
use crate::types::FileRecord;

fn file(language: &str) -> FileRecord {
    FileRecord {
        file_path: format!("fixture.{}", language.to_ascii_lowercase()),
        language: language.to_string(),
        source: String::new(),
        methods: Vec::new(),
    }
}

#[test]
fn all_supported_languages_have_a_pinned_indexer() {
    let kinds = [
        SemanticIndexerKind::TypeScriptJavaScript,
        SemanticIndexerKind::Python,
        SemanticIndexerKind::Go,
        SemanticIndexerKind::Kotlin,
        SemanticIndexerKind::Rust,
    ];
    for kind in kinds {
        let spec = pinned_indexer(kind).expect("supported indexer must be pinned");
        assert!(!spec.version.is_empty());
        assert!(!spec.entrypoint_relative_path().as_os_str().is_empty());
    }
}

#[test]
fn language_inventory_maps_javascript_and_typescript_to_one_indexer() {
    let files = [
        file("JavaScript"),
        file("typescript"),
        file("Python"),
        file("go"),
        file("KOTLIN"),
        file("rust"),
        file("Ruby"),
    ];
    let kinds = required_indexers(&files);
    assert_eq!(kinds.len(), 5);
    assert!(kinds.contains(&SemanticIndexerKind::TypeScriptJavaScript));
    assert!(kinds.contains(&SemanticIndexerKind::Python));
    assert!(kinds.contains(&SemanticIndexerKind::Go));
    assert!(kinds.contains(&SemanticIndexerKind::Kotlin));
    assert!(kinds.contains(&SemanticIndexerKind::Rust));
}

#[test]
fn version_matching_is_exact_or_token_exact() {
    let typescript = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    assert!(typescript.accepts_version_output("0.4.0"));
    assert!(!typescript.accepts_version_output("0.4.01"));
    assert!(!typescript.accepts_version_output("scip-typescript 0.4.0-dev"));

    let go = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    assert!(go.accepts_version_output("scip-go version 0.2.7"));
    assert!(!go.accepts_version_output("scip-go 0.2.70"));
    assert!(!go.accepts_version_output("v0.2.7"));
}

#[test]
fn pinned_sources_have_expected_distribution_contracts() {
    let javascript = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    assert!(matches!(
        javascript.source,
        IndexerInstallSource::Npm {
            package: "@sourcegraph/scip-typescript",
            integrity_sha512: _
        }
    ));
    assert!(matches!(
        javascript.version_output,
        VersionOutput::Exact("0.4.0")
    ));

    let kotlin = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    assert!(matches!(
        kotlin.source,
        IndexerInstallSource::Download(download) if download.archive == DownloadArchive::Raw
    ));
}

#[test]
fn rust_pin_selects_a_platform_asset_or_reports_unsupported_platform() {
    match pinned_indexer(SemanticIndexerKind::Rust) {
        Ok(spec) => match spec.source {
            IndexerInstallSource::Download(download) => {
                assert_eq!(download.sha256.len(), 64);
                assert!(!download.url.is_empty());
            }
            _ => panic!("rust-analyzer must use a pinned download"),
        },
        Err(error) => assert!(error.contains("has no pinned asset")),
    }
}
