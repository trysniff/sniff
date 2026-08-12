use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, SemanticIndexerKind, VersionOutput, pinned_indexer,
    required_indexers, rust_analyzer_download_for,
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

    let rust = pinned_indexer(SemanticIndexerKind::Rust).unwrap();
    assert!(
        rust.accepts_version_output("rust-analyzer 0.3.2997-standalone (b54a82b32 2026-08-02)")
    );
    assert!(
        rust.accepts_version_output("rust-analyzer 0.3.2997-standalone (b54a82b321 2026-08-02)")
    );
    assert!(
        !rust.accepts_version_output("rust-analyzer 0.3.2997-standalone (b54a82b3 2026-08-02)")
    );
    assert!(
        !rust.accepts_version_output("rust-analyzer 0.3.2997-standalone (b54a82b33f 2026-08-02)")
    );
    assert!(
        !rust.accepts_version_output("rust-analyzer 0.3.2997-standalone (b54a82b32 2026-08-03)")
    );
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

#[test]
fn windows_rust_pins_use_the_reproducible_v1_2_compatibility_bundles() {
    let x64 = rust_analyzer_download_for("windows", "x86_64", false).unwrap();
    assert_eq!(
        x64.url,
        "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.2/sniff-rust-indexer-x86_64-pc-windows-msvc.zip"
    );
    assert_eq!(
        x64.sha256,
        "4b57083b09b46634eabf24589f7059001de7f91f0007875ed6133c4a1727a6a5"
    );
    assert_eq!(x64.archive, DownloadArchive::Zip);

    let arm64 = rust_analyzer_download_for("windows", "aarch64", false).unwrap();
    assert_eq!(
        arm64.url,
        "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.2/sniff-rust-indexer-aarch64-pc-windows-msvc.zip"
    );
    assert_eq!(
        arm64.sha256,
        "dc1d0bdf114919290635f4f2d95eb2c76a744ba406a1ebf62dd38d63069f8361"
    );
    assert_eq!(arm64.archive, DownloadArchive::Zip);
}
