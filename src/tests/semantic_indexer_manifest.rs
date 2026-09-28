use crate::semantic_indexer_manifest::{
    DownloadArchive, IndexerInstallSource, SemanticIndexerKind, VersionOutput, pinned_indexer,
    required_indexers, rust_analyzer_download_for,
};
use crate::types::FileRecord;
use base64::Engine;

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
    let IndexerInstallSource::NpmTarballs { packages } = javascript.source else {
        panic!("scip-typescript must use pinned npm tarballs");
    };
    assert_eq!(
        packages
            .iter()
            .map(|package| (package.name, package.version))
            .collect::<Vec<_>>(),
        [
            ("@sourcegraph/scip-typescript", "0.4.0"),
            ("commander", "12.1.0"),
            ("google-protobuf", "3.21.4"),
            ("progress", "2.0.3"),
            ("typescript", "5.6.2"),
        ]
    );
    assert!(packages.iter().all(|package| {
        package.url.starts_with("https://registry.npmjs.org/")
            && base64::engine::general_purpose::STANDARD
                .decode(package.integrity_sha512)
                .is_ok_and(|integrity| integrity.len() == 64)
    }));
    assert!(matches!(
        javascript.version_output,
        VersionOutput::Exact("0.4.0")
    ));

    let python = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let IndexerInstallSource::NpmTarballs { packages } = python.source else {
        panic!("scip-python must use its pinned self-contained npm tarball");
    };
    assert_eq!(
        packages
            .iter()
            .map(|package| (package.name, package.version))
            .collect::<Vec<_>>(),
        [("@sourcegraph/scip-python", "0.6.6")]
    );
    assert!(packages.iter().all(|package| {
        package.url.starts_with("https://registry.npmjs.org/")
            && base64::engine::general_purpose::STANDARD
                .decode(package.integrity_sha512)
                .is_ok_and(|integrity| integrity.len() == 64)
    }));

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
fn windows_rust_pins_use_the_reproducible_v1_3_compatibility_bundles() {
    #[cfg(windows)]
    assert_eq!(
        pinned_indexer(SemanticIndexerKind::Rust).unwrap().version,
        "2026-08-03-sniff.2"
    );

    let x64 = rust_analyzer_download_for("windows", "x86_64", false).unwrap();
    assert_eq!(
        x64.url,
        "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.3/sniff-rust-indexer-x86_64-pc-windows-msvc.zip"
    );
    assert_eq!(
        x64.sha256,
        "eb6ae43f057d1b08806c5d983762cbd4ad996da1e73c42faa1b06eae20f42add"
    );
    assert_eq!(x64.archive, DownloadArchive::Zip);

    let arm64 = rust_analyzer_download_for("windows", "aarch64", false).unwrap();
    assert_eq!(
        arm64.url,
        "https://github.com/trysniff/sniff/releases/download/semantic-indexers-v1.3/sniff-rust-indexer-aarch64-pc-windows-msvc.zip"
    );
    assert_eq!(
        arm64.sha256,
        "8e4b4444cbe4649bf993644e3d7fcfe78bc39b80d0d108a0dc417641ecd335ac"
    );
    assert_eq!(arm64.archive, DownloadArchive::Zip);
}
