use super::{
    compact_process_output, files_for_indexer, indexer_arguments, missing_position_encoding,
    project_name,
};
use crate::semantic_index::SemanticPositionEncoding;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use crate::types::FileRecord;
use std::path::Path;

fn javascript_file() -> FileRecord {
    FileRecord {
        file_path: "src/main.js".to_string(),
        source: String::new(),
        language: "javascript".to_string(),
        methods: Vec::new(),
    }
}

fn python_file() -> FileRecord {
    FileRecord {
        file_path: "src/main.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: Vec::new(),
    }
}

#[cfg(windows)]
fn synthetic_python_root() -> &'static Path {
    Path::new(r"C:\work\bumpkin")
}

#[cfg(not(windows))]
fn synthetic_python_root() -> &'static Path {
    Path::new("/work/bumpkin")
}

#[cfg(windows)]
fn synthetic_root() -> &'static Path {
    Path::new(r"\")
}

#[cfg(not(windows))]
fn synthetic_root() -> &'static Path {
    Path::new("/")
}

#[test]
fn python_arguments_include_a_stable_project_name() {
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let arguments = indexer_arguments(spec, synthetic_python_root(), &[]);
    assert_eq!(arguments, ["index", ".", "--project-name", "bumpkin"]);
}

#[test]
fn javascript_projects_without_tsconfig_use_inference() {
    let temp = std::env::temp_dir().join(format!("sniff-runner-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    assert_eq!(
        indexer_arguments(spec, &temp, &[javascript_file()]),
        ["index", "--infer-tsconfig"]
    );
    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn unnamed_roots_use_a_stable_project_name() {
    assert_eq!(project_name(synthetic_root()), "sniff-project");
}

#[test]
fn providers_with_missing_positions_use_explicit_encoding_contracts() {
    assert_eq!(
        missing_position_encoding(SemanticIndexerKind::Go),
        Some(SemanticPositionEncoding::Utf8)
    );
    assert_eq!(
        missing_position_encoding(SemanticIndexerKind::Python),
        Some(SemanticPositionEncoding::Utf32)
    );
}

#[test]
fn files_for_indexer_partitions_mixed_language_targets() {
    let files = vec![javascript_file(), python_file()];
    let javascript = files_for_indexer(&files, SemanticIndexerKind::TypeScriptJavaScript);
    let python = files_for_indexer(&files, SemanticIndexerKind::Python);

    assert_eq!(
        javascript
            .iter()
            .map(|file| file.file_path.as_str())
            .collect::<Vec<_>>(),
        ["src/main.js"]
    );
    assert_eq!(
        python
            .iter()
            .map(|file| file.file_path.as_str())
            .collect::<Vec<_>>(),
        ["src/main.py"]
    );
}

#[test]
fn provider_error_output_keeps_the_actionable_tail() {
    let stdout = format!("command context {}", "x".repeat(4_500));
    let stderr = format!("{} failure details", "y".repeat(4_500));

    let compact = compact_process_output(stdout.as_bytes(), stderr.as_bytes());

    assert!(compact.contains("command context"));
    assert!(compact.contains("failure details"));
    assert!(compact.contains("provider output elided"));
}
