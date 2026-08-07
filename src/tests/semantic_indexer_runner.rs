use super::{indexer_arguments, project_name};
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

#[test]
fn python_arguments_include_a_stable_project_name() {
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let arguments = indexer_arguments(spec, Path::new(r"C:\work\bumpkin"), &[]);
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
    assert_eq!(project_name(Path::new(r"\")), "sniff-project");
}
