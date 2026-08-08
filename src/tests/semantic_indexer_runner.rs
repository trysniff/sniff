use super::{
    WINDOWS_SCIP_PYTHON_BOOTSTRAP, compact_process_output, files_for_indexer,
    gradle_script_uses_android, indexer_arguments_with_project, missing_position_encoding,
    project_name, reject_unsupported_android_gradle, sandbox_repository_argument,
    source_integrity_digest, write_private_gradle_properties,
};
#[cfg(windows)]
use super::{indexer_arguments_with_workspace, prepare_indexer_workspace};
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
fn python_arguments_include_stable_project_identity() {
    let spec = pinned_indexer(SemanticIndexerKind::Python).unwrap();
    let arguments = indexer_arguments_with_project(spec, synthetic_python_root(), None);
    assert_eq!(
        arguments,
        [
            "index",
            ".",
            "--project-name",
            "bumpkin",
            "--project-version",
            "_"
        ]
    );
}

#[test]
fn javascript_projects_without_tsconfig_use_inference() {
    let temp = std::env::temp_dir().join(format!("sniff-runner-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    assert_eq!(
        indexer_arguments_with_project(spec, &temp, None),
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
    assert_eq!(
        missing_position_encoding(SemanticIndexerKind::Kotlin),
        Some(SemanticPositionEncoding::Utf16)
    );
}

#[test]
fn private_gradle_properties_disable_daemons_without_host_home_access() {
    let root = std::env::temp_dir().join(format!(
        "sniff-gradle-properties-test-{}",
        std::process::id()
    ));
    let cache = root.join(".sniff-indexer-cache");
    std::fs::create_dir_all(&cache).unwrap();

    write_private_gradle_properties(&root, &cache).unwrap();
    let properties = std::fs::read_to_string(cache.join("gradle.properties")).unwrap();
    let expected_home =
        sandbox_repository_argument(&root, &root.to_string_lossy()).replace('\\', "\\\\");

    assert!(properties.contains(&format!("systemProp.user.home={expected_home}")));
    assert!(properties.contains("org.gradle.daemon=false"));
    assert!(properties.contains("org.gradle.jvmargs=\n"));
    assert!(properties.contains("org.gradle.parallel=false"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_python_provider_bootstrap_loads_the_real_entrypoint() {
    assert!(
        WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("NativeRegExp")
            && WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("PatchedRegExp")
            && WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("process.argv[1]")
    );
    assert!(!WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("sep='/';"));
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

#[test]
fn source_integrity_digest_changes_when_an_eligible_file_changes() {
    let root = std::env::temp_dir().join(format!(
        "sniff-source-integrity-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("main.py");
    std::fs::write(&source, "def main():\n    return 1\n").unwrap();
    let files = vec![FileRecord {
        file_path: source.to_string_lossy().to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: Vec::new(),
    }];

    let before = source_integrity_digest(&files).unwrap();
    std::fs::write(&source, "def main():\n    return 2\n").unwrap();
    let after = source_integrity_digest(&files).unwrap();

    assert_ne!(before, after);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn android_gradle_detection_is_strict_but_does_not_reject_plugin_catalogs() {
    assert!(gradle_script_uses_android(
        r#"plugins { id("com.android.application") }"#
    ));
    assert!(gradle_script_uses_android(
        "android { namespace = \"demo\" }"
    ));
    assert!(gradle_script_uses_android("androidTarget()"));
    assert!(!gradle_script_uses_android(
        r#"plugins { id("com.android.application") apply false }"#
    ));
}

#[test]
fn android_gradle_projects_fail_before_scip_java_invocation() {
    let root = std::env::temp_dir().join(format!(
        "sniff-android-capability-test-{}",
        std::process::id()
    ));
    let source = root.join("apps/android/src/main/kotlin/App.kt");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(
        root.join("apps/android/build.gradle.kts"),
        "plugins { id(\"com.android.application\") }\n",
    )
    .unwrap();
    std::fs::write(&source, "fun app() = Unit\n").unwrap();
    let files = vec![FileRecord {
        file_path: source.to_string_lossy().to_string(),
        source: "fun app() = Unit\n".to_string(),
        language: "kotlin".to_string(),
        methods: Vec::new(),
    }];

    let error = reject_unsupported_android_gradle(&root, &files).unwrap_err();
    assert!(error.contains("does not support Android Gradle integration"));
    assert!(error.contains("build.gradle.kts"));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_kotlin_workspace_uses_the_project_batch_wrapper() {
    let root = std::env::temp_dir().join(format!(
        "sniff-kotlin-workspace-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("gradlew"), "#!/usr/bin/env sh\n").unwrap();
    std::fs::write(root.join("gradlew.bat"), "@echo off\r\n").unwrap();

    let spec = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    let workspace = prepare_indexer_workspace(spec, &root).unwrap().unwrap();
    assert_ne!(workspace.directory, root);
    assert!(workspace.directory.join("build.gradle.kts").is_file());
    assert!(workspace.path_prefix.join("gradle.exe").is_file());

    let arguments = indexer_arguments_with_workspace(spec, &root, None, Some(&workspace));
    assert_eq!(arguments[0], "--cwd");
    assert_eq!(arguments[2], "index");
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair[0] == "--build-tool" && pair[1] == "Gradle")
    );
    let output = root.join("index.scip").to_string_lossy().to_string();
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair[0] == "--output" && pair[1] == output)
    );

    workspace.cleanup(spec.display_name).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
