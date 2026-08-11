use super::{
    GRADLE_INDEXER_BASE_JVM_ARGS, WINDOWS_SCIP_NODE_BOOTSTRAP, WINDOWS_SCIP_PYTHON_BOOTSTRAP,
    compact_process_output, files_for_indexer, format_timeout, go_sandbox_environment,
    gradle_indexer_jvm_args, gradle_script_uses_android, indexer_arguments_with_project,
    missing_position_encoding, project_name, reject_unsupported_android_gradle,
    sandbox_repository_argument, source_integrity_digest, write_private_gradle_properties,
};
#[cfg(windows)]
use super::{
    collect_windows_runtime_images, indexer_arguments_with_workspace, prepare_indexer_workspace,
    push_external_read_only, system_gradle_launcher_jar,
};
use crate::semantic_index::SemanticPositionEncoding;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use crate::types::FileRecord;
use std::path::Path;
use std::time::Duration;

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
fn go_indexing_uses_explicit_module_scope() {
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();

    assert_eq!(
        indexer_arguments_with_project(spec, synthetic_python_root(), None),
        ["--module-root", ".", "./..."]
    );
}

#[test]
fn go_indexing_keeps_mutable_state_inside_the_sandbox() {
    let root = synthetic_python_root();
    let go_root = root.join("trusted-go-runtime");
    let environment = go_sandbox_environment(root, &go_root)
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let private_root = sandbox_repository_argument(
        root,
        &root.join(".sniff-indexer-tmp").join("go").to_string_lossy(),
    );

    assert_eq!(environment.get("GOENV").map(String::as_str), Some("off"));
    assert_eq!(
        environment.get("GOTOOLCHAIN").map(String::as_str),
        Some("local")
    );
    assert_eq!(
        environment.get("GOROOT"),
        Some(&go_root.to_string_lossy().into_owned())
    );
    assert_eq!(environment.get("GOPATH"), Some(&private_root));
    assert!(
        environment
            .get("GOMODCACHE")
            .is_some_and(|path| path.starts_with(&private_root) && path.ends_with("mod"))
    );
    assert!(
        environment
            .get("GOCACHE")
            .is_some_and(|path| path.contains(".sniff-indexer-tmp"))
    );
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
    assert!(!properties.contains("org.gradle.jvmargs"));
    assert!(properties.contains("org.gradle.parallel=false"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gradle_jvm_arguments_require_one_installed_instrumentation_agent() {
    let root = std::env::temp_dir().join(format!("sniff-gradle-agent-test-{}", std::process::id()));
    let bin = root.join("bin");
    let agents = root.join("lib/agents");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::write(bin.join("gradle"), "").unwrap();
    let agent = agents.join("gradle-instrumentation-agent-8.8.jar");
    std::fs::write(&agent, "agent").unwrap();

    let args = gradle_indexer_jvm_args(&bin.join("gradle")).unwrap();
    assert!(args.starts_with(GRADLE_INDEXER_BASE_JVM_ARGS));
    assert!(args.contains("-javaagent:"));
    let agent_path = std::fs::canonicalize(agent).unwrap();
    let agent_text = agent_path.to_string_lossy();
    assert!(args.contains(agent_text.as_ref()));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_python_provider_bootstrap_loads_the_real_entrypoint() {
    assert!(
        WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("NativeRegExp")
            && WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("PatchedRegExp")
            && WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("process.argv[1]")
    );
    assert!(WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("execFileSync=denyProcess"));
    assert!(WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("spawnSync=denyProcess"));
    assert!(WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("spawn=denyProcess"));
    assert!(!WINDOWS_SCIP_PYTHON_BOOTSTRAP.contains("sep='/';"));
}

#[test]
fn windows_node_provider_bootstrap_invokes_the_exported_cli() {
    assert!(WINDOWS_SCIP_NODE_BOOTSTRAP.contains("indexer.main()"));
    assert!(WINDOWS_SCIP_NODE_BOOTSTRAP.contains("process.argv[1]"));
    assert!(WINDOWS_SCIP_NODE_BOOTSTRAP.contains("does not export main"));
}

#[cfg(windows)]
#[test]
fn windows_verbatim_repository_paths_are_not_persistently_granted() {
    let mut paths = Vec::new();

    push_external_read_only(
        Path::new(r"C:\work\repository"),
        &mut paths,
        std::path::PathBuf::from(r"\\?\C:\work\repository\.sniff-indexer-tmp"),
    );

    assert!(paths.is_empty());
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
fn indexer_timeouts_never_round_subminute_values_to_zero() {
    assert_eq!(format_timeout(Duration::from_secs(30)), "30 seconds");
    assert_eq!(format_timeout(Duration::from_secs(60)), "1 minute");
    assert_eq!(format_timeout(Duration::from_secs(3_600)), "60 minutes");
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
fn windows_kotlin_workspace_launches_the_project_wrapper_jar_directly() {
    let root = std::env::temp_dir().join(format!(
        "sniff-kotlin-workspace-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("gradlew"), "#!/usr/bin/env sh\n").unwrap();
    std::fs::write(root.join("gradlew.bat"), "@echo off\r\n").unwrap();
    std::fs::create_dir_all(root.join("gradle/wrapper")).unwrap();
    std::fs::write(
        root.join("gradle/wrapper/gradle-wrapper.jar"),
        b"wrapper fixture",
    )
    .unwrap();

    let spec = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    let workspace = prepare_indexer_workspace(spec, &root).unwrap().unwrap();
    assert_ne!(workspace.directory, root);
    assert!(workspace.directory.join("build.gradle.kts").is_file());
    assert_eq!(
        workspace.gradle_launcher_jar,
        root.join("gradle/wrapper/gradle-wrapper.jar")
    );
    assert_eq!(
        workspace.gradle_main_class,
        "org.gradle.wrapper.GradleWrapperMain"
    );

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

#[cfg(windows)]
#[test]
fn windows_system_gradle_requires_one_known_launcher_jar() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("gradle");
    let bin = home.join("bin");
    let lib = home.join("lib");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    let command = bin.join("gradle.bat");
    std::fs::write(&command, "@echo off\r\n").unwrap();

    let launcher = lib.join("gradle-launcher-8.14.jar");
    std::fs::write(&launcher, b"launcher fixture").unwrap();
    assert_eq!(system_gradle_launcher_jar(&command).unwrap(), launcher);

    std::fs::write(
        lib.join("gradle-gradle-cli-main-9.0.jar"),
        b"ambiguous fixture",
    )
    .unwrap();
    let error = system_gradle_launcher_jar(&command).unwrap_err();
    assert!(error.contains("multiple launcher jars"));
}

#[cfg(windows)]
#[test]
fn windows_project_wrapper_without_its_jar_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("gradlew.bat"), "@echo off\r\n").unwrap();

    let spec = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    let error = match prepare_indexer_workspace(spec, root.path()) {
        Err(error) => error,
        Ok(_) => panic!("missing Gradle wrapper jar should fail closed"),
    };

    assert!(error.contains("gradle-wrapper.jar"));
    assert!(error.contains("refusing to execute the batch wrapper through a shell"));
}

#[cfg(windows)]
#[test]
fn windows_runtime_execution_allowlist_contains_verified_executables_and_libraries() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repository");
    let runtime = temp.path().join("runtime");
    let nested = runtime.join("nested");
    std::fs::create_dir_all(&repository).unwrap();
    std::fs::create_dir_all(&nested).unwrap();
    let compiler = runtime.join("compiler.exe");
    let linker = nested.join("LINKER.EXE");
    std::fs::write(&compiler, b"MZcompiler").unwrap();
    std::fs::write(&linker, b"MZlinker").unwrap();
    let library = runtime.join("runtime.dll");
    std::fs::write(&library, b"MZlibrary").unwrap();
    std::fs::write(runtime.join("notes.txt"), b"not executable").unwrap();

    let mut executable_paths = Vec::new();
    collect_windows_runtime_images(&repository, &mut executable_paths, &runtime).unwrap();
    executable_paths.sort();

    let mut expected = vec![compiler, linker, library];
    expected.sort();
    assert_eq!(executable_paths, expected);
}
