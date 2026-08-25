use super::combine_run_and_integrity;
#[cfg(windows)]
use super::gradle_windows::{
    TEMP_CLASS as WINDOWS_GRADLE_TEMP_CLASS, java_classpath as windows_java_classpath,
    prepare_system_overlay,
};
#[cfg(windows)]
use super::run_one;
use super::{
    GRADLE_INDEXER_BASE_JVM_ARGS, WINDOWS_SCIP_NODE_BOOTSTRAP, WINDOWS_SCIP_PYTHON_BOOTSTRAP,
    compact_process_output, files_for_indexer, format_timeout, go_dependency_arguments,
    go_sandbox_environment, gradle_indexer_jvm_args, gradle_script_uses_android,
    indexer_arguments_with_project, missing_position_encoding, private_indexer_directory_argument,
    private_indexer_environment, private_indexer_jvm_arguments, project_name,
    reject_unsupported_android_gradle, require_dependency_preparation_success,
    resolve_java_home_runtime, runtime_file_identities, sandbox_repository_argument,
    source_integrity_digest, verify_runtime_identities_unchanged, write_private_gradle_properties,
};
#[cfg(windows)]
use super::{
    TemporaryIndexerWorkspace, configure_windows_runtime_images, external_runtime_path_value,
    indexer_arguments_with_workspace, prepare_indexer_workspace, push_external_read_only,
    system_gradle_launcher_jar,
};
use crate::sandbox::SandboxOutput;
use crate::semantic_index::SemanticPositionEncoding;
#[cfg(windows)]
use crate::semantic_indexer_installation::InstalledIndexer;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use crate::types::FileRecord;
#[cfg(windows)]
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires a prebuilt AppContainer-compatible rust-analyzer"]
async fn windows_compatible_rust_analyzer_emits_scip_inside_appcontainer() {
    let entrypoint = std::env::var_os("SNIFF_TEST_WINDOWS_RUST_ANALYZER")
        .map(std::path::PathBuf::from)
        .expect("SNIFF_TEST_WINDOWS_RUST_ANALYZER must name the compatibility artifact");
    let entrypoint = std::fs::canonicalize(entrypoint).expect("resolve compatibility artifact");
    let installation_root = entrypoint
        .parent()
        .and_then(std::path::Path::parent)
        .expect("compatibility artifact should be installed below bin")
        .to_path_buf();
    let repository = tempfile::tempdir().expect("create Rust SCIP probe repository");
    let source_dir = repository.path().join("src");
    std::fs::create_dir(&source_dir).expect("create Rust source directory");
    std::fs::write(
        repository.path().join("Cargo.toml"),
        "[package]\nname = \"sniff-rust-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("write Rust probe manifest");
    let source_path = source_dir.join("lib.rs");
    let source = "pub fn answer() -> u32 { 42 }\n";
    std::fs::write(&source_path, source).expect("write Rust probe source");
    let files = vec![FileRecord {
        file_path: source_path.to_string_lossy().into_owned(),
        source: source.to_string(),
        language: "rust".to_string(),
        methods: Vec::new(),
    }];
    let spec = pinned_indexer(SemanticIndexerKind::Rust).expect("pinned Rust indexer");
    let installed = InstalledIndexer {
        root: installation_root,
        entrypoint,
    };

    run_one(spec, repository.path(), &installed, &files)
        .await
        .expect("compatibility artifact should index inside AppContainer");

    let index = repository.path().join("index.scip");
    assert!(index.is_file(), "rust-analyzer did not emit index.scip");
    assert!(
        std::fs::metadata(index).unwrap().len() > 0,
        "rust-analyzer emitted an empty SCIP index"
    );
}

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

#[cfg(windows)]
#[test]
fn windows_java_classpath_removes_verbatim_prefixes() {
    let classpath = windows_java_classpath(
        Path::new(r"\\?\C:\indexers\scip-java-patch"),
        Path::new(r"\\?\C:\indexers\scip-java"),
    );

    assert_eq!(
        classpath,
        r"C:\indexers\scip-java-patch;C:\indexers\scip-java"
    );
    assert!(!classpath.contains(r"\\?\"));
}

#[cfg(windows)]
#[test]
fn windows_gradle_overlay_replaces_only_the_legacy_temp_class() {
    use zip::write::SimpleFileOptions;

    let temp = tempfile::tempdir().unwrap();
    let gradle_root = temp.path().join("gradle-8.8");
    let gradle_lib = gradle_root.join("lib");
    std::fs::create_dir_all(gradle_lib.join("plugins")).unwrap();
    let launcher = gradle_lib.join("gradle-launcher-8.8.jar");
    std::fs::write(&launcher, b"launcher").unwrap();
    let beacon = gradle_lib.join("gradle-installation-beacon-8.8.jar");
    std::fs::write(&beacon, b"beacon").unwrap();
    let file_temp = gradle_lib.join("gradle-file-temp-8.8.jar");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&file_temp).unwrap());
    writer
        .start_file(
            "gradle-file-temp-classpath.properties",
            SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(b"projects=gradle-files\n").unwrap();
    writer
        .start_file(
            "org/gradle/api/internal/file/temp/DefaultTemporaryFileProvider.class",
            SimpleFileOptions::default(),
        )
        .unwrap();
    writer.write_all(b"provider").unwrap();
    writer
        .start_file(WINDOWS_GRADLE_TEMP_CLASS, SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"legacy-file-temp").unwrap();
    writer.finish().unwrap();

    let patch_dir = temp.path().join("scip-java-v0.13.1-patch");
    let replacement = patch_dir.join("sniff-gradle-patch/TempFiles.class");
    std::fs::create_dir_all(replacement.parent().unwrap()).unwrap();
    std::fs::write(&replacement, b"nio-file-temp").unwrap();
    let workspace_root = temp.path().join("workspace");
    std::fs::create_dir(&workspace_root).unwrap();
    let overlay_root = temp.path().join("overlay");
    std::fs::create_dir(&overlay_root).unwrap();
    let workspace = TemporaryIndexerWorkspace {
        directory: workspace_root.clone(),
        gradle_launcher_jar: launcher,
        gradle_overlay_directory: Some(overlay_root.clone()),
        gradle_main_class: "org.gradle.launcher.GradleMain",
        project_root: temp.path().join("project"),
    };

    let prepared =
        prepare_system_overlay(&overlay_root, &workspace.gradle_launcher_jar, &patch_dir).unwrap();
    let classpath = &prepared.value;

    assert!(classpath.contains(&overlay_root.to_string_lossy().to_string()));
    assert!(classpath.contains(r"lib\*"));
    assert!(classpath.contains(r"lib\plugins\*"));
    assert_eq!(std::fs::read(&beacon).unwrap(), b"beacon");
    let overlay_jar = prepared
        .read_only_directory
        .unwrap()
        .join("lib/gradle-file-temp-8.8.jar");
    let mut original = zip::ZipArchive::new(std::fs::File::open(&file_temp).unwrap()).unwrap();
    let mut original_temp = Vec::new();
    original
        .by_name(WINDOWS_GRADLE_TEMP_CLASS)
        .unwrap()
        .read_to_end(&mut original_temp)
        .unwrap();
    assert_eq!(original_temp, b"legacy-file-temp");
    let mut overlay = zip::ZipArchive::new(std::fs::File::open(overlay_jar).unwrap()).unwrap();
    let mut patched_temp = Vec::new();
    overlay
        .by_name(WINDOWS_GRADLE_TEMP_CLASS)
        .unwrap()
        .read_to_end(&mut patched_temp)
        .unwrap();
    assert_eq!(patched_temp, b"nio-file-temp");
}

#[cfg(windows)]
#[test]
fn windows_java_home_environment_removes_verbatim_prefixes() {
    let java_home = external_runtime_path_value(Path::new(
        r"\\?\C:\hostedtoolcache\windows\Java_Temurin-Hotspot_jdk\17\x64",
    ));

    assert_eq!(
        java_home,
        r"C:\hostedtoolcache\windows\Java_Temurin-Hotspot_jdk\17\x64"
    );
    assert!(!java_home.contains(r"\\?\"));
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
fn go_dependency_preparation_downloads_the_complete_module_graph() {
    assert_eq!(go_dependency_arguments(), ["mod", "download", "all"]);
}

#[test]
fn dependency_registry_failure_is_retryable_infrastructure() {
    let spec = pinned_indexer(SemanticIndexerKind::Go).unwrap();
    let error = require_dependency_preparation_success(
        spec,
        SandboxOutput {
            status_code: Some(1),
            stdout: String::new(),
            stderr: "registry unavailable".to_string(),
            stdout_sha256: "a".repeat(64),
            stderr_sha256: "b".repeat(64),
            timed_out: false,
        },
    )
    .unwrap_err();

    assert_eq!(
        error.kind,
        super::SemanticIndexerRunFailureKind::InfrastructureUnavailable
    );
    assert_eq!(error.phase, super::SemanticIndexerRunPhase::Preparation);
    assert!(error.process.is_some());
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
fn indexer_process_state_uses_only_the_cleaned_private_workspace() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".sniff-indexer-tmp")).unwrap();
    let environment = private_indexer_environment(root.path())
        .unwrap()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let private_root = root.path().join(".sniff-indexer-tmp");

    for (name, directory_name) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("TEMP", "temp"),
        ("TMP", "temp"),
    ] {
        let value = environment.get(name).unwrap();
        assert_eq!(
            value,
            &private_indexer_directory_argument(root.path(), directory_name),
            "{name}"
        );
        assert!(
            private_root.join(directory_name).is_dir(),
            "{name}: {value}"
        );
    }
    assert_ne!(
        environment.get("HOME").unwrap(),
        &sandbox_repository_argument(root.path(), &root.path().to_string_lossy())
    );
    #[cfg(windows)]
    for name in ["USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
        assert!(
            !environment.contains_key(name),
            "the AppContainer must provide its own disposable {name}"
        );
    }

    let jvm_arguments = private_indexer_jvm_arguments(root.path());
    assert_eq!(
        jvm_arguments,
        [
            format!(
                "-Duser.home={}",
                private_indexer_directory_argument(root.path(), "home")
            ),
            format!(
                "-Djava.io.tmpdir={}",
                private_indexer_directory_argument(root.path(), "temp")
            ),
        ]
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
    assert!(cache.join(".tmp").is_dir());
    assert!(cache.join("project-cache").is_dir());
    let expected_home =
        sandbox_repository_argument(&root, &root.to_string_lossy()).replace('\\', "\\\\");
    let expected_project_cache =
        sandbox_repository_argument(&root, &cache.join("project-cache").to_string_lossy())
            .replace('\\', "\\\\");

    assert!(properties.contains(&format!("systemProp.user.home={expected_home}")));
    assert!(properties.contains("org.gradle.daemon=false"));
    assert!(!properties.contains("org.gradle.jvmargs"));
    assert!(properties.contains("org.gradle.parallel=false"));
    assert!(properties.contains("org.gradle.vfs.watch=false"));
    assert!(properties.contains("org.gradle.workers.max=32"));
    assert!(properties.contains(&format!(
        "org.gradle.projectcachedir={expected_project_cache}"
    )));

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
    let agent_text = super::external_runtime_path_value(&agent_path);
    assert!(args.contains(&agent_text));
    #[cfg(windows)]
    assert!(!args.contains(r"\\?\"));

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
fn runtime_identity_detects_same_length_replacement() {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime.bin");
    std::fs::write(&runtime, b"trusted").unwrap();
    let paths = vec![runtime.clone()];

    let before = runtime_file_identities(&paths).unwrap();
    std::fs::write(&runtime, b"changed").unwrap();
    let after = runtime_file_identities(&paths).unwrap();

    let error =
        verify_runtime_identities_unchanged("fixture indexer", &before, &after).unwrap_err();
    assert!(error.contains("executable runtime changed while indexing"));
    assert!(error.contains(&runtime.to_string_lossy().to_string()));
}

#[test]
fn explicit_java_home_resolves_exactly_and_never_uses_path_as_a_fallback() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let java = bin.join(if cfg!(windows) { "java.exe" } else { "java" });
    std::fs::write(&java, b"runtime").unwrap();

    assert_eq!(
        resolve_java_home_runtime(root.path().as_os_str()).unwrap(),
        std::fs::canonicalize(&java).unwrap()
    );
    let missing = root.path().join("missing");
    let error = resolve_java_home_runtime(missing.as_os_str()).unwrap_err();
    assert!(error.contains("refusing PATH-based Java resolution"));
}

#[test]
fn runtime_integrity_error_does_not_hide_execution_error() {
    let error = combine_run_and_integrity::<()>(
        Err("indexer process failed".to_string()),
        Err("runtime changed".to_string()),
    )
    .unwrap_err();

    assert_eq!(
        error,
        "indexer process failed; additionally, runtime changed"
    );
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
    std::fs::create_dir(root.join(".sniff-indexer-tmp")).unwrap();
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
    assert!(workspace.directory.join("build").is_dir());
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
    use zip::write::SimpleFileOptions;

    fn write_runtime_jar(path: &Path, entries: &[&str]) {
        let mut writer = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for entry in entries {
            writer
                .start_file(*entry, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"fixture").unwrap();
        }
        writer.finish().unwrap();
    }

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("gradle");
    let bin = home.join("bin");
    let lib = home.join("lib");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    let command = bin.join("gradle.bat");
    std::fs::write(&command, "@echo off\r\n").unwrap();

    let launcher = lib.join("gradle-launcher-8.14.jar");
    write_runtime_jar(&launcher, &["org/gradle/launcher/bootstrap.class"]);
    let bootstrap = lib.join("gradle-bootstrap-8.14.jar");
    write_runtime_jar(&bootstrap, &["org/gradle/launcher/GradleMain.class"]);
    assert_eq!(system_gradle_launcher_jar(&command).unwrap(), bootstrap);

    write_runtime_jar(&launcher, &["org/gradle/launcher/GradleMain.class"]);
    let error = system_gradle_launcher_jar(&command).unwrap_err();
    assert!(error.contains("multiple runtime jars providing org.gradle.launcher.GradleMain"));
}

#[cfg(windows)]
#[test]
fn windows_project_wrapper_without_its_jar_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".sniff-indexer-tmp")).unwrap();
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
    let mut virtualized_paths = Vec::new();
    configure_windows_runtime_images(
        &repository,
        &mut executable_paths,
        &mut virtualized_paths,
        &runtime,
    )
    .unwrap();
    executable_paths.sort();

    let mut expected = vec![compiler, linker, library];
    expected.sort();
    assert_eq!(executable_paths, expected);
    assert_eq!(virtualized_paths, vec![temp.path().to_path_buf()]);
}
