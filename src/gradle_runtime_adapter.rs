use crate::go_tool_stdio::strip_windows_verbatim_prefix;
use crate::semantic_indexer_installer::WINDOWS_GRADLE_TEMP_FILES;
use crate::windows_runtime_lease;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[path = "gradle_runtime_adapter_tree.rs"]
mod tree;

pub(crate) struct AdaptedGradle {
    pub(crate) home: PathBuf,
    pub(crate) java_home: PathBuf,
    pub(crate) identity_files: Vec<PathBuf>,
    // Release immutable file leases before deleting the private production stage.
    _guard: Vec<fs::File>,
    _stage: tempfile::TempDir,
}

#[derive(Serialize)]
struct Binding {
    contract: &'static str,
    selected_jdk_tree_sha256: String,
    selected_gradle_tree_sha256: String,
    overlay_tree_sha256: String,
    recipe_sha256: String,
    source_sha256: String,
    class_sha256: String,
    compiler_stdout_sha256: String,
    compiler_stderr_sha256: String,
}

pub(crate) fn prepare(
    java: &Path,
    gradle: &Path,
    repository: &Path,
) -> Result<AdaptedGradle, String> {
    let java = canonical(java)?;
    let gradle = canonical(gradle)?;
    let repository = canonical(repository)?;
    let java_home = installation_home(&java, "java.exe")?;
    let gradle_home = installation_home(&gradle, "gradle.bat")?;
    let javac = canonical(&java_home.join("bin/javac.exe"))?;
    if installation_home(&javac, "javac.exe")? != java_home {
        return Err("selected Java compiler escaped its JVM installation".to_string());
    }
    for sdk in [&java_home, &gradle_home] {
        if sdk.starts_with(&repository) || repository.starts_with(sdk) {
            return Err(
                "selected Gradle and JDK must be outside the writable snapshot".to_string(),
            );
        }
    }
    let base = crate::semantic_cache::cache_base_directory()?;
    if !base.is_absolute() {
        return Err("private Gradle overlay cache must be absolute".to_string());
    }
    let mut guard = windows_runtime_lease::lock_base(&base, true)?;
    let base = canonical(&base)?;
    let parent = base.join("gradle-runtime-overlays-v1");
    for sdk in [&repository, &java_home, &gradle_home] {
        if base.starts_with(sdk) || sdk.starts_with(&parent) {
            return Err(
                "private Gradle overlay must be outside snapshot and selected SDKs".to_string(),
            );
        }
    }
    windows_runtime_lease::create_namespace(&parent)?;
    guard.push(windows_runtime_lease::hold_trusted(&parent, true, true)?);
    let stage = tempfile::Builder::new()
        .prefix(".gradle-overlay-")
        .tempdir_in(&parent)
        .map_err(|error| error.to_string())?;
    let stage_root = canonical(stage.path())?;
    let jdk_tree = tree::lease(&java_home)?;
    let gradle_tree = tree::lease(&gradle_home)?;
    require_pinned_distribution(&gradle_home, &gradle_tree)?;
    let compiled = compile_temp_class(&javac, &stage_root)?;
    let home = stage_root.join("gradle");
    tree::copy_distribution(&gradle_tree, &gradle_home, &home)?;
    crate::semantic_indexer_runner::rebuild_gradle_temp_runtime(
        &gradle_home.join("lib/gradle-file-temp-8.8.jar"),
        &home.join("lib/gradle-file-temp-8.8.jar"),
        &compiled.class,
    )?;
    let overlay_tree = tree::lease(&home)?;
    let binding = Binding {
        contract: "sniff-windows-owned-gradle-overlay-v1",
        selected_jdk_tree_sha256: jdk_tree.sha256,
        selected_gradle_tree_sha256: gradle_tree.sha256,
        overlay_tree_sha256: overlay_tree.sha256,
        recipe_sha256: digest(
            concat!(
                include_str!("gradle_runtime_adapter.rs"),
                include_str!("gradle_runtime_adapter_tree.rs"),
                include_str!("semantic_indexer_gradle_windows.rs"),
                include_str!("go_runtime_adapter_security.rs"),
                include_str!("benchmark_non_blind_history_runtime.rs"),
                include_str!("benchmark_non_blind_history_runtime_adapters.rs"),
            )
            .as_bytes(),
        ),
        source_sha256: digest(WINDOWS_GRADLE_TEMP_FILES.as_bytes()),
        class_sha256: digest(&fs::read(&compiled.class).map_err(|error| error.to_string())?),
        compiler_stdout_sha256: compiled.output.stdout_sha256,
        compiler_stderr_sha256: compiled.output.stderr_sha256,
    };
    let record = stage_root.join("overlay.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&record)
        .map_err(|error| error.to_string())?;
    file.write_all(&serde_json::to_vec(&binding).map_err(|error| error.to_string())?)
        .and_then(|_| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    let sealed_stage = tree::lease(&stage_root)?;
    guard.extend(jdk_tree.guard);
    guard.extend(gradle_tree.guard);
    guard.extend(overlay_tree.guard);
    guard.extend(sealed_stage.guard);
    Ok(AdaptedGradle {
        home,
        java_home,
        identity_files: vec![record, compiled.source, compiled.class],
        _guard: guard,
        _stage: stage,
    })
}

fn installation_home(program: &Path, expected: &str) -> Result<PathBuf, String> {
    if !program
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
    {
        return Err(format!(
            "selected Gradle overlay requires native {expected}"
        ));
    }
    let bin = program
        .parent()
        .ok_or("selected runtime has no bin directory")?;
    if bin.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return Err("selected runtime is not inside its installation bin directory".to_string());
    }
    bin.parent()
        .map(Path::to_path_buf)
        .ok_or("selected runtime has no installation root".to_string())
}

fn require_pinned_distribution(home: &Path, tree: &tree::Tree) -> Result<(), String> {
    let temps = tree
        .files
        .iter()
        .filter(|path| {
            path.parent() == Some(home.join("lib").as_path())
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("gradle-file-temp-") && name.ends_with(".jar")
                    })
        })
        .collect::<Vec<_>>();
    if temps != vec![&home.join("lib/gradle-file-temp-8.8.jar")] {
        return Err("selected Gradle requires exactly one pinned 8.8 temp runtime".to_string());
    }
    for relative in [
        "lib/gradle-launcher-8.8.jar",
        "lib/gradle-tooling-api-8.8.jar",
        "lib/gradle-installation-beacon-8.8.jar",
        "lib/agents/gradle-instrumentation-agent-8.8.jar",
    ] {
        if !tree.files.contains(&home.join(relative)) {
            return Err(format!(
                "selected Gradle distribution is missing {relative}"
            ));
        }
    }
    Ok(())
}

struct CompiledClass {
    source: PathBuf,
    class: PathBuf,
    output: crate::bounded_process::BoundedOutput,
}

fn compile_temp_class(javac: &Path, root: &Path) -> Result<CompiledClass, String> {
    let source = root.join("TempFiles.java");
    fs::write(&source, WINDOWS_GRADLE_TEMP_FILES).map_err(|error| error.to_string())?;
    let classes = root.join("classes");
    let temp = root.join("compiler-temp");
    fs::create_dir(&classes)
        .and_then(|_| fs::create_dir(&temp))
        .map_err(|error| error.to_string())?;
    let mut command = Command::new(javac);
    command
        .env_clear()
        .current_dir(root)
        .arg(format!("-J-Djava.io.tmpdir={}", temp.display()))
        .args([
            "-proc:none",
            "-implicit:none",
            "--release",
            "17",
            "-classpath",
        ])
        .arg(&classes)
        .arg("-sourcepath")
        .arg(&classes)
        .arg("-d")
        .arg(&classes)
        .arg(&source)
        .env("TEMP", &temp)
        .env("TMP", &temp);
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        Duration::from_secs(300),
        1024 * 1024,
    )
    .map_err(|error| format!("selected-JDK Gradle patch compilation failed: {error}"))?;
    if output.timed_out
        || output.stdout_truncated
        || output.stderr_truncated
        || !output.status.success()
    {
        return Err(format!(
            "selected-JDK Gradle patch compilation failed: status={}, timeout={}, stderr={}",
            output.status,
            output.timed_out,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let class = classes.join("org/gradle/api/internal/file/temp/TempFiles.class");
    let bytes = fs::read(&class).map_err(|error| error.to_string())?;
    if bytes.len() < 8 || bytes[..4] != [0xca, 0xfe, 0xba, 0xbe] || bytes[6..8] != [0, 61] {
        return Err("selected-JDK Gradle temp patch is not a Java 17 class".to_string());
    }
    Ok(CompiledClass {
        source,
        class,
        output,
    })
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| error.to_string())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "tests/gradle_runtime_adapter.rs"]
mod tests;
