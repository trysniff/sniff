use crate::semantic_indexer_manifest::{PinnedIndexer, SemanticIndexerKind};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[path = "semantic_indexer_scip_java_patch_archive.rs"]
mod archive;

#[path = "semantic_indexer_scip_java_patch_sources.rs"]
mod sources;

const SCIP_JAVA_VERSION: &str = "0.13.1";
const OUTER_JARS: [&str; 9] = [
    "scip-java-0.13.1.jar",
    "kotlin-compiler-embeddable-2.2.0.jar",
    "kotlin-stdlib-2.3.20.jar",
    "kotlin-script-runtime-2.2.0.jar",
    "kotlin-reflect-1.6.10.jar",
    "kotlinx-coroutines-core-jvm-1.8.0.jar",
    "annotations-13.0.jar",
    "scip-shared-0.13.1.jar",
    "scip-java-bindings-0.9.0.jar",
];

pub(super) async fn patch_kotlin_annotation_references(
    root: &Path,
    spec: PinnedIndexer,
) -> Result<(), String> {
    if spec.kind != SemanticIndexerKind::Kotlin || spec.version != SCIP_JAVA_VERSION {
        return Err(format!(
            "Kotlin annotation patch only supports scip-java {SCIP_JAVA_VERSION}"
        ));
    }
    let launcher = root.join(spec.entrypoint_relative_path());
    let patch_root = std::env::temp_dir().join(format!(
        "sniff-scip-java-kotlin-patch-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::create_dir(&patch_root).map_err(|error| {
        format!(
            "failed to create Kotlin compiler patch directory {}: {error}",
            patch_root.display()
        )
    })?;

    let result = patch_in(&launcher, &patch_root).await;
    let cleanup = fs::remove_dir_all(&patch_root);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!(
            "failed to remove Kotlin compiler patch directory {}: {error}",
            patch_root.display()
        )),
        (Err(error), Err(cleanup)) => Err(format!(
            "{error}; additionally failed to remove Kotlin compiler patch directory {}: {cleanup}",
            patch_root.display()
        )),
    }
}

async fn patch_in(launcher: &Path, patch_root: &Path) -> Result<(), String> {
    let jars = extract_patch_jars(launcher, patch_root).await?;
    let sources = patch_root.join("sources");
    fs::create_dir(&sources)
        .map_err(|error| format!("failed to create Kotlin patch source directory: {error}"))?;
    let registrar = sources.join("AnalyzerFirExtensionRegistrar.kt");
    let annotations = sources.join("SniffAnnotationCheckers.kt");
    fs::write(&registrar, sources::REGISTRAR)
        .map_err(|error| format!("failed to write Kotlin patch registrar: {error}"))?;
    fs::write(&annotations, sources::ANNOTATION_CHECKERS)
        .map_err(|error| format!("failed to write Kotlin annotation checker: {error}"))?;

    let classes = patch_root.join("classes");
    fs::create_dir(&classes)
        .map_err(|error| format!("failed to create Kotlin patch class directory: {error}"))?;
    compile_patch(&jars, &registrar, &annotations, &classes).await?;
    let compiled = collect_compiled_classes(&classes)?;

    let patched_kotlinc = patch_root.join("scip-kotlinc-patched.jar");
    archive::rebuild_kotlinc_jar(&jars.scip_kotlinc, &patched_kotlinc, &compiled)?;
    let patched_scip_java = patch_root.join("scip-java-patched.jar");
    archive::replace_plain_zip_entry(
        &jars.scip_java,
        &patched_scip_java,
        archive::SCIP_KOTLINC_ENTRY,
        &patched_kotlinc,
        None,
    )?;
    archive::validate_patched_scip_java(&patched_scip_java)?;
    let rebuilt_zip = rebuild_outer_launcher(launcher, &patched_scip_java, patch_root).await?;
    let patched_launcher = patch_root.join("scip-java-launcher-patched");
    archive::install_rebuilt_launcher(
        launcher,
        &rebuilt_zip,
        &patched_launcher,
        archive::SCIP_JAVA_ENTRY,
    )?;
    verify_launcher_entry(&patched_launcher, &patched_scip_java, patch_root).await?;

    let permissions = fs::metadata(launcher)
        .map_err(|error| format!("failed to inspect scip-java launcher permissions: {error}"))?
        .permissions();
    fs::copy(&patched_launcher, launcher)
        .map_err(|error| format!("failed to install patched scip-java launcher: {error}"))?;
    fs::set_permissions(launcher, permissions)
        .map_err(|error| format!("failed to restore scip-java launcher permissions: {error}"))?;
    verify_launcher_entry(launcher, &patched_scip_java, patch_root).await
}

async fn extract_patch_jars(
    launcher: &Path,
    patch_root: &Path,
) -> Result<archive::PatchJars, String> {
    let extracted = patch_root.join("extracted");
    fs::create_dir(&extracted)
        .map_err(|error| format!("failed to create Kotlin patch jar directory: {error}"))?;
    let mut command = Command::new(jdk_executable("jar")?);
    command.current_dir(&extracted).arg("xf").arg(launcher);
    for name in OUTER_JARS {
        command.arg(format!("coursier/bootstrap/launcher/jars/{name}"));
    }
    super::run_command(&mut command, "extract scip-java Kotlin patch dependencies").await?;
    archive::patch_jars_from_extracted(&extracted)
}

async fn rebuild_outer_launcher(
    launcher: &Path,
    patched_scip_java: &Path,
    patch_root: &Path,
) -> Result<PathBuf, String> {
    let source = patch_root.join("LauncherRepacker.java");
    fs::write(&source, super::scip_java_repacker_source::LAUNCHER_REPACKER)
        .map_err(|error| format!("failed to write scip-java launcher repacker: {error}"))?;
    let classes = patch_root.join("repacker-classes");
    fs::create_dir(&classes)
        .map_err(|error| format!("failed to create launcher repacker classes: {error}"))?;
    let mut compile = Command::new(jdk_executable("javac")?);
    compile.arg("-d").arg(&classes).arg(&source);
    super::run_command(&mut compile, "compile scip-java launcher repacker").await?;

    let rebuilt = patch_root.join("scip-java-launcher-rebuilt.zip");
    let mut repack = Command::new(java_executable()?);
    repack
        .arg("-cp")
        .arg(&classes)
        .arg("LauncherRepacker")
        .arg(launcher)
        .arg(patched_scip_java)
        .arg(&rebuilt)
        .arg(archive::SCIP_JAVA_ENTRY);
    super::run_command(&mut repack, "rebuild scip-java launcher").await?;
    Ok(rebuilt)
}

async fn verify_launcher_entry(
    launcher: &Path,
    expected: &Path,
    patch_root: &Path,
) -> Result<(), String> {
    let verification = patch_root.join(format!("verify-{}", unique_suffix()));
    fs::create_dir(&verification)
        .map_err(|error| format!("failed to create launcher verification directory: {error}"))?;
    let mut command = Command::new(jdk_executable("jar")?);
    command
        .current_dir(&verification)
        .arg("xf")
        .arg(launcher)
        .arg(archive::SCIP_JAVA_ENTRY);
    super::run_command(&mut command, "verify patched scip-java launcher").await?;
    let extracted = verification.join(archive::SCIP_JAVA_ENTRY);
    let actual = fs::read(&extracted)
        .map_err(|error| format!("patched launcher omitted scip-java runtime: {error}"))?;
    let expected = fs::read(expected)
        .map_err(|error| format!("failed to read expected patched scip-java runtime: {error}"))?;
    if actual != expected {
        return Err("patched launcher changed the scip-java runtime bytes".to_string());
    }
    Ok(())
}

async fn compile_patch(
    jars: &archive::PatchJars,
    registrar: &Path,
    annotations: &Path,
    classes: &Path,
) -> Result<(), String> {
    let compiler_classpath = join_classpath(&[
        &jars.compiler,
        &jars.stdlib,
        &jars.script_runtime,
        &jars.reflect,
        &jars.coroutines,
        &jars.annotations,
    ])?;
    let source_classpath = join_classpath(&[
        &jars.scip_kotlinc,
        &jars.shared,
        &jars.bindings,
        &jars.compiler,
        &jars.stdlib,
        &jars.annotations,
    ])?;
    let mut command = Command::new(java_executable()?);
    command
        .arg("-cp")
        .arg(compiler_classpath)
        .arg("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler")
        .arg("-Xcontext-parameters")
        .arg("-no-stdlib")
        .arg("-no-reflect")
        .arg("-jvm-target")
        .arg("17")
        .arg("-classpath")
        .arg(source_classpath)
        .arg("-d")
        .arg(classes)
        .arg(registrar)
        .arg(annotations);
    super::run_command(&mut command, "compile scip-java Kotlin annotation patch")
        .await
        .map(|_| ())
}

fn collect_compiled_classes(root: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let package = root.join(archive::CLASS_PACKAGE);
    let expected = archive::COMPILED_CLASSES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    let mut classes = Vec::new();
    for entry in fs::read_dir(&package).map_err(|error| {
        format!(
            "Kotlin patch compiler omitted {}: {error}",
            package.display()
        )
    })? {
        let entry =
            entry.map_err(|error| format!("failed to inspect Kotlin patch classes: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("failed to inspect Kotlin patch class type: {error}"))?
            .is_file()
        {
            return Err("Kotlin patch compiler emitted a non-file package entry".to_string());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Kotlin patch compiler emitted a non-UTF-8 class name".to_string())?;
        if !expected.contains(name.as_str()) || !found.insert(name.clone()) {
            return Err(format!(
                "Kotlin patch compiler emitted unexpected class {name}"
            ));
        }
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("failed to read Kotlin patch class {name}: {error}"))?;
        if bytes.len() < 4 || !bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
            return Err(format!(
                "Kotlin patch compiler emitted invalid class {name}"
            ));
        }
        classes.push((format!("{}/{name}", archive::CLASS_PACKAGE), bytes));
    }
    if found.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("Kotlin patch compiler omitted required classes".to_string());
    }
    classes.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(classes)
}

fn join_classpath(paths: &[&Path]) -> Result<OsString, String> {
    std::env::join_paths(paths.iter().copied())
        .map_err(|error| format!("failed to build Kotlin patch classpath: {error}"))
}

fn java_executable() -> Result<OsString, String> {
    jdk_executable("java")
}

pub(super) fn jdk_executable(tool: &str) -> Result<OsString, String> {
    let java_home = std::env::var_os("JAVA_HOME");
    jdk_executable_from_java_home(tool, java_home.as_deref())
}

fn jdk_executable_from_java_home(
    tool: &str,
    java_home: Option<&std::ffi::OsStr>,
) -> Result<OsString, String> {
    let name = if cfg!(windows) {
        format!("{tool}.exe")
    } else {
        tool.to_string()
    };
    let Some(java_home) = java_home else {
        return Ok(OsString::from(name));
    };
    if java_home.is_empty() {
        return Err(format!(
            "JAVA_HOME is set but empty; refusing PATH-based {tool} resolution"
        ));
    }
    let candidate = PathBuf::from(java_home).join("bin").join(&name);
    if !candidate.is_file() {
        return Err(format!(
            "JAVA_HOME does not contain the required JDK tool {}; refusing PATH-based {tool} resolution",
            candidate.display()
        ));
    }
    fs::canonicalize(&candidate)
        .map(PathBuf::into_os_string)
        .map_err(|error| {
            format!(
                "failed to resolve JDK tool {}: {error}",
                candidate.display()
            )
        })
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
#[path = "tests/semantic_indexer_scip_java_patch.rs"]
mod tests;
