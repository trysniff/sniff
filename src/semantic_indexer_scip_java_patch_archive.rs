use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MAX_NESTED_JAR_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EXECUTABLE_PREFIX_BYTES: u64 = 1024 * 1024;
const JAR_ROOT: &str = "coursier/bootstrap/launcher/jars";
pub(super) const SCIP_JAVA_ENTRY: &str = "coursier/bootstrap/launcher/jars/scip-java-0.13.1.jar";
pub(super) const SCIP_KOTLINC_ENTRY: &str = "scip-kotlinc.jar";
pub(super) const CLASS_PACKAGE: &str = "org/scip_code/scip_java/kotlinc";

pub(super) const COMPILED_CLASSES: [&str; 7] = [
    "AnalyzerFirExtensionRegistrar$configurePlugin$1.class",
    "AnalyzerFirExtensionRegistrar$configurePlugin$2.class",
    "AnalyzerFirExtensionRegistrar.class",
    "SniffAnnotationCheckers$Companion.class",
    "SniffAnnotationCheckers$SemanticAnnotationCallChecker.class",
    "SniffAnnotationCheckers$expressionCheckers$1.class",
    "SniffAnnotationCheckers.class",
];

pub(super) struct PatchJars {
    pub scip_java: PathBuf,
    pub scip_kotlinc: PathBuf,
    pub compiler: PathBuf,
    pub stdlib: PathBuf,
    pub script_runtime: PathBuf,
    pub reflect: PathBuf,
    pub coroutines: PathBuf,
    pub annotations: PathBuf,
    pub shared: PathBuf,
    pub bindings: PathBuf,
}

pub(super) fn patch_jars_from_extracted(root: &Path) -> Result<PatchJars, String> {
    let extracted = root.join(JAR_ROOT);
    let scip_java = required_jar(&extracted, "scip-java-0.13.1.jar")?;
    let compiler = required_jar(&extracted, "kotlin-compiler-embeddable-2.2.0.jar")?;
    let stdlib = required_jar(&extracted, "kotlin-stdlib-2.3.20.jar")?;
    let script_runtime = required_jar(&extracted, "kotlin-script-runtime-2.2.0.jar")?;
    let reflect = required_jar(&extracted, "kotlin-reflect-1.6.10.jar")?;
    let coroutines = required_jar(&extracted, "kotlinx-coroutines-core-jvm-1.8.0.jar")?;
    let annotations = required_jar(&extracted, "annotations-13.0.jar")?;
    let shared = required_jar(&extracted, "scip-shared-0.13.1.jar")?;
    let bindings = required_jar(&extracted, "scip-java-bindings-0.9.0.jar")?;
    let mut nested = open_zip(&scip_java, "nested scip-java runtime")?;
    let scip_kotlinc = extract_entry(
        &mut nested,
        SCIP_KOTLINC_ENTRY,
        &extracted,
        "scip-kotlinc.jar",
    )?;
    Ok(PatchJars {
        scip_java,
        scip_kotlinc,
        compiler,
        stdlib,
        script_runtime,
        reflect,
        coroutines,
        annotations,
        shared,
        bindings,
    })
}

pub(super) fn rebuild_kotlinc_jar(
    source: &Path,
    destination: &Path,
    classes: &[(String, Vec<u8>)],
) -> Result<(), String> {
    let input = File::open(source)
        .map_err(|error| format!("failed to open scip-kotlinc runtime: {error}"))?;
    let mut archive = ZipArchive::new(input)
        .map_err(|error| format!("failed to parse scip-kotlinc runtime: {error}"))?;
    if archive.offset() != 0 {
        return Err("scip-kotlinc runtime is not a plain jar".to_string());
    }
    let output = create_new(destination, "patched scip-kotlinc runtime")?;
    let mut rebuilt = ZipWriter::new(output);
    rebuilt.set_raw_comment(archive.comment().to_vec().into_boxed_slice());
    let mut replaced = 0usize;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect scip-kotlinc entry {index}: {error}"))?;
        if registrar_class(entry.name()) {
            replaced += 1;
        } else if entry
            .name()
            .starts_with(&format!("{CLASS_PACKAGE}/SniffAnnotationCheckers"))
        {
            return Err(
                "pinned scip-kotlinc already contains Sniff annotation classes".to_string(),
            );
        } else {
            rebuilt.raw_copy_file(entry).map_err(|error| {
                format!("failed to preserve scip-kotlinc entry {index}: {error}")
            })?;
        }
    }
    if replaced != 2 {
        return Err(format!(
            "pinned scip-kotlinc contained {replaced} registrar classes; expected 2"
        ));
    }
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (name, bytes) in classes {
        rebuilt
            .start_file(name, options)
            .map_err(|error| format!("failed to add Kotlin patch class {name}: {error}"))?;
        rebuilt
            .write_all(bytes)
            .map_err(|error| format!("failed to write Kotlin patch class {name}: {error}"))?;
    }
    finish_zip(rebuilt, "patched scip-kotlinc runtime")
}

pub(super) fn replace_plain_zip_entry(
    source: &Path,
    destination: &Path,
    target: &str,
    replacement: &Path,
    required_compression: Option<CompressionMethod>,
) -> Result<(), String> {
    let input = File::open(source)
        .map_err(|error| format!("failed to open {}: {error}", source.display()))?;
    let mut archive = ZipArchive::new(input)
        .map_err(|error| format!("failed to parse {}: {error}", source.display()))?;
    if archive.offset() != 0 {
        return Err(format!("{} is not a plain jar", source.display()));
    }
    let output = create_new(destination, "rebuilt jar")?;
    replace_archive_entry(
        &mut archive,
        ZipWriter::new(output),
        target,
        replacement,
        required_compression,
    )
}

pub(super) fn install_rebuilt_launcher(
    original: &Path,
    rebuilt_zip: &Path,
    destination: &Path,
    target: &str,
) -> Result<(), String> {
    let bytes = fs::read(original)
        .map_err(|error| format!("failed to read scip-java launcher: {error}"))?;
    let search_end = bytes.len().min(MAX_EXECUTABLE_PREFIX_BYTES as usize);
    let offset = bytes[..search_end]
        .windows(4)
        .position(|window| window == b"PK\x03\x04")
        .ok_or_else(|| "scip-java launcher has no bounded ZIP header".to_string())?;
    let prefix = &bytes[..offset];
    if !prefix.starts_with(b"#!") {
        return Err("scip-java launcher has no executable shebang".to_string());
    }
    let input = File::open(rebuilt_zip)
        .map_err(|error| format!("failed to open rebuilt scip-java ZIP: {error}"))?;
    let mut archive = ZipArchive::new(input)
        .map_err(|error| format!("failed to parse rebuilt scip-java ZIP: {error}"))?;
    if archive.offset() != 0 {
        return Err("rebuilt scip-java launcher is not a plain ZIP".to_string());
    }
    let target_index = exact_entry_index(&mut archive, target)?;
    if archive
        .by_index(target_index)
        .map_err(|error| format!("failed to inspect rebuilt launcher target: {error}"))?
        .compression()
        != CompressionMethod::Stored
    {
        return Err(format!("rebuilt launcher target {target} is not stored"));
    }
    let mut output = create_new(destination, "patched scip-java launcher")?;
    output
        .write_all(prefix)
        .map_err(|error| format!("failed to preserve scip-java executable prefix: {error}"))?;
    let mut rebuilt = ZipWriter::new(output);
    rebuilt.set_raw_comment(archive.comment().to_vec().into_boxed_slice());
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect rebuilt launcher entry: {error}"))?;
        rebuilt
            .raw_copy_file(entry)
            .map_err(|error| format!("failed to preserve rebuilt launcher entry: {error}"))?;
    }
    finish_zip(rebuilt, "patched scip-java launcher")
}

pub(super) fn validate_patched_scip_java(scip_java: &Path) -> Result<(), String> {
    let mut java = open_zip(scip_java, "patched scip-java nested runtime")?;
    let scip_kotlinc = read_entry(&mut java, SCIP_KOTLINC_ENTRY)?;
    let mut kotlinc = ZipArchive::new(std::io::Cursor::new(scip_kotlinc))
        .map_err(|error| format!("patched scip-kotlinc runtime is invalid: {error}"))?;
    for class in COMPILED_CLASSES {
        let name = format!("{CLASS_PACKAGE}/{class}");
        let bytes = read_entry(&mut kotlinc, &name)?;
        if !bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
            return Err(format!("patched scip-kotlinc class {name} is invalid"));
        }
    }
    Ok(())
}

fn extract_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    entry_name: &str,
    directory: &Path,
    filename: &str,
) -> Result<PathBuf, String> {
    let index = exact_entry_index(archive, entry_name)?;
    let mut entry = archive
        .by_index(index)
        .map_err(|error| format!("failed to open scip-java runtime entry {entry_name}: {error}"))?;
    if entry.is_dir() || entry.size() == 0 || entry.size() > MAX_NESTED_JAR_BYTES {
        return Err(format!(
            "scip-java runtime has invalid nested jar {entry_name}"
        ));
    }
    let destination = directory.join(filename);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("failed to create extracted {entry_name}: {error}"))?;
    std::io::copy(&mut entry, &mut output)
        .map_err(|error| format!("failed to extract {entry_name}: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("failed to sync extracted {entry_name}: {error}"))?;
    Ok(destination)
}

fn required_jar(directory: &Path, name: &str) -> Result<PathBuf, String> {
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("scip-java extraction omitted {name}: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_NESTED_JAR_BYTES
    {
        return Err(format!("scip-java extracted invalid nested jar {name}"));
    }
    Ok(path)
}

fn registrar_class(name: &str) -> bool {
    name == format!("{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar.class")
        || (name.starts_with(&format!(
            "{CLASS_PACKAGE}/AnalyzerFirExtensionRegistrar$configurePlugin$"
        )) && name.ends_with(".class"))
}

fn replace_archive_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    mut rebuilt: ZipWriter<File>,
    target: &str,
    replacement: &Path,
    required_compression: Option<CompressionMethod>,
) -> Result<(), String> {
    rebuilt.set_raw_comment(archive.comment().to_vec().into_boxed_slice());
    let replacement = fs::read(replacement)
        .map_err(|error| format!("failed to read replacement for {target}: {error}"))?;
    let mut replaced = 0usize;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect archive entry {index}: {error}"))?;
        if entry.name() != target {
            rebuilt
                .raw_copy_file(entry)
                .map_err(|error| format!("failed to preserve archive entry {index}: {error}"))?;
            continue;
        }
        let compression = entry.compression();
        if required_compression.is_some_and(|required| compression != required) {
            return Err(format!(
                "archive entry {target} has unexpected compression {compression:?}"
            ));
        }
        drop(entry);
        rebuilt
            .start_file(
                target,
                SimpleFileOptions::default()
                    .compression_method(compression)
                    .unix_permissions(0o644),
            )
            .map_err(|error| format!("failed to replace archive entry {target}: {error}"))?;
        rebuilt
            .write_all(&replacement)
            .map_err(|error| format!("failed to write archive entry {target}: {error}"))?;
        replaced += 1;
    }
    if replaced != 1 {
        return Err(format!(
            "archive contained {replaced} copies of {target}; expected 1"
        ));
    }
    finish_zip(rebuilt, target)
}

fn read_entry<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>, String> {
    let index = exact_entry_index(archive, name)?;
    let mut entry = archive
        .by_index(index)
        .map_err(|error| format!("failed to open archive entry {name}: {error}"))?;
    if entry.size() == 0 || entry.size() > MAX_NESTED_JAR_BYTES {
        return Err(format!("archive entry {name} has invalid size"));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read archive entry {name}: {error}"))?;
    Ok(bytes)
}

fn exact_entry_index<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
) -> Result<usize, String> {
    let mut matches = Vec::new();
    let basename = name.rsplit('/').next().unwrap_or(name);
    let mut similarly_named = Vec::new();
    let mut sample = Vec::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to inspect archive entry {index}: {error}"))?;
        if entry.name() == name {
            matches.push(index);
        } else if similarly_named.len() < 8 && entry.name().contains(basename) {
            similarly_named.push(entry.name().to_string());
        }
        if sample.len() < 8 {
            sample.push(entry.name().to_string());
        }
    }
    match matches.as_slice() {
        [index] => Ok(*index),
        [] if similarly_named.is_empty() => Err(format!(
            "archive is missing {name}; archive has {} entries at offset {} (sample: {})",
            archive.len(),
            archive.offset(),
            sample.join(", ")
        )),
        [] => Err(format!(
            "archive is missing {name}; similarly named entries: {}",
            similarly_named.join(", ")
        )),
        _ => Err(format!(
            "archive contains {} copies of {name}; expected 1",
            matches.len()
        )),
    }
}

fn open_zip(path: &Path, label: &str) -> Result<ZipArchive<File>, String> {
    let input = File::open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    ZipArchive::new(input).map_err(|error| format!("failed to parse {label}: {error}"))
}

fn create_new(path: &Path, label: &str) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))
}

fn finish_zip(archive: ZipWriter<File>, label: &str) -> Result<(), String> {
    let output = archive
        .finish()
        .map_err(|error| format!("failed to finish {label}: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("failed to sync {label}: {error}"))
}

#[cfg(test)]
#[path = "tests/semantic_indexer_scip_java_patch_archive.rs"]
mod tests;
