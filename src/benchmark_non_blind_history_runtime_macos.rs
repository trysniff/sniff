use super::{
    HistoricalRuntimePlanError, canonical_file, is_system_runtime, reject_broad_user_root,
    unavailable,
};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MAX_RUNTIME_IMAGES: usize = 256;
const OTOOL_OUTPUT_LIMIT: usize = 256 * 1024;
const OTOOL_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct MacosRuntimeClosure {
    pub(super) identity_files: Vec<PathBuf>,
    pub(super) read_only_paths: Vec<PathBuf>,
}

pub(super) fn resolve_runtime_closure(
    repository_root: &Path,
    executable: &Path,
    runtime_files: &[PathBuf],
    runtime_roots: &[PathBuf],
) -> Result<MacosRuntimeClosure, HistoricalRuntimePlanError> {
    let otool = Path::new("/usr/bin/otool");
    if !otool.is_file() {
        return Err(unavailable(
            "macOS runtime dependency inspection requires /usr/bin/otool",
        ));
    }
    let executable = canonical_file(executable, "macOS runtime executable")?;
    let mut pending = runtime_files.iter().cloned().collect::<VecDeque<_>>();
    let mut seen = BTreeSet::new();
    let mut identity_files = BTreeSet::new();
    let mut read_only_paths = BTreeSet::new();

    while let Some(image) = pending.pop_front() {
        let image = canonical_file(&image, "macOS runtime image")?;
        if !seen.insert(image.clone()) || !is_macho(&image)? {
            continue;
        }
        if seen.len() > MAX_RUNTIME_IMAGES {
            return Err(unavailable(format!(
                "macOS runtime dependency closure exceeds {MAX_RUNTIME_IMAGES} images"
            )));
        }
        for dependency in inspect_dependencies(otool, &image)? {
            let lexical = resolve_dependency(&dependency, &image, &executable, runtime_roots)?;
            let canonical = canonical_file(&lexical, "macOS runtime dependency")?;
            reject_repository_overlap(repository_root, &canonical)?;
            if !is_system_runtime(&canonical) {
                identity_files.insert(canonical.clone());
                add_read_directory(repository_root, &lexical, &mut read_only_paths)?;
                add_read_directory(repository_root, &canonical, &mut read_only_paths)?;
            }
            pending.push_back(canonical);
        }
    }

    Ok(MacosRuntimeClosure {
        identity_files: identity_files.into_iter().collect(),
        read_only_paths: read_only_paths.into_iter().collect(),
    })
}

fn inspect_dependencies(
    otool: &Path,
    image: &Path,
) -> Result<Vec<String>, HistoricalRuntimePlanError> {
    let mut command = Command::new(otool);
    command.arg("-L").arg(image);
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        OTOOL_TIMEOUT,
        OTOOL_OUTPUT_LIMIT,
    )
    .map_err(|error| unavailable(format!("failed to inspect macOS runtime image: {error}")))?;
    if output.timed_out || output.stdout_truncated || output.stderr_truncated {
        return Err(unavailable(
            "macOS runtime dependency inspection returned unbounded output",
        ));
    }
    if !output.status.success() {
        return Err(unavailable(format!(
            "otool rejected macOS runtime image {}",
            image.display()
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| unavailable("otool returned non-UTF-8 dependency output"))?;
    parse_otool_dependencies(&stdout)
}

fn parse_otool_dependencies(output: &str) -> Result<Vec<String>, HistoricalRuntimePlanError> {
    let mut lines = output.lines();
    let header = lines
        .next()
        .filter(|line| line.trim_end().ends_with(':'))
        .ok_or_else(|| unavailable("otool dependency output has no image header"))?;
    if header.trim().is_empty() {
        return Err(unavailable(
            "otool dependency output has an empty image header",
        ));
    }
    let mut dependencies = BTreeSet::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let line = line.trim();
        let (dependency, _) = line
            .split_once(" (compatibility version")
            .ok_or_else(|| unavailable("otool dependency output has an unknown record"))?;
        if dependency.is_empty() || dependency.contains('\0') {
            return Err(unavailable("otool dependency output has an invalid path"));
        }
        dependencies.insert(dependency.to_string());
    }
    Ok(dependencies.into_iter().collect())
}

fn resolve_dependency(
    dependency: &str,
    loader: &Path,
    executable: &Path,
    runtime_roots: &[PathBuf],
) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let path = Path::new(dependency);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if let Some(relative) = dependency.strip_prefix("@loader_path/") {
        return loader
            .parent()
            .map(|parent| parent.join(relative))
            .ok_or_else(|| unavailable("macOS runtime loader has no containing directory"));
    }
    if let Some(relative) = dependency.strip_prefix("@executable_path/") {
        return executable
            .parent()
            .map(|parent| parent.join(relative))
            .ok_or_else(|| unavailable("macOS runtime executable has no containing directory"));
    }
    let Some(relative) = dependency.strip_prefix("@rpath/") else {
        return Err(unavailable(format!(
            "unsupported macOS runtime dependency path: {dependency}"
        )));
    };
    let mut candidates = Vec::new();
    if let Some(parent) = loader.parent() {
        candidates.push(parent.join(relative));
        if let Some(prefix) = parent.parent() {
            candidates.push(prefix.join("lib").join(relative));
        }
    }
    for root in runtime_roots {
        candidates.push(root.join(relative));
        candidates.push(root.join("lib").join(relative));
    }
    let mut resolved = BTreeSet::new();
    let mut lexical = None;
    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        let canonical = canonical_file(&candidate, "macOS rpath dependency")?;
        lexical.get_or_insert(candidate);
        resolved.insert(canonical);
    }
    if resolved.len() != 1 {
        return Err(unavailable(format!(
            "macOS runtime dependency {dependency} resolved to {} exact images",
            resolved.len()
        )));
    }
    lexical.ok_or_else(|| unavailable(format!("macOS runtime dependency is absent: {dependency}")))
}

fn add_read_directory(
    repository_root: &Path,
    image: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<(), HistoricalRuntimePlanError> {
    let directory = image
        .parent()
        .ok_or_else(|| unavailable("macOS runtime dependency has no containing directory"))?;
    if !directory.is_absolute() || !directory.is_dir() {
        return Err(unavailable(format!(
            "macOS runtime dependency directory is unavailable: {}",
            directory.display()
        )));
    }
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        unavailable(format!(
            "failed to inspect macOS runtime dependency directory: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(unavailable(format!(
            "macOS runtime dependency directory is a symlink: {}",
            directory.display()
        )));
    }
    let canonical = fs::canonicalize(directory).map_err(|error| {
        unavailable(format!(
            "failed to resolve macOS runtime dependency directory: {error}"
        ))
    })?;
    reject_repository_overlap(repository_root, &canonical)?;
    reject_broad_user_root(&canonical)?;
    paths.insert(directory.to_path_buf());
    Ok(())
}

fn reject_repository_overlap(
    repository_root: &Path,
    path: &Path,
) -> Result<(), HistoricalRuntimePlanError> {
    if path.starts_with(repository_root) || repository_root.starts_with(path) {
        return Err(HistoricalRuntimePlanError::Invalid(format!(
            "macOS runtime dependency overlaps the repository: {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_macho(path: &Path) -> Result<bool, HistoricalRuntimePlanError> {
    let mut file = fs::File::open(path).map_err(|error| {
        unavailable(format!(
            "failed to inspect macOS runtime image {}: {error}",
            path.display()
        ))
    })?;
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic).map_err(|error| {
        unavailable(format!(
            "failed to read macOS runtime image {}: {error}",
            path.display()
        ))
    })?;
    if read != magic.len() {
        return Ok(false);
    }
    Ok(matches!(
        u32::from_be_bytes(magic),
        0xfeed_face
            | 0xcefa_edfe
            | 0xfeed_facf
            | 0xcffa_edfe
            | 0xcafe_babe
            | 0xbeba_feca
            | 0xcafe_babf
            | 0xbfba_feca
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_otool_dependencies;

    #[test]
    fn parses_exact_otool_dependency_paths() {
        let parsed = parse_otool_dependencies(
            "/opt/homebrew/bin/node:\n\t@rpath/libnode.137.dylib (compatibility version 137.0.0, current version 137.0.0)\n\t/opt/homebrew/opt/libuv/lib/libuv.1.dylib (compatibility version 1.0.0, current version 1.0.0)\n",
        )
        .unwrap();

        assert_eq!(
            parsed,
            vec![
                "/opt/homebrew/opt/libuv/lib/libuv.1.dylib".to_string(),
                "@rpath/libnode.137.dylib".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_untyped_otool_records() {
        let error = parse_otool_dependencies("/opt/homebrew/bin/node:\n\tlibuv\n").unwrap_err();

        assert!(matches!(
            error,
            super::HistoricalRuntimePlanError::Unavailable(_)
        ));
    }
}
