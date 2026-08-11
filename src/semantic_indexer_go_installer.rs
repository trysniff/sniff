use super::{run_command, run_json_command};
use crate::semantic_indexer_manifest::PinnedIndexer;
use serde_json::{Deserializer, Value};
use std::ffi::OsString;
use std::fs;
#[cfg(windows)]
use std::io;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[cfg(windows)]
const MAX_BUILD_SOURCE_FILES: usize = 20_000;
#[cfg(windows)]
const MAX_BUILD_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
#[cfg(windows)]
const SCIP_GO_TOOLS_REQUIREMENT: &str = "golang.org/x/tools v0.45.0";
#[cfg(windows)]
const SCIP_GO_INVOKE_PATH: &str = "vendor/golang.org/x/tools/internal/gocommand/invoke.go";
#[cfg(windows)]
const SCIP_GO_INVOKE_SHA256: &str =
    "6a07f4ecd3e7566643810962ba551001b50bd4403e87a915327899f0cd6d55a5";
#[cfg(windows)]
const SCIP_GO_STDIN_BEFORE: &str = concat!(
    "\tcmd := exec.Command(\"go\", goArgs...)\n",
    "\tcmd.Stdout = stdout\n",
    "\tcmd.Stderr = stderr\n"
);
#[cfg(windows)]
const SCIP_GO_STDIN_AFTER: &str = concat!(
    "\tcmd := exec.Command(\"go\", goArgs...)\n",
    "\tcmd.Stdin = bytes.NewReader(nil)\n",
    "\tcmd.Stdout = stdout\n",
    "\tcmd.Stderr = stderr\n"
);
#[cfg(windows)]
const SCIP_GO_TRACE_BEFORE: &str = "\treturn runCmdContext(ctx, cmd)\n";
#[cfg(windows)]
const SCIP_GO_TRACE_AFTER: &str = concat!(
    "\tresult := runCmdContext(ctx, cmd)\n",
    "\tif os.Getenv(\"SNIFF_DEBUG_INDEXERS\") != \"\" {\n",
    "\t\tstdoutBytes := -1\n",
    "\t\tif buffer, ok := stdout.(*bytes.Buffer); ok {\n",
    "\t\t\tstdoutBytes = buffer.Len()\n",
    "\t\t}\n",
    "\t\tstderrText := fmt.Sprint(stderr)\n",
    "\t\tfmt.Fprintf(os.Stderr, \"[sniff] go command: %s; stdout bytes: %d; result: %v; stderr: %q\\n\", debugStr, stdoutBytes, result, stderrText)\n",
    "\t}\n",
    "\treturn result\n"
);

#[derive(Debug, PartialEq, Eq)]
struct GoModuleMetadata {
    origin_hash: String,
    directory: PathBuf,
}

pub(super) async fn install(
    spec: PinnedIndexer,
    root: &Path,
    module: &str,
    package: &str,
    commit: &str,
) -> Result<(), String> {
    let module_spec = format!("{module}@v{}", spec.version);
    let mut metadata_command = Command::new(go_executable_name());
    metadata_command
        .args(["mod", "download", "-json"])
        .arg(&module_spec);
    let metadata_bytes =
        run_json_command(&mut metadata_command, "Go module pin verification").await?;
    let metadata = parse_go_module_metadata(&metadata_bytes, module)?;
    if metadata.origin_hash != commit {
        return Err(format!(
            "{} Go commit mismatch; expected {}, received {}",
            spec.display_name, commit, metadata.origin_hash
        ));
    }

    #[cfg(windows)]
    {
        install_windows(root, module, package, &metadata.directory).await
    }
    #[cfg(not(windows))]
    {
        let _ = metadata.directory;
        install_official(spec, root, package).await
    }
}

#[cfg(not(windows))]
async fn install_official(spec: PinnedIndexer, root: &Path, package: &str) -> Result<(), String> {
    let bin = root.join("bin");
    fs::create_dir_all(&bin)
        .map_err(|error| format!("failed to create Go bin directory: {error}"))?;
    let mut command = Command::new(go_executable_name());
    command
        .args(["install"])
        .arg(format!("{package}@v{}", spec.version))
        .env("GOBIN", &bin);
    run_command(&mut command, "Go indexer installation")
        .await
        .map(|_| ())
}

#[cfg(windows)]
async fn install_windows(
    root: &Path,
    module: &str,
    package: &str,
    downloaded_source: &Path,
) -> Result<(), String> {
    let build_root = root.join(".go-build");
    fs::create_dir(&build_root).map_err(|error| {
        format!(
            "failed to create isolated scip-go build directory {}: {error}",
            build_root.display()
        )
    })?;
    let result = install_windows_inner(root, module, package, downloaded_source, &build_root).await;
    let cleanup = fs::remove_dir_all(&build_root);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!(
            "failed to remove isolated scip-go build directory {}: {error}",
            build_root.display()
        )),
        (Err(build_error), Err(cleanup_error)) => Err(format!(
            "{build_error}; additionally failed to remove isolated scip-go build directory {}: {cleanup_error}",
            build_root.display()
        )),
    }
}

#[cfg(windows)]
async fn install_windows_inner(
    root: &Path,
    module: &str,
    package: &str,
    downloaded_source: &Path,
    build_root: &Path,
) -> Result<(), String> {
    let source_root = build_root.join("scip-go");
    copy_verified_source_tree(downloaded_source, &source_root)?;
    verify_go_requirement(&source_root.join("go.mod"))?;

    let mut vendor_command = Command::new(go_executable_name());
    vendor_command
        .current_dir(&source_root)
        .args(["mod", "vendor"]);
    run_command(&mut vendor_command, "scip-go dependency vendoring").await?;
    patch_go_command_compatibility(&source_root.join(SCIP_GO_INVOKE_PATH))?;

    let relative_package = package.strip_prefix(module).ok_or_else(|| {
        format!("scip-go package {package} is outside the pinned module {module}")
    })?;
    let relative_package = relative_package.strip_prefix('/').ok_or_else(|| {
        format!("scip-go package {package} is not a child of pinned module {module}")
    })?;
    let bin = root.join("bin");
    fs::create_dir_all(&bin)
        .map_err(|error| format!("failed to create Go bin directory: {error}"))?;
    let output = bin.join("scip-go.exe");
    let mut build_command = Command::new(go_executable_name());
    build_command
        .current_dir(&source_root)
        .args(["build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-o"])
        .arg(&output)
        .arg(format!("./{relative_package}"));
    run_command(&mut build_command, "scip-go Windows compatibility build")
        .await
        .map(|_| ())
}

#[cfg(windows)]
fn verify_go_requirement(go_mod: &Path) -> Result<(), String> {
    let source = fs::read_to_string(go_mod)
        .map_err(|error| format!("failed to read pinned scip-go go.mod: {error}"))?;
    let count = source.matches(SCIP_GO_TOOLS_REQUIREMENT).count();
    if count != 1 {
        return Err(format!(
            "pinned scip-go must contain exactly one {SCIP_GO_TOOLS_REQUIREMENT} requirement; found {count}"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn patch_go_command_compatibility(invoke_path: &Path) -> Result<(), String> {
    let source = fs::read(invoke_path).map_err(|error| {
        format!(
            "failed to read pinned x/tools command runner {}: {error}",
            invoke_path.display()
        )
    })?;
    let digest = format!("{:x}", Sha256::digest(&source));
    if digest != SCIP_GO_INVOKE_SHA256 {
        return Err(format!(
            "pinned x/tools command runner checksum mismatch; expected {SCIP_GO_INVOKE_SHA256}, received {digest}"
        ));
    }
    let source = String::from_utf8(source)
        .map_err(|error| format!("pinned x/tools command runner is not UTF-8: {error}"))?;
    let stdin_count = source.matches(SCIP_GO_STDIN_BEFORE).count();
    if stdin_count != 1 {
        return Err(format!(
            "pinned x/tools command runner has {stdin_count} compatible go-command sites; expected exactly one"
        ));
    }
    let trace_count = source.matches(SCIP_GO_TRACE_BEFORE).count();
    if trace_count != 1 {
        return Err(format!(
            "pinned x/tools command runner has {trace_count} traceable go-command return sites; expected exactly one"
        ));
    }
    let patched = source
        .replacen(SCIP_GO_STDIN_BEFORE, SCIP_GO_STDIN_AFTER, 1)
        .replacen(SCIP_GO_TRACE_BEFORE, SCIP_GO_TRACE_AFTER, 1);
    fs::write(invoke_path, patched).map_err(|error| {
        format!(
            "failed to write the scip-go Windows stdin compatibility patch {}: {error}",
            invoke_path.display()
        )
    })
}

#[cfg(windows)]
fn copy_verified_source_tree(source: &Path, target: &Path) -> Result<(), String> {
    let source = source.canonicalize().map_err(|error| {
        format!(
            "failed to canonicalize downloaded scip-go source {}: {error}",
            source.display()
        )
    })?;
    let mut budget = SourceBudget::default();
    copy_source_directory(&source, target, &mut budget)
}

#[cfg(windows)]
#[derive(Default)]
struct SourceBudget {
    files: usize,
    bytes: u64,
}

#[cfg(windows)]
fn copy_source_directory(
    source: &Path,
    target: &Path,
    budget: &mut SourceBudget,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "failed to inspect downloaded Go source {}: {error}",
            source.display()
        )
    })?;
    reject_reparse_point(source, &metadata)?;
    if !metadata.is_dir() {
        return Err(format!(
            "downloaded Go source is not a directory: {}",
            source.display()
        ));
    }
    fs::create_dir(target).map_err(|error| {
        format!(
            "failed to create isolated Go source directory {}: {error}",
            target.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "failed to read downloaded Go source directory {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate downloaded Go source directory {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            format!(
                "failed to inspect downloaded Go source {}: {error}",
                source_path.display()
            )
        })?;
        reject_reparse_point(&source_path, &metadata)?;
        if metadata.is_dir() {
            copy_source_directory(&source_path, &target_path, budget)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "downloaded Go source contains a non-file entry: {}",
                source_path.display()
            ));
        }
        budget.files = budget.files.saturating_add(1);
        budget.bytes = budget.bytes.saturating_add(metadata.len());
        if budget.files > MAX_BUILD_SOURCE_FILES || budget.bytes > MAX_BUILD_SOURCE_BYTES {
            return Err(format!(
                "downloaded Go source exceeds the isolated build limit of {MAX_BUILD_SOURCE_FILES} files or {MAX_BUILD_SOURCE_BYTES} bytes"
            ));
        }
        let mut source_file = fs::File::open(&source_path).map_err(|error| {
            format!(
                "failed to open downloaded Go source {}: {error}",
                source_path.display()
            )
        })?;
        let mut target_file = fs::File::create(&target_path).map_err(|error| {
            format!(
                "failed to create isolated Go source {}: {error}",
                target_path.display()
            )
        })?;
        let copied = io::copy(&mut source_file, &mut target_file).map_err(|error| {
            format!(
                "failed to copy downloaded Go source {}: {error}",
                source_path.display()
            )
        })?;
        if copied != metadata.len() {
            return Err(format!(
                "downloaded Go source changed while copying {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn reject_reparse_point(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(format!(
            "downloaded Go source contains a reparse point: {}",
            path.display()
        ));
    }
    Ok(())
}

fn parse_go_module_metadata(bytes: &[u8], module: &str) -> Result<GoModuleMetadata, String> {
    let values = Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Go module metadata is not valid JSON: {error}"))?;
    let value = values
        .into_iter()
        .find(|value| value.get("Path").and_then(Value::as_str) == Some(module))
        .ok_or_else(|| format!("Go module metadata omitted {module}"))?;
    let origin_hash = value
        .get("Origin")
        .and_then(|origin| origin.get("Hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "Go module metadata omitted Origin.Hash for {module}; refusing unverified install"
            )
        })?;
    let directory = value.get("Dir").and_then(Value::as_str).ok_or_else(|| {
        format!("Go module metadata omitted Dir for {module}; refusing unverified install")
    })?;
    if directory.trim().is_empty() {
        return Err(format!(
            "Go module metadata returned an empty Dir for {module}; refusing unverified install"
        ));
    }
    Ok(GoModuleMetadata {
        origin_hash: origin_hash.to_string(),
        directory: PathBuf::from(directory),
    })
}

fn go_executable_name() -> OsString {
    if cfg!(windows) {
        OsString::from("go.exe")
    } else {
        OsString::from("go")
    }
}

#[cfg(test)]
mod tests {
    use super::{go_executable_name, parse_go_module_metadata};
    use std::path::PathBuf;

    #[test]
    fn installation_uses_the_native_go_executable_name() {
        let expected = if cfg!(windows) { "go.exe" } else { "go" };
        assert_eq!(go_executable_name().to_string_lossy(), expected);
    }

    #[test]
    fn metadata_accepts_a_json_stream_and_selects_the_pinned_module() {
        let metadata = br#"{"Path":"dependency","Dir":"ignored","Origin":{"Hash":"wrong"}}
{"Path":"github.com/scip-code/scip-go","Dir":"C:/module","Origin":{"Hash":"expected"}}"#;
        assert_eq!(
            parse_go_module_metadata(metadata, "github.com/scip-code/scip-go").unwrap(),
            super::GoModuleMetadata {
                origin_hash: "expected".to_string(),
                directory: PathBuf::from("C:/module"),
            }
        );
    }

    #[test]
    fn metadata_requires_both_commit_identity_and_source_directory() {
        let no_hash = br#"{"Path":"github.com/scip-code/scip-go","Dir":"C:/module"}"#;
        assert!(
            parse_go_module_metadata(no_hash, "github.com/scip-code/scip-go")
                .unwrap_err()
                .contains("Origin.Hash")
        );
        let no_directory =
            br#"{"Path":"github.com/scip-code/scip-go","Origin":{"Hash":"expected"}}"#;
        assert!(
            parse_go_module_metadata(no_directory, "github.com/scip-code/scip-go")
                .unwrap_err()
                .contains("omitted Dir")
        );
    }
}
