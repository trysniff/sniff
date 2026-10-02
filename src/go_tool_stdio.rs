use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const BUILD_ID_SOURCE: &str = "src/cmd/go/internal/work/buildid.go";
const SHELL_SOURCE: &str = "src/cmd/go/internal/work/shell.go";
const GENERATE_SOURCE: &str = "src/cmd/go/internal/generate/generate.go";
const BUILD_ID_BEFORE: &str = concat!(
    "\t\tcmd := exec.Command(cmdline[0], cmdline[1:]...)\n",
    "\t\tvar stdout, stderr strings.Builder\n"
);
const BUILD_ID_AFTER: &str = concat!(
    "\t\tcmd := exec.Command(cmdline[0], cmdline[1:]...)\n",
    "\t\tcmd.Stdin = strings.NewReader(\"\")\n",
    "\t\tif os.Getenv(\"SNIFF_DEBUG_INDEXERS\") != \"\" {\n",
    "\t\t\tfmt.Fprintln(os.Stderr, \"[sniff] sandbox Go build-ID probe uses explicit stdin\")\n",
    "\t\t}\n",
    "\t\tvar stdout, stderr strings.Builder\n"
);
const SHELL_BEFORE: &str = concat!(
    "\tcmd := exec.Command(path, cmdline[1:]...)\n",
    "\tif cmd.Path != \"\" {\n"
);
const SHELL_AFTER: &str = concat!(
    "\tcmd := exec.Command(path, cmdline[1:]...)\n",
    "\tcmd.Stdin = bytes.NewReader(nil)\n",
    "\tif cmd.Path != \"\" {\n"
);
const GENERATE_STDIN_BEFORE: &str = "\tcmd.Stdout = os.Stdout\n\tcmd.Stderr = os.Stderr\n";
const GENERATE_STDIN_AFTER: &str = concat!(
    "\tcmd.Stdin = bytes.NewReader(nil)\n",
    "\tcmd.Stdout = os.Stdout\n\tcmd.Stderr = os.Stderr\n"
);
const GENERATE_DRIVER_BEFORE: &str = concat!(
    "\tpath := words[0]\n",
    "\tif path != \"\" && !strings.Contains(path, string(os.PathSeparator)) {\n"
);
const GENERATE_DRIVER_AFTER: &str = concat!(
    "\tpath := words[0]\n",
    "\tif path == \"go\" {\n",
    "\t\t// Keep the same SDK-bound driver and its empty-stdin child transport.\n",
    "\t\tself, err := os.Executable()\n",
    "\t\tif err != nil {\n",
    "\t\t\tg.errorf(\"resolve current go driver: %s\", err)\n",
    "\t\t}\n",
    "\t\tpath = self\n",
    "\t} else if path != \"\" && !strings.Contains(path, string(os.PathSeparator)) {\n"
);

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct GoOverlay {
    replace: BTreeMap<String, String>,
}

/// Adapts only process transport in the selected SDK; never edits its installation.
pub(crate) fn prepare_overlay(goroot: &Path, overlay_root: &Path) -> Result<PathBuf, String> {
    if !goroot.is_absolute() || !overlay_root.is_absolute() {
        return Err("sandbox Go overlay requires absolute SDK and output paths".to_string());
    }
    fs::create_dir(overlay_root)
        .map_err(|error| format!("failed to create sandbox Go overlay: {error}"))?;
    let goroot = strip_windows_verbatim_prefix(goroot.to_path_buf());
    let mut replace = BTreeMap::new();
    for (relative, output_name, replacements) in recipes() {
        let source_path = goroot.join(relative);
        let mut source = read_source(&source_path)?;
        for (before, after) in replacements {
            source = replace_exact_once(&source, before, after, relative)?;
        }
        let output_path = overlay_root.join(output_name);
        write_new(&output_path, source.as_bytes())?;
        replace.insert(
            source_path.to_string_lossy().into_owned(),
            strip_windows_verbatim_prefix(output_path)
                .to_string_lossy()
                .into_owned(),
        );
    }
    let manifest = overlay_root.join("overlay.json");
    let bytes = serde_json::to_vec(&GoOverlay { replace })
        .map_err(|error| format!("failed to encode sandbox Go overlay: {error}"))?;
    write_new(&manifest, &bytes)?;
    Ok(strip_windows_verbatim_prefix(manifest))
}

type Recipe = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
);

fn recipes() -> [Recipe; 3] {
    [
        (
            BUILD_ID_SOURCE,
            "buildid.go",
            &[(BUILD_ID_BEFORE, BUILD_ID_AFTER)],
        ),
        (SHELL_SOURCE, "shell.go", &[(SHELL_BEFORE, SHELL_AFTER)]),
        (
            GENERATE_SOURCE,
            "generate.go",
            &[
                (GENERATE_STDIN_BEFORE, GENERATE_STDIN_AFTER),
                (GENERATE_DRIVER_BEFORE, GENERATE_DRIVER_AFTER),
            ],
        ),
    ]
}

fn read_source(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)
        .map_err(|error| format!("failed to open Go tool source {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect Go tool source: {error}"))?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > MAX_SOURCE_BYTES
    {
        return Err("Go tool source is not a plain bounded file".to_string());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read Go tool source: {error}"))?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("Go tool source exceeds its read limit".to_string());
    }
    String::from_utf8(bytes).map_err(|error| format!("Go tool source is not UTF-8: {error}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "failed to create Go overlay file {}: {error}",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to write Go overlay file {}: {error}",
                path.display()
            )
        })
}

fn replace_exact_once(
    source: &str,
    before: &str,
    after: &str,
    label: &str,
) -> Result<String, String> {
    let count = source.matches(before).count();
    if count != 1 {
        return Err(format!(
            "Go {label} source has {count} compatible command sites; expected exactly one"
        ));
    }
    Ok(source.replacen(before, after, 1))
}

pub(crate) fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path
}

#[cfg(test)]
#[path = "tests/go_tool_stdio.rs"]
mod tests;
