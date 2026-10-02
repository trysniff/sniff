use super::*;
use crate::sandbox::{SandboxCommand, sandbox_test_resource_guard};
use std::process::Command;
use std::time::Duration;

#[test]
fn adaptation_requires_one_exact_command_site() {
    assert_eq!(
        replace_exact_once("before command after", "command", "patched", "test").unwrap(),
        "before patched after"
    );
    for source in ["no site", "command command"] {
        assert!(
            replace_exact_once(source, "command", "patched", "test")
                .unwrap_err()
                .contains("expected exactly one")
        );
    }
}

#[test]
fn overlay_paths_use_the_same_drive_form_as_the_go_tool() {
    assert_eq!(
        strip_windows_verbatim_prefix(PathBuf::from(r"\\?\C:\Go\src\cmd\go")),
        PathBuf::from(r"C:\Go\src\cmd\go")
    );
    assert_eq!(
        strip_windows_verbatim_prefix(PathBuf::from(r"\\?\UNC\server\share\Go")),
        PathBuf::from(r"\\server\share\Go")
    );
}

fn fixture_sdk(root: &Path) {
    for (relative, _, replacements) in recipes() {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = replacements
            .iter()
            .map(|(before, _)| *before)
            .collect::<String>();
        fs::write(path, source).unwrap();
    }
}

#[test]
fn overlay_covers_all_three_transports_without_modifying_the_sdk() {
    let root = tempfile::tempdir().unwrap();
    fixture_sdk(root.path());
    let original = recipes().map(|(relative, _, _)| fs::read(root.path().join(relative)).unwrap());
    let output = root.path().join("overlay");
    let manifest = prepare_overlay(root.path(), &output).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    assert_eq!(value["Replace"].as_object().unwrap().len(), 3);
    for ((relative, file, replacements), bytes) in recipes().into_iter().zip(original) {
        assert_eq!(fs::read(root.path().join(relative)).unwrap(), bytes);
        let patched = fs::read_to_string(output.join(file)).unwrap();
        for (_, after) in replacements {
            assert!(patched.contains(after), "{relative}");
        }
    }
    assert!(
        fs::read_to_string(output.join("generate.go"))
            .unwrap()
            .contains("self, err := os.Executable()")
    );
    assert!(
        prepare_overlay(root.path(), &output).is_err(),
        "never overwrite an existing overlay"
    );
}

#[test]
fn incompatible_source_fails_instead_of_emitting_a_partial_manifest() {
    for (relative, _, replacements) in recipes() {
        for (before, _) in replacements {
            for repeated in [false, true] {
                let root = tempfile::tempdir().unwrap();
                fixture_sdk(root.path());
                let path = root.path().join(relative);
                let source = fs::read_to_string(&path).unwrap();
                let changed = if repeated {
                    format!("{source}{before}")
                } else {
                    source.replace(before, "")
                };
                fs::write(path, changed).unwrap();
                let output = root.path().join("overlay");
                assert!(
                    prepare_overlay(root.path(), &output)
                        .unwrap_err()
                        .contains("expected exactly one"),
                    "{relative}: repeated={repeated}"
                );
                assert!(!output.join("overlay.json").exists());
            }
        }
    }
}

#[test]
fn source_reader_rejects_oversized_and_non_utf8_sources() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.go");
    fs::write(&path, vec![b'x'; MAX_SOURCE_BYTES as usize + 1]).unwrap();
    assert!(read_source(&path).unwrap_err().contains("bounded"));
    fs::write(&path, [0xff]).unwrap();
    assert!(read_source(&path).unwrap_err().contains("UTF-8"));
    assert!(prepare_overlay(Path::new("relative"), &root.path().join("overlay")).is_err());
}

#[test]
#[ignore = "requires installed Go SDK source and actual Windows AppContainer execution"]
fn same_sdk_go_driver_compiles_and_generates_with_eof_in_appcontainer() {
    let _guard = sandbox_test_resource_guard();
    let work = tempfile::tempdir().unwrap();
    let mut query = Command::new("go");
    query
        .current_dir(work.path())
        .args(["env", "GOROOT", "GOTOOLDIR"])
        .env("GOENV", "off")
        .env("GOTOOLCHAIN", "local");
    let output = crate::bounded_process::run_with_output_limit(
        &mut query,
        Duration::from_secs(30),
        64 * 1024,
    )
    .unwrap();
    assert!(!output.timed_out && output.status.success());
    let paths = String::from_utf8(output.stdout).unwrap();
    let mut paths = paths.lines();
    let root = PathBuf::from(paths.next().unwrap().trim());
    let tools = PathBuf::from(paths.next().unwrap().trim());
    assert!(paths.next().is_none());
    assert!(root.is_absolute());
    let goroot = strip_windows_verbatim_prefix(fs::canonicalize(root).unwrap());
    let tools = strip_windows_verbatim_prefix(fs::canonicalize(tools).unwrap());
    assert!(tools.starts_with(&goroot));
    let original = recipes().map(|(relative, _, _)| fs::read(goroot.join(relative)).unwrap());
    let runtime = tempfile::tempdir().unwrap();
    let overlay = prepare_overlay(&goroot, &runtime.path().join("overlay")).unwrap();
    let bin = runtime.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let driver = bin.join("go.exe");
    let build_cache = runtime.path().join("build-cache");
    let build_temp = runtime.path().join("tmp");
    fs::create_dir(&build_cache).unwrap();
    fs::create_dir(&build_temp).unwrap();
    let mut build = Command::new(goroot.join("bin/go.exe"));
    build
        .env_clear()
        .current_dir(&goroot)
        .args(["build", "-p=1", "-trimpath", "-buildvcs=false", "-overlay"])
        .arg(overlay)
        .arg("-o")
        .arg(&driver)
        .arg("cmd/go")
        .env("GOROOT", &goroot)
        .env("GOCACHE", &build_cache)
        .env("TEMP", &build_temp)
        .env("TMP", &build_temp)
        .env("GOMAXPROCS", "2")
        .env("CGO_ENABLED", "0")
        .env("GOTOOLCHAIN", "local")
        .env("GOENV", "off")
        .env("GO111MODULE", "off")
        .env("GOWORK", "off")
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off");
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        build.env("SystemRoot", system_root);
    }
    let output = crate::bounded_process::run_with_output_limit(
        &mut build,
        Duration::from_secs(600),
        1024 * 1024,
    )
    .unwrap();
    assert!(
        !output.timed_out
            && !output.stdout_truncated
            && !output.stderr_truncated
            && output.status.success(),
        "trusted same-SDK build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for ((relative, _, _), bytes) in recipes().into_iter().zip(original) {
        assert_eq!(fs::read(goroot.join(relative)).unwrap(), bytes);
    }
    fs::create_dir_all(work.path().join("cmd/generate")).unwrap();
    fs::create_dir(work.path().join("cache")).unwrap();
    fs::create_dir(work.path().join("tmp")).unwrap();
    fs::write(
        work.path().join("go.mod"),
        "module example.com/stdio\n\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        work.path().join("generate.go"),
        "package stdio\n//go:generate go run ./cmd/generate\n",
    )
    .unwrap();
    fs::write(
        work.path().join("cmd/generate/main.go"),
        concat!(
            "package main\nimport (\"fmt\"; \"io\"; \"os\")\n",
            "func main() { data, err := io.ReadAll(os.Stdin); ",
            "if err != nil || len(data) != 0 { panic(\"stdin is not EOF\") }; ",
            "fmt.Println(\"generator-eof\") }\n"
        ),
    )
    .unwrap();
    let executable_paths = fs::read_dir(tools)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "exe"))
        .chain(std::iter::once(driver.clone()))
        .collect();
    let command = SandboxCommand {
        root: work.path().to_path_buf(),
        workdir: PathBuf::from("."),
        program: driver.to_string_lossy().into_owned(),
        args: vec!["generate".to_string(), "./...".to_string()],
        read_only_paths: vec![goroot.clone(), bin.clone()],
        writable_paths: Vec::new(),
        persistent_read_only_paths: Vec::new(),
        persistent_executable_paths: Vec::new(),
        executable_paths,
        windows_virtualized_paths: vec![work.path().to_path_buf(), goroot.clone(), bin],
        env: vec![
            ("GOROOT".to_string(), goroot.to_string_lossy().into_owned()),
            (
                "GOCACHE".to_string(),
                work.path().join("cache").to_string_lossy().into_owned(),
            ),
            (
                "TEMP".to_string(),
                work.path().join("tmp").to_string_lossy().into_owned(),
            ),
            (
                "TMP".to_string(),
                work.path().join("tmp").to_string_lossy().into_owned(),
            ),
            ("GOTOOLCHAIN".to_string(), "local".to_string()),
            ("GOENV".to_string(), "off".to_string()),
            ("GOWORK".to_string(), "off".to_string()),
            ("GOPROXY".to_string(), "off".to_string()),
            ("GOSUMDB".to_string(), "off".to_string()),
            ("CGO_ENABLED".to_string(), "0".to_string()),
            ("GOMAXPROCS".to_string(), "2".to_string()),
        ],
        allow_network: false,
        timeout: Duration::from_secs(240),
        output_limit: 1024 * 1024,
        memory_limit: 2 * 1024 * 1024 * 1024,
        process_limit: 128,
    };
    let output = crate::sandbox::run(&command).expect("real AppContainer execution is required");
    assert!(
        !output.timed_out && output.status_code == Some(0),
        "stdout={} stderr={}",
        output.stdout,
        output.stderr
    );
    assert_eq!(output.stdout.trim(), "generator-eof");
}
