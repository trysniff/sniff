use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub(super) fn control_environment(command: &mut Command) {
    command
        .env_clear()
        .env("GOTOOLCHAIN", "local")
        .env("GOENV", "off")
        .env("GOFLAGS", "")
        .env("GOWORK", "off");
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
}

pub(super) fn driver(
    go: &Path,
    goroot: &Path,
    output: &Path,
    parent: &Path,
) -> Result<crate::bounded_process::BoundedOutput, String> {
    let work = tempfile::Builder::new()
        .prefix(".go-adapter-build-")
        .tempdir_in(parent)
        .map_err(|error| format!("failed to create owned SDK build work: {error}"))?;
    let overlay = crate::go_tool_stdio::prepare_overlay(goroot, &work.path().join("overlay"))?;
    for name in ["build-cache", "tmp", "mod-cache", "go-path"] {
        fs::create_dir(work.path().join(name)).map_err(|error| error.to_string())?;
    }
    let mut command = Command::new(go);
    control_environment(&mut command);
    command
        .current_dir(goroot)
        .args(["build", "-p=1", "-trimpath", "-buildvcs=false", "-overlay"])
        .arg(overlay)
        .arg("-o")
        .arg(output)
        .arg("cmd/go")
        .env("GOROOT", goroot)
        .env("GO111MODULE", "off")
        .env("GOCACHE", work.path().join("build-cache"))
        .env("GOMODCACHE", work.path().join("mod-cache"))
        .env("GOPATH", work.path().join("go-path"))
        .env("TEMP", work.path().join("tmp"))
        .env("TMP", work.path().join("tmp"))
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("CGO_ENABLED", "0")
        .env("GOMAXPROCS", "2");
    let result = crate::bounded_process::run_with_output_limit(
        &mut command,
        Duration::from_secs(600),
        1024 * 1024,
    )
    .map_err(|error| format!("failed to build selected-SDK Go adapter: {error}"))?;
    if result.timed_out
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.status.success()
    {
        return Err(format!(
            "selected-SDK Go adapter build failed: status={}, timeout={}, stderr={}",
            result.status,
            result.timed_out,
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    work.close()
        .map_err(|error| format!("failed to remove owned SDK build work: {error}"))?;
    Ok(result)
}
