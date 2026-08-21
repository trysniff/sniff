use super::*;
use crate::semantic_indexer_manifest::{SemanticIndexerKind, pinned_indexer};
use sha2::{Digest, Sha256};

const UPSTREAM_SHA256: &str = "a694cae143c32c5b6226362fb4bd268a8d13d3cd9b482819b3b0029a9a97b8fe";

#[test]
fn explicit_java_home_requires_the_exact_jdk_tool_without_path_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let tool_name = if cfg!(windows) { "jar.exe" } else { "jar" };
    let expected = bin.join(tool_name);
    fs::write(&expected, b"tool").unwrap();

    assert_eq!(
        PathBuf::from(jdk_executable_from_java_home("jar", Some(temp.path().as_os_str())).unwrap()),
        fs::canonicalize(&expected).unwrap()
    );

    let missing = temp.path().join("missing");
    let error = jdk_executable_from_java_home("jar", Some(missing.as_os_str())).unwrap_err();
    assert!(error.contains("refusing PATH-based jar resolution"));
    let error = jdk_executable_from_java_home("jar", Some(std::ffi::OsStr::new(""))).unwrap_err();
    assert!(error.contains("set but empty"));
}

#[tokio::test]
#[ignore = "requires the 86 MB checksum-pinned upstream scip-java v0.13.1 launcher"]
async fn patches_the_verified_upstream_launcher_with_the_embedded_compiler() {
    let source = PathBuf::from(
        std::env::var_os("SNIFF_TEST_SCIP_JAVA_LAUNCHER")
            .expect("set SNIFF_TEST_SCIP_JAVA_LAUNCHER to the upstream launcher"),
    );
    let source_bytes = fs::read(&source).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&source_bytes)),
        UPSTREAM_SHA256
    );

    let temp = tempfile::tempdir().unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::Kotlin).unwrap();
    let launcher = temp.path().join(spec.entrypoint_relative_path());
    fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    fs::write(&launcher, source_bytes).unwrap();

    patch_kotlin_annotation_references(temp.path(), spec)
        .await
        .unwrap();
    #[cfg(windows)]
    super::super::scip_java_windows::patch_scip_java_windows(temp.path(), spec).unwrap();

    let version = std::process::Command::new(java_executable().unwrap())
        .arg("-jar")
        .arg(&launcher)
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "patched launcher failed to execute: {}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        "scip-java version 0.0.0-SNAPSHOT"
    );
}
