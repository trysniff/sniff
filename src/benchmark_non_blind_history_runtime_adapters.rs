use super::non_blind_history_runtime::HistoricalRuntimePlanError;
use super::non_blind_history_runtime_support::{
    canonical_file, executable_installation_root, is_system_runtime, looks_repository_relative,
    parent_directory, path_value, query_path, reject_broad_user_root, repository_program,
    resolve_on_path, resolve_rust_tool, rust_toolchain_root, sandbox_repository_path, unavailable,
};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::{fs, io::Read};

pub(super) struct Launch {
    pub(super) target: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) runtime_files: Vec<PathBuf>,
    pub(super) runtime_roots: Vec<PathBuf>,
    pub(super) env: Vec<(String, String)>,
    pub(super) repository_target: bool,
    #[cfg(windows)]
    pub(super) collect_runtime_images: bool,
}

pub(super) fn cargo_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    let cargo = resolve_rust_tool("cargo")?;
    let rustc = resolve_rust_tool("rustc")?;
    let cargo_root = rust_toolchain_root(&cargo)?;
    let rustc_root = rust_toolchain_root(&rustc)?;
    reject_broad_user_root(&cargo_root)?;
    reject_broad_user_root(&rustc_root)?;
    #[cfg(target_os = "macos")]
    let (runtime_roots, env) = {
        let xcode_select = resolve_on_path("xcode-select")?;
        let developer_dir = query_path(&xcode_select, &["-p"], "active macOS developer directory")?;
        let developer_root = parent_directory(&developer_dir, "active macOS developer root")?;
        (
            vec![cargo_root, rustc_root, developer_root],
            vec![
                ("CARGO".to_string(), path_value(&cargo)),
                ("RUSTC".to_string(), path_value(&rustc)),
                ("DEVELOPER_DIR".to_string(), path_value(&developer_dir)),
            ],
        )
    };
    #[cfg(not(target_os = "macos"))]
    let (runtime_roots, env) = (
        vec![cargo_root, rustc_root],
        vec![
            ("CARGO".to_string(), path_value(&cargo)),
            ("RUSTC".to_string(), path_value(&rustc)),
        ],
    );
    Ok(Launch {
        target: cargo.clone(),
        args: args.to_vec(),
        runtime_files: vec![cargo.clone(), rustc.clone()],
        runtime_roots,
        env,
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn go_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    let go = resolve_on_path("go")?;
    let go_root = query_path(&go, &["env", "GOROOT"], "Go GOROOT")?;
    Ok(Launch {
        target: go.clone(),
        args: args.to_vec(),
        runtime_files: vec![go],
        runtime_roots: vec![go_root.clone()],
        env: vec![("GOROOT".to_string(), path_value(&go_root))],
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn python_launch(
    program: &str,
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    let python = resolve_on_path(program)?;
    let prefix = query_path(
        &python,
        &["-c", "import sys; print(sys.prefix)"],
        "Python prefix",
    )?;
    let runtime_files = vec![python.clone()];
    #[cfg(windows)]
    let runtime_files = {
        let mut runtime_files = runtime_files;
        extend_windows_python_images(&prefix, &mut runtime_files)?;
        runtime_files
    };
    Ok(Launch {
        target: python.clone(),
        args: args.to_vec(),
        runtime_files,
        runtime_roots: vec![prefix],
        env: Vec::new(),
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: false,
    })
}

pub(super) fn uv_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    let uv = resolve_on_path("uv")?;
    #[cfg(windows)]
    let python_program = "python";
    #[cfg(not(windows))]
    let python_program = "python3";
    let python = resolve_on_path(python_program)?;
    let python_prefix = query_path(
        &python,
        &["-c", "import sys; print(sys.prefix)"],
        "Python prefix",
    )?;
    let uv_root = executable_installation_root(&uv, "uv runtime")?;
    reject_broad_user_root(&uv_root)?;
    reject_broad_user_root(&python_prefix)?;
    let runtime_files = vec![uv.clone(), python.clone()];
    #[cfg(windows)]
    let runtime_files = {
        let mut runtime_files = runtime_files;
        extend_windows_python_images(&python_prefix, &mut runtime_files)?;
        runtime_files
    };
    Ok(Launch {
        target: uv.clone(),
        args: args.to_vec(),
        runtime_files,
        runtime_roots: vec![uv_root, python_prefix],
        env: vec![("UV_PYTHON".to_string(), path_value(&python))],
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: false,
    })
}

pub(super) fn private_python_launch(
    cache_root: &Path,
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    let host = resolve_on_path("python")?;
    let prefix = query_path(
        &host,
        &["-c", "import sys; print(sys.prefix)"],
        "Python prefix",
    )?;
    #[cfg(windows)]
    let private = cache_root
        .join("python-env")
        .join("Scripts")
        .join("python.exe");
    #[cfg(not(windows))]
    let private = cache_root.join("python-env").join("bin").join("python");
    let private = canonical_file(&private, "private historical Python runtime")?;
    let runtime_files = vec![host];
    #[cfg(windows)]
    let runtime_files = {
        let mut runtime_files = runtime_files;
        extend_windows_python_images(&prefix, &mut runtime_files)?;
        runtime_files
    };
    Ok(Launch {
        target: private,
        args: args.to_vec(),
        runtime_files,
        runtime_roots: vec![prefix],
        env: Vec::new(),
        repository_target: true,
        #[cfg(windows)]
        collect_runtime_images: false,
    })
}

pub(super) fn node_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    let node = resolve_on_path("node")?;
    let root = executable_installation_root(&node, "Node runtime")?;
    reject_broad_user_root(&root)?;
    Ok(Launch {
        target: node.clone(),
        args: args.to_vec(),
        runtime_files: vec![node],
        runtime_roots: vec![root],
        env: Vec::new(),
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn node_manager_launch(
    manager: &str,
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    let manager_path = resolve_on_path(manager)?;
    let node = resolve_on_path("node")?;
    let node_root = executable_installation_root(&node, "Node runtime")?;
    reject_broad_user_root(&node_root)?;
    Ok(Launch {
        target: manager_path.clone(),
        args: args.to_vec(),
        runtime_files: vec![manager_path.clone(), node.clone()],
        runtime_roots: vec![
            parent_directory(&manager_path, "package-manager runtime")?,
            node_root,
        ],
        env: Vec::new(),
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn bun_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    let bun = resolve_on_path("bun")?;
    Ok(Launch {
        target: bun.clone(),
        args: args.to_vec(),
        runtime_files: vec![bun.clone()],
        runtime_roots: vec![parent_directory(&bun, "Bun runtime")?],
        env: Vec::new(),
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn gradle_launch(
    root: &Path,
    program: &str,
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    let wrapper = repository_program(root, program)?;
    let java = resolve_on_path("java")?;
    let java_home = java
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unavailable("Java runtime has no JAVA_HOME"))?
        .to_path_buf();
    Ok(Launch {
        target: wrapper,
        args: args.to_vec(),
        runtime_files: vec![java],
        runtime_roots: vec![java_home.clone()],
        env: vec![("JAVA_HOME".to_string(), path_value(&java_home))],
        repository_target: true,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn gradle_installation_launch(
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    let java = resolve_on_path("java")?;
    let java_home = java
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unavailable("Java runtime has no JAVA_HOME"))?
        .to_path_buf();
    let gradle = resolve_on_path("gradle")?;
    let gradle_home = gradle
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unavailable("Gradle runtime has no installation root"))?
        .to_path_buf();
    reject_broad_user_root(&java_home)?;
    reject_broad_user_root(&gradle_home)?;
    let tooling_api = canonical_file(
        &gradle_home.join("lib").join("gradle-tooling-api-8.8.jar"),
        "pinned Gradle 8.8 Tooling API",
    )?;
    Ok(Launch {
        target: gradle.clone(),
        args: args.to_vec(),
        runtime_files: vec![java, gradle, tooling_api],
        runtime_roots: vec![java_home.clone(), gradle_home],
        env: vec![("JAVA_HOME".to_string(), path_value(&java_home))],
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn gradle_tooling_launch(args: &[String]) -> Result<Launch, HistoricalRuntimePlanError> {
    if args.len() != 4 {
        return Err(HistoricalRuntimePlanError::Invalid(
            "Gradle Tooling API launch requires client, project, cache, and init-script arguments"
                .to_string(),
        ));
    }
    let java = resolve_on_path("java")?;
    let java_home = java
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unavailable("Java runtime has no JAVA_HOME"))?
        .to_path_buf();
    let gradle = resolve_on_path("gradle")?;
    let gradle_home = gradle
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unavailable("Gradle runtime has no installation root"))?
        .to_path_buf();
    reject_broad_user_root(&java_home)?;
    reject_broad_user_root(&gradle_home)?;
    let tooling_api = canonical_file(
        &gradle_home.join("lib").join("gradle-tooling-api-8.8.jar"),
        "pinned Gradle 8.8 Tooling API",
    )?;
    let separator = if cfg!(windows) { ";" } else { ":" };
    let classpath = format!(
        "{}{}{}",
        gradle_home.join("lib").join("*").to_string_lossy(),
        separator,
        gradle_home
            .join("lib")
            .join("plugins")
            .join("*")
            .to_string_lossy()
    );
    let java_args = vec![
        "-Xms64m".to_string(),
        "-Xmx768m".to_string(),
        "-XX:MaxMetaspaceSize=256m".to_string(),
        "-XX:ReservedCodeCacheSize=128m".to_string(),
        "-XX:+UseSerialGC".to_string(),
        "-cp".to_string(),
        classpath,
        "groovy.ui.GroovyMain".to_string(),
        args[0].clone(),
        args[1].clone(),
        path_value(&gradle_home),
        args[2].clone(),
        args[3].clone(),
    ];
    Ok(Launch {
        target: java.clone(),
        args: java_args,
        runtime_files: vec![java, gradle, tooling_api],
        runtime_roots: vec![java_home.clone(), gradle_home],
        env: vec![("JAVA_HOME".to_string(), path_value(&java_home))],
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

pub(super) fn generic_launch(
    root: &Path,
    program: &str,
    args: &[String],
) -> Result<Launch, HistoricalRuntimePlanError> {
    if looks_repository_relative(program) {
        let target = repository_program(root, program)?;
        let extension = target
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if extension.eq_ignore_ascii_case("py") {
            let mut launch = python_launch("python", &[])?;
            launch.args.push(sandbox_repository_path(root, &target));
            launch.args.extend_from_slice(args);
            return Ok(launch);
        }
        if extension.eq_ignore_ascii_case("js") {
            let mut launch = node_launch(&[])?;
            launch.args.push(sandbox_repository_path(root, &target));
            launch.args.extend_from_slice(args);
            return Ok(launch);
        }
        return Ok(Launch {
            target,
            args: args.to_vec(),
            runtime_files: Vec::new(),
            runtime_roots: Vec::new(),
            env: Vec::new(),
            repository_target: true,
            #[cfg(windows)]
            collect_runtime_images: true,
        });
    }
    let target = resolve_on_path(program)?;
    let runtime_roots = if is_system_runtime(&target) {
        Vec::new()
    } else {
        vec![parent_directory(&target, "host runtime")?]
    };
    Ok(Launch {
        target: target.clone(),
        args: args.to_vec(),
        runtime_files: vec![target.clone()],
        runtime_roots,
        env: Vec::new(),
        repository_target: false,
        #[cfg(windows)]
        collect_runtime_images: true,
    })
}

#[cfg(windows)]
fn extend_windows_python_images(
    prefix: &Path,
    images: &mut Vec<PathBuf>,
) -> Result<(), HistoricalRuntimePlanError> {
    const MAX_ENTRIES: usize = 512;
    let mut entries = 0usize;
    for directory in [prefix.to_path_buf(), prefix.join("DLLs")] {
        if !directory.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&directory).map_err(|error| {
            unavailable(format!(
                "failed to enumerate Python runtime {}: {error}",
                directory.display()
            ))
        })? {
            let entry =
                entry.map_err(|error| unavailable(format!("invalid runtime entry: {error}")))?;
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(unavailable(
                    "Python runtime exceeds the bounded image entry limit",
                ));
            }
            let path = entry.path();
            if !path.is_file()
                || !path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| {
                        value.eq_ignore_ascii_case("exe")
                            || value.eq_ignore_ascii_case("dll")
                            || value.eq_ignore_ascii_case("pyd")
                    })
            {
                continue;
            }
            let mut file = fs::File::open(&path)
                .map_err(|error| unavailable(format!("failed to inspect Python image: {error}")))?;
            let mut magic = [0u8; 2];
            file.read_exact(&mut magic)
                .map_err(|error| unavailable(format!("failed to inspect Python image: {error}")))?;
            if magic != *b"MZ" {
                return Err(unavailable(format!(
                    "Python runtime image is not PE: {}",
                    path.display()
                )));
            }
            images.push(canonical_file(&path, "Python runtime image")?);
        }
    }
    images.sort();
    images.dedup();
    Ok(())
}
