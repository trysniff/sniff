use std::ffi::OsStr;
use std::fs;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

pub(super) fn resolve_java_runtime() -> Result<PathBuf, String> {
    let Some(java_home) = std::env::var_os("JAVA_HOME") else {
        return super::resolve_runtime("java");
    };
    resolve_java_home_runtime(&java_home)
}

pub(super) fn resolve_java_home_runtime(java_home: &OsStr) -> Result<PathBuf, String> {
    if java_home.is_empty() {
        return Err("JAVA_HOME is set but empty; refusing PATH-based Java resolution".to_string());
    }
    let candidate =
        PathBuf::from(java_home)
            .join("bin")
            .join(if cfg!(windows) { "java.exe" } else { "java" });
    if !candidate.is_file() {
        return Err(format!(
            "JAVA_HOME does not contain the required Java runtime {}; refusing PATH-based Java resolution",
            candidate.display()
        ));
    }
    fs::canonicalize(&candidate).map_err(|error| {
        format!(
            "failed to resolve JAVA_HOME runtime {}: {error}",
            candidate.display()
        )
    })
}

#[cfg(windows)]
pub(super) fn system_gradle_launcher_jar(gradle: &Path) -> Result<PathBuf, String> {
    let home = gradle.parent().and_then(Path::parent).ok_or_else(|| {
        format!(
            "system Gradle has no installation root: {}",
            gradle.display()
        )
    })?;
    let lib = home.join("lib");
    let mut candidates = fs::read_dir(&lib)
        .map_err(|error| {
            format!(
                "failed to inspect system Gradle libraries at {}: {error}",
                lib.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            path.is_file()
                && name.ends_with(".jar")
                && (name.starts_with("gradle-gradle-cli-main-")
                    || name.starts_with("gradle-launcher-"))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    let mut providers = Vec::new();
    for candidate in candidates {
        let input = fs::File::open(&candidate).map_err(|error| {
            format!(
                "failed to open system Gradle runtime {}: {error}",
                candidate.display()
            )
        })?;
        let archive = zip::ZipArchive::new(input).map_err(|error| {
            format!(
                "failed to inspect system Gradle runtime {}: {error}",
                candidate.display()
            )
        })?;
        if archive
            .file_names()
            .any(|name| name == "org/gradle/launcher/GradleMain.class")
        {
            providers.push(candidate);
        }
    }
    match providers.as_slice() {
        [provider] => Ok(provider.clone()),
        [] => Err(format!(
            "system Gradle at {} has no runtime jar providing org.gradle.launcher.GradleMain in {}",
            gradle.display(),
            lib.display()
        )),
        _ => Err(format!(
            "system Gradle at {} has multiple runtime jars providing org.gradle.launcher.GradleMain in {}; refusing an ambiguous runtime",
            gradle.display(),
            lib.display()
        )),
    }
}
