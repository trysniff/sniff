use super::super::non_blind_history_runtime_support::{canonical_file, path_value};
use super::HistoricalRuntimePlanError;
use std::path::{Path, PathBuf};

pub(super) fn installation(
    java: &Path,
    home: &Path,
    args: &[String],
) -> Result<(Vec<String>, Vec<PathBuf>), HistoricalRuntimePlanError> {
    if !java
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("java.exe"))
    {
        return Err(HistoricalRuntimePlanError::Invalid(
            "selected Windows Gradle JVM must be native java.exe, not a batch launcher".to_string(),
        ));
    }
    let launcher = distribution_image(home, "gradle-launcher-8.8.jar")?;
    let agent = distribution_image(home, "agents/gradle-instrumentation-agent-8.8.jar")?;
    // Launch the selected distribution's entrypoint directly, not through a
    // second process created by cmd. There is no batch-launch retry path.
    let mut arguments = vec![
        "-Xmx64m".to_string(),
        "-Xms64m".to_string(),
        format!("-javaagent:{}", path_value(&agent)),
        "-Dorg.gradle.appname=gradle".to_string(),
        "-classpath".to_string(),
        path_value(&launcher),
        "org.gradle.launcher.GradleMain".to_string(),
    ];
    arguments.extend_from_slice(args);
    Ok((arguments, vec![launcher, agent]))
}

fn distribution_image(home: &Path, relative: &str) -> Result<PathBuf, HistoricalRuntimePlanError> {
    let image = canonical_file(
        &home.join("lib").join(relative),
        "selected Gradle 8.8 image",
    )?;
    if !image.starts_with(home) {
        return Err(HistoricalRuntimePlanError::Invalid(
            "Gradle launcher image escaped the selected distribution".to_string(),
        ));
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::super::super::non_blind_history_runtime_support::canonical_directory;
    use super::*;

    #[test]
    fn direct_launcher_preserves_exact_jvm_and_cli_arguments_and_images() {
        let root = tempfile::tempdir().unwrap();
        let home = canonical_directory(root.path(), "fixture Gradle distribution").unwrap();
        let lib = home.join("lib");
        std::fs::create_dir_all(lib.join("agents")).unwrap();
        for relative in [
            "gradle-launcher-8.8.jar",
            "agents/gradle-instrumentation-agent-8.8.jar",
        ] {
            std::fs::write(lib.join(relative), b"fixture image, not executable proof").unwrap();
        }
        let cli = vec![
            "--project-dir".to_string(),
            "a b".to_string(),
            "help".to_string(),
        ];
        let (arguments, images) = installation(Path::new("java.exe"), &home, &cli).unwrap();
        assert_eq!(images.len(), 2);
        assert!(images.iter().all(|image| image.starts_with(&home)));
        assert_eq!(arguments[0..2], ["-Xmx64m", "-Xms64m"]);
        assert_eq!(
            arguments[2],
            format!("-javaagent:{}", path_value(&images[1]))
        );
        assert_eq!(arguments[3], "-Dorg.gradle.appname=gradle");
        assert_eq!(arguments[4], "-classpath");
        assert_eq!(arguments[5], path_value(&images[0]));
        assert_eq!(arguments[6], "org.gradle.launcher.GradleMain");
        assert_eq!(arguments[7..], cli);
    }

    #[test]
    fn missing_pinned_images_fail_without_a_batch_or_version_fallback() {
        let root = tempfile::tempdir().unwrap();
        let home = canonical_directory(root.path(), "fixture Gradle distribution").unwrap();
        assert!(matches!(
            installation(Path::new("java.exe"), &home, &[]),
            Err(HistoricalRuntimePlanError::Unavailable(_))
        ));
        std::fs::create_dir(home.join("lib")).unwrap();
        std::fs::write(home.join("lib").join("gradle-launcher-8.8.jar"), b"fixture").unwrap();
        assert!(matches!(
            installation(Path::new("java.exe"), &home, &[]),
            Err(HistoricalRuntimePlanError::Unavailable(_))
        ));
    }

    #[test]
    fn selected_java_batch_shims_are_rejected_before_distribution_planning() {
        let root = tempfile::tempdir().unwrap();
        for name in ["java.cmd", "java.bat", "java"] {
            assert!(matches!(
                installation(Path::new(name), root.path(), &[]),
                Err(HistoricalRuntimePlanError::Invalid(_))
            ));
        }
    }
}
