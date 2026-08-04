use crate::config::ResolvedConfig;
use crate::languages;
use crate::roles::{FileRole, classify_file_role};
use ignore::DirEntry;
use std::path::Path;

fn is_test_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let has_test_segment = path.components().any(|c| {
        c.as_os_str()
            .to_string_lossy()
            .to_lowercase()
            .starts_with("test")
    });

    name.starts_with("test_")
        || name.ends_with("_test.go")
        || name.contains(".test.")
        || name.contains(".spec.")
        || has_test_segment
}

fn is_supported_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .and_then(languages::get_adapter)
        .is_some()
}

fn is_gradle_kotlin_script(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".gradle.kts"))
}

fn is_test_only_rust_file(path: &Path) -> bool {
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return false;
    }

    let Ok(source) = std::fs::read_to_string(path) else {
        return false;
    };
    source.lines().map(str::trim).find(|line| !line.is_empty()) == Some("#![cfg(test)]")
}

fn is_skipped_surface(path: &Path) -> bool {
    let path_str = path.to_string_lossy().replace("\\\\?\\", "");
    matches!(
        classify_file_role(&path_str),
        FileRole::Docs | FileRole::Generated | FileRole::Fixture
    )
}

pub(crate) fn is_explicit_surface_root(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component
                .as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
            "test" | "tests" | "fixture" | "fixtures" | "gold_fixtures"
        )
    })
}

fn path_matches_ignored_component(path: &Path, ignored: &[String]) -> bool {
    ignored.iter().any(|ignored_name| {
        let ignored_name = ignored_name.to_lowercase();
        path.components()
            .any(|component| component.as_os_str().to_string_lossy().to_lowercase() == ignored_name)
    })
}

pub(crate) fn should_descend(entry: &DirEntry, ignored: &[String]) -> bool {
    !path_matches_ignored_component(entry.path(), ignored)
}

pub(crate) fn should_keep_file(
    path: &Path,
    config: &ResolvedConfig,
    include_surface_files: bool,
) -> bool {
    !path_matches_ignored_component(path, &config.ignore)
        && !is_gradle_kotlin_script(path)
        && (include_surface_files
            || (!is_test_file(path) && !is_test_only_rust_file(path) && !is_skipped_surface(path)))
        && is_supported_file(path)
}

pub(crate) fn should_keep_evidence_file(path: &Path, config: &ResolvedConfig) -> bool {
    !path_matches_ignored_component(path, &config.ignore)
        && !is_gradle_kotlin_script(path)
        && (is_test_file(path) || is_test_only_rust_file(path))
        && is_supported_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn root_compatibility_shims_are_still_scanned() {
        let config = ResolvedConfig::default();
        assert!(should_keep_file(Path::new("src/llm.py"), &config, false));
    }

    #[test]
    fn gradle_kotlin_dsl_scripts_are_not_treated_as_application_source() {
        let config = ResolvedConfig::default();
        assert!(!should_keep_file(
            Path::new("apps/android/host/app/build.gradle.kts"),
            &config,
            false
        ));
        assert!(should_keep_file(
            Path::new("apps/android/host/app/src/main/kotlin/App.kt"),
            &config,
            false
        ));
    }

    #[test]
    fn test_only_rust_modules_are_not_scanned_as_production_code() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sniff-test-only-{unique}.rs"));
        fs::write(&path, "#![cfg(test)]\nfn helper() {}\n").unwrap();

        assert!(!should_keep_file(&path, &ResolvedConfig::default(), false));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ignored_directory_names_match_case_insensitively() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-walker-case-test-{unique}"));
        let ignored_dir = root.join("NODE_MODULES");
        let src_dir = root.join("src");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::create_dir_all(&src_dir).unwrap();

        fs::write(
            ignored_dir.join("ignore.ts"),
            "export function ignored() {}\n",
        )
        .unwrap();
        fs::write(src_dir.join("keep.ts"), "export function kept() {}\n").unwrap();

        let files =
            crate::walker::walk(root.to_str().unwrap(), &ResolvedConfig::default()).unwrap();
        assert!(
            files.iter().any(|path| path.contains("keep.ts")),
            "expected visible file to remain visible: {files:?}"
        );
        assert!(
            !files.iter().any(|path| path.contains("NODE_MODULES")),
            "expected uppercase ignored directory to be pruned: {files:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
