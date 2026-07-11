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

fn is_skipped_surface(path: &Path) -> bool {
    let path_str = path.to_string_lossy().replace("\\\\?\\", "");
    matches!(
        classify_file_role(&path_str),
        FileRole::Docs | FileRole::Generated | FileRole::Fixture
    )
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

pub(crate) fn should_keep_file(path: &Path, config: &ResolvedConfig) -> bool {
    !path_matches_ignored_component(path, &config.ignore)
        && !is_test_file(path)
        && !is_skipped_surface(path)
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
        assert!(should_keep_file(Path::new("src/llm.py"), &config));
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
