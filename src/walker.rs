use crate::config::ResolvedConfig;
use ignore::WalkBuilder;
use std::path::Path;

#[path = "walker_filters.rs"]
mod filters;

fn walk_directory(
    root: &Path,
    config: &ResolvedConfig,
    file_paths: &mut Vec<String>,
) -> Result<(), String> {
    let ignored = config.ignore.clone();
    let mut builder = WalkBuilder::new(root);
    builder.standard_filters(true);
    builder.follow_links(false);
    builder.filter_entry(move |entry| filters::should_descend(entry, &ignored));

    for result in builder.build() {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() && filters::should_keep_file(path, config) {
                    file_paths.push(path.to_string_lossy().replace("\\\\?\\", ""));
                }
            }
            Err(err) => {
                return Err(format!("failed to read directory entry: {err}"));
            }
        }
    }

    Ok(())
}

pub fn walk(root_path: &str, config: &ResolvedConfig) -> Result<Vec<String>, String> {
    let mut file_paths = Vec::new();
    let root_buf = std::fs::canonicalize(root_path)
        .map_err(|err| format!("failed to resolve scan target {root_path}: {err}"))?;
    let root = root_buf.as_path();

    if !root.exists() {
        return Err(format!("scan target does not exist: {root_path}"));
    }

    if root.is_file() {
        if filters::should_keep_file(root, config) {
            file_paths.push(root.to_string_lossy().replace("\\\\?\\", ""));
        }
        return Ok(file_paths);
    }

    walk_directory(root, config, &mut file_paths)?;

    file_paths.sort();
    Ok(file_paths)
}

#[cfg(test)]
mod tests {
    use super::walk;
    use crate::config::ResolvedConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn ignored_directory_names_are_pruned_without_substring_overmatch() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-walker-test-{unique}"));
        let output_dir = root.join("output");
        let next_dir = root.join(".next");
        let src_dir = root.join("src");
        fs::create_dir_all(&output_dir).unwrap();
        fs::create_dir_all(&next_dir).unwrap();
        fs::create_dir_all(&src_dir).unwrap();

        fs::write(output_dir.join("main.ts"), "export function ignored() {}\n").unwrap();
        fs::write(next_dir.join("chunk.ts"), "export function ignored() {}\n").unwrap();
        fs::write(
            src_dir.join("output_parser.ts"),
            "export function kept() {}\n",
        )
        .unwrap();

        let files = walk(root.to_str().unwrap(), &ResolvedConfig::default()).unwrap();
        assert!(
            files.iter().any(|path| path.contains("output_parser.ts")),
            "expected non-ignored file to remain visible: {files:?}"
        );
        assert!(
            !files.iter().any(|path| path.contains("output\\main.ts")),
            "expected ignored output directory to be pruned: {files:?}"
        );
        assert!(
            !files.iter().any(|path| path.contains(".next\\chunk.ts")),
            "expected ignored .next directory to be pruned: {files:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gold_fixture_corpus_paths_are_pruned_from_walk_results() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-fixture-walk-{unique}"));
        let fixtures_dir = root.join("gold_fixtures").join("repo").join("go");
        fs::create_dir_all(&fixtures_dir).unwrap();
        fs::write(
            fixtures_dir.join("math.go"),
            "package main\n\nfunc ProcessData(values []string) []string { return values }\n",
        )
        .unwrap();

        let files = walk(root.to_str().unwrap(), &ResolvedConfig::default()).unwrap();
        assert!(
            files.is_empty(),
            "expected fixture corpus files to be skipped from walks: {files:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_scan_targets_return_an_error() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-missing-walk-{unique}"));

        let err = walk(root.to_str().unwrap(), &ResolvedConfig::default())
            .expect_err("missing scan target should fail explicitly");
        assert!(err.contains("failed to resolve scan target"), "{err}");
    }
}
