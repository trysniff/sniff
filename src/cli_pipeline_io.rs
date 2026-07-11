use crate::config::ResolvedConfig;
use crate::types::FileRecord;
use indicatif::{ProgressBar, ProgressStyle};

pub(super) async fn parse_files(file_paths: &[String]) -> Result<Vec<FileRecord>, String> {
    let pb_parse = ProgressBar::new(file_paths.len() as u64);
    let style = ProgressStyle::default_bar()
        .tick_chars("/|\\-")
        .template("{spinner:.cyan.bold} {msg} [{bar:30.cyan/dim}] {percent}% {elapsed}")
        .map_err(|err| err.to_string())?
        .progress_chars("=>-");
    pb_parse.set_style(style);
    pb_parse.set_message("Parsing...");

    let mut file_records = Vec::new();
    for fp in file_paths {
        let fp_clone = fp.clone();
        let record =
            match tokio::task::spawn_blocking(move || crate::parser::parse_file_checked(&fp_clone))
                .await
            {
                Ok(Ok(record)) => record,
                Ok(Err(err)) => {
                    pb_parse.finish_and_clear();
                    return Err(err);
                }
                Err(err) => {
                    pb_parse.finish_and_clear();
                    return Err(format!("parser task failed for {fp}: {err}"));
                }
            };
        if !record.language.is_empty() {
            file_records.push(record);
        }
        pb_parse.inc(1);
    }
    pb_parse.finish_and_clear();
    Ok(file_records)
}

pub(super) async fn scan_files(
    path: &str,
    config: &ResolvedConfig,
) -> Result<Vec<FileRecord>, String> {
    let file_paths = crate::walker::walk(path, config)?;
    if file_paths.is_empty() {
        return Ok(Vec::new());
    }

    parse_files(&file_paths).await
}

#[cfg(test)]
mod tests {
    use super::scan_files;
    use crate::config::ResolvedConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn unsupported_files_are_dropped_from_scan_results() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-scan-filter-{nanos}"));
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("note.txt"), "plain text\n").unwrap();
        fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

        let files = scan_files(root.to_str().unwrap(), &ResolvedConfig::default())
            .await
            .expect("scan should complete");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, "rust");
        assert!(files[0].file_path.ends_with("main.rs"));

        let _ = fs::remove_dir_all(&root);
    }
}
