use crate::benchmark::{BenchmarkCorpus, BenchmarkSubmission, evaluate_release, freeze_corpus};
use std::fs;
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::Path;

/// Evaluate a complete external benchmark ledger without loading configuration
/// or contacting an LLM provider.
pub(crate) fn benchmark(
    cases_path: &str,
    predictions_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(cases_path)?;
    let submission = read_json::<BenchmarkSubmission>(predictions_path)?;
    let corpus_root = Path::new(cases_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let metrics = evaluate_release(&corpus, &submission, corpus_root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark ledger is invalid: {error}"),
        )
    })?;
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    match metrics.assert_release_gate() {
        Ok(()) => {
            eprintln!("SniffBench release gate passed.");
            Ok(0)
        }
        Err(error) => {
            eprintln!("SniffBench release gate failed: {error}");
            Ok(1)
        }
    }
}

pub(crate) fn freeze_benchmark(
    draft_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let draft = read_json::<BenchmarkCorpus>(draft_path)?;
    let corpus_root = Path::new(draft_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let frozen = freeze_corpus(draft, corpus_root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark corpus cannot be frozen: {error}"),
        )
    })?;
    let bytes = serde_json::to_vec_pretty(&frozen)?;
    write_new_file(Path::new(output_path), &bytes)?;
    eprintln!(
        "Frozen SniffBench corpus written to {output_path}\nSource commitment: {}\nLabel commitment: {}",
        frozen.source_commitment_sha256, frozen.label_commitment_sha256
    );
    Ok(0)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), IoError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            IoError::new(
                error.kind(),
                format!(
                    "failed to create frozen benchmark file {}: {error}",
                    path.display()
                ),
            )
        })?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_json<T>(path: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let text = fs::read_to_string(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read benchmark file {path}: {error}"),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("failed to parse benchmark JSON {path}: {error}"),
        )
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::{benchmark, write_new_file};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sniff-benchmark-cli-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn legacy_arrays_are_rejected_as_release_proof() {
        let cases = temp_path("cases");
        let predictions = temp_path("predictions");
        fs::write(
            &cases,
            r#"[{"case_id":"clean-1","language":"python","expected_tier":"clean","expected_pattern":"none"}]"#,
        )
        .expect("write benchmark cases");
        fs::write(
            &predictions,
            r#"[{"case_id":"clean-1","tier":"clean","pattern":"none","evidence_valid":false}]"#,
        )
        .expect("write benchmark predictions");

        let error = benchmark(
            cases.to_str().expect("cases path should be UTF-8"),
            predictions
                .to_str()
                .expect("predictions path should be UTF-8"),
        )
        .expect_err("legacy arrays must not be accepted as release proof");
        assert!(error.to_string().contains("failed to parse benchmark JSON"));
        let _ = fs::remove_file(cases);
        let _ = fs::remove_file(predictions);
    }

    #[test]
    fn malformed_ledger_fails_before_metrics_are_emitted() {
        let cases = temp_path("invalid-cases");
        let predictions = temp_path("invalid-predictions");
        fs::write(&cases, "not json").expect("write invalid cases");
        fs::write(&predictions, "[]").expect("write predictions");

        assert!(
            benchmark(
                cases.to_str().expect("cases path should be UTF-8"),
                predictions
                    .to_str()
                    .expect("predictions path should be UTF-8")
            )
            .is_err()
        );
        let _ = fs::remove_file(cases);
        let _ = fs::remove_file(predictions);
    }

    #[test]
    fn frozen_manifest_writer_never_overwrites_an_existing_file() {
        let output = temp_path("existing-frozen");
        fs::write(&output, "existing").expect("write existing output");

        let error = write_new_file(&output, b"replacement").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&output).unwrap(), "existing");
        let _ = fs::remove_file(output);
    }
}
