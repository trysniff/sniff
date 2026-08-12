use crate::benchmark::{BenchmarkCorpus, BenchmarkSubmission, evaluate_release};
use std::fs;
use std::io::{Error as IoError, ErrorKind};
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
    use super::benchmark;
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
}
