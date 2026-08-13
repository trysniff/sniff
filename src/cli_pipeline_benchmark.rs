use crate::benchmark::{BenchmarkCorpus, BenchmarkSubmission, evaluate_release, freeze_corpus};
use crate::benchmark::{
    BenchmarkSourceSeal, LabelReviewWorksheet, SourceSelectionDraft, audit_label_reviews,
    create_source_seal, prepare_label_review, validate_source_seal,
};
use crate::benchmark_import::{BenchmarkRunReview, import_reviewed_run, prepare_run_review};
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

pub(crate) fn seal_benchmark_sources(
    draft_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let draft = read_json::<SourceSelectionDraft>(draft_path)?;
    let draft_root = Path::new(draft_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let seal = create_source_seal(draft, draft_root, Path::new(output_path)).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark sources cannot be sealed: {error}"),
        )
    })?;
    eprintln!(
        "Label-free SniffBench source seal written to {output_path}\nSources: {}\nEligible methods: {}\nSeal commitment: {}",
        seal.sources.len(),
        seal.methods.len(),
        seal.seal_sha256
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_labels(
    seal_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let seal_root = Path::new(seal_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let worksheet =
        prepare_label_review(&seal, seal_root, &sha256(&seal_bytes)).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark labels cannot be prepared: {error}"),
            )
        })?;
    write_new_file(
        Path::new(output_path),
        &serde_json::to_vec_pretty(&worksheet)?,
    )?;
    eprintln!(
        "Source-only SniffBench label worksheet written to {output_path}. Methods: {}. Complete it independently without Sniff output.",
        worksheet.methods.len()
    );
    Ok(0)
}

pub(crate) fn audit_benchmark_labels(
    seal_path: &str,
    output_path: &str,
    review_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let (seal, seal_bytes) = read_source_seal(seal_path)?;
    let seal_root = Path::new(seal_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let reviews = review_paths
        .iter()
        .map(|path| read_json::<LabelReviewWorksheet>(path))
        .collect::<Result<Vec<_>, _>>()?;
    let audit =
        audit_label_reviews(&seal, seal_root, &sha256(&seal_bytes), &reviews).map_err(|error| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("benchmark label worksheets cannot be audited: {error}"),
            )
        })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&audit)?)?;
    eprintln!(
        "Verified SniffBench label audit written to {output_path}. Agreements: {}. Disputes requiring resolution: {}.",
        audit.agreement_count, audit.disputed_count
    );
    Ok(0)
}

pub(crate) fn prepare_benchmark_run(
    corpus_path: &str,
    output_path: &str,
    artifact_paths: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(corpus_path)?;
    let corpus_root = Path::new(corpus_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let artifacts = artifact_paths
        .iter()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    let review = prepare_run_review(&corpus, corpus_root, &artifacts).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark run cannot be prepared: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&review)?)?;
    eprintln!(
        "Label-blind SniffBench review worksheet written to {output_path}. Complete only reviews, actual cost provenance, and wall-clock time."
    );
    Ok(0)
}

pub(crate) fn import_benchmark_run(
    corpus_path: &str,
    review_path: &str,
    output_path: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    let corpus = read_json::<BenchmarkCorpus>(corpus_path)?;
    let review = read_json::<BenchmarkRunReview>(review_path)?;
    let corpus_root = Path::new(corpus_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let run = import_reviewed_run(&corpus, corpus_root, &review).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark run cannot be imported: {error}"),
        )
    })?;
    write_new_file(Path::new(output_path), &serde_json::to_vec_pretty(&run)?)?;
    eprintln!("Verified SniffBench run written to {output_path}.");
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

fn read_source_seal(
    path: &str,
) -> Result<(BenchmarkSourceSeal, Vec<u8>), Box<dyn std::error::Error>> {
    let bytes = fs::read(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read benchmark source seal {path}: {error}"),
        )
    })?;
    let seal = serde_json::from_slice::<BenchmarkSourceSeal>(&bytes).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("failed to parse benchmark source seal {path}: {error}"),
        )
    })?;
    let root = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    validate_source_seal(&seal, root).map_err(|error| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("benchmark source seal is invalid: {error}"),
        )
    })?;
    Ok((seal, bytes))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{benchmark, seal_benchmark_sources, write_new_file};
    use crate::benchmark::{
        SOURCE_SEAL_SCHEMA_VERSION, SourceRepositoryDraft, SourceSelectionDraft,
    };
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

    #[test]
    fn source_sealing_is_an_offline_create_new_workflow() {
        let bundle = temp_path("source-seal-bundle");
        let repository = bundle.join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(
            repository.join("src/lib.rs"),
            "pub fn sealed() -> i32 { 1 }\n",
        )
        .unwrap();
        fs::write(repository.join("LICENSE"), "test license\n").unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        git(&["init"]);
        git(&["config", "user.email", "seal@example.test"]);
        git(&["config", "user.name", "Seal Test"]);
        git(&["add", "."]);
        git(&["commit", "-m", "fixture"]);
        let revision = git(&["rev-parse", "HEAD"]);
        let draft = SourceSelectionDraft {
            schema_version: SOURCE_SEAL_SCHEMA_VERSION,
            selection_id: "offline-seal".to_string(),
            selected_at: "2026-08-12T00:00:00Z".to_string(),
            selection_methodology: "Selected before labels and tool output.".to_string(),
            selection_attestation: "No provider was used during source selection.".to_string(),
            repositories: vec![SourceRepositoryDraft {
                repository: "https://example.test/offline".to_string(),
                revision,
                local_path: repository.to_string_lossy().into_owned(),
                license_path: "LICENSE".to_string(),
                context_paths: Vec::new(),
            }],
        };
        let draft_path = bundle.join("selection.json");
        let output_path = bundle.join("seal.json");
        fs::write(&draft_path, serde_json::to_vec_pretty(&draft).unwrap()).unwrap();

        let code =
            seal_benchmark_sources(draft_path.to_str().unwrap(), output_path.to_str().unwrap())
                .unwrap();

        assert_eq!(code, 0);
        assert!(output_path.is_file());
        assert!(
            bundle
                .join("seal.sources/repository-0/source/src/lib.rs")
                .is_file()
        );
        let error =
            seal_benchmark_sources(draft_path.to_str().unwrap(), output_path.to_str().unwrap())
                .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        let _ = fs::remove_dir_all(bundle);
    }
}
