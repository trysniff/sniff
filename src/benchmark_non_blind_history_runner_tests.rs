use super::*;
#[cfg(windows)]
use crate::benchmark::HistoricalEvidenceKind;
use crate::benchmark::{HistoricalCloneOutcome, prepare_non_blind_history_assessment};
use std::cell::Cell;
use std::path::PathBuf;
use std::process::Command;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const WORKSHEET: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-history-assessment-protocol.json");

struct EmptyCloner {
    calls: Cell<usize>,
}

struct LocalRepositoryCloner {
    source: PathBuf,
}

impl HistoricalRepositoryCloner for LocalRepositoryCloner {
    fn clone_repository(
        &self,
        repository: &str,
        destination: &Path,
    ) -> Result<HistoricalCloneOutcome, String> {
        git_command(
            Path::new("."),
            &[
                "clone",
                "--no-checkout",
                "--no-tags",
                self.source.to_str().unwrap(),
                destination.to_str().unwrap(),
            ],
        )?;
        git_command(destination, &["remote", "set-head", "origin", "main"])?;
        git_command(
            destination,
            &["checkout", "--force", "--detach", "origin/HEAD"],
        )?;
        git_command(
            destination,
            &[
                "remote",
                "set-url",
                "origin",
                &format!("https://{repository}.git"),
            ],
        )?;
        Ok(HistoricalCloneOutcome::Complete)
    }
}

impl HistoricalRepositoryCloner for EmptyCloner {
    fn clone_repository(
        &self,
        _repository: &str,
        _destination: &Path,
    ) -> Result<HistoricalCloneOutcome, String> {
        self.calls.set(self.calls.get() + 1);
        Ok(HistoricalCloneOutcome::Empty)
    }
}

#[tokio::test]
async fn resumes_from_hash_verified_rank_transactions() {
    let root = tempfile::tempdir().unwrap();
    let template = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let client = Client::builder().build().unwrap();
    let cloner = EmptyCloner {
        calls: Cell::new(0),
    };

    let first = assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template.clone(),
        root.path(),
        &client,
        &cloner,
        Some(1),
        false,
    )
    .await
    .unwrap();
    assert_eq!(cloner.calls.get(), 1);
    assert_eq!(
        first.assessments[0].exclusion_reason,
        Some(crate::benchmark::HistoricalExclusionReason::EmptyRepository)
    );

    let second = assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template,
        root.path(),
        &client,
        &cloner,
        Some(1),
        false,
    )
    .await
    .unwrap();
    assert_eq!(cloner.calls.get(), 2);
    assert!(second.assessments[0].disposition.is_some());
    assert!(second.assessments[1].disposition.is_some());
    assert!(second.assessments[2].disposition.is_none());
}

#[tokio::test]
async fn recovers_publish_before_checkpoint_without_repeating_work() {
    let root = tempfile::tempdir().unwrap();
    let template = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let client = Client::builder().build().unwrap();
    let cloner = EmptyCloner {
        calls: Cell::new(0),
    };
    assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template.clone(),
        root.path(),
        &client,
        &cloner,
        Some(1),
        false,
    )
    .await
    .unwrap();
    fs::remove_file(root.path().join("checkpoints/rank-0001.json")).unwrap();

    let recovered = assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template,
        root.path(),
        &client,
        &cloner,
        Some(0),
        false,
    )
    .await
    .unwrap();
    assert_eq!(cloner.calls.get(), 1);
    assert!(recovered.assessments[0].disposition.is_some());
    assert!(root.path().join("checkpoints/rank-0001.json").is_file());
}

#[tokio::test]
async fn refuses_tampered_published_evidence() {
    let root = tempfile::tempdir().unwrap();
    let template = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let client = Client::builder().build().unwrap();
    let cloner = EmptyCloner {
        calls: Cell::new(0),
    };
    assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template.clone(),
        root.path(),
        &client,
        &cloner,
        Some(1),
        false,
    )
    .await
    .unwrap();
    fs::write(
        root.path().join("artifacts/rank-0001/repository-refs.json"),
        b"tampered\n",
    )
    .unwrap();

    let error = assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template,
        root.path(),
        &client,
        &cloner,
        Some(0),
        false,
    )
    .await
    .unwrap_err();
    assert!(error.contains("artifact inventory"));
    assert_eq!(cloner.calls.get(), 1);
}

#[tokio::test]
async fn seals_selected_history_or_typed_host_sandbox_unavailability() {
    let upstream = tempfile::tempdir().unwrap();
    initialize_rust_history(upstream.path());
    let state = tempfile::tempdir().unwrap();
    let template = prepare_non_blind_history_assessment(POLICY, WORKSHEET, PROTOCOL).unwrap();
    let client = Client::builder().build().unwrap();
    let cloner = LocalRepositoryCloner {
        source: upstream.path().to_path_buf(),
    };

    let result = assess_with_cloner(
        POLICY,
        WORKSHEET,
        PROTOCOL,
        template,
        state.path(),
        &client,
        &cloner,
        Some(1),
        false,
    )
    .await
    .unwrap();
    let assessment = &result.assessments[0];
    if assessment.disposition != Some(HistoricalAssessmentDisposition::Selected) {
        #[cfg(not(windows))]
        {
            let availability = assessment
                .evidence
                .iter()
                .filter_map(|entry| {
                    entry
                        .artifact_path
                        .ends_with("-availability.json")
                        .then(|| {
                            fs::read_to_string(state.path().join(&entry.artifact_path))
                                .unwrap_or_else(|error| format!("unreadable: {error}"))
                        })
                })
                .collect::<Vec<_>>();
            panic!(
                "non-Windows host did not select the trusted fixture: {assessment:#?}\navailability: {availability:#?}"
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(
                assessment.exclusion_reason,
                Some(crate::benchmark::HistoricalExclusionReason::SandboxUnavailable),
                "{assessment:#?}"
            );
            let facts = assessment.facts.as_ref().unwrap();
            assert_eq!(
                facts.test_outcome,
                Some(crate::benchmark::HistoricalTestOutcome::SandboxUnavailable)
            );
            assert!(facts.parent_test.is_none());
            let availability = assessment
                .evidence
                .iter()
                .find(|entry| entry.kind == HistoricalEvidenceKind::ParentTest)
                .expect("sandbox unavailability must retain parent-side evidence");
            assert!(
                availability
                    .artifact_path
                    .ends_with("parent-availability.json")
            );
            assert_eq!(availability.sha256.len(), 64);
            return;
        }
    }
    let parent_output =
        fs::read_to_string(state.path().join("artifacts/rank-0001/tests/parent.json"))
            .unwrap_or_default();
    assert_eq!(
        assessment.disposition,
        Some(HistoricalAssessmentDisposition::Selected),
        "{assessment:#?}\n{parent_output}"
    );
    let facts = assessment.facts.as_ref().unwrap();
    assert_eq!(
        facts.test_outcome,
        Some(crate::benchmark::HistoricalTestOutcome::Passed)
    );
    assert_eq!(facts.quota_language.as_deref(), Some("rust"));
    assert!(facts.parent_test.as_ref().unwrap().test_executed);
    assert!(facts.commit_test.as_ref().unwrap().test_executed);
    let provenance = assessment.selected_provenance.as_ref().unwrap();
    assert!(!provenance.before.is_empty());
    assert!(!provenance.after.is_empty());
    assert_eq!(provenance.behavioral_evidence.len(), 2);
}

fn initialize_rust_history(root: &Path) {
    git_command(root, &["init", "-b", "main"]).unwrap();
    git_command(root, &["config", "user.email", "fixture@example.test"]).unwrap();
    git_command(root, &["config", "user.name", "Fixture"]).unwrap();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"history_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("LICENSE"), "fixture license\n").unwrap();
    fs::write(root.join("src/lib.rs"), rust_fixture_source(false)).unwrap();
    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
    git_command(root, &["add", "."]).unwrap();
    git_command(root, &["commit", "-m", "initial"]).unwrap();
    fs::write(root.join("src/lib.rs"), rust_fixture_source(true)).unwrap();
    git_command(root, &["add", "src/lib.rs"]).unwrap();
    git_command(root, &["commit", "-m", "simplify fixture method"]).unwrap();
}

fn rust_fixture_source(simplified: bool) -> String {
    let mut source = String::new();
    for index in 0..20 {
        if index == 0 && simplified {
            source.push_str("pub fn method_0() -> usize { 0 }\n\n");
        } else {
            source.push_str(&format!(
                "pub fn method_{index}() -> usize {{\n    let value = {index};\n    value\n}}\n\n"
            ));
        }
    }
    source.push_str(
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn contract_holds() {\n        assert_eq!(super::method_0(), 0);\n    }\n}\n",
    );
    source
}

fn git_command(root: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}
