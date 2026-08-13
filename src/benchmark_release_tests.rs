use super::*;
use std::fs;
use tempfile::TempDir;

fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn snapshot(root: &Path, artifact_path: &str, repository_path: &str, text: &str) -> SourceSnapshot {
    let path = root.join(artifact_path);
    fs::create_dir_all(path.parent().expect("artifact parent")).expect("create artifact dir");
    fs::write(&path, text).expect("write benchmark artifact");
    SourceSnapshot {
        repository: "https://example.test/repo".to_string(),
        revision: "0123456789abcdef".to_string(),
        repository_path: repository_path.to_string(),
        artifact_path: artifact_path.to_string(),
        sha256: digest(text),
    }
}

fn corpus() -> (TempDir, BenchmarkCorpus) {
    let root = TempDir::new().expect("temp corpus");
    let definitions = [
        (
            "python",
            BenchmarkPartition::SyntheticGold,
            FindingTier::Slop,
            "ceremonial_logic",
            false,
        ),
        (
            "javascript",
            BenchmarkPartition::HistoricalSimplification,
            FindingTier::Slop,
            "residual_machinery",
            false,
        ),
        (
            "typescript",
            BenchmarkPartition::ResearchTrajectory,
            FindingTier::Slop,
            "duplicated_semantics",
            false,
        ),
        (
            "kotlin",
            BenchmarkPartition::IntentionalBoundary,
            FindingTier::Clean,
            "none",
            true,
        ),
        (
            "rust",
            BenchmarkPartition::BlindOss,
            FindingTier::Slop,
            "needless_indirection",
            false,
        ),
        (
            "go",
            BenchmarkPartition::BlindOss,
            FindingTier::Slop,
            "band_aid_control_flow",
            false,
        ),
        (
            "python",
            BenchmarkPartition::BlindOss,
            FindingTier::Clean,
            "none",
            false,
        ),
        (
            "javascript",
            BenchmarkPartition::BlindOss,
            FindingTier::Clean,
            "none",
            false,
        ),
        (
            "typescript",
            BenchmarkPartition::BlindOss,
            FindingTier::Clean,
            "none",
            false,
        ),
        (
            "kotlin",
            BenchmarkPartition::BlindOss,
            FindingTier::Clean,
            "none",
            false,
        ),
    ];
    let mut cases = Vec::new();
    for (index, (language, partition, tier, pattern, intentional_boundary)) in
        definitions.into_iter().enumerate()
    {
        let case_id = format!("case-{index}-{language}");
        let (extension, before_text) = match language {
            "rust" => ("rs", format!("fn blind_{index}() -> i32 {{ 1 }}\n")),
            "go" => (
                "go",
                format!("package demo\nfunc Blind{index}() int {{ return 1 }}\n"),
            ),
            "python" if partition == BenchmarkPartition::BlindOss => {
                ("py", format!("def blind_{index}():\n    return 1\n"))
            }
            "javascript" if partition == BenchmarkPartition::BlindOss => {
                ("js", format!("function blind{index}() {{ return 1; }}\n"))
            }
            "typescript" if partition == BenchmarkPartition::BlindOss => (
                "ts",
                format!("function blind{index}(): number {{ return 1; }}\n"),
            ),
            "kotlin" if partition == BenchmarkPartition::BlindOss => {
                ("kt", format!("fun blind{index}(): Int = 1\n"))
            }
            _ => (
                "txt",
                format!("line one\nunnecessary_{index}\nline three\n"),
            ),
        };
        let after_text = "line one\nline three\n";
        let before = snapshot(
            root.path(),
            &format!("before/{index}-{language}.{extension}"),
            &format!("src/{language}.{extension}"),
            &before_text,
        );
        let after = if is_finding(tier) {
            vec![snapshot(
                root.path(),
                &format!("after/{index}-{language}.txt"),
                &format!("src/{language}.txt"),
                after_text,
            )]
        } else {
            Vec::new()
        };
        let adjudications = if partition == BenchmarkPartition::SyntheticGold {
            Vec::new()
        } else {
            vec![BenchmarkAdjudication {
                reviewer_id: format!("reviewer-{index}-{language}"),
                years_experience: 7,
                tier,
                pattern: pattern.to_string(),
                rationale: "The before and after snapshots establish the intended label."
                    .to_string(),
                maintainer: language == "rust",
            }]
        };
        cases.push(ReleaseBenchmarkCase {
            label: BenchmarkCase {
                case_id,
                language: language.to_string(),
                expected_tier: tier,
                expected_pattern: pattern.to_string(),
                intentional_boundary,
            },
            partition,
            before: vec![before],
            after,
            human_explanation: "The case has an independently documented repository intent."
                .to_string(),
            behavioral_evidence: if is_finding(tier) {
                vec!["The after revision preserves the observed behavior.".to_string()]
            } else {
                Vec::new()
            },
            expected_proof_level: if is_finding(tier) { 1 } else { 0 },
            covered_method_ids: Vec::new(),
            adjudications,
            disputed: false,
            dispute_resolution: None,
        });
    }
    let blind_sources = cases
        .iter()
        .filter(|case| case.partition == BenchmarkPartition::BlindOss)
        .flat_map(|case| case.before.clone())
        .collect::<Vec<_>>();
    let (source_seal_artifact_path, source_seal_sha256, methods_by_artifact) =
        source_seal::write_test_source_seal(root.path(), &blind_sources);
    for case in &mut cases {
        if case.partition == BenchmarkPartition::BlindOss {
            case.covered_method_ids = methods_by_artifact[&case.before[0].artifact_path].clone();
        }
    }
    let mut corpus = BenchmarkCorpus {
        schema_version: RELEASE_SCHEMA_VERSION,
        corpus_id: "frozen-corpus-v1".to_string(),
        frozen_at: "2026-08-12T00:00:00Z".to_string(),
        source_commitment_sha256: "0".repeat(64),
        label_commitment_sha256: "0".repeat(64),
        source_seal_artifact_path,
        source_seal_sha256,
        analysis_sources: cases.iter().flat_map(|case| case.before.clone()).collect(),
        cases,
    };
    corpus.source_commitment_sha256 = corpus
        .computed_source_commitment_sha256()
        .expect("compute source commitment");
    corpus.label_commitment_sha256 = corpus
        .computed_label_commitment_sha256()
        .expect("compute commitment");
    fs::create_dir_all(root.path().join("baselines")).expect("create baseline dir");
    fs::write(
        root.path().join("baselines/raw.json"),
        "raw baseline output\n",
    )
    .expect("write baseline output");
    fs::create_dir_all(root.path().join("costs")).expect("create cost evidence dir");
    for index in 1..=3 {
        let raw_path = format!("costs/raw-{index}.json");
        let raw = format!("{{\"run\":{index},\"cost_usd\":0.5}}\n");
        fs::write(root.path().join(&raw_path), &raw).expect("write raw cost evidence");
        let receipt = ActualCostReceipt {
            schema_version: 1,
            provider: "provider".to_string(),
            model: "model".to_string(),
            currency: "USD".to_string(),
            actual_cost_microusd: 500_000,
            provenance: format!("provider invoice run {index}"),
            raw_evidence_artifact_path: raw_path,
            raw_evidence_sha256: digest(&raw),
        };
        fs::write(
            root.path().join(format!("costs/receipt-{index}.json")),
            serde_json::to_vec_pretty(&receipt).expect("serialize cost receipt"),
        )
        .expect("write cost receipt");
    }
    (root, corpus)
}

fn submission(corpus: &BenchmarkCorpus, root: &std::path::Path) -> BenchmarkSubmission {
    let predictions = corpus
        .cases
        .iter()
        .map(|case| {
            let finding = is_finding(case.label.expected_tier);
            BenchmarkRunPrediction {
                prediction_id: format!("prediction-{}", case.label.case_id),
                finding_fingerprint: finding.then(|| format!("fingerprint-{}", case.label.case_id)),
                matched_case_id: Some(case.label.case_id.clone()),
                tier: case.label.expected_tier,
                pattern: case.label.expected_pattern.clone(),
                evidence: if finding {
                    let snapshot = &case.before[0];
                    let source = fs::read_to_string(root.join(&snapshot.artifact_path)).unwrap();
                    let (line_index, quote) = source
                        .lines()
                        .enumerate()
                        .find(|(_, line)| !line.trim().is_empty())
                        .map(|(index, line)| (index + 1, line.trim().to_string()))
                        .unwrap();
                    vec![BenchmarkEvidence {
                        artifact_path: snapshot.artifact_path.clone(),
                        source_sha256: snapshot.sha256.clone(),
                        start_line: line_index,
                        end_line: line_index,
                        quote,
                    }]
                } else {
                    Vec::new()
                },
                proof_level: if finding { 1 } else { 0 },
                reviewer_disposition: if finding {
                    ReviewerDisposition::Accepted
                } else {
                    ReviewerDisposition::Unreviewed
                },
                reviewer_minutes: if finding { 1.0 } else { 0.0 },
            }
        })
        .collect::<Vec<_>>();
    let runs = (1..=3)
        .map(|index| {
            let receipt_path = format!("costs/receipt-{index}.json");
            let receipt_hash =
                digest(&fs::read_to_string(root.join(&receipt_path)).expect("read cost receipt"));
            BenchmarkRun {
                run_id: format!("run-{index}"),
                tool_version: "1.0.0".to_string(),
                source_revision: "abcdef".to_string(),
                provider: "provider".to_string(),
                model: "model".to_string(),
                prompt_contract_version: "v1".to_string(),
                source_commitment_sha256: corpus.source_commitment_sha256.clone(),
                label_commitment_sha256: corpus.label_commitment_sha256.clone(),
                completed_artifact_ids: vec![digest(&format!("artifact-{index}"))],
                execution_commitments_sha256: vec![digest(&format!("execution-{index}"))],
                cross_scan_reused_units: 0,
                analyzed_method_count: 1000,
                covered_case_ids: corpus
                    .cases
                    .iter()
                    .map(|case| case.label.case_id.clone())
                    .collect(),
                predictions: predictions.clone(),
                usage: BenchmarkUsage {
                    input_tokens: 100_000,
                    cached_input_tokens: 25_000,
                    output_tokens: 20_000,
                    actual_cost_microusd: 500_000,
                },
                actual_cost_provenance: format!("provider invoice run {index}"),
                actual_cost_artifact_path: receipt_path,
                actual_cost_artifact_sha256: receipt_hash,
                blind_reviewer: BlindReviewer {
                    reviewer_id: format!("reviewer-{index}"),
                    years_experience: 8,
                    affiliation: "Independent evaluator".to_string(),
                    independent_from_sniff: true,
                    labels_hidden_during_review: true,
                    attestation:
                        "I reviewed these outcomes independently without access to hidden labels."
                            .to_string(),
                },
                wall_clock_seconds: 60.0,
            }
        })
        .collect();
    BenchmarkSubmission {
        schema_version: RELEASE_SCHEMA_VERSION,
        corpus_id: corpus.corpus_id.clone(),
        runs,
        baselines: REQUIRED_BASELINES
            .iter()
            .map(|tool_id| BenchmarkBaseline {
                tool_id: (*tool_id).to_string(),
                tool_version: "test-version".to_string(),
                run_id: format!("baseline-{tool_id}"),
                corpus_id: corpus.corpus_id.clone(),
                source_commitment_sha256: corpus.source_commitment_sha256.clone(),
                label_commitment_sha256: corpus.label_commitment_sha256.clone(),
                raw_output_artifact_path: "baselines/raw.json".to_string(),
                raw_output_sha256: digest("raw baseline output\n"),
                covered_case_ids: corpus
                    .cases
                    .iter()
                    .map(|case| case.label.case_id.clone())
                    .collect(),
                findings: vec![BenchmarkBaselineFinding {
                    finding_id: format!("{tool_id}-rejected"),
                    matched_case_id: None,
                    reviewer_disposition: ReviewerDisposition::Rejected,
                    reviewer_minutes: 10.0,
                }],
            })
            .collect(),
    }
}

#[test]
fn complete_release_submission_passes_every_offline_gate() {
    let (root, corpus) = corpus();
    let submission = submission(&corpus, root.path());

    let metrics = evaluate_release(&corpus, &submission, root.path()).expect("evaluate");

    assert!(metrics.release_gate_errors.is_empty());
    assert_eq!(metrics.run_count, 3);
    assert_eq!(metrics.verdict_repeatability, 1.0);
    assert_eq!(metrics.overall_evidence_validity, 1.0);
    assert_eq!(metrics.cost_usd_per_1000_methods, 0.5);
    assert_eq!(metrics.by_partition.len(), 5);
}

#[test]
fn blind_corpus_rejects_tampered_or_incomplete_source_seals() {
    let (root, corpus) = corpus();
    let seal_path = root.path().join(&corpus.source_seal_artifact_path);
    let original = fs::read(&seal_path).unwrap();
    fs::write(&seal_path, b"tampered seal\n").unwrap();

    let error = validate_frozen_corpus(&corpus, root.path()).unwrap_err();

    assert!(error.contains("source-seal artifact hash mismatch"));
    fs::write(&seal_path, original).unwrap();

    let mut seal: BenchmarkSourceSeal =
        serde_json::from_slice(&fs::read(&seal_path).unwrap()).unwrap();
    seal.methods.pop();
    seal.seal_sha256 = seal.computed_seal_sha256().unwrap();
    let mut bytes = serde_json::to_vec_pretty(&seal).unwrap();
    bytes.push(b'\n');
    fs::write(&seal_path, &bytes).unwrap();
    let mut incomplete = corpus.clone();
    incomplete.source_seal_sha256 = digest(&String::from_utf8(bytes).unwrap());
    incomplete.source_commitment_sha256 = incomplete.computed_source_commitment_sha256().unwrap();

    let error = validate_frozen_corpus(&incomplete, root.path()).unwrap_err();

    assert!(error.contains("eligible-method census does not match"));
}

#[test]
fn blind_corpus_requires_every_sealed_method_exactly_once() {
    let (root, corpus) = corpus();
    let blind_index = corpus
        .cases
        .iter()
        .position(|case| case.partition == BenchmarkPartition::BlindOss)
        .unwrap();
    let method_id = corpus.cases[blind_index].covered_method_ids[0].clone();
    let mut omitted = corpus.clone();
    omitted.cases[blind_index].covered_method_ids.clear();
    omitted.label_commitment_sha256 = omitted.computed_label_commitment_sha256().unwrap();

    let error = validate_frozen_corpus(&omitted, root.path()).unwrap_err();

    assert!(error.contains("does not identify any sealed method"));

    let mut duplicated = corpus.clone();
    duplicated.cases[blind_index]
        .covered_method_ids
        .push(method_id);
    duplicated.label_commitment_sha256 = duplicated.computed_label_commitment_sha256().unwrap();

    let error = validate_frozen_corpus(&duplicated, root.path()).unwrap_err();

    assert!(error.contains("assigned to more than one case"));
}

#[test]
fn release_submission_rejects_label_adjudicator_as_blind_reviewer() {
    let (root, corpus) = corpus();
    let mut submission = submission(&corpus, root.path());
    submission.runs[0].blind_reviewer.reviewer_id =
        corpus.cases[1].adjudications[0].reviewer_id.clone();

    let error = evaluate_release(&corpus, &submission, root.path()).unwrap_err();

    assert!(error.contains("also adjudicated a frozen corpus label"));
}

#[test]
fn freeze_computes_both_commitments_and_validates_snapshots() {
    let (root, mut draft) = corpus();
    draft.source_commitment_sha256.clear();
    draft.label_commitment_sha256.clear();

    let frozen = freeze_corpus(draft, root.path()).expect("freeze corpus");

    assert_eq!(frozen.source_commitment_sha256.len(), 64);
    assert_eq!(frozen.label_commitment_sha256.len(), 64);
    assert_ne!(
        frozen.source_commitment_sha256,
        frozen.label_commitment_sha256
    );
}

#[test]
fn release_corpus_rejects_tampered_labels_and_source_artifacts() {
    let (root, mut tampered_corpus) = corpus();
    let valid_submission = submission(&tampered_corpus, root.path());
    tampered_corpus.cases[0].expected_proof_level = 2;
    let error = evaluate_release(&tampered_corpus, &valid_submission, root.path()).unwrap_err();
    assert!(error.contains("label commitment"));

    let (root, source_corpus) = corpus();
    let valid_submission = submission(&source_corpus, root.path());
    fs::write(
        root.path()
            .join(&source_corpus.cases[0].before[0].artifact_path),
        "tampered",
    )
    .expect("tamper artifact");
    let error = evaluate_release(&source_corpus, &valid_submission, root.path()).unwrap_err();
    assert!(error.contains("hash mismatch"));
}

#[test]
fn release_submission_is_bound_to_sources_and_raw_baseline_outputs() {
    let (root, corpus) = corpus();
    let mut source_mismatch = submission(&corpus, root.path());
    source_mismatch.runs[0].source_commitment_sha256 = "b".repeat(64);
    let error = evaluate_release(&corpus, &source_mismatch, root.path()).unwrap_err();
    assert!(error.contains("frozen source corpus"));

    let valid_submission = submission(&corpus, root.path());
    fs::write(
        root.path().join("baselines/raw.json"),
        "tampered baseline output\n",
    )
    .expect("tamper baseline output");
    let error = evaluate_release(&corpus, &valid_submission, root.path()).unwrap_err();
    assert!(error.contains("baseline raw output") && error.contains("hash mismatch"));
}

#[test]
fn release_submission_rejects_incomplete_coverage() {
    let (root, corpus) = corpus();
    let mut submission = submission(&corpus, root.path());
    submission.runs[0].predictions.pop();

    let error = evaluate_release(&corpus, &submission, root.path()).unwrap_err();

    assert!(error.contains("omitted case-level outcomes"));
}

#[test]
fn unmatched_and_invalid_evidence_findings_fail_the_release_gate() {
    let (root, corpus) = corpus();
    let mut submission = submission(&corpus, root.path());
    for run in &mut submission.runs {
        run.predictions.push(BenchmarkRunPrediction {
            prediction_id: format!("unmatched-{}", run.run_id),
            finding_fingerprint: Some(format!("unmatched-fingerprint-{}", run.run_id)),
            matched_case_id: None,
            tier: FindingTier::Slop,
            pattern: "ceremonial_logic".to_string(),
            evidence: vec![BenchmarkEvidence {
                artifact_path: corpus.cases[0].before[0].artifact_path.clone(),
                source_sha256: corpus.cases[0].before[0].sha256.clone(),
                start_line: 2,
                end_line: 2,
                quote: "not present".to_string(),
            }],
            proof_level: 1,
            reviewer_disposition: ReviewerDisposition::Rejected,
            reviewer_minutes: 1.0,
        });
    }

    let metrics = evaluate_release(&corpus, &submission, root.path()).expect("evaluate");

    assert_eq!(metrics.unmatched_findings, 3);
    assert!(metrics.overall_evidence_validity < 1.0);
    assert!(metrics.release_gate_errors.iter().any(|error| {
        error.contains("including unmatched findings") || error.contains("every emitted finding")
    }));
}

#[test]
fn repeatability_includes_unmatched_findings() {
    let (root, corpus) = corpus();
    let mut submission = submission(&corpus, root.path());
    let snapshot = &corpus.cases[0].before[0];
    for index in 0..2 {
        submission.runs[0].predictions.push(BenchmarkRunPrediction {
            prediction_id: format!("unstable-extra-{index}"),
            finding_fingerprint: Some(format!("unstable-fingerprint-{index}")),
            matched_case_id: None,
            tier: FindingTier::KindaSlop,
            pattern: "ceremonial_logic".to_string(),
            evidence: vec![BenchmarkEvidence {
                artifact_path: snapshot.artifact_path.clone(),
                source_sha256: snapshot.sha256.clone(),
                start_line: 2,
                end_line: 2,
                quote: "unnecessary_0".to_string(),
            }],
            proof_level: 1,
            reviewer_disposition: ReviewerDisposition::Rejected,
            reviewer_minutes: 1.0,
        });
    }

    let metrics = evaluate_release(&corpus, &submission, root.path()).expect("evaluate");

    assert!(metrics.verdict_repeatability < 0.90);
    assert!(
        metrics
            .release_gate_errors
            .iter()
            .any(|error| error.contains("repeatability"))
    );
}

#[test]
fn unmatched_unresolved_outcomes_are_counted_not_erased() {
    let (root, corpus) = corpus();
    let mut submission = submission(&corpus, root.path());
    for run in &mut submission.runs {
        run.predictions.push(BenchmarkRunPrediction {
            prediction_id: format!("unresolved-{}", run.run_id),
            finding_fingerprint: None,
            matched_case_id: None,
            tier: FindingTier::Unresolved,
            pattern: "none".to_string(),
            evidence: Vec::new(),
            proof_level: 0,
            reviewer_disposition: ReviewerDisposition::Unreviewed,
            reviewer_minutes: 0.0,
        });
    }

    let metrics = evaluate_release(&corpus, &submission, root.path()).expect("evaluate");

    assert!(metrics.unresolved_rate > 0.0);
}
