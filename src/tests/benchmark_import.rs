use super::{
    OutcomeReview, PreparedOutcome, build_predictions, import_reviewed_run, prepare_run_review,
};
use crate::benchmark::{
    ActualCostReceipt, BenchmarkAdjudication, BenchmarkCase, BenchmarkCorpus, BenchmarkPartition,
    BenchmarkSourceSeal, BlindCaseBundle, LABEL_RESOLUTION_SCHEMA_VERSION, LabelResolver,
    ReleaseBenchmarkCase, ReviewerDisposition, SourceSnapshot, freeze_corpus,
};
use crate::completed_run::{
    COMPLETED_RUN_SCHEMA_VERSION, CompletedRunArtifact, CompletedRunCoverage,
    CompletedRunSourceFile, CompletedRunUsage,
};
use crate::pricing::PricingRates;
use crate::product_contract::SlopPattern;
use crate::report_types::{LLMVerdict, MethodReviewRecord, RunReport, RunStats};
use crate::slop_cases::{CaseEvidence, ProofLevel, SlopCase};
use crate::types::FindingTier;
use sha2::{Digest, Sha256};
use std::fs;

fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn snapshot(
    root: &std::path::Path,
    language: &str,
    repository_path: &str,
    text: &str,
) -> SourceSnapshot {
    let extension = std::path::Path::new(repository_path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap();
    let source_name = repository_path
        .replace(['/', '\\'], "-")
        .trim_end_matches(&format!(".{extension}"))
        .to_string();
    let artifact_path = format!("before/{language}-{source_name}.{extension}");
    let path = root.join(&artifact_path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    SourceSnapshot {
        repository: "https://github.com/example/polyglot".to_string(),
        revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
        repository_path: repository_path.to_string(),
        artifact_path,
        sha256: digest(text),
    }
}

fn write_blind_case_bundle(
    root: &std::path::Path,
    source_seal_artifact_path: &str,
    source_seal_sha256: &str,
    cases: &[ReleaseBenchmarkCase],
) -> (String, String) {
    let seal: BenchmarkSourceSeal = serde_json::from_slice(
        &fs::read(root.join(source_seal_artifact_path)).expect("read source seal"),
    )
    .expect("parse source seal");
    let mut bundle = BlindCaseBundle {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: source_seal_sha256.to_string(),
        source_seal_commitment_sha256: seal.seal_sha256,
        label_audit_sha256: "a".repeat(64),
        resolver: LabelResolver {
            resolver_id: "resolver-fixture".to_string(),
            years_experience: 8,
            affiliation: "Independent fixture reviewer".to_string(),
            maintainer: false,
            attestation: "Fixture labels were independently resolved.".to_string(),
        },
        cases: cases
            .iter()
            .filter(|case| case.partition == BenchmarkPartition::BlindOss)
            .cloned()
            .collect(),
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = bundle.computed_bundle_sha256().unwrap();
    let artifact_path = "blind-case-bundle.json".to_string();
    let bytes = serde_json::to_vec_pretty(&bundle).unwrap();
    fs::write(root.join(&artifact_path), &bytes).unwrap();
    (artifact_path, digest(&bytes))
}

fn frozen_corpus(root: &std::path::Path) -> BenchmarkCorpus {
    let definitions = [
        ("python", "src/demo.py", "def demo():\n    return 1\n"),
        (
            "javascript",
            "src/demo.js",
            "function demo() { return 1; }\n",
        ),
        (
            "typescript",
            "src/demo.ts",
            "function demo(): number { return 1; }\n",
        ),
        ("kotlin", "src/Demo.kt", "fun demo(): Int = 1\n"),
        ("rust", "src/demo.rs", "fn demo() -> i32 { 1 }\n"),
        (
            "go",
            "src/demo.go",
            "package demo\nfunc Demo() int { return 1 }\n",
        ),
        (
            "python",
            "blind/demo.py",
            "def blind_demo():\n    return 1\n",
        ),
        (
            "javascript",
            "blind/demo.js",
            "function blindDemo() { return 1; }\n",
        ),
        (
            "typescript",
            "blind/demo.ts",
            "function blindDemo(): number { return 1; }\n",
        ),
        ("kotlin", "blind/Demo.kt", "fun blindDemo(): Int = 1\n"),
    ];
    let sources = definitions
        .iter()
        .map(|(language, path, text)| snapshot(root, language, path, text))
        .collect::<Vec<_>>();
    let partitions = [
        BenchmarkPartition::SyntheticGold,
        BenchmarkPartition::HistoricalSimplification,
        BenchmarkPartition::ResearchTrajectory,
        BenchmarkPartition::IntentionalBoundary,
        BenchmarkPartition::BlindOss,
        BenchmarkPartition::BlindOss,
        BenchmarkPartition::BlindOss,
        BenchmarkPartition::BlindOss,
        BenchmarkPartition::BlindOss,
        BenchmarkPartition::BlindOss,
    ];
    let mut cases = definitions
        .iter()
        .zip(&sources)
        .zip(partitions)
        .enumerate()
        .map(|(index, (((language, _, _), source), partition))| {
            let finding = index == 0;
            ReleaseBenchmarkCase {
                label: BenchmarkCase {
                    case_id: format!("case-{index}-{language}"),
                    language: (*language).to_string(),
                    expected_tier: if finding {
                        FindingTier::Slop
                    } else {
                        FindingTier::Clean
                    },
                    expected_pattern: if finding {
                        SlopPattern::CeremonialLogic.as_str().to_string()
                    } else {
                        SlopPattern::None.as_str().to_string()
                    },
                    intentional_boundary: partition == BenchmarkPartition::IntentionalBoundary,
                },
                partition,
                before: vec![source.clone()],
                after: if finding {
                    let path = root.join("after/python.txt");
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(&path, "def demo():\n    return 1\n").unwrap();
                    vec![SourceSnapshot {
                        repository: source.repository.clone(),
                        revision: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
                        repository_path: source.repository_path.clone(),
                        artifact_path: "after/python.txt".to_string(),
                        sha256: digest("def demo():\n    return 1\n"),
                    }]
                } else {
                    Vec::new()
                },
                human_explanation: "Independent review established the intended label.".to_string(),
                behavioral_evidence: if finding {
                    vec!["The simplified revision preserves behavior.".to_string()]
                } else {
                    Vec::new()
                },
                expected_proof_level: if finding { 1 } else { 0 },
                covered_method_ids: Vec::new(),
                adjudications: if partition == BenchmarkPartition::SyntheticGold {
                    Vec::new()
                } else {
                    vec![BenchmarkAdjudication {
                        reviewer_id: format!("reviewer-{index}"),
                        years_experience: 8,
                        tier: FindingTier::Clean,
                        pattern: SlopPattern::None.as_str().to_string(),
                        rationale: "The boundary is intentional.".to_string(),
                        maintainer: false,
                    }]
                },
                disputed: false,
                dispute_resolution: None,
            }
        })
        .collect::<Vec<_>>();
    let blind_sources = cases
        .iter()
        .filter(|case| case.partition == BenchmarkPartition::BlindOss)
        .flat_map(|case| case.before.clone())
        .collect::<Vec<_>>();
    let (source_seal_artifact_path, source_seal_sha256, methods_by_artifact) =
        crate::benchmark::write_test_source_seal(root, &blind_sources);
    for case in &mut cases {
        if case.partition == BenchmarkPartition::BlindOss {
            case.covered_method_ids = methods_by_artifact[&case.before[0].artifact_path].clone();
        }
    }
    let (blind_case_bundle_artifact_path, blind_case_bundle_sha256) = write_blind_case_bundle(
        root,
        &source_seal_artifact_path,
        &source_seal_sha256,
        &cases,
    );
    freeze_corpus(
        BenchmarkCorpus {
            schema_version: 5,
            corpus_id: "import-corpus".to_string(),
            frozen_at: "2026-08-12T00:00:00Z".to_string(),
            source_commitment_sha256: String::new(),
            label_commitment_sha256: String::new(),
            source_seal_artifact_path,
            source_seal_sha256,
            blind_case_bundle_artifact_path,
            blind_case_bundle_sha256,
            analysis_sources: sources,
            cases,
        },
        root,
    )
    .unwrap()
}

fn completed_artifact(corpus: &BenchmarkCorpus) -> CompletedRunArtifact {
    let source_files = corpus
        .analysis_sources
        .iter()
        .map(|source| CompletedRunSourceFile {
            repository_path: source.repository_path.clone(),
            sha256: source.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let file_count = source_files.len();
    let verdict = LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: "src/demo.py".to_string(),
        method_name: Some("demo".to_string()),
        check_type: "method".to_string(),
        smelly: true,
        tier: FindingTier::Slop,
        cohesive: None,
        name_accurate: None,
        evidence: "return 1".to_string(),
        reason: "A ceremonial branch can be removed.".to_string(),
        loc: 2,
        start_line: 1,
        end_line: 2,
    };
    let unit_id = digest("unit-demo");
    let record = MethodReviewRecord {
        unit_id: unit_id.clone(),
        source_hash: digest("def demo():\n    return 1\n"),
        file_path: "src/demo.py".to_string(),
        method_name: "demo".to_string(),
        start_line: 1,
        end_line: 2,
        loc: 2,
        verdict: verdict.clone(),
        pattern: SlopPattern::CeremonialLogic.as_str().to_string(),
        intent: "Return one.".to_string(),
        necessity_check: "The branch has no contract.".to_string(),
        contract_status: "resolved".to_string(),
        contract_impact: "none".to_string(),
        dependency_impact: "none".to_string(),
        simplification: "Return one directly.".to_string(),
        change_scope: "local".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
        evidence: vec![crate::report_types::MethodEvidenceRecord {
            start_line: 2,
            end_line: 2,
            quote: "    return 1".to_string(),
        }],
    };
    let case = SlopCase {
        case_id: unit_id.clone(),
        tier: FindingTier::Slop,
        pattern: SlopPattern::CeremonialLogic,
        mechanism: "A ceremonial branch can be removed.".to_string(),
        intent: "Return one.".to_string(),
        evidence: vec![CaseEvidence {
            unit_id: unit_id.clone(),
            file_path: "src/demo.py".to_string(),
            method_name: "demo".to_string(),
            start_line: 2,
            end_line: 2,
            quote: "    return 1".to_string(),
        }],
        affected_units: vec![unit_id],
        contract_boundary: "none".to_string(),
        counterfactual: "Return one directly.".to_string(),
        counterfactual_edits: Vec::new(),
        proof_level: ProofLevel::P1CompilerValidated,
        unresolved_assumptions: Vec::new(),
        provenance: vec!["method census".to_string()],
    };
    let rates = PricingRates {
        input_per_million: 0.14,
        cached_input_per_million: 0.0028,
        output_per_million: 0.28,
    };
    let stats = RunStats {
        files_scanned: file_count,
        methods_analyzed: 1,
        ai_reviews: 1,
        ai_expected_reviews: 1,
        method_reviews_completed: 1,
        method_reviews_expected: 1,
        compiler_methods_covered: 1,
        compiler_methods_expected: 1,
        input_tokens: 100,
        cached_input_tokens: 20,
        output_tokens: 10,
        estimated_cost_usd: rates.cost(100, 20, 10),
        pricing_snapshots: vec![rates],
        pricing_provenance_complete: true,
        ..RunStats::default()
    };
    let report = RunReport {
        file_verdicts: Vec::new(),
        static_flags: Vec::new(),
        llm_verdicts: vec![verdict],
        method_review_records: vec![record],
        slop_cases: vec![case],
        stats,
    };
    let source_commitment = {
        let mut inventory = source_files
            .iter()
            .map(|source| (source.repository_path.as_str(), source.sha256.as_str()))
            .collect::<Vec<_>>();
        inventory.sort_unstable();
        digest(serde_json::to_vec(&inventory).unwrap())
    };
    let report_commitment = digest(serde_json::to_vec(&report).unwrap());
    let execution = digest("execution-one");
    let scan = digest("scan-one");
    let run_id = digest(format!(
        "schema={COMPLETED_RUN_SCHEMA_VERSION}\nscan={scan}\nexecution={execution}\nsource={source_commitment}\nreport={report_commitment}\nsniff={}\n",
        env!("CARGO_PKG_VERSION")
    ).trim_end());
    CompletedRunArtifact {
        schema_version: COMPLETED_RUN_SCHEMA_VERSION,
        run_id,
        scan_fingerprint: scan,
        execution_commitment_sha256: execution,
        sniff_version: env!("CARGO_PKG_VERSION").to_string(),
        completed_unix_ms: 1,
        provider: "openai-compatible".to_string(),
        model: "test-model".to_string(),
        endpoint: "https://example.invalid/v1".to_string(),
        prompt_contract_version: "semantic-method-v28".to_string(),
        semantic_index_hashes: vec![digest("semantic")],
        source_files,
        source_commitment_sha256: source_commitment,
        report_commitment_sha256: report_commitment,
        coverage: CompletedRunCoverage {
            files_scanned: file_count,
            source_files_committed: file_count,
            methods_expected: 1,
            methods_completed: 1,
            compiler_methods_expected: 1,
            compiler_methods_covered: 1,
            role_units_expected: 0,
            role_units_completed: 0,
            synthesis_units_expected: 0,
            synthesis_units_completed: 0,
            adjudication_units_expected: 0,
            adjudication_units_completed: 0,
            proof_units_expected: 0,
            proof_units_completed: 0,
            cross_scan_reused_units: 0,
        },
        usage: CompletedRunUsage {
            input_tokens: 100,
            cached_input_tokens: 20,
            output_tokens: 10,
            estimated_cost_usd: rates.cost(100, 20, 10),
            pricing_snapshots: vec![rates],
            pricing_provenance_complete: true,
        },
        report,
    }
}

#[test]
fn completed_artifacts_prepare_and_import_without_exposing_labels() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    artifact.verify().unwrap();
    let artifact_path = root.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();

    let mut review = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap();

    let prepared_json = serde_json::to_string(&review).unwrap();
    assert!(!prepared_json.contains("expected_tier"));
    assert!(!prepared_json.contains("human_explanation"));
    assert!(!prepared_json.contains("case-python"));
    assert!(!prepared_json.contains(&root.path().to_string_lossy().to_string()));
    assert!(import_reviewed_run(&corpus, root.path(), &review).is_err());

    review.reviews[0].matched_case_id = Some(review.blind_cases[0].case_id.clone());
    review.reviews[0].reviewer_disposition = ReviewerDisposition::Accepted;
    review.reviews[0].reviewer_minutes = 2.0;
    review.actual_cost_microusd = Some(50_000);
    review.actual_cost_provenance = "provider invoice export row 7".to_string();
    fs::create_dir_all(root.path().join("cost")).unwrap();
    let raw = "{\"cost\":0.05}\n";
    fs::write(root.path().join("cost/provider.json"), raw).unwrap();
    let receipt = ActualCostReceipt {
        schema_version: 1,
        provider: review.prepared.provider.clone(),
        model: review.prepared.model.clone(),
        currency: "USD".to_string(),
        actual_cost_microusd: 50_000,
        provenance: review.actual_cost_provenance.clone(),
        raw_evidence_artifact_path: "cost/provider.json".to_string(),
        raw_evidence_sha256: digest(raw),
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
    fs::write(root.path().join("cost/receipt.json"), &receipt_bytes).unwrap();
    review.actual_cost_artifact_path = "cost/receipt.json".to_string();
    review.actual_cost_artifact_sha256 = digest(&receipt_bytes);
    review.blind_reviewer = Some(crate::benchmark::BlindReviewer {
        reviewer_id: "reviewer-001".to_string(),
        years_experience: 8,
        affiliation: "Independent evaluator".to_string(),
        independent_from_sniff: true,
        labels_hidden_during_review: true,
        attestation: "I reviewed these outcomes without access to the frozen labels.".to_string(),
    });
    review.wall_clock_seconds = Some(12.5);

    let run = import_reviewed_run(&corpus, root.path(), &review).unwrap();

    assert_eq!(run.predictions.len(), corpus.cases.len());
    assert_eq!(
        run.predictions[0].matched_case_id.as_deref(),
        Some("case-0-python")
    );
    assert_eq!(run.usage.actual_cost_microusd, 50_000);
    assert_eq!(run.cross_scan_reused_units, 0);
}

#[test]
fn import_rejects_cost_claim_that_differs_from_receipt() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    let artifact_path = root.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();
    let mut review = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap();
    review.reviews[0].reviewer_disposition = ReviewerDisposition::Rejected;
    review.reviews[0].reviewer_minutes = 1.0;
    review.actual_cost_microusd = Some(60_000);
    review.actual_cost_provenance = "provider invoice export row 7".to_string();
    review.blind_reviewer = Some(crate::benchmark::BlindReviewer {
        reviewer_id: "reviewer-001".to_string(),
        years_experience: 8,
        affiliation: "Independent evaluator".to_string(),
        independent_from_sniff: true,
        labels_hidden_during_review: true,
        attestation: "I reviewed these outcomes without access to the frozen labels.".to_string(),
    });
    review.wall_clock_seconds = Some(10.0);
    fs::create_dir_all(root.path().join("cost")).unwrap();
    fs::write(root.path().join("cost/provider.json"), "raw\n").unwrap();
    let receipt = ActualCostReceipt {
        schema_version: 1,
        provider: review.prepared.provider.clone(),
        model: review.prepared.model.clone(),
        currency: "USD".to_string(),
        actual_cost_microusd: 50_000,
        provenance: review.actual_cost_provenance.clone(),
        raw_evidence_artifact_path: "cost/provider.json".to_string(),
        raw_evidence_sha256: digest("raw\n"),
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
    fs::write(root.path().join("cost/receipt.json"), &receipt_bytes).unwrap();
    review.actual_cost_artifact_path = "cost/receipt.json".to_string();
    review.actual_cost_artifact_sha256 = digest(&receipt_bytes);

    let error = import_reviewed_run(&corpus, root.path(), &review).unwrap_err();

    assert!(error.contains("does not match the benchmark run"));
}

#[test]
fn import_rejects_non_independent_or_unblinded_reviewer() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    let artifact_path = root.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();
    let mut review = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap();
    review.blind_reviewer = Some(crate::benchmark::BlindReviewer {
        reviewer_id: "reviewer-001".to_string(),
        years_experience: 8,
        affiliation: "Sniff project".to_string(),
        independent_from_sniff: false,
        labels_hidden_during_review: true,
        attestation: "I reviewed these outcomes without access to the frozen labels.".to_string(),
    });

    let error = import_reviewed_run(&corpus, root.path(), &review).unwrap_err();

    assert!(error.contains("independence from Sniff"));
}

#[test]
fn import_rejects_a_blind_reviewer_who_adjudicated_corpus_labels() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    let artifact_path = root.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();
    let mut review = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap();
    review.blind_reviewer = Some(crate::benchmark::BlindReviewer {
        reviewer_id: "reviewer-1".to_string(),
        years_experience: 8,
        affiliation: "Independent evaluator".to_string(),
        independent_from_sniff: true,
        labels_hidden_during_review: true,
        attestation: "I reviewed these outcomes without access to the frozen labels.".to_string(),
    });

    let error = import_reviewed_run(&corpus, root.path(), &review).unwrap_err();

    assert!(error.contains("also adjudicated a frozen corpus label"));
}

#[test]
fn import_rejects_tampered_prepared_outcomes() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    let artifact_path = root.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();
    let mut review = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap();
    review.outcomes[0].tier = FindingTier::Clean;

    let error = import_reviewed_run(&corpus, root.path(), &review).unwrap_err();

    assert!(error.contains("changed source-bound preparation fields"));
}

#[test]
fn unmatched_unresolved_outcome_is_preserved_in_run_ledger() {
    let root = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let prepared = PreparedOutcome {
        outcome_id: "unresolved-method".to_string(),
        finding_fingerprint: None,
        tier: FindingTier::Unresolved,
        pattern: SlopPattern::None.as_str().to_string(),
        mechanism: "The external callback contract could not be established.".to_string(),
        evidence: Vec::new(),
        proof_level: 0,
    };
    let review = OutcomeReview {
        outcome_id: prepared.outcome_id.clone(),
        matched_case_id: None,
        reviewer_disposition: ReviewerDisposition::Unreviewed,
        reviewer_minutes: 0.0,
    };
    let blind_cases = prepare_run_review(
        &corpus,
        root.path(),
        &[{
            let artifact = completed_artifact(&corpus);
            let path = root.path().join("completed.json");
            fs::write(&path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
            path
        }],
    )
    .unwrap()
    .blind_cases;
    let outcomes = vec![prepared];
    let reviews = std::collections::HashMap::from([(outcomes[0].outcome_id.as_str(), &review)]);

    let predictions = build_predictions(&corpus, &outcomes, &reviews, &blind_cases).unwrap();

    assert!(predictions.iter().any(|prediction| {
        prediction.prediction_id == "unresolved-method"
            && prediction.matched_case_id.is_none()
            && prediction.tier == FindingTier::Unresolved
    }));
}

#[test]
fn preparation_rejects_completed_artifact_outside_corpus_bundle() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let corpus = frozen_corpus(root.path());
    let artifact = completed_artifact(&corpus);
    let artifact_path = external.path().join("completed.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).unwrap(),
    )
    .unwrap();

    let error = prepare_run_review(&corpus, root.path(), &[artifact_path]).unwrap_err();

    assert!(error.contains("inside the benchmark corpus bundle"));
}
