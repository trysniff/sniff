use super::{
    build_completed_run, build_final_completed_run, journal_is_final, write_completed_run,
};
use crate::analyzer::JournalSummary;
use crate::pricing::PricingRates;
use crate::report_types::{LLMVerdict, MethodReviewRecord, RunReport, RunStats};
use crate::review_journal::sha256_text;
use crate::types::FindingTier;
use crate::types::{FileRecord, MethodRecord};

fn source_files(root: &std::path::Path) -> Vec<FileRecord> {
    let path = root.join("src/demo.py");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "def demo():\n    return 1\n").unwrap();
    vec![FileRecord {
        file_path: path.to_string_lossy().to_string(),
        source: "def demo():\n    return 1\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "demo".to_string(),
            file_path: "src/demo.py".to_string(),
            source: "def demo():\n    return 1\n".to_string(),
            loc: 2,
            param_count: 0,
            start_line: 1,
            end_line: 2,
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        }],
    }]
}

fn clean_report() -> RunReport {
    let verdict = LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: "src/demo.py".to_string(),
        method_name: Some("demo".to_string()),
        check_type: "method".to_string(),
        smelly: false,
        tier: FindingTier::Clean,
        cohesive: None,
        name_accurate: None,
        evidence: String::new(),
        reason: "The method directly implements its contract.".to_string(),
        loc: 2,
        start_line: 1,
        end_line: 2,
    };
    let record = MethodReviewRecord {
        unit_id: sha256_text("unit"),
        source_hash: sha256_text("def demo():\n    return 1\n"),
        file_path: verdict.file_path.clone(),
        method_name: "demo".to_string(),
        start_line: 1,
        end_line: 2,
        loc: 2,
        verdict: verdict.clone(),
        pattern: "none".to_string(),
        intent: "Return the configured value.".to_string(),
        necessity_check: "No unnecessary machinery found.".to_string(),
        contract_status: "resolved".to_string(),
        contract_impact: "none".to_string(),
        dependency_impact: "none".to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
        evidence: Vec::new(),
    };
    let rates = PricingRates {
        input_per_million: 0.14,
        cached_input_per_million: 0.0028,
        output_per_million: 0.28,
    };
    RunReport {
        file_verdicts: Vec::new(),
        static_flags: Vec::new(),
        llm_verdicts: vec![verdict],
        method_review_records: vec![record],
        slop_cases: Vec::new(),
        stats: RunStats {
            files_scanned: 1,
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
        },
    }
}

fn complete_journal() -> JournalSummary {
    JournalSummary {
        scan_id: Some(sha256_text("scan")),
        execution_commitment_sha256: Some(sha256_text("execution")),
        expected_units: 1,
        completed_units: 1,
        expected_synthesis_units: 1,
        completed_synthesis_units: 1,
        input_tokens: 100,
        cached_input_tokens: 20,
        output_tokens: 10,
        estimated_cost_usd: PricingRates {
            input_per_million: 0.14,
            cached_input_per_million: 0.0028,
            output_per_million: 0.28,
        }
        .cost(100, 20, 10),
        pricing_snapshots: vec![PricingRates {
            input_per_million: 0.14,
            cached_input_per_million: 0.0028,
            output_per_million: 0.28,
        }],
        pricing_provenance_complete: true,
        prompt_contract_version: Some("semantic-method-v28".to_string()),
        endpoint: Some("https://example.invalid/v1".to_string()),
        semantic_index_hashes: vec![sha256_text("semantic-index")],
        provider: Some("openai-compatible".to_string()),
        model: Some("test-model".to_string()),
        ..JournalSummary::default()
    }
}

#[test]
fn completed_run_binds_the_exhaustive_report_and_usage() {
    let root = tempfile::tempdir().unwrap();
    let artifact = build_completed_run(
        &clean_report(),
        &complete_journal(),
        &source_files(root.path()),
        root.path(),
    )
    .unwrap();

    artifact.verify().unwrap();
    assert_eq!(artifact.coverage.methods_completed, 1);
    assert_eq!(artifact.source_files.len(), 1);
    assert_eq!(artifact.usage.input_tokens, 100);
    assert!(artifact.usage.pricing_provenance_complete);
}

#[test]
fn incomplete_method_or_compiler_coverage_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let mut report = clean_report();
    report.stats.compiler_methods_covered = 0;

    let error = build_completed_run(
        &report,
        &complete_journal(),
        &source_files(root.path()),
        root.path(),
    )
    .unwrap_err();

    assert!(error.contains("exhaustive method and compiler coverage"));
}

#[test]
fn tampering_with_a_finalized_report_breaks_its_commitment() {
    let root = tempfile::tempdir().unwrap();
    let mut artifact = build_completed_run(
        &clean_report(),
        &complete_journal(),
        &source_files(root.path()),
        root.path(),
    )
    .unwrap();
    artifact.report.method_review_records[0].intent = "tampered".to_string();

    let error = artifact.verify().unwrap_err();

    assert!(error.contains("report commitment"));
}

#[test]
fn finalized_runs_are_written_immutably_under_the_report_root() {
    let root = tempfile::tempdir().unwrap();
    let report_path = root.path().join("sniff-report.md");
    let artifact = build_completed_run(
        &clean_report(),
        &complete_journal(),
        &source_files(root.path()),
        root.path(),
    )
    .unwrap();

    let (path, created) = write_completed_run(&artifact, &report_path).unwrap();
    let stored: super::CompletedRunArtifact =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

    assert_eq!(path.parent().unwrap(), root.path().join(".sniff/runs"));
    assert!(created);
    stored.verify().unwrap();
    let (second, created) = write_completed_run(&artifact, &report_path).unwrap();
    assert_eq!(second, path);
    assert!(!created);
}

#[test]
fn tampering_with_the_scanned_source_inventory_breaks_its_commitment() {
    let root = tempfile::tempdir().unwrap();
    let mut artifact = build_completed_run(
        &clean_report(),
        &complete_journal(),
        &source_files(root.path()),
        root.path(),
    )
    .unwrap();
    artifact.source_files[0].sha256 = sha256_text("tampered");

    let error = artifact.verify().unwrap_err();

    assert!(error.contains("scanned source inventory"));
}

#[test]
fn completed_run_normalizes_machine_paths_without_rewriting_source_evidence() {
    let root = tempfile::tempdir().unwrap();
    let files = source_files(root.path());
    let absolute = files[0].file_path.clone();
    let mut report = clean_report();
    report.llm_verdicts[0].file_path = absolute.clone();
    report.method_review_records[0].file_path = absolute.clone();
    report.method_review_records[0].verdict.file_path = absolute;
    report.method_review_records[0]
        .evidence
        .push(crate::report_types::MethodEvidenceRecord {
            start_line: 2,
            end_line: 2,
            quote: "    return 1  # C:\\not-a-path-rewrite".to_string(),
        });

    let artifact = build_completed_run(&report, &complete_journal(), &files, root.path()).unwrap();

    assert_eq!(artifact.report.llm_verdicts[0].file_path, "src/demo.py");
    assert_eq!(
        artifact.report.method_review_records[0].file_path,
        "src/demo.py"
    );
    assert_eq!(
        artifact.report.method_review_records[0].evidence[0].quote,
        "    return 1  # C:\\not-a-path-rewrite"
    );
}

#[test]
fn retryable_unresolved_work_is_not_final_benchmark_evidence() {
    let mut journal = complete_journal();
    assert!(journal_is_final(&journal));

    journal.retryable_units = 1;

    assert!(!journal_is_final(&journal));
}

#[test]
fn retryable_unresolved_work_skips_completed_artifact_export() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = complete_journal();
    journal.retryable_units = 1;

    let artifact = build_final_completed_run(
        &clean_report(),
        &journal,
        &source_files(root.path()),
        root.path(),
    )
    .unwrap();

    assert!(artifact.is_none());
}
