use super::*;
use crate::benchmark::{
    HistoricalDiffHunk, HistoricalV2ChangedMethodResolutionFailure, HistoricalV2PublicSurfaceDelta,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SourceMethod,
    HistoricalV2SourceSemanticCoverage,
};

#[test]
fn hunk_overlap_is_side_specific() {
    let method = source_method();
    let hunks = vec![HistoricalDiffHunk {
        previous_path: None,
        path: "src/lib.rs".to_string(),
        parent_start: 10,
        parent_count: 3,
        commit_start: 20,
        commit_count: 2,
    }];
    assert!(method_overlaps_hunks(
        HistoricalRevisionSide::Parent,
        &method,
        &hunks
    ));
    assert!(!method_overlaps_hunks(
        HistoricalRevisionSide::Commit,
        &method,
        &hunks
    ));
}

#[test]
fn production_role_change_is_terminal() {
    let mut reasons = BTreeSet::new();
    assert!(!production_role(
        Some(HistoricalV2SourceRoleDecision {
            role: HistoricalV2SourceRole::Production,
            basis: crate::benchmark::HistoricalV2SourceRoleBasis::TrackedSupportedSource,
        }),
        Some(HistoricalV2SourceRoleDecision {
            role: HistoricalV2SourceRole::Test,
            basis: crate::benchmark::HistoricalV2SourceRoleBasis::TestPath,
        }),
        &mut reasons,
    ));
    assert!(reasons.contains(&HistoricalV2QualificationExclusionReason::ProductionRoleChanged));
}

#[test]
fn absent_compiler_method_is_recorded_unresolved() {
    let file = source_file_fixture();
    let semantic = semantic_snapshot();
    let hunks = vec![HistoricalDiffHunk {
        previous_path: None,
        path: "src/lib.rs".to_string(),
        parent_start: 10,
        parent_count: 1,
        commit_start: 10,
        commit_count: 1,
    }];
    let mut changed = BTreeMap::new();
    let mut unresolved = BTreeMap::new();
    collect_side_methods(
        HistoricalRevisionSide::Parent,
        "src/lib.rs",
        Some(&file),
        &semantic,
        &hunks,
        &mut changed,
        &mut unresolved,
    );
    assert!(changed.is_empty());
    assert!(matches!(
        unresolved.values().next().map(|method| &method.failure),
        Some(HistoricalV2ChangedMethodResolutionFailure::MissingSemanticMethod)
    ));
}

#[test]
fn qualification_hash_binds_the_outcome() {
    let qualification = seal_qualification(qualification()).expect("seal qualification");
    let mut changed = qualification.clone();
    changed.outcome = HistoricalV2QualificationOutcome::Qualified;
    assert_ne!(
        qualification.qualification_sha256,
        qualification_sha256(&changed).expect("hash changed qualification")
    );
    assert!(seal_qualification(qualification).is_err());
}

#[test]
fn supported_language_mapping_is_exact() {
    assert_eq!(path_language("src/lib.rs"), Some("rust"));
    assert_eq!(path_language("src/view.tsx"), Some("typescript"));
    assert_eq!(path_language("README.md"), None);
}

fn source_method() -> HistoricalV2SourceMethod {
    HistoricalV2SourceMethod {
        parser_unit_id: "method".to_string(),
        symbol_name: "work".to_string(),
        start_line: 9,
        end_line: 15,
        source_sha256: "1".repeat(64),
        is_exported: false,
    }
}

fn source_file_fixture() -> HistoricalV2SourceFile {
    HistoricalV2SourceFile {
        repository_path: "src/lib.rs".to_string(),
        object_id: "1".repeat(40),
        byte_length: 10,
        source_sha256: "2".repeat(64),
        non_whitespace_lines: 10,
        language: "rust".to_string(),
        semantic_coverage: HistoricalV2SourceSemanticCoverage::Required,
        methods: vec![source_method()],
    }
}

fn semantic_snapshot() -> HistoricalV2SemanticSnapshotCensus {
    HistoricalV2SemanticSnapshotCensus {
        revision: "1".repeat(40),
        source_snapshot_census_sha256: "2".repeat(64),
        indexers: Vec::new(),
        methods: Vec::new(),
        public_symbols: Vec::new(),
        public_symbol_count: 0,
        resolved_method_count: 0,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_snapshot_sha256: "3".repeat(64),
    }
}

fn qualification() -> HistoricalV2Qualification {
    HistoricalV2Qualification {
        schema_version: HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
        qualification_contract: QUALIFICATION_CONTRACT.to_string(),
        assessment_identity_sha256: "0".repeat(64),
        language: "rust".to_string(),
        slot_number: 1,
        patch_changed_paths: vec!["src/lib.rs".to_string()],
        git_changed_paths: vec!["src/lib.rs".to_string()],
        qualified_paths: Vec::new(),
        repository_production_method_count: 20,
        repository_method_minimum: 20,
        repository_method_maximum: 500,
        changed_methods: Vec::new(),
        unresolved_changed_methods: Vec::new(),
        production_non_whitespace_lines_before: 10,
        production_non_whitespace_lines_after: 9,
        public_surface: HistoricalV2PublicSurfaceDelta {
            base_entries: Vec::new(),
            patched_entries: Vec::new(),
            removed: Vec::new(),
            added: Vec::new(),
            changed: Vec::new(),
            preserved: true,
            delta_sha256: "4".repeat(64),
        },
        outcome: HistoricalV2QualificationOutcome::Excluded {
            reasons: vec![HistoricalV2QualificationExclusionReason::NoChangedBaseProductionMethods],
        },
        qualification_sha256: String::new(),
    }
}
