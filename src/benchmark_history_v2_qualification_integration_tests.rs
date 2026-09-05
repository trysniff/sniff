use super::*;
use crate::benchmark::{
    HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
    HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION, HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION,
    HistoricalV2MaterializedRoots, HistoricalV2SelectedPayloads, HistoricalV2SemanticCensus,
    HistoricalV2SemanticMethod, HistoricalV2SemanticMethodStatus,
    HistoricalV2SemanticPublicBinding, HistoricalV2SemanticPublicBindingKind,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SemanticSymbol, HistoricalV2SourceCensus,
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticVisibility,
    census_historical_v2_sources,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn real_git_reduction_with_resolved_methods_qualifies() {
    let fixture = Fixture::new();
    let (materialization, roots) = fixture.materialize();
    let source_census =
        census_historical_v2_sources(&materialization, &roots).expect("source census");
    assert_eq!(source_census.base.method_count, 20);
    assert_eq!(source_census.patched.method_count, 20);

    let semantic_census = semantic_census(&source_census);
    let payloads = selected_payloads(&fixture.historical_patch);
    let identity = assessment_identity(&materialization);
    let qualification = qualify_evidence(
        &QualificationEvidenceInputs {
            protocol_bytes: include_bytes!("../sniffbench/historical-v2-protocol.json"),
            payloads: &payloads,
            materialization: &materialization,
            materialized_roots: &roots,
            source_census: &source_census,
            semantic_census: &semantic_census,
        },
        &identity,
    )
    .expect("qualification");

    assert_eq!(
        qualification.outcome,
        HistoricalV2QualificationOutcome::Qualified
    );
    assert_eq!(qualification.repository_production_method_count, 20);
    assert!(
        qualification.production_non_whitespace_lines_before
            > qualification.production_non_whitespace_lines_after
    );
    assert!(qualification.changed_methods.iter().any(|method| {
        method.side == HistoricalRevisionSide::Parent && method.symbol_name == "Method0"
    }));
    assert!(qualification.unresolved_changed_methods.is_empty());
    assert!(qualification.public_surface.preserved);
    assert_eq!(qualification.public_surface.base_entries.len(), 20);
    assert_eq!(qualification.public_surface.patched_entries.len(), 20);
    assert_eq!(
        qualification.qualified_paths[0].base_role,
        Some(HistoricalV2SourceRoleDecision {
            role: HistoricalV2SourceRole::Production,
            basis: crate::benchmark::HistoricalV2SourceRoleBasis::TrackedSupportedSource,
        })
    );
}

struct Fixture {
    source: tempfile::TempDir,
    output: tempfile::TempDir,
    base_revision: String,
    historical_patch: String,
}

impl Fixture {
    fn new() -> Self {
        let source = tempfile::tempdir().expect("source repository");
        git_ok(source.path(), &["init", "-b", "main"]);
        git_ok(
            source.path(),
            &["config", "user.email", "fixture@example.test"],
        );
        git_ok(source.path(), &["config", "user.name", "Fixture"]);
        git_ok(source.path(), &["config", "core.autocrlf", "false"]);
        fs::create_dir_all(source.path().join("src")).expect("source directory");
        fs::write(source.path().join("src/lib.go"), go_source(true)).expect("base source");
        git_ok(source.path(), &["add", "."]);
        git_ok(source.path(), &["commit", "-m", "base"]);
        let base_revision = git_text(source.path(), &["rev-parse", "HEAD"]);
        fs::write(source.path().join("src/lib.go"), go_source(false)).expect("patched source");
        let historical_patch = format!(
            "{}\n",
            git_text(source.path(), &["diff", "--binary", "HEAD"])
        );
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);
        Self {
            source,
            output: tempfile::tempdir().expect("materialization parent"),
            base_revision,
            historical_patch,
        }
    }

    fn materialize(
        &self,
    ) -> (
        crate::benchmark::HistoricalV2Materialization,
        HistoricalV2MaterializedRoots,
    ) {
        let materialized = super::super::history_v2_materialization::materialize_from_url(
            "example/qualification-fixture",
            &self.source.path().to_string_lossy(),
            &self.base_revision,
            &self.historical_patch,
            &sha256(self.historical_patch.as_bytes()),
            &self.output.path().join("slot"),
        )
        .expect("materialization");
        git_ok(
            &materialized.1.repository_root,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/example/qualification-fixture.git",
            ],
        );
        materialized
    }
}

fn go_source(redundant: bool) -> String {
    let methods = (0..20)
        .map(|index| {
            if index == 0 && redundant {
                "func Method0() int {\n\tvalue := 0\n\treturn value\n}\n".to_string()
            } else {
                format!("func Method{index}() int {{\n\treturn {index}\n}}\n")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("package fixture\n\n{methods}")
}

fn semantic_census(source: &HistoricalV2SourceCensus) -> HistoricalV2SemanticCensus {
    HistoricalV2SemanticCensus {
        schema_version: HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_census_contract: "fixture".to_string(),
        canonical_repository: source.canonical_repository.clone(),
        materialization_sha256: source.materialization_sha256.clone(),
        source_census_sha256: source.source_census_sha256.clone(),
        changed_indexers: vec![IntentionalBoundaryIndexerKind::Go],
        base: semantic_snapshot(&source.base),
        patched: semantic_snapshot(&source.patched),
        semantic_census_sha256: "1".repeat(64),
    }
}

fn semantic_snapshot(
    source: &crate::benchmark::HistoricalV2SourceSnapshotCensus,
) -> HistoricalV2SemanticSnapshotCensus {
    let mut methods = Vec::new();
    let mut symbols = Vec::new();
    let mut public_bindings = Vec::new();
    for file in &source.source_files {
        for method in &file.methods {
            let symbol = symbol_facts(&file.repository_path, &method.symbol_name);
            let declaration = file
                .public_declarations
                .iter()
                .find(|declaration| declaration.name == method.symbol_name)
                .expect("public source declaration");
            methods.push(HistoricalV2SemanticMethod {
                parser_unit_id: method.parser_unit_id.clone(),
                repository_path: file.repository_path.clone(),
                symbol_name: method.symbol_name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                indexer: IntentionalBoundaryIndexerKind::Go,
                status: HistoricalV2SemanticMethodStatus::Resolved {
                    symbol_id: symbol.symbol_id.clone(),
                    joined_definition: None,
                },
            });
            symbols.push(HistoricalV2SemanticSymbol {
                indexer: IntentionalBoundaryIndexerKind::Go,
                is_public_surface: true,
                is_public_root_evidence: false,
                is_reexport_evidence: false,
                symbol: symbol.clone(),
            });
            public_bindings.push(HistoricalV2SemanticPublicBinding {
                indexer: IntentionalBoundaryIndexerKind::Go,
                surface_unit_id: declaration.surface_unit_id.clone(),
                declaration_unit_id: declaration.declaration_unit_id.clone(),
                origin_declaration_unit_id: declaration.declaration_unit_id.clone(),
                reexport_path: Vec::new(),
                repository_path: file.repository_path.clone(),
                symbol_id: symbol.symbol_id.clone(),
                owner_symbol_id: None,
                exposing_owner_declaration_unit_id: None,
                package_exposure_id: None,
                binding: HistoricalV2SemanticPublicBindingKind::Definition,
                externally_reachable: true,
                position_encoding: crate::semantic_index::SemanticPositionEncoding::Utf8,
                compiler_anchor: symbol.definitions[0].clone(),
                owner_compiler_anchor: None,
            });
        }
    }
    HistoricalV2SemanticSnapshotCensus {
        revision: source.revision.clone(),
        source_snapshot_census_sha256: source.snapshot_census_sha256.clone(),
        required_document_paths: source
            .source_files
            .iter()
            .map(|file| file.repository_path.clone())
            .collect(),
        public_surface_document_paths: source
            .source_files
            .iter()
            .map(|file| file.repository_path.clone())
            .collect(),
        indexers: Vec::new(),
        public_binding_count: public_bindings.len(),
        public_bindings,
        public_root_count: 0,
        public_roots: Vec::new(),
        public_reexport_hop_count: 0,
        public_reexport_hops: Vec::new(),
        symbol_count: symbols.len(),
        public_symbol_count: symbols.len(),
        resolved_method_count: methods.len(),
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        methods,
        symbols,
        semantic_snapshot_sha256: "2".repeat(64),
    }
}

fn symbol_facts(repository_path: &str, name: &str) -> IntentionalBoundarySemanticSymbolFacts {
    IntentionalBoundarySemanticSymbolFacts {
        symbol_id: format!("go fixture {name}."),
        provider_identity: format!("fixture:{name}"),
        display_name: Some(name.to_string()),
        category: IntentionalBoundarySemanticSymbolCategory::Callable,
        provider_kind: "function".to_string(),
        documentation: Vec::new(),
        signatures: vec![
            crate::benchmark::IntentionalBoundarySemanticSignatureFacts {
                language: "go".to_string(),
                text: format!("pub fn {name}() -> i32"),
                referenced_symbols: Vec::new(),
            },
        ],
        owner: Some(IntentionalBoundarySemanticResolution::Resolved {
            value: "fixture".to_string(),
        }),
        definitions: vec![crate::benchmark::IntentionalBoundarySemanticRange {
            repository_path: repository_path.to_string(),
            start_line_zero_based: 0,
            start_character_zero_based: 0,
            end_line_zero_based: 0,
            end_character_zero_based: 1,
        }],
        visibility: IntentionalBoundarySemanticVisibility::Public,
        surfaces: vec![crate::benchmark::IntentionalBoundarySemanticSurface::PublicApi],
        origin: IntentionalBoundarySemanticOrigin::Repository,
        ambiguity_notes: Vec::new(),
    }
}

fn selected_payloads(patch: &str) -> HistoricalV2SelectedPayloads {
    HistoricalV2SelectedPayloads {
        schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
        payload_contract: "fixture".to_string(),
        protocol_sha256: "1".repeat(64),
        frame_sha256: "2".repeat(64),
        exclusion_manifest_sha256: "3".repeat(64),
        selection_sha256: "4".repeat(64),
        selected_count: 1,
        records: vec![HistoricalV2SelectedPayload {
            language: "go".to_string(),
            slot_number: 1,
            source_shard_index: 0,
            source_row_index: 0,
            global_row_index: 0,
            instance_id: "fixture".to_string(),
            patch: patch.to_string(),
            patch_sha256: sha256(patch.as_bytes()),
            install_config: None,
            install_config_sha256: None,
            test_patch: None,
            test_patch_sha256: None,
            payload_sha256: "5".repeat(64),
        }],
        payloads_sha256: "6".repeat(64),
    }
}

fn assessment_identity(
    materialization: &crate::benchmark::HistoricalV2Materialization,
) -> HistoricalV2AssessmentIdentity {
    HistoricalV2AssessmentIdentity {
        schema_version: HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
        assessment_identity_contract: "fixture".to_string(),
        protocol_sha256: "1".repeat(64),
        frame_sha256: "2".repeat(64),
        exclusion_manifest_sha256: "3".repeat(64),
        selection_sha256: "4".repeat(64),
        payloads_sha256: "5".repeat(64),
        language: "go".to_string(),
        slot_number: 1,
        global_row_index: 0,
        instance_id: "fixture".to_string(),
        canonical_repository: materialization.canonical_repository.clone(),
        pull_number: 1,
        base_revision: materialization.base_revision.clone(),
        rank_sha256: "6".repeat(64),
        payload_sha256: "7".repeat(64),
        historical_patch_sha256: materialization.historical_patch_sha256.clone(),
        install_config_sha256: None,
        test_patch_sha256: None,
        materialization_sha256: materialization.materialization_sha256.clone(),
        test_materialization_sha256: None,
        source_census_sha256: "8".repeat(64),
        base_source_snapshot_sha256: "9".repeat(64),
        patched_source_snapshot_sha256: "a".repeat(64),
        semantic_census_sha256: "b".repeat(64),
        base_semantic_snapshot_sha256: "c".repeat(64),
        patched_semantic_snapshot_sha256: "d".repeat(64),
        assessment_identity_sha256: "e".repeat(64),
    }
}

fn git_ok(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_text(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 Git output")
        .trim()
        .to_string()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
