use super::super::history_v3_materialization::materialize_historical_v3_candidate_from_url;
use super::super::history_v3_rank_journal::{rank_workspace, run_materialization_stage_with};
use super::super::{
    HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3CandidateCollectionManifest, HistoricalV3CandidateIdentity,
    HistoricalV3CandidateRepository, HistoricalV3Language, HistoricalV3Materialization,
    HistoricalV3MaterializationStageRun, HistoricalV3Protocol, HistoricalV3RankJournal,
    HistoricalV3RankStage, HistoricalV3SemanticCensusStageRun,
    HistoricalV3SemanticSnapshotEvidence, HistoricalV3SourceCensus, HistoricalV3SourceSide,
    prepare_historical_v3_stream_task, run_historical_v3_source_census_stage,
};
use super::runtime::{SemanticRunFuture, run_historical_v3_semantic_census_stage_with};
use super::*;
use crate::semantic_index::{
    RepositoryPath, SemanticDocument, SemanticIndex, SemanticIndexProvenance,
    SemanticIndexerContribution, SemanticIndexerInvocation, SemanticLocation, SemanticOccurrence,
    SemanticOccurrenceRole, SemanticPosition, SemanticPositionEncoding, SemanticSourceRange,
    SemanticSurface, SemanticSymbol, SemanticSymbolCategory, SemanticSymbolId, SemanticSymbolKind,
    SemanticSymbolOrigin, SemanticTextEncoding, SemanticVisibility,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::{
    SemanticIndexerBatchOutcome, SemanticIndexerRunFailure, SemanticIndexerRunFailureKind,
    SemanticIndexerRunPhase,
};
use crate::types::FileRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct GitFixture {
    _root: tempfile::TempDir,
    repository: PathBuf,
    base: String,
    head: String,
    merge: String,
}

pub(crate) fn fixture() -> GitFixture {
    fixture_with_source(
        "src/lib.rs",
        "pub fn total() -> i32 {\n    let value = 1;\n    value\n}\n",
        "pub fn total() -> i32 { 2 }\n",
    )
}

pub(crate) fn fixture_with_source(path: &str, base_source: &str, merge_source: &str) -> GitFixture {
    fixture_with_source_and_recipe(
        path,
        base_source,
        merge_source,
        Some((cargo_lock(), cargo_lock())),
    )
}

pub(crate) fn fixture_with_changed_recipe(
    path: &str,
    base_source: &str,
    merge_source: &str,
) -> GitFixture {
    fixture_with_source_and_recipe(
        path,
        base_source,
        merge_source,
        Some((cargo_lock(), format!("{}# changed\n", cargo_lock()))),
    )
}

pub(crate) fn fixture_without_recipe(
    path: &str,
    base_source: &str,
    merge_source: &str,
) -> GitFixture {
    fixture_with_source_and_recipe(path, base_source, merge_source, None)
}

fn fixture_with_source_and_recipe(
    path: &str,
    base_source: &str,
    merge_source: &str,
    cargo_locks: Option<(String, String)>,
) -> GitFixture {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("source");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-b", "main"]);
    git(&repository, &["config", "user.name", "Sniff Test"]);
    git(&repository, &["config", "user.email", "sniff-test@invalid"]);
    let source_path = repository.join(path);
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(&source_path, base_source).unwrap();
    if let Some((base_lock, _)) = &cargo_locks {
        fs::write(repository.join("Cargo.toml"), cargo_manifest()).unwrap();
        fs::write(repository.join("Cargo.lock"), base_lock).unwrap();
    }
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "base"]);
    let base = git_text(&repository, &["rev-parse", "HEAD"]);
    git(&repository, &["checkout", "-b", "feature"]);
    fs::write(&source_path, merge_source).unwrap();
    if let Some((_, merge_lock)) = &cargo_locks {
        fs::write(repository.join("Cargo.lock"), merge_lock).unwrap();
    }
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "change source"]);
    let head = git_text(&repository, &["rev-parse", "HEAD"]);
    git(&repository, &["update-ref", "refs/pull/7/head", &head]);
    git(&repository, &["checkout", "main"]);
    git(
        &repository,
        &["merge", "--no-ff", "feature", "-m", "merge feature"],
    );
    let merge = git_text(&repository, &["rev-parse", "HEAD"]);
    GitFixture {
        _root: root,
        repository,
        base,
        head,
        merge,
    }
}

fn cargo_manifest() -> &'static str {
    "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
}

fn cargo_lock() -> String {
    "version = 3\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n".to_string()
}

pub(crate) fn protocol() -> HistoricalV3Protocol {
    use super::super::history_v3_source_binding::tests as source_fixture;
    let fixtures = source_fixture::fixtures();
    let prior = source_fixture::prior_identity_seal();
    source_fixture::protocol(&prior, &fixtures)
}

pub(crate) fn collection(
    protocol: &HistoricalV3Protocol,
    fixture: &GitFixture,
) -> HistoricalV3CandidateCollection {
    let identity = HistoricalV3CandidateIdentity {
        language: HistoricalV3Language::Rust,
        repository_id: 14,
        pull_request_number: 7,
        base_commit: fixture.base.clone(),
        head_commit: fixture.head.clone(),
        merge_commit: fixture.merge.clone(),
    };
    let stream_task = prepare_historical_v3_stream_task(protocol, vec![identity.clone()]).unwrap();
    let manifest = super::super::history_v3_candidate_collection::seal_collection_manifest(
        HistoricalV3CandidateCollectionManifest {
            schema_version: HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION,
            manifest_contract: "sniffbench-historical-v3-candidate-manifest-v1".to_string(),
            protocol_sha256: protocol.protocol_sha256.clone(),
            source_binding_audit_sha256: "a".repeat(64),
            query_document_sha256:
                super::super::history_v3_candidate_collection::historical_v3_candidate_query_sha256_for_tests(),
            repositories: vec![HistoricalV3CandidateRepository {
                language: HistoricalV3Language::Rust,
                repository_id: 14,
                name_with_owner: "fresh/rust".to_string(),
            }],
            partitions: Vec::new(),
            page_checkpoint_sha256s: Vec::new(),
            candidate_count: 1,
            stream_task,
            manifest_sha256: String::new(),
        },
    )
    .unwrap();
    HistoricalV3CandidateCollection {
        manifest,
        candidates: vec![identity],
    }
}

pub(crate) fn prepare_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    fixture: &GitFixture,
    journal: &Path,
    workspace: &Path,
) {
    let materialization = run_materialization_stage_with(
        protocol,
        collection,
        1,
        journal,
        workspace,
        |destination| {
            materialize_historical_v3_candidate_from_url(
                protocol,
                collection,
                1,
                destination,
                fixture.repository.to_str().unwrap(),
            )
        },
    )
    .unwrap();
    assert!(matches!(
        materialization,
        HistoricalV3MaterializationStageRun::Completed { resumed: false, .. }
    ));
    run_historical_v3_source_census_stage(protocol, collection, 1, journal, workspace).unwrap();
}

pub(crate) async fn prepare_semantic_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    journal: &Path,
    workspace: &Path,
) {
    let outcome = run_historical_v3_semantic_census_stage_with(
        protocol,
        collection,
        1,
        journal,
        workspace,
        successful_run,
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        HistoricalV3SemanticCensusStageRun::Completed { resumed: false, .. }
    ));
}

#[tokio::test]
async fn commits_surface_and_resumes_without_git_or_indexers() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    let first = run_historical_v3_semantic_census_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        successful_run,
    )
    .await
    .unwrap();
    let HistoricalV3SemanticCensusStageRun::Completed {
        artifact,
        resumed: false,
    } = first
    else {
        panic!("synthetic compiler indexes must complete");
    };
    assert_eq!(artifact.base.semantic_census.resolved_method_count, 1);
    assert_eq!(artifact.merge.semantic_census.resolved_method_count, 1);
    assert_eq!(artifact.base.surface_symbol_count, 2);
    assert_eq!(artifact.merge.surface_symbol_count, 2);
    assert!(
        artifact.base.compiler_indexes[0]
            .index
            .provenance
            .arguments
            .is_empty()
    );

    let mut tampered = (*artifact).clone();
    tampered.base.surface_symbols.remove(0);
    tampered.base.surface_symbol_count -= 1;
    tampered.base = super::commitment::seal_snapshot(tampered.base).unwrap();
    tampered = super::commitment::seal_semantic_census(tampered).unwrap();
    let (materialization, source_census) = committed_inputs(&protocol, &collection, journal.path());
    let error = validate_historical_v3_semantic_census_commitment(
        &protocol,
        &collection,
        &materialization,
        &source_census,
        &tampered,
    )
    .unwrap_err();
    assert!(error.contains("projection"));

    let identity = super::super::historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed = run_historical_v3_semantic_census_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        panic_run,
    )
    .await
    .unwrap();
    assert!(matches!(
        resumed,
        HistoricalV3SemanticCensusStageRun::Completed { resumed: true, .. }
    ));
}

#[tokio::test]
async fn inspects_both_sides_before_terminal_semantic_exclusion() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    let outcome = run_historical_v3_semantic_census_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        terminal_run,
    )
    .await
    .unwrap();
    let HistoricalV3SemanticCensusStageRun::Excluded { artifact, .. } = outcome else {
        panic!("terminal compiler evidence must exclude");
    };
    assert_eq!(artifact.sides.len(), 2);
    for (side, expected) in artifact
        .sides
        .iter()
        .zip([HistoricalV3SourceSide::Base, HistoricalV3SourceSide::Merge])
    {
        assert!(matches!(
            side,
            HistoricalV3SemanticSnapshotEvidence::Excluded {
                side,
                failures,
                ..
            } if *side == expected && failures.len() == 1
        ));
    }
}

#[tokio::test]
async fn operational_failure_leaves_semantic_rank_open_for_retry() {
    let fixture = fixture();
    let protocol = protocol();
    let collection = collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    let error = run_historical_v3_semantic_census_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        operational_run,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.kind,
        super::super::HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    );
    let identity = super::super::historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 2);
    assert_eq!(
        persisted.next_stage(),
        Some(HistoricalV3RankStage::SemanticCensus)
    );
    drop(persisted);
    let retried = run_historical_v3_semantic_census_stage_with(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        successful_run,
    )
    .await
    .unwrap();
    assert!(matches!(
        retried,
        HistoricalV3SemanticCensusStageRun::Completed { resumed: false, .. }
    ));
}

fn successful_run<'a>(root: &'a Path, files: &'a [FileRecord]) -> SemanticRunFuture<'a> {
    Box::pin(async move {
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::from([(SemanticIndexerKind::Rust, semantic_index(root, files))]),
            failures: Vec::new(),
        })
    })
}

fn panic_run<'a>(_root: &'a Path, _files: &'a [FileRecord]) -> SemanticRunFuture<'a> {
    Box::pin(async move { panic!("committed semantic resume invoked an indexer") })
}

fn terminal_run<'a>(_root: &'a Path, _files: &'a [FileRecord]) -> SemanticRunFuture<'a> {
    Box::pin(async move {
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::new(),
            failures: vec![SemanticIndexerRunFailure {
                kind: SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                phase: SemanticIndexerRunPhase::RepositoryValidation,
                indexer: Some(SemanticIndexerKind::Rust),
                detail: "synthetic unsupported project".to_string(),
                process: None,
            }],
        })
    })
}

fn operational_run<'a>(_root: &'a Path, _files: &'a [FileRecord]) -> SemanticRunFuture<'a> {
    Box::pin(async move {
        Err(SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            phase: SemanticIndexerRunPhase::InstallationVerification,
            indexer: Some(SemanticIndexerKind::Rust),
            detail: "synthetic indexer unavailable".to_string(),
            process: None,
        })
    })
}

fn semantic_index(root: &Path, files: &[FileRecord]) -> SemanticIndex {
    let file = &files[0];
    let method = &file.methods[0];
    let repository_path = Path::new(&file.file_path)
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    let document = RepositoryPath(repository_path);
    let method_id = SemanticSymbolId(format!("rust fixture {}", method.name));
    let surface_id = SemanticSymbolId("rust fixture Surface#".to_string());
    let method_start = method.source.find(&method.name).unwrap() as u32;
    let method_definition = SemanticLocation {
        document: document.clone(),
        range: range(0, method_start, method_start + method.name.len() as u32),
    };
    let surface_definition = SemanticLocation {
        document: document.clone(),
        range: range(0, 0, 3),
    };
    let method_symbol = semantic_symbol(
        method_id.clone(),
        Some(method.name.clone()),
        SemanticSymbolCategory::Callable,
        "function",
        method_definition.clone(),
    );
    let surface_symbol = semantic_symbol(
        surface_id.clone(),
        Some("Surface".to_string()),
        SemanticSymbolCategory::Type,
        "struct",
        surface_definition.clone(),
    );
    SemanticIndex {
        format_version: crate::semantic_index::SEMANTIC_INDEX_FORMAT_VERSION,
        repository_root: root.to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: vec![root.to_string_lossy().into_owned()],
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            invocations: vec![SemanticIndexerInvocation {
                arguments: vec![root.to_string_lossy().into_owned()],
                context: BTreeMap::from([("root".to_string(), root.display().to_string())]),
                contribution: SemanticIndexerContribution::CompleteIndex,
                output_sha256: "0".repeat(64),
            }],
            diagnostics: vec![format!("indexed {}", root.display())],
        },
        variant: crate::semantic_index::SemanticIndexVariant::Unqualified,
        documents: BTreeMap::from([(
            document.clone(),
            SemanticDocument {
                path: document,
                language: "rust".to_string(),
                position_encoding: SemanticPositionEncoding::Utf8,
                embedded_text: None,
                occurrences: vec![
                    SemanticOccurrence {
                        range: method_definition.range,
                        symbol: Some(method_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                        override_documentation: Vec::new(),
                    },
                    SemanticOccurrence {
                        range: surface_definition.range,
                        symbol: Some(surface_id.clone()),
                        roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                        override_documentation: Vec::new(),
                    },
                ],
            },
        )]),
        symbols: BTreeMap::from([(method_id, method_symbol), (surface_id, surface_symbol)]),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::new(),
    }
}

fn semantic_symbol(
    id: SemanticSymbolId,
    display_name: Option<String>,
    category: SemanticSymbolCategory,
    provider_name: &str,
    definition: SemanticLocation,
) -> SemanticSymbol {
    SemanticSymbol {
        provider_identity: id.0.clone(),
        id,
        display_name,
        kind: SemanticSymbolKind {
            category,
            provider_name: provider_name.to_string(),
        },
        documentation: Vec::new(),
        signatures: BTreeSet::new(),
        owner: None,
        definitions: BTreeSet::from([definition]),
        visibility: SemanticVisibility::Public,
        surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
        origin: SemanticSymbolOrigin::Repository,
        ambiguity_notes: Vec::new(),
    }
}

fn committed_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    journal: &Path,
) -> (HistoricalV3Materialization, HistoricalV3SourceCensus) {
    let identity = super::super::historical_v3_rank_identity(protocol, collection, 1).unwrap();
    let persisted = HistoricalV3RankJournal::open(journal, &identity).unwrap();
    let materialization = persisted.history()[0]
        .read_artifact::<HistoricalV3Materialization>()
        .unwrap()
        .unwrap();
    let source_census = persisted.history()[1]
        .read_artifact::<HistoricalV3SourceCensus>()
        .unwrap()
        .unwrap();
    (materialization, source_census)
}

fn range(line: u32, start: u32, end: u32) -> SemanticSourceRange {
    SemanticSourceRange {
        start: SemanticPosition {
            line,
            character: start,
        },
        end: SemanticPosition {
            line,
            character: end,
        },
    }
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_text(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
