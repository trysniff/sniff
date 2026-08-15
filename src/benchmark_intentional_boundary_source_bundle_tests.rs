use super::*;
use std::collections::BTreeMap;
use std::process::Command;
use tempfile::TempDir;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

struct Fixture {
    repository: TempDir,
    protocol: ValidatedIntentionalBoundaryProtocol,
    task: IntentionalBoundaryFrameTask,
    frame: IntentionalBoundaryCandidateFrame,
    selection: IntentionalBoundarySlotSelection,
    inventory: IntentionalBoundaryRepositoryInventory,
    source_census: IntentionalBoundarySourceCensus,
    candidate_id: String,
    evidence_id: String,
    exact_symbol_identity: String,
}

impl Fixture {
    fn material(&self) -> IntentionalBoundarySourceMaterial<'_> {
        IntentionalBoundarySourceMaterial {
            root: self.repository.path(),
            inventory: &self.inventory,
            source_census: &self.source_census,
        }
    }
}

fn fixture() -> Fixture {
    let protocol =
        validate_intentional_boundary_protocol(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap();
    let task =
        prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap();
    let repository_name = task.repositories[0].repository.clone();
    let (repository, revision) = repository(&repository_name);
    let inventory =
        inventory_intentional_boundary_repository(&repository_name, &revision, repository.path())
            .unwrap();
    let source_census = census_intentional_boundary_repository(
        &repository_name,
        &revision,
        repository.path(),
        &inventory,
    )
    .unwrap();
    let source_file = source_census
        .source_files
        .iter()
        .find(|file| file.repository_path == "src/main.rs")
        .unwrap();
    let method = source_file
        .methods
        .iter()
        .find(|method| method.symbol_name == "launch")
        .unwrap();
    let exact_symbol_identity = "scip-rust fixture launch().".to_string();
    let evidence_id = "ibe-v1:runtime-manifest".to_string();
    let candidate_id = format!(
        "ibc-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-candidate-v1",
            IntentionalBoundaryCategory::Entrypoint,
            &repository_name,
            &revision,
            &source_file.repository_path,
            &exact_symbol_identity,
        ))
    );
    let candidate = IntentionalBoundaryCandidate {
        candidate_id: candidate_id.clone(),
        category: IntentionalBoundaryCategory::Entrypoint,
        repository: repository_name.clone(),
        revision: revision.clone(),
        repository_path: source_file.repository_path.clone(),
        parser_unit_id: method.parser_unit_id.clone(),
        exact_symbol_identity: exact_symbol_identity.clone(),
        evidence_kinds: vec![BoundaryEvidenceKind::RuntimeOrPackageManifest],
        evidence_ids: vec![evidence_id.clone()],
    };
    let mut candidate_count_by_category = BTreeMap::new();
    candidate_count_by_category.insert(IntentionalBoundaryCategory::Entrypoint, 1);
    let mut candidate_census = IntentionalBoundaryCandidateCensus {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION,
        candidate_contract: "sniffbench-intentional-boundary-candidate-census-v1".to_string(),
        protocol_sha256: task.protocol_sha256.clone(),
        repository: repository_name,
        revision,
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: "2".repeat(64),
        evidence_census_sha256: "3".repeat(64),
        candidates: vec![candidate],
        candidate_count_by_category,
        candidate_census_sha256: String::new(),
    };
    candidate_census.candidate_census_sha256 =
        super::super::intentional_boundary_candidate::candidate_census_sha256(&candidate_census)
            .unwrap();
    let analyzed = prepare_intentional_boundary_analyzed_rank(
        &task,
        1,
        &inventory.inventory_sha256,
        candidate_census,
    )
    .unwrap();
    let records = std::iter::once(analyzed)
        .chain(task.repositories.iter().skip(1).map(|repository| {
            prepare_intentional_boundary_excluded_rank(
                &task,
                repository.population_rank,
                IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible,
                &"5".repeat(64),
            )
            .unwrap()
        }))
        .collect();
    let frame =
        super::super::intentional_boundary_frame::finish_candidate_frame(&task, records).unwrap();
    let selection = select_intentional_boundary_slots(POLICY, &protocol, &task, &frame).unwrap();
    Fixture {
        repository,
        protocol,
        task,
        frame,
        selection,
        inventory,
        source_census,
        candidate_id,
        evidence_id,
        exact_symbol_identity,
    }
}

#[test]
fn creates_complete_source_only_context_without_candidate_evidence_leakage() {
    let fixture = fixture();
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("source-only");
    let materials = [fixture.material()];

    let bundle = create_intentional_boundary_source_bundle(
        POLICY,
        &fixture.protocol,
        &fixture.task,
        &fixture.frame,
        &fixture.selection,
        &materials,
        &output,
    )
    .unwrap();

    assert_eq!(bundle.selected_slot_count, 1);
    assert_eq!(bundle.review_items.len(), 1);
    assert_eq!(bundle.repositories.len(), 1);
    assert_eq!(
        bundle.repositories[0].tracked_entry_count,
        fixture.inventory.tracked_entries.len()
    );
    let encoded = serde_json::to_string(&bundle).unwrap();
    assert!(!encoded.contains(&fixture.candidate_id));
    assert!(!encoded.contains(&fixture.evidence_id));
    assert!(!encoded.contains(&fixture.exact_symbol_identity));
    assert!(!encoded.contains("entrypoint"));
    let item = &bundle.review_items[0];
    let source = fs::read_to_string(output.join(&item.source_artifact_path)).unwrap();
    assert!(source.contains("pub fn launch()"));
    assert!(
        bundle.repositories[0]
            .artifacts
            .iter()
            .any(|artifact| artifact.repository_path == "README.md")
    );
    validate_intentional_boundary_source_bundle(
        POLICY,
        &fixture.protocol,
        &fixture.task,
        &fixture.frame,
        &fixture.selection,
        &materials,
        &output,
        &bundle,
    )
    .unwrap();
    validate_intentional_boundary_source_bundle_artifacts(&output, &bundle).unwrap();

    fs::write(output.join("sniff-output.json"), "{}\n").unwrap();
    assert!(
        validate_intentional_boundary_source_bundle_artifacts(&output, &bundle)
            .unwrap_err()
            .contains("unexpected or missing files")
    );
}

#[test]
fn rejects_artifact_tampering_and_refuses_to_overwrite_a_bundle() {
    let fixture = fixture();
    let output_parent = tempfile::tempdir().unwrap();
    let output = output_parent.path().join("source-only");
    let materials = [fixture.material()];
    let bundle = create_intentional_boundary_source_bundle(
        POLICY,
        &fixture.protocol,
        &fixture.task,
        &fixture.frame,
        &fixture.selection,
        &materials,
        &output,
    )
    .unwrap();

    assert!(
        create_intentional_boundary_source_bundle(
            POLICY,
            &fixture.protocol,
            &fixture.task,
            &fixture.frame,
            &fixture.selection,
            &materials,
            &output,
        )
        .unwrap_err()
        .contains("already exists")
    );
    let artifact = &bundle.review_items[0].source_artifact_path;
    fs::write(output.join(artifact), "tampered\n").unwrap();
    assert!(
        validate_intentional_boundary_source_bundle(
            POLICY,
            &fixture.protocol,
            &fixture.task,
            &fixture.frame,
            &fixture.selection,
            &materials,
            &output,
            &bundle,
        )
        .unwrap_err()
        .contains("artifact changed")
    );
}

fn repository(repository: &str) -> (TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(
        root.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            &format!("https://{repository}.git"),
        ],
    );
    fs::create_dir_all(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/main.rs"),
        "pub fn launch() -> u8 { 7 }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(root.path().join("README.md"), "review context\n").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    (root, revision)
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn hash_json(value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}
