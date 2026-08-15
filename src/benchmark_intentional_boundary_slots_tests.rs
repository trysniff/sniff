use super::*;
use sha2::{Digest, Sha256};

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

fn protocol() -> ValidatedIntentionalBoundaryProtocol {
    validate_intentional_boundary_protocol(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn task() -> IntentionalBoundaryFrameTask {
    prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn candidate(
    repository: &str,
    revision: &str,
    category: IntentionalBoundaryCategory,
    symbol: &str,
) -> IntentionalBoundaryCandidate {
    let repository_path = format!("src/{symbol}.rs");
    let candidate_id = hash_json(&(
        "sniffbench-intentional-boundary-candidate-v1",
        category,
        repository,
        revision,
        &repository_path,
        symbol,
    ));
    let mut evidence_kinds = match category {
        IntentionalBoundaryCategory::PublicWrapper => vec![
            BoundaryEvidenceKind::ExportedApiIdentity,
            BoundaryEvidenceKind::PublishedApiContract,
        ],
        IntentionalBoundaryCategory::Entrypoint => {
            vec![BoundaryEvidenceKind::RuntimeOrPackageManifest]
        }
        _ => unreachable!(),
    };
    evidence_kinds.sort();
    IntentionalBoundaryCandidate {
        candidate_id: format!("ibc-v1:{candidate_id}"),
        category,
        repository: repository.to_string(),
        revision: revision.to_string(),
        repository_path,
        parser_unit_id: format!("ibm-v1:{symbol}"),
        exact_symbol_identity: symbol.to_string(),
        evidence_kinds,
        evidence_ids: vec![format!("ibe-v1:{symbol}")],
    }
}

fn analyzed_record(task: &IntentionalBoundaryFrameTask) -> IntentionalBoundaryFrameRankRecord {
    let repository = &task.repositories[0].repository;
    let revision = "a".repeat(40);
    let mut candidates = vec![
        candidate(
            repository,
            &revision,
            IntentionalBoundaryCategory::PublicWrapper,
            "alpha",
        ),
        candidate(
            repository,
            &revision,
            IntentionalBoundaryCategory::PublicWrapper,
            "beta",
        ),
        candidate(
            repository,
            &revision,
            IntentionalBoundaryCategory::PublicWrapper,
            "gamma",
        ),
        candidate(
            repository,
            &revision,
            IntentionalBoundaryCategory::Entrypoint,
            "main",
        ),
    ];
    candidates.sort();
    let candidate_count_by_category = candidates.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<IntentionalBoundaryCategory, usize>, candidate| {
            *counts.entry(candidate.category).or_insert(0) += 1;
            counts
        },
    );
    let mut census = IntentionalBoundaryCandidateCensus {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION,
        candidate_contract: "sniffbench-intentional-boundary-candidate-census-v1".to_string(),
        protocol_sha256: task.protocol_sha256.clone(),
        repository: repository.clone(),
        revision,
        source_census_sha256: "1".repeat(64),
        semantic_census_sha256: "2".repeat(64),
        evidence_census_sha256: "3".repeat(64),
        candidates,
        candidate_count_by_category,
        candidate_census_sha256: String::new(),
    };
    census.candidate_census_sha256 =
        super::super::intentional_boundary_candidate::candidate_census_sha256(&census).unwrap();
    prepare_intentional_boundary_analyzed_rank(task, 1, &"4".repeat(64), census).unwrap()
}

fn frame(task: &IntentionalBoundaryFrameTask) -> IntentionalBoundaryCandidateFrame {
    let records = std::iter::once(analyzed_record(task))
        .chain(task.repositories.iter().skip(1).map(|repository| {
            prepare_intentional_boundary_excluded_rank(
                task,
                repository.population_rank,
                IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible,
                &"5".repeat(64),
            )
            .unwrap()
        }))
        .collect();
    super::super::intentional_boundary_frame::finish_candidate_frame(task, records).unwrap()
}

#[test]
fn selects_exactly_the_two_lowest_ranked_candidates_per_category() {
    let task = task();
    let frame = frame(&task);
    let protocol = protocol();

    let selection = select_intentional_boundary_slots(POLICY, &protocol, &task, &frame).unwrap();

    assert_eq!(selection.slots.len(), 16);
    assert_eq!(selection.selected_candidate_count, 3);
    assert_eq!(selection.unfilled_slot_count, 13);
    let mut expected = frame
        .candidates
        .iter()
        .filter(|candidate| candidate.category == IntentionalBoundaryCategory::PublicWrapper)
        .map(|candidate| {
            (
                candidate_rank_sha256(&selection.ranking_seed, candidate),
                candidate_identity(candidate),
                candidate.candidate_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    let selected = selection
        .slots
        .iter()
        .filter(|slot| slot.category == IntentionalBoundaryCategory::PublicWrapper)
        .map(|slot| match &slot.outcome {
            IntentionalBoundarySlotOutcome::Selected { candidate_id, .. } => candidate_id,
            IntentionalBoundarySlotOutcome::Unfilled { .. } => panic!("wrapper slot was unfilled"),
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, vec![&expected[0].2, &expected[1].2]);
}

#[test]
fn missing_candidates_close_slots_without_cross_category_backfill() {
    let task = task();
    let frame = frame(&task);
    let protocol = protocol();

    let selection = select_intentional_boundary_slots(POLICY, &protocol, &task, &frame).unwrap();
    let entrypoint_slots = selection
        .slots
        .iter()
        .filter(|slot| slot.category == IntentionalBoundaryCategory::Entrypoint)
        .collect::<Vec<_>>();

    assert!(matches!(
        entrypoint_slots[0].outcome,
        IntentionalBoundarySlotOutcome::Selected { .. }
    ));
    assert_eq!(
        entrypoint_slots[1].outcome,
        IntentionalBoundarySlotOutcome::Unfilled {
            available_candidate_count: 1
        }
    );
}

#[test]
fn validation_rejects_slot_policy_and_selection_tampering() {
    let task = task();
    let frame = frame(&task);
    let protocol = protocol();
    let mut selection =
        select_intentional_boundary_slots(POLICY, &protocol, &task, &frame).unwrap();
    selection.slots.swap(0, 1);
    assert!(
        validate_intentional_boundary_slot_selection(POLICY, &protocol, &task, &frame, &selection,)
            .unwrap_err()
            .contains("changed")
    );

    let mut policy: serde_json::Value = serde_json::from_slice(POLICY).unwrap();
    policy["ranking_seed"] = serde_json::json!("changed-after-frame");
    assert!(
        select_intentional_boundary_slots(
            &serde_json::to_vec(&policy).unwrap(),
            &protocol,
            &task,
            &frame,
        )
        .unwrap_err()
        .contains("frozen protocol")
    );
}

fn hash_json(value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}
