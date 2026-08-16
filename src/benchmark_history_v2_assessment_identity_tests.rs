use super::*;
use crate::benchmark::{
    HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION, HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION,
    HistoricalV2Materialization, HistoricalV2SelectedPayload, HistoricalV2Slot,
    HistoricalV2SlotOutcome, HistoricalV2SlotSelection,
};

#[test]
fn assessment_identity_hash_binds_every_projected_field() {
    let identity = seal_identity(identity()).expect("seal identity");
    assert_eq!(
        identity.assessment_identity_sha256,
        identity_sha256(&identity).expect("hash identity")
    );

    let mut changed = identity.clone();
    changed.canonical_repository = "example/other".to_string();
    assert_ne!(
        identity.assessment_identity_sha256,
        identity_sha256(&changed).expect("hash changed identity")
    );
}

#[test]
fn assessment_identity_cannot_be_resealed() {
    let identity = seal_identity(identity()).expect("seal identity");
    assert!(seal_identity(identity).is_err());
}

#[test]
fn selected_slot_must_be_selected_and_exact() {
    let mut selection = selection(HistoricalV2SlotOutcome::Unfilled);
    assert!(selected_slot(&selection, "rust", 1).is_err());

    selection.slots[0].outcome = HistoricalV2SlotOutcome::Selected {
        global_row_index: 9,
        instance_id: "instance".to_string(),
        canonical_repository: "example/repo".to_string(),
        pull_number: 7,
        base_revision: "1".repeat(40),
        patch_sha256: "2".repeat(64),
        rank_sha256: "3".repeat(64),
    };
    let slot = selected_slot(&selection, "rust", 1).expect("selected slot");
    assert_eq!(slot.global_row_index, 9);
    assert!(selected_slot(&selection, "python", 1).is_err());
}

#[test]
fn slot_lineage_rejects_a_different_repository() {
    let selection = selection(HistoricalV2SlotOutcome::Selected {
        global_row_index: 9,
        instance_id: "instance".to_string(),
        canonical_repository: "example/repo".to_string(),
        pull_number: 7,
        base_revision: "1".repeat(40),
        patch_sha256: digest('7'),
        rank_sha256: digest('3'),
    });
    let slot = selected_slot(&selection, "rust", 1).expect("selected slot");
    let payload = payload();
    let materialization = materialization();
    assert!(validate_slot_lineage(&slot, &payload, &materialization).is_ok());

    let mut changed = materialization;
    changed.canonical_repository = "example/other".to_string();
    assert!(validate_slot_lineage(&slot, &payload, &changed).is_err());
}

fn identity() -> HistoricalV2AssessmentIdentity {
    HistoricalV2AssessmentIdentity {
        schema_version: HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION,
        assessment_identity_contract: ASSESSMENT_IDENTITY_CONTRACT.to_string(),
        protocol_sha256: digest('0'),
        frame_sha256: digest('1'),
        exclusion_manifest_sha256: digest('2'),
        selection_sha256: digest('3'),
        payloads_sha256: digest('4'),
        language: "rust".to_string(),
        slot_number: 1,
        global_row_index: 9,
        instance_id: "instance".to_string(),
        canonical_repository: "example/repo".to_string(),
        pull_number: 7,
        base_revision: "1".repeat(40),
        rank_sha256: digest('5'),
        payload_sha256: digest('6'),
        historical_patch_sha256: digest('7'),
        install_config_sha256: Some(digest('8')),
        test_patch_sha256: Some(digest('9')),
        materialization_sha256: digest('a'),
        test_materialization_sha256: Some(digest('b')),
        source_census_sha256: digest('c'),
        base_source_snapshot_sha256: digest('d'),
        patched_source_snapshot_sha256: digest('e'),
        semantic_census_sha256: digest('f'),
        base_semantic_snapshot_sha256: digest('0'),
        patched_semantic_snapshot_sha256: digest('1'),
        assessment_identity_sha256: String::new(),
    }
}

fn selection(outcome: HistoricalV2SlotOutcome) -> HistoricalV2SlotSelection {
    HistoricalV2SlotSelection {
        schema_version: HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION,
        selection_contract: "selection".to_string(),
        protocol_sha256: digest('0'),
        frame_sha256: digest('1'),
        exclusion_manifest_sha256: digest('2'),
        ranking_seed: "seed".to_string(),
        ranking_contract: "rank".to_string(),
        slots_per_language: 1,
        candidate_decisions: Vec::new(),
        slots: vec![HistoricalV2Slot {
            language: "rust".to_string(),
            slot_number: 1,
            outcome,
        }],
        selected_count: 0,
        unfilled_slot_count: 1,
        excluded_partition_count: 0,
        repository_collision_count: 0,
        language_capacity_count: 0,
        selection_sha256: digest('3'),
    }
}

fn materialization() -> HistoricalV2Materialization {
    HistoricalV2Materialization {
        schema_version: HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION,
        materialization_contract: "materialization".to_string(),
        canonical_repository: "example/repo".to_string(),
        base_revision: "1".repeat(40),
        object_format: "sha1".to_string(),
        base_tree_oid: "2".repeat(40),
        historical_patch_sha256: digest('7'),
        patched_tree_oid: "3".repeat(40),
        patched_commit_oid: "4".repeat(40),
        materialization_sha256: digest('a'),
    }
}

fn payload() -> HistoricalV2SelectedPayload {
    HistoricalV2SelectedPayload {
        language: "rust".to_string(),
        slot_number: 1,
        source_shard_index: 0,
        source_row_index: 9,
        global_row_index: 9,
        instance_id: "instance".to_string(),
        patch: "patch".to_string(),
        patch_sha256: digest('7'),
        install_config: None,
        install_config_sha256: None,
        test_patch: None,
        test_patch_sha256: None,
        payload_sha256: digest('6'),
    }
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}
