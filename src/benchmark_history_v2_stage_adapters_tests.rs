use super::*;
use crate::benchmark::{
    HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
    HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
    HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION, HistoricalV2ExecutionSide,
    HistoricalV2IdenticalTestExclusionReason, HistoricalV2MaterializationExclusion,
    HistoricalV2MaterializationExclusionEvidence, HistoricalV2MaterializationExclusionReason,
    HistoricalV2PublicSurfaceDelta, HistoricalV2QualificationExclusionReason,
    HistoricalV2SelectedPayload, HistoricalV2SourceCensusExclusion,
    HistoricalV2SourceCensusExclusionReason, HistoricalV2TestMaterializationExclusion,
    HistoricalV2TestMaterializationExclusionEvidence,
    HistoricalV2TestMaterializationExclusionReason, HistoricalV2TestMaterializationSide,
    HistoricalV2TestRecipeExclusionReason,
};

#[test]
fn selected_slot_payload_envelope_binds_the_complete_resume_identity() {
    let artifact = seal_selected_slot_payload(HistoricalV2SelectedSlotPayloadArtifact {
        schema_version: HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION,
        artifact_contract: SELECTED_PAYLOAD_CONTRACT.to_string(),
        selection_sha256: digest('1'),
        language: "rust".to_string(),
        slot_number: 1,
        global_row_index: 7,
        instance_id: "owner__repo-1".to_string(),
        canonical_repository: "github.com/owner/repo".to_string(),
        pull_number: 1,
        base_revision: "a".repeat(40),
        rank_sha256: digest('2'),
        payload: payload(),
        artifact_sha256: String::new(),
    })
    .unwrap();
    validate_selected_slot_payload(&artifact).unwrap();

    let mut changed = artifact;
    changed.base_revision = "b".repeat(40);
    assert!(validate_selected_slot_payload(&changed).is_err());
}

#[test]
fn no_test_patch_artifact_is_not_an_uncommitted_skip() {
    let artifact = seal_no_test_patch(HistoricalV2NoTestPatchArtifact {
        schema_version: HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION,
        artifact_contract: NO_TEST_PATCH_CONTRACT.to_string(),
        selected_slot_payload_sha256: digest('1'),
        materialization_sha256: digest('2'),
        language: "rust".to_string(),
        slot_number: 1,
        canonical_repository: "github.com/owner/repo".to_string(),
        artifact_sha256: String::new(),
    })
    .unwrap();
    assert_ne!(artifact.artifact_sha256, digest('1'));
    assert_ne!(artifact.artifact_sha256, digest('2'));
}

#[test]
fn materialization_exclusion_keeps_its_exact_evidence_commitment() {
    let exclusion = HistoricalV2MaterializationExclusion {
        schema_version: HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: "fixture".to_string(),
        canonical_repository: "github.com/owner/repo".to_string(),
        base_revision: "a".repeat(40),
        historical_patch_sha256: digest('3'),
        reason: HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
        evidence: HistoricalV2MaterializationExclusionEvidence::RepositoryProbe {
            url: "https://github.com/owner/repo.git/info/refs?service=git-upload-pack".to_string(),
            status: 404,
        },
        exclusion_sha256: digest('9'),
    };
    assert_eq!(
        materialization_exclusion_outcome(&exclusion),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::Materialization(
                HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
            ),
            artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
            artifact_sha256: digest('9'),
        }
    );
}

#[test]
fn test_materialization_exclusion_keeps_its_exact_evidence_commitment() {
    let exclusion = HistoricalV2TestMaterializationExclusion {
        schema_version: HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: "fixture".to_string(),
        materialization_sha256: digest('1'),
        test_patch_sha256: digest('2'),
        reason: HistoricalV2TestMaterializationExclusionReason::TestPatchProducesNoTreeChange,
        evidence: HistoricalV2TestMaterializationExclusionEvidence::TestPatchProducesNoTreeChange {
            test_patch_sha256: digest('2'),
            unchanged_sides: vec![HistoricalV2TestMaterializationSide::Base],
            base_input_tree_oid: "a".repeat(40),
            base_test_tree_oid: "a".repeat(40),
            patched_input_tree_oid: "b".repeat(40),
            patched_test_tree_oid: "c".repeat(40),
        },
        exclusion_sha256: digest('8'),
    };
    assert_eq!(
        test_materialization_exclusion_outcome(&exclusion),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::TestMaterialization(
                HistoricalV2TestMaterializationExclusionReason::TestPatchProducesNoTreeChange,
            ),
            artifact_kind: HistoricalV2StageArtifactKind::TestMaterializationExclusion,
            artifact_sha256: digest('8'),
        }
    );
}

#[test]
fn source_census_exclusion_keeps_all_typed_reasons_and_its_evidence_commitment() {
    let exclusion = HistoricalV2SourceCensusExclusion {
        schema_version: HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: "fixture".to_string(),
        materialization_sha256: digest('1'),
        reasons: vec![
            HistoricalV2SourceCensusExclusionReason::SupportedSourceIsNotUtf8,
            HistoricalV2SourceCensusExclusionReason::SupportedSourceCannotBeParsed,
        ],
        failures: Vec::new(),
        exclusion_sha256: digest('7'),
    };
    assert_eq!(
        source_census_exclusion_outcome(&exclusion),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::SourceCensus(exclusion.reasons.clone()),
            artifact_kind: HistoricalV2StageArtifactKind::SourceCensusExclusion,
            artifact_sha256: digest('7'),
        }
    );
}

#[test]
fn qualification_exclusion_keeps_its_exact_artifact_commitment() {
    let qualification = qualification(HistoricalV2QualificationOutcome::Excluded {
        reasons: vec![HistoricalV2QualificationExclusionReason::NoNetProductionReduction],
    });
    assert_eq!(
        qualification_outcome(&qualification),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
                HistoricalV2QualificationExclusionReason::NoNetProductionReduction,
            ]),
            artifact_kind: HistoricalV2StageArtifactKind::Qualification,
            artifact_sha256: digest('a'),
        }
    );
}

#[test]
fn recipe_exclusion_keeps_its_exact_artifact_commitment() {
    let recipe = HistoricalV2TestRecipe {
        schema_version: HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION,
        test_recipe_contract: "fixture".to_string(),
        assessment_identity_sha256: digest('1'),
        qualification_sha256: digest('2'),
        install_config_sha256: None,
        outcome: HistoricalV2TestRecipeOutcome::Excluded {
            reason: HistoricalV2TestRecipeExclusionReason::MissingInstallConfig,
        },
        test_recipe_sha256: digest('b'),
    };
    assert_eq!(
        test_recipe_outcome(&recipe),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::TestRecipe(
                HistoricalV2TestRecipeExclusionReason::MissingInstallConfig,
            ),
            artifact_kind: HistoricalV2StageArtifactKind::TestRecipe,
            artifact_sha256: digest('b'),
        }
    );
}

#[test]
fn execution_exclusion_keeps_command_evidence_in_the_committed_artifact() {
    let execution = HistoricalV2IdenticalTestExecution {
        schema_version: HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
        execution_contract: "fixture".to_string(),
        plan_sha256: digest('1'),
        image_id: format!("sha256:{}", digest('2')),
        events: Vec::new(),
        outcome: HistoricalV2IdenticalTestOutcome::Excluded {
            reason: HistoricalV2IdenticalTestExclusionReason::TestCommandsFailed {
                side: HistoricalV2ExecutionSide::Base,
            },
        },
        execution_sha256: digest('c'),
    };
    assert_eq!(
        identical_test_outcome(&execution),
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::IdenticalTests(
                HistoricalV2IdenticalTestExclusionReason::TestCommandsFailed {
                    side: HistoricalV2ExecutionSide::Base,
                },
            ),
            artifact_kind: HistoricalV2StageArtifactKind::IdenticalTestExecution,
            artifact_sha256: digest('c'),
        }
    );
}

fn qualification(outcome: HistoricalV2QualificationOutcome) -> HistoricalV2Qualification {
    HistoricalV2Qualification {
        schema_version: HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION,
        qualification_contract: "fixture".to_string(),
        assessment_identity_sha256: digest('1'),
        language: "rust".to_string(),
        slot_number: 1,
        patch_changed_paths: Vec::new(),
        git_changed_paths: Vec::new(),
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
            delta_sha256: digest('2'),
        },
        outcome,
        qualification_sha256: digest('a'),
    }
}

fn payload() -> HistoricalV2SelectedPayload {
    HistoricalV2SelectedPayload {
        language: "rust".to_string(),
        slot_number: 1,
        source_shard_index: 0,
        source_row_index: 0,
        global_row_index: 7,
        instance_id: "owner__repo-1".to_string(),
        patch: "diff --git a/src/lib.rs b/src/lib.rs".to_string(),
        patch_sha256: digest('3'),
        install_config: None,
        install_config_sha256: None,
        test_patch: None,
        test_patch_sha256: None,
        payload_sha256: digest('4'),
    }
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}
