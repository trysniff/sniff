use super::*;
use crate::benchmark::{
    HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
    HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION, HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION,
    HistoricalV2ExecutionSide, HistoricalV2IdenticalTestExclusionReason,
    HistoricalV2PublicSurfaceDelta, HistoricalV2QualificationExclusionReason,
    HistoricalV2TestRecipeExclusionReason,
};

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

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}
