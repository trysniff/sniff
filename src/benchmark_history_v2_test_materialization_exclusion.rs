use super::history_v2_materialization_git::{
    require_oid, require_sha256, validate_git_command_rejection_evidence,
};
use super::{
    HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
    HistoricalV2TestMaterializationExclusion, HistoricalV2TestMaterializationExclusionEvidence,
    HistoricalV2TestMaterializationExclusionReason, HistoricalV2TestMaterializationSide,
};
use sha2::{Digest, Sha256};

const EXCLUSION_CONTRACT: &str =
    "sniffbench-historical-v2-identical-test-materialization-exclusion-v1";

pub fn validate_historical_v2_test_materialization_exclusion(
    exclusion: &HistoricalV2TestMaterializationExclusion,
) -> Result<(), String> {
    require_sha256(&exclusion.materialization_sha256)?;
    require_sha256(&exclusion.test_patch_sha256)?;
    if exclusion.schema_version != HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION
        || exclusion.exclusion_contract != EXCLUSION_CONTRACT
        || exclusion.exclusion_sha256 != exclusion_sha256(exclusion)?
        || !matching_evidence(exclusion)
    {
        return Err("historical-v2 test materialization exclusion commitment changed".to_string());
    }
    validate_evidence(exclusion)
}

pub(super) fn seal_test_materialization_exclusion(
    materialization_sha256: &str,
    test_patch_sha256: &str,
    reason: HistoricalV2TestMaterializationExclusionReason,
    evidence: HistoricalV2TestMaterializationExclusionEvidence,
) -> Result<HistoricalV2TestMaterializationExclusion, HistoricalV2SlotStageError> {
    let mut exclusion = HistoricalV2TestMaterializationExclusion {
        schema_version: HISTORICAL_V2_TEST_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        materialization_sha256: materialization_sha256.to_string(),
        test_patch_sha256: test_patch_sha256.to_string(),
        reason,
        evidence,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion).map_err(invalid)?;
    validate_historical_v2_test_materialization_exclusion(&exclusion).map_err(invalid)?;
    Ok(exclusion)
}

fn matching_evidence(exclusion: &HistoricalV2TestMaterializationExclusion) -> bool {
    use HistoricalV2TestMaterializationExclusionEvidence as Evidence;
    use HistoricalV2TestMaterializationExclusionReason as Reason;

    matches!(
        (&exclusion.reason, &exclusion.evidence),
        (
            Reason::TestPatchDoesNotApply,
            Evidence::TestPatchRejected { .. }
        ) | (
            Reason::TestPatchProducesNoTreeChange,
            Evidence::TestPatchProducesNoTreeChange { .. }
        )
    )
}

fn validate_evidence(exclusion: &HistoricalV2TestMaterializationExclusion) -> Result<(), String> {
    use HistoricalV2TestMaterializationExclusionEvidence as Evidence;

    match &exclusion.evidence {
        Evidence::TestPatchRejected {
            test_patch_sha256,
            rejections,
        } => {
            if test_patch_sha256 != &exclusion.test_patch_sha256
                || rejections.is_empty()
                || !rejections
                    .windows(2)
                    .all(|pair| pair[0].side < pair[1].side)
            {
                return Err("historical-v2 test patch rejection evidence changed".to_string());
            }
            for rejection in rejections {
                validate_git_command_rejection_evidence(&rejection.command)?;
            }
        }
        Evidence::TestPatchProducesNoTreeChange {
            test_patch_sha256,
            unchanged_sides,
            base_input_tree_oid,
            base_test_tree_oid,
            patched_input_tree_oid,
            patched_test_tree_oid,
        } => {
            for oid in [
                base_input_tree_oid,
                base_test_tree_oid,
                patched_input_tree_oid,
                patched_test_tree_oid,
            ] {
                require_oid(oid)?;
            }
            let mut expected = Vec::new();
            if base_input_tree_oid == base_test_tree_oid {
                expected.push(HistoricalV2TestMaterializationSide::Base);
            }
            if patched_input_tree_oid == patched_test_tree_oid {
                expected.push(HistoricalV2TestMaterializationSide::Patched);
            }
            if test_patch_sha256 != &exclusion.test_patch_sha256
                || expected.is_empty()
                || unchanged_sides != &expected
            {
                return Err("historical-v2 no-change test patch evidence changed".to_string());
            }
        }
    }
    Ok(())
}

fn exclusion_sha256(value: &HistoricalV2TestMaterializationExclusion) -> Result<String, String> {
    let mut committed = value.clone();
    committed.exclusion_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            format!("failed to commit historical-v2 test materialization exclusion: {error}")
        })
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::TestMaterialization,
        kind: HistoricalV2SlotStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::HistoricalV2TestPatchRejectionEvidence;
    use super::*;

    #[test]
    fn no_change_evidence_must_equal_the_tree_comparison() {
        let mut exclusion = seal_test_materialization_exclusion(
            &digest('1'),
            &digest('2'),
            HistoricalV2TestMaterializationExclusionReason::TestPatchProducesNoTreeChange,
            HistoricalV2TestMaterializationExclusionEvidence::TestPatchProducesNoTreeChange {
                test_patch_sha256: digest('2'),
                unchanged_sides: vec![HistoricalV2TestMaterializationSide::Base],
                base_input_tree_oid: oid('a'),
                base_test_tree_oid: oid('a'),
                patched_input_tree_oid: oid('b'),
                patched_test_tree_oid: oid('c'),
            },
        )
        .unwrap();
        validate_historical_v2_test_materialization_exclusion(&exclusion).unwrap();

        let HistoricalV2TestMaterializationExclusionEvidence::TestPatchProducesNoTreeChange {
            unchanged_sides,
            ..
        } = &mut exclusion.evidence
        else {
            unreachable!();
        };
        unchanged_sides.push(HistoricalV2TestMaterializationSide::Patched);
        assert!(validate_historical_v2_test_materialization_exclusion(&exclusion).is_err());
    }

    #[test]
    fn rejected_sides_must_be_nonempty_sorted_and_unique() {
        let error = seal_test_materialization_exclusion(
            &digest('1'),
            &digest('2'),
            HistoricalV2TestMaterializationExclusionReason::TestPatchDoesNotApply,
            HistoricalV2TestMaterializationExclusionEvidence::TestPatchRejected {
                test_patch_sha256: digest('2'),
                rejections: vec![
                    rejection(HistoricalV2TestMaterializationSide::Patched),
                    rejection(HistoricalV2TestMaterializationSide::Base),
                ],
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    }

    fn rejection(
        side: HistoricalV2TestMaterializationSide,
    ) -> HistoricalV2TestPatchRejectionEvidence {
        HistoricalV2TestPatchRejectionEvidence {
            side,
            command: super::super::HistoricalV2GitCommandRejectionEvidence {
                command_label: "git apply --check".to_string(),
                exit_code: Some(1),
                stdout_sha256: digest('3'),
                stderr_sha256: digest('4'),
                retained_stderr: "rejected".to_string(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
        }
    }

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn oid(character: char) -> String {
        std::iter::repeat_n(character, 40).collect()
    }
}
