use super::{
    HistoricalV2AssessmentContract, HistoricalV2DatasetContract, HistoricalV2DatasetShard,
    HistoricalV2MethodBounds, HistoricalV2Protocol, HistoricalV2ReviewContract,
    HistoricalV2SelectionContract, ValidatedHistoricalV2Protocol,
};
use sha2::{Digest, Sha256};

pub const HISTORICAL_V2_PROTOCOL_SCHEMA_VERSION: u32 = 1;
const PROTOCOL_ID: &str = "sniffbench-historical-v2-protocol-v1";
const DATASET_ID: &str = "nebius/SWE-rebench-V2-PRs";
const DATASET_REVISION: &str = "40faf2c1bb160de625f3c3270ac9d62ea45f3f9c";
const PRECOMMIT_PARENT_REVISION: &str = "3fdd5f8f0ec5b64f7c16c997f2492acd75275952";
const RANK_CONTRACT: &str = "sniffbench-historical-v2-rank-v1";
const SLOTS_PER_LANGUAGE: usize = 128;
const MINIMUM_ACCEPTED_PER_LANGUAGE: usize = 40;
const REQUIRED_LANGUAGES: [&str; 6] =
    ["go", "javascript", "kotlin", "python", "rust", "typescript"];

pub fn validate_historical_v2_protocol(
    protocol_bytes: &[u8],
) -> Result<ValidatedHistoricalV2Protocol, String> {
    let protocol: HistoricalV2Protocol = serde_json::from_slice(protocol_bytes)
        .map_err(|error| format!("failed to parse historical-v2 protocol: {error}"))?;
    if protocol.schema_version != HISTORICAL_V2_PROTOCOL_SCHEMA_VERSION
        || protocol.protocol_id != PROTOCOL_ID
        || protocol.prepared_at.trim().is_empty()
        || protocol.precommit_parent_revision != PRECOMMIT_PARENT_REVISION
        || !protocol.no_fallbacks
    {
        return Err("historical-v2 protocol identity or fallback mode changed".to_string());
    }
    require_git_revision(
        "historical-v2 precommit_parent_revision",
        &protocol.precommit_parent_revision,
    )?;
    if protocol.dataset != expected_dataset_contract() {
        return Err("historical-v2 dataset or field-projection contract changed".to_string());
    }
    if protocol.selection != expected_selection_contract() {
        return Err("historical-v2 fixed-slot selection contract changed".to_string());
    }
    if protocol.assessment != expected_assessment_contract() {
        return Err("historical-v2 repository assessment contract changed".to_string());
    }
    if protocol.review != expected_review_contract() {
        return Err("historical-v2 independent-review contract changed".to_string());
    }
    Ok(ValidatedHistoricalV2Protocol {
        protocol,
        protocol_sha256: sha256(protocol_bytes),
    })
}

fn expected_dataset_contract() -> HistoricalV2DatasetContract {
    HistoricalV2DatasetContract {
        dataset_id: DATASET_ID.to_string(),
        revision: DATASET_REVISION.to_string(),
        dataset_license: "CC-BY-4.0".to_string(),
        expected_rows: 126_300,
        shards: vec![
            shard(
                "data/train-00000-of-00003.parquet",
                920_026_603,
                "8faffd024e34e157308212912887ffd393e04aa6760d7fb1438b8f7c31ce0e0e",
            ),
            shard(
                "data/train-00001-of-00003.parquet",
                948_535_559,
                "f2bc9061699bb7c5ddd83af1498737008c55ff699dac999d31a1f39b8ce6083d",
            ),
            shard(
                "data/train-00002-of-00003.parquet",
                817_735_990,
                "7f33795ee41acd6974f409a0240cef165b385e088ecd431803b1ea1059357f52",
            ),
        ],
        projected_selection_fields: strings(&[
            "base_commit",
            "created_at",
            "instance_id",
            "license",
            "patch",
            "pull_number",
            "repo",
        ]),
        post_selection_reproducibility_fields: strings(&["install_config", "test_patch"]),
        permanently_forbidden_fields: strings(&[
            "FAIL_TO_PASS",
            "PASS_TO_PASS",
            "hints_text",
            "interface",
            "meta",
            "pr_description",
            "problem_statement",
        ]),
        unlisted_fields_fail_closed: true,
        dataset_judgments_are_not_evidence: true,
    }
}

fn expected_selection_contract() -> HistoricalV2SelectionContract {
    HistoricalV2SelectionContract {
        supported_languages: strings(&REQUIRED_LANGUAGES),
        slots_per_language: SLOTS_PER_LANGUAGE,
        total_slots: SLOTS_PER_LANGUAGE * REQUIRED_LANGUAGES.len(),
        ranking_contract: format!(
            "sha256({RANK_CONTRACT}\\0 || ranking_seed || \\0 || canonical_repository || \\0 || pull_number || \\0 || base_revision || \\0 || patch_sha256), ascending digest then canonical identity"
        ),
        ranking_seed: PRECOMMIT_PARENT_REVISION.to_string(),
        language_derived_from_patch_and_git_objects: true,
        changed_methods_derived_from_compiler_census: true,
        net_non_whitespace_production_reduction_required: true,
        one_slot_per_repository: true,
        one_slot_per_pull_request: true,
        selection_committed_before_repository_assessment: true,
        failed_candidate_closes_slot: true,
        backfill_forbidden: true,
        model_access_forbidden: true,
        sniff_output_access_forbidden: true,
        repository_method_bounds: HistoricalV2MethodBounds {
            minimum: 20,
            maximum: 500,
        },
        excluded_partitions: strings(&[
            "blind-oss-v1",
            "historical-v1",
            "intentional-boundary-v1",
            "slopcodebench",
            "synthetic-gold-v1",
            "trim",
        ]),
        exact_exclusion_artifacts_required: true,
    }
}

fn expected_assessment_contract() -> HistoricalV2AssessmentContract {
    HistoricalV2AssessmentContract {
        complete_git_objects_required: true,
        exact_base_revision_required: true,
        patch_must_apply_cleanly: true,
        patched_tree_identity_committed: true,
        source_and_test_inventory_committed: true,
        compiler_semantic_census_required: true,
        same_test_recipe_on_both_revisions: true,
        test_patch_may_open_only_after_slot_freeze: true,
        test_patch_applied_identically_to_both_revisions: true,
        dataset_recipe_is_untrusted: true,
        hardened_sandbox_required: true,
        host_secrets_and_filesystem_hidden: true,
        public_surface_must_be_preserved: true,
        behavior_change_closes_slot: true,
        typed_terminal_exclusions_required: true,
        every_slot_checkpointed: true,
    }
}

fn expected_review_contract() -> HistoricalV2ReviewContract {
    HistoricalV2ReviewContract {
        source_only_review: true,
        independent_reviewers: 2,
        reviewers_must_not_see_sniff_output: true,
        reviewers_must_not_see_each_other_labels: true,
        exact_before_slop_mechanism_required: true,
        exact_after_removal_required: true,
        historical_patch_must_match_simpler_counterfactual: true,
        behavior_evidence_required: true,
        distinct_dispute_resolver: true,
        rejected_label_closes_slot: true,
        minimum_accepted_per_language: MINIMUM_ACCEPTED_PER_LANGUAGE,
        minimum_total_accepted: MINIMUM_ACCEPTED_PER_LANGUAGE * REQUIRED_LANGUAGES.len(),
        underfilled_language_fails_release: true,
    }
}

fn shard(path: &str, size_bytes: u64, lfs_sha256: &str) -> HistoricalV2DatasetShard {
    HistoricalV2DatasetShard {
        path: path.to_string(),
        size_bytes,
        lfs_sha256: lfs_sha256.to_string(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn require_git_revision(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "{label} must be a complete 40-character Git revision"
        ))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
