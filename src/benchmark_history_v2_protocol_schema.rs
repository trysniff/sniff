use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2DatasetShard {
    pub path: String,
    pub size_bytes: u64,
    pub lfs_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2DatasetContract {
    pub dataset_id: String,
    pub revision: String,
    pub dataset_license: String,
    pub expected_rows: usize,
    pub shards: Vec<HistoricalV2DatasetShard>,
    pub projected_selection_fields: Vec<String>,
    pub post_selection_reproducibility_fields: Vec<String>,
    pub permanently_forbidden_fields: Vec<String>,
    pub unlisted_fields_fail_closed: bool,
    pub dataset_judgments_are_not_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2MethodBounds {
    pub minimum: usize,
    pub maximum: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SelectionContract {
    pub supported_languages: Vec<String>,
    pub slots_per_language: usize,
    pub total_slots: usize,
    pub ranking_contract: String,
    pub ranking_seed: String,
    pub language_derived_from_patch_and_git_objects: bool,
    pub changed_methods_derived_from_compiler_census: bool,
    pub net_non_whitespace_production_reduction_required: bool,
    pub one_slot_per_repository: bool,
    pub one_slot_per_pull_request: bool,
    pub selection_committed_before_repository_assessment: bool,
    pub failed_candidate_closes_slot: bool,
    pub backfill_forbidden: bool,
    pub model_access_forbidden: bool,
    pub sniff_output_access_forbidden: bool,
    pub repository_method_bounds: HistoricalV2MethodBounds,
    pub excluded_partitions: Vec<String>,
    pub exact_exclusion_artifacts_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2AssessmentContract {
    pub complete_git_objects_required: bool,
    pub exact_base_revision_required: bool,
    pub patch_must_apply_cleanly: bool,
    pub patched_tree_identity_committed: bool,
    pub source_and_test_inventory_committed: bool,
    pub compiler_semantic_census_required: bool,
    pub same_test_recipe_on_both_revisions: bool,
    pub test_patch_may_open_only_after_slot_freeze: bool,
    pub test_patch_applied_identically_to_both_revisions: bool,
    pub dataset_recipe_is_untrusted: bool,
    pub hardened_sandbox_required: bool,
    pub host_secrets_and_filesystem_hidden: bool,
    pub public_surface_must_be_preserved: bool,
    pub behavior_change_closes_slot: bool,
    pub typed_terminal_exclusions_required: bool,
    pub every_slot_checkpointed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewContract {
    pub source_only_review: bool,
    pub independent_reviewers: usize,
    pub reviewers_must_not_see_sniff_output: bool,
    pub reviewers_must_not_see_each_other_labels: bool,
    pub exact_before_slop_mechanism_required: bool,
    pub exact_after_removal_required: bool,
    pub historical_patch_must_match_simpler_counterfactual: bool,
    pub behavior_evidence_required: bool,
    pub distinct_dispute_resolver: bool,
    pub rejected_label_closes_slot: bool,
    pub minimum_accepted_per_language: usize,
    pub minimum_total_accepted: usize,
    pub underfilled_language_fails_release: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Protocol {
    pub schema_version: u32,
    pub protocol_id: String,
    pub prepared_at: String,
    pub precommit_parent_revision: String,
    pub no_fallbacks: bool,
    pub dataset: HistoricalV2DatasetContract,
    pub selection: HistoricalV2SelectionContract,
    pub assessment: HistoricalV2AssessmentContract,
    pub review: HistoricalV2ReviewContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHistoricalV2Protocol {
    pub protocol: HistoricalV2Protocol,
    pub protocol_sha256: String,
}
