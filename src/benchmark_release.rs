use super::{BenchmarkCase, BenchmarkMetrics, BenchmarkPrediction, evaluate};
use crate::product_contract::SlopPattern;
use crate::types::FindingTier;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path};

pub(crate) const RELEASE_SCHEMA_VERSION: u32 = 6;
const REQUIRED_LANGUAGES: [&str; 6] =
    ["go", "javascript", "kotlin", "python", "rust", "typescript"];
const REQUIRED_BASELINES: [&str; 7] = [
    "generic_agent",
    "copilot",
    "gemini_code_assist",
    "coderabbit",
    "qodo",
    "greptile",
    "deterministic_scanner",
];

#[path = "benchmark_release_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_non_blind_seal.rs"]
mod non_blind_seal;

pub use non_blind_seal::*;

#[path = "benchmark_non_blind_history.rs"]
mod non_blind_history;

pub use non_blind_history::*;

#[path = "benchmark_intentional_boundary_protocol.rs"]
mod intentional_boundary_protocol;

pub use intentional_boundary_protocol::*;

#[path = "benchmark_history_v2_protocol_schema.rs"]
mod history_v2_protocol_schema;

pub use history_v2_protocol_schema::*;

#[path = "benchmark_history_v2_protocol.rs"]
mod history_v2_protocol;

pub use history_v2_protocol::*;

#[path = "benchmark_history_v2_frame_schema.rs"]
mod history_v2_frame_schema;

pub use history_v2_frame_schema::*;

#[path = "benchmark_history_v2_frame.rs"]
mod history_v2_frame;

pub use history_v2_frame::*;

#[path = "benchmark_history_v2_selection_schema.rs"]
mod history_v2_selection_schema;

pub use history_v2_selection_schema::*;

#[path = "benchmark_history_v2_exclusions.rs"]
mod history_v2_exclusions;

pub use history_v2_exclusions::*;

#[path = "benchmark_history_v2_exclusion_identity.rs"]
mod history_v2_exclusion_identity;

#[path = "benchmark_history_v2_exclusion_derivation.rs"]
mod history_v2_exclusion_derivation;

pub use history_v2_exclusion_derivation::*;

#[path = "benchmark_history_v2_selection.rs"]
mod history_v2_selection;

pub use history_v2_selection::*;

#[path = "benchmark_history_v2_payload_schema.rs"]
mod history_v2_payload_schema;

pub use history_v2_payload_schema::*;

#[path = "benchmark_history_v2_payload_commitment.rs"]
mod history_v2_payload_commitment;

pub use history_v2_payload_commitment::validate_historical_v2_selected_payloads_commitment;

#[cfg(feature = "sniffbench-frame")]
#[path = "benchmark_history_v2_parquet.rs"]
mod history_v2_parquet;

#[cfg(feature = "sniffbench-frame")]
pub use history_v2_parquet::*;

#[cfg(feature = "sniffbench-frame")]
#[path = "benchmark_history_v2_payload_parquet.rs"]
mod history_v2_payload_parquet;

#[cfg(feature = "sniffbench-frame")]
#[path = "benchmark_history_v2_payloads.rs"]
mod history_v2_payloads;

#[cfg(feature = "sniffbench-frame")]
pub use history_v2_payloads::*;

#[path = "benchmark_history_v2_materialization_schema.rs"]
mod history_v2_materialization_schema;

pub use history_v2_materialization_schema::*;

#[path = "benchmark_history_v2_materialization_stage_schema.rs"]
mod history_v2_materialization_stage_schema;

pub use history_v2_materialization_stage_schema::*;

#[path = "benchmark_history_v2_materialization_exclusion.rs"]
mod history_v2_materialization_exclusion;

pub use history_v2_materialization_exclusion::*;

#[path = "benchmark_history_v2_materialization.rs"]
mod history_v2_materialization;

pub use history_v2_materialization::*;

#[path = "benchmark_history_v2_materialization_stage.rs"]
mod history_v2_materialization_stage;

pub use history_v2_materialization_stage::*;

#[path = "benchmark_history_v2_materialization_git.rs"]
mod history_v2_materialization_git;

#[path = "benchmark_history_v2_test_materialization_schema.rs"]
mod history_v2_test_materialization_schema;

pub use history_v2_test_materialization_schema::*;

#[path = "benchmark_history_v2_test_materialization_stage_schema.rs"]
mod history_v2_test_materialization_stage_schema;

pub use history_v2_test_materialization_stage_schema::*;

#[path = "benchmark_history_v2_test_materialization_exclusion.rs"]
mod history_v2_test_materialization_exclusion;

pub use history_v2_test_materialization_exclusion::*;

#[path = "benchmark_history_v2_test_materialization.rs"]
mod history_v2_test_materialization;

pub use history_v2_test_materialization::*;

#[path = "benchmark_history_v2_source_census_schema.rs"]
mod history_v2_source_census_schema;

pub use history_v2_source_census_schema::*;

#[path = "benchmark_history_v2_source_census_stage_schema.rs"]
mod history_v2_source_census_stage_schema;

pub use history_v2_source_census_stage_schema::*;

#[path = "benchmark_history_v2_source_census_exclusion.rs"]
mod history_v2_source_census_exclusion;

pub use history_v2_source_census_exclusion::*;

#[path = "benchmark_history_v2_source_census.rs"]
mod history_v2_source_census;

pub use history_v2_source_census::*;

#[path = "benchmark_history_v2_semantic_schema.rs"]
mod history_v2_semantic_schema;

pub use history_v2_semantic_schema::*;

#[path = "benchmark_history_v2_semantic_stage_schema.rs"]
mod history_v2_semantic_stage_schema;

pub use history_v2_semantic_stage_schema::*;

#[path = "benchmark_history_v2_semantic_exclusion.rs"]
mod history_v2_semantic_exclusion;

pub use history_v2_semantic_exclusion::*;

#[path = "benchmark_history_v2_semantic.rs"]
mod history_v2_semantic;

pub use history_v2_semantic::*;

#[path = "benchmark_history_v2_assessment_identity_schema.rs"]
mod history_v2_assessment_identity_schema;

pub use history_v2_assessment_identity_schema::*;

#[path = "benchmark_history_v2_assessment_identity.rs"]
mod history_v2_assessment_identity;

pub use history_v2_assessment_identity::*;

#[path = "benchmark_history_v2_qualification_schema.rs"]
mod history_v2_qualification_schema;

pub use history_v2_qualification_schema::*;

#[path = "benchmark_history_v2_qualification_roles.rs"]
mod history_v2_qualification_roles;

#[path = "benchmark_history_v2_qualification_surface.rs"]
mod history_v2_qualification_surface;

#[path = "benchmark_history_v2_qualification_methods.rs"]
mod history_v2_qualification_methods;

#[path = "benchmark_history_v2_qualification.rs"]
mod history_v2_qualification;

pub use history_v2_qualification::*;

#[path = "benchmark_history_v2_test_recipe_schema.rs"]
mod history_v2_test_recipe_schema;

pub use history_v2_test_recipe_schema::*;

#[path = "benchmark_history_v2_test_recipe.rs"]
mod history_v2_test_recipe;

pub use history_v2_test_recipe::*;

#[path = "benchmark_history_v2_execution_harness_schema.rs"]
mod history_v2_execution_harness_schema;

pub use history_v2_execution_harness_schema::*;

#[path = "benchmark_history_v2_execution_harness.rs"]
mod history_v2_execution_harness;

pub use history_v2_execution_harness::*;

#[path = "benchmark_history_v2_identical_tests_schema.rs"]
mod history_v2_identical_tests_schema;

pub use history_v2_identical_tests_schema::*;

#[path = "benchmark_history_v2_identical_tests.rs"]
mod history_v2_identical_tests;

pub use history_v2_identical_tests::*;

#[path = "benchmark_history_v2_identical_tests_docker.rs"]
mod history_v2_identical_tests_docker;

pub use history_v2_identical_tests_docker::*;

#[path = "benchmark_history_v2_execution_checkpoint_schema.rs"]
mod history_v2_execution_checkpoint_schema;

pub use history_v2_execution_checkpoint_schema::*;

#[path = "benchmark_history_v2_slot_store_support.rs"]
mod history_v2_slot_store_support;

#[path = "benchmark_history_v2_execution_checkpoint.rs"]
mod history_v2_execution_checkpoint;

pub use history_v2_execution_checkpoint::*;

#[path = "benchmark_history_v2_slot_stage_schema.rs"]
mod history_v2_slot_stage_schema;

pub use history_v2_slot_stage_schema::*;

#[path = "benchmark_history_v2_slot_stage.rs"]
mod history_v2_slot_stage;

pub use history_v2_slot_stage::*;

#[path = "benchmark_history_v2_slot_runner_schema.rs"]
mod history_v2_slot_runner_schema;

pub use history_v2_slot_runner_schema::*;

#[path = "benchmark_history_v2_slot_runner.rs"]
mod history_v2_slot_runner;

pub use history_v2_slot_runner::*;

#[path = "benchmark_history_v2_slot_sweep_schema.rs"]
mod history_v2_slot_sweep_schema;

pub use history_v2_slot_sweep_schema::*;

#[path = "benchmark_history_v2_slot_sweep.rs"]
mod history_v2_slot_sweep;

pub use history_v2_slot_sweep::*;

#[path = "benchmark_history_v2_slot_operations_support.rs"]
mod history_v2_slot_operations_support;

#[path = "benchmark_history_v2_slot_operations.rs"]
mod history_v2_slot_operations;

pub use history_v2_slot_operations::*;

#[path = "benchmark_history_v2_stage_adapters.rs"]
mod history_v2_stage_adapters;

pub use history_v2_stage_adapters::*;

#[path = "benchmark_history_v2_stage_adapters_schema.rs"]
mod history_v2_stage_adapters_schema;

pub use history_v2_stage_adapters_schema::*;

#[path = "benchmark_intentional_boundary_frame_task.rs"]
mod intentional_boundary_frame_task;

pub use intentional_boundary_frame_task::*;

#[path = "benchmark_intentional_boundary_inventory.rs"]
mod intentional_boundary_inventory;

pub use intentional_boundary_inventory::*;

#[path = "benchmark_intentional_boundary_source_census.rs"]
mod intentional_boundary_source_census;

pub use intentional_boundary_source_census::*;

#[path = "benchmark_intentional_boundary_semantic_schema.rs"]
mod intentional_boundary_semantic_schema;

pub use intentional_boundary_semantic_schema::*;

#[path = "benchmark_intentional_boundary_semantic.rs"]
mod intentional_boundary_semantic;

pub use intentional_boundary_semantic::*;

#[path = "benchmark_intentional_boundary_evidence_schema.rs"]
mod intentional_boundary_evidence_schema;

pub use intentional_boundary_evidence_schema::*;

#[path = "benchmark_intentional_boundary_ast_schema.rs"]
mod intentional_boundary_ast_schema;

pub use intentional_boundary_ast_schema::*;

#[path = "benchmark_intentional_boundary_ast.rs"]
mod intentional_boundary_ast;

#[path = "benchmark_intentional_boundary_ast_rust.rs"]
mod intentional_boundary_ast_rust;

pub use intentional_boundary_ast_rust::*;

#[path = "benchmark_intentional_boundary_ast_python.rs"]
mod intentional_boundary_ast_python;

pub use intentional_boundary_ast_python::*;

#[path = "benchmark_intentional_boundary_ast_js_ts.rs"]
mod intentional_boundary_ast_js_ts;

pub use intentional_boundary_ast_js_ts::*;

#[path = "benchmark_intentional_boundary_ast_go_kotlin.rs"]
mod intentional_boundary_ast_go_kotlin;

pub use intentional_boundary_ast_go_kotlin::*;

#[path = "benchmark_intentional_boundary_ast_evidence.rs"]
mod intentional_boundary_ast_evidence;

pub use intentional_boundary_ast_evidence::*;

#[path = "benchmark_intentional_boundary_manifest_evidence.rs"]
mod intentional_boundary_manifest_evidence;

pub use intentional_boundary_manifest_evidence::*;

#[path = "benchmark_intentional_boundary_project_model_schema.rs"]
mod intentional_boundary_project_model_schema;

pub use intentional_boundary_project_model_schema::*;

#[path = "benchmark_intentional_boundary_runtime_snapshot.rs"]
mod intentional_boundary_runtime_snapshot;

#[path = "benchmark_intentional_boundary_behavior_schema.rs"]
mod intentional_boundary_behavior_schema;

pub use intentional_boundary_behavior_schema::*;

#[path = "benchmark_intentional_boundary_behavior.rs"]
mod intentional_boundary_behavior;

pub use intentional_boundary_behavior::*;

#[path = "benchmark_intentional_boundary_project_model.rs"]
mod intentional_boundary_project_model;

pub use intentional_boundary_project_model::*;

#[path = "benchmark_intentional_boundary_project_model_cargo.rs"]
mod intentional_boundary_project_model_cargo;

pub use intentional_boundary_project_model_cargo::*;

#[path = "benchmark_intentional_boundary_project_model_go.rs"]
mod intentional_boundary_project_model_go;

pub use intentional_boundary_project_model_go::*;

#[path = "benchmark_intentional_boundary_project_model_gradle.rs"]
mod intentional_boundary_project_model_gradle;

pub use intentional_boundary_project_model_gradle::*;

#[path = "benchmark_intentional_boundary_project_model_binding_schema.rs"]
mod intentional_boundary_project_model_binding_schema;

pub use intentional_boundary_project_model_binding_schema::*;

#[path = "benchmark_intentional_boundary_project_model_binding.rs"]
mod intentional_boundary_project_model_binding;

pub use intentional_boundary_project_model_binding::*;

#[path = "benchmark_intentional_boundary_project_model_evidence.rs"]
mod intentional_boundary_project_model_evidence;

pub use intentional_boundary_project_model_evidence::*;

#[path = "benchmark_intentional_boundary_candidate_schema.rs"]
mod intentional_boundary_candidate_schema;

pub use intentional_boundary_candidate_schema::*;

#[path = "benchmark_intentional_boundary_candidate.rs"]
mod intentional_boundary_candidate;

pub use intentional_boundary_candidate::*;

#[path = "benchmark_intentional_boundary_frame_schema.rs"]
mod intentional_boundary_frame_schema;

pub use intentional_boundary_frame_schema::*;

#[path = "benchmark_intentional_boundary_frame.rs"]
mod intentional_boundary_frame;

pub use intentional_boundary_frame::*;

#[path = "benchmark_intentional_boundary_slots_schema.rs"]
mod intentional_boundary_slots_schema;

pub use intentional_boundary_slots_schema::*;

#[path = "benchmark_intentional_boundary_slots.rs"]
mod intentional_boundary_slots;

pub use intentional_boundary_slots::*;

#[path = "benchmark_intentional_boundary_source_bundle_schema.rs"]
mod intentional_boundary_source_bundle_schema;

pub use intentional_boundary_source_bundle_schema::*;

#[path = "benchmark_intentional_boundary_source_bundle.rs"]
mod intentional_boundary_source_bundle;

pub use intentional_boundary_source_bundle::*;

#[path = "benchmark_intentional_boundary_label_schema.rs"]
mod intentional_boundary_label_schema;

pub use intentional_boundary_label_schema::*;

#[path = "benchmark_intentional_boundary_label_review.rs"]
mod intentional_boundary_label_review;

pub use intentional_boundary_label_review::*;

#[path = "benchmark_intentional_boundary_label_resolution_schema.rs"]
mod intentional_boundary_label_resolution_schema;

pub use intentional_boundary_label_resolution_schema::*;

#[path = "benchmark_intentional_boundary_label_resolution.rs"]
mod intentional_boundary_label_resolution;

pub use intentional_boundary_label_resolution::*;

#[path = "benchmark_intentional_boundary_manifest_schema.rs"]
mod intentional_boundary_manifest_schema;

pub use intentional_boundary_manifest_schema::*;

#[path = "benchmark_intentional_boundary_manifest.rs"]
mod intentional_boundary_manifest;

pub use intentional_boundary_manifest::*;

#[path = "benchmark_intentional_boundary_manifest_binding_schema.rs"]
mod intentional_boundary_manifest_binding_schema;

pub use intentional_boundary_manifest_binding_schema::*;

#[path = "benchmark_intentional_boundary_manifest_binding.rs"]
mod intentional_boundary_manifest_binding;

pub use intentional_boundary_manifest_binding::*;

#[path = "benchmark_intentional_boundary_compiler_evidence.rs"]
mod intentional_boundary_compiler_evidence;

pub use intentional_boundary_compiler_evidence::*;

#[path = "benchmark_non_blind_history_assessment_schema.rs"]
mod non_blind_history_assessment_schema;

pub use non_blind_history_assessment_schema::*;

#[path = "benchmark_non_blind_history_assessment.rs"]
mod non_blind_history_assessment;

pub use non_blind_history_assessment::*;

#[path = "benchmark_non_blind_history_git.rs"]
mod non_blind_history_git;

pub use non_blind_history_git::*;

#[path = "benchmark_non_blind_history_source.rs"]
mod non_blind_history_source;

pub use non_blind_history_source::*;

#[path = "benchmark_non_blind_history_recipe.rs"]
mod non_blind_history_recipe;

pub use non_blind_history_recipe::*;

#[path = "benchmark_non_blind_history_runtime.rs"]
mod non_blind_history_runtime;

#[path = "benchmark_non_blind_history_runtime_adapters.rs"]
mod non_blind_history_runtime_adapters;

#[path = "benchmark_non_blind_history_runtime_support.rs"]
mod non_blind_history_runtime_support;

#[path = "benchmark_non_blind_history_test.rs"]
mod non_blind_history_test;

pub use non_blind_history_test::*;

#[path = "benchmark_non_blind_history_materialize.rs"]
mod non_blind_history_materialize;

pub use non_blind_history_materialize::*;

#[path = "benchmark_non_blind_history_artifacts.rs"]
mod non_blind_history_artifacts;

#[path = "benchmark_non_blind_history_candidate.rs"]
mod non_blind_history_candidate;

#[path = "benchmark_non_blind_history_candidate_evidence.rs"]
mod non_blind_history_candidate_evidence;

#[path = "benchmark_non_blind_history_candidate_support.rs"]
mod non_blind_history_candidate_support;

#[path = "benchmark_non_blind_history_candidate_test.rs"]
mod non_blind_history_candidate_test;

#[path = "benchmark_non_blind_history_runner.rs"]
mod non_blind_history_runner;

pub use non_blind_history_runner::{assess_non_blind_history, assess_non_blind_history_slice};

#[path = "benchmark_source_seal.rs"]
mod source_seal;

pub use source_seal::*;

#[path = "benchmark_source_selection.rs"]
mod source_selection;

pub use source_selection::*;

#[path = "benchmark_source_frame.rs"]
mod source_frame;

pub use source_frame::*;

#[path = "benchmark_source_assessment.rs"]
mod source_assessment;

pub use source_assessment::assess_source_selection;

#[path = "benchmark_label_review.rs"]
mod label_review;

pub use label_review::*;

#[path = "benchmark_label_resolution.rs"]
mod label_resolution;

pub use label_resolution::*;

#[path = "benchmark_cost_receipt.rs"]
mod cost_receipt;

pub use cost_receipt::validate_actual_cost_receipt;

impl BenchmarkPartition {
    fn all() -> [Self; 5] {
        [
            Self::SyntheticGold,
            Self::HistoricalSimplification,
            Self::ResearchTrajectory,
            Self::IntentionalBoundary,
            Self::BlindOss,
        ]
    }
}

impl BenchmarkCorpus {
    pub fn computed_label_commitment_sha256(&self) -> Result<String, String> {
        #[derive(serde::Serialize)]
        struct CommittedLabel<'a> {
            case_id: &'a str,
            language: &'a str,
            expected_tier: FindingTier,
            expected_pattern: &'a str,
            intentional_boundary: bool,
            partition: BenchmarkPartition,
            scope: BenchmarkScope,
            expected_proof_level: u8,
            covered_method_ids: &'a [String],
            after: &'a [SourceSnapshot],
            human_explanation: &'a str,
            behavioral_evidence: &'a [String],
            adjudications: &'a [BenchmarkAdjudication],
            disputed: bool,
            dispute_resolution: Option<&'a str>,
        }

        #[derive(serde::Serialize)]
        struct CommittedLabels<'a> {
            blind_case_bundle_artifact_path: &'a str,
            blind_case_bundle_sha256: &'a str,
            labels: Vec<CommittedLabel<'a>>,
        }

        let mut labels = self
            .cases
            .iter()
            .map(|case| CommittedLabel {
                case_id: &case.label.case_id,
                language: &case.label.language,
                expected_tier: case.label.expected_tier,
                expected_pattern: &case.label.expected_pattern,
                intentional_boundary: case.label.intentional_boundary,
                partition: case.partition,
                scope: case.scope,
                expected_proof_level: case.expected_proof_level,
                covered_method_ids: &case.covered_method_ids,
                after: &case.after,
                human_explanation: &case.human_explanation,
                behavioral_evidence: &case.behavioral_evidence,
                adjudications: &case.adjudications,
                disputed: case.disputed,
                dispute_resolution: case.dispute_resolution.as_deref(),
            })
            .collect::<Vec<_>>();
        labels.sort_by(|left, right| left.case_id.cmp(right.case_id));
        let bytes = serde_json::to_vec(&CommittedLabels {
            blind_case_bundle_artifact_path: &self.blind_case_bundle_artifact_path,
            blind_case_bundle_sha256: &self.blind_case_bundle_sha256,
            labels,
        })
        .map_err(|error| format!("failed to serialize benchmark label commitment: {error}"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn computed_source_commitment_sha256(&self) -> Result<String, String> {
        #[derive(serde::Serialize)]
        struct CommittedCaseSource<'a> {
            case_id: &'a str,
            partition: BenchmarkPartition,
            provenance_id: Option<&'a str>,
            before: &'a [SourceSnapshot],
            after: &'a [SourceSnapshot],
        }

        #[derive(serde::Serialize)]
        struct CommittedSources<'a> {
            source_seal_artifact_path: &'a str,
            source_seal_sha256: &'a str,
            non_blind_source_seal_artifact_path: &'a str,
            non_blind_source_seal_sha256: &'a str,
            sources: Vec<&'a SourceSnapshot>,
            case_sources: Vec<CommittedCaseSource<'a>>,
        }
        let mut sources = self.analysis_sources.iter().collect::<Vec<_>>();
        sources.sort_by(|left, right| {
            (
                &left.repository,
                &left.revision,
                &left.repository_path,
                &left.artifact_path,
                &left.sha256,
            )
                .cmp(&(
                    &right.repository,
                    &right.revision,
                    &right.repository_path,
                    &right.artifact_path,
                    &right.sha256,
                ))
        });
        let bytes = serde_json::to_vec(&CommittedSources {
            source_seal_artifact_path: &self.source_seal_artifact_path,
            source_seal_sha256: &self.source_seal_sha256,
            non_blind_source_seal_artifact_path: &self.non_blind_source_seal_artifact_path,
            non_blind_source_seal_sha256: &self.non_blind_source_seal_sha256,
            sources,
            case_sources: {
                let mut cases = self
                    .cases
                    .iter()
                    .map(|case| CommittedCaseSource {
                        case_id: &case.label.case_id,
                        partition: case.partition,
                        provenance_id: case.provenance_id.as_deref(),
                        before: &case.before,
                        after: &case.after,
                    })
                    .collect::<Vec<_>>();
                cases.sort_by(|left, right| left.case_id.cmp(right.case_id));
                cases
            },
        })
        .map_err(|error| format!("failed to serialize benchmark source inventory: {error}"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

pub fn evaluate_release(
    corpus: &BenchmarkCorpus,
    submission: &BenchmarkSubmission,
    corpus_root: &Path,
) -> Result<ReleaseBenchmarkMetrics, String> {
    let source_texts = validate_corpus(corpus, corpus_root)?;
    validate_submission(corpus, submission, corpus_root)?;

    let case_map = corpus
        .cases
        .iter()
        .map(|case| (case.label.case_id.as_str(), case))
        .collect::<HashMap<_, _>>();
    let normalized = submission
        .runs
        .iter()
        .map(|run| normalize_run(corpus, run, &source_texts))
        .collect::<Result<Vec<_>, _>>()?;
    let per_run = submission
        .runs
        .iter()
        .zip(&normalized)
        .map(|(run, predictions)| {
            Ok((
                run.run_id.clone(),
                evaluate(&corpus_labels(corpus), predictions)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let real_world_per_run = submission
        .runs
        .iter()
        .zip(&normalized)
        .map(|(run, predictions)| {
            Ok((
                run.run_id.clone(),
                subset_metrics(corpus, predictions, |case| {
                    case.partition != BenchmarkPartition::SyntheticGold
                })?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let primary = per_run[&submission.runs[0].run_id].clone();
    let real_world = real_world_per_run[&submission.runs[0].run_id].clone();
    let blind_oss_per_run = submission
        .runs
        .iter()
        .zip(&normalized)
        .map(|(run, predictions)| {
            Ok((
                run.run_id.clone(),
                subset_metrics(corpus, predictions, |case| {
                    case.partition == BenchmarkPartition::BlindOss
                })?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let verdict_repeatability = repeatability(&submission.runs);
    let all_predictions = submission
        .runs
        .iter()
        .flat_map(|run| run.predictions.iter())
        .collect::<Vec<_>>();
    let duplicate_count = submission
        .runs
        .iter()
        .map(|run| duplicate_prediction_count(&run.predictions))
        .sum::<usize>();
    let unmatched_findings = all_predictions
        .iter()
        .filter(|prediction| prediction.matched_case_id.is_none() && is_finding(prediction.tier))
        .count();
    let unmatched_slop = all_predictions
        .iter()
        .filter(|prediction| {
            prediction.matched_case_id.is_none() && prediction.tier == FindingTier::Slop
        })
        .count();
    let unresolved = all_predictions
        .iter()
        .filter(|prediction| prediction.tier == FindingTier::Unresolved)
        .count();
    let unresolved_opportunities = corpus.cases.len() * submission.runs.len()
        + all_predictions
            .iter()
            .filter(|prediction| {
                prediction.matched_case_id.is_none() && prediction.tier == FindingTier::Unresolved
            })
            .count();
    let proof_opportunities = all_predictions
        .iter()
        .filter(|prediction| is_finding(prediction.tier))
        .count();
    let proof_matches = all_predictions
        .iter()
        .filter(|prediction| {
            is_finding(prediction.tier)
                && prediction
                    .matched_case_id
                    .as_deref()
                    .and_then(|id| case_map.get(id))
                    .is_some_and(|case| prediction.proof_level >= case.expected_proof_level)
        })
        .count();
    let all_predicted_findings = proof_opportunities;
    let valid_evidence_findings = all_predictions
        .iter()
        .filter(|prediction| {
            is_finding(prediction.tier)
                && prediction_evidence_valid(prediction, &case_map, &source_texts)
        })
        .count();
    let accepted_findings = all_predictions
        .iter()
        .filter(|prediction| prediction.reviewer_disposition == ReviewerDisposition::Accepted)
        .count();
    let reviewed_findings = all_predictions
        .iter()
        .filter(|prediction| prediction.reviewer_disposition != ReviewerDisposition::Unreviewed)
        .count();
    let maintainer_predictions = all_predictions
        .iter()
        .filter(|prediction| {
            prediction
                .matched_case_id
                .as_deref()
                .and_then(|id| case_map.get(id))
                .is_some_and(|case| case.adjudications.iter().any(|item| item.maintainer))
        })
        .collect::<Vec<_>>();
    let maintainer_accepted = maintainer_predictions
        .iter()
        .filter(|prediction| prediction.reviewer_disposition == ReviewerDisposition::Accepted)
        .count();
    let reviewer_minutes = all_predictions
        .iter()
        .map(|prediction| prediction.reviewer_minutes)
        .sum::<f64>();
    let total_methods = submission
        .runs
        .iter()
        .map(|run| run.analyzed_method_count)
        .sum::<usize>();
    let total_cost_microusd = submission
        .runs
        .iter()
        .map(|run| run.usage.actual_cost_microusd)
        .sum::<u64>();
    let cost_usd_per_1000_methods = if total_methods == 0 {
        0.0
    } else {
        total_cost_microusd as f64 / 1_000_000.0 * 1000.0 / total_methods as f64
    };
    let accepted_findings_per_reviewer_minute = ratio(accepted_findings, reviewer_minutes);
    let by_partition = partition_metrics(corpus, &normalized[0])?;

    let mut metrics = ReleaseBenchmarkMetrics {
        primary,
        real_world,
        per_run,
        real_world_per_run,
        blind_oss_per_run,
        run_count: submission.runs.len(),
        verdict_repeatability,
        duplicate_case_rate: ratio(duplicate_count, all_predictions.len() as f64),
        unresolved_rate: ratio(unresolved, unresolved_opportunities as f64),
        proof_level_accuracy: ratio(proof_matches, proof_opportunities as f64),
        overall_evidence_validity: ratio(valid_evidence_findings, all_predicted_findings as f64),
        maintainer_acceptance: ratio(maintainer_accepted, maintainer_predictions.len() as f64),
        accepted_findings,
        reviewer_minutes,
        accepted_findings_per_reviewer_minute,
        cost_usd_per_1000_methods,
        unmatched_findings,
        unmatched_slop,
        by_partition,
        release_gate_errors: Vec::new(),
    };
    metrics.release_gate_errors = release_errors(&metrics, submission, reviewed_findings);
    Ok(metrics)
}

pub fn freeze_corpus(
    mut corpus: BenchmarkCorpus,
    corpus_root: &Path,
) -> Result<BenchmarkCorpus, String> {
    corpus.source_commitment_sha256 = corpus.computed_source_commitment_sha256()?;
    corpus.label_commitment_sha256 = corpus.computed_label_commitment_sha256()?;
    validate_corpus(&corpus, corpus_root)?;
    Ok(corpus)
}

impl ReleaseBenchmarkMetrics {
    pub fn assert_release_gate(&self) -> Result<(), String> {
        if self.release_gate_errors.is_empty() {
            Ok(())
        } else {
            Err(self.release_gate_errors.join("; "))
        }
    }
}

fn validate_corpus(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
) -> Result<HashMap<String, String>, String> {
    if corpus.schema_version != RELEASE_SCHEMA_VERSION {
        return Err(format!(
            "benchmark corpus schema_version must be {RELEASE_SCHEMA_VERSION}"
        ));
    }
    require_text("corpus_id", &corpus.corpus_id)?;
    require_text("frozen_at", &corpus.frozen_at)?;
    require_sha256("source_commitment_sha256", &corpus.source_commitment_sha256)?;
    require_sha256("label_commitment_sha256", &corpus.label_commitment_sha256)?;
    require_safe_artifact_path(&corpus.source_seal_artifact_path)?;
    require_sha256("source_seal_sha256", &corpus.source_seal_sha256)?;
    require_safe_artifact_path(&corpus.blind_case_bundle_artifact_path)?;
    require_sha256("blind_case_bundle_sha256", &corpus.blind_case_bundle_sha256)?;
    require_safe_artifact_path(&corpus.non_blind_source_seal_artifact_path)?;
    require_sha256(
        "non_blind_source_seal_sha256",
        &corpus.non_blind_source_seal_sha256,
    )?;
    if corpus.cases.is_empty() {
        return Err("release benchmark corpus cannot be empty".to_string());
    }
    if corpus.analysis_sources.is_empty() {
        return Err("release benchmark analysis source inventory cannot be empty".to_string());
    }
    let mut ids = HashSet::new();
    let mut languages = HashSet::new();
    let mut partitions = HashSet::new();
    for case in &corpus.cases {
        validate_case(case)?;
        if !ids.insert(case.label.case_id.as_str()) {
            return Err(format!(
                "benchmark corpus repeats case {}",
                case.label.case_id
            ));
        }
        languages.insert(case.label.language.to_ascii_lowercase());
        partitions.insert(case.partition);
    }
    for language in REQUIRED_LANGUAGES {
        if !languages.contains(language) {
            return Err(format!(
                "release corpus is missing required language {language}"
            ));
        }
    }
    for partition in BenchmarkPartition::all() {
        if !partitions.contains(&partition) {
            return Err(format!("release corpus is missing partition {partition:?}"));
        }
    }
    let computed_source = corpus.computed_source_commitment_sha256()?;
    if !corpus
        .source_commitment_sha256
        .eq_ignore_ascii_case(&computed_source)
    {
        return Err(format!(
            "benchmark source commitment does not match the frozen analysis corpus; expected {computed_source}"
        ));
    }
    let computed = corpus.computed_label_commitment_sha256()?;
    if !corpus
        .label_commitment_sha256
        .eq_ignore_ascii_case(&computed)
    {
        return Err(format!(
            "benchmark label commitment does not match the frozen labels; expected {computed}"
        ));
    }
    let source_texts = validate_source_snapshots(corpus, corpus_root)?;
    validate_case_source_membership(corpus)?;
    validate_corpus_non_blind_source_seal(corpus, corpus_root)?;
    validate_blind_source_seal(corpus, corpus_root)?;
    Ok(source_texts)
}

fn validate_corpus_non_blind_source_seal(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
) -> Result<(), String> {
    let path = corpus_root.join(&corpus.non_blind_source_seal_artifact_path);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "failed to read benchmark non-blind source seal {}: {error}",
            path.display()
        )
    })?;
    let actual_hash = format!("{:x}", Sha256::digest(&bytes));
    if !actual_hash.eq_ignore_ascii_case(&corpus.non_blind_source_seal_sha256) {
        return Err(format!(
            "benchmark non-blind source-seal artifact hash mismatch: expected {actual_hash}"
        ));
    }
    let seal: NonBlindSourceSeal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse non-blind source seal: {error}"))?;
    validate_non_blind_source_seal(&seal, corpus_root)?;
    let entries = seal
        .entries
        .iter()
        .map(|entry| (entry.provenance_id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut used = HashSet::new();
    for case in &corpus.cases {
        match case.partition {
            BenchmarkPartition::HistoricalSimplification
            | BenchmarkPartition::ResearchTrajectory
            | BenchmarkPartition::IntentionalBoundary => {
                let provenance_id = case.provenance_id.as_deref().ok_or_else(|| {
                    format!(
                        "non-blind real case {} requires a sealed provenance_id",
                        case.label.case_id
                    )
                })?;
                let entry = entries.get(provenance_id).ok_or_else(|| {
                    format!(
                        "benchmark case {} references unknown non-blind provenance_id {provenance_id}",
                        case.label.case_id
                    )
                })?;
                if entry.partition != case.partition
                    || !case
                        .before
                        .iter()
                        .all(|source| entry.before.contains(source))
                    || !case.after.iter().all(|source| entry.after.contains(source))
                {
                    return Err(format!(
                        "benchmark case {} differs from sealed non-blind provenance {provenance_id}",
                        case.label.case_id
                    ));
                }
                used.insert(provenance_id);
            }
            BenchmarkPartition::SyntheticGold | BenchmarkPartition::BlindOss => {
                if case.provenance_id.is_some() {
                    return Err(format!(
                        "benchmark case {} cannot claim non-blind provenance",
                        case.label.case_id
                    ));
                }
            }
        }
    }
    if used.len() != entries.len() {
        let mut unused = entries
            .keys()
            .filter(|id| !used.contains(**id))
            .copied()
            .collect::<Vec<_>>();
        unused.sort_unstable();
        return Err(format!(
            "non-blind source seal contains unassigned provenance entries: {}",
            unused.join(", ")
        ));
    }
    Ok(())
}

fn validate_blind_source_seal(corpus: &BenchmarkCorpus, corpus_root: &Path) -> Result<(), String> {
    let seal_path = corpus_root.join(&corpus.source_seal_artifact_path);
    let bytes = fs::read(&seal_path).map_err(|error| {
        format!(
            "failed to read benchmark source seal {}: {error}",
            seal_path.display()
        )
    })?;
    let actual_hash = format!("{:x}", Sha256::digest(&bytes));
    if !actual_hash.eq_ignore_ascii_case(&corpus.source_seal_sha256) {
        return Err(format!(
            "benchmark source-seal artifact hash mismatch; expected {actual_hash}"
        ));
    }
    let seal: BenchmarkSourceSeal = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse benchmark source seal: {error}"))?;
    validate_source_seal(&seal, corpus_root)?;
    validate_corpus_blind_case_bundle(corpus, corpus_root, &seal)?;

    let analysis_sources = corpus.analysis_sources.iter().collect::<HashSet<_>>();
    let sealed_sources = seal.sources.iter().collect::<HashSet<_>>();
    for source in &seal.sources {
        if !analysis_sources.contains(source) {
            return Err(format!(
                "blind source seal includes {} at {} but analysis_sources does not",
                source.repository, source.repository_path
            ));
        }
    }
    let sealed_methods = seal
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let sealed_languages = seal
        .methods
        .iter()
        .map(|method| method.language.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    for language in REQUIRED_LANGUAGES {
        if !sealed_languages.contains(language) {
            return Err(format!(
                "blind source seal is missing required language {language}"
            ));
        }
    }
    let mut covered_methods = HashSet::new();
    for case in &corpus.cases {
        if case.partition == BenchmarkPartition::BlindOss {
            if case.covered_method_ids.is_empty() {
                return Err(format!(
                    "blind OSS case {} does not identify any sealed method",
                    case.label.case_id
                ));
            }
            for method_id in &case.covered_method_ids {
                require_sha256("blind covered_method_id", method_id)?;
                let Some(method) = sealed_methods.get(method_id.as_str()) else {
                    return Err(format!(
                        "blind OSS case {} references method outside the source seal: {method_id}",
                        case.label.case_id
                    ));
                };
                if !method.language.eq_ignore_ascii_case(&case.label.language) {
                    return Err(format!(
                        "blind OSS case {} labels {} as {}",
                        case.label.case_id, method.language, case.label.language
                    ));
                }
                if !case.before.iter().any(|source| {
                    source.repository == method.repository
                        && source.revision == method.revision
                        && source.repository_path == method.repository_path
                        && source.artifact_path == method.artifact_path
                }) {
                    return Err(format!(
                        "blind OSS case {} does not include the sealed source for method {method_id}",
                        case.label.case_id
                    ));
                }
                if !covered_methods.insert(method_id.as_str()) {
                    return Err(format!(
                        "blind OSS method {method_id} is assigned to more than one case"
                    ));
                }
            }
            if !is_finding(case.label.expected_tier) && case.covered_method_ids.len() != 1 {
                return Err(format!(
                    "blind non-finding case {} must represent exactly one sealed method",
                    case.label.case_id
                ));
            }
        } else if !case.covered_method_ids.is_empty() {
            return Err(format!(
                "non-blind case {} must not claim source-seal methods",
                case.label.case_id
            ));
        } else if case
            .before
            .iter()
            .any(|source| sealed_sources.contains(source))
        {
            return Err(format!(
                "non-blind case {} reuses a source from the blind source seal",
                case.label.case_id
            ));
        }
    }
    let sealed_method_ids = sealed_methods.keys().copied().collect::<HashSet<_>>();
    if covered_methods != sealed_method_ids {
        let mut missing = sealed_methods
            .keys()
            .copied()
            .collect::<HashSet<_>>()
            .difference(&covered_methods)
            .copied()
            .collect::<Vec<_>>();
        missing.sort_unstable();
        return Err(format!(
            "blind OSS adjudication omitted sealed methods: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

fn validate_corpus_blind_case_bundle(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
    seal: &BenchmarkSourceSeal,
) -> Result<(), String> {
    let path = corpus_root.join(&corpus.blind_case_bundle_artifact_path);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "failed to read benchmark blind-case bundle {}: {error}",
            path.display()
        )
    })?;
    let actual_hash = format!("{:x}", Sha256::digest(&bytes));
    if !actual_hash.eq_ignore_ascii_case(&corpus.blind_case_bundle_sha256) {
        return Err(format!(
            "benchmark blind-case bundle artifact hash mismatch; expected {actual_hash}"
        ));
    }
    let bundle: BlindCaseBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse benchmark blind-case bundle: {error}"))?;
    bundle.validate_commitment()?;
    if bundle.source_seal_artifact_sha256 != corpus.source_seal_sha256
        || bundle.source_seal_commitment_sha256 != seal.seal_sha256
    {
        return Err("benchmark blind-case bundle does not match the source seal".to_string());
    }
    let mut expected = bundle.cases;
    expected.sort_by(|left, right| left.label.case_id.cmp(&right.label.case_id));
    let mut actual = corpus
        .cases
        .iter()
        .filter(|case| case.partition == BenchmarkPartition::BlindOss)
        .cloned()
        .collect::<Vec<_>>();
    actual.sort_by(|left, right| left.label.case_id.cmp(&right.label.case_id));
    if actual != expected {
        return Err(
            "benchmark BlindOss cases differ from the independently resolved blind-case bundle"
                .to_string(),
        );
    }
    Ok(())
}

pub fn validate_frozen_corpus(corpus: &BenchmarkCorpus, corpus_root: &Path) -> Result<(), String> {
    validate_corpus(corpus, corpus_root).map(|_| ())
}

fn validate_case_source_membership(corpus: &BenchmarkCorpus) -> Result<(), String> {
    let analysis_sources = corpus.analysis_sources.iter().collect::<HashSet<_>>();
    for case in &corpus.cases {
        for snapshot in &case.before {
            if !analysis_sources.contains(snapshot) {
                return Err(format!(
                    "benchmark case {} references before source {} that is absent from analysis_sources",
                    case.label.case_id, snapshot.artifact_path
                ));
            }
        }
    }
    Ok(())
}

fn validate_case(case: &ReleaseBenchmarkCase) -> Result<(), String> {
    let id = &case.label.case_id;
    require_text("case_id", id)?;
    require_text("language", &case.label.language)?;
    let pattern = SlopPattern::parse(&case.label.expected_pattern)
        .ok_or_else(|| format!("benchmark case {id} has an unknown typed pattern"))?;
    if !pattern.is_valid_for(case.label.expected_tier) {
        return Err(format!(
            "benchmark case {id} uses a pattern incompatible with its tier"
        ));
    }
    if case.before.is_empty() {
        return Err(format!("benchmark case {id} requires a before snapshot"));
    }
    validate_snapshots(id, "before", &case.before)?;
    require_text("human_explanation", &case.human_explanation)?;
    if case.scope == BenchmarkScope::Method && case.before.len() != 1 {
        return Err(format!(
            "method-scoped benchmark case {id} must identify exactly one before source"
        ));
    }
    if case.scope == BenchmarkScope::MultiMethod
        && case.partition == BenchmarkPartition::BlindOss
        && case.covered_method_ids.len() < 2
    {
        return Err(format!(
            "multi-method benchmark case {id} must identify at least two covered methods"
        ));
    }
    if case.expected_proof_level > 5 {
        return Err(format!("benchmark case {id} has proof level above P5"));
    }
    if is_finding(case.label.expected_tier) {
        if case.after.is_empty() {
            return Err(format!("finding case {id} requires an after snapshot"));
        }
        validate_snapshots(id, "after", &case.after)?;
        if case.behavioral_evidence.is_empty()
            || case
                .behavioral_evidence
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(format!("finding case {id} requires behavioral evidence"));
        }
    }
    if case.partition != BenchmarkPartition::SyntheticGold {
        validate_adjudications(case)?;
    }
    if case.partition == BenchmarkPartition::IntentionalBoundary
        && (!case.label.intentional_boundary || is_finding(case.label.expected_tier))
    {
        return Err(format!(
            "intentional-boundary case {id} must be a labeled non-finding boundary"
        ));
    }
    Ok(())
}

fn validate_adjudications(case: &ReleaseBenchmarkCase) -> Result<(), String> {
    let mut reviewers = HashSet::new();
    for item in &case.adjudications {
        require_text("reviewer_id", &item.reviewer_id)?;
        require_text("adjudication rationale", &item.rationale)?;
        if item.years_experience == 0 {
            return Err(format!(
                "benchmark case {} has an adjudicator without recorded experience",
                case.label.case_id
            ));
        }
        if !reviewers.insert(item.reviewer_id.as_str()) {
            return Err(format!(
                "benchmark case {} repeats adjudicator {}",
                case.label.case_id, item.reviewer_id
            ));
        }
        let pattern = SlopPattern::parse(&item.pattern).ok_or_else(|| {
            format!(
                "benchmark case {} adjudication has unknown pattern {}",
                case.label.case_id, item.pattern
            )
        })?;
        if !pattern.is_valid_for(item.tier) {
            return Err(format!(
                "benchmark case {} adjudication has an incompatible pattern",
                case.label.case_id
            ));
        }
    }
    if reviewers.is_empty() {
        return Err(format!(
            "real benchmark case {} requires an experienced adjudicator",
            case.label.case_id
        ));
    }
    let labels = case
        .adjudications
        .iter()
        .map(|item| (item.tier, item.pattern.as_str()))
        .collect::<HashSet<_>>();
    if labels.len() > 1 && !case.disputed {
        return Err(format!(
            "benchmark case {} has disagreeing labels but is not marked disputed",
            case.label.case_id
        ));
    }
    if !case.disputed
        && case.adjudications.iter().any(|item| {
            item.tier != case.label.expected_tier || item.pattern != case.label.expected_pattern
        })
    {
        return Err(format!(
            "benchmark case {} final label disagrees with its undisputed adjudication",
            case.label.case_id
        ));
    }
    if case.disputed {
        if reviewers.len() < 2 {
            return Err(format!(
                "disputed benchmark case {} requires two independent adjudicators",
                case.label.case_id
            ));
        }
        require_text(
            "dispute_resolution",
            case.dispute_resolution.as_deref().unwrap_or_default(),
        )?;
    }
    Ok(())
}

fn validate_snapshots(
    case_id: &str,
    label: &str,
    snapshots: &[SourceSnapshot],
) -> Result<(), String> {
    let mut artifacts = HashSet::new();
    for snapshot in snapshots {
        require_text(
            &format!("{case_id} {label} repository"),
            &snapshot.repository,
        )?;
        require_text(&format!("{case_id} {label} revision"), &snapshot.revision)?;
        require_text(
            &format!("{case_id} {label} repository_path"),
            &snapshot.repository_path,
        )?;
        require_safe_artifact_path(&snapshot.artifact_path)?;
        require_sha256(&format!("{case_id} {label} sha256"), &snapshot.sha256)?;
        if !artifacts.insert(snapshot.artifact_path.as_str()) {
            return Err(format!(
                "benchmark case {case_id} repeats {label} artifact {}",
                snapshot.artifact_path
            ));
        }
    }
    Ok(())
}

fn validate_submission(
    corpus: &BenchmarkCorpus,
    submission: &BenchmarkSubmission,
    corpus_root: &Path,
) -> Result<(), String> {
    if submission.schema_version != RELEASE_SCHEMA_VERSION {
        return Err(format!(
            "benchmark submission schema_version must be {RELEASE_SCHEMA_VERSION}"
        ));
    }
    if submission.corpus_id != corpus.corpus_id {
        return Err("benchmark submission does not target this frozen corpus".to_string());
    }
    if submission.runs.len() < 3 {
        return Err("release benchmark requires at least three complete runs".to_string());
    }
    let expected_ids = corpus
        .cases
        .iter()
        .map(|case| case.label.case_id.as_str())
        .collect::<HashSet<_>>();
    let mut run_ids = HashSet::new();
    let mut completed_artifact_ids = HashSet::new();
    let mut execution_commitments = HashSet::new();
    let mut cost_receipts = HashSet::new();
    let identity = submission.runs.first().map(run_identity);
    for run in &submission.runs {
        require_text("run_id", &run.run_id)?;
        require_text("tool_version", &run.tool_version)?;
        require_text("source_revision", &run.source_revision)?;
        require_text("provider", &run.provider)?;
        require_text("model", &run.model)?;
        require_text("prompt_contract_version", &run.prompt_contract_version)?;
        require_text("actual_cost_provenance", &run.actual_cost_provenance)?;
        validate_blind_reviewer(&run.blind_reviewer)?;
        validate_reviewer_separation(corpus, &run.blind_reviewer)?;
        require_safe_artifact_path(&run.actual_cost_artifact_path)?;
        require_sha256(
            "actual_cost_artifact_sha256",
            &run.actual_cost_artifact_sha256,
        )?;
        validate_actual_cost_receipt(
            corpus_root,
            &run.actual_cost_artifact_path,
            &run.actual_cost_artifact_sha256,
            &run.provider,
            &run.model,
            run.usage.actual_cost_microusd,
            &run.actual_cost_provenance,
        )?;
        if !cost_receipts.insert(run.actual_cost_artifact_sha256.as_str()) {
            return Err(format!(
                "repeatability runs reuse actual cost receipt {}",
                run.actual_cost_artifact_sha256
            ));
        }
        if !run_ids.insert(run.run_id.as_str()) {
            return Err(format!("benchmark submission repeats run {}", run.run_id));
        }
        if Some(run_identity(run)) != identity {
            return Err("repeatability runs use different tool/model contracts".to_string());
        }
        if !run
            .source_commitment_sha256
            .eq_ignore_ascii_case(&corpus.source_commitment_sha256)
        {
            return Err(format!(
                "benchmark run {} was not bound to the frozen source corpus",
                run.run_id
            ));
        }
        if !run
            .label_commitment_sha256
            .eq_ignore_ascii_case(&corpus.label_commitment_sha256)
        {
            return Err(format!(
                "benchmark run {} was not bound to the frozen label commitment",
                run.run_id
            ));
        }
        if run.usage.input_tokens == 0 && run.usage.output_tokens == 0 {
            return Err(format!(
                "benchmark run {} has no measured provider token usage",
                run.run_id
            ));
        }
        if run.completed_artifact_ids.is_empty()
            || run.completed_artifact_ids.len() != run.execution_commitments_sha256.len()
        {
            return Err(format!(
                "benchmark run {} has an incomplete completed-artifact ledger",
                run.run_id
            ));
        }
        if run.cross_scan_reused_units != 0 {
            return Err(format!(
                "benchmark run {} reused {} units from another scan and is not independent",
                run.run_id, run.cross_scan_reused_units
            ));
        }
        for artifact_id in &run.completed_artifact_ids {
            require_sha256("completed_artifact_id", artifact_id)?;
            if !completed_artifact_ids.insert(artifact_id.as_str()) {
                return Err(format!(
                    "repeatability runs reuse completed artifact {artifact_id}"
                ));
            }
        }
        for commitment in &run.execution_commitments_sha256 {
            require_sha256("execution_commitment_sha256", commitment)?;
            if !execution_commitments.insert(commitment.as_str()) {
                return Err(format!(
                    "repeatability runs reuse execution commitment {commitment}"
                ));
            }
        }
        if run.usage.cached_input_tokens > run.usage.input_tokens {
            return Err(format!(
                "benchmark run {} reports more cached input than total input",
                run.run_id
            ));
        }
        if run.analyzed_method_count == 0
            || !run.wall_clock_seconds.is_finite()
            || run.wall_clock_seconds <= 0.0
        {
            return Err(format!(
                "benchmark run {} has invalid execution measurements",
                run.run_id
            ));
        }
        let covered = run
            .covered_case_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if covered.len() != run.covered_case_ids.len() || covered != expected_ids {
            return Err(format!(
                "benchmark run {} does not prove complete corpus coverage",
                run.run_id
            ));
        }
        validate_run_predictions(run, &expected_ids)?;
    }
    validate_baselines(corpus, &submission.baselines, corpus_root)
}

fn validate_run_predictions(run: &BenchmarkRun, expected: &HashSet<&str>) -> Result<(), String> {
    let mut prediction_ids = HashSet::new();
    let mut matched_case_ids = HashSet::new();
    for prediction in &run.predictions {
        require_text("prediction_id", &prediction.prediction_id)?;
        if !prediction_ids.insert(prediction.prediction_id.as_str()) {
            return Err(format!(
                "benchmark run {} repeats prediction {}",
                run.run_id, prediction.prediction_id
            ));
        }
        if !prediction.reviewer_minutes.is_finite() || prediction.reviewer_minutes < 0.0 {
            return Err(format!(
                "prediction {} has invalid reviewer time",
                prediction.prediction_id
            ));
        }
        if prediction.proof_level > 5 {
            return Err(format!(
                "prediction {} has proof level above P5",
                prediction.prediction_id
            ));
        }
        let pattern = SlopPattern::parse(&prediction.pattern).ok_or_else(|| {
            format!(
                "prediction {} has unknown pattern",
                prediction.prediction_id
            )
        })?;
        if !pattern.is_valid_for(prediction.tier) {
            return Err(format!(
                "prediction {} has a pattern incompatible with its tier",
                prediction.prediction_id
            ));
        }
        if let Some(case_id) = prediction.matched_case_id.as_deref()
            && !expected.contains(case_id)
        {
            return Err(format!(
                "prediction {} matches unknown case {case_id}",
                prediction.prediction_id
            ));
        }
        if let Some(case_id) = prediction.matched_case_id.as_deref()
            && !matched_case_ids.insert(case_id)
        {
            return Err(format!(
                "benchmark run {} repeats the case-level outcome for {case_id}",
                run.run_id
            ));
        }
        if prediction.matched_case_id.is_none()
            && !is_finding(prediction.tier)
            && prediction.tier != FindingTier::Unresolved
        {
            return Err(format!(
                "unmatched prediction {} must be an emitted finding or unresolved coverage outcome",
                prediction.prediction_id
            ));
        }
        if is_finding(prediction.tier)
            && prediction.reviewer_disposition == ReviewerDisposition::Unreviewed
        {
            return Err(format!(
                "finding {} has not received blind human review",
                prediction.prediction_id
            ));
        }
        if is_finding(prediction.tier) {
            require_text(
                "finding_fingerprint",
                prediction
                    .finding_fingerprint
                    .as_deref()
                    .unwrap_or_default(),
            )?;
            if prediction.evidence.is_empty() {
                return Err(format!(
                    "finding {} has no exact source evidence",
                    prediction.prediction_id
                ));
            }
        } else if prediction.finding_fingerprint.is_some() {
            return Err(format!(
                "non-finding prediction {} supplies a finding fingerprint",
                prediction.prediction_id
            ));
        } else if !prediction.evidence.is_empty() {
            return Err(format!(
                "non-finding prediction {} supplies source evidence",
                prediction.prediction_id
            ));
        }
    }
    if matched_case_ids != *expected {
        let mut missing = expected
            .difference(&matched_case_ids)
            .copied()
            .collect::<Vec<_>>();
        missing.sort_unstable();
        return Err(format!(
            "benchmark run {} omitted case-level outcomes: {}",
            run.run_id,
            missing.join(", ")
        ));
    }
    Ok(())
}

fn validate_baselines(
    corpus: &BenchmarkCorpus,
    baselines: &[BenchmarkBaseline],
    corpus_root: &Path,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    let expected = corpus
        .cases
        .iter()
        .map(|case| case.label.case_id.as_str())
        .collect::<HashSet<_>>();
    for baseline in baselines {
        require_text("baseline tool_id", &baseline.tool_id)?;
        require_text("baseline tool_version", &baseline.tool_version)?;
        require_text("baseline run_id", &baseline.run_id)?;
        if !seen.insert(baseline.tool_id.as_str()) {
            return Err(format!(
                "benchmark submission repeats baseline {}",
                baseline.tool_id
            ));
        }
        if baseline.corpus_id != corpus.corpus_id
            || !baseline
                .source_commitment_sha256
                .eq_ignore_ascii_case(&corpus.source_commitment_sha256)
            || !baseline
                .label_commitment_sha256
                .eq_ignore_ascii_case(&corpus.label_commitment_sha256)
        {
            return Err(format!(
                "baseline {} is not bound to the frozen corpus labels",
                baseline.tool_id
            ));
        }
        require_safe_artifact_path(&baseline.raw_output_artifact_path)?;
        require_sha256("baseline raw_output_sha256", &baseline.raw_output_sha256)?;
        validate_artifact_hash(
            corpus_root,
            &baseline.raw_output_artifact_path,
            &baseline.raw_output_sha256,
            "baseline raw output",
        )?;
        let covered = baseline
            .covered_case_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if covered.len() != baseline.covered_case_ids.len() || covered != expected {
            return Err(format!(
                "baseline {} does not prove complete corpus coverage",
                baseline.tool_id
            ));
        }
        let mut finding_ids = HashSet::new();
        for finding in &baseline.findings {
            require_text("baseline finding_id", &finding.finding_id)?;
            if !finding_ids.insert(finding.finding_id.as_str()) {
                return Err(format!(
                    "baseline {} repeats finding {}",
                    baseline.tool_id, finding.finding_id
                ));
            }
            if finding.reviewer_disposition == ReviewerDisposition::Unreviewed {
                return Err(format!(
                    "baseline {} finding {} has not received blind human review",
                    baseline.tool_id, finding.finding_id
                ));
            }
            if !finding.reviewer_minutes.is_finite() || finding.reviewer_minutes <= 0.0 {
                return Err(format!(
                    "baseline {} finding {} has invalid reviewer time",
                    baseline.tool_id, finding.finding_id
                ));
            }
            if let Some(case_id) = finding.matched_case_id.as_deref()
                && !expected.contains(case_id)
            {
                return Err(format!(
                    "baseline {} finding {} matches unknown case {case_id}",
                    baseline.tool_id, finding.finding_id
                ));
            }
        }
    }
    for required in REQUIRED_BASELINES {
        if !seen.contains(required) {
            return Err(format!(
                "benchmark submission is missing baseline {required}"
            ));
        }
    }
    Ok(())
}

fn normalize_run(
    corpus: &BenchmarkCorpus,
    run: &BenchmarkRun,
    source_texts: &HashMap<String, String>,
) -> Result<Vec<BenchmarkPrediction>, String> {
    let case_map = corpus
        .cases
        .iter()
        .map(|case| (case.label.case_id.as_str(), case))
        .collect::<HashMap<_, _>>();
    let by_case = run
        .predictions
        .iter()
        .filter_map(|prediction| {
            prediction
                .matched_case_id
                .as_deref()
                .map(|case_id| (case_id, prediction))
        })
        .collect::<HashMap<_, _>>();
    corpus
        .cases
        .iter()
        .map(|case| {
            let prediction = by_case.get(case.label.case_id.as_str()).ok_or_else(|| {
                format!(
                    "benchmark run {} omitted case-level outcome {}",
                    run.run_id, case.label.case_id
                )
            })?;
            Ok(BenchmarkPrediction {
                case_id: case.label.case_id.clone(),
                tier: prediction.tier,
                pattern: prediction.pattern.clone(),
                evidence_valid: prediction_evidence_valid(prediction, &case_map, source_texts),
            })
        })
        .collect()
}

fn corpus_labels(corpus: &BenchmarkCorpus) -> Vec<BenchmarkCase> {
    corpus.cases.iter().map(|case| case.label.clone()).collect()
}

fn partition_metrics(
    corpus: &BenchmarkCorpus,
    predictions: &[BenchmarkPrediction],
) -> Result<BTreeMap<String, BenchmarkMetrics>, String> {
    let mut result = BTreeMap::new();
    for partition in BenchmarkPartition::all() {
        result.insert(
            format!("{partition:?}"),
            subset_metrics(corpus, predictions, |case| case.partition == partition)?,
        );
    }
    Ok(result)
}

fn subset_metrics<F>(
    corpus: &BenchmarkCorpus,
    predictions: &[BenchmarkPrediction],
    include: F,
) -> Result<BenchmarkMetrics, String>
where
    F: Fn(&ReleaseBenchmarkCase) -> bool,
{
    let prediction_map = predictions
        .iter()
        .map(|prediction| (prediction.case_id.as_str(), prediction))
        .collect::<HashMap<_, _>>();
    let cases = corpus
        .cases
        .iter()
        .filter(|case| include(case))
        .map(|case| case.label.clone())
        .collect::<Vec<_>>();
    let selected = cases
        .iter()
        .map(|case| prediction_map[case.case_id.as_str()].clone())
        .collect::<Vec<_>>();
    evaluate(&cases, &selected)
}

fn repeatability(runs: &[BenchmarkRun]) -> f64 {
    let identities = runs
        .iter()
        .map(run_prediction_identities)
        .collect::<Vec<_>>();
    let union = identities
        .iter()
        .flat_map(|identity| identity.iter().cloned())
        .collect::<HashSet<_>>();
    let stable = union
        .iter()
        .filter(|identity| identities.iter().all(|run| run.contains(*identity)))
        .count();
    ratio(stable, union.len() as f64)
}

fn run_prediction_identities(run: &BenchmarkRun) -> HashSet<String> {
    run.predictions
        .iter()
        .map(|prediction| {
            let identity = if let Some(case_id) = prediction.matched_case_id.as_deref() {
                format!("case:{case_id}")
            } else {
                format!(
                    "finding:{}",
                    prediction
                        .finding_fingerprint
                        .as_deref()
                        .unwrap_or_default()
                )
            };
            format!("{identity}:{:?}:{}", prediction.tier, prediction.pattern)
        })
        .collect()
}

fn duplicate_prediction_count(predictions: &[BenchmarkRunPrediction]) -> usize {
    let mut counts = HashMap::<&str, usize>::new();
    for prediction in predictions {
        if let Some(fingerprint) = prediction.finding_fingerprint.as_deref() {
            *counts.entry(fingerprint).or_default() += 1;
        }
    }
    counts.values().map(|count| count.saturating_sub(1)).sum()
}

fn validate_source_snapshots(
    corpus: &BenchmarkCorpus,
    corpus_root: &Path,
) -> Result<HashMap<String, String>, String> {
    let root = fs::canonicalize(corpus_root).map_err(|error| {
        format!(
            "failed to resolve benchmark corpus root {}: {error}",
            corpus_root.display()
        )
    })?;
    let mut expected_hashes = HashMap::<String, String>::new();
    for snapshot in corpus
        .analysis_sources
        .iter()
        .chain(corpus.cases.iter().flat_map(|case| case.after.iter()))
    {
        match expected_hashes.get(&snapshot.artifact_path) {
            Some(existing) if !existing.eq_ignore_ascii_case(&snapshot.sha256) => {
                return Err(format!(
                    "benchmark artifact {} is declared with conflicting hashes",
                    snapshot.artifact_path
                ));
            }
            Some(_) => {}
            None => {
                expected_hashes.insert(snapshot.artifact_path.clone(), snapshot.sha256.clone());
            }
        }
    }
    let mut source_texts = HashMap::new();
    for (artifact_path, expected_hash) in expected_hashes {
        let resolved = fs::canonicalize(root.join(&artifact_path)).map_err(|error| {
            format!("failed to resolve benchmark artifact {artifact_path}: {error}")
        })?;
        if !resolved.starts_with(&root) {
            return Err(format!(
                "benchmark artifact {artifact_path} escapes the corpus root"
            ));
        }
        let bytes = fs::read(&resolved).map_err(|error| {
            format!("failed to read benchmark artifact {artifact_path}: {error}")
        })?;
        let actual_hash = format!("{:x}", Sha256::digest(&bytes));
        if !actual_hash.eq_ignore_ascii_case(&expected_hash) {
            return Err(format!(
                "benchmark artifact {artifact_path} hash mismatch: expected {expected_hash}, got {actual_hash}"
            ));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| format!("benchmark artifact {artifact_path} is not UTF-8 source"))?;
        source_texts.insert(artifact_path, text);
    }
    Ok(source_texts)
}

fn validate_artifact_hash(
    corpus_root: &Path,
    artifact_path: &str,
    expected_hash: &str,
    label: &str,
) -> Result<(), String> {
    let root = fs::canonicalize(corpus_root).map_err(|error| {
        format!(
            "failed to resolve benchmark corpus root {}: {error}",
            corpus_root.display()
        )
    })?;
    let resolved = fs::canonicalize(root.join(artifact_path))
        .map_err(|error| format!("failed to resolve {label} {artifact_path}: {error}"))?;
    if !resolved.starts_with(&root) {
        return Err(format!("{label} {artifact_path} escapes the corpus root"));
    }
    let bytes = fs::read(&resolved)
        .map_err(|error| format!("failed to read {label} {artifact_path}: {error}"))?;
    let actual_hash = format!("{:x}", Sha256::digest(bytes));
    if !actual_hash.eq_ignore_ascii_case(expected_hash) {
        return Err(format!(
            "{label} {artifact_path} hash mismatch: expected {expected_hash}, got {actual_hash}"
        ));
    }
    Ok(())
}

fn validate_blind_reviewer(reviewer: &BlindReviewer) -> Result<(), String> {
    require_text("blind reviewer_id", &reviewer.reviewer_id)?;
    require_text("blind reviewer affiliation", &reviewer.affiliation)?;
    require_text("blind reviewer attestation", &reviewer.attestation)?;
    if reviewer.years_experience < 3 || reviewer.attestation.trim().len() < 20 {
        return Err(
            "blind reviewer requires at least three years of experience and a substantive attestation"
                .to_string(),
        );
    }
    if !reviewer.independent_from_sniff || !reviewer.labels_hidden_during_review {
        return Err(
            "blind reviewer must attest independence from Sniff and no access to hidden labels"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_reviewer_separation(
    corpus: &BenchmarkCorpus,
    reviewer: &BlindReviewer,
) -> Result<(), String> {
    let reviewer_id = reviewer.reviewer_id.trim();
    if corpus.cases.iter().any(|case| {
        case.adjudications
            .iter()
            .any(|adjudication| adjudication.reviewer_id.trim() == reviewer_id)
    }) {
        return Err(format!(
            "blind reviewer {reviewer_id} also adjudicated a frozen corpus label"
        ));
    }
    Ok(())
}

fn prediction_evidence_valid(
    prediction: &BenchmarkRunPrediction,
    cases: &HashMap<&str, &ReleaseBenchmarkCase>,
    source_texts: &HashMap<String, String>,
) -> bool {
    if !is_finding(prediction.tier) || prediction.evidence.is_empty() {
        return false;
    }
    let allowed = prediction
        .matched_case_id
        .as_deref()
        .and_then(|case_id| cases.get(case_id))
        .map(|case| {
            case.before
                .iter()
                .map(|snapshot| (snapshot.artifact_path.as_str(), snapshot.sha256.as_str()))
                .collect::<HashSet<_>>()
        });
    prediction.evidence.iter().all(|evidence| {
        if require_safe_artifact_path(&evidence.artifact_path).is_err()
            || require_sha256("evidence source_sha256", &evidence.source_sha256).is_err()
            || evidence.start_line == 0
            || evidence.end_line < evidence.start_line
            || evidence.quote.trim().is_empty()
        {
            return false;
        }
        if let Some(allowed) = &allowed
            && !allowed.iter().any(|(path, hash)| {
                *path == evidence.artifact_path
                    && hash.eq_ignore_ascii_case(&evidence.source_sha256)
            })
        {
            return false;
        }
        let Some(source) = source_texts.get(&evidence.artifact_path) else {
            return false;
        };
        let actual_hash = format!("{:x}", Sha256::digest(source.as_bytes()));
        if !actual_hash.eq_ignore_ascii_case(&evidence.source_sha256) {
            return false;
        }
        let lines = source.lines().collect::<Vec<_>>();
        let Some(selected) = lines.get(evidence.start_line - 1..evidence.end_line) else {
            return false;
        };
        let quote = evidence.quote.replace("\r\n", "\n");
        quote.lines().count() == evidence.end_line - evidence.start_line + 1
            && selected.join("\n").contains(&quote)
    })
}

fn require_safe_artifact_path(value: &str) -> Result<(), String> {
    require_text("artifact_path", value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "benchmark artifact_path must be a safe relative path: {value}"
        ));
    }
    Ok(())
}

fn release_errors(
    metrics: &ReleaseBenchmarkMetrics,
    submission: &BenchmarkSubmission,
    reviewed_findings: usize,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (run_id, run_metrics) in &metrics.real_world_per_run {
        errors.extend(
            run_metrics
                .release_gate_errors()
                .into_iter()
                .map(|error| format!("real-world corpus run {run_id}: {error}")),
        );
    }
    for (run_id, blind) in &metrics.blind_oss_per_run {
        errors.extend(
            blind
                .release_gate_errors()
                .into_iter()
                .map(|error| format!("blind OSS corpus run {run_id}: {error}")),
        );
    }
    for run in &submission.runs {
        let run_metrics = &metrics.per_run[&run.run_id];
        let unmatched_slop = run
            .predictions
            .iter()
            .filter(|prediction| {
                prediction.matched_case_id.is_none() && prediction.tier == FindingTier::Slop
            })
            .count();
        let unmatched_findings = run
            .predictions
            .iter()
            .filter(|prediction| {
                prediction.matched_case_id.is_none() && is_finding(prediction.tier)
            })
            .count();
        let adjusted_slop_precision = ratio(
            run_metrics.slop_true_positives,
            (run_metrics.predicted_slop + unmatched_slop) as f64,
        );
        let adjusted_combined_precision = ratio(
            run_metrics.combined_true_positives,
            (run_metrics.predicted_findings + unmatched_findings) as f64,
        );
        if adjusted_slop_precision < 0.95 {
            errors.push(format!(
                "run {} Slop precision including unmatched findings {:.2}% is below 95.00%",
                run.run_id,
                adjusted_slop_precision * 100.0
            ));
        }
        if adjusted_combined_precision < 0.85 {
            errors.push(format!(
                "run {} combined precision including unmatched findings {:.2}% is below 85.00%",
                run.run_id,
                adjusted_combined_precision * 100.0
            ));
        }
    }
    if metrics.overall_evidence_validity < 1.0 {
        errors.push(format!(
            "evidence validity across every emitted finding {:.2}% is below 100.00%",
            metrics.overall_evidence_validity * 100.0
        ));
    }
    if metrics.verdict_repeatability < 0.90 {
        errors.push(format!(
            "verdict repeatability {:.2}% is below 90.00%",
            metrics.verdict_repeatability * 100.0
        ));
    }
    if metrics.proof_level_accuracy < 1.0 {
        errors.push(format!(
            "proof-level compliance {:.2}% is below 100.00%",
            metrics.proof_level_accuracy * 100.0
        ));
    }
    if metrics.cost_usd_per_1000_methods > 0.75 {
        errors.push(format!(
            "cost ${:.4} per 1,000 methods exceeds $0.7500",
            metrics.cost_usd_per_1000_methods
        ));
    }
    if metrics.duplicate_case_rate > 0.02 {
        errors.push(format!(
            "duplicate-case rate {:.2}% exceeds 2.00%",
            metrics.duplicate_case_rate * 100.0
        ));
    }
    if metrics.accepted_findings == 0 || reviewed_findings == 0 || metrics.reviewer_minutes <= 0.0 {
        errors.push("blind human review produced no measurable accepted finding".to_string());
    }
    for baseline in &submission.baselines {
        let baseline_accepted = baseline
            .findings
            .iter()
            .filter(|finding| finding.reviewer_disposition == ReviewerDisposition::Accepted)
            .count();
        let baseline_minutes = baseline
            .findings
            .iter()
            .map(|finding| finding.reviewer_minutes)
            .sum::<f64>();
        let baseline_rate = ratio(baseline_accepted, baseline_minutes);
        if metrics.accepted_findings_per_reviewer_minute <= baseline_rate {
            errors.push(format!(
                "Sniff did not beat {} on accepted findings per reviewer-minute",
                baseline.tool_id
            ));
        }
    }
    errors
}

fn run_identity(run: &BenchmarkRun) -> (&str, &str, &str, &str, &str) {
    (
        run.tool_version.as_str(),
        run.source_revision.as_str(),
        run.provider.as_str(),
        run.model.as_str(),
        run.prompt_contract_version.as_str(),
    )
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("{label} must be a 64-character SHA-256 digest"))
    }
}

fn is_finding(tier: FindingTier) -> bool {
    matches!(tier, FindingTier::Slop | FindingTier::KindaSlop)
}

fn ratio(numerator: usize, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator as f64 / denominator
    }
}

#[cfg(test)]
#[path = "benchmark_release_tests.rs"]
mod tests;
