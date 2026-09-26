#[path = "benchmark_history_v3_schema.rs"]
mod schema;

pub use schema::*;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const PROTOCOL_CONTRACT: &str = "sniffbench-historical-v3-protocol-v6";
const MODEL_PROTOCOL_CONTRACT: &str = "sniffbench-historical-v3-model-judged-protocol-v7";
const STREAM_CONTRACT: &str = "sniffbench-historical-v3-stream-task-v1";
const RANKING_DOMAIN: &str = "sniffbench-historical-v3-candidate-rank-v1";
pub(super) const TEST_RECIPE_SELECTOR_CONTRACT: &str =
    "sniffbench-historical-v3-test-recipe-selectors-v1";
pub(super) const IDENTICAL_TEST_EXECUTION_POLICY_CONTRACT: &str =
    "sniffbench-historical-v3-identical-test-policy-v1";
const GITHUB_API_VERSION: &str = "2022-11-28";
const CANDIDATE_PARTITION: &str = "repository_then_merged_at_utc";
const CANDIDATE_PAGINATION: &str = "github_graphql_cursor_until_exhausted";

pub fn seal_historical_v3_protocol(
    mut protocol: HistoricalV3Protocol,
) -> Result<HistoricalV3Protocol, String> {
    protocol.protocol_sha256.clear();
    validate_historical_v3_protocol_fields(&protocol)?;
    protocol.protocol_sha256 = compute_protocol_sha256(&protocol)?;
    Ok(protocol)
}

pub fn validate_historical_v3_protocol(protocol: &HistoricalV3Protocol) -> Result<(), String> {
    validate_historical_v3_protocol_fields(protocol)?;
    require_sha256("historical-v3 protocol SHA-256", &protocol.protocol_sha256)?;
    if protocol.protocol_sha256 != compute_protocol_sha256(protocol)? {
        return Err("historical-v3 protocol commitment changed".to_string());
    }
    Ok(())
}

pub fn historical_v3_candidate_rank_sha256(
    protocol: &HistoricalV3Protocol,
    identity: &HistoricalV3CandidateIdentity,
) -> Result<String, String> {
    validate_historical_v3_protocol(protocol)?;
    validate_candidate_identity(protocol, identity)?;
    let mut digest = Sha256::new();
    for field in [
        protocol.ranking_domain.as_bytes(),
        protocol.ranking_seed.as_bytes(),
        language_key(identity.language).as_bytes(),
        identity.repository_id.to_string().as_bytes(),
        identity.pull_request_number.to_string().as_bytes(),
        identity.base_commit.as_bytes(),
        identity.merge_commit.as_bytes(),
    ] {
        digest.update(field);
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn prepare_historical_v3_stream_task(
    protocol: &HistoricalV3Protocol,
    identities: Vec<HistoricalV3CandidateIdentity>,
) -> Result<HistoricalV3StreamTask, String> {
    validate_historical_v3_protocol(protocol)?;
    if identities.is_empty() {
        return Err("historical-v3 candidate stream is empty".to_string());
    }

    let mut ranked = identities
        .into_iter()
        .map(|identity| {
            let rank_sha256 = historical_v3_candidate_rank_sha256(protocol, &identity)?;
            let tie_breaker = candidate_identity_key(&identity);
            Ok((rank_sha256, tie_breaker, identity))
        })
        .collect::<Result<Vec<_>, String>>()?;
    ranked.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));

    let mut identities_seen = HashSet::new();
    let mut ranks_seen = HashSet::new();
    let candidates = ranked
        .into_iter()
        .enumerate()
        .map(|(offset, (rank_sha256, identity_key, identity))| {
            if !identities_seen.insert(identity_key) {
                return Err("historical-v3 candidate identity is duplicated".to_string());
            }
            if !ranks_seen.insert(rank_sha256.clone()) {
                return Err("historical-v3 candidate rank is duplicated".to_string());
            }
            Ok(HistoricalV3CandidateTask {
                stream_rank: offset + 1,
                identity,
                rank_sha256,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let mut task = HistoricalV3StreamTask {
        schema_version: HISTORICAL_V3_STREAM_TASK_SCHEMA_VERSION,
        stream_contract: STREAM_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        candidates,
        task_sha256: String::new(),
    };
    task.task_sha256 = compute_stream_task_sha256(&task)?;
    Ok(task)
}

pub fn validate_historical_v3_stream_task(
    protocol: &HistoricalV3Protocol,
    task: &HistoricalV3StreamTask,
) -> Result<(), String> {
    validate_historical_v3_protocol(protocol)?;
    if task.schema_version != HISTORICAL_V3_STREAM_TASK_SCHEMA_VERSION
        || task.stream_contract != STREAM_CONTRACT
        || task.protocol_sha256 != protocol.protocol_sha256
        || task.candidates.is_empty()
    {
        return Err("historical-v3 stream task uses an unsupported contract".to_string());
    }

    let expected = prepare_historical_v3_stream_task(
        protocol,
        task.candidates
            .iter()
            .map(|candidate| candidate.identity.clone())
            .collect(),
    )?;
    if task != &expected {
        return Err("historical-v3 stream task changed its immutable candidates".to_string());
    }
    Ok(())
}

/// Checks an all-adjudicated language prefix. Terminal exclusions require the
/// separate evidence-bound ordered-stop evaluator before cohort publication.
pub fn evaluate_historical_v3_review_prefix(
    protocol: &HistoricalV3Protocol,
    task: &HistoricalV3StreamTask,
    language: HistoricalV3Language,
    records: &[HistoricalV3ReviewRecord],
) -> Result<HistoricalV3StopStatus, String> {
    validate_historical_v3_protocol(protocol)?;
    validate_historical_v3_stream_task(protocol, task)?;
    if !protocol.languages.contains(&language) {
        return Err("historical-v3 review language is outside the protocol".to_string());
    }

    let rule = &protocol.stop_rule;
    if records.len() > rule.adjudication_cap_per_language {
        return Err("historical-v3 review prefix exceeds its adjudication cap".to_string());
    }
    let language_candidates = task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == language)
        .collect::<Vec<_>>();
    let mut reviewed_by_repository = BTreeMap::<u64, usize>::new();
    let mut accepted_by_repository = BTreeMap::<u64, usize>::new();
    let mut accepted = 0;
    let mut accepted_repositories = BTreeSet::new();

    for (offset, record) in records.iter().enumerate() {
        if record.disposition == HistoricalV3ReviewDisposition::Disputed {
            return Err("historical-v3 review prefix contains an unresolved dispute".to_string());
        }
        require_sha256("historical-v3 review rank SHA-256", &record.rank_sha256)?;
        let candidate = language_candidates.get(offset).ok_or_else(|| {
            "historical-v3 review rank is outside the language stream".to_string()
        })?;
        if record.language != language
            || record.stream_rank != candidate.stream_rank
            || record.rank_sha256 != candidate.rank_sha256
            || record.language != candidate.identity.language
            || record.repository_id != candidate.identity.repository_id
        {
            return Err(
                "historical-v3 review prefix is not bound to its ordered language stream"
                    .to_string(),
            );
        }
        let reviewed = reviewed_by_repository
            .entry(record.repository_id)
            .or_default();
        *reviewed += 1;
        if *reviewed > rule.reviewable_candidate_cap_per_repository {
            return Err("historical-v3 repository review cap was exceeded".to_string());
        }

        if record.disposition == HistoricalV3ReviewDisposition::Accepted {
            accepted += 1;
            accepted_repositories.insert(record.repository_id);
            let repository_accepted = accepted_by_repository
                .entry(record.repository_id)
                .or_default();
            *repository_accepted += 1;
            if *repository_accepted > rule.accepted_case_cap_per_repository {
                return Err("historical-v3 repository acceptance cap was exceeded".to_string());
            }
        }

        if accepted >= rule.accepted_target_per_language
            && accepted_repositories.len() >= rule.distinct_repository_floor_per_language
        {
            if offset + 1 != records.len() {
                return Err(
                    "historical-v3 review continued past its first successful prefix".to_string(),
                );
            }
            return Ok(HistoricalV3StopStatus::TargetReached {
                reviewed_prefix: offset + 1,
                accepted,
                distinct_accepted_repositories: accepted_repositories.len(),
            });
        }
    }

    let status = if records.len() == rule.adjudication_cap_per_language {
        HistoricalV3StopStatus::FailedAdjudicationCap {
            reviewed: records.len(),
            accepted,
            distinct_accepted_repositories: accepted_repositories.len(),
        }
    } else if records.len() == language_candidates.len() {
        HistoricalV3StopStatus::FailedSourceExhausted {
            reviewed: records.len(),
            accepted,
            distinct_accepted_repositories: accepted_repositories.len(),
        }
    } else {
        HistoricalV3StopStatus::Continue {
            reviewed: records.len(),
            accepted,
            distinct_accepted_repositories: accepted_repositories.len(),
        }
    };
    Ok(status)
}

fn validate_historical_v3_protocol_fields(protocol: &HistoricalV3Protocol) -> Result<(), String> {
    if !matches!(
        protocol.schema_version,
        HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION | HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION
    ) || protocol.protocol_id.trim().is_empty()
        || (protocol.schema_version == HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION
            && protocol.protocol_contract != PROTOCOL_CONTRACT)
        || (protocol.schema_version == HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION
            && protocol.protocol_contract != MODEL_PROTOCOL_CONTRACT)
        || protocol.ranking_domain != RANKING_DOMAIN
    {
        return Err("historical-v3 protocol uses an unsupported contract".to_string());
    }
    require_sha256("historical-v3 ranking seed", &protocol.ranking_seed)?;
    require_sha256(
        "historical-v3 prior benchmark identity seal",
        &protocol.prior_benchmark_identity_seal_sha256,
    )?;
    if protocol.repository_created_after_utc != HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC {
        return Err("historical-v3 repository creation cutoff changed".to_string());
    }
    if protocol.languages != HistoricalV3Language::ALL {
        return Err(
            "historical-v3 protocol must cover the exact supported language set".to_string(),
        );
    }
    validate_source_frames(&protocol.source_frames)?;
    validate_candidate_window(&protocol.candidate_window)?;
    if protocol.allowed_metadata_fields != HistoricalV3AllowedMetadataField::ALL
        || protocol.forbidden_metadata_fields != HistoricalV3ForbiddenMetadataField::ALL
        || protocol.mechanical_requirements != HistoricalV3MechanicalRequirement::ALL
    {
        return Err("historical-v3 evidence policy changed".to_string());
    }
    validate_mechanical_policy(&protocol.mechanical_policy)?;
    validate_test_recipe_policy(&protocol.test_recipe_policy)?;
    validate_identical_test_policy(&protocol.identical_test_policy)?;
    match protocol.schema_version {
        HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION => {
            if protocol.model_review_policy.is_some() || !protocol.model_access_forbidden {
                return Err(
                    "historical-v3 human protocol cannot authorize model review".to_string()
                );
            }
            validate_human_review_policy(protocol.human_review_policy.as_ref().ok_or_else(
                || "historical-v3 human protocol lacks its human-review policy".to_string(),
            )?)?;
        }
        HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION => {
            if protocol.human_review_policy.is_some() || protocol.model_access_forbidden {
                return Err(
                    "historical-v3 model protocol cannot use human-review authority".to_string(),
                );
            }
            validate_model_review_policy(protocol.model_review_policy.as_ref().ok_or_else(
                || "historical-v3 model protocol lacks its model-review policy".to_string(),
            )?)?;
        }
        _ => unreachable!("schema version checked above"),
    }
    validate_stop_rule(&protocol.stop_rule)?;
    if !protocol.no_fallbacks || !protocol.sniff_output_access_forbidden {
        return Err("historical-v3 construction must fail closed and remain blind".to_string());
    }
    Ok(())
}

fn validate_model_review_policy(policy: &HistoricalV3ModelReviewPolicy) -> Result<(), String> {
    require_sha256(
        "historical-v3 approved agent prompt",
        &policy.approved_prompt_sha256,
    )?;
    if !policy.source_only_review
        || policy.independent_reviewers != 2
        || policy.prompt_public_url.trim().is_empty()
        || !policy.exact_presented_material_record_required
        || !policy.invocation_response_record_required
        || !policy.disagreements_remain_unresolved
        || !policy.human_gold_claim_forbidden
    {
        return Err("historical-v3 model-review policy is invalid".to_string());
    }
    Ok(())
}

fn validate_human_review_policy(policy: &HistoricalV3HumanReviewPolicy) -> Result<(), String> {
    if !policy.source_only_review
        || policy.independent_reviewers != 2
        || !policy.distinct_dispute_resolver
        || !policy.reviewers_must_not_see_sniff_output
        || !policy.reviewers_must_not_see_repository_identity
        || !policy.reviewers_must_not_see_change_metadata
        || !policy.reviewers_must_not_see_each_other_labels
        || !policy.human_only_review
        || !policy.complete_source_context_required
        || !policy.behavior_evidence_required
        || !policy.exact_before_mechanism_required
        || !policy.exact_after_removal_required
        || !policy.relocation_check_required
        || !policy.simpler_counterfactual_required
    {
        return Err("historical-v3 human-review policy is invalid".to_string());
    }
    Ok(())
}

fn validate_identical_test_policy(policy: &HistoricalV3IdenticalTestPolicy) -> Result<(), String> {
    if policy.execution_contract != IDENTICAL_TEST_EXECUTION_POLICY_CONTRACT
        || policy.cpu_limit_millis != 4_000
        || policy.memory_limit_bytes != 8 * 1024 * 1024 * 1024
        || policy.process_limit != 1_024
        || policy.temporary_filesystem_bytes != 2 * 1024 * 1024 * 1024
        || policy.preparation_command_timeout_seconds != 30 * 60
        || policy.test_command_timeout_seconds != 60 * 60
        || policy.retained_output_bytes != 64 * 1024
        || !policy.network_disabled_during_all_commands
        || !policy.ephemeral_container_filesystem
        || !policy.host_source_mounts_forbidden
        || !policy.all_capabilities_dropped
        || !policy.no_new_privileges
    {
        return Err("historical-v3 identical-test policy is invalid".to_string());
    }
    Ok(())
}

fn validate_test_recipe_policy(policy: &HistoricalV3TestRecipePolicy) -> Result<(), String> {
    const MAXIMUM_FILE_BYTES: u64 = 16 * 1024 * 1024;
    const MAXIMUM_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    if policy.selector_contract != TEST_RECIPE_SELECTOR_CONTRACT
        || policy.selectors != HistoricalV3TestRecipeSelector::ALL
        || policy.maximum_input_file_bytes == 0
        || policy.maximum_input_file_bytes > MAXIMUM_FILE_BYTES
        || policy.maximum_total_input_bytes < policy.maximum_input_file_bytes
        || policy.maximum_total_input_bytes > MAXIMUM_TOTAL_BYTES
        || policy.execution_platform != "linux/amd64"
        || !policy.network_disabled_during_tests
    {
        return Err("historical-v3 test-recipe policy is invalid".to_string());
    }
    if policy.environments.len() != HistoricalV3Language::ALL.len()
        || policy
            .environments
            .iter()
            .map(|environment| environment.language)
            .ne(HistoricalV3Language::ALL)
    {
        return Err(
            "historical-v3 test environments do not cover every language in order".to_string(),
        );
    }
    for environment in &policy.environments {
        if !valid_image_digest(&environment.image_digest) {
            return Err("historical-v3 test environment image digest is invalid".to_string());
        }
        require_sha256(
            "historical-v3 test toolchain manifest",
            &environment.toolchain_manifest_sha256,
        )?;
        require_sha256(
            "historical-v3 test dependency store",
            &environment.dependency_store_sha256,
        )?;
    }
    Ok(())
}

fn valid_image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_mechanical_policy(policy: &HistoricalV3MechanicalPolicy) -> Result<(), String> {
    if policy.production_method_minimum == 0
        || policy.production_method_maximum < policy.production_method_minimum
    {
        return Err("historical-v3 mechanical method bounds are invalid".to_string());
    }
    let path_segment_groups = [
        ("generated path segments", &policy.generated_path_segments),
        ("vendored path segments", &policy.vendored_path_segments),
        (
            "documentation path segments",
            &policy.documentation_path_segments,
        ),
        ("fixture path segments", &policy.fixture_path_segments),
        ("test path segments", &policy.test_path_segments),
    ];
    let mut path_segments = BTreeSet::new();
    for (label, values) in path_segment_groups {
        validate_policy_strings(label, values, false)?;
        if values
            .iter()
            .any(|value| !path_segments.insert(value.as_str()))
        {
            return Err("historical-v3 mechanical path role segments must be disjoint".to_string());
        }
    }
    validate_policy_strings("test file suffixes", &policy.test_file_suffixes, true)?;
    Ok(())
}

fn validate_policy_strings(label: &str, values: &[String], suffix: bool) -> Result<(), String> {
    if values.is_empty()
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| {
            value.is_empty()
                || value != &value.to_ascii_lowercase()
                || value.contains('/')
                || value.contains('\\')
                || value.contains('\0')
                || (suffix
                    && value
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric()))
                || (!suffix && (value == "." || value == ".."))
        })
    {
        return Err(format!(
            "historical-v3 mechanical {label} are not canonical, unique, and ordered"
        ));
    }
    Ok(())
}

fn validate_source_frames(frames: &[HistoricalV3SourceFrameBinding]) -> Result<(), String> {
    if frames.len() != HistoricalV3Language::ALL.len() {
        return Err("historical-v3 requires one source frame per language".to_string());
    }
    if frames
        .iter()
        .map(|frame| frame.language)
        .ne(HistoricalV3Language::ALL)
    {
        return Err("historical-v3 source frames are not in canonical language order".to_string());
    }
    let mut languages = BTreeSet::new();
    let mut frame_ids = HashSet::new();
    for frame in frames {
        if !languages.insert(frame.language)
            || frame.frame_id.trim().is_empty()
            || !frame_ids.insert(frame.frame_id.clone())
            || frame.repository_count == 0
        {
            return Err("historical-v3 source-frame binding is invalid".to_string());
        }
        require_sha256("historical-v3 frame policy", &frame.policy_sha256)?;
        require_sha256("historical-v3 frame manifest", &frame.manifest_sha256)?;
        require_sha256("historical-v3 frame", &frame.frame_sha256)?;
    }
    if languages.into_iter().collect::<Vec<_>>() != HistoricalV3Language::ALL {
        return Err("historical-v3 source frames do not cover every language".to_string());
    }
    Ok(())
}

fn validate_candidate_window(window: &HistoricalV3CandidateWindow) -> Result<(), String> {
    if window.github_api_version != GITHUB_API_VERSION
        || window.partition != CANDIDATE_PARTITION
        || window.pagination != CANDIDATE_PAGINATION
        || !is_utc_timestamp(&window.merged_at_or_after_utc)
        || !is_utc_timestamp(&window.merged_before_utc)
        || window.merged_at_or_after_utc >= window.merged_before_utc
    {
        return Err("historical-v3 candidate window is invalid".to_string());
    }
    Ok(())
}

fn validate_stop_rule(rule: &HistoricalV3StopRule) -> Result<(), String> {
    if rule.accepted_target_per_language != 40
        || rule.distinct_repository_floor_per_language != 20
        || rule.accepted_case_cap_per_repository != 4
        || rule.reviewable_candidate_cap_per_repository != 8
        || rule.adjudication_cap_per_language != 400
    {
        return Err("historical-v3 stopping rule changed".to_string());
    }
    Ok(())
}

fn validate_candidate_identity(
    protocol: &HistoricalV3Protocol,
    identity: &HistoricalV3CandidateIdentity,
) -> Result<(), String> {
    if !protocol.languages.contains(&identity.language)
        || identity.repository_id == 0
        || identity.pull_request_number == 0
    {
        return Err("historical-v3 candidate identity is invalid".to_string());
    }
    for (label, value) in [
        ("base commit", &identity.base_commit),
        ("head commit", &identity.head_commit),
        ("merge commit", &identity.merge_commit),
    ] {
        require_git_oid(&format!("historical-v3 {label}"), value)?;
    }
    if identity.base_commit == identity.merge_commit {
        return Err("historical-v3 candidate does not change its base revision".to_string());
    }
    Ok(())
}

fn compute_protocol_sha256(protocol: &HistoricalV3Protocol) -> Result<String, String> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema_version: u32,
        protocol_id: &'a str,
        protocol_contract: &'a str,
        ranking_domain: &'a str,
        ranking_seed: &'a str,
        prior_benchmark_identity_seal_sha256: &'a str,
        repository_created_after_utc: &'a str,
        languages: &'a [HistoricalV3Language],
        source_frames: &'a [HistoricalV3SourceFrameBinding],
        candidate_window: &'a HistoricalV3CandidateWindow,
        allowed_metadata_fields: &'a [HistoricalV3AllowedMetadataField],
        forbidden_metadata_fields: &'a [HistoricalV3ForbiddenMetadataField],
        mechanical_requirements: &'a [HistoricalV3MechanicalRequirement],
        mechanical_policy: &'a HistoricalV3MechanicalPolicy,
        stop_rule: &'a HistoricalV3StopRule,
        no_fallbacks: bool,
        model_access_forbidden: bool,
        sniff_output_access_forbidden: bool,
    }
    let base = Commitment {
        schema_version: protocol.schema_version,
        protocol_id: &protocol.protocol_id,
        protocol_contract: &protocol.protocol_contract,
        ranking_domain: &protocol.ranking_domain,
        ranking_seed: &protocol.ranking_seed,
        prior_benchmark_identity_seal_sha256: &protocol.prior_benchmark_identity_seal_sha256,
        repository_created_after_utc: &protocol.repository_created_after_utc,
        languages: &protocol.languages,
        source_frames: &protocol.source_frames,
        candidate_window: &protocol.candidate_window,
        allowed_metadata_fields: &protocol.allowed_metadata_fields,
        forbidden_metadata_fields: &protocol.forbidden_metadata_fields,
        mechanical_requirements: &protocol.mechanical_requirements,
        mechanical_policy: &protocol.mechanical_policy,
        stop_rule: &protocol.stop_rule,
        no_fallbacks: protocol.no_fallbacks,
        model_access_forbidden: protocol.model_access_forbidden,
        sniff_output_access_forbidden: protocol.sniff_output_access_forbidden,
    };
    if protocol.schema_version == HISTORICAL_V3_MODEL_PROTOCOL_SCHEMA_VERSION {
        json_sha256(&(
            &base,
            protocol.model_review_policy.as_ref().ok_or_else(|| {
                "historical-v3 model protocol lacks its model-review policy".to_string()
            })?,
        ))
    } else {
        json_sha256(&base)
    }
}

fn compute_stream_task_sha256(task: &HistoricalV3StreamTask) -> Result<String, String> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema_version: u32,
        stream_contract: &'a str,
        protocol_sha256: &'a str,
        candidates: &'a [HistoricalV3CandidateTask],
    }
    json_sha256(&Commitment {
        schema_version: task.schema_version,
        stream_contract: &task.stream_contract,
        protocol_sha256: &task.protocol_sha256,
        candidates: &task.candidates,
    })
}

fn candidate_identity_key(identity: &HistoricalV3CandidateIdentity) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}",
        language_key(identity.language),
        identity.repository_id,
        identity.pull_request_number,
        identity.base_commit,
        identity.head_commit,
        identity.merge_commit
    )
}

fn language_key(language: HistoricalV3Language) -> &'static str {
    match language {
        HistoricalV3Language::Go => "go",
        HistoricalV3Language::JavaScript => "javascript",
        HistoricalV3Language::Kotlin => "kotlin",
        HistoricalV3Language::Python => "python",
        HistoricalV3Language::Rust => "rust",
        HistoricalV3Language::TypeScript => "typescript",
    }
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 artifact: {error}"))
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not a lowercase SHA-256"));
    }
    Ok(())
}

fn require_git_oid(label: &str, value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not a full lowercase Git object ID"));
    }
    Ok(())
}

fn is_utc_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

#[cfg(test)]
#[path = "benchmark_history_v3_protocol_tests.rs"]
mod tests;
