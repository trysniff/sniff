use super::{BenchmarkSourceSeal, NonBlindHistoryWorksheet, NonBlindSelectionPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INTENTIONAL_BOUNDARY_PROTOCOL_SCHEMA_VERSION: u32 = 1;
const PROTOCOL_ID: &str = "sniffbench-intentional-boundary-protocol-v1";
const POLICY_PATH: &str = "sniffbench/non-blind-v1-selection-policy.json";
const BLIND_SEAL_PATH: &str = "sniffbench/blind-oss-v1-source-seal.json";
const POPULATION_PATH: &str = "sniffbench/non-blind-v1-history-worksheet.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindSealBinding {
    pub artifact_path: String,
    pub sha256: String,
    pub seal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPopulationBinding {
    pub artifact_path: String,
    pub sha256: String,
    pub task_sha256: String,
    pub candidate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryFrameContract {
    pub schema_version: u32,
    pub complete_population_required: bool,
    pub immutable_revision_required: bool,
    pub clean_complete_non_sparse_checkout_required: bool,
    pub compiler_semantic_index_required: bool,
    pub every_repository_checkpointed: bool,
    pub typed_exclusions_required: bool,
    pub path_or_name_only_evidence_forbidden: bool,
    pub model_access_forbidden: bool,
    pub sniff_output_access_forbidden: bool,
    pub candidate_identity_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryCategory {
    Adapter,
    RetryBoundary,
    PublicWrapper,
    CompatibilityApi,
    GeneratedSurface,
    TestSeam,
    Entrypoint,
    FrameworkCallback,
}

impl IntentionalBoundaryCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Adapter => "adapter",
            Self::RetryBoundary => "retry_boundary",
            Self::PublicWrapper => "public_wrapper",
            Self::CompatibilityApi => "compatibility_api",
            Self::GeneratedSurface => "generated_surface",
            Self::TestSeam => "test_seam",
            Self::Entrypoint => "entrypoint",
            Self::FrameworkCallback => "framework_callback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryEvidenceKind {
    CompilerResolvedImplementationOrDelegation,
    PassingBehaviorTest,
    DistinctRetryableAndTerminalOutcomes,
    ExportedApiIdentity,
    ResolvedConsumer,
    PublishedApiContract,
    VersionedCompatibilityContract,
    RetainedCompatibilityConsumer,
    GeneratorIdentity,
    GeneratorConfiguration,
    ReproducibleGeneratedOutput,
    ResolvedTestInjectionOrReplacement,
    RuntimeOrPackageManifest,
    FrameworkRegistration,
    CompilerResolvedOverrideOrInterface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAlternativeGroup {
    pub any_of: Vec<BoundaryEvidenceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryCategoryContract {
    pub category: IntentionalBoundaryCategory,
    pub required_evidence_groups: Vec<EvidenceAlternativeGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundarySlotContract {
    pub cases_per_category: usize,
    pub total_slots: usize,
    pub ranking_contract: String,
    pub selection_after_complete_frame: bool,
    pub failed_candidate_closes_slot: bool,
    pub backfill_forbidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryLabelContract {
    pub source_only_review: bool,
    pub independent_reviewers: usize,
    pub reviewers_must_not_see_sniff_output: bool,
    pub reviewers_must_not_see_each_other_labels: bool,
    pub required_tier: String,
    pub intentional_boundary_must_be_true: bool,
    pub distinct_dispute_resolver: bool,
    pub rejected_label_closes_slot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProtocol {
    pub schema_version: u32,
    pub protocol_id: String,
    pub prepared_at: String,
    pub precommit_parent_revision: String,
    pub no_fallbacks: bool,
    pub selection_policy: ArtifactBinding,
    pub blind_source_seal: BlindSealBinding,
    pub repository_population: RepositoryPopulationBinding,
    pub frame_contract: BoundaryFrameContract,
    pub category_contracts: Vec<BoundaryCategoryContract>,
    pub slot_contract: BoundarySlotContract,
    pub label_contract: BoundaryLabelContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIntentionalBoundaryProtocol {
    pub protocol: IntentionalBoundaryProtocol,
    pub protocol_sha256: String,
}

pub fn validate_intentional_boundary_protocol(
    policy_bytes: &[u8],
    history_worksheet_bytes: &[u8],
    blind_seal_bytes: &[u8],
    protocol_bytes: &[u8],
) -> Result<ValidatedIntentionalBoundaryProtocol, String> {
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    super::non_blind_history::validate_policy(&policy)?;
    let worksheet: NonBlindHistoryWorksheet = serde_json::from_slice(history_worksheet_bytes)
        .map_err(|error| format!("failed to parse intentional-boundary population: {error}"))?;
    let blind_seal: BenchmarkSourceSeal = serde_json::from_slice(blind_seal_bytes)
        .map_err(|error| format!("failed to parse intentional-boundary blind seal: {error}"))?;
    if blind_seal.computed_seal_sha256()? != blind_seal.seal_sha256 {
        return Err("intentional-boundary blind source seal commitment mismatch".to_string());
    }
    let protocol: IntentionalBoundaryProtocol = serde_json::from_slice(protocol_bytes)
        .map_err(|error| format!("failed to parse intentional-boundary protocol: {error}"))?;
    if protocol.schema_version != INTENTIONAL_BOUNDARY_PROTOCOL_SCHEMA_VERSION
        || protocol.protocol_id != PROTOCOL_ID
        || protocol.prepared_at.trim().is_empty()
        || !protocol.no_fallbacks
    {
        return Err("intentional-boundary protocol identity or fallback mode changed".to_string());
    }
    require_git_revision(
        "intentional-boundary precommit_parent_revision",
        &protocol.precommit_parent_revision,
    )?;
    validate_artifact_binding(
        &protocol.selection_policy,
        POLICY_PATH,
        policy_bytes,
        "selection policy",
    )?;
    validate_blind_binding(&protocol.blind_source_seal, blind_seal_bytes, &blind_seal)?;
    validate_population_binding(
        &protocol.repository_population,
        history_worksheet_bytes,
        &worksheet,
    )?;
    if protocol.frame_contract != expected_frame_contract() {
        return Err("intentional-boundary frame contract changed".to_string());
    }
    let expected_categories = expected_category_contracts();
    if protocol.category_contracts != expected_categories
        || policy
            .intentional_boundaries
            .categories
            .iter()
            .map(String::as_str)
            .ne(expected_categories
                .iter()
                .map(|contract| contract.category.as_str()))
    {
        return Err("intentional-boundary category evidence contract changed".to_string());
    }
    let boundaries = &policy.intentional_boundaries;
    let expected_slots = BoundarySlotContract {
        cases_per_category: boundaries.cases_per_category,
        total_slots: boundaries.cases_per_category * expected_categories.len(),
        ranking_contract: boundaries.candidate_ranking_contract.clone(),
        selection_after_complete_frame: true,
        failed_candidate_closes_slot: true,
        backfill_forbidden: true,
    };
    if protocol.slot_contract != expected_slots {
        return Err("intentional-boundary fixed-slot contract changed".to_string());
    }
    if protocol.label_contract != expected_label_contract() {
        return Err("intentional-boundary independent-label contract changed".to_string());
    }
    Ok(ValidatedIntentionalBoundaryProtocol {
        protocol,
        protocol_sha256: sha256(protocol_bytes),
    })
}

fn validate_artifact_binding(
    binding: &ArtifactBinding,
    expected_path: &str,
    bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    if binding.artifact_path != expected_path
        || !binding.sha256.eq_ignore_ascii_case(&sha256(bytes))
    {
        return Err(format!("intentional-boundary {label} binding changed"));
    }
    Ok(())
}

fn validate_blind_binding(
    binding: &BlindSealBinding,
    bytes: &[u8],
    seal: &BenchmarkSourceSeal,
) -> Result<(), String> {
    if binding.artifact_path != BLIND_SEAL_PATH
        || !binding.sha256.eq_ignore_ascii_case(&sha256(bytes))
        || !binding.seal_sha256.eq_ignore_ascii_case(&seal.seal_sha256)
    {
        return Err("intentional-boundary blind source-seal binding changed".to_string());
    }
    Ok(())
}

fn validate_population_binding(
    binding: &RepositoryPopulationBinding,
    bytes: &[u8],
    worksheet: &NonBlindHistoryWorksheet,
) -> Result<(), String> {
    if binding.artifact_path != POPULATION_PATH
        || !binding.sha256.eq_ignore_ascii_case(&sha256(bytes))
        || binding.task_sha256 != worksheet.task_sha256
        || binding.candidate_count != worksheet.candidates.len()
        || worksheet.candidates.len() != 600
        || worksheet
            .candidates
            .iter()
            .enumerate()
            .any(|(index, candidate)| candidate.rank != index + 1)
    {
        return Err("intentional-boundary repository population binding changed".to_string());
    }
    Ok(())
}

fn expected_frame_contract() -> BoundaryFrameContract {
    BoundaryFrameContract {
        schema_version: 1,
        complete_population_required: true,
        immutable_revision_required: true,
        clean_complete_non_sparse_checkout_required: true,
        compiler_semantic_index_required: true,
        every_repository_checkpointed: true,
        typed_exclusions_required: true,
        path_or_name_only_evidence_forbidden: true,
        model_access_forbidden: true,
        sniff_output_access_forbidden: true,
        candidate_identity_fields: [
            "category",
            "repository",
            "revision",
            "repository_path",
            "exact_symbol_identity",
        ]
        .map(str::to_string)
        .to_vec(),
    }
}

fn evidence(any_of: &[BoundaryEvidenceKind]) -> EvidenceAlternativeGroup {
    EvidenceAlternativeGroup {
        any_of: any_of.to_vec(),
    }
}

fn expected_category_contracts() -> Vec<BoundaryCategoryContract> {
    use BoundaryEvidenceKind as Evidence;
    use IntentionalBoundaryCategory as Category;
    vec![
        BoundaryCategoryContract {
            category: Category::Adapter,
            required_evidence_groups: vec![
                evidence(&[Evidence::CompilerResolvedImplementationOrDelegation]),
                evidence(&[Evidence::PassingBehaviorTest]),
            ],
        },
        BoundaryCategoryContract {
            category: Category::RetryBoundary,
            required_evidence_groups: vec![
                evidence(&[Evidence::DistinctRetryableAndTerminalOutcomes]),
                evidence(&[Evidence::PassingBehaviorTest]),
            ],
        },
        BoundaryCategoryContract {
            category: Category::PublicWrapper,
            required_evidence_groups: vec![
                evidence(&[Evidence::ExportedApiIdentity]),
                evidence(&[Evidence::ResolvedConsumer, Evidence::PublishedApiContract]),
            ],
        },
        BoundaryCategoryContract {
            category: Category::CompatibilityApi,
            required_evidence_groups: vec![
                evidence(&[Evidence::VersionedCompatibilityContract]),
                evidence(&[Evidence::RetainedCompatibilityConsumer]),
            ],
        },
        BoundaryCategoryContract {
            category: Category::GeneratedSurface,
            required_evidence_groups: vec![
                evidence(&[Evidence::GeneratorIdentity]),
                evidence(&[Evidence::GeneratorConfiguration]),
                evidence(&[Evidence::ReproducibleGeneratedOutput]),
            ],
        },
        BoundaryCategoryContract {
            category: Category::TestSeam,
            required_evidence_groups: vec![evidence(&[
                Evidence::ResolvedTestInjectionOrReplacement,
            ])],
        },
        BoundaryCategoryContract {
            category: Category::Entrypoint,
            required_evidence_groups: vec![evidence(&[Evidence::RuntimeOrPackageManifest])],
        },
        BoundaryCategoryContract {
            category: Category::FrameworkCallback,
            required_evidence_groups: vec![evidence(&[
                Evidence::FrameworkRegistration,
                Evidence::CompilerResolvedOverrideOrInterface,
            ])],
        },
    ]
}

fn expected_label_contract() -> BoundaryLabelContract {
    BoundaryLabelContract {
        source_only_review: true,
        independent_reviewers: 2,
        reviewers_must_not_see_sniff_output: true,
        reviewers_must_not_see_each_other_labels: true,
        required_tier: "clean".to_string(),
        intentional_boundary_must_be_true: true,
        distinct_dispute_resolver: true,
        rejected_label_closes_slot: true,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
    const HISTORY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
    const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
    const PROTOCOL: &[u8] =
        include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

    fn parsed() -> IntentionalBoundaryProtocol {
        serde_json::from_slice(PROTOCOL).unwrap()
    }

    #[test]
    fn validates_the_precommitted_intentional_boundary_protocol() {
        let validated =
            validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, PROTOCOL).unwrap();

        assert_eq!(validated.protocol.category_contracts.len(), 8);
        assert_eq!(validated.protocol.slot_contract.total_slots, 16);
        assert_eq!(validated.protocol_sha256.len(), 64);
    }

    #[test]
    fn rejects_path_or_name_selection_and_category_drift() {
        let mut protocol = parsed();
        protocol.frame_contract.path_or_name_only_evidence_forbidden = false;
        let bytes = serde_json::to_vec(&protocol).unwrap();
        assert!(
            validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, &bytes)
                .unwrap_err()
                .contains("frame contract changed")
        );

        let mut protocol = parsed();
        protocol.category_contracts[0]
            .required_evidence_groups
            .clear();
        let bytes = serde_json::to_vec(&protocol).unwrap();
        assert!(
            validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, &bytes)
                .unwrap_err()
                .contains("category evidence contract changed")
        );
    }

    #[test]
    fn rejects_population_or_slot_backfill_drift() {
        let mut protocol = parsed();
        protocol.repository_population.candidate_count -= 1;
        let bytes = serde_json::to_vec(&protocol).unwrap();
        assert!(
            validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, &bytes)
                .unwrap_err()
                .contains("population binding changed")
        );

        let mut protocol = parsed();
        protocol.slot_contract.backfill_forbidden = false;
        let bytes = serde_json::to_vec(&protocol).unwrap();
        assert!(
            validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, &bytes)
                .unwrap_err()
                .contains("fixed-slot contract changed")
        );
    }
}
