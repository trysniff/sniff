use super::{
    FrameEligibilityAudit, SOURCE_RANK_CONTRACT, SUPPORTED_LANGUAGES, SourceCandidateAssessment,
    SourceRepositoryDraft, SourceSamplingPolicy, SourceSelectionWorksheet, build_source_selection,
    json_sha256, ranked_candidates, require_sha256, require_text, selection_task_sha256, sha256,
    validate_assessment, validate_frame_eligibility, validate_policy,
    validate_source_selection_worksheet, validate_worksheet_header,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const SOURCE_SELECTION_COMPONENT_AUDIT_SCHEMA_VERSION: u32 = 1;
pub const SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION: u32 = 1;
pub const SOURCE_SELECTION_COMPOSITE_AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionComponentAudit {
    pub schema_version: u32,
    pub rank_contract: String,
    pub policy: SourceSamplingPolicy,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub frame_eligibility: FrameEligibilityAudit,
    pub task_sha256: String,
    pub assessments: Vec<SourceCandidateAssessment>,
    pub selected_counts: BTreeMap<String, usize>,
    pub selected_repositories: Vec<SourceRepositoryDraft>,
    pub component_audit_sha256: String,
}

impl SourceSelectionComponentAudit {
    pub fn computed_component_audit_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            rank_contract: &'a str,
            policy: &'a SourceSamplingPolicy,
            policy_sha256: &'a str,
            frame_sha256: &'a str,
            frame_eligibility: &'a FrameEligibilityAudit,
            task_sha256: &'a str,
            assessments: &'a [SourceCandidateAssessment],
            selected_counts: &'a BTreeMap<String, usize>,
            selected_repositories: &'a [SourceRepositoryDraft],
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            rank_contract: &self.rank_contract,
            policy: &self.policy,
            policy_sha256: &self.policy_sha256,
            frame_sha256: &self.frame_sha256,
            frame_eligibility: &self.frame_eligibility,
            task_sha256: &self.task_sha256,
            assessments: &self.assessments,
            selected_counts: &self.selected_counts,
            selected_repositories: &self.selected_repositories,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionComponentCommitment {
    pub selection_id: String,
    pub policy_sha256: String,
    pub frame_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionCompositePolicy {
    pub schema_version: u32,
    pub selection_id: String,
    pub selected_at: String,
    pub language_quotas: BTreeMap<String, usize>,
    pub components: Vec<SourceSelectionComponentCommitment>,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionCompositeAudit {
    pub schema_version: u32,
    pub policy: SourceSelectionCompositePolicy,
    pub policy_sha256: String,
    pub components: Vec<SourceSelectionComponentAudit>,
    pub selected_counts: BTreeMap<String, usize>,
    pub selected_repositories: Vec<SourceRepositoryDraft>,
    pub composite_audit_sha256: String,
}

impl SourceSelectionCompositeAudit {
    pub fn computed_composite_audit_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            policy: &'a SourceSelectionCompositePolicy,
            policy_sha256: &'a str,
            components: &'a [SourceSelectionComponentAudit],
            selected_counts: &'a BTreeMap<String, usize>,
            selected_repositories: &'a [SourceRepositoryDraft],
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            policy: &self.policy,
            policy_sha256: &self.policy_sha256,
            components: &self.components,
            selected_counts: &self.selected_counts,
            selected_repositories: &self.selected_repositories,
        })
    }
}

pub fn audit_source_selection_component(
    policy: SourceSamplingPolicy,
    frame: &[u8],
    worksheet: SourceSelectionWorksheet,
) -> Result<SourceSelectionComponentAudit, String> {
    validate_source_selection_worksheet(&policy, frame, &worksheet)?;
    let expected = build_source_selection(policy, frame)?;
    validate_worksheet_header(&worksheet, &expected)?;
    if worksheet.candidates.len() != expected.candidates.len() {
        return Err("source selection worksheet changed the ranked candidate prefix".to_string());
    }
    for (completed, immutable) in worksheet.candidates.iter().zip(&expected.candidates) {
        if completed.candidate != immutable.candidate {
            return Err(format!(
                "source selection changed ranked candidate {}",
                immutable.candidate.rank
            ));
        }
    }
    let mut selected_counts = worksheet
        .policy
        .language_quotas
        .keys()
        .map(|language| (language.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut selected_repositories = Vec::new();
    for assessment in &worksheet.candidates {
        validate_assessment(
            assessment,
            &worksheet.policy,
            &mut selected_counts,
            &mut selected_repositories,
        )?;
    }
    selected_repositories.sort_by(|left, right| left.repository.cmp(&right.repository));
    let mut audit = SourceSelectionComponentAudit {
        schema_version: SOURCE_SELECTION_COMPONENT_AUDIT_SCHEMA_VERSION,
        rank_contract: SOURCE_RANK_CONTRACT.to_string(),
        policy: worksheet.policy,
        policy_sha256: worksheet.policy_sha256,
        frame_sha256: worksheet.frame_sha256,
        frame_eligibility: worksheet.frame_eligibility,
        task_sha256: worksheet.task_sha256,
        assessments: worksheet.candidates,
        selected_counts,
        selected_repositories,
        component_audit_sha256: String::new(),
    };
    audit.component_audit_sha256 = audit.computed_component_audit_sha256()?;
    Ok(audit)
}

pub fn combine_source_selections(
    policy: SourceSelectionCompositePolicy,
    components: Vec<SourceSelectionComponentAudit>,
) -> Result<SourceSelectionCompositeAudit, String> {
    let audit = combine_source_selections_unchecked(policy, components)?;
    validate_source_selection_composite_audit(&audit)?;
    Ok(audit)
}

fn combine_source_selections_unchecked(
    policy: SourceSelectionCompositePolicy,
    components: Vec<SourceSelectionComponentAudit>,
) -> Result<SourceSelectionCompositeAudit, String> {
    validate_composite_policy(&policy)?;
    if components.len() != policy.components.len() {
        return Err(
            "composite source selection does not contain every precommitted component".to_string(),
        );
    }
    let mut selected_counts = policy
        .language_quotas
        .keys()
        .map(|language| (language.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut selected_repositories = Vec::new();
    let mut identities = HashSet::new();
    for (commitment, component) in policy.components.iter().zip(&components) {
        validate_source_selection_component_audit(component)?;
        if commitment.selection_id != component.policy.selection_id
            || commitment.policy_sha256 != component.policy_sha256
            || commitment.frame_sha256 != component.frame_sha256
        {
            return Err(
                "composite source selection component does not match its precommitment".to_string(),
            );
        }
        for repository in &component.selected_repositories {
            let language = repository.selection_language.to_ascii_lowercase();
            let Some(count) = selected_counts.get_mut(&language) else {
                return Err(format!(
                    "composite source selection contains unrequested language {language}"
                ));
            };
            if !identities.insert((
                repository.repository.to_ascii_lowercase(),
                repository.revision.to_ascii_lowercase(),
            )) {
                return Err(format!(
                    "composite source selection repeats {} at {}",
                    repository.repository, repository.revision
                ));
            }
            *count += 1;
            selected_repositories.push(repository.clone());
        }
    }
    for (language, expected) in &policy.language_quotas {
        let actual = selected_counts[language];
        if actual != *expected {
            return Err(format!(
                "composite source selection filled {actual} of {expected} required {language} repositories"
            ));
        }
    }
    selected_repositories.sort_by(|left, right| left.repository.cmp(&right.repository));
    let policy_sha256 = json_sha256(&policy)?;
    let mut audit = SourceSelectionCompositeAudit {
        schema_version: SOURCE_SELECTION_COMPOSITE_AUDIT_SCHEMA_VERSION,
        policy,
        policy_sha256,
        components,
        selected_counts,
        selected_repositories,
        composite_audit_sha256: String::new(),
    };
    audit.composite_audit_sha256 = audit.computed_composite_audit_sha256()?;
    Ok(audit)
}

pub fn validate_source_selection_component_audit(
    audit: &SourceSelectionComponentAudit,
) -> Result<(), String> {
    if audit.schema_version != SOURCE_SELECTION_COMPONENT_AUDIT_SCHEMA_VERSION
        || audit.rank_contract != SOURCE_RANK_CONTRACT
    {
        return Err("source selection component audit uses an unsupported contract".to_string());
    }
    validate_policy(&audit.policy)?;
    let policy_sha256 = json_sha256(&audit.policy)?;
    if audit.policy_sha256 != policy_sha256 || audit.frame_sha256 != audit.policy.frame_sha256 {
        return Err("source selection component policy or frame commitment changed".to_string());
    }
    require_sha256("source selection task SHA-256", &audit.task_sha256)?;
    validate_frame_eligibility(&audit.frame_eligibility)?;
    if audit.assessments.len() != audit.policy.assessment_prefix {
        return Err(
            "source selection component does not contain the precommitted prefix".to_string(),
        );
    }
    validate_ranked_assessments(audit)?;
    let mut selected_counts = audit
        .policy
        .language_quotas
        .keys()
        .map(|language| (language.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut selected_repositories = Vec::new();
    for assessment in &audit.assessments {
        validate_assessment(
            assessment,
            &audit.policy,
            &mut selected_counts,
            &mut selected_repositories,
        )?;
    }
    selected_repositories.sort_by(|left, right| left.repository.cmp(&right.repository));
    if audit.selected_counts != selected_counts {
        return Err("source selection component count ledger changed".to_string());
    }
    if audit.selected_repositories != selected_repositories {
        return Err("source selection component repository ledger changed".to_string());
    }
    let expected = audit.computed_component_audit_sha256()?;
    if !audit.component_audit_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "source selection component commitment mismatch; expected {expected}"
        ));
    }
    Ok(())
}

pub fn validate_source_selection_component_against_frame(
    audit: &SourceSelectionComponentAudit,
    frame: &[u8],
) -> Result<(), String> {
    validate_source_selection_component_audit(audit)?;
    let frame_sha256 = sha256(frame);
    if frame_sha256 != audit.frame_sha256 {
        return Err(format!(
            "source selection component frame hash mismatch; expected {}, got {frame_sha256}",
            audit.frame_sha256
        ));
    }
    let expected = ranked_candidates(frame, &audit.policy.seed, audit.policy.assessment_prefix)?;
    if audit.frame_eligibility != expected.eligibility {
        return Err(
            "source selection component does not match the pinned frame eligibility census"
                .to_string(),
        );
    }
    if !audit
        .assessments
        .iter()
        .map(|assessment| &assessment.candidate)
        .eq(expected.candidates.iter())
    {
        return Err(
            "source selection component does not match the pinned frame ranking".to_string(),
        );
    }
    Ok(())
}

pub fn validate_source_selection_composite_audit(
    audit: &SourceSelectionCompositeAudit,
) -> Result<(), String> {
    if audit.schema_version != SOURCE_SELECTION_COMPOSITE_AUDIT_SCHEMA_VERSION {
        return Err("composite source selection uses an unsupported contract".to_string());
    }
    validate_composite_policy(&audit.policy)?;
    if audit.policy_sha256 != json_sha256(&audit.policy)? {
        return Err("composite source selection policy commitment changed".to_string());
    }
    let rebuilt =
        combine_source_selections_unchecked(audit.policy.clone(), audit.components.clone())?;
    if audit.selected_counts != rebuilt.selected_counts
        || audit.selected_repositories != rebuilt.selected_repositories
    {
        return Err("composite source selection ledger changed".to_string());
    }
    let expected = audit.computed_composite_audit_sha256()?;
    if !audit.composite_audit_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "composite source selection commitment mismatch; expected {expected}"
        ));
    }
    Ok(())
}

fn validate_composite_policy(policy: &SourceSelectionCompositePolicy) -> Result<(), String> {
    if policy.schema_version != SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION {
        return Err(format!(
            "composite source-selection policy schema_version must be {SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION}"
        ));
    }
    require_text("composite selection_id", &policy.selection_id)?;
    require_text("composite selected_at", &policy.selected_at)?;
    require_text("composite selection attestation", &policy.attestation)?;
    if policy.language_quotas.len() != SUPPORTED_LANGUAGES.len()
        || SUPPORTED_LANGUAGES.iter().any(|language| {
            policy
                .language_quotas
                .get(*language)
                .is_none_or(|quota| *quota == 0)
        })
    {
        return Err(
            "composite source-selection policy requires positive quotas for all supported languages"
                .to_string(),
        );
    }
    if policy.components.len() < 2 {
        return Err(
            "composite source-selection policy requires at least two components".to_string(),
        );
    }
    let mut selection_ids = HashSet::new();
    for component in &policy.components {
        require_text("component selection_id", &component.selection_id)?;
        require_sha256("component policy SHA-256", &component.policy_sha256)?;
        require_sha256("component frame SHA-256", &component.frame_sha256)?;
        if !selection_ids.insert(component.selection_id.as_str()) {
            return Err("composite source-selection policy repeats a component".to_string());
        }
    }
    Ok(())
}

fn validate_ranked_assessments(audit: &SourceSelectionComponentAudit) -> Result<(), String> {
    let mut repositories = HashSet::new();
    for (index, assessment) in audit.assessments.iter().enumerate() {
        if assessment.candidate.rank != index + 1
            || assessment.candidate.rank_sha256
                != sha256(
                    format!(
                        "{SOURCE_RANK_CONTRACT}\n{}\n{}",
                        audit.policy.seed, assessment.candidate.repository
                    )
                    .as_bytes(),
                )
            || !repositories.insert(assessment.candidate.repository.as_str())
        {
            return Err(
                "source selection component audit has an invalid ranked prefix".to_string(),
            );
        }
    }
    let expected = selection_task_sha256(
        &audit.policy_sha256,
        &audit.frame_sha256,
        &audit.frame_eligibility,
        &audit.assessments,
    )?;
    if audit.task_sha256 != expected {
        return Err("source selection audit task commitment changed".to_string());
    }
    Ok(())
}
