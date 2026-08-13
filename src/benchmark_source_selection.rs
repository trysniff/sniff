use super::SourceRepositoryDraft;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const SOURCE_SELECTION_AUDIT_SCHEMA_VERSION: u32 = 1;
const SOURCE_RANK_CONTRACT: &str = "sniffbench-source-rank-v1";
const SUPPORTED_LANGUAGES: [&str; 6] =
    ["go", "javascript", "kotlin", "python", "rust", "typescript"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSamplingPolicy {
    pub schema_version: u32,
    pub selection_id: String,
    pub selected_at: String,
    pub frame_source: String,
    pub frame_revision: String,
    pub frame_blob_sha: String,
    pub frame_sha256: String,
    pub seed: String,
    pub assessment_prefix: usize,
    pub minimum_methods: usize,
    pub maximum_methods: usize,
    pub language_quotas: BTreeMap<String, usize>,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankedSourceCandidate {
    pub rank: usize,
    pub repository: String,
    pub rank_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSelectionDisposition {
    Selected,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceExclusionReason {
    UnsupportedLanguage,
    Archived,
    Fork,
    Inaccessible,
    MissingLicense,
    NoSupportedMethods,
    BelowMethodFloor,
    AboveMethodCeiling,
    UnsupportedProjectShape,
    QuotaFilled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAssessmentFacts {
    pub repository: String,
    pub selection_quota_language: String,
    pub observed_method_count: Option<usize>,
    pub accessible: bool,
    pub archived: Option<bool>,
    pub fork: Option<bool>,
    pub license_path: Option<String>,
    pub supported_project_shape: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAssessmentEvidenceKind {
    StructuredFacts,
    RawSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAssessmentEvidence {
    pub kind: SourceAssessmentEvidenceKind,
    pub source: String,
    pub observed_at: String,
    pub payload: String,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCandidateAssessment {
    #[serde(flatten)]
    pub candidate: RankedSourceCandidate,
    pub selection_quota_language: String,
    pub observed_method_count: Option<usize>,
    pub facts: Option<SourceAssessmentFacts>,
    pub evidence: Vec<SourceAssessmentEvidence>,
    pub disposition: Option<SourceSelectionDisposition>,
    pub exclusion_reason: Option<SourceExclusionReason>,
    pub selected_repository: Option<SourceRepositoryDraft>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionWorksheet {
    pub schema_version: u32,
    pub rank_contract: String,
    pub policy: SourceSamplingPolicy,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub task_sha256: String,
    pub candidates: Vec<SourceCandidateAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSelectionAudit {
    pub schema_version: u32,
    pub rank_contract: String,
    pub policy: SourceSamplingPolicy,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub task_sha256: String,
    pub assessments: Vec<SourceCandidateAssessment>,
    pub selected_repositories: Vec<SourceRepositoryDraft>,
    pub audit_sha256: String,
}

impl SourceSelectionAudit {
    pub fn computed_audit_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            rank_contract: &'a str,
            policy: &'a SourceSamplingPolicy,
            policy_sha256: &'a str,
            frame_sha256: &'a str,
            task_sha256: &'a str,
            assessments: &'a [SourceCandidateAssessment],
            selected_repositories: &'a [SourceRepositoryDraft],
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            rank_contract: &self.rank_contract,
            policy: &self.policy,
            policy_sha256: &self.policy_sha256,
            frame_sha256: &self.frame_sha256,
            task_sha256: &self.task_sha256,
            assessments: &self.assessments,
            selected_repositories: &self.selected_repositories,
        })
    }
}

pub fn prepare_source_selection(
    policy: SourceSamplingPolicy,
    frame: &[u8],
) -> Result<SourceSelectionWorksheet, String> {
    validate_policy(&policy)?;
    let frame_sha256 = sha256(frame);
    if !frame_sha256.eq_ignore_ascii_case(&policy.frame_sha256) {
        return Err(format!(
            "source sampling frame hash mismatch; expected {}, got {frame_sha256}",
            policy.frame_sha256
        ));
    }
    let policy_sha256 = json_sha256(&policy)?;
    let candidates = ranked_candidates(frame, &policy.seed, policy.assessment_prefix)?
        .into_iter()
        .map(|candidate| SourceCandidateAssessment {
            candidate,
            selection_quota_language: String::new(),
            observed_method_count: None,
            facts: None,
            evidence: Vec::new(),
            disposition: None,
            exclusion_reason: None,
            selected_repository: None,
        })
        .collect::<Vec<_>>();
    let task_sha256 = selection_task_sha256(&policy_sha256, &frame_sha256, &candidates)?;
    Ok(SourceSelectionWorksheet {
        schema_version: SOURCE_SELECTION_AUDIT_SCHEMA_VERSION,
        rank_contract: SOURCE_RANK_CONTRACT.to_string(),
        policy,
        policy_sha256,
        frame_sha256,
        task_sha256,
        candidates,
    })
}

pub fn audit_source_selection(
    policy: SourceSamplingPolicy,
    frame: &[u8],
    worksheet: SourceSelectionWorksheet,
) -> Result<SourceSelectionAudit, String> {
    let expected = prepare_source_selection(policy, frame)?;
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
    for (language, expected) in &worksheet.policy.language_quotas {
        let actual = selected_counts[language];
        if actual != *expected {
            return Err(format!(
                "source selection filled {actual} of {expected} required {language} repositories"
            ));
        }
    }
    selected_repositories.sort_by(|left, right| left.repository.cmp(&right.repository));
    let mut audit = SourceSelectionAudit {
        schema_version: SOURCE_SELECTION_AUDIT_SCHEMA_VERSION,
        rank_contract: SOURCE_RANK_CONTRACT.to_string(),
        policy: worksheet.policy,
        policy_sha256: worksheet.policy_sha256,
        frame_sha256: worksheet.frame_sha256,
        task_sha256: worksheet.task_sha256,
        assessments: worksheet.candidates,
        selected_repositories,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit.computed_audit_sha256()?;
    Ok(audit)
}

pub fn validate_source_selection_audit(audit: &SourceSelectionAudit) -> Result<(), String> {
    if audit.schema_version != SOURCE_SELECTION_AUDIT_SCHEMA_VERSION
        || audit.rank_contract != SOURCE_RANK_CONTRACT
    {
        return Err("source selection audit uses an unsupported contract".to_string());
    }
    validate_policy(&audit.policy)?;
    let policy_sha256 = json_sha256(&audit.policy)?;
    if audit.policy_sha256 != policy_sha256 || audit.frame_sha256 != audit.policy.frame_sha256 {
        return Err("source selection audit policy or frame commitment changed".to_string());
    }
    require_sha256("source selection task SHA-256", &audit.task_sha256)?;
    if audit.assessments.len() != audit.policy.assessment_prefix {
        return Err("source selection audit does not contain the precommitted prefix".to_string());
    }
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
            return Err("source selection audit has an invalid ranked prefix".to_string());
        }
    }
    let task_sha256 = selection_task_sha256(
        &audit.policy_sha256,
        &audit.frame_sha256,
        &audit.assessments,
    )?;
    if audit.task_sha256 != task_sha256 {
        return Err("source selection audit task commitment changed".to_string());
    }
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
    for (language, quota) in &audit.policy.language_quotas {
        if selected_counts[language] != *quota {
            return Err(format!(
                "source selection audit does not fill the {language} quota"
            ));
        }
    }
    selected_repositories.sort_by(|left, right| left.repository.cmp(&right.repository));
    if audit.selected_repositories != selected_repositories {
        return Err("source selection audit selected-repository ledger changed".to_string());
    }
    let expected = audit.computed_audit_sha256()?;
    if !audit.audit_sha256.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "source selection audit commitment mismatch; expected {expected}"
        ));
    }
    Ok(())
}

pub fn source_selection_draft(
    audit: &SourceSelectionAudit,
    frame: &[u8],
) -> Result<super::SourceSelectionDraft, String> {
    validate_source_selection_against_frame(audit, frame)?;
    Ok(super::SourceSelectionDraft {
        schema_version: super::SOURCE_SEAL_SCHEMA_VERSION,
        selection_id: audit.policy.selection_id.clone(),
        selected_at: audit.policy.selected_at.clone(),
        selection_methodology: format!(
            "Hash-ranked {} candidates from {} at {} under {} with seed commitment {}.",
            audit.policy.assessment_prefix,
            audit.policy.frame_source,
            audit.policy.frame_revision,
            audit.rank_contract,
            sha256(audit.policy.seed.as_bytes())
        ),
        selection_attestation: audit.policy.attestation.clone(),
        selection_audit_sha256: audit.audit_sha256.clone(),
        selection_frame_sha256: audit.frame_sha256.clone(),
        repositories: audit.selected_repositories.clone(),
    })
}

pub(crate) fn validate_source_selection_against_frame(
    audit: &SourceSelectionAudit,
    frame: &[u8],
) -> Result<(), String> {
    validate_source_selection_audit(audit)?;
    let frame_sha256 = sha256(frame);
    if frame_sha256 != audit.frame_sha256 {
        return Err(format!(
            "source selection frame hash mismatch; expected {}, got {frame_sha256}",
            audit.frame_sha256
        ));
    }
    let expected = ranked_candidates(frame, &audit.policy.seed, audit.policy.assessment_prefix)?;
    if !audit
        .assessments
        .iter()
        .map(|assessment| &assessment.candidate)
        .eq(expected.iter())
    {
        return Err("source selection audit does not match the pinned frame ranking".to_string());
    }
    Ok(())
}

fn validate_assessment(
    assessment: &SourceCandidateAssessment,
    policy: &SourceSamplingPolicy,
    selected_counts: &mut BTreeMap<String, usize>,
    selected_repositories: &mut Vec<SourceRepositoryDraft>,
) -> Result<(), String> {
    let language = assessment
        .selection_quota_language
        .trim()
        .to_ascii_lowercase();
    require_text("candidate selection_quota_language", &language)?;
    let supported = selected_counts.contains_key(&language);
    let method_count = assessment.observed_method_count;
    let facts = assessment.facts.as_ref().ok_or_else(|| {
        format!(
            "ranked candidate {} has no assessed repository facts",
            assessment.candidate.repository
        )
    })?;
    validate_assessment_evidence(assessment)?;
    if facts.repository != assessment.candidate.repository
        || !facts
            .selection_quota_language
            .eq_ignore_ascii_case(&language)
        || facts.observed_method_count != method_count
    {
        return Err(format!(
            "ranked candidate {} contradicts its structured evidence facts",
            assessment.candidate.repository
        ));
    }
    if let Some(license_path) = &facts.license_path {
        safe_relative(license_path)?;
    }
    match assessment.disposition {
        Some(SourceSelectionDisposition::Selected) => {
            if !supported {
                return Err(format!(
                    "selected repository {} has unsupported quota language {language}",
                    assessment.candidate.repository
                ));
            }
            let methods = method_count.ok_or_else(|| {
                format!(
                    "selected repository {} has no observed method count",
                    assessment.candidate.repository
                )
            })?;
            if methods < policy.minimum_methods || methods > policy.maximum_methods {
                return Err(format!(
                    "selected repository {} is outside the precommitted method range",
                    assessment.candidate.repository
                ));
            }
            if assessment.exclusion_reason.is_some() {
                return Err("selected repository cannot carry an exclusion reason".to_string());
            }
            let selected = assessment.selected_repository.as_ref().ok_or_else(|| {
                format!(
                    "selected candidate {} has no checkout identity",
                    assessment.candidate.repository
                )
            })?;
            let canonical_repository = format!("https://{}", assessment.candidate.repository);
            if selected.repository != canonical_repository
                || normalize_repository(&selected.repository)? != assessment.candidate.repository
            {
                return Err(format!(
                    "selected checkout identity must be {canonical_repository}"
                ));
            }
            if !selected.selection_language.eq_ignore_ascii_case(&language)
                || selected.observed_method_count != methods
            {
                return Err(format!(
                    "selected checkout {} does not match its assessed language or method count",
                    assessment.candidate.repository
                ));
            }
            validate_selected_repository(selected)?;
            if !facts.accessible
                || facts.archived != Some(false)
                || facts.fork != Some(false)
                || facts.supported_project_shape != Some(true)
                || facts.license_path.as_deref() != Some(selected.license_path.as_str())
            {
                return Err(format!(
                    "selected checkout {} contradicts its assessed repository facts",
                    assessment.candidate.repository
                ));
            }
            let count = selected_counts
                .get_mut(&language)
                .expect("supported language was checked");
            if *count >= policy.language_quotas[&language] {
                return Err(format!(
                    "source selection chose {} after the {language} quota was full",
                    assessment.candidate.repository
                ));
            }
            *count += 1;
            selected_repositories.push(selected.clone());
        }
        Some(SourceSelectionDisposition::Excluded) => {
            if assessment.selected_repository.is_some() {
                return Err("excluded candidate cannot carry a selected checkout".to_string());
            }
            let reason = assessment.exclusion_reason.ok_or_else(|| {
                format!(
                    "excluded candidate {} has no typed reason",
                    assessment.candidate.repository
                )
            })?;
            validate_exclusion(
                reason,
                supported,
                method_count,
                &language,
                facts,
                policy,
                selected_counts,
            )?;
        }
        None => {
            return Err(format!(
                "ranked candidate {} has not been assessed",
                assessment.candidate.repository
            ));
        }
    }
    Ok(())
}

fn validate_exclusion(
    reason: SourceExclusionReason,
    supported: bool,
    method_count: Option<usize>,
    language: &str,
    facts: &SourceAssessmentFacts,
    policy: &SourceSamplingPolicy,
    selected_counts: &BTreeMap<String, usize>,
) -> Result<(), String> {
    let valid = match reason {
        SourceExclusionReason::UnsupportedLanguage => !supported,
        SourceExclusionReason::NoSupportedMethods => method_count == Some(0),
        SourceExclusionReason::BelowMethodFloor => {
            method_count.is_some_and(|count| count < policy.minimum_methods)
        }
        SourceExclusionReason::AboveMethodCeiling => {
            method_count.is_some_and(|count| count > policy.maximum_methods)
        }
        SourceExclusionReason::QuotaFilled => {
            supported && selected_counts[language] >= policy.language_quotas[language]
        }
        SourceExclusionReason::Archived => facts.archived == Some(true),
        SourceExclusionReason::Fork => facts.fork == Some(true),
        SourceExclusionReason::Inaccessible => !facts.accessible,
        SourceExclusionReason::MissingLicense => facts.accessible && facts.license_path.is_none(),
        SourceExclusionReason::UnsupportedProjectShape => {
            facts.supported_project_shape == Some(false)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "candidate exclusion {reason:?} contradicts its recorded evidence"
        ))
    }
}

fn validate_assessment_evidence(assessment: &SourceCandidateAssessment) -> Result<(), String> {
    if assessment.evidence.is_empty() || assessment.evidence.len() > 4 {
        return Err(format!(
            "ranked candidate {} requires one to four evidence payloads",
            assessment.candidate.repository
        ));
    }
    let mut identities = HashSet::new();
    let mut structured_facts = 0_usize;
    let mut raw_sources = 0_usize;
    for evidence in &assessment.evidence {
        require_text("source assessment evidence source", &evidence.source)?;
        require_text(
            "source assessment evidence observed_at",
            &evidence.observed_at,
        )?;
        require_text("source assessment evidence payload", &evidence.payload)?;
        match evidence.kind {
            SourceAssessmentEvidenceKind::StructuredFacts
                if evidence.source != "derived:source-assessment-facts-v1" =>
            {
                return Err("structured-fact evidence must use its canonical source ID".to_string());
            }
            SourceAssessmentEvidenceKind::RawSource if !evidence.source.starts_with("https://") => {
                return Err("raw-source evidence must identify an HTTPS source".to_string());
            }
            _ => {}
        }
        require_sha256(
            "source assessment evidence payload SHA-256",
            &evidence.payload_sha256,
        )?;
        if evidence.payload.len() > 65_536 {
            return Err("source assessment evidence payload exceeds 64 KiB".to_string());
        }
        let actual = sha256(evidence.payload.as_bytes());
        if !actual.eq_ignore_ascii_case(&evidence.payload_sha256) {
            return Err(format!(
                "source assessment evidence hash mismatch for {}",
                assessment.candidate.repository
            ));
        }
        if !identities.insert((evidence.source.as_str(), evidence.payload_sha256.as_str())) {
            return Err(format!(
                "source assessment repeats evidence for {}",
                assessment.candidate.repository
            ));
        }
        match evidence.kind {
            SourceAssessmentEvidenceKind::StructuredFacts => {
                structured_facts += 1;
                if serde_json::from_str::<SourceAssessmentFacts>(&evidence.payload).ok()
                    != assessment.facts
                {
                    return Err(format!(
                        "ranked candidate {} has contradictory structured-fact evidence",
                        assessment.candidate.repository
                    ));
                }
            }
            SourceAssessmentEvidenceKind::RawSource => raw_sources += 1,
        }
    }
    if structured_facts != 1 || raw_sources == 0 {
        return Err(format!(
            "ranked candidate {} requires exactly one structured-fact payload and at least one raw-source payload",
            assessment.candidate.repository
        ));
    }
    Ok(())
}

fn validate_selected_repository(repository: &SourceRepositoryDraft) -> Result<(), String> {
    require_revision(&repository.revision)?;
    safe_relative(&repository.license_path)?;
    let mut context = HashSet::new();
    for path in &repository.context_paths {
        safe_relative(path)?;
        if !context.insert(path) {
            return Err(format!(
                "selected repository {} repeats a context path",
                repository.repository
            ));
        }
    }
    Ok(())
}

fn validate_policy(policy: &SourceSamplingPolicy) -> Result<(), String> {
    if policy.schema_version != SOURCE_SELECTION_AUDIT_SCHEMA_VERSION {
        return Err(format!(
            "source sampling policy schema_version must be {SOURCE_SELECTION_AUDIT_SCHEMA_VERSION}"
        ));
    }
    require_text("selection_id", &policy.selection_id)?;
    require_text("selected_at", &policy.selected_at)?;
    require_text("frame_source", &policy.frame_source)?;
    require_revision(&policy.frame_revision)?;
    require_revision(&policy.frame_blob_sha)?;
    require_sha256("frame SHA-256", &policy.frame_sha256)?;
    require_text("selection seed", &policy.seed)?;
    require_text("selection attestation", &policy.attestation)?;
    if policy.assessment_prefix == 0
        || policy.minimum_methods == 0
        || policy.maximum_methods < policy.minimum_methods
    {
        return Err("source sampling policy has invalid prefix or method limits".to_string());
    }
    if policy.language_quotas.is_empty()
        || policy.language_quotas.iter().any(|(language, quota)| {
            *quota == 0 || !SUPPORTED_LANGUAGES.contains(&language.as_str())
        })
    {
        return Err(
            "source sampling policy requires positive supported-language quotas".to_string(),
        );
    }
    if policy.language_quotas.values().sum::<usize>() > policy.assessment_prefix {
        return Err("source sampling quotas exceed the assessment prefix".to_string());
    }
    Ok(())
}

fn ranked_candidates(
    frame: &[u8],
    seed: &str,
    prefix: usize,
) -> Result<Vec<RankedSourceCandidate>, String> {
    let text = std::str::from_utf8(frame)
        .map_err(|_| "source sampling frame must be UTF-8 CSV".to_string())?;
    let mut lines = text.lines();
    if lines.next().map(str::trim_end) != Some("repo,metadata") {
        return Err("source sampling frame must use the OpenSSF repo,metadata header".to_string());
    }
    let mut seen = HashSet::new();
    let mut ranked = Vec::new();
    for (index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let repository = line
            .split_once(',')
            .map(|(repository, _)| repository)
            .ok_or_else(|| format!("source sampling frame line {} is malformed", index + 2))?;
        let repository = normalize_repository(repository)?;
        if !seen.insert(repository.clone()) {
            return Err(format!(
                "source sampling frame repeats repository {repository}"
            ));
        }
        ranked.push(RankedSourceCandidate {
            rank: 0,
            rank_sha256: sha256(format!("{SOURCE_RANK_CONTRACT}\n{seed}\n{repository}").as_bytes()),
            repository,
        });
    }
    if ranked.len() < prefix {
        return Err(format!(
            "source sampling frame has {} repositories but policy requires {prefix}",
            ranked.len()
        ));
    }
    ranked.sort_by(|left, right| {
        (&left.rank_sha256, &left.repository).cmp(&(&right.rank_sha256, &right.repository))
    });
    ranked.truncate(prefix);
    for (index, candidate) in ranked.iter_mut().enumerate() {
        candidate.rank = index + 1;
    }
    Ok(ranked)
}

fn validate_worksheet_header(
    worksheet: &SourceSelectionWorksheet,
    expected: &SourceSelectionWorksheet,
) -> Result<(), String> {
    if worksheet.schema_version != SOURCE_SELECTION_AUDIT_SCHEMA_VERSION
        || worksheet.rank_contract != SOURCE_RANK_CONTRACT
        || worksheet.policy != expected.policy
        || worksheet.policy_sha256 != expected.policy_sha256
        || worksheet.frame_sha256 != expected.frame_sha256
        || worksheet.task_sha256 != expected.task_sha256
    {
        return Err("source selection worksheet changed its immutable task".to_string());
    }
    Ok(())
}

fn selection_task_sha256(
    policy_sha256: &str,
    frame_sha256: &str,
    candidates: &[SourceCandidateAssessment],
) -> Result<String, String> {
    let immutable = candidates
        .iter()
        .map(|assessment| &assessment.candidate)
        .collect::<Vec<_>>();
    json_sha256(&(SOURCE_RANK_CONTRACT, policy_sha256, frame_sha256, immutable))
}

fn normalize_repository(value: &str) -> Result<String, String> {
    let normalized = value.trim();
    let normalized = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .unwrap_or(normalized)
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_ascii_lowercase();
    let parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0] != "github.com"
        || parts[1].is_empty()
        || parts[2].is_empty()
        || parts[1..]
            .iter()
            .any(|part| !part.bytes().all(valid_repository_byte))
    {
        return Err(format!(
            "invalid GitHub source repository identity: {value}"
        ));
    }
    Ok(normalized)
}

fn valid_repository_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn safe_relative(value: &str) -> Result<(), String> {
    let path = std::path::Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        Err(format!(
            "source selection path must be safe and relative: {value}"
        ))
    } else {
        Ok(())
    }
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_revision(value: &str) -> Result<(), String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err("source selection revision must be a complete 40-character Git SHA".to_string())
    } else {
        Ok(())
    }
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!("{label} must be a 64-character SHA-256 digest"))
    } else {
        Ok(())
    }
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize source selection commitment: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) fn test_selection_artifacts(
    repositories: Vec<SourceRepositoryDraft>,
) -> (super::SourceSelectionDraft, Vec<u8>, Vec<u8>) {
    assert!(!repositories.is_empty());
    let mut frame = String::from("repo,metadata\n");
    for repository in &repositories {
        frame.push_str(&normalize_repository(&repository.repository).unwrap());
        frame.push_str(",fixture\n");
    }
    let frame = frame.into_bytes();
    let mut language_quotas = BTreeMap::new();
    for repository in &repositories {
        *language_quotas
            .entry(repository.selection_language.clone())
            .or_insert(0) += 1;
    }
    let policy = SourceSamplingPolicy {
        schema_version: SOURCE_SELECTION_AUDIT_SCHEMA_VERSION,
        selection_id: "test-selection".to_string(),
        selected_at: "2026-08-12T00:00:00Z".to_string(),
        frame_source: "https://github.com/ossf/scorecard/test-frame.csv".to_string(),
        frame_revision: "1".repeat(40),
        frame_blob_sha: "2".repeat(40),
        frame_sha256: sha256(&frame),
        seed: "deterministic-test-selection-seed".to_string(),
        assessment_prefix: repositories.len(),
        minimum_methods: 1,
        maximum_methods: repositories
            .iter()
            .map(|repository| repository.observed_method_count)
            .max()
            .unwrap(),
        language_quotas,
        attestation: "Fixture sources were selected before fixture labels.".to_string(),
    };
    let mut worksheet = prepare_source_selection(policy.clone(), &frame).unwrap();
    for assessment in &mut worksheet.candidates {
        let repository = repositories
            .iter()
            .find(|repository| {
                normalize_repository(&repository.repository).unwrap()
                    == assessment.candidate.repository
            })
            .unwrap();
        assessment.selection_quota_language = repository.selection_language.clone();
        assessment.observed_method_count = Some(repository.observed_method_count);
        let facts = SourceAssessmentFacts {
            repository: assessment.candidate.repository.clone(),
            selection_quota_language: repository.selection_language.clone(),
            observed_method_count: Some(repository.observed_method_count),
            accessible: true,
            archived: Some(false),
            fork: Some(false),
            license_path: Some(repository.license_path.clone()),
            supported_project_shape: Some(true),
        };
        let payload = serde_json::to_string(&facts).unwrap();
        assessment.facts = Some(facts);
        let raw_payload = format!(
            "synthetic metadata for {} at {}",
            repository.repository, repository.revision
        );
        assessment.evidence = vec![
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::StructuredFacts,
                source: "derived:source-assessment-facts-v1".to_string(),
                observed_at: "2026-08-12T00:00:00Z".to_string(),
                payload_sha256: sha256(payload.as_bytes()),
                payload,
            },
            SourceAssessmentEvidence {
                kind: SourceAssessmentEvidenceKind::RawSource,
                source: "https://example.test/source-selection-metadata".to_string(),
                observed_at: "2026-08-12T00:00:00Z".to_string(),
                payload_sha256: sha256(raw_payload.as_bytes()),
                payload: raw_payload,
            },
        ];
        assessment.disposition = Some(SourceSelectionDisposition::Selected);
        assessment.selected_repository = Some(repository.clone());
    }
    let audit = audit_source_selection(policy, &frame, worksheet).unwrap();
    let mut audit_bytes = serde_json::to_vec_pretty(&audit).unwrap();
    audit_bytes.push(b'\n');
    let draft = source_selection_draft(&audit, &frame).unwrap();
    (draft, audit_bytes, frame)
}

#[cfg(test)]
#[path = "benchmark_source_selection_tests.rs"]
mod tests;
