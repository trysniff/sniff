use super::{BenchmarkSourceSeal, SealedMethod, validate_source_seal};
use crate::product_contract::SlopPattern;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const LABEL_REVIEW_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelReviewer {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub sniff_output_hidden: bool,
    pub repository_context_inspected: bool,
    #[serde(default)]
    pub maintainer: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelContextSource {
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub sha256: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodLabelDecision {
    pub tier: Option<FindingTier>,
    pub pattern: String,
    pub intentional_boundary: Option<bool>,
    pub rationale: String,
    pub simplification: String,
    pub behavioral_evidence: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub related_method_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodLabelReview {
    pub method_id: String,
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub language: String,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub source: String,
    pub decision: MethodLabelDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelReviewWorksheet {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub selection_id: String,
    pub task_commitment_sha256: String,
    pub reviewer: Option<LabelReviewer>,
    pub context_sources: Vec<LabelContextSource>,
    pub methods: Vec<MethodLabelReview>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelAgreementStatus {
    Agreement,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerLabel {
    pub reviewer_id: String,
    pub decision: MethodLabelDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodLabelAudit {
    pub method_id: String,
    pub status: LabelAgreementStatus,
    pub labels: Vec<ReviewerLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelReviewAudit {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub worksheet_sha256s: Vec<String>,
    pub reviewers: Vec<LabelReviewer>,
    pub methods: Vec<MethodLabelAudit>,
    pub agreement_count: usize,
    pub disputed_count: usize,
    pub audit_sha256: String,
}

impl LabelReviewAudit {
    pub fn computed_audit_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            source_seal_artifact_sha256: &'a str,
            source_seal_commitment_sha256: &'a str,
            worksheet_sha256s: &'a [String],
            reviewers: &'a [LabelReviewer],
            methods: &'a [MethodLabelAudit],
            agreement_count: usize,
            disputed_count: usize,
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            source_seal_artifact_sha256: &self.source_seal_artifact_sha256,
            source_seal_commitment_sha256: &self.source_seal_commitment_sha256,
            worksheet_sha256s: &self.worksheet_sha256s,
            reviewers: &self.reviewers,
            methods: &self.methods,
            agreement_count: self.agreement_count,
            disputed_count: self.disputed_count,
        })
    }
}

pub fn prepare_label_review(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
) -> Result<LabelReviewWorksheet, String> {
    require_sha256("source seal artifact SHA-256", source_seal_artifact_sha256)?;
    validate_source_seal(seal, seal_root)?;
    let source_by_method = method_sources(seal, seal_root)?;
    let context_sources = label_context_sources(seal, seal_root)?;
    let mut methods = seal
        .methods
        .iter()
        .map(|method| label_task(method, &source_by_method))
        .collect::<Result<Vec<_>, _>>()?;
    methods.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    let task_commitment_sha256 = task_commitment(
        source_seal_artifact_sha256,
        &seal.seal_sha256,
        &seal.selection_id,
        &context_sources,
        &methods,
    )?;
    Ok(LabelReviewWorksheet {
        schema_version: LABEL_REVIEW_SCHEMA_VERSION,
        source_seal_artifact_sha256: source_seal_artifact_sha256.to_string(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        selection_id: seal.selection_id.clone(),
        task_commitment_sha256,
        reviewer: None,
        context_sources,
        methods,
    })
}

pub fn audit_label_reviews(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
    source_seal_artifact_sha256: &str,
    worksheets: &[LabelReviewWorksheet],
) -> Result<LabelReviewAudit, String> {
    if worksheets.len() < 2 {
        return Err(
            "label audit requires at least two independent completed worksheets".to_string(),
        );
    }
    let expected = prepare_label_review(seal, seal_root, source_seal_artifact_sha256)?;
    let known_ids = seal
        .methods
        .iter()
        .map(|method| method.method_id.as_str())
        .collect::<HashSet<_>>();
    let mut reviewers = Vec::new();
    let mut reviewer_ids = HashSet::new();
    let mut worksheet_sha256s = Vec::new();
    for worksheet in worksheets {
        validate_completed_worksheet(worksheet, &expected, &known_ids)?;
        let reviewer = worksheet.reviewer.as_ref().expect("validated reviewer");
        if !reviewer_ids.insert(reviewer.reviewer_id.as_str()) {
            return Err(format!(
                "label audit repeats reviewer {}",
                reviewer.reviewer_id
            ));
        }
        reviewers.push(reviewer.clone());
        worksheet_sha256s.push(json_sha256(worksheet)?);
    }
    reviewers.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
    worksheet_sha256s.sort();

    let mut methods = Vec::with_capacity(expected.methods.len());
    for expected_method in &expected.methods {
        let mut labels = worksheets
            .iter()
            .map(|worksheet| ReviewerLabel {
                reviewer_id: worksheet
                    .reviewer
                    .as_ref()
                    .expect("validated reviewer")
                    .reviewer_id
                    .clone(),
                decision: worksheet
                    .methods
                    .iter()
                    .find(|method| method.method_id == expected_method.method_id)
                    .expect("validated method census")
                    .decision
                    .clone(),
            })
            .collect::<Vec<_>>();
        labels.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
        let first = decision_signature(&labels[0].decision);
        let status = if labels
            .iter()
            .skip(1)
            .all(|label| decision_signature(&label.decision) == first)
        {
            LabelAgreementStatus::Agreement
        } else {
            LabelAgreementStatus::Disputed
        };
        methods.push(MethodLabelAudit {
            method_id: expected_method.method_id.clone(),
            status,
            labels,
        });
    }
    let agreement_count = methods
        .iter()
        .filter(|method| method.status == LabelAgreementStatus::Agreement)
        .count();
    let disputed_count = methods.len() - agreement_count;
    let mut audit = LabelReviewAudit {
        schema_version: LABEL_REVIEW_SCHEMA_VERSION,
        source_seal_artifact_sha256: source_seal_artifact_sha256.to_string(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        worksheet_sha256s,
        reviewers,
        methods,
        agreement_count,
        disputed_count,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit.computed_audit_sha256()?;
    Ok(audit)
}

pub fn validate_label_review_audit(
    seal: &BenchmarkSourceSeal,
    source_seal_artifact_sha256: &str,
    audit: &LabelReviewAudit,
) -> Result<(), String> {
    if audit.schema_version != LABEL_REVIEW_SCHEMA_VERSION
        || audit.source_seal_artifact_sha256 != source_seal_artifact_sha256
        || audit.source_seal_commitment_sha256 != seal.seal_sha256
    {
        return Err("label audit does not match the source seal".to_string());
    }
    if audit.reviewers.len() < 2 || audit.worksheet_sha256s.len() != audit.reviewers.len() {
        return Err("label audit requires one worksheet per independent reviewer".to_string());
    }
    let mut reviewer_ids = HashSet::new();
    for reviewer in &audit.reviewers {
        require_text("audit reviewer_id", &reviewer.reviewer_id)?;
        require_text("audit reviewer affiliation", &reviewer.affiliation)?;
        require_text("audit reviewer attestation", &reviewer.attestation)?;
        if reviewer.years_experience == 0
            || !reviewer.independent_from_sniff
            || !reviewer.sniff_output_hidden
            || !reviewer.repository_context_inspected
        {
            return Err("label audit contains an ineligible reviewer".to_string());
        }
        if !reviewer_ids.insert(reviewer.reviewer_id.as_str()) {
            return Err(format!(
                "label audit repeats reviewer {}",
                reviewer.reviewer_id
            ));
        }
    }
    let mut worksheet_hashes = HashSet::new();
    for hash in &audit.worksheet_sha256s {
        require_sha256("worksheet SHA-256", hash)?;
        if !worksheet_hashes.insert(hash.as_str()) {
            return Err(format!("label audit repeats worksheet {hash}"));
        }
    }
    let sealed_ids = seal
        .methods
        .iter()
        .map(|method| method.method_id.as_str())
        .collect::<HashSet<_>>();
    let mut audited_ids = HashSet::new();
    let mut agreement_count = 0;
    let mut disputed_count = 0;
    for method in &audit.methods {
        if !sealed_ids.contains(method.method_id.as_str()) {
            return Err(format!(
                "label audit references unknown method {}",
                method.method_id
            ));
        }
        if !audited_ids.insert(method.method_id.as_str()) {
            return Err(format!("label audit repeats method {}", method.method_id));
        }
        if method.labels.len() != audit.reviewers.len() {
            return Err(format!(
                "label audit method {} does not contain every reviewer",
                method.method_id
            ));
        }
        let mut labels_by_reviewer = HashSet::new();
        for label in &method.labels {
            if !reviewer_ids.contains(label.reviewer_id.as_str())
                || !labels_by_reviewer.insert(label.reviewer_id.as_str())
            {
                return Err(format!(
                    "label audit method {} has an invalid reviewer ledger",
                    method.method_id
                ));
            }
            validate_decision(&method.method_id, &label.decision, &sealed_ids)?;
        }
        let first = decision_signature(&method.labels[0].decision);
        let expected_status = if method
            .labels
            .iter()
            .skip(1)
            .all(|label| decision_signature(&label.decision) == first)
        {
            LabelAgreementStatus::Agreement
        } else {
            LabelAgreementStatus::Disputed
        };
        if method.status != expected_status {
            return Err(format!(
                "label audit method {} has an incorrect agreement status",
                method.method_id
            ));
        }
        match method.status {
            LabelAgreementStatus::Agreement => agreement_count += 1,
            LabelAgreementStatus::Disputed => disputed_count += 1,
        }
    }
    if audited_ids != sealed_ids {
        return Err("label audit omits sealed methods".to_string());
    }
    validate_audit_relationships(seal, audit)?;
    if agreement_count != audit.agreement_count || disputed_count != audit.disputed_count {
        return Err("label audit summary counts do not match its method ledger".to_string());
    }
    let expected_hash = audit.computed_audit_sha256()?;
    if !audit.audit_sha256.eq_ignore_ascii_case(&expected_hash) {
        return Err(format!(
            "label audit commitment mismatch; expected {expected_hash}"
        ));
    }
    Ok(())
}

fn validate_audit_relationships(
    seal: &BenchmarkSourceSeal,
    audit: &LabelReviewAudit,
) -> Result<(), String> {
    let methods = seal
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    for reviewer in &audit.reviewers {
        let decisions = audit
            .methods
            .iter()
            .map(|method| {
                let decision = method
                    .labels
                    .iter()
                    .find(|label| label.reviewer_id == reviewer.reviewer_id)
                    .expect("reviewer completeness was validated");
                (method.method_id.as_str(), &decision.decision)
            })
            .collect::<HashMap<_, _>>();
        for (method_id, decision) in &decisions {
            let method = methods
                .get(method_id)
                .expect("method coverage was validated");
            for related_id in &decision.related_method_ids {
                let related_decision = decisions
                    .get(related_id.as_str())
                    .expect("related method identity was validated");
                if !related_decision
                    .related_method_ids
                    .iter()
                    .any(|candidate| candidate == method_id)
                {
                    return Err(format!(
                        "label audit reviewer {} has a non-reciprocal relationship from {method_id} to {related_id}",
                        reviewer.reviewer_id
                    ));
                }
                let related = methods
                    .get(related_id.as_str())
                    .expect("related method identity was validated");
                if method.language != related.language
                    || method.repository != related.repository
                    || method.revision != related.revision
                    || decision.tier != related_decision.tier
                    || decision.pattern != related_decision.pattern
                    || decision.intentional_boundary != related_decision.intentional_boundary
                {
                    return Err(format!(
                        "label audit reviewer {} has an incompatible relationship from {method_id} to {related_id}",
                        reviewer.reviewer_id
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_completed_worksheet(
    worksheet: &LabelReviewWorksheet,
    expected: &LabelReviewWorksheet,
    known_ids: &HashSet<&str>,
) -> Result<(), String> {
    if worksheet.schema_version != LABEL_REVIEW_SCHEMA_VERSION
        || worksheet.source_seal_artifact_sha256 != expected.source_seal_artifact_sha256
        || worksheet.source_seal_commitment_sha256 != expected.source_seal_commitment_sha256
        || worksheet.selection_id != expected.selection_id
        || worksheet.task_commitment_sha256 != expected.task_commitment_sha256
    {
        return Err("label worksheet does not match the immutable source-seal task".to_string());
    }
    if worksheet.context_sources != expected.context_sources {
        return Err("label worksheet changed immutable review context".to_string());
    }
    if worksheet.methods.len() != expected.methods.len() {
        return Err(
            "label worksheet does not contain the complete sealed method census".to_string(),
        );
    }
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .ok_or_else(|| "label worksheet is missing reviewer identity".to_string())?;
    require_text("reviewer_id", &reviewer.reviewer_id)?;
    require_text("reviewer affiliation", &reviewer.affiliation)?;
    require_text("reviewer attestation", &reviewer.attestation)?;
    if reviewer.years_experience == 0 {
        return Err("label reviewer must record non-zero experience".to_string());
    }
    if !reviewer.independent_from_sniff
        || !reviewer.sniff_output_hidden
        || !reviewer.repository_context_inspected
    {
        return Err(
            "label reviewer must be independent, blind to Sniff output, and attest repository-context inspection"
                .to_string(),
        );
    }
    let expected_by_id = expected
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let mut seen = HashSet::new();
    let methods_by_id = worksheet
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    for method in &worksheet.methods {
        let Some(expected_method) = expected_by_id.get(method.method_id.as_str()) else {
            return Err(format!(
                "label worksheet invents method {}",
                method.method_id
            ));
        };
        if !seen.insert(method.method_id.as_str()) {
            return Err(format!(
                "label worksheet repeats method {}",
                method.method_id
            ));
        }
        if immutable_method(method) != immutable_method(expected_method) {
            return Err(format!(
                "label worksheet changed immutable source facts for method {}",
                method.method_id
            ));
        }
        validate_decision(&method.method_id, &method.decision, known_ids)?;
    }
    validate_relationships(&methods_by_id)?;
    Ok(())
}

fn validate_relationships(methods: &HashMap<&str, &MethodLabelReview>) -> Result<(), String> {
    for method in methods.values() {
        for related_id in &method.decision.related_method_ids {
            let related = methods
                .get(related_id.as_str())
                .expect("related method identity was validated");
            if !related
                .decision
                .related_method_ids
                .iter()
                .any(|candidate| candidate == &method.method_id)
            {
                return Err(format!(
                    "method {} relates to {related_id} without a reciprocal relationship",
                    method.method_id
                ));
            }
            if !method.language.eq_ignore_ascii_case(&related.language) {
                return Err(format!(
                    "related methods {} and {related_id} use different languages",
                    method.method_id
                ));
            }
            if method.repository != related.repository || method.revision != related.revision {
                return Err(format!(
                    "related methods {} and {related_id} must belong to one repository revision",
                    method.method_id
                ));
            }
            if method.decision.tier != related.decision.tier
                || method.decision.pattern != related.decision.pattern
                || method.decision.intentional_boundary != related.decision.intentional_boundary
            {
                return Err(format!(
                    "related methods {} and {related_id} must share one tier and mechanism",
                    method.method_id
                ));
            }
        }
    }
    Ok(())
}

fn validate_decision(
    method_id: &str,
    decision: &MethodLabelDecision,
    known_ids: &HashSet<&str>,
) -> Result<(), String> {
    let tier = decision
        .tier
        .ok_or_else(|| format!("method {method_id} has not been labeled"))?;
    let pattern = SlopPattern::parse(&decision.pattern)
        .ok_or_else(|| format!("method {method_id} has an unknown slop pattern"))?;
    if !pattern.is_valid_for(tier) {
        return Err(format!(
            "method {method_id} has a tier-incompatible pattern"
        ));
    }
    let intentional_boundary = decision.intentional_boundary.ok_or_else(|| {
        format!("method {method_id} has not classified its intentional-boundary status")
    })?;
    if intentional_boundary && tier != FindingTier::Clean {
        return Err(format!(
            "method {method_id} can classify an intentional boundary only when Clean"
        ));
    }
    require_text("method label rationale", &decision.rationale)?;
    require_text_items("related method IDs", &decision.related_method_ids)?;
    let mut related = HashSet::new();
    for related_id in &decision.related_method_ids {
        if related_id == method_id {
            return Err(format!("method {method_id} lists itself as related"));
        }
        if !known_ids.contains(related_id.as_str()) {
            return Err(format!(
                "method {method_id} references unknown related method {related_id}"
            ));
        }
        if !related.insert(related_id.as_str()) {
            return Err(format!(
                "method {method_id} repeats related method {related_id}"
            ));
        }
    }
    match tier {
        FindingTier::Slop | FindingTier::KindaSlop => {
            require_text("finding simplification", &decision.simplification)?;
            require_nonempty_items("finding behavioral evidence", &decision.behavioral_evidence)?;
            if !decision.missing_evidence.is_empty() {
                return Err(format!(
                    "finding method {method_id} cannot retain unresolved missing evidence"
                ));
            }
        }
        FindingTier::Unresolved => {
            require_nonempty_items("unresolved missing evidence", &decision.missing_evidence)?;
            if !decision.simplification.trim().is_empty() {
                return Err(format!(
                    "unresolved method {method_id} must not claim a proven simplification"
                ));
            }
            if !decision.related_method_ids.is_empty() {
                return Err(format!(
                    "unresolved method {method_id} must not claim a proven relationship case"
                ));
            }
        }
        FindingTier::Clean => {
            if !decision.simplification.trim().is_empty()
                || !decision.behavioral_evidence.is_empty()
                || !decision.missing_evidence.is_empty()
            {
                return Err(format!(
                    "clean method {method_id} must not carry finding or unresolved fields"
                ));
            }
            if !decision.related_method_ids.is_empty() {
                return Err(format!(
                    "clean method {method_id} must not claim a slop relationship"
                ));
            }
        }
    }
    Ok(())
}

fn label_task(
    method: &SealedMethod,
    source_by_method: &HashMap<String, String>,
) -> Result<MethodLabelReview, String> {
    let source = source_by_method
        .get(&method.method_id)
        .ok_or_else(|| format!("sealed method {} has no parsed source", method.method_id))?;
    Ok(MethodLabelReview {
        method_id: method.method_id.clone(),
        repository: method.repository.clone(),
        revision: method.revision.clone(),
        repository_path: method.repository_path.clone(),
        artifact_path: method.artifact_path.clone(),
        language: method.language.clone(),
        name: method.name.clone(),
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: method.source_sha256.clone(),
        source: source.clone(),
        decision: MethodLabelDecision {
            tier: None,
            pattern: String::new(),
            intentional_boundary: None,
            rationale: String::new(),
            simplification: String::new(),
            behavioral_evidence: Vec::new(),
            missing_evidence: Vec::new(),
            related_method_ids: Vec::new(),
        },
    })
}

fn method_sources(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
) -> Result<HashMap<String, String>, String> {
    let mut result = HashMap::new();
    let methods_by_artifact = seal.methods.iter().fold(
        HashMap::<&str, Vec<&SealedMethod>>::new(),
        |mut grouped, method| {
            grouped
                .entry(method.artifact_path.as_str())
                .or_default()
                .push(method);
            grouped
        },
    );
    for source in &seal.sources {
        let artifact = seal_root.join(&source.artifact_path);
        let record = crate::parser::parse_file_checked(&artifact.to_string_lossy())?;
        let parsed = record
            .methods
            .into_iter()
            .map(|method| {
                (
                    (
                        method.name,
                        method.start_line,
                        method.end_line,
                        sha256(method.source.as_bytes()),
                    ),
                    method.source,
                )
            })
            .collect::<HashMap<_, _>>();
        for method in methods_by_artifact
            .get(source.artifact_path.as_str())
            .into_iter()
            .flatten()
        {
            let key = (
                method.name.clone(),
                method.start_line,
                method.end_line,
                method.source_sha256.clone(),
            );
            let method_source = parsed.get(&key).ok_or_else(|| {
                format!(
                    "sealed method {} no longer matches its source",
                    method.method_id
                )
            })?;
            result.insert(method.method_id.clone(), method_source.clone());
        }
    }
    Ok(result)
}

fn label_context_sources(
    seal: &BenchmarkSourceSeal,
    seal_root: &Path,
) -> Result<Vec<LabelContextSource>, String> {
    let mut context = seal
        .sources
        .iter()
        .chain(&seal.context_sources)
        .map(|source| {
            let bytes = std::fs::read(seal_root.join(&source.artifact_path)).map_err(|error| {
                format!(
                    "failed to read sealed label context {}: {error}",
                    source.artifact_path
                )
            })?;
            let text = String::from_utf8(bytes).map_err(|_| {
                format!(
                    "sealed label context is not UTF-8: {}",
                    source.artifact_path
                )
            })?;
            Ok(LabelContextSource {
                repository: source.repository.clone(),
                revision: source.revision.clone(),
                repository_path: source.repository_path.clone(),
                artifact_path: source.artifact_path.clone(),
                sha256: source.sha256.clone(),
                source: text,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    context.sort_by(|left, right| {
        (&left.repository, &left.revision, &left.repository_path).cmp(&(
            &right.repository,
            &right.revision,
            &right.repository_path,
        ))
    });
    Ok(context)
}

fn task_commitment(
    source_seal_artifact_sha256: &str,
    source_seal_commitment_sha256: &str,
    selection_id: &str,
    context_sources: &[LabelContextSource],
    methods: &[MethodLabelReview],
) -> Result<String, String> {
    let immutable = methods.iter().map(immutable_method).collect::<Vec<_>>();
    json_sha256(&(
        LABEL_REVIEW_SCHEMA_VERSION,
        source_seal_artifact_sha256,
        source_seal_commitment_sha256,
        selection_id,
        context_sources,
        immutable,
    ))
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ImmutableMethod<'a> {
    method_id: &'a str,
    repository: &'a str,
    revision: &'a str,
    repository_path: &'a str,
    artifact_path: &'a str,
    language: &'a str,
    name: &'a str,
    start_line: usize,
    end_line: usize,
    source_sha256: &'a str,
    source: &'a str,
}

fn immutable_method(method: &MethodLabelReview) -> ImmutableMethod<'_> {
    ImmutableMethod {
        method_id: &method.method_id,
        repository: &method.repository,
        revision: &method.revision,
        repository_path: &method.repository_path,
        artifact_path: &method.artifact_path,
        language: &method.language,
        name: &method.name,
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: &method.source_sha256,
        source: &method.source,
    }
}

fn decision_signature(
    decision: &MethodLabelDecision,
) -> (Option<FindingTier>, &str, Option<bool>, Vec<&str>) {
    let mut related = decision
        .related_method_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    related.sort_unstable();
    (
        decision.tier,
        decision.pattern.as_str(),
        decision.intentional_boundary,
        related,
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
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!("{label} must be a 64-character SHA-256 digest"))
    } else {
        Ok(())
    }
}

fn require_text_items(label: &str, values: &[String]) -> Result<(), String> {
    if values.iter().any(|value| value.trim().is_empty()) {
        Err(format!("{label} cannot contain empty values"))
    } else {
        Ok(())
    }
}

fn require_nonempty_items(label: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    require_text_items(label, values)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize label-review commitment: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_label_review_tests.rs"]
mod tests;
