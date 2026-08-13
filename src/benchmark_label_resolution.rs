use super::{
    BenchmarkAdjudication, BenchmarkCase, BenchmarkPartition, BenchmarkSourceSeal,
    LabelAgreementStatus, LabelReviewAudit, ReleaseBenchmarkCase, SourceSnapshot,
    validate_label_review_audit,
};
use crate::product_contract::SlopPattern;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path};

pub const LABEL_RESOLUTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelResolver {
    pub resolver_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    #[serde(default)]
    pub maintainer: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedLabelCase {
    pub case_id: String,
    pub method_ids: Vec<String>,
    pub tier: Option<FindingTier>,
    pub pattern: String,
    pub intentional_boundary: Option<bool>,
    pub human_explanation: String,
    pub behavioral_evidence: Vec<String>,
    pub expected_proof_level: u8,
    pub after: Vec<SourceSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_resolution: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelResolutionManifest {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub label_audit_sha256: String,
    pub resolver: LabelResolver,
    pub cases: Vec<ResolvedLabelCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindCaseBundle {
    pub schema_version: u32,
    pub source_seal_artifact_sha256: String,
    pub source_seal_commitment_sha256: String,
    pub label_audit_sha256: String,
    pub resolver: LabelResolver,
    pub cases: Vec<ReleaseBenchmarkCase>,
    pub bundle_sha256: String,
}

impl BlindCaseBundle {
    pub fn computed_bundle_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            source_seal_artifact_sha256: &'a str,
            source_seal_commitment_sha256: &'a str,
            label_audit_sha256: &'a str,
            resolver: &'a LabelResolver,
            cases: &'a [ReleaseBenchmarkCase],
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            source_seal_artifact_sha256: &self.source_seal_artifact_sha256,
            source_seal_commitment_sha256: &self.source_seal_commitment_sha256,
            label_audit_sha256: &self.label_audit_sha256,
            resolver: &self.resolver,
            cases: &self.cases,
        })
    }
}

pub fn build_blind_case_bundle(
    seal: &BenchmarkSourceSeal,
    source_seal_artifact_sha256: &str,
    audit: &LabelReviewAudit,
    resolution: &LabelResolutionManifest,
    artifact_root: &Path,
) -> Result<BlindCaseBundle, String> {
    validate_label_review_audit(seal, source_seal_artifact_sha256, audit)?;
    validate_resolution_header(seal, audit, resolution)?;
    let sealed_methods = seal
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let audit_methods = audit
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let source_by_artifact = seal
        .sources
        .iter()
        .map(|source| (source.artifact_path.as_str(), source))
        .collect::<HashMap<_, _>>();
    let agreed_components = agreed_relationship_components(audit)?;
    let mut covered = HashSet::new();
    let mut case_ids = HashSet::new();
    let mut cases = Vec::with_capacity(resolution.cases.len());
    for resolved in &resolution.cases {
        require_text("resolved case_id", &resolved.case_id)?;
        if !case_ids.insert(resolved.case_id.as_str()) {
            return Err(format!(
                "label resolution repeats case {}",
                resolved.case_id
            ));
        }
        let method_ids = unique_sorted_ids(&resolved.case_id, &resolved.method_ids)?;
        let methods = method_ids
            .iter()
            .map(|method_id| {
                if !covered.insert(method_id.clone()) {
                    return Err(format!(
                        "label resolution assigns method {method_id} more than once"
                    ));
                }
                sealed_methods
                    .get(method_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        format!("label resolution references unknown method {method_id}")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let audited = method_ids
            .iter()
            .map(|method_id| audit_methods[method_id.as_str()])
            .collect::<Vec<_>>();
        validate_resolved_case(
            resolved,
            &method_ids,
            &methods,
            &audited,
            &agreed_components,
            audit,
            artifact_root,
        )?;
        cases.push(to_release_case(
            resolved,
            &method_ids,
            &methods,
            &audited,
            audit,
            &source_by_artifact,
        )?);
    }
    let sealed_ids = sealed_methods
        .keys()
        .map(|method_id| (*method_id).to_string())
        .collect::<HashSet<_>>();
    if covered != sealed_ids {
        return Err("label resolution omits sealed methods".to_string());
    }
    cases.sort_by(|left, right| left.label.case_id.cmp(&right.label.case_id));
    let mut bundle = BlindCaseBundle {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: source_seal_artifact_sha256.to_string(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolution.resolver.clone(),
        cases,
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = bundle.computed_bundle_sha256()?;
    Ok(bundle)
}

pub fn prepare_label_resolution(
    seal: &BenchmarkSourceSeal,
    source_seal_artifact_sha256: &str,
    audit: &LabelReviewAudit,
) -> Result<LabelResolutionManifest, String> {
    validate_label_review_audit(seal, source_seal_artifact_sha256, audit)?;
    let components = agreed_relationship_components(audit)?;
    let audit_by_id = audit
        .methods
        .iter()
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let mut assigned = HashSet::new();
    let mut cases = Vec::new();
    for method in &seal.methods {
        if !assigned.insert(method.method_id.clone()) {
            continue;
        }
        let audited = audit_by_id[method.method_id.as_str()];
        let method_ids = if audited.status == LabelAgreementStatus::Agreement {
            let mut ids = components[method.method_id.as_str()]
                .iter()
                .map(|id| (*id).to_string())
                .collect::<Vec<_>>();
            ids.sort();
            for id in &ids {
                assigned.insert(id.clone());
            }
            ids
        } else {
            vec![method.method_id.clone()]
        };
        let agreed = (audited.status == LabelAgreementStatus::Agreement)
            .then(|| &audited.labels[0].decision);
        let tier = agreed.and_then(|decision| decision.tier);
        let pattern = agreed.map_or_else(String::new, |decision| decision.pattern.clone());
        let intentional_boundary = agreed.and_then(|decision| decision.intentional_boundary);
        let human_explanation = agreed.map_or_else(String::new, |decision| {
            decision.rationale.trim().to_string()
        });
        cases.push(ResolvedLabelCase {
            case_id: format!("blind-{}", &method_ids[0][..16]),
            method_ids,
            tier,
            pattern,
            intentional_boundary,
            human_explanation,
            behavioral_evidence: Vec::new(),
            expected_proof_level: 0,
            after: Vec::new(),
            dispute_resolution: None,
        });
    }
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    Ok(LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: source_seal_artifact_sha256.to_string(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: LabelResolver {
            resolver_id: String::new(),
            years_experience: 0,
            affiliation: String::new(),
            maintainer: false,
            attestation: String::new(),
        },
        cases,
    })
}

fn validate_resolution_header(
    seal: &BenchmarkSourceSeal,
    audit: &LabelReviewAudit,
    resolution: &LabelResolutionManifest,
) -> Result<(), String> {
    if resolution.schema_version != LABEL_RESOLUTION_SCHEMA_VERSION
        || resolution.source_seal_artifact_sha256 != audit.source_seal_artifact_sha256
        || resolution.source_seal_commitment_sha256 != seal.seal_sha256
        || resolution.label_audit_sha256 != audit.audit_sha256
    {
        return Err("label resolution does not match the source seal and audit".to_string());
    }
    require_text("resolver_id", &resolution.resolver.resolver_id)?;
    require_text("resolver affiliation", &resolution.resolver.affiliation)?;
    require_text("resolver attestation", &resolution.resolver.attestation)?;
    if resolution.resolver.years_experience == 0 {
        return Err("label resolver must record non-zero experience".to_string());
    }
    if audit.disputed_count > 0
        && audit
            .reviewers
            .iter()
            .any(|reviewer| reviewer.reviewer_id == resolution.resolver.resolver_id)
    {
        return Err(
            "disputed labels require a resolver distinct from the original reviewers".to_string(),
        );
    }
    if resolution.cases.is_empty() {
        return Err("label resolution requires cases".to_string());
    }
    Ok(())
}

fn validate_resolved_case(
    resolved: &ResolvedLabelCase,
    method_ids: &[String],
    methods: &[&super::SealedMethod],
    audited: &[&super::MethodLabelAudit],
    agreed_components: &HashMap<&str, HashSet<&str>>,
    audit: &LabelReviewAudit,
    artifact_root: &Path,
) -> Result<(), String> {
    let tier = resolved
        .tier
        .ok_or_else(|| format!("resolved case {} has no final tier", resolved.case_id))?;
    let pattern = SlopPattern::parse(&resolved.pattern)
        .ok_or_else(|| format!("resolved case {} has an unknown pattern", resolved.case_id))?;
    if !pattern.is_valid_for(tier) {
        return Err(format!(
            "resolved case {} has a tier-incompatible pattern",
            resolved.case_id
        ));
    }
    let intentional_boundary = resolved.intentional_boundary.ok_or_else(|| {
        format!(
            "resolved case {} has no intentional-boundary decision",
            resolved.case_id
        )
    })?;
    if intentional_boundary && tier != FindingTier::Clean {
        return Err(format!(
            "resolved case {} can classify an intentional boundary only when Clean",
            resolved.case_id
        ));
    }
    require_text("resolved case explanation", &resolved.human_explanation)?;
    let first = methods[0];
    if methods.iter().any(|method| {
        method.repository != first.repository
            || method.revision != first.revision
            || method.language != first.language
    }) {
        return Err(format!(
            "resolved case {} crosses repository revisions or languages",
            resolved.case_id
        ));
    }
    let has_dispute = audited
        .iter()
        .any(|method| method.status == LabelAgreementStatus::Disputed);
    if has_dispute
        != audited
            .iter()
            .all(|method| method.status == LabelAgreementStatus::Disputed)
    {
        return Err(format!(
            "resolved case {} mixes disputed and undisputed methods",
            resolved.case_id
        ));
    }
    if has_dispute {
        require_text(
            "dispute resolution",
            resolved.dispute_resolution.as_deref().unwrap_or_default(),
        )?;
    } else {
        if resolved.dispute_resolution.is_some() {
            return Err(format!(
                "undisputed case {} must not invent a dispute resolution",
                resolved.case_id
            ));
        }
        let agreed = &audited[0].labels[0].decision;
        if agreed.tier != Some(tier)
            || agreed.pattern != resolved.pattern
            || agreed.intentional_boundary != resolved.intentional_boundary
        {
            return Err(format!(
                "resolved case {} changes an undisputed label",
                resolved.case_id
            ));
        }
        let expected = agreed_components[method_ids[0].as_str()].clone();
        let actual = method_ids
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if expected != actual {
            return Err(format!(
                "resolved case {} changes an undisputed relationship component",
                resolved.case_id
            ));
        }
    }
    for reviewer in &audit.reviewers {
        let labels = audited
            .iter()
            .map(|method| {
                &method
                    .labels
                    .iter()
                    .find(|label| label.reviewer_id == reviewer.reviewer_id)
                    .expect("audit reviewer completeness was validated")
                    .decision
            })
            .collect::<Vec<_>>();
        if labels.iter().skip(1).any(|label| {
            label.tier != labels[0].tier
                || label.pattern != labels[0].pattern
                || label.intentional_boundary != labels[0].intentional_boundary
        }) {
            return Err(format!(
                "resolved case {} combines methods that reviewer {} labeled differently",
                resolved.case_id, reviewer.reviewer_id
            ));
        }
    }
    match tier {
        FindingTier::Slop | FindingTier::KindaSlop => {
            if resolved.expected_proof_level == 0 || resolved.expected_proof_level > 5 {
                return Err(format!(
                    "finding case {} requires proof level P1 through P5",
                    resolved.case_id
                ));
            }
            require_nonempty_texts("finding behavioral evidence", &resolved.behavioral_evidence)?;
            if resolved.after.is_empty() {
                return Err(format!(
                    "finding case {} requires after evidence",
                    resolved.case_id
                ));
            }
            validate_snapshots(&resolved.after, artifact_root, "resolved after")?;
        }
        FindingTier::Clean | FindingTier::Unresolved => {
            if method_ids.len() != 1
                || resolved.expected_proof_level != 0
                || !resolved.after.is_empty()
                || !resolved.behavioral_evidence.is_empty()
            {
                return Err(format!(
                    "non-finding case {} must be one method without proof or after artifacts",
                    resolved.case_id
                ));
            }
        }
    }
    Ok(())
}

fn to_release_case(
    resolved: &ResolvedLabelCase,
    method_ids: &[String],
    methods: &[&super::SealedMethod],
    audited: &[&super::MethodLabelAudit],
    audit: &LabelReviewAudit,
    source_by_artifact: &HashMap<&str, &SourceSnapshot>,
) -> Result<ReleaseBenchmarkCase, String> {
    let before = unique_before_snapshots(methods, source_by_artifact)?;
    let adjudications = audit
        .reviewers
        .iter()
        .map(|reviewer| {
            let decisions = audited
                .iter()
                .map(|method| {
                    method
                        .labels
                        .iter()
                        .find(|label| label.reviewer_id == reviewer.reviewer_id)
                        .expect("audit reviewer completeness was validated")
                        .decision
                        .clone()
                })
                .collect::<Vec<_>>();
            let decision = &decisions[0];
            BenchmarkAdjudication {
                reviewer_id: reviewer.reviewer_id.clone(),
                years_experience: reviewer.years_experience,
                tier: decision.tier.expect("completed audit decision"),
                pattern: decision.pattern.clone(),
                rationale: decisions
                    .iter()
                    .map(|decision| decision.rationale.trim())
                    .collect::<Vec<_>>()
                    .join(" | "),
                maintainer: reviewer.maintainer,
            }
        })
        .collect();
    Ok(ReleaseBenchmarkCase {
        label: BenchmarkCase {
            case_id: resolved.case_id.clone(),
            language: methods[0].language.clone(),
            expected_tier: resolved.tier.expect("resolved tier was validated"),
            expected_pattern: resolved.pattern.clone(),
            intentional_boundary: resolved
                .intentional_boundary
                .expect("intentional-boundary decision was validated"),
        },
        partition: BenchmarkPartition::BlindOss,
        before,
        after: resolved.after.clone(),
        human_explanation: resolved.human_explanation.clone(),
        behavioral_evidence: resolved.behavioral_evidence.clone(),
        expected_proof_level: resolved.expected_proof_level,
        covered_method_ids: method_ids.to_vec(),
        adjudications,
        disputed: audited
            .iter()
            .any(|method| method.status == LabelAgreementStatus::Disputed),
        dispute_resolution: resolved.dispute_resolution.clone(),
    })
}

fn agreed_relationship_components(
    audit: &LabelReviewAudit,
) -> Result<HashMap<&str, HashSet<&str>>, String> {
    let agreed = audit
        .methods
        .iter()
        .filter(|method| method.status == LabelAgreementStatus::Agreement)
        .map(|method| (method.method_id.as_str(), method))
        .collect::<HashMap<_, _>>();
    let mut result = HashMap::new();
    for start in agreed.keys().copied() {
        let mut component = HashSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(current) = queue.pop_front() {
            if !component.insert(current) {
                continue;
            }
            for related in &agreed[current].labels[0].decision.related_method_ids {
                if !agreed.contains_key(related.as_str()) {
                    return Err(format!(
                        "undisputed method {current} relates to a disputed method {related}"
                    ));
                }
                queue.push_back(related.as_str());
            }
        }
        result.insert(start, component);
    }
    Ok(result)
}

fn unique_before_snapshots(
    methods: &[&super::SealedMethod],
    source_by_artifact: &HashMap<&str, &SourceSnapshot>,
) -> Result<Vec<SourceSnapshot>, String> {
    let mut by_artifact = HashMap::new();
    for method in methods {
        let source = source_by_artifact
            .get(method.artifact_path.as_str())
            .ok_or_else(|| format!("sealed method {} has no source snapshot", method.method_id))?;
        by_artifact
            .entry(method.artifact_path.as_str())
            .or_insert_with(|| (*source).clone());
    }
    let mut snapshots = by_artifact.into_values().collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.artifact_path.cmp(&right.artifact_path));
    Ok(snapshots)
}

fn unique_sorted_ids(case_id: &str, values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err(format!("resolved case {case_id} has no methods"));
    }
    let mut result = values.to_vec();
    result.sort();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!("resolved case {case_id} repeats a method"));
    }
    Ok(result)
}

fn validate_snapshots(
    snapshots: &[SourceSnapshot],
    root: &Path,
    label: &str,
) -> Result<(), String> {
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve label artifact root: {error}"))?;
    let mut paths = HashSet::new();
    for snapshot in snapshots {
        require_text("snapshot repository", &snapshot.repository)?;
        require_text("snapshot revision", &snapshot.revision)?;
        safe_relative(&snapshot.repository_path)?;
        safe_relative(&snapshot.artifact_path)?;
        require_sha256("snapshot SHA-256", &snapshot.sha256)?;
        if !paths.insert(snapshot.artifact_path.as_str()) {
            return Err(format!("{label} repeats {}", snapshot.artifact_path));
        }
        let artifact = fs::canonicalize(root.join(&snapshot.artifact_path)).map_err(|error| {
            format!(
                "failed to resolve {label} {}: {error}",
                snapshot.artifact_path
            )
        })?;
        if !artifact.starts_with(&canonical_root) {
            return Err(format!(
                "{label} escapes its bundle: {}",
                snapshot.artifact_path
            ));
        }
        let actual = sha256(&fs::read(&artifact).map_err(|error| {
            format!("failed to read {label} {}: {error}", snapshot.artifact_path)
        })?);
        if !actual.eq_ignore_ascii_case(&snapshot.sha256) {
            return Err(format!(
                "{label} hash mismatch for {}; expected {}, got {actual}",
                snapshot.artifact_path, snapshot.sha256
            ));
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(format!(
            "label artifact path must be safe and relative: {value}"
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

fn require_nonempty_texts(label: &str, values: &[String]) -> Result<(), String> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
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

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize blind-case commitment: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_label_resolution_tests.rs"]
mod tests;
