use super::super::{
    HISTORICAL_V3_MECHANICAL_QUALIFICATION_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_MECHANICAL_QUALIFICATION_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3Materialization, HistoricalV3MechanicalExclusionReason,
    HistoricalV3MechanicalQualification, HistoricalV3MechanicalQualificationExclusion,
    HistoricalV3MechanicalQualificationOutcome, HistoricalV3NonProductionRole,
    HistoricalV3Protocol, HistoricalV3SemanticCensus, HistoricalV3SourceCensus,
    historical_v3_rank_identity, validate_historical_v3_materialization_commitment,
    validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_source_census_commitment,
};
use super::evidence::{build_evidence, evidence_sha256, language_name};
use super::{MECHANICAL_QUALIFICATION_CONTRACT, MECHANICAL_QUALIFICATION_EXCLUSION_CONTRACT};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn derive_historical_v3_mechanical_qualification(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
) -> Result<HistoricalV3MechanicalQualificationOutcome, String> {
    validate_inputs(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
    )?;
    let rank = historical_v3_rank_identity(protocol, collection, materialization.stream_rank)?;
    let evidence = build_evidence(
        &protocol.mechanical_policy,
        &source_census.base,
        &source_census.merge,
        &semantic_census.base,
        &semantic_census.merge,
    )?;
    let reasons = exclusion_reasons(rank.language(), &evidence);
    if reasons.is_empty() {
        let mut artifact = HistoricalV3MechanicalQualification {
            schema_version: HISTORICAL_V3_MECHANICAL_QUALIFICATION_SCHEMA_VERSION,
            qualification_contract: MECHANICAL_QUALIFICATION_CONTRACT.to_string(),
            rank,
            materialization_sha256: materialization.materialization_sha256.clone(),
            source_census_sha256: source_census.source_census_sha256.clone(),
            semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
            evidence,
            qualification_sha256: String::new(),
        };
        artifact = seal_qualification(artifact)?;
        Ok(HistoricalV3MechanicalQualificationOutcome::Qualified(
            Box::new(artifact),
        ))
    } else {
        let mut artifact = HistoricalV3MechanicalQualificationExclusion {
            schema_version: HISTORICAL_V3_MECHANICAL_QUALIFICATION_EXCLUSION_SCHEMA_VERSION,
            exclusion_contract: MECHANICAL_QUALIFICATION_EXCLUSION_CONTRACT.to_string(),
            rank,
            materialization_sha256: materialization.materialization_sha256.clone(),
            source_census_sha256: source_census.source_census_sha256.clone(),
            semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
            evidence,
            reasons,
            exclusion_sha256: String::new(),
        };
        artifact = seal_exclusion(artifact)?;
        Ok(HistoricalV3MechanicalQualificationOutcome::Excluded(
            Box::new(artifact),
        ))
    }
}

pub fn validate_historical_v3_mechanical_qualification(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    artifact: &HistoricalV3MechanicalQualification,
) -> Result<(), String> {
    let HistoricalV3MechanicalQualificationOutcome::Qualified(expected) =
        derive_historical_v3_mechanical_qualification(
            protocol,
            collection,
            materialization,
            source_census,
            semantic_census,
        )?
    else {
        return Err("historical-v3 mechanical evidence is not qualified".to_string());
    };
    if artifact != expected.as_ref()
        || artifact.schema_version != HISTORICAL_V3_MECHANICAL_QUALIFICATION_SCHEMA_VERSION
        || artifact.qualification_contract != MECHANICAL_QUALIFICATION_CONTRACT
        || artifact.evidence.evidence_sha256 != evidence_sha256(&artifact.evidence)?
        || artifact.qualification_sha256 != qualification_sha256(artifact)?
    {
        return Err("historical-v3 mechanical qualification changed".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_mechanical_qualification_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    artifact: &HistoricalV3MechanicalQualificationExclusion,
) -> Result<(), String> {
    let HistoricalV3MechanicalQualificationOutcome::Excluded(expected) =
        derive_historical_v3_mechanical_qualification(
            protocol,
            collection,
            materialization,
            source_census,
            semantic_census,
        )?
    else {
        return Err("historical-v3 mechanical evidence is not excluded".to_string());
    };
    if artifact != expected.as_ref()
        || artifact.schema_version
            != HISTORICAL_V3_MECHANICAL_QUALIFICATION_EXCLUSION_SCHEMA_VERSION
        || artifact.exclusion_contract != MECHANICAL_QUALIFICATION_EXCLUSION_CONTRACT
        || artifact.evidence.evidence_sha256 != evidence_sha256(&artifact.evidence)?
        || artifact.exclusion_sha256 != exclusion_sha256(artifact)?
    {
        return Err("historical-v3 mechanical qualification exclusion changed".to_string());
    }
    Ok(())
}

fn validate_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
) -> Result<(), String> {
    validate_historical_v3_materialization_commitment(protocol, collection, materialization)
        .map_err(|error| error.detail)?;
    validate_historical_v3_source_census_commitment(
        protocol,
        collection,
        materialization,
        source_census,
    )?;
    validate_historical_v3_semantic_census_commitment(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
    )?;
    if materialization.materialization_sha256 != source_census.materialization_sha256
        || source_census.source_census_sha256 != semantic_census.source_census_sha256
        || source_census.rank != semantic_census.rank
    {
        return Err("historical-v3 mechanical input binding changed".to_string());
    }
    Ok(())
}

fn exclusion_reasons(
    language: super::super::HistoricalV3Language,
    evidence: &super::super::HistoricalV3MechanicalEvidence,
) -> Vec<HistoricalV3MechanicalExclusionReason> {
    let mut reasons = BTreeSet::new();
    if evidence.base_production_method_count < evidence.production_method_minimum
        || evidence.merge_production_method_count < evidence.production_method_minimum
    {
        reasons.insert(HistoricalV3MechanicalExclusionReason::RepositoryMethodCountBelowMinimum);
    }
    if evidence.base_production_method_count > evidence.production_method_maximum
        || evidence.merge_production_method_count > evidence.production_method_maximum
    {
        reasons.insert(HistoricalV3MechanicalExclusionReason::RepositoryMethodCountAboveMaximum);
    }
    if evidence.changed_methods.is_empty() && evidence.unresolved_changed_methods.is_empty() {
        reasons.insert(HistoricalV3MechanicalExclusionReason::NoChangedProductionMethods);
        match evidence.non_production_roles.as_slice() {
            [HistoricalV3NonProductionRole::Generated] => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::GeneratedOnly);
            }
            [HistoricalV3NonProductionRole::Vendored] => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::VendoredOnly);
            }
            [HistoricalV3NonProductionRole::Documentation] => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::DocumentationOnly);
            }
            [HistoricalV3NonProductionRole::Fixture] => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::FixtureOnly);
            }
            [HistoricalV3NonProductionRole::Test] => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::TestOnly);
            }
            roles if roles.len() > 1 => {
                reasons.insert(HistoricalV3MechanicalExclusionReason::MixedNonProductionOnly);
            }
            _ => {}
        }
    }
    let rank_language = language_name(language);
    if !evidence
        .changed_methods
        .iter()
        .any(|method| method.language == rank_language)
        && !evidence
            .unresolved_changed_methods
            .iter()
            .any(|method| method.language == rank_language)
    {
        reasons.insert(HistoricalV3MechanicalExclusionReason::NoChangedRankLanguageMethods);
    }
    if !evidence.unresolved_changed_methods.is_empty() {
        reasons.insert(HistoricalV3MechanicalExclusionReason::ChangedProductionMethodUnresolved);
    }
    if evidence.simplifications.is_empty() {
        reasons
            .insert(HistoricalV3MechanicalExclusionReason::NoNetProductionReductionOrConsolidation);
    }
    if !evidence.public_surface.preserved {
        reasons.insert(HistoricalV3MechanicalExclusionReason::PublicSurfaceChanged);
    }
    if evidence.formatting_only {
        reasons.insert(HistoricalV3MechanicalExclusionReason::FormattingOnly);
    }
    reasons.into_iter().collect()
}

fn qualification_sha256(artifact: &HistoricalV3MechanicalQualification) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.qualification_sha256.clear();
    json_sha256(&committed)
}

pub(super) fn seal_qualification(
    mut artifact: HistoricalV3MechanicalQualification,
) -> Result<HistoricalV3MechanicalQualification, String> {
    artifact.evidence.evidence_sha256 = evidence_sha256(&artifact.evidence)?;
    artifact.qualification_sha256.clear();
    artifact.qualification_sha256 = qualification_sha256(&artifact)?;
    Ok(artifact)
}

fn exclusion_sha256(
    artifact: &HistoricalV3MechanicalQualificationExclusion,
) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.exclusion_sha256.clear();
    json_sha256(&committed)
}

pub(super) fn seal_exclusion(
    mut artifact: HistoricalV3MechanicalQualificationExclusion,
) -> Result<HistoricalV3MechanicalQualificationExclusion, String> {
    artifact.evidence.evidence_sha256 = evidence_sha256(&artifact.evidence)?;
    artifact.exclusion_sha256.clear();
    artifact.exclusion_sha256 = exclusion_sha256(&artifact)?;
    Ok(artifact)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 qualification: {error}"))
}
