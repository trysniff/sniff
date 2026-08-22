use super::intentional_boundary_ast_evidence::{
    AST_INPUT_PREFIX, derive_compiler_and_ast_evidence, index_ast_census_set,
};
use super::intentional_boundary_compiler_evidence::COMPILER_INPUT;
use super::intentional_boundary_evidence_outcome::{EvidenceDerivationError, evidence_invalid};
use super::intentional_boundary_manifest_evidence::{
    MANIFEST_BINDING_INPUT, MANIFEST_INPUT, derive_manifest_evidence,
};
use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestCensus,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySourceCensus,
};
use std::collections::BTreeMap;

pub(super) fn derive_base_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, EvidenceDerivationError> {
    let ast_by_language =
        index_ast_census_set(source_census, ast_censuses).map_err(evidence_invalid)?;
    let compiler_and_ast =
        derive_compiler_and_ast_evidence(source_census, semantic_census, &ast_by_language)
            .map_err(evidence_invalid)?;
    derive_manifest_evidence(
        source_census,
        semantic_census,
        manifest_census,
        binding_census,
        compiler_and_ast,
    )
    .map_err(evidence_invalid)
}

pub(super) fn expected_base_evidence_inputs(
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
) -> Result<BTreeMap<String, String>, EvidenceDerivationError> {
    let mut inputs = BTreeMap::from([(
        COMPILER_INPUT.to_string(),
        semantic_census.semantic_census_sha256.clone(),
    )]);
    for census in ast_censuses {
        let [language] = census.languages.as_slice() else {
            return Err(evidence_invalid(
                "intentional-boundary evidence stage requires one language per AST census",
            ));
        };
        if inputs
            .insert(
                format!("{AST_INPUT_PREFIX}{language}"),
                census.ast_census_sha256.clone(),
            )
            .is_some()
        {
            return Err(evidence_invalid(format!(
                "intentional-boundary evidence stage repeated AST language {language}"
            )));
        }
    }
    inputs.insert(
        MANIFEST_INPUT.to_string(),
        manifest_census.manifest_census_sha256.clone(),
    );
    inputs.insert(
        MANIFEST_BINDING_INPUT.to_string(),
        binding_census.binding_census_sha256.clone(),
    );
    Ok(inputs)
}
