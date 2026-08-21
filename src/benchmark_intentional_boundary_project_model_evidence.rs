use super::intentional_boundary_compiler_evidence::{
    finish_evidence_census, push_typed_atom, validate_evidence_census_commitment,
};
use super::{
    BoundaryEvidenceKind, IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProofKind,
    IntentionalBoundaryProjectModelBindingCensus, IntentionalBoundaryProjectModelBindingOutcome,
    IntentionalBoundaryProjectModelBoundSubject, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundaryProjectModelTargetStatus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_project_model_bindings,
};
use std::collections::{BTreeMap, BTreeSet};

const PROJECT_MODEL_INPUT: &str = "compiler_project_models";
const PROJECT_MODEL_BINDING_INPUT: &str = "compiler_project_model_bindings";

pub fn compose_intentional_boundary_project_model_evidence(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryProjectModelBindingCensus,
    base_evidence: IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_evidence_census_commitment(source_census, semantic_census, &base_evidence)?;
    validate_intentional_boundary_project_model_bindings(
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        binding_census,
    )?;
    derive_project_model_evidence(
        source_census,
        semantic_census,
        project_model_census,
        binding_census,
        base_evidence,
    )
}

pub fn validate_intentional_boundary_project_model_evidence(
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryProjectModelBindingCensus,
    base_evidence: IntentionalBoundaryEvidenceCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = compose_intentional_boundary_project_model_evidence(
        inventory,
        source_census,
        semantic_census,
        project_model_census,
        binding_census,
        base_evidence,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary project-model evidence changed".to_string());
    }
    Ok(())
}

fn derive_project_model_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    project_model_census: &IntentionalBoundaryProjectModelCensus,
    binding_census: &IntentionalBoundaryProjectModelBindingCensus,
    base_evidence: IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    let targets = project_model_census
        .targets
        .iter()
        .map(|target| (target.target_id.as_str(), target))
        .collect::<BTreeMap<_, _>>();
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = base_evidence.atoms;
    for binding in &binding_census.bindings {
        let IntentionalBoundaryProjectModelBindingOutcome::Bound { subjects } = &binding.outcome
        else {
            continue;
        };
        let target = targets.get(binding.target_id.as_str()).ok_or_else(|| {
            format!(
                "intentional-boundary project-model evidence invented target {}",
                binding.target_id
            )
        })?;
        for subject in subjects {
            let method = resolved_subject_method(&methods, subject)?;
            append_target_evidence(&mut atoms, target, method)?;
        }
    }
    let mut input_census_sha256 = base_evidence.input_census_sha256;
    if input_census_sha256
        .insert(
            PROJECT_MODEL_INPUT.to_string(),
            project_model_census.project_model_census_sha256.clone(),
        )
        .is_some()
        || input_census_sha256
            .insert(
                PROJECT_MODEL_BINDING_INPUT.to_string(),
                binding_census.binding_census_sha256.clone(),
            )
            .is_some()
    {
        return Err("intentional-boundary project-model evidence input collision".to_string());
    }
    finish_evidence_census(source_census, semantic_census, input_census_sha256, atoms)
}

fn resolved_subject_method<'a>(
    methods: &'a BTreeMap<&str, &'a IntentionalBoundarySemanticMethod>,
    subject: &IntentionalBoundaryProjectModelBoundSubject,
) -> Result<&'a IntentionalBoundarySemanticMethod, String> {
    let method = methods
        .get(subject.parser_unit_id.as_str())
        .copied()
        .ok_or_else(|| {
            format!(
                "intentional-boundary project-model evidence invented method {}",
                subject.parser_unit_id
            )
        })?;
    if !matches!(
        &method.status,
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. }
            if symbol.symbol_id == subject.subject_symbol_id
    ) {
        return Err(format!(
            "intentional-boundary project-model evidence changed compiler subject {}",
            subject.parser_unit_id
        ));
    }
    Ok(method)
}

fn append_target_evidence(
    atoms: &mut Vec<super::IntentionalBoundaryEvidenceAtom>,
    target: &IntentionalBoundaryProjectModelTarget,
    method: &IntentionalBoundarySemanticMethod,
) -> Result<(), String> {
    let IntentionalBoundaryProjectModelTargetStatus::Boundary {
        declaration_kind, ..
    } = target.target_status
    else {
        return Err("bound project-model evidence target is not a boundary".to_string());
    };
    let IntentionalBoundarySemanticMethodStatus::Resolved {
        symbol,
        joined_definition,
    } = &method.status
    else {
        unreachable!("resolved_subject_method checked the method status")
    };
    let definitions = joined_definition
        .iter()
        .cloned()
        .chain(symbol.definitions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if definitions.is_empty() {
        return Err(format!(
            "project-model evidence subject has no compiler definition: {}",
            method.parser_unit_id
        ));
    }
    match declaration_kind {
        IntentionalBoundaryManifestDeclarationKind::PublishedModule => {
            push_typed_atom(
                atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::ExportedApiIdentity,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::ProjectModelPublishedExport,
                ),
                definitions.clone(),
                Vec::new(),
            )?;
            push_typed_atom(
                atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::PublishedApiContract,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::ProjectModelPublishedExport,
                ),
                definitions,
                Vec::new(),
            )
        }
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint => push_typed_atom(
            atoms,
            method,
            &symbol.symbol_id,
            BoundaryEvidenceKind::RuntimeOrPackageManifest,
            IntentionalBoundaryEvidenceProof::ManifestContract(
                IntentionalBoundaryManifestProofKind::ProjectModelRuntimeEntrypoint,
            ),
            definitions,
            Vec::new(),
        ),
        IntentionalBoundaryManifestDeclarationKind::BuildScript
        | IntentionalBoundaryManifestDeclarationKind::PackageScript
        | IntentionalBoundaryManifestDeclarationKind::GeneratorCommand => {
            Err("build-script project models require generator replay evidence".to_string())
        }
    }
}
