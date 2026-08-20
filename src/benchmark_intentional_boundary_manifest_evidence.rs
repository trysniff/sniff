use super::intentional_boundary_compiler_evidence::{finish_evidence_census, push_typed_atom};
use super::{
    BoundaryEvidenceKind, IntentionalBoundaryAstCensus, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestBindingOutcome, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestProofKind, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySourceCensus,
    extract_intentional_boundary_compiler_and_ast_evidence,
    validate_intentional_boundary_manifest_bindings,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MANIFEST_INPUT: &str = "package_manifest_declarations";
const MANIFEST_BINDING_INPUT: &str = "package_manifest_bindings";

#[allow(clippy::too_many_arguments)]
pub fn extract_intentional_boundary_compiler_ast_and_manifest_evidence(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    let compiler_and_ast = extract_intentional_boundary_compiler_and_ast_evidence(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_censuses,
    )?;
    derive_manifest_evidence(
        source_census,
        semantic_census,
        manifest_census,
        binding_census,
        compiler_and_ast,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_compiler_ast_and_manifest_evidence(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = extract_intentional_boundary_compiler_ast_and_manifest_evidence(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_censuses,
        manifest_census,
        binding_census,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary compiler/AST/manifest evidence changed".to_string());
    }
    Ok(())
}

pub(super) fn derive_manifest_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    manifest_census: &IntentionalBoundaryManifestCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    compiler_and_ast: IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_manifest_bindings(
        source_census,
        semantic_census,
        manifest_census,
        binding_census,
    )?;
    if compiler_and_ast.repository != source_census.repository
        || compiler_and_ast.revision != source_census.revision
        || compiler_and_ast.source_census_sha256 != source_census.census_sha256
        || compiler_and_ast.semantic_census_sha256 != semantic_census.semantic_census_sha256
    {
        return Err("intentional-boundary manifest evidence base changed".to_string());
    }
    let declarations = manifest_census
        .declarations
        .iter()
        .map(|declaration| (declaration.declaration_id.as_str(), declaration))
        .collect::<BTreeMap<_, _>>();
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = compiler_and_ast.atoms;
    for binding in &binding_census.bindings {
        let IntentionalBoundaryManifestBindingOutcome::Bound { subjects } = &binding.outcome else {
            continue;
        };
        let declaration = declarations
            .get(binding.declaration_id.as_str())
            .ok_or_else(|| {
                format!(
                    "intentional-boundary manifest evidence invented declaration {}",
                    binding.declaration_id
                )
            })?;
        for subject in subjects {
            let method = resolved_subject_method(&methods, subject)?;
            append_declaration_evidence(&mut atoms, declaration, method)?;
        }
    }
    let mut input_census_sha256 = compiler_and_ast.input_census_sha256;
    if input_census_sha256
        .insert(
            MANIFEST_INPUT.to_string(),
            manifest_census.manifest_census_sha256.clone(),
        )
        .is_some()
        || input_census_sha256
            .insert(
                MANIFEST_BINDING_INPUT.to_string(),
                binding_census.binding_census_sha256.clone(),
            )
            .is_some()
    {
        return Err("intentional-boundary manifest evidence input collision".to_string());
    }
    finish_evidence_census(source_census, semantic_census, input_census_sha256, atoms)
}

fn resolved_subject_method<'a>(
    methods: &'a BTreeMap<&str, &'a IntentionalBoundarySemanticMethod>,
    subject: &super::IntentionalBoundaryManifestBoundSubject,
) -> Result<&'a IntentionalBoundarySemanticMethod, String> {
    let method = methods
        .get(subject.parser_unit_id.as_str())
        .copied()
        .ok_or_else(|| {
            format!(
                "intentional-boundary manifest evidence invented method {}",
                subject.parser_unit_id
            )
        })?;
    if !matches!(
        &method.status,
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. }
            if symbol.symbol_id == subject.subject_symbol_id
    ) {
        return Err(format!(
            "intentional-boundary manifest evidence changed compiler subject {}",
            subject.parser_unit_id
        ));
    }
    Ok(method)
}

fn append_declaration_evidence(
    atoms: &mut Vec<super::IntentionalBoundaryEvidenceAtom>,
    declaration: &IntentionalBoundaryManifestDeclaration,
    method: &IntentionalBoundarySemanticMethod,
) -> Result<(), String> {
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
            "intentional-boundary manifest subject has no compiler definition: {}",
            method.parser_unit_id
        ));
    }
    match declaration.declaration_kind {
        IntentionalBoundaryManifestDeclarationKind::PublishedModule => {
            let mut identity_locations = definitions;
            identity_locations.push(declaration.declaration_location.clone());
            push_typed_atom(
                atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::ExportedApiIdentity,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::PublishedExport,
                ),
                identity_locations,
                Vec::new(),
            )?;
            push_typed_atom(
                atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::PublishedApiContract,
                IntentionalBoundaryEvidenceProof::ManifestContract(
                    IntentionalBoundaryManifestProofKind::PublishedExport,
                ),
                vec![declaration.declaration_location.clone()],
                Vec::new(),
            )
        }
        IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint => push_typed_atom(
            atoms,
            method,
            &symbol.symbol_id,
            BoundaryEvidenceKind::RuntimeOrPackageManifest,
            IntentionalBoundaryEvidenceProof::ManifestContract(
                IntentionalBoundaryManifestProofKind::RuntimeEntrypoint,
            ),
            vec![declaration.declaration_location.clone()],
            Vec::new(),
        ),
        IntentionalBoundaryManifestDeclarationKind::BuildScript
        | IntentionalBoundaryManifestDeclarationKind::PackageScript => {
            Err("generator-command declarations require replay before method evidence".to_string())
        }
    }
}
