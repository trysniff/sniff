use super::{
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticResolution,
    IntentionalBoundarySemanticSourceReference,
};

#[derive(Clone, Copy)]
pub(super) enum AstCompilerReferenceIdentity {
    PythonWarningsWarn,
    PythonDeprecationWarning,
    KotlinDeprecated,
}

#[derive(Clone)]
pub(super) struct AstCompilerReferenceRequirement {
    pub range: IntentionalBoundarySemanticRange,
    pub identity: AstCompilerReferenceIdentity,
}

pub(super) fn compiler_reference_requirements_satisfied(
    requirements: &[AstCompilerReferenceRequirement],
    source_references: &[IntentionalBoundarySemanticSourceReference],
) -> bool {
    requirements.iter().all(|requirement| {
        let indexer = required_indexer(requirement.identity);
        let mut matches = source_references.iter().filter(|reference| {
            reference.indexer == indexer
                && reference.location == requirement.range
                && reference_matches_identity(reference, requirement.identity)
        });
        if matches.next().is_none() {
            return false;
        }
        matches.next().is_none()
    })
}

fn reference_matches_identity(
    reference: &IntentionalBoundarySemanticSourceReference,
    identity: AstCompilerReferenceIdentity,
) -> bool {
    let IntentionalBoundarySemanticResolution::Resolved { value: target } = &reference.target
    else {
        return false;
    };
    target.origin == IntentionalBoundarySemanticOrigin::External
        && target.symbol_id
            == format!(
                "scip-global:{}:{}",
                target.provider_identity.len(),
                target.provider_identity
            )
        && compiler_identity_matches(identity, &target.provider_identity)
}

fn required_indexer(identity: AstCompilerReferenceIdentity) -> IntentionalBoundaryIndexerKind {
    match identity {
        AstCompilerReferenceIdentity::PythonWarningsWarn
        | AstCompilerReferenceIdentity::PythonDeprecationWarning => {
            IntentionalBoundaryIndexerKind::Python
        }
        AstCompilerReferenceIdentity::KotlinDeprecated => IntentionalBoundaryIndexerKind::Kotlin,
    }
}

fn compiler_identity_matches(
    identity: AstCompilerReferenceIdentity,
    provider_identity: &str,
) -> bool {
    use scip::types::descriptor::Suffix;

    let expected = match identity {
        AstCompilerReferenceIdentity::PythonWarningsWarn => {
            [("_warnings", Suffix::Package), ("warn", Suffix::Method)]
        }
        AstCompilerReferenceIdentity::PythonDeprecationWarning => [
            ("builtins", Suffix::Package),
            ("DeprecationWarning", Suffix::Type),
        ],
        AstCompilerReferenceIdentity::KotlinDeprecated => {
            [("kotlin", Suffix::Package), ("Deprecated", Suffix::Type)]
        }
    };
    let Ok(symbol) = scip::symbol::parse_symbol(provider_identity) else {
        return false;
    };
    let Some(package) = symbol.package.as_ref() else {
        return false;
    };
    let package_matches = match identity {
        AstCompilerReferenceIdentity::PythonWarningsWarn
        | AstCompilerReferenceIdentity::PythonDeprecationWarning => {
            symbol.scheme == "scip-python"
                && package.manager == "python"
                && package.name == "python-stdlib"
        }
        AstCompilerReferenceIdentity::KotlinDeprecated => {
            symbol.scheme == "scip-java"
                && package.manager == "maven"
                && package.name == "maven/org.jetbrains.kotlin/kotlin-stdlib"
        }
    };
    package_matches
        && !package.version.is_empty()
        && symbol.descriptors.len() == expected.len()
        && symbol
            .descriptors
            .iter()
            .zip(expected)
            .all(|(actual, (name, suffix))| {
                actual.name == name
                    && actual.disambiguator.is_empty()
                    && actual.suffix.enum_value() == Ok(suffix)
            })
}
