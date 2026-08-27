use crate::semantic_index::{
    RepositoryPath, SemanticIndex, SemanticRelationship, SemanticRelationshipKind,
    SemanticResolution, SemanticSignature, SemanticSymbol, SemanticSymbolCategory,
    SemanticSymbolId, SemanticSymbolKind, SemanticSymbolOrigin, SemanticVisibility,
};
use protobuf::Enum;
use scip::types::{Relationship, SymbolInformation, symbol_information::Kind};
use std::collections::BTreeSet;

const CONFLICTING_KINDS: &str = "ConflictingKinds";

struct ImportedSignature {
    value: Option<SemanticSignature>,
    references: Vec<(SemanticSymbolId, String)>,
}

pub(super) fn stable_symbol_id(
    raw: &str,
    document: Option<&RepositoryPath>,
) -> Result<SemanticSymbolId, String> {
    scip::symbol::parse_symbol(raw)
        .map_err(|error| format!("invalid SCIP symbol identity {raw:?}: {error:?}"))?;
    if scip::symbol::is_local_symbol(raw) {
        let document = document.ok_or_else(|| {
            format!("local SCIP symbol {raw:?} has no containing document identity")
        })?;
        return Ok(SemanticSymbolId(format!(
            "scip-local:{}:{}:{}:{}",
            document.0.len(),
            document.0,
            raw.len(),
            raw
        )));
    }
    Ok(SemanticSymbolId(format!(
        "scip-global:{}:{}",
        raw.len(),
        raw
    )))
}

pub(super) fn ingest_symbol_information(
    index: &mut SemanticIndex,
    information: &SymbolInformation,
    document: Option<&RepositoryPath>,
    external: bool,
) -> Result<(), String> {
    if information.symbol.is_empty() {
        return Err("SCIP symbol information has an empty identity".to_string());
    }
    let id = stable_symbol_id(&information.symbol, document)?;
    if external && scip::symbol::is_local_symbol(&information.symbol) {
        return Err(format!(
            "SCIP external symbol cannot use a document-local identity: {}",
            information.symbol
        ));
    }

    let owner = if information.enclosing_symbol.is_empty() {
        None
    } else {
        let owner = stable_symbol_id(&information.enclosing_symbol, document)?;
        ensure_placeholder(
            index,
            owner.clone(),
            information.enclosing_symbol.clone(),
            if scip::symbol::is_local_symbol(&information.enclosing_symbol) {
                SemanticSymbolOrigin::Repository
            } else {
                SemanticSymbolOrigin::Unknown
            },
        );
        Some(SemanticResolution::Resolved { value: owner })
    };
    let signature = ingest_signature(information, document)?;
    for (referenced, provider_identity) in signature.references {
        ensure_placeholder(
            index,
            referenced,
            provider_identity,
            SemanticSymbolOrigin::Unknown,
        );
    }
    let candidate = SemanticSymbol {
        id: id.clone(),
        provider_identity: information.symbol.clone(),
        display_name: (!information.display_name.is_empty())
            .then(|| information.display_name.clone()),
        kind: symbol_kind(information.kind.value(), &information.symbol)?,
        documentation: information.documentation.clone(),
        signature: signature.value,
        owner,
        definitions: BTreeSet::new(),
        visibility: SemanticVisibility::Unknown,
        surfaces: BTreeSet::new(),
        origin: if external {
            SemanticSymbolOrigin::External
        } else {
            SemanticSymbolOrigin::Repository
        },
        ambiguity_notes: Vec::new(),
    };
    merge_symbol(index, candidate)?;

    for relationship in &information.relationships {
        ingest_relationship(index, &id, relationship, document)?;
    }
    Ok(())
}

fn ingest_signature(
    information: &SymbolInformation,
    document: Option<&RepositoryPath>,
) -> Result<ImportedSignature, String> {
    let Some(signature) = information.signature_documentation.as_ref() else {
        return Ok(ImportedSignature {
            value: None,
            references: Vec::new(),
        });
    };
    if signature.language.is_empty()
        && signature.text.is_empty()
        && signature.occurrences.is_empty()
    {
        return Ok(ImportedSignature {
            value: None,
            references: Vec::new(),
        });
    }
    if signature.language.trim().is_empty() || signature.text.is_empty() {
        return Err(format!(
            "SCIP signature for {} must include language and text",
            information.symbol
        ));
    }
    let mut referenced_symbols = BTreeSet::new();
    let mut references = Vec::new();
    for occurrence in &signature.occurrences {
        if !occurrence.symbol.is_empty() {
            let id = stable_symbol_id(&occurrence.symbol, document)?;
            referenced_symbols.insert(id.clone());
            references.push((id, occurrence.symbol.clone()));
        }
    }
    Ok(ImportedSignature {
        value: Some(SemanticSignature {
            language: signature.language.clone(),
            text: signature.text.clone(),
            referenced_symbols,
        }),
        references,
    })
}

fn ingest_relationship(
    index: &mut SemanticIndex,
    source: &SemanticSymbolId,
    relationship: &Relationship,
    document: Option<&RepositoryPath>,
) -> Result<(), String> {
    if relationship.symbol.is_empty() {
        return Err(format!(
            "SCIP relationship from {} has an empty target",
            source.0
        ));
    }
    let target = stable_symbol_id(&relationship.symbol, document)?;
    ensure_placeholder(
        index,
        target.clone(),
        relationship.symbol.clone(),
        if scip::symbol::is_local_symbol(&relationship.symbol) {
            SemanticSymbolOrigin::Repository
        } else {
            SemanticSymbolOrigin::Unknown
        },
    );
    let kinds = [
        (
            relationship.is_reference,
            SemanticRelationshipKind::Reference,
        ),
        (
            relationship.is_implementation,
            SemanticRelationshipKind::Implementation,
        ),
        (
            relationship.is_type_definition,
            SemanticRelationshipKind::TypeDefinition,
        ),
        (
            relationship.is_definition,
            SemanticRelationshipKind::Definition,
        ),
    ];
    let mut inserted = false;
    for (enabled, kind) in kinds {
        if enabled {
            inserted = true;
            index.relationships.insert(SemanticRelationship {
                source: source.clone(),
                target: target.clone(),
                kind,
            });
        }
    }
    if !inserted {
        return Err(format!(
            "SCIP relationship from {} to {} has no relationship role",
            source.0, target.0
        ));
    }
    Ok(())
}

pub(super) fn ensure_placeholder(
    index: &mut SemanticIndex,
    id: SemanticSymbolId,
    provider_identity: String,
    origin: SemanticSymbolOrigin,
) {
    index
        .symbols
        .entry(id.clone())
        .or_insert_with(|| SemanticSymbol {
            id,
            provider_identity,
            display_name: None,
            kind: SemanticSymbolKind {
                category: SemanticSymbolCategory::Unknown,
                provider_name: "UnspecifiedKind".to_string(),
            },
            documentation: Vec::new(),
            signature: None,
            owner: None,
            definitions: BTreeSet::new(),
            visibility: SemanticVisibility::Unknown,
            surfaces: BTreeSet::new(),
            origin,
            ambiguity_notes: Vec::new(),
        });
}

fn merge_symbol(index: &mut SemanticIndex, incoming: SemanticSymbol) -> Result<(), String> {
    let Some(existing) = index.symbols.get_mut(&incoming.id) else {
        index.symbols.insert(incoming.id.clone(), incoming);
        return Ok(());
    };
    if !existing.provider_identity.is_empty()
        && existing.provider_identity != incoming.provider_identity
    {
        return Err(format!(
            "semantic symbol identity collision for {}",
            incoming.id.0
        ));
    }
    if existing.provider_identity.is_empty() {
        existing.provider_identity = incoming.provider_identity;
    }
    merge_optional(
        &mut existing.display_name,
        incoming.display_name,
        &incoming.id,
        "display name",
    )?;
    if existing.kind.category == SemanticSymbolCategory::Unknown {
        if existing.kind.provider_name == CONFLICTING_KINDS {
            if incoming.kind.category != SemanticSymbolCategory::Unknown {
                let detail = format!(
                    "additional conflicting SCIP symbol kind for {}: {}",
                    incoming.id.0, incoming.kind.provider_name
                );
                if !existing.ambiguity_notes.contains(&detail) {
                    existing.ambiguity_notes.push(detail);
                }
            }
        } else {
            existing.kind = incoming.kind;
        }
    } else if incoming.kind.category != SemanticSymbolCategory::Unknown
        && existing.kind != incoming.kind
    {
        let mut provider_names = [
            existing.kind.provider_name.as_str(),
            incoming.kind.provider_name.as_str(),
        ];
        provider_names.sort_unstable();
        let detail = format!(
            "conflicting SCIP symbol kinds for {}: {} and {}",
            incoming.id.0, provider_names[0], provider_names[1]
        );
        existing.kind = SemanticSymbolKind {
            category: SemanticSymbolCategory::Unknown,
            provider_name: CONFLICTING_KINDS.to_string(),
        };
        existing.ambiguity_notes.push(detail);
    }
    if let Err(detail) = merge_optional(
        &mut existing.signature,
        incoming.signature,
        &incoming.id,
        "signature",
    ) {
        existing.signature = None;
        existing.ambiguity_notes.push(detail);
    }
    merge_optional(&mut existing.owner, incoming.owner, &incoming.id, "owner")?;
    for documentation in incoming.documentation {
        if !existing.documentation.contains(&documentation) {
            existing.documentation.push(documentation);
        }
    }
    if existing.origin == SemanticSymbolOrigin::Unknown {
        existing.origin = incoming.origin;
    } else if incoming.origin != SemanticSymbolOrigin::Unknown && existing.origin != incoming.origin
    {
        return Err(format!(
            "conflicting SCIP symbol origins for {}",
            incoming.id.0
        ));
    }
    Ok(())
}

fn merge_optional<T: PartialEq + std::fmt::Debug>(
    existing: &mut Option<T>,
    incoming: Option<T>,
    id: &SemanticSymbolId,
    field: &str,
) -> Result<(), String> {
    match (&existing, incoming) {
        (None, Some(value)) => *existing = Some(value),
        (Some(left), Some(right)) if left != &right => {
            return Err(format!(
                "conflicting SCIP symbol {field} values for {}: existing={left:?}, incoming={right:?}",
                id.0,
            ));
        }
        _ => {}
    }
    Ok(())
}

fn symbol_kind(raw: i32, provider_identity: &str) -> Result<SemanticSymbolKind, String> {
    let kind =
        Kind::from_i32(raw).ok_or_else(|| format!("SCIP symbol uses unknown kind value {raw}"))?;
    let category = match kind {
        Kind::UnspecifiedKind if provider_identity.ends_with("().") => {
            SemanticSymbolCategory::Callable
        }
        Kind::UnspecifiedKind => SemanticSymbolCategory::Unknown,
        Kind::Function | Kind::Getter | Kind::Setter | Kind::Operator | Kind::Accessor => {
            SemanticSymbolCategory::Callable
        }
        Kind::Constructor => SemanticSymbolCategory::Constructor,
        Kind::Method
        | Kind::AbstractMethod
        | Kind::MethodAlias
        | Kind::MethodReceiver
        | Kind::MethodSpecification
        | Kind::ProtocolMethod
        | Kind::PureVirtualMethod
        | Kind::SingletonMethod
        | Kind::StaticMethod
        | Kind::TraitMethod
        | Kind::TypeClassMethod => SemanticSymbolCategory::Method,
        Kind::Class
        | Kind::Enum
        | Kind::Struct
        | Kind::Type
        | Kind::TypeAlias
        | Kind::Union
        | Kind::AssociatedType
        | Kind::TypeParameter => SemanticSymbolCategory::Type,
        Kind::Interface | Kind::Protocol | Kind::Trait | Kind::TypeClass => {
            SemanticSymbolCategory::TraitOrInterface
        }
        Kind::Module | Kind::Library => SemanticSymbolCategory::Module,
        Kind::Namespace => SemanticSymbolCategory::Namespace,
        Kind::Package | Kind::PackageObject => SemanticSymbolCategory::Package,
        Kind::Field
        | Kind::Property
        | Kind::StaticDataMember
        | Kind::StaticField
        | Kind::StaticProperty => SemanticSymbolCategory::FieldOrProperty,
        Kind::Parameter | Kind::ParameterLabel | Kind::SelfParameter | Kind::ThisParameter => {
            SemanticSymbolCategory::Parameter
        }
        Kind::Variable | Kind::StaticVariable | Kind::Value => SemanticSymbolCategory::Variable,
        Kind::Constant | Kind::EnumMember => SemanticSymbolCategory::Constant,
        Kind::Macro => SemanticSymbolCategory::Macro,
        _ => SemanticSymbolCategory::Other,
    };
    Ok(SemanticSymbolKind {
        category,
        provider_name: format!("{kind:?}"),
    })
}
