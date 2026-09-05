use serde::{Deserialize, Serialize};

#[path = "source_public_surface_go.rs"]
mod go;

#[path = "source_public_surface_js_ts.rs"]
mod js_ts;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePublicSymbolKind {
    CompilerDefined,
    Callable,
    Method,
    Type,
    Module,
    Field,
    Variable,
    Constant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePublicBindingKind {
    Definition,
    Reference,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePublicNamespace {
    Module,
    InstanceMember,
    StaticMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePublicReexportKind {
    Wildcard,
    Namespace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceByteRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePublicDeclaration {
    pub name: String,
    pub target_name: String,
    pub owner: Option<String>,
    pub namespace: SourcePublicNamespace,
    pub kind: SourcePublicSymbolKind,
    pub exposed_identifier: SourceByteRange,
    pub compiler_anchor: SourceByteRange,
    pub binding: SourcePublicBindingKind,
    pub source_module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePublicReexport {
    pub kind: SourcePublicReexportKind,
    pub name: Option<String>,
    pub source_module: String,
    pub directive: SourceByteRange,
    pub exposed_identifier: Option<SourceByteRange>,
    pub compiler_anchor: SourceByteRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePublicSurface {
    pub declarations: Vec<SourcePublicDeclaration>,
    pub reexports: Vec<SourcePublicReexport>,
}

pub(crate) fn census_source_public_surface(
    file_path: &str,
    source: &[u8],
) -> Result<SourcePublicSurface, String> {
    let extension = std::path::Path::new(file_path)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("source file has no supported extension: {file_path}"))?;
    let language = crate::languages::get_adapter(extension)
        .ok_or_else(|| format!("unsupported source extension for {file_path}"))?
        .name;
    let mut surface = match language.as_str() {
        "go" => go::census(file_path, source)?,
        "typescript" | "javascript" => js_ts::census(file_path, source)?,
        _ => {
            return Err(format!(
                "public-surface census is not implemented for {language}: {file_path}"
            ));
        }
    };
    surface.declarations.sort();
    surface.reexports.sort();
    if surface
        .declarations
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(format!(
            "public-surface census repeated a declaration in {file_path}"
        ));
    }
    for declaration in &surface.declarations {
        let valid_namespace = matches!(
            (declaration.namespace, declaration.owner.as_ref()),
            (SourcePublicNamespace::Module, None)
                | (SourcePublicNamespace::InstanceMember, Some(_))
                | (SourcePublicNamespace::StaticMember, Some(_))
        );
        if !valid_namespace {
            return Err(format!(
                "public-surface declaration has an incoherent namespace in {file_path}"
            ));
        }
    }
    if surface.reexports.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!(
            "public-surface census repeated a re-export in {file_path}"
        ));
    }
    Ok(surface)
}

#[cfg(test)]
#[path = "tests/source_public_surface.rs"]
mod tests;
