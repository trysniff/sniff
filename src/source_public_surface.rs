use serde::{Deserialize, Serialize};

#[path = "source_public_surface_go.rs"]
mod go;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePublicSymbolKind {
    Callable,
    Method,
    Type,
    Field,
    Variable,
    Constant,
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
    pub owner: Option<String>,
    pub kind: SourcePublicSymbolKind,
    pub identifier: SourceByteRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePublicSurface {
    pub declarations: Vec<SourcePublicDeclaration>,
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
        _ => {
            return Err(format!(
                "public-surface census is not implemented for {language}: {file_path}"
            ));
        }
    };
    surface.declarations.sort();
    if surface
        .declarations
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(format!(
            "public-surface census repeated a declaration in {file_path}"
        ));
    }
    Ok(surface)
}

#[cfg(test)]
#[path = "tests/source_public_surface.rs"]
mod tests;
