use super::{ParsedManifestDeclaration, resolve_manifest_path};
use crate::benchmark::release::{
    IntentionalBoundaryManifestDeclarationKind as DeclarationKind,
    IntentionalBoundaryManifestProvider as Provider, IntentionalBoundaryManifestTarget as Target,
};
use toml_edit::{ImDocument, Item};

pub(super) fn parse_manifest(
    provider: Provider,
    manifest_path: &str,
    source: &str,
) -> Result<Vec<ParsedManifestDeclaration>, String> {
    let document = ImDocument::parse(source).map_err(|error| {
        format!("failed to parse intentional-boundary TOML manifest {manifest_path}: {error}")
    })?;
    match provider {
        Provider::CargoManifest => parse_cargo(manifest_path, &document),
        Provider::PythonProjectManifest => parse_pyproject(manifest_path, &document),
        _ => Err(format!(
            "TOML manifest parser does not support provider {provider:?}"
        )),
    }
}

fn parse_cargo(
    manifest_path: &str,
    document: &ImDocument<&str>,
) -> Result<Vec<ParsedManifestDeclaration>, String> {
    let mut declarations = Vec::new();
    if let Some(path) = document.get("lib").and_then(|item| item.get("path")) {
        declarations.push(path_declaration(
            manifest_path,
            path,
            DeclarationKind::PublishedModule,
            "Cargo [lib].path",
        )?);
    }
    if let Some(binaries) = document.get("bin").and_then(Item::as_array_of_tables) {
        for binary in binaries.iter() {
            if let Some(path) = binary.get("path") {
                declarations.push(path_declaration(
                    manifest_path,
                    path,
                    DeclarationKind::RuntimeEntrypoint,
                    "Cargo [[bin]].path",
                )?);
            }
        }
    }
    if let Some(build) = document.get("package").and_then(|item| item.get("build"))
        && build.as_bool() != Some(false)
    {
        declarations.push(path_declaration(
            manifest_path,
            build,
            DeclarationKind::BuildScript,
            "Cargo package.build",
        )?);
    }
    Ok(declarations)
}

fn parse_pyproject(
    _manifest_path: &str,
    document: &ImDocument<&str>,
) -> Result<Vec<ParsedManifestDeclaration>, String> {
    let mut declarations = Vec::new();
    let Some(project) = document.get("project") else {
        return Ok(declarations);
    };
    for table_name in ["scripts", "gui-scripts"] {
        if let Some(table) = project.get(table_name).and_then(Item::as_table_like) {
            for (command, item) in table.iter() {
                declarations.push(python_entrypoint(
                    item,
                    &format!("project.{table_name}.{command}"),
                )?);
            }
        }
    }
    if let Some(groups) = project.get("entry-points").and_then(Item::as_table_like) {
        for (group_name, group_item) in groups.iter() {
            let group = group_item
                .as_table_like()
                .ok_or_else(|| format!("project.entry-points.{group_name} must be a TOML table"))?;
            for (entry_name, item) in group.iter() {
                declarations.push(python_entrypoint(
                    item,
                    &format!("project.entry-points.{group_name}.{entry_name}"),
                )?);
            }
        }
    }
    Ok(declarations)
}

fn path_declaration(
    manifest_path: &str,
    item: &Item,
    declaration_kind: DeclarationKind,
    label: &str,
) -> Result<ParsedManifestDeclaration, String> {
    let target = item
        .as_str()
        .ok_or_else(|| format!("{label} must be a string path"))?;
    Ok(ParsedManifestDeclaration {
        declaration_kind,
        span: item_span(item, label)?,
        target: Target::RepositoryPath {
            repository_path: resolve_manifest_path(manifest_path, target)?,
        },
    })
}

fn python_entrypoint(item: &Item, label: &str) -> Result<ParsedManifestDeclaration, String> {
    let value = item
        .as_str()
        .ok_or_else(|| format!("{label} must be a Python object-reference string"))?;
    let (module, qualname) = value.split_once(':').unwrap_or((value, ""));
    let module = python_dotted_name(module, &format!("{label} module"))?;
    let qualname = if qualname.is_empty() {
        Vec::new()
    } else {
        python_dotted_name(qualname, &format!("{label} object"))?
    };
    Ok(ParsedManifestDeclaration {
        declaration_kind: DeclarationKind::RuntimeEntrypoint,
        span: item_span(item, label)?,
        target: Target::PythonObject { module, qualname },
    })
}

fn python_dotted_name(value: &str, label: &str) -> Result<Vec<String>, String> {
    if value.trim() != value || value.is_empty() {
        return Err(format!(
            "{label} is empty or contains surrounding whitespace"
        ));
    }
    value
        .split('.')
        .map(|part| {
            let mut characters = part.chars();
            let first = characters
                .next()
                .ok_or_else(|| format!("{label} contains an empty identifier"))?;
            if !(first == '_' || first.is_alphabetic())
                || !characters.all(|character| character == '_' || character.is_alphanumeric())
            {
                return Err(format!("{label} contains invalid identifier {part}"));
            }
            Ok(part.to_string())
        })
        .collect()
}

fn item_span(item: &Item, label: &str) -> Result<std::ops::Range<usize>, String> {
    item.span()
        .ok_or_else(|| format!("{label} has no parsed TOML source span"))
}
