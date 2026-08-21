use super::{GeneratorCommand, manifest_directory};
use crate::benchmark::release::{
    BoundaryGitEntryKind, IntentionalBoundaryIndexerKind, IntentionalBoundaryManifestBindingCensus,
    IntentionalBoundaryManifestBindingOutcome, IntentionalBoundaryManifestDeclaration,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethodStatus,
};
use std::collections::BTreeMap;

const PYTHON_ENTRYPOINT_RUNNER: &str = concat!(
    "import asyncio,functools,importlib,inspect,pathlib,sys;",
    "sys.path.insert(0,str(pathlib.Path(sys.argv[1]).resolve()));",
    "target=functools.reduce(getattr,sys.argv[3].split('.'),",
    "importlib.import_module(sys.argv[2]));",
    "result=target();",
    "result=asyncio.run(result) if inspect.isawaitable(result) else result"
);

pub(super) fn python_generator_command(
    inventory: &IntentionalBoundaryRepositoryInventory,
    semantic_census: &IntentionalBoundarySemanticCensus,
    binding_census: &IntentionalBoundaryManifestBindingCensus,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> Option<GeneratorCommand> {
    if declaration.provider != IntentionalBoundaryManifestProvider::PythonProjectManifest
        || declaration.declaration_kind
            != IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
    {
        return None;
    }
    let IntentionalBoundaryManifestTarget::PythonObject { module, qualname } = &declaration.target
    else {
        return None;
    };
    if module.is_empty() || qualname.is_empty() || !has_unambiguous_uv_lock(inventory, declaration)
    {
        return None;
    }
    let binding = binding_census
        .bindings
        .iter()
        .find(|binding| binding.declaration_id == declaration.declaration_id)?;
    let IntentionalBoundaryManifestBindingOutcome::Bound { subjects } = &binding.outcome else {
        return None;
    };
    let [subject] = subjects.as_slice() else {
        return None;
    };
    let method = semantic_census
        .methods
        .iter()
        .find(|method| method.parser_unit_id == subject.parser_unit_id)?;
    let IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } = &method.status else {
        return None;
    };
    if method.indexer != IntentionalBoundaryIndexerKind::Python
        || symbol.symbol_id != subject.subject_symbol_id
        || method.symbol_name != *qualname.last()?
    {
        return None;
    }
    let directory = manifest_directory(declaration);
    let project = if directory.is_empty() { "." } else { directory };
    let import_root = python_import_root(directory, &method.repository_path, module)?;
    Some(GeneratorCommand {
        preparation: Some(
            [
                "uv",
                "sync",
                "--project",
                project,
                "--locked",
                "--no-install-project",
                "--no-install-workspace",
                "--no-dev",
                "--no-default-groups",
                "--no-progress",
                "--no-python-downloads",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        ),
        preparation_environment: BTreeMap::new(),
        execution: vec![
            "uv".to_string(),
            "run".to_string(),
            "--project".to_string(),
            project.to_string(),
            "--frozen".to_string(),
            "--no-sync".to_string(),
            "--no-dev".to_string(),
            "--no-default-groups".to_string(),
            "--no-env-file".to_string(),
            "--no-progress".to_string(),
            "--no-python-downloads".to_string(),
            "--".to_string(),
            "python".to_string(),
            "-I".to_string(),
            "-B".to_string(),
            "-c".to_string(),
            PYTHON_ENTRYPOINT_RUNNER.to_string(),
            import_root,
            module.join("."),
            qualname.join("."),
        ],
        execution_environment: BTreeMap::new(),
        cleanup_paths: Vec::new(),
    })
}

fn has_unambiguous_uv_lock(
    inventory: &IntentionalBoundaryRepositoryInventory,
    declaration: &IntentionalBoundaryManifestDeclaration,
) -> bool {
    const LOCKFILES: &[&str] = &[
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "pdm.lock",
        "pylock.toml",
        "requirements.lock",
    ];
    let directory = manifest_directory(declaration);
    let present = LOCKFILES
        .iter()
        .filter(|name| {
            let path = scoped_path(directory, name);
            inventory.tracked_entries.iter().any(|entry| {
                entry.repository_path == path && entry.kind == BoundaryGitEntryKind::RegularBlob
            })
        })
        .copied()
        .collect::<Vec<_>>();
    present == ["uv.lock"]
}

fn python_import_root(directory: &str, source_path: &str, module: &[String]) -> Option<String> {
    let relative = if directory.is_empty() {
        source_path
    } else {
        source_path.strip_prefix(&format!("{directory}/"))?
    };
    let module_path = module.join("/");
    let suffixes = [
        format!("{module_path}.py"),
        format!("{module_path}/__init__.py"),
    ];
    let prefix = suffixes
        .iter()
        .find_map(|suffix| relative.strip_suffix(suffix))?
        .trim_end_matches('/');
    Some(if prefix.is_empty() {
        if directory.is_empty() {
            ".".to_string()
        } else {
            directory.to_string()
        }
    } else {
        scoped_path(directory, prefix)
    })
}

fn scoped_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_string()
    } else {
        format!("{directory}/{name}")
    }
}
