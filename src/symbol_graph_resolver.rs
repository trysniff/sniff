use super::paths::{
    resolve_default_export, resolve_direct_symbol, resolve_module_path,
    resolve_qualified_reference, resolve_symbol_key, same_path,
};
use super::{ResolveContext, SymbolGraph};
use crate::types::{ImportRecord, LocalFileSymbols, ResolvedSymbol, SymbolKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

fn lookup_graph_file(all_files: &HashMap<String, String>, candidate: &Path) -> Option<String> {
    all_files
        .get(&super::paths::normalize_path(&candidate.to_string_lossy()))
        .cloned()
}

fn default_rust_module_candidates(parent_file: &str, module_name: &str) -> Vec<PathBuf> {
    let parent = Path::new(parent_file);
    let directory = parent.parent().unwrap_or_else(|| Path::new("."));
    let stem = parent
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    let mut candidates = Vec::new();
    if !matches!(stem, "lib" | "main" | "mod") && !stem.is_empty() {
        candidates.push(directory.join(stem).join(format!("{module_name}.rs")));
        candidates.push(directory.join(stem).join(module_name).join("mod.rs"));
    }
    candidates.push(directory.join(format!("{module_name}.rs")));
    candidates.push(directory.join(module_name).join("mod.rs"));
    candidates
}

fn build_rust_module_maps(
    files: &HashMap<String, crate::types::LocalFileSymbols>,
    all_files: &HashMap<String, String>,
) -> (HashMap<(String, String), String>, HashMap<String, String>) {
    let mut modules = HashMap::new();
    let mut parents = HashMap::new();
    for (parent_file, symbols) in files {
        if !parent_file.ends_with(".rs") {
            continue;
        }
        let parent_dir = Path::new(parent_file)
            .parent()
            .unwrap_or_else(|| Path::new("."));
        for module in &symbols.modules {
            let target = module
                .source_path
                .as_deref()
                .and_then(|source| lookup_graph_file(all_files, &parent_dir.join(source)))
                .or_else(|| {
                    default_rust_module_candidates(parent_file, &module.local_name)
                        .iter()
                        .find_map(|candidate| lookup_graph_file(all_files, candidate))
                });
            let Some(target) = target else {
                continue;
            };
            let parent_key = super::paths::normalize_path(parent_file);
            let target_key = super::paths::normalize_path(&target);
            modules.insert(
                (parent_key.clone(), module.local_name.clone()),
                target.clone(),
            );
            parents
                .entry(target_key)
                .or_insert_with(|| parent_file.clone());
        }
    }
    (modules, parents)
}

fn rust_crate_names(project_root: &str) -> HashSet<String> {
    let manifest = Path::new(project_root).join("Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(manifest) else {
        return HashSet::new();
    };
    let Ok(value) = contents.parse::<toml::Value>() else {
        return HashSet::new();
    };
    let mut names = HashSet::new();
    if let Some(name) = value
        .get("lib")
        .and_then(|section| section.get("name"))
        .and_then(toml::Value::as_str)
    {
        names.insert(name.to_string());
    }
    if let Some(name) = value
        .get("package")
        .and_then(|section| section.get("name"))
        .and_then(toml::Value::as_str)
    {
        names.insert(name.replace('-', "_"));
    }
    names
}

fn language_for_path(file_path: &str) -> &'static str {
    if file_path.ends_with(".go") {
        "go"
    } else if file_path.ends_with(".py") {
        "python"
    } else if file_path.ends_with(".rs") {
        "rust"
    } else if file_path.ends_with(".kt") {
        "kotlin"
    } else if file_path.ends_with(".js")
        || file_path.ends_with(".ts")
        || file_path.ends_with(".jsx")
        || file_path.ends_with(".tsx")
    {
        "javascript"
    } else {
        "unknown"
    }
}

#[path = "symbol_graph_resolver_kotlin.rs"]
mod kotlin;

impl SymbolGraph {
    fn resolve_js_ts_qualified_member_reference(
        &self,
        ctx: &ResolveContext<'_>,
        current_file: &str,
        reference_name: &str,
    ) -> Option<ResolvedSymbol> {
        let (receiver, member) = reference_name.rsplit_once('.')?;
        if receiver.is_empty() || member.is_empty() || receiver.contains('.') {
            return None;
        }
        let current_symbols = self.files.get(current_file)?;
        if let Some(definition) = current_symbols.definitions.iter().find(|definition| {
            definition.name == member && definition.owner_type.as_deref() == Some(receiver)
        }) {
            return Some(ResolvedSymbol::Local(definition.id));
        }

        let (import_index, import) = current_symbols
            .imports
            .iter()
            .enumerate()
            .find(|(_, import)| import.local_name == receiver)?;
        if import.imported_name == "*" {
            let target_file = resolve_module_path(ctx, &import.source_module)?;
            return self.resolve_symbol_in_file(ctx, &target_file, member, &mut HashSet::new());
        }

        let resolved_owner = self
            .resolved_imports
            .get(&(current_file.to_string(), import_index));
        let (target_file, owner_name) = match resolved_owner {
            Some(ResolvedSymbol::Local(definition_id)) => {
                let definition = current_symbols
                    .definitions
                    .iter()
                    .find(|definition| definition.id == *definition_id)?;
                (current_file.to_string(), definition.name.clone())
            }
            Some(ResolvedSymbol::External {
                file_path,
                symbol_name,
                definition_id,
            }) => {
                let owner_name = definition_id
                    .and_then(|id| {
                        self.files
                            .get(file_path)?
                            .definitions
                            .iter()
                            .find_map(|definition| {
                                (definition.id == id).then(|| definition.name.clone())
                            })
                    })
                    .unwrap_or_else(|| symbol_name.clone());
                (file_path.clone(), owner_name)
            }
            None => {
                let target_file = resolve_module_path(ctx, &import.source_module)?;
                (target_file, import.imported_name.clone())
            }
        };
        let target_symbols = self.files.get(&target_file)?;
        let definition = target_symbols.definitions.iter().find(|definition| {
            definition.name == member
                && definition.owner_type.as_deref() == Some(owner_name.as_str())
        })?;
        if same_path(current_file, &target_file) {
            Some(ResolvedSymbol::Local(definition.id))
        } else {
            Some(ResolvedSymbol::External {
                file_path: target_file,
                symbol_name: definition.name.clone(),
                definition_id: Some(definition.id),
            })
        }
    }

    fn refine_rust_callable_target(
        &self,
        current_file: &str,
        resolved: ResolvedSymbol,
        symbol_name: &str,
        member_call: bool,
    ) -> ResolvedSymbol {
        let target_file = match &resolved {
            ResolvedSymbol::Local(_) => current_file,
            ResolvedSymbol::External { file_path, .. } => file_path,
        };
        let Some(symbols) = self.files.get(target_file) else {
            return resolved;
        };
        let mut matches = symbols.definitions.iter().filter(|definition| {
            definition.name == symbol_name
                && if member_call {
                    definition.owner_type.is_some()
                } else {
                    definition.owner_type.is_none()
                }
        });
        let Some(definition) = matches.next() else {
            return resolved;
        };
        if matches.next().is_some() {
            return resolved;
        }
        if same_path(current_file, target_file) {
            ResolvedSymbol::Local(definition.id)
        } else {
            ResolvedSymbol::External {
                file_path: target_file.to_string(),
                symbol_name: definition.name.clone(),
                definition_id: Some(definition.id),
            }
        }
    }

    fn resolve_export_target(
        &self,
        ctx: &ResolveContext<'_>,
        target_file: &str,
        symbol_name: &str,
    ) -> Option<(String, String)> {
        let file_symbols = self.files.get(target_file)?;
        let export_ctx = ResolveContext {
            importing_file: target_file,
            project_root: ctx.project_root,
            all_files: ctx.all_files,
            rust_modules: ctx.rust_modules,
            rust_parents: ctx.rust_parents,
            rust_crate_names: ctx.rust_crate_names,
            language: ctx.language,
        };
        for export in file_symbols
            .exports
            .iter()
            .filter(|export| export.exported_name == symbol_name || export.exported_name == "*")
        {
            let (Some(source_module), Some(source_symbol_name)) = (
                export.source_module.as_deref(),
                export.source_symbol_name.as_deref(),
            ) else {
                continue;
            };

            let source_file = if source_module.is_empty() {
                target_file.to_string()
            } else if let Some(resolved_path) = resolve_module_path(&export_ctx, source_module) {
                resolved_path
            } else {
                continue;
            };

            if export.exported_name == "*" {
                return Some((source_file, symbol_name.to_string()));
            }

            return Some((source_file, source_symbol_name.to_string()));
        }
        None
    }

    pub(super) fn resolve_symbol_in_file(
        &self,
        ctx: &ResolveContext<'_>,
        target_file: &str,
        symbol_name: &str,
        visited: &mut HashSet<String>,
    ) -> Option<ResolvedSymbol> {
        let mut current_file = target_file.to_string();
        let mut current_symbol = symbol_name.to_string();

        loop {
            let visit_key = resolve_symbol_key(&current_file, &current_symbol);
            if !visited.insert(visit_key) {
                return None;
            }

            let file_symbols = self.files.get(&current_file)?;
            if let Some(resolved) = resolve_direct_symbol(
                ctx.importing_file,
                &current_file,
                file_symbols,
                &current_symbol,
            ) {
                return Some(resolved);
            }

            let (next_file, next_symbol) =
                self.resolve_export_target(ctx, &current_file, &current_symbol)?;

            current_file = next_file;
            current_symbol = next_symbol;
        }
    }

    pub(super) fn resolve_unique_symbol_reference(
        &self,
        current_file: &str,
        symbol_name: &str,
    ) -> Option<ResolvedSymbol> {
        let mut matches = Vec::new();

        for (file_path, file_symbols) in &self.files {
            for def in &file_symbols.definitions {
                if def.name == symbol_name
                    && matches!(&def.kind, SymbolKind::Function | SymbolKind::Method)
                {
                    matches.push((file_path.clone(), def.id, def.name.clone()));
                }
            }
        }

        if matches.len() != 1 {
            return None;
        }

        let (matched_file, def_id, def_name) = matches.remove(0);
        Some(if same_path(current_file, &matched_file) {
            ResolvedSymbol::Local(def_id)
        } else {
            ResolvedSymbol::External {
                file_path: matched_file,
                symbol_name: def_name,
                definition_id: Some(def_id),
            }
        })
    }

    fn resolve_unique_owned_method_reference(
        &self,
        current_file: &str,
        symbol_name: &str,
    ) -> Option<ResolvedSymbol> {
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    definition.name == symbol_name
                        && matches!(&definition.kind, SymbolKind::Method)
                        && definition.owner_type.is_some()
                })
                .map(move |definition| (file_path.clone(), definition.id, definition.name.clone()))
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let (matched_file, definition_id, definition_name) = first;
        Some(if same_path(current_file, &matched_file) {
            ResolvedSymbol::Local(definition_id)
        } else {
            ResolvedSymbol::External {
                file_path: matched_file,
                symbol_name: definition_name,
                definition_id: Some(definition_id),
            }
        })
    }

    fn resolve_go_package_method_reference(
        &self,
        current_file: &str,
        symbol_name: &str,
    ) -> Option<ResolvedSymbol> {
        let current_dir = Path::new(current_file).parent()?;
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            let same_package = Path::new(file_path).parent() == Some(current_dir);
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    same_package
                        && definition.name == symbol_name
                        && matches!(&definition.kind, SymbolKind::Method)
                        && definition.owner_type.is_some()
                })
                .map(move |definition| (file_path.clone(), definition.id, definition.name.clone()))
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let (matched_file, definition_id, definition_name) = first;
        Some(if same_path(current_file, &matched_file) {
            ResolvedSymbol::Local(definition_id)
        } else {
            ResolvedSymbol::External {
                file_path: matched_file,
                symbol_name: definition_name,
                definition_id: Some(definition_id),
            }
        })
    }

    fn resolve_python_inherited_method(
        &self,
        ctx: &ResolveContext<'_>,
        current_file: &str,
        owner_type: &str,
        member_name: &str,
        visited: &mut HashSet<String>,
    ) -> Option<ResolvedSymbol> {
        let visit_key = format!(
            "{}::{owner_type}",
            super::paths::normalize_path(current_file)
        );
        if !visited.insert(visit_key) {
            return None;
        }
        let symbols = self.files.get(current_file)?;
        let type_record = symbols
            .types
            .iter()
            .find(|record| record.name == owner_type)?;

        for base in &type_record.bases {
            let (base_file, base_name) = if let Some(import) = symbols
                .imports
                .iter()
                .find(|import| import.local_name == *base)
            {
                (
                    resolve_module_path(ctx, &import.source_module)?,
                    import.imported_name.clone(),
                )
            } else {
                (current_file.to_string(), base.clone())
            };
            let base_symbols = self.files.get(&base_file)?;
            if let Some(definition) = base_symbols.definitions.iter().find(|definition| {
                definition.name == member_name
                    && definition.owner_type.as_deref() == Some(base_name.as_str())
            }) {
                return Some(if same_path(ctx.importing_file, &base_file) {
                    ResolvedSymbol::Local(definition.id)
                } else {
                    ResolvedSymbol::External {
                        file_path: base_file,
                        symbol_name: definition.name.clone(),
                        definition_id: Some(definition.id),
                    }
                });
            }
            if let Some(resolved) = self.resolve_python_inherited_method(
                ctx,
                &base_file,
                &base_name,
                member_name,
                visited,
            ) {
                return Some(resolved);
            }
        }
        None
    }

    pub(super) fn resolve_all_impl(&mut self) {
        let all_files: HashMap<String, String> = self
            .files
            .keys()
            .map(|f| (super::paths::normalize_path(f), f.clone()))
            .collect();
        let (rust_modules, rust_parents) = build_rust_module_maps(&self.files, &all_files);
        let rust_crate_names = rust_crate_names(&self.project_root);
        let mut resolved_imports = HashMap::new();
        let mut resolved_exports = HashMap::new();
        for (file_path, file_symbols) in &self.files {
            let ctx = ResolveContext {
                importing_file: file_path,
                project_root: &self.project_root,
                all_files: &all_files,
                rust_modules: &rust_modules,
                rust_parents: &rust_parents,
                rust_crate_names: &rust_crate_names,
                language: language_for_path(file_path),
            };
            for (index, import) in file_symbols.imports.iter().enumerate() {
                if matches!(import.imported_name.as_str(), "*" | "default") {
                    continue;
                }
                let Some(target_file) = resolve_module_path(&ctx, &import.source_module) else {
                    continue;
                };
                let mut visited = HashSet::new();
                if let Some(resolved) = self.resolve_symbol_in_file(
                    &ctx,
                    &target_file,
                    &import.imported_name,
                    &mut visited,
                ) {
                    resolved_imports.insert((file_path.clone(), index), resolved);
                }
            }
            for (index, export) in file_symbols.exports.iter().enumerate() {
                let resolved = if let (Some(source_module), Some(source_symbol)) = (
                    export.source_module.as_deref(),
                    export.source_symbol_name.as_deref(),
                ) {
                    if matches!(source_symbol, "*" | "default") {
                        None
                    } else {
                        resolve_module_path(&ctx, source_module).and_then(|target_file| {
                            self.resolve_symbol_in_file(
                                &ctx,
                                &target_file,
                                source_symbol,
                                &mut HashSet::new(),
                            )
                        })
                    }
                } else {
                    resolve_direct_symbol(
                        file_path,
                        file_path,
                        file_symbols,
                        &export.local_symbol_name,
                    )
                };
                if let Some(resolved) = resolved {
                    resolved_exports.insert((file_path.clone(), index), resolved);
                }
            }
        }
        self.resolved_imports = resolved_imports;
        self.resolved_exports = resolved_exports;
        let mut updates: HashMap<String, Vec<(usize, ResolvedSymbol)>> = HashMap::new();

        for (file_path, file_symbols) in &self.files {
            let mut resolved_refs = Vec::new();

            let language = language_for_path(file_path);

            for (ref_idx, reference) in file_symbols.references.iter().enumerate() {
                let ctx = ResolveContext {
                    importing_file: file_path,
                    project_root: &self.project_root,
                    all_files: &all_files,
                    rust_modules: &rust_modules,
                    rust_parents: &rust_parents,
                    rust_crate_names: &rust_crate_names,
                    language,
                };

                let is_rust_member_call = language == "rust"
                    && !reference.name.contains("::")
                    && reference.is_member_call;
                let is_python_member_call = language == "python" && reference.is_member_call;
                let is_go_member_call = language == "go" && reference.is_member_call;
                let is_js_ts_member_call =
                    matches!(language, "javascript" | "typescript") && reference.is_member_call;
                let js_ts_owner = is_js_ts_member_call
                    .then(|| {
                        file_symbols
                            .definitions
                            .iter()
                            .filter(|definition| {
                                definition.start_line <= reference.line
                                    && reference.line <= definition.end_line
                                    && definition.owner_type.is_some()
                            })
                            .min_by_key(|definition| {
                                definition.end_line.saturating_sub(definition.start_line)
                            })
                            .and_then(|definition| definition.owner_type.as_deref())
                    })
                    .flatten();

                if language == "kotlin"
                    && reference.name.contains('.')
                    && let Some(resolved) = self.resolve_kotlin_qualified_method_reference(
                        file_path,
                        &reference.name,
                        reference.line,
                    )
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if language == "kotlin"
                    && !reference.name.contains('.')
                    && let Some(resolved) = self.resolve_kotlin_private_constructor_invoke(
                        file_path,
                        &reference.name,
                        reference.line,
                    )
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if language == "kotlin"
                    && !reference.name.contains('.')
                    && let Some(resolved) = self.resolve_kotlin_local_callable_reference(
                        file_path,
                        &reference.name,
                        reference.line,
                    )
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if language == "rust"
                    && reference.name.contains("::")
                    && let Some(resolved) =
                        self.resolve_rust_qualified_reference(&ctx, &reference.name)
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if matches!(language, "javascript" | "typescript")
                    && reference.name.contains('.')
                    && let Some(resolved) = self.resolve_js_ts_qualified_member_reference(
                        &ctx,
                        file_path,
                        &reference.name,
                    )
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                let mut local_match = None;
                for def in &file_symbols.definitions {
                    if def.name == reference.name
                        && ((!matches!(
                            language,
                            "rust" | "python" | "javascript" | "typescript" | "kotlin"
                        ) || (is_js_ts_member_call
                            && js_ts_owner.is_some()
                            && def.owner_type.as_deref() == js_ts_owner)
                            || (matches!(language, "javascript" | "typescript")
                                && !is_js_ts_member_call
                                && def.owner_type.is_none()))
                            || (is_rust_member_call && def.owner_type.is_some())
                            || (language == "rust"
                                && !is_rust_member_call
                                && def.owner_type.is_none())
                            || (is_python_member_call && def.owner_type.is_some())
                            || (language == "python"
                                && !is_python_member_call
                                && def.owner_type.is_none()))
                    {
                        local_match = Some(ResolvedSymbol::Local(def.id));
                        break;
                    }
                }

                if let Some(resolved) = local_match {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if language == "go" {
                    let ref_dir = Path::new(file_path).parent();
                    let mut package_match = None;
                    for (other_file, other_symbols) in &self.files {
                        if Path::new(other_file).parent() == ref_dir {
                            for def in &other_symbols.definitions {
                                if def.name == reference.name {
                                    package_match = Some(ResolvedSymbol::External {
                                        file_path: other_file.clone(),
                                        symbol_name: def.name.clone(),
                                        definition_id: Some(def.id),
                                    });
                                    break;
                                }
                            }
                        }
                        if package_match.is_some() {
                            break;
                        }
                    }
                    if let Some(resolved) = package_match {
                        resolved_refs.push((ref_idx, resolved));
                        continue;
                    }
                }

                let mut import_match = None;
                for imp in &file_symbols.imports {
                    if language == "kotlin"
                        && let Some(resolved) =
                            self.resolve_kotlin_imported_reference(file_path, imp, &reference.name)
                    {
                        import_match = Some(resolved);
                        break;
                    }
                    if language == "python"
                        && imp.imported_name == "*"
                        && let Some(resolved_path) = resolve_module_path(&ctx, &imp.source_module)
                    {
                        let mut visited = HashSet::new();
                        if let Some(resolved) = self.resolve_symbol_in_file(
                            &ctx,
                            &resolved_path,
                            &reference.name,
                            &mut visited,
                        ) {
                            import_match = Some(resolved);
                            break;
                        }
                    }

                    let matches_direct = imp.local_name == reference.name;
                    let matches_qualified = reference.name.contains('.')
                        && reference
                            .name
                            .rsplit_once('.')
                            .map(|(qualifier, _)| qualifier == imp.local_name)
                            .unwrap_or(false);

                    if matches_direct || matches_qualified {
                        let target_symbol_name = if matches_qualified {
                            reference
                                .name
                                .rsplit_once('.')
                                .map(|(_, symbol)| symbol.to_string())
                                .unwrap_or_else(|| imp.imported_name.clone())
                        } else if imp.imported_name == "default" || imp.imported_name == "*" {
                            reference.name.clone()
                        } else {
                            imp.imported_name.clone()
                        };

                        let mut candidate_paths = Vec::new();
                        if let Some(resolved_path) = resolve_module_path(&ctx, &imp.source_module) {
                            candidate_paths.push(resolved_path);
                        }
                        if language == "python" && matches_qualified && imp.imported_name != "*" {
                            let combined_module = if imp.source_module.is_empty() {
                                imp.imported_name.clone()
                            } else if imp.source_module.ends_with('.') {
                                format!("{}{}", imp.source_module, imp.imported_name)
                            } else {
                                format!("{}.{}", imp.source_module, imp.imported_name)
                            };

                            if let Some(alt_path) = resolve_module_path(&ctx, &combined_module)
                                && !candidate_paths.contains(&alt_path)
                            {
                                candidate_paths.push(alt_path);
                            }
                        }

                        for resolved_path in candidate_paths {
                            let direct_target = if imp.imported_name == "default" {
                                if let Some(target_symbols) = self.files.get(&resolved_path) {
                                    resolve_default_export(target_symbols)
                                        .unwrap_or_else(|| reference.name.clone())
                                } else {
                                    reference.name.clone()
                                }
                            } else {
                                target_symbol_name.clone()
                            };

                            let mut visited = HashSet::new();
                            if let Some(resolved) = self.resolve_symbol_in_file(
                                &ctx,
                                &resolved_path,
                                &direct_target,
                                &mut visited,
                            ) {
                                import_match = Some(if language == "rust" {
                                    self.refine_rust_callable_target(
                                        file_path,
                                        resolved,
                                        &direct_target,
                                        is_rust_member_call,
                                    )
                                } else {
                                    resolved
                                });
                                break;
                            }

                            if (language == "javascript" || language == "typescript")
                                && matches_qualified
                                && let Some(target_symbols) = self.files.get(&resolved_path)
                                && let Some(ns_export) = target_symbols.exports.iter().find(|e| {
                                    e.exported_name == imp.local_name
                                        && e.source_symbol_name.as_deref() == Some("*")
                                })
                                && let Some(source_module) = ns_export.source_module.as_deref()
                                && let Some(ns_module_path) =
                                    resolve_module_path(&ctx, source_module)
                            {
                                let mut visited = HashSet::new();
                                if let Some(resolved) = self.resolve_symbol_in_file(
                                    &ctx,
                                    &ns_module_path,
                                    &target_symbol_name,
                                    &mut visited,
                                ) {
                                    import_match = Some(resolved);
                                    break;
                                }
                            }

                            if language == "go"
                                && let Some(target_symbols) = self.files.get(&resolved_path)
                            {
                                let symbol_exists = target_symbols
                                    .definitions
                                    .iter()
                                    .any(|d| d.name == target_symbol_name);
                                if !symbol_exists {
                                    let resolved_parent = Path::new(&resolved_path).parent();
                                    if let Some((candidate_path, _)) = self.files.iter().find(
                                        |(candidate_path, candidate_symbols)| {
                                            Path::new(candidate_path).parent() == resolved_parent
                                                && candidate_symbols
                                                    .definitions
                                                    .iter()
                                                    .any(|d| d.name == target_symbol_name)
                                        },
                                    ) {
                                        import_match = Some(ResolvedSymbol::External {
                                            file_path: candidate_path.clone(),
                                            symbol_name: target_symbol_name.clone(),
                                            definition_id: None,
                                        });
                                        break;
                                    }
                                }
                            }
                        }

                        if import_match.is_none() && (matches_direct || matches_qualified) {
                            break;
                        }
                    }
                }

                if let Some(resolved) = import_match {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if let Some(resolved) = resolve_qualified_reference(&ctx, &reference.name) {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                if is_go_member_call {
                    let (qualifier, terminal_name) = reference
                        .name
                        .rsplit_once('.')
                        .unwrap_or(("", &reference.name));
                    let qualifier_is_import = file_symbols
                        .imports
                        .iter()
                        .any(|import| import.local_name == qualifier);
                    if !qualifier_is_import
                        && let Some(resolved) =
                            self.resolve_go_package_method_reference(file_path, terminal_name)
                    {
                        resolved_refs.push((ref_idx, resolved));
                        continue;
                    }
                }

                if language == "rust" {
                    if is_rust_member_call
                        && let Some(resolved) =
                            self.resolve_unique_owned_method_reference(file_path, &reference.name)
                    {
                        resolved_refs.push((ref_idx, resolved));
                        continue;
                    }
                    if !is_rust_member_call
                        && !reference.name.contains("::")
                        && let Some(resolved) = self.resolve_rust_symbol_through_globs(
                            &ctx,
                            file_path,
                            &reference.name,
                            &mut HashSet::new(),
                        )
                    {
                        resolved_refs.push((ref_idx, resolved));
                        continue;
                    }
                    let terminal_name = reference
                        .name
                        .rsplit("::")
                        .next()
                        .unwrap_or(&reference.name);
                    if !reference.is_callable_value
                        && let Some(resolved) =
                            self.resolve_unique_symbol_reference(file_path, terminal_name)
                    {
                        resolved_refs.push((ref_idx, resolved));
                    }
                } else if language == "python" && is_python_member_call {
                    let terminal_name =
                        reference.name.rsplit('.').next().unwrap_or(&reference.name);
                    let owner_type = file_symbols
                        .definitions
                        .iter()
                        .filter(|definition| {
                            definition.start_line <= reference.line
                                && reference.line <= definition.end_line
                                && definition.owner_type.is_some()
                        })
                        .min_by_key(|definition| {
                            definition.end_line.saturating_sub(definition.start_line)
                        })
                        .and_then(|definition| definition.owner_type.as_deref());
                    if let Some(owner_type) = owner_type
                        && let Some(resolved) = self.resolve_python_inherited_method(
                            &ctx,
                            file_path,
                            owner_type,
                            terminal_name,
                            &mut HashSet::new(),
                        )
                    {
                        resolved_refs.push((ref_idx, resolved));
                        continue;
                    }
                    if let Some(resolved) =
                        self.resolve_unique_owned_method_reference(file_path, terminal_name)
                    {
                        resolved_refs.push((ref_idx, resolved));
                    }
                } else if language == "kotlin"
                    && !reference.name.contains('.')
                    && let Some(resolved) =
                        self.resolve_kotlin_top_level_reference(file_path, &reference.name)
                {
                    resolved_refs.push((ref_idx, resolved));
                }
            }

            if !resolved_refs.is_empty() {
                updates.insert(file_path.clone(), resolved_refs);
            }
        }

        for (file_path, resolved_list) in updates {
            if let Some(file_symbols) = self.files.get_mut(&file_path) {
                for (ref_idx, resolved) in resolved_list {
                    file_symbols.references[ref_idx].resolved_symbol = Some(resolved);
                }
            }
        }
    }
}
