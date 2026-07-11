use super::paths::{
    resolve_default_export, resolve_direct_symbol, resolve_module_path,
    resolve_qualified_reference, resolve_symbol_key, same_path,
};
use super::{ResolveContext, SymbolGraph};
use crate::types::ResolvedSymbol;
use std::collections::{HashMap, HashSet};
use std::path::Path;

impl SymbolGraph {
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
                if def.name == symbol_name {
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
            }
        })
    }

    pub(super) fn resolve_all_impl(&mut self) {
        let all_files: HashMap<String, String> = self
            .files
            .keys()
            .map(|f| (super::paths::normalize_path(f), f.clone()))
            .collect();
        let mut updates: HashMap<String, Vec<(usize, ResolvedSymbol)>> = HashMap::new();

        for (file_path, file_symbols) in &self.files {
            let mut resolved_refs = Vec::new();

            let language = if file_path.ends_with(".go") {
                "go"
            } else if file_path.ends_with(".py") {
                "python"
            } else if file_path.ends_with(".rs") {
                "rust"
            } else if file_path.ends_with(".js")
                || file_path.ends_with(".ts")
                || file_path.ends_with(".jsx")
                || file_path.ends_with(".tsx")
            {
                "javascript"
            } else {
                "unknown"
            };

            for (ref_idx, reference) in file_symbols.references.iter().enumerate() {
                let ctx = ResolveContext {
                    importing_file: file_path,
                    project_root: &self.project_root,
                    all_files: &all_files,
                    language,
                };

                if language == "rust"
                    && reference.name.contains("::")
                    && let Some(resolved) =
                        self.resolve_rust_qualified_reference(&ctx, &reference.name)
                {
                    resolved_refs.push((ref_idx, resolved));
                    continue;
                }

                let mut local_match = None;
                for def in &file_symbols.definitions {
                    if def.name == reference.name {
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
                                import_match = Some(resolved);
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

                if language == "rust" {
                    let terminal_name = reference
                        .name
                        .rsplit("::")
                        .next()
                        .unwrap_or(&reference.name);
                    if let Some(resolved) =
                        self.resolve_unique_symbol_reference(file_path, terminal_name)
                    {
                        resolved_refs.push((ref_idx, resolved));
                    }
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
