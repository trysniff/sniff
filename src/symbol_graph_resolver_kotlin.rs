use super::*;

fn kotlin_type_leaf(type_name: &str) -> &str {
    type_name
        .split('<')
        .next()
        .unwrap_or(type_name)
        .trim()
        .trim_end_matches('?')
        .rsplit('.')
        .next()
        .unwrap_or(type_name)
}

fn kotlin_first_generic_argument(type_name: &str) -> Option<&str> {
    let start = type_name.find('<')? + 1;
    let mut depth = 0usize;
    for (offset, character) in type_name[start..].char_indices() {
        match character {
            '<' => depth += 1,
            '>' if depth == 0 => return Some(type_name[start..start + offset].trim()),
            '>' => depth -= 1,
            ',' if depth == 0 => return Some(type_name[start..start + offset].trim()),
            _ => {}
        }
    }
    None
}

fn kotlin_enclosing_owner(symbols: &LocalFileSymbols, line: usize) -> Option<&str> {
    symbols
        .definitions
        .iter()
        .filter(|definition| {
            matches!(&definition.kind, SymbolKind::Method)
                && definition.start_line <= line
                && line <= definition.end_line
                && definition.owner_type.is_some()
        })
        .min_by_key(|definition| definition.end_line.saturating_sub(definition.start_line))
        .and_then(|definition| definition.owner_type.as_deref())
}

impl SymbolGraph {
    fn kotlin_unique_callable_value_type(
        &self,
        current_file: &str,
        callable_name: &str,
    ) -> Option<String> {
        let current_package = self
            .files
            .get(current_file)?
            .modules
            .first()
            .map(|module| module.local_name.as_str());
        let mut value_types = self.files.values().flat_map(|symbols| {
            let same_package = symbols
                .modules
                .first()
                .map(|module| module.local_name.as_str())
                == current_package;
            symbols.definitions.iter().filter_map(move |definition| {
                (same_package
                    && matches!(&definition.kind, SymbolKind::Function | SymbolKind::Method)
                    && definition.name == callable_name)
                    .then(|| definition.value_type.as_deref().map(kotlin_type_leaf))
                    .flatten()
            })
        });
        let first = value_types.next()?.to_string();
        value_types
            .all(|value_type| value_type == first)
            .then_some(first)
    }

    fn kotlin_member_value_type(&self, owner_type: &str, member_name: &str) -> Option<String> {
        let owner_type = kotlin_type_leaf(owner_type);
        let mut value_types = self.files.values().flat_map(|symbols| {
            symbols.definitions.iter().filter_map(move |definition| {
                (matches!(&definition.kind, SymbolKind::Variable | SymbolKind::Method)
                    && definition.name == member_name
                    && definition.owner_type.as_deref().map(kotlin_type_leaf) == Some(owner_type))
                .then(|| definition.value_type.as_deref().map(kotlin_type_leaf))
                .flatten()
            })
        });
        let first = value_types.next()?.to_string();
        value_types
            .all(|value_type| value_type == first)
            .then_some(first)
    }

    fn kotlin_receiver_type_at(
        &self,
        current_file: &str,
        qualifier_parts: &[&str],
        reference_line: usize,
    ) -> Option<String> {
        let root = *qualifier_parts.first()?;
        let current_symbols = self.files.get(current_file)?;
        let binding_type = current_symbols
            .definitions
            .iter()
            .filter(|definition| {
                matches!(&definition.kind, SymbolKind::Variable)
                    && definition.name == root
                    && definition.start_line <= reference_line
                    && reference_line <= definition.end_line
                    && definition.value_type.is_some()
            })
            .min_by_key(|definition| {
                (
                    definition.end_line.saturating_sub(definition.start_line),
                    usize::MAX - definition.start_line,
                )
            })
            .and_then(|definition| definition.value_type.clone())
            .or_else(|| {
                root.chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_uppercase())
                    .then(|| root.to_string())
            });

        let (mut current, remaining) =
            if let Some(binding_type) = binding_type {
                (binding_type, &qualifier_parts[1..])
            } else {
                let (index, inferred) = qualifier_parts.iter().enumerate().skip(1).find_map(
                    |(index, projection)| {
                        self.kotlin_unique_callable_value_type(current_file, projection)
                            .map(|value_type| (index, value_type))
                    },
                )?;
                (inferred, &qualifier_parts[index + 1..])
            };

        for projection in remaining {
            current = match *projection {
                "current" | "value" => kotlin_first_generic_argument(&current)?.to_string(),
                member => self.kotlin_member_value_type(&current, member)?,
            };
        }
        Some(kotlin_type_leaf(&current).to_string())
    }

    pub(super) fn resolve_kotlin_private_constructor_invoke(
        &self,
        current_file: &str,
        reference_name: &str,
        reference_line: usize,
    ) -> Option<ResolvedSymbol> {
        let current_symbols = self.files.get(current_file)?;
        let current_package = current_symbols
            .modules
            .first()
            .map(|module| module.local_name.as_str());
        let current_owner = kotlin_enclosing_owner(current_symbols, reference_line);
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            let candidate_package = symbols
                .modules
                .first()
                .map(|module| module.local_name.as_str());
            let imported_name = current_symbols.imports.iter().find_map(|import| {
                (import.local_name == reference_name
                    && import.source_module == candidate_package.unwrap_or_default())
                .then_some(import.imported_name.as_str())
            });
            let class_name = imported_name.unwrap_or(reference_name);
            let visible = current_package == candidate_package || imported_name.is_some();
            let private_constructor = visible
                && symbols.types.iter().any(|type_record| {
                    type_record.name == class_name && type_record.constructor_is_private
                });
            let called_from_owner = same_path(current_file, file_path)
                && current_owner.is_some_and(|owner| kotlin_type_leaf(owner) == class_name);
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    private_constructor
                        && !called_from_owner
                        && matches!(&definition.kind, SymbolKind::Method)
                        && definition.name == "invoke"
                        && definition.owner_type.as_deref().map(kotlin_type_leaf)
                            == Some(class_name)
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

    pub(super) fn resolve_kotlin_local_callable_reference(
        &self,
        current_file: &str,
        symbol_name: &str,
        reference_line: usize,
    ) -> Option<ResolvedSymbol> {
        let symbols = self.files.get(current_file)?;
        if let Some(owner) = kotlin_enclosing_owner(symbols, reference_line) {
            let mut owned = symbols.definitions.iter().filter(|definition| {
                matches!(&definition.kind, SymbolKind::Method)
                    && definition.name == symbol_name
                    && definition.owner_type.as_deref() == Some(owner)
            });
            let first = owned.next();
            if owned.next().is_none()
                && let Some(definition) = first
            {
                return Some(ResolvedSymbol::Local(definition.id));
            }
        }

        let mut top_level = symbols.definitions.iter().filter(|definition| {
            matches!(&definition.kind, SymbolKind::Function)
                && definition.name == symbol_name
                && definition.owner_type.is_none()
                && definition.receiver_type.is_none()
        });
        let first = top_level.next()?;
        top_level
            .next()
            .is_none()
            .then_some(ResolvedSymbol::Local(first.id))
    }

    pub(super) fn resolve_kotlin_top_level_reference(
        &self,
        current_file: &str,
        symbol_name: &str,
    ) -> Option<ResolvedSymbol> {
        let current_symbols = self.files.get(current_file)?;
        let current_package = current_symbols
            .modules
            .first()
            .map(|module| &module.local_name);
        let current_parent = Path::new(current_file).parent();
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            let same_package = current_package.is_some_and(|package| {
                symbols
                    .modules
                    .first()
                    .is_some_and(|module| module.local_name == *package)
            }) || (current_package.is_none()
                && Path::new(file_path).parent() == current_parent);
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    same_package
                        && definition.name == symbol_name
                        && matches!(&definition.kind, SymbolKind::Function)
                        && definition.owner_type.is_none()
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

    pub(super) fn resolve_kotlin_imported_reference(
        &self,
        current_file: &str,
        import: &ImportRecord,
        reference_name: &str,
    ) -> Option<ResolvedSymbol> {
        let symbol_name = if import.imported_name == "*" {
            reference_name
        } else if import.local_name == reference_name {
            &import.imported_name
        } else {
            return None;
        };
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            let package_matches = symbols
                .modules
                .first()
                .is_some_and(|module| module.local_name == import.source_module);
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    package_matches
                        && definition.name == symbol_name
                        && matches!(&definition.kind, SymbolKind::Function)
                        && definition.owner_type.is_none()
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

    pub(super) fn resolve_kotlin_qualified_method_reference(
        &self,
        current_file: &str,
        reference_name: &str,
        reference_line: usize,
    ) -> Option<ResolvedSymbol> {
        let (qualifier_path, method_name) = reference_name.rsplit_once('.')?;
        let qualifier_parts = qualifier_path.split('.').collect::<Vec<_>>();
        let owner_name =
            self.kotlin_receiver_type_at(current_file, &qualifier_parts, reference_line)?;
        let owner_name = owner_name.as_str();
        let current_owner = self
            .files
            .get(current_file)
            .and_then(|symbols| kotlin_enclosing_owner(symbols, reference_line));
        let mut matches = self.files.iter().flat_map(|(file_path, symbols)| {
            symbols
                .definitions
                .iter()
                .filter(move |definition| {
                    matches!(&definition.kind, SymbolKind::Method)
                        && definition.name == method_name
                        && (definition.owner_type.as_deref().map(kotlin_type_leaf)
                            == Some(owner_name)
                            || (definition.receiver_type.as_deref().map(kotlin_type_leaf)
                                == Some(owner_name)
                                && (definition.owner_type.is_none()
                                    || (same_path(current_file, file_path)
                                        && definition.owner_type.as_deref() == current_owner))))
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
}
