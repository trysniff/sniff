use super::*;
use crate::types::{SymbolKind, SymbolReference};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

fn simple_name_from_text(text: &str) -> Option<String> {
    let trimmed = text
        .trim()
        .trim_end_matches('{')
        .trim_end_matches('(')
        .trim_end_matches(':')
        .trim_end_matches('<')
        .trim_end_matches('>')
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn first_identifier_from_node(node: Node, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(kind, "simple_identifier" | "identifier" | "type_identifier")
        && let Some(text) = node_text(node, source)
    {
        return simple_name_from_text(text);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = first_identifier_from_node(child, source) {
            return Some(name);
        }
    }
    None
}

fn name_for_node(node: Node, source: &str) -> Option<String> {
    if let Some(field) = node.child_by_field_name("name") {
        if let Some(text) = node_text(field, source)
            && let Some(name) = simple_name_from_text(text)
        {
            return Some(name);
        }
        if let Some(name) = first_identifier_from_node(field, source) {
            return Some(name);
        }
    }
    first_identifier_from_node(node, source)
}

fn kotlin_identifier_prefix(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .take_while(|(_, ch)| *ch == '_' || ch.is_ascii_alphanumeric())
        .map(|(index, ch)| index + ch.len_utf8())
        .last()?;
    Some(&value[..end])
}

fn kotlin_type_leaf(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let end = value
        .char_indices()
        .take_while(|(_, ch)| *ch == '_' || ch.is_ascii_alphanumeric() || *ch == '.')
        .map(|(index, ch)| index + ch.len_utf8())
        .last()?;
    value[..end].rsplit('.').find(|part| !part.is_empty())
}

fn kotlin_explicit_type(value: &str) -> Option<String> {
    let value = value
        .split_once('=')
        .map(|(type_name, _)| type_name)
        .unwrap_or(value)
        .trim()
        .trim_end_matches(',')
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn kotlin_receiver_type(node: Node, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    let prefix = source.get(node.start_byte()..name.start_byte())?;
    let mut receiver = prefix.rsplit_once("fun")?.1.trim();
    if receiver.starts_with('<') {
        let mut depth = 0usize;
        let mut end = None;
        for (index, character) in receiver.char_indices() {
            match character {
                '<' => depth += 1,
                '>' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(index + character.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        receiver = receiver.get(end?..)?.trim_start();
    }
    receiver = receiver.trim_end_matches('.').trim();
    (!receiver.is_empty())
        .then(|| kotlin_type_leaf(receiver).map(str::to_string))
        .flatten()
}

fn kotlin_function_return_type(node: Node, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    let suffix = source.get(name.end_byte()..node.end_byte())?;
    let open = suffix.find('(')?;
    let mut depth = 0usize;
    let mut close = None;
    for (offset, character) in suffix[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(open + offset + character.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let after_parameters = suffix.get(close?..)?.trim_start();
    let return_declaration = after_parameters.strip_prefix(':')?.trim_start();
    let mut generic_depth = 0usize;
    let mut function_depth = 0usize;
    let mut end = return_declaration.len();
    for (offset, character) in return_declaration.char_indices() {
        match character {
            '<' => generic_depth += 1,
            '>' => generic_depth = generic_depth.saturating_sub(1),
            '(' => function_depth += 1,
            ')' => function_depth = function_depth.saturating_sub(1),
            '=' | '{' if generic_depth == 0 && function_depth == 0 => {
                end = offset;
                break;
            }
            _ => {}
        }
    }
    let return_type = return_declaration[..end]
        .split_once(" where ")
        .map(|(return_type, _)| return_type)
        .unwrap_or(&return_declaration[..end])
        .trim();
    (!return_type.is_empty()).then(|| return_type.to_string())
}

fn binding_scope_end(node: Node, source: &str) -> usize {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if matches!(
            candidate.kind(),
            "function_declaration"
                | "class_declaration"
                | "object_declaration"
                | "interface_declaration"
                | "enum_class_declaration"
                | "fun_interface_declaration"
                | "lambda_literal"
        ) {
            return candidate.end_position().row + 1;
        }
        ancestor = candidate.parent();
    }
    source.lines().count().max(node.end_position().row + 1)
}

fn kotlin_property_binding(node: Node, source: &str) -> Option<(String, String)> {
    let text = node_text(node, source)?.trim();
    let declaration = text
        .strip_prefix("val ")
        .or_else(|| text.strip_prefix("var "))
        .or_else(|| text.split_once(" val ").map(|(_, rest)| rest))
        .or_else(|| text.split_once(" var ").map(|(_, rest)| rest))?;
    let name = kotlin_identifier_prefix(declaration.trim_start())?.to_string();
    let after_name = declaration.trim_start()[name.len()..].trim_start();
    let value_type = if let Some(explicit) = after_name.strip_prefix(':') {
        kotlin_explicit_type(explicit)?
    } else {
        let initializer = after_name.split_once('=')?.1.trim_start();
        let constructor = kotlin_type_leaf(initializer)?;
        if !constructor
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase())
        {
            return None;
        }
        constructor.to_string()
    };
    Some((name, value_type))
}

fn kotlin_parameter_binding(node: Node, source: &str) -> Option<(String, String)> {
    let text = node_text(node, source)?.trim();
    let (declaration, explicit_type) = text.split_once(':')?;
    let name = declaration
        .split_whitespace()
        .next_back()
        .and_then(kotlin_identifier_prefix)?
        .to_string();
    let value_type = kotlin_explicit_type(explicit_type)?;
    Some((name, value_type))
}

fn split_kotlin_top_level(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0usize;
    let mut paren_depth = 0usize;
    for (index, character) in value.char_indices() {
        match character {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ',' if angle_depth == 0 && paren_depth == 0 => {
                parts.push(value[start..index].trim());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}

fn kotlin_function_parameter_types(value: &str) -> Vec<String> {
    let Some(open) = value.find('(') else {
        return Vec::new();
    };
    let mut depth = 0usize;
    let mut close = None;
    for (offset, character) in value[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return Vec::new();
    };
    split_kotlin_top_level(&value[open + 1..close])
        .into_iter()
        .filter_map(|parameter| {
            let parameter = parameter
                .rsplit_once(':')
                .map(|(_, value_type)| value_type)
                .unwrap_or(parameter)
                .trim();
            (!parameter.is_empty()).then(|| parameter.to_string())
        })
        .collect()
}

fn first_descendant_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| first_descendant_of_kind(child, kind))
}

fn collect_typed_lambda_parameter_pair(
    extractor: &mut SymbolExtractor<'_>,
    declaration: Node,
    lambda: Node,
    source: &str,
) {
    let Some(text) = node_text(declaration, source) else {
        return;
    };
    let declaration = text
        .split_once('=')
        .map(|(declaration, _)| declaration)
        .unwrap_or(text);
    let Some((_, explicit_type)) = declaration.split_once(':') else {
        return;
    };
    let parameter_types = kotlin_function_parameter_types(explicit_type);
    let Some(lambda_text) = node_text(lambda, source) else {
        return;
    };
    let Some((parameters, _)) = lambda_text.split_once("->") else {
        return;
    };
    let parameters = parameters.trim().trim_start_matches('{').trim();
    let parameter_names = split_kotlin_top_level(parameters)
        .into_iter()
        .filter_map(|parameter| {
            let parameter = parameter
                .split_once(':')
                .map(|(name, _)| name)
                .unwrap_or(parameter)
                .trim();
            kotlin_identifier_prefix(parameter).map(str::to_string)
        })
        .collect::<Vec<_>>();
    if parameter_names.len() != parameter_types.len() {
        return;
    }
    for (name, value_type) in parameter_names.into_iter().zip(parameter_types) {
        extractor.definitions.push(SymbolDefinition {
            id: extractor.next_id,
            name,
            kind: SymbolKind::Variable,
            start_line: lambda.start_position().row + 1,
            end_line: lambda.end_position().row + 1,
            is_exported: false,
            owner_type: None,
            receiver_type: None,
            value_type: Some(value_type),
        });
        extractor.next_id += 1;
    }
}

fn collect_owned_typed_lambda_parameters(
    extractor: &mut SymbolExtractor<'_>,
    declaration: Node,
    source: &str,
) {
    let Some(lambda) = first_descendant_of_kind(declaration, "lambda_literal") else {
        return;
    };
    collect_typed_lambda_parameter_pair(extractor, declaration, lambda, source);
}

fn collect_default_parameter_lambda_parameters(
    extractor: &mut SymbolExtractor<'_>,
    parameters: Node,
    source: &str,
) {
    let mut pending_parameter = None;
    let mut cursor = parameters.walk();
    for child in parameters
        .children(&mut cursor)
        .filter(|child| child.is_named())
    {
        match child.kind() {
            "parameter" => pending_parameter = Some(child),
            "lambda_literal" => {
                if let Some(parameter) = pending_parameter.take() {
                    collect_typed_lambda_parameter_pair(extractor, parameter, child, source);
                }
            }
            _ => pending_parameter = None,
        }
    }
}

fn identifier_line(node: Node, source: &str, name: &str) -> Option<usize> {
    if matches!(
        node.kind(),
        "simple_identifier" | "identifier" | "type_identifier"
    ) && node_text(node, source) == Some(name)
    {
        return Some(node.start_position().row + 1);
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| identifier_line(child, source, name))
}

fn record_declaration_occurrence(
    occurrences: &mut HashMap<(usize, String), usize>,
    node: Node,
    source: &str,
    name: &str,
) {
    let line = identifier_line(node, source, name)
        .or_else(|| {
            node.child_by_field_name("name")
                .map(|name| name.start_position().row + 1)
        })
        .unwrap_or_else(|| node.start_position().row + 1);
    *occurrences.entry((line, name.to_string())).or_default() += 1;
}

fn skip_kotlin_type_parameters(value: &str) -> &str {
    let value = value.trim_start();
    if !value.starts_with('<') {
        return value;
    }
    let mut depth = 0usize;
    for (index, character) in value.char_indices() {
        match character {
            '<' => depth += 1,
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return value[index + character.len_utf8()..].trim_start();
                }
            }
            _ => {}
        }
    }
    value
}

fn declared_name_in_snippet(snippet: &str) -> Option<String> {
    if let Some((_, declaration)) = snippet.split_once("fun interface ") {
        return kotlin_identifier_prefix(declaration.trim_start()).map(str::to_string);
    }
    if let Some((_, after_fun)) = snippet.split_once("fun ") {
        let declaration = skip_kotlin_type_parameters(after_fun)
            .split_once('(')
            .map(|(declaration, _)| declaration)
            .unwrap_or(after_fun)
            .trim();
        return declaration
            .trim_end_matches('.')
            .rsplit('.')
            .next()
            .and_then(kotlin_identifier_prefix)
            .map(str::to_string);
    }
    for keyword in ["class ", "object ", "interface ", "val ", "var "] {
        if let Some((_, declaration)) = snippet.split_once(keyword) {
            return kotlin_identifier_prefix(declaration.trim_start()).map(str::to_string);
        }
    }
    None
}

fn remove_precollected_declaration_references(
    references: &mut Vec<SymbolReference>,
    declaration_occurrences: &HashMap<(usize, String), usize>,
) {
    let mut remaining = declaration_occurrences.clone();
    references.retain(|reference| {
        let terminal = reference.name.rsplit('.').next().unwrap_or(&reference.name);
        let key = (reference.line, terminal.to_string());
        let declaration_shaped =
            declared_name_in_snippet(&reference.snippet).as_deref() == Some(terminal);
        if declaration_shaped
            && let Some(count) = remaining.get_mut(&key)
            && *count > 0
        {
            *count -= 1;
            return false;
        }
        true
    });
}

fn collect_typed_binding(
    extractor: &mut SymbolExtractor<'_>,
    node: Node,
    source: &str,
    binding: Option<(String, String)>,
    owner_type: Option<String>,
    declaration_occurrences: &mut HashMap<(usize, String), usize>,
) {
    let Some((name, value_type)) = binding else {
        return;
    };
    record_declaration_occurrence(declaration_occurrences, node, source, &name);
    extractor.definitions.push(SymbolDefinition {
        id: extractor.next_id,
        name,
        kind: SymbolKind::Variable,
        start_line: node.start_position().row + 1,
        end_line: binding_scope_end(node, source),
        is_exported: false,
        owner_type,
        receiver_type: None,
        value_type: Some(value_type),
    });
    extractor.next_id += 1;
}

fn collect_definition(
    extractor: &mut SymbolExtractor<'_>,
    node: Node,
    source: &str,
    kind: SymbolKind,
    owner_type: Option<String>,
    is_exported: bool,
    declaration_occurrences: &mut HashMap<(usize, String), usize>,
) {
    let Some(name) = name_for_node(node, source) else {
        return;
    };
    record_declaration_occurrence(declaration_occurrences, node, source, &name);
    extractor.definitions.push(SymbolDefinition {
        id: extractor.next_id,
        name,
        kind,
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
        is_exported,
        owner_type,
        receiver_type: None,
        value_type: None,
    });
    extractor.next_id += 1;
}

fn collect_imports(extractor: &mut SymbolExtractor<'_>) {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    for line in source.lines() {
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        if let Some(package_name) = trimmed.strip_prefix("package ") {
            extractor.modules.push(ModuleRecord {
                local_name: package_name.trim().trim_end_matches(';').to_string(),
                source_path: None,
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let imported = rest.trim().trim_end_matches(';');
            let (path, alias) = imported
                .split_once(" as ")
                .map(|(path, alias)| (path.trim(), Some(alias.trim())))
                .unwrap_or((imported, None));
            let (source_module, imported_name) = if let Some(package) = path.strip_suffix(".*") {
                (package.to_string(), "*".to_string())
            } else {
                path.rsplit_once('.')
                    .map(|(package, symbol)| (package.to_string(), symbol.to_string()))
                    .unwrap_or_else(|| (String::new(), path.to_string()))
            };
            let local_name = alias.unwrap_or(&imported_name).to_string();
            extractor.imports.push(ImportRecord {
                local_name,
                source_module,
                imported_name,
            });
        }
    }
}

fn visit_node(
    extractor: &mut SymbolExtractor<'_>,
    node: Node,
    source: &str,
    owner_stack: &mut Vec<(String, bool)>,
    function_ranges: &mut Vec<(usize, usize)>,
    declaration_occurrences: &mut HashMap<(usize, String), usize>,
) {
    match node.kind() {
        "class_declaration"
        | "object_declaration"
        | "interface_declaration"
        | "enum_class_declaration"
        | "fun_interface_declaration" => {
            let owner = name_for_node(node, source);
            let is_exported = super::declaration_is_repository_external(node, source)
                && owner_stack
                    .last()
                    .is_none_or(|(_, is_external)| *is_external);
            collect_definition(
                extractor,
                node,
                source,
                SymbolKind::Class,
                None,
                is_exported,
                declaration_occurrences,
            );
            if let Some(owner) = owner {
                owner_stack.push((owner, is_exported));
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    visit_node(
                        extractor,
                        child,
                        source,
                        owner_stack,
                        function_ranges,
                        declaration_occurrences,
                    );
                }
                owner_stack.pop();
                return;
            }
        }
        "function_declaration" => {
            let name = match name_for_node(node, source) {
                Some(name) => name,
                None => return,
            };
            let source_text = node_text(node, source).unwrap_or("").to_string();
            let owner_type = owner_stack.last().map(|(owner, _)| owner.clone());
            let receiver_type = kotlin_receiver_type(node, source);
            let is_exported = super::declaration_is_repository_external(node, source)
                && owner_stack
                    .last()
                    .is_none_or(|(_, is_external)| *is_external);
            record_declaration_occurrence(declaration_occurrences, node, source, &name);
            extractor.definitions.push(SymbolDefinition {
                id: extractor.next_id,
                name: name.clone(),
                kind: if owner_type.is_some() || receiver_type.is_some() {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                },
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                is_exported,
                owner_type,
                receiver_type,
                value_type: kotlin_function_return_type(node, source),
            });
            extractor.next_id += 1;
            let mut declaration_removed = false;
            for (offset, snippet, mut references) in super::refs::collect_source_refs(&source_text)
            {
                if !declaration_removed
                    && snippet.contains("fun ")
                    && let Some(declaration) = references
                        .iter()
                        .position(|reference| reference.rsplit('.').next() == Some(name.as_str()))
                {
                    references.remove(declaration);
                    declaration_removed = true;
                }
                for r in references {
                    extractor.references.push(SymbolReference {
                        name: r,
                        line: node.start_position().row + offset + 1,
                        snippet: snippet.clone(),
                        is_member_call: false,
                        is_callable_value: false,
                        resolved_symbol: None,
                    });
                }
            }
            function_ranges.push((node.start_position().row, node.end_position().row));
        }
        "function_value_parameters" => {
            collect_default_parameter_lambda_parameters(extractor, node, source);
        }
        "property_declaration" => {
            collect_typed_binding(
                extractor,
                node,
                source,
                kotlin_property_binding(node, source),
                owner_stack.last().map(|(owner, _)| owner.clone()),
                declaration_occurrences,
            );
            collect_owned_typed_lambda_parameters(extractor, node, source);
        }
        "parameter" => {
            collect_typed_binding(
                extractor,
                node,
                source,
                kotlin_parameter_binding(node, source),
                None,
                declaration_occurrences,
            );
        }
        "class_parameter" => {
            let owner_type = node_text(node, source)
                .is_some_and(|text| text.contains("val ") || text.contains("var "))
                .then(|| owner_stack.last().map(|(owner, _)| owner.clone()))
                .flatten();
            collect_typed_binding(
                extractor,
                node,
                source,
                kotlin_parameter_binding(node, source),
                owner_type,
                declaration_occurrences,
            );
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(
            extractor,
            child,
            source,
            owner_stack,
            function_ranges,
            declaration_occurrences,
        );
    }
}

pub(crate) fn scan_kotlin_defs_and_imports(
    extractor: &mut SymbolExtractor<'_>,
) -> Vec<(usize, usize)> {
    let source = String::from_utf8_lossy(extractor.source_bytes).into_owned();
    collect_imports(extractor);
    let mut ranges = Vec::new();
    let mut declaration_occurrences = HashMap::<(usize, String), usize>::new();
    if let Some(tree) = super::super::get_parser(extractor.adapter)
        .and_then(|mut parser| parser.parse(extractor.source_bytes, None))
    {
        let mut owner_stack = Vec::new();
        visit_node(
            extractor,
            tree.root_node(),
            &source,
            &mut owner_stack,
            &mut ranges,
            &mut declaration_occurrences,
        );
    }
    remove_precollected_declaration_references(&mut extractor.references, &declaration_occurrences);
    let mut known_references = extractor
        .references
        .iter()
        .map(|reference| (reference.line, reference.name.clone()))
        .collect::<HashSet<_>>();
    for (offset, snippet, references) in super::refs::collect_source_refs(&source) {
        let line = offset + 1;
        for reference in references {
            let terminal = reference.rsplit('.').next().unwrap_or(&reference);
            let declaration_key = (line, terminal.to_string());
            let declaration_shaped =
                declared_name_in_snippet(&snippet).as_deref() == Some(terminal);
            if declaration_shaped
                && let Some(remaining) = declaration_occurrences.get_mut(&declaration_key)
                && *remaining > 0
            {
                *remaining -= 1;
                continue;
            }
            if !known_references.insert((line, reference.clone())) {
                continue;
            }
            extractor.references.push(SymbolReference {
                name: reference,
                line,
                snippet: snippet.clone(),
                is_member_call: false,
                is_callable_value: false,
                resolved_symbol: None,
            });
        }
    }
    let _ = &extractor.adapter;
    let _ = &extractor.language;
    ranges
}
