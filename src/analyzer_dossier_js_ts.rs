use super::*;

#[derive(Clone, Copy)]
enum JsLexState {
    Code,
    SingleQuote,
    DoubleQuote,
    Template,
    LineComment,
    BlockComment,
    Regex,
    RegexClass,
}

fn regex_can_start(masked: &[u8]) -> bool {
    let Some((index, previous)) = masked
        .iter()
        .enumerate()
        .rev()
        .find(|(_, byte)| !byte.is_ascii_whitespace())
    else {
        return true;
    };
    if matches!(
        previous,
        b'(' | b'[' | b'{' | b'=' | b':' | b',' | b';' | b'!' | b'?' | b'&' | b'|'
    ) {
        return true;
    }
    if !previous.is_ascii_alphabetic() {
        return false;
    }
    let start = masked[..=index]
        .iter()
        .rposition(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        .map_or(0, |position| position + 1);
    matches!(
        &masked[start..=index],
        b"return" | b"case" | b"throw" | b"yield" | b"await" | b"typeof" | b"instanceof"
    )
}

fn mask_js_non_code(source: &str) -> Vec<u8> {
    let source = source.as_bytes();
    let mut masked = source.to_vec();
    let mut state = JsLexState::Code;
    let mut escaped = false;
    let mut index = 0;
    while index < source.len() {
        let byte = source[index];
        match state {
            JsLexState::Code => {
                if byte == b'/' && source.get(index + 1) == Some(&b'/') {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = JsLexState::LineComment;
                    index += 2;
                    continue;
                }
                if byte == b'/' && source.get(index + 1) == Some(&b'*') {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = JsLexState::BlockComment;
                    index += 2;
                    continue;
                }
                state = match byte {
                    b'\'' => JsLexState::SingleQuote,
                    b'"' => JsLexState::DoubleQuote,
                    b'`' => JsLexState::Template,
                    b'/' if regex_can_start(&masked[..index]) => JsLexState::Regex,
                    _ => {
                        index += 1;
                        continue;
                    }
                };
                masked[index] = b' ';
            }
            JsLexState::LineComment => {
                if byte == b'\n' {
                    state = JsLexState::Code;
                } else {
                    masked[index] = b' ';
                }
            }
            JsLexState::BlockComment => {
                if byte == b'*' && source.get(index + 1) == Some(&b'/') {
                    masked[index] = b' ';
                    masked[index + 1] = b' ';
                    state = JsLexState::Code;
                    index += 2;
                    continue;
                }
                if byte != b'\n' {
                    masked[index] = b' ';
                }
            }
            JsLexState::SingleQuote
            | JsLexState::DoubleQuote
            | JsLexState::Template
            | JsLexState::Regex
            | JsLexState::RegexClass => {
                if byte != b'\n' {
                    masked[index] = b' ';
                }
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else {
                    state = match state {
                        JsLexState::SingleQuote if byte == b'\'' => JsLexState::Code,
                        JsLexState::DoubleQuote if byte == b'"' => JsLexState::Code,
                        JsLexState::Template if byte == b'`' => JsLexState::Code,
                        JsLexState::Regex if byte == b'[' => JsLexState::RegexClass,
                        JsLexState::Regex if byte == b'/' => JsLexState::Code,
                        JsLexState::RegexClass if byte == b']' => JsLexState::Regex,
                        JsLexState::SingleQuote | JsLexState::DoubleQuote | JsLexState::Regex
                            if byte == b'\n' =>
                        {
                            JsLexState::Code
                        }
                        current => current,
                    };
                }
            }
        }
        index += 1;
    }
    masked
}

fn returned_object_spans(source: &str) -> Vec<(usize, usize)> {
    let masked = mask_js_non_code(source);
    let mut spans = Vec::new();
    let mut index = 0;
    while index + "return".len() <= masked.len() {
        if &masked[index..index + "return".len()] != b"return"
            || index > 0 && is_identifier_char(masked[index - 1] as char)
            || masked
                .get(index + "return".len())
                .is_some_and(|byte| is_identifier_char(*byte as char))
        {
            index += 1;
            continue;
        }
        let mut open = index + "return".len();
        while masked
            .get(open)
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(')
        {
            open += 1;
        }
        if masked.get(open) != Some(&b'{') {
            index += "return".len();
            continue;
        }
        let mut depth = 0usize;
        let mut close = None;
        for (offset, byte) in masked[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        close = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(close) = close {
            spans.push((open, close));
            index = close + 1;
        } else {
            index += "return".len();
        }
    }
    spans
}

fn returned_member_factory<'a>(
    file: &'a FileRecord,
    method: &MethodRecord,
) -> Option<&'a MethodRecord> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") {
        return None;
    }
    let outer = file
        .methods
        .iter()
        .filter(|candidate| {
            candidate.start_line < method.start_line && method.end_line <= candidate.end_line
        })
        .min_by_key(|candidate| candidate.end_line.saturating_sub(candidate.start_line))?;
    let masked = mask_js_non_code(&outer.source);
    let masked = std::str::from_utf8(&masked).ok()?;
    for (open, close) in returned_object_spans(&outer.source) {
        let open_line =
            outer.start_line + outer.source[..open].bytes().filter(|b| *b == b'\n').count();
        let close_line = outer.start_line
            + outer.source[..=close]
                .bytes()
                .filter(|b| *b == b'\n')
                .count();
        let declared_in_object = open_line <= method.start_line && method.end_line <= close_line;
        let returned_by_name = method.end_line < open_line
            && contains_identifier(&masked[open + 1..close], &method.name);
        if declared_in_object || returned_by_name {
            return Some(outer);
        }
    }
    let relative_method_line = method.start_line.saturating_sub(outer.start_line);
    let outer_lines = outer.source.lines().collect::<Vec<_>>();
    for (return_index, line) in outer_lines.iter().enumerate().skip(relative_method_line) {
        let trimmed = line.trim().trim_end_matches(';');
        let Some(returned_name) = trimmed.strip_prefix("return ").map(str::trim) else {
            continue;
        };
        if returned_name.is_empty()
            || !returned_name.chars().all(is_identifier_char)
            || return_index <= relative_method_line
        {
            continue;
        }
        let declaration = outer_lines[..=relative_method_line]
            .iter()
            .rposition(|candidate| {
                let compact = candidate
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect::<String>();
                compact.contains(&format!("const{returned_name}:"))
                    || compact.contains(&format!("const{returned_name}="))
                    || compact.contains(&format!("let{returned_name}:"))
                    || compact.contains(&format!("let{returned_name}="))
            });
        if declaration.is_some() {
            return Some(outer);
        }
    }
    None
}

pub(super) fn externally_returned_member_evidence(
    file: &FileRecord,
    method: &MethodRecord,
) -> Option<String> {
    let outer =
        returned_member_factory(file, method).filter(|outer| has_external_visibility(outer))?;
    Some(format!(
        "{} returns this member through an externally visible object contract",
        outer.name
    ))
}

pub(super) fn returned_member_surface_entries(
    file: &FileRecord,
    method: &MethodRecord,
) -> Vec<(usize, String)> {
    let Some(factory) = returned_member_factory(file, method) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for (open, close) in returned_object_spans(&factory.source) {
        let open_line = factory.start_line
            + factory.source[..open]
                .bytes()
                .filter(|b| *b == b'\n')
                .count();
        let close_line = factory.start_line
            + factory.source[..=close]
                .bytes()
                .filter(|b| *b == b'\n')
                .count();
        for line_number in open_line..=close_line {
            if line_number <= method.end_line {
                continue;
            }
            let line = file
                .source
                .lines()
                .nth(line_number.saturating_sub(1))
                .unwrap_or_default();
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let entry = compact.trim_end_matches(',');
            let returns_method = entry == method.name
                || entry
                    .rsplit_once(':')
                    .is_some_and(|(_, value)| value == method.name);
            if returns_method {
                entries.push((line_number, line.trim().to_string()));
            }
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

pub(super) fn inline_object_is_implicit_return(file: &FileRecord, owner: &str) -> bool {
    let Some(line) = owner
        .strip_prefix("<object@")
        .and_then(|value| value.strip_suffix('>'))
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return false;
    };
    let compact = file
        .source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or_default()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    compact.contains("=>({") || compact.starts_with("return{")
}

pub(super) fn returned_member_usage_evidence(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let Some(factory) = returned_member_factory(file, method) else {
        return Vec::new();
    };
    let mut aliases = Vec::<(usize, String)>::new();
    let mut evidence = Vec::new();

    for (file_index, lines) in index.source_lines.iter().enumerate() {
        for (line_index, line) in lines.iter().enumerate() {
            let Some(call_end) = identifier_matches(line, &factory.name)
                .find(|end| line[*end..].trim_start().starts_with('('))
            else {
                continue;
            };
            let multiline_destructure_start = (line_index.saturating_sub(64)..=line_index)
                .rev()
                .find(|candidate| {
                    let compact = lines[*candidate]
                        .chars()
                        .filter(|character| !character.is_whitespace())
                        .collect::<String>();
                    ["const{", "let{", "var{"]
                        .iter()
                        .any(|prefix| compact.starts_with(prefix))
                });
            if let Some(start) = multiline_destructure_start {
                let declaration = lines[start..=line_index].join("\n");
                if declaration.split_once('=').is_some_and(|(left, right)| {
                    contains_identifier(left, &method.name)
                        && identifier_matches(right, &factory.name)
                            .any(|end| right[end..].trim_start().starts_with('('))
                }) {
                    evidence.push(format!(
                        "{}:{}: member `{}` is destructured from `{}` across lines {}-{}",
                        index.file_records[file_index].file_path,
                        start + 1,
                        method.name,
                        factory.name,
                        start + 1,
                        line_index + 1,
                    ));
                    continue;
                }
            }
            let Some((left, _)) = line[..call_end].split_once('=') else {
                continue;
            };
            if left.contains('{') && contains_identifier(left, &method.name) {
                evidence.push(format!(
                    "{}:{}: {}",
                    index.file_records[file_index].file_path,
                    line_index + 1,
                    line.trim()
                ));
                continue;
            }
            if left.contains('{') || left.contains('[') {
                continue;
            }
            let Some(alias) = left
                .rsplit(|character: char| !is_identifier_char(character))
                .find(|part| !part.is_empty())
            else {
                continue;
            };
            aliases.push((file_index, alias.to_string()));
        }
    }

    aliases.sort();
    aliases.dedup();
    let mut surface_aliases = aliases
        .iter()
        .map(|(_, alias)| alias.clone())
        .collect::<Vec<_>>();
    surface_aliases.extend(composed_factory_surface_aliases(&factory.name, index));
    surface_aliases.sort();
    surface_aliases.dedup();
    for alias in surface_aliases {
        let direct = format!("{alias}.{}", method.name);
        let optional = format!("{alias}?.{}", method.name);
        let quoted_single = format!("{alias}['{}']", method.name);
        let quoted_double = format!("{alias}[\"{}\"]", method.name);
        for location in index.source_locations(&method.name) {
            let file_index = location.file_index;
            let line = index.source_lines[file_index][location.line_index];
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if [
                direct.as_str(),
                optional.as_str(),
                quoted_single.as_str(),
                quoted_double.as_str(),
            ]
            .iter()
            .any(|pattern| compact.contains(pattern))
                || (contains_identifier(line, &alias)
                    && compact.contains(&format!(".{}", method.name)))
            {
                evidence.push(format!(
                    "{}:{}: {}",
                    index.file_records[file_index].file_path,
                    location.line_index + 1,
                    index.source_lines[file_index][location.line_index].trim()
                ));
                continue;
            }

            let window_start = location.line_index.saturating_sub(16);
            let window_end = (location.line_index + 17).min(index.source_lines[file_index].len());
            let window = index.source_lines[file_index][window_start..window_end].join("\n");
            let compact_window = window
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            let destructured = compact_window.contains(&format!("{{{}", method.name))
                || compact_window.contains(&format!(",{}", method.name));
            let from_alias = compact_window.contains(&format!("}}={alias}"));
            if destructured && from_alias {
                evidence.push(format!(
                    "{}:{}: member `{}` is destructured from factory-result alias `{alias}`",
                    index.file_records[file_index].file_path,
                    location.line_index + 1,
                    method.name,
                ));
            }
        }
    }

    evidence.sort();
    evidence.dedup();
    evidence
}

fn commonjs_imported_callable_alias(
    file_index: usize,
    target: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let mut aliases = Vec::new();
    let lines = &index.source_lines[file_index];
    for (require_line, line) in lines.iter().enumerate() {
        let Some(module) = quoted_require(line) else {
            continue;
        };
        if !dynamic_import_targets_file(module, &target.file_path) {
            continue;
        }
        let declaration_start = (require_line.saturating_sub(16)..=require_line)
            .rev()
            .find(|line| contains_any(lines[*line], &["const ", "let ", "var "]))
            .unwrap_or(require_line);
        let declaration = lines[declaration_start..=require_line].join("\n");
        if !contains_identifier(&declaration, &target.name) {
            continue;
        }
        let compact = declaration
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        if compact.contains(&format!(".{}", target.name)) {
            if let Some(alias) = assignment_alias(&declaration) {
                aliases.push(alias);
            }
            continue;
        }
        let Some(name_end) = identifier_matches(&compact, &target.name).next() else {
            continue;
        };
        let suffix = &compact[name_end..];
        if let Some(alias) = suffix.strip_prefix(':').and_then(|suffix| {
            suffix
                .split(|character: char| !is_identifier_char(character))
                .find(|part| !part.is_empty())
        }) {
            aliases.push(alias.to_string());
        } else {
            aliases.push(target.name.clone());
        }
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

fn resolved_callable_aliases(
    target: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<(usize, String)> {
    let target_definition_id = index
        .graph
        .files
        .get(&target.file_path)
        .and_then(|symbols| {
            symbols
                .definitions
                .iter()
                .find(|definition| {
                    definition.name == target.name
                        && definition.start_line <= target.start_line
                        && target.end_line <= definition.end_line
                })
                .map(|definition| definition.id)
        });
    let mut aliases = Vec::new();
    for (file_index, candidate) in index.file_records.iter().enumerate() {
        if candidate.file_path.eq_ignore_ascii_case(&target.file_path) {
            aliases.push((file_index, target.name.clone()));
        }
        if let Some(symbols) = index.graph.files.get(&candidate.file_path) {
            for (import_index, import) in symbols.imports.iter().enumerate() {
                if import.imported_name == target.name
                    && target_definition_id.is_some_and(|definition_id| {
                        index.graph.import_targets_definition(
                            &candidate.file_path,
                            import_index,
                            &target.file_path,
                            definition_id,
                        )
                    })
                {
                    aliases.push((file_index, import.local_name.clone()));
                }
            }
        }
        aliases.extend(
            commonjs_imported_callable_alias(file_index, target, index)
                .into_iter()
                .map(|alias| (file_index, alias)),
        );
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

fn assigned_factory_result_aliases(
    factory: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<(usize, String)> {
    let mut result_aliases = Vec::new();
    for (file_index, callable_alias) in resolved_callable_aliases(factory, index) {
        for line in &index.source_lines[file_index] {
            let Some(call_end) = identifier_matches(line, &callable_alias)
                .find(|end| line[*end..].trim_start().starts_with('('))
            else {
                continue;
            };
            let Some(alias) = assignment_alias(&line[..call_end]) else {
                continue;
            };
            result_aliases.push((file_index, alias));
        }
    }
    result_aliases.sort();
    result_aliases.dedup();
    result_aliases
}

pub(super) fn factory_constructed_class_member_usage_evidence(
    file: &FileRecord,
    method: &MethodRecord,
    owner: &str,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") || owner.starts_with('<') {
        return Vec::new();
    }

    let constructor = format!("new{owner}(");
    let constructor_factories = file.methods.iter().filter(|candidate| {
        candidate.start_line != method.start_line
            && candidate
                .source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .contains(&constructor)
    });
    let mut evidence = Vec::new();

    for constructor_factory in constructor_factories {
        let Some(outer_factory) = returned_member_factory(file, constructor_factory) else {
            continue;
        };
        for (file_index, surface_alias) in assigned_factory_result_aliases(outer_factory, index) {
            let constructed_call = format!("{surface_alias}.{}(", constructor_factory.name);
            let mut instance_aliases = Vec::new();
            for line in &index.source_lines[file_index] {
                let compact = line
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect::<String>();
                let Some(call_start) = compact.find(&constructed_call) else {
                    continue;
                };
                if call_start == 0 {
                    continue;
                }
                let Some(alias) = assignment_alias(line) else {
                    continue;
                };
                instance_aliases.push(alias);
            }

            for instance_alias in instance_aliases {
                let invocation = format!("{instance_alias}.{}(", method.name);
                for location in index.source_locations(&method.name) {
                    if location.file_index != file_index {
                        continue;
                    }
                    let line = index.source_lines[file_index][location.line_index];
                    let compact = line
                        .chars()
                        .filter(|character| !character.is_whitespace())
                        .collect::<String>();
                    if compact.contains(&invocation) {
                        evidence.push(format!(
                            "{}:{}: `{}` is constructed through `{}.{}` and invokes `{}`: {}",
                            index.file_records[file_index].file_path,
                            location.line_index + 1,
                            instance_alias,
                            surface_alias,
                            constructor_factory.name,
                            method.name,
                            line.trim(),
                        ));
                    }
                }
            }
        }
    }

    evidence.sort();
    evidence.dedup();
    evidence
}

fn assignment_alias(line: &str) -> Option<String> {
    let (left, _) = line.split_once('=')?;
    if !contains_any(left, &["const ", "let ", "var "]) {
        return None;
    }
    left.rsplit(|character: char| !is_identifier_char(character))
        .find(|part| !part.is_empty())
        .map(str::to_string)
}

fn nearest_assignment_alias(lines: &[&str], line_index: usize) -> Option<String> {
    let start = line_index.saturating_sub(96);
    lines[start..=line_index]
        .iter()
        .rev()
        .find_map(|line| assignment_alias(line))
}

fn composed_factory_surface_aliases(
    factory_name: &str,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let mut aliases = Vec::new();
    for location in index.source_locations(factory_name) {
        let line = index.source_lines[location.file_index][location.line_index];
        let compact = line
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        if !compact.contains(&format!("...{factory_name}(")) {
            continue;
        }
        if let Some(alias) = nearest_assignment_alias(
            &index.source_lines[location.file_index],
            location.line_index,
        ) {
            aliases.push(alias);
        }
    }
    aliases
}

pub(super) fn inline_object_surface_usage_evidence(
    file: &FileRecord,
    owner: &str,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let Some(owner_line) = owner
        .strip_prefix("<object@")
        .and_then(|value| value.strip_suffix('>'))
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return Vec::new();
    };
    let Some(file_index) = index
        .file_records
        .iter()
        .position(|candidate| candidate.file_path == file.file_path)
    else {
        return Vec::new();
    };
    let Some(alias) = nearest_assignment_alias(
        &index.source_lines[file_index],
        owner_line.saturating_sub(1),
    ) else {
        return Vec::new();
    };

    let mut evidence = Vec::new();
    for location in index.source_locations(&method.name) {
        if location.file_index == file_index && location.line_index + 1 == method.start_line {
            continue;
        }
        let line = index.source_lines[location.file_index][location.line_index];
        let compact = line
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let same_line_consumer = contains_identifier(line, &alias)
            && (compact.contains(&format!(".{}", method.name))
                || compact.contains(&format!("{{{}", method.name))
                || compact.contains(&format!(",{}", method.name)));

        let window_start = location.line_index.saturating_sub(16);
        let window_end =
            (location.line_index + 17).min(index.source_lines[location.file_index].len());
        let compact_window = index.source_lines[location.file_index][window_start..window_end]
            .join("\n")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let multiline_destructure = (compact_window.contains(&format!("{{{}", method.name))
            || compact_window.contains(&format!(",{}", method.name)))
            && compact_window.contains(&format!("}}={alias}"));

        if same_line_consumer || multiline_destructure {
            evidence.push(format!(
                "{}:{}: {}",
                index.file_records[location.file_index].file_path,
                location.line_index + 1,
                line.trim(),
            ));
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

pub(super) fn class_contract_evidence(file: &FileRecord, owner: &str) -> Option<String> {
    if owner.starts_with('<') {
        return None;
    }
    file.source.lines().find_map(|line| {
        let compact = line
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let class = format!("class{owner}");
        if !compact.contains(&class)
            || !compact.contains("extends") && !compact.contains("implements")
        {
            return None;
        }
        Some(format!("class protocol declaration: {}", line.trim()))
    })
}

pub(super) fn private_js_ts_surface_declaration_evidence(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") {
        return Vec::new();
    }
    let Some(file_index) = index
        .file_records
        .iter()
        .position(|candidate| candidate.file_path == file.file_path)
    else {
        return Vec::new();
    };
    let mut evidence = Vec::new();
    for location in index.source_locations(&method.name) {
        if location.file_index != file_index
            || method.start_line <= location.line_index + 1 && location.line_index < method.end_line
        {
            continue;
        }
        let line = index.source_lines[file_index][location.line_index];
        let trimmed = line.trim();
        let compact = trimmed
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let typed_property = compact.starts_with(&format!("{}:", method.name))
            && compact.contains("=>")
            && !compact.ends_with(',')
            && !compact
                .split_once("=>")
                .is_some_and(|(_, body)| body.contains('{'));
        let typed_method = compact.starts_with(&format!("{}(", method.name))
            && !compact.contains('{')
            && !compact.ends_with(',');
        if typed_property || typed_method {
            evidence.push(format!(
                "{}:{}: {}",
                file.file_path,
                location.line_index + 1,
                trimmed,
            ));
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

pub(super) fn js_ts_owner_invocation_evidence(
    method: &MethodRecord,
    owner: Option<&str>,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") {
        return Vec::new();
    }
    let Some(owner) = owner.filter(|owner| !owner.starts_with('<')) else {
        return Vec::new();
    };
    let mut evidence = Vec::new();
    if method.name == "constructor" {
        let constructor = format!("new{owner}(");
        for location in index.source_locations(owner) {
            let line = index.source_lines[location.file_index][location.line_index];
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if compact.contains(&constructor) {
                evidence.push(format!(
                    "{}:{}: {}",
                    index.file_records[location.file_index].file_path,
                    location.line_index + 1,
                    line.trim(),
                ));
            }
        }
    } else {
        let invocation = format!(".{}(", method.name);
        for location in index.source_locations(&method.name) {
            let line = index.source_lines[location.file_index][location.line_index];
            let compact = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if compact.contains(owner) && compact.contains(&invocation) {
                evidence.push(format!(
                    "{}:{}: {}",
                    index.file_records[location.file_index].file_path,
                    location.line_index + 1,
                    line.trim(),
                ));
            }
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

fn quoted_dynamic_import(line: &str) -> Option<&str> {
    let (_, after_import) = line.split_once("import(")?;
    let after_import = after_import.trim_start();
    let quote = after_import.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    after_import[quote.len_utf8()..]
        .split_once(quote)
        .map(|(path, _)| path)
}

fn dynamic_import_targets_file(module: &str, target_file: &str) -> bool {
    let target = target_file.replace('\\', "/").to_lowercase();
    let target_without_extension = target
        .rsplit_once('.')
        .map(|(path, _)| path)
        .unwrap_or(&target);
    let module = module.replace('\\', "/").to_lowercase();
    if let Some(alias_path) = module.strip_prefix("@/") {
        return target_without_extension.ends_with(&format!("/src/{alias_path}"));
    }
    let module = module.trim_start_matches("./").trim_start_matches("../");
    let module = [".tsx", ".ts", ".jsx", ".js"]
        .into_iter()
        .find_map(|extension| module.strip_suffix(extension))
        .unwrap_or(module);
    target_without_extension == module || target_without_extension.ends_with(&format!("/{module}"))
}

pub(super) fn dynamic_import_evidence(
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") {
        return Vec::new();
    }
    let mut evidence = Vec::new();
    for location in index.source_locations(&method.name) {
        let line = index.source_lines[location.file_index][location.line_index];
        let Some(module) = quoted_dynamic_import(line) else {
            continue;
        };
        if !contains_identifier(line, &method.name)
            || !dynamic_import_targets_file(module, &method.file_path)
        {
            continue;
        }
        evidence.push(format!(
            "{}:{}: {}",
            index.file_records[location.file_index].file_path,
            location.line_index + 1,
            line.trim(),
        ));
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

fn quoted_require(line: &str) -> Option<&str> {
    let (_, after_require) = line.split_once("require(")?;
    let after_require = after_require.trim_start();
    let quote = after_require.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    after_require[quote.len_utf8()..]
        .split_once(quote)
        .map(|(path, _)| path)
}

pub(super) fn commonjs_require_evidence(
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    if !matches!(method.language.as_str(), "javascript" | "typescript") {
        return Vec::new();
    }
    let mut evidence = Vec::new();
    for location in index.source_locations(&method.name) {
        let candidate = &index.file_records[location.file_index];
        if candidate.file_path == method.file_path {
            continue;
        }
        let lines = &index.source_lines[location.file_index];
        let window_start = location.line_index.saturating_sub(16);
        let window_end = (location.line_index + 17).min(lines.len());
        for require_line in window_start..window_end {
            let Some(module) = quoted_require(lines[require_line]) else {
                continue;
            };
            if !dynamic_import_targets_file(module, &method.file_path) {
                continue;
            }
            let declaration_start = (window_start..=require_line)
                .rev()
                .find(|line| contains_any(lines[*line], &["const {", "let {", "var {"]))
                .unwrap_or(require_line);
            let declaration = lines[declaration_start..=require_line].join("\n");
            let direct_member = lines[require_line].contains(&format!(".{}", method.name));
            if !contains_identifier(&declaration, &method.name) && !direct_member {
                continue;
            }
            evidence.push(format!(
                "{}:{}: CommonJS import of `{}` includes `{}`",
                candidate.file_path,
                require_line + 1,
                module,
                method.name,
            ));
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

#[path = "analyzer_dossier_js_ts_contracts.rs"]
mod contracts;
#[cfg(test)]
pub(super) use contracts::external_call_line_spans;
pub(super) use contracts::{
    external_framework_contract_evidence, external_object_escape_evidence,
    file_content_test_contract_evidence, file_test_contract_evidence, object_enumeration_evidence,
    object_enumeration_invocation_proof,
};
