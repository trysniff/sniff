use super::*;

fn is_python_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[derive(Debug)]
struct PythonParameter {
    name: String,
    caller_position: Option<usize>,
}

fn split_python_top_level(value: &str, delimiter: char) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            _ if ch == delimiter && depth == 0 => {
                parts.push(value[start..index].trim().to_string());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() || depth != 0 {
        return None;
    }
    parts.push(value[start..].trim().to_string());
    Some(parts)
}

fn matching_parenthesis(value: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, ch) in value[open..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn top_level_prefix(value: &str, delimiter: char) -> Option<&str> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            _ if ch == delimiter && depth == 0 => return Some(value[..index].trim()),
            _ => {}
        }
    }
    Some(value.trim())
}

fn python_signature(method: &MethodRecord) -> Option<(&str, usize, usize)> {
    let def = method.source.find("def ")?;
    let open = method.source[def..].find('(')? + def;
    let close = matching_parenthesis(&method.source, open)?;
    Some((&method.source[open + 1..close], open, close))
}

fn python_parameters(method: &MethodRecord) -> Option<Vec<PythonParameter>> {
    let (signature, _, _) = python_signature(method)?;
    let mut caller_position = 0usize;
    let mut keyword_only = false;
    let mut parameters = Vec::new();
    for raw in split_python_top_level(signature, ',')? {
        let raw = raw.trim();
        if raw.is_empty() || raw == "/" {
            continue;
        }
        if raw == "*" {
            keyword_only = true;
            continue;
        }
        if raw.starts_with("**") {
            parameters.push(PythonParameter {
                name: raw
                    .trim_start_matches('*')
                    .split([':', '='])
                    .next()?
                    .trim()
                    .to_string(),
                caller_position: None,
            });
            continue;
        }
        if raw.starts_with('*') {
            keyword_only = true;
            parameters.push(PythonParameter {
                name: raw
                    .trim_start_matches('*')
                    .split([':', '='])
                    .next()?
                    .trim()
                    .to_string(),
                caller_position: None,
            });
            continue;
        }
        let without_default = top_level_prefix(raw, '=')?;
        let name = top_level_prefix(without_default, ':')?.trim();
        if !is_python_identifier(name) {
            return None;
        }
        let implicit_receiver = parameters.is_empty() && matches!(name, "self" | "cls");
        let position = (!implicit_receiver && !keyword_only).then_some(caller_position);
        if !implicit_receiver && !keyword_only {
            caller_position += 1;
        }
        parameters.push(PythonParameter {
            name: name.to_string(),
            caller_position: position,
        });
    }
    Some(parameters)
}

fn python_parameter_discard_names(method: &MethodRecord) -> Option<Vec<String>> {
    if !method.language.eq_ignore_ascii_case("python") {
        return None;
    }
    let lines = method.source.lines().collect::<Vec<_>>();
    for (start, line) in lines.iter().enumerate() {
        let Some(mut remainder) = line.trim_start().strip_prefix("_ = (") else {
            continue;
        };
        let mut names = Vec::new();
        let mut end = start;
        loop {
            let (content, closed) = remainder
                .split_once(')')
                .map_or((remainder, false), |(before, _)| (before, true));
            for value in content
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if !is_python_identifier(value) {
                    return None;
                }
                names.push(value.to_string());
            }
            if closed {
                names.sort();
                names.dedup();
                return (!names.is_empty()).then_some(names);
            }
            end += 1;
            remainder = *lines.get(end)?;
        }
    }
    None
}

fn discarded_parameters_have_no_other_reads(method: &MethodRecord, names: &[String]) -> bool {
    let Some((_, _, close)) = python_signature(method) else {
        return false;
    };
    let Some(block) = python_parameter_discard_block(method) else {
        return false;
    };
    let body = method.source[close + 1..].replacen(&block, "", 1);
    names.iter().all(|name| !contains_identifier(&body, name))
}

fn python_call_arguments(snippet: &str, method_name: &str) -> Option<Vec<String>> {
    let mut search = 0usize;
    while let Some(relative) = snippet[search..].find(method_name) {
        let name_start = search + relative;
        let name_end = name_start + method_name.len();
        let before_ok = snippet[..name_start]
            .chars()
            .next_back()
            .is_none_or(|ch| ch != '_' && !ch.is_ascii_alphanumeric());
        let after_ok = snippet[name_end..]
            .chars()
            .next()
            .is_none_or(|ch| ch != '_' && !ch.is_ascii_alphanumeric());
        if before_ok && after_ok {
            let whitespace = snippet[name_end..]
                .find(|ch: char| !ch.is_whitespace())
                .unwrap_or(snippet.len() - name_end);
            let open = name_end + whitespace;
            if snippet.as_bytes().get(open) == Some(&b'(') {
                let close = matching_parenthesis(snippet, open)?;
                return split_python_top_level(&snippet[open + 1..close], ',');
            }
        }
        search = name_end;
    }
    None
}

fn removable_python_argument(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.starts_with('*') {
        return false;
    }
    if is_python_identifier(value)
        || matches!(value, "None" | "True" | "False" | "..." | "object()")
    {
        return true;
    }
    if value.parse::<f64>().is_ok() {
        return true;
    }
    let quoted = (value.starts_with('\'') && value.ends_with('\''))
        || (value.starts_with('"') && value.ends_with('"'));
    quoted && value.len() >= 2
}

fn caller_supplies_removable_parameters(
    reference: &Reference,
    method_name: &str,
    discarded: &[&PythonParameter],
) -> bool {
    let Some(arguments) = python_call_arguments(&reference.snippet, method_name) else {
        return false;
    };
    let mut positional = Vec::new();
    let mut keywords = std::collections::HashMap::new();
    for argument in arguments {
        if argument.starts_with('*') {
            return false;
        }
        let prefix = top_level_prefix(&argument, '=');
        if let Some(name) = prefix.filter(|prefix| *prefix != argument.trim()) {
            if !is_python_identifier(name) {
                return false;
            }
            let value = argument[name.len() + 1..].trim();
            keywords.insert(name.to_string(), value.to_string());
        } else {
            positional.push(argument);
        }
    }
    discarded.iter().all(|parameter| {
        keywords
            .get(&parameter.name)
            .is_some_and(|value| removable_python_argument(value))
            || parameter
                .caller_position
                .and_then(|position| positional.get(position))
                .is_some_and(|value| removable_python_argument(value))
    })
}

pub(super) fn python_stale_discard_signature_proof(
    method: &MethodRecord,
) -> Option<StaleDiscardSignatureProof> {
    let discarded_names = python_parameter_discard_names(method)?;
    let parameters = python_parameters(method)?;
    let discarded = discarded_names
        .iter()
        .map(|name| parameters.iter().find(|parameter| parameter.name == *name))
        .collect::<Option<Vec<_>>>()?;
    if discarded
        .iter()
        .any(|parameter| parameter.caller_position.is_none())
        || !discarded_parameters_have_no_other_reads(method, &discarded_names)
        || method.references.is_empty()
        || !method.references.iter().all(|reference| {
            caller_supplies_removable_parameters(reference, &method.name, &discarded)
        })
    {
        return None;
    }
    Some(StaleDiscardSignatureProof {
        discarded_parameters: discarded_names,
        caller_sites: method
            .references
            .iter()
            .map(|reference| {
                format!(
                    "{}:{}: {}",
                    reference.file_path, reference.line, reference.snippet
                )
            })
            .collect(),
    })
}

pub(crate) fn python_parameter_discard_block(method: &MethodRecord) -> Option<String> {
    python_parameter_discard_names(method)?;
    let lines = method.source.lines().collect::<Vec<_>>();
    for (start, line) in lines.iter().enumerate() {
        let Some(mut remainder) = line.trim_start().strip_prefix("_ = (") else {
            continue;
        };
        let mut saw_identifier = false;
        let mut end = start;
        loop {
            let (content, closed) = remainder
                .split_once(')')
                .map_or((remainder, false), |(before, _)| (before, true));
            for value in content
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if !is_python_identifier(value) {
                    return None;
                }
                saw_identifier = true;
            }
            if closed {
                return saw_identifier.then(|| lines[start..=end].join("\n"));
            }
            end += 1;
            remainder = *lines.get(end)?;
        }
    }
    None
}

pub(crate) fn duplicated_branch_construct(method: &MethodRecord) -> Option<String> {
    if method.language == "python" {
        duplicated_python_branch(&method.source)
    } else {
        duplicated_brace_branch(&method.source)
    }
}

pub(crate) fn rejected_non_exhaustive_duplicate_branch(method: &MethodRecord) -> Option<String> {
    (method.language != "python")
        .then(|| non_exhaustive_duplicated_brace_branch(&method.source))
        .flatten()
}

fn duplicated_python_branch(source: &str) -> Option<String> {
    let lines = source.lines().collect::<Vec<_>>();
    for (start, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("if ") || !trimmed.ends_with(':') {
            continue;
        }
        let indent = leading_indent(line);
        let else_index = ((start + 1)..lines.len()).find(|index| {
            leading_indent(lines[*index]) == indent && lines[*index].trim() == "else:"
        });
        if else_index.is_none() {
            let tail_index = ((start + 1)..lines.len()).find(|index| {
                !lines[*index].trim().is_empty() && leading_indent(lines[*index]) <= indent
            });
            let Some(tail_index) = tail_index else {
                continue;
            };
            let branch_lines = lines[start + 1..tail_index]
                .iter()
                .map(|line| line.trim())
                .filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")
                })
                .collect::<Vec<_>>();
            let first_is_return = branch_lines.len() == 1 && branch_lines[0].starts_with("return ");
            let first = single_branch_statement(&lines[start + 1..tail_index]);
            let tail = normalize_branch_statement(lines[tail_index].trim());
            if first
                .as_deref()
                .is_some_and(|statement| first_is_return && statement == tail)
            {
                return Some(lines[start..=tail_index].join("\n"));
            }
            continue;
        }
        let else_index = else_index.expect("checked above");
        let first = single_branch_statement(&lines[start + 1..else_index]);
        let end = ((else_index + 1)..lines.len())
            .find(|index| {
                !lines[*index].trim().is_empty() && leading_indent(lines[*index]) <= indent
            })
            .unwrap_or(lines.len());
        let second = single_branch_statement(&lines[else_index + 1..end]);
        if first.is_some() && first == second {
            return Some(lines[start..end].join("\n"));
        }
    }
    None
}

fn duplicated_brace_branch(source: &str) -> Option<String> {
    let lines = source.lines().collect::<Vec<_>>();
    for (start, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(inline) = duplicated_inline_branch(trimmed) {
            return Some(inline.to_string());
        }
        if !trimmed.starts_with("if ") || !trimmed.contains('{') {
            continue;
        }
        let Some(else_index) = ((start + 1)..lines.len()).find(|index| {
            let candidate = lines[*index].trim();
            let Some((_, after_else)) = candidate.split_once("else") else {
                return false;
            };
            after_else.trim_start().starts_with('{')
        }) else {
            continue;
        };
        let first = single_branch_statement(&lines[start + 1..else_index]);
        let Some(end) =
            ((else_index + 1)..lines.len()).find(|index| lines[*index].trim().starts_with('}'))
        else {
            continue;
        };
        let second = single_branch_statement(&lines[else_index + 1..end]);
        if first.is_some() && first == second {
            return Some(lines[start..=end].join("\n"));
        }
    }
    None
}

fn non_exhaustive_duplicated_brace_branch(source: &str) -> Option<String> {
    let lines = source.lines().collect::<Vec<_>>();
    for (start, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("if ") || !trimmed.contains('{') {
            continue;
        }
        let Some(else_if_index) = ((start + 1)..lines.len()).find(|index| {
            let candidate = lines[*index].trim();
            candidate
                .split_once("else")
                .is_some_and(|(_, after_else)| after_else.trim_start().starts_with("if "))
        }) else {
            continue;
        };
        let first = single_branch_statement(&lines[start + 1..else_if_index]);
        let Some(end) =
            ((else_if_index + 1)..lines.len()).find(|index| lines[*index].trim().starts_with('}'))
        else {
            continue;
        };
        let second = single_branch_statement(&lines[else_if_index + 1..end]);
        if first.is_some() && first == second {
            return Some(lines[start..=end].join("\n"));
        }
    }
    None
}

fn duplicated_inline_branch(line: &str) -> Option<&str> {
    let else_index = line.find(" else ")?;
    let before_else = &line[..else_index];
    if !before_else.contains("if (") {
        return None;
    }
    let condition_end = before_else.rfind(')')?;
    let first = normalize_branch_statement(&before_else[condition_end + 1..]);
    let second = normalize_branch_statement(&line[else_index + " else ".len()..]);
    (!first.is_empty() && first == second).then_some(line)
}

fn single_branch_statement(lines: &[&str]) -> Option<String> {
    let statements = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with('#'))
        .map(normalize_branch_statement)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    (statements.len() == 1).then(|| statements[0].clone())
}

fn normalize_branch_statement(statement: &str) -> String {
    statement
        .trim()
        .strip_prefix("return ")
        .unwrap_or(statement.trim())
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

pub(super) fn is_lexical_call_site(line: &str, method_name: &str) -> bool {
    identifier_matches(line, method_name).any(|end| line[end..].trim_start().starts_with('('))
}
