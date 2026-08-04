use super::*;

fn is_external_js_ts_module(source_module: &str) -> bool {
    !source_module.starts_with('.')
        && !source_module.starts_with('/')
        && !source_module.starts_with("@/")
}

fn matching_call_end(masked: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in masked[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn external_call_line_spans(
    file: &FileRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<(usize, usize, String)> {
    let Some(symbols) = index.graph.files.get(&file.file_path) else {
        return Vec::new();
    };
    let names = symbols
        .imports
        .iter()
        .filter(|import| is_external_js_ts_module(&import.source_module))
        .map(|import| import.local_name.as_str())
        .collect::<HashSet<_>>();
    let masked = mask_js_non_code(&file.source);
    let masked_text = std::str::from_utf8(&masked).unwrap_or_default();
    let mut spans = Vec::new();
    for name in names {
        for end in identifier_matches(masked_text, name) {
            let mut open = end;
            while masked
                .get(open)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                open += 1;
            }
            while masked.get(open) == Some(&b'.') {
                open += 1;
                while masked
                    .get(open)
                    .is_some_and(|byte| byte.is_ascii_whitespace())
                {
                    open += 1;
                }
                let member_start = open;
                while masked
                    .get(open)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
                {
                    open += 1;
                }
                if open == member_start {
                    break;
                }
                while masked
                    .get(open)
                    .is_some_and(|byte| byte.is_ascii_whitespace())
                {
                    open += 1;
                }
            }
            if masked.get(open) != Some(&b'(') {
                continue;
            }
            let Some(close) = matching_call_end(&masked, open) else {
                continue;
            };
            let start_line = 1 + masked[..open].iter().filter(|byte| **byte == b'\n').count();
            let end_line = 1 + masked[..=close]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count();
            let call =
                format!("{name}{}", &masked_text[end..open]).replace(char::is_whitespace, "");
            spans.push((start_line, end_line, call));
        }
    }
    spans
}

pub(crate) fn external_framework_contract_evidence(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Option<String> {
    if !matches!(
        classify_file_role(&file.file_path),
        FileRole::AdapterIntegration | FileRole::Entrypoint
    ) {
        return None;
    }
    let spans = external_call_line_spans(file, index);
    if let Some((_, _, call)) = spans
        .iter()
        .find(|(start, end, _)| *start <= method.start_line && method.end_line <= *end)
    {
        return Some(format!(
            "adapter method is nested in imported external `{call}(...)` configuration contract"
        ));
    }
    let factory = returned_member_factory(file, method)?;
    for location in index.source_locations(&factory.name) {
        if index.file_records[location.file_index].file_path != file.file_path {
            continue;
        }
        if let Some((_, _, call)) = spans
            .iter()
            .find(|(start, end, _)| *start <= location.line_index + 1 && location.line_index < *end)
        {
            return Some(format!(
                "factory `{}` supplies this member to imported external `{call}(...)` configuration contract",
                factory.name
            ));
        }
    }
    None
}

pub(crate) fn external_object_escape_evidence(
    file: &FileRecord,
    owner: &str,
    index: &DossierRepositoryIndex<'_>,
) -> Option<String> {
    if owner.starts_with('<') {
        return None;
    }
    let spans = external_call_line_spans(file, index);
    for location in index.source_locations(owner) {
        if index.file_records[location.file_index].file_path != file.file_path {
            continue;
        }
        let line = index.source_lines[location.file_index][location.line_index];
        let compact = line
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let used_as_value = compact.contains(&format!(":{owner}"))
            || compact.contains(&format!("({owner},"))
            || compact.contains(&format!(",{owner},"))
            || compact.contains(&format!(",{owner})"));
        if !used_as_value {
            continue;
        }
        if let Some((_, _, call)) = spans
            .iter()
            .find(|(start, end, _)| *start <= location.line_index + 1 && location.line_index < *end)
        {
            return Some(format!(
                "object `{owner}` is supplied as a protocol value to imported external `{call}(...)`: {}:{}: {}",
                file.file_path,
                location.line_index + 1,
                line.trim(),
            ));
        }
    }
    None
}

pub(crate) fn object_enumeration_evidence(
    owner_name: &str,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let needles = [
        format!("Object.entries({owner_name})"),
        format!("Object.values({owner_name})"),
        format!("Reflect.ownKeys({owner_name})"),
    ];
    let mut evidence = index
        .source_locations(owner_name)
        .into_iter()
        .filter(|location| {
            let line = index.source_lines[location.file_index][location.line_index];
            needles.iter().any(|needle| line.contains(needle))
        })
        .map(|location| index.source_window(location))
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    evidence
}

fn identifier_prefix(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let end = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        .map(|(index, ch)| index + ch.len_utf8())
        .last()?;
    Some(&value[..end])
}

pub(crate) fn object_enumeration_invocation_proof(
    owner_name: &str,
    evidence: &[String],
) -> Option<String> {
    let marker = format!("Object.entries({owner_name})");
    evidence.iter().find_map(|window| {
        let after_marker = window.split_once(&marker)?.1;
        let after_comma = after_marker.split_once(',')?.1;
        let binding = identifier_prefix(after_comma)?;
        let after_binding = after_comma.trim_start().strip_prefix(binding)?;
        let after_destructure = after_binding.split_once(']')?.1;
        after_destructure
            .contains(&format!("{binding}("))
            .then(|| {
                format!(
                    "`Object.entries({owner_name})` binds every object value as `{binding}` and invokes `{binding}(...)`; every member participates in this repository call path"
                )
            })
    })
}

pub(crate) fn file_test_contract_evidence(
    file: &FileRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let Some(file_name) = file
        .file_path
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
    else {
        return Vec::new();
    };
    let mut evidence = index
        .test_files_by_referenced_name
        .get(file_name)
        .into_iter()
        .flatten()
        .copied()
        .filter(|file_index| {
            !index.file_records[*file_index]
                .file_path
                .eq_ignore_ascii_case(&file.file_path)
        })
        .map(|file_index| {
            index.source_window(SourceLocation {
                file_index,
                line_index: index.source_lines[file_index]
                    .iter()
                    .position(|line| contains_identifier(line, file_name))
                    .unwrap_or(0),
            })
        })
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    evidence
}

fn asserted_source_literal(line: &str) -> Option<&str> {
    if line.contains(".not.toContain(") {
        return None;
    }
    let after = [".toContain(", "assertIn(", "assert_contains("]
        .into_iter()
        .find_map(|marker| line.split_once(marker).map(|(_, after)| after))?
        .trim_start();
    let quote = after.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    after[quote.len_utf8()..]
        .split_once(quote)
        .map(|(literal, _)| literal)
}

pub(crate) fn file_content_test_contract_evidence(
    file: &FileRecord,
    method: &MethodRecord,
    index: &DossierRepositoryIndex<'_>,
) -> Vec<String> {
    let Some(file_name) = file
        .file_path
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
    else {
        return Vec::new();
    };
    let mut evidence = index
        .test_files_by_referenced_name
        .get(file_name)
        .into_iter()
        .flatten()
        .copied()
        .filter(|file_index| {
            let candidate = &index.file_records[*file_index];
            !candidate.file_path.eq_ignore_ascii_case(&file.file_path)
                && contains_any(
                    &candidate.source,
                    &["readFileSync", "read_to_string", "readText("],
                )
        })
        .flat_map(|file_index| {
            index.source_lines[file_index]
                .iter()
                .enumerate()
                .filter(move |(_, line)| {
                    asserted_source_literal(line)
                        .is_some_and(|literal| method.source.contains(literal))
                })
                .map(move |(line_index, _)| {
                    index.source_window(SourceLocation {
                        file_index,
                        line_index,
                    })
                })
        })
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    evidence
}
