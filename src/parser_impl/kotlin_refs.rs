fn mask_non_code(line: &str) -> String {
    let mut bytes = line.as_bytes().to_vec();
    let mut index = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            bytes[index] = b' ';
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            quote = Some(byte);
            bytes[index] = b' ';
            index += 1;
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            bytes[index..end].fill(b' ');
            index = end;
            continue;
        }
        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            let end = bytes[index + 2..]
                .windows(2)
                .position(|window| window == b"*/")
                .map(|offset| index + 2 + offset + 2)
                .unwrap_or(bytes.len());
            bytes[index..end].fill(b' ');
            index = end;
            continue;
        }
        index += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn identifier_end(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    index
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn matching_parenthesis(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn push_reference(reference: String, refs: &mut Vec<String>) {
    if !reference.is_empty() {
        refs.push(reference);
    }
}

fn string_template_expressions(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut expressions = Vec::new();
    let mut index = 0usize;
    let mut quote = None::<u8>;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                index += 1;
                continue;
            }
            if active_quote == b'"'
                && byte == b'$'
                && index + 1 < bytes.len()
                && bytes[index + 1] == b'{'
            {
                let start = index + 2;
                let mut cursor = start;
                let mut depth = 1usize;
                let mut inner_quote = None::<u8>;
                let mut inner_escaped = false;
                while cursor < bytes.len() {
                    let current = bytes[cursor];
                    if let Some(inner) = inner_quote {
                        if inner_escaped {
                            inner_escaped = false;
                        } else if current == b'\\' {
                            inner_escaped = true;
                        } else if current == inner {
                            inner_quote = None;
                        }
                    } else if current == b'"' || current == b'\'' {
                        inner_quote = Some(current);
                    } else if current == b'{' {
                        depth += 1;
                    } else if current == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            expressions.push(&line[start..cursor]);
                            index = cursor + 1;
                            break;
                        }
                    }
                    cursor += 1;
                }
                if depth == 0 {
                    continue;
                }
            }
            if byte == active_quote {
                quote = None;
            }
        } else if byte == b'"' || byte == b'\'' {
            quote = Some(byte);
        } else if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            break;
        }
        index += 1;
    }
    expressions
}

fn collect_code_refs(line: &str) -> Vec<String> {
    let masked = mask_non_code(line);
    let bytes = masked.as_bytes();
    let mut refs = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b':' && index + 1 < bytes.len() && bytes[index + 1] == b':' {
            let start = skip_whitespace(bytes, index + 2);
            let end = identifier_end(bytes, start);
            if start < end {
                refs.push(masked[start..end].to_string());
                index = end;
                continue;
            }
        }
        if !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }

        let first_start = index;
        let first_end = identifier_end(bytes, first_start + 1);
        let mut parts = vec![masked[first_start..first_end].to_string()];
        let mut cursor = first_end;
        let mut nested_ranges = Vec::new();
        let mut emitted_current_chain = false;
        loop {
            let separator = skip_whitespace(bytes, cursor);
            if separator + 1 < bytes.len()
                && bytes[separator] == b':'
                && bytes[separator + 1] == b':'
            {
                let next_start = skip_whitespace(bytes, separator + 2);
                let next_end = identifier_end(bytes, next_start);
                if next_start < next_end {
                    parts.push(masked[next_start..next_end].to_string());
                    cursor = next_end;
                    push_reference(parts.join("."), &mut refs);
                }
                break;
            }

            if separator < bytes.len() && bytes[separator] == b'.' {
                let next_start = skip_whitespace(bytes, separator + 1);
                let next_end = identifier_end(bytes, next_start);
                if next_start == next_end {
                    break;
                }
                parts.push(masked[next_start..next_end].to_string());
                cursor = next_end;
                emitted_current_chain = false;
                continue;
            }

            if separator < bytes.len() && bytes[separator] == b'{' {
                if !emitted_current_chain {
                    push_reference(parts.join("."), &mut refs);
                }
                cursor = separator;
                break;
            }

            if separator >= bytes.len() || bytes[separator] != b'(' {
                break;
            }

            if !emitted_current_chain {
                push_reference(parts.join("."), &mut refs);
                emitted_current_chain = true;
            }
            let Some(close) = matching_parenthesis(bytes, separator) else {
                break;
            };
            nested_ranges.push((separator + 1, close));
            cursor = close + 1;
        }

        for (start, end) in nested_ranges {
            for reference in collect_code_refs(&masked[start..end]) {
                push_reference(reference, &mut refs);
            }
        }
        index = cursor.max(first_end);
    }
    refs
}

pub(crate) fn collect_refs(line: &str) -> Vec<String> {
    let mut refs = collect_code_refs(line);
    for expression in string_template_expressions(line) {
        refs.extend(collect_code_refs(expression));
    }
    refs
}

fn parenthesis_balance(source: &str) -> isize {
    mask_non_code(source).bytes().fold(0isize, |balance, byte| {
        balance
            + match byte {
                b'(' => 1,
                b')' => -1,
                _ => 0,
            }
    })
}

pub(crate) fn collect_source_refs(source: &str) -> Vec<(usize, String, Vec<String>)> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut references = Vec::new();
    let mut line_index = 0usize;
    while line_index < lines.len() {
        let start = line_index;
        let mut logical = lines[line_index].to_string();
        let mut balance = parenthesis_balance(&logical);
        while line_index + 1 < lines.len()
            && (balance > 0 || lines[line_index + 1].trim_start().starts_with('.'))
        {
            line_index += 1;
            logical.push('\n');
            logical.push_str(lines[line_index]);
            balance += parenthesis_balance(lines[line_index]);
        }
        let refs = collect_refs(&logical);
        let mut search_from = 0usize;
        for reference in refs {
            let terminal = reference.rsplit('.').next().unwrap_or(&reference);
            let occurrence = logical[search_from..]
                .find(&reference)
                .map(|offset| (search_from + offset, reference.len()))
                .or_else(|| {
                    logical[search_from..]
                        .find(terminal)
                        .map(|offset| (search_from + offset, terminal.len()))
                })
                .or_else(|| {
                    logical
                        .find(&reference)
                        .map(|offset| (offset, reference.len()))
                })
                .or_else(|| {
                    logical
                        .find(terminal)
                        .map(|offset| (offset, terminal.len()))
                });
            let reference_line = occurrence
                .map(|(offset, _)| {
                    start
                        + logical[..offset]
                            .bytes()
                            .filter(|byte| *byte == b'\n')
                            .count()
                })
                .unwrap_or(start);
            if let Some((offset, matched_len)) = occurrence {
                search_from = offset + matched_len;
            }
            references.push((reference_line, logical.trim().to_string(), vec![reference]));
        }
        line_index += 1;
    }
    references
}

#[cfg(test)]
mod tests {
    use super::{collect_refs, collect_source_refs};

    #[test]
    fn collects_unqualified_callable_references() {
        assert_eq!(
            collect_refs("rows.map(::toContractHistoryItemState)"),
            vec!["rows.map", "toContractHistoryItemState"]
        );
    }

    #[test]
    fn collects_owner_qualified_callable_references() {
        assert_eq!(
            collect_refs("rows.map(Coordinator::convert)"),
            vec!["rows.map", "Coordinator.convert"]
        );
    }

    #[test]
    fn preserves_complete_receiver_chains() {
        assert_eq!(
            collect_refs("LocalOnPillStrings.current.text(key, fallback)"),
            vec!["LocalOnPillStrings.current.text"]
        );
    }

    #[test]
    fn ignores_calls_inside_strings_and_comments() {
        assert_eq!(
            collect_refs("real.call() // fake.call() and \"string.call()\""),
            vec!["real.call"]
        );
    }

    #[test]
    fn collects_calls_inside_kotlin_string_templates_only() {
        assert_eq!(
            collect_refs("val label = \"time ${timestamp(now)} fake.call()\" // ignored.call()"),
            vec!["timestamp"]
        );
    }

    #[test]
    fn preserves_constructor_result_member_calls() {
        assert_eq!(
            collect_refs("HostAdherenceStore(context).replaceAll(events)"),
            vec!["HostAdherenceStore", "HostAdherenceStore.replaceAll"]
        );
    }

    #[test]
    fn preserves_nested_call_result_member_chains() {
        assert_eq!(
            collect_refs("runtime.shell().onOnboardingStateSelected(state)"),
            vec!["runtime.shell", "runtime.shell.onOnboardingStateSelected"]
        );
    }

    #[test]
    fn collects_trailing_lambda_calls_without_parentheses() {
        assert_eq!(
            collect_refs("return cursor.useCursor { row -> row.value() }"),
            vec!["cursor.useCursor", "row.value"]
        );
    }

    #[test]
    fn call_followed_by_lambda_is_emitted_once() {
        assert_eq!(collect_refs("render() { value }"), vec!["render"]);
    }

    #[test]
    fn attributes_qualified_call_after_same_named_parameter() {
        let source = "fun launch(\n  shadow: Shadow,\n  onAppLaunched: () -> Unit,\n  build: (Shadow) -> Unit =\n    { shadow -> shadow.onAppLaunched() },\n) = Unit";
        let references = collect_source_refs(source);
        assert!(references.iter().any(|(line, _, references)| {
            *line == 4 && references == &["shadow.onAppLaunched".to_string()]
        }));
    }

    #[test]
    fn preserves_multiline_qualified_calls() {
        let refs =
            collect_source_refs("return DoseProjectionEngine\n  .terminalHistory(events, now)\n");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, 1);
        assert_eq!(refs[0].2, vec!["DoseProjectionEngine.terminalHistory"]);
    }

    #[test]
    fn attributes_each_multiline_argument_call_to_its_source_line() {
        let refs = collect_source_refs(
            "return Candidate(\n  first = inventory.toDisplayLabel(),\n  second = threshold.toDisplayLabel(),\n)\n",
        );
        let display_lines = refs
            .iter()
            .filter_map(|(line, _, refs)| {
                refs.iter()
                    .any(|reference| reference.ends_with(".toDisplayLabel"))
                    .then_some(*line)
            })
            .collect::<Vec<_>>();
        assert_eq!(display_lines, vec![1, 2]);
    }
}
