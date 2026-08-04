fn skip_ws(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

fn read_ident_end(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && (bytes[idx].is_ascii_alphanumeric() || bytes[idx] == b'_') {
        idx += 1;
    }
    idx
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor + 1, cursor - hashes_start))
}

fn mask_rust_non_code(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut masked = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            masked[index..].fill(b' ');
            break;
        }
        if let Some((content_start, hashes)) = raw_string_start(bytes, index) {
            let suffix = format!("\"{}", "#".repeat(hashes));
            let end = line[content_start..]
                .find(&suffix)
                .map(|offset| content_start + offset + suffix.len())
                .unwrap_or(bytes.len());
            masked[index..end].fill(b' ');
            index = end;
            continue;
        }
        let quote = if bytes[index] == b'"'
            || (bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"'))
        {
            Some(b'"')
        } else if bytes[index] == b'\''
            && bytes[index + 1..]
                .iter()
                .take(8)
                .position(|byte| *byte == b'\'')
                .is_some()
        {
            Some(b'\'')
        } else {
            None
        };
        if let Some(quote) = quote {
            let start = index;
            if bytes[index] == b'b' {
                index += 1;
            }
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    break;
                }
            }
            masked[start..index].fill(b' ');
            continue;
        }
        index += 1;
    }
    String::from_utf8(masked).expect("masking ASCII delimiters preserves UTF-8")
}

fn starts_with_double_colon(bytes: &[u8], idx: usize) -> bool {
    idx + 1 < bytes.len() && bytes[idx] == b':' && bytes[idx + 1] == b':'
}

fn scan_namespace_chain(line: &str, bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor = start;
    let mut parts = Vec::new();

    while starts_with_double_colon(bytes, cursor) {
        cursor += 2;
        cursor = skip_ws(bytes, cursor);
        let seg_start = cursor;
        cursor = read_ident_end(bytes, cursor);
        if seg_start == cursor {
            break;
        }
        parts.push(&line[seg_start..cursor]);
        cursor = skip_ws(bytes, cursor);
    }

    if parts.is_empty() {
        None
    } else {
        Some((parts.join("::"), cursor))
    }
}

fn advance_member_path(line: &str, bytes: &[u8], mut cursor: usize) -> (String, usize) {
    let mut last_member = String::new();
    let mut last_cursor = cursor;

    loop {
        cursor = skip_ws(bytes, cursor);
        if cursor >= bytes.len() || bytes[cursor] != b'.' {
            break;
        }

        cursor += 1;
        cursor = skip_ws(bytes, cursor);
        let seg_start = cursor;
        cursor = read_ident_end(bytes, cursor);
        if seg_start == cursor {
            break;
        }
        last_member.clear();
        last_member.push_str(&line[seg_start..cursor]);
        last_cursor = cursor;
    }

    (last_member, last_cursor)
}

fn scan_member_chain(line: &str, bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor = skip_ws(bytes, start);
    let member_start = cursor;
    cursor = read_ident_end(bytes, cursor);

    if member_start >= cursor {
        return None;
    }

    let lookahead = skip_ws(bytes, cursor);
    if lookahead < bytes.len() && bytes[lookahead] == b'.' {
        let (last_member, last_cursor) = advance_member_path(line, bytes, lookahead);
        let call_cursor = skip_ws(bytes, last_cursor);
        if call_cursor < bytes.len() && bytes[call_cursor] == b'(' {
            return Some((last_member, call_cursor));
        }
    } else if lookahead < bytes.len() && bytes[lookahead] == b'(' {
        return Some((line[member_start..cursor].to_string(), lookahead));
    }

    None
}

pub(crate) struct RustReference {
    pub name: String,
    pub is_member_call: bool,
}

pub(crate) fn collect_refs(line: &str) -> Vec<RustReference> {
    let code = mask_rust_non_code(line);
    let line = code.as_str();
    let mut refs = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
            continue;
        }

        let start = i;
        let preceded_by_dot = line[..start]
            .chars()
            .rev()
            .find(|character| !character.is_whitespace())
            == Some('.');
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let ident = &line[start..i];
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }

        if starts_with_double_colon(bytes, j) {
            if let Some((chain, cursor)) = scan_namespace_chain(line, bytes, j) {
                refs.push(RustReference {
                    name: format!("{}::{}", ident, chain),
                    is_member_call: false,
                });
                i = cursor;
                continue;
            }
        } else if j < bytes.len() && bytes[j] == b'.' {
            if let Some((member, cursor)) = scan_member_chain(line, bytes, j + 1) {
                refs.push(RustReference {
                    name: member,
                    is_member_call: true,
                });
                i = cursor;
                continue;
            }
        } else if j < bytes.len() && bytes[j] == b'(' {
            refs.push(RustReference {
                name: ident.to_string(),
                is_member_call: preceded_by_dot,
            });
            continue;
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::collect_refs;

    #[test]
    fn rust_reference_scan_ignores_strings_raw_strings_and_comments() {
        for line in [
            r#"let source = "LineIndex::new(value)";"#,
            r##"let source = r#"LineIndex::new(value)"#;"##,
            "// LineIndex::new(value)",
            r#"assert!(report.contains("LineIndex::new"));"#,
        ] {
            assert!(
                !collect_refs(line)
                    .iter()
                    .any(|reference| reference.name == "LineIndex::new"),
                "string or comment became a LineIndex::new reference in {line}"
            );
        }
    }

    #[test]
    fn rust_reference_scan_keeps_real_associated_and_member_calls() {
        let references = collect_refs("let value = LineIndex::new(source); cache.get(key);");
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].name, "LineIndex::new");
        assert!(!references[0].is_member_call);
        assert_eq!(references[1].name, "get");
        assert!(references[1].is_member_call);
    }
}
