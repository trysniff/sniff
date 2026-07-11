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

pub(crate) fn collect_refs(line: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
            continue;
        }

        let start = i;
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
                refs.push(format!("{}::{}", ident, chain));
                i = cursor;
                continue;
            }
        } else if j < bytes.len() && bytes[j] == b'.' {
            if let Some((member, cursor)) = scan_member_chain(line, bytes, j + 1) {
                refs.push(member);
                i = cursor;
                continue;
            }
        } else if j < bytes.len() && bytes[j] == b'(' {
            refs.push(ident.to_string());
            continue;
        }
    }
    refs
}
