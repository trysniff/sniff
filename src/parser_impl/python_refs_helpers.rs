use std::collections::HashSet;

pub(super) fn collect_python_refs(line: &str, shadowed: &HashSet<String>) -> Vec<String> {
    let mut refs = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
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
            if j < bytes.len() && bytes[j] == b'.' {
                let mut k = j + 1;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                let member_start = k;
                while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                    k += 1;
                }
                if member_start < k && !shadowed.contains(ident) {
                    refs.push(format!("{}.{}", ident, &line[member_start..k]));
                }
                i = k;
                continue;
            }
            if j < bytes.len() && bytes[j] == b'(' && !shadowed.contains(ident) {
                refs.push(ident.to_string());
            }
            continue;
        }
        i += 1;
    }
    refs
}
