pub(crate) fn collect_refs(line: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
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
                let start2 = k;
                while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                    k += 1;
                }
                if start2 < k && k < bytes.len() && bytes[k] == b'(' {
                    refs.push(format!("{}.{}", ident, &line[start2..k]));
                }
            } else if j < bytes.len() && bytes[j] == b'(' {
                refs.push(ident.to_string());
            }
            continue;
        }
        i += 1;
    }
    refs
}
