use std::collections::HashSet;

pub(super) struct PythonReference {
    pub name: String,
    pub is_member_call: bool,
}

pub(super) fn collect_python_refs(
    line: &str,
    shadowed: &HashSet<String>,
    imported_names: &HashSet<String>,
) -> Vec<PythonReference> {
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
            let value_position = python_value_position(bytes, start);
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'.' {
                let mut k = j;
                let mut parts = vec![ident];
                while k < bytes.len() && bytes[k] == b'.' {
                    k += 1;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    let member_start = k;
                    while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_')
                    {
                        k += 1;
                    }
                    if member_start == k {
                        break;
                    }
                    parts.push(&line[member_start..k]);
                    let next = k;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k >= bytes.len() || bytes[k] != b'.' {
                        k = next;
                        break;
                    }
                }
                let call = skip_python_whitespace(bytes, k) < bytes.len()
                    && bytes[skip_python_whitespace(bytes, k)] == b'(';
                let known_receiver = matches!(ident, "self" | "cls");
                if parts.len() > 1
                    && (call || value_position || imported_names.contains(ident))
                    && (known_receiver || !shadowed.contains(ident))
                {
                    refs.push(PythonReference {
                        name: parts.join("."),
                        is_member_call: call,
                    });
                }
                i = k;
                continue;
            }
            if j < bytes.len() && bytes[j] == b'(' && !shadowed.contains(ident) {
                refs.push(PythonReference {
                    name: ident.to_string(),
                    is_member_call: false,
                });
                continue;
            }

            // A callable can be used as a value instead of invoked here,
            // most commonly when wiring a dependency-injection seam:
            // `run_git_fn=_run_git`. Keep these references in the graph so
            // wrappers are not misclassified as orphaned or unused.
            if value_position && !shadowed.contains(ident) {
                refs.push(PythonReference {
                    name: ident.to_string(),
                    is_member_call: false,
                });
            }
            continue;
        }
        i += 1;
    }
    refs
}

fn python_value_position(bytes: &[u8], start: usize) -> bool {
    let mut previous = start;
    while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {
        previous -= 1;
    }
    previous > 0 && matches!(bytes[previous - 1], b'=' | b',' | b'(' | b'[' | b'{')
}

fn skip_python_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::collect_python_refs;
    use std::collections::HashSet;

    #[test]
    fn collects_private_callable_passed_as_dependency() {
        let refs = collect_python_refs(
            "resolve_target_ref_fn=_resolve_target_ref",
            &HashSet::new(),
            &HashSet::new(),
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "_resolve_target_ref");
    }

    #[test]
    fn does_not_collect_shadowed_callable_reference() {
        let shadowed = HashSet::from(["_resolve_target_ref".to_string()]);
        let refs = collect_python_refs(
            "resolve_target_ref_fn=_resolve_target_ref",
            &shadowed,
            &HashSet::new(),
        );
        assert!(refs.is_empty());
    }

    #[test]
    fn collects_parenthesized_qualified_callable_alias_value() {
        let imported = HashSet::from(["finding_python_signatures".to_string()]);
        let refs = collect_python_refs(
            "finding_python_signatures.extract_python_signatures",
            &HashSet::new(),
            &imported,
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].name,
            "finding_python_signatures.extract_python_signatures"
        );
    }
}
