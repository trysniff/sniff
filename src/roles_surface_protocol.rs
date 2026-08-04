use crate::roles::normalize_path;
use crate::types::{FileRecord, MethodRecord};

pub fn is_protocol_stub_method(method: &MethodRecord) -> bool {
    let source = method.source.trim();
    if source.is_empty() {
        return false;
    }

    let lines = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let Some(signature_index) = lines
        .iter()
        .position(|line| line.starts_with("def ") || line.starts_with("async def "))
    else {
        return false;
    };
    let mut signature_end = None;
    for (index, line) in lines.iter().enumerate().skip(signature_index) {
        let lowered = line.to_ascii_lowercase();
        if line.contains(": ...")
            || lowered.contains(": pass")
            || lowered.contains(": raise notimplementederror")
        {
            return true;
        }
        if line.ends_with(':') {
            signature_end = Some(index);
            break;
        }
    }
    let Some(signature_end) = signature_end else {
        return false;
    };

    let mut saw_stub = false;
    let mut docstring_delimiter = None::<&str>;
    for line in &lines[signature_end + 1..] {
        if let Some(delimiter) = docstring_delimiter {
            if line.contains(delimiter) {
                docstring_delimiter = None;
            }
            continue;
        }
        if let Some(delimiter) = ["\"\"\"", "'''"]
            .into_iter()
            .find(|delimiter| line.starts_with(delimiter))
        {
            if line[delimiter.len()..].contains(delimiter) {
                continue;
            }
            docstring_delimiter = Some(delimiter);
            continue;
        }
        let statement = line.split_once('#').map_or(*line, |(code, _)| code).trim();
        if statement.is_empty() {
            continue;
        }
        let lowered = statement.to_ascii_lowercase();
        let is_stub = statement == "..."
            || statement == "pass"
            || lowered.starts_with("raise notimplementederror")
            || lowered == "return notimplemented";
        if !is_stub {
            return false;
        }
        saw_stub = true;
    }
    saw_stub
}

pub fn is_protocol_surface_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    if normalized.ends_with("_protocols.py") {
        return !file.methods.is_empty();
    }

    if !file.source.contains("Protocol") {
        return false;
    }

    if file.methods.is_empty() {
        return false;
    }

    file.methods.iter().all(is_protocol_stub_method)
}

#[cfg(test)]
mod tests {
    use super::is_protocol_stub_method;
    use crate::types::MethodRecord;

    fn method(source: &str) -> MethodRecord {
        MethodRecord {
            name: "demo".to_string(),
            file_path: "src/demo.py".to_string(),
            source: source.to_string(),
            loc: source.lines().count(),
            param_count: 0,
            start_line: 1,
            end_line: source.lines().count(),
            is_exported: false,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }
    }

    #[test]
    fn exception_pass_inside_real_logic_is_not_a_protocol_stub() {
        let source = "def extract(content):\n    try:\n        return parse(content)\n    except ValueError:\n        pass\n    return recover(content)\n";

        assert!(!is_protocol_stub_method(&method(source)));
    }

    #[test]
    fn substantive_body_with_a_nested_pass_is_not_a_protocol_stub() {
        let source = "def process(value):\n    if value is None:\n        pass\n    return normalize(value)\n";

        assert!(!is_protocol_stub_method(&method(source)));
    }

    #[test]
    fn pass_and_not_implemented_bodies_remain_protocol_stubs() {
        assert!(is_protocol_stub_method(&method(
            "def close(self):\n    pass\n"
        )));
        assert!(is_protocol_stub_method(&method(
            "def load(self):\n    raise NotImplementedError()\n"
        )));
    }
}
