use super::lookup_file;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Clone)]
struct TsPathAlias {
    base_dir: PathBuf,
    pattern: String,
    targets: Vec<String>,
}

#[derive(Clone)]
struct JestPathAlias {
    root_dir: PathBuf,
    pattern: String,
    targets: Vec<String>,
}

fn strip_jsonc(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            output.push(byte as char);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            output.push('"');
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                }
                output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                index += 1;
            }
            continue;
        }
        if byte == b',' {
            let mut next = index + 1;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if matches!(bytes.get(next), Some(b'}' | b']')) {
                index += 1;
                continue;
            }
        }
        output.push(byte as char);
        index += 1;
    }
    output
}

fn aliases_in_directory(directory: &Path) -> Vec<TsPathAlias> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<TsPathAlias>>>> = OnceLock::new();
    let key = directory
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();
    if let Some(cached) = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()
        .and_then(|cache| cache.get(&key).cloned())
    {
        return cached;
    }

    let mut configs = std::fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("tsconfig") && name.ends_with(".json"))
        })
        .collect::<Vec<_>>();
    configs.sort();

    let mut aliases = Vec::new();
    for config in configs {
        let Ok(contents) = std::fs::read_to_string(&config) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&strip_jsonc(&contents)) else {
            continue;
        };
        let Some(options) = value.get("compilerOptions") else {
            continue;
        };
        let base_url = options
            .get("baseUrl")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(".");
        let base_dir = directory.join(base_url);
        let Some(paths) = options.get("paths").and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (pattern, targets) in paths {
            let targets = targets
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !targets.is_empty() {
                aliases.push(TsPathAlias {
                    base_dir: base_dir.clone(),
                    pattern: pattern.clone(),
                    targets,
                });
            }
        }
    }
    if let Ok(mut cache) = CACHE.get().expect("alias cache initialized").lock() {
        cache.insert(key, aliases.clone());
    }
    aliases
}

fn wildcard_match<'a>(pattern: &str, source_module: &'a str) -> Option<&'a str> {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return (pattern == source_module).then_some("");
    };
    source_module.strip_prefix(prefix)?.strip_suffix(suffix)
}

fn jest_aliases(project_root: &Path) -> Vec<JestPathAlias> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<JestPathAlias>>>> = OnceLock::new();
    let key = project_root
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();
    if let Some(cached) = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()
        .and_then(|cache| cache.get(&key).cloned())
    {
        return cached;
    }

    let mapper = std::fs::read_to_string(project_root.join("jest.config.json"))
        .ok()
        .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
        .and_then(|value| value.get("moduleNameMapper").cloned())
        .or_else(|| {
            std::fs::read_to_string(project_root.join("package.json"))
                .ok()
                .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
                .and_then(|value| value.pointer("/jest/moduleNameMapper").cloned())
        });
    let aliases = mapper
        .and_then(|mapper| mapper.as_object().cloned())
        .into_iter()
        .flatten()
        .filter_map(|(pattern, targets)| {
            let targets = match targets {
                serde_json::Value::String(target) => vec![target],
                serde_json::Value::Array(targets) => targets
                    .into_iter()
                    .filter_map(|target| target.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            };
            (!targets.is_empty()).then_some(JestPathAlias {
                root_dir: project_root.to_path_buf(),
                pattern,
                targets,
            })
        })
        .collect::<Vec<_>>();
    if let Ok(mut cache) = CACHE.get().expect("Jest alias cache initialized").lock() {
        cache.insert(key, aliases.clone());
    }
    aliases
}

fn jest_pattern_match<'a>(pattern: &str, source_module: &'a str) -> Option<&'a str> {
    let pattern = pattern.strip_prefix('^').unwrap_or(pattern);
    let pattern = pattern.strip_suffix('$').unwrap_or(pattern);
    let Some((prefix, suffix)) = pattern.split_once("(.*)") else {
        return (pattern == source_module).then_some("");
    };
    source_module.strip_prefix(prefix)?.strip_suffix(suffix)
}

fn resolve_jest_alias(
    project_root: &Path,
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    for alias in jest_aliases(project_root) {
        let Some(capture) = jest_pattern_match(&alias.pattern, source_module) else {
            continue;
        };
        for target in alias.targets {
            let target = target
                .replace("<rootDir>", &alias.root_dir.to_string_lossy())
                .replace("$1", capture);
            if let Some(resolved) = resolve_candidate(Path::new(&target), all_files) {
                return Some(resolved);
            }
        }
    }
    None
}

fn resolve_candidate(candidate: &Path, all_files: &HashMap<String, String>) -> Option<String> {
    if let Some(orig) = lookup_file(&candidate.to_string_lossy(), all_files) {
        return Some(orig);
    }
    for ext in &["ts", "js", "tsx", "jsx", "mjs", "cjs"] {
        let appended = PathBuf::from(format!("{}.{ext}", candidate.to_string_lossy()));
        if let Some(orig) = lookup_file(&appended.to_string_lossy(), all_files) {
            return Some(orig);
        }
    }
    if candidate
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "ts" | "js" | "tsx" | "jsx" | "mjs" | "cjs"))
    {
        for ext in &["ts", "js", "tsx", "jsx", "mjs", "cjs"] {
            if let Some(orig) =
                lookup_file(&candidate.with_extension(ext).to_string_lossy(), all_files)
            {
                return Some(orig);
            }
        }
    }
    for ext in &["ts", "js", "tsx", "jsx"] {
        if let Some(orig) = lookup_file(
            &candidate.join(format!("index.{ext}")).to_string_lossy(),
            all_files,
        ) {
            return Some(orig);
        }
    }
    None
}

fn resolve_tsconfig_alias(
    parent_dir: &Path,
    project_root: &str,
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let root = Path::new(project_root);
    for directory in parent_dir.ancestors() {
        for alias in aliases_in_directory(directory) {
            let Some(capture) = wildcard_match(&alias.pattern, source_module) else {
                continue;
            };
            for target in alias.targets {
                let target = target.replace('*', capture);
                if let Some(resolved) = resolve_candidate(&alias.base_dir.join(target), all_files) {
                    return Some(resolved);
                }
            }
        }
        if directory == root {
            break;
        }
    }
    None
}

pub(super) fn resolve_js_ts_module_path(
    parent_dir: &Path,
    source_module: &str,
    project_root: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    if !source_module.starts_with('.') {
        return resolve_tsconfig_alias(parent_dir, project_root, source_module, all_files)
            .or_else(|| resolve_jest_alias(Path::new(project_root), source_module, all_files));
    }

    let relative_path = parent_dir.join(source_module);
    resolve_candidate(&relative_path, all_files)
}
