use super::*;

#[path = "rust_refs.rs"]
pub(crate) mod refs;
#[path = "rust_ref_scan.rs"]
pub(crate) mod scan;

pub(super) fn balanced_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0isize;
    let mut started = false;
    let mut in_block_comment = false;
    let mut in_string: Option<char> = None;
    let mut escape = false;

    for (idx, line) in lines.iter().enumerate().skip(start) {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if !started {
                if ch == '{' {
                    started = true;
                    depth = 1;
                }
                continue;
            }

            if in_block_comment {
                if ch == '*' && matches!(chars.peek(), Some('/')) {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }

            if let Some(quote) = in_string {
                if escape {
                    escape = false;
                    continue;
                }
                if ch == '\\' {
                    escape = true;
                    continue;
                }
                if ch == quote {
                    in_string = None;
                }
                continue;
            }

            match ch {
                '/' if matches!(chars.peek(), Some('/')) => {
                    break;
                }
                '/' if matches!(chars.peek(), Some('*')) => {
                    chars.next();
                    in_block_comment = true;
                }
                '"' | '\'' | '`' => in_string = Some(ch),
                '{' => {
                    depth += 1;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if started && depth <= 0 {
            return idx;
        }
    }

    lines.len().saturating_sub(1)
}

pub(super) fn parse_use(trimmed: &str) -> Option<(ImportRecord, Option<ExportRecord>)> {
    let is_pub = trimmed.starts_with("pub use ");
    let rest = if is_pub {
        trimmed.strip_prefix("pub use ")?
    } else {
        trimmed.strip_prefix("use ")?
    }
    .trim_end_matches(';')
    .trim();

    let imported_name = rest.split("::").last()?.trim().to_string();
    let source_module = rest
        .rsplit_once("::")
        .map(|(module, _)| module.to_string())
        .unwrap_or_default();
    let import = ImportRecord {
        local_name: imported_name.clone(),
        source_module: source_module.clone(),
        imported_name: imported_name.clone(),
    };
    let export = if is_pub {
        Some(ExportRecord {
            exported_name: imported_name.clone(),
            local_symbol_name: imported_name.clone(),
            source_module: Some(source_module),
            source_symbol_name: Some(imported_name.clone()),
        })
    } else {
        None
    };
    Some((import, export))
}

fn strip_rust_visibility_prefix(mut trimmed: &str) -> &str {
    loop {
        let line = trimmed.trim_start();
        if let Some(rest) = line.strip_prefix("pub ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub(")
            && let Some(end) = rest.find(')')
        {
            trimmed = &rest[end + 1..];
            continue;
        }
        return line;
    }
}

fn strip_rust_fn_prefixes(mut trimmed: &str) -> Option<&str> {
    loop {
        let line = trimmed.trim_start();
        if let Some(rest) = line.strip_prefix("fn ") {
            return Some(rest);
        }
        if let Some(rest) = line.strip_prefix("pub ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("async ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("const ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("unsafe ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("default ") {
            trimmed = rest;
            continue;
        }
        if let Some(rest) = line.strip_prefix("extern ") {
            let rest = rest.trim_start();
            if let Some(after_abi) = rest.strip_prefix('"') {
                let end_quote = after_abi.find('"')?;
                trimmed = &after_abi[end_quote + 1..];
            } else {
                trimmed = rest;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub(") {
            let end = rest.find(')')?;
            trimmed = &rest[end + 1..];
            continue;
        }
        return None;
    }
}

pub(super) fn parse_fn_name(trimmed: &str) -> Option<String> {
    let trimmed = trimmed.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('#') {
        return None;
    }
    let rest = strip_rust_fn_prefixes(trimmed)?;
    Some(
        rest.split(|c: char| c == '(' || c == '<' || c.is_whitespace())
            .next()?
            .trim()
            .to_string(),
    )
}

pub(super) fn parse_struct_name(trimmed: &str) -> Option<String> {
    let rest = strip_rust_visibility_prefix(trimmed);
    let rest = rest.strip_prefix("struct ")?;
    Some(
        rest.split(|c: char| c == '{' || c == ';' || c == '<' || c.is_whitespace())
            .next()?
            .trim()
            .to_string(),
    )
}

pub(super) fn parse_impl_name(trimmed: &str) -> Option<String> {
    let mut rest = trimmed.trim_start();
    let after_impl = rest.strip_prefix("impl")?;
    rest = after_impl.trim_start();

    if rest.starts_with('<') {
        let mut depth = 0isize;
        let mut end = None;
        for (idx, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = rest.get(end? + 1..)?.trim_start();
    }

    let target = rest
        .rsplit_once(" for ")
        .map(|(_, after_for)| after_for)
        .unwrap_or(rest);
    let target = target
        .split(|c: char| c == '{' || c == ';' || c == '(' || c.is_whitespace())
        .next()?
        .trim();
    if target.is_empty() {
        return None;
    }

    let target = target
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches("dyn ")
        .trim_start_matches("crate::")
        .trim_start_matches("self::");
    let target = target.split('<').next().unwrap_or(target);
    let target = target.split("::").last().unwrap_or(target);
    let target = target.trim_matches(|c: char| c == '{' || c == '}' || c == '<' || c == '>');

    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

fn build_rust_method_record(
    file_path: &str,
    source: String,
    name: String,
    start: usize,
    end: usize,
    param_count: usize,
    is_exported: bool,
) -> MethodRecord {
    MethodRecord {
        name,
        file_path: file_path.to_string(),
        source,
        loc: end.saturating_sub(start) + 1,
        param_count,
        start_line: start,
        end_line: end,
        is_exported,
        language: "rust".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    }
}

fn build_rust_definition(
    next_id: usize,
    name: String,
    start: usize,
    end: usize,
    is_exported: bool,
    owner_type: Option<String>,
) -> SymbolDefinition {
    SymbolDefinition {
        id: next_id,
        name,
        kind: if owner_type.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
        start_line: start,
        end_line: end,
        is_exported,
        owner_type,
    }
}

fn push_rust_method(
    extractor: &mut RustExtractor<'_>,
    name: String,
    source: String,
    start: usize,
    end: usize,
    param_count: usize,
    is_exported: bool,
) {
    extractor.methods.push(build_rust_method_record(
        &extractor.file_path,
        source,
        name,
        start,
        end,
        param_count,
        is_exported,
    ));
}

fn push_rust_definition(
    extractor: &mut RustExtractor<'_>,
    name: String,
    start: usize,
    end: usize,
    is_exported: bool,
    owner_type: Option<String>,
) {
    extractor.definitions.push(build_rust_definition(
        extractor.next_id,
        name,
        start,
        end,
        is_exported,
        owner_type,
    ));
    extractor.next_id += 1;
}

pub(super) fn record_rust_fn_block(
    extractor: &mut RustExtractor<'_>,
    lines: &[&str],
    idx: usize,
    impl_type: Option<String>,
) -> usize {
    let trimmed = lines[idx].trim();
    let Some(name) = parse_fn_name(trimmed) else {
        return idx + 1;
    };
    let start = idx + 1;
    let end_idx = balanced_end(lines, idx);
    let end = end_idx + 1;
    push_rust_definition(
        extractor,
        name.clone(),
        start,
        end,
        trimmed.starts_with("pub ") || trimmed.starts_with("pub("),
        impl_type.clone(),
    );
    let body = lines[idx..=end_idx].join("\n");
    refs::collect_rust_refs(extractor, lines, idx, end_idx, &name);
    push_rust_method(
        extractor,
        name,
        body,
        start,
        end,
        trimmed
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')').map(|(inside, _)| inside))
            .map(|inside| inside.split(',').filter(|p| !p.trim().is_empty()).count())
            .unwrap_or(0),
        trimmed.starts_with("pub fn "),
    );
    end_idx + 1
}

pub(super) fn record_rust_method_block(
    extractor: &mut RustExtractor<'_>,
    lines: &[&str],
    idx: usize,
    impl_type: Option<String>,
) -> usize {
    let inner_trimmed = lines[idx].trim();
    let Some(name) = parse_fn_name(inner_trimmed) else {
        return idx + 1;
    };
    let start = idx + 1;
    let end_idx = balanced_end(lines, idx);
    let end = end_idx + 1;
    push_rust_definition(
        extractor,
        name.clone(),
        start,
        end,
        inner_trimmed.starts_with("pub ") || inner_trimmed.starts_with("pub("),
        impl_type.clone(),
    );
    let body = lines[idx..=end_idx].join("\n");
    refs::collect_rust_refs(extractor, lines, idx, end_idx, &name);
    push_rust_method(
        extractor,
        name,
        body,
        start,
        end,
        inner_trimmed
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')').map(|(inside, _)| inside))
            .map(|inside| inside.split(',').filter(|p| !p.trim().is_empty()).count())
            .unwrap_or(0),
        inner_trimmed.starts_with("pub fn "),
    );
    end_idx + 1
}

impl<'a> RustExtractor<'a> {
    pub(super) fn scan_rust_impl_block(
        &mut self,
        lines: &[&str],
        idx: usize,
        impl_type: Option<String>,
    ) -> usize {
        let impl_end = balanced_end(lines, idx);
        let mut inner = idx + 1;
        while inner <= impl_end {
            let inner_trimmed = lines[inner].trim();
            if parse_fn_name(inner_trimmed).is_some() {
                inner = record_rust_method_block(self, lines, inner, impl_type.clone());
                continue;
            }
            inner += 1;
        }
        impl_end + 1
    }

    pub(super) fn scan_rust_fn_block(
        &mut self,
        lines: &[&str],
        idx: usize,
        impl_type: Option<String>,
    ) -> usize {
        record_rust_fn_block(self, lines, idx, impl_type)
    }
}
