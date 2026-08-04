use super::*;

fn parse_import(trimmed: &str) -> Option<ImportRecord> {
    let rest = trimmed.strip_prefix("import ")?;
    let rest = rest.trim().trim_end_matches(';');
    if rest.starts_with('(') {
        return None;
    }
    if let Some((local, source)) = rest.split_once(' ') {
        Some(ImportRecord {
            local_name: local.trim().to_string(),
            source_module: source
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
            imported_name: "*".to_string(),
        })
    } else {
        Some(ImportRecord {
            local_name: rest.trim().trim_matches('"').to_string(),
            source_module: rest.trim().trim_matches('"').to_string(),
            imported_name: "*".to_string(),
        })
    }
}

pub(crate) fn parse_func_name(trimmed: &str) -> Option<(Option<String>, String, usize)> {
    let rest = trimmed.strip_prefix("func ")?;
    let rest = rest.trim_start();
    if rest.starts_with('(') {
        let recv_end = rest.find(')')?;
        let recv = rest[1..recv_end].trim();
        let recv_name = recv
            .split_whitespace()
            .last()?
            .trim_start_matches('*')
            .to_string();
        let after = rest[recv_end + 1..].trim_start();
        let name = after.split('(').next()?.trim().to_string();
        let params = after
            .split_once('(')
            .and_then(|(_, rem)| rem.split_once(')').map(|(inside, _)| inside))
            .unwrap_or("");
        return Some((
            Some(recv_name),
            name,
            params.split(',').filter(|p| !p.trim().is_empty()).count(),
        ));
    }

    let name = rest.split('(').next()?.trim().to_string();
    let params = rest
        .split_once('(')
        .and_then(|(_, rem)| rem.split_once(')').map(|(inside, _)| inside))
        .unwrap_or("");
    Some((
        None,
        name,
        params.split(',').filter(|p| !p.trim().is_empty()).count(),
    ))
}

fn record_go_import(trimmed: &str, imports: &mut Vec<ImportRecord>) -> bool {
    if let Some(import_record) = parse_import(trimmed) {
        imports.push(import_record);
        return true;
    }
    false
}

fn record_go_function(
    lines: &[&str],
    idx: usize,
    next_id: &mut usize,
    definitions: &mut Vec<SymbolDefinition>,
) -> Option<usize> {
    let trimmed = lines[idx].trim();
    let (recv, name, _) = parse_func_name(trimmed)?;
    let end = super::shared::scan_block_end(lines, idx);
    definitions.push(SymbolDefinition {
        id: *next_id,
        name: name.clone(),
        kind: if recv.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
        start_line: idx + 1,
        end_line: end + 1,
        is_exported: name
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false),
        owner_type: recv,
        receiver_type: None,
        value_type: None,
    });
    *next_id += 1;
    Some(end)
}

pub(crate) fn scan_go_defs_and_imports(extractor: &mut SymbolExtractor<'_>) -> Vec<(usize, usize)> {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    let lines: Vec<&str> = source.lines().collect();
    let mut ranges = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("package ") {
            i += 1;
            continue;
        }

        if record_go_import(trimmed, &mut extractor.imports) {
            i += 1;
            continue;
        }

        if let Some(end) = record_go_function(
            &lines,
            i,
            &mut extractor.next_id,
            &mut extractor.definitions,
        ) {
            ranges.push((i, end));
            i = end + 1;
            continue;
        }

        i += 1;
    }
    let _ = extractor.adapter;
    let _ = extractor.language;
    ranges
}
