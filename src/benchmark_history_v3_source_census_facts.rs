use super::super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::super::{
    HistoricalV3SourceFileFacts, HistoricalV3SourceMethodFacts,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensus,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use tree_sitter::Node;

pub(super) fn source_file_facts(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &IntentionalBoundarySourceCensus,
) -> Result<Vec<HistoricalV3SourceFileFacts>, String> {
    let records = intentional_boundary_file_records_typed(root, inventory, census)
        .map_err(|error| error.detail)?;
    if records.len() != census.source_files.len() {
        return Err("historical-v3 source facts do not cover the source census".to_string());
    }
    records
        .iter()
        .zip(&census.source_files)
        .map(|(record, source)| {
            if record.language != source.language {
                return Err(format!(
                    "historical-v3 source facts changed language for {}",
                    source.repository_path
                ));
            }
            let bytes = record.source.as_bytes();
            if record.methods.len() != source.methods.len() {
                return Err(format!(
                    "historical-v3 source method facts changed for {}",
                    source.repository_path
                ));
            }
            let methods = record
                .methods
                .iter()
                .zip(&source.methods)
                .map(|(method, expected)| {
                    Ok(HistoricalV3SourceMethodFacts {
                        parser_unit_id: expected.parser_unit_id.clone(),
                        source_sha256: expected.source_sha256.clone(),
                        non_whitespace_line_count: method
                            .source
                            .lines()
                            .filter(|line| !line.trim().is_empty())
                            .count(),
                        syntax_sha256: canonical_layout_sha256(method.source.as_bytes())?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(HistoricalV3SourceFileFacts {
                repository_path: source.repository_path.clone(),
                source_sha256: source.source_sha256.clone(),
                non_whitespace_line_count: record
                    .source
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count(),
                syntax_sha256: syntax_sha256(&source.repository_path, bytes)?,
                methods,
            })
        })
        .collect()
}

fn syntax_sha256(path: &str, bytes: &[u8]) -> Result<String, String> {
    let extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if !matches!(extension, "go" | "kt" | "kts") {
        return canonical_layout_sha256(bytes);
    }
    let tree = crate::parser::parse_tree_sitter_source_checked(path, bytes)?;
    let mut digest = Sha256::new();
    hash_node(tree.root_node(), bytes, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn canonical_layout_sha256(bytes: &[u8]) -> Result<String, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "historical-v3 syntax source is not UTF-8".to_string())?;
    // Quoted contents and line breaks can be language-significant. Refuse to
    // erase layout around them; this is deliberately conservative.
    if source.contains(['\'', '"', '`']) {
        return Ok(format!("{:x}", Sha256::digest(bytes)));
    }
    let mut canonical = Vec::with_capacity(bytes.len());
    for (line_index, line) in source.split('\n').enumerate() {
        if line_index > 0 {
            canonical.push(b'\n');
        }
        canonical.extend(canonical_line(line.as_bytes()));
    }
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn canonical_line(line: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(line.len());
    let mut index = 0;
    while index < line.len() {
        if !line[index].is_ascii_whitespace() {
            output.push(line[index]);
            index += 1;
            continue;
        }
        let start = index;
        while index < line.len() && line[index].is_ascii_whitespace() {
            index += 1;
        }
        let previous = output.last().copied();
        let next = line.get(index).copied();
        let at_indentation = start == 0;
        if at_indentation {
            output.extend_from_slice(&line[start..index]);
        } else if !previous.is_some_and(layout_delimiter)
            && !next.is_some_and(layout_delimiter)
            && next.is_some()
        {
            output.push(b' ');
        }
    }
    output
}

fn layout_delimiter(byte: u8) -> bool {
    matches!(byte, b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b';')
}

fn hash_node(node: Node<'_>, bytes: &[u8], digest: &mut Sha256) -> Result<(), String> {
    if node.kind().to_ascii_lowercase().contains("comment") {
        return Ok(());
    }
    hash_field(digest, node.kind().as_bytes());
    if node.child_count() == 0 {
        let text = bytes
            .get(node.byte_range())
            .ok_or_else(|| "historical-v3 syntax node escaped its source bytes".to_string())?;
        hash_field(digest, text);
        return Ok(());
    }
    for index in 0..node.child_count() {
        let field_index = u32::try_from(index)
            .map_err(|_| "historical-v3 syntax child index overflowed".to_string())?;
        let child = node
            .child(index)
            .ok_or_else(|| "historical-v3 syntax child disappeared".to_string())?;
        hash_field(
            digest,
            node.field_name_for_child(field_index)
                .unwrap_or("")
                .as_bytes(),
        );
        hash_node(child, bytes, digest)?;
    }
    Ok(())
}

fn hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(value.len().to_le_bytes());
    digest.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_layout_ignores_only_safe_horizontal_layout() {
        let compact = syntax_sha256("src/lib.rs", b"pub fn total()->i32{1}\n").unwrap();
        let spaced = syntax_sha256("src/lib.rs", b"pub fn total() ->i32 {1}\n").unwrap();
        assert_eq!(compact, spaced);

        let separated_operators = syntax_sha256("src/lib.rs", b"fn f(){a+ +b}\n").unwrap();
        let increment = syntax_sha256("src/lib.rs", b"fn f(){a++b}\n").unwrap();
        assert_ne!(separated_operators, increment);
    }

    #[test]
    fn canonical_layout_preserves_quotes_lines_and_indentation() {
        assert_ne!(
            syntax_sha256("src/lib.rs", b"fn f(){\"a b\"}\n").unwrap(),
            syntax_sha256("src/lib.rs", b"fn f(){\"ab\"}\n").unwrap()
        );
        assert_ne!(
            syntax_sha256("pkg/mod.py", b"if ready:\n    run()\n").unwrap(),
            syntax_sha256("pkg/mod.py", b"if ready:\n        run()\n").unwrap()
        );
        assert_ne!(
            syntax_sha256("src/app.js", b"return value\n").unwrap(),
            syntax_sha256("src/app.js", b"return\nvalue\n").unwrap()
        );
    }
}
