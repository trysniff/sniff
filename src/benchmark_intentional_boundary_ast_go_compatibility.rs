use super::super::intentional_boundary_compatibility_version::contains_explicit_version;
use super::IntentionalBoundarySemanticRange;
use tree_sitter::Node;

pub(super) fn versioned_compatibility_contract(
    repository_path: &str,
    source: &[u8],
    declaration: Node<'_>,
) -> Option<IntentionalBoundarySemanticRange> {
    let comments = attached_doc_comments(source, declaration)?;
    let text = normalized_doc_text(source, &comments)?;
    let notice = deprecation_notice(&text)?;
    if !contains_explicit_version(&notice) {
        return None;
    }

    let first = comments.first()?;
    let last = comments.last()?;
    let start = first.start_position();
    let end = last.end_position();
    Some(IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: start.row as u32,
        start_character_zero_based: start.column as u32,
        end_line_zero_based: end.row as u32,
        end_character_zero_based: end.column as u32,
    })
}

fn attached_doc_comments<'tree>(
    source: &[u8],
    declaration: Node<'tree>,
) -> Option<Vec<Node<'tree>>> {
    let mut comments = Vec::new();
    let mut next_start = declaration.start_byte();
    let mut previous = declaration.prev_named_sibling();

    while let Some(node) = previous {
        if node.kind() != "comment" || !is_attached_gap(source.get(node.end_byte()..next_start)?) {
            break;
        }
        comments.push(node);
        next_start = node.start_byte();
        previous = node.prev_named_sibling();
    }
    if comments.is_empty() {
        return None;
    }
    comments.reverse();
    Some(comments)
}

fn is_attached_gap(gap: &[u8]) -> bool {
    let mut newlines = 0;
    let mut index = 0;
    while index < gap.len() {
        match gap[index] {
            b' ' | b'\t' => index += 1,
            b'\n' => {
                newlines += 1;
                index += 1;
            }
            b'\r' if gap.get(index + 1) == Some(&b'\n') => {
                newlines += 1;
                index += 2;
            }
            _ => return false,
        }
    }
    newlines <= 1
}

fn normalized_doc_text(source: &[u8], comments: &[Node<'_>]) -> Option<String> {
    let mut normalized = Vec::with_capacity(comments.len());
    for comment in comments {
        let raw = std::str::from_utf8(source.get(comment.byte_range())?).ok()?;
        normalized.push(normalize_comment(raw)?);
    }
    Some(normalized.join("\n"))
}

fn normalize_comment(raw: &str) -> Option<String> {
    if let Some(line) = raw.strip_prefix("//") {
        return Some(line.strip_prefix(' ').unwrap_or(line).to_string());
    }
    let block = raw.strip_prefix("/*")?.strip_suffix("*/")?;
    Some(
        block
            .lines()
            .map(|line| {
                let line = line.trim_start();
                let line = line.strip_prefix('*').unwrap_or(line);
                line.strip_prefix(' ').unwrap_or(line).trim_end()
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn deprecation_notice(text: &str) -> Option<String> {
    let mut paragraph = Vec::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if !paragraph.is_empty() {
                let joined = paragraph.join(" ");
                if joined.starts_with("Deprecated: ") {
                    return Some(joined);
                }
                paragraph.clear();
            }
        } else {
            paragraph.push(line.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_multiline_block_deprecation_paragraph() {
        let normalized = normalize_comment("/*\n * Deprecated: retained until version 3.\n */")
            .expect("block comment");
        assert_eq!(normalized, "\nDeprecated: retained until version 3.\n");
        let notice = deprecation_notice(&normalized).expect("deprecation paragraph");
        assert!(contains_explicit_version(&notice));
    }
}
