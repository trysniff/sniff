use super::super::intentional_boundary_compatibility_version::contains_explicit_version;
use oxc_ast::CommentKind;
use oxc_span::Span;

pub(super) fn versioned_compatibility_contract(
    source: &str,
    comments: &[(CommentKind, Span)],
    declaration_start: u32,
) -> Option<Span> {
    let (kind, content) = comments
        .iter()
        .filter(|(kind, span)| {
            let delimiter = if kind.is_multi_line() { 2 } else { 0 };
            span.end.saturating_add(delimiter) <= declaration_start
        })
        .max_by_key(|(_, span)| span.end)?;
    if !kind.is_multi_line() || content.start < 2 {
        return None;
    }
    let comment = Span::new(content.start - 2, content.end.checked_add(2)?);
    if !is_attached_gap(source.get(comment.end as usize..declaration_start as usize)?) {
        return None;
    }
    let raw = source.get(comment.start as usize..comment.end as usize)?;
    if !raw.starts_with("/**") {
        return None;
    }
    let description = deprecated_description(raw)?;
    contains_explicit_version(&description).then_some(comment)
}

fn is_attached_gap(gap: &str) -> bool {
    let mut newlines = 0;
    let mut characters = gap.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' => {}
            '\n' => newlines += 1,
            '\r' if characters.peek() == Some(&'\n') => {
                characters.next();
                newlines += 1;
            }
            _ => return false,
        }
    }
    newlines <= 1
}

fn deprecated_description(raw: &str) -> Option<String> {
    let body = raw.strip_prefix("/**")?.strip_suffix("*/")?;
    let lines = body.lines().map(normalize_jsdoc_line).collect::<Vec<_>>();
    let mut descriptions = Vec::new();
    let mut current = None::<String>;

    for line in lines {
        if let Some((tag, rest)) = jsdoc_tag(line) {
            if let Some(description) = current.take() {
                descriptions.push(description);
            }
            if tag == "deprecated" {
                current = Some(strip_inline_tag(rest).trim().to_string());
            }
        } else if let Some(description) = current.as_mut() {
            let continuation = strip_inline_tag(line).trim();
            if !continuation.is_empty() {
                if !description.is_empty() {
                    description.push(' ');
                }
                description.push_str(continuation);
            }
        }
    }
    if let Some(description) = current {
        descriptions.push(description);
    }

    let [description] = descriptions.as_slice() else {
        return None;
    };
    (!description.is_empty()).then(|| description.clone())
}

fn normalize_jsdoc_line(line: &str) -> &str {
    let line = line.trim_start();
    let line = line.strip_prefix('*').unwrap_or(line);
    line.strip_prefix(' ').unwrap_or(line).trim_end()
}

fn jsdoc_tag(line: &str) -> Option<(&str, &str)> {
    let tag = line.strip_prefix('@')?;
    let end = tag
        .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .unwrap_or(tag.len());
    if end == 0 {
        return None;
    }
    let (name, rest) = tag.split_at(end);
    Some((name, rest.trim_start()))
}

fn strip_inline_tag(text: &str) -> &str {
    let bytes = text.as_bytes();
    for index in 1..bytes.len() {
        if bytes[index] == b'@'
            && bytes[index - 1].is_ascii_whitespace()
            && bytes.get(index + 1).is_some_and(u8::is_ascii_alphabetic)
        {
            return text[..index].trim_end();
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_one_versioned_deprecated_tag() {
        assert_eq!(
            deprecated_description(
                "/**\n * Use current instead.\n * @deprecated remove after v3.1\n * @since 1.0\n */"
            )
            .as_deref(),
            Some("remove after v3.1")
        );
        assert!(deprecated_description("/** @deprecated use current */").is_some());
        assert!(deprecated_description("/** @deprecated v2 @since 1.0 */").is_some());
        assert!(deprecated_description("/** @deprecated v2\n * @deprecated v3 */").is_none());
    }
}
