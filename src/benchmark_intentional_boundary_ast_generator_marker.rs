use super::IntentionalBoundarySemanticRange;

pub(super) fn exact_generator_marker(
    repository_path: &str,
    source: &str,
) -> Option<IntentionalBoundarySemanticRange> {
    if repository_path.ends_with(".go") {
        return exact_go_generator_marker(repository_path, source);
    }
    source
        .lines()
        .take(20)
        .enumerate()
        .find_map(|(line, text)| {
            let leading = text.len().saturating_sub(text.trim_start().len());
            let trimmed = text.trim();
            let payload = trimmed
                .strip_prefix("//")
                .or_else(|| trimmed.strip_prefix('#'))
                .map(str::trim)
                .or_else(|| {
                    trimmed
                        .strip_prefix("/*")
                        .and_then(|value| value.strip_suffix("*/"))
                        .map(str::trim)
                })?;
            let exact_marker = payload == "@generated"
                || (payload.starts_with("Code generated ") && payload.ends_with(" DO NOT EDIT."));
            exact_marker.then(|| IntentionalBoundarySemanticRange {
                repository_path: repository_path.to_string(),
                start_line_zero_based: line as u32,
                start_character_zero_based: leading as u32,
                end_line_zero_based: line as u32,
                end_character_zero_based: text.len() as u32,
            })
        })
}

fn exact_go_generator_marker(
    repository_path: &str,
    source: &str,
) -> Option<IntentionalBoundarySemanticRange> {
    let mut in_block_comment = false;
    for (line, raw_text) in source.lines().enumerate() {
        let text = raw_text.strip_suffix('\r').unwrap_or(raw_text);
        if !in_block_comment
            && text.starts_with("// Code generated ")
            && text.ends_with(" DO NOT EDIT.")
        {
            return Some(IntentionalBoundarySemanticRange {
                repository_path: repository_path.to_string(),
                start_line_zero_based: line as u32,
                start_character_zero_based: 0,
                end_line_zero_based: line as u32,
                end_character_zero_based: text.len() as u32,
            });
        }
        if !go_line_is_comment_or_blank(text, &mut in_block_comment) {
            return None;
        }
    }
    None
}

fn go_line_is_comment_or_blank(mut text: &str, in_block_comment: &mut bool) -> bool {
    loop {
        text = text.trim_start();
        if text.is_empty() {
            return true;
        }
        if *in_block_comment {
            let Some((_, remainder)) = text.split_once("*/") else {
                return true;
            };
            *in_block_comment = false;
            text = remainder;
            continue;
        }
        if text.starts_with("//") {
            return true;
        }
        if let Some(remainder) = text.strip_prefix("/*") {
            *in_block_comment = true;
            text = remainder;
            continue;
        }
        return false;
    }
}
