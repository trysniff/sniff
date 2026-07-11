pub(super) fn truncate_for_log(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }

    let head = max_chars.min(160);
    let tail = max_chars.saturating_sub(head);
    let head_text: String = text.chars().take(head).collect();
    let tail_text: String = text
        .chars()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if tail_text.is_empty() {
        format!("{head_text}...")
    } else {
        format!("{head_text}...{tail_text}")
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_for_log;

    #[test]
    fn truncate_for_log_preserves_utf8_boundaries() {
        let text = "αβγδεζηθικλμνξοπρστυφχψω";
        let output = truncate_for_log(text, 5);
        assert!(output.chars().count() <= 9);
        assert!(output.starts_with('α'));
    }
}
