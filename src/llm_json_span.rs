pub(super) fn find_balanced_json_span(content: &str) -> Option<&str> {
    let mut start_idx: Option<usize> = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in content.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => {
                    escaped = true;
                }
                '"' => {
                    in_string = false;
                }
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
            }
            '{' => {
                if depth == 0 {
                    start_idx = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                if depth == 0
                    && let Some(start) = start_idx
                {
                    let end = idx + ch.len_utf8();
                    return content.get(start..end);
                }
            }
            _ => {}
        }
    }

    None
}
