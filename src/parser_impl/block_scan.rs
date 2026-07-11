pub(super) fn scan_block_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0isize;
    let mut started = false;
    let mut in_block_comment = false;
    let mut in_string: Option<char> = None;
    let mut escape = false;

    for (idx, line) in lines.iter().enumerate().skip(start) {
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
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
                    started = true;
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
