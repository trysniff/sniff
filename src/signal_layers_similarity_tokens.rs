pub(crate) fn normalize_identifier_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();

    while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        if ch == '/' {
            let mut lookahead = chars.clone();
            let _ = lookahead.next();
            match lookahead.next() {
                Some('/') => {
                    chars.next();
                    chars.next();
                    for next in chars.by_ref() {
                        if next == '\n' {
                            break;
                        }
                    }
                    continue;
                }
                Some('*') => {
                    chars.next();
                    chars.next();
                    let mut prev = '\0';
                    for next in chars.by_ref() {
                        if prev == '*' && next == '/' {
                            break;
                        }
                        prev = next;
                    }
                    continue;
                }
                _ => {}
            }
        }

        if ch == '#' {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            continue;
        }

        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = ch;
            chars.next();
            tokens.push("STR".to_string());
            let mut escaped = false;
            for next in chars.by_ref() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if next == '\\' {
                    escaped = true;
                    continue;
                }
                if next == quote {
                    break;
                }
            }
            continue;
        }

        if ch.is_ascii_digit() {
            tokens.push("NUM".to_string());
            chars.next();
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric()
                    || matches!(next, '.' | '_' | 'x' | 'X' | 'o' | 'O' | 'b' | 'B')
                {
                    chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        if ch.is_alphabetic() || ch == '_' {
            tokens.push("ID".to_string());
            chars.next();
            while let Some(next) = chars.peek().copied() {
                if next.is_alphanumeric() || next == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        let op = match (ch, chars.clone().nth(1)) {
            ('=', Some('>')) => Some("=>"),
            ('=', Some('=')) => Some("=="),
            ('!', Some('=')) => Some("!="),
            ('<', Some('=')) => Some("<="),
            ('>', Some('=')) => Some(">="),
            ('&', Some('&')) => Some("&&"),
            ('|', Some('|')) => Some("||"),
            (':', Some(':')) => Some("::"),
            ('-', Some('>')) => Some("->"),
            ('+', Some('=')) => Some("+="),
            ('-', Some('=')) => Some("-="),
            ('*', Some('=')) => Some("*="),
            ('/', Some('=')) => Some("/="),
            ('?', Some('?')) => Some("??"),
            ('?', Some('.')) => Some("?."),
            _ => None,
        };
        if let Some(op) = op {
            tokens.push(op.to_string());
            chars.next();
            chars.next();
            continue;
        }

        tokens.push(ch.to_string());
        chars.next();
    }

    tokens
}
