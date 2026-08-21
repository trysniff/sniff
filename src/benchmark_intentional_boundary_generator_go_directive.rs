use crate::benchmark::release::IntentionalBoundaryGoGenerateDirective;
use std::collections::BTreeMap;

pub(super) fn directives_use_only_go(
    directives: &[IntentionalBoundaryGoGenerateDirective],
) -> bool {
    let mut aliases = BTreeMap::<String, String>::new();
    let mut current_file = None::<&str>;
    let mut executable_directive = false;
    for directive in directives {
        let file = directive.location.repository_path.as_str();
        if current_file != Some(file) {
            aliases.clear();
            current_file = Some(file);
        }
        let Some(body) = directive
            .source_text
            .strip_prefix("//go:generate ")
            .or_else(|| directive.source_text.strip_prefix("//go:generate\t"))
        else {
            return false;
        };
        let Some(words) = leading_words(body, 3) else {
            return false;
        };
        let Some(first) = words.first() else {
            return false;
        };
        if first == "-command" {
            let [_, alias, executable] = words.as_slice() else {
                return false;
            };
            if !stable_command_word(alias) || !stable_command_word(executable) {
                return false;
            }
            if aliases.insert(alias.clone(), executable.clone()).is_some() {
                return false;
            }
            continue;
        }
        if !stable_command_word(first) {
            return false;
        }
        let effective = aliases.get(first).unwrap_or(first);
        if effective != "go" {
            return false;
        }
        executable_directive = true;
    }
    executable_directive
}

fn leading_words(mut input: &str, limit: usize) -> Option<Vec<String>> {
    let mut words = Vec::new();
    while words.len() < limit {
        input = input.trim_start_matches([' ', '\t']);
        if input.is_empty() {
            break;
        }
        if input.starts_with('"') {
            let (word, remaining) = go_quoted_word(input)?;
            if !remaining.is_empty() && !remaining.starts_with(' ') && !remaining.starts_with('\t')
            {
                return None;
            }
            words.push(word);
            input = remaining;
            continue;
        }
        let end = input.find([' ', '\t']).unwrap_or(input.len());
        words.push(input[..end].to_string());
        input = &input[end..];
    }
    Some(words)
}

fn go_quoted_word(input: &str) -> Option<(String, &str)> {
    let bytes = input.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut output = String::new();
    let mut index = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some((output, &input[index + 1..])),
            b'\\' => {
                let (character, consumed) = go_escape(&bytes[index + 1..])?;
                output.push(character);
                index += consumed + 1;
            }
            byte if byte.is_ascii_control() => return None,
            byte if byte.is_ascii() => {
                output.push(byte as char);
                index += 1;
            }
            _ => {
                let character = input[index..].chars().next()?;
                output.push(character);
                index += character.len_utf8();
            }
        }
    }
    None
}

fn go_escape(input: &[u8]) -> Option<(char, usize)> {
    let first = *input.first()?;
    let simple = match first {
        b'a' => Some('\u{0007}'),
        b'b' => Some('\u{0008}'),
        b'f' => Some('\u{000c}'),
        b'n' => Some('\n'),
        b'r' => Some('\r'),
        b't' => Some('\t'),
        b'v' => Some('\u{000b}'),
        b'\\' => Some('\\'),
        b'"' => Some('"'),
        _ => None,
    };
    if let Some(character) = simple {
        return Some((character, 1));
    }
    match first {
        b'x' => escaped_byte(&input[1..], 2, 16).map(|value| (value, 3)),
        b'u' => escaped_scalar(&input[1..], 4, 16).map(|value| (value, 5)),
        b'U' => escaped_scalar(&input[1..], 8, 16).map(|value| (value, 9)),
        b'0'..=b'7' => escaped_byte(input, 3, 8).map(|value| (value, 3)),
        _ => None,
    }
}

fn escaped_byte(input: &[u8], digits: usize, radix: u32) -> Option<char> {
    let value = escaped_value(input, digits, radix)?;
    (value <= u8::MAX as u32)
        .then(|| char::from_u32(value))
        .flatten()
}

fn escaped_scalar(input: &[u8], digits: usize, radix: u32) -> Option<char> {
    char::from_u32(escaped_value(input, digits, radix)?)
}

fn escaped_value(input: &[u8], digits: usize, radix: u32) -> Option<u32> {
    if input.len() < digits {
        return None;
    }
    let text = std::str::from_utf8(&input[..digits]).ok()?;
    u32::from_str_radix(text, radix).ok()
}

fn stable_command_word(word: &str) -> bool {
    !word.is_empty()
        && word.is_ascii()
        && !word.contains(['$', '\0'])
        && !word.contains(['/', '\\'])
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_go_directive_tests.rs"]
mod tests;
