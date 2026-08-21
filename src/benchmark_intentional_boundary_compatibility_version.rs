pub(super) fn contains_explicit_version(notice: &str) -> bool {
    let tokens = notice
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+'))
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    tokens.iter().any(|token| version_token(token))
        || tokens.windows(2).any(|pair| {
            pair[0].eq_ignore_ascii_case("version") && unsigned_integer(pair[1].trim_matches('.'))
        })
}

fn version_token(token: &str) -> bool {
    let token = token.trim_matches('.');
    let stable = token.split_once('-').map_or(token, |(value, _)| value);
    let stable = stable.split_once('+').map_or(stable, |(value, _)| value);
    let (prefixed, numeric) = match stable.strip_prefix('v') {
        Some(value) => (true, value),
        None => (false, stable),
    };
    if numeric.is_empty() || (!prefixed && !numeric.contains('.')) {
        return false;
    }
    numeric.split('.').all(unsigned_integer)
}

fn unsigned_integer(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_explicit_release_versions_only() {
        for notice in [
            "remove in v2",
            "remove in 2.1",
            "remove in v2.1.0-beta.1",
            "remove in version 3",
        ] {
            assert!(contains_explicit_version(notice), "{notice}");
        }
        for notice in [
            "use Current",
            "tracked by issue 123",
            "use APIv2",
            "remove eventually",
        ] {
            assert!(!contains_explicit_version(notice), "{notice}");
        }
    }
}
