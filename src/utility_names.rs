const PREFIXES: &[&str] = &[
    "file",
    "classify",
    "intentional",
    "duplicate",
    "test",
    "contains",
    "starts",
    "is",
    "get",
    "set",
    "build",
    "make",
    "parse",
    "resolve",
    "collect",
    "emit",
    "render",
    "default",
    "json",
    "push",
    "record",
    "scan",
    "normalize",
    "count",
    "match",
    "same",
    "has",
    "method",
    "score",
    "walk",
    "format",
    "as",
];

const SUFFIXES: &[&str] = &[
    "_flags", "_label", "_report", "_helpers", "_helper", "_paths", "_key",
];

fn has_prefix(name: &str) -> bool {
    PREFIXES.iter().any(|prefix| {
        if name == *prefix {
            return true;
        }

        let Some(rest) = name.strip_prefix(prefix) else {
            return false;
        };

        rest.starts_with('_')
            || rest
                .chars()
                .next()
                .map(|ch| ch.is_uppercase())
                .unwrap_or(false)
    })
}

fn has_suffix(lower: &str) -> bool {
    SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

pub fn is_utility_helper_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    has_prefix(name) || has_suffix(&lower) || lower.contains("expands_to")
}
