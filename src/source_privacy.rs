use crate::types::FileRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretFinding {
    pub(crate) file_path: String,
    pub(crate) line: usize,
    pub(crate) kind: &'static str,
}

/// Detect only high-confidence credential shapes before source can leave the
/// machine. This is a transmission guard, not a general secret scanner.
pub(crate) fn find_likely_secrets(files: &[FileRecord]) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    for file in files {
        for (line_index, line) in file.source.lines().enumerate() {
            if let Some(kind) = high_confidence_token_kind(line) {
                findings.push(SecretFinding {
                    file_path: file.file_path.clone(),
                    line: line_index + 1,
                    kind,
                });
            }
        }
    }
    findings.sort_by(|left, right| {
        (&left.file_path, left.line, left.kind).cmp(&(&right.file_path, right.line, right.kind))
    });
    findings.dedup();
    findings
}

fn high_confidence_token_kind(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if trimmed.contains("-----BEGIN ") && trimmed.contains(" PRIVATE KEY-----") {
        return Some("private key");
    }

    for (prefix, kind, minimum_suffix_length) in [
        ("ghp_", "GitHub token", 20),
        ("gho_", "GitHub OAuth token", 20),
        ("github_pat_", "GitHub fine-grained token", 20),
        ("xoxb-", "Slack bot token", 20),
        ("xoxp-", "Slack user token", 20),
        ("AIza", "Google API key", 35),
        ("AKIA", "AWS access key", 16),
    ] {
        if line
            .split(|character: char| {
                !character.is_ascii_alphanumeric() && character != '_' && character != '-'
            })
            .any(|token| {
                token
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.len() >= minimum_suffix_length)
            })
        {
            return Some(kind);
        }
    }

    let lower = trimmed.to_ascii_lowercase();
    let has_secret_name = [
        "api_key",
        "apikey",
        "secret",
        "password",
        "access_token",
        "auth_token",
    ]
    .iter()
    .any(|name| lower.contains(name));
    let has_assignment = trimmed.contains('=') || trimmed.contains(':');
    let quoted_value = trimmed.contains('"') || trimmed.contains('\'');
    if has_secret_name && has_assignment && quoted_value {
        let value = trimmed
            .split(['=', ':'])
            .nth(1)
            .map(str::trim)
            .unwrap_or("");
        let lower_value = value.to_ascii_lowercase();
        if lower_value.contains("environ")
            || lower_value.contains("process.env")
            || value.contains('$')
            || value.contains("${")
        {
            return None;
        }
        let value_length = value
            .trim_matches(|character: char| {
                character == '"' || character == '\'' || character == ',' || character == ';'
            })
            .len();
        if value_length >= 20 {
            return Some("credential-like assignment");
        }
    }
    None
}

pub(crate) fn reject_likely_secrets(files: &[FileRecord]) -> Result<(), String> {
    let findings = find_likely_secrets(files);
    if findings.is_empty() {
        return Ok(());
    }
    let locations = findings
        .iter()
        .map(|finding| format!("{}:{} ({})", finding.file_path, finding.line, finding.kind))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "likely credential material detected before remote analysis: {locations}; remove or redact it before running Sniff"
    ))
}

#[cfg(test)]
mod tests {
    use super::{find_likely_secrets, reject_likely_secrets};
    use crate::types::FileRecord;

    fn file(source: &str) -> FileRecord {
        FileRecord {
            file_path: "src/config.py".to_string(),
            source: source.to_string(),
            language: "python".to_string(),
            methods: Vec::new(),
        }
    }

    #[test]
    fn detects_high_confidence_credentials_without_echoing_values() {
        let files = vec![file(
            "PRIVATE = \"ghp_123456789012345678901234567890123456\"\n\
             KEY = \"-----BEGIN RSA PRIVATE KEY-----\"\n",
        )];

        let findings = find_likely_secrets(&files);

        assert_eq!(findings.len(), 2);
        let error = reject_likely_secrets(&files).unwrap_err();
        assert!(error.contains("src/config.py:1"));
        assert!(error.contains("src/config.py:2"));
        assert!(!error.contains("123456789012345678901234567890123456"));
    }

    #[test]
    fn does_not_block_environment_references_or_short_test_values() {
        let files = vec![file(
            "api_key = os.environ[\"SNIFF_API_KEY\"]\n\
             password = \"test-value\"\n\
             token = \"${TOKEN}\"\n",
        )];

        assert!(find_likely_secrets(&files).is_empty());
        assert!(reject_likely_secrets(&files).is_ok());
    }
}
