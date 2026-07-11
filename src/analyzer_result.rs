use crate::report_types::LLMVerdict;
use crate::types::FindingTier;

pub(crate) fn parse_result_fields(
    result: &serde_json::Value,
) -> (FindingTier, String, String, Option<bool>, Option<bool>) {
    let smelly = result
        .get("smelly")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tier = match result.get("tier").and_then(|v| v.as_str()) {
        Some("slop") => FindingTier::Slop,
        Some("kinda_slop") => FindingTier::KindaSlop,
        Some("clean") => FindingTier::Clean,
        _ if smelly => FindingTier::Slop,
        _ => FindingTier::Clean,
    };
    let evidence = result
        .get("evidence")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let reason = result
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let cohesive = result.get("cohesive").and_then(|v| v.as_bool());
    let name_accurate = result.get("name_accurate").and_then(|v| v.as_bool());
    (tier, evidence, reason, cohesive, name_accurate)
}

pub(crate) fn build_method_verdict(
    result: &serde_json::Value,
    file_path: &str,
    method_name: &str,
    loc: usize,
    start_line: usize,
    end_line: usize,
) -> LLMVerdict {
    let (tier, evidence, reason, _, _) = parse_result_fields(result);
    LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: file_path.to_string(),
        method_name: Some(method_name.to_string()),
        check_type: "method".to_string(),
        smelly: !matches!(tier, FindingTier::Clean),
        tier,
        cohesive: None,
        name_accurate: None,
        evidence,
        reason,
        loc,
        start_line,
        end_line,
    }
}

pub(crate) fn build_file_verdict(result: &serde_json::Value, file_path: &str) -> LLMVerdict {
    let (tier, evidence, reason, cohesive, name_accurate) = parse_result_fields(result);
    LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file_path.to_string(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: !matches!(tier, FindingTier::Clean),
        tier,
        cohesive,
        name_accurate,
        evidence,
        reason,
        loc: 0,
        start_line: 0,
        end_line: 0,
    }
}

pub(crate) fn evidence_is_exact_substring(source: &str, evidence: &str) -> bool {
    let trimmed = evidence.trim();
    if trimmed.is_empty() {
        return false;
    }

    if source.contains(trimmed) {
        return true;
    }

    fn strip_whitespace(text: &str) -> String {
        text.chars().filter(|ch| !ch.is_whitespace()).collect()
    }

    let normalized_source = strip_whitespace(source);
    let normalized_evidence = strip_whitespace(trimmed);
    !normalized_evidence.is_empty() && normalized_source.contains(&normalized_evidence)
}

#[cfg(test)]
mod tests {
    use super::evidence_is_exact_substring;

    #[test]
    fn evidence_match_accepts_exact_substrings() {
        assert!(evidence_is_exact_substring(
            "def demo(value):\n    return value\n",
            "def demo(value):"
        ));
    }

    #[test]
    fn evidence_match_accepts_whitespace_variants() {
        assert!(evidence_is_exact_substring(
            "def extract_python_signatures(items):\n    return 1\n",
            "def  extract_python_signatures( items ) :"
        ));
    }

    #[test]
    fn evidence_match_rejects_missing_text() {
        assert!(!evidence_is_exact_substring(
            "def demo(value):\n    return value\n",
            "def other(value):"
        ));
    }
}
