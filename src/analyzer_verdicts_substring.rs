pub(crate) fn evidence_is_exact_substring(source: &str, evidence: &str) -> bool {
    let trimmed = evidence.trim();
    !trimmed.is_empty() && source.contains(trimmed)
}
