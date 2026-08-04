use super::llm_text::truncate_for_log;

pub(super) fn build_repair_prompt(
    original_prompt: &str,
    bad_response: &str,
    schema: super::ResponseSchema,
    failure: &str,
) -> String {
    let batch_schema = matches!(
        schema,
        super::ResponseSchema::MethodIntentBatchReview
            | super::ResponseSchema::SemanticMethodBatchReview
    );
    let has_response = !bad_response.trim().is_empty();
    let prompt_excerpt = if batch_schema && has_response {
        "Repair the response format without repeating the repository investigation.".to_string()
    } else {
        truncate_for_log(original_prompt, 3800)
    };
    // Batch responses can contain several independently valid method records.
    // Preserve them for a cheap format-only repair instead of retransmitting
    // the much larger source and repository dossier.
    let response_limit = if batch_schema { 32_000 } else { 800 };
    let snippet = truncate_for_log(bad_response.trim(), response_limit);

    format!(
        "{prompt_excerpt}\n\nYour previous answer was not valid JSON for this request ({failure}). \
        Return exactly one JSON object and no extra text. Escape every backslash inside a JSON string as `\\\\`; for example, a Windows prefix must be written as `\\\\?\\\\C:` rather than `\\?\\C:`. \
{schema_desc}\n\
If you need to correct the previous output, use this failed response as the only context:\n---\n{snippet}\n---",
        schema_desc = super::llm_transport::schema_description(schema)
    )
}

#[cfg(test)]
mod tests {
    use super::super::ResponseSchema;

    #[test]
    fn batch_format_repairs_do_not_resend_the_complete_evidence_packet() {
        let sentinel = "FOURTH_METHOD_CONTEXT";
        let original = format!("{}{sentinel}{}", "x".repeat(1000), "x".repeat(4000));
        let response = format!("{{\"reviews\":[{{\"reason\":\"{sentinel}\"}}]}}");

        let repaired = super::build_repair_prompt(
            &original,
            &response,
            ResponseSchema::SemanticMethodBatchReview,
            "missing fields: reviews",
        );

        assert!(!repaired.contains(&"x".repeat(1000)));
        assert!(repaired.contains(sentinel));
        assert!(repaired.contains("without repeating the repository investigation"));
    }

    #[test]
    fn empty_batch_responses_keep_enough_original_context_to_retry() {
        let sentinel = "METHOD_EVIDENCE_SENTINEL";
        let original = format!("evidence: {sentinel}");

        let repaired = super::build_repair_prompt(
            &original,
            "",
            ResponseSchema::SemanticMethodBatchReview,
            "empty response",
        );

        assert!(repaired.contains(sentinel));
    }

    #[test]
    fn ordinary_repairs_still_bound_prompt_growth() {
        let sentinel = "MIDDLE_OF_LONG_PROMPT";
        let original = format!("{}{sentinel}{}", "x".repeat(1000), "x".repeat(4000));

        let repaired = super::build_repair_prompt(
            &original,
            "{}",
            ResponseSchema::SemanticMethodReview,
            "missing fields: tier",
        );

        assert!(!repaired.contains(sentinel));
    }
}
