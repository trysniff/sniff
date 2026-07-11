use super::llm_text::truncate_for_log;

pub(super) fn build_repair_prompt(
    original_prompt: &str,
    bad_response: &str,
    schema: super::ResponseSchema,
    failure: &str,
) -> String {
    let prompt_excerpt = truncate_for_log(original_prompt, 3800);
    let snippet = truncate_for_log(bad_response.trim(), 800);

    format!(
        "{prompt_excerpt}\n\nYour previous answer was not valid JSON for this request ({failure}). \
Return exactly one JSON object and no extra text. \
{schema_desc}\n\
If you need to correct the previous output, use this failed response as the only context:\n---\n{snippet}\n---",
        schema_desc = super::llm_transport::schema_description(schema)
    )
}
