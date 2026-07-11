pub(super) fn token_count_for_text(text: &str) -> usize {
    (text.len() as f64 / 4.0).ceil() as usize
}

pub(super) fn openai_usage(
    data: &serde_json::Value,
    prompt: &str,
    content: &str,
) -> (usize, usize) {
    let usage = data.get("usage");
    let in_t = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(prompt));
    let out_t = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(content));
    (in_t, out_t)
}

pub(super) fn anthropic_usage(
    data: &serde_json::Value,
    prompt: &str,
    content: &str,
) -> (usize, usize) {
    let usage = data.get("usage");
    let in_t = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(prompt));
    let out_t = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(content));
    (in_t, out_t)
}
