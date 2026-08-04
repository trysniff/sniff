pub(super) fn token_count_for_text(text: &str) -> usize {
    (text.len() as f64 / 4.0).ceil() as usize
}

pub(super) fn openai_usage(
    data: &serde_json::Value,
    prompt: &str,
    content: &str,
) -> (usize, usize, usize) {
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
    let cached_t = usage
        .and_then(|u| u.get("prompt_cache_hit_tokens"))
        .or_else(|| {
            usage
                .and_then(|u| u.get("prompt_tokens_details"))
                .and_then(|details| details.get("cached_tokens"))
        })
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(0)
        .min(in_t);
    (in_t, out_t, cached_t)
}

pub(super) fn anthropic_usage(
    data: &serde_json::Value,
    prompt: &str,
    content: &str,
) -> (usize, usize, usize) {
    let usage = data.get("usage");
    let direct_in_t = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(prompt));
    let cached_t = usage
        .and_then(|u| u.get("cache_read_input_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(0);
    let cache_write_t = usage
        .and_then(|u| u.get("cache_creation_input_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(0);
    let in_t = direct_in_t
        .saturating_add(cached_t)
        .saturating_add(cache_write_t);
    let out_t = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or_else(|| token_count_for_text(content));
    (in_t, out_t, cached_t)
}

#[cfg(test)]
mod tests {
    #[test]
    fn openai_usage_reads_deepseek_cache_hits() {
        let data = serde_json::json!({
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 40,
                "prompt_cache_hit_tokens": 750,
                "prompt_cache_miss_tokens": 250
            }
        });

        assert_eq!(super::openai_usage(&data, "", ""), (1_000, 40, 750));
    }

    #[test]
    fn openai_usage_reads_nested_cached_tokens() {
        let data = serde_json::json!({
            "usage": {
                "prompt_tokens": 900,
                "completion_tokens": 30,
                "prompt_tokens_details": {"cached_tokens": 600}
            }
        });

        assert_eq!(super::openai_usage(&data, "", ""), (900, 30, 600));
    }

    #[test]
    fn anthropic_usage_includes_cache_reads_and_writes_in_total_input() {
        let data = serde_json::json!({
            "usage": {
                "input_tokens": 100,
                "cache_read_input_tokens": 700,
                "cache_creation_input_tokens": 200,
                "output_tokens": 50
            }
        });

        assert_eq!(super::anthropic_usage(&data, "", ""), (1_000, 50, 700));
    }
}
