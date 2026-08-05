pub(super) fn openai_payload(
    model: &str,
    sys_ctx: &str,
    prompt: &str,
    use_max_completion_tokens: bool,
    disable_deepseek_thinking: bool,
) -> serde_json::Value {
    let mut messages = Vec::new();
    if !sys_ctx.is_empty() {
        messages.push(serde_json::json!({
            "role": "system",
            "content": sys_ctx
        }));
    }
    messages.push(serde_json::json!({
        "role": "user",
        "content": prompt
    }));

    let mut payload = serde_json::json!({
        "model": model,
        "temperature": 0,
        "stream": false,
        "messages": messages,
        "response_format": {"type": "json_object"}
    });
    let token_field = if use_max_completion_tokens {
        "max_completion_tokens"
    } else {
        "max_tokens"
    };
    payload[token_field] = serde_json::json!(4096);
    if disable_deepseek_thinking {
        payload["thinking"] = serde_json::json!({"type": "disabled"});
    }
    payload
}

pub(super) fn anthropic_payload(model: &str, sys_ctx: &str, prompt: &str) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "model": model,
        "max_tokens": 4096,
        "stream": false,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    }
                ]
            }
        ]
    });

    if !sys_ctx.is_empty() {
        payload["system"] = serde_json::Value::String(sys_ctx.to_string());
    }

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deepseek_payload_disables_thinking_and_uses_max_tokens() {
        let payload = openai_payload("test-model", "system", "prompt", false, true);
        assert_eq!(payload["thinking"]["type"], "disabled");
        assert_eq!(payload["max_tokens"], 4096);
        assert_eq!(payload["response_format"]["type"], "json_object");
        assert_eq!(payload["stream"], false);
    }

    #[test]
    fn openai_payload_uses_current_completion_limit_field() {
        let payload = openai_payload("test-model", "system", "prompt", true, false);
        assert_eq!(payload["max_completion_tokens"], 4096);
        assert!(payload.get("max_tokens").is_none());
        assert!(payload.get("thinking").is_none());
    }

    #[test]
    fn anthropic_payload_omits_optional_sampling_and_thinking_fields() {
        let payload = anthropic_payload("test-model", "system", "prompt");
        assert_eq!(payload["messages"][0]["role"], "user");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["max_tokens"], 4096);
        assert!(payload.get("thinking").is_none());
        assert!(payload.get("temperature").is_none());
    }
}
