pub(super) fn openai_payload(model: &str, sys_ctx: &str, prompt: &str) -> serde_json::Value {
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

    serde_json::json!({
        "model": model,
        "temperature": 0,
        "max_tokens": 1024,
        "stream": false,
        "thinking": {"type": "disabled"},
        "messages": messages,
        "response_format": {"type": "json_object"}
    })
}

pub(super) fn anthropic_payload(model: &str, sys_ctx: &str, prompt: &str) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "model": model,
        "temperature": 0,
        "max_tokens": 1024,
        "stream": false,
        "thinking": {"type": "disabled"},
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
    fn openai_payload_disables_thinking() {
        let payload = openai_payload("test-model", "system", "prompt");
        assert_eq!(payload["thinking"]["type"], "disabled");
        assert_eq!(payload["response_format"]["type"], "json_object");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["max_tokens"], 1024);
    }

    #[test]
    fn anthropic_payload_disables_thinking() {
        let payload = anthropic_payload("test-model", "system", "prompt");
        assert_eq!(payload["thinking"]["type"], "disabled");
        assert_eq!(payload["messages"][0]["role"], "user");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["max_tokens"], 1024);
    }
}
