fn string_from_array(items: &[serde_json::Value]) -> Option<String> {
    let parts: Vec<String> = items
        .iter()
        .filter_map(string_from_value)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(""))
    }
}

fn string_from_object(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    ["text", "content", "value", "output"]
        .iter()
        .find_map(|key| {
            map.get(*key)
                .and_then(string_from_value)
                .filter(|part| !part.is_empty())
        })
}

fn string_from_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(items) => string_from_array(items),
        serde_json::Value::Object(map) => string_from_object(map),
        _ => None,
    }
}

pub(super) fn openai_content(data: &serde_json::Value) -> String {
    let candidates = [
        "/choices/0/message/content",
        "/choices/0/text",
        "/choices/0/message/output",
        "/output_text",
        "/content",
        "/message/content",
    ];

    for candidate in candidates {
        if let Some(value) = data.pointer(candidate)
            && let Some(text) = string_from_value(value)
            && !text.trim().is_empty()
        {
            return text;
        }
    }

    String::new()
}

pub(super) fn anthropic_content(data: &serde_json::Value) -> String {
    let candidates = ["/content", "/choices/0/message/content", "/output_text"];

    for candidate in candidates {
        if let Some(value) = data.pointer(candidate)
            && let Some(text) = string_from_value(value)
            && !text.trim().is_empty()
        {
            return text;
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_content_handles_string_and_array_shapes() {
        let data = serde_json::json!({
            "choices": [
                {
                    "message": {
                        "content": [
                            { "type": "text", "text": "{\"smelly\":false}" }
                        ]
                    }
                }
            ]
        });

        assert_eq!(openai_content(&data), "{\"smelly\":false}");
    }

    #[test]
    fn anthropic_content_handles_block_arrays() {
        let data = serde_json::json!({
            "content": [
                { "type": "text", "text": "{\"smelly\":false}" }
            ]
        });

        assert_eq!(anthropic_content(&data), "{\"smelly\":false}");
    }

    #[test]
    fn anthropic_content_ignores_thinking_blocks() {
        let data = serde_json::json!({
            "content": [
                {
                    "type": "thinking",
                    "thinking": "I will think out loud here."
                },
                {
                    "type": "text",
                    "text": "{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"
                }
            ]
        });

        assert_eq!(
            anthropic_content(&data),
            "{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"reason\":\"clean\"}"
        );
    }
}
