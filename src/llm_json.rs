use super::llm_text::truncate_for_log;

#[path = "llm_json_span.rs"]
mod span;

fn strip_json_fences(content: &str) -> &str {
    let mut parsed_target = content.trim();
    if let Some(rest) = parsed_target.strip_prefix("```json") {
        parsed_target = rest;
    } else if let Some(rest) = parsed_target.strip_prefix("```") {
        parsed_target = rest;
    }
    if let Some(rest) = parsed_target.strip_suffix("```") {
        parsed_target = rest;
    }
    parsed_target.trim()
}

fn find_json_object(content: &str) -> Option<serde_json::Value> {
    content
        .char_indices()
        .filter(|(_, ch)| *ch == '{')
        .find_map(|(idx, _)| {
            let slice = &content[idx..];
            let mut stream =
                serde_json::Deserializer::from_str(slice).into_iter::<serde_json::Value>();
            stream
                .next()
                .and_then(Result::ok)
                .and_then(|val| val.is_object().then_some(val))
        })
}

fn coerce_json_object(value: serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => {
            if object_looks_like_result(&map) {
                return Some(serde_json::Value::Object(map));
            }

            for nested in map.values() {
                if let Some(obj) = coerce_json_object(nested.clone()) {
                    return Some(obj);
                }
            }

            Some(serde_json::Value::Object(map))
        }
        serde_json::Value::String(s) => extract_json_object(&s).ok(),
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(obj) = coerce_json_object(item) {
                    return Some(obj);
                }
            }
            None
        }
        _ => None,
    }
}

fn object_looks_like_result(map: &serde_json::Map<String, serde_json::Value>) -> bool {
    map.contains_key("smelly")
        || map.contains_key("tier")
        || map.contains_key("reason")
        || map.contains_key("evidence")
        || map.contains_key("role")
        || map.contains_key("verdict")
        || map.contains_key("reviews")
        || map.contains_key("cases")
        || map.contains_key("decisions")
}

fn repair_unclosed_object(content: &str) -> Option<String> {
    let mut start_idx = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in content.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if start_idx.is_none() {
                    start_idx = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    let start_idx = start_idx?;
    if depth == 0 {
        return None;
    }

    let mut candidate = content[start_idx..].trim().to_string();
    if in_string {
        // Model output is sometimes cut off in the middle of an evidence or
        // reason string. Close the string before balancing object braces.
        if escaped {
            candidate.push('\\');
        }
        candidate.push('"');
    }
    while candidate.trim_end().ends_with(',') {
        candidate.truncate(candidate.trim_end().len() - 1);
    }
    candidate.extend(std::iter::repeat_n('}', depth));
    Some(candidate)
}

fn sanitize_json_strings(content: &str) -> Option<String> {
    let mut escaped_content = String::with_capacity(content.len());
    let mut in_string = false;
    let mut changed = false;

    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_string {
            match ch {
                '\\' => {
                    let Some(next) = chars.peek().copied() else {
                        escaped_content.push_str("\\\\");
                        changed = true;
                        continue;
                    };

                    if matches!(next, '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u') {
                        escaped_content.push('\\');
                        escaped_content.push(next);
                        chars.next();
                    } else {
                        // Models sometimes describe a path with prose such as
                        // "\\?\\C:". Preserve that prose by escaping only the
                        // invalid JSON backslash instead of discarding the reply.
                        escaped_content.push_str("\\\\");
                        changed = true;
                    }
                }
                '"' => {
                    escaped_content.push(ch);
                    in_string = false;
                }
                '\n' => {
                    escaped_content.push_str("\\n");
                    changed = true;
                }
                '\r' => {
                    escaped_content.push_str("\\r");
                    changed = true;
                }
                '\t' => {
                    escaped_content.push_str("\\t");
                    changed = true;
                }
                ch if ch.is_control() => {
                    escaped_content.push_str(&format!("\\u{:04x}", ch as u32));
                    changed = true;
                }
                _ => escaped_content.push(ch),
            }
            continue;
        }

        escaped_content.push(ch);
        if ch == '"' {
            in_string = true;
        }
    }

    changed.then_some(escaped_content)
}

fn parse_json_object_candidate(content: &str) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
        && let Some(obj) = coerce_json_object(value)
    {
        return Some(obj);
    }

    if let Some(val) = find_json_object(content) {
        return Some(val);
    }

    if let Some(span) = span::find_balanced_json_span(content)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(span)
        && let Some(obj) = coerce_json_object(value)
    {
        return Some(obj);
    }

    if let Some(repaired) = repair_unclosed_object(content)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&repaired)
        && let Some(obj) = coerce_json_object(value)
    {
        return Some(obj);
    }

    None
}

pub(super) fn extract_json_object(content: &str) -> Result<serde_json::Value, String> {
    let content = content.trim();
    if content.is_empty() {
        return Err("Empty response content".to_string());
    }

    let parsed_target = strip_json_fences(content);
    if let Some(obj) = parse_json_object_candidate(parsed_target) {
        return Ok(obj);
    }

    if let Some(sanitized) = sanitize_json_strings(parsed_target)
        && let Some(obj) = parse_json_object_candidate(&sanitized)
    {
        return Ok(obj);
    }

    Err(format!(
        "No JSON object found in response. Raw output: {}",
        truncate_for_log(content, 100)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_object_handles_fenced_json() {
        let content = "```json\n{\"smelly\":true,\"tier\":\"slop\"}\n```";
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
    }

    #[test]
    fn extract_json_object_handles_json_embedded_in_chatter() {
        let content = "Sure, here you go:\n{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}\nThanks!";
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert_eq!(value["reason"], "function is too big");
    }

    #[test]
    fn extract_json_object_handles_array_wrapped_json() {
        let content = "```json\n[{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}]\n```";
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert_eq!(value["reason"], "function is too big");
    }

    #[test]
    fn extract_json_object_repairs_unclosed_json_object() {
        let content = "{\n  \"smelly\": true,\n  \"tier\": \"slop\",\n  \"evidence\": \"fn demo()\",\n  \"reason\": \"function is too big\"\n";
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert_eq!(value["reason"], "function is too big");
    }

    #[test]
    fn extract_json_object_repairs_truncated_string_before_balancing() {
        let content = r#"{"smelly":true,"tier":"slop","evidence":"return total","reason":"function is too big"#;
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert_eq!(value["reason"], "function is too big");
    }

    #[test]
    fn extract_json_object_repairs_trailing_comma_before_balancing() {
        let content = r#"{"smelly":false,"tier":"clean","evidence":"","reason":"clean","#;
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "clean");
    }

    #[test]
    fn extract_json_object_salvages_newlines_inside_strings() {
        let content = "{\n  \"smelly\": true,\n  \"tier\": \"slop\",\n  \"evidence\": \"build_output_payload(\n    status=status,\n    body=payload\n  )\",\n  \"reason\": \"function is too big\"\n}";
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert!(
            value["evidence"]
                .as_str()
                .unwrap()
                .contains("build_output_payload(")
        );
    }

    #[test]
    fn extract_json_object_repairs_invalid_backslash_escapes_in_strings() {
        let content = r#"{"smelly":false,"tier":"clean","pattern":"none","intent":"Strip prefix (\?\\C:)","reason":"clean","necessity_check":"necessary","evidence":[]}"#;
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "clean");
        assert!(value["intent"].as_str().unwrap().contains("\\?"));
    }

    #[test]
    fn extract_json_object_unwraps_openai_style_content_wrappers() {
        let content = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"fn demo()\",\"reason\":\"function is too big\"}"}}]}"#;
        let value = extract_json_object(content).unwrap();
        assert_eq!(value["tier"], "slop");
        assert_eq!(value["reason"], "function is too big");
    }

    #[test]
    fn extract_json_object_preserves_batch_review_roots() {
        let content = r#"{"reviews":[{"method_key":"m0","tier":"clean"},{"method_key":"m1","tier":"clean"}]}"#;
        let value = extract_json_object(content).unwrap();

        assert_eq!(value["reviews"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn extract_json_object_preserves_case_and_adjudication_roots() {
        let cases = r#"{"cases":[{"case_id":"a","tier":"slop"}]}"#;
        let decisions = r#"{"decisions":[{"case_id":"a","decision":"keep","reason":"verified"}]}"#;

        let cases_value = extract_json_object(cases).unwrap();
        let decisions_value = extract_json_object(decisions).unwrap();

        assert_eq!(cases_value["cases"].as_array().unwrap().len(), 1);
        assert_eq!(decisions_value["decisions"].as_array().unwrap().len(), 1);
    }
}
