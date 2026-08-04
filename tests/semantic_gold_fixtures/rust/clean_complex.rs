pub fn clean_parse_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            current.push(ch);
            escaped = true;
        } else if ch == '"' {
            current.push(ch);
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

pub fn clean_validate_contract(result: &serde_json::Value) -> &str {
    let tier = result.get("tier").and_then(|value| value.as_str()).unwrap_or("");
    let smelly = result.get("smelly").and_then(|value| value.as_bool()).unwrap_or(false);
    if smelly != (tier != "clean") {
        panic!("tier and smelly disagree");
    }
    tier
}

pub fn kinda_forward_payload(payload: Payload) -> Payload {
    let forwarded = payload;
    forwarded
}
