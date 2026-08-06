use super::ResponseSchema;
use super::llm_payload;
use crate::config::ResolvedConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointKind {
    OpenAi,
    Anthropic,
}

pub(super) fn endpoint_kind(config: &ResolvedConfig) -> EndpointKind {
    let endpoint = config.llm.endpoint.to_lowercase();
    if endpoint.contains("api.anthropic.com") || endpoint.contains("/anthropic") {
        EndpointKind::Anthropic
    } else {
        EndpointKind::OpenAi
    }
}

pub(super) fn request_url(config: &ResolvedConfig) -> String {
    let base = config.llm.endpoint.trim_end_matches('/');
    match endpoint_kind(config) {
        EndpointKind::OpenAi => {
            if base.ends_with("/chat/completions") {
                base.to_string()
            } else {
                format!("{}/chat/completions", base)
            }
        }
        EndpointKind::Anthropic => {
            if base.ends_with("/v1/messages") {
                base.to_string()
            } else if base.ends_with("/v1") {
                format!("{base}/messages")
            } else {
                format!("{}/v1/messages", base)
            }
        }
    }
}

pub(super) fn build_payload(
    config: &ResolvedConfig,
    prompt: &str,
) -> (serde_json::Value, reqwest::header::HeaderMap) {
    let sys_ctx = &config.llm.system_context;
    let endpoint = config.llm.endpoint.to_lowercase();
    let payload = match endpoint_kind(config) {
        EndpointKind::OpenAi => llm_payload::openai_payload(
            &config.model,
            sys_ctx,
            prompt,
            endpoint.contains("api.openai.com"),
            endpoint.contains("api.deepseek.com"),
        ),
        EndpointKind::Anthropic => llm_payload::anthropic_payload(&config.model, sys_ctx, prompt),
    };

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    // Long sequential repository scans can outlive a provider's keep-alive
    // connection. Use a fresh connection per request so a stale pooled socket
    // cannot strand one required method review.
    headers.insert(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("close"),
    );
    (payload, headers)
}

pub(super) fn schema_description(schema: ResponseSchema) -> String {
    super::llm_schema::schema_description(schema)
}

pub(super) fn validate_schema(
    value: &serde_json::Value,
    schema: ResponseSchema,
) -> Result<(), String> {
    super::llm_schema::validate_schema(value, schema)
}

#[cfg(test)]
mod tests {
    use super::{EndpointKind, build_payload, endpoint_kind, request_url};
    use crate::config::ResolvedConfig;

    fn config(endpoint: &str) -> ResolvedConfig {
        let mut config = ResolvedConfig {
            model: "model".to_string(),
            ..ResolvedConfig::default()
        };
        config.llm.endpoint = endpoint.to_string();
        config
    }

    #[test]
    fn recognizes_the_direct_anthropic_api() {
        let config = config("https://api.anthropic.com");
        assert_eq!(endpoint_kind(&config), EndpointKind::Anthropic);
        assert_eq!(
            request_url(&config),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn preserves_complete_anthropic_message_urls() {
        let config = config("https://api.anthropic.com/v1/messages");
        assert_eq!(
            request_url(&config),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn openai_uses_max_completion_tokens_without_thinking() {
        let config = config("https://api.openai.com/v1");
        let (payload, _) = build_payload(&config, "return json");
        assert_eq!(payload["max_completion_tokens"], 4096);
        assert!(payload.get("thinking").is_none());
    }

    #[test]
    fn deepseek_uses_its_supported_thinking_switch() {
        let config = config("https://api.deepseek.com");
        let (payload, _) = build_payload(&config, "return json");
        assert_eq!(payload["max_tokens"], 4096);
        assert_eq!(payload["thinking"]["type"], "disabled");
    }
}
