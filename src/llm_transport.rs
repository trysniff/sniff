use super::ResponseSchema;
use super::llm_payload;
use crate::config::ResolvedConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointKind {
    OpenAi,
    Anthropic,
}

pub(super) fn endpoint_kind(config: &ResolvedConfig) -> EndpointKind {
    if config.llm.endpoint.to_lowercase().contains("/anthropic") {
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
    let payload = match endpoint_kind(config) {
        EndpointKind::OpenAi => llm_payload::openai_payload(&config.model, sys_ctx, prompt),
        EndpointKind::Anthropic => llm_payload::anthropic_payload(&config.model, sys_ctx, prompt),
    };

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    (payload, headers)
}

pub(super) fn schema_description(schema: ResponseSchema) -> &'static str {
    super::llm_schema::schema_description(schema)
}

pub(super) fn validate_schema(
    value: &serde_json::Value,
    schema: ResponseSchema,
) -> Result<(), String> {
    super::llm_schema::validate_schema(value, schema)
}
